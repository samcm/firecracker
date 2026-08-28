// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Condvar, Mutex};

use crate::EventManager;

/// Stops event dispatch for the whole of a capture epoch.
///
/// Pausing the vCPUs and draining asynchronous block IO leaves one writer of guest memory
/// running: the event loop. Every virtio device is a subscriber of its own, so a queue
/// notification that arrives between two capture commands would mutate device state, and often
/// guest memory, after the vmstate was serialized or after the dirty bitmap was harvested. The
/// checkpoint would then hold half of that change.
///
/// Per-command locks cannot close that hole, because the writer runs between commands. The gate
/// closes for the epoch instead: the event loop takes a shared hold around each dispatch slice,
/// and `close` waits for the slice in flight to finish before it returns. After it returns no
/// subscriber callback is running and none may start until `open`.
///
/// The startup and restore paths that resume vCPUs take the same hold, so a boot or a restore that
/// completes while an epoch is open cannot let the guest run inside it.
///
/// Lock order: a hold is always taken before the VMM lock, never after. `close` waits for holds
/// without holding the VMM lock, so a caller parked on the gate blocks nothing the capture service
/// needs.
#[derive(Debug)]
pub struct DispatchGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

/// Whether the gate is closed, how many dispatch slices are inside it, and how many callers are
/// waiting on either side of it.
#[derive(Debug)]
struct GateState {
    closed: bool,
    dispatching: usize,
    parked: usize,
    closing: usize,
}

/// Shared hold on an open gate. Dispatch runs while this is alive, and a `close` that is waiting
/// cannot return until it is dropped.
#[derive(Debug)]
pub struct DispatchHold<'a> {
    gate: &'a DispatchGate,
}

impl DispatchGate {
    /// Builds an open gate with nothing dispatching. The event loop and the capture service share
    /// one gate, so the only instances are `GATE` and the ones the tests build.
    const fn new() -> Self {
        Self {
            state: Mutex::new(GateState {
                closed: false,
                dispatching: 0,
                parked: 0,
                closing: 0,
            }),
            changed: Condvar::new(),
        }
    }

    /// Blocks while a capture epoch is open, then reports a hold that keeps the epoch from opening
    /// until dispatch is done with it.
    pub fn enter(&self) -> DispatchHold<'_> {
        let mut state = self.state.lock().expect("Poisoned lock");
        if state.closed {
            state.parked += 1;
            self.changed.notify_all();
            while state.closed {
                state = self.changed.wait(state).expect("Poisoned lock");
            }
            state.parked -= 1;
        }
        state.dispatching += 1;
        DispatchHold { gate: self }
    }

    /// Runs `f` under a hold on this gate, parked for as long as a capture epoch is open.
    ///
    /// The wait happens before `f` runs and takes no other lock, which is what keeps the lock
    /// order one-way: whatever `f` locks, it locks after the hold.
    pub fn run_outside_epoch<T>(&self, f: impl FnOnce() -> T) -> T {
        let _hold = self.enter();
        f()
    }

    /// Closes the gate and waits for the dispatch slice in flight, if any, to finish.
    ///
    /// Closing an already closed gate waits the same way and is otherwise a no-op, so a retried
    /// `quiesce` cannot open a window.
    pub fn close(&self) {
        let mut state = self.state.lock().expect("Poisoned lock");
        state.closed = true;
        state.closing += 1;
        self.changed.notify_all();
        while state.dispatching > 0 {
            state = self.changed.wait(state).expect("Poisoned lock");
        }
        state.closing -= 1;
    }

    /// Lets dispatch run again.
    pub fn open(&self) {
        let mut state = self.state.lock().expect("Poisoned lock");
        state.closed = false;
        drop(state);
        self.changed.notify_all();
    }

    /// States whether dispatch is currently stopped.
    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("Poisoned lock").closed
    }

    /// Blocks until at least `count` callers are parked on the closed gate.
    ///
    /// The gate counts them itself, so an ordering proof waits for the state it needs instead of
    /// for a duration.
    pub fn wait_for_parked(&self, count: usize) {
        let mut state = self.state.lock().expect("Poisoned lock");
        while state.parked < count {
            state = self.changed.wait(state).expect("Poisoned lock");
        }
    }

    /// Blocks until at least `count` callers are inside `close`, waiting for holds to drain.
    pub fn wait_for_closing(&self, count: usize) {
        let mut state = self.state.lock().expect("Poisoned lock");
        while state.closing < count {
            state = self.changed.wait(state).expect("Poisoned lock");
        }
    }
}

impl Drop for DispatchHold<'_> {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().expect("Poisoned lock");
        state.dispatching -= 1;
        drop(state);
        self.gate.changed.notify_all();
    }
}

/// The gate the microVM's event loop and the capture service share.
static GATE: DispatchGate = DispatchGate::new();

/// Returns the gate the event loop and the capture service share.
pub fn gate() -> &'static DispatchGate {
    &GATE
}

/// Milliseconds one dispatch slice of the event loop may block for.
///
/// The loop takes a hold for the length of a slice, so the slice bounds how long `close` waits for
/// dispatch that is already running. An idle loop wakes ten times a second, which costs nothing
/// and is what lets a capture start promptly.
const DISPATCH_SLICE_MS: i32 = 100;

/// Runs one dispatch slice of the microVM's event loop, parked while a capture epoch is open.
///
/// The hold lives exactly as long as the slice: `close` waits for a slice that has started, and a
/// slice that has not started waits for the epoch to end.
pub fn dispatch_slice(event_manager: &mut EventManager) -> event_manager::Result<usize> {
    GATE.run_outside_epoch(|| event_manager.run_with_timeout(DISPATCH_SLICE_MS))
}

/// Runs work that mutates microVM or device state, parked while a capture epoch is open.
///
/// This is the path for an API action and for the startup and restore paths that resume the vCPUs
/// themselves. The work reaches the microVM either before the epoch closes the gate or after
/// `resume` opens it, never in between, so it cannot land between the vmstate and the dirty
/// harvest of the same checkpoint.
///
/// The wait happens before the work runs and takes no other lock, so a caller parked here holds
/// nothing the capture service needs: `close` runs before the capture service takes the VMM lock,
/// and this hold is dropped by the time the work returns.
pub fn outside_capture_epoch<T>(f: impl FnOnce() -> T) -> T {
    GATE.run_outside_epoch(f)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::channel;

    use super::*;

    /// A closed gate stops a dispatch that has not started, and the same dispatch runs as soon as
    /// the epoch ends: this is the exclusion a capture epoch needs, seen from the event loop.
    ///
    /// The proof waits for the gate to report the parked caller rather than for a duration, so it
    /// cannot pass by being slow.
    #[test]
    fn a_closed_gate_parks_dispatch_until_it_opens() {
        let gate = Arc::new(DispatchGate::new());
        gate.close();
        let (dispatched_tx, dispatched_rx) = channel();

        let loop_gate = Arc::clone(&gate);
        let event_loop = std::thread::spawn(move || {
            let _hold = loop_gate.enter();
            dispatched_tx.send(()).unwrap();
        });

        // The epoch is open and the handler is provably waiting on the gate, not merely late.
        gate.wait_for_parked(1);
        assert!(
            dispatched_rx.try_recv().is_err(),
            "a device handler ran during the capture epoch"
        );

        gate.open();
        dispatched_rx.recv().unwrap();
        event_loop.join().unwrap();
    }

    /// A dispatch already running holds the epoch off: `close` does not return until the handler
    /// in flight is done, so no command of the epoch can observe half of its work.
    ///
    /// Every step is an observation of the gate or a channel handover: the closer is known to be
    /// inside `close` before the handler is released, and the value it reports afterwards is the
    /// handler's own completion flag.
    #[test]
    fn closing_waits_for_the_dispatch_in_flight() {
        let gate = Arc::new(DispatchGate::new());
        let finished = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = channel();
        let (release_tx, release_rx) = channel();
        let (observed_tx, observed_rx) = channel();

        let loop_gate = Arc::clone(&gate);
        let loop_finished = Arc::clone(&finished);
        let event_loop = std::thread::spawn(move || {
            let hold = loop_gate.enter();
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            loop_finished.store(true, Ordering::SeqCst);
            drop(hold);
        });

        entered_rx.recv().unwrap();

        let closer_gate = Arc::clone(&gate);
        let closer_finished = Arc::clone(&finished);
        let closer = std::thread::spawn(move || {
            closer_gate.close();
            observed_tx
                .send(closer_finished.load(Ordering::SeqCst))
                .unwrap();
        });

        // `quiesce` is inside `close`, and the only thing it can be waiting for is the hold.
        gate.wait_for_closing(1);
        assert!(
            !finished.load(Ordering::SeqCst),
            "the handler cannot have finished: it is waiting to be released"
        );
        assert!(
            observed_rx.try_recv().is_err(),
            "quiesce returned while a device handler was still running"
        );

        release_tx.send(()).unwrap();
        assert!(
            observed_rx.recv().unwrap(),
            "close returned before the handler in flight had finished"
        );
        assert!(gate.is_closed());
        event_loop.join().unwrap();
        closer.join().unwrap();
    }

    /// Closing twice is what a retried `quiesce` does, and it must not leave the gate open or
    /// count a hold that never existed.
    #[test]
    fn closing_twice_keeps_dispatch_stopped() {
        let gate = DispatchGate::new();

        gate.close();
        gate.close();
        assert!(gate.is_closed());

        gate.open();
        assert!(!gate.is_closed());
        let hold = gate.enter();
        drop(hold);
    }

    /// The startup and restore resume paths run through `run_outside_epoch`, which parks before it
    /// runs the work: the vCPUs of a booting or restoring microVM cannot be started inside a
    /// capture epoch.
    ///
    /// The stand-in for `Vmm::resume_vm` is a lock the test can inspect. While the resume is
    /// parked, that lock must be free, which is the lock order the capture service depends on: a
    /// resume takes the hold first and the VMM lock second, so `quiesce` can close the gate and
    /// then take the VMM lock without waiting on a caller that is waiting on it.
    #[test]
    fn a_startup_resume_parks_before_it_takes_the_vmm_lock() {
        let gate = Arc::new(DispatchGate::new());
        let vmm_lock = Arc::new(Mutex::new(false));
        let (resumed_tx, resumed_rx) = channel();

        gate.close();

        let startup_gate = Arc::clone(&gate);
        let startup_lock = Arc::clone(&vmm_lock);
        let startup = std::thread::spawn(move || {
            startup_gate.run_outside_epoch(|| {
                *startup_lock.lock().expect("Poisoned lock") = true;
            });
            resumed_tx.send(()).unwrap();
        });

        gate.wait_for_parked(1);
        assert!(
            resumed_rx.try_recv().is_err(),
            "the vCPUs were resumed during the capture epoch"
        );
        let held = vmm_lock
            .try_lock()
            .expect("a parked resume holds the VMM lock");
        assert!(!*held, "the resume ran before the epoch ended");
        drop(held);

        gate.open();
        resumed_rx.recv().unwrap();
        startup.join().unwrap();
        assert!(*vmm_lock.lock().expect("Poisoned lock"));
    }
}
