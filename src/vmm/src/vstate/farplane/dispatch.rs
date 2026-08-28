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
#[derive(Debug)]
pub struct DispatchGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

/// Whether the gate is closed, and how many dispatch slices are inside it.
#[derive(Debug)]
struct GateState {
    closed: bool,
    dispatching: usize,
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
            }),
            changed: Condvar::new(),
        }
    }

    /// Blocks while a capture epoch is open, then reports a hold that keeps the epoch from opening
    /// until dispatch is done with it.
    pub fn enter(&self) -> DispatchHold<'_> {
        let mut state = self.state.lock().expect("Poisoned lock");
        while state.closed {
            state = self.changed.wait(state).expect("Poisoned lock");
        }
        state.dispatching += 1;
        DispatchHold { gate: self }
    }

    /// Closes the gate and waits for the dispatch slice in flight, if any, to finish.
    ///
    /// Closing an already closed gate waits the same way and is otherwise a no-op, so a retried
    /// `quiesce` cannot open a window.
    pub fn close(&self) {
        let mut state = self.state.lock().expect("Poisoned lock");
        state.closed = true;
        while state.dispatching > 0 {
            state = self.changed.wait(state).expect("Poisoned lock");
        }
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
    let _hold = GATE.enter();
    event_manager.run_with_timeout(DISPATCH_SLICE_MS)
}

/// Runs work that mutates microVM or device state, parked while a capture epoch is open.
///
/// This is the path for an API action. The action reaches the microVM either before the epoch
/// closes the gate or after `resume` opens it, never in between, so a queued action cannot land
/// between the vmstate and the dirty harvest.
///
/// The wait happens before `f` runs and takes no other lock, so an action parked here holds
/// nothing the capture service needs: `close` runs before the capture service takes the VMM lock,
/// and this hold is dropped by the time `f` returns.
pub fn outside_capture_epoch<T>(f: impl FnOnce() -> T) -> T {
    let _hold = GATE.enter();
    f()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;

    /// A closed gate stops a dispatch that has not started, and the same dispatch runs as soon as
    /// the epoch ends: this is the exclusion a capture epoch needs, seen from the event loop.
    #[test]
    fn a_closed_gate_parks_dispatch_until_it_opens() {
        let gate = Arc::new(DispatchGate::new());
        gate.close();
        let dispatched = Arc::new(AtomicBool::new(false));

        let loop_gate = Arc::clone(&gate);
        let loop_dispatched = Arc::clone(&dispatched);
        let event_loop = std::thread::spawn(move || {
            let _hold = loop_gate.enter();
            loop_dispatched.store(true, Ordering::SeqCst);
        });

        // The epoch is open, so the handler cannot run however long it is given.
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !dispatched.load(Ordering::SeqCst),
            "a device handler ran during the capture epoch"
        );

        gate.open();
        event_loop.join().unwrap();
        assert!(dispatched.load(Ordering::SeqCst));
    }

    /// A dispatch already running holds the epoch off: `close` does not return until the handler
    /// in flight is done, so no command of the epoch can observe half of its work.
    #[test]
    fn closing_waits_for_the_dispatch_in_flight() {
        let gate = Arc::new(DispatchGate::new());
        let finished = Arc::new(AtomicBool::new(false));

        let loop_gate = Arc::clone(&gate);
        let loop_finished = Arc::clone(&finished);
        let event_loop = std::thread::spawn(move || {
            let hold = loop_gate.enter();
            std::thread::sleep(Duration::from_millis(50));
            loop_finished.store(true, Ordering::SeqCst);
            drop(hold);
        });

        // Give the handler time to start, then close as `quiesce` does.
        std::thread::sleep(Duration::from_millis(10));
        gate.close();

        assert!(
            finished.load(Ordering::SeqCst),
            "quiesce returned while a device handler was still running"
        );
        assert!(gate.is_closed());
        event_loop.join().unwrap();
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
}
