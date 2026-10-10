// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The memory channel's background worker. It re-shares the pages a live fold refused, and
//! watches the standing version's growth while a refresh flattens it.
//!
//! A live fold refuses a page the source maps exclusively and read-only: it cannot tell it
//! from a page a pin is racing for. GUP's unshare leaves exactly that behind when it pins a
//! page shared with the standing version for an O_DIRECT write, and the guest may never write
//! the page again, so the standing version would keep its old copy for good. The worker takes
//! a write fault on each such page with an atomic read-modify-write of zero: the kernel reuses
//! the page (no copy), makes it writable and marks it, and the next live fold shares it. The
//! value never changes and no concurrent guest write is lost, because the operation is atomic.
//! A page that really is pinned still fails the fold's pin check.
//!
//! The worker is a guest-memory writer, so a capture fences it before CREATE and the disk
//! clone, as it stops every other writer.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::memversion::{self, Region};
use crate::Vmm;
use crate::logger::{error, info};
use crate::vmm_config::instance_info::VmState;

/// Pages touched between two checks of the fence, and the wait after them: about 64k pages a
/// second at most, off every vCPU thread.
const TOUCH_BATCH: usize = 256;
const TOUCH_PAUSE: Duration = Duration::from_millis(4);
/// How often a refresh's watch reads the tracker's dirty counter.
const WATCH_PERIOD: Duration = Duration::from_millis(1);

/// One unit of background work.
enum Job {
    /// Re-share these pages: host addresses of the pages a live fold left exclusive.
    Touch(Vec<u64>),
    /// Watch the tracker while a refresh flattens: pause the vCPUs if the guest dirties
    /// `budget` pages beyond `base`, and resume them when the watch ends.
    Watch { tracker: i32, base: u64, budget: u64 },
}

#[derive(Default)]
struct State {
    job: Option<Job>,
    /// A capture holds the fence: no touch may run.
    fenced: bool,
    /// A batch of touches is running.
    touching: bool,
    /// The watch is asked to end.
    watch_end: bool,
    /// The watch's result: how long it held the vCPUs paused.
    watched: Option<Duration>,
}

/// Handle on the background worker thread.
#[derive(Clone)]
pub(crate) struct Background {
    shared: Arc<(Mutex<State>, Condvar)>,
}

impl std::fmt::Debug for Background {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Background")
    }
}

impl Background {
    /// A handle no worker serves: its jobs queue and never run. For tests of the channel.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
        }
    }

    /// Starts the worker. It installs `filter` on itself before it does anything.
    pub(crate) fn spawn(
        vmm: Arc<Mutex<Vmm>>,
        filter: Arc<crate::seccomp::BpfProgram>,
    ) -> std::io::Result<Self> {
        let bg = Self {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
        };
        let worker = bg.clone();
        std::thread::Builder::new()
            .name("fc_ramet_bg".to_string())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    error!("Ramet background worker could not install its filter: {err}");
                    return;
                }
                worker.run(&vmm);
            })?;
        Ok(bg)
    }

    fn run(&self, vmm: &Arc<Mutex<Vmm>>) {
        let (lock, cvar) = &*self.shared;
        loop {
            let job = {
                let mut state = lock.lock().expect("Poisoned lock");
                loop {
                    if let Some(job) = state.job.take() {
                        break job;
                    }
                    state = cvar.wait(state).expect("Poisoned lock");
                }
            };
            match job {
                Job::Touch(pages) => self.touch(&pages),
                Job::Watch {
                    tracker,
                    base,
                    budget,
                } => {
                    let paused = self.watch(vmm, tracker, base, budget);
                    let mut state = lock.lock().expect("Poisoned lock");
                    state.watched = Some(paused);
                    cvar.notify_all();
                }
            }
        }
    }

    /// Re-shares `pages`, a batch at a time between fence checks. A fence drops the rest: a
    /// capture folds them, and its set is stale after it.
    fn touch(&self, pages: &[u64]) {
        let (lock, cvar) = &*self.shared;
        let started = Instant::now();
        let mut done = 0;
        for batch in pages.chunks(TOUCH_BATCH) {
            {
                let mut state = lock.lock().expect("Poisoned lock");
                if state.fenced || state.job.is_some() {
                    break;
                }
                state.touching = true;
            }
            for &addr in batch {
                // SAFETY: addr is a page of the guest's memory, mapped for the VMM's life; the
                // atomic OR of zero leaves its value as it is.
                unsafe { reshare(addr) };
            }
            done += batch.len();
            let mut state = lock.lock().expect("Poisoned lock");
            state.touching = false;
            cvar.notify_all();
            let (_state, _) = cvar
                .wait_timeout(state, TOUCH_PAUSE)
                .expect("Poisoned lock");
        }
        if !pages.is_empty() {
            info!(
                "Ramet re-shared {done} of {} refused pages in {} us",
                pages.len(),
                started.elapsed().as_micros()
            );
        }
    }

    fn watch(&self, vmm: &Arc<Mutex<Vmm>>, tracker: i32, base: u64, budget: u64) -> Duration {
        let (lock, cvar) = &*self.shared;
        let mut paused_at: Option<Instant> = None;
        let mut we_paused = false;
        loop {
            {
                let state = lock.lock().expect("Poisoned lock");
                let (state, _) = cvar
                    .wait_timeout_while(state, WATCH_PERIOD, |s| !s.watch_end)
                    .expect("Poisoned lock");
                if state.watch_end {
                    break;
                }
            }
            if paused_at.is_some() {
                continue;
            }
            // SAFETY: the tracker descriptor stays open for the refresh the watch belongs to.
            let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(tracker) };
            let Ok(info) = memversion::track_info(fd) else {
                continue;
            };
            if info.dirty_pages.saturating_sub(base) < budget {
                continue;
            }
            super::dispatch::gate().close();
            let mut vmm = vmm.lock().expect("Poisoned lock");
            if vmm.instance_info.state == VmState::Running {
                match vmm.pause_vm() {
                    Ok(()) => we_paused = true,
                    Err(err) => error!("Ramet could not pause the guest for the refresh: {err}"),
                }
            }
            drop(vmm);
            if !we_paused {
                super::dispatch::gate().open();
            }
            paused_at = Some(Instant::now());
        }
        let mut held = Duration::ZERO;
        if let Some(at) = paused_at {
            held = at.elapsed();
            if we_paused {
                let mut vmm = vmm.lock().expect("Poisoned lock");
                if let Err(err) = vmm.resume_vm() {
                    error!("Ramet could not resume the guest after the refresh: {err}");
                }
                drop(vmm);
                super::dispatch::gate().open();
                info!(
                    "Ramet paused the guest {} us while the refresh caught up",
                    held.as_micros()
                );
            } else {
                held = Duration::ZERO;
            }
        }
        held
    }

    /// Stops every touch: returns once none runs, and keeps any from starting until `unfence`.
    pub(crate) fn fence(&self) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        state.fenced = true;
        if matches!(state.job, Some(Job::Touch(_))) {
            state.job = None;
        }
        let _state = cvar
            .wait_while(state, |s| s.touching)
            .expect("Poisoned lock");
    }

    /// Lets touches run again.
    pub(crate) fn unfence(&self) {
        let (lock, _) = &*self.shared;
        lock.lock().expect("Poisoned lock").fenced = false;
    }

    /// Queues the re-share of the pages `written` marks in `regions`: the pages the source
    /// maps exclusively, which after a live fold are the ones it refused and any written since.
    pub(crate) fn reshare(&self, regions: &[Region], written: &[Vec<u64>]) {
        let mut pages = Vec::new();
        for (region, words) in regions.iter().zip(written) {
            for (w, &word) in words.iter().enumerate() {
                let mut bits = word;
                while bits != 0 {
                    let bit = bits.trailing_zeros() as u64;
                    bits &= bits - 1;
                    let page = w as u64 * 64 + bit;
                    if page * 4096 < region.len {
                        pages.push(region.addr + page * 4096);
                    }
                }
            }
        }
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        if state.fenced || state.job.is_some() {
            return;
        }
        state.job = Some(Job::Touch(pages));
        cvar.notify_all();
    }

    /// Starts the watch for one refresh's flatten. The current touch job, if any, ends first.
    pub(crate) fn start_watch(&self, tracker: i32, base: u64, budget: u64) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        state.watch_end = false;
        state.watched = None;
        state.job = Some(Job::Watch {
            tracker,
            base,
            budget,
        });
        cvar.notify_all();
    }

    /// Ends the watch and returns how long it held the guest paused.
    pub(crate) fn end_watch(&self) -> Duration {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        state.watch_end = true;
        cvar.notify_all();
        let mut state = cvar
            .wait_while(state, |s| s.watched.is_none())
            .expect("Poisoned lock");
        state.watch_end = false;
        state.watched.take().unwrap_or_default()
    }
}

/// Takes a write fault on the page at `addr` without changing it.
///
/// # Safety
/// `addr` must be mapped and writable in this process.
#[cfg(target_arch = "x86_64")]
unsafe fn reshare(addr: u64) {
    // SAFETY: the caller guarantees the byte is mapped; a locked OR of zero is atomic and
    // leaves it unchanged.
    unsafe {
        std::arch::asm!("lock or byte ptr [{0}], 0", in(reg) addr, options(nostack));
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn reshare(addr: u64) {
    use std::sync::atomic::{AtomicU8, Ordering};
    // SAFETY: as above; an atomic fetch_or of zero leaves the byte unchanged.
    unsafe { (*(addr as *const AtomicU8)).fetch_or(0, Ordering::SeqCst) };
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;

    fn worker() -> Background {
        let bg = Background {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
        };
        let w = bg.clone();
        std::thread::spawn(move || {
            let (lock, cvar) = &*w.shared;
            loop {
                let job = {
                    let mut state = lock.lock().unwrap();
                    loop {
                        if let Some(job) = state.job.take() {
                            break job;
                        }
                        state = cvar.wait(state).unwrap();
                    }
                };
                if let Job::Touch(pages) = job {
                    w.touch(&pages);
                }
            }
        });
        bg
    }

    /// A page buffer of `n` pages, page aligned.
    fn pages(n: usize) -> (Vec<u8>, u64) {
        let buf = vec![0u8; (n + 1) * 4096];
        let base = (buf.as_ptr() as u64).next_multiple_of(4096);
        (buf, base)
    }

    #[test]
    fn a_reshare_loses_no_concurrent_write() {
        // Writers increment counters in the pages the worker touches, the first one in the very
        // byte it ORs, over and over: every increment must survive, so each count is exact.
        let n = 64;
        let (_buf, base) = pages(n);
        let bg = worker();
        let stop = Arc::new(AtomicBool::new(false));
        let counter = move |p: u64, w: u64| {
            // SAFETY: an aligned u64 inside the live buffer, only ever accessed atomically.
            unsafe { &*((base + p * 4096 + w * 8) as *const AtomicU64) }
        };
        let writers: Vec<_> = (0..4u64)
            .map(|w| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut rounds = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        for p in 0..n as u64 {
                            counter(p, w).fetch_add(1, Ordering::Relaxed);
                        }
                        rounds += 1;
                    }
                    rounds
                })
            })
            .collect();
        let region = [Region {
            addr: base,
            len: (n * 4096) as u64,
        }];
        let all = vec![vec![u64::MAX; n.div_ceil(64)]];
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(300) {
            bg.reshare(&region, &all);
            std::thread::sleep(Duration::from_millis(1));
        }
        stop.store(true, Ordering::Relaxed);
        let rounds: Vec<u64> = writers.into_iter().map(|w| w.join().unwrap()).collect();
        // No touch may outlive the buffer.
        bg.fence();
        assert!(rounds.iter().all(|&r| r > 100), "writers barely ran: {rounds:?}");
        for p in 0..n as u64 {
            for (w, &r) in rounds.iter().enumerate() {
                assert_eq!(counter(p, w as u64).load(Ordering::Relaxed), r, "page {p} writer {w}");
            }
        }
    }

    #[test]
    fn the_fence_stops_every_touch_until_it_lifts() {
        // A fenced worker runs no touch: a page it would touch keeps a value written after
        // the fence, which a touch would not change anyway, so watch the touching flag itself.
        let n = 4096;
        let (_buf, base) = pages(n);
        let bg = worker();
        let region = [Region {
            addr: base,
            len: (n * 4096) as u64,
        }];
        let all = vec![vec![u64::MAX; n.div_ceil(64)]];
        bg.reshare(&region, &all);
        std::thread::sleep(Duration::from_millis(2));
        bg.fence();
        let (lock, _) = &*bg.shared;
        for _ in 0..50 {
            let state = lock.lock().unwrap();
            assert!(!state.touching && state.job.is_none(), "a touch ran under the fence");
            drop(state);
            bg.reshare(&region, &all);
            std::thread::sleep(Duration::from_millis(1));
        }
        bg.unfence();
        bg.reshare(&region, &all);
        let queued = {
            let state = lock.lock().unwrap();
            state.job.is_some() || state.touching
        };
        // No touch may outlive the buffer.
        bg.fence();
        assert!(queued, "the lifted fence queued nothing");
    }

    #[test]
    fn reshare_lists_every_marked_page_inside_its_region() {
        let bg = Background {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
        };
        let regions = [
            Region { addr: 0x1000_0000, len: 3 * 4096 },
            Region { addr: 0x2000_0000, len: 70 * 4096 },
        ];
        // Region 0 marks bits past its three pages; region 1 marks pages 0, 63 and 64.
        bg.reshare(&regions, &[vec![0b1111_0101], vec![1 | 1 << 63, 1]]);
        let state = bg.shared.0.lock().unwrap();
        let Some(Job::Touch(pages)) = &state.job else {
            panic!("no touch queued");
        };
        assert_eq!(
            pages,
            &vec![
                0x1000_0000,
                0x1000_0000 + 2 * 4096,
                0x2000_0000,
                0x2000_0000 + 63 * 4096,
                0x2000_0000 + 64 * 4096
            ]
        );
    }
}
