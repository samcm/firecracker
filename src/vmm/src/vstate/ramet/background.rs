// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The memory channel's background worker. It re-shares the pages a live fold refused, and
//! guards the standing version's bound while the guest runs.
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
//!
//! Every page the standing version keeps beyond the guest's own is one the guest dirtied since
//! the version's fold, so the tracker's dirty count bounds it. A refresh arms the guard with a
//! dirty count, which the kernel signals on an eventfd as the guest's writes reach it
//! (MV_IOC_TRACK_LIMIT): the guard thread, blocked on that eventfd, then pauses the vCPUs until
//! the next refresh's rebase lets the old copies go, so what the guest writes past the bound is
//! only what it writes while its vCPUs are being paused. Memory plane starts refreshes early
//! enough that this is rare; the guard is what makes the bound hard.

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
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

/// One unit of background work.
enum Job {
    /// Re-share these pages: host addresses of the pages a live fold left exclusive.
    Touch(Vec<u64>),
}

/// The armed guard: pause the vCPUs once the tracker counts `at` dirty pages.
struct Guard {
    /// The channel's tracker descriptor, open while the guard is armed: untrack disarms first.
    tracker: RawFd,
    at: u64,
}

#[derive(Default)]
struct State {
    job: Option<Job>,
    /// A capture holds the fence: no touch may run.
    fenced: bool,
    /// A batch of touches is running.
    touching: bool,
    guard: Option<Guard>,
    /// The guard is reading the counter or pausing the guest.
    guarding: bool,
    /// When the guard paused the guest, while it holds it paused.
    paused_at: Option<Instant>,
    /// Guard pauses another path ended (a capture or untrack), not yet reported.
    unreported: Duration,
    /// Memory plane's eventfd, signalled when the guard pauses the guest, so its refresh
    /// starts at once instead of at its next reading of the counter.
    wake: Option<File>,
}

/// How long the guard held a guest paused, and how much of it came before a refresh started.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Paused {
    pub(crate) total: Duration,
    pub(crate) waited: Duration,
}

/// Handle on the background worker and guard threads.
#[derive(Clone)]
pub(crate) struct Background {
    shared: Arc<(Mutex<State>, Condvar)>,
    vcpus: Arc<dyn Pauser>,
    /// The eventfd the kernel signals at the guard's count; the guard thread reads it.
    limit: Arc<OwnedFd>,
}

impl std::fmt::Debug for Background {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Background")
    }
}

/// A new eventfd, close-on-exec, for the kernel's limit signal.
fn limit_eventfd() -> std::io::Result<OwnedFd> {
    // SAFETY: eventfd takes no pointer; a non-negative result is a new descriptor we own.
    let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl Background {
    /// A handle no worker serves: its jobs queue and never run. For tests of the channel.
    #[cfg(test)]
    pub(crate) fn detached() -> Self {
        Self::new(Arc::new(NoVcpus)).expect("eventfd")
    }

    fn new(vcpus: Arc<dyn Pauser>) -> std::io::Result<Self> {
        Ok(Self {
            shared: Arc::new((Mutex::new(State::default()), Condvar::new())),
            vcpus,
            limit: Arc::new(limit_eventfd()?),
        })
    }

    /// Starts the worker and the guard. Each installs `filter` on itself before it does
    /// anything.
    pub(crate) fn spawn(
        vmm: Arc<Mutex<Vmm>>,
        filter: Arc<crate::seccomp::BpfProgram>,
    ) -> std::io::Result<Self> {
        let bg = Self::new(Arc::new(VmmPauser(vmm)))?;
        for (name, guard) in [("fc_ramet_bg", false), ("fc_ramet_guard", true)] {
            let worker = bg.clone();
            let filter = filter.clone();
            std::thread::Builder::new()
                .name(name.to_string())
                .spawn(move || {
                    if let Err(err) = crate::seccomp::apply_filter(&filter) {
                        error!("Ramet {name} could not install its filter: {err}");
                        return;
                    }
                    if guard {
                        worker.guard_run();
                    } else {
                        worker.run();
                    }
                })?;
        }
        Ok(bg)
    }

    fn run(&self) {
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
            }
        }
    }

    /// Waits for the kernel's signal and checks the guard on each.
    fn guard_run(&self) {
        let mut count = [0u8; 8];
        loop {
            // SAFETY: reads 8 bytes into a live buffer from the eventfd this handle owns.
            let n = unsafe { libc::read(self.limit.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
            if n != 8 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                error!("Ramet standing guard cannot read its eventfd: {err}");
                return;
            }
            self.guard_check();
        }
    }

    /// Reads the counter and pauses the guest if it reached the guard.
    fn guard_check(&self) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        let reached = match &state.guard {
            Some(guard) if state.paused_at.is_none() => {
                // SAFETY: the tracker stays open while the guard is armed.
                let fd = unsafe { BorrowedFd::borrow_raw(guard.tracker) };
                memversion::track_info(fd).is_ok_and(|info| info.dirty_pages >= guard.at)
            }
            _ => false,
        };
        if !reached {
            return;
        }
        // Pausing takes the VMM lock, which a capture's quiesce holds: never with the state
        // lock held. `guarding` keeps a disarm waiting until the pause is recorded.
        state.guarding = true;
        drop(state);
        let paused = self.vcpus.pause();
        let mut state = lock.lock().expect("Poisoned lock");
        state.guarding = false;
        if paused {
            state.paused_at = Some(Instant::now());
            if let Some(wake) = state.wake.as_mut()
                && let Err(err) = wake.write_all(&1u64.to_ne_bytes())
            {
                error!("Ramet could not wake memory plane at the standing bound: {err}");
            }
        }
        cvar.notify_all();
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

    /// Replaces the eventfd the guard signals when it pauses the guest.
    pub(crate) fn wake_with(&self, wake: OwnedFd) {
        let (lock, _) = &*self.shared;
        lock.lock().expect("Poisoned lock").wake = Some(File::from(wake));
    }

    /// Arms the guard, or moves it: pause the guest once `tracker` counts `at` dirty pages, which
    /// the kernel signals. A guest already paused by it stays paused.
    pub(crate) fn guard(&self, tracker: &impl AsRawFd, at: u64) {
        let fd = tracker.as_raw_fd();
        {
            let (lock, _) = &*self.shared;
            lock.lock().expect("Poisoned lock").guard = Some(Guard { tracker: fd, at });
        }
        // SAFETY: the caller's tracker is open for this call.
        let device = unsafe { BorrowedFd::borrow_raw(fd) };
        // A zero count is reached already: the kernel takes 0 as off, so ask for 1 and check.
        if let Err(err) = memversion::track_limit(device, self.limit.as_fd(), at.max(1)) {
            error!("Ramet could not arm the standing guard at {at} pages: {err}");
        }
        if at == 0 {
            self.guard_check();
        }
    }

    /// Ends a refresh: resumes a guest the guard paused, and returns how long it was paused
    /// in all, and of that how long before `refresh_started`, guard pauses another path ended
    /// included. The guard stays as armed.
    pub(crate) fn release(&self, refresh_started: Instant) -> Paused {
        let (lock, cvar) = &*self.shared;
        let mut state = cvar
            .wait_while(lock.lock().expect("Poisoned lock"), |s| s.guarding)
            .expect("Poisoned lock");
        let unreported = std::mem::take(&mut state.unreported);
        let mut paused = Paused {
            total: unreported,
            waited: unreported,
        };
        if let Some(at) = state.paused_at.take() {
            self.vcpus.resume();
            paused.total += at.elapsed();
            paused.waited += refresh_started.saturating_duration_since(at);
            info!(
                "Ramet paused the guest {} us until the refresh caught up",
                at.elapsed().as_micros()
            );
        }
        drop(state);
        cvar.notify_all();
        paused
    }

    /// Disarms the guard, waiting out a check in flight, and resumes a guest it paused: a
    /// capture, an untrack, a new tracker or a failed refresh ends what the guard was for. The
    /// next refresh reports the pause.
    pub(crate) fn disarm(&self) {
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        if let Some(guard) = state.guard.take() {
            // SAFETY: the tracker stays open while the guard is armed.
            let device = unsafe { BorrowedFd::borrow_raw(guard.tracker) };
            if let Err(err) = memversion::track_limit(device, self.limit.as_fd(), 0) {
                error!("Ramet could not disarm the standing guard: {err}");
            }
        }
        let mut state = cvar
            .wait_while(state, |s| s.guarding)
            .expect("Poisoned lock");
        if let Some(at) = state.paused_at.take() {
            self.vcpus.resume();
            state.unreported += at.elapsed();
        }
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

    /// Re-shares the pages `written` marks in `regions` on the calling thread, with the worker
    /// fenced meanwhile: a refresh does it before its fold, so the fold takes them. Returns how
    /// many it touched.
    pub(crate) fn reshare_now(&self, regions: &[Region], written: &[Vec<u64>]) -> usize {
        let pages = marked_pages(regions, written);
        self.fence();
        for &addr in &pages {
            // SAFETY: as in `touch`.
            unsafe { reshare(addr) };
        }
        self.unfence();
        pages.len()
    }

    /// Queues the re-share of the pages `written` marks in `regions`: the pages the source
    /// maps exclusively, which after a live fold are the ones it refused and any written since.
    pub(crate) fn reshare(&self, regions: &[Region], written: &[Vec<u64>]) {
        let pages = marked_pages(regions, written);
        let (lock, cvar) = &*self.shared;
        let mut state = lock.lock().expect("Poisoned lock");
        if state.fenced || state.job.is_some() {
            return;
        }
        state.job = Some(Job::Touch(pages));
        cvar.notify_all();
    }
}

/// Pauses and resumes the guest's vCPUs for the guard.
pub(crate) trait Pauser: Send + Sync {
    /// Pauses a running guest; false if it was not running or could not be paused.
    fn pause(&self) -> bool;
    /// Resumes a guest `pause` paused.
    fn resume(&self);
}

/// No guest: for a handle no worker serves, and for tests.
#[cfg(test)]
pub(crate) struct NoVcpus;

#[cfg(test)]
impl Pauser for NoVcpus {
    fn pause(&self) -> bool {
        false
    }

    fn resume(&self) {}
}

/// The VMM's vCPUs, with dispatch closed while they are paused, as a capture's quiesce does.
pub(crate) struct VmmPauser(pub(crate) Arc<Mutex<Vmm>>);

impl Pauser for VmmPauser {
    fn pause(&self) -> bool {
        super::dispatch::gate().close();
        let mut vmm = self.0.lock().expect("Poisoned lock");
        let paused = vmm.instance_info.state == VmState::Running
            && match vmm.pause_vm() {
                Ok(()) => true,
                Err(err) => {
                    error!("Ramet could not pause the guest at its standing bound: {err}");
                    false
                }
            };
        drop(vmm);
        if !paused {
            super::dispatch::gate().open();
        }
        paused
    }

    fn resume(&self) {
        let mut vmm = self.0.lock().expect("Poisoned lock");
        if let Err(err) = vmm.resume_vm() {
            error!("Ramet could not resume the guest after its standing bound: {err}");
        }
        drop(vmm);
        super::dispatch::gate().open();
    }
}

/// The host addresses of the pages `written` marks in `regions`.
fn marked_pages(regions: &[Region], written: &[Vec<u64>]) -> Vec<u64> {
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
    pages
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
        let bg = Background::detached();
        let w = bg.clone();
        std::thread::spawn(move || w.run());
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

    /// Counts the pauses and resumes the guard asks for.
    #[derive(Default)]
    struct Vcpus {
        paused: AtomicBool,
        pauses: AtomicU64,
    }

    impl Pauser for Vcpus {
        fn pause(&self) -> bool {
            assert!(!self.paused.swap(true, Ordering::SeqCst), "paused twice");
            self.pauses.fetch_add(1, Ordering::SeqCst);
            true
        }

        fn resume(&self) {
            assert!(self.paused.swap(false, Ordering::SeqCst), "resumed a running guest");
        }
    }

    #[test]
    fn the_guard_pauses_at_its_count_until_released_and_reports_the_wait() {
        // No tracker: an unreadable counter never trips the guard. The worker's count check is
        // the kernel's; here the guard state machine is driven through a tripped pause.
        let vcpus = Arc::new(Vcpus::default());
        let bg = Background::new(vcpus.clone()).unwrap();
        let w = bg.clone();
        std::thread::spawn(move || w.run());
        bg.guard(&1_000_000, 0);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(vcpus.pauses.load(Ordering::SeqCst), 0, "an unreadable counter paused");
        // Trip it by hand, as a reached count does, then release as a refresh would.
        {
            let (lock, _) = &*bg.shared;
            let mut state = lock.lock().unwrap();
            assert!(vcpus.pause());
            state.paused_at = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(10));
        let refresh = Instant::now();
        std::thread::sleep(Duration::from_millis(5));
        let paused = bg.release(refresh);
        assert!(!vcpus.paused.load(Ordering::SeqCst), "release left the guest paused");
        assert!(paused.waited >= Duration::from_millis(10) && paused.waited < paused.total);
        assert!(paused.total >= Duration::from_millis(15));
        // A pause a capture ends is reported by the next release.
        {
            let (lock, _) = &*bg.shared;
            let mut state = lock.lock().unwrap();
            assert!(vcpus.pause());
            state.paused_at = Some(Instant::now());
        }
        std::thread::sleep(Duration::from_millis(5));
        bg.disarm();
        assert!(!vcpus.paused.load(Ordering::SeqCst), "disarm left the guest paused");
        let later = bg.release(Instant::now());
        assert!(later.total >= Duration::from_millis(5) && later.waited == later.total);
        assert_eq!(bg.release(Instant::now()), Paused::default());
    }

    #[test]
    fn reshare_lists_every_marked_page_inside_its_region() {
        let bg = Background::detached();
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
