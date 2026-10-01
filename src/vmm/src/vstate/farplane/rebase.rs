// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Maps a sealed generation's pages over the private copies a source still holds of them.
//!
//! A capture copies every page the source wrote into the generation children share, and the
//! source keeps its own private copy. Once the generation is sealed, a page the source has not
//! written since the flip is byte for byte the page the generation stores, so the private copy
//! is a second resident copy of it. A rebase replaces those copies with a private mapping of the
//! generation's overlay: the source reads the shared page, and its next write takes an ordinary
//! copy on write.
//!
//! `MAP_FIXED` destroys whatever the range held, so only a page the dirty accumulator does not
//! mark since the last harvest is remapped, and only while every guest-memory writer is stopped.

use std::io;
use std::os::fd::RawFd;

use userfaultfd::{RegisterMode, Uffd};

use super::protocol::{
    ChannelError, ErrorCode, MAX_EXTENTS, REBASE_BODY_LEN, REBASE_RUN_RECORD_LEN, REBASED_BODY_LEN,
    REBASED_RANGE_RECORD_LEN, RegionRecord,
};
use crate::utils::u64_to_usize;

/// `MADV_POPULATE_READ`, which the C library this builds against may not name yet.
const MADV_POPULATE_READ: libc::c_int = 22;

/// One range pagemaster asks to rebase: a guest range and the overlay offset of its first page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebaseRun {
    /// Guest physical address the run starts at.
    pub guest_addr: u64,
    /// Run length in bytes.
    pub len: u64,
    /// Offset of the run's first page in the overlay.
    pub fd_offset: u64,
}

impl RebaseRun {
    /// Parses one run record.
    pub fn decode(buf: &[u8]) -> Result<Self, ChannelError> {
        if buf.len() < REBASE_RUN_RECORD_LEN {
            return Err(ChannelError::Malformed);
        }
        Ok(Self {
            guest_addr: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            len: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            fd_offset: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        })
    }

    /// Serializes the record.
    pub fn encode(self) -> [u8; REBASE_RUN_RECORD_LEN] {
        let mut buf = [0u8; REBASE_RUN_RECORD_LEN];
        buf[0..8].copy_from_slice(&self.guest_addr.to_le_bytes());
        buf[8..16].copy_from_slice(&self.len.to_le_bytes());
        buf[16..24].copy_from_slice(&self.fd_offset.to_le_bytes());
        buf
    }
}

/// Parsed `rebase` body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebaseRequest {
    /// Records in the run table.
    pub run_count: u32,
    /// Most ranges the rebase may map, which bounds the mappings it adds to the source.
    pub max_ranges: u32,
    /// Microseconds of pause after which no further run is started.
    pub budget_us: u64,
}

/// Parses a `rebase` body.
pub fn parse_rebase(body: &[u8]) -> Result<RebaseRequest, ChannelError> {
    if body.len() != REBASE_BODY_LEN {
        return Err(ChannelError::Malformed);
    }
    Ok(RebaseRequest {
        run_count: u32::from_le_bytes(body[0..4].try_into().unwrap()),
        max_ranges: u32::from_le_bytes(body[4..8].try_into().unwrap()),
        budget_us: u64::from_le_bytes(body[8..16].try_into().unwrap()),
    })
}

/// Why a rebase stopped before its last run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RebaseStop {
    /// Every run was considered.
    Complete = 0,
    /// The pause budget was spent.
    Budget = 1,
    /// The next run would have mapped more ranges than the request allows.
    RangeLimit = 2,
}

/// What one rebase mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebaseOutcome {
    /// Leading runs of the table that were considered in full.
    pub applied_runs: u32,
    /// Guest ranges now mapped from the overlay, as `(guest_addr, len)`.
    pub ranges: Vec<(u64, u64)>,
    /// Why the rebase stopped.
    pub stop: RebaseStop,
    /// Pages of the considered runs left in place because the guest wrote them since the flip.
    pub skipped_pages: u64,
}

/// Serializes a `rebased` body.
pub fn encode_rebased(outcome: &RebaseOutcome, paused_us: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(REBASED_BODY_LEN);
    body.extend_from_slice(&outcome.applied_runs.to_le_bytes());
    let ranges = u32::try_from(outcome.ranges.len()).expect("ranges are bounded by max_ranges");
    body.extend_from_slice(&ranges.to_le_bytes());
    body.extend_from_slice(&(outcome.stop as u32).to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&paused_us.to_le_bytes());
    body.extend_from_slice(&outcome.skipped_pages.to_le_bytes());
    body
}

/// Serializes the mapped ranges in the layout the reply buffer carries.
pub fn encode_ranges(ranges: &[(u64, u64)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ranges.len() * REBASED_RANGE_RECORD_LEN);
    for (guest_addr, len) in ranges {
        buf.extend_from_slice(&guest_addr.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
    }
    buf
}

/// Rejects a run table that is not page aligned, leaves its region, reads past the overlay, or
/// names one guest page twice.
pub fn validate_runs(
    runs: &[RebaseRun],
    regions: &[RegionRecord],
    overlay_size: u64,
    page: u64,
) -> Result<(), ErrorCode> {
    if runs.len() > MAX_EXTENTS as usize {
        return Err(ErrorCode::TooManyExtents);
    }
    for run in runs {
        if run.len == 0
            || !run.guest_addr.is_multiple_of(page)
            || !run.len.is_multiple_of(page)
            || !run.fd_offset.is_multiple_of(page)
        {
            return Err(ErrorCode::BadExtent);
        }
        let end = run
            .guest_addr
            .checked_add(run.len)
            .ok_or(ErrorCode::BadExtent)?;
        if region_of(regions, run.guest_addr, end).is_none() {
            return Err(ErrorCode::BadExtent);
        }
        if run
            .fd_offset
            .checked_add(run.len)
            .is_none_or(|stored| stored > overlay_size)
        {
            return Err(ErrorCode::BadExtent);
        }
    }
    let mut sorted: Vec<&RebaseRun> = runs.iter().collect();
    sorted.sort_by_key(|run| run.guest_addr);
    if sorted
        .windows(2)
        .any(|pair| pair[0].guest_addr + pair[0].len > pair[1].guest_addr)
    {
        return Err(ErrorCode::PlanNotCanonical);
    }
    Ok(())
}

/// Index of the region that holds all of `[start, end)`, if one does.
fn region_of(regions: &[RegionRecord], start: u64, end: u64) -> Option<usize> {
    regions
        .iter()
        .position(|region| start >= region.guest_addr && end <= region.guest_addr + region.size)
}

/// Splits one run into the ranges whose pages the dirty bitmap of its region does not mark, and
/// counts the pages it leaves out.
pub fn clean_ranges(
    run: &RebaseRun,
    region: &RegionRecord,
    bits: &[u64],
    page: u64,
) -> (Vec<(u64, u64)>, u64) {
    let mut ranges = Vec::new();
    let mut skipped = 0;
    let mut open: Option<u64> = None;
    let mut addr = run.guest_addr;
    let end = run.guest_addr + run.len;
    while addr < end {
        let index = u64_to_usize((addr - region.guest_addr) / page);
        let dirty = bits
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0);
        match (dirty, open) {
            (true, Some(start)) => {
                ranges.push((start, addr - start));
                open = None;
                skipped += 1;
            }
            (true, None) => skipped += 1,
            (false, None) => open = Some(addr),
            (false, Some(_)) => {}
        }
        addr += page;
    }
    if let Some(start) = open {
        ranges.push((start, end - start));
    }
    (ranges, skipped)
}

/// Maps the clean ranges of each run in table order, stopping before a run whose ranges would
/// pass `max_ranges` or once `budget_spent` reports the pause budget gone. At least one run is
/// always considered. A failure to map is returned with the outcome so far: the range it failed
/// on may already have lost its old mapping, so the caller must not let the guest run again.
pub fn apply_runs(
    runs: &[RebaseRun],
    regions: &[RegionRecord],
    dirty: &[Vec<u64>],
    max_ranges: u32,
    page: u64,
    mut budget_spent: impl FnMut() -> bool,
    mut map: impl FnMut(&RebaseRun, u64, u64) -> io::Result<()>,
) -> Result<RebaseOutcome, (RebaseOutcome, io::Error)> {
    let mut outcome = RebaseOutcome {
        applied_runs: 0,
        ranges: Vec::new(),
        stop: RebaseStop::Complete,
        skipped_pages: 0,
    };
    for run in runs {
        if outcome.applied_runs > 0 && budget_spent() {
            outcome.stop = RebaseStop::Budget;
            return Ok(outcome);
        }
        let Some(region) = region_of(regions, run.guest_addr, run.guest_addr + run.len) else {
            unreachable!("validate_runs placed every run inside one region");
        };
        let bits = dirty.get(region).map(Vec::as_slice).unwrap_or(&[]);
        let (ranges, skipped) = clean_ranges(run, &regions[region], bits, page);
        if outcome.ranges.len() + ranges.len() > max_ranges as usize {
            outcome.stop = RebaseStop::RangeLimit;
            return Ok(outcome);
        }
        for (guest_addr, len) in ranges {
            if let Err(err) = map(run, guest_addr, len) {
                return Err((outcome, err));
            }
            outcome.ranges.push((guest_addr, len));
        }
        outcome.skipped_pages += skipped;
        outcome.applied_runs += 1;
    }
    Ok(outcome)
}

/// Maps `len` bytes of the overlay from `fd_offset` over the guest memory at `host_addr`, installs
/// its pages read-only from the overlay, and reinstates what every guest extent carries: no huge
/// pages, missing, minor and write-protect faults on the userfaultfd, and locking on fault.
///
/// The pages are installed before the range is registered, so populating it raises no userfault
/// and leaves no page for the guest to fault in later: a guest fault on a page that is not
/// installed is served by KVM's asynchronous worker, which faults with write intent and would copy
/// the page straight back into private memory.
pub fn map_overlay_range(
    host_addr: u64,
    len: u64,
    overlay: RawFd,
    fd_offset: u64,
    uffd: &Uffd,
) -> io::Result<()> {
    let target = host_addr as *mut libc::c_void;
    let size = u64_to_usize(len);
    let offset =
        libc::off_t::try_from(fd_offset).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: the range is guest memory this process reserved, which validation placed inside one
    // region, and every writer of it is stopped, so replacing its mapping races with nothing.
    let mapped = unsafe {
        libc::mmap(
            target,
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_FIXED,
            overlay,
            offset,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    if mapped != target {
        return Err(io::Error::from_raw_os_error(libc::EFAULT));
    }
    for advice in [libc::MADV_NOHUGEPAGE, MADV_POPULATE_READ] {
        // SAFETY: `target` and `size` describe the mapping just established.
        if unsafe { libc::madvise(target, size, advice) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    uffd.register_with_mode(
        target,
        size,
        RegisterMode::MISSING | RegisterMode::MINOR | RegisterMode::WRITE_PROTECT,
    )
    .map_err(io::Error::other)?;
    // SAFETY: same mapping; locking on fault changes only reclaim policy.
    if unsafe { libc::mlock2(target, size, libc::MLOCK_ONFAULT) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

    fn region(guest_addr: u64, pages: u64) -> RegionRecord {
        RegionRecord {
            guest_addr,
            size: pages * PAGE,
        }
    }

    fn run(guest_addr: u64, pages: u64, fd_offset: u64) -> RebaseRun {
        RebaseRun {
            guest_addr,
            len: pages * PAGE,
            fd_offset,
        }
    }

    #[test]
    fn a_run_record_round_trips() {
        let record = run(3 * PAGE, 2, 7 * PAGE);
        assert_eq!(RebaseRun::decode(&record.encode()).unwrap(), record);
    }

    #[test]
    fn the_request_body_has_one_exact_shape() {
        let mut body = Vec::new();
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&8u32.to_le_bytes());
        body.extend_from_slice(&5000u64.to_le_bytes());
        assert_eq!(
            parse_rebase(&body).unwrap(),
            RebaseRequest {
                run_count: 3,
                max_ranges: 8,
                budget_us: 5000
            }
        );
        parse_rebase(&body[..15]).unwrap_err();
    }

    /// A run that leaves its region, reads past the overlay or overlaps another would replace
    /// memory the overlay does not hold, so the table is refused before anything is touched.
    #[test]
    fn a_run_table_must_stay_inside_one_region_and_the_overlay() {
        let regions = [region(0, 8), region(16 * PAGE, 8)];
        let overlay = 24 * PAGE;
        assert_eq!(
            validate_runs(&[run(PAGE, 2, PAGE)], &regions, overlay, PAGE),
            Ok(())
        );
        assert_eq!(
            validate_runs(&[run(7 * PAGE, 2, 7 * PAGE)], &regions, overlay, PAGE),
            Err(ErrorCode::BadExtent),
            "a run crossing out of its region"
        );
        assert_eq!(
            validate_runs(&[run(10 * PAGE, 1, 10 * PAGE)], &regions, overlay, PAGE),
            Err(ErrorCode::BadExtent),
            "a run in the gap between regions"
        );
        assert_eq!(
            validate_runs(&[run(16 * PAGE, 2, 23 * PAGE)], &regions, overlay, PAGE),
            Err(ErrorCode::BadExtent),
            "a run past the end of the overlay"
        );
        assert_eq!(
            validate_runs(&[run(PAGE + 1, 1, PAGE)], &regions, overlay, PAGE),
            Err(ErrorCode::BadExtent),
            "a misaligned run"
        );
        assert_eq!(
            validate_runs(&[run(0, 0, 0)], &regions, overlay, PAGE),
            Err(ErrorCode::BadExtent),
            "an empty run"
        );
        assert_eq!(
            validate_runs(
                &[run(4 * PAGE, 2, 4 * PAGE), run(PAGE, 4, PAGE)],
                &regions,
                overlay,
                PAGE
            ),
            Err(ErrorCode::PlanNotCanonical),
            "runs that name one page twice, out of address order"
        );
    }

    /// A page the guest wrote since the flip holds bytes the generation does not, so the run is
    /// split around it and the page stays where it is.
    #[test]
    fn a_dirty_page_splits_its_run_and_stays_in_place() {
        let reg = region(32 * PAGE, 64);
        // Pages 2 and 3 of the region and page 7 are dirty.
        let bits = [0b1000_1100u64];
        let (ranges, skipped) = clean_ranges(&run(33 * PAGE, 8, 0), &reg, &bits, PAGE);
        assert_eq!(
            ranges,
            vec![(33 * PAGE, PAGE), (36 * PAGE, 3 * PAGE), (40 * PAGE, PAGE)]
        );
        assert_eq!(skipped, 3);

        let (ranges, skipped) = clean_ranges(&run(34 * PAGE, 2, 0), &reg, &bits, PAGE);
        assert!(ranges.is_empty());
        assert_eq!(skipped, 2);
    }

    /// Runs are taken in table order, so the caller chooses what a budget leaves out; a run is
    /// never half applied, and at least one is always considered.
    #[test]
    fn the_budget_and_the_range_limit_stop_between_runs() {
        let regions = [region(0, 64)];
        let dirty = vec![vec![0b100u64]];
        let runs = [
            run(0, 4, 0),
            run(8 * PAGE, 2, 8 * PAGE),
            run(16 * PAGE, 1, 16 * PAGE),
        ];
        let mut mapped = Vec::new();

        let outcome = apply_runs(
            &runs,
            &regions,
            &dirty,
            16,
            PAGE,
            || true,
            |_, addr, len| {
                mapped.push((addr, len));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(outcome.applied_runs, 1);
        assert_eq!(outcome.stop, RebaseStop::Budget);
        assert_eq!(outcome.ranges, vec![(0, 2 * PAGE), (3 * PAGE, PAGE)]);
        assert_eq!(outcome.skipped_pages, 1);
        assert_eq!(mapped, outcome.ranges);

        let outcome =
            apply_runs(&runs, &regions, &dirty, 3, PAGE, || false, |_, _, _| Ok(())).unwrap();
        assert_eq!(outcome.applied_runs, 2);
        assert_eq!(outcome.stop, RebaseStop::RangeLimit);
        assert_eq!(outcome.ranges.len(), 3);

        let outcome = apply_runs(
            &runs,
            &regions,
            &dirty,
            16,
            PAGE,
            || false,
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome.applied_runs, 3);
        assert_eq!(outcome.stop, RebaseStop::Complete);
    }

    /// A failed mapping reports what was already mapped, so the caller can fail closed knowing it.
    #[test]
    fn a_failed_mapping_returns_what_was_mapped_before_it() {
        let regions = [region(0, 64)];
        let runs = [run(0, 1, 0), run(4 * PAGE, 1, 4 * PAGE)];
        let (outcome, err) = apply_runs(
            &runs,
            &regions,
            &[],
            16,
            PAGE,
            || false,
            |_, addr, _| {
                if addr == 0 {
                    Ok(())
                } else {
                    Err(io::Error::from_raw_os_error(libc::ENOMEM))
                }
            },
        )
        .unwrap_err();
        assert_eq!(outcome.ranges, vec![(0, PAGE)]);
        assert_eq!(outcome.applied_runs, 1);
        assert_eq!(err.raw_os_error(), Some(libc::ENOMEM));
    }

    /// A userfaultfd of this process with the shmem features guest extents need. A user-mode-only
    /// descriptor needs no privilege, so the proof runs wherever the suite does.
    fn test_uffd() -> Uffd {
        use std::os::fd::FromRawFd;

        use userfaultfd_sys::{UFFD_API, uffdio_api};
        use vmm_sys_util::ioctl::ioctl_with_mut_ref;
        vmm_sys_util::ioctl_iowr_nr!(UFFDIO_API, 0xAA, 0x3f, uffdio_api);
        const UFFD_USER_MODE_ONLY: libc::c_int = 1;

        // SAFETY: `userfaultfd` takes a flag word and returns a new descriptor or an error.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_userfaultfd,
                libc::O_CLOEXEC | libc::O_NONBLOCK | UFFD_USER_MODE_ONLY,
            )
        };
        assert!(raw >= 0, "userfaultfd: {}", io::Error::last_os_error());
        let raw = RawFd::try_from(raw).unwrap();
        let mut api = uffdio_api {
            api: UFFD_API,
            features: super::super::backend::REQUIRED_UFFD_FEATURES,
            ioctls: 0,
        };
        // SAFETY: `raw` is the userfaultfd just created, and `api` outlives the call.
        let ret = unsafe {
            ioctl_with_mut_ref(
                &std::os::fd::BorrowedFd::borrow_raw(raw),
                UFFDIO_API(),
                &mut api,
            )
        };
        assert_eq!(ret, 0, "UFFDIO_API: {}", io::Error::last_os_error());
        // SAFETY: `raw` is a userfaultfd whose handshake completed, owned by nothing else.
        unsafe { Uffd::from_raw_fd(raw) }
    }

    /// The overlay a sealed generation hands a source: page `i` filled with `0x10 + i`, sealed and
    /// reopened read-only the way pagemaster sends it.
    fn sealed_overlay(pages: u64) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;

        // SAFETY: the name is NUL-terminated and outlives the call.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"farplane-overlay".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        let fd = RawFd::try_from(fd).unwrap();
        for i in 0..pages {
            let fill = vec![0x10 + u8::try_from(i).unwrap(); u64_to_usize(PAGE)];
            // SAFETY: `fill` is readable for its length.
            let written = unsafe {
                libc::pwrite(
                    fd,
                    fill.as_ptr().cast(),
                    fill.len(),
                    libc::off_t::try_from(i * PAGE).unwrap(),
                )
            };
            assert_eq!(written, libc::ssize_t::try_from(PAGE).unwrap());
        }
        let seals = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_FUTURE_WRITE;
        // SAFETY: sealing an owned memfd only restricts what it permits.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
        let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
        // SAFETY: `path` is NUL-terminated and opening it allocates a new descriptor.
        let ro = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        assert!(ro >= 0, "{}", io::Error::last_os_error());
        // SAFETY: the writable descriptor is no longer used.
        unsafe { libc::close(fd) };
        // SAFETY: `ro` was just opened and is owned by nothing else.
        unsafe { std::os::fd::OwnedFd::from_raw_fd(ro) }
    }

    /// The pagemap word of one page of this process.
    fn pagemap_entry(addr: u64) -> u64 {
        use std::os::unix::fs::FileExt;

        let pagemap = std::fs::File::open("/proc/self/pagemap").unwrap();
        let mut word = [0u8; 8];
        pagemap.read_exact_at(&mut word, addr / PAGE * 8).unwrap();
        u64::from_le_bytes(word)
    }

    /// A remapped range holds exactly the overlay's bytes as installed shared pages, its private
    /// copies are gone, the pages beside it keep their own, and a later write copies on write
    /// without reaching the overlay.
    #[test]
    fn a_remapped_range_reads_the_overlay_and_copies_on_write() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;

        const PRESENT: u64 = 1 << 63;
        const FILE_PAGE: u64 = 1 << 61;
        let pages = 8u64;
        let overlay = sealed_overlay(pages);
        let uffd = test_uffd();
        // SAFETY: a fresh private anonymous mapping stands in for a guest extent.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                u64_to_usize(pages * PAGE),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(base, libc::MAP_FAILED);
        let base = base as u64;
        let byte = |page: u64| base + page * PAGE;
        for page in 0..pages {
            // SAFETY: every page lies inside the mapping just made.
            unsafe {
                std::ptr::write_bytes(
                    byte(page) as *mut u8,
                    0x10 + u8::try_from(page).unwrap(),
                    u64_to_usize(PAGE),
                );
            }
        }

        map_overlay_range(byte(2), 4 * PAGE, overlay.as_raw_fd(), 2 * PAGE, &uffd).unwrap();

        for page in 0..pages {
            let entry = pagemap_entry(byte(page));
            assert_ne!(entry & PRESENT, 0, "page {page} is not resident");
            let shared = entry & FILE_PAGE != 0;
            assert_eq!(
                shared,
                (2..6).contains(&page),
                "page {page} file-backed: {shared}"
            );
            // SAFETY: the page is mapped readable.
            let first = unsafe { *(byte(page) as *const u8) };
            assert_eq!(first, 0x10 + u8::try_from(page).unwrap());
        }

        // SAFETY: page 3 is mapped writable.
        unsafe { *(byte(3) as *mut u8) = 0xee };
        assert_eq!(
            pagemap_entry(byte(3)) & FILE_PAGE,
            0,
            "the write did not copy"
        );
        let mut stored = [0u8; 1];
        let file = std::fs::File::from(overlay.try_clone().unwrap());
        file.read_exact_at(&mut stored, 3 * PAGE).unwrap();
        assert_eq!(stored[0], 0x13, "the write reached the overlay");
        // SAFETY: the mapping is owned by this test and no longer used.
        unsafe { libc::munmap(base as *mut libc::c_void, u64_to_usize(pages * PAGE)) };
    }

    #[test]
    fn the_reply_carries_the_outcome_in_a_fixed_shape() {
        let outcome = RebaseOutcome {
            applied_runs: 2,
            ranges: vec![(0, PAGE), (2 * PAGE, PAGE)],
            stop: RebaseStop::Budget,
            skipped_pages: 5,
        };
        let body = encode_rebased(&outcome, 1234);
        assert_eq!(body.len(), REBASED_BODY_LEN);
        assert_eq!(u32::from_le_bytes(body[0..4].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(body[8..12].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(body[16..24].try_into().unwrap()), 1234);
        assert_eq!(u64::from_le_bytes(body[24..32].try_into().unwrap()), 5);
        assert_eq!(
            encode_ranges(&outcome.ranges).len(),
            2 * REBASED_RANGE_RECORD_LEN
        );
    }
}
