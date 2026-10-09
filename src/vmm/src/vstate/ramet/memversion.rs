// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Frozen v1 UAPI plus the additive ABI v2 requests (incremental versions). Firecracker borrows the device capability from pagemaster; never opens it.
//! The companion integration stub is resources/memversion.h, not the research ioctl ABI.

use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use vmm_sys_util::ioctl::{ioctl, ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_io_nr, ioctl_iow_nr, ioctl_iowr_nr};

use super::protocol::RegionRecord;

pub(crate) const GUEST_RAM_BASE: u64 = 0x3000_0000_0000;
pub(crate) const MAX_REGIONS: usize = 16;
const MAX_EXCLUSIONS: usize = 65_536;

/// A lower run limit set once at startup by `--ramet-exclusion-cap`, so a test cell can
/// drive a capture over it with an ordinary guest. Unset, the limit is [`MAX_EXCLUSIONS`].
static EXCLUSION_CAP: std::sync::OnceLock<usize> = std::sync::OnceLock::new();

/// Parses an exclusion cap: a decimal run count in `1..=MAX_EXCLUSIONS`. It can only lower the
/// kernel's limit; anything else is an error, never the default.
pub(crate) fn parse_exclusion_cap(value: &str) -> io::Result<usize> {
    match value.parse::<usize>() {
        Ok(cap) if (1..=MAX_EXCLUSIONS).contains(&cap) => Ok(cap),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("exclusion cap {value:?} is not a run count in 1..={MAX_EXCLUSIONS}"),
        )),
    }
}

/// Sets the run limit every capture and Track count uses from now on. Once only.
pub fn set_exclusion_cap(value: &str) -> io::Result<usize> {
    let cap = parse_exclusion_cap(value)?;
    EXCLUSION_CAP
        .set(cap)
        .map_err(|_| io::Error::other("the exclusion cap is already set"))?;
    Ok(cap)
}

/// The run limit in force: the startup cap, or [`MAX_EXCLUSIONS`].
pub(crate) fn exclusion_cap() -> usize {
    EXCLUSION_CAP.get().copied().unwrap_or(MAX_EXCLUSIONS)
}

/// Mapping failure retaining the exact guest range and failed operation.
#[derive(Debug, thiserror::Error)]
#[error("{operation}(addr={addr:#x}, len={len:#x}) failed: {source}")]
pub struct MappingError {
    operation: &'static str,
    addr: u64,
    len: u64,
    source: io::Error,
}

impl MappingError {
    fn last(operation: &'static str, addr: usize, len: usize) -> Self {
        Self {
            operation,
            addr: addr as u64,
            len: len as u64,
            source: io::Error::last_os_error(),
        }
    }

    #[cfg(test)]
    fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }
}

/// Owns exactly one successful reservation or import until the last guest-region owner drops.
/// It must never own the released hole while an import is being attempted.
#[derive(Debug)]
pub(crate) struct Mapping {
    pub addr: usize,
    pub len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: Mapping is created only after successful reservation/import and is not cloned.
        unsafe { libc::munmap(self.addr as *mut libc::c_void, self.len) };
    }
}

impl Mapping {
    fn reserve(region: Region) -> Result<Self, MappingError> {
        // Supported architectures have 64-bit usize; geometry already checked the range.
        let addr = usize::try_from(region.addr).expect("validated 64-bit geometry");
        let len = usize::try_from(region.len).expect("validated 64-bit geometry");
        // SAFETY: NOREPLACE cannot overwrite another mapping. No guest accesses exist yet.
        let result = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if result == libc::MAP_FAILED {
            return Err(MappingError::last(
                "mmap(PROT_NONE, PRIVATE|ANONYMOUS|FIXED_NOREPLACE, fd=-1, offset=0)",
                addr,
                len,
            ));
        }
        let mapping = Self {
            addr: result as usize,
            len,
        };
        if mapping.addr != addr {
            return Err(MappingError {
                operation: "mmap returned wrong address",
                addr: region.addr,
                len: region.len,
                source: invalid(),
            });
        }
        // CREATE requires this VMA policy, not merely the absence of huge pages today.
        // Set it while still PROT_NONE, before boot can touch any guest RAM.
        mapping.no_huge_pages()?;
        Ok(mapping)
    }

    fn no_huge_pages(&self) -> Result<(), MappingError> {
        // SAFETY: this object exclusively owns the live VMA; the call changes only its policy.
        if unsafe {
            libc::madvise(
                self.addr as *mut libc::c_void,
                self.len,
                libc::MADV_NOHUGEPAGE,
            )
        } != 0
        {
            return Err(MappingError::last(
                "madvise(MADV_NOHUGEPAGE)",
                self.addr,
                self.len,
            ));
        }
        Ok(())
    }

    pub(crate) fn lock_on_fault(&self) -> Result<(), MappingError> {
        // SAFETY: the live owned mapping; locking on fault changes only residency policy.
        if unsafe {
            libc::mlock2(
                self.addr as *mut libc::c_void,
                self.len,
                libc::MLOCK_ONFAULT,
            )
        } != 0
        {
            return Err(MappingError::last(
                "mlock2(MLOCK_ONFAULT)",
                self.addr,
                self.len,
            ));
        }
        Ok(())
    }
}

/// Reserve all ranges before importing any. Failure drops only mappings we still own.
pub(crate) fn map_regions(
    regions: &[Region],
    version: Option<BorrowedFd<'_>>,
) -> Result<Vec<Mapping>, MappingError> {
    map_regions_with(regions, version.is_some(), |index, addr| {
        map_private(
            version.expect("import only runs with a version"),
            index,
            addr,
        )
    })
}

fn map_regions_with(
    regions: &[Region],
    import: bool,
    mut map: impl FnMut(u32, u64) -> io::Result<()>,
) -> Result<Vec<Mapping>, MappingError> {
    let mut mappings = regions
        .iter()
        .map(|region| Mapping::reserve(*region).map(Some))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, slot) in mappings.iter_mut().enumerate() {
        if import {
            // Drop releases just this owned reservation; the slot stays empty if MAP fails.
            let reservation = slot.take().unwrap();
            let (addr, len) = (reservation.addr, reservation.len);
            drop(reservation);
            let region = regions[index];
            map(
                u32::try_from(index).expect("bounded by MAX_REGIONS"),
                region.addr,
            )
            .map_err(|source| MappingError {
                operation: "MV_MAP(PRIVATE)",
                addr: region.addr,
                len: region.len,
                source,
            })?;
            *slot = Some(Mapping { addr, len });
            // PRIVATE imports carry VM_NOHUGEPAGE in v1; explicitly enforce it here too,
            // before exposing the mapping to guest-memory users.
            slot.as_ref().unwrap().no_huge_pages()?;
        } else {
            let mapping = slot.as_ref().unwrap();
            // SAFETY: change permissions of our own anonymous reservation, without replacing it.
            if unsafe {
                libc::mprotect(
                    mapping.addr as *mut libc::c_void,
                    mapping.len,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
            {
                return Err(MappingError::last(
                    "mprotect(PROT_READ|PROT_WRITE)",
                    mapping.addr,
                    mapping.len,
                ));
            }
        }
    }
    Ok(mappings.into_iter().map(Option::unwrap).collect())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Region {
    pub addr: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Exclusion {
    pub region: u32,
    pub reserved: u32,
    pub offset: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Debug)]
struct Create {
    regions: u64,
    exclusions: u64,
    nr_regions: u32,
    nr_exclusions: u32,
    flags: u32,
    fd: i32,
}

#[repr(C)]
#[derive(Debug)]
struct Map {
    region: u32,
    flags: u32,
    addr: u64,
}

#[repr(C)]
#[derive(Debug)]
struct Info {
    abi: u32,
    nr_regions: u32,
    regions: u64,
    present_pages: u64,
    excluded_pages: u64,
    new_pages: u64,
}

ioctl_iowr_nr!(MV_IOC_CREATE, 0x56, 0x40, Create);
ioctl_iow_nr!(MV_IOC_MAP, 0x56, 0x41, Map);
ioctl_iowr_nr!(MV_IOC_INFO, 0x56, 0x42, Info);

fn invalid() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

pub(crate) fn geometry(regions: &[RegionRecord]) -> io::Result<Vec<Region>> {
    if regions.is_empty() || regions.len() > MAX_REGIONS {
        return Err(invalid());
    }
    let page = crate::arch::host_page_size() as u64;
    let mut end = GUEST_RAM_BASE;
    regions
        .iter()
        .map(|region| {
            let addr = GUEST_RAM_BASE
                .checked_add(region.guest_addr)
                .ok_or_else(invalid)?;
            if region.size == 0
                || !addr.is_multiple_of(page)
                || !region.size.is_multiple_of(page)
                || addr < end
            {
                return Err(invalid());
            }
            end = addr.checked_add(region.size).ok_or_else(invalid)?;
            // Both supported architectures use lower-half userspace addresses.
            if end > (1u64 << 47) {
                return Err(invalid());
            }
            Ok(Region {
                addr,
                len: region.size,
            })
        })
        .collect()
}

/// The runs a capture excludes, and what the run limit left out.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Exclusions {
    /// Sorted by region then offset, disjoint, at most [`exclusion_cap`]: what CREATE and
    /// TRACK_INFO2 are both given.
    pub runs: Vec<Exclusion>,
    /// The runs the bitmaps hold, `runs.len()` unless the limit dropped some.
    pub found: usize,
    /// Free pages in the dropped runs: copied rather than excluded.
    pub dropped_pages: u64,
}

/// Exclude only reported-free pages with no subsequent KVM, ring or host write evidence.
///
/// More runs than CREATE takes keep the [`exclusion_cap`] longest (ties to the lower address)
/// and drop the rest: a dropped free page is copied, which is always correct, only more bytes.
/// The choice is a function of the bitmaps alone, so Track's count and CREATE agree.
///
/// Runs inside a capture's freeze, so it works a bitmap word at a time: a word costs one step
/// plus one per run edge in it, never one per page.
pub(crate) fn exclusions(
    regions: &[Region],
    free: &[Vec<u64>],
    dirty: &[Vec<u64>],
) -> io::Result<Exclusions> {
    exclusions_within(regions, free, dirty, exclusion_cap())
}

/// The exclusions of a free summary: its words are already reported-free pages with no write
/// evidence, the capture's `free & !dirty`, so they are the free log against an empty dirty log.
pub(crate) fn exclusions_from_free(
    regions: &[Region],
    summary: &[Vec<u64>],
) -> io::Result<Exclusions> {
    let clean: Vec<Vec<u64>> = summary.iter().map(|words| vec![0; words.len()]).collect();
    exclusions(regions, summary, &clean)
}

/// Keeps the `limit` longest of `runs`, ties to the lower address; returns the bytes dropped.
fn keep_longest(runs: &mut Vec<Exclusion>, limit: usize) -> u64 {
    if runs.len() <= limit {
        return 0;
    }
    // A total order (runs are disjoint), so the kept set does not depend on the input order.
    let rank = |x: &Exclusion| (std::cmp::Reverse(x.len), x.region, x.offset);
    if limit > 0 {
        runs.select_nth_unstable_by_key(limit - 1, rank);
    }
    let dropped = runs[limit..].iter().map(|x| x.len).sum();
    runs.truncate(limit);
    dropped
}

fn exclusions_within(
    regions: &[Region],
    free: &[Vec<u64>],
    dirty: &[Vec<u64>],
    limit: usize,
) -> io::Result<Exclusions> {
    let page = crate::arch::host_page_size() as u64;
    if free.len() != regions.len() || dirty.len() != regions.len() {
        return Err(invalid());
    }
    let mut out = Vec::new();
    let mut found = 0usize;
    let mut dropped = 0u64;
    for (index, region) in regions.iter().enumerate() {
        let pages = region.len / page;
        let words = usize::try_from(pages.div_ceil(64)).map_err(|_| invalid())?;
        if free[index].len() != words || dirty[index].len() != words {
            return Err(invalid());
        }
        let region_index = u32::try_from(index).map_err(|_| invalid())?;
        // Candidates stay below twice the limit: past it, only the longest can still be kept.
        let mut push = |start: u64, end: u64| {
            found += 1;
            out.push(Exclusion {
                region: region_index,
                reserved: 0,
                offset: start * page,
                len: (end - start) * page,
            });
            if out.len() >= limit.saturating_mul(2).max(1) {
                dropped += keep_longest(&mut out, limit);
            }
        };
        // The first page of the run still open at the current bit, which may continue from an
        // earlier word.
        let mut run = None;
        for (word, (free, dirty)) in (0u64..).zip(free[index].iter().zip(&dirty[index])) {
            let first = word * 64;
            let mut bits = free & !dirty;
            // Bits past the region's last page describe no guest page.
            if pages - first < 64 {
                bits &= (1u64 << (pages - first)) - 1;
            }
            let mut at = 0;
            while at < 64 {
                // Bits below `at` are consumed; above the word they read as zero.
                let rest = bits >> at;
                match run {
                    None if rest == 0 => break,
                    None => {
                        at += rest.trailing_zeros();
                        run = Some(first + u64::from(at));
                    }
                    Some(start) => {
                        at += rest.trailing_ones();
                        if at < 64 {
                            push(start, first + u64::from(at));
                            run = None;
                        }
                    }
                }
            }
        }
        if let Some(start) = run {
            push(start, pages);
        }
    }
    dropped += keep_longest(&mut out, limit);
    if out.len() < found {
        out.sort_unstable_by_key(|x| (x.region, x.offset));
    }
    Ok(Exclusions {
        runs: out,
        found,
        dropped_pages: dropped / page,
    })
}

pub(crate) fn info(fd: BorrowedFd<'_>) -> io::Result<Vec<Region>> {
    let mut regions = [Region::default(); MAX_REGIONS];
    let mut request = Info {
        abi: 1,
        nr_regions: u32::try_from(MAX_REGIONS).unwrap(),
        regions: regions.as_mut_ptr() as u64,
        present_pages: 0,
        excluded_pages: 0,
        new_pages: 0,
    };
    // SAFETY: request and its region array remain writable for the entire synchronous ioctl.
    let result = unsafe { ioctl_with_mut_ref(&fd, MV_IOC_INFO(), &mut request) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if request.abi != 1 || request.nr_regions == 0 || request.nr_regions as usize > MAX_REGIONS {
        return Err(invalid());
    }
    Ok(regions[..request.nr_regions as usize].to_vec())
}

pub(crate) fn create(
    device: BorrowedFd<'_>,
    regions: &[Region],
    exclusions: &[Exclusion],
) -> io::Result<OwnedFd> {
    create_with(regions, exclusions, |request| {
        // SAFETY: request points at immutable live slices, and its output fd is writable.
        let result = unsafe { ioctl_with_mut_ref(&device, MV_IOC_CREATE(), request) };
        if result != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

fn create_with(
    regions: &[Region],
    exclusions: &[Exclusion],
    ioctl: impl FnOnce(&mut Create) -> io::Result<()>,
) -> io::Result<OwnedFd> {
    create_flags_with(regions, exclusions, 0, ioctl)
}

fn create_flags_with(
    regions: &[Region],
    exclusions: &[Exclusion],
    flags: u32,
    ioctl: impl FnOnce(&mut Create) -> io::Result<()>,
) -> io::Result<OwnedFd> {
    if regions.is_empty() || regions.len() > MAX_REGIONS || exclusions.len() > exclusion_cap() {
        return Err(invalid());
    }
    let mut request = Create {
        regions: regions.as_ptr() as u64,
        exclusions: exclusions.as_ptr() as u64,
        nr_regions: u32::try_from(regions.len()).unwrap(),
        nr_exclusions: u32::try_from(exclusions.len()).unwrap(),
        flags,
        fd: -1,
    };
    ioctl(&mut request)?;
    if request.fd < 0 {
        return Err(invalid());
    }
    // SAFETY: successful CREATE transfers exactly this newly allocated CLOEXEC fd to the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(request.fd) })
}

const MV_MAP_PRIVATE: u32 = 1;
/// With MV_MAP_PRIVATE: the kernel installs no PTEs; each page resolves from
/// the version on first fault. Kernels without it refuse the flag with EINVAL
/// before touching the address space.
const MV_MAP_LAZY: u32 = 4;
/// Cleared once a kernel refuses MV_MAP_LAZY, so later regions map eagerly
/// without another refused ioctl.
static LAZY_IMPORT: AtomicBool = AtomicBool::new(true);

fn map_with(version: BorrowedFd<'_>, region: u32, addr: u64, flags: u32) -> io::Result<()> {
    let request = Map {
        region,
        flags,
        addr,
    };
    // SAFETY: the fixed-size request remains live; the kernel rejects occupied destinations.
    if unsafe { ioctl_with_ref(&version, MV_IOC_MAP(), &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Caller releases only its own reservation immediately before this NOREPLACE operation.
/// Imports lazily where the kernel supports it, otherwise eagerly.
pub(crate) fn map_private(version: BorrowedFd<'_>, region: u32, addr: u64) -> io::Result<()> {
    if LAZY_IMPORT.load(Ordering::Relaxed) {
        match map_with(version, region, addr, MV_MAP_PRIVATE | MV_MAP_LAZY) {
            Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
                LAZY_IMPORT.store(false, Ordering::Relaxed);
            }
            // A version this kernel cannot import lazily still imports eagerly.
            Err(err) if err.raw_os_error() == Some(libc::EOPNOTSUPP) => {}
            other => return other,
        }
    }
    map_with(version, region, addr, MV_MAP_PRIVATE)
}

// ABI v2: incremental versions. Every v1 request keeps its v1 meaning; a v1 kernel refuses
// each of these with ENOTTY (unknown request) or EINVAL (unknown CREATE flag).

/// The caller's mm is tracked; the version is the standing version plus only the pages
/// written since it, and becomes the new standing version.
const MV_CREATE_TRACKED: u32 = 1;
/// With MV_CREATE_TRACKED: the source keeps running. A page that may be pinned stays
/// unfolded rather than failing the call; at the depth bound the call fails with E2BIG.
const MV_CREATE_LIVE: u32 = 2;

#[repr(C)]
#[derive(Debug)]
struct Track {
    regions: u64,
    nr_regions: u32,
    base_fd: i32,
}

/// Dirty state of the caller's tracked mm.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TrackInfo {
    pub tracked: u32,
    pub depth: u32,
    /// Pages written since the standing version: what the next fold copies.
    pub dirty_pages: u64,
    pub standing_id: u64,
    /// In: MV_TRACK_INFO_RETAINED to also count retained_pages.
    pub flags: u32,
    pub reserved: u32,
    /// Pages the standing chain maps that this process no longer maps
    /// (diagnostic: a background walk of the chain).
    pub retained_pages: u64,
}

/// A version's v2 description: its place in a chain and what this level holds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Info2 {
    pub abi: u32,
    pub nr_regions: u32,
    pub regions: u64,
    pub present_pages: u64,
    pub excluded_pages: u64,
    pub new_pages: u64,
    pub id: u64,
    pub base_id: u64,
    pub content_id: u64,
    pub depth: u32,
    pub nr_zero_runs: u32,
    pub own_pages: u64,
    pub folded_pages: u64,
}

ioctl_iowr_nr!(MV_IOC_INFO2, 0x56, 0x43, Info2);
ioctl_io_nr!(MV_IOC_FLATTEN, 0x56, 0x44);
ioctl_iow_nr!(MV_IOC_TRACK, 0x56, 0x45, Track);
ioctl_iowr_nr!(MV_IOC_TRACK_INFO, 0x56, 0x46, TrackInfo);
ioctl_iow_nr!(MV_IOC_TRACK_REBASE, 0x56, 0x47, i32);
ioctl_iow_nr!(MV_IOC_TRACK_DROP, 0x56, 0x48, u32);

/// The longest range one MV_IOC_RESIDENT request reports.
pub(crate) const MV_RESIDENT_MAX_LEN: u64 = 1 << 30;

/// Residency of a page-aligned range of the caller's own mm. `present` and `written` point at
/// u64-word bitmaps, one bit per page, least significant first, which the kernel writes in full;
/// `written` may be null. A written page is mapped exclusively by the caller: its private copy,
/// not a version's page.
#[repr(C)]
#[derive(Debug, Default)]
struct Resident {
    addr: u64,
    len: u64,
    present: u64,
    written: u64,
    nr_present: u64,
    nr_written: u64,
    flags: u32,
    reserved: u32,
}

ioctl_iowr_nr!(MV_IOC_RESIDENT, 0x56, 0x49, Resident);

/// In: also count `included_pages` against `exclusions`.
const MV_TRACK_INFO_INCLUDED: u32 = 0x2;

/// `struct mv_track_info2` of the fpmv4 uapi: [`TrackInfo`] plus what a quiesced CREATE with a
/// given exclusion list would fold. fpmv2 and fpmv3 kernels do not have it and answer ENOTTY.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct TrackInfo2 {
    tracked: u32,
    depth: u32,
    dirty_pages: u64,
    standing_id: u64,
    flags: u32,
    nr_exclusions: u32,
    retained_pages: u64,
    /// A user pointer to `nr_exclusions` [`Exclusion`]s, validated as CREATE validates them.
    exclusions: u64,
    /// With MV_TRACK_INFO_INCLUDED: `dirty_pages` less the dirty pages inside the exclusions.
    included_pages: u64,
    reserved: u32,
    reserved2: u32,
}

ioctl_iowr_nr!(MV_IOC_TRACK_INFO2, 0x56, 0x4a, TrackInfo2);

/// How a CREATE treats the caller's tracked mm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fold {
    /// Quiesced source: fold every page written since the standing version.
    Quiesced,
    /// Running source (background refresh): fold what is not possibly pinned.
    Live,
}

/// Tracks the caller's guest regions from now on. `base` is the version every page not
/// yet faulted in equals (the lazily imported version), or `None` for a booted guest
/// whose untouched memory is zero. Call before the guest runs.
pub(crate) fn track(
    device: BorrowedFd<'_>,
    regions: &[Region],
    base: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    if regions.is_empty() || regions.len() > MAX_REGIONS {
        return Err(invalid());
    }
    let request = Track {
        regions: regions.as_ptr() as u64,
        nr_regions: u32::try_from(regions.len()).unwrap(),
        base_fd: base.map_or(-1, |fd| fd.as_raw_fd()),
    };
    // SAFETY: request points at an immutable live slice; the kernel only reads it.
    if unsafe { ioctl_with_ref(&device, MV_IOC_TRACK(), &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn track_info(device: BorrowedFd<'_>) -> io::Result<TrackInfo> {
    // flags stay 0: the retained walk is a diagnostic the commands never need.
    let mut info = TrackInfo::default();
    // SAFETY: info is a live, writable struct of the exact request size.
    if unsafe { ioctl_with_mut_ref(&device, MV_IOC_TRACK_INFO(), &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// The pages of each region this process has written since the standing version, as one
/// bitmap per region shaped like the dirty log: for a tracked source every such page is mapped
/// exclusively by it. Reads at most [`MV_RESIDENT_MAX_LEN`] per request.
pub(crate) fn written_pages(
    device: BorrowedFd<'_>,
    regions: &[Region],
) -> io::Result<Vec<Vec<u64>>> {
    written_pages_with(regions, |addr, len, present, written| {
        let mut request = Resident {
            addr,
            len,
            present: present.as_mut_ptr() as u64,
            written: written.as_mut_ptr() as u64,
            ..Default::default()
        };
        // SAFETY: request is live and writable, and both bitmaps hold one bit per page of the
        // range for the entire synchronous ioctl.
        if unsafe { ioctl_with_mut_ref(&device, MV_IOC_RESIDENT(), &mut request) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    })
}

/// Splits each region into RESIDENT ranges and assembles their `written` bitmaps. `resident`
/// gets a range's address and length and its `present` and `written` words.
fn written_pages_with(
    regions: &[Region],
    mut resident: impl FnMut(u64, u64, &mut [u64], &mut [u64]) -> io::Result<()>,
) -> io::Result<Vec<Vec<u64>>> {
    let page = crate::arch::host_page_size() as u64;
    let chunk_pages = MV_RESIDENT_MAX_LEN / page;
    // A range then starts on a bitmap word, so its words concatenate into the region's.
    if !chunk_pages.is_multiple_of(64) {
        return Err(invalid());
    }
    let words_of = |pages: u64| usize::try_from(pages.div_ceil(64)).map_err(|_| invalid());
    regions
        .iter()
        .map(|region| {
            if region.len == 0 || !region.len.is_multiple_of(page) {
                return Err(invalid());
            }
            let pages = region.len / page;
            let mut written = vec![0u64; words_of(pages)?];
            let mut present = vec![0u64; words_of(chunk_pages.min(pages))?];
            let mut first = 0;
            while first < pages {
                let count = chunk_pages.min(pages - first);
                let words = words_of(count)?;
                let start = words_of(first)?;
                resident(
                    region.addr + first * page,
                    count * page,
                    &mut present[..words],
                    &mut written[start..start + words],
                )?;
                first += count;
            }
            // Bits past the region's last page describe no guest page.
            if !pages.is_multiple_of(64) {
                *written.last_mut().expect("nonempty region") &= (1u64 << (pages % 64)) - 1;
            }
            Ok(written)
        })
        .collect()
}

/// The pages a quiesced tracked CREATE would newly retain: those written since the standing
/// version (`written`, from [`written_pages`]) that are outside its `exclusions`.
pub(crate) fn newly_retained(
    regions: &[Region],
    mut written: Vec<Vec<u64>>,
    exclusions: &[Exclusion],
) -> io::Result<u64> {
    let page = crate::arch::host_page_size() as u64;
    if written.len() != regions.len() {
        return Err(invalid());
    }
    for (region, words) in regions.iter().zip(&written) {
        if u64::try_from(words.len()).map_err(|_| invalid())? != (region.len / page).div_ceil(64) {
            return Err(invalid());
        }
    }
    for exclusion in exclusions {
        let index = usize::try_from(exclusion.region).map_err(|_| invalid())?;
        let (Some(region), Some(words)) = (regions.get(index), written.get_mut(index)) else {
            return Err(invalid());
        };
        let end = exclusion
            .offset
            .checked_add(exclusion.len)
            .ok_or_else(invalid)?;
        if !exclusion.offset.is_multiple_of(page) || !end.is_multiple_of(page) || end > region.len {
            return Err(invalid());
        }
        let mut first = exclusion.offset / page;
        let last = end / page;
        while first < last {
            let bit = first % 64;
            let count = (64 - bit).min(last - first);
            let mask = if count == 64 {
                u64::MAX
            } else {
                ((1u64 << count) - 1) << bit
            };
            words[usize::try_from(first / 64).map_err(|_| invalid())?] &= !mask;
            first += count;
        }
    }
    Ok(written
        .iter()
        .flatten()
        .map(|word| u64::from(word.count_ones()))
        .sum())
}

/// The pages a quiesced tracked CREATE with `exclusions` would fold, and who counted them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Included {
    /// The kernel, with the tracker state it read under the same lock. O(runs) word operations
    /// on the tracker's dirty bits: no page walk.
    Kernel(TrackInfo, u64),
    /// A kernel without MV_IOC_TRACK_INFO2: the pages MV_IOC_RESIDENT reports written less the
    /// exclusions ([`newly_retained`]), a walk of every guest page.
    Resident(u64),
}

impl Included {
    pub(crate) fn pages(self) -> u64 {
        match self {
            Self::Kernel(_, pages) | Self::Resident(pages) => pages,
        }
    }
}

/// Counts what a quiesced tracked CREATE with `exclusions`, the list it will be given, would
/// fold. Only a kernel that does not know MV_IOC_TRACK_INFO2 (ENOTTY) is counted by residency;
/// any other refusal is an error, never a reason to count another way.
pub(crate) fn included_pages(
    device: BorrowedFd<'_>,
    regions: &[Region],
    exclusions: &[Exclusion],
) -> io::Result<Included> {
    included_pages_with(
        exclusions,
        |request| {
            // SAFETY: request is live and writable, and its exclusion pointer names a live slice
            // of nr_exclusions entries the kernel only reads, for the entire synchronous ioctl.
            if unsafe { ioctl_with_mut_ref(&device, MV_IOC_TRACK_INFO2(), request) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        },
        || newly_retained(regions, written_pages(device, regions)?, exclusions),
    )
}

fn included_pages_with(
    exclusions: &[Exclusion],
    track_info2: impl FnOnce(&mut TrackInfo2) -> io::Result<()>,
    resident: impl FnOnce() -> io::Result<u64>,
) -> io::Result<Included> {
    if exclusions.len() > exclusion_cap() {
        return Err(invalid());
    }
    let mut request = TrackInfo2 {
        flags: MV_TRACK_INFO_INCLUDED,
        nr_exclusions: u32::try_from(exclusions.len()).unwrap(),
        exclusions: exclusions.as_ptr() as u64,
        ..Default::default()
    };
    match track_info2(&mut request) {
        Err(err) if err.raw_os_error() == Some(libc::ENOTTY) => {
            return Ok(Included::Resident(resident()?));
        }
        result => result?,
    }
    let info = TrackInfo {
        tracked: request.tracked,
        depth: request.depth,
        dirty_pages: request.dirty_pages,
        standing_id: request.standing_id,
        ..Default::default()
    };
    Ok(Included::Kernel(info, request.included_pages))
}

/// The kernel's count of what a quiesced CREATE with `exclusions` would fold, taken while the
/// guest runs, or `None` on a kernel without MV_IOC_TRACK_INFO2 (ENOTTY). Never walks the guest:
/// an estimate taken outside a freeze has no use for the residency count.
pub(crate) fn track_sample(
    device: BorrowedFd<'_>,
    exclusions: &[Exclusion],
) -> io::Result<Option<(TrackInfo, u64)>> {
    match included_pages_with(
        exclusions,
        |request| {
            // SAFETY: as in `included_pages`.
            if unsafe { ioctl_with_mut_ref(&device, MV_IOC_TRACK_INFO2(), request) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        },
        || Err(io::Error::from_raw_os_error(libc::ENOTTY)),
    ) {
        Ok(Included::Kernel(info, pages)) => Ok(Some((info, pages))),
        Ok(Included::Resident(_)) => unreachable!("the residency count is never taken"),
        Err(err) if err.raw_os_error() == Some(libc::ENOTTY) => Ok(None),
        Err(err) => Err(err),
    }
}

/// CREATE over the tracked standing version. The returned version is the new standing
/// version; the tracker holds its own reference.
pub(crate) fn create_tracked(
    device: BorrowedFd<'_>,
    regions: &[Region],
    exclusions: &[Exclusion],
    fold: Fold,
) -> io::Result<OwnedFd> {
    let flags = match fold {
        Fold::Quiesced => MV_CREATE_TRACKED,
        Fold::Live => MV_CREATE_TRACKED | MV_CREATE_LIVE,
    };
    create_flags_with(regions, exclusions, flags, |request| {
        // SAFETY: request points at immutable live slices, and its output fd is writable.
        let result = unsafe { ioctl_with_mut_ref(&device, MV_IOC_CREATE(), request) };
        if result != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

pub(crate) fn info2(version: BorrowedFd<'_>) -> io::Result<Info2> {
    let mut info = Info2::default();
    // SAFETY: info is a live, writable struct of the exact request size; regions stays null,
    // so the kernel writes no region array.
    if unsafe { ioctl_with_mut_ref(&version, MV_IOC_INFO2(), &mut info) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// A new flat version with the same content as `version`. Reads only immutable versions,
/// so it needs no source lock and pauses nothing.
pub(crate) fn flatten(version: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    // SAFETY: the request takes no argument; a non-negative result is a new CLOEXEC fd.
    let fd = unsafe { ioctl(&version, MV_IOC_FLATTEN()) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful FLATTEN transfers exactly this newly allocated fd to the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Stops tracking this process's guest memory and releases its standing version. Later
/// captures copy whole until the guest is tracked again.
pub(crate) fn untrack(device: BorrowedFd<'_>) -> io::Result<()> {
    let flags: u32 = 0;
    // SAFETY: the request reads one live u32.
    if unsafe { ioctl_with_ref(&device, MV_IOC_TRACK_DROP(), &flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces the tracker's standing version with `flat`, a FLATTEN of it.
pub(crate) fn rebase(device: BorrowedFd<'_>, flat: BorrowedFd<'_>) -> io::Result<()> {
    let fd: i32 = flat.as_raw_fd();
    // SAFETY: the request reads one live i32.
    if unsafe { ioctl_with_ref(&device, MV_IOC_TRACK_REBASE(), &fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Tracks the guest whose memory was imported from `base`, if any. A guest imported eagerly
/// (a kernel or version that refused the lazy import) is tracked without a base: every present
/// page starts dirty and the first fold copies it, as a v1 capture would.
pub(crate) fn track_guest(
    device: BorrowedFd<'_>,
    regions: &[Region],
    base: Option<BorrowedFd<'_>>,
) -> io::Result<()> {
    track_guest_with(base.is_some(), |with_base| {
        track(device, regions, if with_base { base } else { None })
    })
}

fn track_guest_with(
    has_base: bool,
    mut track: impl FnMut(bool) -> io::Result<()>,
) -> io::Result<()> {
    match track(has_base) {
        Err(err) if has_base && err.raw_os_error() == Some(libc::EINVAL) => track(false),
        other => other,
    }
}

/// Refreshes the standing version while the guest runs: folds the pages written since it,
/// without free-page exclusions (a running guest may write an excluded page; the next
/// quiesced fold applies them). At the depth bound the standing version is flattened and
/// rebased first, still without pausing anything. Returns the new standing version.
pub(crate) fn refresh(
    device: BorrowedFd<'_>,
    regions: &[Region],
    standing: Option<BorrowedFd<'_>>,
) -> io::Result<OwnedFd> {
    refresh_with(
        || create_tracked(device, regions, &[], Fold::Live),
        || {
            let standing = standing.ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            let flat = flatten(standing)?;
            rebase(device, flat.as_fd())
        },
    )
}

fn refresh_with(
    mut fold: impl FnMut() -> io::Result<OwnedFd>,
    flatten_and_rebase: impl FnOnce() -> io::Result<()>,
) -> io::Result<OwnedFd> {
    match fold() {
        Err(err) if err.raw_os_error() == Some(libc::E2BIG) => {
            flatten_and_rebase()?;
            fold()
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsFd, IntoRawFd};

    fn assert_no_huge_pages(mapping: &Mapping) {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut contains = false;
        for line in smaps.lines() {
            if let Some((start, rest)) = line.split_once('-')
                && let Ok(start) = usize::from_str_radix(start, 16)
            {
                let end =
                    usize::from_str_radix(rest.split_whitespace().next().unwrap(), 16).unwrap();
                contains = start <= mapping.addr && mapping.addr + mapping.len <= end;
            }
            if contains && let Some(flags) = line.strip_prefix("VmFlags:") {
                assert!(flags.split_whitespace().any(|flag| flag == "nh"), "{line}");
                return;
            }
        }
        panic!("owned mapping missing from smaps");
    }

    #[test]
    fn reservations_import_and_collision_rollback_preserve_other_owners() {
        let regions = [
            Region {
                addr: GUEST_RAM_BASE + 0x2000_0000,
                len: 4096,
            },
            Region {
                addr: GUEST_RAM_BASE + 0x2000_2000,
                len: 4096,
            },
        ];
        let reservation = Mapping::reserve(regions[0]).unwrap();
        assert_no_huge_pages(&reservation);
        drop(reservation);
        let null = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            map_regions(&regions, Some(null.as_fd()))
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
        let boot = map_regions(&regions, None).unwrap();
        for mapping in &boot {
            assert_no_huge_pages(mapping);
        }
        boot[0].lock_on_fault().unwrap();
        // SAFETY: both mappings are live and writable until boot drops below.
        unsafe {
            (boot[0].addr as *mut u8).write(0x5a);
        }
        assert_eq!(
            map_regions(&regions, None).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        // SAFETY: failed NOREPLACE did not change the owned mapping.
        assert_eq!(unsafe { (boot[0].addr as *const u8).read() }, 0x5a);
        drop(boot);

        let mut calls = 0;
        let imports = map_regions_with(&regions, true, |index, addr| {
            calls += 1;
            assert_eq!(addr, regions[index as usize].addr);
            if index == 0 {
                assert_eq!(
                    Mapping::reserve(regions[1]).unwrap_err().raw_os_error(),
                    Some(libc::EEXIST),
                    "all later ranges reserved before first import"
                );
            }
            // Model a successful NOREPLACE import, without claiming a kernel version proof.
            let mapped = map_regions(&[regions[index as usize]], None)
                .unwrap()
                .pop()
                .unwrap();
            // Deliberately strip the reservation policy to catch a missing import madvise.
            assert_eq!(
                // SAFETY: the test owns this live mapping and has not touched it.
                unsafe {
                    libc::madvise(
                        mapped.addr as *mut libc::c_void,
                        mapped.len,
                        libc::MADV_HUGEPAGE,
                    )
                },
                0
            );
            std::mem::forget(mapped);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        for mapping in &imports {
            assert_no_huge_pages(mapping);
        }
        drop(imports);

        let mut collision = None;
        assert_eq!(
            map_regions_with(&regions, true, |index, _| {
                let mapped = map_regions(&[regions[index as usize]], None)
                    .unwrap()
                    .pop()
                    .unwrap();
                if index == 0 {
                    std::mem::forget(mapped);
                    Ok(())
                } else {
                    collision = Some(mapped);
                    Err(io::Error::from_raw_os_error(libc::EEXIST))
                }
            })
            .unwrap_err()
            .raw_os_error(),
            Some(libc::EEXIST)
        );
        // Partial success cleaned up the first mapping, but MUST NOT unmap the colliding owner.
        drop(Mapping::reserve(regions[0]).unwrap());
        assert_eq!(
            Mapping::reserve(regions[1]).unwrap_err().raw_os_error(),
            Some(libc::EEXIST)
        );
        drop(collision);
        drop(map_regions(&regions, None).unwrap());
    }

    #[test]
    fn frozen_header_layout_and_numbers() {
        assert_eq!(
            (
                size_of::<Region>(),
                size_of::<Exclusion>(),
                size_of::<Create>(),
                size_of::<Map>(),
                size_of::<Info>()
            ),
            (16, 24, 32, 16, 40)
        );
        assert_eq!(
            (MV_IOC_CREATE(), MV_IOC_MAP(), MV_IOC_INFO()),
            (0xc0205640, 0x40105641, 0xc0285642)
        );
        assert_eq!(std::mem::offset_of!(Create, fd), 28);
        assert_eq!(std::mem::offset_of!(Info, regions), 8);
    }

    #[test]
    fn abi_v2_layout_and_numbers() {
        // Sizes and offsets of research/907-memversion/fork-speed/patch/stage4-uapi.h.
        assert_eq!(
            (
                size_of::<Track>(),
                size_of::<TrackInfo>(),
                size_of::<Info2>()
            ),
            (16, 40, 88)
        );
        assert_eq!(std::mem::offset_of!(Track, base_fd), 12);
        assert_eq!(std::mem::offset_of!(Info2, id), 40);
        assert_eq!(std::mem::offset_of!(Info2, depth), 64);
        assert_eq!(std::mem::offset_of!(Info2, own_pages), 72);
        assert_eq!(
            (
                MV_IOC_INFO2(),
                MV_IOC_FLATTEN(),
                MV_IOC_TRACK(),
                MV_IOC_TRACK_INFO(),
                MV_IOC_TRACK_REBASE(),
                MV_IOC_TRACK_DROP()
            ),
            (
                0xc0585643, 0x5644, 0x40105645, 0xc0285646, 0x40045647, 0x40045648
            )
        );
        assert_eq!(std::mem::offset_of!(TrackInfo, retained_pages), 32);
        // struct mv_resident of the fpmv3 uapi.
        assert_eq!(size_of::<Resident>(), 56);
        assert_eq!(std::mem::offset_of!(Resident, written), 24);
        assert_eq!(std::mem::offset_of!(Resident, nr_written), 40);
        assert_eq!(std::mem::offset_of!(Resident, flags), 48);
        assert_eq!(MV_IOC_RESIDENT(), 0xc0385649);
        assert_eq!(MV_RESIDENT_MAX_LEN, 1 << 30);
        // struct mv_track_info2 of the fpmv4 uapi.
        assert_eq!(size_of::<TrackInfo2>(), 64);
        assert_eq!(std::mem::offset_of!(TrackInfo2, flags), 24);
        assert_eq!(std::mem::offset_of!(TrackInfo2, nr_exclusions), 28);
        assert_eq!(std::mem::offset_of!(TrackInfo2, retained_pages), 32);
        assert_eq!(std::mem::offset_of!(TrackInfo2, exclusions), 40);
        assert_eq!(std::mem::offset_of!(TrackInfo2, included_pages), 48);
        assert_eq!(std::mem::offset_of!(TrackInfo2, reserved), 56);
        assert_eq!(MV_IOC_TRACK_INFO2(), 0xc040564a);
        assert_eq!(MV_TRACK_INFO_INCLUDED, 0x2);
    }

    #[test]
    fn included_pages_fall_back_to_residency_only_on_a_kernel_without_track_info2() {
        let excluded = [
            Exclusion {
                region: 0,
                reserved: 0,
                offset: 0,
                len: 4096,
            },
            Exclusion {
                region: 1,
                reserved: 0,
                offset: 8192,
                len: 4096,
            },
        ];
        // fpmv4 counts against the list it is given and reports the tracker beside it.
        let counted = included_pages_with(
            &excluded,
            |request| {
                assert_eq!(
                    (request.flags, request.nr_exclusions, request.exclusions),
                    (MV_TRACK_INFO_INCLUDED, 2, excluded.as_ptr() as u64)
                );
                assert_eq!((request.reserved, request.reserved2), (0, 0));
                request.tracked = 1;
                request.depth = 3;
                request.dirty_pages = 700;
                request.standing_id = 9;
                request.included_pages = 41;
                Ok(())
            },
            || panic!("walked residency on a kernel that counts"),
        )
        .unwrap();
        assert_eq!(
            counted,
            Included::Kernel(
                TrackInfo {
                    tracked: 1,
                    depth: 3,
                    dirty_pages: 700,
                    standing_id: 9,
                    ..Default::default()
                },
                41
            )
        );
        assert_eq!(counted.pages(), 41);
        // fpmv2 and fpmv3 do not know the request: the exact residency count stands in.
        let mut walks = 0;
        let counted = included_pages_with(
            &excluded,
            |_| Err(io::Error::from_raw_os_error(libc::ENOTTY)),
            || {
                walks += 1;
                Ok(17)
            },
        )
        .unwrap();
        assert_eq!((counted, walks), (Included::Resident(17), 1));
        // A failed walk fails the count rather than guessing one.
        included_pages_with(
            &excluded,
            |_| Err(io::Error::from_raw_os_error(libc::ENOTTY)),
            || Err(io::Error::from_raw_os_error(libc::EINVAL)),
        )
        .unwrap_err();
        // An fpmv4 refusal is a fault on one side, not an older kernel: never counted otherwise.
        for errno in [libc::EINVAL, libc::EFAULT, libc::ENOMEM, libc::EINTR] {
            let err = included_pages_with(
                &excluded,
                |_| Err(io::Error::from_raw_os_error(errno)),
                || panic!("fell back on errno {errno}"),
            )
            .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(errno));
        }
        // More runs than CREATE takes never reach the kernel.
        let too_many = vec![excluded[0]; MAX_EXCLUSIONS + 1];
        included_pages_with(
            &too_many,
            |_| panic!("asked the kernel"),
            || panic!("walked residency"),
        )
        .unwrap_err();
        // A non-device answers ENOTTY, so the real request takes the residency path, which a
        // non-device refuses too.
        let null = std::fs::File::open("/dev/null").unwrap();
        let regions = [Region {
            addr: GUEST_RAM_BASE,
            len: 4096,
        }];
        assert_eq!(
            included_pages(null.as_fd(), &regions, &[])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
    }

    #[test]
    fn a_free_summarys_exclusions_are_the_captures() {
        let page = crate::arch::host_page_size() as u64;
        let regions = [
            Region {
                addr: GUEST_RAM_BASE,
                len: 256 * page,
            },
            Region {
                addr: GUEST_RAM_BASE + (1 << 30),
                len: 197 * page,
            },
        ];
        let mut state = 0x853c_49e6_748f_ea9bu64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..500 {
            let free: Vec<Vec<u64>> = [4, 4]
                .iter()
                .map(|&n| (0..n).map(|_| next()).collect())
                .collect();
            let dirty: Vec<Vec<u64>> = [4, 4]
                .iter()
                .map(|&n| (0..n).map(|_| next() & next()).collect())
                .collect();
            // What free_summary_until reports: reported free and no write evidence.
            let summary: Vec<Vec<u64>> = free
                .iter()
                .zip(&dirty)
                .map(|(f, d)| f.iter().zip(d).map(|(f, d)| f & !d).collect())
                .collect();
            assert_eq!(
                exclusions_from_free(&regions, &summary).unwrap(),
                exclusions(&regions, &free, &dirty).unwrap()
            );
        }
        exclusions_from_free(&regions, &[vec![0; 4]]).unwrap_err();
        // More runs than CREATE takes: the summary's reduction is the capture's, and the pages
        // of the dropped runs stay outside the exclusions, so the kernel counts them included.
        let words = MAX_EXCLUSIONS / 32 + 2;
        let big = [Region {
            addr: GUEST_RAM_BASE,
            len: u64::try_from(words).unwrap() * 64 * page,
        }];
        let free = vec![vec![0x5555_5555_5555_5555u64; words]];
        let dirty = vec![vec![0u64; words]];
        let from_summary = exclusions_from_free(&big, &free).unwrap();
        assert_eq!(from_summary, exclusions(&big, &free, &dirty).unwrap());
        assert_eq!(
            (
                from_summary.runs.len(),
                from_summary.found,
                from_summary.dropped_pages
            ),
            (MAX_EXCLUSIONS, MAX_EXCLUSIONS * 2 / 2 + 64, 64)
        );
    }

    #[test]
    fn a_running_sample_is_the_kernels_count_or_no_sample_never_a_walk() {
        // A kernel without TRACK_INFO2 answers ENOTTY: no sample, and no residency walk.
        let null = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(track_sample(null.as_fd(), &[]).unwrap(), None);
    }

    #[test]
    fn written_pages_read_each_region_in_resident_chunks() {
        let page = crate::arch::host_page_size() as u64;
        let chunk = MV_RESIDENT_MAX_LEN / page;
        let regions = [
            Region {
                addr: GUEST_RAM_BASE,
                len: MV_RESIDENT_MAX_LEN + 3 * page,
            },
            Region {
                addr: GUEST_RAM_BASE + (2 << 30),
                len: 5 * page,
            },
        ];
        // Pages each side of the 1 GiB boundary, the region's last page, and two in region 1.
        let written_at = [
            GUEST_RAM_BASE,
            GUEST_RAM_BASE + (chunk - 1) * page,
            GUEST_RAM_BASE + chunk * page,
            GUEST_RAM_BASE + (chunk + 2) * page,
            regions[1].addr + page,
            regions[1].addr + 4 * page,
        ];
        let mut calls = Vec::new();
        let written = written_pages_with(&regions, |addr, len, present, written| {
            calls.push((addr, len));
            let words = usize::try_from((len / page).div_ceil(64)).unwrap();
            assert_eq!((present.len(), written.len()), (words, words));
            for at in written_at
                .iter()
                .filter(|at| (addr..addr + len).contains(at))
            {
                let bit = (at - addr) / page;
                written[usize::try_from(bit / 64).unwrap()] |= 1 << (bit % 64);
            }
            // A kernel may set bits past the range; they describe no guest page.
            if !(len / page).is_multiple_of(64) {
                *written.last_mut().unwrap() |= 1 << 63;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            calls,
            vec![
                (regions[0].addr, MV_RESIDENT_MAX_LEN),
                (regions[0].addr + MV_RESIDENT_MAX_LEN, 3 * page),
                (regions[1].addr, 5 * page),
            ]
        );
        let pages = |words: &Vec<u64>| -> Vec<u64> {
            (0..words.len() as u64 * 64)
                .filter(|p| words[usize::try_from(p / 64).unwrap()] & (1 << (p % 64)) != 0)
                .collect()
        };
        assert_eq!(pages(&written[0]), vec![0, chunk - 1, chunk, chunk + 2]);
        assert_eq!(pages(&written[1]), vec![1, 4]);

        // Exclusions over written and unwritten pages: one straddles the boundary, one covers
        // region 1's page 1 (but not region 0's), one covers only unwritten pages.
        let exclusion = |region, first: u64, count: u64| Exclusion {
            region,
            reserved: 0,
            offset: first * page,
            len: count * page,
        };
        let excluded = [
            exclusion(0, chunk - 2, 4),
            exclusion(1, 0, 2),
            exclusion(1, 2, 2),
        ];
        assert_eq!(
            newly_retained(&regions, written.clone(), &excluded).unwrap(),
            3
        );
        assert_eq!(newly_retained(&regions, written.clone(), &[]).unwrap(), 6);
        // A run spanning whole words clears only its own pages.
        let all = vec![
            vec![u64::MAX; written[0].len() - 1]
                .into_iter()
                .chain([0b111])
                .collect(),
            vec![0b11111],
        ];
        assert_eq!(
            newly_retained(&regions, all, &[exclusion(0, 1, chunk + 1)]).unwrap(),
            chunk + 3 + 5 - (chunk + 1)
        );
        for bad in [
            exclusion(2, 0, 1),
            exclusion(1, 4, 2),
            Exclusion {
                offset: 1,
                ..exclusion(1, 0, 1)
            },
        ] {
            newly_retained(&regions, written.clone(), &[bad]).unwrap_err();
        }
        newly_retained(&regions, written[..1].to_vec(), &[]).unwrap_err();
        newly_retained(&regions, vec![written[0].clone(), vec![0; 2]], &[]).unwrap_err();

        // A failed range fails the whole read: the caller never guesses a count.
        let mut seen = 0;
        written_pages_with(&regions, |_, _, _, _| {
            seen += 1;
            Err(io::Error::from_raw_os_error(libc::EINVAL))
        })
        .unwrap_err();
        assert_eq!(seen, 1);
        let null = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(
            written_pages(null.as_fd(), &regions[1..])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
    }

    #[test]
    fn tracked_create_flags_and_v2_requests_on_a_non_device() {
        let regions = [Region {
            addr: GUEST_RAM_BASE,
            len: 4096,
        }];
        for (fold, flags) in [
            (Fold::Quiesced, MV_CREATE_TRACKED),
            (Fold::Live, MV_CREATE_TRACKED | MV_CREATE_LIVE),
        ] {
            let want = flags;
            let fd = create_flags_with(&regions, &[], flags, |request| {
                assert_eq!(
                    (request.flags, request.nr_regions, request.fd),
                    (want, 1, -1)
                );
                request.fd = std::fs::File::open("/dev/null")?.into_raw_fd();
                Ok(())
            })
            .unwrap();
            drop(fd);
            let null = std::fs::File::open("/dev/null").unwrap();
            assert_eq!(
                create_tracked(null.as_fd(), &regions, &[], fold)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::ENOTTY)
            );
        }
        let null = std::fs::File::open("/dev/null").unwrap();
        let enotty = Some(libc::ENOTTY);
        assert_eq!(
            track(null.as_fd(), &regions, None)
                .unwrap_err()
                .raw_os_error(),
            enotty
        );
        assert_eq!(
            track(null.as_fd(), &regions, Some(null.as_fd()))
                .unwrap_err()
                .raw_os_error(),
            enotty
        );
        assert_eq!(
            track(null.as_fd(), &[], None).unwrap_err().raw_os_error(),
            Some(libc::EINVAL)
        );
        assert_eq!(track_info(null.as_fd()).unwrap_err().raw_os_error(), enotty);
        assert_eq!(untrack(null.as_fd()).unwrap_err().raw_os_error(), enotty);
        assert_eq!(info2(null.as_fd()).unwrap_err().raw_os_error(), enotty);
        assert_eq!(flatten(null.as_fd()).unwrap_err().raw_os_error(), enotty);
        assert_eq!(
            rebase(null.as_fd(), null.as_fd())
                .unwrap_err()
                .raw_os_error(),
            enotty
        );
    }

    #[test]
    fn track_falls_back_to_no_base_only_for_a_refused_base() {
        let einval = || Err(io::Error::from_raw_os_error(libc::EINVAL));
        // An eagerly imported guest refuses its base; tracked without one.
        let mut calls = vec![];
        track_guest_with(true, |base| {
            calls.push(base);
            if base { einval() } else { Ok(()) }
        })
        .unwrap();
        assert_eq!(calls, [true, false]);
        // A booted guest has no base to drop: EINVAL is final.
        let mut calls = vec![];
        let err = track_guest_with(false, |base| {
            calls.push(base);
            einval()
        })
        .unwrap_err();
        assert_eq!(
            (calls, err.raw_os_error()),
            (vec![false], Some(libc::EINVAL))
        );
        // Any other refusal is final: no silent untracked retry.
        let mut calls = vec![];
        track_guest_with(true, |base| {
            calls.push(base);
            Err(io::Error::from_raw_os_error(libc::EBUSY))
        })
        .unwrap_err();
        assert_eq!(calls, [true]);
    }

    #[test]
    fn refresh_flattens_only_at_the_depth_bound_and_retries_once() {
        let version = || Ok(std::fs::File::open("/dev/null")?.into());
        let e2big = || Err(io::Error::from_raw_os_error(libc::E2BIG));
        let mut folds = 0;
        refresh_with(
            || {
                folds += 1;
                version()
            },
            || panic!("flattened below the bound"),
        )
        .unwrap();
        assert_eq!(folds, 1);
        let (mut folds, mut flattened) = (0, 0);
        refresh_with(
            || {
                folds += 1;
                if folds == 1 { e2big() } else { version() }
            },
            || {
                flattened += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!((folds, flattened), (2, 1));
        // A failed flatten fails the refresh without folding again.
        let mut folds = 0;
        refresh_with(
            || {
                folds += 1;
                e2big()
            },
            || Err(io::Error::from_raw_os_error(libc::ENOMEM)),
        )
        .unwrap_err();
        assert_eq!(folds, 1);
    }

    #[test]
    fn exact_geometry_and_exclusions() {
        let regions = geometry(&[
            RegionRecord {
                guest_addr: 0,
                size: 5 * 4096,
            },
            RegionRecord {
                guest_addr: 0x10000,
                size: 4096,
            },
        ])
        .unwrap();
        assert_eq!(regions[1].addr, GUEST_RAM_BASE + 0x10000);
        let runs = exclusions(
            &regions,
            &[vec![0b11111], vec![1]],
            &[vec![0b00100], vec![0]],
        )
        .unwrap()
        .runs;
        assert_eq!(
            runs,
            vec![
                Exclusion {
                    region: 0,
                    reserved: 0,
                    offset: 0,
                    len: 8192
                },
                Exclusion {
                    region: 0,
                    reserved: 0,
                    offset: 12288,
                    len: 8192
                },
                Exclusion {
                    region: 1,
                    reserved: 0,
                    offset: 0,
                    len: 4096
                }
            ]
        );
        geometry(&[]).unwrap_err();
        geometry(&[RegionRecord {
            guest_addr: u64::MAX,
            size: 4096,
        }])
        .unwrap_err();
        exclusions(&regions, &[vec![1]], &[vec![0]]).unwrap_err();
    }

    /// The per-page builder the word-wise one replaced: the runs are defined page by page.
    fn exclusions_by_page(
        regions: &[Region],
        free: &[Vec<u64>],
        dirty: &[Vec<u64>],
    ) -> Vec<Exclusion> {
        let page = crate::arch::host_page_size() as u64;
        let mut out = Vec::new();
        for (index, region) in regions.iter().enumerate() {
            let pages = region.len / page;
            let mut run = None;
            for p in 0..=pages {
                let word = usize::try_from(p / 64).unwrap();
                let excluded =
                    p < pages && (free[index][word] & !dirty[index][word]) & (1 << (p % 64)) != 0;
                if excluded {
                    run.get_or_insert(p);
                } else if let Some(start) = run.take() {
                    out.push(Exclusion {
                        region: u32::try_from(index).unwrap(),
                        reserved: 0,
                        offset: start * page,
                        len: (p - start) * page,
                    });
                }
            }
        }
        out
    }

    #[test]
    fn word_wise_exclusions_match_the_per_page_runs() {
        let page = crate::arch::host_page_size() as u64;
        // A whole-word region, one ending mid-word, and one shorter than a word.
        let regions = [
            Region {
                addr: GUEST_RAM_BASE,
                len: 256 * page,
            },
            Region {
                addr: GUEST_RAM_BASE + (1 << 30),
                len: 197 * page,
            },
            Region {
                addr: GUEST_RAM_BASE + (2 << 30),
                len: 5 * page,
            },
        ];
        let words: Vec<usize> = regions
            .iter()
            .map(|region| usize::try_from((region.len / page).div_ceil(64)).unwrap())
            .collect();
        let check = |free: &[Vec<u64>], dirty: &[Vec<u64>]| {
            let built = exclusions(&regions, free, dirty).unwrap();
            assert_eq!((built.found, built.dropped_pages), (built.runs.len(), 0));
            assert_eq!(
                built.runs,
                exclusions_by_page(&regions, free, dirty),
                "free={free:x?} dirty={dirty:x?}"
            );
        };
        // Runs across word edges, ending on bit 63, starting on bit 0, whole words, single
        // pages, and free bits past a region's last page (which never extend a run).
        let shaped = [
            vec![u64::MAX, u64::MAX, 0, 1 << 63],
            vec![1 << 63, u64::MAX, 1, u64::MAX],
            vec![0x5555_5555_5555_5555; 4],
            vec![0xf000_0000_0000_000f, 0x8000_0000_0000_0001, u64::MAX, 0],
        ];
        for free0 in &shaped {
            for dirty0 in [vec![0; 4], vec![0, 1 << 5, 0, 0], vec![u64::MAX; 4]] {
                let free = vec![free0.clone(), free0.clone(), vec![u64::MAX]];
                let dirty = vec![dirty0.clone(), dirty0, vec![0b100]];
                check(&free, &dirty);
            }
        }
        // And a deterministic spread of random bitmaps, dense and sparse.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..2000 {
            let mut bitmap = |dense: bool| -> Vec<Vec<u64>> {
                words
                    .iter()
                    .map(|&n| {
                        (0..n)
                            .map(|_| match round % 3 {
                                0 => next(),
                                1 if dense => next() | next() | next(),
                                _ => next() & next() & next(),
                            })
                            .collect()
                    })
                    .collect()
            };
            let free = bitmap(true);
            let dirty = bitmap(false);
            check(&free, &dirty);
        }
    }

    /// The runs a limit keeps, by brute force: every run, longest first then by address.
    fn longest_by_page(
        regions: &[Region],
        free: &[Vec<u64>],
        dirty: &[Vec<u64>],
        limit: usize,
    ) -> Vec<Exclusion> {
        let mut all = exclusions_by_page(regions, free, dirty);
        all.sort_by(|a, b| {
            b.len
                .cmp(&a.len)
                .then((a.region, a.offset).cmp(&(b.region, b.offset)))
        });
        all.truncate(limit);
        all.sort_by_key(|x| (x.region, x.offset));
        all
    }

    /// Pages set in `written` outside `runs`, one page at a time.
    fn retained_by_page(regions: &[Region], written: &[Vec<u64>], runs: &[Exclusion]) -> u64 {
        let page = crate::arch::host_page_size() as u64;
        let mut count = 0;
        for (index, region) in regions.iter().enumerate() {
            for p in 0..region.len / page {
                let set = written[index][usize::try_from(p / 64).unwrap()] & (1 << (p % 64)) != 0;
                let excluded = runs.iter().any(|x| {
                    x.region as usize == index
                        && (x.offset / page..(x.offset + x.len) / page).contains(&p)
                });
                count += u64::from(set && !excluded);
            }
        }
        count
    }

    #[test]
    fn over_the_run_limit_the_longest_runs_are_kept_and_counted_exactly() {
        let page = crate::arch::host_page_size() as u64;
        let regions = [
            Region {
                addr: GUEST_RAM_BASE,
                len: 640 * page,
            },
            Region {
                addr: GUEST_RAM_BASE + (1 << 30),
                len: 197 * page,
            },
        ];
        let words = [10, 4];
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..300 {
            let mut bitmap = |sparse: bool| -> Vec<Vec<u64>> {
                words
                    .iter()
                    .map(|&n| {
                        (0..n)
                            .map(|_| {
                                if sparse {
                                    next() & next()
                                } else {
                                    next() | next()
                                }
                            })
                            .collect()
                    })
                    .collect()
            };
            let (free, dirty) = (bitmap(false), bitmap(true));
            let mut written = bitmap(round % 2 == 0);
            // As written_pages gives it: nothing past a region's last page.
            *written[1].last_mut().unwrap() &= (1 << (197 % 64)) - 1;
            let all = exclusions_by_page(&regions, &free, &dirty);
            // Limits below, at and above the candidate compaction point.
            for limit in [1, 3, all.len() / 3, all.len() / 2, all.len() - 1, all.len()] {
                let built = exclusions_within(&regions, &free, &dirty, limit).unwrap();
                let kept = longest_by_page(&regions, &free, &dirty, limit);
                assert_eq!(built.runs, kept, "round {round} limit {limit}");
                assert_eq!(built.found, all.len());
                let dropped: u64 = all.iter().map(|x| x.len / page).sum::<u64>()
                    - kept.iter().map(|x| x.len / page).sum::<u64>();
                assert_eq!(built.dropped_pages, dropped);
                // What CREATE would retain against the kept runs, as the residency count gives it.
                assert_eq!(
                    newly_retained(&regions, written.clone(), &built.runs).unwrap(),
                    retained_by_page(&regions, &written, &built.runs)
                );
            }
        }
    }

    #[test]
    fn a_guest_with_more_runs_than_create_takes_still_captures() {
        let page = crate::arch::host_page_size() as u64;
        // One more run than the ABI takes: single pages, 32 to a word, except one 64-page run in
        // the middle (two words) that the limit must keep. The dropped run is the last single
        // page, the highest address among the shortest.
        let words = MAX_EXCLUSIONS as u64 / 32 + 2;
        let pages = words * 64;
        let region = Region {
            addr: GUEST_RAM_BASE,
            len: pages * page,
        };
        let n = usize::try_from(pages.div_ceil(64)).unwrap();
        let mut free = vec![0x5555_5555_5555_5555u64; n];
        free[n / 2] = u64::MAX;
        free[n / 2 + 1] = 0;
        let built = exclusions(&[region], &[free.clone()], &[vec![0; n]]).unwrap();
        assert_eq!(
            (built.runs.len(), built.found),
            (MAX_EXCLUSIONS, MAX_EXCLUSIONS + 1)
        );
        assert_eq!(built.dropped_pages, 1);
        assert!(built.runs.iter().any(|x| x.len == 64 * page));
        assert_eq!(built.runs.last().unwrap().offset, (pages - 4) * page);
        assert!(!built.runs.iter().any(|x| x.offset == (pages - 2) * page));
        // CREATE and TRACK_INFO2 both take the list as it is.
        create_flags_with(&[region], &built.runs, MV_CREATE_TRACKED, |request| {
            assert_eq!(request.nr_exclusions as usize, MAX_EXCLUSIONS);
            request.fd = std::fs::File::open("/dev/null")?.into_raw_fd();
            Ok(())
        })
        .unwrap();
        included_pages_with(
            &built.runs,
            |request| {
                assert_eq!(request.nr_exclusions as usize, MAX_EXCLUSIONS);
                Ok(())
            },
            || panic!("walked residency"),
        )
        .unwrap();
    }

    /// On a memversion host (any device ABI): an untracked CREATE of a guest with more free runs
    /// than the ABI takes succeeds, and its version holds zero in the kept runs and the source's
    /// bytes everywhere else, the dropped run included. Skips where the device is absent.
    #[test]
    fn a_capture_over_the_run_limit_on_the_host_kernel_copies_the_dropped_runs() {
        let Ok(device) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/memversion_v1")
        else {
            eprintln!("skipped: requires the pinned memversion host");
            return;
        };
        let page = crate::arch::host_page_size() as u64;
        let words = MAX_EXCLUSIONS as u64 / 32 + 2;
        let pages = words * 64;
        let regions = [Region {
            addr: GUEST_RAM_BASE,
            len: pages * page,
        }];
        let source = map_regions(&regions, None).unwrap();
        let at = |p: u64| (GUEST_RAM_BASE + p * page) as *mut u64;
        for p in 0..pages {
            // SAFETY: every page lies in the live, writable source mapping.
            unsafe { at(p).write(p + 1) };
        }
        let n = usize::try_from(words).unwrap();
        let mut free = vec![0x5555_5555_5555_5555u64; n];
        let long = u64::try_from(n / 2).unwrap() * 64;
        free[n / 2] = u64::MAX;
        free[n / 2 + 1] = 0;
        let built = exclusions(&regions, &[free], &[vec![0; n]]).unwrap();
        assert_eq!(
            (built.runs.len(), built.found),
            (MAX_EXCLUSIONS, MAX_EXCLUSIONS + 1)
        );
        let excluded: u64 = built.runs.iter().map(|x| x.len / page).sum();

        let version = create(device.as_fd(), &regions, &built.runs).unwrap();
        // The v1 counts, which every device ABI answers (INFO2 is ABI 2 only).
        let mut described = [Region::default(); MAX_REGIONS];
        let mut info = Info {
            abi: 1,
            nr_regions: u32::try_from(MAX_REGIONS).unwrap(),
            regions: described.as_mut_ptr() as u64,
            present_pages: 0,
            excluded_pages: 0,
            new_pages: 0,
        };
        // SAFETY: info and its region array stay writable for the synchronous ioctl.
        let described_ok = unsafe { ioctl_with_mut_ref(&version, MV_IOC_INFO(), &mut info) };
        assert_eq!(described_ok, 0, "{}", io::Error::last_os_error());
        assert_eq!(info.excluded_pages, excluded, "{info:?}");
        // Every other page, the dropped run's included, is captured and newly retained: it is
        // what memory plane charges the capture for.
        assert_eq!(info.present_pages, pages - excluded, "{info:?}");
        assert_eq!(info.new_pages, pages - excluded, "{info:?}");
        drop(source);

        let imported = map_regions(&regions, Some(version.as_fd())).unwrap();
        // SAFETY: every page lies in the live imported mapping.
        let read = |p: u64| unsafe { at(p).read() };
        // A kept single-page run, the long run and the last kept run read zero.
        for p in [0, long, long + 63, pages - 4] {
            assert_eq!(read(p), 0, "page {p} was excluded");
        }
        // Pages never free, and the dropped run's page, hold the source's bytes.
        for p in [1, long + 64, pages - 3, pages - 2, pages - 1] {
            assert_eq!(read(p), p + 1, "page {p} was captured");
        }
        drop(imported);
    }

    /// On a memversion host with TRACK (fpmv3 or later): the residency count an older kernel
    /// takes (TRACK_INFO2 answers ENOTTY, so MV_IOC_RESIDENT then `newly_retained`) over a
    /// reduced exclusion list equals the new pages the tracked CREATE given that list retains,
    /// both for a first fold whose dropped runs are present source-only pages and for a later
    /// fold over pages the first version already backs. Only TRACK_INFO2 is forced to ENOTTY:
    /// RESIDENT, TRACK and CREATE are the device's. Skips where the device or TRACK is absent.
    #[test]
    fn the_residency_count_over_a_reduced_list_equals_what_a_tracked_create_retains() {
        let Ok(device) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/memversion_v1")
        else {
            eprintln!("skipped: requires the pinned memversion host");
            return;
        };
        let page = crate::arch::host_page_size() as u64;
        let pages = 64 * 64;
        let regions = [Region {
            addr: GUEST_RAM_BASE,
            len: pages * page,
        }];
        let source = map_regions(&regions, None).unwrap();
        let at = |p: u64| (GUEST_RAM_BASE + p * page) as *mut u64;
        let fill = |range: std::ops::Range<u64>, tag: u64| {
            for p in range {
                // SAFETY: every page lies in the live, writable source mapping.
                unsafe { at(p).write((tag << 32) | p) };
            }
        };
        fill(0..pages, 1);
        if let Err(err) = track(device.as_fd(), &regions, None) {
            eprintln!("skipped: this device does not track: {err}");
            return;
        }
        let words = usize::try_from(pages / 64).unwrap();
        let residency = |runs: &[Exclusion]| {
            let counted = included_pages_with(
                runs,
                |_| Err(io::Error::from_raw_os_error(libc::ENOTTY)),
                || newly_retained(&regions, written_pages(device.as_fd(), &regions)?, runs),
            )
            .unwrap();
            let Included::Resident(pages) = counted else {
                panic!("an ENOTTY count came from {counted:?}");
            };
            pages
        };
        let fold = |runs: &[Exclusion]| {
            let version = create_tracked(device.as_fd(), &regions, runs, Fold::Quiesced).unwrap();
            info2(version.as_fd()).unwrap()
        };

        // First fold: free runs of 1..=8 pages in every word, cut to the 8 longest. Every page is
        // present and only the source maps it, so each dropped run is copied and retained.
        let free: Vec<u64> = (0..words)
            .map(|w| {
                let len = u32::try_from(w % 8).unwrap() + 1;
                ((1u64 << len) - 1) << 3
            })
            .collect();
        let first =
            exclusions_within(&regions, std::slice::from_ref(&free), &[vec![0; words]], 8).unwrap();
        assert!(
            first.found > first.runs.len() && first.dropped_pages > 0,
            "{first:?}"
        );
        let counted = residency(&first.runs);
        let info = fold(&first.runs);
        let kept: u64 = first.runs.iter().map(|x| x.len / page).sum();
        assert_eq!(counted, pages - kept, "residency count, first fold");
        assert_eq!(info.new_pages, counted, "first fold {info:?}");

        // Second fold: the guest rewrites a quarter of the pages, some of them in runs the first
        // fold excluded or dropped; the rest the first version already backs. A new reduction,
        // now to the 4 longest, with the rewritten pages dirty.
        let mut dirty = vec![0u64; words];
        for p in (0..pages).filter(|p| p % 4 == 1) {
            dirty[usize::try_from(p / 64).unwrap()] |= 1 << (p % 64);
        }
        for p in (0..pages).filter(|p| p % 4 == 1) {
            fill(p..p + 1, 2);
        }
        let second = exclusions_within(&regions, &[free], &[dirty], 4).unwrap();
        let counted = residency(&second.runs);
        let info = fold(&second.runs);
        assert_eq!(info.new_pages, counted, "second fold {info:?}");
        drop(source);
        untrack(device.as_fd()).unwrap();
    }

    #[test]
    fn an_exclusion_cap_can_only_lower_the_limit_and_a_bad_one_is_an_error() {
        assert_eq!(parse_exclusion_cap("1").unwrap(), 1);
        assert_eq!(parse_exclusion_cap("1024").unwrap(), 1024);
        assert_eq!(parse_exclusion_cap("65536").unwrap(), MAX_EXCLUSIONS);
        for bad in [
            "0",
            "65537",
            "4294967296",
            "-1",
            "",
            " 8",
            "8 ",
            "0x10",
            "1e3",
        ] {
            parse_exclusion_cap(bad).unwrap_err();
        }
        // Unset, every capture uses the kernel's limit.
        assert_eq!(exclusion_cap(), MAX_EXCLUSIONS);
    }

    #[test]
    fn create_once_all_regions_and_failures_publish_nothing() {
        let regions = [
            Region {
                addr: GUEST_RAM_BASE,
                len: 4096,
            },
            Region {
                addr: GUEST_RAM_BASE + 8192,
                len: 4096,
            },
        ];
        let fd = create_with(&regions, &[], |request| {
            assert_eq!(
                (
                    request.nr_regions,
                    request.nr_exclusions,
                    request.flags,
                    request.fd
                ),
                (2, 0, 0, -1)
            );
            assert_eq!(request.regions, regions.as_ptr() as u64);
            request.fd = std::fs::File::open("/dev/null")?.into_raw_fd();
            Ok(())
        })
        .unwrap();
        info(fd.as_fd()).unwrap_err();
        assert_eq!(
            create(fd.as_fd(), &regions, &[])
                .unwrap_err()
                .raw_os_error(),
            Some(libc::ENOTTY)
        );
        create_with(&regions, &[], |_| Ok(())).unwrap_err();
        create_with(&regions, &[], |_| {
            Err(io::Error::from_raw_os_error(libc::EBUSY))
        })
        .unwrap_err();
    }
}
