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

/// Exclude only reported-free pages with no subsequent KVM, ring or host write evidence.
/// If fragmentation exceeds the ABI limit, fail before CREATE; never truncate the bitmap.
pub(crate) fn exclusions(
    regions: &[Region],
    free: &[Vec<u64>],
    dirty: &[Vec<u64>],
) -> io::Result<Vec<Exclusion>> {
    let page = crate::arch::host_page_size() as u64;
    if free.len() != regions.len() || dirty.len() != regions.len() {
        return Err(invalid());
    }
    let mut out = Vec::new();
    for (index, region) in regions.iter().enumerate() {
        let pages = region.len / page;
        let words = usize::try_from(pages.div_ceil(64)).map_err(|_| invalid())?;
        if free[index].len() != words || dirty[index].len() != words {
            return Err(invalid());
        }
        let mut run = None;
        for p in 0..=pages {
            let word = usize::try_from(p / 64).map_err(|_| invalid())?;
            let excluded =
                p < pages && (free[index][word] & !dirty[index][word]) & (1 << (p % 64)) != 0;
            if excluded {
                run.get_or_insert(p);
            } else if let Some(start) = run.take() {
                if out.len() == MAX_EXCLUSIONS {
                    return Err(invalid());
                }
                out.push(Exclusion {
                    region: u32::try_from(index).map_err(|_| invalid())?,
                    reserved: 0,
                    offset: start * page,
                    len: (p - start) * page,
                });
            }
        }
    }
    Ok(out)
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
    if regions.is_empty() || regions.len() > MAX_REGIONS || exclusions.len() > MAX_EXCLUSIONS {
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
        .unwrap();
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
