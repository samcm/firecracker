// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Frozen v1 UAPI. Firecracker borrows the device capability from pagemaster; never opens it.
//! The companion integration stub is resources/memversion.h, not the research ioctl ABI.

use std::io;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};

use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_ref};
use vmm_sys_util::{ioctl_iow_nr, ioctl_iowr_nr};

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
    if regions.is_empty() || regions.len() > MAX_REGIONS || exclusions.len() > MAX_EXCLUSIONS {
        return Err(invalid());
    }
    let mut request = Create {
        regions: regions.as_ptr() as u64,
        exclusions: exclusions.as_ptr() as u64,
        nr_regions: u32::try_from(regions.len()).unwrap(),
        nr_exclusions: u32::try_from(exclusions.len()).unwrap(),
        flags: 0,
        fd: -1,
    };
    ioctl(&mut request)?;
    if request.fd < 0 {
        return Err(invalid());
    }
    // SAFETY: successful CREATE transfers exactly this newly allocated CLOEXEC fd to the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(request.fd) })
}

/// Caller releases only its own reservation immediately before this NOREPLACE operation.
pub(crate) fn map_private(version: BorrowedFd<'_>, region: u32, addr: u64) -> io::Result<()> {
    let request = Map {
        region,
        flags: 1,
        addr,
    };
    // SAFETY: the fixed-size request remains live; the kernel rejects occupied destinations.
    if unsafe { ioctl_with_ref(&version, MV_IOC_MAP(), &request) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
