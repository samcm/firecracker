// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bring-up prefault: warms a restored child's stage-2 tables over the pages an earlier child of
//! the same lineage touched during bring-up, while the vCPUs are still paused.
//!
//! A restored VM starts with empty stage-2 tables, so every page its first instructions touch
//! costs a VM exit and a host fault, and every page they write costs a copy-on-write of the
//! version's page as well. The hot set names those pages. This worker first copies the written
//! pages privately (`MADV_POPULATE_WRITE`), within a byte budget the supervisor derived from the
//! child's memory envelope, and then maps every named page into the stage-2 tables with
//! `KVM_PRE_FAULT_MEMORY`.
//!
//! The set is a hint. Prefaulting any page of guest memory is correct, and a page the set misses
//! faults the ordinary way, so a stale, wrong or partial set costs prefetch work and nothing else:
//! a range that lies outside guest memory is dropped, and a call that fails abandons only its
//! range. The worker never delays resume by more than one chunk: resume raises the stop flag and
//! joins, and whatever was not reached by then faults normally.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use vm_memory::{Address, GuestAddress, GuestMemory, GuestMemoryRegion, MemoryRegionAddress};

use crate::logger::{error, info};
use crate::vstate::memory::GuestMemoryMmap;

/// Largest amount of work one call does, so a raised stop flag waits for at most one chunk.
pub const CHUNK_BYTES: u64 = 256 << 10;
/// Page size the hot set is expressed in.
const PAGE_BYTES: u64 = 4096;
/// `KVM_PRE_FAULT_MEMORY`: `_IOWR(KVMIO, 0xd5, struct kvm_pre_fault_memory)`.
const KVM_PRE_FAULT_MEMORY: libc::c_ulong = 0xC040_AED5;
/// `MADV_POPULATE_WRITE`, Linux 5.14.
const MADV_POPULATE_WRITE: libc::c_int = 23;

/// Decodes an FPHS v1 hot set into (gpa, size, written) entries, or `None` for anything that is
/// not exactly a canonical set.
pub fn decode_entries(encoded: &[u8]) -> Option<Vec<(u64, u64, bool)>> {
    let set = super::hot_set::HotSet::decode(encoded).ok()?;
    Some(
        set.ranges()
            .iter()
            .map(|r| (r.gpa, r.size, r.flags & super::hot_set::FLAG_WRITTEN != 0))
            .collect(),
    )
}

/// One hot-set range resolved against this VM's guest memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefaultRange {
    /// Guest-physical address of the first page.
    pub gpa: u64,
    /// Host virtual address of the same page in this process.
    pub host: usize,
    /// Length in bytes, a whole number of pages.
    pub size: u64,
    /// Whether the recording child wrote these pages.
    pub written: bool,
}

/// What the worker did before it finished or was stopped.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrefaultReport {
    /// Bytes copied privately ahead of the guest's writes.
    pub precow_bytes: u64,
    /// Bytes mapped into the stage-2 tables.
    pub prefaulted_bytes: u64,
    /// Ranges abandoned because a call on them failed.
    pub abandoned_ranges: u32,
    /// Whether resume stopped the worker before it reached the end.
    pub stopped: bool,
    /// Wall time the worker ran.
    pub micros: u64,
}

/// The two operations the worker performs, separated so its scheduling can be tested without KVM.
pub(crate) trait PrefaultOps {
    /// Copies `len` bytes at `host` privately, as a write would.
    fn populate_write(&mut self, host: usize, len: u64) -> io::Result<()>;
    /// Maps `len` bytes at `gpa` into the stage-2 tables.
    fn pre_fault(&mut self, gpa: u64, len: u64) -> io::Result<()>;
}

/// Resolves hot-set entries against guest memory. An entry that is not page-aligned or does not
/// lie inside one guest-memory region is dropped: the set is a hint about pages, not a claim
/// about this VM's layout. Returns the resolved ranges and how many entries were dropped.
pub fn resolve(
    memory: &GuestMemoryMmap,
    entries: impl IntoIterator<Item = (u64, u64, bool)>,
) -> (Vec<PrefaultRange>, u32) {
    let mut ranges = Vec::new();
    let mut dropped = 0u32;
    for (gpa, size, written) in entries {
        let resolved = (gpa % PAGE_BYTES == 0 && size % PAGE_BYTES == 0 && size > 0)
            .then(|| memory.find_region(GuestAddress(gpa)))
            .flatten()
            .and_then(|region| {
                let offset = gpa - region.start_addr().raw_value();
                let end = offset.checked_add(size)?;
                (end <= region.len())
                    .then(|| region.get_host_address(MemoryRegionAddress(offset)).ok())
                    .flatten()
            });
        match resolved {
            Some(host) => ranges.push(PrefaultRange {
                gpa,
                host: host as usize,
                size,
                written,
            }),
            None => dropped += 1,
        }
    }
    (ranges, dropped)
}

/// Runs the hot set: written ranges are copied privately first, in order, until the budget is
/// spent; then every range is mapped into the stage-2 tables. A written range the budget did not
/// cover is still mapped, for read. Stops between chunks once `stop` is raised.
pub(crate) fn run(
    ops: &mut impl PrefaultOps,
    ranges: &[PrefaultRange],
    precow_budget: u64,
    stop: &AtomicBool,
) -> PrefaultReport {
    let started = Instant::now();
    let mut report = PrefaultReport::default();
    let mut budget = precow_budget - precow_budget % PAGE_BYTES;
    let stopped = |report: &mut PrefaultReport| {
        let raised = stop.load(Ordering::Acquire);
        report.stopped |= raised;
        raised
    };

    'precow: for range in ranges.iter().filter(|range| range.written) {
        let mut offset = 0;
        while offset < range.size {
            if budget == 0 {
                break 'precow;
            }
            if stopped(&mut report) {
                report.micros = elapsed_micros(started);
                return report;
            }
            let len = CHUNK_BYTES.min(range.size - offset).min(budget);
            let host = range.host + usize::try_from(offset).expect("offset fits in usize");
            if ops.populate_write(host, len).is_err() {
                report.abandoned_ranges += 1;
                break;
            }
            report.precow_bytes += len;
            budget -= len;
            offset += len;
        }
    }

    for range in ranges {
        let mut offset = 0;
        while offset < range.size {
            if stopped(&mut report) {
                report.micros = elapsed_micros(started);
                return report;
            }
            let len = CHUNK_BYTES.min(range.size - offset);
            if ops.pre_fault(range.gpa + offset, len).is_err() {
                report.abandoned_ranges += 1;
                break;
            }
            report.prefaulted_bytes += len;
            offset += len;
        }
    }
    report.micros = elapsed_micros(started);
    report
}

fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

/// Copies `len` bytes at `host` privately, as a guest write would, without changing their content.
pub(crate) fn populate_write(host: usize, len: u64) -> io::Result<()> {
    let len = usize::try_from(len).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: the range lies inside a guest-memory mapping this process holds for its lifetime;
    // MADV_POPULATE_WRITE faults pages in for write and never changes their content.
    let ret = unsafe { libc::madvise(host as *mut libc::c_void, len, MADV_POPULATE_WRITE) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The operations on a real VM: madvise on this process's guest memory, and
/// `KVM_PRE_FAULT_MEMORY` on a duplicate of the first vCPU's descriptor.
struct KvmOps {
    vcpu: OwnedFd,
}

impl PrefaultOps for KvmOps {
    fn populate_write(&mut self, host: usize, len: u64) -> io::Result<()> {
        populate_write(host, len)
    }

    fn pre_fault(&mut self, gpa: u64, len: u64) -> io::Result<()> {
        let mut range = kvm_bindings::kvm_pre_fault_memory {
            gpa,
            size: len,
            ..Default::default()
        };
        // KVM maps part of the range and returns early on a pending signal or a contended MMU
        // lock, leaving gpa and size describing what is left.
        while range.size > 0 {
            // SAFETY: the descriptor is a vCPU of this VM, and `range` is a live
            // kvm_pre_fault_memory that KVM reads and updates.
            let ret = unsafe {
                libc::ioctl(
                    self.vcpu.as_raw_fd(),
                    KVM_PRE_FAULT_MEMORY as _,
                    &mut range as *mut kvm_bindings::kvm_pre_fault_memory,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                    _ => return Err(err),
                }
            }
        }
        Ok(())
    }
}

/// A running bring-up prefault.
#[derive(Debug)]
pub struct Prefaulter {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<PrefaultReport>,
}

/// The prefault of the VM this process restored, until resume stops it.
static ACTIVE: Mutex<Option<Prefaulter>> = Mutex::new(None);

impl Prefaulter {
    /// Starts the worker on its own thread, confined by `filter`. `vcpu` is a duplicate of a
    /// vCPU descriptor of this VM; the vCPU must not run until the worker is stopped, because
    /// `KVM_PRE_FAULT_MEMORY` and `KVM_RUN` take the same vCPU lock.
    pub fn start(
        vcpu: OwnedFd,
        ranges: Vec<PrefaultRange>,
        precow_budget: u64,
        filter: Arc<crate::seccomp::BpfProgram>,
    ) -> io::Result<()> {
        let stop = Arc::new(AtomicBool::new(false));
        let raised = stop.clone();
        let handle = std::thread::Builder::new()
            .name("fc_prefault".to_string())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    error!("Bring-up prefault could not install its filter: {err}");
                    return PrefaultReport::default();
                }
                run(&mut KvmOps { vcpu }, &ranges, precow_budget, &raised)
            })?;
        *ACTIVE.lock().expect("Poisoned lock") = Some(Self { stop, handle });
        Ok(())
    }

    /// Stops the worker, if one is running, and waits for its chunk in flight. Called before the
    /// vCPUs first run.
    pub fn stop() -> Option<PrefaultReport> {
        let prefaulter = ACTIVE.lock().expect("Poisoned lock").take()?;
        prefaulter.stop.store(true, Ordering::Release);
        let report = prefaulter.handle.join().unwrap_or_default();
        info!(
            "Bring-up prefault: precow {} B, prefaulted {} B, abandoned {} ranges, stopped {}, \
             {} us",
            report.precow_bytes,
            report.prefaulted_bytes,
            report.abandoned_ranges,
            report.stopped,
            report.micros
        );
        Some(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder {
        populated: Vec<(usize, u64)>,
        prefaulted: Vec<(u64, u64)>,
        fail_populate_at: Option<usize>,
        fail_prefault_at: Option<u64>,
        stop_after_calls: Option<(usize, Arc<AtomicBool>)>,
        calls: usize,
    }

    impl Recorder {
        fn tick(&mut self) {
            self.calls += 1;
            if let Some((after, stop)) = &self.stop_after_calls
                && self.calls >= *after
            {
                stop.store(true, Ordering::Release);
            }
        }
    }

    impl PrefaultOps for Recorder {
        fn populate_write(&mut self, host: usize, len: u64) -> io::Result<()> {
            self.tick();
            if self.fail_populate_at == Some(host) {
                return Err(io::Error::from_raw_os_error(libc::EFAULT));
            }
            self.populated.push((host, len));
            Ok(())
        }

        fn pre_fault(&mut self, gpa: u64, len: u64) -> io::Result<()> {
            self.tick();
            if self.fail_prefault_at == Some(gpa) {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            }
            self.prefaulted.push((gpa, len));
            Ok(())
        }
    }

    fn range(gpa: u64, pages: u64, written: bool) -> PrefaultRange {
        PrefaultRange {
            gpa,
            host: 0x7000_0000_0000 + usize::try_from(gpa).unwrap(),
            size: pages * PAGE_BYTES,
            written,
        }
    }

    fn total(calls: &[(impl Copy, u64)]) -> u64 {
        calls.iter().map(|(_, len)| len).sum()
    }

    #[test]
    fn precow_stops_at_the_budget_and_the_rest_is_prefaulted_for_read() {
        // 100 written pages against a 37-page budget, a read range between two written ones.
        let ranges = [
            range(0x10_0000, 30, true),
            range(0x20_0000, 50, false),
            range(0x40_0000, 70, true),
        ];
        let mut ops = Recorder::default();
        // A budget that is not page-aligned is rounded down, never up.
        let budget = 37 * PAGE_BYTES + 100;
        let report = run(&mut ops, &ranges, budget, &AtomicBool::new(false));
        assert_eq!(total(&ops.populated), 37 * PAGE_BYTES);
        assert_eq!(report.precow_bytes, 37 * PAGE_BYTES);
        // Pre-COW takes the written ranges in order: all of the first, then 7 pages of the third.
        assert_eq!(ops.populated[0], (ranges[0].host, 30 * PAGE_BYTES));
        assert_eq!(ops.populated[1], (ranges[2].host, 7 * PAGE_BYTES));
        // Nothing read-only is ever copied.
        assert!(
            ops.populated
                .iter()
                .all(|(host, _)| *host != ranges[1].host)
        );
        // Every range, written or not, is mapped in full.
        assert_eq!(total(&ops.prefaulted), 150 * PAGE_BYTES);
        assert_eq!(report.prefaulted_bytes, 150 * PAGE_BYTES);
        assert!(!report.stopped);
    }

    #[test]
    fn a_zero_budget_copies_nothing() {
        let ranges = [range(0, 8, true)];
        let mut ops = Recorder::default();
        let report = run(&mut ops, &ranges, PAGE_BYTES - 1, &AtomicBool::new(false));
        assert!(ops.populated.is_empty());
        assert_eq!(report.precow_bytes, 0);
        assert_eq!(report.prefaulted_bytes, 8 * PAGE_BYTES);
    }

    #[test]
    fn no_call_is_larger_than_a_chunk() {
        let ranges = [range(0, 1000, true)];
        let mut ops = Recorder::default();
        run(&mut ops, &ranges, u64::MAX, &AtomicBool::new(false));
        assert!(ops.populated.iter().all(|(_, len)| *len <= CHUNK_BYTES));
        assert!(ops.prefaulted.iter().all(|(_, len)| *len <= CHUNK_BYTES));
        assert_eq!(total(&ops.populated), 1000 * PAGE_BYTES);
        assert_eq!(total(&ops.prefaulted), 1000 * PAGE_BYTES);
    }

    #[test]
    fn a_raised_stop_ends_the_work_after_the_chunk_in_flight() {
        let ranges = [range(0, 1000, true), range(0x100_0000, 1000, false)];
        let stop = Arc::new(AtomicBool::new(false));
        let mut ops = Recorder {
            stop_after_calls: Some((3, stop.clone())),
            ..Default::default()
        };
        let report = run(&mut ops, &ranges, u64::MAX, &stop);
        assert!(report.stopped);
        assert_eq!(ops.calls, 3);
        assert!(ops.prefaulted.is_empty());
        assert_eq!(report.precow_bytes, 3 * CHUNK_BYTES);
    }

    #[test]
    fn a_stop_raised_before_the_start_does_nothing() {
        let ranges = [range(0, 10, true)];
        let mut ops = Recorder::default();
        let report = run(&mut ops, &ranges, u64::MAX, &AtomicBool::new(true));
        assert_eq!(ops.calls, 0);
        assert!(report.stopped);
    }

    #[test]
    fn a_failed_call_abandons_only_its_range() {
        let ranges = [
            range(0x10_0000, 4, true),
            range(0x20_0000, 4, true),
            range(0x30_0000, 4, false),
        ];
        let mut ops = Recorder {
            fail_populate_at: Some(ranges[0].host),
            fail_prefault_at: Some(0x30_0000),
            ..Default::default()
        };
        let report = run(&mut ops, &ranges, u64::MAX, &AtomicBool::new(false));
        assert_eq!(ops.populated, vec![(ranges[1].host, 4 * PAGE_BYTES)]);
        assert_eq!(
            ops.prefaulted,
            vec![(0x10_0000, 4 * PAGE_BYTES), (0x20_0000, 4 * PAGE_BYTES)]
        );
        assert_eq!(report.abandoned_ranges, 2);
    }

    #[test]
    fn resolve_drops_what_is_not_inside_one_region() {
        let memory = crate::test_utils::single_region_mem_at(0x10_0000, 0x10_0000);
        let base = memory.get_host_address(GuestAddress(0x10_0000)).unwrap() as usize;
        let (ranges, dropped) = resolve(
            &memory,
            [
                (0x10_0000, 2 * PAGE_BYTES, true),
                // Below guest memory.
                (0, PAGE_BYTES, false),
                // Starts inside, ends past the region.
                (0x1F_F000, 2 * PAGE_BYTES, false),
                // Not page-aligned.
                (0x10_0800, PAGE_BYTES, false),
                // Empty.
                (0x12_0000, 0, false),
                (0x1F_F000, PAGE_BYTES, false),
            ],
        );
        assert_eq!(dropped, 4);
        assert_eq!(
            ranges,
            vec![
                PrefaultRange {
                    gpa: 0x10_0000,
                    host: base,
                    size: 2 * PAGE_BYTES,
                    written: true
                },
                PrefaultRange {
                    gpa: 0x1F_F000,
                    host: base + 0xF_F000,
                    size: PAGE_BYTES,
                    written: false
                },
            ]
        );
    }

    /// Anonymous bytes the mapping at `addr` holds, from this process's smaps: in a private
    /// file mapping, exactly the pages copied on write.
    fn copied_bytes(addr: usize) -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        for line in smaps.lines() {
            if let Some((range, _)) = line.split_once(' ')
                && let Some((start, end)) = range.split_once('-')
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                inside = (start..end).contains(&addr);
                continue;
            }
            if inside && let Some(rest) = line.strip_prefix("Anonymous:") {
                let kib: u64 = rest.trim().trim_end_matches(" kB").trim().parse().unwrap();
                return kib * 1024;
            }
        }
        panic!("no mapping at {addr:#x}");
    }

    #[test]
    fn precow_of_a_shared_file_mapping_creates_exactly_the_budget_in_private_copies() {
        // A private mapping of a populated memfd stands in for a version view: reads share the
        // file's pages, and each write copies one page privately, which is what the child's
        // memory envelope is charged for.
        const PAGES: u64 = 256;
        let size = PAGES * PAGE_BYTES;
        let len = usize::try_from(size).unwrap();
        // SAFETY: plain syscalls on descriptors and a mapping this test owns.
        let addr = unsafe {
            let fd = libc::memfd_create(c"prefault-test".as_ptr(), 0);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, libc::off_t::try_from(size).unwrap()), 0);
            let buf = vec![0x5Au8; len];
            assert_eq!(
                libc::pwrite(fd, buf.as_ptr().cast(), buf.len(), 0),
                isize::try_from(size).unwrap()
            );
            let addr = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd,
                0,
            );
            assert_ne!(addr, libc::MAP_FAILED);
            libc::close(fd);
            addr as usize
        };
        // Read everything first, so every page is mapped shared and the copies are what remains.
        // SAFETY: the mapping is `size` bytes long and readable.
        let sum: u64 = unsafe { std::slice::from_raw_parts(addr as *const u8, len) }
            .iter()
            .map(|b| u64::from(*b))
            .sum();
        assert_eq!(sum, 0x5A * size);
        assert_eq!(copied_bytes(addr), 0);

        struct Madvise;
        impl PrefaultOps for Madvise {
            fn populate_write(&mut self, host: usize, len: u64) -> io::Result<()> {
                populate_write(host, len)
            }
            fn pre_fault(&mut self, _gpa: u64, _len: u64) -> io::Result<()> {
                Ok(())
            }
        }
        let ranges = [
            PrefaultRange {
                gpa: 0,
                host: addr,
                size: 100 * PAGE_BYTES,
                written: true,
            },
            PrefaultRange {
                gpa: 100 * PAGE_BYTES,
                host: addr + usize::try_from(100 * PAGE_BYTES).unwrap(),
                size: 156 * PAGE_BYTES,
                written: true,
            },
        ];
        let budget = 130 * PAGE_BYTES;
        let report = run(&mut Madvise, &ranges, budget, &AtomicBool::new(false));
        assert_eq!(report.precow_bytes, budget);
        assert_eq!(copied_bytes(addr), budget);
        // The copies hold the file's content: pre-COW changes no byte the guest sees.
        // SAFETY: as above.
        let sum: u64 = unsafe { std::slice::from_raw_parts(addr as *const u8, len) }
            .iter()
            .map(|b| u64::from(*b))
            .sum();
        assert_eq!(sum, 0x5A * size);
        // SAFETY: unmapping the mapping this test created.
        unsafe { libc::munmap(addr as *mut libc::c_void, len) };
    }
}
