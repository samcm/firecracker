// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ignored, destructive-to-explicit-scratch kernel experiment, absent from release builds.
//! Run ONE case per process: FC_BUDGET_CASE=read|write|failed|oversize,
//! FC_BUDGET_SCRATCH=/dev/vda, FC_BUDGET_ALLOW_DESTROY_SCRATCH=YES.
//! Requires the experimental kernel and a fresh 64MiB raw QEMU scratch disk, never passthrough.
//! This tests actual FC block/dispatch primitives, not a running VMM, KVM pause, or memory export.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use vmm_sys_util::{ioctl_io_nr, ioctl_ior_nr, ioctl_iow_nr};

use super::*;
use crate::devices::virtio::block::virtio::test_utils::{
    default_block_with_descriptor, read_blk_req_descriptors,
};
use crate::devices::virtio::queue::VIRTQ_DESC_F_NEXT;
use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
use crate::snapshot::Persist;
use crate::test_utils::single_region_mem;
use crate::vstate::farplane::dispatch;
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemory};

// Exact experimental header SHA256:
// c215c3a6da4f63c911e8bd17c87888ff6e37783bcb7a80e5b07af8531cffc99b.
// No production ABI or memory-version interface is implied.
#[repr(C)]
struct Range {
    addr: u64,
    len: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
struct OpStats {
    reserved: u64,
    spent: u64,
    inflight: u64,
    refunded: u64,
    active: u64,
    requests: u64,
    bios: u64,
    bios_done: u64,
    worker_issues: u64,
    unauth_denied: u64,
    exhausted: u64,
    ended: u64,
    peak_inflight: u64,
    serialized: u64,
}

ioctl_iow_nr!(ENROLL, 0x42, 1, Range);
ioctl_ior_nr!(STATS, 0x42, 3, [u64; 7]);
ioctl_iow_nr!(OP_RESERVE, 0x42, 6, u64);
ioctl_io_nr!(OP_ENTER, 0x42, 7);
ioctl_io_nr!(OP_LEAVE, 0x42, 8);
ioctl_ior_nr!(OP_STATS, 0x42, 9, OpStats);
ioctl_io_nr!(OP_FINISH, 0x42, 10);

fn call<T>(fd: &File, request: u64, value: &mut T) -> io::Result<()> {
    // SAFETY: each call below pairs its exact experimental ioctl with the matching repr(C)
    // object or scalar; no-argument commands ignore the additional pointer.
    if unsafe { vmm_sys_util::ioctl::ioctl_with_mut_ref(fd, request, value) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn stats(fd: &File) -> OpStats {
    let mut result = OpStats::default();
    call(fd, OP_STATS(), &mut result).unwrap();
    result
}

/// Holds anonymous pages shared BEFORE enrollment. The child never executes Rust after fork.
/// Closing the pipe releases it normally; parent death also kills it, including setup failures.
struct SharingChild {
    wake: OwnedFd,
    pid: libc::pid_t,
}

impl SharingChild {
    fn new() -> Self {
        let mut pipe = [0; 2];
        assert_eq!(
            // SAFETY: writable two-fd output array.
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: fresh unique fds returned by pipe2.
        let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        // SAFETY: fresh unique fd returned by pipe2.
        let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        // SAFETY: getpid has no preconditions.
        let parent = unsafe { libc::getpid() };
        // SAFETY: the child invokes only libc syscalls and _exit, no allocator or Rust locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // SAFETY: inherited fds are valid; _exit avoids all inherited Rust destructors.
            unsafe {
                libc::close(write.as_raw_fd());
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() != parent
                {
                    libc::_exit(1);
                }
                let mut byte = 0u8;
                libc::read(read.as_raw_fd(), std::ptr::from_mut(&mut byte).cast(), 1);
                libc::_exit(0);
            }
        }
        drop(read);
        Self { wake: write, pid }
    }
}

impl Drop for SharingChild {
    fn drop(&mut self) {
        // SAFETY: one byte to our live pipe wakes the child without running Rust in it.
        unsafe { libc::write(self.wake.as_raw_fd(), b"x".as_ptr().cast(), 1) };
        let mut status = 0;
        loop {
            // SAFETY: wait only for the child this object owns; status points to live storage.
            if unsafe { libc::waitpid(self.pid, &mut status, 0) } == self.pid {
                break;
            }
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EINTR));
        }
    }
}

#[test]
fn memory_budget_baseline_header_and_sharing_holder() {
    // Values independently emitted by C compiled against the transferred header, not merely
    // compared to another Rust definition of the same layout.
    assert_eq!(std::mem::size_of::<Range>(), 16);
    assert_eq!(std::mem::size_of::<OpStats>(), 112);
    assert_eq!(std::mem::offset_of!(OpStats, bios_done), 56);
    assert_eq!(std::mem::offset_of!(OpStats, ended), 88);
    assert_eq!(std::mem::offset_of!(OpStats, serialized), 104);
    assert_eq!(
        [
            ENROLL(),
            STATS(),
            OP_RESERVE(),
            OP_ENTER(),
            OP_LEAVE(),
            OP_STATS(),
            OP_FINISH()
        ],
        [
            0x40104201, 0x80384203, 0x40084206, 0x4207, 0x4208, 0x80704209, 0x420a
        ]
    );
    let null = File::open("/dev/null").unwrap();
    assert_eq!(
        call(&null, OP_STATS(), &mut OpStats::default())
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ENOTTY)
    );
    drop(SharingChild::new());
}

#[test]
#[ignore = "requires experimental mv-budget kernel and explicitly disposable raw scratch disk"]
fn memory_budget_single_operation_raw() {
    const LEN: u32 = 65536;
    const MEM_LEN: usize = 0x40000;
    assert_eq!(std::mem::size_of::<OpStats>(), 112);
    assert_eq!(
        std::env::var("FC_BUDGET_ALLOW_DESTROY_SCRATCH").as_deref(),
        Ok("YES")
    );
    let case = std::env::var("FC_BUDGET_CASE").unwrap();
    assert!(matches!(
        case.as_str(),
        "read" | "write" | "failed" | "oversize"
    ));
    let path = std::env::var("FC_BUDGET_SCRATCH").unwrap();
    let mut seed = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(seed.metadata().unwrap().file_type().is_block_device());
    assert_eq!(seed.seek(SeekFrom::End(0)).unwrap(), 64 << 20);
    seed.seek(SeekFrom::Start(0)).unwrap();
    seed.write_all(&vec![0x35; 2 * LEN as usize]).unwrap();
    seed.sync_all().unwrap();
    let direct = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_DIRECT)
        .open(&path)
        .unwrap();

    let mem = single_region_mem(MEM_LEN);
    let base = mem.get_host_address(GuestAddress(0)).unwrap();
    assert_eq!(
        // SAFETY: the entire anonymous guest mapping is live, page-aligned and owned by mem.
        unsafe { libc::madvise(base.cast(), MEM_LEN, libc::MADV_NOHUGEPAGE) },
        0
    );
    let driver = VirtQueue::new(GuestAddress(0x1000), &mem, 256);
    read_blk_req_descriptors(&driver);
    let header = GuestAddress(0x4ff8);
    // Raw-block DIO must reject the misaligned pointer via a failed CQE, still owing status
    // and used-ring writes. No attempt to make kernel allocation fail by removing funding.
    let payload = GuestAddress(if case == "failed" { 0x8201 } else { 0x8200 });
    let status = GuestAddress(0x7000);
    driver.dtable[0].addr.set(header.0);
    driver.dtable[1].addr.set(payload.0);
    driver.dtable[1].len.set(LEN);
    driver.dtable[2].addr.set(status.0);
    if case == "write" {
        driver.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        mem.write_slice(&vec![0xa6; LEN as usize], payload).unwrap();
    }
    mem.write_obj(
        RequestHeader::new(
            if case == "write" {
                VIRTIO_BLK_T_OUT
            } else {
                VIRTIO_BLK_T_IN
            },
            0,
        ),
        header,
    )
    .unwrap();
    mem.write_obj(0xffu8, status).unwrap();
    // An earlier preflight sees 64KiB; the authoritative parse must reject the changed 128KiB.
    assert_eq!(driver.dtable[1].len.get(), LEN);
    if case == "oversize" {
        driver.dtable[1].len.set(2 * LEN);
    }
    let holder = SharingChild::new();
    let mut block = default_block_with_descriptor(direct.as_raw_fd(), false, FileEngineType::Async);
    block.queues[0] = driver.create_queue();
    block.acked_features |= 1 << VIRTIO_RING_F_EVENT_IDX;
    block.activate(mem.clone(), default_interrupt()).unwrap();
    let FileEngine::Async(engine) = &mut block.disk.file_engine else {
        unreachable!()
    };
    engine.force_async_for_test();

    // This thread is created before ENTER; it closes actual FC dispatch while our hold is live.
    let (stop_tx, stop_rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        stop_rx.recv().unwrap();
        dispatch::gate().close();
    });
    let budget = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mv-budget-spike")
        .unwrap();
    call(
        &budget,
        ENROLL(),
        &mut Range {
            addr: base as u64,
            len: MEM_LEN as u64,
        },
    )
    .unwrap();
    call(&budget, OP_RESERVE(), &mut 26u64).unwrap();
    call(&budget, OP_ENTER(), &mut 0u64).unwrap();
    assert_eq!(
        call(&budget, OP_FINISH(), &mut 0u64)
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EBUSY)
    );
    let hold = dispatch::gate().enter();
    // One admitted request ONLY. No unfunded second pop, notification-arm loop, or reentry.
    let head = block.queues[0]
        .pop_or_enable_notification()
        .unwrap()
        .unwrap();
    let request = Request::parse(&head, &mem, block.disk.nsectors).unwrap();
    let rejected = request.data_len > LEN;
    assert_eq!(rejected, case == "oversize");
    if rejected {
        block.queues[0].undo_pop();
    } else {
        assert!(matches!(request.r#type, RequestType::In | RequestType::Out));
        assert!(matches!(
            request.process(&mut block.disk, false, head.index, &mem, &block.metrics),
            ProcessingResult::Submitted
        ));
        let FileEngine::Async(engine) = &mut block.disk.file_engine else {
            unreachable!()
        };
        engine.kick_submission_queue().unwrap();
    }
    stop_tx.send(()).unwrap();
    dispatch::gate().wait_for_closing(1);
    call(&budget, OP_LEAVE(), &mut 0u64).unwrap();
    drop(hold);
    stopper.join().unwrap();
    assert!(dispatch::gate().is_closed());

    call(&budget, OP_ENTER(), &mut 0u64).unwrap();
    // Direct drain never invokes process_async_completion_event's admission restart.
    block.drain_writes().unwrap();
    assert_eq!(driver.used.idx.get(), u16::from(!rejected));
    assert_eq!(
        mem.read_obj::<u8>(status).unwrap(),
        if rejected {
            0xff
        } else if case == "failed" {
            1
        } else {
            0
        }
    );
    if !rejected {
        assert_eq!(
            driver.used.ring[0].get().len,
            if case == "read" { LEN + 1 } else { 1 }
        );
    }
    if matches!(case.as_str(), "read" | "write") {
        let mut actual = vec![0; LEN as usize];
        mem.read_slice(&mut actual, payload).unwrap();
        assert!(
            actual
                .iter()
                .all(|byte| *byte == if case == "write" { 0xa6 } else { 0x35 })
        );
    }
    // Device-only state, not a full VM capture. No guest payload copies for this serialization.
    let state_bytes = bitcode::serialize(&block.save()).unwrap();
    assert!(!state_bytes.is_empty());
    call(&budget, OP_LEAVE(), &mut 0u64).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let FileEngine::Async(engine) = &block.disk.file_engine else {
            unreachable!()
        };
        engine.run_task_work_for_test().unwrap();
        match call(&budget, OP_FINISH(), &mut 0u64) {
            Ok(()) => break,
            Err(err) if err.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => panic!("OP_FINISH failed: {err}; {:?}", stats(&budget)),
        }
    }
    let final_stats = stats(&budget);
    println!("FC_SINGLE_OP case={case} {final_stats:?}");
    assert_eq!(final_stats.reserved, 26);
    assert!(final_stats.spent > 0 && final_stats.spent <= 26);
    assert_eq!(
        (
            final_stats.active,
            final_stats.requests,
            final_stats.bios,
            final_stats.inflight
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(final_stats.exhausted, 0);
    assert_eq!(final_stats.ended, 1);
    if rejected {
        assert_eq!((final_stats.worker_issues, final_stats.bios_done), (0, 0));
    } else if case == "failed" {
        assert!(final_stats.worker_issues > 0);
    } else {
        assert!(final_stats.worker_issues > 0 && final_stats.bios_done > 0);
        assert!(
            final_stats.spent >= 17,
            "payload must allocate/unshare its 17 pages"
        );
    }
    let mut ordinary = [0u64; 7];
    call(&budget, STATS(), &mut ordinary).unwrap();
    assert_eq!(ordinary[0], 0, "ordinary grant must stay zero");
    assert_eq!(ordinary[4], 0, "unsupported faults must not be hidden");
    assert!(call(&budget, OP_RESERVE(), &mut 26u64).is_err());
    // No authority or renewed grant during destruction. No pending I/O remains by FINISH proof.
    drop(block);
    drop(holder);
    assert_eq!(
        stats(&budget).spent,
        final_stats.spent,
        "successful spend is not refunded on drop"
    );
    let mut disk = vec![0; LEN as usize];
    seed.seek(SeekFrom::Start(0)).unwrap();
    seed.read_exact(&mut disk).unwrap();
    assert!(
        disk.iter()
            .all(|byte| *byte == if case == "write" { 0xa6 } else { 0x35 })
    );
    println!("FC_SINGLE_OP_DEVICE_PASS case={case}; NOT full VM stop/capture proof");
}
