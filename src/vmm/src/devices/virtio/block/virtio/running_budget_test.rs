// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only manually constructed VMM: no production backend switch or UFFD fallback.
//! Needs /dev/kvm, the same experimental budget header, tty stdin, and disposable raw scratch.
//! One 64KiB READ is host-admitted while a real guest independently blocks on a COW store.
//! No guest driver, event-loop fairness, net/vsock/rng/reporting or durable RAM export is tested.
//! Normal VMGenID/VMClock activation runs before enrollment; their save is host-state-only.

use std::sync::{Arc, Mutex};

use super::*;
use crate::device_manager::DeviceManager;
use crate::devices::virtio::block::device::Block;
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::test_utils::single_region_mem_raw;
use crate::vmm_config::instance_info::{InstanceInfo, VmState};
use crate::vmm_config::machine_config::MachineConfig;
use crate::vstate::bus::BusDevice;
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::MemoryRegionAddress;
use crate::vstate::vm::{KvmVm, Vm};
use crate::{EventManager, Vmm};

const CODE: u64 = 0x2000;
const HEARTBEAT: u64 = 0x6000;
const TARGET: u64 = 0x7000;
const FAULT_RIP: u64 = CODE + 5;
// Real-mode x86: mov byte [0x6000],1; mov byte [0x7000],0xa7; jmp $.
// IF stays clear, no stack, interrupts, page tables, BIOS or guest kernel needed.
const GUEST: [u8; 12] = [
    0xc6, 0x06, 0x00, 0x60, 0x01, 0xc6, 0x06, 0x00, 0x70, 0xa7, 0xeb, 0xfe,
];

#[test]
fn memory_budget_baseline_running_guest_layout() {
    assert_eq!(
        u64::from(u16::from_le_bytes([GUEST[2], GUEST[3]])),
        HEARTBEAT
    );
    assert_eq!(u64::from(u16::from_le_bytes([GUEST[7], GUEST[8]])), TARGET);
    assert_eq!(FAULT_RIP - CODE, 5);
    assert_eq!(&GUEST[10..], &[0xeb, 0xfe]);
}

#[test]
#[ignore = "requires KVM, experimental mv-budget kernel, tty stdin and disposable raw scratch"]
fn memory_budget_running_vmm_pause_save_drop() {
    const MEM_LEN: usize = 64 << 20;
    const LEN: u32 = 65536;
    assert_eq!(
        std::env::var("FC_BUDGET_ALLOW_DESTROY_SCRATCH").as_deref(),
        Ok("YES")
    );
    // Do this before destructive setup: start_vcpus requires terminal raw/nonblocking mode.
    assert_eq!(
        // SAFETY: isatty only queries the supplied fd and accepts invalid fds as well.
        unsafe { libc::isatty(libc::STDIN_FILENO) },
        1,
        "stdin must be a tty"
    );
    let path = std::env::var("FC_BUDGET_SCRATCH").unwrap();
    let mut seed = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    assert!(seed.metadata().unwrap().file_type().is_block_device());
    assert_eq!(seed.seek(SeekFrom::End(0)).unwrap(), 64 << 20);
    seed.seek(SeekFrom::Start(0)).unwrap();
    seed.write_all(&vec![0x35; LEN as usize]).unwrap();
    seed.sync_all().unwrap();
    let direct = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_DIRECT)
        .open(&path)
        .unwrap();
    let budget = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/mv-budget-spike")
        .unwrap();

    let regions = single_region_mem_raw(MEM_LEN);
    let base = regions[0].as_ptr();
    assert_eq!(
        // SAFETY: live, page-aligned anonymous mapping for precisely MEM_LEN bytes.
        unsafe { libc::madvise(base.cast(), MEM_LEN, libc::MADV_NOHUGEPAGE) },
        0
    );
    regions[0]
        .write_slice(&GUEST, MemoryRegionAddress(CODE))
        .unwrap();
    regions[0]
        .write_obj(0u8, MemoryRegionAddress(HEARTBEAT))
        .unwrap();
    regions[0]
        .write_obj(0x5au8, MemoryRegionAddress(TARGET))
        .unwrap();
    // Fork before any KVM fd/vCPU/uring worker exists, and before enrollment. Only the target
    // stays shared: make the two bootstrap pages private before ordinary funding becomes zero.
    let holder = SharingChild::new();
    regions[0]
        .write_slice(&GUEST, MemoryRegionAddress(CODE))
        .unwrap();
    regions[0]
        .write_obj(0u8, MemoryRegionAddress(HEARTBEAT))
        .unwrap();

    let mut vm = KvmVm::new(Kvm::new(vec![]).unwrap()).unwrap();
    vm.register_memory_regions(regions).unwrap();
    let vcpus = vm.create_vcpus(1).unwrap();
    let cpu = &vcpus[0].kvm_vcpu.fd;
    cpu.set_cpuid2(&vm.kvm().supported_cpuid).unwrap();
    let mut sregs = cpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    sregs.ds.base = 0;
    sregs.ds.selector = 0;
    cpu.set_sregs(&sregs).unwrap();
    cpu.set_regs(&kvm_bindings::kvm_regs {
        rip: CODE,
        rflags: 2,
        ..Default::default()
    })
    .unwrap();
    let kvm = Arc::new(vm);
    let mem = kvm.guest_memory().clone();
    let mut events = EventManager::new().unwrap();
    let mut devices =
        DeviceManager::new(&mut events, kvm.vcpus_exit_evt(), &kvm, None, None).unwrap();
    let driver = VirtQueue::new(GuestAddress(0x10000), &mem, 256);
    read_blk_req_descriptors(&driver);
    let header = GuestAddress(0x1fff8);
    let payload = GuestAddress(0x30200);
    let status = GuestAddress(0x28000);
    driver.dtable[0].addr.set(header.0);
    driver.dtable[1].addr.set(payload.0);
    driver.dtable[1].len.set(LEN);
    driver.dtable[2].addr.set(status.0);
    mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_IN, 0), header)
        .unwrap();
    mem.write_obj(0xffu8, status).unwrap();
    let mut block = default_block_with_descriptor(direct.as_raw_fd(), false, FileEngineType::Async);
    block.queues[0] = driver.create_queue();
    block.acked_features = block.avail_features;
    let FileEngine::Async(engine) = &mut block.disk.file_engine else {
        unreachable!()
    };
    engine.force_async_for_test();
    let block = Arc::new(Mutex::new(Block::Virtio(block)));
    let block_weak = Arc::downgrade(&block);
    let mut cmdline = linux_loader::cmdline::Cmdline::new(crate::arch::CMDLINE_MAX_SIZE).unwrap();
    devices
        .attach_virtio_device(
            &Vm::Kvm(kvm.clone()),
            "test".to_string(),
            block.clone(),
            &mut cmdline,
            &mut events,
        )
        .unwrap();
    {
        let mmio = devices
            .mmio_devices
            .get_virtio_device(VirtioDeviceType::Block, "test")
            .unwrap();
        let mut transport = mmio.inner.lock().unwrap();
        // Use the real transport activation transition, not an inconsistent hand-made snapshot
        // with an activated device behind transport status INIT. Queue/features are test seeded.
        for value in [1u32, 3, 11, 15] {
            transport.write(mmio.resources.addr, 0x70, &value.to_le_bytes());
        }
        assert!(transport.locked_device().is_activated());
    }
    // DeviceManager::save requires both ACPI devices, just like the production builder.
    // Their activation writes guest memory now, before enrollment or vCPU execution.
    devices.attach_vmgenid_device(&kvm).unwrap();
    devices.attach_vmclock_device(&kvm).unwrap();
    let mut vmm = Vmm {
        instance_info: InstanceInfo {
            state: VmState::Paused,
            ..Default::default()
        },
        machine_config: MachineConfig {
            mem_size_mib: 64,
            vcpu_count: 1,
            ..Default::default()
        },
        boot_source_config: Default::default(),
        shutdown_exit_code: None,
        vm: Vm::Kvm(kvm.clone()),
        device_manager: devices,
    };
    // Unlike default_vmm(), these handles are actually started and owned by this VMM.
    kvm.start_vcpus(vcpus, Arc::new(vec![])).unwrap();
    assert_eq!(kvm.vcpus_handles().len(), 1);
    let (stop_tx, stop_rx) = mpsc::channel();
    let stopper = std::thread::spawn(move || {
        stop_rx.recv().unwrap();
        dispatch::gate().close();
    });
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
    vmm.resume_vm().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let blocked = loop {
        let mut ordinary = [0u64; 7];
        call(&budget, STATS(), &mut ordinary).unwrap();
        if ordinary[3] != 0 {
            break ordinary;
        }
        assert!(
            Instant::now() < deadline,
            "guest never reached unfunded fault: {:?}",
            stats(&budget)
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(blocked[0], 0);
    assert_eq!(blocked[1], 0);
    assert_eq!(
        blocked[3], 1,
        "only the independent vCPU can be waiting here"
    );
    assert_eq!(blocked[4], 0);
    assert_eq!(mem.read_obj::<u8>(GuestAddress(HEARTBEAT)).unwrap(), 1);
    assert_eq!(mem.read_obj::<u8>(GuestAddress(TARGET)).unwrap(), 0x5a);
    let before_io = stats(&budget);
    assert_eq!(before_io.spent, 0, "vCPU stole the operation's allowance");
    assert!(before_io.unauth_denied > 0);
    println!(
        "FC_RUNNING_BLOCKED expected_rip={FAULT_RIP:#x} target=0x5a ordinary={blocked:?} {before_io:?}"
    );

    let hold = dispatch::gate().enter();
    {
        let mut locked = block.lock().unwrap();
        let Block::Virtio(device) = &mut *locked;
        // A test-only single dispatch, never the normal unbounded process_queue loop.
        device.queue_evts[0].read().unwrap(); // consume resume_vm's queued notification
        let head = device.queues[0]
            .pop_or_enable_notification()
            .unwrap()
            .unwrap();
        let request = Request::parse(&head, &mem, device.disk.nsectors).unwrap();
        assert!(request.data_len <= LEN);
        assert_eq!(request.r#type, RequestType::In);
        assert!(matches!(
            request.process(&mut device.disk, false, head.index, &mem, &device.metrics),
            ProcessingResult::Submitted
        ));
        let FileEngine::Async(engine) = &mut device.disk.file_engine else {
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
    vmm.pause_vm().unwrap();
    assert_eq!(vmm.instance_info.state, VmState::Paused);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut ordinary = [0u64; 7];
        call(&budget, STATS(), &mut ordinary).unwrap();
        if ordinary[3] == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fault waiter did not clear after pause ACK: {ordinary:?}"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        kvm.vcpus_handles()[0].vcpu_fd.get_regs().unwrap().rip,
        FAULT_RIP
    );
    assert_eq!(
        kvm.vcpus_exit_evt().read().unwrap_err().raw_os_error(),
        Some(libc::EAGAIN)
    );
    assert_eq!(driver.used.idx.get(), 0, "completion is still owed at stop");
    assert_eq!(mem.read_obj::<u8>(status).unwrap(), 0xff);
    println!(
        "FC_RUNNING_PAUSED rip={FAULT_RIP:#x} waiting=0 used_idx=0 status=0xff; vCPU exit event absent; bio may already be unpinned"
    );

    call(&budget, OP_ENTER(), &mut 0u64).unwrap();
    vmm.drain_guest_memory_writers().unwrap();
    assert_eq!(driver.used.idx.get(), 1);
    assert_eq!(driver.used.ring[0].get().len, LEN + 1);
    assert_eq!(mem.read_obj::<u8>(status).unwrap(), 0);
    assert_eq!(mem.read_obj::<u8>(GuestAddress(TARGET)).unwrap(), 0x5a);
    let mut data = vec![0; LEN as usize];
    mem.read_slice(&mut data, payload).unwrap();
    assert!(data.iter().all(|byte| *byte == 0x35));
    call(&budget, OP_LEAVE(), &mut 0u64).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let locked = block.lock().unwrap();
        let Block::Virtio(device) = &*locked;
        let FileEngine::Async(engine) = &device.disk.file_engine else {
            unreachable!()
        };
        engine.run_task_work_for_test().unwrap();
        match call(&budget, OP_FINISH(), &mut 0u64) {
            Ok(()) => break,
            Err(err) if err.raw_os_error() == Some(libc::EBUSY) && Instant::now() < deadline => {
                drop(locked);
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(err) => panic!("running VMM FINISH: {err}; {:?}", stats(&budget)),
        }
    }
    let drained = stats(&budget);
    assert_eq!(
        (
            drained.active,
            drained.requests,
            drained.bios,
            drained.inflight
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(
        (drained.reserved, drained.exhausted, drained.ended),
        (26, 0, 1)
    );
    assert!((17..=26).contains(&drained.spent));
    assert!(drained.worker_issues > 0 && drained.bios_done > 0 && drained.unauth_denied > 0);
    println!("FC_RUNNING_DRAINED {drained:?}");

    // No operation authority after FINISH. The drained block and initialized ACPI devices'
    // save paths do not write guest memory. This is vmstate, NOT a RAM export or disk clone.
    let info = VmInfo::from(&vmm);
    let state = vmm.save_state(&info).unwrap();
    assert_eq!(state.vcpu_states.len(), 1);
    assert_eq!(state.vcpu_states[0].regs.rip, FAULT_RIP);
    assert_eq!(state.device_states.mmio_state.block_devices.len(), 1);
    assert!(state.device_states.mmio_state.net_devices.is_empty());
    assert!(state.device_states.mmio_state.vsock_device.is_none());
    assert!(state.device_states.mmio_state.entropy_device.is_none());
    assert!(
        state
            .device_states
            .mmio_state
            .free_page_reporting_device
            .is_none()
    );
    let mut encoded = Vec::new();
    Snapshot::new(state).save(&mut encoded).unwrap();
    let decoded = Snapshot::<MicrovmState>::load(&mut encoded.as_slice()).unwrap();
    assert_eq!(decoded.data.vcpu_states[0].regs.rip, FAULT_RIP);
    assert_eq!(mem.read_obj::<u8>(GuestAddress(TARGET)).unwrap(), 0x5a);
    println!(
        "FC_RUNNING_VMSTATE bytes={} saved_rip={FAULT_RIP:#x} target=0x5a",
        encoded.len()
    );
    assert_eq!(stats(&budget).spent, drained.spent);
    assert!(vmm.shutdown_exit_code().is_none());
    drop(vmm); // shutdown_vcpus sends Finish, clears handles, and joins every vCPU thread.
    assert!(kvm.vcpus_handles().is_empty());
    drop(events);
    drop(block);
    drop(kvm);
    assert!(
        block_weak.upgrade().is_none(),
        "device still retained after teardown"
    );
    drop(holder);
    let mut ordinary = [0u64; 7];
    call(&budget, STATS(), &mut ordinary).unwrap();
    assert_eq!(
        (ordinary[0], ordinary[1], ordinary[3], ordinary[4]),
        (0, 0, 0, 0)
    );
    assert_eq!(stats(&budget).spent, drained.spent);
    assert!(dispatch::gate().is_closed());
    println!(
        "FC_RUNNING_VMM_PASS joined=1 target=0x5a ordinary={ordinary:?}; vmstate only, NO RAM export/durable capture"
    );
}
