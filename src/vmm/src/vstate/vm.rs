// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::{
    KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2, KVM_DIRTY_LOG_INITIALLY_SET,
    KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI,
    KVM_MSI_VALID_DEVID, KvmIrqRouting, kvm_clear_dirty_log, kvm_enable_cap, kvm_irq_routing_entry,
    kvm_userspace_memory_region,
};
use kvm_ioctls::VmFd;
use serde::{Deserialize, Serialize};
use vmm_sys_util::errno;
use vmm_sys_util::eventfd::EventFd;
use vmm_sys_util::ioctl::ioctl_with_ref;
use vmm_sys_util::terminal::Terminal;

use crate::Vcpu;
use crate::arch::{GSI_MSI_END, host_page_size};
pub use crate::arch::{KvmVm, KvmVmError, VmState};
use crate::logger::{debug, info};
use crate::utils::u64_to_usize;
use crate::vstate::bus::Bus;
use crate::vstate::interrupts::{InterruptError, MsixVector, MsixVectorConfig, MsixVectorGroup};
use crate::vstate::kvm::Kvm;
use crate::vstate::memory::{
    GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion, GuestMemoryState,
    GuestRegionMmap, GuestRegionMmapExt, MemoryError,
};
use crate::vstate::resources::ResourceAllocator;
use crate::vstate::vcpu::{StartThreadedError, VcpuError, VcpuHandle};

mod ioctls {
    use kvm_bindings::{kvm_clear_dirty_log, kvm_enable_cap};
    use vmm_sys_util::{ioctl_iow_nr, ioctl_iowr_nr};

    ioctl_iow_nr!(KVM_ENABLE_CAP, kvm_bindings::KVMIO, 0xa3, kvm_enable_cap);
    ioctl_iowr_nr!(
        KVM_CLEAR_DIRTY_LOG,
        kvm_bindings::KVMIO,
        0xc0,
        kvm_clear_dirty_log
    );
}

use ioctls::{KVM_CLEAR_DIRTY_LOG, KVM_ENABLE_CAP};

/// Error type for [`KvmVm::start_vcpus`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum StartVcpusError {
    /// Failed to set terminal mode: {0}
    SetTerminalMode(#[from] vmm_sys_util::errno::Error),
    /// Vcpu handle error: {0}
    VcpuHandle(#[from] StartThreadedError),
}

#[derive(Debug, Serialize, Deserialize)]
/// A struct representing an interrupt line used by some device of the microVM
pub struct RoutingEntry {
    entry: kvm_irq_routing_entry,
    masked: bool,
}

/// One line interrupt's IRQFD registration, in the journal [`KvmVm::detach_irqfds`] keeps.
#[derive(Debug)]
struct IrqfdRegistration {
    /// A duplicate of the registered eventfd.
    evt: EventFd,
    gsi: u32,
    /// Whether KVM has the registration now.
    attached: bool,
}

/// Architecture independent parts of a VM.
#[derive(Debug)]
pub struct VmCommon {
    /// The KVM file descriptor used to access this KvmVm.
    pub fd: VmFd,
    max_memslots: u32,
    /// The guest memory of this KvmVm.
    pub guest_memory: GuestMemoryMmap,
    next_kvm_slot: AtomicU32,
    /// Interrupts used by KvmVm's devices
    pub interrupts: Mutex<HashMap<u32, RoutingEntry>>,
    /// Journal of every eventfd/GSI pair registered as a line interrupt's IRQFD: a duplicate of
    /// the eventfd, so the exact registration can be detached and attached again, and whether it
    /// is attached now.
    irqfds: Mutex<Vec<IrqfdRegistration>>,
    /// Allocator for VM resources
    pub resource_allocator: Mutex<ResourceAllocator>,
    /// MMIO bus
    pub mmio_bus: Arc<Bus>,
    /// The global KVM state (fd + capabilities).
    pub kvm: Kvm,
    /// Handles to vCPU threads.
    pub vcpus_handles: Mutex<Vec<VcpuHandle>>,
    /// Event fd written to by vCPUs on exit.
    pub vcpus_exit_evt: EventFd,
    /// Dirty bits handed back by [`KvmVm::union_dirty_log`], keyed by kvm slot and shaped like
    /// the owning region's bitmap. Word-level so a rollback of a mostly-dirty multi-gigabyte
    /// bitmap costs one pass over the words rather than one atomic operation per page.
    pending_dirty_union: Mutex<HashMap<u32, Vec<u64>>>,
}

/// Errors associated with the wrappers over KVM ioctls.
/// Needs `rustfmt::skip` to make multiline comments work
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VmError {
    /// Cannot set the memory regions: {0}
    SetUserMemoryRegion(kvm_ioctls::Error),
    /// Failed to create VM: {0}
    CreateVm(kvm_ioctls::Error),
    /// Failed to get KVM's dirty log: {0}
    GetDirtyLog(kvm_ioctls::Error),
    /// {0}
    Arch(#[from] KvmVmError),
    /// Error during eventfd operations: {0}
    EventFd(std::io::Error),
    /// Failed to create vcpu: {0}
    CreateVcpu(VcpuError),
    /// The number of configured slots is bigger than the maximum reported by KVM: {0}
    NotEnoughMemorySlots(u32),
    /// Failed to add a memory region: {0}
    InsertRegion(#[from] vm_memory::GuestRegionCollectionError),
    /// Failed to clear KVM's dirty log: {0}
    ClearDirtyLog(vmm_sys_util::errno::Error),
    /// Failed to enable manual dirty log protection: {0}
    ManualDirtyLogProtect(kvm_ioctls::Error),
    /// Harvested bitmap does not match the guest geometry
    DirtyBitmapShape,
    /// ResourceAllocator error: {0}
    ResourceAllocator(#[from] vm_allocator::Error),
    /// MemoryError error: {0}
    MemoryError(#[from] MemoryError),
    /// Cannot adopt guest memory: {0}
    AdoptGuestMemory(#[from] AdoptGuestMemoryError),
    /// Cannot detach or attach the IRQFD of GSI {0}: {1}
    Irqfd(u32, errno::Error),
    /// Detaching the IRQFD of GSI {0} failed ({1}), and attaching GSI {2} again failed too: {3}
    IrqfdRollback(u32, errno::Error, u32, errno::Error),
}

/// Error type for [`KvmVm::adopt_guest_memory`].
#[derive(Debug, PartialEq, Eq, thiserror::Error, displaydoc::Display)]
pub enum AdoptGuestMemoryError {
    /// the VM already owns guest memory
    NotFresh,
    /// geometry {got:?} does not match the vmstate {want:?}
    Geometry {
        /// Geometry of the adopted memory.
        got: GuestMemoryState,
        /// Geometry recorded in the vmstate.
        want: GuestMemoryState,
    },
    /// region at {addr:#x} is registered under slot {slot}, but this VM's next slot is {fresh}
    Slot {
        /// Guest physical base address of the region.
        addr: u64,
        /// Slot the region was registered under.
        slot: u32,
        /// Slot this VM would assign.
        fresh: u32,
    },
}

/// Checks that `memory` matches `state` and that its regions, in address order, carry exactly
/// the slots a VM whose next free slot is `first_slot` would assign.
fn check_adoption(
    memory: &GuestMemoryMmap,
    state: &GuestMemoryState,
    first_slot: u32,
    max_memslots: u32,
) -> Result<(), VmError> {
    let got = memory.describe();
    if got != *state {
        return Err(AdoptGuestMemoryError::Geometry {
            got,
            want: state.clone(),
        }
        .into());
    }
    for (fresh, region) in (first_slot..).zip(memory.iter()) {
        if max_memslots <= fresh {
            return Err(VmError::NotEnoughMemorySlots(max_memslots));
        }
        if region.slot != fresh {
            return Err(AdoptGuestMemoryError::Slot {
                addr: region.start_addr().0,
                slot: region.slot,
                fresh,
            }
            .into());
        }
    }
    Ok(())
}

/// VM abstraction: either a KVM-based VM or (in the future) a Nitro Enclave.
#[derive(Debug)]
pub enum Vm {
    /// KVM-backed virtual machine.
    Kvm(Arc<KvmVm>),
}

impl Vm {
    /// Returns the name of the VM type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Vm::Kvm(_) => "Kvm",
        }
    }

    /// Returns a reference to the inner KVM VM, or `None` if this is not a KVM VM.
    pub fn as_kvm(&self) -> Option<&Arc<KvmVm>> {
        match self {
            Vm::Kvm(v) => Some(v),
        }
    }
}

/// Contains KvmVm functions that are usable across CPU architectures
impl KvmVm {
    /// Create a KVM VM
    pub fn create_common(kvm: Kvm) -> Result<VmCommon, VmError> {
        // It is known that KVM_CREATE_VM occasionally fails with EINTR on heavily loaded machines
        // with many VMs.
        //
        // The behavior itself that KVM_CREATE_VM can return EINTR is intentional. This is because
        // the KVM_CREATE_VM path includes mm_take_all_locks() that is CPU intensive and all CPU
        // intensive syscalls should check for pending signals and return EINTR immediately to allow
        // userland to remain interactive.
        // https://lists.nongnu.org/archive/html/qemu-devel/2014-01/msg01740.html
        //
        // However, it is empirically confirmed that, even though there is no pending signal,
        // KVM_CREATE_VM returns EINTR.
        // https://lore.kernel.org/qemu-devel/8735e0s1zw.wl-maz@kernel.org/
        //
        // To mitigate it, QEMU does an infinite retry on EINTR that greatly improves reliabiliy:
        // - https://github.com/qemu/qemu/commit/94ccff133820552a859c0fb95e33a539e0b90a75
        // - https://github.com/qemu/qemu/commit/bbde13cd14ad4eec18529ce0bf5876058464e124
        //
        // Similarly, we do retries up to 5 times. Although Firecracker clients are also able to
        // retry, they have to start Firecracker from scratch. Doing retries in Firecracker makes
        // recovery faster and improves reliability.
        const MAX_ATTEMPTS: u32 = 5;
        let mut attempt = 1;
        let fd = loop {
            match kvm.fd.create_vm() {
                Ok(fd) => break fd,
                Err(e) if e.errno() == libc::EINTR && attempt < MAX_ATTEMPTS => {
                    info!("Attempt #{attempt} of KVM_CREATE_VM returned EINTR");
                    // Exponential backoff (1us, 2us, 4us, and 8us => 15us in total)
                    std::thread::sleep(std::time::Duration::from_micros(2u64.pow(attempt - 1)));
                }
                Err(e) => return Err(VmError::CreateVm(e)),
            }

            attempt += 1;
        };

        // Manual protection makes a harvest a snapshot-then-clear: reading the log neither clears
        // nor re-protects, so a capture reports each epoch exactly once. New slots start fully
        // dirty so the first clear re-protects even pages that the userspace loader, rather than
        // KVM, populated. Otherwise those pages are clean in KVM and cannot be armed by a clear.
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            ..Default::default()
        };
        cap.args[0] = u64::from(KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE | KVM_DIRTY_LOG_INITIALLY_SET);
        // SAFETY: the ioctl reads `cap`, which is a fully initialized capability request.
        let ret = unsafe { ioctl_with_ref(&fd, KVM_ENABLE_CAP(), &cap) };
        if ret != 0 {
            return Err(VmError::ManualDirtyLogProtect(errno::Error::last()));
        }

        let vcpus_exit_evt = EventFd::new(libc::EFD_NONBLOCK).map_err(VmError::EventFd)?;

        Ok(VmCommon {
            fd,
            max_memslots: kvm.max_nr_memslots(),
            guest_memory: GuestMemoryMmap::default(),
            next_kvm_slot: AtomicU32::new(0),
            interrupts: Mutex::new(HashMap::with_capacity(GSI_MSI_END as usize + 1)),
            irqfds: Mutex::new(Vec::new()),
            resource_allocator: Mutex::new(ResourceAllocator::new()),
            mmio_bus: Arc::new(Bus::new()),
            kvm,
            vcpus_handles: Mutex::new(Vec::new()),
            vcpus_exit_evt,
            pending_dirty_union: Mutex::new(HashMap::new()),
        })
    }

    /// Creates the specified number of [`Vcpu`]s.
    ///
    /// Each vCPU gets a clone of the `vcpus_exit_evt` EventFd stored on this KvmVm.
    pub fn create_vcpus(&mut self, vcpu_count: u8) -> Result<Vec<Vcpu>, VmError> {
        self.arch_pre_create_vcpus(vcpu_count)?;

        let mut vcpus = Vec::with_capacity(vcpu_count as usize);
        for cpu_idx in 0..vcpu_count {
            let exit_evt = self
                .vcpus_exit_evt()
                .try_clone()
                .map_err(VmError::EventFd)?;
            let vcpu = Vcpu::new(cpu_idx, self, exit_evt).map_err(VmError::CreateVcpu)?;
            vcpus.push(vcpu);
        }

        self.arch_post_create_vcpus(vcpu_count)?;

        Ok(vcpus)
    }

    /// Returns a reference to the [`Kvm`] instance.
    pub fn kvm(&self) -> &Kvm {
        &self.common.kvm
    }

    /// Returns a reference to the vCPU exit [`EventFd`].
    pub fn vcpus_exit_evt(&self) -> &EventFd {
        &self.common.vcpus_exit_evt
    }

    /// Returns a locked reference to the vCPU handles.
    pub fn vcpus_handles(&self) -> MutexGuard<'_, Vec<VcpuHandle>> {
        self.common.vcpus_handles.lock().expect("Poisoned lock")
    }

    /// Puts the terminal into raw, non-blocking mode for an interactive serial console, as the
    /// default mode does before starting its vCPUs. Native mode never acquires the terminal.
    pub fn acquire_terminal() -> Result<(), StartVcpusError> {
        let stdin = std::io::stdin().lock();
        stdin.set_raw_mode().inspect_err(|&err| {
            crate::logger::warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;
        stdin.set_non_block(true).inspect_err(|&err| {
            crate::logger::warn!("Cannot set non block for the terminal. {:?}", err);
        })?;
        Ok(())
    }

    /// Starts the microVM vCPUs.
    ///
    /// Starts a thread per vCPU, each ready with its kick handler and filter before the next one
    /// starts, and stores the handles. On failure the vCPUs started so far are stopped again and
    /// every vCPU is returned.
    pub fn start_vcpus(
        self: &Arc<Self>,
        vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<crate::seccomp::BpfProgram>,
    ) -> Result<(), (StartVcpusError, Vec<Vcpu>)> {
        let mut handles = self.vcpus_handles();
        let first = handles.len();
        handles.reserve(vcpus.len());
        let mut pending = vcpus.into_iter();
        for index in 0.. {
            let Some(mut vcpu) = pending.next() else {
                break;
            };
            vcpu.set_mmio_bus(self.common.mmio_bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu.set_pio_bus(self.pio_bus.clone());

            #[cfg(test)]
            let vcpu_seccomp_filter = if tests::FAIL_VCPU_START.get() == Some(index) {
                // A filter the kernel refuses fails this vCPU's start after the earlier ones ran.
                Arc::new(vec![0; crate::seccomp::BPF_MAX_LEN + 1])
            } else {
                vcpu_seccomp_filter.clone()
            };
            #[cfg(not(test))]
            let _ = index;
            match vcpu.start_threaded(self, vcpu_seccomp_filter.clone()) {
                Ok(handle) => handles.push(handle),
                Err((err, vcpu)) => {
                    let mut vcpus = Self::stop_handles(handles.drain(first..).collect());
                    vcpus.push(vcpu);
                    vcpus.extend(pending);
                    return Err((err.into(), vcpus));
                }
            }
        }

        Ok(())
    }

    /// Stops every vCPU worker and returns the vCPUs in start order. All are told to finish
    /// before any is joined, so once this returns no vCPU runs, and none ran on after another's
    /// return.
    pub fn stop_vcpus(&self) -> Vec<Vcpu> {
        let handles = self.vcpus_handles().drain(..).collect();
        Self::stop_handles(handles)
    }

    fn stop_handles(mut handles: Vec<VcpuHandle>) -> Vec<Vcpu> {
        for handle in &mut handles {
            handle.finish();
        }
        handles.into_iter().map(VcpuHandle::join).collect()
    }

    /// Sends a pause event to all vCPUs and waits for acknowledgement.
    pub fn pause_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Pause))
            .map_err(|_| crate::VmmError::VcpuMessage)?;

        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Paused)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Sends a resume event to all vCPUs and waits for acknowledgement.
    pub fn resume_vcpus(&self) -> Result<(), crate::VmmError> {
        let mut handles = self.vcpus_handles();
        handles
            .iter_mut()
            .try_for_each(|handle| handle.send_event(crate::VcpuEvent::Resume))
            .map_err(|_| crate::VmmError::VcpuMessage)?;

        if handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .any(|response| !matches!(response, Ok(crate::VcpuResponse::Resumed)))
        {
            return Err(crate::VmmError::VcpuMessage);
        }
        Ok(())
    }

    /// Saves vCPU states by requesting each vCPU thread to serialize its state.
    pub fn save_vcpu_states(
        &self,
    ) -> Result<Vec<crate::vstate::vcpu::VcpuState>, crate::persist::MicrovmStateError> {
        use crate::persist::MicrovmStateError;

        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::SaveState)
                .map_err(MicrovmStateError::SignalVcpu)?;
        }

        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| MicrovmStateError::UnexpectedVcpuResponse)?;

        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::SavedState(state) => Ok(*state),
                crate::VcpuResponse::Error(err) => Err(MicrovmStateError::SaveVcpuState(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(MicrovmStateError::NotAllowed(reason))
                }
                _ => Err(MicrovmStateError::UnexpectedVcpuResponse),
            })
            .collect()
    }

    /// Dumps CPU configuration from all vCPU threads.
    pub fn dump_cpu_config_states(
        &self,
    ) -> Result<Vec<crate::cpu_config::templates::CpuConfiguration>, crate::DumpCpuConfigError>
    {
        use crate::DumpCpuConfigError;

        let mut handles = self.vcpus_handles();
        for handle in handles.iter_mut() {
            handle
                .send_event(crate::VcpuEvent::DumpCpuConfig)
                .map_err(DumpCpuConfigError::SendEvent)?;
        }

        let vcpu_responses = handles
            .iter()
            .map(|handle| {
                handle
                    .response_receiver()
                    .recv_timeout(crate::RECV_TIMEOUT_SEC)
            })
            .collect::<Result<Vec<crate::VcpuResponse>, _>>()
            .map_err(|_| DumpCpuConfigError::UnexpectedResponse)?;

        vcpu_responses
            .into_iter()
            .map(|response| match response {
                crate::VcpuResponse::DumpedCpuConfig(cpu_config) => Ok(*cpu_config),
                crate::VcpuResponse::Error(err) => Err(DumpCpuConfigError::DumpCpuConfig(err)),
                crate::VcpuResponse::NotAllowed(reason) => {
                    Err(DumpCpuConfigError::NotAllowed(reason))
                }
                _ => Err(DumpCpuConfigError::UnexpectedResponse),
            })
            .collect()
    }

    /// Sends finish events to all vCPU threads and joins them.
    pub fn shutdown_vcpus(&self) {
        let mut handles = self.vcpus_handles();
        for (idx, handle) in handles.iter_mut().enumerate() {
            if let Err(err) = handle.send_event(crate::VcpuEvent::Finish) {
                crate::logger::error!("Failed to send VcpuEvent::Finish to vCPU {}: {}", idx, err);
            }
        }
        // Join the vCPU threads by running VcpuHandle::drop().
        handles.clear();
    }

    /// Reserves the next `slot_cnt` contiguous kvm slot ids and returns the first one
    pub fn next_kvm_slot(&self, slot_cnt: u32) -> Option<u32> {
        let next = self
            .common
            .next_kvm_slot
            .fetch_add(slot_cnt, Ordering::Relaxed);
        if self.common.max_memslots <= next {
            None
        } else {
            Some(next)
        }
    }

    pub(crate) fn set_user_memory_region(
        &self,
        region: kvm_userspace_memory_region,
    ) -> Result<(), VmError> {
        // SAFETY: Safe because the fd is a valid KVM file descriptor.
        unsafe {
            self.fd()
                .set_user_memory_region(region)
                .map_err(VmError::SetUserMemoryRegion)
        }
    }

    fn register_memory_region(&mut self, region: Arc<GuestRegionMmapExt>) -> Result<(), VmError> {
        let new_guest_memory = self
            .common
            .guest_memory
            .insert_region(Arc::clone(&region))?;

        self.set_user_memory_region(region.as_ref().into())?;
        let words = u64_to_usize(region.len())
            .div_ceil(host_page_size())
            .div_ceil(64);
        self.pending_dirty_union()
            .insert(region.slot, vec![0u64; words]);
        self.common.guest_memory = new_guest_memory;

        Ok(())
    }

    /// Locks the accumulator holding the dirty bits returned by [`KvmVm::union_dirty_log`].
    fn pending_dirty_union(&self) -> MutexGuard<'_, HashMap<u32, Vec<u64>>> {
        self.common
            .pending_dirty_union
            .lock()
            .expect("Poisoned lock")
    }

    /// Register a list of new memory regions to this [`KvmVm`].
    pub fn register_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
    ) -> Result<(), VmError> {
        for region in regions {
            let slot = self
                .next_kvm_slot(1)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            self.register_memory_region(Arc::new(GuestRegionMmapExt::from_mmap_region(
                region, slot,
            )))?;
        }

        Ok(())
    }

    /// Register a list of restored memory regions to this [`KvmVm`].
    ///
    /// Note: regions and state.regions need to be in the same order.
    pub fn restore_memory_regions(
        &mut self,
        regions: Vec<GuestRegionMmap>,
        state: &GuestMemoryState,
    ) -> Result<(), VmError> {
        if regions.len() != state.regions.len() {
            return Err(VmError::MemoryError(MemoryError::Farplane(
                "restored geometry does not match the vmstate".to_string(),
            )));
        }
        for (region, state) in regions.into_iter().zip(state.regions.iter()) {
            let slot = self
                .next_kvm_slot(1)
                .ok_or(VmError::NotEnoughMemorySlots(self.common.max_memslots))?;

            self.register_memory_region(Arc::new(GuestRegionMmapExt::from_state(
                region, state, slot,
            )?))?;
        }

        Ok(())
    }

    /// Adopts an owned clone of guest memory registered by another [`KvmVm`] of this process,
    /// such as the copy of the source VM a fork child inherits.
    ///
    /// Cloning a [`GuestMemoryMmap`] clones its region `Arc`s, not RAM, so this VM keeps the
    /// mappings alive once the original owners drop. The geometry must match `state`, every
    /// region keeps the slot it was registered under, and this VM must not own memory yet. The
    /// collection is owned before the first slot is registered, so a partial registration failure
    /// never leaves KVM referencing a mapping this VM does not keep alive.
    ///
    /// Admission is fixed and sequential: a fresh VM assigns slots from 0 in address order, and
    /// only memory whose slots are exactly that sequence is adopted; sparse or reordered slots are
    /// rejected, never renumbered. A cold native boot satisfies this, because
    /// [`KvmVm::register_memory_regions`] reserves one slot per region in address order on a VM
    /// that has no other slots.
    ///
    /// The host dirty bitmaps are shared by every clone of the collection and are cleared here;
    /// adopt only where the original owner no longer harvests them. KVM's log for the new slots
    /// is the caller's to baseline, as after [`KvmVm::restore_memory_regions`].
    pub fn adopt_guest_memory(
        &mut self,
        memory: GuestMemoryMmap,
        state: &GuestMemoryState,
    ) -> Result<(), VmError> {
        if self.common.guest_memory.num_regions() != 0 {
            return Err(AdoptGuestMemoryError::NotFresh.into());
        }
        let next_slot = self.common.next_kvm_slot.get_mut();
        check_adoption(&memory, state, *next_slot, self.common.max_memslots)?;
        // Bounded by max_memslots, which is a u32, in check_adoption.
        *next_slot += u32::try_from(memory.num_regions()).unwrap();

        memory.reset_dirty();
        self.common.guest_memory = memory;
        for region in self.common.guest_memory.iter() {
            self.set_user_memory_region(region.into())?;
            let words = u64_to_usize(region.len())
                .div_ceil(host_page_size())
                .div_ceil(64);
            self.pending_dirty_union()
                .insert(region.slot, vec![0u64; words]);
        }

        Ok(())
    }

    /// Gets a reference to the kvm file descriptor owned by this VM.
    pub fn fd(&self) -> &VmFd {
        &self.common.fd
    }

    /// Gets a reference to this [`KvmVm`]'s [`GuestMemoryMmap`] object
    pub fn guest_memory(&self) -> &GuestMemoryMmap {
        &self.common.guest_memory
    }

    /// Gets a mutable reference to this [`KvmVm`]'s [`ResourceAllocator`] object
    pub fn resource_allocator(&self) -> MutexGuard<'_, ResourceAllocator> {
        self.common
            .resource_allocator
            .lock()
            .expect("Poisoned lock")
    }

    /// Snapshots the dirty accumulator of every guest region, in ascending guest address order.
    /// Under manual protection `KVM_GET_DIRTY_LOG` neither clears nor re-protects, so the bits
    /// stay set until [`KvmVm::clear_dirty_log`] retires them.
    ///
    /// A region's report is the union of KVM's log, the host write accumulator, and the bits a
    /// previous harvest returned through [`KvmVm::union_dirty_log`]. Host bits are moved into the
    /// pending accumulator as they are read, so snapshotting retires no evidence:
    /// [`KvmVm::clear_dirty_log`] owns that commit after the report is durably handed to the caller.
    pub fn snapshot_dirty_log(&self) -> Result<Vec<Vec<u64>>, VmError> {
        let page_size = host_page_size();
        let mut pending = self.pending_dirty_union();
        let mut harvest = Vec::with_capacity(self.guest_memory().num_regions());

        // Read and validate every KVM bitmap before draining a host accumulator. A late KVM or
        // geometry failure therefore leaves all host-owned evidence untouched.
        for region in self.guest_memory().iter() {
            let len = u64_to_usize(region.len());
            let words = self
                .fd()
                .get_dirty_log(region.slot, len)
                .map_err(VmError::GetDirtyLog)?;
            let pages = len.div_ceil(page_size);
            if words.len() != pages.div_ceil(64) {
                return Err(VmError::DirtyBitmapShape);
            }
            if let Some(host_writes) = region.inner.deref().bitmap().as_ref()
                && (host_writes.len() != pages || host_writes.byte_size() != len)
            {
                return Err(VmError::DirtyBitmapShape);
            }
            match pending.get(&region.slot) {
                Some(returned) if returned.len() != words.len() => {
                    return Err(VmError::DirtyBitmapShape);
                }
                Some(_) => {}
                None => {}
            }
            harvest.push(words);
        }

        for (region, words) in self.guest_memory().iter().zip(&mut harvest) {
            let returned = pending
                .entry(region.slot)
                .or_insert_with(|| vec![0u64; words.len()]);
            if let Some(host_writes) = region.inner.deref().bitmap().as_ref() {
                let host_words = host_writes.clone().get_and_reset();
                if host_words.len() != words.len() {
                    return Err(VmError::DirtyBitmapShape);
                }
                for (returned_word, host_word) in returned.iter_mut().zip(host_words) {
                    *returned_word |= host_word;
                }
            }
            for (word, returned_word) in words.iter_mut().zip(returned) {
                *word |= *returned_word;
            }
        }
        Ok(harvest)
    }

    /// Retires the bits of a snapshot: KVM re-protects them and the host accumulator is reset.
    ///
    /// KVM drops a slot's bits as it clears them. If a later slot fails, the complete snapshot is
    /// returned to the pending-union accumulator; on success, the host accumulator is reset only
    /// after every slot cleared. Either outcome leaves every reported bit owned exactly once.
    pub fn clear_dirty_log(&self, snapshot: &[Vec<u64>]) -> Result<(), VmError> {
        let page_size = host_page_size();
        if snapshot.len() != self.guest_memory().num_regions() {
            return Err(VmError::DirtyBitmapShape);
        }
        let page_counts = self
            .guest_memory()
            .iter()
            .zip(snapshot)
            .map(|(region, words)| {
                let pages = u64_to_usize(region.len()).div_ceil(page_size);
                if words.len() != pages.div_ceil(64) {
                    return Err(VmError::DirtyBitmapShape);
                }
                u32::try_from(pages).map_err(|_| VmError::DirtyBitmapShape)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Keep the returned bits until every KVM slot has accepted the clear. A failed bitmap
        // write or flush between snapshot and this call therefore changes nothing, and a clear
        // failure keeps one complete retryable report without returning to per-page atomics.
        let mut pending = self.pending_dirty_union();
        for (region, words) in self.guest_memory().iter().zip(snapshot) {
            if pending
                .get(&region.slot)
                .is_some_and(|acc| acc.len() != words.len())
            {
                return Err(VmError::DirtyBitmapShape);
            }
        }

        for ((region, words), pages) in self.guest_memory().iter().zip(snapshot).zip(page_counts) {
            let clear = kvm_clear_dirty_log {
                slot: region.slot,
                num_pages: pages,
                first_page: 0,
                __bindgen_anon_1: kvm_bindings::kvm_clear_dirty_log__bindgen_ty_1 {
                    dirty_bitmap: words.as_ptr().cast_mut().cast(),
                },
            };
            // SAFETY: the ioctl reads `clear`, whose bitmap covers exactly this slot's pages.
            let ret = unsafe { ioctl_with_ref(self.fd(), KVM_CLEAR_DIRTY_LOG(), &clear) };
            if ret != 0 {
                let err = errno::Error::last();
                // A previous slot may already be clear. Preserve the complete report so the next
                // harvest repeats every bit rather than losing that slot's part of the snapshot.
                for (reported_region, reported_words) in self.guest_memory().iter().zip(snapshot) {
                    let accumulated = pending
                        .entry(reported_region.slot)
                        .or_insert_with(|| vec![0u64; reported_words.len()]);
                    for (dst, src) in accumulated.iter_mut().zip(reported_words) {
                        *dst |= *src;
                    }
                }
                return Err(VmError::ClearDirtyLog(err));
            }
        }
        self.guest_memory().reset_dirty();
        for (region, reported) in self.guest_memory().iter().zip(snapshot) {
            if let Some(returned) = pending.get_mut(&region.slot) {
                for (returned_word, reported_word) in returned.iter_mut().zip(reported) {
                    *returned_word &= !*reported_word;
                }
            }
        }
        Ok(())
    }

    /// Retires KVM's initial all-ones dirty state on every registered slot and re-arms write
    /// protection, without touching the host accumulator.
    ///
    /// `KVM_DIRTY_LOG_INITIALLY_SET` makes a new slot start fully dirty so that the first clear
    /// can protect pages a userspace loader, rather than KVM, populated. A VM restored from a
    /// checkpoint has no such pages: its memory arrives already committed by
    /// [`KvmVm::restore_memory_regions`]. Leaving the initial state in place would make the first
    /// harvest report the whole geometry, so the restored VM's first fork would recapture the
    /// entire resident checkpoint instead of the writes that followed the restore.
    ///
    /// The host accumulator is deliberately left alone. Host-side writes that follow this call
    /// (device restore, VMGenID) are tracked there and belong to the first harvest; only KVM's
    /// initial state is retired here.
    pub fn baseline_dirty_log(&self) -> Result<(), VmError> {
        let page_size = host_page_size();
        for region in self.guest_memory().iter() {
            let pages = u64_to_usize(region.len()).div_ceil(page_size);
            let words = vec![u64::MAX; pages.div_ceil(64)];
            let clear = kvm_clear_dirty_log {
                slot: region.slot,
                num_pages: u32::try_from(pages).map_err(|_| VmError::DirtyBitmapShape)?,
                first_page: 0,
                __bindgen_anon_1: kvm_bindings::kvm_clear_dirty_log__bindgen_ty_1 {
                    dirty_bitmap: words.as_ptr().cast_mut().cast(),
                },
            };
            // SAFETY: the ioctl reads `clear`, whose bitmap covers exactly this slot's pages.
            let ret = unsafe { ioctl_with_ref(self.fd(), KVM_CLEAR_DIRTY_LOG(), &clear) };
            if ret != 0 {
                return Err(VmError::ClearDirtyLog(errno::Error::last()));
            }
        }
        Ok(())
    }

    /// Returns a previously snapshotted bitmap to the accumulator, so the next snapshot reports it.
    ///
    /// The bits land in the pending-union accumulator, which
    /// [`KvmVm::snapshot_dirty_log`] reports until [`KvmVm::clear_dirty_log`] retires them.
    /// Repeated unions accumulate exactly, and a rollback of a mostly-dirty bitmap costs one pass
    /// over its words. A geometry that does not match the registered regions is rejected before
    /// any word is touched, so a rejected union leaves ownership of the reported bits with the
    /// caller.
    pub fn union_dirty_log(&self, bits: &[Vec<u64>]) -> Result<(), VmError> {
        let page_size = host_page_size();
        if bits.len() != self.guest_memory().num_regions() {
            return Err(VmError::DirtyBitmapShape);
        }
        let mut pending = self.pending_dirty_union();
        for (region, words) in self.guest_memory().iter().zip(bits) {
            let expected = u64_to_usize(region.len()).div_ceil(page_size).div_ceil(64);
            if words.len() != expected {
                return Err(VmError::DirtyBitmapShape);
            }
            if pending
                .get(&region.slot)
                .is_some_and(|acc| acc.len() != expected)
            {
                return Err(VmError::DirtyBitmapShape);
            }
        }
        for (region, words) in self.guest_memory().iter().zip(bits) {
            let accumulated = pending
                .entry(region.slot)
                .or_insert_with(|| vec![0u64; words.len()]);
            for (dst, src) in accumulated.iter_mut().zip(words) {
                *dst |= *src;
            }
        }
        Ok(())
    }

    /// Register a device IRQ
    pub fn register_irq(&self, fd: &EventFd, gsi: u32) -> Result<(), errno::Error> {
        // The tracking duplicate comes first: a registration it failed to track could never be
        // detached exactly.
        let tracked = fd.try_clone()?;
        self.common.fd.register_irqfd(fd, gsi)?;
        self.irqfds().push(IrqfdRegistration {
            evt: tracked,
            gsi,
            attached: true,
        });

        let mut entry = kvm_irq_routing_entry {
            gsi,
            type_: KVM_IRQ_ROUTING_IRQCHIP,
            ..Default::default()
        };
        #[cfg(target_arch = "x86_64")]
        {
            entry.u.irqchip.irqchip = KVM_IRQCHIP_IOAPIC;
        }
        #[cfg(target_arch = "aarch64")]
        {
            entry.u.irqchip.irqchip = 0;
        }
        entry.u.irqchip.pin = gsi;

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(
                gsi,
                RoutingEntry {
                    entry,
                    masked: false,
                },
            );
        Ok(())
    }

    fn irqfds(&self) -> MutexGuard<'_, Vec<IrqfdRegistration>> {
        self.common.irqfds.lock().expect("Poisoned lock")
    }

    /// Detaches every attached line interrupt's IRQFD, exactly the eventfd/GSI pairs
    /// registered: an assignment with a different pair would detach nothing and still succeed.
    /// KVM's deassign completes that registration's pending injection before returning, so
    /// with every producer stopped, no device interrupt is in flight into the interrupt
    /// controller afterwards.
    ///
    /// On failure the pairs this call detached are attached again. If that rollback fails too,
    /// [`VmError::IrqfdRollback`] reports it; the journal still records exactly which pairs are
    /// attached.
    pub fn detach_irqfds(&self) -> Result<(), VmError> {
        let mut irqfds = self.irqfds();
        let mut detached = Vec::new();
        for (index, registration) in irqfds.iter_mut().enumerate() {
            if !registration.attached {
                continue;
            }
            match self
                .common
                .fd
                .unregister_irqfd(&registration.evt, registration.gsi)
            {
                Ok(()) => {
                    registration.attached = false;
                    detached.push(index);
                }
                Err(err) => {
                    let failed = registration.gsi;
                    for index in detached {
                        let registration = &mut irqfds[index];
                        if let Err(rollback) = self
                            .common
                            .fd
                            .register_irqfd(&registration.evt, registration.gsi)
                        {
                            return Err(VmError::IrqfdRollback(
                                failed,
                                err,
                                registration.gsi,
                                rollback,
                            ));
                        }
                        registration.attached = true;
                    }
                    return Err(VmError::Irqfd(failed, err));
                }
            }
        }
        Ok(())
    }

    /// Attaches again every IRQFD the journal records as detached. A failure leaves the pairs
    /// attached so far attached, as the journal records.
    pub fn attach_irqfds(&self) -> Result<(), VmError> {
        for registration in self.irqfds().iter_mut().filter(|r| !r.attached) {
            self.common
                .fd
                .register_irqfd(&registration.evt, registration.gsi)
                .map_err(|err| VmError::Irqfd(registration.gsi, err))?;
            registration.attached = true;
        }
        Ok(())
    }

    /// Register an MSI device interrupt
    pub fn register_msi(
        &self,
        route: &MsixVector,
        masked: bool,
        config: MsixVectorConfig,
    ) -> Result<(), errno::Error> {
        let mut entry = kvm_irq_routing_entry {
            gsi: route.gsi,
            type_: KVM_IRQ_ROUTING_MSI,
            ..Default::default()
        };
        entry.u.msi.address_lo = config.low_addr;
        entry.u.msi.address_hi = config.high_addr;
        entry.u.msi.data = config.data;

        if self.common.fd.check_extension(kvm_ioctls::Cap::MsiDevid) {
            entry.flags = KVM_MSI_VALID_DEVID;
            entry.u.msi.__bindgen_anon_1.devid = config.devid.into();
        }

        self.common
            .interrupts
            .lock()
            .expect("Poisoned lock")
            .insert(route.gsi, RoutingEntry { entry, masked });

        Ok(())
    }

    /// Create a group of MSI-X interrupts
    pub fn create_msix_group(
        vm: Arc<KvmVm>,
        count: u16,
    ) -> Result<MsixVectorGroup, InterruptError> {
        debug!("Creating new MSI group with {count} vectors");
        let mut vectors = Vec::with_capacity(count as usize);
        for gsi in vm
            .resource_allocator()
            .allocate_gsi_msi(count as u32)?
            .iter()
        {
            vectors.push(MsixVector::new(*gsi, false)?);
        }

        Ok(MsixVectorGroup { vm, vectors })
    }

    /// Set GSI routes to KVM
    pub fn set_gsi_routes(&self) -> Result<(), InterruptError> {
        let entries = self.common.interrupts.lock().expect("Poisoned lock");
        let mut routes = KvmIrqRouting::new(0)?;

        for entry in entries.values() {
            if entry.masked {
                continue;
            }
            routes.push(entry.entry)?;
        }

        self.common.fd.set_gsi_routing(&routes)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::Ordering;

    use vm_memory::mmap::MmapRegionBuilder;
    use vm_memory::{Bytes, GuestAddress};

    use super::*;
    use crate::pci::PciSBDF;
    use crate::snapshot::Persist;
    use crate::test_utils::single_region_mem_raw;
    use crate::utils::mib_to_bytes;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::Bitmap;
    use crate::vstate::memory::{GuestMemoryRegionState, GuestRegionMmap};

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm() -> KvmVm {
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        KvmVm::new(kvm).expect("Cannot create new vm")
    }

    // Auxiliary function being used throughout the tests.
    pub(crate) fn setup_vm_with_memory(mem_size: usize) -> KvmVm {
        let mut vm = setup_vm();
        let gm = single_region_mem_raw(mem_size);
        vm.register_memory_regions(gm).unwrap();
        vm
    }

    fn slotted_memory(layout: &[(GuestAddress, usize)], slots: &[u32]) -> GuestMemoryMmap {
        let regions = crate::test_utils::multi_region_mem_raw(layout)
            .into_iter()
            .zip(slots)
            .map(|(region, &slot)| GuestRegionMmapExt::from_mmap_region(region, slot))
            .collect();
        GuestMemoryMmap::from_regions(regions).unwrap()
    }

    #[test]
    fn test_adoption_rejects_asymmetric_geometry() {
        let page_size = host_page_size();
        let layout = [
            (GuestAddress(0), 4 * page_size),
            (GuestAddress(0x10_0000), 2 * page_size),
        ];
        let memory = slotted_memory(&layout, &[0, 1]);
        check_adoption(&memory, &memory.describe(), 0, 32).unwrap();

        let mut resized = memory.describe();
        resized.regions[1].size = 4 * page_size;
        let mut moved = memory.describe();
        moved.regions[1].base_address = 0x20_0000;
        let mut truncated = memory.describe();
        truncated.regions.pop();
        let mut extended = memory.describe();
        extended.regions.push(GuestMemoryRegionState {
            base_address: 0x30_0000,
            size: page_size,
        });
        for want in [resized, moved, truncated, extended] {
            assert_eq!(
                check_adoption(&memory, &want, 0, 32)
                    .unwrap_err()
                    .to_string(),
                VmError::from(AdoptGuestMemoryError::Geometry {
                    got: memory.describe(),
                    want: want.clone(),
                })
                .to_string()
            );
        }
    }

    #[test]
    fn test_adoption_preserves_slot_ids() {
        let page_size = host_page_size();
        let layout = [
            (GuestAddress(0), page_size),
            (GuestAddress(0x10_0000), page_size),
        ];
        let slot_error = |memory: &GuestMemoryMmap, first_slot, max_memslots| match check_adoption(
            memory,
            &memory.describe(),
            first_slot,
            max_memslots,
        ) {
            Err(VmError::AdoptGuestMemory(err)) => err,
            other => panic!("unexpected {other:?}"),
        };

        let memory = slotted_memory(&layout, &[0, 1]);
        // A VM that already reserved a slot would silently renumber the regions.
        assert_eq!(
            slot_error(&memory, 1, 32),
            AdoptGuestMemoryError::Slot {
                addr: 0,
                slot: 0,
                fresh: 1
            }
        );
        // Slots must follow address order, as the source assigned them.
        assert_eq!(
            slot_error(&slotted_memory(&layout, &[1, 0]), 0, 32),
            AdoptGuestMemoryError::Slot {
                addr: 0,
                slot: 1,
                fresh: 0
            }
        );
        assert_eq!(
            slot_error(&slotted_memory(&layout, &[0, 2]), 0, 32),
            AdoptGuestMemoryError::Slot {
                addr: 0x10_0000,
                slot: 2,
                fresh: 1
            }
        );
        assert!(matches!(
            check_adoption(&memory, &memory.describe(), 0, 1),
            Err(VmError::NotEnoughMemorySlots(1))
        ));
    }

    #[test]
    fn test_cold_native_memory_is_adoptable() {
        // Native boot registers its private anonymous RAM on a fresh VM, the admission contract
        // adoption relies on.
        let regions = crate::arch::arch_memory_regions(mib_to_bytes(64));
        let mut source = setup_vm();
        source
            .register_memory_regions(crate::vstate::memory::anonymous(&regions).unwrap())
            .unwrap();
        let memory = source.guest_memory().clone();
        let state = memory.describe();
        check_adoption(&memory, &state, 0, source.common.max_memslots).unwrap();
        let mut child = setup_vm();
        child.adopt_guest_memory(memory, &state).unwrap();
    }

    #[test]
    fn test_adopt_guest_memory() {
        let page_size = host_page_size();
        let mut source = setup_vm();
        source
            .register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
                (GuestAddress(0), 2 * page_size),
                (GuestAddress(0x10_0000), 2 * page_size),
            ]))
            .unwrap();
        let written = GuestAddress(0x10_0000 + page_size as u64);
        source.guest_memory().write_obj(0xabu8, written).unwrap();
        let any_dirty = |memory: &GuestMemoryMmap| {
            memory.iter().any(|region| {
                let bitmap = (**region).bitmap().as_ref().unwrap();
                (0..u64_to_usize(region.len()))
                    .step_by(page_size)
                    .any(|offset| bitmap.dirty_at(offset))
            })
        };
        assert!(any_dirty(source.guest_memory()));
        let state = source.guest_memory().describe();
        let memory = source.guest_memory().clone();
        // The adopted RAM must outlive every original owner.
        drop(source);

        let mut child = setup_vm();
        child.adopt_guest_memory(memory, &state).unwrap();
        let adopted = child.guest_memory();
        assert_eq!(
            adopted.iter().map(|region| region.slot).collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(adopted.read_obj::<u8>(written).unwrap(), 0xab);
        // The source's host accumulator does not leak into the child's first harvest.
        assert!(!any_dirty(adopted));
        let mut union_slots: Vec<_> = child.pending_dirty_union().keys().copied().collect();
        union_slots.sort_unstable();
        assert_eq!(union_slots, [0, 1]);
        // The next slot follows the adopted ones.
        assert_eq!(child.next_kvm_slot(1), Some(2));

        let again = child.guest_memory().clone();
        assert!(matches!(
            child.adopt_guest_memory(again, &state),
            Err(VmError::AdoptGuestMemory(AdoptGuestMemoryError::NotFresh))
        ));
    }

    thread_local! {
        /// Index of the vCPU whose start [`KvmVm::start_vcpus`] fails, if any.
        pub(super) static FAIL_VCPU_START: std::cell::Cell<Option<usize>> =
            const { std::cell::Cell::new(None) };
    }

    #[test]
    fn test_start_vcpus_recovers_every_vcpu_after_nth_failure() {
        use crate::vstate::vcpu::StartThreadedError;
        use crate::vstate::worker::WorkerStartError;

        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        let vcpus = vm.create_vcpus(3).unwrap();
        let vm = Arc::new(vm);
        let indexes = |vcpus: &[Vcpu]| vcpus.iter().map(|v| v.kvm_vcpu.index).collect::<Vec<_>>();

        FAIL_VCPU_START.set(Some(1));
        let (err, vcpus) = vm.start_vcpus(vcpus, Arc::new(vec![])).unwrap_err();
        FAIL_VCPU_START.set(None);
        assert!(matches!(
            err,
            StartVcpusError::VcpuHandle(StartThreadedError::Worker(WorkerStartError::Filter(_)))
        ));
        // The vCPU already running was stopped again: none is left running, none is lost.
        assert!(vm.vcpus_handles().is_empty());
        assert_eq!(indexes(&vcpus), [0, 1, 2]);

        vm.start_vcpus(vcpus, Arc::new(vec![]))
            .map_err(|(err, _)| err)
            .unwrap();
        let vcpus = vm.stop_vcpus();
        assert!(vm.vcpus_handles().is_empty());
        assert_eq!(indexes(&vcpus), [0, 1, 2]);
    }

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        KvmVm::new(kvm).unwrap();
    }

    #[test]
    fn test_snapshot_dirty_log_merges_host_words_without_resetting_them() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
            (GuestAddress(0), 65 * page_size),
            (GuestAddress(0x10_0000), 2 * page_size),
        ]))
        .unwrap();
        vm.baseline_dirty_log().unwrap();

        let dirty_pages = [vec![0, 63, 64], vec![1]];
        for (region, pages) in vm.guest_memory().iter().zip(&dirty_pages) {
            let bitmap = region.bitmap().unwrap();
            for page in pages {
                bitmap.mark_dirty(page * page_size, 1);
            }
        }

        let snapshot = vm.snapshot_dirty_log().unwrap();
        for ((region, words), dirty) in vm.guest_memory().iter().zip(&snapshot).zip(&dirty_pages) {
            let pages = u64_to_usize(region.len()).div_ceil(page_size);
            for page in 0..pages {
                let want = dirty.contains(&page);
                assert_eq!(words[page / 64] & (1 << (page % 64)) != 0, want);
                assert_eq!(region.bitmap().unwrap().dirty_at(page * page_size), want);
            }
        }
    }

    #[test]
    fn test_register_memory_regions() {
        let mut vm = setup_vm();

        // Trying to set a memory region with a size that is not a multiple of GUEST_PAGE_SIZE
        // will result in error.
        let gm = single_region_mem_raw(0x10);
        let res = vm.register_memory_regions(gm);
        assert_eq!(
            res.unwrap_err().to_string(),
            "Cannot set the memory regions: Invalid argument (os error 22)"
        );

        let gm = single_region_mem_raw(0x1000);
        let res = vm.register_memory_regions(gm);
        res.unwrap();
    }

    /// A clear that fails part way through must leave every reported bit for the next harvest.
    #[test]
    fn test_failed_clear_preserves_every_reported_bit() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
            (GuestAddress(0), 65 * page_size),
            (GuestAddress(0x10_0000), 65 * page_size),
        ]))
        .unwrap();

        vm.guest_memory().mark_dirty(GuestAddress(0), page_size);
        vm.guest_memory()
            .mark_dirty(GuestAddress(0x10_0000), page_size);
        let snapshot = vm.snapshot_dirty_log().unwrap();
        assert!(
            snapshot
                .iter()
                .all(|words| { words[0] == u64::MAX && words[1] & 1 == 1 && words[1] & !1 == 0 })
        );

        // Emptying the accumulator leaves the snapshot as the only record of those bits, so the
        // assertion below holds exactly when the clear took them over before touching KVM.
        vm.guest_memory().reset_dirty();

        // Dropping dirty logging on the second slot makes its clear fail while the first succeeds.
        let second: &GuestRegionMmapExt = vm.guest_memory().iter().nth(1).unwrap();
        let mut region = kvm_userspace_memory_region::from(second);
        region.flags = 0;
        vm.set_user_memory_region(region).unwrap();

        assert!(matches!(
            vm.clear_dirty_log(&snapshot),
            Err(VmError::ClearDirtyLog(_))
        ));
        // The bits live in the pending-union accumulator, word for word, rather than in the host
        // bitmap the clear reset.
        let pending = vm.pending_dirty_union();
        for (region, words) in vm.guest_memory().iter().zip(&snapshot) {
            assert_eq!(pending.get(&region.slot).unwrap(), words);
        }
        drop(pending);

        // Re-arm dirty logging on the second slot so the next harvest can read it. KVM cleared the
        // first slot and the host accumulator was emptied, so the returned bits are the only
        // record of that slot's pages.
        let armed: &GuestRegionMmapExt = vm.guest_memory().iter().nth(1).unwrap();
        vm.set_user_memory_region(kvm_userspace_memory_region::from(armed))
            .unwrap();
        let next = vm.snapshot_dirty_log().unwrap();
        assert_eq!(next[0], snapshot[0]);
    }

    fn empty_snapshot(vm: &KvmVm) -> Vec<Vec<u64>> {
        let page_size = host_page_size();
        vm.guest_memory()
            .iter()
            .map(|region| vec![0u64; u64_to_usize(region.len()).div_ceil(page_size).div_ceil(64)])
            .collect()
    }

    fn dirty_pages_of(vm: &KvmVm, snapshot: &[Vec<u64>]) -> Vec<Vec<usize>> {
        let page_size = host_page_size();
        vm.guest_memory()
            .iter()
            .zip(snapshot)
            .map(|(region, words)| {
                let pages = u64_to_usize(region.len()).div_ceil(page_size);
                (0..pages)
                    .filter(|page| words[page / 64] & (1 << (page % 64)) != 0)
                    .collect()
            })
            .collect()
    }

    /// A harvest reports the exact union of KVM's log, the host accumulator, and returned bits.
    /// Only a successful clear retires those sources.
    #[test]
    fn test_snapshot_unions_kvm_host_and_returned_words() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
            (GuestAddress(0), 65 * page_size),
            (GuestAddress(0x10_0000), 2 * page_size),
        ]))
        .unwrap();
        vm.baseline_dirty_log().unwrap();

        let mut returned = empty_snapshot(&vm);
        returned[0][1] |= 1;
        returned[1][0] |= 1 << 1;
        vm.union_dirty_log(&returned).unwrap();

        vm.guest_memory().mark_dirty(GuestAddress(0), page_size);

        let snapshot = vm.snapshot_dirty_log().unwrap();
        assert_eq!(dirty_pages_of(&vm, &snapshot), vec![vec![0, 64], vec![1]]);

        // Snapshotting alone retires nothing, so the returned words remain visible.
        let next = vm.snapshot_dirty_log().unwrap();
        assert_eq!(dirty_pages_of(&vm, &next), vec![vec![0, 64], vec![1]]);

        vm.clear_dirty_log(&snapshot).unwrap();
        let retired = vm.snapshot_dirty_log().unwrap();
        assert!(retired.iter().flatten().all(|word| *word == 0));
    }

    /// Two unions accumulate: the harvest that follows reports every returned bit once.
    #[test]
    fn test_repeated_unions_accumulate() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(single_region_mem_raw(130 * page_size))
            .unwrap();
        vm.baseline_dirty_log().unwrap();

        let mut first = empty_snapshot(&vm);
        first[0][0] |= 1 << 3;
        first[0][2] |= 1;
        vm.union_dirty_log(&first).unwrap();

        let mut second = empty_snapshot(&vm);
        second[0][0] |= 1 << 3;
        second[0][1] |= 1 << 5;
        vm.union_dirty_log(&second).unwrap();

        let snapshot = vm.snapshot_dirty_log().unwrap();
        assert_eq!(dirty_pages_of(&vm, &snapshot), vec![vec![3, 69, 128]]);
    }

    /// A union whose geometry does not match the registered regions is rejected as a whole.
    #[test]
    fn test_union_rejects_a_mismatched_shape() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
            (GuestAddress(0), 2 * page_size),
            (GuestAddress(0x10_0000), 2 * page_size),
        ]))
        .unwrap();
        vm.baseline_dirty_log().unwrap();

        let mut short = empty_snapshot(&vm);
        short.pop().unwrap();
        assert!(matches!(
            vm.union_dirty_log(&short),
            Err(VmError::DirtyBitmapShape)
        ));

        // The first region's words are too wide. The second region's bit must not land either.
        let mut wide = empty_snapshot(&vm);
        wide[0].push(u64::MAX);
        wide[1][0] |= 1;
        assert!(matches!(
            vm.union_dirty_log(&wide),
            Err(VmError::DirtyBitmapShape)
        ));

        let snapshot = vm.snapshot_dirty_log().unwrap();
        assert!(snapshot.iter().flatten().all(|word| *word == 0));
    }

    /// A restored VM's baseline retires KVM's initially-set state and nothing else.
    #[test]
    fn test_baseline_retires_only_the_initial_kvm_bitmap() {
        let page_size = host_page_size();
        let mut vm = setup_vm();
        vm.register_memory_regions(crate::test_utils::multi_region_mem_raw(&[
            (GuestAddress(0), 4 * page_size),
            (GuestAddress(0x10_0000), 2 * page_size),
        ]))
        .unwrap();

        let set_pages = |vm: &KvmVm| -> Vec<Vec<usize>> {
            let snapshot = vm.snapshot_dirty_log().unwrap();
            vm.guest_memory()
                .iter()
                .zip(&snapshot)
                .map(|(region, words)| {
                    let pages = u64_to_usize(region.len()).div_ceil(page_size);
                    (0..pages)
                        .filter(|page| words[page / 64] & (1 << (page % 64)) != 0)
                        .collect()
                })
                .collect()
        };

        // KVM_DIRTY_LOG_INITIALLY_SET: every page of every freshly registered slot starts dirty.
        assert_eq!(set_pages(&vm), vec![vec![0, 1, 2, 3], vec![0, 1]]);

        vm.baseline_dirty_log().unwrap();
        assert_eq!(set_pages(&vm), vec![Vec::<usize>::new(), Vec::new()]);

        // The host accumulator is a separate channel, and the writes it holds happen after the
        // slots are committed. A baseline that swallowed them would drop device-restore writes.
        let second_page = GuestAddress(u64::try_from(page_size).unwrap());
        vm.guest_memory().mark_dirty(second_page, page_size);
        vm.baseline_dirty_log().unwrap();
        assert_eq!(set_pages(&vm), vec![vec![1], Vec::new()]);

        // And a harvest still retires them, so the baseline did not make the log write-only.
        let snapshot = vm.snapshot_dirty_log().unwrap();
        vm.clear_dirty_log(&snapshot).unwrap();
        assert_eq!(set_pages(&vm), vec![Vec::<usize>::new(), Vec::new()]);
    }

    #[test]
    fn test_too_many_regions() {
        let mut vm = setup_vm();
        let max_nr_regions = vm.kvm().max_nr_memslots();

        // SAFETY: valid mmap parameters
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };

        assert_ne!(ptr, libc::MAP_FAILED);

        for i in 0..=max_nr_regions {
            // SAFETY: we assert above that the ptr is valid, and the size matches what we passed to
            // mmap
            let region = unsafe {
                MmapRegionBuilder::new(0x1000)
                    .with_raw_mmap_pointer(ptr.cast())
                    .build()
                    .unwrap()
            };

            let region = GuestRegionMmap::new(region, GuestAddress(i as u64 * 0x1000)).unwrap();

            let res = vm.register_memory_regions(vec![region]);

            if max_nr_regions <= i {
                assert!(
                    matches!(res, Err(VmError::NotEnoughMemorySlots(v)) if v == max_nr_regions),
                    "{:?} at iteration {}",
                    res,
                    i
                );
            } else {
                res.unwrap_or_else(|_| {
                    panic!(
                        "to be able to insert more regions in iteration {i} - max_nr_memslots: \
                         {max_nr_regions} - num_regions: {}",
                        vm.guest_memory().num_regions()
                    )
                });
            }
        }
    }

    #[test]
    fn test_create_vcpus() {
        let vcpu_count = 2;
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));

        let vcpu_vec = vm.create_vcpus(vcpu_count).unwrap();

        assert_eq!(vcpu_vec.len(), vcpu_count as usize);
    }

    fn enable_irqchip(vm: &mut KvmVm) {
        #[cfg(target_arch = "x86_64")]
        vm.setup_irqchip().unwrap();
        #[cfg(target_arch = "aarch64")]
        vm.setup_irqchip(1).unwrap();
    }

    #[test]
    fn test_msi_vector_group_new() {
        let vm = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
        assert_eq!(msix_group.num_vectors(), 4);
    }

    #[test]
    fn test_msi_vector_group_enable_disable() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        // Initially all vectors are disabled
        for route in &msix_group.vectors {
            assert!(!route.enabled.load(Ordering::Acquire))
        }

        // Enable works
        msix_group.enable().unwrap();
        for route in &msix_group.vectors {
            assert!(route.enabled.load(Ordering::Acquire));
        }
        // Enabling an enabled group doesn't error out
        msix_group.enable().unwrap();

        // Disable works
        msix_group.disable().unwrap();
        for route in &msix_group.vectors {
            assert!(!route.enabled.load(Ordering::Acquire))
        }
        // Disabling a disabled group doesn't error out
    }

    #[test]
    fn test_msi_vector_group_trigger() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);

        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        // We can now trigger all vectors
        for i in 0..4 {
            msix_group.trigger(i).unwrap()
        }

        // We can't trigger an invalid vector
        msix_group.trigger(4).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_notifier() {
        let vm = setup_vm_with_memory(mib_to_bytes(128));
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        for i in 0..4 {
            assert!(msix_group.notifier(i).is_some());
        }

        assert!(msix_group.notifier(4).is_none());
    }

    #[test]
    fn test_msi_vector_group_update_invalid_vector() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
        let config = MsixVectorConfig {
            high_addr: 0x42,
            low_addr: 0x12,
            data: 0x12,
            devid: PciSBDF::from(0xafa),
        };
        msix_group.update(0, config, true, true).unwrap();
        msix_group.update(4, config, true, true).unwrap_err();
    }

    #[test]
    fn test_msi_vector_group_update() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        assert!(vm.common.interrupts.lock().unwrap().is_empty());
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        // Set some configuration for the vectors. Initially all are masked
        let mut config = MsixVectorConfig {
            high_addr: 0x42,
            low_addr: 0x13,
            data: 0x12,
            devid: PciSBDF::from(0xafa),
        };
        for i in 0..4 {
            config.data = 0x12 * i;
            msix_group.update(i as usize, config, true, false).unwrap();
        }

        // All vectors should be disabled
        for vector in &msix_group.vectors {
            assert!(!vector.enabled.load(Ordering::Acquire));
        }

        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert!(kvm_route.masked);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }

        // Simply enabling the vectors should not update the registered IRQ routes
        msix_group.enable().unwrap();
        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert!(kvm_route.masked);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }

        // Updating the config of a vector should enable its route (and only its route)
        config.data = 0;
        msix_group.update(0, config, false, true).unwrap();
        for i in 0..4 {
            let gsi = crate::arch::GSI_MSI_START + i;
            let interrupts = vm.common.interrupts.lock().unwrap();
            let kvm_route = interrupts.get(&gsi).unwrap();
            assert_eq!(kvm_route.masked, i != 0);
            assert_eq!(kvm_route.entry.gsi, gsi);
            assert_eq!(kvm_route.entry.type_, KVM_IRQ_ROUTING_MSI);
            // SAFETY: because we know we setup MSI routes.
            unsafe {
                assert_eq!(kvm_route.entry.u.msi.address_hi, 0x42);
                assert_eq!(kvm_route.entry.u.msi.address_lo, 0x13);
                assert_eq!(kvm_route.entry.u.msi.data, 0x12 * i);
            }
        }
    }

    #[test]
    fn test_msi_vector_group_persistence() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);
        let msix_group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();

        msix_group.enable().unwrap();
        let state = msix_group.save();
        let restored_group = MsixVectorGroup::restore(vm.clone(), &state).unwrap();

        assert_eq!(msix_group.num_vectors(), restored_group.num_vectors());
        // Even if an MSI group is enabled, we don't save it as such. During restoration, the PCI
        // transport will make sure the correct config is set for the vectors and enable them
        // accordingly.
        for (id, vector) in msix_group.vectors.iter().enumerate() {
            let new_vector = &restored_group.vectors[id];
            assert_eq!(vector.gsi, new_vector.gsi);
            assert!(!new_vector.enabled.load(Ordering::Acquire));
        }

        // Both groups own the same GSIs in this test so dropping both will result in panic. Resolve
        // this by simply forgetting about the restored version.
        std::mem::forget(restored_group);
    }

    #[test]
    fn test_msi_vector_group_drop_frees_gsis() {
        let mut vm = setup_vm_with_memory(mib_to_bytes(128));
        enable_irqchip(&mut vm);
        let vm = Arc::new(vm);

        let gsis_before = vm.resource_allocator().allocate_gsi_msi(1).unwrap();
        for id in gsis_before.iter() {
            vm.resource_allocator()
                .gsi_msi_allocator
                .free_id(*id)
                .unwrap();
        }

        // Allocating, configuring and dropping a group must leave the allocator and the routing
        // table in the same state as before.
        {
            let group = KvmVm::create_msix_group(vm.clone(), 4).unwrap();
            let config = MsixVectorConfig {
                high_addr: 0x42,
                low_addr: 0x13,
                data: 0x12,
                devid: PciSBDF::from(0xafa),
            };
            for i in 0..group.num_vectors() as usize {
                group.update(i, config, false, true).unwrap();
            }
            assert_eq!(vm.common.interrupts.lock().unwrap().len(), 4);
        }

        assert!(vm.common.interrupts.lock().unwrap().is_empty());
        let gsis_after = vm.resource_allocator().allocate_gsi_msi(1).unwrap();
        assert_eq!(gsis_before, gsis_after);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_restore_state_resource_allocator() {
        use vm_allocator::AllocPolicy;

        let mut vm = setup_vm_with_memory(0x1000);
        vm.setup_irqchip().unwrap();

        // Allocate a GSI and some memory and make sure they are still allocated after restore
        let (gsi, range) = {
            let mut resource_allocator = vm.resource_allocator();

            let gsi = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
            let range = resource_allocator
                .mmio32_memory
                .allocate(1024, 1024, AllocPolicy::FirstMatch)
                .unwrap();
            (gsi, range.start())
        };

        let state = vm.save_state().unwrap();
        let serialized_data = bitcode::serialize(&state).unwrap();

        let restored_state: VmState = bitcode::deserialize(&serialized_data).unwrap();
        vm.restore_state(&restored_state, false).unwrap();

        let mut resource_allocator = vm.resource_allocator();
        let gsi_new = resource_allocator.allocate_gsi_msi(1).unwrap()[0];
        assert_eq!(gsi + 1, gsi_new);

        resource_allocator
            .mmio32_memory
            .allocate(1024, 1024, AllocPolicy::ExactMatch(range))
            .unwrap_err();
        let range_new = resource_allocator
            .mmio32_memory
            .allocate(1024, 1024, AllocPolicy::FirstMatch)
            .unwrap();
        assert_eq!(range + 1024, range_new.start());
    }
}
