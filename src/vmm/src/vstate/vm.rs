// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

#[cfg(target_arch = "x86_64")]
use kvm_bindings::KVM_IRQCHIP_IOAPIC;
use kvm_bindings::{
    KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2, KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE,
    KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI, KVM_MSI_VALID_DEVID, KvmIrqRouting,
    kvm_clear_dirty_log, kvm_enable_cap, kvm_irq_routing_entry, kvm_userspace_memory_region,
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
    Bitmap, GuestMemory, GuestMemoryExtension, GuestMemoryMmap, GuestMemoryRegion,
    GuestMemoryState, GuestRegionMmap, GuestRegionMmapExt, MemoryError,
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
        // nor re-protects, so a capture reports each epoch exactly once.
        let mut cap = kvm_enable_cap {
            cap: KVM_CAP_MANUAL_DIRTY_LOG_PROTECT2,
            ..Default::default()
        };
        cap.args[0] = u64::from(KVM_DIRTY_LOG_MANUAL_PROTECT_ENABLE);
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
            resource_allocator: Mutex::new(ResourceAllocator::new()),
            mmio_bus: Arc::new(Bus::new()),
            kvm,
            vcpus_handles: Mutex::new(Vec::new()),
            vcpus_exit_evt,
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

    /// Starts the microVM vCPUs.
    ///
    /// Sets the terminal to raw/non-blocking mode, then spawns a thread per vCPU
    /// and stores the resulting handles. The barrier is used to synchronize TLS
    /// initialization across all vCPU threads before returning.
    pub fn start_vcpus(
        self: &Arc<Self>,
        mut vcpus: Vec<Vcpu>,
        vcpu_seccomp_filter: Arc<crate::seccomp::BpfProgram>,
    ) -> Result<(), StartVcpusError> {
        let vcpu_count = vcpus.len();
        let barrier = Arc::new(Barrier::new(vcpu_count + 1));

        let stdin = std::io::stdin().lock();
        stdin.set_raw_mode().inspect_err(|&err| {
            crate::logger::warn!("Cannot set raw mode for the terminal. {:?}", err);
        })?;
        stdin.set_non_block(true).inspect_err(|&err| {
            crate::logger::warn!("Cannot set non block for the terminal. {:?}", err);
        })?;

        let mut handles = self.vcpus_handles();
        handles.reserve(vcpu_count);
        for mut vcpu in vcpus.drain(..) {
            vcpu.set_mmio_bus(self.common.mmio_bus.clone());
            #[cfg(target_arch = "x86_64")]
            vcpu.kvm_vcpu.set_pio_bus(self.pio_bus.clone());

            handles.push(vcpu.start_threaded(
                self,
                vcpu_seccomp_filter.clone(),
                barrier.clone(),
            )?);
        }
        drop(handles);
        barrier.wait();

        Ok(())
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
        self.common.guest_memory = new_guest_memory;

        Ok(())
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
    pub fn snapshot_dirty_log(&self) -> Result<Vec<Vec<u64>>, VmError> {
        let page_size = host_page_size();
        self.guest_memory()
            .iter()
            .map(|region| {
                let len = u64_to_usize(region.len());
                let mut words = self
                    .fd()
                    .get_dirty_log(region.slot, len)
                    .map_err(VmError::GetDirtyLog)?;
                let pages = len.div_ceil(page_size);
                if words.len() != pages.div_ceil(64) {
                    return Err(VmError::DirtyBitmapShape);
                }
                if let Some(host_writes) = region.bitmap() {
                    for page in 0..pages {
                        if host_writes.dirty_at(page * page_size) {
                            words[page / 64] |= 1 << (page % 64);
                        }
                    }
                }
                Ok(words)
            })
            .collect()
    }

    /// Retires the bits of a snapshot: KVM re-protects them and the host accumulator is reset.
    ///
    /// KVM drops a slot's bits as it clears them, so the accumulator takes the whole snapshot over
    /// first and is only reset once every slot cleared: a failure part way through leaves every
    /// reported bit for the next harvest.
    pub fn clear_dirty_log(&self, snapshot: &[Vec<u64>]) -> Result<(), VmError> {
        let page_size = host_page_size();
        if snapshot.len() != self.guest_memory().num_regions() {
            return Err(VmError::DirtyBitmapShape);
        }
        for (region, words) in self.guest_memory().iter().zip(snapshot) {
            let pages = u64_to_usize(region.len()).div_ceil(page_size);
            if words.len() != pages.div_ceil(64) {
                return Err(VmError::DirtyBitmapShape);
            }
        }

        self.union_dirty_log(snapshot);
        for (region, words) in self.guest_memory().iter().zip(snapshot) {
            let pages = u64_to_usize(region.len()).div_ceil(page_size);
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
        self.guest_memory().reset_dirty();
        Ok(())
    }

    /// Returns a previously snapshotted bitmap to the accumulator, so the next snapshot reports it.
    pub fn union_dirty_log(&self, bits: &[Vec<u64>]) {
        let page_size = host_page_size();
        for (region, words) in self.guest_memory().iter().zip(bits) {
            let Some(host_writes) = region.bitmap() else {
                continue;
            };
            let pages = u64_to_usize(region.len()).div_ceil(page_size);
            for page in 0..pages {
                if words[page / 64] & (1 << (page % 64)) != 0 {
                    host_writes.mark_dirty(page * page_size, 1);
                }
            }
        }
    }

    /// Register a device IRQ
    pub fn register_irq(&self, fd: &EventFd, gsi: u32) -> Result<(), errno::Error> {
        self.common.fd.register_irqfd(fd, gsi)?;

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

    use vm_memory::GuestAddress;
    use vm_memory::mmap::MmapRegionBuilder;

    use super::*;
    use crate::pci::PciSBDF;
    use crate::snapshot::Persist;
    use crate::test_utils::single_region_mem_raw;
    use crate::utils::mib_to_bytes;
    use crate::vstate::kvm::Kvm;
    use crate::vstate::memory::GuestRegionMmap;

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

    #[test]
    fn test_new() {
        // Testing with a valid /dev/kvm descriptor.
        let kvm = Kvm::new(vec![]).expect("Cannot create Kvm");
        KvmVm::new(kvm).unwrap();
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
            (GuestAddress(0), page_size),
            (GuestAddress(0x1_0000), page_size),
        ]))
        .unwrap();

        vm.guest_memory().mark_dirty(GuestAddress(0), page_size);
        vm.guest_memory()
            .mark_dirty(GuestAddress(0x1_0000), page_size);
        let snapshot = vm.snapshot_dirty_log().unwrap();
        assert!(snapshot.iter().all(|words| words[0] & 1 == 1));

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
        for region in vm.guest_memory().iter() {
            assert!(region.bitmap().unwrap().dirty_at(0));
        }
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
