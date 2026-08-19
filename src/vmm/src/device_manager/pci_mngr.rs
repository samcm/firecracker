// Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::DerefMut;
use std::sync::{Arc, Mutex};

use event_manager::{MutEventSubscriber, SubscriberOps};
use serde::{Deserialize, Serialize};

use crate::EventManager;
use crate::device_manager::DevicePersistError;
use crate::devices::pci::PciSegment;
use crate::devices::virtio::block::device::Block;
use crate::devices::virtio::block::persist::{BlockConstructorArgs, BlockState};
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceId, VirtioDeviceType};
use crate::devices::virtio::net::Net;
use crate::devices::virtio::net::persist::{NetConstructorArgs, NetState};
use crate::devices::virtio::rng::Entropy;
use crate::devices::virtio::rng::persist::{EntropyConstructorArgs, EntropyState};
use crate::devices::virtio::transport::pci::device::{
    CAPABILITY_BAR_SIZE, VirtioPciDevice, VirtioPciDeviceError, VirtioPciDeviceState,
};
use crate::devices::virtio::vsock::persist::{
    VsockConstructorArgs, VsockState, VsockUdsConstructorArgs,
};
use crate::devices::virtio::vsock::{Vsock, VsockUnixBackend};
use crate::logger::debug;
use crate::pci::PciSBDF;
use crate::pci::bus::PciRootError;
use crate::resources::VmResources;
use crate::snapshot::Persist;
use crate::vstate::bus::BusError;
use crate::vstate::interrupts::InterruptError;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

#[derive(Debug, Default)]
pub struct PciDevices {
    /// PCIe segment of the VMM, if PCI is enabled. We currently support a single PCIe segment.
    pub pci_segment: Option<PciSegment>,
    /// All VirtIO PCI devices of the system
    pub virtio_devices: HashMap<VirtioDeviceId, Arc<Mutex<VirtioPciDevice>>>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum PciManagerError {
    /// Resource allocation error: {0}
    ResourceAllocation(#[from] vm_allocator::Error),
    /// Bus error: {0}
    Bus(#[from] BusError),
    /// PCI root error: {0}
    PciRoot(#[from] PciRootError),
    /// MSI error: {0}
    Msi(#[from] InterruptError),
    /// VirtIO PCI device error: {0}
    VirtioPciDevice(#[from] VirtioPciDeviceError),
    /// KVM error: {0}
    Kvm(#[from] vmm_sys_util::errno::Error),
}

impl PciDevices {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn attach_pci_segment(&mut self, vm: &Arc<KvmVm>) -> Result<(), PciManagerError> {
        // We only support a single PCIe segment. Calling this function twice is a Firecracker
        // internal error.
        assert!(self.pci_segment.is_none());

        // Currently we don't assign any IRQs to PCI devices. We will be using MSI-X interrupts
        // only.
        let pci_segment = PciSegment::new(0, vm, &[0u8; 32])?;
        self.pci_segment = Some(pci_segment);

        Ok(())
    }

    fn register_bars_with_bus(
        vm: &KvmVm,
        virtio_device: &Arc<Mutex<VirtioPciDevice>>,
    ) -> Result<(), PciManagerError> {
        let virtio_device_locked = virtio_device.lock().expect("Poisoned lock");

        debug!(
            "Inserting MMIO BAR region: {:#x}:{:#x}",
            virtio_device_locked.config_bar_addr(),
            CAPABILITY_BAR_SIZE
        );
        vm.common.mmio_bus.insert(
            virtio_device.clone(),
            virtio_device_locked.config_bar_addr(),
            CAPABILITY_BAR_SIZE,
        )?;

        Ok(())
    }

    fn attach_common(
        &mut self,
        vm: &KvmVm,
        device_type: VirtioDeviceType,
        id: String,
        sbdf: PciSBDF,
        virtio_device: Arc<Mutex<VirtioPciDevice>>,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        // We should only be reaching this point if PCI is enabled
        let pci_segment = self.pci_segment.as_ref().unwrap();

        pci_segment
            .pci_bus
            .lock()
            .expect("Poisoned lock")
            .add_device(sbdf.device(), virtio_device.clone())?;

        self.virtio_devices
            .insert((device_type, id), virtio_device.clone());

        Self::register_bars_with_bus(vm, &virtio_device)?;

        let mut device = virtio_device.lock().expect("Poisoned lock");
        device.register_notification_ioevent(vm)?;

        let sub_id = event_manager.add_subscriber(device.virtio_device());
        device.sub_id = Some(sub_id);

        Ok(())
    }

    pub(crate) fn attach_pci_virtio_device(
        &mut self,
        vm: &Arc<KvmVm>,
        id: String,
        device: Arc<Mutex<dyn VirtioDevice>>,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        // We should only be reaching this point if PCI is enabled
        let pci_segment = self.pci_segment.as_ref().unwrap();
        let sbdf = pci_segment.next_device_sbdf()?;
        debug!("Allocating SBDF: {sbdf:?} for device");
        let mem = vm.guest_memory().clone();

        let device_type = device.lock().expect("Poisoned lock").device_type();

        // Allocate one MSI vector per queue, plus one for configuration
        let msix_num =
            u16::try_from(device.lock().expect("Poisoned lock").queues().len() + 1).unwrap();

        let msix_vectors = KvmVm::create_msix_group(vm.clone(), msix_num)?;

        // Create the transport
        let mut virtio_device =
            VirtioPciDevice::new(id.clone(), mem, device, Arc::new(msix_vectors), sbdf)?;

        // Allocate bars
        let mut resource_allocator_lock = vm.resource_allocator();
        let resource_allocator = resource_allocator_lock.deref_mut();

        virtio_device.allocate_bars(&mut resource_allocator.mmio64_memory);

        let virtio_device = Arc::new(Mutex::new(virtio_device));

        self.attach_common(vm, device_type, id, sbdf, virtio_device, event_manager)
    }

    fn restore_pci_device<T: 'static + VirtioDevice + MutEventSubscriber + Debug>(
        &mut self,
        vm: &Arc<KvmVm>,
        device: Arc<Mutex<T>>,
        device_id: &str,
        transport_state: &VirtioPciDeviceState,
        event_manager: &mut EventManager,
    ) -> Result<(), PciManagerError> {
        let device_type = device.lock().expect("Poisoned lock").device_type();

        let virtio_device = Arc::new(Mutex::new(VirtioPciDevice::new_from_state(
            device_id.to_string(),
            vm,
            device.clone(),
            transport_state.clone(),
        )?));

        self.attach_common(
            vm,
            device_type,
            device_id.to_string(),
            transport_state.sbdf,
            virtio_device,
            event_manager,
        )?;

        Ok(())
    }

    /// Gets the specified device.
    pub fn get_virtio_device(
        &self,
        device_type: VirtioDeviceType,
        device_id: &str,
    ) -> Option<&Arc<Mutex<VirtioPciDevice>>> {
        self.virtio_devices
            .get(&(device_type, device_id.to_string()))
    }

    pub fn for_each_virtio_device(&self, mut f: impl FnMut(VirtioDeviceType, &dyn VirtioDevice)) {
        for ((device_type, _), pci_device) in &self.virtio_devices {
            let device_arc = pci_device.lock().expect("Poisoned lock").virtio_device();
            let device = device_arc.lock().expect("Poisoned lock");
            f(*device_type, &*device);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtioDeviceState<T> {
    /// Device identifier
    pub device_id: String,
    /// Device SBDF
    pub sbdf: PciSBDF,
    /// Device state
    pub device_state: T,
    /// Transport state
    pub transport_state: VirtioPciDeviceState,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PciDevicesState {
    /// Whether PCI is enabled
    pub pci_enabled: bool,
    /// Block device states.
    pub block_devices: Vec<VirtioDeviceState<BlockState>>,
    /// Net device states.
    pub net_devices: Vec<VirtioDeviceState<NetState>>,
    /// Vsock device state.
    pub vsock_device: Option<VirtioDeviceState<VsockState>>,
    /// Entropy device state.
    pub entropy_device: Option<VirtioDeviceState<EntropyState>>,
}

pub struct PciDevicesConstructorArgs<'a> {
    pub vm: &'a Arc<KvmVm>,
    pub mem: &'a GuestMemoryMmap,
    pub vm_resources: &'a mut VmResources,
    pub event_manager: &'a mut EventManager,
}

impl<'a> Debug for PciDevicesConstructorArgs<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PciDevicesConstructorArgs")
            .field("vm", &self.vm)
            .field("mem", &self.mem)
            .field("vm_resources", &self.vm_resources)
            .finish()
    }
}

impl<'a> Persist<'a> for PciDevices {
    type State = PciDevicesState;
    type ConstructorArgs = PciDevicesConstructorArgs<'a>;
    type Error = DevicePersistError;

    fn save(&self) -> Self::State {
        let mut state = PciDevicesState::default();
        if self.pci_segment.is_some() {
            state.pci_enabled = true;
        } else {
            return state;
        }

        for pci_dev in self.virtio_devices.values() {
            let locked_pci_dev = pci_dev.lock().expect("Poisoned lock");
            let virtio_dev = locked_pci_dev.virtio_device();
            // We need to call `prepare_save()` on the device before saving the transport
            // so that, if we modify the transport state while preparing the device, e.g. sending
            // an interrupt to the guest, this is correctly captured in the saved transport state.
            let mut locked_virtio_dev = virtio_dev.lock().expect("Poisoned lock");
            locked_virtio_dev.prepare_save();
            let transport_state = locked_pci_dev.state();

            let sbdf = transport_state.sbdf;

            match locked_virtio_dev.device_type() {
                VirtioDeviceType::Block => {
                    let block_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Block>()
                        .unwrap();
                    let device_state = block_dev.save();
                    state.block_devices.push(VirtioDeviceState {
                        device_id: block_dev.id().to_string(),
                        sbdf,
                        device_state,
                        transport_state,
                    });
                }
                VirtioDeviceType::Net => {
                    let net_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Net>()
                        .unwrap();
                    let device_state = net_dev.save();

                    state.net_devices.push(VirtioDeviceState {
                        device_id: net_dev.id().to_string(),
                        sbdf,
                        device_state,
                        transport_state,
                    })
                }
                VirtioDeviceType::Vsock => {
                    let vsock_dev = locked_virtio_dev
                        .as_mut_any()
                        // Currently, VsockUnixBackend is the only implementation of VsockBackend.
                        .downcast_mut::<Vsock<VsockUnixBackend>>()
                        .unwrap();

                    // Save state after potential notification to the guest. This
                    // way we save changes to the queue the notification can cause.
                    let vsock_state = VsockState {
                        backend: vsock_dev.backend().save(),
                        frontend: vsock_dev.save(),
                    };

                    state.vsock_device = Some(VirtioDeviceState {
                        device_id: vsock_dev.id().to_string(),
                        sbdf,
                        device_state: vsock_state,
                        transport_state,
                    });
                }
                VirtioDeviceType::Rng => {
                    let rng_dev = locked_virtio_dev
                        .as_mut_any()
                        .downcast_mut::<Entropy>()
                        .unwrap();
                    let device_state = rng_dev.save();

                    state.entropy_device = Some(VirtioDeviceState {
                        device_id: rng_dev.id().to_string(),
                        sbdf,
                        device_state,
                        transport_state,
                    })
                }
            }
        }

        state
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mem = constructor_args.mem;
        let mut pci_devices = PciDevices::new();
        if !state.pci_enabled {
            return Ok(pci_devices);
        }

        pci_devices.attach_pci_segment(constructor_args.vm)?;

        for block_state in &state.block_devices {
            let device = Arc::new(Mutex::new(Block::restore(
                BlockConstructorArgs::inherited(mem.clone(), &block_state.device_state),
                &block_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .block
                .add_virtio_device(device.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &block_state.device_id,
                &block_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        for net_state in &state.net_devices {
            let device = Arc::new(Mutex::new(Net::restore(
                NetConstructorArgs { mem: mem.clone() },
                &net_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .net_builder
                .add_device(device.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &net_state.device_id,
                &net_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        if let Some(vsock_state) = &state.vsock_device {
            let ctor_args = VsockUdsConstructorArgs {
                cid: vsock_state.device_state.frontend.cid,
            };
            let backend = VsockUnixBackend::restore(ctor_args, &vsock_state.device_state.backend)?;
            let device = Arc::new(Mutex::new(Vsock::restore(
                VsockConstructorArgs {
                    mem: mem.clone(),
                    backend,
                },
                &vsock_state.device_state.frontend,
            )?));

            constructor_args
                .vm_resources
                .vsock
                .set_device(device.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &vsock_state.device_id,
                &vsock_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        if let Some(entropy_state) = &state.entropy_device {
            let ctor_args = EntropyConstructorArgs { mem: mem.clone() };

            let device = Arc::new(Mutex::new(Entropy::restore(
                ctor_args,
                &entropy_state.device_state,
            )?));

            constructor_args
                .vm_resources
                .entropy
                .set_device(device.clone());

            pci_devices.restore_pci_device(
                constructor_args.vm,
                device,
                &entropy_state.device_id,
                &entropy_state.transport_state,
                constructor_args.event_manager,
            )?
        }

        Ok(pci_devices)
    }
}
