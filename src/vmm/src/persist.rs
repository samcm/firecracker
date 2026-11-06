// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state structures for saving/restoring a Firecracker microVM.

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "aarch64")]
use crate::arch::aarch64::vcpu::get_manufacturer_id_from_host;
use crate::builder::{self, BuildMicrovmFromSnapshotError};
use crate::cpu_config::templates::StaticCpuTemplate;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::CpuidTrait;
#[cfg(target_arch = "x86_64")]
use crate::cpu_config::x86_64::cpuid::common::get_vendor_id_from_host;
use crate::device_manager::{DevicePersistError, DevicesState};
use crate::logger::{info, warn};
use crate::resources::VmResources;
use crate::seccomp::BpfThreadMap;
use crate::utils::u64_to_usize;
use crate::vmm_config::boot_source::BootSourceConfig;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{MachineConfigError, MachineConfigUpdate};
use crate::vmm_config::snapshot::LoadSnapshotParams;
use crate::vstate::farplane::FarplaneBackend;
use crate::vstate::kvm::KvmState;
use crate::vstate::vcpu::{VcpuSendEventError, VcpuState};
use crate::vstate::vm::VmState;
use crate::{EventManager, Vmm, vstate};

/// Holds information related to the VM that is not part of VmState.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct VmInfo {
    /// Guest memory size.
    pub mem_size_mib: u64,
    /// smt information
    pub smt: bool,
    /// CPU template type
    pub cpu_template: StaticCpuTemplate,
    /// Boot source information.
    pub boot_source: BootSourceConfig,
}

impl From<&VmResources> for VmInfo {
    fn from(value: &VmResources) -> Self {
        Self {
            mem_size_mib: value.machine_config.mem_size_mib as u64,
            smt: value.machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&value.machine_config.cpu_template),
            boot_source: value.boot_source.config.clone(),
        }
    }
}

impl From<&Vmm> for VmInfo {
    fn from(value: &Vmm) -> Self {
        let machine_config = &value.machine_config;
        Self {
            mem_size_mib: machine_config.mem_size_mib as u64,
            smt: machine_config.smt,
            cpu_template: StaticCpuTemplate::from(&machine_config.cpu_template),
            boot_source: value.boot_source_config.clone(),
        }
    }
}

/// Contains the necessary state for saving/restoring a microVM.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MicrovmState {
    /// Miscellaneous VM info.
    pub vm_info: VmInfo,
    /// KVM KVM state.
    pub kvm_state: KvmState,
    /// VM KVM state.
    pub vm_state: VmState,
    /// Vcpu states.
    pub vcpu_states: Vec<VcpuState>,
    /// Device states.
    pub device_states: DevicesState,
}

/// Errors related to saving and restoring Microvm state.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum MicrovmStateError {
    /// Operation not allowed: {0}
    NotAllowed(String),
    /// Cannot restore devices: {0}
    RestoreDevices(#[from] DevicePersistError),
    /// Cannot save Vcpu state: {0}
    SaveVcpuState(vstate::vcpu::VcpuError),
    /// Cannot save KvmVm state: {0}
    SaveVmState(vstate::vm::KvmVmError),
    /// Cannot signal Vcpu: {0}
    SignalVcpu(VcpuSendEventError),
    /// Vcpu is in unexpected state.
    UnexpectedVcpuResponse,
}

/// Validates that snapshot CPU vendor matches the host CPU vendor.
///
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "x86_64")]
pub fn validate_cpu_vendor(microvm_state: &MicrovmState) {
    let host_vendor_id = get_vendor_id_from_host();
    let snapshot_vendor_id = microvm_state.vcpu_states[0].cpuid.vendor_id();
    match (host_vendor_id, snapshot_vendor_id) {
        (Ok(host_id), Some(snapshot_id)) => {
            info!("Host CPU vendor ID: {host_id:?}");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU vendor ID differs from the snapshotted one",);
            }
        }
        (Ok(host_id), None) => {
            info!("Host CPU vendor ID: {host_id:?}");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
        (Err(_), Some(snapshot_id)) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            info!("Snapshot CPU vendor ID: {snapshot_id:?}");
        }
        (Err(_), None) => {
            warn!("Host CPU vendor ID: couldn't get from the host");
            warn!("Snapshot CPU vendor ID: couldn't get from the snapshot");
        }
    }
}

/// Validate that Snapshot Manufacturer ID matches
/// the one from the Host
///
/// The manufacturer ID for the Snapshot is taken from each VCPU state.
/// # Errors
///
/// When:
/// - Failed to read host vendor.
/// - Failed to read snapshot vendor.
#[cfg(target_arch = "aarch64")]
pub fn validate_cpu_manufacturer_id(microvm_state: &MicrovmState) {
    let host_cpu_id = get_manufacturer_id_from_host();
    let snapshot_cpu_id = microvm_state.vcpu_states[0].regs.manifacturer_id();
    match (host_cpu_id, snapshot_cpu_id) {
        (Some(host_id), Some(snapshot_id)) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
            if host_id != snapshot_id {
                warn!("Host CPU manufacturer ID differs from the snapshotted one",);
            }
        }
        (Some(host_id), None) => {
            info!("Host CPU manufacturer ID: {host_id:?}");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
        (None, Some(snapshot_id)) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            info!("Snapshot CPU manufacturer ID: {snapshot_id:?}");
        }
        (None, None) => {
            warn!("Host CPU manufacturer ID: couldn't get from the host");
            warn!("Snapshot CPU manufacturer ID: couldn't get from the snapshot");
        }
    }
}
/// Error type for [`snapshot_state_sanity_check`].
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum SnapShotStateSanityCheckError {
    /// No memory region defined.
    NoMemory,
}

/// Performs sanity checks against the state file and returns specific errors.
pub fn snapshot_state_sanity_check(
    microvm_state: &MicrovmState,
) -> Result<(), SnapShotStateSanityCheckError> {
    // Check that the snapshot contains at least one memory region. The upper bound check is
    // done when creating guest memory by comparing against KVM's max_memslots().
    let regions = &microvm_state.vm_state.memory.regions;

    if regions.is_empty() {
        return Err(SnapShotStateSanityCheckError::NoMemory);
    }

    #[cfg(target_arch = "x86_64")]
    validate_cpu_vendor(microvm_state);
    #[cfg(target_arch = "aarch64")]
    validate_cpu_manufacturer_id(microvm_state);

    Ok(())
}

/// Error type for [`restore_from_snapshot`].
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RestoreFromSnapshotError {
    /// Invalid snapshot state: {0}
    Invalid(#[from] SnapShotStateSanityCheckError),
    /// Failed to load guest memory: Farplane restore failed: {0}
    GuestMemory(String),
    /// Failed to build microVM from snapshot: {0}
    Build(#[from] BuildMicrovmFromSnapshotError),
}

/// Loads a Microvm snapshot producing a 'paused' Microvm.
pub fn restore_from_snapshot(
    instance_info: &InstanceInfo,
    event_manager: &mut EventManager,
    seccomp_filters: &BpfThreadMap,
    params: &LoadSnapshotParams,
    vm_resources: &mut VmResources,
) -> Result<Arc<Mutex<Vmm>>, RestoreFromSnapshotError> {
    let (guest_memory, microvm_state) = FarplaneBackend::construct_restore()
        .map_err(|err| RestoreFromSnapshotError::GuestMemory(err.to_string()))?;

    let vcpu_count = microvm_state
        .vcpu_states
        .len()
        .try_into()
        .map_err(|_| MachineConfigError::InvalidVcpuCount)
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    vm_resources
        .update_machine_config(&MachineConfigUpdate {
            vcpu_count: Some(vcpu_count),
            mem_size_mib: Some(u64_to_usize(microvm_state.vm_info.mem_size_mib)),
            smt: Some(microvm_state.vm_info.smt),
            cpu_template: Some(microvm_state.vm_info.cpu_template),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        })
        .map_err(BuildMicrovmFromSnapshotError::VmUpdateConfig)?;

    snapshot_state_sanity_check(&microvm_state)?;
    builder::build_microvm_from_snapshot(
        instance_info,
        event_manager,
        microvm_state,
        guest_memory,
        seccomp_filters,
        vm_resources,
        params.resume_vm,
    )
    .map_err(RestoreFromSnapshotError::Build)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vmm;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmclock_device;
    #[cfg(target_arch = "x86_64")]
    use crate::builder::tests::insert_vmgenid_device;
    use crate::builder::tests::{
        CustomBlockConfig, default_kernel_cmdline, default_vmm, insert_block_devices,
        insert_net_device, insert_vsock_device,
    };
    #[cfg(target_arch = "aarch64")]
    use crate::construct_kvm_mpidrs;
    use crate::device_manager::persist::VirtioDeviceState;
    use crate::devices::virtio::block::CacheType;
    use crate::snapshot::Persist;
    use crate::vmm_config::net::NetworkInterfaceConfig;
    use crate::vmm_config::vsock::tests::default_config;
    use vmm_sys_util::tempfile::TempFile;

    /// Round-trip equality is checked through the transport state and the MMIO resources;
    /// per-device state equality is covered by each device's own tests.
    fn assert_virtio_states_eq<T>(
        restored: &[VirtioDeviceState<T>],
        expected: &[VirtioDeviceState<T>],
    ) {
        assert_eq!(restored.len(), expected.len());
        for (restored, expected) in restored.iter().zip(expected) {
            assert_eq!(restored.device_id, expected.device_id);
            assert_eq!(restored.transport_state, expected.transport_state);
            assert_eq!(restored.device_info, expected.device_info);
        }
    }

    fn default_vmm_with_devices() -> Vmm {
        let mut event_manager = EventManager::new().expect("Cannot create EventManager");
        let mut vmm = default_vmm();
        let mut cmdline = default_kernel_cmdline();

        let drive_id = String::from("root");
        let block_configs = vec![CustomBlockConfig::new(
            drive_id,
            true,
            None,
            true,
            CacheType::Unsafe,
        )];
        insert_block_devices(&mut vmm, &mut cmdline, &mut event_manager, block_configs);

        let network_interface = NetworkInterfaceConfig {
            iface_id: String::from("netif"),
            host_dev_name: String::from("hostname"),
            guest_mac: None,
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        };
        insert_net_device(
            &mut vmm,
            &mut cmdline,
            &mut event_manager,
            network_interface,
        );

        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let vsock_config = default_config(&tmp_sock_file);
        insert_vsock_device(&mut vmm, &mut cmdline, &mut event_manager, vsock_config);

        #[cfg(target_arch = "x86_64")]
        insert_vmgenid_device(&mut vmm);
        #[cfg(target_arch = "x86_64")]
        insert_vmclock_device(&mut vmm);

        vmm
    }

    #[test]
    fn test_microvm_state_snapshot() {
        let vmm = default_vmm_with_devices();
        let states = vmm.device_manager.save();
        assert_eq!(states.mmio_state.block_devices.len(), 1);
        assert_eq!(states.mmio_state.net_devices.len(), 1);
        assert!(states.mmio_state.vsock_device.is_some());

        let vcpu_states = vec![VcpuState::default()];
        #[cfg(target_arch = "aarch64")]
        let mpidrs = construct_kvm_mpidrs(&vcpu_states);
        let microvm_state = MicrovmState {
            device_states: states,
            vcpu_states,
            kvm_state: Default::default(),
            vm_info: VmInfo {
                mem_size_mib: 1u64,
                ..Default::default()
            },
            #[cfg(target_arch = "aarch64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state(&mpidrs).unwrap(),
            #[cfg(target_arch = "x86_64")]
            vm_state: vmm.vm.as_kvm().unwrap().save_state().unwrap(),
        };

        let serialized_data = bitcode::serialize(&microvm_state).unwrap();
        let restored_microvm_state: MicrovmState = bitcode::deserialize(&serialized_data).unwrap();
        assert_eq!(restored_microvm_state.vm_info, microvm_state.vm_info);

        let restored_mmio_state = &restored_microvm_state.device_states.mmio_state;
        let mmio_state = &microvm_state.device_states.mmio_state;
        assert_virtio_states_eq(
            &restored_mmio_state.block_devices,
            &mmio_state.block_devices,
        );
        assert_virtio_states_eq(&restored_mmio_state.net_devices, &mmio_state.net_devices);
        assert_virtio_states_eq(
            restored_mmio_state.vsock_device.as_slice(),
            mmio_state.vsock_device.as_slice(),
        );
        assert_virtio_states_eq(
            restored_mmio_state.entropy_device.as_slice(),
            mmio_state.entropy_device.as_slice(),
        );
    }
}
