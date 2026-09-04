// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::tests_outside_test_module)]

use std::os::fd::RawFd;

use vmm::EventManager;
use vmm::builder::build_and_boot_microvm;
use vmm::devices::virtio::block::{CacheType, ROOT_DESCRIPTOR_FILENO, SCRATCH_DESCRIPTOR_FILENO};
use vmm::resources::VmResources;
use vmm::rpc_interface::{LoadSnapshotError, PrebootApiController, VmmAction, VmmActionError};
use vmm::seccomp::get_empty_filters;
use vmm::vmm_config::boot_source::BootSourceConfig;
use vmm::vmm_config::drive::BlockDeviceConfig;
use vmm::vmm_config::instance_info::InstanceInfo;
use vmm::vmm_config::machine_config::{MachineConfig, MachineConfigUpdate};
use vmm::vmm_config::net::NetworkInterfaceConfig;
use vmm::vmm_config::snapshot::LoadSnapshotParams;
use vmm::vmm_config::vsock::VsockDeviceConfig;
use vmm_sys_util::tempfile::TempFile;

/// Stands the descriptors the jailer inherits up for this test binary: a sealed read-only image
/// at [`ROOT_DESCRIPTOR_FILENO`] and a read-write scratch disk at [`SCRATCH_DESCRIPTOR_FILENO`].
/// It runs before `main`, so the reserved numbers are claimed before any test can be handed one.
#[used]
#[unsafe(link_section = ".init_array")]
static INHERIT_RESERVED_DESCRIPTORS: extern "C" fn() = inherit_reserved_descriptors;

extern "C" fn inherit_reserved_descriptors() {
    let image = disk_image(c"sealed-drive-image", libc::MFD_ALLOW_SEALING);

    // SAFETY: `image` is an owned memfd of this process, and sealing only restricts what it
    // permits.
    unsafe {
        let seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(
            libc::fcntl(image, libc::F_ADD_SEALS, seals),
            0,
            "F_ADD_SEALS"
        );
    }

    let link = std::ffi::CString::new(format!("/proc/self/fd/{image}")).unwrap();
    // SAFETY: `link` is a NUL-terminated string that outlives the call.
    let read_only = unsafe { libc::open(link.as_ptr(), libc::O_RDONLY) };
    assert!(read_only >= 0, "reopening the sealed image read-only");

    // A memfd is opened read-write, the access mode the scratch slot requires.
    let scratch = disk_image(c"scratch-disk", 0);

    // Both descriptors, and the ones they were duplicated from, stay open for the lifetime of the
    // process, exactly as a jailed Firecracker holds them.
    for (source, reserved) in [
        (read_only, ROOT_DESCRIPTOR_FILENO),
        (scratch, SCRATCH_DESCRIPTOR_FILENO),
    ] {
        // SAFETY: `source` is an owned descriptor and `dup2` rewrites this process' own table.
        assert!(unsafe { libc::dup2(source, reserved) } >= 0, "dup2");
    }
}

/// A memfd holding one page of disk image, opened read-write.
fn disk_image(name: &std::ffi::CStr, flags: libc::c_uint) -> RawFd {
    // SAFETY: `name` is a NUL-terminated string that outlives the call.
    let image = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), flags) };
    assert!(image >= 0, "memfd_create");
    let image = RawFd::try_from(image).unwrap();

    // SAFETY: `image` is an owned memfd of this process.
    assert_eq!(unsafe { libc::ftruncate(image, 0x1000) }, 0, "ftruncate");
    image
}

#[test]
fn test_build_and_boot_microvm_without_boot_source() {
    let resources = VmResources::default();
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();

    let vmm_ret = build_and_boot_microvm(
        &InstanceInfo::default(),
        &resources,
        &mut event_manager,
        &empty_seccomp_filters,
    );
    assert_eq!(format!("{:?}", vmm_ret.err()), "Some(MissingKernelConfig)");
}

fn verify_load_snap_disallowed_after_boot_resources(res: VmmAction, res_name: &str) {
    let mut event_manager = EventManager::new().unwrap();
    let empty_seccomp_filters = get_empty_filters();
    let mut vm_resources = VmResources::default();

    let mut preboot_api_controller = PrebootApiController::new(
        &empty_seccomp_filters,
        InstanceInfo::default(),
        &mut vm_resources,
        &mut event_manager,
    );

    preboot_api_controller.handle_preboot_request(res).unwrap();

    // Load snapshot should no longer be allowed.
    let req = VmmAction::LoadSnapshot(LoadSnapshotParams { resume_vm: false });
    let err = preboot_api_controller.handle_preboot_request(req);
    assert!(
        matches!(
            err.unwrap_err(),
            VmmActionError::LoadSnapshot(LoadSnapshotError::LoadSnapshotNotAllowed)
        ),
        "LoadSnapshot should be disallowed after {}",
        res_name
    );
}

#[test]
fn test_preboot_load_snap_disallowed_after_boot_resources() {
    let tmp_file = TempFile::new().unwrap();
    tmp_file.as_file().set_len(0x1000).unwrap();
    let kernel_image_path = tmp_file.as_path().to_str().unwrap().to_string();
    // Verify LoadSnapshot not allowed after configuring various boot-specific resources.
    let req = VmmAction::ConfigureBootSource(BootSourceConfig {
        kernel_image_path,
        ..Default::default()
    });
    verify_load_snap_disallowed_after_boot_resources(req, "ConfigureBootSource");

    let config = BlockDeviceConfig {
        drive_id: String::new(),
        partuuid: None,
        is_root_device: false,
        cache_type: CacheType::Unsafe,
        is_read_only: Some(false),
        fd: SCRATCH_DESCRIPTOR_FILENO,
        rate_limiter: None,
        file_engine_type: None,
    };

    let req = VmmAction::InsertBlockDevice(config);
    verify_load_snap_disallowed_after_boot_resources(req, "InsertBlockDevice");

    let req = VmmAction::InsertNetworkDevice(NetworkInterfaceConfig {
        iface_id: String::new(),
        host_dev_name: String::new(),
        guest_mac: None,
        mtu: None,
        rx_rate_limiter: None,
        tx_rate_limiter: None,
    });
    verify_load_snap_disallowed_after_boot_resources(req, "InsertNetworkDevice");

    let req = VmmAction::SetVsockDevice(VsockDeviceConfig {
        vsock_id: Some(String::new()),
        guest_cid: 0,
        uds_path: String::new(),
    });
    verify_load_snap_disallowed_after_boot_resources(req, "SetVsockDevice");

    let req =
        VmmAction::UpdateMachineConfiguration(MachineConfigUpdate::from(MachineConfig::default()));
    verify_load_snap_disallowed_after_boot_resources(req, "SetVmConfiguration");
}
