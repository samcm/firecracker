// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Test-only durable decoder experiment. This module is not compiled into Firecracker and
//! grants no production compatibility. Promotion requires each disposable producer fixture to
//! restore in the actual jailed new runtime, including memory, disk and device behavior.
//!
//! Producer identities come from the authenticated restore claim's original artifact tuple,
//! never from the vmstate header. The selected execution binary is a separate identity. These
//! exact candidate builds are recorded in samcm/farplane build/firecracker.published.json:
//! b261ca082a2550940ff776c24c66d10b82f7a5e5 (/4), d187edd71edae101381c9da9688596c52e409345 (/6).

use aws_lc_rs::digest::{SHA256, digest};

use super::*;
use crate::device_manager::DevicesState;
use crate::device_manager::pci_mngr::{self, VirtioDeviceState as PciDevice};
use crate::device_manager::persist::{self, VirtioDeviceState as MmioDevice};
use crate::devices::virtio::block::persist::BlockState;
use crate::devices::virtio::net::persist::NetState;
use crate::devices::virtio::rng::persist::EntropyState;
use crate::devices::virtio::vsock::persist::VsockState;
use crate::persist::{MicrovmState, VmInfo};
use crate::vstate::farplane::Arch;
use crate::vstate::kvm::KvmState;
use crate::vstate::vcpu::VcpuState;
use crate::vstate::vm::VmState;

const PRODUCER_4: &str = "a68a19234638aa845406f8f605395b1364a6c59f1e7b5ed33fed027f768c2758";
const PRODUCER_6: &str = "90a6e9dfa3aa63830fe7f2086e7eadf43230964f91306d4a5ff333563aa2c1e1";

// Exact x86_64 layout at samcm/firecracker 55697cdde0fe9d59fb4280885b5d44c02550384f.
// The diff to fd09516dd0ff8b7933b99b61f24f08f92f791dbe changes neither the reused nested
// state types nor Cargo.lock. Both MMIO and PCI gain a reporting-device field in /6, even
// when PCI is disabled. Numeric snapshot version 12.0.0 alone cannot distinguish the layouts.
#[derive(Debug, Default, Serialize, Deserialize)]
struct LegacyMicrovmState {
    vm_info: VmInfo,
    kvm_state: KvmState,
    vm_state: VmState,
    vcpu_states: Vec<VcpuState>,
    device_states: LegacyDevicesState,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LegacyDevicesState {
    mmio_state: LegacyMmioState,
    acpi_state: persist::ACPIDeviceManagerState,
    pci_state: LegacyPciState,
    serial_state: Option<persist::SerialState>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LegacyMmioState {
    block_devices: Vec<MmioDevice<BlockState>>,
    net_devices: Vec<MmioDevice<NetState>>,
    vsock_device: Option<MmioDevice<VsockState>>,
    entropy_device: Option<MmioDevice<EntropyState>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LegacyPciState {
    pci_enabled: bool,
    block_devices: Vec<PciDevice<BlockState>>,
    net_devices: Vec<PciDevice<NetState>>,
    vsock_device: Option<PciDevice<VsockState>>,
    entropy_device: Option<PciDevice<EntropyState>>,
}

impl From<LegacyMicrovmState> for MicrovmState {
    fn from(old: LegacyMicrovmState) -> Self {
        let mmio = old.device_states.mmio_state;
        let pci = old.device_states.pci_state;
        Self {
            vm_info: old.vm_info,
            kvm_state: old.kvm_state,
            vm_state: old.vm_state,
            vcpu_states: old.vcpu_states,
            device_states: DevicesState {
                mmio_state: persist::DeviceStates {
                    block_devices: mmio.block_devices,
                    net_devices: mmio.net_devices,
                    vsock_device: mmio.vsock_device,
                    entropy_device: mmio.entropy_device,
                    // /4 has no reporting device, not an uninitialized /6 device to invent.
                    free_page_reporting_device: None,
                },
                acpi_state: old.device_states.acpi_state,
                pci_state: pci_mngr::PciDevicesState {
                    pci_enabled: pci.pci_enabled,
                    block_devices: pci.block_devices,
                    net_devices: pci.net_devices,
                    vsock_device: pci.vsock_device,
                    entropy_device: pci.entropy_device,
                    free_page_reporting_device: None,
                },
                serial_state: old.device_states.serial_state,
            },
        }
    }
}

#[derive(Debug)]
enum Error {
    UnsupportedProducer,
    ByteIdentity,
    Snapshot(SnapshotError),
}

impl From<SnapshotError> for Error {
    fn from(error: SnapshotError) -> Self {
        Self::Snapshot(error)
    }
}

/// Only called by tests. Production has no candidate-cohort acceptance path.
/// The caller supplies the existing verified VMStateRef hash/length, not a replacement header.
fn decode_candidate(
    producer: &str,
    arch: Arch,
    image: &[u8],
    expected_sha256: &[u8],
    expected_len: u64,
) -> Result<MicrovmState, Error> {
    if arch != Arch::X86_64 || !matches!(producer, PRODUCER_4 | PRODUCER_6) {
        return Err(Error::UnsupportedProducer);
    }
    if image.len() > SNAPSHOT_DESERIALIZATION_BYTES_LIMIT {
        return Err(SnapshotError::SizeLimitExceeded(SNAPSHOT_DESERIALIZATION_BYTES_LIMIT).into());
    }
    if image.len() as u64 != expected_len || digest(&SHA256, image).as_ref() != expected_sha256 {
        return Err(Error::ByteIdentity);
    }
    let body_len = image.len().checked_sub(8).ok_or_else(|| {
        SnapshotError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;
    if crc64(0, image) != 0 {
        return Err(SnapshotError::Crc64.into());
    }
    // Exactly one type graph is selected from authenticated provenance before deserialization.
    // A failed decode never falls through to another cohort's layout.
    match producer {
        PRODUCER_4 => {
            let snapshot: Snapshot<LegacyMicrovmState> =
                bitcode::deserialize(&image[..body_len]).map_err(SnapshotError::Bitcode)?;
            validate_header(&snapshot.header, "farplane/4")?;
            Ok(snapshot.data.into())
        }
        PRODUCER_6 => {
            let snapshot: Snapshot<MicrovmState> =
                bitcode::deserialize(&image[..body_len]).map_err(SnapshotError::Bitcode)?;
            validate_header(&snapshot.header, "farplane/6")?;
            Ok(snapshot.data)
        }
        _ => unreachable!("producer was checked before decoding"),
    }
}

fn validate_header(header: &SnapshotHdr, feature: &str) -> Result<(), SnapshotError> {
    if header.magic != SNAPSHOT_MAGIC_ID {
        return Err(SnapshotError::InvalidMagic(header.magic));
    }
    if header.version != Version::new(12, 0, 0) {
        return Err(SnapshotError::InvalidFormatVersion(header.version.clone()));
    }
    if header.feature_identity != feature {
        return Err(SnapshotError::IncompatibleFeatureIdentity {
            expected: feature.to_string(),
            found: header.feature_identity.clone(),
        });
    }
    Ok(())
}

fn image<T: Serialize>(snapshot: &Snapshot<T>) -> Vec<u8> {
    let mut image = Vec::new();
    snapshot.save(&mut image).unwrap();
    image
}

fn candidate(producer: &str, image: &[u8]) -> Result<MicrovmState, Error> {
    decode_candidate(
        producer,
        Arch::X86_64,
        image,
        digest(&SHA256, image).as_ref(),
        image.len() as u64,
    )
}

#[test]
fn legacy_layout_converts_only_the_two_absent_fields() {
    let mut old = Snapshot::new(LegacyMicrovmState::default());
    old.header.feature_identity = "farplane/4".to_string();
    old.data.vm_info.mem_size_mib = 2048;
    old.data.device_states.serial_state = Some(persist::SerialState {
        in_buffer: b"nonempty legacy serial state".to_vec(),
        ..Default::default()
    });
    let encoded = image(&old);
    let state = candidate(PRODUCER_4, &encoded).unwrap();
    assert_eq!(state.vm_info.mem_size_mib, 2048);
    assert_eq!(
        state.device_states.serial_state.unwrap().in_buffer,
        b"nonempty legacy serial state"
    );
    assert!(
        state
            .device_states
            .mmio_state
            .free_page_reporting_device
            .is_none()
    );
    assert!(
        state
            .device_states
            .pci_state
            .free_page_reporting_device
            .is_none()
    );
    candidate(PRODUCER_6, &encoded).unwrap_err();
    let mut fp6 = Snapshot::new(MicrovmState::default());
    fp6.header.feature_identity = "farplane/6".to_string();
    let current = image(&fp6);
    candidate(PRODUCER_4, &current).unwrap_err();
    candidate(PRODUCER_6, &current).unwrap();
    // A new /7 image is not a pinned historical producer's output.
    candidate(PRODUCER_6, &image(&Snapshot::new(MicrovmState::default()))).unwrap_err();
    old.header.feature_identity = "farplane/6".to_string();
    assert!(matches!(
        candidate(PRODUCER_4, &image(&old)),
        Err(Error::Snapshot(
            SnapshotError::IncompatibleFeatureIdentity { .. }
        ))
    ));
}

#[test]
fn producer_arch_and_exact_bytes_are_not_header_claims() {
    let encoded = image(&Snapshot::new(MicrovmState::default()));
    assert!(matches!(
        candidate("farplane/6", &encoded),
        Err(Error::UnsupportedProducer)
    ));
    assert!(matches!(
        candidate(&"0".repeat(64), &encoded),
        Err(Error::UnsupportedProducer)
    ));
    assert!(matches!(
        decode_candidate(
            PRODUCER_6,
            Arch::Aarch64,
            &encoded,
            digest(&SHA256, &encoded).as_ref(),
            encoded.len() as u64
        ),
        Err(Error::UnsupportedProducer)
    ));
    assert!(matches!(
        decode_candidate(
            PRODUCER_6,
            Arch::X86_64,
            &encoded,
            &[0; 32],
            encoded.len() as u64
        ),
        Err(Error::ByteIdentity)
    ));
    assert!(matches!(
        decode_candidate(
            PRODUCER_6,
            Arch::X86_64,
            &encoded,
            digest(&SHA256, &encoded).as_ref(),
            encoded.len() as u64 + 1
        ),
        Err(Error::ByteIdentity)
    ));
    let mut other = Snapshot::new(MicrovmState::default());
    other.data.vm_info.mem_size_mib = 4096;
    assert!(matches!(
        decode_candidate(
            PRODUCER_6,
            Arch::X86_64,
            &image(&other),
            digest(&SHA256, &encoded).as_ref(),
            image(&other).len() as u64
        ),
        Err(Error::ByteIdentity)
    ));
}

#[test]
fn header_crc_schema_and_trailing_data_fail_closed() {
    let mut snapshot = Snapshot::new(MicrovmState::default());
    snapshot.header.feature_identity = "farplane/4".to_string();
    assert!(matches!(
        candidate(PRODUCER_6, &image(&snapshot)),
        Err(Error::Snapshot(
            SnapshotError::IncompatibleFeatureIdentity { .. }
        ))
    ));
    snapshot.header.feature_identity = "farplane/6".to_string();
    snapshot.header.version = Version::new(12, 0, 1);
    assert!(matches!(
        candidate(PRODUCER_6, &image(&snapshot)),
        Err(Error::Snapshot(SnapshotError::InvalidFormatVersion(_)))
    ));
    snapshot.header.version = Version::new(12, 0, 0);
    snapshot.header.magic = 0x0710_1984_AAAA_0000;
    assert!(matches!(
        candidate(PRODUCER_6, &image(&snapshot)),
        Err(Error::Snapshot(SnapshotError::InvalidMagic(_)))
    ));
    let mut encoded = image(&Snapshot::new(MicrovmState::default()));
    *encoded.last_mut().unwrap() ^= 1;
    assert!(matches!(
        candidate(PRODUCER_6, &encoded),
        Err(Error::Snapshot(SnapshotError::Crc64))
    ));
    encoded.truncate(encoded.len() - 8);
    encoded.push(0); // Well-checksummed extra byte must not be ignored by the decoder.
    encoded.extend_from_slice(&crc64(0, &encoded).to_le_bytes());
    assert!(matches!(
        candidate(PRODUCER_6, &encoded),
        Err(Error::Snapshot(SnapshotError::Bitcode(_)))
    ));
    candidate(PRODUCER_6, &[0; 7]).unwrap_err();
    assert!(matches!(
        candidate(
            PRODUCER_6,
            &vec![0; SNAPSHOT_DESERIALIZATION_BYTES_LIMIT + 1]
        ),
        Err(Error::Snapshot(SnapshotError::SizeLimitExceeded(_)))
    ));
}

/// Real /6 capture, not a synthetic default state. This is decoder evidence only: RAM, disk,
/// guest execution, trusted-claim authentication and the new backend are not tested here.
#[test]
#[ignore = "requires disposable deployment fixture in FC_COMPAT_FIXTURES"]
fn golden_fp6_decode() {
    let directory = std::env::var("FC_COMPAT_FIXTURES").expect("set FC_COMPAT_FIXTURES");
    let encoded = std::fs::read(std::path::Path::new(&directory).join("fp6-vmstate.bin")).unwrap();
    assert_eq!(encoded.len(), 26107);
    let expected_hash = [
        0xae, 0x73, 0xef, 0x2d, 0x38, 0x13, 0x23, 0x96, 0x20, 0x2a, 0xea, 0x53, 0xf6, 0x20, 0x79,
        0xdf, 0xc0, 0xfd, 0xf0, 0xda, 0x56, 0x1d, 0xd0, 0xc2, 0x4c, 0xca, 0xdc, 0xb2, 0x53, 0x6e,
        0x3e, 0xdd,
    ];
    let state =
        decode_candidate(PRODUCER_6, Arch::X86_64, &encoded, &expected_hash, 26107).unwrap();
    assert_eq!(state.vm_info.mem_size_mib, 2048);
    assert_eq!(state.vcpu_states.len(), 2);
    assert_eq!(state.vm_state.memory.regions.len(), 1);
    assert_eq!(state.vm_state.memory.regions[0].base_address, 0);
    assert_eq!(state.vm_state.memory.regions[0].size, 2 << 30);
    assert_eq!(state.device_states.mmio_state.block_devices.len(), 2);
    assert_eq!(state.device_states.mmio_state.net_devices.len(), 1);
    assert!(state.device_states.mmio_state.vsock_device.is_some());
    assert!(
        state
            .device_states
            .mmio_state
            .free_page_reporting_device
            .is_some()
    );
    assert!(!state.device_states.pci_state.pci_enabled);
    candidate(PRODUCER_4, &encoded).unwrap_err();
}

/// Disposable exact-/4 producer capture from snap_b806e6396edb. The historical layout is
/// selected externally; a valid old checksum/header never authorizes a different producer.
#[test]
#[ignore = "requires disposable deployment fixture in FC_COMPAT_FIXTURES"]
fn golden_fp4_decode_and_conversion() {
    let directory = std::env::var("FC_COMPAT_FIXTURES").expect("set FC_COMPAT_FIXTURES");
    let encoded = std::fs::read(std::path::Path::new(&directory).join("fp4-vmstate.bin")).unwrap();
    assert_eq!(encoded.len(), 25955);
    let expected_hash = [
        0x70, 0xfc, 0xb3, 0x3c, 0x57, 0xec, 0xd1, 0x6e, 0xec, 0x60, 0xbc, 0x67, 0xfe, 0xc8, 0xdf,
        0x48, 0xb9, 0x51, 0xb5, 0xe1, 0x43, 0x1c, 0xde, 0x75, 0x9f, 0xa8, 0x3c, 0x66, 0x2f, 0x77,
        0x31, 0x97,
    ];
    let state =
        decode_candidate(PRODUCER_4, Arch::X86_64, &encoded, &expected_hash, 25955).unwrap();
    assert_eq!(state.vm_info.mem_size_mib, 2048);
    assert_eq!(state.vcpu_states.len(), 2);
    assert_eq!(state.vm_state.memory.regions.len(), 1);
    assert_eq!(state.vm_state.memory.regions[0].base_address, 0);
    assert_eq!(state.vm_state.memory.regions[0].size, 2 << 30);
    assert_eq!(state.device_states.mmio_state.block_devices.len(), 2);
    assert_eq!(state.device_states.mmio_state.net_devices.len(), 1);
    assert!(state.device_states.mmio_state.vsock_device.is_some());
    assert!(
        state
            .device_states
            .mmio_state
            .free_page_reporting_device
            .is_none()
    );
    assert!(
        state
            .device_states
            .pci_state
            .free_page_reporting_device
            .is_none()
    );
    assert!(!state.device_states.pci_state.pci_enabled);
    candidate(PRODUCER_6, &encoded).unwrap_err();

    // Compare every decoded state field, not just the shape: conversion may only introduce
    // the two explicitly absent devices. This does not mutate or rewrite the archive bytes.
    let original: Snapshot<LegacyMicrovmState> =
        bitcode::deserialize(&encoded[..encoded.len() - 8]).unwrap();
    let mut converted = serde_json::to_value(&state).unwrap();
    for transport in ["mmio_state", "pci_state"] {
        assert_eq!(
            converted["device_states"][transport]
                .as_object_mut()
                .unwrap()
                .remove("free_page_reporting_device"),
            Some(serde_json::Value::Null)
        );
    }
    assert_eq!(converted, serde_json::to_value(&original.data).unwrap());
}
