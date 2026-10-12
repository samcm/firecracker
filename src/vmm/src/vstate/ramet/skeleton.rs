// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The shape-independent KVM skeleton of a warm Firecracker: the VM with its in-kernel interrupt
//! controller and PIT, built while the process waits for its sandbox, so a load or boot takes
//! them instead of creating them on the fork path. A warm Firecracker does not know its claim's
//! shape, so the vCPUs, the memory slots, all VM and vCPU state and the devices are still the
//! load's. Nothing here holds guest memory.
//!
//! The skeleton is built with no KVM capability modifiers; a load with modifiers drops it and
//! builds the VM as before. Built and taken on the main thread, which owns it.

use std::cell::RefCell;
use std::time::Instant;

use crate::Vcpu;
use crate::cpu_config::templates::KvmCapability;
use crate::logger::{info, warn};
use crate::vstate::kvm::Kvm;
use crate::vstate::vm::{KvmVm, VmError};

thread_local! {
    static SKELETON: RefCell<Option<KvmVm>> = const { RefCell::new(None) };
}

/// Builds the skeleton: KVM_CREATE_VM, the TSS address, the irqchip and the PIT. A failure
/// leaves none, and the load builds the VM itself.
pub fn prewarm() {
    let started = Instant::now();
    let built = (|| -> Result<KvmVm, String> {
        let kvm = Kvm::new(Vec::new()).map_err(|err| err.to_string())?;
        let vm = KvmVm::new(kvm).map_err(|err| err.to_string())?;
        vm.setup_irqchip().map_err(|err| err.to_string())?;
        Ok(vm)
    })();
    match built {
        Ok(vm) => {
            SKELETON.with(|s| *s.borrow_mut() = Some(vm));
            info!(
                "Ramet built a warm KVM skeleton in {} us",
                started.elapsed().as_micros()
            );
        }
        Err(err) => warn!("Ramet could not build a warm KVM skeleton: {err}"),
    }
}

/// The VM with `vcpu_count` vCPUs: the skeleton's, with the vCPUs created now, if it fits;
/// otherwise built from scratch exactly as before.
pub fn vm_with_vcpus(
    vcpu_count: u8,
    kvm_cap_modifiers: &[KvmCapability],
) -> Result<(KvmVm, Vec<Vcpu>), SkeletonError> {
    let skeleton = SKELETON.with(|s| s.borrow_mut().take());
    if let Some(mut vm) = skeleton {
        if kvm_cap_modifiers.is_empty() {
            // The irqchip exists already: create the vCPUs as create_vcpus does after its
            // pre-create step.
            let mut vcpus = Vec::with_capacity(usize::from(vcpu_count));
            for cpu_idx in 0..vcpu_count {
                let exit_evt = vm.vcpus_exit_evt().try_clone().map_err(VmError::EventFd)?;
                vcpus.push(Vcpu::new(cpu_idx, &vm, exit_evt).map_err(VmError::CreateVcpu)?);
            }
            vm.arch_post_create_vcpus(vcpu_count)
                .map_err(VmError::Arch)?;
            info!("Ramet builds on the warm KVM skeleton ({vcpu_count} vCPUs)");
            return Ok((vm, vcpus));
        }
        info!(
            "Ramet dropped the warm KVM skeleton: the VM needs {} capability modifiers",
            kvm_cap_modifiers.len()
        );
    }
    let kvm = Kvm::new(kvm_cap_modifiers.to_vec())?;
    let mut vm = KvmVm::new(kvm)?;
    let vcpus = vm.create_vcpus(vcpu_count)?;
    Ok((vm, vcpus))
}

/// Why the VM could not be built.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SkeletonError {
    /// Kvm: {0}
    Kvm(#[from] crate::vstate::kvm::KvmError),
    /// Vm: {0}
    Vm(#[from] VmError),
}
