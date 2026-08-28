// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Debug;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};

/// The default memory size of the VM, in MiB.
pub const DEFAULT_MEM_SIZE_MIB: usize = 128;
/// Firecracker aims to support small scale workloads only, so limit the maximum
/// vCPUs supported.
pub const MAX_SUPPORTED_VCPUS: u8 = 32;

/// Errors associated with configuring the microVM.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum MachineConfigError {
    /// The memory size (MiB) must be greater than 0.
    InvalidMemorySize,
    /// The number of vCPUs must be greater than 0, less than {MAX_SUPPORTED_VCPUS:} and must be 1 or an even number if SMT is enabled.
    InvalidVcpuCount,
    /// Enabling simultaneous multithreading is not supported on aarch64.
    #[cfg(target_arch = "aarch64")]
    SmtNotSupported,
}

/// Struct used in PUT `/machine-config` API call.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// Number of vcpu to start.
    pub vcpu_count: u8,
    /// The memory size in MiB.
    pub mem_size_mib: usize,
    /// Enables or disabled SMT.
    #[serde(default)]
    pub smt: bool,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    // FIXME: once support for static CPU templates is removed, this field can be dropped altogether
    #[serde(
        default,
        skip_serializing_if = "is_none_or_custom_template",
        deserialize_with = "deserialize_static_template",
        serialize_with = "serialize_static_template"
    )]
    pub cpu_template: Option<CpuTemplateType>,
    /// Path of the UNIX socket the GDB stub listens on.
    #[cfg(feature = "gdb")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gdb_socket_path: Option<String>,
}

fn is_none_or_custom_template(template: &Option<CpuTemplateType>) -> bool {
    matches!(template, None | Some(CpuTemplateType::Custom(_)))
}

fn deserialize_static_template<'de, D>(deserializer: D) -> Result<Option<CpuTemplateType>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<StaticCpuTemplate>::deserialize(deserializer)
        .map(|maybe_template| maybe_template.map(CpuTemplateType::Static))
}

fn serialize_static_template<S>(
    template: &Option<CpuTemplateType>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let Some(CpuTemplateType::Static(template)) = template else {
        // We have a skip_serializing_if on the field
        unreachable!()
    };

    template.serialize(serializer)
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            mem_size_mib: DEFAULT_MEM_SIZE_MIB,
            smt: false,
            cpu_template: None,
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        }
    }
}

/// Struct used in PATCH `/machine-config` API call.
/// Used to update `MachineConfig` in `VmResources`.
/// This struct mirrors all the fields in `MachineConfig`.
/// All fields are optional, but at least one needs to be specified.
/// If a field is `Some(value)` then we assume an update is requested
/// for that field.
#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfigUpdate {
    /// Number of vcpu to start.
    #[serde(default)]
    pub vcpu_count: Option<u8>,
    /// The memory size in MiB.
    #[serde(default)]
    pub mem_size_mib: Option<usize>,
    /// Enables or disabled SMT.
    #[serde(default)]
    pub smt: Option<bool>,
    /// A CPU template that it is used to filter the CPU features exposed to the guest.
    #[serde(default)]
    pub cpu_template: Option<StaticCpuTemplate>,
    /// Path of the UNIX socket the GDB stub listens on.
    #[cfg(feature = "gdb")]
    #[serde(default)]
    pub gdb_socket_path: Option<String>,
}

impl MachineConfigUpdate {
    /// Checks if the update request contains any data.
    /// Returns `true` if all fields are set to `None` which means that there is nothing
    /// to be updated.
    pub fn is_empty(&self) -> bool {
        self == &Default::default()
    }
}

impl From<MachineConfig> for MachineConfigUpdate {
    fn from(cfg: MachineConfig) -> Self {
        MachineConfigUpdate {
            vcpu_count: Some(cfg.vcpu_count),
            mem_size_mib: Some(cfg.mem_size_mib),
            smt: Some(cfg.smt),
            cpu_template: cfg.static_template(),
            #[cfg(feature = "gdb")]
            gdb_socket_path: cfg.gdb_socket_path,
        }
    }
}

impl MachineConfig {
    /// Sets cpu tempalte field to `CpuTemplateType::Custom(cpu_template)`.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.cpu_template = Some(CpuTemplateType::Custom(cpu_template));
    }

    fn static_template(&self) -> Option<StaticCpuTemplate> {
        match self.cpu_template {
            Some(CpuTemplateType::Static(template)) => Some(template),
            _ => None,
        }
    }

    /// Updates [`MachineConfig`] with [`MachineConfigUpdate`].
    /// Mapping for cpu template update:
    /// StaticCpuTemplate::None -> None
    /// StaticCpuTemplate::Other -> Some(CustomCpuTemplate::Static(Other)),
    /// Returns the updated `MachineConfig` object.
    pub fn update(
        &self,
        update: &MachineConfigUpdate,
    ) -> Result<MachineConfig, MachineConfigError> {
        let vcpu_count = update.vcpu_count.unwrap_or(self.vcpu_count);

        let smt = update.smt.unwrap_or(self.smt);

        #[cfg(target_arch = "aarch64")]
        if smt {
            return Err(MachineConfigError::SmtNotSupported);
        }

        if vcpu_count == 0 || vcpu_count > MAX_SUPPORTED_VCPUS {
            return Err(MachineConfigError::InvalidVcpuCount);
        }

        // If SMT is enabled or is to be enabled in this call
        // only allow vcpu count to be 1 or even.
        if smt && vcpu_count > 1 && vcpu_count % 2 == 1 {
            return Err(MachineConfigError::InvalidVcpuCount);
        }

        let mem_size_mib = update.mem_size_mib.unwrap_or(self.mem_size_mib);
        if mem_size_mib == 0 {
            return Err(MachineConfigError::InvalidMemorySize);
        }

        let cpu_template = match update.cpu_template {
            None => self.cpu_template.clone(),
            Some(StaticCpuTemplate::None) => None,
            Some(other) => Some(CpuTemplateType::Static(other)),
        };

        Ok(MachineConfig {
            vcpu_count,
            mem_size_mib,
            smt,
            cpu_template,
            #[cfg(feature = "gdb")]
            gdb_socket_path: update.gdb_socket_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};
    use crate::vmm_config::machine_config::MachineConfig;

    // Ensure the special (de)serialization logic for the cpu_template field works:
    // only static cpu templates can be specified via the machine-config endpoint, but
    // we still cram custom cpu templates into the MachineConfig struct if they're set otherwise
    // Ensure that during (de)serialization we preserve static templates, but we set custom
    // templates to None
    #[test]
    fn test_serialize_machine_config() {
        #[cfg(target_arch = "aarch64")]
        const TEMPLATE: StaticCpuTemplate = StaticCpuTemplate::V1N1;
        #[cfg(target_arch = "x86_64")]
        const TEMPLATE: StaticCpuTemplate = StaticCpuTemplate::T2S;

        let mconfig = MachineConfig {
            cpu_template: None,
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert!(deserialized.cpu_template.is_none());

        let mconfig = MachineConfig {
            cpu_template: Some(CpuTemplateType::Static(TEMPLATE)),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert_eq!(
            deserialized.cpu_template,
            Some(CpuTemplateType::Static(TEMPLATE))
        );

        let mconfig = MachineConfig {
            cpu_template: Some(CpuTemplateType::Custom(CustomCpuTemplate::default())),
            ..Default::default()
        };

        let serialized = serde_json::to_string(&mconfig).unwrap();
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();

        assert!(deserialized.cpu_template.is_none());
    }
}
