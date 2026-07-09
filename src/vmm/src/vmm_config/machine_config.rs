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

/// Inclusive lower bound for `tsc_khz_multiplier` when the value is not exactly 1.0.
pub const TSC_KHZ_MULTIPLIER_MIN: f64 = 0.1;
/// Inclusive upper bound for `tsc_khz_multiplier` when the value is not exactly 1.0.
pub const TSC_KHZ_MULTIPLIER_MAX: f64 = 100.0;

/// Errors associated with configuring the microVM.
#[rustfmt::skip]
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum MachineConfigError {
    /// The memory size (MiB) is smaller than the previously set balloon device target size.
    IncompatibleBalloonSize,
    /// The memory size (MiB) is either 0, or not a multiple of the configured page size.
    InvalidMemorySize,
    /// The number of vCPUs must be greater than 0, less than {MAX_SUPPORTED_VCPUS:} and must be 1 or an even number if SMT is enabled.
    InvalidVcpuCount,
    /// Could not get the configuration of the previously installed balloon device to validate the memory size.
    InvalidVmState,
    /// Enabling simultaneous multithreading is not supported on aarch64.
    #[cfg(target_arch = "aarch64")]
    SmtNotSupported,
    /// Could not determine host kernel version when checking hugetlbfs compatibility
    KernelVersion,
    /// The `tsc_khz_multiplier` must be a finite value greater than 0; if not exactly 1.0, it must be in [0.1, 100.0].
    InvalidTscKhzMultiplier,
    /// Guest TSC frequency dilation is only supported on x86_64.
    #[cfg(target_arch = "aarch64")]
    TscDilationNotSupported,
    /// Computed guest TSC frequency is 0 kHz; increase `tsc_khz_multiplier` or host TSC frequency.
    ZeroTscFrequency,
}

/// Describes the possible (huge)page configurations for a microVM's memory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum HugePageConfig {
    /// Do not use hugepages, e.g. back guest memory by 4K
    #[default]
    None,
    /// Back guest memory by 2MB hugetlbfs pages
    #[serde(rename = "2M")]
    Hugetlbfs2M,
}

impl HugePageConfig {
    /// Checks whether the given memory size (in MiB) is valid for this [`HugePageConfig`], e.g.
    /// whether it is a multiple of the page size
    fn is_valid_mem_size(&self, mem_size_mib: usize) -> bool {
        let divisor = match self {
            // Any integer memory size expressed in MiB will be a multiple of 4096KiB.
            HugePageConfig::None => 1,
            HugePageConfig::Hugetlbfs2M => 2,
        };

        mem_size_mib.is_multiple_of(divisor)
    }

    /// Returns the flags required to pass to `mmap`, in addition to `MAP_ANONYMOUS`, to
    /// create a mapping backed by huge pages as described by this [`HugePageConfig`].
    pub fn mmap_flags(&self) -> libc::c_int {
        match self {
            HugePageConfig::None => 0,
            HugePageConfig::Hugetlbfs2M => libc::MAP_HUGETLB | libc::MAP_HUGE_2MB,
        }
    }

    /// Returns `true` iff this [`HugePageConfig`] describes a hugetlbfs-based configuration.
    pub fn is_hugetlbfs(&self) -> bool {
        matches!(self, HugePageConfig::Hugetlbfs2M)
    }

    /// Gets the page size in bytes of this [`HugePageConfig`].
    pub fn page_size(&self) -> usize {
        match self {
            HugePageConfig::None => 4096,
            HugePageConfig::Hugetlbfs2M => 2 * 1024 * 1024,
        }
    }
}

impl From<HugePageConfig> for Option<memfd::HugetlbSize> {
    fn from(value: HugePageConfig) -> Self {
        match value {
            HugePageConfig::None => None,
            HugePageConfig::Hugetlbfs2M => Some(memfd::HugetlbSize::Huge2MB),
        }
    }
}

/// Struct used in PUT `/machine-config` API call.
///
/// `Eq` is implemented manually because [`f64`] does not implement [`Eq`]; the
/// `tsc_khz_multiplier` field is validated to reject NaN/inf, so equality is total
/// for all accepted configurations.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
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
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: bool,
    /// Configures what page size Firecracker should use to back guest memory.
    #[serde(default)]
    pub huge_pages: HugePageConfig,
    /// Optional guest TSC frequency multiplier for time-compressed guests (x86_64 only).
    ///
    /// When set to a value other than `1.0`, Firecracker programs each vCPU with
    /// `KVM_SET_TSC_KHZ` so the guest's TSC frequency is
    /// `floor(host_tsc_khz * multiplier)`. The guest then observes wall-clock time
    /// advancing at `multiplier` times real time (requires guest `clocksource=tsc`
    /// and host hardware TSC scaling / `KVM_CAP_TSC_CONTROL`).
    ///
    /// Exactly `1.0` is a documented no-op (the KVM call is skipped). Values other
    /// than `1.0` must be finite and in `[0.1, 100.0]`. NaN and infinities are
    /// rejected.
    ///
    /// Snapshot restore re-applies the saved per-vCPU `tsc_khz` from the snapshot
    /// state (see `build_microvm_from_snapshot`), so a snapshot of a dilated VM
    /// restores dilated for free — no separate multiplier field is persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsc_khz_multiplier: Option<f64>,
    /// GDB socket address.
    #[cfg(feature = "gdb")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gdb_socket_path: Option<String>,
}

impl Eq for MachineConfig {}

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
            track_dirty_pages: false,
            huge_pages: HugePageConfig::None,
            tsc_khz_multiplier: None,
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
///
/// `Eq` is implemented manually because [`f64`] does not implement [`Eq`].
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
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
    /// Enables or disables dirty page tracking. Enabling allows incremental snapshots.
    #[serde(default)]
    pub track_dirty_pages: Option<bool>,
    /// Configures what page size Firecracker should use to back guest memory.
    #[serde(default)]
    pub huge_pages: Option<HugePageConfig>,
    /// Guest TSC frequency multiplier update (see [`MachineConfig::tsc_khz_multiplier`]).
    ///
    /// Triple-state so PUT full replacement and PATCH partial update both work:
    /// * `None` — field omitted on PATCH: leave the current value unchanged.
    /// * `Some(None)` — explicit clear. Produced by [`From<MachineConfig>`] when the
    ///   PUT body omits the field (or sets it to JSON `null` on `MachineConfig`).
    /// * `Some(Some(m))` — set the multiplier to `m` (PATCH JSON number, or PUT body).
    ///
    /// PUT always goes through [`From<MachineConfig>`], which wraps the body value
    /// in the outer `Some(...)` so omission clears dilation — the same pattern as
    /// `track_dirty_pages: Some(cfg.track_dirty_pages)`.
    #[serde(default)]
    pub tsc_khz_multiplier: Option<Option<f64>>,
    /// GDB socket address.
    #[cfg(feature = "gdb")]
    #[serde(default)]
    pub gdb_socket_path: Option<String>,
}

impl Eq for MachineConfigUpdate {}

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
            track_dirty_pages: Some(cfg.track_dirty_pages),
            huge_pages: Some(cfg.huge_pages),
            // Always `Some(...)` so PUT omission clears the field (see field docs).
            tsc_khz_multiplier: Some(cfg.tsc_khz_multiplier),
            #[cfg(feature = "gdb")]
            gdb_socket_path: cfg.gdb_socket_path,
        }
    }
}

/// Validates a guest TSC frequency multiplier.
///
/// Accepts exactly `1.0` (no-op) and finite values in
/// [`TSC_KHZ_MULTIPLIER_MIN`]..=[`TSC_KHZ_MULTIPLIER_MAX`]. Rejects NaN, infinities,
/// non-positive values, and values outside the range (other than `1.0`).
pub fn validate_tsc_khz_multiplier(multiplier: f64) -> Result<(), MachineConfigError> {
    if !multiplier.is_finite() || multiplier <= 0.0 {
        return Err(MachineConfigError::InvalidTscKhzMultiplier);
    }
    if multiplier == 1.0 {
        return Ok(());
    }
    if !(TSC_KHZ_MULTIPLIER_MIN..=TSC_KHZ_MULTIPLIER_MAX).contains(&multiplier) {
        return Err(MachineConfigError::InvalidTscKhzMultiplier);
    }
    Ok(())
}

/// Computes the guest TSC frequency in kHz for the given host frequency and multiplier.
///
/// Returns `None` when `multiplier == 1.0` (no-op; caller should skip `KVM_SET_TSC_KHZ`).
/// Otherwise returns `floor(host_tsc_khz * multiplier)` as a `u32`.
///
/// # Errors
///
/// * [`MachineConfigError::InvalidTscKhzMultiplier`] if the multiplier fails validation.
/// * [`MachineConfigError::ZeroTscFrequency`] if the computed frequency rounds down to 0.
pub fn compute_guest_tsc_khz(
    host_tsc_khz: u32,
    multiplier: f64,
) -> Result<Option<u32>, MachineConfigError> {
    validate_tsc_khz_multiplier(multiplier)?;
    if multiplier == 1.0 {
        return Ok(None);
    }

    let product = f64::from(host_tsc_khz) * multiplier;
    // Positive finite product; round down (toward zero for positive values).
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let desired_khz = product as u32;
    if desired_khz == 0 {
        return Err(MachineConfigError::ZeroTscFrequency);
    }
    Ok(Some(desired_khz))
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
        let page_config = update.huge_pages.unwrap_or(self.huge_pages);

        if mem_size_mib == 0 || !page_config.is_valid_mem_size(mem_size_mib) {
            return Err(MachineConfigError::InvalidMemorySize);
        }

        let cpu_template = match update.cpu_template {
            None => self.cpu_template.clone(),
            Some(StaticCpuTemplate::None) => None,
            Some(other) => Some(CpuTemplateType::Static(other)),
        };

        // `None` = PATCH omit (keep); `Some(inner)` = set/clear (PUT always supplies this).
        let tsc_khz_multiplier = match update.tsc_khz_multiplier {
            Some(value) => value,
            None => self.tsc_khz_multiplier,
        };
        #[cfg(target_arch = "aarch64")]
        if tsc_khz_multiplier.is_some() {
            return Err(MachineConfigError::TscDilationNotSupported);
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(multiplier) = tsc_khz_multiplier {
            validate_tsc_khz_multiplier(multiplier)?;
        }

        Ok(MachineConfig {
            vcpu_count,
            mem_size_mib,
            smt,
            cpu_template,
            track_dirty_pages: update.track_dirty_pages.unwrap_or(self.track_dirty_pages),
            huge_pages: page_config,
            tsc_khz_multiplier,
            #[cfg(feature = "gdb")]
            gdb_socket_path: update.gdb_socket_path.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::cpu_config::templates::{CpuTemplateType, CustomCpuTemplate, StaticCpuTemplate};
    use crate::vmm_config::machine_config::{
        MachineConfig, MachineConfigError, MachineConfigUpdate, compute_guest_tsc_khz,
        validate_tsc_khz_multiplier,
    };

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

    #[test]
    fn test_validate_tsc_khz_multiplier() {
        validate_tsc_khz_multiplier(1.0).unwrap();
        validate_tsc_khz_multiplier(0.1).unwrap();
        validate_tsc_khz_multiplier(100.0).unwrap();
        validate_tsc_khz_multiplier(2.0).unwrap();
        validate_tsc_khz_multiplier(0.5).unwrap();

        assert_eq!(
            validate_tsc_khz_multiplier(0.0),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(-1.0),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(0.09),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(100.1),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(f64::NAN),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(f64::INFINITY),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
        assert_eq!(
            validate_tsc_khz_multiplier(f64::NEG_INFINITY),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
    }

    #[test]
    fn test_compute_guest_tsc_khz() {
        // 1.0 is a no-op.
        assert_eq!(compute_guest_tsc_khz(3_000_000, 1.0).unwrap(), None);

        // Integer kHz, round down.
        assert_eq!(
            compute_guest_tsc_khz(3_000_000, 2.0).unwrap(),
            Some(6_000_000)
        );
        assert_eq!(
            compute_guest_tsc_khz(3_000_000, 0.5).unwrap(),
            Some(1_500_000)
        );
        // floor: 1000 * 0.1 = 100
        assert_eq!(compute_guest_tsc_khz(1000, 0.1).unwrap(), Some(100));
        // floor of fractional product: 1 * 0.1 = 0.1 -> 0
        assert_eq!(
            compute_guest_tsc_khz(1, 0.1),
            Err(MachineConfigError::ZeroTscFrequency)
        );

        assert_eq!(
            compute_guest_tsc_khz(3_000_000, 0.0),
            Err(MachineConfigError::InvalidTscKhzMultiplier)
        );
    }

    #[test]
    fn test_tsc_khz_multiplier_update() {
        let base = MachineConfig::default();

        // PATCH omit (`None`) leaves config unchanged.
        let updated = base
            .update(&MachineConfigUpdate {
                vcpu_count: Some(2),
                ..Default::default()
            })
            .unwrap();
        assert!(updated.tsc_khz_multiplier.is_none());
        assert_eq!(updated.vcpu_count, 2);

        #[cfg(target_arch = "x86_64")]
        {
            let with_mult = base
                .update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(Some(2.0)),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(with_mult.tsc_khz_multiplier, Some(2.0));

            // PUT-style clear: `Some(None)` (as produced by `From<MachineConfig>` when
            // the body omits the field) resets dilation.
            let cleared = with_mult
                .update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(None),
                    ..Default::default()
                })
                .unwrap();
            assert!(cleared.tsc_khz_multiplier.is_none());

            // PUT-style full conversion omits the field on MachineConfig → clears.
            let put_body = MachineConfig {
                vcpu_count: 2,
                mem_size_mib: 256,
                ..Default::default()
            };
            let from_put = MachineConfigUpdate::from(put_body);
            assert_eq!(from_put.tsc_khz_multiplier, Some(None));
            let after_put = with_mult.update(&from_put).unwrap();
            assert!(after_put.tsc_khz_multiplier.is_none());
            assert_eq!(after_put.vcpu_count, 2);
            assert_eq!(after_put.mem_size_mib, 256);

            // Invalid multiplier rejected.
            assert_eq!(
                base.update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(Some(0.0)),
                    ..Default::default()
                }),
                Err(MachineConfigError::InvalidTscKhzMultiplier)
            );
            assert_eq!(
                base.update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(Some(f64::NAN)),
                    ..Default::default()
                }),
                Err(MachineConfigError::InvalidTscKhzMultiplier)
            );

            // Exactly 1.0 accepted (no-op at boot).
            let updated = base
                .update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(Some(1.0)),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(updated.tsc_khz_multiplier, Some(1.0));

            // PATCH JSON sets the nested option correctly.
            let patch: MachineConfigUpdate =
                serde_json::from_str(r#"{"tsc_khz_multiplier": 3.0}"#).unwrap();
            assert_eq!(patch.tsc_khz_multiplier, Some(Some(3.0)));
            let updated = base.update(&patch).unwrap();
            assert_eq!(updated.tsc_khz_multiplier, Some(3.0));
        }

        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(
                base.update(&MachineConfigUpdate {
                    tsc_khz_multiplier: Some(Some(2.0)),
                    ..Default::default()
                }),
                Err(MachineConfigError::TscDilationNotSupported)
            );
        }
    }

    #[test]
    fn test_serialize_tsc_khz_multiplier() {
        let mconfig = MachineConfig {
            tsc_khz_multiplier: Some(2.5),
            ..Default::default()
        };
        let serialized = serde_json::to_string(&mconfig).unwrap();
        assert!(serialized.contains("tsc_khz_multiplier"));
        let deserialized = serde_json::from_str::<MachineConfig>(&serialized).unwrap();
        assert_eq!(deserialized.tsc_khz_multiplier, Some(2.5));

        // Default omits the field.
        let mconfig = MachineConfig::default();
        let serialized = serde_json::to_string(&mconfig).unwrap();
        assert!(!serialized.contains("tsc_khz_multiplier"));
    }
}
