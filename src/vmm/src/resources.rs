// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vm_memory::GuestAddress;

use crate::cpu_config::templates::CustomCpuTemplate;
use crate::logger::LoggerConfig;
use crate::utils::mib_to_bytes;
use crate::vmm_config::TokenBucketConfig;
use crate::vmm_config::boot_source::{
    BootConfig, BootSource, BootSourceConfig, BootSourceConfigError,
};
use crate::vmm_config::drive::*;
use crate::vmm_config::entropy::*;
use crate::vmm_config::instance_info::InstanceInfo;
use crate::vmm_config::machine_config::{MachineConfig, MachineConfigError, MachineConfigUpdate};
use crate::vmm_config::metrics::{MetricsConfig, MetricsConfigError, init_metrics};
use crate::vmm_config::net::*;
use crate::vmm_config::serial::SerialConfig;
use crate::vmm_config::vsock::*;
use crate::vstate::farplane::FarplaneBackend;
use crate::vstate::memory::{GuestRegionMmap, MemoryError};

/// Errors encountered when configuring microVM resources.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResourcesError {
    /// Block device error: {0}
    BlockDevice(#[from] DriveError),
    /// Boot source error: {0}
    BootSource(#[from] BootSourceConfigError),
    /// File operation error: {0}
    File(#[from] std::io::Error),
    /// Invalid JSON: {0}
    InvalidJson(#[from] serde_json::Error),
    /// Logger error: {0}
    Logger(#[from] crate::logger::LoggerUpdateError),
    /// Metrics error: {0}
    Metrics(#[from] MetricsConfigError),
    /// Network device error: {0}
    NetDevice(#[from] NetworkInterfaceError),
    /// VM config error: {0}
    MachineConfig(#[from] MachineConfigError),
    /// Vsock device error: {0}
    VsockDevice(#[from] VsockConfigError),
    /// Entropy device error: {0}
    EntropyConfig(#[from] EntropyDeviceError),
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(untagged)]
#[allow(missing_docs)]
pub enum CustomCpuTemplateOrPath {
    Path(PathBuf),
    Template(CustomCpuTemplate),
}

/// Used for configuring a vmm from one single json passed to the Firecracker process.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs)]
pub struct VmmConfig {
    pub drives: Vec<BlockDeviceConfig>,
    pub boot_source: BootSourceConfig,
    pub cpu_config: Option<CustomCpuTemplateOrPath>,
    pub logger: Option<LoggerConfig>,
    pub machine_config: Option<MachineConfig>,
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterfaceConfig>,
    pub vsock: Option<VsockDeviceConfig>,
    pub entropy: Option<EntropyDeviceConfig>,
    #[serde(skip)]
    pub serial_config: Option<SerialConfig>,
}

/// A data structure that encapsulates the device configurations
/// held in the Vmm.
#[derive(Debug, Default)]
pub struct VmResources {
    /// The vCpu and memory configuration for this microVM.
    pub machine_config: MachineConfig,
    /// The boot source spec (contains both config and builder) for this microVM.
    pub boot_source: BootSource,
    /// The block devices.
    pub block: BlockBuilder,
    /// The vsock device.
    pub vsock: VsockBuilder,
    /// The network devices builder.
    pub net_builder: NetBuilder,
    /// The entropy device builder.
    pub entropy: EntropyDeviceBuilder,
    /// Whether or not to load boot timer device.
    pub boot_timer: bool,
    /// Whether or not to use PCIe transport for VirtIO devices.
    pub pci_enabled: bool,
    /// Where serial console output should be written to
    pub serial_out_path: Option<PathBuf>,
    /// Optional rate limiter config for serial output.
    pub serial_rate_limiter_cfg: Option<TokenBucketConfig>,
}

impl VmResources {
    /// Returns a `TokenBucket` from the serial rate limiter config, if configured.
    pub fn serial_rate_limiter(&self) -> Option<crate::rate_limiter::TokenBucket> {
        self.serial_rate_limiter_cfg.as_ref().and_then(|cfg| {
            crate::rate_limiter::TokenBucket::new(
                cfg.size,
                cfg.one_time_burst.unwrap_or(0),
                cfg.refill_time,
            )
        })
    }

    /// Configures Vmm resources as described by the `config_json` param.
    pub fn from_json(
        config_json: &str,
        _instance_info: &InstanceInfo,
        _size_limit: usize,
        _metadata: Option<&str>,
    ) -> Result<Self, ResourcesError> {
        let vmm_config = serde_json::from_str::<VmmConfig>(config_json)?;

        if let Some(logger_config) = vmm_config.logger {
            crate::logger::LOGGER.update(logger_config)?;
        }

        if let Some(metrics) = vmm_config.metrics {
            init_metrics(metrics)?;
        }

        let mut resources = Self::default();
        if let Some(machine_config) = vmm_config.machine_config {
            let machine_config = MachineConfigUpdate::from(machine_config);
            resources.update_machine_config(&machine_config)?;
        }

        if let Some(either) = vmm_config.cpu_config {
            match either {
                CustomCpuTemplateOrPath::Path(path) => {
                    let cpu_config_json =
                        std::fs::read_to_string(path).map_err(ResourcesError::File)?;
                    let cpu_template = CustomCpuTemplate::try_from(cpu_config_json.as_str())?;
                    resources.set_custom_cpu_template(cpu_template);
                }
                CustomCpuTemplateOrPath::Template(template) => {
                    resources.set_custom_cpu_template(template)
                }
            }
        }

        resources.build_boot_source(vmm_config.boot_source)?;

        for drive_config in vmm_config.drives.into_iter() {
            resources.set_block_device(drive_config)?;
        }

        for net_config in vmm_config.network_interfaces.into_iter() {
            resources.build_net_device(net_config)?;
        }

        if let Some(vsock_config) = vmm_config.vsock {
            resources.set_vsock_device(vsock_config)?;
        }

        if let Some(entropy_device_config) = vmm_config.entropy {
            resources.build_entropy_device(entropy_device_config)?;
        }

        if let Some(serial_cfg) = vmm_config.serial_config {
            resources.serial_out_path = serial_cfg.serial_out_path;
            resources.serial_rate_limiter_cfg = serial_cfg.rate_limiter;
        }

        Ok(resources)
    }

    /// Add a custom CPU template to the VM resources
    /// to configure vCPUs.
    pub fn set_custom_cpu_template(&mut self, cpu_template: CustomCpuTemplate) {
        self.machine_config.set_custom_cpu_template(cpu_template);
    }

    /// Updates the configuration of the microVM.
    pub fn update_machine_config(
        &mut self,
        update: &MachineConfigUpdate,
    ) -> Result<(), MachineConfigError> {
        let updated = self.machine_config.update(update)?;

        self.machine_config = updated;

        Ok(())
    }

    /// Obtains the boot source hooks (kernel fd, command line creation and validation).
    pub fn build_boot_source(
        &mut self,
        boot_source_cfg: BootSourceConfig,
    ) -> Result<(), BootSourceConfigError> {
        self.boot_source = BootSource {
            builder: Some(BootConfig::new(&boot_source_cfg)?),
            config: boot_source_cfg,
        };

        Ok(())
    }

    /// Inserts a block to be attached when the VM starts.
    // Only call this function as part of user configuration.
    // If the drive_id does not exist, a new Block Device Config is added to the list.
    pub fn set_block_device(
        &mut self,
        block_device_config: BlockDeviceConfig,
    ) -> Result<(), DriveError> {
        self.block.insert(block_device_config)
    }

    /// Builds a network device to be attached when the VM starts.
    pub fn build_net_device(
        &mut self,
        body: NetworkInterfaceConfig,
    ) -> Result<(), NetworkInterfaceError> {
        let _ = self.net_builder.build(body)?;
        Ok(())
    }

    /// Sets a vsock device to be attached when the VM starts.
    pub fn set_vsock_device(&mut self, config: VsockDeviceConfig) -> Result<(), VsockConfigError> {
        self.vsock.insert(config)
    }

    /// Builds an entropy device to be attached when the VM starts.
    pub fn build_entropy_device(
        &mut self,
        body: EntropyDeviceConfig,
    ) -> Result<(), EntropyDeviceError> {
        self.entropy.insert(body)
    }

    fn allocate_memory_regions(
        &self,
        regions: &[(GuestAddress, usize)],
    ) -> Result<Vec<GuestRegionMmap>, MemoryError> {
        FarplaneBackend::construct_boot(regions)
            .map_err(|err| MemoryError::Farplane(err.to_string()))
    }

    /// Allocates guest memory in a configuration most appropriate for these [`VmResources`].
    pub fn allocate_guest_memory(&self) -> Result<Vec<GuestRegionMmap>, MemoryError> {
        let regions =
            crate::arch::arch_memory_regions(mib_to_bytes(self.machine_config.mem_size_mib));
        self.allocate_memory_regions(&regions)
    }

    /// Allocates a single guest memory region.
    pub fn allocate_memory_region(
        &self,
        start: GuestAddress,
        size: usize,
    ) -> Result<GuestRegionMmap, MemoryError> {
        Ok(self
            .allocate_memory_regions(&[(start, size)])?
            .pop()
            .unwrap())
    }
}

impl From<&VmResources> for VmmConfig {
    fn from(resources: &VmResources) -> Self {
        VmmConfig {
            drives: resources.block.configs(),
            boot_source: resources.boot_source.config.clone(),
            cpu_config: None,
            logger: None,
            machine_config: Some(resources.machine_config.clone()),
            metrics: None,
            network_interfaces: resources.net_builder.configs(),
            vsock: resources.vsock.config(),
            entropy: resources.entropy.config(),
            // serial_config is marked serde(skip) so that it doesnt end up in snapshots.
            serial_config: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::linux::fs::MetadataExt;
    use std::str::FromStr;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::HTTP_MAX_PAYLOAD_SIZE;
    use crate::cpu_config::templates::test_utils::TEST_TEMPLATE_JSON;
    use crate::cpu_config::templates::{CpuTemplateType, StaticCpuTemplate};
    use crate::devices::virtio::block::virtio::VirtioBlockError;
    use crate::devices::virtio::block::{BlockError, CacheType};
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::vsock::VSOCK_DEV_ID;
    use crate::resources::VmResources;
    use crate::utils::net::mac::MacAddr;
    use crate::vmm_config::RateLimiterConfig;
    use crate::vmm_config::boot_source::{
        BootConfig, BootSource, BootSourceConfig, DEFAULT_KERNEL_CMDLINE,
    };
    use crate::vmm_config::drive::{BlockBuilder, BlockDeviceConfig};
    use crate::vmm_config::net::{NetBuilder, NetworkInterfaceConfig};
    use crate::vmm_config::vsock::tests::default_config;

    fn default_net_cfg() -> NetworkInterfaceConfig {
        NetworkInterfaceConfig {
            iface_id: "net_if1".to_string(),
            // TempFile::new_with_prefix("") generates a random file name used as random net_if
            // name.
            host_dev_name: TempFile::new_with_prefix("")
                .unwrap()
                .as_path()
                .to_str()
                .unwrap()
                .to_string(),
            guest_mac: Some(MacAddr::from_str("01:23:45:67:89:0a").unwrap()),
            mtu: None,
            rx_rate_limiter: Some(RateLimiterConfig::default()),
            tx_rate_limiter: Some(RateLimiterConfig::default()),
        }
    }

    fn default_net_builder() -> NetBuilder {
        let mut net_builder = NetBuilder::new();
        net_builder.build(default_net_cfg()).unwrap();

        net_builder
    }

    fn default_block_cfg() -> (BlockDeviceConfig, TempFile) {
        let tmp_file = TempFile::new().unwrap();
        (
            BlockDeviceConfig {
                drive_id: "block1".to_string(),
                partuuid: Some("0eaa91a0-01".to_string()),
                is_root_device: false,
                cache_type: CacheType::Unsafe,
                is_read_only: Some(false),
                path_on_host: Some(tmp_file.as_path().to_str().unwrap().to_string()),
                fd: None,
                rate_limiter: Some(RateLimiterConfig::default()),
                file_engine_type: None,
            },
            tmp_file,
        )
    }

    fn default_blocks() -> BlockBuilder {
        let mut blocks = BlockBuilder::new();
        let (cfg, _file) = default_block_cfg();
        blocks.insert(cfg).unwrap();
        blocks
    }

    fn default_boot_cfg() -> BootSource {
        let kernel_cmdline =
            linux_loader::cmdline::Cmdline::try_from(DEFAULT_KERNEL_CMDLINE, 4096).unwrap();
        let tmp_file = TempFile::new().unwrap();
        BootSource {
            config: BootSourceConfig::default(),
            builder: Some(BootConfig {
                cmdline: kernel_cmdline,
                kernel_file: File::open(tmp_file.as_path()).unwrap(),
                initrd_file: Some(File::open(tmp_file.as_path()).unwrap()),
            }),
        }
    }

    fn default_vm_resources() -> VmResources {
        VmResources {
            machine_config: MachineConfig::default(),
            boot_source: default_boot_cfg(),
            block: default_blocks(),
            vsock: Default::default(),
            net_builder: default_net_builder(),
            boot_timer: false,
            entropy: Default::default(),
            pci_enabled: false,
            serial_out_path: None,
            serial_rate_limiter_cfg: None,
        }
    }

    #[test]
    fn test_from_json() {
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();

        // We will test different scenarios with invalid resources configuration and
        // check the expected errors. We include configuration for the kernel and rootfs
        // in every json because they are mandatory fields. If we don't configure
        // these resources, it is considered an invalid json and the test will crash.

        // Invalid JSON string must yield a `serde_json` error.
        let error =
            VmResources::from_json(r#"}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
                .unwrap_err();
        assert!(
            matches!(error, ResourcesError::InvalidJson(_)),
            "{:?}",
            error
        );

        // Valid JSON string without the configuration for kernel or rootfs
        // result in an invalid JSON error.
        let error =
            VmResources::from_json(r#"{}"#, &default_instance_info, HTTP_MAX_PAYLOAD_SIZE, None)
                .unwrap_err();
        assert!(
            matches!(error, ResourcesError::InvalidJson(_)),
            "{:?}",
            error
        );

        // Invalid kernel path.
        let mut json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "/invalid/path",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            rootfs_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::BootSource(BootSourceConfigError::InvalidKernelPath(_))
            ),
            "{:?}",
            error
        );

        // Invalid rootfs path.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "/invalid/path",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::BlockDevice(DriveError::CreateBlockDevice(
                    BlockError::VirtioBackend(VirtioBlockError::BackingFile(_, _)),
                ))
            ),
            "{:?}",
            error
        );
        // Valid config for x86 but invalid on aarch64 since it uses cpu_template.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "cpu_template": "C3"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );
        #[cfg(target_arch = "x86_64")]
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
        #[cfg(target_arch = "aarch64")]
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();

        // Invalid memory size.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 0
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::MachineConfig(MachineConfigError::InvalidMemorySize)
            ),
            "{:?}",
            error
        );

        // Invalid path for logger pipe.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "logger": {{
	                    "log_path": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::Logger(crate::logger::LoggerUpdateError(_))
            ),
            "{:?}",
            error
        );

        // Invalid path for metrics pipe.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "metrics": {{
	                    "metrics_path": "/invalid/path"
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ResourcesError::Metrics(MetricsConfigError::InitializationFailure { .. })
            ),
            "{:?}",
            error
        );

        // Reuse of a host name.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "network-interfaces": [
                        {{
                            "iface_id": "netif1",
                            "host_dev_name": "hostname7"
                        }},
                        {{
                            "iface_id": "netif2",
                            "host_dev_name": "hostname7"
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap()
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();

        assert!(
            matches!(
                error,
                ResourcesError::NetDevice(NetworkInterfaceError::CreateNetworkDevice(
                    crate::devices::virtio::net::NetError::TapOpen { .. },
                ))
            ),
            "{:?}",
            error
        );

        // Let's try now passing a valid configuration. We won't include any logger
        // or metrics configuration because these were already initialized in other
        // tests of this module and the reinitialization of them will cause crashing.
        json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ],
                    "network-interfaces": [
                        {{
                            "iface_id": "netif",
                            "host_dev_name": "hostname8"
                        }}
                    ],
                    "machine-config": {{
                        "vcpu_count": 2,
                        "mem_size_mib": 1024,
                        "smt": false
                    }}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );
        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_cpu_config_from_invalid_json() {
        // Invalid cpu config file path.
        // `VmResources::from_json()` should fail with `Error::File`.
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();

        let json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "cpu-config": "/invalid/path",
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        let error = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap_err();
        assert!(matches!(error, ResourcesError::File(_)), "{:?}", error);
    }

    #[test]
    fn test_cpu_config_inline() {
        // Include custom cpu template directly inline in config json
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();

        let json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "cpu-config": {},
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            TEST_TEMPLATE_JSON,
            rootfs_file.as_path().to_str().unwrap(),
        );

        VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_cpu_config_from_valid_json() {
        // Valid cpu config file path.
        // `VmResources::from_json()` should succeed and it should have a custom CPU template.
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let default_instance_info = InstanceInfo::default();
        let cpu_config_file = TempFile::new().unwrap();
        cpu_config_file
            .as_file()
            .write_all("{}".as_bytes())
            .unwrap();

        let json = format!(
            r#"{{
                    "boot-source": {{
                        "kernel_image_path": "{}",
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                    }},
                    "cpu-config": "{}",
                    "drives": [
                        {{
                            "drive_id": "rootfs",
                            "path_on_host": "{}",
                            "is_root_device": true,
                            "is_read_only": false
                        }}
                    ]
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            cpu_config_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        let vm_resources = VmResources::from_json(
            json.as_str(),
            &default_instance_info,
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();
        assert_eq!(
            vm_resources.machine_config.cpu_template,
            Some(CpuTemplateType::Custom(CustomCpuTemplate::default()))
        );
    }

    #[test]
    fn test_cast_to_vmm_config() {
        let kernel_file = TempFile::new().unwrap();
        let rootfs_file = TempFile::new().unwrap();
        let json = format!(
            r#"{{
                "boot-source": {{
                    "kernel_image_path": "{}",
                    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
                }},
                "drives": [
                    {{
                        "drive_id": "rootfs",
                        "path_on_host": "{}",
                        "is_root_device": true,
                        "is_read_only": false,
                        "io_engine": "Sync"
                    }}
                ],
                "machine-config": {{
                    "vcpu_count": 2,
                    "mem_size_mib": 1024,
                    "smt": false
                }},
                "entropy": {{}}
            }}"#,
            kernel_file.as_path().to_str().unwrap(),
            rootfs_file.as_path().to_str().unwrap(),
        );

        let resources = VmResources::from_json(
            json.as_str(),
            &InstanceInfo::default(),
            HTTP_MAX_PAYLOAD_SIZE,
            None,
        )
        .unwrap();

        let initial_vmm_config = serde_json::from_str::<VmmConfig>(&json).unwrap();
        let vmm_config: VmmConfig = (&resources).into();
        assert_eq!(initial_vmm_config, vmm_config);
    }

    #[test]
    fn test_update_machine_config() {
        let mut vm_resources = default_vm_resources();
        let mut aux_vm_config = MachineConfigUpdate {
            vcpu_count: Some(32),
            mem_size_mib: Some(512),
            smt: Some(false),
            #[cfg(target_arch = "x86_64")]
            cpu_template: Some(StaticCpuTemplate::T2),
            #[cfg(target_arch = "aarch64")]
            cpu_template: Some(StaticCpuTemplate::V1N1),
            #[cfg(feature = "gdb")]
            gdb_socket_path: None,
        };

        assert_ne!(
            MachineConfigUpdate::from(vm_resources.machine_config.clone()),
            aux_vm_config
        );
        vm_resources.update_machine_config(&aux_vm_config).unwrap();
        assert_eq!(
            MachineConfigUpdate::from(vm_resources.machine_config.clone()),
            aux_vm_config
        );

        // Invalid vcpu count.
        aux_vm_config.vcpu_count = Some(0);
        assert_eq!(
            vm_resources.update_machine_config(&aux_vm_config),
            Err(MachineConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(33);
        assert_eq!(
            vm_resources.update_machine_config(&aux_vm_config),
            Err(MachineConfigError::InvalidVcpuCount)
        );

        // Check that SMT is not supported on aarch64, and that on x86_64 enabling it requires vcpu
        // count to be even.
        aux_vm_config.smt = Some(true);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(
            vm_resources.update_machine_config(&aux_vm_config),
            Err(MachineConfigError::SmtNotSupported)
        );
        aux_vm_config.vcpu_count = Some(3);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            vm_resources.update_machine_config(&aux_vm_config),
            Err(MachineConfigError::InvalidVcpuCount)
        );
        aux_vm_config.vcpu_count = Some(32);
        #[cfg(target_arch = "x86_64")]
        vm_resources.update_machine_config(&aux_vm_config).unwrap();
        aux_vm_config.smt = Some(false);

        // Invalid mem_size_mib.
        aux_vm_config.mem_size_mib = Some(0);
        assert_eq!(
            vm_resources.update_machine_config(&aux_vm_config),
            Err(MachineConfigError::InvalidMemorySize)
        );
    }

    #[test]
    fn test_set_entropy_device() {
        let mut vm_resources = default_vm_resources();
        vm_resources.entropy = EntropyDeviceBuilder::new();
        let entropy_device_cfg = EntropyDeviceConfig::default();

        assert!(vm_resources.entropy.get().is_none());
        vm_resources
            .build_entropy_device(entropy_device_cfg.clone())
            .unwrap();

        let actual_entropy_cfg = vm_resources.entropy.config().unwrap();
        assert_eq!(actual_entropy_cfg, entropy_device_cfg);
    }

    #[test]
    fn test_set_boot_source() {
        let tmp_file = TempFile::new().unwrap();
        let cmdline = "reboot=k panic=1 pci=off nomodule 8250.nr_uarts=0";
        let expected_boot_cfg = BootSourceConfig {
            kernel_image_path: String::from(tmp_file.as_path().to_str().unwrap()),
            initrd_path: Some(String::from(tmp_file.as_path().to_str().unwrap())),
            boot_args: Some(cmdline.to_string()),
        };

        let mut vm_resources = default_vm_resources();
        let boot_builder = vm_resources.boot_source.builder.as_ref().unwrap();
        let tmp_ino = tmp_file.as_file().metadata().unwrap().st_ino();

        assert_ne!(
            boot_builder
                .cmdline
                .as_cstring()
                .unwrap()
                .as_bytes_with_nul(),
            [cmdline.as_bytes(), b"\0"].concat()
        );
        assert_ne!(
            boot_builder.kernel_file.metadata().unwrap().st_ino(),
            tmp_ino
        );
        assert_ne!(
            boot_builder
                .initrd_file
                .as_ref()
                .unwrap()
                .metadata()
                .unwrap()
                .st_ino(),
            tmp_ino
        );

        vm_resources.build_boot_source(expected_boot_cfg).unwrap();
        let boot_source_builder = vm_resources.boot_source.builder.unwrap();
        assert_eq!(
            boot_source_builder
                .cmdline
                .as_cstring()
                .unwrap()
                .as_bytes_with_nul(),
            [cmdline.as_bytes(), b"\0"].concat()
        );
        assert_eq!(
            boot_source_builder.kernel_file.metadata().unwrap().st_ino(),
            tmp_ino
        );
        assert_eq!(
            boot_source_builder
                .initrd_file
                .as_ref()
                .unwrap()
                .metadata()
                .unwrap()
                .st_ino(),
            tmp_ino
        );
    }

    #[test]
    fn test_set_block_device() {
        let mut vm_resources = default_vm_resources();
        let (mut new_block_device_cfg, _file) = default_block_cfg();
        let tmp_file = TempFile::new().unwrap();
        new_block_device_cfg.drive_id = "block2".to_string();
        new_block_device_cfg.path_on_host = Some(tmp_file.as_path().to_str().unwrap().to_string());
        assert_eq!(vm_resources.block.devices.len(), 1);
        vm_resources.set_block_device(new_block_device_cfg).unwrap();
        assert_eq!(vm_resources.block.devices.len(), 2);
    }

    #[test]
    fn test_set_vsock_device() {
        let mut vm_resources = default_vm_resources();
        let mut tmp_sock_file = TempFile::new().unwrap();
        tmp_sock_file.remove().unwrap();
        let new_vsock_cfg = default_config(&tmp_sock_file);
        assert!(vm_resources.vsock.get().is_none());
        vm_resources.set_vsock_device(new_vsock_cfg).unwrap();
        let actual_vsock_cfg = vm_resources.vsock.get().unwrap();
        assert_eq!(actual_vsock_cfg.lock().unwrap().id(), VSOCK_DEV_ID);
    }

    #[test]
    fn test_set_net_device() {
        let mut vm_resources = default_vm_resources();

        // Clone the existing net config in order to obtain a new one.
        let mut new_net_device_cfg = default_net_cfg();
        new_net_device_cfg.iface_id = "new_net_if".to_string();
        new_net_device_cfg.guest_mac = Some(MacAddr::from_str("01:23:45:67:89:0c").unwrap());
        new_net_device_cfg.host_dev_name = "dummy_path2".to_string();
        assert_eq!(vm_resources.net_builder.len(), 1);

        vm_resources.build_net_device(new_net_device_cfg).unwrap();
        assert_eq!(vm_resources.net_builder.len(), 2);
    }
}
