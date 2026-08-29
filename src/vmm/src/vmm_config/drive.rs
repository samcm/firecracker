// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::RateLimiterConfig;
use crate::VmmError;
use crate::devices::virtio::block::device::Block;
pub use crate::devices::virtio::block::virtio::device::FileEngineType;
use crate::devices::virtio::block::{
    BOOTSTRAP_DESCRIPTOR_FILENO, BlockError, CacheType, ROOT_DESCRIPTOR_FILENO,
};
use crate::devices::virtio::device::VirtioDevice;

/// Errors associated with the operations allowed on a drive.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum DriveError {
    /// Unable to create the virtio block device: {0}
    CreateBlockDevice(BlockError),
    /// Cannot create RateLimiter: {0}
    CreateRateLimiter(io::Error),
    /// Descriptor {0} is not inherited: {1}
    DescriptorNotInherited(RawFd, io::Error),
    /// Descriptor {0} contradicts `is_root_device`: only the root image backs the root device.
    DescriptorRoleMismatch(RawFd),
    /// Unable to patch the block device: {0} Please verify the request arguments.
    DeviceUpdate(VmmError),
    /// A read-only drive has no write-back cache to flush.
    ReadOnlyWriteback,
    /// A root block device already exists!
    RootBlockDeviceAlreadyAdded,
    /// Descriptor {0} is not one of the descriptors the jailer reserves for inherited images.
    UnreservedDescriptor(RawFd),
    /// Descriptor {0} is not read-only.
    WritableDescriptor(RawFd),
    /// A drive backed by `fd` requires `is_read_only` to be true.
    WritableDrive,
}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceConfig {
    /// Unique identifier of the drive.
    pub drive_id: String,
    /// Part-UUID. Represents the unique id of the boot partition of this device. It is
    /// optional and it will be used only if the `is_root_device` field is true.
    pub partuuid: Option<String>,
    /// If set to true, it makes the current device the root block device.
    /// Setting this flag to true will mount the block device in the
    /// guest under /dev/vda unless the partuuid is present.
    pub is_root_device: bool,
    /// If set to true, the drive will ignore flush requests coming from
    /// the guest driver.
    #[serde(default)]
    pub cache_type: CacheType,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: Option<bool>,
    /// Descriptor the read-only image backing this drive was inherited at: the root image at
    /// [`ROOT_DESCRIPTOR_FILENO`], the bootstrap image at [`BOOTSTRAP_DESCRIPTOR_FILENO`].
    pub fd: RawFd,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    #[serde(rename = "io_engine")]
    pub file_engine_type: Option<FileEngineType>,
}

impl BlockDeviceConfig {
    /// Pairs the descriptors the jailer inherits with the drive each one backs: the root image at
    /// [`ROOT_DESCRIPTOR_FILENO`] backs the root device, and the bootstrap image at
    /// [`BOOTSTRAP_DESCRIPTOR_FILENO`] backs a drive that never is. No other number names a drive's
    /// backing store.
    pub fn reserved_descriptor(&self) -> Result<RawFd, DriveError> {
        let backs_root = match self.fd {
            ROOT_DESCRIPTOR_FILENO => true,
            BOOTSTRAP_DESCRIPTOR_FILENO => false,
            fd => return Err(DriveError::UnreservedDescriptor(fd)),
        };
        if self.is_root_device != backs_root {
            return Err(DriveError::DescriptorRoleMismatch(self.fd));
        }
        Ok(self.fd)
    }

    /// Validates the descriptor backing this drive. Every inherited image descriptor is read-only,
    /// so the drive requires `is_read_only` and the number must still name a read-only descriptor.
    pub fn descriptor(&self) -> Result<RawFd, DriveError> {
        let fd = self.reserved_descriptor()?;
        if self.is_read_only != Some(true) {
            return Err(DriveError::WritableDrive);
        }
        if self.cache_type == CacheType::Writeback {
            return Err(DriveError::ReadOnlyWriteback);
        }
        // The jailer owns image identity, immutability and size validation; Firecracker only
        // confirms that the number it was handed still names an inherited read-only descriptor.
        // SAFETY: `F_GETFL` only reads descriptor flags.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(DriveError::DescriptorNotInherited(
                fd,
                io::Error::last_os_error(),
            ));
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(DriveError::WritableDescriptor(fd));
        }
        Ok(fd)
    }
}

/// Only provided fields will be updated. I.e. if any optional fields
/// are missing, they will not be updated.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockDeviceUpdateConfig {
    /// The drive ID, as provided by the user at creation time.
    pub drive_id: String,

    // VirtioBlock specific fields
    /// New rate limiter config.
    pub rate_limiter: Option<RateLimiterConfig>,
}

/// Wrapper for the collection that holds all the Block Devices
#[derive(Debug, Default)]
pub struct BlockBuilder {
    /// The list of block devices.
    /// There can be at most one root block device and it would be the first in the list.
    // Root Device should be the first in the list whether or not PARTUUID is
    // specified in order to avoid bugs in case of switching from partuuid boot
    // scenarios to /dev/vda boot type.
    pub devices: VecDeque<Arc<Mutex<Block>>>,
}

impl BlockBuilder {
    /// Constructor for BlockDevices. It initializes an empty LinkedList.
    pub fn new() -> Self {
        Self {
            devices: Default::default(),
        }
    }

    /// Specifies whether there is a root block device already present in the list.
    pub fn has_root_device(&self) -> bool {
        // If there is a root device, it would be at the top of the list.
        if let Some(block) = self.devices.front() {
            block.lock().expect("Poisoned lock").root_device()
        } else {
            false
        }
    }

    /// Gets the index of the device with the specified `drive_id` if it exists in the list.
    fn get_index_of_drive_id(&self, drive_id: &str) -> Option<usize> {
        self.devices
            .iter()
            .position(|b| b.lock().expect("Poisoned lock").id().eq(drive_id))
    }

    /// Inserts an existing block device.
    pub fn add_virtio_device(&mut self, block_device: Arc<Mutex<Block>>) {
        if block_device.lock().expect("Poisoned lock").root_device() {
            self.devices.push_front(block_device);
        } else {
            self.devices.push_back(block_device);
        }
    }

    /// Inserts a `Block` in the block devices list using the specified configuration.
    /// If a block with the same id already exists, it will overwrite it.
    /// Inserting a secondary root block device will fail.
    pub fn insert(&mut self, config: BlockDeviceConfig) -> Result<(), DriveError> {
        let position = self.get_index_of_drive_id(&config.drive_id);
        let has_root_device = self.has_root_device();
        let configured_as_root = config.is_root_device;

        // Don't allow adding a second root block device.
        // If the new device cfg is root and not an update to the existing root, fail fast.
        if configured_as_root && has_root_device && position != Some(0) {
            return Err(DriveError::RootBlockDeviceAlreadyAdded);
        }

        let block_dev = Arc::new(Mutex::new(Block::new(config)?));

        // If the id of the drive already exists in the list, the operation is update/overwrite.
        match position {
            // New block device.
            None => {
                if configured_as_root {
                    self.devices.push_front(block_dev);
                } else {
                    self.devices.push_back(block_dev);
                }
            }
            // Update existing block device.
            Some(index) => {
                // Update the slot with the new block.
                self.devices[index] = block_dev;
                // Check if the root block device is being updated.
                if index != 0 && configured_as_root {
                    // Make sure the root device is on the first position.
                    self.devices.swap(0, index);
                }
            }
        }
        Ok(())
    }

    /// Returns a vec with the structures used to configure the devices.
    pub fn configs(&self) -> Vec<BlockDeviceConfig> {
        self.devices
            .iter()
            .map(|b| b.lock().unwrap().config())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::panic::AssertUnwindSafe;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_F_RO;

    impl PartialEq for DriveError {
        fn eq(&self, other: &DriveError) -> bool {
            self.to_string() == other.to_string()
        }
    }

    // This implementation is used only in tests.
    // We cannot directly derive clone because RateLimiter does not implement clone.
    impl Clone for BlockDeviceConfig {
        fn clone(&self) -> Self {
            BlockDeviceConfig {
                drive_id: self.drive_id.clone(),
                partuuid: self.partuuid.clone(),
                is_root_device: self.is_root_device,
                is_read_only: self.is_read_only,
                cache_type: self.cache_type,
                fd: self.fd,
                rate_limiter: self.rate_limiter,
                file_engine_type: self.file_engine_type,
            }
        }
    }

    /// Runs `body` in a child process, so retiring one of the inherited descriptors stands in for a
    /// supervisor that passed none without disturbing the rest of the test binary.
    fn in_child(body: impl FnOnce()) {
        // SAFETY: the fork is taken for its private descriptor table and the child never returns
        // to the test harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork: {}", io::Error::last_os_error());
        if child == 0 {
            // The harness routes panic output to a per-thread buffer the parent never reads, so
            // the child reports on the inherited stderr instead.
            std::panic::set_hook(Box::new(|panic| {
                let report = format!("{panic}\n");
                // SAFETY: the buffer is initialized and outlives the call.
                unsafe { libc::write(libc::STDERR_FILENO, report.as_ptr().cast(), report.len()) };
            }));
            let failed = std::panic::catch_unwind(AssertUnwindSafe(body)).is_err();
            // SAFETY: the child must neither unwind into the harness nor flush inherited buffers.
            unsafe { libc::_exit(i32::from(failed)) }
        }

        let mut status = 0;
        // SAFETY: `waitpid` writes nothing but `status`.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        assert_eq!(waited, child, "waitpid: {}", io::Error::last_os_error());
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "the child retiring an inherited descriptor failed"
        );
    }

    /// The drive the inherited root image backs.
    fn root_drive(drive_id: &str) -> BlockDeviceConfig {
        BlockDeviceConfig {
            drive_id: drive_id.to_string(),
            is_root_device: true,
            is_read_only: Some(true),
            fd: ROOT_DESCRIPTOR_FILENO,
            ..Default::default()
        }
    }

    /// The drive the inherited bootstrap image backs.
    fn bootstrap_drive(drive_id: &str) -> BlockDeviceConfig {
        BlockDeviceConfig {
            drive_id: drive_id.to_string(),
            is_root_device: false,
            is_read_only: Some(true),
            fd: BOOTSTRAP_DESCRIPTOR_FILENO,
            ..Default::default()
        }
    }

    #[test]
    fn test_create_block_devs() {
        let block_devs = BlockBuilder::new();
        assert_eq!(block_devs.devices.len(), 0);
    }

    #[test]
    fn test_add_bootstrap_block_device() {
        let bootstrap = bootstrap_drive("1");

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(bootstrap.clone()).unwrap();

        assert!(!block_devs.has_root_device());
        assert_eq!(block_devs.devices.len(), 1);
        assert_eq!(block_devs.get_index_of_drive_id("1"), Some(0));

        let block = block_devs.devices[0].lock().unwrap();
        assert_eq!(block.id(), bootstrap.drive_id);
        assert_eq!(block.partuuid(), &bootstrap.partuuid);
        assert!(block.read_only());
    }

    #[test]
    fn test_add_one_root_block_device() {
        let root = root_drive("1");

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root.clone()).unwrap();

        assert!(block_devs.has_root_device());
        assert_eq!(block_devs.devices.len(), 1);
        let block = block_devs.devices[0].lock().unwrap();
        assert_eq!(block.id(), root.drive_id);
        assert_eq!(block.partuuid(), &root.partuuid);
        assert!(block.read_only());
    }

    #[test]
    fn test_add_two_root_block_devs() {
        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root_drive("1")).unwrap();
        assert_eq!(
            block_devs.insert(root_drive("2")).unwrap_err(),
            DriveError::RootBlockDeviceAlreadyAdded
        );
    }

    #[test]
    // The root device is first in the list whichever order the drives were added in.
    fn test_root_block_device_is_first() {
        for order in [
            [root_drive("1"), bootstrap_drive("2")],
            [bootstrap_drive("2"), root_drive("1")],
        ] {
            let mut block_devs = BlockBuilder::new();
            for config in order {
                block_devs.insert(config).unwrap();
            }

            assert_eq!(block_devs.devices.len(), 2);
            let mut block_iter = block_devs.devices.iter();
            assert_eq!(block_iter.next().unwrap().lock().unwrap().id(), "1");
            assert_eq!(block_iter.next().unwrap().lock().unwrap().id(), "2");
        }
    }

    #[test]
    fn test_update() {
        let mut bootstrap = bootstrap_drive("2");

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root_drive("1")).unwrap();
        block_devs.insert(bootstrap.clone()).unwrap();

        assert_eq!(block_devs.get_index_of_drive_id("1"), Some(0));
        assert!(block_devs.get_index_of_drive_id("foo").is_none());

        // Update OK.
        bootstrap.partuuid = Some("0eaa91a0-02".to_string());
        block_devs.insert(bootstrap.clone()).unwrap();

        let index = block_devs
            .get_index_of_drive_id(&bootstrap.drive_id)
            .unwrap();
        assert_eq!(
            block_devs.devices[index].lock().unwrap().partuuid(),
            &bootstrap.partuuid
        );
        assert!(block_devs.devices[index].lock().unwrap().read_only());

        // Update with 2 root block devices.
        let mut second_root = root_drive("2");
        second_root.partuuid = Some("0eaa91a0-01".to_string());
        assert_eq!(
            block_devs.insert(second_root),
            Err(DriveError::RootBlockDeviceAlreadyAdded)
        );

        // The descriptor pins the role, so the root drive cannot become a secondary one.
        let mut demoted_root = root_drive("1");
        demoted_root.is_root_device = false;
        assert_eq!(
            block_devs.insert(demoted_root),
            Err(DriveError::DescriptorRoleMismatch(ROOT_DESCRIPTOR_FILENO))
        );
    }

    #[test]
    fn test_block_config() {
        let mut root = root_drive("1");
        root.file_engine_type = Some(FileEngineType::Sync);

        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root.clone()).unwrap();

        let configs = block_devs.configs();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs.first().unwrap(), &root);
    }

    #[test]
    fn test_add_device() {
        let mut block_devs = BlockBuilder::new();
        let block = Block::new(bootstrap_drive("test_id")).unwrap();

        block_devs.add_virtio_device(Arc::new(Mutex::new(block)));
        assert_eq!(block_devs.devices.len(), 1);
        assert_eq!(
            block_devs.devices.pop_back().unwrap().lock().unwrap().id(),
            "test_id"
        );
    }

    #[test]
    fn test_descriptor_admission_matrix() {
        // The root image backs the root device, the bootstrap image a second drive that never is.
        assert_eq!(
            root_drive("root").descriptor().unwrap(),
            ROOT_DESCRIPTOR_FILENO
        );
        assert_eq!(
            bootstrap_drive("bootstrap").descriptor().unwrap(),
            BOOTSTRAP_DESCRIPTOR_FILENO
        );

        // Neither descriptor backs the other's role.
        let mut demoted_root = root_drive("root");
        demoted_root.is_root_device = false;
        assert_eq!(
            demoted_root.descriptor().unwrap_err(),
            DriveError::DescriptorRoleMismatch(ROOT_DESCRIPTOR_FILENO)
        );

        let mut promoted_bootstrap = bootstrap_drive("bootstrap");
        promoted_bootstrap.is_root_device = true;
        assert_eq!(
            promoted_bootstrap.descriptor().unwrap_err(),
            DriveError::DescriptorRoleMismatch(BOOTSTRAP_DESCRIPTOR_FILENO)
        );

        // No other number names a drive's backing store.
        for fd in [0, 3, 6, 9] {
            let mut unreserved = root_drive("root");
            unreserved.fd = fd;
            assert_eq!(
                unreserved.descriptor().unwrap_err(),
                DriveError::UnreservedDescriptor(fd)
            );
        }

        // An inherited image is neither writable nor flushable.
        let mut writable = root_drive("root");
        writable.is_read_only = Some(false);
        assert_eq!(
            writable.descriptor().unwrap_err(),
            DriveError::WritableDrive
        );

        let mut unspecified = root_drive("root");
        unspecified.is_read_only = None;
        assert_eq!(
            unspecified.descriptor().unwrap_err(),
            DriveError::WritableDrive
        );

        let mut writeback = root_drive("root");
        writeback.cache_type = CacheType::Writeback;
        assert_eq!(
            writeback.descriptor().unwrap_err(),
            DriveError::ReadOnlyWriteback
        );
    }

    #[test]
    fn test_uninherited_descriptor_is_refused() {
        in_child(|| {
            // A supervisor that passes no bootstrap descriptor leaves the number closed.
            // SAFETY: the descriptor belongs to this child alone.
            assert_eq!(unsafe { libc::close(BOOTSTRAP_DESCRIPTOR_FILENO) }, 0);
            assert_eq!(
                bootstrap_drive("bootstrap").descriptor().unwrap_err(),
                DriveError::DescriptorNotInherited(
                    BOOTSTRAP_DESCRIPTOR_FILENO,
                    io::Error::from_raw_os_error(libc::EBADF)
                )
            );

            // A writable descriptor never carries an admitted image.
            let writable_image = TempFile::new().unwrap();
            writable_image.as_file().set_len(0x1000).unwrap();
            // SAFETY: `dup2` rewrites this child's own descriptor table alone.
            let installed = unsafe {
                libc::dup2(
                    writable_image.as_file().as_raw_fd(),
                    BOOTSTRAP_DESCRIPTOR_FILENO,
                )
            };
            assert_eq!(installed, BOOTSTRAP_DESCRIPTOR_FILENO);
            assert_eq!(
                bootstrap_drive("bootstrap").descriptor().unwrap_err(),
                DriveError::WritableDescriptor(BOOTSTRAP_DESCRIPTOR_FILENO)
            );
        });
    }

    #[test]
    fn test_insert_descriptor_backed_drives() {
        let mut block_devs = BlockBuilder::new();
        block_devs.insert(root_drive("root")).unwrap();
        block_devs.insert(bootstrap_drive("bootstrap")).unwrap();

        assert!(block_devs.has_root_device());
        for device in &block_devs.devices {
            let block = device.lock().unwrap();
            assert!(block.read_only());
            assert_ne!(block.avail_features() & (1u64 << VIRTIO_BLK_F_RO), 0);
        }

        let configs = block_devs.configs();
        assert_eq!(configs[0].fd, ROOT_DESCRIPTOR_FILENO);
        assert!(configs[0].is_root_device);
        assert_eq!(configs[1].fd, BOOTSTRAP_DESCRIPTOR_FILENO);
        assert!(!configs[1].is_root_device);
    }
}
