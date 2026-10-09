// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::ops::Deref;
use std::os::fd::{BorrowedFd, RawFd};
use std::os::linux::fs::MetadataExt;
use std::sync::Arc;

use block_io::FileEngine;
use serde::{Deserialize, Serialize};
use vm_memory::ByteValued;
use vmm_sys_util::eventfd::EventFd;

use super::io::async_io;
use super::request::*;
use super::{BLOCK_QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE, VirtioBlockError, io as block_io};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::block::CacheType;
use crate::devices::virtio::block::virtio::metrics::{BlockDeviceMetrics, BlockMetricsPerDevice};
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_blk::{
    VIRTIO_BLK_F_FLUSH, VIRTIO_BLK_F_RO, VIRTIO_BLK_F_SEG_MAX, VIRTIO_BLK_F_SIZE_MAX,
    VIRTIO_BLK_ID_BYTES,
};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{IncMetric, error, warn};
use crate::rate_limiter::{BucketUpdate, RateLimiter};
use crate::utils::u64_to_usize;
use crate::vmm_config::RateLimiterConfig;
use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
use crate::vstate::memory::{Bytes, GuestMemoryMmap};

/// The engine file type, either Sync or Async (through io_uring).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum FileEngineType {
    /// Use an Async engine, based on io_uring.
    Async,
    /// Use a Sync engine, based on blocking system calls.
    #[default]
    Sync,
}

/// Helper object for setting up all `Block` fields derived from its backing file.
#[derive(Debug)]
pub struct DiskProperties {
    pub descriptor: RawFd,
    pub file_engine: FileEngine,
    pub nsectors: u64,
    pub image_id: [u8; VIRTIO_BLK_ID_BYTES as usize],
    /// The writes that reached the backing file while a capture records them.
    pub write_log: std::sync::Arc<super::write_log::WriteLog>,
}

impl DiskProperties {
    // The inherited descriptor outlives every device built from it, so a device owns a duplicate
    // of it instead of the descriptor itself.
    fn clone_descriptor(fd: RawFd) -> Result<File, VirtioBlockError> {
        if fd < 0 {
            return Err(VirtioBlockError::InvalidDescriptor(fd));
        }

        // SAFETY: the jailer inherits the descriptor to us and it stays open for the lifetime of
        // the process, so it is valid for the duration of this borrow.
        let inherited = unsafe { BorrowedFd::borrow_raw(fd) };
        inherited
            .try_clone_to_owned()
            .map(File::from)
            .map_err(|err| VirtioBlockError::CloneDescriptor(fd, err))
    }

    // Helper function that gets the size of the file
    fn file_size(fd: RawFd, disk_image: &mut File) -> Result<u64, VirtioBlockError> {
        let disk_size = disk_image
            .seek(SeekFrom::End(0))
            .map_err(|err| VirtioBlockError::BackingFile(err, fd))?;

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if disk_size % u64::from(SECTOR_SIZE) != 0 {
            warn!(
                "Disk size {} is not a multiple of sector size {}; the remainder will not be \
                 visible to the guest.",
                disk_size, SECTOR_SIZE
            );
        }

        Ok(disk_size)
    }

    /// Create a new file for the block device using a FileEngine
    pub fn new(fd: RawFd, file_engine_type: FileEngineType) -> Result<Self, VirtioBlockError> {
        let mut disk_image = Self::clone_descriptor(fd)?;
        let disk_size = Self::file_size(fd, &mut disk_image)?;
        if disk_size == 0 {
            return Err(VirtioBlockError::EmptyDescriptor(fd));
        }
        let image_id = Self::build_disk_image_id(&disk_image);

        Ok(Self {
            descriptor: fd,
            file_engine: FileEngine::from_file(disk_image, file_engine_type)
                .map_err(VirtioBlockError::FileEngine)?,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id,
            write_log: Default::default(),
        })
    }

    fn build_device_id(disk_file: &File) -> Result<String, VirtioBlockError> {
        let blk_metadata = disk_file
            .metadata()
            .map_err(VirtioBlockError::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> [u8; VIRTIO_BLK_ID_BYTES as usize] {
        let mut default_id = [0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(disk_id_string) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = disk_id_string.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].copy_from_slice(&disk_id[..bytes_to_copy]);
            }
        }
        default_id
    }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
#[repr(C)]
pub struct ConfigSpace {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
}

// SAFETY: `ConfigSpace` contains only PODs in `repr(C)` or `repr(transparent)`, without padding.
unsafe impl ByteValued for ConfigSpace {}

/// Use this structure to set up the Block Device before booting the kernel.
#[derive(Debug, PartialEq, Eq)]
pub struct VirtioBlockConfig {
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
    pub cache_type: CacheType,

    /// If set to true, the drive is opened in read-only mode. Otherwise, the
    /// drive is opened as read-write.
    pub is_read_only: bool,
    /// Descriptor the read-only image backing this drive was inherited at.
    pub fd: RawFd,
    /// Rate Limiter for I/O operations.
    pub rate_limiter: Option<RateLimiterConfig>,
    /// The type of IO engine used by the device.
    pub file_engine_type: FileEngineType,
}

impl TryFrom<&BlockDeviceConfig> for VirtioBlockConfig {
    type Error = DriveError;

    fn try_from(value: &BlockDeviceConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            drive_id: value.drive_id.clone(),
            partuuid: value.partuuid.clone(),
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,
            is_read_only: value.is_read_only.unwrap_or(false),
            fd: value.descriptor()?,
            rate_limiter: value.rate_limiter,
            file_engine_type: value.file_engine_type.unwrap_or_default(),
        })
    }
}

impl From<VirtioBlockConfig> for BlockDeviceConfig {
    fn from(value: VirtioBlockConfig) -> Self {
        Self {
            drive_id: value.drive_id,
            partuuid: value.partuuid,
            is_root_device: value.is_root_device,
            cache_type: value.cache_type,
            is_read_only: Some(value.is_read_only),
            fd: value.fd,
            rate_limiter: value.rate_limiter,
            file_engine_type: Some(value.file_engine_type),
        }
    }
}

/// Virtio device for exposing block level read/write operations on a host file.
#[derive(Debug)]
pub struct VirtioBlock {
    // Virtio fields.
    pub avail_features: u64,
    pub acked_features: u64,
    pub config_space: ConfigSpace,
    pub activate_evt: EventFd,

    // Transport related fields.
    pub queues: Vec<Queue>,
    pub queue_evts: [EventFd; 1],
    pub device_state: DeviceState,

    // Implementation specific fields.
    pub id: String,
    pub partuuid: Option<String>,
    pub cache_type: CacheType,
    pub root_device: bool,
    pub read_only: bool,

    // Host file and properties.
    pub disk: DiskProperties,
    pub rate_limiter: RateLimiter,
    pub is_io_engine_throttled: bool,
    pub metrics: Arc<BlockDeviceMetrics>,
}

macro_rules! unwrap_async_file_engine_or_return {
    ($file_engine: expr) => {
        match $file_engine {
            FileEngine::Async(engine) => engine,
            FileEngine::Sync(_) => {
                error!("The block device doesn't use an async IO engine");
                return;
            }
        }
    };
}

impl VirtioBlock {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    pub fn new(config: VirtioBlockConfig) -> Result<VirtioBlock, VirtioBlockError> {
        let disk_properties = DiskProperties::new(config.fd, config.file_engine_type)?;

        let rate_limiter = config
            .rate_limiter
            .map(RateLimiterConfig::try_into)
            .transpose()
            .map_err(VirtioBlockError::RateLimiter)?
            .unwrap_or_default();

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX)
            | (1u64 << VIRTIO_BLK_F_SIZE_MAX)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX);

        if config.cache_type == CacheType::Writeback {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if config.is_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let queue_evts = [EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?];

        let queues = BLOCK_QUEUE_SIZES.iter().map(|&s| Queue::new(s)).collect();

        let config_space = ConfigSpace {
            capacity: disk_properties.nsectors.to_le(),
            size_max: super::MAX_REQUEST_BYTES.to_le(),
            seg_max: 1u32.to_le(),
        };

        Ok(VirtioBlock {
            avail_features,
            acked_features: 0u64,
            config_space,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VirtioBlockError::EventFd)?,

            queues,
            queue_evts,
            device_state: DeviceState::Inactive,

            id: config.drive_id.clone(),
            partuuid: config.partuuid,
            cache_type: config.cache_type,
            root_device: config.is_root_device,
            read_only: config.is_read_only,

            disk: disk_properties,
            rate_limiter,
            is_io_engine_throttled: false,
            metrics: BlockMetricsPerDevice::alloc(config.drive_id),
        })
    }

    /// Returns a copy of a device config
    pub fn config(&self) -> VirtioBlockConfig {
        let rl: RateLimiterConfig = (&self.rate_limiter).into();
        VirtioBlockConfig {
            drive_id: self.id.clone(),
            fd: self.disk.descriptor,
            is_root_device: self.root_device,
            partuuid: self.partuuid.clone(),
            is_read_only: self.read_only,
            cache_type: self.cache_type,
            rate_limiter: rl.into_option(),
            file_engine_type: self.file_engine_type(),
        }
    }

    /// Process a single event in the Virtio queue.
    ///
    /// This function is called by the event manager when the guest notifies us
    /// about new buffers in the queue.
    pub(crate) fn process_queue_event(&mut self) {
        self.metrics.queue_event_count.inc();
        if let Err(err) = self.queue_evts[0].read() {
            error!("Failed to get queue event: {:?}", err);
            self.metrics.event_fails.inc();
        } else if self.rate_limiter.is_blocked() {
            self.metrics.rate_limiter_throttled_events.inc();
        } else if self.is_io_engine_throttled {
            self.metrics.io_engine_throttled_events.inc();
        } else {
            self.process_virtio_queues().unwrap()
        }
    }

    /// Process device virtio queue(s).
    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_queue(0)
    }

    pub(crate) fn process_rate_limiter_event(&mut self) {
        self.metrics.rate_limiter_event_count.inc();
        // Upon rate limiter event, call the rate limiter handler
        // and restart processing the queue.
        if self.rate_limiter.event_handler().is_ok() {
            self.process_queue(0).unwrap()
        }
    }

    /// Device specific function for peaking inside a queue and processing descriptors.
    pub fn process_queue(&mut self, queue_index: usize) -> Result<(), InvalidAvailIdx> {
        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();

        let queue = &mut self.queues[queue_index];
        let mut used_any = false;

        loop {
            // A close racing after this check may finish this iteration, but cannot keep
            // dispatch alive by refilling the queue. Still run the submission/used epilogue.
            if crate::vstate::farplane::dispatch::gate().is_closed() {
                // The handler consumed its eventfd before entering this loop. Preserve a host
                // wakeup for reopen, even when EVENT_IDX suppressed the guest's refill kick.
                // EAGAIN means the nonblocking counter is full: a wake is already pending.
                if let Err(err) = self.queue_evts[queue_index].write(1)
                    && err.raw_os_error() != Some(libc::EAGAIN)
                {
                    error!("Failed to defer block queue event: {:?}", err);
                    self.metrics.event_fails.inc();
                }
                break;
            }
            let Some(head) = queue.pop_or_enable_notification()? else {
                break;
            };
            #[cfg(test)]
            tests::AFTER_QUEUE_POP.with_borrow_mut(|hook| {
                if let Some(hook) = hook.take() {
                    hook();
                }
            });
            self.metrics.remaining_reqs_count.add(queue.len().into());
            let processing_result =
                match Request::parse(&head, &active_state.mem, self.disk.nsectors) {
                    Ok(request) => {
                        if request.rate_limit(&mut self.rate_limiter) {
                            // Stop processing the queue and return this descriptor chain to the
                            // avail ring, for later processing.
                            queue.undo_pop();
                            self.metrics.rate_limiter_throttled_events.inc();
                            break;
                        }

                        request.process(
                            &mut self.disk,
                            self.read_only,
                            head.index,
                            &active_state.mem,
                            &self.metrics,
                        )
                    }
                    Err(VirtioBlockError::PayloadTooLarge(status)) => {
                        // Refuse before touching the payload, but give a valid request an
                        // explicit EIO rather than completing with its stale status byte.
                        self.metrics.execute_fails.inc();
                        let written = active_state
                        .mem
                        .write_obj(
                            u8::try_from(
                                crate::devices::virtio::generated::virtio_blk::VIRTIO_BLK_S_IOERR,
                            )
                            .unwrap(),
                            status,
                        )
                        .is_ok();
                        ProcessingResult::Executed(FinishedRequest {
                            num_bytes_to_mem: u32::from(written),
                            desc_idx: head.index,
                        })
                    }
                    Err(err) => {
                        error!("Failed to parse available descriptor chain: {:?}", err);
                        self.metrics.execute_fails.inc();
                        ProcessingResult::Executed(FinishedRequest {
                            num_bytes_to_mem: 0,
                            desc_idx: head.index,
                        })
                    }
                };

            match processing_result {
                ProcessingResult::Submitted => {}
                ProcessingResult::Throttled => {
                    queue.undo_pop();
                    self.is_io_engine_throttled = true;
                    break;
                }
                ProcessingResult::Executed(finished) => {
                    used_any = true;
                    queue
                        .add_used(head.index, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                head.index, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if used_any && queue.prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }

        if let FileEngine::Async(ref mut engine) = self.disk.file_engine
            && let Err(err) = engine.kick_submission_queue()
        {
            error!("BlockError submitting pending block requests: {:?}", err);
        }

        if !used_any {
            self.metrics.no_avail_buffer.inc();
        }

        Ok(())
    }

    fn process_async_completion_queue(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        // This is safe since we checked in the event handler that the device is activated.
        let active_state = self.device_state.active_state().unwrap();
        let queue = &mut self.queues[0];

        loop {
            match engine.pop(&active_state.mem) {
                Err(error) => {
                    error!("Failed to read completed io_uring entry: {:?}", error);
                    break;
                }
                Ok(None) => break,
                Ok(Some(cqe)) => {
                    let res = cqe.result();
                    let user_data = cqe.user_data();

                    let (pending, res) = match res {
                        Ok(count) => (user_data, Ok(count)),
                        Err(error) => (
                            user_data,
                            Err(IoErr::FileEngine(block_io::BlockIoError::Async(
                                async_io::AsyncIoError::IO(error),
                            ))),
                        ),
                    };
                    let finished = pending.finish(&active_state.mem, res, &self.metrics);
                    queue
                        .add_used(finished.desc_idx, finished.num_bytes_to_mem)
                        .unwrap_or_else(|err| {
                            error!(
                                "Failed to add available descriptor head {}: {}",
                                finished.desc_idx, err
                            )
                        });
                }
            }
        }
        queue.advance_used_ring_idx();

        if queue.prepare_kick() {
            active_state
                .interrupt
                .trigger(VirtioInterruptType::Queue(0))
                .unwrap_or_else(|_| {
                    self.metrics.event_fails.inc();
                });
        }
    }

    pub fn process_async_completion_event(&mut self) {
        let engine = unwrap_async_file_engine_or_return!(&mut self.disk.file_engine);

        if let Err(err) = engine.completion_evt().read() {
            error!("Failed to get async completion event: {:?}", err);
        } else {
            self.process_async_completion_queue();

            if self.is_io_engine_throttled {
                self.is_io_engine_throttled = false;
                self.process_queue(0).unwrap()
            }
        }
    }

    /// Updates the parameters for the rate limiter
    pub fn update_rate_limiter(&mut self, bytes: BucketUpdate, ops: BucketUpdate) {
        self.rate_limiter.update_buckets(bytes, ops);
    }

    /// Retrieve the file engine type.
    pub fn file_engine_type(&self) -> FileEngineType {
        match self.disk.file_engine {
            FileEngine::Sync(_) => FileEngineType::Sync,
            FileEngine::Async(_) => FileEngineType::Async,
        }
    }

    /// Drains every in-flight request, so nothing this device started can still write guest
    /// memory or hold a guest page once it returns. Only a `Writeback` drive also syncs its
    /// backing store: an `Unsafe` drive promises the guest no durability, and a reflink clone
    /// writes back and waits for the source range itself, so a sync there buys nothing but a
    /// device cache flush inside the pause.
    pub fn drain_writes(&mut self) -> Result<(), VirtioBlockError> {
        if !self.is_activated() {
            return Ok(());
        }

        match self.cache_type {
            CacheType::Unsafe => self.disk.file_engine.drain(false),
            CacheType::Writeback => self.disk.file_engine.drain_and_flush(false),
        }
        .map_err(VirtioBlockError::FileEngine)?;
        if let FileEngine::Async(ref _engine) = self.disk.file_engine {
            self.process_async_completion_queue();
        }
        Ok(())
    }
}

impl VirtioDevice for VirtioBlock {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        &self.id
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_evts
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        if let Some(config_space_bytes) = self.config_space.as_slice().get(u64_to_usize(offset)..) {
            let len = config_space_bytes.len().min(data.len());
            data[..len].copy_from_slice(&config_space_bytes[..len]);
        } else {
            error!("Failed to read config space");
            self.metrics.cfg_fails.inc();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let config_space_bytes = self.config_space.as_mut_slice();
        let start = usize::try_from(offset).ok();
        let end = start.and_then(|s| s.checked_add(data.len()));
        let Some(dst) = start
            .zip(end)
            .and_then(|(start, end)| config_space_bytes.get_mut(start..end))
        else {
            error!("Failed to write config space");
            self.metrics.cfg_fails.inc();
            return;
        };

        dst.copy_from_slice(data);
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }

        let event_idx = self.has_feature(u64::from(VIRTIO_RING_F_EVENT_IDX));
        if event_idx {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            self.metrics.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }
}

impl Drop for VirtioBlock {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Unsafe => {
                if let Err(err) = self.disk.file_engine.drain(true) {
                    error!("Failed to drain ops on drop: {:?}", err);
                }
            }
            CacheType::Writeback => {
                if let Err(err) = self.disk.file_engine.drain_and_flush(true) {
                    error!(
                        "Failed to drain ops and flush block data on drop: {:?}",
                        err
                    );
                }
            }
        };
    }
}

#[cfg(test)]
#[cfg(target_arch = "x86_64")]
#[path = "budget_test.rs"]
mod budget_test;

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::thread;
    use std::time::Duration;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::check_metric_after_block;
    use crate::devices::virtio::block::virtio::IO_URING_NUM_ENTRIES;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, default_block_with_descriptor, read_blk_req_descriptors, set_queue,
        set_rate_limiter, simulate_async_completion_event,
        simulate_queue_and_async_completion_events, simulate_queue_event,
    };
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::rate_limiter::TokenType;
    use crate::vstate::memory::{Address, Bytes, GuestAddress};

    thread_local! {
        pub(super) static AFTER_QUEUE_POP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    #[test]
    fn guard_limits_real_queue_payload_and_returns_eio() {
        use crate::devices::virtio::block::persist::BlockConstructorArgs;
        use crate::snapshot::Persist;
        use crate::test_utils::single_region_mem;

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let cap = super::super::MAX_REQUEST_BYTES;
            let backing = TempFile::new().unwrap();
            backing.as_file().set_len(u64::from(cap + 512)).unwrap();
            let mut block =
                default_block_with_descriptor(backing.as_file().as_raw_fd(), false, engine);
            block.acked_features = (1 << VIRTIO_BLK_F_SIZE_MAX) | (1 << VIRTIO_BLK_F_SEG_MAX);
            let state = block.save();
            let mem = single_region_mem(3 * 1024 * 1024);
            let mut block = VirtioBlock::restore(
                BlockConstructorArgs {
                    mem: mem.clone(),
                    descriptor: backing.as_file().as_raw_fd(),
                },
                &state,
            )
            .unwrap();
            assert_eq!(
                block.save().virtio_state.acked_features,
                state.virtio_state.acked_features
            );
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), default_interrupt()).unwrap();
            for (iteration, len) in [cap, cap + 512].into_iter().enumerate() {
                vq.dtable[0].set(0x1000, 16, VIRTQ_DESC_F_NEXT, 1);
                vq.dtable[1].set(0x10000, len, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
                vq.dtable[2].set(0x2000, 1, VIRTQ_DESC_F_WRITE, 0);
                vq.avail.ring[iteration].set(0);
                vq.avail.idx.set(u16::try_from(iteration + 1).unwrap());
                mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_IN, 0), GuestAddress(0x1000))
                    .unwrap();
                mem.write_slice(&vec![0xa5; len as usize], GuestAddress(0x10000))
                    .unwrap();
                mem.write_obj(0xffu8, GuestAddress(0x2000)).unwrap();
                block.process_queue(0).unwrap();
                block.drain_writes().unwrap();
                let mut payload = vec![0; len as usize];
                mem.read_slice(&mut payload, GuestAddress(0x10000)).unwrap();
                let expected_status = if len == cap {
                    0
                } else {
                    u8::try_from(VIRTIO_BLK_S_IOERR).unwrap()
                };
                assert_eq!(
                    mem.read_obj::<u8>(GuestAddress(0x2000)).unwrap(),
                    expected_status
                );
                assert!(
                    payload
                        .iter()
                        .all(|byte| *byte == if len == cap { 0 } else { 0xa5 })
                );
                assert_eq!(vq.used.idx.get(), u16::try_from(iteration + 1).unwrap());
                assert_eq!(
                    vq.used.ring[iteration].get().len,
                    if len == cap { cap + 1 } else { 1 }
                );
            }
        }
    }

    // The gate is process-global: this portable test must run alone, not alongside other
    // block tests that deliberately invoke device methods without a dispatch hold.
    #[test]
    #[ignore = "process-global dispatch gate; run this exact test in isolation"]
    fn close_yields_real_block_handler_and_reopen_wakes_pending_work() {
        use std::sync::{Mutex, mpsc};

        use event_manager::SubscriberOps;

        use crate::vstate::farplane::dispatch;

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            for event_idx in [false, true] {
                let mem = default_mem();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                let mut block = default_block(engine);
                block.queues[0] = vq.create_queue();
                if event_idx {
                    block.acked_features |= 1 << VIRTIO_RING_F_EVENT_IDX;
                }
                block.activate(mem.clone(), default_interrupt()).unwrap();
                read_blk_req_descriptors(&vq);
                vq.dtable[3].set(0x4000, 16, VIRTQ_DESC_F_NEXT, 4);
                vq.dtable[4].set(0x5000, 512, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 5);
                vq.dtable[5].set(0x6000, 1, VIRTQ_DESC_F_WRITE, 0);
                vq.avail.ring[1].set(3);
                mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_IN, 0), GuestAddress(0x1000))
                    .unwrap();
                mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_IN, 0), GuestAddress(0x4000))
                    .unwrap();
                mem.write_obj(0xffu8, GuestAddress(0x3000)).unwrap();
                mem.write_obj(0xffu8, GuestAddress(0x6000)).unwrap();
                block.queue_evts[0].write(1).unwrap();
                let queue_event = block.queue_evts[0].try_clone().unwrap();
                let block = Arc::new(Mutex::new(block));
                let mut events = crate::EventManager::new().unwrap();
                events.add_subscriber(block.clone());

                let (close_tx, close_rx) = mpsc::channel();
                let closer = thread::spawn(move || {
                    close_rx.recv().unwrap();
                    dispatch::gate().close();
                });
                let publish_mem = mem.clone();
                let avail_idx = vq.avail.idx.location;
                AFTER_QUEUE_POP.with_borrow_mut(|hook| {
                    *hook = Some(Box::new(move || {
                        // The real event handler consumed the only queue event and popped the
                        // first head. Close while it is in flight, then simulate guest refill.
                        assert_eq!(
                            queue_event.read().unwrap_err().raw_os_error(),
                            Some(libc::EAGAIN)
                        );
                        close_tx.send(()).unwrap();
                        dispatch::gate().wait_for_closing(1);
                        publish_mem.write_obj(2u16, avail_idx).unwrap();
                        // No new eventfd write: EVENT_IDX may suppress this notification.
                    }));
                });
                assert_eq!(dispatch::dispatch_slice(&mut events).unwrap(), 1);
                closer.join().unwrap();
                assert!(dispatch::gate().is_closed());
                {
                    let mut block = block.lock().unwrap();
                    assert_eq!(
                        block.queues[0].next_avail.0, 1,
                        "second request admitted after close"
                    );
                    assert_eq!(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0xff);
                    if engine == FileEngineType::Async {
                        assert_eq!(vq.used.idx.get(), 0, "async completion still owed");
                        assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0xff);
                    }
                    block.drain_writes().unwrap();
                    assert_eq!(vq.used.idx.get(), 1);
                    assert_eq!(vq.used.ring[0].get().id, 0);
                    assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0);
                    assert_eq!(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0xff);
                }
                dispatch::gate().open();
                // No guest kick and no resume_vm kick: the yielding handler must retain a wakeup.
                assert!(dispatch::dispatch_slice(&mut events).unwrap() > 0);
                {
                    let mut block = block.lock().unwrap();
                    assert_eq!(
                        block.queues[0].next_avail.0, 2,
                        "pending work stranded after reopen"
                    );
                    block.drain_writes().unwrap();
                    assert_eq!(vq.used.idx.get(), 2);
                    assert_eq!(vq.used.ring[1].get().id, 3);
                    assert_eq!(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0);
                    if event_idx {
                        assert_eq!(vq.used.event.get(), 2, "normal empty-queue path must rearm");
                    }
                    // Publish a third request after the queue drained. With EVENT_IDX its
                    // advance crosses the rearmed avail_event, so the driver issues this kick.
                    vq.avail.ring[2].set(0);
                    vq.avail.idx.set(3);
                    mem.write_obj(0xffu8, GuestAddress(0x3000)).unwrap();
                    block.queue_evts[0].write(1).unwrap();
                }
                assert!(dispatch::dispatch_slice(&mut events).unwrap() > 0);
                block.lock().unwrap().drain_writes().unwrap();
                assert_eq!(vq.used.idx.get(), 3);
                assert_eq!(mem.read_obj::<u8>(GuestAddress(0x3000)).unwrap(), 0);
                if event_idx {
                    assert_eq!(vq.used.event.get(), 3);
                }
                // Exercise a failed self-kick too: saturating the eventfd makes write(1)
                // return EAGAIN, but must leave the existing wake readable after reopen.
                dispatch::gate().close();
                vq.avail.ring[3].set(3);
                vq.avail.idx.set(4);
                mem.write_obj(0xffu8, GuestAddress(0x6000)).unwrap();
                {
                    let mut block = block.lock().unwrap();
                    block.queue_evts[0].write(u64::MAX - 1).unwrap();
                    let errors = block.metrics.event_fails.count();
                    block.process_queue(0).unwrap();
                    assert_eq!(block.metrics.event_fails.count(), errors);
                    assert_eq!(block.queues[0].next_avail.0, 3);
                    assert_eq!(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0xff);
                }
                dispatch::gate().open();
                assert!(dispatch::dispatch_slice(&mut events).unwrap() > 0);
                block.lock().unwrap().drain_writes().unwrap();
                assert_eq!(vq.used.idx.get(), 4);
                assert_eq!(mem.read_obj::<u8>(GuestAddress(0x6000)).unwrap(), 0);
                println!(
                    "CLOSE_YIELD_PASS engine={engine:?} event_idx={event_idx} admitted_at_close=1 drained=1 reopened=2 rearmed=3 saturated_wake=4"
                );
            }
        }
    }

    #[test]
    fn test_from_config() {
        // The conversion resolves the descriptor, so a number the jailer never reserves for an
        // inherited image cannot reach a device.
        let unreserved = BlockDeviceConfig {
            drive_id: "root".to_string(),
            is_root_device: true,
            is_read_only: Some(true),
            fd: 9,
            ..Default::default()
        };
        assert!(matches!(
            VirtioBlockConfig::try_from(&unreserved),
            Err(DriveError::UnreservedDescriptor(9))
        ));
    }

    #[test]
    fn test_disk_backing_descriptor() {
        let num_sectors = 2;
        let f = TempFile::new().unwrap();
        f.as_file()
            .set_len(u64::from(SECTOR_SIZE) * num_sectors)
            .unwrap();
        let fd = f.as_file().as_raw_fd();

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let disk_properties = DiskProperties::new(fd, engine).unwrap();
            assert_eq!(disk_properties.nsectors, num_sectors);

            // The device owns a duplicate, so the inherited descriptor outlives it.
            drop(disk_properties);
            assert_eq!(f.as_file().metadata().unwrap().len(), 1024);

            let empty = TempFile::new().unwrap();
            assert!(matches!(
                DiskProperties::new(empty.as_file().as_raw_fd(), engine),
                Err(VirtioBlockError::EmptyDescriptor(_))
            ));

            assert!(matches!(
                DiskProperties::new(-1, engine),
                Err(VirtioBlockError::InvalidDescriptor(-1))
            ));
        }
    }

    #[test]
    fn test_descriptor_backed_device_access_mode() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();

        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            for is_root_device in [true, false] {
                let block =
                    default_block_with_descriptor(f.as_file().as_raw_fd(), is_root_device, engine);

                // Only the root image is read-only, and only it advertises the feature.
                assert_eq!(block.root_device, is_root_device);
                assert_eq!(block.read_only, is_root_device);
                assert_eq!(
                    block.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0,
                    is_root_device
                );
                assert_eq!(block.avail_features & (1u64 << VIRTIO_BLK_F_FLUSH), 0);
                assert_eq!(block.config_space.capacity, 0x1000 >> SECTOR_SHIFT);
            }
        }
    }

    #[test]
    fn test_root_image_backed_device_rejects_writes() {
        let f = TempFile::new().unwrap();
        f.as_file().set_len(0x1000).unwrap();
        f.as_file().write_all(&[0x11; 0x1000]).unwrap();

        // The root image is read-only, so the device fails every write and flush request.
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block_with_descriptor(f.as_file().as_raw_fd(), true, engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());
            mem.write_slice(&[0x22; 0x1000], data_addr).unwrap();

            for request_type in [VIRTIO_BLK_T_OUT, VIRTIO_BLK_T_FLUSH] {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());
                vq.avail.idx.set(1);
                // The data of a write request is read by the device.
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
                mem.write_obj::<RequestHeader>(
                    RequestHeader::new(request_type, 0),
                    request_type_addr,
                )
                .unwrap();

                simulate_queue_event(&mut block, Some(true));

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }

        let mut content = [0u8; 0x1000];
        let mut file = f.as_file();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_exact(&mut content).unwrap();
        assert_eq!(content, [0x11; 0x1000]);
    }

    #[test]
    fn test_virtio_features() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            assert_eq!(block.device_type(), VirtioDeviceType::Block);

            let features: u64 = (1u64 << VIRTIO_F_VERSION_1)
                | (1u64 << VIRTIO_RING_F_EVENT_IDX)
                | (1u64 << VIRTIO_BLK_F_SIZE_MAX)
                | (1u64 << VIRTIO_BLK_F_SEG_MAX);

            assert_eq!(
                block.avail_features_by_page(0),
                (features & 0xffffffff) as u32,
            );
            assert_eq!(block.avail_features_by_page(1), (features >> 32) as u32);

            for i in 2..10 {
                assert_eq!(block.avail_features_by_page(i), 0u32);
            }

            for i in 0..10 {
                block.ack_features_by_page(i, u32::MAX);
            }
            assert_eq!(block.acked_features, features);
        }
    }

    #[test]
    fn test_virtio_read_config() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let block = default_block(engine);

            let mut actual_config_space = ConfigSpace::default();
            block.read_config(0, actual_config_space.as_mut_slice());
            // This will read the number of sectors.
            // The block's backing file size is 0x1000, so there are 8 (4096/512) sectors.
            // The config space is little endian.
            let expected_config_space = ConfigSpace {
                capacity: 8,
                size_max: super::super::MAX_REQUEST_BYTES.to_le(),
                seg_max: 1u32.to_le(),
            };
            assert_eq!(actual_config_space, expected_config_space);

            // Invalid read.
            let expected_config_space = ConfigSpace {
                capacity: 696969,
                ..Default::default()
            };
            actual_config_space = expected_config_space;
            block.read_config(
                std::mem::size_of::<ConfigSpace>() as u64 + 1,
                actual_config_space.as_mut_slice(),
            );

            // Validate read failed (the config space was not updated).
            assert_eq!(actual_config_space, expected_config_space);
        }
    }

    #[test]
    fn test_virtio_write_config() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let expected_config_space = ConfigSpace {
                capacity: 696969,
                ..Default::default()
            };
            block.write_config(0, expected_config_space.as_slice());

            let mut actual_config_space = ConfigSpace::default();
            block.read_config(0, actual_config_space.as_mut_slice());
            assert_eq!(actual_config_space, expected_config_space);

            // If privileged user writes to `/dev/mem`, in block config space - byte by byte.
            let expected_config_space = ConfigSpace {
                capacity: 0x1122334455667788,
                ..Default::default()
            };
            let expected_config_space_slice = expected_config_space.as_slice();
            for (i, b) in expected_config_space_slice.iter().enumerate() {
                block.write_config(i as u64, &[*b]);
            }
            block.read_config(0, actual_config_space.as_mut_slice());
            assert_eq!(actual_config_space, expected_config_space);

            // Invalid write.
            let new_config_space = ConfigSpace {
                capacity: 0xDEADBEEF,
                ..Default::default()
            };
            block.write_config(5, new_config_space.as_slice());
            // Make sure nothing got written.
            block.read_config(0, actual_config_space.as_mut_slice());
            assert_eq!(actual_config_space, expected_config_space);

            // Large offset that may cause an overflow.
            block.write_config(u64::MAX, new_config_space.as_slice());
            // Make sure nothing got written.
            block.read_config(0, actual_config_space.as_mut_slice());
            assert_eq!(actual_config_space, expected_config_space);
        }
    }

    #[test]
    fn test_invalid_request() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            // Request is invalid because the first descriptor is write-only.
            vq.dtable[0]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 0);
        }
    }

    #[test]
    fn test_addr_out_of_bounds() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            // Default mem size is 0x10000
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);
            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            // Read at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }

            // Write at out of bounds address.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);

                vq.dtable[1].set(0x20000, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);

                let used = vq.used.ring[0].get();
                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(used.len, 1);
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_request_parse_failures() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

            {
                // First descriptor no longer writable.
                vq.dtable[0].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);

                // Generate a seek execute error caused by a very large sector number.
                let request_header = RequestHeader::new(VIRTIO_BLK_T_OUT, 0x000f_ffff_ffff);
                mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }

            {
                // Reset the queue to reuse descriptors and memory.
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                // Set sector to a valid number large enough that the full 0x1000 read will fail.
                let request_header = RequestHeader::new(VIRTIO_BLK_T_IN, 10);
                mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }
        }
    }

    #[test]
    fn test_unsupported_request_type() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Currently only VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT,
            // VIRTIO_BLK_T_FLUSH and VIRTIO_BLK_T_GET_ID  are supported.
            // Generate an unsupported request.
            let request_header = RequestHeader::new(42, 0);
            mem.write_obj::<RequestHeader>(request_header, request_type_addr)
                .unwrap();

            simulate_queue_event(&mut block, Some(true));

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(vq.used.ring[0].get().len, 1);
            assert_eq!(
                mem.read_obj::<u32>(status_addr).unwrap(),
                VIRTIO_BLK_S_UNSUPP
            );
        }
    }

    #[test]
    fn test_end_of_region() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);
            vq.dtable[1].set(0xf000, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            vq.used.idx.set(0);

            mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                .unwrap();
            vq.dtable[1]
                .flags
                .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

            check_metric_after_block!(
                &block.metrics.read_count,
                1,
                simulate_queue_and_async_completion_events(&mut block, true)
            );

            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            // Added status byte length.
            assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
            assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
        }
    }

    #[test]
    fn test_read_write() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            let empty_data = vec![0; 512];
            let rand_data = vmm_sys_util::rand::rand_alphanumerics(1024)
                .as_bytes()
                .to_vec();

            // Write with invalid data len (not a multiple of 512).
            {
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();
                // Make data read only, 512 bytes in len, and set the actual value to be written.
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].len.set(511);
                mem.write_slice(&rand_data[..511], data_addr).unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that the data wasn't written to the file
                let mut buf = [0u8; 512];
                block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(0))
                    .unwrap();
                block.disk.file_engine.file().read_exact(&mut buf).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Write from valid address, with an overflowing length.
            {
                let mut block = default_block(engine);

                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
                read_blk_req_descriptors(&vq);
                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT, 2);
                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }

            // Write.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                    .unwrap();
                // Make data read only, 512 bytes in len, and set the actual value to be written.
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
                vq.dtable[1].len.set(512);
                mem.write_slice(&rand_data[..512], data_addr).unwrap();

                check_metric_after_block!(
                    &block.metrics.write_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }

            // Read with invalid data len (not a multiple of 512).
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(511);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // The descriptor should have been discarded.
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that no data was read.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Read.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(512);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                check_metric_after_block!(
                    &block.metrics.read_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // Added status byte length.
                assert_eq!(vq.used.ring[0].get().len, vq.dtable[1].len.get() + 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

                // Check that the data is the same that we wrote before
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, &rand_data[..512]);
            }

            // Read with error.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                mem.write_slice(empty_data.as_slice(), data_addr).unwrap();

                let size = block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
                mem.write_obj(10, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // The descriptor should have been discarded.
                assert_eq!(vq.used.ring[0].get().len, 0);

                // Check that no data was read.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            // Partial buffer error on read.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

                let size = block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::End(0))
                    .unwrap();
                block.disk.file_engine.file().set_len(size / 2).unwrap();
                // Update sector number: stored at `request_type_addr.0 + 8`
                mem.write_obj(5, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                // This will attempt to read past end of file.
                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);

                // No data since can't read past end of file, only status byte length.
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(
                    mem.read_obj::<u32>(status_addr).unwrap(),
                    VIRTIO_BLK_S_IOERR
                );

                // Check that no data was read since we can't read past the end of the file.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, empty_data.as_slice());
            }

            {
                // Note: this test case only works because when we truncated the file above (with
                // set_len), we did not update the sector count stored in the block device
                // itself (is still 8, even though the file length is 1024 now, e.g. has 2 sectors).
                // Normally, requests that reach past the final sector are rejected by
                // Request::parse.
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);
                vq.dtable[1].len.set(1024);

                mem.write_obj(1, GuestAddress(request_type_addr.0 + 8))
                    .unwrap();

                block
                    .disk
                    .file_engine
                    .file()
                    .seek(SeekFrom::Start(512))
                    .unwrap();
                block
                    .disk
                    .file_engine
                    .file()
                    .write_all(&rand_data[512..])
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);

                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);

                assert_eq!(
                    mem.read_obj::<u32>(status_addr).unwrap(),
                    VIRTIO_BLK_S_IOERR
                );

                // Check that we correctly read the second file sector.
                let mut buf = [0u8; 512];
                mem.read_slice(&mut buf, data_addr).unwrap();
                assert_eq!(buf, rand_data[512..]);
            }

            // Read at valid address, with an overflowing length.
            {
                // Default mem size is 0x10000
                let mem = default_mem();
                let interrupt = default_interrupt();
                let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
                set_queue(&mut block, 0, vq.create_queue());
                block.activate(mem.clone(), interrupt).unwrap();
                read_blk_req_descriptors(&vq);
                vq.dtable[1].set(0xff00, 0x1000, VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE, 2);

                let request_type_addr = GuestAddress(vq.dtable[0].addr.get());

                // Mark the next available descriptor.
                vq.avail.idx.set(1);
                vq.used.idx.set(0);

                mem.write_obj::<u32>(VIRTIO_BLK_T_IN, request_type_addr)
                    .unwrap();
                vq.dtable[1]
                    .flags
                    .set(VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE);

                check_metric_after_block!(
                    &block.metrics.invalid_reqs_count,
                    1,
                    simulate_queue_and_async_completion_events(&mut block, true)
                );

                let used_idx = vq.used.idx.get();
                assert_eq!(used_idx, 1);

                let status_addr = GuestAddress(vq.dtable[2].addr.get());
                assert_eq!(
                    u32::from(mem.read_obj::<u8>(status_addr).unwrap()),
                    VIRTIO_BLK_S_IOERR
                );
            }
        }
    }

    #[test]
    fn test_flush() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Flush completes successfully without a data descriptor.
            {
                vq.dtable[0].next.set(2);

                mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }

            // Flush completes successfully even with a data descriptor.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());
                vq.dtable[0].next.set(1);

                mem.write_obj::<u32>(VIRTIO_BLK_T_FLUSH, request_type_addr)
                    .unwrap();

                simulate_queue_and_async_completion_events(&mut block, true);
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                // status byte length.
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }

    #[test]
    fn test_get_device_id() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());
            let blk_metadata = block.disk.file_engine.file().metadata();

            // Test that the driver receives the correct device id.
            {
                vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES);

                mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 21);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

                let blk_meta = blk_metadata.unwrap();
                let expected_device_id = format!(
                    "{}{}{}",
                    blk_meta.st_dev(),
                    blk_meta.st_rdev(),
                    blk_meta.st_ino()
                );

                let mut buf = [0; VIRTIO_BLK_ID_BYTES as usize];
                mem.read_slice(&mut buf, data_addr).unwrap();
                let chars_to_trim: &[char] = &['\u{0}'];
                let received_device_id = String::from_utf8(buf.to_ascii_lowercase())
                    .unwrap()
                    .trim_matches(chars_to_trim)
                    .to_string();
                assert_eq!(received_device_id, expected_device_id);
            }

            // Test that a device ID request will be discarded, if it fails to provide enough buffer
            // space.
            {
                vq.used.idx.set(0);
                set_queue(&mut block, 0, vq.create_queue());
                vq.dtable[1].len.set(VIRTIO_BLK_ID_BYTES - 1);

                mem.write_obj::<u32>(VIRTIO_BLK_T_GET_ID, request_type_addr)
                    .unwrap();

                simulate_queue_event(&mut block, Some(true));
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 0);
            }
        }
    }

    fn add_flush_requests_batch(block: &mut VirtioBlock, vq: &VirtQueue, count: u16) {
        let mem = vq.memory();
        vq.avail.idx.set(0);
        vq.used.idx.set(0);
        set_queue(block, 0, vq.create_queue());

        let hdr_addr = vq
            .end()
            .checked_align_up(std::mem::align_of::<RequestHeader>() as u64)
            .unwrap();
        // Write request header. All requests will use the same header.
        mem.write_obj(RequestHeader::new(VIRTIO_BLK_T_FLUSH, 0), hdr_addr)
            .unwrap();

        let mut status_addr = hdr_addr
            .checked_add(std::mem::size_of::<RequestHeader>() as u64)
            .unwrap()
            .checked_align_up(4)
            .unwrap();

        for i in 0..count {
            let idx = i * 2;

            let hdr_desc = &vq.dtable[idx as usize];
            hdr_desc.addr.set(hdr_addr.0);
            hdr_desc.flags.set(VIRTQ_DESC_F_NEXT);
            hdr_desc.next.set(idx + 1);

            let status_desc = &vq.dtable[idx as usize + 1];
            status_desc.addr.set(status_addr.0);
            status_desc.flags.set(VIRTQ_DESC_F_WRITE);
            status_desc.len.set(4);
            status_addr = status_addr.checked_add(4).unwrap();

            vq.avail.ring[i as usize].set(idx);
            vq.avail.idx.set(i + 1);
        }
    }

    fn check_flush_requests_batch(count: u16, vq: &VirtQueue) {
        let used_idx = vq.used.idx.get();
        assert_eq!(used_idx, count);

        for i in 0..count {
            let used = vq.used.ring[i as usize].get();
            let status_addr = vq.dtable[used.id as usize + 1].addr.get();
            assert_eq!(used.len, 1);
            assert_eq!(
                u32::from(
                    vq.memory()
                        .read_obj::<u8>(GuestAddress(status_addr))
                        .unwrap(),
                ),
                VIRTIO_BLK_S_OK
            );
        }
    }

    #[test]
    fn test_io_engine_throttling() {
        // Device admission is bounded independently of the larger SQ/CQ capacities.
        let cap = u16::try_from(super::super::MAX_INFLIGHT_REQUESTS).unwrap();
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Exactly the fixed admission cap fits.
            add_flush_requests_batch(&mut block, &vq, cap);
            simulate_queue_event(&mut block, Some(false));
            assert!(!block.is_io_engine_throttled);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(cap, &vq);

            // Further guest refill must wait for completed requests to be consumed.
            add_flush_requests_batch(&mut block, &vq, cap + 10);
            simulate_queue_event(&mut block, Some(false));
            assert!(block.is_io_engine_throttled);
            // When the async_completion_event is triggered:
            // 1. cap requests should be completed.
            // 2. is_io_engine_throttled should be set back to false.
            // 3. process_queue() should be called again.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(cap, &vq);
            // check that process_queue() was called again resulting in the processing of the
            // remaining 10 ops.
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(cap + 10, &vq);
        }

        // Completion in the kernel alone does not free device admission capacity.
        {
            let mut block = default_block(FileEngineType::Async);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, IO_URING_NUM_ENTRIES * 4);
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            add_flush_requests_batch(&mut block, &vq, cap + 1);
            simulate_queue_event(&mut block, Some(false));
            let FileEngine::Async(engine) = &mut block.disk.file_engine else {
                unreachable!()
            };
            engine.drain(false).unwrap();
            block.process_queue(0).unwrap();
            assert!(block.is_io_engine_throttled);
            assert_eq!(block.queues[0].next_avail.0, cap);
            assert_eq!(vq.used.idx.get(), 0);
            simulate_async_completion_event(&mut block, true);
            assert!(!block.is_io_engine_throttled);
            check_flush_requests_batch(cap, &vq);
            simulate_async_completion_event(&mut block, true);
            check_flush_requests_batch(cap + 1, &vq);
        }
    }

    #[test]
    fn test_drain_writes() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);

            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            block.queues[0] = vq.create_queue();
            block.activate(mem.clone(), interrupt).unwrap();

            // Add a batch of flush requests.
            add_flush_requests_batch(&mut block, &vq, 5);
            simulate_queue_event(&mut block, None);
            block.drain_writes().unwrap();

            // Check that all the pending flush requests were processed during the drain.
            check_flush_requests_batch(5, &vq);
        }
    }

    /// Real READ/WRITE, drain, device serialization and destruction for the proposed single-op
    /// experiment. This does NOT enroll a budget, fork-shared memory or a VM; passing is only
    /// baseline characterization, not isolated-reserve, quiescence or full-capture evidence.
    #[test]
    fn memory_budget_baseline_single_direct_request_drain_save_drop() {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        use crate::snapshot::Persist;
        use crate::test_utils::single_region_mem;

        const LEN: u32 = 65536;
        let disk_bytes = vec![0x35; LEN as usize];
        let guest_bytes = vec![0xa6; LEN as usize];
        for request_type in [VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT] {
            let image = TempFile::new().unwrap();
            image.as_file().write_all(&disk_bytes).unwrap();
            image.as_file().sync_all().unwrap();
            let direct = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_DIRECT)
                .open(image.as_path())
                .unwrap();
            let mut block =
                default_block_with_descriptor(direct.as_raw_fd(), false, FileEngineType::Async);
            let FileEngine::Async(engine) = &mut block.disk.file_engine else {
                unreachable!()
            };
            engine.force_async_for_test();
            let mem = single_region_mem(0x30000);
            let vq = VirtQueue::new(GuestAddress(0x1000), &mem, 256);
            block.queues[0] = vq.create_queue();
            block.acked_features |= 1 << VIRTIO_RING_F_EVENT_IDX;
            block.activate(mem.clone(), default_interrupt()).unwrap();
            read_blk_req_descriptors(&vq);
            // Header crosses two pages; sector-aligned payload crosses 17 pages.
            let header = GuestAddress(0x4ff8);
            let payload = GuestAddress(0x8200);
            let status = GuestAddress(0x7000);
            vq.dtable[0].addr.set(header.0);
            vq.dtable[1].addr.set(payload.0);
            vq.dtable[1].len.set(LEN);
            if request_type == VIRTIO_BLK_T_OUT {
                vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            }
            vq.dtable[2].addr.set(status.0);
            mem.write_obj(RequestHeader::new(request_type, 0), header)
                .unwrap();
            mem.write_obj(0xffu8, status).unwrap();
            mem.write_slice(&guest_bytes, payload).unwrap();

            block.process_queue(0).unwrap();
            // Async completion has not been published into the guest yet.
            assert_eq!(vq.used.idx.get(), 0);
            assert_eq!(mem.read_obj::<u8>(status).unwrap(), 0xff);
            assert_eq!(vq.used.event.get(), 1);
            // Mutating descriptors after submission cannot enlarge the cached request.
            vq.dtable[1].len.set(2 * LEN);
            block.drain_writes().unwrap();
            assert_eq!(mem.read_obj::<u8>(status).unwrap(), 0);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(vq.used.ring[0].get().id, 0);
            assert_eq!(
                vq.used.ring[0].get().len,
                if request_type == VIRTIO_BLK_T_IN {
                    LEN + 1
                } else {
                    1
                }
            );
            let mut actual = vec![0; LEN as usize];
            mem.read_slice(&mut actual, payload).unwrap();
            assert_eq!(
                actual,
                if request_type == VIRTIO_BLK_T_IN {
                    &disk_bytes
                } else {
                    &guest_bytes
                }
                .as_slice()
            );
            let saved = block.save();
            assert_eq!(
                serde_json::to_value(&saved.virtio_state.queues[0]).unwrap()["next_used"],
                1
            );
            assert!(!bitcode::serialize(&saved).unwrap().is_empty());
            // A repeated empty drain still visits ring state but must not republish a CQE.
            block.drain_writes().unwrap();
            assert_eq!(vq.used.idx.get(), 1);
            let FileEngine::Async(engine) = &block.disk.file_engine else {
                unreachable!()
            };
            engine.run_task_work_for_test().unwrap();
            drop(block);
            let mut file = image.as_file();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.read_exact(&mut actual).unwrap();
            assert_eq!(
                actual,
                if request_type == VIRTIO_BLK_T_IN {
                    &disk_bytes
                } else {
                    &guest_bytes
                }
                .as_slice()
            );
            assert_eq!(file.metadata().unwrap().len(), u64::from(LEN));
        }
    }

    #[test]
    fn test_bandwidth_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create bandwidth rate limiter that allows only 5120 bytes/s with bucket size of 8
            // bytes.
            let mut rl = RateLimiter::new(512, 0, 100, 0, 0, 0).unwrap();
            // Use up the budget.
            assert!(rl.consume(512, TokenType::Bytes));

            set_rate_limiter(&mut block, rl);

            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Following write procedure should fail because of bandwidth rate limiting.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.rate_limiter.is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Wait for 100ms to give the rate-limiter timer a chance to replenish.
            // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
            thread::sleep(Duration::from_millis(150));

            // Following write procedure should succeed because bandwidth should now be available.
            {
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    0,
                    block.process_rate_limiter_event()
                );
                // Validate the rate_limiter is no longer blocked.
                assert!(!block.rate_limiter.is_blocked());
                // Complete async IO ops if needed
                simulate_async_completion_event(&mut block, true);

                // Make sure the data queue advanced.
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }

    #[test]
    fn test_ops_rate_limiter() {
        for engine in [FileEngineType::Sync, FileEngineType::Async] {
            let mut block = default_block(engine);
            let mem = default_mem();
            let interrupt = default_interrupt();
            let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
            set_queue(&mut block, 0, vq.create_queue());
            block.activate(mem.clone(), interrupt).unwrap();
            read_blk_req_descriptors(&vq);

            let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
            let data_addr = GuestAddress(vq.dtable[1].addr.get());
            let status_addr = GuestAddress(vq.dtable[2].addr.get());

            // Create ops rate limiter that allows only 10 ops/s with bucket size of 1 ops.
            let mut rl = RateLimiter::new(0, 0, 0, 1, 0, 100).unwrap();
            // Use up the budget.
            assert!(rl.consume(1, TokenType::Ops));

            set_rate_limiter(&mut block, rl);

            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Following write procedure should fail because of ops rate limiting.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.rate_limiter.is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Do a second write that still fails but this time on the fast path.
            {
                // Trigger the attempt to write.
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    1,
                    simulate_queue_event(&mut block, Some(false))
                );

                // Assert that limiter is blocked.
                assert!(block.rate_limiter.is_blocked());
                // Make sure the data is still queued for processing.
                assert_eq!(vq.used.idx.get(), 0);
            }

            // Wait for 100ms to give the rate-limiter timer a chance to replenish.
            // Wait for an extra 50ms to make sure the timerfd event makes its way from the kernel.
            thread::sleep(Duration::from_millis(150));

            // Following write procedure should succeed because ops budget should now be available.
            {
                check_metric_after_block!(
                    &block.metrics.rate_limiter_throttled_events,
                    0,
                    block.process_rate_limiter_event()
                );
                // Validate the rate_limiter is no longer blocked.
                assert!(!block.rate_limiter.is_blocked());
                // Complete async IO ops if needed
                simulate_async_completion_event(&mut block, true);

                // Make sure the data queue advanced.
                assert_eq!(vq.used.idx.get(), 1);
                assert_eq!(vq.used.ring[0].get().id, 0);
                assert_eq!(vq.used.ring[0].get().len, 1);
                assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
            }
        }
    }
}
