// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::fd::RawFd;

use serde::{Deserialize, Serialize};

use self::virtio::VirtioBlockError;

pub mod device;
pub mod persist;
pub mod virtio;

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum CacheType {
    /// Flushing mechanic not will be advertised to the guest driver
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

/// Number the jailer inherits the sealed read-only root image at. It renumbers the memfd to this
/// descriptor on every launch, so it is where a restored root drive finds its backing store.
pub const ROOT_DESCRIPTOR_FILENO: RawFd = 4;

/// Errors the block device can trigger.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BlockError {
    /// Virtio backend error: {0}
    VirtioBackend(VirtioBlockError),
}
