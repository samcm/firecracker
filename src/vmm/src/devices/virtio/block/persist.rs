// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;

use serde::{Deserialize, Serialize};

use super::ROOT_DESCRIPTOR_FILENO;
use super::virtio::persist::VirtioBlockState;
use crate::vstate::memory::GuestMemoryMmap;

/// Block device state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockState {
    Virtio(VirtioBlockState),
}

impl BlockState {
    pub fn is_activated(&self) -> bool {
        match self {
            BlockState::Virtio(virtio_block_state) => virtio_block_state.virtio_state.activated,
        }
    }
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct BlockConstructorArgs {
    pub mem: GuestMemoryMmap,
    pub descriptor: RawFd,
}

impl BlockConstructorArgs {
    /// Arguments for restoring the root drive, which is backed by the descriptor the jailer
    /// inherited the sealed root image at.
    pub fn root(mem: GuestMemoryMmap) -> Self {
        Self {
            mem,
            descriptor: ROOT_DESCRIPTOR_FILENO,
        }
    }
}
