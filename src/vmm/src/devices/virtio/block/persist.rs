// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::fd::RawFd;

use serde::{Deserialize, Serialize};

use super::virtio::persist::VirtioBlockState;
use super::{BOOTSTRAP_DESCRIPTOR_FILENO, ROOT_DESCRIPTOR_FILENO};
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
    /// Arguments for restoring a drive, backed by the descriptor the jailer inherited its image
    /// at: the root drive at [`ROOT_DESCRIPTOR_FILENO`], every other drive at
    /// [`BOOTSTRAP_DESCRIPTOR_FILENO`]. A snapshot never records a path or a descriptor number.
    pub fn inherited(mem: GuestMemoryMmap, state: &BlockState) -> Self {
        let descriptor = match state {
            BlockState::Virtio(state) if state.root_device() => ROOT_DESCRIPTOR_FILENO,
            BlockState::Virtio(_) => BOOTSTRAP_DESCRIPTOR_FILENO,
        };
        Self { mem, descriptor }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::block::virtio::test_utils::default_block_with_descriptor;
    use crate::devices::virtio::test_utils::default_mem;
    use crate::snapshot::Persist;

    #[test]
    fn test_restore_resolves_inherited_descriptor() {
        let image = TempFile::new().unwrap();
        image.as_file().set_len(0x1000).unwrap();

        for (is_root_device, expected) in [
            (true, ROOT_DESCRIPTOR_FILENO),
            (false, BOOTSTRAP_DESCRIPTOR_FILENO),
        ] {
            let block = default_block_with_descriptor(
                image.as_file().as_raw_fd(),
                is_root_device,
                FileEngineType::Sync,
            );
            let state = BlockState::Virtio(block.save());

            let args = BlockConstructorArgs::inherited(default_mem(), &state);
            assert_eq!(args.descriptor, expected);
        }
    }
}
