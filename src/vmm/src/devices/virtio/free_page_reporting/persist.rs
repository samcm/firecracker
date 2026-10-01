// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Saving and restoring the free page reporting device.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::{FreePageReporting, FreePageReportingError, NUM_QUEUES};
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreePageReportingState {
    pub virtio_state: VirtioDeviceState,
    actual_pages: u32,
}

#[derive(Debug)]
pub struct FreePageReportingConstructorArgs {
    pub mem: GuestMemoryMmap,
    pub vm: Arc<KvmVm>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FreePageReportingPersistError {
    /// Create the free page reporting device: {0}
    Create(#[from] FreePageReportingError),
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
}

impl Persist<'_> for FreePageReporting {
    type State = FreePageReportingState;
    type ConstructorArgs = FreePageReportingConstructorArgs;
    type Error = FreePageReportingPersistError;

    fn save(&self) -> Self::State {
        FreePageReportingState {
            virtio_state: VirtioDeviceState::from_device(self),
            actual_pages: self.actual_pages(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let queues = state.virtio_state.build_queues_checked(
            &constructor_args.mem,
            VirtioDeviceType::Balloon,
            NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;
        let mut device = FreePageReporting::new_with_queues(queues, constructor_args.vm)?;
        device.set_restored(
            state.virtio_state.avail_features,
            state.virtio_state.acked_features,
            state.actual_pages,
        );
        Ok(device)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::free_page_reporting::device::FREE_PAGE_REPORTING_DEV_ID;
    use crate::vstate::vm::tests::setup_vm_with_memory;

    #[test]
    fn test_persistence_keeps_features_and_what_the_driver_wrote() {
        let vm = Arc::new(setup_vm_with_memory(0x10_0000));
        let mem = vm.guest_memory().clone();
        let mut device = FreePageReporting::new(vm.clone()).unwrap();
        device.set_acked_features(device.avail_features());
        device.write_config(4, &3u32.to_le_bytes());

        let serialized = bitcode::serialize(&device.save()).unwrap();
        let state: FreePageReportingState = bitcode::deserialize(&serialized).unwrap();
        let restored =
            FreePageReporting::restore(FreePageReportingConstructorArgs { mem, vm }, &state)
                .unwrap();

        assert_eq!(restored.device_type(), VirtioDeviceType::Balloon);
        assert_eq!(restored.id(), FREE_PAGE_REPORTING_DEV_ID);
        assert!(!restored.is_activated());
        assert_eq!(restored.avail_features(), device.avail_features());
        assert_eq!(restored.acked_features(), device.acked_features());
        let mut word = [0u8; 4];
        restored.read_config(4, &mut word);
        assert_eq!(u32::from_le_bytes(word), 3);
    }
}
