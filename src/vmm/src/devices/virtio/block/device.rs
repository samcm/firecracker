// Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::eventfd::EventFd;

use super::BlockError;
use super::persist::{BlockConstructorArgs, BlockState};
use super::virtio::VirtioBlockError;
use super::virtio::device::{VirtioBlock, VirtioBlockConfig};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::impl_device_type;
use crate::rate_limiter::BucketUpdate;
use crate::snapshot::Persist;
use crate::vmm_config::drive::{BlockDeviceConfig, DriveError};
use crate::vstate::memory::GuestMemoryMmap;

#[derive(Debug)]
pub enum Block {
    Virtio(VirtioBlock),
}

impl Block {
    pub fn new(config: BlockDeviceConfig) -> Result<Block, DriveError> {
        let config = VirtioBlockConfig::try_from(&config)?;
        VirtioBlock::new(config)
            .map(Self::Virtio)
            .map_err(|err| DriveError::CreateBlockDevice(BlockError::VirtioBackend(err)))
    }

    /// Drains every in-flight request so nothing this device started can write guest memory
    /// after the call returns.
    pub fn drain_writes(&mut self) -> Result<(), VirtioBlockError> {
        match self {
            Self::Virtio(b) => b.drain_writes(),
        }
    }

    pub fn config(&self) -> BlockDeviceConfig {
        match self {
            Self::Virtio(b) => b.config().into(),
        }
    }

    pub fn update_rate_limiter(
        &mut self,
        bytes: BucketUpdate,
        ops: BucketUpdate,
    ) -> Result<(), BlockError> {
        match self {
            Self::Virtio(b) => {
                b.update_rate_limiter(bytes, ops);
                Ok(())
            }
        }
    }

    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        match self {
            Self::Virtio(b) => b.process_virtio_queues(),
        }
    }

    pub fn root_device(&self) -> bool {
        match self {
            Self::Virtio(b) => b.root_device,
        }
    }

    pub fn read_only(&self) -> bool {
        match self {
            Self::Virtio(b) => b.read_only,
        }
    }

    pub fn partuuid(&self) -> &Option<String> {
        match self {
            Self::Virtio(b) => &b.partuuid,
        }
    }
}

impl VirtioDevice for Block {
    impl_device_type!(VirtioDeviceType::Block);

    fn id(&self) -> &str {
        match self {
            Self::Virtio(b) => b.id(),
        }
    }

    fn avail_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.avail_features,
        }
    }

    fn acked_features(&self) -> u64 {
        match self {
            Self::Virtio(b) => b.acked_features,
        }
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        match self {
            Self::Virtio(b) => b.acked_features = acked_features,
        }
    }

    fn queues(&self) -> &[Queue] {
        match self {
            Self::Virtio(b) => &b.queues,
        }
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
        match self {
            Self::Virtio(b) => &mut b.queues,
        }
    }

    fn queue_events(&self) -> &[EventFd] {
        match self {
            Self::Virtio(b) => &b.queue_evts,
        }
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        match self {
            Self::Virtio(b) => b.interrupt_trigger(),
        }
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match self {
            Self::Virtio(b) => b.read_config(offset, data),
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        match self {
            Self::Virtio(b) => b.write_config(offset, data),
        }
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        match self {
            Self::Virtio(b) => b.activate(mem, interrupt),
        }
    }

    fn is_activated(&self) -> bool {
        match self {
            Self::Virtio(b) => b.device_state.is_activated(),
        }
    }
}

impl MutEventSubscriber for Block {
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.process(event, ops),
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        match self {
            Self::Virtio(b) => b.init(ops),
        }
    }
}

impl Persist<'_> for Block {
    type State = BlockState;
    type ConstructorArgs = BlockConstructorArgs;
    type Error = BlockError;

    fn save(&self) -> Self::State {
        match self {
            Self::Virtio(b) => BlockState::Virtio(b.save()),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        match state {
            BlockState::Virtio(s) => Ok(Self::Virtio(
                VirtioBlock::restore(constructor_args, s).map_err(BlockError::VirtioBackend)?,
            )),
        }
    }
}
