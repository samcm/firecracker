// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;

use serde::{Deserialize, Serialize};

use super::device::Net;
use super::{NET_NUM_QUEUES, NET_QUEUE_MAX_SIZE, TapError};
use crate::devices::virtio::device::VirtioDeviceType;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::rate_limiter::RateLimiter;
use crate::rate_limiter::persist::RateLimiterState;
use crate::snapshot::Persist;
use crate::utils::net::mac::MacAddr;
use crate::vstate::memory::GuestMemoryMmap;

/// Information about the network config's that are saved
/// at snapshot.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NetConfigSpaceState {
    guest_mac: Option<MacAddr>,
    #[serde(default)]
    mtu: Option<u16>,
}

/// Information about the network device that are saved
/// at snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetState {
    pub id: String,
    pub tap_if_name: String,
    rx_rate_limiter_state: RateLimiterState,
    tx_rate_limiter_state: RateLimiterState,
    config_space: NetConfigSpaceState,
    pub virtio_state: VirtioDeviceState,
}

/// Auxiliary structure for creating a device when resuming from a snapshot.
#[derive(Debug)]
pub struct NetConstructorArgs {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
}

/// Errors triggered when trying to construct a network device at resume time.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum NetPersistError {
    /// Failed to create a network device: {0}
    CreateNet(#[from] super::NetError),
    /// Failed to create a rate limiter: {0}
    CreateRateLimiter(#[from] io::Error),
    /// Failed to re-create the virtio state (i.e queues etc): {0}
    VirtioState(#[from] VirtioStateError),
    /// Setting tap interface offload flags failed: {0}
    TapSetOffload(TapError),
}

impl Persist<'_> for Net {
    type State = NetState;
    type ConstructorArgs = NetConstructorArgs;
    type Error = NetPersistError;

    fn save(&self) -> Self::State {
        NetState {
            id: self.id.clone(),
            tap_if_name: self.iface_name(),
            rx_rate_limiter_state: self.rx_rate_limiter.save(),
            tx_rate_limiter_state: self.tx_rate_limiter.save(),
            config_space: NetConfigSpaceState {
                guest_mac: self.guest_mac,
                mtu: self.mtu(),
            },
            virtio_state: VirtioDeviceState::from_device(self),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let rx_rate_limiter = RateLimiter::restore((), &state.rx_rate_limiter_state)?;
        let tx_rate_limiter = RateLimiter::restore((), &state.tx_rate_limiter_state)?;
        let mut net = Net::new(
            state.id.clone(),
            &state.tap_if_name,
            state.config_space.guest_mac,
            rx_rate_limiter,
            tx_rate_limiter,
            state.config_space.mtu,
        )?;

        net.queues = state.virtio_state.build_queues_checked(
            &constructor_args.mem,
            VirtioDeviceType::Net,
            NET_NUM_QUEUES,
            NET_QUEUE_MAX_SIZE,
        )?;
        net.avail_features = state.virtio_state.avail_features;
        net.acked_features = state.virtio_state.acked_features;

        Ok(net)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::net::test_utils::default_net;
    use crate::devices::virtio::test_utils::default_mem;

    #[test]
    fn test_persistence() {
        let net = default_net();
        let guest_mem = default_mem();
        let id = net.id.clone();
        let tap_if_name = net.iface_name();
        let virtio_state = VirtioDeviceState::from_device(&net);
        let serialized_data = bitcode::serialize(&net.save()).unwrap();
        drop(net);

        let restored_state = bitcode::deserialize(&serialized_data).unwrap();
        let restored_net =
            Net::restore(NetConstructorArgs { mem: guest_mem }, &restored_state).unwrap();
        assert_eq!(restored_net.device_type(), VirtioDeviceType::Net);
        assert_eq!(restored_net.avail_features(), virtio_state.avail_features);
        assert_eq!(restored_net.acked_features(), virtio_state.acked_features);
        assert_eq!(restored_net.is_activated(), virtio_state.activated);
        assert_eq!(&restored_net.id, &id);
        assert_eq!(&restored_net.iface_name(), &tap_if_name);
        assert_eq!(restored_net.rx_rate_limiter, RateLimiter::default());
        assert_eq!(restored_net.tx_rate_limiter, RateLimiter::default());
    }
}
