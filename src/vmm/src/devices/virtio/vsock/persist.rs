// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Defines state and support structures for persisting Vsock devices and backends.

use std::fmt::Debug;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::*;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDeviceType};
use crate::devices::virtio::persist::VirtioDeviceState;
use crate::devices::virtio::queue::FIRECRACKER_MAX_QUEUE_SIZE;
use crate::devices::virtio::transport::VirtioInterrupt;
use crate::snapshot::Persist;
use crate::vstate::memory::GuestMemoryMmap;

/// The Vsock serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockState {
    /// The vsock backend state.
    pub backend: VsockBackendState,
    /// The vsock frontend state.
    pub frontend: VsockFrontendState,
}

/// The Vsock frontend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockFrontendState {
    /// Context Identifier.
    pub cid: u64,
    pub virtio_state: VirtioDeviceState,
    /// The `TRANSPORT_RESET` this device's guest is owed once it is restored, and whether that
    /// event already reached its event queue. A snapshot of an active device carries `Owed`: the
    /// restored device's backend is fresh, so it publishes the reset when the guest provides a
    /// descriptor and gates guest data until the acknowledgement arrives. `Published` is carried
    /// only when the captured guest memory already holds the event.
    pub transport_reset: TransportReset,
}

/// The Vsock Unix Backend serializable state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockBackendState {
    /// The path for the UDS socket.
    pub uds_path: String,
    /// The last used host-side port.
    pub local_port_last: u32,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockConstructorArgs<B> {
    /// Pointer to guest memory.
    pub mem: GuestMemoryMmap,
    /// The vsock Unix Backend.
    pub backend: B,
}

/// A helper structure that holds the constructor arguments for VsockUnixBackend
#[derive(Debug)]
pub struct VsockUdsConstructorArgs {
    /// cid available in VsockFrontendState.
    pub cid: u64,
}

impl Persist<'_> for VsockUnixBackend {
    type State = VsockBackendState;
    type ConstructorArgs = VsockUdsConstructorArgs;
    type Error = VsockUnixBackendError;

    fn save(&self) -> Self::State {
        VsockBackendState {
            uds_path: self.host_sock_path.clone(),
            local_port_last: self.local_port_last,
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        let mut backend = Self::new(constructor_args.cid, state.uds_path.clone())?;
        backend.local_port_last = state.local_port_last;
        Ok(backend)
    }
}

impl<B> Persist<'_> for Vsock<B>
where
    B: VsockBackend + 'static + Debug,
{
    type State = VsockFrontendState;
    type ConstructorArgs = VsockConstructorArgs<B>;
    type Error = VsockError;

    fn save(&self) -> Self::State {
        VsockFrontendState {
            cid: self.cid(),
            virtio_state: VirtioDeviceState::from_device(self),
            transport_reset: self.snapshot_transport_reset(),
        }
    }

    fn restore(
        constructor_args: Self::ConstructorArgs,
        state: &Self::State,
    ) -> Result<Self, Self::Error> {
        // Restore queues.
        let queues = state
            .virtio_state
            .build_queues_checked(
                &constructor_args.mem,
                VirtioDeviceType::Vsock,
                defs::VSOCK_NUM_QUEUES,
                FIRECRACKER_MAX_QUEUE_SIZE,
            )
            .map_err(VsockError::VirtioState)?;
        let mut vsock = Self::with_queues(state.cid, constructor_args.backend, queues)?;

        vsock.acked_features = state.virtio_state.acked_features;
        vsock.avail_features = state.virtio_state.avail_features;
        vsock.transport_reset = state.transport_reset;
        vsock.device_state = DeviceState::Inactive;
        Ok(vsock)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::device::{AVAIL_FEATURES, EVQ_INDEX};
    use super::*;
    use crate::devices::virtio::device::VirtioDevice;
    use crate::devices::virtio::test_utils::default_interrupt;
    use crate::devices::virtio::vsock::defs::uapi;
    use crate::devices::virtio::vsock::test_utils::{TestBackend, TestContext};
    use crate::utils::byte_order;

    impl Persist<'_> for TestBackend {
        type State = VsockBackendState;
        type ConstructorArgs = VsockUdsConstructorArgs;
        type Error = VsockUnixBackendError;

        fn save(&self) -> Self::State {
            VsockBackendState {
                uds_path: "test".to_owned(),
                local_port_last: 0xdeadbeef,
            }
        }

        fn restore(_: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
            Ok(TestBackend::new())
        }
    }

    #[test]
    fn test_persist_uds_backend() {
        let ctx = TestContext::new();
        let device_features = AVAIL_FEATURES;
        let driver_features: u64 = AVAIL_FEATURES | 1 | (1 << 32);
        let device_pages = [
            (device_features & 0xffff_ffff) as u32,
            (device_features >> 32) as u32,
        ];
        let driver_pages = [
            (driver_features & 0xffff_ffff) as u32,
            (driver_features >> 32) as u32,
        ];

        // Test serialization
        // Save backend and device state separately.
        let state = VsockState {
            backend: ctx.device.backend().save(),
            frontend: ctx.device.save(),
        };

        let serialized_data = bitcode::serialize(&state).unwrap();

        let restored_state: VsockState = bitcode::deserialize(&serialized_data).unwrap();
        let mut restored_device = Vsock::restore(
            VsockConstructorArgs {
                mem: ctx.mem.clone(),
                backend: {
                    assert_eq!(restored_state.backend.uds_path, "test".to_owned());
                    assert_eq!(restored_state.backend.local_port_last, 0xdeadbeef);
                    TestBackend::new()
                },
            },
            &restored_state.frontend,
        )
        .unwrap();

        assert_eq!(restored_device.device_type(), VirtioDeviceType::Vsock);
        assert_eq!(restored_device.avail_features_by_page(0), device_pages[0]);
        assert_eq!(restored_device.avail_features_by_page(1), device_pages[1]);
        assert_eq!(restored_device.avail_features_by_page(2), 0);

        restored_device.ack_features_by_page(0, driver_pages[0]);
        restored_device.ack_features_by_page(1, driver_pages[1]);
        restored_device.ack_features_by_page(2, 0);
        restored_device.ack_features_by_page(0, !driver_pages[0]);
        assert_eq!(
            restored_device.acked_features(),
            device_features & driver_features
        );

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        restored_device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[..])),
            ctx.cid & 0xffff_ffff
        );
        restored_device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        restored_device.read_config(0, &mut data);
        assert_eq!(byte_order::read_le_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        restored_device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);
    }

    /// Serializes a device and restores it through the wire format the snapshot uses.
    fn round_trip(device: &Vsock<TestBackend>, mem: &GuestMemoryMmap) -> Vsock<TestBackend> {
        let state = VsockState {
            backend: device.backend().save(),
            frontend: device.save(),
        };
        let bytes = bitcode::serialize(&state).unwrap();
        let restored: VsockState = bitcode::deserialize(&bytes).unwrap();
        Vsock::restore(
            VsockConstructorArgs {
                mem: mem.clone(),
                backend: TestBackend::new(),
            },
            &restored.frontend,
        )
        .unwrap()
    }

    /// A snapshot taken while a published reset was unacknowledged carries the gate, so the
    /// restored device knows the guest still owes the acknowledgement.
    #[test]
    fn test_persist_carries_an_unacknowledged_reset() {
        let mut ctx = TestContext::new();
        ctx.device.transport_reset = TransportReset::Published;

        let restored = round_trip(&ctx.device, &ctx.mem);

        assert_eq!(
            restored.transport_reset,
            TransportReset::Published,
            "a restored device must owe the acknowledgement the snapshot recorded"
        );

        // Chained restore: the gate survives a snapshot taken of a restored device, which is how
        // a guest captured twice in a row would lose it.
        let chained = round_trip(&restored, &ctx.mem);
        assert_eq!(chained.transport_reset, TransportReset::Published);
    }

    /// A snapshot that could not publish the reset carries the debt, not silence: the restored
    /// device still owes the guest a reset and gates data until it is published.
    #[test]
    fn test_persist_carries_an_owed_reset() {
        let mut ctx = TestContext::new();
        ctx.device.transport_reset = TransportReset::Owed;

        let restored = round_trip(&ctx.device, &ctx.mem);

        assert_eq!(restored.transport_reset, TransportReset::Owed);
        assert!(restored.data_gated());

        let chained = round_trip(&restored, &ctx.mem);
        assert_eq!(chained.transport_reset, TransportReset::Owed);
    }

    /// A device the guest never activated restores ungated: it has no connections to reset, so a
    /// restore must not invent a gate that only a published reset could ever clear.
    #[test]
    fn test_persist_carries_a_settled_transport() {
        let ctx = TestContext::new();
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);

        let restored = round_trip(&ctx.device, &ctx.mem);

        assert_eq!(restored.transport_reset, TransportReset::Settled);
        assert!(!restored.data_gated());

        let chained = round_trip(&restored, &ctx.mem);
        assert_eq!(chained.transport_reset, TransportReset::Settled);
    }

    /// The gate the guest acknowledged is not inherited: a later snapshot hands the restored device
    /// its own reset to publish rather than the answered one to wait on. A restored `Published`
    /// would wait for the acknowledgement of an event no descriptor of its guest holds.
    #[test]
    fn test_persist_does_not_inherit_an_acknowledged_gate() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.transport_reset = TransportReset::Published;

        // The guest's event-queue kick acknowledges the published reset.
        ctx.signal_evq_event();
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);

        assert_eq!(ctx.device.save().transport_reset, TransportReset::Owed);
    }

    /// The whole path a source with an empty event queue hands to its child: the capture publishes
    /// nothing into the source's guest, and the restored device publishes the reset once its own
    /// guest provides a descriptor. That reset must reach the guest before any data crosses in
    /// either direction.
    #[test]
    fn test_snapshot_of_an_active_source_publishes_the_reset_after_restore() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        let state = VsockState {
            backend: ctx.device.backend().save(),
            frontend: ctx.device.save(),
        };

        // The reset is the child's obligation, not an event in the source's guest.
        assert_eq!(state.frontend.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert!(!ctx.device.data_gated());
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);

        let bytes = bitcode::serialize(&state).unwrap();
        let restored: VsockState = bitcode::deserialize(&bytes).unwrap();

        // Restore into the same guest queues, as a resumed guest sees them.
        ctx.device = Vsock::restore(
            VsockConstructorArgs {
                mem: test_ctx.mem.clone(),
                backend: TestBackend::new(),
            },
            &restored.frontend,
        )
        .unwrap();
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);

        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.backend.set_pending_rx(true);

        // Resume: the reset is still owed, so nothing may cross yet.
        ctx.device.kick();
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        assert_eq!(ctx.guest_txvq.used.idx.get(), 0);

        // The guest refills the event queue and kicks it: that descriptor carries the reset.
        ctx.publish_evq_descriptor();
        let used = ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "the reset must be published as soon as a descriptor exists"
        );
        assert!(used.is_empty());
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "no RX may be delivered before the reset reaches the guest"
        );
        assert_eq!(
            ctx.guest_txvq.used.idx.get(),
            0,
            "no TX may reach the backend before the reset reaches the guest"
        );
        assert_eq!(ctx.device.backend.rx_ok_cnt, 0);
        assert_eq!(ctx.device.backend.tx_ok_cnt, 0);

        // Only the guest's answer to the published reset lets data cross.
        ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
    }

    /// A restored device whose guest left a descriptor on the event queue publishes the reset the
    /// moment it is resumed, and the capture that produced it left that descriptor alone.
    #[test]
    fn test_restored_device_publishes_the_owed_reset_on_resume() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        let state = VsockState {
            backend: ctx.device.backend().save(),
            frontend: ctx.device.save(),
        };
        assert_eq!(state.frontend.transport_reset, TransportReset::Owed);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            0,
            "the source's descriptor must survive the capture untouched"
        );

        let bytes = bitcode::serialize(&state).unwrap();
        let wire: VsockState = bitcode::deserialize(&bytes).unwrap();
        ctx.device = Vsock::restore(
            VsockConstructorArgs {
                mem: test_ctx.mem.clone(),
                backend: TestBackend::new(),
            },
            &wire.frontend,
        )
        .unwrap();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.backend.set_pending_rx(true);

        ctx.device.kick();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "the descriptor the guest left carries the reset on resume"
        );
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        assert_eq!(ctx.guest_txvq.used.idx.get(), 0);

        // Only the child guest's answer lets data cross.
        ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
    }

    /// The acknowledgement a guest gives after event dispatch has stopped is not lost.
    ///
    /// Farplane's capture closes dispatch before it pauses the vCPUs, so the kick that answers a
    /// published reset can land in an eventfd no handler will ever read. The restored VM gets fresh
    /// eventfds and a used ring its guest has already consumed, so a snapshot that recorded
    /// `Published` would ask for an answer that can no longer be given and gate that guest for the
    /// rest of its life.
    #[test]
    fn test_save_collects_an_acknowledgement_left_in_the_eventfd() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.transport_reset = TransportReset::Published;

        // The guest refills the event queue and kicks it. No handler runs, so the kick stays in
        // the eventfd, exactly as a capture that closed dispatch first leaves it.
        ctx.publish_evq_descriptor();
        ctx.device.queue_events[EVQ_INDEX].write(1).unwrap();
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);

        ctx.device.prepare_save();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "the acknowledgement waiting in the eventfd must be collected before serialization"
        );

        let state = VsockState {
            backend: ctx.device.backend().save(),
            frontend: ctx.device.save(),
        };
        assert_eq!(
            state.frontend.transport_reset,
            TransportReset::Owed,
            "an answered reset is not inherited; the child owes one of its own"
        );

        let bytes = bitcode::serialize(&state).unwrap();
        let wire: VsockState = bitcode::deserialize(&bytes).unwrap();
        ctx.device = Vsock::restore(
            VsockConstructorArgs {
                mem: test_ctx.mem.clone(),
                backend: TestBackend::new(),
            },
            &wire.frontend,
        )
        .unwrap();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.backend.set_pending_rx(true);

        // The child publishes one fresh reset into the descriptor its guest left, and nothing
        // crosses until that reset is answered.
        ctx.device.kick();
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);

        // The child's guest answers, and both directions open.
        ctx.signal_evq_event();
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert!(!ctx.device.data_gated());
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
    }

    /// A published reset the guest has not answered stays published: the event is in the guest
    /// memory the snapshot captures, and reading an empty eventfd is not an acknowledgement.
    #[test]
    fn test_save_keeps_a_reset_the_guest_has_not_answered() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.transport_reset = TransportReset::Published;

        ctx.device.prepare_save();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(
            ctx.device.save().transport_reset,
            TransportReset::Published,
            "the guest of the restored VM still owes the answer"
        );
    }

    /// An owed reset has no acknowledgement to collect, and the capture must not publish one into
    /// a source that keeps running: the source's own connections are still there.
    #[test]
    fn test_save_does_not_publish_an_owed_reset_into_the_source() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.transport_reset = TransportReset::Owed;

        // A descriptor and a kick the source's guest left behind, which a publish would consume.
        ctx.publish_evq_descriptor();
        ctx.device.queue_events[EVQ_INDEX].write(1).unwrap();

        ctx.device.prepare_save();

        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            0,
            "the source's event queue must be left untouched by the capture"
        );
        assert_eq!(ctx.device.save().transport_reset, TransportReset::Owed);
        assert_eq!(
            ctx.device.queue_events[EVQ_INDEX].read().unwrap(),
            1,
            "the kick belongs to the source's event handler, not to the capture"
        );
    }

    /// The capture must not take the descriptor-arrival kick for the guest's answer.
    ///
    /// A data-queue kick can publish an owed reset before any event-queue handler runs, which
    /// leaves the kick that carried the descriptor unserved unless the publication consumes it. A
    /// capture that read it as an acknowledgement would serialize a settled device, and the
    /// restored VM would publish a second event for a reset its guest has already been given but
    /// never answered.
    #[test]
    fn test_save_does_not_take_a_descriptor_arrival_kick_for_an_acknowledgement() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.device.transport_reset = TransportReset::Owed;

        // The guest refills the event queue and kicks it, and a data-queue kick publishes the
        // owed reset before the event queue's handler gets to run.
        ctx.publish_evq_descriptor();
        ctx.device.queue_events[EVQ_INDEX].write(1).unwrap();
        ctx.signal_rxq_event();
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);

        ctx.device.prepare_save();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Published,
            "the kick that carried the descriptor is not an acknowledgement of the event in it"
        );
        assert_eq!(
            ctx.device.save().transport_reset,
            TransportReset::Published,
            "the restored guest still owes the answer to the event in its event queue"
        );
    }
}
