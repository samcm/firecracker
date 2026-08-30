// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::fmt::Debug;

/// The vsock object implements the runtime logic of our vsock device:
/// 1. Respond to TX queue events by wrapping virtio buffers into `VsockPacket`s, then sending
///    those packets to the `VsockBackend`;
/// 2. Forward backend FD event notifications to the `VsockBackend`;
/// 3. Fetch incoming packets from the `VsockBackend` and place them into the virtio RX queue;
/// 4. Whenever we have processed some virtio buffers (either TX or RX), let the driver know by
///    raising our assigned IRQ.
///
/// In a nutshell, the logic looks like this:
/// - on TX queue event:
///   - fetch all packets from the TX queue and send them to the backend; then
///   - if the backend has queued up any incoming packets, fetch them into any available RX
///     buffers.
/// - on RX queue event:
///   - fetch any incoming packets, queued up by the backend, into newly available RX buffers.
/// - on backend event:
///   - forward the event to the backend; then
///   - again, attempt to fetch any incoming packets queued by the backend into virtio RX
///     buffers.
use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::VsockBackend;
use super::device::{EVQ_INDEX, RXQ_INDEX, TXQ_INDEX, TransportReset, Vsock};
use crate::devices::virtio::device::VirtioDevice;
use crate::devices::virtio::queue::InvalidAvailIdx;
use crate::devices::virtio::vsock::metrics::METRICS;
use crate::logger::{IncMetric, error, warn};

impl<B> Vsock<B>
where
    B: Debug + VsockBackend + 'static,
{
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_RXQ: u32 = 1;
    const PROCESS_TXQ: u32 = 2;
    const PROCESS_EVQ: u32 = 3;
    const PROCESS_NOTIFY_BACKEND: u32 = 4;

    pub fn handle_rxq_event(&mut self, evset: EventSet) -> Vec<u16> {
        let mut used_queues = Vec::new();
        if evset != EventSet::IN {
            warn!("vsock: rxq unexpected event {:?}", evset);
            METRICS.rx_queue_event_fails.inc();
            return used_queues;
        }

        // A guest that kicks a data queue may have supplied the event queue with a descriptor for
        // a reset the device owes, or answered one it published, without the device seeing a
        // notification for either.
        used_queues.extend(self.advance_transport_reset());

        if let Err(err) = self.queue_events[RXQ_INDEX].read() {
            error!("Failed to get vsock rx queue event: {:?}", err);
            METRICS.rx_queue_event_fails.inc();
        } else if self.backend.has_pending_rx() {
            if self.process_rx().unwrap() {
                used_queues.push(RXQ_INDEX.try_into().unwrap());
            }
            METRICS.rx_queue_event_count.inc();
        }
        used_queues
    }

    pub fn handle_txq_event(&mut self, evset: EventSet) -> Vec<u16> {
        let mut used_queues = Vec::new();
        if evset != EventSet::IN {
            warn!("vsock: txq unexpected event {:?}", evset);
            METRICS.tx_queue_event_fails.inc();
            return used_queues;
        }

        used_queues.extend(self.advance_transport_reset());

        if let Err(err) = self.queue_events[TXQ_INDEX].read() {
            error!("Failed to get vsock tx queue event: {:?}", err);
            METRICS.tx_queue_event_fails.inc();
        } else {
            let txq: u16 = TXQ_INDEX.try_into().unwrap();
            if self.process_tx().unwrap() && !used_queues.contains(&txq) {
                used_queues.push(txq);
            }
            METRICS.tx_queue_event_count.inc();
            // The backend may have queued up responses to the packets we sent during
            // TX queue processing. If that happened, we need to fetch those responses
            // and place them into RX buffers.
            if self.backend.has_pending_rx() && self.process_rx().unwrap() {
                used_queues.push(RXQ_INDEX.try_into().unwrap());
            }
        }
        used_queues
    }

    pub fn handle_evq_event(&mut self, evset: EventSet) -> Vec<u16> {
        let mut used_queues = Vec::new();
        if evset != EventSet::IN {
            warn!("vsock: evq unexpected event {:?}", evset);
            METRICS.ev_queue_event_fails.inc();
            return used_queues;
        }

        // The kick is drained because the eventfd is level triggered, and for nothing else. A
        // token says the guest touched the event queue at some instant, never which of the
        // device's writes it followed, so it settles nothing and publishes nothing. A read that
        // failed observed no guest action at all, so there is nothing to look at the rings for.
        if let Err(err) = self.queue_events[EVQ_INDEX].read() {
            error!("Failed to consume vsock evq event: {:?}", err);
            METRICS.ev_queue_event_fails.inc();
            return used_queues;
        }

        // Publishes a reset the device owes, or settles a published one the guest has answered by
        // advancing the event queue past the watermark, walking the TX descriptors that frees.
        used_queues.extend(self.advance_transport_reset());

        // A reset still outstanding keeps the gate shut. This kick was not the answer: either the
        // event has only just been published, or the ring has not moved off the watermark. Nothing
        // is re-armed and no wakeup is lost, because publication armed `avail_event` at exactly
        // the watermark, so the advance that does answer produces its own kick.
        if self.data_gated() {
            return used_queues;
        }

        // No reset is outstanding, so this is ordinary event queue activity. Assumes
        // TRANSPORT_RESET is the only evq event we publish; new event types would need to
        // disambiguate before clearing the gate above.
        if self.backend.has_pending_rx() {
            match self.process_rx() {
                Ok(true) => used_queues.push(RXQ_INDEX.try_into().unwrap()),
                Ok(false) => {}
                Err(err) => error!("vsock: process_rx after evq ack failed: {:?}", err),
            }
        }
        used_queues
    }

    /// Notify backend of new events.
    pub fn notify_backend(&mut self, evset: EventSet) -> Result<Vec<u16>, InvalidAvailIdx> {
        let mut used_queues = Vec::new();
        self.backend.notify(evset);
        // After the backend has been kicked it may have freed up resources, so walk the TX
        // queue again in case there are packets waiting to be forwarded to it.
        if self.process_tx()? {
            used_queues.push(TXQ_INDEX.try_into().unwrap());
        }
        if self.backend.has_pending_rx() && self.process_rx()? {
            used_queues.push(RXQ_INDEX.try_into().unwrap())
        }

        Ok(used_queues)
    }

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events[RXQ_INDEX],
            Self::PROCESS_RXQ,
            EventSet::IN,
        )) {
            error!("Failed to register rx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events[TXQ_INDEX],
            Self::PROCESS_TXQ,
            EventSet::IN,
        )) {
            error!("Failed to register tx queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_events[EVQ_INDEX],
            Self::PROCESS_EVQ,
            EventSet::IN,
        )) {
            error!("Failed to register ev queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.backend,
            Self::PROCESS_NOTIFY_BACKEND,
            self.backend.get_polled_evset(),
        )) {
            error!("Failed to register vsock backend event: {}", err);
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to register activate event: {}", err);
        }
    }

    fn handle_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_evt.read() {
            error!("Failed to consume net activate event: {:?}", err);
        }
        self.register_runtime_events(ops);
        if let Err(err) = ops.remove(Events::with_data(
            &self.activate_evt,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("Failed to un-register activate event: {}", err);
        }
    }
}

impl<B> MutEventSubscriber for Vsock<B>
where
    B: Debug + VsockBackend + 'static,
{
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let evset = event.event_set();

        if self.is_activated() {
            let used_queues = match source {
                Self::PROCESS_ACTIVATE => {
                    self.handle_activate_event(ops);
                    Vec::new()
                }
                Self::PROCESS_RXQ => self.handle_rxq_event(evset),
                Self::PROCESS_TXQ => self.handle_txq_event(evset),
                Self::PROCESS_EVQ => self.handle_evq_event(evset),
                Self::PROCESS_NOTIFY_BACKEND => self.notify_backend(evset).unwrap(),
                _ => {
                    warn!("Unexpected vsock event received: {:?}", source);
                    Vec::new()
                }
            };
            self.signal_used_queues(&used_queues)
                .expect("vsock: Could not trigger device interrupt");
        } else {
            warn!(
                "Vsock: The device is not yet activated. Spurious event received: {:?}",
                source
            );
        }
    }

    fn init(&mut self, ops: &mut EventOps) {
        // This function can be called during different points in the device lifetime:
        //  - shortly after device creation,
        //  - on device activation (is-activated already true at this point),
        //  - on device restore from snapshot.
        if self.is_activated() {
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use event_manager::{EventManager, SubscriberOps};

    use super::super::*;
    use super::*;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::vsock::test_utils::{
        EVQ_PAYLOAD_GUEST_ADDR, EventHandlerContext, TestContext, published_ack_from,
    };

    /// A descriptor the guest made available while the device was publishing is inside the
    /// watermark, so the kick that carried it answers nothing.
    #[test]
    fn test_a_descriptor_that_raced_the_publication_is_not_an_acknowledgement() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        // Two available event descriptors. The device publishes into the first; the second models
        // the add that landed before the guest could have seen the used ring.
        ctx.guest_evvq.dtable[0].set(EVQ_PAYLOAD_GUEST_ADDR, 4, VIRTQ_DESC_F_WRITE, 0);
        ctx.guest_evvq.dtable[1].set(EVQ_PAYLOAD_GUEST_ADDR + 0x1000, 4, VIRTQ_DESC_F_WRITE, 0);
        ctx.guest_evvq.avail.ring[0].set(0);
        ctx.guest_evvq.avail.ring[1].set(1);
        ctx.guest_evvq.avail.idx.set(2);
        ctx.device.queues[EVQ_INDEX] = ctx.guest_evvq.create_queue();

        ctx.device.send_transport_reset_event().unwrap();

        assert_eq!(
            published_ack_from(&ctx.device),
            2,
            "the watermark must cover the descriptor that raced the publication"
        );
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);

        // The kick that carried the raced descriptor settles nothing, on any path.
        ctx.device.backend.set_pending_rx(true);
        let used = ctx.signal_evq_event();
        assert!(used.is_empty());
        assert_eq!(published_ack_from(&ctx.device), 2);
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        ctx.device.prepare_save();
        assert_eq!(published_ack_from(&ctx.device), 2);

        // The refill of the consumed head advances past the watermark, and that is the answer.
        ctx.guest_refills_evq(2);
        let used = ctx.signal_evq_event();
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert!(used.contains(&RXQ_INDEX.try_into().unwrap()));
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
    }

    #[test]
    fn test_txq_event() {
        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend has no pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(false);
            ctx.signal_txq_event();

            // The available TX descriptor should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The available RX descriptor should be untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend also has some pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(true);
            ctx.signal_txq_event();

            // Both available RX and TX descriptors should have been used.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - the driver supplied a malformed TX buffer.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            // Invalidate the descriptor chain, by setting its length to 0.
            ctx.guest_txvq.dtable[0].len.set(0);
            ctx.guest_txvq.dtable[1].len.set(0);
            ctx.signal_txq_event();

            // The available descriptor should have been consumed, but no packet should have
            // reached the backend.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            assert_eq!(ctx.device.backend.tx_ok_cnt, 0);
        }

        // Test case: spurious TXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            let metric_before = METRICS.tx_queue_event_fails.count();
            ctx.device.handle_txq_event(EventSet::IN);
            assert_eq!(metric_before + 1, METRICS.tx_queue_event_fails.count());
        }
    }

    #[test]
    fn test_rxq_event() {
        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend successfully places its RX data into the queue.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(true);
            ctx.device.backend.set_rx_err(Some(VsockError::NoData));
            ctx.signal_rxq_event();

            // The available RX buffer should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }

        // Test case:
        // - there is pending RX data in the backend; and
        // - the driver makes RX buffers available; and
        // - the backend errors out, when attempting to receive data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(true);
            ctx.signal_rxq_event();

            // The available RX buffer should have been used.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case: the driver provided a malformed RX descriptor chain.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            // Invalidate the descriptor chain, by setting its length to 0.
            ctx.guest_rxvq.dtable[0].len.set(0);
            ctx.guest_rxvq.dtable[1].len.set(0);

            // The chain should've been processed, without employing the backend.
            assert!(ctx.device.process_rx().unwrap());
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
            assert_eq!(ctx.device.backend.rx_ok_cnt, 0);
        }

        // Test case: spurious RXQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
            ctx.device.backend.set_pending_rx(false);
            let metric_before = METRICS.rx_queue_event_fails.count();
            ctx.device.handle_rxq_event(EventSet::IN);
            assert_eq!(metric_before + 1, METRICS.rx_queue_event_fails.count());
        }
    }

    #[test]
    fn test_evq_event() {
        // Test case: spurious EVQ_EVENT.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.device.backend.set_pending_rx(false);
            let metric_before = METRICS.ev_queue_event_fails.count();
            ctx.device.handle_evq_event(EventSet::IN);
            assert_eq!(metric_before + 1, METRICS.ev_queue_event_fails.count());
        }
    }

    #[test]
    fn test_published_reset_gates_rx() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(true);

        let used = ctx.device.notify_backend(EventSet::IN).unwrap();
        assert!(
            !used.contains(&RXQ_INDEX.try_into().unwrap()),
            "RX vq must not be signalled while the reset is unacknowledged"
        );
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "RX vq used ring must be untouched while the reset is unacknowledged"
        );

        ctx.device.backend.set_pending_rx(true);

        // The driver refills the head the device consumed. That advance past the watermark is the
        // acknowledgement; the kick beside it only wakes the handler.
        ctx.guest_refills_evq(0);
        let used = ctx.signal_evq_event();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "the guest's refill of the event queue acknowledges the published reset"
        );
        assert!(
            used.contains(&RXQ_INDEX.try_into().unwrap()),
            "the acknowledgement should drain pending RX and signal the RX vq"
        );
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            1,
            "RX vq must be drained immediately after the acknowledgement"
        );
    }

    #[test]
    fn test_published_reset_gates_rxq_event() {
        // RX queue events arriving before the guest acknowledges the TRANSPORT_RESET must not
        // drain the RX virtqueue.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(true);

        ctx.signal_rxq_event();

        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "RX vq must stay empty while the reset is unacknowledged"
        );
        assert_eq!(
            ctx.device.backend.rx_ok_cnt, 0,
            "backend recv_pkt must not be called while gated"
        );
    }

    #[test]
    fn test_published_reset_gates_txq_drain() {
        // TX is gated too: until the guest knows its connections are gone, a packet it queued
        // for one of them must not reach the backend. The acknowledgement is what drains it.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(true);

        ctx.signal_txq_event();

        assert_eq!(
            ctx.guest_txvq.used.idx.get(),
            0,
            "TX vq must stay untouched while the reset is unacknowledged"
        );
        assert_eq!(
            ctx.device.backend.tx_ok_cnt, 0,
            "no packet may reach the backend before the guest is told"
        );
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "RX vq must stay empty during txq drain while gated"
        );

        ctx.guest_refills_evq(0);
        let used = ctx.signal_evq_event();

        assert!(
            used.contains(&TXQ_INDEX.try_into().unwrap()),
            "the acknowledgement must walk the TX queue the gate held back"
        );
        assert_eq!(
            ctx.guest_txvq.used.idx.get(),
            1,
            "the TX descriptor gated before the acknowledgement must be processed after it"
        );
    }

    #[test]
    fn test_owed_reset_is_published_when_the_guest_refills_the_event_queue() {
        // The descriptor that arrives while a reset is owed carries the reset, and does not
        // acknowledge it: data stays gated until the guest answers the published event.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.backend.set_pending_rx(true);
        ctx.publish_evq_descriptor();

        let used = ctx.signal_evq_event();

        assert_eq!(published_ack_from(&ctx.device), 1);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "the arriving descriptor must carry the reset"
        );
        assert!(
            used.is_empty(),
            "publishing the reset must not signal a data queue"
        );
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "data must stay gated until the guest acknowledges the published reset"
        );
        assert_eq!(ctx.guest_txvq.used.idx.get(), 0);

        // Only now, with the reset in the guest's hands, does its refill release data.
        ctx.guest_refills_evq(1);
        let used = ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert!(used.contains(&RXQ_INDEX.try_into().unwrap()));
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
    }

    #[test]
    fn test_evq_event_clears_the_gate_without_pending_rx() {
        // The acknowledgement must clear the gate even when the backend has nothing queued,
        // otherwise a later RX would stay gated forever.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(false);

        ctx.guest_refills_evq(0);
        ctx.signal_evq_event();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "the gate must clear on the refill regardless of RX backlog"
        );
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
    }

    #[test]
    fn test_evq_event_logs_eventfd_read_failure() {
        // Driving handle_evq_event without writing to the eventfd first triggers the EAGAIN read
        // error branch. No guest kick was observed, so the published reset stays published and
        // data stays gated: a settle here would release data on an acknowledgement the guest
        // never gave. A same-batch retry that publishes and consumes the kick leaves exactly this
        // state behind for the event queue's already-ready callback.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(true);

        let metric_before = METRICS.ev_queue_event_fails.count();
        let used = ctx.device.handle_evq_event(EventSet::IN);

        assert_eq!(metric_before + 1, METRICS.ev_queue_event_fails.count());
        assert_eq!(
            published_ack_from(&ctx.device),
            0,
            "a failed eventfd read observes no ring progress either"
        );
        assert!(used.is_empty());
        assert_eq!(
            ctx.guest_rxvq.used.idx.get(),
            0,
            "data must stay gated when no guest kick was read"
        );
        assert_eq!(ctx.guest_txvq.used.idx.get(), 0);
    }

    #[test]
    fn test_txq_retry_then_evq_readiness_keeps_the_reset_published() {
        // The TX side of the same epoll batch. The guest's event-queue kick carried the
        // descriptor, a TX kick published the reset into it, and the event-queue callback that
        // the very same kick made ready runs afterwards. It must leave the reset published: the
        // guest has not answered an event it was only just given.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.backend.set_pending_rx(true);
        ctx.publish_evq_descriptor();
        ctx.device.queue_events[EVQ_INDEX].write(1).unwrap();

        ctx.signal_txq_event();

        assert_eq!(published_ack_from(&ctx.device), 1);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);

        let used = ctx.device.handle_evq_event(EventSet::IN);

        assert_eq!(
            published_ack_from(&ctx.device),
            1,
            "a kick with no ring progress behind it is not the acknowledgement"
        );
        assert!(used.is_empty());
        assert_eq!(
            ctx.guest_txvq.used.idx.get(),
            0,
            "TX must stay gated until the guest answers the published reset"
        );
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
    }

    #[test]
    fn test_process_rx_short_circuits_while_gated() {
        // Direct call to process_rx must respect the gate and not touch the queue.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published { ack_from: 0 };
        ctx.device.backend.set_pending_rx(true);

        let progressed = ctx.device.process_rx().unwrap();

        assert!(!progressed, "process_rx must report no progress when gated");
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        assert_eq!(ctx.device.backend.rx_ok_cnt, 0);
    }

    #[test]
    fn test_backend_event() {
        // Test case:
        // - a backend event is received; and
        // - the backend has pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(true);
            ctx.device.notify_backend(EventSet::IN).unwrap();

            // The backend should've received this event.
            assert_eq!(ctx.device.backend.evset, Some(EventSet::IN));
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // RX queue processing should've been triggered.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 1);
        }

        // Test case:
        // - a backend event is received; and
        // - the backend doesn't have any pending RX data.
        {
            let test_ctx = TestContext::new();
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

            ctx.device.backend.set_pending_rx(false);
            ctx.device.notify_backend(EventSet::IN).unwrap();

            // The backend should've received this event.
            assert_eq!(ctx.device.backend.evset, Some(EventSet::IN));
            // TX queue processing should've been triggered.
            assert_eq!(ctx.guest_txvq.used.idx.get(), 1);
            // The RX queue should've been left untouched.
            assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        }
    }

    // Creates an epoll handler context and attempts to assemble a VsockPkt from the descriptor
    // chains available on the rx and tx virtqueues, but first it will set the addr and len
    // of the descriptor specified by desc_idx to the provided values. We are only using this
    // function for testing error cases, so the asserts always expect is_err() to be true. When
    // desc_idx = 0 we are altering the header (first descriptor in the chain), and when
    // desc_idx = 1 we are altering the packet buffer.
    #[cfg(target_arch = "x86_64")]
    fn vsock_bof_helper(test_ctx: &mut TestContext, desc_idx: usize, addr: u64, len: u32) {
        use crate::vstate::memory::{Bytes, GuestAddress};

        assert!(desc_idx <= 1);

        {
            let mut ctx = test_ctx.create_event_handler_context();
            ctx.guest_rxvq.dtable[desc_idx].addr.set(addr);
            ctx.guest_rxvq.dtable[desc_idx].len.set(len);
            // If the descriptor chain is already declared invalid, there's no reason to assemble
            // a packet.
            if let Some(rx_desc) = ctx.device.queues[RXQ_INDEX].pop().unwrap() {
                VsockPacketRx::new()
                    .unwrap()
                    .parse(&test_ctx.mem, rx_desc)
                    .unwrap_err();
            }
        }

        {
            let mut ctx = test_ctx.create_event_handler_context();

            // When modifying the buffer descriptor, make sure the len field is altered in the
            // vsock packet header descriptor as well.
            if desc_idx == 1 {
                // The vsock packet len field has offset 24 in the header.
                let hdr_len_addr = GuestAddress(ctx.guest_txvq.dtable[0].addr.get() + 24);
                test_ctx
                    .mem
                    .write_obj(len.to_le_bytes(), hdr_len_addr)
                    .unwrap();
            }

            ctx.guest_txvq.dtable[desc_idx].addr.set(addr);
            ctx.guest_txvq.dtable[desc_idx].len.set(len);

            if let Some(tx_desc) = ctx.device.queues[TXQ_INDEX].pop().unwrap() {
                VsockPacketTx::default()
                    .parse(&test_ctx.mem, tx_desc)
                    .unwrap_err();
            }
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_possible_truncation)] /* casting of constants we know fit into u32 */
    fn test_vsock_bof() {
        use crate::arch::x86_64::layout::FIRST_ADDR_PAST_32BITS;
        use crate::arch::{MMIO32_MEM_SIZE, MMIO32_MEM_START};
        use crate::devices::virtio::vsock::packet::VSOCK_PKT_HDR_SIZE;
        use crate::test_utils::multi_region_mem;
        use crate::utils::mib_to_bytes;
        use crate::vstate::memory::GuestAddress;

        const MIB: usize = mib_to_bytes(1);

        let mut test_ctx = TestContext::new();
        test_ctx.mem = multi_region_mem(&[
            (GuestAddress(0), 8 * MIB),
            (GuestAddress(MMIO32_MEM_START - MIB as u64), MIB),
            (GuestAddress(FIRST_ADDR_PAST_32BITS), MIB),
        ]);

        // The default configured descriptor chains are valid.
        {
            let mut ctx = test_ctx.create_event_handler_context();
            let rx_desc = ctx.device.queues[RXQ_INDEX].pop().unwrap().unwrap();
            VsockPacketRx::new()
                .unwrap()
                .parse(&test_ctx.mem, rx_desc)
                .unwrap();
        }

        {
            let mut ctx = test_ctx.create_event_handler_context();
            let tx_desc = ctx.device.queues[TXQ_INDEX].pop().unwrap().unwrap();
            VsockPacketTx::default()
                .parse(&test_ctx.mem, tx_desc)
                .unwrap();
        }

        // Let's check what happens when the header descriptor is right before the gap.
        vsock_bof_helper(&mut test_ctx, 0, MMIO32_MEM_START - 1, VSOCK_PKT_HDR_SIZE);

        // Let's check what happens when the buffer descriptor crosses into the gap, but does
        // not go past its right edge.
        vsock_bof_helper(
            &mut test_ctx,
            1,
            MMIO32_MEM_START - 4,
            MMIO32_MEM_SIZE as u32 + 4,
        );

        // Let's modify the buffer descriptor addr and len such that it crosses over the MMIO gap,
        // and check we cannot assemble the VsockPkts.
        vsock_bof_helper(
            &mut test_ctx,
            1,
            MMIO32_MEM_START - 4,
            MMIO32_MEM_SIZE as u32 + 100,
        );
    }

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let test_ctx = TestContext::new();
        let EventHandlerContext {
            device,
            guest_rxvq,
            guest_txvq,
            ..
        } = test_ctx.create_event_handler_context();

        let vsock = Arc::new(Mutex::new(device));
        let _id = event_manager.add_subscriber(vsock.clone());

        // Push a queue event
        // - the driver has something to send (there's data in the TX queue); and
        // - the backend also has some pending RX data.
        {
            let mut device = vsock.lock().unwrap();
            device.backend.set_pending_rx(true);
            device.queue_events[TXQ_INDEX].write(1).unwrap();
        }

        // EventManager should report no events since vsock has only registered
        // its activation event so far (even though there is also a queue event pending).
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Manually force a queue event and check it's ignored pre-activation.
        {
            let device = vsock.lock().unwrap();

            // Artificially push event.
            device.queue_events[TXQ_INDEX].write(1).unwrap();
            let ev_count = event_manager.run_with_timeout(50).unwrap();
            assert_eq!(ev_count, 0);

            // Both available RX and TX descriptors should be untouched.
            assert_eq!(guest_rxvq.used.idx.get(), 0);
            assert_eq!(guest_txvq.used.idx.get(), 0);
        }

        // Now activate the device.
        vsock
            .lock()
            .unwrap()
            .activate(test_ctx.mem.clone(), test_ctx.interrupt.clone())
            .unwrap();
        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Handle the previously pushed queue event through EventManager.
        {
            let ev_count = event_manager
                .run_with_timeout(100)
                .expect("Metrics event timeout or error.");
            assert_eq!(ev_count, 1);
            // Both available RX and TX descriptors should have been used.
            assert_eq!(guest_rxvq.used.idx.get(), 1);
            assert_eq!(guest_txvq.used.idx.get(), 1);
        }
    }

    /// A reset published from one callback is not acknowledged by another in the same batch.
    ///
    /// The guest refills the event queue, kicks it, and kicks a data queue. Both eventfds are
    /// ready before the event manager dispatches, so both callbacks run whatever either does to
    /// the other's fd. Whichever runs first publishes the owed reset; the other must leave it
    /// published, because the guest has had no chance to answer an event it was only just given.
    #[test]
    fn test_same_batch_retry_and_evq_readiness_keeps_the_reset_published() {
        let mut event_manager = EventManager::new().unwrap();
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.backend.set_pending_rx(true);
        // The guest puts a descriptor on the event queue: the reset can be published into it.
        ctx.publish_evq_descriptor();

        let EventHandlerContext {
            device,
            guest_rxvq,
            guest_txvq,
            guest_evvq,
        } = ctx;

        let vsock = Arc::new(Mutex::new(device));
        let _id = event_manager.add_subscriber(vsock.clone());
        vsock
            .lock()
            .unwrap()
            .activate(test_ctx.mem.clone(), test_ctx.interrupt.clone())
            .unwrap();
        // Processing the activate event is what registers the queue eventfds.
        assert_eq!(event_manager.run_with_timeout(50).unwrap(), 1);

        {
            let device = vsock.lock().unwrap();
            device.queue_events[RXQ_INDEX].write(1).unwrap();
            device.queue_events[EVQ_INDEX].write(1).unwrap();
        }

        let mut dispatched = 0;
        for _ in 0..3 {
            dispatched += event_manager.run_with_timeout(50).unwrap();
            if dispatched >= 2 {
                break;
            }
        }
        assert_eq!(
            dispatched, 2,
            "both the data-queue kick and the event-queue kick must reach a callback"
        );

        let device = vsock.lock().unwrap();
        assert_eq!(
            device.transport_reset,
            TransportReset::Published { ack_from: 1 },
            "the kick that carried the descriptor must not acknowledge the reset it carried"
        );
        assert_eq!(
            guest_evvq.used.idx.get(),
            1,
            "exactly one reset must be published into the descriptor the guest left"
        );
        assert_eq!(
            guest_rxvq.used.idx.get(),
            0,
            "RX must stay gated until the guest answers the published reset"
        );
        assert_eq!(
            guest_txvq.used.idx.get(),
            0,
            "TX must stay gated until the guest answers the published reset"
        );
    }
}
