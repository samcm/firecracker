// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! This is the `VirtioDevice` implementation for our vsock device. It handles the virtio-level
//! device logic: feature negotiation, device configuration, and device activation.
//!
//! We aim to conform to the VirtIO v1.1 spec:
//! https://docs.oasis-open.org/virtio/virtio/v1.1/virtio-v1.1.html
//!
//! The vsock device has two input parameters: a CID to identify the device, and a
//! `VsockBackend` to use for offloading vsock traffic.
//!
//! Upon its activation, the vsock device registers handlers for the following events/FDs:
//! - an RX queue FD;
//! - a TX queue FD;
//! - an event queue FD; and
//! - a backend FD.

use std::fmt::Debug;
use std::ops::Deref;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use vmm_sys_util::eventfd::EventFd;

use super::super::super::DeviceError;
use super::defs::uapi;
use super::packet::{VSOCK_PKT_HDR_SIZE, VsockPacketRx, VsockPacketTx};
use super::{VsockBackend, defs};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::{VIRTIO_F_IN_ORDER, VIRTIO_F_VERSION_1};
use crate::devices::virtio::generated::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use crate::devices::virtio::queue::{InvalidAvailIdx, Queue as VirtQueue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::devices::virtio::vsock::VsockError;
use crate::devices::virtio::vsock::metrics::METRICS;
use crate::impl_device_type;
use crate::logger::{IncMetric, error, info, warn};
use crate::utils::byte_order;
use crate::vstate::memory::{Bytes, GuestMemoryMmap};

pub(crate) const RXQ_INDEX: usize = 0;
pub(crate) const TXQ_INDEX: usize = 1;
pub(crate) const EVQ_INDEX: usize = 2;

pub(crate) const VIRTIO_VSOCK_EVENT_TRANSPORT_RESET: u32 = 0;

/// The virtio features supported by our vsock device:
/// - VIRTIO_F_VERSION_1: the device conforms to at least version 1.0 of the VirtIO spec.
/// - VIRTIO_F_IN_ORDER: the device returns used buffers in the same order that the driver makes
///   them available.
/// - VIRTIO_RING_F_EVENT_IDX: the device supports used_event/avail_event notification
///   suppression.
pub(crate) const AVAIL_FEATURES: u64 = (1 << VIRTIO_F_VERSION_1 as u64)
    | (1 << VIRTIO_F_IN_ORDER as u64)
    | (1 << VIRTIO_RING_F_EVENT_IDX as u64);

/// Whether the guest owes an acknowledgement of a `TRANSPORT_RESET`, and whether the event has
/// reached its event queue.
///
/// A reset tells the guest that the backend connections it believes in are gone. It needs a
/// descriptor on the event queue, which the guest may not have provided, so being owed a reset and
/// having published one are different states: only the published one can be acknowledged, and only
/// the acknowledgement lets guest data cross again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportReset {
    /// No reset is outstanding. RX and TX flow.
    Settled,
    /// A reset is owed to the guest, and the event queue had no descriptor to publish it into.
    /// Data is gated until a descriptor arrives and the event is published.
    Owed,
    /// The reset is in the guest's event queue. Data is gated until the guest acknowledges it.
    Published,
}

/// Structure representing the vsock device.
#[derive(Debug)]
pub struct Vsock<B> {
    cid: u64,
    pub(crate) queues: Vec<VirtQueue>,
    pub(crate) queue_events: Vec<EventFd>,
    pub(crate) backend: B,
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    // This EventFd is the only one initially registered for a vsock device, and is used to convert
    // a VirtioDevice::activate call into an EventHandler read event which allows the other events
    // (queue and backend related) to be registered post virtio device activation. That's
    // mostly something we wanted to happen for the backend events, to prevent (potentially)
    // continuous triggers from happening before the device gets activated.
    pub(crate) activate_evt: EventFd,
    pub(crate) device_state: DeviceState,

    pub rx_packet: VsockPacketRx,
    pub tx_packet: VsockPacketTx,

    /// Whether the guest owes an acknowledgement of a `TRANSPORT_RESET`. Guest data is gated
    /// until it arrives.
    pub(crate) transport_reset: TransportReset,
}

// TODO: Detect / handle queue deadlock:
// 1. If the driver halts RX queue processing, we'll need to notify `self.backend`, so that it can
//    unregister any EPOLLIN listeners, since otherwise it will keep spinning, unable to consume its
//    EPOLLIN events.

impl<B> Vsock<B>
where
    B: VsockBackend + Debug,
{
    /// Auxiliary function for creating a new virtio-vsock device with the given VM CID, vsock
    /// backend and empty virtio queues.
    pub fn with_queues(
        cid: u64,
        backend: B,
        queues: Vec<VirtQueue>,
    ) -> Result<Vsock<B>, VsockError> {
        let mut queue_events = Vec::new();
        for _ in 0..queues.len() {
            queue_events.push(EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?);
        }

        Ok(Vsock {
            cid,
            queues,
            queue_events,
            backend,
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            activate_evt: EventFd::new(libc::EFD_NONBLOCK).map_err(VsockError::EventFd)?,
            device_state: DeviceState::Inactive,
            rx_packet: VsockPacketRx::new()?,
            tx_packet: VsockPacketTx::default(),
            transport_reset: TransportReset::Settled,
        })
    }

    /// Create a new virtio-vsock device with the given VM CID and vsock backend.
    pub fn new(cid: u64, backend: B) -> Result<Vsock<B>, VsockError> {
        let queues: Vec<VirtQueue> = defs::VSOCK_QUEUE_SIZES
            .iter()
            .map(|&max_size| VirtQueue::new(max_size))
            .collect();
        Self::with_queues(cid, backend, queues)
    }

    /// Retrieve the cid associated with this vsock device.
    pub fn cid(&self) -> u64 {
        self.cid
    }

    /// Access the backend behind the device.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Whether an outstanding `TRANSPORT_RESET` gates guest data.
    ///
    /// From the moment a reset is owed until the guest acknowledges it, the guest still believes
    /// in connections the host no longer has. Both directions are held: a TX packet would be sent
    /// to a connection that is gone, and an RX packet would be delivered onto one, so neither may
    /// cross before the guest has been told.
    pub(crate) fn data_gated(&self) -> bool {
        !matches!(self.transport_reset, TransportReset::Settled)
    }

    /// Signal the guest driver that we've used some virtio buffers that it had previously made
    /// available.
    pub fn signal_used_queue(&self, qidx: usize) -> Result<(), DeviceError> {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .trigger(VirtioInterruptType::Queue(qidx.try_into().unwrap_or_else(
                |_| panic!("vsock: invalid queue index: {qidx}"),
            )))
            .map_err(DeviceError::FailedSignalingIrq)
    }

    /// Signal the guest which queues are ready to be consumed
    pub fn signal_used_queues(&self, used_queues: &[u16]) -> Result<(), DeviceError> {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .trigger_queues(used_queues)
            .map_err(DeviceError::FailedSignalingIrq)
    }

    /// Walk the driver-provided RX queue buffers and attempt to fill them up with any data that we
    /// have pending. Return `true` if the guest needs to be notified (respecting notification
    /// suppression).
    pub fn process_rx(&mut self) -> Result<bool, InvalidAvailIdx> {
        if self.data_gated() {
            return Ok(false);
        }

        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[RXQ_INDEX];
        let mut have_used = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            let index = head.index;
            let used_len = match self.rx_packet.parse(mem, head) {
                Ok(()) => {
                    if self.backend.recv_pkt(&mut self.rx_packet).is_ok() {
                        match self.rx_packet.commit_hdr() {
                            // This addition cannot overflow, because packet length
                            // is previously validated against `MAX_PKT_BUF_SIZE`
                            // bound as part of `commit_hdr()`.
                            Ok(()) => VSOCK_PKT_HDR_SIZE + self.rx_packet.hdr.len(),
                            Err(err) => {
                                warn!(
                                    "vsock: Error writing packet header to guest memory: \
                                     {:?}.Discarding the package.",
                                    err
                                );
                                0
                            }
                        }
                    } else {
                        // We are using a consuming iterator over the virtio buffers, so, if we
                        // can't fill in this buffer, we'll need to undo the
                        // last iterator step.
                        queue.undo_pop();
                        break;
                    }
                }
                Err(err) => {
                    warn!("vsock: RX queue error: {:?}. Discarding the package.", err);
                    0
                }
            };

            have_used = true;
            queue.add_used(index, used_len).unwrap_or_else(|err| {
                error!("Failed to add available descriptor {}: {}", index, err)
            });
        }
        queue.advance_used_ring_idx();

        Ok(have_used && queue.prepare_kick())
    }

    /// Walk the driver-provided TX queue buffers, package them up as vsock packets, and send them
    /// to the backend for processing. Return `true` if the guest needs to be notified (respecting
    /// notification suppression).
    pub fn process_tx(&mut self) -> Result<bool, InvalidAvailIdx> {
        if self.data_gated() {
            return Ok(false);
        }

        // This is safe since we checked in the event handler that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[TXQ_INDEX];
        let mut have_used = false;

        while let Some(head) = queue.pop_or_enable_notification()? {
            let index = head.index;
            match self.tx_packet.parse(mem, head) {
                Ok(()) => (),
                Err(err) => {
                    error!("vsock: error reading TX packet: {:?}", err);
                    have_used = true;
                    queue.add_used(index, 0).unwrap_or_else(|err| {
                        error!("Failed to add available descriptor {}: {}", index, err);
                    });
                    continue;
                }
            };

            self.backend.send_pkt(&self.tx_packet);

            have_used = true;
            queue.add_used(index, 0).unwrap_or_else(|err| {
                error!("Failed to add available descriptor {}: {}", index, err);
            });
        }
        queue.advance_used_ring_idx();

        Ok(have_used && queue.prepare_kick())
    }

    /// Publishes a `TRANSPORT_RESET` event to the guest.
    ///
    /// According to specs, the driver shuts down established connections and the guest_cid
    /// configuration field is fetched again. Existing listen sockets remain but their CID is
    /// updated to reflect the current guest_cid.
    ///
    /// Publication needs an available descriptor on the event queue. A queue that has none leaves
    /// the reset owed rather than dropped, with the event queue notification armed, and guest data
    /// stays gated until the event is published and acknowledged.
    pub fn send_transport_reset_event(&mut self) -> Result<(), DeviceError> {
        // This is safe since we checked in the caller function that the device is activated.
        let mem = &self.device_state.active_state().unwrap().mem;

        let queue = &mut self.queues[EVQ_INDEX];
        // `pop_or_enable_notification` arms `avail_event` and rechecks the ring as one step, so a
        // descriptor the guest publishes concurrently either carries the reset now or produces the
        // notification that carries it later. A bare `enable_notification` loses that race: it
        // arms at an avail index the guest has already passed, and EVENT_IDX does not repeat the
        // notification the guest has already given, so the reset would never be published.
        let head = match queue.pop_or_enable_notification() {
            Ok(Some(head)) => head,
            Ok(None) => {
                self.owe_transport_reset();
                METRICS.ev_queue_event_fails.inc();
                return Err(DeviceError::VsockError(VsockError::EmptyQueue));
            }
            // A queue the device cannot read cannot carry the reset either, so the guest is still
            // owed one and data stays gated.
            Err(err) => {
                self.owe_transport_reset();
                METRICS.ev_queue_event_fails.inc();
                return Err(err.into());
            }
        };

        mem.write_obj::<u32>(VIRTIO_VSOCK_EVENT_TRANSPORT_RESET, head.addr)
            .unwrap_or_else(|err| error!("Failed to write virtio vsock reset event: {:?}", err));

        queue.add_used(head.index, head.len).unwrap_or_else(|err| {
            error!("Failed to add used descriptor {}: {}", head.index, err);
        });
        queue.advance_used_ring_idx();

        // Arm the notification so the driver's refill of the consumed head is not suppressed by
        // EVENT_IDX: that refill is also the acknowledgement this device waits for. The driver
        // cannot refill before it has seen this used-ring update, which is what makes arming
        // without a recheck correct here.
        queue.enable_notification();

        self.transport_reset = TransportReset::Published;
        METRICS.transport_reset_published.inc();

        // NOTE: kick() will be called on resume and it will trigger the interrupt again. As calling
        // it multiple times should not cause any harm, it would be safer to call it here as well
        // as part of the sequence of actions that signal the reset event, prior to saving the
        // transport state.
        self.signal_used_queue(EVQ_INDEX)?;

        Ok(())
    }

    /// Records that the guest is owed a reset the device could not publish.
    ///
    /// A reset that is already in the guest's event queue is never downgraded: it has been
    /// published, the guest can answer it, and a second event for the same fact would consume
    /// another descriptor and outlive the single acknowledgement that clears the gate. A repeated
    /// failure while already owed is counted instead: the guest is not answering, and data stays
    /// gated for as long as that holds.
    fn owe_transport_reset(&mut self) {
        match self.transport_reset {
            TransportReset::Published => {}
            TransportReset::Owed => METRICS.transport_reset_stuck.inc(),
            TransportReset::Settled => {
                self.transport_reset = TransportReset::Owed;
                METRICS.transport_reset_owed.inc();
            }
        }
    }

    /// Publishes a reset the device owes the guest, if it owes one.
    ///
    /// Guest activity on the data queues is a retry point: the event queue may hold a descriptor
    /// the device has no notification for, and data stays gated until the reset is published.
    pub(crate) fn retry_owed_transport_reset(&mut self) {
        if !self.device_state.is_activated() || self.transport_reset != TransportReset::Owed {
            return;
        }
        if let Err(err) = self.send_transport_reset_event() {
            warn!("vsock: transport reset still owed to the guest: {:?}", err);
        }
    }

    /// Applies the guest's acknowledgement of a published `TRANSPORT_RESET`, and reports whether
    /// the gate it cleared was holding data back.
    ///
    /// Two paths observe that acknowledgement: the event handler, which serves the guest's kick of
    /// the event queue, and `prepare_save`, which finds such a kick unserved in the event queue's
    /// eventfd. Both have to leave the same device behind, so the transition lives here.
    ///
    /// A caller told the gate was shut owes the TX queue a walk: the notification the guest gave
    /// while the gate held is not repeated.
    pub(crate) fn acknowledge_transport_reset(&mut self) -> bool {
        let was_gated = self.data_gated();
        self.transport_reset = TransportReset::Settled;
        was_gated
    }

    /// The reset obligation a snapshot of this device carries.
    ///
    /// A `TRANSPORT_RESET` belongs to the VM restored from the serialized state, not to the one
    /// being saved. The restored device's backend is fresh, so every connection its guest believes
    /// in is gone and it owes the guest a reset before any data crosses. The device being saved
    /// keeps its connections, its event queue and its data flow, so an active device that owes
    /// nothing serializes the debt without incurring it.
    ///
    /// A reset already published is serialized as published: that event is in the guest memory the
    /// snapshot captures, and a state claiming it was merely owed would publish a second event for
    /// the same fact, consuming another descriptor and outliving the single acknowledgement that
    /// clears the gate.
    ///
    /// A device the guest never activated owes nothing: it has no connections to reset, and a
    /// restore must not invent a gate that only a published reset could ever clear.
    pub(crate) fn snapshot_transport_reset(&self) -> TransportReset {
        match self.transport_reset {
            TransportReset::Published => TransportReset::Published,
            TransportReset::Owed => TransportReset::Owed,
            TransportReset::Settled if self.device_state.is_activated() => TransportReset::Owed,
            TransportReset::Settled => TransportReset::Settled,
        }
    }
}

impl<B> VirtioDevice for Vsock<B>
where
    B: VsockBackend + Debug + 'static,
{
    impl_device_type!(VirtioDeviceType::Vsock);

    fn id(&self) -> &str {
        defs::VSOCK_DEV_ID
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn queues(&self) -> &[VirtQueue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [VirtQueue] {
        &mut self.queues
    }

    fn queue_events(&self) -> &[EventFd] {
        &self.queue_events
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        match offset {
            0 if data.len() == 8 => byte_order::write_le_u64(data, self.cid()),
            0 if data.len() == 4 => {
                byte_order::write_le_u32(data, (self.cid() & 0xffff_ffff) as u32)
            }
            4 if data.len() == 4 => {
                byte_order::write_le_u32(data, ((self.cid() >> 32) & 0xffff_ffff) as u32)
            }
            _ => {
                METRICS.cfg_fails.inc();
                warn!(
                    "vsock: virtio-vsock received invalid read request of {} bytes at offset {}",
                    data.len(),
                    offset
                )
            }
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        METRICS.cfg_fails.inc();
        warn!(
            "vsock: guest driver attempted to write device config (offset={:#x}, len={:#x})",
            offset,
            data.len()
        );
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

        if self.queues.len() != defs::VSOCK_NUM_QUEUES {
            METRICS.activate_fails.inc();
            return Err(ActivateError::QueueMismatch {
                expected: defs::VSOCK_NUM_QUEUES,
                got: self.queues.len(),
            });
        }

        if self.has_feature(VIRTIO_RING_F_EVENT_IDX as u64) {
            for queue in &mut self.queues {
                queue.enable_notif_suppression();
            }
        }

        if self.activate_evt.write(1).is_err() {
            METRICS.activate_fails.inc();
            return Err(ActivateError::EventFd);
        }

        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });

        Ok(())
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn kick(&mut self) {
        if !self.is_activated() {
            return;
        }

        match self.transport_reset {
            // The snapshot recorded a reset this VM owes its guest: the connections the guest
            // believes in belonged to a backend this device does not have. Publish it now, and if
            // the event queue holds no descriptor the notification armed by the failure brings the
            // device back when the guest refills the queue. Data stays gated until the reset is
            // published and acknowledged, so the guest cannot use connections the host has lost.
            TransportReset::Owed => {
                if let Err(err) = self.send_transport_reset_event() {
                    info!(
                        "[{:?}:{}] transport reset still owed to the guest: {:?}",
                        self.device_type(),
                        self.id(),
                        err
                    );
                }
            }

            // Vsock has a complicated protocol that isn't resilient to any packet loss,
            // so for Vsock we don't support connection persistence through snapshot. Any
            // in-flight packets or events are simply lost and Vsock is restored 'empty'.
            // The reset was already in the guest's event queue when the snapshot was taken,
            // and the guest had not answered it yet. We signal the event queue to make the
            // guest process it. (We signal it host->guest rather than writing its eventfd,
            // which would invoke the guest's acknowledgement path and clear the gate
            // prematurely.)
            //
            // TX is not replayed here: it is gated until the acknowledgement, and the
            // acknowledgement path walks it.
            TransportReset::Published => {
                info!(
                    "[{:?}:{}] signaling event queue",
                    self.device_type(),
                    self.id()
                );
                self.signal_used_queue(EVQ_INDEX).unwrap();
            }

            // Replay the TX queue notification, like the default `VirtioDevice::kick`
            // does for its data queues, so the device re-processes any TX descriptor
            // that was in-flight at snapshot time and re-arms `avail_event`.
            //
            // Without this, `avail_idx` stays ahead of the `avail_event` we published.
            // Under EVENT_IDX the guest only notifies us when `avail_idx` crosses
            // `avail_event`; since it is already past, the guest considers itself to
            // have notified us and stays silent, so we never process the queue and
            // guest-to-host connections hang. RX needs no replay: the host pulls from the
            // backend rather than waiting on a guest RX notification.
            TransportReset::Settled => {
                info!(
                    "[{:?}:{}] notifying tx queue",
                    self.device_type(),
                    self.id()
                );
                if let Err(err) = self.queue_events[TXQ_INDEX].write(1) {
                    error!(
                        "[{:?}:{}] error notifying tx queue: {}",
                        self.device_type(),
                        self.id(),
                        err
                    );
                }
            }
        }
    }

    /// Collects an acknowledgement the guest has already given, so the serialized state does not
    /// wait for it twice.
    ///
    /// Only the event handler turns the guest's event queue kick into the acknowledgement of a
    /// published reset, and that kick can arrive when no handler will run: Farplane's capture
    /// closes event dispatch before it pauses the vCPUs, so a guest that refills the event queue
    /// in between leaves its kick in the eventfd. That eventfd does not reach the restored VM,
    /// whose eventfds are fresh, and the used ring a `Published` restore signals is the one the
    /// guest has already consumed: the restored guest would never be asked again, would never
    /// answer, and both of its directions would stay gated for the rest of its life. The pending
    /// kick is read here instead and the acknowledgement applied before serialization, which makes
    /// the snapshot carry a reset the restored VM publishes for itself.
    ///
    /// Only a published reset is read for. An owed one has no acknowledgement to collect, and
    /// publishing it here would push an event into a source that keeps running. The TX descriptors
    /// the gate held are not walked here either: `kick()` replays their notification, on this
    /// source when it resumes and on the restored VM once its own reset is acknowledged.
    fn prepare_save(&mut self) {
        if !self.is_activated() || self.transport_reset != TransportReset::Published {
            return;
        }

        match self.queue_events[EVQ_INDEX].read() {
            Ok(_) => {
                self.acknowledge_transport_reset();
                info!(
                    "[{:?}:{}] collected the guest's transport reset acknowledgement while saving",
                    self.device_type(),
                    self.id()
                );
            }
            // Nothing to collect, so the reset stays published: the event is in the guest memory
            // the snapshot captures and the restored guest still owes the answer.
            Err(err) if err.raw_os_error() == Some(libc::EAGAIN) => {}
            Err(err) => error!(
                "[{:?}:{}] could not read the event queue eventfd while saving: {:?}",
                self.device_type(),
                self.id(),
                err
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use vmm_sys_util::epoll::EventSet;

    use super::*;
    use crate::devices::virtio::vsock::defs::uapi;
    use crate::devices::virtio::vsock::test_utils::{EVQ_PAYLOAD_GUEST_ADDR, TestContext};
    use crate::snapshot::Persist;
    use crate::vstate::memory::GuestAddress;

    #[test]
    fn test_virtio_device() {
        let mut ctx = TestContext::new();
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
        assert_eq!(ctx.device.device_type(), VirtioDeviceType::Vsock);
        assert_eq!(ctx.device.avail_features_by_page(0), device_pages[0]);
        assert_eq!(ctx.device.avail_features_by_page(1), device_pages[1]);
        assert_eq!(ctx.device.avail_features_by_page(2), 0);

        // Ack device features, page 0.
        ctx.device.ack_features_by_page(0, driver_pages[0]);
        // Ack device features, page 1.
        ctx.device.ack_features_by_page(1, driver_pages[1]);
        // Ack some bogus page (i.e. 2). This should have no side effect.
        ctx.device.ack_features_by_page(2, 0);
        // Attempt to un-ack the first feature page. This should have no side effect.
        ctx.device.ack_features_by_page(0, !driver_pages[0]);
        // Check that no side effect are present, and that the acked features are exactly the same
        // as the device features.
        assert_eq!(ctx.device.acked_features, device_features & driver_features);

        // Test reading 32-bit chunks.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data[..4]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[..])),
            ctx.cid & 0xffff_ffff
        );
        ctx.device.read_config(4, &mut data[4..]);
        assert_eq!(
            u64::from(byte_order::read_le_u32(&data[4..])),
            (ctx.cid >> 32) & 0xffff_ffff
        );

        // Test reading 64-bit.
        let mut data = [0u8; 8];
        ctx.device.read_config(0, &mut data);
        assert_eq!(byte_order::read_le_u64(&data), ctx.cid);

        // Check that out-of-bounds reading doesn't mutate the destination buffer.
        let mut data = [0u8, 1, 2, 3, 4, 5, 6, 7];
        ctx.device.read_config(2, &mut data);
        assert_eq!(data, [0u8, 1, 2, 3, 4, 5, 6, 7]);

        // Just covering lines here, since the vsock device has no writable config.
        // A warning is, however, logged, if the guest driver attempts to write any config data.
        ctx.device.write_config(0, &data[..4]);

        // Test a bad activation.
        // let bad_activate = ctx.device.activate(
        //     ctx.mem.clone(),
        // );
        // match bad_activate {
        //     Err(ActivateError::BadActivate) => (),
        //     other => panic!("{:?}", other),
        // }

        // Test a correct activation.
        ctx.device
            .activate(ctx.mem.clone(), ctx.interrupt.clone())
            .unwrap();
    }

    #[test]
    fn test_send_transport_reset_event_publishes_and_gates() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);

        ctx.device.send_transport_reset_event().unwrap();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Published,
            "TRANSPORT_RESET emission must gate guest data until the guest acknowledges it"
        );
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "evq used ring must advance once the event is published"
        );

        // The 4-byte payload must be VIRTIO_VSOCK_EVENT_TRANSPORT_RESET (== 0).
        let mut buf = [0xffu8; 4];
        test_ctx
            .mem
            .read_slice(&mut buf, GuestAddress(EVQ_PAYLOAD_GUEST_ADDR))
            .unwrap();
        assert_eq!(u32::from_le_bytes(buf), VIRTIO_VSOCK_EVENT_TRANSPORT_RESET);
    }

    #[test]
    fn test_send_transport_reset_event_empty_queue_owes_the_reset() {
        // No available descriptors on the evq -> the device cannot publish the event, so the
        // guest is owed one and data stays gated until it is published and acknowledged.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        let err = ctx.device.send_transport_reset_event().unwrap_err();
        match err {
            DeviceError::VsockError(VsockError::EmptyQueue) => (),
            other => panic!("unexpected error variant: {other:?}"),
        }
        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Owed,
            "a reset that could not be published must not be dropped"
        );
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            0,
            "nothing may be published into an empty event queue"
        );
        assert!(
            ctx.device.data_gated(),
            "guest data must not cross while the reset is owed"
        );
    }

    #[test]
    fn test_kick_when_inactive_is_a_noop() {
        // The fix runs `kick()` only when activated. The inactive branch must not gate data,
        // otherwise a freshly restored-but-unactivated device would refuse RX forever.
        let mut ctx = TestContext::new();
        assert!(!ctx.device.is_activated());

        ctx.device.kick();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "kick() on an inactive device must remain a no-op"
        );
    }

    #[test]
    fn test_kick_keeps_the_state_the_snapshot_recorded() {
        // Restore path: whether a reset is outstanding belongs to the snapshot. A snapshot that
        // recorded none leaves data flowing.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Settled;
        ctx.device.kick();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "kick() must not gate data the snapshot never gated"
        );

        // With no reset outstanding, RX delivers.
        ctx.device.backend.set_pending_rx(true);
        assert!(ctx.device.process_rx().unwrap());
    }

    #[test]
    fn test_kick_preserves_a_published_reset() {
        // The other half: a snapshot taken while a published reset was unacknowledged restores
        // that gate, and data stays shut until the guest acknowledges it.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published;
        ctx.device.kick();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);

        ctx.device.backend.set_pending_rx(true);
        assert!(!ctx.device.process_rx().unwrap());
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
        assert!(!ctx.device.process_tx().unwrap());
        assert_eq!(ctx.guest_txvq.used.idx.get(), 0);
    }

    #[test]
    fn test_kick_publishes_an_owed_reset_when_a_descriptor_is_there() {
        // A restored device that owes a reset publishes it as soon as it can, and data stays
        // gated until the guest acknowledges the published event.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.kick();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);
        // The TX queue is not replayed while the reset is unacknowledged.
        ctx.device.queue_events[TXQ_INDEX].read().unwrap_err();
    }

    #[test]
    fn test_kick_keeps_an_owed_reset_owed_without_a_descriptor() {
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.kick();

        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);
    }

    #[test]
    fn test_kick_replays_tx_notification_only() {
        // On restore, kick() must replay only the TX data queue (to re-process in-flight
        // TX and re-arm avail_event). RX needs no replay, and the event queue's data eventfd
        // must not be notified -- that is the
        // guest's TRANSPORT_RESET ack path; the event queue is signaled host->guest.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.kick();

        // TX queue eventfd was replayed for re-processing.
        assert_eq!(ctx.device.queue_events[TXQ_INDEX].read().unwrap(), 1);
        // RX and the event queue's data eventfd must not be signaled by kick()
        // (non-blocking read returns an error when the eventfd has no pending count).
        ctx.device.queue_events[RXQ_INDEX].read().unwrap_err();
        ctx.device.queue_events[EVQ_INDEX].read().unwrap_err();
    }

    #[test]
    fn test_save_owes_the_restored_device_a_reset_and_leaves_the_source_alone() {
        // The reset belongs to the VM restored from the serialized state: its backend connections
        // do not exist. The device being saved keeps its connections, so the capture must not
        // publish an event into its guest's event queue, even though a descriptor is there for one.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        let state = ctx.device.save();

        assert_eq!(
            state.transport_reset,
            TransportReset::Owed,
            "the restored device owes the guest a reset for the connections it does not have"
        );
        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "saving must not gate the source's data"
        );
        assert!(!ctx.device.data_gated());
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            0,
            "saving must not write the source guest's event queue"
        );

        // The source keeps delivering after the capture.
        ctx.device.backend.set_pending_rx(true);
        assert!(ctx.device.process_rx().unwrap());
    }

    #[test]
    fn test_save_passes_an_owed_reset_through() {
        // A source that already owes its guest a reset serializes that debt, and the capture is
        // not a publication attempt: the descriptor stays where the guest put it.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        ctx.device.transport_reset = TransportReset::Owed;

        let state = ctx.device.save();

        assert_eq!(state.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);
    }

    #[test]
    fn test_save_passes_a_published_reset_through() {
        // The event is already in the guest memory the snapshot captures, so the serialized state
        // has to agree with it: the restored device waits for the acknowledgement instead of
        // publishing a second event for the same reset.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        ctx.device.transport_reset = TransportReset::Published;

        let state = ctx.device.save();

        assert_eq!(state.transport_reset, TransportReset::Published);
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);
    }

    #[test]
    fn test_repeated_capture_keeps_a_published_reset_published() {
        // A capture consumes no event-queue descriptor, so repeating one cannot exhaust the queue
        // and downgrade the published reset. It stays the single event the guest can answer.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        ctx.publish_evq_descriptor();

        ctx.device.transport_reset = TransportReset::Published;

        assert_eq!(ctx.device.save().transport_reset, TransportReset::Published);
        assert_eq!(ctx.device.save().transport_reset, TransportReset::Published);
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            0,
            "no capture may publish an event for a reset already outstanding"
        );

        // Even a direct publication attempt that runs out of descriptors leaves the published
        // reset alone.
        ctx.device.queues[EVQ_INDEX].pop().unwrap().unwrap();
        let err = ctx.device.send_transport_reset_event().unwrap_err();
        assert!(matches!(
            err,
            DeviceError::VsockError(VsockError::EmptyQueue)
        ));
        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);
    }

    #[test]
    fn test_repeated_capture_keeps_an_owed_reset_owed() {
        // A capture records the debt and never attempts to publish it, so repeating one leaves the
        // guest's empty event queue exactly as it found it.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Owed;

        assert_eq!(ctx.device.save().transport_reset, TransportReset::Owed);
        assert_eq!(ctx.device.save().transport_reset, TransportReset::Owed);
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(ctx.guest_evvq.used.idx.get(), 0);

        // A retry that runs out of descriptors keeps the debt and reports it.
        let stuck_before = METRICS.transport_reset_stuck.count();
        ctx.device.retry_owed_transport_reset();
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert!(
            METRICS.transport_reset_stuck.count() > stuck_before,
            "a failed retry of an owed reset must be counted"
        );
    }

    #[test]
    fn test_event_idx_arms_the_event_queue_for_an_owed_reset() {
        // With EVENT_IDX the guest suppresses notifications until the device asks for one. A reset
        // the device cannot publish therefore has to arm the event queue, or the refill that would
        // carry it never announces itself.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.device
            .ack_features_by_page(0, 1 << VIRTIO_RING_F_EVENT_IDX);
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());
        // `avail_event` is only ever written by the notification-suppression path.
        ctx.guest_evvq.used.event.set(0xffff);

        // The restored device owes the reset, and its guest has not refilled the event queue.
        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.kick();

        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);
        assert_eq!(
            ctx.guest_evvq.used.event.get(),
            0,
            "the device must arm avail_event at the index it will next read"
        );

        // The guest refills the queue and kicks it: the notification the device armed for.
        ctx.guest_refills_evq(0);
        let used = ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Published);
        assert_eq!(
            ctx.guest_evvq.used.idx.get(),
            1,
            "the refilled descriptor must carry the reset"
        );
        assert!(used.is_empty(), "publishing a reset signals no data queue");

        // The guest answers the published event, and only then does data cross.
        ctx.device.backend.set_pending_rx(true);
        ctx.guest_refills_evq(1);
        let used = ctx.signal_evq_event();

        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
        assert!(used.contains(&RXQ_INDEX.try_into().unwrap()));
    }

    #[test]
    fn test_event_idx_publishes_a_descriptor_that_arrived_without_a_notification() {
        // With EVENT_IDX the guest may have refilled the event queue before the device armed it,
        // in which case no further notification is coming: the guest considers itself to have
        // notified already. The next guest activity of any kind must publish the owed reset rather
        // than wait for a notification that never arrives.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.device
            .ack_features_by_page(0, 1 << VIRTIO_RING_F_EVENT_IDX);
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Owed;
        ctx.device.kick();
        assert_eq!(ctx.device.transport_reset, TransportReset::Owed);

        // The descriptor appears with no event-queue kick behind it.
        ctx.guest_refills_evq(0);
        ctx.signal_rxq_event();

        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Published,
            "a data-queue kick must retry the owed reset"
        );
        assert_eq!(ctx.guest_evvq.used.idx.get(), 1);
    }

    #[test]
    fn test_save_of_an_inactive_device_owes_nothing() {
        // A device the guest never brought up has no connections to reset, and a restore must not
        // invent a gate: only a published reset can ever be acknowledged.
        let ctx = TestContext::new();
        assert!(!ctx.device.is_activated());

        let state = ctx.device.save();

        assert_eq!(state.transport_reset, TransportReset::Settled);
        assert_eq!(ctx.device.transport_reset, TransportReset::Settled);
    }

    #[test]
    fn test_transport_reset_default_is_settled() {
        let ctx = TestContext::new();
        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Settled,
            "freshly created device must not gate guest data"
        );
    }

    #[test]
    fn test_evq_event_with_non_in_evset_is_a_noop() {
        // Spurious evset flavours must not clear the gate or drain the RX queue.
        let test_ctx = TestContext::new();
        let mut ctx = test_ctx.create_event_handler_context();
        ctx.mock_activate(test_ctx.mem.clone(), test_ctx.interrupt.clone());

        ctx.device.transport_reset = TransportReset::Published;
        ctx.device.backend.set_pending_rx(true);

        let used = ctx.device.handle_evq_event(EventSet::OUT);

        assert!(used.is_empty());
        assert_eq!(
            ctx.device.transport_reset,
            TransportReset::Published,
            "non-IN evset must not clear the gate"
        );
        assert_eq!(ctx.guest_rxvq.used.idx.get(), 0);
    }
}
