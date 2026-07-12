// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::io::FileEngine;
use crate::devices::virtio::block::virtio::device::VirtioBlock;
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl VirtioBlock {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_QUEUE: u32 = 1;
    const PROCESS_RATE_LIMITER: u32 = 2;
    const PROCESS_ASYNC_COMPLETION: u32 = 3;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.queue_evts[0],
            Self::PROCESS_QUEUE,
            EventSet::IN,
        )) {
            error!("Failed to register queue event: {}", err);
        }
        if let Err(err) = ops.add(Events::with_data(
            &self.rate_limiter,
            Self::PROCESS_RATE_LIMITER,
            EventSet::IN,
        )) {
            error!("Failed to register ratelimiter event: {}", err);
        }
        if let FileEngine::Async(ref engine) = self.disk.file_engine
            && let Err(err) = ops.add(Events::with_data(
                engine.completion_evt(),
                Self::PROCESS_ASYNC_COMPLETION,
                EventSet::IN,
            ))
        {
            error!("Failed to register IO engine completion event: {}", err);
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

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_evt.read() {
            error!("Failed to consume block activate event: {:?}", err);
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

impl MutEventSubscriber for VirtioBlock {
    // Handle an event for queue or rate limiter.
    fn process(&mut self, event: Events, ops: &mut EventOps) {
        let source = event.data();
        let event_set = event.event_set();

        // TODO: also check for errors. Pending high level discussions on how we want
        // to handle errors in devices.
        let supported_events = EventSet::IN;
        if !supported_events.contains(event_set) {
            warn!(
                "Block: Received unknown event: {:?} from source: {:?}",
                event_set, source
            );
            return;
        }

        if self.is_activated() {
            match source {
                Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
                Self::PROCESS_QUEUE => self.process_queue_event(),
                Self::PROCESS_RATE_LIMITER => self.process_rate_limiter_event(),
                Self::PROCESS_ASYNC_COMPLETION => self.process_async_completion_event(),
                _ => warn!("Block: Spurious event received: {:?}", source),
            }
        } else {
            warn!(
                "Block: The device is not yet activated. Spurious event received: {:?}",
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

    use super::*;
    use crate::devices::virtio::block::virtio::device::FileEngineType;
    use crate::devices::virtio::block::virtio::test_utils::{
        default_block, read_blk_req_descriptors, set_queue, simulate_async_completion_event,
    };
    use crate::devices::virtio::block::virtio::{VIRTIO_BLK_S_OK, VIRTIO_BLK_T_OUT};
    use crate::devices::virtio::queue::VIRTQ_DESC_F_NEXT;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt, default_mem};
    use crate::rate_limiter::BucketUpdate;
    use crate::vstate::memory::{Bytes, GuestAddress};

    #[test]
    fn test_event_handler() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::default());
        let mem = default_mem();
        let interrupt = default_interrupt();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        read_blk_req_descriptors(&vq);

        let block = Arc::new(Mutex::new(block));
        let _id = event_manager.add_subscriber(block.clone());

        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());

        // Push a 'Write' operation.
        {
            mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
                .unwrap();
            // Make data read only, 512 bytes in len, and set the actual value to be written.
            vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
            vq.dtable[1].len.set(512);
            mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

            // Trigger the queue event.
            block.lock().unwrap().queue_evts[0].write(1).unwrap();
        }

        // EventManager should report no events since block has only registered
        // its activation event so far (even though queue event is pending).
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);

        // Now activate the device.
        block
            .lock()
            .unwrap()
            .activate(mem.clone(), interrupt)
            .unwrap();
        // Process the activate event.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 1);

        // Handle the pending queue event through EventManager.
        event_manager
            .run_with_timeout(100)
            .expect("Metrics event timeout or error.");
        // Complete async IO ops if needed
        simulate_async_completion_event(&mut block.lock().unwrap(), true);

        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(vq.used.ring[0].get().id, 0);
        assert_eq!(vq.used.ring[0].get().len, 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);
    }

    fn write_request_descriptors(
        mem: &crate::vstate::memory::GuestMemoryMmap,
        vq: &VirtQueue,
    ) -> GuestAddress {
        let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
        let data_addr = GuestAddress(vq.dtable[1].addr.get());
        let status_addr = GuestAddress(vq.dtable[2].addr.get());
        mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
            .unwrap();
        vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
        vq.dtable[1].len.set(512);
        mem.write_obj::<u64>(123_456_789, data_addr).unwrap();
        status_addr
    }

    #[test]
    fn test_queue_gate_defers_and_replays_kick_once() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        read_blk_req_descriptors(&vq);
        block
            .activate(mem.clone(), default_interrupt())
            .expect("device activation failed");
        let status_addr = write_request_descriptors(&mem, &vq);

        let block = Arc::new(Mutex::new(block));
        let _id = event_manager.add_subscriber(block.clone());

        // Double engage is idempotent. The queue event is consumed, but the
        // available descriptor remains untouched while the gate is engaged.
        // Rate-limiter updates still apply immediately.
        {
            let mut b = block.lock().unwrap();
            b.set_queue_gate(true);
            b.set_queue_gate(true);
            b.update_rate_limiter(BucketUpdate::Disabled, BucketUpdate::Disabled);
            assert!(b.rate_limiter.bandwidth().is_none());
            assert!(b.rate_limiter.ops().is_none());
            b.queue_evts[0].write(1).unwrap();
        }
        let ev_count = event_manager.run_with_timeout(100).unwrap();
        assert_eq!(ev_count, 1);
        {
            let b = block.lock().unwrap();
            assert_eq!(b.queues[0].len(), 1);
            assert_eq!(vq.used.idx.get(), 0);
            assert_eq!(
                b.queue_evts[0].read().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }

        // Disengage re-arms the queue eventfd instead of replaying inline;
        // the next event-loop turn performs the replay.
        block.lock().unwrap().set_queue_gate(false);
        assert_eq!(vq.used.idx.get(), 0);
        let ev_count = event_manager.run_with_timeout(100).unwrap();
        assert_eq!(ev_count, 1);
        assert_eq!(block.lock().unwrap().queues[0].len(), 0);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

        // A gate cycle without a deferred kick does not re-arm the eventfd.
        {
            let mut b = block.lock().unwrap();
            b.set_queue_gate(true);
            b.set_queue_gate(false);
        }
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);
        assert_eq!(vq.used.idx.get(), 1);
    }

    #[test]
    fn test_queue_gate_disengage_rearms_kick_without_touching_guest_memory() {
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        read_blk_req_descriptors(&vq);
        block
            .activate(mem.clone(), default_interrupt())
            .expect("device activation failed");
        let status_addr = write_request_descriptors(&mem, &vq);

        // Sentinel: a completed request would overwrite this with
        // VIRTIO_BLK_S_OK (0), so a surviving sentinel proves no status write.
        let status_sentinel: u32 = 0xAAAA_AAAA;
        mem.write_obj::<u32>(status_sentinel, status_addr).unwrap();

        block.set_queue_gate(true);
        block.queue_evts[0].write(1).unwrap();
        block.process_queue_event();
        assert_eq!(block.queues[0].len(), 1);

        // Disengage must return with guest memory untouched: no used-ring
        // write, no status write, and the deferred kick pending on the
        // queue eventfd for the event loop to pick up.
        block.set_queue_gate(false);
        assert_eq!(block.queues[0].len(), 1);
        assert_eq!(vq.used.idx.get(), 0);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), status_sentinel);
        assert_eq!(block.queue_evts[0].read().unwrap(), 1);
    }

    #[test]
    fn test_queue_gate_multiple_kicks_while_gated_replay_exactly_once() {
        let mut event_manager = EventManager::new().unwrap();
        let mut block = default_block(FileEngineType::Sync);
        let mem = default_mem();
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        set_queue(&mut block, 0, vq.create_queue());
        read_blk_req_descriptors(&vq);
        block
            .activate(mem.clone(), default_interrupt())
            .expect("device activation failed");
        let status_addr = write_request_descriptors(&mem, &vq);

        let block = Arc::new(Mutex::new(block));
        let _id = event_manager.add_subscriber(block.clone());

        block.lock().unwrap().set_queue_gate(true);
        for _ in 0..3 {
            block.lock().unwrap().queue_evts[0].write(1).unwrap();
            let ev_count = event_manager.run_with_timeout(100).unwrap();
            assert_eq!(ev_count, 1);
        }
        assert_eq!(block.lock().unwrap().queues[0].len(), 1);
        assert_eq!(vq.used.idx.get(), 0);

        // All gated kicks collapse into a single deferred replay.
        block.lock().unwrap().set_queue_gate(false);
        let ev_count = event_manager.run_with_timeout(100).unwrap();
        assert_eq!(ev_count, 1);
        assert_eq!(block.lock().unwrap().queues[0].len(), 0);
        assert_eq!(vq.used.idx.get(), 1);
        assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);

        // Nothing further is pending on the event loop.
        let ev_count = event_manager.run_with_timeout(50).unwrap();
        assert_eq!(ev_count, 0);
        assert_eq!(vq.used.idx.get(), 1);
    }
}
