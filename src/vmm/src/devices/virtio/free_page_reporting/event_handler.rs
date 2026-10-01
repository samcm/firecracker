// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use event_manager::{EventOps, Events, MutEventSubscriber};
use vmm_sys_util::epoll::EventSet;

use super::{DEFLATE_QUEUE, FreePageReporting, INFLATE_QUEUE, REPORTING_QUEUE};
use crate::devices::virtio::device::VirtioDevice;
use crate::logger::{error, warn};

impl FreePageReporting {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_INFLATE: u32 = 1;
    const PROCESS_DEFLATE: u32 = 2;
    const PROCESS_REPORTING: u32 = 3;

    fn register_runtime_events(&self, ops: &mut EventOps) {
        let mut queues = vec![
            (INFLATE_QUEUE, Self::PROCESS_INFLATE),
            (DEFLATE_QUEUE, Self::PROCESS_DEFLATE),
        ];
        if self.reporting_acked() {
            queues.push((REPORTING_QUEUE, Self::PROCESS_REPORTING));
        }
        for (queue, data) in queues {
            if let Err(err) = ops.add(Events::with_data(
                &self.queue_events()[queue],
                data,
                EventSet::IN,
            )) {
                error!("free page reporting: failed to register queue {queue}: {err}");
            }
        }
    }

    fn register_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("free page reporting: failed to register the activate event: {err}");
        }
    }

    fn process_activate_event(&self, ops: &mut EventOps) {
        if let Err(err) = self.activate_event().read() {
            error!("free page reporting: failed to consume the activate event: {err}");
        }
        self.register_runtime_events(ops);
        if let Err(err) = ops.remove(Events::with_data(
            self.activate_event(),
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!("free page reporting: failed to unregister the activate event: {err}");
        }
    }
}

impl MutEventSubscriber for FreePageReporting {
    fn init(&mut self, ops: &mut EventOps) {
        if self.is_activated() {
            self.register_runtime_events(ops);
        } else {
            self.register_activate_event(ops);
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let event_set = events.event_set();
        let source = events.data();
        if !event_set.contains(EventSet::IN) {
            warn!("free page reporting: unknown event {event_set:?} from source {source}");
            return;
        }
        if !self.is_activated() {
            warn!("free page reporting: spurious event {source} before activation");
            return;
        }
        match source {
            Self::PROCESS_ACTIVATE => self.process_activate_event(ops),
            Self::PROCESS_INFLATE => self.process_queue_event(INFLATE_QUEUE),
            Self::PROCESS_DEFLATE => self.process_queue_event(DEFLATE_QUEUE),
            Self::PROCESS_REPORTING => self.process_queue_event(REPORTING_QUEUE),
            _ => warn!("free page reporting: unknown event source {source}"),
        }
    }
}
