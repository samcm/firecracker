// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::ops::Deref;
use std::sync::Arc;

use vmm_sys_util::eventfd::EventFd;

use super::{DEFLATE_QUEUE, INFLATE_QUEUE, NUM_QUEUES, REPORTING_QUEUE};
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::queue::{FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::error;
use crate::vstate::memory::GuestMemoryMmap;
use crate::vstate::vm::KvmVm;

pub const FREE_PAGE_REPORTING_DEV_ID: &str = "free_page_reporting";

/// The virtio balloon feature bit for free page reporting.
pub(crate) const VIRTIO_BALLOON_F_REPORTING: u32 = 5;

/// The two configuration words the driver reads without hinting or poisoning: the balloon target
/// in pages, always zero here, and the size the driver reports it actually holds.
const CONFIG_SPACE_SIZE: usize = 8;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FreePageReportingError {
    /// Error while handling an event file descriptor: {0}
    EventFd(#[from] io::Error),
}

/// A virtio balloon whose only function is free page reporting.
#[derive(Debug)]
pub struct FreePageReporting {
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,

    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,

    /// The balloon size the driver last wrote back, in pages. Kept so a restored guest reads what
    /// it wrote; the target is zero, so it never changes from zero in a guest that follows it.
    actual_pages: u32,
    /// The machine whose dirty log a report is recorded against.
    vm: Arc<KvmVm>,
}

impl FreePageReporting {
    pub fn new(vm: Arc<KvmVm>) -> Result<Self, FreePageReportingError> {
        let queues = vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); NUM_QUEUES];
        Self::new_with_queues(queues, vm)
    }

    pub fn new_with_queues(
        queues: Vec<Queue>,
        vm: Arc<KvmVm>,
    ) -> Result<Self, FreePageReportingError> {
        let queue_events = (0..NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<EventFd>, io::Error>>()?;
        Ok(Self {
            avail_features: (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_BALLOON_F_REPORTING),
            acked_features: 0,
            activate_event: EventFd::new(libc::EFD_NONBLOCK)?,
            device_state: DeviceState::Inactive,
            queues,
            queue_events,
            actual_pages: 0,
            vm,
        })
    }

    /// Whether the driver negotiated reporting, which is what sets the third queue up at all.
    pub(crate) fn reporting_acked(&self) -> bool {
        self.acked_features & (1 << VIRTIO_BALLOON_F_REPORTING) != 0
    }

    pub(crate) fn actual_pages(&self) -> u32 {
        self.actual_pages
    }

    pub(crate) fn set_restored(&mut self, avail: u64, acked: u64, actual_pages: u32) {
        self.avail_features = avail;
        self.acked_features = acked;
        self.actual_pages = actual_pages;
    }

    pub(crate) fn activate_event(&self) -> &EventFd {
        &self.activate_event
    }

    fn signal_used_queue(&self, queue: usize) {
        let Ok(index) = u16::try_from(queue) else {
            return;
        };
        if let Err(err) = self
            .interrupt_trigger()
            .trigger(VirtioInterruptType::Queue(index))
        {
            error!("free page reporting: could not signal queue {queue}: {err:?}");
        }
    }

    /// Hands every buffer on an inflate or deflate queue straight back. The target is zero, so a
    /// guest that follows the device never sends one, and one that does gives nothing away: no
    /// page is discarded.
    pub(crate) fn process_balloon_queue(&mut self, queue: usize) -> Result<(), InvalidAvailIdx> {
        let mut used_any = false;
        loop {
            if self.defer_closed_queue(queue) {
                break;
            }
            let Some(head) = self.queues[queue].pop()? else {
                break;
            };
            #[cfg(test)]
            tests::after_queue_pop();
            if let Err(err) = self.queues[queue].add_used(head.index, 0) {
                error!("free page reporting: could not return a balloon buffer: {err}");
                break;
            }
            used_any = true;
        }
        self.queues[queue].advance_used_ring_idx();
        if used_any {
            self.signal_used_queue(queue);
        }
        Ok(())
    }

    /// Records every reported range against the dirty log, then returns the buffers. The guest
    /// holds the reported pages isolated until it sees its buffer used, so nothing writes them
    /// while they are recorded.
    pub(crate) fn process_reporting_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let mut used_any = false;
        loop {
            if self.defer_closed_queue(REPORTING_QUEUE) {
                break;
            }
            let Some(head) = self.queues[REPORTING_QUEUE].pop()? else {
                break;
            };
            #[cfg(test)]
            tests::after_queue_pop();
            let index = head.index;
            let mut next = Some(head);
            while let Some(desc) = next {
                if let Err(err) = self.vm.report_free(desc.addr, u64::from(desc.len)) {
                    error!(
                        "free page reporting: could not record {:#x}+{:#x}: {err}",
                        desc.addr.0, desc.len
                    );
                }
                next = desc.next_descriptor();
            }
            if let Err(err) = self.queues[REPORTING_QUEUE].add_used(index, 0) {
                error!("free page reporting: could not return a report buffer: {err}");
                break;
            }
            used_any = true;
        }
        self.queues[REPORTING_QUEUE].advance_used_ring_idx();
        if used_any {
            self.signal_used_queue(REPORTING_QUEUE);
        }
        Ok(())
    }

    fn defer_closed_queue(&self, queue: usize) -> bool {
        if !crate::vstate::farplane::dispatch::gate().is_closed() {
            return false;
        }
        // A saturated counter already holds a wake for reopen.
        if let Err(err) = self.queue_events[queue].write(1)
            && err.raw_os_error() != Some(libc::EAGAIN)
        {
            error!("free page reporting: could not defer queue {queue}: {err}");
        }
        true
    }

    pub(crate) fn process_queue_event(&mut self, queue: usize) {
        if let Err(err) = self.queue_events[queue].read() {
            error!("free page reporting: could not read queue {queue} event: {err}");
            return;
        }
        let result = if queue == REPORTING_QUEUE {
            self.process_reporting_queue()
        } else {
            self.process_balloon_queue(queue)
        };
        if let Err(err) = result {
            error!("free page reporting: queue {queue}: {err}");
        }
    }

    pub fn process_virtio_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_balloon_queue(INFLATE_QUEUE)?;
        self.process_balloon_queue(DEFLATE_QUEUE)?;
        if self.reporting_acked() {
            self.process_reporting_queue()?;
        }
        Ok(())
    }

    fn config_bytes(&self) -> [u8; CONFIG_SPACE_SIZE] {
        let mut config = [0u8; CONFIG_SPACE_SIZE];
        config[4..8].copy_from_slice(&self.actual_pages.to_le_bytes());
        config
    }
}

impl VirtioDevice for FreePageReporting {
    impl_device_type!(VirtioDeviceType::Balloon);

    fn id(&self) -> &str {
        FREE_PAGE_REPORTING_DEV_ID
    }

    fn queues(&self) -> &[Queue] {
        &self.queues
    }

    fn queues_mut(&mut self) -> &mut [Queue] {
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

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, data: &mut [u8]) {
        let config = self.config_bytes();
        let Ok(start) = usize::try_from(offset) else {
            return;
        };
        let Some(end) = start.checked_add(data.len()) else {
            return;
        };
        if end > config.len() {
            error!("free page reporting: config read {start}..{end} out of range");
            return;
        }
        data.copy_from_slice(&config[start..end]);
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        // Only `actual` is the driver's to write; it is one aligned little-endian word.
        if offset == 4 && data.len() == 4 {
            self.actual_pages = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        } else {
            error!(
                "free page reporting: refused a config write of {} bytes at {offset}",
                data.len()
            );
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        // A driver that did not negotiate reporting never sets its queue up.
        let used = if self.reporting_acked() {
            NUM_QUEUES
        } else {
            REPORTING_QUEUE
        };
        for queue in self.queues.iter_mut().take(used) {
            queue
                .initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }
        self.activate_event
            .write(1)
            .map_err(|_| ActivateError::EventFd)?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use vm_memory::GuestAddress;

    use super::*;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
    use crate::vstate::vm::tests::setup_vm_with_memory;

    thread_local! {
        static AFTER_QUEUE_POP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn after_queue_pop() {
        AFTER_QUEUE_POP.with_borrow_mut(|hook| {
            if let Some(hook) = hook.take() {
                hook();
            }
        });
    }

    #[test]
    #[ignore = "requires KVM and process-global dispatch gate; run exact test in isolation"]
    fn close_yields_reporting_loops_and_reopen_wakes_refill() {
        use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
        use crate::vstate::farplane::dispatch;
        use crate::vstate::memory::Bytes;

        for queue in [INFLATE_QUEUE, DEFLATE_QUEUE, REPORTING_QUEUE] {
            let (mut device, mem) = device_with_memory();
            let vqs: Vec<_> = (0..NUM_QUEUES)
                .map(|index| VirtQueue::new(GuestAddress(index as u64 * 0x1000), &mem, 16))
                .collect();
            for (index, vq) in vqs.iter().enumerate() {
                device.queues[index] = vq.create_queue();
            }
            device.set_acked_features(device.avail_features());
            device.activate(mem.clone(), default_interrupt()).unwrap();
            let vq = &vqs[queue];
            vq.dtable[0].set(0x40000, 0x40000, VIRTQ_DESC_F_WRITE, 0);
            vq.dtable[1].set(0x80000, 0x40000, VIRTQ_DESC_F_WRITE, 0);
            vq.avail.ring[0].set(0);
            vq.avail.ring[1].set(1);
            vq.avail.idx.set(1);
            mem.write_obj(0xaau8, GuestAddress(0x80000)).unwrap();
            let publish_mem = mem.clone();
            let avail_idx = vq.avail.idx.location;
            AFTER_QUEUE_POP.with_borrow_mut(|hook| {
                *hook = Some(Box::new(move || {
                    dispatch::gate().close();
                    publish_mem.write_obj(2u16, avail_idx).unwrap();
                }));
            });
            device.queue_events[queue].write(1).unwrap();
            device.process_queue_event(queue);
            assert_eq!(device.queues[queue].next_avail.0, 1);
            assert_eq!(vq.used.idx.get(), 1);
            assert_eq!(mem.read_obj::<u8>(GuestAddress(0x80000)).unwrap(), 0xaa);
            if queue == REPORTING_QUEUE {
                assert_eq!(device.vm.snapshot_free_log().unwrap()[0][2], 0);
            }
            dispatch::gate().open();
            device.process_queue_event(queue);
            assert_eq!(device.queues[queue].next_avail.0, 2);
            assert_eq!(vq.used.idx.get(), 2);
            // Reporting is metadata-only, including after reopen.
            assert_eq!(mem.read_obj::<u8>(GuestAddress(0x80000)).unwrap(), 0xaa);
        }
    }

    fn device_with_memory() -> (FreePageReporting, GuestMemoryMmap) {
        let vm = Arc::new(setup_vm_with_memory(0x10_0000));
        let mem = vm.guest_memory().clone();
        (FreePageReporting::new(vm).unwrap(), mem)
    }

    #[test]
    fn test_offers_reporting_and_nothing_else_beyond_version_one() {
        let (device, _) = device_with_memory();
        assert_eq!(
            device.avail_features(),
            (1 << VIRTIO_F_VERSION_1) | (1 << VIRTIO_BALLOON_F_REPORTING)
        );
        assert_eq!(device.device_type(), VirtioDeviceType::Balloon);
        assert_eq!(device.queues().len(), NUM_QUEUES);
    }

    #[test]
    fn test_config_reports_a_zero_target_and_keeps_what_the_driver_writes() {
        let (mut device, _) = device_with_memory();
        let mut word = [0xffu8; 4];
        device.read_config(0, &mut word);
        assert_eq!(word, [0; 4], "the target is always zero");
        device.write_config(4, &7u32.to_le_bytes());
        device.read_config(4, &mut word);
        assert_eq!(u32::from_le_bytes(word), 7);
        // A write to the target is refused.
        device.write_config(0, &9u32.to_le_bytes());
        device.read_config(0, &mut word);
        assert_eq!(word, [0; 4]);
        // A read past the two words leaves the buffer untouched.
        let mut beyond = [0xaau8; 4];
        device.read_config(8, &mut beyond);
        assert_eq!(beyond, [0xaa; 4]);
    }

    #[test]
    fn test_activation_without_reporting_sets_up_only_the_balloon_queues() {
        let (mut device, mem) = device_with_memory();
        let inflate = VirtQueue::new(GuestAddress(0), &mem, 16);
        let deflate = VirtQueue::new(GuestAddress(0x2000), &mem, 16);
        device.queues[INFLATE_QUEUE] = inflate.create_queue();
        device.queues[DEFLATE_QUEUE] = deflate.create_queue();
        device.set_acked_features(1 << VIRTIO_F_VERSION_1);
        device.activate(mem.clone(), default_interrupt()).unwrap();
        assert!(device.is_activated());
    }

    #[test]
    fn test_a_report_is_recorded_and_its_buffer_returned() {
        use crate::arch::host_page_size;
        use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;

        let (mut device, mem) = device_with_memory();
        let page = host_page_size() as u64;
        let inflate = VirtQueue::new(GuestAddress(0), &mem, 16);
        let deflate = VirtQueue::new(GuestAddress(0x1000), &mem, 16);
        let reporting = VirtQueue::new(GuestAddress(0x2000), &mem, 16);
        device.queues[INFLATE_QUEUE] = inflate.create_queue();
        device.queues[DEFLATE_QUEUE] = deflate.create_queue();
        device.queues[REPORTING_QUEUE] = reporting.create_queue();
        device.set_acked_features(device.avail_features());
        device.activate(mem.clone(), default_interrupt()).unwrap();

        // One report of 128 pages starting at page 64.
        reporting.dtable[0].set(
            64 * page,
            128 * u32::try_from(page).unwrap(),
            VIRTQ_DESC_F_WRITE,
            0,
        );
        reporting.avail.ring[0].set(0);
        reporting.avail.idx.set(1);
        device.process_reporting_queue().unwrap();

        reporting.check_used_elem(0, 0, 0);
        let free = device.vm.snapshot_free_log().unwrap();
        let recorded: u32 = free[0].iter().map(|word| word.count_ones()).sum();
        assert_eq!(recorded, 128);
        assert_eq!(free[0][1], u64::MAX);
        assert_eq!(free[0][2], u64::MAX);
    }
}
