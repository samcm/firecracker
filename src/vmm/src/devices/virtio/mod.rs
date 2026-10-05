// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements virtio devices, queues, and transport mechanisms.

use std::any::Any;

use self::queue::QueueError;
use crate::devices::virtio::net::TapError;

pub mod block;
pub mod device;
pub mod free_page_reporting;
pub mod generated;
mod iov_deque;
pub mod iovec;
pub mod net;
pub mod persist;
pub mod queue;
pub mod rng;
pub mod test_utils;
pub mod transport;
pub mod vsock;

/// Maximum device multiplicities covered by the capture guard, in block/net/vsock/rng/reporting
/// order. Enforced for boot and across BOTH transports before restoring any device.
pub(crate) const GUARD_DEVICE_LIMITS: [usize; 5] = [2, 1, 1, 1, 1];

/// Maximum distinct 4-KiB guest pages host devices can write after dispatch closes, before
/// reopening. Includes already admitted asynchronous I/O; excludes the separately funded vCPU
/// observation-to-pause window. See docs/memversion-guard.md and the arithmetic regression below.
pub const MAX_POST_CLOSE_GUEST_PAGES: usize = 2804;

/// The configured device set exceeds the installed guest-write guard.
#[derive(Debug, thiserror::Error)]
pub enum DeviceGuardError {
    #[error("guest-write guard covers at most {limit} {device} devices, found {count}")]
    Count {
        device: &'static str,
        count: usize,
        limit: usize,
    },
    #[error("restored block must have advertised and negotiated SIZE_MAX and SEG_MAX")]
    BlockLimits,
}

pub(crate) fn validate_guard_counts(counts: [usize; 5]) -> Result<(), DeviceGuardError> {
    for ((device, count), limit) in ["block", "net", "vsock", "rng", "reporting"]
        .into_iter()
        .zip(counts)
        .zip(GUARD_DEVICE_LIMITS)
    {
        if count > limit {
            return Err(DeviceGuardError::Count {
                device,
                count,
                limit,
            });
        }
    }
    Ok(())
}

/// When the driver initializes the device, it lets the device know about the
/// completed stages using the Device Status Field.
///
/// These following consts are defined in the order in which the bits would
/// typically be set by the driver. INIT -> ACKNOWLEDGE -> DRIVER and so on.
///
/// This module is a 1:1 mapping for the Device Status Field in the virtio 1.0
/// specification, section 2.1.
mod device_status {
    pub const INIT: u32 = 0;
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const FAILED: u32 = 128;
    pub const FEATURES_OK: u32 = 8;
    pub const DRIVER_OK: u32 = 4;
    pub const DEVICE_NEEDS_RESET: u32 = 64;
}

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

/// Errors triggered when activating a VirtioDevice.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ActivateError {
    /// Wrong number of queue for virtio device: expected {expected}, got {got}
    QueueMismatch { expected: usize, got: usize },
    /// Failed to write to activate eventfd
    EventFd,
    /// Setting tap interface offload flags failed: {0}
    TapSetOffload(TapError),
    /// Error setting pointers in the queue: (0)
    QueueMemoryError(QueueError),
    /// The driver didn't acknowledge a required feature: {0}
    RequiredFeatureNotAcked(&'static str),
}

/// Trait that helps in upcasting an object to Any
pub trait AsAny {
    /// Return the immutable any encapsulated object.
    fn as_any(&self) -> &dyn Any;

    /// Return the mutable encapsulated any object.
    fn as_mut_any(&mut self) -> &mut dyn Any;
}

impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn guard_rejects_each_extra_device() {
        validate_guard_counts([0; 5]).unwrap();
        validate_guard_counts(GUARD_DEVICE_LIMITS).unwrap();
        for index in 0..GUARD_DEVICE_LIMITS.len() {
            let mut counts = GUARD_DEVICE_LIMITS;
            counts[index] += 1;
            let error = validate_guard_counts(counts).unwrap_err();
            let DeviceGuardError::Count { count, limit, .. } = error else {
                panic!()
            };
            assert_eq!(count, counts[index]);
            assert_eq!(limit, GUARD_DEVICE_LIMITS[index]);
        }
    }

    /// Locks the constants behind docs/memversion-guard.md to their production limits.
    /// This arithmetic test complements the per-device refill/close and pre-write cap tests;
    /// it is not, by itself, proof of a queue admission or memory-accounting invariant.
    #[test]
    fn post_close_guest_write_page_bound() {
        const PAGE: usize = 4096;
        // Any N separately placed spans totalling B bytes touch at most ceil(B/P) + 2N
        // pages: each span has at most two partially covered end pages. Do not merely round
        // aggregate payload bytes to pages: an adversarial chain can scatter tiny writes.
        let scatter = |bytes: usize, spans: usize| bytes.div_ceil(PAGE) + 2 * spans;
        let descriptors = usize::from(queue::FIRECRACKER_MAX_QUEUE_SIZE);
        let ring = (4 + 8 * descriptors + 2).div_ceil(PAGE) + 1;
        assert_eq!(ring, 2); // flags, idx, used elements, avail_event; arbitrary placement.

        // Include 32 async completions plus one already admitted synchronous/error/ID path.
        // Each block payload is contiguous; a one-byte status touches one extra page.
        let block = (block::virtio::MAX_INFLIGHT_REQUESTS as usize + 1)
            * ((block::virtio::MAX_REQUEST_BYTES as usize).div_ceil(PAGE) + 1 + 1)
            + block::virtio::BLOCK_NUM_QUEUES * ring;
        // One RX frame plus separately conservative num_buffers header and both rings.
        let net = scatter(net::MAX_BUFFER_SIZE, usize::from(net::NET_QUEUE_MAX_SIZE))
            + 2
            + net::NET_NUM_QUEUES * ring;
        // One RX packet (header included), a four-byte reset event, and all three rings.
        let vsock = scatter(
            (vsock::MAX_PKT_BUF_SIZE + vsock::VSOCK_PKT_HDR_SIZE) as usize,
            descriptors,
        ) + 2
            + 3 * ring;
        let rng = scatter(rng::device::MAX_ENTROPY_BYTES as usize, descriptors)
            + rng::RNG_NUM_QUEUES * ring;
        let reporting = free_page_reporting::NUM_QUEUES * ring;
        // VMGenID and VMClock each occupy at most two pages, including restore updates.
        let acpi = 4;
        assert_eq!((block, net, vsock, rng, reporting), (596, 535, 537, 530, 6));
        let default_pages: usize = [block, net, vsock, rng, reporting]
            .into_iter()
            .zip(GUARD_DEVICE_LIMITS)
            .map(|(pages, count)| pages * count)
            .sum::<usize>()
            + acpi;
        assert_eq!(default_pages, MAX_POST_CLOSE_GUEST_PAGES);
        assert_eq!(default_pages * PAGE, 11_485_184);

        // Check sparse/unaligned span geometry, including exact page sizes. This would fail
        // for the tempting but incorrect ceil(total_bytes/PAGE) payload-only formula.
        for len in [1, 2, 4095, 4096, 4097, 65536] {
            for offset in 0..PAGE {
                let actual = descriptors * (offset + len).div_ceil(PAGE);
                assert!(actual <= scatter(descriptors * len, descriptors));
            }
        }
    }
}
