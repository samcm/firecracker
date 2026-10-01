// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! A virtio balloon that implements free page reporting and nothing else.
//!
//! The guest's balloon driver reports blocks of memory it holds free. Nothing is discarded: guest
//! memory stays resident and locked, and the report is recorded against the dirty log instead, so
//! the next capture publishes those pages as zero rather than copying the bytes the guest no longer
//! cares about. The balloon target is always zero, so the inflate and deflate queues carry nothing.

pub mod device;
mod event_handler;
pub mod persist;

pub use self::device::{FreePageReporting, FreePageReportingError};

/// The inflate, deflate and reporting queues, in the order the virtio balloon specification
/// numbers them when no statistics or hinting feature is offered.
pub(crate) const NUM_QUEUES: usize = 3;
pub(crate) const INFLATE_QUEUE: usize = 0;
pub(crate) const DEFLATE_QUEUE: usize = 1;
pub(crate) const REPORTING_QUEUE: usize = 2;
