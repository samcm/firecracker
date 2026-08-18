// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Handshake that maps guest memory from pagemaster's backing plan.
pub mod backend;
/// Capture half of the memory channel, served on the microVM's event loop.
pub mod capture;
/// Wire format of the pagemaster memory channel.
pub mod protocol;

pub use backend::{BackendError, BackendState, FarplaneBackend, FarplaneState};
pub use capture::CaptureService;
pub use protocol::{
    Arch, BackendReadyRegion, ChannelError, ErrorCode, ExtentRecord, FEATURE_IDENTITY, Header,
    MAGIC, MAX_DATAGRAM, MAX_EXTENTS, MAX_PLAN_FDS, Mode, MsgType, RegionRecord, VERSION,
};
