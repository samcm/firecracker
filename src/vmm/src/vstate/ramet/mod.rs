// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Handshake that maps guest memory from pagemaster's backing plan.
pub mod backend;
mod background;
/// Capture half of the memory channel, served on the microVM's event loop.
pub mod capture;
/// Exclusion that stops event dispatch for the whole of a capture epoch.
pub mod dispatch;
/// Drive images handed over at claim to a Firecracker started before its sandbox was known.
pub mod drives;
pub(crate) mod memversion;
/// Wire format of the pagemaster memory channel.
pub mod protocol;

pub use backend::{BackendError, BackendState, RametBackend, RametState, seal_process, set_source_commit};
pub use capture::CaptureService;
pub use dispatch::{dispatch_slice, gate, outside_capture_epoch};
pub use memversion::set_exclusion_cap;
pub use protocol::{
    Arch, BackendReadyRegion, ChannelError, ErrorCode, FEATURE_IDENTITY, Header, MAGIC,
    MAX_DATAGRAM, Mode, MsgType, RegionRecord, VERSION,
};
