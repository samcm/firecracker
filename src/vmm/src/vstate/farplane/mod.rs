// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Handshake that maps guest memory from pagemaster's backing plan.
pub mod backend;
/// Capture half of the memory channel, served on the microVM's event loop.
pub mod capture;
/// Exclusion that stops event dispatch for the whole of a capture epoch.
pub mod dispatch;
/// Drive images handed over at claim to a Firecracker started before its sandbox was known.
pub mod drives;
pub(crate) mod memversion;
/// Research timing of one restore's phases (not for merge).
pub mod phases {
    use std::sync::Mutex;
    use std::time::Instant;

    static MARKS: Mutex<Vec<(&'static str, Instant)>> = Mutex::new(Vec::new());

    /// Marks the end of one phase.
    pub fn mark(name: &'static str) {
        MARKS
            .lock()
            .expect("Poisoned lock")
            .push((name, Instant::now()));
    }

    /// Logs every phase's duration since the previous mark, in microseconds, and clears them.
    pub fn report(label: &str) {
        let marks = std::mem::take(&mut *MARKS.lock().expect("Poisoned lock"));
        let mut line = String::new();
        for pair in marks.windows(2) {
            let us = pair[1].1.duration_since(pair[0].1).as_micros();
            line.push_str(&format!(" {}={}", pair[1].0, us));
        }
        if let (Some(first), Some(last)) = (marks.first(), marks.last()) {
            line.push_str(&format!(
                " total={}",
                last.1.duration_since(first.1).as_micros()
            ));
        }
        crate::logger::info!("{label}:{line}");
    }
}
/// Wire format of the pagemaster memory channel.
pub mod protocol;

pub use backend::{BackendError, BackendState, FarplaneBackend, FarplaneState, set_source_commit};
pub use capture::CaptureService;
pub use dispatch::{dispatch_slice, gate, outside_capture_epoch};
pub use protocol::{
    Arch, BackendReadyRegion, ChannelError, ErrorCode, FEATURE_IDENTITY, Header, MAGIC,
    MAX_DATAGRAM, Mode, MsgType, RegionRecord, VERSION,
};
