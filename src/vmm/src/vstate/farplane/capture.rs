// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use utils::time::{ClockType, get_time_us};

use super::backend::{
    BackendState, MemoryChannel, VMSTATE_CAPACITY_BYTES, set_capture_buffers_armed,
    validate_buffer_fd, validate_clone_destination,
};
use super::protocol::{self, ChannelError, ErrorCode, Incoming, MsgType};
use super::{dispatch, memversion};
use crate::Vmm;
use crate::devices::virtio::block::virtio::write_log::WriteLog;
use crate::logger::{IncMetric, METRICS, error, info, warn};
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vmm_config::instance_info::VmState;

#[derive(Debug)]
struct CaptureBuffers {
    vmstate: File,
    disk_clone: Option<File>,
    /// The scratch disk cloned into `disk_clone` at arm, while the guest ran, and the log of
    /// what it has written since: the freeze then catches up only that.
    pre_cloned: Option<PreClone>,
    /// The standing destination this arm adopted, which a disarm returns to standing.
    adopted: Option<Adopted>,
}

/// A scratch clone taken before the freeze. It is never used on its own: the freeze either
/// catches it up from its write log or replaces it with a whole clone.
#[derive(Debug)]
struct PreClone {
    log: Arc<WriteLog>,
    /// How long the whole clone took, for the log.
    clone_us: u64,
    /// The scratch disk's extent count at the pre-clone, which a whole clone's cost follows.
    extents: u64,
}

/// A standing scratch clone: a funded destination Firecracker keeps equal to the scratch disk
/// except for the writes its log holds, so a capture that adopts it catches up only those.
#[derive(Debug)]
struct StandingDisk {
    dest: File,
    /// The destination's (st_dev, st_ino): a capture adopts it only when its own destination is
    /// this inode.
    inode: (u64, u64),
    log: Arc<WriteLog>,
    phase: StandingPhase,
}

#[derive(Debug)]
enum StandingPhase {
    /// The background clone is at `next` of `size`.
    Cloning {
        next: u64,
        size: u64,
        done: ChunkedClone,
        started_us: u64,
    },
    /// The destination equals the disk except for what the log holds and `pending`, ranges
    /// swapped out of the log that a background catch-up is applying.
    Ready {
        clone: ChunkedClone,
        pending: Vec<(u64, u64)>,
    },
}

/// A capture's adopted standing destination, kept so a disarm hands it back.
#[derive(Debug)]
struct Adopted {
    inode: (u64, u64),
    clone: ChunkedClone,
}

/// Ranges or bytes the log may hold before a background catch-up applies them.
const STANDING_CATCH_UP_RANGES: usize = 256;
const STANDING_CATCH_UP_BYTES: u64 = 16 << 20;
/// Ranges one background catch-up step clones, keeping each lock hold short.
const STANDING_CATCH_UP_STEP: usize = 64;

/// What a chunked pre-clone did, for its log line.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ChunkedClone {
    /// Microseconds from the first chunk to the last.
    clone_us: u64,
    /// Extents the walk met.
    extents: u64,
    /// FICLONERANGE calls.
    chunks: u32,
    /// The longest single chunk, the longest a guest disk write waited.
    longest_chunk_us: u64,
}

/// A catch-up runs only while its ranges stay under this share of the file's extents (in
/// tenths), and never past `CATCH_UP_MAX_RANGES`. Measured on XFS: a whole clone costs 14-18 µs
/// per extent and a rewritten range 36-55 µs on Zen 2 (9-12 and 23-27 on Zen 4), so the catch-up
/// beats the whole clone below ~0.35 ranges per extent. Both costs grow alike under load, so the
/// bound is a ratio rather than a fixed time.
const CATCH_UP_RANGES_PER_TEN_EXTENTS: u64 = 3;
/// Ranges no catch-up exceeds: 1024 rewritten ranges already cost ~40 ms on Zen 2.
const CATCH_UP_MAX_RANGES: u64 = 1024;
/// Merged ranges a write log holds before it gives up: past this no catch-up fits any clone.
const WRITE_LOG_MAX_RANGES: usize = 65_536;
/// Bytes a write log covers before it gives up and the freeze clones whole.
const WRITE_LOG_MAX_BYTES: u64 = 64 << 20;
/// Extents one pre-clone chunk covers. A clone holds the scratch inode's IO lock for its whole
/// length, so a guest disk write waits for at most one chunk: a whole clone costs 38-46 µs per
/// extent on fragmented production and Zen 2 sources, so 256 extents hold it ~10-12 ms.
const PRE_CLONE_CHUNK_EXTENTS: u32 = 256;
/// A pre-clone chunk this slow is logged with its range.
const SLOW_PRE_CLONE_CHUNK_US: u64 = 20_000;

/// A successful epoch owns the CREATE result before any reply is attempted.
#[derive(Debug, Default)]
struct EpochOrder {
    result: Option<(u64, Arc<OwnedFd>)>,
}

impl EpochOrder {
    fn open(&mut self) {
        self.result = None;
    }
}

/// What a Track request may do in a backend state: start a tracker only while the guest runs,
/// and report an existing one while it runs or is quiesced for a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackMode {
    Start,
    Report,
    Refuse,
}

fn track_mode(state: BackendState, tracked: bool) -> TrackMode {
    match (state, tracked) {
        (BackendState::Ready, false) => TrackMode::Start,
        (BackendState::Ready | BackendState::Quiesced, true) => TrackMode::Report,
        _ => TrackMode::Refuse,
    }
}

/// A refused WriteVMState: its code, and the cause the reply's detail names.
#[derive(Debug, PartialEq, Eq)]
struct VmstateRefusal {
    code: ErrorCode,
    detail: String,
}

impl VmstateRefusal {
    /// `step: err`, cut to the reply's detail field on a character boundary.
    fn failed(step: &str, err: impl std::fmt::Display) -> Self {
        let mut detail = format!("{step}: {err}");
        if detail.len() > protocol::ERROR_DETAIL_LEN {
            let mut end = protocol::ERROR_DETAIL_LEN;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        Self {
            code: ErrorCode::VmstateWriteFailed,
            detail,
        }
    }
}

/// Serialization and CREATE are one operation. Failed operations publish nothing and may retry
/// under a new request ID; successful operations never run twice in the same epoch.
fn serve_write_vmstate(
    order: &mut EpochOrder,
    capture: impl FnOnce() -> Result<(u64, OwnedFd), VmstateRefusal>,
) -> Result<(u64, Arc<OwnedFd>), VmstateRefusal> {
    if let Some(result) = &order.result {
        return Ok(result.clone());
    }
    let (bytes, version) = capture()?;
    let result = (bytes, Arc::new(version));
    order.result = Some(result.clone());
    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorIdentity {
    dev: libc::dev_t,
    ino: libc::ino_t,
}

fn descriptor_identity(fd: RawFd) -> Option<DescriptorIdentity> {
    // SAFETY: stat is plain data and fd remains owned by the incoming frame.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable for the duration of fstat.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return None;
    }
    Some(DescriptorIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandKey {
    msg: MsgType,
    body: Vec<u8>,
    descriptors: Option<Vec<DescriptorIdentity>>,
}

impl CommandKey {
    fn of(msg: MsgType, body: &[u8], fds: &[OwnedFd]) -> Self {
        Self {
            msg,
            body: body.to_vec(),
            descriptors: fds
                .iter()
                .map(|fd| descriptor_identity(fd.as_raw_fd()))
                .collect(),
        }
    }
    /// Unprovable identities are never exact. Order and ordinary fstat dev/ino are significant.
    fn is_exactly(&self, answered: &Self) -> bool {
        self.descriptors.is_some() && answered.descriptors.is_some() && self == answered
    }
}

#[derive(Debug)]
struct CachedReply {
    request_id: u64,
    command: CommandKey,
    msg: MsgType,
    body: Vec<u8>,
    version: Option<Arc<OwnedFd>>,
    /// The answer carried a version this cache no longer holds: replaying it would drop the
    /// descriptor, so a retry is refused instead.
    version_released: bool,
}

#[derive(Debug)]
enum FrameDisposition {
    Serve,
    Replay(MsgType, Vec<u8>, Option<Arc<OwnedFd>>),
    ReplayUnavailable,
    Reused,
}

/// Bounded exact-ID history outlives epoch resets. Evicted IDs are refused, never recaptured.
#[derive(Debug, Default)]
struct ReplyCache {
    answers: std::collections::VecDeque<CachedReply>,
    highest: u64,
}

impl ReplyCache {
    fn disposition(&self, request_id: u64, command: &CommandKey) -> FrameDisposition {
        if let Some(answer) = self
            .answers
            .iter()
            .find(|answer| answer.request_id == request_id)
        {
            if command.is_exactly(&answer.command) {
                if answer.version_released {
                    return FrameDisposition::ReplayUnavailable;
                }
                return FrameDisposition::Replay(
                    answer.msg,
                    answer.body.clone(),
                    answer.version.clone(),
                );
            }
            return FrameDisposition::Reused;
        }
        if request_id <= self.highest {
            return FrameDisposition::Reused;
        }
        FrameDisposition::Serve
    }
    /// Pagemaster sends one command at a time and the next only once the previous resolved,
    /// so a new request acknowledges every earlier answer: their version descriptors are
    /// released here, and with them the last reference this process holds to a generation
    /// pagemaster has let go. Otherwise each would live until 64 later answers evicted it.
    fn acknowledge_before(&mut self, request_id: u64) {
        for answer in self.answers.iter_mut() {
            if answer.request_id < request_id && answer.version.take().is_some() {
                answer.version_released = true;
            }
        }
    }
    fn record(
        &mut self,
        request_id: u64,
        command: CommandKey,
        msg: MsgType,
        body: Vec<u8>,
        version: Option<Arc<OwnedFd>>,
    ) {
        if self.answers.len() == protocol::MAX_RETRYABLE_REQUESTS {
            self.answers.pop_front();
        }
        self.answers.push_back(CachedReply {
            request_id,
            command,
            msg,
            body,
            version,
            version_released: false,
        });
        self.highest = self.highest.max(request_id);
    }
}

fn send_reply(
    sock: &UnixStream,
    msg: MsgType,
    request_id: u64,
    body: &[u8],
    version: Option<&Arc<OwnedFd>>,
) -> Result<(), ChannelError> {
    let rights: Vec<RawFd> = version.into_iter().map(|fd| fd.as_raw_fd()).collect();
    protocol::send_frame(sock, msg, request_id, body, &rights)
}

/// Record BEFORE sending, including errors: a failed send cannot undo an effect or drop its fd.
fn send_and_record(
    sock: &UnixStream,
    replies: &mut ReplyCache,
    pending: &mut Option<(u64, CommandKey)>,
    request_id: u64,
    msg: MsgType,
    body: Vec<u8>,
    version: Option<Arc<OwnedFd>>,
) -> Result<(), ChannelError> {
    if let Some((pending_id, command)) = pending.take()
        && pending_id == request_id
    {
        replies.record(request_id, command, msg, body.clone(), version.clone());
    }
    send_reply(sock, msg, request_id, &body, version.as_ref())
}

fn validate_command(msg: MsgType, body_len: usize, fd_count: usize) -> Result<(), ChannelError> {
    let (lens, counts): (&[usize], &[usize]) = match msg {
        MsgType::CaptureBuffers => (&[0], &[1, 2]),
        MsgType::Quiesce => (&[0], &[0]),
        MsgType::WriteVmstate => (&[0], &[1]),
        MsgType::Resume => (&[8], &[0]),
        MsgType::FreeSummary => (&[8], &[1]),
        MsgType::Track => (&[0, 8], &[1, 2]),
        MsgType::Refresh => (&[0], &[0]),
        MsgType::Untrack => (&[0], &[0]),
        MsgType::Rearm => (&[0], &[1]),
        MsgType::Disarm => (&[0, 1], &[0]),
        MsgType::Stand => (&[0], &[1]),
        _ => return Err(ChannelError::Malformed),
    };
    if !lens.contains(&body_len) || !counts.contains(&fd_count) {
        return Err(ChannelError::Malformed);
    }
    Ok(())
}

/// Capture commands run on a confined thread with dispatch gated throughout each paused epoch.
#[derive(Debug)]
pub struct CaptureService {
    channel: MemoryChannel,
    vmm: Arc<Mutex<Vmm>>,
    vm_info: VmInfo,
    buffers: Option<CaptureBuffers>,
    order: EpochOrder,
    replies: ReplyCache,
    pending: Option<(u64, CommandKey)>,
    /// The memversion device once the guest's memory is tracked: captures then fold only
    /// what changed, and refreshes run without a pause.
    tracker: Option<OwnedFd>,
    /// The last version a tracked capture or refresh produced, which the kernel's tracker
    /// also holds; kept to flatten it at the depth bound.
    standing: Option<Arc<OwnedFd>>,
    /// The standing scratch clone a `stand` handed over, while no capture has adopted it.
    stood: Option<StandingDisk>,
}

/// The 32-byte `tracked` reply body. An untracked reply is zero after `tracked`.
fn encode_tracked(info: &memversion::TrackInfo, included_pages: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(&info.tracked.to_le_bytes());
    if info.tracked == 0 {
        body.resize(32, 0);
        return body;
    }
    body.extend_from_slice(&info.depth.to_le_bytes());
    body.extend_from_slice(&info.dirty_pages.to_le_bytes());
    body.extend_from_slice(&info.standing_id.to_le_bytes());
    body.extend_from_slice(&included_pages.to_le_bytes());
    body
}

/// Whether a Track reply counts exactly what the next CREATE would newly retain. Only a
/// capture's freeze needs it, and only when the dirty count does not already fit the bound:
/// otherwise the dirty count is the reported upper bound and the freeze pays nothing.
fn counts_retained(state: BackendState, info: &memversion::TrackInfo, bound: u64) -> bool {
    state == BackendState::Quiesced && info.tracked != 0 && info.dirty_pages > bound
}

/// The tracked sample of a successful free summary: the included pages and standing version the
/// kernel counts against the summary's own words, or no count. `count` is TRACK_INFO2; the
/// deadline is checked before the reducer, before the ioctl and after it, so a late count is
/// never reported.
fn sample_tracked(
    tracker: Option<BorrowedFd<'_>>,
    regions: &[protocol::RegionRecord],
    summary: &[Vec<u64>],
    deadline: Instant,
    count: impl FnOnce(
        BorrowedFd<'_>,
        &[memversion::Exclusion],
    ) -> io::Result<Option<(memversion::TrackInfo, u64)>>,
) -> (u64, u64) {
    let in_time = || Instant::now() < deadline;
    let Some(tracker) = tracker else {
        return NO_TRACKED_SAMPLE;
    };
    if !in_time() {
        return NO_TRACKED_SAMPLE;
    }
    let Ok(exclusions) = memversion::geometry(regions)
        .and_then(|regions| memversion::exclusions_from_free(&regions, summary))
    else {
        return NO_TRACKED_SAMPLE;
    };
    if !in_time() {
        return NO_TRACKED_SAMPLE;
    }
    let counted = count(tracker, &exclusions.runs);
    if !in_time() {
        return NO_TRACKED_SAMPLE;
    }
    match counted {
        Ok(Some((info, included))) if info.tracked != 0 && info.standing_id != 0 => {
            (included, info.standing_id)
        }
        _ => NO_TRACKED_SAMPLE,
    }
}

/// The `capture_buffers_armed` body, LE u64 each: the adopted standing clone's extent count, its
/// clone duration and its longest chunk in microseconds, then how long the arm waited for the
/// standing clone to finish. Without one, extents u64::MAX and zeros: the freeze clones whole.
fn encode_capture_buffers_armed(pre_clone: Option<(u64, u64, u64)>, wait_us: u64) -> [u8; 32] {
    let (extents, clone_us, longest_us) = pre_clone.unwrap_or((u64::MAX, 0, 0));
    let mut body = [0; 32];
    body[..8].copy_from_slice(&extents.to_le_bytes());
    body[8..16].copy_from_slice(&clone_us.to_le_bytes());
    body[16..24].copy_from_slice(&longest_us.to_le_bytes());
    body[24..].copy_from_slice(&wait_us.to_le_bytes());
    body
}

/// A free summary's tracked sample when there is no count: included pages u64::MAX, id 0.
const NO_TRACKED_SAMPLE: (u64, u64) = (u64::MAX, 0);

/// The 24-byte `free_summary_done` body: popcount, included pages, standing version id.
fn encode_free_summary_done(pages: u64, included: u64, standing_id: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&pages.to_le_bytes());
    body.extend_from_slice(&included.to_le_bytes());
    body.extend_from_slice(&standing_id.to_le_bytes());
    body
}

/// The `refreshed` reply body.
fn encode_refreshed(info: &memversion::Info2) -> Vec<u8> {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(&info.own_pages.to_le_bytes());
    body.extend_from_slice(&info.new_pages.to_le_bytes());
    body.extend_from_slice(&info.depth.to_le_bytes());
    body.extend_from_slice(&info.nr_zero_runs.to_le_bytes());
    body.extend_from_slice(&info.folded_pages.to_le_bytes());
    body
}

impl CaptureService {
    /// Capture is served on its own confined thread because the paused API stops the event loop.
    pub fn spawn(
        channel: MemoryChannel,
        vmm: Arc<Mutex<Vmm>>,
        vm_info: VmInfo,
        filter: Arc<crate::seccomp::BpfProgram>,
    ) {
        std::thread::Builder::new()
            .name("fc_farplane".to_string())
            .spawn(move || {
                // The channel waits at most a second for a command, so a standing clone's
                // catch-up runs even while no command arrives. Set before the filter, which does
                // not admit setsockopt.
                if let Err(err) = channel.sock.set_read_timeout(Some(Duration::from_secs(1))) {
                    error!("Farplane channel could not set its receive timeout: {err}");
                    BackendState::fail();
                    return;
                }
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    error!("Farplane channel could not install its filter: {err}");
                    BackendState::fail();
                    return;
                }
                let mut service = Self {
                    channel,
                    vmm,
                    vm_info,
                    buffers: None,
                    order: EpochOrder::default(),
                    replies: ReplyCache::default(),
                    pending: None,
                    tracker: None,
                    standing: None,
                    stood: None,
                };
                loop {
                    if BackendState::load() == BackendState::ChannelFailed {
                        return;
                    }
                    if let Err(err) = service.serve_or_work() {
                        error!("Farplane memory channel failed: {err}");
                        BackendState::fail();
                        return;
                    }
                }
            })
            .expect("Failed to spawn the farplane memory channel thread");
    }

    /// Serves the next command, or with none waiting runs one step of background work: a
    /// command waits at most one chunk behind it.
    fn serve_or_work(&mut self) -> Result<(), ChannelError> {
        let busy = self.has_background_work();
        match protocol::try_recv_frame(&self.channel.sock, busy)? {
            Some(incoming) => self.serve(incoming),
            None => {
                if busy {
                    self.background_step();
                }
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn serve_one(&mut self) -> Result<(), ChannelError> {
        let incoming = protocol::recv_frame(&self.channel.sock)?;
        self.serve(incoming)
    }

    fn serve(&mut self, mut incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if request_id == 0 {
            return Err(ChannelError::Malformed);
        }
        let msg = incoming.header.msg();
        validate_command(msg, incoming.body.len(), incoming.fds.len())?;
        let command = CommandKey::of(msg, &incoming.body, &incoming.fds);
        match self.replies.disposition(request_id, &command) {
            FrameDisposition::Serve => self.replies.acknowledge_before(request_id),
            FrameDisposition::Replay(msg, body, version) => {
                // A frame answered without being served closes what it carried before the
                // answer goes out: a reply proves Firecracker holds no descriptor it delivered.
                drop(std::mem::take(&mut incoming.fds));
                return send_reply(&self.channel.sock, msg, request_id, &body, version.as_ref());
            }
            FrameDisposition::ReplayUnavailable => {
                drop(std::mem::take(&mut incoming.fds));
                return protocol::send_frame(
                    &self.channel.sock,
                    MsgType::Error,
                    request_id,
                    &protocol::encode_error(ErrorCode::ReplayUnavailable, msg, ""),
                    &[],
                );
            }
            FrameDisposition::Reused => {
                drop(std::mem::take(&mut incoming.fds));
                return protocol::send_frame(
                    &self.channel.sock,
                    MsgType::Error,
                    request_id,
                    &protocol::encode_error(ErrorCode::RequestIdReused, msg, ""),
                    &[],
                );
            }
        }
        self.pending = Some((request_id, command));
        match msg {
            MsgType::CaptureBuffers => self.arm_buffers(incoming),
            MsgType::Quiesce => self.quiesce(request_id),
            MsgType::WriteVmstate => self.write_vmstate(incoming),
            MsgType::Resume => self.resume(request_id, protocol::parse_resume(&incoming.body)?),
            MsgType::FreeSummary => self.free_summary(incoming),
            MsgType::Track => self.track(incoming),
            MsgType::Refresh => self.refresh(request_id),
            MsgType::Untrack => self.untrack(request_id),
            MsgType::Rearm => self.rearm(incoming),
            MsgType::Disarm => self.disarm(request_id, &incoming.body),
            MsgType::Stand => self.stand(incoming),
            _ => Err(ChannelError::Malformed),
        }
    }

    fn free_summary(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let budget = protocol::parse_free_summary_budget(&incoming.body)?;
        let deadline = Instant::now() + Duration::from_micros(budget);
        let request_id = incoming.header.request_id;
        let [fd] = <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        let mut summary_words = None;
        let result = serve_free_summary(
            BackendState::load(),
            &File::from(fd),
            &self.channel.regions,
            deadline,
            || {
                // Never hold the VMM lock during bitmap reads or IO. A pressure pause must not
                // wait behind an advisory scan. Busy/poisoned locks are advisory refusals too.
                let vm = self
                    .vmm
                    .try_lock()
                    .ok()
                    .and_then(|vmm| vmm.kvm_vm().cloned())
                    .ok_or(ErrorCode::FreeSummaryUnavailable)?;
                let summary = vm
                    .free_summary_until(deadline)
                    .map_err(|_| ErrorCode::FreeSummaryUnavailable)?;
                summary_words = Some(summary.clone());
                Ok(summary)
            },
        );
        match result {
            Ok(pages) => {
                let (included, standing_id) = summary_words.map_or(NO_TRACKED_SAMPLE, |words| {
                    self.tracked_sample(&words, deadline)
                });
                self.reply(
                    request_id,
                    MsgType::FreeSummaryDone,
                    &encode_free_summary_done(pages, included, standing_id),
                )
            }
            Err(code) => self.reject(request_id, code, MsgType::FreeSummary),
        }
    }

    /// What the next quiesced CREATE would fold against the exclusions it would get now, and the
    /// standing version that count is against: the estimate pagemaster sizes a tracked capture's
    /// charge by.
    ///
    /// The free summary is already the capture's exclusion input: per page, reported free and not
    /// written since (no KVM, pending or host-write evidence), read under the summary's own
    /// try_locks. So the sample reads no log and takes no lock of its own, and retires no
    /// evidence: a later capture sees exactly what it would have. It reduces those words with the
    /// capture's builder and asks MV_IOC_TRACK_INFO2 for the count. The budget is cooperative:
    /// the deadline is checked before and after each step, and a count that arrives after it is
    /// not reported. TRACK_INFO2 itself cannot be preempted. Anything short of the kernel's count
    /// in time is no count, and it never falls back to the residency walk.
    fn tracked_sample(&self, summary: &[Vec<u64>], deadline: Instant) -> (u64, u64) {
        let started = Instant::now();
        let sample = sample_tracked(
            self.tracker.as_ref().map(AsFd::as_fd),
            &self.channel.regions,
            summary,
            deadline,
            memversion::track_sample,
        );
        if sample != NO_TRACKED_SAMPLE {
            info!(
                "Farplane sampled {} pages for the next CREATE in {} us",
                sample.0,
                started.elapsed().as_micros()
            );
        }
        sample
    }

    /// Tracks the guest's memory from now on. Runs while the guest runs: the kernel walks the
    /// present pages once under the mmap write lock, which stalls only guest faults. A second
    /// request reports the existing tracker, also while the guest is quiesced for a capture:
    /// that report allocates nothing and is what pagemaster refuses an over-budget capture by,
    /// before CREATE moves the standing version. Starting a tracker needs a running guest.
    ///
    /// The reply's included pages is what that capture would charge: while quiesced, a dirty
    /// count over the request's bound is replaced by the exact count CREATE would newly retain,
    /// which leaves out pages the guest reported free and has not written since.
    fn track(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        let bound = protocol::parse_track_bound(&incoming.body)?;
        let state = BackendState::load();
        if track_mode(state, self.tracker.is_some()) == TrackMode::Refuse {
            return self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track);
        }
        let mut fds = incoming.fds.into_iter();
        let device = fds.next().ok_or(ChannelError::FdCountMismatch)?;
        let base = fds.next();
        if self.tracker.is_none() {
            let started = Instant::now();
            if let Err(err) = memversion::geometry(&self.channel.regions).and_then(|regions| {
                memversion::track_guest(device.as_fd(), &regions, base.as_ref().map(AsFd::as_fd))
            }) {
                error!("Farplane could not track guest memory: {err}");
                return self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track);
            }
            info!(
                "Farplane tracks guest memory (base={}) after {} us",
                base.is_some(),
                started.elapsed().as_micros()
            );
            self.tracker = Some(device);
        }
        let tracker = self.tracker.as_ref().expect("tracker set above");
        let info = match memversion::track_info(tracker.as_fd()) {
            Ok(info) => info,
            Err(err) => {
                error!("Farplane could not read the memory tracker: {err}");
                return self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track);
            }
        };
        let (info, included) = if counts_retained(state, &info, bound) {
            let started = Instant::now();
            match self.included_pages(tracker.as_fd()) {
                Ok(included) => {
                    let (info, by) = match included {
                        // The kernel's count is against the tracker state it read with it.
                        memversion::Included::Kernel(fresh, _) => (fresh, "kernel"),
                        memversion::Included::Resident(_) => (info, "residency"),
                    };
                    info!(
                        "Farplane counted {} of {} dirty pages for CREATE by {by} in {} us",
                        included.pages(),
                        info.dirty_pages,
                        started.elapsed().as_micros()
                    );
                    (info, included.pages())
                }
                Err(err) => {
                    error!("Farplane could not count the pages CREATE would retain: {err}");
                    return self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track);
                }
            }
        } else {
            (info, info.dirty_pages)
        };
        self.reply(
            request_id,
            MsgType::Tracked,
            &encode_tracked(&info, included),
        )
    }

    /// The pages a quiesced tracked CREATE would fold now, counted against the exclusions
    /// `write_vmstate` would pass, built the same way under the VMM lock. Both log snapshots
    /// are reads; neither retires dirty evidence.
    fn included_pages(&self, tracker: BorrowedFd<'_>) -> io::Result<memversion::Included> {
        let regions = memversion::geometry(&self.channel.regions)?;
        let exclusions = {
            let vmm = self.vmm.lock().expect("Poisoned lock");
            let kvm_vm = vmm.kvm_vm().ok_or_else(|| io::Error::other("no KVM VM"))?;
            let dirty = kvm_vm.snapshot_dirty_log().map_err(io::Error::other)?;
            let free = kvm_vm.snapshot_free_log().map_err(io::Error::other)?;
            memversion::exclusions(&regions, &free, &dirty)?
        };
        memversion::included_pages(tracker, &regions, &exclusions.runs)
    }

    /// Folds what the guest wrote since the standing version into a new one, without a pause.
    /// The result is a base for the next fork's fold, never a capture: a running guest has no
    /// consistent instant. Optional: a refusal leaves the guest running and the next fork
    /// folds more.
    fn refresh(&mut self, request_id: u64) -> Result<(), ChannelError> {
        let Some(tracker) = self.tracker.as_ref() else {
            return self.reject(request_id, ErrorCode::RefreshFailed, MsgType::Refresh);
        };
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::RefreshFailed, MsgType::Refresh);
        }
        let started = Instant::now();
        let refreshed = memversion::geometry(&self.channel.regions)
            .and_then(|regions| {
                memversion::refresh(
                    tracker.as_fd(),
                    &regions,
                    self.standing.as_ref().map(|fd| fd.as_fd()),
                )
            })
            .and_then(|version| Ok((memversion::info2(version.as_fd())?, version)));
        match refreshed {
            Ok((info, version)) => {
                info!(
                    "Farplane refreshed the standing version in {} us: own={} folded={} depth={}",
                    started.elapsed().as_micros(),
                    info.own_pages,
                    info.folded_pages,
                    info.depth
                );
                let version = Arc::new(version);
                self.standing = Some(version.clone());
                self.answer_with_version(
                    request_id,
                    MsgType::Refreshed,
                    encode_refreshed(&info),
                    Some(version),
                )
            }
            Err(err) => {
                error!("Farplane could not refresh the standing version: {err}");
                self.reject(request_id, ErrorCode::RefreshFailed, MsgType::Refresh)
            }
        }
    }

    /// Stops tracking and releases the standing version, the cheapest memory a pressure path
    /// can give back without pausing the guest. The versions stay alive while anything else
    /// holds them; pagemaster releases their charge on the kernel's last-holder receipt, not on
    /// this reply. Untracking an untracked guest reports the same state.
    fn untrack(&mut self, request_id: u64) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::UntrackFailed, MsgType::Untrack);
        }
        if let Some(tracker) = self.tracker.as_ref() {
            if let Err(err) = memversion::untrack(tracker.as_fd()) {
                error!("Farplane could not untrack guest memory: {err}");
                return self.reject(request_id, ErrorCode::UntrackFailed, MsgType::Untrack);
            }
            self.tracker = None;
            self.standing = None;
            info!("Farplane untracked guest memory");
        }
        self.reply(
            request_id,
            MsgType::Tracked,
            &encode_tracked(&memversion::TrackInfo::default(), 0),
        )
    }

    /// Moves the tracker onto `flat`, the flat version pagemaster made of the standing version
    /// after a transient capture published, so the next capture folds onto a version its source
    /// keeps instead of one that leaves the node. Runs while the guest runs: the kernel swaps one
    /// reference under the tracker's lock and touches no dirty bit, which stay valid because
    /// `flat` holds the same content. The kernel refuses a version whose content is not the
    /// standing version's, so a standing version moved by another CREATE is never replaced. Any
    /// refusal changes nothing and pagemaster untracks instead.
    fn rearm(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        let [flat] = <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        let Some(tracker) = self.tracker.as_ref() else {
            return self.reject(request_id, ErrorCode::RearmFailed, MsgType::Rearm);
        };
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::RearmFailed, MsgType::Rearm);
        }
        if let Err(err) = memversion::rebase(tracker.as_fd(), flat.as_fd()) {
            error!("Farplane could not rearm the memory tracker: {err}");
            return self.reject(request_id, ErrorCode::RearmFailed, MsgType::Rearm);
        }
        info!("Farplane rearmed the memory tracker on a flat version");
        self.standing = Some(Arc::new(flat));
        self.reply(request_id, MsgType::Rearmed, &[])
    }

    fn arm_buffers(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::CaptureBuffers);
        }
        let mut fds = incoming.fds;
        let destination = (fds.len() == 2).then(|| fds.remove(1));
        let [vmstate] = <[_; 1]>::try_from(fds).map_err(|_| ChannelError::FdCountMismatch)?;
        if let Err(code) = validate_buffer_fd(vmstate.as_raw_fd(), VMSTATE_CAPACITY_BYTES) {
            return self.reject(request_id, code, MsgType::CaptureBuffers);
        }
        if let Some(destination) = &destination
            && let Err(code) =
                accept_clone_destination(destination.as_raw_fd(), self.scratch_descriptor())
        {
            return self.reject(request_id, code, MsgType::CaptureBuffers);
        }
        let mut disk_clone = destination.map(File::from);
        // A capture whose destination is the standing clone's inode adopts it; any other arm
        // leaves no standing clone and no recording behind, and its freeze clones whole.
        let wanted = disk_clone
            .as_ref()
            .and_then(|d| inode_of(d.as_raw_fd()).ok());
        let (pre_cloned, adopted, wait_us) = match self.stood.take() {
            Some(stood) if Some(stood.inode) == wanted => match self.adopt(stood) {
                Ok((dest, pre, adopted, wait_us)) => {
                    disk_clone = Some(dest);
                    (Some(pre), Some(adopted), wait_us)
                }
                Err(err) => {
                    error!("Farplane could not adopt the standing scratch clone: {err}");
                    self.stop_write_log();
                    (None, None, 0)
                }
            },
            _ => {
                self.stop_write_log();
                (None, None, 0)
            }
        };
        let body = encode_capture_buffers_armed(
            adopted
                .as_ref()
                .map(|a| (a.clone.extents, a.clone.clone_us, a.clone.longest_chunk_us)),
            wait_us,
        );
        self.buffers = Some(CaptureBuffers {
            vmstate: File::from(vmstate),
            disk_clone,
            pre_cloned,
            adopted,
        });
        set_capture_buffers_armed(true);
        self.reply(request_id, MsgType::CaptureBuffersArmed, &body)
    }

    fn adopt(&mut self, stood: StandingDisk) -> Result<(File, PreClone, Adopted, u64), io::Error> {
        let scratch = self
            .scratch_descriptor()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        adopt_standing(stood, scratch)
    }

    /// Takes a funded, empty destination as the standing scratch clone: starts the write log,
    /// then clones the disk into it in the background, between commands. An earlier standing
    /// clone is dropped. Refused while a capture is armed or quiesced.
    fn stand(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        let [dest] = <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        // Every refusal closes the descriptor before it answers: a reply proves Firecracker
        // holds no reference to a destination it did not take.
        if BackendState::load() != BackendState::Ready || self.buffers.is_some() {
            drop(dest);
            return self.reject(request_id, ErrorCode::CaptureOrderViolation, MsgType::Stand);
        }
        let (scratch, log) = {
            let vmm = self.vmm.lock().expect("Poisoned lock");
            (vmm.scratch_descriptor(), vmm.scratch_write_log())
        };
        let (Some(scratch), Some(log)) = (scratch, log) else {
            drop(dest);
            return self.reject(request_id, ErrorCode::NoScratchDrive, MsgType::Stand);
        };
        if let Err(code) = validate_clone_destination(dest.as_raw_fd()) {
            drop(dest);
            return self.reject(request_id, code, MsgType::Stand);
        }
        let ready = file_size(dest.as_raw_fd())
            .and_then(|len| {
                if len == 0 {
                    Ok(())
                } else {
                    Err(io::Error::other("the standing destination is not empty"))
                }
            })
            .and_then(|()| Ok((inode_of(dest.as_raw_fd())?, file_size(scratch)?)));
        let (inode, size) = match ready {
            Ok(ready) => ready,
            Err(err) => {
                error!("Farplane refused a standing destination: {err}");
                drop(dest);
                return self.reject(request_id, ErrorCode::BadCloneDestination, MsgType::Stand);
            }
        };
        // The earlier standing clone, if any, is closed before the reply.
        self.stood = None;
        log.start(WRITE_LOG_MAX_RANGES, WRITE_LOG_MAX_BYTES);
        self.stood = Some(StandingDisk {
            dest: File::from(dest),
            inode,
            log,
            phase: StandingPhase::Cloning {
                next: 0,
                size,
                done: ChunkedClone::default(),
                started_us: get_time_us(ClockType::Monotonic),
            },
        });
        self.reply(request_id, MsgType::Standing, &[])
    }

    fn has_background_work(&self) -> bool {
        self.stood.as_ref().is_some_and(standing_has_work)
    }

    /// One step of standing work. A failure drops the standing clone; the next capture's freeze
    /// clones whole.
    fn background_step(&mut self) {
        let Some(mut stood) = self.stood.take() else {
            return;
        };
        match self.advance(&mut stood) {
            Ok(()) => self.stood = Some(stood),
            Err(err) => {
                error!("Farplane dropped the standing scratch clone: {err}");
                stood.log.stop();
            }
        }
    }

    fn advance(&self, stood: &mut StandingDisk) -> Result<(), io::Error> {
        let scratch = self
            .scratch_descriptor()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))?;
        advance_standing(stood, scratch)
    }

    /// Drops an armed capture that was never quiesced: its vmstate buffer and clone destination.
    /// An adopted standing clone returns to standing with its log still recording, so a
    /// readmitted capture adopts it again; body {1} drops the standing clone too and stops the
    /// log. On a ready backend with nothing it names held it is refused `not_armed`; a quiesced
    /// capture, which it leaves only by `resume`, is refused `already_quiesced`.
    fn disarm(&mut self, request_id: u64, body: &[u8]) -> Result<(), ChannelError> {
        let drop_standing = body == [1];
        // `not_armed` is a proof that nothing it names is held, so it answers only a ready
        // backend: a quiesced capture still owns its buffers and is refused as such.
        match BackendState::load() {
            BackendState::Ready => {}
            BackendState::Quiesced => {
                return self.reject(request_id, ErrorCode::AlreadyQuiesced, MsgType::Disarm);
            }
            _ => {
                return self.reject(
                    request_id,
                    ErrorCode::CaptureOrderViolation,
                    MsgType::Disarm,
                );
            }
        }
        let held = self.buffers.is_some() || (drop_standing && self.stood.is_some());
        if !held {
            return self.reject(request_id, ErrorCode::NotArmed, MsgType::Disarm);
        }
        if let Some(buffers) = self.buffers.take()
            && let (Some(adopted), Some(dest), Some(pre)) =
                (buffers.adopted, buffers.disk_clone, buffers.pre_cloned)
        {
            self.stood = Some(StandingDisk {
                dest,
                inode: adopted.inode,
                log: pre.log,
                phase: StandingPhase::Ready {
                    clone: adopted.clone,
                    pending: Vec::new(),
                },
            });
        }
        if drop_standing {
            self.stood = None;
            self.stop_write_log();
        } else if self.stood.is_none() {
            self.stop_write_log();
        }
        set_capture_buffers_armed(false);
        info!(
            "Farplane disarmed the capture{}",
            if drop_standing {
                " and dropped the standing scratch clone"
            } else {
                ""
            }
        );
        self.reply(request_id, MsgType::Disarmed, &[])
    }

    fn stop_write_log(&self) {
        if let Some(log) = self.vmm.lock().expect("Poisoned lock").scratch_write_log() {
            log.stop();
        }
    }

    fn scratch_descriptor(&self) -> Option<RawFd> {
        self.vmm.lock().expect("Poisoned lock").scratch_descriptor()
    }

    /// Close dispatch, pause, drain, then clone: no guest-memory or disk writer crosses the cut.
    fn quiesce(&mut self, request_id: u64) -> Result<(), ChannelError> {
        match BackendState::load() {
            BackendState::Ready => {}
            BackendState::Quiesced => {
                return self.reject(request_id, ErrorCode::AlreadyQuiesced, MsgType::Quiesce);
            }
            _ => return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Quiesce),
        }
        // Each stage's end, in microseconds from the quiesce request, for one timing line.
        let started = Instant::now();
        let at = || u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
        // Wait for in-flight handlers before taking the VMM lock they may need.
        dispatch::gate().close();
        let gate_us = at();
        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        let lock_us = at();
        let were_running = vmm.instance_info.state == VmState::Running;
        if were_running && let Err(err) = vmm.pause_vm() {
            error!("Farplane quiesce could not pause the vCPUs: {err}");
            drop(vmm);
            dispatch::gate().open();
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        let pause_us = at();
        if let Err(err) = vmm.drain_guest_memory_writers() {
            error!("Farplane quiesce could not stop every guest-memory writer: {err}");
            hand_back_source(vmm, were_running);
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        let destination = self
            .buffers
            .as_ref()
            .and_then(|buffers| buffers.disk_clone.as_ref())
            .map(|file| file.as_raw_fd());
        // A pre-clone is caught up at most once; a retried quiesce clones whole.
        let pre_cloned = self
            .buffers
            .as_mut()
            .and_then(|buffers| buffers.pre_cloned.take());
        if let Some(destination) = destination {
            match vmm
                .scratch_descriptor()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
                .and_then(|scratch| finish_scratch_clone(destination, scratch, pre_cloned))
            {
                Ok((elapsed_us, how)) => {
                    info!("Farplane quiesce cloned the scratch disk in {elapsed_us} us ({how})");
                    METRICS.farplane.disk_clones.inc();
                    METRICS.farplane.disk_clone_agg.record_us(elapsed_us);
                }
                Err(err) => {
                    error!("Farplane quiesce could not clone the scratch disk: {err}");
                    METRICS.farplane.disk_clone_failures.inc();
                    hand_back_source(vmm, were_running);
                    return self.reject(request_id, ErrorCode::DiskCloneFailed, MsgType::Quiesce);
                }
            }
        }
        let drain_clone_us = at();
        drop(vmm);
        self.order.open();
        BackendState::Quiesced.store();
        info!(
            "Farplane quiesce timing gate_close_us={gate_us} vmm_lock_us={lock_us} \
             vcpu_pause_us={pause_us} drain_and_clone_us={drain_clone_us} were_running={were_running}"
        );
        self.reply(
            request_id,
            MsgType::Quiesced,
            &u32::from(were_running).to_le_bytes(),
        )
    }

    fn write_vmstate(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::WriteVmstate);
        }
        if self.buffers.is_none() {
            return self.reject(
                request_id,
                ErrorCode::NoCaptureBuffers,
                MsgType::WriteVmstate,
            );
        }
        let [device] =
            <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        let Self {
            channel,
            vmm,
            vm_info,
            buffers,
            order,
            tracker,
            ..
        } = self;
        let result = serve_write_vmstate(order, || {
            // Keep the lock through device preparation, serialization and CREATE.
            let mut vmm = vmm.lock().expect("Poisoned lock");
            let state = vmm.save_state(vm_info).map_err(|err| {
                error!("Farplane capture could not save the microVM state: {err}");
                VmstateRefusal::failed("save_state", err)
            })?;
            let bytes = serialize_vmstate(&mut buffers.as_mut().unwrap().vmstate, state)?;
            vmm.mark_virtio_queues_dirty();
            let version = (|| -> io::Result<OwnedFd> {
                let kvm_vm = vmm.kvm_vm().ok_or_else(|| io::Error::other("no KVM VM"))?;
                let dirty = kvm_vm.snapshot_dirty_log().map_err(io::Error::other)?;
                let free = kvm_vm.snapshot_free_log().map_err(io::Error::other)?;
                let regions = memversion::geometry(&channel.regions)?;
                let memversion::Exclusions {
                    runs: exclusions,
                    found,
                    dropped_pages,
                } = memversion::exclusions(&regions, &free, &dirty)?;
                // One line per capture, so how close guests come to the run limit is visible.
                info!(
                    "Farplane capture excludes {} of {found} free runs (cap {}); {dropped_pages} \
                     free pages in dropped runs are copied",
                    exclusions.len(),
                    memversion::exclusion_cap()
                );
                if tracker.is_none() {
                    return memversion::create(device.as_fd(), &regions, &exclusions);
                }
                // A tracked source folds only the pages written since the standing version.
                // A failed fold leaves the tracker marking everything, so a whole copy is
                // still exact and the next fold catches up.
                memversion::create_tracked(
                    device.as_fd(),
                    &regions,
                    &exclusions,
                    memversion::Fold::Quiesced,
                )
                .or_else(|err| {
                    error!("Farplane tracked capture fell back to a whole copy: {err}");
                    memversion::create(device.as_fd(), &regions, &exclusions)
                })
            })()
            .map_err(|err| {
                error!("Farplane capture could not create the memory version: {err}");
                VmstateRefusal::failed("memory version", err)
            })?;
            // Deliberately do not clear dirty logs: accumulating evidence is conservative and
            // avoids a fallible step after CREATE. Retirement can be optimized separately.
            Ok((bytes, version))
        });
        match result {
            Ok((bytes, version)) => {
                let answered = self.answer_with_version(
                    request_id,
                    MsgType::VmstateWritten,
                    bytes.to_le_bytes().to_vec(),
                    Some(version.clone()),
                );
                // After the reply: only the version the tracker now stands on is a refresh's
                // flatten source, not a whole copy made after a failed fold.
                if let Some(tracker) = &self.tracker
                    && let Ok(track) = memversion::track_info(tracker.as_fd())
                    && memversion::info2(version.as_fd())
                        .is_ok_and(|info| info.id == track.standing_id)
                {
                    self.standing = Some(version);
                }
                answered
            }
            Err(refusal) => self.reject_with(
                request_id,
                refusal.code,
                MsgType::WriteVmstate,
                &refusal.detail,
            ),
        }
    }

    /// Ends the capture epoch. With `keep_standing`, for a flip pagemaster refused, a destination
    /// the capture adopted from standing returns to standing: the freeze made it the disk as it
    /// stands, nothing published it, and the write log restarts here, while the vCPUs are
    /// stopped and device handlers are gated, so the next capture adopts it with nothing to wait
    /// for. A destination not adopted from standing is closed either way, as is every
    /// destination without `keep_standing`.
    fn resume(&mut self, request_id: u64, body: protocol::ResumeBody) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Resume);
        }
        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        let keep = body.keep_standing
            && self
                .buffers
                .as_ref()
                .is_some_and(|b| b.adopted.is_some() && b.disk_clone.is_some());
        let log = if keep { vmm.scratch_write_log() } else { None };
        // Before any vCPU or device handler can write the disk again.
        if let Some(log) = &log {
            log.start(WRITE_LOG_MAX_RANGES, WRITE_LOG_MAX_BYTES);
        }
        if body.run_vcpus > 0
            && vmm.instance_info.state != VmState::Running
            && let Err(err) = vmm.resume_vm()
        {
            error!("Farplane capture could not restart the vCPUs: {err}");
            if let Some(log) = &log {
                log.stop();
            }
            drop(vmm);
            return self.reject(request_id, ErrorCode::ResumeFailed, MsgType::Resume);
        }
        let running = vmm.instance_info.state == VmState::Running;
        drop(vmm);
        let buffers = self.buffers.take();
        if let (Some(log), Some(buffers)) = (log, buffers) {
            self.stood = keep_standing(buffers, log);
            info!("Farplane kept the standing scratch clone across a refused flip");
        }
        self.order.open();
        set_capture_buffers_armed(false);
        BackendState::Ready.store();
        dispatch::gate().open();
        self.reply(
            request_id,
            MsgType::Resumed,
            &u32::from(running).to_le_bytes(),
        )
    }

    fn reply(&mut self, request_id: u64, msg: MsgType, body: &[u8]) -> Result<(), ChannelError> {
        self.answer(request_id, msg, body.to_vec())
    }
    fn reject(
        &mut self,
        request_id: u64,
        code: ErrorCode,
        op: MsgType,
    ) -> Result<(), ChannelError> {
        self.reject_with(request_id, code, op, "")
    }
    fn reject_with(
        &mut self,
        request_id: u64,
        code: ErrorCode,
        op: MsgType,
        detail: &str,
    ) -> Result<(), ChannelError> {
        self.answer(
            request_id,
            MsgType::Error,
            protocol::encode_error(code, op, detail),
        )
    }
    fn answer(&mut self, request_id: u64, msg: MsgType, body: Vec<u8>) -> Result<(), ChannelError> {
        self.answer_with_version(request_id, msg, body, None)
    }
    fn answer_with_version(
        &mut self,
        request_id: u64,
        msg: MsgType,
        body: Vec<u8>,
        version: Option<Arc<OwnedFd>>,
    ) -> Result<(), ChannelError> {
        send_and_record(
            &self.channel.sock,
            &mut self.replies,
            &mut self.pending,
            request_id,
            msg,
            body,
            version,
        )
    }
}

/// Validate the entire output before scanning or writing. A failed/expired request may have
/// partially filled its private buffer, but never reports success; the caller discards that file.
fn serve_free_summary(
    state: BackendState,
    buffer: &File,
    regions: &[protocol::RegionRecord],
    deadline: Instant,
    read: impl FnOnce() -> Result<Vec<Vec<u64>>, ErrorCode>,
) -> Result<u64, ErrorCode> {
    if state == BackendState::Quiesced {
        return Err(ErrorCode::AlreadyQuiesced);
    }
    if state != BackendState::Ready {
        return Err(ErrorCode::FreeSummaryUnavailable);
    }
    let check = || {
        if Instant::now() >= deadline {
            Err(ErrorCode::FreeSummaryUnavailable)
        } else {
            Ok(())
        }
    };
    let mut bytes = 0u64;
    for region in regions {
        check()?;
        if region.size == 0 || region.size % 4096 != 0 {
            return Err(ErrorCode::FreeSummaryUnavailable);
        }
        bytes = bytes
            .checked_add((region.size / 4096).div_ceil(64) * 8)
            .filter(|&n| n <= protocol::MAX_FREE_SUMMARY_BYTES)
            .ok_or(ErrorCode::FreeSummaryUnavailable)?;
    }
    validate_buffer_fd(buffer.as_raw_fd(), bytes)?;
    check()?;
    let summary = read()?;
    check()?;
    if summary.len() != regions.len() {
        return Err(ErrorCode::FreeSummaryUnavailable);
    }
    for (words, region) in summary.iter().zip(regions) {
        check()?;
        if words.len() as u64 != (region.size / 4096).div_ceil(64) {
            return Err(ErrorCode::FreeSummaryUnavailable);
        }
    }
    let mut offset = 0;
    let mut pages = 0u64;
    for (words, region) in summary.iter().zip(regions) {
        let tail = (region.size / 4096) % 64;
        for (chunk_index, chunk) in words.chunks(512).enumerate() {
            check()?;
            let mut encoded = [0u8; 4096];
            for (index, &word) in chunk.iter().enumerate() {
                let last = chunk_index * 512 + index + 1 == words.len();
                let word = if last && tail != 0 {
                    word & ((1u64 << tail) - 1)
                } else {
                    word
                };
                pages += u64::from(word.count_ones());
                encoded[index * 8..index * 8 + 8].copy_from_slice(&word.to_le_bytes());
            }
            let mut remaining = &encoded[..chunk.len() * 8];
            while !remaining.is_empty() {
                check()?;
                match buffer.write_at(remaining, offset) {
                    Ok(0) => return Err(ErrorCode::FreeSummaryUnavailable),
                    Ok(n) => {
                        offset += n as u64;
                        remaining = &remaining[n..];
                    }
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(ErrorCode::FreeSummaryUnavailable),
                }
            }
        }
    }
    check()?;
    Ok(pages)
}

fn accept_clone_destination(destination: RawFd, scratch: Option<RawFd>) -> Result<(), ErrorCode> {
    validate_clone_destination(destination)?;
    if scratch.is_none() {
        return Err(ErrorCode::NoScratchDrive);
    }
    Ok(())
}

fn hand_back_source(mut vmm: MutexGuard<'_, Vmm>, were_running: bool) {
    if were_running && let Err(err) = vmm.resume_vm() {
        error!("Farplane quiesce could not restart the vCPUs after the failure: {err}");
        BackendState::fail();
    }
    drop(vmm);
    if BackendState::load() != BackendState::ChannelFailed {
        dispatch::gate().open();
    }
}

/// How the freeze finished the scratch clone, for its log line.
#[derive(Debug, PartialEq, Eq)]
enum ScratchCloneHow {
    /// No pre-clone: the whole clone, as before.
    Whole,
    /// The pre-clone's log overflowed, or its ranges would cost more than a whole clone.
    WholeOverPreClone {
        ranges: usize,
        extents: u64,
        overflowed: bool,
    },
    /// The pre-clone caught up from its log.
    CaughtUp {
        ranges: usize,
        extents: u64,
        pre_clone_us: u64,
    },
}

impl std::fmt::Display for ScratchCloneHow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Whole => write!(f, "whole"),
            Self::WholeOverPreClone {
                ranges,
                extents,
                overflowed,
            } => write!(
                f,
                "whole over pre-clone; ranges={ranges} extents={extents} overflowed={overflowed}"
            ),
            Self::CaughtUp {
                ranges,
                extents,
                pre_clone_us,
            } => write!(
                f,
                "caught up; ranges={ranges} extents={extents} pre_clone_us={pre_clone_us}"
            ),
        }
    }
}

/// Makes `destination` the scratch disk as it stands now, its writers drained: from the
/// pre-clone's write log when its ranges cost less than a whole clone, else by a whole clone.
fn finish_scratch_clone(
    destination: RawFd,
    scratch: RawFd,
    pre_cloned: Option<PreClone>,
) -> Result<(u64, ScratchCloneHow), io::Error> {
    finish_scratch_clone_with(
        scratch,
        pre_cloned,
        |offset, len| clone_scratch_range(destination, scratch, offset, len),
        || clone_scratch(destination, scratch),
    )
}

fn finish_scratch_clone_with(
    scratch: RawFd,
    pre_cloned: Option<PreClone>,
    mut clone_range: impl FnMut(u64, u64) -> Result<(), io::Error>,
    clone_whole: impl FnOnce() -> Result<u64, io::Error>,
) -> Result<(u64, ScratchCloneHow), io::Error> {
    let Some(PreClone {
        log,
        clone_us,
        extents,
    }) = pre_cloned
    else {
        return Ok((clone_whole()?, ScratchCloneHow::Whole));
    };
    let written = log.take();
    let ranges = written.ranges.len();
    let affordable = u64::try_from(ranges).unwrap_or(u64::MAX)
        <= CATCH_UP_MAX_RANGES.min(extents.saturating_mul(CATCH_UP_RANGES_PER_TEN_EXTENTS) / 10);
    if written.overflowed || !affordable {
        let how = ScratchCloneHow::WholeOverPreClone {
            ranges,
            extents,
            overflowed: written.overflowed,
        };
        return Ok((clone_whole()?, how));
    }
    let started = get_time_us(ClockType::Monotonic);
    // SAFETY: stat is plain data.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: scratch is open and stat is writable for the call.
    if unsafe { libc::fstat(scratch, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let size = u64::try_from(stat.st_size).map_err(|_| io::Error::from_raw_os_error(libc::EIO))?;
    for (start, end) in written.ranges {
        // A range widened past the file's last block ends at the file's end, which
        // FICLONERANGE accepts unaligned.
        let end = end.min(size);
        if start < end {
            clone_range(start, end - start)?;
        }
    }
    let elapsed = get_time_us(ClockType::Monotonic) - started;
    Ok((
        elapsed,
        ScratchCloneHow::CaughtUp {
            ranges,
            extents,
            pre_clone_us: clone_us,
        },
    ))
}

/// Clones `len` bytes at `offset` of the scratch disk over the same bytes of `destination`.
fn clone_scratch_range(
    destination: RawFd,
    scratch: RawFd,
    offset: u64,
    len: u64,
) -> Result<(), io::Error> {
    let range = libc::file_clone_range {
        src_fd: i64::from(scratch),
        src_offset: offset,
        src_length: len,
        dest_offset: offset,
    };
    // SAFETY: both descriptors remain open throughout the ioctl, which only reads `range`.
    if unsafe { libc::ioctl(destination, libc::FICLONERANGE, &range) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The number of extents of `file`, read by a count-only FIEMAP: no extent records are copied.
/// Whether a standing clone has work: an unfinished clone, a catch-up in progress, or a log past
/// its catch-up threshold or overflowed.
fn standing_has_work(stood: &StandingDisk) -> bool {
    match &stood.phase {
        StandingPhase::Cloning { .. } => true,
        StandingPhase::Ready { pending, .. } if !pending.is_empty() => true,
        StandingPhase::Ready { .. } => {
            let (ranges, bytes, overflowed) = stood.log.pending();
            overflowed || ranges >= STANDING_CATCH_UP_RANGES || bytes >= STANDING_CATCH_UP_BYTES
        }
    }
}

/// Advances a standing clone of `scratch` by one step: one chunk of the clone; or one batch of a
/// catch-up; or, at a log past its threshold, swaps the log's ranges out for a catch-up; or, at
/// an overflowed log, restarts the clone over the destination, which every chunk remaps.
fn advance_standing(stood: &mut StandingDisk, scratch: RawFd) -> Result<(), io::Error> {
    let dest = stood.dest.as_raw_fd();
    match &mut stood.phase {
        StandingPhase::Cloning {
            next,
            size,
            done,
            started_us,
        } => {
            *next = clone_chunk_step(
                *next,
                *size,
                PRE_CLONE_CHUNK_EXTENTS,
                &mut |from, want| extents_from(scratch, from, want),
                &mut |offset, len| clone_scratch_range(dest, scratch, offset, len),
                done,
            )?;
            if *next >= *size {
                let mut clone = std::mem::take(done);
                clone.clone_us = get_time_us(ClockType::Monotonic) - *started_us;
                info!(
                    "Farplane stood the scratch disk ({} extents, {} chunks, longest {} us) in {} us",
                    clone.extents, clone.chunks, clone.longest_chunk_us, clone.clone_us
                );
                stood.phase = StandingPhase::Ready {
                    clone,
                    pending: Vec::new(),
                };
            }
        }
        StandingPhase::Ready { pending, .. } if !pending.is_empty() => {
            let size = file_size(scratch)?;
            let batch = pending.len().min(STANDING_CATCH_UP_STEP);
            for (start, end) in pending.drain(..batch) {
                let end = end.min(size);
                if start < end {
                    clone_scratch_range(dest, scratch, start, end - start)?;
                }
            }
        }
        StandingPhase::Ready { pending, .. } => {
            let swapped = stood.log.swap();
            if swapped.overflowed {
                warn!("Farplane standing write log overflowed; cloning the disk again");
                stood.log.start(WRITE_LOG_MAX_RANGES, WRITE_LOG_MAX_BYTES);
                stood.phase = StandingPhase::Cloning {
                    next: 0,
                    size: file_size(scratch)?,
                    done: ChunkedClone::default(),
                    started_us: get_time_us(ClockType::Monotonic),
                };
            } else {
                *pending = swapped.ranges;
            }
        }
    }
    Ok(())
}

/// Takes a standing clone into a capture: an unfinished background clone finishes its remaining
/// chunks first (the wait the reply reports), and ranges swapped out for a background catch-up
/// go back into the log, so the freeze catches up everything written since the clone.
fn adopt_standing(
    mut stood: StandingDisk,
    scratch: RawFd,
) -> Result<(File, PreClone, Adopted, u64), io::Error> {
    let started = get_time_us(ClockType::Monotonic);
    while matches!(stood.phase, StandingPhase::Cloning { .. }) {
        advance_standing(&mut stood, scratch)?;
    }
    let StandingPhase::Ready { clone, pending } = stood.phase else {
        unreachable!("the loop above leaves the clone ready")
    };
    for (start, end) in pending {
        stood.log.record(start, end - start);
    }
    let wait_us = get_time_us(ClockType::Monotonic) - started;
    let pre = PreClone {
        log: stood.log,
        clone_us: clone.clone_us,
        extents: clone.extents,
    };
    let adopted = Adopted {
        inode: stood.inode,
        clone,
    };
    Ok((stood.dest, pre, adopted, wait_us))
}

/// Returns a refused flip's adopted destination to standing. The freeze caught it up to the disk
/// and `log`, restarted before anything could write since, holds what follows.
fn keep_standing(buffers: CaptureBuffers, log: Arc<WriteLog>) -> Option<StandingDisk> {
    let (Some(dest), Some(adopted)) = (buffers.disk_clone, buffers.adopted) else {
        return None;
    };
    Some(StandingDisk {
        dest,
        inode: adopted.inode,
        log,
        phase: StandingPhase::Ready {
            clone: adopted.clone,
            pending: Vec::new(),
        },
    })
}

/// The chunk walk of a standing clone, whole. `extents_from(from, n)` names the logical
/// starts of at most `n` extents at or overlapping `from`, in order; `clone_range` clones one
/// chunk. Each chunk ends where the extent after its `per_chunk`th begins, so each covers at most
/// `per_chunk` extents however the file changes between calls.
#[cfg(test)]
fn clone_chunks_with(
    size: u64,
    per_chunk: u32,
    mut extents_from: impl FnMut(u64, u32) -> Result<Vec<u64>, io::Error>,
    mut clone_range: impl FnMut(u64, u64) -> Result<(), io::Error>,
) -> Result<ChunkedClone, io::Error> {
    let started = get_time_us(ClockType::Monotonic);
    let mut done = ChunkedClone::default();
    let mut start = 0;
    while start < size {
        start = clone_chunk_step(
            start,
            size,
            per_chunk,
            &mut extents_from,
            &mut clone_range,
            &mut done,
        )?;
    }
    done.clone_us = get_time_us(ClockType::Monotonic) - started;
    Ok(done)
}

/// Clones the one chunk at `start` and returns where the next begins: it ends where the extent
/// after its `per_chunk`th begins, or at `size`.
fn clone_chunk_step(
    start: u64,
    size: u64,
    per_chunk: u32,
    extents_from: &mut impl FnMut(u64, u32) -> Result<Vec<u64>, io::Error>,
    clone_range: &mut impl FnMut(u64, u64) -> Result<(), io::Error>,
    done: &mut ChunkedClone,
) -> Result<u64, io::Error> {
    let per_chunk = per_chunk.max(1);
    let starts = extents_from(start, per_chunk + 1)?;
    let mut end = size;
    if let Some(&next) = starts.get(per_chunk as usize) {
        if next > start && next < size {
            end = next;
        }
        done.extents += u64::from(per_chunk);
    } else {
        done.extents += u64::try_from(starts.len()).unwrap_or(u64::MAX);
    }
    let chunk_started = get_time_us(ClockType::Monotonic);
    clone_range(start, end - start)?;
    let chunk_us = get_time_us(ClockType::Monotonic) - chunk_started;
    if chunk_us >= SLOW_PRE_CLONE_CHUNK_US {
        // A chunk is ~10 ms by its extents; one far over that waited on something else, which
        // its range and position name.
        warn!(
            "Farplane pre-clone chunk {} at {start}+{} took {chunk_us} us",
            done.chunks,
            end - start
        );
    }
    done.longest_chunk_us = done.longest_chunk_us.max(chunk_us);
    done.chunks += 1;
    Ok(end)
}

fn inode_of(file: RawFd) -> Result<(u64, u64), io::Error> {
    // SAFETY: stat is plain data.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and stat is writable for the call.
    if unsafe { libc::fstat(file, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((stat.st_dev, stat.st_ino))
}

fn file_size(file: RawFd) -> Result<u64, io::Error> {
    // SAFETY: stat is plain data.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: the descriptor is open and stat is writable for the call.
    if unsafe { libc::fstat(file, &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    u64::try_from(stat.st_size).map_err(|_| io::Error::from_raw_os_error(libc::EIO))
}

/// The logical starts of at most `want` extents of `file` at or overlapping `from`, by FIEMAP.
fn extents_from(file: RawFd, from: u64, want: u32) -> Result<Vec<u64>, io::Error> {
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct FiemapExtent {
        logical: u64,
        physical: u64,
        length: u64,
        reserved64: [u64; 2],
        flags: u32,
        reserved: [u32; 3],
    }
    #[repr(C)]
    struct Request {
        start: u64,
        length: u64,
        flags: u32,
        mapped_extents: u32,
        extent_count: u32,
        reserved: u32,
        extents: [FiemapExtent; PRE_CLONE_CHUNK_EXTENTS as usize + 1],
    }
    const FS_IOC_FIEMAP: libc::Ioctl = libc::_IOWR::<[u64; 4]>(b'f' as u32, 11);
    let want = want.min(PRE_CLONE_CHUNK_EXTENTS + 1);
    let mut request = Box::new(Request {
        start: from,
        length: u64::MAX - from,
        flags: 0,
        mapped_extents: 0,
        extent_count: want,
        reserved: 0,
        extents: [FiemapExtent::default(); PRE_CLONE_CHUNK_EXTENTS as usize + 1],
    });
    // SAFETY: the request holds `want` extent slots after its header, which is all the kernel
    // writes, and it stays live for the call.
    if unsafe { libc::ioctl(file, FS_IOC_FIEMAP, &mut *request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mapped = request.mapped_extents.min(want) as usize;
    Ok(request.extents[..mapped]
        .iter()
        .map(|e| e.logical)
        .collect())
}

#[cfg(test)]
fn extent_count(file: RawFd) -> Result<u64, io::Error> {
    /// struct fiemap without its trailing extent array.
    #[repr(C)]
    #[derive(Default)]
    struct Fiemap {
        start: u64,
        length: u64,
        flags: u32,
        mapped_extents: u32,
        extent_count: u32,
        reserved: u32,
    }
    const FS_IOC_FIEMAP: libc::Ioctl = libc::_IOWR::<Fiemap>(b'f' as u32, 11);
    let mut request = Fiemap {
        length: u64::MAX,
        ..Default::default()
    };
    // SAFETY: with extent_count 0 the kernel writes only mapped_extents into the live request.
    if unsafe { libc::ioctl(file, FS_IOC_FIEMAP, &mut request) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(request.mapped_extents))
}

fn clone_scratch(destination: RawFd, scratch: RawFd) -> Result<u64, io::Error> {
    let started = get_time_us(ClockType::Monotonic);
    // SAFETY: both descriptors remain open throughout the ioctl; the return code is checked.
    if unsafe { libc::ioctl(destination, libc::FICLONE, scratch) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(get_time_us(ClockType::Monotonic) - started)
}

fn serialize_vmstate(buffer: &mut File, state: MicrovmState) -> Result<u64, VmstateRefusal> {
    serialize_vmstate_within(buffer, state, VMSTATE_CAPACITY_BYTES)
}

fn serialize_vmstate_within(
    buffer: &mut File,
    state: MicrovmState,
    capacity: u64,
) -> Result<u64, VmstateRefusal> {
    let failed = |step: &str, err: &dyn std::fmt::Display| {
        error!("Farplane capture could not serialize the microVM state ({step}): {err}");
        VmstateRefusal::failed(step, err)
    };
    buffer
        .seek(SeekFrom::Start(0))
        .map_err(|err| failed("vmstate seek", &err))?;
    let mut bounded = BoundedWriter {
        inner: buffer,
        remaining: u64_to_usize(capacity),
    };
    Snapshot::new(state)
        .save(&mut bounded)
        .map_err(|err| failed("vmstate save", &err))?;
    bounded
        .flush()
        .map_err(|err| failed("vmstate flush", &err))?;
    Ok(capacity - usize_to_u64(bounded.remaining))
}

#[derive(Debug)]
struct BoundedWriter<'a> {
    inner: &'a mut File,
    remaining: usize,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.len() > self.remaining {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let written = self.inner.write(buf)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests;
