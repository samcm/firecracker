// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
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
use crate::logger::{IncMetric, METRICS, error, info};
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vmm_config::instance_info::VmState;

#[derive(Debug)]
struct CaptureBuffers {
    vmstate: File,
    disk_clone: Option<File>,
}

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

/// Serialization and CREATE are one operation. Failed operations publish nothing and may retry
/// under a new request ID; successful operations never run twice in the same epoch.
fn serve_write_vmstate(
    order: &mut EpochOrder,
    capture: impl FnOnce() -> Result<(u64, OwnedFd), ErrorCode>,
) -> Result<(u64, Arc<OwnedFd>), ErrorCode> {
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
    /// memory plane has let go. Otherwise each would live until 64 later answers evicted it.
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
        // A peer resends only the request it waits on, its newest. Once a newer one is recorded
        // no older answer is replayed, so an older version is not kept: it would pin every page
        // its source has rewritten since. Its ID is then refused as reused, never served again.
        self.answers
            .retain(|answer| answer.version.is_none() || answer.request_id >= request_id);
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
    let (len, counts): (usize, &[usize]) = match msg {
        MsgType::CaptureBuffers => (0, &[1, 2]),
        MsgType::Quiesce => (0, &[0]),
        MsgType::WriteVmstate => (0, &[1]),
        MsgType::Resume => (4, &[0]),
        MsgType::FreeSummary => (8, &[1]),
        MsgType::Track => (0, &[1, 2]),
        MsgType::Refresh => (0, &[0]),
        MsgType::Untrack => (0, &[0]),
        _ => return Err(ChannelError::Malformed),
    };
    if body_len != len || !counts.contains(&fd_count) {
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
}

/// The `tracked` reply body.
fn encode_track_info(info: &memversion::TrackInfo) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    body.extend_from_slice(&info.tracked.to_le_bytes());
    body.extend_from_slice(&info.depth.to_le_bytes());
    body.extend_from_slice(&info.dirty_pages.to_le_bytes());
    body.extend_from_slice(&info.standing_id.to_le_bytes());
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
            .name("fc_ramet".to_string())
            .spawn(move || {
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    error!("Ramet channel could not install its filter: {err}");
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
                };
                loop {
                    if BackendState::load() == BackendState::ChannelFailed {
                        return;
                    }
                    if let Err(err) = service.serve_one() {
                        error!("Ramet memory channel failed: {err}");
                        BackendState::fail();
                        return;
                    }
                }
            })
            .expect("Failed to spawn the ramet memory channel thread");
    }

    fn serve_one(&mut self) -> Result<(), ChannelError> {
        let incoming = protocol::recv_frame(&self.channel.sock)?;
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
                return send_reply(&self.channel.sock, msg, request_id, &body, version.as_ref());
            }
            FrameDisposition::ReplayUnavailable => {
                return protocol::send_frame(
                    &self.channel.sock,
                    MsgType::Error,
                    request_id,
                    &protocol::encode_error(ErrorCode::ReplayUnavailable, msg, ""),
                    &[],
                );
            }
            FrameDisposition::Reused => {
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
            MsgType::Resume => self.resume(request_id, protocol::parse_u32(&incoming.body)?),
            MsgType::FreeSummary => self.free_summary(incoming),
            MsgType::Track => self.track(incoming),
            MsgType::Refresh => self.refresh(request_id),
            MsgType::Untrack => self.untrack(request_id),
            _ => Err(ChannelError::Malformed),
        }
    }

    fn free_summary(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let budget = protocol::parse_free_summary_budget(&incoming.body)?;
        let deadline = Instant::now() + Duration::from_micros(budget);
        let request_id = incoming.header.request_id;
        let [fd] = <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
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
                vm.free_summary_until(deadline)
                    .map_err(|_| ErrorCode::FreeSummaryUnavailable)
            },
        );
        match result {
            Ok(pages) => self.reply(request_id, MsgType::FreeSummaryDone, &pages.to_le_bytes()),
            Err(code) => self.reject(request_id, code, MsgType::FreeSummary),
        }
    }

    /// Tracks the guest's memory from now on. Runs while the guest runs: the kernel walks the
    /// present pages once under the mmap write lock, which stalls only guest faults. A second
    /// request reports the existing tracker.
    fn track(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Ready {
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
                error!("Ramet could not track guest memory: {err}");
                return self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track);
            }
            info!(
                "Ramet tracks guest memory (base={}) after {} us",
                base.is_some(),
                started.elapsed().as_micros()
            );
            self.tracker = Some(device);
        }
        let tracker = self.tracker.as_ref().expect("tracker set above");
        match memversion::track_info(tracker.as_fd()) {
            Ok(info) => self.reply(request_id, MsgType::Tracked, &encode_track_info(&info)),
            Err(err) => {
                error!("Ramet could not read the memory tracker: {err}");
                self.reject(request_id, ErrorCode::TrackFailed, MsgType::Track)
            }
        }
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
                    "Ramet refreshed the standing version in {} us: own={} folded={} depth={}",
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
                error!("Ramet could not refresh the standing version: {err}");
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
                error!("Ramet could not untrack guest memory: {err}");
                return self.reject(request_id, ErrorCode::UntrackFailed, MsgType::Untrack);
            }
            self.tracker = None;
            self.standing = None;
            info!("Ramet untracked guest memory");
        }
        self.reply(
            request_id,
            MsgType::Tracked,
            &encode_track_info(&memversion::TrackInfo::default()),
        )
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
        self.buffers = Some(CaptureBuffers {
            vmstate: File::from(vmstate),
            disk_clone: destination.map(File::from),
        });
        set_capture_buffers_armed(true);
        self.reply(request_id, MsgType::CaptureBuffersArmed, &[])
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
            error!("Ramet quiesce could not pause the vCPUs: {err}");
            drop(vmm);
            dispatch::gate().open();
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        let pause_us = at();
        if let Err(err) = vmm.drain_guest_memory_writers() {
            error!("Ramet quiesce could not stop every guest-memory writer: {err}");
            hand_back_source(vmm, were_running);
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        let destination = self
            .buffers
            .as_ref()
            .and_then(|buffers| buffers.disk_clone.as_ref())
            .map(|file| file.as_raw_fd());
        if let Some(destination) = destination {
            match vmm
                .scratch_descriptor()
                .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODEV))
                .and_then(|scratch| clone_scratch(destination, scratch))
            {
                Ok(elapsed_us) => {
                    info!("Ramet quiesce cloned the scratch disk in {elapsed_us} us");
                    METRICS.ramet.disk_clones.inc();
                    METRICS.ramet.disk_clone_agg.record_us(elapsed_us);
                }
                Err(err) => {
                    error!("Ramet quiesce could not clone the scratch disk: {err}");
                    METRICS.ramet.disk_clone_failures.inc();
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
            "Ramet quiesce timing gate_close_us={gate_us} vmm_lock_us={lock_us} \
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
                error!("Ramet capture could not save the microVM state: {err}");
                ErrorCode::VmstateWriteFailed
            })?;
            let bytes = serialize_vmstate(&mut buffers.as_mut().unwrap().vmstate, state)?;
            vmm.mark_virtio_queues_dirty();
            let version = (|| -> io::Result<OwnedFd> {
                let kvm_vm = vmm.kvm_vm().ok_or_else(|| io::Error::other("no KVM VM"))?;
                let dirty = kvm_vm.snapshot_dirty_log().map_err(io::Error::other)?;
                let free = kvm_vm.snapshot_free_log().map_err(io::Error::other)?;
                let regions = memversion::geometry(&channel.regions)?;
                let exclusions = memversion::exclusions(&regions, &free, &dirty)?;
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
                    error!("Ramet tracked capture fell back to a whole copy: {err}");
                    memversion::create(device.as_fd(), &regions, &exclusions)
                })
            })()
            .map_err(|err| {
                error!("Ramet capture could not create the memory version: {err}");
                ErrorCode::VmstateWriteFailed
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
            Err(code) => self.reject(request_id, code, MsgType::WriteVmstate),
        }
    }

    fn resume(&mut self, request_id: u64, run_vcpus: u32) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Resume);
        }
        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        if run_vcpus > 0
            && vmm.instance_info.state != VmState::Running
            && let Err(err) = vmm.resume_vm()
        {
            error!("Ramet capture could not restart the vCPUs: {err}");
            drop(vmm);
            return self.reject(request_id, ErrorCode::ResumeFailed, MsgType::Resume);
        }
        let running = vmm.instance_info.state == VmState::Running;
        drop(vmm);
        self.buffers = None;
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
        self.answer(
            request_id,
            MsgType::Error,
            protocol::encode_error(code, op, ""),
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
        error!("Ramet quiesce could not restart the vCPUs after the failure: {err}");
        BackendState::fail();
    }
    drop(vmm);
    if BackendState::load() != BackendState::ChannelFailed {
        dispatch::gate().open();
    }
}

fn clone_scratch(destination: RawFd, scratch: RawFd) -> Result<u64, io::Error> {
    let started = get_time_us(ClockType::Monotonic);
    // SAFETY: both descriptors remain open throughout the ioctl; the return code is checked.
    if unsafe { libc::ioctl(destination, libc::FICLONE, scratch) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(get_time_us(ClockType::Monotonic) - started)
}

fn serialize_vmstate(buffer: &mut File, state: MicrovmState) -> Result<u64, ErrorCode> {
    buffer
        .seek(SeekFrom::Start(0))
        .map_err(|_| ErrorCode::VmstateWriteFailed)?;
    let mut bounded = BoundedWriter {
        inner: buffer,
        remaining: u64_to_usize(VMSTATE_CAPACITY_BYTES),
    };
    Snapshot::new(state)
        .save(&mut bounded)
        .map_err(|_| ErrorCode::VmstateWriteFailed)?;
    bounded.flush().map_err(|_| ErrorCode::VmstateWriteFailed)?;
    Ok(VMSTATE_CAPACITY_BYTES - usize_to_u64(bounded.remaining))
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
