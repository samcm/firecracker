// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, MutexGuard};

use utils::time::{ClockType, get_time_us};

use super::backend::{
    BackendState, MemoryChannel, VMSTATE_CAPACITY_BYTES, set_capture_buffers_armed,
    validate_buffer_fd, validate_clone_destination,
};
use super::dispatch;
use super::protocol::{self, ChannelError, ErrorCode, Incoming, MsgType};
use crate::Vmm;
use crate::logger::{IncMetric, METRICS, error, info};
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vmm_config::instance_info::VmState;

/// Buffers pagemaster preallocated for one capture epoch.
#[derive(Debug)]
struct CaptureBuffers {
    dirty: File,
    vmstate: File,
    /// Inode the scratch disk is reflinked into inside the quiesce, when the sandbox has a disk.
    disk_clone: Option<File>,
}

/// How far through one capture epoch the commands that produce a checkpoint have got.
///
/// The vmstate has to be serialized before the dirty accumulator is harvested. Serialization
/// calls `prepare_save()` on every device, and a device may write guest memory there: virtio-net
/// hands the guest its deferred RX frame, which advances the used ring the guest reads. A harvest
/// that ran first would report a bitmap that predates those writes, so pagemaster would copy pages
/// the restored vmstate no longer agrees with. The order is a property of the epoch, not of one
/// command, so it is tracked here and enforced for both directions.
///
/// The phase also makes a repeated command a replay rather than a second effect. A reply lost on
/// the way back to pagemaster is answered by a retry, and a retry that redid the work would
/// destroy what the first one produced: a second harvest would overwrite the armed bitmap with the
/// accumulator the first one cleared, and a second serialization would run `prepare_save()` again
/// and write a vmstate the harvested bitmap does not cover.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum EpochPhase {
    /// Nothing has been written or harvested yet in this epoch.
    #[default]
    Open,
    /// The vmstate has been serialized: the dirty accumulator may now be harvested.
    StateWritten,
    /// The dirty accumulator has been harvested into the armed bitmap.
    Harvested,
}

/// What a `write_vmstate` has to do, given what the epoch has already produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmstateStep {
    /// The epoch owes a vmstate: serialize it into the armed buffer.
    Serialize,
    /// The vmstate is already in the armed buffer: answer with the length it reported, without
    /// serializing a second, possibly different one.
    Replay(u64),
    /// The command cannot be served in this phase.
    Refuse(ErrorCode),
}

/// What a `dirty_snapshot` has to do, given what the epoch has already produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HarvestStep {
    /// The accumulator holds the epoch's dirty set: harvest it into the armed buffer.
    Harvest,
    /// The armed buffer already holds this epoch's harvest: answer without reading or clearing
    /// the accumulator, which no longer holds those bits.
    Replay,
    /// The command cannot be served in this phase.
    Refuse(ErrorCode),
}

/// Order guard of one capture epoch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct EpochOrder {
    phase: EpochPhase,
    /// Length the epoch's serialization reported, replayed by a repeat of the command.
    vmstate_len: u64,
}

impl EpochOrder {
    /// Opens a fresh epoch, discarding whatever the previous one reached.
    fn open(&mut self) {
        self.phase = EpochPhase::Open;
        self.vmstate_len = 0;
    }

    /// What to do with a `write_vmstate` in this phase.
    fn vmstate_step(self) -> VmstateStep {
        match self.phase {
            EpochPhase::Open => VmstateStep::Serialize,
            EpochPhase::StateWritten => VmstateStep::Replay(self.vmstate_len),
            // The harvest already reported the epoch's dirty set, so writes a serialization
            // performs could never reach pagemaster.
            EpochPhase::Harvested => VmstateStep::Refuse(ErrorCode::CaptureOrderViolation),
        }
    }

    /// Records a vmstate that reached the armed buffer.
    fn vmstate_written(&mut self, bytes: u64) {
        self.phase = EpochPhase::StateWritten;
        self.vmstate_len = bytes;
    }

    /// What to do with a `dirty_snapshot` in this phase.
    fn harvest_step(self) -> HarvestStep {
        match self.phase {
            EpochPhase::Open => HarvestStep::Refuse(ErrorCode::CaptureOrderViolation),
            EpochPhase::StateWritten => HarvestStep::Harvest,
            EpochPhase::Harvested => HarvestStep::Replay,
        }
    }

    /// Records a harvest that reached the armed buffer.
    fn harvested(&mut self) {
        self.phase = EpochPhase::Harvested;
    }

    /// Records a bitmap folded back into the accumulator: those bits are no longer reported by
    /// the armed buffer, so the epoch owes a harvest again and a repeat may not replay.
    fn unioned(&mut self) {
        if self.phase == EpochPhase::Harvested {
            self.phase = EpochPhase::StateWritten;
        }
    }
}

/// Serves one `write_vmstate` against `order`, running `serialize` only when the epoch owes a
/// vmstate. A repeat of the command replays the length the first one reported.
fn serve_write_vmstate(
    order: &mut EpochOrder,
    serialize: impl FnOnce() -> Result<u64, ErrorCode>,
) -> Result<u64, ErrorCode> {
    match order.vmstate_step() {
        VmstateStep::Refuse(code) => Err(code),
        VmstateStep::Replay(bytes) => Ok(bytes),
        VmstateStep::Serialize => {
            // A serialization that failed records nothing: the epoch still owes one, and the
            // writes `prepare_save()` performed before the failure are still in the accumulator
            // for the harvest that a later serialization unblocks.
            let bytes = serialize()?;
            order.vmstate_written(bytes);
            Ok(bytes)
        }
    }
}

/// Serves one `dirty_snapshot` against `order`, running `harvest` only when the accumulator still
/// holds the epoch's dirty set. A repeat of the command leaves the armed bitmap exactly as the
/// harvest left it.
fn serve_dirty_snapshot(
    order: &mut EpochOrder,
    harvest: impl FnOnce() -> Result<(), ErrorCode>,
) -> Result<(), ErrorCode> {
    match order.harvest_step() {
        HarvestStep::Refuse(code) => Err(code),
        HarvestStep::Replay => Ok(()),
        HarvestStep::Harvest => {
            // A harvest that failed cleared nothing, so the epoch is still one whose dirty set is
            // in the accumulator: the retry harvests rather than replays.
            harvest()?;
            order.harvested();
            Ok(())
        }
    }
}

/// Stable identity of one descriptor a frame carried: the file it refers to. Two descriptors
/// duplicated from one file report the same identity; a descriptor of another file does not.
/// Length is not part of it, because a clone destination grows between arming and the replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorIdentity {
    dev: libc::dev_t,
    ino: libc::ino_t,
}

/// Reads the identity of one received descriptor, or reports that it could not be proven.
fn descriptor_identity(fd: RawFd) -> Option<DescriptorIdentity> {
    // SAFETY: `stat` is a plain data structure with no invalid bit patterns.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is owned by the frame being served, and `stat` outlives the call.
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return None;
    }
    Some(DescriptorIdentity {
        dev: stat.st_dev,
        ino: stat.st_ino,
    })
}

/// Exactly which command one frame carried: its message type, its bytes, and the files its
/// descriptors refer to.
///
/// The command bodies of this protocol are at most four bytes, so the bytes themselves are kept
/// rather than a digest of them: a digest would make two different commands under one identifier
/// collide into an acknowledgement of work that was never done.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandKey {
    msg: MsgType,
    body: Vec<u8>,
    /// Identity of each descriptor, in the order the frame carried them, or `None` when one of
    /// them could not be proven.
    descriptors: Option<Vec<DescriptorIdentity>>,
}

impl CommandKey {
    /// Reads the identity of the command a frame carries.
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

    /// Whether this is exactly the command `answered` was.
    ///
    /// `CaptureBuffers` and `DirtyUnion` carry their input in descriptors, and a retry duplicates
    /// the descriptors of the same memfds rather than sending the same count of other ones. An
    /// identity that could not be proven is never exact, on either side, so such a command is
    /// refused rather than acknowledged with an answer about resources that may have changed.
    fn is_exactly(&self, answered: &Self) -> bool {
        self.descriptors.is_some()
            && answered.descriptors.is_some()
            && self.msg == answered.msg
            && self.body == answered.body
            && self.descriptors == answered.descriptors
    }
}

/// One answer already sent on this connection.
#[derive(Debug)]
struct CachedReply {
    request_id: u64,
    /// The command that produced this answer.
    command: CommandKey,
    msg: MsgType,
    body: Vec<u8>,
}

/// What to do with a frame, given the answers this connection has already sent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FrameDisposition {
    /// The identifier is new: serve the command.
    Serve,
    /// The identifier and the command are the ones already answered: send that answer again.
    Replay(MsgType, Vec<u8>),
    /// The identifier was used before, for a different command or too long ago to answer from
    /// memory. Serving it again could repeat an effect, so it is refused.
    Reused,
}

/// Answers of the commands this connection has served, so a retry of one is answered rather than
/// executed a second time.
///
/// Pagemaster retries a command whose reply it never saw, with the identifier and the contents it
/// sent the first time. Phase alone cannot make that safe: a `dirty_union` legitimately reopens
/// the dirty set, and the retried `dirty_snapshot` behind it would harvest again. The identifier
/// plus the exact command answers it instead, for the life of the connection and across epochs.
///
/// The history is bounded by `protocol::MAX_RETRYABLE_REQUESTS`: an identifier older than that
/// cannot be answered from memory, so it is refused rather than served a second time.
#[derive(Debug, Default)]
struct ReplyCache {
    answers: std::collections::VecDeque<CachedReply>,
    /// Highest identifier this connection has answered.
    highest: u64,
}

impl ReplyCache {
    /// States what to do with a frame that carries `request_id` and the command `command`.
    fn disposition(&self, request_id: u64, command: &CommandKey) -> FrameDisposition {
        if let Some(answer) = self
            .answers
            .iter()
            .find(|answer| answer.request_id == request_id)
        {
            if command.is_exactly(&answer.command) {
                return FrameDisposition::Replay(answer.msg, answer.body.clone());
            }
            return FrameDisposition::Reused;
        }
        if request_id <= self.highest {
            return FrameDisposition::Reused;
        }
        FrameDisposition::Serve
    }

    /// Records the answer sent for one command.
    fn record(&mut self, request_id: u64, command: CommandKey, msg: MsgType, body: Vec<u8>) {
        if self.answers.len() == protocol::MAX_RETRYABLE_REQUESTS {
            self.answers.pop_front();
        }
        self.answers.push_back(CachedReply {
            request_id,
            command,
            msg,
            body,
        });
        self.highest = self.highest.max(request_id);
    }
}

/// Sends one answer and records it for an exact retry.
///
/// The answer is recorded whether or not the send reached pagemaster: the command's effect has
/// already happened, so a retry of it has to be answered from the record rather than served a
/// second time. `pending` names the command the answer belongs to, and is consumed either way.
fn send_and_record(
    sock: &UnixStream,
    replies: &mut ReplyCache,
    pending: &mut Option<(u64, CommandKey)>,
    request_id: u64,
    msg: MsgType,
    body: Vec<u8>,
) -> Result<(), ChannelError> {
    let sent = protocol::send_frame(sock, msg, request_id, &body, &[]);
    if let Some((pending_id, command)) = pending.take()
        && pending_id == request_id
    {
        replies.record(request_id, command, msg, body);
    }
    sent
}

/// Serves the capture half of the memory channel on the event loop that owns the microVM: while a
/// command is served no device event source is dispatched, so between `quiesced` and `resume` no
/// Firecracker thread writes guest memory.
#[derive(Debug)]
pub struct CaptureService {
    channel: MemoryChannel,
    vmm: Arc<Mutex<Vmm>>,
    vm_info: VmInfo,
    buffers: Option<CaptureBuffers>,
    order: EpochOrder,
    /// Answers this connection has sent, so an exact retry is replayed.
    replies: ReplyCache,
    /// Identifier and exact command of the frame being served, which the answer is recorded under.
    pending: Option<(u64, CommandKey)>,
}

impl CaptureService {
    /// Starts serving capture commands for `vmm`.
    /// Serves the memory channel on a thread of its own.
    ///
    /// The event loop this used to run on stops while the API has the instance
    /// paused: that thread takes API requests inline and deliberately does not
    /// relinquish control to the event manager. Every capture command arrives
    /// while the source is paused, so a channel served from that loop could
    /// never be answered. The thread installs the filter the VMM thread runs
    /// under, so it is spawned before that filter is applied and confined by it
    /// from its first instruction.
    pub fn spawn(
        channel: MemoryChannel,
        vmm: Arc<Mutex<Vmm>>,
        vm_info: VmInfo,
        filter: Arc<crate::seccomp::BpfProgram>,
    ) {
        std::thread::Builder::new()
            .name("fc_farplane".to_string())
            .spawn(move || {
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
                };
                loop {
                    if BackendState::load() == BackendState::ChannelFailed {
                        return;
                    }
                    if let Err(err) = service.serve_one() {
                        error!("Farplane memory channel failed: {err}");
                        // Fail closed: a channel that died inside an epoch leaves event dispatch
                        // stopped, so nothing writes guest memory or device state behind a
                        // half-taken checkpoint. The supervisor kills this process.
                        BackendState::fail();
                        return;
                    }
                }
            })
            .expect("Failed to spawn the farplane memory channel thread");
    }

    /// Serves exactly one command.
    ///
    /// A command whose body length or descriptor count differs from its wire definition is a
    /// protocol violation, rejected before any state changes.
    fn serve_one(&mut self) -> Result<(), ChannelError> {
        let incoming = protocol::recv_frame(&self.channel.sock)?;
        let request_id = incoming.header.request_id;
        if request_id == 0 {
            return Err(ChannelError::Malformed);
        }
        let msg = incoming.header.msg();
        // `capture_buffers` carries the dirty bitmap and the vmstate buffer, and a third
        // descriptor when the sandbox has a disk the quiesce has to clone.
        let (body_len, fd_counts): (usize, &[usize]) = match msg {
            MsgType::CaptureBuffers => (0, &[2, 3]),
            MsgType::Quiesce | MsgType::DirtySnapshot | MsgType::WriteVmstate => (0, &[0]),
            MsgType::DirtyUnion => (0, &[1]),
            MsgType::Resume => (4, &[0]),
            _ => return Err(ChannelError::Malformed),
        };
        if incoming.body.len() != body_len || !fd_counts.contains(&incoming.fds.len()) {
            return Err(ChannelError::Malformed);
        }

        // Exact replay is decided before the phase is consulted: an identifier this connection
        // has already answered gets that answer back, whatever the epoch has done since, and an
        // identifier that names a different command is refused rather than served. Both paths
        // return with `incoming` still owning the descriptors the frame carried, so they are
        // closed on the way out exactly as a served command closes them.
        let command = CommandKey::of(msg, &incoming.body, &incoming.fds);
        match self.replies.disposition(request_id, &command) {
            FrameDisposition::Serve => {}
            FrameDisposition::Replay(cached_msg, cached_body) => {
                return protocol::send_frame(
                    &self.channel.sock,
                    cached_msg,
                    request_id,
                    &cached_body,
                    &[],
                );
            }
            FrameDisposition::Reused => {
                // Not recorded: the answer to a reused identifier is not an answer to any
                // command, so it must never be replayed for one.
                let body = protocol::encode_error(ErrorCode::RequestIdReused, msg, "");
                return protocol::send_frame(
                    &self.channel.sock,
                    MsgType::Error,
                    request_id,
                    &body,
                    &[],
                );
            }
        }

        self.pending = Some((request_id, command));
        match msg {
            MsgType::CaptureBuffers => self.arm_buffers(incoming),
            MsgType::Quiesce => self.quiesce(request_id),
            MsgType::DirtySnapshot => self.dirty_snapshot(request_id),
            MsgType::WriteVmstate => self.write_vmstate(request_id),
            MsgType::DirtyUnion => self.dirty_union(incoming),
            MsgType::Resume => {
                let run_vcpus = protocol::parse_u32(&incoming.body)?;
                self.resume(request_id, run_vcpus)
            }
            _ => Err(ChannelError::Malformed),
        }
    }

    /// Validates and arms the buffers of one capture epoch, and the disk clone destination when
    /// pagemaster sends one. A destination arrives only for a sandbox with a disk, so one sent
    /// for a guest that has no scratch drive names a clone that could never be taken.
    fn arm_buffers(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::CaptureBuffers);
        }
        let mut fds = incoming.fds;
        let destination = (fds.len() == 3).then(|| fds.remove(2));
        let [dirty, vmstate] =
            <[_; 2]>::try_from(fds).map_err(|_| ChannelError::FdCountMismatch)?;
        if let Err(code) = validate_buffer_fd(dirty.as_raw_fd(), self.channel.dirty_bitmap_bytes) {
            return self.reject(request_id, code, MsgType::CaptureBuffers);
        }
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
            dirty: File::from(dirty),
            vmstate: File::from(vmstate),
            disk_clone: destination.map(File::from),
        });
        set_capture_buffers_armed(true);
        self.reply(request_id, MsgType::CaptureBuffersArmed, &[])
    }

    /// Descriptor of the drive the armed destination is cloned from.
    fn scratch_descriptor(&self) -> Option<RawFd> {
        self.vmm.lock().expect("Poisoned lock").scratch_descriptor()
    }

    /// Stops every guest-memory writer and enters the capture epoch.
    ///
    /// The vCPUs are paused, asynchronous block IO is drained, and event dispatch is stopped for
    /// the whole epoch: every virtio device is a subscriber of its own, so a queue notification
    /// served between two capture commands would write device state or guest memory the
    /// checkpoint has already accounted for. Dispatch is only handed back by a successful
    /// `resume`, or by a `quiesce` that failed before the epoch opened.
    ///
    /// An armed destination is cloned here, the one point where the disk and the memory are
    /// observed on one thread with no writer between them.
    fn quiesce(&mut self, request_id: u64) -> Result<(), ChannelError> {
        match BackendState::load() {
            BackendState::Ready => {}
            BackendState::Quiesced => {
                return self.reject(request_id, ErrorCode::AlreadyQuiesced, MsgType::Quiesce);
            }
            _ => return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Quiesce),
        }

        // Closed before the vCPUs are paused and before this thread takes the VMM lock: a handler
        // in flight is waited for here, and no handler waits on a lock this thread holds.
        dispatch::gate().close();

        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        let were_running = vmm.instance_info.state == VmState::Running;
        if were_running && let Err(err) = vmm.pause_vm() {
            error!("Farplane quiesce could not pause the vCPUs: {err}");
            drop(vmm);
            dispatch::gate().open();
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        if let Err(err) = vmm.drain_guest_memory_writers() {
            error!("Farplane quiesce could not stop every guest-memory writer: {err}");
            // The epoch never opened, so the source is handed back exactly as it was found and the
            // backend stays `Ready`: pagemaster may arm the epoch again.
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
                    info!("Farplane quiesce cloned the scratch disk in {elapsed_us} us");
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
        drop(vmm);

        // A fresh epoch has produced neither a vmstate nor a harvest, whatever the last one
        // reached before it was left.
        self.order.open();
        BackendState::Quiesced.store();
        self.reply(
            request_id,
            MsgType::Quiesced,
            &u32::from(were_running).to_le_bytes(),
        )
    }

    /// Harvests the dirty accumulator into the armed buffer and only then clears it, so a failure
    /// at any step leaves every bit where it was.
    ///
    /// The harvest closes the epoch's dirty set, so it is refused until the vmstate has been
    /// serialized: `prepare_save()` may write guest memory, and those writes have to land in the
    /// bitmap pagemaster reads. Once it has run, a repeat of the command is answered without
    /// touching the accumulator or the armed bitmap: the bits are no longer in the accumulator, so
    /// harvesting again would overwrite the only copy of them with an empty one.
    fn dirty_snapshot(&mut self, request_id: u64) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::DirtySnapshot);
        }
        if self.buffers.is_none() {
            return self.reject(
                request_id,
                ErrorCode::NoCaptureBuffers,
                MsgType::DirtySnapshot,
            );
        }

        let Self {
            channel,
            vmm,
            buffers,
            order,
            ..
        } = self;
        let result = serve_dirty_snapshot(order, || {
            let buffers = buffers
                .as_mut()
                .expect("the armed buffers were just checked");
            harvest(vmm, channel.dirty_bitmap_bytes, &mut buffers.dirty)
        });
        match result {
            Ok(()) => self.reply(request_id, MsgType::DirtySnapshotDone, &[]),
            Err(code) => self.reject(request_id, code, MsgType::DirtySnapshot),
        }
    }

    /// Serializes the vmstate into the armed buffer.
    ///
    /// Refused once the dirty accumulator has been harvested: device serialization may write guest
    /// memory, and the epoch has no way left to report those writes. Before the harvest, a repeat
    /// of the command replays the length the first serialization reported rather than running
    /// `prepare_save()` again and leaving a second, possibly different vmstate in the buffer.
    fn write_vmstate(&mut self, request_id: u64) -> Result<(), ChannelError> {
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

        let Self {
            vmm,
            vm_info,
            buffers,
            order,
            ..
        } = self;
        let result = serve_write_vmstate(order, || {
            let buffers = buffers
                .as_mut()
                .expect("the armed buffers were just checked");
            let state = vmm
                .lock()
                .expect("Poisoned lock")
                .save_state(vm_info)
                .map_err(|err| {
                    error!("Farplane capture could not save the microVM state: {err}");
                    ErrorCode::VmstateWriteFailed
                })?;
            serialize_vmstate(&mut buffers.vmstate, state)
        });
        match result {
            Ok(bytes) => self.reply(request_id, MsgType::VmstateWritten, &bytes.to_le_bytes()),
            Err(code) => self.reject(request_id, code, MsgType::WriteVmstate),
        }
    }

    /// Returns a previously harvested bitmap to the accumulator so the next harvest reports it.
    ///
    /// The returned bits are back in the accumulator and no longer in the armed bitmap, so the
    /// epoch owes a harvest again: the next `dirty_snapshot` harvests rather than replaying.
    fn dirty_union(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::DirtyUnion);
        }
        let [bitmap] =
            <[_; 1]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        if let Err(code) = validate_buffer_fd(bitmap.as_raw_fd(), self.channel.dirty_bitmap_bytes) {
            return self.reject(request_id, code, MsgType::DirtyUnion);
        }

        let mut file = File::from(bitmap);
        match self.read_bitmap(&mut file) {
            Ok(bits) => {
                let vmm = self.vmm.lock().expect("Poisoned lock");
                let unioned = match vmm.kvm_vm() {
                    Some(kvm_vm) => kvm_vm.union_dirty_log(&bits).map_err(|err| {
                        error!("Farplane capture could not return the dirty bits: {err}");
                    }),
                    None => Err(()),
                };
                if unioned.is_err() {
                    drop(vmm);
                    return self.reject(
                        request_id,
                        ErrorCode::DirtyHarvestFailed,
                        MsgType::DirtyUnion,
                    );
                }
                drop(vmm);
                self.order.unioned();
                self.reply(request_id, MsgType::UnionDone, &[])
            }
            Err(code) => self.reject(request_id, code, MsgType::DirtyUnion),
        }
    }

    /// Leaves the capture epoch, restarting the vCPUs when pagemaster asks for it, and hands event
    /// dispatch back. The armed buffers go with it, the disk clone destination among them. The
    /// initial boot and restore acknowledgement is answered by the handshake itself, so on this
    /// channel the command is only ever a capture exit.
    fn resume(&mut self, request_id: u64, run_vcpus: u32) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Resume);
        }

        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        if run_vcpus > 0
            && vmm.instance_info.state != VmState::Running
            && let Err(err) = vmm.resume_vm()
        {
            error!("Farplane capture could not restart the vCPUs: {err}");
            drop(vmm);
            return self.reject(request_id, ErrorCode::ResumeFailed, MsgType::Resume);
        }
        let running = vmm.instance_info.state == VmState::Running;
        drop(vmm);

        self.buffers = None;
        self.order.open();
        set_capture_buffers_armed(false);
        BackendState::Ready.store();
        // The epoch is over, so the event loop may dispatch again. This is the only path that
        // hands dispatch back once an epoch has opened.
        dispatch::gate().open();
        self.reply(
            request_id,
            MsgType::Resumed,
            &u32::from(running).to_le_bytes(),
        )
    }

    /// Reads a bitmap of the geometry's exact shape out of a descriptor.
    fn read_bitmap(&self, file: &mut File) -> Result<Vec<Vec<u64>>, ErrorCode> {
        let page = crate::arch::host_page_size() as u64;
        let mut raw = vec![0u8; u64_to_usize(self.channel.dirty_bitmap_bytes)];
        file.seek(SeekFrom::Start(0))
            .map_err(|_| ErrorCode::BufferTooSmall)?;
        std::io::Read::read_exact(file, &mut raw).map_err(|_| ErrorCode::BufferTooSmall)?;

        let mut offset = 0;
        let mut bits = Vec::with_capacity(self.channel.regions.len());
        for region in &self.channel.regions {
            let words = u64_to_usize(region.size.div_ceil(page).div_ceil(64));
            let mut region_bits = Vec::with_capacity(words);
            for _ in 0..words {
                let word = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
                region_bits.push(word);
                offset += 8;
            }
            bits.push(region_bits);
        }
        Ok(bits)
    }

    /// Sends a reply that echoes the request identifier, and records it for an exact retry.
    fn reply(&mut self, request_id: u64, msg: MsgType, body: &[u8]) -> Result<(), ChannelError> {
        self.answer(request_id, msg, body.to_vec())
    }

    /// Rejects a command without changing any state. The rejection is the command's answer, so a
    /// retry of it is answered the same way rather than served.
    fn reject(
        &mut self,
        request_id: u64,
        code: ErrorCode,
        op: MsgType,
    ) -> Result<(), ChannelError> {
        let body = protocol::encode_error(code, op, "");
        self.answer(request_id, MsgType::Error, body)
    }

    /// Sends one answer and records it as the answer of the command being served.
    fn answer(&mut self, request_id: u64, msg: MsgType, body: Vec<u8>) -> Result<(), ChannelError> {
        send_and_record(
            &self.channel.sock,
            &mut self.replies,
            &mut self.pending,
            request_id,
            msg,
            body,
        )
    }
}

/// Decides whether an armed destination could hold a clone at all: it has to be a descriptor a
/// reflink can land in, and the guest has to have a scratch drive to clone from.
fn accept_clone_destination(destination: RawFd, scratch: Option<RawFd>) -> Result<(), ErrorCode> {
    validate_clone_destination(destination)?;
    if scratch.is_none() {
        return Err(ErrorCode::NoScratchDrive);
    }
    Ok(())
}

/// Hands the source back exactly as `quiesce` found it, for a failure before the epoch opened. A
/// source that cannot be handed back is no longer describable, so the channel fails and dispatch
/// stays stopped until the supervisor kills this process.
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

/// Reflinks the scratch disk into `destination`, reporting how long the ioctl took in
/// microseconds. `FICLONE` writes the source's dirty host pages back and then shares its extents,
/// so the destination is the whole disk at this instant and no byte is copied.
fn clone_scratch(destination: RawFd, scratch: RawFd) -> Result<u64, io::Error> {
    let started = get_time_us(ClockType::Monotonic);
    // SAFETY: both arguments are descriptors this process holds open, and the return code is
    // checked.
    if unsafe { libc::ioctl(destination, libc::FICLONE, scratch) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(get_time_us(ClockType::Monotonic) - started)
}

/// Snapshots the dirty accumulator, writes it out, and only then clears it.
fn harvest(vmm: &Mutex<Vmm>, dirty_bitmap_bytes: u64, buffer: &mut File) -> Result<(), ErrorCode> {
    let vmm = vmm.lock().expect("Poisoned lock");
    let kvm_vm = vmm.kvm_vm().ok_or(ErrorCode::DirtyHarvestFailed)?;
    let snapshot = kvm_vm.snapshot_dirty_log().map_err(|err| {
        error!("Farplane capture could not read the dirty log: {err}");
        ErrorCode::DirtyHarvestFailed
    })?;

    let bytes: u64 = snapshot.iter().map(|words| words.len() as u64 * 8).sum();
    if bytes != dirty_bitmap_bytes {
        return Err(ErrorCode::DirtyHarvestFailed);
    }
    buffer
        .seek(SeekFrom::Start(0))
        .map_err(|_| ErrorCode::DirtyHarvestFailed)?;
    for words in &snapshot {
        // SAFETY: the words are a contiguous little-endian bitmap, which is exactly the wire
        // representation, so they are written without a second copy.
        let raw =
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), words.len() * 8) };
        buffer
            .write_all(raw)
            .map_err(|_| ErrorCode::DirtyHarvestFailed)?;
    }
    buffer.flush().map_err(|_| ErrorCode::DirtyHarvestFailed)?;

    kvm_vm.clear_dirty_log(&snapshot).map_err(|err| {
        error!("Farplane capture could not clear the dirty log: {err}");
        ErrorCode::DirtyHarvestFailed
    })
}

/// Writes the vmstate at offset zero of the armed buffer and reports its length. The writer stops
/// at the capacity `backend_ready` advertised, so a vmstate larger than the bound fails here
/// instead of overrunning what pagemaster reserved.
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

/// Writer that refuses to write past the capacity `backend_ready` advertised.
#[derive(Debug)]
struct BoundedWriter<'a> {
    inner: &'a mut File,
    /// Bytes the advertised capacity still allows.
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
