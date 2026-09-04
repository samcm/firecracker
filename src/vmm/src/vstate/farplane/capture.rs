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

/// Stable identity of one descriptor a frame carried: which file it refers to, and how large that
/// file is. Two descriptors duplicated from one memfd report the same identity; a descriptor of
/// another memfd does not. Descriptor numbers are process-local and say nothing, so they are not
/// part of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorIdentity {
    dev: libc::dev_t,
    ino: libc::ino_t,
    size: libc::off_t,
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
        size: stat.st_size,
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

    /// Stops every guest-memory writer, clones the scratch disk when a destination is armed, and
    /// enters the capture epoch.
    ///
    /// The vCPUs are paused, asynchronous block IO is drained, and event dispatch is stopped for
    /// the whole epoch: every virtio device is a subscriber of its own, so a queue notification
    /// served between two capture commands would write device state or guest memory the
    /// checkpoint has already accounted for. Dispatch is only handed back by a successful
    /// `resume`, or by a `quiesce` that failed before the epoch opened.
    ///
    /// The clone is taken here because this is the only point at which the disk and the memory
    /// are observed on one thread with no writer between them: every block writer has stopped
    /// and no epoch has opened, so a clone that fails refuses the quiesce and seals nothing.
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
    /// dispatch back. The initial boot and restore acknowledgement is answered by the handshake
    /// itself, so on this channel the command is only ever a capture exit.
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

/// Hands the source back exactly as `quiesce` found it, for a failure before the epoch opened.
///
/// A source that cannot be handed back is no longer describable, so the channel fails and the
/// supervisor kills this process; until it does, dispatch stays stopped so no handler writes
/// guest memory.
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
mod tests {
    use std::os::fd::FromRawFd;

    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    /// The advertised vmstate capacity is a bound, not a promise: a serialization that would pass
    /// it fails instead of writing past what pagemaster reserved.
    #[test]
    fn the_vmstate_writer_stops_at_the_advertised_capacity() {
        let mut file = TempFile::new().unwrap().into_file();
        let mut writer = BoundedWriter {
            inner: &mut file,
            remaining: 8,
        };

        assert_eq!(writer.write(&[0u8; 6]).unwrap(), 6);
        assert_eq!(
            writer.write(&[0u8; 4]).unwrap_err().raw_os_error(),
            Some(libc::EFBIG)
        );
        assert_eq!(writer.write(&[0u8; 2]).unwrap(), 2);
        assert_eq!(writer.remaining, 0);
    }

    /// A counting stand-in for the effect a capture command performs, so a test can prove the
    /// effect ran exactly once however many times the command arrives.
    #[derive(Debug, Default)]
    struct Effect {
        runs: std::cell::Cell<u32>,
    }

    impl Effect {
        /// Runs the effect, reporting `outcome`.
        fn run<T>(&self, outcome: Result<T, ErrorCode>) -> Result<T, ErrorCode> {
            self.runs.set(self.runs.get() + 1);
            outcome
        }
    }

    /// The order one epoch's commands may arrive in: the vmstate first, the harvest after it.
    #[test]
    fn the_capture_order_accepts_state_then_harvest() {
        let mut order = EpochOrder::default();

        assert_eq!(order.vmstate_step(), VmstateStep::Serialize);
        order.vmstate_written(4096);
        assert_eq!(order.harvest_step(), HarvestStep::Harvest);
        order.harvested();

        assert_eq!(order.phase, EpochPhase::Harvested);
    }

    /// A harvest ahead of the vmstate would report a bitmap that predates the guest-memory writes
    /// `prepare_save()` performs, so it is refused with the order violation, not served.
    #[test]
    fn the_capture_order_refuses_a_harvest_before_the_vmstate() {
        let mut order = EpochOrder::default();

        assert_eq!(
            order.harvest_step(),
            HarvestStep::Refuse(ErrorCode::CaptureOrderViolation),
            "a harvest must not precede the vmstate"
        );
        // The refusal changed nothing: the epoch still owes a vmstate, and the harvest that
        // follows it is served.
        assert_eq!(order.vmstate_step(), VmstateStep::Serialize);
        order.vmstate_written(4096);
        assert_eq!(order.harvest_step(), HarvestStep::Harvest);
    }

    /// Serializing after the harvest is the same violation seen from the other side: the writes
    /// that serialization performs have no harvest left to report them.
    #[test]
    fn the_capture_order_refuses_a_vmstate_after_the_harvest() {
        let mut order = EpochOrder::default();
        order.vmstate_written(4096);
        order.harvested();

        assert_eq!(
            order.vmstate_step(),
            VmstateStep::Refuse(ErrorCode::CaptureOrderViolation)
        );
    }

    /// A repeat of `dirty_snapshot` is a replay, not a second harvest: the accumulator no longer
    /// holds the bits the armed bitmap does, so harvesting again would overwrite the only copy of
    /// this epoch's dirty set with an empty one.
    #[test]
    fn a_repeated_harvest_replays_instead_of_clearing_the_bitmap() {
        let mut order = EpochOrder::default();
        order.vmstate_written(4096);
        order.harvested();

        assert_eq!(order.harvest_step(), HarvestStep::Replay);
        // The replay is not a state change either: however many arrive, the epoch stays harvested.
        assert_eq!(order.harvest_step(), HarvestStep::Replay);
        assert_eq!(order.phase, EpochPhase::Harvested);
    }

    /// A repeat of `write_vmstate` replays the exact length the first one reported rather than
    /// running `prepare_save()` again and leaving a different vmstate in the buffer.
    #[test]
    fn a_repeated_vmstate_replays_the_length_the_first_one_reported() {
        let mut order = EpochOrder::default();

        order.vmstate_written(12_345);

        assert_eq!(order.vmstate_step(), VmstateStep::Replay(12_345));
        assert_eq!(order.vmstate_step(), VmstateStep::Replay(12_345));
        assert_eq!(order.harvest_step(), HarvestStep::Harvest);
    }

    /// A bitmap folded back into the accumulator is no longer in the armed bitmap, so the epoch
    /// owes a harvest again: the next `dirty_snapshot` harvests rather than replaying.
    #[test]
    fn a_union_makes_the_next_harvest_run_again() {
        let mut order = EpochOrder::default();
        order.vmstate_written(4096);
        order.harvested();

        order.unioned();

        assert_eq!(order.phase, EpochPhase::StateWritten);
        assert_eq!(order.harvest_step(), HarvestStep::Harvest);
        // The vmstate is still the one the epoch recorded: a union does not ask for another.
        assert_eq!(order.vmstate_step(), VmstateStep::Replay(4096));
    }

    /// A union before any harvest leaves the epoch where it was: it owes nothing back.
    #[test]
    fn a_union_before_the_harvest_changes_nothing() {
        let mut order = EpochOrder::default();

        order.unioned();
        assert_eq!(order.phase, EpochPhase::Open);

        order.vmstate_written(4096);
        order.unioned();
        assert_eq!(order.phase, EpochPhase::StateWritten);
        assert_eq!(order.vmstate_step(), VmstateStep::Replay(4096));
    }

    /// Every epoch starts owing a vmstate, whatever the previous one reached: `quiesce` and
    /// `resume` both open a fresh one.
    #[test]
    fn opening_an_epoch_forgets_what_the_last_one_reached() {
        let mut order = EpochOrder::default();
        order.vmstate_written(4096);
        order.harvested();

        order.open();

        assert_eq!(order.phase, EpochPhase::Open);
        assert_eq!(
            order.harvest_step(),
            HarvestStep::Refuse(ErrorCode::CaptureOrderViolation),
            "a fresh epoch must not inherit the last epoch's vmstate"
        );
        assert_eq!(
            order.vmstate_step(),
            VmstateStep::Serialize,
            "a fresh epoch must not replay the last epoch's length"
        );
    }

    /// The service half of the harvest: the second command reports success without reading or
    /// clearing the accumulator, so the bitmap the first one produced survives the retry.
    #[test]
    fn the_served_harvest_runs_once_however_often_it_arrives() {
        let mut order = EpochOrder::default();
        serve_write_vmstate(&mut order, || Ok(4096)).unwrap();
        let effect = Effect::default();

        serve_dirty_snapshot(&mut order, || effect.run(Ok(()))).unwrap();
        serve_dirty_snapshot(&mut order, || effect.run(Ok(()))).unwrap();
        serve_dirty_snapshot(&mut order, || effect.run(Ok(()))).unwrap();

        assert_eq!(
            effect.runs.get(),
            1,
            "a repeated dirty_snapshot must not harvest a second time"
        );
    }

    /// The service half of the serialization: the second command reports the first one's length
    /// without running device serialization again.
    #[test]
    fn the_served_vmstate_runs_once_and_replays_its_length() {
        let mut order = EpochOrder::default();
        let effect = Effect::default();

        let first = serve_write_vmstate(&mut order, || effect.run(Ok(9_001))).unwrap();
        let second = serve_write_vmstate(&mut order, || effect.run(Ok(7))).unwrap();

        assert_eq!(first, 9_001);
        assert_eq!(
            second, 9_001,
            "a repeated write_vmstate must report the length that is in the buffer"
        );
        assert_eq!(
            effect.runs.get(),
            1,
            "a repeated write_vmstate must not serialize a second time"
        );
    }

    /// A failure records nothing: the retry of a failed command does the work, and a failed
    /// serialization still blocks the harvest.
    #[test]
    fn a_failed_command_is_retried_rather_than_replayed() {
        let mut order = EpochOrder::default();
        let effect = Effect::default();

        assert_eq!(
            serve_write_vmstate(&mut order, || effect
                .run(Err(ErrorCode::VmstateWriteFailed))),
            Err(ErrorCode::VmstateWriteFailed)
        );
        assert_eq!(
            serve_dirty_snapshot(&mut order, || effect.run(Ok(()))),
            Err(ErrorCode::CaptureOrderViolation),
            "a serialization that failed leaves the epoch owing one"
        );
        assert_eq!(effect.runs.get(), 1, "the refused harvest must not run");

        assert_eq!(
            serve_write_vmstate(&mut order, || effect.run(Ok(64))),
            Ok(64)
        );
        assert_eq!(
            serve_dirty_snapshot(&mut order, || effect
                .run(Err(ErrorCode::DirtyHarvestFailed))),
            Err(ErrorCode::DirtyHarvestFailed)
        );
        // The failed harvest cleared nothing, so the retry harvests instead of replaying.
        assert_eq!(
            serve_dirty_snapshot(&mut order, || effect.run(Ok(()))),
            Ok(())
        );
        assert_eq!(effect.runs.get(), 4);
        assert_eq!(order.phase, EpochPhase::Harvested);
    }

    /// A memfd of `size` bytes, owned by the caller.
    fn memfd(name: &std::ffi::CStr, size: u64) -> OwnedFd {
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: the descriptor was just created and is not owned by anything else.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: `owned` is a fresh memfd, so it may be sized.
        let sized = unsafe { libc::ftruncate(owned.as_raw_fd(), size.cast_signed()) };
        assert_eq!(sized, 0, "{}", io::Error::last_os_error());
        owned
    }

    /// Another descriptor for the same open file, as a retry of a descriptor-bearing command
    /// carries: duplicated, not reopened.
    fn duplicate(fd: &OwnedFd) -> OwnedFd {
        fd.try_clone().unwrap()
    }

    /// The command a bodyless frame with no descriptors carries.
    fn command(msg: MsgType) -> CommandKey {
        CommandKey::of(msg, &[], &[])
    }

    /// The retry of an answered command is replayed by identifier and exact command, whatever the
    /// epoch has done since. This is the case phase alone cannot cover: a `dirty_union` reopens
    /// the dirty set, so the phase would harvest again for a command already answered.
    #[test]
    fn an_answered_request_is_replayed_after_later_commands() {
        let mut replies = ReplyCache::default();
        replies.record(
            7,
            command(MsgType::DirtySnapshot),
            MsgType::DirtySnapshotDone,
            Vec::new(),
        );

        // A union and a resume happen on other identifiers, and a new epoch follows.
        let bitmap = memfd(c"farplane-union", 4096);
        replies.record(
            8,
            CommandKey::of(MsgType::DirtyUnion, &[], std::slice::from_ref(&bitmap)),
            MsgType::UnionDone,
            Vec::new(),
        );
        let resumed = 1u32.to_le_bytes().to_vec();
        replies.record(
            9,
            CommandKey::of(MsgType::Resume, &resumed, &[]),
            MsgType::Resumed,
            resumed.clone(),
        );
        replies.record(10, command(MsgType::Quiesce), MsgType::Quiesced, resumed);

        assert_eq!(
            replies.disposition(7, &command(MsgType::DirtySnapshot)),
            FrameDisposition::Replay(MsgType::DirtySnapshotDone, Vec::new()),
            "the original harvest reply must be replayed, not harvested again"
        );
    }

    /// A retry of a descriptor-bearing command duplicates the descriptors of the same memfds. The
    /// descriptor numbers differ, the files do not, so the answer is replayed.
    #[test]
    fn a_retry_with_duplicated_descriptors_is_replayed() {
        let dirty = memfd(c"farplane-dirty", 4096);
        let vmstate = memfd(c"farplane-vmstate", 8192);
        let sent = [duplicate(&dirty), duplicate(&vmstate)];
        let mut replies = ReplyCache::default();
        replies.record(
            3,
            CommandKey::of(MsgType::CaptureBuffers, &[], &sent),
            MsgType::CaptureBuffersArmed,
            Vec::new(),
        );

        let retried = [duplicate(&dirty), duplicate(&vmstate)];
        assert_ne!(
            retried[0].as_raw_fd(),
            sent[0].as_raw_fd(),
            "the retry must carry other descriptor numbers for the same files"
        );
        assert_eq!(
            replies.disposition(3, &CommandKey::of(MsgType::CaptureBuffers, &[], &retried)),
            FrameDisposition::Replay(MsgType::CaptureBuffersArmed, Vec::new())
        );
    }

    /// Same identifier, same message, same body, same descriptor count, other memfds: the answer
    /// on record acknowledged buffers that are not these, so it is refused.
    #[test]
    fn a_retry_naming_other_memfds_is_refused() {
        let dirty = memfd(c"farplane-dirty", 4096);
        let vmstate = memfd(c"farplane-vmstate", 8192);
        let mut replies = ReplyCache::default();
        replies.record(
            3,
            CommandKey::of(
                MsgType::CaptureBuffers,
                &[],
                &[duplicate(&dirty), duplicate(&vmstate)],
            ),
            MsgType::CaptureBuffersArmed,
            Vec::new(),
        );

        // Other files of exactly the same sizes, in the same order.
        let other_dirty = memfd(c"farplane-dirty", 4096);
        let other_vmstate = memfd(c"farplane-vmstate", 8192);
        assert_eq!(
            replies.disposition(
                3,
                &CommandKey::of(MsgType::CaptureBuffers, &[], &[other_dirty, other_vmstate])
            ),
            FrameDisposition::Reused,
            "a frame naming other memfds is not the command that was answered"
        );

        // Nor is the same file in the other position.
        assert_eq!(
            replies.disposition(
                3,
                &CommandKey::of(
                    MsgType::CaptureBuffers,
                    &[],
                    &[duplicate(&vmstate), duplicate(&dirty)]
                )
            ),
            FrameDisposition::Reused,
            "descriptor order is part of the command"
        );
    }

    /// Equality is over the command bytes themselves, not a digest of them: a message or a body
    /// that differs is a different command, whatever any hash of it would say.
    #[test]
    fn a_different_message_or_body_is_refused() {
        let mut replies = ReplyCache::default();
        replies.record(
            7,
            command(MsgType::DirtySnapshot),
            MsgType::DirtySnapshotDone,
            Vec::new(),
        );

        assert_eq!(
            replies.disposition(7, &command(MsgType::WriteVmstate)),
            FrameDisposition::Reused
        );

        let mut replies = ReplyCache::default();
        let stop = 0u32.to_le_bytes().to_vec();
        replies.record(
            9,
            CommandKey::of(MsgType::Resume, &stop, &[]),
            MsgType::Resumed,
            Vec::new(),
        );
        assert_eq!(
            replies.disposition(
                9,
                &CommandKey::of(MsgType::Resume, &1u32.to_le_bytes(), &[])
            ),
            FrameDisposition::Reused,
            "the body of a resume decides whether the vCPUs run"
        );
    }

    /// A descriptor whose identity could not be read is never exact, on either side: such a
    /// command is refused rather than acknowledged with an answer about resources that may have
    /// changed.
    #[test]
    fn an_unprovable_descriptor_identity_is_never_exact() {
        let unprovable = CommandKey {
            msg: MsgType::DirtyUnion,
            body: Vec::new(),
            descriptors: None,
        };
        assert!(!unprovable.is_exactly(&unprovable));

        let bitmap = memfd(c"farplane-union", 4096);
        let provable = CommandKey::of(MsgType::DirtyUnion, &[], std::slice::from_ref(&bitmap));
        assert!(!unprovable.is_exactly(&provable));
        assert!(!provable.is_exactly(&unprovable));

        let mut replies = ReplyCache::default();
        replies.record(4, unprovable.clone(), MsgType::UnionDone, Vec::new());
        assert_eq!(
            replies.disposition(4, &unprovable),
            FrameDisposition::Reused
        );

        let mut replies = ReplyCache::default();
        replies.record(4, provable, MsgType::UnionDone, Vec::new());
        assert_eq!(
            replies.disposition(4, &unprovable),
            FrameDisposition::Reused
        );
    }

    /// A fresh identifier is served, and one below the high-water mark whose answer has been
    /// evicted is refused rather than served a second time.
    #[test]
    fn an_identifier_too_old_to_replay_is_refused_rather_than_served() {
        let mut replies = ReplyCache::default();
        for request_id in 1..=protocol::MAX_RETRYABLE_REQUESTS as u64 + 1 {
            replies.record(
                request_id,
                command(MsgType::Quiesce),
                MsgType::Quiesced,
                Vec::new(),
            );
        }

        assert_eq!(
            replies.answers.len(),
            protocol::MAX_RETRYABLE_REQUESTS,
            "the history is bounded"
        );
        assert_eq!(
            replies.disposition(1, &command(MsgType::Quiesce)),
            FrameDisposition::Reused,
            "an evicted answer must not be re-served"
        );
        assert_eq!(
            replies.disposition(9_999, &command(MsgType::Quiesce)),
            FrameDisposition::Serve
        );
    }

    /// A send that never reached pagemaster does not undo the command: the answer is recorded, so
    /// the retry that follows the lost reply is answered rather than served again.
    #[test]
    fn an_answer_whose_send_failed_is_still_recorded() {
        let (sock, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let mut replies = ReplyCache::default();
        let mut pending = Some((5, command(MsgType::DirtySnapshot)));

        let sent = send_and_record(
            &sock,
            &mut replies,
            &mut pending,
            5,
            MsgType::DirtySnapshotDone,
            Vec::new(),
        );

        assert!(
            sent.is_err(),
            "the peer is gone, so the send cannot succeed"
        );
        assert_eq!(
            replies.disposition(5, &command(MsgType::DirtySnapshot)),
            FrameDisposition::Replay(MsgType::DirtySnapshotDone, Vec::new()),
            "the effect happened, so the answer has to survive the failed send"
        );
        assert!(pending.is_none(), "the command was answered exactly once");
    }

    /// The descriptors a replayed or refused frame carried are closed on the way out, exactly as
    /// a served command closes them: `Incoming` owns them, and dropping it is that close.
    #[test]
    fn a_frames_descriptors_are_closed_when_it_is_not_served() {
        let bitmap = memfd(c"farplane-union", 4096);
        let raw = bitmap.as_raw_fd();
        let incoming = Incoming {
            header: protocol::Header::new(MsgType::DirtyUnion, 11, 0, 1),
            body: Vec::new(),
            fds: vec![bitmap],
        };
        // SAFETY: `F_GETFD` only reads the flags of a descriptor.
        let open = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert!(open >= 0, "the frame should own an open descriptor");

        drop(incoming);

        // SAFETY: as above; the descriptor is expected to be closed by now.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF),
            "a frame that was not served must not leak its descriptors"
        );
    }

    /// Directory on a reflink filesystem the clone proofs need, or a skip reason.
    fn reflink_dir() -> Option<std::path::PathBuf> {
        match std::env::var_os("FARPLANE_TEST_XFS_DIR") {
            Some(dir) => Some(std::path::PathBuf::from(dir)),
            None => {
                eprintln!(
                    "skipping: FARPLANE_TEST_XFS_DIR must name a directory on an XFS filesystem \
                     formatted with reflink=1, because FICLONE has no meaning without one"
                );
                None
            }
        }
    }

    /// A file of `content` under `dir`, opened read-write.
    fn file_in(dir: &std::path::Path, name: &str, content: &[u8]) -> File {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(dir.join(name))
            .unwrap();
        file.write_all(content).unwrap();
        file.flush().unwrap();
        file
    }

    /// A destination is only worth arming for a guest that has a disk: a clone of nothing is a
    /// clone that could never be taken, so it is refused while the source can still be resumed.
    #[test]
    fn an_armed_destination_is_refused_without_a_scratch_drive() {
        let destination = TempFile::new().unwrap();
        let fd = destination.as_file().as_raw_fd();

        assert_eq!(
            accept_clone_destination(fd, None),
            Err(ErrorCode::NoScratchDrive)
        );
        assert_eq!(accept_clone_destination(fd, Some(5)), Ok(()));
    }

    /// A reflink lands in a regular file this thread can write, and in nothing else.
    #[test]
    fn a_clone_destination_must_be_a_regular_file_opened_read_write() {
        let regular = TempFile::new().unwrap();
        assert_eq!(
            validate_clone_destination(regular.as_file().as_raw_fd()),
            Ok(())
        );

        let read_only = std::fs::File::open(regular.as_path()).unwrap();
        assert_eq!(
            validate_clone_destination(read_only.as_raw_fd()),
            Err(ErrorCode::BadCloneDestination),
            "a read-only descriptor cannot receive a clone"
        );

        // SAFETY: the path is a NUL-terminated literal and the returned descriptor is owned here.
        let path_fd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH) };
        assert!(path_fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: `path_fd` was just opened and is not owned by anything else.
        let path_fd = unsafe { OwnedFd::from_raw_fd(path_fd) };
        assert_eq!(
            validate_clone_destination(path_fd.as_raw_fd()),
            Err(ErrorCode::BadCloneDestination),
            "an O_PATH descriptor grants no access at all"
        );

        let device = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .unwrap();
        assert_eq!(
            validate_clone_destination(device.as_raw_fd()),
            Err(ErrorCode::BadCloneDestination),
            "a character device is not a file a reflink can share extents with"
        );
    }

    /// The clone the quiesce takes: the destination holds the scratch's bytes when the ioctl
    /// returns, and the duration it reports is what the freeze paid for it.
    #[test]
    fn the_scratch_clone_reproduces_the_disk_and_reports_its_duration() {
        let Some(dir) = reflink_dir() else {
            return;
        };
        let content = vec![0xa5u8; 1 << 20];
        let scratch = file_in(&dir, "farplane-clone-source", &content);
        let destination = file_in(&dir, "farplane-clone-destination", &[]);

        match clone_scratch(destination.as_raw_fd(), scratch.as_raw_fd()) {
            Ok(_) => {}
            Err(err) if err.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                eprintln!(
                    "skipping: {} is not on a filesystem that supports FICLONE, so the reflink \
                     cannot be proven here",
                    dir.display()
                );
                return;
            }
            Err(err) => panic!("the clone failed for a reason other than a missing reflink: {err}"),
        }

        assert_eq!(
            std::fs::read(dir.join("farplane-clone-destination")).unwrap(),
            content,
            "the clone is not the disk the scratch held"
        );
    }

    /// A clone the kernel refuses is reported as a failure carrying its errno, which is what the
    /// quiesce answers `DiskCloneFailed` on. Which errno it is depends on the filesystems:
    /// `EXDEV` across two of them, `EOPNOTSUPP` without reflinks, `EINVAL` or `ENOTTY` for a
    /// source that has no extents to share.
    #[test]
    fn a_clone_the_kernel_refuses_is_reported_as_a_failure() {
        let destination = TempFile::new().unwrap();
        let device = std::fs::File::open("/dev/null").unwrap();

        let err = clone_scratch(destination.as_file().as_raw_fd(), device.as_raw_fd())
            .expect_err("a character device has no extents to clone");

        assert!(
            matches!(
                err.raw_os_error(),
                Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOTTY | libc::EXDEV)
            ),
            "unexpected errno: {err}"
        );
    }
}
