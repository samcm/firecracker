// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use super::backend::{
    BackendState, MemoryChannel, VMSTATE_CAPACITY_BYTES, send_error, set_capture_buffers_armed,
    validate_buffer_fd,
};
use super::protocol::{self, ChannelError, ErrorCode, Incoming, MsgType};
use crate::Vmm;
use crate::logger::error;
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::utils::{u64_to_usize, usize_to_u64};
use crate::vmm_config::instance_info::VmState;

/// Buffers pagemaster preallocated for one capture epoch.
#[derive(Debug)]
struct CaptureBuffers {
    dirty: File,
    vmstate: File,
}

/// How far through one capture epoch the commands that produce a checkpoint have got.
///
/// The vmstate has to be serialized before the dirty accumulator is harvested. Serialization
/// calls `prepare_save()` on every device, and a device may write guest memory there: virtio-vsock
/// publishes a `TRANSPORT_RESET` event into the guest's event queue. A harvest that ran first
/// would report a bitmap that predates those writes, so pagemaster would copy pages the restored
/// vmstate no longer agrees with. The order is a property of the epoch, not of one command, so it
/// is tracked here and enforced for both directions.
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
                };
                loop {
                    if BackendState::load() == BackendState::ChannelFailed {
                        return;
                    }
                    if let Err(err) = service.serve_one() {
                        error!("Farplane memory channel failed: {err}");
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
        let (body_len, fd_count) = match msg {
            MsgType::CaptureBuffers => (0, 2),
            MsgType::Quiesce | MsgType::DirtySnapshot | MsgType::WriteVmstate => (0, 0),
            MsgType::DirtyUnion => (0, 1),
            MsgType::Resume => (4, 0),
            _ => return Err(ChannelError::Malformed),
        };
        if incoming.body.len() != body_len || incoming.fds.len() != fd_count {
            return Err(ChannelError::Malformed);
        }

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

    /// Validates and arms the buffers of one capture epoch.
    fn arm_buffers(&mut self, incoming: Incoming) -> Result<(), ChannelError> {
        let request_id = incoming.header.request_id;
        if BackendState::load() != BackendState::Ready {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::CaptureBuffers);
        }
        let [dirty, vmstate] =
            <[_; 2]>::try_from(incoming.fds).map_err(|_| ChannelError::FdCountMismatch)?;
        if let Err(code) = validate_buffer_fd(dirty.as_raw_fd(), self.channel.dirty_bitmap_bytes) {
            return self.reject(request_id, code, MsgType::CaptureBuffers);
        }
        if let Err(code) = validate_buffer_fd(vmstate.as_raw_fd(), VMSTATE_CAPACITY_BYTES) {
            return self.reject(request_id, code, MsgType::CaptureBuffers);
        }

        self.buffers = Some(CaptureBuffers {
            dirty: File::from(dirty),
            vmstate: File::from(vmstate),
        });
        set_capture_buffers_armed(true);
        self.reply(request_id, MsgType::CaptureBuffersArmed, &[])
    }

    /// Stops every guest-memory writer and enters the capture epoch.
    fn quiesce(&mut self, request_id: u64) -> Result<(), ChannelError> {
        match BackendState::load() {
            BackendState::Ready => {}
            BackendState::Quiesced => {
                return self.reject(request_id, ErrorCode::AlreadyQuiesced, MsgType::Quiesce);
            }
            _ => return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Quiesce),
        }

        let mut vmm = self.vmm.lock().expect("Poisoned lock");
        let were_running = vmm.instance_info.state == VmState::Running;
        if were_running && let Err(err) = vmm.pause_vm() {
            error!("Farplane quiesce could not pause the vCPUs: {err}");
            drop(vmm);
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
        }
        if let Err(err) = vmm.drain_guest_memory_writers() {
            error!("Farplane quiesce could not stop every guest-memory writer: {err}");
            // The epoch never opened, so the source is handed back exactly as it was found and the
            // backend stays `Ready`: pagemaster may arm the epoch again. A source that cannot be
            // handed back is no longer describable, so the channel fails and the supervisor kills
            // this process.
            if were_running && let Err(err) = vmm.resume_vm() {
                error!(
                    "Farplane quiesce could not restart the vCPUs after the failed drain: {err}"
                );
                BackendState::fail();
            }
            drop(vmm);
            return self.reject(request_id, ErrorCode::QuiesceFailed, MsgType::Quiesce);
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
                match vmm.kvm_vm() {
                    Some(kvm_vm) => kvm_vm.union_dirty_log(&bits),
                    None => {
                        drop(vmm);
                        return self.reject(
                            request_id,
                            ErrorCode::DirtyHarvestFailed,
                            MsgType::DirtyUnion,
                        );
                    }
                }
                drop(vmm);
                self.order.unioned();
                self.reply(request_id, MsgType::UnionDone, &[])
            }
            Err(code) => self.reject(request_id, code, MsgType::DirtyUnion),
        }
    }

    /// Leaves the capture epoch, restarting the vCPUs when pagemaster asks for it. The initial
    /// boot and restore acknowledgement is answered by the handshake itself, so on this channel
    /// the command is only ever a capture exit.
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

    /// Sends a reply that echoes the request identifier.
    fn reply(&self, request_id: u64, msg: MsgType, body: &[u8]) -> Result<(), ChannelError> {
        protocol::send_frame(&self.channel.sock, msg, request_id, body, &[])
    }

    /// Rejects a command without changing any state.
    fn reject(&self, request_id: u64, code: ErrorCode, op: MsgType) -> Result<(), ChannelError> {
        send_error(&self.channel.sock, request_id, code, op);
        Ok(())
    }
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
}
