// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm_sys_util::epoll::EventSet;

use super::backend::{
    BackendState, MemoryChannel, VMSTATE_CAPACITY_BYTES, send_error, set_capture_buffers_armed,
    validate_buffer_fd,
};
use super::protocol::{self, ChannelError, ErrorCode, Incoming, MsgType};
use crate::logger::{error, warn};
use crate::persist::{MicrovmState, VmInfo};
use crate::snapshot::Snapshot;
use crate::utils::u64_to_usize;
use crate::vmm_config::instance_info::VmState;
use crate::{EventManager, Vmm};

/// Buffers pagemaster preallocated for one capture epoch.
#[derive(Debug)]
struct CaptureBuffers {
    dirty: File,
    vmstate: File,
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
}

impl CaptureService {
    /// Starts serving capture commands for `vmm`.
    pub fn register(
        channel: MemoryChannel,
        vmm: Arc<Mutex<Vmm>>,
        vm_info: VmInfo,
        event_manager: &mut EventManager,
    ) {
        event_manager.add_subscriber(Arc::new(Mutex::new(Self {
            channel,
            vmm,
            vm_info,
            buffers: None,
        })));
    }

    /// Serves exactly one command.
    fn serve_one(&mut self) -> Result<(), ChannelError> {
        let incoming = protocol::recv_frame(&self.channel.sock)?;
        let request_id = incoming.header.request_id;
        if request_id == 0 {
            return Err(ChannelError::Malformed);
        }
        match incoming.header.msg() {
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
        vmm.drain_guest_memory_writers();
        drop(vmm);

        BackendState::Quiesced.store();
        self.reply(
            request_id,
            MsgType::Quiesced,
            &u32::from(were_running).to_le_bytes(),
        )
    }

    /// Harvests the dirty accumulator into the armed buffer and only then clears it, so a failure
    /// at any step leaves every bit where it was.
    fn dirty_snapshot(&mut self, request_id: u64) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::DirtySnapshot);
        }
        let Some(mut buffers) = self.buffers.take() else {
            return self.reject(
                request_id,
                ErrorCode::NoCaptureBuffers,
                MsgType::DirtySnapshot,
            );
        };

        let result = self.harvest(&mut buffers.dirty);
        self.buffers = Some(buffers);
        match result {
            Ok(()) => self.reply(request_id, MsgType::DirtySnapshotDone, &[]),
            Err(code) => self.reject(request_id, code, MsgType::DirtySnapshot),
        }
    }

    /// Serializes the vmstate into the armed buffer.
    fn write_vmstate(&mut self, request_id: u64) -> Result<(), ChannelError> {
        if BackendState::load() != BackendState::Quiesced {
            return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::WriteVmstate);
        }
        let Some(mut buffers) = self.buffers.take() else {
            return self.reject(
                request_id,
                ErrorCode::NoCaptureBuffers,
                MsgType::WriteVmstate,
            );
        };

        let saved = self
            .vmm
            .lock()
            .expect("Poisoned lock")
            .save_state(&self.vm_info)
            .map_err(|err| {
                error!("Farplane capture could not save the microVM state: {err}");
                ErrorCode::VmstateWriteFailed
            });
        let result = saved.and_then(|state| serialize_vmstate(&mut buffers.vmstate, state));
        self.buffers = Some(buffers);
        match result {
            Ok(bytes) => self.reply(request_id, MsgType::VmstateWritten, &bytes.to_le_bytes()),
            Err(code) => self.reject(request_id, code, MsgType::WriteVmstate),
        }
    }

    /// Returns a previously harvested bitmap to the accumulator so the next harvest reports it.
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
                self.reply(request_id, MsgType::UnionDone, &[])
            }
            Err(code) => self.reject(request_id, code, MsgType::DirtyUnion),
        }
    }

    /// Leaves the capture epoch, restarting the vCPUs when pagemaster asks for it.
    fn resume(&mut self, request_id: u64, run_vcpus: u32) -> Result<(), ChannelError> {
        match BackendState::load() {
            BackendState::Ready | BackendState::Quiesced => {}
            _ => return self.reject(request_id, ErrorCode::NotQuiesced, MsgType::Resume),
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
        set_capture_buffers_armed(false);
        BackendState::Ready.store();
        self.reply(
            request_id,
            MsgType::Resumed,
            &u32::from(running).to_le_bytes(),
        )
    }

    /// Snapshots the dirty accumulator, writes it out, and only then clears it.
    fn harvest(&self, buffer: &mut File) -> Result<(), ErrorCode> {
        let vmm = self.vmm.lock().expect("Poisoned lock");
        let kvm_vm = vmm.kvm_vm().ok_or(ErrorCode::DirtyHarvestFailed)?;
        let snapshot = kvm_vm.snapshot_dirty_log().map_err(|err| {
            error!("Farplane capture could not read the dirty log: {err}");
            ErrorCode::DirtyHarvestFailed
        })?;

        let bytes: u64 = snapshot.iter().map(|words| words.len() as u64 * 8).sum();
        if bytes != self.channel.dirty_bitmap_bytes {
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

    /// Stops serving commands for good. Nothing else changes: the guest keeps running, faults keep
    /// resolving on the retained userfaultfd, and only the supervisor kills this process.
    fn fail(&mut self, ops: &mut EventOps) {
        BackendState::fail();
        if let Err(err) = ops.remove(Events::new(&self.channel.sock, EventSet::IN)) {
            warn!("Farplane channel could not be removed from the event loop: {err}");
        }
    }
}

impl MutEventSubscriber for CaptureService {
    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.channel.sock, EventSet::IN)) {
            error!("Farplane channel could not join the event loop: {err}");
            BackendState::fail();
        }
    }

    fn process(&mut self, event: Events, ops: &mut EventOps) {
        if BackendState::load() == BackendState::ChannelFailed {
            return;
        }
        if !event.event_set().contains(EventSet::IN) {
            self.fail(ops);
            return;
        }
        // While the capture epoch is open the next command is served inline, so no other event
        // source of this loop runs until pagemaster resumes.
        loop {
            if let Err(err) = self.serve_one() {
                error!("Farplane memory channel failed: {err}");
                self.fail(ops);
                return;
            }
            if BackendState::load() != BackendState::Quiesced {
                return;
            }
        }
    }
}

/// Writes the vmstate at offset zero of the armed buffer and reports its length.
fn serialize_vmstate(buffer: &mut File, state: MicrovmState) -> Result<u64, ErrorCode> {
    buffer
        .seek(SeekFrom::Start(0))
        .map_err(|_| ErrorCode::VmstateWriteFailed)?;
    Snapshot::new(state)
        .save(buffer)
        .map_err(|_| ErrorCode::VmstateWriteFailed)?;
    buffer.flush().map_err(|_| ErrorCode::VmstateWriteFailed)?;
    buffer
        .stream_position()
        .map_err(|_| ErrorCode::VmstateWriteFailed)
}
