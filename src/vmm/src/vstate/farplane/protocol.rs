// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use vmm_sys_util::sock_ctrl_msg::ScmSocket;

/// Frame magic, "FPM1" in little-endian byte order.
pub const MAGIC: u32 = 0x314D_5046;
/// Protocol version carried by every frame.
pub const VERSION: u16 = 1;
/// Size of the fixed frame header.
pub const HEADER_LEN: usize = 32;
/// Largest datagram accepted or produced, header included.
pub const MAX_DATAGRAM: usize = 65_536;
/// Largest extent table accepted, in records.
pub const MAX_EXTENTS: u32 = 65_536;
/// Largest number of backing descriptors accepted for one plan, across datagrams.
pub const MAX_PLAN_FDS: u32 = 1_024;
/// Largest number of descriptors one datagram carries: the kernel's `SCM_MAX_FD`.
pub const MAX_SCM_FDS: usize = 253;
/// Number of answered requests one connection keeps, so a retry of one is replayed rather than
/// served twice. Pagemaster serves one command at a time, so this is a history of retries, not a
/// window of requests in flight: an identifier older than this cannot be answered from memory and
/// is refused instead.
pub const MAX_RETRYABLE_REQUESTS: usize = 64;
/// Compatibility identity of this protocol, quiesce semantics and vmstate format. A warm image
/// baked by another identity is refused rather than restored: the capture command order and the
/// vmstate the epoch produces are part of what this string names.
pub const FEATURE_IDENTITY: &str = "farplane/2";
/// Size of one extent table record.
pub const EXTENT_RECORD_LEN: usize = 32;
/// Size of one region record.
pub const REGION_RECORD_LEN: usize = 16;
/// Size of the region record reported by `backend_ready`.
pub const READY_REGION_RECORD_LEN: usize = 24;
/// Size of the fixed tail of a `backend_ready` body, which follows the region records.
pub const BACKEND_READY_TAIL_LEN: usize = 28;
/// Size of the detail field of an `error` frame.
pub const ERROR_DETAIL_LEN: usize = 128;
/// Size of the feature identity field of a `hello` frame.
pub const FEATURE_IDENTITY_LEN: usize = 32;

/// Message types of the memory channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MsgType {
    /// Pagemaster transfers backing descriptors.
    PlanFds = 1,
    /// Pagemaster transfers the geometry and the extent table.
    BackingPlan = 2,
    /// Pagemaster arms one capture epoch with its buffers.
    CaptureBuffers = 3,
    /// Pagemaster asks for all guest-memory writers to stop.
    Quiesce = 4,
    /// Pagemaster asks for a snapshot-and-clear of the dirty accumulator.
    DirtySnapshot = 5,
    /// Pagemaster asks for the vmstate to be written into the armed buffer.
    WriteVmstate = 6,
    /// Pagemaster returns a previously harvested bitmap to the accumulator.
    DirtyUnion = 7,
    /// Pagemaster leaves the capture epoch.
    Resume = 8,
    /// Firecracker announces itself and its geometry.
    Hello = 9,
    /// Firecracker reports the mapped geometry and hands over a userfaultfd duplicate.
    BackendReady = 10,
    /// Firecracker confirms every guest-memory writer has stopped.
    Quiesced = 11,
    /// Firecracker confirms the dirty accumulator was harvested and cleared.
    DirtySnapshotDone = 12,
    /// Firecracker confirms the vmstate was written.
    VmstateWritten = 13,
    /// Firecracker confirms the returned bitmap was unioned back.
    UnionDone = 14,
    /// Firecracker confirms the capture epoch is over.
    Resumed = 15,
    /// Firecracker rejects a command.
    Error = 16,
    /// Firecracker confirms the capture buffers are armed.
    CaptureBuffersArmed = 17,
}

impl MsgType {
    /// Returns the message type for `value`, or `None` if it names no message.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::PlanFds),
            2 => Some(Self::BackingPlan),
            3 => Some(Self::CaptureBuffers),
            4 => Some(Self::Quiesce),
            5 => Some(Self::DirtySnapshot),
            6 => Some(Self::WriteVmstate),
            7 => Some(Self::DirtyUnion),
            8 => Some(Self::Resume),
            9 => Some(Self::Hello),
            10 => Some(Self::BackendReady),
            11 => Some(Self::Quiesced),
            12 => Some(Self::DirtySnapshotDone),
            13 => Some(Self::VmstateWritten),
            14 => Some(Self::UnionDone),
            15 => Some(Self::Resumed),
            16 => Some(Self::Error),
            17 => Some(Self::CaptureBuffersArmed),
            _ => None,
        }
    }
}

/// Closed set of rejection reasons reported in an `error` frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// The plan region list does not match the architecture layout for this guest.
    GeometryMismatch = 1,
    /// An extent record is unusable on its own terms.
    BadExtent = 2,
    /// The extent table is not in canonical form.
    PlanNotCanonical = 3,
    /// A transferred descriptor is not a memfd.
    FdNotMemfd = 4,
    /// A transferred descriptor lacks a required seal.
    FdNotSealed = 5,
    /// A backing descriptor still permits writes.
    FdWritable = 6,
    /// The extent table exceeds the accepted record count.
    TooManyExtents = 7,
    /// The plan exceeds the accepted descriptor count.
    TooManyFds = 8,
    /// A guest mapping could not be established.
    MapFailed = 9,
    /// The userfaultfd could not be prepared or registered.
    UffdRegisterFailed = 10,
    /// Guest memory could not be locked on fault.
    MlockFailed = 11,
    /// The vmstate handed over with the plan could not be parsed.
    VmstateParseFailed = 12,
    /// The vmstate could not be serialized into the armed buffer.
    VmstateWriteFailed = 13,
    /// The dirty accumulator could not be harvested; no bit was lost.
    DirtyHarvestFailed = 14,
    /// The command requires the capture epoch to be entered first.
    NotQuiesced = 15,
    /// The capture epoch has already been entered.
    AlreadyQuiesced = 16,
    /// The capture epoch has no armed buffers.
    NoCaptureBuffers = 17,
    /// An armed buffer is smaller than the reported requirement.
    BufferTooSmall = 18,
    /// The plan names a pid other than the peer of the channel.
    PeercredMismatch = 19,
    /// The vCPUs could not be restarted.
    ResumeFailed = 20,
    /// Guest-memory writers could not be stopped.
    QuiesceFailed = 21,
    /// A capture command arrived out of order within one epoch: the vmstate must be serialized
    /// before the dirty accumulator is harvested.
    CaptureOrderViolation = 22,
    /// A request identifier this connection already answered arrived with different contents, or
    /// too long ago to be answered from memory.
    RequestIdReused = 23,
}

/// Architecture Firecracker is running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Arch {
    /// x86_64.
    X86_64 = 1,
    /// aarch64.
    Aarch64 = 2,
}

/// Whether the guest is being booted or restored from a vmstate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Mode {
    /// Cold boot: the plan tiles the regions the machine configuration asks for.
    Boot = 1,
    /// Restore: the plan tiles the regions the vmstate geometry states.
    Restore = 2,
}

/// Fixed header of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Frame magic.
    pub magic: u32,
    /// Protocol version.
    pub version: u16,
    /// Message type.
    pub msg_type: u16,
    /// Request identifier; zero for Firecracker-initiated frames.
    pub request_id: u64,
    /// Body length in bytes, header excluded.
    pub body_len: u32,
    /// Number of descriptors carried by this frame.
    pub fd_count: u32,
    /// Must be zero.
    pub reserved: u64,
}

impl Header {
    /// Builds a well-formed header.
    pub fn new(msg_type: MsgType, request_id: u64, body_len: u32, fd_count: u32) -> Self {
        Self {
            magic: MAGIC,
            version: VERSION,
            msg_type: msg_type as u16,
            request_id,
            body_len,
            fd_count,
            reserved: 0,
        }
    }

    /// Serializes the header.
    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version.to_le_bytes());
        buf[6..8].copy_from_slice(&self.msg_type.to_le_bytes());
        buf[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        buf[16..20].copy_from_slice(&self.body_len.to_le_bytes());
        buf[20..24].copy_from_slice(&self.fd_count.to_le_bytes());
        buf[24..32].copy_from_slice(&self.reserved.to_le_bytes());
        buf
    }

    /// Parses a header, rejecting anything this version does not define.
    pub fn decode(buf: &[u8]) -> Result<Self, ChannelError> {
        if buf.len() < HEADER_LEN {
            return Err(ChannelError::Truncated);
        }
        let header = Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(buf[4..6].try_into().unwrap()),
            msg_type: u16::from_le_bytes(buf[6..8].try_into().unwrap()),
            request_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            body_len: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            fd_count: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            reserved: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        };
        if header.magic != MAGIC || header.version != VERSION || header.reserved != 0 {
            return Err(ChannelError::Malformed);
        }
        if MsgType::from_u16(header.msg_type).is_none() {
            return Err(ChannelError::Malformed);
        }
        Ok(header)
    }

    /// Returns the message type, which `decode` has already validated.
    pub fn msg(self) -> MsgType {
        MsgType::from_u16(self.msg_type).expect("decode rejects undefined message types")
    }
}

/// One guest memory region of the checkpoint geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegionRecord {
    /// Guest physical address the region starts at.
    pub guest_addr: u64,
    /// Region size in bytes.
    pub size: u64,
}

impl RegionRecord {
    /// Serializes the record.
    pub fn encode(self) -> [u8; REGION_RECORD_LEN] {
        let mut buf = [0u8; REGION_RECORD_LEN];
        buf[0..8].copy_from_slice(&self.guest_addr.to_le_bytes());
        buf[8..16].copy_from_slice(&self.size.to_le_bytes());
        buf
    }

    /// Parses one record.
    pub fn decode(buf: &[u8]) -> Result<Self, ChannelError> {
        if buf.len() < REGION_RECORD_LEN {
            return Err(ChannelError::Malformed);
        }
        Ok(Self {
            guest_addr: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            size: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        })
    }
}

/// One extent of the backing plan: a maximal range served by one descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentRecord {
    /// Guest physical address the extent starts at.
    pub guest_addr: u64,
    /// Extent length in bytes.
    pub len: u64,
    /// Index into the ordered descriptor table.
    pub fd_index: u32,
    /// Must be zero.
    pub reserved: u32,
    /// Offset into the descriptor the extent is served from.
    pub fd_offset: u64,
}

impl ExtentRecord {
    /// Parses one record.
    pub fn decode(buf: &[u8]) -> Result<Self, ChannelError> {
        if buf.len() < EXTENT_RECORD_LEN {
            return Err(ChannelError::Malformed);
        }
        Ok(Self {
            guest_addr: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            len: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            fd_index: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            reserved: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            fd_offset: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
        })
    }

    /// Serializes the record.
    pub fn encode(self) -> [u8; EXTENT_RECORD_LEN] {
        let mut buf = [0u8; EXTENT_RECORD_LEN];
        buf[0..8].copy_from_slice(&self.guest_addr.to_le_bytes());
        buf[8..16].copy_from_slice(&self.len.to_le_bytes());
        buf[16..20].copy_from_slice(&self.fd_index.to_le_bytes());
        buf[20..24].copy_from_slice(&self.reserved.to_le_bytes());
        buf[24..32].copy_from_slice(&self.fd_offset.to_le_bytes());
        buf
    }
}

/// One mapped guest region as reported by `backend_ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendReadyRegion {
    /// Guest physical address the region starts at.
    pub guest_addr: u64,
    /// Region size in bytes.
    pub size: u64,
    /// Host virtual address the contiguous reservation starts at.
    pub host_base: u64,
}

impl BackendReadyRegion {
    /// Serializes the record.
    pub fn encode(self) -> [u8; READY_REGION_RECORD_LEN] {
        let mut buf = [0u8; READY_REGION_RECORD_LEN];
        buf[0..8].copy_from_slice(&self.guest_addr.to_le_bytes());
        buf[8..16].copy_from_slice(&self.size.to_le_bytes());
        buf[16..24].copy_from_slice(&self.host_base.to_le_bytes());
        buf
    }
}

/// Framing failures of the memory channel.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ChannelError {
    /// Datagram was truncated.
    Truncated,
    /// Frame is malformed.
    Malformed,
    /// Descriptor count does not match SCM_RIGHTS.
    FdCountMismatch,
    /// Peer closed the channel.
    Closed,
    /// Socket I/O failed: {0}
    Io(#[from] io::Error),
}

/// One received frame with the descriptors that rode on it.
#[derive(Debug)]
pub struct Incoming {
    /// Frame header.
    pub header: Header,
    /// Frame body.
    pub body: Vec<u8>,
    /// Descriptors received on this frame.
    pub fds: Vec<OwnedFd>,
}

/// Sends one frame, with `fds` riding on it as `SCM_RIGHTS`.
pub fn send_frame(
    sock: &UnixStream,
    msg: MsgType,
    request_id: u64,
    body: &[u8],
    fds: &[RawFd],
) -> Result<(), ChannelError> {
    if HEADER_LEN + body.len() > MAX_DATAGRAM {
        return Err(ChannelError::Malformed);
    }
    let header = Header::new(
        msg,
        request_id,
        u32::try_from(body.len()).map_err(|_| ChannelError::Malformed)?,
        u32::try_from(fds.len()).map_err(|_| ChannelError::Malformed)?,
    );
    let mut frame = Vec::with_capacity(HEADER_LEN + body.len());
    frame.extend_from_slice(&header.encode());
    frame.extend_from_slice(body);
    sock.send_with_fds(&[frame.as_slice()], fds)
        .map_err(|err| ChannelError::Io(io::Error::from_raw_os_error(err.errno())))?;
    Ok(())
}

/// Control buffer of a received frame, in 64-bit words: one `SCM_RIGHTS` header plus the kernel's
/// per-datagram descriptor limit. A smaller buffer turns a legal plan datagram into `MSG_CTRUNC`.
const CONTROL_WORDS: usize =
    (size_of::<libc::cmsghdr>() + MAX_SCM_FDS * size_of::<RawFd>()).div_ceil(size_of::<u64>());

/// Narrows a control buffer length to the width `msghdr` declares for it, which is a `size_t` on
/// one C library and a `socklen_t` on another.
fn control_len<T: TryFrom<usize>>(len: usize) -> T {
    match T::try_from(len) {
        Ok(len) => len,
        Err(_) => unreachable!("the control buffer is smaller than any msghdr length"),
    }
}

/// Receives exactly one frame. A datagram whose payload or control message did not fit is a
/// protocol violation, never a partially parsed frame.
pub fn recv_frame(sock: &UnixStream) -> Result<Incoming, ChannelError> {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let mut control = [0u64; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: `msghdr` is a plain data structure with no invalid bit patterns.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control_len(std::mem::size_of_val(&control));

    // SAFETY: the socket is open, and the buffers outlive the call.
    let nbytes = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if nbytes < 0 {
        return Err(ChannelError::Io(io::Error::last_os_error()));
    }
    let fds = collect_fds(&msg);
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(ChannelError::Truncated);
    }
    let nbytes = nbytes.cast_unsigned();
    if nbytes == 0 {
        return Err(ChannelError::Closed);
    }
    if nbytes < HEADER_LEN {
        return Err(ChannelError::Truncated);
    }
    let header = Header::decode(&buf[..HEADER_LEN])?;
    let expected =
        HEADER_LEN + usize::try_from(header.body_len).map_err(|_| ChannelError::Malformed)?;
    if nbytes != expected {
        return Err(ChannelError::Malformed);
    }
    if usize::try_from(header.fd_count).map_err(|_| ChannelError::Malformed)? != fds.len() {
        return Err(ChannelError::FdCountMismatch);
    }
    Ok(Incoming {
        header,
        body: buf[HEADER_LEN..expected].to_vec(),
        fds,
    })
}

/// Takes ownership of every descriptor found in the control message of `msg`.
fn collect_fds(msg: &libc::msghdr) -> Vec<OwnedFd> {
    let mut fds = Vec::new();
    // SAFETY: `msg` was filled in by `recvmsg`, so its control buffer is consistent.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        // SAFETY: `CMSG_FIRSTHDR`/`CMSG_NXTHDR` only return headers inside the control buffer.
        let header = unsafe { *cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: `cmsg_len` covers the header plus the descriptor array.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            // SAFETY: `CMSG_LEN` is a pure computation over a constant.
            let header_len = unsafe { libc::CMSG_LEN(0) } as u64;
            let payload = (header.cmsg_len as u64).saturating_sub(header_len);
            let count = usize::try_from(payload / std::mem::size_of::<RawFd>() as u64).unwrap_or(0);
            for i in 0..count {
                // SAFETY: `data` points at `count` descriptors written by the kernel.
                let raw = unsafe { data.cast::<RawFd>().add(i).read_unaligned() };
                // SAFETY: the kernel just installed `raw` in this process.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        // SAFETY: iterating the control buffer of a message filled in by `recvmsg`.
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    fds
}

/// Serializes an `error` body.
pub fn encode_error(code: ErrorCode, op: MsgType, detail: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + ERROR_DETAIL_LEN);
    body.extend_from_slice(&(code as u32).to_le_bytes());
    body.extend_from_slice(&(op as u16).to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    let mut detail_bytes = [0u8; ERROR_DETAIL_LEN];
    let bytes = detail.as_bytes();
    let n = bytes.len().min(ERROR_DETAIL_LEN);
    detail_bytes[..n].copy_from_slice(&bytes[..n]);
    body.extend_from_slice(&detail_bytes);
    body
}

/// Serializes a `hello` body.
pub fn encode_hello(
    pid: u32,
    page_size: u32,
    arch: Arch,
    mode: Mode,
    regions: &[RegionRecord],
) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(16 + FEATURE_IDENTITY_LEN + regions.len() * REGION_RECORD_LEN);
    body.extend_from_slice(&pid.to_le_bytes());
    body.extend_from_slice(&page_size.to_le_bytes());
    body.extend_from_slice(&(arch as u16).to_le_bytes());
    body.extend_from_slice(&(mode as u16).to_le_bytes());
    let region_count =
        u32::try_from(regions.len()).expect("region count is bounded by the plan datagram");
    body.extend_from_slice(&region_count.to_le_bytes());
    body.extend_from_slice(&feature_identity_padded());
    for region in regions {
        body.extend_from_slice(&region.encode());
    }
    body
}

/// Serializes a `backend_ready` body: the region count, one record per mapped region, then the
/// fixed tail.
pub fn encode_backend_ready(
    regions: &[BackendReadyRegion],
    kvm_slot_count: u32,
    uffd_features: u64,
    dirty_bitmap_bytes: u64,
    vmstate_capacity_bytes: u64,
) -> Vec<u8> {
    let mut body =
        Vec::with_capacity(4 + BACKEND_READY_TAIL_LEN + regions.len() * READY_REGION_RECORD_LEN);
    let region_count =
        u32::try_from(regions.len()).expect("region count is bounded by the plan datagram");
    body.extend_from_slice(&region_count.to_le_bytes());
    for region in regions {
        body.extend_from_slice(&region.encode());
    }
    body.extend_from_slice(&kvm_slot_count.to_le_bytes());
    body.extend_from_slice(&uffd_features.to_le_bytes());
    body.extend_from_slice(&dirty_bitmap_bytes.to_le_bytes());
    body.extend_from_slice(&vmstate_capacity_bytes.to_le_bytes());
    body
}

/// Parses a body that carries exactly one `u32`, as `plan_fds` and `resume` do.
pub fn parse_u32(body: &[u8]) -> Result<u32, ChannelError> {
    if body.len() != 4 {
        return Err(ChannelError::Malformed);
    }
    Ok(u32::from_le_bytes(body[0..4].try_into().unwrap()))
}

/// Parsed `backing_plan` body.
#[derive(Debug)]
pub struct BackingPlanBody {
    /// Pid of the pagemaster that serves faults on this channel.
    pub pm_pid: u32,
    /// Number of extent records in the transferred table.
    pub extent_count: u32,
    /// Frame flags; bit 0 states a vmstate descriptor rides along.
    pub flags: u32,
    /// Checkpoint geometry the plan tiles.
    pub regions: Vec<RegionRecord>,
}

impl BackingPlanBody {
    /// States whether a vmstate descriptor rides on the frame.
    pub fn has_vmstate(&self) -> bool {
        self.flags & Self::FLAG_VMSTATE != 0
    }

    /// Flag bit stating a vmstate descriptor rides on the frame.
    pub const FLAG_VMSTATE: u32 = 1;
}

/// Parses a `backing_plan` body.
pub fn parse_backing_plan(body: &[u8]) -> Result<BackingPlanBody, ChannelError> {
    if body.len() < 16 {
        return Err(ChannelError::Malformed);
    }
    let pm_pid = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let region_count = u32::from_le_bytes(body[4..8].try_into().unwrap());
    let extent_count = u32::from_le_bytes(body[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(body[12..16].try_into().unwrap());
    if flags & !BackingPlanBody::FLAG_VMSTATE != 0 {
        return Err(ChannelError::Malformed);
    }
    let expected = 16 + region_count as usize * REGION_RECORD_LEN;
    if body.len() != expected {
        return Err(ChannelError::Malformed);
    }
    let mut regions = Vec::with_capacity(region_count as usize);
    let mut off = 16;
    for _ in 0..region_count {
        regions.push(RegionRecord::decode(&body[off..off + REGION_RECORD_LEN])?);
        off += REGION_RECORD_LEN;
    }
    Ok(BackingPlanBody {
        pm_pid,
        extent_count,
        flags,
        regions,
    })
}

/// Returns the feature identity in its wire representation.
pub fn feature_identity_padded() -> [u8; FEATURE_IDENTITY_LEN] {
    let mut identity = [0u8; FEATURE_IDENTITY_LEN];
    identity[..FEATURE_IDENTITY.len()].copy_from_slice(FEATURE_IDENTITY.as_bytes());
    identity
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;

    use super::*;

    fn seqpacket_pair() -> (UnixStream, UnixStream) {
        let mut fds = [-1i32; 2];
        // SAFETY: `fds` has room for the two descriptors the call returns.
        let ret = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(ret, 0, "{}", io::Error::last_os_error());
        // SAFETY: both descriptors were just created by `socketpair`.
        unsafe {
            (
                UnixStream::from_raw_fd(fds[0]),
                UnixStream::from_raw_fd(fds[1]),
            )
        }
    }

    fn set_buffers(sock: &UnixStream) {
        let size = libc::c_int::try_from(MAX_DATAGRAM).unwrap();
        for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            // SAFETY: `size` outlives the call and matches the option's expected type.
            let ret = unsafe {
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_SOCKET,
                    opt,
                    std::ptr::addr_of!(size).cast(),
                    libc::socklen_t::try_from(std::mem::size_of_val(&size)).unwrap(),
                )
            };
            assert_eq!(ret, 0, "{}", io::Error::last_os_error());
        }
    }

    fn memfd(name: &[u8]) -> std::fs::File {
        // SAFETY: `name` is a NUL-terminated byte string that outlives the call.
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0) };
        assert!(fd >= 0, "{}", io::Error::last_os_error());
        // SAFETY: the descriptor was just created and is not owned by anything else.
        unsafe { std::fs::File::from_raw_fd(RawFd::try_from(fd).unwrap()) }
    }

    #[test]
    fn header_roundtrip() {
        let header = Header::new(MsgType::Hello, 0, 16, 0);
        assert_eq!(Header::decode(&header.encode()).unwrap(), header);
    }

    #[test]
    fn header_rejects_undefined_frames() {
        let mut bad_magic = Header::new(MsgType::Hello, 0, 0, 0).encode();
        bad_magic[0] ^= 0xff;
        assert!(matches!(
            Header::decode(&bad_magic),
            Err(ChannelError::Malformed)
        ));

        let mut bad_version = Header::new(MsgType::Hello, 0, 0, 0).encode();
        bad_version[4] = 2;
        assert!(matches!(
            Header::decode(&bad_version),
            Err(ChannelError::Malformed)
        ));

        let mut reserved_set = Header::new(MsgType::Hello, 0, 0, 0).encode();
        reserved_set[24] = 1;
        assert!(matches!(
            Header::decode(&reserved_set),
            Err(ChannelError::Malformed)
        ));

        let mut unknown_type = Header::new(MsgType::Hello, 0, 0, 0).encode();
        unknown_type[6] = 0xff;
        assert!(matches!(
            Header::decode(&unknown_type),
            Err(ChannelError::Malformed)
        ));

        assert!(matches!(
            Header::decode(&[0u8; HEADER_LEN - 1]),
            Err(ChannelError::Truncated)
        ));
    }

    #[test]
    fn frame_roundtrip_carries_descriptors() {
        let (tx, rx) = seqpacket_pair();
        set_buffers(&tx);
        set_buffers(&rx);
        let mut memfd = memfd(b"farplane-test\0");
        memfd.write_all(b"payload").unwrap();

        let body = 3u32.to_le_bytes().to_vec();
        send_frame(&tx, MsgType::Quiesced, 7, &body, &[memfd.as_raw_fd()]).unwrap();

        let frame = recv_frame(&rx).unwrap();
        assert_eq!(frame.header.request_id, 7);
        assert_eq!(frame.header.msg(), MsgType::Quiesced);
        assert_eq!(frame.body, body);
        assert_eq!(frame.fds.len(), 1);
    }

    #[test]
    fn frame_carries_the_kernel_descriptor_limit() {
        let (tx, rx) = seqpacket_pair();
        set_buffers(&tx);
        set_buffers(&rx);
        let memfd = memfd(b"farplane-fd-limit\0");
        let fds = vec![memfd.as_raw_fd(); MAX_SCM_FDS];

        let count = u32::try_from(MAX_SCM_FDS).unwrap();
        send_frame(&tx, MsgType::PlanFds, 0, &count.to_le_bytes(), &fds).unwrap();

        let frame = recv_frame(&rx).unwrap();
        assert_eq!(frame.header.msg(), MsgType::PlanFds);
        assert_eq!(frame.fds.len(), MAX_SCM_FDS);
    }

    #[test]
    fn control_buffer_holds_the_kernel_descriptor_limit() {
        // SAFETY: `CMSG_LEN` is a pure computation over a constant.
        let header = unsafe { libc::CMSG_LEN(0) } as usize;
        let payload = CONTROL_WORDS * size_of::<u64>() - header;
        assert!(payload / size_of::<RawFd>() >= MAX_SCM_FDS);
    }

    #[test]
    fn body_length_must_match_the_datagram() {
        let (tx, rx) = seqpacket_pair();
        set_buffers(&tx);
        set_buffers(&rx);
        let mut frame = Header::new(MsgType::Quiesce, 1, 8, 0).encode().to_vec();
        frame.extend_from_slice(&[0u8; 4]);
        tx.send_with_fds(&[frame.as_slice()], &[]).unwrap();
        assert!(matches!(recv_frame(&rx), Err(ChannelError::Malformed)));
    }

    #[test]
    fn oversized_datagram_is_a_violation() {
        let (tx, rx) = seqpacket_pair();
        set_buffers(&tx);
        set_buffers(&rx);
        let oversized = vec![0u8; MAX_DATAGRAM + 1];
        // A frame larger than the protocol maximum cannot be produced by `send_frame`.
        assert!(matches!(
            send_frame(&tx, MsgType::Quiesce, 1, &oversized, &[]),
            Err(ChannelError::Malformed)
        ));
        // A peer that bypasses framing is rejected rather than parsed from a truncated datagram.
        let body_len = u32::try_from(oversized.len()).unwrap();
        let mut raw = Header::new(MsgType::Quiesce, 1, body_len, 0)
            .encode()
            .to_vec();
        raw.extend_from_slice(&oversized);
        if tx.send_with_fds(&[raw.as_slice()], &[]).is_ok() {
            assert!(matches!(recv_frame(&rx), Err(ChannelError::Truncated)));
        }
    }

    #[test]
    fn closed_channel_is_reported() {
        let (tx, rx) = seqpacket_pair();
        drop(tx);
        assert!(matches!(recv_frame(&rx), Err(ChannelError::Closed)));
    }

    #[test]
    fn extent_record_roundtrip() {
        let record = ExtentRecord {
            guest_addr: 0x1000,
            len: 0x2000,
            fd_index: 1,
            reserved: 0,
            fd_offset: 0x3000,
        };
        assert_eq!(ExtentRecord::decode(&record.encode()).unwrap(), record);
    }

    #[test]
    fn backing_plan_rejects_unknown_flags() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0b10u32.to_le_bytes());
        assert!(matches!(
            parse_backing_plan(&body),
            Err(ChannelError::Malformed)
        ));
    }

    #[test]
    fn backing_plan_region_count_must_match_body() {
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(
            &RegionRecord {
                guest_addr: 0,
                size: 0x1000,
            }
            .encode(),
        );
        assert!(matches!(
            parse_backing_plan(&body),
            Err(ChannelError::Malformed)
        ));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(ErrorCode::GeometryMismatch as u32, 1);
        assert_eq!(ErrorCode::NoCaptureBuffers as u32, 17);
        assert_eq!(ErrorCode::PeercredMismatch as u32, 19);
        assert_eq!(ErrorCode::CaptureOrderViolation as u32, 22);
    }

    /// The `hello` frame is the only place the feature identity crosses to pagemaster, so its
    /// bytes are pinned by fixtures the Python fake decodes as well. Both architectures are
    /// pinned, because the frame is produced on both and only one of them is ever running here.
    /// A change to the identity or to the body layout has to be made in both languages or this
    /// fails.
    #[test]
    fn hello_frames_match_the_shared_fixtures() {
        let regions = [RegionRecord {
            guest_addr: 0,
            size: 0x0800_0000,
        }];

        for (arch, fixture) in [
            (Arch::X86_64, include_str!("testdata/hello.hex")),
            (Arch::Aarch64, include_str!("testdata/hello_aarch64.hex")),
        ] {
            let body = encode_hello(4242, 4096, arch, Mode::Boot, &regions);
            let header = Header::new(MsgType::Hello, 0, u32::try_from(body.len()).unwrap(), 0);
            let mut datagram = header.encode().to_vec();
            datagram.extend_from_slice(&body);

            let hex: String = datagram.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(hex, fixture.trim(), "{arch:?} hello frame changed");
        }
        assert_eq!(FEATURE_IDENTITY, "farplane/2");
    }
}
