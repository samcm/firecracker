// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::raw::c_ulong;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use userfaultfd::{RegisterMode, Uffd};
use userfaultfd_sys::{
    UFFD_API, UFFD_FEATURE_MINOR_SHMEM, UFFD_FEATURE_MISSING_SHMEM, UFFD_FEATURE_PAGEFAULT_FLAG_WP,
    UFFD_FEATURE_WP_HUGETLBFS_SHMEM, uffdio_api,
};
use vm_memory::GuestAddress;
use vm_memory::bitmap::{AtomicBitmap, NewBitmap};
use vm_memory::mmap::MmapRegionBuilder;
use vmm_sys_util::ioctl::{ioctl_with_mut_ref, ioctl_with_val};

use super::protocol::{
    self, Arch, BackendReadyRegion, BackingPlanBody, ChannelError, ErrorCode, ExtentRecord,
    Incoming, MAX_EXTENTS, MAX_PLAN_FDS, Mode, MsgType, RegionRecord,
};
use crate::arch::host_page_size;
use crate::persist::MicrovmState;
use crate::snapshot::Snapshot;
use crate::utils::u64_to_usize;
use crate::vmm_config::instance_info::VmState;
use crate::vstate::memory::GuestRegionMmap;

mod ioctls {
    use userfaultfd_sys::uffdio_api;
    use vmm_sys_util::{ioctl_io_nr, ioctl_iowr_nr};

    ioctl_io_nr!(USERFAULTFD_IOC_NEW, 0xAA, 0x00);
    ioctl_iowr_nr!(UFFDIO_API, 0xAA, 0x3f, uffdio_api);
}

use ioctls::{UFFDIO_API, USERFAULTFD_IOC_NEW};

/// Descriptor the jailer hands the userfaultfd device on.
const UFFD_DEVICE_FILENO: RawFd = 3;
/// Filesystem magic of the internal shmem mount every memfd lives on.
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// Filesystem magic of hugetlbfs, where a memfd created with `MFD_HUGETLB` lives.
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
/// Seals a backing descriptor must carry before it is mapped.
const REQUIRED_BACKING_SEALS: i32 =
    libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_FUTURE_WRITE;
/// Seals a capture buffer must carry: it is written, but its size is fixed.
const REQUIRED_BUFFER_SEALS: i32 = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
/// Userfaultfd features the deployment kernel must provide for shmem-backed guest memory. Guest
/// extents are file mappings, so write protection over them needs the shmem write-protect feature
/// as well as write-protect fault reporting.
const REQUIRED_UFFD_FEATURES: u64 = UFFD_FEATURE_PAGEFAULT_FLAG_WP
    | UFFD_FEATURE_MISSING_SHMEM
    | UFFD_FEATURE_MINOR_SHMEM
    | UFFD_FEATURE_WP_HUGETLBFS_SHMEM;

/// Upper bound Firecracker guarantees for a serialized vmstate of its device set, reported so
/// pagemaster preallocates the capture buffer before the source is frozen.
pub const VMSTATE_CAPACITY_BYTES: u64 = 16 << 20;

static STATE: AtomicU8 = AtomicU8::new(BackendState::AwaitingPlan as u8);
static CAPTURE_BUFFERS_ARMED: AtomicBool = AtomicBool::new(false);
static SOCKET_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);
static CHANNEL: Mutex<Option<MemoryChannel>> = Mutex::new(None);

/// Lifecycle of the composite guest-memory backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BackendState {
    /// Connected, waiting for the backing plan.
    AwaitingPlan = 0,
    /// Validating the plan and establishing the guest mappings.
    Mapping = 1,
    /// Every extent is mapped, locked and registered on the userfaultfd.
    Registered = 2,
    /// Geometry reported to pagemaster; the guest may run.
    Ready = 3,
    /// Capture epoch entered: no Firecracker thread writes guest memory.
    Quiesced = 4,
    /// The channel failed; commands are no longer processed.
    ChannelFailed = 5,
}

impl BackendState {
    /// Returns the name reported through the instance description.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingPlan => "awaiting_plan",
            Self::Mapping => "mapping",
            Self::Registered => "registered",
            Self::Ready => "ready",
            Self::Quiesced => "quiesced",
            Self::ChannelFailed => "channel_failed",
        }
    }

    /// Returns the current state of this process's backend.
    pub fn load() -> Self {
        match STATE.load(Ordering::Acquire) {
            0 => Self::AwaitingPlan,
            1 => Self::Mapping,
            2 => Self::Registered,
            3 => Self::Ready,
            4 => Self::Quiesced,
            _ => Self::ChannelFailed,
        }
    }

    /// Publishes a state transition, unless the channel has already failed.
    pub fn store(self) {
        if Self::load() != Self::ChannelFailed {
            STATE.store(self as u8, Ordering::Release);
        }
    }

    /// Marks the channel permanently failed.
    pub fn fail() {
        STATE.store(Self::ChannelFailed as u8, Ordering::Release);
    }
}

/// Backend observation reported by `GET /`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FarplaneState {
    /// Backend lifecycle state.
    pub backend_state: String,
    /// vCPU execution state.
    pub vcpus: String,
    /// Whether a capture epoch has buffers armed.
    pub capture_buffers_armed: bool,
    /// Compatibility identity of this binary's memory protocol.
    pub feature_identity: String,
}

impl Default for FarplaneState {
    fn default() -> Self {
        Self::observe()
    }
}

impl FarplaneState {
    /// Samples the process-wide backend and vCPU state.
    pub fn observe() -> Self {
        let vcpus = match VmState::load() {
            VmState::NotStarted => "not_started",
            VmState::Paused => "paused",
            VmState::Running => "running",
        };
        Self {
            backend_state: BackendState::load().as_str().to_string(),
            vcpus: vcpus.to_string(),
            capture_buffers_armed: CAPTURE_BUFFERS_ARMED.load(Ordering::Acquire),
            feature_identity: protocol::FEATURE_IDENTITY.to_string(),
        }
    }
}

/// Failures of the handshake with pagemaster.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum BackendError {
    /// Memory channel failed: {0}
    Channel(#[from] ChannelError),
    /// Socket connect failed: {0}
    Connect(io::Error),
    /// Peer of the memory channel is not the pagemaster
    Peercred,
    /// Plan rejected: {0:?}
    Plan(ErrorCode),
    /// Guest mapping failed: {0}
    Map(io::Error),
    /// Userfaultfd operation failed: {0}
    Uffd(io::Error),
    /// Kernel lacks required userfaultfd features: {0:#x}
    UffdFeatures(u64),
    /// Process identity could not be set: {0}
    Identity(io::Error),
    /// Vmstate handed over with the plan is unusable: {0}
    Vmstate(#[from] crate::snapshot::SnapshotError),
    /// The pagemaster memory channel path was not configured
    MissingSocket,
}

/// The memory channel, kept for the lifetime of the process.
#[derive(Debug)]
pub struct MemoryChannel {
    /// Command socket; pagemaster is the only initiator.
    pub sock: UnixStream,
    /// Checkpoint geometry the plan tiled, in ascending guest address order.
    pub regions: Vec<RegionRecord>,
    /// Exact size of one harvested dirty bitmap.
    pub dirty_bitmap_bytes: u64,
    /// The registered userfaultfd. Holding it until process exit is what keeps guest faults
    /// blocked rather than zero-filled when pagemaster dies.
    _uffd: Uffd,
}

/// Handshake with pagemaster: the only way guest memory comes into existence.
#[derive(Debug)]
pub struct FarplaneBackend;

impl FarplaneBackend {
    /// Records the channel path taken from the command line.
    pub fn set_socket_path(path: PathBuf) {
        *SOCKET_PATH.lock().expect("Poisoned lock") = Some(path);
    }

    /// Returns the configured channel path.
    pub fn socket_path() -> Option<PathBuf> {
        SOCKET_PATH.lock().expect("Poisoned lock").clone()
    }

    /// Takes the channel established by the handshake, so it can be driven by the event loop.
    pub fn take_channel() -> Option<MemoryChannel> {
        CHANNEL.lock().expect("Poisoned lock").take()
    }

    /// States whether a capture epoch is under way, which forbids lifecycle commands.
    pub fn capture_in_progress() -> bool {
        BackendState::load() == BackendState::Quiesced
    }

    /// Maps guest memory for a cold boot over the region list the machine configuration asks for.
    pub fn construct_boot(
        regions: &[(GuestAddress, usize)],
    ) -> Result<Vec<GuestRegionMmap>, BackendError> {
        let arch_regions = regions
            .iter()
            .map(|(addr, size)| RegionRecord {
                guest_addr: addr.0,
                size: *size as u64,
            })
            .collect::<Vec<_>>();
        let (memory, state) = handshake(Mode::Boot, &arch_regions)?;
        debug_assert!(state.is_none());
        Ok(memory)
    }

    /// Maps guest memory for a restore and parses the vmstate handed over with the plan.
    pub fn construct_restore() -> Result<(Vec<GuestRegionMmap>, MicrovmState), BackendError> {
        let (memory, state) = handshake(Mode::Restore, &[])?;
        let state = state.ok_or(BackendError::Plan(ErrorCode::VmstateParseFailed))?;
        Ok((memory, state))
    }
}

/// Marks the capture buffers armed or disarmed for the instance description.
pub fn set_capture_buffers_armed(armed: bool) {
    CAPTURE_BUFFERS_ARMED.store(armed, Ordering::Release);
}

/// Exact size of one harvested dirty bitmap: per region, `ceil(pages / 64)` words of 64 bits,
/// concatenated in plan region order.
pub fn dirty_bitmap_len(regions: &[RegionRecord]) -> u64 {
    let page = host_page_size() as u64;
    regions
        .iter()
        .map(|region| region.size.div_ceil(page).div_ceil(64) * 8)
        .sum()
}

/// Validates a capture buffer descriptor against the requirement reported at `backend_ready`. A
/// buffer is written during the freeze, so it has to be writable now rather than fail then.
pub fn validate_buffer_fd(fd: RawFd, min_size: u64) -> Result<(), ErrorCode> {
    let seals = memfd_seals(fd).ok_or(ErrorCode::FdNotMemfd)?;
    let stat = fstat(fd).ok_or(ErrorCode::FdNotMemfd)?;
    // SAFETY: `F_GETFL` only reads descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(ErrorCode::FdNotMemfd);
    }
    if flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(ErrorCode::FdNotSealed);
    }
    if seals & REQUIRED_BUFFER_SEALS != REQUIRED_BUFFER_SEALS
        || seals & (libc::F_SEAL_WRITE | libc::F_SEAL_FUTURE_WRITE) != 0
    {
        return Err(ErrorCode::FdNotSealed);
    }
    if stat.st_size.cast_unsigned() < min_size {
        return Err(ErrorCode::BufferTooSmall);
    }
    Ok(())
}

/// One guest region: a contiguous reservation tiled by extents of the plan.
#[derive(Debug)]
struct MappedRegion {
    guest_addr: u64,
    size: u64,
    host_base: usize,
    extents: Vec<MappedExtent>,
}

/// One extent mapping: the VMA that owns the folios of a range of guest memory.
#[derive(Debug)]
struct MappedExtent {
    len: u64,
    host_base: usize,
}

/// Runs the handshake through to `backend_ready` and publishes the channel. Every failure before
/// that point leaves the guest unable to execute: the caller propagates it and Firecracker exits.
fn handshake(
    mode: Mode,
    arch_regions: &[RegionRecord],
) -> Result<(Vec<GuestRegionMmap>, Option<MicrovmState>), BackendError> {
    let path = FarplaneBackend::socket_path().ok_or(BackendError::MissingSocket)?;
    BackendState::AwaitingPlan.store();

    let sock = connect_seqpacket(&path)?;
    set_socket_buffers(&sock)?;
    let peer = peer_cred(&sock)?;
    // SAFETY: `geteuid` has no failure mode and no side effects.
    if peer.uid != unsafe { libc::geteuid() } {
        return Err(BackendError::Peercred);
    }

    let hello = protocol::encode_hello(
        std::process::id(),
        u32::try_from(host_page_size()).expect("host page size fits in 32 bits"),
        if cfg!(target_arch = "x86_64") {
            Arch::X86_64
        } else {
            Arch::Aarch64
        },
        mode,
        arch_regions,
    );
    protocol::send_frame(&sock, MsgType::Hello, 0, &hello, &[])?;

    let mut plan_fds: Vec<OwnedFd> = Vec::new();
    loop {
        let incoming = protocol::recv_frame(&sock)?;
        match incoming.header.msg() {
            MsgType::PlanFds => {
                let count = protocol::parse_u32(&incoming.body)?;
                if count as usize != incoming.fds.len() {
                    return Err(BackendError::Channel(ChannelError::FdCountMismatch));
                }
                if plan_fds.len() + incoming.fds.len() > MAX_PLAN_FDS as usize {
                    reject(&sock, &incoming, ErrorCode::TooManyFds);
                    return Err(BackendError::Plan(ErrorCode::TooManyFds));
                }
                plan_fds.extend(incoming.fds);
            }
            MsgType::BackingPlan => {
                return commit_plan(sock, incoming, plan_fds, mode, arch_regions, peer.pid);
            }
            _ => return Err(BackendError::Channel(ChannelError::Malformed)),
        }
    }
}

/// Validates the plan, establishes every mapping, and reports the resulting geometry.
fn commit_plan(
    sock: UnixStream,
    incoming: Incoming,
    plan_fds: Vec<OwnedFd>,
    mode: Mode,
    arch_regions: &[RegionRecord],
    peer_pid: libc::pid_t,
) -> Result<(Vec<GuestRegionMmap>, Option<MicrovmState>), BackendError> {
    BackendState::Mapping.store();
    let plan = protocol::parse_backing_plan(&incoming.body)?;

    if plan.pm_pid != peer_pid.cast_unsigned() {
        reject(&sock, &incoming, ErrorCode::PeercredMismatch);
        return Err(BackendError::Peercred);
    }
    if plan.extent_count > MAX_EXTENTS {
        reject(&sock, &incoming, ErrorCode::TooManyExtents);
        return Err(BackendError::Plan(ErrorCode::TooManyExtents));
    }
    let expected_fds = 1 + usize::from(plan.has_vmstate());
    if incoming.fds.len() != expected_fds {
        reject(&sock, &incoming, ErrorCode::PlanNotCanonical);
        return Err(BackendError::Channel(ChannelError::FdCountMismatch));
    }

    let mut fd_sizes = Vec::with_capacity(plan_fds.len());
    for fd in &plan_fds {
        match validate_backing_fd(fd.as_raw_fd()) {
            Ok(size) => fd_sizes.push(size),
            Err(code) => {
                reject(&sock, &incoming, code);
                return Err(BackendError::Plan(code));
            }
        }
    }

    let extents = match read_extent_table(&incoming.fds[0], plan.extent_count) {
        Ok(extents) => extents,
        Err(code) => {
            reject(&sock, &incoming, code);
            return Err(BackendError::Plan(code));
        }
    };
    if let Err(code) = validate_canonical(&plan, &extents, &fd_sizes) {
        reject(&sock, &incoming, code);
        return Err(BackendError::Plan(code));
    }

    // Firecracker owns the architecture layout: the plan must tile exactly the regions this guest
    // has, whether they come from the machine configuration or from the vmstate being restored.
    let restored_state = match mode {
        Mode::Boot => {
            if plan.regions != arch_regions {
                reject(&sock, &incoming, ErrorCode::GeometryMismatch);
                return Err(BackendError::Plan(ErrorCode::GeometryMismatch));
            }
            None
        }
        Mode::Restore => {
            let state = match parse_vmstate(&incoming.fds[1]) {
                Ok(state) => state,
                Err(code) => {
                    reject(&sock, &incoming, code);
                    return Err(BackendError::Plan(code));
                }
            };
            let vmstate_regions: Vec<RegionRecord> = state
                .vm_state
                .memory
                .regions
                .iter()
                .map(|region| RegionRecord {
                    guest_addr: region.base_address,
                    size: region.size as u64,
                })
                .collect();
            if plan.regions != vmstate_regions {
                reject(&sock, &incoming, ErrorCode::GeometryMismatch);
                return Err(BackendError::Plan(ErrorCode::GeometryMismatch));
            }
            Some(state)
        }
    };

    let mapped = map_plan(&plan.regions, &extents, &plan_fds).inspect_err(|_| {
        reject(&sock, &incoming, ErrorCode::MapFailed);
    })?;
    let uffd = create_uffd().inspect_err(|_| {
        reject(&sock, &incoming, ErrorCode::UffdRegisterFailed);
    })?;
    register_uffd(&uffd, &mapped).inspect_err(|_| {
        reject(&sock, &incoming, ErrorCode::UffdRegisterFailed);
    })?;
    apply_residency(&mapped).inspect_err(|_| {
        reject(&sock, &incoming, ErrorCode::MlockFailed);
    })?;
    BackendState::Registered.store();

    // Pagemaster reads Firecracker's memory to probe its own permission path, so the exact-pid
    // grant is installed before the geometry it needs is reported.
    set_dumpable_and_ptracer(plan.pm_pid)?;

    let memory = wrap_guest_memory(&mapped)?;
    let dirty_bitmap_bytes = dirty_bitmap_len(&plan.regions);
    let ready_regions: Vec<BackendReadyRegion> = mapped
        .iter()
        .map(|region| BackendReadyRegion {
            guest_addr: region.guest_addr,
            size: region.size,
            host_base: region.host_base as u64,
        })
        .collect();
    let body = protocol::encode_backend_ready(
        &ready_regions,
        u32::try_from(mapped.len()).expect("region count is bounded by the plan datagram"),
        REQUIRED_UFFD_FEATURES,
        dirty_bitmap_bytes,
        VMSTATE_CAPACITY_BYTES,
    );
    let dup = dup_cloexec(uffd.as_raw_fd())?;
    protocol::send_frame(&sock, MsgType::BackendReady, 0, &body, &[dup.as_raw_fd()])?;
    drop(dup);
    BackendState::Ready.store();

    // Pagemaster verifies the reported geometry and probes its read permission, then acknowledges
    // with a bare `resume` before the guest is allowed to execute.
    let ack = protocol::recv_frame(&sock)?;
    if ack.header.msg() != MsgType::Resume
        || ack.header.request_id == 0
        || protocol::parse_u32(&ack.body)? != 0
    {
        return Err(BackendError::Channel(ChannelError::Malformed));
    }
    protocol::send_frame(
        &sock,
        MsgType::Resumed,
        ack.header.request_id,
        &0u32.to_le_bytes(),
        &[],
    )?;

    *CHANNEL.lock().expect("Poisoned lock") = Some(MemoryChannel {
        sock,
        regions: plan.regions,
        dirty_bitmap_bytes,
        _uffd: uffd,
    });
    Ok((memory, restored_state))
}

/// Reports a typed rejection of the command that carried `incoming`.
fn reject(sock: &UnixStream, incoming: &Incoming, code: ErrorCode) {
    let header = incoming.header;
    send_error(sock, header.request_id, code, header.msg());
}

/// Sends an `error` frame. A channel that cannot carry the rejection is itself the failure the
/// caller is already reporting.
pub fn send_error(sock: &UnixStream, request_id: u64, code: ErrorCode, op: MsgType) {
    let body = protocol::encode_error(code, op, "");
    let _ = protocol::send_frame(sock, MsgType::Error, request_id, &body, &[]);
}

/// Connects to the pagemaster channel.
fn connect_seqpacket(path: &Path) -> Result<UnixStream, BackendError> {
    // SAFETY: `socket` only allocates a descriptor.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(BackendError::Connect(io::Error::last_os_error()));
    }
    // SAFETY: `fd` was just created and is not owned by anything else.
    let sock = unsafe { UnixStream::from_raw_fd(fd) };

    let mut addr = libc::sockaddr_un {
        sun_family: libc::sa_family_t::try_from(libc::AF_UNIX)
            .expect("AF_UNIX fits in sa_family_t"),
        sun_path: [0; 108],
    };
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.len() >= addr.sun_path.len() {
        return Err(BackendError::Connect(io::Error::from_raw_os_error(
            libc::ENAMETOOLONG,
        )));
    }
    // SAFETY: `sun_path` is an array of one-byte `c_char`, whose signedness is arch dependent.
    let sun_path = unsafe {
        std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr().cast::<u8>(), bytes.len())
    };
    sun_path.copy_from_slice(bytes);
    // SAFETY: `addr` is a fully initialized `sockaddr_un` that outlives the call.
    let ret = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            std::ptr::addr_of!(addr).cast(),
            libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>())
                .expect("sockaddr_un size fits in socklen_t"),
        )
    };
    if ret != 0 {
        return Err(BackendError::Connect(io::Error::last_os_error()));
    }
    Ok(sock)
}

/// Sizes the socket buffers for the largest datagram the protocol allows.
fn set_socket_buffers(sock: &UnixStream) -> Result<(), BackendError> {
    let size = libc::c_int::try_from(protocol::MAX_DATAGRAM)
        .expect("the maximum datagram fits in a socket option");
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: `size` matches the option's expected type and outlives the call.
        let ret = unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(size).cast(),
                libc::socklen_t::try_from(std::mem::size_of_val(&size))
                    .expect("socket option size fits in socklen_t"),
            )
        };
        if ret != 0 {
            return Err(BackendError::Connect(io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Reads the credentials the kernel recorded for the peer when it called `listen`.
fn peer_cred(sock: &UnixStream) -> Result<libc::ucred, BackendError> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred size fits in socklen_t");
    // SAFETY: `cred` and `len` outlive the call and match the option's expected types.
    let ret = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(BackendError::Connect(io::Error::last_os_error()));
    }
    Ok(cred)
}

/// Reads the seals of a descriptor that is a memfd, or `None` when it is neither.
///
/// Identity is proven without procfs, which the jail does not have: only shmem and hugetlbfs
/// descriptors answer `F_GET_SEALS` at all, and those two filesystems are the only place a memfd
/// lives. A file opened from a mounted tmpfs would pass both, but carries `F_SEAL_SEAL` alone and
/// so can never satisfy the seals its role requires.
fn memfd_seals(fd: RawFd) -> Option<i32> {
    let seals = seals(fd)?;
    // `f_type` is a signed word on some targets and an unsigned one on others, so both sides are
    // widened to a type that holds either representation exactly.
    let magic = i128::from(fstatfs(fd)?.f_type);
    (magic == i128::from(TMPFS_MAGIC) || magic == i128::from(HUGETLBFS_MAGIC)).then_some(seals)
}

/// Returns the size of a backing descriptor that satisfies every precondition.
fn validate_backing_fd(fd: RawFd) -> Result<u64, ErrorCode> {
    let seals = memfd_seals(fd).ok_or(ErrorCode::FdNotMemfd)?;
    let stat = fstat(fd).ok_or(ErrorCode::FdNotMemfd)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(ErrorCode::FdNotMemfd);
    }
    // SAFETY: `F_GETFL` only reads descriptor flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(ErrorCode::FdNotMemfd);
    }
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(ErrorCode::FdWritable);
    }
    if seals & REQUIRED_BACKING_SEALS != REQUIRED_BACKING_SEALS {
        return Err(ErrorCode::FdNotSealed);
    }
    if stat.st_size <= 0 {
        return Err(ErrorCode::BadExtent);
    }
    Ok(stat.st_size.cast_unsigned())
}

/// Reads the seals of a descriptor, or `None` if it does not support sealing.
fn seals(fd: RawFd) -> Option<i32> {
    // SAFETY: `F_GET_SEALS` only reads descriptor state.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    (seals >= 0).then_some(seals)
}

/// Stats a descriptor.
fn fstat(fd: RawFd) -> Option<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` fills `stat` or fails without touching it.
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `fstat` returned success, so `stat` is initialized.
    Some(unsafe { stat.assume_init() })
}

/// Reads the filesystem identity of a descriptor.
fn fstatfs(fd: RawFd) -> Option<libc::statfs> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fstatfs` fills `stat` or fails without touching it.
    if unsafe { libc::fstatfs(fd, stat.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: `fstatfs` returned success, so `stat` is initialized.
    Some(unsafe { stat.assume_init() })
}

/// Reads the extent table out of its sealed descriptor.
fn read_extent_table(fd: &OwnedFd, count: u32) -> Result<Vec<ExtentRecord>, ErrorCode> {
    if memfd_seals(fd.as_raw_fd())
        .is_none_or(|seals| seals & REQUIRED_BACKING_SEALS != REQUIRED_BACKING_SEALS)
    {
        return Err(ErrorCode::FdNotSealed);
    }
    let mut file = File::from(fd.try_clone().map_err(|_| ErrorCode::FdNotMemfd)?);
    let mut buf = vec![0u8; count as usize * protocol::EXTENT_RECORD_LEN];
    file.read_exact(&mut buf)
        .map_err(|_| ErrorCode::BadExtent)?;
    buf.chunks_exact(protocol::EXTENT_RECORD_LEN)
        .map(|chunk| ExtentRecord::decode(chunk).map_err(|_| ErrorCode::BadExtent))
        .collect()
}

/// Parses the vmstate handed over with a restore plan.
fn parse_vmstate(fd: &OwnedFd) -> Result<MicrovmState, ErrorCode> {
    let mut file = File::from(fd.try_clone().map_err(|_| ErrorCode::VmstateParseFailed)?);
    // The vmstate always starts at offset zero, and a descriptor a live source
    // wrote through arrives with that source's own offset: the writer seeks to
    // the start and leaves the cursor past the bytes it wrote. Reading is
    // absolute so a forked child parses the same buffer its parent produced.
    file.seek(SeekFrom::Start(0))
        .map_err(|_| ErrorCode::VmstateParseFailed)?;
    Snapshot::<MicrovmState>::load(&mut file)
        .map(|snapshot| snapshot.data)
        .map_err(|_| ErrorCode::VmstateParseFailed)
}

/// Rejects any plan that is not in canonical form: sorted, page-aligned, gap-free, coalesced,
/// tiling every region exactly once and never crossing a region boundary.
fn validate_canonical(
    plan: &BackingPlanBody,
    extents: &[ExtentRecord],
    fd_sizes: &[u64],
) -> Result<(), ErrorCode> {
    if extents.len() != plan.extent_count as usize {
        return Err(ErrorCode::BadExtent);
    }
    if plan.regions.is_empty() || extents.is_empty() {
        return Err(ErrorCode::PlanNotCanonical);
    }

    let page = host_page_size() as u64;
    let mut next = 0usize;
    let mut region_cursor = 0u64;
    for region in &plan.regions {
        if region.size == 0
            || !region.guest_addr.is_multiple_of(page)
            || !region.size.is_multiple_of(page)
            || region.guest_addr < region_cursor
        {
            return Err(ErrorCode::GeometryMismatch);
        }
        let region_end = region
            .guest_addr
            .checked_add(region.size)
            .ok_or(ErrorCode::GeometryMismatch)?;

        // Coalescing is only required inside a region: extents of two regions live in two
        // reservations and cannot share a mapping.
        let mut previous: Option<ExtentRecord> = None;
        let mut cursor = region.guest_addr;
        while cursor < region_end {
            let extent = *extents.get(next).ok_or(ErrorCode::PlanNotCanonical)?;
            next += 1;

            if extent.reserved != 0
                || extent.len == 0
                || !extent.guest_addr.is_multiple_of(page)
                || !extent.len.is_multiple_of(page)
                || !extent.fd_offset.is_multiple_of(page)
            {
                return Err(ErrorCode::BadExtent);
            }
            let size = *fd_sizes
                .get(extent.fd_index as usize)
                .ok_or(ErrorCode::BadExtent)?;
            let extent_end = extent
                .guest_addr
                .checked_add(extent.len)
                .ok_or(ErrorCode::BadExtent)?;
            let offset_end = extent
                .fd_offset
                .checked_add(extent.len)
                .ok_or(ErrorCode::BadExtent)?;
            if offset_end > size {
                return Err(ErrorCode::BadExtent);
            }
            if extent_end > region_end {
                return Err(ErrorCode::BadExtent);
            }
            if extent.guest_addr != cursor {
                return Err(ErrorCode::PlanNotCanonical);
            }
            if previous.is_some_and(|previous| {
                previous.fd_index == extent.fd_index
                    && previous.guest_addr + previous.len == extent.guest_addr
                    && previous.fd_offset + previous.len == extent.fd_offset
            }) {
                return Err(ErrorCode::PlanNotCanonical);
            }

            cursor = extent_end;
            previous = Some(extent);
        }
        region_cursor = region_end;
    }
    if next != extents.len() {
        return Err(ErrorCode::PlanNotCanonical);
    }
    Ok(())
}

/// Reserves one contiguous host range per region and maps every extent into it.
fn map_plan(
    regions: &[RegionRecord],
    extents: &[ExtentRecord],
    fds: &[OwnedFd],
) -> Result<Vec<MappedRegion>, BackendError> {
    let mut mapped = Vec::with_capacity(regions.len());
    for region in regions {
        // SAFETY: an anonymous `PROT_NONE` reservation at an address of the kernel's choosing.
        let reservation = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                u64_to_usize(region.size),
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if reservation == libc::MAP_FAILED {
            return Err(BackendError::Map(io::Error::last_os_error()));
        }

        let region_end = region.guest_addr + region.size;
        let mut mapped_extents = Vec::new();
        for extent in extents.iter().filter(|extent| {
            extent.guest_addr >= region.guest_addr && extent.guest_addr < region_end
        }) {
            let offset = u64_to_usize(extent.guest_addr - region.guest_addr);
            // SAFETY: `offset + extent.len` is within the reservation, which validation proved.
            let target = unsafe { reservation.byte_add(offset) };
            // SAFETY: `MAP_FIXED` over a range of our own reservation, from a descriptor that is
            // sealed read-only and long enough for the offset and length being mapped.
            let addr = unsafe {
                libc::mmap(
                    target,
                    u64_to_usize(extent.len),
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_FIXED,
                    fds[extent.fd_index as usize].as_raw_fd(),
                    extent.fd_offset.cast_signed(),
                )
            };
            if addr == libc::MAP_FAILED {
                return Err(BackendError::Map(io::Error::last_os_error()));
            }
            mapped_extents.push(MappedExtent {
                len: extent.len,
                host_base: addr as usize,
            });
        }

        mapped.push(MappedRegion {
            guest_addr: region.guest_addr,
            size: region.size,
            host_base: reservation as usize,
            extents: mapped_extents,
        });
    }
    Ok(mapped)
}

/// Wraps each contiguous reservation as one guest memory region with its dirty bitmap.
fn wrap_guest_memory(mapped: &[MappedRegion]) -> Result<Vec<GuestRegionMmap>, BackendError> {
    mapped
        .iter()
        .map(|region| {
            let size = u64_to_usize(region.size);
            let builder =
                MmapRegionBuilder::new_with_bitmap(size, Some(AtomicBitmap::with_len(size)))
                    .with_mmap_prot(libc::PROT_READ | libc::PROT_WRITE)
                    .with_mmap_flags(libc::MAP_PRIVATE);
            // SAFETY: the reservation is a live mapping of exactly `size` bytes, owned by this
            // process for its lifetime.
            let mmap = unsafe { builder.with_raw_mmap_pointer(region.host_base as *mut u8) }
                .build()
                .map_err(|err| BackendError::Map(io::Error::other(err)))?;
            GuestRegionMmap::new(mmap, GuestAddress(region.guest_addr))
                .ok_or_else(|| BackendError::Map(io::Error::from_raw_os_error(libc::EINVAL)))
        })
        .collect()
}

/// Creates this process's userfaultfd from the device the jailer passed, then performs the API
/// handshake. A userfaultfd belongs to the memory map of the process that created it, so it has
/// to be created here, after exec, for the guest mappings to be registrable on it.
fn create_uffd() -> Result<Uffd, BackendError> {
    // SAFETY: fd 3 is the userfaultfd device the jailer opened; the argument is a flag word.
    let raw = unsafe {
        ioctl_with_val(
            &BorrowedFd::borrow_raw(UFFD_DEVICE_FILENO),
            USERFAULTFD_IOC_NEW(),
            c_ulong::from((libc::O_CLOEXEC | libc::O_NONBLOCK).cast_unsigned()),
        )
    };
    if raw < 0 {
        return Err(BackendError::Uffd(io::Error::last_os_error()));
    }

    let mut api = uffdio_api {
        api: UFFD_API,
        features: REQUIRED_UFFD_FEATURES,
        ioctls: 0,
    };
    // SAFETY: `raw` is the userfaultfd just created, and `api` outlives the call.
    let ret = unsafe { ioctl_with_mut_ref(&BorrowedFd::borrow_raw(raw), UFFDIO_API(), &mut api) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `raw` is owned here and unused after the failed handshake.
        unsafe { libc::close(raw) };
        return Err(BackendError::Uffd(err));
    }
    if api.features & REQUIRED_UFFD_FEATURES != REQUIRED_UFFD_FEATURES {
        // SAFETY: `raw` is owned here and unused once the features are refused.
        unsafe { libc::close(raw) };
        return Err(BackendError::UffdFeatures(api.features));
    }
    // SAFETY: `raw` is a userfaultfd whose API handshake just completed, and nothing else owns it.
    Ok(unsafe { Uffd::from_raw_fd(raw) })
}

/// Registers missing, minor and write-protect faults over every extent mapping.
fn register_uffd(uffd: &Uffd, mapped: &[MappedRegion]) -> Result<(), BackendError> {
    let mode = RegisterMode::MISSING | RegisterMode::MINOR | RegisterMode::WRITE_PROTECT;
    for region in mapped {
        for extent in &region.extents {
            uffd.register_with_mode(
                extent.host_base as *mut libc::c_void,
                u64_to_usize(extent.len),
                mode,
            )
            .map_err(|err| BackendError::Uffd(io::Error::other(err)))?;
        }
    }
    Ok(())
}

/// Locks guest memory on fault and keeps it out of transparent huge pages.
fn apply_residency(mapped: &[MappedRegion]) -> Result<(), BackendError> {
    for region in mapped {
        for extent in &region.extents {
            let addr = extent.host_base as *mut libc::c_void;
            let len = u64_to_usize(extent.len);
            // SAFETY: `addr` and `len` describe a mapping this process just established.
            let ret = unsafe { libc::mlock2(addr, len, libc::MLOCK_ONFAULT) };
            if ret != 0 {
                return Err(BackendError::Map(io::Error::last_os_error()));
            }
            // SAFETY: same mapping; `MADV_NOHUGEPAGE` only changes fault-time page size policy.
            let ret = unsafe { libc::madvise(addr, len, libc::MADV_NOHUGEPAGE) };
            if ret != 0 {
                return Err(BackendError::Map(io::Error::last_os_error()));
            }
        }
    }
    Ok(())
}

/// Makes this process readable by exactly the pagemaster that serves its faults.
fn set_dumpable_and_ptracer(pm_pid: u32) -> Result<(), BackendError> {
    // SAFETY: both `prctl` operations only change this process's own attributes.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 1) != 0 {
            return Err(BackendError::Identity(io::Error::last_os_error()));
        }
        if libc::prctl(libc::PR_SET_PTRACER, pm_pid as libc::c_ulong) != 0 {
            return Err(BackendError::Identity(io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Duplicates a descriptor for transfer over the channel.
fn dup_cloexec(fd: RawFd) -> Result<OwnedFd, BackendError> {
    // SAFETY: `F_DUPFD_CLOEXEC` only allocates a new descriptor for `fd`.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(BackendError::Uffd(io::Error::last_os_error()));
    }
    // SAFETY: `dup` was just created and is not owned by anything else.
    Ok(unsafe { OwnedFd::from_raw_fd(dup) })
}

#[cfg(test)]
mod tests {
    use std::ffi::CStr;

    use super::*;

    fn plan(regions: &[RegionRecord], extent_count: u32) -> BackingPlanBody {
        BackingPlanBody {
            pm_pid: 1,
            extent_count,
            flags: 0,
            regions: regions.to_vec(),
        }
    }

    fn extent(guest_addr: u64, len: u64, fd_index: u32, fd_offset: u64) -> ExtentRecord {
        ExtentRecord {
            guest_addr,
            len,
            fd_index,
            reserved: 0,
            fd_offset,
        }
    }

    fn page() -> u64 {
        host_page_size() as u64
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
    }

    fn memfd(name: &CStr, size: libc::off_t) -> RawFd {
        // SAFETY: `name` is a NUL-terminated string that outlives the call.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                libc::MFD_ALLOW_SEALING,
            )
        };
        assert!(raw >= 0, "{}", io::Error::last_os_error());
        let fd = RawFd::try_from(raw).unwrap();
        // SAFETY: `fd` is an owned memfd of this process.
        assert_eq!(unsafe { libc::ftruncate(fd, size) }, 0);
        fd
    }

    #[test]
    fn dirty_bitmap_size_is_one_word_per_64_pages_per_region() {
        let page = page();
        let regions = [
            RegionRecord {
                guest_addr: 0,
                size: page * 64,
            },
            RegionRecord {
                guest_addr: page * 64,
                size: page * 65,
            },
        ];
        assert_eq!(dirty_bitmap_len(&regions), 8 + 16);
    }

    #[test]
    fn capture_buffer_must_be_sealed_and_large_enough() {
        let buffer = memfd(c"farplane-capture-buffer", 4096);

        assert_eq!(
            validate_buffer_fd(buffer, 4096),
            Err(ErrorCode::FdNotSealed)
        );

        // SAFETY: sealing an owned memfd only restricts what it permits.
        let sealed = unsafe { libc::fcntl(buffer, libc::F_ADD_SEALS, REQUIRED_BUFFER_SEALS) };
        assert_eq!(sealed, 0);
        assert_eq!(validate_buffer_fd(buffer, 4096), Ok(()));
        assert_eq!(
            validate_buffer_fd(buffer, 8192),
            Err(ErrorCode::BufferTooSmall)
        );

        // SAFETY: `buffer` is owned by this test and no longer used.
        unsafe { libc::close(buffer) };
    }

    /// The bytes of `backend_ready` are the seam with pagemaster: the region count leads the body,
    /// records follow, then the fixed tail. The same datagram is pinned on the Go side.
    #[test]
    fn backend_ready_matches_the_cross_language_fixture() {
        // Dirty bitmap of this geometry on a 4 KiB-page host, stated as a constant so the fixture
        // does not depend on the page size of the machine running the test.
        const DIRTY_BITMAP_BYTES: u64 = 0x9000;
        let regions = [
            BackendReadyRegion {
                guest_addr: 0,
                size: 0x0800_0000,
                host_base: 0x0000_7f00_0000_0000,
            },
            BackendReadyRegion {
                guest_addr: 0x1_0000_0000,
                size: 0x4000_0000,
                host_base: 0x0000_7f10_0000_0000,
            },
        ];

        let body = protocol::encode_backend_ready(
            &regions,
            u32::try_from(regions.len()).unwrap(),
            REQUIRED_UFFD_FEATURES,
            DIRTY_BITMAP_BYTES,
            VMSTATE_CAPACITY_BYTES,
        );
        let header = protocol::Header::new(
            MsgType::BackendReady,
            0,
            u32::try_from(body.len()).unwrap(),
            1,
        );
        let mut datagram = header.encode().to_vec();
        datagram.extend_from_slice(&body);
        assert_eq!(
            hex(&datagram),
            include_str!("testdata/backend_ready.hex").trim()
        );

        if host_page_size() == 4096 {
            let plan_regions = regions.map(|region| RegionRecord {
                guest_addr: region.guest_addr,
                size: region.size,
            });
            assert_eq!(dirty_bitmap_len(&plan_regions), DIRTY_BITMAP_BYTES);
        }
    }

    /// Descriptor identity is proven from the descriptor alone: the jail has no procfs to read a
    /// link target from.
    #[test]
    fn memfd_identity_is_proven_without_procfs() {
        let image = memfd(c"farplane-backing", 4096);
        assert_eq!(memfd_seals(image), Some(0));

        let mut pipe = [-1i32; 2];
        // SAFETY: `pipe` has room for the two descriptors the call returns.
        let created = unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(created, 0, "{}", io::Error::last_os_error());
        assert_eq!(memfd_seals(pipe[0]), None);
        assert_eq!(validate_backing_fd(pipe[0]), Err(ErrorCode::FdNotMemfd));

        for fd in [image, pipe[0], pipe[1]] {
            // SAFETY: every descriptor is owned by this test and no longer used.
            unsafe { libc::close(fd) };
        }
    }

    #[test]
    fn canonical_plan_over_two_descriptors_is_accepted() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page * 2,
        }];
        let extents = [extent(0, page, 0, 0), extent(page, page, 1, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &extents, &[page, page]),
            Ok(())
        );
    }

    #[test]
    fn uncoalesced_adjacency_is_rejected() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page * 2,
        }];
        let extents = [extent(0, page, 0, 0), extent(page, page, 0, page)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &extents, &[page * 2]),
            Err(ErrorCode::PlanNotCanonical)
        );
    }

    #[test]
    fn adjacent_extents_across_a_region_boundary_are_accepted() {
        let page = page();
        let regions = [
            RegionRecord {
                guest_addr: 0,
                size: page,
            },
            RegionRecord {
                guest_addr: page,
                size: page,
            },
        ];
        let extents = [extent(0, page, 0, 0), extent(page, page, 0, page)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &extents, &[page * 2]),
            Ok(())
        );
    }

    #[test]
    fn gap_overlap_and_disorder_are_rejected() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page * 4,
        }];

        let gap = [extent(0, page, 0, 0), extent(page * 2, page * 2, 1, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &gap, &[page, page * 2]),
            Err(ErrorCode::PlanNotCanonical)
        );

        let overlap = [extent(0, page * 2, 0, 0), extent(page, page * 3, 1, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &overlap, &[page * 2, page * 3]),
            Err(ErrorCode::PlanNotCanonical)
        );

        let unsorted = [extent(page * 2, page * 2, 0, 0), extent(0, page * 2, 1, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &unsorted, &[page * 2, page * 2]),
            Err(ErrorCode::PlanNotCanonical)
        );
    }

    #[test]
    fn extent_crossing_a_region_boundary_is_rejected() {
        let page = page();
        let regions = [
            RegionRecord {
                guest_addr: 0,
                size: page,
            },
            RegionRecord {
                guest_addr: page,
                size: page,
            },
        ];
        let extents = [extent(0, page * 2, 0, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &extents, &[page * 2]),
            Err(ErrorCode::BadExtent)
        );
    }

    #[test]
    fn misalignment_reserved_bits_and_bad_indices_are_rejected() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page * 2,
        }];

        let mut reserved_set = extent(0, page * 2, 0, 0);
        reserved_set.reserved = 1;
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &[reserved_set], &[page * 2]),
            Err(ErrorCode::BadExtent)
        );

        let misaligned_len = [extent(0, page + 1, 0, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &misaligned_len, &[page * 2]),
            Err(ErrorCode::BadExtent)
        );

        let misaligned_offset = [extent(0, page * 2, 0, 1)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &misaligned_offset, &[page * 4]),
            Err(ErrorCode::BadExtent)
        );

        let unknown_fd = [extent(0, page * 2, 7, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &unknown_fd, &[page * 2]),
            Err(ErrorCode::BadExtent)
        );
    }

    #[test]
    fn extent_past_the_end_of_its_descriptor_is_rejected() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page * 2,
        }];
        let extents = [extent(0, page * 2, 0, page)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &extents, &[page * 2]),
            Err(ErrorCode::BadExtent)
        );
    }

    #[test]
    fn plan_that_does_not_tile_every_region_is_rejected() {
        let page = page();
        let regions = [
            RegionRecord {
                guest_addr: 0,
                size: page,
            },
            RegionRecord {
                guest_addr: page,
                size: page,
            },
        ];
        let short = [extent(0, page, 0, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 1), &short, &[page]),
            Err(ErrorCode::PlanNotCanonical)
        );

        let trailing = [
            extent(0, page, 0, 0),
            extent(page, page, 0, page),
            extent(page * 2, page, 0, page * 2),
        ];
        assert_eq!(
            validate_canonical(&plan(&regions, 3), &trailing, &[page * 3]),
            Err(ErrorCode::PlanNotCanonical)
        );
    }

    #[test]
    fn extent_count_must_match_the_table() {
        let page = page();
        let regions = [RegionRecord {
            guest_addr: 0,
            size: page,
        }];
        let extents = [extent(0, page, 0, 0)];
        assert_eq!(
            validate_canonical(&plan(&regions, 2), &extents, &[page]),
            Err(ErrorCode::BadExtent)
        );
    }
}
