// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks
)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use vm_memory::GuestAddress;
use vmm::vstate::ramet::backend::VMSTATE_CAPACITY_BYTES;
use vmm::vstate::ramet::protocol::{
    self, ChannelError, ERROR_DETAIL_LEN, HEADER_LEN, Header, MAGIC, MAX_DATAGRAM, Mode, MsgType,
    READY_REGION_RECORD_LEN, RegionRecord, VERSION,
};
use vmm::vstate::ramet::{BackendError, ErrorCode, RametBackend};
use vmm_sys_util::tempdir::TempDir;

// Socket/channel state and fixed guest addresses are process-global.
static HANDSHAKE: Mutex<()> = Mutex::new(());
const RAM_BASE: u64 = 0x3000_0000_0000;

fn handshake_lock() -> MutexGuard<'static, ()> {
    HANDSHAKE.lock().unwrap_or_else(|err| err.into_inner())
}

/// A sealed, read-only memfd: an image every root slot contract accepts.
fn sealed_root_image() -> OwnedFd {
    let fd = unsafe { libc::memfd_create(c"root".as_ptr().cast(), libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0, "memfd_create: {}", last_error());
    assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    let path = std::ffi::CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let read_only = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(read_only >= 0, "reopen: {}", last_error());
    unsafe { libc::close(fd) };
    unsafe { OwnedFd::from_raw_fd(read_only) }
}

/// Points the backend at `path` and connects it, as Firecracker does at startup. The drive
/// images a real claim hands over first are installed once per process, so every handshake
/// here starts where a claimed Firecracker's does.
fn connect_backend(path: &Path) {
    static DRIVES: std::sync::Once = std::sync::Once::new();
    DRIVES.call_once(|| {
        // The drive slots are this process's own descriptor numbers; the jailer reserves them
        // for Firecracker, and nothing in this test binary may already hold them.
        for slot in [4, 5] {
            assert_eq!(
                unsafe { libc::fcntl(slot, libc::F_GETFD) },
                -1,
                "fd {slot} is taken"
            );
            let null = std::fs::File::open("/dev/null").unwrap();
            assert_eq!(unsafe { libc::dup2(null.as_raw_fd(), slot) }, slot);
        }
        vmm::vstate::ramet::drives::install(sealed_root_image(), None).unwrap();
    });
    RametBackend::set_socket_path(path.to_path_buf());
    RametBackend::connect().expect("connect the memory channel");
}

fn page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn listen_seqpacket(path: &Path) -> OwnedFd {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", last_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = path.as_os_str().as_encoded_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (i, byte) in bytes.iter().enumerate() {
        addr.sun_path[i] = *byte as libc::c_char;
    }
    assert_eq!(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast(),
                std::mem::size_of::<libc::sockaddr_un>() as u32,
            )
        },
        0,
        "bind: {}",
        last_error()
    );
    assert_eq!(unsafe { libc::listen(fd.as_raw_fd(), 1) }, 0);
    fd
}

fn accept(listener: &OwnedFd) -> UnixStream {
    let fd = unsafe {
        libc::accept(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert!(fd >= 0, "accept: {}", last_error());
    let sock = unsafe { UnixStream::from_raw_fd(fd) };
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock
}

fn seqpacket_pair() -> (UnixStream, UnixStream) {
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        },
        0
    );
    unsafe {
        (
            UnixStream::from_raw_fd(fds[0]),
            UnixStream::from_raw_fd(fds[1]),
        )
    }
}

fn regions() -> Vec<RegionRecord> {
    let page = page_size();
    vec![
        RegionRecord {
            guest_addr: 0,
            size: page,
        },
        RegionRecord {
            guest_addr: 3 * page,
            size: 2 * page,
        },
    ]
}

fn encode_plan(regions: &[RegionRecord], extents: u32, flags: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&std::process::id().to_le_bytes());
    body.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    body.extend_from_slice(&extents.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    for region in regions {
        body.extend_from_slice(&region.encode());
    }
    body
}

fn check_hello(sock: &UnixStream, mode: Mode) {
    let hello = protocol::recv_frame(sock).unwrap();
    assert_eq!(hello.header.msg_type, MsgType::Hello as u16);
    assert_eq!(hello.header.request_id, 0);
    assert!(hello.fds.is_empty());
    assert_eq!(&hello.body[10..12], &(mode as u16).to_le_bytes());
    assert_eq!(&hello.body[16..48], &protocol::feature_identity_padded());
    let expected = if mode == Mode::Boot {
        regions()
    } else {
        vec![]
    };
    assert_eq!(hello.body.len(), 48 + expected.len() * 16);
    for (bytes, region) in hello.body[48..].chunks_exact(16).zip(expected) {
        assert_eq!(RegionRecord::decode(bytes).unwrap(), region);
    }
}

fn raw_send(sock: &UnixStream, bytes: &[u8]) {
    assert_eq!(
        unsafe {
            libc::send(
                sock.as_raw_fd(),
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        bytes.len() as isize,
        "send: {}",
        last_error()
    );
}

// Retired PlanFds, extent-table canonicalization and UFFD-adoption tests are intentionally
// replaced: /7 has a single plan, anonymous boot RAM, and a version capability on restore.
#[test]
fn cold_boot_multiregion_ready_ack_and_mapping_lifetime() {
    let _guard = handshake_lock();
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("pagemaster.sock");
    let listener = listen_seqpacket(&path);
    connect_backend(&path);
    let pm = thread::spawn(move || {
        let sock = accept(&listener);
        check_hello(&sock, Mode::Boot);
        let regions = regions();
        let body = encode_plan(&regions, 0, 0);
        assert_eq!(body.len(), 16 + 16 * regions.len());
        protocol::send_frame(&sock, MsgType::BackingPlan, 2, &body, &[]).unwrap();
        let ready = protocol::recv_frame(&sock).unwrap();
        assert_eq!(ready.header.msg_type, MsgType::BackendReady as u16);
        assert_eq!(ready.header.request_id, 0);
        assert_eq!(ready.header.fd_count, 0);
        assert!(ready.fds.is_empty());
        let mut expected = (regions.len() as u32).to_le_bytes().to_vec();
        for region in &regions {
            expected.extend_from_slice(&region.encode());
            expected.extend_from_slice(&(RAM_BASE + region.guest_addr).to_le_bytes());
        }
        assert_eq!(expected.len(), 4 + regions.len() * READY_REGION_RECORD_LEN);
        expected.extend_from_slice(&(regions.len() as u32).to_le_bytes());
        expected.extend_from_slice(&0u64.to_le_bytes()); // features
        expected.extend_from_slice(&0u64.to_le_bytes()); // harvest buffer
        expected.extend_from_slice(&VMSTATE_CAPACITY_BYTES.to_le_bytes());
        assert_eq!(ready.body, expected);
        protocol::send_frame(&sock, MsgType::Resume, 3, &0u32.to_le_bytes(), &[]).unwrap();
        let resumed = protocol::recv_frame(&sock).unwrap();
        assert_eq!(resumed.header.msg_type, MsgType::Resumed as u16);
        assert_eq!(resumed.header.request_id, 3);
        assert_eq!(resumed.body, 0u32.to_le_bytes());
        assert!(resumed.fds.is_empty());
    });
    let requested: Vec<_> = regions()
        .iter()
        .map(|r| (GuestAddress(r.guest_addr), r.size as usize))
        .collect();
    let memory = RametBackend::construct_boot(&requested).expect("portable anonymous cold boot");
    pm.join().unwrap();
    let memory: Vec<_> = memory.into_iter().map(Arc::new).collect();
    for (guest, record) in memory.iter().zip(regions()) {
        assert_eq!(guest.as_ptr() as u64, RAM_BASE + record.guest_addr);
        // Access only while a guest-region owner holds the anonymous RW mapping alive.
        let bytes = unsafe { std::slice::from_raw_parts_mut(guest.as_ptr(), record.size as usize) };
        assert!(bytes.iter().all(|byte| *byte == 0));
        bytes.fill(0xa5);
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
    drop(RametBackend::take_channel().expect("published channel"));
    for record in regions() {
        assert_mapped(&record);
    }
    let last_owner = Arc::clone(&memory[0]);
    drop(memory);
    assert_mapped(&regions()[0]);
    assert_unmapped(&regions()[1]);
    drop(last_owner);
    assert_unmapped(&regions()[0]);
}

fn assert_mapped(region: &RegionRecord) {
    let mut resident = vec![0u8; (region.size / page_size()) as usize];
    assert_eq!(
        unsafe {
            libc::mincore(
                (RAM_BASE + region.guest_addr) as *mut libc::c_void,
                region.size as usize,
                resident.as_mut_ptr(),
            )
        },
        0,
        "mincore: {}",
        last_error()
    );
}

fn assert_unmapped(region: &RegionRecord) {
    let addr = (RAM_BASE + region.guest_addr) as *mut libc::c_void;
    let mapped = unsafe {
        libc::mmap(
            addr,
            region.size as usize,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    assert_eq!(
        mapped,
        addr,
        "last region owner must unmap: {}",
        last_error()
    );
    assert_eq!(unsafe { libc::munmap(mapped, region.size as usize) }, 0);
}

// Exercise constructor rejection over a real socket. Some early failures simply close the
// channel; those must not be mistaken for a successful BackendReady.
fn reject_plan(mode: Mode, body: Vec<u8>, fds: Vec<OwnedFd>) -> (BackendError, Option<u32>) {
    let _guard = handshake_lock();
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("pagemaster.sock");
    let listener = listen_seqpacket(&path);
    connect_backend(&path);
    let pm = thread::spawn(move || {
        let sock = accept(&listener);
        check_hello(&sock, mode);
        let rights: Vec<RawFd> = fds.iter().map(AsRawFd::as_raw_fd).collect();
        protocol::send_frame(&sock, MsgType::BackingPlan, 2, &body, &rights).unwrap();
        match protocol::recv_frame(&sock) {
            Ok(frame) => {
                assert_eq!(frame.header.msg_type, MsgType::Error as u16);
                assert_eq!(frame.header.request_id, 2);
                assert!(frame.fds.is_empty());
                assert_eq!(frame.body.len(), 8 + ERROR_DETAIL_LEN);
                assert_eq!(
                    &frame.body[4..6],
                    &(MsgType::BackingPlan as u16).to_le_bytes()
                );
                assert_eq!(&frame.body[6..8], &[0, 0]);
                Some(u32::from_le_bytes(frame.body[..4].try_into().unwrap()))
            }
            Err(ChannelError::Closed) => None,
            Err(ChannelError::Io(err)) => {
                assert!(matches!(
                    err.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ));
                None
            }
            Err(err) => panic!("unexpected receive error: {err:?}"),
        }
    });
    let result = if mode == Mode::Boot {
        let requested: Vec<_> = regions()
            .iter()
            .map(|r| (GuestAddress(r.guest_addr), r.size as usize))
            .collect();
        RametBackend::construct_boot(&requested).map(|_| ())
    } else {
        RametBackend::construct_restore().map(|_| ())
    };
    let error = result.expect_err("invalid plan must fail");
    let wire = pm.join().unwrap();
    assert!(RametBackend::take_channel().is_none());
    (error, wire)
}

fn ordinary_fd() -> OwnedFd {
    std::fs::File::open("/dev/null").unwrap().into()
}

#[test]
fn bad_region_geometry_is_rejected() {
    let page = page_size();
    let cases = [
        vec![],
        vec![RegionRecord {
            guest_addr: 1,
            size: page,
        }],
        vec![RegionRecord {
            guest_addr: 0,
            size: 0,
        }],
        vec![RegionRecord {
            guest_addr: 0,
            size: page - 1,
        }],
        vec![
            RegionRecord {
                guest_addr: 0,
                size: 2 * page,
            },
            RegionRecord {
                guest_addr: page,
                size: page,
            },
        ],
        vec![RegionRecord {
            guest_addr: u64::MAX - page + 1,
            size: page,
        }],
    ];
    for records in cases {
        let (error, _) = reject_plan(Mode::Boot, encode_plan(&records, 0, 0), vec![]);
        assert!(matches!(error, BackendError::Map(_)), "{error:?}");
    }
    let (error, wire) = reject_plan(Mode::Boot, encode_plan(&regions()[..1], 0, 0), vec![]);
    assert!(matches!(
        error,
        BackendError::Plan(ErrorCode::GeometryMismatch)
    ));
    assert_eq!(wire, Some(ErrorCode::GeometryMismatch as u32));
}

#[test]
fn nonzero_extent_count_is_rejected() {
    let (error, _) = reject_plan(Mode::Boot, encode_plan(&regions(), 1, 0), vec![]);
    assert!(matches!(
        error,
        BackendError::Channel(ChannelError::Malformed)
    ));
}

#[test]
fn boot_with_rights_is_rejected() {
    let (error, wire) = reject_plan(
        Mode::Boot,
        encode_plan(&regions(), 0, 0),
        vec![ordinary_fd()],
    );
    assert!(matches!(
        error,
        BackendError::Channel(ChannelError::FdCountMismatch)
    ));
    assert_eq!(wire, Some(ErrorCode::PlanNotCanonical as u32));
}

#[test]
fn restore_requires_provenance_and_two_descriptors() {
    let (error, _) = reject_plan(Mode::Restore, encode_plan(&regions(), 0, 1), vec![]);
    assert!(matches!(
        error,
        BackendError::Channel(ChannelError::Malformed)
    ));
    let (error, wire) = reject_plan(Mode::Restore, encode_plan(&regions(), 0, 0), vec![]);
    assert!(matches!(
        error,
        BackendError::Plan(ErrorCode::PlanNotCanonical)
    ));
    assert_eq!(wire, Some(ErrorCode::PlanNotCanonical as u32));
    for fds in [vec![], vec![ordinary_fd()]] {
        let mut body = encode_plan(&regions(), 0, 1);
        body.extend_from_slice(&[0x42; 32]);
        let (error, wire) = reject_plan(Mode::Restore, body, fds);
        assert!(matches!(
            error,
            BackendError::Channel(ChannelError::FdCountMismatch)
        ));
        assert_eq!(wire, Some(ErrorCode::PlanNotCanonical as u32));
    }
}

#[test]
fn restore_rejects_a_nonversion_descriptor_without_a_device() {
    let mut body = encode_plan(&regions(), 0, 1);
    body.extend_from_slice(&[0x42; 32]);
    let (error, _) = reject_plan(Mode::Restore, body, vec![ordinary_fd(), ordinary_fd()]);
    assert!(matches!(error, BackendError::Map(_)), "{error:?}");
    // An ordinary fd cannot answer MV_IOC_INFO. This proves rejection, not kernel import success.
}

#[test]
fn header_round_trips_every_active_message_type() {
    let types = [
        MsgType::BackingPlan,
        MsgType::CaptureBuffers,
        MsgType::Quiesce,
        MsgType::WriteVmstate,
        MsgType::Resume,
        MsgType::Hello,
        MsgType::BackendReady,
        MsgType::Quiesced,
        MsgType::VmstateWritten,
        MsgType::Resumed,
        MsgType::Error,
        MsgType::CaptureBuffersArmed,
    ];
    for (index, msg_type) in types.into_iter().enumerate() {
        let header = Header::new(
            msg_type,
            index as u64 * 7,
            index as u32 * 32,
            index as u32 % 3,
        );
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_eq!(&encoded[..4], &MAGIC.to_le_bytes());
        assert_eq!(&encoded[4..6], &VERSION.to_le_bytes());
        assert_eq!(Header::decode(&encoded).unwrap(), header);
        assert_eq!(MsgType::from_u16(header.msg_type), Some(msg_type));
    }
}

#[test]
fn legacy_tags_are_rejected_on_the_wire() {
    for tag in [1u16, 5, 7, 12, 14, 18, 19, 20, 21] {
        assert_eq!(MsgType::from_u16(tag), None);
        let mut encoded = Header::new(MsgType::Hello, 1, 0, 0).encode();
        encoded[6..8].copy_from_slice(&tag.to_le_bytes());
        assert!(matches!(
            Header::decode(&encoded),
            Err(ChannelError::Malformed)
        ));
        let (tx, rx) = seqpacket_pair();
        raw_send(&tx, &encoded);
        assert!(matches!(
            protocol::recv_frame(&rx),
            Err(ChannelError::Malformed)
        ));
    }
}

#[test]
fn invalid_header_fields_are_rejected() {
    for (offset, bytes) in [
        (0, (MAGIC ^ 1).to_le_bytes().to_vec()),
        (4, (VERSION + 1).to_le_bytes().to_vec()),
        (24, 1u64.to_le_bytes().to_vec()),
    ] {
        let mut encoded = Header::new(MsgType::Hello, 0, 0, 0).encode();
        encoded[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(matches!(
            Header::decode(&encoded),
            Err(ChannelError::Malformed)
        ));
    }
}

#[test]
fn body_length_inconsistent_with_datagram_is_rejected() {
    let (tx, rx) = seqpacket_pair();
    let mut bytes = Header::new(MsgType::Quiesced, 9, 17, 0).encode().to_vec();
    bytes.extend_from_slice(&[0; 16]);
    raw_send(&tx, &bytes);
    assert!(matches!(
        protocol::recv_frame(&rx),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn frame_round_trips_scm_rights_and_body() {
    let (tx, rx) = seqpacket_pair();
    let fd = ordinary_fd();
    protocol::send_frame(
        &tx,
        MsgType::CaptureBuffers,
        7,
        &[1, 2, 3],
        &[fd.as_raw_fd()],
    )
    .unwrap();
    let got = protocol::recv_frame(&rx).unwrap();
    assert_eq!(got.header.request_id, 7);
    assert_eq!(got.body, [1, 2, 3]);
    assert_eq!(got.fds.len(), 1);
    let mut original: libc::stat = unsafe { std::mem::zeroed() };
    let mut received: libc::stat = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut original) }, 0);
    assert_eq!(
        unsafe { libc::fstat(got.fds[0].as_raw_fd(), &mut received) },
        0
    );
    assert_eq!(
        (original.st_dev, original.st_ino),
        (received.st_dev, received.st_ino)
    );
}

#[test]
fn datagram_larger_than_maximum_is_refused() {
    let (tx, _rx) = seqpacket_pair();
    protocol::send_frame(
        &tx,
        MsgType::Quiesced,
        1,
        &vec![0; MAX_DATAGRAM - HEADER_LEN],
        &[],
    )
    .unwrap();
    assert!(matches!(
        protocol::send_frame(
            &tx,
            MsgType::Quiesced,
            2,
            &vec![0; MAX_DATAGRAM - HEADER_LEN + 1],
            &[]
        ),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn oversized_datagram_arriving_truncated_is_rejected() {
    let (tx, rx) = seqpacket_pair();
    let body_len = MAX_DATAGRAM + 4096 - HEADER_LEN;
    let mut bytes = Header::new(MsgType::Quiesced, 5, body_len as u32, 0)
        .encode()
        .to_vec();
    bytes.resize(HEADER_LEN + body_len, 0);
    raw_send(&tx, &bytes);
    assert!(matches!(
        protocol::recv_frame(&rx),
        Err(ChannelError::Malformed | ChannelError::Truncated)
    ));
}

#[test]
fn free_summary_v8_wire_budget_and_descriptor_roundtrip() {
    let (tx, rx) = seqpacket_pair();
    let file = vmm_sys_util::tempfile::TempFile::new().unwrap();
    for budget in [1u64, protocol::MAX_FREE_SUMMARY_MICROS] {
        protocol::send_frame(
            &tx,
            MsgType::FreeSummary,
            budget,
            &budget.to_le_bytes(),
            &[file.as_file().as_raw_fd()],
        )
        .unwrap();
        let request = protocol::recv_frame(&rx).unwrap();
        assert_eq!(request.header.msg_type, 22);
        assert_eq!(request.fds.len(), 1);
        assert_eq!(
            protocol::parse_free_summary_budget(&request.body).unwrap(),
            budget
        );
        protocol::send_frame(
            &rx,
            MsgType::FreeSummaryDone,
            budget,
            &65u64.to_le_bytes(),
            &[],
        )
        .unwrap();
        let reply = protocol::recv_frame(&tx).unwrap();
        assert_eq!(reply.header.msg_type, 23);
        assert_eq!(reply.body, 65u64.to_le_bytes());
        assert!(reply.fds.is_empty());
    }
    for budget in [0u64, protocol::MAX_FREE_SUMMARY_MICROS + 1, u64::MAX] {
        assert!(matches!(
            protocol::parse_free_summary_budget(&budget.to_le_bytes()),
            Err(ChannelError::Malformed)
        ));
    }
    for len in [0, 7, 9, 16] {
        protocol::parse_free_summary_budget(&vec![1; len]).unwrap_err();
    }
}

/// A Firecracker started before its sandbox is known receives the drive images on the channel it
/// connected at startup, ahead of any drive configuration or handshake, and refuses an image its
/// slot's contract does not accept. Each case runs in a fresh process: installation happens once
/// per process and takes over the process's own drive slots.
#[test]
fn drives_frame_installs_images_before_the_handshake() {
    const CHILD: &str = "RAMET_DRIVES_FRAME_CASE";
    let Some(case) = std::env::var_os(CHILD) else {
        for case in ["sealed", "writable", "count"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "drives_frame_installs_images_before_the_handshake",
                ])
                .env(CHILD, case)
                .status()
                .unwrap();
            assert!(status.success(), "case {case}: {status}");
        }
        return;
    };
    for slot in [4, 5] {
        let null = std::fs::File::open("/dev/null").unwrap();
        assert_eq!(unsafe { libc::dup2(null.as_raw_fd(), slot) }, slot);
    }
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("pagemaster.sock");
    let listener = listen_seqpacket(&path);
    RametBackend::set_socket_path(path);
    RametBackend::connect().unwrap();
    let case = case.into_string().unwrap();
    let (root, count) = match case.as_str() {
        "sealed" => (sealed_root_image(), 1u32),
        "writable" => {
            let fd = unsafe { libc::memfd_create(c"root".as_ptr().cast(), 0) };
            assert_eq!(unsafe { libc::ftruncate(fd, 4096) }, 0);
            (unsafe { OwnedFd::from_raw_fd(fd) }, 1)
        }
        "count" => (sealed_root_image(), 2),
        _ => unreachable!(),
    };
    let root_inode = {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        assert_eq!(
            unsafe { libc::fstat(root.as_raw_fd(), stat.as_mut_ptr()) },
            0
        );
        unsafe { stat.assume_init() }.st_ino
    };
    let pm = thread::spawn(move || {
        let sock = accept(&listener);
        protocol::send_frame(
            &sock,
            MsgType::Drives,
            0,
            &count.to_le_bytes(),
            &[root.as_raw_fd()],
        )
        .unwrap();
        // A refusal is answered on the channel; an installation is not.
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        protocol::recv_frame(&sock).ok()
    });
    let result = RametBackend::ensure_drives();
    let reply = pm.join().unwrap();
    match case.as_str() {
        "sealed" => {
            result.unwrap();
            assert!(reply.is_none());
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            assert_eq!(unsafe { libc::fstat(4, stat.as_mut_ptr()) }, 0);
            assert_eq!(unsafe { stat.assume_init() }.st_ino, root_inode);
            // A sandbox without a disk keeps the read-only placeholder in the scratch slot.
            let flags = unsafe { libc::fcntl(5, libc::F_GETFL) };
            assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
            // Installation happens once.
            RametBackend::ensure_drives().unwrap();
        }
        "writable" => {
            assert!(matches!(result, Err(BackendError::Drives(_))), "{result:?}");
            let reply = reply.expect("a refusal is reported to pagemaster");
            assert_eq!(reply.header.msg_type, MsgType::Error as u16);
            assert_eq!(
                u32::from_le_bytes(reply.body[..4].try_into().unwrap()),
                ErrorCode::BadDrive as u32
            );
            assert!(!vmm::vstate::ramet::drives::installed());
        }
        "count" => {
            assert!(
                result.is_err(),
                "a count that disagrees with the rights was accepted"
            );
            assert!(!vmm::vstate::ramet::drives::installed());
        }
        _ => unreachable!(),
    }
}
