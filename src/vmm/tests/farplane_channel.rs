// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::tests_outside_test_module,
    clippy::undocumented_unsafe_blocks
)]

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::thread;

use vm_memory::GuestAddress;
use vmm::vstate::farplane::protocol::{
    self, Arch, BackendReadyRegion, ChannelError, ERROR_DETAIL_LEN, EXTENT_RECORD_LEN,
    ExtentRecord, HEADER_LEN, Header, MAGIC, MAX_DATAGRAM, MAX_EXTENTS, Mode, MsgType,
    READY_REGION_RECORD_LEN, REGION_RECORD_LEN, RegionRecord, VERSION,
};
use vmm::vstate::farplane::{BackendError, ErrorCode, FEATURE_IDENTITY, FarplaneBackend};
use vmm_sys_util::tempdir::TempDir;

/// The backend keeps its socket path and state in process-wide statics, so only one handshake may
/// be in flight at a time.
static HANDSHAKE: Mutex<()> = Mutex::new(());

fn handshake_lock() -> MutexGuard<'static, ()> {
    HANDSHAKE.lock().unwrap_or_else(|err| err.into_inner())
}

fn page_size() -> u64 {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 }
}

fn last_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

fn memfd(name: &str) -> RawFd {
    let name = CString::new(name).unwrap();
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            name.as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    } as RawFd;
    assert!(fd >= 0, "memfd_create: {}", last_error());
    fd
}

fn truncate(fd: RawFd, size: u64) {
    let ret = unsafe { libc::ftruncate(fd, size as libc::off_t) };
    assert_eq!(ret, 0, "ftruncate: {}", last_error());
}

fn add_seals(fd: RawFd, seals: libc::c_int) {
    let ret = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) };
    assert_eq!(ret, 0, "F_ADD_SEALS: {}", last_error());
}

fn pwrite_all(fd: RawFd, bytes: &[u8]) {
    let ret = unsafe { libc::pwrite(fd, bytes.as_ptr().cast(), bytes.len(), 0) };
    assert_eq!(ret, bytes.len() as isize, "pwrite: {}", last_error());
}

/// Reopens `fd` through procfs so the pagemaster hands out a descriptor whose access mode is
/// `O_RDONLY`, the way a real pagemaster does.
fn reopen_read_only(fd: RawFd) -> OwnedFd {
    let path = CString::new(format!("/proc/self/fd/{fd}")).unwrap();
    let ro = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(ro >= 0, "reopen read-only: {}", last_error());
    unsafe { OwnedFd::from_raw_fd(ro) }
}

fn close(fd: RawFd) {
    let ret = unsafe { libc::close(fd) };
    assert_eq!(ret, 0, "close: {}", last_error());
}

const BACKING_SEALS: libc::c_int =
    libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_FUTURE_WRITE;

/// A sealed, read-only backing memfd of `size` bytes filled with `fill`.
fn backing_memfd(size: u64, fill: u8) -> OwnedFd {
    let fd = memfd("farplane-backing");
    truncate(fd, size);
    pwrite_all(fd, &vec![fill; size as usize]);
    add_seals(fd, BACKING_SEALS);
    let ro = reopen_read_only(fd);
    close(fd);
    ro
}

fn encode_extent(record: ExtentRecord) -> [u8; EXTENT_RECORD_LEN] {
    let mut buf = [0u8; EXTENT_RECORD_LEN];
    buf[0..8].copy_from_slice(&record.guest_addr.to_le_bytes());
    buf[8..16].copy_from_slice(&record.len.to_le_bytes());
    buf[16..20].copy_from_slice(&record.fd_index.to_le_bytes());
    buf[20..24].copy_from_slice(&record.reserved.to_le_bytes());
    buf[24..32].copy_from_slice(&record.fd_offset.to_le_bytes());
    buf
}

fn extent_table_memfd(extents: &[ExtentRecord]) -> OwnedFd {
    let mut table = Vec::with_capacity(extents.len() * EXTENT_RECORD_LEN);
    for record in extents {
        table.extend_from_slice(&encode_extent(*record));
    }
    let fd = memfd("farplane-extents");
    truncate(fd, table.len() as u64);
    pwrite_all(fd, &table);
    add_seals(fd, BACKING_SEALS);
    let ro = reopen_read_only(fd);
    close(fd);
    ro
}

fn encode_backing_plan(
    pm_pid: u32,
    regions: &[RegionRecord],
    extent_count: u32,
    flags: u32,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + regions.len() * REGION_RECORD_LEN);
    body.extend_from_slice(&pm_pid.to_le_bytes());
    body.extend_from_slice(&(regions.len() as u32).to_le_bytes());
    body.extend_from_slice(&extent_count.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    for region in regions {
        body.extend_from_slice(&region.encode());
    }
    body
}

fn decode_error(body: &[u8]) -> (u32, u16) {
    assert_eq!(
        body.len(),
        8 + ERROR_DETAIL_LEN,
        "error body must be code+op+reserved+detail"
    );
    let code = u32::from_le_bytes(body[0..4].try_into().unwrap());
    let op = u16::from_le_bytes(body[4..6].try_into().unwrap());
    assert_eq!(
        u16::from_le_bytes(body[6..8].try_into().unwrap()),
        0,
        "error reserved field must be zero"
    );
    (code, op)
}

fn listen_seqpacket(path: &Path) -> OwnedFd {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    assert!(fd >= 0, "socket: {}", last_error());
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX as libc::sa_family_t,
        sun_path: [0; 108],
    };
    let bytes = path.as_os_str().as_encoded_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (i, byte) in bytes.iter().enumerate() {
        addr.sun_path[i] = *byte as libc::c_char;
    }
    let ret = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as u32,
        )
    };
    assert_eq!(ret, 0, "bind: {}", last_error());
    let ret = unsafe { libc::listen(fd, 1) };
    assert_eq!(ret, 0, "listen: {}", last_error());
    unsafe { OwnedFd::from_raw_fd(fd) }
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
    unsafe { UnixStream::from_raw_fd(fd) }
}

fn seqpacket_pair() -> (UnixStream, UnixStream) {
    let mut fds = [-1i32; 2];
    let ret = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    };
    assert_eq!(ret, 0, "socketpair: {}", last_error());
    unsafe {
        (
            UnixStream::from_raw_fd(fds[0]),
            UnixStream::from_raw_fd(fds[1]),
        )
    }
}

/// What a pagemaster offers to Firecracker in place of a well-formed plan.
struct Plan {
    regions: Vec<RegionRecord>,
    extents: Vec<ExtentRecord>,
    /// `extent_count` advertised in `backing_plan`, when it must differ from `extents.len()`.
    advertised_count: Option<u32>,
    backing: Vec<OwnedFd>,
}

/// Both halves of a rejection: what the guest-memory constructor returned, and the `error` frame
/// the pagemaster saw on the wire.
#[derive(Debug)]
struct Outcome {
    boot: Result<(), BackendError>,
    wire: Option<(u32, u16)>,
}

fn pagemaster(listener: OwnedFd, plan: Plan) -> Option<(u32, u16)> {
    let sock = accept(&listener);

    let hello = protocol::recv_frame(&sock).expect("hello");
    assert_eq!(hello.header.msg_type, MsgType::Hello as u16);
    assert_eq!(hello.header.request_id, 0, "hello is unsolicited");
    assert_eq!(
        &hello.body[16..48],
        &protocol::feature_identity_padded(),
        "hello must carry the feature identity"
    );

    let fds: Vec<RawFd> = plan.backing.iter().map(|fd| fd.as_raw_fd()).collect();
    protocol::send_frame(
        &sock,
        MsgType::PlanFds,
        1,
        &(fds.len() as u32).to_le_bytes(),
        &fds,
    )
    .expect("plan_fds");

    let table = extent_table_memfd(&plan.extents);
    let count = plan.advertised_count.unwrap_or(plan.extents.len() as u32);
    let body = encode_backing_plan(std::process::id(), &plan.regions, count, 0);
    protocol::send_frame(&sock, MsgType::BackingPlan, 2, &body, &[table.as_raw_fd()])
        .expect("backing_plan");

    match protocol::recv_frame(&sock) {
        Ok(frame) if frame.header.msg_type == MsgType::Error as u16 => {
            assert_eq!(frame.header.request_id, 2, "error echoes the request id");
            Some(decode_error(&frame.body))
        }
        _ => None,
    }
}

fn drive(plan: Plan) -> Outcome {
    let _guard = handshake_lock();
    let dir = TempDir::new().unwrap();
    let socket_path = dir.as_path().join("pagemaster.sock");
    let listener = listen_seqpacket(&socket_path);
    FarplaneBackend::set_socket_path(socket_path);

    let boot_regions: Vec<(GuestAddress, usize)> = plan
        .regions
        .iter()
        .map(|region| (GuestAddress(region.guest_addr), region.size as usize))
        .collect();

    let pm = thread::spawn(move || pagemaster(listener, plan));
    let boot = FarplaneBackend::construct_boot(&boot_regions).map(|_| ());
    let wire = pm.join().expect("pagemaster thread");
    Outcome { boot, wire }
}

#[track_caller]
fn assert_rejected(outcome: Outcome, expected: ErrorCode) {
    match outcome.boot {
        Err(BackendError::Plan(code)) => assert_eq!(
            code, expected,
            "plan rejected with the wrong code: {code:?}"
        ),
        other => panic!("plan must be rejected with {expected:?}, got {other:?}"),
    }
    assert_eq!(
        outcome.wire,
        Some((expected as u32, MsgType::BackingPlan as u16)),
        "pagemaster must be told {expected:?} on the wire"
    );
}

/// Two one-page regions tiled by one extent each, out of two distinct memfds.
fn canonical_plan() -> Plan {
    let page = page_size();
    Plan {
        regions: vec![
            RegionRecord {
                guest_addr: 0,
                size: page,
            },
            RegionRecord {
                guest_addr: 2 * page,
                size: page,
            },
        ],
        extents: vec![
            ExtentRecord {
                guest_addr: 0,
                len: page,
                fd_index: 0,
                reserved: 0,
                fd_offset: 0,
            },
            ExtentRecord {
                guest_addr: 2 * page,
                len: page,
                fd_index: 1,
                reserved: 0,
                fd_offset: 0,
            },
        ],
        advertised_count: None,
        backing: vec![backing_memfd(page, 0xa1), backing_memfd(page, 0xb2)],
    }
}

/// One two-page region tiled by `extents`, backed by a single two-page memfd.
fn single_region_plan(extents: Vec<ExtentRecord>) -> Plan {
    let page = page_size();
    Plan {
        regions: vec![RegionRecord {
            guest_addr: 0,
            size: 2 * page,
        }],
        extents,
        advertised_count: None,
        backing: vec![backing_memfd(2 * page, 0xc3)],
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

// ---------------------------------------------------------------------------
// Header framing
// ---------------------------------------------------------------------------

#[test]
fn header_round_trips_every_message_type() {
    let types = [
        MsgType::PlanFds,
        MsgType::BackingPlan,
        MsgType::CaptureBuffers,
        MsgType::Quiesce,
        MsgType::DirtySnapshot,
        MsgType::WriteVmstate,
        MsgType::DirtyUnion,
        MsgType::Resume,
        MsgType::Hello,
        MsgType::BackendReady,
        MsgType::Quiesced,
        MsgType::DirtySnapshotDone,
        MsgType::VmstateWritten,
        MsgType::UnionDone,
        MsgType::Resumed,
        MsgType::Error,
    ];
    for (index, msg_type) in types.into_iter().enumerate() {
        let request_id = index as u64 * 7;
        let header = Header::new(msg_type, request_id, index as u32 * 32, index as u32 % 3);
        let encoded = header.encode();
        assert_eq!(encoded.len(), HEADER_LEN);
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), MAGIC);
        assert_eq!(
            u16::from_le_bytes(encoded[4..6].try_into().unwrap()),
            VERSION
        );
        let decoded = Header::decode(&encoded).expect("header must decode");
        assert_eq!(decoded, header);
        assert_eq!(MsgType::from_u16(decoded.msg_type), Some(msg_type));
    }
}

#[test]
fn header_with_wrong_magic_is_rejected() {
    let mut encoded = Header::new(MsgType::Hello, 0, 0, 0).encode();
    encoded[0..4].copy_from_slice(&(MAGIC ^ 1).to_le_bytes());
    assert!(matches!(
        Header::decode(&encoded),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn header_with_wrong_version_is_rejected() {
    let mut encoded = Header::new(MsgType::Hello, 0, 0, 0).encode();
    encoded[4..6].copy_from_slice(&(VERSION + 1).to_le_bytes());
    assert!(matches!(
        Header::decode(&encoded),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn header_with_nonzero_reserved_is_rejected() {
    let mut encoded = Header::new(MsgType::Hello, 0, 0, 0).encode();
    encoded[24..32].copy_from_slice(&1u64.to_le_bytes());
    assert!(matches!(
        Header::decode(&encoded),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn body_len_inconsistent_with_the_datagram_is_rejected() {
    let (tx, rx) = seqpacket_pair();
    let body = [0u8; 16];
    let mut frame = Header::new(MsgType::Quiesced, 9, body.len() as u32 + 1, 0)
        .encode()
        .to_vec();
    frame.extend_from_slice(&body);
    let sent = unsafe { libc::send(tx.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    assert_eq!(sent, frame.len() as isize, "send: {}", last_error());

    assert!(matches!(
        protocol::recv_frame(&rx),
        Err(ChannelError::Malformed)
    ));
}

// ---------------------------------------------------------------------------
// Canonical plan matrix
// ---------------------------------------------------------------------------

#[test]
fn canonical_plan_survives_plan_validation() {
    let outcome = drive(canonical_plan());
    match outcome.boot {
        // fd 3 of a test binary is not the jailer-created userfaultfd, so the handshake can only
        // get as far as adopting it. Anything earlier means the plan itself was refused.
        Err(BackendError::Uffd(_)) => {}
        other => panic!("canonical plan must pass validation, got {other:?}"),
    }
    assert_eq!(
        outcome.wire,
        Some((
            ErrorCode::UffdRegisterFailed as u32,
            MsgType::BackingPlan as u16
        ))
    );
}

#[test]
fn uncoalesced_adjacent_extents_are_not_canonical() {
    let page = page_size();
    let outcome = drive(single_region_plan(vec![
        extent(0, page, 0, 0),
        extent(page, page, 0, page),
    ]));
    assert_rejected(outcome, ErrorCode::PlanNotCanonical);
}

#[test]
fn unsorted_extents_are_not_canonical() {
    let page = page_size();
    let outcome = drive(single_region_plan(vec![
        extent(page, page, 0, page),
        extent(0, page, 0, 0),
    ]));
    assert_rejected(outcome, ErrorCode::PlanNotCanonical);
}

#[test]
fn a_gap_between_extents_is_not_canonical() {
    let page = page_size();
    let mut plan = single_region_plan(vec![extent(0, page, 0, 0), extent(2 * page, page, 0, 0)]);
    plan.regions[0].size = 3 * page;
    plan.backing = vec![backing_memfd(3 * page, 0xc3)];
    assert_rejected(drive(plan), ErrorCode::PlanNotCanonical);
}

#[test]
fn overlapping_extents_are_not_canonical() {
    let page = page_size();
    let mut plan = single_region_plan(vec![
        extent(0, 2 * page, 0, 0),
        extent(page, 2 * page, 0, 0),
    ]);
    plan.regions[0].size = 3 * page;
    plan.backing = vec![backing_memfd(3 * page, 0xc3)];
    assert_rejected(drive(plan), ErrorCode::PlanNotCanonical);
}

#[test]
fn an_extent_crossing_a_region_boundary_is_a_bad_extent() {
    let page = page_size();
    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 0)]);
    // The same two pages, split into two regions: no single extent may span both.
    plan.regions = vec![
        RegionRecord {
            guest_addr: 0,
            size: page,
        },
        RegionRecord {
            guest_addr: page,
            size: page,
        },
    ];
    assert_rejected(drive(plan), ErrorCode::BadExtent);
}

#[test]
fn an_extent_with_a_nonzero_reserved_field_is_a_bad_extent() {
    let page = page_size();
    let mut record = extent(0, 2 * page, 0, 0);
    record.reserved = 1;
    assert_rejected(
        drive(single_region_plan(vec![record])),
        ErrorCode::BadExtent,
    );
}

#[test]
fn a_misaligned_extent_address_is_a_bad_extent() {
    let page = page_size();
    assert_rejected(
        drive(single_region_plan(vec![extent(8, 2 * page, 0, 0)])),
        ErrorCode::BadExtent,
    );
}

#[test]
fn a_misaligned_extent_length_is_a_bad_extent() {
    let page = page_size();
    assert_rejected(
        drive(single_region_plan(vec![extent(0, 2 * page - 8, 0, 0)])),
        ErrorCode::BadExtent,
    );
}

#[test]
fn a_misaligned_extent_offset_is_a_bad_extent() {
    let page = page_size();
    assert_rejected(
        drive(single_region_plan(vec![extent(0, 2 * page, 0, 8)])),
        ErrorCode::BadExtent,
    );
}

#[test]
fn an_extent_reaching_past_the_end_of_its_memfd_is_a_bad_extent() {
    let page = page_size();
    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 2 * page)]);
    // The memfd holds exactly two pages, so offset 2*page + length 2*page has no backing bytes.
    plan.backing = vec![backing_memfd(2 * page, 0xe5)];
    assert_rejected(drive(plan), ErrorCode::BadExtent);
}

#[test]
fn an_out_of_range_fd_index_is_a_bad_extent() {
    let page = page_size();
    assert_rejected(
        drive(single_region_plan(vec![extent(0, 2 * page, 1, 0)])),
        ErrorCode::BadExtent,
    );
}

#[test]
fn an_extent_count_above_the_cap_is_rejected() {
    let page = page_size();
    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 0)]);
    plan.advertised_count = Some(MAX_EXTENTS + 1);
    assert_rejected(drive(plan), ErrorCode::TooManyExtents);
}

#[test]
fn extents_that_do_not_tile_every_region_are_not_canonical() {
    let page = page_size();
    // The region is two pages wide; the plan only tiles the first page of it.
    assert_rejected(
        drive(single_region_plan(vec![extent(0, page, 0, 0)])),
        ErrorCode::PlanNotCanonical,
    );
}

// ---------------------------------------------------------------------------
// Backing descriptor preconditions
// ---------------------------------------------------------------------------

#[test]
fn a_backing_memfd_without_the_future_write_seal_is_rejected() {
    let page = page_size();
    let fd = memfd("farplane-unsealed");
    truncate(fd, 2 * page);
    add_seals(fd, libc::F_SEAL_GROW | libc::F_SEAL_SHRINK);
    let ro = reopen_read_only(fd);
    close(fd);

    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 0)]);
    plan.backing = vec![ro];
    assert_rejected(drive(plan), ErrorCode::FdNotSealed);
}

#[test]
fn a_backing_memfd_opened_read_write_is_rejected() {
    let page = page_size();
    let fd = memfd("farplane-writable");
    truncate(fd, 2 * page);
    add_seals(fd, BACKING_SEALS);

    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 0)]);
    // memfd_create hands back an O_RDWR description; a pagemaster must not pass it on.
    plan.backing = vec![unsafe { OwnedFd::from_raw_fd(fd) }];
    assert_rejected(drive(plan), ErrorCode::FdWritable);
}

#[test]
fn a_backing_descriptor_that_is_not_a_memfd_is_rejected() {
    let page = page_size();
    let dir = TempDir::new().unwrap();
    let path = dir.as_path().join("backing.bin");
    std::fs::write(&path, vec![0u8; 2 * page as usize]).unwrap();
    let file = std::fs::File::open(&path).unwrap();

    let mut plan = single_region_plan(vec![extent(0, 2 * page, 0, 0)]);
    plan.backing = vec![OwnedFd::from(file)];
    assert_rejected(drive(plan), ErrorCode::FdNotMemfd);
}

// ---------------------------------------------------------------------------
// Datagram framing over a real SEQPACKET pair
// ---------------------------------------------------------------------------

#[test]
fn a_full_conversation_round_trips_bodies_and_descriptors() {
    let page = page_size();
    let (fc, pm) = seqpacket_pair();

    // Firecracker -> pagemaster: hello.
    let regions = [
        RegionRecord {
            guest_addr: 0,
            size: page,
        },
        RegionRecord {
            guest_addr: 4 * page,
            size: 2 * page,
        },
    ];
    let hello = protocol::encode_hello(4242, page as u32, Arch::X86_64, Mode::Boot, &regions);
    protocol::send_frame(&fc, MsgType::Hello, 0, &hello, &[]).unwrap();
    let got = protocol::recv_frame(&pm).unwrap();
    assert_eq!(got.header.msg_type, MsgType::Hello as u16);
    assert_eq!(got.header.body_len as usize, got.body.len());
    assert_eq!(u32::from_le_bytes(got.body[0..4].try_into().unwrap()), 4242);
    assert_eq!(
        u32::from_le_bytes(got.body[4..8].try_into().unwrap()),
        page as u32
    );
    assert_eq!(
        u16::from_le_bytes(got.body[8..10].try_into().unwrap()),
        Arch::X86_64 as u16
    );
    assert_eq!(
        u16::from_le_bytes(got.body[10..12].try_into().unwrap()),
        Mode::Boot as u16
    );
    assert_eq!(u32::from_le_bytes(got.body[12..16].try_into().unwrap()), 2);
    let mut identity = [0u8; 32];
    identity[..FEATURE_IDENTITY.len()].copy_from_slice(FEATURE_IDENTITY.as_bytes());
    assert_eq!(&got.body[16..48], &identity);
    assert_eq!(RegionRecord::decode(&got.body[48..64]).unwrap(), regions[0]);
    assert_eq!(RegionRecord::decode(&got.body[64..80]).unwrap(), regions[1]);

    // Pagemaster -> Firecracker: plan_fds carrying two backing memfds.
    let first = backing_memfd(page, 0x11);
    let second = backing_memfd(page, 0x22);
    protocol::send_frame(
        &pm,
        MsgType::PlanFds,
        1,
        &2u32.to_le_bytes(),
        &[first.as_raw_fd(), second.as_raw_fd()],
    )
    .unwrap();
    let got = protocol::recv_frame(&fc).unwrap();
    assert_eq!(protocol::parse_u32(&got.body).unwrap(), 2);
    assert_eq!(got.fds.len(), 2, "SCM_RIGHTS must deliver both descriptors");
    assert_eq!(first_byte(&got.fds[0]), 0x11);
    assert_eq!(first_byte(&got.fds[1]), 0x22);

    // Pagemaster -> Firecracker: backing_plan plus the extent table.
    let extents = [extent(0, page, 0, 0), extent(4 * page, 2 * page, 1, 0)];
    let table = extent_table_memfd(&extents);
    let body = encode_backing_plan(std::process::id(), &regions, extents.len() as u32, 0);
    protocol::send_frame(&pm, MsgType::BackingPlan, 2, &body, &[table.as_raw_fd()]).unwrap();
    let got = protocol::recv_frame(&fc).unwrap();
    let parsed = protocol::parse_backing_plan(&got.body).unwrap();
    assert_eq!(parsed.pm_pid, std::process::id());
    assert_eq!(parsed.extent_count, 2);
    assert_eq!(parsed.regions, regions);
    assert_eq!(got.fds.len(), 1);
    let mut raw = [0u8; EXTENT_RECORD_LEN];
    let read = unsafe {
        libc::pread(
            got.fds[0].as_raw_fd(),
            raw.as_mut_ptr().cast(),
            raw.len(),
            0,
        )
    };
    assert_eq!(read, raw.len() as isize);
    assert_eq!(ExtentRecord::decode(&raw).unwrap(), extents[0]);

    // Firecracker -> pagemaster: backend_ready plus the userfaultfd duplicate.
    let ready_regions = [BackendReadyRegion {
        guest_addr: 0,
        size: page,
        host_base: 0x7f00_0000_0000,
    }];
    let ready = protocol::encode_backend_ready(&ready_regions, 1, 0b11, 8, 16 * 1024 * 1024);
    let handed_over = backing_memfd(page, 0x33);
    protocol::send_frame(
        &fc,
        MsgType::BackendReady,
        0,
        &ready,
        &[handed_over.as_raw_fd()],
    )
    .unwrap();
    let got = protocol::recv_frame(&pm).unwrap();
    assert_eq!(got.header.msg_type, MsgType::BackendReady as u16);
    assert_eq!(
        got.fds.len(),
        1,
        "the uffd duplicate must cross the channel"
    );
    assert_eq!(
        first_byte(&got.fds[0]),
        0x33,
        "the received descriptor must name the same object"
    );
    assert_eq!(
        u32::from_le_bytes(got.body[0..4].try_into().unwrap()),
        1,
        "the region count leads the body"
    );
    let tail = 4 + READY_REGION_RECORD_LEN;
    assert_eq!(
        u64::from_le_bytes(got.body[tail + 4..tail + 12].try_into().unwrap()),
        0b11
    );
    assert_eq!(
        u64::from_le_bytes(got.body[tail + 12..tail + 20].try_into().unwrap()),
        8
    );

    // The capture cycle: every request carries a nonzero id and every reply echoes it.
    let cycle = [
        (
            MsgType::Quiesce,
            MsgType::Quiesced,
            2u32.to_le_bytes().to_vec(),
        ),
        (
            MsgType::DirtySnapshot,
            MsgType::DirtySnapshotDone,
            Vec::new(),
        ),
        (
            MsgType::WriteVmstate,
            MsgType::VmstateWritten,
            4096u64.to_le_bytes().to_vec(),
        ),
        (MsgType::DirtyUnion, MsgType::UnionDone, Vec::new()),
        (
            MsgType::Resume,
            MsgType::Resumed,
            2u32.to_le_bytes().to_vec(),
        ),
    ];
    for (index, (request, reply, reply_body)) in cycle.into_iter().enumerate() {
        let request_id = index as u64 + 3;
        let request_body = if request == MsgType::Resume {
            2u32.to_le_bytes().to_vec()
        } else {
            Vec::new()
        };
        protocol::send_frame(&pm, request, request_id, &request_body, &[]).unwrap();
        let got = protocol::recv_frame(&fc).unwrap();
        assert_eq!(got.header.msg_type, request as u16);
        assert_eq!(got.header.request_id, request_id);
        if request == MsgType::Resume {
            assert_eq!(protocol::parse_u32(&got.body).unwrap(), 2);
        }

        protocol::send_frame(&fc, reply, request_id, &reply_body, &[]).unwrap();
        let got = protocol::recv_frame(&pm).unwrap();
        assert_eq!(got.header.msg_type, reply as u16);
        assert_eq!(
            got.header.request_id, request_id,
            "reply must echo the request id"
        );
        assert_eq!(got.body, reply_body);
    }
}

fn first_byte(fd: &OwnedFd) -> u8 {
    let mut byte = [0u8; 1];
    let read = unsafe { libc::pread(fd.as_raw_fd(), byte.as_mut_ptr().cast(), 1, 0) };
    assert_eq!(read, 1, "pread: {}", last_error());
    byte[0]
}

#[test]
fn a_datagram_larger_than_the_maximum_is_refused() {
    let (fc, _pm) = seqpacket_pair();
    let biggest = vec![0u8; MAX_DATAGRAM - HEADER_LEN];
    protocol::send_frame(&fc, MsgType::Quiesced, 1, &biggest, &[])
        .expect("a datagram of exactly MAX_DATAGRAM bytes is legal");

    let too_big = vec![0u8; MAX_DATAGRAM - HEADER_LEN + 1];
    assert!(matches!(
        protocol::send_frame(&fc, MsgType::Quiesced, 2, &too_big, &[],),
        Err(ChannelError::Malformed)
    ));
}

#[test]
fn an_oversized_datagram_arriving_truncated_is_rejected() {
    let (tx, rx) = seqpacket_pair();
    let body_len = MAX_DATAGRAM + 4096 - HEADER_LEN;
    let mut frame = Header::new(MsgType::Quiesced, 5, body_len as u32, 0)
        .encode()
        .to_vec();
    frame.resize(HEADER_LEN + body_len, 0);
    // Bypass send_frame: only a peer that ignores the channel limits can produce this.
    let sent = unsafe { libc::send(tx.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    assert_eq!(
        sent,
        frame.len() as isize,
        "the oversized datagram must reach the socket: {}",
        last_error()
    );

    assert!(matches!(
        protocol::recv_frame(&rx),
        Err(ChannelError::Malformed | ChannelError::Truncated)
    ));
}
