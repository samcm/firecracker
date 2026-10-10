// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::os::fd::{BorrowedFd, FromRawFd};

use vmm_sys_util::tempfile::TempFile;

use super::*;


fn memfd(name: &std::ffi::CStr, size: u64) -> OwnedFd {
    // SAFETY: name is NUL terminated and outlives the call.
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0);
    // SAFETY: this newly created descriptor has no other owner.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: this test owns the memfd and may resize it.
    assert_eq!(unsafe { libc::ftruncate(fd, size.cast_signed()) }, 0);
    owned
}

fn command(msg: MsgType) -> CommandKey {
    CommandKey::of(msg, &[], &[])
}

#[test]
fn the_vmstate_writer_stops_at_the_advertised_capacity() {
    let mut file = TempFile::new().unwrap().into_file();
    let mut writer = BoundedWriter {
        inner: &mut file,
        remaining: 8,
    };
    assert_eq!(writer.write(&[0; 6]).unwrap(), 6);
    assert_eq!(
        writer.write(&[0; 4]).unwrap_err().raw_os_error(),
        Some(libc::EFBIG)
    );
    assert_eq!(writer.write(&[0; 2]).unwrap(), 2);
    assert_eq!(writer.remaining, 0);
}

#[test]
fn a_vmstate_over_the_capacity_names_efbig_in_the_reply() {
    let mut file = TempFile::new().unwrap().into_file();
    let refusal = serialize_vmstate_within(&mut file, MicrovmState::default(), 8).unwrap_err();
    assert_eq!(refusal.code, ErrorCode::VmstateWriteFailed);
    let efbig = io::Error::from_raw_os_error(libc::EFBIG).to_string();
    assert!(
        refusal.detail.starts_with("vmstate save: "),
        "{}",
        refusal.detail
    );
    assert!(refusal.detail.contains(&efbig), "{}", refusal.detail);
    // The detail travels in the error reply's fixed field, as the client decodes it.
    let mut order = EpochOrder::default();
    let refused = serve_write_vmstate(&mut order, || {
        serialize_vmstate_within(&mut file, MicrovmState::default(), 8)?;
        unreachable!("serialization failed")
    })
    .unwrap_err();
    let body = protocol::encode_error(refused.code, MsgType::WriteVmstate, &refused.detail);
    let detail = &body[8..8 + protocol::ERROR_DETAIL_LEN];
    let text = std::str::from_utf8(detail).unwrap().trim_end_matches('\0');
    assert_eq!(text, refusal.detail);
    // The default state fits the real capacity.
    assert!(serialize_vmstate(&mut file, MicrovmState::default()).unwrap() > 8);
}

#[test]
fn a_long_refusal_is_cut_to_the_detail_field_on_a_character_boundary() {
    let refusal = VmstateRefusal::failed("memory version", "é".repeat(100));
    assert!(refusal.detail.len() <= protocol::ERROR_DETAIL_LEN);
    assert!(refusal.detail.len() > protocol::ERROR_DETAIL_LEN - 2);
    assert!(refusal.detail.starts_with("memory version: é"));
}

#[test]
fn a_free_summary_reply_carries_its_tracked_sample_or_no_count() {
    let body = encode_free_summary_done(0x0102, 0x0304, 0x0506);
    assert_eq!(body.len(), 24);
    assert_eq!(body[..8], 0x0102u64.to_le_bytes());
    assert_eq!(body[8..16], 0x0304u64.to_le_bytes());
    assert_eq!(body[16..], 0x0506u64.to_le_bytes());
    // No count is u64::MAX with no standing version, never a zero a reader could mistake for a
    // small capture.
    let (included, standing_id) = NO_TRACKED_SAMPLE;
    let body = encode_free_summary_done(7, included, standing_id);
    assert_eq!(body[8..16], [0xff; 8]);
    assert_eq!(body[16..], [0; 8]);
    assert_eq!(body[..8], 7u64.to_le_bytes());
}

#[test]
fn a_tracked_sample_is_the_kernels_timely_count_or_no_count() {
    let regions = [protocol::RegionRecord {
        guest_addr: 0,
        size: 128 * 4096,
    }];
    // Runs at pages 0..3 and 64..66 of the summary's words.
    let summary = vec![vec![0b111, 0b11]];
    let device = memfd(c"device", 0);
    let later = Instant::now() + Duration::from_secs(60);
    let tracked = |included| {
        Ok(Some((
            memversion::TrackInfo {
                tracked: 1,
                standing_id: 9,
                ..Default::default()
            },
            included,
        )))
    };
    // The kernel counts against exactly the summary's runs.
    let sample = sample_tracked(
        Some(device.as_fd()),
        &regions,
        &summary,
        later,
        |_, runs| {
            assert_eq!(
                runs.iter().map(|x| (x.offset, x.len)).collect::<Vec<_>>(),
                [(0, 3 * 4096), (64 * 4096, 2 * 4096)]
            );
            tracked(41)
        },
    );
    assert_eq!(sample, (41, 9));
    // Untracked: no count, and the kernel is never asked.
    let never = |_: BorrowedFd<'_>, _: &[memversion::Exclusion]| -> io::Result<_> {
        panic!("asked the kernel")
    };
    assert_eq!(
        sample_tracked(None, &regions, &summary, later, never),
        NO_TRACKED_SAMPLE
    );
    // A deadline already gone: no count, and the kernel is never asked.
    assert_eq!(
        sample_tracked(
            Some(device.as_fd()),
            &regions,
            &summary,
            Instant::now(),
            never
        ),
        NO_TRACKED_SAMPLE
    );
    // A count that arrives after the deadline is not reported.
    let soon = Instant::now() + Duration::from_millis(20);
    let late = sample_tracked(Some(device.as_fd()), &regions, &summary, soon, |_, _| {
        std::thread::sleep(Duration::from_millis(40));
        tracked(41)
    });
    assert_eq!(late, NO_TRACKED_SAMPLE);
    // ENOTTY (older kernel), an error, an untracked answer or no standing version: no count.
    for answer in [
        Ok(None),
        Err(io::Error::from_raw_os_error(libc::EINVAL)),
        Ok(Some((memversion::TrackInfo::default(), 5))),
        Ok(Some((
            memversion::TrackInfo {
                tracked: 1,
                ..Default::default()
            },
            5,
        ))),
    ] {
        assert_eq!(
            sample_tracked(Some(device.as_fd()), &regions, &summary, later, |_, _| {
                answer
            }),
            NO_TRACKED_SAMPLE
        );
    }
    // A summary that does not fit the geometry: no count.
    assert_eq!(
        sample_tracked(Some(device.as_fd()), &regions, &[vec![0]], later, never),
        NO_TRACKED_SAMPLE
    );
}

#[test]
fn serialization_and_create_run_once_per_epoch() {
    let mut order = EpochOrder::default();
    let runs = std::cell::Cell::new(0);
    let capture = || {
        runs.set(runs.get() + 1);
        Ok((9001, memfd(c"version", 0)))
    };
    let first = serve_write_vmstate(&mut order, capture).unwrap();
    let second = serve_write_vmstate(&mut order, capture).unwrap();
    assert_eq!(second.0, 9001);
    assert!(Arc::ptr_eq(&first.1, &second.1));
    assert_eq!(runs.get(), 1);
    order.open();
    let third = serve_write_vmstate(&mut order, capture).unwrap();
    assert!(!Arc::ptr_eq(&first.1, &third.1));
    assert_eq!(runs.get(), 2);
}

#[test]
fn exact_id_retains_version_across_epoch_reset() {
    let device = memfd(c"device", 0);
    let key = CommandKey::of(MsgType::WriteVmstate, &[], std::slice::from_ref(&device));
    let mut order = EpochOrder::default();
    let (bytes, version) =
        serve_write_vmstate(&mut order, || Ok((123, memfd(c"version", 0)))).unwrap();
    let mut replies = ReplyCache::default();
    replies.record(
        1,
        key.clone(),
        MsgType::VmstateWritten,
        bytes.to_le_bytes().to_vec(),
        Some(version.clone()),
    );
    order.open();
    serve_write_vmstate(&mut order, || Ok((456, memfd(c"next-version", 0)))).unwrap();
    let FrameDisposition::Replay(msg, body, Some(retained)) = replies.disposition(1, &key) else {
        panic!("not replayed")
    };
    assert_eq!(msg, MsgType::VmstateWritten);
    assert_eq!(body, 123u64.to_le_bytes());
    assert!(Arc::ptr_eq(&version, &retained));
    let (sock, peer) = UnixStream::pair().unwrap();
    send_reply(&sock, msg, 1, &body, Some(&retained)).unwrap();
    let received = protocol::recv_frame(&peer).unwrap();
    assert_eq!(received.fds.len(), 1);
    assert_eq!(
        descriptor_identity(received.fds[0].as_raw_fd()),
        descriptor_identity(version.as_raw_fd())
    );
}

#[test]
fn next_request_releases_answered_versions_and_a_late_retry_is_refused() {
    let device = memfd(c"device", 0);
    let key = CommandKey::of(MsgType::WriteVmstate, &[], std::slice::from_ref(&device));
    let plain = CommandKey::of(MsgType::Resume, &1u32.to_le_bytes(), &[]);
    let version = Arc::new(memfd(c"version", 0));
    let mut replies = ReplyCache::default();
    replies.record(
        1,
        key.clone(),
        MsgType::VmstateWritten,
        vec![7],
        Some(version.clone()),
    );
    // Until a newer request arrives, the answer and its version replay exactly.
    assert_eq!(Arc::strong_count(&version), 2);
    assert!(matches!(
        replies.disposition(1, &key),
        FrameDisposition::Replay(MsgType::VmstateWritten, _, Some(_))
    ));
    // A new request acknowledges every earlier answer: the cache lets the version go...
    assert!(matches!(
        replies.disposition(3, &plain),
        FrameDisposition::Serve
    ));
    replies.acknowledge_before(3);
    assert_eq!(Arc::strong_count(&version), 1);
    // ...so a retry of it is refused with a typed error, never replayed without its fd.
    assert!(matches!(
        replies.disposition(1, &key),
        FrameDisposition::ReplayUnavailable
    ));
    replies.record(2, plain.clone(), MsgType::Resumed, vec![], None);
    // An answer that carried no version still replays, and a reused id is still refused.
    assert!(matches!(
        replies.disposition(2, &plain),
        FrameDisposition::Replay(MsgType::Resumed, _, None)
    ));
    assert!(matches!(
        replies.disposition(1, &plain),
        FrameDisposition::Reused
    ));
    // Only answers older than the new request are released.
    let later = Arc::new(memfd(c"later", 0));
    replies.record(
        4,
        key.clone(),
        MsgType::VmstateWritten,
        vec![8],
        Some(later.clone()),
    );
    replies.acknowledge_before(4);
    assert_eq!(Arc::strong_count(&later), 2);
}

#[test]
fn failed_create_publishes_nothing_exact_failure_replays_new_id_retries() {
    let mut order = EpochOrder::default();
    let device = memfd(c"not-a-memversion-device", 0);
    let regions = [memversion::Region {
        addr: memversion::GUEST_RAM_BASE,
        len: 4096,
    }];
    assert!(matches!(
        serve_write_vmstate(&mut order, || {
            let version = memversion::create(device.as_fd(), &regions, &[])
                .map_err(|err| VmstateRefusal::failed("memory version", err))?;
            Ok((64, version))
        }),
        Err(VmstateRefusal {
            code: ErrorCode::VmstateWriteFailed,
            ..
        })
    ));
    assert!(order.result.is_none());
    let mut replies = ReplyCache::default();
    let body = protocol::encode_error(ErrorCode::VmstateWriteFailed, MsgType::WriteVmstate, "");
    let (sock, peer) = UnixStream::pair().unwrap();
    let key = CommandKey::of(MsgType::WriteVmstate, &[], std::slice::from_ref(&device));
    let mut pending = Some((1, key.clone()));
    send_and_record(
        &sock,
        &mut replies,
        &mut pending,
        1,
        MsgType::Error,
        body.clone(),
        None,
    )
    .unwrap();
    assert!(protocol::recv_frame(&peer).unwrap().fds.is_empty());
    assert!(
        matches!(replies.disposition(1, &key), FrameDisposition::Replay(MsgType::Error, cached, None) if cached == body)
    );
    assert!(matches!(
        replies.disposition(2, &key),
        FrameDisposition::Serve
    ));
    serve_write_vmstate(&mut order, || Ok((64, memfd(c"retry", 0)))).unwrap();
}

#[test]
fn an_answer_whose_send_failed_retains_reply_and_fd() {
    let (sock, peer) = UnixStream::pair().unwrap();
    drop(peer);
    let mut replies = ReplyCache::default();
    let key = command(MsgType::WriteVmstate);
    let mut pending = Some((5, key.clone()));
    let version = Arc::new(memfd(c"version", 0));
    let weak = Arc::downgrade(&version);
    assert!(
        send_and_record(
            &sock,
            &mut replies,
            &mut pending,
            5,
            MsgType::VmstateWritten,
            7u64.to_le_bytes().to_vec(),
            Some(version)
        )
        .is_err()
    );
    assert!(pending.is_none());
    let FrameDisposition::Replay(MsgType::VmstateWritten, body, Some(retained)) =
        replies.disposition(5, &key)
    else {
        panic!("not retained")
    };
    assert_eq!(body, 7u64.to_le_bytes());
    assert!(Arc::ptr_eq(&retained, &weak.upgrade().unwrap()));
}

#[test]
fn a_newer_answer_releases_an_older_version_and_refuses_its_id() {
    let mut replies = ReplyCache::default();
    let version = Arc::new(memfd(c"version", 0));
    let weak = Arc::downgrade(&version);
    replies.record(
        1,
        command(MsgType::WriteVmstate),
        MsgType::VmstateWritten,
        vec![],
        Some(version),
    );
    // The same request again still finds its version.
    assert!(matches!(
        replies.disposition(1, &command(MsgType::WriteVmstate)),
        FrameDisposition::Replay(_, _, Some(_))
    ));
    replies.record(
        2,
        command(MsgType::Resume),
        MsgType::Resumed,
        vec![],
        None,
    );
    assert!(weak.upgrade().is_none(), "an answered version outlived the next request");
    assert!(matches!(
        replies.disposition(1, &command(MsgType::WriteVmstate)),
        FrameDisposition::ReplayUnavailable
    ));
    assert!(matches!(
        replies.disposition(2, &command(MsgType::Resume)),
        FrameDisposition::Replay(MsgType::Resumed, _, None)
    ));
}

#[test]
fn eviction_drops_ownership_and_refuses_old_id() {
    let mut replies = ReplyCache::default();
    let version = Arc::new(memfd(c"version", 0));
    let weak = Arc::downgrade(&version);
    replies.record(
        1,
        command(MsgType::WriteVmstate),
        MsgType::VmstateWritten,
        vec![],
        Some(version),
    );
    for id in 2..=protocol::MAX_RETRYABLE_REQUESTS as u64 + 1 {
        replies.record(
            id,
            command(MsgType::Quiesce),
            MsgType::Quiesced,
            vec![],
            None,
        );
    }
    assert!(weak.upgrade().is_none());
    assert_eq!(replies.answers.len(), protocol::MAX_RETRYABLE_REQUESTS);
    assert!(matches!(
        replies.disposition(1, &command(MsgType::WriteVmstate)),
        FrameDisposition::Reused
    ));
    assert!(matches!(
        replies.disposition(9999, &command(MsgType::Quiesce)),
        FrameDisposition::Serve
    ));
}

#[test]
fn exact_command_checks_descriptor_identity_order_message_and_body() {
    let vmstate = memfd(c"vmstate", 8192);
    let disk = memfd(c"disk", 0);
    let key = CommandKey::of(
        MsgType::CaptureBuffers,
        &[],
        &[vmstate.try_clone().unwrap(), disk.try_clone().unwrap()],
    );
    let mut replies = ReplyCache::default();
    replies.record(3, key.clone(), MsgType::CaptureBuffersArmed, vec![], None);
    let retry = CommandKey::of(
        MsgType::CaptureBuffers,
        &[],
        &[vmstate.try_clone().unwrap(), disk.try_clone().unwrap()],
    );
    assert!(matches!(
        replies.disposition(3, &retry),
        FrameDisposition::Replay(MsgType::CaptureBuffersArmed, _, None)
    ));
    for other in [
        CommandKey::of(
            MsgType::CaptureBuffers,
            &[],
            &[disk.try_clone().unwrap(), vmstate.try_clone().unwrap()],
        ),
        CommandKey::of(
            MsgType::CaptureBuffers,
            &[],
            &[memfd(c"other", 8192), disk.try_clone().unwrap()],
        ),
        CommandKey {
            msg: MsgType::Quiesce,
            ..key.clone()
        },
        CommandKey {
            body: vec![1],
            ..key.clone()
        },
        CommandKey {
            descriptors: None,
            ..key.clone()
        },
    ] {
        assert!(matches!(
            replies.disposition(3, &other),
            FrameDisposition::Reused
        ));
    }
    let unprovable = CommandKey {
        descriptors: None,
        ..key
    };
    assert!(!unprovable.is_exactly(&unprovable));
}

#[test]
fn descriptor_counts_and_bodies_match_v8() {
    for (msg, len, counts) in [
        (MsgType::CaptureBuffers, 0, vec![1, 2]),
        (MsgType::WriteVmstate, 0, vec![1]),
        (MsgType::Quiesce, 0, vec![0]),
        (MsgType::Resume, 4, vec![0]),
        (MsgType::FreeSummary, 8, vec![1]),
    ] {
        for count in 0..=4 {
            assert_eq!(
                validate_command(msg, len, count).is_ok(),
                counts.contains(&count)
            );
        }
        assert!(validate_command(msg, len + 1, counts[0]).is_err());
    }
    assert!(validate_command(MsgType::VmstateWritten, 8, 1).is_err());
}

#[test]
fn a_frames_descriptors_are_closed_when_it_is_not_served() {
    let fd = memfd(c"device", 0);
    let incoming = Incoming {
        header: protocol::Header::new(MsgType::WriteVmstate, 11, 0, 1),
        body: vec![],
        fds: vec![fd],
    };
    let raw = incoming.fds[0].as_raw_fd();
    drop(incoming);
    // SAFETY: F_GETFD only reads descriptor flags; it is expected to fail after close.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}

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

#[test]
fn a_clone_destination_must_be_a_regular_file_opened_read_write() {
    let regular = TempFile::new().unwrap();
    assert_eq!(
        validate_clone_destination(regular.as_file().as_raw_fd()),
        Ok(())
    );
    let read_only = File::open(regular.as_path()).unwrap();
    assert_eq!(
        validate_clone_destination(read_only.as_raw_fd()),
        Err(ErrorCode::BadCloneDestination)
    );
    // SAFETY: the literal is NUL terminated; the returned descriptor is owned below.
    let fd = unsafe { libc::open(c"/".as_ptr(), libc::O_PATH) };
    assert!(fd >= 0);
    // SAFETY: this newly opened fd has no other owner.
    let path = unsafe { OwnedFd::from_raw_fd(fd) };
    assert_eq!(
        validate_clone_destination(path.as_raw_fd()),
        Err(ErrorCode::BadCloneDestination)
    );
    let device = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert_eq!(
        validate_clone_destination(device.as_raw_fd()),
        Err(ErrorCode::BadCloneDestination)
    );
}

#[test]
fn a_clone_the_kernel_refuses_is_reported_as_a_failure() {
    let destination = TempFile::new().unwrap();
    let device = File::open("/dev/null").unwrap();
    let err = clone_scratch(destination.as_file().as_raw_fd(), device.as_raw_fd()).unwrap_err();
    assert!(
        matches!(
            err.raw_os_error(),
            Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOTTY | libc::EXDEV)
        ),
        "{err}"
    );
}

#[test]
fn a_retry_is_replayed_after_the_clone_destination_grew() {
    let vmstate = memfd(c"vmstate", 8192);
    let destination = memfd(c"clone", 0);
    let key = CommandKey::of(
        MsgType::CaptureBuffers,
        &[],
        &[
            vmstate.try_clone().unwrap(),
            destination.try_clone().unwrap(),
        ],
    );
    let mut replies = ReplyCache::default();
    replies.record(4, key, MsgType::CaptureBuffersArmed, vec![], None);
    assert_eq!(
        // SAFETY: this test owns the destination and may resize it.
        unsafe { libc::ftruncate(destination.as_raw_fd(), 1 << 20) },
        0
    );
    let retry = CommandKey::of(MsgType::CaptureBuffers, &[], &[vmstate, destination]);
    assert!(matches!(
        replies.disposition(4, &retry),
        FrameDisposition::Replay(MsgType::CaptureBuffersArmed, _, None)
    ));
}

#[test]
fn the_scratch_clone_reproduces_the_disk_and_reports_its_duration() {
    let Some(dir) = std::env::var_os("RAMET_TEST_XFS_DIR") else {
        eprintln!("skipping: RAMET_TEST_XFS_DIR must name XFS with reflink=1");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    assert!(dir.is_dir());
    let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: path is NUL terminated and stat is writable for the call.
    assert_eq!(unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) }, 0);
    assert_eq!(
        // SAFETY: successful statfs initialized the structure.
        i128::from(unsafe { stat.assume_init() }.f_type),
        0x5846_5342
    );
    let source = TempFile::new_in(&dir).unwrap();
    let destination = TempFile::new_in(&dir).unwrap();
    let content = vec![0xa5; 1 << 20];
    let mut scratch = source.as_file();
    scratch.write_all(&content).unwrap();
    scratch.flush().unwrap();
    match clone_scratch(destination.as_file().as_raw_fd(), scratch.as_raw_fd()) {
        Err(err) if err.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            eprintln!("skipping: XFS without reflinks");
            return;
        }
        result => {
            result.unwrap();
        }
    }
    assert_eq!(std::fs::read(destination.as_path()).unwrap(), content);
}

#[test]
fn the_clone_request_is_the_number_the_seccomp_policies_admit() {
    assert_eq!(libc::FICLONE, 0x4004_9409);
}

fn summary_buffer(size: u64) -> File {
    let fd = memfd(c"summary", size);
    assert_eq!(
        // SAFETY: we own this memfd; only its size is sealed so the query can fill it.
        unsafe {
            libc::fcntl(
                fd.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_GROW | libc::F_SEAL_SHRINK,
            )
        },
        0
    );
    File::from(fd)
}

fn summary_regions() -> [protocol::RegionRecord; 2] {
    [
        protocol::RegionRecord {
            guest_addr: 0,
            size: 65 * 4096,
        },
        protocol::RegionRecord {
            guest_addr: 0x1_0000_0000,
            size: 4096,
        },
    ]
}

fn summary_deadline() -> Instant {
    Instant::now() + Duration::from_micros(protocol::MAX_FREE_SUMMARY_MICROS)
}

#[test]
fn free_summary_writes_every_word_including_zeros_and_masks_region_tails() {
    let file = summary_buffer(32);
    file.write_all_at(&[0xff; 32], 0).unwrap();
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            summary_deadline(),
            || Ok(vec![vec![0, u64::MAX], vec![1]])
        ),
        Ok(2)
    );
    let mut bytes = [0; 32];
    file.read_exact_at(&mut bytes, 0).unwrap();
    let expected: Vec<u8> = [0u64, 1, 1, u64::MAX]
        .into_iter()
        .flat_map(u64::to_le_bytes)
        .collect();
    assert_eq!(bytes.as_slice(), expected);
}

#[test]
fn free_summary_rejects_short_unsealed_nonmemfd_and_readonly_before_reading() {
    let regions = summary_regions();
    let short = summary_buffer(23);
    let unsealed = File::from(memfd(c"unsealed", 24));
    let ordinary = TempFile::new().unwrap().into_file();
    let sealed = summary_buffer(24);
    let readonly = File::open(format!("/proc/self/fd/{}", sealed.as_raw_fd())).unwrap();
    for (file, code) in [
        (&short, ErrorCode::BufferTooSmall),
        (&unsealed, ErrorCode::FdNotSealed),
        (&ordinary, ErrorCode::FdNotMemfd),
        (&readonly, ErrorCode::FdNotSealed),
    ] {
        assert_eq!(
            serve_free_summary(
                BackendState::Ready,
                file,
                &regions,
                summary_deadline(),
                || panic!("invalid output must not read KVM")
            ),
            Err(code)
        );
    }
}

#[test]
fn free_summary_caps_geometry_before_reading_and_accepts_exact_limit() {
    let file = summary_buffer(protocol::MAX_FREE_SUMMARY_BYTES);
    let mut region = protocol::RegionRecord {
        guest_addr: 0,
        size: protocol::MAX_FREE_SUMMARY_BYTES * 8 * 4096,
    };
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &[region],
            summary_deadline(),
            || Ok(vec![vec![
                0;
                u64_to_usize(protocol::MAX_FREE_SUMMARY_BYTES) / 8
            ]])
        ),
        Ok(0)
    );
    region.size += 4096;
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &[region],
            summary_deadline(),
            || panic!("over-cap geometry must not read")
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
    region.size = u64::MAX;
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &[region],
            summary_deadline(),
            || panic!("invalid geometry must not read")
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
}

#[test]
fn free_summary_busy_quiesced_expired_and_read_failures_are_advisory() {
    let file = summary_buffer(24);
    for (state, code) in [
        (BackendState::Quiesced, ErrorCode::AlreadyQuiesced),
        (BackendState::Registered, ErrorCode::FreeSummaryUnavailable),
    ] {
        assert_eq!(
            serve_free_summary(
                state,
                &file,
                &summary_regions(),
                summary_deadline(),
                || panic!("unavailable backend must not read")
            ),
            Err(code)
        );
    }
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            Instant::now(),
            || panic!("expired request must not read")
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            summary_deadline(),
            || Err(ErrorCode::FreeSummaryUnavailable)
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
    // Read overruns the deadline: no successful reply and not even a first output word.
    file.write_all_at(&[0xff; 24], 0).unwrap();
    let deadline = Instant::now() + Duration::from_millis(1);
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            deadline,
            || {
                std::thread::sleep(Duration::from_millis(2));
                Ok(vec![vec![0, 0], vec![0]])
            }
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
    let mut bytes = [0; 24];
    file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [0xff; 24]);
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            summary_deadline(),
            || Ok(vec![vec![0], vec![0]])
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
    // A late seal makes positional IO fail: still an advisory refusal, never partial success.
    assert_eq!(
        serve_free_summary(
            BackendState::Ready,
            &file,
            &summary_regions(),
            summary_deadline(),
            || {
                assert_eq!(
                    // SAFETY: this test owns the buffer and intentionally withdraws write access.
                    unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_WRITE) },
                    0
                );
                Ok(vec![vec![0, 0], vec![0]])
            }
        ),
        Err(ErrorCode::FreeSummaryUnavailable)
    );
}

#[test]
fn free_summary_exact_replay_never_rewrites_the_buffer() {
    let file = summary_buffer(24);
    let fd: OwnedFd = file.try_clone().unwrap().into();
    let body = protocol::MAX_FREE_SUMMARY_MICROS.to_le_bytes();
    let key = CommandKey::of(MsgType::FreeSummary, &body, &[fd]);
    let count = serve_free_summary(
        BackendState::Ready,
        &file,
        &summary_regions(),
        summary_deadline(),
        || Ok(vec![vec![0, 1], vec![0]]),
    )
    .unwrap();
    let mut replies = ReplyCache::default();
    replies.record(
        1,
        key.clone(),
        MsgType::FreeSummaryDone,
        count.to_le_bytes().to_vec(),
        None,
    );
    file.write_all_at(&[0xa5; 24], 0).unwrap();
    let FrameDisposition::Replay(msg, body, None) = replies.disposition(1, &key) else {
        panic!("not replayed")
    };
    let (tx, rx) = UnixStream::pair().unwrap();
    send_reply(&tx, msg, 1, &body, None).unwrap();
    let reply = protocol::recv_frame(&rx).unwrap();
    assert_eq!(reply.header.msg(), MsgType::FreeSummaryDone);
    assert_eq!(reply.body, 1u64.to_le_bytes());
    assert!(reply.fds.is_empty());
    let mut bytes = [0; 24];
    file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [0xa5; 24]);
}

/// Uses the real command dispatcher and KVM but no guest image. Like the release lane, run the
/// suite with --test-threads=1: backend state and the dispatch gate belong to the whole process.
#[test]
fn free_summary_handler_roundtrip_replay_busy_and_capture_priority() {
    use vm_memory::GuestAddress;

    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: real capture dispatcher requires /dev/kvm");
        return;
    }
    let vmm = Arc::new(Mutex::new(crate::builder::tests::default_vmm()));
    let vm = vmm.lock().unwrap().kvm_vm().unwrap().clone();
    vm.baseline_dirty_log().unwrap();
    vm.report_free(GuestAddress(64 * 4096), 64 * 4096).unwrap();
    let (sock, peer) = UnixStream::pair().unwrap();
    let mut service = CaptureService {
        channel: MemoryChannel {
            sock,
            regions: vec![protocol::RegionRecord {
                guest_addr: 0,
                size: 128 * 1024 * 1024,
            }],
        },
        vmm: vmm.clone(),
        vm_info: VmInfo::default(),
        buffers: None,
        order: EpochOrder::default(),
        replies: ReplyCache::default(),
        pending: None,
        tracker: None,
        standing: None,
        background: Background::detached(),
    };
    let file = summary_buffer(4096);
    let budget = protocol::MAX_FREE_SUMMARY_MICROS.to_le_bytes();
    let previous_state = BackendState::load();
    BackendState::Ready.store();
    let request = |service: &mut CaptureService, msg, id, body: &[u8], fds: &[RawFd]| {
        protocol::send_frame(&peer, msg, id, body, fds).unwrap();
        service.serve_one().unwrap();
        protocol::recv_frame(&peer).unwrap()
    };
    let reply = request(
        &mut service,
        MsgType::FreeSummary,
        1,
        &budget,
        &[file.as_raw_fd()],
    );
    assert_eq!(reply.header.msg(), MsgType::FreeSummaryDone);
    // ramet/10: the popcount, then no tracked sample (an untracked guest): MAX and id 0.
    let untracked = encode_free_summary_done(64, u64::MAX, 0);
    assert_eq!(reply.body, untracked);
    assert!(reply.fds.is_empty());
    file.write_all_at(&[0xa5; 4096], 0).unwrap();
    let replay = request(
        &mut service,
        MsgType::FreeSummary,
        1,
        &budget,
        &[file.as_raw_fd()],
    );
    assert_eq!(replay.body, reply.body);
    let mut bytes = [0; 4096];
    file.read_exact_at(&mut bytes, 0).unwrap();
    assert_eq!(bytes, [0xa5; 4096]);
    let guard = vmm.lock().unwrap();
    let busy = request(
        &mut service,
        MsgType::FreeSummary,
        2,
        &budget,
        &[file.as_raw_fd()],
    );
    assert_eq!(
        busy.body[..4],
        (ErrorCode::FreeSummaryUnavailable as u32).to_le_bytes()
    );
    drop(guard);
    let paused = request(&mut service, MsgType::Quiesce, 3, &[], &[]);
    assert_eq!(paused.header.msg(), MsgType::Quiesced);
    let refused = request(
        &mut service,
        MsgType::FreeSummary,
        4,
        &budget,
        &[file.as_raw_fd()],
    );
    assert_eq!(
        refused.body[..4],
        (ErrorCode::AlreadyQuiesced as u32).to_le_bytes()
    );
    let resumed = request(&mut service, MsgType::Resume, 5, &0u32.to_le_bytes(), &[]);
    assert_eq!(resumed.header.msg(), MsgType::Resumed);
    let after = request(
        &mut service,
        MsgType::FreeSummary,
        6,
        &budget,
        &[file.as_raw_fd()],
    );
    assert_eq!(after.header.msg(), MsgType::FreeSummaryDone);
    assert_eq!(after.body, untracked);
    assert_eq!(BackendState::load(), BackendState::Ready);
    assert!(!dispatch::gate().is_closed());
    for (id, body, fds) in [
        (7, vec![0; 7], vec![file.as_raw_fd()]),
        (8, budget.to_vec(), vec![]),
        (9, 0u64.to_le_bytes().to_vec(), vec![file.as_raw_fd()]),
    ] {
        protocol::send_frame(&peer, MsgType::FreeSummary, id, &body, &fds).unwrap();
        assert!(matches!(service.serve_one(), Err(ChannelError::Malformed)));
    }
    previous_state.store();
}

#[test]
fn track_starts_only_while_running_and_reports_while_quiesced() {
    use BackendState::{Quiesced, Ready};
    assert_eq!(track_mode(Ready, false), TrackMode::Start);
    assert_eq!(track_mode(Ready, true), TrackMode::Report);
    // A capture's freeze may read the tracker, which allocates nothing, but never start one.
    assert_eq!(track_mode(Quiesced, true), TrackMode::Report);
    assert_eq!(track_mode(Quiesced, false), TrackMode::Refuse);
}

#[test]
fn only_a_quiesced_dirty_count_over_the_bound_is_counted_exactly() {
    use BackendState::{Quiesced, Ready};
    let info = memversion::TrackInfo {
        tracked: 1,
        dirty_pages: 100,
        ..Default::default()
    };
    assert!(counts_retained(Quiesced, &info, 99));
    // A count that fits pays nothing inside the freeze: it is reported as the upper bound.
    assert!(!counts_retained(Quiesced, &info, 100));
    assert!(!counts_retained(Quiesced, &info, u64::MAX));
    // A running guest has no consistent instant to count at.
    assert!(!counts_retained(Ready, &info, 0));
    let untracked = memversion::TrackInfo { tracked: 0, ..info };
    assert!(!counts_retained(Quiesced, &untracked, 0));
}

#[test]
fn untrack_releases_every_answered_version() {
    let device = memfd(c"device", 0);
    let create = CommandKey::of(MsgType::WriteVmstate, &[], std::slice::from_ref(&device));
    let untrack = CommandKey::of(MsgType::Untrack, &[], &[]);
    let version = Arc::new(memfd(c"refused", 0));
    let mut replies = ReplyCache::default();
    replies.record(
        4,
        create.clone(),
        MsgType::VmstateWritten,
        vec![7],
        Some(version.clone()),
    );
    // The Untrack after a refused capture is a new request: the refused version's descriptor
    // is let go before the tracker is, and no cached answer can hand it out again.
    assert!(matches!(
        replies.disposition(5, &untrack),
        FrameDisposition::Serve
    ));
    replies.acknowledge_before(5);
    assert_eq!(Arc::strong_count(&version), 1);
    assert!(matches!(
        replies.disposition(4, &create),
        FrameDisposition::ReplayUnavailable
    ));
}

#[test]
fn track_and_refresh_frames_numbers_and_bodies() {
    assert_eq!(
        [
            MsgType::Track,
            MsgType::Tracked,
            MsgType::Refresh,
            MsgType::Refreshed
        ]
        .map(|msg| msg as u16),
        [28, 29, 30, 31]
    );
    for value in 28..=31 {
        assert_eq!(MsgType::from_u16(value).unwrap() as u16, value);
    }
    assert_eq!(
        (
            ErrorCode::UntrackFailed as u32,
            ErrorCode::TrackFailed as u32,
            ErrorCode::RefreshFailed as u32
        ),
        (30, 31, 32)
    );
    assert_eq!(MsgType::Untrack as u16, 25);
    assert_eq!(MsgType::from_u16(25), Some(MsgType::Untrack));
    validate_command(MsgType::Untrack, 0, 0).unwrap();
    validate_command(MsgType::Untrack, 0, 1).unwrap_err();
    // Track carries the device, and the imported version for a lazy import; Refresh nothing.
    validate_command(MsgType::Track, 0, 1).unwrap();
    validate_command(MsgType::Track, 0, 2).unwrap();
    validate_command(MsgType::Track, 0, 0).unwrap_err();
    // Its body is empty or one u64 bound.
    validate_command(MsgType::Track, 8, 1).unwrap();
    validate_command(MsgType::Track, 8, 2).unwrap();
    validate_command(MsgType::Track, 8, 0).unwrap_err();
    validate_command(MsgType::Track, 16, 1).unwrap();
    for len in [1, 4, 7, 9, 15, 17, 24] {
        validate_command(MsgType::Track, len, 1).unwrap_err();
    }
    assert_eq!(protocol::parse_track(&[]).unwrap(), (u64::MAX, 0));
    assert_eq!(
        protocol::parse_track(&0x0102_0304_0506_0708u64.to_le_bytes()).unwrap(),
        (0x0102_0304_0506_0708, 0)
    );
    let mut counted = 7u64.to_le_bytes().to_vec();
    counted.extend_from_slice(&protocol::TRACK_COUNT_RETAINED.to_le_bytes());
    assert_eq!(protocol::parse_track(&counted).unwrap(), (7, 1));
    let mut unknown = 7u64.to_le_bytes().to_vec();
    unknown.extend_from_slice(&2u64.to_le_bytes());
    protocol::parse_track(&unknown).unwrap_err();
    for len in [1, 4, 7, 9, 15, 17, 24] {
        protocol::parse_track(&vec![0; len]).unwrap_err();
    }
    validate_command(MsgType::Refresh, 0, 0).unwrap();
    validate_command(MsgType::Refresh, 8, 0).unwrap();
    validate_command(MsgType::Refresh, 0, 1).unwrap_err();
    validate_command(MsgType::Refresh, 4, 0).unwrap_err();
    assert_eq!(protocol::parse_refresh_budget(&[]).unwrap(), 0);
    assert_eq!(protocol::parse_refresh_budget(&9u64.to_le_bytes()).unwrap(), 9);
    protocol::parse_refresh_budget(&[0; 4]).unwrap_err();
    // Replies are commands only Firecracker sends.
    validate_command(MsgType::Tracked, 40, 0).unwrap_err();
    validate_command(MsgType::Refreshed, 32, 1).unwrap_err();

    let tracked = memversion::TrackInfo {
        tracked: 1,
        depth: 2,
        dirty_pages: 0x0102_0304_0506_0708,
        standing_id: 9,
        flags: 3,
        reserved: 4,
        retained_pages: 5,
    };
    let body = encode_tracked(&tracked, 0x1112_1314_1516_1718, 0x2122);
    assert_eq!(body.len(), 40);
    assert_eq!(body[..8], [1, 0, 0, 0, 2, 0, 0, 0]);
    assert_eq!(body[8..16], 0x0102_0304_0506_0708u64.to_le_bytes());
    assert_eq!(body[16..24], 9u64.to_le_bytes());
    assert_eq!(body[24..32], 0x1112_1314_1516_1718u64.to_le_bytes());
    assert_eq!(body[32..], 0x2122u64.to_le_bytes());
    // An untracked reply, as Untrack sends, is zero after `tracked` whatever it was given.
    assert_eq!(
        encode_tracked(&memversion::TrackInfo::default(), 0, 0),
        vec![0; 40]
    );
    assert_eq!(
        encode_tracked(
            &memversion::TrackInfo {
                tracked: 0,
                ..tracked
            },
            7,
            8
        ),
        vec![0; 40]
    );
    let body = encode_refreshed(&memversion::Info2 {
        own_pages: 5,
        new_pages: 6,
        depth: 3,
        nr_zero_runs: 4,
        folded_pages: 7,
        ..Default::default()
    }, 8, 9, 10);
    assert_eq!(body.len(), 56);
    assert_eq!(body[..8], 5u64.to_le_bytes());
    assert_eq!(body[8..16], 6u64.to_le_bytes());
    assert_eq!(body[16..24], [3, 0, 0, 0, 4, 0, 0, 0]);
    assert_eq!(body[24..32], 7u64.to_le_bytes());
    assert_eq!(body[32..40], 8u64.to_le_bytes());
    assert_eq!(body[40..48], 9u64.to_le_bytes());
    assert_eq!(body[48..], 10u64.to_le_bytes());
}

#[test]
fn rearm_frames_numbers_and_bodies() {
    assert_eq!(
        [MsgType::Rearm, MsgType::Rearmed].map(|msg| msg as u16),
        [32, 33]
    );
    for value in 32..=33 {
        assert_eq!(MsgType::from_u16(value).unwrap() as u16, value);
    }
    assert_eq!(MsgType::from_u16(34), None);
    assert_eq!(ErrorCode::RearmFailed as u32, 34);
    // Rearm carries the flat version and nothing else.
    validate_command(MsgType::Rearm, 0, 1).unwrap();
    validate_command(MsgType::Rearm, 0, 0).unwrap_err();
    validate_command(MsgType::Rearm, 0, 2).unwrap_err();
    validate_command(MsgType::Rearm, 8, 1).unwrap_err();
    // The reply is one only Firecracker sends.
    validate_command(MsgType::Rearmed, 0, 0).unwrap_err();
}

#[test]
fn rearm_refuses_without_a_running_tracked_guest_and_changes_nothing() {
    if !std::path::Path::new("/dev/kvm").exists() {
        eprintln!("SKIP: real capture dispatcher requires /dev/kvm");
        return;
    }
    let vmm = Arc::new(Mutex::new(crate::builder::tests::default_vmm()));
    let (sock, peer) = UnixStream::pair().unwrap();
    let mut service = CaptureService {
        channel: MemoryChannel {
            sock,
            regions: vec![protocol::RegionRecord {
                guest_addr: 0,
                size: 128 * 1024 * 1024,
            }],
        },
        vmm,
        vm_info: VmInfo::default(),
        buffers: None,
        order: EpochOrder::default(),
        replies: ReplyCache::default(),
        pending: None,
        tracker: None,
        standing: None,
        background: Background::detached(),
    };
    let previous_state = BackendState::load();
    let flat = memfd(c"flat", 0);
    let rearm = |service: &mut CaptureService, id| {
        protocol::send_frame(&peer, MsgType::Rearm, id, &[], &[flat.as_raw_fd()]).unwrap();
        service.serve_one().unwrap();
        let reply = protocol::recv_frame(&peer).unwrap();
        assert_eq!(reply.header.msg(), MsgType::Error);
        assert!(reply.fds.is_empty());
        assert_eq!(
            reply.body[..4],
            (ErrorCode::RearmFailed as u32).to_le_bytes()
        );
    };

    // Nothing is tracked, so there is no tracker to move.
    BackendState::Ready.store();
    rearm(&mut service, 1);
    assert!(service.standing.is_none());

    // A guest quiesced for a capture is never rearmed: CREATE may be about to move the standing
    // version, and memory plane sends Rearm only after the resume.
    let standing = Arc::new(memfd(c"standing", 0));
    service.tracker = Some(memfd(c"device", 0));
    service.standing = Some(standing.clone());
    BackendState::Quiesced.store();
    rearm(&mut service, 2);
    assert!(Arc::ptr_eq(service.standing.as_ref().unwrap(), &standing));

    // The kernel refusing the swap (here: a descriptor that is not the device) leaves the
    // tracker and the standing version where they were, so memory plane's Untrack still releases
    // the version the tracker stands on.
    BackendState::Ready.store();
    rearm(&mut service, 3);
    assert!(service.tracker.is_some());
    assert!(Arc::ptr_eq(service.standing.as_ref().unwrap(), &standing));
    previous_state.store();
}
