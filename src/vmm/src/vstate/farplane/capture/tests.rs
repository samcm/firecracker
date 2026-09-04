// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
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

/// Filesystem magic of XFS, the only filesystem the measured clone and alignment facts hold on.
const XFS_SUPER_MAGIC: i128 = 0x5846_5342;

/// Directory the clone proofs run in, or `None` when the run did not configure one.
///
/// A configured directory that is not an XFS one is a broken environment and fails; an XFS one
/// without reflinks cannot host the proof and skips. Nothing else skips.
fn reflink_dir() -> Option<std::path::PathBuf> {
    let Some(dir) = std::env::var_os("FARPLANE_TEST_XFS_DIR") else {
        eprintln!(
            "skipping: FARPLANE_TEST_XFS_DIR must name a directory on an XFS filesystem \
             formatted with reflink=1, because FICLONE has no meaning without one"
        );
        return None;
    };
    let dir = std::path::PathBuf::from(dir);
    assert!(
        dir.is_dir(),
        "FARPLANE_TEST_XFS_DIR is {}, which is not a directory",
        dir.display()
    );
    let magic = filesystem_magic(&dir);
    assert_eq!(
        magic,
        XFS_SUPER_MAGIC,
        "FARPLANE_TEST_XFS_DIR is {}, whose filesystem magic is {magic:#x} and not XFS",
        dir.display()
    );

    let source = file_in(&dir, "farplane-reflink-probe-source", &[0u8; 4096]);
    let destination = file_in(&dir, "farplane-reflink-probe-destination", &[]);
    let probe = clone_scratch(destination.as_raw_fd(), source.as_raw_fd());
    let _ = std::fs::remove_file(dir.join("farplane-reflink-probe-source"));
    let _ = std::fs::remove_file(dir.join("farplane-reflink-probe-destination"));
    match probe {
        Ok(_) => Some(dir),
        Err(err) if err.raw_os_error() == Some(libc::EOPNOTSUPP) => {
            eprintln!("skipping: {} is XFS without reflinks", dir.display());
            None
        }
        Err(err) => panic!("the reflink probe in {} failed: {err}", dir.display()),
    }
}

/// Filesystem magic of the filesystem `dir` lives on.
fn filesystem_magic(dir: &std::path::Path) -> i128 {
    let path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and outlives the call, and `stat` is a valid allocation.
    let probed = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    assert_eq!(
        probed,
        0,
        "statfs {}: {}",
        dir.display(),
        io::Error::last_os_error()
    );
    // SAFETY: `statfs` returned success, so it initialized the whole struct.
    i128::from(unsafe { stat.assume_init() }.f_type)
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
/// returns. The gate has already proven the filesystem reflinks, so a failure here is a bug.
#[test]
fn the_scratch_clone_reproduces_the_disk_and_reports_its_duration() {
    let Some(dir) = reflink_dir() else {
        return;
    };
    let content = vec![0xa5u8; 1 << 20];
    let scratch = file_in(&dir, "farplane-clone-source", &content);
    let destination = file_in(&dir, "farplane-clone-destination", &[]);

    clone_scratch(destination.as_raw_fd(), scratch.as_raw_fd())
        .expect("the clone of a scratch disk on a reflink filesystem must succeed");

    assert_eq!(
        std::fs::read(dir.join("farplane-clone-destination")).unwrap(),
        content,
        "the clone is not the disk the scratch held"
    );
}

/// A clone the kernel refuses is reported as a failure carrying its errno, which is what the
/// quiesce answers `DiskCloneFailed` on. Only a regular file has extents to share, and which
/// errno says so depends on the filesystems the two descriptors are on.
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

/// An armed clone destination is empty and `FICLONE` grows it to the size of the scratch disk,
/// so a descriptor's identity is the file it names and not how long that file is.
#[test]
fn a_retry_is_replayed_after_the_clone_destination_grew() {
    let dirty = memfd(c"farplane-dirty", 4096);
    let vmstate = memfd(c"farplane-vmstate", 8192);
    let destination = memfd(c"farplane-clone", 0);
    let sent = [
        duplicate(&dirty),
        duplicate(&vmstate),
        duplicate(&destination),
    ];
    let mut replies = ReplyCache::default();
    replies.record(
        4,
        CommandKey::of(MsgType::CaptureBuffers, &[], &sent),
        MsgType::CaptureBuffersArmed,
        Vec::new(),
    );

    // SAFETY: `destination` is a memfd this test owns, so it may be resized.
    let grown = unsafe { libc::ftruncate(destination.as_raw_fd(), 1 << 20) };
    assert_eq!(grown, 0, "{}", io::Error::last_os_error());

    let retried = [
        duplicate(&dirty),
        duplicate(&vmstate),
        duplicate(&destination),
    ];
    assert_eq!(
        replies.disposition(4, &CommandKey::of(MsgType::CaptureBuffers, &[], &retried)),
        FrameDisposition::Replay(MsgType::CaptureBuffersArmed, Vec::new()),
        "the arming frame must replay after the clone grew its destination"
    );
}

/// The number the clone issues and the number the seccomp policies admit are one value. A libc
/// or policy change that parts them would raise `SIGSYS` inside the freeze.
#[test]
fn the_clone_request_is_the_number_the_seccomp_policies_admit() {
    assert_eq!(libc::FICLONE, 0x4004_9409);
}
