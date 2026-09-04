// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::undocumented_unsafe_blocks)]

use super::*;
use crate::build_arg_parser;

fn get_pseudo_exec_file_path() -> String {
    format!(
        "/tmp/{}/pseudo_firecracker_exec_file",
        vmm_sys_util::rand::rand_alphanumerics(4)
            .into_string()
            .unwrap()
    )
}

fn cmdline(root_fd: &str, extra: &[&str]) -> Vec<String> {
    let pseudo_exec_file_path = get_pseudo_exec_file_path();
    let dir = Path::new(&pseudo_exec_file_path).parent().unwrap();
    fs::create_dir_all(dir).unwrap();
    File::create(&pseudo_exec_file_path).unwrap();

    let mut args = vec![
        "--binary-name".to_string(),
        "--id".to_string(),
        "bd65600d-8669-4903-8a14-af88203add38".to_string(),
        "--exec-file".to_string(),
        pseudo_exec_file_path,
        "--uid".to_string(),
        "1001".to_string(),
        "--gid".to_string(),
        "1002".to_string(),
        "--root-fd".to_string(),
        root_fd.to_string(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_string()));
    args
}

fn new_env(args: &[String]) -> Result<Env, JailerError> {
    let arg_parser = build_arg_parser();
    let mut arguments = arg_parser.arguments().clone();
    arguments.parse(args).unwrap();
    Env::new(&arguments, 0, 0)
}

fn memfd(size: libc::off_t, seals: libc::c_int) -> RawFd {
    let fd = unsafe { libc::memfd_create(c"root".as_ptr().cast(), libc::MFD_ALLOW_SEALING) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    assert_eq!(unsafe { libc::ftruncate(fd, size) }, 0);
    if seals != 0 {
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    }
    fd
}

fn reopen_read_only(fd: RawFd) -> RawFd {
    let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let read_only = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    assert!(read_only >= 0, "{}", io::Error::last_os_error());
    read_only
}

#[test]
fn test_new_env() {
    let env = new_env(&cmdline(
        "7",
        &[
            "--chroot-base-dir",
            "/",
            "--resource-limit",
            "memlock=1048576",
        ],
    ))
    .unwrap();
    assert_eq!(env.uid(), 1001);
    assert_eq!(env.gid(), 1002);
    assert_eq!(env.root_fd, 7);
    assert_eq!(env.scratch_fd, None);
    assert_eq!(env.highest_reserved_fd(), ROOT_FILENO);
}

/// A scratch disk is optional, and reserving fd 5 follows from passing one.
#[test]
fn test_scratch_fd_reserves_its_slot_only_when_passed() {
    let args = cmdline("7", &["--chroot-base-dir", "/", "--scratch-fd", "8"]);
    let env = new_env(&args).unwrap();

    assert_eq!(env.scratch_fd, Some(8));
    assert_eq!(env.highest_reserved_fd(), SCRATCH_FILENO);
}

#[test]
fn test_scratch_fd_must_be_a_descriptor_number() {
    let args = cmdline(
        "7",
        &["--chroot-base-dir", "/", "--scratch-fd", "/dev/scratch"],
    );

    assert!(matches!(
        new_env(&args),
        Err(JailerError::ScratchFdArgument(_))
    ));
}

#[test]
fn test_root_fd_must_be_a_descriptor_number() {
    assert!(matches!(
        new_env(&cmdline("/dev/root", &["--chroot-base-dir", "/"])),
        Err(JailerError::RootFdArgument(_))
    ));
}

#[test]
fn test_cgroup_join_must_be_absolute() {
    assert!(matches!(
        new_env(&cmdline(
            "7",
            &["--chroot-base-dir", "/", "--cgroup-join", "relative/path"]
        )),
        Err(JailerError::CgroupJoinNotAbsolute)
    ));
}

/// A jail uid that is never the uid the test process runs as, so an image the test creates is
/// owned by someone other than the jail, and never root, which the regular arm refuses.
fn other_uid() -> u32 {
    match own_uid() {
        0 => 1,
        uid => uid.wrapping_add(1),
    }
}

fn own_uid() -> u32 {
    unsafe { libc::getuid() }
}

/// The uid an image is given to when the ownership check is under test. It is the uid the test
/// runs as, unless that is root, which is refused before ownership is ever looked at.
fn jail_owner_uid() -> u32 {
    match own_uid() {
        0 => NOBODY_UID,
        uid => uid,
    }
}

const NOBODY_UID: u32 = 65534;

/// Whether an inode created in `dir` answers `F_GET_SEALS`, which is what decides the arm of
/// the contract an image there is held to.
fn seals_inodes(dir: &Path) -> bool {
    let cstr = CString::new(dir.to_str().unwrap()).unwrap();
    let mut fs_stat = MaybeUninit::<libc::statfs>::uninit();
    assert_eq!(
        unsafe { libc::statfs(cstr.as_ptr(), fs_stat.as_mut_ptr()) },
        0,
        "statfs {}: {}",
        dir.display(),
        io::Error::last_os_error()
    );
    let magic = i128::from(unsafe { fs_stat.assume_init() }.f_type);
    magic == i128::from(TMPFS_MAGIC) || magic == i128::from(HUGETLBFS_MAGIC)
}

/// Directory the regular test images are created in. Every shmem inode answers `F_GET_SEALS`,
/// so a file on tmpfs is held to the sealed memfd arm and can never exercise the regular one.
/// `/tmp` is tmpfs on most hosts, so the image goes next to the test binary in the build tree,
/// falling back to the source tree for a build tree that is itself tmpfs.
fn regular_image_dir() -> PathBuf {
    let build_tree = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let source_tree = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    [build_tree, source_tree]
        .into_iter()
        .find(|dir| !seals_inodes(dir))
        .expect("every candidate directory seals its inodes, so no regular image can be built")
}

/// Creates a regular file holding `size` bytes with `mode` as its final permissions, and
/// returns an `O_RDONLY` descriptor to it. The file is owned by the uid the test runs as.
fn regular_image(mode: u32, size: u64) -> RawFd {
    regular_image_opened(mode, size, libc::O_RDONLY, None)
}

/// Creates a regular image belonging to `owner`. Only a test running as root can give an image
/// away, which is the only case where the uid the test runs as will not do.
fn regular_image_owned_by(owner: u32, mode: u32, size: u64) -> RawFd {
    regular_image_opened(mode, size, libc::O_RDONLY, Some(owner))
}

fn regular_image_opened(
    mode: u32,
    size: u64,
    open_flags: libc::c_int,
    owner: Option<u32>,
) -> RawFd {
    let path = regular_image_dir().join(format!(
        "jailer-image-{}",
        vmm_sys_util::rand::rand_alphanumerics(8)
            .into_string()
            .unwrap()
    ));
    let file = File::create(&path).unwrap();
    file.set_len(size).unwrap();
    if let Some(owner) = owner {
        fchown(&file, Some(owner), None).unwrap();
    }
    drop(file);
    // Permissions are set last: `File::create` obeys the umask, and a mode without a write
    // bit would stop the size from being set.
    fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();

    let cstr = CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(cstr.as_ptr(), open_flags | libc::O_CLOEXEC) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    fs::remove_file(&path).unwrap();
    fd
}

#[test]
fn test_validate_root_fd_accepts_sealed_read_only_memfd() {
    let fd = memfd(4096, REQUIRED_IMAGE_SEALS);
    let read_only = reopen_read_only(fd);

    validate_image_fd("--root-fd", read_only, other_uid()).unwrap();

    close(fd).unwrap();
    close(read_only).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_writable_memfd() {
    let fd = memfd(4096, REQUIRED_IMAGE_SEALS);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, other_uid()),
        Err(JailerError::ImageFdNotReadOnly("--root-fd"))
    ));

    close(fd).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_unsealed_memfd() {
    let fd = memfd(4096, libc::F_SEAL_WRITE);
    let read_only = reopen_read_only(fd);

    assert!(matches!(
        validate_image_fd("--root-fd", read_only, other_uid()),
        Err(JailerError::ImageFdNotSealed("--root-fd"))
    ));

    close(fd).unwrap();
    close(read_only).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_empty_memfd() {
    let fd = memfd(0, REQUIRED_IMAGE_SEALS);
    let read_only = reopen_read_only(fd);

    assert!(matches!(
        validate_image_fd("--root-fd", read_only, other_uid()),
        Err(JailerError::ImageFdEmpty("--root-fd"))
    ));

    close(fd).unwrap();
    close(read_only).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_non_regular_fd() {
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);

    assert!(matches!(
        validate_image_fd("--root-fd", pipe[0], other_uid()),
        Err(JailerError::ImageFdNotRegularFile("--root-fd"))
    ));

    close(pipe[0]).unwrap();
    close(pipe[1]).unwrap();
}

/// A content-addressed image shared by every microVM on the node is an ordinary read-only
/// regular file, not a memfd, and no per-jail copy of it is made.
#[test]
fn test_validate_root_fd_accepts_read_only_regular_file() {
    let fd = regular_image(0o400, 4096);

    validate_image_fd("--root-fd", fd, other_uid()).unwrap();

    close(fd).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_empty_regular_file() {
    let fd = regular_image(0o400, 0);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, other_uid()),
        Err(JailerError::ImageFdEmpty("--root-fd"))
    ));

    close(fd).unwrap();
}

#[test]
fn test_validate_root_fd_rejects_writable_regular_fd() {
    let fd = regular_image_opened(0o600, 4096, libc::O_RDWR, None);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, other_uid()),
        Err(JailerError::ImageFdNotReadOnly("--root-fd"))
    ));

    close(fd).unwrap();
}

/// An `O_PATH` descriptor reports an access mode of `O_RDONLY` without granting a read, so the
/// access mode alone must not decide the question.
#[test]
fn test_validate_root_fd_rejects_o_path_fd() {
    let fd = regular_image_opened(0o400, 4096, libc::O_PATH, None);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, other_uid()),
        Err(JailerError::ImageFdNotReadOnly("--root-fd"))
    ));

    close(fd).unwrap();
}

/// A write bit means some uid can change the bytes under the running guest. Which uid it is
/// does not matter, because the jail is never the arbiter of who that uid is.
#[test]
fn test_validate_root_fd_rejects_regular_file_write_mode_bits() {
    for mode in [0o600, 0o460, 0o406] {
        let fd = regular_image(mode, 4096);

        assert!(
            matches!(
                validate_image_fd("--root-fd", fd, other_uid()),
                Err(JailerError::ImageFdWritablePermissions("--root-fd"))
            ),
            "mode {mode:o} was accepted"
        );

        close(fd).unwrap();
    }
}

#[test]
fn test_validate_root_fd_rejects_regular_file_special_mode_bits() {
    for mode in [0o4400, 0o2400, 0o1400] {
        let fd = regular_image(mode, 4096);

        assert!(
            matches!(
                validate_image_fd("--root-fd", fd, other_uid()),
                Err(JailerError::ImageFdSpecialModeBits("--root-fd"))
            ),
            "mode {mode:o} was accepted"
        );

        close(fd).unwrap();
    }
}

/// Ownership carries the right to chmod, so an image the jailed uid owns is one it can make
/// writable the moment it starts running.
#[test]
fn test_validate_root_fd_rejects_regular_file_owned_by_jail_uid() {
    let owner = jail_owner_uid();
    let fd = regular_image_owned_by(owner, 0o400, 4096);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, owner),
        Err(JailerError::ImageFdOwnedByJailUid("--root-fd"))
    ));

    close(fd).unwrap();
}

/// A jail that keeps uid 0 keeps `CAP_DAC_OVERRIDE` and `CAP_FOWNER`, so neither the missing
/// write bits nor foreign ownership stop it from writing the image. Only a seal does.
#[test]
fn test_validate_root_fd_rejects_regular_file_for_a_root_jail() {
    let fd = regular_image(0o400, 4096);

    assert!(matches!(
        validate_image_fd("--root-fd", fd, 0),
        Err(JailerError::ImageFdRegularFileAtRootUid("--root-fd"))
    ));

    close(fd).unwrap();
}

/// The seals hold against every uid, root included, so uid 0 keeps the memfd arm.
#[test]
fn test_validate_root_fd_accepts_sealed_memfd_for_a_root_jail() {
    let fd = memfd(4096, REQUIRED_IMAGE_SEALS);
    let read_only = reopen_read_only(fd);

    validate_image_fd("--root-fd", read_only, 0).unwrap();

    close(fd).unwrap();
    close(read_only).unwrap();
}

/// Creates a regular image and returns a read-only descriptor to it alongside a writable one on
/// the same inode. The writable descriptor is opened before the permissions are narrowed,
/// which is how a caller comes to hold one for an image no permission bit says is writable.
fn regular_image_with_writable_alias(size: u64) -> (RawFd, RawFd) {
    let path = regular_image_dir().join(format!(
        "jailer-image-{}",
        vmm_sys_util::rand::rand_alphanumerics(8)
            .into_string()
            .unwrap()
    ));
    let file = File::create(&path).unwrap();
    file.set_len(size).unwrap();
    drop(file);

    let cstr = CString::new(path.to_str().unwrap()).unwrap();
    let writable = unsafe { libc::open(cstr.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    assert!(writable >= 0, "{}", io::Error::last_os_error());
    fs::set_permissions(&path, Permissions::from_mode(0o400)).unwrap();
    let read_only = unsafe { libc::open(cstr.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(read_only >= 0, "{}", io::Error::last_os_error());
    fs::remove_file(&path).unwrap();
    (read_only, writable)
}

/// The inherited image descriptor is not the only way the jail reaches the inode. The standard
/// streams survive `close_range`, so a writable one aimed at the image is a writable alias the
/// image's own access mode, permissions and ownership all look innocent of.
#[test]
fn test_validate_root_fd_rejects_a_writable_standard_stream_alias() {
    let (read_only, writable) = regular_image_with_writable_alias(4096);

    // Firecracker's stderr is the alias, as the caller would have left it. The test process
    // needs its own back, so it is parked on a descriptor of its own for the one call.
    let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
    assert!(saved_stderr >= 0, "{}", io::Error::last_os_error());
    dup2(writable, libc::STDERR_FILENO).unwrap();
    let verdict = validate_image_fd("--root-fd", read_only, other_uid());
    dup2(saved_stderr, libc::STDERR_FILENO).unwrap();
    close(saved_stderr).unwrap();

    assert!(
        matches!(
            verdict,
            Err(JailerError::ImageFdWritableStreamAlias(
                "--root-fd",
                libc::STDERR_FILENO
            ))
        ),
        "a writable stderr alias of the image was accepted: {verdict:?}"
    );

    // The same image with no alias behind it is the contract the supervisor is held to, so the
    // check must not refuse it.
    validate_image_fd("--root-fd", read_only, other_uid()).unwrap();

    close(read_only).unwrap();
    close(writable).unwrap();
}

/// Creates a regular file of `size` bytes and returns a descriptor on it opened with
/// `open_flags`, which must include `O_DIRECT`. A filesystem that refuses direct I/O holds no
/// scratch disk, so the caller gets no descriptor and skips.
fn scratch_file_opened(size: u64, open_flags: libc::c_int) -> Option<RawFd> {
    let dir = regular_image_dir();
    let path = dir.join(format!(
        "jailer-scratch-{}",
        vmm_sys_util::rand::rand_alphanumerics(8)
            .into_string()
            .unwrap()
    ));
    let file = File::create(&path).unwrap();
    file.set_len(size).unwrap();
    drop(file);
    fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();

    let cstr = CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(cstr.as_ptr(), open_flags | libc::O_CLOEXEC) };
    let err = io::Error::last_os_error();
    fs::remove_file(&path).unwrap();
    if fd < 0 && err.raw_os_error() == Some(libc::EINVAL) {
        eprintln!("skipped: {} does not support O_DIRECT", dir.display());
        return None;
    }
    assert!(fd >= 0, "{}", err);
    Some(fd)
}

/// A fifo opened read-write, which is the non-regular inode a scratch descriptor can name
/// while still carrying the access mode the contract asks for.
fn read_write_fifo() -> RawFd {
    let path = regular_image_dir().join(format!(
        "jailer-fifo-{}",
        vmm_sys_util::rand::rand_alphanumerics(8)
            .into_string()
            .unwrap()
    ));

    let cstr = CString::new(path.to_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { libc::mkfifo(cstr.as_ptr(), 0o600) },
        0,
        "{}",
        io::Error::last_os_error()
    );
    let fd = unsafe { libc::open(cstr.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    assert!(fd >= 0, "{}", io::Error::last_os_error());
    fs::remove_file(&path).unwrap();
    fd
}

/// The scratch disk is a file on the node the guest reads and writes at offsets of its own
/// choosing, which is what the supervisor is contracted to hand over.
#[test]
fn test_validate_scratch_fd_accepts_read_write_direct_regular_file() {
    let flags = libc::O_RDWR | libc::O_DIRECT;
    let Some(fd) = scratch_file_opened(4096, flags) else {
        return;
    };

    validate_scratch_fd("--scratch-fd", fd).unwrap();

    close(fd).unwrap();
}

/// The two slots are held to opposite contracts, so neither of them takes the descriptor the
/// other one is given.
#[test]
fn test_root_and_scratch_contracts_refuse_each_others_descriptor() {
    let flags = libc::O_RDWR | libc::O_DIRECT;
    let Some(scratch) = scratch_file_opened(4096, flags) else {
        return;
    };

    assert!(matches!(
        validate_image_fd("--root-fd", scratch, other_uid()),
        Err(JailerError::ImageFdNotReadOnly("--root-fd"))
    ));
    close(scratch).unwrap();

    let image = regular_image(0o400, 4096);
    assert!(matches!(
        validate_scratch_fd("--scratch-fd", image),
        Err(JailerError::ScratchFdNotReadWrite("--scratch-fd"))
    ));
    close(image).unwrap();
}

/// An `O_PATH` descriptor reports an access mode of `O_RDONLY` while granting no access at
/// all, so the access mode alone must not decide the question.
#[test]
fn test_validate_scratch_fd_rejects_o_path_fd() {
    let fd = regular_image_opened(0o600, 4096, libc::O_PATH, None);

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdNotReadWrite("--scratch-fd"))
    ));

    close(fd).unwrap();
}

#[test]
fn test_validate_scratch_fd_rejects_read_only_fd() {
    let flags = libc::O_RDONLY | libc::O_DIRECT;
    let Some(fd) = scratch_file_opened(4096, flags) else {
        return;
    };

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdNotReadWrite("--scratch-fd"))
    ));

    close(fd).unwrap();
}

/// `O_APPEND` moves every write to the end of the file, so a guest writing its first block
/// would land wherever the disk happens to end.
#[test]
fn test_validate_scratch_fd_rejects_o_append_fd() {
    let flags = libc::O_RDWR | libc::O_DIRECT | libc::O_APPEND;
    let Some(fd) = scratch_file_opened(4096, flags) else {
        return;
    };

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdAppend("--scratch-fd"))
    ));

    close(fd).unwrap();
}

/// Buffered writes leave a second copy of every sandbox's disk in the node's page cache,
/// which is the memory the sandboxes are sized against.
#[test]
fn test_validate_scratch_fd_rejects_buffered_fd() {
    let fd = regular_image_opened(0o600, 4096, libc::O_RDWR, None);

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdNotDirect("--scratch-fd"))
    ));

    close(fd).unwrap();
}

#[test]
fn test_validate_scratch_fd_rejects_empty_file() {
    let flags = libc::O_RDWR | libc::O_DIRECT;
    let Some(fd) = scratch_file_opened(0, flags) else {
        return;
    };

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdEmpty("--scratch-fd"))
    ));

    close(fd).unwrap();
}

#[test]
fn test_validate_scratch_fd_rejects_non_regular_fd() {
    let fd = read_write_fifo();

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdNotRegularFile("--scratch-fd"))
    ));

    close(fd).unwrap();
}

/// A sandbox disk on shmem or hugetlbfs is the node's memory rather than its storage, and
/// answering `F_GET_SEALS` at all is what tells those two filesystems apart from the rest.
#[test]
fn test_validate_scratch_fd_rejects_sealed_memfd() {
    let fd = memfd(4096, REQUIRED_IMAGE_SEALS);

    assert!(matches!(
        validate_scratch_fd("--scratch-fd", fd),
        Err(JailerError::ScratchFdSealingFilesystem("--scratch-fd"))
    ));

    close(fd).unwrap();
}

/// A caller can open one inode twice, read-only for the root slot and writable for the
/// scratch slot, which would leave the guest writing the immutable root image.
#[test]
fn test_reject_root_alias_refuses_one_inode_in_both_slots() {
    let flags = libc::O_RDWR | libc::O_DIRECT;
    let Some(scratch) = scratch_file_opened(4096, flags) else {
        return;
    };
    let root = reopen_read_only(scratch);

    assert!(matches!(
        reject_root_alias(root, scratch),
        Err(JailerError::ScratchFdAliasesRoot)
    ));

    // Two descriptors on inodes of their own are what the supervisor is contracted to pass,
    // so the check must not refuse them.
    let Some(other) = scratch_file_opened(4096, flags) else {
        return;
    };
    reject_root_alias(root, other).unwrap();

    close(other).unwrap();
    close(root).unwrap();
    close(scratch).unwrap();
}
