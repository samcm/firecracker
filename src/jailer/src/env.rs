// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, fchown};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio, id};

use utils::arg_parser::UtilsArgParserError::MissingValue;
use utils::time::{ClockType, get_time_us};
use utils::{arg_parser, validators};
use vmm_sys_util::syscall::SyscallReturnCode;

use crate::chroot::chroot;
use crate::resource_limits::{FSIZE_ARG, MEMLOCK_ARG, NO_FILE_ARG, ResourceLimits};
use crate::{JailerError, ROOT_FILENO, SCRATCH_FILENO, UFFD_FILENO, close_inherited_fds};

const DEV_KVM: &CStr = c"/dev/kvm";
const DEV_KVM_MAJOR: u32 = 10;
const DEV_KVM_MINOR: u32 = 232;

const DEV_NET_TUN: &CStr = c"/dev/net/tun";
const DEV_NET_TUN_MAJOR: u32 = 10;
const DEV_NET_TUN_MINOR: u32 = 200;

const DEV_URANDOM: &CStr = c"/dev/urandom";
const DEV_URANDOM_MAJOR: u32 = 1;
const DEV_URANDOM_MINOR: u32 = 9;

const DEV_USERFAULTFD: &CStr = c"/dev/userfaultfd";

const FOLDER_HIERARCHY: [&str; 4] = ["/", "/dev", "/dev/net", "/run"];
const FOLDER_PERMISSIONS: u32 = 0o700;
const PID_FILE_EXTENSION: &str = ".pid";

/// Filesystem magic of the internal shmem mount every memfd lives on.
const TMPFS_MAGIC: u64 = 0x0102_1994;
/// Filesystem magic of hugetlbfs, where a memfd created with `MFD_HUGETLB` lives.
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const REQUIRED_IMAGE_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
/// Permission bits that grant write access to an image, none of which a regular one may carry.
const IMAGE_WRITE_MODE_BITS: libc::mode_t = libc::S_IWUSR | libc::S_IWGRP | libc::S_IWOTH;
/// Bits that change the meaning of an inode beyond its permissions. A block device image is
/// neither a program to gain privileges from nor a directory, so all three are refused.
const IMAGE_SPECIAL_MODE_BITS: libc::mode_t = libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX;

fn dup2(old_fd: RawFd, new_fd: RawFd) -> Result<(), JailerError> {
    // SAFETY: both arguments are descriptor numbers and the return code is checked.
    SyscallReturnCode(unsafe { libc::dup2(old_fd, new_fd) })
        .into_empty_result()
        .map_err(JailerError::Dup2)
}

fn close(fd: RawFd) -> Result<(), JailerError> {
    // SAFETY: `fd` is a descriptor this process owns and no longer uses.
    SyscallReturnCode(unsafe { libc::close(fd) })
        .into_empty_result()
        .map_err(JailerError::Close)
}

/// Opens the userfaultfd device Firecracker turns into its own userfaultfd. A userfaultfd is
/// bound to the memory map of the process that created it, so only the exec'd binary can create
/// one that its guest mappings can be registered on; access to this device node is the
/// permission that lets it.
fn open_userfaultfd_device() -> Result<RawFd, JailerError> {
    // SAFETY: the path is a static NUL-terminated string and the return code is checked.
    SyscallReturnCode(unsafe {
        libc::open(DEV_USERFAULTFD.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC)
    })
    .into_result()
    .map_err(JailerError::UserfaultfdDevice)
}

/// Moves `fd` past the descriptor numbers reserved for Firecracker, so that renumbering one of
/// them cannot overwrite the other. The copy is returned and the original is closed.
fn move_off_reserved_fds(fd: RawFd) -> Result<RawFd, JailerError> {
    if fd > SCRATCH_FILENO {
        return Ok(fd);
    }
    // SAFETY: `F_DUPFD` returns the lowest free descriptor number greater than or equal to its
    // argument, and the return code is checked.
    let moved = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_DUPFD, SCRATCH_FILENO + 1) })
        .into_result()
        .map_err(JailerError::Dup2)?;
    close(fd)?;
    Ok(moved)
}

/// Renumbers `fd` to `target` and makes sure the jailed binary inherits it: a descriptor that is
/// already at `target` keeps whatever `FD_CLOEXEC` it was opened with, so the flag is cleared
/// explicitly rather than relying on `dup2`.
fn place_fd(fd: RawFd, target: RawFd) -> Result<(), JailerError> {
    if fd != target {
        dup2(fd, target)?;
        close(fd)?;
    }
    // SAFETY: `target` is a descriptor this process owns and the return code is checked.
    SyscallReturnCode(unsafe { libc::fcntl(target, libc::F_SETFD, 0) })
        .into_empty_result()
        .map_err(JailerError::Dup2)
}

#[derive(Debug)]
pub struct Env {
    id: String,
    chroot_dir: PathBuf,
    exec_file_path: PathBuf,
    uid: u32,
    gid: u32,
    netns: Option<String>,
    start_time_us: u64,
    start_time_cpu_us: u64,
    jailer_cpu_time_us: u64,
    extra_args: Vec<String>,
    resource_limits: ResourceLimits,
    root_fd: RawFd,
    scratch_fd: Option<RawFd>,
    cgroup_join: Option<PathBuf>,
}

impl Env {
    pub fn new(
        arguments: &arg_parser::Arguments,
        start_time_us: u64,
        start_time_cpu_us: u64,
    ) -> Result<Self, JailerError> {
        let id = arguments
            .single_value("id")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("id".to_string())))?;

        validators::validate_instance_id(id).map_err(JailerError::InvalidInstanceId)?;

        let exec_file = arguments
            .single_value("exec-file")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("exec-file".to_string())))?;
        let (exec_file_path, exec_file_name) = Env::validate_exec_file(exec_file)?;

        let chroot_base = arguments.single_value("chroot-base-dir").ok_or_else(|| {
            JailerError::ArgumentParsing(MissingValue("chroot-base-dir".to_string()))
        })?;
        let mut chroot_dir = fs::canonicalize(chroot_base)
            .map_err(|err| JailerError::Canonicalize(PathBuf::from(&chroot_base), err))?;

        if !chroot_dir.is_dir() {
            return Err(JailerError::NotADirectory(chroot_dir));
        }

        chroot_dir.push(&exec_file_name);
        chroot_dir.push(id);
        chroot_dir.push("root");

        let uid_str = arguments
            .single_value("uid")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("uid".to_string())))?;
        let uid = uid_str
            .parse::<u32>()
            .map_err(|_| JailerError::Uid(uid_str.to_owned()))?;

        let gid_str = arguments
            .single_value("gid")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("gid".to_string())))?;
        let gid = gid_str
            .parse::<u32>()
            .map_err(|_| JailerError::Gid(gid_str.to_owned()))?;

        let netns = arguments.single_value("netns").cloned();

        let root_fd_str = arguments
            .single_value("root-fd")
            .ok_or_else(|| JailerError::ArgumentParsing(MissingValue("root-fd".to_string())))?;
        let root_fd = root_fd_str
            .parse::<RawFd>()
            .map_err(|_| JailerError::RootFdArgument(root_fd_str.to_owned()))?;

        let scratch_fd = arguments
            .single_value("scratch-fd")
            .map(|fd| {
                fd.parse::<RawFd>()
                    .map_err(|_| JailerError::ScratchFdArgument(fd.to_owned()))
            })
            .transpose()?;

        let mut resource_limits = ResourceLimits::default();
        if let Some(args) = arguments.multiple_values("resource-limit") {
            Env::parse_resource_limits(&mut resource_limits, args)?;
        }

        let cgroup_join = arguments
            .single_value("cgroup-join")
            .map(|path| {
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    return Err(JailerError::CgroupJoinNotAbsolute);
                }
                Ok(path)
            })
            .transpose()?;

        Ok(Env {
            id: id.to_owned(),
            chroot_dir,
            exec_file_path,
            uid,
            gid,
            netns,
            start_time_us,
            start_time_cpu_us,
            jailer_cpu_time_us: 0,
            extra_args: arguments.extra_args(),
            resource_limits,
            root_fd,
            scratch_fd,
            cgroup_join,
        })
    }

    pub fn chroot_dir(&self) -> &Path {
        self.chroot_dir.as_path()
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    fn validate_exec_file(exec_file: &str) -> Result<(PathBuf, String), JailerError> {
        let exec_file_path = fs::canonicalize(exec_file)
            .map_err(|err| JailerError::Canonicalize(PathBuf::from(exec_file), err))?;

        if !exec_file_path.is_file() {
            return Err(JailerError::NotAFile(exec_file_path));
        }

        let exec_file_name = exec_file_path
            .file_name()
            .ok_or_else(|| JailerError::ExtractFileName(exec_file_path.clone()))?
            .to_str()
            .unwrap()
            .to_string();

        Ok((exec_file_path, exec_file_name))
    }

    fn parse_resource_limits(
        resource_limits: &mut ResourceLimits,
        args: &[String],
    ) -> Result<(), JailerError> {
        for arg in args {
            let (name, value) = arg
                .split_once('=')
                .ok_or_else(|| JailerError::ResLimitFormat(arg.to_string()))?;

            let limit_value = value
                .parse::<u64>()
                .map_err(|err| JailerError::ResLimitValue(value.to_string(), err.to_string()))?;
            match name {
                FSIZE_ARG => resource_limits.set_file_size(limit_value),
                NO_FILE_ARG => resource_limits.set_no_file(limit_value),
                MEMLOCK_ARG => resource_limits.set_memlock(limit_value),
                _ => return Err(JailerError::ResLimitArgument(name.to_string())),
            }
        }
        Ok(())
    }

    fn save_exec_file_pid(
        &mut self,
        pid: i32,
        chroot_exec_file: PathBuf,
    ) -> Result<(), JailerError> {
        let chroot_exec_file_str = chroot_exec_file
            .to_str()
            .ok_or_else(|| JailerError::ExtractFileName(chroot_exec_file.clone()))?;
        let pid_file_path =
            PathBuf::from(format!("{}{}", chroot_exec_file_str, PID_FILE_EXTENSION));
        let mut pid_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(pid_file_path.clone())
            .map_err(|err| JailerError::FileOpen(pid_file_path.clone(), err))?;

        write!(pid_file, "{}", pid).map_err(|err| JailerError::Write(pid_file_path, err))
    }

    fn mknod_and_own_dev(
        &self,
        dev_path: &CStr,
        dev_major: u32,
        dev_minor: u32,
    ) -> Result<(), JailerError> {
        // SAFETY: `dev_path` is a NUL-terminated path whose storage remains valid for this call,
        // and the device major and minor values are passed by value.
        SyscallReturnCode(unsafe {
            libc::mknod(
                dev_path.as_ptr(),
                libc::S_IFCHR | libc::S_IRUSR | libc::S_IWUSR,
                libc::makedev(dev_major, dev_minor),
            )
        })
        .into_empty_result()
        .map_err(|err| JailerError::MknodDev(err, dev_path.to_str().unwrap().to_owned()))?;

        // SAFETY: `dev_path` is a NUL-terminated path whose storage remains valid for this call.
        SyscallReturnCode(unsafe { libc::chown(dev_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|err| {
                JailerError::ChangeFileOwner(PathBuf::from(dev_path.to_str().unwrap()), err)
            })
    }

    fn setup_jailed_folder(&self, folder: impl AsRef<Path>) -> Result<(), JailerError> {
        let folder_path = folder.as_ref();
        fs::create_dir_all(folder_path)
            .map_err(|err| JailerError::CreateDir(folder_path.to_owned(), err))?;
        fs::set_permissions(folder_path, Permissions::from_mode(FOLDER_PERMISSIONS))
            .map_err(|err| JailerError::Chmod(folder_path.to_owned(), err))?;

        let c_path = CString::new(folder_path.to_str().unwrap()).unwrap();
        // SAFETY: `c_path` owns a NUL-terminated copy of `folder_path` for the duration of the call.
        SyscallReturnCode(unsafe { libc::chown(c_path.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|err| JailerError::ChangeFileOwner(folder_path.to_owned(), err))
    }

    fn copy_exec_to_chroot(&mut self) -> Result<OsString, JailerError> {
        let exec_file_name = self
            .exec_file_path
            .file_name()
            .ok_or_else(|| JailerError::ExtractFileName(self.exec_file_path.clone()))?;
        let jailer_exec_file_path = self.chroot_dir.join(exec_file_name);

        let mut src_file = OpenOptions::new()
            .read(true)
            .open(&self.exec_file_path)
            .map_err(|err| JailerError::Open(self.exec_file_path.clone(), err))?;
        let src_file_metadata = src_file
            .metadata()
            .map_err(|err| JailerError::Metadata(self.exec_file_path.clone(), err))?;
        let src_file_mode = src_file_metadata.mode();
        let mut dst_file = OpenOptions::new()
            .write(true)
            .create(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(src_file_mode)
            .open(&jailer_exec_file_path)
            .map_err(|err| JailerError::Open(jailer_exec_file_path.clone(), err))?;
        let dst_file_metadata = dst_file
            .metadata()
            .map_err(|err| JailerError::Metadata(jailer_exec_file_path.clone(), err))?;
        if 1 < dst_file_metadata.nlink() {
            return Err(JailerError::HardLink(jailer_exec_file_path.clone()));
        }

        fchown(&dst_file, Some(self.uid()), Some(self.gid()))
            .map_err(|err| JailerError::ChangeFileOwner(jailer_exec_file_path.clone(), err))?;

        _ = std::io::copy(&mut src_file, &mut dst_file).map_err(|err| {
            JailerError::Copy(
                self.exec_file_path.clone(),
                jailer_exec_file_path.clone(),
                err,
            )
        })?;

        Ok(exec_file_name.to_owned())
    }

    fn join_netns(path: &str) -> Result<(), JailerError> {
        let netns =
            File::open(path).map_err(|err| JailerError::FileOpen(PathBuf::from(path), err))?;

        // SAFETY: `netns` is an open namespace descriptor owned by this function until it returns.
        SyscallReturnCode(unsafe { libc::setns(netns.as_raw_fd(), libc::CLONE_NEWNET) })
            .into_empty_result()
            .map_err(JailerError::SetNetNs)
    }

    fn join_cgroup(&self) -> Result<(), JailerError> {
        let Some(path) = &self.cgroup_join else {
            return Ok(());
        };
        let procs = path.join("cgroup.procs");
        // No fork happens between here and the exec, so this process is the one Firecracker
        // runs as.
        fs::write(&procs, id().to_string()).map_err(|err| JailerError::CgroupJoin(procs, err))
    }

    /// Hands Firecracker the userfaultfd device as [`UFFD_FILENO`], the root image as
    /// [`ROOT_FILENO`] and, when the caller passes one, the writable scratch disk as
    /// [`SCRATCH_FILENO`]. Every passed descriptor is moved clear of the reserved slots first,
    /// because the caller is free to pass them in at any number.
    fn install_inherited_fds(&self) -> Result<(), JailerError> {
        let uffd_device = open_userfaultfd_device()?;

        validate_image_fd("--root-fd", self.root_fd, self.uid())?;
        if let Some(fd) = self.scratch_fd {
            validate_scratch_fd("--scratch-fd", fd)?;
            reject_root_alias(self.root_fd, fd)?;
        }

        let root_fd = move_off_reserved_fds(self.root_fd)?;
        let scratch_fd = self.scratch_fd.map(move_off_reserved_fds).transpose()?;

        place_fd(uffd_device, UFFD_FILENO)?;
        place_fd(root_fd, ROOT_FILENO)?;
        match scratch_fd {
            Some(fd) => place_fd(fd, SCRATCH_FILENO),
            None => Ok(()),
        }
    }

    /// Last descriptor number Firecracker is given, which is the highest one that survives exec.
    fn highest_reserved_fd(&self) -> libc::c_int {
        match self.scratch_fd {
            Some(_) => SCRATCH_FILENO,
            None => ROOT_FILENO,
        }
    }

    fn exec_command(&self, chroot_exec_file: PathBuf) -> io::Error {
        Command::new(chroot_exec_file)
            .args(["--id", &self.id])
            .args(["--start-time-us", &self.start_time_us.to_string()])
            .args([
                "--start-time-cpu-us",
                &get_time_us(ClockType::ProcessCpu).to_string(),
            ])
            .args(["--parent-cpu-time-us", &self.jailer_cpu_time_us.to_string()])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .uid(self.uid())
            .gid(self.gid())
            .args(&self.extra_args)
            .exec()
    }

    #[cfg(target_arch = "aarch64")]
    fn copy_cache_info(&self) -> Result<(), JailerError> {
        use crate::{readln_special, to_cstring, writeln_special};

        const HOST_CACHE_INFO: &str = "/sys/devices/system/cpu/cpu0/cache";
        const MAX_CACHE_LEVEL: u8 = 7;
        const FOLDER_HIERARCHY: [&str; 6] = [
            "size",
            "level",
            "type",
            "shared_cpu_map",
            "coherency_line_size",
            "number_of_sets",
        ];

        let jailer_cache_dir =
            Path::new(self.chroot_dir()).join("sys/devices/system/cpu/cpu0/cache/");
        fs::create_dir_all(&jailer_cache_dir)
            .map_err(|err| JailerError::CreateDir(jailer_cache_dir.to_owned(), err))?;

        for index in 0..(MAX_CACHE_LEVEL + 1) {
            let index_folder = format!("index{}", index);
            let host_path = PathBuf::from(HOST_CACHE_INFO).join(&index_folder);

            if fs::metadata(&host_path).is_err() {
                break;
            }

            let jailer_path = jailer_cache_dir.join(&index_folder);
            fs::create_dir_all(&jailer_path)
                .map_err(|err| JailerError::CreateDir(jailer_path.to_owned(), err))?;

            for entry in FOLDER_HIERARCHY.iter() {
                let host_cache_file = host_path.join(entry);
                let jailer_cache_file = jailer_path.join(entry);

                if let Ok(line) = readln_special(&host_cache_file) {
                    writeln_special(&jailer_cache_file, line)?;

                    let dest_path_cstr = to_cstring(&jailer_cache_file)?;
                    // SAFETY: `dest_path_cstr` owns a NUL-terminated path valid for this call.
                    SyscallReturnCode(unsafe {
                        libc::chown(dest_path_cstr.as_ptr(), self.uid(), self.gid())
                    })
                    .into_empty_result()
                    .map_err(|err| {
                        JailerError::ChangeFileOwner(jailer_cache_file.to_owned(), err)
                    })?;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn copy_midr_el1_info(&self) -> Result<(), JailerError> {
        use crate::{readln_special, to_cstring, writeln_special};

        const HOST_MIDR_EL1_INFO: &str = "/sys/devices/system/cpu/cpu0/regs/identification";

        let jailer_midr_el1_directory =
            Path::new(self.chroot_dir()).join("sys/devices/system/cpu/cpu0/regs/identification/");
        fs::create_dir_all(&jailer_midr_el1_directory)
            .map_err(|err| JailerError::CreateDir(jailer_midr_el1_directory.to_owned(), err))?;

        let host_midr_el1_file = PathBuf::from(format!("{}/midr_el1", HOST_MIDR_EL1_INFO));
        let jailer_midr_el1_file = jailer_midr_el1_directory.join("midr_el1");

        let line = readln_special(&host_midr_el1_file)?;
        writeln_special(&jailer_midr_el1_file, line)?;

        let dest_path_cstr = to_cstring(&jailer_midr_el1_file)?;
        // SAFETY: `dest_path_cstr` owns a NUL-terminated path valid for this call.
        SyscallReturnCode(unsafe { libc::chown(dest_path_cstr.as_ptr(), self.uid(), self.gid()) })
            .into_empty_result()
            .map_err(|err| JailerError::ChangeFileOwner(jailer_midr_el1_file.to_owned(), err))?;

        Ok(())
    }

    pub fn run(mut self) -> Result<(), JailerError> {
        let exec_file_name = self.copy_exec_to_chroot()?;
        let chroot_exec_file = PathBuf::from("/").join(exec_file_name);

        if let Some(ref path) = self.netns {
            Env::join_netns(path)?;
        }

        self.install_inherited_fds()?;
        self.join_cgroup()?;
        self.resource_limits.install()?;
        close_inherited_fds(self.highest_reserved_fd())?;

        #[cfg(target_arch = "aarch64")]
        self.copy_cache_info()?;
        #[cfg(target_arch = "aarch64")]
        self.copy_midr_el1_info()?;

        chroot(self.chroot_dir())?;

        FOLDER_HIERARCHY
            .iter()
            .try_for_each(|f| self.setup_jailed_folder(f))?;

        self.mknod_and_own_dev(DEV_NET_TUN, DEV_NET_TUN_MAJOR, DEV_NET_TUN_MINOR)?;
        self.mknod_and_own_dev(DEV_KVM, DEV_KVM_MAJOR, DEV_KVM_MINOR)?;
        let _ = self.mknod_and_own_dev(DEV_URANDOM, DEV_URANDOM_MAJOR, DEV_URANDOM_MINOR);

        self.jailer_cpu_time_us = get_time_us(ClockType::ProcessCpu) - self.start_time_cpu_us;
        self.save_exec_file_pid(id().try_into().unwrap(), chroot_exec_file.clone())?;
        Err(JailerError::Exec(self.exec_command(chroot_exec_file)))
    }
}

/// Checks that `fd` is a descriptor the supervisor is contracted to pass: a readable, read-only,
/// non-empty regular file holding a block device image whose bytes the jail cannot change. The
/// image itself is never read here.
///
/// Two kinds of descriptor satisfy that contract, told apart by whether the inode answers
/// `F_GET_SEALS`:
///
/// * A sealed memfd proves immutability in the kernel. The seals hold for every descriptor to the
///   inode, so no process changes the bytes, and no process needs to be trusted not to.
/// * A regular file cannot prove that much. Byte stability of a regular image is the
///   responsibility of the node or cache owner that published it, and that responsibility is not
///   transferred to the jailer by any check below. What the jailer does prove is the part it owns:
///   the confined process cannot obtain write access to the inode, neither through the inherited
///   descriptor, nor by chmod'ing a file it owns, nor through a setuid or setgid transition. None
///   of that holds for a jail that keeps uid 0, which is why that jail is refused this arm.
fn validate_image_fd(flag: &'static str, fd: RawFd, jail_uid: u32) -> Result<(), JailerError> {
    // SAFETY: `F_GETFL` writes nothing and the return code is checked.
    let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
        .into_result()
        .map_err(|err| JailerError::ImageFdInspect(flag, err))?;
    // An `O_PATH` descriptor reports an access mode of `O_RDONLY` while referring to the inode
    // without granting any read at all, so it is rejected explicitly.
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(JailerError::ImageFdNotReadOnly(flag));
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
    SyscallReturnCode(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })
        .into_empty_result()
        .map_err(|err| JailerError::ImageFdInspect(flag, err))?;
    // SAFETY: `fstat` returned success, so it initialized the whole struct.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(JailerError::ImageFdNotRegularFile(flag));
    }
    if stat.st_size == 0 {
        return Err(JailerError::ImageFdEmpty(flag));
    }

    // Every shmem and hugetlbfs inode answers `F_GET_SEALS`, memfd or not, and every other
    // filesystem fails it with EINVAL. That is what selects the arm: an image on tmpfs or
    // hugetlbfs is held to the sealed memfd contract even when it was created as an ordinary
    // file, so a plain tmpfs file is refused for the seals it does not carry.
    // SAFETY: `F_GET_SEALS` writes nothing and the return code is checked.
    match SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) }).into_result() {
        Ok(seals) => validate_sealed_image(flag, fd, seals),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {
            validate_unwritable_image(flag, &stat, jail_uid)
        }
        Err(err) => Err(JailerError::ImageFdInspect(flag, err)),
    }
}

/// Holds an image on a sealing filesystem to the memfd contract: the seals that make the bytes
/// unchangeable for every holder of the inode, plus the identity of the two filesystems a memfd
/// can live on.
fn validate_sealed_image(
    flag: &'static str,
    fd: RawFd,
    seals: libc::c_int,
) -> Result<(), JailerError> {
    // Seals only ever remove abilities, and a kernel with vm.memfd_noexec enabled adds
    // F_SEAL_EXEC by itself, so anything beyond the required set is accepted.
    if seals & REQUIRED_IMAGE_SEALS != REQUIRED_IMAGE_SEALS {
        return Err(JailerError::ImageFdNotSealed(flag));
    }

    // A memfd lives on the internal shmem mount or on hugetlbfs and nowhere else. Together with
    // the seals above this proves identity without procfs, which no jail is required to have.
    // Anything else that answers `F_GET_SEALS`, such as a file on a mounted tmpfs, reaches here
    // and is refused unless it carries the same seals.
    let mut fs_stat = MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `fs_stat` is a valid, aligned, sufficiently sized allocation for a `libc::statfs`.
    SyscallReturnCode(unsafe { libc::fstatfs(fd, fs_stat.as_mut_ptr()) })
        .into_empty_result()
        .map_err(|err| JailerError::ImageFdInspect(flag, err))?;
    // SAFETY: `fstatfs` returned success, so it initialized the whole struct.
    let fs_stat = unsafe { fs_stat.assume_init() };
    // `f_type` is a signed word on some targets and an unsigned one on others, so both sides are
    // widened to a type that holds either representation exactly.
    let magic = i128::from(fs_stat.f_type);
    if magic != i128::from(TMPFS_MAGIC) && magic != i128::from(HUGETLBFS_MAGIC) {
        return Err(JailerError::ImageFdSealedNotShmem(flag));
    }

    Ok(())
}

/// Holds an ordinary regular image to the property the jailer can enforce on it: the jailed uid
/// has no path to write access. That property only exists below root. A jail that keeps uid 0
/// keeps `CAP_DAC_OVERRIDE` and `CAP_FOWNER`, which defeat both the permission bits and the
/// ownership of the inode, so uid 0 is held to the sealed memfd arm instead. Below root, write
/// permission for anyone is refused outright rather than reasoned about, the setuid, setgid and
/// sticky bits are refused because an image is not a program and not a directory, and an image
/// the jail owns is refused because ownership carries the right to chmod it writable after this
/// check.
fn validate_unwritable_image(
    flag: &'static str,
    stat: &libc::stat,
    jail_uid: u32,
) -> Result<(), JailerError> {
    if jail_uid == 0 {
        return Err(JailerError::ImageFdRegularFileAtRootUid(flag));
    }
    if stat.st_mode & IMAGE_WRITE_MODE_BITS != 0 {
        return Err(JailerError::ImageFdWritablePermissions(flag));
    }
    if stat.st_mode & IMAGE_SPECIAL_MODE_BITS != 0 {
        return Err(JailerError::ImageFdSpecialModeBits(flag));
    }
    if stat.st_uid == jail_uid {
        return Err(JailerError::ImageFdOwnedByJailUid(flag));
    }

    reject_writable_stream_aliases(flag, stat)
}

/// Refuses a regular image that a descriptor surviving the exec also holds open for writing.
///
/// The checks above prove the jail cannot obtain write access through the inherited image
/// descriptor itself, nor through the permissions or the ownership of the inode. A second open file
/// description on the same inode is neither of those: it carries its own access mode, granted
/// before this process narrowed anything, and `fstat` on the image says nothing about it.
///
/// The standard streams are the whole set of descriptors that reach Firecracker without the jailer
/// choosing what they refer to: `close_inherited_fds` keeps them so the jailed process can log,
/// [`UFFD_FILENO`] is a device the jailer opens itself, and [`ROOT_FILENO`] and
/// [`SCRATCH_FILENO`] are overwritten by the descriptors it places there or closed with the rest.
/// So a caller that points a standard stream at the image inode with an access mode that includes
/// writing is the one way a writable alias survives into the jail, and that is refused here. The
/// scratch disk is not held to this: the jail is meant to write it.
fn reject_writable_stream_aliases(
    flag: &'static str,
    stat: &libc::stat,
) -> Result<(), JailerError> {
    for fd in libc::STDIN_FILENO..=libc::STDERR_FILENO {
        let mut alias = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `alias` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
        match SyscallReturnCode(unsafe { libc::fstat(fd, alias.as_mut_ptr()) }).into_empty_result()
        {
            Ok(()) => {}
            // A standard stream the caller left closed refers to no inode, so it aliases nothing.
            Err(err) if err.raw_os_error() == Some(libc::EBADF) => continue,
            Err(err) => return Err(JailerError::ImageFdInspect(flag, err)),
        }
        // SAFETY: `fstat` returned success, so it initialized the whole struct.
        let alias = unsafe { alias.assume_init() };
        if alias.st_dev != stat.st_dev || alias.st_ino != stat.st_ino {
            continue;
        }

        // SAFETY: `F_GETFL` writes nothing and the return code is checked.
        let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
            .into_result()
            .map_err(|err| JailerError::ImageFdInspect(flag, err))?;
        // An `O_PATH` descriptor grants no access at all, whatever access mode it reports.
        if flags & libc::O_PATH == 0 && flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(JailerError::ImageFdWritableStreamAlias(flag, fd));
        }
    }

    Ok(())
}

/// Checks that `fd` is the descriptor the supervisor is contracted to pass for the scratch disk:
/// a non-empty regular file on the node's filesystem, opened read-write for direct I/O. The inode
/// is meant to be writable by the jail, so no permission, ownership or mode bit is read.
fn validate_scratch_fd(flag: &'static str, fd: RawFd) -> Result<(), JailerError> {
    // SAFETY: `F_GETFL` writes nothing and the return code is checked.
    let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
        .into_result()
        .map_err(|err| JailerError::ScratchFdInspect(flag, err))?;
    // An `O_PATH` descriptor reports an access mode of `O_RDONLY` while referring to the inode
    // without granting any access at all, so it is rejected explicitly.
    if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDWR {
        return Err(JailerError::ScratchFdNotReadWrite(flag));
    }
    // `O_APPEND` moves every write to the end of the file, wherever the guest aimed it.
    if flags & libc::O_APPEND != 0 {
        return Err(JailerError::ScratchFdAppend(flag));
    }

    let stat = inode_of(fd).map_err(|err| JailerError::ScratchFdInspect(flag, err))?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(JailerError::ScratchFdNotRegularFile(flag));
    }
    if stat.st_size == 0 {
        return Err(JailerError::ScratchFdEmpty(flag));
    }

    // Every shmem and hugetlbfs inode answers `F_GET_SEALS` and every other filesystem fails it
    // with EINVAL, so an answer means the disk is the node's memory and not its filesystem.
    // SAFETY: `F_GET_SEALS` writes nothing and the return code is checked.
    match SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) }).into_result() {
        Ok(_) => return Err(JailerError::ScratchFdSealingFilesystem(flag)),
        Err(err) if err.raw_os_error() == Some(libc::EINVAL) => {}
        Err(err) => return Err(JailerError::ScratchFdInspect(flag, err)),
    }

    // The guest's reads and writes reach the disk itself, so the host holds no second copy of a
    // sandbox's data in its page cache.
    if flags & libc::O_DIRECT == 0 {
        return Err(JailerError::ScratchFdNotDirect(flag));
    }

    Ok(())
}

/// Refuses a scratch descriptor that names the root image inode. A caller could open one inode
/// twice, read-only for the root slot and writable for the scratch slot, and the guest would
/// reach the immutable root image through the writes it makes to its own disk.
fn reject_root_alias(root_fd: RawFd, scratch_fd: RawFd) -> Result<(), JailerError> {
    let root = inode_of(root_fd).map_err(|err| JailerError::ImageFdInspect("--root-fd", err))?;
    let scratch =
        inode_of(scratch_fd).map_err(|err| JailerError::ScratchFdInspect("--scratch-fd", err))?;
    if root.st_dev == scratch.st_dev && root.st_ino == scratch.st_ino {
        return Err(JailerError::ScratchFdAliasesRoot);
    }

    Ok(())
}

/// The inode `fd` refers to.
fn inode_of(fd: RawFd) -> Result<libc::stat, io::Error> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
    SyscallReturnCode(unsafe { libc::fstat(fd, stat.as_mut_ptr()) }).into_empty_result()?;
    // SAFETY: `fstat` returned success, so it initialized the whole struct.
    Ok(unsafe { stat.assume_init() })
}

#[cfg(test)]
mod tests {
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
}
