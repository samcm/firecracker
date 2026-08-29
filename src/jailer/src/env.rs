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
use crate::{BOOTSTRAP_FILENO, JailerError, ROOT_FILENO, UFFD_FILENO, close_inherited_fds};

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
    if fd > BOOTSTRAP_FILENO {
        return Ok(fd);
    }
    // SAFETY: `F_DUPFD` returns the lowest free descriptor number greater than or equal to its
    // argument, and the return code is checked.
    let moved = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_DUPFD, BOOTSTRAP_FILENO + 1) })
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
    bootstrap_fd: Option<RawFd>,
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

        let bootstrap_fd = arguments
            .single_value("bootstrap-fd")
            .map(|fd| {
                fd.parse::<RawFd>()
                    .map_err(|_| JailerError::BootstrapFdArgument(fd.to_owned()))
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
            bootstrap_fd,
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
    /// [`ROOT_FILENO`] and, when the caller passes one, the bootstrap image as
    /// [`BOOTSTRAP_FILENO`]. Every passed descriptor is moved clear of the reserved slots first,
    /// because the caller is free to pass them in at any number.
    fn install_inherited_fds(&self) -> Result<(), JailerError> {
        let uffd_device = open_userfaultfd_device()?;

        validate_image_fd("--root-fd", self.root_fd, self.uid())?;
        let root_fd = move_off_reserved_fds(self.root_fd)?;

        let bootstrap_fd = match self.bootstrap_fd {
            Some(fd) => {
                validate_image_fd("--bootstrap-fd", fd, self.uid())?;
                Some(move_off_reserved_fds(fd)?)
            }
            None => None,
        };

        place_fd(uffd_device, UFFD_FILENO)?;
        place_fd(root_fd, ROOT_FILENO)?;
        match bootstrap_fd {
            Some(fd) => place_fd(fd, BOOTSTRAP_FILENO),
            None => Ok(()),
        }
    }

    /// Last descriptor number Firecracker is given, which is the highest one that survives exec.
    fn highest_reserved_fd(&self) -> libc::c_int {
        match self.bootstrap_fd {
            Some(_) => BOOTSTRAP_FILENO,
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

    Ok(())
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
        assert_eq!(env.bootstrap_fd, None);
        assert_eq!(env.highest_reserved_fd(), ROOT_FILENO);
    }

    /// A bootstrap image is optional, and reserving fd 5 follows from passing one.
    #[test]
    fn test_bootstrap_fd_reserves_its_slot_only_when_passed() {
        let env = new_env(&cmdline(
            "7",
            &["--chroot-base-dir", "/", "--bootstrap-fd", "8"],
        ))
        .unwrap();
        assert_eq!(env.bootstrap_fd, Some(8));
        assert_eq!(env.highest_reserved_fd(), BOOTSTRAP_FILENO);
    }

    #[test]
    fn test_bootstrap_fd_must_be_a_descriptor_number() {
        assert!(matches!(
            new_env(&cmdline(
                "7",
                &["--chroot-base-dir", "/", "--bootstrap-fd", "/dev/bootstrap"]
            )),
            Err(JailerError::BootstrapFdArgument(_))
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

    /// The bootstrap image is held to the same contract as the root image, reported under its own
    /// flag name so a caller can tell which descriptor it got wrong.
    #[test]
    fn test_validate_bootstrap_fd_holds_the_root_contract() {
        let sealed = memfd(4096, REQUIRED_IMAGE_SEALS);
        let read_only = reopen_read_only(sealed);
        validate_image_fd("--bootstrap-fd", read_only, other_uid()).unwrap();
        close(read_only).unwrap();

        assert!(matches!(
            validate_image_fd("--bootstrap-fd", sealed, other_uid()),
            Err(JailerError::ImageFdNotReadOnly("--bootstrap-fd"))
        ));
        close(sealed).unwrap();

        let unsealed = memfd(4096, libc::F_SEAL_WRITE);
        let read_only = reopen_read_only(unsealed);
        assert!(matches!(
            validate_image_fd("--bootstrap-fd", read_only, other_uid()),
            Err(JailerError::ImageFdNotSealed("--bootstrap-fd"))
        ));
        close(read_only).unwrap();
        close(unsealed).unwrap();

        let empty = memfd(0, REQUIRED_IMAGE_SEALS);
        let read_only = reopen_read_only(empty);
        assert!(matches!(
            validate_image_fd("--bootstrap-fd", read_only, other_uid()),
            Err(JailerError::ImageFdEmpty("--bootstrap-fd"))
        ));
        close(read_only).unwrap();
        close(empty).unwrap();

        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
        assert!(matches!(
            validate_image_fd("--bootstrap-fd", pipe[0], other_uid()),
            Err(JailerError::ImageFdNotRegularFile("--bootstrap-fd"))
        ));
        close(pipe[0]).unwrap();
        close(pipe[1]).unwrap();

        let owner = jail_owner_uid();
        let regular = regular_image_owned_by(owner, 0o400, 4096);
        validate_image_fd("--bootstrap-fd", regular, other_uid()).unwrap();
        assert!(matches!(
            validate_image_fd("--bootstrap-fd", regular, owner),
            Err(JailerError::ImageFdOwnedByJailUid("--bootstrap-fd"))
        ));
        close(regular).unwrap();
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
}
