// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
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
use crate::{JailerError, ROOT_FILENO, UFFD_FILENO, close_inherited_fds};

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

/// A memfd link target always starts with this prefix, regardless of the name it was created
/// with.
const MEMFD_LINK_PREFIX: &[u8] = b"/memfd:";
const REQUIRED_ROOT_SEALS: libc::c_int =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;

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
    if fd > ROOT_FILENO {
        return Ok(fd);
    }
    // SAFETY: `F_DUPFD` returns the lowest free descriptor number greater than or equal to its
    // argument, and the return code is checked.
    let moved = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_DUPFD, ROOT_FILENO + 1) })
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

    /// Hands Firecracker the userfaultfd device as [`UFFD_FILENO`] and the sealed root image as
    /// [`ROOT_FILENO`]. The root descriptor is moved clear of both slots first, because the
    /// caller is free to pass it in at either of them.
    fn install_inherited_fds(&self) -> Result<(), JailerError> {
        let uffd_device = open_userfaultfd_device()?;

        validate_root_fd(self.root_fd)?;
        let root_fd = move_off_reserved_fds(self.root_fd)?;

        place_fd(uffd_device, UFFD_FILENO)?;
        place_fd(root_fd, ROOT_FILENO)
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
        close_inherited_fds()?;

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

/// Checks that `fd` is the descriptor the sandbox is contracted to pass: a sealed, read-only,
/// non-empty memfd holding the root block device image. The image itself is never read here.
fn validate_root_fd(fd: RawFd) -> Result<(), JailerError> {
    // SAFETY: `F_GETFL` writes nothing and the return code is checked.
    let flags = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GETFL) })
        .into_result()
        .map_err(JailerError::RootFdInspect)?;
    if flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(JailerError::RootFdNotReadOnly);
    }

    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` is a valid, aligned, sufficiently sized allocation for a `libc::stat`.
    SyscallReturnCode(unsafe { libc::fstat(fd, stat.as_mut_ptr()) })
        .into_empty_result()
        .map_err(JailerError::RootFdInspect)?;
    // SAFETY: `fstat` returned success, so it initialized the whole struct.
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(JailerError::RootFdNotMemfd);
    }
    if stat.st_size == 0 {
        return Err(JailerError::RootFdEmpty);
    }

    // Only shmem-backed files answer `F_GET_SEALS`; anything else fails with EINVAL. Plain tmpfs
    // files answer it too, which is what the link target below rules out.
    // SAFETY: `F_GET_SEALS` writes nothing and the return code is checked.
    let seals = SyscallReturnCode(unsafe { libc::fcntl(fd, libc::F_GET_SEALS) })
        .into_result()
        .map_err(|err| match err.raw_os_error() {
            Some(libc::EINVAL) => JailerError::RootFdNotMemfd,
            _ => JailerError::RootFdInspect(err),
        })?;
    // Seals only ever remove abilities, and a kernel with vm.memfd_noexec enabled adds
    // F_SEAL_EXEC by itself, so anything beyond the required set is accepted.
    if seals & REQUIRED_ROOT_SEALS != REQUIRED_ROOT_SEALS {
        return Err(JailerError::RootFdNotSealed);
    }

    let link =
        fs::read_link(format!("/proc/self/fd/{}", fd)).map_err(JailerError::RootFdInspect)?;
    if !link.as_os_str().as_bytes().starts_with(MEMFD_LINK_PREFIX) {
        return Err(JailerError::RootFdNotMemfd);
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

    #[test]
    fn test_validate_root_fd_accepts_sealed_read_only_memfd() {
        let fd = memfd(4096, REQUIRED_ROOT_SEALS);
        let read_only = reopen_read_only(fd);

        validate_root_fd(read_only).unwrap();

        close(fd).unwrap();
        close(read_only).unwrap();
    }

    #[test]
    fn test_validate_root_fd_rejects_writable_memfd() {
        let fd = memfd(4096, REQUIRED_ROOT_SEALS);

        assert!(matches!(
            validate_root_fd(fd),
            Err(JailerError::RootFdNotReadOnly)
        ));

        close(fd).unwrap();
    }

    #[test]
    fn test_validate_root_fd_rejects_unsealed_memfd() {
        let fd = memfd(4096, libc::F_SEAL_WRITE);
        let read_only = reopen_read_only(fd);

        assert!(matches!(
            validate_root_fd(read_only),
            Err(JailerError::RootFdNotSealed)
        ));

        close(fd).unwrap();
        close(read_only).unwrap();
    }

    #[test]
    fn test_validate_root_fd_rejects_empty_memfd() {
        let fd = memfd(0, REQUIRED_ROOT_SEALS);
        let read_only = reopen_read_only(fd);

        assert!(matches!(
            validate_root_fd(read_only),
            Err(JailerError::RootFdEmpty)
        ));

        close(fd).unwrap();
        close(read_only).unwrap();
    }

    #[test]
    fn test_validate_root_fd_rejects_non_memfd() {
        let mut pipe = [-1; 2];
        assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);

        assert!(matches!(
            validate_root_fd(pipe[0]),
            Err(JailerError::RootFdNotMemfd)
        ));

        close(pipe[0]).unwrap();
        close(pipe[1]).unwrap();
    }
}
