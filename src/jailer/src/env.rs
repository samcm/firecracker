// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io;
use std::io::Write;
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
use crate::{JailerError, ROOT_FILENO, SCRATCH_FILENO, close_inherited_fds};

const DEV_KVM: &CStr = c"/dev/kvm";
const DEV_KVM_MAJOR: u32 = 10;
const DEV_KVM_MINOR: u32 = 232;

const DEV_NET_TUN: &CStr = c"/dev/net/tun";
const DEV_NET_TUN_MAJOR: u32 = 10;
const DEV_NET_TUN_MINOR: u32 = 200;

const DEV_URANDOM: &CStr = c"/dev/urandom";
const DEV_URANDOM_MAJOR: u32 = 1;
const DEV_URANDOM_MINOR: u32 = 9;

const FOLDER_HIERARCHY: [&str; 4] = ["/", "/dev", "/dev/net", "/run"];
const FOLDER_PERMISSIONS: u32 = 0o700;
const PID_FILE_EXTENSION: &str = ".pid";

/// What the drive slots hold until pagemaster hands Firecracker its drive images.
const DEV_NULL: &CStr = c"/dev/null";

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

        let mut resource_limits = ResourceLimits::default();
        if let Some(args) = arguments.multiple_values("resource-limit") {
            Env::parse_resource_limits(&mut resource_limits, args)?;
        }

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

    /// Reserves the descriptor numbers drives are backed by. Firecracker starts before the sandbox
    /// it will run is known, so its drive images arrive later over the memory channel and replace
    /// these placeholders in place. Holding the numbers from the start means no descriptor
    /// Firecracker opens in the meantime can take one, and a drive configured before its image
    /// arrives names a read-only empty device that every drive contract refuses.
    fn reserve_drive_slots(&self) -> Result<(), JailerError> {
        // SAFETY: `DEV_NULL` is a NUL-terminated path and the return code is checked.
        let placeholder = SyscallReturnCode(unsafe {
            libc::open(DEV_NULL.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        })
        .into_result()
        .map_err(JailerError::ReserveDriveSlot)?;
        // The placeholder is moved clear of both slots first, so `dup2` always renumbers and the
        // copies never carry the close-on-exec flag the original was opened with.
        let placeholder = move_off_reserved_fds(placeholder)?;
        dup2(placeholder, ROOT_FILENO)?;
        dup2(placeholder, SCRATCH_FILENO)?;
        close(placeholder)
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

        self.reserve_drive_slots()?;
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
        // Setup may reuse the hole at fd 3. Leave only the contracted descriptors at exec.
        close_inherited_fds()?;
        Err(JailerError::Exec(self.exec_command(chroot_exec_file)))
    }
}

#[cfg(test)]
mod tests;
