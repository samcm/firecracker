// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CString, NulError, OsString};
use std::fmt::{Debug, Display};
use std::path::{Path, PathBuf};
use std::{fs, io};

use utils::arg_parser::{ArgParser, Argument, UtilsArgParserError};
use utils::time::{ClockType, get_time_us};
use utils::validators;
use vmm_sys_util::syscall::SyscallReturnCode;

use crate::env::Env;

mod chroot;
mod env;
mod resource_limits;

const JAILER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Descriptor Firecracker creates its userfaultfd from.
pub(crate) const UFFD_FILENO: libc::c_int = 3;
/// Descriptor Firecracker reads the read-only root block device image from.
pub(crate) const ROOT_FILENO: libc::c_int = 4;
/// Descriptor Firecracker reads the read-only bootstrap block device image from, when the caller
/// passes one.
pub(crate) const BOOTSTRAP_FILENO: libc::c_int = 5;

#[derive(Debug, thiserror::Error)]
pub enum JailerError {
    #[error("Failed to parse arguments: {0}")]
    ArgumentParsing(UtilsArgParserError),
    #[error("{}", format!("Failed to canonicalize path {:?}: {}", .0, .1).replace('\"', ""))]
    Canonicalize(PathBuf, io::Error),
    #[error("Failed to join cgroup {0}: {1}")]
    CgroupJoin(PathBuf, io::Error),
    #[error("--cgroup-join path must be absolute")]
    CgroupJoinNotAbsolute,
    #[error("Failed to change owner for {0}: {1}")]
    ChangeFileOwner(PathBuf, io::Error),
    #[error("Failed to chdir into chroot directory: {0}")]
    ChdirNewRoot(io::Error),
    #[error("Failed to change permissions on {0}: {1}")]
    Chmod(PathBuf, io::Error),
    #[error("Failed to close fd: {0}")]
    Close(io::Error),
    #[error("Failed to call close range syscall: {0}")]
    CloseRange(io::Error),
    #[error("{}", format!("Failed to copy {:?} to {:?}: {}", .0, .1, .2).replace('\"', ""))]
    Copy(PathBuf, PathBuf, io::Error),
    #[error("{}", format!("Failed to create directory {:?}: {}", .0, .1).replace('\"', ""))]
    CreateDir(PathBuf, io::Error),
    #[error("Encountered interior \\0 while parsing a string")]
    CStringParsing(NulError),
    #[error("Failed to duplicate fd: {0}")]
    Dup2(io::Error),
    #[error("Failed to exec into Firecracker: {0}")]
    Exec(io::Error),
    #[error("{}", format!("Failed to extract filename from path {:?}", .0).replace('\"', ""))]
    ExtractFileName(PathBuf),
    #[error("{}", format!("Failed to open file {:?}: {}", .0, .1).replace('\"', ""))]
    FileOpen(PathBuf, io::Error),
    #[error("Invalid gid: {0}")]
    Gid(String),
    #[error("Detected hard link at: {0}")]
    HardLink(PathBuf),
    #[error("Invalid instance ID: {0}")]
    InvalidInstanceId(validators::ValidatorError),
    #[error("Cannot get metadata for a file: {0}: {1}")]
    Metadata(PathBuf, io::Error),
    #[error("Failed to create the jail root directory before pivoting root: {0}")]
    MkdirOldRoot(io::Error),
    #[error("Failed to create {1} via mknod inside the jail: {0}")]
    MknodDev(io::Error, String),
    #[error("Failed to bind mount the jail root directory: {0}")]
    MountBind(io::Error),
    #[error("Failed to change the propagation type to slave: {0}")]
    MountPropagationSlave(io::Error),
    #[error("{}", format!("{:?} is not a file", .0).replace('\"', ""))]
    NotAFile(PathBuf),
    #[error("{}", format!("{:?} is not a directory", .0).replace('\"', ""))]
    NotADirectory(PathBuf),
    #[error("Failed to open {0}: {1}")]
    Open(PathBuf, io::Error),
    #[error("{}", format!("Failed to parse path {:?} into an OsString", .0).replace('\"', ""))]
    OsStringParsing(PathBuf, OsString),
    #[error("Failed to pivot root: {0}")]
    PivotRoot(io::Error),
    #[error("{}", format!("Failed to read file {:?} into a string: {}", .0, .1).replace('\"', ""))]
    ReadToString(PathBuf, io::Error),
    #[error("Invalid resource argument: {0}")]
    ResLimitArgument(String),
    #[error("Invalid format for resources limits: {0}")]
    ResLimitFormat(String),
    #[error("Invalid limit value for resource: {0}: {1}")]
    ResLimitValue(String, String),
    #[error("Failed to remove old jail root directory: {0}")]
    RmOldRootDir(io::Error),
    #[error("--bootstrap-fd is not a descriptor number: {0}")]
    BootstrapFdArgument(String),
    #[error("--root-fd is not a descriptor number: {0}")]
    RootFdArgument(String),
    #[error("{0} must have a nonzero size")]
    ImageFdEmpty(&'static str),
    #[error("Failed to inspect {0}: {1}")]
    ImageFdInspect(&'static str, io::Error),
    #[error("{0} must be opened O_RDONLY")]
    ImageFdNotReadOnly(&'static str),
    #[error("{0} must be a regular file")]
    ImageFdNotRegularFile(&'static str),
    #[error("{0} is missing the write, grow, shrink or seal memfd seal")]
    ImageFdNotSealed(&'static str),
    #[error("{0} must not be owned by the jailed uid")]
    ImageFdOwnedByJailUid(&'static str),
    #[error("{0} must be a sealed memfd because --uid is 0")]
    ImageFdRegularFileAtRootUid(&'static str),
    #[error("{0} answers F_GET_SEALS but does not live on shmem or hugetlbfs")]
    ImageFdSealedNotShmem(&'static str),
    #[error("{0} must not have the setuid, setgid or sticky bit set")]
    ImageFdSpecialModeBits(&'static str),
    #[error("{0} must not have any write permission bit set")]
    ImageFdWritablePermissions(&'static str),
    #[error("{0} shares an inode with fd {1}, which is open for writing and survives the exec")]
    ImageFdWritableStreamAlias(&'static str, libc::c_int),
    #[error("Failed to change current directory: {0}")]
    SetCurrentDir(io::Error),
    #[error("Failed to join network namespace: netns: {0}")]
    SetNetNs(io::Error),
    #[error("Failed to set limit for resource: {0}")]
    Setrlimit(String),
    #[error("Invalid uid: {0}")]
    Uid(String),
    #[error("Failed to unmount the old jail root: {0}")]
    UmountOldRoot(io::Error),
    #[error("Failed to unshare into new mount namespace: {0}")]
    UnshareNewNs(io::Error),
    #[error("Failed to open the userfaultfd device: {0}")]
    UserfaultfdDevice(io::Error),
    #[error("{}", format!("Failed to write to {:?}: {}", .0, .1).replace('\"', ""))]
    Write(PathBuf, io::Error),
}

/// Create an ArgParser object which contains info about the command line argument parser and
/// populate it with the expected arguments and their characteristics.
pub fn build_arg_parser() -> ArgParser<'static> {
    ArgParser::new()
        .arg(
            Argument::new("id")
                .required(true)
                .takes_value(true)
                .help("Jail ID."),
        )
        .arg(
            Argument::new("exec-file")
                .required(true)
                .takes_value(true)
                .help("File path to exec into."),
        )
        .arg(
            Argument::new("uid")
                .required(true)
                .takes_value(true)
                .help("The user identifier the jailer switches to after exec."),
        )
        .arg(
            Argument::new("gid")
                .required(true)
                .takes_value(true)
                .help("The group identifier the jailer switches to after exec."),
        )
        .arg(
            Argument::new("root-fd")
                .required(true)
                .takes_value(true)
                .help(
                    "Inherited read-only descriptor of the root block device image, either a \
                     sealed memfd or a regular file the jailed uid cannot write. It is validated \
                     and handed to Firecracker as fd 4.",
                ),
        )
        .arg(Argument::new("bootstrap-fd").takes_value(true).help(
            "Inherited read-only descriptor of the bootstrap block device image, either a sealed \
             memfd or a regular file the jailed uid cannot write. It is validated and handed to \
             Firecracker as fd 5.",
        ))
        .arg(
            Argument::new("chroot-base-dir")
                .takes_value(true)
                .default_value("/srv/jailer")
                .help("The base folder where chroot jails are located."),
        )
        .arg(
            Argument::new("netns")
                .takes_value(true)
                .help("Path to the network namespace this microVM should join."),
        )
        .arg(Argument::new("cgroup-join").takes_value(true).help(
            "Absolute cgroupfs path of a pre-created leaf cgroup. The Firecracker process \
                     is moved into it before privileges are dropped.",
        ))
        .arg(Argument::new("resource-limit").allow_multiple(true).help(
            "Resource limit values to be set by the jailer. It must follow this format: \
             <resource>=<value> (e.g no-file=1024). This argument can be used multiple times to \
             add multiple resource limits. Current available resource values are:\n\t\tfsize: The \
             maximum size in bytes for files created by the process.\n\t\tno-file: Specifies a \
             value one greater than the maximum file descriptor number that can be opened by this \
             process.\n\t\tmemlock: The maximum size in bytes of memory that may be locked into \
             RAM.",
        ))
        .arg(
            Argument::new("version")
                .takes_value(false)
                .help("Print the binary version number."),
        )
}

pub fn writeln_special<T, V>(file_path: &T, value: V) -> Result<(), JailerError>
where
    T: AsRef<Path> + Debug,
    V: Display + Debug,
{
    fs::write(file_path, format!("{}\n", value))
        .map_err(|err| JailerError::Write(PathBuf::from(file_path.as_ref()), err))
}

pub fn readln_special<T: AsRef<Path> + Debug>(file_path: &T) -> Result<String, JailerError> {
    let mut line = fs::read_to_string(file_path)
        .map_err(|err| JailerError::ReadToString(PathBuf::from(file_path.as_ref()), err))?;

    // Remove the newline character at the end (if any).
    line.pop();

    Ok(line)
}

/// Closes every inherited descriptor above the ones the jailed binary needs: the standard
/// streams and the descriptors Firecracker is given. `highest_reserved` is the last of those:
/// [`BOOTSTRAP_FILENO`] when the caller passed a bootstrap image, [`ROOT_FILENO`] otherwise, so an
/// absent bootstrap image leaves fd 5 unreserved.
pub(crate) fn close_inherited_fds(highest_reserved: libc::c_int) -> Result<(), JailerError> {
    // SAFETY: closing a range which holds no open descriptors is a no-op, and the return code
    // of the syscall is checked.
    SyscallReturnCode(unsafe {
        libc::syscall(
            libc::SYS_close_range,
            highest_reserved + 1,
            libc::c_uint::MAX,
            libc::CLOSE_RANGE_UNSHARE,
        )
    })
    .into_empty_result()
    .map_err(JailerError::CloseRange)
}

fn clean_env_vars() {
    // Remove environment variables received from the parent process so there are no leaks inside
    // the jailer environment.
    for (key, _) in std::env::vars() {
        // SAFETY: the function is safe to call in a single-threaded program
        unsafe {
            std::env::remove_var(key);
        }
    }
}

/// Turns an [`AsRef<Path>`] into a [`CString`] (c style string).
pub fn to_cstring<T: AsRef<Path> + Debug>(path: T) -> Result<CString, JailerError> {
    let path_str = path
        .as_ref()
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(|err| JailerError::OsStringParsing(path.as_ref().to_path_buf(), err))?;
    CString::new(path_str).map_err(JailerError::CStringParsing)
}

/// We wrap the actual main in order to pretty print an error with Display trait.
fn main() -> Result<(), JailerError> {
    let result = main_exec();
    if let Err(e) = result {
        eprintln!("{}", e);
        Err(e)
    } else {
        Ok(())
    }
}

fn main_exec() -> Result<(), JailerError> {
    clean_env_vars();

    let mut arg_parser = build_arg_parser();
    arg_parser
        .parse_from_cmdline()
        .map_err(JailerError::ArgumentParsing)?;
    let arguments = arg_parser.arguments();

    if arguments.flag_present("help") {
        println!("Jailer v{}\n", JAILER_VERSION);
        println!("{}\n", arg_parser.formatted_help());
        println!("Any arguments after the -- separator will be supplied to the jailed binary.\n");
        return Ok(());
    }

    if arguments.flag_present("version") {
        println!("Jailer v{}\n", JAILER_VERSION);
        return Ok(());
    }

    Env::new(
        arguments,
        get_time_us(ClockType::Monotonic),
        get_time_us(ClockType::ProcessCpu),
    )
    .and_then(|env| {
        fs::create_dir_all(env.chroot_dir())
            .map_err(|err| JailerError::CreateDir(env.chroot_dir().to_owned(), err))?;
        env.run()
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_cstring() {
        let path = PathBuf::from("/tmp");
        assert_eq!(to_cstring(&path).unwrap(), CString::new("/tmp").unwrap());
    }

    #[test]
    fn test_clean_env_vars() {
        let env_vars: [&str; 5] = ["VAR1", "VAR2", "VAR3", "VAR4", "VAR5"];

        for env_var in env_vars.iter() {
            // SAFETY: the function is safe to call in a single-threaded program
            unsafe {
                std::env::set_var(env_var, "0");
            }
        }

        clean_env_vars();

        for env_var in env_vars.iter() {
            assert_eq!(std::env::var_os(env_var), None);
        }
    }
}
