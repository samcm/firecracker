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

/// Descriptor Firecracker reads the read-only root block device image from.
pub(crate) const ROOT_FILENO: libc::c_int = 4;
/// Descriptor Firecracker reads and writes the scratch block device through, when the caller
/// passes one.
pub(crate) const SCRATCH_FILENO: libc::c_int = 5;

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
    #[error("--scratch-fd must not name the root image inode")]
    ScratchFdAliasesRoot,
    #[error("{0} must not be opened O_APPEND")]
    ScratchFdAppend(&'static str),
    #[error("--scratch-fd is not a descriptor number: {0}")]
    ScratchFdArgument(String),
    #[error("{0} must have a nonzero size")]
    ScratchFdEmpty(&'static str),
    #[error("Failed to inspect {0}: {1}")]
    ScratchFdInspect(&'static str, io::Error),
    #[error("{0} must be opened O_DIRECT")]
    ScratchFdNotDirect(&'static str),
    #[error("{0} must be opened O_RDWR")]
    ScratchFdNotReadWrite(&'static str),
    #[error("{0} must be a regular file")]
    ScratchFdNotRegularFile(&'static str),
    #[error("{0} must be a file on the node's filesystem, not on shmem or hugetlbfs")]
    ScratchFdSealingFilesystem(&'static str),
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
        .arg(Argument::new("scratch-fd").takes_value(true).help(
            "Inherited read-write, O_DIRECT descriptor of the scratch block device, which is a \
             regular non-empty file. It is validated and handed to Firecracker as fd 5.",
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
/// [`SCRATCH_FILENO`] when the caller passed a scratch descriptor, [`ROOT_FILENO`] otherwise, so
/// an absent scratch descriptor leaves fd 5 unreserved. The unused fd 3 is also closed;
/// memversion descriptors are received later via SCM_RIGHTS, not inherited from the jailer.
pub(crate) fn close_inherited_fds(highest_reserved: libc::c_int) -> Result<(), JailerError> {
    // SAFETY: close_range tolerates an already closed slot. Installation has moved root and
    // scratch clear of fd 3 before this function is called.
    SyscallReturnCode(unsafe { libc::syscall(libc::SYS_close_range, 3u32, 3u32, 0u32) })
        .into_empty_result()
        .map_err(JailerError::CloseRange)?;
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

    /// Compile both architectures with libseccomp and interpret their actual classic BPF.
    /// This requires only the repository's Python/libseccomp tooling, not KVM or memversion.
    #[test]
    fn test_memversion_seccomp_policies() {
        let result = std::process::Command::new("python3")
            .arg("-c")
            .arg(r#"
import ctypes as c
import json, os, pathlib, struct, sys
lib = c.CDLL('libseccomp.so.2')
class Cmp(c.Structure):
    _fields_ = [('arg', c.c_uint), ('op', c.c_uint), ('a', c.c_uint64), ('b', c.c_uint64)]
def api(name, result, *args):
    f = getattr(lib, name)
    f.restype, f.argtypes = result, args
    return f
init = api('seccomp_init', c.c_void_p, c.c_uint32)
release = api('seccomp_release', None, c.c_void_p)
native = api('seccomp_arch_native', c.c_uint32)
add_arch = api('seccomp_arch_add', c.c_int, c.c_void_p, c.c_uint32)
remove_arch = api('seccomp_arch_remove', c.c_int, c.c_void_p, c.c_uint32)
resolve = api('seccomp_syscall_resolve_name', c.c_int, c.c_char_p)
resolve_arch = api('seccomp_syscall_resolve_name_arch', c.c_int, c.c_uint32, c.c_char_p)
add = api('seccomp_rule_add_array', c.c_int, c.c_void_p, c.c_uint32, c.c_int, c.c_uint, c.POINTER(Cmp))
export = api('seccomp_export_bpf', c.c_int, c.c_void_p, c.c_int)
ALLOW, TRAP = 0x7fff0000, 0x30000
for arch, token in [('x86_64', 0xc000003e), ('aarch64', 0xc00000b7)]:
    policy = json.loads((pathlib.Path(sys.argv[1]) / (arch + '-unknown-linux-musl.json')).read_text())['vmm']
    assert policy['default_action'] == 'trap' and policy['filter_action'] == 'allow'
    ctx = init(TRAP)
    assert ctx
    if native() != token:
        assert add_arch(ctx, token) == 0
        assert remove_arch(ctx, native()) == 0
    for rule in policy['filter']:
        comparisons = []
        for arg in rule.get('args', []):
            assert arg['type'] == 'dword'
            op = arg['op']
            if op == 'eq':
                # Match seccompiler's dword comparisons, including musl ioctl's high bits.
                comparisons.append(Cmp(arg['index'], 7, 0xffffffff, arg['val']))
            else:
                comparisons.append(Cmp(arg['index'], 7, op['masked_eq'], arg['val']))
        args = (Cmp * len(comparisons))(*comparisons)
        assert add(ctx, ALLOW, resolve(rule['syscall'].encode()), len(args), args) == 0
    fd = os.memfd_create('policy-bpf')
    assert export(ctx, fd) == 0
    release(ctx)
    os.lseek(fd, 0, 0)
    bpf = list(struct.iter_unpack('HBBI', os.read(fd, 32768)))
    os.close(fd)
    def permits(name, args):
        nr = resolve_arch(token, name.encode())
        data = struct.pack('iIQ6Q', nr, token, 0, *(args + [0] * (6 - len(args))))
        pc, acc = 0, 0
        while True:
            code, jt, jf, k = bpf[pc]
            pc += 1
            if code == 0x20: acc = struct.unpack_from('I', data, k)[0]
            elif code == 0x54: acc &= k
            elif code == 0x15: pc += jt if acc == k else jf
            elif code == 0x25: pc += jt if acc > k else jf
            elif code == 0x35: pc += jt if acc >= k else jf
            elif code == 0x45: pc += jt if acc & k else jf
            elif code == 0x05: pc += k
            elif code == 0x06: return k == ALLOW
            else: raise AssertionError(hex(code))
    for op in [0xc0205640, 0x40105641, 0xc0285642]:
        assert permits('ioctl', [9, op]), (arch, hex(op))
        assert permits('ioctl', [9, op | (0xdeadbeef << 32)]), (arch, hex(op))
    for op in [43520, 3222841919, 3223366144, 0xc0205642, 0xc0285643, 0xc0205641, 0]:
        assert not permits('ioctl', [9, op]), (arch, hex(op))
    assert permits('mmap', [0, 4096, 0, 1048610])
    for prot in [1, 2, 3, 4, 7]:
        assert not permits('mmap', [0, 4096, prot, 1048610])
    for flags in [18, 50, 1048611, 1048626]:
        assert not permits('mmap', [0, 4096, 0, flags])
    assert permits('mprotect', [0, 4096, 3])
    for prot in [4, 5, 6, 7]:
        assert not permits('mprotect', [0, 4096, prot])
    assert permits('munmap', [0, 4096])
    assert not permits('prctl', [4, 1])
    assert not permits('prctl', [1499557217, 123])
    assert permits('prctl', [1, 9])
    print(arch + ': compiled BPF memversion policy checks passed')
"#)
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../resources/seccomp"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "policy checks failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        print!("{}", String::from_utf8_lossy(&result.stdout));
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
