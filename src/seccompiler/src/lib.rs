// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::str::FromStr;

mod bindings;
use bindings::*;

pub mod types;
pub use types::*;
use zerocopy::IntoBytes;

// This byte limit is passed to `bitcode` to guard against a potential memory
// allocation DOS caused by binary filters that are too large.
// This limit can be safely determined since the maximum length of a BPF
// filter is 4096 instructions and Firecracker has a finite number of threads.
const DESERIALIZATION_BYTES_LIMIT: usize = 100_000;

/// Binary filter compilation errors.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CompilationError {
    /// Cannot open input file: {0}
    IntputOpen(std::io::Error),
    /// Cannot read input file: {0}
    InputRead(std::io::Error),
    /// Cannot deserialize json: {0}
    JsonDeserialize(serde_json::Error),
    /// Cannot parse arch: {0}
    ArchParse(String),
    /// Cannot create libseccomp context
    LibSeccompContext,
    /// Cannot add libseccomp arch
    LibSeccompArch,
    /// Cannot add libseccomp syscall
    LibSeccompSycall,
    /// Cannot add libseccomp syscall rule
    LibSeccompRule,
    /// Cannot export libseccomp bpf
    LibSeccompExport,
    /// Cannot create memfd: {0}
    MemfdCreate(std::io::Error),
    /// Cannot rewind memfd: {0}
    MemfdRewind(std::io::Error),
    /// Cannot read from memfd: {0}
    MemfdRead(std::io::Error),
    /// Cannot create output file: {0}
    OutputCreate(std::io::Error),
    /// Cannot serialize bfp: {0}
    BitcodeSerialize(bitcode::Error),
    /// Serialized BPF exceeds size limit of {0} bytes
    SizeLimitExceeded(usize),
}

pub fn compile_bpf(
    input_path: &str,
    arch: &str,
    out_path: &str,
    basic: bool,
    split_output: bool,
) -> Result<(), CompilationError> {
    let mut file_content = String::new();
    File::open(input_path)
        .map_err(CompilationError::IntputOpen)?
        .read_to_string(&mut file_content)
        .map_err(CompilationError::InputRead)?;
    let bpf_map_json: BpfJson =
        serde_json::from_str(&file_content).map_err(CompilationError::JsonDeserialize)?;

    let arch = TargetArch::from_str(arch).map_err(CompilationError::ArchParse)?;

    // SAFETY: Safe because the parameters are valid.
    let memfd_fd = unsafe { libc::memfd_create(c"bpf".as_ptr().cast(), 0) };
    if memfd_fd < 0 {
        return Err(CompilationError::MemfdCreate(
            std::io::Error::last_os_error(),
        ));
    }

    // SAFETY: Safe because the parameters are valid.
    let mut memfd = unsafe { File::from_raw_fd(memfd_fd) };

    let mut bpf_map: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for (name, filter) in bpf_map_json.0.iter() {
        let default_action = filter.default_action.to_scmp_type();
        let filter_action = filter.filter_action.to_scmp_type();

        // SAFETY: Safe as all args are correct.
        let bpf_filter = {
            let r = seccomp_init(default_action);
            if r.is_null() {
                return Err(CompilationError::LibSeccompContext);
            }
            r
        };

        // SAFETY: Safe as all args are correct.
        unsafe {
            let r = seccomp_arch_add(bpf_filter, arch.to_scmp_type());
            if r != 0 && r != MINUS_EEXIST {
                return Err(CompilationError::LibSeccompArch);
            }
        }

        for rule in filter.filter.iter() {
            // SAFETY: Safe as all args are correct.
            let syscall = unsafe {
                let r = seccomp_syscall_resolve_name(rule.syscall.as_ptr());
                if r == __NR_SCMP_ERROR {
                    return Err(CompilationError::LibSeccompSycall);
                }
                r
            };

            // TODO remove when we drop deprecated "basic" arg from cli.
            // "basic" bpf means it ignores condition checks.
            if basic {
                // SAFETY: Safe as all args are correct.
                unsafe {
                    if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            } else if let Some(rules) = &rule.args {
                let comparators = rules
                    .iter()
                    .map(|rule| rule.to_scmp_type())
                    .collect::<Vec<scmp_arg_cmp>>();

                // SAFETY: Safe as all args are correct.
                // We can assume no one will define u32::MAX
                // filters for a syscall.
                #[allow(clippy::cast_possible_truncation)]
                unsafe {
                    if seccomp_rule_add_array(
                        bpf_filter,
                        filter_action,
                        syscall,
                        comparators.len() as u32,
                        comparators.as_ptr(),
                    ) != 0
                    {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            } else {
                // SAFETY: Safe as all args are correct.
                unsafe {
                    if seccomp_rule_add(bpf_filter, filter_action, syscall, 0) != 0 {
                        return Err(CompilationError::LibSeccompRule);
                    }
                }
            }
        }

        // SAFETY: Safe as all args are correect.
        unsafe {
            if seccomp_export_bpf(bpf_filter, memfd.as_raw_fd()) != 0 {
                return Err(CompilationError::LibSeccompExport);
            }
        }
        memfd.rewind().map_err(CompilationError::MemfdRewind)?;

        // Cast is safe because usize == u64
        #[allow(clippy::cast_possible_truncation)]
        let size = memfd.metadata().unwrap().size() as usize;
        // Bpf instructions are 8 byte values and 4 byte alignment.
        // We use u64 to satisfy these requirements.
        let instructions = size / std::mem::size_of::<u64>();
        let mut bpf = vec![0_u64; instructions];

        memfd
            .read_exact(bpf.as_mut_bytes())
            .map_err(CompilationError::MemfdRead)?;
        memfd.rewind().map_err(CompilationError::MemfdRewind)?;

        bpf_map.insert(name.clone(), bpf);
    }

    if split_output {
        // Output individual files for each thread (for testing)
        let base_path = Path::new(out_path);
        let parent = base_path.parent().unwrap_or_else(|| Path::new("."));

        for (thread_name, bpf_data) in &bpf_map {
            let thread_file_path = parent.join(format!("{}.bpf", thread_name));
            let mut thread_file =
                File::create(&thread_file_path).map_err(CompilationError::OutputCreate)?;

            // Write raw BPF data as bytes
            use zerocopy::IntoBytes;
            std::io::Write::write_all(&mut thread_file, bpf_data.as_bytes())
                .map_err(CompilationError::OutputCreate)?;
        }
    } else {
        // Create and write the main bitcode output file
        let mut output_file = File::create(out_path).map_err(CompilationError::OutputCreate)?;
        let encoded = bitcode::serialize(&bpf_map).map_err(CompilationError::BitcodeSerialize)?;

        // Check size limit to prevent DOS attacks
        if encoded.len() > DESERIALIZATION_BYTES_LIMIT {
            return Err(CompilationError::SizeLimitExceeded(
                DESERIALIZATION_BYTES_LIMIT,
            ));
        }

        std::io::Write::write_all(&mut output_file, &encoded)
            .map_err(CompilationError::OutputCreate)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped_filters() -> BTreeMap<String, Vec<u64>> {
        let arch = std::env::consts::ARCH;
        let policy = format!(
            "{}/../../resources/seccomp/{arch}-unknown-linux-musl.json",
            env!("CARGO_MANIFEST_DIR")
        );
        // SAFETY: a constant name; the returned descriptor is checked and owned below.
        let fd = unsafe { libc::memfd_create(c"test-filter".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        // SAFETY: the successful syscall transferred ownership of this descriptor.
        let mut output = unsafe { File::from_raw_fd(fd) };
        compile_bpf(&policy, arch, &format!("/proc/self/fd/{fd}"), false, false).unwrap();
        let mut bytes = Vec::new();
        output.read_to_end(&mut bytes).unwrap();
        let filters: BTreeMap<String, Vec<u64>> = bitcode::deserialize(&bytes).unwrap();
        assert_eq!(filters.len(), 3);
        filters
    }

    #[test]
    fn shipped_filters_trap_madv_free_on_every_thread() {
        let filters = shipped_filters();
        for name in ["vmm", "vcpu", "api"] {
            let filter = &filters[name];
            // The kernel consumes advice as an int. High register bits must not bypass it.
            for advice in [u64::from(libc::MADV_FREE as u32), (1 << 32) | 8] {
                assert_advice_action(filter, advice, true);
            }
        }
        // Positive control: the filter is argument-selective, not a blanket madvise denial.
        assert_advice_action(&filters["vmm"], libc::MADV_NOHUGEPAGE as u64, false);
    }

    #[test]
    fn shipped_vmm_filter_allows_free_summary_syscalls() {
        let filters = shipped_filters();
        let filter = &filters["vmm"];
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len()).unwrap(),
            filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
        };
        // SAFETY: the child uses only libc syscalls then _exit, without unwinding or allocation.
        unsafe {
            let child = libc::fork();
            assert!(child >= 0);
            if child == 0 {
                let fd = libc::memfd_create(
                    c"summary-filter".as_ptr(),
                    libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
                );
                if fd < 0
                    || libc::ftruncate(fd, 8) != 0
                    || libc::fcntl(
                        fd,
                        libc::F_ADD_SEALS,
                        libc::F_SEAL_GROW | libc::F_SEAL_SHRINK,
                    ) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &prog)
                        != 0
                {
                    libc::_exit(90);
                }
                let mut stat: libc::stat = std::mem::zeroed();
                let mut fs: libc::statfs = std::mem::zeroed();
                // Test the shipped musl syscall, even when this test itself uses glibc,
                // whose fstat wrapper instead issues newfstatat (not in the musl policy).
                if libc::syscall(libc::SYS_fstat, fd, &mut stat) != 0
                    || libc::fstatfs(fd, &mut fs) != 0
                    || libc::fcntl(fd, libc::F_GETFL) < 0
                    || libc::fcntl(fd, libc::F_GET_SEALS) < 0
                    || libc::pwrite(fd, [0u8; 8].as_ptr().cast(), 8, 0) != 8
                {
                    libc::_exit(91);
                }
                // Invalid fd is intentional: EBADF proves KVM_GET_DIRTY_LOG reached the kernel,
                // without requiring /dev/kvm. A missing allowance would instead deliver SIGSYS.
                let result = libc::ioctl(-1, 0x4010_ae42, std::ptr::null::<u8>());
                if result != -1 || *libc::__errno_location() != libc::EBADF {
                    libc::_exit(92);
                }
                // MV_IOC_RESIDENT, which the capture thread issues inside a capture's freeze.
                // A raw syscall: musl's ioctl takes the request as a (too narrow) int.
                let result = libc::syscall(
                    libc::SYS_ioctl,
                    -1_i64,
                    0xc038_5649_u64,
                    std::ptr::null::<u8>(),
                );
                libc::_exit(
                    if result == -1 && *libc::__errno_location() == libc::EBADF {
                        0
                    } else {
                        93
                    },
                );
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            assert!(libc::WIFEXITED(status), "status={status}");
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    fn assert_advice_action(filter: &[u64], advice: u64, trap: bool) {
        let prog = libc::sock_fprog {
            len: u16::try_from(filter.len()).unwrap(),
            filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
        };
        // SAFETY: the child uses only async-signal-safe syscalls then _exit; all pointers
        // reference live stack/filter memory inherited across fork. No child unwinding.
        unsafe {
            let child = libc::fork();
            assert!(child >= 0);
            if child == 0 {
                let no_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &no_core);
                let page = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if page == libc::MAP_FAILED
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                    || libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &prog)
                        != 0
                {
                    libc::_exit(90);
                }
                let result = libc::syscall(libc::SYS_madvise, page, 4096, advice);
                libc::_exit(if result == 0 { 0 } else { 91 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(child, &mut status, 0), child);
            if trap {
                assert!(libc::WIFSIGNALED(status), "advice={advice} status={status}");
                assert_eq!(libc::WTERMSIG(status), libc::SIGSYS);
            } else {
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
            }
        }
    }
}
