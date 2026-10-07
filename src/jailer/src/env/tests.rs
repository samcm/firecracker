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

fn cmdline(extra: &[&str]) -> Vec<String> {
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

#[test]
fn test_new_env() {
    let env = new_env(&cmdline(&[
        "--chroot-base-dir",
        "/",
        "--resource-limit",
        "memlock=1048576",
    ]))
    .unwrap();
    assert_eq!(env.uid(), 1001);
    assert_eq!(env.gid(), 1002);
}

/// The jailer takes no drive image: Firecracker receives those from pagemaster at claim.
#[test]
fn test_drive_images_are_not_jailer_arguments() {
    for flag in ["--root-fd", "--scratch-fd", "--cgroup-join"] {
        let mut args = cmdline(&["--chroot-base-dir", "/"]);
        args.extend([flag.to_string(), "7".to_string()]);
        let parser = build_arg_parser();
        let mut arguments = parser.arguments().clone();
        assert!(arguments.parse(&args).is_err(), "{flag} was accepted");
    }
}

/// Both drive slots hold a read-only placeholder at exec and fd 3 is a hole, whatever the caller
/// left at those numbers.
#[test]
fn test_drive_slots_are_reserved_and_fd_three_is_a_hole() {
    const CHILD: &str = "JAILER_DRIVE_SLOT_TEST";
    let Some(case) = std::env::var_os(CHILD) else {
        for case in ["open", "closed"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "env::tests::test_drive_slots_are_reserved_and_fd_three_is_a_hole",
                ])
                .env(CHILD, case)
                .status()
                .unwrap();
            assert!(status.success(), "case {case}: {status}");
        }
        return;
    };
    let env = new_env(&cmdline(&["--chroot-base-dir", "/"])).unwrap();
    fs::remove_file(&env.exec_file_path).unwrap();
    fs::remove_dir(env.exec_file_path.parent().unwrap()).unwrap();
    if case == "open" {
        // A caller's descriptors at 3, 4 and 5 are replaced or closed, never inherited.
        for fd in 3..=SCRATCH_FILENO {
            let pipe = {
                let mut fds = [0; 2];
                assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
                fds[1]
            };
            dup2(pipe, fd).unwrap();
        }
    } else {
        for fd in 3..=SCRATCH_FILENO {
            unsafe { libc::close(fd) };
        }
    }
    env.reserve_drive_slots().unwrap();
    close_inherited_fds().unwrap();
    assert_eq!(unsafe { libc::fcntl(3, libc::F_GETFD) }, -1);
    let null = fs::metadata("/dev/null").unwrap();
    for slot in [ROOT_FILENO, SCRATCH_FILENO] {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(slot, stat.as_mut_ptr()) }, 0);
        let stat = unsafe { stat.assume_init() };
        assert_eq!(
            stat.st_rdev,
            null.rdev(),
            "slot {slot} is not the placeholder"
        );
        assert_eq!(
            unsafe { libc::fcntl(slot, libc::F_GETFD) },
            0,
            "slot {slot} is close-on-exec"
        );
        assert_eq!(
            unsafe { libc::fcntl(slot, libc::F_GETFL) } & libc::O_ACCMODE,
            libc::O_RDONLY
        );
    }
    // Descriptor cleanup may have closed libtest's own descriptors in this isolated process.
    unsafe { libc::_exit(0) };
}
