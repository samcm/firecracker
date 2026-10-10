// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::sync::Arc;

use vmm::seccomp::{
    BpfProgram, BpfThreadMap, DeserializationError, deserialize_binary, get_empty_filters,
};

const THREAD_CATEGORIES: [&str; 3] = ["vmm", "api", "vcpu"];

/// Filter of the main thread in native mode, which the default mode never installs, so policies
/// written for it remain valid without one.
const NATIVE_MAIN_CATEGORY: &str = "native_main";

/// Returns the native-main filter, failing closed when the policy lacks one.
pub fn native_main_filter(filters: &BpfThreadMap) -> Result<Arc<BpfProgram>, FilterError> {
    filters
        .get(NATIVE_MAIN_CATEGORY)
        .cloned()
        .ok_or_else(|| FilterError::MissingThreadCategory(NATIVE_MAIN_CATEGORY.to_string()))
}

/// Error retrieving seccomp filters.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum FilterError {
    /// Filter deserialization failed: {0}
    Deserialization(DeserializationError),
    /// Invalid thread categories: {0}
    ThreadCategories(String),
    /// Missing thread category: {0}
    MissingThreadCategory(String),
    /// Filter file open error: {0}
    FileOpen(std::io::Error),
}

/// Seccomp filter configuration.
#[derive(Debug)]
pub enum SeccompConfig {
    /// Seccomp filtering disabled.
    None,
    /// Default, advanced filters.
    Advanced,
    /// Custom, user-provided filters.
    Custom(File),
}

impl SeccompConfig {
    /// Given the relevant command line args, return the appropriate config type.
    pub fn from_args<T: AsRef<Path> + Debug>(
        no_seccomp: bool,
        seccomp_filter: Option<T>,
    ) -> Result<Self, FilterError> {
        if no_seccomp {
            Ok(SeccompConfig::None)
        } else {
            match seccomp_filter {
                Some(path) => Ok(SeccompConfig::Custom(
                    File::open(path).map_err(FilterError::FileOpen)?,
                )),
                None => Ok(SeccompConfig::Advanced),
            }
        }
    }
}

/// Retrieve the appropriate filters, based on the SeccompConfig.
pub fn get_filters(config: SeccompConfig) -> Result<BpfThreadMap, FilterError> {
    match config {
        SeccompConfig::None => Ok(get_empty_filters()),
        SeccompConfig::Advanced => get_default_filters(),
        SeccompConfig::Custom(reader) => get_custom_filters(reader),
    }
}

/// Retrieve the default filters containing the syscall rules required by `Firecracker`
/// to function. The binary file is generated via the `build.rs` script of this crate.
fn get_default_filters() -> Result<BpfThreadMap, FilterError> {
    // Retrieve, at compile-time, the serialized binary filter generated with seccompiler.
    let bytes: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/seccomp_filter.bpf"));
    let map = deserialize_binary(bytes).map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Retrieve custom seccomp filters.
fn get_custom_filters<R: Read + Debug>(reader: R) -> Result<BpfThreadMap, FilterError> {
    let map = deserialize_binary(BufReader::new(reader)).map_err(FilterError::Deserialization)?;
    filter_thread_categories(map)
}

/// Return an error if the BpfThreadMap contains invalid thread categories.
fn filter_thread_categories(map: BpfThreadMap) -> Result<BpfThreadMap, FilterError> {
    let (filters, invalid_filters): (BpfThreadMap, BpfThreadMap) = map
        .into_iter()
        .partition(|(k, _)| THREAD_CATEGORIES.contains(&k.as_str()) || k == NATIVE_MAIN_CATEGORY);
    if !invalid_filters.is_empty() {
        // build the error message
        let mut thread_categories_string =
            invalid_filters
                .keys()
                .fold("".to_string(), |mut acc, elem| {
                    acc.push_str(elem);
                    acc.push(',');
                    acc
                });
        thread_categories_string.pop();
        return Err(FilterError::ThreadCategories(thread_categories_string));
    }

    for &category in THREAD_CATEGORIES.iter() {
        let category_string = category.to_string();
        if !filters.contains_key(&category_string) {
            return Err(FilterError::MissingThreadCategory(category_string));
        }
    }

    Ok(filters)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vmm::seccomp::BpfThreadMap;
    use vmm_sys_util::tempfile::TempFile;

    use super::*;

    #[test]
    fn test_get_filters() {
        let mut filters = get_empty_filters();
        assert_eq!(filters.len(), 4);
        assert_eq!(filters.remove("vmm").unwrap().len(), 0);
        assert_eq!(filters.remove("api").unwrap().len(), 0);
        assert_eq!(filters.remove("vcpu").unwrap().len(), 0);
        assert_eq!(filters.remove(NATIVE_MAIN_CATEGORY).unwrap().len(), 0);

        let file = TempFile::new().unwrap().into_file();

        get_filters(SeccompConfig::Custom(file)).unwrap_err();
    }

    #[test]
    fn test_default_filters_have_native_main() {
        let filters = get_filters(SeccompConfig::Advanced).unwrap();
        assert!(filters.contains_key(NATIVE_MAIN_CATEGORY));
    }

    #[test]
    fn test_native_main_is_optional() {
        let mut map = BpfThreadMap::new();
        for category in THREAD_CATEGORIES {
            map.insert(category.to_string(), Arc::new(vec![]));
        }
        // A custom policy written for the default mode stays valid.
        assert_eq!(filter_thread_categories(map.clone()).unwrap().len(), 3);

        map.insert(NATIVE_MAIN_CATEGORY.to_string(), Arc::new(vec![1]));
        let filters = filter_thread_categories(map).unwrap();
        assert_eq!(*filters[NATIVE_MAIN_CATEGORY], vec![1]);
    }

    #[test]
    fn test_filter_thread_categories() {
        // correct categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));
        map.insert("api".to_string(), Arc::new(vec![]));

        assert_eq!(filter_thread_categories(map).unwrap().len(), 3);

        // invalid categories
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));
        map.insert("thread1".to_string(), Arc::new(vec![]));
        map.insert("thread2".to_string(), Arc::new(vec![]));

        match filter_thread_categories(map).unwrap_err() {
            FilterError::ThreadCategories(err) => {
                assert!(err == "thread2,thread1" || err == "thread1,thread2")
            }
            _ => panic!("Expected ThreadCategories error."),
        }

        // missing category
        let mut map = BpfThreadMap::new();
        map.insert("vcpu".to_string(), Arc::new(vec![]));
        map.insert("vmm".to_string(), Arc::new(vec![]));

        match filter_thread_categories(map).unwrap_err() {
            FilterError::MissingThreadCategory(name) => assert_eq!(name, "api"),
            _ => panic!("Expected MissingThreadCategory error."),
        }
    }

    #[test]
    fn test_seccomp_config() {
        assert!(matches!(
            SeccompConfig::from_args(true, Option::<&str>::None),
            Ok(SeccompConfig::None)
        ));

        assert!(matches!(
            SeccompConfig::from_args(false, Some("/dev/null")),
            Ok(SeccompConfig::Custom(_))
        ));

        assert!(matches!(
            SeccompConfig::from_args(false, Some("invalid_path")),
            Err(FilterError::FileOpen(_))
        ));

        // test the default case, no parametes -> default advanced.
        assert!(matches!(
            SeccompConfig::from_args(false, Option::<&str>::None),
            Ok(SeccompConfig::Advanced)
        ));
    }

    /// Starting and joining a worker the way native mode does, under the embedded filters: the
    /// thread, named, inherits `native_main`, registers the vCPU kick handler, installs its
    /// role filter, reports ready and exits. A system call the filters lack kills the forked
    /// child with SIGSYS. With the empty debug filters this only exercises the sequence; run
    /// it against the release build for the policy:
    /// `cargo test --release --target x86_64-unknown-linux-musl -p firecracker --bin
    /// firecracker -- seccomp::tests::test_native_worker_bootstrap_under_embedded_filters`.
    #[test]
    fn test_native_worker_bootstrap_under_embedded_filters() {
        use vmm::vstate::worker::OwnedWorker;

        let filters = get_filters(SeccompConfig::Advanced).unwrap();
        for (role, name) in [("vmm", "fc_native_vmm"), ("vcpu", "fc_vcpu 0")] {
            // SAFETY: the child only installs filters, runs one worker and exits.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid == 0 {
                vmm::seccomp::apply_filter(&native_main_filter(&filters).unwrap()).unwrap();
                let worker = OwnedWorker::start(
                    std::thread::Builder::new().name(name.to_string()),
                    (),
                    filters[role].clone(),
                    |()| {
                        extern "C" fn kick(_: i32, _: *mut libc::siginfo_t, _: *mut libc::c_void) {}
                        vmm::utils::signal::register_signal_handler(
                            vmm::utils::signal::sigrtmin() + vmm::vstate::vcpu::VCPU_RTSIG_OFFSET,
                            kick,
                        )
                        .unwrap();
                    },
                    |()| {},
                )
                .map_err(|(err, ())| err)
                .unwrap();
                worker.join();
                // SAFETY: ending the forked child without running the harness's teardown.
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            // SAFETY: waiting for the child forked above.
            assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "{role} worker bootstrap: status {status:#x}"
            );
        }
    }

    /// The microVM build's first random draw, the VMGenID generation ID, runs AWS-LC's
    /// once-per-process fork-safety setup under `native_main` (traced on hardware: `getrandom`,
    /// `madvise` `MADV_WIPEONFORK`, then `stat("/dev/sysgenid")`). A process where it already
    /// ran would prove nothing, so [`native_vmgenid_first_draw`] runs alone in a fresh copy of
    /// this test executable; a system call `native_main` lacks kills it with SIGSYS. With the
    /// empty debug filters this only exercises the sequence; run it against the release build:
    /// `cargo test --release --target x86_64-unknown-linux-musl -p firecracker --bin
    /// firecracker -- seccomp::tests::test_native_vmgenid_first_draw_under_embedded_filters`.
    #[test]
    fn test_native_vmgenid_first_draw_under_embedded_filters() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "seccomp::tests::native_vmgenid_first_draw",
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
    }

    /// The fresh process half of the test above.
    #[test]
    #[ignore = "run in a fresh process by test_native_vmgenid_first_draw_under_embedded_filters"]
    fn native_vmgenid_first_draw() {
        let filters = get_filters(SeccompConfig::Advanced).unwrap();
        vmm::seccomp::apply_filter(&native_main_filter(&filters).unwrap()).unwrap();
        vmm::devices::acpi::vmgenid::VmGenId::from_parts(vmm::vstate::memory::GuestAddress(0), 5)
            .unwrap();
    }

    /// A clone forks through libc's `fork` from main, under `native_main`: libc's child side
    /// (its thread pointer's tid reset through `set_tid_address`, and whatever else it does
    /// before returning) runs under that filter too. The forked grandchild reports through a
    /// pipe, since `native_main` has no reason to allow waiting for it; a system call the filter
    /// lacks kills it with SIGSYS and the pipe closes empty. With the empty debug filters this
    /// only exercises the sequence; run it against the release build:
    /// `cargo test --release --target x86_64-unknown-linux-musl -p firecracker --bin
    /// firecracker -- seccomp::tests::test_native_libc_fork_under_embedded_filters`.
    #[test]
    fn test_native_libc_fork_under_embedded_filters() {
        let filters = get_filters(SeccompConfig::Advanced).unwrap();
        let native_main = native_main_filter(&filters).unwrap();
        // SAFETY: the child only installs the filter, forks, reads a pipe and exits.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut report = [-1; 2];
            // SAFETY: `report` has room for both descriptors; the rest are descriptor calls on
            // it, the grandchild's single write and exits.
            unsafe {
                if libc::pipe2(report.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
                    libc::_exit(10);
                }
                if vmm::seccomp::apply_filter(&native_main).is_err() {
                    libc::_exit(11);
                }
                match libc::fork() {
                    -1 => libc::_exit(12),
                    0 => {
                        libc::write(report[1], [1u8].as_ptr().cast(), 1);
                        libc::_exit(0);
                    }
                    _ => {}
                }
                libc::close(report[1]);
                let mut byte = 0u8;
                let read = libc::read(report[0], (&raw mut byte).cast(), 1);
                libc::_exit(if read == 1 && byte == 1 { 0 } else { 13 });
            }
        }
        let mut status = 0;
        // SAFETY: waiting for the child forked above.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            "libc fork under native_main: status {status:#x}"
        );
    }
}
