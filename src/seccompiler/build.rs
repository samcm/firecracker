// Copyright 2024 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

/// Names the directory holding the libseccomp this crate links. A build that supplies its own
/// audited copy of the library points this at it, and that directory then becomes the only one
/// this crate adds to the link search path.
const LIB_PATH_ENV: &str = "LIBSECCOMP_LIB_PATH";

/// The directory searched when `LIBSECCOMP_LIB_PATH` names none. The development container
/// installs its static libseccomp there.
const DEFAULT_LIB_PATH: &str = "/usr/local/lib";

fn holds_libseccomp(dir: &Path) -> bool {
    ["libseccomp.a", "libseccomp.so"]
        .iter()
        .any(|name| dir.join(name).exists())
}

fn main() {
    println!("cargo::rerun-if-env-changed={LIB_PATH_ENV}");

    let lib_path = match std::env::var_os(LIB_PATH_ENV) {
        Some(path) if !path.is_empty() => {
            let path = PathBuf::from(path);
            // The linker searches its own default directories after this one, so a supplied
            // directory that holds no library resolves to a copy the caller did not supply
            // and links successfully. Refuse that instead of linking something unintended.
            assert!(
                holds_libseccomp(&path),
                "{LIB_PATH_ENV} is {}, which holds neither libseccomp.a nor libseccomp.so",
                path.display()
            );
            path
        }
        Some(_) => panic!("{LIB_PATH_ENV} is set to an empty value"),
        None => PathBuf::from(DEFAULT_LIB_PATH),
    };

    println!("cargo::rustc-link-search=native={}", lib_path.display());
    println!("cargo::rustc-link-lib=seccomp");
}
