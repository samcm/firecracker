// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;
use std::process::Command;

const ADVANCED_BINARY_FILTER_FILE_NAME: &str = "seccomp_filter.bpf";

const JSON_DIR: &str = "../../resources/seccomp";
const SECCOMPILER_SRC_DIR: &str = "../seccompiler/src";

// This script is run on every modification in the target-specific JSON file in `resources/seccomp`.
// It compiles the JSON seccomp policies into a serializable BPF format, using seccompiler-bin.
// The generated binary code will get included in Firecracker's code, at compile-time.
fn main() {
    // Target triple
    let target = std::env::var("TARGET").expect("Missing target.");
    let debug: bool = std::env::var("DEBUG")
        .expect("Missing debug.")
        .parse()
        .expect("Invalid env variable DEBUG");
    let out_dir = std::env::var("OUT_DIR").expect("Missing build-level OUT_DIR.");
    // Target arch (x86_64 / aarch64)
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").expect("Missing target arch.");

    let seccomp_json_path = format!("{}/{}.json", JSON_DIR, target);
    // If the current target doesn't have a default filter, or if we're building a debug binary,
    // use a default, empty filter.
    // This is to make sure that Firecracker builds even with libc toolchains for which we don't
    // provide a default filter. For example, GNU libc.
    let seccomp_json_path = if debug {
        println!(
            "cargo:warning=Using empty default seccomp policy for debug builds: \
             `resources/seccomp/unimplemented.json`."
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else if !Path::new(&seccomp_json_path).exists() {
        println!(
            "cargo:warning=No default seccomp policy for target: {}. Defaulting to \
             `resources/seccomp/unimplemented.json`.",
            target
        );
        format!("{}/unimplemented.json", JSON_DIR)
    } else {
        seccomp_json_path
    };

    // Retrigger the build script if the JSON file has changed.
    // let json_path = json_path.to_str().expect("Invalid bytes");
    println!("cargo:rerun-if-changed={}", seccomp_json_path);
    // Also retrigger the build script on any seccompiler source code change.
    println!("cargo:rerun-if-changed={}", SECCOMPILER_SRC_DIR);

    let out_path = format!("{}/{}", out_dir, ADVANCED_BINARY_FILTER_FILE_NAME);
    seccompiler::compile_bpf(&seccomp_json_path, &target_arch, &out_path, false, false)
        .expect("Cannot compile seccomp filters");

    emit_build_commit();
}

/// Emits `FIRECRACKER_BUILD_COMMIT` for the binary to report at runtime.
///
/// A commit alone does not describe a build: a tree with uncommitted or untracked files compiles
/// into something no commit names, so that case is reported as `-dirty` rather than as the commit
/// it is not. A source tree with no git checkout at all reports `unknown`; refusing to build there
/// would break vendored and archive builds, and the authoritative release mode is what rejects an
/// unidentified tree.
fn emit_build_commit() {
    // A build script that names any watched path is watched for those paths alone, so everything
    // that can change the value below has to be named here.
    //
    // `.git` is a directory in a normal clone and a file naming another directory in a linked
    // worktree, so the metadata paths are asked for rather than assumed. The ref HEAD names is
    // resolved and watched as well: a commit lands in that ref, or in `packed-refs` once the refs
    // are packed, and leaves `HEAD` itself untouched, so watching `HEAD` alone follows branch
    // switches and misses commits. A detached HEAD carries the commit in `HEAD` and has no ref to
    // resolve.
    let mut metadata: Vec<String> = ["HEAD", "index", "packed-refs"]
        .into_iter()
        .map(String::from)
        .collect();
    if let Some(head_ref) = git(&["symbolic-ref", "--quiet", "HEAD"]) {
        metadata.push(head_ref);
    }
    for name in &metadata {
        // A path that does not exist yet is not watched: cargo would rerun this script on every
        // build. Refs move between their loose file and `packed-refs`, and either move edits a
        // path that does exist.
        match git(&["rev-parse", "--git-path", name]) {
            Some(path) if Path::new(&path).exists() => {
                println!("cargo::rerun-if-changed={path}")
            }
            _ => {}
        }
    }

    // The `-dirty` suffix is a property of the work tree rather than of the metadata above, so the
    // sources are watched too: cargo compares directory trees recursively, so an edit, an addition
    // or a removal under any of these reruns this script. It is a development-build convenience
    // and not the guarantee: a tree can be dirtied outside these paths. `tools/release.sh`
    // compiles an authoritative build from an extraction of the commit, where the work tree cannot
    // change at all, and requires the built binary to report that commit before it records it.
    for path in [
        "../../src",
        "../../resources",
        "../../Cargo.toml",
        "../../Cargo.lock",
    ] {
        println!("cargo::rerun-if-changed={path}");
    }

    let commit = git(&["rev-parse", "HEAD"]);
    let status = git(&["status", "--porcelain", "--untracked-files=all"]);
    let value = match (commit, status) {
        (Some(commit), Some(status)) if status.is_empty() => commit,
        (Some(commit), Some(_)) => format!("{commit}-dirty"),
        // A readable HEAD with an unreadable work tree says nothing trustworthy about the bytes
        // being compiled, so it is not reported as that commit.
        _ => "unknown".to_string(),
    };
    println!("cargo::rustc-env=FIRECRACKER_BUILD_COMMIT={value}");
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
}
