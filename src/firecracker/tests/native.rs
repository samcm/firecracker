// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Native mode against the actual binary, with the filters it embeds: the debug build's empty
//! policy, or the release policy when run with `--release`.
//!
//! The compiled test runs anywhere: `FIRECRACKER_BINARY` names the binary to test instead of the
//! one built with it, `NATIVE_TEST_TMPDIR` where its scratch directories go (the system temporary
//! directory by default), and `NATIVE_GUEST_DIR` the guest fixture of the ignored KVM tests, in
//! which `NATIVE_GUEST_KERNEL` and `NATIVE_GUEST_ROOTFS` name the kernel and root image
//! (`vmlinux-6.1.155` and `rootfs.squashfs` by default).

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// The binary under test: `FIRECRACKER_BINARY`, or the one built with this test.
fn firecracker() -> PathBuf {
    std::env::var_os("FIRECRACKER_BINARY").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_firecracker")),
        PathBuf::from,
    )
}

fn scratch(name: &str) -> PathBuf {
    let base =
        std::env::var_os("NATIVE_TEST_TMPDIR").map_or_else(std::env::temp_dir, PathBuf::from);
    let dir = base.join(format!("native-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn(args: &[&str]) -> Child {
    Command::new(firecracker())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn wait_for(path: &Path, child: &mut Child) {
    let start = Instant::now();
    while !path.exists() {
        assert!(child.try_wait().unwrap().is_none(), "firecracker exited");
        assert!(start.elapsed() < Duration::from_secs(10), "no API socket");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Reads responses until `count` status lines arrived; returns the status codes and the text.
fn read_responses(stream: &mut UnixStream, count: usize) -> (Vec<u16>, String) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    loop {
        let statuses: Vec<u16> = text
            .match_indices("HTTP/1.1 ")
            .map(|(at, _)| text[at + 9..at + 12].parse().unwrap())
            .collect();
        if statuses.len() >= count {
            return (statuses, text);
        }
        let read = stream.read(&mut buf).unwrap();
        assert_ne!(read, 0, "connection closed after {text:?}");
        text.push_str(std::str::from_utf8(&buf[..read]).unwrap());
    }
}

fn status_field(pid: u32, field: &str) -> String {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn test_native_api_serves_partial_and_pipelined_requests_on_main() {
    let dir = scratch("api");
    let sock = dir.join("api.sock");
    let mut child = spawn(&["--native", "--api-sock", sock.to_str().unwrap()]);
    wait_for(&sock, &mut child);

    // No API thread: main serves the socket, confined by its own filter in release builds.
    let pid = child.id();
    assert_eq!(
        std::fs::read_dir(format!("/proc/{pid}/task"))
            .unwrap()
            .count(),
        1
    );
    if !cfg!(debug_assertions) {
        assert_eq!(status_field(pid, "Seccomp:"), "2");
        assert_eq!(status_field(pid, "Seccomp_filters:"), "1");
    }

    let mut stream = UnixStream::connect(&sock).unwrap();
    let config = r#"{"vcpu_count":1,"mem_size_mib":32}"#;
    // Two requests in one write: each is answered against the state the previous one left.
    let pipelined = format!(
        "GET /machine-config HTTP/1.1\r\n\r\nPUT /machine-config HTTP/1.1\r\nContent-Type: \
         application/json\r\nContent-Length: {}\r\n\r\n{config}GET /machine-config \
         HTTP/1.1\r\n\r\n",
        config.len()
    );
    stream.write_all(pipelined.as_bytes()).unwrap();
    let (statuses, text) = read_responses(&mut stream, 3);
    assert_eq!(statuses, [200, 204, 200], "{text}");
    assert!(
        text.ends_with(r#""mem_size_mib":32,"smt":false}"#),
        "{text}"
    );

    // One request split across writes.
    let request = b"GET /machine-config HTTP/1.1\r\n\r\n";
    stream.write_all(&request[..7]).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    stream.write_all(&request[7..]).unwrap();
    let (statuses, text) = read_responses(&mut stream, 1);
    assert_eq!(statuses, [200], "{text}");

    // Unsupported devices are refused before anything is built from them.
    let vsock = r#"{"guest_cid":3,"uds_path":"v.sock"}"#;
    let request = format!(
        "PUT /vsock HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{vsock}",
        vsock.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let (statuses, text) = read_responses(&mut stream, 1);
    assert_eq!(statuses, [400], "{text}");
    assert!(text.contains("not supported in native mode"), "{text}");
    assert!(child.try_wait().unwrap().is_none());

    // Only a running microVM clones; a malformed request is refused before anything stops.
    let clone = r#"{"api_sock":"c.sock","control_sock":"l.sock","instance_id":"c","log_path":"c.log","metrics_path":"c.metrics","serial_out_path":"c.serial"}"#;
    let (status, text) = crate::request(&mut stream, "PUT", "/clone", clone);
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("running microVM"), "{text}");
    let (status, text) = crate::request(&mut stream, "PUT", "/clone", r#"{"unknown":1}"#);
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("Invalid clone request"), "{text}");
    assert!(child.try_wait().unwrap().is_none());

    child.kill().unwrap();
    child.wait().unwrap();
}

/// Native boot from JSON under the embedded filter gets past everything main does before it
/// needs a kernel, including mapping the guest's private anonymous memory: it fails opening KVM
/// without `/dev/kvm`, or loading the empty kernel with it, never on a filtered system call.
#[test]
fn test_native_bootstrap_is_not_killed_by_its_filter() {
    let dir = scratch("bootstrap");
    let kernel = dir.join("kernel");
    std::fs::write(&kernel, []).unwrap();
    let config = dir.join("config.json");
    std::fs::write(
        &config,
        format!(
            r#"{{"boot-source":{{"kernel_image_path":"{}"}},"machine-config":{{"vcpu_count":1,"mem_size_mib":128}},"drives":[]}}"#,
            kernel.display()
        ),
    )
    .unwrap();
    let output = spawn(&[
        "--native",
        "--no-api",
        "--config-file",
        config.to_str().unwrap(),
    ])
    .wait_with_output()
    .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Firecracker exits with 148 when its seccomp handler catches a filtered system call.
    assert_ne!(output.status.code(), Some(148), "{stdout}");
    assert!(!stdout.contains("bad syscall"), "{stdout}");
    assert!(stdout.contains("Cannot start the microVM"), "{stdout}");
}

#[test]
fn test_native_requires_custom_native_main_filter() {
    let dir = scratch("filter");
    let policy = serde_json::json!({
        "default_action": "allow",
        "filter_action": "trap",
        "filter": [],
    });
    let mut map: HashMap<String, serde_json::Value> = ["vmm", "api", "vcpu"]
        .into_iter()
        .map(|category| (category.to_string(), policy.clone()))
        .collect();
    let json = dir.join("policy.json");
    let compile = |map: &HashMap<String, serde_json::Value>, output: &Path| {
        std::fs::write(&json, serde_json::to_vec(map).unwrap()).unwrap();
        seccompiler::compile_bpf(
            json.to_str().unwrap(),
            std::env::consts::ARCH,
            output.to_str().unwrap(),
            false,
            false,
        )
        .unwrap();
    };
    let without = dir.join("without.bpf");
    compile(&map, &without);
    let sock = dir.join("api.sock");

    // Native mode fails closed before it binds the API socket.
    let output = spawn(&[
        "--native",
        "--seccomp-filter",
        without.to_str().unwrap(),
        "--api-sock",
        sock.to_str().unwrap(),
    ])
    .wait_with_output()
    .unwrap();
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("native_main"), "{stdout}");
    assert!(!sock.exists());

    // The same policy with the category starts native mode.
    map.insert("native_main".to_string(), policy);
    let with = dir.join("with.bpf");
    compile(&map, &with);
    let mut child = spawn(&[
        "--native",
        "--seccomp-filter",
        with.to_str().unwrap(),
        "--api-sock",
        sock.to_str().unwrap(),
    ]);
    wait_for(&sock, &mut child);
    child.kill().unwrap();
    child.wait().unwrap();
}

/// The guest fixture: `NATIVE_GUEST_DIR`, or `build/native-qualification-guest`.
fn guest_dir() -> PathBuf {
    std::env::var_os("NATIVE_GUEST_DIR").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/native-qualification-guest"),
        PathBuf::from,
    )
}

/// A fixture file: the name `var` gives, or `default`, in [`guest_dir`].
fn guest_file(var: &str, default: &str) -> PathBuf {
    guest_dir().join(std::env::var_os(var).map_or_else(|| default.into(), PathBuf::from))
}

/// Seals `image` in a memfd and returns a read-only description of it, as the jailer hands the
/// root image over.
fn sealed_root(image: &Path) -> File {
    // SAFETY: the name is a valid C string; the result is checked.
    let fd = unsafe {
        libc::memfd_create(
            c"native-root".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    // SAFETY: `fd` is a fresh descriptor owned by nothing else.
    let mut memfd = unsafe { File::from_raw_fd(fd) };
    memfd.write_all(&std::fs::read(image).unwrap()).unwrap();
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: adding seals to an owned memfd.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) }, 0);
    File::open(format!("/proc/self/fd/{fd}")).unwrap()
}

/// Sends one request and returns its status and body.
fn request(stream: &mut UnixStream, method: &str, path: &str, body: &str) -> (u16, String) {
    let request = format!(
        "{method} {path} HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: \
         {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let (statuses, text) = read_responses(stream, 1);
    (statuses[0], text)
}

/// Heartbeat ticks the guest printed so far.
fn heartbeats(serial: &Path) -> Vec<u64> {
    std::fs::read_to_string(serial)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_once("NATIVE_HEARTBEAT"))
        .filter_map(|(_, rest)| {
            rest.split_whitespace()
                .next()?
                .strip_prefix("tick=")?
                .parse()
                .ok()
        })
        .collect()
}

/// Boots the fixture guest through the native API, its root image a sealed read-only memfd
/// at descriptor 4, and waits for readiness and increasing heartbeats.
///
/// `cargo test [--release --target x86_64-unknown-linux-musl] -p firecracker --test native --
/// --ignored test_native_boots_sealed_root_fixture`, with `/dev/kvm` and `NATIVE_GUEST_DIR`
/// naming the extracted fixture.
#[test]
#[ignore = "needs /dev/kvm and the native guest fixture"]
fn test_native_boots_sealed_root_fixture() {
    let dir = scratch("boot");
    let sock = dir.join("api.sock");
    let serial = dir.join("serial.log");
    let root = sealed_root(&guest_file("NATIVE_GUEST_ROOTFS", "rootfs.squashfs"));
    let root_fd = root.as_raw_fd();

    let mut command = Command::new(firecracker());
    command
        .args(["--native", "--api-sock", sock.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(root_fd, 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // Every process this test starts is owned, and killed and reaped however the test ends.
    let mut family = Family::new();
    let mut child = command.spawn().unwrap();
    let source_pid = i32::try_from(child.id()).unwrap();
    family.own(source_pid);
    drop(root);
    wait_for(&sock, &mut child);

    let mut stream = UnixStream::connect(&sock).unwrap();
    let kernel = guest_file("NATIVE_GUEST_KERNEL", "vmlinux-6.1.155");
    let boot_source = format!(
        r#"{{"kernel_image_path":"{}","boot_args":"console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda ro rootfstype=squashfs init=/init"}}"#,
        kernel.canonicalize().unwrap().display()
    );
    let steps = [
        ("PUT", "/boot-source", boot_source),
        (
            "PUT",
            "/machine-config",
            r#"{"vcpu_count":2,"mem_size_mib":128}"#.to_string(),
        ),
        (
            "PUT",
            "/drives/rootfs",
            r#"{"drive_id":"rootfs","is_root_device":true,"is_read_only":true,"fd":4,"io_engine":"Sync"}"#.to_string(),
        ),
        (
            "PUT",
            "/serial",
            format!(r#"{{"serial_out_path":"{}"}}"#, serial.display()),
        ),
        (
            "PUT",
            "/actions",
            r#"{"action_type":"InstanceStart"}"#.to_string(),
        ),
    ];
    for (method, path, body) in steps {
        let (status, text) = request(&mut stream, method, path, &body);
        assert_eq!(status, 204, "{method} {path}: {text}");
    }

    let start = Instant::now();
    loop {
        let ticks = heartbeats(&serial);
        if std::fs::read_to_string(&serial)
            .unwrap_or_default()
            .contains("NATIVE_BOOT_READY")
            && ticks.len() >= 2
        {
            assert!(ticks.windows(2).all(|pair| pair[0] < pair[1]), "{ticks:?}");
            break;
        }
        assert!(child.try_wait().unwrap().is_none(), "firecracker exited");
        assert!(start.elapsed() < Duration::from_secs(30), "no heartbeats");
        std::thread::sleep(Duration::from_millis(100));
    }

    // Clone through the launcher contract: the source answers with the child's pid only once it
    // runs its original objects again and the child reported ready; the child serves nothing
    // and runs nothing until the launcher commits it on its own control connection.
    let child_sock = dir.join("child.sock");
    let child_serial = dir.join("child-serial.log");
    let control_sock = dir.join("control.sock");
    let control = std::os::unix::net::UnixListener::bind(&control_sock).unwrap();
    let (status, text) = request(
        &mut stream,
        "PUT",
        "/clone",
        &format!(
            r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"clone-1","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
            child_sock.display(),
            control_sock.display(),
            dir.join("child.log").display(),
            dir.join("child.metrics").display(),
            child_serial.display()
        ),
    );
    assert_eq!(status, 200, "{text}");
    let clone_pid: i32 = text
        .rsplit_once(r#""child_pid":"#)
        .and_then(|(_, rest)| rest.trim_end_matches('}').parse().ok())
        .unwrap_or_else(|| panic!("{text}"));
    family.own(clone_pid);
    let (mut child_control, _) = control.accept().unwrap();
    let mut ready = [0u8; 6];
    child_control.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready\n");
    let source_tick = *heartbeats(&serial).last().unwrap();
    // The source keeps running; the unpublished child neither serves nor runs.
    let start = Instant::now();
    while heartbeats(&serial).last().copied().unwrap_or(0) <= source_tick {
        assert!(start.elapsed() < Duration::from_secs(10), "source stalled");
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!child_sock.exists());
    assert!(heartbeats(&child_serial).is_empty());

    child_control.write_all(b"commit\n").unwrap();
    let start = Instant::now();
    while !child_sock.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no child API socket"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(1000));
    assert!(heartbeats(&child_serial).is_empty());
    // The child logs under its own identity, to its own log.
    assert!(
        std::fs::read_to_string(dir.join("child.log"))
            .unwrap_or_default()
            .lines()
            .all(|line| line.contains("[clone-1:"))
    );

    let mut child_stream = UnixStream::connect(&child_sock).unwrap();
    let (status, text) = request(&mut child_stream, "PATCH", "/vm", r#"{"state":"Resumed"}"#);
    assert_eq!(status, 204, "{text}");
    let start = Instant::now();
    loop {
        // The child continues the guest from the clone point, not from boot.
        if let Some(tick) = heartbeats(&child_serial).first() {
            assert!(*tick >= source_tick, "{tick} < {source_tick}");
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "child never ran");
        std::thread::sleep(Duration::from_millis(100));
    }
    family.kill(clone_pid);
    let source_tick = *heartbeats(&serial).last().unwrap();
    let start = Instant::now();
    while heartbeats(&serial).last().copied().unwrap_or(0) <= source_tick {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "source died with its clone"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    // Cancel: the unpublished child exits without serving or running.
    let (pid, mut control) = launch_clone(&mut family, &mut stream, &dir, "cancelled");
    control.write_all(b"cancel\n").unwrap();
    family.reap(pid);
    assert!(!dir.join("cancelled.sock").exists());
    assert!(heartbeats(&dir.join("cancelled-serial.log")).is_empty());

    // A child that cannot take its own outputs exits without writing anything to its source's
    // (checked at the end, once every holder of the source's streams is gone); the clone fails
    // and the source keeps running.
    let body = format!(
        r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"prerebind","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
        dir.join("prerebind.sock").display(),
        dir.join("prerebind-control.sock").display(),
        dir.join("missing/prerebind.log").display(),
        dir.join("prerebind.metrics").display(),
        dir.join("prerebind-serial.log").display()
    );
    let (status, text) = request(&mut stream, "PUT", "/clone", &body);
    assert_ne!(status, 200, "{text}");
    let tick = *heartbeats(&serial).last().unwrap();
    wait_for_tick(&serial, tick);
    assert!(!dir.join("prerebind.metrics").exists());

    // A child that took its own outputs but cannot rebuild, its console inside a missing
    // directory, fails before it is ready: it reports the typed restore error in its own log
    // only, never connects to the launcher, serves nothing and runs no guest; the clone fails
    // and the source keeps running.
    let control =
        std::os::unix::net::UnixListener::bind(dir.join("serialfail-control.sock")).unwrap();
    control.set_nonblocking(true).unwrap();
    let body = format!(
        r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"serialfail","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
        dir.join("serialfail.sock").display(),
        dir.join("serialfail-control.sock").display(),
        dir.join("serialfail.log").display(),
        dir.join("serialfail.metrics").display(),
        dir.join("missing/serialfail-serial.log").display()
    );
    let (status, text) = request(&mut stream, "PUT", "/clone", &body);
    assert_eq!(status, 400, "{text}");
    assert!(text.contains("The child could not get ready"), "{text}");
    let tick = *heartbeats(&serial).last().unwrap();
    wait_for_tick(&serial, tick);
    assert!(matches!(
        control.accept(),
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert!(!dir.join("serialfail.sock").exists());
    assert!(!dir.join("missing").exists());
    let child_log = std::fs::read_to_string(dir.join("serialfail.log")).unwrap();
    assert!(
        child_log.lines().any(|line| line.contains("[serialfail:")
            && line.contains("The clone's child failed: Cannot rebuild the child")),
        "{child_log}"
    );

    // Launcher death after commit ends the published child.
    let (pid, mut control) = launch_clone(&mut family, &mut stream, &dir, "orphaned");
    control.write_all(b"commit\n").unwrap();
    wait_for_path(&dir.join("orphaned.sock"));
    drop(control);
    family.reap(pid);

    // Nested: a published clone clones again, and its clone runs from the clone point too.
    let (clone_pid, mut clone_control) = launch_clone(&mut family, &mut stream, &dir, "parent");
    clone_control.write_all(b"commit\n").unwrap();
    wait_for_path(&dir.join("parent.sock"));
    let mut clone_stream = UnixStream::connect(dir.join("parent.sock")).unwrap();
    // A published child describes itself, not its source, and is Paused until resumed.
    clone_stream.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let (statuses, text) = read_responses(&mut clone_stream, 1);
    assert_eq!(statuses[0], 200, "{text}");
    assert!(text.contains(r#""id":"parent""#), "{text}");
    assert!(text.contains(r#""state":"Paused""#), "{text}");
    let (status, text) = request(&mut clone_stream, "PATCH", "/vm", r#"{"state":"Resumed"}"#);
    assert_eq!(status, 204, "{text}");
    let clone_tick = wait_for_tick(&dir.join("parent-serial.log"), 0);
    let (grandchild_pid, mut grandchild_control) =
        launch_clone(&mut family, &mut clone_stream, &dir, "grandchild");
    grandchild_control.write_all(b"commit\n").unwrap();
    wait_for_path(&dir.join("grandchild.sock"));
    let mut grandchild_stream = UnixStream::connect(dir.join("grandchild.sock")).unwrap();
    let (status, text) = request(
        &mut grandchild_stream,
        "PATCH",
        "/vm",
        r#"{"state":"Resumed"}"#,
    );
    assert_eq!(status, 204, "{text}");
    let first = wait_for_tick(&dir.join("grandchild-serial.log"), 0);
    assert!(first >= clone_tick, "{first} < {clone_tick}");

    // The source dying after publication leaves its published clone running, adopted by this
    // test's subreaper.
    family.kill(source_pid);
    let tick = *heartbeats(&dir.join("parent-serial.log")).last().unwrap();
    wait_for_tick(&dir.join("parent-serial.log"), tick);

    // The grandchild disposed of the event loop's copy of its source's control connection: once
    // the clone dies, its launcher reads end of stream while the grandchild still runs.
    family.kill(clone_pid);
    clone_control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    assert_eq!(clone_control.read(&mut [0u8; 1]).unwrap(), 0);
    let tick = *heartbeats(&dir.join("grandchild-serial.log"))
        .last()
        .unwrap();
    wait_for_tick(&dir.join("grandchild-serial.log"), tick);
    family.kill(grandchild_pid);
    let mut output = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(!output.contains("[prerebind:"), "{output}");
    assert!(!output.contains("[serialfail:"), "{output}");
}

/// Clones `stream`'s microVM as a launcher named `name`: returns the child's pid, owned by
/// `family` as soon as the source reports it, and its control connection once the child
/// reported ready.
fn launch_clone(
    family: &mut Family,
    stream: &mut UnixStream,
    dir: &Path,
    name: &str,
) -> (i32, UnixStream) {
    let control_sock = dir.join(format!("{name}-control.sock"));
    let listener = std::os::unix::net::UnixListener::bind(&control_sock).unwrap();
    let body = format!(
        r#"{{"api_sock":"{}","control_sock":"{}","instance_id":"{name}","log_path":"{}","metrics_path":"{}","serial_out_path":"{}"}}"#,
        dir.join(format!("{name}.sock")).display(),
        control_sock.display(),
        dir.join(format!("{name}.log")).display(),
        dir.join(format!("{name}.metrics")).display(),
        dir.join(format!("{name}-serial.log")).display()
    );
    let (status, text) = request(stream, "PUT", "/clone", &body);
    assert_eq!(status, 200, "{text}");
    let pid = text
        .rsplit_once(r#""child_pid":"#)
        .and_then(|(_, rest)| rest.trim_end_matches('}').parse().ok())
        .unwrap_or_else(|| panic!("{text}"));
    family.own(pid);
    let (mut control, _) = listener.accept().unwrap();
    let mut ready = [0u8; 6];
    control.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"ready\n");
    (pid, control)
}

fn wait_for_path(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "no {path:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Waits for a heartbeat tick above `after` on `serial` and returns it.
fn wait_for_tick(serial: &Path, after: u64) -> u64 {
    let start = Instant::now();
    loop {
        if let Some(tick) = heartbeats(serial)
            .last()
            .copied()
            .filter(|tick| *tick > after)
        {
            return tick;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "no heartbeat after {after}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Serializes process families: the subreaper attribute belongs to the whole test process.
static FAMILY_OWNER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The processes a test started, directly or through a source it launched, which it kills and
/// reaps when it ends, including through a failed assertion.
///
/// While a family exists, this process is a child subreaper: a clone that outlives its source
/// is adopted here rather than by init, and must be reaped here. Killing it alone leaves a
/// zombie that `kill(pid, 0)` still finds. A clone whose source still runs is reaped by the
/// kernel, its source ignoring SIGCHLD, and is never this process's to wait for.
struct Family {
    pids: Vec<i32>,
    _owner: std::sync::MutexGuard<'static, ()>,
}

impl Family {
    fn new() -> Self {
        let owner = FAMILY_OWNER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(subreaper(), 0, "this process is already a subreaper");
        // SAFETY: setting this process's subreaper attribute.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        Family {
            pids: Vec::new(),
            _owner: owner,
        }
    }

    /// Records `pid` as this test's to kill and reap.
    fn own(&mut self, pid: i32) {
        self.pids.push(pid);
    }

    /// Kills an owned process and waits until it is gone.
    fn kill(&mut self, pid: i32) {
        sigkill(pid).unwrap();
        self.reap(pid);
    }

    /// Waits until an owned process is gone.
    fn reap(&mut self, pid: i32) {
        if let Err(state) = gone(pid, Duration::from_secs(10)) {
            panic!("{pid} is not gone: {state}");
        }
        self.pids.retain(|owned| *owned != pid);
    }
}

impl Drop for Family {
    fn drop(&mut self) {
        for &pid in &self.pids {
            if let Err(err) = sigkill(pid) {
                eprintln!("cannot kill test process {pid}: {err}");
            }
        }
        for pid in std::mem::take(&mut self.pids) {
            if let Err(state) = gone(pid, Duration::from_secs(10)) {
                eprintln!("test process {pid} is left: {state}");
            }
        }
        // SAFETY: ending this process's subreaper role.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0) };
    }
}

/// Sends SIGKILL; a process already gone is not an error.
fn sigkill(pid: i32) -> std::io::Result<()> {
    // SAFETY: signalling one process this test owns.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::ESRCH) => Ok(()),
        _ => Err(err),
    }
}

/// Waits until `pid` is gone: reaped here when it is this process's child, by birth or
/// adoption, or else by its own parent. On timeout, returns its `/proc` state.
fn gone(pid: i32, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    loop {
        let mut status = 0;
        // SAFETY: waiting for this one process only.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            return Ok(());
        }
        if waited < 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                // Not this process's child, at least not yet: its parent reaps it.
                // SAFETY: probing whether the process exists.
                Some(libc::ECHILD) => match unsafe { libc::kill(pid, 0) } {
                    0 => {}
                    _ => {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::ESRCH) {
                            return Ok(());
                        }
                        return Err(format!("kill(0): {err}"));
                    }
                },
                Some(libc::EINTR) => continue,
                _ => return Err(format!("waitpid: {err}")),
            }
        }
        if start.elapsed() > timeout {
            return Err(format!("state {:?}", proc_state(pid)));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The state letter and parent of `pid` in `/proc`, if it still has an entry.
fn proc_state(pid: i32) -> Option<(char, i32)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let state = fields.next()?.chars().next()?;
    Some((state, fields.next()?.parse().ok()?))
}

/// Forks a stand-in for a native source, owned by `family` from the fork on: it ignores SIGCHLD,
/// as native mode does, and, if `report`, forks a stand-in clone and reports its pid, which is
/// owned as soon as it is read; otherwise it closes the report unwritten. Both then wait for a
/// signal. Returns both pids.
fn fork_source_and_clone(family: &mut Family, report: bool) -> (i32, i32) {
    use std::os::fd::FromRawFd;

    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for both descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: the descriptors were just created, and each is owned once.
    let (reader, writer) = unsafe {
        (
            std::os::fd::OwnedFd::from_raw_fd(fds[0]),
            std::os::fd::OwnedFd::from_raw_fd(fds[1]),
        )
    };
    // SAFETY: the forked processes only make async-signal-safe calls.
    let source = unsafe { libc::fork() };
    assert!(source >= 0);
    if source == 0 {
        // SAFETY: as above.
        unsafe {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            if report {
                let clone = libc::fork();
                if clone != 0 {
                    libc::write(fds[1], (&raw const clone).cast(), size_of::<i32>());
                }
            }
            libc::close(fds[1]);
            loop {
                libc::pause();
            }
        }
    }
    family.own(source);
    drop(writer);
    let mut clone = [0u8; size_of::<i32>()];
    File::from(reader).read_exact(&mut clone).unwrap();
    let clone = i32::from_ne_bytes(clone);
    assert!(clone > 0, "the stand-in source could not fork");
    family.own(clone);
    (source, clone)
}

fn exists(pid: i32) -> bool {
    // SAFETY: probing whether a process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Once its source is gone, a clone is adopted by the test's subreaper; killed, it stays a
/// zombie that `kill(pid, 0)` still finds, so probing alone never sees it go, until the family
/// reaps it. A failure inside the stand-in's construction, before the clone's pid arrives,
/// leaves the source owned; a failed assertion unwinding through a family kills and reaps
/// everything it owns, and the next family recovers the owner lock that unwinding poisoned.
#[test]
fn test_family_reaps_adopted_clones_and_cleans_up_after_failure() {
    {
        let mut family = Family::new();
        let (source, clone) = fork_source_and_clone(&mut family, true);
        family.kill(source);
        assert!(!exists(source));
        let this = i32::try_from(std::process::id()).unwrap();
        let start = Instant::now();
        while proc_state(clone).map(|(_, parent)| parent) != Some(this) {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "{clone} not adopted"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        sigkill(clone).unwrap();
        while proc_state(clone).map(|(state, _)| state) != Some('Z') {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "{clone} still runs"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(exists(clone), "a killed, unreaped orphan is still found");
        family.reap(clone);
        assert!(!exists(clone));
        assert_eq!(proc_state(clone), None);
    }

    // A constructor failure before the clone's pid arrives leaves the source owned.
    let mut family = Family::new();
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        fork_source_and_clone(&mut family, false);
    }));
    assert!(failed.is_err());
    let owned = family.pids.clone();
    assert_eq!(owned.len(), 1);
    drop(family);
    assert_gone(&owned);

    // A failed assertion with the family owned by the failing scope: unwinding drops it.
    let mut family = Family::new();
    fork_source_and_clone(&mut family, true);
    let owned = family.pids.clone();
    assert_eq!(owned.len(), 2);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _family = family;
        panic!("a failed assertion while the family runs");
    }));
    assert!(failed.is_err());
    assert_gone(&owned);
    assert!(FAMILY_OWNER.is_poisoned());
    assert_eq!(subreaper(), 0);
    let family = Family::new();
    assert_eq!(subreaper(), 1);
    drop(family);
    assert_eq!(subreaper(), 0);
}

fn assert_gone(pids: &[i32]) {
    for &pid in pids {
        assert!(!exists(pid), "{pid} survived the failed test");
        assert_eq!(proc_state(pid), None);
    }
}

/// This process's child subreaper attribute.
fn subreaper() -> libc::c_int {
    let mut subreaper: libc::c_int = -1;
    // SAFETY: reading this process's subreaper attribute.
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut subreaper) },
        0
    );
    subreaper
}
