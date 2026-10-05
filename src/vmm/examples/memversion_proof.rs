// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Privileged nested-kernel proof driver, not a production pagemaster or backend bypass.
//! Usage: memversion_proof FIRECRACKER JAILER GUEST_ELF EMPTY_WORK_DIRECTORY
//! Requires root, /dev/kvm, /dev/memversion_v1, procfs, devpts and the default release seccomp.
//! The two jailed FCs get their own ptys; the driver's stdin need not be a tty.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;
use vmm::vstate::farplane::protocol::{self, Incoming, MsgType};
use vmm_sys_util::ioctl::ioctl_with_mut_ref;

const BASE: u64 = 0x3000_0000_0000;
const RAM: u64 = 64 << 20;
const PATTERN: u64 = 0x400000;
const TIMEOUT: Duration = Duration::from_secs(30);
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[repr(C)]
#[derive(Debug)]
struct Info {
    abi: u32,
    nr_regions: u32,
    regions: u64,
    present: u64,
    excluded: u64,
    new_pages: u64,
}

fn info(fd: &OwnedFd) -> Info {
    let mut regions = [[0u64; 2]; 16];
    let mut value = Info {
        abi: 1,
        nr_regions: 16,
        regions: regions.as_mut_ptr() as u64,
        present: 0,
        excluded: 0,
        new_pages: 0,
    };
    assert_eq!(size_of::<Info>(), 40);
    assert_eq!(std::mem::offset_of!(Info, new_pages), 32);
    assert_eq!(
        // SAFETY: value and the region output array remain live and writable through the ioctl.
        unsafe { ioctl_with_mut_ref(fd, 0xc0285642, &mut value) },
        0,
        "INFO: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!((value.abi, value.nr_regions), (1, 1));
    assert_eq!(regions[0], [BASE, RAM]);
    value
}

fn buffer(name: &std::ffi::CStr, size: u64) -> File {
    // SAFETY: the C string is NUL terminated and remains live.
    let raw = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING) };
    assert!(raw >= 0);
    // SAFETY: newly created descriptor, uniquely owned here.
    let file = unsafe { File::from_raw_fd(raw) };
    file.set_len(size).unwrap();
    file
}

fn seal(file: &File, flags: i32) {
    assert_eq!(
        // SAFETY: this modifies seals on our live file descriptor only.
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, flags) },
        0
    );
}

fn readonly(file: &File) -> File {
    File::open(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap()
}

fn listener(path: &Path, uid: u32) -> File {
    // SAFETY: socket creates a new descriptor without accessing application memory.
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0);
    // SAFETY: newly allocated raw descriptor has no other owner.
    let file = unsafe { File::from_raw_fd(raw) };
    let mut addr = libc::sockaddr_un {
        sun_family: libc::AF_UNIX.try_into().unwrap(),
        sun_path: [0; 108],
    };
    let bytes = path.as_os_str().as_encoded_bytes();
    assert!(bytes.len() < addr.sun_path.len());
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = libc::c_char::from_ne_bytes([*src]);
    }
    assert_eq!(
        // SAFETY: addr is a valid initialized sockaddr_un of the supplied length.
        unsafe {
            libc::bind(
                raw,
                std::ptr::addr_of!(addr).cast(),
                size_of_val(&addr).try_into().unwrap(),
            )
        },
        0
    );
    fs::set_permissions(path, fs::Permissions::from_mode(0o777)).unwrap();
    // Match jailed FC's peer-uid requirement. No other thread exists during this transition.
    // SAFETY: geteuid only reads this process's effective uid.
    let original = unsafe { libc::geteuid() };
    // SAFETY: the privileged test driver deliberately changes its effective uid for listen only.
    assert_eq!(unsafe { libc::seteuid(uid) }, 0);
    // SAFETY: listen operates on the valid bound socket.
    let rc = unsafe { libc::listen(raw, 1) };
    // SAFETY: restore the privileged driver's saved real uid before starting other threads.
    assert_eq!(unsafe { libc::seteuid(original) }, 0);
    assert_eq!(rc, 0);
    file
}

fn accept(listener: &File) -> UnixStream {
    let mut poll = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        // SAFETY: poll references one initialized pollfd for a bounded timeout.
        unsafe { libc::poll(&mut poll, 1, 30_000) },
        1,
        "handshake timeout"
    );
    // SAFETY: no address output is requested, valid listening descriptor.
    let raw = unsafe {
        libc::accept4(
            listener.as_raw_fd(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert!(raw >= 0);
    // SAFETY: accept4 returned a new uniquely owned descriptor.
    let sock = unsafe { UnixStream::from_raw_fd(raw) };
    sock.set_read_timeout(Some(TIMEOUT)).unwrap();
    sock
}

fn api(path: &Path, endpoint: &str, value: serde_json::Value) -> Result<()> {
    let body = value.to_string();
    let mut sock = UnixStream::connect(path)?;
    sock.set_read_timeout(Some(TIMEOUT))?;
    write!(
        sock,
        "PUT {endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut response = Vec::new();
    let mut data = [0; 4096];
    loop {
        let n = sock.read(&mut data)?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&data[..n]);
        if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&response[..end]);
            let length = header
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if response.len() >= end + 4 + length {
                break;
            }
        }
    }
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 204"),
        "{endpoint}: {response}"
    );
    Ok(())
}

struct ChildOwner(Child);

impl std::ops::Deref for ChildOwner {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for ChildOwner {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Vm {
    child: ChildOwner,
    console: File,
    transcript: File,
    socket: UnixStream,
    next_id: u64,
    vmstate_capacity: u64,
}

impl Vm {
    fn stop(mut self) {
        use std::os::unix::process::ExitStatusExt;
        let pid = self.child.id();
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "FC exited before explicit teardown"
        );
        self.child.kill().unwrap();
        assert_eq!(self.child.wait().unwrap().signal(), Some(libc::SIGKILL));
        assert!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "FC was not reaped"
        );
        println!("JOIN pid={pid} reaped=1");
    }

    fn start(
        fc: &Path,
        jailer: &Path,
        guest: &Path,
        work: &Path,
        id: &str,
        restore: Option<(&OwnedFd, &File)>,
        producer: &[u8],
    ) -> Result<Self> {
        let jail = work.join(fc.file_name().unwrap()).join(id).join("root");
        fs::create_dir_all(&jail)?;
        fs::set_permissions(&jail, fs::Permissions::from_mode(0o777))?;
        fs::copy(guest, jail.join("guest.elf"))?;
        let listener = listener(&jail.join("memory.sock"), 1234);
        let root = buffer(c"unused-root-image", 4096);
        seal(
            &root,
            libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL,
        );
        let root = readonly(&root);
        // Rust opens files CLOEXEC; only the intentionally passed root descriptor survives exec.
        assert_eq!(
            // SAFETY: F_SETFD modifies descriptor flags for this driver's file.
            unsafe { libc::fcntl(root.as_raw_fd(), libc::F_SETFD, 0) },
            0
        );
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            // SAFETY: both output pointers are valid; null termios/winsize request system defaults.
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        // SAFETY: openpty transferred two newly allocated descriptors.
        let (console, terminal) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        assert_eq!(
            // SAFETY: file status flags belong to this live pty descriptor.
            unsafe { libc::fcntl(master, libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let child = Command::new(jailer)
            .args(["--id", id, "--exec-file"])
            .arg(fc)
            .args([
                "--uid",
                "1234",
                "--gid",
                "1234",
                "--root-fd",
                &root.as_raw_fd().to_string(),
                "--resource-limit",
                "memlock=67108864",
                "--chroot-base-dir",
            ])
            .arg(work)
            .args([
                "--",
                "--api-sock",
                "/api.sock",
                "--farplane-mem-socket",
                "/memory.sock",
                "--log-path",
                "/fc.log",
                "--level",
                "Debug",
            ])
            .stdin(Stdio::from(terminal.try_clone()?))
            .stdout(Stdio::from(terminal.try_clone()?))
            .stderr(Stdio::from(terminal))
            .spawn()?;
        let mut child = ChildOwner(child);
        let api_path = jail.join("api.sock");
        let deadline = Instant::now() + TIMEOUT;
        while !api_path.exists() {
            assert!(
                child.try_wait()?.is_none(),
                "jailer exited before API startup"
            );
            assert!(Instant::now() < deadline, "API startup timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
        if restore.is_none() {
            api(
                &api_path,
                "/machine-config",
                json!({"vcpu_count":1,"mem_size_mib":64}),
            )?;
            api(
                &api_path,
                "/boot-source",
                json!({"kernel_image_path":"/guest.elf","boot_args":"console=ttyS0"}),
            )?;
        }
        let restore_mode = restore.is_some();
        let request = std::thread::spawn(move || {
            if restore_mode {
                api(&api_path, "/snapshot/load", json!({"resume_vm":false}))
            } else {
                api(
                    &api_path,
                    "/actions",
                    json!({"action_type":"InstanceStart"}),
                )
            }
        });
        let socket = accept(&listener);
        let hello = protocol::recv_frame(&socket)?;
        assert_eq!(hello.header.msg(), MsgType::Hello);
        assert!(hello.fds.is_empty());
        assert_eq!(&hello.body[16..26], b"farplane/7");
        assert_eq!(
            u16::from_le_bytes(hello.body[10..12].try_into()?),
            if restore_mode { 2 } else { 1 }
        );
        let mut plan = Vec::new();
        for value in [std::process::id(), 1, 0, u32::from(restore_mode)] {
            plan.extend(value.to_le_bytes());
        }
        plan.extend(0u64.to_le_bytes());
        plan.extend(RAM.to_le_bytes());
        let rights = if let Some((version, vmstate)) = restore {
            plan.extend(producer);
            vec![version.as_raw_fd(), vmstate.as_raw_fd()]
        } else {
            vec![]
        };
        protocol::send_frame(&socket, MsgType::BackingPlan, 1, &plan, &rights)?;
        let ready = protocol::recv_frame(&socket)?;
        assert_eq!(ready.header.msg(), MsgType::BackendReady, "{ready:?}");
        assert!(ready.fds.is_empty());
        assert_eq!(ready.body.len(), 56);
        assert_eq!(
            &ready.body[4..28],
            [0u64, RAM, BASE].map(u64::to_le_bytes).concat()
        );
        assert_eq!(&ready.body[32..48], &[0u8; 16]);
        let capacity = u64::from_le_bytes(ready.body[48..56].try_into()?);
        protocol::send_frame(&socket, MsgType::Resume, 2, &0u32.to_le_bytes(), &[])?;
        assert_eq!(
            protocol::recv_frame(&socket)?.header.msg(),
            MsgType::Resumed
        );
        request.join().expect("API worker panicked")?;
        let vm = Self {
            child,
            console,
            transcript: File::create(work.join(format!("{id}.console")))?,
            socket,
            next_id: 3,
            vmstate_capacity: capacity,
        };
        Ok(vm)
    }

    fn assert_confined(&self) {
        let base = format!("/proc/{}", self.child.id());
        for task in fs::read_dir(format!("{base}/task")).unwrap() {
            let status = fs::read_to_string(task.unwrap().path().join("status")).unwrap();
            assert!(
                status.lines().any(|l| l == "Seccomp:\t2"),
                "unconfined FC task: {status}"
            );
            assert!(
                status
                    .lines()
                    .any(|l| l.starts_with("Uid:\t1234\t1234\t1234\t1234"))
            );
        }
        assert!(
            !Path::new(&format!("{base}/root/proc/self/maps")).exists(),
            "jail has procfs"
        );
    }

    fn request_id(&self, msg: MsgType, id: u64, body: &[u8], fds: &[RawFd]) -> Incoming {
        protocol::send_frame(&self.socket, msg, id, body, fds).unwrap();
        let response = protocol::recv_frame(&self.socket).unwrap();
        assert_ne!(response.header.msg(), MsgType::Error, "{response:?}");
        assert_eq!(response.header.request_id, id);
        response
    }
    fn request(&mut self, msg: MsgType, body: &[u8], fds: &[RawFd]) -> Incoming {
        let id = self.next_id;
        self.next_id += 1;
        self.request_id(msg, id, body, fds)
    }
    fn resume(&mut self) {
        assert_eq!(
            self.request(MsgType::Resume, &1u32.to_le_bytes(), &[])
                .header
                .msg(),
            MsgType::Resumed
        );
    }
    fn serial(&mut self, command: Option<u8>, marker: &str) -> Result<()> {
        if let Some(byte) = command {
            self.console.write_all(&[byte])?;
        }
        let deadline = Instant::now() + TIMEOUT;
        let mut text = String::new();
        loop {
            let mut bytes = [0u8; 4096];
            match self.console.read(&mut bytes) {
                Ok(n) if n > 0 => {
                    self.transcript.write_all(&bytes[..n])?;
                    text.push_str(&String::from_utf8_lossy(&bytes[..n]));
                    assert!(!text.contains("MVG FAIL"), "guest pattern mismatch");
                    if text.contains(marker) {
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("FC console ended: {other:?}; {text}"),
            }
            assert!(self.child.try_wait()?.is_none(), "FC exited: {text}");
            assert!(Instant::now() < deadline, "guest marker timeout: {text}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn capture(&mut self, device: &File) -> (OwnedFd, File, Info) {
        let vmstate = buffer(c"vmstate", self.vmstate_capacity);
        seal(&vmstate, libc::F_SEAL_GROW | libc::F_SEAL_SHRINK);
        assert_eq!(
            self.request(MsgType::CaptureBuffers, &[], &[vmstate.as_raw_fd()])
                .header
                .msg(),
            MsgType::CaptureBuffersArmed
        );
        assert_eq!(
            self.request(MsgType::Quiesce, &[], &[]).header.msg(),
            MsgType::Quiesced
        );
        let response = self.request(MsgType::WriteVmstate, &[], &[device.as_raw_fd()]);
        assert_eq!(response.header.msg(), MsgType::VmstateWritten);
        let length = u64::from_le_bytes(response.body[..].try_into().unwrap());
        let [version] = <[_; 1]>::try_from(response.fds).unwrap();
        let exact = self.request_id(
            MsgType::WriteVmstate,
            self.next_id - 1,
            &[],
            &[device.as_raw_fd()],
        );
        let epoch = self.request(MsgType::WriteVmstate, &[], &[device.as_raw_fd()]);
        for replay in [exact, epoch] {
            assert_eq!(replay.header.msg(), MsgType::VmstateWritten);
            assert_eq!(replay.body, length.to_le_bytes());
            let [same] = <[_; 1]>::try_from(replay.fds).unwrap();
            // kcmp(FILE), unlike anon-inode stat, proves the SAME open file description.
            assert_eq!(
                // SAFETY: syscall compares live descriptor numbers owned by this process.
                unsafe {
                    libc::syscall(
                        libc::SYS_kcmp,
                        std::process::id(),
                        std::process::id(),
                        0,
                        version.as_raw_fd(),
                        same.as_raw_fd(),
                    )
                },
                0
            );
        }
        let finalized = buffer(c"final-vmstate", length);
        let mut bytes = vec![0; usize::try_from(length).unwrap()];
        vmstate.read_exact_at(&mut bytes, 0).unwrap();
        finalized.write_all_at(&bytes, 0).unwrap();
        seal(
            &finalized,
            libc::F_SEAL_GROW
                | libc::F_SEAL_SHRINK
                | libc::F_SEAL_WRITE
                | libc::F_SEAL_FUTURE_WRITE
                | libc::F_SEAL_SEAL,
        );
        let stats = info(&version);
        println!(
            "CAPTURE pid={} bytes={length} present={} new_pages={} replay_same=1",
            self.child.id(),
            stats.present,
            stats.new_pages
        );
        (version, readonly(&finalized), stats)
    }
    fn pfns(&self) -> [u64; 4] {
        let map = File::open(format!("/proc/{}/pagemap", self.child.id())).unwrap();
        std::array::from_fn(|index| {
            let mut bytes = [0; 8];
            map.read_exact_at(&mut bytes, ((BASE + PATTERN) / 4096 + index as u64) * 8)
                .unwrap();
            let entry = u64::from_le_bytes(bytes);
            assert_ne!(entry & (1 << 63), 0, "pattern page not resident");
            let pfn = entry & ((1 << 55) - 1);
            assert_ne!(pfn, 0, "privileged PFN oracle unavailable");
            pfn
        })
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    assert_eq!(
        args.len(),
        5,
        "usage: memversion_proof FIRECRACKER JAILER GUEST_ELF EMPTY_WORK_DIRECTORY"
    );
    let fc = fs::canonicalize(&args[1])?;
    let jailer = fs::canonicalize(&args[2])?;
    let guest = fs::canonicalize(&args[3])?;
    let work = PathBuf::from(&args[4]);
    fs::create_dir(&work)?;
    let work = fs::canonicalize(work)?;
    let producer = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &fs::read(&fc)?);
    let device = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/memversion_v1")?;
    let mut a = Vm::start(&fc, &jailer, &guest, &work, "a", None, producer.as_ref())?;
    // Cold InstanceStart leaves this backend paused; quiesce establishes a resumable epoch.
    a.request(MsgType::Quiesce, &[], &[]);
    a.assert_confined();
    a.resume();
    a.serial(None, "MVG READY")?;
    a.serial(Some(b'v'), "MVG VERIFIED")?;
    let (av, ast, ai) = a.capture(&device);
    assert!(ai.new_pages >= 4);
    let ap = a.pfns();
    let mut b = Vm::start(
        &fc,
        &jailer,
        &guest,
        &work,
        "b",
        Some((&av, &ast)),
        producer.as_ref(),
    )?;
    b.request(MsgType::Quiesce, &[], &[]);
    b.assert_confined();
    b.resume();
    b.serial(Some(b'v'), "MVG VERIFIED")?;
    let (baseline, _bst, _) = b.capture(&device);
    assert_eq!(ap, b.pfns(), "restore copied unwritten pattern pages");
    println!("SHARING same_pfn_pages=4 guest_verified=1 confined=1");
    a.stop();
    b.resume();
    b.serial(Some(b'v'), "MVG VERIFIED")?;
    println!("PARENT_DELETED child_verified=1");
    b.serial(Some(b'w'), "MVG VERIFIED")?;
    let (deep, _dst, di) = b.capture(&device);
    assert_eq!(
        di.new_pages, 2,
        "baseline retains restore metadata; guest writes exactly two pages"
    );
    let bp = b.pfns();
    assert_ne!(bp[0], ap[0]);
    assert_ne!(bp[1], ap[1]);
    assert_eq!(&bp[2..], &ap[2..]);
    assert_eq!(info(&av).new_pages, ai.new_pages);
    drop((deep, baseline, av));
    b.resume();
    b.serial(Some(b'v'), "MVG VERIFIED")?;
    b.stop();
    println!(
        "MEMVERSION_FC_PASS jailed=2 seccomp=1 same_pfn=4 cow_pages=2 new_pages=2 replay_same=1 parent_delete=1 joined=2"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn api_handles_split_http_headers_and_body() {
        let dir = TempDir::new().unwrap();
        let path = dir.as_path().join("api.sock");
        let server = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let mut peer = server.accept().unwrap().0;
            let mut request = [0; 1024];
            assert!(peer.read(&mut request).unwrap() > 0);
            peer.write_all(b"HTTP/1.1 204 No Content\r\nContent-Len")
                .unwrap();
            peer.write_all(b"gth: 0\r\n\r\n").unwrap();
        });
        api(&path, "/test", json!({"a":1})).unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn vmstate_finalization_preserves_exact_bytes_and_seals() {
        let source = buffer(c"fixture", 4096);
        source.write_all_at(b"exact", 0).unwrap();
        seal(
            &source,
            libc::F_SEAL_GROW
                | libc::F_SEAL_SHRINK
                | libc::F_SEAL_WRITE
                | libc::F_SEAL_FUTURE_WRITE
                | libc::F_SEAL_SEAL,
        );
        let ro = readonly(&source);
        let mut bytes = [0; 5];
        ro.read_exact_at(&mut bytes, 0).unwrap();
        assert_eq!(&bytes, b"exact");
        assert!(ro.write_all_at(b"bad", 0).is_err());
        assert!(source.write_all_at(b"bad", 0).is_err());
    }

    #[test]
    fn child_owner_reaps_even_on_early_return() {
        let child = ChildOwner(Command::new("sleep").arg("30").spawn().unwrap());
        let pid = child.id();
        drop(child);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    fn seqpacket_peer_credential_and_rights_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.as_path().join("memory.sock");
        // SAFETY: geteuid only reads this process's effective uid.
        let listening = listener(&path, unsafe { libc::geteuid() });
        let worker = std::thread::spawn(move || {
            // SAFETY: socket allocates a uniquely owned descriptor.
            let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET, 0) };
            assert!(fd >= 0);
            // SAFETY: this new descriptor has no other owner.
            let sock = unsafe { UnixStream::from_raw_fd(fd) };
            let mut addr = libc::sockaddr_un {
                sun_family: libc::AF_UNIX.try_into().unwrap(),
                sun_path: [0; 108],
            };
            for (dst, src) in addr
                .sun_path
                .iter_mut()
                .zip(path.as_os_str().as_encoded_bytes())
            {
                *dst = libc::c_char::from_ne_bytes([*src]);
            }
            // SAFETY: sockaddr is initialized and live for the call.
            assert_eq!(
                unsafe {
                    libc::connect(
                        fd,
                        std::ptr::addr_of!(addr).cast(),
                        size_of_val(&addr).try_into().unwrap(),
                    )
                },
                0
            );
            let file = buffer(c"mock-version", 4096);
            protocol::send_frame(
                &sock,
                MsgType::VmstateWritten,
                7,
                &64u64.to_le_bytes(),
                &[file.as_raw_fd()],
            )
            .unwrap();
        });
        let connection = accept(&listening);
        let response = protocol::recv_frame(&connection).unwrap();
        assert_eq!(response.header.request_id, 7);
        assert_eq!(response.fds.len(), 1);
        assert_eq!(response.body, 64u64.to_le_bytes());
        worker.join().unwrap();
    }
}
