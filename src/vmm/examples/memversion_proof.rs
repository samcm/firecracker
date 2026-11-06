// Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Privileged nested-kernel proof driver, not a production pagemaster or backend bypass.
//! Usage: memversion_proof FIRECRACKER JAILER GUEST_ELF EMPTY_WORK_DIRECTORY
//! Requires root, /dev/kvm, /dev/memversion_v1, procfs, devpts and the default release seccomp.
//! The two jailed FCs get their own ptys; the driver's stdin need not be a tty.

use std::collections::BTreeMap;
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
// Production memoryenvelope: guest bytes + FirecrackerWorkingSetBytes, not RAM alone.
const WORKING_SET: u64 = 64 << 20;
const MEMLOCK: u64 = RAM + WORKING_SET;
const MEMLOCK_MARGIN: u64 = 1 << 20;
// Exact bootstrap paging layout in arch/x86_64/regs.rs, not an allowance for arbitrary pages.
const PAGE_TABLES: [(u64, &str); 3] = [(0x9000, "PML4"), (0xa000, "PDPT"), (0xb000, "PD")];
const PFN_MASK: u64 = (1 << 55) - 1;
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
        let n = match sock.read(&mut data) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
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

// Drain from spawn, including while the main thread blocks in API/memory-channel calls.
// EIO is the terminal's EOF after its slave closes. Preserve stdout AND stderr in one file.
fn capture_console(
    mut console: File,
    mut transcript: File,
) -> (
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::thread::JoinHandle<std::io::Result<()>>,
) {
    let (send, receive) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        loop {
            let mut bytes = [0u8; 4096];
            match console.read(&mut bytes) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    transcript.write_all(&bytes[..n])?;
                    let _ = send.send(bytes[..n].to_vec());
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(err) if err.raw_os_error() == Some(libc::EIO) => return Ok(()),
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
    });
    (receive, reader)
}

fn dump_logs(work: &Path) {
    // The wrapper repeats these on normal exit too; this hook runs even in panic=abort builds.
    for id in ["a", "b"] {
        if let Ok(pid) = fs::read_to_string(work.join(format!("{id}.pid"))) {
            for name in ["status", "limits"] {
                let path = format!("/proc/{}/{name}", pid.trim());
                if let Ok(text) = fs::read_to_string(&path) {
                    eprintln!("--- {path} ---\n{text}");
                }
            }
        }
        let path = work.join(format!("{id}.console"));
        if let Ok(bytes) = fs::read(&path) {
            eprintln!(
                "--- {} ---\n{}",
                path.display(),
                String::from_utf8_lossy(&bytes)
            );
        }
    }
    if let Ok(binaries) = fs::read_dir(work) {
        for binary in binaries.flatten().filter(|entry| entry.path().is_dir()) {
            for id in ["a", "b"] {
                let path = binary.path().join(id).join("root/fc.log");
                if let Ok(bytes) = fs::read(&path) {
                    eprintln!(
                        "--- {} ---\n{}",
                        path.display(),
                        String::from_utf8_lossy(&bytes)
                    );
                }
            }
        }
    }
}

struct ObservedPage {
    entry: u64,
    bytes: Vec<u8>,
}

fn page_changes(
    stage: &str,
    before: &BTreeMap<u64, ObservedPage>,
    after: &BTreeMap<u64, ObservedPage>,
) -> Vec<u64> {
    let mut changed = Vec::new();
    for (gpa, page) in after {
        let old = before.get(gpa).map_or(0, |page| page.entry);
        let became_exclusive = old & (1 << 56) == 0 && page.entry & (1 << 56) != 0;
        let pfn_changed = old & PFN_MASK != page.entry & PFN_MASK;
        if pfn_changed || became_exclusive {
            let name = PAGE_TABLES
                .iter()
                .find(|(addr, _)| addr == gpa)
                .map_or("unclassified", |(_, name)| *name);
            println!(
                "PAGE_CHANGE stage={stage} gpn={:#x} gpa={gpa:#x} before_pfn={:#x} after_pfn={:#x} became_exclusive={became_exclusive} name={name}",
                gpa / 4096,
                old & PFN_MASK,
                page.entry & PFN_MASK
            );
            if pfn_changed {
                changed.push(*gpa);
            }
        }
        // Pagemap exclusive is mapping-count metadata, not proof that a version released
        // ownership (killing FC-A can change it). The baseline version stays retained here.
        if !pfn_changed {
            assert_eq!(
                before[gpa].bytes, page.bytes,
                "retained version's PFN mutated in place"
            );
        }
    }
    for gpa in before.keys() {
        assert!(
            after.contains_key(gpa),
            "resident page disappeared: {gpa:#x}"
        );
    }
    println!("PAGE_CHANGE_SET stage={stage} gpas={changed:x?}");
    changed
}

fn assert_paging_maintenance(
    before: &BTreeMap<u64, ObservedPage>,
    after: &BTreeMap<u64, ObservedPage>,
    changed: &[u64],
) {
    for gpa in changed {
        let (_, name) = PAGE_TABLES
            .iter()
            .find(|(addr, _)| addr == gpa)
            .expect("unexplained page changed during read-only resume");
        let old = &before[gpa].bytes;
        let new = &after[gpa].bytes;
        assert_eq!((old.len(), new.len()), (4096, 4096));
        let mut differences = 0;
        for (index, (old, new)) in old.chunks_exact(8).zip(new.chunks_exact(8)).enumerate() {
            let old = u64::from_le_bytes(old.try_into().unwrap());
            let new = u64::from_le_bytes(new.try_into().unwrap());
            if old != new {
                println!(
                    "PAGE_TABLE_WORD name={name} gpa={:#x} before={old:#x} after={new:#x}",
                    gpa + index as u64 * 8
                );
                differences += 1;
            }
            // Only hardware accessed/dirty bits may change. Other writes remain a finding.
            assert_eq!(old & !0x60, new & !0x60, "unexplained page-table mutation");
        }
        println!(
            "PAGING_MAINTENANCE name={name} gpa={gpa:#x} changed_words={differences} identical_bytes={}",
            differences == 0
        );
    }
}

struct Vm {
    child: ChildOwner,
    console: File,
    console_messages: std::sync::mpsc::Receiver<Vec<u8>>,
    console_reader: std::thread::JoinHandle<std::io::Result<()>>,
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
        self.console_reader.join().unwrap().unwrap();
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
        let transcript = File::create(work.join(format!("{id}.console")))?;
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
                &format!("memlock={MEMLOCK}"),
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
        fs::write(work.join(format!("{id}.pid")), child.id().to_string())?;
        let (console_messages, console_reader) = capture_console(console.try_clone()?, transcript);
        let api_path = jail.join("api.sock");
        let deadline = Instant::now() + TIMEOUT;
        while !api_path.exists() {
            if let Some(status) = child.try_wait()? {
                console_reader.join().expect("console reader panicked")?;
                dump_logs(work);
                return Err(format!(
                    "jailer pid={} exited before API startup: {status}",
                    child.id()
                )
                .into());
            }
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
        assert_eq!(&hello.body[16..48], &protocol::feature_identity_padded());
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
            console_messages,
            console_reader,
            socket,
            next_id: 3,
            vmstate_capacity: capacity,
        };
        vm.assert_memlock(if restore_mode { "restore" } else { "boot" });
        Ok(vm)
    }

    fn assert_memlock(&self, stage: &str) {
        let base = format!("/proc/{}", self.child.id());
        let status = fs::read_to_string(format!("{base}/status")).unwrap();
        let locked = status
            .lines()
            .find_map(|line| line.strip_prefix("VmLck:"))
            .expect("VmLck missing")
            .split_whitespace()
            .next()
            .unwrap()
            .parse::<u64>()
            .unwrap()
            * 1024;
        let limits = fs::read_to_string(format!("{base}/limits")).unwrap();
        let limit_line = limits
            .lines()
            .find_map(|line| line.strip_prefix("Max locked memory"))
            .expect("RLIMIT_MEMLOCK missing");
        let mut fields = limit_line.split_whitespace();
        let soft: u64 = fields.next().unwrap().parse().unwrap();
        let hard: u64 = fields.next().unwrap().parse().unwrap();
        println!(
            "MEMLOCK stage={stage} pid={} guest={RAM} working_set={WORKING_SET} limit={MEMLOCK} soft={soft} hard={hard} VmLck={locked} margin={MEMLOCK_MARGIN}",
            self.child.id()
        );
        assert_eq!((soft, hard), (MEMLOCK, MEMLOCK));
        assert!(locked >= RAM, "guest RAM must be locked");
        assert!(
            locked <= MEMLOCK - MEMLOCK_MARGIN,
            "VMM exceeds working-set allowance"
        );
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
            match self.console_messages.recv_timeout(Duration::from_millis(5)) {
                Ok(bytes) => {
                    text.push_str(&String::from_utf8_lossy(&bytes));
                    assert!(!text.contains("MVG FAIL"), "guest pattern mismatch");
                    if text.contains(marker) {
                        return Ok(());
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                other => {
                    let status = self.child.try_wait()?;
                    panic!("FC console ended: {other:?}; child_status={status:?}; {text}");
                }
            }
            if let Some(status) = self.child.try_wait()? {
                panic!("FC pid={} exited: {status}; {text}", self.child.id());
            }
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

    fn observe_pages(&self) -> BTreeMap<u64, ObservedPage> {
        // Privileged oracle only: read pagemap first, then read only already-present pages.
        // Reading untouched RAM through /proc/pid/mem would fault it in and invalidate the proof.
        let map = File::open(format!("/proc/{}/pagemap", self.child.id())).unwrap();
        let memory = File::open(format!("/proc/{}/mem", self.child.id())).unwrap();
        let mut entries = vec![0; usize::try_from(RAM / 4096 * 8).unwrap()];
        map.read_exact_at(&mut entries, BASE / 4096 * 8).unwrap();
        let mut pages = BTreeMap::new();
        for (index, bytes) in entries.chunks_exact(8).enumerate() {
            let entry = u64::from_le_bytes(bytes.try_into().unwrap());
            if entry & (1 << 63) == 0 {
                continue;
            }
            assert_ne!(entry & PFN_MASK, 0, "privileged PFN oracle unavailable");
            let gpa = index as u64 * 4096;
            let mut bytes = vec![0; 4096];
            memory.read_exact_at(&mut bytes, BASE + gpa).unwrap();
            pages.insert(gpa, ObservedPage { entry, bytes });
        }
        pages
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
    let failure_work = work.clone();
    let old_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        dump_logs(&failure_work);
        old_hook(info);
    }));
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
    let baseline_pages = b.observe_pages();
    assert_eq!(ap, b.pfns(), "restore copied unwritten pattern pages");
    println!("SHARING same_pfn_pages=4 guest_verified=1 confined=1");
    a.stop();
    b.resume();
    b.serial(Some(b'v'), "MVG VERIFIED")?;
    println!("PARENT_DELETED child_verified=1");
    b.request(MsgType::Quiesce, &[], &[]);
    let read_only_pages = b.observe_pages();
    let maintenance = page_changes("read-only-resume", &baseline_pages, &read_only_pages);
    assert_paging_maintenance(&baseline_pages, &read_only_pages, &maintenance);
    b.resume();
    b.serial(Some(b'w'), "MVG VERIFIED")?;
    let (deep, _dst, di) = b.capture(&device);
    let deep_pages = b.observe_pages();
    let changed = page_changes("deep-capture", &baseline_pages, &deep_pages);
    assert_paging_maintenance(&baseline_pages, &deep_pages, &maintenance);
    let mut expected = maintenance.clone();
    expected.extend([PATTERN, PATTERN + 4096]);
    expected.sort_unstable();
    assert_eq!(
        changed, expected,
        "unexplained pages outside the two writes and observed paging maintenance"
    );
    assert_eq!(
        di.new_pages,
        u64::try_from(expected.len()).unwrap(),
        "INFO new_pages must match the exact privileged oracle page set"
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
        "MEMVERSION_FC_PASS jailed=2 seccomp=1 same_pfn=4 guest_cow_pages=2 maintenance_pages={} new_pages={} replay_same=1 parent_delete=1 joined=2",
        maintenance.len(),
        di.new_pages
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn page_oracle_requires_named_pages_and_allows_only_accessed_dirty_bits() {
        let page = |entry| ObservedPage {
            entry,
            bytes: vec![0; 4096],
        };
        let before = BTreeMap::from([(0x9000, page(1))]);
        let mut after = BTreeMap::from([(0x9000, page(2))]);
        after.get_mut(&0x9000).unwrap().bytes[0] = 0x60;
        let changed = page_changes("test", &before, &after);
        assert_eq!(changed, [0x9000]);
        assert_paging_maintenance(&before, &after, &changed);
        after.get_mut(&0x9000).unwrap().bytes[0] = 1;
        assert!(
            std::panic::catch_unwind(|| assert_paging_maintenance(&before, &after, &changed))
                .is_err()
        );
        assert!(
            std::panic::catch_unwind(|| assert_paging_maintenance(&before, &after, &[0x12000]))
                .is_err()
        );
        let exclusive = BTreeMap::from([(0x9000, page(1 | (1 << 56)))]);
        assert!(page_changes("mapping-count-only", &before, &exclusive).is_empty());
    }

    #[test]
    #[ignore = "root required for the production listener ownership; no KVM required"]
    fn startup_failure_keeps_stdout_stderr_and_exit_status() {
        let dir = TempDir::new().unwrap();
        let jailer = dir.as_path().join("failing-jailer");
        fs::write(
            &jailer,
            b"#!/bin/sh\necho STARTUP_STDOUT\necho STARTUP_STDERR >&2\nexit 17\n",
        )
        .unwrap();
        fs::set_permissions(&jailer, fs::Permissions::from_mode(0o755)).unwrap();
        let work = dir.as_path().join("work");
        fs::create_dir(&work).unwrap();
        let error = Vm::start(&jailer, &jailer, &jailer, &work, "a", None, &[0; 32])
            .err()
            .expect("fake jailer must fail");
        assert!(error.to_string().contains("exit status: 17"), "{error}");
        let transcript = fs::read_to_string(work.join("a.console")).unwrap();
        assert!(transcript.contains("STARTUP_STDOUT"));
        assert!(transcript.contains("STARTUP_STDERR"));
    }

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
