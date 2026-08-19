# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pagemaster stand-in for the farplane memory channel.

`Pagemaster` owns the SEQPACKET socket Firecracker connects to, hands over the sealed backing
memfds and the canonical extent table, serves userfaultfd events for the guest mappings and drives
the capture cycle. `FarplaneMicrovm` launches the jailer with the inherited root memfd so tests can
talk to a real Firecracker over that channel.
"""

# pylint: disable=too-many-lines

import ctypes
import fcntl
import os
import select
import shutil
import socket
import struct
import subprocess
import threading
import time
from array import array
from collections import namedtuple
from enum import IntEnum
from pathlib import Path

from framework.http_api import Api

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")

MAGIC = 0x314D5046
VERSION = 1
MAX_DATAGRAM = 65536
MAX_EXTENTS = 65536
FEATURE_IDENTITY = "farplane/1"

HEADER = struct.Struct("<IHHQIIQ")
HELLO = struct.Struct("<IIHHI32s")
REGION = struct.Struct("<QQ")
EXTENT = struct.Struct("<QQIIQ")
READY_REGION = struct.Struct("<QQQ")
READY_TAIL = struct.Struct("<IQQQ")
BACKING_PLAN = struct.Struct("<IIII")
ERROR_BODY = struct.Struct("<IHH128s")

DEV_USERFAULTFD = Path("/dev/userfaultfd")
UFFD_DEVICE_FILENO = 3
ROOT_FILENO = 4
BOOTSTRAP_FILENO = 5

ARCH_X86_64 = 1
ARCH_AARCH64 = 2
MODE_BOOT = 1
MODE_RESTORE = 2

BACKING_PLAN_VMSTATE_FLAG = 1


class Msg(IntEnum):
    """Message types on the memory channel."""

    PLAN_FDS = 1
    BACKING_PLAN = 2
    CAPTURE_BUFFERS = 3
    QUIESCE = 4
    DIRTY_SNAPSHOT = 5
    WRITE_VMSTATE = 6
    DIRTY_UNION = 7
    RESUME = 8
    HELLO = 9
    BACKEND_READY = 10
    QUIESCED = 11
    DIRTY_SNAPSHOT_DONE = 12
    VMSTATE_WRITTEN = 13
    UNION_DONE = 14
    RESUMED = 15
    ERROR = 16


class Err(IntEnum):
    """Error codes Firecracker reports on the memory channel."""

    GEOMETRY_MISMATCH = 1
    BAD_EXTENT = 2
    PLAN_NOT_CANONICAL = 3
    FD_NOT_MEMFD = 4
    FD_NOT_SEALED = 5
    FD_WRITABLE = 6
    TOO_MANY_EXTENTS = 7
    TOO_MANY_FDS = 8
    MAP_FAILED = 9
    UFFD_REGISTER_FAILED = 10
    MLOCK_FAILED = 11
    VMSTATE_PARSE_FAILED = 12
    VMSTATE_WRITE_FAILED = 13
    DIRTY_HARVEST_FAILED = 14
    NOT_QUIESCED = 15
    ALREADY_QUIESCED = 16
    NO_CAPTURE_BUFFERS = 17
    BUFFER_TOO_SMALL = 18
    PEERCRED_MISMATCH = 19


F_ADD_SEALS = 1033
F_GET_SEALS = 1034
F_SEAL_SEAL = 0x01
F_SEAL_SHRINK = 0x02
F_SEAL_GROW = 0x04
F_SEAL_WRITE = 0x08
F_SEAL_FUTURE_WRITE = 0x10

BACKING_SEALS = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE
BUFFER_SEALS = F_SEAL_GROW | F_SEAL_SHRINK
ROOT_SEALS = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL

UFFD_EVENT_PAGEFAULT = 0x12
UFFD_PAGEFAULT_FLAG_WRITE = 1 << 0
UFFD_PAGEFAULT_FLAG_WP = 1 << 1
UFFD_PAGEFAULT_FLAG_MINOR = 1 << 2

UFFDIO_WRITEPROTECT_MODE_WP = 1 << 0

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
MFD_ALLOW_SEALING = 0x0002


class _UffdioRange(ctypes.Structure):
    _fields_ = [("start", ctypes.c_uint64), ("len", ctypes.c_uint64)]


class _UffdioZeropage(ctypes.Structure):
    _fields_ = [
        ("range", _UffdioRange),
        ("mode", ctypes.c_int64),
        ("zeropage", ctypes.c_int64),
    ]


class _UffdioContinue(ctypes.Structure):
    _fields_ = [
        ("range", _UffdioRange),
        ("mode", ctypes.c_int64),
        ("mapped", ctypes.c_int64),
    ]


class _UffdioWriteprotect(ctypes.Structure):
    _fields_ = [("range", _UffdioRange), ("mode", ctypes.c_uint64)]


class _Iovec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def _ioc(direction, typ, nr, size):
    return (direction << 30) | (size << 16) | (typ << 8) | nr


_IOC_WRITE = 1
_IOC_READ = 2
_UFFDIO = 0xAA

UFFDIO_ZEROPAGE = _ioc(
    _IOC_WRITE | _IOC_READ, _UFFDIO, 0x04, ctypes.sizeof(_UffdioZeropage)
)
UFFDIO_WRITEPROTECT = _ioc(
    _IOC_WRITE | _IOC_READ, _UFFDIO, 0x06, ctypes.sizeof(_UffdioWriteprotect)
)
UFFDIO_CONTINUE = _ioc(
    _IOC_WRITE | _IOC_READ, _UFFDIO, 0x07, ctypes.sizeof(_UffdioContinue)
)

_PROCESS_VM_ARGTYPES = [
    ctypes.c_int,
    ctypes.POINTER(_Iovec),
    ctypes.c_ulong,
    ctypes.POINTER(_Iovec),
    ctypes.c_ulong,
    ctypes.c_ulong,
]


def _declare_libc():
    """Pin the prototypes of the syscalls this module drives by hand."""
    _libc.ioctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p]
    _libc.ioctl.restype = ctypes.c_int
    for name in ("process_vm_readv", "process_vm_writev"):
        function = getattr(_libc, name)
        function.argtypes = _PROCESS_VM_ARGTYPES
        function.restype = ctypes.c_ssize_t


_declare_libc()


def _errno_error(what):
    err = ctypes.get_errno()
    return OSError(err, f"{what}: {os.strerror(err)}")


class ChannelViolation(Exception):
    """Raised when Firecracker breaks the channel contract."""


Reply = namedtuple("Reply", ["msg", "body", "fds", "error"])


def _memfd_create(name):
    """Create a sealable memfd."""
    fd = _libc.memfd_create(name.encode(), MFD_ALLOW_SEALING)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "memfd_create")
    return fd


def sealed_memfd(
    name, size, *, content=None, offset=0, seals=BACKING_SEALS, read_only=True
):
    """Create a memfd of `size` bytes, optionally seeded, sealed and reopened read-only."""
    fd = _memfd_create(name)
    os.ftruncate(fd, size)
    if content:
        os.pwrite(fd, content, offset)
    if seals:
        fcntl.fcntl(fd, F_ADD_SEALS, seals)
    if not read_only:
        return fd
    read_fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
    os.close(fd)
    return read_fd


def memfd_from_file(name, path, *, seals=ROOT_SEALS, read_only=True):
    """Copy `path` into a sealed memfd, reopened read-only by default."""
    size = os.path.getsize(path)
    fd = _memfd_create(name)
    os.ftruncate(fd, size)
    with open(path, "rb") as src:
        written = 0
        while True:
            chunk = src.read(8 << 20)
            if not chunk:
                break
            os.pwrite(fd, chunk, written)
            written += len(chunk)
    assert written == size
    if seals:
        fcntl.fcntl(fd, F_ADD_SEALS, seals)
    if not read_only:
        return fd
    read_fd = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)
    os.close(fd)
    return read_fd


def seals_of(fd):
    """Return the seal mask of a descriptor."""
    return fcntl.fcntl(fd, F_GET_SEALS)


class DirtyBitmap:
    """The concatenated per-region dirty bitmap the capture buffers carry.

    Each region contributes `ceil(pages / 64)` 64-bit words, in plan region order.
    """

    def __init__(self, regions, data=None):
        self.regions = [(int(addr), int(size)) for addr, size in regions]
        self.words_per_region = [
            (size // PAGE_SIZE + (1 if size % PAGE_SIZE else 0) + 63) // 64
            for _, size in self.regions
        ]
        self.byte_len = sum(self.words_per_region) * 8
        self.data = bytearray(data if data is not None else self.byte_len)
        assert len(self.data) >= self.byte_len

    def set_pages(self):
        """Guest addresses of every page marked dirty."""
        pages = []
        base_bit = 0
        for (addr, size), words in zip(self.regions, self.words_per_region):
            for page in range(0, size, PAGE_SIZE):
                bit = base_bit + page // PAGE_SIZE
                if self.data[bit // 8] & (1 << (bit % 8)):
                    pages.append(addr + page)
            base_bit += words * 64
        return pages

    def count(self):
        """Number of pages marked dirty."""
        return sum(bin(byte).count("1") for byte in self.data[: self.byte_len])


class Extent:
    """One record of the canonical extent table."""

    def __init__(self, guest_addr, length, fd_index, fd_offset):
        self.guest_addr = guest_addr
        self.len = length
        self.fd_index = fd_index
        self.fd_offset = fd_offset

    def pack(self, reserved=0):
        """Serialise this record."""
        return EXTENT.pack(
            self.guest_addr, self.len, self.fd_index, reserved, self.fd_offset
        )

    def __repr__(self):
        return (
            f"<Extent {self.guest_addr:#x}+{self.len:#x} "
            f"fd={self.fd_index}@{self.fd_offset:#x}>"
        )


class Pagemaster:
    """A single-connection pagemaster for one Firecracker instance."""

    # pylint: disable=too-many-public-methods

    def __init__(
        self,
        socket_path,
        *,
        splits=1,
        shared_memfds=None,
        single_memfd=False,
        markers=True,
        vmstate_capacity=16 << 20,
    ):
        self.socket_path = Path(socket_path)
        self.splits = splits
        self.single_memfd = single_memfd
        self.markers = markers
        self.vmstate_capacity = vmstate_capacity

        # Backing descriptors, either supplied by the caller (so two guests share them) or built
        # once the hello tells us the guest geometry.
        self.backing_fds = list(shared_memfds) if shared_memfds else []
        self.owns_backing = not shared_memfds
        self.extents = []
        self.marker_bytes = {}

        self.hello = None
        self.regions = []
        self.ready_regions = []
        self.dirty_bitmap_bytes = 0
        self.vmstate_capacity_bytes = 0
        self.kvm_slot_count = 0
        self.uffd_features = 0
        self.uffd = -1
        self.fc_pid = None

        self.faults = []
        self.errors = []
        self.marker_reads = {}

        self._listener = None
        self._sock = None
        self._request_id = 0
        self._ready = threading.Event()
        self._handshake_error = None
        self._handshake_thread = None
        self._fault_thread = None
        self._serving = threading.Event()
        self._lock = threading.Lock()
        self.dirty_fd = None
        self.vmstate_fd = None

    # ---------------------------------------------------------------- lifecycle

    def start(self):
        """Bind the channel and handle the handshake in the background."""
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self._listener.bind(str(self.socket_path))
        self._listener.listen(1)
        os.chmod(self.socket_path, 0o777)
        self._handshake_thread = threading.Thread(
            target=self._handshake, name="pagemaster-handshake", daemon=True
        )
        self._handshake_thread.start()

    def wait_ready(self, timeout=60):
        """Block until backend_ready has been processed."""
        if not self._ready.wait(timeout):
            raise TimeoutError("Firecracker never reported backend_ready")
        if self._handshake_error is not None:
            raise self._handshake_error
        return self

    def close(self):
        """Release every descriptor and stop the fault handler."""
        self.stop_serving()
        for sock in (self._sock, self._listener):
            if sock is not None:
                sock.close()
        self._sock = None
        self._listener = None
        for fd in list(self.backing_fds) if self.owns_backing else []:
            os.close(fd)
        self.backing_fds = []
        for fd in (self.dirty_fd, self.vmstate_fd):
            if fd is not None:
                os.close(fd)
        self.dirty_fd = None
        self.vmstate_fd = None
        if self.socket_path.exists():
            self.socket_path.unlink()

    def stop_serving(self):
        """Close the userfaultfd duplicate; pending and future faults stay unresolved."""
        self._serving.clear()
        if self._fault_thread is not None:
            self._fault_thread.join(timeout=10)
            self._fault_thread = None
        if self.uffd >= 0:
            os.close(self.uffd)
            self.uffd = -1

    # ---------------------------------------------------------------- handshake

    def _handshake(self):
        try:
            self._sock, _ = self._listener.accept()
            header, body, _ = self._recv()
            if header["msg_type"] != Msg.HELLO or header["request_id"] != 0:
                raise ChannelViolation(f"expected an unsolicited hello, got {header}")
            pid, page_size, arch, mode, region_count, identity = HELLO.unpack_from(body)
            if identity.rstrip(b"\0").decode() != FEATURE_IDENTITY:
                raise ChannelViolation(f"wrong feature identity {identity!r}")
            regions = []
            for index in range(region_count):
                offset = HELLO.size + index * REGION.size
                addr, size = REGION.unpack_from(body, offset)
                regions.append((addr, size))
            self.hello = {
                "pid": pid,
                "page_size": page_size,
                "arch": arch,
                "mode": mode,
            }
            self.fc_pid = pid
            self.regions = regions

            self._build_plan()
            self._send(
                Msg.PLAN_FDS,
                self._next_id(),
                struct.pack("<I", len(self.backing_fds)),
                self.backing_fds,
            )
            plan = BACKING_PLAN.pack(os.getpid(), len(regions), len(self.extents), 0)
            for addr, size in regions:
                plan += REGION.pack(addr, size)
            table = self._extent_table_fd()
            self._send(Msg.BACKING_PLAN, self._next_id(), plan, [table])
            os.close(table)

            header, body, fds = self._recv()
            if header["msg_type"] == Msg.ERROR:
                code, op, _, _ = ERROR_BODY.unpack(body)
                raise ChannelViolation(
                    f"plan refused: {Err(code).name} during {Msg(op).name}"
                )
            if header["msg_type"] != Msg.BACKEND_READY:
                raise ChannelViolation(f"expected backend_ready, got {header}")
            self._parse_backend_ready(body, fds)
            self._start_fault_service()
            if self.markers:
                self._read_markers()
            self.resume(run_vcpus=0)
        except Exception as exc:  # pylint: disable=broad-except
            self._handshake_error = exc
        finally:
            self._ready.set()

    def _build_plan(self):
        """Allocate the backing memfds and compile a canonical extent table."""
        if self.single_memfd:
            total = sum(size for _, size in self.regions)
            if self.owns_backing and not self.backing_fds:
                # One all-hole sparse memfd tiling every region back to back.
                self.backing_fds = [sealed_memfd("farplane-sparse", total)]
            offset = 0
            for addr, size in self.regions:
                self.extents.append(Extent(addr, size, 0, offset))
                offset += size
            return

        build = self.owns_backing and not self.backing_fds
        fd_index = 0
        for addr, size in self.regions:
            pages = size // PAGE_SIZE
            assert pages >= self.splits, "region too small to split"
            chunk = (pages // self.splits) * PAGE_SIZE
            offsets = [index * chunk for index in range(self.splits)]
            lengths = [chunk] * self.splits
            lengths[-1] = size - chunk * (self.splits - 1)
            for length, extent_offset in zip(lengths, offsets):
                guest_addr = addr + extent_offset
                marker = self._marker_for(guest_addr, length)
                if build:
                    self.backing_fds.append(
                        sealed_memfd(
                            f"farplane-backing-{guest_addr:#x}",
                            length,
                            content=marker,
                            offset=length - PAGE_SIZE if marker else 0,
                        )
                    )
                self.extents.append(Extent(guest_addr, length, fd_index, 0))
                fd_index += 1

    def _marker_for(self, guest_addr, length):
        """Record, and return, the marker planted on the last page of an extent."""
        if not self.markers:
            return None
        marker = f"farplane-{guest_addr:#x}".encode()
        self.marker_bytes[guest_addr + length - PAGE_SIZE] = marker
        return marker

    def _extent_table_fd(self):
        table = b"".join(extent.pack() for extent in self.extents)
        return sealed_memfd("farplane-extents", len(table), content=table)

    def _parse_backend_ready(self, body, fds):
        count = len(self.regions)
        self.ready_regions = []
        for index in range(count):
            addr, size, host_base = READY_REGION.unpack_from(
                body, index * READY_REGION.size
            )
            self.ready_regions.append(
                {"guest_addr": addr, "size": size, "host_base": host_base}
            )
        (
            self.kvm_slot_count,
            self.uffd_features,
            self.dirty_bitmap_bytes,
            self.vmstate_capacity_bytes,
        ) = READY_TAIL.unpack_from(body, count * READY_REGION.size)
        if len(fds) != 1:
            raise ChannelViolation("backend_ready must carry the userfaultfd duplicate")
        self.uffd = fds[0]

    def _read_markers(self):
        """Read every extent marker through Firecracker's composite mapping."""
        for guest_addr, marker in self.marker_bytes.items():
            self.marker_reads[guest_addr] = self.read_guest(guest_addr, len(marker))

    # ------------------------------------------------------------ fault service

    def _start_fault_service(self):
        self._serving.set()
        self._fault_thread = threading.Thread(
            target=self._serve_faults, name="pagemaster-uffd", daemon=True
        )
        self._fault_thread.start()

    def _serve_faults(self):
        poller = select.poll()
        poller.register(self.uffd, select.POLLIN)
        while self._serving.is_set():
            if not poller.poll(200):
                continue
            try:
                message = os.read(self.uffd, 32)
            except OSError:
                return
            if len(message) < 32:
                return
            event, _, _, _, flags, address, _ = struct.unpack_from("<BBHIQQI", message)
            if event != UFFD_EVENT_PAGEFAULT:
                continue
            host_page = address & ~(PAGE_SIZE - 1)
            with self._lock:
                self.faults.append((host_page, flags))
            try:
                if flags & UFFD_PAGEFAULT_FLAG_WP:
                    self.write_protect(host_page, PAGE_SIZE, protect=False)
                elif self.guest_addr(host_page) in self.marker_bytes:
                    self._uffdio_continue(host_page)
                else:
                    self._uffdio_zeropage(host_page)
            except OSError:
                return

    def _uffdio_zeropage(self, page):
        arg = _UffdioZeropage(range=_UffdioRange(start=page, len=PAGE_SIZE), mode=0)
        if _libc.ioctl(self.uffd, UFFDIO_ZEROPAGE, ctypes.byref(arg)) != 0:
            raise _errno_error(f"UFFDIO_ZEROPAGE at {page:#x}")

    def _uffdio_continue(self, page):
        arg = _UffdioContinue(range=_UffdioRange(start=page, len=PAGE_SIZE), mode=0)
        if _libc.ioctl(self.uffd, UFFDIO_CONTINUE, ctypes.byref(arg)) != 0:
            raise _errno_error(f"UFFDIO_CONTINUE at {page:#x}")

    def write_protect(self, host_addr, length, *, protect=True):
        """Arm or clear write protection on a host range of the guest mapping."""
        arg = _UffdioWriteprotect(
            range=_UffdioRange(start=host_addr, len=length),
            mode=UFFDIO_WRITEPROTECT_MODE_WP if protect else 0,
        )
        if _libc.ioctl(self.uffd, UFFDIO_WRITEPROTECT, ctypes.byref(arg)) != 0:
            raise _errno_error(f"UFFDIO_WRITEPROTECT at {host_addr:#x}")

    def protect_guest(self, guest_addr, length=PAGE_SIZE):
        """Write protect a guest range."""
        self.write_protect(self.host_addr(guest_addr), length, protect=True)

    def written_pages(self):
        """Guest pages for which a write fault was observed."""
        pages = []
        with self._lock:
            for host, flags in self.faults:
                if flags & UFFD_PAGEFAULT_FLAG_WRITE:
                    pages.append(self.guest_addr(host))
        return pages

    def faulted_pages(self):
        """Every guest page that faulted."""
        with self._lock:
            return {self.guest_addr(host) for host, _ in self.faults}

    # ------------------------------------------------------------ guest memory

    def host_addr(self, guest_addr):
        """Host address of `guest_addr` inside Firecracker."""
        for region in self.ready_regions:
            if (
                region["guest_addr"]
                <= guest_addr
                < region["guest_addr"] + region["size"]
            ):
                return region["host_base"] + (guest_addr - region["guest_addr"])
        raise KeyError(f"{guest_addr:#x} is outside guest memory")

    def guest_addr(self, host_addr):
        """Guest address for a host address inside Firecracker."""
        for region in self.ready_regions:
            if region["host_base"] <= host_addr < region["host_base"] + region["size"]:
                return region["guest_addr"] + (host_addr - region["host_base"])
        raise KeyError(f"{host_addr:#x} is outside guest memory")

    def read_guest(self, guest_addr, length, *, pid=None):
        """Read guest memory out of Firecracker with process_vm_readv."""
        buf = ctypes.create_string_buffer(length)
        local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p), iov_len=length)
        remote = _Iovec(
            iov_base=ctypes.c_void_p(self.host_addr(guest_addr)), iov_len=length
        )
        ctypes.set_errno(0)
        got = _libc.process_vm_readv(
            pid if pid is not None else self.fc_pid,
            ctypes.byref(local),
            1,
            ctypes.byref(remote),
            1,
            0,
        )
        if got != length:
            raise _errno_error(f"process_vm_readv {length} bytes at {guest_addr:#x}")
        return buf.raw

    def write_guest(self, guest_addr, data):
        """Write guest memory inside Firecracker with process_vm_writev."""
        buf = ctypes.create_string_buffer(data, len(data))
        local = _Iovec(iov_base=ctypes.cast(buf, ctypes.c_void_p), iov_len=len(data))
        remote = _Iovec(
            iov_base=ctypes.c_void_p(self.host_addr(guest_addr)), iov_len=len(data)
        )
        ctypes.set_errno(0)
        put = _libc.process_vm_writev(
            self.fc_pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0
        )
        if put != len(data):
            raise _errno_error(
                f"process_vm_writev {len(data)} bytes at {guest_addr:#x}"
            )
        return put

    def backing_bytes(self, guest_addr, length):
        """Read the bytes the backing memfd holds for a guest address."""
        for extent in self.extents:
            if extent.guest_addr <= guest_addr < extent.guest_addr + extent.len:
                offset = extent.fd_offset + (guest_addr - extent.guest_addr)
                return os.pread(self.backing_fds[extent.fd_index], length, offset)
        raise KeyError(f"{guest_addr:#x} is not covered by the plan")

    # ------------------------------------------------------------ capture cycle

    def capture_buffers(self, dirty_fd=None, vmstate_fd=None):
        """Hand over the dirty bitmap and vmstate buffers."""
        if dirty_fd is None:
            if self.dirty_fd is not None:
                os.close(self.dirty_fd)
            dirty_fd = sealed_memfd(
                "farplane-dirty",
                self.dirty_bitmap_bytes,
                seals=BUFFER_SEALS,
                read_only=False,
            )
            self.dirty_fd = dirty_fd
        if vmstate_fd is None:
            if self.vmstate_fd is not None:
                os.close(self.vmstate_fd)
            vmstate_fd = sealed_memfd(
                "farplane-vmstate",
                self.vmstate_capacity_bytes,
                seals=BUFFER_SEALS,
                read_only=False,
            )
            self.vmstate_fd = vmstate_fd
        return self.request(Msg.CAPTURE_BUFFERS, fds=[dirty_fd, vmstate_fd])

    def quiesce(self):
        """Stop the vCPUs; returns the reply."""
        return self.request(Msg.QUIESCE)

    def dirty_snapshot(self):
        """Harvest and clear the dirty log into the capture buffer."""
        return self.request(Msg.DIRTY_SNAPSHOT)

    def harvest(self):
        """The dirty bitmap the last `dirty_snapshot` produced."""
        raw = os.pread(self.dirty_fd, self.dirty_bitmap_bytes, 0)
        return DirtyBitmap(
            [(region["guest_addr"], region["size"]) for region in self.ready_regions],
            raw,
        )

    def write_vmstate(self):
        """Ask for the vmstate to be serialised into the capture buffer."""
        return self.request(Msg.WRITE_VMSTATE)

    def vmstate(self, length):
        """Read `length` bytes of the vmstate buffer."""
        return os.pread(self.vmstate_fd, length, 0)

    def dirty_union(self, bitmap):
        """Fold `bitmap` back into the dirty log."""
        data = bytes(bitmap.data if isinstance(bitmap, DirtyBitmap) else bitmap)
        fd = sealed_memfd(
            "farplane-union",
            len(data),
            content=data,
            seals=BUFFER_SEALS,
            read_only=False,
        )
        try:
            return self.request(Msg.DIRTY_UNION, fds=[fd])
        finally:
            os.close(fd)

    def resume(self, run_vcpus=1):
        """Let the vCPUs run again."""
        return self.request(Msg.RESUME, body=struct.pack("<I", run_vcpus))

    # ----------------------------------------------------------------- plumbing

    def request(self, msg, body=b"", fds=(), timeout=30):
        """Send one request and collect its reply, stashing any error frame."""
        request_id = self._next_id()
        self._sock.settimeout(timeout)
        self._send(msg, request_id, body, fds)
        header, payload, reply_fds = self._recv()
        if header["request_id"] != request_id:
            raise ChannelViolation(
                f"reply {header['request_id']} does not echo request {request_id}"
            )
        if header["msg_type"] == Msg.ERROR:
            code, op, reserved, _ = ERROR_BODY.unpack(payload)
            if reserved != 0:
                raise ChannelViolation("error frame reserved field is not zero")
            self.errors.append((Err(code), Msg(op)))
            return Reply(Msg.ERROR, payload, reply_fds, (Err(code), Msg(op)))
        return Reply(Msg(header["msg_type"]), payload, reply_fds, None)

    def send_raw(self, payload, fds=()):
        """Put an arbitrary datagram on the channel."""
        ancillary = []
        if fds:
            ancillary.append(
                (socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", list(fds)))
            )
        return self._sock.sendmsg([payload], ancillary)

    def close_channel(self):
        """Shut the channel down so Firecracker observes EOF."""
        self._sock.close()
        self._sock = None

    def _next_id(self):
        self._request_id += 1
        return self._request_id

    def _send(self, msg, request_id, body=b"", fds=()):
        fds = list(fds)
        header = HEADER.pack(
            MAGIC, VERSION, int(msg), request_id, len(body), len(fds), 0
        )
        ancillary = []
        if fds:
            ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, array("i", fds)))
        sent = self._sock.sendmsg([header + body], ancillary)
        assert sent == len(header) + len(body)

    def _recv(self):
        fds = array("i")
        payload, ancillary, flags, _ = self._sock.recvmsg(
            MAX_DATAGRAM, socket.CMSG_SPACE(64 * fds.itemsize)
        )
        if flags & socket.MSG_TRUNC:
            raise ChannelViolation("datagram exceeded the channel maximum")
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                fds.frombytes(data[: len(data) - (len(data) % fds.itemsize)])
        if len(payload) < HEADER.size:
            raise ChannelViolation(f"datagram of {len(payload)} bytes is not a frame")
        magic, version, msg_type, request_id, body_len, fd_count, reserved = (
            HEADER.unpack_from(payload)
        )
        if magic != MAGIC or version != VERSION or reserved != 0:
            raise ChannelViolation(f"bad header {payload[: HEADER.size]!r}")
        if len(payload) != HEADER.size + body_len:
            raise ChannelViolation("body_len disagrees with the datagram")
        if fd_count != len(fds):
            raise ChannelViolation(f"fd_count {fd_count} but {len(fds)} descriptors")
        header = {
            "msg_type": msg_type,
            "request_id": request_id,
            "body_len": body_len,
            "fd_count": fd_count,
        }
        return header, payload[HEADER.size :], list(fds)


class FarplaneMicrovm:
    """A jailed Firecracker whose guest memory comes from a `Pagemaster`."""

    SOCKET_NAME = "farplane.sock"

    def __init__(
        self,
        *,
        binary_dir,
        chroot_base,
        microvm_id,
        kernel=None,
        rootfs=None,
        netns=None,
        uid=1234,
        gid=1234,
    ):
        self.jailer_binary = Path(binary_dir) / "jailer"
        self.fc_binary = Path(binary_dir) / "firecracker"
        assert self.jailer_binary.exists() and self.fc_binary.exists()
        self.chroot_base = Path(chroot_base)
        self.microvm_id = microvm_id
        self.kernel = Path(kernel) if kernel else None
        self.rootfs = Path(rootfs) if rootfs else None
        self.bootstrap_file = None
        self.netns = netns
        self.uid = uid
        self.gid = gid

        self.proc = None
        self.wrapper = None
        self.root_fd = None
        self.bootstrap_fd = None
        self.api = None
        self.pagemaster = None
        self._pid = None
        self.stdio = self.chroot_base / f"{microvm_id}.stdio"

    # ---------------------------------------------------------------- filesystem

    @property
    def chroot(self):
        """Path of the jail root."""
        return self.chroot_base / self.fc_binary.name / self.microvm_id / "root"

    @property
    def api_socket(self):
        """Host path of the API socket."""
        return self.chroot / "run" / "firecracker.socket"

    @property
    def pid_file(self):
        """Host path of the pid file the jailer writes."""
        return self.chroot / f"{self.fc_binary.name}.pid"

    @property
    def socket_path(self):
        """Host path of the memory channel socket."""
        return self.chroot / self.SOCKET_NAME

    @property
    def pid(self):
        """Firecracker's pid."""
        if self._pid is None:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.pid_file.exists():
                    text = self.pid_file.read_text(encoding="utf-8").strip()
                    if text:
                        self._pid = int(text)
                        break
                time.sleep(0.05)
            else:
                raise TimeoutError(f"{self.pid_file} never appeared")
        return self._pid

    def open_root_memfd(self, *, seals=ROOT_SEALS, read_only=True, size=None):
        """Create the root memfd the jailer validates and renumbers to fd 4.

        `size` builds an empty memfd instead of copying the rootfs, and `seals`/`read_only` exist
        so tests can offer a descriptor that fails validation.
        """
        if size is None:
            self.root_fd = memfd_from_file(
                "rootfs", self.rootfs, seals=seals, read_only=read_only
            )
        else:
            self.root_fd = sealed_memfd(
                "rootfs", size, seals=seals, read_only=read_only
            )
        return self.root_fd

    def open_bootstrap_memfd(self, *, seals=ROOT_SEALS, read_only=True, size=None):
        """Create the bootstrap memfd the jailer validates and renumbers to fd 5."""
        if size is None:
            self.bootstrap_fd = memfd_from_file(
                "bootstrap", self.bootstrap_file, seals=seals, read_only=read_only
            )
        else:
            self.bootstrap_fd = sealed_memfd(
                "bootstrap", size, seals=seals, read_only=read_only
            )
        return self.bootstrap_fd

    # -------------------------------------------------------------------- launch

    def jailer_argv(
        self,
        *,
        root_fd=None,
        bootstrap_fd=None,
        cgroup_join=None,
        resource_limits=(),
        fc_args=(),
    ):
        """The exact command line used to launch this microVM."""
        argv = [
            str(self.jailer_binary),
            "--id",
            self.microvm_id,
            "--exec-file",
            str(self.fc_binary),
            "--uid",
            str(self.uid),
            "--gid",
            str(self.gid),
        ]
        if root_fd is not None:
            argv += ["--root-fd", str(root_fd)]
        if bootstrap_fd is not None:
            argv += ["--bootstrap-fd", str(bootstrap_fd)]
        argv += ["--chroot-base-dir", str(self.chroot_base)]
        if self.netns is not None:
            argv += ["--netns", str(self.netns.path)]
        if cgroup_join is not None:
            argv += ["--cgroup-join", str(cgroup_join)]
        for limit in resource_limits:
            argv += ["--resource-limit", limit]
        argv += ["--"]
        argv += [
            "--farplane-mem-socket",
            f"/{self.SOCKET_NAME}",
            "--log-path",
            "fc.log",
            "--level",
            "Debug",
        ]
        argv += list(fc_args)
        return argv

    def spawn(
        self,
        *,
        root_fd=-1,
        bootstrap_fd=-1,
        cgroup_join=None,
        resource_limits=(),
        fc_args=(),
        via_wrapper=False,
        wait=True,
    ):
        """Launch the jailer, which execs into Firecracker."""
        if root_fd == -1:
            root_fd = (
                self.root_fd if self.root_fd is not None else self.open_root_memfd()
            )
        if bootstrap_fd == -1:
            if self.bootstrap_file is None:
                bootstrap_fd = None
            else:
                bootstrap_fd = (
                    self.bootstrap_fd
                    if self.bootstrap_fd is not None
                    else self.open_bootstrap_memfd()
                )
        argv = self.jailer_argv(
            root_fd=root_fd,
            bootstrap_fd=bootstrap_fd,
            cgroup_join=cgroup_join,
            resource_limits=resource_limits,
            fc_args=fc_args,
        )
        self.chroot_base.mkdir(parents=True, exist_ok=True)
        stdio = self.stdio.open("wb")
        pass_fds = tuple(
            fd for fd in [root_fd, bootstrap_fd] if fd is not None and fd >= 0
        )
        if via_wrapper:
            # A shell that outlives the exec so the test can kill Firecracker's parent.
            quoted = " ".join(f"'{arg}'" for arg in argv)
            self.wrapper = subprocess.Popen(
                ["/bin/sh", "-c", f"{quoted} & wait"],
                stdin=subprocess.DEVNULL,
                stdout=stdio,
                stderr=stdio,
                pass_fds=pass_fds,
                close_fds=True,
            )
        else:
            self.proc = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=stdio,
                stderr=stdio,
                pass_fds=pass_fds,
                close_fds=True,
            )
        stdio.close()
        if wait:
            self.wait_api()
        return self

    def wait_api(self, timeout=30):
        """Wait for the API socket, then attach a client."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.api_socket.exists():
                self.api = Api(str(self.api_socket))
                return self.api
            if self.proc is not None and self.proc.poll() is not None:
                raise ChildProcessError(
                    f"jailer exited with {self.proc.returncode}: {self.stdio_text()}"
                )
            time.sleep(0.05)
        raise TimeoutError(f"API socket {self.api_socket} never appeared")

    def stdio_text(self):
        """Everything the jailer and Firecracker wrote to stdout and stderr."""
        if not self.stdio.exists():
            return ""
        return self.stdio.read_text(encoding="utf-8", errors="replace")

    # -------------------------------------------------------------- configuration

    def jail_kernel(self):
        """Hardlink or copy the guest kernel into the jail."""
        target = self.chroot / self.kernel.name
        if not target.exists():
            try:
                os.link(self.kernel, target)
            except OSError:
                shutil.copyfile(self.kernel, target)
            os.chown(target, self.uid, self.gid)
        return self.kernel.name

    def start_pagemaster(self, **kwargs):
        """Bind the memory channel inside the jail and start serving it."""
        self.pagemaster = Pagemaster(self.socket_path, **kwargs)
        self.pagemaster.start()
        return self.pagemaster

    def configure(
        self, *, vcpu_count=1, mem_size_mib=128, boot_args=None, root_drive=True
    ):
        """Configure machine, boot source and the root drive served from fd 4."""
        self.api.machine_config.put(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
        if boot_args is None:
            boot_args = (
                "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0"
                " cryptomgr.notests pci=off root=/dev/vda ro"
            )
        self.api.boot.put(kernel_image_path=self.jail_kernel(), boot_args=boot_args)
        if root_drive:
            self.api.drive.put(
                drive_id="rootfs",
                fd=ROOT_FILENO,
                is_root_device=True,
                is_read_only=True,
            )

    def start(self):
        """Send InstanceStart."""
        return self.api.actions.put(action_type="InstanceStart")

    def instance(self):
        """The `GET /` document."""
        return self.api.describe.get().json()

    def farplane_state(self):
        """The `farplane` object of `GET /`."""
        return self.instance()["farplane"]

    # ------------------------------------------------------------------- teardown

    def kill(self):
        """Tear the microVM and the channel down."""
        if self.pagemaster is not None:
            self.pagemaster.close()
            self.pagemaster = None
        for proc in (self.proc, self.wrapper):
            if proc is None or proc.poll() is not None:
                continue
            proc.kill()
            proc.wait(timeout=10)
        if self._pid is not None:
            try:
                os.kill(self._pid, 9)
            except ProcessLookupError:
                pass
        if self.root_fd is not None:
            try:
                os.close(self.root_fd)
            except OSError:
                pass
            self.root_fd = None
        if self.bootstrap_fd is not None:
            try:
                os.close(self.bootstrap_fd)
            except OSError:
                pass
            self.bootstrap_fd = None
