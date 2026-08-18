# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for guest memory served over the farplane pagemaster channel."""

import hashlib
import json
import os
import struct
import time
from pathlib import Path

import pytest

from framework import utils
from framework.defs import SECCOMP_JSON_DIR
from framework.properties import global_props
from host_tools import farplane as fp

pytestmark = pytest.mark.skipif(
    not Path("/dev/kvm").exists()
    or not fp.DEV_USERFAULTFD.exists()
    or global_props.host_linux_version_tpl < (6, 1),
    reason=(
        "farplane needs KVM, /dev/userfaultfd and a host kernel with shmem"
        " minor/write-protect userfaultfd"
    ),
)

PAGE = fp.PAGE_SIZE
MEM_SIZE_MIB = 128


@pytest.fixture
def farplane_factory(
    microvm_factory, test_fc_session_root_path, guest_kernel_default, rootfs
):
    """Build farplane microVMs from the session's binaries and artifacts."""
    built = []
    chroot_base = Path(test_fc_session_root_path) / "farplane"

    def build(microvm_id=None):
        """Create one jailed Firecracker; the fixture tears it down."""
        microvm_id = microvm_id or f"fp{len(built)}"
        vm = fp.FarplaneMicrovm(
            binary_dir=microvm_factory.binary_path,
            chroot_base=chroot_base,
            microvm_id=microvm_id,
            kernel=guest_kernel_default,
            rootfs=rootfs,
        )
        built.append(vm)
        return vm

    yield build

    for vm in built:
        vm.kill()


def boot(vm, *, vcpu_count=1, mem_size_mib=MEM_SIZE_MIB, fc_args=(), **pm_kwargs):
    """Launch the jail, serve the memory channel and start the guest."""
    vm.spawn(fc_args=fc_args)
    pagemaster = vm.start_pagemaster(**pm_kwargs)
    vm.configure(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
    vm.start()
    return pagemaster.wait_ready()


def raw(api, method, path, body=None):
    """Issue a request without the swagger client so status codes stay visible."""
    return api.session.request(method, api.endpoint + path, json=body)


def digest(pagemaster, pages):
    """Hash a set of guest pages as Firecracker maps them."""
    hasher = hashlib.sha256()
    for page in pages:
        hasher.update(pagemaster.read_guest(page, PAGE))
    return hasher.hexdigest()


def wait_for(predicate, *, timeout=30, message="condition"):
    """Poll until `predicate` holds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    raise TimeoutError(f"{message} never held within {timeout}s")


def smaps_of(pid, start, end):
    """Every /proc/pid/smaps entry intersecting [start, end)."""
    entries = []
    current = None
    for line in Path(f"/proc/{pid}/smaps").read_text(encoding="utf-8").splitlines():
        if "-" in line.split()[0] and ":" not in line.split()[0]:
            first, rest = line.split(maxsplit=1)
            low, high = (int(value, 16) for value in first.split("-"))
            current = {"start": low, "end": high, "header": rest}
            if low < end and high > start:
                entries.append(current)
            else:
                current = None
            continue
        if current is None:
            continue
        key, _, value = line.partition(":")
        current[key.strip()] = value.strip()
    return entries


def test_multi_extent_regions_boot_and_read_across_every_boundary(farplane_factory):
    """A region tiled by several memfds boots and serves the right bytes at every VMA boundary."""
    vm = farplane_factory()
    pagemaster = boot(vm, splits=4)

    assert len(pagemaster.extents) == 4 * len(pagemaster.regions)
    assert len(pagemaster.backing_fds) == len(pagemaster.extents)
    assert vm.instance()["state"] == "Running"

    # Every extent planted a marker on its last page; each read crosses into a different memfd.
    assert pagemaster.marker_reads, "no extent markers were probed"
    for guest_addr, marker in pagemaster.marker_bytes.items():
        assert (
            pagemaster.marker_reads[guest_addr] == marker
        ), f"the extent boundary at {guest_addr:#x} served the wrong memfd bytes"

    # Bytes on either side of a boundary must come from the two neighbouring memfds. Only pages
    # the guest has not written can still be compared against their backing store.
    written = set(pagemaster.written_pages())
    for extent in pagemaster.extents[1:]:
        for probe in (extent.guest_addr - PAGE, extent.guest_addr):
            if probe < pagemaster.extents[0].guest_addr or probe in written:
                continue
            assert pagemaster.read_guest(probe, 16) == pagemaster.backing_bytes(
                probe, 16
            ), f"{probe:#x} does not match the memfd the plan assigned to it"


def test_missing_minor_and_wp_events_reach_the_pagemaster(farplane_factory):
    """The userfaultfd Firecracker creates off the device delivers missing, minor and wp faults."""
    vm = farplane_factory()
    pagemaster = boot(vm, splits=2)

    marker = sorted(pagemaster.marker_bytes)[0]
    pagemaster.protect_guest(marker)
    pagemaster.write_guest(marker, b"wp")

    def classes():
        """Which fault classes the pagemaster has observed so far."""
        flags = [flag for _, flag in pagemaster.faults]
        return {
            "minor": any(flag & fp.UFFD_PAGEFAULT_FLAG_MINOR for flag in flags),
            "wp": any(flag & fp.UFFD_PAGEFAULT_FLAG_WP for flag in flags),
            "missing": any(
                not flag & (fp.UFFD_PAGEFAULT_FLAG_MINOR | fp.UFFD_PAGEFAULT_FLAG_WP)
                for flag in flags
            ),
        }

    observed = wait_for(
        lambda: classes() if all(classes().values()) else None,
        message="missing, minor and write-protect faults",
    )
    assert observed == {"minor": True, "wp": True, "missing": True}


def test_siblings_share_clean_pages_and_private_writes_stay_private(farplane_factory):
    """Two guests over the same memfds share clean pages; a write in one is visible nowhere else."""
    first = farplane_factory("share-a")
    second = farplane_factory("share-b")

    left = boot(first, splits=2)
    right = boot(second, splits=2, shared_memfds=left.backing_fds)
    assert right.extents[0].fd_index == left.extents[0].fd_index

    marker_addr = sorted(left.marker_bytes)[0]
    marker = left.marker_bytes[marker_addr]
    assert left.read_guest(marker_addr, len(marker)) == marker
    assert right.read_guest(marker_addr, len(marker)) == marker

    mutation = b"X" * len(marker)
    left.write_guest(marker_addr, mutation)

    assert left.read_guest(marker_addr, len(marker)) == mutation
    assert (
        right.read_guest(marker_addr, len(marker)) == marker
    ), "a private write leaked into the sibling guest"
    assert (
        left.backing_bytes(marker_addr, len(marker)) == marker
    ), "a private write reached the sealed memfd"


def test_fault_stays_blocked_after_the_handler_closes_its_duplicate(farplane_factory):
    """With no handler left, a first touch of guest memory never completes."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    region = pagemaster.ready_regions[-1]
    faulted = pagemaster.faulted_pages()
    untouched = next(
        page
        for page in range(
            region["guest_addr"] + region["size"] - PAGE,
            region["guest_addr"],
            -PAGE,
        )
        if page not in faulted
    )
    resolved = sorted(faulted)[0]
    assert len(pagemaster.read_guest(resolved, PAGE)) == PAGE
    pagemaster.stop_serving()

    child = os.fork()
    if child == 0:
        try:
            pagemaster.read_guest(untouched, PAGE)
        except OSError:
            os._exit(2)  # pylint: disable=protected-access
        os._exit(0)  # pylint: disable=protected-access

    time.sleep(5)
    finished, status = os.waitpid(child, os.WNOHANG)
    if finished != 0:
        pytest.fail(
            f"the first touch of {untouched:#x} completed (status {status:#x}) "
            "although no handler is left to resolve it"
        )
    os.kill(child, 9)
    os.waitpid(child, 0)


def test_dirty_harvest_covers_loader_vcpu_and_device_writes(farplane_factory, rootfs):
    """The first harvest holds the loader image, every faulted guest write and device writes."""
    vm = farplane_factory()
    pagemaster = boot(vm, fc_args=("--metrics-path", "fc.ndjson"))

    def block_reads():
        """How many reads the block device has completed."""
        vm.api.actions.put(action_type="FlushMetrics")
        text = (vm.chroot / "fc.ndjson").read_text(encoding="utf-8")
        for line in text.splitlines():
            if not line.strip():
                continue
            metrics = json.loads(line)
            for name, values in metrics.items():
                if not name.startswith("block") or not isinstance(values, dict):
                    continue
                if values.get("read_count", 0) > 0:
                    return values["read_count"]
        return 0

    wait_for(block_reads, timeout=60, message="a virtio block read")
    written = set(pagemaster.written_pages())
    assert written, "the guest never took a write fault"

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    assert pagemaster.dirty_snapshot().error is None
    harvest = pagemaster.harvest()

    for page in written:
        assert harvest[page], f"guest write to {page:#x} is missing from the harvest"

    kernel_pages = (os.path.getsize(vm.kernel) + PAGE - 1) // PAGE
    first_region = pagemaster.ready_regions[0]
    in_first = [
        page
        for page in harvest.set_pages()
        if first_region["guest_addr"]
        <= page
        < first_region["guest_addr"] + first_region["size"]
    ]
    assert len(in_first) >= kernel_pages, (
        f"the loader wrote {kernel_pages} pages of kernel image but only "
        f"{len(in_first)} pages of the first region are dirty"
    )

    with open(rootfs, "rb") as image:
        signature = image.read(64)
    served_by_device = any(
        pagemaster.read_guest(page, 64) == signature for page in harvest.set_pages()
    )
    assert (
        served_by_device
    ), "no dirty page holds the bytes the block device transferred"


def test_dirty_snapshot_returns_each_epoch_exactly_once(farplane_factory):
    """Harvesting clears the log, so a repeat returns nothing until the guest writes again."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.dirty_snapshot()
    first = pagemaster.harvest()
    assert first.count() > 0, "booting dirtied no page"

    pagemaster.dirty_snapshot()
    second = pagemaster.harvest()
    assert (
        second.count() == 0
    ), f"{second.count()} pages were reported twice while the guest was quiesced"

    pagemaster.resume(run_vcpus=1)
    time.sleep(2)
    pagemaster.quiesce()
    pagemaster.dirty_snapshot()
    third = pagemaster.harvest()
    assert third.count() > 0, "writes after the harvest were not tracked"


def test_dirty_union_restores_the_snapshot_and_is_refused_outside_quiesce(
    farplane_factory,
):
    """Folding a harvest back in reproduces it bit for bit, and only while quiesced."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.dirty_snapshot()
    harvested = pagemaster.harvest()
    assert harvested.count() > 0

    assert pagemaster.dirty_union(harvested).error is None
    pagemaster.dirty_snapshot()
    restored = pagemaster.harvest()
    assert bytes(restored.data) == bytes(
        harvested.data
    ), "dirty_union did not restore exactly the snapshotted bits"

    pagemaster.resume(run_vcpus=1)
    reply = pagemaster.dirty_union(harvested)
    assert reply.error == (fp.Err.NOT_QUIESCED, fp.Msg.DIRTY_UNION)


def test_a_failed_harvest_preserves_every_bit(farplane_factory):
    """A harvest that cannot be written keeps the dirty log intact for the retry."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    write_sealed = fp.sealed_memfd(
        "farplane-dirty-ro",
        pagemaster.dirty_bitmap_bytes,
        seals=fp.BUFFER_SEALS | fp.F_SEAL_WRITE,
        read_only=False,
    )
    vmstate = fp.sealed_memfd(
        "farplane-vmstate",
        pagemaster.vmstate_capacity_bytes,
        seals=fp.BUFFER_SEALS,
        read_only=False,
    )
    assert pagemaster.capture_buffers(write_sealed, vmstate).error is None
    expected = set(pagemaster.written_pages())
    assert expected

    pagemaster.quiesce()
    failed = pagemaster.dirty_snapshot()
    assert failed.error == (fp.Err.DIRTY_HARVEST_FAILED, fp.Msg.DIRTY_SNAPSHOT)

    # Come back to Ready without letting a vCPU run, so nothing can re-dirty the log.
    pagemaster.resume(run_vcpus=0)
    pagemaster.capture_buffers()
    pagemaster.quiesce()
    assert pagemaster.dirty_snapshot().error is None
    harvest = pagemaster.harvest()
    for page in expected:
        assert harvest[page], f"the failed harvest dropped the dirty bit of {page:#x}"

    os.close(write_sealed)
    os.close(vmstate)


def test_guest_memory_is_frozen_between_quiesce_and_resume(farplane_factory):
    """Not one guest byte moves while the capture is in progress."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.dirty_snapshot()
    hot = pagemaster.harvest().set_pages()[:256]
    assert hot, "no page was dirtied before the capture"

    before = digest(pagemaster, hot)
    time.sleep(3)
    after = digest(pagemaster, hot)
    assert before == after, "guest memory changed while quiesced"

    pagemaster.resume(run_vcpus=1)
    assert vm.farplane_state()["backend_state"] == "ready"


def test_vmstate_lands_in_the_supplied_memfd_and_no_file_appears(farplane_factory):
    """write_vmstate fills the capture buffer and never touches the jail filesystem."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    before = sorted(str(path) for path in vm.chroot.rglob("*"))

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    reply = pagemaster.write_vmstate()
    assert reply.error is None
    (length,) = struct.unpack("<Q", reply.body)
    assert length > 0
    payload = pagemaster.vmstate(length)
    assert len(payload) == length
    assert payload.strip(b"\0"), "the vmstate buffer is empty"

    after = sorted(str(path) for path in vm.chroot.rglob("*"))
    assert (
        after == before
    ), f"the capture created files in the jail: {set(after) - set(before)}"


def test_ptracer_permits_the_pagemaster_and_denies_a_stranger(farplane_factory):
    """Guest memory is readable by the declared pagemaster only."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    marker_addr = sorted(pagemaster.marker_bytes)[0]
    marker = pagemaster.marker_bytes[marker_addr]
    assert pagemaster.read_guest(marker_addr, len(marker)) == marker

    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            os.setgroups([])
            os.setgid(65534)
            os.setuid(65534)
            pagemaster.read_guest(marker_addr, len(marker))
            os.write(writer, b"allowed")
        except OSError as err:
            os.write(writer, str(err.errno).encode())
        except Exception:  # pylint: disable=broad-except
            os.write(writer, b"error")
        os._exit(0)  # pylint: disable=protected-access

    os.close(writer)
    outcome = os.read(reader, 32)
    os.close(reader)
    os.waitpid(child, 0)
    assert outcome != b"allowed", "an unrelated process could read guest memory"


def test_every_guest_vma_is_locked_on_fault_and_huge_page_free(farplane_factory):
    """Guest mappings are locked on fault and never backed by huge pages."""
    vm = farplane_factory()
    pagemaster = boot(vm, splits=2)

    for region in pagemaster.ready_regions:
        entries = smaps_of(
            vm.pid, region["host_base"], region["host_base"] + region["size"]
        )
        assert entries, f"no mapping covers guest region {region['guest_addr']:#x}"
        for entry in entries:
            flags = entry["VmFlags"].split()
            assert "lo" in flags, f"{entry['header']} is not locked"
            assert "nh" in flags, f"{entry['header']} allows huge pages"
            assert entry["AnonHugePages"] == "0 kB", entry["header"]
            assert entry["ShmemPmdMapped"] == "0 kB", entry["header"]
            locked = int(entry["Locked"].split()[0])
            resident = int(entry["Rss"].split()[0])
            size = int(entry["Size"].split()[0])
            assert locked <= resident, "more memory is locked than is resident"
            if size > 32 * 1024:
                assert (
                    resident < size
                ), f"{entry['header']} is fully resident, so it was not locked on fault"


def test_hole_punching_syscalls_are_denied_by_the_installed_filter(farplane_factory):
    """Firecracker runs a filter that cannot discard guest pages."""
    vm = farplane_factory()
    boot(vm)

    utils.assert_seccomp_level(vm.pid, "2")

    filter_path = (
        SECCOMP_JSON_DIR / f"{global_props.cpu_architecture}-unknown-linux-musl.json"
    )
    policy = json.loads(filter_path.read_text(encoding="utf-8"))
    for thread, rules in policy.items():
        assert rules["default_action"] != "allow", thread
        for rule in rules["filter"]:
            if rule["syscall"] == "fallocate":
                pytest.fail(
                    "the filter allows fallocate, so guest pages can be punched out"
                )
            if rule["syscall"] != "madvise":
                continue
            args = rule.get("args")
            assert args, "madvise is allowed with any advice"
            for arg in args:
                assert arg["index"] == 2
                assert arg["op"] == "eq", f"{thread} compares the advice loosely: {arg}"
                # MADV_DONTNEED and MADV_REMOVE must never be reachable.
                assert arg["val"] not in (4, 9), f"{thread} allows advice {arg['val']}"


def test_parent_death_kills_firecracker(farplane_factory):
    """Firecracker dies with its parent, so an orphaned jail cannot outlive the pagemaster."""
    vm = farplane_factory()
    vm.spawn(via_wrapper=True)
    pid = vm.pid
    assert Path(f"/proc/{pid}").exists()

    vm.wrapper.kill()
    vm.wrapper.wait(timeout=10)

    wait_for(
        lambda: not Path(f"/proc/{pid}/stat").exists(),
        timeout=10,
        message="Firecracker exiting with its parent",
    )


def test_root_drive_is_served_from_the_sealed_memfd(farplane_factory):
    """The root device comes from fd 4, which no one can write."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    assert fp.seals_of(vm.root_fd) & fp.F_SEAL_WRITE, "the root memfd is writable"
    assert not list(
        vm.chroot.glob("*.squashfs")
    ), "a rootfs image was staged in the jail"
    assert os.readlink(f"/proc/{vm.pid}/fd/4").startswith("/memfd:rootfs")

    # The guest read the image over virtio, so its bytes are in guest memory.
    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.dirty_snapshot()
    with open(vm.rootfs, "rb") as image:
        signature = image.read(64)
    assert any(
        pagemaster.read_guest(page, 64) == signature
        for page in pagemaster.harvest().set_pages()
    ), "the guest never read the sealed root image"
    pagemaster.resume(run_vcpus=1)

    for body, message in [
        (
            {"drive_id": "second", "fd": 4, "is_read_only": False},
            "A drive backed by `fd` requires `is_read_only` to be true.",
        ),
        (
            {
                "drive_id": "second",
                "fd": 4,
                "path_on_host": "/rootfs",
                "is_read_only": True,
            },
            "A drive is backed by either `path_on_host` or `fd`, never both.",
        ),
        (
            {"drive_id": "second", "is_read_only": True},
            "A drive requires either `path_on_host` or `fd`.",
        ),
    ]:
        response = raw(vm.api, "PUT", "/drives/second", body)
        assert response.status_code == 400, response.text
        assert message in response.text, response.text


@pytest.mark.parametrize(
    "flaw,expected",
    [
        ("writable", "--root-fd must be opened O_RDONLY"),
        ("unsealed", "--root-fd is missing required memfd seals"),
        ("empty", "--root-fd size must be nonzero"),
        ("not_a_memfd", "--root-fd is not a memfd"),
    ],
)
def test_jailer_refuses_a_bad_root_fd(farplane_factory, flaw, expected):
    """Every root descriptor precondition is enforced before the jail is built."""
    vm = farplane_factory(f"rootfd-{flaw}")
    if flaw == "writable":
        root_fd = vm.open_root_memfd(size=PAGE, read_only=False)
    elif flaw == "unsealed":
        root_fd = vm.open_root_memfd(size=PAGE, seals=fp.F_SEAL_GROW)
    elif flaw == "empty":
        root_fd = vm.open_root_memfd(size=0)
    else:
        # A directory is never a shmem file, so F_GET_SEALS fails whatever the host filesystem
        # under the jail happens to be.
        vm.chroot_base.mkdir(parents=True, exist_ok=True)
        root_fd = os.open(vm.chroot_base, os.O_RDONLY | os.O_DIRECTORY)
        vm.root_fd = root_fd

    vm.spawn(root_fd=root_fd, wait=False)
    assert vm.proc.wait(timeout=30) != 0
    assert expected in vm.stdio_text()
    assert not vm.api_socket.exists()


@pytest.mark.parametrize("violation", ["eof", "oversized"])
def test_channel_violation_after_ready_only_fails_the_channel(
    farplane_factory, violation
):
    """Breaking the channel after Ready leaves the guest untouched and is reported."""
    vm = farplane_factory(f"violation-{violation}")
    pagemaster = boot(vm)

    sample = sorted(pagemaster.marker_bytes)
    before = digest(pagemaster, sample)

    if violation == "eof":
        pagemaster.close_channel()
    else:
        header = fp.HEADER.pack(
            fp.MAGIC, fp.VERSION, int(fp.Msg.QUIESCE), 4242, fp.MAX_DATAGRAM, 0, 0
        )
        pagemaster.send_raw(header + bytes(fp.MAX_DATAGRAM))

    wait_for(
        lambda: vm.farplane_state()["backend_state"] == "channel_failed",
        message="the backend reporting channel_failed",
    )
    assert vm.instance()["state"] == "Running"
    assert (
        digest(pagemaster, sample) == before
    ), "guest memory changed after the violation"


def test_removed_api_surfaces_are_absent(farplane_factory):
    """Every deleted route and field is refused instead of silently accepted."""
    vm = farplane_factory()
    boot(vm)

    for path, body in [
        ("/snapshot/create", {"snapshot_type": "Full", "snapshot_path": "/snap"}),
        ("/balloon", {"amount_mib": 1, "deflate_on_oom": False}),
        ("/mmds/config", {"ipv4_address": "169.254.169.254"}),
    ]:
        response = raw(vm.api, "PUT", path, body)
        assert response.status_code in (
            400,
            404,
        ), f"{path} still exists: {response.text}"

    for path in ["/balloon/statistics", "/mmds"]:
        response = raw(vm.api, "GET", path)
        assert response.status_code in (
            400,
            404,
        ), f"{path} still exists: {response.text}"

    rejected = [
        ("/machine-config", "PATCH", {"track_dirty_pages": True}),
        ("/machine-config", "PATCH", {"huge_pages": "2M"}),
        (
            "/drives/socket",
            "PUT",
            {"drive_id": "socket", "socket": "/vhost.sock", "is_read_only": True},
        ),
    ]
    for path, method, body in rejected:
        response = raw(vm.api, method, path, body)
        assert response.status_code == 400, f"{body} was accepted at {path}"

    load = raw(
        vm.api, "PUT", "/snapshot/load", {"resume_vm": True, "mem_file_path": "/mem"}
    )
    assert load.status_code == 400, "snapshot/load still accepts file paths"


def test_patch_vm_during_a_capture_conflicts(farplane_factory):
    """Pausing or resuming over the API is refused while a capture holds the vCPUs."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    assert raw(vm.api, "PATCH", "/vm", {"state": "Paused"}).status_code == 204
    assert raw(vm.api, "PATCH", "/vm", {"state": "Resumed"}).status_code == 204

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    conflict = raw(vm.api, "PATCH", "/vm", {"state": "Paused"})
    assert conflict.status_code == 409, conflict.text
    assert "capture_in_progress" in conflict.text

    pagemaster.resume(run_vcpus=1)
    assert raw(vm.api, "PATCH", "/vm", {"state": "Paused"}).status_code == 204


def test_jail_hands_over_renumbered_fds_and_a_stripped_process(farplane_factory):
    """The jailer renumbers the inherited descriptors and strips the process it execs."""
    vm = farplane_factory()
    base = vm.open_root_memfd()
    spares = [os.dup(base) for _ in range(8)]
    high = next(fd for fd in spares if fd > fp.ROOT_FILENO)
    for fd in [base] + [fd for fd in spares if fd != high]:
        os.close(fd)
    vm.root_fd = high

    boot(vm)

    device = f"/proc/{vm.pid}/fd/{fp.UFFD_DEVICE_FILENO}"
    root = f"/proc/{vm.pid}/fd/{fp.ROOT_FILENO}"
    assert os.readlink(device) == str(fp.DEV_USERFAULTFD)
    assert os.stat(device).st_rdev == fp.DEV_USERFAULTFD.stat().st_rdev
    assert os.readlink(root).startswith("/memfd:rootfs")

    status = Path(f"/proc/{vm.pid}/status").read_text(encoding="utf-8")
    caps = dict(
        line.split(":", 1) for line in status.splitlines() if line.startswith("Cap")
    )
    for name in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        assert int(caps[name].strip(), 16) == 0, f"{name} is not empty"

    limits = Path(f"/proc/{vm.pid}/limits").read_text(encoding="utf-8")
    memlock = next(line for line in limits.splitlines() if "locked memory" in line)
    soft = memlock.split()[3]
    assert soft == "unlimited" or int(soft) >= MEM_SIZE_MIB << 20, memlock


def test_jailer_joins_a_precreated_cgroup(farplane_factory):
    """--cgroup-join moves Firecracker into the leaf the caller prepared."""
    vm = farplane_factory()
    leaf = Path("/sys/fs/cgroup") / f"farplane-join-{vm.microvm_id}"
    leaf.mkdir(exist_ok=True)

    vm.spawn(cgroup_join=leaf)
    membership = Path(f"/proc/{vm.pid}/cgroup").read_text(encoding="utf-8")
    assert leaf.name in membership, membership


def test_cold_boot_over_one_all_hole_sparse_memfd(farplane_factory):
    """A guest boots when every page starts as a hole in a single sparse memfd."""
    vm = farplane_factory()
    pagemaster = boot(vm, single_memfd=True, markers=False)

    assert len(pagemaster.backing_fds) == 1
    assert len(pagemaster.extents) == len(pagemaster.regions)
    assert vm.instance()["state"] == "Running"

    faults = list(pagemaster.faults)
    assert faults, "a hole-backed guest took no fault"
    assert all(
        not flags & fp.UFFD_PAGEFAULT_FLAG_MINOR for _, flags in faults
    ), "a hole page produced a minor fault"
    assert os.fstat(pagemaster.backing_fds[0]).st_size == sum(
        size for _, size in pagemaster.regions
    )


def test_instance_info_reports_the_farplane_state_sequence(farplane_factory):
    """GET / follows the backend through the whole capture cycle."""
    vm = farplane_factory()
    vm.spawn()
    pagemaster = vm.start_pagemaster()

    cold = vm.farplane_state()
    assert cold["backend_state"] == "awaiting_plan"
    assert cold["vcpus"] == "not_started"
    assert cold["capture_buffers_armed"] is False
    assert cold["feature_identity"] == fp.FEATURE_IDENTITY

    vm.configure()
    vm.start()
    pagemaster.wait_ready()

    running = vm.farplane_state()
    assert running["backend_state"] == "ready"
    assert running["vcpus"] == "running"
    assert running["capture_buffers_armed"] is False

    pagemaster.capture_buffers()
    assert vm.farplane_state()["capture_buffers_armed"] is True

    pagemaster.quiesce()
    quiesced = vm.farplane_state()
    assert quiesced["backend_state"] == "quiesced"
    assert quiesced["capture_buffers_armed"] is True

    pagemaster.resume(run_vcpus=1)
    resumed = vm.farplane_state()
    assert resumed["backend_state"] == "ready"
    assert resumed["capture_buffers_armed"] is False
