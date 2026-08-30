# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for guest memory served over the farplane pagemaster channel."""

# pylint: disable=too-many-lines

import errno
import fcntl
import hashlib
import json
import os
import re
import struct
import time
import uuid
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
        # A jail persists until the session root is removed, so an ID must not be reused by the
        # next test or kernel parameter. Keep descriptive IDs, but make them valid and unique in
        # the same way as the general microvm factory.
        label = (microvm_id or f"fp{len(built)}").replace("_", "-")
        microvm_id = f"{label}-{uuid.uuid4().hex[:8]}"
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
    # A regular image has to be staged outside the tmpfs session root, so it is removed here
    # rather than left in the build or source tree the run staged it in.
    fp.unpublish_images()


def boot(vm, *, vcpu_count=1, mem_size_mib=MEM_SIZE_MIB, fc_args=(), **pm_kwargs):
    """Launch the jail, serve the memory channel and start the guest."""
    vm.spawn(fc_args=fc_args)
    pagemaster = vm.start_pagemaster(**pm_kwargs)
    vm.configure(vcpu_count=vcpu_count, mem_size_mib=mem_size_mib)
    vm.start()
    pagemaster.wait_ready()
    vm.api.vm.patch(state="Resumed")
    return pagemaster


def restore(vm, parent, vmstate_image, *, splits=1, resume_vm=False):
    """Restore a second Firecracker over the parent's checkpoint.

    The parent's backing descriptors *are* the checkpoint bytes once a capture epoch has closed,
    while `vmstate_image` is the exact-sized immutable artifact finalized from the capture buffer.
    Both are handed to the child's memory channel. A restore hello states no geometry, so the plan
    tiles the regions the parent reported, which is what the vmstate names.
    """
    vm.spawn()
    pagemaster = vm.start_pagemaster(
        splits=splits,
        markers=False,
        shared_memfds=parent.backing_fds,
        restore_regions=[
            (region["guest_addr"], region["size"]) for region in parent.ready_regions
        ],
        vmstate_image=vmstate_image,
    )
    vm.load_snapshot(resume_vm=resume_vm)
    pagemaster.wait_ready()
    return pagemaster


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


def wait_for_block_read(vm, drive_id, *, timeout=60):
    """Wait until the guest completes a read from one named virtio block device."""

    def block_reads():
        vm.api.actions.put(action_type="FlushMetrics")
        metrics_path = vm.chroot / "fc.ndjson"
        if not metrics_path.exists():
            return 0
        text = metrics_path.read_text(encoding="utf-8")
        reads = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            metrics = json.loads(line)
            reads += metrics.get(f"block_{drive_id}", {}).get("read_count", 0)
        return reads

    return wait_for(
        block_reads,
        timeout=timeout,
        message=f"a virtio block read from {drive_id}",
    )


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

    # Before it allowed the guest to execute, the pagemaster read a unique marker from the last
    # page of every extent. Exact address coverage proves each separate memfd mapping, including
    # both sides of every boundary, without mistaking later KVM guest writes for pristine backing
    # bytes (KVM reports those through its dirty log, not userfaultfd write events).
    expected_markers = {
        extent.guest_addr + extent.len - PAGE for extent in pagemaster.extents
    }
    assert set(pagemaster.marker_reads) == expected_markers
    for guest_addr, marker in pagemaster.marker_bytes.items():
        assert (
            pagemaster.marker_reads[guest_addr] == marker
        ), f"the extent boundary at {guest_addr:#x} served the wrong memfd bytes"


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


def test_dirty_harvest_covers_loader_vcpu_and_device_writes(farplane_factory):
    """The first harvest holds the loader image, every faulted guest write and device writes."""
    vm = farplane_factory()
    pagemaster = boot(vm, fc_args=("--metrics-path", "fc.ndjson"))

    wait_for_block_read(vm, "rootfs")
    written = set(pagemaster.written_pages())
    assert written, "the guest never took a write fault"

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    harvest = pagemaster.harvest()
    harvested_pages = set(harvest.set_pages())

    all_pages = {
        region["guest_addr"] + offset
        for region in pagemaster.ready_regions
        for offset in range(0, region["size"], PAGE)
    }
    # `KVM_DIRTY_LOG_INITIALLY_SET` makes every slot of a booted VM start fully dirty, so the
    # loader image, every faulted guest write and every device write are all in the first capture.
    # Asserted as equality in both directions: a subset check over an all-ones bitmap is
    # satisfied by construction and proves nothing about what the harvest tracks.
    assert harvested_pages == all_pages, (
        "the first harvest of a booted VM must be exactly the whole geometry: "
        f"{len(all_pages - harvested_pages)} pages of a region missing, "
        f"{len(harvested_pages - all_pages)} pages outside every region"
    )
    assert written <= harvested_pages


def test_dirty_snapshot_returns_each_epoch_exactly_once(farplane_factory):
    """Harvesting clears the log, so the next epoch reports nothing until the guest writes."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    assert pagemaster.capture_buffers().error is None
    assert pagemaster.quiesce().error is None
    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    first = pagemaster.harvest()
    all_pages = {
        region["guest_addr"] + offset
        for region in pagemaster.ready_regions
        for offset in range(0, region["size"], PAGE)
    }
    assert (
        set(first.set_pages()) == all_pages
    ), "the first epoch of a boot is the whole geometry"

    # Come back to Ready without letting a vCPU run, so nothing can re-dirty the log.
    assert pagemaster.resume(run_vcpus=0).error is None
    assert pagemaster.capture_buffers().error is None
    assert pagemaster.quiesce().error is None
    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    second = pagemaster.harvest()
    assert (
        second.count() == 0
    ), f"{second.count()} pages were reported twice while the guest was quiesced"

    # Arm userfaultfd write protection while the guest is stopped, then wait for a write fault
    # after resuming. This proves a vCPU wrote during this epoch without relying on a tickless idle
    # guest to happen to write during a fixed sleep. Resume releases the prior capture buffers, so
    # every epoch must explicitly arm fresh buffers before harvesting it.
    written_before_resume = set(pagemaster.written_pages())
    for region in pagemaster.ready_regions:
        pagemaster.write_protect(region["host_base"], region["size"])
    assert pagemaster.resume(run_vcpus=1).error is None
    assert pagemaster.capture_buffers().error is None
    wait_for(
        lambda: len(pagemaster.written_pages()) > len(written_before_resume),
        timeout=30,
        message="a guest write after the dirty-log harvest",
    )
    assert pagemaster.quiesce().error is None
    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    third = pagemaster.harvest()
    third_pages = set(third.set_pages())
    new_writes = set(pagemaster.written_pages()) - written_before_resume
    assert new_writes, "the wait returned without a new write fault"
    assert (
        new_writes <= third_pages
    ), f"{sorted(new_writes - third_pages)} were written this epoch and not reported"
    # Independent of the writes above. An epoch reporting the whole geometry satisfies any subset
    # check, so the epoch has to be strictly smaller than the geometry to carry any information.
    assert len(third_pages) < len(all_pages), (
        "the third epoch reported every page of every region, so the harvest is reporting the "
        "geometry rather than the writes"
    )


def test_a_restored_parent_harvests_only_post_restore_writes(farplane_factory):
    """A restored VM's first epoch holds the restore's writes, not the whole geometry."""
    parent_vm = farplane_factory("restore-parent")
    parent = boot(parent_vm, fc_args=("--metrics-path", "fc.ndjson"))
    wait_for_block_read(parent_vm, "rootfs")

    # Close a capture epoch on the parent. Its backing descriptors now hold the checkpoint bytes
    # and its vmstate buffer holds the serialized state. It stays quiesced, so those bytes cannot
    # move while the exact-sized immutable restore image is finalized.
    assert parent.capture_buffers().error is None
    assert parent.quiesce().error is None
    written = parent.write_vmstate()
    assert written.error is None
    (vmstate_length,) = struct.unpack("<Q", written.body)
    vmstate_image = fp.sealed_memfd(
        "farplane-vmstate-image",
        vmstate_length,
        content=parent.vmstate(vmstate_length),
        seals=fp.ROOT_SEALS,
    )
    assert os.fstat(vmstate_image).st_size == vmstate_length
    assert fp.seals_of(vmstate_image) == fp.ROOT_SEALS
    assert fcntl.fcntl(vmstate_image, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
    assert parent.dirty_snapshot().error is None
    assert parent.harvest().count() > 0

    child_vm = farplane_factory("restore-child")
    try:
        child = restore(child_vm, parent, vmstate_image)
    finally:
        os.close(vmstate_image)

    # The child's plan tiles its parent's memfds, and the folios of those are already in the page
    # cache, so a first touch of one is a minor fault and not a missing fault. The child plants no
    # markers of its own: the bytes it has to serve are the ones the descriptors already carry.
    # Resolving such a fault with a zero page would both lose the checkpoint bytes and fail
    # outright, leaving the faulting Firecracker thread stranded, so this reads the parent's
    # marker back through the child's mapping and compares it against the memfd itself.
    assert not child.markers
    marker_addr = sorted(parent.marker_bytes)[0]
    backing = child.backing_bytes(marker_addr, PAGE)
    assert backing.startswith(
        parent.marker_bytes[marker_addr]
    ), "the marker page is not backed"
    assert backing.strip(
        b"\0"
    ), "the backing page is all zeroes, so a zero-fill is undetectable"
    assert child.read_guest(marker_addr, PAGE) == backing
    assert any(
        flags & fp.UFFD_PAGEFAULT_FLAG_MINOR for _, flags in list(child.faults)
    ), "the restored guest took no minor fault over its parent's memfds"
    assert child.fault_error() is None
    assert child.serving_faults(), "the fault service stopped resolving faults"

    all_pages = {
        region["guest_addr"] + offset
        for region in child.ready_regions
        for offset in range(0, region["size"], PAGE)
    }
    assert len(all_pages) == len(
        {
            region["guest_addr"] + offset
            for region in parent.ready_regions
            for offset in range(0, region["size"], PAGE)
        }
    ), "the restored VM was given a different geometry from its parent"

    # The child's vCPUs have not started, so everything this epoch reports was written by the
    # restore itself: the vCPU state KVM applied and the devices the restore rebuilt.
    assert child.capture_buffers().error is None
    assert child.quiesce().error is None
    assert child.write_vmstate().error is None
    assert child.dirty_snapshot().error is None
    first_pages = set(child.harvest().set_pages())

    assert first_pages, "the restore wrote no guest page at all"
    assert len(first_pages) < len(all_pages), (
        f"the restored VM's first harvest reported {len(first_pages)} of {len(all_pages)} pages, "
        "so it inherited KVM's initially-set bitmap instead of retiring it"
    )

    # The baseline re-armed write protection rather than disabling tracking, so the next epoch
    # still reports what the guest writes once its vCPUs run.
    written_before = set(child.written_pages())
    for region in child.ready_regions:
        child.write_protect(region["host_base"], region["size"])
    assert child.resume(run_vcpus=0).error is None
    child_vm.api.vm.patch(state="Resumed")
    assert child.capture_buffers().error is None
    wait_for(
        lambda: len(child.written_pages()) > len(written_before),
        timeout=30,
        message="a guest write after the restored VM's dirty-log baseline",
    )
    assert child.quiesce().error is None
    assert child.write_vmstate().error is None
    assert child.dirty_snapshot().error is None
    second_pages = set(child.harvest().set_pages())
    new_writes = set(child.written_pages()) - written_before
    assert new_writes, "the wait returned without a new write fault"
    assert (
        new_writes <= second_pages
    ), f"{sorted(new_writes - second_pages)} were written this epoch and not reported"
    assert len(second_pages) < len(all_pages)


def test_a_repeated_capture_command_replays_its_answer(farplane_factory):
    """A retry after a lost reply must answer, not redo the work it already did.

    A second harvest would overwrite the armed bitmap with the accumulator the first one
    cleared, which loses the only copy of the epoch's dirty set. A second serialization
    would run device `prepare_save()` again and leave a different vmstate in the buffer.
    """
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()

    first_write = pagemaster.write_vmstate()
    assert first_write.error is None
    repeat_write = pagemaster.write_vmstate()
    assert repeat_write.error is None
    assert (
        repeat_write.body == first_write.body
    ), "the repeat reported a different length"
    (length,) = struct.unpack("<Q", first_write.body)
    vmstate = pagemaster.vmstate(length)

    assert pagemaster.dirty_snapshot().error is None
    harvested = pagemaster.harvest()
    assert harvested.count() > 0

    assert pagemaster.dirty_snapshot().error is None
    replayed = pagemaster.harvest()
    assert bytes(replayed.data) == bytes(
        harvested.data
    ), "the repeated harvest overwrote the bitmap the first one produced"
    assert (
        pagemaster.vmstate(length) == vmstate
    ), "the vmstate buffer changed under a repeat"

    # A union puts the bits back in the accumulator, so the next harvest runs again rather
    # than replaying what the armed bitmap already holds.
    assert pagemaster.dirty_union(harvested).error is None
    assert pagemaster.dirty_snapshot().error is None
    assert bytes(pagemaster.harvest().data) == bytes(harvested.data)


def test_an_exact_retry_of_a_frame_is_answered_not_served(farplane_factory):
    """The same datagram, resent, draws the same answer whatever happened in between.

    Pagemaster resends a command whose reply it never saw. The answer is keyed by the
    request identifier and the contents of the frame, so a retry cannot harvest again even
    after a `dirty_union` has put the bits back and reopened the epoch's dirty set.
    """
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.write_vmstate()

    harvest_id = pagemaster.next_request_id()
    harvest_frame = pagemaster.frame(fp.Msg.DIRTY_SNAPSHOT, harvest_id)
    first = pagemaster.exchange(harvest_frame)
    assert first.msg == fp.Msg.DIRTY_SNAPSHOT_DONE
    harvested = pagemaster.harvest()
    assert harvested.count() > 0

    # The bits go back into the accumulator, so the phase alone would harvest again.
    assert pagemaster.dirty_union(harvested).error is None

    replay = pagemaster.exchange(harvest_frame)
    assert replay.msg == fp.Msg.DIRTY_SNAPSHOT_DONE
    assert bytes(pagemaster.harvest().data) == bytes(
        harvested.data
    ), "the retried frame harvested again instead of replaying its answer"

    # The same identifier with other contents is not the command it answered.
    reused = pagemaster.exchange(pagemaster.frame(fp.Msg.WRITE_VMSTATE, harvest_id))
    assert reused.error == (fp.Err.REQUEST_ID_REUSED, fp.Msg.WRITE_VMSTATE)

    # The answer survives leaving the epoch and opening the next one.
    pagemaster.resume(run_vcpus=0)
    pagemaster.capture_buffers()
    pagemaster.quiesce()
    before_replay = bytes(pagemaster.harvest().data)
    across_epochs = pagemaster.exchange(harvest_frame)
    assert across_epochs.msg == fp.Msg.DIRTY_SNAPSHOT_DONE
    assert (
        bytes(pagemaster.harvest().data) == before_replay
    ), "replaying an old answer served its old harvest into the next epoch's buffer"


def test_a_retry_of_a_descriptor_command_must_name_the_same_memfds(farplane_factory):
    """`capture_buffers` carries its input in descriptors, so identity is the files, not the count.

    A retry duplicates the descriptors of the same memfds and is answered from the record.
    The same identifier naming other memfds of the same sizes is a different command: the
    answer on record acknowledged buffers that are not these, so it is refused.
    """
    vm = farplane_factory()
    pagemaster = boot(vm)

    def buffers():
        return (
            fp.sealed_memfd(
                "farplane-dirty",
                pagemaster.dirty_bitmap_bytes,
                seals=fp.BUFFER_SEALS,
                read_only=False,
            ),
            fp.sealed_memfd(
                "farplane-vmstate",
                pagemaster.vmstate_capacity_bytes,
                seals=fp.BUFFER_SEALS,
                read_only=False,
            ),
        )

    dirty, vmstate = buffers()
    arm_id = pagemaster.next_request_id()
    frame = pagemaster.frame(fp.Msg.CAPTURE_BUFFERS, arm_id, fd_count=2)

    armed = pagemaster.exchange(frame, fds=[dirty, vmstate])
    assert armed.msg == fp.Msg.CAPTURE_BUFFERS_ARMED

    # The retry sends the same open files again; SCM_RIGHTS hands Firecracker other
    # descriptor numbers for them, which must not make it a different command.
    replay = pagemaster.exchange(frame, fds=[dirty, vmstate])
    assert replay.msg == fp.Msg.CAPTURE_BUFFERS_ARMED

    other_dirty, other_vmstate = buffers()
    refused = pagemaster.exchange(frame, fds=[other_dirty, other_vmstate])
    assert refused.error == (fp.Err.REQUEST_ID_REUSED, fp.Msg.CAPTURE_BUFFERS)

    for descriptor in (dirty, vmstate, other_dirty, other_vmstate):
        os.close(descriptor)


def test_a_harvest_before_the_vmstate_is_refused(farplane_factory):
    """The vmstate is serialized before the dirty log is harvested, or not at all.

    Serializing the vmstate runs `prepare_save()` on every device, and a device may write
    guest memory there, so a harvest that ran first would report a bitmap that predates
    those writes.
    """
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    early = pagemaster.dirty_snapshot()
    assert early.error == (fp.Err.CAPTURE_ORDER_VIOLATION, fp.Msg.DIRTY_SNAPSHOT)

    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    assert pagemaster.harvest().count() > 0

    # The same violation from the other side: the writes a second serialization performs
    # have no harvest left to report them.
    late = pagemaster.write_vmstate()
    assert late.error == (fp.Err.CAPTURE_ORDER_VIOLATION, fp.Msg.WRITE_VMSTATE)

    # A fresh epoch owes a vmstate again, whatever the last one reached.
    pagemaster.resume(run_vcpus=0)
    pagemaster.capture_buffers()
    pagemaster.quiesce()
    assert pagemaster.dirty_snapshot().error == (
        fp.Err.CAPTURE_ORDER_VIOLATION,
        fp.Msg.DIRTY_SNAPSHOT,
    )


def test_dirty_union_restores_the_snapshot_and_is_refused_outside_quiesce(
    farplane_factory,
):
    """Folding a harvest back in reproduces it bit for bit, and only while quiesced."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.write_vmstate()
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
        seals=fp.BUFFER_SEALS,
        read_only=False,
    )
    vmstate = fp.sealed_memfd(
        "farplane-vmstate",
        pagemaster.vmstate_capacity_bytes,
        seals=fp.BUFFER_SEALS,
        read_only=False,
    )
    assert pagemaster.capture_buffers(write_sealed, vmstate).error is None
    # The handoff accepted a correctly sized, writable buffer. Seal writes only afterwards so the
    # harvest itself fails rather than the capture-buffer contract rejecting the descriptor.
    fcntl.fcntl(write_sealed, fp.F_ADD_SEALS, fp.F_SEAL_WRITE)
    expected = set(pagemaster.written_pages())
    assert expected

    pagemaster.quiesce()
    assert pagemaster.write_vmstate().error is None
    failed = pagemaster.dirty_snapshot()
    assert failed.error == (fp.Err.DIRTY_HARVEST_FAILED, fp.Msg.DIRTY_SNAPSHOT)

    # Come back to Ready without letting a vCPU run, so nothing can re-dirty the log.
    pagemaster.resume(run_vcpus=0)
    pagemaster.capture_buffers()
    pagemaster.quiesce()
    assert pagemaster.write_vmstate().error is None
    assert pagemaster.dirty_snapshot().error is None
    harvest = pagemaster.harvest()
    harvested_pages = set(harvest.set_pages())
    for page in expected:
        assert (
            page in harvested_pages
        ), f"the failed harvest dropped the dirty bit of {page:#x}"

    os.close(write_sealed)
    os.close(vmstate)


def test_guest_memory_is_frozen_between_quiesce_and_resume(farplane_factory):
    """Not one guest byte moves while the capture is in progress."""
    vm = farplane_factory()
    pagemaster = boot(vm)

    pagemaster.capture_buffers()
    pagemaster.quiesce()
    pagemaster.write_vmstate()
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

    def not_running():
        try:
            # A dead child can remain in /proc as a zombie until its new parent reaps it. The
            # process state, rather than disappearance of its proc entry, proves PDEATHSIG won.
            return (
                Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2] == "Z"
            )
        except FileNotFoundError:
            return True

    wait_for(
        not_running,
        timeout=10,
        message="Firecracker becoming dead after its parent exits",
    )


def test_root_drive_is_served_from_a_shared_read_only_regular_file(farplane_factory):
    """One published image file backs several microVMs, with no per-jail copy of it."""
    first = farplane_factory("shared-image-a")
    second = farplane_factory("shared-image-b")

    first.open_root_image_file()
    second.open_root_image_file()
    assert (
        second.root_image_path == first.root_image_path
    ), "the image was published once per microVM"

    published = os.stat(first.root_image_path)
    assert not published.st_mode & 0o222, "the published image is writable"
    assert (
        published.st_uid != first.uid
    ), "the published image is owned by the jailed uid"

    # The arm of the image descriptor contract is selected by whether the inode answers
    # `F_GET_SEALS`. An image that answers it is held to the sealed memfd arm however it was
    # created, so it is only on a filesystem that refuses the call that this test covers the
    # regular-file arm at all.
    staging = os.stat(fp.regular_image_dir())
    assert (
        published.st_dev == staging.st_dev
    ), "the published image left the filesystem that was probed for seals"
    with pytest.raises(OSError) as sealing:
        fp.seals_of(first.root_fd)
    assert sealing.value.errno == errno.EINVAL, str(sealing.value)

    boot(first, fc_args=("--metrics-path", "fc.ndjson"))
    boot(second)
    wait_for_block_read(first, "rootfs")

    # Both jails hold the published inode itself, so one page cache serves both guests instead of
    # one copy per microVM.
    identity = (published.st_dev, published.st_ino)
    for vm in (first, second):
        jailed = os.stat(f"/proc/{vm.pid}/fd/{fp.ROOT_FILENO}")
        assert (
            jailed.st_dev,
            jailed.st_ino,
        ) == identity, f"{vm.microvm_id} holds another inode"

    # The inherited descriptor is the only path to those bytes: nothing image-sized was staged
    # inside either jail.
    for vm in (first, second):
        staged = [
            path
            for path in vm.chroot.rglob("*")
            if path.is_file() and path.stat().st_size >= published.st_size
        ]
        assert not staged, f"an image was staged in {vm.chroot}: {staged}"


def test_root_drive_is_served_from_the_sealed_memfd(farplane_factory):
    """The root device comes from fd 4, which no one can write."""
    vm = farplane_factory()
    boot(vm, fc_args=("--metrics-path", "fc.ndjson"))
    wait_for_block_read(vm, "rootfs")

    assert fp.seals_of(vm.root_fd) & fp.F_SEAL_WRITE, "the root memfd is writable"
    assert not list(
        vm.chroot.glob("*.squashfs")
    ), "a rootfs image was staged in the jail"
    inherited = os.stat(f"/proc/{vm.pid}/fd/{fp.ROOT_FILENO}")
    supplied = os.fstat(vm.root_fd)
    assert (inherited.st_dev, inherited.st_ino) == (
        supplied.st_dev,
        supplied.st_ino,
    ), "Firecracker fd 4 is not the supplied root memfd"


def test_bootstrap_drive_is_served_from_the_sealed_memfd(farplane_factory):
    """The bootstrap device comes from fd 5 and transfers its bytes to the guest."""
    vm = farplane_factory()
    vm.bootstrap_file = vm.rootfs
    vm.spawn(fc_args=("--metrics-path", "fc.ndjson"))
    pagemaster = vm.start_pagemaster()
    vm.configure(
        boot_args=(
            "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0"
            " cryptomgr.notests pci=off root=/dev/vdb ro"
        )
    )
    vm.api.drive.put(
        drive_id="bootstrap",
        fd=fp.BOOTSTRAP_FILENO,
        is_root_device=False,
        is_read_only=True,
    )
    vm.start()
    pagemaster.wait_ready()
    vm.api.vm.patch(state="Resumed")
    wait_for_block_read(vm, "bootstrap")

    assert (
        fp.seals_of(vm.bootstrap_fd) & fp.F_SEAL_WRITE
    ), "the bootstrap memfd is writable"
    inherited = os.stat(f"/proc/{vm.pid}/fd/{fp.BOOTSTRAP_FILENO}")
    supplied = os.fstat(vm.bootstrap_fd)
    assert (inherited.st_dev, inherited.st_ino) == (
        supplied.st_dev,
        supplied.st_ino,
    ), "Firecracker fd 5 is not the supplied bootstrap memfd"


def test_bootstrap_fd_is_closed_when_not_handed_to_the_jailer(farplane_factory):
    """An unsupplied bootstrap object cannot be selected through a reused fd number."""
    vm = farplane_factory()
    vm.bootstrap_file = vm.rootfs
    supplied = vm.open_bootstrap_memfd()
    supplied_identity = os.fstat(supplied)
    vm.bootstrap_file = None
    boot(vm)

    try:
        inherited = os.stat(f"/proc/{vm.pid}/fd/{fp.BOOTSTRAP_FILENO}")
    except FileNotFoundError:
        pass
    else:
        assert (inherited.st_dev, inherited.st_ino) != (
            supplied_identity.st_dev,
            supplied_identity.st_ino,
        ), "the jailer handed Firecracker the bootstrap object it was told to omit"

    response = raw(
        vm.api,
        "PUT",
        "/drives/bootstrap",
        {
            "drive_id": "bootstrap",
            "fd": fp.BOOTSTRAP_FILENO,
            "is_root_device": False,
            "is_read_only": True,
        },
    )
    assert response.status_code == 400, response.text


def test_api_refuses_bootstrap_fd_without_the_bootstrap_memfd(farplane_factory):
    """fd 5 cannot configure a drive when the jailer did not receive it."""
    vm = farplane_factory()
    boot(vm)

    response = raw(
        vm.api,
        "PUT",
        "/drives/bootstrap",
        {
            "drive_id": "bootstrap",
            "fd": fp.BOOTSTRAP_FILENO,
            "is_root_device": False,
            "is_read_only": True,
        },
    )
    assert response.status_code == 400, response.text


@pytest.mark.parametrize(
    "descriptor,flaw,expected",
    [
        ("root", "writable", "--root-fd must be opened O_RDONLY"),
        (
            "root",
            "unsealed",
            "--root-fd is missing the write, grow, shrink or seal memfd seal",
        ),
        ("root", "empty", "--root-fd must have a nonzero size"),
        ("root", "not_regular", "--root-fd must be a regular file"),
        ("bootstrap", "writable", "--bootstrap-fd must be opened O_RDONLY"),
        (
            "bootstrap",
            "unsealed",
            "--bootstrap-fd is missing the write, grow, shrink or seal memfd seal",
        ),
        ("bootstrap", "empty", "--bootstrap-fd must have a nonzero size"),
        ("bootstrap", "not_regular", "--bootstrap-fd must be a regular file"),
        (
            "root",
            "regular_writable_mode",
            "--root-fd must not have any write permission bit set",
        ),
        (
            "root",
            "regular_jail_owned",
            "--root-fd must not be owned by the jailed uid",
        ),
        ("root", "regular_o_path", "--root-fd must be opened O_RDONLY"),
        (
            "bootstrap",
            "regular_writable_mode",
            "--bootstrap-fd must not have any write permission bit set",
        ),
    ],
)
def test_jailer_refuses_a_bad_block_fd(farplane_factory, descriptor, flaw, expected):
    """Every root and bootstrap descriptor precondition is enforced before the jail is built."""
    vm = farplane_factory(f"{descriptor}fd-{flaw}")
    open_memfd = vm.open_root_memfd if descriptor == "root" else vm.open_bootstrap_memfd
    if flaw.startswith("regular_"):
        flaws = {
            "regular_writable_mode": {"mode": 0o644},
            "regular_jail_owned": {"owner": vm.uid},
            "regular_o_path": {"open_flags": os.O_PATH},
        }
        # Mode and ownership belong to the regular-file arm of the contract, which is reached only
        # off a sealing filesystem: `open_private_image_file` stages the image where an inode
        # refuses `F_GET_SEALS`, or fails. The access mode is checked before either arm.
        block_fd = vm.open_private_image_file(descriptor, **flaws[flaw])
    elif flaw == "writable":
        block_fd = open_memfd(size=PAGE, read_only=False)
    elif flaw == "unsealed":
        block_fd = open_memfd(size=PAGE, seals=fp.F_SEAL_GROW)
    elif flaw == "empty":
        block_fd = open_memfd(size=0)
    else:
        # A directory is never a regular file, whatever the host filesystem under the jail
        # happens to be.
        vm.chroot_base.mkdir(parents=True, exist_ok=True)
        block_fd = os.open(vm.chroot_base, os.O_RDONLY | os.O_DIRECTORY)
        if descriptor == "root":
            vm.root_fd = block_fd
        else:
            vm.bootstrap_fd = block_fd

    vm.spawn(**{f"{descriptor}_fd": block_fd}, wait=False)
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
    root_base = vm.open_root_memfd()
    bootstrap_base = vm.open_root_memfd()
    root_spares = [os.dup(root_base) for _ in range(8)]
    bootstrap_spares = [os.dup(bootstrap_base) for _ in range(8)]
    root_high = next(fd for fd in root_spares if fd > fp.BOOTSTRAP_FILENO)
    bootstrap_high = next(fd for fd in bootstrap_spares if fd > fp.BOOTSTRAP_FILENO)
    for fd in [root_base] + [fd for fd in root_spares if fd != root_high]:
        os.close(fd)
    for fd in [bootstrap_base] + [
        fd for fd in bootstrap_spares if fd != bootstrap_high
    ]:
        os.close(fd)
    vm.root_fd = root_high
    vm.bootstrap_fd = bootstrap_high

    vm.spawn(root_fd=root_high, bootstrap_fd=bootstrap_high)
    pagemaster = vm.start_pagemaster()
    vm.configure()
    vm.start()
    pagemaster.wait_ready()
    vm.api.vm.patch(state="Resumed")

    device = f"/proc/{vm.pid}/fd/{fp.UFFD_DEVICE_FILENO}"
    root = f"/proc/{vm.pid}/fd/{fp.ROOT_FILENO}"
    bootstrap = f"/proc/{vm.pid}/fd/{fp.BOOTSTRAP_FILENO}"
    assert os.readlink(device) == str(fp.DEV_USERFAULTFD)
    assert os.stat(device).st_rdev == fp.DEV_USERFAULTFD.stat().st_rdev
    assert os.readlink(root).startswith("/memfd:rootfs")
    assert os.readlink(bootstrap).startswith("/memfd:rootfs")
    assert os.stat(root).st_ino != os.stat(bootstrap).st_ino

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
    assert cold["source_commit"], "GET / reported no source commit"

    vm.configure()
    vm.start()
    pagemaster.wait_ready()
    vm.api.vm.patch(state="Resumed")

    running = vm.farplane_state()
    assert running["backend_state"] == "ready"
    assert running["vcpus"] == "running"
    assert running["capture_buffers_armed"] is False
    assert running["source_commit"] == cold["source_commit"]

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
    # Every observation resamples the backend, and the provenance of the running binary is not
    # something a state change can move.
    assert resumed["source_commit"] == cold["source_commit"]


def test_the_state_api_reports_the_binarys_own_source_commit(farplane_factory):
    """`GET /` names the commit this binary was built from, exactly as `--version` reports it."""
    vm = farplane_factory()
    version = utils.check_output(f"{vm.fc_binary} --version").stdout
    reported = [
        line.removeprefix("commit ").strip()
        for line in version.splitlines()
        if line.startswith("commit ")
    ]
    assert (
        len(reported) == 1
    ), f"--version printed {len(reported)} commit lines:\n{version}"

    # The description is answered before any memory channel exists, so the provenance is readable
    # without one.
    vm.spawn()

    source_commit = vm.farplane_state()["source_commit"]
    assert source_commit, "GET / reported an empty source commit"
    assert source_commit == reported[0], "the state API and --version disagree"
    # An authoritative build compiles an extraction of a clean commit and the release gate requires
    # exactly that commit. A development tree may carry changes no commit names, or no checkout at
    # all, and the build script says so rather than naming a commit the bytes do not carry.
    assert re.fullmatch(r"[0-9a-f]{40}(-dirty)?|unknown", source_commit), source_commit
