# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that verify the jailer's behavior."""

import os
import resource
import stat
from pathlib import Path

import pytest

from framework.jailer import JailerContext

# These are the permissions that all files/dirs inside the jailer have.
REG_PERMS = (
    stat.S_IRUSR
    | stat.S_IWUSR
    | stat.S_IXUSR
    | stat.S_IRGRP
    | stat.S_IXGRP
    | stat.S_IROTH
    | stat.S_IXOTH
)
DIR_STATS = stat.S_IFDIR | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
FILE_STATS = stat.S_IFREG | REG_PERMS
SOCK_STATS = stat.S_IFSOCK | REG_PERMS
# These are the stats of the devices created by tha jailer.
CHAR_STATS = stat.S_IFCHR | stat.S_IRUSR | stat.S_IWUSR
# Limit on file size in bytes.
FSIZE = 2097151
# Limit on number of file descriptors.
NOFILE = 1024
# Resource limits to be set by the jailer.
RESOURCE_LIMITS = [
    "no-file={}".format(NOFILE),
    "fsize={}".format(FSIZE),
]


def check_stats(filepath, stats, uid, gid):
    """Assert on uid, gid and expected stats for the given path."""
    st = os.stat(filepath)

    assert st.st_gid == gid
    assert st.st_uid == uid
    assert st.st_mode ^ stats == 0


def test_empty_jailer_id(uvm_plain):
    """
    Test that the jailer ID cannot be empty.
    """
    test_microvm = uvm_plain

    # Set the jailer ID to None.
    test_microvm.jailer = JailerContext(
        jailer_id="",
        exec_file=test_microvm.fc_binary_path,
    )

    # If the exception is not thrown, it means that Firecracker was
    # started successfully, hence there's a bug in the code due to which
    # we can set an empty ID.
    with pytest.raises(
        ChildProcessError,
        match=r"Invalid instance ID: Invalid len \(0\);  the length must be between 1 and 64",
    ):
        test_microvm.spawn()


def test_exec_file_not_exist(uvm_plain, tmp_path):
    """
    Test the jailer option `--exec-file`
    """
    test_microvm = uvm_plain

    # Error case 1: No such file exists
    pseudo_exec_file_path = tmp_path / "pseudo_firecracker_exec_file"
    fc_dir = Path("/srv/jailer") / pseudo_exec_file_path.name / test_microvm.id
    fc_dir.mkdir(parents=True, exist_ok=True)
    test_microvm.jailer.exec_file = pseudo_exec_file_path

    with pytest.raises(
        Exception,
        match=rf"Failed to canonicalize path {pseudo_exec_file_path}:"
        rf" No such file or directory \(os error 2\)",
    ):
        test_microvm.spawn()

    # Error case 2: Not a file
    pseudo_exec_dir_path = tmp_path / "firecracker_test_dir"
    pseudo_exec_dir_path.mkdir()
    fc_dir = Path("/srv/jailer") / pseudo_exec_dir_path.name / test_microvm.id
    fc_dir.mkdir(parents=True, exist_ok=True)
    test_microvm.jailer.exec_file = pseudo_exec_dir_path

    with pytest.raises(
        Exception,
        match=rf"{pseudo_exec_dir_path} is not a file",
    ):
        test_microvm.spawn()


def test_exec_destination_path_is_symlink(uvm_plain):
    """
    Test the jailer correctly refuses to copy binary into symlink
    """
    test_microvm = uvm_plain

    firecracker_root_dir = Path(test_microvm.chroot())
    firecracker_bin_path = firecracker_root_dir / "firecracker"
    dummy_path = Path("/srv/dummy")
    dummy_path.unlink(missing_ok=True)
    dummy_path.touch()
    firecracker_bin_path.symlink_to(dummy_path)
    with pytest.raises(
        Exception,
        match=f"Failed to open {firecracker_bin_path}",
    ):
        test_microvm.spawn()


def test_exec_destination_path_is_hardlink(uvm_plain):
    """
    Test the jailer correctly refuses to copy binary into hardlink
    """
    test_microvm = uvm_plain

    firecracker_root_dir = Path(test_microvm.chroot())
    firecracker_bin_path = firecracker_root_dir / "firecracker"
    dummy_path = Path("/srv/dummy")
    dummy_path.unlink(missing_ok=True)
    dummy_path.touch()
    firecracker_bin_path.hardlink_to(dummy_path)
    with pytest.raises(
        Exception,
        match=f"Detected hard link at: {firecracker_bin_path}",
    ):
        test_microvm.spawn()


def test_default_chroot_hierarchy(uvm_plain):
    """
    Test the folder hierarchy created by default by the jailer.
    """
    test_microvm = uvm_plain

    test_microvm.spawn()

    # We do checks for all the things inside the chroot that the jailer crates
    # by default.
    check_stats(
        test_microvm.jailer.chroot_path(),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/net"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "run"),
        DIR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/net/tun"),
        CHAR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "dev/kvm"),
        CHAR_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )
    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "firecracker"),
        FILE_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )


def test_arbitrary_usocket_location(uvm_plain):
    """
    Test arbitrary location scenario for the api socket.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.extra_args = {"api-sock": "api.socket"}

    test_microvm.spawn(serial_out_path=None)

    check_stats(
        os.path.join(test_microvm.jailer.chroot_path(), "api.socket"),
        SOCK_STATS,
        test_microvm.jailer.uid,
        test_microvm.jailer.gid,
    )


def check_limits(pid, no_file, fsize):
    """Verify resource limits against expected values."""
    # Fetch firecracker process limits for number of open fds
    soft, hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    assert soft == no_file
    assert hard == no_file

    # Fetch firecracker process limits for maximum file size
    soft, hard = resource.prlimit(pid, resource.RLIMIT_FSIZE)
    assert soft == fsize
    assert hard == fsize


def test_args_default_resource_limits(uvm_plain):
    """
    Test the default resource limits are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()
    # Get firecracker's PID
    pid = test_microvm.firecracker_pid
    assert pid != 0

    # Fetch firecracker process limits for number of open fds
    soft, hard = resource.prlimit(pid, resource.RLIMIT_NOFILE)
    # Check that the default limit was set.
    assert soft == 2048
    assert hard == 2048

    # Fetch firecracker process limits for number of open fds
    soft, hard = resource.prlimit(pid, resource.RLIMIT_FSIZE)
    # Check that no limit was set
    assert soft == -1
    assert hard == -1


def test_args_resource_limits(uvm_plain):
    """
    Test the resource limits are correctly set by the jailer.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = RESOURCE_LIMITS
    test_microvm.spawn()
    # Get firecracker's PID
    pid = test_microvm.firecracker_pid
    assert pid != 0

    # Check limit values were correctly set.
    check_limits(pid, NOFILE, FSIZE)


def test_positive_file_size_limit(uvm_plain):
    """
    Test creating vm succeeds when memory size is under `fsize` limit.
    """

    vm_mem_size = 128
    jail_limit = (vm_mem_size + 1) << 20

    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = [f"fsize={jail_limit}"]
    test_microvm.spawn()
    test_microvm.basic_config(mem_size_mib=vm_mem_size)

    # Attempt to start a vm.
    test_microvm.start()


def test_negative_no_file_limit(uvm_plain):
    """
    Test microVM is killed when exceeding `no-file` limit.
    """
    test_microvm = uvm_plain
    test_microvm.jailer.resource_limits = ["no-file=3"]

    # pylint: disable=W0703
    try:
        test_microvm.spawn()
    except ChildProcessError as error:
        assert "No file descriptors available (os error 24)" in str(error)

        test_microvm.mark_killed()
    else:
        assert False, "Negative test failed"


def test_firecracker_kill_by_pid(uvm_plain):
    """
    Test that Firecracker can be killed by its pid.
    """
    microvm = uvm_plain
    microvm.spawn()
    microvm.basic_config()
    microvm.add_net_iface()
    microvm.start()

    microvm.kill()
