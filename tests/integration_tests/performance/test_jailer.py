# Copyright 2025 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Performance benchmark for the jailer."""

import os
import shutil
import subprocess
from concurrent.futures import ProcessPoolExecutor

import pytest

from framework import utils
from framework.jailer import DEFAULT_CHROOT_PATH, JailerContext
from framework.properties import global_props
from host_tools.farplane import PAGE_SIZE, ROOT_SEALS, sealed_memfd


def setup_bind_mounts(tmp_path, n):
    """
    Create bind mount points. The exact location of them
    does not matter, they just need to exist.
    """
    mounts_paths = tmp_path / "mounts"
    os.makedirs(mounts_paths)
    for m in range(n):
        mount_path = f"{mounts_paths}/mount{m}"
        os.makedirs(mount_path)
        utils.check_output(f"mount --bind {mount_path} {mount_path}")


def clean_up_mounts(tmp_path):
    """Cleanup mounts and jailer dirs"""
    mounts_paths = tmp_path / "mounts"
    for d in os.listdir(mounts_paths):
        utils.check_output(f"umount {mounts_paths}/{d}")


def time_jailer(argv):
    """Run one jailer with the root memfd it renumbers, returning the timestamps it printed."""
    root_fd = sealed_memfd("rootfs", PAGE_SIZE, seals=ROOT_SEALS)
    try:
        return subprocess.run(
            [*argv, "--root-fd", str(root_fd)],
            capture_output=True,
            check=True,
            pass_fds=(root_fd,),
            text=True,
        ).stdout
    finally:
        os.close(root_fd)


@pytest.mark.nonci
@pytest.mark.parametrize("parallel", [1, 5, 10])
@pytest.mark.parametrize("mounts", [0, 100, 300, 500])
def test_jailer_startup(
    jailer_time_bin, tmp_path, microvm_factory, parallel, mounts, metrics
):
    """
    Test the overhead of jailer startup without and with bind mounts
    with different parallelism options.
    """

    jailer_binary = microvm_factory.jailer_binary_path

    setup_bind_mounts(tmp_path, mounts)

    metrics.set_dimensions(
        {
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": f"linux-{global_props.host_linux_version}",
            "performance_test": "test_jailer_startup",
            "parallel": str(parallel),
            "mounts": str(mounts),
        }
    )

    cmds = []
    for i in range(500):
        jailer = JailerContext(
            jailer_id=f"fakefc{i}",
            exec_file=jailer_time_bin,
        )
        jailer.setup()

        cmd = [str(jailer_binary), *jailer.construct_param_list()]
        cmds.append(cmd)

    with ProcessPoolExecutor(max_workers=parallel) as executor:
        for stdout in executor.map(time_jailer, cmds):
            end_time, start_time = stdout.split()
            metrics.put_metric(
                "startup",
                int(end_time) - int(start_time),
                unit="Microseconds",
            )

    clean_up_mounts(tmp_path)
    shutil.rmtree(DEFAULT_CHROOT_PATH)
