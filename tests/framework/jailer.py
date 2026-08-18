# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Define a class for creating the jailed context."""

import os
import shutil
import stat
from pathlib import Path

from framework import defs

# Default name for the socket used for API calls.
DEFAULT_USOCKET_NAME = "run/firecracker.socket"
# The default location for the chroot.
DEFAULT_CHROOT_PATH = f"{defs.DEFAULT_TEST_SESSION_ROOT_PATH}/jailer"


class JailerContext:
    """Represents jailer configuration and contains jailer helper functions.

    Each microvm will have a jailer configuration associated with it.
    """

    # Keep in sync with parameters from code base.
    jailer_id = None
    exec_file = None
    uid = None
    gid = None
    chroot_base = None
    extra_args = None
    api_socket_name = None
    root_fd = None
    cgroup_join = None
    resource_limits = None

    def __init__(
        self,
        jailer_id,
        exec_file,
        uid=1234,
        gid=1234,
        chroot_base=DEFAULT_CHROOT_PATH,
        netns=None,
        root_fd=None,
        cgroup_join=None,
        resource_limits=None,
        **extra_args,
    ):
        """Set up jailer fields.

        This plays the role of a default constructor as it populates
        the jailer's fields with some default values. Each field can be
        further adjusted by each test even with None values.

        `root_fd` is the number of the descriptor holding the sealed root block
        device image. The process launching the jailer must let the child
        inherit it, since the jailer renumbers it for the exec'd Firecracker.

        `cgroup_join` is the absolute cgroupfs path of a pre-created leaf
        cgroup. The jailer only writes its pid there; it creates no cgroup.
        """
        self.jailer_id = jailer_id
        assert jailer_id is not None
        self.exec_file = exec_file
        self.uid = uid
        self.gid = gid
        self.chroot_base = Path(chroot_base)
        self.netns = netns
        self.extra_args = extra_args
        self.api_socket_name = DEFAULT_USOCKET_NAME
        self.root_fd = root_fd
        self.cgroup_join = cgroup_join
        self.resource_limits = resource_limits
        assert chroot_base is not None

    # Disabling 'too-many-branches' warning for this function as it needs to
    # check every argument, so the number of branches will increase
    # with every new argument.
    # pylint: disable=too-many-branches
    def construct_param_list(self):
        """Create the list of parameters we want the jailer to start with.

        We want to be able to vary any parameter even the required ones as we
        might want to add integration tests that validate the enforcement of
        mandatory arguments.
        """
        jailer_param_list = []

        # Pretty please, try to keep the same order as in the code base.
        if self.jailer_id is not None:
            jailer_param_list.extend(["--id", str(self.jailer_id)])
        if self.exec_file is not None:
            jailer_param_list.extend(["--exec-file", str(self.exec_file)])
        if self.uid is not None:
            jailer_param_list.extend(["--uid", str(self.uid)])
        if self.gid is not None:
            jailer_param_list.extend(["--gid", str(self.gid)])
        if self.root_fd is not None:
            jailer_param_list.extend(["--root-fd", str(self.root_fd)])
        if self.chroot_base is not None:
            jailer_param_list.extend(["--chroot-base-dir", str(self.chroot_base)])
        if self.netns is not None:
            jailer_param_list.extend(["--netns", str(self.netns.path)])
        if self.cgroup_join is not None:
            jailer_param_list.extend(["--cgroup-join", str(self.cgroup_join)])
        if self.resource_limits is not None:
            for limit in self.resource_limits:
                jailer_param_list.extend(["--resource-limit", str(limit)])
        # applying necessary extra args if needed
        if len(self.extra_args) > 0:
            jailer_param_list.append("--")
            for key, value in self.extra_args.items():
                jailer_param_list.append("--{}".format(key))
                if value is not None:
                    jailer_param_list.append(value)
                    if key == "api-sock":
                        self.api_socket_name = value
        return jailer_param_list

    # pylint: enable=too-many-branches

    def chroot_base_with_id(self):
        """Return the MicroVM chroot base + MicroVM ID."""
        return self.chroot_base / Path(self.exec_file).name / self.jailer_id

    def api_socket_path(self):
        """Return the MicroVM API socket path."""
        return os.path.join(self.chroot_path(), self.api_socket_name)

    def chroot_path(self):
        """Return the MicroVM chroot path."""
        return os.path.join(self.chroot_base_with_id(), "root")

    def jailed_path(self, file_path, create=False, subdir="."):
        """Create a hard link or block special device owned by uid:gid.

        Create a hard link or block special device from the specified file,
        changes the owner to uid:gid, and returns a path to the file which is
        valid within the jail.
        """
        file_path = Path(file_path)
        chroot_path = Path(self.chroot_path())
        global_p = chroot_path / subdir / file_path.name
        global_p.parent.mkdir(parents=True, exist_ok=True)
        jailed_p = Path("/") / subdir / file_path.name
        if create:
            stat_src = file_path.stat()
            if file_path.is_block_device():
                perms = stat.S_IRUSR | stat.S_IWUSR
                os.mknod(global_p, mode=stat.S_IFBLK | perms, device=stat_src.st_rdev)
            else:
                stat_dst = chroot_path.stat()
                if stat_src.st_dev == stat_dst.st_dev:
                    # if they are in the same device, hardlink
                    global_p.unlink(missing_ok=True)
                    global_p.hardlink_to(file_path)
                else:
                    # otherwise, copy
                    shutil.copyfile(file_path, global_p)

            os.chown(global_p, self.uid, self.gid)
        return str(jailed_p)

    def setup(self):
        """Set up this jailer context."""
        os.makedirs(self.chroot_base, exist_ok=True)

    @property
    def pid_file(self):
        """Return the PID file of the jailed process"""
        return Path(self.chroot_path()) / (self.exec_file.name + ".pid")
