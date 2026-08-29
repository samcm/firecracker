# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Classes for working with microVMs.

This module defines `Microvm`, which can be used to create, test drive, and
destroy microvms.

- Use the Firecracker Open API spec to populate Microvm API resource URLs.
"""

# pylint:disable=too-many-lines

import json
import logging
import os
import re
import select
import shutil
import signal
import subprocess
import threading
import time
import tty
import uuid
from collections import namedtuple
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Optional

import psutil
from tenacity import Retrying, retry, stop_after_attempt, wait_fixed

import host_tools.network as net_tools
from framework import utils
from framework.defs import MAX_API_CALL_DURATION_MS
from framework.guest import GuestDistro
from framework.http_api import Api
from framework.jailer import JailerContext
from framework.microvm_helpers import MicrovmHelpers
from framework.properties import global_props
from framework.utils_cpu_templates import get_cpu_template_name
from host_tools.farplane import ROOT_FILENO, Pagemaster, memfd_from_file
from host_tools.fcmetrics import FCMetricsMonitor
from host_tools.memory import MemoryMonitor

LOG = logging.getLogger("microvm")


# pylint: disable=R0904
class Microvm:
    """Class to represent a Firecracker microvm.

    A microvm is described by a unique identifier, a path to all the resources
    it needs in order to be able to start and the binaries used to spawn it.
    Besides keeping track of microvm resources and exposing microvm API
    methods, `spawn()` and `kill()` can be used to start/end the microvm
    process.
    """

    MEM_SOCKET_NAME = "farplane.sock"

    def __init__(
        self,
        microvm_id: str,
        fc_binary_path: Path,
        jailer_binary_path: Path,
        netns: net_tools.NetNs,
        monitor_memory: bool = True,
        jailer_kwargs: Optional[dict] = None,
        numa_node=None,
        custom_cpu_template: Path = None,
        pci: bool = False,
    ):
        """Set up microVM attributes, paths, and data structures."""
        # pylint: disable=too-many-statements
        # Unique identifier for this machine.
        assert microvm_id is not None
        self._microvm_id = microvm_id

        self.kernel_file = None
        self.rootfs_file = None
        self.bootstrap_file = None
        self.distro = None
        self.ssh_key = None
        self.initrd_file = None
        self.boot_args = None

        self.fc_binary_path = Path(fc_binary_path)
        assert fc_binary_path.exists()
        self.jailer_binary_path = Path(jailer_binary_path)
        assert jailer_binary_path.exists()

        jailer_kwargs = jailer_kwargs or {}
        self.netns = netns
        # Create the jailer context associated with this microvm.
        self.jailer = JailerContext(
            jailer_id=self._microvm_id,
            exec_file=self.fc_binary_path,
            netns=netns,
            **jailer_kwargs,
        )

        self.pci_enabled = pci
        if pci:
            self.jailer.extra_args["enable-pci"] = None

        # Copy the /etc/localtime file in the jailer root
        self.jailer.jailed_path("/etc/localtime", subdir="etc")

        self._jailer_proc = None
        self._console_fd = None
        self.console_log = None
        self.pagemaster = None
        self._root_fd = None
        self._bootstrap_fd = None

        self.time_api_requests = global_props.host_linux_version != "6.1"
        # disable the HTTP API timings as they cause a lot of false positives
        if int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", 1)) > 1:
            self.time_api_requests = False

        self.monitors = []
        self.memory_monitor = None
        if monitor_memory:
            self.memory_monitor = MemoryMonitor(self)
            self.monitors.append(self.memory_monitor)

        self.api = None
        self.log_file = None
        self.serial_out_path = None
        self.metrics_file = None
        self._spawned = False
        self._killed = False

        # device dictionaries
        self.iface = {}
        self.disks = {}
        self.vcpus_count = None
        self.mem_size_bytes = None
        self.cpu_template_name = "None"
        # The given custom CPU template will be set in basic_config() but could
        # be overwritten via set_cpu_template().
        self.custom_cpu_template = custom_cpu_template

        self._connections = []

        self._pre_cmd = []
        if numa_node:
            node_str = str(numa_node)
            self.add_pre_cmd(["numactl", "-N", node_str, "-m", node_str])

        self.help = MicrovmHelpers(self)

        self.gdb_socket = None

    def __repr__(self):
        return f"<Microvm id={self.id}>"

    def mark_killed(self):
        """
        Marks this `Microvm` as killed, meaning test tear down should not try to kill it

        raises an exception if the Firecracker process managing this VM is not actually dead
        """
        if self.firecracker_pid is not None:
            utils.wait_process_termination(self.firecracker_pid)

        self._killed = True

    def kill(self, might_be_dead=False):
        """All clean up associated with this microVM should go here."""
        try:
            self._kill(might_be_dead)
        finally:
            self._release_resources()

    def _kill(self, might_be_dead):
        """Stop the microVM and assert that nothing survived it."""
        # pylint: disable=subprocess-run-check
        # if it was already killed, return
        if self._killed:
            return

        # Stop any registered monitors
        for monitor in self.monitors:
            monitor.stop()

        # Kill all background SSH connections
        for connection in self._connections:
            connection.close(strict=not might_be_dead)

        assert (
            "Shutting down VM after intercepting signal" not in self.log_data
            or might_be_dead
        ), self.log_data

        # Kill Firecracker. The jailer exec'd into it, so the pid in the pid file
        # is also the pid of our direct child unless a `_pre_cmd` wrapper forked.
        if self.firecracker_pid:
            try:
                os.kill(self.firecracker_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                if not might_be_dead:
                    self._dump_debug_information(
                        "Failed to kill Firecracker Process. Did it already die?"
                    )
                    raise

        if self._jailer_proc is not None:
            if self._jailer_proc.poll() is None:
                self._jailer_proc.kill()
            try:
                self._jailer_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                utils.dump_proc_state(self._jailer_proc.pid)
                raise
            self._jailer_proc = None

        if self._spawned and self.firecracker_pid:
            try:
                utils.wait_process_termination(self.firecracker_pid)
            except TimeoutError:
                utils.dump_proc_state(self.firecracker_pid)
                raise

        # if microvm was spawned then check if it gets killed
        if self._spawned:
            # The following logic guards us against the case where `firecracker_pid` for some
            # reason is the wrong PID, e.g. this is a regression test for
            # https://github.com/firecracker-microvm/firecracker/pull/4442/commits/d63eb7a65ffaaae0409d15ed55d99ecbd29bc572

            # filter ps results for the jailer's unique id
            _, stdout, stderr = utils.run_cmd(
                f"ps ax -o pid,cmd -ww | grep {self.jailer.jailer_id}"
            )

            assert not stderr, f"error querying processes using `ps`: {stderr}"

            offenders = []
            for proc in stdout.splitlines():
                _, cmd = proc.lower().split(maxsplit=1)
                if "firecracker" in cmd:
                    offenders.append(proc)

            # make sure firecracker was killed
            assert not offenders, (
                f"Firecracker reported its pid {self.firecracker_pid}, which was killed, but there still exist processes using the supposedly dead Firecracker's jailer_id: \n"
                + "\n".join(offenders)
            )

        if self.api:
            self.api.session.close()

        # Mark the microVM as not spawned, so we avoid trying to kill twice.
        self._spawned = False
        self._killed = True

        if self.time_api_requests:
            self._validate_api_response_times()

        if self.memory_monitor:
            self.memory_monitor.check_samples()

    def _release_resources(self):
        """Stop serving guest memory and drop the descriptors handed to the jail."""
        if self.pagemaster is not None:
            self.pagemaster.close()
            self.pagemaster = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None
        if self._bootstrap_fd is not None:
            os.close(self._bootstrap_fd)
            self._bootstrap_fd = None
        if self._console_fd is not None:
            os.close(self._console_fd)
            self._console_fd = None

    def _validate_api_response_times(self):
        """
        Parses the firecracker logs for information regarding api server request processing times, and asserts they
        are within acceptable bounds.
        """
        api_request_regex = re.compile(
            r"\] The API server received a (?P<method>\w+) request on \"(?P<url>(/(\w|-)*)+)\"( with body (?P<body>.*))?\."
        )
        api_request_times_regex = re.compile(
            r"\] Total previous API call duration: (?P<execution_time>\d+) us.$"
        )

        # Note: Processing of api requests is synchronous, so these messages cannot be torn by concurrency effects
        log_lines = self.log_data.split("\n")

        ApiCall = namedtuple("ApiCall", "method url body")

        current_call = None

        for log_line in log_lines:
            match = api_request_regex.search(log_line)

            if match:
                if current_call is not None:
                    raise Exception(
                        f"API call duration log entry for {current_call.method} {current_call.url} with body {current_call.body} is missing!"
                    )

                current_call = ApiCall(
                    match.group("method"), match.group("url"), match.group("body")
                )

            match = api_request_times_regex.search(log_line)

            if match:
                if current_call is None:
                    raise Exception(
                        "Got API call duration log entry before request entry"
                    )

                if current_call.url != "/snapshot/load":
                    exec_time = float(match.group("execution_time")) / 1000.0

                    assert (
                        exec_time <= MAX_API_CALL_DURATION_MS
                    ), f"{current_call.method} {current_call.url} API call exceeded maximum duration: {exec_time} ms. Body: {current_call.body}"

                current_call = None

    @property
    def firecracker_version(self):
        """Return the version of the Firecracker executable."""
        _, stdout, _ = utils.check_output(f"{self.fc_binary_path} --version")
        return re.match(r"^Firecracker v(.+)", stdout.partition("\n")[0]).group(1)

    @property
    def path(self):
        """Return the path on disk used that represents this microVM."""
        return self.jailer.chroot_base_with_id()

    # some functions use this
    fsfiles = path

    @property
    def id(self):
        """Return the unique identifier of this microVM."""
        return self._microvm_id

    @property
    def log_data(self):
        """Return the log data."""
        if self.log_file is None:
            return ""
        return self.log_file.read_text()

    @property
    def console_data(self):
        """Return everything the microVM wrote to its stdio."""
        if self.console_log is None:
            return ""
        return self.console_log.read_text(errors="replace")

    @property
    def state(self):
        """Get the InstanceInfo property and return the state field."""
        return self.api.describe.get().json()["state"]

    @cached_property
    def firecracker_pid(self):
        """Return Firecracker's PID

        Reads the pid from a file created by jailer.
        """
        if not self._spawned:
            return None

        # Read the PID from Firecracker's pidfile. Retry if
        # file doesn't exist yet, or doesn't yet contain an integer
        try:
            for attempt in Retrying(
                stop=stop_after_attempt(5),
                wait=wait_fixed(0.1),
                reraise=True,
            ):
                with attempt:
                    return int(self.jailer.pid_file.read_text(encoding="ascii"))
        except OSError:
            if self._jailer_proc is not None and self._jailer_proc.poll() is not None:
                # The jailer died before it could exec into Firecracker.
                return None
            raise

    @cached_property
    def ps(self):
        """Returns a handle to the psutil.Process for this VM"""
        return psutil.Process(self.firecracker_pid)

    @property
    def dimensions(self):
        """Gets a default set of cloudwatch dimensions describing the configuration of this microvm"""
        return {
            "instance": global_props.instance,
            "cpu_model": global_props.cpu_model,
            "host_kernel": f"linux-{global_props.host_linux_version}",
            "guest_kernel": self.kernel_file.stem[2:],
            "rootfs": self.rootfs_file.name,
            "vcpus": str(self.vcpus_count),
            "guest_memory": f"{self.mem_size_bytes / (1024 * 1024)}MB",
            "pci": f"{self.pci_enabled}",
        }

    @property
    def guest_kernel_version(self):
        """Get the guest kernel version from the filename

        It won't work if the file name does not like name-X.Y.Z
        """
        splits = self.kernel_file.name.split("-")
        if len(splits) < 2:
            return None
        return tuple(int(x) for x in splits[1].split("."))

    def get_metrics(self):
        """Return iterator to metric data points written by FC"""
        with self.metrics_file.open() as fd:
            for line in fd:
                if not line.endswith("}\n"):
                    LOG.warning("Line is not a proper JSON object. Partial write?")
                    continue
                yield json.loads(line)

    def get_all_metrics(self):
        """Return all metric data points written by FC."""
        return list(self.get_metrics())

    def flush_metrics(self):
        """Flush the microvm metrics and get the latest datapoint"""
        self.api.actions.put(action_type="FlushMetrics")
        # get the latest metrics
        return self.get_all_metrics()[-1]

    def create_jailed_resource(self, path):
        """Create a hard link to some resource inside this microvm."""
        return self.jailer.jailed_path(path, create=True)

    def get_jailed_resource(self, path):
        """Get the relative jailed path to a resource."""
        return self.jailer.jailed_path(path, create=False)

    def chroot(self):
        """Get the chroot of this microVM."""
        return self.jailer.chroot_path()

    def pin_vmm(self, cpu_id: int) -> bool:
        """Pin the firecracker process VMM thread to a cpu list."""
        if self.firecracker_pid:
            for thread_name, thread_pids in utils.get_threads(
                self.firecracker_pid
            ).items():
                # the firecracker thread should start with firecracker...
                if thread_name.startswith("firecracker"):
                    for pid in thread_pids:
                        utils.set_cpu_affinity(pid, [cpu_id])
                return True
        return False

    def pin_vcpu(self, vcpu_id: int, cpu_id: int):
        """Pin the firecracker vcpu thread to a cpu list."""
        if self.firecracker_pid:
            for thread in utils.get_threads(self.firecracker_pid)[f"fc_vcpu {vcpu_id}"]:
                utils.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def pin_api(self, cpu_id: int):
        """Pin the firecracker process API server thread to a cpu list."""
        if self.firecracker_pid:
            for thread in utils.get_threads(self.firecracker_pid)["fc_api"]:
                utils.set_cpu_affinity(thread, [cpu_id])
            return True
        return False

    def pin_threads(self, first_cpu):
        """
        Pins all microvm threads (VMM, API and vCPUs) to consecutive physical cpu core, starting with "first_cpu"

        Return next "free" cpu core.
        """
        for vcpu, pcpu in enumerate(range(first_cpu, first_cpu + self.vcpus_count)):
            assert self.pin_vcpu(
                vcpu, pcpu
            ), f"Failed to pin fc_vcpu {vcpu} thread to core {pcpu}."
        # The cores first_cpu,...,first_cpu + self.vcpus_count - 1 are assigned to the individual vCPU threads,
        # So the remaining two threads (VMM and API) get first_cpu + self.vcpus_count
        # and first_cpu + self.vcpus_count + 1
        assert self.pin_vmm(
            first_cpu + self.vcpus_count
        ), "Failed to pin firecracker thread."
        assert self.pin_api(
            first_cpu + self.vcpus_count + 1
        ), "Failed to pin fc_api thread."

        return first_cpu + self.vcpus_count + 2

    def add_pre_cmd(self, pre_cmd):
        """Prepends commands to the command line to launch the microVM

        For example, this can be used to pin the VM to a NUMA node or to trace the VM with strace.
        """
        self._pre_cmd = pre_cmd + self._pre_cmd

    def start_pagemaster(self):
        """Bind the memory channel inside the jail and start serving guest memory."""
        socket_path = Path(self.chroot()) / self.MEM_SOCKET_NAME
        socket_path.parent.mkdir(parents=True, exist_ok=True)
        pagemaster = Pagemaster(socket_path, markers=False)
        pagemaster.start()
        return pagemaster

    def _open_console(self):
        """Return a pty for the microVM stdio, drained into `console_log`.

        Firecracker's serial console is its stdio unless a `serial_out_path` is
        configured, so this is what `Serial` and `serial_input` talk to.
        """
        self._console_fd, slave = os.openpty()
        tty.setraw(slave)
        self.console_log = Path(self.path) / "console.log"
        threading.Thread(
            target=self._drain_console,
            args=(self._console_fd, self.console_log.open("wb", buffering=0)),
            name=f"console-{self.id}",
            daemon=True,
        ).start()
        return slave

    def _drain_console(self, fd, log):
        """Copy everything the microVM writes to its pty into `console_log`."""
        with log:
            while True:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    return
                if not data:
                    return
                log.write(data)

    def spawn(
        self,
        log_file="fc.log",
        serial_out_path="serial.log",
        log_level="Debug",
        log_show_level=False,
        log_show_origin=False,
        metrics_path="fc.ndjson",
        emit_metrics: bool = False,
        validate_api: bool = True,
    ):
        """Spawn the microVM.

        The root image and optional bootstrap image reach Firecracker as
        read-only descriptors the jailer renumbers to `ROOT_FILENO` and fd 5,
        and guest memory is served over the memory channel a `Pagemaster` binds
        inside the jail.
        """
        # pylint: disable=too-many-branches
        self.jailer.setup()
        self.api = Api(
            self.jailer.api_socket_path(),
            validate=validate_api,
            on_error=lambda verb, uri, err_msg: self._dump_debug_information(
                f"Error during {verb} {uri}: {err_msg}"
            ),
        )

        if log_file is not None:
            self.log_file = Path(self.path) / log_file
            self.log_file.touch()
            self.create_jailed_resource(self.log_file)
            # The default value for `level`, when configuring the logger via cmd
            # line, is `Info`. We set the level to `Debug` to also have the boot
            # time printed in the log.
            self.jailer.extra_args.update({"log-path": log_file, "level": log_level})
            if log_show_level:
                self.jailer.extra_args["show-level"] = None
            if log_show_origin:
                self.jailer.extra_args["show-log-origin"] = None

        if serial_out_path is not None:
            self.serial_out_path = Path(self.path) / serial_out_path
            self.serial_out_path.touch()
            self.create_jailed_resource(self.serial_out_path)

        if metrics_path is not None:
            self.metrics_file = Path(self.path) / metrics_path
            self.metrics_file.touch()
            self.create_jailed_resource(self.metrics_file)
            self.jailer.extra_args.update({"metrics-path": self.metrics_file.name})
        else:
            assert not emit_metrics

        if log_level != "Debug":
            # Checking the timings requires DEBUG level log messages
            self.time_api_requests = False

        assert self.rootfs_file is not None, "the jailer requires a root image"
        self._root_fd = memfd_from_file("rootfs", self.rootfs_file)
        self.jailer.root_fd = self._root_fd
        if self.bootstrap_file is not None:
            self._bootstrap_fd = memfd_from_file("bootstrap", self.bootstrap_file)
            self.jailer.bootstrap_fd = self._bootstrap_fd
        else:
            self.jailer.bootstrap_fd = None
        self.pagemaster = self.start_pagemaster()
        self.jailer.extra_args["farplane-mem-socket"] = f"/{self.MEM_SOCKET_NAME}"

        cmd = [
            *self._pre_cmd,
            str(self.jailer_binary_path),
            *self.jailer.construct_param_list(),
        ]

        # The jailer execs into Firecracker, so the root and optional bootstrap
        # descriptors have to survive the fork: `pass_fds` keeps exactly the
        # numbers `--root-fd` and `--bootstrap-fd` name open.
        console = self._open_console()
        self._jailer_proc = subprocess.Popen(
            cmd,
            stdin=console,
            stdout=console,
            stderr=console,
            pass_fds=tuple(
                fd for fd in (self._root_fd, self._bootstrap_fd) if fd is not None
            ),
        )
        os.close(console)

        self._spawned = True

        if emit_metrics:
            self.monitors.append(FCMetricsMonitor(self))

        # Ensure Firecracker is in as good a state as possible wrts guest
        # responsiveness / API availability.
        # If we are using a config file and it has a network device specified,
        # use SSH to wait until guest userspace is available. If we are
        # using the API, wait until the API socket file has been created, and
        # then until the log message indicating the API server has finished
        # initializing is printed (if logging is enabled).
        # If none of these apply, do a last ditch effort to make sure the
        # Firecracker process itself at least came up by checking
        # for the startup log message. Otherwise, you're on your own kid.
        if "config-file" in self.jailer.extra_args and self.iface:
            assert not serial_out_path
            self.wait_for_ssh_up()
        elif "no-api" not in self.jailer.extra_args:
            self._wait_for_api_socket()
            if self.log_file and log_level in ("Trace", "Debug", "Info"):
                self.check_log_message("API server started.")

            if serial_out_path is not None:
                self.api.serial.put(serial_out_path=serial_out_path)
        elif self.log_file and log_level in ("Trace", "Debug", "Info"):
            assert not serial_out_path
            self.check_log_message("Running Firecracker")

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def _wait_for_api_socket(self):
        """Wait until the API socket and chroot folder are available."""
        if self._jailer_proc.poll() is not None:
            raise ChildProcessError(
                f"the microVM exited with {self._jailer_proc.returncode} before its "
                f"API socket appeared:\n{self.console_data}"
            )

        # We expect the jailer to start within 80 ms. However, we wait for
        # 1 sec since we are rechecking the existence of the socket 5 times
        # and leave 0.2 delay between them.
        os.stat(self.jailer.api_socket_path())

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def check_log_message(self, message):
        """Wait until `message` appears in logging output."""
        assert (
            message in self.log_data
        ), f'Message ("{message}") not found in log data ("{self.log_data}").'

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def get_exit_code(self):
        """Get exit code from logging output"""
        exit_msg_pattern = (
            r"Firecracker exiting (with error|successfully). exit_code=(\d+)"
        )
        match = re.search(exit_msg_pattern, self.log_data)
        if match:
            exit_code = int(match.group(2))
            return exit_code
        raise AssertionError(f"unable to find exit code from the log: {self.log_data}")

    @retry(wait=wait_fixed(0.2), stop=stop_after_attempt(5), reraise=True)
    def check_any_log_message(self, messages):
        """Wait until any message in `messages` appears in logging output."""
        for message in messages:
            if message in self.log_data:
                return
        raise AssertionError(
            f"`{messages}` were not found in this log: {self.log_data}"
        )

    def serial_input(self, input_string):
        """Send a string to the Firecracker serial console."""
        os.write(self._console_fd, input_string.encode())

    def basic_config(
        self,
        vcpu_count: int = 2,
        smt: bool = None,
        mem_size_mib: int = 256,
        add_root_device: bool = True,
        boot_args: str = None,
        use_initrd: bool = False,
        rootfs_io_engine=None,
        cpu_template: Optional[str] = None,
        enable_entropy_device=False,
    ):
        """Shortcut for quickly configuring a microVM.

        It handles:
        - CPU and memory.
        - Kernel image (will load the one in the microVM allocated path).
        - Root File System (the read-only descriptor the jailer handed over).
        - Does not start the microvm.

        The function checks the response status code and asserts that
        the response is within the interval [200, 300).

        If boot_args is None, the default boot_args used in tests is
            reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 [pci=off]
        which differs from Firecracker's default only in the enabling of the serial console.
        Reference: file:../../src/vmm/src/vmm_config/boot_source.rs::DEFAULT_KERNEL_CMDLINE
        """
        self.api.machine_config.put(
            vcpu_count=vcpu_count,
            smt=smt,
            mem_size_mib=mem_size_mib,
        )
        self.vcpus_count = vcpu_count
        self.mem_size_bytes = mem_size_mib * 2**20

        if self.custom_cpu_template is not None:
            self.set_cpu_template(self.custom_cpu_template)

        if cpu_template is not None:
            self.set_cpu_template(cpu_template)

        if self.memory_monitor:
            self.memory_monitor.start()

        if boot_args is not None:
            self.boot_args = boot_args
        else:
            self.boot_args = "reboot=k panic=1 nomodule swiotlb=noforce console=ttyS0 cryptomgr.notests"
            if not self.pci_enabled:
                self.boot_args += " pci=off"
        boot_source_args = {
            "kernel_image_path": self.create_jailed_resource(self.kernel_file),
            "boot_args": self.boot_args,
        }

        if use_initrd and self.initrd_file is not None:
            boot_source_args.update(
                initrd_path=self.create_jailed_resource(self.initrd_file)
            )

        self.api.boot.put(**boot_source_args)

        if add_root_device:
            # The jailer placed the root image descriptor at `ROOT_FILENO`,
            # which Firecracker only accepts read-only.
            self.api.drive.put(
                drive_id="rootfs",
                fd=ROOT_FILENO,
                is_root_device=True,
                is_read_only=True,
                io_engine=rootfs_io_engine,
            )
            self.disks["rootfs"] = self.rootfs_file

        if enable_entropy_device:
            self.enable_entropy_device()

    def set_cpu_template(self, cpu_template):
        """Set guest CPU template."""
        self.cpu_template_name = get_cpu_template_name(cpu_template)
        if cpu_template is None:
            return
        # static CPU template
        if isinstance(cpu_template, str):
            self.api.machine_config.patch(cpu_template=cpu_template)
        # custom CPU template
        elif isinstance(cpu_template, dict):
            self.api.cpu_config.put(**cpu_template["template"])

    def add_net_iface(self, iface=None, api=True, **kwargs):
        """Add a network interface"""
        if iface is None:
            iface = net_tools.NetIfaceConfig.with_id(len(self.iface))
        tap = self.netns.add_tap(
            iface.tap_name, ip=f"{iface.host_ip}/{iface.netmask_len}"
        )
        self.iface[iface.dev_name] = {
            "iface": iface,
            "tap": tap,
        }

        # If api, call it... there may be cases when we don't want it, for
        # example during restore
        if api:
            self.api.network.put(
                iface_id=iface.dev_name,
                host_dev_name=iface.tap_name,
                guest_mac=iface.guest_mac,
                **kwargs,
            )

        return iface

    def start(self):
        """Start the microvm.

        This function validates that the microvm boot succeeds.
        """
        # Check that the VM has not started yet
        assert self.state == "Not started"

        self.api.actions.put(action_type="InstanceStart")

        # Booting builds guest memory over the memory channel, so surface any
        # failure the pagemaster hit while serving it.
        self.pagemaster.wait_ready()

        # Check that the VM has started
        assert self.state == "Running"

        if self.iface:
            self.wait_for_ssh_up()

    def pause(self):
        """Pauses the microVM"""
        self.api.vm.patch(state="Paused")

    def resume(self):
        """Resume the microVM"""
        self.api.vm.patch(state="Resumed")

    def enable_entropy_device(self):
        """Enable entropy device for microVM"""
        self.api.entropy.put()

    @lru_cache
    def ssh_iface(self, iface_idx=0):
        """Return a cached SSH connection on a given interface id."""
        guest_ip = list(self.iface.values())[iface_idx]["iface"].guest_ip
        self.ssh_key = Path(self.ssh_key)
        connection = net_tools.SSHConnection(
            netns=self.netns.id,
            ssh_key=self.ssh_key,
            user="root",
            host=guest_ip,
            control_path=Path(self.chroot()) / f"ssh-{iface_idx}.sock",
            on_error=lambda exc: self._dump_debug_information(
                f"Failure executing command via SSH in microVM: {exc}"
            ),
        )
        self._connections.append(connection)
        return connection

    @property
    def ssh(self):
        """Return a cached SSH connection on the 1st interface"""
        return self.ssh_iface(0)

    @property
    def thread_backtraces(self):
        """Return backtraces of all threads"""
        backtraces = []
        for thread_name, thread_pids in utils.get_threads(self.firecracker_pid).items():
            for pid in thread_pids:
                try:
                    stack = Path(f"/proc/{pid}/stack").read_text("UTF-8")
                except FileNotFoundError:
                    continue  # process might've gone away between get_threads() call and here

                backtraces.append(f"{thread_name} ({pid=}):\n{stack}")
        return "\n".join(backtraces)

    def _dump_debug_information(self, what: str):
        """
        Dumps debug information about this microvm

        Used for example when running a command inside the guest via `SSHConnection.check_output` fails.
        """
        LOG.error(what)
        LOG.error("Firecracker logs:\n%s", self.log_data)
        if not self._killed:
            LOG.error("Thread backtraces:\n%s", self.thread_backtraces)

    def wait_for_ssh_up(self):
        """Wait for guest running inside the microVM to come up and respond."""
        # Ensure that we have an initialized SSH connection to the guest that can
        # run commands. The actual connection retry loop happens in SSHConnection._init_connection
        _ = self.ssh_iface(0)

    def enable_gdb(self):
        """Enables GDB debugging"""
        self.gdb_socket = "gdb.socket"
        self.api.machine_config.patch(gdb_socket_path=self.gdb_socket)


class MicroVMFactory:
    """MicroVM factory"""

    def __init__(self, binary_path: Path, **kwargs):
        self.vms = []
        self.binary_path = binary_path
        self.netns_factory = kwargs.pop("netns_factory", net_tools.NetNs)
        self.kwargs = kwargs

        assert self.fc_binary_path.exists(), "missing firecracker binary"
        assert self.jailer_binary_path.exists(), "missing jailer binary"

    @property
    def fc_binary_path(self):
        """The path to the firecracker binary from which this factory will build VMs"""
        return self.binary_path / "firecracker"

    @property
    def jailer_binary_path(self):
        """The path to the jailer binary using which this factory will build VMs"""
        return self.binary_path / "jailer"

    def build(self, kernel=None, rootfs=None, **kwargs):
        """Build a microvm"""
        kwargs = self.kwargs | kwargs
        microvm_id = kwargs.pop("microvm_id", str(uuid.uuid4()))
        vm = Microvm(
            microvm_id=microvm_id,
            fc_binary_path=kwargs.pop("fc_binary_path", self.fc_binary_path),
            jailer_binary_path=kwargs.pop(
                "jailer_binary_path", self.jailer_binary_path
            ),
            netns=kwargs.pop("netns", self.netns_factory(microvm_id)),
            **kwargs,
        )
        vm.netns.setup()
        self.vms.append(vm)
        if kernel is not None:
            vm.kernel_file = kernel
        if rootfs is not None:
            vm.rootfs_file = rootfs
            vm.distro = GuestDistro.from_rootfs(rootfs)
            vm.ssh_key = rootfs.with_suffix(".id_rsa")
        return vm

    def kill(self):
        """Clean up all built VMs"""
        for vm in self.vms:
            vm.kill()
            chroot_base_with_id = vm.jailer.chroot_base_with_id()
            if len(vm.jailer.jailer_id) > 0 and chroot_base_with_id.exists():
                shutil.rmtree(chroot_base_with_id)
            vm.netns.cleanup()

        self.vms.clear()


class Serial:
    """Class for serial console communication with a Microvm."""

    RX_TIMEOUT_S = 60

    def __init__(self, vm):
        """Initialize a new Serial object."""
        self._poller = None
        self._vm = vm

    def open(self):
        """Open a serial connection."""
        if self._poller is not None:
            # serial already opened
            return

        console_log_fd = os.open(self._vm.console_log, os.O_RDONLY)
        self._poller = select.poll()
        self._poller.register(console_log_fd, select.POLLIN | select.POLLHUP)

    def tx(self, input_string, end="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Send a string terminated by an end token (defaulting to "\n")."""
        self._vm.serial_input(input_string + end)

    def rx_char(self):
        """Read a single character."""
        result = self._poller.poll(0.1)

        for fd, flag in result:
            if flag & select.POLLHUP:
                assert False, "Oh! The console vanished before test completed."

            if flag & select.POLLIN:
                output_char = str(os.read(fd, 1), encoding="utf-8", errors="ignore")
                return output_char

        return ""

    def rx(self, token="\n"):
        # pylint: disable=invalid-name
        # No need to have a snake_case naming style for a single word.
        r"""Read a string delimited by an end token (defaults to "\n")."""
        rx_str = ""
        start = time.time()
        while True:
            rx_str += self.rx_char()
            if rx_str.endswith(token):
                break
            if (time.time() - start) >= self.RX_TIMEOUT_S:
                self._vm.kill()
                assert False

        return rx_str

    def drain_until_idle(self, idle_seconds=1):
        """Read and discard serial output until the console is idle.

        Returns once no new output has arrived for idle_seconds.
        Used after snapshot restore to let kernel messages (e.g. crng reseeded)
        finish before sending input, avoiding the input being swallowed while
        the kernel holds the console lock.
        """
        last_activity = time.time()
        start = time.time()
        while True:
            now = time.time()
            if (now - start) >= self.RX_TIMEOUT_S:
                break
            ch = self.rx_char()
            if ch:
                last_activity = now
            elif now - last_activity >= idle_seconds:
                break
