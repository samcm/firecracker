# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests for the virtio-vsock device.

In order to test the vsock device connection state machine, these tests will:
- Generate a 20MiB random data blob;
- Use `socat` to start a listening echo server inside the guest VM;
- Run 50, concurrent, host-initiated connections, each transfering the random
  blob to and from the guest echo server;
- For every connection, check that the data received back from the echo server
  hashes to the same value as the data sent;
- Start a host echo server, and repeat the process for the same number of
  guest-initiated connections.
"""

import os.path
from contextlib import ExitStack

import pytest

from framework.utils_vsock import (
    HostEchoWorker,
    _copy_vsock_data_to_guest,
    boot_vsock_vm,
    check_host_connections,
    check_vsock_device,
    make_blob,
    start_guest_echo_server,
)
from host_tools.fcmetrics import validate_fc_metrics

NEGATIVE_TEST_CONNECTION_COUNT = 100


@pytest.fixture
def vsock_uvm_any(uvm_plain_any):
    """Fixture to initialize a kernel-parametrized microVM with vsock device."""
    return boot_vsock_vm(uvm_plain_any)


def test_vsock(vsock_uvm_any, bin_vsock_path, test_fc_session_root_path):
    """
    Test guest and host vsock initiated connections.

    Check the module docstring for details on the setup.
    """

    vm = vsock_uvm_any

    check_vsock_device(vm, bin_vsock_path, test_fc_session_root_path, vm.ssh)
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)


def negative_test_host_connections(vm, blob_path, blob_hash):
    """Negative test for host-initiated connections.

    This will start a daemonized echo server on the guest VM, and then spawn
    `NEGATIVE_TEST_CONNECTION_COUNT` `HostEchoWorker` threads.
    Closes the UDS sockets while data is in flight.
    """

    uds_path = start_guest_echo_server(vm)

    with ExitStack() as stack:
        workers = [
            stack.enter_context(HostEchoWorker(uds_path, blob_path))
            for _ in range(NEGATIVE_TEST_CONNECTION_COUNT)
        ]
        for wrk in workers:
            wrk.start()

        for wrk in workers:
            wrk.close_uds()
            wrk.join()

    # Validate that guest is still up and running.
    # Should fail if Firecracker exited from SIGPIPE handler.

    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)

    # Validate that at least 1 `SIGPIPE` signal was received.
    # Since we are reusing the existing echo server which triggers
    # reads/writes on the UDS backend connections, these might be closed
    # before a read() or a write() is about to be performed by the emulation.
    # The test uses 100 connections it is enough to close at least one
    # before write().
    #
    # If this ever fails due to 100 closes before read() we must
    # add extra tooling that will trigger only writes().
    assert metrics["signals"]["sigpipe"] > 0

    # Validate vsock emulation still accepts connections and works
    # as expected. Use the default blob size to speed up the test.
    blob_path, blob_hash = make_blob(os.path.dirname(blob_path))
    check_host_connections(uds_path, blob_path, blob_hash)
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)


def test_vsock_epipe(vsock_uvm_any, bin_vsock_path, test_fc_session_root_path):
    """
    Vsock negative test to validate SIGPIPE/EPIPE handling.
    """
    vm = vsock_uvm_any

    # Generate the random data blob file, 20MB
    blob_path, blob_hash = make_blob(test_fc_session_root_path, 20 * 2**20)
    vm_blob_path = "/tmp/vsock/test.blob"

    # Set up a tmpfs drive on the guest, so we can copy the blob there.
    # Guest-initiated connections (echo workers) will use this blob.
    _copy_vsock_data_to_guest(vm.ssh, blob_path, vm_blob_path, bin_vsock_path)

    # Negative test for host-initiated connections that
    # are closed with in flight data.
    negative_test_host_connections(vm, blob_path, blob_hash)
    metrics = vm.flush_metrics()
    validate_fc_metrics(metrics)
