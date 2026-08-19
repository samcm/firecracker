# Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests the metrics system."""

from host_tools.fcmetrics import FcDeviceMetrics, validate_fc_metrics


def test_flush_metrics(uvm_plain):
    """
    Check the `FlushMetrics` vmm action.
    """
    microvm = uvm_plain
    microvm.spawn()
    microvm.basic_config()
    microvm.start()

    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)


def test_net_metrics(uvm_plain):
    """
    Validate that NetDeviceMetrics doesn't have a breaking change
    and "net" is aggregate of all "net_*" in the json object.
    """
    test_microvm = uvm_plain
    test_microvm.spawn()

    # Set up a basic microVM.
    test_microvm.basic_config()

    # randomly selected 10 as the number of net devices to test
    num_net_devices = 10

    net_metrics = FcDeviceMetrics("net", num_net_devices)

    # create more than 1 net devices to test aggregation
    for _ in range(num_net_devices):
        test_microvm.add_net_iface()
    test_microvm.start()

    # check that the started microvm has "net" and "NUM_NET_DEVICES" number of "net_" metrics
    net_metrics.validate(test_microvm)

    for i in range(num_net_devices):
        # Test that network devices attached are operational.
        # Verify if guest can run commands.
        exit_code, _, _ = test_microvm.ssh_iface(i).run("sync")
        # test that we get metrics while interacting with different interfaces
        net_metrics.validate(test_microvm)
        assert exit_code == 0
