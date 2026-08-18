# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests that ensure the correctness of the command line parameters."""

import subprocess
from pathlib import Path

import pytest

from host_tools.fcmetrics import validate_fc_metrics


def test_cli_metrics_path(uvm_plain):
    """
    Test --metrics-path parameter
    """
    microvm = uvm_plain
    metrics_path = Path(microvm.path) / "my_metrics.ndjson"
    microvm.spawn(metrics_path=metrics_path)
    microvm.basic_config()
    microvm.start()
    metrics = microvm.flush_metrics()
    validate_fc_metrics(metrics)


def test_cli_metrics_path_if_metrics_initialized_twice_fail(uvm_plain):
    """
    Given: a running firecracker with metrics configured with the CLI option
    When: Configure metrics via API
    Then: API returns an error
    """
    microvm = uvm_plain

    # First configure the µvm metrics with --metrics-path
    metrics_path = Path(microvm.path) / "metrics.ndjson"
    metrics_path.touch()
    microvm.spawn(metrics_path=metrics_path)

    # Then try to configure it with PUT /metrics
    metrics2_path = Path(microvm.path) / "metrics2.ndjson"
    metrics2_path.touch()

    # It should fail with because it's already configured
    with pytest.raises(RuntimeError, match="Reinitialization of metrics not allowed."):
        microvm.api.metrics.put(
            metrics_path=microvm.create_jailed_resource(metrics2_path)
        )


def test_cli_no_params(microvm_factory):
    """
    Test running firecracker with no parameters should work
    """

    fc_binary = microvm_factory.fc_binary_path
    process = subprocess.Popen(fc_binary)
    try:
        process.communicate(timeout=3)
        assert process.returncode is None
    except subprocess.TimeoutExpired:
        # The good case
        process.kill()
