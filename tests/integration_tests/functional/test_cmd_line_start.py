# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Tests microvm start with configuration file as command line parameter."""

import json
import platform
import re
from pathlib import Path

import pytest
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_fixed

from framework import utils
from framework.utils_cpu_templates import SUPPORTED_CPU_TEMPLATES


def _configure_vm_from_json(test_microvm, vm_config_file):
    """
    Configure a microvm using a file sent as command line parameter.

    Create resources needed for the configuration of the microvm and
    set as configuration file a copy of the file that was passed as
    parameter to this helper function.
    """
    # since we don't use basic-config, we do it by hand
    test_microvm.create_jailed_resource(test_microvm.kernel_file)

    vm_config_file = Path(vm_config_file)
    obj = json.load(vm_config_file.open(encoding="UTF-8"))
    obj["boot-source"]["kernel_image_path"] = str(test_microvm.kernel_file.name)
    vm_config = Path(test_microvm.chroot()) / vm_config_file.name
    vm_config.write_text(json.dumps(obj))
    test_microvm.jailer.extra_args = {"config-file": vm_config.name}
    return obj


def _configure_network_interface(test_microvm):
    """
    Create tap interface before spawning the microVM.

    The network namespace is already pre-created.
    The tap interface has to be created beforehand when starting the microVM
    from a config file.
    """

    # Create tap device, and avoid creating it in the guest since it is already
    # specified in the JSON
    test_microvm.add_net_iface(api=False)


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_start_with_api(uvm_plain, vm_config_file):
    """
    Test if a microvm configured from file boots successfully.
    """
    test_microvm = uvm_plain
    vm_config = _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.spawn(serial_out_path=None)

    assert test_microvm.state == "Running"

    # Validate full vm configuration.
    response = test_microvm.api.vm_config.get()
    assert response.json() == vm_config


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config.json"])
def test_config_start_no_api(uvm_plain, vm_config_file):
    """
    Test microvm start when API server thread is disabled.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})
    test_microvm.spawn(serial_out_path=None)

    # Get names of threads in Firecracker.
    cmd = f"ps -T --no-headers -p {test_microvm.firecracker_pid} | awk '{{print $5}}'"

    # Retry running 'ps' in case it failed to list the firecracker process
    # The regex matches any expression that contains 'firecracker' and does
    # not contain 'fc_api'
    for attempt in Retrying(
        retry=retry_if_exception_type(RuntimeError),
        stop=stop_after_attempt(10),
        wait=wait_fixed(1),
        reraise=True,
    ):
        with attempt:
            utils.search_output_from_cmd(
                cmd=cmd,
                find_regex=re.compile("^(?!.*fc_api)(?:.*)?firecracker", re.DOTALL),
            )


@pytest.mark.parametrize("vm_config_file", ["framework/vm_config_network.json"])
def test_config_start_no_api_exit(uvm_plain, vm_config_file):
    """
    Test microvm exit when API server is disabled.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    _configure_network_interface(test_microvm)
    test_microvm.jailer.extra_args.update({"no-api": None})

    test_microvm.spawn(serial_out_path=None)  # Start Firecracker and MicroVM
    test_microvm.ssh.run("reboot")  # Exit

    test_microvm.mark_killed()  # waits for process to terminate

    # Check error log and exit code
    test_microvm.check_log_message("Firecracker exiting successfully")
    assert test_microvm.get_exit_code() == 0


@pytest.mark.parametrize(
    "vm_config_file",
    [
        "framework/vm_config_missing_vcpu_count.json",
        "framework/vm_config_missing_mem_size_mib.json",
    ],
)
def test_config_bad_machine_config(uvm_plain, vm_config_file):
    """
    Test microvm start when the `machine_config` is invalid.
    """
    test_microvm = uvm_plain
    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})
    test_microvm.spawn(serial_out_path=None)
    test_microvm.check_log_message("Configuration for VMM from one single json failed")

    test_microvm.mark_killed()


@pytest.mark.parametrize(
    "test_config",
    [
        ("framework/vm_config_cpu_template_C3.json", True, False),
        ("framework/vm_config_smt_true.json", False, True),
    ],
)
def test_config_machine_config_params(uvm_plain, test_config):
    """
    Test microvm start with optional `machine_config` parameters.
    """
    test_microvm = uvm_plain

    # Test configuration determines if the file is a valid config or not
    # based on the CPU
    vm_config_file, cpu_template_used, smt_used = test_config

    _configure_vm_from_json(test_microvm, vm_config_file)
    test_microvm.jailer.extra_args.update({"no-api": None})

    test_microvm.spawn(serial_out_path=None)

    should_fail = False
    if cpu_template_used and "C3" not in SUPPORTED_CPU_TEMPLATES:
        should_fail = True
    if smt_used and (platform.machine() == "aarch64"):
        should_fail = True

    if should_fail:
        test_microvm.check_any_log_message(
            [
                "Failed to build MicroVM from Json",
                "Could not Start MicroVM from one single json",
            ]
        )

        test_microvm.mark_killed()
    else:
        test_microvm.check_log_message(
            "Successfully started microvm that was configured from one single json"
        )
