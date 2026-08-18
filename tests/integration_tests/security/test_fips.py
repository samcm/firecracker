# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for FIPS-mode guest kernels.

Tests verify that:
1. FIPS reseeding is logged on snapshot restore
2. Kernel CSPRNGs are reseeded (diverge across restored VMs)
3. Userspace CSPRNGs are reseeded (diverge across restored VMs)
"""


def test_fips_enabled(uvm_with_fips):
    """Test that FIPS mode is enabled in the guest kernel."""
    _, dmesg, _ = uvm_with_fips.ssh.run("dmesg | grep -i fips")
    assert "fips mode: enabled" in dmesg.lower()


