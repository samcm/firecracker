# Copyright 2026 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Cross-language checks of the farplane memory channel wire format.

The Python pagemaster fake and the Rust implementation carry two copies of the same
protocol. These tests need no microVM: they compare the fake against the Rust source and
against the frame fixture both languages decode.
"""

import os
import re
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

import host_tools.farplane as fp  # pylint:disable=import-error

# This test needs no built binary and no test artifacts, so it resolves the workspace itself
# rather than through the framework, and runs on any Linux with the test requirements.
WORKSPACE = Path(__file__).resolve().parents[3]
PROTOCOL_RS = WORKSPACE / "src/vmm/src/vstate/farplane/protocol.rs"
FIXTURE_DIR = WORKSPACE / "src/vmm/src/vstate/farplane/testdata"


def rust_constant(name):
    """The value of a `&str` constant declared in the protocol module."""
    source = PROTOCOL_RS.read_text(encoding="utf-8")
    match = re.search(rf'pub const {name}: &str = "([^"]+)";', source)
    assert match, f"{name} is not declared in {PROTOCOL_RS}"
    return match.group(1)


def rust_enum(name):
    """The discriminants of a `#[repr]` enum declared in the protocol module."""
    source = PROTOCOL_RS.read_text(encoding="utf-8")
    body = re.search(rf"pub enum {name} \{{(.*?)\n\}}", source, re.DOTALL)
    assert body, f"{name} is not declared in {PROTOCOL_RS}"
    variants = re.findall(r"^\s{4}(\w+) = (\d+),$", body.group(1), re.MULTILINE)
    assert variants, f"{name} declares no variants"
    return {
        re.sub(r"(?<!^)(?=[A-Z0-9])", "_", variant).upper(): int(value)
        for variant, value in variants
    }


def test_feature_identity_agrees_with_rust():
    """The fake refuses a `hello` whose identity is not this one, so it has to match."""
    assert fp.FEATURE_IDENTITY == "farplane/8"
    assert rust_constant("FEATURE_IDENTITY") == fp.FEATURE_IDENTITY


@pytest.mark.parametrize(
    "fixture_name,expected_arch",
    [("hello.hex", fp.ARCH_X86_64), ("hello_aarch64.hex", fp.ARCH_AARCH64)],
)
def test_hello_fixture_decodes_to_the_expected_identity(fixture_name, expected_arch):
    """The fixtures are the frames Rust encodes on each architecture; the fake parses both."""
    datagram = bytes.fromhex(
        (FIXTURE_DIR / fixture_name).read_text(encoding="utf-8").strip()
    )

    magic, version, msg_type, request_id, body_len, fd_count, reserved = (
        fp.HEADER.unpack_from(datagram)
    )
    assert magic == fp.MAGIC
    assert version == fp.VERSION
    assert msg_type == fp.Msg.HELLO
    assert request_id == 0
    assert fd_count == 0
    assert reserved == 0
    assert len(datagram) == fp.HEADER.size + body_len

    body = datagram[fp.HEADER.size :]
    _pid, page_size, arch, mode, region_count, identity = fp.HELLO.unpack_from(body)
    assert page_size == 4096
    assert arch == expected_arch
    assert mode == fp.MODE_BOOT
    assert region_count == 1
    assert identity.rstrip(b"\0").decode() == fp.FEATURE_IDENTITY

    regions = [
        fp.REGION.unpack_from(body, fp.HELLO.size + index * fp.REGION.size)
        for index in range(region_count)
    ]
    assert regions == [(0, 0x0800_0000)]


def test_error_codes_agree_with_rust():
    """A code the fake cannot name turns a precise rejection into a decode failure."""
    rust = rust_enum("ErrorCode")
    fake = {member.name: int(member) for member in fp.Err}
    assert fake == rust


def test_message_types_agree_with_rust():
    """Every reply the fake may receive has to be nameable, replies included."""
    rust = rust_enum("MsgType")
    fake = {member.name: int(member) for member in fp.Msg}
    assert fake == rust


def test_free_summary_uses_geometry_budget_and_discards_failed_buffer():
    """The /8 fake supplies one fresh bounded bitmap; failed contents never become credit."""
    regions = [{"guest_addr": 0, "size": 65 * 4096}]
    owned = []

    def request(msg, body, fds):
        assert msg == fp.Msg.FREE_SUMMARY == 22
        assert body == struct.pack("<Q", 12345)
        assert len(fds) == 1
        fd = fds[0]
        assert os.fstat(fd).st_size == 16
        assert fp.seals_of(fd) & fp.BUFFER_SEALS == fp.BUFFER_SEALS
        # Keep an independent reference so the next call must have a different inode.
        owned.append(os.dup(fd))
        os.pwrite(fd, struct.pack("<QQ", 0, 1), 0)
        return fp.Reply(fp.Msg.FREE_SUMMARY_DONE, struct.pack("<Q", 1), [], None)

    fake = SimpleNamespace(ready_regions=regions, request=request)
    try:
        _, bitmap = fp.Pagemaster.free_summary(fake, 12345)
        assert bitmap.set_pages() == [64 * 4096]
        _, bitmap = fp.Pagemaster.free_summary(fake, 12345)
        assert bitmap.count() == 1
        assert os.fstat(owned[0]).st_ino != os.fstat(owned[1]).st_ino
        fake.request = lambda *args, **kwargs: fp.Reply(
            fp.Msg.ERROR, b"", [], (fp.Err.FREE_SUMMARY_UNAVAILABLE, fp.Msg.FREE_SUMMARY)
        )
        reply, bitmap = fp.Pagemaster.free_summary(fake)
        assert reply.error[0] == 28
        assert bitmap is None
    finally:
        for fd in owned:
            os.close(fd)
