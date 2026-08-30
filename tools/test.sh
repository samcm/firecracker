#!/bin/bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# fail if we encounter an error, uninitialized variable or a pipe breaks
set -eu -o pipefail

TOOLS_DIR=$(dirname $0)
source "$TOOLS_DIR/functions"

# Set our TMPDIR inside /srv, so all files created in the session end up in one
# place
say "Create TMPDIR in /srv"
export TMPDIR=/srv/tmp
rm -rf "$TMPDIR" /srv/fctest-* /srv/jailer
mkdir -pv $TMPDIR

# Some of the security tests need this (test_jail.py)
# Convert the Docker created cgroup so we can create cgroup children
# From https://github.com/containerd/containerd/issues/6659
say "cgroups v2: enable nesting"
CGROUP=/sys/fs/cgroup
if [ -f $CGROUP/cgroup.controllers -a -e $CGROUP/cgroup.type ]; then
    # move the processes from the root group to the /init group,
    # otherwise writing subtree_control fails with EBUSY.
    # An error during moving non-existent process (i.e., "cat") is ignored.
    mkdir -p $CGROUP/init
    xargs -rn1 < $CGROUP/cgroup.procs > $CGROUP/init/cgroup.procs || :
    # enable controllers
    sed -e 's/ / +/g' -e 's/^/+/' < $CGROUP/cgroup.controllers \
        > $CGROUP/cgroup.subtree_control
fi

if [ "${FC_TEST_SKIP_ARTIFACT_COPY:-}" = "1" ]; then
  mkdir -p /srv/test_artifacts
  say "Skipping artifact copy (FC_TEST_SKIP_ARTIFACT_COPY=1)"
elif [ -f build/current_artifacts ]; then
  artifact_fingerprint() {
    # A jailer may hardlink a kernel and chown that shared inode to its sandbox uid, so ownership
    # is expected to drift. Shape, mode, size and nanosecond mtime still reject missing, replaced,
    # written or chmodded cache entries without rereading every multi-gigabyte image.
    find -L "$1" -mindepth 1 \
      -printf '%P\0%y\0%s\0%m\0%T@\0' \
      | LC_ALL=C sort -z \
      | sha256sum \
      | cut -d' ' -f1
  }
  artifact_source=$(readlink -f "$(cat build/current_artifacts)")
  artifact_stamp=/srv/.firecracker-artifacts-source
  source_fingerprint=$(artifact_fingerprint "$artifact_source")
  staged_fingerprint=$(artifact_fingerprint /srv/test_artifacts 2>/dev/null || true)
  if [ -f "$artifact_stamp" ] \
      && [ "$(cat "$artifact_stamp")" = "$artifact_source" ] \
      && [ "$staged_fingerprint" = "$source_fingerprint" ]; then
    say "Reuse artifacts already staged in /srv/test_artifacts"
  else
    say "Copy artifacts to /srv/test_artifacts, so hardlinks work"
    rm -rf /srv/test_artifacts
    mkdir -p /srv/test_artifacts
    cp -aL "$artifact_source"/. /srv/test_artifacts/
    printf '%s\n' "$artifact_source" > "$artifact_stamp"
  fi
else
  # The directory must exist for pytest to function
  mkdir -p /srv/test_artifacts
  say_warn "No current artifacts are set. Some tests might break"
fi

cd tests
export PYTEST_ADDOPTS="${PYTEST_ADDOPTS:-} --pdbcls=IPython.terminal.debugger:TerminalPdb"

{
    # disable errexit momentarily so we can capture the exit status
    set +e
    pytest "$@"
    ret=$?
    set -e
}

# if the tests failed and we are running in CI, print some disk usage stats
# to help troubleshooting
if [ $ret != 0 ] && [ "${BUILDKITE:-false}" == "true" ]; then
    df -ih
    df -h
    du -h / 2>/dev/null |sort -h |tail -32
fi

exit $ret
