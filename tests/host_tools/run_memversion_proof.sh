#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Installed as /fc-proof in K's existing nested-QEMU initrd. No claim/runner of its own.
set -eu
test -c /dev/kvm
test -c /dev/memversion_v1
mkdir -p /dev/pts /tmp /run
mount -t devpts devpts /dev/pts
test -c /dev/ptmx
ulimit -l unlimited
set +e
/memversion-proof-driver /firecracker-memversion-v7 /jailer-memversion-v7 \
    /memversion-guest.elf /mv-proof-run
rc=$?
set -e
for f in /mv-proof-run/*.console /mv-proof-run/*/*/root/fc.log; do
    test -f "$f" || continue
    echo "--- FC_PROOF_LOG $f ---"
    cat "$f"
done
echo "FC_DRIVER_EXIT=$rc"
exit "$rc"
