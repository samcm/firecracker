#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Installed as /fc-proof in K's existing nested-QEMU initrd. No claim/runner of its own.
set -eu
finish() {
    rc=$?
    trap - EXIT
    # A panic=abort driver cannot run its child-owner destructors. Kill only recorded FC PIDs.
    for f in /newroot/mv-proof-run/*.pid; do
        test -f "$f" || continue
        pid=$(cat "$f")
        case "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" in
            */firecracker-memversion-v7) kill -KILL "$pid" 2>/dev/null || true ;;
        esac
    done
    for f in /newroot/mv-proof-run/*.console /newroot/mv-proof-run/*/*/root/fc.log; do
        test -f "$f" || continue
        echo "--- FC_PROOF_LOG $f ---"
        cat "$f"
    done
    echo "FC_DRIVER_EXIT=$rc"
    exit "$rc"
}
trap finish EXIT
test -c /dev/kvm
test -c /dev/memversion_v1
mkdir -p /dev/pts /tmp /run
mount -t devpts devpts /dev/pts
test -c /dev/ptmx
ulimit -l unlimited
# pivot_root cannot detach initramfs rootfs. Chroot the driver onto a real tmpfs mount first;
# the production jailer still performs its own mount-namespace, bind, and pivot_root sequence.
# No cgroup mount: this invocation deliberately does not pass --cgroup-join.
mkdir /newroot
mount -t tmpfs -o mode=0755 tmpfs /newroot
mkdir -p /newroot/dev /newroot/proc /newroot/sys /newroot/tmp /newroot/run
for name in dev proc sys; do
    mount -o rbind "/$name" "/newroot/$name"
done
for name in memversion-proof-driver firecracker-memversion-v7 jailer-memversion-v7 memversion-guest.elf; do
    cp "/$name" "/newroot/$name"
done
chroot /newroot /memversion-proof-driver /firecracker-memversion-v7 /jailer-memversion-v7 \
    /memversion-guest.elf /mv-proof-run
