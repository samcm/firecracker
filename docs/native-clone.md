# Native mode and same-host cloning

`firecracker --native` runs a microVM standalone: the process owns private
anonymous guest memory, needs no memory channel, and serves its API on the main
thread. It can clone a running microVM on the same host by forking.

## Profile

Native mode admits, and rejects before building anything else:

- x86-64, one MMIO synchronous block root drive (read-only, inherited at file
  descriptor 4) and at most one scratch drive (inherited at descriptor 5);
- serial console output to a file or discarded; the process never takes the
  terminal it shares with its launcher;
- no network, vsock, entropy, PCI, asynchronous block engine, GDB, or block or
  serial rate limiters, and no snapshot loading.

With the jailer, pass `--native` to the jailer and to Firecracker; see
[jailer.md](jailer.md). The jailer then opens no `/dev/userfaultfd` and leaves
file descriptor 3 closed: the launcher reaches each child only through its
`control_sock`.

## Clone contract

A clone family shares one jail, principal and resource scope: clones are
isolated from their source's later writes, not from each other as hostile
tenants. Native mode refuses to run as a PID namespace's init, which would take
its clones down with it.

1. The launcher listens on a control socket and sends the source
   `PUT /clone` with:

   ```json
   {
     "api_sock": "/child/api.sock",
     "control_sock": "/launcher/control.sock",
     "instance_id": "child-1",
     "log_path": "/child/log",
     "metrics_path": "/child/metrics",
     "serial_out_path": "/child/serial",
     "scratch_path": "/child/scratch"
   }
   ```

   `scratch_path` is given exactly when the microVM has a scratch drive. Every
   other destination is mandatory: a child never writes to its source's.

2. The source stops every worker, captures its state with the interrupt lines
   detached, writes out its metrics, reflinks the scratch disk if any, and
   forks from its now only thread. A failure before the fork, including a
   metrics write that fails and so could leave bytes buffered for the child to
   inherit, restarts the source and removes a scratch copy it created, never a
   path that existed.
   After the fork the source restarts its original objects in their prior
   Running or Paused state and tells the child it has.

3. The child first takes its own identity and output destinations (keeping
   the log level and format, forgetting the source's counted increments); if
   it cannot, it exits writing nothing, since every output it holds is still
   its source's. It then disposes of everything it inherited without touching
   the source's objects, including the event loop's copy of its own source's
   control connection when that source is a clone, reopens the root image as
   its own file description, rebuilds a fresh microVM over the guest memory,
   paused, and locks its memory again. It connects to `control_sock` and sends
   `ready\n`.

4. The source answers `200 {"child_pid": N}` only once it runs again and the
   child is ready; otherwise it answers with an error and runs on. A guest that
   has shut down, including one that shuts down while its workers stop for the
   clone, is never cloned or restarted: the request fails and the process exits
   with the guest's exit code.

5. The launcher sends `commit\n` on the child's control connection, as one
   newline-terminated record of at most 16 bytes, however the stream splits
   it. The child publishes only once its source said it recovered and the
   commit arrived, in either order: only then does it serve its API at
   `api_sock`, where `PATCH /vm` with `{"state":"Resumed"}` starts its guest.
   `cancel\n`, any other or overlong record, the connection ending, or the
   source failing or dying before saying it recovered make the child exit
   without its guest ever running.

A published child survives its source. While the source runs, it ignores
SIGCHLD, so the kernel reaps its clone children's exits. Once the source is
gone, its surviving children are adopted by the nearest child subreaper, or by
the PID namespace's init, which must reap them when they exit: until then a
dead child remains a zombie.

## Limits

- A source that cannot restart its microVM, or cannot attach its interrupt
  lines again after a capture, is lost: the process exits.
- Timers restore snapshot-style: no realtime catch-up and no exact PIT phase.
- The launcher keeps its end of the control connection open for the child's
  lifetime. Closing it, or shutting it down for writing, ends the child's
  microVM, before or after commit.
- The source and child wait for each other's readiness and recovery with
  blocking reads, and the child waits for the launcher's verdict the same way;
  none of these waits is bounded by a timeout.
- Stored metrics, such as gauges, keep their last value in a child; increment
  counters start from zero.

## Qualification

The compiled native integration test runs against any binary, without its build
tree: `FIRECRACKER_BINARY` names the Firecracker binary, `NATIVE_TEST_TMPDIR`
where it creates scratch directories (the system temporary directory by
default), and `NATIVE_GUEST_DIR` a guest fixture, in which `NATIVE_GUEST_KERNEL`
and `NATIVE_GUEST_ROOTFS` name the kernel and root image (`vmlinux-6.1.155` and
`rootfs.squashfs` by default). The guest must print `NATIVE_BOOT_READY` and
`NATIVE_HEARTBEAT tick=N` lines. The ignored test needs `/dev/kvm` and plays
the launcher: reserve, ready, recovered, commit and cancel, a child that cannot
open its own log (its source's streams stay free of it), a child that took its
own outputs but cannot rebuild its console (the typed restore error in its own
log only, no launcher connection, API or guest), launcher death after
commit, a nested clone whose source's launcher sees end of stream once that
source dies, and the source dying after publication. As a launcher that
outlives the source, the test makes its process a child subreaper while it
runs, owns the source and every clone it is told of from the moment it gets the
pid, and kills and reaps them all however it ends, including on a failed
assertion.

```bash
FIRECRACKER_BINARY=/path/firecracker NATIVE_GUEST_DIR=/path/fixture \
  ./native-<hash> --ignored --exact test_native_boots_sealed_root_fixture
```
