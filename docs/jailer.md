# The Firecracker Jailer

## Disclaimer

The jailer is a program designed to isolate the Firecracker process in order to
enhance Firecracker's security posture. It is meant to address the security
needs of Firecracker only and is not intended to work with other binaries.
Additionally, each jailer binary should be used with a statically linked
Firecracker binary (with the default musl toolchain) of the same version.
Experimental gnu builds are not supported.

## Jailer Usage

The jailer is invoked in this manner:

```bash
jailer --id <id> \
       --exec-file <exec_file> \
       --uid <uid> \
       --gid <gid> \
       [--chroot-base-dir <chroot_base>] \
       [--netns <netns>] \
       --root-fd <n> \
       [--bootstrap-fd <n>] \
       [--cgroup-join <absolute_cgroupfs_path>] \
       [--resource-limit <no-file|fsize|memlock>=<value>] \
       [--...extra arguments for Firecracker]
```

- `--id` specifies the unique VM identification string, which may contain
  alphanumeric characters and hyphens. The maximum length is currently 64
  characters.
- `--exec-file` specifies the path to the Firecracker binary that will be
  exec-ed by the jailer.
- `--uid` and `--gid` specify the uid and gid the jailer switches to as it execs
  the target binary.
- `--chroot-base-dir` specifies the base folder where chroot jails are built.
  The default is `/srv/jailer`.
- `--netns` specifies the path to a network namespace handle. If present, the
  jailer will use this to join the associated network namespace.
- `--root-fd` is required and identifies the inherited sealed read-only root
  memfd. The jailer renumbers it to file descriptor 4.
- `--bootstrap-fd` is optional and identifies an inherited sealed read-only
  bootstrap memfd. The jailer renumbers it to file descriptor 5; when absent,
  file descriptor 5 is not reserved.
- `--cgroup-join` identifies an absolute cgroupfs path for a pre-created leaf
  cgroup. The jailer joins that cgroup and does not create cgroups.
- For extra security and control over resource usage, `--resource-limit` can be
  used to set bounds to the process resources. The argument must follow this
  format: `<resource>=<value>` (e.g `no-file=1024`) and can be used multiple
  times to set multiple bounds. Current available resources that can be limited
  using this argument are:
  - `fsize`: The maximum size in bytes for files created by the process.
  - `no-file`: Specifies a value one greater than the maximum file descriptor
    number that can be opened by this process.
  - `memlock`: The maximum amount of memory that may be locked into RAM.
- `--version` prints the jailer version.
- The jailer adheres to the "end of command options" convention, meaning all
  parameters specified after `--` are forwarded to Firecracker. For example,
  this can be paired with the `--config-file` Firecracker argument to specify a
  configuration file when starting Firecracker via the jailer (the file path and
  the resources referenced within must be valid relative to a jailed
  Firecracker). Please note the jailer already passes `--id` parameter to the
  Firecracker process.

## Jailer Operation

After starting, the Jailer goes through the following operations:

- Validate **all provided paths** and the VM ID.
- Close all open file descriptors based on `/proc/<jailer-pid>/fd` except input,
  output and error.
- Cleanup all environment variables received from the parent process.
- Create the `<chroot_base>/<exec_file_name>/<id>/root` folder, which will be
  henceforth referred to as `<chroot_dir>`. Nothing is done if the path already
  exists (it should not, since `<id>` is supposed to be unique).
- Copy the file specified with `--exec-file` to `<chroot_dir>/<exec_file_name>`.
  This ensures the new process will not share memory with any other Firecracker
  process.
- Set resource bounds for current process and its children through
  `--resource-limit` argument, by calling `setrlimit()` system call with the
  specific resource argument. If no limits are provided, the jailer bounds
  `no-file` to a maximum default value of 2048.
- If `--cgroup-join` is present, join the specified pre-created cgroup.
- Call `unshare()` into a new mount namespace, use `pivot_root()` to switch the
  old system root mount point with a new one base in `<chroot_dir>`, switch the
  current working directory to the new root, unmount the old root mount point,
  and call `chroot` into the current directory.
- Use `mknod` to create a `/dev/net/tun` equivalent inside the jail.
- Use `mknod` to create a `/dev/kvm` equivalent inside the jail.
- Open `/dev/userfaultfd` before dropping privileges and renumber its descriptor
  to file descriptor 3.
- Renumber the inherited sealed read-only root memfd to file descriptor 4.
- Use `chown` to change ownership of the `<chroot_dir>` (root path `/` as seen
  by the jailed firecracker), `/dev/net/tun`, and `/dev/kvm`. The ownership is
  changed to the provided `<uid>:<gid>`.
- If `--netns <netns>` is present, attempt to join the specified network
  namespace.
- Drop privileges via setting the provided `uid` and `gid`.
- Exec into
  `<exec_file_name> --id=<id> --start-time-us=<opaque> --start-time-cpu-us=<opaque>`
  (and also forward any extra arguments provided to the jailer after `--`, as
  mentioned in the **Jailer Usage** section), where:
  - `<id>`: (`string`) - The `<id>` argument provided to jailer.
  - `<opaque>`: (`number`) time calculated by the jailer that it spent doing its
    work.

## Example Run and Notes

Let’s assume Firecracker is available as `/usr/bin/firecracker`, and the jailer
can be found at `/usr/bin/jailer`. We pick the **unique id
551e7604-e35c-42b3-b825-416853441234**, and use **uid 123**, and **gid 100**.
For this example, we are content with the default `/srv/jailer` chroot base dir.

We start by running:

```bash
/usr/bin/jailer --id 551e7604-e35c-42b3-b825-416853441234 \
--exec-file /usr/bin/firecracker --uid 123 --gid 100 \
--netns /var/run/netns/my_netns --root-fd 4 \
--cgroup-join /sys/fs/cgroup/firecracker/551e7604-e35c-42b3-b825-416853441234
```

After opening the file descriptors mentioned in the previous section, the jailer
will create the following resources (and all their prerequisites, such as the
path which contains them):

- `/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/firecracker`
  (copied from `/usr/bin/firecracker`)

We are going to refer to
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root` as
`<chroot_dir>`.

Since the `--netns` parameter is specified in our example, the jailer opens
`/var/run/netns/my_netns` to get a file descriptor `fd`, uses
`setns(fd, CLONE_NEWNET)` to join the associated network namespace, and then
closes `fd`.

Build the chroot jail. First, the jailer uses `unshare()` to enter a new mount
namespace, and changes the propagation of all mount points in the new namespace
to private using `mount(NULL, “/”, NULL, MS_PRIVATE | MS_REC, NULL)`, as a
prerequisite to `pivot_root()`. Another required operation is to bind mount
`<chroot_dir>` on top of itself using
`mount(<chroot_dir>, <chroot_dir>, NULL, MS_BIND, NULL)`. At this point, the
jailer creates the folder `<chroot_dir>/old_root`, changes the current directory
to `<chroot_dir>`, and calls `syscall(SYS_pivot_root, “.”, “old_root”)`. The
final steps of building the jail are unmounting `old_root` using
`umount2(“old_root”, MNT_DETACH)`, deleting `old_root` with `rmdir`, and finally
calling `chroot(“.”)` for good measure. From now, the process is jailed in
`<chroot_dir>`.

Create the special file `/dev/net/tun`, using
`mknod(“/dev/net/tun”, S_IFCHR | S_IRUSR | S_IWUSR, makedev(10, 200))`, and then
call `chown(“/dev/net/tun”, 123, 100)`, so Firecracker can use it after dropping
privileges. This is required to use multiple TAP interfaces when running jailed.
Do the same for `/dev/kvm`.

The jailer opens `/dev/userfaultfd` before dropping privileges and retains it as
file descriptor 3. It renumbers the inherited sealed read-only root memfd to
file descriptor 4.

Change ownership of `<chroot_dir>` to `<uid>:<gid>` so that Firecracker can
create its API socket there.

Finally, the jailer switches the uid to `123`, and gid to `100`, and execs

```console
./firecracker \
  --id="551e7604-e35c-42b3-b825-416853441234" \
  --start-time-us=<opaque> \
  --start-time-cpu-us=<opaque>
```

Now firecracker creates the socket at
`/srv/jailer/firecracker/551e7604-e35c-42b3-b825-416853441234/root/<api-sock>`
to interact with the VM.

Note: default value for `<api-sock>` is `/run/firecracker.socket`.

### Observations

- All inputs to the jailer are considered trusted, including the paths provided
  via `--exec-file`, `--chroot-base-dir`, `--netns`, and `--cgroup-join`, as well
  as any resources placed inside the jail root directory. The operator invoking
  the jailer is part of the trusted computing base. It is the operator's
  responsibility to ensure that these paths and their parent directories have
  appropriate ownership and permissions (e.g., root-owned, not world-writable)
  to prevent unauthorized modification by other local users.
- The user must create hard links for (or copy) any resources which will be
  provided to the VM via the API (disk images, kernel images, named pipes, etc)
  inside the jailed root folder. Also, permissions must be properly managed for
  these resources; for example the user which Firecracker runs as must have both
  **read and write permissions** to the backing file for a RW block device.
- It’s up to the user to handle cleanup after running the jailer.
- We run the jailer as the `root` user; it actually requires a more restricted
  set of capabilities, but that's to be determined as features stabilize.

### Known limitations

- The time it takes to create a jail depends on the number of mount points in
  the system and the number of jailers starting at the same time.
