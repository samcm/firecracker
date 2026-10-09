# The post-close device guard covers 2804 distinct guest pages

The ramet-vmstate/0 hard cutover has one device profile. The host-device term is
**2804 × 4096 = 11,485,184 bytes**. Its Rust contract is
`devices::virtio::MAX_POST_CLOSE_GUEST_PAGES`; the arithmetic test derives it from
the actual payload, queue and in-flight constants. Pagemaster adds this term to
its separately funded vCPU observation-to-pause term, then page-aligns the sum.
This is a bound on distinct potentially dirtied pages, **not** a latency bound,
a bound on repeated byte stores to one ring page, or a substitute for pausing
vCPUs and draining asynchronous I/O before CREATE.

## Admission and restore enforce the assumptions

- Boot and restore permit at most two block devices and one each of net, vsock,
  RNG and free-page reporting, summed across MMIO and PCI even when PCI is
  disabled. Restore checks before importing RAM and again before device restore.
- Each block advertises SIZE_MAX=65536 and SEG_MAX=1. Parsing permits one data
  descriptor and one status descriptor, rejects trailing descriptors, and refuses
  oversized payloads before I/O or payload writes (a valid status receives EIO).
  The asynchronous engine caps queued, submitted and completed-but-unconsumed
  requests at 32, independently of its larger SQ/CQ sizes. Restore refuses states
  missing either advertised or negotiated SIZE_MAX/SEG_MAX bit. No legacy profile
  or /4-/6 decoder exists; BackendReady retains the /7 28-byte tail and zero FDs.
- Block, net, vsock, RNG, inflate/deflate and reporting loops check close before
  every pop/frame admission. An iteration racing close may finish, but no refill
  can admit another. Each yields through its normal completion/notification
  epilogue and retains a host eventfd wake for reopen; EAGAIN already means a wake
  is pending. This does not depend on guest kicks or EVENT_IDX behavior.
- Net bounds readv to 65562 bytes, even for inflated guest descriptors. Its cached
  writable iovec has at most 256 entries. Vsock bounds payload writes to 65536
  bytes and validates its 44-byte header and guest capacity before header stores.
  RNG is capped at 65536 bytes. Each uses at most 256 guest spans per operation.
- Reporting/balloon queues only update host free-page metadata and used rings;
  they never discard or zero guest RAM. VMGenID and VMClock have one fixed region
  each. RNG is optional at boot; the bound conservatively includes it. Reporting
  and both ACPI devices are attached internally. This fork has no MMDS device
  writer. Serial/RTC/PIO/config accesses affect host register state, not guest RAM.
- vCPU MMIO/PIO is not stopped by closing the dispatch gate. Activation caches
  queue pointers and changes host state/eventfds; it does not write guest RAM.
  Queue addresses cannot change in a live admitted handler holding the device
  mutex. Guest execution belongs to the additional vCPU term, not this device term.

## Formula counts scatter and metadata, not only payload bytes

For 4096-byte pages, a contiguous span of B bytes touches at most ceil(B/4096)+1
pages. For N arbitrary spans with aggregate length B, conservatively use
S(B,N)=ceil(B/4096)+2N. Each queue has at most 256 entries; its used ring, flags,
index and avail_event occupy at most ceil((4+8×256+2)/4096)+1 = 2 pages, even when
unaligned. Repeated ring updates do not introduce additional distinct pages.

| Device | Per-device page formula | Pages | Maximum count |
| --- | --- | ---: | ---: |
| Block | (32 outstanding + 1 racing iteration) × (16 payload + 1 unaligned + 1 status) + 2 ring | 596 | 2 |
| Net | S(65562,256) + 2 num_buffers header + 2 queues × 2 ring | 535 | 1 |
| Vsock | S(65536+44,256) + 2 reset event + 3 queues × 2 ring | 537 | 1 |
| RNG | S(65536,256) + 2 ring | 530 | 1 |
| Reporting/balloon | 3 queues × 2 ring, no payload writes | 6 | 1 |
| ACPI | 2 VMGenID + 2 VMClock, including restore updates | 4 | 1 |

Total: 2×596 + 535 + 537 + 530 + 6 + 4 = **2804 pages**.
Block's extra racing iteration is conservative for synchronous reads, GET_ID,
errors and an admitted request competing with already outstanding asynchronous I/O.
Net deferred frame publication during snapshot preparation touches the already
counted ring. Vsock reset metadata is counted separately from the RX payload.

## Regression evidence and remaining hardware checks

The `post_close_guest_write_page_bound` test locks the formula to production
constants and checks unaligned/scattered spans. `guard_rejects_each_extra_device`
and restore-state tests exercise multiplicity and missing negotiated limits.
Block tests exercise actual sync/async payload writes at the limit, EIO without
payload writes above it, and capacity refunds only on consumed completions.
Net tests exercise actual readv with inflated iovecs through a datagram FD.
Vsock tests check sentinel bytes on refused lengths. Isolated `close_yields_*`
tests refill a guest queue after close and verify only the admitted iteration
finishes and the retained host wake resumes work. The reporting close test needs
KVM; these tests are not a claim that real jailed /7 boot/restore has passed.

No production FC guest-memory path calls MADV_FREE. The shipped seccomp filters
exclude advice 8; `shipped_filters_trap_madv_free_on_every_thread` installs the
compiled native policy and verifies SIGSYS for vmm, vcpu and api, including advice
with nonzero high register bits, plus an allowed NOHUGEPAGE control. Guest RAM is
NOHUGEPAGE before first touch and pinned on fault; running guests never discard it.

## Ramet/8 free summaries do not alter capture or the guard

FreeSummary (22) carries one LE u64 budget of 1–250000 microseconds and one
read-write, grow/shrink-sealed memfd. FreeSummaryDone (23) has one LE u64 popcount
and no descriptors; tags 18–21 remain reserved. Each backend-ready region contributes
ceil((size/4096)/64) LE u64 words in guest-address order. The full geometry-derived
size is validated before any write, is capped at 4 MiB, and includes zero words
and zeroed tail bits. The unchanged BackendReady tail and CREATE ABI are retained.

The summary is **reported minus pending, live KVM and host writes**, not the legacy
uncaptured subset. Pagemaster intersects it with its earlier source-only pagemap
walk to determine ownership. Free reports clear their own KVM bits even before
the first whole-slot harvest, so summaries must inspect live KVM bits regardless
of the slot-wide `kvm_log_armed` marker.

VM creation requires MANUAL_DIRTY_LOG_PROTECT2 with MANUAL_PROTECT_ENABLE and
INITIALLY_SET; enable failure aborts startup. Thus GET_DIRTY_LOG is observational,
not a fetch-and-clear. No summary closes dispatch, pauses or drains the guest,
clears dirty evidence, changes mappings or residency, or creates a version.
The capture thread clones the KVM VM under a VMM try-lock, then releases that
guard before reading. Bookkeeping locks also use try-locks. Deadline checks occur
between regions, within bitmap loops, and between bounded positional writes.
An in-flight kernel syscall is not preempted by this cooperative deadline.

Quiesced queries return AlreadyQuiesced; busy, expired, oversized or failed reads
and writes return advisory FreeSummaryUnavailable (28), not channel failure.
Partial output is never reported successful and must be discarded. Pagemaster
uses a fresh buffer each tick, never an abandoned writable buffer; exact request-ID
replays resend only the cached reply without reading or writing again. This adds
no seccomp allowances: the capture thread already admits GET_DIRTY_LOG and pwrite64,
and MADV_FREE remains denied on every VMM thread.

### An 8 GiB summary scans words, not candidate pages

The userspace scan checks its deadline every 256 words and after the last word.
Host-write masks come from an independent deep copy of `AtomicBitmap`, using the
same extraction pattern as `snapshot_dirty_log`: only the disposable copy is
reset; live host/KVM/pending/reported state is untouched. Source-preservation and
rewrite-between-query tests protect that distinction. CREATE is unchanged.

Run `cargo test -p vmm --release --target x86_64-unknown-linux-musl --lib
test_free_summary_userspace_cost_8gib -- --nocapture --test-threads=1` to compare
the old per-page loop with the production word loop. It allocates only bitmap
metadata for an 8 GiB guest (32768 words); sparse means 2048 candidate pages,
and host/pending/KVM masks are empty. Each release run compares 40 results per
case for equality and prints p50/p95/max wall and thread-CPU microseconds.

On a 2.60 GHz Xeon orb, one musl release run measured:

| Candidates | Old p50 wall/CPU (µs) | New p50 wall/CPU (µs) | New p95 wall/CPU (µs) | New max wall/CPU (µs) |
| --- | ---: | ---: | ---: | ---: |
| All 2097152 | 2450/2451 | 532/533 | 579/579 | 621/622 |
| Sparse 2048 | 835/836 | 528/529 | 567/573 | 593/594 |
| Zero | 835/835 | 531/532 | 571/571 | 770/771 |

These are observed userspace costs including mask copying and output allocation,
not hard latency bounds or an end-to-end KVM measurement. A 1 ms scan allowance
covers these samples, but a **5 ms initial wire budget** is recommended for
scheduling, GET_DIRTY_LOG, descriptor checks and output writes. The former 2 ms
budget cannot accommodate even the old all-free loop. The smallest sustainable
end-to-end budget still needs measurement on a healthy production KVM host;
the 250 ms wire cap and advisory timeout/refusal semantics are unchanged.
