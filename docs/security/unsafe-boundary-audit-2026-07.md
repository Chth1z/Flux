# Explicit unsafe-boundary audit (2026-07)

## Outcome

This audit semantically reviewed every unsafe Rust construct in the root workspace source and test
targets at the P1-R3 checkpoint. It found one fail-closed process-signal defect: two internal
helpers accepted zero and could therefore translate an intended single-process or named-group
signal into `kill(0, signal)`, which addresses the caller's process group. The checkpoint rejects
zero before the syscall and covers the pure target conversion with focused tests.

No other violated pointer, initialization, descriptor-ownership, ABI-length, callback, signal, or
concurrency contract was found in the audited source state. This is a source review, not a proof
that undefined behavior is impossible. Physical ARM64 Android execution, parser fuzzing, coverage,
sanitizer applicability, package provenance, and the release-authorizing C1/C2 and Gate 1 evidence
remain separate requirements.

In particular, this audit does not select `NativeRuntimeWriter`, qualify ARM64, or promote the
Rust-only package. Production continues to construct `ProcessRuntimeWriter` until the existing
physical-device and writer-transfer gates pass.

## Scope And Method

The starting fixed point was commit `02bc604` on `codex/fluxd-rust-rewrite`. The audit includes the
source correction and tests committed with this document. It covers root-workspace Rust files under
`crates/` and `xtask/`; the excluded `addrsyncd` bridge is outside this workspace audit and remains
outside Rust-only release approval.

The review used actual constructs rather than the broad `unsafe` token, which also matches the
unrelated `DiagnosticState::Unsafe` enum variant. For each construct, the review checked:

1. pointer provenance, alignment, validity, aliasing, and lifetime;
2. initialization before reads or `assume_init`;
3. kernel/FFI structure layout, returned lengths, conversions, and slice bounds;
4. raw descriptor creation, borrowing, transfer, close-on-exec state, and unique ownership;
5. post-`fork` syscall restrictions, process identity, signal target scope, and reap authority;
6. callback synchronicity, cookie lifetime, thread affinity, and shared-state synchronization;
7. descriptor-relative path traversal, symlink handling, atomic publication, and durability; and
8. test-only boundaries that could leak resources, signal unrelated processes, or create false
   qualification evidence.

The source contracts used to interpret these boundaries are pinned in
[the primary-source research note](../research/rust-unsafe-boundary-primary-sources-2026-07.md).
Important anchors include the Rust unsafe-operation rules, `CommandExt::pre_exec`, raw-owned-FD
transfer, Linux `kill(2)`, socket/netlink message contracts, and Bionic's synchronous property-read
callback.

## Exact Census

| Scope | Files | `unsafe { ... }` blocks | `SAFETY:` annotations |
|---|---:|---:|---:|
| Runtime source | 17 | 158 | 161 |
| Qualification/tool source | 5 | 41 | 41 |
| Test modules stored under member `src` trees | 5 | 14 | 14 |
| Integration-test targets | 11 | 51 | 51 |
| **All root-workspace targets** | **38** | **264** | **267** |

The 27 files in member `src` trees account for 213 blocks and 216 annotations. The complete target
set additionally contains one Android `unsafe extern "C" fn` callback, three unsafe foreign blocks,
and no unsafe trait or unsafe impl. Annotation counts are deliberately not treated as proof: the
three additional annotations describe enclosing contracts with more than one unsafe operation.

Reproduce the navigation census with:

```text
rg --count-matches 'unsafe[[:space:]]*\{' crates xtask -g '*.rs'
rg --count-matches 'SAFETY:' crates xtask -g '*.rs'
rg -n 'unsafe[[:space:]]+(extern|fn|trait|impl)' crates xtask -g '*.rs'
```

The workspace also requires `unsafe_op_in_unsafe_fn = "deny"` and
`clippy::undocumented_unsafe_blocks = "deny"`. Those lints are useful mechanical controls but do
not establish that an annotation is true.

## File-Level Inventory

### Runtime Source

| File | Blocks | Boundary and disposition |
|---|---:|---|
| `crates/flux-core/src/config.rs` | 4 | Descriptor-relative `openat`/`fstatat` and unique `OwnedFd`; accepted |
| `crates/flux-platform/src/android_identity.rs` | 9 | `uname` plus synchronous Bionic property callback; accepted source contract, physical ARM64 execution still open |
| `crates/flux-platform/src/child_process.rs` | 15 | pre-exec syscalls, descriptor flags, limits, errno, and signaling; zero signal targets corrected |
| `crates/flux-platform/src/file_observer.rs` | 10 | inotify descriptors, bounded event decoding, watch lifecycle, and directory identity; accepted |
| `crates/flux-platform/src/lib.rs` | 3 | `uname` output and bounded C-string conversion; accepted |
| `crates/flux-platform/src/netlink/policy_routing_session.rs` | 8 | route-netlink socket, sender/length checks, nonblocking send/receive, and poll; accepted |
| `crates/flux-platform/src/netlink/socket.rs` | 14 | fixed receive ring, `recvmmsg`, sender metadata, socket options, and descriptor ownership; accepted |
| `crates/flux-platform/src/process.rs` | 8 | pidfd ownership, non-reaping `waitid`, signal disposition, and initialized kernel outputs; accepted |
| `crates/flux-platform/src/reactor.rs` | 8 | eventfd/epoll creation, wake I/O, event slicing, and synchronized stop phase; accepted |
| `crates/flux-platform/src/seqpacket.rs` | 19 | Unix socket addresses, packet bounds, peer credentials, and accepted/socket FD transfer; accepted |
| `crates/flux-platform/src/shutdown.rs` | 11 | signal-set initialization, thread-affine mask restoration, signalfd reads, and FD transfer; accepted |
| `crates/flux-platform/src/socket_diagnostics/implementation.rs` | 8 | bounded netlink datagrams, exact sender/length validation, and process identity checks; accepted |
| `crates/flux-platform/src/xtables/native.rs` | 3 | pinned tool `openat` ownership and effective-UID inspection; accepted |
| `crates/flux-platform/src/xtables/owner_durable.rs` | 15 | no-follow traversal, raw FD transfer, locks, metadata, rename/unlink, and fsync ordering; accepted |
| `crates/flux-platform/src/xtables/owner_process_adapter.rs` | 4 | interface name/index round-trip through libc; accepted |
| `crates/fluxd/src/intent_store.rs` | 8 | no-follow record I/O and synced atomic publication; accepted |
| `crates/fluxd/src/offline_cleanup.rs` | 11 | daemon lease traversal, ownership metadata, `flock`, and explicit inherited-lock release; accepted |

### Qualification And Tool Source

| File | Blocks | Boundary and disposition |
|---|---:|---|
| `crates/fluxd/src/functional_canary/linux_namespace_harness.rs` | 4 | interface lookup, retained child/group signaling, and bounded pre-exec setup; accepted as mechanism evidence only |
| `crates/fluxd/src/functional_canary/linux_namespace_harness/distinct_uid.rs` | 5 | role-file ownership, group clearing, no-new-privileges, and credential probes; accepted as qualification-only |
| `crates/fluxd/src/functional_canary/linux_namespace_harness/ingress_tproxy/transparent_tcp.rs` | 14 | transparent TCP sockets, exact option lengths, address encoding, and bounded connect poll; accepted as qualification-only |
| `crates/fluxd/src/functional_canary/linux_namespace_harness/ingress_tproxy/transparent_udp.rs` | 17 | aligned ancillary buffer, exact `recvmsg` bounds, CMSG parsing, and socket-address decoding; accepted as qualification-only |
| `xtask/src/android_canary.rs` | 1 | host command process-group cleanup through a matching foreign `kill` declaration; accepted as tool-only |

### Test-Only Source

| File or target | Blocks | Boundary and disposition |
|---|---:|---|
| `crates/flux-platform/src/android_identity/tests.rs` | 1 | WSA root precondition; accepted, x86_64 mechanism evidence only |
| `crates/flux-platform/src/process/tests.rs` | 5 | task-local credential heterogeneity syscalls; accepted in isolated helper |
| `crates/flux-platform/src/socket_diagnostics/tests.rs` | 3 | isolated PID/effective-UID observation; accepted |
| `crates/flux-platform/src/xtables/native_tests.rs` | 4 | owned FD duplication/flags and FIFO fixture; accepted |
| `crates/flux-platform/src/xtables/owner_runtime_tests.rs` | 1 | privileged-test UID precondition; accepted |
| `crates/flux-core/tests/config.rs` | 1 | FIFO rejection fixture; accepted |
| `crates/flux-platform/tests/capability_profile.rs` | 1 | FIFO rejection fixture; accepted |
| `crates/flux-platform/tests/legacy_process_dispatcher.rs` | 2 | retained live child signaling with bounded fallback cleanup; accepted |
| `crates/flux-platform/tests/phase_dispatcher.rs` | 6 | retained child/group signal and absence probes in isolated helpers; accepted |
| `crates/flux-platform/tests/reactor.rs` | 15 | scoped signal actions, live pthread delivery, isolated rlimit failure injection, and mask queries; accepted |
| `crates/flux-platform/tests/seqpacket.rs` | 17 | scoped signal actions, live pthread interruption, and credential probes; accepted |
| `crates/flux-platform/tests/shutdown_signal.rs` | 4 | current-thread signal delivery and initialized mask query; accepted |
| `crates/flux-platform/tests/sing_box_process.rs` | 2 | short-lived isolated descendant cleanup; accepted |
| `crates/fluxd/tests/administrative_intent_store.rs` | 1 | FIFO rejection fixture; accepted |
| `crates/fluxd/tests/daemon_shutdown_signal.rs` | 1 | observed live daemon signal through a matching foreign declaration; accepted |
| `crates/fluxd/tests/offline_cleanup_cli.rs` | 1 | owned lease-file lock fixture; accepted |

Test-only code is classified separately because it does not carry runtime authority. It remains in
scope because an invalid pointer, leaked descriptor, overbroad signal, or malformed canary parser
could corrupt the test process or falsely qualify a mechanism.

## Corrected Finding

### Zero Was An Overbroad Signal Target

`signal_process` converted any `u32` that fit `pid_t`; `signal_process_group` converted and negated
the same input. Neither rejected zero. On Linux and Android, `kill(0, signal)` sends to every process
in the caller's process group for which it has permission. That contradicts both helper names and
the safety annotation that described only a positive PID or negative named process-group ID.

Existing production call sites derive their values from `Child::id()`, and no observed path could
supply zero. The helper boundary was still defective: a future internal caller or malformed
identity could broaden a destructive signal instead of failing closed.

The correction:

- routes single-process IDs through `process_target`, which rejects zero and values outside
  `pid_t`;
- routes signal and existence operations through one `process_group_target`, which rejects zero
  before negation; and
- tests both zero rejection and positive/negative addressing through pure conversion helpers, so a
  regression test can never signal its own test process.

Focused verification:

```text
cargo test -p flux-platform child_process::implementation::tests -- --nocapture
```

Result: 2 passed, 0 failed, with 354 unrelated library tests filtered.

## Accepted Cross-Cutting Invariants

### Initialized Kernel Outputs

Every `MaybeUninit` output is read only after a successful syscall or an exact-size read. Netlink,
seqpacket, signalfd, inotify, and ancillary-data paths validate kernel-returned lengths and flags
before slicing, truncating, dereferencing, or calling `assume_init`. Flexible or potentially
unaligned records use bounded `read_unaligned` operations.

### Descriptor Ownership

Every successful descriptor-producing syscall has one transfer into `OwnedFd` or `File`.
Borrow-only syscalls retain their owner for the complete call. Accepted descriptors use atomic
close-on-exec flags where available; post-fork inheritance is explicitly allowlisted or closed.
Failure paths leave Rust owners to close already-adopted descriptors.

### Netlink And Socket Framing

The route ring owns fixed boxed slabs, iovecs, sender addresses, and headers whose allocations are
not resized while raw pointers are live. `recvmmsg` counts are bounded before metadata/slice access.
`MSG_TRUNC`, `MSG_CTRUNC`, `ENOBUFS`, unexpected senders, short writes, and mismatched address sizes
become typed loss or protocol failures rather than partial authority.

### Process, Signal, And Fork Boundaries

Production child authority is retained through `Child`, start-time identity, positive IDs, pidfds,
and non-reaping wait probes. The pre-exec closures use copied/preallocated state and Linux/Bionic
syscall or TLS errno operations. Signal masks are thread-local and guarded by a deliberately
non-`Send`, non-`Sync` owner. Test helpers retain the relevant child or keep the isolated target
live while issuing destructive signals.

### Android Callback

The Bionic property pointer originates from `__system_property_find`; the property-read callback is
synchronous; its cookie points to a live stack-owned result for the call; and null, duplicate, or
missing callback data fails closed. This source contract cross-builds for the pinned Android target,
and the exact callback path passed once on rooted x86_64 WSA. It remains runtime-unverified on a
physical ARM64 device. The callback copies the property bytes before returning and contains no
user-controlled panic path that could unwind across the non-unwinding C ABI.

### Target-Specific Post-Fork Assumptions

The child setup closure uses only copied or preallocated state, allocation-free error construction,
and syscall/TLS wrappers. Some operations (`setrlimit`, `prctl`, `close_range`, the generic
`syscall` wrapper, and libc errno access) are not on the portable POSIX async-signal-safe list; their
acceptance is explicitly tied to the reviewed Linux/Bionic implementations rather than generalized
to an arbitrary libc. Unsupported `CLOSE_RANGE_CLOEXEC` returns an error and prevents `exec`, so it
cannot silently widen descriptor inheritance. Kernel/profile support remains a qualification and
availability requirement, not an inferred property of a `5.10` version string.

### Paths And Durable State

Configuration, intent, lease, and native-owner paths use descriptor-relative traversal and reject
symlink/non-regular substitutions. Raw metadata is initialized before inspection. Durable
publication writes and syncs a temporary file, renames relative to an owned directory, and syncs
that directory. Writer-lock identities are revalidated by device/inode around replacement races.

## Verification At This Checkpoint

- `cargo test -p flux-platform child_process::implementation::tests -- --nocapture`: 2 passed.
- `cargo clippy -p flux-platform --all-targets --all-features -- -D warnings -D
  clippy::undocumented_unsafe_blocks`: passed.
- `cargo test -p flux-platform --all-targets --all-features --no-fail-fast`: the library passed 352
  tests with four privileged ignores, and every integration-test target passed.
- `TMPDIR=/tmp cargo xtask ci`: passed the complete host workspace, documentation, strict Clippy,
  and pinned Android/API-31 cross-check gates.
- `FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux`: the exact disposable
  dual-stack topology/cleanup checkpoint passed once with 298 unrelated tests filtered.
- The pinned x86_64 Android test ELF had four `PT_LOAD` segments aligned to `0x4000`. On rooted WSA
  Android 13/API 33 with a 4096-byte runtime page size, the exact Bionic identity/property test
  passed once with 343 unrelated tests filtered. The private remote directory was removed and an
  exact absence probe confirmed cleanup. This is x86_64 mechanism evidence only.
- The navigation census reconciled to 38 files, 264 unsafe blocks, 267 annotations, one unsafe
  callback, three unsafe foreign blocks, and no unsafe trait or impl. All 50 primary-source URLs
  returned HTTP 200 and the note's 50 definitions, citations, catalog entries, and unique URLs
  reconcile exactly.

## Residual Risk And Re-Audit Triggers

This review must be repeated when any of the following changes:

- an unsafe block, unsafe callable, foreign declaration, unsafe trait, or unsafe impl is added or
  materially edited;
- `libc`, Rust, the pinned NDK/API level, supported kernel ABI, or Android property API changes;
- a raw descriptor changes ownership type or crosses a thread, callback, fork, or process boundary;
- a kernel-returned length, count, flag, sender identity, or structure layout gains a new consumer;
- signal targeting, child identity, pidfd/reap authority, or pre-exec behavior changes;
- a qualification harness gains authority, stops using disposable isolation, or starts mutating a
  physical device; or
- `NativeRuntimeWriter` becomes eligible for production selection.

Open work is intentionally not hidden by this checkpoint: fuzz the exposed parsers and retain a
crash corpus, add coverage visibility, assess target-applicable sanitizer tooling, require the real
production-composition namespace job, complete package SBOM/provenance/reproducibility, and run C1/
C2 plus Gate 1 on rooted physical ARM64 hardware.
