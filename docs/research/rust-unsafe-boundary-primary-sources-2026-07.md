# Primary-source contracts for Flux's Rust unsafe boundary

- Status: audit source pack; not an audit verdict
- Flux code context inspected: root workspace at `02bc604d867ee0114eb43f8e16680d761530b3a9`
  plus the active working-tree changes present on 2026-07-26
- Rust contract version: 1.93.0, edition 2024
- External sources accessed: 2026-07-26
- Source policy: official Rust documentation/source, Linux kernel documentation and Linux
  man-pages, AOSP/Bionic/kernel source, and Android/NDK documentation only

This note gives the unsafe-boundary audit a primary-source baseline. A safety comment is adequate
only when it discharges the contract below for the exact pointer, buffer, descriptor, thread,
process, kernel, and Android API level involved. The note deliberately separates documented
contracts from implementation evidence; a source inspection of one Bionic revision is not a
portable promise for glibc, musl, another Bionic revision, or a vendor kernel.

## High-signal audit consequences

1. An `unsafe` block says that its unchecked obligations have been discharged; it does not make
   the operation correct. Flux's `unsafe_op_in_unsafe_fn = "deny"` and
   `undocumented_unsafe_blocks = "deny"` improve locality and reviewability, but neither lint proves
   pointer validity, initialization, ownership, ABI layout, or syscall semantics. [R-UNSAFE]
   [R-OPERATIONS] [R-2024]
2. `CommandExt::pre_exec` runs after `fork` in a potentially multithreaded process. Rust explicitly
   excludes ordinary allocation, environment access, and mutex acquisition and requires the hook
   to respect the target's async-signal-safety rules. [R-PREEXEC]
3. The POSIX/Linux async-signal-safe list includes `fcntl`, `getpid`, `getppid`, `kill`, `setpgid`,
   and `sigprocmask`, but it does not list `setrlimit`, `prctl`, `close_range`, the generic
   `syscall` wrapper, or libc errno accessors. The latter operations therefore need target-specific
   implementation evidence or removal from the post-`fork` hook; “it is a syscall” is not by itself
   the portable Rust contract. [L-SIGNAL-SAFETY]
4. Upstream Linux v5.10 has `close_range` but not `CLOSE_RANGE_CLOEXEC`; man-pages records that flag
   as Linux 5.11. AOSP's current `android12-5.10` common kernel contains the flag and implementation
   as a backport. Flux may rely on it only for a qualified kernel profile or must define handling
   for `EINVAL`/`ENOSYS`; a `5.10` version string alone is insufficient. [K-CLOSE-V510]
   [L-CLOSE-RANGE] [A-KERNEL-CLOSE]
5. A raw descriptor becomes a Rust owner only after the creating syscall has returned a
   nonnegative, newly owned descriptor. `OwnedFd::from_raw_fd`/`File::from_raw_fd` must receive that
   ownership exactly once; the owner closes it on drop. [R-OWNEDFD] [R-FROMRAWFD]
6. With input `MSG_TRUNC`, `recvmsg`/`recvmmsg` can report the real datagram length even when that
   length exceeds the writable buffer. Only the buffer capacity was initialized. A parser must
   quarantine the datagram before constructing a slice to the reported length. [L-RECVMSG]
   [L-RECVMMSG]
7. Netlink kernel-sender validation belongs to the returned `sockaddr_nl`: kernel port ID is zero.
   `nlmsghdr.nlmsg_pid` and `nlmsg_seq` are opaque to the netlink core and are not a transport
   authentication boundary. Kernel multicast messages can legitimately have a nonzero returned
   group mask. [L-NETLINK]
8. `O_NOFOLLOW` rejects a symlink only in the final pathname component. A directory-descriptor walk
   must apply it at every component, and a prior `fstatat` observation does not pin the later opened
   object. Descriptor-based verification is the stable boundary. [L-OPEN] [L-STAT]
9. `flock` locks attach to an open file description. Forked or duplicated descriptors share the
   same lock, and `FD_CLOEXEC` closes only at `exec`, not at `fork`; therefore a child can retain a
   guard during its pre-exec interval. [L-FLOCK] [L-OPEN]
10. Signal masks are per-thread. For process-directed `SIGINT`/`SIGTERM` to be consumed exclusively
    through `signalfd`, the signals must be blocked before worker creation (so new threads inherit
    the mask), and child processes normally need to unblock them before `exec`. [L-SIGNAL]
    [L-PTHREAD-MASK] [L-SIGNALFD]
11. Bionic's property callback passes a mutable property's value from a stack buffer and invokes
    the callback synchronously in the inspected implementation. Rust must copy `name`/`value`
    during the callback and must not let a panic or foreign unwind cross the non-unwinding `"C"`
    ABI. [A-PROP-HEADER] [A-PROP-IMPL] [R-UNWIND]
12. `__system_property_read_callback` is an API-26 symbol. Flux's current NDK API 31 target is above
    that floor, but the floor is a load-time ABI requirement, not a runtime branch: Android native
    symbols newer than `minSdkVersion` can prevent loading unless weak lookup or `dlsym` is used.
    [A-LIBC-MAP] [A-SDK-VERSIONS]

## Flux call-site map

| Contract family | Principal production call sites |
|---|---|
| post-`fork`, signal targets, close-range inheritance | `crates/flux-platform/src/child_process.rs` |
| raw descriptor creation and ownership transfer | `seqpacket.rs`, `reactor.rs`, `shutdown.rs`, `process.rs`, `file_observer.rs`, `netlink/socket.rs`, `netlink/policy_routing_session.rs`, `socket_diagnostics/implementation.rs`, `xtables/native.rs`, `xtables/owner_durable.rs` |
| `recvmsg`/`recvmmsg`, netlink address and framing | `netlink/socket.rs`, `netlink/policy_routing_session.rs`, `socket_diagnostics/implementation.rs` |
| UNIX credentials and message truncation | `seqpacket.rs` |
| dirfd traversal, no-follow checks, durable locks | `file_observer.rs`, `xtables/native.rs`, `xtables/owner_durable.rs` |
| signal mask and `signalfd` lifetime | `shutdown.rs`, `reactor.rs`, `crates/fluxd/src/daemon.rs` |
| Android C callback and property pointers | `android_identity.rs` |

## 1. Rust language and standard-library contracts

### Unsafe operations and proof boundaries

- Rust defines unsafe operations to include calling an unsafe function, dereferencing a raw
  pointer, reading or writing an unsafe external static, accessing a union field, implementing an
  unsafe trait, and declaring an external block. An unsafe block merely permits those operations.
  [R-OPERATIONS]
- By writing `unsafe { ... }`, the programmer states that every relevant extra safety condition in
  the block has been satisfied. Review should therefore keep the block small enough that its safety
  comment can identify every required invariant and the check or owner that establishes it.
  [R-UNSAFE]
- Edition 2024 requires explicit unsafe blocks inside `unsafe fn` when the
  `unsafe_op_in_unsafe_fn` lint is enabled; Flux promotes this to `deny`. This separates the caller's
  obligation from the implementation's own unsafe operations but does not discharge either.
  [R-2024]

### `unsafe extern` and ABI

- Edition 2024 semantically requires `unsafe extern`. The declarer is responsible for the accuracy
  of every foreign signature; a wrong type, calling convention, nullability assumption, or symbol
  availability can cause undefined behavior. Foreign functions are implicitly unsafe unless an
  item is explicitly marked `safe`. [R-UNSAFE] [R-EXTERN]
- `extern "C"` selects the target's dominant C compiler ABI. `#[repr(C)]` is the Rust layout tool
  intended for C interoperability. Both are target-specific: a Linux-host layout is not evidence
  for an Android target. [R-EXTERN] [R-REPR-C]
- `"C"` is a non-unwinding ABI. A Rust panic reaching it aborts with `panic=unwind`; an unforced
  native unwind crossing it is undefined behavior. FFI callbacks should be panic-free and should
  translate fallible work into data owned on the Rust side. [R-UNWIND]

### Initialization and C strings

- `MaybeUninit::assume_init` requires the value to be fully initialized. A syscall output structure
  may be assumed initialized only on the success return documented for that syscall and, for
  variable-sized outputs, only for the returned length. Zeroing storage before the call does not
  expand what the kernel promises to initialize. [R-MAYBEUNINIT]
- `CStr::from_ptr` requires a non-null pointer to a valid NUL-terminated byte sequence contained in
  one allocation and valid for the returned borrow. The callback or syscall contract must establish
  those facts; the Rust type of the raw pointer does not. [R-CSTR]

## 2. `CommandExt::pre_exec` and the post-`fork` child

Rust documents the closure as running after `fork`, immediately before `exec`. Other threads may
have held allocator or library locks at the instant of `fork`; consequently `malloc`, environment
access, mutex acquisition, and similar ordinary Rust/library work are not guaranteed to work.
Rust also warns that duplicated descriptors and mappings must not be used in a way that violates
library invariants. `Error::new` and `Error::other` are explicitly identified as allocating.
[R-PREEXEC]

### Operation classification

| Operation used by Flux | Primary-source status in the post-`fork` interval |
|---|---|
| `fcntl`, `getpid`, `getppid`, `kill`, `setpgid`, `sigprocmask` | Listed by Linux man-pages as POSIX async-signal-safe. [L-SIGNAL-SAFETY] |
| `close_range(..., CLOSE_RANGE_CLOEXEC)` via `syscall` | Linux-specific and absent from the POSIX list. The syscall marks the inclusive range rather than closing it, but support for the flag is kernel-dependent. [L-CLOSE-RANGE] |
| `prctl(PR_SET_PDEATHSIG, ...)` | Linux-specific and absent from the POSIX list. Its parent is the creating **thread**, and no signal is generated if that parent has already died before arming. [L-PDEATHSIG] |
| `setrlimit` | MT-safe is not async-signal-safe. It is absent from the POSIX safe list; on glibc the wrapper has called `prlimit64` since glibc 2.13. [L-SIGNAL-SAFETY] [L-RLIMIT] |
| Bionic `setrlimit`, `prctl`, `setpgid`, `kill`, `getppid`, `close_range` | In the pinned Bionic revision these are generated syscall stubs. This is useful Android implementation evidence, not a cross-libc contract. [A-SYSCALLS] [A-GENSYSCALLS] |
| Bionic `fcntl(F_GETFD/F_SETFD)` | The pinned wrapper delegates to its syscall stub; its descriptor-tracking branch applies to duplication commands. Invalid `F_SETFD` bits can call the fortify fatal path, so the integer precondition remains material. [A-FCNTL] |
| Bionic `getpid` and `__errno` | The pinned source reads Bionic thread state, with `getpid` falling back to the kernel while forking and `__errno` returning the current thread's errno slot. This remains revision-specific implementation evidence. [A-GETPID] [A-ERRNO] |

The narrow audit rule is: no allocation, formatting, logging, environment access, locking, lazy
initialization, or destructor-dependent cleanup in the closure. Captures must be copied or fully
allocated before `fork`; error construction must use the API's post-fork-safe path. A target-specific
wrapper assumption should cite the exact libc revision and architecture or be replaced with a
documented safe primitive.

### Process setup contracts

- `setpgid(0, 0)` makes the calling process its own process-group leader; the process group survives
  `exec`. [L-SETPGID]
- `PR_SET_PDEATHSIG` is cleared in a child of `fork`, so the spawned child must arm it itself. Since
  it is not retroactive, the documented race is closed by recording the expected parent before
  `fork`, arming in the child, then comparing `getppid`; the comparison also needs the creating-thread
  semantics in its threat model. [L-PDEATHSIG]
- `close_range(first, last, CLOSE_RANGE_CLOEXEC)` treats both ends as inclusive and only marks the
  descriptors close-on-exec. It does not close them during the pre-exec interval. [L-CLOSE-RANGE]
- `RLIMIT_NOFILE` is one greater than the maximum descriptor number. The soft limit may be raised
  only up to the hard limit without privilege; raising the hard limit requires capability. Resource
  limits are preserved across `exec`. [L-RLIMIT]

## 3. PID and process-group signaling

`kill` interprets its target by sign: [L-KILL]

| `pid` argument | Target |
|---|---|
| `> 0` | the process whose PID equals `pid` |
| `0` | every process in the caller's process group |
| `-1` | every permitted process except the documented exclusions |
| `< -1` | every process in process group `-pid` |

Signal zero sends no signal but performs existence and permission checks. Success means the target
existed and was permitted at that instant; `EPERM` also proves at least one target exists but is not
permitted, while `ESRCH` means the process or group does not exist. This probe is inherently racy,
and a zombie/PID-reuse boundary needs separate handling. A Rust conversion layer should reject zero,
values outside `pid_t`, and negation overflow before calling `kill`. [L-KILL]

For an existing process, `pidfd_open(pid, 0)` returns a close-on-exec descriptor referring to the
task or fails, including `ESRCH`. A pidfd is pollable for exit and avoids later operations being
retargeted merely because the numeric PID was recycled. [L-PIDFD]

## 4. File-descriptor creation and Rust ownership

`OwnedFd` closes its descriptor on drop and promises unique close responsibility. Its
`FromRawFd` implementation requires an open resource suitable for ownership whose only cleanup is
`close`. The generic `FromRawFd` contract likewise requires an owned, open descriptor.
[R-OWNEDFD] [R-FROMRAWFD]

| Creating call in Flux | Success and flag contract |
|---|---|
| `openat` | Returns a nonnegative descriptor for a new open file description. `O_CLOEXEC` is atomic. A `mode` argument is mandatory with `O_CREAT`/`O_TMPFILE`; omitting it uses arbitrary stack bytes as mode. [L-OPEN] |
| `socket` | Returns a new descriptor; `SOCK_CLOEXEC` and `SOCK_NONBLOCK` set state atomically. [L-SOCKET] |
| `accept4` | Returns a new connected-socket descriptor and leaves the listener unaffected; its flags atomically set CLOEXEC/nonblocking state. [L-ACCEPT] |
| `eventfd` | Returns a new descriptor; `EFD_CLOEXEC` and `EFD_NONBLOCK` apply to it. [L-EVENTFD] |
| `epoll_create1` | Returns a nonnegative descriptor; `EPOLL_CLOEXEC` applies to it. [L-EPOLL-CREATE] |
| `inotify_init1` | Returns a new descriptor; `IN_CLOEXEC` and `IN_NONBLOCK` apply to it. [L-INOTIFY-INIT] |
| `signalfd(-1, ...)` | Returns a new descriptor; passing an existing signalfd updates and returns that same descriptor, so only the `-1` form creates ownership. [L-SIGNALFD] |
| `pidfd_open` | Returns a nonnegative descriptor with close-on-exec already set. [L-PIDFD] |

For each path, the auditable sequence is: call; reject the documented negative/error result; transfer
the successful descriptor exactly once into `OwnedFd` or `File`; use `BorrowedFd`/`AsFd` for later
borrows; never independently `close` the transferred raw integer. Wrapping immediately also ensures
that later setup failures close the descriptor through RAII. Atomic CLOEXEC creation avoids the
multithreaded open-then-`fcntl` inheritance race documented by `open(2)`. [L-OPEN]

## 5. `recvmsg`, `recvmmsg`, ancillary data, and netlink

### Receive-buffer contract

- Before `recvmsg`, the caller supplies writable `iovec` regions, the capacity of the optional
  address buffer in `msg_namelen`, and the capacity of the optional control buffer in
  `msg_controllen`. On success, the kernel updates the returned address length, control length, and
  output `msg_flags`. [L-RECVMSG]
- `recvmmsg` applies the same contract independently to an array of `mmsghdr`. It returns the number
  of entries updated; only those entries may be consumed. Each updated `msg_len` is the value a
  single `recvmsg` would have returned. Reused headers must have input capacities and output fields
  reset before the next call. [L-RECVMMSG]
- Input `MSG_TRUNC` requests the real packet/datagram size for netlink, UNIX datagram, and UNIX
  seqpacket sockets even when the supplied data buffer is shorter. Output `MSG_TRUNC` says trailing
  bytes were discarded. Correct code treats either `reported_length > capacity` or the output flag
  as truncation and never indexes the storage with the oversized reported length. [L-RECVMSG]
- The returned `msg_namelen` is kernel output. Code must validate the exact expected address size and
  family before reading a custom `#[repr(C)]` address structure; zero-initializing the destination is
  defensive but is not a substitute for that length check. [L-RECVMSG] [R-MAYBEUNINIT]

### Ancillary data

- Ancillary data is a sequence of `cmsghdr` records. It must be traversed with
  `CMSG_FIRSTHDR`/`CMSG_NXTHDR`; bounds use `CMSG_LEN`/`CMSG_SPACE`. `CMSG_DATA` is not guaranteed
  suitably aligned for an arbitrary payload type, so copy bytes into an aligned object rather than
  creating a typed reference. [L-CMSG]
- If `msg_control` is null or too small, ancillary data is discarded/truncated and output
  `MSG_CTRUNC` is set. Any decision-bearing ancillary channel must classify this as incomplete
  evidence. [L-UNIX] [L-RECVMSG]
- `SO_PEERCRED` is not per-message ancillary data: it returns credentials captured at
  `connect`, `listen`, or `socketpair` time. `SCM_CREDENTIALS` is per-message ancillary data and
  requires `SO_PASSCRED`. Flux's seqpacket authorization must preserve that distinction. [L-UNIX]
- `SCM_RIGHTS` transfers references to open file descriptions and installs descriptors in the
  receiver. A future Rust receiver must validate the complete control record and transfer every
  accepted descriptor into one owner exactly once. [L-UNIX] [R-FROMRAWFD]

### Netlink sender, framing, and loss

- `sockaddr_nl.nl_pid` identifies a netlink **socket**, not necessarily a process. Destination port
  zero means the kernel. Multiple sockets in one process can have different automatically allocated
  port IDs. The source address returned by `recvmsg` is therefore the transport-level sender
  evidence; an exact `sockaddr_nl` with port ID zero identifies the kernel. [L-NETLINK]
- `nlmsghdr.nlmsg_pid` and `nlmsg_seq` are opaque to the netlink core. They can support protocol
  correlation after framing validation, but must not replace source-address validation.
  [L-NETLINK]
- One datagram can contain multiple messages. `nlmsg_len` includes the message header. Parsing must
  enforce a complete header, minimum length, length no greater than the remaining datagram, and
  aligned progress equivalent to `NLMSG_OK`/`NLMSG_NEXT`; `NLMSG_DONE` terminates a multipart dump.
  [L-NETLINK] [L-NETLINK-MACROS]
- Attribute length also includes its header but excludes alignment padding; netlink attributes are
  aligned to four bytes. Attribute order is not guaranteed. [K-NETLINK-INTRO]
- Kernel-to-user notifications are not reliable. `ENOBUFS` means userspace and kernel state may
  have diverged and requires resynchronization. A dump carrying `NLM_F_DUMP_INTR` may be
  inconsistent and should be retried. Disabling `ENOBUFS` reporting removes evidence; it does not
  make delivery reliable. [L-NETLINK] [K-NETLINK-INTRO]

## 6. Dirfd traversal, no-follow behavior, and `flock`

- A relative `openat`/`fstatat` path is resolved from `dirfd`. An open directory descriptor remains
  a stable reference even if the directory is renamed, which is why the `*at` family can avoid
  current-working-directory and prefix-substitution races. [L-OPEN] [L-STAT]
- `O_NOFOLLOW` protects only the trailing component; earlier symlinks are followed. A component-wise
  walk needs `O_NOFOLLOW | O_DIRECTORY` for each opened directory. Without `O_PATH`, a final symlink
  fails with `ELOOP`. [L-OPEN]
- `fstatat(..., AT_SYMLINK_NOFOLLOW)` reports the link itself instead of dereferencing it. It is a
  point-in-time pathname observation. If identity matters across a later operation, open first and
  verify the descriptor (`fstat`/Rust metadata), or compare stable device/inode identity after open.
  Only a zero return initializes the output `stat`. [L-STAT]
- `O_CREAT` requires the variadic mode argument; `O_CREAT | O_EXCL` is the atomic create boundary.
  `O_CLOEXEC` should be supplied in the creating call. [L-OPEN]
- Linux `flock` locks are advisory and associated with an open file description. `dup` and `fork`
  references share the lock; any duplicate can modify/unlock it, and it is released only on
  `LOCK_UN` or after all referring descriptors close. Locks survive `exec`. With `LOCK_NB`, a
  conflict returns `EWOULDBLOCK`. Filesystem-specific NFS/SMB semantics can differ from local
  advisory behavior. [L-FLOCK]

## 7. Signal masks and `signalfd`

- Every thread has an independent signal mask. `pthread_sigmask` is the specified API in a
  multithreaded program; `sigprocmask` use there is unspecified. A new thread inherits its creator's
  mask. `pthread_sigmask` returns an error number directly rather than setting the usual `-1`/errno
  result. [L-SIGNAL] [L-SIGPROCMASK] [L-PTHREAD-MASK]
- `signalfd` normally requires its selected signals to be blocked so their default dispositions do
  not consume them. To make a signalfd the sole receiver of process-directed shutdown signals,
  block them before creating other threads; otherwise the kernel may deliver a process-directed
  signal to an arbitrary thread that has it unblocked. [L-SIGNALFD] [L-SIGNAL]
- A `signalfd` read buffer must hold at least one complete `signalfd_siginfo`. The return value is the
  total byte count; consuming one record is sound only after an exact-size read. Nonblocking reads
  return `EAGAIN` when none is pending. [L-SIGNALFD]
- A child inherits its parent's signal mask at `fork`, and the mask survives `exec`. The signalfd
  documentation explicitly recommends unblocking signals in a child before executing a helper that
  expects ordinary signal behavior. [L-SIGNAL] [L-SIGNALFD]
- A signalfd descriptor is inherited across `fork` and remains open across `exec` unless CLOEXEC.
  Its mask guard must be restored on the same thread whose mask it changed; Rust thread affinity is
  a type/lifetime invariant, not merely a convenience. [L-SIGNALFD]

## 8. Android/Bionic property callback and target ABI

### Public property API

- `prop_info` is opaque. `__system_property_find` returns a pointer or null and explicitly recommends
  caching a successful result; callers should pass it back to Bionic rather than inspect its layout.
  [A-PROP-HEADER]
- `__system_property_read_callback` calls one callback with a consistent `(name, value, serial)`
  trio and a caller cookie. It is available since API 26. The C declaration marks the property,
  callback, name, and value nonnull, while the cookie may be null. [A-PROP-HEADER] [A-LIBC-MAP]
- The pinned Bionic implementation calls the callback before returning. Read-only properties pass
  pointers from the property area; mutable properties pass a local `char value_buf[PROP_VALUE_MAX]`.
  Consequently Rust may borrow the C strings only during the callback and must copy any retained
  bytes before it returns. Read-only long properties are not bounded by the legacy 92-byte value
  buffer, so an application-level bound must be checked after copying. [A-PROP-IMPL]
- A null result from `__system_property_find` does not prove semantic absence in all contexts. The
  pinned implementation also returns null when it cannot obtain a property area for the name and
  logs an access-denied warning. Callers that need to distinguish unavailable from absent require
  separate platform evidence. [A-PROP-IMPL]

### Rust declaration and callback obligations

The Rust declaration must exactly match Bionic: `const prop_info*`, a `void`-returning C callback,
`void*` cookie, two `const char*` arguments, and `uint32_t` serial. An opaque Rust pointee must never
be constructed or dereferenced. The callback cookie must point to a live, uniquely borrowed result
for the full synchronous call; returned string pointers must pass the `CStr::from_ptr` requirements;
and the callback must not unwind. [A-PROP-HEADER] [R-CSTR] [R-UNWIND]

### Android/NDK boundary

- Rust 1.93 officially supports `aarch64-linux-android` and `x86_64-linux-android` and requires an
  Android NDK for cross-compilation. Android maps these to the `arm64-v8a` and `x86_64` native ABIs;
  ABI covers calling convention, data layout, ELF format, and instruction set. [R-ANDROID]
  [A-NDK-ABIS]
- Native API availability is governed by the NDK minimum API. Newer directly linked symbols are
  resolved at load time; an unused runtime branch does not make an unavailable symbol safe.
  `__system_property_read_callback` therefore requires API 26 or an explicit weak/dynamic lookup.
  Flux currently selects the API-31 NDK linker, which satisfies this symbol floor. [A-SDK-VERSIONS]
  [A-LIBC-MAP]
- Use Android-target `libc` types and Bionic/UAPI headers for `pid_t`, `socklen_t`, `sigset_t`,
  `msghdr`, `mmsghdr`, `sockaddr_nl`, `stat`, and `signalfd_siginfo`. Custom `#[repr(C)]` mirrors
  should have target-compiled size/alignment assertions and field-level tests; host Linux success is
  not Android ABI evidence. [R-REPR-C] [A-NDK-ABIS]
- NDK symbol availability and kernel syscall availability are independent. A raw syscall avoids a
  missing Bionic wrapper but can still fail with `ENOSYS`, or with `EINVAL` for an unsupported flag;
  an Android common-kernel backport does not prove the same feature exists in every vendor kernel.
  [A-SDK-VERSIONS] [L-CLOSE-RANGE] [A-KERNEL-CLOSE]

ELF 16 KiB load-segment alignment is a release ABI gate, but it does not change the pointer,
descriptor, callback, or syscall contracts in this note; it is covered separately by
`docs/research/android-16kb-elf-compatibility-2026-07.md`.

## Audit checklist derived from the sources

- Every unsafe block names the exact success check, initialized byte range, pointer lifetime,
  alignment, aliasing state, descriptor owner, or ABI assertion that discharges it.
- Every `assume_init` is dominated by a documented full-initialization success return; partial or
  variable-length outputs are represented as bytes until validated.
- Every descriptor-returning call rejects failure before a single ownership transfer and requests
  CLOEXEC atomically where available.
- Every receive path validates returned length, output flags, source-address length/family, and
  buffer capacity before slicing or typed reads.
- Every netlink parser validates the transport sender separately from header sequence/port fields,
  validates aligned message/attribute progress, and turns truncation, `ENOBUFS`, and interrupted
  dumps into resynchronization rather than partial truth.
- Every dirfd walk applies no-follow protection component by component and verifies the opened
  descriptor when a pre-open pathname observation can race.
- Every `flock` design accounts for forked duplicates and treats the lock as advisory cooperation.
- Shutdown signals are blocked before threads are created, the mask guard stays on its installing
  thread, and every helper child restores the intended mask before `exec`.
- The Bionic property callback copies values synchronously, never retains callback pointers, never
  unwinds, and enforces API 26+ at link/package qualification.
- Every post-`fork` operation is either on the documented async-signal-safe list or tied to exact
  target-libc implementation evidence and a maintained compatibility gate.

## Primary-source index

All links below were checked on 2026-07-26. The rendered Linux pages identify Linux man-pages 6.18;
versioned Rust links match Flux's pinned 1.93.0 toolchain. AOSP links use immutable commits unless a
versioned official guide is the source of the contract.

### Rust

- [R-UNSAFE]: Rust Reference, `unsafe` keyword and proof obligations.
- [R-OPERATIONS]: Rust Reference, unsafe operations.
- [R-2024]: Rust Edition Guide, `unsafe_op_in_unsafe_fn` in edition 2024.
- [R-EXTERN]: Rust Reference, external blocks, implicit unsafety, and ABI strings.
- [R-REPR-C]: Rust Reference, C representation and layout.
- [R-UNWIND]: Rust Reference, unwinding across ABI boundaries.
- [R-PREEXEC]: Rust standard library, Unix `CommandExt::pre_exec` safety contract.
- [R-OWNEDFD]: Rust standard library, `OwnedFd` ownership and drop behavior.
- [R-FROMRAWFD]: Rust standard library, `FromRawFd` safety contract.
- [R-MAYBEUNINIT]: Rust standard library, `MaybeUninit::assume_init`.
- [R-CSTR]: Rust standard library, `CStr::from_ptr`.
- [R-ANDROID]: Rust platform support, Android targets and NDK requirement.

### Linux kernel and Linux man-pages

- [L-SIGNAL-SAFETY]: `signal-safety(7)` async-signal-safe function list.
- [L-KILL]: `kill(2)` PID/process-group and signal-zero semantics.
- [L-CLOSE-RANGE]: `close_range(2)` inclusive range and CLOEXEC history.
- [K-CLOSE-V510]: upstream Linux v5.10 UAPI `close_range.h` (no CLOEXEC flag).
- [L-PDEATHSIG]: `PR_SET_PDEATHSIG(2const)` parent-thread and race semantics.
- [L-SETPGID]: `setpgid(2)` zero arguments and process-group inheritance.
- [L-RLIMIT]: `getrlimit(2)`/`setrlimit(2)`, `RLIMIT_NOFILE`, and glibc wrapper note.
- [L-PIDFD]: `pidfd_open(2)` descriptor and task-lifetime contract.
- [L-OPEN]: `open(2)`/`openat(2)`, mode, dirfd, CLOEXEC, and no-follow semantics.
- [L-STAT]: `stat(2)`/`fstatat(2)` and `AT_SYMLINK_NOFOLLOW`.
- [L-FLOCK]: `flock(2)` open-file-description, fork, exec, and advisory semantics.
- [L-SOCKET]: `socket(2)` descriptor and atomic type flags.
- [L-ACCEPT]: `accept4(2)` new-descriptor and flag semantics.
- [L-EVENTFD]: `eventfd(2)` descriptor and flags.
- [L-EPOLL-CREATE]: `epoll_create1(2)` descriptor and CLOEXEC flag.
- [L-INOTIFY-INIT]: `inotify_init1(2)` descriptor and flags.
- [L-RECVMSG]: `recvmsg(2)`, mutable `msghdr`, lengths, and truncation flags.
- [L-RECVMMSG]: `recvmmsg(2)`, updated entry count and per-message length.
- [L-CMSG]: `cmsg(3)`, ancillary traversal, sizing, and alignment.
- [L-UNIX]: `unix(7)`, credentials, descriptor passing, and ancillary truncation.
- [L-NETLINK]: `netlink(7)`, sender addresses, framing, and loss.
- [L-NETLINK-MACROS]: `netlink(3)`, `NLMSG_*` parsing macros.
- [K-NETLINK-INTRO]: kernel userspace API, netlink introduction, lengths, padding, dump retry.
- [L-SIGNAL]: `signal(7)`, per-thread masks and fork/exec inheritance.
- [L-SIGPROCMASK]: `sigprocmask(2)`, mask operations and multithread caveat.
- [L-PTHREAD-MASK]: `pthread_sigmask(3)`, return convention and thread inheritance.
- [L-SIGNALFD]: `signalfd(2)`, blocking, reads, inheritance, and child-unblock guidance.

### AOSP, Bionic, and Android NDK

- [A-PROP-HEADER]: Bionic `sys/system_properties.h` at
  `731631f300090436d7f5df80d50b6275c8c60a93`.
- [A-PROP-IMPL]: Bionic property implementation at the same immutable commit.
- [A-LIBC-MAP]: Bionic exported-symbol map showing API-26 introduction.
- [A-SYSCALLS]: Bionic generated-syscall declaration list.
- [A-GENSYSCALLS]: Bionic syscall-stub generator and architecture templates.
- [A-FCNTL]: Bionic `fcntl` wrapper.
- [A-GETPID]: Bionic `getpid` implementation and fork fallback.
- [A-ERRNO]: Bionic `__errno` implementation.
- [A-KERNEL-CLOSE]: AOSP `android12-5.10` common-kernel close-range backport, pinned at
  `e59730e07782e4e983f4a3213a46f89f1811cffc`.
- [A-NDK-ABIS]: Android NDK ABI definitions.
- [A-SDK-VERSIONS]: Android NDK minimum API and native symbol availability.

[R-UNSAFE]: https://doc.rust-lang.org/1.93.0/reference/unsafe-keyword.html
[R-OPERATIONS]: https://doc.rust-lang.org/1.93.0/reference/unsafety.html
[R-2024]: https://doc.rust-lang.org/1.93.0/edition-guide/rust-2024/unsafe-op-in-unsafe-fn.html
[R-EXTERN]: https://doc.rust-lang.org/1.93.0/reference/items/external-blocks.html
[R-REPR-C]: https://doc.rust-lang.org/1.93.0/reference/type-layout.html#the-c-representation
[R-UNWIND]: https://doc.rust-lang.org/1.93.0/reference/items/functions.html#unwinding
[R-PREEXEC]: https://doc.rust-lang.org/1.93.0/std/os/unix/process/trait.CommandExt.html#method.pre_exec
[R-OWNEDFD]: https://doc.rust-lang.org/1.93.0/std/os/fd/struct.OwnedFd.html
[R-FROMRAWFD]: https://doc.rust-lang.org/1.93.0/std/os/fd/trait.FromRawFd.html
[R-MAYBEUNINIT]: https://doc.rust-lang.org/1.93.0/std/mem/union.MaybeUninit.html#method.assume_init
[R-CSTR]: https://doc.rust-lang.org/1.93.0/std/ffi/struct.CStr.html#method.from_ptr
[R-ANDROID]: https://doc.rust-lang.org/1.93.0/rustc/platform-support/android.html

[L-SIGNAL-SAFETY]: https://man7.org/linux/man-pages/man7/signal-safety.7.html
[L-KILL]: https://man7.org/linux/man-pages/man2/kill.2.html
[L-CLOSE-RANGE]: https://man7.org/linux/man-pages/man2/close_range.2.html
[K-CLOSE-V510]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/close_range.h?h=v5.10
[L-PDEATHSIG]: https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html
[L-SETPGID]: https://man7.org/linux/man-pages/man2/setpgid.2.html
[L-RLIMIT]: https://man7.org/linux/man-pages/man2/getrlimit.2.html
[L-PIDFD]: https://man7.org/linux/man-pages/man2/pidfd_open.2.html
[L-OPEN]: https://man7.org/linux/man-pages/man2/open.2.html
[L-STAT]: https://man7.org/linux/man-pages/man2/stat.2.html
[L-FLOCK]: https://man7.org/linux/man-pages/man2/flock.2.html
[L-SOCKET]: https://man7.org/linux/man-pages/man2/socket.2.html
[L-ACCEPT]: https://man7.org/linux/man-pages/man2/accept.2.html
[L-EVENTFD]: https://man7.org/linux/man-pages/man2/eventfd.2.html
[L-EPOLL-CREATE]: https://man7.org/linux/man-pages/man2/epoll_create.2.html
[L-INOTIFY-INIT]: https://man7.org/linux/man-pages/man2/inotify_init.2.html
[L-RECVMSG]: https://man7.org/linux/man-pages/man2/recvmsg.2.html
[L-RECVMMSG]: https://man7.org/linux/man-pages/man2/recvmmsg.2.html
[L-CMSG]: https://man7.org/linux/man-pages/man3/cmsg.3.html
[L-UNIX]: https://man7.org/linux/man-pages/man7/unix.7.html
[L-NETLINK]: https://man7.org/linux/man-pages/man7/netlink.7.html
[L-NETLINK-MACROS]: https://man7.org/linux/man-pages/man3/netlink.3.html
[K-NETLINK-INTRO]: https://docs.kernel.org/userspace-api/netlink/intro.html
[L-SIGNAL]: https://man7.org/linux/man-pages/man7/signal.7.html
[L-SIGPROCMASK]: https://man7.org/linux/man-pages/man2/sigprocmask.2.html
[L-PTHREAD-MASK]: https://man7.org/linux/man-pages/man3/pthread_sigmask.3.html
[L-SIGNALFD]: https://man7.org/linux/man-pages/man2/signalfd.2.html

[A-PROP-HEADER]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/include/sys/system_properties.h#59
[A-PROP-IMPL]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/system_properties/system_properties.cpp#238
[A-LIBC-MAP]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/libc.map.txt#1290
[A-SYSCALLS]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/SYSCALLS.TXT#68
[A-GENSYSCALLS]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/tools/gensyscalls.py#20
[A-FCNTL]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/bionic/fcntl.cpp#35
[A-GETPID]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/bionic/getpid.cpp#35
[A-ERRNO]: https://android.googlesource.com/platform/bionic/+/731631f300090436d7f5df80d50b6275c8c60a93/libc/bionic/__errno.cpp#34
[A-KERNEL-CLOSE]: https://android.googlesource.com/kernel/common/+/e59730e07782e4e983f4a3213a46f89f1811cffc/fs/file.c#757
[A-NDK-ABIS]: https://developer.android.com/ndk/guides/abis
[A-SDK-VERSIONS]: https://developer.android.com/ndk/guides/sdk-versions
