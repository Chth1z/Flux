# Flux Rewrite Development

The Rust rewrite uses a root Cargo workspace while the legacy `addrsyncd` submodule remains independently locked and buildable during the bridge releases. The executed shell networking path is frozen as the compatibility oracle and remains the sole writer until each Rust component passes its cutover gate.

## Toolchain contract

- Rust `1.93.0` with `rustfmt` and Clippy.
- Primary target: `aarch64-linux-android`.
- Android API level: 31.
- Release-link NDK: revision `27.3.13750724` (NDK r27d).

The root [`rust-toolchain.toml`](../rust-toolchain.toml) installs the Rust components and Android standard library. `cargo check` for Android does not require an NDK linker. A release build does.

## Common commands

```text
cargo xtask fmt
cargo xtask check-host
cargo xtask test-host
cargo xtask clippy
cargo xtask check-android
cargo xtask ci
```

`cargo xtask ci` runs formatting, host checks/tests, Clippy with warnings denied, and the Android cross-check for the new workspace.

The focused Phase 3 Android mark-authority model can be exercised with:

```text
cargo test -p flux-core --test android_mark_authority
cargo test -p flux-core --test rpdb_fwmark_census
```

These are pure evidence/planning checkpoints. The RPDB test covers only one inventory-backed source
fragment; it does not create a complete Mark Census or Planning Authority. Passing host tests do
not replace production Android device-policy verification, the remaining source collectors,
cross-source freshness, or activation canaries.

The compatibility submodule remains separate:

```text
cargo test --manifest-path addrsyncd/Cargo.toml
cargo clippy --manifest-path addrsyncd/Cargo.toml --all-targets -- -D warnings
cargo check --manifest-path addrsyncd/Cargo.toml --target aarch64-linux-android --all-targets
```

Its bridge reconciliation reads canonical kernel rule dumps and preserves duplicate observations instead of relying only on in-memory ownership tracking. `run --daemon` is now a bounded convergence handshake: readiness follows startup cleanup, reconcile/apply, two clean readbacks, and a final drain of the subscribed route socket to `EAGAIN`. Loss or ambiguous framing forces reconciliation, and parent-side readiness failures terminate and reap the child.

The bridge shell regression suites are:

```text
sh tests/shell/config_installer_contract.sh
sh tests/shell/rules_generation.sh
sh tests/shell/run-installer-tests.sh
sh tests/shell/run-fluxctl-tests.sh
sh tests/shell/run-dispatcher-tests.sh
```

The first two suites are host-only and cover installer migration/configuration admissibility and legacy rule-generation semantics. The remaining three wrappers run in isolated Bubblewrap roots: installer rollback after post-extraction failure, authoritative `fluxctl` delegation, and the complete Rust-owned dispatcher lifecycle. Local hosts without Bubblewrap report an isolated-suite skip. CI makes unavailable or prohibited Bubblewrap environments failures.

### Phase 2 shadow Capture Program workflow

The first Capture Policy checkpoint is pure `flux-core` work. Run its focused integration test with:

```text
cargo test -p flux-core --test capture_program
```

The test corpus pins the ordered local-OUTPUT and forwarded-ingress semantics, canonical mandatory
safety baseline, separately configurable bypasses, resolved application modes and multi-user UIDs,
exact/prefix interfaces, family/domain isolation, optional inventory-host provenance,
compatibility engine UID/GID bypass, protocol eligibility, deterministic digest/resource
accounting, and explicit deferred prerequisites. The
oracle-derived fixture is rooted in `tests/shell/rules_generation.sh`; run that shell suite
separately because the Rust test must not execute scripts or inspect live state.

Treat a difference as a review item, not permission to update both sides mechanically. A shell
change is admitted only for a concrete correctness, security, release-contract, or rollback fix,
and the frozen fixture records why it changed. A shadow change may improve typed normalization or
explanation, but passing the fixture is semantic characterization only: the checkpoint has no
restore renderer, byte/device parity claim, Generation ID, Planning Authority, writer token,
ownership lease, prepared/active conversion, Runtime Coordinator path, or functional-canary
authority.

Do not use the shadow work to attach or pin eBPF, touch live Flux chains, enable TUN, request kernel
modules implicitly, load `.ko`/KPM payloads, or perform native networking mutation. The shell phase
path continues to execute all bridge capture, policy-routing, and address-synchronization writes.
After the focused test, run `cargo xtask ci`; renderer differential tests and real-device cutover
qualification belong to later checkpoints.

### Frozen xtables restore syntax workflow

The first xtables support slice is a pure parser/canonical codec for observation artifacts, not a
Capture renderer. Run its focused integration test with:

```text
cargo test -p flux-platform --test xtables_restore
```

The suite uses current-shaped synthetic documents to pin strict LF/single-space printable-ASCII
framing, repeated tables, declaration and command order, duplicates, IPv4/IPv6 context,
apply/cleanup opcode separation, per-transaction
delete-before-flush-before-delete-chain cleanup phases, exact
bounds, canonical round-trip bytes, and digest identity. It performs no filesystem reads, shell or
restore invocation, kernel access, or mutation.

Passing this test does not establish that `scripts/rules` generated the bytes, that the kernel
accepts them, that cleanup is complete, or that a Rust Capture renderer has parity. Raw oracle
fixtures must be generated later in a hermetic, digest-pinned shell/AWK environment and compared in
a separate job; normal `cargo xtask ci` only parses checked-in or synthetic bytes and never invokes
live networking tools.

The privileged Linux functional-canary harness is an independent opt-in checkpoint and is not part
of `cargo xtask ci`:

```text
cargo xtask test-functional-canary-linux
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux
```

The command selects only the ignored test
`functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup`
with exact matching, `--nocapture`, and one test thread. With
`FLUX_LINUX_CANARY_REQUIRED` unset or `0`, an unsupported host, an unavailable checkpoint, or an
outer preflight prerequisite denial before mutation is an explicit skip. Setting it to `1` makes
every such condition a failure; other values are rejected. Failures after isolated mutation begins
remain failures in either mode. The task never invokes `sudo`, and the ignored
Rust test owns the authoritative isolation, capability, and cleanup preflight. The task removes
all harness-internal mode, configuration, token, and outer-namespace variables from its Cargo
children so inherited caller state cannot bypass the outer preflight or select an internal
re-entry mode.

The delivered checkpoint exercises real dual-stack TCP, UDP, and DNS traffic in an isolated Linux
topology and independently checks exact cleanup. It does not install capture and therefore is not
functional or Android qualification.

The delivered ingress checkpoint uses a third probe namespace to exercise real PREROUTING TPROXY
through a test-local transparent Rust relay:

```text
cargo xtask test-functional-canary-linux-tproxy
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-tproxy
```

The command selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup`,
again with exact matching, `--nocapture`, and one test thread. Its current dual-stack TCP/UDP echo
and DNS-over-UDP/TCP slice proves ingress PREROUTING TPROXY, accepted-socket and strict ancillary-
data original-destination recovery, marked relay egress, source-preserving UDP replies, nonce-bound
DNS transaction/question/answer evidence, per-family route controls, independent bounded flow
counters, and cleanup. The deterministic
regression `ingress_rule_plan_never_places_tproxy_in_output` preserves the hook boundary.

This split records an observed kernel boundary. In the privileged harness environment, marking a
locally generated OUTPUT packet and selecting a local policy route did not make that packet
traverse PREROUTING or reach the TPROXY listener; xtables TPROXY also cannot attach to OUTPUT.
OUTPUT mark counters and route lookups are therefore negative controls, not capture success.
The strict Linux/Android `/proc` FD plus INET_DIAG collector is delivered and rejects evidence
unless protocol, exact tuple, UID, mark, FD/inode/cookie, complete dumps, supervised-process
identity, and timing all agree. Its prebound session API exposes the real nonzero netlink port ID
before collection and reuses the same owned socket with monotonic sequences. Collection consumes
the session and returns it only on success; every error retires the handle, sequence exhaustion
cannot wrap, and later calls cannot extend the opening deadline. The original `collect_until` API
still opens a temporary session internally. The canary layer now adds a non-cloneable handoff that
opens this observer under the immutable attempt deadline, derives the request authority plus a
private per-opening identity from the live handle, makes attempt inputs derive the same deadline,
rejects copied/reopened authority or deadline drift at the context and executor boundaries, and
moves the session once into prepared local-OUTPUT execution. Cleanup evidence now records ordered
client/peer retirement, pairwise-distinct selector/guard/counter retirement, authority-sensitive
report-object retirement or verified-never-created disposition, exact absence readback, final
counter/report lifetime, exact attempt-record retirement, retained-facility observation, and
gate/deadline bounds. Cleanup process identities remain unqualified until the real attempt context
binds them to owned process handles. Functional-canary schema v2 now rejects
missing, REDIRECT, DNAT, weak, mismatched, lossy, stale, or transport-incomplete listener delivery
evidence. Fixtures bind the exact Generation/engine/namespace/Capture Program/selector and
listener FD/inode/cookie/socket
state; TCP accept or UDP `recvmsg` delivery; one attempt authority and loss baseline; stable
and globally noncolliding per-family/protocol listener identities; accepted children distinct from
every listener; and exact inbound wire length/SHA-256 including DNS/TCP framing. Positive
constructors remain private and test-only. A production-compiled TPROXY-only local-OUTPUT
executor/driver/verifier/factory seam is now delivered. It rejects REDIRECT/DNAT requests before
driver preparation, maps typed pre-mutation availability to cleanup `NotRequired`, requires
authoritative cleanup after preparation, and prevents unverified driver proof from reaching the
evidence factory. The completed non-cloneable capture-receipt contract stores the exact request and
one fixed-slot event per required flow, binding the request probe UID, nonce, tuple, payload,
listener cookie, exact delivery event, unique sequence, loss baseline, and monotonic attempt/client/
deadline chronology. Only the sealed receipt verifier may mint receipt-bound artifacts. Its
resulting gate evidence owns the receipt and revalidates it with the retained flows and cleanup
client lifetime. A second sealed process-ownership verifier and non-cloneable receipt now bind the
request's explicit probe/engine UID+GID and credential-map domain, exact engine before/after and
client/peer PID/start-tick/handle observations, restricted credentials, role namespaces, exact
cleanup retirements, and chronology before the evidence factory can run. The Linux/Android
`ProcessHandle` substrate opens only from retained children, verifies stable process-wide
credentials plus user/mount/network namespace and UID/GID-map domains through pidfd/procfs
correlation, and distinguishes exit from confirmed parent reap; the no-traffic credential
preflight exercises that ordering. The first integration subcheckpoint
is now delivered: `SingBoxChild::open_process_handle` opens exclusively from the retained live
`std::process::Child`, rechecks the recorded PID/start ticks against the resulting pidfd/procfs
identity, and does not transfer signaling, waiting, or reaping authority. `EngineSupervisor`
requires matching ready, active-spec, readiness, snapshot, owned-identity, and retained-child state;
the serialized coordinator binds a single-use opener to the immutable request identity, snapshot
revision, and deadline; and execution invokes it only after read-only backend availability succeeds
and before the prepared-attempt boundary. It then moves the authority once into the process
verifier after capture verification. The driver never receives the pidfd authority. The authority
records a private nonzero opening identity and a daemon-owned post-open observation time. Tests
cover identity/revision/deadline substitution, live reobservation,
adapter-owned TERM/reap, retained-handle exit observation after reap, request/authority mismatch,
a real Supervisor-to-pidfd lifecycle, successful required-mode opening, and the required xtables
path preserving `Unsupported` without opening an authority or reaching `RUNNING`.

The exact engine-observation-pair subcheckpoint is also delivered.
`ProcessHandle::initial_observation` returns the exact identity, credentials, and process domain
captured during child-origin pidfd opening. The process verifier consumes `EngineChildAuthority`,
preserves that initial observation at the daemon-owned opening time, reobserves the same retained
pidfd after capture verification, timestamps completion
only after the full scan, and receives a non-cloneable raw pair bound to the exact request engine,
snapshot revision, private opening identity, stable complete process observation, and exclusive
deadline. The pair keeps the handle private and exposes no signal, wait, or reap operation. Exit
or deadline failure at this post-preparation stage is cleanup-uncertain and cannot call the evidence
factory. A real child regression proves the pair reaches only the process verifier while the parent
still owns termination and reap; a second regression proves exit between observations fails closed.

The engine credential-policy/domain subcheckpoint is now delivered as well. Each platform
observation opens user/mount/network namespace descriptors for every task and performs a bounded
two-pass UID/GID-map read; the census rejects heterogeneous or changing task credentials,
namespaces, maps, malformed canonical extents, oversized content, and excess entries. The process
verifier requires both engine observations to match the immutable request's exact four-slot UID/GID
policy, empty supplementary groups, zero capabilities, `NoNewPrivs`, exact user/mount/map domain,
and daemon network namespace. Mismatch is cleanup-uncertain, the evidence factory is not called,
and the adapter retains termination/reap ownership.

Both production receipt authorities therefore remain uninhabited, and the current zero-state
xtables driver still returns `Unsupported` before mutation because OUTPUT marking does not reach
PREROUTING TPROXY. The combined integration checkpoint remains incomplete and is split into the
following remaining reviews: final verifier-side completion chronology and prepared-driver
client/peer ownership and retirement; an independent listener observer that proves
UDP listener state, FD/inode/cookie, transparency, and IPv6-only state; a bounded versioned
supervised-report parser and immutable engine capability contract; and actual prebound collector
observations, cleanup binding, and schema-v2 factory execution with test-only fixtures. Readiness
port evidence and the current outbound connected-socket collector do not by themselves prove the
listener contract.
The required-mode plumbing opens this read-only engine authority only after read-only backend
availability succeeds and before a driver returns a prepared value. The current xtables driver
reports `Unsupported` first, performs no pidfd/procfs credential scan, and retains cleanup
`NotRequired`. If a later prepared path cannot open the
authority, normal post-attempt engine/environment observation and teardown still run even when
post-engine reconciliation also fails. Permission failures map to `Denied`; unsupported, identity,
parse, and other adapter failures remain distinct.
Production composition remains structural-only. Every remaining plumbing
subcheckpoint must preserve that fail-closed result: no device-qualified
local-OUTPUT TPROXY capture mechanism or authoritative engine report producer has been admitted.
A separately qualified cgroup-BPF authority remains an unassigned future experiment; ordinary BPF
counters cannot qualify TPROXY, and these checkpoints add no explicit `.ko` load/unload operation.
Ingress, REDIRECT/DNAT, counters, route lookups, or a veth bounce cannot qualify TPROXY.

Run the socket-diagnostics session and live-correlation regressions with:

```text
cargo test -p flux-platform socket_diagnostics
```

These tests prove pre-collection port visibility, distinct simultaneous session ports, same-handle
sequence continuity, deadline capping, sequence exhaustion, the temporary-session wrapper, and the
existing exact TCP/connected-UDP correlation. They observe procfs and NETLINK_SOCK_DIAG only; they
do not send canary traffic, alter rules/routes/sysctls, or explicitly load/unload modules. A host
kernel may nevertheless service the first TCP/UDP diagnostic request through `request_module` when
its INET_DIAG handlers are modular, so run the live regression only where those handlers are already
active or host autoload policy is acceptable. Production integration must preflight built-in or
already-active handlers and report unsupported instead of using a dump request as that probe.

Run the deterministic seam and coordinator regressions with:

```text
cargo test -p fluxd functional_canary::local_output
cargo test -p fluxd xtables_local_output_executor_never_reaches_running
```

These tests are unprivileged. They exercise request/UID/tuple/payload/listener/delivery/sequence/
loss/timing receipt validation and prove that only the separate verifier can pass receipt-bound
artifacts to the evidence factory. They perform no traffic or networking mutation and do not add a
positive host executor. The suite also opens and binds one NETLINK_SOCK_DIAG session to prove the
exact port-bearing handle reaches prepared execution, but it sends no diagnostic dump request and
therefore does not probe or autoload protocol handlers. "Fail-closed" here describes evidence
admission only; it does not alter the separate user-selected connectivity failure policy.

The delivered credential-only local-OUTPUT preflight is also opt-in:

```text
cargo xtask test-functional-canary-linux-output-preflight
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-output-preflight
```

It selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_local_output_distinct_uid_capability_preflight`.
Before any traffic or rule mutation, the checkpoint creates a disposable user/mount/network
namespace with exactly three singleton UID and GID mappings: controller `0`, probe `20001`, and
engine `20002`. The two role identities must come from distinct delegated subordinate IDs. It
uses trusted mapping helpers under a scrubbed `PATH`, clears and verifies supplementary groups,
reads back the exact maps and namespaces, and executes both nonzero roles with matching real,
effective, saved, and filesystem credentials, zero inheritable/permitted/effective/ambient
capabilities, and `NoNewPrivs=1`.

Unavailable helpers, subordinate ranges, parent mappings, or group policy explicitly skip in
optional mode and fail in required mode. Exact-map, namespace, or credential drift after the
availability probe fails in both modes. Root/root, same-UID, broad-map, overflow-ID, inherited-
group, and confined mapped-root fallbacks are rejected. This proves credential capability only;
it does not install local-OUTPUT capture, run Sing-Box, construct schema-v2 evidence, or qualify
Android. None of the three Linux commands is part of `cargo xtask ci`, and none may invoke `sudo`,
`modprobe`, load a `.ko`, or trigger implicit module autoload. The ingress TPROXY preflight runs
before rule mutation and refuses to continue unless the target, mark/comment matches, family
TPROXY support, and selected xtables backend support are already active under `/sys/module`.

Host execution of `addrsyncd` requires Linux or Android. On Windows, use the Android cross-check and run its host tests in Linux CI.

## Android release build

Set `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` to the pinned NDK revision and run:

```text
cargo xtask build-android
```

The task validates `source.properties`, selects the API-suffixed NDK clang linker for the host OS, and builds the `fluxd` release binary. It refuses a different NDK revision instead of silently producing an unqualified artifact.

## Magisk module staging

The bridge release is staged only after a successful pinned Android release build:

```text
cargo xtask stage-module --stage dist/module --runtime-binaries /path/to/runtime-binaries
```

`--runtime-binaries` must contain the independently sourced `sing-box`, `jq`, and rollback `addrsyncd` Android binaries. The task copies the tracked module tree, installs the newly built `fluxd` at `bin/fluxd`, and refuses a non-empty stage or a stage missing any required runtime file. This is a development staging boundary only; it prevents installer changes from landing without a real Android `fluxd` artifact but does not certify third-party provenance.

Before publishing, populate every blank source/source-revision/version/hash/license field in
`conf/manifest.json`, add hashed schema-1 passed device-test evidence bound to the exact source
revision, operational payload, Android build fingerprint, kernel, boot ID, verified-boot/SELinux
state, and the exact passed test set (`module_boot`, `status`, `enable_disable`, `restart`,
`abnormal_sing_box_exit`, `dual_stack_tcp_udp_dns`, and `cleanup`), and generate a populated SPDX
document, exact pinned-toolchain build metadata, and a
complete recursive `checksums.sha256` inventory. Then run:

```text
cargo xtask verify-package --stage dist/module
```

The verifier requires clean root/submodule Git state and binds `fluxd`/`addrsyncd` revisions to
their exact HEADs. It enforces the complete allowed file inventory; byte-compares reviewed module
scripts, configuration, and defaults; requires exactly four manifest binaries; validates bounded
file-backed AArch64 executable entries and Android interpreter paths; rehashes every artifact and
payload-bound device record; cross-binds exact SPDX package/source/license/hash records; verifies
pinned build metadata and complete checksums; and rejects unreviewed Magisk root files, unsafe
paths, symbolic links, `.ko`/`.kpm` payloads, placeholder/unreviewed licenses or evidence, and any
profile other than `full`. The checked-in manifest is intentionally not release-complete; a
normal development stage must fail until release metadata and device evidence are supplied. The
standalone `addrsyncd` crate remains `UNLICENSED`, so its release license field cannot be populated
until the copyright holder records a compatible grant.

The current verifier establishes internal consistency, not external trust in an unsigned evidence
file or self-declared third-party build. Publication remains blocked until `package-magisk` verifies
signed or reproducible third-party provenance and trusted device/CI attestations.

## Phase 1 bridge runtime

The packaged module installs `flux_service.sh` as module-local `service.sh`. It launches a bounded watchdog for `fluxd daemon` and an `inotifyd` Adapter that forwards raw facts through `scripts/flux-event`; event-to-intent policy remains in Rust.

Native online commands are:

```text
fluxd ping
fluxd status [--json]
fluxd control start|stop|restart|reload|resync
fluxd event EVENT_TYPE WATCHED_PATH EVENT_NAME
```

The local `SOCK_SEQPACKET` control contract is protocol version 3. Version 2 introduced the coherent Capability Profile; version 3 adds the required orthogonal runtime-verification state to status responses. Version-1 and version-2 requests are rejected explicitly instead of being decoded against the new response shape.

The socket defaults to `/data/adb/flux/run/fluxd.sock` with mode `0600`. Accepted peers must match the daemon effective UID. Administrative intent is atomically recorded in `/data/adb/flux/state/administrative-intent.json` with the current Linux boot ID, so a daemon restart replays desired running/stopped state before normal control traffic. Startup reconciliation must complete before the socket binds; journal, dispatcher, peer, or socket-safety failures remain fatal and are handled by the bounded watchdog.

The authoritative Phase 1 user configuration is `/data/adb/flux/conf/flux.toml` (override with `FLUXD_CONFIG_PATH` for development and tests). Schema 1 is intentionally exact: unknown or missing fields are rejected, and only `fail_policy = "open"` is accepted. `daemon.event_queue_capacity` sizes the bounded legacy-writer queue; the other accepted daemon fields reserve the validated contract for later Phase 1 slices. Configuration is loaded once during mutation-allowed startup, so changes to `flux.toml` currently require a daemon restart. When the Capability Profile permits mutation, a missing or invalid file is fatal before the legacy writer starts or the control socket is admitted.

When the kernel is below 5.10, or when the kernel version or boot identity cannot be verified, `fluxd` enters its settled read-only service without loading `flux.toml`, reading administrative intent or disable state, or starting the legacy mutation writer. In particular, every verified below-5.10 kernel is guaranteed to remain queryable without mutation. Read-only Capability Profile collection may still inspect boot identity, SELinux state, and legacy artifact metadata, but it never executes the dispatcher. Tests and nonstandard environments may override the first two probe files with `FLUX_BOOT_ID_PATH` and `FLUX_SELINUX_ENFORCE_PATH`. This keeps status queries available while preventing mutation-configuration or persistence failures from turning a read-only device into a watchdog restart loop. Module upgrades automatically preserve an existing `flux.toml`; a first installation receives the packaged default.

The Phase 1 daemon now owns control admission and shutdown through one `epoll` reactor covering the Unix listener and shutdown `signalfd`. A stop request closes admission before in-flight connection work drains. This delivered baseline does not yet claim the future netlink, timerfd, pidfd, or BPF event sources planned for later phases.

Mutating `fluxctl` commands use this socket exclusively and never fall back to direct script execution. Read-only diagnostics still use the legacy inspection paths during the bridge release. The legacy dispatcher accepts networking mutations only with `FLUXD_BRIDGE=1`, serializes them with an identity-bearing lock, and remains the sole networking writer.

### Rust-owned engine handoff shell contract

The delivered Phase 1 handoff invokes `FLUXD_BRIDGE=1 scripts/dispatcher` through the phase verbs `startup-recover`, `prepare`, `capture-start GENERATION`, `capture-stop`, `capture-verify GENERATION`, `address-resync`, `state-running GENERATION`, `state-stopped`, and `state-failed`. These verbs never invoke `scripts/core`. A boot-scoped dispatcher mode lease rejects mixing them with the retained legacy `start`, `stop`, and `restart` rollback path; `state-stopped` releases the Rust-owned lease only after capture is detached. This makes Rust the sole Sing-Box owner for the daemon run while shell remains the serialized networking writer for Phase 1 capture, policy-routing, and address-synchronization mutations.

`prepare` runs under the dispatcher lock, allocates a positive shell-owned generation ID, and snapshots the generated configuration, environment, rule/cleanup caches, manifest, and generation-local Sing-Box log under `/data/adb/flux/run/generations/<id>/`. Later mutation phases load those immutable generation artifacts instead of the shared live cache. The compatibility path `/data/adb/flux/run/engine.manifest` is atomically published from that generation's manifest for Rust intake; failure discards the incomplete generation and removes the compatibility manifest. The manifest is at most 16 KiB and has this strict line grammar:

```text
FLUX_ENGINE_MANIFEST_V1
generation=1..2147483647
binary=/absolute/path
config=/absolute/path
working_directory=/absolute/path
log=/absolute/path
launcher=direct|busybox-setuidgid
[busybox=/absolute/path]
[identity=USER:GROUP]
readiness=listener|tun
startup_timeout_ms=1..60000
stop_timeout_ms=1..60000
[listener_port=1..65535]
[tun_interface=IFNAME]
```

There are no blank, unknown, duplicate, missing, or mode-inappropriate lines. The complete UTF-8 document is limited to 16 KiB. The generation is a nonzero decimal integer no greater than `2147483647`, and both timeouts are decimal milliseconds in `1..=60000`. `launcher=direct` forbids `busybox` and `identity`; `busybox-setuidgid` requires exactly both. Listener readiness requires exactly `listener_port`, while TUN readiness requires exactly `tun_interface`. Rust rejects symbolic/non-regular manifest files, parses the strict grammar, and constructs the generation-bound `EngineSpec` before launch.

`RuntimeCoordinator` implements the existing `LegacyDispatcher` interface and therefore runs inside the same bounded, serialized `LegacyControlBridge` worker as all control mutations. Start ordering is `prepare` → descriptor-pinned `sing-box check`/launch and child-owned listener or TUN readiness → `capture-start <id>` → structural `capture-verify <id>` → configured functional gate → `state-running <id>`. The production composition selects the structural-only gate; required-mode tests run the complete exact-binding canary. Capture start, verification evidence, active/previous Generation records, and `RUNNING` publication must all name the same boot-scoped Generation. Before its first networking mutation, `capture-start` records that Generation as the capture owner, then starts address synchronization before TPROXY. It compensates both on partial failure, but removes the Generation marker only when both cleanup operations succeed; uncertain compensation retains the evidence needed for a later detach proof. Stop and shutdown detach capture before asking the supervisor to stop/reap the child, then publish `state-stopped`. `address-resync` uses the same writer and cannot interleave with lifecycle work; required mode invalidates the Network-Epoch-bound pass and schedules a fresh gate.

For the current TPROXY compatibility path, `prepare` requires `xt_owner` both before `init` and after loading the generated capability cache. Local OUTPUT always traverses `APP_CHAIN`, even when application filtering is disabled, so the configured Sing-Box UID/GID bypass executes before the default proxy action. The fallback `ROUTING_MARK` setting is not accepted as Rust-owned loop authority because the bridge does not yet prove that the supervised engine applies it to its sockets.

Reload prepares the candidate while the current generation remains active. Only after preparation succeeds does it detach old capture and replace the engine. A failed or uncertain old-capture detach does not launch the candidate: it retains the old engine in `CaptureRepairPending`, blocks start/reload, and lets maintenance repeatedly prove detach before republishing and re-verifying capture for that same old generation. Candidate activation failure attempts to detach partial capture; only proven detach permits candidate retirement and rollback to the recorded previous immutable generation. Uncertain candidate compensation remains `DetachPending` and does not restart the previous generation. Rollback capture and publication are bound to the previous generation ID; failed rollback remains fail-open with capture detached.

If capture detachment fails during stop or failure compensation—including uncertain cleanup after `capture-start`—the coordinator enters `DetachPending`: it retains the generation evidence and intended terminal state, does not signal the engine, does not publish `STOPPED`/`FAILED`, and blocks start/reload. Maintenance retries detachment; only proven detach permits engine retirement/reap and terminal publication.

The worker calls maintenance after requests and on bounded idle intervals. This drives supervisor reap/backoff/restart without starting a second child, restores and re-verifies capture after a successful restart, and retries pending `RUNNING`, `STOPPED`, or `FAILED` publication. A failed `state-running` call does not authorize a blind retry: maintenance first observes the owned engine, reasserts and structurally verifies capture, and, when the injected gate requires it, runs a fresh complete functional canary. Only the still-ready matching Generation may retry `state-running`. Failed verification enters `CaptureRepairPending`, which proves detach, republishes capture for the same Generation, runs the complete configured gate again, and only then republishes `RUNNING`; an observed engine exit takes detach/repair precedence. Engine identity loss, uncertain reload detachment, repair/restoration, and active address resynchronization invalidate a previous functional pass. Required-mode address resynchronization schedules a fresh `RUNNING` gate through the normal maintenance path.

`fluxd status` exposes an observed `RuntimeSnapshot` (runtime phase, capture, engine, verification, generation, bounded last error, and its own revision) separately from the desired/control `ControlSnapshot` (administrative intent, in-flight request, dirty state, and last completion). Verification is orthogonal to operational phase: `structural_only` is the conservative baseline and means no functional pass authorizes the current observation; `functional_pending` means a fresh exact-binding gate is required; `functional_passed` means the latest required attempt and `RUNNING` publication succeeded for the current binding; and `functional_failed` means the complete required gate, including its structural prerequisite, attempt, evidence, or cleanup, failed. Stop/reset returns to the no-functional-authorization `structural_only` baseline. `RUNNING` alone never implies functional qualification. The production Phase 1 composition explicitly remains `structural_only`; required functional mode is currently limited to coordinator tests and later privileged harnesses, and even a passed host attempt is not Android device qualification.

Every phase process has a nonzero execution deadline capped at 60 seconds. The Rust Adapter launches the phase shell in its own process group and performs bounded forced cleanup on timeout. Sing-Box validation/run children and phase-shell children also arm `PR_SET_PDEATHSIG(SIGKILL)` with a post-arm parent check, containing direct children if `fluxd` dies. Direct Sing-Box launch therefore supports automatic same-boot crash recovery after capture is detached. This is not process-tree containment: phase descendants do not inherit the lease, and BusyBox `setuidgid` credential changes may clear it. A post-credential Rust launcher and verified Flux-owned process-cgroup containment remain deferred.

On daemon startup, the Capability Profile first decides whether mutation is admissible. An admitted runtime runs the bounded `startup-recover` phase before strict `flux.toml` loading, so a broken current configuration cannot strand same-boot capture; recovery must also succeed before administrative intent is read, persisted, or executed and before the control socket is admitted. Below-floor or unverified profiles stay on the non-mutating read-only path and never invoke recovery. Recovery is serialized by the dispatcher lock. With no lease and no capture evidence it idempotently publishes `STOPPED`. A same-boot Rust lease removes the exact active generation, or uses the immutable prepared generation for markerless partial activation, then stops TPROXY before address synchronization and proves capture evidence absent. For a direct engine launch, `PDEATHSIG` supplies the child-death proof, so recovery publishes `STOPPED`, clears active/previous/verification records, and releases the lease. For `busybox-setuidgid`, child death cannot be proven after daemon loss: recovery publishes `FAILED` only after detachment, preserves the Rust lease and active engine generation, and blocks automatic daemon restart for explicit repair. Cleanup failure likewise preserves evidence and ownership. Same-boot legacy ownership is rejected without mutation; prior-boot evidence is retired without treating kernel objects as surviving the reboot.

Phase 1 `capture-verify` proves shell-owned structural evidence; the always-on owner bypass prevents the default self-capture omission but is not itself a synthetic end-to-end traffic or exact-process loop-prevention proof. The Stage-1 typed canary model, coordinator ordering, failure injection, status contract, authoritative schema-v2 listener/delivery validator, temporal cleanup/retirement validator, fail-closed TPROXY-only local-OUTPUT executor seam, explicit per-flow capture-receipt/verifier contract, process-ownership receipt contract, child-origin pidfd substrate, exact retained-engine before/after observation pair, authoritative engine credential-policy/domain validation, prebound socket-diagnostics session transport, and type-safe attempt-owned observer handoff are delivered, along with the first Stage-2 isolated topology checkpoint, the complete dual-stack TCP/UDP echo plus DNS-over-UDP/TCP third-namespace ingress PREROUTING TPROXY checkpoint, and the strict Linux/Android `/proc` FD plus INET_DIAG outbound-collector prerequisite. The exact retained engine-child authority now travels from `SingBoxChild` through matching `EngineSupervisor` ownership and the serialized coordinator into the process-verifier boundary while preserving adapter-owned signal/wait/reap authority. Deferred are the positive traffic producer; verifier-side completion chronology and prepared-driver client/peer child ownership; backend listener observation and delivery-report parsing/factories; actual prebound collector observations; Android adapter and device qualification; ancestor-safe directory traversal with `openat`/`openat2`; long-term retention/rotation policy for Generation logs; pidfd/timerfd reactor integration; full process-tree containment; and real-device release evidence on the minimum Android 5.10 kernel. Both production receipt authorities remain uninhabited, current xtables remains `Unsupported`, optional eBPF requires separate qualification, and no explicit `.ko` load/unload operation was added. The legacy structural bridge has not yet proven that every xtables/kernel dependency is already active without implicit module requests, so it cannot satisfy the future no-autoload qualification. Ingress or collector evidence cannot discharge the local-OUTPUT gate, REDIRECT/DNAT cannot qualify TPROXY, and production must remain `structural_only` rather than publish `functional_passed` from host evidence.
