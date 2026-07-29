# Flux Code And Architecture Review

Date: 2026-07-29
Branch: `codex/fluxd-rust-rewrite`
Baseline: `c3d153b679346dce9d0c7422ba1536b5ff65637e`
Reviewed state: R8 qualified Capture Path selection checkpoint based on `19f2f16`

## Conclusion

The host-implementable shell networking and standalone `addrsyncd` migration is complete. The
package has one Rust runtime owner, one staged native-admission decision, one reactor-owned network
inventory, and one current Capture Program/lowering path. Schema-4 `auto`/exact Capture Path
selection is now bound to the Generation, runtime status, diagnostics, and explain output. No
executable shell networking writer,
standalone address synchronizer, bridge renderer, takeover parser, or fallback path remains.

The product is not release-complete. Packaged safety defaults intentionally reject native mutation
because Android VPN-policy observation and the production functional-canary adapter are not yet
qualified. Exact rooted Android 5.10+/ARM64 activation, rollback, cleanup, and power evidence also
remains unavailable in this workspace. The bounded statistics core and daemon automation seam are
implemented, but no production counter collector, manager serialization, or qualified automated
policy is connected yet. The selector's production Android behavioral evidence deliberately remains
unqualified, so the packaged daemon stays queryable but read-only.

## Migration Answer

| Question | Status | Evidence |
|---|---|---|
| Shell networking runtime removed? | Yes | Package checks forbid networking mutation in platform glue; no runtime `scripts/` tree or shell fallback is present. |
| Standalone `addrsyncd` removed? | Yes | No process recognition, executable, config loader, status field, or runtime ownership path remains. |
| Native Rust owner composed? | Yes | `fluxd` composes planning, Sing-Box supervision, `NativeXtablesOwner`, rollback, recovery, and control. |
| Default packaged mutation admitted? | No, intentionally | Both safety defaults are `true`; unavailable VPN/canary adapters produce typed read-only rejection. |
| Physical release qualification complete? | No | No attached rooted ARM64 Android target produced exact device evidence. |

Therefore: the migration itself is complete, but the release and device-qualification program is
not complete.

## Architecture Review

### Admission and lifecycle

The previous split authority has been replaced by staged type-state admission:

1. `CapabilityProfile::mutation_gate` evaluates kernel and boot facts.
2. `NativeAdmissionCandidate` binds verified boot and device/namespace identity.
3. `ConfiguredNativeAdmission` enforces requested VPN and canary safety policy.
4. `AdmittedNativeRuntime` requires a complete reactor-owned inventory snapshot.
5. Only the admitted type can enter native startup recovery and runtime composition.

Rejected startup remains queryable through control IPC, exposes one typed reason, refuses mutation,
handles process-directed `SIGTERM` through `signalfd`, and removes the control socket.

### Inventory and observation

The reactor is opened before composition, attaches and primes one route-netlink driver, then binds
control. Generation planning and address reconciliation clone the same `NetworkInventorySource`.
Loss or descriptor failure invalidates the inventory instead of allowing a one-shot or partial view
to authorize a Generation.

Traffic observation now has a separate backend-neutral seam. A Generation/Capture Path-bound
`TrafficCounterPlan` maps opaque cells to reviewed privacy-reduced dimensions under an exact
240-row ceiling. Complete cumulative samples are validated under row, decoded-byte, and work
limits; sequence gaps, source replacement/reset, reported loss, regression, saturation, and total
exhaustion create explicit epochs without joining uncertain deltas. Conflicting replay and invalid
coverage are rejected without changing the accepted snapshot.

`TrafficObservationModule` publishes whole immutable `Arc` replacements and optionally evaluates
one replaceable in-process policy synchronously. Policies receive only a snapshot and may request
only reload or address resync. The daemon binds policy/statistics/Generation/Capture Path/epoch
provenance, freshness, and rule identity; decision-journal and accepted-action capacities are
configured independently under separate 128-entry ceilings. Plan replacement publishes a typed
sequenced discontinuity record. Policy evaluation requires Running administrative intent, and the
serialized writer repeats that gate after earlier queued intents. Accepted actions enter only
`RuntimeControl`; protocol-v8 socket clients cannot forge the reserved automation reason. No
collector, timer, worker, persistence, manager transport, or concrete product policy is introduced
by this checkpoint.

### Capture Path selection

Desired State schema 4 accepts `auto` and exact nftables TPROXY, xtables TPROXY, or managed-TUN
requests. One daemon selector combines the implemented Adapter inventory with the same fresh Android
planning evidence used to assemble the Generation. The current production inventory contains only
xtables TPROXY; nftables and TUN remain `Unimplemented`, and an exact unavailable request never
falls back.

Selected and rejected outcomes both retain the exact request, every bounded candidate state, first
kernel gaps, and one canonical evidence digest. Selected outcomes are bound to Generation identity,
prepared records, runtime publication, protocol v8, diagnostics, and explain output. Rejections
remain inspectable while mutation stays disabled. Production probe state defaults to `Unqualified`,
so Kconfig or structural eligibility cannot grant behavioral authority.

Qualification evidence records one observation time and an at-most-five-minute deadline. That
original deadline survives admission, preparation, and runtime ownership; no later layer refreshes
the lease. Decoding rejects a claimed `Qualified` candidate unless its behavioral probe is qualified
and no disabled kernel prerequisite remains. Expiry or inventory loss clears the public decision
and detaches fail-open. Normal Stop clears a latest selected decision immediately while retaining
the active Generation binding until detachment is proven. Once
detachment is proven, the coordinator requests one explicit full reactor redump through a
capacity-one eventfd-woken command. Every complete observation transaction receives a distinct
snapshot ID while `NetworkEpoch` changes only for topology changes. The prior transaction is
rejected behind a freshness barrier. Revision mismatch schedules exactly one complete transaction;
an unsent, active, or already-published transaction bound to the requested revision satisfies a
later dequeued command without a parallel follow-up flag. Manual restart is blocked, and exactly one
fresh-evidence `DaemonRecovery` attempt is allowed.

### Capture and native ownership

The public migration vocabulary is gone. The current flow is:

`CaptureProgramRequest` -> `CaptureProgramCompilation` -> `CaptureProgram` ->
`XtablesCaptureArtifactSet` -> admitted native target -> `NativeXtablesOwner`.

The compilation result exposes only the semantic program and inventory provenance. Historical
assumption/deferred-prerequisite reports and the shell oracle fixture were deleted. Xtables lowering
has one schema and mandatory lifecycle ordering for every artifact; forwarded-only input is rejected
by the native owner because local OUTPUT is required, not because of an obsolete schema identity.

The native owner exclusively controls stable hooks, generation chains, policy routing, durable
target material, writer lease, exact readback, rollback, recovery, and cleanup. Recovery accepts one
coherent native owner entry and fails closed on unknown, mixed, corrupt, or unjournaled state.

Proxy-only RPDB placement stores no fabricated address-bypass priority. The optional priority is
represented directly in the placement Interface, errors, routing projection, and Generation digest;
the old bypass-equals-proxy sentinel, parallel boolean, and compatibility-stable identity are gone.

### Control contract

Protocol v8 reports native admission and current runtime state. `active_generation` structurally
pairs one Generation with the selection it actually owns; `latest_capture_path_decision` separately
reports the latest completed selection attempt, including a rejected successor. Explain snapshots
runtime once and labels whether each request matches current Desired State; decoding rejects forged
relation labels. The protocol no longer carries bridge facts, a redundant kernel summary, public
events, or shell/address-synchronizer status. Direct user actions use `user_control`; current
xtables evidence uses `xtables`; daemon-originated automation uses the reserved `automation` reason,
which inbound clients cannot claim.

### Safety posture

The default configuration sets `respect_android_vpn = true` and
`require_functional_canary = true`. Neither field is inert. Until qualified adapters exist, the
daemon stays online but read-only. Explicitly disabling a requirement selects
`StructuralVerificationOnly`; that is a policy mode, not an automatic fallback.

## Peer Source Review

Pinned source studies are archived under
`archive/codex/2026-07-29-peer-source-design-study/` and excluded from Git.

| Project group | Adopted lesson | Rejected design |
|---|---|---|
| dae | Prepare/ready/commit/retire and bounded pending reload | Global TC/cgroup/BPF/netns ownership and PII-rich state |
| Sing-Box / sing-tun | TPROXY socket behavior and external-descriptor TUN | Autonomous route, RPDB, nftables, iptables, and TUN ownership |
| Vector | Typed IPC, identity checks, replacement publication | Manager-level root authority and broad privileged interface |
| NeoZygisk | Small epoll loop as lifecycle evidence | Unbounded request threads, weak framing, duplicated protocol enums |
| Magisk / KernelSU | Minimal idempotent launch glue | Treating root-framework scripts as supervision or runtime authority |
| Re-Kernel | Bounded rings/maps and event-driven observation ideas | Kernel module dependency, silent loss, incomplete unwind, global hooks |
| bindhosts | Runtime re-probing and atomic status publication | Shell/file multi-writer state and privileged WebUI execution |

The studies reinforce the current ownership decision: root frameworks launch one `fluxd`; Sing-Box
is an external engine; `fluxd` alone owns admission, host mutation, rollback, observation, and
manager IPC.

## Differences From The Previous Review

| Previous state | Current state |
|---|---|
| Shell bridge described as production writer | No shell networking implementation or fallback exists |
| Capability, composition, mutation, and status used different gates | One `NativeAdmissionState` projects into all four |
| Production always accepted structural-only canary behavior | Packaged canary requirement rejects admission until qualified |
| VPN and canary settings were identity-only fields | Both settings enforce fail-closed behavior |
| Planning and reconciliation used separate inventory collection | Both consume one loss-aware reactor source |
| Startup recovery ran before final policy admission | Only `AdmittedNativeRuntime` can trigger recovery |
| Capture Program was a shadow/oracle migration artifact | It is the current backend-neutral policy Interface |
| Forwarded lowering retained schema-v1 compatibility | One current lowering schema with mandatory transaction order |
| Shell writer takeover and bridge ownership were recognized | Only exact native owner state is recoverable |
| Proxy-only placement fabricated a bypass priority for identity stability | Optional bypass state is explicit and identity-tagged |
| Generation and Capture Path identities were duplicated or projected through primitives | One canonical `GenerationId` and `CapturePathId` cross core, daemon, platform, status, and qualification evidence |
| Traffic counters had no product Interface | One bounded backend-neutral accumulator publishes immutable privacy-reduced snapshots |
| Automation was only a target sketch | One least-authority typed policy seam submits bounded maintenance proposals through `RuntimeControl` |
| Capture Path selector was disconnected and configuration was xtables-only | Schema-4 `auto`/exact selection is Generation/status/explain-bound with complete decisions and no-fallback behavior |
| Selection could outlive quiet, stopped, or lost inventory evidence | The original at-most-five-minute qualification deadline, Stop entry, and inventory loss invalidate the public selection; loss detaches fail-open, forces one current transaction, and allows one recovery attempt |
| Runtime status used parallel optional Generation, selection, and decision fields | Protocol v8 uses one active Generation/selection binding plus an independent latest-attempt decision and validated Desired State request relations |

## Qualification Harness Progress

The current Android local-OUTPUT checkpoint now uses one command,
`test-functional-canary-android-output-tproxy`, for both ARM64 and x86_64. It derives the Cargo/NDK
target from verified kernel architecture plus the matching Android ABI, rejects kernels below 5.10
or malformed complete release identities, and applies the package verifier's strict AArch64 ELF/
interpreter/16 KiB alignment checks before an ARM64 upload. One shared artifact-identity module now
gives the profile, census, and canary runners the same non-symlink regular-file SHA-256/size
contract; the canary revalidates it immediately before push and on-device before execution.

The canary and census also share one owner-marked remote-directory transaction: a 256-bit
host-generated token, root-owned owner record, creation-time device/inode identity, fail-closed
`/proc` process scan, mandatory cleanup after ambiguous creation, and independent absence proof.
The canary checks device identity and directory ownership immediately before push, suppresses raw
ADB/test output, and exposes only sanitized pass/fail stages. The retired x86_64-specific command
has no dispatcher or help alias.

This is host-side qualification infrastructure, not a production adapter or device result. No ADB
target was attached in this pass, so native admission remains intentionally read-only under the
packaged VPN and functional-canary requirements.

## Remaining Work

### P0: release correctness

1. Implement and qualify the production Android Capture Path behavioral-evidence producer; retain
   `Unqualified` as the packaged default until device evidence exists.
2. Attach a rooted ARM64 Android 5.10+ target and run the profile, mark-ordering, fwmark-census, and
   architecture-neutral local-OUTPUT commands, followed by the reviewed VPN, RPDB, listener, and
   payload-identity matrix.
3. Implement and qualify the Android VPN-policy adapter against observed netd/Connectivity behavior.
4. Implement and qualify the production local-OUTPUT functional-canary observer, binding exact
   transparent-listener delivery, supervised-engine receipt, pre/post identity, bounded counters,
   and cleanup.
5. Exercise fresh install, duplicate service triggers, reboot, safe mode, disable/re-enable,
   replacement, forced death, partial mutation, rollback, and uninstall on both Magisk and KernelSU.
6. Record exact ARM64 tool/payload digests, power and wakeup budgets, SELinux behavior, and verified
   clean absence before changing the manifest from development-only.

### P1: required product surface

1. Build the digest-bound xtables counter plan, counter-aware parser, and production collector;
   qualify its schedule, CPU, RSS, wakeup, queue, and optional persistence budgets.
2. Build the manager as an unprivileged Android client of typed, credential-checked IPC, following
   Vector's replacement-state UX without inheriting its broad root interface. Serialize bounded
   statistics and automation state without exposing kernel or mutation authority.
3. Add concrete automated policies only after production inputs exist and each policy has a reviewed
   deterministic work bound, freshness rule, and failure behavior.
4. Complete subscription and configuration workflows through daemon-owned atomic replacement only;
   the manager must never write runtime state directly.

### P2: backend expansion after xtables qualification

1. Add a transactional nftables adapter with the same Generation, readback, rollback, and ownership
   contracts.
2. Add managed TUN through an externally owned descriptor with Sing-Box host mutation disabled.
3. Add eBPF observation before considering acceleration. Require exact hook identity, bounded maps
   and ring buffers, explicit loss/reset epochs, complete detach, and a conventional correctness
   path.

Do not add kernel modules, opaque KMI payloads, a second writer, shell execution, compatibility
aliases, or speculative backend selection to bypass the P0 physical evidence gate.

## Verification

- `cargo fmt --all -- --check`: passed.
- `cargo check --workspace --all-targets`: passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.
- `cargo test -p flux-core`: 56 unit tests plus every integration and doc test passed; the runtime
  control suite includes the serialized Stop-before-automation ordering case.
- Canonical platform unit suite: 466 passed, 7 environment-gated tests ignored. Six focused refresh
  tests cover command-before-retry, retry-before-command, publish-before-command, active
  supersession, ordinary refresh, and debounced-event supersession.
- `cargo test -p fluxd --lib`: 368 passed, 4 privileged namespace tests ignored, including prepared
  candidate settlement, cleanup retry, every Running-publication deadline boundary, and Stop-entry
  decision invalidation through uncertain detachment.
- `cargo test -p fluxd --test startup_reconciliation_admission`: 5 passed.
- `cargo test -p flux-platform --test reactor`: 16 passed.
- `cargo test -p fluxd --test control_protocol`: 17 passed, including protocol-v8 outbound
  automation serialization and inbound reserved-reason rejection.
- `cargo test -p fluxd --test daemon_cli`: 10 passed.
- `cargo test -p fluxd --test socket_round_trip`: 7 passed.
- `cargo test -p xtask`: 73 passed, 3 ignored; covers ARM64/x86_64 target selection, complete kernel
  grammar, shared artifact drift detection, owner/inode-bound remote transactions, sanitized
  diagnostics, strict dangling-symlink-aware path absence, current-command uniqueness, pinned
  toolchain construction, bounded command cleanup, and existing collectors.
- `cargo xtask ci`: passed with exit code 0, including the complete workspace test suite, strict
  linting, doc tests, and Android target checks.
- `git diff --check`: passed.
- Final active-source vocabulary audit found no Capture Program compatibility names, shell-writer
  recovery, bridge owner, standalone address-synchronizer owner, or obsolete lowering branch.

Privileged namespace tests remain intentionally ignored on the host. No rooted ARM64 Android
device was attached, so this verification does not qualify a release payload.
