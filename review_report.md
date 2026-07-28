# Flux Code And Architecture Review

Date: 2026-07-29
Branch: `codex/fluxd-rust-rewrite`
Baseline: `c3d153b679346dce9d0c7422ba1536b5ff65637e`

## Conclusion

The host-implementable shell networking and standalone `addrsyncd` migration is complete. The
package has one Rust runtime owner, one staged native-admission decision, one reactor-owned network
inventory, and one current Capture Program/lowering path. No executable shell networking writer,
standalone address synchronizer, bridge renderer, takeover parser, or fallback path remains.

The product is not release-complete. Packaged safety defaults intentionally reject native mutation
because Android VPN-policy observation and the production functional-canary adapter are not yet
qualified. Exact rooted Android 5.10+/ARM64 activation, rollback, cleanup, and power evidence also
remains unavailable in this workspace.

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

Protocol v5 reports native admission and current runtime state only. It no longer carries bridge
facts, a redundant kernel summary, public events, or shell/address-synchronizer status. Direct user
actions use `user_control`; current xtables evidence uses `xtables`.

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

## Remaining Work

### P0: release correctness

1. Attach a rooted ARM64 Android 5.10+ target and run the read-only capability, namespace, netd,
   VPN, mark-census, RPDB, listener, and payload-identity probes.
2. Implement and qualify the Android VPN-policy adapter against observed netd/Connectivity behavior.
3. Implement and qualify the production local-OUTPUT functional-canary observer, binding exact
   transparent-listener delivery, supervised-engine receipt, pre/post identity, bounded counters,
   and cleanup.
4. Exercise fresh install, duplicate service triggers, reboot, safe mode, disable/re-enable,
   replacement, forced death, partial mutation, rollback, and uninstall on both Magisk and KernelSU.
5. Record exact ARM64 tool/payload digests, power and wakeup budgets, SELinux behavior, and verified
   clean absence before changing the manifest from development-only.

### P1: required product surface

1. Build the manager as an unprivileged Android client of typed, credential-checked IPC, following
   Vector's replacement-state UX without inheriting its broad root interface.
2. Expose bounded aggregate traffic, health, loss/reset, generation, and power statistics. Keep
   per-flow and PII-rich data disabled by default.
3. Complete subscription and configuration workflows through daemon-owned atomic replacement only;
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
- `cargo test -p flux-core --test capture_program`: 17 passed.
- `cargo test -p flux-platform --test xtables_capture_lowering`: 23 passed.
- `cargo test -p fluxd --lib`: 312 passed, 4 ignored.
- `cargo test -p fluxd --test startup_reconciliation_admission`: 5 passed.
- `cargo test -p flux-platform --test reactor`: 16 passed.
- `cargo test -p fluxd --test control_protocol`: 16 passed.
- `cargo xtask ci`: passed with exit code 0 after replacing retired `fluxctl` tokens in raw
  protocol-v5 test fixtures, boxing the startup-only configured admission state, simplifying the
  remaining current xtables save case, documenting each signal-set unsafe contract, and replacing
  the proxy-only RPDB sentinel with explicit optional state.
- Final active-source vocabulary audit found no Capture Program compatibility names, shell-writer
  recovery, bridge owner, standalone address-synchronizer owner, or obsolete lowering branch.

Privileged namespace tests remain intentionally ignored on the host. No rooted ARM64 Android
device was attached, so this verification does not qualify a release payload.
