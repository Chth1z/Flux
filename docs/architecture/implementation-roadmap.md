# Fluxd Rewrite Implementation Roadmap

This roadmap turns the [blueprint](fluxd-blueprint.md) and [technical specification](fluxd-technical-specification.md) into independently verifiable tracer bullets. Each phase leaves a usable rollback path and assigns exactly one owner to active networking state.

## Delivery principles

- Preserve the current working TPROXY path until the Rust replacement reaches parity on real devices.
- Introduce one new ownership seam at a time.
- Prefer vertical slices that can run on a device over broad unfinished abstractions.
- Keep backend selection explicit until each `auto` preference has conformance evidence.
- Do not remove a shell behavior until its Rust replacement has failure-injection and recovery tests.
- Treat a real Android 5.10 device as the minimum release gate, not merely a compile target.

## Phase 0 — Baseline and reproducible toolchain

### Deliverables

- Root Rust workspace with `fluxd`, `flux-core`, `flux-platform`, `flux-testkit`, eBPF crates, and `xtask`.
- Pinned Rust toolchain, Android NDK version, Cargo dependency policy, formatting, linting, audit, and license checks.
- CI build for host Linux and `aarch64-linux-android`.
- Package manifest populated with exact Sing-Box and Flux binary sources, versions, targets, licenses, and hashes.
- `THIRD_PARTY.md`/SBOM provenance for all studied or reused code, with explicit review before copying GPL/AGPL sources.
- Captured real-device baseline replacing `BASELINE_CAPTURED_AT=UNSET`.
- Golden fixtures for current `settings.ini`, `addrsyncd.toml`, generated iptables restore files, and representative Sing-Box configs.
- Device inventory covering at least one 5.10 GKI device and one vendor-modified kernel.

### Exit gate

- Reproducible package creation succeeds from a clean checkout.
- Current release behavior is benchmarked and recorded before rewrite code becomes authoritative.
- CI refuses placeholder device evidence.

## Phase 1 — Control-plane tracer bullet

Current implementation status: the control-plane tracer bullet uses one `epoll` reactor for Unix control admission and `signalfd` shutdown, with admission closed before active connection handlers drain. The strict schema-1 `flux.toml` parser supplies the bounded writer queue. One immutable Capability Profile gates mutation-capable startup; below-floor or unverified profiles remain queryable without loading mutation configuration, disable/intent state, or the writer.

The atomic Rust-owned engine handoff is now wired into daemon startup. `RuntimeCoordinator` is a deep module behind the existing `LegacyDispatcher` seam and runs on the single serialized `LegacyControlBridge` worker. Its shell Adapter exposes `startup-recover`, `prepare`, generation-bound capture start/verify/`RUNNING`, capture stop, address resynchronization, and terminal state-publication phases. A boot-scoped mode lease prevents those phases from being mixed with `scripts/core` ownership; shell remains the Phase 1 networking writer, while Rust is the sole Sing-Box owner.

`prepare` allocates a nonzero shell-issued generation ID under the dispatcher lock and snapshots immutable runtime artifacts under `run/generations/<id>/`, including the generation manifest, exact Sing-Box configuration, generated environment/rule/cleanup data, and generation-local log. The manifest carries the same ID, is limited to 16 KiB, and bounds startup/stop timeouts to `1..=60000` milliseconds. Capture start, structural verification, active/previous records, `RUNNING` publication, and rollback all reject generation mismatch.

The `EngineSupervisor` binds the binary, config, and optional BusyBox launcher to SHA-256 identities, pins verified descriptors through `sing-box check` and `run`, records PID plus `/proc` start ticks, and requires child-owned listener/TUN readiness. It retains ownership through bounded TERM/KILL/reap, restart-window backoff, and delayed disappearance, so replacement cannot create a second child. Each phase child is also bounded to a nonzero timeout no greater than 60 seconds and isolated for forced process-group cleanup.

Start is `prepare` → engine admission → generation-bound capture start → generation-bound structural verification → generation-bound `RUNNING`. Capture start records its generation before mutation and removes that evidence only after successful compensation. Stop is capture detach → supervisor stop/reap → `STOPPED`. A stop/failure detach error enters `DetachPending`, retaining generation and terminal intent while blocking replacement until maintenance proves detachment; engine retirement and `STOPPED`/`FAILED` publication cannot overtake it. Reload prepares while the prior generation remains active, then detaches before replacement. Failed or uncertain reload detach enters `CaptureRepairPending`: the candidate is not launched, and maintenance proves detach before restoring, re-verifying, and republishing the old generation. Candidate failure rolls back using the prior immutable generation only after candidate detach is proven; uncertain compensation stays `DetachPending` and does not restart the previous generation. Rollback failure remains fail-open. A pending `RUNNING` retry requires fresh generation-bound capture verification, and verification uncertainty uses the same capture-repair path. Status carries an observed, independently revisioned `RuntimeSnapshot` alongside the desired/control `ControlSnapshot`.

After the Capability Profile admits mutation, startup invokes bounded `startup-recover` before strict configuration loading, administrative-intent replay, or socket admission. This lets stale same-boot capture be removed even when the current `flux.toml` is invalid. Below-floor or unverified profiles remain non-mutating/read-only and never invoke recovery. Recovery idempotently settles an empty runtime, cleans a same-boot Rust-owned active or partially activated generation, preserves evidence/lease on cleanup failure, rejects same-boot legacy ownership without component mutation, and retires prior-boot persistent evidence. Direct launches recover automatically after `PDEATHSIG` supplies child-death containment. A same-boot `busybox-setuidgid` generation is instead quarantined after capture detachment: recovery publishes `FAILED`, retains Rust ownership and the engine generation, and blocks automatic daemon restart because stale child death is unproven. Failure occurs before configuration validation or the initial intent is persisted or executed.

Direct Sing-Box and phase-shell children arm `PR_SET_PDEATHSIG(SIGKILL)` with a parent-race check. This contains direct children on daemon death, not whole process trees: phase descendants do not inherit it and BusyBox credential changes may clear it, which is why BusyBox generations require quarantine rather than automatic restart.

Still deferred are a stronger synthetic traffic and loop-prevention probe beyond structural capture verification, ancestor-safe `openat`/`openat2` traversal, long-term generation-log retention/rotation, pidfd/timerfd integration into the reactor, post-credential/process-cgroup containment, and real Android 5.10 release-gate evidence. Netlink and BPF reactor sources remain assigned to later phases.

### Deliverables

- `fluxd daemon` boot lifecycle with Unix control socket.
- Module-local Magisk `service.sh`; stop installing a global `/data/adb/service.d` launcher.
- Daemon-owned startup recovery before the control socket accepts mutations; the boot wrapper only launches/restarts and never runs a second recovery owner.
- `fluxd status`, `start`, `stop`, `reload`, `diagnose`, and JSON responses.
- Typed config parser for a minimal `flux.toml`.
- Read-only Capability Profile containing kernel version, boot identity, SELinux state, and current legacy backend facts.
- Sing-Box supervisor using child identity checks and bounded restart.
- Shell bridge adapter that invokes the existing `dispatcher`/scripts while `fluxd` owns administrative intent.
- `fluxctl` compatibility wrapper.

### Ownership rule

Shell phase scripts remain the only networking-state writer. Rust owns Sing-Box lifecycle and transaction ordering, but does not directly write rules, routes, or address-derived sets in Phase 1; the boot-scoped mode lease prevents `scripts/core` from becoming a second engine owner.

### Exit gate

- Magisk boot, enable/disable, status, restart, and abnormal Sing-Box exit pass on a device.
- A kernel below 5.10 performs no persistent mutation, remains queryable in settled `UnsupportedKernel`, returns the stable unsupported result to mutating clients, and does not enter a watchdog restart loop.
- Control protocol fuzz tests and permission tests pass.
- No behavior regression relative to the recorded baseline.

## Phase 2 — Configuration and Generation Compiler

### Deliverables

- Complete versioned config model and legacy migration command.
- Pure Desired State normalization.
- Network Inventory model populated from snapshots, initially without live ownership.
- Backend-neutral Capture Policy compiler.
- Generation IDs, digests, resource budgets, dry-run plan, and explain output.
- Sing-Box per-Generation overlay generation and validation.
- Revisioned device and Sing-Box Engine Capability Profiles, with Generation planning leases invalidated by boot changes, runtime demotions, or engine binary/profile changes.
- Golden tests proving parity with representative current rules.

### Exit gate

- Identical normalized inputs produce identical Generation artifacts.
- Property tests cover CIDR normalization, UID expansion, mark preservation, rule ordering, and resource limits.
- Boot/profile revisions and Sing-Box binary/profile changes invalidate stale planning leases, and persisted Generation records retain enough identity to reject unsafe recovery.
- Migration round-trips all supported current settings or emits an explicit lossy-mapping error.

## Phase 3 — Absorb `addrsyncd` and policy routing

### Deliverables

- Port `addrsyncd` netlink codecs, batched receive/send, extack handling, address filters, debounce maximum, and resync logic into `flux-platform`.
- Live link/address/route/rule observer.
- In-process address-derived Bypass Policy.
- Rust rtnetlink PBR apply/verify/cleanup.
- Generation journal and startup recovery for routes/rules.
- Remove the standalone `addrsyncd` process from runtime, while keeping its binary available for one bridge release as emergency rollback.

### Ownership rule

`fluxd` becomes the only owner of Flux PBR and address-derived rules. The shell `tproxy` adapter must call into `fluxd` or skip its old route section.

### Exit gate

- Lifecycle, event loss, address churn, IPv6 temporary-address, and cleanup tests equal or exceed current `addrsyncd` behavior.
- Kill-9 at each journal phase converges without deleting unrelated rules.
- Real-device CPU/RSS and convergence baseline is captured.

## Phase 4 — Rust xtables and ipset parity

### Deliverables

- Rust compiler for xtables restore programs.
- Direct child-process adapter for `iptables-restore`/`ip6tables-restore`.
- Coherent iptables-legacy versus iptables-nft detection and exact canaries; one Generation may use only one matched IPv4/IPv6 implementation family.
- Stable dispatch chains plus generation chains.
- ipset capability probes, generation-specific sets, inactive population/optional temporary swap, stable-jump cutover, verification, and cleanup without changing set contents under the old Generation.
- Bounded-tree fallback compiler.
- Transaction coordinator spanning Sing-Box, xtables, ipsets, and rtnetlink.
- Drift detection for Flux-owned chains, sets, routes, and rules.

### Ownership rule

`fluxd` becomes the only writer of Flux xtables/ipset state. `scripts/rules` and `scripts/tproxy` become unused compatibility artifacts.

### Exit gate

- TCP/UDP, IPv4/IPv6, DNS, FakeIP ICMP, tethering, per-app modes, multi-user policy, QUIC option, MSS clamp, and loop prevention pass on device.
- Android VPN scenarios prove that the default policy does not bypass always-on, lockdown, per-app, or explicitly selected networks.
- Failure injection before and after every external command/kernel acknowledgement produces old-active, new-active, or clean fail-open state.
- Rule-count and packet-path benchmarks are no worse than the current implementation outside agreed tolerances.

## Phase 5 — Native nftables backend

### Deliverables

- Native nfnetlink codecs for required nftables messages and expressions.
- Initial fingerprinted `nft` JSON/stdin Adapter used as a tracer bullet and differential oracle before the native codec is promoted.
- A side-effect-contained canary in the correct hook context combining the exact set lookup, masked mark, socket-transparent, TCP/UDP TPROXY, counter, and atomic batch behavior; list/normalize/delete verification is mandatory.
- nftables Capture Program compiler.
- Atomic activation/replace, verification, drift observation, and cleanup.
- Backend comparison tool that compiles the same Capture Policy to nftables and xtables artifacts.
- Device allow-evidence for `auto` selection.

### Exit gate

- Semantic parity suite passes against xtables for all supported Traffic Scope cases.
- nftables activation has no observable capture gap in stress tests.
- At least two independent Android kernel/vendor profiles pass before nftables becomes preferred in `auto` mode.

## Phase 6 — Managed TUN backend

### Deliverables

- TUN ioctl probe adapter.
- `EngineOwnedTun` as the shipping plan, with version-qualified `system`/`mixed`/`gvisor` stacks and route automation proven disabled as a hard capability requirement.
- A fully resolved TUN I/O plan: strict/automatic offload and multiqueue choices for `EngineOwnedTun`, plus future queue count, offload set, I/O driver, and steering choices for `FluxOwnedTunFd`; no unresolved `auto` value reaches activation.
- Flux-owned policy routing, exclusions, UID policy, IPv4/IPv6 handling, and recovery around the engine-owned TUN link.
- NAT64/CLAT, default-network handover, and VPN coexistence tests.
- Bounded stop/swap capture gap, prior-generation restart rollback, and outage reporting for fixed-interface Sing-Box-owned TUN reloads.
- A separate future `FluxOwnedTunFd` spike only after a documented Sing-Box FD-handoff contract; direct queue-count control, direct offload negotiation, `io_uring`, and TUN eBPF steering remain behind that gate, while engine-owned multiqueue/offloads stay version-qualified Sing-Box features.
- Accurate degraded reports for scopes TUN cannot capture without supporting netfilter behavior.

### Exit gate

- Local-app TUN parity passes on all reference devices.
- Tethering behavior is either verified equivalent or explicitly reported unsupported/degraded.
- Engine restart and interface recreation do not leak default routes or blackhole traffic.
- Candidate failure either restores the previous known-good TUN Generation or leaves a verified clean fail-open state with the outage recorded.

## Phase 7 — eBPF observation

### Deliverables

- Aya-based loader spike and documented comparison with libbpf-rs.
- `no_std` eBPF program workspace and shared map ABI.
- Generation-scoped-TUN tc probes using a Flux-owned qdisc/filter lease after exact link verification, including when Sing-Box owns the interface and queue FDs; add cgroup probes where feasible.
- Experimental physical-interface TC probe guarded by netd/qdisc/offload conflict detection.
- Bounded `RLIMIT_MEMLOCK` calculation/raise plus real map allocation; classify `CAP_BPF`, `CAP_NET_ADMIN`, relevant `CAP_PERFMON`, `CAP_SYS_ADMIN` fallback, and SELinux denial separately.
- Per-CPU counters, LRU sampled flow map, probed ring-buffer events with perf-event-array fallback, and generation control map.
- Cgroup programs limited to Flux/Sing-Box child processes unless a separate Android-owned-cgroup coexistence experiment proves safety.
- Capability and verifier diagnostics.
- Read-only CLI/web metrics path.

### Exit gate

- Detaching or crashing the eBPF plane has no correctness effect.
- Verifier/attach failure automatically selects `Off` or `Observe` degradation without disturbing capture.
- Idle overhead and event volume remain within recorded budgets.

## Phase 8 — eBPF acceleration

### Deliverables

- Flow/socket decision cache populated from the same compiled Capture Policy.
- Reserved-mark stamping as the explicit 5.10 bridge, with hook ordering documented: TC ingress may accelerate PREROUTING/tethered traffic; local OUTPUT is not claimed through TC egress.
- nftables/xtables fast path consuming only the verified Flux mark, never reading eBPF maps directly.
- Per-generation policy maps plus shared control map: attach new programs dormant, flip one BPF active-policy selector, then detach old programs; this does not publish `active.json`, and Flux falls back to detach/attach when the selector contract cannot be proven.
- Optional TUN queue steering only under the future `FluxOwnedTunFd` contract; TUN filter eBPF remains deferred.
- Parity oracle comparing accelerated decisions with the non-eBPF compiler for recorded traffic cases.

### Exit gate

- Zero policy divergence across replay, property, and real-device tests.
- Acceleration demonstrates a material packet-path or CPU improvement on target workloads.
- Unsupported/denied devices remain fully correct without acceleration.

## Phase 9 — Subscription and remaining shell removal

### Deliverables

- Rust subscription download/size limits, decoding, normalization, filtering, naming, template merge, validation, and atomic snapshot publication.
- Content-addressed rule-set asset lifecycle with size/format/digest validation and a retained known-good predecessor.
- Versioned DNS/fake-IP/reverse-mapping persistence with policy-change migration or deliberate flush and corruption fallback.
- External curl transport adapter retained only if Android TLS integration is not yet sufficiently proven.
- Installer migration and rollback support.
- Remove runtime dependencies on `jq`, AWK rule/config generation, dispatcher, init, core, addrsync, rules, and tproxy scripts.
- Keep only installation, a launch/restart-only boot watchdog, an uninstall wrapper that invokes `fluxd cleanup --offline`, and compatibility wrapper shell; shell never performs networking cleanup itself.

### Exit gate

- Existing supported subscription inputs have regression fixtures.
- Asset refresh failure never removes the active asset; fake-IP/cache crash, corruption, reload, and incompatible-schema tests pass.
- Malformed and adversarial inputs pass fuzz/resource-limit tests.
- Package contains only the documented final runtime paths.

## Phase 10 — Hardening and default switch

### Deliverables

- Capability/group reduction where device policy permits.
- Optional seccomp profile after syscall capture across every backend.
- State-path symlink/hardlink protections.
- Dependency audit, SBOM, reproducibility check, and unsafe-code audit.
- Final default backend selection based on the device evidence set.
- User migration guide and rollback package.

### Exit gate

- Full Android conformance matrix passes.
- Recovery, chaos, performance, and security gates pass.
- Standalone `addrsyncd` and old runtime scripts are removed from the release manifest.

## Test strategy

### Pure and model tests

- Config parsing and migration fixtures.
- Capture Policy normalization and ordering.
- Backend-plan selection over generated Capability Profiles.
- Mark/priority allocation and collision rejection.
- CIDR/IP set canonicalization.
- Generation digest determinism.
- State-machine and journal replay model tests.
- Failure injection after every planned operation.

### Fuzzing

- Legacy settings parser.
- TOML/JSON control inputs.
- Netlink route and netfilter decoders.
- nftables expression/ack decoders.
- Subscription URI and base64 decoders.
- eBPF event/map value decoders.

### Linux integration matrix

Run privileged network-namespace tests on at least:

- Linux 5.10;
- Linux 5.15;
- Linux 6.1;
- Linux 6.3 and 6.4 (or equivalent fixtures) to exercise the netfilter-BPF eligibility boundary;
- Linux 6.6 to exercise TCX and its legacy-TC fallback.

Scenarios:

- nftables and xtables TPROXY TCP/UDP;
- ipset swap and rollback;
- IPv4/IPv6 marked policy routing;
- TUN interface lifecycle;
- netlink event loss and full resync;
- external drift and ownership conflict;
- process crash during every transaction phase;
- eBPF load/attach/detach and verifier failure.

### Android device matrix

Minimum release set:

| Dimension | Required coverage |
|---|---|
| Kernel | 5.10 baseline plus at least one newer LTS |
| Kernel style | GKI and vendor-modified |
| Root framework | Magisk, KernelSU, APatch across the maintained set |
| Network | Wi-Fi, mobile, IPv6, IPv6-only/NAT64 where available |
| Traffic | local apps, hotspot/tethering, DNS, UDP/QUIC, long-lived TCP |
| Android identity | owner plus secondary user/profile |
| Coexistence | Private DNS, another VPN/TUN, CLAT, network handover |
| Backends | xtables, nftables where supported, TUN, eBPF off/observe/accelerate |

### Chaos cases

- `SIGKILL` `fluxd`.
- `SIGKILL` Sing-Box.
- Remove active chains/sets/routes externally.
- Replace config during activation.
- Repeated address churn and default-network flips.
- Netlink receive overflow.
- Disk full or read-only state directory.
- Corrupt `active.json` and newest Generation record.
- Command timeout or hung xtables lock.
- SELinux denial after a previously successful hint.
- Package UID reuse.

## Initial performance gates

These are provisional until Phase 0 captures real baselines:

- idle daemon CPU statistically indistinguishable from zero outside health ticks;
- no netlink event drops in the standard churn test;
- p95 address-to-safety-rule convergence below 250 ms after debounce;
- no more than 20% RSS growth over the measured current total of shell orchestration plus `addrsyncd`, unless justified by enabled eBPF/TLS features;
- no packet-path regression beyond 5% for the compatibility xtables backend;
- nftables/eBPF claims require statistically repeatable gains, not synthetic rule-count claims alone;
- startup reaches verified Running State within 5 seconds after Android boot readiness on the baseline device, excluding subscription download.

## Documentation required per backend

Before a backend may be selected automatically, its documentation must include:

- exact required capabilities and probes;
- kernel objects it owns;
- activation and cleanup order;
- failure and compensation behavior;
- semantic limitations;
- tested kernel/device matrix;
- benchmark results;
- security considerations;
- diagnostic examples.

## Immediate implementation backlog

1. Create the Rust workspace and `xtask` Android build.
2. Capture the current real-device baseline.
3. Implement kernel-version parsing and Capability Profile JSON.
4. Implement the control socket and `status` command.
5. Add Sing-Box child supervision without changing networking ownership.
6. Build and persist the exact Sing-Box Engine Capability Profile before compiling any Generation.
7. Implement legacy config migration in check-only mode.
8. Extract current rule-generation cases into backend-neutral golden fixtures.
9. Port the `addrsyncd` netlink codec and event loop behind the new Kernel Plane seam.
