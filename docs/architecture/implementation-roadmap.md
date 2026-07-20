# Fluxd Rewrite Implementation Roadmap

This roadmap turns the [blueprint](fluxd-blueprint.md) and [technical specification](fluxd-technical-specification.md) into independently verifiable tracer bullets. Each phase leaves a usable rollback path and assigns exactly one owner to active networking state.

## Delivery principles

- Treat this branch as pre-release development. Intermediate internal schemas, state, CLI, and
  adapters may break when that materially simplifies the final Rust architecture; per-commit
  backward compatibility with obsolete bridge content is not a goal.
- Preserve the current working TPROXY path only until the Rust replacement passes its safety
  cutover gate; then remove the superseded runtime component promptly.
- Introduce one new ownership seam at a time.
- Prefer vertical slices that can run on a device over broad unfinished abstractions.
- Keep backend selection explicit until each `auto` preference has conformance evidence.
- Do not remove a shell behavior until its Rust replacement has failure-injection and recovery tests.
- Freeze the executed shell networking path as a compatibility oracle that receives only
  correctness, security, cutover-contract, and rollback fixes; transfer one component at a time
  and never admit a second writer during comparison.
- Treat a real Android 5.10 device as the minimum release gate, not merely a compile target.
- Publish no bridge, alpha, beta, or release candidate for the rewrite. The only releasable state is
  the completed Rust runtime after legacy runtime writers, helpers, and compatibility wrappers are
  absent from the package; see ADR-0011.

## Current staged priority (2026-07-20)

The 2026-07-15 direction review closes the shadow/compiler/parser/oracle proof-infrastructure and
host bridge-attestation stage. The attested shell bridge is now a frozen development safety/oracle
substrate, not a product or release lane. Canonical xtables lowering now preserves exact schema-v1
forwarded-only bytes and identities while any local-OUTPUT input selects pure schema v2. The new
schema represents `FLX{4|6}O{generation:010}` MARK-only OUTPUT classifiers,
`FLX{4|6}P{generation:010}` mark-qualified loopback PREROUTING TPROXY companions, optional
unchanged `FLX{4|6}F{generation:010}` forwarded chains, typed routing/listener/escape requirements,
and descriptive prepare/attach/detach/retire ordering. The bounded native owner now consumes this
shape behind only `converge(target)` and `recover()`: stable PREROUTING/OUTPUT roots, coherent
descriptor-pinned restore/save, journaled groups-zero rtnetlink, exact readback, rollback, crash
recovery, cleanup invertibility, and the shell transition lease pass deterministic host tests and a
mechanism-only rooted x86_64 WSA namespace. Owner-payload schema 2 now binds a complete IPv4/IPv6
policy-routing audit digest, including loopback name/index identity; live name/index validation and
both-family xtables/routing residue audits gate `Active` and `CleanAbsent`. The shared shell fence
uses owner-v2 parent plus optional child PID/start identities and boot ID; either live participant
blocks, and one parent-bound mutating `addrsync` or `tproxy` phase child at a time changes only its
child slot and remains blocking after parent death. Current terminal journals retain the
guard, writer fence, and optional lease through fresh global dual-family absence. The exact coherent
previous-boot revision-1 `Activating` pre-lease boundary is recoverable, while same-boot or mismatched
missing-lease state and malformed/bare/mixed shell locks fail closed. Every legacy start, stop,
restart, and failure cleanup claims the fence before networking mutation. Production target
admission remains uninhabited, so the shell bridge is still the sole production writer.

The native owner cannot be cut over while standalone address synchronization or shell policy
routing remains active: its durable Generation lease deliberately blocks every mutating
`addrsync`, `tproxy`, and dispatcher phase. The immediate delivery lane is therefore backlog item 3:
finish the canonical Generation and exact device/mark/routing/address inputs required by one
complete native transaction. Backlog item 4 then qualifies that complete transaction on reviewed
Android 5.10/ARM64 profiles, stops every shell networking writer and standalone address synchronizer
before the first Rust write, transfers the lease atomically, and deletes the replaced duties. No
supported intermediate native-xtables/shell-addrsync composition exists.

Within backlog item 3, the remaining 21 fwmark census cells are paused. The pinned Android `netId`
packet writer is ordered under mangle INPUT after input route selection, so its envelope overlap is
not yet a proven simultaneous collision; it is also not compatible until the runtime netd
profile/chain, listener observation, and mark preservation can be bound on one physical Android
ARM64 target. Establishing a viable ordered-lifetime/coexistence target and procedure is the next
mark-authority step. Only then should source-collector expansion resume; adding more non-authorizing
cells first would not advance the production activation target.

Correctness gates retain strict ordering:

Phase numbers below preserve architectural workstreams and implementation history. They are not the
execution order; this current-priority section and the prioritized backlog are authoritative.

The mandatory bridge-contract correction from the 2026-07-14 code/documentation deviation audit is
complete. The reported live-worktree compile failure was stale at the audited HEAD, but the
remaining findings were valid. The completed checkpoint makes `fluxctl status`
delegate to authoritative daemon state, rejects the meaningless one-shot `addrsyncd` tracked cleanup,
completes settings migration, exposes only the current development bridge's TPROXY/zone choices,
replaces obsolete public lifecycle documentation, and separates development staging from strict
package-consistency verification. It does
not authorize native mutation, TUN, eBPF acceleration, or kernel-module loading. Release provenance,
license, hash, SBOM/build metadata, and real-device evidence must still be populated before the new
verifier can pass, and a verifier pass cannot override ADR-0011's runtime-completion gate.

1. **Bridge safety:** the `100.64.0.0/10`, mandatory-exclusion, empty allow/deny,
   TUN-rejection, and converged-`addrsyncd` readiness checkpoints are complete. The Stage-1
   [Generation-scoped functional capture canary](functional-capture-canary.md) model, coordinator
   ordering, lifecycle tests, protocol-v3 verification status, and authoritative schema-v2
   listener/delivery validator are complete; the current pre-release bridge still explicitly
   selects structural-only compatibility. The privileged Linux checkpoints prove the isolated dual-stack TCP/UDP/DNS
   topology, ingress-only PREROUTING TPROXY, original-destination recovery, marked relay egress,
   source-preserving UDP replies, route controls/counters, and exact cleanup. The strict
   Linux/Android `/proc` FD plus INET_DIAG collector prerequisite, prebound session, and typed
   attempt-context handoff bind the exact tuple, UID, mark, FD/inode/cookie, complete dumps,
   process identity, timing, netlink port/opening identity, sequences, deadline, and single-move
   ownership. Cleanup validation binds process and object retirement, absence, evidence lifetime,
   retained-facility observation, and gate/deadline chronology. The no-traffic credential
   preflight proves restricted role credentials, namespace/map identity, pidfd exit versus parent
   reap, and retained-child ordering.

   The fail-closed TPROXY-only executor seam and both receipt contracts are complete model
   boundaries, but both production receipt authorities remain uninhabited and the production
   xtables target still reports `Unsupported` before mutation. The retained `SingBoxChild` now opens
   an exact child-origin `ProcessHandle`; `EngineSupervisor` admits it only from matching ready
   ownership, specification, readiness, identity, and snapshot revision; the coordinator binds one
   opener to the immutable request; and execution opens it after availability but before preparation
   without giving the driver pidfd or signal/wait/reap authority. The process verifier now preserves
   the child-origin
   initial observation and reobserves the same retained pidfd after capture verification, producing
   a non-cloneable raw pair bound to identity, revision, opening ID, stable complete process
   observations, and the exclusive deadline. The platform now obtains authoritative
   user/mount/network namespace identities for every thread, reads bounded canonical UID/GID maps
   twice, and rejects thread/domain/map drift. The process verifier validates both observations
   against the request's exact four-slot UID/GID policy, empty groups, zero capabilities,
   `NoNewPrivs`, credential-map domain, and daemon network namespace. Still pending are verifier
   completion chronology, driver-owned client/peer child retirement, independent listener
   observation, a versioned report capability/parser, actual prebound collector observations,
   cleanup binding, and schema-v2 construction with test-only fixtures. All remain fail-closed
   while production returns `Unsupported`.

   Before any positive traffic producer or receipt authority may be inhabited, one concrete
   local-OUTPUT capture mechanism must preserve TPROXY listener semantics on the target device and
   the immutable `EngineCapabilityProfile` must declare the exact supervised report source,
   transport/framing, loss/sequence behavior, object lifetime, and schema. Stock logs or APIs are
   not assumed authoritative. A separately qualified cgroup-BPF authority remains an unassigned
   future experiment; production never loads a `.ko`. REDIRECT/DNAT cannot qualify a TPROXY plan,
   and TUN remains rejected until one exact routing owner passes readback and forced-death cleanup
   canaries.
   The remaining 13b-2b driver-child retirement, listener/report, and collector/factory work are now
   production authority-binding prerequisites in backlog item 3 for the delivered owner, not
   grounds for another backend-mechanics checkpoint. Cgroup-BPF remains unassigned until a separate
   TCP/UDP-complete authority design and exit gate exist.
2. **Phase 2 shadow policy — complete and frozen:** the deterministic, backend-neutral shadow
   Capture Program, semantic fixtures, bounded restore parser, pinned raw shell oracle, and
   checked-in oracle-fixture parser round-trip are delivered. They remain non-authorizing
   characterization inputs: no shadow artifact enters a Generation or activation path, and this
   lane receives only corrections needed to preserve its frozen contract. The separate Phase 4
   lowerer may consume an artifact with a caller-supplied non-authorizing namespace, mark candidate,
   and optional descriptive local-routing targets; forwarded-only results remain schema v1 and
   local-OUTPUT results select schema v2. Neither form promotes or mutates the Phase 2 artifact.
3. **Native Phase 3 activation prerequisites — current:** complete exact device/artifact identity,
   then make one physical ARM64 ordered-mark-lifetime/coexistence target viable before resuming the
   remaining census cells and point-in-time coordination. Complete observer continuity, mark
   preservation, domain/network-selection handoff, route reachability, canonical Generation
   finalization, and in-process address-derived policy. These inputs must describe one complete
   transaction before production target admission exists. They confer no mutation authority by
   themselves and must not create another public raw-writer seam.
4. **Phase 4 bridge substrate — frozen; bounded native owner delivered, production cutover follows
   Phase 3:**
   the validated legacy source-shape renderer independently reproduces the pinned IPv4/IPv6
   apply/cleanup fixtures, and Rust-owned preparation exclusively invokes
   `fluxd render-legacy-rules`. Explicit legacy ownership alone sources `scripts/rules`; the cache
   records `rust` or `shell` and never silently falls back between them. In current production
   composition, `scripts/tproxy` remains the sole restore executor and kernel writer. Renderer-owned
   plan, family-pair, and enabled-family-set identities are domain-separated, and Rust-owned
   preparation publishes a strict Generation-bound receipt only after every staged artifact exactly
   matches one rebuilt plan. The separate private owner now consumes canonical schema-v2 output
   behind `converge(target)` and `recover()` and owns stable roots, restore/save, policy routing,
   exact readback, rollback, crash recovery, and the shell-visible transition lease. Its rooted
   x86_64 WSA execution is mechanism evidence only; positive production target construction remains
   uninhabited. Do not expand the bridge into a release-qualification project. Reuse it for targeted
   cutover fault injection only after backlog item 3 completes the production inputs. Backlog item 4
   then qualifies reviewed Android 5.10/ARM64 profiles, stops standalone address synchronization and
   all shell route/xtables mutation before the first Rust write, transfers the writer lease, and
   deletes the replaced duties. There is no dual-writer interval and no public bridge release.
5. **Optional eBPF probe — deferred:** isolated, opt-in `xt_bpf` mechanics may run only in a
   disposable test namespace without persistent pins, production daemon integration, Capability
   Profile publication, implicit module autoload, or writes to live Flux chains. Production-state
   integration waits until `fluxd` is the sole xtables writer; positive acceleration also requires a
   complete conventional classifier, parity evidence, and device benchmarks.

TUN dual route ownership is P0: until `EngineOwnedTun` has one proven owner, the bridge selects exactly
one routing owner or reports TUN unsupported.

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
- CI refuses placeholder, payload-unbound, wrong-device, or incomplete test-set evidence. Signed
  device/CI attestation remains a `package-magisk` release gate.

## Phase 1 — Control-plane tracer bullet

Current implementation status: the control-plane tracer bullet uses one `epoll` reactor for Unix control admission and `signalfd` shutdown, with admission closed before active connection handlers drain. The strict schema-1 `flux.toml` parser supplies the bounded writer queue. One immutable Capability Profile gates mutation-capable startup; below-floor or unverified profiles remain queryable without loading mutation configuration, disable/intent state, or the writer.

The atomic Rust-owned engine handoff is now wired into daemon startup. `RuntimeCoordinator` is a deep module behind the existing `LegacyDispatcher` seam and runs on the single serialized `LegacyControlBridge` worker. Its shell Adapter exposes `startup-recover`, `prepare`, generation-bound capture start/verify/`RUNNING`, capture stop, address resynchronization, and terminal state-publication phases. A boot-scoped mode lease prevents those phases from being mixed with `scripts/core` ownership; shell remains the Phase 1 networking writer, while Rust is the sole Sing-Box owner. The Rust-owned Phase 1 `prepare` path currently admits only `PROXY_MODE=tproxy`: it rejects TUN before initialization or engine-manifest publication because neither exact Sing-Box route cleanup after forced death nor a non-TPROXY Flux route owner has been proven.

`prepare` allocates a nonzero shell-issued generation ID under the dispatcher lock and snapshots immutable runtime artifacts under `run/generations/<id>/`, including the generation manifest, exact Sing-Box configuration, generated environment/rule/cleanup data, and generation-local log. The manifest carries the same ID, is limited to 16 KiB, and bounds startup/stop timeouts to `1..=60000` milliseconds. Capture start, structural verification, active/previous records, `RUNNING` publication, and rollback all reject generation mismatch.

The `EngineSupervisor` binds the binary, config, and optional BusyBox launcher to SHA-256 identities, pins verified descriptors through `sing-box check` and `run`, records PID plus `/proc` start ticks, and requires child-owned listener readiness for the currently admitted TPROXY bridge. Its strict manifest model retains TUN readiness parsing for the future single-owner plan, but Phase 1 preparation does not publish such a manifest. The supervisor retains ownership through bounded TERM/KILL/reap, restart-window backoff, and delayed disappearance, so replacement cannot create a second child. Each phase child is also bounded to a nonzero timeout no greater than 60 seconds and isolated for forced process-group cleanup.

The standalone bridge `addrsyncd` now builds resynchronization plans from fresh canonical IPv4/IPv6 rule dumps instead of treating its in-memory address set as observed truth. The dump path preserves multiplicity, removes duplicate exact-shape rules, refreshes later event/cleanup tracking, and conservatively retains observed plus desired identities after partial failure before requesting another resync. This is exact semantic-shape evidence rather than creator provenance because the current rule requests do not set `FRA_PROTOCOL`.

`run --daemon` now retains its ready descriptor until startup cleanup, reconciliation/apply, and two clean readback passes have converged. Address and rule snapshots use the unicast rule socket so the subscribed route socket retains racing notifications; immediately before readiness, that socket is drained to `EAGAIN` as the linearization barrier. Notifications, parse failures, truncated datagrams, overruns, interrupted dumps, discarded receive-budget tails, or failure to reach `EAGAIN` force another reconciliation. An eight-second absolute convergence deadline bounds the child, while parent-side timeout, EOF, or invalid readiness tears the child down through bounded TERM/KILL/reap. Partial or lossy dumps are never accepted as verification.

The retained xtables bridge now invokes its application chain for every local OUTPUT policy, including `APP_PROXY_MODE=0`, so the configured Proxy Engine owner bypass is not skipped before the default proxy action. Rust-owned Phase 1 requires `xt_owner` before `init` and revalidates that capability from the generated configuration before publishing immutable Generation artifacts. This is the current compatibility loop-escape prerequisite, not the required functional proof: root/root mode still bypasses a broader credential class than the final exact-process/socket ownership design.

Start is `prepare` → engine admission → generation-bound capture start → generation-bound structural verification → configured functional gate → generation-bound `RUNNING`. The current pre-release composition selects structural-only compatibility, while required-mode tests execute fresh exact-binding attempts. Capture start records its Generation before mutation and removes that evidence only after successful compensation. Stop is capture detach → supervisor stop/reap → `STOPPED`. A stop/failure detach error enters `DetachPending`, retaining Generation and terminal intent while blocking replacement until maintenance proves detachment; engine retirement and `STOPPED`/`FAILED` publication cannot overtake it. Reload prepares while the prior Generation remains active, then invalidates its functional authorization immediately before detachment and replacement. A prepare-only failure preserves the untouched active pass. Failed or uncertain reload detach enters `CaptureRepairPending`: the candidate is not launched, and maintenance proves detach before restoring, freshly verifying, and republishing the old Generation. Candidate failure rolls back using the prior immutable Generation only after candidate detach is proven; candidate canary evidence never authorizes the rollback. Uncertain compensation stays `DetachPending` and does not restart the previous Generation. Rollback failure remains fail-open. A pending `RUNNING` retry, engine identity loss, repair/restoration, or active address resynchronization requires a fresh complete gate. Status carries an observed, independently revisioned `RuntimeSnapshot`, including protocol-v3 verification state, alongside the desired/control `ControlSnapshot`.

After the Capability Profile admits mutation, startup invokes bounded `startup-recover` before strict configuration loading, administrative-intent replay, or socket admission. This lets stale same-boot capture be removed even when the current `flux.toml` is invalid. Below-floor or unverified profiles remain non-mutating/read-only and never invoke recovery. Recovery idempotently settles an empty runtime, cleans a same-boot Rust-owned active or partially activated generation, preserves evidence/lease on cleanup failure, rejects same-boot legacy ownership without component mutation, and retires prior-boot persistent evidence. Direct launches recover automatically after `PDEATHSIG` supplies child-death containment. A same-boot `busybox-setuidgid` generation is instead quarantined after capture detachment: recovery publishes `FAILED`, retains Rust ownership and the engine generation, and blocks automatic daemon restart because stale child death is unproven. Failure occurs before configuration validation or the initial intent is persisted or executed.

Direct Sing-Box and phase-shell children arm `PR_SET_PDEATHSIG(SIGKILL)` with a parent-race check. This contains direct children on daemon death, not whole process trees: phase descendants do not inherit it and BusyBox credential changes may clear it, which is why BusyBox generations require quarantine rather than automatic restart.

The exact Linux distinct-UID/GID credential preflight is delivered but sends no traffic. It now
keeps probe/engine children live while parent-owned pidfds bind exact PID/start ticks and stable
process-wide credentials; bounded handshakes separately validate namespace/map identity and the
distinction between exit and confirmed parent reap. The TPROXY-only local-OUTPUT executor,
capture-receipt, and process-ownership-receipt
boundaries are also delivered: read-only typed availability is separate from prepared execution,
drivers return unverified capture/process proof and raw observations, sealed verifiers alone may
mint the two non-cloneable receipts, and only fully receipt-bound artifacts reach the module-private
evidence factory. The current zero-state xtables
driver reports `Unsupported` with cleanup `NotRequired` before mutation because it does not
implement or authorize the complete local-OUTPUT TPROXY transaction; its prepared/raw type and the
production receipt authority are
uninhabited, so it adds no positive traffic or evidence path. The retained engine-child authority
handoff is delivered: `SingBoxChild` opens an exact child-origin `ProcessHandle`, `EngineSupervisor`
requires matching ready ownership, and the coordinator/execution path moves that authority once
into the process verifier without transferring signal/wait/reap authority. The verifier now
preserves the initial child-origin observation and reobserves the same retained pidfd after capture
verification. The raw observation now includes authoritative stable user/mount/network namespace
identities and canonical UID/GID-map digests, and the verifier requires the exact request engine
credential/domain policy for both scans. Still deferred are final verifier completion chronology,
prepared-driver client/peer child ownership, schema-v2 listener-observer/report parsing and
factories, production context use of the delivered
attempt-owned outbound-collector handoff, actual collector observations, capability-qualified
engine/probe execution, a production traffic producer, and production Android
adapter/qualification. The validator
itself is complete and rejects weak,
substituted, lossy,
stale, or transport-incomplete delivery evidence. REDIRECT/DNAT, ingress promotion, counters,
route lookups, and veth-bounce substitutions cannot qualify that TPROXY backend. The delivered
preflight makes
missing helpers, subordinate IDs, parent maps, and group authority an explicit optional-mode skip
or required-mode failure, never a root/root or same-UID fallback. Also deferred are an exact-device TUN single-
owner and forced-death route-cleanup canary, ancestor-safe `openat`/`openat2` traversal, long-term
Generation-log retention/rotation, pidfd/timerfd integration into the reactor, post-credential/
process-cgroup containment, and real Android 5.10 release-gate evidence. Netlink and BPF reactor
sources remain assigned to later phases.

### Deliverables

- `fluxd daemon` boot lifecycle with Unix control socket.
- Module-local Magisk `service.sh`; stop installing a global `/data/adb/service.d` launcher.
- Daemon-owned startup recovery before the control socket accepts mutations; the boot wrapper only launches/restarts and never runs a second recovery owner.
- `fluxd status`, `start`, `stop`, `reload`, `diagnose`, and JSON responses.
- Typed config parser for a minimal `flux.toml`.
- Read-only Capability Profile containing kernel version, boot identity, SELinux state, and current legacy backend facts.
- Sing-Box supervisor using child identity checks and bounded restart.
- Shell bridge adapter that invokes the existing `dispatcher`/scripts while `fluxd` owns administrative intent.
- Development-only `fluxctl` compatibility wrapper, removed or replaced by a direct Rust
  multicall/symlink entry before release.

### Ownership rule

Shell phase scripts remain the only networking-state writer. Rust owns Sing-Box lifecycle and transaction ordering, but does not directly write rules, routes, or address-derived sets in Phase 1; the boot-scoped mode lease prevents `scripts/core` from becoming a second engine owner.

### Exit gate

- Magisk boot, enable/disable, status, restart, and abnormal Sing-Box exit pass on a device.
- A kernel below 5.10 performs no persistent mutation, remains queryable in settled `UnsupportedKernel`, returns the stable unsupported result to mutating clients, and does not enter a watchdog restart loop.
- Control protocol fuzz tests and permission tests pass.
- No behavior regression relative to the recorded baseline.
- The bridge emits RFC 6598 as `100.64.0.0/10`, keeps mandatory loop/device-local exclusions separate from configurable direct defaults, and has golden fixtures for both.
- Empty application allowlist proxies zero otherwise eligible applications; empty denylist proxies all otherwise eligible applications.
- The Rust-owned Phase 1 bridge reports TUN unsupported. Re-enabling it requires an exact-device single routing owner plus forced-death cleanup/readback evidence; it must never activate the current Sing-Box automation together with Flux's TPROXY-specific PBR.
- `addrsyncd` readiness requires initial dump/cleanup/apply/readback convergence. The coordinator now supports the required [Generation-scoped functional capture and loop-prevention canary](functional-capture-canary.md) at every `RUNNING` gate, but the production Android composition remains explicitly structural-only until the real-device qualification matrix succeeds.

## Phase 2 — Configuration and Generation Compiler

The first Phase 2 checkpoint is complete and frozen. It is deliberately narrower than a Generation
compiler and compiles
typed compatibility inputs into an ordered shadow Capture Program, with distinct local and
forwarded programs, canonical mandatory/configurable bypass layers, optional inventory-derived
host bypass provenance, deterministic application and interface selectors, compile-time budgets,
semantic version/digest, and an explanation of every compatibility assumption and deferred
prerequisite. It is pure and observation-only. The artifact itself contains no backend restore
renderer, package-to-UID discovery, kernel or filesystem access, Generation ID, planning or
mutation authority, writer/ownership token, prepared/active conversion, coordinator execution path,
or eBPF/TUN/module action. The shell path remains the sole production bridge networking writer and
the frozen semantic oracle.

The independent Phase 4 `LegacyRulesPlan` does not change this boundary. It preserves the admitted
shell generator's source shape for bridge cache production; it neither consumes nor promotes a
`ShadowCaptureArtifact` and carries no Generation or mutation authority.

The separate Phase 4 lowerer now consumes a `ShadowCaptureArtifact` together with a non-authorizing
generation namespace, structurally valid TPROXY target, optional descriptive local-routing targets,
explicit extension state, and command budget. Forwarded-only input preserves exact schema v1.
Local-OUTPUT input selects schema v2 and derives the separate MARK-only OUTPUT classifier,
mark-qualified loopback PREROUTING TPROXY companion, typed prerequisite identities, and lifecycle
order. Both forms remain unattached prepare/retire syntax artifacts and add no authority or runtime
execution path.

This completed checkpoint does not discharge the complete runtime-semantic or ownership gate.
Oracle-derived fixtures pin semantics such as RFC 6598, mandatory bypasses, empty allow/deny
behavior, multi-user UIDs, interface matching, family/domain separation, and compatibility engine
UID/GID loop bypass. The independent source-shape renderer now reproduces and attests the frozen
IPv4/IPv6 restore artifacts. Extension-free schema-v1 forwarded and schema-v2 local-OUTPUT programs
now lower into unattached xtables artifacts. The separate private owner consumes the ADR-0012
transaction with stable hooks, restore/readback/rollback, failure recovery, cleanup, and the writer
lease behind test-only admission. Production authority binding and real-device cutover gates remain
before xtables ownership transfers; established-flow caching, transparent-socket DIVERT, FakeIP ICMP,
QUIC rejection, and MSS clamping remain separately unsupported extensions.

The bounded raw oracle checkpoint is also complete and frozen. The canonical environment, input,
and fixture pin contract lives in `tests/oracle/xtables/manifest.json`; do not duplicate or update
its hashes in narrative documentation. `cargo xtask xtables-oracle --check` verifies the four raw
IPv4/IPv6 apply/cleanup fixtures, while explicit `--update` is the reviewed regeneration path.
Separately, `cargo test -p flux-platform --test xtables_restore_oracle` proves that the checked-in
bytes parse and canonically round-trip through the syntax artifact. Neither command invokes restore
tools or live networking, and neither establishes renderer semantics, kernel acceptance, or device
parity. See `docs/development.md` for the operational workflow.

This profile does not run configuration/kernel detection and does not cover QUIC, PBR, or forced
cleanup. The fixtures are not kernel-acceptance or Android/Magisk-parity evidence and add no
renderer, Generation, ownership, writer, prepared/active, coordinator, or activation path.

### Deliverables

- Complete versioned config model. A one-time legacy migration command is optional and is omitted if
  it would delay cutover.
- Pure Desired State normalization.
- Network Inventory model populated from snapshots, initially without live ownership.
- Backend-neutral Capture Policy compiler producing separate ordered local-OUTPUT and
  forwarded-ingress programs, a canonical mandatory safety baseline, resource accounting, and a
  stable semantic digest.
- Two-stage Generation compiler: bounded non-authorizing candidate enumeration/scoring, followed by finalization that takes a bounded candidate-keyed Planning Evidence set by value and consumes the selected authority.
- Generation IDs, digests, non-authorizing evidence receipts, resource budgets, dry-run candidate set, and explain/rejection output.
- Sing-Box per-Generation overlay generation and validation.
- Revisioned device and Sing-Box Engine Capability Profiles, with Generation planning leases invalidated by boot changes, runtime demotions, or engine binary/profile changes.
- Frozen oracle-derived semantic fixtures plus the completed independent source-shape renderer
  golden tests and the separate extension-free schema-v1/v2 canonical xtables lowering tests.

### Exit gate

- Identical normalized discovery inputs produce identical bounded candidate sets; identical candidate/evidence/selection inputs produce identical Generation artifacts and receipts.
- Property tests cover CIDR normalization, UID expansion, mark preservation, rule ordering, and resource limits.
- Boot/profile revisions and Sing-Box binary/profile changes invalidate stale planning leases, and persisted Generation records retain enough identity to reject unsafe recovery.
- If the optional legacy importer is implemented, it round-trips its declared supported settings or
  emits an explicit lossy-mapping error.

## Phase 3 — Absorb `addrsyncd` and policy routing

Current implementation status: the observer publishes one atomic link/address/route/rule `NetworkInventorySource` epoch from a strict `RTM_GETLINK` → `AF_UNSPEC RTM_GETADDR` → `AF_UNSPEC RTM_GETROUTE` → `AF_UNSPEC RTM_GETRULE` transaction. Every phase owns a fresh nonzero sequence and completes before the next request is sent; only RULE completion may replay transaction-wide bounded LINK/ADDRESS races and publish. Links and addresses are canonical sets, while routes and rules preserve validated dump order and multiplicity. Link decoding preserves raw names and link kinds through the netlink wire bound, unknown flags/types/states, and extended dump acknowledgements while rejecting ambiguous or loss-marked datagrams; partial live link notifications preserve optional fields omitted by the kernel. The driver uses 256 KiB receive slots, a 1 MiB default per-turn byte budget, fresh phase/interphase deadlines, exact sequence ownership, and optional registration in the daemon's existing reactor after capability admission.

The route layer adds canonical route domain facts and a strict private `RTM_NEWROUTE`/`RTM_DELROUTE` decoder, including canonical prefixes, raw table/protocol/scope/type/flag preservation, direct and cross-family-via gateways, ordered multipath weights, named-nexthop IDs, `NLM_F_REPLACE`, and strict loss/DONE/attribute validation. Route dumps now enter `NetworkInventory` as ordered multisets. Metrics, encapsulation, flow, and new-destination semantics remain a lossy topology/selection projection; NH-ID-only paths require later nexthop-object observation or compatibility gating; and live route identity/replacement is not yet defined. Route notifications before `GETROUTE` are subsumed by the later dump, while notifications after that cutoff taint the transaction and force a fresh full dump.

The rule foundation adds canonical IPv4/IPv6 policy-rule facts and a strict private `RTM_NEWRULE`/`RTM_DELRULE` decoder. It preserves raw action, origin-protocol, and rule-flag values while decoding table, priority, interface, GOTO, fwmark, tunnel, suppression, L3MDEV, UID, IP-protocol, port-range, and IPv4 flow selectors. Prefix host bits and fwmark bits outside the mask are normalized to their effective selection semantics; mandatory Linux 5.10 dump attributes, reserved header bytes, compact/extended table agreement, family widths, scalar endianness, interface termination, range bounds, padding, ordered duplicate events, and whole-datagram loss metadata are validated. Well-framed future `FRA_*` attributes remain observable without being trusted: each affected rule carries bounded ordered opacity diagnostics plus an aggregate SHA-256 change fingerprint over every opaque attribute. The fingerprint participates in inventory identity but is not raw ownership or deletion evidence. Linux fib rules have no replacement operation, so `NLM_F_REPLACE` remains an ordinary upsert flag with no exposed rule semantics.

Canonical rules remain semantic projections rather than exact deletion identities, but they now enter the runtime inventory in exact dump order with multiplicity because equal-priority and duplicate rules are valid. Rule notifications before `GETRULE` are subsumed by the later dump; notifications after RULE starts force a full resynchronization instead of ambiguous live insertion or deletion. Generic kernel rule identity and reusable policy-routing mutation remain pending in this inventory layer; the delivered bounded xtables owner separately retains exact raw route/rule identities for its admitted transaction.

The transport uses byte-exact `AF_UNSPEC RTM_GETROUTE` and `RTM_GETRULE` requests with zeroed 12-byte family headers, unique nonzero sequences, strict `NLM_F_REQUEST | NLM_F_DUMP` framing, and no filter attributes. Endian-specific fixtures and a sequential real-kernel LINK→ADDRESS→ROUTE→RULE smoke verify the shared socket and receive ring. Faults during an active phase stale the source and drain the owned sequence to terminal `NLMSG_DONE` or `NLMSG_ERROR` before restarting at LINK; raw terminal hints survive semantic decode failures and intact kernel-response slots in otherwise lossy receive batches. A drain that cannot recover terminal evidence by its deadline permanently degrades only observation for the current socket registration rather than risking an overlapping request.

The first inventory consumer is now a pure address-bypass planner in `flux-core`. From one complete snapshot and an explicit caller-resolved routing specification, it derives deterministic unique IPv4 `/32` and IPv6 `/128` intents after family, usability, flag, exact-address, and CIDR filtering. Valid IPv4-mapped inputs normalize consistently, malformed mapped inventory facts are rejected, and fixed rule/conflict bounds prevent unbounded planning evidence. Plans carry the originating epoch plus an opaque snapshot identity. The planner rechecks selected priority slots but does not allocate Android-safe priorities, infer ownership from semantic equality, adopt or retire existing rules, encode rtnetlink messages, or mutate the kernel. The placement checkpoint below validates caller-selected numeric windows; Android classification and allocation, the generation journal, native encoding, and mutation remain later work.

The versioned RPDB placement checkpoint is now present as a second pure inventory consumer. Caller-supplied classifications remain aligned with every ordered rule fact and are bound to a classifier revision; enabled families fail closed on opaque attributes, unknown classifications, or missing policy boundaries. A classifier cannot override incomplete kernel semantics with `DoesNotConstrainFlux`; opacity in a disabled family remains outside a single-family lease, while dual-stack admission still succeeds or fails atomically. Candidate admission reserves distinct address-bypass and proxy priorities strictly between the proven boundaries, rejects exact priority occupancy and intersecting GOTO edges, and requires the proposed private route table to be empty of foreign routes and rule references. Same-epoch cross-tracker audits and stale classifier revisions are rejected by process-local snapshot identity. The lease projects address-bypass rules only toward table 254 and explicitly defers mark leasing, boot and network-namespace identity, durable ownership, exact kernel mutation identity, route-policy canaries, native encoding, and all mutation.

The partial mark-planning checkpoint is present rather than manufacturing a synthetic lease. `flux-core` can validate a common masked field and prove collisions with Android's `netId` bits and the ordered RPDB selector inventory, including exact-looking, inverted, unknown-action, cross-family, and duplicate rules. Reports retain bounded ordered conflict evidence, mark the RPDB evidence source `Opaque` whenever any observed rule has unmodeled attributes, expose unavailable device-policy, xtables, nftables, TC/BPF, XFRM, connmark/socket, and ownership sources, and remain bound to the exact inventory identity. Opacity is uncertainty rather than a manufactured collision: a definite selector overlap still yields `Conflicting`, while a disjoint opaque inventory remains `Incomplete`. Even with no known collision the partial outcome is only `Incomplete`: generic Android has no public mark allocator, negative scans are not positive allocation authority, and no `MarkLease`, expert override, backend plan, or mutation intent is produced.

The Android semantic classifier checkpoint now extracts exact roles under three explicitly selected, source-pinned AOSP grammars: Android 12 r1, Android 13 r1, and the pinned March 2025 netd revision. It validates the complete modeled signature rather than priority alone, preserves rule order and duplicates, requires the fixed initialization skeleton in every observed family, and publishes bounded diagnostics for opacity, signature drift, unfamiliar priorities, missing anchors, and nonmonotonic order. V1 conservatively maps every recognized role before default-network to `MustPrecedeFlux`, maps exact default-network and final unreachable rules to `TerminalBarrier`, and never emits `DoesNotConstrainFlux`.

The classifier also embeds a static lattice contract in its aligned audit because an observed dump cannot reserve absent future netd rules. Android 12 has no integer priority between the maximum UID-default-unreachable priority `28999` and default-network `29000`; Android 13 and later have only `30999` between `30998` and `31000`. Both the generic planner and Android-specific diagnostic wrapper therefore reject the current two-rule address-bypass-plus-proxy topology even when a sparse snapshot appears to contain a hole. This is a discovered design constraint, not a reason to weaken classification: the next routing-design checkpoint must split traffic domains, prove selector/network-selection handoff, or remove one RPDB priority before allocation, encoding, ownership, and mutation work can continue.

The first topology-redesign checkpoint now provides a pure `flux-core` feasibility report rather than weakening the placement lease. Address filtering first produces a neutral snapshot-bound host set shared with the compatibility address-rule planner, allowing a future pre-mark Capture Policy realization to consume zero RPDB priorities without yet claiming backend ordering. Android topology reports then anchor residual local OUTPUT to one exact observed default-network rule and present/admin-up loopback link, or forwarded capture to one exact observed tethering rule and present/admin-up non-loopback ingress link. Exact input-interface and fwmark conflicts are the only current selector-disjoint proofs; opacity, drift, missing anchors, invalid family profiles, and overlapping same-domain anchors with distinct tables fail closed.

The resulting structural evidence is explicit: Android 12 local OUTPUT remains impossible; Android 13/current local OUTPUT has only `30999`; and each exact tether ingress has `20001..20999`. A dedicated address-bypass RPDB rule still needs two slots and fails for local OUTPUT; because that rule has no traffic-domain selector, it is also incompatible with the tether interval. A pre-mark address host set reduces the structural demand to one, but no result is Android-policy-safe or activation-capable: domain-identity and network-selection handoff, mark authority, route reachability, exact Capture Program ordering, boot/namespace identity, observer continuity, ownership, mutation identity, and device canaries remain mandatory.

The next pure checkpoint now aggregates those reports atomically for a bounded requested Traffic Scope. A request binds one routing shape to selected IPv4/IPv6 residual-local domains and exact tether ingress interfaces, rejects empty/duplicate/oversized scopes, and requires at least one recognized usable anchor for every requested domain. Every matching anchor is assessed rather than letting a caller cherry-pick one rule; successful assessments are retained in deterministic order, while any unusable or ambiguous match rejects the whole scope without partial output. Definite incompatibility or priority-slot exhaustion dominates an otherwise incomplete aggregate; absent a definite rejection, any incomplete anchor keeps the scope incomplete, and only all residual windows produce the residual multi-domain summary. Freshness repeats complete anchor discovery and assessment against the current inventory/classifier instead of comparing only epoch or revision headers. This remains diagnostic evidence: it neither intersects or sums per-domain windows nor emits a priority, mark, route/table intent, ownership claim, or mutation authority.

The positive Android mark-authority model is now implemented as the next pure checkpoint. Generic AOSP is a zero-grant policy; bits 21–30 are only a syntactic envelope for a device-qualified candidate. Capability Profile schema 2 now carries typed exact Android product/build/vendor/security-patch, kernel-build, verified-boot/vbmeta, SELinux-policy, netd/Connectivity, bounded tool-artifact, boot, and namespace identity. A stable `ReviewedPolicySelector` excludes runtime-only verified-boot and namespace bindings from literal catalog keys. The positive policy and complete-census trust boundaries reject every non-verified device identity and any mismatch between the separately observed namespace and the full profile. The Android-target collector directly reads and double-samples immutable properties, kernel and namespace facts; hashes fixed SELinux-policy, netd and active-Connectivity paths through bounded no-follow reads; hashes the executing image through `/proc/self/exe`; revalidates path and descriptor metadata; and requires complete AVB lock/algorithm/digest evidence. Generic Linux remains unavailable. Rooted x86_64 WSA correctly settles `Absent` because its apparent green state lacks the other AVB facts. The compiled catalog selector now validates exact literal entries and retains catalog-entry provenance through policy/census identity, but its production entry table remains empty until independent physical-device review; therefore this checkpoint still cannot manufacture authority. Planning authorization separately requires the assertion to cover packet, socket, and conntrack marks.

Planning authorization consumes a non-`Clone` census with exactly nine evidence sources—Android `netId`, RPDB, device policy, legacy xtables, nftables, TC/BPF, XFRM, connmark/socket transfers, and existing Flux ownership—across all three planes. Every one of the 27 source-plane cells must be complete-present or complete-absent, at most 512 raw uses are accepted before canonical sorting and deduplication, and the observation binds inventory snapshot/epoch, full capability facts, namespace, policy identity/revision, collector revision, and ownership-journal identity/revision. Definite or unresolved external read/write/transfer overlap rejects regardless of values, opaque RPDB rejects, and known definite conflicts take precedence over incomplete topology evidence. The exact Android `netId` packet masked writer is separately reported as an ordered-write qualification requirement under ADR-0013; it also rejects, and any definite conflict takes precedence. The result exposes only a consuming, freshness-checked `AndroidMarkPlanningAuthority`; it cannot produce a `MarkLease`, priority, table, route, encoder, mutation, writer, or activation conversion, and reauthorization requires a fresh census.

The first source-scoped mark-evidence checkpoint is now implemented as a pure
`RpdbFwmarkCensusFragment`. It projects each ordered RPDB fwmark selector into adjacent packet- and
socket-plane predicate reads because Linux route lookup can seed `flowi_mark` from either
`skb->mark` or `sk->sk_mark`; RPDB directly reads no conntrack mark. Duplicate rules remain duplicate
raw pairs, opaque rules keep both flow-origin cells opaque while retaining known uses, and the
snapshot/epoch binding rejects drift and equal-epoch cross-tracker evidence. The fragment accepts
at most 512 raw records—256 marked rules—and rejects selector 257 without truncation. It has no
complete-collector revision, policy or ownership binding, complete-census conversion, Planning
Authority, lease, writer, or mutation capability. At that first checkpoint, the remaining 24 cells
and cross-source point-in-time coordination were still pending.

The second source-scoped checkpoint is a static `AndroidNetIdFwmarkCensusFragment` under one
canonical explicit `AndroidNetdSourceProfile` shared with RPDB classification. It records the exact
incoming-packet masked writer—`0xffef_ffff` on Android 12/13 and `0x7fef_ffff` at the pinned March
2025 revision—plus low-16-bit socket predicate-read/masked-write semantics. Every pinned packet
writer overlaps the complete `0x7fe0_0000` device-qualified candidate envelope. Source tracing
places that writer below mangle INPUT after input route selection, so the exact packet overlap is an
ordered qualification blocker rather than a proven simultaneous collision. It still rejects until
the runtime profile/chain and listener/observer mark preservation are qualified on a physical ARM64
target. The direct conntrack cell is complete-absent because connmark copy operations remain a
separate transfer source. It performs no runtime artifact authentication or automatic profile
selection and exposes no complete-census conversion or authority. The two fragments now model six
cells; the remaining 21 cells and point-in-time coordination are paused until that target and
coexistence procedure are viable.

### Deliverables

- Reimplement the required `addrsyncd` netlink behavior behind private `flux-platform` modules; do not expose raw rtnetlink framing as the product Interface. Resolve the standalone subproject's `UNLICENSED` provenance before copying source text into the GPL workspace.
- Deliver a read-only, subscribe-before-dump link/address/route/rule observer before any native mutation. It must publish only complete, canonical `NetworkInventory` snapshots with a monotonic `NetworkEpoch` and integrate into the existing single reactor rather than creating a second epoll owner.
- Preserve batched receive/send, optional extack diagnostics, address filters, bounded per-turn work, quiet debounce, debounce maximum, and compensating resync behavior.
- Treat `MSG_TRUNC`, `ENOBUFS`, `NLMSG_OVERRUN`, malformed or ambiguous messages, `NLM_F_DUMP_INTR`, missing `NLMSG_DONE`, and sequence inconsistency as mandatory full-resync conditions. While a dump is active, serialize resynchronization behind that sequence's terminal response; if terminal evidence cannot be recovered by the drain deadline, leave the source invalid and degrade observation rather than overlap a replacement request. Partial dumps never advance the Network Epoch.
- In-process address-derived Bypass Policy.
- **Delivered model, Android collector, and wire boundary:** add exact Android product/build/vendor/security-patch,
  kernel-build, verified-boot/vbmeta, SELinux-policy, netd/Connectivity artifact, bounded tool, boot,
  and namespace identity to the freshness-bound profile. Android collection is direct, bounded and
  point-in-time rechecked; generic Linux remains `Unavailable`, and WSA cannot satisfy complete AVB.
- **Delivered empty catalog boundary:** select positive policy only from bounded source-coded entries keyed by stable product/build/kernel/policy/tool artifact identities and external policy digest/revision; retain catalog entry ID through census identity, bind matches to verified boot/profile/namespace, and reject arbitrary runtime catalogs or manifests. Production entries remain pending independent physical-device review.
- **Paused behind ADR-0013:** before continuing the remaining 21 bounded source-plane cells, make
  one physical Android ARM64 ordered-lifetime/coexistence target viable with exact runtime
  netd profile and INPUT-chain binding plus listener/observer mark-preservation canaries. Then
  assemble the fresh complete 27-cell fwmark census collector; source fragments cannot authorize
  planning, and generic AOSP must continue to produce zero grant.
- Rust rtnetlink PBR apply/verify/cleanup.
- Generation journal and startup recovery for routes/rules.
- Remove the standalone `addrsyncd` process from runtime. Its binary may remain only in controlled
  pre-release cutover fixtures until the Rust PBR/address-sync transition gate passes; it is never
  shipped in a rewrite release.

### Ownership rule

`fluxd` becomes the only owner of Flux PBR and address-derived rules. The shell `tproxy` adapter must call into `fluxd` or skip its old route section.

### Exit gate

- Lifecycle, event loss, address churn, IPv6 temporary-address, and cleanup tests meet the stricter loss/recovery contract even where current `addrsyncd` behavior does not.
- An event arriving during the initial dump is replayed after that dump or forces another complete dump; no event/dump race may publish a stale inventory.
- Netlink work budgets yield to ready control and shutdown sources in the one daemon reactor.
- Kill-9 at each journal phase converges without deleting unrelated rules.
- Real-device CPU/RSS and convergence baseline is captured.

## Phase 4 — Rust xtables and ipset parity

The first supporting checkpoint is complete and frozen below a canonical Capture Program renderer. `flux-platform` can
parse and canonically re-encode the frozen restore syntax as an ordered, bounded observation
artifact: repeated `mangle`/`filter`/`nat` transactions, chain declarations, `-A`/`-I` apply
commands, `-D`/`-F`/`-X` cleanup commands, duplicates, family context, cleanup phase ordering,
resource usage, and an exact byte digest are retained. Cleanup phase ordering is enforced within
each restore transaction. The parser performs no shell execution,
filesystem discovery, restore invocation, kernel access, Generation conversion, ownership, or
activation. Its current-shaped synthetic tests establish grammar and bounds. The separate
`xtables_restore_oracle` integration test parses all four checked-in shell-oracle fixtures and
canonically reproduces their exact bytes and syntax-artifact digests.

Keep the four evidence levels distinct:

1. **Syntax byte round-trip — complete:** the parser accepts a bounded restore document and emits
   the same canonical bytes; the pinned-fixture test demonstrates this for the four oracle files.
2. **Legacy source-shape renderer parity — complete for the admitted bridge:** validated Rust inputs
   preserve the frozen generator ordering, duplicates, feature branches, marks, application UIDs,
   and cleanup shape and reproduce all four pinned fixtures. Domain-separated plan, mandatory
   family apply/cleanup pair, and enabled-family set digests bind this renderer-owned identity and
   resource accounting. The Generation-bound receipt verifies exact staged bytes against that set;
   it is still level-2 source-shape evidence, not Capture Program lowering.
3. **Canonical Capture Program base lowering — complete, non-authorizing:** forwarded-only input
   preserves the exact schema-v1 family/clause order, restore bytes, `F` names, accounting, and
   digests. Any local-OUTPUT input selects schema v2, with a MARK-only private `O` classifier,
   proxying families adding a private `P` loopback TPROXY companion, and mixed families retaining
   the unchanged `F` role. Typed entry selectors, per-family routing identity, transparent listener,
   compatibility loop escape, and lifecycle metadata record `P` then optional `F` then `O` for
   attachment and the inverse hook order for detachment. Prepare/retire restore artifacts still
   only create/fill and flush/delete private chains; nothing attaches, executes, or authorizes mutation.
   Complete production runtime ownership remains open, as do established-flow caching,
   transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS clamping.
4. **Private native transaction execution — complete as mechanism evidence:** the bounded owner now
   supplies stable hooks, coherent restore/save, exact policy-routing mutation/readback, rollback,
   durable recovery, cleanup invertibility, and the transition lease. Schema-2 durable identity binds
   the complete IPv4/IPv6 routing audit plus loopback name/index; both-family residue checks precede
   `Active`/`CleanAbsent`, and stale live loopback identity fails before routing access. Authenticated
   shell-owner-v2 participation, fenced current-terminal retirement, the coherent previous-boot
   revision-1 pre-lease exception, and fail-closed missing-lease mismatches preserve the same writer
   boundary. Deterministic write-boundary injection and rooted disposable-WSA apply/recover/stop
   passed. Production target admission, functional receipts, reviewed Android 5.10/ARM64 behavior,
   and packet-path release qualification
   remain backlog items 3 and 4 rather than being inferred from this mechanism checkpoint.

The canonical oracle pin and fixture inventory live in `tests/oracle/xtables/manifest.json`; the
operational commands live in `docs/development.md`. The bounded raw profile excludes QUIC, PBR,
forced-cleanup behavior, kernel acceptance, Android/Magisk parity, and every
Generation/ownership/activation claim. Oracle regeneration remains a separate CI job and is
intentionally absent from normal `cargo xtask ci`.

### Current vertical-slice deliverables

- **Delivered:** bounded validated legacy source-shape compiler for xtables restore programs, with
  exact fixture differential tests and explicit rejection of unsupported production profiles.
- **Delivered:** bridge integration that binds renderer marks to the exported shell PBR inputs,
  conditionally invokes `fluxd snapshot-legacy-packages` for one no-follow, descriptor-stable,
  bounded immutable package inventory, supplies Rust-generated
  apply/cleanup artifacts to the existing shell restore executor, records the producer, and
  preserves the active Generation on candidate-render failure.
- **Delivered:** renderer-owned `LegacyRulesPlanDigest`, mandatory apply/cleanup family-pair
  identity, and complete enabled-family set identity. `fluxd attest-legacy-rules-set` rebuilds one
  plan from the allowlisted environment and bounded package snapshot, safely byte-compares every
  staged artifact, and emits one strict Generation-bound manifest with plan/pair/set/artifact
  digests and bounded resource totals. Shell invalidates old receipts before rebuilding shared cache artifacts,
  publishes `cache_rules_manifest` only after all renders pass, and copies it into the immutable
  Generation as `legacy-rules.manifest` before publishing `engine.manifest`.
- **Delivered:** extension-free canonical lowering for the clause shapes emitted by the frozen
  shadow compiler. Forwarded-only input preserves exact schema-v1 restore bytes and identities.
  Local-OUTPUT input selects schema v2, emits private `O` MARK classifiers and proxying `P`
  loopback TPROXY companions, retains optional `F` forwarded chains, and records typed routing,
  listener, loop-escape, entry-selector, lifecycle, identity, and resource metadata. The artifacts
  remain unattached and non-authorizing.
- **Delivered bounded native owner:** one coherent trusted command/restore/save tool set is admitted
  before version execution; role-specific multicall descriptor invocation, complete save capture,
  stable `FLX{4|6}SP`/`FLX{4|6}SO` roots, exact structured readback, journal-before-write
  restore/rtnetlink ordering with a nonzero route protocol, nonzero rule protocol, explicit nonzero
  route metric, IPv4 HOST scope, and IPv6 UNIVERSE scope, rollback, crash recovery, Generation
  rebind, and the component transition lease are private behind `converge(target)` and `recover()`.
  Payload schema 2 digests the complete IPv4/IPv6 policy-routing audit, including exact loopback
  name/index identity. The real Adapter checks that identity in both directions, and both xtables
  families plus both routing audit identities must be exact or absent before `Active` or
  `CleanAbsent`. Current terminal recovery keeps the native guard, writer marker, and optional lease
  until global dual-family absence permits terminal-artifact retirement. Previous-boot recovery also
  admits the coherent revision-1 `Activating` `JournalDurable`/`JournalBeforeLease` boundary; same-boot,
  wrong-phase/revision, or scope-mismatched missing-lease state stays blocking.

  Shell-owner v2 records parent plus optional child PID/start identities and boot ID. Either live
  participant blocks; one serialized parent-bound mutating `addrsync` or `tproxy` phase child changes
  only its slot and remains blocking after parent death; a live parent can reclaim a dead child; and
  only both-dead, PID-reused, or previous-boot records retire after exact revalidation. Ambient state
  is discarded, release is authenticated, signals exit through cleanup, and bare, malformed, mixed,
  and unverifiable locks remain blocking. Legacy start/stop/restart/failure cleanup holds this fence
  before `addrsync` or `tproxy` mutation. The standalone daemon remains an item-4 cutover duty after
  item 3 has supplied its Rust-owned replacement inputs.
  Deterministic tests cover every mutation boundary, and the real Adapter passes apply/recover/stop
  in a rooted disposable x86_64 WSA namespace as mechanism evidence only. Positive production
  target admission remains intentionally uninhabited.
- **Open production prerequisite and cutover checkpoints:** first bind exact Android mark/RPDB,
  engine/process/canary, address-policy, ownership, and no-autoload evidence into one canonical
  Generation target. Then qualify reviewed Android 5.10/ARM64 profiles, stop standalone address
  synchronization and every shell route/xtables writer, transfer the lease, and delete the replaced
  duties.
  Established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS
  clamping remain typed unsupported extensions and should be implemented only where the supported
  runtime actually requires them.
- **Delivered Linux and rooted-WSA mechanism checkpoints:** ADR-0012 selects masked mangle/OUTPUT
  marking,
  output-route recomputation, an RPDB local route through loopback, and mark-qualified loopback
  PREROUTING TPROXY as the first conventional candidate. The ignored disposable-namespace test and
  xtask entry exercise dual-stack TCP/UDP original-destination delivery, response bypass, counters,
  safe misses, no-autoload refusal, and ordered activation/retirement. Linux proves exact baseline
  restoration; the rooted WSA lane proves exact owned-object retirement plus semantic baseline
  restoration with only the admitted inactive-loopback `noop`/`noqueue` equivalence and the exact
  addition of `mangle` to an otherwise preserved registration baseline caused by built-in per-
  namespace table initialization; WSA's observed baseline was empty. The Android runner passes on
  WSA Android 13 / SDK 33, preserves Android-owned mark bits, tolerates only bounded legacy-iproute2
  differences, and proves remote cleanup before the disposable namespace is retired. Both lanes
  remain outside production authority and do not combine distinct UID,
  Generation/receipt evidence, a production report producer, Android 5.10/ARM64, or release
  qualification.
- Bind the delivered native owner to the production Runtime Reconciler and exact activation
  authorities without exposing raw prepare/activate/retire verbs.
- Complete production coherent iptables-legacy versus iptables-nft selection/no-autoload evidence;
  one Generation may use only one matched IPv4/IPv6 implementation family.
- ipset capability probes, generation-specific sets, inactive population/optional temporary swap, stable-jump cutover, verification, and cleanup without changing set contents under the old Generation.
- Bounded-tree fallback compiler.
- Transaction coordinator spanning Sing-Box, xtables, ipsets, and rtnetlink.
- Drift detection for Flux-owned chains, sets, routes, and rules.
- Optional post-cutover `xt_bpf` capability adapter: first prove the match is built in or already active without
  triggering `request_module`, then perform map operations, socket-filter load/helpers, bpffs
  pin/get, revision-1 `--object-pinned`, IPv4/IPv6 OUTPUT/PREROUTING packet canaries, UID-context
  behavior, rule-reference teardown, and crash cleanup. The conventional xtables compiler remains
  complete when this adapter is absent. This adapter is not part of the immediate ownership lane or
  a first-release requirement.

### Ownership rule

Rust-owned preparation never sources `scripts/rules`: it invokes only `fluxd render-legacy-rules`
and records `rust` as the cache producer. Explicit legacy ownership alone sources the frozen shell
generator and records `shell`, preserving an intentional rollback path without automatic fallback.
The retained shell phase scripts remain the production networking writers, while `scripts/tproxy`
alone is the production restore executor for either prepared cache. The delivered native owner
already publishes and enforces the same shell-visible transition lease in deterministic and
disposable WSA execution. Shell claims are not bare directory locks: owner v2 retains parent plus
optional child PID/start identities and one boot ID. Either live participant blocks; one serialized
parent-bound mutating `addrsync` or `tproxy` phase child adds/clears only the child slot and remains
blocking after parent death; and a live parent can reclaim a dead child. Only both-dead, PID-reused,
or previous-boot claims retire after exact re-read; missing, malformed, mixed, or unverifiable
records remain fail-closed. Every legacy start, stop, restart, and failure-cleanup phase transaction
acquires this fence before `addrsync` or `tproxy`. No production path can yet construct an admitted
native target or acquire its lease.
Backlog item 3 must complete the production authorities and full transaction target without native
mutation. Backlog item 4 must then disable standalone address synchronization and every shell
route/xtables mutation before the first Rust write; only then does `fluxd` become the sole writer of
Flux networking state. There is no shadow/native dual-writer interval.

### Current-stage exit gate

- **Complete in host implementation:** Rust independently renders the admitted IPv4/IPv6
  source-shape apply/cleanup programs and passes reviewed differential tests against the bounded
  pinned profile.
- **Complete in host implementation:** Rust-owned preparation uses Rust-generated restore artifacts
  without executing `scripts/rules`; explicit legacy ownership retains the shell rollback producer.
- **Complete in the current production bridge:** `scripts/tproxy` remains the only restore
  executor/writer, and renderer failure aborts the candidate without replacing the active Generation
  or falling back to shell. The delivered native owner remains test-admitted through backlog item 3
  and until backlog item 4's atomic transfer.
- **Complete structurally:** explicit legacy restart prepares fresh settings, replacement Sing-Box
  configuration, and replacement caches before stopping the active runtime.
- **Complete in host implementation:** each Rust-owned candidate has one exact Generation/family
  receipt. Rust strictly produces/parses the canonical schema and byte-compares the complete staged
  set. Shell enforces the bounded response envelope, expected Generation, and family shape before
  publication. Stale receipts are invalidated and rebuilt/re-attested rather than reused; an
  unresolved mismatch, failed attestation, partial family, unsafe file, or wrong Generation rejects
  candidate publication and preserves the active Generation.
- **Complete in host implementation:** forwarded-only input retains exact schema-v1 identities, and
  local-OUTPUT input lowers through pure schema v2 to deterministic generation-namespaced IPv4/IPv6
  `O`/`P`/optional-`F` prepare/retire artifacts plus typed routing/listener/escape and lifecycle
  metadata. No built-in hook is attached, no restore/routing operation executes, and no mark,
  writer, ownership, or activation authority is granted.
- **Complete host and mechanism runtime semantics:** the private owner consumes schema v2 in one
  stable-hook, restore/rtnetlink, exact-readback, rollback, crash-recovery, cleanup, and
  transition-lease transaction. Its real Adapter passes in a rooted disposable x86_64 WSA namespace
  as mechanism evidence only.
  Caching, DIVERT, FakeIP ICMP, QUIC rejection, and MSS clamping remain unsupported until a
  supported runtime profile both requires and qualifies their typed semantics.
- **Open production cutover evidence:** use the bridge only for targeted failure/rollback comparison
  while binding reviewed Android 5.10/ARM64 mark/RPDB, engine, canary, VPN/netd, no-autoload, and
  ownership evidence to the native transition. Do not turn this temporary substrate into a
  release-packaging lane.

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
- `xt_bpf` observation in Flux-owned xtables chains as the first hook: update bounded counters and always return false.
- Bounded `RLIMIT_MEMLOCK` calculation/raise plus real map allocation; classify `CAP_BPF`, `CAP_NET_ADMIN`, relevant `CAP_PERFMON`, `CAP_SYS_ADMIN` fallback, and SELinux denial separately.
- Per-CPU counters, LRU sampled flow map, probed ring-buffer events with perf-event-array fallback, and generation control map.
- Capability and verifier diagnostics.
- Read-only CLI/web metrics path.

### Exit gate

- Detaching or crashing the eBPF plane has no correctness effect.
- Verifier/attach failure automatically selects `Off` or `Observe` degradation without disturbing capture.
- Idle overhead and event volume remain within recorded budgets.

## Phase 8 — eBPF acceleration

### Deliverables

The order below is implementation priority, not a runtime dependency. Once implemented, TUN TC and
proxy-child telemetry are independently selectable for nftables/TUN plans from their own probes and
conventional fallback; they do not require xtables or an active `xt_bpf` accelerator.

- `xt_bpf` proxy-positive fast path populated from the same compiled Capture Policy; every miss, parse ambiguity, `overflowuid`, stale Generation, or map failure uses the complete classic classifier.
- Generation-scoped-TUN TC observation after positive `xt_bpf` parity, including when Sing-Box owns the interface and queue FDs. Legacy TC uses a Flux-owned `clsact`/filter lease bound to Network Epoch; verified 6.6+ TCX is qdisc-less but still revalidates link identity and foreign-program ordering.
- Proxy-child `sockops` telemetry only after full ancestor-chain plus child program inventory proves that exact hook available; pair it with userspace TCP/UDP mark canaries and never use event absence as loop-escape proof.
- Experimental physical/tether-interface TC probe guarded by netd/qdisc/offload conflict detection.
- Cgroup programs remain limited to Flux/Sing-Box child processes unless a separate Android-owned-cgroup coexistence experiment proves safety.
- Flow/socket decision cache only after positive-path parity and bounded resource evidence.
- Reserved-mark stamping as the explicit 5.10 bridge, with hook ordering documented: TC ingress may accelerate PREROUTING/tethered traffic; local OUTPUT is not claimed through TC egress.
- nftables/xtables fast path consuming only the verified Flux mark, never reading eBPF maps directly.
- Per-generation policy maps plus shared control map: attach new programs dormant, flip one BPF active-policy selector, then detach old programs; this does not publish `active.json`, and Flux falls back to detach/attach when the selector contract cannot be proven.
- Optional TUN queue steering only under the future `FluxOwnedTunFd` contract; TUN filter eBPF remains deferred.
- Parity oracle comparing accelerated decisions with the non-eBPF compiler for recorded traffic cases.
- Per-domain backend-plan experiment proving bounded Traffic Domain fragments exhaustive, selector-disjoint, non-overlapping, and compatible in engine/listener, mark, route, address-set, activation, and cleanup ownership.
- Exact tether-domain TC ingress socket-assignment experiment using `bpf_sk_assign` only with a compatible same-netns transparent listener, a proven local route, and miss behavior that preserves ordinary forwarding. It cannot become correctness-bearing without a separate ADR.
- Netns `sk_lookup` remains a narrow listener-selection experiment. Add reuseport BPF only after Flux controls the listener FD/group or Sing-Box exposes a verified inherited-listener contract.

### Exit gate

- Zero policy divergence across replay, property, and real-device tests.
- Acceleration demonstrates a material packet-path or CPU improvement on target workloads.
- Unsupported/denied devices remain fully correct without acceleration.

## Phase 9 — Subscription and remaining shell removal

### Deliverables

- Rust subscription download/size limits, decoding, normalization, filtering, naming, template merge, validation, and atomic snapshot publication.
- Content-addressed rule-set asset lifecycle with size/format/digest validation and a retained known-good predecessor.
- Versioned DNS/fake-IP/reverse-mapping persistence with policy-change migration or deliberate flush and corruption fallback.
- A temporary external `curl` transport adapter may exist only in pre-release fixtures while Android
  TLS integration is being proven; the release path uses a Rust-owned transport and ships no curl
  compatibility dependency.
- Optional one-time Rust importer for already released legacy settings, provided it does not retain
  a legacy runtime dependency or delay the ownership cutover.
- Remove runtime dependencies on `jq`, AWK rule/config generation, dispatcher, init, core, addrsync, rules, and tproxy scripts.
- Keep only platform-required installation, launch/restart-only boot, disable, and uninstall glue;
  shell never performs networking policy or cleanup, and no legacy compatibility wrapper ships.

### Exit gate

- Existing supported subscription inputs have regression fixtures.
- Asset refresh failure never removes the active asset; fake-IP/cache crash, corruption, reload, and incompatible-schema tests pass.
- Malformed and adversarial inputs pass fuzz/resource-limit tests.
- Package contains only the documented final runtime paths.

## Phase 10 — Hardening and default switch

### Deliverables

- Capability/group reduction where device policy permits.
- Optional seccomp profile after syscall capture across every backend.
- Production seccomp and package verification deny/reject `init_module`, `finit_module`, `delete_module`, `.ko`, KPM, and opaque kernel payloads.
- State-path symlink/hardlink protections.
- Dependency audit, SBOM, reproducibility check, and unsafe-code audit.
- Final default backend selection based on the device evidence set.
- User migration guide and rollback package.

### Exit gate

- Full Android conformance matrix passes.
- Recovery, chaos, performance, and security gates pass.
- Standalone `addrsyncd` and old runtime scripts are removed from the release manifest.
- Only after this exit gate and the final provenance/package gate pass may the Rust rewrite be named
  or published as a release candidate or release.

## Test strategy

### Pure and model tests

- Config parsing and migration fixtures.
- Shadow Capture Policy normalization, local/forwarded ordering, canonical mandatory baseline,
  semantic digest determinism, resource bounds, and explicit non-authorizing/deferred reports.
- Canonical xtables lowering: frozen schema-v1 forwarded identities; schema-v2 `O`/`P`/`F`
  namespace, UID set algebra, masked MARK/TPROXY rendering, exact routing/listener/escape metadata,
  lifecycle order, combined budgets, and explicit non-authorizing boundaries.
- Frozen shell-oracle semantic fixtures; these characterize decisions before a renderer exists and
  do not by themselves claim restore or device parity.
- Backend-plan selection over generated Capability Profiles.
- Mark-authority, routing-candidate, and collision rejection.
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

- nftables and xtables PREROUTING TPROXY TCP/UDP from an exact ingress namespace;
- separate local-OUTPUT capture, listener-delivery, and loop-escape qualification without
  inferring success from OUTPUT mark counters or route lookups;
- ipset swap and rollback;
- IPv4/IPv6 marked policy routing;
- TUN interface lifecycle;
- netlink event loss and full resync;
- external drift and ownership conflict;
- process crash during every transaction phase;
- eBPF load/attach/detach and verifier failure.

### Android device matrix

The rooted x86_64 WSA checkpoint is development mechanism evidence and does not count toward this
minimum release set.

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
| Backends | every advertised release backend; optional nftables, TUN, or eBPF modes may remain explicitly unsupported |

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

## Prioritized implementation backlog

1. **Close and freeze the attested development bridge.** Land only the current correctness and race
   fixes, keep it as a bounded oracle/rollback substrate, and add no new compatibility features or
   release qualification. Stale receipts are rebuilt, not reused; preview and Generation builds
   remain serialized.
2. **Delivered: execute the canonical xtables transaction as one bounded native slice.** The private
   owner consumes schema-v2 `O`/`P`/optional-`F` entries without changing their pure identities and
   owns stable entry chains, direct-child restore/save, journaled rtnetlink with a nonzero route
   protocol, nonzero rule protocol, explicit nonzero route metric, IPv4 HOST scope, and IPv6
   UNIVERSE scope, exact live readback, rollback, crash recovery, cleanup invertibility, ownership
   naming, and the transition lease. Schema-2 payload identity binds the complete dual-family
   route/rule audit and loopback name/index; both-family residue, bidirectional live-loopback checks,
   fenced current-terminal cleanup, the exact coherent previous-boot revision-1 pre-lease boundary,
   shell-owner-v2 parent/child recovery, serialized authenticated phase children, ambient-state and
   signal-exit hardening, legacy phase-transaction fencing, and malformed/bare/mixed fail-closed
   boundaries are part of the delivered ownership contract. Every mutation boundary is
   failure-injected, and the real Adapter passes apply/recover/stop in a rooted disposable x86_64 WSA
   mechanism test.
   The source-shape renderer remains an oracle and is not promoted into the native compiler.
   Production admission remains `Unsupported` throughout item 3 and until item 4's atomic transfer;
   WSA is not release authority.
3. **Current: complete one native activation target.** Finish the canonical Generation/config
   authority and exact device/artifact Capability Profile, then make one physical Android ARM64
   ordered-mark-lifetime/coexistence target viable under ADR-0013. Keep the remaining 21 census
   cells paused until the runtime netd profile/INPUT chain and listener/observer mark-preservation
   procedure can be bound to that target; then complete the point-in-time 27-cell census,
   RPDB/domain placement, route reachability, observer continuity, rollback inputs, and in-process
   address-derived policy. Bind the delivered engine/process/canary evidence to that complete target
   without admitting production mutation or exposing raw native writer verbs.
4. **Qualify and atomically cut over the networking writer.** Qualify the complete transaction on
   reviewed Android 5.10/ARM64 profiles. Stop standalone `addrsyncd` and disable every shell
   address/PBR/xtables mutation before the first Rust write, transfer the native Generation lease,
   and only then remove `scripts/addrsync`, the replaced `scripts/rules`/`scripts/tproxy` duties, and
   the standalone binary from runtime and packaging. Add established-flow cache, transparent-socket
   DIVERT, FakeIP ICMP, QUIC rejection, or MSS clamping only when the advertised runtime requires and
   separately qualifies that extension. No dual writer and no compatibility release.
5. **Move configuration, subscription, and remaining lifecycle policy into Rust.** Implement Rust
   config/subscription generation, bounded network transport, assets, DNS/fake-IP persistence,
   diagnostics, offline cleanup, and direct Rust CLI entry points. Remove runtime dependencies on
   `jq`, AWK generation, external `curl`, dispatcher/init/config/core/updater scripts, and legacy
   wrappers. Only platform-required installation/boot/disable/uninstall glue may remain outside
   Rust, with no networking policy or cleanup logic.
6. **Qualify the fully Rust-owned release scope.** A first release needs at least one complete,
   explicitly selected conventional Capture Path with TCP/UDP, dual-stack, DNS, tethering,
   per-application/multi-user policy, Android VPN coexistence, recovery, performance, and security
   evidence. The complete rewrite does not require shipping every optional backend: nftables, TUN,
   or eBPF may remain explicitly unsupported if they are not advertised and do not leave legacy
   runtime dependencies.
7. **Pass the final package and provenance gate.** Update the package inventory to the Rust-only
   runtime, then require clean immutable source revisions, hashes, licenses, SBOM, checksums, pinned
   build metadata, reproducible or signed third-party provenance, and trusted device/CI evidence.
   Only after both this gate and ADR-0011's runtime-completion gate pass may the branch produce a
   release candidate or release.
8. **Keep optional work subordinate to the cutover.** Isolated no-autoload `xt_bpf` probes, broader
   eBPF observation/acceleration, native nftables, managed TUN, TC/TCX, and preloaded custom-kernel
   observation may proceed only when isolated from the ownership lane. Production `fluxd` never
   loads/unloads `.ko`/KPM payloads, and optional work must not delay removal of legacy runtime code.
9. **Treat migration import as optional.** A one-time isolated Rust importer for already published
   legacy settings may be added only if it does not preserve a legacy runtime dependency or delay
   cutover. Pre-release internal schemas and state may otherwise be invalidated deliberately.
