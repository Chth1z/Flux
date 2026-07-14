# Fluxd Rewrite Implementation Roadmap

This roadmap turns the [blueprint](fluxd-blueprint.md) and [technical specification](fluxd-technical-specification.md) into independently verifiable tracer bullets. Each phase leaves a usable rollback path and assigns exactly one owner to active networking state.

## Delivery principles

- Preserve the current working TPROXY path until the Rust replacement reaches parity on real devices.
- Introduce one new ownership seam at a time.
- Prefer vertical slices that can run on a device over broad unfinished abstractions.
- Keep backend selection explicit until each `auto` preference has conformance evidence.
- Do not remove a shell behavior until its Rust replacement has failure-injection and recovery tests.
- Freeze the executed shell networking path as a compatibility oracle that receives only
  correctness, security, release-contract, and rollback fixes; transfer one component at a time
  and never admit a second writer during comparison.
- Treat a real Android 5.10 device as the minimum release gate, not merely a compile target.

## Current parallel workstreams (2026-07-14)

The next checkpoint is not a single linear Phase 3 task. Four bounded lanes may proceed in parallel,
but correctness gates retain strict ordering:

The 2026-07-14 code/documentation deviation audit adds one mandatory bridge-contract correction
checkpoint before further positive canary integration. The reported live-worktree compile failure
was stale at the audited HEAD, but the remaining findings were valid. This checkpoint makes `fluxctl status`
delegate to authoritative daemon state, rejects the meaningless one-shot `addrsyncd` tracked cleanup,
completes settings migration, exposes only the shipped TPROXY/zone choices, replaces obsolete public
lifecycle documentation, and separates development staging from strict release verification. It does
not authorize native mutation, TUN, eBPF acceleration, or kernel-module loading. Release provenance,
license, hash, SBOM/build metadata, and real-device evidence must still be populated before the new
verifier can pass.

1. **Bridge safety:** the `100.64.0.0/10`, mandatory-exclusion, empty allow/deny,
   TUN-rejection, and converged-`addrsyncd` readiness checkpoints are complete. The Stage-1
   [Generation-scoped functional capture canary](functional-capture-canary.md) model, coordinator
   ordering, lifecycle tests, protocol-v3 verification status, and authoritative schema-v2
   listener/delivery validator are complete; production still explicitly selects structural-only
   compatibility. The privileged Linux checkpoints prove the isolated dual-stack TCP/UDP/DNS
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
   boundaries, but both production receipt authorities remain uninhabited and xtables still reports
   `Unsupported` before mutation. The retained `SingBoxChild` now opens an exact child-origin
   `ProcessHandle`; `EngineSupervisor` admits it only from matching ready ownership, specification,
   readiness, identity, and snapshot revision; the coordinator binds one opener to the immutable
   request; and execution opens it after availability but before preparation without giving the
   driver pidfd or signal/wait/reap authority. The process verifier now preserves the child-origin
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
   The immediate next subcheckpoint is 13b-2b driver-owned client/peer retirement plus final
   verifier completion chronology. Listener/report and collector/factory work follow as separate
   reviews. Cgroup-BPF is not assigned to Phase 8 until a separate TCP/UDP-complete authority design
   and exit gate exist.
2. **Phase 2 shadow policy:** compile the frozen compatibility semantics into a pure,
   deterministic, backend-neutral shadow Capture Program with separate local-OUTPUT and
   forwarded-ingress programs, a canonical mandatory safety baseline, optional snapshot-bound host
   bypass provenance, bounded inputs/output, a stable semantic digest, and explicit
   assumptions/deferred prerequisites. This lane performs no
   I/O and produces no Generation ID, Planning Authority, writer token, renderer, prepared/active
   value, Runtime Coordinator entry point, or functional-canary authority. Frozen shell fixtures
   are characterization inputs, not a parity or activation claim.
3. **Native Phase 3 correctness:** add exact device/artifact identity; select positive mark policies from a compile-time reviewed stable artifact catalog and then bind them to boot/namespace freshness; complete the remaining 24 census cells and point-in-time coordinator; prove writer semantics, observer continuity, mark preservation, domain/network-selection handoff, and route reachability; only then allocate priorities/tables/marks or mutate the kernel.
4. **Optional eBPF implementation/probe:** implement only isolated, opt-in `xt_bpf` probe mechanics in a disposable test namespace without persistent pins, production daemon integration, Capability Profile publication, implicit module autoload, or writes to live Flux chains. The device-qualified adapter and first production-state integration land in Phase 4 after `fluxd` becomes the sole xtables writer; broader observation remains Phase 7. Positive acceleration waits for the Rust xtables compiler, a complete conventional classifier, parity evidence, and device benchmarks.

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

Start is `prepare` → engine admission → generation-bound capture start → generation-bound structural verification → configured functional gate → generation-bound `RUNNING`. The production composition currently selects structural-only compatibility, while required-mode tests execute fresh exact-binding attempts. Capture start records its Generation before mutation and removes that evidence only after successful compensation. Stop is capture detach → supervisor stop/reap → `STOPPED`. A stop/failure detach error enters `DetachPending`, retaining Generation and terminal intent while blocking replacement until maintenance proves detachment; engine retirement and `STOPPED`/`FAILED` publication cannot overtake it. Reload prepares while the prior Generation remains active, then invalidates its functional authorization immediately before detachment and replacement. A prepare-only failure preserves the untouched active pass. Failed or uncertain reload detach enters `CaptureRepairPending`: the candidate is not launched, and maintenance proves detach before restoring, freshly verifying, and republishing the old Generation. Candidate failure rolls back using the prior immutable Generation only after candidate detach is proven; candidate canary evidence never authorizes the rollback. Uncertain compensation stays `DetachPending` and does not restart the previous Generation. Rollback failure remains fail-open. A pending `RUNNING` retry, engine identity loss, repair/restoration, or active address resynchronization requires a fresh complete gate. Status carries an observed, independently revisioned `RuntimeSnapshot`, including protocol-v3 verification state, alongside the desired/control `ControlSnapshot`.

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
driver reports `Unsupported` with cleanup `NotRequired` before mutation because OUTPUT marking does
not re-enter PREROUTING TPROXY; its prepared/raw type and the production receipt authority are
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
engine/probe execution, a real traffic producer, and Android adapter/qualification. The validator
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
- `fluxctl` compatibility wrapper.

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

The first Phase 2 checkpoint is deliberately narrower than a Generation compiler. It compiles
typed compatibility inputs into an ordered shadow Capture Program, with distinct local and
forwarded programs, canonical mandatory/configurable bypass layers, optional inventory-derived
host bypass provenance, deterministic application and interface selectors, compile-time budgets,
semantic version/digest, and an explanation of every compatibility assumption and deferred
prerequisite. It is pure and observation-only. There is no
backend restore renderer, package-to-UID discovery, kernel or filesystem access, Generation ID,
planning or mutation authority, writer/ownership token, prepared/active conversion, coordinator
execution path, or eBPF/TUN/module action. The shell path remains the sole executed networking
writer and the frozen semantic oracle.

This checkpoint does not discharge the Phase 2 exit gate. Oracle-derived fixtures first pin
semantics such as RFC 6598, mandatory bypasses, empty allow/deny behavior, multi-user UIDs,
interface matching, family/domain separation, and compatibility engine UID/GID loop bypass. A
later bounded renderer checkpoint must compare canonical IPv4/IPv6 restore artifacts and then pass
failure/recovery plus real-device gates before claiming xtables parity or ownership.

### Deliverables

- Complete versioned config model and legacy migration command.
- Pure Desired State normalization.
- Network Inventory model populated from snapshots, initially without live ownership.
- Backend-neutral Capture Policy compiler producing separate ordered local-OUTPUT and
  forwarded-ingress programs, a canonical mandatory safety baseline, resource accounting, and a
  stable semantic digest.
- Two-stage Generation compiler: bounded non-authorizing candidate enumeration/scoring, followed by finalization that takes a bounded candidate-keyed Planning Evidence set by value and consumes the selected authority.
- Generation IDs, digests, non-authorizing evidence receipts, resource budgets, dry-run candidate set, and explain/rejection output.
- Sing-Box per-Generation overlay generation and validation.
- Revisioned device and Sing-Box Engine Capability Profiles, with Generation planning leases invalidated by boot changes, runtime demotions, or engine binary/profile changes.
- Frozen oracle-derived semantic fixtures, followed later by renderer-level golden tests proving
  parity with representative current rules.

### Exit gate

- Identical normalized discovery inputs produce identical bounded candidate sets; identical candidate/evidence/selection inputs produce identical Generation artifacts and receipts.
- Property tests cover CIDR normalization, UID expansion, mark preservation, rule ordering, and resource limits.
- Boot/profile revisions and Sing-Box binary/profile changes invalidate stale planning leases, and persisted Generation records retain enough identity to reject unsafe recovery.
- Migration round-trips all supported current settings or emits an explicit lossy-mapping error.

## Phase 3 — Absorb `addrsyncd` and policy routing

Current implementation status: the observer publishes one atomic link/address/route/rule `NetworkInventorySource` epoch from a strict `RTM_GETLINK` → `AF_UNSPEC RTM_GETADDR` → `AF_UNSPEC RTM_GETROUTE` → `AF_UNSPEC RTM_GETRULE` transaction. Every phase owns a fresh nonzero sequence and completes before the next request is sent; only RULE completion may replay transaction-wide bounded LINK/ADDRESS races and publish. Links and addresses are canonical sets, while routes and rules preserve validated dump order and multiplicity. Link decoding preserves raw names and link kinds through the netlink wire bound, unknown flags/types/states, and extended dump acknowledgements while rejecting ambiguous or loss-marked datagrams; partial live link notifications preserve optional fields omitted by the kernel. The driver uses 256 KiB receive slots, a 1 MiB default per-turn byte budget, fresh phase/interphase deadlines, exact sequence ownership, and optional registration in the daemon's existing reactor after capability admission.

The route layer adds canonical route domain facts and a strict private `RTM_NEWROUTE`/`RTM_DELROUTE` decoder, including canonical prefixes, raw table/protocol/scope/type/flag preservation, direct and cross-family-via gateways, ordered multipath weights, named-nexthop IDs, `NLM_F_REPLACE`, and strict loss/DONE/attribute validation. Route dumps now enter `NetworkInventory` as ordered multisets. Metrics, encapsulation, flow, and new-destination semantics remain a lossy topology/selection projection; NH-ID-only paths require later nexthop-object observation or compatibility gating; and live route identity/replacement is not yet defined. Route notifications before `GETROUTE` are subsumed by the later dump, while notifications after that cutoff taint the transaction and force a fresh full dump.

The rule foundation adds canonical IPv4/IPv6 policy-rule facts and a strict private `RTM_NEWRULE`/`RTM_DELRULE` decoder. It preserves raw action, origin-protocol, and rule-flag values while decoding table, priority, interface, GOTO, fwmark, tunnel, suppression, L3MDEV, UID, IP-protocol, port-range, and IPv4 flow selectors. Prefix host bits and fwmark bits outside the mask are normalized to their effective selection semantics; mandatory Linux 5.10 dump attributes, reserved header bytes, compact/extended table agreement, family widths, scalar endianness, interface termination, range bounds, padding, ordered duplicate events, and whole-datagram loss metadata are validated. Well-framed future `FRA_*` attributes remain observable without being trusted: each affected rule carries bounded ordered opacity diagnostics plus an aggregate SHA-256 change fingerprint over every opaque attribute. The fingerprint participates in inventory identity but is not raw ownership or deletion evidence. Linux fib rules have no replacement operation, so `NLM_F_REPLACE` remains an ordinary upsert flag with no exposed rule semantics.

Canonical rules remain semantic projections rather than exact deletion identities, but they now enter the runtime inventory in exact dump order with multiplicity because equal-priority and duplicate rules are valid. Rule notifications before `GETRULE` are subsumed by the later dump; notifications after RULE starts force a full resynchronization instead of ambiguous live insertion or deletion. Kernel rule identity and native policy-routing mutation remain pending.

The transport uses byte-exact `AF_UNSPEC RTM_GETROUTE` and `RTM_GETRULE` requests with zeroed 12-byte family headers, unique nonzero sequences, strict `NLM_F_REQUEST | NLM_F_DUMP` framing, and no filter attributes. Endian-specific fixtures and a sequential real-kernel LINK→ADDRESS→ROUTE→RULE smoke verify the shared socket and receive ring. Faults during an active phase stale the source and drain the owned sequence to terminal `NLMSG_DONE` or `NLMSG_ERROR` before restarting at LINK; raw terminal hints survive semantic decode failures and intact kernel-response slots in otherwise lossy receive batches. A drain that cannot recover terminal evidence by its deadline permanently degrades only observation for the current socket registration rather than risking an overlapping request.

The first inventory consumer is now a pure address-bypass planner in `flux-core`. From one complete snapshot and an explicit caller-resolved routing specification, it derives deterministic unique IPv4 `/32` and IPv6 `/128` intents after family, usability, flag, exact-address, and CIDR filtering. Valid IPv4-mapped inputs normalize consistently, malformed mapped inventory facts are rejected, and fixed rule/conflict bounds prevent unbounded planning evidence. Plans carry the originating epoch plus an opaque snapshot identity. The planner rechecks selected priority slots but does not allocate Android-safe priorities, infer ownership from semantic equality, adopt or retire existing rules, encode rtnetlink messages, or mutate the kernel. The placement checkpoint below validates caller-selected numeric windows; Android classification and allocation, the generation journal, native encoding, and mutation remain later work.

The versioned RPDB placement checkpoint is now present as a second pure inventory consumer. Caller-supplied classifications remain aligned with every ordered rule fact and are bound to a classifier revision; enabled families fail closed on opaque attributes, unknown classifications, or missing policy boundaries. A classifier cannot override incomplete kernel semantics with `DoesNotConstrainFlux`; opacity in a disabled family remains outside a single-family lease, while dual-stack admission still succeeds or fails atomically. Candidate admission reserves distinct address-bypass and proxy priorities strictly between the proven boundaries, rejects exact priority occupancy and intersecting GOTO edges, and requires the proposed private route table to be empty of foreign routes and rule references. Same-epoch cross-tracker audits and stale classifier revisions are rejected by process-local snapshot identity. The lease projects address-bypass rules only toward table 254 and explicitly defers mark leasing, boot and network-namespace identity, durable ownership, exact kernel mutation identity, route-policy canaries, native encoding, and all mutation.

The partial mark-planning checkpoint is present rather than manufacturing a synthetic lease. `flux-core` can validate a common masked field and prove collisions with Android's `netId` bits and the ordered RPDB selector inventory, including exact-looking, inverted, unknown-action, cross-family, and duplicate rules. Reports retain bounded ordered conflict evidence, mark the RPDB evidence source `Opaque` whenever any observed rule has unmodeled attributes, expose unavailable device-policy, xtables, nftables, TC/BPF, XFRM, connmark/socket, and ownership sources, and remain bound to the exact inventory identity. Opacity is uncertainty rather than a manufactured collision: a definite selector overlap still yields `Conflicting`, while a disjoint opaque inventory remains `Incomplete`. Even with no known collision the partial outcome is only `Incomplete`: generic Android has no public mark allocator, negative scans are not positive allocation authority, and no `MarkLease`, expert override, backend plan, or mutation intent is produced.

The Android semantic classifier checkpoint now extracts exact roles under three explicitly selected, source-pinned AOSP grammars: Android 12 r1, Android 13 r1, and the pinned March 2025 netd revision. It validates the complete modeled signature rather than priority alone, preserves rule order and duplicates, requires the fixed initialization skeleton in every observed family, and publishes bounded diagnostics for opacity, signature drift, unfamiliar priorities, missing anchors, and nonmonotonic order. V1 conservatively maps every recognized role before default-network to `MustPrecedeFlux`, maps exact default-network and final unreachable rules to `TerminalBarrier`, and never emits `DoesNotConstrainFlux`.

The classifier also embeds a static lattice contract in its aligned audit because an observed dump cannot reserve absent future netd rules. Android 12 has no integer priority between the maximum UID-default-unreachable priority `28999` and default-network `29000`; Android 13 and later have only `30999` between `30998` and `31000`. Both the generic planner and Android-specific diagnostic wrapper therefore reject the current two-rule address-bypass-plus-proxy topology even when a sparse snapshot appears to contain a hole. This is a discovered design constraint, not a reason to weaken classification: the next routing-design checkpoint must split traffic domains, prove selector/network-selection handoff, or remove one RPDB priority before allocation, encoding, ownership, and mutation work can continue.

The first topology-redesign checkpoint now provides a pure `flux-core` feasibility report rather than weakening the placement lease. Address filtering first produces a neutral snapshot-bound host set shared with the compatibility address-rule planner, allowing a future pre-mark Capture Policy realization to consume zero RPDB priorities without yet claiming backend ordering. Android topology reports then anchor residual local OUTPUT to one exact observed default-network rule and present/admin-up loopback link, or forwarded capture to one exact observed tethering rule and present/admin-up non-loopback ingress link. Exact input-interface and fwmark conflicts are the only current selector-disjoint proofs; opacity, drift, missing anchors, invalid family profiles, and overlapping same-domain anchors with distinct tables fail closed.

The resulting structural evidence is explicit: Android 12 local OUTPUT remains impossible; Android 13/current local OUTPUT has only `30999`; and each exact tether ingress has `20001..20999`. A dedicated address-bypass RPDB rule still needs two slots and fails for local OUTPUT; because that rule has no traffic-domain selector, it is also incompatible with the tether interval. A pre-mark address host set reduces the structural demand to one, but no result is Android-policy-safe or activation-capable: domain-identity and network-selection handoff, mark authority, route reachability, exact Capture Program ordering, boot/namespace identity, observer continuity, ownership, mutation identity, and device canaries remain mandatory.

The next pure checkpoint now aggregates those reports atomically for a bounded requested Traffic Scope. A request binds one routing shape to selected IPv4/IPv6 residual-local domains and exact tether ingress interfaces, rejects empty/duplicate/oversized scopes, and requires at least one recognized usable anchor for every requested domain. Every matching anchor is assessed rather than letting a caller cherry-pick one rule; successful assessments are retained in deterministic order, while any unusable or ambiguous match rejects the whole scope without partial output. Definite incompatibility or priority-slot exhaustion dominates an otherwise incomplete aggregate; absent a definite rejection, any incomplete anchor keeps the scope incomplete, and only all residual windows produce the residual multi-domain summary. Freshness repeats complete anchor discovery and assessment against the current inventory/classifier instead of comparing only epoch or revision headers. This remains diagnostic evidence: it neither intersects or sums per-domain windows nor emits a priority, mark, route/table intent, ownership claim, or mutation authority.

The positive Android mark-authority model is now implemented as the next pure checkpoint. Generic AOSP is a zero-grant policy; bits 21–30 are only a syntactic envelope for a device-qualified candidate. A positive policy factory records an externally established cooperative assertion bound to the exact candidate and topology scope, full Capability Profile with verified boot identity, network namespace, named policy plus nonzero SHA-256 artifact digest and revision, and the exact nonempty plane set asserted by that policy. The delivered factory is a modeling trust boundary, not a production policy loader. Production use first requires exact Android product/build/vendor, kernel-build, verified-boot, SELinux-policy, netd/Connectivity artifact, tool, boot, and namespace identity. A compile-time reviewed catalog is keyed only by stable artifact identities; its selected assertion is then bound to verified boot, boot ID, and the observed namespace. A runtime manifest cannot create authority by hashing itself. Planning authorization separately requires the assertion to cover packet, socket, and conntrack marks.

Planning authorization consumes a non-`Clone` census with exactly nine evidence sources—Android `netId`, RPDB, device policy, legacy xtables, nftables, TC/BPF, XFRM, connmark/socket transfers, and existing Flux ownership—across all three planes. Every one of the 27 source-plane cells must be complete-present or complete-absent, at most 512 raw uses are accepted before canonical sorting and deduplication, and the observation binds inventory snapshot/epoch, full capability facts, namespace, policy identity/revision, collector revision, and ownership-journal identity/revision. Any external read/write/transfer overlap rejects regardless of values, opaque RPDB rejects, and known conflicts take precedence over incomplete topology evidence. The result exposes only a consuming, freshness-checked `AndroidMarkPlanningAuthority`; it cannot produce a `MarkLease`, priority, table, route, encoder, mutation, writer, or activation conversion, and reauthorization requires a fresh census.

The first source-scoped mark-evidence checkpoint is now implemented as a pure
`RpdbFwmarkCensusFragment`. It projects each ordered RPDB fwmark selector into adjacent packet- and
socket-plane predicate reads because Linux route lookup can seed `flowi_mark` from either
`skb->mark` or `sk->sk_mark`; RPDB directly reads no conntrack mark. Duplicate rules remain duplicate
raw pairs, opaque rules keep both flow-origin cells opaque while retaining known uses, and the
snapshot/epoch binding rejects drift and equal-epoch cross-tracker evidence. The fragment accepts
at most 512 raw records—256 marked rules—and rejects selector 257 without truncation. It has no
complete-collector revision, policy or ownership binding, complete-census conversion, Planning
Authority, lease, writer, or mutation capability. The remaining 24 cells and cross-source
point-in-time coordination are still pending.

### Deliverables

- Reimplement the required `addrsyncd` netlink behavior behind private `flux-platform` modules; do not expose raw rtnetlink framing as the product Interface. Resolve the standalone subproject's `UNLICENSED` provenance before copying source text into the GPL workspace.
- Deliver a read-only, subscribe-before-dump link/address/route/rule observer before any native mutation. It must publish only complete, canonical `NetworkInventory` snapshots with a monotonic `NetworkEpoch` and integrate into the existing single reactor rather than creating a second epoll owner.
- Preserve batched receive/send, optional extack diagnostics, address filters, bounded per-turn work, quiet debounce, debounce maximum, and compensating resync behavior.
- Treat `MSG_TRUNC`, `ENOBUFS`, `NLMSG_OVERRUN`, malformed or ambiguous messages, `NLM_F_DUMP_INTR`, missing `NLMSG_DONE`, and sequence inconsistency as mandatory full-resync conditions. While a dump is active, serialize resynchronization behind that sequence's terminal response; if terminal evidence cannot be recovered by the drain deadline, leave the source invalid and degrade observation rather than overlap a replacement request. Partial dumps never advance the Network Epoch.
- In-process address-derived Bypass Policy.
- Add exact Android product/build/vendor, kernel-build, verified-boot, SELinux-policy, netd/Connectivity artifact, tool, and namespace identity to the freshness-bound profile.
- Define a compile-time reviewed positive-policy catalog keyed by stable product/build/kernel/policy/tool artifact identities and an externally reviewed digest/revision; bind the selected assertion to verified boot, boot ID, and observed namespace, and reject arbitrary runtime manifests as authority.
- Continue bounded source-by-source mark-evidence collection and then assemble the fresh complete 27-cell fwmark census collector; source fragments cannot authorize planning, and generic AOSP must continue to produce zero grant.
- Rust rtnetlink PBR apply/verify/cleanup.
- Generation journal and startup recovery for routes/rules.
- Remove the standalone `addrsyncd` process from runtime, while keeping its binary available for one bridge release as emergency rollback.

### Ownership rule

`fluxd` becomes the only owner of Flux PBR and address-derived rules. The shell `tproxy` adapter must call into `fluxd` or skip its old route section.

### Exit gate

- Lifecycle, event loss, address churn, IPv6 temporary-address, and cleanup tests meet the stricter loss/recovery contract even where current `addrsyncd` behavior does not.
- An event arriving during the initial dump is replayed after that dump or forces another complete dump; no event/dump race may publish a stale inventory.
- Netlink work budgets yield to ready control and shutdown sources in the one daemon reactor.
- Kill-9 at each journal phase converges without deleting unrelated rules.
- Real-device CPU/RSS and convergence baseline is captured.

## Phase 4 — Rust xtables and ipset parity

The first supporting checkpoint is intentionally below a Capture renderer. `flux-platform` can
parse and canonically re-encode the frozen restore syntax as an ordered, bounded observation
artifact: repeated `mangle`/`filter`/`nat` transactions, chain declarations, `-A`/`-I` apply
commands, `-D`/`-F`/`-X` cleanup commands, duplicates, family context, cleanup phase ordering,
resource usage, and an exact byte digest are retained. Cleanup phase ordering is enforced within
each restore transaction. The parser performs no shell execution,
filesystem discovery, restore invocation, kernel access, Generation conversion, ownership, or
activation. Its current-shaped synthetic tests are grammar tests, not shell-generated fixture,
renderer, byte-parity, kernel-acceptance, cleanup-completeness, or device-parity evidence.

### Deliverables

- Rust compiler for xtables restore programs.
- Direct child-process adapter for `iptables-restore`/`ip6tables-restore`.
- Coherent iptables-legacy versus iptables-nft detection and exact canaries; one Generation may use only one matched IPv4/IPv6 implementation family.
- Stable dispatch chains plus generation chains.
- ipset capability probes, generation-specific sets, inactive population/optional temporary swap, stable-jump cutover, verification, and cleanup without changing set contents under the old Generation.
- Bounded-tree fallback compiler.
- Transaction coordinator spanning Sing-Box, xtables, ipsets, and rtnetlink.
- Drift detection for Flux-owned chains, sets, routes, and rules.
- Exact `xt_bpf` capability adapter: first prove the match is built in or already active without
  triggering `request_module`, then perform map operations, socket-filter load/helpers, bpffs
  pin/get, revision-1 `--object-pinned`, IPv4/IPv6 OUTPUT/PREROUTING packet canaries, UID-context
  behavior, rule-reference teardown, and crash cleanup. The conventional xtables compiler remains
  complete when this adapter is absent.

### Ownership rule

`scripts/rules` and `scripts/tproxy` remain frozen, executed compatibility-oracle components until
the Phase 4 transition lease disables their writer path. Only then does `fluxd` become the sole
writer of Flux xtables/ipset state and the scripts become non-executed compatibility artifacts.
There is no shadow/native dual-writer interval.

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
- Production seccomp and package verification deny/reject `init_module`, `finit_module`, `delete_module`, `.ko`, KPM, and opaque kernel payloads.
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
- Shadow Capture Policy normalization, local/forwarded ordering, canonical mandatory baseline,
  semantic digest determinism, resource bounds, and explicit non-authorizing/deferred reports.
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

1. Keep the Rust-owned bridge and public configuration TUN rejection until an exact Flux or
   Sing-Box owner passes route readback and forced-death cleanup canaries; then replace the
   rejection with that single proven owner. Keep `BYPASS_SET_BACKEND=zone` as the only admitted
   bridge value until the ipset/auto adapters have distinct capability and parity evidence.
2. Complete the bounded Phase 2 shadow Capture Program checkpoint. Keep compilation pure and
   deterministic; emit separate ordered local/forwarded programs, the canonical mandatory safety
   baseline, optional inventory-host provenance, bounded resource accounting, semantic digest,
   compatibility assumptions, and deferred prerequisites. Extract semantic fixtures from the
   frozen shell oracle, but add no restore
   renderer, Generation ID, Planning Authority, writer token, prepared/active conversion,
   Runtime Coordinator path, eBPF attach/pin, TUN activation, implicit module request, or `.ko`/KPM
   loading. Treat any later renderer/parity/cutover as its own reviewed checkpoint.
3. Continue the incomplete local-OUTPUT integration-plumbing checkpoint only after the audited
   bridge-contract correction checkpoint passes full CI. Build on the delivered fail-closed
   TPROXY-only seam, exact credential preflight, and completed capture plus process-ownership
   receipt contracts, and submit each subcheckpoint separately:
   - **2a complete — retained engine-child authority handoff:**
     `SingBoxChild::open_process_handle` opens only from the retained live child, checks exact
     recorded PID/start ticks against the pidfd/procfs identity, and leaves signal/wait/reap
     authority with the adapter. `EngineSupervisor` requires matching ready/active/readiness/
     snapshot/child identity and exact snapshot revision, while the serialized coordinator binds a
     single-use opener to the immutable request identity/revision/deadline. Execution invokes it
     only after read-only backend availability succeeds and before prepared-attempt construction,
     then moves the result once into the process verifier after capture verification. The driver never receives the pidfd authority, and current
     xtables `Unsupported` opens no authority.
   - **2b-1 complete — exact engine observation pair:** consume that exact authority in the process
     verifier, preserve its child-origin initial observation, and reobserve the same retained pidfd
     after capture verification. The non-cloneable raw pair binds identity, snapshot revision,
     private opening identity, stable credentials, and exclusive deadline; the handle remains
     observation-only and exit/deadline failure is cleanup-uncertain. Production still cannot mint
     a process receipt.
   - **2b-2a complete — engine credential-policy and process-domain validation:** observe opened
     user/mount/network namespace descriptors for every task and bounded canonical UID/GID maps
     instead of copying request values; reject thread, namespace, or map drift across the two-pass
     census; and validate both engine observations against all four request UID/GID slots, empty
     supplementary groups, zero capabilities, `NoNewPrivs`, the exact credential-map domain, and
     daemon network namespace. The production process-receipt authority remains uninhabited.
   - **2b-2b pending — driver-child ownership and final receipt chronology:** retain client/peer
     children through exact termination and parent reap, bind their exact handle/domain evidence,
     and record final attempt completion only after all verifier observations before minting any
     process receipt.
   - **2c pending — listener observer:** independently prove every required listener FD/inode/cookie,
     wildcard bind, UDP listener state, transparency, and IPv6-only state; readiness port evidence
     and the current outbound connected-socket collector are insufficient substitutes.
   - **2d pending — supervised report capability/parser:** define a bounded schema-v1 parser and
     test-only report frames, then bind the exact producer source, transport/framing, sequence/loss,
     object lifetime, and cleanup semantics to the immutable `EngineCapabilityProfile`.
   - **2e pending — collector/factory/cleanup integration:** use the exact prebound `/proc` FD plus
     INET_DIAG session for actual observations, bind every cleanup identity and report object to its
     owned resource, and drive test-only fixtures through schema-v2 `validate_for`.

   The combined checkpoint remains incomplete and production continues to return `Unsupported`.
   Before a real producer may inhabit either receipt authority, document and device-qualify one
   local-OUTPUT capture mechanism that preserves TPROXY semantics and bind an exact report producer
   contract to the immutable `EngineCapabilityProfile`; an unavailable producer is not inferred
   from logs, APIs, counters, or successful proxy traffic. REDIRECT/DNAT, ingress traffic, counters,
   route lookups, and veth-bounce paths cannot qualify TPROXY. Only after the selected backend's
   listener path is proven may the explicit Android adapter and qualification matrix proceed.
4. Populate the release manifest with exact immutable source revisions, versions, targets, hashes,
   licenses, device-test evidence, SBOM, checksums, and build metadata, then make the strict
   `verify-package` boundary pass. Resolve the standalone `addrsyncd` license before publication;
   do not treat development staging or unsigned self-authored evidence as a release artifact. The
   later `package-magisk` boundary must verify signed/reproducible third-party provenance and
   trusted device/CI attestations.
5. Capture the current real-device baseline and replace every placeholder evidence field.
6. Build and persist the exact versioned Sing-Box Engine Capability Profile before compiling any final Generation, including whether an authoritative supervised delivery-report producer exists and its exact versioned transport/framing, schema, loss/sequence, and lifecycle contract.
7. Extend the Capability Profile with exact Android product/build/vendor, kernel-build, verified-boot, SELinux-policy, netd/Connectivity artifact, tool, and namespace identity.
8. Define the compile-time reviewed positive mark-policy catalog over stable artifact identities, then bind selections to verified boot, boot ID, and observed namespace; never authorize an arbitrary runtime self-hashed manifest.
9. Complete the remaining mark-evidence fragments and point-in-time 27-cell coordinator, then satisfy exact writer semantics, observer continuity, and mark-preservation canaries; do not turn planning authority into an activation lease.
10. Redesign the RPDB program around the proven no-two-slot/default-network and tethering/per-UID constraints, satisfy domain/network-selection handoff, ownership, reachability, and canary prerequisites, and only then implement priority/table allocation.
11. Cut over address-derived rules and PBR with a transition lease that disables the shell route writer before the first native mutation.
12. Implement the future Rust `fluxd migrate --check-only` compatibility importer from legacy
    `settings.ini`/`addrsyncd.toml`, distinct from the completed shell installer migration, and
    extract current rule-generation cases into backend-neutral golden fixtures.
13. Implement only isolated `xt_bpf` probe mechanics in parallel. Do not attach from the production
    daemon, publish device capability, retain pins, trigger implicit module loading, or modify live Flux chains while shell
    remains the bridge writer. Wire the device-qualified compiler adapter in Phase 4, and keep
    broader eBPF observation in Phase 7 without delaying correctness work or selecting acceleration
    before parity and benchmark gates.
