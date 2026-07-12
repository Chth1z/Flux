# Fluxd Technical Specification

Status: proposed  
Companion document: [Fluxd Rewrite Blueprint](fluxd-blueprint.md)

## 1. Supported platform contract

| Item | Contract |
|---|---|
| Operating system | Android/Linux; Android is the release target |
| Kernel | `>= 5.10`; older versions settle the daemon into read-only `UnsupportedKernel` before mutation |
| Primary architecture | `aarch64-linux-android` |
| Secondary CI architecture | `x86_64-unknown-linux-gnu` for host/integration tests |
| Rust | Edition 2024, pinned stable toolchain |
| Android linking | NDK-built PIE using bionic; no assumption of glibc or a fully static libc |
| Privilege | root at startup; capability minimization is conditional on device policy |
| Proxy Engine | an external, version-qualified Sing-Box binary |

The code compiles only for Linux/Android. Android-specific behavior is runtime-detected rather than selected by product-name conditionals where possible.

## 2. Process model

`fluxd` is a multicall binary:

```text
fluxd daemon
fluxd status [--json]
fluxd start|stop|reload
fluxd reconcile [--wait]
fluxd capabilities [--json] [--refresh]
fluxd backend explain [--json]
fluxd plan [--json] [--dry-run]
fluxd subscription update
fluxd diagnose [--bundle PATH]
fluxd repair
fluxd migrate [--check|--write]
fluxd recover --offline
fluxd cleanup --offline
```

`fluxctl` is a symlink or a small shell wrapper that executes the same binary.

Only `fluxd daemon` is long-lived. Sing-Box is its child. A boot shell watchdog may restart `fluxd` after a crash or fatal invariant exit, but it contains no policy logic, never invokes a second recovery owner, and does not restart a settled `UnsupportedKernel` daemon. Normal journal recovery runs inside daemon startup before mutating commands are accepted. `fluxd recover --offline` is an explicit salvage command that requires the daemon lease to be absent. The legacy `fluxctl restart` verb is a client alias for `ReloadSources` followed by `Converge(Configured)`; it has no separate protocol or lifecycle meaning.

In the delivered Phase 1 bridge, `RuntimeCoordinator` implements `LegacyDispatcher` and runs on the one bounded `LegacyControlBridge` worker. The worker serializes requests, address resynchronization, idle maintenance, and shutdown. `EngineSupervisor` owns the Sing-Box child; shell phase scripts remain the only rules/routes/address-sync writer. A boot-scoped mode lease rejects legacy `scripts/core` verbs for the duration of a Rust-owned engine run.

## 3. Local control socket and Module routing

The control socket is `/data/adb/flux/run/fluxd.sock`, Unix `SOCK_SEQPACKET`, protocol version 2. Version 2 adds the coherent boot-scoped Capability Profile to status responses; version-1 requests are rejected explicitly rather than decoded against the new response shape.

### 3.1 Request envelope

```rust
#[derive(Serialize, Deserialize)]
struct RequestEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    command: SocketCommand,
    wait: WaitPolicy,
}

enum WaitPolicy {
    Accepted,
    Completed { timeout_ms: u32 },
}
```

### 3.2 Commands

```rust
enum SocketCommand {
    Controller(ControllerWireCommand),
    Inspect(InspectCommand),
    Maintenance(MaintenanceCommand),
}

enum ControllerWireCommand {
    SetEnabled { enabled: bool },
    ReloadSources,
    Reconcile { reason: ReconcileReason },
    Shutdown,
}

enum InspectCommand {
    Snapshot,
    Watch { after: StatusRevision, timeout_ms: u32 },
}

enum MaintenanceCommand {
    RefreshCapabilities,
    ExplainPlan,
    UpdateSubscription,
    Diagnose { include_sensitive_metadata: bool },
    Repair,
    Migrate { write: bool },
}
```

The socket router is not the Controller Module. `ControllerWireCommand` maps to the selected `submit` Interface; `InspectCommand` maps to `snapshot`/`watch`; maintenance commands are dispatched to separate capability, planning, subscription, diagnostics, migration, or recovery Modules with their own authorization and failure contracts.

Separate Modules do not imply separate kernel writers. Capability probes, online repair, and every other operation that may create, attach, replace, or delete a kernel object are submitted through the same kernel-mutation scheduler and Generation fence as reconciliation. Offline `recover` and `cleanup` require the exclusive daemon lease and refuse to run while a live daemon owns it. Read-only planning/diagnostics and file-only migration may execute outside the kernel writer but use their own bounded state/configuration locks.

### 3.3 Response envelope

```rust
struct ResponseEnvelope {
    protocol_version: u16,
    request_id: RequestId,
    result: Result<ResponseBody, ErrorReport>,
}
```

Packets larger than 1 MiB are rejected. The daemon verifies peer credentials and socket permissions. Mutating commands require root or the configured administrative group; read-only commands may be granted to the Android shell UID.

Request IDs are retained in a bounded recent-result cache so a retried mutating request is not applied twice.

Phase 1 status returns `control` and `runtime` separately. `ControlSnapshot` describes desired/control progress. `RuntimeSnapshot` is an independently revisioned observed projection containing runtime phase, capture state, engine state, generation, and an optional bounded operation/message/recovery failure. Clients must not infer observed health solely from administrative intent or request completion.

## 4. Core domain types

### 4.1 Desired State

```rust
struct DesiredState {
    administrative: AdministrativeState,
    engine: EngineSpec,
    capture: CaptureIntent,
    scope: TrafficScope,
    bypass: BypassPolicy,
    subscription: SubscriptionPolicy,
    failure: FailurePolicy,
}

enum AdministrativeState {
    Enabled,
    Disabled,
}

enum FailurePolicy {
    Open,
    Closed,
}
```

### 4.2 Capture intent

```rust
struct CaptureIntent {
    mode: CaptureMode,
    backend: BackendPreference,
    ipv6: TriState,
    ebpf: EbpfPreference,
    marks: MarkPolicy,
    routing: RoutingPolicy,
    tun: TunPolicy,
}

enum CaptureMode { Auto, Tproxy, Tun }
enum BackendPreference { Auto, Nftables, Xtables }
enum EbpfPreference { Auto, Off, Observe, Accelerate }
enum TriState { Auto, On, Off }
enum AutoToggle { Auto, On, Off }

struct TunPolicy {
    stack: TunStackPreference,
    interface: InterfaceName,
    mtu: u32,
    offload: AutoToggle,
    multiqueue: AutoToggle,
}

enum TunStackPreference { Auto, System, Mixed, Gvisor }
```

### 4.3 Observed State

```rust
struct ObservedState {
    daemon: DaemonHealth,
    engine: Option<ObservedEngine>,
    kernel: KernelSnapshot,
    network: NetworkInventory,
    active_record: Option<GenerationRecord>,
    drift: Vec<DriftFinding>,
}
```

### 4.4 Compiled Generation

```rust
struct CompiledGeneration {
    id: GenerationId,
    artifact: GenerationArtifact,
}

struct GenerationArtifact {
    desired_digest: Digest,
    capability_profile_revision: CapabilityProfileRevision,
    engine_profile_revision: EngineCapabilityProfileRevision,
    engine_binary_digest: Digest,
    backend_plan: BackendPlan,
    engine_config: EngineConfigArtifact,
    capture_program: CaptureProgram,
    route_program: RouteProgram,
    ebpf_program: Option<EbpfProgramSpec>,
    resource_budget: ResourceBudget,
    invariants: Vec<GenerationInvariant>,
}
```

`GenerationArtifact` is the deterministic, digest-bearing compiler output. Capture, route, and eBPF programs inside it use logical Managed Object keys rather than concrete kernel names. The Controller assigns the `GenerationId` only after successful compilation, and adapters derive bounded concrete names deterministically from that ID during preparation; creation/update timestamps belong to `GenerationRecord`, not the artifact. All numeric kernel identifiers use validated newtypes. Generation IDs use a monotonic local sequence plus an artifact-digest prefix; correctness does not depend on wall-clock uniqueness.

## 5. Configuration schema

The authoritative user file is `conf/flux.toml`.

### 5.1 Parsing rules

- `schema` is mandatory.
- Unknown fields are errors unless explicitly reserved by the active schema.
- Duplicate fields are errors.
- Durations and sizes have bounded numeric representations.
- CIDRs are parsed and canonicalized; host bits outside the prefix are rejected or normalized with an explicit diagnostic according to field policy.
- Marks and masks accept decimal or `0x` syntax and are stored as `u32`.
- Package lists are names only; UID resolution happens from the Android inventory.
- Secrets are read from separately permissioned files by default.
- No configuration file is evaluated as shell.

### 5.2 Required sections

```toml
schema = 1

[daemon]
fail_policy = "open"
reconcile_debounce_ms = 250
event_queue_capacity = 256
generation_history = 2

[engine]
binary = "/data/adb/flux/bin/sing-box"
template = "/data/adb/flux/conf/sing-box.json"
runtime_user = "root"
runtime_group = "root"
startup_timeout_ms = 8000
restart_burst = 3
restart_window_secs = 60

[capture]
mode = "auto"
backend = "auto"
ipv6 = "auto"

[capture.marks]
allocation = "auto"

[capture.routing]
table = "auto"
rule_priority = "auto"

[android]
respect_android_vpn = true

[capture.ebpf]
mode = "auto"
sample_rate = 0

[capture.tun]
interface = "flux0"
ipv4 = "172.19.0.1/30"
ipv6 = "fdfe:dcba:9876::1/126"
mtu = 9000
stack = "auto"       # auto | system | mixed | gvisor
offload = "auto"
multiqueue = "auto"

[scope]
android_users = "owner"
app_mode = "all"
packages = []

[[scope.interfaces]]
pattern = "rmnet_data*"
action = "proxy"

[[scope.interfaces]]
pattern = "wlan0"
action = "proxy"

[bypass]
private = true
local_addresses = true
multicast = true
cidrs = []

[subscription]
enabled = false
url_file = "/data/adb/flux/conf/subscription.url"
update_interval_secs = 86400
download_timeout_secs = 10
max_download_bytes = 16777216
max_nodes = 10000
```

The legacy values (`0x14`, `0x19`, `0x11` under mask `0xff`, table/priority `2025`) are imported only as compatibility candidates. They are not presumed safe: AOSP netd assigns bits 0–15 of the fwmark to `netId`, so the compiler must remap or reject overlapping legacy marks. New installations use automatic allocation after live mark/rule conflict analysis.

## 6. Capability Profile

### 6.1 Record format

```rust
struct CapabilityProfile {
    revision: CapabilityProfileRevision,
    boot_id: BootId,
    identity: DeviceIdentity,
    kernel: KernelVersion,
    probed_at: SystemTime,
    capabilities: BTreeMap<CapabilityId, CapabilityEvidence>,
}

struct CapabilityEvidence {
    status: CapabilityStatus,
    version_gate: VersionGateResult,
    hints: Vec<CapabilityHint>,
    probe: Option<ProbeResult>,
    runtime_demotions: Vec<DemotionRecord>,
}

enum CapabilityStatus {
    Supported,
    Unsupported,
    Denied,
    Broken,
    Unknown,
}
```

### 6.2 Version catalog

Every optional feature entry has:

```rust
struct FeatureCatalogEntry {
    introduced: Option<KernelVersion>,
    removed: Option<KernelVersion>,
    known_bad: &'static [KernelVersionRange],
    required_config_hints: &'static [&'static str],
    probe_kind: ProbeKind,
}
```

The catalog is evidence and optimization, not final authority. Exact introduction and known-bad metadata must be sourced from upstream kernel documentation or source and covered by unit tests.

### 6.3 Required probes

| Capability | Active probe |
|---|---|
| Kernel floor | parse `uname`, compare with 5.10 |
| Rtnetlink extack/batching | open sockets, issue harmless dump/request, validate acks |
| nftables base support | create/delete uniquely named temporary table in one batch |
| nftables required program | create a non-matching canary in the real hook context using the exact set lookup, counter, masked mark update, socket-transparent match, TCP/UDP TPROXY expressions, and one batch; list/normalize it, then delete and verify absence |
| xtables TPROXY path | detect legacy versus nft variants, require coherent IPv4/IPv6 restore tools, then apply/verify/clean a private chain with the exact matches and targets |
| ipset | create, populate, swap, and destroy temporary family-specific sets |
| TUN | open device, create unique non-persistent interface, query flags, close, verify removal |
| eBPF map types | create each required map type and close it |
| eBPF program types | load minimal program and capture verifier output |
| eBPF attach points | attach/detach harmless program at the exact intended hook |
| BTF/CO-RE | open BTF and load a relocation-dependent probe program |
| BPF ring event transport | create, mmap, epoll, submit/consume, and overflow-test ringbuf; otherwise probe perf-event-array fallback |
| TUN eBPF steering | only for a Flux-owned TUN FD contract: load socket-filter canary, attach with `TUNSETSTEERINGEBPF`, verify queue selection, detach |
| io_uring TUN I/O | only for a Flux-owned TUN FD contract: setup, opcode/cancel probes, real packet read/write, and benchmark |
| pidfd | open pidfd for self/child and poll it |
| Unix seqpacket/peer credentials | local socket pair and credential read |

Probe objects carry an RAII cleanup guard. A process crash may still leave kernel objects, so boot recovery scans only the reserved probe namespace and removes objects whose owner PID/boot ID is stale.

### 6.4 Engine Capability Profile

Before Generation compilation, Flux queries and validates the exact Sing-Box binary and builds an `EngineCapabilityProfile` containing an immutable revision, binary digest, parsed version/build identity, supported configuration dialect, TPROXY listener staging, TUN route-automation control, `system`/`mixed`/`gvisor` stacks, mark/interface controls, DNS fields, reload behavior, and any documented FD-handoff contract. The planner rejects plans whose engine requirements are not proven even when the kernel path is available.

Every `CompiledGeneration` records both the device `CapabilityProfileRevision` and the `EngineCapabilityProfileRevision` used by the planner. A boot change, runtime capability demotion, Sing-Box binary replacement, or engine-profile refresh invalidates the planning lease: Flux must recompile or explicitly prove that the active Generation's requirements are still satisfied before repairing or reactivating it.

## 7. Backend Plan

```rust
struct BackendPlan {
    capture: CaptureBackend,
    address_sets: AddressSetBackend,
    routing: RoutingBackend,
    tun: Option<TunBackendPlan>,
    ebpf: EbpfMode,
    degraded: Vec<DegradedFeature>,
    rejected: Vec<RejectedBackend>,
}

enum CaptureBackend {
    NftTproxy,
    XtablesTproxy,
    SingBoxTun,
}

enum AddressSetBackend {
    NftIntervalSet,
    IpsetHashNet,
    XtablesBoundedTree,
    NotApplicable,
}

enum RoutingBackend {
    RtnetlinkMarkedLocal,
    RtnetlinkTun,
}

enum EbpfMode {
    Off,
    Observe,
    Accelerate,
}

struct TunBackendPlan {
    ownership: TunOwnership,
    stack: TunStack,
    io: TunIoPlan,
}

enum TunOwnership { EngineOwned, FluxOwnedFd }
enum TunStack { System, Mixed, Gvisor }
enum ResolvedToggle { Enabled, Disabled }
enum TunIoPlan {
    EngineOwned {
        offload: ResolvedToggle,
        multiqueue: ResolvedToggle,
    },
    FluxOwnedFd {
        queues: NonZeroU16,
        offloads: TunOffloadSet,
        io_driver: TunIoDriver,
        steering: TunSteeringMode,
    },
}
struct TunOffloadSet { checksum: bool, gso: bool, gro: bool }
enum TunIoDriver { Epoll, IoUring }
enum TunSteeringMode { KernelDefault, Ebpf }
```

`AutoToggle::On` is a strict requirement and fails planning unless the selected ownership model and exact Engine Capability Profile prove it. `Off` disables the feature. `Auto` enables it only after the relevant end-to-end kernel/engine probe and benchmark gate succeeds. A compiled plan contains only resolved values; no `Auto` reaches activation.

### 7.1 Selection algorithm

1. Reject kernel `< 5.10`.
2. Normalize explicit user preferences.
3. Derive hard requirements from Traffic Scope: local apps, tethered traffic, IPv6, per-app policy, UDP, DNS, Android VPN semantics, and fail policy.
4. Evaluate candidate plans against `Supported` device capabilities and the version-qualified Engine Capability Profile only.
5. Reject candidates that exceed rule/set/map/resource budgets.
6. Score remaining candidates by requested mode, semantic coverage, atomicity, recovery quality, and tested preference order.
7. Add eBPF independently; it cannot rescue an otherwise invalid correctness plan.
8. Return the selected plan and all rejection reasons.

The algorithm is pure and has golden tests for representative device profiles.

## 8. Policy compilation

### 8.1 Normalized decision order

The backend-neutral Capture Program uses this order:

1. traffic outside Traffic Scope;
2. Flux control and Proxy Engine loop prevention;
3. invalid, local-only, multicast, broadcast, and configured Bypass Policy;
4. established-flow cached bypass/proxy decision when valid;
5. interface/network role decision;
6. Android user/UID policy for locally originated traffic;
7. protocol-specific safety policy;
8. proxy action;
9. direct default for unsupported or explicitly bypassed scopes.

Forwarded traffic never evaluates an OUTPUT-only UID predicate. Local and forwarded programs are compiled separately even when a backend later shares chains or sets.

### 8.2 Mark invariants

- `mask != 0`.
- Proxy and bypass values differ under the mask.
- Values contain no bits outside the mask.
- Every update preserves bits outside the Flux mask.
- The Flux mask is disjoint from AOSP netd's `netId` field and any other Android/vendor fields discovered in active rules or device policy.
- The current legacy low-byte mask `0xff` is never accepted merely because it was previously configured.
- Observed Android/vendor rules are checked for overlapping semantics before activation.
- Engine outbound sockets receive an unambiguous bypass identity.
- IPv4 and IPv6 may share the same value only when route rules remain unambiguous.

### 8.3 Resource budgets

Default hard limits, configurable only within compiled maxima:

| Resource | Initial limit |
|---|---:|
| Normalized CIDRs | 65,536 per family |
| Android UIDs | 20,000 |
| nftables rules | 4,096 |
| xtables rules | 16,384 |
| ipset entries | 131,072 per family |
| eBPF map locked memory | 32 MiB |
| Control event queue | 256 |
| Netlink receive batch | 64 messages, dynamically bounded |
| Subscription download | 16 MiB |
| Subscription nodes | 10,000 |

Limits are starting values to be revised by device benchmarks. Exceeding a limit is a compile error, never silent truncation.

## 9. nftables specification

### 9.1 Ownership

- Dedicated table name in the reserved Flux namespace.
- All objects include Generation identity through names, userdata/comments where supported, or the durable manifest.
- No command shells and no dependency on an `nft` executable.

The final native Adapter has no `nft` dependency. The first implementation stage may use a packaged or verified `nft` binary through JSON/stdin as a separate Adapter and oracle; it must be fingerprinted, invoked without a shell, and replaced by the narrow native codec before the final helper-minimal architecture is declared complete.

### 9.2 Program shape

The exact hook priorities are selected only after collision observation, but the logical chains are:

- prerouting classification and TPROXY;
- output classification and marking for policy reroute;
- optional postrouting MSS handling;
- stable action chains;
- IPv4/IPv6 bypass interval sets;
- UID sets for local output;
- interface-name sets or verdict maps;
- counters keyed by decision reason where supported.

### 9.3 Transaction

Use `NFNL_MSG_BATCH_BEGIN` and `NFNL_MSG_BATCH_END`. Prefer complete replacement of the Flux-owned table in one batch. If a device rejects that pattern, use stable dispatch objects and an atomic verdict-map or jump replacement proven by an active probe.

Extended acknowledgements are captured and mapped to the specific generated operation.

## 10. xtables and ipset specification

### 10.1 Invocation

Rust spawns the discovered `iptables-restore`/`ip6tables-restore` binaries directly, passes `--noflush` and a bounded wait option, writes generated content to stdin, and captures stderr with a size limit.

Before selection, Flux detects whether each tool belongs to iptables-legacy, iptables-nft, a wrapper, or a vendor implementation. IPv4/IPv6 command and restore tools must form one coherent implementation and pass the exact canary. One Generation never mixes legacy and nft variants or manages the same policy through both.

### 10.2 Generation shape

- Stable entry chains are attached once.
- Generation chains contain the actual policy and reference only generation-specific sets.
- Activation updates stable jumps in one restore transaction per family/table.
- Cleanup removes exact generation chains only after no stable jump references them.

### 10.3 ipset

- Separate IPv4 and IPv6 `hash:net` sets.
- Create generation-specific target sets and populate an unreferenced temporary set.
- Optionally use `swap` to publish the fully populated contents into the generation-specific target name before any generation chain references it.
- Switch only the stable xtables jump at cutover; never swap contents under a set still referenced by the old Generation.
- Destroy retired generation sets only after their generation chains are unreferenced and removed.
- If create/add/swap semantics are not all verified, do not select ipset.

### 10.4 Bounded-tree fallback

Retain the current prefix-zone concept as a compatibility compiler, with hard depth and chain-count budgets. Canonicalized user CIDRs are permitted, but compiler estimates must reject pathological expansions.

## 11. Routing and address synchronization

All route/rule operations use rtnetlink from the daemon.

### 11.1 TPROXY routing

For each enabled family:

- one Flux-owned fwmark rule using the configured value/mask and validated priority;
- one local default route in the Flux table to loopback;
- address-derived higher-priority bypass rules for active local interface addresses where required by the selected topology;
- exact cleanup messages carrying the same attributes used to create objects.

Rule priority is allocated only after parsing the Android RPDB. With `respect_android_vpn = true`, the selected placement must preserve secure/lockdown VPN and per-UID network selection. A fixed legacy priority such as `2025` is not accepted without a proven device-specific policy.

Implementation checkpoint: `flux-core` now has a mutation-free address-bypass planner. It consumes one complete `NetworkInventory` plus an explicit caller-resolved per-family priority, lookup-table, and rule-protocol specification; it does not allocate those values or claim that numeric placement alone preserves Android VPN policy. The planner filters unusable, disabled-family, flag-matched, exact-address, and CIDR-matched facts; normalizes valid IPv4-mapped inputs; rejects mapped prefixes crossing the mapping boundary; deduplicates addresses across interfaces; and emits deterministic `/32` or `/128` destination-host intents under a fixed rule-count budget. The result is bound to both the source `NetworkEpoch` and an opaque process-local snapshot identity so an equal epoch from another observer cannot authorize later work. Selected-priority occupancy is audited against the ordered rule multiset with bounded diagnostics. Even an exact canonical `NetworkRuleRecord` remains an unowned conflict: canonical equality is not journal/raw ownership evidence, so adoption, retirement, native encoding, and cleanup remain deferred.

The versioned RPDB placement checkpoint adds a pure audit around that planner. An external classifier must provide exactly one ordered classification for every observed rule and explicit must-precede and terminal boundaries for each enabled family. A rule with semantically opaque attributes rejects placement in an enabled family before any caller classification is trusted; opacity in a disabled family remains outside that family-scoped lease. The audit otherwise admits a candidate only when `last must-precede < address bypass < Flux proxy < first terminal barrier`, both requested priority slots are empty, no GOTO edge intersects the candidate interval, and the proposed Flux-private table has no route or rule occupancy in that family. IPv4 and IPv6 admission is atomic, and the resulting process-local lease is bound to snapshot identity, epoch, and classifier revision; it can project only the address-bypass priorities targeting Linux table 254. This is placement evidence, not an Android VPN-safety or activation proof: classifier implementation, selector-overlap analysis, mark allocation, route reachability, boot and namespace binding, durable ownership, exact mutation identity, and contained device canaries remain required before native writes.

A third pure checkpoint now performs only the fwmark conflict analysis that current Rust evidence can honestly support. It validates one nonzero common mask with distinct nonzero proxy and bypass values, exposes masked-merge semantics that preserve every outside bit, and reports definite overlap with Android's low 16-bit `netId` field plus every ordered IPv4/IPv6 RPDB fwmark selector. Conflict evidence is bounded without changing the decision, and the report is bound to the exact inventory snapshot and epoch. Its RPDB source status becomes `Opaque` if any rule carries unmodeled attributes; this does not invent a collision, and known selector overlaps remain definite conflicts alongside the incomplete source state. There is intentionally no accepted outcome and no `MarkLease`: a conflict-free or semantically opaque RPDB report remains `Incomplete`, while device-qualified positive allocation authority, complete xtables/nftables and TC/BPF censuses, socket/connmark transfer semantics, other-instance ownership, boot and namespace identity, exact writer behavior, observer continuity, and activation canaries remain unavailable or deferred. Unobserved or opaque bits must never be treated as allocatable by taking the complement of current conflicts.

### 11.2 Network events

Subscribe to link, IPv4/IPv6 address, route, and rule groups required by the active plan. Use sequence-aware dump reconciliation after startup, overrun, receive truncation, or suspected event loss.

Do not enable `NETLINK_NO_ENOBUFS`; Flux needs loss notification. Dumps marked `NLM_F_DUMP_INTR`, lacking `NLMSG_DONE`, truncated, malformed, or sequence-inconsistent are invalid. A replacement dump may start immediately only when no request is active; otherwise Flux first stales the source and drains the owned sequence to terminal `NLMSG_DONE` or `NLMSG_ERROR`. If that terminal cannot be recovered by the drain deadline, network observation degrades for the current socket registration rather than overlapping requests.

Phase 3 first delivers this as a read-only `NetworkInventorySource`. The production Adapter subscribes before starting its initial dump, queues or compensates for events racing that dump, and publishes only a complete canonical snapshot. `MSG_TRUNC`, `ENOBUFS`, `NLMSG_OVERRUN`, malformed/ambiguous messages, interrupted dumps, missing completion, and mixed sequences invalidate all partial state and require a safely serialized full resynchronization. Only a materially different complete snapshot advances the monotonic `NetworkEpoch`. Netlink readiness is registered with the existing daemon reactor and processed under a bounded per-turn budget; no second epoll owner is permitted.

Implementation checkpoint: the current substrate publishes one canonical link/address/route/rule inventory from a strict `RTM_GETLINK` → `AF_UNSPEC RTM_GETADDR` → `AF_UNSPEC RTM_GETROUTE` → `AF_UNSPEC RTM_GETRULE` transaction on the already subscribed route-netlink socket. Each phase owns a fresh nonzero sequence and must reach its matching terminal response before the next request is sent; only RULE completion may replay transaction-wide LINK/ADDRESS races and publish one `NetworkEpoch`. Links and addresses remain canonical sets, while routes and rules retain exact validated dump order and multiplicity. The link decoder preserves raw names and link kinds through the netlink wire bound, unknown flags/types/states, extended dump acknowledgements, and whole-datagram loss semantics; partial live link notifications preserve optional fields omitted by the kernel. Receive slots are 256 KiB with a 1 MiB default turn budget; 256 KiB is an operational bound rather than a protocol-wide maximum, so truncation remains a mandatory full-resync signal.

The route inventory uses canonical IPv4/IPv6 route prefixes, raw-preserving route properties, gateways, nexthops, paths, and records plus a strict private `RTM_NEWROUTE`/`RTM_DELROUTE` decoder. It validates table encoding, family-sized addresses, prefix host bits, multipath framing, deferred nested attributes, dump metadata, and loss signals while preserving `NLM_F_REPLACE`, named-nexthop IDs, unknown route values, duplicate records, dump order, and wire-order multipath weights. Omitted metrics, encapsulation, flow, and new-destination semantics still make each record a topology/selection projection rather than an exact route identity; NH-ID-only paths still require nexthop-object observation or a compatibility-mode gate. Consequently route notifications received before `GETROUTE` are subsumed by that later dump, while any route notification after the route-dump cutoff taints the transaction and forces a fresh full dump instead of attempting an ambiguous live replacement or deletion. Core constructors enforce semantic and family canonicality, not single-message rtnetlink encodability; future mutation encoders must enforce their exact attribute and message-size budgets.

The current rule foundation defines canonical IPv4/IPv6 policy-rule records plus a strict private `RTM_NEWRULE`/`RTM_DELRULE` decoder. It preserves raw action, origin-protocol, and rule flags; decodes table, priority, input/output interfaces, GOTO, fwmark/mask, tunnel ID, suppressors, L3MDEV, UID range, IP protocol, port ranges, and IPv4 flow/class ID; and validates the Linux 5.10 mandatory dump attributes, zero reserved header fields, family-sized prefixes, compact/extended table agreement, scalar widths and endianness, interface termination, range domains, repeatable padding, dump metadata, and loss signals. IPv6 `FRA_FLOW` follows the kernel's liberal ignored-input behavior and does not become a rule fact. Well-framed unknown `FRA_*` attributes do not disappear: the record becomes semantically opaque, retains the first eight ordered type/flag/payload-length descriptors and an omitted count, and carries a SHA-256 fingerprint over every opaque attribute's type, flags, length, payload, order, and multiplicity. The digest is bounded change evidence for inventory identity, not raw mutation identity, ownership, or deletion authority. Unknown actions and flags remain observable rather than being rejected.

These records are semantic selection projections: prefix host bits and fwmark bits outside the mask are normalized, so future mutation requires a separate raw kernel identity. Linux fib rules do not implement replacement through `NLM_F_REPLACE`, and equal-priority or duplicate rules are valid, so the inventory retains rule dump order and multiplicity instead of using a priority map or record set. Rule notifications before `GETRULE` are subsumed by that later dump; once RULE is active, any rule notification taints the transaction and triggers a full resynchronization rather than inventing an insertion position or deletion identity. Native kernel rule identity and mutation remain pending.

The route and rule requests are exact 28-byte `nlmsghdr` plus zeroed 12-byte `rtmsg` or `fib_rule_hdr` messages carrying `NLM_F_REQUEST | NLM_F_DUMP`, a unique nonzero sequence, kernel-selected port ID, and no filter attributes. Byte-exact endian tests and a sequential real-kernel smoke cover all four phases on one socket and fixed receive ring. If best-effort strict dump checking is unavailable, a zero `GETROUTE` request may also return cloned exceptions; the route decoder fully validates and then filters `RTM_F_CLONED` records. Any fault during an active dump immediately stales the public source but retains a bounded dirty-drain state for that owned sequence. A minimal raw envelope preserves terminal `NLMSG_DONE`/`NLMSG_ERROR` evidence across semantic decode failures and intact kernel-response slots in an otherwise lossy receive batch, so a fresh LINK request is not overlapped with an unfinished dump. Missing terminal evidence through the drain deadline is a permanent observation failure for the current socket registration; it invalidates the source and degrades only network observation rather than risking an overlapping request.

The existing `addrsyncd` batching, acknowledgement classification, debounce maximum, bounded maintenance work, and compensating resync behaviors are ported into this owner rather than called as a subprocess.

## 12. TUN specification

### 12.1 Ownership split

- `EngineOwnedTun` is the first shipping plan: Sing-Box owns packet-stack processing, interface creation, queue FDs, and packet I/O. Flux owns policy compilation, route/rule lifecycle, exact link-identity verification, optional Flux-owned tc qdisc/filter leases on that Generation-scoped link, loop prevention, and recovery.
- `FluxOwnedTunFd` is a future plan and is eligible only when the exact Sing-Box version exposes a documented, version-tested FD-handoff contract. Only this plan permits Flux queue workers, queue-count control, `io_uring`, `TUNSETSTEERINGEBPF`, or direct offload negotiation. `TUNSETFILTEREBPF` remains deferred even under this ownership model. TC attachment to the verified netdevice is a separate link-level capability and does not require queue-FD ownership.
- Flux's direct TUN ioctl support is required for contained probes even when the active plan is engine-owned.
- Android probes `/dev/tun` first, then `/dev/net/tun` for non-Android Linux compatibility.

### 12.2 Activation order

For `EngineOwnedTun`, disabling Sing-Box route automation is a required Engine Capability. Reload uses a bounded stop/swap window because the old and candidate child cannot be assumed to coexist on a fixed interface:

1. Render, validate, and preflight the candidate plus every non-binding Flux operation.
2. Persist `Activating`, detach old TUN capture/routes into a bounded fail-open bypass, and record the outage start.
3. Stop the old child and wait for its owned TUN to disappear.
4. Start the candidate, wait for the exact interface, and verify name, ifindex, addresses, MTU, and selected stack.
5. Install the candidate's loop-prevention and capture routes/rules.
6. Verify representative IPv4/IPv6 routing and DNS behavior.
7. Publish `Active` only after verification.
8. On failure, stop the candidate, restart the previous known-good config, restore its recorded routes/rules, and report outage and rollback results. If rollback fails, remain clean fail-open.

### 12.3 Offloads

In `EngineOwnedTun`, multiqueue, GSO, checksum, and stack behavior are version-qualified Sing-Box features and Flux reports the selected evidence but does not touch queue FDs. Direct offload negotiation belongs only to `FluxOwnedTunFd`, where each feature has a separate end-to-end capability state.

## 13. eBPF specification

### 13.1 Map ABI

Shared Rust `#[repr(C)]` types live in `flux-ebpf-common` and contain no pointers or platform-sized integers.

Candidate maps:

```rust
ConfigMap: Array<u32, BpfGenerationConfig>
UidPolicy: Hash<UidKey, PolicyDecision>
Prefix4: LpmTrie<Ipv4LpmKey, PolicyDecision>
Prefix6: LpmTrie<Ipv6LpmKey, PolicyDecision>
FlowCache: LruHash<FlowKey, FlowDecision>
Counters: PerCpuArray<DecisionReason, CounterPair>
Events: RingBuf<SampledEvent> | PerfEventArray<SampledEvent>
```

All map sizes are calculated by the Generation Compiler and checked against the memory budget before load.

### 13.2 Generation safety

Old and new program sets share a small control map. Each program has an immutable expected Generation and reads the BPF active-policy selector plus the selected per-generation policy-map slot. Userspace populates the new maps, attaches every new program in dormant/pass-through mode, and then performs one control-map update selecting the new BPF policy slot. New programs accelerate only on a match; old programs immediately pass through and are detached afterward. This internal selector update does not publish the authoritative `GenerationRecord` or modify `active.json`.

When shared-map reuse or concurrent attachment cannot be proven, Flux detaches/re-attaches acceleration non-atomically while nftables/xtables/TUN remains the complete correctness path.

On the 5.10 correctness stack, the only general BPF-to-netfilter bridge is a masked Flux mark. TC ingress may stamp a verified decision before PREROUTING for forwarded/tethered traffic, and nftables/xtables may match that mark. TC egress occurs after local OUTPUT and is not claimed to accelerate that classification path. No backend assumes it can read Aya maps directly.

Only `FluxOwnedTunFd` may attach a socket-filter steering program through `TUNSETSTEERINGEBPF`. `TUNSETFILTEREBPF` is deferred because a zero return drops traffic and there is no automatic distinction between a program bug and an intended filter decision.

### 13.3 Attachment

- Prefer `bpf_link` ownership when probed.
- Legacy tc attachment uses a private qdisc/filter identity and exact cleanup.
- Default tc attachment is limited to a verified Generation-scoped TUN netdevice, whether its queue FDs are engine-owned or Flux-owned. Flux must own a collision-checked qdisc/filter identity, revalidate link identity after recreation, and remove only that lease. Physical interfaces require an experimental opt-in because AOSP netd can delete `clsact` qdiscs on startup and tethering offload may use the same path.
- Physical-interface experiments observe netd lifecycle, verify attachment after every Network Epoch, and immediately demote on qdisc/filter conflict.
- Never replace or multi-attach to Android's root cgroup hooks by default. A Flux-owned child cgroup covers Flux/Sing-Box processes only; arbitrary Android-app coverage on an Android-owned cgroup is a separate experimental coexistence plan.
- Detach or userspace death must leave the correctness Capture Path intact.
- `BPF_PROG_TYPE_NETFILTER` is eligible only on parsed kernel 6.4+ and a successful real hook probe.
- TCX is eligible only on parsed kernel 6.6+ and a successful attach/query/detach probe; legacy TC remains the fallback.

### 13.4 Telemetry

- Counters are polled in batches at a configurable interval.
- Ring-buffer events are exceptional/sampled, never one per packet, and require create/mmap/epoll/overflow probes.
- A perf-event-array Adapter is the event fallback; if neither works, sampled events degrade off while map counters remain available.
- Payloads exclude raw application data and secrets.
- Verifier logs are bounded and stored only for failed loads or explicit diagnostics.

## 14. Sing-Box supervision

```rust
struct EngineIdentity {
    pid: NonZeroU32,
    start_time_ticks: u64,
    binary_digest: Digest,
    version: EngineVersion,
    generation: GenerationId,
}
```

Rules:

- validate the binary hash against `manifest.json` when a populated manifest is present;
- query and parse version before config rendering;
- select config fields through a version capability table;
- treat Clash API as optional telemetry/selector control, not authoritative process reload;
- do not implement a generic Clash API relay; when enabled, require loopback binding and a generated credential, and map only supported status/selector actions into typed Flux authorization;
- in TPROXY mode, support a candidate child on a generation-specific port and switch capture only after readiness;
- use a child handle and pidfd when supported;
- never signal a process based only on a PID file;
- cap restart bursts and enter fail-open repair after the limit;
- treat port/TUN presence as one readiness signal, not full health;
- keep engine logs separate but correlated by Generation.

Delivered Phase 1 supervision additionally requires:

- a strict engine manifest no larger than 16 KiB, with no unknown, duplicate, malformed, missing, or mode-inappropriate fields;
- startup and stop timeout fields in `1..=60000` milliseconds;
- SHA-256 identities for the exact binary, configuration, and optional BusyBox launcher;
- descriptor-pinned `sing-box check` and `run`, followed by a rehash of the same descriptors before readiness acceptance;
- PID plus `/proc` start-tick identity before every signal and child-owned listener/TUN readiness evidence;
- a direct-child `PR_SET_PDEATHSIG(SIGKILL)` lease with a post-arm parent-identity race check for Sing-Box and phase-shell processes;
- bounded TERM/KILL/reap, restart windows, exponential backoff, and retained ownership until disappearance is observed.

The Phase 1 transaction orders start as `prepare` → engine admission → generation-bound capture start → structural capture verification → generation-bound `RUNNING`, and stop as capture detach → engine stop/reap → `STOPPED`. Partial capture-start compensation retains generation evidence until both networking writers prove cleanup; terminal publication and engine retirement are forbidden while detachment is uncertain. Reload prepares the candidate while the previous generation remains active, blocks replacement if detach fails, and attempts the previous immutable `EngineSpec` if candidate activation fails. An uncertain reload detach enters capture repair: prove full detachment, retain/reconcile the old engine, then republish and reverify that generation. Publication failure after successful verification retains the runtime, but maintenance performs a fresh generation-bound capture verification before retrying `RUNNING`. The current structural capture check is not a synthetic traffic/loop-prevention proof.

The parent-death lease is deliberately described as direct-child containment, not process-tree containment. Linux does not inherit `PDEATHSIG` across `fork`, and clears it when a later `setuidgid` transition changes effective or filesystem credentials. Direct-launch Sing-Box therefore supports automatic same-boot restart recovery. A crashed `busybox-setuidgid` generation is handled conservatively: startup recovery detaches capture, publishes `FAILED`, preserves the Rust ownership lease and active generation evidence, and refuses automatic daemon restart because stale child death cannot be proven. Phase descendants remain outside the direct-child guarantee. Full crash-time coverage requires a post-credential Rust launcher plus a verified Flux-owned process-cgroup containment design; those are deferred hardening and must be proven on Android before the broader guarantee is claimed.

## 15. Generation journal

### 15.1 Record

```rust
struct GenerationRecord {
    schema: u16,
    id: GenerationId,
    phase: GenerationPhase,
    desired_digest: Digest,
    capability_profile_revision: CapabilityProfileRevision,
    engine_profile_revision: EngineCapabilityProfileRevision,
    engine_binary_digest: Digest,
    backend_plan: BackendPlan,
    engine: Option<EngineIdentity>,
    managed_objects: Vec<ManagedObjectRecord>,
    previous: Option<GenerationId>,
    created_at: SystemTime,
    updated_at: SystemTime,
}

enum GenerationPhase {
    Prepared,
    Activating,
    Active,
    Retiring,
    Retired,
    Failed,
}
```

### 15.2 Persistence protocol

1. Write to a new file in the target directory.
2. `fsync` the file.
3. Rename over the target.
4. `fsync` the directory.

`active.json` points to or contains the active record digest. Startup validates checksums and scans the most recent generation files if the pointer is corrupt.

`active.json` is updated only after mandatory engine and kernel verification. `Prepared` and `Activating` records may exist without becoming authoritative.

The journal records intent and ownership; recovery always confirms kernel reality before acting.

### 15.3 DNS, fake-IP, and asset state

Durable state is separate from the kernel-object journal but referenced by Generation digest:

```rust
struct DnsStateRecord {
    schema: u16,
    policy_digest: Digest,
    engine_version: EngineVersion,
    fake_ip_state_digest: Option<Digest>,
    reverse_mapping_digest: Option<Digest>,
}

struct AssetRecord {
    content_digest: Digest,
    source: RedactedSourceId,
    format: AssetFormat,
    validated_by: EngineVersion,
    previous_known_good: Option<Digest>,
}
```

Fake-IP/cache state is versioned, atomically persisted, and either migrated or deliberately flushed on incompatible policy/schema change. Corrupt state is quarantined and falls back to an empty validated cache rather than blocking direct connectivity. Rule-set/subscription assets are content-addressed, validated before publication, retain a known-good predecessor, and are never erased by a failed refresh. Each Generation records the exact asset and DNS-state digests it expects.

## 16. Error model

Stable top-level categories:

```rust
enum ErrorCode {
    UnsupportedKernel,
    CapabilityUnsupported,
    CapabilityDenied,
    ConfigurationInvalid,
    EngineInvalid,
    EngineUnhealthy,
    BackendCompileFailed,
    KernelMutationFailed,
    KernelDrift,
    OwnershipConflict,
    ResourceLimit,
    Timeout,
    RecoveryFailed,
    InternalInvariant,
}
```

Every `ErrorReport` includes:

- code and human message;
- operation and Generation ID;
- backend/capability context;
- errno, netlink extack, command status, or verifier excerpt when applicable;
- whether state was mutated;
- compensation result;
- recommended user action;
- a redacted diagnostic correlation ID.

## 17. Event and reconciliation semantics

### 17.1 Event sources

```rust
enum RuntimeEvent {
    ConfigChanged,
    AdministrativeStateChanged,
    NetworkChanged(NetworkEvent),
    PackageInventoryChanged,
    EngineExited(ExitStatus),
    HealthTick,
    SubscriptionDue,
    Control(ControlRequest),
    KernelDriftDetected,
}
```

### 17.2 Coalescing

- Config and package changes are debounced.
- Multiple netlink events merge into one pending Network Epoch update.
- Engine exit bypasses normal debounce.
- Disable/shutdown cancels uncommitted work and has priority.
- A bounded maximum debounce guarantees eventual convergence during continuous address churn.

### 17.3 Idempotence

If the compiled digest and observed managed-object digest equal the active Generation, reconciliation performs health verification only and returns `NoChange`.

The Phase 1 serialized worker calls `maintain` after each request and after bounded idle timeouts. Maintenance advances pending child reap/backoff without spawning a second child, detaches capture after abnormal exit or uncertain mutation, restarts only after supervisor admission, restores and structurally verifies capture, and freshly re-verifies the matching generation before retrying pending `RUNNING`; `STOPPED` and `FAILED` retries occur only after capture is proven detached. Shutdown uses bounded retries of the same detach-before-stop ordering.

## 18. Kernel I/O runtime

The mandatory target baseline is one custom `epoll` reactor derived from the current `addrsyncd` design. Phase 1 currently integrates the control descriptor and shutdown `signalfd`; nonblocking route/netfilter netlink sockets, timerfd, pidfds, child pipes, and pollable BPF buffers remain later work. It owns TUN queue FDs only in a future `FluxOwnedTunFd` plan; in `EngineOwnedTun`, packet I/O stays entirely inside Sing-Box. Handlers drain bounded batches to `EAGAIN` and yield after a work budget.

Higher-level async tasks communicate through bounded channels. `io_uring` is a separate `FluxOwnedTunFd` TUN I/O Adapter selected only when the FD-handoff contract, `io_uring_setup`, required opcode probes, cancellation, a real TUN read/write smoke test, policy permissions, and device benchmarks all succeed.

## 19. Packaging and build

### 19.1 Build outputs

- `fluxd` for `aarch64-linux-android`;
- eBPF object(s) embedded in `fluxd` or packaged with verified hashes;
- Sing-Box binary supplied by the release pipeline;
- generated `manifest.json`, SBOM, checksums, and build metadata;
- Magisk-compatible ZIP.

### 19.2 `xtask`

Required commands:

```text
cargo xtask build-android
cargo xtask build-ebpf
cargo xtask test-linux
cargo xtask package-magisk
cargo xtask verify-package
cargo xtask device-test --serial <adb-serial>
```

The packaging task fails if binary source, version, target, hash, license, or required device-test evidence is missing.

## 20. Compatibility and removal schedule

| Release stage | Runtime behavior |
|---|---|
| Bridge | `fluxd` owns Sing-Box through the atomic runtime coordinator; serialized shell phases still own networking writes and expose separate control/runtime status |
| Legacy parity | `fluxd` owns xtables/PBR/address sync; updater may still use external curl/jq adapters |
| New backends | nftables, ipset, managed TUN, and eBPF observation available behind capability gates |
| Default switch | `auto` prefers nftables where conformance passes |
| Cleanup | standalone `addrsyncd` and runtime policy scripts removed; wrappers retained |

No compatibility stage may have two independent owners mutating the same kernel objects.

Open Phase 1 hardening gates are a stronger functional traffic/loop-prevention probe, ancestor-safe `openat`/`openat2` traversal, bounded rotating Generation-correlated logs, pidfd/timerfd reactor integration, and real-device evidence on Android kernel 5.10.
