# Fluxd Technical Specification

- Status: accepted living specification
- Last updated: 2026-07-16
- Companion document: [Fluxd Rewrite Blueprint](fluxd-blueprint.md)

This specification describes both the target architecture and temporary development checkpoints.
ADR-0011 controls publication: bridge, shadow, parity, and migration states are not releasable, and
obsolete internal contracts may break when that accelerates the full Rust cutover. A final package
contains no legacy runtime networking component or compatibility wrapper.

## 1. Supported platform contract

| Item | Contract |
|---|---|
| Operating system | Android/Linux; Android is the release target |
| Kernel | `>= 5.10`; older versions settle the daemon into read-only `UnsupportedKernel` before mutation |
| Primary architecture | `aarch64-linux-android` |
| Secondary CI architecture | `x86_64-unknown-linux-gnu` for host/integration tests |
| Development Android test architecture | `x86_64-linux-android`; checkpoint-only, never packaged or release-qualified |
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
fluxd recover --offline
fluxd cleanup --offline
# optional, only if it does not delay cutover:
fluxd migrate --check-only
```

The target-state `fluxctl` is a symlink/hardlink or direct multicall entry into the same Rust binary;
it is not a policy-bearing shell compatibility wrapper. In the delivered pre-release Phase 1
bridge, the temporary shell wrapper delegates authoritative status and every mutating control to
`fluxd`, while `diagnose`, rule preview, logs, and other compatibility observations still use
legacy read-only paths. That wrapper and those paths are removed as their Rust call sites land.

Only `fluxd daemon` is long-lived. Sing-Box is its child. A boot shell watchdog may restart `fluxd` after a crash or fatal invariant exit, but it contains no policy logic, never invokes a second recovery owner, and does not restart a settled `UnsupportedKernel` daemon. Normal journal recovery runs inside daemon startup before mutating commands are accepted. `fluxd recover --offline` is an explicit salvage command that requires the daemon lease to be absent. The legacy `fluxctl restart` verb is a client alias for `ReloadSources` followed by `Converge(Configured)`; it has no separate protocol or lifecycle meaning.

In the delivered Phase 1 bridge, `RuntimeCoordinator` implements `LegacyDispatcher` and runs on the one bounded `LegacyControlBridge` worker. The worker serializes requests, address resynchronization, idle maintenance, and shutdown. `EngineSupervisor` owns the Sing-Box child. Rust-owned preparation compiles the legacy restore caches, but shell phase scripts remain the only rules/routes/address-sync writer and `scripts/tproxy` remains the sole restore executor. A boot-scoped mode lease rejects legacy `scripts/core` verbs for the duration of a Rust-owned engine run. This bridge currently admits only TPROXY: `prepare` rejects `PROXY_MODE=tun` before initialization and manifest publication because the shell Flux PBR is TPROXY-specific and exact Sing-Box route cleanup after forced death has no device-qualified proof.

## 3. Local control socket and Module routing

The control socket is `/data/adb/flux/run/fluxd.sock`, Unix `SOCK_SEQPACKET`, protocol version 3. Version 2 introduced the coherent boot-scoped Capability Profile; version 3 adds a required orthogonal runtime-verification field. Version-1 and version-2 requests are rejected explicitly rather than decoded against the new response shape.

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
    // Optional build/API surface for already published legacy settings only.
    Migrate { write: bool },
}
```

The socket router is not the Controller Module. `ControllerWireCommand` maps to the selected `submit` Interface; `InspectCommand` maps to `snapshot`/`watch`; maintenance commands are dispatched to separate capability, planning, subscription, diagnostics, optional migration, or recovery Modules with their own authorization and failure contracts. The migration variant is omitted from the first release if implementing it would delay the Rust-only cutover.

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

Phase 1 status returns `control` and `runtime` separately. `ControlSnapshot` describes desired/control progress. `RuntimeSnapshot` is an independently revisioned observed projection containing runtime phase, capture state, engine state, verification state, generation, and an optional bounded operation/message/recovery failure. Verification is required on the version-3 wire shape and is one of `structural_only`, `functional_pending`, `functional_passed`, or `functional_failed`. `structural_only` is the conservative no-functional-authorization baseline rather than proof that structural verification has completed. A functional pass is bound to the exact current Generation, engine, environment, and successful `RUNNING` publication; publication failure, identity loss, address resynchronization, restart, repair, or rollback invalidates it until a fresh gate succeeds. Clients must not infer observed health solely from administrative intent, request completion, runtime phase, or verification state in isolation. The current pre-release Phase 1 composition remains structural-only and Android-unqualified.

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

enum MarkPolicy {
    Auto,
    Explicit { mask: u32, proxy_value: u32, bypass_value: u32 },
}

enum RoutingPolicy { Auto }

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
    planning_evidence: PlanningEvidenceReceipts,
    engine_binary_digest: Digest,
    backend_plan: BackendPlan,
    engine_config: EngineConfigArtifact,
    capture_program: CaptureProgram,
    route_program: RouteProgram,
    ebpf_program: Option<EbpfProgramSpec>,
    resource_budget: ResourceBudget,
    invariants: Vec<GenerationInvariant>,
}

struct AndroidMarkPlanningReceipt {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    policy_digest: Sha256Digest,
    policy_revision: PolicyRevision,
    candidate: MarkCandidate,
    topology: TopologyScopeIdentity,
    inventory_epoch: NetworkEpoch,
    inventory_snapshot: NetworkInventoryIdentity,
    complete_census_observation_id: CompleteFwmarkCensusObservationId,
    canonical_census_digest: Sha256Digest,
    census_collector_revision: CensusCollectorRevision,
    ownership_journal_identity: OwnershipJournalIdentity,
    ownership_journal_revision: OwnershipJournalRevision,
    capability_profile_revision: CapabilityProfileRevision,
    boot_id: BootId,
    network_namespace: NetworkNamespaceIdentity,
}

struct PlanningEvidenceReceipts {
    android_mark: Option<AndroidMarkPlanningReceipt>,
}
```

`GenerationArtifact` is the deterministic, digest-bearing compiler output. Capture, route, and eBPF programs inside it use logical Managed Object keys rather than concrete kernel names. The Controller assigns the `GenerationId` only after successful compilation, and adapters derive bounded concrete names deterministically from that ID during preparation; creation/update timestamps belong to `GenerationRecord`, not the artifact. All numeric kernel identifiers use validated newtypes. Generation IDs use a monotonic local sequence plus an artifact-digest prefix; correctness does not depend on wall-clock uniqueness.

`PlanningEvidenceReceipts` contains no authority or mutation capability. A mark-dependent domain plan
requires the compiler to consume a fresh `AndroidMarkPlanningAuthority` and retain the resulting
receipt; a plan containing no mark reads, writes, or transfers records that mark authority was not required. Activation rechecks
the receipt's exact boot, namespace, inventory, catalog, census, and ownership facts and still needs
a separate activation lease.

### 4.5 Shadow Capture Artifact

The completed and frozen Phase 2 tracer bullet emits an artifact class distinct from a Generation.
A shadow Capture artifact contains only a semantic version, deterministic digest,
bounded resource accounting, explicit compatibility assumptions/deferred prerequisites, and
separate ordered local-OUTPUT and forwarded-ingress programs over already typed and resolved
inputs. It performs no discovery or I/O.

This artifact is observation-only and is never implicitly promoted to the type in section 4.4. It
has no Generation ID, Capability/Engine Profile planning lease, Planning Authority or receipt,
Backend Plan, route/mark program, Managed Object key or kernel name, writer/ownership token,
prepared/active conversion, journal record, or Runtime Coordinator/Reconciler entry point. Its
digest is domain-separated from a Generation Capture Program digest and cannot satisfy a
functional-canary request. No production API treats it as a packet-decision service.

The separate Phase 4 xtables lowerer may consume this artifact together with a caller-supplied
non-authorizing namespace, structurally valid TPROXY target, optional descriptive local-routing
targets, explicit extension state, and command budget. Forwarded-only input preserves the frozen
schema-v1 result; local-OUTPUT input selects pure schema v2 and adds the separate loopback
PREROUTING companion plus typed listener/routing/escape and lifecycle metadata. That operation does
not add authority or runtime state to the source artifact, attach either hook, or prove delivery to
the TPROXY listener.

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
allocation = "auto" # auto | explicit
# mask = "0x..."         # required only for explicit
# proxy_value = "0x..."  # required only for explicit
# bypass_value = "0x..." # required only for explicit

[capture.routing]
allocation = "auto"

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

For marks, `auto` asks the planner to derive a candidate; it does not create authority or promise that a candidate exists. `explicit` requires every commented mark value and supplies only a candidate subject to the same conflict, freshness, ownership, and activation gates as `auto`. It is not an expert override. The legacy mark values (`0x14`, `0x19`, `0x11` under mask `0xff`) are imported only as explicit compatibility candidates. Generic AOSP grants Flux no mark field, so neither a new-installation `auto` request nor an explicit value may become a TPROXY mark plan without a matching device-qualified positive assertion and complete live evidence.

Routing currently admits only `allocation = "auto"`, meaning topology-qualified candidate derivation rather than a promise of success. A singular explicit table/priority schema is deliberately deferred: one atomic Traffic Scope retains per-anchor intervals and may have no common priority across residual-local and tether domains. The legacy table/priority `2025` is therefore a migration diagnostic, not a native routing candidate, until the next Phase 3 slice defines the per-domain realization contract.

## 6. Capability Profile

### 6.1 Record format

```rust
struct DeviceIdentity {
    android_product: AndroidProductIdentity,
    android_build: AndroidBuildIdentity,
    vendor_build: VendorBuildIdentity,
    security_patch: SecurityPatchLevel,
    verified_boot: VerifiedBootIdentity,
    kernel_build: KernelBuildIdentity,
    selinux_policy: SelinuxPolicyIdentity,
    netd: ArtifactIdentity,
    connectivity: ArtifactIdentity,
    tools: BTreeMap<ToolId, ArtifactIdentity>,
    network_namespace: NetworkNamespaceIdentity,
}

struct ReviewedPolicySelector {
    android_product: AndroidProductIdentity,
    android_build: AndroidBuildIdentity,
    vendor_build: VendorBuildIdentity,
    security_patch: SecurityPatchLevel,
    kernel_build: KernelBuildIdentity,
    selinux_policy: SelinuxPolicyIdentity,
    netd: ArtifactIdentity,
    connectivity: ArtifactIdentity,
    tools: BTreeMap<ToolId, ArtifactIdentity>,
}

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
    Conflicting,
    Broken,
    Unknown,
}

enum ProbeAttemptOutcome {
    Success,
    TransientFailure { retry: RetryPolicy },
    StableFailure,
}
```

The target record includes exact device identity, but the delivered `CapabilityProfile` model is
currently narrower: it binds boot identity, kernel facts, SELinux state, and the legacy bridge, but
not exact Android product/build/vendor identity or the selected netd/Connectivity artifact. A
production positive mark-policy loader therefore remains blocked until those facts enter the full
freshness-bound profile. Production assertions are selected from a compile-time reviewed policy
catalog keyed by `ReviewedPolicySelector` and an externally reviewed artifact digest/revision. The
selected assertion is then freshness-bound to the full Capability Profile, verified boot, boot ID,
and observed network namespace. Runtime-only boot/namespace identities are never literal catalog
keys. Parsing an arbitrary runtime manifest and hashing its own bytes must not create a
device-qualified grant.

`CapabilityStatus` records durable availability. Timeout, interruption, temporary resource
pressure, and other retryable failures are retained as `ProbeAttemptOutcome` evidence with bounded
backoff; they do not create a durable `Transient` capability state.

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
| `xt_bpf` | first prove the match is built in or already active without triggering `request_module`; then create/update required maps, load and pin the exact socket-filter programs, reference them with the selected iptables revision-1 `--object-pinned` extension in private IPv4/IPv6 OUTPUT/PREROUTING canary chains, send packets, validate UID/context/counters including ambiguous `overflowuid`, remove rules before unpinning, and verify cleanup |
| ipset | create, populate, swap, and destroy temporary family-specific sets |
| TUN | open device, create unique non-persistent interface, query flags, close, verify removal |
| eBPF map types | create each required map type and close it |
| eBPF program types | load minimal program and capture verifier output |
| eBPF attach points | inventory existing programs and flags, then attach/query/detach a harmless program at the exact intended hook without replacing an unknown owner |
| Cgroup hierarchy | identify the intended proxy-child cgroup and every ancestor to the root, query every requested attach type and flags, and prove that no ancestor blocks the child hook before attaching |
| BTF/CO-RE | open BTF and load a relocation-dependent probe program |
| BPF ring event transport | create, mmap, epoll, submit/consume, and overflow-test ringbuf; otherwise probe perf-event-array fallback |
| TUN eBPF steering | only for a Flux-owned TUN FD contract: load socket-filter canary, attach with `TUNSETSTEERINGEBPF`, verify queue selection, detach |
| io_uring TUN I/O | only for a Flux-owned TUN FD contract: setup, opcode/cancel probes, real packet read/write, and benchmark |
| pidfd | open pidfd for self/child and poll it |
| Unix seqpacket/peer credentials | local socket pair and credential read |

Probe objects carry an RAII cleanup guard. A process crash may still leave kernel objects, so boot recovery scans only the reserved probe namespace and removes objects whose owner PID/boot ID is stale.

### 6.4 Engine Capability Profile

Before Generation compilation, Flux queries and validates the exact Sing-Box binary and builds an `EngineCapabilityProfile` containing an immutable revision, binary digest, parsed version/build identity, supported configuration dialect, TPROXY listener staging, TUN route-automation control, `system`/`mixed`/`gvisor` stacks, mark/interface controls, DNS fields, reload behavior, any documented FD-handoff contract, and any authoritative supervised delivery-report producer. A report capability is positive only when it binds the exact producer process, transport and framing, schema revision, sequence/loss behavior, attempt-owned object lifecycle, and shutdown/cleanup semantics to that immutable engine artifact; ordinary logs, management APIs, or observed proxy success are not assumed to satisfy it. The planner rejects plans whose engine requirements are not proven even when the kernel path is available.

Every `CompiledGeneration` records both the device `CapabilityProfileRevision` and the `EngineCapabilityProfileRevision` used by the planner. A boot change, runtime capability demotion, Sing-Box binary replacement, or engine-profile refresh invalidates the planning lease: Flux must recompile or explicitly prove that the active Generation's requirements are still satisfied before repairing or reactivating it.

### 6.5 Preloaded Kernel Extension Profile

Production Flux does not load or unload kernel modules. If a reviewed OEM/custom-kernel extension is
already active, an optional `KernelExtensionProfile` may describe it without promoting it to a
general fallback:

```rust
struct KernelExtensionProfile {
    revision: KernelExtensionProfileRevision,
    boot_id: BootId,
    namespace: NetworkNamespaceIdentity,
    device: DeviceIdentity,
    kernel_kmi: KernelKmiIdentity,
    owner: KernelExtensionOwner,
    live_identity: KernelExtensionLiveIdentity,
    source_digest: Sha256Digest,
    signer: Option<SignerIdentity>,
    protocol: GenericNetlinkProtocolIdentity,
    semantics: KernelExtensionSemantics,
    canary: CapabilityEvidence,
}
```

The control handshake resolves the family through Generic Netlink control, validates kernel sender,
sequence, command, reserved fields, and strict attributes, and exchanges a nonce plus expected
protocol/boot/namespace for origin and correlation. Echoed identity fields are claims, not
authentication. Acceptance requires independently observed AVB/module-signature/measurement or
other reviewed platform evidence matching the catalog, followed by a nonpersistent behavioral
canary. Until a concrete partner contract and superseding ADR define a passive-by-default,
Generation-leased, expiring fail-open mechanism, this profile is read-only observation/diagnostic
evidence and is not referenced by `BackendPlan` or `GenerationArtifact`. Flux never unloads an
extension it did not load, and production Flux loads none.

## 7. Backend Plan

```rust
struct BackendPlan {
    domains: Vec<DomainBackendPlan>,
    tun: Option<TunBackendPlan>,
    ebpf: EbpfPlan,
    degraded: Vec<DegradedFeature>,
    rejected: Vec<RejectedBackend>,
}

struct DomainBackendPlan {
    domain: TrafficDomain,
    capture: CaptureBackend,
    address_sets: AddressSetBackend,
    routing: RoutingBackend,
    coverage: DomainCoverageProof,
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
    RtnetlinkInputInterfaceLocal,
    RtnetlinkTun,
}

enum EbpfMode {
    Off,
    Observe,
    Accelerate,
}

struct EbpfPlan {
    requested: EbpfMode,
    roles: Vec<EbpfRolePlan>,
}

struct EbpfRolePlan {
    domains: TrafficDomainSet,
    mechanism: EbpfMechanism,
    role: EbpfRole,
    attachment: AttachmentLeasePlan,
    fallback: ConventionalFallbackProof,
}

enum EbpfMechanism {
    XtBpfMatcher,
    TunTc,
    ProxyChildSockOps,
    PhysicalTcExperimental,
    TcSocketAssignExperimental,
    NetnsSkLookupExperimental,
    ListenerReuseportFuture,
    NetfilterBpfExperimental,
    TunSteering,
}

enum EbpfRole {
    Observe,
    ProxyPositive,
    FlowCache,
    MaskedMarkAcceleration,
    SocketAssign,
    ListenerSelect,
    QueueSteering,
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

Planning is two-stage. `enumerate_generation_candidates(...)` returns a bounded ranked set of
non-authorizing syntactic/topology candidates. `compile_generation(candidates, evidence, selection)`
takes a bounded candidate-keyed `PlanningEvidenceSet` by value so a selected non-`Clone` authority
is actually consumed; each candidate retains the exact Capability Profile, Engine Capability
Profile, inventory, and topology identities used during enumeration.

Candidate enumeration:

1. Reject kernel `< 5.10`.
2. Normalize explicit user preferences.
3. Derive hard requirements from Traffic Scope: local apps, tethered traffic, IPv6, per-app policy, UDP, DNS, Android VPN semantics, and fail policy.
4. Partition the requested Traffic Scope into a bounded set of explicit domains and require a recognized anchor for each.
5. Evaluate candidate domain plans against `Supported` device capabilities and the version-qualified Engine Capability Profile only.
6. Reject combinations that are not exhaustive, selector-disjoint, non-overlapping, or compatible in engine/listener, mark, route, per-domain address-set, activation, and cleanup ownership.
7. Reject candidates that exceed rule/set/map/resource budgets.
8. Add independently eligible eBPF roles per domain; they cannot rescue an otherwise invalid correctness plan.
9. Rank remaining candidates by requested mode, semantic coverage, atomicity, recovery quality, and tested preference order.
10. Return the bounded ranked candidates and all rejection reasons without consuming authority.

Candidate finalization:

1. For an explicit request, evaluate only the named candidate and fail immediately if its exact evidence is missing or stale.
2. For `auto`, boundedly visit ranked candidates, rechecking each candidate's Capability Profile, Engine Capability Profile, inventory, topology, boot, and namespace bindings; retain every failure as a rejection reason.
3. For a candidate containing mark reads, writes, or transfers, remove, freshness-check, and consume its exact `AndroidMarkPlanningAuthority` from the owned evidence set. A candidate with no mark use records that authority was not required.
4. Select the first `auto` candidate whose exact evidence succeeds, or fail with the complete bounded rejection report when none does.
5. Emit the immutable Backend Plan, programs, non-authorizing evidence receipt, resource budget, and all retained rejection/explanation data.

The algorithm is pure and has golden tests for representative device profiles.

## 8. Policy compilation

### Phase 2 shadow boundary

The completed and frozen first checkpoint is a pure, non-authorizing compatibility compiler. The
compiler itself owns a versioned canonical mandatory safety baseline; callers may supply bounded
configurable direct prefixes but cannot delete, replace, or reclassify mandatory entries. It
canonicalizes and deduplicates resolved UIDs, exact/prefix interface selectors, family-matching
prefixes, and optional inventory-derived host bypasses before compiling two distinct programs. If
no host-set plan is supplied, the report explicitly defers inventory-host observation rather than
claiming complete device-owned-address safety. A partially covering plan reports every selected
family that remains unobserved, and provenance retains the plan's exact family selection:

- local OUTPUT, where compatibility engine credentials, output-interface policy, and resolved
  application UID policy are meaningful; and
- forwarded ingress, where input-interface/tether scope is meaningful and OUTPUT-only UID policy
  is absent.

The checkpoint orders family/domain scope, compatibility loop prevention, mandatory destination
safety, inventory-derived address hosts, configurable destination bypass, interface/domain
selection, local application selection, protocol eligibility, and the proxy/direct result. It
retains the host-set snapshot/epoch as provenance but defers its Generation-finalization freshness
check. It records the compatibility UID/GID loop bypass as an assumption rather than claiming exact
engine-socket authority. Forwarded programs likewise record the legacy exact `lo` name as an
assumption; native activation still requires observed loopback link identity. Unsupported protocol
handling is explicit. Established-flow caching,
transparent-socket acceleration, FakeIP ICMP, QUIC policy, MSS clamping, mark/routing actions,
backend object naming, and activation remain deferred from the shadow artifact itself.

Compilation has fixed prefix, UID, and interface-selector ceilings and fails rather than truncating.
Canonical ordering and a domain-separated semantic digest make identical normalized inputs
byte-for-byte reproducible. The initial shell-derived fixtures characterize policy decisions only;
the frozen Phase 2 checkpoint itself contains no xtables/nftables renderer, restore-byte parity,
live-kernel readback, device-parity claim, or conversion to Generation/prepared/active state. A
separate Phase 4 lowerer now consumes the sealed artifact: forwarded-only input preserves the exact
schema-v1 contract, while any local-OUTPUT input selects canonical xtables-lowering schema v2. Both
forms remain pure and outside every activation path.

The separate Phase 4 `LegacyRulesPlan` does not widen this shadow boundary. It preserves and
validates the legacy generator's source shape so bridge preparation can reproduce compatibility
restore bytes. It is neither constructed from nor convertible from `ShadowCaptureArtifact` and is
not canonical Capture Program lowering.

The canonical Phase 4 lowerer is independent of `LegacyRulesPlan`. It emits generation-namespaced
but unattached mangle implementation chains. Schema v1 remains byte-for-byte and digest-compatible
for forwarded-only input. Schema v2 represents local OUTPUT with a MARK-only private classifier,
a separate loopback PREROUTING TPROXY companion when proxy traffic exists, typed routing/listener/
loop-escape requirements, and descriptive lifecycle ordering. It still rejects established-flow
caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS clamping, and it provides
no restore execution, stable-hook mutation, ownership, or activation conversion.

The shadow IR follows the target order in section 8.1: compatibility engine loop prevention is
before destination/interface policy, and forwarded loopback safety is before configurable bypass.
The shipped shell reaches `BYPASS_IP` and some interface rules before `APP_CHAIN` owner matching,
and emits its combined bypass chain before the loopback rule. Those overlap cases normally share a
direct disposition but differ in explanation precedence. This is an intentional documented
target-versus-oracle distinction, not a renderer-parity claim; the later differential checkpoint
must review it explicitly rather than silently copying either order.

Shadow list predicates are set predicates: members are ORed, while `LocalUidNotIn` and
`InterfaceDoesNotMatch` negate the complete set. Interface selectors are backend-neutral bytes,
not proof that an xtables token is renderable. The canonical lowerer validates token bytes,
leading-dash and trailing-`+` ambiguity, and IFNAMSIZ expansion before emitting restore syntax. It
preserves whole-set `InterfaceDoesNotMatch` and local allowlist `LocalUidNotIn` semantics by
expanding positive proxy membership only, rather than emitting a sequence of incorrectly negated
direct rules, and applies one checked command budget across every family-private chain.

### 8.1 Normalized decision order

The backend-neutral Capture Program uses this order:

1. traffic outside Traffic Scope;
2. Flux control and Proxy Engine loop prevention;
3. mandatory invalid, local/device-owned, multicast, broadcast, and other loop-safety exclusions;
4. configurable private, CGNAT, special-use, and user-direct Bypass Policy;
5. established-flow cached bypass/proxy decision when valid;
6. interface/network role decision;
7. Android user/UID policy for locally originated traffic;
8. protocol-specific safety policy;
9. proxy action;
10. direct default for unsupported or explicitly bypassed scopes.

Forwarded traffic never evaluates an OUTPUT-only UID predicate. Local and forwarded programs are compiled separately even when a backend later shares chains or sets.

Application selection uses typed set algebra after package/user inventory resolution:

- `all` proxies every otherwise eligible local application;
- `allowlist(S)` proxies exactly the eligible UIDs in `S`, so `allowlist(∅)` proxies zero applications;
- `denylist(S)` proxies eligible UIDs not in `S`, so `denylist(∅)` proxies every otherwise eligible application.

The bridge compiler and every native backend must share these semantics. The canonical CGNAT prefix
is `100.64.0.0/10`; `100.0.0.0/8` is never emitted as an RFC 6598 default. Mandatory loop/device-
local exclusions are not disabled by an empty configurable bypass set.

### 8.2 Mark invariants

- `mask != 0`.
- Proxy and bypass values differ under the mask.
- Values contain no bits outside the mask.
- Every update preserves bits outside the Flux mask.
- Generic AOSP grants no Flux mark field; a conflict-free scan is not positive authority.
- Bits 21–30 (`0x7fe0_0000`) are only the syntactic envelope in which a device-qualified policy may name a candidate, not a reservation.
- The Flux mask is disjoint from every externally observed predicate read, masked write, transfer read, and transfer write on packet, socket, and conntrack marks.
- The current legacy low-byte mask `0xff` is never accepted merely because it was previously configured.
- Opaque RPDB evidence rejects authority; unobserved or opaque bits are never allocated by complement.
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

The first non-mutating Phase 4 cutover is delivered. Rust-owned preparation exclusively invokes
`fluxd render-legacy-rules`, records `rust` as the cache producer, and never sources `scripts/rules`.
Explicit legacy ownership exclusively sources the frozen generator, records `shell`, and remains a
deliberate rollback producer. Render failure does not silently change producers and cannot replace
the active Generation. In either mode, `scripts/tproxy` remains the sole xtables restore executor
and kernel writer. A later transition lease disables that shell writer before the first native
restore mutation; native ownership still requires failure/recovery, exact readback, rollback, and
real-device gates.

The completed `flux-platform` syntax checkpoint remains a frozen-syntax observer. A pure parser
accepts an explicit IPv4/IPv6 plus apply/cleanup context and a bounded canonical byte slice; it
retains ordered and repeated `mangle`/`filter`/`nat` transactions, declarations, commands, opaque
validated tokens, duplicate lines, cleanup phase order, resource usage, and a domain-separated
digest, and can canonically re-encode the same IR. Cleanup phase order is transaction-local,
matching the current repeated-table artifact shape. Its grammar is closed to the current cache
artifact operations (`-A`, `-I`, `-D`, `-F`, and `-X`) with exact LF/single-space printable-ASCII
framing. Synthetic tests establish the grammar and bounds; `xtables_restore_oracle` parses all four
checked-in shell-oracle fixtures and canonically reproduces their exact bytes. This parses neither
shell configuration nor Capture Policy and proves neither option semantics, independent renderer
parity, backend support, kernel acceptance, apply/cleanup invertibility, nor full cleanup coverage.

The syntax artifact has no Generation ID, renderer bindings, executable path, process adapter,
writer/ownership token, prepared/active conversion, Runtime Coordinator entry point, or canary
authority.

The raw shell/AWK oracle is a separate, complete and frozen cache-artifact checkpoint.
`tests/oracle/xtables/manifest.json` is authoritative for its environment, input, and fixture pin
contract; narrative documents must not duplicate those hashes. `cargo xtask xtables-oracle
--check` regenerates and compares the four raw fixtures, and explicit `--update` is the reviewed
path for intentional input changes. Normal `cargo xtask ci` never invokes either mode. The runner
is networkless, unprivileged, does not mount the host workspace, does not invoke a restore
executable, and does not inspect or mutate live networking state. See `docs/development.md` for the
operational workflow.

The oracle inputs are cache inputs only: `scripts/rules`, its semantic shell regression, the
bounded generator, a reviewed environment cache, and a package-list cache. The profile performs
no normal configuration or kernel-capability detection, does not cover QUIC, PBR, or forced
cleanup, and proves neither restore/kernel acceptance nor Android/Magisk parity. Its cleanup
fixtures characterize the ordinary generated `-D` form. Raw fixtures alone do not constitute a
Capture renderer, Generation, ownership/writer lease, prepared/active conversion, coordinator
entry point, or activation authority. Their use by the independent legacy-renderer differential
suite does not turn that source-shape renderer into canonical Capture Program lowering.

### 10.1 Delivered legacy source-shape renderer

`LegacyRulesPlan` is a validated compatibility input model. It preserves byte-significant ordering,
duplicates, application modes and ordered resolved UIDs, mobile/Wi-Fi/hotspot/USB roles, owner
matches, bound bypass/proxy mark values and mask, conntrack/mark/socket fast paths, TCP/UDP DIVERT gates,
IPv6 NAT, FakeIP, MSS, family admission, chain naming, and cleanup symmetry. Interface patterns,
owner tokens, ports, masks, FakeIP families, resource counts, and production prerequisites fail
closed. The proxy marks are not independently allocated: preparation exports the same
`IPV4_MARK`/`IPV6_MARK`/`BYPASS_MARK` contract consumed by the shell PBR executor.

The renderer is pure: it performs no filesystem, process, restore, or kernel I/O and returns the
bounded canonical syntax artifact. Its exact pinned-profile and branch-matrix tests prove legacy
source-shape parity only. Cached-flow ordering, direct-action side effects, protocol eligibility,
and other target semantic differences are not inherited by the separate canonical lowerer. The
delivered canonical base covers extension-free forwarded ingress and the pure schema-v2 local-
OUTPUT transaction representation; the five typed legacy extensions remain open.

Renderer-owned identity is schema-versioned and domain-separated. `LegacyRulesPlanDigest` binds
every byte-significant compatibility input, including ordered and duplicate UID/interface facts,
marks, owner tokens, family/feature gates, and FakeIP/MSS inputs. A
`LegacyRulesArtifactPair` can be constructed only by rendering the mandatory apply and cleanup
contexts for one family from one immutable plan. `LegacyRulesArtifactSet` always contains IPv4 and
contains IPv6 exactly when that plan enables it. Pair and set digests bind the plan identity,
context-qualified syntax-artifact digests, parser schema, and aggregate input-byte/line/
transaction/declaration/command/token totals. These identities are neither signatures nor
freshness, readback, rollback, writer, activation, or kernel-acceptance authority.

### 10.2 Delivered bridge cache-generation adapter

The compatibility-only command is:

```text
fluxd render-legacy-rules --packages-list PATH --family 4|6 --action apply|cleanup
fluxd snapshot-legacy-packages --source PATH
fluxd attest-legacy-rules-set --generation ID --packages-list PATH \
  --ipv4-apply PATH --ipv4-cleanup PATH \
  [--ipv6-apply PATH --ipv6-cleanup PATH]
```

The renderer reads a strict allowlist of exported generated-cache values, resolves Android package/user IDs
from one bounded regular package snapshot when application policy needs them, constructs the
validated plan, and writes canonical bytes to stdout. TUN, non-`iptables_restore`, non-zone,
missing-owner, missing-TPROXY, disabled-family, malformed, oversized, or ambiguous inputs are
rejected explicitly.

The snapshot helper opens its source without following symlinks, requires a bounded regular file,
checks descriptor identity/stability across the read, and streams bytes to stdout for atomic cache
publication. Shell does not copy a live package database directly.

Rust-owned `scripts/init` snapshots `packages.list` only when application resolution is active and
nonempty; otherwise it publishes an empty snapshot without reading Android package state. The
snapshot is bounded, non-symlink, read-only, shared by every parallel family/action render, and
copied with the prepared Generation. Successful cache publication records producer `rust`.
Explicit legacy ownership instead sources `scripts/rules`, removes the package snapshot, and
records `shell`. Candidate failure leaves the prior active Generation unchanged.

After all enabled family/action renders succeed, `attest-legacy-rules-set` rereads the same strict
allowlisted environment, resolves the plan from the bounded package snapshot, renders one complete
renderer-owned set, and safely reads each supplied artifact without following the final symlink.
Regular-file, size, descriptor identity, metadata stability, family presence, and exact byte
equality are mandatory. Generation is canonical decimal `1..=2147483647`; IPv6 paths are required
exactly when `PROXY_IPV6=1`. Success emits one canonical LF-terminated
`FLUX_LEGACY_RULES_SET_MANIFEST_V1` document containing the Generation, family shape,
plan/pair/set/artifact digests, and per-artifact/pair/set resource totals. Fixed field positions
carry the IPv4/IPv6 plus apply/cleanup contexts; paths and timestamps are excluded.

Shell removes any prior receipt before the first shared-cache rebuild mutation. It validates a
bounded response envelope: nonempty size-limited content, the expected header, exactly one expected
Generation, and the enabled-family shape. Trusted Rust owns canonical schema production and strict
parsing/identity verification; shell does not claim to parse every manifest field. Stale receipts
are invalidated and rebuilt/re-attested, never reused directly. An unresolved mismatch or failed
attestation prevents `cache_valid` publication. The dispatcher copies the exact receipt into the
candidate Generation as `legacy-rules.manifest` before `engine.manifest` and directory immutability.
A non-Generation `fluxctl rules-preview` rebuild is serialized under the same dispatcher lock,
deliberately emits no receipt, and cannot authorize later publication. The manifest exposes no restore execution API,
writer/ownership token, live readback, rollback proof, prepared-capture conversion, or functional
verification claim; `scripts/tproxy` remains the sole restore executor and kernel writer.

These compatibility-only renderer, snapshot, and attestation commands are removed or made private
with the bridge when the remaining canonical semantics and native restore ownership pass their
cutover gate. They are not public release APIs.

Explicit legacy restart similarly prepares and validates fresh settings, the replacement Sing-Box
configuration, and every replacement cache before stopping the active runtime. Preparation failure
restores the prior cache authority, leaves that runtime untouched, and keeps stop/cleanup available.

### 10.3 Delivered canonical schema-v1/v2 xtables lowering

`lower_xtables_capture` consumes the sealed schema-v1 `ShadowCaptureArtifact` and selects its own
canonical xtables-lowering schema. Forwarded-only input retains schema v1 exactly; any artifact that
contains local OUTPUT selects schema v2. The request carries an `XtablesCaptureNamespace`, an
`XtablesTproxyTarget`, optional per-family `XtablesLocalOutputRoutingSpec`, an explicit
`XtablesCaptureExtensions` value, and a caller-selected command budget bounded by the immutable
restore grammar. The namespace's nonzero numeric label derives deterministic private-chain names;
it is not a Generation, ownership token, writer lease, or activation authority. The target's
listener port and `FwmarkCandidate`, and the caller-selected routing target, prove neither Android-
safe placement nor a mark, route, listener, or writer lease.

Forwarded-only lowering preserves the frozen schema-v1 restore bytes, names, usage accounting, and
lowering/pair/set digests. Each selected family has one `ForwardedIngress` entry on `PREROUTING`
with selector `Any` and chain `FLX{4|6}F{generation:010}`. Ordered direct predicates become
uncached `RETURN` rules; terminal whole-set `InterfaceDoesNotMatch` becomes positive proxy
membership; and eligible TCP/UDP traffic receives protocol-qualified TPROXY using the exact port
and masked proxy mark. Existing schema-v1 fixtures therefore remain identity-stable.

Schema v2 adds two distinct local roles without changing that forwarded role:

- `LocalOutputClassifier` is an `OUTPUT` entry with selector `mark 0/mask` and private chain
  `FLX{4|6}O{generation:010}`. Its ordered direct decisions remain `RETURN` rules. Eligible local
  TCP/UDP decisions use masked `MARK --set-xmark proxy/mask`; this chain never emits TPROXY.
  Allowlist `LocalUidNotIn` is lowered as positive proxy membership for the selected UIDs, while
  denylist members remain ordered direct returns.
- `LocalOutputLoopbackTproxy` exists only when that family can proxy traffic. It is a
  `PREROUTING` entry with selector `-i lo` plus `mark proxy/mask` and private chain
  `FLX{4|6}P{generation:010}`. The private chain contains only protocol-qualified TCP/UDP TPROXY
  actions for the exact listener port and mark, followed by direct fallthrough.
- A mixed local/forwarded family additionally retains the unchanged
  `FLX{4|6}F{generation:010}` forwarded chain.

The restore parser reserves all three `O`, `P`, and `F` namespaces, requires a nonzero ten-digit
`u32` generation, and rejects malformed or cross-family names. The stable-hook selectors are typed
entry metadata, not commands embedded in the private chains. Prepare restore artifacts only
declare and fill those private chains; retire artifacts only flush and delete them.

For every proxying local family, schema v2 requires one exact typed routing target before lowering:
nonzero RPDB priority, non-reserved table, nonzero route protocol, optional nonzero rule protocol,
the selected proxy mark/mask, and loopback interface identity. It also records an unspecified-
address transparent listener requirement for the exact family, port, and TCP/UDP set, plus a loop-
escape requirement binding the compatibility engine credentials and required bypass mark/mask.
These values describe the objects and exact inverse identity a later transaction must own; they do
not allocate them, prove listener readiness, or authorize Android mutation. An all-direct local
program remains schema v2 but has only the `O` chain and needs no `P`, routing, listener, or typed
loop-escape requirement.

Schema-v2 transaction metadata makes lifecycle dependencies explicit. When present, preparation
orders private `O`, `P`, and `F` entry objects before listener, policy routing, and loop escape;
attachment then orders `P`, `F`, and `O`, so local OUTPUT is reachable last. Retirement detaches
`O`, `F`, and `P` first, then retires loop escape, policy routing, listener, and the private entry
objects in reverse order. This ordering is descriptive only: it cannot attach a stable hook,
execute restore, mutate routing, or prove absence.

Schema-v2 lowering, family-pair, and artifact-set identities use new domain-separated digest
domains and bind the routing input, typed entry roles/hooks/selectors, local requirements,
transaction order, restore syntax, and expanded resource accounting. Accounting includes entry
points, listener requirements, routing objects, and transaction steps in addition to clauses,
rules, chains, commands, and jump depth. Schema-v1 identity remains frozen by selecting its prior
digest domains and prior accounting shape for forwarded-only input.

Both schemas reject established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC
rejection, and MSS clamping. Neither artifact attaches `PREROUTING` or `OUTPUT`, invokes restore,
inspects live state, proves cleanup invertibility, performs readback or rollback, acquires
ownership, enters the journal/coordinator, or constructs prepared/active state. Native stable-hook
activation, restore execution, exact readback/rollback, transition leases, production driver and
receipt authorities, and reviewed Android release qualification remain the next cutover gates.

### 10.4 Native restore invocation

The first internal process primitive now opens caller-selected absolute
`iptables-restore`/`ip6tables-restore` paths while rejecting a final-component symlink, pins their
descriptors and domain-separated byte digests, probes bounded `--version` output, and requires the selected family
pair to report matching legacy or nf_tables restore flavors. This hint does not classify wrappers,
vendor implementations, command/save coherence, or Backend Plan eligibility. Before and after each invocation it
revalidates the pinned bytes. It spawns the pinned descriptor directly, clears the inherited
environment, passes fixed `-w N --noflush` arguments, writes the canonical restore artifact to
stdin, bounds stdout and stderr, applies a nonzero deadline plus direct-child parent-death
containment, marks unrelated parent descriptors close-on-exec, and kills/reaps the process group so
descendants cannot retain its pipes. Its stdin writer is nonblocking and cancellation-aware;
cleanup failure returns a typed error and transfers unresolved reaping out of the deadline path.
Every failure after a restore child successfully spawns carries `MayHaveMutated`, requiring the
future owner to re-read live state before compensation. Probe and pre-spawn failures are
`NotStarted`.

This primitive remains crate-private and is not a
restore authority. It is not wired to the Runtime Reconciler or functional-canary driver and has no
stable-hook, rtnetlink, live readback, rollback, journal, transition lease, prepared/active, or
ownership conversion. A zero exit is process evidence only. System discovery, coherent
command/restore/save identity, exact lock-timeout classification, live readback, and the complete
native transaction remain open.

Before selection, Flux detects whether each tool belongs to iptables-legacy, iptables-nft, a wrapper, or a vendor implementation. IPv4/IPv6 command and restore tools must form one coherent implementation and pass the exact canary. One Generation never mixes legacy and nft variants or manages the same policy through both.

### 10.5 Generation shape

- Stable entry chains are attached once.
- Generation chains contain the actual policy and reference only generation-specific sets.
- Activation updates stable jumps in one restore transaction per family/table.
- Cleanup removes exact generation chains only after no stable jump references them.

### 10.6 ipset

- Separate IPv4 and IPv6 `hash:net` sets.
- Create generation-specific target sets and populate an unreferenced temporary set.
- Optionally use `swap` to publish the fully populated contents into the generation-specific target name before any generation chain references it.
- Switch only the stable xtables jump at cutover; never swap contents under a set still referenced by the old Generation.
- Destroy retired generation sets only after their generation chains are unreferenced and removed.
- If create/add/swap semantics are not all verified, do not select ipset.

### 10.7 Bounded-tree fallback

Retain the current prefix-zone concept as a compatibility compiler, with hard depth and chain-count budgets. Canonicalized user CIDRs are permitted, but compiler estimates must reject pathological expansions.

## 11. Routing and address synchronization

All route/rule operations use rtnetlink from the daemon.

### 11.1 TPROXY routing

For each enabled family, a future activation-capable TPROXY plan requires:

- one Flux-owned fwmark rule using an authorized mark candidate and a separately admitted routing candidate;
- one local default route in the Flux table to loopback;
- address-derived higher-priority bypass rules for active local interface addresses where required by the selected topology;
- exact cleanup messages carrying the same attributes used to create objects.

Routing candidates remain unselected until the complete Android RPDB grammar, requested traffic-domain topology, table occupancy, ownership evidence, and later activation prerequisites admit them. With `respect_android_vpn = true`, placement must preserve secure/lockdown VPN and per-UID network selection. A fixed legacy priority such as `2025` is not accepted as a native candidate, and the final explicit routing schema remains deferred until per-domain realization is designed.

Implementation checkpoint: `flux-core` now has a mutation-free address-bypass planner. It consumes one complete `NetworkInventory` plus an explicit caller-resolved per-family priority, lookup-table, and rule-protocol specification; it does not allocate those values or claim that numeric placement alone preserves Android VPN policy. The planner filters unusable, disabled-family, flag-matched, exact-address, and CIDR-matched facts; normalizes valid IPv4-mapped inputs; rejects mapped prefixes crossing the mapping boundary; deduplicates addresses across interfaces; and emits deterministic `/32` or `/128` destination-host intents under a fixed rule-count budget. The result is bound to both the source `NetworkEpoch` and an opaque process-local snapshot identity so an equal epoch from another observer cannot authorize later work. Selected-priority occupancy is audited against the ordered rule multiset with bounded diagnostics. Even an exact canonical `NetworkRuleRecord` remains an unowned conflict: canonical equality is not journal/raw ownership evidence, so adoption, retirement, native encoding, and cleanup remain deferred.

The versioned RPDB placement checkpoint adds a pure audit around that planner. A classifier must provide exactly one ordered classification for every observed rule and explicit must-precede and terminal boundaries for each enabled family. A rule with semantically opaque attributes rejects placement in an enabled family before any caller classification is trusted; opacity in a disabled family remains outside that family-scoped lease. The audit otherwise admits a candidate only when `last must-precede < address bypass < Flux proxy < first terminal barrier`, both requested priority slots are empty, no GOTO edge intersects the candidate interval, and the proposed Flux-private table has no route or rule occupancy in that family. IPv4 and IPv6 admission is atomic, and the resulting process-local lease is bound to snapshot identity, epoch, and classifier revision; it can project only the address-bypass priorities targeting Linux table 254. This is placement evidence, not an Android VPN-safety or activation proof: positive mark authority, route reachability, boot and namespace binding, durable ownership, exact mutation identity, and contained device canaries remain required before native writes.

A third pure checkpoint performs the partial fwmark conflict analysis that current `NetworkInventory` evidence can support. It validates one nonzero common mask with distinct nonzero proxy and bypass values, exposes masked-merge arithmetic that preserves every outside bit, and reports definite overlap with Android's low 16-bit `netId` field plus every ordered IPv4/IPv6 RPDB fwmark selector. Conflict evidence is bounded without changing the decision, and the report is bound to the exact inventory snapshot and epoch. Its RPDB source status becomes `Opaque` if any rule carries unmodeled attributes; this does not invent a collision, and known selector overlaps remain definite conflicts alongside the incomplete source state. The partial report alone has no accepted outcome and no `MarkLease`: device policy, xtables, nftables, TC/BPF, XFRM, socket/connmark transfers, and existing Flux ownership require stronger evidence. Unobserved or opaque bits must never be treated as allocatable by taking the complement of current conflicts.

The Android RPDB classifier checkpoint is also pure. Callers must explicitly select one exact source-pinned grammar: AOSP Android 12 r1, Android 13 r1, or the repository's pinned March 2025 netd revision. The classifier never guesses from an SDK level or priorities. It matches the complete AOSP rule shape—wildcard prefixes, zero TOS, origin protocol, action, table class, fwmark/mask, loopback/input/output interface, UID presence, flags, and absence of every unrelated selector—then retains one aligned role per ordered rule plus bounded unknown diagnostics. Opaque attributes, unfamiliar priorities, one-field signature drift, unsupported actions or flags, missing initialization sentinels, and nonmonotonic per-family order fail closed. Exact kernel-local and recognized Android roles through UID-default-unreachable become `MustPrecedeFlux`; exact default-network and global unreachable rules become `TerminalBarrier`; the classifier never emits `DoesNotConstrainFlux` without a later traffic-domain proof.

Observed rules alone are insufficient to reserve priorities that netd may add later. The classifier therefore embeds its static UID-default-unreachable band in the aligned audit itself, so both the generic placement planner and the Android-specific diagnostic wrapper enforce absent future netd rules. Android 12 reserves through priority `28999` immediately before default-network `29000`; Android 13 and later reserve through `30998`, leaving only `30999` before default-network `31000`. Neither profile can hold the current pair of distinct address-bypass and proxy priorities. A single global proxy rule also cannot, by priority alone, both follow per-UID local-output policy and precede tethering at `21000`. This checkpoint deliberately returns no Android-safe allocation authority: the routing topology must gain traffic-class/selector-aware placement, a verified network-selection handoff, or a design that removes one RPDB priority before native mutation can proceed.

The next pure checkpoint separates realization-neutral address selection from the compatibility RPDB-rule planner. One snapshot-bound address host-set plan now preserves the same family filtering, mapped-address normalization, flag/address/prefix exclusions, deduplication, deterministic ordering, budget, and stale-snapshot checks without assigning a table or priority. It may later feed a Capture Policy bypass that runs before all mark restoration and writes; until a backend proves that exact ordering under address churn, the existing address-rule plan remains the bridge realization and the host set is not activation evidence.

Android TPROXY topology assessment is traffic-domain and observed-anchor aware. Each report is bound to one exact observed `DefaultNetwork` or `Tethering` rule, its classifier revision, and the corresponding present, administratively-up input-link identity. Residual local OUTPUT inherits the anchor's `iif lo` and Android fwmark predicate; tether ingress inherits the exact non-loopback `iif`. Only a trusted input-interface mismatch or incompatible fwmark predicate is selector-disjoint. Unknown/opaque rules and an invalid family profile remain unknown before any disjointness claim, and overlapping same-domain anchors that select distinct tables are rejected as ambiguous. Android 12 therefore has no local-output slot, Android 13+ has only `30999`, and an exact tether domain has the open interval `20000 < priority < 21000`. The existing unqualified address-bypass rule is not a valid tether-domain shape because placing it in that interval could also affect local OUTPUT. These are structural intervals only: the report exposes no selected priority, placement/mark lease, route intent, or mutation identity. Even a one-slot residual window still requires one-rule address handling, positive mark authority, exact Capture Program ordering, per-connection domain identity, Android network-selection handoff, route reachability canaries, boot/namespace binding, observer continuity, durable ownership, exact mutation identity, and an explicit Proxy Engine loop escape.

The multi-domain scope checkpoint keeps that evidence atomic without turning it into a plan. One bounded, nonempty, duplicate-free request binds exactly one routing shape to selected residual-local families and exact tether ingress interfaces. The assessor discovers every recognized anchor matching each requested domain, retains every per-anchor interval, selector, link identity, disposition vector, and structural result in deterministic request/dump order, and rejects a missing domain, mixed inventory/classifier evidence, an unusable or ambiguous anchor, or an exceeded request/report bound without returning a partial scope. Valid negative results remain diagnostic data. The aggregate summary gives definite domain incompatibility or slot exhaustion precedence over incomplete evidence; otherwise any incomplete anchor makes the scope incomplete, and only all residual windows yield an all-candidate structural summary. Freshness re-runs complete domain discovery and every per-anchor assessment against the current inventory and classifier, so anchor additions, removals, reorderings, link reuse, opacity, profile drift, or selector/table drift invalidate the old scope. The scope still selects no common priority, route table, mark, route intent, ownership identity, encoder, or mutation operation.

The positive Android mark-authority checkpoint is also planning-only. Generic AOSP is an explicit zero-grant policy, and bits 21–30 are merely the device-qualified candidate envelope. The device-policy factory records an external trust-boundary assertion rather than verifying the artifact: it binds the exact mark candidate and topology scope, the full `CapabilityProfile` with verified boot identity, network-namespace identity, a named cooperative device policy with a nonzero SHA-256 artifact digest and revision, and the exact nonempty plane set asserted by that policy. A partial assertion is representable for diagnostics but cannot authorize planning; authorization requires the grant to cover packet, socket, and conntrack marks. It then consumes one non-`Clone`, point-in-time census with exactly 27 complete-present/complete-absent coverage records: Android `netId`, RPDB, device policy, legacy xtables, nftables, TC/BPF, XFRM, connmark/socket transfers, and existing Flux ownership across all three planes. The census accepts at most 512 raw mark-use records before canonical sorting and deduplication, and binds the exact inventory snapshot/epoch, full Capability Profile, namespace, policy identity/revision, collector revision, and ownership-journal identity/revision. Any candidate-mask overlap with an external predicate read, masked write, transfer read, or transfer write rejects regardless of values; opaque RPDB evidence also rejects. Known mark conflicts are reported before an otherwise incomplete topology result, while definite topology incompatibility remains a structural rejection.

`AndroidMarkPlanningAuthority` has no public constructor and cannot become a `MarkLease`, priority, table, route intent, encoder, mutation operation, activation lease, or writer. Reauthorization consumes the authority and requires a newly collected census observation. Exact writer semantics, mark-observer continuity, and a mark-preservation canary remain mark-specific activation prerequisites. The topology separately retains exact Capture Program ordering, domain-identity and Android network-selection handoff, route-reachability canaries, observer continuity, durable ownership, exact mutation identity, and Proxy Engine loop escape; the pre-mark host-set shape also retains one-rule address-handling proof. Binding the census to the ownership journal is freshness evidence, not ownership or cleanup authority.

The first concrete census-source checkpoint is now an inventory-bound RPDB fwmark fragment. Linux
FIB rules predicate on a transient `flowi_mark`: packet-origin paths populate it from `skb->mark`,
while local-output paths populate it from `sk->sk_mark`. Every modeled `fwmark` selector therefore
emits an ordered packet-plane and socket-plane `PredicateRead` using the selector mask; RPDB does
not directly read conntrack marks, so that cell is complete-absent. Exact rule dump order and
duplicates are retained. Any semantically opaque rule makes both packet and socket coverage
opaque, but known selectors remain in the fragment. The exact 512-raw-record budget is enforced
before sorting or deduplication, so 256 selectors fit and selector 257 rejects without truncation.
The fragment binds the exact inventory snapshot identity and epoch, carries no complete-collector
revision or policy/ownership bindings, and exposes no conversion to a complete Mark Census,
Planning Authority, lease, encoder, writer, or mutation operation. The other 24 source-plane cells
and cross-source point-in-time coordination remain deferred.

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

For `xt_bpf`, each Generation owns new maps, programs, pins, and private xtables chains. Observation
programs always return zero. Positive programs return nonzero only for an unambiguous proxy decision;
every miss, parse ambiguity, `bpf_get_socket_uid() == overflowuid`, stale Generation, or map failure continues through
the complete classic classifier. Activation switches the stable xtables jump only after the new
program reference and packet canary verify; retirement removes referencing rules before unpinning.

Old and new program sets share a small control map. Each program has an immutable expected Generation and reads the BPF active-policy selector plus the selected per-generation policy-map slot. Userspace populates the new maps, attaches every new program in dormant/pass-through mode, and then performs one control-map update selecting the new BPF policy slot. New programs accelerate only on a match; old programs immediately pass through and are detached afterward. This internal selector update does not publish the authoritative `GenerationRecord` or modify `active.json`.

When shared-map reuse or concurrent attachment cannot be proven, Flux detaches/re-attaches acceleration non-atomically while nftables/xtables/TUN remains the complete correctness path.

On the 5.10 correctness stack, the general bridge from out-of-chain TC/cgroup programs into netfilter is a masked Flux mark. `xt_bpf` is a separate direct Boolean bridge inside a referencing xtables rule. TC ingress may stamp a verified decision before PREROUTING for forwarded/tethered traffic, and nftables/xtables may match that mark. TC egress occurs after local OUTPUT and is not claimed to accelerate that classification path. No backend assumes it can read Aya maps directly.

TC ingress `bpf_sk_assign` is an exact-domain experiment, not a general bridge. The assigned socket
must be compatible and in the same namespace, and the packet still requires a correct local route.
A miss must retain an ordinary forwarding route rather than fall into a proxy-local default. This
role cannot become correctness-bearing without a separate ADR and domain fallback proof.

Only `FluxOwnedTunFd` may attach a socket-filter steering program through `TUNSETSTEERINGEBPF`. `TUNSETFILTEREBPF` is deferred because a zero return drops traffic and there is no automatic distinction between a program bug and an intended filter decision.

### 13.3 Attachment

- Prefer `bpf_link` ownership when probed.
- Legacy TC attachment uses a private `clsact`/filter identity and exact cleanup. It is bound to Network Epoch and reverified after netd lifecycle changes because AOSP netd may delete `clsact` from every extant interface.
- TCX attachment is qdisc-less and owns a BPF link rather than a `clsact` filter. Netd `clsact` deletion does not itself demote TCX, but link identity, foreign TCX program ordering, attach flags, link/program IDs, and offload semantics remain freshness evidence.
- Default TC attachment is limited to a verified Generation-scoped TUN netdevice, whether its queue FDs are engine-owned or Flux-owned. Physical interfaces additionally require an experimental opt-in because tethering offload may use the same path.
- Physical-interface experiments observe netd lifecycle, verify attachment after every Network Epoch, and immediately demote on qdisc/filter conflict.
- Never replace Android's cgroup hooks. Program IDs and attach flags across every ancestor plus the child must prove an exact hook unoccupied or explicitly compatible; an attachment at any ancestor can constrain descendants, and AOSP's root defaults normally prevent the same type below it. The first allowed child role is optional proxy-child `sockops` telemetry, paired with userspace TCP/UDP canaries rather than used as the loop-escape mechanism.
- The functional-canary `QualifiedCgroupBpf` delivery authority is a reserved schema variant, not a delivered attachment. No program may use it until ancestor-chain compatibility, exact hook semantics, event completeness, payload visibility, cumulative loss accounting, and owned cleanup have a separate qualification record.
- Detach or userspace death must leave the correctness Capture Path intact.
- `BPF_PROG_TYPE_NETFILTER` is eligible only on parsed kernel 6.4+ and a successful real hook probe.
- TCX is eligible only on parsed kernel 6.6+ and a successful attach/query/detach probe; legacy TC remains the fallback.

### 13.4 Telemetry

- Counters are polled in batches at a configurable interval.
- Ring-buffer events are exceptional/sampled, never one per packet, and require create/mmap/epoll/overflow probes.
- A perf-event-array Adapter is the event fallback; if neither works, sampled events degrade off while map counters remain available.
- Payloads exclude raw application data and secrets.
- Verifier logs are bounded and stored only for failed loads or explicit diagnostics.
- Sampled ring/perf events and aggregate counters are never authoritative functional-canary delivery evidence. A future qualified producer must emit one complete, loss-accounted attempt-bound event per required flow.

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
- PID plus `/proc` start-tick identity before every signal and child-owned listener readiness evidence for the admitted TPROXY bridge; the strict TUN readiness manifest form remains reserved for the future proven single-owner plan;
- a direct-child `PR_SET_PDEATHSIG(SIGKILL)` lease with a post-arm parent-identity race check for Sing-Box and phase-shell processes;
- bounded TERM/KILL/reap, restart windows, exponential backoff, and retained ownership until disappearance is observed.

The Phase 1 transaction rejects TUN during `prepare`, before engine admission or networking mutation. It also requires `xt_owner` before initialization and revalidates it from the generated capability cache; the Rust-rendered legacy compatibility program sends every local OUTPUT policy through the application chain so the configured engine UID/GID bypass remains active even when application filtering is disabled. `ROUTING_MARK` is not accepted as equivalent authority because the bridge does not prove that the supervised engine applies it to its sockets. For admitted TPROXY state, start is `prepare` → engine admission → Generation-bound capture start → structural capture verification → configured functional gate → Generation-bound `RUNNING`, and stop is capture detach → engine stop/reap → `STOPPED`. The current pre-release bridge explicitly selects structural-only compatibility; required-mode tests execute the delivered Stage-1 exact-binding canary transaction, and the first Stage-2 Linux checkpoint now exercises the isolated dual-stack topology and cleanup without installing capture. Partial capture-start compensation retains Generation evidence until both networking writers prove cleanup; terminal publication and engine retirement are forbidden while detachment is uncertain. Reload prepares the candidate while the previous Generation remains active, preserves its pass on prepare-only failure, invalidates it before detachment, blocks replacement if detach fails, and attempts the previous immutable `EngineSpec` if candidate activation fails. An uncertain reload detach enters capture repair: prove full detachment, retain/reconcile the old engine, then republish and freshly verify that Generation. Publication failure, identity loss, repair/restoration, and address resynchronization require a fresh complete gate before retrying `RUNNING`. Candidate evidence never authorizes rollback publication. The current owner bypass is a compatibility loop-escape prerequisite; the socket-correlation collector, its prebound session and typed attempt-owned handoff transports, schema-v2 listener/delivery validator, temporal cleanup/retirement validator, fail-closed TPROXY-only local-OUTPUT executor seam, per-flow capture receipt, and process-ownership receipt contracts are delivered. The Linux/Android child-origin pidfd substrate and no-traffic live credential preflight are also delivered. Both production receipt authorities remain uninhabited; the production traffic producer, real `EngineSupervisor`/`SingBoxChild` and prepared-driver child integration, production listener/report parser and factories, actual collector integration, and reviewed Android release-device qualification remain open. The rooted x86_64 WSA mechanism checkpoint is development-only and does not inhabit any of those authorities.

The delivered Linux evidence class is explicitly ingress-only. The command
`cargo xtask test-functional-canary-linux-tproxy` selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup`.
Its current slice adds a third probe network namespace and sends dual-stack TCP/UDP echo plus
nonce-bound DNS over UDP/TCP through exact PREROUTING TPROXY selectors into a test-local transparent
Rust relay. It proves accepted-socket and strict ancillary-data original-destination recovery,
relay and peer tuples, relay socket-mark readback, source-preserving UDP replies, parsed DNS
transaction/question/answer evidence, per-family route controls, independent bounded flow
counters, and exact cleanup. Before invoking
xtables TPROXY, the harness requires the target, mark/comment matches, family TPROXY support, and
selected xtables backend support to be visible as already active under `/sys/module`; it refuses
implicit kernel-module autoload.

That checkpoint does not qualify local OUTPUT. Its exact PREROUTING selectors are tied to the veth
ingress domain, while Linux 5.10 source permits a mark-triggered OUTPUT reroute to select an
`RTN_LOCAL` route through loopback and re-enter PREROUTING. Xtables still rejects TPROXY directly in
OUTPUT. An OUTPUT mark counter, proxy-table route lookup, or zero peer observation is therefore
never positive capture evidence; a separate checkpoint must prove the complete loopback-reinjected
listener path. The deterministic regression
`ingress_rule_plan_never_places_tproxy_in_output` preserves the rule-placement boundary.

ADR-0012 selects the conventional local candidate as one ordered transaction. Preparation binds
the exact transparent TCP/UDP listeners, reviewed masked mark, RPDB rules, local default routes
through loopback, private chains, mark-qualified `-i lo` PREROUTING TPROXY hooks, and zero-state
readback before OUTPUT becomes reachable. OUTPUT attachment is the activation boundary. Retirement
removes and proves absence of every OUTPUT attachment first, keeps the listener available until
that proof completes, and only then retires PREROUTING, listener, routes, rules, and private objects
by exact inverse identity.

`cargo xtask test-functional-canary-linux-output-tproxy` selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup`.
The disposable host checkpoint proves IPv4/IPv6 TCP accept and UDP original-destination delivery,
positive hook/delivery counters, bypass-mark replies, safe misses, zero peer leakage, no implicit
module autoload, and baseline restoration. It is mechanism-only evidence in one test process and
namespace; it does not combine the distinct-UID checkpoint, mint Generation/canary authority,
consume a production Proxy Engine report, or qualify a production Android profile.

`cargo xtask test-functional-canary-android-x86_64-output-tproxy --serial SERIAL [--adb PROGRAM]`
cross-builds that exact ignored test with the pinned NDK and runs it under UID 0 on one explicit
x86_64 Android serial. The runner validates ADB readiness, ABI, kernel architecture, SDK floor, and
UID 0; records the kernel release, build fingerprint, and boot identity; revalidates the same device
after the cross-build; derives exactly one test ELF from Cargo JSON; uses a root-owned private
`/data/local/tmp` directory and `TMPDIR`; sanitizes `PATH`; clears re-entry state; forces required
mode; lists the exact test; applies bounded host and device deadlines; and removes plus independently
proves absence of the remote directory. It is excluded from ordinary CI, staging, manifests,
packaging, and release outputs.

The 2026-07-15 WSA Android 13 / SDK 33 run passed the complete dual-stack transaction. Its Android
authority path binds UID 0 to the exact live parent and changed mount/network namespaces; the test
uses a disposable `0x00600000` role field and masked merge to preserve Android-owned socket-mark
bits. Bounded adapters handle WSA's built-in/no-`/sys/module` proof, legacy route/rule text,
unsupported rule-protocol syntax, synchronous `EPERM` negative drops, and inactive fresh-loopback
qdisc normalization. This is profile-specific mechanism and cleanup evidence, not production
Generation/driver/report/receipt authority, Android 5.10/ARM64, distinct UID, VPN/netd coexistence,
crash recovery, or release qualification.

The strict Linux/Android `/proc` FD plus INET_DIAG collector is now delivered. One caller-supplied
exclusive deadline bounds identical pre/post socket-FD inventories plus complete IPv4/IPv6 TCP and
connected-UDP dumps. Correlation is accepted only when protocol, exact local/remote tuple, UID,
required mark, numeric FD, matching FD/diag inode, INET_DIAG cookie, exact supervised PID/start-tick
identity, and recorded dump/snapshot timing all agree; partial, drifting, oversized, late,
ambiguous, malformed, stale, or interrupted observations fail closed. The collector supplies
outbound evidence plumbing only; it does not prove transparent/v6-only listener options, TCP
accept, or UDP ancillary delivery.

### 14.1 Prebound socket-diagnostics sessions

The platform collector exposes this stateful authority surface on Linux and Android:

```rust
let session = SystemSocketDiagnosticsSource.open_until(attempt_deadline)?;
let port_id = session.netlink_port_id();
let (session, snapshot) = session.collect_process_until(engine_identity, attempt_deadline)?;
```

The session uniquely owns one nonblocking, close-on-exec NETLINK_SOCK_DIAG FD and is not cloneable.
`netlink_port_id()` returns the kernel-assigned nonzero local port before any process collection.
All snapshots use that same FD. Collection consumes the session and returns it only with a complete
snapshot, so safe code cannot overlap transactions or reuse a handle after any error. Every four-
dump snapshot reserves a new monotonic nonzero sequence range, and exhaustion fails instead of
wrapping. The opening deadline is the absolute upper bound for the session; later calls may shorten
it but cannot extend it. Dropping either an unused session or any error path closes the observer.

`SystemSocketDiagnosticsSource::collect_until` is a temporary in-tree migration wrapper that opens
one session and performs one collection. It carries no compatibility promise and is removed after
all call sites use the stateful API. While present, both paths retain the same complete
PID/start-tick, stable pre/post FD inventory, four dump, bounds, tuple, cookie, mark, and timing
guarantees.

Binding the NETLINK_SOCK_DIAG socket does not itself request a protocol handler. Before the first
production dump, the future capability-qualified attempt integration must prove that the required
TCP and UDP INET_DIAG handlers are built in or already active and otherwise report unsupported. It
must not use a dump request as an availability probe because kernels may invoke `request_module`
for a missing modular handler; production Flux never relies on that implicit autoload path.

`fluxd` now carries this authority through a separate non-cloneable
`CanaryAttemptSocketObserverSession`, leaving `CanaryEnvironmentBinding`, `CanaryAttemptBinding`, and
`CanaryAttemptRequest` as cloneable/equatable data. Its production constructor opens the platform
session in the caller's current network namespace under `CanaryDeadline::expires_at()` and derives
the `ProcFdInetDiag` port authority plus a private process-local per-opening identity only from that
live handle. Attempt inputs derive their deadline from the transport instead of accepting an
independent value. Checked attempt-input and execution envelopes require exact equality with the
environment/request binding and deadline. The coordinator retains
the immutable request for post-observation and evidence validation while moving the observer once
into the executor; read-only driver availability runs first, and only a prepared local-OUTPUT
attempt receives the session by value. Request construction, binding, availability, or execution
failure therefore retires the handle automatically. A copied port ID cannot be paired with a
reopened replacement socket, even if the kernel later reuses that numeric port. Deterministic tests use a test-only synthetic transport,
while a live regression proves the real prebound port reaches prepared execution unchanged.

This completes the type-safe handoff boundary, not the positive producer. The future production
`prepare_attempt` implementation must use this constructor in the exact daemon namespace before it
builds `CanaryEnvironmentAuthorityBinding`; it must also bind the real collector object
identity/revision, capability-qualify the handlers without autoload, and drive the returned session
through the actual socket observations. No production required-mode context exists yet.

### 14.2 Functional-canary schema-v2 listener delivery

The internal functional-canary evidence model is schema v2. The control protocol remains v3, the
supervised inbound-delivery report validation format is independently schema v1, and `flux.toml`
remains schema v1. The schema defines evidence admission; it does not establish that the selected
engine artifact actually exposes an authoritative report producer.
Request construction selects TPROXY only. `REDIRECT` and `DNAT` values are negative evidence used
to reject backend substitution, not supported request backends.

Every required flow contains an independently observed static listener identity and a per-flow
delivery event. The listener binds the exact Generation, supervised PID/start ticks, admitted
readiness identity, daemon network namespace, Capture Program digest, attempt selector, protocol,
family, FD, inode, INET_DIAG cookie, family-correct wildcard bind and port, transparent state, and
IPv6-only semantics. Its exact pre-bound observer authority, sequence, unchanged loss counter, and
monotonic time are also required. Different `(family, protocol)` roles cannot reuse a listener FD,
inode, or cookie. A supervised delivery report never replaces this socket observation.

One delivery authority is used for the complete attempt. A supervised report must name the exact
engine, attempt-owned report-object identity, and report schema v1. The alternative must be the
exact pre-bound, separately qualified cgroup-BPF observer; it cannot wrap a proc/diag observer or
be mixed with supervised reports. Delivery sequences are nonzero and unique across flows, delivery
and listener-observation loss baselines are constant, and every observation is loss-free. Listener
and delivery sequences are independent numeric domains; only monotonic timestamps order them.

TCP delivery binds the parent-listener cookie, exact engine, distinct accepted FD/inode/cookie,
original local destination, and probe peer tuple. The accepted identity cannot collide with any
listener, and accepted inode or cookie reuse across flows is rejected. UDP delivery binds one
datagram to the listener cookie, source, original destination, no
payload/control truncation, and exactly one family-correct original-destination cmsg of length 16
for `sockaddr_in` or 28 for `sockaddr_in6`. Echo and DNS share one stable listener for each
`(family, protocol)` pair. Echo payload evidence binds the exact 32-byte nonce, length, and SHA-256;
DNS binds the canonical query, nonce, transaction ID, question digest, length, and SHA-256, with an
exact two-byte DNS/TCP length prefix.

The schema-v2 `validate_for` path and the explicit local-OUTPUT capture plus process-ownership
receipt contracts are complete, but authoritative construction is intentionally not available in
production. The non-cloneable capture receipt stores the exact request plus one fixed-slot event
per required flow and validates the request-bound probe UID, nonce, tuple, payload, listener cookie,
exact delivery event,
unique sequence, unchanged loss baseline, and attempt/client/deadline chronology. Drivers return
unverified capture proof, process proof, and raw observations; the capture verifier carries process
proof into a second sealed process verifier, and only artifacts owning both receipts can reach the
evidence factory. The process receipt binds the complete request's explicit probe/engine UID+GID
and credential-map domain, the engine's exact PID/start ticks and retained handle before/after the
flows, client/peer PID/start-tick identities and distinct handle openings, stable restricted
credentials, role network namespaces, exact cleanup retirement records, and chronology. The gate
record owns both receipts and rechecks them against its exact flows and cleanup evidence. Both
production verifier authorities and the current xtables prepared/raw path remain uninhabited, and
listener/delivery constructors remain private and test-only.

The Linux/Android `ProcessHandle` substrate opens only from a retained live `Child`, correlates a
pidfd to exact procfs PID/start ticks, proves the child remains waitable by this parent, and accepts
credentials only after two bounded stable censuses of every task show one homogeneous UID/GID,
supplementary-group, capability, and `NoNewPrivs` state. Pidfd readability proves exit, not reap.
The separate Linux credential preflight now keeps the role children live, verifies exact singleton
controller/probe/engine UID and GID maps plus namespace/map readback, reobserves through the same
handles, releases and confirms `Child::wait`, and only then corroborates exit through pidfd. It
sends no traffic, uses file-backed subordinate-ID discovery, and cannot publish
`functional_passed`.

REDIRECT or DNAT to a conventional local listener cannot qualify a TPROXY Generation because it
does not exercise that backend's transparent listener and destination semantics. The local-OUTPUT
adapter must prove delivery to the selected Generation's backend-specific listener, or explicitly
report the backend unsupported. Neither the collector nor any host-only adapter result may publish
production `functional_passed`; Android qualification remains a separate real-device gate.

### 14.3 Local-OUTPUT executor admission

`CanaryAttemptRequest` remains TPROXY-only. The local-OUTPUT executor rejects a REDIRECT or DNAT
request as `InvalidEvidence` with cleanup `NotRequired` before consulting a driver. Driver
preparation is a read-only availability phase and returns only `Unsupported`, `Denied`,
`Conflicting`, `Broken`, or `Unknown`; conversion is fixed to `Availability(...)` plus cleanup
`NotRequired`. Once a prepared value exists, any error must retain authoritative cleanup
`VerifiedAbsent` or `Uncertain`. A post-preparation `NotRequired` or inconsistent uncertain result
is promoted to `CleanupUncertain` with cleanup `Uncertain`.

Drivers return unverified capture proof, process proof, and raw observations and cannot directly
return either receipt or schema-v2 gate evidence. The sealed capture verifier is the only boundary
that may mint capture-bound artifacts; a separate sealed process verifier must then bind exact
owned-process evidence before the private evidence factory can promote the result. Receipt
validation binds the complete immutable request so Generation, boot, namespace,
Network Epoch/snapshot, Capture Program, ownership, engine/listener, selector, nonce, and deadline
cannot be replayed independently. Every required family/transport slot must then correlate its
request UID, tuple, payload, listener cookie, and exact schema-v2 delivery event under unique
loss-free sequence and monotonic-time bounds. The current xtables driver is zero-state, owns no
networking writer, and always returns `Unsupported` before mutation because it does not implement
or authorize the complete OUTPUT mark, RPDB local route, mark-qualified loopback PREROUTING TPROXY,
listener, escape, and cleanup transaction. It never emits TPROXY in OUTPUT and never falls
back to REDIRECT/DNAT, promotes ingress PREROUTING evidence, infers success from counters or route
lookups, or uses a veth bounce. The required-mode coordinator treats this unsupported result as a
failed functional gate, post-observes the attempt binding, compensates capture first, and never
publishes `RUNNING`.

The pure canonical xtables-lowering schema-v2 artifact does not change that driver result. It
describes the two private chains, prerequisite identities, and dependency order, but supplies no
prepared driver, stable-hook attachment, restore/rtnetlink writer, readback, rollback, cleanup
proof, or receipt authority.

This is fail-closed evidence admission only. It does not change the separate default fail-open
connectivity compensation policy. The model now requires typed client/peer retirement, pairwise-
distinct selector/guard/counter retirement, authority-sensitive report-object retirement or
verified-never-created disposition, exact absence readback, final counter/report lifetime,
attempt-record retirement, retained-facility observation, and complete gate/deadline chronology.
Its process identities and retirements now require the process-ownership receipt at the model
boundary, but production cannot mint that receipt until `EngineSupervisor` exposes authority from
its retained `SingBoxChild` and a real prepared driver retains, waits, and retires its client/peer
children. A positive factory also remains prohibited until one concrete capture verifier authority
proves the local-OUTPUT traffic domain, the immutable `EngineCapabilityProfile` declares the exact
supervised report producer contract, a real listener observer and report parser/factory exist, and
the delivered prebound socket-diagnostics handoff performs actual collection under its exact
collector identity/revision. Until both the capture mechanism and report producer are qualified,
the integration-plumbing slice must return `Unsupported` even if every handle, parser, and cleanup
test passes.
Qualified cgroup-BPF remains an alternative only after its independent attachment, identity, loss,
report-object never-created/absence disposition, and lifecycle contract are proven. Production
daemon composition remains `StructuralOnlyCompatibility`. Ordinary BPF counters or sampled events
cannot mint a capture receipt, and production Flux neither loads nor unloads `.ko` modules.

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
    CapabilityConflict,
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

The Phase 1 serialized worker calls `maintain` after each request and after bounded idle timeouts. Maintenance advances pending child reap/backoff without spawning a second child, detaches capture after abnormal exit or uncertain mutation, restarts only after supervisor admission, restores capture, and runs fresh structural plus configured functional verification before retrying pending or invalidated `RUNNING`; `STOPPED` and `FAILED` retries occur only after capture is proven detached. A required-mode `functional_pending` observation is therefore a durable requalification trigger rather than a terminal limbo state. Shutdown uses bounded retries of the same detach-before-stop ordering.

## 18. Kernel I/O runtime

The mandatory target baseline is one custom `epoll` reactor derived from the current `addrsyncd` design. Phase 1 currently integrates the control descriptor and shutdown `signalfd`; nonblocking route/netfilter netlink sockets, timerfd, pidfds, child pipes, and pollable BPF buffers remain later work. It owns TUN queue FDs only in a future `FluxOwnedTunFd` plan; in `EngineOwnedTun`, packet I/O stays entirely inside Sing-Box. Handlers drain bounded batches to `EAGAIN` and yield after a work budget.

Higher-level async tasks communicate through bounded channels. `io_uring` is a separate `FluxOwnedTunFd` TUN I/O Adapter selected only when the FD-handoff contract, `io_uring_setup`, required opcode probes, cancellation, a real TUN read/write smoke test, policy permissions, and device benchmarks all succeed.

## 19. Packaging and build

### 19.1 Build outputs

- `fluxd` for `aarch64-linux-android`;
- optional eBPF object(s), only when a qualified advertised plane is selected, embedded in `fluxd`
  or packaged with verified hashes;
- Sing-Box binary supplied by the release pipeline;
- generated `manifest.json`, SBOM, checksums, and build metadata;
- Magisk-compatible ZIP.

### 19.2 `xtask`

The current bridge implements a deliberately split boundary:

```text
cargo xtask build-android
cargo xtask stage-module --stage <dir> --runtime-binaries <dir>
cargo xtask verify-package --stage <dir>
cargo xtask test-functional-canary-android-x86_64-output-tproxy --serial <serial> [--adb <program>]
```

`stage-module` creates a development tree and does not claim release compliance. The current
`verify-package` is a strict consistency boundary for that temporary hybrid inventory, not a
release-candidate authorization. It requires a clean root worktree and clean `addrsyncd` submodule,
binds their manifest revisions to the exact Git HEADs, byte-compares the
reviewed source-owned module inventory, and rejects every package file outside the exact four
binaries, reviewed module files, declared evidence, and release metadata. Required binaries must
be ELF64 little-endian AArch64 with a bounded file-backed executable entry, congruent load segments,
and either no interpreter or an Android linker path. Manifest sources require a well-formed HTTPS
host/path, immutable revision, version, target, artifact hash, and a recognized SPDX identifier or
explicitly reviewed `LicenseRef`. Schema-1 device evidence is hashed and bound to the exact source
revision plus operational-payload digest, Android build fingerprint, kernel 5.10+ release, boot ID,
verified-boot state, enforcing SELinux, capture time, and the exact required passed test-ID set.
That set is `module_boot`, `status`, `enable_disable`, `restart`, `abnormal_sing_box_exit`,
`dual_stack_tcp_udp_dns`, and `cleanup`.

The x86_64 Android checkpoint command is a separate non-shipping test lane. It produces only a
debug library-test ELF below Cargo `target/`, pushes it to a disposable device directory, and
removes it after the exact test. It never enters `stage-module`, `verify-package`, release build
metadata, required device-test attestations, or the AArch64 package inventory.
SPDX-2.3 package/`documentDescribes` inventories, IDs, and single SHA-256 records must exactly match
the manifest. Pinned Rust/NDK/target build metadata and complete recursive package checksums are
also required. Symbolic links, special files, unsafe paths, hidden or ordinary `.ko`/`.kpm` names,
and unreviewed Magisk root payloads fail.

This command does not authenticate self-authored third-party provenance or unsigned device JSON.
It also verifies a package shape that deliberately still contains temporary bridge components.
Before any rewrite release, the inventory and verifier must be updated to the Rust-only runtime;
standalone `addrsyncd`, `jq`, legacy scripts, and compatibility wrappers must then be rejected rather
than required. Even a pass of the updated verifier is necessary but not sufficient for publication:
ADR-0011's runtime-completion gate and the later `package-magisk` signed/reproducible provenance plus
trusted device/CI attestation gate must also pass. The checked-in manifest intentionally retains
blank third-party fields, so an unqualified development stage must fail this command.

The target release toolchain still requires real-kernel tests, final packaging, and device tests as
later deliverables. `build-ebpf` is required only when an eBPF plane is advertised:

```text
cargo xtask test-linux
cargo xtask package-magisk
cargo xtask device-test --serial <adb-serial>
# only for an advertised eBPF plane:
cargo xtask build-ebpf
```

The final packaging task must additionally reject KPM or any other opaque kernel payload form that
cannot be classified by the current extension checks. Production `fluxd` does not call
`init_module`, `finit_module`, or `delete_module`.

## 20. Pre-release development and removal schedule

| Development checkpoint | Runtime behavior | Releasable? |
|---|---|---|
| Bridge | `fluxd` owns Sing-Box through the atomic runtime coordinator; serialized shell phases still own networking writes | No |
| Shadow compiler | Rust emits deterministic observation-only Capture Programs; no shadow artifact enters a Generation or activation path | No |
| Rust generation bridge | Rust prepares and attests legacy-shaped restore caches; `scripts/tproxy` remains the restore executor/writer | No |
| Canonical xtables lowering | Rust preserves exact schema-v1 forwarded identities and lowers local OUTPUT with pure schema-v2 `O`/`P` transaction metadata, typed routing/listener/escape requirements, and descriptive lifecycle order; five extensions remain rejected and nothing executes | No |
| x86_64 Android mechanism checkpoint | The exact ignored local-OUTPUT TPROXY transaction passes on one rooted WSA development profile with remote cleanup; production execution, receipts, driver, and release matrix remain open | No |
| Native xtables cutover | Rust owns canonical lowering, restore, exact readback, rollback, and the transition lease; replaced shell rule/restore duties are deleted after qualification | No, until all intended runtime duties are Rust-owned |
| PBR/address-sync cutover | Rust owns routing and address-derived rules; standalone `addrsyncd` and shell route writers are removed | No |
| Remaining runtime cutover | Rust owns configuration, subscription, diagnostics, recovery, and offline cleanup; legacy runtime scripts, `jq`/AWK/curl adapters, and wrappers are removed | No |
| Rust-only qualification | Only platform-required install/boot/disable/uninstall glue remains outside Rust; supported runtime scope passes Android, recovery, performance, security, provenance, and packaging gates | Yes, after ADR-0011 and every final gate pass |

None of the bridge, shadow, parity, or partial-cutover checkpoints may be named or published as an
alpha, beta, release candidate, or release. No development checkpoint may have two independent
owners mutating the same kernel objects. The shadow-compiler stage also authorizes no eBPF
attachment/pinning, live-chain integration, TUN activation, implicit module request, `.ko`/KPM
loading, or native netfilter/routing mutation.

The Rust-only gate does not require every optional future backend to ship. A release may explicitly
leave nftables, managed TUN, or eBPF unavailable if at least one fully Rust-owned conventional
Capture Path satisfies the advertised scope and no legacy runtime dependency remains.

Open Phase 1 hardening gates are the production schema-v2 evidence producer, concrete local-OUTPUT
capture/process receipt authorities and executor, actual prebound INET_DIAG collector integration,
and production Android adapter qualification for the functional traffic/loop-prevention
transaction. The development-only WSA mechanism lane is complete but does not reduce the
5.10/ARM64 release matrix. The exact Linux distinct-credential preflight, schema-v2 validator,
strict `/proc` FD plus INET_DIAG collector prerequisite, per-flow capture-receipt/verifier contract,
process-ownership receipt model, and child-origin pidfd substrate are complete. The preflight
explicitly skips or fails unavailable helpers/maps/group authority and rejects root/root or
same-UID substitution, but it is not traffic qualification. Ingress evidence cannot discharge the
local-OUTPUT gate, and REDIRECT/DNAT cannot qualify TPROXY. Also open are an exact-device TUN
single-owner and forced-death route-cleanup canary before removing the current TUN rejection,
ancestor-safe `openat`/`openat2` traversal, bounded rotating Generation-correlated logs,
pidfd/timerfd reactor integration, and real-device evidence on Android kernel 5.10.
