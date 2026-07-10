# Alternative B — Extensible Strategy Fabric Interface

## Design intent

This alternative maximizes flexibility and extension. It treats Flux as a strategy fabric that discovers device facts, composes several independently supplied strategies into candidate Backend Plans, leases a selected plan against the exact facts used to produce it, and executes the resulting transaction graph.

The external Seam is intentionally lower than a common-caller lifecycle Interface and higher than kernel mechanisms. Callers can inspect alternatives, require or forbid semantic capabilities, select a candidate, execute it, query evidence, and observe progress. They cannot submit nft expressions, netlink messages, TUN ioctls, BPF commands, shell text, process arguments, or arbitrary transaction steps.

This is radically different from a minimal `reconcile / snapshot / watch` Controller Module:

- planning and execution are separate operations;
- one request can yield several explainable candidates rather than one hidden fallback choice;
- a candidate is executable only through an opaque lease bound to a Capability Profile, Network Epoch, extension registry, Proxy Engine dialect, and Desired State digest;
- capture, set, routing, Android-policy, Proxy Engine, observation, and I/O strategies are composed through a constraint solver rather than hard-coded as one fallback ladder;
- extensions contribute safe plan fragments and transaction participants through an internal extension Seam;
- low-level I/O remains behind facility ports and production/test Adapters.

The trade is deliberate. Ordinary callers learn more than `enable()` and `reload()`, but expert CLI, UI, diagnostics, automation, conformance tests, and future extensions gain substantially more Leverage. Backend-specific knowledge retains strong Locality inside extensions, while transaction safety remains local to the fabric implementation.

## 1. Concrete Rust Interface

### 1.1 External Interface

```rust
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct FluxFabric {
    inner: Arc<FabricInner>,
}

impl FluxFabric {
    /// Return the immutable registry visible to this daemon instance.
    /// The registry is frozen before the first probe or plan.
    pub fn catalog(&self) -> Arc<ExtensionCatalog>;

    /// Observe the device, refresh required capability evidence, ask registered
    /// strategies for proposals, solve constraints, and return zero or more
    /// executable candidates plus rejected alternatives.
    pub async fn plan(&self, request: PlanRequest)
        -> Result<PlanSet, FabricError>;

    /// Accept an opaque plan lease. The implementation revalidates every bound
    /// revision before mutation and returns a handle once the operation has been
    /// durably accepted by the single writer.
    pub async fn execute(
        &self,
        lease: PlanLease,
        options: ExecuteOptions,
    ) -> Result<ExecutionHandle, FabricError>;

    /// Read one bounded projection. Queries never mutate kernel, Android,
    /// Proxy Engine, or persistent Desired State.
    pub async fn query(&self, query: Query)
        -> Result<QueryResult, FabricError>;

    /// Subscribe to a bounded replay-plus-live event stream. Slow subscribers
    /// lose events explicitly and receive a Gap event requiring a query.
    pub fn subscribe(&self, filter: EventFilter) -> EventStream;
}
```

`FluxFabric` is a concrete handle, not a public trait. Callers and end-to-end tests use the same Interface. Variation lives at internal Seams where at least a production Adapter and a deterministic or fault-injection Adapter exist.

Construction belongs to the daemon composition root:

```rust
pub struct FluxFabricBuilder {
    // Private registry and port bindings.
}

impl FluxFabricBuilder {
    pub fn install<E>(&mut self, extension: E) -> Result<&mut Self, BuildError>
    where
        E: FluxExtension + 'static;

    pub fn bind<P>(&mut self, port: Arc<P>) -> Result<&mut Self, BuildError>
    where
        P: FacilityPort + ?Sized + 'static;

    pub fn build(self) -> Result<FluxFabric, BuildError>;
}
```

The builder is not exposed over the control socket. Extensions are statically linked or packaged as Rust crates selected at build time. Flux does not load arbitrary shared libraries on a rooted device: Rust has no stable plugin ABI, and a dynamically loaded privileged extension would bypass release signing, syscall review, and the safe port model.

### 1.2 Planning request

```rust
#[derive(Debug, Clone)]
pub struct PlanRequest {
    pub desired: Arc<DesiredState>,
    pub selector: StrategySelector,
    pub evidence: EvidencePolicy,
    pub alternatives: AlternativeBudget,
}

#[derive(Debug, Clone, Default)]
pub struct StrategySelector {
    /// Semantic outcomes, not implementation names. Examples:
    /// capture.transparent.tcp, scope.tethered.ipv6, observe.flow-counters.
    pub require: CapabilityExpr,
    pub forbid: CapabilityExpr,

    /// Optional implementation preferences for expert callers. Preferences
    /// influence score; they do not override safety or hard constraints.
    pub prefer: Vec<StrategyPreference>,

    /// When false, any documented loss of Desired State is a no-solution result.
    pub allow_degraded: bool,
}

#[derive(Debug, Clone)]
pub enum StrategyPreference {
    Strategy(StrategyId),
    Extension(ExtensionId),
    Property { id: PropertyId, direction: ScoreDirection },
}

#[derive(Debug, Clone, Copy)]
pub enum EvidencePolicy {
    /// Reuse evidence from this boot when it is still valid for the same
    /// topology, credentials, binaries, cgroup layout, and facility identity.
    FreshWhenInvalid,
    /// Repeat contained probes even when a cache entry is valid.
    ForceRefresh,
    /// Do not perform new probes; useful only for offline explanation/tests.
    CachedOnly,
}

#[derive(Debug, Clone, Copy)]
pub struct AlternativeBudget {
    pub max_candidates: u8,
    pub max_rejections: u16,
    pub planning_deadline: Duration,
}
```

`CapabilityId`, `StrategyId`, `ExtensionId`, and `PropertyId` are validated, namespaced newtypes. They are not arbitrary command names. The catalog defines their schema, stability, and human description. Unknown IDs fail planning rather than being silently ignored.

`DesiredState` remains the complete user-requested Flux behavior. The selector can narrow how that behavior may be realized, but it cannot expand Traffic Scope or weaken Bypass Policy. An expert preference for an eBPF strategy, for example, cannot authorize traffic outside Desired State.

### 1.3 Candidate plans and opaque leases

```rust
#[derive(Debug)]
pub struct PlanSet {
    pub request_id: RequestId,
    pub intent_digest: IntentDigest,
    pub based_on: FactRevisions,
    pub candidates: Vec<PlanCandidate>,
    pub rejected: Vec<RejectedAlternative>,
}

impl PlanSet {
    pub fn preferred(&self) -> Option<&PlanCandidate>;
    pub fn candidate(&self, id: PlanId) -> Option<&PlanCandidate>;
}

#[derive(Debug)]
pub struct PlanCandidate {
    pub id: PlanId,
    pub rank: u16,
    pub summary: PlanSummary,
    pub score: ScoreCard,
    pub provides: CapabilitySet,
    pub degraded: Vec<DegradedBehavior>,
    pub selected: Vec<SelectedStrategy>,
    pub managed_objects: ManagedObjectForecast,
    pub transition: TransitionForecast,
    pub lease: PlanLease,
}

/// Fields are private. It cannot be forged, deserialized from an untrusted
/// client, edited, or reused with another FluxFabric instance.
#[derive(Clone, Debug)]
pub struct PlanLease {
    _sealed: SealedLease,
}

#[derive(Debug, Clone)]
pub struct FactRevisions {
    pub boot: BootId,
    pub network_epoch: NetworkEpoch,
    pub capability_profile: CapabilityRevision,
    pub android_policy: AndroidPolicyRevision,
    pub engine_catalog: EngineCatalogRevision,
    pub extension_registry: RegistryDigest,
    pub active_generation: Option<GenerationId>,
}

#[derive(Debug, Clone)]
pub struct PlanSummary {
    pub capture_path: CapturePathSummary,
    pub set_strategy: SetStrategySummary,
    pub route_strategy: RouteStrategySummary,
    pub engine_dialect: EngineDialectSummary,
    pub android_policy: AndroidPolicySummary,
    pub ebpf: Vec<EbpfStrategySummary>,
    pub io: IoStrategySummary,
    pub explanation: Arc<str>,
}
```

The lease contains a private authenticated reference to the immutable internal plan. It is bound to all `FactRevisions`, the Desired State digest, the exact extension/strategy versions, resource budgets, and an optional bounded lifetime. Serialization of a `PlanCandidate` for a UI omits the executable lease. A remote caller selects a `PlanId`; the local control transport resolves it to a server-held lease.

This prevents a client from constructing low-level operations or replaying a plan built before a VPN, default network, netd rule, Sing-Box binary, capability, or extension changed.

### 1.4 Strategy proposal model

The solver does not understand a fixed `nftables -> xtables -> TUN` ladder. Each extension contributes proposals in a common semantic model:

```rust
#[derive(Debug, Clone)]
pub struct StrategyProposal {
    pub strategy: StrategyId,
    pub role: StrategyRole,
    pub provides: CapabilitySet,
    pub requires: CapabilityExpr,
    pub conflicts: CapabilityExpr,
    pub consumes: ResourceBudget,
    pub score: ScoreVector,
    pub risk: RiskClass,
    pub correctness: CorrectnessClass,
    pub fragment: PlanFragment,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StrategyRole {
    Capture,
    AddressSet,
    PolicyRouting,
    AndroidCoexistence,
    ProxyEngineDialect,
    Observation,
    Acceleration,
    PacketIo,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrectnessClass {
    /// Can satisfy the requested Capture Policy when composed with its stated
    /// requirements.
    CorrectnessPath,
    /// Adds behavior but can disappear without invalidating capture correctness.
    OptionalAugmentation,
    /// Observation only; cannot satisfy a capture requirement.
    ObservationOnly,
}
```

Examples of compositions the solver may produce:

- nftables TPROXY capture + nft interval sets + rtnetlink PBR + Sing-Box TPROXY dialect + optional TC observation;
- xtables TPROXY + ipset `hash:net` swap + rtnetlink PBR + the same engine dialect;
- xtables TPROXY + bounded jump-tree sets when ipset is unavailable;
- managed TUN + Sing-Box TUN dialect + Android VPN coexistence strategy + epoll packet I/O;
- any correct capture composition plus TUN steering eBPF;
- on a future kernel, a verified netfilter-BPF strategy if it provides the required semantics and passes the same conformance contract.

The solver enforces cardinality and safety rules: exactly one correctness Capture Path, exactly one compatible Proxy Engine dialect, one owner for each dispatch point, no mark overlap, no route priority conflict, and no optional acceleration as the sole provider of required behavior.

### 1.5 Execution Interface

```rust
#[derive(Debug, Clone)]
pub struct ExecuteOptions {
    pub supersession: SupersessionPolicy,
    pub verification: VerificationLevel,
    pub client_context: ClientContext,
}

#[derive(Debug, Clone, Copy)]
pub enum SupersessionPolicy {
    Queue,
    ReplaceQueuedSameIntent,
    RejectWhenBusy,
}

#[derive(Debug, Clone, Copy)]
pub enum VerificationLevel {
    Standard,
    Conformance,
}

#[derive(Clone)]
pub struct ExecutionHandle {
    inner: Arc<ExecutionInner>,
}

impl ExecutionHandle {
    pub fn id(&self) -> OperationId;

    /// Each subscriber receives bounded replay followed by live progress.
    pub fn events(&self) -> ExecutionEventStream;

    /// Multiple waiters share one terminal result.
    pub async fn wait(&self) -> Result<ExecutionOutcome, ExecutionError>;

    /// Requests convergence to a safe state. It is not an instruction to stop
    /// between two unsafe transaction steps.
    pub async fn request_cancel(&self) -> CancelDisposition;
}

#[derive(Debug, Clone)]
pub enum ExecutionEvent {
    Accepted { operation: OperationId, plan: PlanId },
    Revalidating { revisions: FactRevisions },
    Preparing { participant: ParticipantId },
    Activating { participant: ParticipantId },
    Verifying { check: VerificationId },
    Compensating { participant: ParticipantId },
    Retiring { generation: GenerationId },
    Published { generation: Option<GenerationId> },
    Gap { after_sequence: EventSequence },
    Terminal(ExecutionTerminalSummary),
}

#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub operation: OperationId,
    pub plan: PlanId,
    pub completion: Completion,
    pub generation: Option<GenerationId>,
    pub previous_generation: Option<GenerationId>,
    pub final_revisions: FactRevisions,
    pub status: Arc<FabricStatus>,
    pub report: Arc<ExecutionReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    NoChange,
    Converged,
    Degraded,
    Disabled,
    Recovered,
}
```

A disabled Desired State is planned and executed like any other transition. There is no separate public `disable()` ordering path to drift away from normal transaction rules. The solver selects a safe detach/retire plan, and the core invariant validator requires capture detachment before Proxy Engine termination.

Dropping the handle or a client connection never abandons accepted work. `request_cancel()` has three outcomes:

- `CancelledBeforeMutation` when the operation was still queued;
- `WillConvergeToSafeState` when preparation or activation has begun;
- `TooLateAlreadyTerminal`.

### 1.6 Query and event Interface

```rust
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum Query {
    Status,
    CapabilityProfile { detail: EvidenceDetail },
    ExplainPlan { plan: PlanId },
    ActiveGeneration,
    ManagedObjects { scope: OwnershipScope },
    Operation { id: OperationId },
    Extension {
        extension: ExtensionId,
        schema: QuerySchemaId,
        payload: BoundedJson,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum QueryResult {
    Status(Arc<FabricStatus>),
    CapabilityProfile(Arc<CapabilityProfileView>),
    PlanExplanation(Arc<PlanExplanation>),
    ActiveGeneration(Option<Arc<GenerationView>>),
    ManagedObjects(Arc<ManagedObjectView>),
    Operation(Arc<OperationView>),
    Extension(ExtensionQueryResult),
}

#[derive(Debug, Clone)]
pub struct EventFilter {
    pub operations: OperationFilter,
    pub kinds: EventKindSet,
    pub extension: Option<ExtensionId>,
    pub replay_after: Option<EventSequence>,
}
```

Built-in queries remain typed. The extension query form exists so a future hook can publish bounded diagnostics without adding a core enum variant. Its JSON schema, size limit, redaction class, and stability are declared in `ExtensionCatalog`. Extension queries are read-only and receive no facility ports.

### 1.7 Internal extension Interface

The extension Interface is not ordinary caller surface. It is available to reviewed, statically linked Flux extensions:

```rust
pub trait FluxExtension: Send + Sync {
    fn manifest(&self) -> ExtensionManifest;

    /// Registration occurs once during build. The registrar accepts only
    /// versioned strategy, evidence, query, and transaction factories.
    fn register(
        self: Arc<Self>,
        registrar: &mut ExtensionRegistrar,
    ) -> Result<(), RegistrationError>;
}

pub trait StrategyFactory: Send + Sync {
    fn descriptor(&self) -> StrategyDescriptor;

    /// Determine whether and how this strategy may participate. Inspection can
    /// request only declared safe probes through ProbePorts.
    fn inspect<'a>(
        &'a self,
        context: InspectContext<'a>,
    ) -> BoxFuture<'a, Result<StrategyEvidence, ExtensionError>>;

    /// Pure planning. No I/O, global reads, process launch, or mutation.
    fn propose(
        &self,
        context: &ProposalContext<'_>,
    ) -> Result<Vec<StrategyProposal>, ExtensionError>;

    /// Bind one solver-selected fragment to safe facility ports and return a
    /// participant whose type enforces transaction ordering.
    fn instantiate(
        &self,
        selected: &SelectedFragment,
        ports: &PortSet,
    ) -> Result<Box<dyn UnpreparedParticipant>, ExtensionError>;
}
```

Transaction ordering is expressed with consuming typestate Interfaces:

```rust
pub trait UnpreparedParticipant: Send {
    fn identity(&self) -> ParticipantIdentity;

    fn prepare(
        self: Box<Self>,
        context: PrepareContext<'_>,
    ) -> BoxFuture<'_, Result<Box<dyn PreparedParticipant>, ParticipantError>>;
}

pub trait PreparedParticipant: Send {
    fn ownership(&self) -> &OwnershipManifest;

    fn activate(
        self: Box<Self>,
        context: ActivateContext<'_>,
    ) -> BoxFuture<'_, Result<Box<dyn ActiveParticipant>, ActivationFailure>>;

    fn abandon(
        self: Box<Self>,
        context: CompensationContext<'_>,
    ) -> BoxFuture<'_, Result<(), ParticipantError>>;
}

pub trait ActiveParticipant: Send {
    fn ownership(&self) -> &OwnershipManifest;

    fn verify<'a>(
        &'a mut self,
        context: VerifyContext<'a>,
    ) -> BoxFuture<'a, Result<VerificationEvidence, ParticipantError>>;

    fn compensate(
        self: Box<Self>,
        context: CompensationContext<'_>,
    ) -> BoxFuture<'_, Result<(), ParticipantError>>;

    fn commit(
        self: Box<Self>,
        context: CommitContext<'_>,
    ) -> BoxFuture<'_, Result<Box<dyn CommittedParticipant>, ParticipantError>>;
}

pub trait CommittedParticipant: Send + Sync {
    fn ownership(&self) -> &OwnershipManifest;

    fn retire(
        self: Box<Self>,
        context: RetireContext<'_>,
    ) -> BoxFuture<'_, Result<(), ParticipantError>>;
}
```

The fabric, not an extension, decides when each method may run. A participant cannot activate before successful preparation because it does not have the required type. A committed participant cannot be silently dropped; the fabric records its ownership and either retains or retires it.

Extensions never receive raw file descriptors owned by another extension, arbitrary syscall functions, a shell executor, or mutable access to the transaction graph. They receive capability-limited safe ports and generation-scoped names. A Linux Adapter may contain audited `unsafe`, but the extension and external Interfaces remain safe Rust.

### 1.8 Core invariants

The following invariants are enforced by the fabric independently of extension claims:

1. Kernels below 5.10 fail before planning can produce an executable lease.
2. A version, config bit, binary path, UAPI constant, or extension claim never proves capability; executable plans require behavioral evidence from the current boot.
3. The extension registry is immutable after `build()`. Registry identity is part of every lease and Generation.
4. Exactly one writer executes kernel, Android-policy, Proxy Engine, and durable-state mutations. Participants may prepare concurrently only when the graph proves their resources independent; activation is ordered by the validated graph.
5. Desired State, Traffic Scope, Capture Policy, and Bypass Policy are immutable inputs to one plan. Extensions may refine implementation but cannot expand scope or delete mandatory bypasses.
6. Every candidate contains exactly one `CorrectnessPath` satisfying required capture semantics. Observation or acceleration proposals cannot fill that role.
7. A Proxy Engine dialect compatible with the selected Sing-Box binary/configuration must be prepared and healthy before any capture activation node can run.
8. Policy-routing prerequisites must verify before a TPROXY dispatch point is attached. TUN routes may activate only after the exact owned TUN identity is ready.
9. Mark masks, rule priorities, table IDs, interface ownership, nft/xtables dispatch points, cgroup hooks, TC/XDP locations, and BPF pin paths are globally conflict-checked across the complete candidate.
10. Every mutation creates or changes only a Managed Object whose ownership is declared before preparation and verified after activation.
11. All participants prepare before the first externally visible capture cutover unless the graph marks an operation as a reversible canary with no production traffic match.
12. Activation uses the smallest available atomic cutover: nft batch, ipset swap plus stable xtables dispatch, generation-map/link switch, or route dispatch after TUN readiness.
13. A Generation becomes authoritative only after all mandatory verification succeeds and its committed ownership record is durably published.
14. The previous verified Generation is retired only after publication of the new one. Cleanup never guesses ownership from a prefix alone.
15. Disable and fatal fail-open compensation detach capture before terminating the Proxy Engine.
16. A plan lease is rejected as stale if any bound revision changed. It is never silently reinterpreted into a different candidate.
17. Extension failure is isolated and attributed. An extension cannot be retried indefinitely, and automatic replanning is bounded to avoid oscillation.
18. Event loss is explicit. A subscriber gap never masquerades as a complete history.

### 1.9 Ordering and concurrency facts

- `catalog()` is available immediately after construction and performs no I/O.
- `plan()` may run concurrently for different Desired States. Device observation and identical probes are deduplicated; pure proposal/solver work can run in parallel.
- Planning never mutates production capture state. Probe mutations use reserved, non-matching, generation-scoped canaries and mandatory cleanup guards.
- `execute()` re-observes lease-critical facts before acceptance. A stale lease returns `PlanStale` with changed revisions and performs no mutation.
- Accepted executions enter a bounded single-writer queue. Equivalent intents may coalesce when both leases resolve to the same immutable internal plan.
- A disabled-state plan has priority over queued non-mutating enabled plans. Once activation starts, cancellation or disable is converted into an ordered safe-state transaction rather than interleaved writes.
- Participant preparation may run concurrently only for disjoint ownership scopes and bounded resources. No lock is held across an external process wait or kernel acknowledgement.
- Activation follows a validated directed acyclic graph. The graph is rejected during planning if it has a cycle, ambiguous owner, missing compensation edge, or violates a core invariant.
- Network Epoch changes during prepare invalidate affected participants. A change after cutover triggers compensation or a follow-up plan; it never splices a new topology into the old transaction.
- `query()` may return cached coherent projections or explicitly perform bounded read-only observation depending on the query. The result states its observation revision and age.
- Event streams use bounded ring storage. Slow readers receive `Gap` and must query current state.

### 1.10 Error Interface

```rust
#[derive(Debug)]
pub struct FabricError {
    pub code: FabricErrorCode,
    pub request: Option<RequestId>,
    pub operation: Option<OperationId>,
    pub plan: Option<PlanId>,
    pub extension: Option<ExtensionId>,
    pub strategy: Option<StrategyId>,
    pub phase: Option<TransactionPhase>,
    pub state_changed: bool,
    pub retry: RetryAdvice,
    pub report: Arc<ErrorReport>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FabricErrorCode {
    UnsupportedKernel,
    InvalidDesiredState,
    UnknownCapability,
    RegistryInvalid,
    ProbeFailed,
    CapabilityDenied,
    NoSolution,
    AlternativeBudgetExceeded,
    PlanStale,
    PlanLeaseInvalid,
    ExtensionFault,
    PortUnavailable,
    OwnershipConflict,
    ResourceLimit,
    QueueFull,
    TransactionFailed,
    VerificationFailed,
    CompensationFailed,
    RecoveryRequired,
    QueryUnsupported,
    DeadlineExceeded,
    InternalInvariant,
}

#[derive(Debug)]
pub struct ExecutionError {
    pub operation: OperationId,
    pub plan: PlanId,
    pub failed_participant: Option<ParticipantId>,
    pub phase: TransactionPhase,
    pub state_changed: bool,
    pub compensation: CompensationReport,
    pub final_status: Arc<FabricStatus>,
    pub retry: RetryAdvice,
    pub report: Arc<ErrorReport>,
}
```

`NoSolution` includes a bounded unsatisfied-constraint explanation: required capability, candidate strategies considered, missing or denied evidence, conflicts, and rejected degraded alternatives. `CapabilityDenied` is distinct from unsupported capability because SELinux/capability remediation differs from a missing kernel facility.

Extension errors preserve extension and strategy identity plus bounded source evidence such as errno, netlink extack, nft/xtables/ipset status, TUN ioctl result, BPF verifier log, or Sing-Box validation output. Ordinary callers receive structured evidence, not adapter-specific Rust error types.

An extension that violates a declared contract, returns inconsistent ownership, panics in an isolated task, exceeds its budget, or repeatedly changes proposals for identical inputs is quarantined for the current boot. The registry remains unchanged, but its strategies become ineligible and the Capability Profile records why. The fabric may replan once when policy permits; it cannot loop forever between failing extensions.

### 1.11 Performance characteristics

- `catalog()` is `O(1)` and returns an immutable `Arc`.
- Planning cost is bounded by `AlternativeBudget`. Fact discovery and probes dominate latency; proposal generation is pure and expected to be linear in registered strategies, while solving is bounded by role/cardinality pruning before combination search.
- The registry rejects unbounded proposal counts. Each strategy has declared maximum proposals, probe time, diagnostic size, and resource forecast.
- Capability evidence is cached only within the current boot and invalidated by relevant revisions. Identical probes are single-flight.
- The solver should normally consider tens, not thousands, of proposals. Candidate generation stops at the requested budget and reports truncation honestly.
- Execution has one writer and bounded preparation concurrency. At most one target Generation, one rollback Generation, and declared canary resources are live beyond the active Generation.
- Trait dispatch and solver metadata exist only in the control plane. TUN packet loops, BPF packet execution, nftables/xtables kernel processing, and Sing-Box data paths do not cross the extension Interface per packet.
- Query and event payloads have hard byte/cardinality limits. Extension JSON is schema-validated and redacted before crossing the external Seam.
- A normal automatic caller can request one candidate and execute the preferred lease, avoiding the cost of materializing a large alternative set.

## 2. Usage examples

### 2.1 Normal automatic caller

The common path is still concise, but planning is explicit:

```rust
async fn converge_from_config(
    fabric: &FluxFabric,
    desired: Arc<DesiredState>,
) -> Result<ExecutionOutcome, AppError> {
    let plans = fabric
        .plan(PlanRequest {
            desired,
            selector: StrategySelector {
                require: CapabilityExpr::all_required_by_desired_state(),
                forbid: CapabilityExpr::none(),
                prefer: vec![
                    StrategyPreference::Property {
                        id: PropertyId::new("transition.atomicity")?,
                        direction: ScoreDirection::Higher,
                    },
                    StrategyPreference::Property {
                        id: PropertyId::new("android.coexistence-confidence")?,
                        direction: ScoreDirection::Higher,
                    },
                ],
                allow_degraded: true,
            },
            evidence: EvidencePolicy::FreshWhenInvalid,
            alternatives: AlternativeBudget {
                max_candidates: 1,
                max_rejections: 32,
                planning_deadline: Duration::from_secs(8),
            },
        })
        .await?;

    let candidate = plans.preferred().ok_or(AppError::NoSafePlan)?;
    tracing::info!(plan = %candidate.id, "{}", candidate.summary.explanation);

    let operation = fabric
        .execute(
            candidate.lease.clone(),
            ExecuteOptions {
                supersession: SupersessionPolicy::ReplaceQueuedSameIntent,
                verification: VerificationLevel::Standard,
                client_context: ClientContext::daemon_boot(),
            },
        )
        .await?;

    Ok(operation.wait().await?)
}
```

The caller does not choose nft commands, marks, routes, BPF program types, TUN flags, or Sing-Box fields. It expresses outcome constraints and scoring preferences.

### 2.2 Expert comparison and explicit selection

An expert CLI can request several candidates and display why one is preferred:

```rust
let plans = fabric
    .plan(PlanRequest {
        desired,
        selector: StrategySelector {
            require: capability_expr!(
                "capture.transparent.tcp" &&
                "capture.transparent.udp" &&
                "scope.local-output"
            ),
            forbid: capability_expr!("hook.xdp.physical-interface"),
            prefer: vec![
                StrategyPreference::Strategy(
                    StrategyId::new("netfilter.nftables-tproxy")?
                ),
                StrategyPreference::Strategy(
                    StrategyId::new("observe.ebpf-tc")?
                ),
            ],
            allow_degraded: false,
        },
        evidence: EvidencePolicy::ForceRefresh,
        alternatives: AlternativeBudget {
            max_candidates: 4,
            max_rejections: 128,
            planning_deadline: Duration::from_secs(20),
        },
    })
    .await?;

for candidate in &plans.candidates {
    print_candidate(candidate);
}
for rejected in &plans.rejected {
    print_rejection(rejected);
}

let chosen = plans
    .candidate(user_selected_plan_id)
    .ok_or(AppError::UnknownPlan)?;
let operation = fabric.execute(chosen.lease.clone(), execute_options).await?;

let mut events = operation.events();
while let Some(event) = events.next().await {
    render_progress(event);
}
let outcome = operation.wait().await?;
```

If the default network or VPN changes between display and execution, `execute()` returns `PlanStale`. It does not silently select a different candidate than the one the user approved.

### 2.3 Adding a future kernel hook

A future upstream `BPF_PROG_TYPE_NETFILTER` extension can be added without changing the external Interface:

```rust
let mut builder = FluxFabricBuilder::new(core_dependencies);

builder
    .bind::<dyn NetfilterBpfPort>(Arc::new(LinuxNetfilterBpfAdapter::new(...)))?
    .install(NetfilterBpfExtension::new(
        NetfilterBpfPolicy {
            minimum_upstream_kernel: KernelVersion::new(6, 4, 0),
            require_real_attach_probe: true,
            allow_vendor_backport_probe: false,
        },
    ))?;

let fabric = builder.build()?;
```

The extension registers namespaced capabilities, a probe, one or more proposals, a transaction factory, conformance checks, diagnostics schema, and resource budgets. The Linux Adapter alone owns BPF syscalls and attach details. Tests bind a `ModelNetfilterBpfAdapter` to the same port and exercise the fabric through `plan()` and `execute()`.

## 3. Implementation hidden behind the external Seam

### 3.1 Frozen extension registry

`FluxFabricBuilder` validates manifests before any extension code can plan:

- unique extension, strategy, capability, property, query-schema, and participant IDs;
- compatible core Interface version range;
- declared required facility ports;
- proposal/probe/resource/diagnostic limits;
- capability definitions with stability and redaction metadata;
- no duplicate ownership of a reserved core invariant or semantic capability;
- deterministic manifest digest.

`build()` binds every required port, constructs a registry digest, and freezes the registry. There is no install/uninstall while running. Upgrading an extension means upgrading/restarting `fluxd`, which creates a new registry revision and invalidates old leases.

### 3.2 Fact graph and Capability Profile

The implementation maintains a typed fact graph rather than backend booleans. Facts include:

- kernel release and boot identity;
- behavioral probe evidence, errno, extack, verifier output, and denial reason;
- Android network topology and Network Epoch;
- netd/vendor rule, mark, route, qdisc, cgroup, VPN, tethering, CLAT, and interface observations relevant to Flux;
- exact Sing-Box binary identity, version, supported configuration dialects, and runtime probes;
- currently active Generation and Managed Objects;
- resource budgets and SELinux/capability context.

Each fact declares its provenance, revision dependencies, freshness, and invalidation triggers. For example, an nft TPROXY canary may remain valid for the boot until credentials, executable identity, net namespace, module state, or a structural runtime failure changes. An XDP attach result is scoped to an interface index and mode, not the whole device.

Probe ports permit only contained operations. Probe resources use reserved generation-scoped names and RAII cleanup. A crash leaves a recognizable probe journal entry that recovery can remove without scanning foreign state.

### 3.3 Proposal collection and constraint solving

Planning has five steps:

1. normalize and validate Desired State;
2. determine which semantic capabilities are required by Traffic Scope, Capture Policy, Bypass Policy, failure policy, and requested diagnostics;
3. refresh only evidence needed by potentially eligible strategies;
4. collect bounded pure proposals from extensions;
5. solve for compatible strategy sets, validate core invariants, score, and materialize candidate transaction graphs.

The solver separates semantic capability from implementation. `capture.transparent.udp` may be provided by an nftables TPROXY proposal, an xtables TPROXY proposal, or a TUN proposal, each with different requirements and limitations. `address-set.large-ipv6` may come from nft interval sets, ipset, or a bounded tree. An Android VPN coexistence strategy may forbid one capture proposal, require a mark reservation strategy, or reduce its confidence score.

Hard constraints decide eligibility. Scores decide ranking only among valid candidates. Risk or preference cannot override missing correctness, ownership conflict, unsupported Traffic Scope, or a denied mandatory operation.

Every rejected proposal retains an explanation edge such as:

```text
netfilter.nftables-tproxy
  rejected because requires kernel.nft.expr.socket-transparent
  evidence: denied (EPERM), SELinux context u:r:magisk:s0

netfilter.xtables-tproxy + sets.ipset-hashnet
  valid, score 81

capture.singbox-tun
  valid but degraded: tethered IPv6 scope not proven on this device
```

This makes adaptive behavior inspectable rather than embedding fallback decisions in nested `if` statements.

### 3.4 Transaction graph compiler

Selected `PlanFragment`s are combined into a directed acyclic graph of declarative participant dependencies. Extensions can declare dependencies and ownership claims but cannot directly edit another fragment or bypass core edges.

Core graph rules inject mandatory ordering:

```text
observe/revalidate
      |
prepare all independent participants
      |
persist Prepared Generation
      |
Proxy Engine validate -> stage -> ready
      |
routing prerequisites / TUN identity
      |
capture atomic cutover
      |
mandatory verification
      |
publish active Generation
      |
retire previous Generation
```

Optional observation may attach before capture only when it cannot change packet decisions. Acceleration attaches after its correctness path exists and verifies fail-safe behavior. Disable uses the reverse safety relationship: detach capture, remove routing/auxiliary objects, then stop the Proxy Engine.

The compiler rejects cycles, ambiguous owners, unbounded resources, missing compensation, and participants whose declared Managed Objects overlap foreign or active objects without an explicit replace relationship.

### 3.5 Transaction runtime

The single-writer runtime:

- revalidates lease revisions;
- writes an accepted operation record;
- instantiates selected participants through their factories and safe ports;
- prepares independent participants with bounded concurrency;
- persists the prepared Generation;
- activates in graph order;
- verifies mandatory semantic outcomes, not merely syscall success;
- commits participant ownership tokens;
- publishes the active Generation durably;
- retires the previous Generation;
- emits a coherent terminal event and status.

If a step fails, it compensates active participants in reverse dependency order, abandons prepared participants, re-observes device state, and reports whether the result is the prior Generation, the target Generation, or clean fail-open. It never assumes compensation succeeded because an Adapter returned no error; required ownership and dispatch points are read back.

Typestate participant Interfaces give Locality to phase-specific cleanup. The nftables extension understands nft batch rollback; the ipset extension understands post-swap name ownership; the BPF extension understands links, maps, pins, and verifier evidence; the TUN extension understands queue FDs and link identity. The fabric understands only their declared ownership, dependencies, semantic verification, and transaction state.

### 3.6 Android policy extensions

Android variation is modeled as strategies and facts, not conditionals spread across capture Adapters. Built-in extensions may include:

- mark/rule-priority allocator for observed netd/vendor state;
- VPN coexistence policy for VPN-underlay, VPN-over-Flux, or explicit refusal;
- tethering/interface-role classifier;
- CLAT/NAT64 inventory and bypass policy contributor;
- Android user/package-to-UID compiler;
- physical-interface TC/XDP conflict guard;
- network-handover hysteresis strategy.

These extensions can constrain or score capture proposals and add Managed Objects, but cannot mutate the device outside a selected transaction. This placement gives Locality to Android-version/vendor knowledge without allowing it to bypass Generation ordering.

### 3.7 Sing-Box dialect extensions

Sing-Box integration is split into a true-external `ProxyEnginePort` and in-process dialect strategies. A dialect strategy declares:

- supported binary version range and feature probes;
- accepted inbound mode: TPROXY, redirect where applicable, or TUN;
- fields and defaults it owns;
- route/TUN ownership expectations;
- transparent socket, mark, DNS, and UDP behavior;
- validation and readiness contract;
- reload versus staged-restart behavior;
- redaction rules for generated configuration and errors.

Adding support for a new Sing-Box version normally adds or updates one dialect extension and its fixtures. Capture extensions depend on semantic engine capabilities, not version strings or JSON field names. This gives strong Locality to version drift.

### 3.8 No unsafe syscall escape hatch

There is intentionally no `RawKernelOperation`, `run_command(String)`, arbitrary ioctl number, raw netlink byte buffer, raw BPF command, or inherited-FD list in the extension Interface.

Facility ports accept validated typed specifications and enforce cross-cutting safety:

- generation-scoped names and ownership manifests;
- fixed executable paths and argument vectors where a userspace tool is unavoidable;
- no shell interpretation;
- bounds on messages, sets, maps, verifier logs, and command output;
- `CLOEXEC` and explicit FD transfer;
- reserved mark masks/priorities;
- refusal to delete or replace unowned objects;
- extack/errno/status preservation;
- audit correlation with operation, plan, participant, and Generation IDs.

New kernel functionality requires a new reviewed port plus at least Linux and model/test Adapters. It does not require weakening ordinary callers or every extension.

## 4. Dependency categories, ports, and Adapters

### 4.1 Dependency classification

| Category | Dependency | Port at the internal Seam | Production Adapter | Test Adapter | Why the Seam is real |
|---|---|---|---|---|---|
| In-process | Desired State normalization, semantic capability algebra, proposal solver, graph validation, scoring, state reduction | None | Same pure Rust implementation | Same implementation with property/fuzz inputs | Always deepenable; an Adapter would add indirection without variation |
| Local-substitutable | NETLINK_ROUTE observation and mutation | `RoutePort` / `NetworkInventoryPort` | `LinuxRtnetlinkAdapter`, retaining the current event-driven reactor | `ModelRouteAdapter`, `ReplayNetworkAdapter` | Real kernel and deterministic/loss-injection behavior both matter |
| Local-substitutable | nftables | `NftPort` | bundled/verified `nft` JSON Adapter initially, later native nfnetlink Adapter | `ModelNftAdapter`, namespace conformance Adapter | Multiple production implementations plus test model justify the port |
| Local-substitutable | xtables | `XtablesPort` | coherent legacy or nft-mode restore Adapter selected by probe | `ModelXtablesAdapter`, command-failure Adapter | Compatibility path and fault injection vary independently |
| Local-substitutable | ipset | `IpSetPort` | protocol/restore/swap Adapter | `ModelIpSetAdapter` with pre/post-swap failures | Swap ownership and revision behavior need deterministic tests |
| Local-substitutable | TUN | `TunPort` | direct `/dev/net/tun` and rtnetlink Adapter | `ModelTunAdapter`, namespace TUN Adapter | Creation, multiqueue, offload, and queue failures vary |
| Local-substitutable | eBPF facilities | separate `TcBpfPort`, `CgroupBpfPort`, `TunBpfPort`, `XdpPort`, future `NetfilterBpfPort` | Aya/Linux Adapters; optional libbpf-rs conformance Adapter | Model and verifier-fixture Adapters | Different hooks have different ownership/coexistence contracts; one generic BPF port would be shallow |
| Local-substitutable | Android policy facts | `AndroidPolicyPort` | procfs/package/netd/cgroup/VPN observation Adapter | Recorded-device Adapter | Vendor and network-state replay are essential |
| Local-substitutable | durable generations/journal | `GenerationStorePort` | symlink-safe Android filesystem Adapter | memory/tempfs/crash-point Adapters | Recovery must be tested at write/fsync/rename boundaries |
| Local-substitutable | clock, boot ID, entropy, process identity | focused ports | Linux/Android Adapters | deterministic Adapters | Makes lease expiry, recovery, IDs, and backoff reproducible |
| True external | Sing-Box process and configuration validator | `ProxyEnginePort` | `SingBoxProcessAdapter` | scripted/mock engine and recorded-version Adapters | Third-party behavior/version changes; tests must not depend on a real child |
| True external | subscription endpoint | Separate Subscription Module port, outside execution fabric | bounded HTTP/file Adapter | recorded fixtures/mock Adapter | Retrieval is not required for local planning/execution and should not reduce boot reliability |
| Remote but owned | None in the current runtime | None | None | None | Do not invent a port until an owned remote dependency exists |

### 4.2 Facility port shape

Ports are narrow around coherent facilities rather than one universal kernel Interface. Representative examples:

```rust
pub trait NftPort: FacilityPort {
    fn probe<'a>(
        &'a self,
        spec: &'a NftProbeSpec,
        scope: ProbeScope,
    ) -> BoxFuture<'a, Result<NftEvidence, PortError>>;

    fn prepare<'a>(
        &'a self,
        program: &'a OwnedNftProgram,
        scope: GenerationScope,
    ) -> BoxFuture<'a, Result<PreparedNft, PortError>>;

    fn observe_owned<'a>(
        &'a self,
        owner: &'a OwnerId,
    ) -> BoxFuture<'a, Result<NftSnapshot, PortError>>;
}

pub trait TunPort: FacilityPort {
    fn probe<'a>(
        &'a self,
        spec: &'a TunProbeSpec,
        scope: ProbeScope,
    ) -> BoxFuture<'a, Result<TunEvidence, PortError>>;

    fn prepare<'a>(
        &'a self,
        spec: &'a OwnedTunSpec,
        scope: GenerationScope,
    ) -> BoxFuture<'a, Result<PreparedTun, PortError>>;

    fn observe<'a>(
        &'a self,
        identity: &'a TunIdentity,
    ) -> BoxFuture<'a, Result<Option<TunSnapshot>, PortError>>;
}

pub trait ProxyEnginePort: FacilityPort {
    fn inspect<'a>(
        &'a self,
        binary: &'a EngineBinary,
    ) -> BoxFuture<'a, Result<EngineEvidence, PortError>>;

    fn validate<'a>(
        &'a self,
        spec: &'a EngineSpec,
    ) -> BoxFuture<'a, Result<ValidatedEngineSpec, PortError>>;

    fn stage<'a>(
        &'a self,
        spec: ValidatedEngineSpec,
        scope: GenerationScope,
    ) -> BoxFuture<'a, Result<StagedEngine, PortError>>;
}
```

Prepared/active tokens returned by ports own their resources and expose only phase-safe operations. An extension cannot obtain a raw TUN FD merely because it can plan a TUN strategy. A dedicated, reviewed packet-I/O extension may receive an `OwnedTunQueues` token through a declared transfer edge, and the graph records that ownership move.

Avoid a single `KernelPort::execute(Vec<KernelOperation>)`: it would merely move raw complexity into an enum, give every extension knowledge of every facility, and create a shallow Module. Separate ports keep knowledge and verification local.

### 4.3 Port registry

`PortSet` is type-indexed and immutable after build. A strategy manifest declares required port type IDs; missing or duplicate bindings fail construction. Extensions can request only declared ports, and the registrar verifies that their transaction factories do not acquire undeclared facilities.

This design lets a future hook add `FooHookPort`, `LinuxFooHookAdapter`, and `ModelFooHookAdapter` without changing `FluxFabric`, unrelated extensions, or ordinary tests. It does add an internal Seam, but two real Adapters justify it.

### 4.4 Testing through the external Interface

The primary test surface is `catalog / plan / execute / query / subscribe`, not internal strategy methods. Full fabric tests bind model Adapters, install the same production strategy extensions, and assert:

- candidate composition and rejection explanations;
- lease staleness after fact revision changes;
- activation and compensation outcomes;
- final FabricStatus, Generation, and Managed Object view;
- no modification of modeled foreign objects;
- deterministic events including explicit gaps;
- extension quarantine and bounded replanning.

Focused tests still exist for pure solver mathematics, typed port specifications, unsafe Linux Adapter code, and each extension's conformance suite. They supplement rather than layer assertions on the fabric's private state machine.

Each strategy extension ships a contract suite that runs against all of its Adapters. For example, nftables runs against the JSON/process Adapter, future native nfnetlink Adapter, and model Adapter. The same semantic vectors must produce equivalent Managed Objects and verification evidence.

## 5. Trade-offs in Depth, Locality, and Seam placement

### 5.1 Depth

The external Module has high Depth for expert and extensibility-oriented callers. Five operations cover device discovery, adaptive capability probes, multi-strategy solving, safe transaction compilation, crash recovery, progress, diagnostics, and future extension queries. A caller can compare nftables, xtables/ipset, TUN, and eBPF combinations without learning their syscalls or activation order.

Its Depth is lower for the simplest caller than Alternative C's lifecycle verbs. A boot caller must request a plan, take the preferred lease, and execute it. The design can hide that ceremony in a separate `BootConverger` Module, but the fabric's primary Interface remains plan-oriented. This is the cost of making plan choice and explanation first-class rather than an implementation detail.

The extension Interface is intentionally less deep than the external Interface. Extension authors must understand proposals, capability algebra, ownership, transaction phases, compensation, and ports. That complexity is unavoidable for code that adds privileged mechanisms. The Interface still provides Leverage by centralizing solving, ordering, journaling, concurrency, eventing, evidence, and recovery so each extension does not reimplement them.

The deletion test is favorable: deleting the fabric would redistribute constraint solving, plan staleness, lifecycle ordering, ownership, compensation, and diagnostics across every backend and caller. Deleting an individual extension removes its mechanism-specific knowledge rather than causing core changes.

### 5.2 Locality

This design creates two kinds of Locality:

1. **Mechanism Locality.** nftables encoding/probing/rollback lives in the nft extension and its port Adapters; ipset swap semantics live in the ipset extension; BPF hook/version/verifier knowledge lives in hook-specific extensions; Sing-Box JSON/version drift lives in dialect extensions.
2. **Cross-mechanism Locality.** ownership, transaction ordering, plan leases, one-writer concurrency, journaling, status, event gaps, resource budgets, and safety invariants live once in the fabric.

The main Locality risk is metadata-driven behavior. A bug in a proposal's `provides/requires/conflicts` declaration can affect solver output without looking like ordinary control flow. Mitigations are manifest validation, semantic capability ownership rules, deterministic plan snapshots, extension contract suites, and conformance verification after activation.

Another risk is over-fragmentation: splitting every helper into an extension would scatter knowledge and make the registry harder to understand. An extension should own a coherent variable mechanism or policy with at least a production and test Adapter. Pure helpers remain inside the nearest Module.

### 5.3 External Seam placement

The external Seam sits between intent and a safe executable plan. It exposes more planning truth than a high-level lifecycle Controller but withholds mutation primitives. This placement is appropriate when:

- users need to compare or pin mechanisms;
- device fleets vary substantially;
- future kernel hooks are expected;
- conformance tooling needs candidate/rejection evidence;
- Android coexistence policy and Proxy Engine dialects evolve independently;
- test suites must install different strategy and port Adapters.

It is less appropriate if nearly every caller only wants enable/disable/reload and expert selection is rare. In that world a deeper lifecycle Interface gives better Leverage per fact learned.

### 5.4 Internal extension Seam placement

The extension Seam sits at semantic proposals and transaction participants, not at raw kernel operations. This preserves flexibility in strategy composition while keeping syscall safety and ownership in facility ports.

Placing the Seam higher, at only a complete Backend Plan Adapter, would make extensions simpler but prevent mixing nft capture with independent set, Android, engine, observation, and I/O strategies. Placing it lower, at raw netlink/ioctl/BPF commands, would maximize mechanism freedom but destroy safety, Locality, and testability. The chosen placement lets strategies vary and compose while the fabric retains non-negotiable transaction invariants.

### 5.5 Port Seam placement

Facility ports are private internal Seams. They exist where production and model/fault Adapters both provide real value. Keeping nftables, xtables, ipset, TUN, route, and BPF hook ports separate avoids a universal shallow kernel Interface and keeps unsafe UAPI knowledge local.

The cost is more wiring and more contract suites. A new genuinely different kernel facility may require a new port in addition to an extension. That is desirable friction: privileged low-level capability should not enter the system merely by adding a stringly operation to a generic executor.

### 5.6 Flexibility versus predictability

Constraint solving produces more flexibility than a fixed fallback order, but also more possible compositions. Predictability comes from:

- immutable registry and versioned manifests;
- deterministic proposals for identical facts;
- hard cardinality/safety constraints;
- explicit score cards;
- bounded candidate counts;
- plan leases tied to exact revisions;
- persisted plan/extension digests;
- post-activation semantic verification.

Configuration should offer stable high-level modes that compile to selectors. Most users should not write capability expressions. The expert selector exists for diagnostics, fleet policy, and future extension use, not as a requirement for ordinary operation.

### 5.7 Performance and operational cost

Planning is more expensive than a fixed `match` statement. The implementation pays for fact provenance, probe invalidation, proposal collection, solving, and explanation. That cost is on control-plane transitions, not per packet, and is bounded/cached. In exchange it avoids ad hoc fallback retries during mutation and produces a complete executable transaction before traffic cutover.

The extension model increases binary size and compile-time dependency surface when many strategies are linked. Release profiles should install only supported built-ins, while test binaries can install additional experimental extensions. Runtime dynamic loading is rejected.

Operationally, the plan/lease split makes UI and automation richer but requires server-held leases and stale-plan handling. It also makes user approval meaningful: the candidate executed is the candidate displayed, or execution fails before mutation.

## Final position

Alternative B is the strongest choice when extensibility is a primary architectural goal rather than a secondary implementation detail. It can add nftables encoders, xtables variants, ipset types, managed TUN modes, eBPF hooks, Android coexistence policies, Sing-Box dialects, packet-I/O engines, and deterministic test Adapters without expanding ordinary callers into syscall programmers.

Its defining design choices are:

- a plan/lease/execute external Interface;
- semantic capability composition instead of a hard-coded backend ladder;
- statically linked extensions in a frozen registry;
- typestate transaction participants;
- safe facility ports with Linux and model Adapters;
- a core-owned invariant validator and single writer;
- no unsafe raw-operation escape hatch.

The price is a wider Interface, more internal contracts, solver/metadata complexity, and more wiring than a minimal Controller Module. That price buys extension Leverage and mechanism Locality while preserving the safety properties required by a privileged Android networking daemon.
