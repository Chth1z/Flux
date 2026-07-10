# Alternative C — Common-Caller Flux Controller Interface

## Design intent

This alternative optimizes the external Flux Controller Module for the callers that dominate normal operation: the CLI transport, Magisk boot glue, a local control socket handler, and a UI status reader. Those callers should not need to understand Desired State compilation, Capability Profiles, Backend Plans, Sing-Box process identity, kernel transactions, or crash journals.

The external Seam therefore sits above all reconciliation policy. Its Interface is five zero-argument operations on one concrete, cloneable Rust handle:

- recover after boot or a daemon crash;
- enable Flux;
- disable Flux;
- reload the current configuration sources;
- read a coherent status snapshot.

The Controller Module has high Depth for these callers: five operations exercise configuration migration, generation compilation, adaptive backend selection, Sing-Box supervision, nftables or xtables/ipset or TUN activation, optional eBPF, drift repair, and journal recovery. That Depth gives every caller the same lifecycle behavior and concentrates change in one place for strong Locality.

This is deliberately a concrete Module rather than a public trait. External tests exercise the real Controller implementation through the same Interface as production callers, while replacing dependencies at private internal Seams. A public mock of the Controller would test callers against a second implementation of lifecycle semantics and weaken the Interface as the test surface.

## 1. Concrete Rust Interface

```rust
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct FluxController {
    inner: Arc<ControllerInner>,
}

impl FluxController {
    /// Reconstruct reality from the journal and the device, compensate for an
    /// interrupted transaction, then converge to the persisted Desired State.
    pub async fn recover_boot(&self) -> Result<ControlReport, ControlError>;

    /// Persist AdministrativeState::Enabled and converge to it.
    pub async fn enable(&self) -> Result<ControlReport, ControlError>;

    /// Persist AdministrativeState::Disabled, detach capture, remove only
    /// Flux Managed Objects, and then stop the Proxy Engine.
    pub async fn disable(&self) -> Result<ControlReport, ControlError>;

    /// Re-read local configuration and the current immutable Subscription
    /// Snapshot, compile it, and converge if Flux is enabled.
    pub async fn reload(&self) -> Result<ControlReport, ControlError>;

    /// Return the latest coherent snapshot. This performs no I/O and cannot
    /// mutate the device.
    pub fn status(&self) -> Arc<FluxStatus>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    RecoverBoot,
    Enable,
    Disable,
    Reload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completion {
    /// Desired State and Observed State already agreed; health was verified.
    NoChange,
    /// A Generation was prepared, activated, verified, and made authoritative.
    Converged,
    /// Desired State was reached with documented optional capabilities absent.
    Degraded,
    /// An interrupted operation was repaired without changing the target state.
    Recovered,
}

#[derive(Debug, Clone)]
pub struct ControlReport {
    pub operation_id: OperationId,
    pub action: ControlAction,
    pub completion: Completion,
    pub generation: Option<GenerationId>,
    pub previous_generation: Option<GenerationId>,
    pub backend: Option<BackendPlanSummary>,
    pub elapsed: Duration,
    /// The coherent snapshot published at this operation's linearization point.
    pub status: Arc<FluxStatus>,
}

#[derive(Debug, Clone)]
pub struct FluxStatus {
    /// Monotonically increasing within one daemon process.
    pub sequence: StatusSequence,
    pub observed_at: WallClockTime,
    pub observation_age: Duration,
    pub boot_id: Option<BootId>,
    pub kernel: Option<KernelVersion>,
    pub desired_administrative_state: AdministrativeState,
    pub runtime_state: RuntimeState,
    pub active_generation: Option<GenerationSummary>,
    pub backend: Option<BackendPlanSummary>,
    pub engine: EngineHealthSummary,
    pub capabilities: CapabilitySummary,
    pub network_epoch: Option<NetworkEpoch>,
    pub drift: DriftSummary,
    pub pending: Option<PendingOperationSummary>,
    pub last_success: Option<OperationSummary>,
    pub last_error: Option<Arc<ErrorReport>>,
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeState {
    Starting,
    Recovering,
    Stopped,
    Reconciling(ReconcilePhase),
    Running,
    Degraded,
    Failed,
    UnsupportedKernel,
}

#[derive(Debug)]
pub struct ControlError {
    pub code: ControlErrorCode,
    pub operation_id: OperationId,
    pub generation: Option<GenerationId>,
    pub phase: Option<ReconcilePhase>,
    /// True if any persistent or kernel state changed before the error.
    pub state_changed: bool,
    pub compensation: CompensationResult,
    pub retry: RetryAdvice,
    pub report: ErrorReport,
    /// The coherent snapshot published after compensation and re-observation.
    pub status: Arc<FluxStatus>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlErrorCode {
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
    Overloaded,
    Superseded,
    ControllerUnavailable,
    InternalInvariant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAdvice {
    SafeImmediately,
    After(Duration),
    AfterUserAction,
    DoNotRetry,
}
```

The application composition root injects dependencies through a crate-private `ControllerWiring` and constructs `FluxController`. Construction is intentionally not part of the operator Interface: CLI, socket, UI, and boot callers receive an already assembled handle and never learn kernel or process dependencies.

### 1.1 Operation facts

| Operation | Required facts a caller must know | Terminal success |
|---|---|---|
| `recover_boot()` | Safe to call repeatedly or concurrently. All callers join the same recovery for the current boot ID. It first observes the journal, Proxy Engine, Android networks, and Flux-owned kernel state; it never assumes the last journal write completed. | The prior Generation, target Generation, or a clean fail-open state has been proved, and persisted Desired State has then been reconciled. |
| `enable()` | Sets the persisted administrative intent to enabled and reads the latest local configuration sources. It does not download a subscription. | `Running`, `Degraded`, or `NoChange`, with the target Proxy Engine ready before traffic capture is attached. |
| `disable()` | Has priority over queued enable/reload work. It preserves configuration and journal history. | Capture is detached first, only Flux Managed Objects are removed, and the Proxy Engine is stopped last. Repeated calls return `NoChange`. |
| `reload()` | Preserves the current administrative intent. It re-reads local config and the already published Subscription Snapshot. If disabled, it validates and records the new Desired State without starting Sing-Box or attaching capture. | When enabled, a verified Generation is active or the active digest already matches. When disabled, the new Desired State is valid and runtime state remains `Stopped`. |
| `status()` | Callable before, during, or after recovery. It is a cached coherent snapshot, not a request to probe or reconcile. Callers must use `observation_age` when freshness matters. | Always returns a snapshot; initial construction can legitimately report `Starting`. |

Remote subscription refresh, dry-run planning, detailed capability evidence, and diagnostic bundle creation are not smuggled into `reload()` or `status()`. They belong to separate maintenance/inspection Modules so the common Interface remains deep and predictable.

### 1.2 Invariants hidden but guaranteed at the Interface

1. The running kernel must be at least 5.10. An older kernel produces `UnsupportedKernel` before any persistent mutation.
2. Kernel version is only a probe gate. Optional capability selection requires behavioral evidence from the current boot's Capability Profile.
3. Exactly one Controller task writes Flux-owned kernel state. Concurrent callers are linearized; kernel mutations from two Generations never interleave.
4. Every compiled Generation is immutable and content-addressed. Equal normalized inputs produce an equal desired digest and therefore an idempotent `NoChange` path.
5. A new Capture Path is never attached until the generation-specific Sing-Box child has passed configuration validation and readiness checks.
6. A successful report is returned only after prepare, activate, verify, durable active-record publication, and safe retirement or retention of the prior Generation.
7. Disable and fatal fail-open recovery detach capture before stopping Sing-Box.
8. Cleanup and compensation remove only Managed Objects whose ownership can be proved from names, metadata, and the journal.
9. An explicit nftables, xtables, TUN, or eBPF request never silently changes mechanism. Automatic fallback is allowed only for an `auto` preference and is reported as a Backend Plan or Degraded State.
10. eBPF is optional for correctness. Unsupported BTF, verifier, program type, attach, map, cgroup, or TC behavior can demote eBPF for the current boot without disabling a working nftables, xtables/ipset, or TUN Capture Path.
11. After every failed or interrupted kernel mutation, Observed State is read again before rollback, compensation, or a returned error.
12. The default failure policy is fail-open. Fail-closed behavior requires explicit Desired State and is never inferred from a backend failure.
13. Dropping or timing out the caller's Rust future does not cancel an accepted mutation. The Controller completes or compensates it; a retry is safe because operations are idempotent by Desired State and Generation digest.
14. `ControlReport.status` and `ControlError.status` are published at the operation's terminal linearization point, so a caller does not need a racy follow-up `status()` call.

### 1.3 Ordering and concurrency

The caller-visible ordering is intentionally small:

- No caller is required to call `recover_boot()` first. The first mutating operation automatically joins the same internal boot-recovery gate. The explicit method exists so `fluxd daemon` can make boot progress and failure visible before opening its mutating control socket.
- Calls are ordered by acceptance, except that `disable()` enters a priority lane. It may supersede queued, not-yet-mutating enable/reload work. Superseded callers receive `ControlErrorCode::Superseded` with `state_changed = false`.
- If disable arrives during prepare, the uncommitted target is discarded and disable proceeds. If it arrives during an activation step that cannot be interrupted safely, the Controller completes compensation and re-observation before detaching capture.
- Equivalent simultaneous enable or reload requests share one reconciliation result once they resolve to the same desired digest.
- The command mailbox is bounded (default 64 accepted operations). Saturation returns `Overloaded` before mutation; `status()` remains available because it does not use the mutation mailbox.
- Once shutdown begins, new mutations return `ControllerUnavailable`; the last published status remains readable.

### 1.4 Error facts

Every error crosses the Seam with enough evidence for a caller to decide what to display or retry, without exposing implementation types:

- a stable `ControlErrorCode` and redacted human report;
- operation and optional Generation identity;
- failed transaction phase;
- capability/backend context, including the selected and rejected plan when relevant;
- preserved `errno`, netlink extack, xtables command status, TUN ioctl result, or bounded eBPF verifier excerpt inside `ErrorReport`;
- whether state changed;
- whether compensation succeeded, partially succeeded, failed open, or requires recovery;
- explicit retry advice;
- a coherent post-error status snapshot and diagnostic correlation ID.

`CapabilityUnsupported` means the requested mechanism was behaviorally absent. `CapabilityDenied` means it appeared present but credentials or SELinux denied the required operation. These are not interchangeable because their remediation differs. Structural unsupported errors discovered after selection demote that capability for the current boot, trigger one Backend Plan recompilation when `auto` permits it, and are returned only if no valid plan converges.

### 1.5 Performance characteristics

- `status()` is `O(1)`, performs no syscalls, does not wait for the writer task, and returns an `Arc` to an immutable snapshot published through `ArcSwap` or an equivalent read-optimized primitive. The target is below 1 ms even while reconciliation is active.
- Mutating methods wait for a terminal report. They can take seconds because readiness and kernel verification are part of success. A transport that wants a client timeout applies it outside this Interface; cancellation does not abandon the accepted transaction.
- Boot recovery and initial enabled reconciliation target verified `Running` or `Degraded` within 5 seconds after Android boot readiness on the baseline device, excluding remote subscription retrieval.
- `enable()` and `reload()` perform no unbounded network I/O. Configuration bytes, decoded Subscription Snapshot size, node/rule/set counts, verifier logs, child logs, and journal history all have explicit resource budgets. Budget violations return `ResourceLimit`; data is never silently truncated into a different policy.
- Generation compilation is deterministic pure computation. CIDRs and ranges are canonicalized and sorted, giving expected `O(n log n)` compile cost; backend emission is linear in the bounded compiled policy.
- Kernel activation minimizes externally visible transition time: one nftables batch, an ipset swap plus atomic xtables dispatch restore, a Generation-ID publication after eBPF map population/attachment, or routing activation after the managed TUN device is ready.
- The Controller holds at most one active target, one rollback candidate, and one uncommitted prepared Generation in memory. Event and command queues are bounded.

## 2. Common-caller usage

The local control transport maps ordinary commands one-for-one. It does not construct a reconciliation request or select a backend:

```rust
async fn serve_command(
    controller: &FluxController,
    command: CliCommand,
) -> Result<WireReply, WireError> {
    let reply = match command {
        CliCommand::Enable => WireReply::Report(controller.enable().await?),
        CliCommand::Disable => WireReply::Report(controller.disable().await?),
        CliCommand::Reload => WireReply::Report(controller.reload().await?),
        CliCommand::Status => WireReply::Status(controller.status()),
    };

    Ok(reply)
}
```

The Magisk boot path is equally small:

```rust
pub async fn boot(controller: FluxController) -> ExitCode {
    match controller.recover_boot().await {
        Ok(report) if report.status.runtime_state.is_operational_or_stopped() => {
            ExitCode::SUCCESS
        }
        Ok(_) => ExitCode::FAILURE,
        Err(error) => {
            emit_boot_error(&error);
            ExitCode::FAILURE
        }
    }
}
```

Shell glue only launches `fluxd daemon` and may apply bounded restart backoff. It does not choose nftables versus xtables, install rules, start Sing-Box directly, or interpret the recovery journal.

## 3. Implementation hidden behind the Seam

`FluxController` is a cheap handle to a private actor-like writer task. Cloneable handles send typed commands over bounded Tokio channels and receive results over one-shot channels. Status publication uses immutable `Arc<FluxStatus>` values so read-heavy UI polling never contends with kernel reconciliation.

The private implementation contains the following Modules without exposing their Interfaces to common callers:

1. **Boot Gate Module** — keys recovery by boot ID, makes concurrent calls join one shared result, rejects kernels below 5.10, validates journal checksums, and prevents mutation until recovery establishes a safe baseline.
2. **Desired State Loader Module** — reads authoritative local sources, migrates schema, validates duplicate/unknown fields, resolves the Magisk administrative state, and reads the latest immutable Subscription Snapshot. It never mutates the user's source template.
3. **Network Inventory Module** — performs sequence-aware netlink dumps, subscribes to link/address/route/rule changes, derives Android interface roles, and advances the Network Epoch after material topology changes.
4. **Capability Registry Module** — combines version hints with active create/load/attach probes and records `Supported`, `Unsupported`, `Denied`, `Broken`, or `Unknown` evidence. Probe resources have RAII cleanup guards and a reserved stale-probe namespace for crash cleanup.
5. **Generation Compiler Module** — pure deterministic code that normalizes Traffic Scope, Capture Policy, Bypass Policy, package-to-UID expansion, marks, priorities, routes, address sets, Sing-Box overlay, resource budgets, and invariant checks into one immutable Generation.
6. **Backend Planner Module** — selects and explains a Backend Plan from Desired State plus the current Capability Profile. It never treats a version, binary path, or `/proc/config.gz` bit as sufficient proof.
7. **Runtime Reconciler Module** — serializes prepare/activate/verify/retire, owns failure compensation, and uses Rust typestate tokens such as `PreparedGeneration` and `ActiveGeneration` so invalid transition order is unrepresentable inside the implementation.
8. **Sing-Box Supervisor Module** — validates binary/version/config, starts one child per target Generation, uses `OwnedFd` and pidfd when verified, checks PID plus start time plus binary digest, bounds restart bursts, captures correlated logs, and never relies on a PID file alone.
9. **Generation Store Module** — persists immutable records with write, file `fsync`, rename, and directory `fsync`; maintains `active.json`; scans recent records if the pointer is corrupt; and records ownership intent without pretending the journal is Observed State.
10. **Status Publisher Module** — reduces internal state and evidence to the stable summary types at the external Interface, preserves the last error, and publishes one coherent snapshot per state transition.

### 3.1 Adaptive Backend Plan

The implementation composes one correctness Capture Path with optional observation/acceleration:

| Need | Preferred when behaviorally verified | Adaptive alternative |
|---|---|---|
| Transparent TPROXY capture | Native nftables transaction with generation-specific table/chains/sets | xtables stable dispatch chains plus generation chains and atomic ipset swap; managed TUN if capture mode is `auto` |
| Large bypass membership | nftables interval/concatenation sets | ipset; otherwise a bounded xtables jump structure or `ResourceLimit` |
| TUN capture | Flux-managed routes/rules plus version-qualified Sing-Box TUN inbound | No mechanism change for an explicit TUN request; report missing evidence |
| eBPF observation | Verified cgroup or safe TC attachment with bounded maps/counters | Off with documented Degraded State when requested as `observe`; correctness Capture Path remains active |
| eBPF acceleration | Verified BTF/CO-RE or matching object, verifier acceptance, map ABI, attach/link behavior, and safe Android coexistence | Observation, then off, only when preference is `auto` |

Kernel 5.10 is the hard floor, not a promise that any advanced path exists. Later-version facilities such as particular BPF link types are attempted only when their version gate permits a safe probe, and selected only after that probe succeeds. Physical-NIC TC/XDP remains opt-in because Android netd and tethering offload may own those locations. A structural failure after activation demotes only the failing capability for the current boot and causes bounded replanning.

### 3.2 Reconciliation transaction

For an enabled target, the Controller implementation performs:

1. Observe kernel, Proxy Engine, Network Inventory, active journal record, and drift.
2. Normalize Desired State and compile an immutable Generation.
3. Prepare generation-specific kernel objects without attaching traffic.
4. Render and validate the generation-specific Sing-Box configuration.
5. Persist and `fsync` the `Prepared` record.
6. Stage/start Sing-Box and prove generation-specific readiness.
7. Install routing prerequisites.
8. Atomically attach the selected Capture Path and optional eBPF layer.
9. Verify ownership, exact rules/routes/marks, IPv4 and enabled IPv6 behavior, loop prevention, engine identity, and backend health.
10. Publish the durable active record, then retire only the previous Generation's Managed Objects.
11. Publish the terminal `FluxStatus` and return the matching `ControlReport`.

Opaque ownership tokens and RAII cleanup guards keep prepared file descriptors, netlink batches, TUN descriptors, BPF links, and child handles local to the transaction. `unsafe` code is confined to audited syscall wrappers; domain and orchestration code remains safe Rust.

### 3.3 Crash recovery

Recovery compares journal intent with Observed State rather than replaying commands blindly:

- `Prepared` with no attachment: remove only proved prepared objects and retain the prior active Generation.
- `Activating` or mismatched `Active`: re-observe dispatch points, routes, TUN identity, BPF links/maps, and child identity; complete the target only if all invariants can be proved.
- New target attached but unhealthy: restore the previous verified Generation where atomic compensation is provable.
- Exact rollback not provable: detach Flux capture first, retain evidence, stop or quarantine the unowned child, and report a clean fail-open `RecoveryFailed` state.
- Corrupt active pointer: verify checksums and scan recent immutable records; never delete non-Flux objects to make the journal appear consistent.

The boot wrapper can restart `fluxd` with bounded backoff, but every correctness decision remains behind the Controller Seam.

## 4. Dependency categories and Adapters

All dependency Seams below are private to the Controller implementation. They exist because production and deterministic/fault-injection Adapters both provide real value; none leaks into the common caller Interface.

| Dependency category | Private Interface at the Seam | Production Adapter | Test/replay Adapter | Placement rationale |
|---|---|---|---|---|
| In-process | No Adapter: normalization, Generation Compiler, Backend Planner, state reducer | Same pure Rust implementation | Same implementation with property/fuzz inputs | Always deepenable. Tests call through the Controller Interface and assert observable reports/status; focused compiler tests cover deterministic mathematical properties. |
| Local-substitutable | `KernelPlane` | `LinuxAndroidKernelAdapter` using netlink/nftables, xtables/ipset command execution where required, routing, TUN ioctls, and BPF syscalls | `ModelKernelAdapter` with exact object ownership and phase failure injection | The Android kernel is local I/O with a useful deterministic stand-in. This is a real internal Seam with two Adapters. |
| Local-substitutable | `ProxyEngine` | `SingBoxProcessAdapter` | `ScriptedEngineAdapter` that controls validation, readiness, exit, and pidfd behavior | Keeps third-party process/version details local while testing full Controller outcomes. |
| Local-substitutable | `GenerationStore` | `AndroidFsGenerationStoreAdapter` using directory-relative, symlink-safe atomic persistence | `FaultInjectingGenerationStoreAdapter` and temporary-filesystem Adapter | Enables crash tests at every write/fsync/rename point without exposing storage in the external Interface. |
| Local-substitutable | `CapabilityProbeSet` | `AndroidCapabilityProbeAdapter` | `RecordedCapabilityProbeAdapter` | Replays vendor-kernel and SELinux evidence deterministically, including `Denied` versus `Unsupported`. |
| Local-substitutable | `NetworkObserver` | `RtnetlinkNetworkObserverAdapter` | `ReplayNetworkObserverAdapter` with loss, overrun, and epoch changes | Makes Android handover and address-synchronization behavior testable through enable/reload/recovery. |
| Local-substitutable | `ConfigurationSource` | `AndroidConfigurationAdapter` | `MemoryConfigurationAdapter` | Tests migration, invalid input, and digest idempotence without making file paths caller knowledge. |
| Local-substitutable | `Clock`, `BootIdentity`, and `Entropy` | Android/Linux system Adapters | Deterministic time/boot/ID Adapters | Makes backoff, status age, recovery-once, and operation IDs reproducible. |
| Remote but owned | None on this path | None | None | Normal lifecycle operations do not depend on a Flux-owned remote process. Adding one would reduce boot reliability and Interface Depth. |
| True external | Subscription transport is outside this Controller Seam | A separate Subscription Module publishes an immutable snapshot | Recorded HTTP/file fixtures in that Module | `reload()` consumes the latest snapshot but never contacts a remote provider, keeping common operations bounded and repeatable. |

The replacement strategy is “replace, do not layer”: lifecycle tests run the real Controller implementation with the internal test Adapters and assert only `ControlReport`, `ControlError`, `FluxStatus`, child/kernel observations represented at the external Interface, and durable end states. Tests should not reach through the Controller to assert private state-machine fields.

## 5. Trade-offs

### Depth and Leverage

This alternative maximizes Leverage for the overwhelmingly common path. A caller learns five methods, no request structures, no backend enums, no Generation transaction, and no recovery ordering. The same call works whether the implementation selects nftables, xtables plus ipset, managed TUN, optional eBPF, or a degraded plan. Deleting the Controller Module would force every CLI, boot, UI, and socket caller to reproduce lifecycle ordering, backend adaptation, and recovery, so the Module is earning substantial Depth.

The cost is that five verb methods are a slightly wider Interface than a single `execute(Command)` method. That width is intentional: zero-argument verbs improve discovery, make invalid parameter combinations impossible, and make the common caller read like its intent. The returned report types are shared, so behavioral breadth does not multiply result handling.

### Locality

Lifecycle policy has strong Locality: changes to fallback order, Sing-Box readiness, journal repair, activation ordering, or disable safety are implemented and verified once. Private Modules can remain small and independently reasoned about without leaking their Interfaces outward.

The risk is an oversized Controller implementation. The mitigation is not a wider external Interface; it is private decomposition and real internal Seams only where production and test/replay Adapters both exist. The actor owns ordering, while compiler, kernel, engine, store, probe, and observer implementations remain local to their respective concerns.

### Seam placement

Placing the external Seam above Reconciliation is the defining choice. It prevents callers from selecting a Backend Plan, passing partially observed state, or manually sequencing prepare/activate/verify. This is safer for boot and crash recovery and preserves one writer.

The trade-off is reduced flexibility for expert operations. Dry-run planning, full capability evidence, subscription refresh, diagnosis, repair forcing, event watching, and raw state export should use separate inspection/maintenance Modules or a privileged diagnostic transport. Adding those as options to `enable()` or `reload()` would make every common caller learn rare facts and would make the Controller shallower.

The cached `status()` choice favors fast, failure-free UI and shell reads. Its explicit timestamp and age preserve honesty, but a caller cannot demand a synchronous fresh kernel dump through this Interface. Fresh diagnosis belongs behind the inspection Seam because it can block, fail, and perturb probes.

Finally, fixed terminal-wait semantics are easy for ordinary callers but less flexible than exposing accepted-versus-completed wait policy. Transport Modules may impose their own client timeout and later read status; accepted work continues safely. If asynchronous operation tracking becomes a dominant caller need, it should be justified with evidence before adding an operation-watch Interface and another external Seam.
