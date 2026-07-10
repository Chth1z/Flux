# Flux Controller Interface Comparison

The three designs below were produced independently after the current-system, Android/kernel, Sing-Box, and Rust/eBPF research. They use the same domain vocabulary from [`CONTEXT.md`](../../CONTEXT.md) and the same deep-module vocabulary.

## Alternative A — Minimal mailbox Interface

[Full design](alternatives/interface-a-minimal.md)

Alternative A exposes only daemon `run` and a versioned `execute` request/reply operation. External requests are intentionally limited to:

- `Converge(Configured)`;
- `Converge(Disabled)`;
- `Inspect` with cached, observed, or long-poll consistency.

Its strongest idea is that callers request a Desired State target, never a lifecycle step or backend. “Restart” disappears: converging unchanged Desired State repairs the active Generation, while changed sources compile a successor Generation.

Depth is very high because two entry points hide configuration loading, Capability Profiles, Backend Plans, Sing-Box supervision, Android VPN/netd coexistence, kernel transactions, and crash recovery. Locality is strong around the single-writer controller. The external Seam is correctly above mechanism and ordering.

Its weakness is that `run` and `execute(endpoint, request)` mix the daemon composition root and transport client with the in-process Controller Module. Folding status watching into repeated `Inspect` calls is excellent for the wire protocol but less natural for internal Rust callers that can cheaply read a snapshot or subscribe to a stream.

## Alternative B — Extensible strategy fabric

[Full design](alternatives/interface-b-extensible.md)

Alternative B exposes catalog, plan, execute, query, and subscribe. Multiple strategies contribute semantic capabilities, constraints, resource costs, and transaction fragments. A solver produces candidate Backend Plans, and an opaque lease binds an executable plan to the exact Capability Profile, Network Epoch, Android policy revision, Sing-Box dialect, extension registry, and Desired State digest.

This design has excellent mechanism Locality:

- nftables, xtables, ipset, TUN, routing, Android policy, Sing-Box dialect, eBPF hook, and packet-I/O knowledge can evolve independently;
- facility ports prevent extensions from issuing raw syscalls or arbitrary shell commands;
- plan leases make expert approval meaningful and reject stale execution;
- test Adapters can exercise the same semantic strategy through a model or real kernel.

The cost is a wider, lower external Seam. An ordinary boot or UI caller must understand planning, candidates, leases, and execution even when it only wants Flux enabled. A metadata/constraint solver also adds a new correctness surface before the initial rewrite has even achieved one-owner parity. Its extension Seam is valuable, but exposing it as the primary caller model would reduce leverage for normal operation.

## Alternative C — Common-caller lifecycle Interface

[Full design](alternatives/interface-c-common-caller.md)

Alternative C exposes five discoverable methods:

- `recover_boot`;
- `enable`;
- `disable`;
- `reload`;
- `status`.

This gives excellent leverage to the current CLI, Magisk boot glue, and UI. The zero-argument methods make invalid combinations impossible, status is an O(1) coherent snapshot, equivalent concurrent operations share results, and disable receives priority.

The weakness is growth pressure. Subscription refresh, repair, dry-run planning, safe mode, diagnostic capture, rollback, and future administrative intentions either add more verbs or require separate Modules. `recover_boot` is also a daemon responsibility rather than something ordinary callers should choose. The method set is a good client facade, but a less stable core Interface.

## Comparison

| Design | Depth for normal callers | Locality | External Seam placement | Extensibility | Main risk |
|---|---|---|---|---|---|
| A: minimal mailbox | Highest | Strong around one controller | Above Desired State convergence; transport-shaped | New intentions extend a bounded request enum | Transport/composition concerns leak into the Module Interface |
| B: strategy fabric | Moderate | Excellent for mechanisms and cross-mechanism rules | Between intent and executable plan | Highest; semantic strategy composition | Solver/metadata complexity and too much ceremony for boot/UI |
| C: common caller | Very high for today's verbs | Strong lifecycle Locality | Above reconciliation | Moderate; extra intentions add methods or Modules | Core Interface grows with operational vocabulary |

## Recommendation — Minimal Controller, common-caller client, internal strategy planner

Use a hybrid with three deliberately placed seams.

### 1. Core Controller Module

```rust
#[derive(Clone)]
pub struct FluxController {
    inner: Arc<ControllerInner>,
}

impl FluxController {
    pub async fn submit(
        &self,
        command: ControllerCommand,
    ) -> Result<OperationHandle, ControlError>;

    pub fn snapshot(&self) -> Arc<SystemSnapshot>;

    pub fn watch(&self, after: StatusRevision) -> StatusStream;
}

pub enum ControllerCommand {
    Converge { target: DesiredTarget, reason: ReconcileReason },
    ReloadSources,
    Shutdown,
}

pub enum DesiredTarget {
    Configured,
    Disabled,
}
```

Interface facts:

- Boot recovery occurs before the daemon accepts mutating commands; it is not a caller-selected method.
- `submit` durably accepts and orders an intention. Dropping the returned handle never abandons an accepted kernel transaction.
- `OperationHandle` exposes operation identity, progress, and terminal wait; client timeouts do not cancel reconciliation.
- `snapshot` is O(1), coherent, immutable, and syscall-free. It includes observation age.
- `watch` streams bounded status revisions and emits an explicit gap when a slow reader must resynchronize through `snapshot`.
- Exactly one task owns Flux kernel mutation. Commands and internal events share the same Generation fence.
- `Converge(Configured)` means start, repair, network-epoch adaptation, or successor activation as needed; it never means “run these steps.”
- `Converge(Disabled)` detaches capture first, removes only Managed Objects, and stops the Proxy Engine last.
- `ReloadSources` validates sources and changes Desired State; when enabled it schedules convergence, and when disabled it remains inactive.
- Maintenance work with materially different authority or failure behavior—subscription retrieval, fresh capability probing, diagnostic bundles, migration, and offline planning—uses separate Modules rather than expanding every caller's Interface.

This keeps Alternative A's intent model while separating the in-process Module Interface from the control-socket transport.

### 2. Common-caller client Adapter

The CLI/UI client provides Alternative C's discoverable facade:

```rust
impl FluxClient {
    pub async fn enable(&self) -> Result<OperationReceipt>;
    pub async fn disable(&self) -> Result<OperationReceipt>;
    pub async fn reload(&self) -> Result<OperationReceipt>;
    pub async fn status(&self) -> Result<Arc<SystemSnapshot>>;
}
```

These are thin mappings to the versioned control protocol. They contain no lifecycle, backend, or recovery policy. Adding a different transport or UI does not create another Controller implementation.

### 3. Internal strategy planner

Adopt the strongest parts of Alternative B behind a private Seam:

- semantic capabilities rather than backend booleans;
- candidate and rejection explanations;
- facts bound to Capability Profile and Network Epoch revisions;
- typed facility ports for nftables, xtables, ipset, TUN, route, and hook-specific eBPF behavior;
- transaction participants with declared ownership, dependencies, verification, and compensation;
- a frozen statically linked registry when extension count justifies it;
- no raw syscall/command escape hatch.

Do not begin with a general constraint-solver plugin framework. The first implementation should use exhaustive Rust enums and an explicit deterministic planner for the known strategies. Promote a private extension Seam only after at least two independently varying implementations need it and contract tests demonstrate the leverage. This follows the rule that one Adapter is hypothetical and two make a real Seam.

## Why this is the strongest design

- Depth remains highest where most callers interact.
- Backend and Android/Sing-Box knowledge retains Locality behind internal seams.
- The core Interface stays stable as nftables, ipset, TUN, eBPF, TCX, netfilter BPF, or packet-I/O Adapters change.
- Expert plan explanation remains available through a separate inspection Module without forcing boot callers to select leases.
- The Controller is the test surface for lifecycle correctness; strategy/port contract tests supplement it without testing past the external Seam.
- The design can start simple and deepen as real variation appears, rather than committing the rewrite to a plugin framework before parity.

