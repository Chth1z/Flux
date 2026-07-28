# Flux Architecture Context

Flux is a pre-release Rust transparent-proxy runtime for rooted Android. Magisk and KernelSU are
installation and launch envelopes only. One `fluxd` process owns runtime admission, Capture Path
selection, network mutation, rollback, observation, statistics, and manager-facing control.

## Release Boundary

**Fresh-install development line**

Flux has no supported pre-release upgrade contract. Internal schemas may change together, and a
fresh package refuses an existing `/data/adb/flux` tree instead of interpreting unknown state.
Compatibility aliases, dual readers, transition renderers, and fallback writers are prohibited.

**Rust runtime boundary**

Shell is limited to package installation, boot launch/restart, and uninstall delegation required by
the root framework. Shell must not classify traffic, write routes or firewall state, retrieve
subscriptions, compile configuration, observe runtime networks, or clean up owned kernel state.

**Release qualification boundary**

Host tests prove architecture and mechanism behavior, not Android release readiness. Release
requires the exact ARM64 payloads on rooted Android 5.10 or newer, across the supported Magisk and
KernelSU lifecycle matrix, with reviewed rollback and cleanup evidence.

## Ownership Model

**Root framework**

Packages files and launches one singleton `fluxd` from minimal idempotent glue. It is not a runtime
supervisor, capability authority, networking writer, or status source.

**Flux daemon**

Owns Desired State, staged native admission, the reactor, Generation compilation, Sing-Box
supervision, the native network writer, durable recovery, control IPC, and observation publication.

**Proxy engine**

Sing-Box remains a descriptor-pinned external process. Flux supplies its accepted configuration and
supervises its exact identity. Sing-Box route, RPDB, nftables, iptables, and autonomous TUN ownership
must remain disabled; an eventual managed TUN path passes an externally owned descriptor.

**Manager**

The future manager is an unprivileged client of versioned, credential-checked, least-authority IPC.
It must not execute root shell, read kernel journals directly, or become a second state writer.

## State Model

**Desired State**

The complete requested runtime behavior: administrative state, traffic scope, proxy engine input,
Capture Policy, and safety requirements.

**Observed State**

Fresh facts about the boot, namespace, Android device, kernel, network inventory, engine, and
Flux-owned kernel objects. Missing or lossy evidence cannot authorize mutation.

**Capability Profile**

Schema 3 identity-bound facts collected for the current boot and network namespace. Kernel version,
configuration, static installation probes, and root-framework identity establish eligibility only;
runtime observations establish authority.

**Network Inventory**

One reactor-owned, loss-aware stream of links, addresses, routes, and rules. Generation planning and
address reconciliation consume the same immutable snapshot ID and epoch. Descriptor failure, loss,
or reset invalidates the source instead of publishing an incomplete view.

**Native Admission**

A staged type-state decision. Capability and boot rejection occurs before Desired State or mutation
inputs are loaded. Configured safety policy is evaluated next. A complete reactor inventory is the
final prerequisite. The result is the sole authority projected into composition, mutation control,
status, and recovery.

**Generation**

An immutable Desired State realization bound to exact engine input, Capture Program, Android mark
and RPDB planning authority, native target identity, inventory evidence, and a unique generation ID.
Only the Runtime Coordinator may prepare, publish, verify, replace, or retire it.

RPDB placement represents the address-bypass priority as optional state. Proxy-only placement has
no fabricated bypass value or parallel boolean, and Generation identity tags presence explicitly.

## Traffic Model

**Traffic Scope**

The selected address families and disjoint traffic domains. Current production planning requires
residual local OUTPUT and rejects forwarded ingress; the backend-neutral model and lowerer retain
forwarded-ingress semantics for later qualified ownership.

**Capture Policy**

Ordered direct/proxy decisions: loop prevention, mandatory safety exclusions, configured bypasses,
inventory-derived host bypasses, interface roles, application UIDs, protocol safety, proxy action,
and direct default.

**Capture Program**

The current backend-neutral compilation Interface. `CaptureProgramRequest` compiles into one
`CaptureProgramCompilation`, whose `CaptureProgram` contains canonical domain programs, bounded
resource usage, schema 1, and a semantic digest. Inventory provenance is retained beside the program
and deliberately excluded from the semantic digest.

**Xtables lowering**

One schema-2 lowering converts a Capture Program into immutable IPv4/IPv6 private-chain artifacts,
typed entry points, exact local-listener and routing requirements, mandatory transaction ordering,
resource usage, and domain-separated identities. There is no forwarded-only compatibility schema.

**Native xtables owner**

A private deep Module with convergence and recovery as its external Interface. It owns stable
`FLX{4|6}SP` and `FLX{4|6}SO` roots, generation chains, exact save projections, policy-routing
netlink mutation, durable target material, writer lease, rollback, crash recovery, and verified
cleanup. Unknown, mixed, corrupt, or unjournaled Flux state fails closed.

**Capture Path**

The selected mechanism that realizes Capture Policy. Xtables TPROXY is the only composed native
writer today. Nftables, managed TUN, and eBPF remain future adapters and must not be selected until
their exact implementation and device evidence qualify them.

## Lifecycle

Startup is ordered as follows:

1. Collect the Capability Profile and evaluate capability admission.
2. Load Desired State only for a capability-admissible candidate and evaluate safety policy.
3. Open the reactor, attach and prime its network inventory driver, and obtain a complete snapshot.
4. Finalize `AdmittedNativeRuntime`.
5. Run native startup recovery only after final admission.
6. Compose planning, native ownership, engine supervision, and Runtime Control.
7. Bind control IPC after composition is complete.

A rejected daemon remains queryable and read-only. Mutation commands return the typed admission
reason. Process-directed `SIGTERM` is consumed through `signalfd`, runtime cleanup completes, and the
control socket is removed.

Runtime replacement follows prepare, exact engine readiness, capture convergence, readback,
optional functional verification, publication, and old-generation retirement. Every failure after a
possibly mutating boundary requires fresh readback and rollback or durable recovery state.

## Safety Policy

Packaged defaults set both `respect_android_vpn` and `require_functional_canary` to `true`. No
qualified Android VPN-policy or production functional-canary adapter is currently packaged, so the
default configuration intentionally rejects mutation while retaining read-only control. Setting a
requirement to `false` selects structural verification only; it is an explicit policy decision, not
a silent fallback.

The production functional-canary adapter must prove exact local-OUTPUT TPROXY delivery to the
transparent listener and supervised engine, bind pre/post identity and counter bounds, and prove
cleanup. Route lookups, counters alone, REDIRECT, DNAT, or unrelated ingress traffic are not
substitutes.

## Observation Model

The reactor uses bounded readiness work, bounded worker concurrency, immutable replacement
snapshots, explicit degradation, and loss/reset semantics. Statistics should default to aggregate,
privacy-reduced counters with explicit CPU, memory, wakeup, retention, and disk budgets. Per-flow or
PII-rich observation requires an explicit product and privacy contract.

## Peer-Derived Decisions

- Adopt dae's prepare/ready/commit/retire and bounded pending-reload ideas, not its global BPF or
  namespace ownership.
- Use Sing-Box TPROXY listener behavior and external-descriptor TUN only; reject autonomous host
  mutation.
- Use Vector's typed IPC and replacement publication as references, but keep the manager strictly
  less privileged.
- Treat Magisk and KernelSU as launch envelopes, not supervisors.
- Treat Re-Kernel as bounded-observation evidence only, never as a dependency or Capture Path.
- Borrow bindhosts workflows and atomic publication lessons, not its shell/file writer model.

## Current External Gate

The shell networking and standalone `addrsyncd` migration is complete in executable production
source. The remaining release gate is not migration cleanup: it is implementation and physical
qualification of the Android VPN-policy and functional-canary adapters, followed by exact ARM64
native activation, rollback, power, and cleanup evidence.
