---
status: accepted
decision_date: 2026-07-15
last_reviewed: 2026-07-15
---

# Keep the rewrite pre-release until the runtime is fully Rust-owned

The current rewrite branch is a development program, not a sequence of compatibility releases.
Requiring every intermediate commit to preserve obsolete internal schemas, bridge layouts, or
legacy runtime behavior would slow the ownership cutover and encourage temporary adapters to become
permanent product surface.

Intermediate checkpoints may therefore make reviewed breaking changes to internal configuration,
state, CLI, manifest, and adapter contracts when that materially simplifies the target Rust
architecture. Development module staging exists for testing only. It is not an upgrade promise,
release candidate, or supported distribution channel.

This freedom does not weaken runtime safety. A legacy networking component may remain temporarily
only while it is the sole proven writer, rollback path, or executable oracle for a component whose
Rust replacement has not passed its cutover gate. The gate still requires the applicable renderer
or encoder parity, failure and recovery injection, exact ownership/readback, rollback,
single-writer transition, and Android evidence. Once the Rust replacement passes, the superseded
runtime component is removed promptly rather than retained for backward compatibility. No phase
may create a dual-writer interval.

No public release, rewrite alpha/beta, or release candidate is permitted until the intended runtime
is fully Rust-owned. At minimum:

- `fluxd` owns Sing-Box supervision, capture, policy routing, address synchronization,
  configuration/subscription generation, reconciliation, recovery, and offline cleanup;
- standalone `addrsyncd`, `jq`/AWK policy generation, dispatcher/init/core/addrsync/rules/tproxy
  runtime scripts, and legacy compatibility wrappers are absent from the shipped package;
- only platform-required Magisk/KernelSU/APatch installation, boot-launch, disable, and uninstall
  glue may remain outside Rust, and that glue contains no networking policy or cleanup logic;
- the final package passes the documented host, real-kernel, Android device, recovery, security,
  performance, provenance, SBOM, reproducibility, and license gates.

"Rewrite complete" means complete Rust ownership of the advertised runtime scope, not mandatory
delivery of every optional future backend. The first release may explicitly leave nftables, managed
TUN, or eBPF unavailable if at least one fully Rust-owned conventional Capture Path satisfies the
documented product scope and no legacy runtime dependency remains.

A one-time importer for settings from an already published legacy Flux release may be implemented
as an isolated Rust migration command if it does not preserve a legacy runtime dependency or delay
the rewrite. It is not a requirement for every development checkpoint, and internal development
state may be deliberately invalidated when schemas change.

The consequence is a faster and cleaner rewrite with fewer permanent seams. Development builds may
not be safely upgrade-compatible and must not be presented to users as releases. ADR-0010 remains
authoritative for the temporary single-writer/oracle safety boundary; this decision makes clear
that the boundary exists only inside pre-release development and must be gone before publication.
