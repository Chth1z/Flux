---
status: accepted
decision_date: 2026-07-14
---

# Freeze shell networking as the oracle for a non-authorizing Rust shadow compiler

The working shell path is still Flux's only executed compatibility implementation and behavioral
baseline for capture, policy routing, address synchronization, and their cleanup ordering. Removing it before
the Rust replacements have deterministic parity, failure recovery, exact ownership/readback,
rollback, and Android evidence would discard the only executable semantic baseline. Running a
partially native path beside it would be worse: two writers could independently mutate the same
networking objects.

During the bridge releases, the networking portions of `scripts/init`, `scripts/config`,
`scripts/rules`, `scripts/tproxy`, and `scripts/addrsync` are therefore frozen as a compatibility
oracle. They receive only correctness, security, release-contract, and rollback fixes. The
serialized shell phase path remains the sole executed networking writer until a component-specific
cutover gate transfers ownership to Rust. This is a migration constraint, not an endorsement of
shell as the final architecture.

Phase 2 may proceed without mutation by compiling a deterministic backend-neutral shadow Capture
Program in pure Rust. The shadow compiler normalizes typed UID/GID, application, interface,
family, and destination policy; keeps the canonical mandatory safety baseline separate from
configurable bypasses; retains optional inventory-derived host-set provenance without treating it
as final freshness authority, or explicitly defers host observation when it is absent; produces
separate ordered local-OUTPUT and forwarded-ingress
programs; enforces compile-time resource budgets; and emits stable semantic digest and explanation data.
Identical normalized inputs must produce identical shadow output. Frozen semantic fixtures derived
from the compatibility oracle are review inputs for later differential work.

A shadow artifact is deliberately non-authorizing. It has no Generation ID, Planning Authority,
writer token, ownership lease, prepared/active conversion, Runtime Coordinator entry point, or
kernel object names. It is not rendered to xtables, nftables, routes, TUN configuration, or eBPF,
and its digest is not a Generation Capture Program digest accepted by activation or the functional
canary. This checkpoint claims neither byte-for-byte restore parity nor device semantic parity.

Each compatibility component is retired only after its Rust replacement passes all applicable
gates: canonical rendering and differential fixtures, backend and real-device behavior, failure
and recovery injection, exact live readback and Managed Object ownership, rollback, and an atomic
single-writer transition. Phase 4 transfers xtables/ipset ownership; Phase 3 separately transfers
address-derived rule and policy-routing ownership. Until a transfer is complete, Rust may observe
and compile but must not execute that component's networking mutations. Minimal Magisk
installation, launcher/watchdog, disable, uninstall, and compatibility-wrapper glue may remain
after runtime policy scripts are retired.

This decision does not authorize eBPF attachment, persistent pins, live-chain integration, TUN
activation, implicit module autoload, `.ko`/KPM packaging or loading, or consumption of a kernel
extension as a correctness path. Those mechanisms retain their existing independent capability,
ownership, conformance, and ADR gates.

The consequence is a longer overlap in source code but a shorter period of semantic uncertainty:
the old path stays executable and frozen while the new path first becomes explainable, testable,
and deterministic, then takes ownership one component at a time without a big-bang rewrite or a
dual-writer interval.
