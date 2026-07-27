# Flux Rewrite Documentation

> **Pre-release policy:** the Rust rewrite branch is development-only. Intermediate checkpoints may
> break obsolete internal compatibility contracts, no bridge checkpoint is a release candidate,
> and publication is blocked until the intended runtime is fully Rust-owned and legacy runtime
> components are removed. See [ADR-0011](adr/0011-pre-release-rust-only-release-gate.md).

## Authority and reading order

1. [ADR-0011](adr/0011-pre-release-rust-only-release-gate.md) is the release gate.
2. The [implementation roadmap](architecture/implementation-roadmap.md) is the authoritative
   execution order. Its named lanes, gates, and backlog IDs define the current sequence.
3. The [blueprint](architecture/fluxd-blueprint.md) and
   [technical specification](architecture/fluxd-technical-specification.md) define the target
   architecture and contracts.
4. Research notes and alternatives preserve evidence and discarded options. Their old priority or
   compatibility recommendations are non-normative when they conflict with ADR-0011 or the current
   roadmap.

## Start here

- [Comprehensive project review (2026-07)](architecture/project-review-2026-07.md) - current
  implementation assessment, strengths, risks, alternatives, and Rust-unification recommendation.
- [Shell runtime retirement review and plan (2026-07)](architecture/shell-runtime-retirement-plan-2026-07.md) -
  current deviations, complete script ownership map, and the gated Rust implementation/removal sequence.
- [Fluxd rewrite blueprint](architecture/fluxd-blueprint.md) — recommended architecture and design decisions.
- [Technical specification](architecture/fluxd-technical-specification.md) — types, protocols, probes, transactions, backend behavior, and packaging contract.
- [Implementation roadmap](architecture/implementation-roadmap.md) — Rust-unification critical path and verification gates.
- [Functional capture canary](architecture/functional-capture-canary.md) — supporting
  Generation-scoped qualification contract, resumed when a real Rust-owned backend can inhabit it.
- [Controller interface comparison](architecture/interface-comparison.md) — three alternative Interfaces and the selected hybrid.
- [Domain language](../CONTEXT.md) — canonical project terms.
- [Development and build workflow](development.md) — pinned Rust/Android toolchains and verification commands.
- [Explicit unsafe-boundary audit (2026-07)](security/unsafe-boundary-audit-2026-07.md) - exact
  construct inventory, semantic review, corrected signal contract, residual risk, and re-audit
  triggers.

## Research

- [Research index and synthesis](research/README.md)
- [Current system baseline](research/current-system-baseline.md)
- [Android networking and kernel constraints](research/android-network-kernel.md)
- [Sing-Box and adjacent projects](research/sing-box-and-projects.md)
- [Rust, eBPF, netfilter, and TUN](research/rust-ebpf-netfilter.md)
- [Current implementation follow-up (2026-07, Chinese)](research/current-system-follow-up-2026-07.zh-CN.md)
- [Peer kernel/proxy projects and `xt_bpf` (2026-07, Chinese)](research/peer-kernel-projects-2026-07.zh-CN.md)
- [Expanded eBPF and kernel-extension assessment (2026-07)](research/ebpf-and-kernel-extensions-2026-07.md)
- [Local-origin transparent-capture mechanisms on Linux 5.10 (2026-07)](research/local-output-capture-mechanisms-2026-07.md)
- [Open-source architecture comparison for the Rust cutover (2026-07)](research/open-source-architecture-comparison-2026-07.md)
- [Primary sources for the explicit Rust unsafe-boundary audit (2026-07)](research/rust-unsafe-boundary-primary-sources-2026-07.md)

## Architecture alternatives

- [Alternative A: minimal mailbox Interface](architecture/alternatives/interface-a-minimal.md)
- [Alternative B: extensible strategy fabric](architecture/alternatives/interface-b-extensible.md)
- [Alternative C: common-caller Interface](architecture/alternatives/interface-c-common-caller.md)

## Architecture decisions

- [ADR-0001: one `fluxd` with external Sing-Box](adr/0001-one-fluxd-with-external-sing-box.md)
- [ADR-0002: generation-based reconciliation](adr/0002-generation-based-reconciliation.md)
- [ADR-0003: kernel floor and active probes](adr/0003-kernel-floor-and-active-capability-probes.md)
- [ADR-0004: optional eBPF observation/acceleration](adr/0004-ebpf-is-optional-observation-and-acceleration.md)
- [ADR-0005: nftables with compatible fallbacks](adr/0005-prefer-native-nftables-with-compatible-fallbacks.md)
- [ADR-0006: positive device-qualified mark authority](adr/0006-allocate-marks-after-android-conflict-analysis.md)
- [ADR-0007: respect Android VPN policy](adr/0007-respect-android-vpn-policy-by-default.md)
- [ADR-0008: minimal Controller, internal planner](adr/0008-minimal-controller-with-internal-strategy-planner.md)
- [ADR-0009: do not make Flux a kernel-module loader](adr/0009-do-not-make-flux-a-kernel-module-loader.md)
- [ADR-0010: freeze shell networking as a shadow-compiler oracle](adr/0010-freeze-shell-networking-as-a-shadow-compiler-oracle.md)
- [ADR-0011: keep the rewrite pre-release until the runtime is fully Rust-owned](adr/0011-pre-release-rust-only-release-gate.md)
- [ADR-0012: qualify local OUTPUT through loopback-reinjected PREROUTING TPROXY](adr/0012-qualify-local-output-through-loopback-tproxy.md)
- [ADR-0013: qualify ordered Android mark overlaps without granting authority](adr/0013-qualify-ordered-android-mark-overlaps.md)
- [ADR-0014: separate platform policy selection from runtime tool identity](adr/0014-separate-platform-policy-selection-from-runtime-tool-identity.md)
- [ADR-0015: separate Android policy assurance classes](adr/0015-separate-android-policy-assurance-classes.md)

## Reviewed policies

- [Samsung SM-S9180 FZDP observed-behavior mark policy v1](policy/samsung-sm-s9180-fzdp-observed-behavior-v1.md)
