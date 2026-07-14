# Flux Rewrite Documentation

## Start here

- [Fluxd rewrite blueprint](architecture/fluxd-blueprint.md) — recommended architecture and design decisions.
- [Technical specification](architecture/fluxd-technical-specification.md) — types, protocols, probes, transactions, backend behavior, and packaging contract.
- [Implementation roadmap](architecture/implementation-roadmap.md) — phased migration and verification gates.
- [Functional capture canary](architecture/functional-capture-canary.md) — Generation-scoped TCP, UDP, DNS, and loop-escape verification contract.
- [Controller interface comparison](architecture/interface-comparison.md) — three alternative Interfaces and the selected hybrid.
- [Domain language](../CONTEXT.md) — canonical project terms.
- [Development and build workflow](development.md) — pinned Rust/Android toolchains and verification commands.

## Research

- [Research index and synthesis](research/README.md)
- [Current system baseline](research/current-system-baseline.md)
- [Android networking and kernel constraints](research/android-network-kernel.md)
- [Sing-Box and adjacent projects](research/sing-box-and-projects.md)
- [Rust, eBPF, netfilter, and TUN](research/rust-ebpf-netfilter.md)
- [Current implementation follow-up (2026-07, Chinese)](research/current-system-follow-up-2026-07.zh-CN.md)
- [Peer kernel/proxy projects and `xt_bpf` (2026-07, Chinese)](research/peer-kernel-projects-2026-07.zh-CN.md)
- [Expanded eBPF and kernel-extension assessment (2026-07)](research/ebpf-and-kernel-extensions-2026-07.md)

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
