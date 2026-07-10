# Flux Rewrite Documentation

## Start here

- [Fluxd rewrite blueprint](architecture/fluxd-blueprint.md) — recommended architecture and design decisions.
- [Technical specification](architecture/fluxd-technical-specification.md) — types, protocols, probes, transactions, backend behavior, and packaging contract.
- [Implementation roadmap](architecture/implementation-roadmap.md) — phased migration and verification gates.
- [Controller interface comparison](architecture/interface-comparison.md) — three alternative Interfaces and the selected hybrid.
- [Domain language](../CONTEXT.md) — canonical project terms.

## Research

- [Research index and synthesis](research/README.md)
- [Current system baseline](research/current-system-baseline.md)
- [Android networking and kernel constraints](research/android-network-kernel.md)
- [Sing-Box and adjacent projects](research/sing-box-and-projects.md)
- [Rust, eBPF, netfilter, and TUN](research/rust-ebpf-netfilter.md)

## Architecture alternatives

- [Alternative A: minimal mailbox Interface](architecture/alternatives/interface-a-minimal.md)
- [Alternative B: extensible strategy fabric](architecture/alternatives/interface-b-extensible.md)
- [Alternative C: common-caller Interface](architecture/alternatives/interface-c-common-caller.md)

## Proposed decisions

- [ADR-0001: one `fluxd` with external Sing-Box](adr/0001-one-fluxd-with-external-sing-box.md)
- [ADR-0002: generation-based reconciliation](adr/0002-generation-based-reconciliation.md)
- [ADR-0003: kernel floor and active probes](adr/0003-kernel-floor-and-active-capability-probes.md)
- [ADR-0004: optional eBPF observation/acceleration](adr/0004-ebpf-is-optional-observation-and-acceleration.md)
- [ADR-0005: nftables with compatible fallbacks](adr/0005-prefer-native-nftables-with-compatible-fallbacks.md)
- [ADR-0006: audited mark allocation](adr/0006-allocate-marks-after-android-conflict-analysis.md)
- [ADR-0007: respect Android VPN policy](adr/0007-respect-android-vpn-policy-by-default.md)
- [ADR-0008: minimal Controller, internal planner](adr/0008-minimal-controller-with-internal-strategy-planner.md)

