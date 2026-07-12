---
status: accepted
decision_date: 2026-07-13
---

# Require positive device-qualified authority for Android mark planning

Generic AOSP grants Flux no mark field, and bits 21–30 are only a device-qualified candidate envelope. Automatic and explicit values are candidates, not overrides. Before a production policy loader exists, the freshness-bound Capability Profile must include exact Android product/build/vendor, kernel build, verified-boot, SELinux-policy, netd/Connectivity artifact, tool, boot, and network-namespace identity. Positive policy is selected from a compile-time reviewed catalog keyed only by stable product/build/kernel/policy/tool artifact identities and an externally reviewed digest/revision; the selected assertion is then freshness-bound to verified boot, boot ID, and the observed namespace. Runtime-only boot/namespace identities are not catalog keys, and a runtime manifest cannot authenticate itself by hashing its own bytes.

The selected assertion binds the exact candidate/topology, full Capability Profile, named policy and exact nonempty plane set. Planning authority requires packet, socket, and conntrack coverage.

Authorization consumes a fresh complete census of nine sources, including XFRM, across all three planes and binds inventory, policy, collector, and ownership-journal evidence. Any external overlap or opaque RPDB evidence rejects. The result is planning-only: it exposes no `MarkLease`, priority, table, route, encoder, writer, mutation, ownership, or activation conversion, and reauthorization requires a newly collected census.
