---
status: accepted
decision_date: 2026-07-13
last_reviewed: 2026-07-27
---

# Require positive device-qualified authority for Android mark planning

Generic AOSP grants Flux no mark field, and bits 21–30 are only a device-qualified candidate envelope. Automatic and explicit values are candidates, not overrides. Before a production policy loader exists, the freshness-bound Capability Profile must include exact Android product/build/vendor, kernel build, verified-boot, SELinux-policy, netd/Connectivity artifact, tool, boot, and network-namespace identity. Positive policy is selected from a compile-time reviewed catalog keyed only by stable platform identities and an externally reviewed digest/revision; the selected assertion is then freshness-bound to the full profile, including the executing tool, verified boot, boot ID, and observed namespace. Runtime-only boot/namespace identities are not catalog keys. ADR-0014 also excludes the executing ELF's full digest from the compile-time key because embedding it is self-referential; a runtime manifest cannot authenticate the executable that produced it.

The selected assertion binds the exact candidate/topology, full Capability Profile, named policy and exact nonempty plane set. Planning authority requires packet, socket, and conntrack coverage.

Authorization consumes a fresh complete census of nine sources, including XFRM, across all three
planes and binds inventory, policy, collector, and ownership-journal evidence. Definite or unknown
external overlap and opaque RPDB evidence reject. ADR-0013 permits the exact Android `netId`
packet-plane masked writer to be diagnosed as an ordered-write qualification requirement rather
than a proven simultaneous conflict, but that result also rejects and definite conflicts retain
precedence. The result is planning-only: it exposes no `MarkLease`, priority, table, route, encoder,
writer, mutation, ownership, or activation conversion, and reauthorization requires a newly
collected census.
