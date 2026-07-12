---
status: proposed
---

# Require positive device-qualified authority for Android mark planning

Generic AOSP grants Flux no mark field, and bits 21–30 are only a device-qualified candidate envelope. Automatic and explicit values are candidates, not overrides. Positive planning authority requires an externally reviewed cooperative-policy assertion bound to the exact candidate/topology, full Capability Profile and verified boot, network namespace, named policy plus nonzero SHA-256 artifact digest/revision, and all packet/socket/conntrack planes.

Authorization consumes a fresh complete census of nine sources, including XFRM, across all three planes and binds inventory, policy, collector, and ownership-journal evidence. Any external overlap or opaque RPDB evidence rejects. The result is planning-only: it exposes no `MarkLease`, priority, table, route, encoder, writer, mutation, ownership, or activation conversion, and reauthorization requires a newly collected census.
