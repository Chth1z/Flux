---
status: accepted
decision_date: 2026-07-27
---

# Separate platform policy selection from runtime tool identity

The compiled Android mark-policy catalog cannot use the full SHA-256 of the executing `fluxd` ELF
as a selector fact. The catalog is linked into that ELF, so embedding the expected digest changes
the bytes whose digest is expected. A runtime manifest containing a newly measured value would
avoid the build cycle only by allowing the executable to authenticate itself, which grants no
independent review authority.

Compile-time selection therefore uses only stable platform facts: exact Android product, system
build, vendor build, security patch, kernel build, loaded SELinux policy, `/system/bin/netd`, and
active Connectivity APEX identities. `DeviceIdentity` continues to record the exact executing-tool
artifact. The selected positive grant, complete census, native target evidence, package verifier,
and physical qualification evidence bind the full `CapabilityProfile`, including that tool
identity. A tool-only change does not select a different platform policy, but it does produce a
different qualification and release artifact identity.

Catalog entries also name one typed `AndroidNetdSourceProfile`. Selection now precedes RPDB and
topology classification and returns that profile without constructing positive mark authority.
The caller classifies a fresh inventory with the selected profile and must consume the selection to
bind the resulting topology scope. Binding rejects a scope produced with any other netd profile.
This removes the former ordering cycle in which callers had to guess a source profile before the
catalog selected it.

No runtime file, caller-supplied selector, WSA observation, artifact hash alone, or behavior sample
may add a catalog entry. A positive entry still requires a checked-in independent review artifact,
exact platform identities, source or explicitly bounded behavior-compatibility evidence, a
complete point-in-time census, a collision-free candidate, and the physical coexistence procedure.
Until those facts pass, the production catalog remains empty and generic AOSP remains zero grant.

This decision narrows the tool-key clause in ADR-0006. It does not weaken its full-profile
freshness binding, census, topology, verified-boot, namespace, or positive-grant requirements.
