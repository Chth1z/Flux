---
status: accepted
decision_date: 2026-07-20
---

# Qualify ordered Android mark overlaps without granting authority

The complete fwmark census records source, plane, operation, and mask, but it does not yet model
netfilter hook order, traffic domain, or mark lifetime. Treating every overlapping packet write as
a proven simultaneous collision therefore overstates what the census can establish.

For every pinned `AndroidNetdSourceProfile`, netd appends its incoming-packet `MARK --set-mark`
rule to `routectrl_mangle_INPUT`, a child of the built-in mangle INPUT hook. Linux 5.10 executes
PREROUTING, performs input routing, and reaches LOCAL_IN afterward. The canonical Flux TPROXY paths
consume their candidate mark during OUTPUT rerouting or PREROUTING plus local route selection.
The exact Android `netId` packet-plane masked write is therefore a known ordered late-writer
question, not by itself proof of a simultaneous collision with that routing lifetime.

This ordering is not compatibility evidence. The current source fragment does not authenticate the
runtime netd artifact, prove that the observed chain matches the selected source profile, bind the
rule's input-interface selector to one Traffic Domain, or show that the transparent listener and
observers tolerate the later rewrite. WSA and disposable namespaces are mechanism evidence only;
they cannot qualify a physical Android 5.10/ARM64 product or its vendor policy.

Planning authorization will therefore partition overlapping census uses:

- the exact `(AndroidNetId, Packet, MaskedWrite)` use returns a typed ordered-packet-write
  qualification error;
- every predicate read, socket or conntrack use, transfer, other writer, opaque case, and unknown
  semantic remains a definite or unresolved census conflict;
- any definite conflict takes precedence over an ordered-write diagnostic.

Both outcomes reject. The ordered result has no conversion into
`AndroidMarkPlanningAuthority`, `MarkLease`, priority, table, route, encoder, writer, ownership, or
activation authority. This checkpoint adds no generic temporal solver and no caller-supplied hook
claim that could manufacture compatibility.

Before the ordered overlap may be accepted, one exact physical Android ARM64 profile must bind the
runtime netd and Connectivity artifacts to the reviewed source profile, read back the actual INPUT
chain and interface selectors, prove the canonical Flux hook and routing order, preserve required
mark semantics through listener delivery and observation, and pass VPN/netd coexistence and
mark-preservation canaries. Expansion of the remaining 21 census cells pauses until such a target
and qualification procedure are viable; source-count growth must not displace the current
activation blocker.

## 2026-07-21 implementation checkpoint

The development-only `preflight-android-arm64-mark-ordering` xtask now determines whether one
explicit rooted serial is viable for the later qualification procedure without changing device
networking. It reuses bounded ADB execution and stable boot/fingerprint revalidation, checks the
production identity collector's shared bounded property contract and artifact inputs, requires
at least one valid device-lock property (and agreement when both exist), ARM64, Linux 5.10+,
enforcing SELinux, and PID-1 network-namespace identity, and reads only mangle tables already
initialized by Android. Its bounded parser requires the exact unconditional INPUT child hook,
one declared `routectrl_mangle_INPUT`, no other `-j` or `-g` reference to that child from any chain,
unique cross-family-consistent interface-scoped writers, one
supported incoming mask, zero candidate-envelope bits in writer values, and no unknown child rule
in either family.

The report is explicitly diagnostic-only, hashes rather than prints raw table snapshots, and has no
authority conversion. A pass establishes only that the target and read-only procedure are usable;
it does not authenticate the netd/Connectivity artifact digest to a source profile, prove the Flux
Capture Path order on that boot, observe listener mark behavior, or pass VPN/netd coexistence and
mark-preservation canaries.

## 2026-07-27 assurance and ordered-write amendment

ADR-0015 separates source authentication from exact-artifact observed behavior. Under either
positive assurance class, an ordered overlap can be admitted to planning only when the reviewed
policy and complete live census retain the identical canonical
`FwmarkOrderedLateWriteQualification` set. Each record binds the exact family, built-in hook, child
chain, hook and rule ordinals, and selector digest. Construction rejects non-packet writes,
socket/conntrack persistence, any earlier matching overlap, and a source/hook/placement mismatch.

This replaces the prior rule that every ordered write must always stop planning. It does not create
activation authority: listener/observer continuity, mark-preservation, VPN/netd coexistence,
rollback, restart/recovery, and cleanup canaries remain mandatory. The initial Samsung observed-
behavior policy admits no ordered record and therefore retains the earlier fail-closed result until
an exact later policy revision and coherent live census agree.
