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
