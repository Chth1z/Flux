---
status: accepted
decision_date: 2026-07-27
---

# Separate Android policy assurance classes

Exact Android runtime artifacts can support a bounded deployment policy even when an OEM does not
publish enough signed build metadata for exact source authentication. Treating those cases as
source-authenticated would overstate the evidence; rejecting them categorically is unnecessarily
strict for an explicitly accepted customized-root deployment.

Positive Android mark policies therefore carry one non-ordered assurance class:

- `AuthenticatedSource` requires a producer-authenticated artifact/source mapping or an exact
  reproducible build.
- `ExactArtifactObservedBehavior` binds exact platform artifacts and reviewed live behavior but
  makes no source-provenance claim.

The assurance class is part of the catalog selection, positive grant, policy identity, complete
census binding, and canonical planning-evidence digest. It is not a boolean and there is no
conversion from observed behavior to authenticated source. Generic AOSP remains zero grant.

Both positive classes retain the same exact stable selector, verified boot, boot ID, executing-tool,
network-namespace, topology, complete-census, ownership-journal, freshness, functional, rollback,
and cleanup requirements. The lower source-provenance bar does not relax runtime drift or
coexistence checks.

An external overlapping packet write may be admitted only through a typed ordered-late-write
record that binds its family, built-in hook, child chain, hook and rule ordinals, and exact selector
digest. The record must establish packet-only lifetime, no earlier matching overlap, and placement
after Flux's final routing/capture use. The reviewed policy and the complete live census must contain
the same canonical record set. Unknown, earlier, mismatched, socket, conntrack, or transferred
overlaps reject. Functional mark-preservation and VPN/netd coexistence remain activation canaries,
not facts inferred from structural ordering.

The first checked-in observed-behavior policy targets one exact Samsung SM-S9180 platform selector.
Its initial revision intentionally admits no ordered-write exception, so selection alone cannot
cross C2. Later revisions must update the reviewed artifact digest and policy revision together.
