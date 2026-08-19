---
status: accepted
decision_date: 2026-08-20
supersedes:
  - 0004-ebpf-is-optional-observation-and-acceleration
  - 0005-prefer-native-nftables-with-compatible-fallbacks
---

# Promote Sing-Box eBPF to an engine-owned Capture Path

Flux will support the upstream Sing-Box eBPF inbound as a correctness-bearing Capture Path. While
nftables remains deferred, automatic selection is ordered as eBPF, xtables TPROXY, then Managed
TUN. An exact request never falls back. Automatic selection may try the next implemented,
freshly-qualified path when the current candidate is rejected before publication.

This decision supersedes only the eBPF role and automatic-order portions of ADR-0004 and ADR-0005.
Their requirements for active qualification, complete policy coverage, explainable rejection,
single-writer ownership, exact verification, and safe fallback remain in force. eBPF observation
and acceleration may still be used on another primary Capture Path, but that role is independent
from qualification of the eBPF inbound itself.

The first delivery slice is Android local capture for IPv4 TCP. UDP and IPv6 may be enabled only
when the exact upstream binary and current kernel pass their requested active probes. Shared and
hybrid capture remain later slices. A candidate is not Qualified merely because the kernel version,
configuration, or build tags appear compatible.

Flux does not patch Sing-Box to add a prepare/activate protocol. It consumes an externally supplied,
upstream eBPF-capable Sing-Box binary and its standard configuration and `tools ebpf status --json`
command. The qualification receipt binds the binary digest, network namespace, exact probe request,
probe output digest, observation time, and bounded expiry. `unsupported` and `inconclusive` are both
non-authorizing; UNKNOWN findings never become Qualified.

## Engine-owned lifecycle

Sing-Box creates cgroup or TC attachments while the eBPF inbound starts. Consequently eBPF uses a
process-coupled lifecycle rather than the existing externally-attached xtables sequence.

1. Preparation compiles the Capture Program and canonical Sing-Box eBPF configuration, validates
   complete requested coverage, and records a fresh binary-bound probe receipt. It does not attach
   programs or change traffic.
2. Activation starts the supervised engine. Runtime state reports capture as activating while the
   process may be creating attachments; it must not claim that capture remains detached.
3. After normal engine readiness, Flux verifies the expected active attachment/program inventory
   and the required functional behavior. Only then does it admit capture as Published and publish
   the Generation as Running.
4. Stopping or replacing an engine-owned Generation stops the supervised process first, then proves
   clean attachment absence. This order is the inverse of an externally-attached xtables path.
5. Candidate failure stops the candidate, proves clean absence, and only then may restart the
   recorded predecessor. Failure to prove absence blocks replacement and remains an explicit repair
   state; it is not treated as successful fail-open cleanup.

`capture_start` for this lifecycle is an admission/readback operation over attachments already
created by the retained engine process. `capture_stop` is an absence verifier after that process has
stopped. Neither method may be implemented as an unconditional no-op or claim ownership of links
that Flux did not create.

Every Generation still has exactly one primary Capture Path. Flux never intentionally leaves eBPF
and xtables/TUN capture active together. Observability may explain selection, health, load, and
fallback, but telemetry cannot attach programs, switch paths, or publish a Generation.

