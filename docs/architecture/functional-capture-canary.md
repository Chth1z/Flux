# Generation-Scoped Functional Capture Canary

- Status: accepted implementation contract; production qualification incomplete
- Last updated: 2026-07-13

This document defines the next Phase 1 bridge tracer bullet. It turns `capture-verify` from a
structural check into a bounded functional transaction without claiming that the Android
production adapter is already qualified.

## Verification boundary

Structural verification remains mandatory. The current bridge check proves the exact Generation,
capture-owner record, address-synchronizer status, runtime mode, and cleanup artifacts. Before the
functional gate becomes a production claim, the structural layer must additionally read back the
exact live rules, routes, marks, listener ownership, and engine identity. Neither form proves that
a packet reaches the listener, that Sing-Box reaches an outbound peer, that DNS works, or that an
engine socket escapes recapture.

Functional verification runs only after structural verification and capture publication. It must
send real TCP, UDP, and DNS traffic through the active Generation and receive nonce-correlated
attempt-local responses. Listener presence, file presence, a successful command, or netfilter/BPF
counters alone never satisfy the functional gate. Counters may support the evidence record.

`RUNNING` may be published only when both verification layers succeed for the same Generation.

## Attempt identity and evidence

Each attempt is immutable and records at least:

- schema version, Generation ID, boot ID, Capability Profile revision, daemon network-namespace
  identity, Network Epoch/snapshot identity, Capture Program digest, and the current capture-owner
  record;
- exact engine PID, `/proc` start ticks, executable/configuration digest, engine Generation, and
  generation-specific listener identity;
- a cryptographically random attempt nonce, a monotonic start time, and one absolute deadline that
  retries cannot extend;
- dedicated probe UID, peer network-namespace identity, veth ifindexes and addresses, enabled
  address families, reviewed RPDB/table placement, and the installed canary selector/object
  identities;
- per-flow protocol, family, destination, expected nonce-bearing payload, received payload, peer
  observation, timing, and bounded failure diagnostics;
- engine outbound loop-escape evidence and final cleanup/readback result.

The coordinator rechecks the boot, namespace, engine identity, and capture Generation immediately
before the first flow and after the last flow. A mismatch, stale reply, missing peer observation,
or expired deadline invalidates the whole attempt. A verification record names only one
Generation; it cannot be reused after restart, reload, network-namespace replacement, or engine
replacement.

## Contained peer topology

The probe must not depend on a public Internet service. It must not target loopback, because
loopback and device-local traffic are mandatory bypass domains and would not exercise capture.

The contained topology is split into a boot-scoped facility and Generation-scoped attempts:

1. Before any Generation is planned or an active Generation exists, the one serialized networking
   writer creates a uniquely named, journaled peer network namespace and veth pair. In the Phase 1
   bridge this is a dedicated shell writer phase ordered by Rust; `fluxd` does not issue a second
   set of network mutations. The future native writer creates the same facility before collecting
   the final Network Inventory. Reload reuses the existing verified facility and never creates or
   replaces it while the prior Generation is active.
2. The daemon side stays in the engine's network namespace; the peer side is reserved for bounded
   canary servers. The facility's link identities, IPv4 and enabled IPv6 point-to-point addresses,
   stable responder ports, private canary table, exact RPDB selectors, and namespace identity enter
   the Capability Profile and every Generation's planning evidence. Creation is followed by a
   fresh inventory snapshot; a verifier must never introduce an unobserved link after activation.
3. Facility addresses must be ordinary unicast destinations outside every mandatory and
   configurable bypass, FakeIP, listener, and local/device-owned domain. They come from a reviewed
   canary pool and are rejected on any live collision. Private, ULA, link-local, documentation,
   benchmark/FakeIP, multicast, loopback, and other normally bypassed ranges cannot prove loop
   escape. No main-table or Android-owned route is replaced.
4. Every attempt rechecks the facility's exact ifindexes, addresses, routes, namespace identity,
   responder ports, and current Network Epoch before installing ephemeral selectors or starting
   traffic. The facility does not change the device default route or Android-owned policy.
5. A short-lived client runs under a dedicated probe UID. A Generation-scoped selector matching
   that UID, peer addresses, protocols, and ports sends only the attempt's traffic through the same
   TPROXY action, policy route, and generation-specific listener used by production capture. The
   selector is ordered after control/engine loop prevention and before ordinary configurable
   bypass policy, and cannot match production traffic.
6. The peer namespace runs nonce-aware TCP echo, UDP echo, and authoritative DNS responders. It
   accepts only the attempt's addresses, ports, and nonce-derived query name, applies strict byte
   and request limits, and exits at the attempt deadline.

The peer route is traffic-scoped, not a boot-long override of an arbitrary global destination.
The facility requires a dedicated engine UID and installs a device-qualified RPDB rule matching
that UID, exact canary destination, protocol, and responder port before selecting the private
canary table and veth route. The priority, table, selectors, rule semantics, and readback are
subject to the same Android collision and ownership gates as production policy routing. Other
UIDs—including ordinary traffic to the same destination—continue through Android's normal policy.
A root-wide UID rule, unqualified fixed priority/table, main-table host route, or canary socket mark
without positive mark authority is forbidden.

The canary engine-UID rule must also match `fwmark 0/FLUX_PROXY_MASK`, while the normal Flux
proxy-fwmark rule has strictly higher precedence. Exact readback proves both selectors and their
ordering for each family. An engine packet recaptured by mistake therefore cannot match the peer
table and returns to the local TPROXY path. Before the positive flow, a kernel route-lookup negative
control using the engine UID, canary tuple, and Flux proxy mark must resolve the Flux local-capture
table rather than the peer table; where side-effect-contained packet injection is available, the
peer must additionally observe zero such packets. The real supervised engine outbound leg must
then reach the peer with the Flux proxy-mask bits clear. These checks are mandatory parts of the
loop-escape proof.

Object names come from a reserved Flux canary namespace. Facility addresses and ports are allocated
once per boot only after collision checks against the complete live inventory and supported
Generation bypass, FakeIP, listener, and route domains. Every attempt revalidates them. Any link,
route, rule, process, address, port, or object collision rejects facility creation or later use.
The implementation must not scan or delete objects by a broad prefix.

## Immutable engine canary plan

The facility endpoints are stable before Generation compilation. The immutable Sing-Box
configuration contains a private, version-qualified canary plan that the user cannot select or
override:

- an exact direct outbound used only for the facility addresses and responder ports;
- exact TCP and UDP route rules to that outbound;
- a dedicated DNS transport to the facility's authoritative responder and an exact nonce-name
  suffix rule that selects it after DNS hijack;
- explicit exclusions preventing ordinary traffic from selecting any canary component.

The exact packaged Sing-Box binary validates this configuration before engine admission. Attempt
nonces change payloads and DNS names, not addresses, ports, or routing syntax. A public or
user-selected outbound, the user's normal DNS transports, or a post-launch configuration mutation
cannot satisfy the canary.

## Required flows

For IPv4 and for IPv6 whenever the Generation enables it, the attempt performs:

- one TCP connection whose nonce-bearing request and response are observed by both the client and
  peer;
- one UDP exchange with the same bidirectional nonce proof;
- one DNS query over UDP and one over TCP for a nonce-derived name, with a nonce-derived answer and
  matching transaction/question data.

All flows must enter through the dedicated client selector, traverse the active capture path and
generation-specific Sing-Box listener, leave through an engine-owned outbound socket, reach the
contained peer, and return before the absolute deadline. Success in one family never substitutes
for an enabled family that failed.

The local peer validates the received payload and records the engine-side connection/datagram
tuple. The adapter correlates that tuple with the exact supervised engine identity and validates
the configured loop-escape mechanism where the platform exposes authoritative socket/route
evidence. The response plus peer observation proves real outbound progress; supporting capture and
bypass counters must show a bounded, expected delta rather than recursion. An absent BPF event,
zero packet loss, or an engine UID match by itself is not loop-prevention evidence. In particular,
a blanket root-UID bypass is forbidden: the escape must belong to the supervised engine's sockets
or exact process identity. The current root/root compatibility bridge therefore cannot satisfy
this final proof and remains structural-only.

## Cleanup and failure semantics

Every mutation has an ownership token and an inverse operation recorded before execution. Attempt
cleanup is capture-safe:

1. quiesce, terminate, and reap the probe client while selectors and leak guards remain active;
2. remove the canary selector and attempt-only guards/counters and verify them absent;
3. stop and reap the peer servers;
4. retire the attempt record while retaining the unchanged boot facility for fresh
   verification after restart or publication retry.

Clean daemon shutdown and startup/offline recovery remove the facility's RPDB rules and private
table routes, then its addresses, veth pair, and peer namespace, and finally verify every exact
journaled object absent. They do so only when no active Generation exists and capture detachment is
proven. Candidate failure or retirement removes only that Generation's attempt evidence and
immutable config references; it does not disturb the shared boot facility.

RAII guards handle ordinary exits. Separate facility and attempt recovery records keyed by boot
ID, Generation, and nonce handle daemon death; startup recovery removes only exact journaled
objects. Cleanup is bounded by the same phase policy as other bridge operations and retains
evidence on uncertainty.

Any functional failure, timeout, identity change, unexpected extra flow, response mismatch, or
uncertain canary cleanup prevents `RUNNING`. The coordinator then uses the existing capture-first
compensation path: prove capture detached before stopping or retiring the engine or publishing a
terminal state. Uncertain detachment remains `DetachPending` or `CaptureRepairPending` and blocks
start/reload. Reload may restore the previous immutable Generation only after candidate detachment
is proven. A failed `RUNNING` publication requires a fresh engine observation and a fresh complete
canary; previous evidence never authorizes a blind retry. Default compensation is fail-open unless
the user explicitly selected fail-closed policy.

Attempt-level interruption, busy, or timeout evidence may receive bounded retry/backoff within the
absolute deadline. It does not become a durable `Transient` capability and does not permit a
functional pass.

## Staged delivery and qualification

1. Add typed attempt/evidence types, an injectable canary executor, coordinator ordering, failure
   injection, deadline, stale-identity, and cleanup tests. Existing structural verification remains
   a separate prerequisite.
2. Implement a privileged Linux network-namespace integration harness with real TCP, UDP, DNS,
   loop-escape, IPv4, and IPv6 flows. This proves the transaction and test topology, not Android
   compatibility.
3. Add an Android lab adapter that reports explicit `unsupported`, `denied`, `conflicting`,
   `broken`, or `unknown` evidence. It remains diagnostic-only until exact-device qualification.
4. Permit TPROXY `RUNNING` only for reviewed device profiles whose functional canary passes the
   real-device matrix and cleanup/crash tests. Other profiles remain unqualified; broaden the
   reviewed set without weakening the probe. TUN remains rejected until its separate
   single-route-owner and forced-death cleanup canaries pass.

Until stage 4 is evidenced, Flux must describe Phase 1 capture verification as structural and the
functional exit gate as incomplete. Host tests, Linux namespaces, or successful counters do not
constitute production Android evidence.

## Open Android qualification work

The production endpoint remains deliberately unresolved. Exact devices must establish whether
SELinux and the installed root environment permit safe network-namespace, veth, host-route,
dedicated-UID, TPROXY, DNS responder, socket-identity, and cleanup operations without disturbing
netd, secure/lockdown VPN, per-UID selection, Private DNS, CLAT, tethering, or default-network
handover. Address pools and labels must be collision-checked against live Android state rather than
hard-coded globally.

Qualification requires real Android devices at the 5.10 floor and later kernels, both enforcing
and relevant root-manager modes, IPv4 and enabled IPv6, network transitions, forced daemon/engine
death at every probe step, and readback proving cleanup. A device on which the contained topology
cannot be created safely is not functionally verified; the implementation must report the exact
denial or conflict and must not fall back to a public endpoint, loopback, or counter-only success.
