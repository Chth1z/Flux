# Generation-Scoped Functional Capture Canary

- Status: accepted implementation contract; production qualification incomplete
- Last updated: 2026-07-14

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

When the required functional gate is selected, `RUNNING` may be published only when both
verification layers succeed for the same Generation. The production compatibility composition
continues to publish operational `RUNNING` after structural verification while reporting
`structural_only` rather than claiming functional authorization.

### Ingress evidence is not local-OUTPUT evidence

The Linux namespace program must classify capture evidence by hook and traffic domain. A packet
injected from a separate probe namespace can enter the daemon namespace through an exact ingress
interface and exercise PREROUTING TPROXY. That is useful evidence for transparent listeners,
original-destination recovery, policy routing, relay behavior, counters, and cleanup, but it does
not exercise the Android local-application OUTPUT path.

This distinction is based on an observed kernel boundary, not only on documentation. In the
privileged Linux harness environment, marking a locally generated OUTPUT packet and selecting a
local policy route did not cause that packet to traverse PREROUTING or reach the TPROXY listener;
the xtables TPROXY target also rejects attachment to OUTPUT. Flux therefore never treats an
OUTPUT mark counter, a local-route lookup, or zero peer packets as proof that local OUTPUT reached
TPROXY. Those observations are route/loop negative controls only. Production local-OUTPUT
qualification requires its own device-supported capture mechanism and listener evidence.

REDIRECT and DNAT are not substitutes for that proof. They can deliver a rewritten local flow to
a conventional listener, but that does not exercise the selected TPROXY backend, its transparent
listener, or its original-destination semantics. A local-OUTPUT adapter may qualify only the
backend-specific listener path that it actually exercises. For a TPROXY Generation it must prove
delivery to that Generation's TPROXY listener with the expected tuple semantics; if the device has
no supported way to do so, the adapter reports `unsupported` instead of silently qualifying a
REDIRECT/DNAT path.

## Runtime status contract

Protocol version 3 carries a required verification field inside the independently revisioned
`RuntimeSnapshot`. It is deliberately orthogonal to operational phase:

- `structural_only` is the conservative baseline: no functional pass authorizes the current
  observation. It does not assert that structural verification has already completed.
- `functional_pending` means the current binding requires a fresh complete gate before it can
  regain functional authorization.
- `functional_passed` means the required gate and the subsequent `RUNNING` publication both
  succeeded for the exact current Generation, engine, and environment binding.
- `functional_failed` means the complete required gate failed, including a structural
  prerequisite, attempt execution, evidence/identity validation, or cleanup proof.

A passed attempt is not published as `functional_passed` before `state-running` succeeds. Failed
publication returns to `functional_pending`, because the retry requires a fresh attempt. Engine or
environment identity loss, restart, repair, uncertain reload detachment, and active address
resynchronization also invalidate a pass. Address resynchronization schedules a fresh running gate;
failure enters capture repair because the Network Epoch may have changed partially. Rollback runs a
new attempt for the restored Generation and never inherits candidate evidence. Administrative stop
resets to `structural_only`, meaning no functional authorization remains for an inactive runtime.

`RuntimePhase::Running` remains an operational statement and never implies functional
qualification. Likewise, `functional_passed` records an exact attempt-level result; until the
stage-4 Android matrix is evidenced, it is not a production-device qualification claim. The
production Phase 1 composition explicitly selects structural-only compatibility.

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

### Schema-v2 listener and delivery authority

Functional-canary evidence schema v2 requires authoritative inbound listener-delivery evidence
for every flow. The request-selected backend remains TPROXY. `REDIRECT` and `DNAT` are typed
negative evidence only and always fail backend matching; they are not supported fallback request
backends.

The proof has two independent parts. The static listener observation binds the exact Generation,
supervised engine PID and start ticks, readiness listener identity, daemon network namespace,
Capture Program digest, attempt selector, protocol and family, listener FD/inode/INET_DIAG cookie,
family-correct wildcard bind at the admitted port, transparent-socket state, and IPv6-only state.
IPv4 carries no `IPV6_V6ONLY` state, while the separate IPv6 listener must be v6-only. The
observation also names the pre-bound socket-observer authority, its nonzero sequence, unchanged
loss counter, and monotonic observation time. Distinct `(family, protocol)` listener roles cannot
reuse an FD, inode, or socket cookie.

The per-flow delivery event uses one authority for the whole attempt: either an exact supervised-
engine report bound to the attempt-owned report object and report schema v1, or the exact
separately qualified cgroup-BPF observer. Delivery sequences are nonzero and unique per flow; the
cumulative delivery-loss and listener-observation-loss baselines remain constant, and no event may
lose records. Listener-observer and delivery-event sequences are independent numeric domains, so
only monotonic timestamps establish their causal order.

TCP evidence links a distinct accepted FD/inode/cookie to the parent listener cookie and exact
supervised engine. Its identity cannot collide with any listener role; its local tuple equals the
original destination and its peer tuple equals the probe source. Accepted inodes and cookies
cannot be reused across TCP flows. UDP evidence records
one `recvmsg` delivery per datagram, the selected listener cookie, exact source and original
destination, no payload or control truncation, and exactly one family-correct original-destination
cmsg with a 16-byte `sockaddr_in` or 28-byte `sockaddr_in6`. Echo and DNS share one stable listener
socket for each `(family, protocol)` pair.

The inbound payload is also exact: echo binds the 32-byte nonce, wire length, and SHA-256; DNS binds
the canonical query bytes, attempt nonce, transaction ID, question digest, wire length, and
SHA-256. DNS/TCP additionally binds the two-byte length prefix to the DNS message length; the
digest covers the DNS message bytes. A copied tuple, readiness port/path, `Tproxy` enum, self-report
alone, or counters cannot qualify a flow.

The schema-v2 `validate_for` listener/delivery validation is complete. Production evidence
construction is not: positive listener and delivery constructors remain private and test-only
until a real observer/report factory can prove the local-OUTPUT traffic domain and exact capture
receipt. A production-compiled executor/driver/factory boundary now exists, but its current
xtables raw-artifact type is uninhabited and therefore cannot construct positive evidence.

### Fail-closed local-OUTPUT executor seam

The delivered local-OUTPUT seam is an evidence-admission boundary, not a positive capture
implementation. Request construction remains hardwired to TPROXY. The executor rejects a
REDIRECT or DNAT request as `InvalidEvidence` with cleanup `NotRequired` before driver preparation.
Driver preparation is read-only and can report only the typed availability classes
`unsupported`, `denied`, `conflicting`, `broken`, or `unknown`; each maps to
`Availability(...)` with cleanup `NotRequired`. A prepared value marks the boundary after which
mutation may have occurred. Failures after that point must carry cleanup `VerifiedAbsent` or
`Uncertain`; a missing or inconsistent proof is promoted to `CleanupUncertain` with cleanup
`Uncertain`.

The driver returns raw observations only. A module-private evidence factory is the sole promotion
path into schema-v2 gate evidence. The current zero-state xtables driver has no prepared value: it
reports `Availability(Unsupported)` before acquiring a networking writer or mutating state because
the installed program can only mark OUTPUT and apply TPROXY in PREROUTING. It never attempts
TPROXY in OUTPUT and never substitutes REDIRECT, DNAT, ingress PREROUTING traffic, a veth bounce,
counters, or route-lookup inference. Its raw type and the current factory input are uninhabited, so
the seam cannot produce a positive host result.

Before a positive factory can inhabit that path, it must bind an explicit local-OUTPUT capture
receipt rather than trusting a `Tproxy` label, observe the exact probe and engine UID+GID/process
credentials, prove report-object cleanup and cleanup timing, and bind the real pre-opened socket-
diagnostics authority. Those are later checkpoints. "Fail-closed" here means weak evidence cannot
qualify the gate; it does not override the separate user-selected fail-open versus fail-closed
connectivity compensation policy.

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

The Linux ingress checkpoint uses a narrower three-namespace topology. A probe namespace sends
traffic through a second veth into the daemon/relay namespace, where exact interface, source,
destination, protocol, and port selectors exercise PREROUTING TPROXY. Its delivered ingress slice
proxies dual-stack TCP and UDP echo through transparent Rust listeners, proves accepted TCP sockets
and strict UDP original-destination ancillary data retain the intended peer tuple, and opens
separately marked relay sockets to the existing peer namespace. UDP responses use a separate
transparent marked socket bound to the recovered destination so the probe observes the original
source. The same listeners also proxy nonce-derived authoritative DNS queries over UDP and TCP,
retaining the existing transaction, question, digest, and answer checks. Forwarding remains
disabled so a missed selector cannot silently reach the peer. This
proves only the ingress traffic domain and test-local relay; it does not instantiate the dedicated
production probe/engine UIDs or the Sing-Box local-OUTPUT path.

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

The delivered Linux ingress slice applies the TCP/UDP echo payload contract to a test-local relay
for both address families. Its report cross-checks three distinct observations rather than
equating the client and peer tuples: probe client to original peer destination, transparent relay
receive state to the recovered original destination, and marked relay outbound socket to peer
responder. UDP additionally cross-checks the transparent response socket bound to the recovered
destination and connected to the exact probe tuple, proving source-preserving responses. The DNS
flows retain the existing transaction/question/answer checks over both transports and cross-check
the parsed client, relay, and peer reports. The schema-v2 validator is complete, but these ingress
reports are not authoritative constructors for it. A positive distinct-UID local-OUTPUT producer
behind the delivered executor seam must produce the backend-specific listener and delivery records,
invoke the outbound collector against the exact supervised engine, and construct the remaining
attempt evidence.

### Delivered `/proc` FD plus INET_DIAG correlation prerequisite

The Linux/Android collector for the primary non-eBPF correlation path is delivered. For the exact
supervised PID and `/proc` start-tick identity, it requires identical bounded pre/post socket-FD
inventories and completes the IPv4/IPv6 TCP and connected-UDP INET_DIAG dumps under one caller-
supplied exclusive monotonic deadline. A successful evidence join binds the transport protocol,
exact local and remote tuple, socket UID, required mark, numeric FD, matching `/proc` and INET_DIAG
socket inode, INET_DIAG cookie, collector identity/sequence, process identity, and the recorded
dump/snapshot timing interval inside the corresponding flow window. An incomplete scan or dump,
FD drift, deadline expiry, resource-bound breach, dump interruption, malformed or duplicate/
ambiguous match, identity drift, missing cookie/inode/FD/mark binding, tuple/UID/mark mismatch, or
out-of-window observation fails closed; enumeration hints are never promoted into correlation
evidence.

This collector is deliberately not a canary executor or the complete listener-envelope producer.
It does not create the distinct probe and engine UIDs, install local-OUTPUT capture, generate
traffic, prove transparent/v6-only listener socket options, observe TCP accept or UDP ancillary
delivery, or construct the schema-v2 evidence. Those transaction-level responsibilities remain in
the separate local-OUTPUT adapter/executor and authoritative observer/report factories.

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

1. **Complete:** typed attempt/evidence types, an injectable canary executor, coordinator ordering,
   failure injection, deadline, stale-identity, cleanup, retry, restart, resynchronization, and
   rollback tests. Existing structural verification remains a separate prerequisite, and protocol
   version 3 exposes the orthogonal verification result without enabling the production gate.
2. **Complete:** the first privileged Linux namespace checkpoint exercises real dual-stack TCP,
   UDP, and DNS traffic and independently verifies exact topology cleanup. It proves the
   traffic-flow contracts and contained test topology without installing capture.
3. **Complete for the ingress domain:** the third-probe-namespace checkpoint exercises exact dual-
   stack TCP/UDP echo and DNS-over-UDP/TCP PREROUTING TPROXY selectors, accepted-socket and strict
   ancillary-data original-destination recovery, marked relay egress, source-preserving UDP
   responses, parsed DNS transaction/question/answer evidence, per-family route controls,
   independent bounded flow counters, and exact cleanup. The empirical OUTPUT boundary above
   remains part of its acceptance contract.
4. **Complete prerequisite:** the strict Linux/Android `/proc` FD plus INET_DIAG collector and
   model correlation bind protocol, exact tuple, UID, mark, FD/inode/cookie identity, complete
   dumps, supervised-process identity, and timing. This is evidence plumbing, not a functional
   pass.
5. **Complete model checkpoint:** functional-canary schema v2 requires the exact TPROXY listener,
   transport-specific TCP accept or UDP `recvmsg` delivery, attempt-bound authority, loss/timing,
   stable cross-flow socket identity, and exact inbound wire evidence described above. Positive
   constructors remain private and test-only.
6. **Complete credential preflight:** the opt-in Linux checkpoint creates a disposable namespace
   with exact singleton controller/probe/engine UID and GID maps, delegated nonzero role IDs,
   empty supplementary groups, exact namespace/map readback, zero role capabilities, and
   `NoNewPrivs`. Optional mode skips unavailable outer prerequisites and required mode fails; exact
   validation failures fail in both modes. It sends no traffic and is not capture qualification.
7. **Complete fail-closed seam:** the TPROXY-only executor separates read-only availability,
   prepared execution, raw observations, and module-private evidence promotion. The current
   xtables driver reports `unsupported` with cleanup `NotRequired` before mutation and has no
   positive raw value. Required-mode coordinator regression proves this result cannot reach
   `RUNNING`; production composition remains structural-only.
8. Add a separate positive local-OUTPUT qualification slice using the delivered credential preflight, real
   listener-observer and delivery-report factories, prebound integration of the delivered outbound
   collector, and the completed schema-v2 `validate_for` path. A separately qualified cgroup-eBPF observer may replace
   the report only after its own authority and loss contract is proven. REDIRECT/DNAT delivery
   cannot qualify a TPROXY Generation; an adapter without a qualifying TPROXY listener path reports
   `unsupported`. This slice must not weaken the model to accommodate the ingress checkpoint.
9. Add an Android lab adapter that reports explicit `unsupported`, `denied`, `conflicting`,
   `broken`, or `unknown` evidence. It remains diagnostic-only until exact-device qualification.
10. Permit TPROXY `RUNNING` only for reviewed device profiles whose functional canary passes the
   real-device matrix and cleanup/crash tests. Other profiles remain unqualified; broaden the
   reviewed set without weakening the probe. TUN remains rejected until its separate
   single-route-owner and forced-death cleanup canaries pass.

Invoke the credential-only checkpoint separately from ordinary CI:

```text
cargo xtask test-functional-canary-linux-output-preflight
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-output-preflight
```

It never invokes `sudo`, loads modules, installs capture, or sends traffic. File-backed subordinate-
ID discovery may conservatively skip NSS-only configurations; Android requires a separate true-
root, collision-qualified UID/GID adapter.

Invoke the delivered topology checkpoint separately from ordinary CI:

```text
cargo xtask test-functional-canary-linux
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux
```

The task selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup`
and runs it with one test thread. `FLUX_LINUX_CANARY_REQUIRED` accepts only `0` or `1`: optional
mode reports unavailable or denied outer preflight prerequisites as an explicit skip, while
required mode fails. Once isolated mutation begins, later setup or capability errors fail in both
modes so cleanup uncertainty cannot be mistaken for an unavailable host. The task does not invoke
`sudo`; the Rust harness owns authoritative isolation and capability
preflight. It also removes all harness-internal mode, configuration, token, and outer-namespace
variables before invoking Cargo, so caller state cannot bypass the outer preflight. This command
is deliberately excluded from `cargo xtask ci`.

Invoke the delivered ingress TCP/UDP/DNS slice with:

```text
cargo xtask test-functional-canary-linux-tproxy
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-tproxy
```

The command selects only the ignored test
`functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup`
with exact matching, `--nocapture`, and one test thread. The current implementation covers
dual-stack TCP/UDP echo plus nonce-bound DNS over UDP/TCP, including strict UDP original-
destination cmsg validation, source-preserving replies, and DNS transaction/question/answer
cross-checks across the client, relay, and peer.
The deterministic regression `ingress_rule_plan_never_places_tproxy_in_output` proves that rule
generation never emits xtables TPROXY in OUTPUT. OUTPUT-mark or route-lookup evidence still cannot
qualify PREROUTING TPROXY without exact listener/flow evidence.

The ingress checkpoint remains outside `cargo xtask ci` and uses the same optional/required
preflight policy as the delivered topology checkpoint. It must not invoke `sudo`, `modprobe`, load
a `.ko`, or convert unavailable kernel support into a passing capture result. Before any rule
mutation, preflight requires the xtables TPROXY, mark, comment, family TPROXY, and selected backend
support to be visible as already active under `/sys/module`; otherwise it skips or fails rather
than triggering implicit module autoload.

Until the positive local-OUTPUT producer and real-device qualification are evidenced, Flux must
describe Phase 1 capture verification as structural and the functional exit gate as incomplete.
The delivered collector, host ingress tests, Linux namespaces, route lookups, or successful
counters do not authorize production `functional_passed` and do not constitute Android evidence.

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
