# Generation-Scoped Functional Capture Canary

- Status: supporting pre-release qualification contract; activation work deferred
- Last updated: 2026-07-17

This document defines a supporting qualification contract for an executed Rust-owned Capture Path.
The model and development mechanism evidence are retained, but further activation plumbing is deferred until a real
backend can inhabit its receipt authorities. It is not the next delivery lane, and none of its
bridge/shadow/model checkpoints is releasable. A final advertised Capture Path must eventually pass
the applicable Android transaction before the Rust-only release gate can close.

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
verification layers succeed for the same Generation. The current pre-release compatibility
composition continues to publish operational `RUNNING` after structural verification while
reporting `structural_only` rather than claiming functional authorization; that development bridge
cannot become a release on this basis.

### Shadow Capture Programs are not canary authority

The Phase 2 shadow compiler is outside this verification transaction. Its deterministic semantic
digest is domain-separated from the Generation-bound Capture Program digest in an attempt, and a
shadow artifact has no Generation ID, capture-owner record, Backend Plan, writer token,
prepared/active state, listener identity, or Runtime Coordinator entry point. A model decision or
successful frozen-oracle fixture comparison therefore cannot satisfy structural verification,
construct an attempt, authorize traffic, or publish any functional status. The observation-only
shadow compiler is complete and frozen; `scripts/tproxy` remains the sole production restore writer
until backlog item 3 qualifies and transfers the native component lease.

Legacy source-shape renderer parity and canonical xtables lowering are complete as non-authorizing
artifacts. Forwarded-only input preserves exact schema-v1 bytes and identities. Any local-OUTPUT
input selects schema v2: `FLX{4|6}O{generation:010}` is the MARK-only OUTPUT classifier,
`FLX{4|6}P{generation:010}` is the mark-qualified loopback PREROUTING TPROXY companion when proxy
traffic exists, and an optional `FLX{4|6}F{generation:010}` retains the forwarded role. Typed entry,
transparent-listener, compatibility loop-escape, lifecycle, identity, and resource metadata describe
the full ADR-0012 dependency shape. The exact routing identity requires nonzero route and rule
protocols, an explicit nonzero route metric, IPv4 HOST scope, and IPv6 UNIVERSE scope. The lowering
itself attaches no built-in hook and acquires no route, listener, or writer authority.

The crate-private `NativeXtablesOwner` and its real process/netlink `Adapter` now consume that
artifact and provide stable-hook mutation, restore/save, journaled routing, exact readback,
rollback, crash recovery, and cleanup in deterministic tests and the rooted disposable-WSA
mechanism checkpoint. Its schema-2 durable identity digests the complete IPv4/IPv6 routing audit and
loopback name/index; live validation runs in both directions, and complete two-family xtables/routing
residue checks precede `Active` or `CleanAbsent`. Current terminal journals retain the native guard,
shared writer fence, and optional lease through fresh global dual-family absence before terminal
artifacts retire. The coherent previous-boot revision-1 `Activating` pre-lease boundary is
recoverable; same-boot or mismatched missing-lease state stays fail-closed.

Shell-owner v2 retains parent plus optional child PID/start identities and boot ID. Either live
participant blocks; one serialized parent-bound mutating `addrsync` or `tproxy` phase child changes
only its slot and remains blocking after parent death; a live parent can reclaim a dead child; and
only both-dead, PID-reused, or previous-boot records retire after revalidation. Bare, malformed,
mixed, and unverifiable locks stay fail-closed. Legacy start/stop/restart/failure cleanup holds the
same fence before `addrsync` or `tproxy` mutation. The standalone daemon remains a later cutover
duty. Positive production target
admission remains deliberately uninhabited, and WSA is not release authority. Backlog item 3 must
still bind the engine/canary and ownership
authorities, qualify reviewed Android 5.10/ARM64 profiles, transfer the lease, and delete the
replaced shell duties. Established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC
rejection, and MSS clamping remain later gates. Neither lane adds an eBPF attach/pin path, TUN
activation, implicit module request, or `.ko`/KPM loading that could provide an alternate evidence
source.

### Ingress evidence is not local-OUTPUT evidence

The Linux namespace program must classify capture evidence by hook and traffic domain. A packet
injected from a separate probe namespace can enter the daemon namespace through an exact ingress
interface and exercise PREROUTING TPROXY. That is useful evidence for transparent listeners,
original-destination recovery, policy routing, relay behavior, counters, and cleanup, but it does
not exercise the Android local-application OUTPUT path.

The hook distinction remains real, but the earlier negative interpretation was too broad. Linux
5.10 recomputes the OUTPUT route after a relevant mark change, an RPDB-selected local route can
transmit through loopback, and loopback receive processing invokes PREROUTING. The checked-in
ingress harness does not exercise that path: its selector is tied to the veth ingress interface.
In the frozen shell source shape, an optional connmark-qualified TPROXY fast path precedes the
generic loopback bypass. That historical variant does not define or qualify the selected mandatory
packet-mark contract. Flux therefore never treats an OUTPUT mark counter,
a route lookup, or zero peer packets as proof of capture, but it may qualify the complete
OUTPUT-mark → local-route → loopback-PREROUTING-TPROXY transaction through a dedicated canary.
Production qualification still requires exact listener evidence and reviewed Android profiles.

ADR-0012 selects the first conventional qualification candidate as one ordered transaction. The
schema-v2 description prepares private `O`, `P`, and optional `F` objects plus the exact transparent
TCP/UDP listener, loop escape, and RPDB/local-route identity with nonzero route and rule protocols,
an explicit nonzero route metric, IPv4 HOST scope, and IPv6 UNIVERSE scope; it then orders
attachment as `P`,
optional `F`, and `O` last. Retirement orders detachment as `O`, optional `F`, and `P`, then releases
escape, routing, listener, and private objects by exact inverse identity. A production executor must
perform and prove that order; the lowering metadata itself does not.
The checkpoint must prove dual-stack TCP accept and UDP original-destination delivery, positive
boundary counters, bypass-mark response escape, safe misses, no peer leakage, no implicit module
autoload, exact owned-state removal, and baseline restoration with only explicitly admitted
namespace-local equivalence.

The first opt-in mechanism-only host checkpoint is:

```text
cargo xtask test-functional-canary-linux-output-tproxy
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-output-tproxy
```

It selects
`functional_canary::linux_namespace_harness::privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup`.
This test does not combine the separate distinct-UID preflight, bind a Generation or production
receipt authority, consume a supervised Proxy Engine report, or qualify an Android profile. A host
pass therefore remains supporting mechanism evidence and cannot publish `functional_passed`.

The same exact ignored test also has a non-shipping rooted x86_64 Android runner:

```text
ANDROID_NDK_HOME=/path/to/android-ndk-r27d \
  cargo xtask test-functional-canary-android-x86_64-output-tproxy \
  --serial SERIAL [--adb PROGRAM]
```

The runner requires one explicit ADB serial, x86_64/SDK-31-or-later Android, UID 0, the pinned NDK,
and the installed Rust target. It cross-builds from Cargo JSON, binds the exact build fingerprint and
boot ID before remote mutation and around cleanup, bounds every host command with kill/reap handling,
forces required mode, sanitizes the Android helper path, uses a private `/data/local/tmp` `TMPDIR`,
lists and runs only the exact test, and proves remote cleanup. On 2026-07-15 it passed on WSA Android
13 / SDK 33 with Magisk root, SELinux enforcing, legacy iptables 1.8.7, and kernel
`5.15.104-windows-subsystem-for-android-20230927+`.

That pass adds Android mechanism evidence for the selected transaction. It proves real-root
mount/network isolation, dual-stack TCP/UDP listener delivery, Android-owned socket-mark-bit
preservation through a test-only masked field, legacy iproute2 compatibility, no-autoload built-in
evidence, negative controls, and cleanup. It still does not combine distinct UIDs, a Generation,
production capture/process receipts, a supervised Proxy Engine report, Android 5.10/ARM64,
netd/VPN/network-transition coexistence, forced-death recovery, or release qualification, so it
cannot publish production `functional_passed`.

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
stage-4 Android matrix is evidenced, it is not a production-device qualification claim. The current
pre-release Phase 1 composition explicitly selects structural-only compatibility.

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

The schema-v2 `validate_for` listener/delivery validation is complete. The separate local-OUTPUT
TPROXY capture-receipt contract is also complete at the model boundary. One non-cloneable receipt
stores the exact immutable request and one fixed-slot event for every required flow. Each event
binds the flow, nonce, request-bound probe UID, client tuple, exact inbound payload identity,
transparent-listener cookie, the same authoritative delivery event retained by schema-v2 evidence,
a unique nonzero sequence, and a daemon-observed monotonic time. Validation rejects missing or
unexpected family slots, request/backend drift, tuple/payload/listener/delivery mismatch, sequence
reuse, event loss, and observations outside the flow, attempt, client-lifetime, or immutable-deadline
envelope.

Receipt issuance is a separate authority boundary. A driver may return only unverified capture
proof plus raw observations; a module-private verifier must first mint receipt-bound artifacts, and
the evidence factory accepts only that verified form. The resulting unqualified gate record owns
the receipt by value, and its final `validate_for` path revalidates the receipt against the retained
flow evidence and cleanup client lifetime before loop, counter, and cleanup validation can pass.
The production verifier authority remains deliberately uninhabited, while tests use a scripted
authority to exercise the complete contract. Positive listener and delivery constructors therefore
remain private and test-only, and the current xtables prepared/raw path remains uninhabited and
cannot construct positive evidence.

The process-ownership receipt is now a second, separately sealed authority boundary after capture
verification. The immutable request carries explicit probe and engine UID plus GID and an exact
user-namespace, mount-namespace, UID-map, and GID-map domain. One non-cloneable receipt binds the
supervised engine's exact PID/start ticks and one retained handle across observations before and
after the required flows; it also binds the client and all peer PID/start-tick identities to
distinct attempt-owned handle openings and the exact cleanup retirement records. Every credential
observation requires stable real/effective/saved/filesystem UID and GID values, empty supplementary
groups, zero inheritable/permitted/effective/ambient capabilities, `NoNewPrivs`, the exact
credential-map domain, the role-correct network namespace, and flow/cleanup/deadline chronology.
Handle-opening IDs are receipt-local opaque correlation tokens: their numeric values are
alpha-renamable, while the sealed verifier authority proves which owned handle produced each
identity and validation rejects engine-handle drift or reuse across live roles.

The Linux/Android platform substrate for that future verifier is also delivered. A non-cloneable
`ProcessHandle` opens only from a retained live `Child`, correlates a pidfd with its procfs PID and
start ticks, proves the child remains waitable by this parent, and performs two stable bounded
censuses of every `/proc/<pid>/task/*/status` entry and opened user/mount/network namespace
descriptor so all threads have identical credentials and process domains. It also reads the
process UID/GID maps in both passes, strictly parses at most 340 canonical non-overlapping extents
within 16 KiB, and records domain-separated SHA-256 digests without copying request expectations.
A pidfd reporting exit is not accepted as reap evidence: the owner must still confirm
`Child::wait`, and the distinct-UID/GID preflight now exercises that ordering with live probe and
engine children.
The retained-engine authority handoff is now delivered. `SingBoxChild::open_process_handle` opens
the authority only from its retained live child, rechecks the recorded PID/start ticks, and leaves
signal/wait/reap ownership with the adapter. `EngineSupervisor` then requires matching ready,
active-spec, readiness, snapshot, owned-identity, and retained-child state before opening a
non-cloneable `EngineChildAuthority`. The serialized coordinator binds a single-use opener to the
exact request engine, snapshot revision, and deadline. The local-OUTPUT
executor invokes that opener only after read-only backend availability succeeds and before the
prepared-attempt boundary, so the current xtables `Unsupported` result performs no pidfd/procfs
scan. A successful opening carries a private nonzero opening identity and daemon-owned observation
time, then moves into the process-verifier boundary after capture verification. The first reviewed
verifier slice consumes that authority, preserves the complete child-origin observation,
reobserves the same retained pidfd after capture verification, and returns a non-cloneable raw pair
bound to the exact engine identity, snapshot revision, opening identity, and exclusive attempt
deadline. The final observation is timestamped only after the complete procfs scan, the pair
retains the handle privately without exposing signal/wait/reap operations, and an exit or deadline
failure after preparation becomes cleanup-uncertain.

The completed engine-policy/domain slice then validates both complete observations against the
immutable request. All four real/effective/saved/filesystem UID and GID slots must equal the exact
request engine UID/GID values; supplementary groups and every capability set must be empty;
`NoNewPrivs` must be set; and the observed user, mount, daemon network namespace, UID-map digest,
and GID-map digest must match exactly. Before/after stability compares the complete authoritative
platform observation, including its domain, and any mismatch remains cleanup-uncertain without
calling the evidence factory. Production process-receipt authority remains uninhabited: the
verifier does not yet retain and retire real client/peer `Child` values or establish the final
verifier-side attempt-completion timestamp required by receipt chronology.

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

The driver returns unverified capture proof, process proof, and raw observations only. The capture
receipt verifier first binds capture proof while carrying the process proof forward; the separate
process-ownership verifier must then mint a process receipt before the module-private evidence
factory can promote artifacts into schema-v2 gate evidence. A failure at either verifier remains a
post-preparation failure and cannot call a later stage. The production xtables driver has no
admitted prepared value: it reports `Availability(Unsupported)` before constructing a native target,
acquiring the production writer lease, or mutating state because positive target admission is
deliberately uninhabited. This is an admission fence, not an absent transaction engine. The private
`NativeXtablesOwner` and real process/netlink `Adapter` consume canonical schema-v2 lowering into
stable hooks, restore/save, journaled routing, exact readback, rollback, recovery, and cleanup under
deterministic and rooted disposable-WSA mechanism tests. The exact routing identity requires
nonzero route and rule protocols, an explicit nonzero route metric, IPv4 HOST scope, and IPv6
UNIVERSE scope. Its payload schema 2 additionally binds the complete dual-family route/rule audit and
loopback name/index, and publication requires both xtables families plus both routing identities to
be exact or absent.

That private mechanism never attempts TPROXY in OUTPUT and never substitutes REDIRECT, DNAT,
ingress PREROUTING traffic, a veth bounce, counters, or route-lookup inference. WSA does not supply
release authority, and the concrete production capture/process receipt authorities and factory
input remain uninhabited, so this seam cannot produce a positive production result. `scripts/tproxy`
remains the sole production restore writer until backlog item 3 qualifies Android 5.10/ARM64 and
transfers the component lease.

The remaining integration subcheckpoints must bind client/peer authority to driver-retained
children, establish final verifier completion chronology, construct the delivered report-object
and temporal cleanup evidence, and use the real pre-opened socket-diagnostics authority for actual
observations. A later positive producer must also replace both sealed receipt authorities with
reviewed concrete verifiers. A
separately qualified cgroup-BPF observer may later replace supervised delivery reports only after
its own attachment, identity, complete-event, loss, and lifecycle contract is proven; ordinary BPF
counters or sampled events cannot mint the receipt. No qualified production receipt path may
depend on explicit `.ko` loading or implicit module autoload. The current legacy structural bridge
does not yet prove that stronger no-autoload prerequisite and therefore cannot qualify the receipt.
"Fail-closed" here
means weak evidence cannot qualify the gate; it does not override the separate user-selected
fail-open versus fail-closed connectivity compensation policy.

## Contained peer topology

The probe must not depend on a public Internet service. It must not target loopback, because
loopback and device-local traffic are mandatory bypass domains and would not exercise capture.

The contained topology is split into a boot-scoped facility and Generation-scoped attempts:

1. Before any Generation is planned or an active Generation exists, the one serialized networking
   writer creates a uniquely named, journaled peer network namespace and veth pair. In the Phase 1
   bridge this is a dedicated shell writer phase ordered by Rust; `fluxd` does not issue a second
   set of network mutations. Backlog item 3 must bind the delivered native owner into production
   composition and create the same facility before collecting the final Network Inventory. Reload
   reuses the existing verified facility and never creates or
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

The collector now also exposes a uniquely owned, non-cloneable prebound session. Calling
`SystemSocketDiagnosticsSource::open_until` binds NETLINK_SOCK_DIAG under the caller's exclusive
deadline and exposes the kernel-assigned nonzero port ID before any process snapshot. Every later
`collect_process_until` consumes that session, uses the same FD, and returns the clean session with
the snapshot only on success. This linear ownership serializes transactions and makes every error
retire the socket, so late unread datagrams cannot satisfy a later transaction. Nonzero sequences
remain monotonic across successful snapshots. A deadline supplied later may shorten but cannot
extend the opening deadline, and sequence exhaustion fails rather than wrapping. The existing
`collect_until` entry point is a temporary in-tree migration wrapper that opens one session
internally and is deleted after stateful call-site migration.

Opening the session does not issue a protocol dump. The future capability-qualified attempt path
must prove that the TCP and UDP INET_DIAG handlers are built in or already active before collection
and report unsupported otherwise. A dump request is not an admissible availability probe because a
kernel may satisfy it through implicit `request_module` autoload, which production Flux prohibits.

The canary layer now closes the next ownership gap with a non-cloneable attempt transport. Its
production constructor opens the platform session under the immutable canary deadline and derives
the request authority plus a private per-opening identity from that exact handle. Attempt inputs
derive the request deadline from the transport. Checked context-output and execution envelopes
reject numeric-authority reuse, replacement sessions, or deadline drift; the coordinator keeps the pure request for post-observation while moving
the session once into the executor, and only a successfully prepared local-OUTPUT attempt receives
it by value. Request construction, availability, or later failure drops the session. A copied port
ID cannot be paired with a reopened replacement socket even if the kernel reuses the port number,
and a live regression proves the bound port is unchanged at prepared execution.

This type-safe handoff is still not a real producer. A production `prepare_attempt` context must
invoke it in the exact daemon network namespace, supply the real collector object identity/revision,
perform no-autoload capability admission, and use the session for the actual per-flow observations.
The current daemon has no production required-mode context.

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
2. remove the canary selector and attempt-only guards/counters; retire the attempt-owned listener-
   delivery report for supervised-report authority, or verify it was never created for qualified
   cgroup-BPF authority; then verify every exact reserved object absent;
3. stop and reap the peer servers;
4. retire the attempt record while retaining the unchanged boot facility for fresh
   verification after restart or publication retry.

The unqualified gate record carries daemon-observed monotonic timestamps rather than cleanup
booleans. Client and peer retirement evidence records PID/start-time identity plus ordered
quiesce, terminate, and reap observations. The validator rejects collisions among those roles and
with the supervised engine. The process-ownership receipt now requires every claimed identity and
exact retirement record to come through a distinct attempt-owned handle opening before the factory
can promote evidence, and revalidates that receipt only after ordinary cleanup validation. Its
production authority is intentionally uninhabited until the real attempt context supplies retained
children and the supervisor supplies its retained engine child.
Object-retirement evidence binds each pairwise-distinct selector, leak-guard, counter, and
listener-delivery-report identity plus retirement and subsequent absence readback. The attempt
record binds the exact Generation and nonce plus retirement and absence observations. Validation
requires the final flow and delivery to precede client quiescence, final counter readback to
precede counter retirement, client reaping to precede every object retirement, every object
absence readback to precede peer stopping, peer reaping to precede attempt-record retirement, and
final record absence to precede observation of the unchanged retained facility. Every timestamp is
no later than gate completion and strictly before the immutable request deadline. These `Instant`
values are local coordinator observations; they are not accepted as serialized timestamps supplied
by child processes. A qualified cgroup-BPF delivery authority selects the explicit verified-never-
created report-object disposition rather than inventing a retirement event; a positive producer
still needs the observer's separately proven lifecycle authority before it can construct that
claim.

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

   **Complete development-only local-OUTPUT mechanism lane:** the exact ignored ADR-0012
   checkpoint passes in the disposable Linux harness and through the rooted x86_64 Android runner
   on WSA Android 13 / SDK 33. It proves the two-hook dual-stack TCP/UDP mechanism, masked Android
   mark preservation, original destinations, bypass, negative controls, and cleanup. The production
   Android adapter, distinct role credentials, Generation/receipt/report integration, reviewed
   Android 5.10/ARM64 devices, coexistence matrix, and failure injection remain incomplete.

   **Complete non-authorizing canonical representation:** forwarded-only lowering preserves exact
   schema-v1 identity, while local-OUTPUT input selects schema v2 with private `O` and `P` chains,
   optional `F`, typed routing/listener/escape requirements, and descriptive attach/retire order.
   This closes the representation gap only. The production driver remains `Unsupported`; the
   separately delivered private owner supplies transaction mechanics only for admitted targets, and
   no stable hook, route, listener, receipt, or cleanup authority follows from the artifact itself.

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
   `RUNNING`; the current pre-release composition remains structural-only.
8. **Complete prebound transport:** the Linux/Android socket-diagnostics source can bind a uniquely
   owned session before request construction, expose its real port ID, reuse the same FD with
   monotonic nonzero sequences, retire the handle on any error, prevent deadline extension, and
   preserve the temporary-session migration API. That wrapper is removed after stateful call-site
   migration; this remains observation plumbing.
9. **Complete typed attempt handoff:** a non-cloneable canary transport derives request authority,
   a private per-opening identity, and the immutable deadline from the exact prebound session;
   checked input/execution envelopes reject copied/reopened mismatches or deadline drift, and the
   coordinator moves the handle once into prepared local-OUTPUT execution. Production still
   has no real required-mode context or positive driver.
10. **Complete temporal cleanup model:** typed process retirement, exact pairwise-distinct attempt-
   object retirement and absence (including the listener-delivery report), attempt-record
   retirement, retained-facility observation, and gate/deadline chronology now replace boolean
   cleanup claims. Counter readback and the final authoritative delivery event must precede
   retirement of their evidence objects. Qualified cgroup-BPF delivery instead requires the exact
   report object to be verified never created and absent after the final event. This is validation
   plumbing; production still has no positive evidence producer or real runtime process-receipt
   authority.
11. **Complete capture-receipt contract:** the selected TPROXY request now has a non-cloneable,
   per-flow local-OUTPUT receipt model that binds the complete request, request probe UID, nonce,
   tuple, payload, listener cookie, exact delivery event, unique sequence, loss baseline, and
   attempt/client/deadline chronology. Drivers return unverified proof; only the separate sealed
   verifier may mint receipt-bound artifacts for the evidence factory. The gate record then owns
   the receipt and revalidates it with its exact flows and client cleanup lifetime. The production
   authority is still uninhabited, so REDIRECT/DNAT, ingress traffic, counters, route lookups, a
   backend enum, or the current xtables path cannot produce a positive receipt.
12. **Complete process-ownership contract:** explicit probe/engine UID+GID and credential-map
   domains now enter the immutable request. A second non-cloneable receipt binds exact engine
   before/after and client/peer PID/start-tick/handle observations, complete restricted credentials,
   role network namespaces, exact cleanup retirements, distinct handle openings, and flow/cleanup/
   deadline chronology. The Linux/Android pidfd substrate opens only from retained children,
   validates stable process-wide thread credentials and process domains, distinguishes exit from
   parent reap, and is exercised by the no-traffic credential preflight. Production receipt
   authority remains uninhabited. The engine-child authority handoff and raw same-pidfd before/after
   pair below are delivered together with exact engine credential-policy/domain validation, but
   final verifier completion chronology and real driver child integration remain open.
13. **Incomplete local-OUTPUT integration-plumbing checkpoint:** deliver this work as separately
   reviewed subcheckpoints so no plumbing-only step is mistaken for capture qualification:
   - **13a complete — retained engine-child authority handoff:**
     `SingBoxChild::open_process_handle` opens a non-cloneable `ProcessHandle` only from the
     retained live `std::process::Child`, then rechecks the pidfd/procfs PID and start-time ticks
     against the identity recorded at spawn. The handle grants observation only; signaling,
     waiting, and reaping remain with the Sing-Box adapter. `EngineSupervisor` opens the exact
     authority only from matching ready ownership, active specification, and snapshot revision.
     The coordinator binds a single-use opener to the immutable request, and execution invokes it
     only after read-only backend availability succeeds and before prepared-attempt construction,
     then moves the authority once into the process verifier after capture verification; the driver
     never receives the pidfd authority. Tests cover recorded-identity substitution,
     live reobservation, adapter-owned TERM/reap, retained-handle exit observation after reap,
     request/revision/deadline mismatch rejection, a real Supervisor-to-pidfd lifecycle, successful
     required-mode opening, and the xtables path preserving `Unsupported` without opening an
     authority or reaching `RUNNING`.
   - **13b-1 complete — exact engine observation pair:** the process verifier consumes the exact
     engine authority, preserves its child-origin initial observation, and reobserves the same
     retained pidfd after capture verification. One non-cloneable raw pair binds both observations
     to the engine identity, snapshot revision, private opening identity, stable credentials, and
     exclusive request deadline while retaining no signal/wait/reap capability. Exit, identity,
     deadline, or pair-contract failure after preparation is cleanup-uncertain. Tests exercise the
     real Supervisor-to-pidfd lifecycle, distinct openings, successful verifier-only handoff, and
     exit between observations. This slice does not mint a process receipt.
   - **13b-2a complete — engine credential-policy and process-domain validation:** every
     `ProcessObservation` now carries authoritative user/mount/network namespace identities from
     opened descriptors plus canonical UID/GID-map digests. The bounded two-pass task census
     requires stable homogeneous credentials and namespaces across every thread and stable maps;
     map parsing rejects malformed, zero-length, overflowing, overlapping, oversized, or
     over-entry-limit input before domain-separated hashing. The process verifier validates both
     engine observations against the request's exact four-slot UID/GID policy, empty supplementary
     groups, zero inheritable/permitted/effective/ambient capabilities, `NoNewPrivs`, exact
     user/mount/map domain, and daemon network namespace. No expected domain is copied into an
     observed field, policy mismatch is cleanup-uncertain, and the production process-receipt
     authority remains uninhabited.
   - **13b-2b pending — driver-child ownership and final receipt chronology:** retain driver-owned
     client/peer `Child` values through exact termination and parent reap, bind their corresponding
     process handles and domain observations, and assign final attempt completion only after every
     verifier observation before minting the process receipt. No component may reconstruct
     authority from a PID or mint the receipt from copied identities.
   - **13c pending — listener observation:** add an independently authoritative listener observer
     for every required family/protocol role, including UDP listener state, FD/inode/cookie,
     wildcard binding, transparency, and IPv6-only state. The existing outbound connected-socket
     collector and readiness port observation do not by themselves prove this contract.
   - **13d pending — supervised report contract and parser:** define a bounded, versioned
     delivery-report schema-v1 parser interface plus test-only frames, and bind source,
     transport/framing, sequence/loss behavior, report-object lifetime, and shutdown semantics to
     the immutable `EngineCapabilityProfile`. Stock logs or management APIs are not evidence.
   - **13e pending — collector, cleanup, and evidence-factory integration:** perform actual
     observations with the exact prebound collector session, bind every cleanup identity and
     report object to its owned resource, and exercise the completed schema-v2 `validate_for` path
     with test-only fixtures.

   The combined checkpoint remains incomplete. Production must continue to report `unsupported`
   and cannot mint either receipt until one concrete device-supported local-OUTPUT capture
   mechanism preserves TPROXY listener semantics and the immutable `EngineCapabilityProfile`
   declares an authoritative report producer. A separately qualified cgroup-eBPF observer may
   replace the report only after its own authority and loss contract is proven. REDIRECT/DNAT
   delivery cannot qualify a TPROXY Generation; an adapter without a qualifying TPROXY listener
   path reports `unsupported`. None of these subcheckpoints may weaken the model to accommodate the
   ingress checkpoint or be renamed positive merely because its plumbing is complete.
14. Add an Android lab adapter that reports explicit `unsupported`, `denied`, `conflicting`,
   `broken`, or `unknown` evidence. It remains diagnostic-only until exact-device qualification.
15. Permit TPROXY `RUNNING` only for reviewed device profiles whose functional canary passes the
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

Until the production local-OUTPUT producer and reviewed release-device qualification are evidenced,
Flux must describe Phase 1 capture verification as structural and the functional exit gate as
incomplete.
The delivered collector, host ingress tests, Linux namespaces, route lookups, successful counters,
or WSA mechanism pass do not authorize production `functional_passed`.

## Open Android qualification work

The rooted WSA pass above closes only the first Android mechanism checkpoint. It is not the
production endpoint or the minimum Android 5.10/ARM64 release profile.

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
