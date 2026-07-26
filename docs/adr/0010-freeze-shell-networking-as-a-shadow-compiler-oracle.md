---
status: accepted
decision_date: 2026-07-14
last_reviewed: 2026-07-23
---

# Freeze shell networking as the oracle for a non-authorizing Rust shadow compiler

The working shell path is still Flux's only executed compatibility implementation and behavioral
baseline for capture, policy routing, address synchronization, and their cleanup ordering. Removing it before
the Rust replacements have deterministic parity, failure recovery, exact ownership/readback,
rollback, and Android evidence would discard the only executable semantic baseline. Running a
partially native path beside it would be worse: two writers could independently mutate the same
networking objects.

During pre-release development, the networking portions of `scripts/init`, `scripts/config`,
`scripts/rules`, `scripts/tproxy`, and `scripts/addrsync` are therefore frozen as a compatibility
oracle. They receive only correctness, security, cutover-contract, and rollback fixes. The
serialized shell phase path remains the sole production networking writer until a component-specific
cutover gate transfers ownership to Rust. This is a migration constraint, not an endorsement of
shell as the final architecture or a releasable bridge. ADR-0011 prohibits publishing any of these
mixed-runtime checkpoints.

Phase 2 may proceed without mutation by compiling a deterministic backend-neutral shadow Capture
Program in pure Rust. The shadow compiler normalizes typed UID/GID, application, interface,
family, and destination policy; keeps the canonical mandatory safety baseline separate from
configurable bypasses; retains optional inventory-derived host-set provenance without treating it
as final freshness authority, or explicitly defers host observation when it is absent; produces
separate ordered local-OUTPUT and forwarded-ingress
programs; enforces compile-time resource budgets; and emits stable semantic digest and explanation data.
Identical normalized inputs must produce identical shadow output. Frozen semantic fixtures derived
from the compatibility oracle are review inputs for later differential work.

A shadow artifact is deliberately non-authorizing. It has no Generation ID, Planning Authority,
writer token, ownership lease, prepared/active conversion, Runtime Coordinator entry point, or
kernel object names. It does not itself authorize or execute xtables, nftables, routes, TUN
configuration, or eBPF, and its digest is not a Generation Capture Program digest accepted by
activation or the functional canary. A separate pure lowerer may consume a supported shadow shape
without promoting the source artifact. This checkpoint claims neither byte-for-byte restore parity
nor device semantic parity.

Each compatibility component is retired only after its Rust replacement passes all applicable
gates: canonical rendering and differential fixtures, backend and real-device behavior, failure
and recovery injection, exact live readback and Managed Object ownership, rollback, and an atomic
single-writer transition. Roadmap Lane A completes one canonical target containing the
address-derived policy and every host-buildable input needed by the native transaction, while Lane
C supplies the exact physical-device routing and authority evidence. Gate 1 then transfers xtables,
policy routing, and address synchronization together because the native
Generation lease intentionally excludes every shell networking writer. Until that transfer is complete, Rust may observe
and compile but must not execute that component's networking mutations. The final package may
retain only platform-required Magisk installation, launch, disable, and uninstall glue; it retains
no legacy compatibility wrapper or shell networking policy/cleanup implementation.

This decision does not authorize eBPF attachment, persistent pins, live-chain integration, TUN
activation, implicit module autoload, `.ko`/KPM packaging or loading, or consumption of a kernel
extension as a correctness path. Those mechanisms retain their existing independent capability,
ownership, conformance, and ADR gates.

The consequence is a longer overlap in source code but a shorter period of semantic uncertainty:
the old path stays executable and frozen while the new path first becomes explainable, testable,
and deterministic, then takes ownership one component at a time without a big-bang rewrite or a
dual-writer interval. Source overlap is temporary development scaffolding: once a component passes
its cutover gate, its replaced runtime code is removed rather than maintained for compatibility.

## 2026-07-15 implementation status

The first rule-generation cutover is non-mutating and complies with this decision. Rust-owned
preparation now exclusively invokes `fluxd render-legacy-rules`, records `rust` as the cache
producer, and never sources `scripts/rules`. Explicit legacy ownership exclusively sources the
frozen generator, records `shell`, and remains the intentional rollback path. Producer selection is
fail-closed: a Rust render failure aborts candidate preparation and preserves the active Generation;
it does not silently fall back to shell generation.

The delivered `LegacyRulesPlan` validates and preserves the compatibility source shape. It is not a
lowering of `ShadowCaptureArtifact`, does not resolve canonical Capture Program ordering, and has no
writer or activation conversion. Its fixed proxy/bypass marks are supplied from the same exported
inputs consumed by the shell PBR path. When application UID resolution is needed,
`fluxd snapshot-legacy-packages --source PATH` obtains the bounded read-only snapshot through a
no-follow, regular, descriptor-stable read; shell does not copy the live package database directly.
The snapshot is retained with the prepared Generation.

Renderer-owned plan, family-pair, and enabled-family-set digests now bind the source-shape output.
Rust-owned preparation uses `fluxd attest-legacy-rules-set` to compare every staged artifact with
one rebuilt plan and retain a strict Generation-bound receipt before `engine.manifest` publication.
This is non-mutating exact-file verification only and does not advance the single-writer cutover.

Explicit legacy restart prepares and validates fresh settings, the replacement Sing-Box
configuration, and replacement caches before stopping the active runtime. A failed replacement
preparation preserves that runtime.

`scripts/tproxy` remains the sole production restore executor and kernel writer. The private native
owner now supplies stable-hook mutation, coherent restore/save, journaled policy routing, exact
readback, rollback, crash recovery, cleanup, and the transition lease in deterministic and rooted
disposable-WSA mechanism tests. Positive target admission remains test-only, leaving production
target admission uninhabited, so those mechanisms are not part of production composition and WSA
is not release authority. Runtime local-OUTPUT authority, reviewed Android 5.10/ARM64 release
evidence, nftables, TUN, production
eBPF, implicit module requests, and `.ko`/KPM paths remain outside this cutover.

The extension-free canonical lowerer is delivered separately from `LegacyRulesPlan`. Forwarded-
ingress-only input preserves the exact schema-v1 bytes and digests in generation-namespaced `F`
chains. Any input containing local OUTPUT selects schema v2: `O` chains classify eligible traffic
with masked `MARK`, `P` chains describe the mark-qualified loopback PREROUTING TPROXY companion, and
mixed programs may also carry `F` chains. Typed metadata binds stable-hook roles/selectors, the
transparent listener, engine loop escape, and per-family RPDB/local-route identity requiring
nonzero route and rule protocols, an explicit nonzero route metric, IPv4 HOST scope, and IPv6
UNIVERSE scope,
along with lifecycle order, digests, and resource budgets. The prepare/retire documents still
operate only on unattached private chains; the metadata cannot execute, attach, provision, or
authorize anything. Established-flow
caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS clamping remain rejected,
and the production xtables driver remains `Unsupported`.

Local-OUTPUT research also identified a contract boundary rather than a categorical oracle defect.
The frozen shell source shape places its generic loopback bypass after an optional connmark-
qualified fast path; that historical variant may encode a related local-output path, but it does not
define or qualify the mandatory packet-mark-qualified loopback PREROUTING companion selected by
ADR-0012. The shell remains useful evidence for source behavior and rollback during development,
but byte parity with that behavior cannot veto a qualified target-semantic change. The native
compiler must follow ADR-0012 and retire any superseded shell behavior at the component cutover.

## 2026-07-17 native-owner checkpoint

This checkpoint has one complete private Rust transaction owner rather than another shadow
artifact. `NativeXtablesOwner` exposes only `converge(target)` and `recover()` and owns stable
PREROUTING/OUTPUT roots, coherent descriptor-pinned restore/save, journaled policy-routing
netlink, exact structured readback, rollback, crash recovery, cleanup invertibility, and the
shell-visible transition lease. Its exact routing identity requires nonzero route and rule
protocols, an explicit nonzero route metric, IPv4 HOST scope, and IPv6 UNIVERSE scope. Durable
owner-payload schema 3 stores only target and optional previous identities; each binds the source
artifact, coherent tool set, complete private runtime plan, and a domain-separated digest of the
complete IPv4/IPv6 route/rule audit and exact loopback name/index. A separate bounded,
checksum-protected archive retains exact active/replacement recovery material under the runtime lock.
The real Adapter validates the live mapping name-to-index and index-to-name before every policy access, and both
xtables families plus both routing audit identities must be exact or absent before `Active` or
`CleanAbsent` can be published.

A current terminal journal keeps the native guard, shared writer fence, and optional surviving lease
until its payload resolves and fresh global IPv4/IPv6 xtables plus policy absence succeeds; only then
are terminal artifacts retired. Previous-boot recovery also accepts the exact revision-1
`Activating` boundary interrupted at `JournalDurable` or `JournalBeforeLease` when the inherited
native-owner scope matches the journal. Same-boot nonterminal or scope-mismatched missing-lease state
remains fail-closed.

Shell-owner v2 retains parent plus optional child PID/start identities and boot ID. Either live
participant blocks; one serialized parent-bound mutating `addrsync` or `tproxy` phase child
adds/clears only the child slot and remains blocking after parent death; and a live parent may
reclaim a dead child. Both-dead, PID-reused, and previous-boot records retire only after exact
revalidation. Ambient state is discarded, release is authenticated, signals exit through cleanup,
and bare, malformed, mixed, or unverifiable locks remain fail-closed. Every legacy start, stop,
restart, and failure-cleanup phase transaction claims this fence before `addrsync` or `tproxy`
mutation. The standalone daemon remains legacy ownership until the component cutover.

Deterministic failure injection covers every mutation boundary, and the same real Adapter passed
apply, active-journal recovery, stop, and exact cleanup in a rooted disposable WSA namespace. That
WSA result is mechanism evidence, not release authority.

This checkpoint does not transfer production ownership. Positive target admission remains
test-only, the daemon and canary cannot construct production execution authority, and
`scripts/tproxy` remains the sole production restore writer. ADR-0010 therefore still forbids any
dual-writer comparison. The next cutover must bind reviewed Android 5.10/ARM64 mark/RPDB,
engine/canary, no-autoload, VPN/netd, and ownership evidence; acquire the transition lease before
the first Rust write; disable shell mutation; and then delete the replaced shell rule/restore
duties. Optional eBPF remains outside correctness-critical ownership, and production adds no
`.ko`/KPM loading path.
