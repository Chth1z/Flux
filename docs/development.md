# Flux Rewrite Development

The Rust rewrite is pre-release development. The root Cargo workspace is authoritative while the
legacy `addrsyncd` submodule remains independently locked and buildable only as temporary cutover
evidence. The shell phase path and standalone `addrsyncd` remain the production bridge networking
writers until one fenced cutover transfers all networking mutation ownership to Rust, then the
replaced runtime code is removed promptly. Rust-owned preparation
now compiles the legacy restore caches, while the frozen shell generator remains an explicit
legacy-owner rollback oracle rather than a silent fallback. No bridge, shadow, parity, staged
module, or package-verifier result is a release candidate.

Subscription retrieval and asset management are now production-connected Rust behavior. The
development bridge still packages `scripts/updater.sh` for frozen comparison until Gate 1, but no
initialization or runtime path references or invokes it. The exact Rust-only stage excludes it.

## Toolchain contract

- Rust `1.93.0` with `rustfmt` and Clippy.
- Primary target: `aarch64-linux-android`.
- Development checkpoint target: `x86_64-linux-android` (test-only; never packaged).
- Android API level: 31.
- Release-link NDK: revision `27.3.13750724` (NDK r27d).
- Dependency policy tool: cargo-deny `0.20.2`.

The root [`rust-toolchain.toml`](../rust-toolchain.toml) installs the Rust components and Android
standard library. The subscription TLS graph includes `ring`, whose Android build script compiles C
and assembly even during `cargo check`. Android checks and release builds therefore both require the
pinned NDK; `xtask` validates its revision and binds the API-31 compiler as Cargo's linker and the
target-specific `cc` compiler. Because NDK r27d still defaults to 4 KiB ELF load alignment,
`xtask` also passes both `-z max-page-size=16384` and
`-z common-page-size=16384` through target-specific Rust flags for every final ARM64 and x86_64
Android link.

## Common commands

```text
cargo xtask fmt
cargo xtask check-host
cargo xtask test-host
cargo xtask clippy
cargo xtask check-android
cargo xtask ci
```

Set `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` to NDK `27.3.13750724` before running
`check-android`, `build-android`, or `ci`. `cargo xtask ci` runs formatting, host checks/tests,
Clippy with warnings denied, and the pinned-NDK Android cross-check for the new workspace.

## Rust dependency assurance

The standard Linux workflow separately requires the root workspace advisory, license, and source
policy because it refreshes network-owned RustSec data and is not part of portable `cargo xtask ci`:

```text
cargo deny --manifest-path Cargo.toml --config deny.toml --all-features --locked \
  check advisories licenses sources
```

Use cargo-deny `0.20.2`. CI downloads the official x86_64 Linux musl archive and requires SHA-256
`9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f` before execution. The
policy denies vulnerable/unsound advisories, yanked packages, unknown registries, Git dependencies,
and license expressions outside the explicit compatible set. A new advisory may therefore fail CI
without a repository change; review the advisory rather than weakening the required gate.

This command covers the root workspace lockfile, including development and target-specific
dependencies. It does not cover the excluded `addrsyncd` development bridge, whose manifest remains
`UNLICENSED`; the Rust-only package forbids that binary, and a passing workspace audit is not
release-license approval for the bridge or a replacement for the final package SBOM.

## Unsafe-boundary assurance

The [explicit unsafe-boundary audit](security/unsafe-boundary-audit-2026-07.md) semantically reviews
all 264 unsafe blocks in the 38 root-workspace source and test files that contain them. The census
also records one unsafe Android callback, three unsafe foreign blocks, and no unsafe trait or impl.
The review corrected one fail-closed signal contract: internal process and process-group helpers now
reject zero before it can become the process-group-wide `kill(0, signal)` target.

The workspace lints remain required mechanical controls:

```text
cargo clippy --workspace --all-targets --all-features -- -D warnings \
  -D clippy::undocumented_unsafe_blocks
```

Repeat the semantic review whenever an unsafe construct or foreign declaration changes, or when
Rust, `libc`, the pinned NDK/API, a supported syscall ABI, callback lifetime, descriptor owner,
kernel-returned length, child identity, or signal target changes. A passing lint and source review
do not qualify physical ARM64, authorize `NativeRuntimeWriter`, replace parser fuzzing/sanitizers,
or satisfy final package provenance.

## Deterministic parser fuzz smoke

The host CI job requires a bounded, reproducible malformed-input smoke for the root netlink and
socket-diagnostics decoders:

```text
cargo xtask test-parser-fuzz-smoke
```

The command runs seven exact `flux-platform` library tests. Four generate 4,096 fixed-seed arbitrary
datagrams for address/link/route/rule decoders; route and rule additionally test every prefix and
single-byte mutation of a valid structured fixture; the socket-diagnostics test runs the same
4,096 cases across IPv4/IPv6 TCP/UDP dump specifications. Each case is bounded and wrapped in
`catch_unwind`, so a panic or unexpected process abort fails the job. This is deterministic parser
smoke evidence only: it is not a libFuzzer/AFL corpus, a branch-coverage result, a sanitizer run,
or Android/ARM64 qualification. Keep any future crash reproducer as a checked-in test before
expanding the generator or adding a native fuzzing toolchain.

The focused Phase 3 Android mark-authority model can be exercised with:

```text
cargo test -p flux-core android_mark_authority::tests::
cargo test -p flux-core android_mark_policy_catalog::tests::
cargo test -p flux-core --test android_net_id_fwmark_census
cargo test -p flux-core --test rpdb_fwmark_census
cargo xtask preflight-android-arm64-mark-ordering --serial SERIAL --adb PROGRAM
```

These are pure evidence/planning checkpoints. The source-pinned Android `netId` and inventory-bound
RPDB tests model only six source-plane cells; they do not create a complete Mark Census or Planning
Authority. The exact pinned incoming-packet writer masks intersect the complete device-qualified
candidate envelope, but the packet writer runs under mangle INPUT after input route selection. Its
exact overlap is therefore reported as an ordered-write qualification requirement, not a mark
grant, and still fails closed. Definite overlaps retain precedence. Passing host tests do not
replace runtime profile/chain binding or listener/observer mark-preservation evidence on a physical
Android ARM64 target. The remaining 21 source-plane cells are intentionally paused until that
qualification target is viable.

The ARM64 preflight requires one explicit serial and accepts an explicit ADB program, including a
Windows `adb.exe` path from WSL. It performs no push, temporary-directory creation, restore, rule
mutation, module request, or live Flux-chain write. After root and stable boot/fingerprint checks,
it reads the production identity collector's property/artifact prerequisites, validates properties
through the same bounded parser (including at least one consistent device-lock fact), checks
PID-1/self network namespaces and SELinux mode, and reads only mangle tables already listed in
`/proc/net/*_tables_names`. The bounded report requires exact dual-family
`routectrl_mangle_INPUT` declarations, exactly one total
`-j`/`-g` reference to each child and requires that reference to be the unconditional built-in INPUT
jump, unique cross-family-consistent interface-scoped MARK writers, one supported
mask, zero candidate-envelope bits in writer values, and no unknown child rule. Raw table bytes are
not printed. A `viable_for_full_qualification` result is still diagnostic-only: runtime artifact
digest/source-profile authentication, exact Capture Path ordering, listener/observer mark
preservation, and VPN/netd coexistence remain separate physical-device gates.

The compatibility submodule remains separate:

```text
cargo test --manifest-path addrsyncd/Cargo.toml
cargo clippy --manifest-path addrsyncd/Cargo.toml --all-targets -- -D warnings
cargo check --manifest-path addrsyncd/Cargo.toml --target aarch64-linux-android --all-targets
```

Its bridge reconciliation reads canonical kernel rule dumps and preserves duplicate observations instead of relying only on in-memory ownership tracking. `run --daemon` is now a bounded convergence handshake: readiness follows startup cleanup, reconcile/apply, two clean readbacks, and a final drain of the subscribed route socket to `EAGAIN`. Loss or ambiguous framing forces reconciliation, and parent-side readiness failures terminate and reap the child.

The bridge shell regression suites are:

```text
sh tests/shell/config_installer_contract.sh
sh tests/shell/rules_generation.sh
sh tests/shell/run-installer-tests.sh
sh tests/shell/run-dispatcher-tests.sh
```

The first two suites are host-only and cover installer migration/configuration admissibility and legacy rule-generation semantics. The remaining two wrappers run in isolated Bubblewrap roots: installer rollback/uninstall delegation and the complete Rust-owned dispatcher lifecycle. Local hosts without Bubblewrap report an isolated-suite skip. CI makes unavailable or prohibited Bubblewrap environments failures.

### Completed Phase 2 shadow Capture Program workflow

The frozen Capture Policy checkpoint is pure `flux-core` work. Run its focused integration test with:

```text
cargo test -p flux-core --test capture_program
```

The test corpus pins the ordered local-OUTPUT and forwarded-ingress semantics, canonical mandatory
safety baseline, separately configurable bypasses, resolved application modes and multi-user UIDs,
exact/prefix interfaces, family/domain isolation, optional inventory-host provenance,
compatibility engine UID/GID bypass, protocol eligibility, deterministic digest/resource
accounting, and explicit deferred prerequisites. The
oracle-derived fixture is rooted in `tests/shell/rules_generation.sh`; run that shell suite
separately because the Rust test must not execute scripts or inspect live state.

Treat a difference as a review item, not permission to update both sides mechanically. A shell
change is admitted only for a concrete correctness, security, cutover-contract, or rollback fix,
and the frozen fixture records why it changed. A shadow change may improve typed normalization or
explanation, but passing the fixture is semantic characterization only: the checkpoint has no
conversion into the independent legacy source-shape renderer, byte/device parity claim,
Generation ID, Planning Authority, writer token,
ownership lease, prepared/active conversion, Runtime Coordinator path, or functional-canary
authority.

Do not use the shadow work to attach or pin eBPF, touch live Flux chains, enable TUN, request kernel
modules implicitly, load `.ko`/KPM payloads, or perform native networking mutation. The production
bridge continues to execute all capture, policy-routing, and address-synchronization writes.
The delivered `LegacyRulesPlan` is a separate source-shape compatibility compiler; it does not
promote the shadow artifact or implement the canonical lowering described below.

### Canonical xtables lowering workflow

Run the focused pure-lowering and sealed restore-namespace suites with:

```text
cargo test -p flux-platform --test xtables_capture_lowering
cargo test -p flux-platform --test xtables_restore
```

The lowering suite consumes extension-free `ShadowCaptureArtifact` values. Forwarded-ingress-only input
retains schema v1 and pins its exact restore bytes and lowering, family-pair, and artifact-set
digests. It proves deterministic IPv4/IPv6 family artifacts, canonical mandatory/host/loopback/
configured direct-rule order, positive expansion of the terminal whole-set interface selector,
TCP-only/UDP-only/TCP+UDP TPROXY eligibility, exact interface token and IFNAMSIZ rejection, checked
command and immutable restore-byte budgets, and family-sealed `FLX{4|6}F{generation}` identity.
Direct decisions emit uncached `RETURN`; selected forwarded traffic receives protocol-qualified
TPROXY rules.

Any artifact containing local OUTPUT selects schema v2. The suite proves ordered engine-credential,
destination, output-interface, and application direct decisions; positive UID proxy membership for
allowlists; protocol-qualified masked `MARK --set-xmark` in private
`FLX{4|6}O{generation}` classifier chains; and exact-port TCP/UDP TPROXY in private
`FLX{4|6}P{generation}` loopback companions. Mixed programs retain distinct `O`, `P`, and `F` roles.
Proxying local programs require an exact caller-selected, descriptive routing target for every
enabled family; supplying it creates no allocation or mutation authority. Zero priority, reserved
tables, unspecified route protocol, and explicitly unspecified rule protocol fail before rendering.
All-direct local programs require no companion, listener, or routing target and reject an unexpected
one. Combined classifier/companion command and byte expansion is budgeted before artifact
construction.

Schema-v2 entry-point metadata describes the stable-hook contract without mutating it: the
OUTPUT classifier selects the unassigned `0/mask` role, the loopback PREROUTING companion selects
`lo` plus `proxy/mask`, and forwarded ingress retains its separate PREROUTING role. Typed local
requirements bind the wildcard-family transparent listener and exact port/protocols, the
compatibility engine UID/GID predicate plus independently required bypass socket mark, and the RPDB
priority/table, explicit nonzero route metric, nonzero route and rule protocols, proxy mark/mask, and
exact family `/0` `RTN_LOCAL` route through loopback with IPv4 `HOST` scope or IPv6 `UNIVERSE` scope.
Descriptive lifecycle metadata prepares all private chains, listener, routing, and escape before
attaching `P`, then `F`, then `O`; retirement detaches `O`, then `F`, then `P` before removing the
supporting objects and private chains.

The resulting prepare/retire documents still declare, fill, flush, and delete only unattached
generation-namespaced implementation chains. The tests verify that neither artifact modifies a
built-in hook and that the restore grammar accepts only family-matching, nonzero-generation `F`,
`O`, and `P` names. Established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection,
and MSS clamping remain explicit unsupported-extension errors in both lowering schemas.

Passing this lowering suite proves pure canonical representation only. The private native owner
described below can consume an independently admitted artifact and supply restore, stable-hook,
policy-routing, readback, rollback, recovery, and transition-lease mechanics; the lowerer itself
still grants none of those authorities and does not allocate an Android mark, enter the coordinator,
or qualify Android packet delivery. The production xtables driver remains `Unsupported`. Do not feed
these artifacts to `scripts/tproxy`; the development bridge continues to use the independent
`LegacyRulesPlan` artifacts below.

### Native xtables transaction owner

Run the complete owner, save/readback, durable-lease, process, and policy-routing suites with:

```text
cargo test -p flux-platform xtables::
cargo test -p flux-platform netlink::policy_routing
FLUX_DISPATCHER_TESTS_REQUIRED=1 sh tests/shell/run-dispatcher-tests.sh
```

The coherent tool-set tests open, hash, trust-check, and map every command/restore/save descriptor
before the first version execution; verify role-specific multicall `argv[0]`; and exercise bounded
restore/save behavior, identity revalidation, timeout, parent-death, process-group cleanup, and
`MayHaveMutated` classification. The owner tests use a deterministic kernel Adapter to cover
zero-to-active, idempotence, replacement, stop, every route/rule/restore write boundary,
dual-stack partial success, rollback failure, crash recovery, Generation rebind, and lease
retention. Policy-routing tests include a live unprivileged groups-zero dump and Linux-5.10 IPv6
readback shape. They also prove that an opposite-family xtables or routing residue blocks both
activation and clean-absence publication, and that stale loopback name/index binding fails before
policy mutation or deletion. Durable tests cover current terminal recovery with and without a
surviving lease, the exact previous-boot revision-1 `JournalDurable`/`JournalBeforeLease` boundary,
and rejected same-boot or scope-mismatched missing-lease states. The shell suite covers owner-v2
parent-only and parent/child records, either participant live, dead-child reclamation, orphaned live
child release, both dead, PID reuse, previous boot, spoof rejection, native-marker precedence, and
bare/malformed/mixed/unverifiable fail-closed cases. It also covers ambient ownership-state
sanitization, forged parent/child release, signal-exit cleanup, direct `addrsync` lease refusal, and
a surviving mutating `addrsync` phase child that remains blocking after dispatcher death.

The owner durably publishes activating intent and acquires the component transition lease before its
first restore or rtnetlink write. The lease scope is bound to boot, network namespace, component, and
ownership-journal identity and deliberately survives an atomic Generation rebind; the journal
binding carries the current Generation. Owner-payload schema 3 stores only target and optional
previous identities. Each identity binds the source artifact, coherent tool set, complete private
runtime plan, and the IPv4/IPv6 policy-routing audit; the routing digest includes every exact
route/rule field and the loopback name/index identity. The bounded checksum-protected
`native_xtables.targets` archive stores exact restore/topology/routing material for at most the
active and replacement targets. `.native_xtables.runtime.lock` spans archive refresh and staging,
owner journal/kernel convergence, and archive settling, so another process cannot prune material
while a durable journal references it.
Stable `FLX{4|6}SP` PREROUTING roots precede `FLX{4|6}SO` OUTPUT activation; stop and recovery detach
OUTPUT before deleting the rule, route, remaining roots, and private chains. The journal and lease
remain retained whenever exact active or clean-absent state cannot be proved. Every routing access
first validates live loopback name-to-index and index-to-name resolution, and every `Active` or
`CleanAbsent` result audits both xtables families plus both routing identities.

A terminal current journal is not accepted as clean absence merely because its phase is terminal.
Recovery retains the native guard, shared writer fence, and an optional still-present lease; resolves
the terminal payload; proves fresh global IPv4/IPv6 xtables and policy-routing absence; and only then
removes any lease, terminal journal, and writer marker. An audit failure leaves the fence intact.

Previous-boot records are not deleted merely because their boot ID is old. Complete coherent pairs
and terminal boundaries use the same fenced absence-first retirement. The one admitted incomplete
shape is an inherited native-owner scope matching a revision-1 `Activating` journal interrupted at
`JournalDurable` or `JournalBeforeLease`, before lease publication. Same-boot nonterminal missing
lease, any other previous-boot missing-lease revision/phase, and scope mismatch remain fail-closed.

Shell-owner v2 stores schema magic, parent PID/start ticks, optional child PID/start ticks, and boot
ID. Either live participant blocks competitors. One parent-bound mutating `addrsync` or `tproxy`
phase command at a time revalidates the parent and record, then adds/clears only the child slot; a
surviving phase child remains blocking after parent death, and a live parent can reclaim a dead
child. Release authenticates the current participant and unchanged record. Only both-dead,
PID-reused, or previous-boot records retire after exact record/directory revalidation. Bare,
malformed, mixed-owner, and unverifiable state remains blocking. The slot covers the controller
command lifetime, not the standalone daemon. Roadmap Lane A must supply its Rust-owned replacement
behavior and inputs, and Gate 1 must remove the daemon during the fenced writer cutover.

The ignored real-Adapter test is:

```text
xtables::owner::runtime::tests::privileged_real_owner_apply_recover_and_stop_is_exactly_invertible
```

Run it only as UID 0 inside a disposable network namespace whose loopback is up, with
`FLUX_NATIVE_OWNER_TEST_REQUIRED=1` and `FLUX_NATIVE_XTABLES_TOOL_ROOT` naming the trusted applet
directory. The test applies the dual-stack owner, reconstructs a fresh owner from the active
journal, stops, proves exact xtables and RPDB/route absence, checks that required xtables
registrations were already active, and verifies they did not change. It passed on the documented
rooted WSA Android 13 x86_64 profile. WSA remains mechanism evidence only.

The owner and real Adapter are crate-private. Production target admission is still uninhabited, so
the Runtime Reconciler and functional-canary driver remain `Unsupported` for native execution and
`scripts/tproxy` remains the production bridge xtables/Flux PBR writer until the Android 5.10/ARM64
cutover gate. WSA is mechanism evidence only, eBPF remains optional, and production loads no
`.ko`/KPM payload.

### Rust legacy-rule renderer and frozen oracle workflow

Run the parser, source-shape renderer, strict bridge-input adapter, and checked-in oracle suites:

```text
cargo test -p flux-platform --test xtables_restore
cargo test -p flux-platform --test xtables_restore_oracle
cargo test -p flux-platform --test xtables_legacy_render
cargo test -p flux-platform --test xtables_legacy_identity
cargo test -p fluxd --test legacy_rules_cli
sh tests/shell/run-dispatcher-tests.sh
```

The parser suite uses current-shaped synthetic documents to pin strict LF/single-space printable-ASCII
framing, repeated tables, declaration and command order, duplicates, IPv4/IPv6 context,
apply/cleanup opcode separation, per-transaction
delete-before-flush-before-delete-chain cleanup phases, exact
bounds, canonical round-trip bytes, and digest identity. It performs no filesystem reads, shell or
restore invocation, kernel access, or mutation. The oracle parser suite parses the four checked-in
IPv4/IPv6 apply/cleanup oracle fixtures and proves exact canonical byte round-trip plus the expected
syntax-artifact accounting and digest.

`xtables_legacy_render` independently emits those four fixtures from a validated
`LegacyRulesPlan` and covers the admitted application modes, ordered UIDs and duplicate interfaces,
feature gates, mark/mask inputs, FakeIP/MSS branches, family admission, and cleanup symmetry. This
is deliberate legacy source-shape parity, including compatibility ordering that the canonical
shadow policy normalizes away. It is not a lowering of `ShadowCaptureArtifact`.

`xtables_legacy_identity` binds the byte-significant plan fields, mandatory apply/cleanup pair for
each family, enabled-family set, context-qualified artifact digests, and aggregate resource totals.
Only renderer calls can construct those identities; arbitrary parsed artifacts cannot be relabeled.
Passing this suite proves deterministic renderer-owned identity, not signature validity, live
freshness, restore acceptance, readback, rollback, or device parity.

`legacy_rules_cli` covers the strict preparation adapter used by
`fluxd render-legacy-rules --packages-list PATH --family 4|6 --action apply|cleanup`. The adapter
reads only its allowlisted exported cache environment and bounded package snapshot, resolves the
ordered Android multi-user UIDs, rejects unsupported TUN, non-`iptables_restore`, non-zone,
missing-`xt_owner`, and missing-TPROXY profiles, and writes canonical restore bytes to stdout. It
does not invoke restore tools or mutate networking state.

The same suite covers `fluxd snapshot-legacy-packages --source PATH`. This helper opens the source
without following symlinks, requires a bounded regular file, verifies the opened descriptor remains
stable across the read, and streams the snapshot to stdout for `atomic_write`; shell never directly
copies a live `packages.list` into the preparation cache.

It also covers `fluxd attest-legacy-rules-set`. The command rebuilds one plan from the allowlisted
environment and package snapshot, safely reads the staged restore files, rejects family/Generation/
byte mismatches and unsafe files, and emits a strict canonical receipt. The parser rejects
noncanonical framing and internally inconsistent aggregate resource totals. The binary-dispatch
test proves this command runs before daemon socket routing and emits no stdout on rejection.

Rust-owned preparation has a mutually exclusive cache-producer contract:

1. `fluxd` atomically publishes the validated 41-field `run/desired-state.env`; `scripts/config`
   validates that exact allowlist, copies it into `cache_config`, and appends only observed
   `KFEAT_*` values.
2. When application selection needs package resolution, it invokes
   `fluxd snapshot-legacy-packages --source "${PACKAGES_LIST}"` through `atomic_write` to publish one
   descriptor-validated, at-most-4-MiB read-only `cache_packages`; otherwise it publishes an empty
   snapshot without reading Android package state.
3. The same immutable snapshot and exported `IPV4_MARK`/`IPV6_MARK`/`BYPASS_MARK` shell PBR inputs
   feed every parallel family/action Rust render.
4. After every render succeeds, the allocated Generation ID and staged files are passed to
   `fluxd attest-legacy-rules-set`; only a bounded receipt with the exact header, Generation, and
   enabled-family shape may become `cache_rules_manifest`.
5. Successful Rust preparation records `rust` in `cache_valid` and copies `cache_packages`, the
   restore caches, and the receipt into the immutable Generation as `legacy-rules.manifest` before
   `engine.manifest` publication. Stale receipts are deleted and rebuilt/re-attested rather than
   reused. Direct `fluxd rules-preview` no longer enters the dispatcher or rebuilds shared caches;
   it compiles the current Desired State and canonical engine JSON in memory and returns an explicit
   non-authorizing explanation.
6. Explicit legacy ownership alone sources `scripts/rules`, removes the package snapshot, records
   `shell`, and remains the rollback producer. Rust render failure aborts candidate preparation and
   preserves the active Generation; it never falls back silently to shell generation.

In both modes, `scripts/tproxy` remains the sole xtables restore executor and writer. These host
tests do not establish kernel acceptance, exact live readback, Android/Magisk packet-path parity, or
production native writer ownership. The bounded raw cache-artifact regeneration workflow remains
separate and explicit:

The dispatcher suite also proves that explicit legacy restart prepares and validates fresh
settings, the replacement Sing-Box configuration, and replacement caches before stopping the
active runtime. A failed replacement render restores the prior cache authority, leaves that runtime
running, and still permits an explicit stop.

```text
cargo xtask xtables-oracle --check
# After reviewing an intentional oracle-input change:
cargo xtask xtables-oracle --update
```

`tests/oracle/xtables/manifest.json` is the sole canonical inventory for the platform image,
environment identity, inputs, fixture hashes, sizes, and line counts. Do not copy those values into
another document. Both modes require a Linux Docker host with the manifest's platform image already
present because the runner uses `--pull=never`. Generation runs unprivileged, with capabilities
dropped, a read-only image root, `no-new-privileges`, and no container network; it never mounts the
host workspace or invokes `iptables-restore`/`ip6tables-restore`. The dedicated CI job performs the
explicit image pull before `--check`.

The `maximal-zone-v1` profile emits exactly four raw files:
`maximal-zone-v1-ipv4-apply.restore`, `maximal-zone-v1-ipv4-cleanup.restore`,
`maximal-zone-v1-ipv6-apply.restore`, and `maximal-zone-v1-ipv6-cleanup.restore`. It is driven only
by the checked-in `scripts/rules`, semantic shell test, generator, environment cache, and
package-list cache recorded in the manifest. `--check` rejects contract or fixture drift; `--update`
is the deliberate review path for an intentional oracle-input change. Neither mode is part of
normal `cargo xtask ci`.

These files characterize only that bounded cache-input profile. They do not run configuration or
kernel capability detection and do not cover QUIC, policy-based routing, or forced cleanup; the
cleanup pair records the shell generator's ordinary `-D` form. They prove neither kernel
acceptance nor Android/Magisk-device parity. Raw fixtures alone create no renderer, Generation,
writer/ownership authority, prepared/active conversion, coordinator path, or activation claim;
their role in the separate Rust differential suite does not widen that authority.

The privileged Linux functional-canary topology harness remains outside the portable
`cargo xtask ci` command. The standard Linux workflow runs it separately in required mode so an
unavailable namespace prerequisite fails CI; local execution supports both modes:

```text
cargo xtask test-functional-canary-linux
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux
```

The command selects only the ignored test
`functional_canary::linux_namespace_harness::privileged_dual_stack_canary_exercises_real_topology_and_cleanup`
with exact matching, `--nocapture`, and one test thread. With
`FLUX_LINUX_CANARY_REQUIRED` unset or `0`, an unsupported host, an unavailable checkpoint, or an
outer preflight prerequisite denial before mutation is an explicit skip. Setting it to `1` makes
every such condition a failure; other values are rejected. Failures after isolated mutation begins
remain failures in either mode. The task never invokes `sudo`, and the ignored
Rust test owns the authoritative isolation, capability, and cleanup preflight. The task removes
all harness-internal mode, configuration, token, and outer-namespace variables from its Cargo
children so inherited caller state cannot bypass the outer preflight or select an internal
re-entry mode.

The delivered checkpoint exercises real dual-stack TCP, UDP, and DNS traffic in an isolated Linux
topology and independently checks exact cleanup. It does not install capture and therefore is not
functional or Android qualification.

The delivered ingress checkpoint uses a third probe namespace to exercise real PREROUTING TPROXY
through a test-local transparent Rust relay:

```text
cargo xtask test-functional-canary-linux-tproxy
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-tproxy
```

The command selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_ingress_tproxy_checkpoint_exercises_real_capture_counters_and_cleanup`,
again with exact matching, `--nocapture`, and one test thread. Its current dual-stack TCP/UDP echo
and DNS-over-UDP/TCP slice proves ingress PREROUTING TPROXY, accepted-socket and strict ancillary-
data original-destination recovery, marked relay egress, source-preserving UDP replies, nonce-bound
DNS transaction/question/answer evidence, per-family route controls, independent bounded flow
counters, and cleanup. The deterministic
regression `ingress_rule_plan_never_places_tproxy_in_output` preserves the hook boundary.

The selected conventional local-OUTPUT mechanism has a separate opt-in checkpoint:

```text
cargo xtask test-functional-canary-linux-output-tproxy
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-output-tproxy
```

The command selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_local_output_tproxy_checkpoint_exercises_loopback_reinjection_and_cleanup`.
Following ADR-0012, it prepares transparent TCP/UDP listeners, reviewed disposable RPDB local
routes, private chains, and mark-qualified loopback PREROUTING TPROXY before attaching the local
OUTPUT classifiers last. Cleanup detaches and proves absence of OUTPUT first, retains the listener
through that boundary, and then replays exact inverses. The test requires positive IPv4/IPv6 TCP
accept and UDP original-destination delivery, boundary and response-bypass counters, safe misses,
zero egress leakage, stable module/registration inventories, and exact xtables/RPDB/route/link
baseline restoration.

This invocation is mechanism-only host evidence in one test process and network namespace. It does
not combine the separate distinct-UID preflight, use a Generation or production receipt authority,
consume a supervised Proxy Engine report, or qualify a production Android profile. Optional mode
may skip only a denied or unavailable outer/preflight prerequisite before the isolated transaction begins; any later
mutation, traffic, evidence, or cleanup failure remains a test failure.

The same exact ignored test has a non-shipping x86_64 Android lane for rooted WSA or another
explicit compatible development serial:

```text
ANDROID_NDK_HOME=/path/to/android-ndk-r27d \
  cargo xtask test-functional-canary-android-x86_64-output-tproxy \
  --serial SERIAL
```

The command requires Linux/WSL, the pinned NDK 27.3.13750724, API 31 linker, installed
`x86_64-linux-android` Rust target, one explicit ADB serial advertising x86_64, SDK 31 or later, and
`su` UID 0. It parses Cargo JSON to select exactly one library-test ELF, creates a unique private
directory below `/data/local/tmp`, fixes ownership/mode after `adb push`, sanitizes Android `PATH`,
sets a private `TMPDIR`, clears every harness re-entry variable, forces
`FLUX_LINUX_CANARY_REQUIRED=1`, and requires the exact normalized libtest listing before execution.
Every Cargo, ADB, and WSL path command has a host deadline with bounded output plus kill/reap on
timeout or setup failure. The runner records kernel architecture/release, build fingerprint, and
boot ID, requires the exact same profile after the cross-build and around cleanup, and removes plus
independently proves absence of the remote directory. It remains outside `cargo xtask ci`, module
staging, package verification, release manifests, and AArch64 artifacts.
`xtask` applies the same two 16 KiB compatibility linker options to this non-shipping artifact,
but a WSA runtime that reports `getconf PAGE_SIZE=4096` remains functional evidence only and
cannot satisfy the separate 16 KiB Android runtime gate.
`--adb PROGRAM` is optional; the runner uses `$ADB` when set and otherwise `adb`. A Linux `adb`
client may address WSA directly after connecting the explicit serial. To use a Windows
platform-tools client from WSL:

```text
ANDROID_NDK_HOME=/path/to/android-ndk-r27d \
  cargo xtask test-functional-canary-android-x86_64-output-tproxy \
  --serial SERIAL --adb /mnt/c/path/to/platform-tools/adb.exe
```

For an `.exe` client, the runner converts the local WSL artifact path with `wslpath -w` before
`adb push`.

The 2026-07-15 WSA run passed on Android 13 / SDK 33, Magisk 30.6, SELinux enforcing, legacy
iptables 1.8.7, and kernel `5.15.104-windows-subsystem-for-android-20230927+`. The Android harness
uses real-root live-parent plus changed mount/network namespace proof, preserves Android-owned
socket-mark bits through a test-only `0x00600000` role field, accepts the legacy `ip` text fallback
and missing rule-protocol syntax, proves built-in facilities without autoload, admits only addition
of `mangle` to an otherwise preserved registration baseline when built-in per-namespace table
initialization occurs (the observed WSA baseline was empty), handles synchronous `EPERM` for
intentional UDP drops, and normalizes only the inactive fresh-loopback qdisc before namespace
retirement. This is Android mechanism evidence, not Android 5.10/ARM64, distinct-UID, Generation,
supervised-engine, VPN/netd-coexistence, crash-recovery, or release qualification.

This split records a traffic-domain boundary, not a kernel-wide impossibility result. The ingress
checkpoint selects a veth interface and does not exercise a locally generated packet rerouted
through loopback. Linux 5.10 source permits that loop to re-enter PREROUTING, while xtables TPROXY
still cannot attach directly to OUTPUT. OUTPUT mark counters and route lookups therefore remain
supporting or negative-control evidence, not capture success by themselves.
The strict Linux/Android `/proc` FD plus INET_DIAG collector is delivered and rejects evidence
unless protocol, exact tuple, UID, mark, FD/inode/cookie, complete dumps, supervised-process
identity, and timing all agree. Its prebound session API exposes the real nonzero netlink port ID
before collection and reuses the same owned socket with monotonic sequences. Collection consumes
the session and returns it only on success; every error retires the handle, sequence exhaustion
cannot wrap, and later calls cannot extend the opening deadline. The original `collect_until` API
still opens a temporary session internally. The canary layer now adds a non-cloneable handoff that
opens this observer under the immutable attempt deadline, derives the request authority plus a
private per-opening identity from the live handle, makes attempt inputs derive the same deadline,
rejects copied/reopened authority or deadline drift at the context and executor boundaries, and
moves the session once into prepared local-OUTPUT execution. Cleanup evidence now records ordered
client/peer retirement, pairwise-distinct selector/guard/counter retirement, authority-sensitive
report-object retirement or verified-never-created disposition, exact absence readback, final
counter/report lifetime, exact attempt-record retirement, retained-facility observation, and
gate/deadline bounds. Cleanup process identities remain unqualified until the real attempt context
binds them to owned process handles. Functional-canary schema v2 now rejects
missing, REDIRECT, DNAT, weak, mismatched, lossy, stale, or transport-incomplete listener delivery
evidence. Fixtures bind the exact Generation/engine/namespace/Capture Program/selector and
listener FD/inode/cookie/socket
state; TCP accept or UDP `recvmsg` delivery; one attempt authority and loss baseline; stable
and globally noncolliding per-family/protocol listener identities; accepted children distinct from
every listener; and exact inbound wire length/SHA-256 including DNS/TCP framing. Positive
constructors remain private and test-only. A production-compiled TPROXY-only local-OUTPUT
executor/driver/verifier/factory seam is now delivered. It rejects REDIRECT/DNAT requests before
driver preparation, maps typed pre-mutation availability to cleanup `NotRequired`, requires
authoritative cleanup after preparation, and prevents unverified driver proof from reaching the
evidence factory. The completed non-cloneable capture-receipt contract stores the exact request and
one fixed-slot event per required flow, binding the request probe UID, nonce, tuple, payload,
listener cookie, exact delivery event, unique sequence, loss baseline, and monotonic attempt/client/
deadline chronology. Only the sealed receipt verifier may mint receipt-bound artifacts. Its
resulting gate evidence owns the receipt and revalidates it with the retained flows and cleanup
client lifetime. A second sealed process-ownership verifier and non-cloneable receipt now bind the
request's explicit probe/engine UID+GID and credential-map domain, exact engine before/after and
client/peer PID/start-tick/handle observations, restricted credentials, role namespaces, exact
cleanup retirements, and chronology before the evidence factory can run. The Linux/Android
`ProcessHandle` substrate opens only from retained children, verifies stable process-wide
credentials plus user/mount/network namespace and UID/GID-map domains through pidfd/procfs
correlation, and distinguishes exit from confirmed parent reap; the no-traffic credential
preflight exercises that ordering. The first integration subcheckpoint
is now delivered: `SingBoxChild::open_process_handle` opens exclusively from the retained live
`std::process::Child`, rechecks the recorded PID/start ticks against the resulting pidfd/procfs
identity, and does not transfer signaling, waiting, or reaping authority. `EngineSupervisor`
requires matching ready, active-spec, readiness, snapshot, owned-identity, and retained-child state;
the serialized coordinator binds a single-use opener to the immutable request identity, snapshot
revision, and deadline; and execution invokes it only after read-only backend availability succeeds
and before the prepared-attempt boundary. It then moves the authority once into the process
verifier after capture verification. The driver never receives the pidfd authority. The authority
records a private nonzero opening identity and a daemon-owned post-open observation time. Tests
cover identity/revision/deadline substitution, live reobservation,
adapter-owned TERM/reap, retained-handle exit observation after reap, request/authority mismatch,
a real Supervisor-to-pidfd lifecycle, successful required-mode opening, and the required xtables
path preserving `Unsupported` without opening an authority or reaching `RUNNING`.

The exact engine-observation-pair subcheckpoint is also delivered.
`ProcessHandle::initial_observation` returns the exact identity, credentials, and process domain
captured during child-origin pidfd opening. The process verifier consumes `EngineChildAuthority`,
preserves that initial observation at the daemon-owned opening time, reobserves the same retained
pidfd after capture verification, timestamps completion
only after the full scan, and receives a non-cloneable raw pair bound to the exact request engine,
snapshot revision, private opening identity, stable complete process observation, and exclusive
deadline. The pair keeps the handle private and exposes no signal, wait, or reap operation. Exit
or deadline failure at this post-preparation stage is cleanup-uncertain and cannot call the evidence
factory. A real child regression proves the pair reaches only the process verifier while the parent
still owns termination and reap; a second regression proves exit between observations fails closed.

The engine credential-policy/domain subcheckpoint is now delivered as well. Each platform
observation opens user/mount/network namespace descriptors for every task and performs a bounded
two-pass UID/GID-map read; the census rejects heterogeneous or changing task credentials,
namespaces, maps, malformed canonical extents, oversized content, and excess entries. The process
verifier requires both engine observations to match the immutable request's exact four-slot UID/GID
policy, empty supplementary groups, zero capabilities, `NoNewPrivs`, exact user/mount/map domain,
and daemon network namespace. Mismatch is cleanup-uncertain, the evidence factory is not called,
and the adapter retains termination/reap ownership.

Both production receipt authorities therefore remain uninhabited, and the current zero-state
xtables driver still returns `Unsupported` before invoking the delivered private owner. The owner
can provision, attach, verify, read back, recover, and retire the schema-v2 xtables plus exact
transaction-local policy routing when given an admitted target, but production composition cannot
yet construct that target from Android mark/RPDB authority or bind it to the listener, escape,
engine, functional-receipt, and cleanup authorities. The combined integration checkpoint remains incomplete
and is split into the following remaining reviews: final verifier-side completion chronology and prepared-driver
client/peer ownership and retirement; an independent listener observer that proves
UDP listener state, FD/inode/cookie, transparency, and IPv6-only state; a bounded versioned
supervised-report parser and immutable engine capability contract; and actual prebound collector
observations, cleanup binding, and schema-v2 factory execution with test-only fixtures. Readiness
port evidence and the current outbound connected-socket collector do not by themselves prove the
listener contract.
The required-mode plumbing opens this read-only engine authority only after read-only backend
availability succeeds and before a driver returns a prepared value. The current production xtables
driver reports `Unsupported` first, performs no pidfd/procfs credential scan or native mutation, and retains cleanup
`NotRequired`. If a later prepared path cannot open the
authority, normal post-attempt engine/environment observation and teardown still run even when
post-engine reconciliation also fails. Permission failures map to `Denied`; unsupported, identity,
parse, and other adapter failures remain distinct.
The current pre-release composition remains structural-only. Every remaining plumbing
subcheckpoint must preserve that fail-closed result: no device-qualified
local-OUTPUT TPROXY capture mechanism or authoritative engine report producer has been admitted.
A separately qualified cgroup-BPF authority remains an unassigned future experiment; ordinary BPF
counters cannot qualify TPROXY, and these checkpoints add no explicit `.ko` load/unload operation.
Ingress, REDIRECT/DNAT, counters, route lookups, or a veth bounce cannot qualify TPROXY.

Run the socket-diagnostics session and live-correlation regressions with:

```text
cargo test -p flux-platform socket_diagnostics
```

These tests prove pre-collection port visibility, distinct simultaneous session ports, same-handle
sequence continuity, deadline capping, sequence exhaustion, the temporary-session wrapper, and the
existing exact TCP/connected-UDP correlation. They observe procfs and NETLINK_SOCK_DIAG only; they
do not send canary traffic, alter rules/routes/sysctls, or explicitly load/unload modules. A host
kernel may nevertheless service the first TCP/UDP diagnostic request through `request_module` when
its INET_DIAG handlers are modular, so run the live regression only where those handlers are already
active or host autoload policy is acceptable. Production integration must preflight built-in or
already-active handlers and report unsupported instead of using a dump request as that probe.

Run the deterministic seam and coordinator regressions with:

```text
cargo test -p fluxd functional_canary::local_output
cargo test -p fluxd xtables_local_output_executor_never_reaches_running
```

These tests are unprivileged. They exercise request/UID/tuple/payload/listener/delivery/sequence/
loss/timing receipt validation and prove that only the separate verifier can pass receipt-bound
artifacts to the evidence factory. They perform no traffic or networking mutation and do not add a
positive host executor. The suite also opens and binds one NETLINK_SOCK_DIAG session to prove the
exact port-bearing handle reaches prepared execution, but it sends no diagnostic dump request and
therefore does not probe or autoload protocol handlers. "Fail-closed" here describes evidence
admission only; it does not alter the separate user-selected connectivity failure policy.

The delivered credential-only local-OUTPUT preflight is also opt-in:

```text
cargo xtask test-functional-canary-linux-output-preflight
FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux-output-preflight
```

It selects the exact ignored test
`functional_canary::linux_namespace_harness::privileged_local_output_distinct_uid_capability_preflight`.
Before any traffic or rule mutation, the checkpoint creates a disposable user/mount/network
namespace with exactly three singleton UID and GID mappings: controller `0`, probe `20001`, and
engine `20002`. The two role identities must come from distinct delegated subordinate IDs. It
uses trusted mapping helpers under a scrubbed `PATH`, clears and verifies supplementary groups,
reads back the exact maps and namespaces, and executes both nonzero roles with matching real,
effective, saved, and filesystem credentials, zero inheritable/permitted/effective/ambient
capabilities, and `NoNewPrivs=1`.

Unavailable helpers, subordinate ranges, parent mappings, or group policy explicitly skip in
optional mode and fail in required mode. Exact-map, namespace, or credential drift after the
availability probe fails in both modes. Root/root, same-UID, broad-map, overflow-ID, inherited-
group, and confined mapped-root fallbacks are rejected. This proves credential capability only;
it does not install local-OUTPUT capture, run Sing-Box, construct schema-v2 evidence, or qualify
Android. None of the four Linux commands is part of the portable `cargo xtask ci` command, and none
may invoke `sudo`, `modprobe`, load a `.ko`, or trigger implicit module autoload. The standard Linux
workflow requires only the non-capture dual-stack topology checkpoint. The ingress, local-OUTPUT,
and distinct-UID checkpoints remain explicit environment gates. The ingress TPROXY preflight runs
before rule mutation and refuses to continue unless the target, mark/comment matches, family
TPROXY support, and selected xtables backend support are already active under `/sys/module`.

Host execution of `addrsyncd` requires Linux or Android. On Windows, use the Android cross-check and run its host tests in Linux CI.

## Android release-profile cross-build

Set `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` to the pinned NDK revision and run:

```text
cargo xtask build-android
```

The task validates `source.properties`, selects the API-suffixed NDK clang linker for the host OS,
applies both NDK-r27 16 KiB page-compatibility options, and builds the `fluxd` release binary. It
then parses the final ELF program-header table and rejects any non-empty `PT_LOAD` whose
`p_align` is not a congruent power of two at least `2**14`. It refuses a different NDK revision
or an under-aligned final artifact instead of silently producing an unqualified binary.

## Magisk module staging

The development bridge is staged only after a successful pinned Android release-profile build:

```text
cargo xtask stage-module --profile bridge --stage dist/module --runtime-binaries /path/to/runtime-binaries
```

`--runtime-binaries` must contain the independently sourced `sing-box`, `jq`, and rollback
`addrsyncd` Android binaries required by the current temporary hybrid stage. The task reads the
checked profile contract from `conf/manifest.json`, copies only its required source and binary
paths, installs the newly built `fluxd` at `bin/fluxd`, and refuses a non-empty stage, missing file,
forbidden path, or extra staged file. `bridge` is the compatibility default when `--profile` is
omitted, but every successful result is labeled development-only.

`--profile rust-only` stages only the 13 final paths and needs only Sing-Box from the runtime-binary
directory. The development bridge currently has 28 required paths, with the exact 15-path difference
forbidden by Rust-only. Staging selects the minimal tracked `customize.sh` and `flux_service.sh`
sources under `packaging/rust-only/`; the already-minimal update binary and Rust-delegating
uninstaller remain shared. The installer is deliberately fresh-install-only and refuses an existing
`/data/adb/flux` rather than migrating bridge state in shell. This is still a non-runnable,
non-releasable migration skeleton: the checked profile remains `failing-until-complete`, production
still selects the bridge writer, and provenance/device/cutover gates remain incomplete.

To exercise the current hybrid package-consistency boundary, populate every blank
source/source-revision/version/hash/license field in
`conf/manifest.json`, add hashed schema-1 passed device-test evidence bound to the exact source
revision, operational payload, Android build fingerprint, kernel, boot ID, verified-boot/SELinux
state, and the exact passed test set (`module_boot`, `status`, `enable_disable`, `restart`,
`abnormal_sing_box_exit`, `dual_stack_tcp_udp_dns`, and `cleanup`), and generate a populated SPDX
document, exact pinned-toolchain build metadata, and a
complete recursive `checksums.sha256` inventory. Then run:

```text
cargo xtask verify-package --profile bridge --stage dist/module
cargo xtask verify-package --profile rust-only --stage dist/module
```

The first command checks the temporary bridge and, even on success, reports it as development-only.
The second is the Rust-unification gate: today's bridge stage fails immediately on an explicitly
forbidden path, and a structurally complete Rust-only stage still cannot authorize release while
the checked status is `failing-until-complete`.

The verifier requires a clean root Git state and, for the bridge only, a clean `addrsyncd` submodule.
It binds each applicable first-party binary revision to its exact HEAD. It requires the staged
schema-2 profile policy to equal the checked-in policy; enforces the selected exact file inventory;
byte-compares selected source-owned files; derives the exact manifest binary set from the profile;
validates bounded
file-backed AArch64 executable entries and Android interpreter paths; rehashes every artifact and
payload-bound device record; cross-binds exact SPDX package/source/license/hash records; verifies
pinned build metadata and complete checksums; and rejects unreviewed Magisk root files, unsafe
paths, symbolic links, `.ko`/`.kpm` payloads, placeholder/unreviewed licenses or evidence, and any
unknown or altered profile policy. The Rust-only contract requires `fluxd`, Sing-Box, Rust-owned
configuration/assets, and platform glue, while forbidding standalone `addrsyncd`, `jq`, both legacy
configuration files, and all 11 current runtime scripts. The checked-in metadata remains
intentionally incomplete, so an ordinary staged tree also fails provenance and device-evidence
requirements.

For `rust-only` only, module-content verification also inspects the exact four platform-glue sources:
the Magisk update binary, installer customizer, boot service, and uninstaller. Each is limited to
128 KiB of non-NUL ASCII, must contain the expected direct installer/`fluxd` delegation, and is
rejected if normalized source contains networking or kernel mutation, subscription retrieval,
configuration compilation, owned-state cleanup, legacy runtime paths, direct Sing-Box orchestration,
or dynamic `eval`/`sh -c`/backtick command construction. This policy is deliberately not applied to
the active development bridge; its shared installer/watchdog remains the rollback oracle and fails
when evaluated as Rust-only until profile-specific minimal glue is staged.

The current verifier establishes internal consistency, not external trust in an unsigned evidence
file or self-declared third-party build. Passing it cannot override ADR-0011. Publication remains
blocked until the runtime is fully Rust-owned, the Rust-only profile is promoted only after its
ownership gates pass, and
`package-magisk` verifies signed or reproducible third-party provenance and trusted device/CI
attestations.

## Pre-release Phase 1 development bridge

The packaged module installs `flux_service.sh` as module-local `service.sh`. It launches only a
bounded watchdog for `fluxd daemon`; mutation-capable daemon profiles own file observation inside
the existing reactor. `scripts/flux-event` remains in the development bridge inventory as a legacy
adapter with no runtime caller and is removed with the other bridge artifacts in B3.

Native online commands are:

```text
fluxd ping
fluxd status [--json]
fluxd start|stop|restart|reload|resync
fluxd control start|stop|restart|reload|resync
fluxd diagnose [--json]
fluxd logs [runtime|daemon|engine] [--lines 1..1000] [--json]
fluxd backend explain [--json]
fluxd plan [--dry-run] [--json]
fluxd rules-preview [--json]
fluxd event EVENT_TYPE WATCHED_PATH EVENT_NAME
fluxd subscription update
fluxd cleanup --offline
```

The `event` form is retained only for compatibility testing. Module boot and the dispatcher do not
invoke it after B2.2.

The local `SOCK_SEQPACKET` control contract is protocol version 3. Version 2 introduced the coherent Capability Profile; version 3 adds the required orthogonal runtime-verification state, subscription maintenance, and additive read-only diagnostic/log/explain commands. The nested Capability Profile is independently versioned and now uses schema 2 for exact device identity. Version-1 and version-2 requests are rejected explicitly instead of being decoded against the new response shape.

The socket defaults to `/data/adb/flux/run/fluxd.sock` with mode `0600`. Accepted peers must match
the daemon effective UID. `/data/adb/flux/run/fluxd.lease` is a persistent regular file whose
nonblocking exclusive kernel lock is the only daemon/offline ownership fact; its presence,
`fluxd.pid`, and the socket do not authorize cleanup. Administrative intent is atomically recorded
in `/data/adb/flux/state/administrative-intent.json` with the current Linux boot ID, so a daemon
restart replays desired running/stopped state before normal control traffic. Startup reconciliation
must complete before the socket binds; journal, dispatcher, peer, or socket-safety failures remain
fatal and are handled by the bounded watchdog. `fluxd cleanup --offline` acquires the same lease
before invoking bounded `startup-recover`, and returns exit `75` when a daemon is active or starting.

The authoritative Phase 1 user configuration is `/data/adb/flux/conf/flux.toml` (override with
`FLUXD_CONFIG_PATH` for development and tests). Schema 3 is intentionally exact: unknown,
duplicate, or missing fields are rejected; only explicit xtables TPROXY and
`fail_policy = "open"` are admitted. It types daemon, engine, capture, listener,
application/user, interface, bypass, subscription, and safety intent, including separate
encoded-download and decoded-content byte budgets. `daemon.event_queue_capacity` sizes the bounded
legacy-writer queue. Mutation-allowed startup validates the file before admitting the writer or
control socket, and every subsequent preparation reloads it so one immutable current snapshot feeds
canonical engine compilation. The daemon observes the parent directories of `flux.toml`, its
selected template, its selected subscription URL file, and the module `disable` entry. A valid
Desired State edit retargets the dynamic watches; an invalid edit queues a fail-closed reload while
retaining the last valid watch set.

When the kernel is below 5.10, or when the kernel version or boot identity cannot be verified, `fluxd` enters its settled read-only service without loading `flux.toml`, reading administrative intent or disable state, or starting the legacy mutation writer. In particular, every verified below-5.10 kernel is guaranteed to remain queryable without mutation. Read-only Capability Profile collection may still inspect boot identity, SELinux state, and legacy artifact metadata, but it never executes the dispatcher. Schema 2 also exposes exact Android device identity. Generic Linux reports that observation as `Unavailable`; Android reads properties through bionic, requires complete verified-boot lock/algorithm/digest facts, rechecks properties/kernel/namespace and the active Connectivity APEX selection, hashes fixed policy/netd/APEX paths through bounded no-follow reads, and hashes the executing image through `/proc/self/exe` with path/descriptor metadata revalidation. Any missing, denied, malformed, changing, unsafe or oversized fact fails closed. The compiled reviewed-policy selector accepts only exact source-coded entries and currently has an empty production entry table: verified nonmatches receive zero grant, while incomplete identity fails closed, pending independent physical ARM64 review. Tests and nonstandard environments may override the first two legacy probe files with `FLUX_BOOT_ID_PATH` and `FLUX_SELINUX_ENFORCE_PATH`. This keeps status queries available while preventing mutation-configuration or persistence failures from turning a read-only device into a watchdog restart loop. Development-bridge upgrades automatically preserve an existing `flux.toml`; a first bridge installation receives the packaged default. The non-releasable Rust-only skeleton is fresh-install-only and refuses an existing runtime root until migration is Rust-owned.

The Phase 1 daemon owns control admission, shutdown, route-network observation, and file observation
through one `epoll` reactor. The inotify driver uses nonblocking parent-directory watches, processes
at most eight 16 KiB reads per readiness turn, treats queue overflow and watch invalidation as full
reconciliation facts, retries missing watches, and periodically detects replaced directories by
identity. Directory ancestry is opened without following symbolic links. Recoverable watch-install
failures keep the daemon alive; a fatal inotify descriptor/read failure remains a reactor error. A
stop request closes admission before in-flight connection work drains. Timerfd, pidfd, netfilter
netlink, and BPF event sources remain later work.

Supported lifecycle, status, diagnostic, log, and explain/preview commands run directly through `fluxd`; no shell control wrapper remains. Read-only diagnostics, fixed `runtime`/`daemon`/`engine` log streams, and explain/preview use same-effective-user socket requests, do not enter mutation deduplication, and never invoke `ip`, `iptables-save`, shell, or shared-cache generation. The obsolete dispatcher `cache-preview` branch is also removed. Log requests are limited to 1,000 lines and a 256 KiB source tail. Explain is explicitly non-authorizing and does not publish a Generation, cache, receipt, or writer lease; it reports configured intent and canonical engine identity but does not yet resolve application UIDs or live network inventory into the full Capture Program. The legacy dispatcher accepts networking mutations only with `FLUXD_BRIDGE=1` and serializes the two production bridge writers with an identity-bearing lock: `scripts/tproxy` owns xtables/Flux PBR writes, while standalone `addrsyncd` owns address synchronization. Its legacy start, stop, restart, and failure-cleanup paths also acquire the shared writer fence before each parent-bound mutating `addrsync` or `tproxy` phase child. Those phase children are serialized into one authenticated slot, so a survivor remains blocking after dispatcher death; a native lease rejects the phase transaction before networking mutation.

### A2 host-only Generation assembly

`GenerationAssembler::assemble` now provides one internal deterministic path from the schema-2
Desired State, canonical engine and Capture Program artifacts, exact Capability/Engine Profiles,
Network Inventory, planning evidence, and optional prior owned identity to a complete
`AdmittedGeneration`. Equal numeric capability revisions do not substitute for exact profile
identity: canonical SHA-256 digests bind every retained profile field and all Android planning
evidence, including topology, census observation/content, policy, ownership journal, namespace,
planes, and partial audit. The Generation identity also binds exact RPDB placement and predecessor
identity.

The coordinator currently exposes only a read-only inspection projection. Its strict prepared
record is limited to 16 KiB, validates lowercase SHA-256 values and contiguous lineage, rejects
symlinks, and publishes with file/directory fsync plus atomic rename. This path has no daemon CLI,
native-target conversion, writer token, activation lease, or mutation method. WSA can supply
development evidence when attached, but neither WSA nor a host fixture authorizes Android release
or changes the fenced legacy networking writers.

### Rust-owned engine handoff shell contract

The delivered Phase 1 handoff invokes `FLUXD_BRIDGE=1 scripts/dispatcher` through the phase verbs `startup-recover`, `prepare`, `capture-start GENERATION`, `capture-stop`, `capture-verify GENERATION`, `address-resync`, `state-running GENERATION`, `state-stopped`, and `state-failed`. These verbs never invoke `scripts/core`. A boot-scoped dispatcher mode lease rejects mixing them with the retained legacy `start`, `stop`, and `restart` rollback path; `state-stopped` releases the Rust-owned lease only after capture is detached. This makes Rust the sole Sing-Box owner for the daemon run while the dispatcher serializes the legacy `scripts/tproxy` capture/PBR writer and standalone `addrsyncd` address-sync writer.

Before invoking `prepare`, `ProcessRuntimeWriter` reloads schema 3, opens the configured template as
a bounded regular non-symlink file, compiles the listener into deterministic canonical JSON, derives
the temporary renderer inputs in Rust, and atomically publishes read-only
`/data/adb/flux/conf/config.json` and `/data/adb/flux/run/desired-state.env` from the same snapshot.
The environment has one strict 41-field allowlist and cannot carry shell syntax. It binds engine
path, numeric launch identity, startup/stop timeouts, listener, application/user and interface
selection, family policy, structurally parsed FakeIP ranges, and reviewed fixed bridge constants.
No `init` branch runs the shell subscription updater. Rust-owned preparation also never reads
`settings.ini`, legacy cache policy, generated JSON, or `jq`; only kernel observation may append
`KFEAT_*` fields.

The compatibility compiler fails closed when valid schema-3 intent cannot be represented by the
frozen renderer, including missing local/forwarded capture, single-protocol or IPv6-only capture,
user bypass CIDRs, Android VPN intent, required functional canaries, or interface-role overflow.
Enabled subscription intent is admitted only with an exact store-validated Rust artifact and the
current root-owned engine identity. After the dispatcher snapshots the artifacts, Rust requires the
returned manifest's binary, launch identity, startup and stop timeouts, config digest, and listener
to match the same Desired State. The typed restart policy replaces the manifest's bridge default.
Any shell drift fails before engine activation.

### Rust subscription runtime

The daemon owns one capacity-one synchronous subscription worker outside the serialized runtime
writer. It applies the schema-3 HTTPS, redirect, timeout, encoded-byte, decoded-byte, aggregate
asset, and node-count limits; accepts the frozen supported outbound/URI formats; normalizes stable
node names; rewrites supported remote binary rule sets to content-addressed local files; and runs a
descriptor-pinned `sing-box check` before committing the snapshot under
`/data/adb/flux/state/subscription/`.

Startup first recovers the bounded active/predecessor index without network access. It performs one
bootstrap fetch only when subscription intent is enabled and no validated snapshot can be
recovered. Periodic refresh uses `subscription.update_interval_secs`; the manual path is
`fluxd subscription update`. Observed Desired State, template, or subscription URL changes request
an immediate refresh after successful configuration reconciliation. A busy worker retains one
coalesced pending refresh, and configuration observed while disabled requests it when the deferred
inputs are consumed during restart. A published candidate crosses back to `RuntimeCoordinator`, which
either reloads it through the normal Generation compensation path, retains it as an explicit
deferred source while stopped, or rejects it and waits for exact-digest store rollback. Startup
admission uses the same accept/reject handshake. Retrieval, parsing, validation, persistence,
source drift, activation, timeout, or shutdown failure preserves the prior active snapshot.

Manual output distinguishes `updated`, `updated_deferred`, `unchanged`, `disabled`, and `busy`;
typed failures exit nonzero. The snapshot store is currently private (`0700` directories and
`0600` files), so subscription-backed activation rejects non-root engine UID/GID until a secure
traversal/read-mode contract is implemented. Static WebPKI roots intentionally do not inherit
Android user-installed or enterprise CAs.

`prepare` runs under the dispatcher lock, allocates a positive shell-owned generation ID, and snapshots the Rust-generated configuration, environment, rule/cleanup caches, manifest, and generation-local Sing-Box log under `/data/adb/flux/run/generations/<id>/`. Later mutation phases load those immutable generation artifacts instead of the shared live cache. The compatibility path `/data/adb/flux/run/engine.manifest` is atomically published from that generation's manifest for Rust intake; failure discards the incomplete generation and removes the compatibility manifest. The manifest is at most 16 KiB and has this strict line grammar:

```text
FLUX_ENGINE_MANIFEST_V1
generation=1..2147483647
binary=/absolute/path
config=/absolute/path
working_directory=/absolute/path
log=/absolute/path
launcher=direct|busybox-setuidgid
[busybox=/absolute/path]
[identity=USER:GROUP]
readiness=listener|tun
startup_timeout_ms=1..60000
stop_timeout_ms=1..60000
[listener_port=1..65535]
[tun_interface=IFNAME]
```

There are no blank, unknown, duplicate, missing, or mode-inappropriate lines. The complete UTF-8 document is limited to 16 KiB. The generation is a nonzero decimal integer no greater than `2147483647`, and both timeouts are decimal milliseconds in `1..=60000`. `launcher=direct` forbids `busybox` and `identity`; `busybox-setuidgid` requires exactly both. Listener readiness requires exactly `listener_port`, while TUN readiness requires exactly `tun_interface`. Rust rejects symbolic/non-regular manifest files, parses the strict grammar, and constructs the generation-bound `EngineSpec` before launch.

`RuntimeCoordinator` implements the existing `LegacyDispatcher` interface and therefore runs inside the same bounded, serialized `LegacyControlBridge` worker as all control mutations. Start ordering is `prepare` → descriptor-pinned `sing-box check`/launch and child-owned listener or TUN readiness → `capture-start <id>` → structural `capture-verify <id>` → configured functional gate → `state-running <id>`. The current pre-release composition selects the structural-only gate; required-mode tests run the complete exact-binding canary. Capture start, verification evidence, active/previous Generation records, and `RUNNING` publication must all name the same boot-scoped Generation. Before its first networking mutation, `capture-start` records that Generation as the capture owner, then runs the authenticated address-synchronization and TPROXY phase commands sequentially through the one child slot. It compensates both on partial failure, but removes the Generation marker only when both cleanup operations succeed; uncertain compensation retains the evidence needed for a later detach proof. Stop and shutdown detach capture before asking the supervisor to stop/reap the child, then publish `state-stopped`. `address-resync` uses the same writer and cannot interleave with lifecycle work; required mode invalidates the Network-Epoch-bound pass and schedules a fresh gate.

For the current TPROXY compatibility path, `prepare` requires `xt_owner` both before `init` and after loading the generated capability cache. Local OUTPUT always traverses `APP_CHAIN`, even when application filtering is disabled, so the configured Sing-Box UID/GID bypass executes before the default proxy action. The fallback `ROUTING_MARK` setting is not accepted as Rust-owned loop authority because the bridge does not yet prove that the supervised engine applies it to its sockets.

Reload prepares the candidate while the current generation remains active. Only after preparation succeeds does it detach old capture and replace the engine. A failed or uncertain old-capture detach does not launch the candidate: it retains the old engine in `CaptureRepairPending`, blocks start/reload, and lets maintenance repeatedly prove detach before republishing and re-verifying capture for that same old generation. Candidate activation failure attempts to detach partial capture; only proven detach permits candidate retirement and rollback to the recorded previous immutable generation. Uncertain candidate compensation remains `DetachPending` and does not restart the previous generation. Rollback capture and publication are bound to the previous generation ID; failed rollback remains fail-open with capture detached.

If capture detachment fails during stop or failure compensation—including uncertain cleanup after `capture-start`—the coordinator enters `DetachPending`: it retains the generation evidence and intended terminal state, does not signal the engine, does not publish `STOPPED`/`FAILED`, and blocks start/reload. Maintenance retries detachment; only proven detach permits engine retirement/reap and terminal publication.

The worker calls maintenance after requests and on bounded idle intervals. This drives supervisor reap/backoff/restart without starting a second child, restores and re-verifies capture after a successful restart, and retries pending `RUNNING`, `STOPPED`, or `FAILED` publication. A failed `state-running` call does not authorize a blind retry: maintenance first observes the owned engine, reasserts and structurally verifies capture, and, when the injected gate requires it, runs a fresh complete functional canary. Only the still-ready matching Generation may retry `state-running`. Failed verification enters `CaptureRepairPending`, which proves detach, republishes capture for the same Generation, runs the complete configured gate again, and only then republishes `RUNNING`; an observed engine exit takes detach/repair precedence. Engine identity loss, uncertain reload detachment, repair/restoration, and active address resynchronization invalidate a previous functional pass. Required-mode address resynchronization schedules a fresh `RUNNING` gate through the normal maintenance path.

`fluxd status` exposes an observed `RuntimeSnapshot` (runtime phase, capture, engine, verification, generation, bounded last error, and its own revision) separately from the desired/control `ControlSnapshot` (administrative intent, in-flight request, dirty state, and last completion). Verification is orthogonal to operational phase: `structural_only` is the conservative baseline and means no functional pass authorizes the current observation; `functional_pending` means a fresh exact-binding gate is required; `functional_passed` means the latest required attempt and `RUNNING` publication succeeded for the current binding; and `functional_failed` means the complete required gate, including its structural prerequisite, attempt, evidence, or cleanup, failed. Stop/reset returns to the no-functional-authorization `structural_only` baseline. `RUNNING` alone never implies functional qualification. The current pre-release Phase 1 composition explicitly remains `structural_only`; required functional mode is currently limited to coordinator tests and later privileged harnesses, and even a passed host attempt is not Android device qualification.

Every phase process has a nonzero execution deadline capped at 60 seconds. The Rust Adapter launches the phase shell in its own process group and performs bounded forced cleanup on timeout. Sing-Box validation/run children and phase-shell children also arm `PR_SET_PDEATHSIG(SIGKILL)` with a post-arm parent check, containing direct children if `fluxd` dies. Direct Sing-Box launch therefore supports automatic same-boot crash recovery after capture is detached. This is not process-tree containment: phase descendants do not inherit the lease, and BusyBox `setuidgid` credential changes may clear it. A post-credential Rust launcher and verified Flux-owned process-cgroup containment remain deferred.

On daemon startup, the Capability Profile first decides whether mutation is admissible. An admitted runtime runs the bounded `startup-recover` phase before strict `flux.toml` loading, so a broken current configuration cannot strand same-boot capture; recovery must also succeed before administrative intent is read, persisted, or executed and before the control socket is admitted. Below-floor or unverified profiles stay on the non-mutating read-only path and never invoke recovery. Recovery is serialized by the dispatcher lock. With no lease and no capture evidence it idempotently publishes `STOPPED`. A same-boot Rust lease removes the exact active generation, or uses the immutable prepared generation for markerless partial activation, then stops TPROXY before address synchronization and proves capture evidence absent. For a direct engine launch, `PDEATHSIG` supplies the child-death proof, so recovery publishes `STOPPED`, clears active/previous/verification records, and releases the lease. For `busybox-setuidgid`, child death cannot be proven after daemon loss: recovery publishes `FAILED` only after detachment, preserves the Rust lease and active engine generation, and blocks automatic daemon restart for explicit repair. Cleanup failure likewise preserves evidence and ownership. Same-boot legacy ownership is rejected without mutation; prior-boot evidence is retired without treating kernel objects as surviving the reboot.

Phase 1 `capture-verify` proves shell-owned structural evidence; the always-on owner bypass prevents the default self-capture omission but is not itself a synthetic end-to-end traffic or exact-process loop-prevention proof. The Stage-1 typed canary model, coordinator ordering, failure injection, status contract, authoritative schema-v2 listener/delivery validator, temporal cleanup/retirement validator, fail-closed TPROXY-only local-OUTPUT executor seam, explicit per-flow capture-receipt/verifier contract, process-ownership receipt contract, child-origin pidfd substrate, exact retained-engine before/after observation pair, authoritative engine credential-policy/domain validation, prebound socket-diagnostics session transport, and type-safe attempt-owned observer handoff are delivered, along with the first Stage-2 isolated topology checkpoint, the complete dual-stack TCP/UDP echo plus DNS-over-UDP/TCP third-namespace ingress PREROUTING TPROXY checkpoint, the development-only rooted WSA local-OUTPUT TPROXY checkpoint, and the strict Linux/Android `/proc` FD plus INET_DIAG outbound-collector prerequisite. The exact retained engine-child authority now travels from `SingBoxChild` through matching `EngineSupervisor` ownership and the serialized coordinator into the process-verifier boundary while preserving adapter-owned signal/wait/reap authority. Deferred are the production positive traffic producer; verifier-side completion chronology and prepared-driver client/peer child ownership; backend listener observation and delivery-report parsing/factories; actual prebound collector observations; a production Android adapter and reviewed device qualification; ancestor-safe directory traversal with `openat`/`openat2`; long-term retention/rotation policy for Generation logs; pidfd/timerfd reactor integration; full process-tree containment; and real-device release evidence on the minimum Android 5.10 kernel. Both production receipt authorities remain uninhabited, current xtables remains `Unsupported`, optional eBPF requires separate qualification, and no explicit `.ko` load/unload operation was added. The legacy structural bridge has not yet proven that every xtables/kernel dependency is already active without implicit module requests, so it cannot satisfy the future no-autoload qualification. Ingress, collector, host, or WSA mechanism evidence cannot discharge the production local-OUTPUT gate, REDIRECT/DNAT cannot qualify TPROXY, and production must remain `structural_only` rather than publish `functional_passed` from development evidence.
