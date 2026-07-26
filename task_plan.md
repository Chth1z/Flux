# Task Plan: Comprehensive Project Review and Rust Unification

## Goal
Reconstruct Flux's current design and implementation from repository evidence, compare it with
relevant primary-source projects and platform documentation, then publish a prioritized review and
revise the canonical roadmap so the project reaches one Rust-owned runtime as early and safely as
possible.

## Scope Priorities
- P0: Establish the actual shipped/runtime ownership split and the shortest credible Rust-only path.
- P0: Identify roadmap gates that protect correctness versus gates or artifacts that delay ownership
  convergence without reducing material risk.
- P0: Revise the execution order around an explicit, measurable Rust-unification milestone.
- P1: Preserve the project's strongest safety properties: generation reconciliation, single-writer
  ownership, fail-open rollback, exact capability evidence, and Android coexistence.
- P1: Compare maintained open-source implementations and first-party Linux/Android/Rust sources.
- P2: Defer optional backend breadth and speculative abstractions that do not move the Rust-only gate.

## Phases
- [x] Phase 1: Initialize the review, preserve the Git baseline, and inventory prior planning artifacts.
- [x] Phase 2: Read and index all project documentation, ADRs, manifests, scripts, and test entry points.
- [x] Phase 3: Map the implemented architecture, runtime ownership, dependency seams, and verification state.
- [x] Phase 4: Research comparable open-source projects and primary platform/tooling documentation.
- [x] Phase 5: Synthesize strengths, weaknesses, risks, and alternative execution strategies.
- [x] Phase 6: Write the comprehensive review and revise the canonical implementation roadmap.
- [x] Phase 7: Verify documentation consistency, links, formatting, and the final Git diff.

## Key Questions
1. What executes in production today, and which responsibilities are owned by Rust, shell, or external binaries?
2. Which documented modules and authority types provide real leverage, and which are shallow or premature?
3. What exact work remains before shell networking and the standalone `addrsyncd` can leave the package?
4. Can device qualification proceed in parallel with host-side Rust implementation instead of blocking it?
5. Which external projects demonstrate simpler ownership, backend, packaging, or test strategies?
6. What is the smallest Rust-only release gate that preserves rollback and Android networking safety?

## Intended Outputs
- `notes.md`: repository evidence, quantitative inventory, and source-backed research notes.
- `docs/research/open-source-architecture-comparison-2026-07.md`: primary-source external comparison.
- `docs/architecture/project-review-2026-07.md`: comprehensive design review and recommendations.
- `docs/architecture/implementation-roadmap.md`: revised execution order and future-work plan.
- Documentation indexes only if needed to make the new artifacts discoverable.

## Decisions Made
- Treat Rust unification as the scheduling objective, not as permission to weaken the single-writer,
  rollback, or real-device qualification gates.
- Separate host-implementable work from device-dependent evidence so missing hardware does not pause
  code that can be built and verified safely off-device.
- Use primary project documentation, source repositories, specifications, and first-party platform
  documentation for external claims.
- Make no production-code changes in this review unless a documentation claim cannot be corrected
  without a tightly scoped source fix.
- Define the near-term target as one Rust-owned `fluxd` runtime plus the explicitly external
  Sing-Box engine. Platform-required installer/boot glue may remain shell, but it may not own
  configuration compilation, lifecycle policy, networking mutation, recovery, or cleanup.
- Pull host-implementable configuration, subscription, CLI, address-observation, and packaging work
  ahead of the physical-device boundary. Physical ARM64 qualification remains mandatory for native
  activation, but no longer serializes unrelated Rust ownership work.
- Keep the first Rust-only release to conventional xtables TPROXY. nftables, managed TUN, eBPF,
  ipset acceleration, and broader backend selection are post-unification work unless evidence shows
  one is required for the minimum supported product behavior.
- Add source-backed release gates for per-origin VPN/network egress and 16 KB-compatible Android
  ELF alignment; neither may be inferred from root UID, kernel version, or a successful cross-build.

## Errors Encountered
- The first final B2.1 `cargo xtask ci` invocation yielded into a child session whose final status
  was not retained by the wrapper; no Cargo/xtask process remained afterward, so the partial compile
  output is not evidence. Rerun with explicit session polling and record only the captured exit.
- The first final B2.1 focused gate stopped at rustfmt on one long read-only protocol-test line.
  Apply canonical formatting and rerun the unchanged gate; production code was unaffected.
- The first lightweight B2.1 manifest-summary test compile returned a borrowed `&Path` where the
  inspection source owns a `PathBuf`. Convert the validated path with `to_path_buf`; the summary
  interface remains narrow and the full runtime manifest path is unchanged.
- The first B2.1 all-target compile found a wire-validation `usize`/`u64` comparison, a run-directory
  borrow retained across moving its manifest path, and one test-only `File` import at module scope.
  Convert the observed byte count with checked `u64::try_from`, own the derived run directory, and
  move the import into the test module; no interface or runtime behavior changes.
- The next B2.1 all-target compile passed the production implementation but found that the public
  `DaemonClient` test Adapter lacked the three additive read-only methods; it also identified a
  socket constructor used only by unit tests. Give additive inspection methods a stable unavailable
  default and gate the old constructor to tests, preserving existing client implementations.
- The first focused B2.1 test compile referenced `DiagnosticState` from the protocol test without
  importing its public re-export. Add the explicit fixture import and rerun the unchanged target;
  production code was unaffected.
- The first post-wrapper B2.1 rustfmt check requested one line-wrap change in the Desired State
  diagnostic error arm. Apply canonical formatting; shell syntax and the isolated wrapper
  delegation suite already passed.
- The first external-research dispatch combined full-context inheritance with an explicit agent
  type, which the collaboration tool rejects. No agent started and no repository state changed;
  relaunch with inherited defaults and the same single-file ownership.
- The first stale-reference patch did not match one wrapped sentence in `docs/development.md`.
  `apply_patch` changed nothing; the patch was reapplied against the exact context.
- The first Gate 1 terminology patch appended the ADR-0012 replacement sentence without deleting
  its predecessor. The immediate verification read found it, and the duplicate was removed.
- The first external-URL recheck wrapper used a nested JavaScript template literal that the tool
  wrapper parsed before execution. No request ran; the check was rerun with plain concatenation.
- Two combined final-sweep wrappers were rejected before execution because a literal Markdown fence
  conflicted with the wrapper string. No checks ran in those attempts; the diagnostics were split
  into independent commands and all passed.
- The first P0-G0 `cargo test -p xtask` compile reached the rewritten fixture helper and found that
  its match expression still compared `&String` values with `&str` patterns. Production `xtask`
  had already passed `cargo check -p xtask`; matching on `relative.as_str()` corrected the fixture.
- The first P0-G0 `cargo fmt --all -- --check` reported formatting-only differences in
  `xtask/src/main.rs`. `cargo fmt --all` applied the canonical layout before the verification rerun.
- The first helper-append patch for schema-2 config tests targeted an older formatting shape at the
  end of `crates/flux-core/tests/config.rs` and changed nothing. Reading the exact tail and applying
  against its current multiline assertion resolved the context mismatch.
- The first schema-2 focused Clippy run rejected two test-only `replacen` calls whose old and new
  strings were identical. Removing those no-op fixture transformations preserved the cases and
  cleared the lint finding.
- The first direct Desired State compiler test searched for escaped quote bytes in canonical JSON,
  so one of five new tests failed even though the typed listener value was correct. Using an
  unescaped raw byte string fixed the test fixture; production code was unchanged.
- The first A1.3 focused command passed two positional test filters to `cargo test`, which Cargo
  rejects at argument parsing. The publisher and production-writer filters were rerun separately.
- The first A1.3 test compile found that `expect_err` requires `Debug` on success types which
  deliberately do not expose it. Explicit result matching kept those production traits narrow and
  preserved the same failure assertions.
- The first hostile shell-drift fixture tried to append to a copied `0444` canonical artifact and
  failed in the dispatcher before reaching the binding check. The fixture now explicitly changes
  its private copy's mode before mutation so the test exercises digest rejection.
- One patch combining that fixture fix with the error log used task-plan context under the source
  file and matched nothing. Reapplying the two file hunks against their exact contexts resolved it.
- The first full `cargo test -p fluxd` passed all 196 library tests but the daemon shutdown
  integration fixture still pointed schema-2 engine sources at `/data/adb/flux`. Rebinding its
  binary, template, listener, and immutable Generation config paths to the temporary test root
  restored an honest production-preparation fixture.
- The first schema-documentation patch generated unprefixed TOML lines inside an `apply_patch`
  hunk and was rejected before changing files. Splitting it into exact per-file patches resolved
  the patch encoding error.
- The first combined patch for that fixture encoded the shell continuation lines incorrectly and
  was rejected before changing either file. The source and plan updates were reapplied as smaller
  exact-context patches.
- The first A1.4 compile check found that bridge interface conversion borrowed bytes from the
  temporary returned by `selector.name()`. Binding the copy to a local value extends the borrow for
  the conversion without changing the interface or artifact format.
- The first A1.4 dispatcher fixture copied the read-only Desired State environment directly onto
  its mutable derived cache, preserving mode `0444` and blocking test capability append. The
  fixture now changes only the derived cache to `0644`; the Rust-owned source remains `0444`.
- The next dispatcher run found that `scripts/lib` declared the three mark values read-only before
  sourcing the Rust artifact. They now remain legacy defaults but are assignable by the validated
  Rust environment, moving their Rust-owned-mode authority out of shell.
- The subsequent suite reached the explicit legacy rollback fixture and found its test cache no
  longer supplied legacy-only `UPDATE_INTERVAL`. That field is restored only to the fixture's
  legacy derived cache; it is not part of the Rust-owned environment.
- The first focused A1.4 process-writer test compile used a nonexistent `Reason::Reload` variant in
  the new restart-policy fixture. `Reason::ConfigChanged` is the real reload trigger; changing only
  the test call restored the intended production-path coverage.
- The first complete A1 `fluxd` run passed all 206 library tests, then the daemon-shutdown integration
  fixture failed before startup because its old minimal template had no canonical FakeIP server.
  The same fixture also declared obsolete 3000 ms manifest timeouts against schema 2's 5000 ms
  Desired State. Adding the required template shape and matching the manifest to Desired State keeps
  the integration test on the real production preparation path.
- The first A2 assembler compile found three local representation mismatches: an already-copied
  placement was dereferenced, RPDB placement exposes `RuleTableId` while route lowering requires
  `RouteTableId`, and TUN readiness names are strings rather than OS strings. Removing the
  dereference and performing explicit typed/byte conversions preserves the intended identities.
- The first A2 Clippy checkpoint found that the owned Android planning authority made
  `GenerationPlanningAuthority` a 1280-byte enum versus 448 bytes for host inspection. Boxing only
  the non-cloneable Android variant preserves its single-use semantics and reduces request size.
- The first boxed-authority compile kept its constructor `const`, but Rust 1.93 does not permit
  `Box::new` there. Making this internal constructor an ordinary function preserves its interface
  and authority ownership while allowing the required indirection.
- After boxing Android authority, Clippy identified the 448-byte host profile as the remaining
  oversized enum variant. Boxing both owned planning variants keeps the enum compact without
  suppressing the lint or changing validation semantics.
- A2 semantic diff review found that successor identity advanced the numeric Generation but did not
  bind the prior digest, allowing divergent histories to converge on one successor identity. The
  assembler now hashes the complete prior identity, and record loading requires contiguous lineage.
- The first final A2 `cargo xtask ci` run reached the workspace suite but failed the pre-existing
  `validation_timeout_is_bounded_and_forcibly_reaps_the_check` diagnostic-tail assertion after its
  75 ms timeout returned an empty stderr tail. The exact test passed alone but failed consistently
  in the parallel 19-test target; a later run also proved the deadline could expire before the
  fixture recorded its descendant PID. Raising only the test deadline to 500 ms and treating
  timeout diagnostics as bounded but optional preserves the process-group cleanup/reap proof. The
  parallel target then passed twice, and a clean full repository gate passed with production code
  unchanged.

## Status
**Complete** - the source-backed review, revised roadmap, cross-document reconciliation, and final
verification are complete. Physical Android qualification remains an explicit external release gate.

## Verification Snapshot
- `cargo xtask ci`: passed on 2026-07-23.
- Root workspace: 984 passed, 0 failed, 12 ignored.
- Excluded `addrsyncd` submodule: 98 passed, 0 failed, 1 ignored.
- External sources: 44 checked, 44 HTTP 200, 0 failed.
- Documentation: 138 local targets across 43 Markdown files resolved; 48 citation labels defined;
  three Mermaid blocks and heading/fence structure passed; zero stale numbered-backlog references.
- `git diff --check` and changed-file trailing-whitespace checks: passed.
- Production composition remains hybrid: `fluxd` -> `ProcessRuntimeWriter` -> shell dispatcher/
  `tproxy`/`addrsync`; native owner admission, Generation compilation, network inventory, and the
  functional canary are not connected to production mutation.

## Execution: P0-G0 Package Profiles

### Goal
Make the current bridge package and the target Rust-only package distinct, machine-checked
contracts without deleting or weakening the bridge that remains the WSA/runtime oracle.

### Priorities
- P0: Put the exact required and forbidden path inventories for both profiles in the checked-in
  release manifest.
- P0: Make `xtask` staging, verification, binary validation, source binding, and payload hashing
  select an explicit profile contract.
- P0: Ensure bridge verification is reported as development-only and the Rust-only verifier remains
  non-authorizing while its manifest status is `failing-until-complete`.
- P1: Update the operator-facing development/specification text and the canonical roadmap status.
- P2: Do not remove bridge files, absorb `addrsyncd`, or start device-authority work in this gate.

### Phases
- [x] Phase G0.1: Inspect the current stage/verifier implementation and freeze the profile schema.
- [x] Phase G0.2: Implement manifest-owned package contracts and profile-aware `xtask` behavior.
- [x] Phase G0.3: Add focused parser, contract, bridge-pass, and Rust-only-fail tests.
- [x] Phase G0.4: Reconcile documentation and record the next unblocked host implementation slice.
- [x] Phase G0.5: Run focused and repository-wide verification, then review the complete diff.

### Decisions
- Retain `bridge` as the default CLI profile for compatibility, but label every successful stage or
  verification result as development-only and never as release-ready.
- Treat the checked-in profile array in `conf/manifest.json` as the only path-inventory source.
  Staged release metadata may populate hashes and evidence, but its profile policy must byte-for-byte
  deserialize to the checked-in policy.
- Require the Rust-only forbidden set to equal the bridge-required minus Rust-only-required set.
  This proves every removed bridge path is named and prevents silent inventory gaps.
- Keep Rust-only structurally verifiable but reject release authorization while its status remains
  `failing-until-complete`; Gate B3 will change that status only after runtime ownership converges.
- WSA may exercise mechanisms later, but cannot satisfy physical Android ARM64 release evidence.

### Status
**Gate 0 verification passed; P0-A1 started** - implementing the complete typed Desired State in
bounded host-verifiable slices.

## Execution: P0-A1 Complete Product Desired State

### Goal
Replace the shell-era split configuration with one strict Rust-owned snapshot that can feed the
existing canonical engine and Capture Program compilers.

### Phases
- [x] Phase A1.0: Inspect the daemon-only parser, shell settings, documented schema, capture inputs,
  engine compiler, and current production prepare path.
- [x] Phase A1.1: Introduce schema 2 with typed engine, capture, listener, application/user,
  interface, bypass, subscription, and safety sections; update the packaged configuration.
- [x] Phase A1.2: Add one deep Desired State compilation interface returning identity-bound engine
  and Capture Program artifacts from an immutable config snapshot.
- [x] Phase A1.3: Connect canonical engine compilation to production preparation without letting
  shell or `jq` rewrite the generated artifact.
- [x] Phase A1.4: Replace `settings.ini`/read-only `jq` capture derivation with Rust-exported typed
  compatibility inputs while retaining the fenced shell writer.
- [x] Phase A1.5: Verify focused behavior and the full repository; reconcile documentation.

### A1.1 Decisions
- Bump the authoritative user schema from 1 to 2 because the prior accepted shape contained only
  daemon controls; silently changing schema 1 would make old files mean something materially new.
- Admit only explicit `backend = "xtables"` TPROXY in the first Rust-only release. Do not expose
  `auto`, nftables, TUN, eBPF, or reserved compatibility knobs through the active schema.
- Store numeric engine UID/GID rather than evaluating names, and store absolute bounded paths rather
  than shell expressions.
- Represent interface intent as three explicit lists (`forwarded_proxy`, `local_bypass`, and
  `excluded`) that map directly to the existing Capture Program model.
- Keep mandatory private/loopback/link-local/multicast safety compiler-owned. User bypass input is
  an additional canonical CIDR list, not a way to disable mandatory safety.
- Parse subscription and VPN/functional-safety intent now, but do not claim the B1 downloader or
  physical Android/VPN authority exists merely because configuration accepts the intent.

### Status
**Complete on 2026-07-25** - Rust owns product-policy compilation and immutable bridge publication;
the mutually exclusive shell networking writer remains fenced until the joined native cutover.

### A1.4 Execution Plan
- [x] A1.4.1: Compile one bounded, deterministic compatibility environment from schema-2 Desired
  State plus the canonical engine artifact; reject shapes the fenced renderer cannot represent.
- [x] A1.4.2: Atomically publish that environment with the canonical engine configuration and bind
  both paths into production daemon options.
- [x] A1.4.3: Make Rust-owned shell preparation consume only the published environment plus observed
  `KFEAT_*` values; remove its runtime dependency on `settings.ini` and `jq`.
- [x] A1.4.4: Add pure compiler, publication, production-writer, and dispatcher contract tests.
- [x] A1.4.5: Reconcile active documentation and run the complete A1 verification matrix.

### A1.4 Decisions
- Keep `scripts/tproxy` and `scripts/addrsync` as the mutually exclusive, fenced networking writer;
  this gate changes their inputs, not mutation ownership.
- Represent schema interface selectors through the four frozen legacy role slots only when the
  mapping is exact. More than four forwarded/local-bypass selectors fails closed.
- Require both local and forwarded capture plus TCP and UDP in the bridge. Narrower schema shapes,
  configured bypass CIDRs, enabled subscription retrieval, Android-VPN intent, and mandatory
  functional-canary intent remain valid future Desired State but are rejected by this temporary
  bridge rather than silently ignored.
- Derive engine binary, numeric credentials, listener, timeouts, application/user selection,
  interface selection, family selection, and FakeIP ranges in Rust. Keep marks, backend names, MSS,
  QUIC, and device-wide compatibility switches at reviewed fixed bridge values.
- Kernel capability observation may append only `KFEAT_*` fields after the immutable Rust-owned
  environment. It may not read product intent or engine JSON.

## Execution: P0-A2 Complete Generation Assembly

### Goal
Add one internal coordinator-facing assembly interface that turns the already modeled immutable
inputs into a complete, inspectable `AdmittedGeneration` on a host without manufacturing Android
mutation authority.

### Priorities
- P0: Reuse the existing Desired State compiler, inventory identity, capability profiles, target
  admission, canonical lowering, and prior-owned-state models behind one small interface.
- P0: Make the host result complete enough for coordinator preparation and inspection while keeping
  production native mutation unconstructible without physical Android authority.
- P1: Keep raw receipts, partial candidates, and backend-specific planning details private to the
  assembler.
- P2: Do not connect live native mutation, invent Android evidence, or begin address-reactor
  integration in this gate.

### Phases
- [x] Phase A2.0: Map the existing assembly inputs, authority types, coordinator contract, and
  persistence discipline; freeze the narrow interface.
- [x] Phase A2.1: Implement `GenerationAssembler` and `AdmittedGeneration` using existing modules.
- [x] Phase A2.2: Add host assembly, identity binding, stale-input rejection, authority-gating, and
  prior-state tests at the assembler interface.
- [x] Phase A2.3: Connect the non-mutating result to coordinator preparation/inspection and bounded
  Generation persistence without enabling production mutation.
- [x] Phase A2.4: Reconcile active documentation and run focused plus repository-wide verification.

### Decisions
- WSA may provide development evidence if it becomes available, but neither WSA nor a host fixture
  can authorize a production Android networking target.
- A2 ends at non-mutating coordinator preparation and inspection. The production native writer and
  physical target constructor remain A4/C-lane work.
- Capability revision is only freshness metadata. Generation identity additionally binds the
  canonical complete Capability Profile and the full Android planning authority, including
  topology, census, policy/journal, namespace, planes, and partial-audit evidence.
- Generation assembly binds exact RPDB placement and predecessor identity. Prepared-record loading
  admits only Generation 1 without a predecessor or an exact contiguous successor lineage.
- Both planning-authority variants are boxed at the assembler seam so the request retains owned,
  single-use authority without a 448-1280 byte enum representation.

### Status
**Complete on 2026-07-25** - A2 is host-verified and documented without creating Android mutation
authority. The next executable host slice is `P0-A3`: connect `NetworkInventorySource` to
reconciliation and absorb address-sync behavior/tests while the physical ARM64 lane remains blocked.

## Execution: P0-A3 Absorb Address Reconciliation

### Goal
Consume the daemon reactor's one complete `NetworkInventorySource` inside the existing serialized
coordinator worker, compile address-derived pre-mark bypass evidence without kernel mutation, and
absorb missing behavior tests without copying the unlicensed standalone `addrsyncd` implementation.

### Priorities
- P0: Treat `NetworkInventorySource` as the only daemon observation stream and invalidate pending
  reconciliation whenever the source becomes stale or unavailable.
- P0: Reconcile only complete, materially changed snapshots and bind every derived host bypass and
  Capture Program to that exact snapshot identity and epoch.
- P0: Preserve the mutually exclusive shell/addrsyncd writer fence until the joined native-owner
  cutover; A3 must add no production mutation method or Android authority.
- P1: Port behavior-level startup, churn, loss/resync, duplicate, and replacement coverage into the
  root workspace using specifications and existing root implementation, not unlicensed source.
- P2: Do not add another daemon, worker thread, signal/PID control plane, raw-netlink stack, or
  per-address RPDB realization.

### Phases
- [x] Phase A3.0: Map observer ownership, coordinator serialization, address planning, and bridge
  resync semantics; freeze one narrow non-mutating reconciliation interface.
- [x] Phase A3.1: Implement snapshot-bound address reconciliation and Capture Program compilation
  with explicit unchanged, stale/loss, replacement, and error outcomes.
- [x] Phase A3.2: Attach the reactor source after bind and consume it from the existing serialized
  coordinator maintenance worker without adding a thread or enabling kernel mutation.
- [x] Phase A3.3: Add focused behavior tests for initial publication, coalesced/no-op snapshots,
  churn, loss/full-resync invalidation, replacement, and bridge-writer isolation.
- [x] Phase A3.4: Reconcile active documentation and run focused plus repository-wide verification.

### Initial Decisions
- Poll the immutable source from `LegacyControlBridge`'s existing bounded maintenance worker. The
  observer already performs 50 ms quiet / 250 ms maximum coalescing and publishes only complete
  materially changed inventories, so a second notification queue would duplicate state.
- Use the realization-neutral `AddressHostSetPlan` as Capture Program input. Do not allocate RPDB
  priorities or emit address rules in A3.
- Keep manual bridge `address-resync` behavior unchanged until A4 can transfer xtables, routing, and
  address ownership in one fenced transaction.
- Treat `None` after a previously complete snapshot as explicit invalidation. Do not compile or
  retain that snapshot as current while the observer performs its full redump.
- The excluded `addrsyncd` tree is `UNLICENSED`; behavior may be independently reimplemented from
  specifications and tests, but implementation text must not be copied.
- Introduce one crate-private reconciliation module whose interface is `reconcile()` plus read-only
  inspection. Its production adapter is the deferred reactor source; deterministic tests use a
  replay adapter at the same seam.
- A successful reconciliation retains the exact immutable inventory, realization-neutral host-set
  plan, and complete non-authorizing Desired State artifacts. This makes the result ready for the
  A2 assembler without inventing mark, RPDB, target, lease, or writer authority.
- Resolve an empty application selection locally only when the Desired State names no packages.
  Package-backed allow/deny policy fails closed until the authoritative package-to-UID resolver is
  connected; address reconciliation must not silently compile an empty policy for named packages.

### Errors Encountered
- The first reactor source search targeted `crates/flux-platform/src/reactor/`, but the module is
  `crates/flux-platform/src/reactor.rs`. The failed read changed nothing; subsequent inspection used
  the correct file.
- The first A3 standards-review dispatch combined full-context inheritance with an explicit agent
  type, which the collaboration tool rejects. No agent started and no files changed; the bounded
  read-only review was relaunched with inherited defaults.
- A3 diff review found non-authorizing address compilation scheduled before safety-critical runtime
  maintenance. Reordering the same serialized maintenance callback preserves the one-worker design
  while ensuring detach, repair, reap, and publication retries run first.
- A conventional Android SDK path probe included three directories that do not exist on this host;
  it changed nothing, and PATH/cmd discovery located Linux and Windows ADB directly.
- Both ADB clients listed no device, and Windows ADB could not connect to the standard WSA endpoint
  `127.0.0.1:58526` because the endpoint refused the connection. Host verification continued; no
  Android evidence was claimed.

### Status
**Complete on 2026-07-25** - the live daemon inventory now drives serialized, non-mutating,
snapshot-bound address reconciliation; bridge mutation remains fenced until A4.

## Execution: P0-A4 Production Native Runtime Writer

### Goal
Compose the existing real xtables/rtnetlink Adapter, durable owner, exact crash-recovery resolver,
and coordinator-facing convergence interface without exporting raw kernel verbs, manufacturing
Android authority, or replacing the active bridge before Gate 1.

### Priorities
- P0: Persist and resolve every immutable native target named by the owner journal before any
  mutation, including both sides of an interrupted replacement.
- P0: Keep `recover()` plus `converge(target)` as the kernel-mutation interface and prove startup
  recovery runs before current configuration preparation.
- P0: Construct the real process/netlink Adapter and durable owner behind one small facade; expose
  reports and diagnostics, not restore/rule/route operations.
- P1: Exercise start, replacement, address-driven reconvergence, crash recovery, stop, rollback,
  and exact cleanup through deterministic tests, then run the existing ignored real-Adapter test
  in a disposable user/network namespace when host authority permits.
- P2: Do not add a host-promotable Android authority, enable native production activation, remove
  the bridge/addrsyncd writer, or claim WSA/namespace evidence as physical ARM64 qualification.

### Phases
- [x] Phase A4.0: Map owner visibility, process Adapter construction, durable recovery, coordinator
  ordering, and the missing exact-target resolver; freeze the narrow facade.
- [x] Phase A4.1: Add a bounded no-follow, atomically published native-target recovery archive and
  exact resolver with corruption, identity, replacement, and crash-replay tests.
- [x] Phase A4.2: Add the production native writer facade and dry-run observation report while
  keeping positive target admission authority-gated.
- [x] Phase A4.3: Connect a coordinator-facing convergence seam and tests for recovery-before-config,
  engine/capture ordering, reload rollback, address reconvergence, stop, and no dispatcher use.
- [x] Phase A4.4: Run focused, privileged-when-available, and repository-wide verification; reconcile
  active documentation and record the remaining C2/Gate 1 boundary.

### Initial Decisions
- Store exact owner-consumed runtime material, not only Generation identities/digests. The archive
  is published before the journal can name a target and retains old plus candidate material across
  replacement; recovery therefore never consults current user configuration or live host state as
  authorization.
- Deepen the private native target into the minimal runtime plan the owner actually consumes:
  canonical prepare/retire/stable artifacts, private-chain identities, exact routing, complete
  routing audit, coherent tool identity, and a digest over that recovery material.
- Keep raw xtables restore, save, and rtnetlink route/rule types private to `flux-platform`. The
  coordinator receives opaque targets and convergence/observation reports only.
- A dry run may inspect tools, durable records, intended identities, and conflicts, but cannot
  construct an admitted target or mint a writer lease.
- The production daemon remains on `ProcessRuntimeWriter` until the same physical target supplies
  C2 authority and Gate 1 fences the writer transfer. A4 builds and host-verifies the cutover path;
  it does not silently perform the cutover.

### Errors Encountered
- The first focused compile after deepening the native target found one `&str`/`Box<str>` comparison
  and one deterministic test Adapter that still read prepare/retire artifacts from the removed
  redundant artifact-set field. Explicit comparison through `str` and reading the same artifacts
  from the retained runtime family plan corrected both mechanical call sites.
- The first target-archive check used paths relative to `xtables::owner` rather than the archive's
  actual `xtables::owner::runtime` nesting. Correcting the durable/restore imports by one parent and
  importing recovery material from the owner module resolved the compile-only path error.
- The first archive round-trip tests rejected valid canonical private chains because the recovery
  check assumed an obsolete `FLX{4|6}G` prefix. The lowerer emits role-specific
  `FLX{4|6}{O|P|F}` names; validating the family prefix plus exact prepare-artifact declaration
  preserves the intended constraint and admits the canonical output.
- The first facade stop test showed that a clean-absent convergence still leaves the owner's
  terminal journal for a later fenced absence proof. Pruning its referenced target immediately
  would break crash recovery. Archive maintenance now retains material while that journal exists
  and prunes only after `recover()` proves absence and removes the journal.
- One focused rerun passed two positional filters to `cargo test`; Cargo rejected the invocation
  before compilation or execution. The archive and writer cases were rerun together through the
  single native-owner module filter.
- The first strict A4 Clippy run found the facade error enum exceeded the `result_large_err` bound
  and retained one identity `map_err`. Boxing only its typed source errors and removing the no-op
  mapping preserved diagnostics and cleared the lint without an allowance.
- Review found that atomic archive publication alone did not serialize `stage -> owner journal ->
  prune` across competing processes. A separate no-follow advisory runtime guard plus archive
  refresh now spans the complete mutation transaction; a pausepoint test proves a competitor
  cannot acquire it after the journal names a staged target and before convergence settles.
- The first A4.3 interface patch used one insertion context that did not match `xtables/mod.rs`.
  `apply_patch` rejected the complete patch without changing files; splitting the public contract,
  facade, and re-export edits into inspectable patches resolved it.
- The first native coordinator test compile imported `EngineRuntime` from `engine_supervisor` rather
  than `runtime_coordinator` and retained two unused test imports. Removing those imports fixed the
  compile-only error; production code had already passed `cargo check -p fluxd`.
- The candidate-rollback test first expected an immediate `Running` snapshot. The coordinator
  correctly restores the previous capture but preserves the failed reload as `Degraded` until the
  next maintenance observation. Giving the scripted engine an observed Ready snapshot and asserting
  `Degraded -> Running` preserved both rollback and error-visibility semantics.
- The ignored real-Adapter namespace test reached the harness but user-namespace root could not read
  `/proc/net/ip_tables_targets` (`EACCES`). A private proc remount was also denied by the host and
  `no_new_privs` prevents sudo. The target-registration preflight was not weakened or skipped.
- WSA was installed but stopped. Starting its settings/runtime entry points brought up `vmmemWSA`,
  `WsaService`, and port 58526, but Windows ADB reported the device `unauthorized`. The bundled
  computer-use runtime could not initialize because this WSL workspace URI is not a local Windows
  file URI. No WSA verification or Android authority is claimed unless authorization succeeds.
- Final A4 semantic review found that the coordinator could consume a newly compiled address input
  while runtime ownership was not eligible for replacement, and could continue into address work
  after failed runtime maintenance. A lightweight pending marker now preserves pre-attempt work,
  invalidation clears it, and only a successfully maintained Ready/Published runtime may consume it.
- The same review found that `PreparedNativeGeneration` carried an independently supplied runtime ID
  and opaque capture target. The native adapter now projects and validates the target's Generation
  before retention, so engine/status Generation M cannot converge or publish capture target N.
- The final Windows ADB retry returned an empty device list rather than an authorized WSA target.
  Native `resync` remains request-based at this host checkpoint; C2/Gate 1 must give the control
  response explicit completed-versus-deferred semantics before production selection.

### A4.1-A4.2 Checkpoint
- The archive retains at most the active and replacement targets, reparses every restore artifact,
  validates recovered topology/routing/audit identity, checksums the bounded binary record, and
  publishes it through the existing atomic no-follow durable I/O.
- The facade composes the real process/netlink Adapter, requires successful recovery before
  convergence, stages recovery material before owner journal mutation, retains terminally
  referenced material, and exposes a read-only observation report.
- Focused verification on 2026-07-25: 35 owner/runtime tests passed, the one UID-0 namespace test
  remained intentionally ignored, and `cargo clippy -p flux-platform --all-targets -- -D warnings`
  passed.

### Status
**A4 host composition complete on 2026-07-25** - the opaque convergence interface,
rollback-capable coordinator adapter, Generation binding, and address-maintenance ordering are
host-verified. Production remains on `ProcessRuntimeWriter` until C2/Gate 1; the real namespace check
is blocked by host procfs authority, the final WSA ADB retry listed no devices, and no ARM64
qualification is claimed. The final independent specification audit reported no unresolved A4
finding in the corrected tree.

## Execution: P0-B1 Rust Subscription And Asset Manager

### Goal
Move subscription retrieval, supported input decoding/normalization, template merge, Sing-Box
validation, and known-good publication into `fluxd` without changing the fenced networking writer
or requiring Android hardware.

### Priorities
- P0: Freeze the currently supported subscription contract from root-owned configuration,
  documentation, shell behavior, and adversarial fixtures without reading excluded implementation
  sources.
- P0: Bound redirects, time, wire bytes, decompressed bytes, parsed nodes, JSON depth/shape, and
  persisted state; keep the active snapshot on every failure.
- P0: Publish only engine-validated, digest-bound snapshots through no-follow atomic storage and
  retain at most one known-good predecessor plus content-addressed rule assets.
- P1: Serialize refresh with existing daemon coordination and expose honest completed/deferred/error
  outcomes without adding an async runtime or another long-lived daemon.
- P2: Do not select the native networking writer, remove bridge files from the package, add optional
  proxy protocols beyond the frozen contract, or invent Android qualification evidence.

### Phases
- [x] Phase B1.0: Inventory the current subscription/template/asset contract, production call sites,
  fixtures, and available dependency surface; freeze one narrow Rust-owned interface.
- [x] Phase B1.1: Implement bounded decoding, supported input parsing, normalization, stable naming,
  filtering, deterministic template merge, and adversarial unit fixtures.
- [x] Phase B1.2: Implement policy-bounded synchronous HTTP(S) retrieval and content-addressed asset
  verification using an approved Android-suitable TLS dependency surface.
- [x] Phase B1.3: Implement engine-check-before-publication, atomic active/predecessor persistence,
  corruption handling, and recovery tests.
- [x] Phase B1.4: Connect refresh and periodic scheduling to the serialized daemon path, prepare and
  reload the resulting Generation, and prove failures preserve the active snapshot.
- [x] Phase B1.5: Retire runtime use of `scripts/updater.sh`, reconcile active documentation, and run
  focused plus repository-wide verification.

### Initial Decisions
- Reuse the canonical Generation compiler and existing Sing-Box process validation rather than
  introducing a second configuration validator or publisher.
- Keep retrieval synchronous and bounded on a dedicated finite operation; do not add an async
  runtime solely for periodic downloads.
- Keep `scripts/updater.sh` as a frozen bridge/oracle until B1 parity tests pass. B3, not B1, owns
  its package-profile deletion.
- Treat disabled subscription configuration as no work and never fetch during startup unless the
  Desired State explicitly enables it.
- Recommend exact `ureq 3.3.0` with only Rustls/static roots, gzip, and Brotli, behind a Flux-owned
  synchronous fetch interface. Disable ambient proxies, require HTTPS at every hop, permit at most
  five redirects, and enforce separate encoded and decoded byte budgets.
- Recommend exact `url 2.5.8` for subscription and proxy-URI structure and established
  `base64 0.22.1` for strict standard/URL-safe decoding. Do not use the newly released Base64 SIMD
  default or hand-roll URL parsing.
- Require the committed graph to resolve `rustls-webpki >= 0.103.13`, pass vulnerability/license
  checks, and preserve static-root trust limitations explicitly. The dependency spike cross-compiled
  for ARM64 but produced no device-runtime qualification.

### Errors Encountered
- The first design-skill read used a nonexistent repository-local alias under `.agents`; no file
  was changed, and the catalogued installed skill path was read successfully.
- `cargo info` identified `ureq 3.3.0` and `minreq 3.0.0` but could not write downloaded crate
  metadata into the read-only global Cargo cache. Dependency research continues through upstream
  manifests and documentation; the workspace dependency set remains unchanged.
- The first B1 HTTP/TLS research dispatch combined full-history inheritance with an explicit agent
  type, which the collaboration tool rejects. No agent started and no repository file changed; the
  same single-file assignment was relaunched with inherited defaults.
- The first dependency-resolution check updated `Cargo.lock` to the approved graph, including
  `rustls-webpki 0.103.13`, but could not download into the read-only global Cargo cache. Rerunning
  the same `cargo check -p fluxd` with approved Cargo-cache access downloaded the exact dependencies
  and passed.
- The first B1.1 `cargo fmt --all -- --check` named only the newly added subscription compiler and
  failed on mechanical formatting drift. Applying the repository formatter is the required
  resolution before compilation; no behavior changed during the failed check.
- The first focused `cargo test -p fluxd subscription --no-fail-fast` stopped at five compiler
  errors: four `u64`/`usize` mismatches around the shared engine-config limit and one overlapping
  immutable/mutable selector borrow. It also reported an unused intermediate re-export and a
  redundant Unicode range. Convert the shared bound once with `usize::try_from`, own the selector
  tag before mutation, keep the slice private under the existing temporary `dead_code` fence, and
  remove the subsumed range before rerunning the same target.
- The first B1.2 strict Clippy run rejected one test-only `iter().copied().collect()` conversion in
  the duplicate-rule-set fixture. Replacing it with `to_vec()` resolves the mechanical lint; all
  14 focused subscription tests had already passed.
- The first post-Clippy hardening patch targeted the pre-format multiline fetch import instead of
  the current single-line form, so `apply_patch` rejected it without changing a file. The exact
  formatted locations were reread before applying the same URL-policy and packaged-template test.
- The first B1.2 Android `cargo check` reached the new Rustls dependency graph but `ring` could not
  find an unsuffixed `aarch64-linux-android-clang`. The pinned NDK is installed and provides the
  API-31 compiler; rerun with Cargo's target-specific `CC` bound to that exact executable. This is
  a cross-toolchain setup failure, not Flux source or device-runtime evidence.
- The NDK-bound rerun reached `ring` assembly but Clang could not create a temporary file because
  its default temporary location is read-only in the managed workspace. Bind `TMPDIR=/tmp` for the
  repeat; this is a sandbox-path failure after successful compiler discovery, not a code failure.
- A fresh `cargo xtask check-android` reproduced the canonical-tooling gap: the command installed
  the Rust target but did not bind the pinned NDK compiler required by `ring`. Make both Android
  check/build paths validate the NDK and export the same API-31 compiler to Cargo and `cc`; install
  that exact NDK in CI rather than relying on a host-global unsuffixed compiler.
- The first post-audit `cargo fmt --all -- --check` reported layout-only drift in the edited fetch
  and asset modules. Let the already-running focused compiles finish, then apply canonical rustfmt
  before rerunning the same gates; no behavior is inferred from this formatting failure.
- The focused subscription compile passed all 18 tests but warned that the sanitized transport
  category was narrower than the sibling-visible `FetchError` variant carrying it. Match the two
  private-module visibility levels before strict Clippy; no public API or behavior changes.
- The first hardened B1.2 strict Clippy run rejected the safe digest formatter because it appeared
  after the fetch test module. Move the helper above `#[cfg(test)]` and rerun without suppressing
  `items_after_test_module`; runtime behavior is unchanged.
- The first B1.3 focused compile found one partial move in index rotation: the candidate index took
  the recovered active record before the index-persistence failure path could prune against the old
  references. Clone that single bounded record into the candidate index so the unchanged pre-commit
  index remains available to every rollback/cleanup path.
- The next B1.3 focused run passed 28 of 29 tests; its persistence-failure fixture expected an
  unreferenced candidate-path symlink to survive recovery, but secure pruning correctly removed the
  symlink before persistence and allowed publication. Use an unremovable directory at the managed
  object name to exercise rename failure; retain the separate orphan-symlink fixture for no-follow
  deletion evidence.
- The first B1.3 strict Clippy run identified one collapsible conditional and a 432-byte index enum
  variant; collapse the condition and box only the bounded valid-index variant. Semantic review at
  the same checkpoint found that the production validator rebuilt a pinned candidate `EngineSpec`
  without comparing its binary/launcher identities to the accepted base engine. Bind both digests
  explicitly and cover the path with a real pinned check fixture plus same-path binary drift.
- The first compile of that production validator fixture imported Sing-Box launch types from the
  `fluxd` root, which intentionally does not re-export them. Import the same public types directly
  from `flux-platform`; production code and persisted state were unaffected.
- The first combined cleanup-status patch no longer matched rustfmt's compact failure branches and
  changed nothing. Reapply it in smaller exact-context hunks; storage, validation, and revalidation
  failures now all preserve prior cleanup state and the result of the final orphan-prune attempt.
- The first B1.4.1 combined patch expected a selective compiler re-export, while
  `generation_engine_config::mod` uses a wildcard re-export. `apply_patch` rejected the complete
  patch before changing any file; reread the exact blocks and apply smaller hunks.
- The first B1.4.2 progress-record patch contained an empty update hunk, so `apply_patch` rejected
  it without changing any file. Reread the exact B1.4 block and apply this focused update.
- The first B1.4.2 formatter check found layout-only drift in the new subscription worker.
  `cargo fmt --all` applied canonical formatting before compilation; no behavior changed.
- The first B1.4.2 subscription compile stopped before tests because a local `EngineSpec` binding
  shadowed the helper used for the post-fetch source-stability check; it also exposed one unused
  prepared-refresh import. Rename the binding and remove the import, then rerun the same suite.
- The first B1.4.2 worker-test compile used an assertion message in `matches!`, which that macro
  does not accept. Replace it with an `Option::is_none` assertion; production code compiled.
- The first typed subscription-preparation test used `expect_err`, which would require the opaque
  successful publication to expose `Debug`. Match the result explicitly instead; production code
  compiled and the publication remains opaque.
- The first B1.4.3 coordinator run passed 50 lifecycle tests but its two-preparation process-writer
  fixture reused fixed Generation 1, whose first copied config was correctly read-only. Remove that
  fixture file before the synthetic second prepare; production allocates new Generation paths.
- The first B1.4.1 rustfmt check reported layout-only drift in two new subscription error arms.
  `cargo fmt --all` applied canonical formatting before the focused test run; no behavior changed.
- The first post-rollback B1.4.1 compile omitted the new canonical reconstruction helper from the
  Generation test module's explicit import list; both concurrently launched focused targets stopped
  at that same compile error. Add the import, apply rustfmt's two layout changes, and rerun the
  suites sequentially to avoid irrelevant Cargo artifact-lock waiting.
- The next focused compile passed the import and found the new reconstruction test supplied its
  existing `u16` fixture constant where the production interface correctly requires `NonZeroU16`.
  Convert the test value explicitly; production code was unaffected.
- The first Generation test run after compilation passed 46 of 47 tests. Exact canonical
  reconstruction preserved bytes, content digest, and listener, but correctly produced a different
  template-provenance digest because its input is the final canonical document rather than the
  pre-normalized template. Assert the binding properties consumed by the writer instead of equating
  those deliberately different provenance records.
- The first full B1.3 `fluxd` run passed the 266-test library and every integration target except
  one packaged-config assertion left at product schema 2 by B1.2. Rename the test away from its
  obsolete phase-one wording and require schema 3; the parser and packaged configuration already
  agreed on schema 3.
- The first B1.4.4 all-target check found that the test-only refresh-client channel needed an
  explicit `RefreshRequest` type, its error-kind re-export was needed only under `cfg(test)`, and
  the external CLI fixture needed the new `DaemonClient::update_subscription` method. Narrow the
  re-export, annotate the channel, and extend the fixture before rerunning the same check.
- Removing the obsolete subscription module dead-code fence made the first B1.4.5 strict Clippy
  run expose 15 inspection-only helpers plus one eight-argument preparation constructor. Gate the
  inspection types/getters to test builds, remove the unused snapshot conversion, and group the four
  related fetch bounds into `SubscriptionRefreshLimits` before rerunning without a broad allowance.
- The next strict Clippy compile showed that the validated subscription byte accessor is consumed by
  a coordinator assertion outside the subscription module. Restore that accessor under `cfg(test)`;
  it remains absent from the production interface.

### B1.1 Verification
- The pure compiler admits bounded Sing-Box outbound JSON and strict Base64-wrapped or plain URI
  lists for the frozen VMess, Shadowsocks, VLESS, Trojan, Hysteria 1/2, TUIC, SOCKS, HTTP, and
  Snell family. It filters infrastructure/legacy metadata entries, assigns deterministic duplicate
  tags, fills empty selectors, removes nulls, and binds the merged bytes to SHA-256 identities.
- `cargo test -p fluxd subscription --no-fail-fast` passed 5 subscription tests with 234 unrelated
  library tests filtered out on 2026-07-26.
- `cargo clippy -p fluxd --all-targets -- -D warnings` passed on 2026-07-26.

### B1.2 Execution Plan
- [x] B1.2.1: Bump the exact product configuration to schema 3, add a separately bounded
  `subscription.max_decoded_bytes`, and bind it into the Desired State identity and active docs.
- [x] B1.2.2: Implement a private synchronous `ureq` Adapter with explicit Rustls/WebPKI trust,
  no ambient proxy, HTTPS-only redirect handling, global timeout, content policy, and independent
  encoded/decoded body limits.
- [x] B1.2.3: Extract bounded remote binary rule sets, fetch/hash/deduplicate their bytes, rewrite
  the candidate to immutable local content-addressed paths, and reject unmanaged UI downloads.
- [x] B1.2.4: Add deterministic Adapter/adversarial fixtures and pass focused tests, rustfmt,
  strict Clippy, and the available Android cross-check without claiming device qualification.

### B1.2 Verification
- Schema 3 requires separate encoded and decoded subscription budgets and binds both into Desired
  State identity. The checked template no longer delegates external-UI retrieval to Sing-Box.
- The private `ureq 3.3.0` Adapter uses Rustls/static WebPKI roots, no ambient proxy, HTTPS at every
  redirect, no forwarded authorization, five redirects, one global request deadline, bounded
  headers, explicit 2xx/content policy, and inclusive raw plus decoded body limits.
- Template preflight rejects unmanaged/local/future-field assets and invalid URL policy before any
  request. Remote binary rule sets become exact Sing-Box local `type`/`tag`/`format`/`path` entries;
  every decoded response counts against the aggregate work budget even when stored bytes dedupe.
- Errors and Debug projections retain typed categories, sizes, and digests without subscription or
  rule-set URLs, response header values, node bodies, or transport-source strings.
- `cargo test -p flux-core --test config --no-fail-fast`: 35 passed.
- `cargo test -p fluxd subscription --no-fail-fast`: 18 passed.
- `cargo test -p xtask --no-fail-fast`: 36 passed, 4 intentional fixtures ignored.
- Strict Clippy passed for `fluxd` and `flux-core`; rustfmt and `git diff --check` passed.
- `TMPDIR=/tmp cargo xtask check-android` passed through `ring`, Rustls, and `fluxd` with pinned NDK
  `27.3.13750724`/API 31. CI now installs and binds that NDK. This is compile evidence only.
- Static WebPKI roots do not inherit Android user, enterprise, distrust, or revocation policy. No
  WSA TLS run or physical ARM64 qualification is claimed.

### B1.3 Execution Plan
- [x] B1.3.1: Add descriptor-relative bounded enumeration and unlink operations for Module-owned
  snapshot directories without following symbolic-link ancestors or entries.
- [x] B1.3.2: Implement a strict bounded active/predecessor index, content-addressed config and
  asset loading, complete digest revalidation, corrupt-active fallback, and empty recovery when no
  known-good snapshot survives.
- [x] B1.3.3: Persist candidate objects before a descriptor-pinned Sing-Box check, reverify every
  candidate object afterward, atomically rotate the index only on success, and prune unreferenced
  objects without turning post-commit cleanup into a false publication failure.
- [x] B1.3.4: Add deterministic validation and storage-fault fixtures, pass focused tests, rustfmt,
  strict Clippy, diff hygiene, and the available Android cross-check without claiming runtime
  qualification.

### B1.3 Verification
- The private store exposes only serialized `recover` and `publish` operations plus its exact asset
  root. A strict schema-1 index retains one active and at most one predecessor; configs and rule
  sets are addressed by lowercase SHA-256 names and bounded to 16 MiB and 64 MiB aggregate.
- Descriptor-anchored enumeration uses an already-open no-follow directory through
  `/proc/self/fd`; removal uses `unlinkat` against the same securely traversed parent and syncs the
  directory. Managed orphans and interrupted-write names are pruned without following entries;
  unknown names are preserved and cleanup failure remains an explicit pending state.
- Recovery rehashes every referenced config and asset, rebuilds and verifies the complete prepared
  snapshot digest and local rule-set bindings, promotes a verified predecessor when active is
  corrupt, drops only a corrupt predecessor, and publishes an honest empty index if neither
  survives. A future index schema is preserved rather than erased.
- Publication persists unreferenced objects first, checks the exact final config and asset paths,
  binds the previously accepted Sing-Box binary/launcher identities, runs `sing-box check` through
  pinned descriptors, and reloads every object afterward. Only then can one atomic index write
  rotate history; persistence, validation, or post-check mutation failures preserve the recovered
  active index and report orphan-cleanup state.
- `cargo test -p fluxd subscription --no-fail-fast`: 32 passed.
- `cargo test -p fluxd --no-fail-fast`: 352 passed, 4 privileged namespace fixtures intentionally
  ignored. The run also corrected one stale schema-2 packaged-config assertion from B1.2.
- `cargo clippy -p fluxd --all-targets -- -D warnings`, `cargo fmt --all -- --check`, and
  `git diff --check` passed. No `cargo-audit` or `cargo-deny` executable is installed locally.
- `TMPDIR=/tmp cargo xtask check-android` passed with the pinned NDK/API-31 toolchain. This is
  compile evidence only; no WSA or physical ARM64 runtime qualification is claimed.

### B1.4 Execution Plan
- [x] B1.4.1: Make subscription output an exact canonical TPROXY engine artifact and add a
  conditional store rollback operation that restores the predecessor or honest empty state when a
  published candidate cannot become the running Generation.
- [x] B1.4.2: Implement one bounded refresh worker that owns configuration/URL/template loading,
  synchronous fetch, compilation, validation, store publication, periodic timing, and final manual
  outcomes; keep all network work off the serialized legacy writer.
- [x] B1.4.3: Let `ProcessRuntimeWriter` prepare from the exact verified subscription artifact,
  consume completed worker outcomes from `RuntimeCoordinator::maintain`, and acknowledge activation
  only after the existing reload/rollback path settles.
- [x] B1.4.4: Add the manual `fluxd subscription update` socket/CLI path with explicit updated,
  unchanged, disabled, deferred, busy, and failed outcomes; do not report queued work as complete.
- [x] B1.4.5: Add focused worker, store, writer, coordinator, protocol, and CLI tests, then pass
  rustfmt, strict Clippy, the complete `fluxd` suite, diff hygiene, and the Android cross-build.

### B1.4 Decisions
- The store index remains the durable validated-snapshot authority. A candidate is published before
  Generation preparation so every engine input and local asset path is durable; a failed prepare or
  reload sends a rejection acknowledgement to the sole store owner, which conditionally restores
  the exact prior index before the manual operation completes.
- `ProcessRuntimeWriter` retains only the accepted validated engine bytes/digests. Candidate
  preparation does not replace that retained source until activation succeeds, so ordinary reloads
  cannot silently retry a rejected candidate.
- Startup may perform one bounded refresh on the dedicated worker only when subscription intent is
  explicitly enabled and no recoverable snapshot exists. A recovered snapshot avoids startup
  networking; a disabled subscription never fetches.
- B1.4 explicitly supports the packaged root-owned engine launch. Non-root subscription activation
  remains rejected until the content-addressed store has securely applied traversal/read modes for
  `busybox setuidgid`; this avoids claiming path access that the current `0700`/`0600` store cannot
  provide.
- Production networking remains on `ProcessRuntimeWriter`; this phase changes only its canonical
  engine input and does not activate native xtables/RPDB mutation or create Android authority.
- Keep protocol version 3 for the additive `subscription_update` request/response pair. The command
  is mutating, so it uses the existing capability gate and peer/request-ID result cache; every worker
  error category maps to a fixed rejection code and incoherent optional metadata fails closed.
- A bootstrap-published snapshot remains guarded inside the sole store-owning worker until initial
  runtime admission explicitly accepts it. Admission failure rejects it synchronously, while worker
  startup failure or premature shutdown triggers the same exact-digest conditional rollback on drop.

### B1.4 Final Verification
- `cargo test -p fluxd subscription --no-fail-fast`: 49 focused tests passed.
- `cargo test -p fluxd --test startup_reconciliation_admission --no-fail-fast`: 9 passed.
- `cargo test -p fluxd --test daemon_shutdown_signal --no-fail-fast`: 1 passed.
- `cargo test -p fluxd --no-fail-fast`: the 280-test library target passed with 4 privileged tests
  ignored, and every integration target passed.
- `cargo clippy -p fluxd --all-targets -- -D warnings`, `cargo fmt --all -- --check`, and
  `git diff --check` passed.
- `TMPDIR=/tmp cargo xtask check-android` passed with the pinned NDK/API-31 toolchain. This is
  compile evidence only; neither WSA nor physical ARM64 runtime qualification is claimed.

### B1.5 Execution Plan
- [x] B1.5.1: Remove every runtime reference to `scripts/updater.sh` while retaining the file only
  in the development bridge package as a frozen comparison oracle until B3.
- [x] B1.5.2: Add shell regression coverage proving both Rust-owned preparation and the retained
  legacy rollback path never invoke or require the updater.
- [x] B1.5.3: Reconcile README, development guide, blueprint, technical specification, project
  review, and canonical roadmap with the production-connected Rust subscription path.
- [x] B1.5.4: Run focused shell/Rust verification, strict formatting/linting, Android cross-build,
  complete repository CI, and final diff review.

### Status
**B1 complete on 2026-07-26; B2 inventory starting** - no runtime source names or invokes the shell
updater, and both ownership modes consume only an already-published canonical engine config. The
bridge package still carries the frozen updater artifact for B3 deletion. Active documentation now
describes the Rust worker, store, reload/rollback handshake, manual command, root-engine limitation,
static-root trust boundary, and compile-only Android evidence.

### B1.5 Final Verification
- `sh -n scripts/init scripts/lib tests/shell/dispatcher_fluxd_mode.sh`: passed.
- `tests/shell/run-dispatcher-tests.sh`: passed, including the missing-updater legacy fixture.
- `cargo test -p fluxd subscription --no-fail-fast`: 49 focused tests passed.
- `cargo clippy -p fluxd --all-targets -- -D warnings` and `cargo fmt --all -- --check`: passed.
- `TMPDIR=/tmp cargo xtask check-android`: passed with the pinned NDK/API-31 toolchain.
- `TMPDIR=/tmp cargo xtask ci`: passed; the `fluxd` library target reported 280 passed and 4
  privileged ignores, every integration target passed, and `xtask` reported 36 passed with 4
  intentional fixture ignores.
- `git diff --check`: passed with only existing CRLF normalization warnings.

## Execution: P0-B2 Direct Control, Observation, Diagnostics, And Cleanup

### Goal
Make `fluxd` the only runtime/diagnostic command surface and move file observation plus bounded
offline cleanup behind Rust interfaces, without changing the fenced networking writer or claiming
device authority.

### Priorities
- P0: Inventory every runtime invocation and behavior in `scripts/fluxctl`, `scripts/flux-event`,
  `flux_service.sh`, dispatcher preview paths, status/log diagnostics, and uninstall cleanup.
- P0: Land direct Rust commands and typed protocol/offline contracts before removing any shell
  wrapper or observation path.
- P0: Preserve the one serialized mutation scheduler, daemon-lease exclusion for offline work,
  Generation ownership, fail-open cleanup, bounded I/O, and honest completed/deferred outcomes.
- P1: Move config/disable observation into the existing daemon reactor without adding a second
  watcher process or unbounded queue.
- P2: Defer package-profile deletion to B3 and native networking selection to C2/Gate 1.

### Phases
- [x] B2.0: Map the complete remaining shell command/event/diagnostic/cleanup call graph and freeze
  the smallest direct Rust interfaces plus removal order.
- [x] B2.1: Complete direct `fluxd` lifecycle, status, bounded logs/diagnostics, and explain/preview
  commands with focused CLI/protocol tests.
- [x] B2.2: Attach config/disable observation to the daemon reactor with typed coalescing and remove
  the runtime `inotifyd`/`scripts/flux-event` path after parity tests.
- [x] B2.3: Implement daemon-exclusive bounded offline recovery/cleanup and prove exact owned-state
  absence without shell rule reconstruction.
- [x] B2.4: Remove runtime use of `scripts/fluxctl` and superseded diagnostic/preview paths, reconcile
  active documentation, and pass focused plus repository-wide verification.

### Status
**B2 complete on 2026-07-26; B3 next** - `fluxd` is the only supported runtime and diagnostic
command surface, native file observation and daemon-exclusive offline cleanup are connected, and
the forwarding CLI wrapper plus cache-mutating shell preview path are gone. The no-caller event
adapter remains packaged for the B3 profile transition, and production networking remains on the
fenced bridge writer.

### B2.0 Frozen Interfaces And Removal Order
- `fluxd start|stop|restart|reload|resync` are direct aliases for the existing authenticated
  `control` operation. They add no protocol action or lifecycle state.
- `fluxd status [--json]` remains the authoritative live snapshot. `diagnose`, bounded `logs`, and
  explain/preview are read-only same-effective-user socket operations with bounded response types;
  they do not run `ip`, `iptables-save`, shell, or mutate shared caches.
- Explain compiles current schema-3 Desired State through Rust and reports exact identities,
  resource use, assumptions, and deferred prerequisites. It is explicitly non-authorizing and
  cannot create a Generation, writer lease, cache-valid marker, or kernel command.
- B2.2 observes the configured `flux.toml`, engine template, subscription URL file, and module
  `disable` state inside `DaemonReactor`. It reconciles current state after watch loss/rename and
  submits typed facts into the existing bounded control scheduler. The raw socket `event` surface
  remains compatibility-only with no runtime caller until B3 deletes its packaged adapter.
- B2.3 offline recovery/cleanup first proves the daemon lease absent, then consumes only durable
  ownership records and exact owner absence checks. It does not reconstruct rules or infer managed
  objects from live table names.
- Removal order is: land/test Rust read-only commands; switch callers to direct lifecycle aliases;
  attach/test internal observation; delete `inotifyd` supervision and the `scripts/flux-event`
  invocation; land/test offline cleanup and uninstall invocation; remove `scripts/fluxctl` and
  remaining runtime call sites; delete no-caller bridge package artifacts only in B3.

### B2.1 Verification
- Direct `fluxd start|stop|restart|reload|resync` aliases reuse the existing authenticated control
  operation. Same-user protocol-v3 requests now provide authoritative diagnostics, fixed
  `runtime`/`daemon`/`engine` logs bounded to 1,000 lines and a 256 KiB source tail, and a
  non-authorizing Desired State explanation.
- Engine-log resolution uses a strict lightweight manifest summary. It validates every manifest
  field but does not hash the engine binary, launcher, or config merely to locate a log; runtime
  preparation still uses full `EngineManifest::load_prepared` artifact inspection.
- Explain compiles schema-3 configuration and canonical engine JSON in memory, reports temporary
  bridge representability, and publishes no Generation, cache, receipt, or writer lease. It does
  not claim resolved Android package UIDs, live Network Inventory, or a complete Capture Program.
- `scripts/fluxctl` contains no status, diagnostic, preview-cache, arbitrary-file tail, or lifecycle
  policy; it forwards supported arguments to `fluxd`. Package deletion remains ordered after
  observation and offline-cleanup migration.
- Focused verification passed formatting, all-target compilation, strict Clippy, 6 inspection tests,
  10 manifest tests, 2 control-CLI tests, 12 daemon-CLI tests, shell syntax, and the isolated
  delegation suite. The full `fluxd` suite passed 285 library tests with 4 expected privileged
  ignores plus every integration target; the pinned Android/API-31 cross-build and
  `TMPDIR=/tmp cargo xtask ci` both passed. No WSA or physical ARM64 runtime evidence is claimed.

### B2.2 Execution Plan
- [x] B2.2.1: Add a bounded nonblocking inotify Module that watches the parent directories of the
  Desired State, selected engine template, selected subscription URL file, and module `disable`
  entry; coalesce raw records into configuration-input and disable-state facts.
- [x] B2.2.2: Register that Module with `DaemonReactor`, recover from queue overflow, watch
  invalidation, and directory replacement by rereading current state and reinstalling watches on a
  bounded retry/identity-check deadline.
- [x] B2.2.3: Add a capacity-bounded coalescing ingress to the existing `LegacyControlBridge`
  worker so the reactor never waits for writer completion and no second watcher/dispatcher thread
  is introduced.
- [x] B2.2.4: Wire only mutation-allowed daemon profiles, close the startup observation gap with an
  initial authoritative reconciliation, and retain the last valid dynamic watch set while an
  edited `flux.toml` is invalid.
- [x] B2.2.5: Add parser/coalescing/live rename and reinstallation tests, remove runtime `inotifyd`
  supervision plus `scripts/flux-event` invocation, reconcile active docs, and run focused/full,
  Android cross-build, and repository verification without claiming WSA or ARM64 runtime evidence.

### B2.2 Decisions
- File observation exposes only two typed facts. Raw inotify masks, watch descriptors, cookies,
  paths, and retry state remain inside `flux-platform`; the daemon rereads authoritative files.
- The existing serialized legacy writer remains the sole mutation scheduler. A shared two-fact
  coalescer plus one best-effort wake request absorbs queue pressure without blocking the reactor or
  adding a thread; the worker drains pending facts after every queued request.
- Parent-directory watches preserve atomic-replacement visibility. Periodic descriptor-identity
  checks cover replacement of a watched directory through an ancestor, while missing watches retry
  without terminating an otherwise healthy daemon.
- Runtime-invalid `disable` entries are treated as effectively disabled and logged. Runtime-invalid
  Desired State keeps the last valid dynamic watch set while still queuing a reload that fails
  closed through the existing Generation rollback path.

### B2.2 Errors Encountered
- The first plan-only patch used a wrapped B2.1 sentence as its anchor and did not apply. Re-read
  the file tail and inserted this section against the exact final verification paragraph; no source
  file was affected.
- The first combined architecture-documentation patch assumed the blueprint's delivered-B2.1
  paragraph also appeared verbatim in the technical specification. `apply_patch` rejected the
  complete patch without changing either file; the two documents were patched against their actual
  control/event sections.
- The first strict B2.2 Clippy gate rejected `bool::then` inside one `filter_map` in the new file
  observer. Replace it with the equivalent `filter` plus `map` iterator shape and rerun the same
  strict gate; no observation behavior changes.
- The first B2.2 Android cross-build found that Android libc types the `inotify_rm_watch` watch
  descriptor as `u32` while Linux types it as `c_int`. Add a checked Android-only conversion at the
  syscall boundary, preserve the internal signed event/watch identity, and rerun host plus Android
  gates.
- Two initial patch encodings for that Android portability fix were rejected before editing: the
  first accidentally scoped the plan-log hunk to the source file, and the second contained a stray
  hunk marker before the file boundary. Reapply with explicit valid source and plan sections.

### B2.2 Verification
- `cargo test -p flux-core --test legacy_control_bridge --no-fail-fast`: 11 passed.
- `cargo test -p flux-platform --test reactor --no-fail-fast`: 16 passed, including atomic
  replacement, dynamic retargeting, and ancestor-directory replacement recovery.
- `cargo test -p fluxd subscription --no-fail-fast`: 52 focused tests passed.
- `cargo test -p fluxd --test daemon_shutdown_signal --no-fail-fast -- --nocapture`: the live
  create/remove-disable, atomic-template-reload, and SIGTERM lifecycle test passed.
- `cargo test -p fluxd --no-fail-fast`: 288 library tests passed, 4 privileged tests ignored, and
  every integration target passed.
- Shell syntax and `tests/shell/run-dispatcher-tests.sh`: passed.
- Strict rustfmt and all-target `-D warnings` Clippy for `flux-core`, `flux-platform`, and `fluxd`:
  passed.
- `TMPDIR=/tmp cargo xtask check-android` and `TMPDIR=/tmp cargo xtask ci`: passed.
- `git diff --check`: no whitespace errors; only existing CRLF normalization warnings.

### B2.3 Execution Plan
- [x] B2.3.1: Add one persistent `run/fluxd.lease` regular file opened through no-follow
  descriptor-relative ancestry and guarded by nonblocking exclusive `flock`; make `fluxd daemon`
  hold it from before startup recovery through complete reactor shutdown.
- [x] B2.3.2: Add exactly `fluxd cleanup --offline` as a pre-socket command. While holding the same
  lease, run the existing bounded `startup-recover` effect Adapter and return stable complete,
  busy, usage, or failed CLI outcomes without inspecting PID/socket/watchdog records.
- [x] B2.3.3: Prove daemon/offline mutual exclusion, stale-hint independence, symlink/nonregular/
  unsafe-path rejection, lease retention throughout recovery, post-failure release, and honest
  recovery failure through focused tests.
- [x] B2.3.4: Add module `uninstall.sh` as policy-free delegation: use the serialized online `stop`
  path when a daemon answers, otherwise invoke `cleanup --offline`; bind it into both checked
  package profiles and installer permissions.
- [x] B2.3.5: Reconcile active documentation and pass focused/full Rust, shell/package, strict
  rustfmt/Clippy, Android cross-build, repository CI, and diff gates without claiming runtime
  device qualification.

### B2.3 Decisions
- `run/fluxd.lease` is persistent and is never interpreted as liveness. Only the kernel lock is
  authoritative, so stale `fluxd.pid`, `fluxd.sock`, watchdog directories, or the unlocked lease
  inode neither authorize nor block cleanup.
- The lease is acquired before capability collection or startup recovery for every daemon profile.
  This closes the daemon-start/offline-cleanup race even while the control socket is absent and
  also makes a settled read-only daemon visible as an active owner.
- `DaemonLease::drop` explicitly unlocks its open-file description before closing the owning
  descriptor. This prevents a concurrent pre-`exec` fork duplicate from extending lease lifetime;
  `O_CLOEXEC` still prevents the descriptor from surviving successful `exec`.
- The offline command is exactly `fluxd cleanup --offline`: success means the existing recovery
  Adapter established its exact terminal postcondition, not that Rust inferred whether work was
  necessary. Exit `75` means daemon active/starting, `2` means invalid syntax, and `1` means the
  lease or bounded recovery failed. `recover --offline` remains unimplemented rather than adding a
  second alias before salvage semantics differ from cleanup.
- B2.3 reuses `ProcessPhaseDispatcher::StartupRecover`; it does not select
  `NativeRuntimeWriter`, reconstruct rules, scan live table names, or weaken the Gate 1 device
  boundary. The Adapter remains a B3 bridge artifact.
- Platform uninstall glue may choose between Rust online and offline entry points, but it contains
  no PID interpretation, networking commands, rule identities, or cleanup implementation.

### B2.3 Errors Encountered
- The first focused lease test expected an unsafe `child/../` path to be rejected before I/O, but
  traversal reached the missing `child` first and returned an I/O category. Pre-scan every parent
  component for `..` before opening any descriptor; the unchanged hostile-path test then passed.
- The first strict B2.3 Clippy run found that the integration fixture's safety comment preceded an
  `assert_eq!` invocation rather than the nested `unsafe` expression. Bind the documented `flock`
  result before asserting it; production code and lease behavior are unchanged.
- The first repository CI run exposed a parallel-process lease lifetime race: the recovery-failure
  test saw `Busy` after the Rust lease value dropped because a concurrently forked child could
  briefly retain the same open-file description before `exec` applied `O_CLOEXEC`. Add a
  deterministic duplicated-descriptor regression, explicitly issue `LOCK_UN` in `DaemonLease`
  drop, and rerun the focused, strict, Android, and repository gates successfully.

### B2.3 Verification
- `cargo test -p fluxd offline_cleanup --no-fail-fast`: 7 focused tests passed, including the
  deterministic fork-inherited open-file-description regression.
- `cargo test -p fluxd --test offline_cleanup_cli --no-fail-fast`: 2 binary/cross-process tests
  passed.
- Strict all-target `fluxd` and `xtask` Clippy plus repository rustfmt passed.
- Shell syntax, `tests/shell/run-dispatcher-tests.sh`, `tests/shell/run-fluxctl-tests.sh`, and
  `tests/shell/run-installer-tests.sh` passed; installer coverage now proves online stop, exact
  offline fallback, and exit-75 propagation.
- `TMPDIR=/tmp cargo xtask check-android` passed with the pinned NDK/API-31 toolchain after the
  explicit-unlock fix.
- `TMPDIR=/tmp cargo xtask ci` passed: the `fluxd` library target reported 295 passed with 4
  privileged ignores, every integration target passed, and `xtask` reported 36 passed with 4
  intentional fixture ignores.
- `git diff --check` reported no whitespace errors; only existing CRLF normalization warnings
  remain. No WSA ADB target or physical ARM64 device was available, so Android evidence is
  cross-compile only and no runtime, native-networking, device, or release qualification is claimed.

### B2.4 Execution Plan
- [x] B2.4.1: Delete `scripts/fluxctl`, remove its `scripts/lib` identity and legacy-init integrity
  dependency, and retire the isolated wrapper-delegation suite plus CI/documentation invocations.
- [x] B2.4.2: Remove the unreachable dispatcher `cache-preview` command and its shared-cache mutation
  tests; retain direct non-publishing Rust `rules-preview`/`preview` coverage.
- [x] B2.4.3: Remove the wrapper from the development bridge and Rust-only forbidden package sets,
  update exact manifest/`xtask` inventory assertions, and keep `scripts/flux-event` packaged only as
  a no-caller B3 artifact.
- [x] B2.4.4: Reconcile active English/Chinese and architecture/development documentation, then pass
  focused CLI/shell/package, strict Rust, Android cross-build, repository CI, stale-reference, and
  diff gates without changing writer selection or claiming device qualification.

### B2.4 Decisions
- The supported command surface is the Rust `fluxd` binary. B2.4 does not add a second executable,
  symlink, hardlink, protocol action, or shell alias merely to retain the obsolete `fluxctl` name.
- The raw `event` protocol and packaged `scripts/flux-event` file remain compatibility-only with no
  runtime caller. B3 deletes that and the other bridge artifacts as one package-profile transition.
- Dispatcher `cache-preview` is removed rather than preserved as a private fallback: direct Rust
  explain/preview is non-authorizing and in-memory, while the shell branch mutates shared caches and
  has no caller after B2.1.

### B2.4 Errors Encountered
- The first exact `xtask` package-contract command used an incomplete test filter and selected zero
  tests. Rerun with the full test name
  `tests::checked_package_contract_names_the_exact_bridge_difference`; the exact test passed.

### B2.4 Verification
- Shell syntax, `tests/shell/run-dispatcher-tests.sh`, and
  `tests/shell/run-installer-tests.sh`: passed. The dispatcher suite includes direct-entry rejection;
  installer coverage retains exact online-stop and offline-cleanup delegation.
- `cargo test -p fluxd --test daemon_cli --test control_cli --test offline_cleanup_cli
  --no-fail-fast`: 16 passed, 0 failed.
- `cargo test -p xtask --no-fail-fast`: 36 passed, 0 failed, 4 intentional fixture ignores; the
  exact package contract is 28 bridge-required, 13 Rust-only required, and 15 forbidden paths.
- Strict all-target `fluxd`/`xtask` Clippy and repository rustfmt passed.
- `TMPDIR=/tmp cargo xtask check-android` passed with the pinned NDK/API-31 toolchain.
- `TMPDIR=/tmp cargo xtask ci` passed: the `fluxd` library target reported 295 passed with 4
  privileged ignores, every integration and doc-test target passed, and `xtask` reported 36 passed
  with 4 intentional fixture ignores.
- Stale-reference checks found no live `FLUXCTL_SCRIPT`, wrapper test, wrapper file, or shell preview
  implementation. Remaining mentions are removal statements or explicitly historical records.
- No WSA ADB target or physical ARM64 device was available. Android evidence remains compile-only;
  runtime behavior, native-networking qualification, physical-device authority, and release
  qualification are unclaimed.

## Execution: P0-B3 Rust-Only Package Profile

### Goal
Make the Rust-only package contract independently buildable and structurally verifiable while the
development bridge remains the production writer rollback boundary until Gate 1.

### Priorities
- P0: Restore the exact rooted x86_64 WSA mechanism lane after the Rust HTTP/TLS dependency added a
  native `ring` build, without treating WSA as ARM64 or release authority.
- P0: Make every packaged Android ELF explicitly 16 KB-page compatible and reject any noncompliant
  `PT_LOAD` alignment before package verification can succeed.
- P0: Machine-check that Rust-only platform glue contains no networking mutation, configuration
  compiler, subscription, or cleanup policy beyond direct `fluxd` delegation.
- P1: Exercise exact Rust-only staging/inventory rejection with no legacy runtime artifacts while
  retaining the active development bridge unchanged.
- P2: Keep provenance/SBOM/signing promotion failing until exact third-party artifacts and physical
  Android evidence exist; do not manufacture placeholder release metadata.

### Phases
- [x] B3.0: Export the complete x86_64 Android native compiler contract, add a regression at the
  actual Cargo-command seam, and rerun the exact rooted WSA local-OUTPUT TPROXY checkpoint with
  bounded cleanup.
- [x] B3.1: Add explicit NDK-r27 16 KB linker compatibility flags to Android builds and extend ELF
  verification plus fixtures to require every non-empty `PT_LOAD` segment to align to at least
  `2**14`.
- [x] B3.2: Add Rust-only platform-glue source policy and hostile fixtures for forbidden networking,
  subscription, configuration-compilation, and cleanup implementation.
- [x] B3.3: Prove exact 13-path Rust-only staging and exact legacy-artifact rejection without
  promoting its `failing-until-complete` status or deleting the still-active bridge.
- [x] B3.4: Reconcile active documentation, run focused/full/Android/WSA/diff gates, and create
  periodic local Conventional Commit checkpoints without pushing.

### Status
**B3 complete on 2026-07-26 through the structural package gate** - the exact Rust-only stage,
platform-glue policy, Android ELF contract, full repository gates, and connected WSA mechanism
checkpoint pass. Production remains on the development bridge and `ProcessRuntimeWriter`; the next
release-authorizing work is C1/C2 on a rooted physical ARM64 target.

### Decisions
- WSA is development mechanism evidence only. It cannot construct physical Android ARM64 planning,
  activation, coexistence, device, or release authority.
- B3 does not remove or weaken `ProcessRuntimeWriter`, the bridge profile, standalone `addrsyncd`, or
  shell networking artifacts while they remain the production rollback boundary.
- The Rust-only verifier remains `failing-until-complete` until Lane C and Gate 1 pass. B3 improves
  its structural contract; it does not bypass missing provenance or device evidence.
- Create a local checkpoint after each independently verified B3 slice. Do not push without a
  separate user request.
- Follow the current Android compatibility guide for raw NDK-r27 Cargo links: pass both
  `max-page-size=16384` and `common-page-size=16384`. The final structured ELF inspection, not the
  presence of either flag, is authoritative.
- Apply the platform-glue source policy only to the Rust-only profile. Require exact installation,
  daemon, and uninstall delegation markers; reject networking mutation, subscription retrieval,
  configuration compilation, owned-state cleanup, legacy runtime paths, and dynamic shell command
  construction without weakening or rewriting the active bridge.
- Override only `customize.sh` and `flux_service.sh` below `packaging/rust-only/`. The shared update
  binary and Rust-delegating uninstaller already satisfy the final policy and should not be copied
  into a second source tree.
- Keep the Rust-only installer fresh-install-only in B3.3. It may place the reviewed package payload
  but must refuse an existing `/data/adb/flux` tree rather than migrate or delete bridge/runtime
  state in shell; the profile remains non-releasable until the Rust-owned cutover/migration gate.

### Errors Encountered
- Windows Computer Use initialization failed before UI automation because the Node runtime rejected
  the WSL workspace URI `file:///mnt/d/Github/Flux` as non-local. Use installed AppX/ADB command
  surfaces for WSA and retain the exact error as a tooling limitation, not a device result.
- An exploratory `cargo xtask android-canary --help` used a nonexistent command name and returned
  usage error `1`. `cargo xtask help` identified the exact checked command; no repository or device
  state changed.
- The first exact WSA canary reached the x86_64 Cargo build but `ring`/`cc-rs` failed because
  `CC_x86_64_linux_android` was unset and `x86_64-linux-android-clang` was not on `PATH`. No remote
  test directory was created; add a command-environment regression and export the pinned compiler.
- The first post-fix WSA retry found that the subsystem had automatically stopped, so the explicit
  serial was absent and port 58526 refused reconnection. Relaunch the installed WSA App entry,
  reconnect the same Windows ADB serial, and rerun; this was external target state, not a code
  regression.
- The first B3.1 focused compile declared crate-root constants as `pub(super)`, which Rust rejects
  because the crate root has no parent module. Plain private constants remain visible to the child
  WSA module and fixed the compile without widening the interface.
- One B3.1 test patch targeted the pre-rustfmt shape of the Android environment regression and
  matched nothing. Reading the exact formatted block and reapplying the scoped hunk resolved it.
- The first independent WSA cleanup probe passed a compound `if` expression through Windows ADB;
  argument reconstruction truncated the `su -c` program and Android `sh` rejected it. An exact
  single-command `ls` probe returned `No such file or directory`, and a separate bounded `find`
  returned no private-prefix directories.
- The first strict B3.1 Clippy pass rejected an explicit lifetime on the Android Cargo-environment
  helper as needless. Eliding only that lifetime cleared strict all-target Clippy; the subsequent
  rustfmt check requested its canonical one-line signature, which `cargo fmt -p xtask` applied.
- The first B3.2 `xtask` suite exposed a punctuation-sensitive `ping` delegation marker in the
  synthetic minimal uninstall fixture, which also made the complete bridge fixture fail before its
  expected Rust-only forbidden-path check. Parse required commands as exact normalized shell tokens
  so punctuation cannot change the policy result.
- That B3.2 run also tried to validate every live bridge source directly and reached the unrelated
  data-style `scripts/config` entry, which intentionally has no shebang. Copy only the four active
  platform-glue sources into an otherwise canonical bridge fixture to prove their bridge admission
  and Rust-only rejection without widening this gate to legacy script semantics.
- The first B3.2 checkpoint staging command could not create `.git/index.lock` because the managed
  sandbox mounted Git metadata read-only. No file was staged; rerun the same exact five-file `git
  add` with Git-metadata write authority, then verify the cached diff before committing locally.
- The first B3.3 strict Clippy run found one needless borrow of the already borrowed `fluxd_source`
  path at the extracted post-build staging seam. Remove only the redundant `&`; shell tests and the
  48-test `xtask` suite had already passed with unchanged behavior.
- The first combined B3.4 documentation patch missed one wrapped roadmap sentence and was rejected
  before changing any file. Re-read the exact B1/B2 contexts and apply the reconciliation as scoped
  per-file patches.

### B3.0 Verification
- The command-environment regression failed before the fix on the absent
  `CC_x86_64_linux_android` value, then passed after the pinned NDK compiler was exported for native
  build scripts.
- The exact rooted WSA command passed twice after reconnection. It validated WSA
  2407.40000.4.0, Android 13 / SDK 33, x86_64, the exact fingerprint and boot ID, executed the one
  ignored local-OUTPUT TPROXY checkpoint, and independently removed each private remote directory.
- Android-target test imports are gated to their actual Linux-only fixture, leaving the final WSA
  cross-build warning-free.
- `cargo test -p xtask --no-fail-fast`: 37 passed, 0 failed, 4 intentional fixture ignores.
- Strict all-target `fluxd`/`xtask` Clippy, repository rustfmt, and
  `TMPDIR=/tmp cargo xtask check-android` passed.
- No physical ARM64 target was attached. The ARM64 result is cross-build evidence and the WSA result
  is mechanism evidence; neither qualifies production networking or release authority.

### B3.1 Verification
- The pre-change NDK-r27d ARM64 release build succeeded but all four `PT_LOAD` headers had
  `p_align=0x1000`, proving that the pinned toolchain did not provide 16 KB compatibility by
  default.
- Primary Android, NDK r27d, LLD, Bionic, AOSP, and Cargo sources are recorded in
  `docs/research/android-16kb-elf-compatibility-2026-07.md`. They require both linker options for
  raw r27 Cargo links and inspection of every load segment rather than only the first.
- The final ARM64/API-31 release cross-build passed the in-process verifier. `llvm-readelf -lW`
  independently reported four `PT_LOAD` headers, each with `p_align=0x4000`.
- `cargo test -p xtask --no-fail-fast`: 39 passed, 0 failed, 4 intentional fixture ignores. The
  hostile matrix accepts 16/64 KiB and rejects 8 KiB plus a later 4 KiB segment after a compliant
  first segment.
- WSA reported `getconf PAGE_SIZE=4096`. The exact rooted x86_64 local-OUTPUT TPROXY checkpoint
  passed 1 test with 277 filtered, its final ELF exposed four `0x4000` load segments, and exact plus
  prefix-wide probes independently found no remote test directory afterward.
- Strict all-target `xtask` Clippy, repository rustfmt, the pinned ARM64/API-31 `check-android`,
  `git diff --check`, the new research-index target, and the scoped high-confidence secret scan
  passed. Existing CRLF normalization notices remain warnings only.
- No physical ARM64 or 16 KB Android runtime target was available. ARM64 remains cross-build and
  structural evidence; WSA remains 4 KB x86_64 mechanism evidence.
- Local checkpoint `585a57f` records the complete verified rewrite through B3.1; it was not pushed.

### B3.2 Verification
- The source-policy gate runs only for `rust-only` and inspects exactly the four manifest-required
  platform-glue paths. Each source is bounded to 128 KiB, non-NUL ASCII, normalized for case,
  whitespace, CRLF, and shell line continuations, and checked for exact delegation markers/tokens.
- A compliant minimal fixture passes. Eight hostile cases reject `iptables-restore`, `curl`, `jq`,
  `awk`, `/data/adb/flux/run/active_runtime`, `/data/adb/flux/scripts/lib`, `eval`, and `sh -c`;
  line-continuation variants prove the normalizer cannot be bypassed by splitting the command.
- The four active shared bridge glue files still pass bridge content validation and fail when
  evaluated under Rust-only policy. No bridge source, writer selection, or package profile status
  changed.
- `TMPDIR=/tmp cargo test -p xtask --no-fail-fast`: 42 passed, 0 failed, 4 intentional fixture
  ignores. `TMPDIR=/tmp cargo clippy -p xtask --all-targets -- -D warnings` passed.
- Repository rustfmt, `git diff --check`, and the scoped high-confidence secret scan passed.

### B3.3 Verification
- Only `customize.sh` and `flux_service.sh` resolve from `packaging/rust-only/`; the shared Magisk
  update binary and Rust-delegating `uninstall.sh` remain single authoritative sources. Staging and
  later source-byte verification call the same static resolver.
- The extracted post-build staging seam uses the real checked source tree in tests. Bridge produces
  exactly 28 paths from the root sources; Rust-only produces exactly 13 paths and its two staged
  overrides differ from the active bridge files.
- Each of the exact 15 Rust-only forbidden paths was injected independently and rejected by name.
  Tampering staged Rust-only `customize.sh` failed against
  `packaging/rust-only/customize.sh`; restoring its bytes passed.
- The Rust-only installer is deliberately fresh-install-only: it stages/publishes only the reviewed
  `bin/` and `conf/` payload, installs module metadata/service/uninstaller, and refuses an existing
  `/data/adb/flux` instead of migrating or deleting bridge/runtime state in shell.
- The Rust-only service waits boundedly for boot, invokes only `fluxd daemon`, exits after a clean
  daemon return, and stops after five nonzero launches with exponential backoff capped at 16 seconds.
- The isolated Bubblewrap suite passed fresh placement, exact no-legacy assertions, fail-closed
  reinstall without payload drift, recovery on launch three, and the five-failure bound. The active
  bridge installer/uninstaller suite remained green.
- `TMPDIR=/tmp cargo test -p xtask --no-fail-fast`: 44 passed, 0 failed, 4 intentional fixture
  ignores. Strict all-target `xtask` Clippy passed after removing one redundant borrowed path; shell
  syntax checks passed.
- Repository rustfmt, `git diff --check`, and the scoped high-confidence secret scan passed. The
  existing `.github/workflows/ci.yml` CRLF normalization notice remains warning-only.

### B3.4 Verification
- `TMPDIR=/tmp cargo xtask ci` passed with pinned NDK r27d. The `fluxd` library reported 295 passed
  with four privileged ignores, `xtask` reported 44 passed with four fixture ignores, and workspace,
  documentation, and ARM64 cross-check targets passed.
- `TMPDIR=/tmp cargo xtask build-android` produced
  `target/aarch64-linux-android/release/fluxd` at 4,128,000 bytes with SHA-256
  `5a49abc896ccb95593de2f0bb088c501ce4f99c96bbaae84790fcc94fd26aa36`. Independent pinned-NDK
  `llvm-readelf -lW` inspection reported four `LOAD` segments, all aligned to `0x4000`.
- The authorized WSA serial `127.0.0.1:58526` reported WSA 2407.40000.4.0, Android 13 / SDK 33,
  rooted x86_64, and a 4096-byte runtime page size. The exact local-OUTPUT TPROXY checkpoint passed
  one test with 277 filtered; its x86_64 ELF also had four `0x4000` load segments.
- The WSA runner removed `/data/local/tmp/flux-output-tproxy.BcLpuT`; an exact absence probe and a
  prefix-wide search found no retained test directory. This is x86_64 mechanism evidence only and
  does not authorize an ARM64 profile, native writer selection, or release.
- Full Bash syntax, config/installer contract, rules generation, dispatcher, bridge installer, and
  Rust-only installer/watchdog suites passed. Their exercised rejection diagnostics are expected
  fail-closed cases, and every suite returned success.
- Active documentation now distinguishes the exact 13-path Rust-only skeleton from the still-active
  28-path development bridge and records fresh-install-only behavior. Production composition was
  re-read at `crates/fluxd/src/daemon.rs` and still constructs `ProcessRuntimeWriter`.
- Final `cargo fmt --all -- --check` and `git diff --check` passed. Scoped stale-B3/progress searches
  and the high-confidence secret-signature scan returned no matches; the complete seven-file
  documentation/plan diff was reviewed before staging.

## Execution: P1-R1 Required Host Assurance Baseline

### Goal
Turn already-implemented, host-verifiable safety checks into required CI evidence while physical
ARM64 C1/C2 remains unavailable, without representing isolated Linux mechanisms as production or
Android qualification.

### Phases
- [x] R1.1: Re-audit the required host backlog, workspace unsafe lints, ignored privileged tests,
  available host tools, and exact qualification boundaries.
- [x] R1.2: Make the passing disposable dual-stack namespace topology checkpoint a required CI step
  without enabling unsupported TPROXY or distinct-UID claims.
- [x] R1.3: Reconcile the roadmap/review with the existing enforced unsafe boundary and new CI
  checkpoint.
- [x] R1.4: Run focused, full, Android, workflow, diff, and secret gates; review and commit locally.

### Decisions
- Keep physical ARM64 C1/C2 as the P0 release-authorizing boundary. P1 host assurance may proceed
  while hardware is unavailable but cannot mint Android or native-writer authority.
- Require only `cargo xtask test-functional-canary-linux` in the standard Linux CI job. This test
  proved disposable user/mount/network namespace topology and cleanup on the current host, but its
  own contract explicitly excludes TPROXY, production composition, and Android qualification.
- Do not require the ingress/local-OUTPUT TPROXY checkpoints on a generic runner whose kernel has
  not already exposed the necessary targets and expressions. Flux tests must not load kernel
  modules merely to turn a capability absence into a pass.
- Do not add a duplicate unsafe tool. The workspace already denies unsafe operations in unsafe
  functions and undocumented unsafe blocks; strict all-target Clippy is the required enforcement
  surface.

### Errors Encountered
- Required ingress TPROXY failed closed because `/sys/module/xt_TPROXY` was absent. Required
  local-OUTPUT TPROXY likewise found no already-active module/procfs/built-in proof. These are honest
  host capability failures; no module was loaded and neither result is a code regression.
- Required distinct-UID preflight rejected the WSL environment because outer `setgroups` is denied
  while inherited supplementary groups remain. Keep the credential gate external until a host can
  provide its exact authority.
- The first workflow syntax probe selected Ruby's YAML parser, but Ruby is not installed on this
  host. The workflow was unchanged; use the available structured Python YAML parser for the same
  read-only syntax check.
- The first final R1 `cargo xtask ci` run reached the parallel `flux-platform` library target and
  exposed a pre-existing pidfd exit race: the unreaped child lost
  `/proc/<pid>/task/<pid>/ns/net`, and the test treated that observation failure as unexpected.
  Preserve the failing output, build a repeated focused feedback loop, and correct only the proven
  observation/test contract before rerunning the unchanged full gate.
- The first corrected pidfd-test compile could not access the implementation-private `require_live`
  primitive from its sibling test module. Give that existing helper parent-module visibility and
  import it only under the Linux test module; this does not widen the crate's public interface.
- The first focused post-fix rustfmt check requested only the canonical one-line signature for the
  newly parent-visible `require_live` helper. Apply repository formatting and rerun the unchanged
  focused and full gates.
- The first unsafe census used a broad `unsafe` token search over member `src` trees and counted the
  `DiagnosticState::Unsafe` enum variant as unsafe Rust. It also used a pattern that missed an
  `unsafe extern "C" fn` Android property callback. The fixed review records both the exact
  block-based production/tool census and the larger all-target census, names the callback/foreign
  blocks, and leaves the explicit semantic boundary audit open.
- The first final staging attempt could not create `.git/index.lock` because the managed sandbox
  exposes Git metadata read-only. No index entry changed; retry the same explicit eight-path stage
  with repository-metadata permission, without widening the file set.

### Verification
- The exact pidfd regression passed, five repeated parallel `flux-platform` library runs each passed
  350 tests with four privileged ignores, and strict all-target `flux-platform` Clippy passed.
- `TMPDIR=/tmp cargo xtask ci` returned success after workspace, documentation, strict Clippy, and
  pinned ARM64/API-31 Android cross-check gates. `flux-platform` reported 350 passed with four
  privileged ignores; `fluxd` reported 295 passed with four privileged ignores; `xtask` reported
  44 passed with four intentional fixture ignores.
- Required-mode `cargo xtask test-functional-canary-linux` passed its one exact disposable
  dual-stack topology/cleanup test with 298 filtered. The unsupported ingress/local-OUTPUT TPROXY
  and distinct-UID gates remain fail-closed environment evidence rather than CI requirements.
- Python structured workflow parsing, `cargo fmt --all -- --check`, `git diff --check`, scoped stale-
  authority wording, and high-confidence secret-signature checks passed.
- Independent Standards and Spec reviews found no code smell, public-interface widening, scope
  creep, or authority-boundary regression after the unsafe inventory correction. A GitHub-hosted
  run remains pending because this workflow change has not been pushed; local success is not
  represented as hosted-runner evidence.

### Status
**Local P1-R1 checkpoint complete on 2026-07-26** - the required host topology step and pidfd test
correction are verified and ready for the local checkpoint commit. Physical ARM64 C1/C2 and the
first GitHub-hosted execution of the new required step remain external evidence, not local claims.

## Execution: P1-R2 Rust Dependency Assurance

### Goal
Add a required, pinned advisory/license/source policy for the root Rust workspace dependency
graph without adding a production dependency or misrepresenting the excluded `addrsyncd`
development bridge as release-license-approved.

### Phases
- [x] R2.1: Research the current RustSec/cargo-deny contracts and audit the exact locked workspace
  graph with a temporary, pinned tool.
- [x] R2.2: Freeze the smallest explicit advisory, license, and registry/source policy that the
  current graph can satisfy without broad exceptions.
- [x] R2.3: Integrate the policy into required CI and reconcile development/roadmap evidence and
  the separate `addrsyncd` boundary.
- [x] R2.4: Run focused and full verification, perform Standards/Spec review, and make
  a scoped local checkpoint commit without pushing.

### Decisions
- Use primary RustSec and cargo-deny sources and pin every introduced CI/tool contract; do not rely
  on an unversioned global installation.
- Audit the root `Cargo.lock` and complete workspace graph. The excluded `addrsyncd` crate remains a
  development-bridge artifact with `UNLICENSED` metadata and cannot be covered up by a workspace-
  only pass; the Rust-only package already forbids its binary.
- Do not add or update runtime dependencies merely to make the policy pass. Any advisory or license
  finding must be evaluated explicitly before changing the graph or adding a narrow exception.

### Errors Encountered
- The first research-agent dispatch combined full-context inheritance with an explicit worker type,
  which the collaboration tool rejects. No agent started and no file changed; retry the same bounded
  one-file research task without full-context inheritance.
- The first temporary cargo-deny run reached Cargo metadata but could not cache two Windows target
  crates under the sandbox's read-only default Cargo home. No repository file changed; a task-local
  Cargo home under `/tmp` retained the locked graph and allowed the audit inputs to download.
- The first strict license run correctly rejected the five GPL-3.0-only workspace members and
  `webpki-roots 1.0.9` under CDLA-Permissive-2.0. Add the project license to the global compatible
  set and one exact-version CDLA exception; do not weaken deny-by-default license evaluation.
- The pinned official cargo-deny action commit installs its release archive without checking a
  digest. Do not use that Docker action for Flux; download the same upstream 0.20.2 musl archive in
  the workflow, require its published SHA-256, and execute only after verification.

### Verification
- The pinned cargo-deny 0.20.2 archive matched its published SHA-256. The all-feature locked graph
  contains 113 packages (five workspace, 108 crates.io, zero Git), and the final checked-in policy
  passed advisories, licenses, and sources against RustSec commit
  `29638ff054fdbb83d2844240f7ef7e576cb52629` with no advisory ignore.
- The exact dependency workflow step was parsed from YAML and executed in a disposable Cargo home.
  Download, strict checksum verification, extraction, live advisory refresh, locked metadata, and
  all three policy checks passed. Replacing the expected digest with 64 zeroes failed before
  extraction and left no cargo-deny binary under the temporary root.
- `TMPDIR=/tmp cargo xtask ci` passed workspace checks/tests, documentation tests, strict Clippy,
  and the pinned ARM64/API-31 Android cross-check. `fluxd` reported 295 passed with four privileged
  ignores; `xtask` reported 44 passed with four intentional fixture ignores.
- The separately required topology checkpoint passed one exact disposable dual-stack test with 298
  filtered. Workflow/TOML contract parsing, Bash syntax, repository rustfmt, `git diff --check`, the
  scoped stale-status/secret scans, and the new local research-index target passed.
- All ten new primary-source URLs returned HTTP 200. Fixed-point Standards and Spec review found no
  scope creep, baseline smell, policy broadening, runtime dependency change, lockfile change, or
  false bridge/package authority claim.

### Status
**Local P1-R2 checkpoint complete on 2026-07-26** - the root Rust workspace dependency policy and
digest-pinned required CI step are verified and ready for the local checkpoint commit. The first
GitHub-hosted run remains external evidence; `addrsyncd` licensing, package SBOM/provenance,
reproducible builds, explicit unsafe review, fuzzing, and coverage remain open.

## Execution: P1-R3 Explicit Unsafe-Boundary Audit

### Goal
Semantically review every unsafe boundary in the root workspace production/tool sources and their
test-only counterparts, correct any proven contract defect, and publish a durable audit that does
not confuse lint annotations or block counts with soundness evidence.

### Phases
- [x] R3.1: Generate the exact production/tool and all-target unsafe inventories, group them by
  owner/API contract, and identify every unsafe callable, foreign block, trait, and impl.
- [x] R3.2: Review each group for pointer validity, initialized memory, descriptor ownership,
  syscall ABI/length conversion, aliasing/lifetime, callback, signal, and concurrency assumptions.
- [x] R3.3: Fix and test only proven defects; publish the module-level audit, residual risks, and
  re-audit triggers, including a separate classification for test-only unsafe helpers.
- [x] R3.4: Run focused/full verification, perform Standards/Spec review, and create a scoped local
  checkpoint commit without pushing.

### Decisions
- Use actual unsafe constructs, not the broad `unsafe` token, as the census. The member `src` trees
  currently contain 27 files with 213 `unsafe { ... }` blocks and 216 `SAFETY:` annotations; all
  workspace targets contain 38 files, 264 blocks, 267 annotations, one unsafe Android callback,
  three unsafe foreign blocks, and no unsafe trait or impl.
- Treat `unsafe_op_in_unsafe_fn` and `clippy::undocumented_unsafe_blocks` as required mechanical
  controls, not proof that a safety comment is correct or complete.
- Keep required Linux/Android syscall and FFI adapters narrow. Do not pursue a cosmetic zero-unsafe
  rewrite or replace reviewed standard-library gaps with an unproven abstraction.
- Separate production/tool findings from integration-test helpers. Test-only unsafe can invalidate
  verification and must still be reviewed, but it does not carry production runtime authority.
- Preserve physical ARM64 C1/C2 as the release-authorizing boundary; a host source audit cannot
  authorize `NativeRuntimeWriter` or the Rust-only release profile.

### Errors Encountered
- The first R3 primary-source research dispatch combined full-history inheritance with an explicit
  worker role, which the collaboration tool rejects. No agent started and no file changed; retry
  the same one-file assignment with an isolated worker context.
- The first WSA identity-probe cross-build omitted the target-specific linker environment and
  therefore invoked host `cc`, which could not resolve Android `liblog` or `libunwind`. It produced
  no test artifact and made no device change; rerun with the pinned NDK API-31 x86_64 linker and
  the repository's two 16 KiB linker options.
- The first rooted WSA execution wrapper changed directory before invoking the test through Android
  `env`, which then could not resolve the relative executable. The already-validated binary and
  device state were unchanged; invoking the same test by absolute path passed, and exact cleanup
  followed.
- The first final Standards-review dispatch combined full-history inheritance with an explicit
  reviewer type, which the collaboration tool rejects. No reviewer started and no file changed;
  the completed independent review reports and a local post-correction two-axis review supplied
  the same read-only evidence for this checkpoint.
- The first explicit ten-path staging attempt could not create `.git/index.lock` because the
  managed sandbox exposes repository metadata read-only. No index entry changed; retry the same
  exact path list with repository-metadata permission and do not widen the staged set.

### Verification
- The exact target-conversion regression passed 2 tests. Strict all-target/all-feature
  `flux-platform` Clippy passed with undocumented unsafe blocks denied, and the full all-target/
  all-feature crate suite passed 352 library tests with four privileged ignores plus every
  integration-test target.
- `TMPDIR=/tmp cargo xtask ci` passed workspace checks/tests, documentation tests, strict Clippy,
  and the pinned ARM64/API-31 cross-check. Required-mode
  `cargo xtask test-functional-canary-linux` passed its one disposable dual-stack topology/cleanup
  test with 298 filtered.
- The 38-file/264-block/267-annotation census reconciled, including one unsafe callback and three
  unsafe foreign blocks. All 50 primary-source URLs returned HTTP 200, and their definitions,
  substantive citations, source catalog, and unique URL set reconcile exactly.
- The exact Android-only Bionic identity/property callback test passed once on rooted x86_64 WSA
  Android 13/API 33 with 343 filtered. The test ELF had four `0x4000` load segments; WSA reported a
  4096-byte runtime page size. The private remote directory was removed and independently proved
  absent. This is x86_64 mechanism evidence only and does not affect ARM64 or release authority.

### Fixed-Point Review
- Standards axis: pass after reconciling the prior independent review findings. The corrected
  census names the unsafe Android callback and all foreign blocks; the Rust guard is small, private,
  tested without signaling, and compatible with the workspace lint/format standards. No actionable
  documented-standard breach or baseline smell remains in the scoped hunks.
- Spec axis: pass. R3.1/R3.2 inventory and semantic review, the zero-target fail-closed correction,
  the module-level audit, test-only classification, primary-source pack, and verification evidence
  satisfy the R3 goal. No production dependency, writer selection, Rust-only release claim, or
  hardware authority was added; physical ARM64 C1/C2, production composition, fuzzing, coverage,
  provenance, and reproducibility remain explicitly open requirements.

### Status
**R3.4 complete on 2026-07-26** - the semantic audit, one fail-closed signal correction,
primary-source binding, full local gate, required namespace checkpoint, and x86_64 WSA callback
probe are complete. Final link/security checks pass and the fixed-point Standards/Spec review found
no actionable issue. The scoped local checkpoint is ready to commit locally without pushing.

## Execution: P1-R4 Deterministic Parser Fuzz Smoke

### Goal
Promote the existing bounded arbitrary-datagram no-panic checks into an explicit required CI
checkpoint, add equivalent coverage for the socket-diagnostics decoder, and keep the evidence
honest about the absence of a coverage corpus, sanitizer, or physical-device qualification.

### Phases
- [x] R4.1: Inventory parser fuzz-like tests and freeze the exact seven-test smoke contract.
- [x] R4.2: Add the socket-diagnostics arbitrary-input test, `xtask` command, and required workflow
  step without adding a runtime or fuzzing dependency.
- [x] R4.3: Reconcile development/roadmap/review documentation and record the remaining fuzz,
  coverage, sanitizer, and device limits.
- [x] R4.4: Run focused/full verification, perform Standards/Spec review, and create a scoped local
  checkpoint commit without pushing.

### Decisions
- Use deterministic fixed-seed generators already present in the parser tests; each selected test
  remains bounded and reproducible, and `catch_unwind` proves malformed bytes do not panic.
- Include address, link, route, rule, socket-diagnostics, and the two structured route/rule mutation
  suites. Do not call this a libFuzzer/AFL corpus or claim branch coverage.
- Keep the production dependency graph and `Cargo.lock` unchanged. A future native fuzzer can
  consume these contracts separately after toolchain/sanitizer applicability is established.
- Require the smoke in hosted CI while leaving privileged TPROXY, production composition, physical
  ARM64 C1/C2, and Rust-only writer authority on their existing gates.

### Errors Encountered
- The first socket-diagnostics smoke test tried to read the implementation-private `DumpSpec::ALL`
  constant from its sibling test module. The crate did not compile and no test ran; keep the
  production visibility unchanged and use an explicit local four-variant test array.

### Verification
- Focused `cargo test -p flux-platform --lib
  socket_diagnostics::tests::deterministic_arbitrary_datagrams_never_panic -- --exact` passed.
- `cargo xtask test-parser-fuzz-smoke` passed all seven exact tests: four 4,096-case arbitrary
  datagram suites, two structured route/rule mutation suites, and the four-family socket-
  diagnostics smoke. The implementation-private `DumpSpec::ALL` was not widened for tests.

- Fresh `TMPDIR=/tmp cargo xtask ci` returned exit code 0, including workspace checks/tests,
  documentation tests, strict workspace Clippy, and the pinned Android/API-31 cross-check.
- Strict `cargo clippy -p flux-platform --all-targets --all-features -- -D warnings
  -D clippy::undocumented_unsafe_blocks` passed after the final accessor refinement. Required-mode
  `FLUX_LINUX_CANARY_REQUIRED=1 cargo xtask test-functional-canary-linux` passed the disposable
  dual-stack topology/cleanup test with 298 filtered tests.
- `cargo fmt --all -- --check`, `git diff --check`, structured workflow parsing, the unchanged
  `Cargo.lock` check, the 38-file/264-block/267-annotation census, the production writer fence, and
  the high-confidence secret scan passed. No `NativeRuntimeWriter` production selection was added.

### Fixed-Point Review
- Standards axis: pass. The seven-test contract is explicit, bounded, deterministic, and named in
  one `xtask` constant; the test-only `DumpSpec::all()` accessor does not widen production
  visibility. The workflow, Rust formatting, lint, and documentation conventions are preserved;
  no actionable baseline smell or undocumented-standard breach remains in the R4 diff.
- Spec axis: pass. R4.1-R4.3 are implemented and the required workflow checkpoint invokes exactly
  the seven documented tests. The documentation states the deterministic-smoke limits and keeps
  coverage, corpus, sanitizer, Android/ARM64, production-composition, and writer-authority claims
  separate. No runtime dependency, `Cargo.lock` entry, public API, or release authority changed.
- The local workflow contract and command pass are recorded; a GitHub-hosted execution remains
  unclaimed because this branch has not been pushed.

### Status
**R4.4 complete on 2026-07-26** - the seven-test command, socket-diagnostics arbitrary-input
coverage, required workflow step, full local CI, focused lint/canary reruns, workflow/security
scans, and the fixed-point Standards/Spec review all pass. The scoped local checkpoint is ready to
commit without pushing; hosted workflow evidence and the previously documented fuzz corpus,
coverage, sanitizer, physical ARM64, production-composition, and Rust-only writer gates remain
open.

## Execution: P0-D1 Shell Runtime Retirement Planning (2026-07-26)

### Goal
Review implementation progress since the last fixed-point report, identify design deviations, and
publish an implementation-ready plan that retires every runtime responsibility represented by the
11 files under `scripts/` into Rust without preserving a second policy or writer implementation.

### Priorities
- P0: Reconcile actual production callers and package profiles with the canonical roadmap and
  ADR-0010/ADR-0011 authority boundaries.
- P0: Map every script responsibility to an existing Rust owner, a remaining Rust gap, or a frozen
  test-only oracle, including removal and acceptance criteria.
- P0: Keep physical Android authority and the fenced networking-writer transfer explicit; a host
  plan may not manufacture C1-C3 evidence or select the native writer prematurely.
- P1: Define focused tests, package checks, documentation changes, and an executable commit order.
- P2: Defer line-by-line shell transliteration, optional backends, and unrelated release-assurance
  work.

### Phases
- [x] D1.0: Pin the prior review boundary, confirm the worktree/branch baseline, and inventory the
  authoritative roadmap, package profiles, and `scripts/` tree.
- [x] D1.1: Map script entry points, production callers, ownership decisions, Rust counterparts,
  and remaining gaps.
- [x] D1.2: Review `e738e8c...HEAD` on Standards and Spec axes and audit current design claims
  against the production call graph.
- [x] D1.3: Write the prioritized Rust implementation/removal plan with per-slice acceptance gates.
- [x] D1.4: Verify paths, counts, links, Markdown, and diff hygiene; report exact changed and
  untouched files.

### Decisions
- Interpret "fully implement the shell scripts using Rust" as functional ownership convergence and
  removal from the shipped runtime, not source-for-source translation. Several responsibilities
  are already Rust-owned, while the networking writer cannot be activated before C1-C3/Gate 1.
- Preserve platform-required root-framework glue outside `scripts/`; the manifest already requires
  all 11 `scripts/` paths to be absent from the Rust-only package.
- Remove the two no-caller scripts in R0.5 and move their paths from the exact bridge-profile
  difference into a profile-independent retired-path denylist; remove the nine active/rollback
  bridge scripts only after Gate 1.
- Make no production-code, script, manifest, or canonical-roadmap change during this planning pass.
  The durable deliverable is
  `docs/architecture/shell-runtime-retirement-plan-2026-07.md`.

### Errors Encountered
- The first Standards-review dispatch combined full-history inheritance with an explicit agent
  type, which the collaboration tool rejects. No agent started and no file changed; the same
  bounded review was relaunched with inherited context only.
- The first combined documentation patch missed because the retirement-plan draft changed during
  the review. The failed patch changed nothing; the latest file was reread and updated with smaller
  context-stable edits.
- The first manifest-count check used the wrong `required_paths` field and an unparenthesized `jq`
  expression, so two read-only probes exited 5. The corrected `required_files` query returned
  bridge/Rust-only/forbidden counts `28/13/15` and proved the forbidden set is the exact difference.

### Status
**Complete on 2026-07-26** - the fixed-point Standards/Spec review, full script ownership map,
R0-R6 implementation/removal sequence, verification matrix, and final path/link/diff checks are
recorded. Implementation has not started; physical C1-C3 and Gate 1 remain external prerequisites
for production writer selection and bridge deletion.

## Execution: R0-R3 Host-Ready Shell Retirement Implementation (2026-07-26)

### Goal
Implement every host-verifiable prerequisite in R0 through R3, remove the two scripts that already
have no runtime callers, and leave production networking mutation fail-closed until physical ARM64
C1-C3 and Gate 1 can authorize R4.

### Scope And Priorities
- P0: Fix subscription source binding, address-successor engine-source ownership, native/bridge
  offline-recovery separation, descriptor-safe template loading, and structural platform-glue
  verification with focused regression tests.
- P0: Complete Rust-owned runtime layout, logging, native Generation/resync/offline recovery, and
  the real privileged Linux composition gate without selecting the production native writer.
- P1: Remove `scripts/flux-event` and `scripts/updater.sh` plus their bridge inventory residue after
  their replacement contracts pass.
- P2: Do not perform physical writer transfer, delete the remaining nine scripts, or promote the
  Rust-only profile without C1-C3/Gate 1 evidence.

### Phases
- [x] H0: Reconfirm baseline behavior, module boundaries, test commands, and exact R0 failure
  reproductions.
- [x] H1: Implement and verify the five R0 correctness/security contracts and the shell-reference
  source guard.
- [x] H2: Remove the two no-caller scripts and update manifest, source policy, fixtures, and docs.
- [x] H3: Implement and verify Rust-owned runtime layout and bounded logging.
- [x] H4: Implement and verify native Generation source, typed resync, and native offline recovery.
- [x] H5: Implement and require the real privileged Linux native-composition test without granting
  Android authority.
- [x] H6: Run focused and full verification, reconcile canonical documentation, and report the
  exact physical-device blocker for R4-R6.

### Decisions
- Preserve the existing single-writer fence: host tests may inject sealed test authority, but
  `run_daemon` remains on `ProcessRuntimeWriter` until R4.
- Make protocol/schema changes explicitly because the branch is pre-release; do not hide typed
  resync outcomes behind the current success-only contract.
- Reuse descriptor-relative record I/O and existing typed native owner interfaces instead of
  introducing parallel filesystem or networking implementations.
- Work with the four existing planning-file changes; do not discard or commit them.

### Errors Encountered
- The first strict H6 all-feature Clippy sweep found four mechanical issues: an elidable lifetime in
  the platform-glue parser, an over-wide Generation-digest helper signature, a manual even-length
  check in audit decoding, and an undocumented test-only `kill(2)` call. Elide the lifetime, group
  the digest inputs, use `is_multiple_of(2)`, and document the validated positive-PID boundary; the
  unchanged strict gate then passed without suppressions.
- The first H4.2 platform-admission patch used a stale `native_generation_source.rs` import context,
  so `apply_patch` rejected the complete multi-file patch without changing any file. Split the edit
  into exact per-file patches against the current import shape.
- The first H4.2 all-target compile reached `flux-platform` and found that the new admission items
  were visible only through an existing `pub(crate)` runtime-writer glob; moving raw admission out
  of `#[cfg(test)]` also exposed its test-only artifact import. Add the items to the explicit public
  re-export and make the artifact type import unconditional; the unchanged all-target check passes.
- The first H4.2 synchronous-resync fixture tried to inspect sibling-module private coordinator
  fields and therefore failed at test compilation. Exercise the same queued state through a real
  injected reload failure and public dispatcher/maintenance behavior; do not widen production or
  test visibility.
- The first H4.2 source-test compile used `expect_err` on
  `Result<PreparedNativeGeneration<_>, _>`, but the deliberately opaque prepared type has no
  `Debug` implementation. Replace the fixture assertion with an explicit result match; production
  code was not reached.
- The v4 control/status tests passed, then the text-status fixture reported the intentional new
  `last address resync: none` line as an exact-output mismatch. Update that operator-facing fixture;
  JSON and protocol resync assertions already passed.
- After the protocol bump, the first v4 fixture run retained one stale expected error string
  (`expected 3`) and therefore failed only the explicit old-version rejection test. Generalize the
  case to prove both versions 2 and 3 are rejected in favor of 4.
- The first H4.1 focused control test correctly rejected the concurrency fixture because it returned
  a generic completion for eight resync intents. Return the typed resync completion from that
  fixture; production serialization and revision behavior were unchanged.
- A combined H4.1 fixture patch matched the runtime-writer wrappers but not the exact
  `socket_round_trip.rs` import layout, so `apply_patch` rejected the whole patch before changing
  either file. Split production-test wrappers from integration-test imports.
- The first H4.1 control patch targeted an older grouped import shape in
  `runtime_coordinator.rs`, so `apply_patch` rejected the complete multi-file edit before changing
  either Rust file. Re-read the exact imports/signatures and apply smaller exact-context hunks.
- The first H3.1 focused compile found the new `runtime_root` field missing from the offline-cleanup
  `DaemonOptions` fixture. Add the same explicit root to every direct fixture initializer and rerun
  the unchanged runtime-layout tests; production behavior was not reached.
- The first H3.2 logging compile moved the fixed log-name `CString` into `BoundedLogSink` before
  deriving its diagnostic path. Derive the path before constructing the sink and rerun the same
  focused logging tests; no runtime behavior was reached.
- The next H3.2 focused run passed rotation and symlink rejection but exposed a credential leak in
  redaction: `token=` inside a URL query won assignment precedence and left URL user-info visible.
  Give a URL scheme precedence over sensitive markers that occur later in the same token, retain
  assignment redaction before the scheme, and rerun the unchanged secret-leak assertions.
- The first full H3 `cargo test -p fluxd` run stopped in the library suite when
  `startup_rejection_restores_only_the_exact_pending_bootstrap_candidate` observed the subscription
  worker busy during startup settlement. Rerun the exact test, then reproduce under parallel load
  before deciding whether this is timing exposed by diagnostic routing or an independent flaky
  handoff; do not weaken the rollback assertion.
- The first real-process H3 smoke created the fresh layout and logs, then selected the supported
  legacy mutation path because that gate depends on kernel support plus boot identity rather than
  script readiness. Use a deliberately malformed controlled boot-identity fixture so this
  script-free R1 smoke exercises the production read-only initialization path; do not add a fake
  dispatcher or change writer authority.
- The first privileged H5 design tried to compare namespace identity through `/proc/1/ns/*`, which
  is inaccessible on the supported hosted runner. Prove non-initial mapped-root user authority from
  bounded `/proc/self/uid_map`, then use `NS_GET_USERNS` on the isolated network namespace FD to
  bind its owning user namespace without weakening the isolation contract.
- The first real H5 platform convergence rejected host-installed xtables helpers because their host
  ownership did not map to UID 0 inside the user namespace. Stage byte-identical copies of the six
  installed helpers under the private fixture root so their namespace ownership and tool digests
  satisfy the real adapter contract.
- The first real H5 readback found that xtables-save canonicalizes address hosts as IPv4 `/32` and
  IPv6 `/128`. Render those exact canonical prefixes and retain a focused lowering regression.
- After adding the required subscription reload to H5, the first crash-recovery pass failed closed
  because the reconstructed test source did not receive the accepted validated subscription
  snapshot. Retain that accepted snapshot across coordinator reconstruction, matching the production
  subscription-store recovery handoff; the unchanged privileged gate then passed.
- The first final H6 `TMPDIR=/tmp cargo xtask ci` run failed only in
  `a_successful_parent_cannot_leave_a_descendant_holding_capture_pipes` when its successful shell
  fixture exited without consuming restore stdin. Under load this raced the adapter's stdin worker
  and correctly produced `Restore/Ipv4/Stdin: Broken pipe`; the exact test passed alone, while four
  of eight concurrent full library targets reproduced it. Drain the canonical restore input before
  spawning the descendant so the fixture tests only capture-pipe cleanup. Production incomplete-
  stdin handling remains fail-closed; 100 exact runs and eight concurrent full library targets then
  passed.
- The final consistency scan found one old functional-canary paragraph still naming control
  protocol v3 and one bridge-cleanup comment still naming R2 as the selection point. Update both to
  protocol version 4 and physical Gate 1; no runtime composition changed.
- The first attempt to mirror the hosted shell commands through `sudo` was blocked by the sandbox's
  no-new-privileges setting, and the escalated host command required an interactive password. The
  wrappers need namespace isolation rather than host root here, so rerun all three directly through
  their required bubblewrap mode; dispatcher, installer, and Rust-only glue suites passed.
- The first final `jq` manifest assertion bound profile objects across an unparenthesized boolean
  pipeline and failed with `Cannot index boolean with string "status"`; it did not evaluate or
  modify the manifest. Bind the profile arrays and objects before the conjunction; the corrected
  schema/status/count/exact-difference assertion passed.

### H2 Verification
- Deleted `scripts/flux-event` and `scripts/updater.sh`; `scripts/` now contains nine files and
  5,026 lines.
- Bumped `conf/manifest.json` to schema 3 with an exact two-path `retired_runtime_paths` policy.
  Bridge required paths are 26; Rust-only required/forbidden paths are 13/13.
- `cargo test -p xtask`: 48 passed, 0 failed, 4 ignored.
- `cargo xtask check-shell-bridge-sources`, `bash -n tests/shell/dispatcher_fluxd_mode.sh`,
  `cargo fmt --all -- --check`, and `git diff --check`: passed.

### H3 Verification
- `RuntimeLayout` bootstraps descriptor-relatively before lease acquisition, creates only private
  `run/` and `state/`, and validates all daemon-owned paths as exact direct children.
- Rust owns bounded `run/fluxd.log` and `run/flux.log` sinks: 4 KiB records, 1 MiB current file,
  one predecessor, `openat`/`renameat`/`unlinkat`, no-follow revalidation, mode/owner checks,
  structured severity/component/Generation fields, and credential/query/assignment redaction.
- Daemon, coordinator, and subscription diagnostics use the new sinks; inspection is explicitly
  bound to the layout-owned paths. Offline cleanup bootstraps the same layout before leasing.
- The real-binary fresh-root smoke starts without a `scripts/` directory under controlled read-only
  capability evidence, creates the exact layout/logs/socket, and records a clean SIGTERM shutdown.
- Focused checks: runtime layout 4/4, runtime logging 4/4, offline cleanup 9/9, real-process smoke
  1/1, startup reconciliation 9/9. Full `cargo test -p fluxd`: 311 library tests passed, 4
  privileged tests ignored, and all integration targets passed.

### H4 Execution Plan
- [x] H4.1: Make control completion carry an explicit native address-resync disposition and bump
  the strict wire protocol, including CLI/status and duplicate-request coverage.
- [x] H4.2: Add the production native Generation source around `GenerationAssembler`, retain the
  exact selected engine source transactionally, and admit opaque platform targets only by consuming
  Android planning evidence.
- [x] H4.3: Implement native offline recovery as `recover()` plus `converge(Stopped)` and require
  verified clean absence, without selecting it in the bridge package yet.
- [x] H4.4: Prove no-change, successor, deferred/loss, subscription preservation, failure, rollback,
  crash recovery, foreign/stale ownership, partial cleanup, and idempotence through focused tests.

### H5 Execution Plan
- [x] H5.1: Add a production-composition constructor that contains no dispatcher dependency and
  accepts only an already admitted opaque target/source seam.
- [x] H5.2: Add the ignored privileged Linux namespace lifecycle test and exact `xtask` command,
  including subprocess-deny evidence and exact dual-stack cleanup.
- [x] H5.3: Require the command in supported Linux CI while preserving a clear unsupported-host
  failure instead of treating an ignored test as evidence.

### H5 Verification
- `compose_native_runtime` wires the real native process converger, transactional Generation
  source, `EngineSupervisor`, coordinator, and canary with no dispatcher dependency. Linux receives
  only sealed feature-gated test authority and cannot construct or impersonate Android authority.
- The exact ignored test covers initial start, ordinary reload, validated subscription reload,
  address-driven successor plus typed disposition, forced engine recovery, candidate rejection and
  settlement, stop, coordinator-drop recovery, repeated native offline recovery, subprocess denial,
  and exact dual-stack xtables/RPDB/route cleanup.
- `NativeOfflineRecovery` performs `recover()` -> `converge(Stopped)` -> `recover()`; the final pass
  retires the terminal journal before verified-clean success. The canonical empty target archive is
  retained while journal, lease, and writer lock are absent.
- `FLUX_NATIVE_COMPOSITION_REQUIRED=1 cargo xtask test-native-composition-linux`: 1 passed, 0 failed,
  331 filtered out; final lifecycle execution completed in 51.18 seconds after subscription coverage.
- Supported Linux CI installs the required platform tools and sets the command to required mode.
  Production still selects `ProcessRuntimeWriter` and `BridgeOfflineRecovery`.

### H6 Verification
- The corrected descendant-cleanup fixture passed 100 exact repetitions and eight concurrent full
  `flux-platform` library targets. Every stressed target reported 354 passed and four privileged
  ignores; production `EPIPE` handling was not changed.
- `cargo fmt --all -- --check` and strict all-target/all-feature workspace Clippy passed with
  warnings and undocumented unsafe blocks denied.
- `TMPDIR=/tmp cargo xtask ci` passed source policy, formatting, all-target checks, the complete
  workspace tests and documentation tests, warnings-denied Clippy, and the pinned ARM64/API-31
  Android cross-check. `fluxd` passed 426 tests with four privileged ignores; `xtask` passed 49
  with four fixture ignores; the full xtables-lowering target passed 23.
- Required Linux evidence passed on the final source state: the existing dual-stack topology canary
  passed one test with 330 filtered, the dispatcher-free native composition passed one test with
  331 filtered in 49.33 seconds, and all seven deterministic parser smoke tests passed.
- Shell syntax, configuration/installer, rule generation, required dispatcher, required installer
  rollback/uninstall, and required Rust-only installer/watchdog suites passed. Source policy still
  permits only the reviewed bridge references.
- All 148 local Markdown targets across 49 files resolve. Protocol/composition/retired-path scans,
  exact nine-file/5,026-line script inventory, manifest profile counts, repository formatting, and
  `git diff --check` passed.

### Status
**Complete on 2026-07-26** - every host-verifiable R0-R3 prerequisite and the full H6 matrix pass.
Production and public offline cleanup deliberately remain on `ProcessRuntimeWriter` and
`BridgeOfflineRecovery`; nine scripts remain, and Rust-only stays `failing-until-complete` until a
physical ARM64 target supplies C1-C3 and Gate 1 authority for R4-R6.
