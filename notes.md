# Notes: Comprehensive Flux Project Review

## Review Boundary

- Review conducted: 2026-07-22 to 2026-07-23.
- Branch: `codex/fluxd-rust-rewrite` at `d4b08be`, one commit ahead of upstream when the review
  started.
- Initial worktree: clean. This review changes documentation and planning artifacts only.
- No repository-local `AGENTS.md` was present.
- No physical Android ARM64 device was attached. Host and WSA evidence is not treated as Android
  release authority.

## Repository Inventory

- 140 tracked Rust files in the root workspace, totaling 138,646 lines across the four product
  crates and `xtask`.
- 12,590 lines of architecture, ADR, research, and development Markdown under `docs/`.
- 6,886 lines in the shipped root shell/runtime/installer files under `scripts/`,
  `flux_service.sh`, and `customize.sh`.
- `addrsyncd` is an excluded Git submodule at `6b7c4ebe7d5f5362fb62271cc193bfca1601e562`
  with another 9,433 Rust lines and a separate lockfile/toolchain.
- The largest source files are `functional_canary.rs` (7,317 lines),
  `runtime_coordinator.rs` (4,987), `engine_supervisor.rs` (4,280), and several privileged canary
  harnesses between roughly 2,000 and 4,000 lines.
- Root direct runtime dependencies remain small: `libc`, `serde`, `serde_json`, `sha2`, and `toml`.

## Production Composition At Review Baseline

At the 2026-07-23 review baseline, the live composition was a migration hybrid, not the target
design:

1. `fluxd daemon` collects one Capability Profile and admits or rejects mutation.
2. `run_daemon` executes shell `startup-recover`, loads the narrow Rust `flux.toml`, and constructs
   `ProcessRuntimeWriter` plus `EngineSupervisor`.
3. `RuntimeCoordinator` serializes prepare, engine, capture, verification, rollback, and publication.
4. Every networking phase crosses `ProcessRuntimeWriter` into `ProcessPhaseDispatcher` and
   `scripts/dispatcher`.
5. `scripts/tproxy` remains the production xtables and policy-routing writer.
6. `scripts/addrsync` controls the separately running `addrsyncd` process.
7. Production explicitly selects `RuntimeFunctionalCanary::StructuralOnlyCompatibility`.
8. The reactor created a `NetworkInventorySource`, but `run_daemon` retained it as
   `_network_inventory`; no reconciliation consumer observed it before A3.

The ownership result is precise: Rust owns administrative intent, serialization, recovery order,
status, and Sing-Box process supervision; shell and standalone `addrsyncd` still own the active
networking effects.

## Implemented But Disconnected

- `generation_engine_config` compiles a canonical Sing-Box artifact, inspects the exact engine, and
  creates a non-authorizing TPROXY candidate. The module is marked `allow(dead_code)` and has no
  production caller.
- At the review baseline, `NetworkInventorySource` performed strict subscribe-before-dump
  link/address/route/rule observation with loss recovery, but its production handle was unused.
- The canonical xtables lowerer represents schema-v2 local OUTPUT/loopback PREROUTING artifacts.
- `NativeXtablesOwner` implements descriptor-pinned restore/save, rtnetlink policy routing, exact
  readback, durable journal, rollback, recovery, cleanup, and a shared writer fence.
- `NativeXtablesAdmittedTarget` has only a `#[cfg(test)]` positive constructor. The owner is private
  and cannot enter production composition.
- The functional-canary protocol and Linux harness are extensive, but the local-OUTPUT driver and
  several authorities are deliberately uninhabited in production.

These components are valuable implementation inventory. They do not yet form a deployable Rust
runtime, and completing more detached evidence types would not close the ownership gap.

## Configuration And Package Split

- Rust `FluxConfig` currently owns only schema version plus four daemon values: failure policy,
  reconciliation debounce, event queue capacity, and Generation history.
- Product capture, interface, UID/user, mark, subscription, updater, and compatibility settings
  remain in `settings.ini` and are compiled by shell/AWK.
- Sing-Box template mutation and extraction still use the packaged `jq` binary.
- Subscription retrieval and normalization remain in `scripts/updater.sh`, using external `curl`,
  AWK, and `jq`.
- `scripts/fluxctl` partly delegates to `fluxd`, but retains legacy status, diagnostics, rules
  preview, log, and policy-routing behavior.
- The package verifier requires exactly `fluxd`, `sing-box`, `jq`, and `addrsyncd`, both legacy
  configuration files, and all runtime scripts. It therefore proves the bridge package rather than
  the ADR-0011 Rust-only package.
- `addrsyncd/Cargo.toml` declares `UNLICENSED`, while the root workspace is GPL-3.0-only and the
  release verifier deliberately rejects an unreviewed `LicenseRef-UNLICENSED`. This is a release
  provenance blocker requiring an explicit license decision before any code is absorbed or shipped.

## Verification Evidence

- `cargo xtask ci`: passed on 2026-07-23.
- Root workspace: 984 passed, 0 failed, 12 ignored.
- Excluded `addrsyncd`: 98 passed, 0 failed, 1 ignored.
- CI also runs shell configuration/installer/rule/dispatcher/CLI suites and a pinned xtables oracle.
- Critical privileged Linux canaries are ignored by ordinary workspace tests and are not required
  by `cargo xtask ci`.
- At the 2026-07-23 review baseline, no committed fuzz target, coverage gate,
  dependency-vulnerability gate, or sanitizer/Miri job was found despite several roadmap fuzzing
  and hardening commitments. P1-R2 later closes the root Rust workspace dependency gate only.

The suite strongly validates pure models, parsers, lifecycle state machines, and fault injection.
It does not yet validate the production Rust composition because that composition does not exist.

## Final Documentation Verification

- All 44 pinned external URLs returned HTTP 200 on 2026-07-23.
- All 48 local/external citation labels in the comparison report have definitions.
- All 138 local Markdown targets across the 43 repository Markdown files inspected resolve.
- The three Mermaid blocks in the review and roadmap have balanced fences and valid flowchart
  starts; the three key documents have no heading-level jumps.
- No retired backlog-item 3/4 references, trailing whitespace, or `git diff --check` errors remain.

## Strengths To Preserve

1. Immutable Generation reconciliation and explicit prepare/activate/verify/retire semantics.
2. One writer per mutable kernel object, with a durable transition lease and no dual-writer window.
3. Capture detachment before engine shutdown, fail-open compensation, bounded retry, and exact
   recovery state.
4. Strict bounded parsing, descriptor-relative/no-follow I/O, pinned process identity, and exact
   readback rather than exit-status trust.
5. Honest separation of host mechanism evidence from physical Android authority.
6. Detailed Android fwmark, RPDB, VPN/netd coexistence, and network-namespace reasoning.
7. A small dependency surface and a clearly external Sing-Box engine.

## Main Problems

### P0: Scheduling And Ownership

- The roadmap serializes host-implementable Rust work behind unavailable physical ARM64 evidence.
- The project optimizes intermediate proof completeness instead of time to one Rust-owned runtime.
- Four major Rust subsystems exist outside production composition, so their integration risk is
  accumulating rather than shrinking.
- The current package cannot satisfy its own Rust-only release decision.

### P1: Maintainability And Assurance

- Proof and receipt vocabulary has grown faster than executable composition. New types should be
  admitted only when they close an actual authority gap consumed by the next runtime step.
- Several deep modules have become very large. Keep their public interfaces, but split internal pure
  state reduction, effect execution, and test harness code after the production path is connected.
- Hand-written syscall/netlink/process code is justified in key places, but its unsafe and parser
  surface needs fuzzing, syscall-level integration, and dependency/security audit gates.
- Status histories are embedded throughout long ADRs/specification/roadmap sections, making the
  current plan hard to discover and easy to stale.

## Recommended Direction

- Near-term target: one `fluxd` binary owns Desired State, configuration/subscription compilation,
  Generation assembly, network observation, xtables/RPDB mutation, address reconciliation,
  Sing-Box supervision, control/CLI, recovery, and offline cleanup. Sing-Box remains external.
- Keep only platform-required installer, boot launcher, disable, and uninstall glue in shell. That
  glue must contain no networking policy or cleanup implementation.
- Ship the first Rust-only release with one conventional xtables TPROXY path. Defer nftables, TUN,
  eBPF, ipset acceleration, and broad `auto` planning.
- Run host Runtime Composition, Rust Product Plane, and Physical Android Qualification as parallel
  lanes. Join them only at the atomic native-writer cutover.
- Absorb behavior, tests, and useful reactor lessons from `addrsyncd`; do not preserve it as a
  second daemon or copy its parallel netlink stack wholesale. Prefer inventory-driven Generation
  refresh and pre-mark host bypass in the Capture Program when that preserves semantics.
- Keep the native production constructor unforgeable, but make the complete authority-consuming
  constructor and coordinator path the next integration deliverable rather than another detached
  artifact.
- Treat VPN egress as an explicit per-origin contract: a root-owned engine socket does not inherit
  the intercepted UID's network automatically. Exclude VPN-owned traffic or prove an exact probed
  adapter before claiming `respect_android_vpn`.
- Add 16 KB Android ELF alignment to the package gate; NDK r27d does not supply it by default.

## External Research Additions

- Netavark supports typed validate-before-mutate setup and compensation, but its one-shot container
  model is weaker than Flux's durable Android reconciliation needs.
- nmstate's closest lifecycle is prevalidate, checkpoint, apply, retrieve/verify, then commit or
  rollback. Its kernel-only path has no checkpoint, so Flux must keep its own journal.
- nftables atomicity covers one nf_tables ruleset batch, not RPDB, routes, listener readiness,
  process identity, or Generation publication. It does not justify delaying the existing native
  xtables owner.
- AOSP uses `/system/etc/xtables.lock` and long-lived restore processes; verified system restore/save
  adapters are the most compatible first cutover mechanism.
- AOSP chooses implicit socket networks by calling UID. Root-owned proxy sockets require explicit
  VPN/network-context treatment.
- Magisk late-start scripts are detached rather than supervised, so minimal boot watchdog behavior
  remains platform glue even after networking policy moves to Rust.
- Android 15's 16 KB-page support requires explicit alignment for the pinned NDK r27d build and
  verifier coverage for all packaged ELF files.

## Scope Deferred Until Rust Unification

- Native nftables and backend auto-selection.
- Managed TUN and Flux-owned TUN file descriptors.
- eBPF observation/acceleration, TC/TCX, `sk_lookup`, and kernel-extension integrations.
- Established-flow caches, DIVERT, optional FakeIP ICMP handling, QUIC rejection, and MSS clamping
  unless the minimum advertised xtables behavior demonstrably requires one.
- Broad device matrices beyond the minimum release qualification set.

## P0-G0 Execution Evidence

### Existing package boundary

- `xtask/src/main.rs` hard-codes one 28-file bridge inventory in `REQUIRED_MODULE_FILES` and one
  four-binary inventory (`fluxd`, Sing-Box, `jq`, and `addrsyncd`).
- `stage-module` and `verify-package` have no package selector; the manifest accepts only a profile
  named `full` with no lifecycle or path policy.
- Source comparison, exact package inventory, operational-payload hashing, manifest binary checks,
  and first-party revision binding all assume the bridge shape.
- `validate_module_content` also unconditionally parses bridge-only scripts and configuration, so it
  must follow the selected contract before a Rust-only layout can be evaluated honestly.

### Gate 0 contract selected

- Profiles: `bridge` with status `development-only`; `rust-only` with status
  `failing-until-complete`.
- Rust-only required runtime/module paths: Magisk installer entries, `bin/fluxd`, `bin/sing-box`,
  `conf/flux.toml`, `conf/template.json`, `conf/manifest.json`, `webroot/index.html`,
  `customize.sh`, `flux_service.sh`, `uninstall.sh`, `module.prop`, and `LICENSE`.
- Rust-only forbidden bridge paths: `bin/addrsyncd`, `bin/jq`, `conf/settings.ini`,
  `conf/addrsyncd.toml`, and every current file below `scripts/`.
- Release metadata (`SBOM.spdx.json`, `checksums.sha256`, `build-metadata.json`) and declared evidence
  remain verifier-managed additions rather than runtime paths.
- The contract validator will require the Rust-only required set to be a strict subset of bridge
  required paths and its forbidden set to equal the exact difference. This makes omissions and
  undeclared bridge residue fail deterministically.

### Gate 0 implementation result (historical checkpoint)

- At the Gate 0 checkpoint, `conf/manifest.json` schema 2 contained the only package path policy:
  29 bridge-required paths, 13 Rust-only required paths, and the exact 16-path difference as
  Rust-only forbidden paths. B2.4 later removed `scripts/fluxctl`, reducing the current contract to
  28 bridge-required, 13 Rust-only required, and 15 forbidden paths.
- `stage-module` and `verify-package` accept `--profile bridge|rust-only`, defaulting to `bridge` for
  compatibility. Staging copies only selected required paths rather than whole source/runtime trees.
- Source-byte comparison, exact inventory, module-content checks, binary-manifest inventory,
  operational-payload hashing, and applicable first-party revision binding use the selected profile.
- A staged manifest must carry exactly the checked-in profile policy. Populating provenance and
  evidence cannot weaken or replace that policy.
- Rust-only source verification no longer requires a clean or manifest-bound `addrsyncd` submodule;
  the bridge verifier still does.
- Focused result on 2026-07-25: `cargo test -p xtask` passed 36 tests with 4 intentional ignored
  fixtures. The complete bridge package fixture passes `bridge` and fails `rust-only` at the first
  explicit forbidden path, `bin/addrsyncd`.

## P0-A1 Initial Evidence

- `FluxConfig` currently accepts only `schema` plus four `[daemon]` fields. Every engine, capture,
  interface, application, family, listener, subscription, and compatibility setting still comes
  from `settings.ini` or generated JSON.
- `generation_engine_config` already supplies a deterministic bounded TPROXY template compiler,
  exact artifact/config/launch digests, Sing-Box validation, and a non-authorizing candidate. It is
  private and marked dead because production never calls it.
- The existing Capture Program accepts typed traffic/family scope, engine UID/GID, CIDRs, interface
  roles, resolved application UIDs, TCP/UDP selection, and an optional inventory host set. This is
  the correct target for config compilation; a new policy representation is unnecessary.
- `ProcessRuntimeWriter::prepare` still calls shell first and then reads a shell-generated
  `engine.manifest`; the shell snapshots `conf/config.json`, settings-derived caches, and rule files.
  Therefore merely validating the new TOML will not complete A1: a later slice must move canonical
  artifact creation ahead of this dispatcher path and prevent subsequent `jq` rewriting.

## P0-A1 Implementation Evidence

- `FluxConfig` now accepts schema 2 as one strict, typed Desired State covering daemon, engine,
  capture, listener, applications/users, interfaces, bypass, subscription, and safety intent.
- `conf/flux.toml` has moved to schema 2. Focused verification passed 35 config tests and strict
  Clippy for `flux-core`.
- `generation_engine_config::compile_desired_state` is one pure interface over an owned
  `FluxConfig`, resolved application policy, optional inventory host set, and template bytes. It
  returns the same immutable snapshot plus canonical engine and shadow Capture Program artifacts;
  it performs no I/O, subprocess execution, or activation.
- An initial `cargo test -p fluxd generation_engine_config` compile passed 18 existing engine tests,
  proving the new module type-checks but also showing that its behavior still needed direct tests.

### A1.4 bridge-input cutover evidence

- `publish_bridge_preparation` now compiles and atomically publishes both the canonical read-only
  `conf/config.json` and a bounded read-only `run/desired-state.env` from one schema-2 snapshot.
- Rust-owned shell preparation validates an exact 41-field allowlist before sourcing the environment.
  Its only derived additions are observed `KFEAT_*` facts; `settings.ini`, legacy cache policy, and
  read-only `jq` extraction can no longer override Rust-owned product intent.
- `ProcessRuntimeWriter` rejects manifest drift in binary path, launch identity, startup timeout,
  stop timeout, config digest, or listener binding, and replaces the old fixed manifest restart
  policy with the current typed Desired State policy.
- The temporary bridge fails closed for Desired State shapes its frozen shell renderer cannot express
  exactly, including missing local/forwarded capture, single-protocol or IPv6-only capture, user CIDR
  bypasses, enabled subscription retrieval, Android VPN intent, mandatory functional canaries, and
  interface-role overflow.
- Focused verification on 2026-07-25: `cargo test -p fluxd generation_engine_config` passed 30 tests;
  `cargo test -p fluxd process_writer` passed 7 tests; and
  `tests/shell/run-dispatcher-tests.sh` passed the complete dispatcher contract suite.

### A1 final verification and environment evidence

- `cargo test -p flux-core --test config`: 35 passed.
- `cargo test -p fluxd generation_engine_config`: 30 passed.
- `cargo test -p fluxd process_writer`: 7 passed.
- `cargo test -p fluxd`: 296 passed, 4 ignored.
- `cargo clippy -p fluxd --all-targets -- -D warnings`: passed.
- `tests/shell/run-dispatcher-tests.sh`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo xtask ci`: passed.
- `git diff --check`: passed with only the pre-existing CRLF normalization warning for
  `crates/fluxd/tests/daemon_shutdown_signal.rs`.
- Linux `adb devices -l` produced no output before a 10-second timeout. Windows `adb.exe devices -l`
  started successfully and reported no attached devices; the newly started Windows ADB server was
  stopped. No WSA execution evidence was obtained, and no physical Android authority was available.

## P0-A2 Initial Evidence

- `TproxyGenerationCandidate` already binds a verified device Capability Profile, exact Network
  Inventory snapshot/epoch, Engine Capability Profile, and canonical engine launch binding, but it
  deliberately has no Generation ID, route/mark program, coordinator entry point, or mutation
  authority.
- The schema-2 shadow Capture Program can already lower deterministically into an
  `XtablesCaptureArtifactSet` when supplied a non-authorizing Generation namespace, mark candidate,
  and local-output routing description.
- `AndroidMarkPlanningAuthority` is non-cloneable, snapshot/boot/namespace-bound, and authorizes
  only further pure planning. `RpdbPlacementLease` separately proves snapshot-bound numeric
  placement and remains non-authorizing.
- `NativeXtablesAdmittedTarget` is private to `flux-platform` and exposes only a test constructor.
  A2 must not weaken that deliberate production gate or manufacture a physical-device target.
- The existing bridge engine-policy binding is general Generation assembly behavior: it validates
  binary path, numeric launch identity, startup/stop timeouts, and typed restart policy. It should
  move behind the assembler interface so bridge and native preparation cannot drift.
- Frozen interface: one internal `GenerationAssembler::assemble(request)` call consumes immutable
  Desired State artifacts, exact `EngineSpec`, device/inventory/engine evidence, planning evidence,
  and optional prior owned identity. It returns one inspection-ready `AdmittedGeneration` or a
  typed error. Host inspection authority remains explicitly non-authorizing; Android planning
  consumes the existing non-cloneable mark authority and current placement lease.

## P0-A2 Implementation Evidence

- `GenerationAssembler::assemble` now assigns a monotonic Generation, binds the current Desired
  State to the exact engine specification/config/profile and inventory, validates host or Android
  planning evidence, lowers the shadow Capture Program into canonical xtables artifacts, and
  returns one non-mutating `AdmittedGeneration`.
- `CapabilityProfileDigest` canonically length-frames every retained profile field. Equal local
  revisions with different SELinux or other evidence no longer share Generation identity.
- `AndroidMarkPlanningEvidenceDigest` binds the exact mark candidate, topology scope, complete
  Capability Profile and boot/namespace identity, policy identity/revision, planes, complete census
  observation plus canonical coverage/uses, collector and ownership-journal revisions, and partial
  audit. The Generation planning digest additionally binds the exact RPDB placement lease.
- Successor assembly hashes the complete prior identity, and prepared-record loading admits only
  Generation 1 without a predecessor or an exact `n-1` predecessor. Divergent histories cannot
  converge on one successor identity merely because current inputs and numeric IDs match.
- `PreparedGenerationRecordStore` persists a strict 16 KiB JSON projection with complete
  capability/planning, engine, capture, xtables, inventory, admission, identity, and lineage
  fields through no-follow atomic I/O. Dedicated tests reject final-component symlinks, malformed
  lowercase digests, oversized input, and noncontiguous lineage.
- The coordinator connection remains `inspect_admitted_generation`, a read-only projection with a
  reasoned dead-code allowance. No native target, writer authority, activation lease, or mutation
  method was added, and both production legacy networking writers remain fenced.
- Focused verification on 2026-07-25: all 223 `flux-core` tests plus one doc-test passed;
  `cargo test -p fluxd generation_engine_config --no-fail-fast` passed 41 focused tests;
  `cargo test -p fluxd process_writer --no-fail-fast` passed 7 tests;
  `cargo test -p fluxd --test administrative_intent_store --no-fail-fast` passed 8 tests; and
  `cargo clippy -p fluxd --all-targets -- -D warnings` passed after boxing both large authority
  variants.
- The first final `cargo xtask ci` run exposed a pre-existing parallel-test timing assumption:
  the Sing-Box timeout fixture required nonempty stderr and a descendant PID within 75 ms. The exact
  test passed alone, while the 19-test target reproduced the failure. Its test-only timeout is now
  500 ms, timeout diagnostics remain bounded to 8 KiB without being required to exist, and the
  descendant PID/reap assertions still prove process-group cleanup. Production process control is
  unchanged; the parallel target passed twice after the correction.
- Final A2 verification on 2026-07-25 passed `cargo fmt --all -- --check`, strict `fluxd` Clippy,
  the complete dispatcher shell contract, and a clean `cargo xtask ci`. The workspace contains
  1,036 listed tests: 1,024 passed and 12 privileged/helper fixtures remained intentionally ignored;
  no test failed. Final diff hygiene reported only the pre-existing CRLF normalization warning for
  `crates/fluxd/tests/daemon_shutdown_signal.rs`.
- No WSA ADB endpoint or physical ARM64 Android target was available, so this pass creates no device
  qualification evidence. WSA remains development-only, and physical Android authority remains a
  release prerequisite. `P0-A3` address reconciliation is the next host-executable slice.
- A final cross-document ownership sweep removed the remaining ambiguous "sole networking/kernel
  writer" wording. Active documentation now states the implemented bridge split consistently:
  `scripts/tproxy` owns xtables/Flux PBR writes, standalone `addrsyncd` owns address synchronization,
  the dispatcher serializes both, and Gate 1 transfers all networking ownership in one fenced cutover.

## P0-A3 Address Reconciliation Evidence (2026-07-25)

- `DaemonReactor::bind_with_network_inventory` already opens one subscribed route-netlink socket,
  registers it in the existing epoll reactor, and returns a cloneable `NetworkInventorySource`.
  Before A3, `run_daemon` retained that source as unused `_network_inventory`; the completed wiring
  now attaches it to `AddressReconciler` before reactor execution.
- `NetworkInventoryObserver` publishes only after a complete LINK -> ADDRESS -> ROUTE -> RULE dump.
  Live link/address changes use a 50 ms quiet and 250 ms maximum debounce; material equality avoids
  a new publication. `ENOBUFS`, truncation, overruns, decode ambiguity, interrupted/incomplete dumps,
  or sequence faults immediately replace the public snapshot with `None` and require a full redump.
- `LegacyControlBridge` already gives `RuntimeCoordinator` one serialized worker. Its bounded idle
  `maintain()` callback runs at 50-250 ms from the configured reconciliation interval, so polling
  the immutable source there needs no thread, event queue, second reactor, or sidecar lifecycle.
- `flux-core::plan_address_host_set` is realization-neutral and binds deterministic, deduplicated,
  family-filtered usable hosts to the exact inventory snapshot identity and epoch. The Desired State
  compiler already accepts that plan and emits host provenance plus pre-mark destination-host
  bypass clauses in the shadow Capture Program.
- `ProcessRuntimeWriter::resync_addresses` still invokes the fenced bridge `address-resync` phase.
  A3 keeps that explicit compatibility command unchanged but does not invoke it for inventory
  observations. Networking ownership must still transfer with xtables and Flux PBR in one later
  native-owner cutover.
- The clean late-attachment lifetime is one `OnceLock<NetworkInventorySource>` shared between an
  attachment handle retained by daemon startup and a reconciler moved into the coordinator worker.
  The source is attached after reactor bind and before `run()`. Before attachment, initialization
  failure, and read-only startup remain non-mutating unavailable states.
- The excluded standalone implementation is documented as `UNLICENSED`. A3 uses only root-workspace
  code and documented behavior; no submodule implementation or test text is copied.
- `AddressReconciler` now retains the exact complete inventory, `AddressHostSetPlan`, and compiled
  Desired State/Capture Program artifacts. `None` invalidates current results; equal snapshots are
  no-ops unless successful preparation requests a configuration refresh; failed inputs remain
  blocked until either trigger changes.
- `RuntimeCoordinator::maintain` services engine/capture safety and publication retries before the
  bounded non-authorizing address compilation. A replay-source coordinator test proves maintenance
  consumes a complete snapshot without emitting the scripted `AddressesResynchronized` writer
  event.
- `run_daemon` moves the reconciler into the existing bridge worker, binds the reactor, and attaches
  its source before `reactor.run()`. The existing live-daemon SIGTERM integration traverses this
  late-attachment and shutdown path; its exact phase trace contains no `address-resync` call.
- Focused A3 verification on 2026-07-25: 223 `fluxd` library tests passed with 4 privileged tests
  ignored; 43 `flux-platform` network-observer tests passed; the live-daemon shutdown integration,
  Clippy with warnings denied, rustfmt check, and `git diff --check` passed.
- Final A3 verification on 2026-07-25: `cargo xtask ci` and
  `tests/shell/run-dispatcher-tests.sh` passed. Diff hygiene again reported only the pre-existing
  CRLF normalization warning for `crates/fluxd/tests/daemon_shutdown_signal.rs`.
- Linux ADB (`/usr/bin/adb`) and Windows ADB (`D:\Programs\platform-tools\adb.exe`) reported no
  attached device. The standard WSA endpoint `127.0.0.1:58526` refused connection, so no WSA check
  was available and no Android qualification evidence was produced.
- A3 remains explicitly non-authorizing. Exact kernel rule readback, partial-failure compensation,
  and privileged native lifecycle coverage belong to A4, where one owner can apply and roll back the
  complete networking transaction.

## P0-A4 Initial Evidence

- `NativeXtablesOwner` already owns the complete mutation transaction behind only `recover()` and
  `converge(NativeXtablesDesiredTarget)`: transition fencing, real restore/save calls, rtnetlink
  routing, exact readback, replacement rollback, cleanup, and journal recovery are implemented.
- `NativeXtablesProcessOwnerAdapter` already composes the descriptor-pinned coherent xtables tool
  set with fresh policy-routing mutation/observation sessions. Its positive production target
  constructor remains deliberately absent.
- The unresolved production gap is durable target reconstruction. Owner payload schema 2 retains
  target identities only, while `PreparedGenerationRecord` retains Generation identities/digests;
  neither can reconstruct the canonical restore artifacts, stable topology, exact routing, and
  complete recovery audit required by `NativeXtablesTargetResolver` after a crash.
- The smallest safe A4 seam is a bounded atomic archive containing the exact private runtime plan
  for the active and possible replacement targets. The owner facade publishes this material before
  journal acquisition/rebind and prunes it only after a terminal convergence report.
- Current host UID is 1000. `/usr/sbin/iptables`, `/usr/sbin/ip6tables`, and `unshare` are present;
  the ignored real-owner test may be attempted through a disposable user/network namespace. This
  remains mechanism evidence and cannot replace physical Android ARM64 qualification.

## P0-A4 Archive And Facade Evidence (2026-07-25)

- `XtablesStableFamilyPlan` now retains the exact private chains, prepare/retire artifacts, stable
  topology artifacts, and expected states consumed by the owner. One compact target identity binds
  the original lowering digest, complete runtime plan, coherent tool set, routing, and full audit.
- Owner payload schema 3 continues to store only bounded identities. The new checksum-protected
  target archive durably stores the exact private recovery material for the active and possible
  replacement targets and reconstructs it without current configuration or live-state authority.
- `NativeXtablesRuntimeWriter` requires `recover()` before `converge()`, stages target material
  before journal mutation, composes `NativeXtablesProcessOwnerAdapter`, preserves terminally
  referenced targets, and keeps dry-run observation non-mutating.
- Atomic archive replacement was not sufficient for competing processes because pruning could race
  a later stage. A no-follow `flock` runtime guard now spans archive refresh, stage, owner mutation,
  and settling. The in-memory resolver refreshes from the atomic disk snapshot under that guard.
- A deterministic concurrency test pauses after the owner journal durably names the staged target
  and proves a competing runtime transaction cannot acquire the guard until convergence finishes.
- Focused result: 35 tests passed, 1 privileged namespace test was intentionally ignored, and
  strict `flux-platform` Clippy passed. Positive native admission and daemon ownership remain gated.

## P0-A4 Coordinator Convergence Evidence (2026-07-25)

- `flux-platform` now exports only a generic `NativeCaptureConvergence` interface, opaque target
  identity, and convergence desired/state/report values. The concrete process converger and target
  are public opaque types with platform-private constructors; raw xtables restore/save and
  policy-routing types remain private.
- `NativeCoordinatorWriter` is a `fluxd`-private adapter over that deep interface. Its constructor
  completes recovery and converges any recovered active target to verified clean absence before the
  lazy Generation-source closure can run.
- The adapter retains at most the committed and candidate targets. A failed candidate preserves the
  previous target until coordinator rollback is committed; successful Running publication prunes
  the previous target. Stopped publication clears both. These publications are in-memory commit
  callbacks only and perform no dispatcher or legacy state-file I/O.
- An uncertain convergence forces recovery before the next active/stopped request. Successful
  convergence is the structural verification result; the coordinator cannot publish Running for a
  different or absent opaque identity.
- `RuntimeCoordinator::reload_prepared` is the common replacement path for ordinary preparation and
  address-driven successors. `AddressReconciler` still performs only pure compilation; on a
  material complete snapshot, the native Generation source may return one successor which enters
  the same engine-before-capture, compensation, and previous-generation rollback logic.
- Six focused native coordinator tests pass: recovery/cleanup before source acceptance,
  engine-before-capture with no dispatcher/publication events, candidate failure and previous
  restoration, address-driven successor convergence, clean absence before engine stop, and rejection
  of a capture target whose Generation differs from the coordinator Generation.
- Final semantic review retained one pending address-reconciliation marker while runtime ownership is
  ineligible, clears it on invalidation or failed compilation, and consumes it only after successful
  maintenance proves a Ready engine with Published capture. A dedicated regression test proves an
  engine-maintenance failure cannot be followed by address replacement in the same maintenance turn.
- Regression verification passed 47 runtime-coordinator tests, all 35 non-privileged
  native-owner/runtime tests, strict Clippy for `flux-platform` and `fluxd`, rustfmt, and diff
  hygiene (apart from the pre-existing CRLF normalization warning).
- The required ignored namespace test was attempted under `unshare -Urn`; it failed before mutation
  because the mapped root cannot read `/proc/net/ip_tables_targets`. The host also denies a private
  proc remount and prevents sudo through `no_new_privs`, so the registration preflight remains
  unavailable rather than bypassed.
- WSA was started successfully and listens on port 58526, but Windows ADB reports
  `127.0.0.1:58526 unauthorized`. No WSA mechanism result or physical Android qualification is
  recorded from this pass.
- Final A4 verification on 2026-07-25 passed `cargo xtask ci` and the complete dispatcher shell
  contract after the semantic-review corrections. The required ignored real-Adapter namespace test
  remains unavailable because user-namespace root cannot read `/proc/net/ip_tables_targets`; the
  registration preflight was not weakened. A final Windows ADB retry listed no attached devices, so
  neither WSA mechanism evidence nor physical ARM64 qualification is claimed.
- Native manual resync currently records a fresh reconciliation request whose serialized maintenance
  runs after command completion. Before Gate 1 selects the native writer, C2/Gate 1 must expose
  completed convergence versus accepted/deferred work explicitly; it may not report queued work as a
  completed kernel mutation.
- The final independent specification audit found no unresolved A4 defect after the Generation and
  maintenance-ordering corrections. It rechecked recovery-before-source construction,
  archive-before-owner mutation, engine-before-capture activation, clean capture absence before
  engine retirement, in-memory-only native publication, and the continuing production fence.

## P0-B1 Initial Evidence (2026-07-26)

- The workspace has no production HTTP, TLS, URL, Base64, regex, or decompression dependency.
  `fluxd` currently depends only on the two workspace crates plus Serde, JSON, SHA-256, and libc.
- Schema 2 already bounds subscription intent to a regular URL file, a 1-300 second timeout,
  1 KiB-64 MiB response, 1-100,000 nodes, and a 0-365 day interval. Redirect, content-type,
  decompression, filtering/naming, and asset-digest policies are not yet represented.
- `scripts/updater.sh` accepts either a Sing-Box JSON outbound document or an optionally Base64-
  wrapped line list. Its stated URI set is VMess, Shadowsocks, VLESS, Trojan, Hysteria 1/2, TUIC,
  SOCKS, HTTP, and Snell, but the generic URI branch discards query parameters and therefore does
  not preserve many protocol transport/TLS options. There are no updater contract fixtures.
- The legacy updater has a finite total/connect timeout and retries, but no explicit body or decoded
  size limit, no node-count limit, curl's redirect policy, permissive content types, and a shell/AWK/
  `jq` parser. It validates the merged candidate with Sing-Box and retains one backup before rename.
- The Rust bridge deliberately rejects `subscription.enabled = true`. Every preparation rereads
  `engine.template` and republishes `conf/config.json`, so a side publisher would be overwritten;
  the active subscription snapshot must instead become an exact canonical Generation input.
- The checked-in template contains three remote binary rule sets and an external-UI archive URL.
  B1 therefore needs to content-address validated rule assets and rewrite Generation-local engine
  input to local paths; moving only the node subscription would leave remote asset ownership split.
- The deep Module interface is one refresh operation returning a validated immutable snapshot.
  Fetch transport and Sing-Box validation are internal seams with production and deterministic test
  adapters. Callers do not orchestrate fetch, decode, merge, asset staging, validation, or rollback.
- Network retrieval must not block the serialized runtime-maintenance writer. Existing control
  connections already run on bounded reactor workers; periodic refresh needs one bounded worker
  that can submit a successful configuration change back to the serialized coordinator.

## P0-B1.1 Compiler Evidence (2026-07-26)

- `subscription::compiler` is a pure, I/O-free slice over owned template/source bytes and the
  schema-bounded node count. It accepts Sing-Box outbound JSON, plain URI lists, and strict
  standard or URL-safe Base64 wrappers for the frozen protocol family.
- Normalization removes infrastructure and legacy metadata nodes, collapses whitespace and emoji,
  gives duplicate tags stable numeric suffixes, populates empty global/country selectors, removes
  nulls, and emits deterministic content and domain-separated SHA-256 identities.
- The first compilation exposed only local type/borrow/lint defects; after converting the shared
  `u64` engine byte limit once, owning selector tags across mutation, and removing a redundant
  Unicode range, `cargo test -p fluxd subscription --no-fail-fast` passed all 5 focused tests.
- `cargo clippy -p fluxd --all-targets -- -D warnings` passed. The whole subscription module remains
  under an explicit temporary dead-code fence and has no production call path in B1.1.

## P0-B1.2 Retrieval And Asset Evidence (2026-07-26)

- Product configuration is now strict schema 3. `subscription.max_download_bytes` bounds the raw
  encoded entity and the new required `max_decoded_bytes` independently bounds decompressed input;
  both values participate in the Desired State digest.
- The selected graph is exact `ureq 3.3.0`, `url 2.5.8`, and `base64 0.22.1`, with ureq defaults
  disabled and only Rustls/static WebPKI roots plus gzip/Brotli enabled. The lock resolves
  `rustls-webpki 0.103.13`.
- The fetch Adapter rejects credentials, fragments, non-HTTPS/non-default ports, overlong URLs,
  terminal non-2xx responses, disallowed content types, and unsupported residual encoding metadata.
  Ureq removes metadata for encodings it decodes, so unusual stacked encodings may instead fail at
  later bounded parsing rather than one guaranteed encoding-policy category. Redirects remain
  HTTPS-only, authorization is never forwarded, ambient proxy state is disabled, and one global
  timeout covers at most five redirects.
- Ureq's body limiter wraps the encoded source below gzip/Brotli decoding. Flux uses `max + 1` at
  that layer and a second `Read::take(max + 1)` above decoding, accepting exactly-at-limit bodies
  while rejecting raw overflow and decompression amplification independently.
- Template preflight validates every remote rule-set URL and exact supported field set before the
  subscription request. The pinned Sing-Box rule-set documentation confirms the rewritten local
  binary shape is exactly `type`, `tag`, `format`, and `path`.
- Every decoded rule-set response contributes to the aggregate refresh-work budget, including two
  responses with identical bytes. Content-addressed storage still deduplicates those identical
  bytes, preventing repeated downloads from bypassing the work bound while avoiding duplicate
  persisted assets.
- Debug/error output exposes only typed failure categories, bounded sizes, and digests. It does not
  retain raw subscription/rule-set URLs, invalid header values, transport-source strings, template
  bytes, node bodies, or rewritten engine JSON.
- Focused evidence: 35 config tests, 18 subscription tests, and 36 `xtask` tests passed; four
  process/oracle fixtures remained intentionally ignored. Strict Clippy passed for `fluxd` and
  `flux-core`; rustfmt and diff hygiene passed.
- Fresh `cargo xtask check-android` now validates NDK `27.3.13750724`, binds its API-31 compiler for
  Cargo and `cc`, and passes through `ring`, Rustls, and `fluxd`. CI installs the same NDK. This does
  not prove DNS, TLS handshake/root behavior, memory use, WSA behavior, or physical ARM64 runtime.
- Static WebPKI trust intentionally excludes Android user-installed and enterprise roots and does
  not inherit Android CA distrust/revocation updates. Private endpoints need a future typed custom-
  CA contract or deliberately hosted platform verifier; disabling TLS verification is not allowed.

## P0-B1.3 Validated Snapshot Store Evidence (2026-07-26)

- `subscription::store` is a deep private Module with two mutating operations: recover the current
  verified state or publish one prepared candidate. Callers do not sequence object writes,
  Sing-Box validation, history rotation, corruption fallback, or pruning.
- The schema-1 index is capped at 128 KiB and contains only typed metadata for one active and at
  most one predecessor. Configs use `<sha256>.json`; binary rule sets use `<sha256>.srs`. Loaded
  state must use canonical lowercase digests, unique bounded tags/assets, nonzero nodes, exact local
  rule-set paths, and the original domain-separated prepared-snapshot digest.
- Config reads remain capped at the 16 MiB engine limit and all assets together at 64 MiB. Managed
  directories are capped at 4,096 entries for enumeration; excess or removal failure becomes
  explicit cleanup-pending state rather than unbounded allocation or false publication failure.
- The existing no-follow record I/O now provides descriptor-anchored directory listing and
  descriptor-relative `unlinkat` removal. It never uses a path-based `read_dir` through the store
  ancestry. Managed symlink entries are unlinked themselves, ancestor symlinks stop recovery, and
  unknown filenames are preserved.
- Recovery rehashes every referenced object. A corrupt active promotes only a fully verified
  predecessor; a corrupt predecessor is dropped without disturbing active; two corrupt snapshots
  atomically become honest empty state. Unsupported future index schemas are left untouched.
- Candidate objects are durable but unreferenced before validation. The production Adapter binds
  the already accepted Sing-Box binary and launcher digests, opens and pins binary/config/launcher
  descriptors, runs the bounded check against final asset paths, and rehashes all candidate objects
  afterward. Only an atomic index replacement commits the candidate.
- Deterministic tests cover identical no-op publication, two-snapshot rotation, active promotion,
  corrupt-predecessor removal, two-corrupt empty recovery, malformed/future indexes, final-entry and
  ancestor symlinks, persistence failure, validator rejection, post-check mutation, cleanup state,
  and a real pinned shell check with same-path engine-binary drift.
- Focused result: 32 subscription tests passed. Full `fluxd` result: 352 passed and four privileged
  namespace fixtures remained intentionally ignored. Strict Clippy, rustfmt, diff hygiene, and the
  pinned Android/API-31 cross-check passed. No dependency-audit binary, WSA runtime target, or
  physical ARM64 device was available, so those claims remain absent.

## P0-B1.4 Runtime Connection Evidence (2026-07-26)

- `LegacyControlBridge` owns one serialized worker and invokes `RuntimeCoordinator::maintain` every
  50-250 ms. HTTP/DNS/TLS, subscription parsing, rule-set downloads, Sing-Box candidate checks, and
  snapshot-store mutation must execute on a separate bounded worker; only a completed validated
  snapshot may cross back into coordinator maintenance.
- `RuntimeCoordinator::reload_prepared` already prepares before capture detachment and restores the
  prior Generation when candidate activation fails. B1.4 should reuse that path rather than add a
  second lifecycle state machine.
- `ProcessRuntimeWriter::prepare` currently calls `publish_bridge_preparation`, which always rereads
  `engine.template`; `compile_bridge_environment` also rejects `subscription.enabled = true`.
  Therefore side publication alone cannot work: the writer needs a typed exact subscription input,
  and the temporary bridge may admit enabled subscription intent only when that input reconstructs
  the canonical TPROXY artifact byte-for-byte.
- The snapshot index is committed by B1.3 before runtime reload. To preserve both the prior running
  Generation and prior durable active snapshot on reload failure, the worker/coordinator seam needs
  an acknowledgement: accept leaves the candidate active; reject conditionally restores the exact
  predecessor (or prior empty index) before completing the manual request.
- Store files currently inherit no-follow record modes (`0700` directories and `0600` files).
  Packaged Desired State runs Sing-Box as UID/GID 0, so B1.4 can remain correct by explicitly
  rejecting enabled subscription for non-root engine credentials. Secure non-root traversal/read
  modes are a later compatibility requirement, not an implicit chmod in this phase.
- The B1.4 worker owns one synchronous refresh operation behind a capacity-one request/completion
  exchange and an atomic busy gate. Manual callers receive a result only after the serialized
  coordinator acknowledges acceptance or rejection; a missing acknowledgement within 30 seconds
  conditionally restores the published store candidate.
- Startup recovers without network access when a verified snapshot exists, performs one bounded
  bootstrap fetch only for enabled intent with no recoverable snapshot, and never fetches for
  disabled intent. Periodic scheduling follows the latest completed Desired State observation.
- Five deterministic worker tests cover busy gating, accepted completion, activation rejection,
  missing-ack rollback, periodic disablement, and canonical content-digest mismatch. Focused
  `cargo test -p fluxd subscription --no-fail-fast` passes 43 tests after runtime connection.
- Validated refresh candidates retain the exact `FluxConfig` observed during validation. The
  subscription preparation path requires enabled intent, rejects any later Desired State drift,
  and publishes the exact canonical artifact already accepted by the store.
- `ProcessRuntimeWriter` stages a candidate subscription source during preparation but replaces its
  retained source only after `StateRunning` publication. Candidate failure preserves the prior
  source, and an ordinary later reload cannot silently retry a rejected snapshot.
- `RuntimeCoordinator::maintain` polls completed refreshes only after engine/capture maintenance,
  uses the existing `reload_prepared` path, waits for candidate retirement or rollback before
  acknowledging rejection, and preserves the prior Generation on failure. A stopped runtime accepts
  a validated refresh only as deferred source rather than claiming activation.
- Protocol v3 now adds one mutating `subscription_update` command without changing existing wire
  shapes. It uses the capability mutation gate and exact peer/request-ID deduplication, returns a
  typed disposition with optional Generation/node count plus cleanup state, and rejects incoherent
  combinations or worker failures through stable codes.
- `SocketControlClient`, `DaemonClient`, and `fluxd subscription update` use that same operation.
  Updated, updated-deferred, unchanged, and disabled are explicit successful outputs; busy is
  explicit and exits nonzero rather than claiming completion; typed failures retain their rejection
  category.
- The synchronous first-start candidate carries its exact digest into the long-lived store worker.
  Initial runtime admission must explicitly accept it; admission failure rejects it before daemon
  failure completes, and a worker-start failure or premature drop runs the same conditional rollback
  guard. Exact-digest, accepted, and unaccepted-drop tests preserve the prior or honest empty index.

## P0-B1.4 Final Verification (2026-07-26)

- `cargo test -p fluxd subscription --no-fail-fast` passed 49 focused tests.
- `cargo test -p fluxd --test startup_reconciliation_admission --no-fail-fast` passed 9 tests, and
  `cargo test -p fluxd --test daemon_shutdown_signal --no-fail-fast` passed its live signal test.
- The latest complete `cargo test -p fluxd --no-fail-fast` passed the 280-test library target with
  four privileged cases ignored and passed every integration target.
- Strict all-target `fluxd` Clippy and repository rustfmt passed. `git diff --check` reported no
  whitespace errors; its only output was the existing CRLF normalization warnings.
- `TMPDIR=/tmp cargo xtask check-android` passed through `fluxd` with the pinned NDK/API-31
  toolchain. This is cross-compile evidence only. No WSA ADB target or physical ARM64 device was
  available, so no runtime or release qualification is claimed.

## P0-B1.5 Shell Updater Retirement Evidence (2026-07-26)

- `scripts/init` no longer declares freshness policy, reads `UPDATE_INTERVAL`, resolves an updater
  path, or invokes `scripts/updater.sh`. Both Rust-owned preparation and the mutually exclusive
  legacy rollback path now require one existing nonempty regular non-symlink canonical
  `conf/config.json` and never rewrite it through the updater.
- `scripts/lib` no longer exports `UPDATE_SCRIPT`. The file `scripts/updater.sh` remains unchanged
  and remains required only by the development bridge package profile as a frozen comparison
  artifact; the Rust-only profile already forbids it and B3 owns its package deletion.
- The existing Rust-owned regression still installs a hostile updater that would record invocation
  and fail. A new legacy regression removes the updater entirely, ages `config.json`, and requires
  successful initialization with byte-identical config preservation.
- `tests/shell/run-dispatcher-tests.sh` passed after the change. A repository search found no
  runtime updater reference outside the frozen script itself; remaining mentions are package
  inventory, tests, historical research, and documentation that identifies the non-invoked oracle.
- README (English and Chinese), development guide, blueprint, technical specification, project
  review, and canonical roadmap now describe the production-connected Rust subscription worker,
  exact store/reload rollback handshake, manual CLI outcomes, root-engine store limitation, static
  WebPKI trust boundary, and compile-only Android evidence.
- Final B1.5 verification passed shell syntax, the complete dispatcher shell suite, 49 focused
  subscription tests, strict all-target `fluxd` Clippy, rustfmt, the pinned Android/API-31
  cross-build, diff hygiene, and `TMPDIR=/tmp cargo xtask ci`. The full CI run reported 280 passing
  `fluxd` library tests with four privileged ignores, all integration targets passing, and 36
  passing `xtask` tests with four intentional fixture ignores.

## P0-B2.0 Direct-Control Inventory (2026-07-26)

- `scripts/fluxctl` already executes `fluxd control` for start, stop, restart, reload, and resync,
  and executes `fluxd status` for status. Only `diagnose`, `rules-preview`/`preview`, and `logs`
  retain shell implementations.
- The legacy diagnostic concatenates shell PID/module state, two cache files, filtered `ip rule`
  and `iptables-save` output, and a best-effort Sing-Box check. Its output is unversioned, partially
  retrospective, and suppresses command failures; it is not an authority source.
- Legacy `rules-preview` is not purely observational: it invokes `dispatcher cache-preview`, which
  rebuilds shared rule caches under the dispatcher lock and emits no Generation receipt. The Rust
  replacement must compile into memory and expose a non-authorizing report without publishing any
  cache or writer evidence.
- `scripts/flux-event` is a thin argv-preserving Adapter that only executes `fluxd event`. The
  protocol maps create/delete of `disable` and close-write events for `settings.ini`, `config.json`,
  and `addrsyncd.toml`; it currently ignores `watched_path` and does not cover authoritative
  `flux.toml`, the configured engine template, or the subscription URL file.
- `flux_service.sh` owns a second long-lived `inotifyd` process, watches the module directory and
  `conf/`, and treats persistent watcher loss as a reason to terminate a healthy daemon. This is
  removed only after `DaemonReactor` owns typed path observation and watch-loss reconciliation.
- `DaemonReactor` currently multiplexes the control listener, shutdown signalfd, worker eventfd,
  and optional route-network inventory. It has one natural epoll seam for bounded file observation;
  adding a separate watcher thread or daemon would duplicate lifecycle and loss handling.
- At the B2.0 inventory checkpoint there was no shipped uninstall/offline-cleanup script;
  `customize.sh` contained installer rollback and upgrade cleanup only. Daemon startup invoked
  bridge `startup-recover` before current config, while neither `fluxd recover --offline` nor
  `cleanup --offline` existed. B2.3 supersedes this recorded baseline.
- The smallest removal order is Rust read-only commands, direct lifecycle aliases, internal file
  observation, event-adapter removal, daemon-exclusive offline cleanup, CLI-wrapper removal, then
  B3 package deletion. Production remains on `ProcessRuntimeWriter`, and no native networking or
  Android authority is introduced by B2.

## P0-B2.1 Direct Rust Control And Inspection (2026-07-26)

- `fluxd start|stop|restart|reload|resync` are direct aliases of the existing authenticated control
  operation. `diagnose`, bounded `logs`, and `backend explain`/`plan`/`rules-preview`/`preview` are
  additive same-effective-user protocol-v3 operations and are excluded from mutation gating and
  request-result deduplication.
- Logs expose only fixed `runtime`, `daemon`, and manifest-selected `engine` streams. Requests accept
  1..=1,000 lines, read at most a 256 KiB source tail through a regular-file/no-follow descriptor,
  and reject arbitrary filesystem paths.
- Diagnostics combine an authoritative live status request with bounded Desired State, manifest,
  and fixed-log observations. Engine-log resolution uses a strict manifest summary that validates
  all fields but does not hash launch artifacts; the production preparation path retains full
  artifact identity inspection.
- Explain loads schema-3 Desired State plus the bounded engine template, compiles canonical TPROXY
  engine JSON in memory, and reports configured capture/application/interface/safety intent,
  canonical engine digest/size, and fenced-bridge representability. It is explicitly
  `non_authorizing` and creates no Generation, cache, receipt, or writer lease. Android package UID
  resolution and live Network Inventory are intentionally absent, so this is not a complete Capture
  Program or activation plan.
- `scripts/fluxctl` is now only a temporary argument-forwarding adapter. Its shell status,
  diagnostics, shared-cache preview, and arbitrary-file `tail` implementations are gone; B2.4 owns
  final removal after internal observation and offline cleanup land.
- Final B2.1 verification passed rustfmt, all-target `fluxd` compilation, strict Clippy, 30 focused
  Rust tests, shell syntax, the isolated wrapper-delegation suite, the complete `fluxd` suite, the
  pinned Android/API-31 cross-build, diff hygiene, and `TMPDIR=/tmp cargo xtask ci`. The complete
  library target reported 285 passed with 4 expected privileged ignores; `xtask` reported 36 passed
  with 4 fixture ignores. No WSA target or physical ARM64 device was available.

## P0-B2.2 Native File Observation (2026-07-26)

- `flux-platform::file_observer` owns one nonblocking close-on-exec inotify descriptor and watches
  parent directories for the authoritative Desired State, selected engine template, selected
  subscription URL file, and module `disable` entry. Each readiness turn is capped at eight 16 KiB
  reads. Directory ancestry is opened without following symlinks.
- Atomic replacement, `IN_Q_OVERFLOW`, `IN_IGNORED`, self-delete/move/unmount, missing parents, and
  ancestor-directory replacement become full typed reconciliation facts. Missing watches retry at
  250 ms; directory identity is checked every second; repeat issue logs are bounded.
- `DaemonReactor` owns the descriptor, epoll token, and retry deadline. Recoverable watch-install
  issues retain daemon service, while fatal descriptor/read failures terminate the reactor. The
  callback can replace the dynamic template/URL target set after a valid Desired State reload.
- `LegacyControlBridge` now accepts only `ConfigurationInputsChanged` and latest
  `DisableStateChanged` facts through a two-slot coalescer plus one best-effort wake. The reactor
  never waits for writer completion; the existing worker remains the sole mutation scheduler and
  drains observations after normal requests even when its bounded request queue was full.
- Only mutation-capable daemon profiles attach file observation. A pre-admission metadata
  fingerprint plus initial reactor reconciliation closes the startup gap without forcing an
  unconditional reload. Invalid Desired State queues a fail-closed reload but retains the last valid
  dynamic watch set; an invalid `disable` path is treated as disabled.
- Successful observed reloads schedule the Rust subscription worker immediately. Busy observations
  retain one pending refresh, repeated facts coalesce, and configuration deferred while disabled
  schedules refresh when `disable` removal consumes the dirty inputs.
- `flux_service.sh` no longer supervises `inotifyd`; `scripts/lib` no longer exports
  `FLUX_EVENT_SCRIPT`; and the dispatcher no longer invokes `scripts/flux-event`. The adapter file
  and bridge manifest entries remain unchanged as no-caller B3 package-removal artifacts.
- Focused verification passed 11 bridge tests, 16 reactor tests, 52 subscription tests, the live
  disable/template/SIGTERM daemon test, shell syntax, and the dispatcher suite. Strict rustfmt and
  all-target Clippy passed; the full `fluxd` library target passed 288 tests with four privileged
  ignores and every integration target passed. The pinned Android/API-31 cross-build and full
  `cargo xtask ci` passed. `git diff --check` reported only existing CRLF normalization warnings.
- No WSA ADB target or physical ARM64 device was available. Android evidence is cross-build only;
  no runtime, device, native-networking, or release qualification is claimed.

## P0-B2.3 Daemon-Exclusive Offline Cleanup (2026-07-26)

- `fluxd daemon` acquires `/data/adb/flux/run/fluxd.lease` before shutdown-signal setup, capability
  collection, startup recovery, configuration loading, or socket admission and retains the lease
  through complete reactor shutdown. Offline cleanup acquires the same nonblocking exclusive
  `flock`, so daemon startup and recovery cannot overlap while the socket is absent.
- Lease ancestry is opened descriptor-relatively with `O_NOFOLLOW`; the final parent and regular
  single-link lease file must be owned by the effective UID and not writable by group or other.
  Parent traversal, symlinks, nonregular entries, and unsafe metadata fail closed. File presence,
  stale PID/socket/watchdog hints, and an unlocked lease inode are never liveness evidence.
- `DaemonLease::drop` explicitly issues `LOCK_UN` before closing the descriptor. Repository CI
  exposed that `O_CLOEXEC` alone permits a concurrent child to retain the shared open-file
  description during the short fork-to-exec window; a deterministic duplicated-descriptor test now
  proves that lease lifetime ends with the Rust owner even during that window.
- `fluxd cleanup --offline` is dispatched before socket-client construction and accepts no other
  syntax. It holds the lease around the existing bounded `ProcessPhaseDispatcher::StartupRecover`
  operation and returns `0` complete, `75` daemon active/starting, `2` usage, or `1` lease/recovery
  failure. No `recover --offline` alias, rule reconstruction, table scan, or native writer selection
  was added.
- Module `uninstall.sh` contains only policy-free delegation: `ping` plus serialized Rust `stop`
  when the daemon answers, otherwise the exact Rust offline command. It reads no PID or ownership
  record and contains no networking command. The installer extracts it with mode `0700`; at the
  B2.3 checkpoint both checked profiles required it, producing 29 bridge, 13 Rust-only, and 16
  forbidden paths. B2.4 later removed `scripts/fluxctl` from the bridge difference.
- Seven focused lease/cleanup unit tests and two binary cross-process tests passed. Sandboxed shell
  coverage proved online stop, no-daemon offline fallback, failed-stop fallback, and exit-75
  propagation. Dispatcher, `fluxctl`, installer, strict Clippy, rustfmt, pinned Android/API-31
  cross-build, full `cargo xtask ci`, manifest parsing, and diff hygiene all passed. Full CI reported
  295 passing `fluxd` library tests with four privileged ignores and 36 passing `xtask` tests with
  four intentional fixture ignores.
- No WSA ADB target or physical ARM64 device was available. Android evidence is compile-only;
  runtime behavior, native-networking qualification, physical-device authority, and release
  qualification remain unclaimed. B2.4 is the next host-executable slice.

## P0-B2.4 Rust-Only Command Surface And Package Contraction (2026-07-26)

- `scripts/fluxctl` and its isolated shell test are deleted. `scripts/lib`, `scripts/init`, CI, the
  package profiles, and `xtask` no longer name, validate, stage, or invoke the wrapper. Supported
  lifecycle, status, diagnostic, bounded-log, and explain/preview commands enter through `fluxd`.
- Direct `scripts/dispatcher start` without `FLUXD_BRIDGE=1` now returns usage exit `2` before
  configuration loading or component mutation. The internal fenced bridge verbs remain available
  only to `ProcessRuntimeWriter`; production writer selection is unchanged.
- The dispatcher `cache-preview` implementation and mutation-oriented shell fixtures are removed.
  Rust `rules-preview` and `preview` remain aliases for the in-memory, non-authorizing explanation
  path and publish no Generation, cache, receipt, or writer lease.
- The checked package contract is now exactly 28 bridge-required paths, 13 Rust-only required
  paths, and the exact 15-path bridge difference as Rust-only forbidden. `scripts/flux-event`
  remains a no-caller development-bridge artifact for deletion with the other legacy files in B3.
- Active English, Chinese, architecture, development, and research guidance now uses the `fluxd`
  command surface. Changelog entries, the explicitly superseded legacy baseline, archived design
  alternatives, and dated B2.1/B2.3 evidence retain historical names and counts.
- Focused verification passed shell syntax, the dispatcher and installer suites, 16 direct
  `fluxd` CLI/offline integration tests, and all 40 `xtask` tests (36 passed, 4 fixture ignores).
  Strict `fluxd`/`xtask` Clippy, rustfmt, the pinned Android/API-31 cross-build, and
  `TMPDIR=/tmp cargo xtask ci` passed. Full CI reported 295 passing `fluxd` library tests with 4
  privileged ignores and 36 passing `xtask` tests with 4 fixture ignores.
- No WSA ADB target or physical ARM64 device was available. The run provides host and Android
  cross-build evidence only; runtime, native-networking, physical-device, and release qualification
  remain unclaimed. B3 package contraction is the next host-executable slice.

## P0-B3.0 WSA Canary Toolchain Repair (2026-07-26)

- WSA 2407.40000.4.0 was started through its installed AppX entry and exposed Windows ADB at
  `127.0.0.1:58526`. The authorized device reports Android 13 / SDK 33, x86_64, and rooted Magisk
  context. The Windows Computer Use runtime could not attach from the WSL-mounted repository URI, so
  only installed AppX, PowerShell inspection, and explicit Windows ADB command surfaces were used.
- Adding Rust HTTP/TLS introduced `ring`, whose `cc-rs` build does not consume Cargo's target linker
  variable. The x86_64 WSA runner exported `CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER` but omitted
  `CC_x86_64_linux_android`, causing a deterministic pre-device build failure. The runner now binds
  both to the exact pinned NDK/API-31 compiler.
- A command-construction regression observes the actual Cargo environment. It failed on the missing
  native compiler before the fix and passes afterward. Linux-only subscription validator fixture
  imports are now target-gated so the Android test cross-build is warning-free.
- The exact repository WSA runner passed twice after the fix. Each run bound device fingerprint and
  boot ID, pushed the exact x86_64 Android test ELF, ran only the ignored local-OUTPUT TPROXY
  checkpoint, passed the dual-stack transaction, and removed its private `/data/local/tmp` directory.
- Focused verification passed all 41 `xtask` tests (37 passed, 4 fixture ignores), strict all-target
  `fluxd`/`xtask` Clippy, rustfmt, and the pinned ARM64/API-31 cross-check. WSA remains development
  mechanism evidence and no physical ARM64, production-networking, or release authority is claimed.

## P0-B3.1 NDK-r27 16 KiB ELF Contract (2026-07-26)

- The primary-source report at
  `docs/research/android-16kb-elf-compatibility-2026-07.md` pins the current Android guide, exact
  r27d build-system behavior, LLVM LLD, Bionic loader, AOSP helper, and Cargo configuration. NDK
  r27d defaults to 4 KiB. Raw Cargo final links must pass both
  `-Wl,-z,max-page-size=16384` and `-Wl,-z,common-page-size=16384`; CMake/ndk-build opt-ins are not
  interpreted by Cargo.
- The pre-change real ARM64 release artifact had four `PT_LOAD` headers and every `p_align` was
  `0x1000`. The centralized ARM64 release/check and x86_64 canary Cargo command environments now
  carry both target-specific Rust linker arguments. The existing pinned compiler variables remain
  unchanged for Rust linking and `cc-rs` native compilation.
- `build-android` now parses and validates the final `fluxd` artifact after linking. Package
  verification applies the same structured AArch64 ELF parser to every manifest binary and rejects
  a non-empty `PT_LOAD` unless its alignment is a power of two at least `2**14`, its file offset and
  virtual address are congruent, and the existing bounds/entry checks pass.
- The fixture matrix accepts 16 KiB and 64 KiB alignment, rejects 8 KiB, and rejects a later 4 KiB
  load segment after a compliant first segment. This closes the blind spot in AOSP's convenience
  helper, which checks only the first `LOAD` line.
- The final ARM64/API-31 cross-build passed the in-process verifier. Independent NDK
  `llvm-readelf -lW` output showed exactly four load segments, all `0x4000`. This is cross-build and
  structural evidence only because no physical ARM64 or 16 KiB Android runtime target was present.
- The connected WSA target reported `PAGE_SIZE=4096`. Its exact rooted local-OUTPUT TPROXY canary
  passed 1 test with 277 filtered, while the x86_64 final test ELF independently showed four
  `0x4000` load segments. The runner removed `/data/local/tmp/flux-output-tproxy.xyzWWC`; an exact
  root `ls` returned `No such file or directory`, and a prefix-wide `find` returned no entries.
  This is 4 KiB x86_64 mechanism evidence, never 16 KiB runtime, ARM64, production, or release
  authority.
- Focused `xtask` verification passed 43 tests (39 passed, 4 intentional fixture ignores). The
  first compile rejected crate-root `pub(super)` visibility and was corrected to private
  ancestor-visible constants. One exact cleanup probe exposed Windows-ADB compound-command quoting;
  single-command probes supplied the retained cleanup evidence.
- Final B3.1 quality gates passed repository rustfmt, strict all-target `xtask` Clippy, the pinned
  ARM64/API-31 `check-android`, `git diff --check`, the new research-index target, and the scoped
  high-confidence secret scan. Clippy's only initial finding was an elidable helper lifetime; the
  correction was formatting-only and the unchanged 43-test suite remained green.

## P0-B3.2 Rust-Only Platform-Glue Policy (2026-07-26)

- `xtask` applies the new source policy only to the Rust-only profile and only to the exact final
  glue inventory: `META-INF/com/google/android/update-binary`, `customize.sh`, `flux_service.sh`,
  and `uninstall.sh`. The development bridge path and `ProcessRuntimeWriter` remain unchanged.
- Every glue source is limited to 128 KiB of non-NUL ASCII. Inspection lowercases text, collapses
  whitespace, and joins LF/CRLF shell continuations before requiring installer, `fluxd daemon`, and
  online/offline uninstall delegation markers.
- Exact executable tokens reject networking/kernel mutation, subscription clients, `jq`/`awk`
  configuration compilation, and `eval`. Normalized fragments reject sysctl/BPF paths, TPROXY and
  mark implementation, legacy configuration/runtime paths, owned-state cleanup, direct Sing-Box
  orchestration, `sh -c`, and backtick command construction.
- A minimal Rust-only fixture passes. Eight hostile fixtures cover `iptables-restore`, `curl`, `jq`,
  `awk`, the active-runtime ownership path, the legacy script library, `eval`, and `sh -c`, including
  split-line command attempts. Oversized and non-ASCII sources also fail.
- A fixture composed from the four unchanged live bridge glue files passes bridge content validation
  and is rejected by the Rust-only policy. The complete bridge package fixture still fails the
  Rust-only contract first on the exact forbidden `bin/addrsyncd` path.
- Focused verification passed all 46 `xtask` tests (42 passed, 4 intentional fixture ignores) and
  strict all-target `xtask` Clippy. No Android runtime or physical-device claim is part of B3.2.

## P0-B3.3 Exact Rust-Only Staging (2026-07-26)

- `packaging/rust-only/customize.sh` and `packaging/rust-only/flux_service.sh` are the only
  profile-specific source overrides. The shared update binary and `uninstall.sh` are already minimal
  and policy-compliant, so they remain one source for both profiles.
- One static source resolver is used by staging and verifier source-byte binding. Tests stage from
  the actual checkout: bridge selects 28 root paths, while Rust-only selects exactly 13 paths and
  copies both overrides under their manifest names without staging the `packaging/` directory.
- Every one of the 15 declared bridge-only paths was inserted into an otherwise exact Rust-only
  stage and rejected by its exact path. A staged override byte change also failed against its
  authoritative `packaging/rust-only/` source.
- The existing `scripts/config` and `scripts/rules` files are sourced bridge fragments rather than
  executable entries. Removing them from the shebang-only list allows the real 28-path bridge source
  tree to pass staging without changing either file or weakening exact source/inventory binding.
- The Rust-only installer supports a clean install only. It refuses an existing
  `/data/adb/flux`, stages `bin/` and `conf/` on the same filesystem, installs the module-local
  service/uninstaller/metadata, applies permissions, and publishes the runtime tree only after all
  required files exist. Shell performs no bridge migration or runtime-state cleanup.
- The minimal service performs a bounded boot wait and at most five `fluxd daemon` launches, with
  capped exponential delay and no networking, recovery, PID, or ownership-record logic.
- A new required Bubblewrap suite verifies fresh placement, absence of legacy scripts/binaries,
  fail-closed reinstall, exact daemon-only invocation, recovery on attempt three, and final failure
  after attempt five. The existing bridge installer suite remains unchanged and passes.
- Focused verification passed 48 `xtask` tests (44 passed, 4 intentional fixture ignores), strict
  all-target Clippy, both installer suites, and shell syntax. Production still constructs
  `ProcessRuntimeWriter`; the Rust-only profile remains `failing-until-complete` and is not runtime,
  device, or release evidence.

## P0-B3.4 Structural Package Gate Closure (2026-07-26)

- Active README, blueprint, roadmap, project review, and development guidance now describe the exact
  Rust-only stage as structurally complete while the 28-path development bridge remains the active
  rollback boundary. The Rust-only installer is explicitly fresh-install-only; shell never migrates
  or deletes bridge runtime state.
- The final `TMPDIR=/tmp cargo xtask ci` run passed with pinned NDK r27d: 295 `fluxd` library tests
  passed with four privileged ignores, 44 `xtask` tests passed with four fixture ignores, and all
  workspace, documentation, and ARM64 cross-check targets passed.
- The final ARM64 release artifact was 4,128,000 bytes with SHA-256
  `5a49abc896ccb95593de2f0bb088c501ce4f99c96bbaae84790fcc94fd26aa36`. Independent pinned-NDK
  `llvm-readelf -lW` inspection found four `LOAD` segments, each aligned to `0x4000`.
- Authorized WSA at `127.0.0.1:58526` reported WSA 2407.40000.4.0, Android 13 / SDK 33, rooted
  x86_64, and `PAGE_SIZE=4096`. The exact local-OUTPUT TPROXY checkpoint passed one test with 277
  filtered; its x86_64 ELF also exposed four `0x4000` load segments.
- The WSA runner removed `/data/local/tmp/flux-output-tproxy.BcLpuT`. Exact-path and prefix-wide
  probes found no retained directory. WSA remains 4 KiB x86_64 mechanism evidence and cannot bind a
  physical ARM64 device profile or authorize `NativeRuntimeWriter` selection.
- Full Bash syntax, config/installer contract, rules-generation, dispatcher, bridge installer, and
  Rust-only installer/watchdog suites passed. Production source inspection still finds
  `ProcessRuntimeWriter::new` in `crates/fluxd/src/daemon.rs`; no cutover occurred.
- Final rustfmt and diff-integrity checks passed. Scoped stale-status and high-confidence secret
  searches returned no matches, and the complete seven-file documentation/plan diff was reviewed.
- B3 has exhausted the independent host/package work. C1/C2 on a rooted physical ARM64 target are
  now the exact prerequisites for target authority and the later Gate 1 writer transfer.

## P1-R1 Host Assurance Review (2026-07-26)

- The workspace already enforces `unsafe_op_in_unsafe_fn = "deny"` and
  `clippy::undocumented_unsafe_blocks = "deny"`. Strict all-target Clippy passed with the explicit
  lint enabled. The member production/tool `src` trees contain 27 files with 213 actual
  `unsafe { ... }` blocks and 216 `SAFETY:` annotations. Including integration-test targets under
  `crates/` raises that census to 38 files, 264 blocks, and 267 annotations. A broad token search
  finds one extra file because `DiagnosticState::Unsafe` is an enum variant rather than unsafe Rust.
  The complete target set also declares one Android `unsafe extern "C" fn` callback and three
  unsafe foreign blocks; no unsafe trait or impl is present. This is a corrected mechanical census,
  not the explicit unsafe-boundary audit still required by the release roadmap.
- The host provides unprivileged user/mount/network namespaces plus `ip`, xtables, and Bubblewrap.
  Required-mode `cargo xtask test-functional-canary-linux` passed one exact disposable dual-stack
  topology/cleanup test with 298 filtered.
- Required ingress TPROXY refused to run because `xt_TPROXY` was not already active. Required
  local-OUTPUT TPROXY found no already-active module/procfs/built-in support proof. The tests did not
  load a module, preserving the project policy that Flux cannot manufacture kernel capability.
- Required distinct-UID preflight rejected inherited supplementary groups while outer `setgroups`
  is denied in this WSL environment. This keeps the credential mechanism unqualified rather than
  weakening its authority checks.
- The standard CI can honestly require the passing topology checkpoint as mechanism evidence. The
  stronger TPROXY, production-composition, and Android/device gates remain open and separately
  reported.
- The exact pidfd exit test passed after switching its wait primitive to pidfd readiness. Five
  repeated parallel `flux-platform` library runs each passed 350 tests with four privileged ignores,
  and strict all-target `flux-platform` Clippy passed.
- `TMPDIR=/tmp cargo xtask ci` passed, including workspace tests, documentation tests, strict
  Clippy, and the pinned ARM64/API-31 Android cross-check. The required topology checkpoint then
  passed again with one exact test and 298 filtered.
- Python structured workflow parsing, repository rustfmt, `git diff --check`, the scoped stale-
  authority search, and the high-confidence secret-signature scan passed. Independent Standards
  and Spec review found no source or authority-boundary issue after correcting the unsafe census.
- No GitHub-hosted runner execution is claimed for the unpushed workflow change. That evidence can
  exist only after the local commit is pushed or otherwise run on the hosted workflow; it is not a
  reason to weaken the required-mode failure contract locally.

## P1-R2 Rust Dependency Assurance (2026-07-26)

- Primary cargo-deny 0.20.2, RustSec, crates.io, and action sources are recorded in
  `docs/research/rust-dependency-assurance-2026-07.md`. The selected upstream musl archive is
  4,936,832 bytes and matched SHA-256
  `9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f`.
- The all-feature locked graph contains 113 packages: five workspace paths, 108 crates.io packages,
  and zero Git packages. With RustSec database commit
  `29638ff054fdbb83d2844240f7ef7e576cb52629`, advisories and sources passed immediately.
- The first license policy rejected only the five GPL-3.0-only Flux members and exact
  `webpki-roots 1.0.9` under CDLA-Permissive-2.0. The final deny-by-default policy allows the project
  license and constrains CDLA to that exact root-certificate data version; the complete policy then
  passed advisories, licenses, and sources without changing `Cargo.lock`.
- CI downloads the exact cargo-deny release rather than using its official Docker action, whose
  pinned Dockerfile does not verify the downloaded archive. The parsed checked-in workflow step
  passed end to end in a disposable Cargo home: checksum verification, extraction, live advisory
  refresh, locked metadata, and all three policy checks succeeded.
- A hostile run replaced the expected digest with 64 zeroes. `sha256sum --check --strict` rejected
  the archive before extraction, and no cargo-deny binary appeared under the temporary extraction
  root.
- This gate covers only the root workspace. The excluded `addrsyncd` bridge remains `UNLICENSED`
  and is forbidden by the Rust-only package; no workspace audit result is bridge-license approval,
  final package SBOM evidence, or reproducible-build evidence.
- Final `TMPDIR=/tmp cargo xtask ci` passed all workspace, documentation, strict Clippy, and pinned
  ARM64/API-31 cross-check gates. The required Linux topology checkpoint also passed one exact test
  with 298 filtered.
- Workflow/TOML contract parsing, extracted-step Bash syntax, repository rustfmt, diff integrity,
  local research-index binding, stale-status wording, and the high-confidence secret scan passed.
  All ten new primary-source URLs returned HTTP 200, and the complete fixed-point diff was reviewed
  on both Standards and Spec axes before staging.
- No hosted-workflow execution is claimed for the uncommitted R2 change. The live RustSec refresh is
  deliberately time-sensitive and may expose a new required failure when the hosted job first runs.
