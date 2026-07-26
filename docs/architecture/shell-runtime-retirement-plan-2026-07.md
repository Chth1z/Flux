# Shell Runtime Retirement Review And Implementation Plan

Date: 2026-07-26

Status: R0-R3 host implementation complete on 2026-07-26; R4-R6 require physical ARM64 C1-C3 and Gate 1 evidence.

## Decision

The next task should retire shell runtime ownership, not translate 5,573 shell lines into Rust line
by line. The target is one Rust-owned `fluxd` plus the external Sing-Box engine. Platform-required
install, boot, disable, and uninstall glue may remain shell outside `scripts/`, but no shipped shell
may compile configuration, supervise Sing-Box, observe runtime inputs, fetch subscriptions, mutate
networking, recover owned state, or implement cleanup.

The host-verifiable ownership work is complete. Rust owns Desired State compilation, subscription
processing, file/network observation, control, diagnostics, engine supervision, Generation
assembly, native resync/offline recovery, runtime layout/logs, and the private native
xtables/routing owner. The required privileged Linux gate now exercises that composition without a
dispatcher. The remaining work is device-bound: qualify one physical ARM64 target, transfer the
writer fence, delete the nine-file bridge and legacy binary surface, then promote and qualify the
Rust-only package.

## Review Boundary

- Branch: `codex/fluxd-rust-rewrite` at `35fdfc3`.
- Incremental code-review range: `e738e8c...HEAD` (nine commits).
- Primary design: `docs/architecture/implementation-roadmap.md`,
  `docs/architecture/fluxd-technical-specification.md`, ADR-0010, and ADR-0011.
- Planning baseline package contract: `conf/manifest.json` schema 2.
- Planning baseline script inventory: 11 files and 5,573 lines. The current bridge has nine scripts.

## Current Progress

| Area | Current state | Judgment |
|---|---|---|
| A1 Desired State | Complete schema-3 Rust configuration and canonical engine/capture compilation | Keep; remove only bridge renderers after cutover |
| A2 Generation assembly | Complete assembler, lineage, records, selected-source retention, and host/Android authority split | Host-ready; Android target conversion still requires physical authority |
| A3 address observation | Complete reactor-owned inventory and coordinator-synchronous native successor convergence | Host-ready; production bridge retains standalone `addrsyncd` until Gate 1 |
| A4 native writer | Required dispatcher-free privileged composition gate passes | Production still selects `ProcessRuntimeWriter` until physical C1-C3 and Gate 1 pass |
| B1 subscription | Rust fetch/compiler/store/reload path is source-stable across refresh and recovery | No-caller updater retired and denied from every package profile |
| B2 control/observation | Direct CLI, observation, bounded logs/layout, and native offline recovery exist in Rust | Public production offline cleanup still selects `BridgeOfflineRecovery` until writer transfer |
| B3 package | Exact 13-path Rust-only skeleton, 26-path bridge, and retired-path denylist are checked | Honest structural checkpoint; profile remains `failing-until-complete` |
| Gates 1/2 | Not passed | Do not select the native writer or publish a Rust-only release yet |

Production remaining on `ProcessRuntimeWriter`, `BridgeOfflineRecovery`, and
`StructuralOnlyCompatibility` is not a deviation. The real composition test and typed resync
semantics are complete, but the roadmap still requires physical C1-C3 evidence and the Gate 1
writer-fence transfer before native selection.

## Fixed-Point Review Resolution

The original review findings below were resolved during R0-R3 unless explicitly retained as a
device gate.

### Standards

- **Resolved P1:** canonical template loading now reuses descriptor-relative record I/O and rejects
  symlinks in final and ancestor components at publication, reconciliation, and inspection callers.
- **Partially reduced P2:** structural platform-glue and source policy moved into dedicated `xtask`
  modules. Further package-verifier extraction can wait until Gate 2 and must not delay the physical
  writer transfer.

### Spec

- **Resolved for native composition:** `NativeOfflineRecovery` performs bounded durable recovery,
  convergence to `Stopped`, a second recovery pass that retires the terminal journal, and verified
  clean absence. Public bridge cleanup remains deliberately selected until R4.
- **Resolved:** refresh and recovery bind the exact redacted subscription source; URL drift rejects
  the candidate or recovered snapshot without replacing the active source.
- **Resolved:** platform-glue policy parses a bounded command structure and rejects comment/string
  markers, adjacent quotes, variable commands, functions, substitutions, and owned behavior.
- **Resolved:** the native Generation source owns the accepted selected engine source and preserves
  an exact subscription artifact across address successors, failure, rollback, and recovery.

Production remaining on the shell writer, bridge offline recovery, and structural canary is an
explicit pre-cutover state, not scope regression.

## Host Deviations Closed

- `BridgeOfflineRecovery` and `NativeOfflineRecovery` are now distinct adapters. The native adapter
  is complete and exercised by the dispatcher-free composition; the public bridge command remains
  deliberately selected until Gate 1.
- Subscription refresh and startup recovery retain and compare the exact redacted URL source.
- Address successors retain the selected template or validated subscription source behind the
  native Generation module rather than reconstructing it in the reconciler.
- Platform-glue verification uses a bounded structural parser with hostile command-indirection
  fixtures.
- Template reads use descriptor-relative no-follow traversal at all three affected callers.
- Manifest schema 3 and source policy permanently deny the two retired no-caller script paths.

## Open Gates, Not Deviations

- Production and the public offline-cleanup command still select the bridge adapters. Changing
  either selection before the fenced physical writer transfer would violate the single-writer gate.
- The staged `fluxd` still exposes `render-legacy-rules`, `snapshot-legacy-packages`, and
  `attest-legacy-rules-set` (`crates/fluxd/src/main.rs:7-36`). This is needed by the active bridge but
  must disappear with that bridge before ADR-0011 can pass.
- Nine scripts, standalone `addrsyncd`, packaged `jq`, and legacy bridge configuration remain until
  Gate 1 proves the native writer on the qualified target.
- The Rust-only profile remains `failing-until-complete`; structural host staging is not release
  authority.
- Physical ARM64 C1-C3, Gate 1, final provenance/SBOM/reproducibility evidence, and Gate 2 remain
  external release requirements. WSA and host evidence cannot substitute for them.

## Script Ownership Matrix

| Script | Current caller class | Existing Rust owner | Remaining implementation/removal action |
|---|---|---|---|
| `addrsync` (248 lines) | Active bridge | `NetworkInventorySource`, `AddressReconciler`, typed native resync, native routing/owner | Select native owner at Gate 1, then remove standalone `addrsyncd` and script together |
| `config` (521) | Active bridge | `FluxConfig`, canonical compiler, bridge environment, Capability Profile | Do not port legacy settings/TUN knobs; delete compatibility environment and shell capability derivation after native target selection |
| `core` (125) | Explicit rollback only | `EngineSupervisor`, descriptor-pinned Sing-Box process adapters | No new port; remove legacy engine rollback after Gate 1 proves native rollback/cleanup |
| `dispatcher` (1,530) | Active bridge | `RuntimeCoordinator`, intent store, native source/writer, durable owner/archive, native recovery | Transfer the writer at Gate 1, then remove all phase dispatch |
| `init` (395) | Active bridge | Desired State/Generation preparation, engine validation, package verifier, `RuntimeLayout` | Delete cache/oracle preparation with the bridge |
| `lib` (1,065) | Active bridge utility | Typed Rust modules for paths, files, process identity, locks, and recovery | Do not create a Rust utility grab bag; remove after its last script caller is deleted |
| `log` (152) | Active bridge utility | Rust-owned bounded daemon/runtime sinks, rotation, and fixed-stream inspection | Remove with the bridge; omit cosmetic `module.prop` mutation and use CLI status as authority |
| `rules` (424) | Explicit rollback only | canonical Capture Program/lowerer, native target archive, frozen fixtures | Remove legacy CLI compiler and executable generator after Gate 1; keep test-only fixtures only while they add differential value |
| `tproxy` (566) | Active bridge writer | native xtables process adapter, durable owner, exact readback/rollback, privileged composition | Complete C1-C3, transfer the fence atomically, then delete the sole shell networking writer |

## Target Design Rules

1. One serialized Rust control/reconciliation worker remains. No replacement shell command runner,
   second daemon, or second netlink owner is introduced.
2. One immutable Generation binds Desired State, selected engine source, inventory, capability,
   Android planning authority, native target, predecessor, and functional evidence.
3. Subscription template bytes and validated subscription bytes are variants of one selected engine
   source. Address reconciliation cannot choose or reconstruct that source independently.
4. Manual resync reports `complete_no_change`, `successor_converged`, or `accepted_deferred`.
   Queued observation is never reported as completed kernel mutation.
5. Offline cleanup acquires the persistent daemon lease and requests only native
   `recover()` plus `converge(Stopped)`. It does not parse current Desired State or shell artifacts.
6. No native write occurs before physical authority and the Gate 1 fence transfer. No commit creates
   a dual-writer interval.
7. Legacy-only optional behavior is removed, not transliterated: TUN, nftables, eBPF, DIVERT,
   FakeIP ICMP, QUIC rejection, MSS clamping, and compatibility profiles stay unsupported unless a
   separate accepted requirement and authority gate adds them. Removing the bridge's forced MSS
   clamp requires physical PMTU and large-transfer regression evidence, including tethering.

## Implementation Sequence

### R0: Correct contracts before expanding the native path (Complete 2026-07-26)

1. Fix the subscription URL-file stability race and its adversarial rollback test. Recovery must
   compare the stored redacted source identity with the current bounded URL-file bytes before reuse.
2. Replace A3's embedded template-derived engine artifact with realization-neutral address/capture
   inputs. Introduce one selected-engine-source value that binds either the current template artifact
   or accepted subscription snapshot digest/bytes.
3. Add subscription-enabled address-successor tests proving the active engine artifact survives
   no-change, replacement, failed candidate, and rollback paths.
4. Extract a narrow offline-recovery interface. Keep `BridgeOfflineRecovery` explicitly
   development-only and correct B2.3 documentation until `NativeOfflineRecovery` is selected.
5. Make canonical template loading descriptor-relative and reject final or ancestor symlinks at
   every production/inspection caller.
6. Replace normalized-text platform-glue policy checks with bounded structural or canonical-syntax
   validation and adversarial fixtures.
7. Add an `xtask` source/caller guard that prevents new production references to `scripts/` and
   records the shrinking allowed bridge set.

Exit: the four host-correctable deviations have focused regression tests; offline cleanup has a
typed bridge/native boundary and is documented as partial pending R2. No production writer
selection or package status changes.

### R0.5: Remove already-replaced no-caller scripts (Complete 2026-07-26)

1. Delete `scripts/flux-event` after the reactor/file-observer tests prove no runtime caller or
   service launch remains.
2. Delete `scripts/updater.sh` after the R0 subscription fixes. Move only useful comparison inputs
   under `tests/`; do not preserve an executable updater oracle.
3. Remove both paths from the bridge-required inventory and move them out of the profile-difference
   set into a profile-independent retired-path denylist enforced against source and staged trees.
   Update the manifest schema/checker, README inventories, shell fixtures, and the roadmap's stale
   retain-until-Gate-1 statements so neither file can reappear as a runtime dependency.

Exit: the bridge inventory shrinks from 11 scripts to nine without touching writer authority. The
Rust-only profile remains `failing-until-complete`, and the remaining shell tests still protect the
active bridge.

### R1: Own runtime layout and logs in Rust (Complete 2026-07-26)

1. Add a descriptor-safe `RuntimeLayout` bootstrap before daemon lease acquisition. Create and
   validate only the exact root-owned `run/` and `state/` directories with bounded paths, no symlink
   traversal, explicit modes, and parent-directory synchronization where durability is required.
2. Add bounded daemon/runtime log sinks with severity, component, Generation correlation, maximum
   record size, maximum file size, one predecessor, no-follow open/rotation, and redaction tests.
   Keep the existing engine log owned by `EngineSpec`.
3. Route current daemon/coordinator diagnostics through those sinks and make `diagnose`/`logs`
   inspect files Rust actually owns. Do not port ANSI banners or dynamic `module.prop` decoration.
4. Add a staged-layout smoke using a host-built real `fluxd`, controlled capability fixtures, and a
   fake engine Adapter; separately retain Android execution for the device gate.

Exit: a fresh exact Rust-only layout reaches daemon initialization without `scripts/init` or
`scripts/log`, rotation is bounded and race-tested, and offline CLI lease acquisition works on that
layout.

### R2: Complete native Generation, resync, and offline recovery (Complete 2026-07-26)

1. Implement the production `NativeGenerationSource` around the existing assembler. Its target
   conversion must require a fresh one-shot Android planning authority; host inspection remains
   non-promotable.
2. Bind selected engine source, inventory epoch/snapshot, target archive, tool identity, routing
   identity, and predecessor into every normal and address-driven successor.
3. Move native resync semantics into the coordinator: reconcile a fresh complete snapshot and
   converge a successor synchronously when possible; otherwise request a full source resync and
   return `accepted_deferred`. Remove the final writer-level no-op.
4. Add a typed resync report through control, protocol, CLI, status, and duplicate-request caching.
   Because the wire format is strict and pre-release, bump the protocol rather than silently changing
   version 3.
5. Implement `NativeOfflineRecovery` using the native process converger's durable archive/journal,
   `recover()`, and `converge(Stopped)`. Require verified clean absence before success.
6. Test no-change, deferred dump, successor convergence, source loss, subscription-backed successor,
   rollback, crash recovery, stale/foreign ownership, partial cleanup failure, and idempotent offline
   cleanup.

Exit: every Rust runtime operation needed to remove `addrsync`, `dispatcher`, `rules`, and `tproxy`
exists behind non-production/test authority; all failure terminal states are old-active, new-active,
or verified clean absent.

### R3: Prove the real host composition (Complete 2026-07-26)

1. Add one production-composition constructor that wires real engine supervision, reactor inventory,
   native process converger, target archive, runtime coordinator, functional canary, logging, and
   offline recovery without `ProcessPhaseDispatcher`. It accepts only an already-admitted target;
   the Linux test injects a sealed test-only target at that boundary and cannot create Android
   authority.
2. Add a required privileged namespace test covering start, reload, subscription reload, address
   churn, forced engine exit, candidate failure/rollback, daemon crash recovery, stop, offline
   cleanup, and exact dual-stack xtables/RPDB/route absence.
3. Record subprocess execution and fail if any runtime `sh`, dispatcher, `addrsyncd`, `jq`, `curl`,
   AWK, or legacy CLI command is invoked.
4. Expose the exact test as `cargo xtask test-native-composition-linux` and require it in CI on a
   runner that supports the topology.

Exit: roadmap A4's real-composition host gate passes. This still does not grant Android mutation
authority or change production selection.

### R4: Qualify one physical ARM64 target and transfer the writer fence (P0, device-required)

1. Complete C1's explicit-serial read-only device/profile binding.
2. Complete C2 mark, RPDB, route, topology, VPN/per-origin egress, and one-shot planning authority on
   the same boot/namespace/binaries.
3. Complete C3 dual-stack TCP/UDP local-OUTPUT and forwarded canaries, netd restart, handover,
   tethering, owner/user, DNS/FakeIP, PMTU and large TCP transfer behavior without forced MSS
   clamping, failure injection, and exact cleanup.
4. Execute Gate 1: quiesce dispatcher and `addrsyncd`, prove legacy absence, transfer the shared
   writer fence, converge native routing/capture, require functional evidence, and exercise rollback
   without overlapping writers.
5. Only after stable repeated evidence, change `run_daemon` to construct the native writer and
   required functional canary for the qualified production profile.

Exit: production uses the native composition; manual resync and reboot/crash recovery pass on the
same physical target; no shell networking writer remains in the production call graph.

### R5: Delete the bridge and compatibility surface (P0, after Gate 1)

1. Delete the remaining nine files under `scripts/`, standalone `addrsyncd`, packaged `jq`,
   `settings.ini`, and `addrsyncd.toml`; remove every caller, manifest source, installer branch, and
   shell bridge test. Together with R0.5, all 11 original scripts are gone.
2. Delete `ProcessRuntimeWriter`, production `ProcessPhaseDispatcher`, bridge capability gates,
   shell writer records after their one-time retirement contract, and phase-dispatch error surface.
3. Delete `render-legacy-rules`, `snapshot-legacy-packages`, and `attest-legacy-rules-set` from
   `fluxd` and its help/protocol/tests. Keep only non-executable test fixtures needed for historical
   differential checks; never stage them.
4. Rename retained final control types that still say `Legacy` where the name now misstates their
   role. Do this after deletion, not as a prerequisite refactor.
5. Remove the bridge package profile. Keep an explicit final-package forbidden-path policy so any
   reintroduced script/helper/config artifact still fails verification.

Exit: `rg` finds no production caller or CLI surface for a removed component; the root workspace no
longer needs the excluded `addrsyncd` build; CI contains no bridge runtime job.

### R6: Promote and qualify the Rust-only package (P0/P1, Gate 2)

1. Change the profile from `failing-until-complete` only after R4/R5 and all required device evidence
   pass. A structural stage alone cannot authorize this change.
2. Stage exactly `fluxd`, Sing-Box, schema-3 configuration/assets, final platform glue, and metadata.
3. Verify source bytes, final CLI command inventory, ELF/load alignment, hashes, SBOM, licenses,
   provenance, reproducibility/signing, and the exact absence of all legacy paths.
4. Run fresh install, boot, status, enable/disable, restart, abnormal engine exit, dual-stack
   TCP/UDP/DNS, resync, online uninstall, stopped-daemon offline uninstall, reboot recovery, and exact
   cleanup on the qualified physical matrix.

Exit: Gate 2 and ADR-0011 pass. Only then may the rewrite be named a release candidate.

## Verification Matrix

| Check | Required checkpoint |
|---|---|
| Focused subscription/address/offline/native unit and integration tests | Every R0-R2 commit |
| `cargo fmt --all -- --check` and strict workspace Clippy | Every Rust commit |
| `cargo xtask ci` with pinned NDK/API-31 | Every Rust/package commit |
| `cargo xtask test-parser-fuzz-smoke` | Parser/FFI changes and final gate |
| Required existing Linux topology canary | Every native networking change |
| New required real native-composition namespace test | R3 onward |
| Bridge shell tests | Until the corresponding bridge component is deleted |
| Rust-only glue/staging hostile fixtures | Every package-policy change |
| Physical C1-C3 and Gate 1 evidence | Before production selection/deletion |
| Exact Rust-only stage/verify plus physical package matrix | R6/Gate 2 |
| `git diff --check`, stale-reference scan, secret scan, docs/link checks | Every checkpoint |

## Planning Verification

The planning pass verified the original repository shape and reran the standard local CI gate:

- the baseline `scripts/` tree contained exactly 11 files and 5,573 lines;
- the baseline manifest contained 28 bridge-required paths, 13 Rust-only-required paths, and the
  exact 15-path difference as Rust-only-forbidden;
- all 42 local Markdown links in this plan and its `docs/README.md` index entry resolve;
- heading structure, fixed-point `git diff --check e738e8c...HEAD`, and worktree `git diff --check`
  pass;
- `TMPDIR=/tmp cargo xtask ci` passes on the final planning state, including workspace tests,
  documentation tests, strict Clippy, and the pinned Android/API-31 cross-check.

The parser fuzz smoke, required Linux topology canary, and three shell suites passed earlier in this
same audit and were not rerun after the documentation-only edits. No WSA or physical ARM64 target was
used, so C1-C3, Gate 1, and Gate 2 remain unverified.

## R0-R3 Implementation Verification

- The current bridge contains exactly nine scripts; manifest schema 3 denies the two retired paths
  in every package profile. Bridge/Rust-only required-path counts are 26/13, and Rust-only forbids
  the exact 13-path bridge difference.
- Protocol version 4 reports `complete_no_change`, `successor_converged`, or `accepted_deferred` for
  address resync and rejects protocol versions 1 through 3.
- `cargo xtask test-native-composition-linux` passes the real dispatcher-free lifecycle, including
  ordinary reload, validated subscription reload, address successor, forced engine recovery,
  rejected candidate settlement, coordinator-drop recovery, stop, repeated native offline recovery,
  subprocess denial, and exact dual-stack cleanup.
- Native offline recovery executes `recover()` -> `converge(Stopped)` -> `recover()` so verified
  clean absence is followed by terminal-journal retirement before success.
- Final H6 verification passed strict all-feature workspace Clippy, repository formatting,
  `TMPDIR=/tmp cargo xtask ci`, the seven-test parser smoke, the required dual-stack topology and
  native-composition namespace gates, all bridge/package shell suites, 148 local Markdown targets,
  stale-reference scans, and `git diff --check`. The native composition lifecycle passed in 49.33
  seconds; the corrected process fixture passed 100 exact repetitions and eight concurrent full
  `flux-platform` library targets without weakening incomplete-stdin rejection.
- This is host evidence only. Production and public offline cleanup remain on bridge adapters; the
  nine remaining scripts are intentionally retained, and the Rust-only profile remains
  `failing-until-complete` until physical ARM64 C1-C3 and Gate 1 authorize R4-R6.

## Commit Order

1. `fix(subscription): bind refresh to stable url source`
2. `refactor(fluxd): bind address successors to selected engine source`
3. `fix(fluxd): reject ancestor symlinks in template sources`
4. `fix(xtask): validate rust-only glue command structure`
5. `refactor(runtime): remove replaced event and updater scripts`
6. `feat(fluxd): own runtime layout and bounded logs`
7. `feat(fluxd): add typed native resync and offline recovery`
8. `test(fluxd): require real native runtime composition`
9. `feat(fluxd): select qualified native runtime writer` (only with C1-C3/Gate 1 evidence)
10. `refactor(runtime): remove shell bridge and legacy helpers`
11. `feat(package): promote qualified rust-only profile` (only after Gate 2 evidence)

Do not combine production writer selection, bridge deletion, and package promotion into one commit.
The separate checkpoints preserve a reviewable writer-transfer boundary and a recoverable Git
history. Commits 9 and 10 must remain adjacent in one reviewed cutover series, with no release or
automatic shell fallback between them; package promotion remains a later independent gate.

## Definition Of Done

- All 11 original `scripts/` files are absent from production source and package inventories.
- Platform glue delegates install/boot/uninstall only; after delegation, `fluxd` reloads, resyncs,
  recovers, stops, and cleans up without spawning a shell or runtime helper.
- `fluxd` owns Sing-Box, configuration/subscription, observation, Generation reconciliation,
  xtables/RPDB/routes, address-derived policy, logs, recovery, and offline cleanup.
- Native manual resync distinguishes completed convergence from accepted deferred work.
- Every tested failure settles old-active, new-active, or verified clean absent.
- Production composition and the final binary expose no dispatcher, standalone `addrsyncd`, legacy
  rules compiler, updater, event adapter, or compatibility CLI.
- The exact physical ARM64 authority, functional/coexistence evidence, writer fence, package
  inventory, provenance, and device matrix pass before release status changes.
