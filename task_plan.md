# Task Plan: Audit and Resume the Flux Rewrite

## Goal
Reconcile the current implementation with the approved architecture and roadmap, remove only confirmed execution drift, then complete and commit the next coherent roadmap tasks with focused verification.

## Scope Priorities
- P0: Establish the authoritative plan, current Git state, and any deviations in the last execution path.
- P0: Correct inaccurate design/roadmap claims before building on them.
- P0: Remove or replace confirmed erroneous implementation artifacts without discarding unrelated user work.
- P1: Implement the next unblocked roadmap slice and add focused tests.
- P1: Commit each coherent, verified slice locally.
- P2: Defer unrelated refactors and later roadmap milestones.

## Phases
- [x] Phase 1: Read the architecture, roadmap, review artifact, and recent commit history.
- [x] Phase 2: Compare recent implementation behavior and tests against the design contracts.
- [x] Phase 3: Correct the plan/design and remove confirmed drift.
- [x] Phase 4: Execute every unblocked correction and stop at the physical-authority boundary.
- [x] Phase 5: Run focused and repository-level verification, review the final diff, and commit coherent slices.

## Key Questions
1. Which roadmap milestone and acceptance criteria are currently active?
2. Do the four local commits implement that milestone in the required execution order?
3. Are the uncommitted roadmap edit and `review_report.md` valid work products or execution drift?
4. What is the smallest unblocked implementation slice after reconciliation?

## Decisions Made
- Treat `docs/architecture/implementation-roadmap.md` as the current execution plan unless architecture documents or history establish otherwise.
- Preserve all pre-existing worktree changes until their intent and correctness are established.
- Use local commits only; do not push or open a pull request.
- Fix the two confirmed P1 behavioral defects before documentation or structural refactoring.
- Use the existing `SingBoxProcessAdapter` and serialized Android preflight report as the behavioral
  test seams established by the specification and current integration tests.
- Both confirmed behavioral defects are fixed and committed (`dbed3c4`, `22e8945`); preserve their
  verified behavior while correcting the remaining structural drift.
- Split compiler, I/O collector, and candidate responsibilities after behavior is green; do not add
  a new public writer or activation interface.
- Preserve `generation_engine_config` as the crate-private facade while moving implementation into
  `compiler`, `engine_profile`, and `candidate`; keep dependencies one-way and behavior unchanged.
- Share Android identity-property names, bounds, typed parsing, and verified-boot semantics from
  `flux-platform`; expose only validation to `xtask`.
- Keep physical ARM64 evidence explicitly pending because ADB enumeration is unavailable.
- Do not create a complete mark-dependent Generation from host fixtures; the next implementation
  must consume physical `AndroidMarkPlanningAuthority` for one selected target.

## Errors Encountered
- Initial Standards audit dispatch combined a full-history fork with an explicit agent role, which
  the collaboration tool rejects. No agent started and no repository state changed; relaunch with
  a self-contained prompt and no inherited conversation.
- `timeout 5s adb devices -l` exited 124 with no output. Physical Android qualification cannot be
  performed from the current environment; the roadmap requires this lane to remain paused rather
  than replacing device evidence with host fixtures.
- Expected red test: `cargo test -p flux-platform --test sing_box_process
  version_query_rejects_a_detached_descendant_that_retains_output_pipes` failed to compile because
  the bounded `ProbeOutputDrainTimedOut` behavior did not yet exist.
- The first scoped `git add` failed with `.git/index.lock: Read-only file system`; the same exact
  staging command succeeded with the required Git-only sandbox escalation.
- Expected red test: `cargo test -p xtask
  android_mark_preflight::tests::goto_and_non_input_references_to_the_child_chain_block_viability`
  failed because an extra `-g`/non-INPUT child-chain path was still reported viable.
- One combined parser/plan patch was rejected as malformed before any source edit; splitting it into
  one patch per file applied cleanly.
- The first post-split `fluxd` test compile found two facade tests reading private error `source`
  fields and warned that the disconnected crate-private reexports have no production caller. Use
  the standard `Error::source` interface in tests and scope the intentional facade lint allowance.
- The resulting interface-level test exposed that `EngineCapabilityProfileError::source()` returned
  a dynamic `Box<EngineCapabilityProbeError>` rather than the contained probe error. Dereference the
  box in the production implementation so standard error downcasting works.
- Expected red test: the preflight rejected a snapshot with one valid Android device-lock property
  and the other absent even though the production collector accepts that evidence. Move names,
  bounds, typed property parsing, and verified-boot validation into one shared platform contract.
- The post-commit module reread found the mechanical split had left imports/constants at the end of
  `candidate.rs` and `engine_profile.rs`. Move them to each module header; behavior is unchanged.
- The first Git staging request for the shared Android contract was rejected because the approval
  service returned HTTP 429. No index change occurred; the user explicitly resumed the task and the
  identical scoped staging operation then succeeded.

## Outcomes
1. Backlog item 3 remains the active roadmap milestone.
2. The delivered config, binding, engine profile, and candidate follow the required pure/I/O/pure
   execution order and remain disconnected from production mutation.
3. The pre-existing roadmap edit is valid; the stale review report has been replaced.
4. All confirmed behavioral and structural deviations are corrected and locally committed.
5. The next roadmap action requires an attached physical Android ARM64 target; no host substitute is
   authorized.

## Status
**Complete** - In-repository corrections, documentation reconciliation, and repository CI are done;
physical ARM64 qualification remains an explicit external prerequisite.
