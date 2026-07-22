# Notes: Flux Rewrite Audit and Execution

## Baseline
- Branch: `codex/fluxd-rust-rewrite`
- Upstream: `origin/codex/fluxd-rust-rewrite`
- Initial state: four local commits ahead of upstream.
- Pre-existing worktree changes: modified `docs/architecture/implementation-roadmap.md`; untracked `review_report.md`.
- No repository-local `AGENTS.md` or prior `task_plan.md` was found.

## Evidence

### Authoritative plan and design
- The execution order is the roadmap's current-priority section and prioritized backlog, not phase
  numbering (`docs/architecture/implementation-roadmap.md:74-77`).
- Backlog item 3 is current. A complete mark-dependent Generation must consume the exact
  non-cloneable `AndroidMarkPlanningAuthority`; host fixtures cannot replace the physical-target
  evidence boundary (`docs/architecture/implementation-roadmap.md:951-963`).
- The compiler is pure; exact-binary capability collection is a separate pre-compilation adapter
  (`docs/architecture/fluxd-blueprint.md:173-200`).

### Recent execution
- `764f947` delivers the explicit-serial, read-only ARM64 viability preflight.
- `5dda25e` delivers the pure canonical `EngineConfigArtifact` compiler.
- `0d1fd51` binds that artifact to one inspected `EngineSpec` artifact set and listener shape.
- `dcf0909` consolidates engine artifact identity, collects the minimal exact-build/config-acceptance
  profile, and feeds it into a non-authorizing TPROXY candidate.
- These slices remain disconnected from the Runtime Coordinator and native writer by design.

### Confirmed deviations
- `crates/flux-platform/src/sing_box.rs`: after a probe process exits, a detached descendant can
  retain stdout/stderr and block capture joining beyond the advertised timeout.
- `xtask/src/android_mark_preflight.rs`: admission counts only `-j` references from built-in INPUT;
  `-g` or references from another chain can create an extra path without blocking viability.
- `crates/fluxd/src/generation_engine_config.rs`: one 2,007-line module mixes a pure config compiler,
  I/O-performing profile collector, pure candidate compiler, parsers, and their tests.
- `xtask/src/android_mark_preflight.rs`: the production Android property set and verified-boot rules
  are duplicated instead of shared with the production identity collector.
- `review_report.md`: historical claims describe HEAD `5dda25e` and are stale after `0d1fd51` and
  `dcf0909`; the current 18-test count and delivered profile/candidate contradict it.

### Structural design decision
- Keep `generation_engine_config` as the existing crate-private facade; callers should not learn
  internal file ownership or gain a new interface.
- `compiler` owns pure canonical JSON compilation, artifact identities, and exact `EngineSpec`
  launch binding.
- `engine_profile` owns the I/O-performing exact-binary probe, safe version parsing, and immutable
  Engine Capability Profile revision.
- `candidate` owns pure admission of verified device/inventory/config/profile inputs into the
  non-authorizing candidate. It cannot mint a Generation or Android mark authority.
- Facade-level tests exercise the same interface after the split; no behavior or schema changes.
- `c561d47` implements the split and also corrects standard error-source downcasting for exact
  engine-profile probe failures exposed by the interface-level tests.

### Shared Android identity-property contract
- The preflight's duplicate verified-boot logic was behaviorally stricter than production: it
  required both lock properties, while the production collector accepts either one and requires
  agreement only when both are present.
- `flux-platform` now owns all 11 property names, the 1 KiB bound, typed product/build/patch
  validation, and verified-boot state/lock/SHA-256 parsing. Its hidden validation interface is the
  only property contract consumed by `xtask`; parsed domain values remain private to the platform
  collector.

## Verification Log
- `cargo test -p fluxd generation_engine_config::tests::`: 18 passed, 0 failed.
- `cargo test -p flux-platform --test sing_box_process`: 18 passed, 0 failed.
- `cargo test -p xtask android_mark_preflight`: 10 passed, 0 failed.
- `cargo xtask ci`: passed.
- `timeout 5s adb devices -l`: timed out with exit 124 and no device output.

### Corrections committed during this pass
- `dbed3c4`: bounds probe output draining after the direct child exits, including detached-descendant
  regression coverage. Sing-Box integration tests: 19 passed; supervisor tests: 29 passed.
- `22e8945`: counts all `-j`/`-g` references to `routectrl_mangle_INPUT` across each mangle table and
  admits only the sole exact unconditional built-in INPUT jump.
- Post-fix Android verification: `cargo test -p xtask android_mark_preflight` passed 11 tests;
  `cargo clippy -p xtask --all-targets -- -D warnings` and `git diff --check` passed.
- `4366ef2`: shares the production Android identity-property contract with the preflight.
  Production Android identity tests passed 11; Android preflight tests passed 13; combined Clippy
  passed with warnings denied.
- `e738e8c`: moves the mechanically displaced Generation module imports/constants back to their
  module headers. The 18 Generation tests and `fluxd` Clippy passed afterward.
- The pre-existing roadmap correction accurately describes the delivered engine profile/candidate
  and the missing physical mark-planning authority. The stale `review_report.md` was replaced.
- Final `cargo xtask ci`: passed.
- Final `git diff --check`: passed before the documentation close-out.
