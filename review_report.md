# Flux Rewrite Execution Review

## Review boundary

- Reviewed `codex/fluxd-rust-rewrite` from upstream `6404417` through `e738e8c`, plus the pending
  current-milestone correction in `docs/architecture/implementation-roadmap.md`.
- Reconciled the recent Android preflight, canonical engine config, exact engine-profile, and
  non-authorizing candidate work against the blueprint, technical specification, ADR-0013, and the
  roadmap's prioritized backlog.
- Reviewed the current source layout, focused tests, Clippy results, Git diff, and physical-target
  availability. `timeout 5s adb devices -l` exited 124 with no output, so no ARM64 qualification
  claim is made.

## Conclusion

The in-repository execution path is now aligned with the approved design. The pure config compiler,
I/O-performing exact-engine collector, and pure candidate admission are separate modules behind the
existing crate-private facade. Android preflight identity checks use the production collector's
property contract, and the confirmed process/preflight correctness defects are fixed.

Backlog item 3 remains current but is intentionally paused at its physical evidence boundary. The
delivered `TproxyGenerationCandidate` is not a `GenerationArtifact`: it has no Android mark-planning
authority or receipt, routing program, observed listener, Generation identity, native admission, or
activation path. Constructing any of those from host fixtures would be a new design deviation.

## Corrected deviations

1. `dbed3c4` bounds probe-output draining after a direct child exits. Detached descendants can no
   longer retain stdout/stderr indefinitely beyond the declared timeout and cleanup grace.
2. `22e8945` counts every `-j` and `-g` reference to `routectrl_mangle_INPUT` across each mangle
   table. Only one exact unconditional built-in INPUT jump is viable.
3. `c561d47` replaces the 2,007-line mixed Generation module with `compiler`, `engine_profile`, and
   `candidate` implementations plus facade-level tests. It also fixes standard `Error::source`
   downcasting for exact-engine probe failures.
4. `4366ef2` removes duplicate Android property and verified-boot rules. `flux-platform` now owns
   the 11 property names, 1 KiB bound, typed identity parsing, and AVB semantics; `xtask` consumes a
   validation-only hidden interface. Either valid lock fact is sufficient, and both must agree when
   present.
5. `e738e8c` removes the declaration-order residue from the mechanical module split. Imports and
   schema/domain constants now live at the module headers.
6. This report replaces the obsolete review tied to HEAD `5dda25e`; its claims that no engine
   profile/candidate existed and only 11 Generation tests ran are no longer retained.

## Current design

| Module | Responsibility | Authority boundary |
|---|---|---|
| `generation_engine_config/compiler.rs` | Pure canonical JSON compilation and exact launch-artifact binding | No process I/O, Generation ID, writer, or activation authority |
| `generation_engine_config/engine_profile.rs` | Descriptor-pinned version/config probes and immutable profile revision | Claims only exact build identity and exact config acceptance |
| `generation_engine_config/candidate.rs` | Pure device/inventory/profile/config admission | Produces a non-authorizing candidate, not a Generation |
| `android_identity_properties.rs` | Shared bounded Android property and verified-boot parsing | Validation cannot construct mark-planning or mutation authority |
| Runtime networking | Existing compatibility shell path remains the production writer | Native Rust admission remains `Unsupported` |

The roadmap correction is therefore valid: it records the delivered groundwork, names every
missing authority, and requires the lane to pause rather than adding another detached proof type.

## Verification

- `cargo test -p flux-platform --test sing_box_process`: 19 passed.
- `cargo test -p fluxd engine_supervisor::tests::`: 29 passed.
- `cargo test -p fluxd generation_engine_config::tests::`: 18 passed.
- `cargo test -p flux-platform android_identity`: 11 passed.
- `cargo test -p xtask android_mark_preflight`: 13 passed.
- Package-scoped Clippy checks with `-D warnings`: passed.
- `git diff --check`: passed.
- `cargo xtask ci`: passed on the final code state.

## Remaining plan

### P0: resume only with physical evidence

1. Attach one explicit physical Android 5.10+/ARM64 target and run the read-only preflight.
2. Bind the runtime netd/Connectivity artifacts to the reviewed source profile and complete the
   ordered mark-lifetime, listener/observer preservation, and VPN/netd coexistence procedure.
3. Complete the remaining census, RPDB/domain, route-reachability, rollback, and address-policy
   evidence on that same target.
4. Only then finalize a mark-dependent Generation by consuming the exact non-cloneable
   `AndroidMarkPlanningAuthority` and bind the existing engine/process/canary evidence.

### P1: qualify and cut over atomically

Dry-run one complete native target with exact readback and rollback while production admission
remains unsupported. After reviewed ARM64 qualification, stop every shell writer before the first
Rust write, transfer the lease, and remove replaced shell/addrsync duties without a dual-writer
interval.

### P2: defer

Do not add TUN, nftables, eBPF, ipset/`auto`, module loading, established-flow cache, DIVERT, FakeIP
ICMP, QUIC rejection, MSS clamping, or another detached identity/receipt layer before the physical
target and native cutover require them.

The remaining material risk is external and unchanged: this workspace currently has no attached
physical ARM64 target capable of producing the authority required for backlog item 3.
