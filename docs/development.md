# Flux Rewrite Development

Flux now has one Rust-owned runtime and one exact native module profile. The legacy shell networking
bridge, standalone `addrsyncd`, packaged `jq`, compatibility configuration, and bridge-oracle test
surface were removed in R5-R6. This branch remains development-only until the native package passes
the physical-device, provenance, and release-evidence gates.

Historical cutover rationale remains in the ADRs and architecture records. This guide documents
only commands and boundaries that exist in the current tree.

## Toolchain Contract

- Rust: `1.93.0`, including rustfmt and Clippy.
- Primary target: `aarch64-linux-android`.
- Android API level: 31.
- Android NDK: `27.3.13750724` (r27d).
- Minimum Android ELF `PT_LOAD` alignment: 16 KiB.
- Dependency policy tool: cargo-deny `0.20.2`.

The root [`rust-toolchain.toml`](../rust-toolchain.toml) installs the Rust components and Android
standard library. Set `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` to the exact pinned NDK before any
Android command. `xtask` rejects another revision and supplies the API-31 compiler, target-specific
CC/linker environment, and 16 KiB linker flags.

## Standard Verification

The repository-defined gate is:

```text
cargo xtask ci
```

It runs formatting, workspace all-target checks, the complete host tests, strict Clippy, and the
pinned ARM64 Android cross-check. The individual commands are:

```text
cargo xtask fmt
cargo xtask check-host
cargo xtask test-host
cargo xtask clippy
cargo xtask check-android
cargo xtask build-android
```

`build-android` creates `target/aarch64-linux-android/release/fluxd` and validates the ELF machine,
Android interpreter, and minimum 16 KiB `PT_LOAD` alignment.

The network-refreshed dependency-policy gate is separate from portable `xtask ci`:

```text
cargo deny --manifest-path Cargo.toml --config deny.toml --all-features --locked \
  check advisories licenses sources
```

Review new advisories or licenses. Do not weaken policy merely to make the command pass. This check
covers the root workspace; there is no longer an excluded `addrsyncd` submodule.

## Focused Tests

Use the smallest relevant test during implementation, then run `cargo xtask ci` before a reviewable
commit.

```text
cargo test -p xtask
cargo test -p flux-core
cargo test -p flux-platform
cargo test -p fluxd
cargo xtask test-parser-fuzz-smoke
cargo xtask test-native-composition-linux
```

The native-composition checkpoint exercises the dispatcher-free Rust lifecycle, Generation
replacement, exact native-owner convergence, rollback, and recovery in an isolated Linux
namespace. It is mechanism evidence, not Android qualification.

The only package shell test is the platform-glue suite:

```text
bash -n META-INF/com/google/android/update-binary customize.sh \
  flux_service.sh uninstall.sh tests/shell/run-module-glue-tests.sh
FLUX_MODULE_GLUE_TESTS_REQUIRED=1 sh tests/shell/run-module-glue-tests.sh
```

It requires Bubblewrap and `zip`. The suite proves fresh-only installation, exact runtime/module
placement, bounded daemon restart, removal of exact legacy global Flux launchers, online uninstall
delegation, offline Rust cleanup delegation, and failure propagation. It does not execute live
networking commands.

Focused native dataplane suites include:

```text
cargo test -p flux-core --test capture_program
cargo test -p flux-core android_mark_authority::tests::
cargo test -p flux-core android_mark_policy_catalog::tests::
cargo test -p flux-core --test rpdb_placement
cargo test -p flux-platform --test xtables_capture_lowering
cargo test -p flux-platform --test xtables_restore
cargo test -p flux-platform xtables::
cargo test -p flux-platform netlink::policy_routing
```

These tests prove deterministic planning, lowering, transaction ordering, readback, compensation,
journal recovery, and policy-routing models. Host results alone do not allocate Android marks or
authorize a physical-device writer.

## Capability And Path Selection

Flux collects exact kernel, Android policy, namespace, tool, process, rule, route, nftables,
xtables, and optional BPF facts. The selector ranks qualified nftables, xtables, and managed TUN
candidates, but only the native xtables mutation adapter is currently implemented in the packaged
runtime. nftables and TUN remain non-authorizing candidates; eBPF is observation-only and optional.

Selection obeys four rules:

1. A path must have complete, fresh structural evidence and the required behavioral probe.
2. Exact user requests never silently fall back to another path.
3. A higher-ranked path wins only after it is fully qualified.
4. Missing, denied, malformed, drifting, or unknown evidence yields read-only operation, not an
   optimistic mutation attempt.

Focused selector and capability tests are part of the workspace suite. Physical ARM64 collection
commands are:

```text
cargo xtask preflight-android-arm64-mark-ordering \
  --serial "$device_serial" --adb "$adb_program"
cargo xtask collect-android-arm64-profile \
  --serial "$device_serial" --adb "$adb_program"
cargo xtask collect-android-arm64-fwmark-census \
  --serial "$device_serial" --adb "$adb_program"
```

Use exactly one explicitly selected device. Keep the serial process-local; do not commit or paste
the serial, fingerprint, boot ID, endpoints, raw rules, or unrelated device state. The collectors
use bounded Flux-owned temporary paths and must prove their removal. A collection report is evidence
for review, not self-authorizing production policy.

## Functional Canaries

The repository contains privileged Linux mechanism checkpoints for ingress and local-output TPROXY:

```text
cargo xtask test-functional-canary-linux
cargo xtask test-functional-canary-linux-tproxy
cargo xtask test-functional-canary-linux-output-preflight
cargo xtask test-functional-canary-linux-output-tproxy
```

Run them only in a disposable namespace-capable Linux environment with the required tools and
privileges. They mutate only their isolated test namespace and must end with exact cleanup. WSA or
host success does not qualify Android OEM policy, fwmark allocation, VPN coexistence, or the final
packaged payload.

The x86_64 Android checkpoint remains development-only:

```text
cargo xtask test-functional-canary-android-x86_64-output-tproxy \
  --serial "$device_serial" --adb "$adb_program"
```

It is not a substitute for ARM64 package qualification.

## Native Module Staging

The source manifest has one schema-4 `native` profile marked `development-only`. Its exact inventory
contains `fluxd`, the external Sing-Box binary, three configuration files, web content, module
metadata, license, and four platform glue entry points.

Prepare a directory containing an independently sourced and reviewed ARM64 `sing-box` binary:

```text
/path/to/runtime-binaries/sing-box
```

Then stage the module:

```text
cargo xtask stage-module \
  --stage dist/module \
  --runtime-binaries /path/to/runtime-binaries
```

The stage directory must not exist or must be empty. `xtask` rebuilds `fluxd`, copies only the
manifest inventory, rejects missing/extra files, and rejects unsafe paths. It does not download
Sing-Box or infer its provenance.

To create a development installation archive after reviewing the exact tree:

```text
(cd dist/module && zip -qr ../flux-native-development.zip .)
```

Do not call that archive a release. The checked manifest deliberately contains incomplete Sing-Box
and device-evidence metadata.

## Package Verification

The full verifier is:

```text
cargo xtask verify-package --stage dist/module
```

Run it from a clean dedicated worktree. It requires the staged source-owned files to match the
checked source revision and enforces:

- the exact 13-file native inventory and exact binary set;
- bounded regular AArch64 Android executables with safe interpreter/alignment;
- no symlinks, special files, kernel payloads, unreviewed module-root entries, or extra residue;
- platform glue limited to installation, launch/restart, and Rust cleanup delegation;
- complete source/version/target/hash/license provenance for every binary;
- payload- and source-bound physical-device evidence;
- SPDX package/source/license/hash binding;
- pinned build metadata and recursive checksums.

An ordinary `stage-module` result intentionally lacks the release metadata and evidence needed to
pass. Do not bypass or weaken those failures.

## Physical-Device Qualification

The Samsung/ARM64 qualification is a bounded destructive test of Flux-owned state, not a general
device cleanup. Preserve customized user state and never inspect or alter unrelated modules.

Before installation:

1. Require exactly one ready ADB target, verified ARM64, root UID 0, stable reviewed identity, and a
   supported module manager.
2. Prove no Flux test process or temporary probe path remains.
3. Ask the existing Flux runtime to stop and independently prove its exact processes and owned
   kernel objects are absent.
4. Classify `/data/adb/flux` and `/data/adb/modules/flux` as `KEEP`. Create a root-only, device-local,
   exact backup without reading or copying user configuration to host logs.
5. Validate the backup before moving either live path. Do not proceed if ownership, mode, free
   space, or restoration cannot be proved.

Exercise one exact staged payload:

1. Install into an absent `/data/adb/flux`; an existing root must make the installer abort.
2. Reboot only when the reviewed test requires the real module-manager boot path.
3. Verify daemon readiness, status, selected backend, engine identity, and the scoped traffic matrix.
4. Inject only Flux-owned failures, verify rollback/fail-open behavior, and prove cleanup before the
   next case.
5. Run online stop/uninstall and the offline cleanup fallback as separate cases.

After testing:

1. Prove no Flux process, socket, temporary path, journal-owned kernel object, route, or rule remains.
2. Remove only the tested Flux module/runtime paths.
3. Restore the exact pre-test Flux backup and its metadata if the user still needs it, or leave Flux
   absent only when that was the reviewed starting/desired state.
4. Prove the backup staging path is gone and recheck device identity in memory.
5. Retain only sanitized pass/fail evidence. Never retain secrets, subscription URLs, serials,
   fingerprints, boot IDs, raw rules, or unrelated state.

If ADB transport, root, identity, backup validation, cleanup, or restoration becomes uncertain,
stop before mutation and report the exact boundary.

## Runtime Interfaces

The module-local service runs only:

```text
/data/adb/flux/bin/fluxd daemon
```

All user control goes through the private `/data/adb/flux/run/fluxd.sock`. The current CLI is shown
by:

```text
cargo run -p fluxd --bin fluxd -- help
```

`conf/flux.toml` is the sole Flux policy source. `conf/template.json` is a Sing-Box engine source,
not capture authority. Generated engine configurations, Generation records, subscriptions, logs,
sockets, and native-owner journals live under the private runtime tree and are never packaged.

## Documentation Boundaries

- [`README.md`](../README.md): current product/runtime contract and user-facing commands.
- [`architecture/implementation-roadmap.md`](architecture/implementation-roadmap.md): remaining
  implementation and release gates.
- [`architecture/fluxd-technical-specification.md`](architecture/fluxd-technical-specification.md):
  detailed safety and transaction design.
- [`adr/`](adr/): accepted decisions, including historical bridge/cutover rationale.
- [`research/`](research/): dated evidence; historical present-tense statements are not current
  runtime instructions.

When source and a historical document disagree about a removed compatibility surface, current
source plus this guide define the executable workflow. Update canonical current documentation in
the same follow-up commit as a public command or package-contract change.
