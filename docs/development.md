# Flux Rewrite Development

The Rust rewrite uses a root Cargo workspace while the legacy `addrsyncd` submodule remains independently locked and buildable during the bridge releases.

## Toolchain contract

- Rust `1.93.0` with `rustfmt` and Clippy.
- Primary target: `aarch64-linux-android`.
- Android API level: 31.
- Release-link NDK: revision `27.3.13750724` (NDK r27d).

The root [`rust-toolchain.toml`](../rust-toolchain.toml) installs the Rust components and Android standard library. `cargo check` for Android does not require an NDK linker. A release build does.

## Common commands

```text
cargo xtask fmt
cargo xtask check-host
cargo xtask test-host
cargo xtask clippy
cargo xtask check-android
cargo xtask ci
```

`cargo xtask ci` runs formatting, host checks/tests, Clippy with warnings denied, and the Android cross-check for the new workspace.

The focused Phase 3 Android mark-authority model can be exercised with:

```text
cargo test -p flux-core --test android_mark_authority
cargo test -p flux-core --test rpdb_fwmark_census
```

These are pure evidence/planning checkpoints. The RPDB test covers only one inventory-backed source
fragment; it does not create a complete Mark Census or Planning Authority. Passing host tests do
not replace production Android device-policy verification, the remaining source collectors,
cross-source freshness, or activation canaries.

The compatibility submodule remains separate:

```text
cargo test --manifest-path addrsyncd/Cargo.toml
cargo clippy --manifest-path addrsyncd/Cargo.toml --all-targets -- -D warnings
cargo check --manifest-path addrsyncd/Cargo.toml --target aarch64-linux-android --all-targets
```

Host execution of `addrsyncd` requires Linux or Android. On Windows, use the Android cross-check and run its host tests in Linux CI.

## Android release build

Set `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT` to the pinned NDK revision and run:

```text
cargo xtask build-android
```

The task validates `source.properties`, selects the API-suffixed NDK clang linker for the host OS, and builds the `fluxd` release binary. It refuses a different NDK revision instead of silently producing an unqualified artifact.

## Magisk module staging

The bridge release is staged only after a successful pinned Android release build:

```text
cargo xtask stage-module --stage dist/module --runtime-binaries /path/to/runtime-binaries
```

`--runtime-binaries` must contain the independently sourced `sing-box`, `jq`, and rollback `addrsyncd` Android binaries. The task copies the tracked module tree, installs the newly built `fluxd` at `bin/fluxd`, and refuses a non-empty stage or a stage missing any required runtime file. This keeps third-party provenance explicit and prevents installer changes from landing without a real Android `fluxd` artifact.

Before publishing, populate every blank version/source/hash field in `conf/manifest.json` from the staged artifacts and archive the matching provenance records.

## Phase 1 bridge runtime

The packaged module installs `flux_service.sh` as module-local `service.sh`. It launches a bounded watchdog for `fluxd daemon` and an `inotifyd` Adapter that forwards raw facts through `scripts/flux-event`; event-to-intent policy remains in Rust.

Native online commands are:

```text
fluxd ping
fluxd status [--json]
fluxd control start|stop|restart|reload|resync
fluxd event EVENT_TYPE WATCHED_PATH EVENT_NAME
```

The local `SOCK_SEQPACKET` control contract is protocol version 2. Version 2 adds the required coherent Capability Profile to status responses; version-1 requests are rejected explicitly instead of being decoded against the new response shape.

The socket defaults to `/data/adb/flux/run/fluxd.sock` with mode `0600`. Accepted peers must match the daemon effective UID. Administrative intent is atomically recorded in `/data/adb/flux/state/administrative-intent.json` with the current Linux boot ID, so a daemon restart replays desired running/stopped state before normal control traffic. Startup reconciliation must complete before the socket binds; journal, dispatcher, peer, or socket-safety failures remain fatal and are handled by the bounded watchdog.

The authoritative Phase 1 user configuration is `/data/adb/flux/conf/flux.toml` (override with `FLUXD_CONFIG_PATH` for development and tests). Schema 1 is intentionally exact: unknown or missing fields are rejected, and only `fail_policy = "open"` is accepted. `daemon.event_queue_capacity` sizes the bounded legacy-writer queue; the other accepted daemon fields reserve the validated contract for later Phase 1 slices. Configuration is loaded once during mutation-allowed startup, so changes to `flux.toml` currently require a daemon restart. When the Capability Profile permits mutation, a missing or invalid file is fatal before the legacy writer starts or the control socket is admitted.

When the kernel is below 5.10, or when the kernel version or boot identity cannot be verified, `fluxd` enters its settled read-only service without loading `flux.toml`, reading administrative intent or disable state, or starting the legacy mutation writer. In particular, every verified below-5.10 kernel is guaranteed to remain queryable without mutation. Read-only Capability Profile collection may still inspect boot identity, SELinux state, and legacy artifact metadata, but it never executes the dispatcher. Tests and nonstandard environments may override the first two probe files with `FLUX_BOOT_ID_PATH` and `FLUX_SELINUX_ENFORCE_PATH`. This keeps status queries available while preventing mutation-configuration or persistence failures from turning a read-only device into a watchdog restart loop. Module upgrades automatically preserve an existing `flux.toml`; a first installation receives the packaged default.

The Phase 1 daemon now owns control admission and shutdown through one `epoll` reactor covering the Unix listener and shutdown `signalfd`. A stop request closes admission before in-flight connection work drains. This delivered baseline does not yet claim the future netlink, timerfd, pidfd, or BPF event sources planned for later phases.

Mutating `fluxctl` commands use this socket exclusively and never fall back to direct script execution. Read-only diagnostics still use the legacy inspection paths during the bridge release. The legacy dispatcher accepts networking mutations only with `FLUXD_BRIDGE=1`, serializes them with an identity-bearing lock, and remains the sole networking writer.

### Rust-owned engine handoff shell contract

The delivered Phase 1 handoff invokes `FLUXD_BRIDGE=1 scripts/dispatcher` through the phase verbs `startup-recover`, `prepare`, `capture-start GENERATION`, `capture-stop`, `capture-verify GENERATION`, `address-resync`, `state-running GENERATION`, `state-stopped`, and `state-failed`. These verbs never invoke `scripts/core`. A boot-scoped dispatcher mode lease rejects mixing them with the retained legacy `start`, `stop`, and `restart` rollback path; `state-stopped` releases the Rust-owned lease only after capture is detached. This makes Rust the sole Sing-Box owner for the daemon run while shell remains the serialized networking writer for Phase 1 capture, policy-routing, and address-synchronization mutations.

`prepare` runs under the dispatcher lock, allocates a positive shell-owned generation ID, and snapshots the generated configuration, environment, rule/cleanup caches, manifest, and generation-local Sing-Box log under `/data/adb/flux/run/generations/<id>/`. Later mutation phases load those immutable generation artifacts instead of the shared live cache. The compatibility path `/data/adb/flux/run/engine.manifest` is atomically published from that generation's manifest for Rust intake; failure discards the incomplete generation and removes the compatibility manifest. The manifest is at most 16 KiB and has this strict line grammar:

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

`RuntimeCoordinator` implements the existing `LegacyDispatcher` interface and therefore runs inside the same bounded, serialized `LegacyControlBridge` worker as all control mutations. Start ordering is `prepare` → descriptor-pinned `sing-box check`/launch and child-owned listener or TUN readiness → `capture-start <id>` → structural `capture-verify <id>` → `state-running <id>`. Capture start, verification evidence, active/previous generation records, and `RUNNING` publication must all name the same boot-scoped generation. Before its first networking mutation, `capture-start` records that generation as the capture owner, then starts address synchronization before TPROXY. It compensates both on partial failure, but removes the generation marker only when both cleanup operations succeed; uncertain compensation retains the evidence needed for a later detach proof. Stop and shutdown detach capture before asking the supervisor to stop/reap the child, then publish `state-stopped`. `address-resync` uses the same writer and cannot interleave with lifecycle work.

Reload prepares the candidate while the current generation remains active. Only after preparation succeeds does it detach old capture and replace the engine. A failed or uncertain old-capture detach does not launch the candidate: it retains the old engine in `CaptureRepairPending`, blocks start/reload, and lets maintenance repeatedly prove detach before republishing and re-verifying capture for that same old generation. Candidate activation failure attempts to detach partial capture; only proven detach permits candidate retirement and rollback to the recorded previous immutable generation. Uncertain candidate compensation remains `DetachPending` and does not restart the previous generation. Rollback capture and publication are bound to the previous generation ID; failed rollback remains fail-open with capture detached.

If capture detachment fails during stop or failure compensation—including uncertain cleanup after `capture-start`—the coordinator enters `DetachPending`: it retains the generation evidence and intended terminal state, does not signal the engine, does not publish `STOPPED`/`FAILED`, and blocks start/reload. Maintenance retries detachment; only proven detach permits engine retirement/reap and terminal publication.

The worker calls maintenance after requests and on bounded idle intervals. This drives supervisor reap/backoff/restart without starting a second child, restores and re-verifies capture after a successful restart, and retries pending `RUNNING`, `STOPPED`, or `FAILED` publication. A failed `state-running` call does not authorize a blind retry: maintenance first observes the owned engine and runs a fresh `capture-verify <id>`. Only the still-ready, structurally verified matching generation may retry `state-running`. Failed verification enters `CaptureRepairPending`, which proves detach, republishes capture for the same generation, re-verifies it, and only then republishes `RUNNING`; an observed engine exit takes detach/repair precedence. `fluxd status` exposes an observed `RuntimeSnapshot` (runtime phase, capture, engine, generation, bounded last error, and its own revision) separately from the desired/control `ControlSnapshot` (administrative intent, in-flight request, dirty state, and last completion).

Every phase process has a nonzero execution deadline capped at 60 seconds. The Rust Adapter launches the phase shell in its own process group and performs bounded forced cleanup on timeout. Sing-Box validation/run children and phase-shell children also arm `PR_SET_PDEATHSIG(SIGKILL)` with a post-arm parent check, containing direct children if `fluxd` dies. Direct Sing-Box launch therefore supports automatic same-boot crash recovery after capture is detached. This is not process-tree containment: phase descendants do not inherit the lease, and BusyBox `setuidgid` credential changes may clear it. A post-credential Rust launcher and verified Flux-owned process-cgroup containment remain deferred.

On daemon startup, the Capability Profile first decides whether mutation is admissible. An admitted runtime runs the bounded `startup-recover` phase before strict `flux.toml` loading, so a broken current configuration cannot strand same-boot capture; recovery must also succeed before administrative intent is read, persisted, or executed and before the control socket is admitted. Below-floor or unverified profiles stay on the non-mutating read-only path and never invoke recovery. Recovery is serialized by the dispatcher lock. With no lease and no capture evidence it idempotently publishes `STOPPED`. A same-boot Rust lease removes the exact active generation, or uses the immutable prepared generation for markerless partial activation, then stops TPROXY before address synchronization and proves capture evidence absent. For a direct engine launch, `PDEATHSIG` supplies the child-death proof, so recovery publishes `STOPPED`, clears active/previous/verification records, and releases the lease. For `busybox-setuidgid`, child death cannot be proven after daemon loss: recovery publishes `FAILED` only after detachment, preserves the Rust lease and active engine generation, and blocks automatic daemon restart for explicit repair. Cleanup failure likewise preserves evidence and ownership. Same-boot legacy ownership is rejected without mutation; prior-boot evidence is retired without treating kernel objects as surviving the reboot.

Phase 1 `capture-verify` proves shell-owned structural evidence; it is not yet a synthetic end-to-end traffic or loop-prevention probe. Also deferred are ancestor-safe directory traversal with `openat`/`openat2`, long-term retention/rotation policy for generation logs, a pidfd/timerfd reactor, full process-tree containment, and real-device release evidence on the minimum Android 5.10 kernel.
