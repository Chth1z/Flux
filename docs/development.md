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

The socket defaults to `/data/adb/flux/run/fluxd.sock` with mode `0600`. Accepted peers must match the daemon effective UID. Administrative intent is atomically recorded in `/data/adb/flux/state/administrative-intent.json` with the current Linux boot ID, so a daemon restart replays desired running/stopped state before normal control traffic. Startup reconciliation must complete before the socket binds; journal, dispatcher, peer, or socket-safety failures remain fatal and are handled by the bounded watchdog.

The Phase 1 daemon now owns control admission and shutdown through one `epoll` reactor covering the Unix listener and shutdown `signalfd`. A stop request closes admission before in-flight connection work drains. This delivered baseline does not yet claim the future netlink, timerfd, pidfd, or BPF event sources planned for later phases.

Mutating `fluxctl` commands use this socket exclusively and never fall back to direct script execution. Read-only diagnostics still use the legacy inspection paths during the bridge release. The legacy dispatcher accepts networking mutations only with `FLUXD_BRIDGE=1`, serializes them with an identity-bearing lock, and remains the sole networking writer.
