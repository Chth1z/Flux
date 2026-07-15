# Changelog

All notable changes to the Flux project will be documented in this file.

## [Unreleased]

### Rewrite release policy
- Established the pre-release Rust-only release gate in ADR-0011. Bridge, shadow, parity, and
  migration checkpoints are development-only; obsolete internal compatibility may be broken to
  accelerate the rewrite, replaced runtime components are removed after their cutover gates, and no
  further rewrite alpha/beta/release-candidate/public release may ship until `fluxd` owns the
  intended runtime and legacy runtime components are absent from the package.

### Local-OUTPUT TPROXY qualification
- Corrected the earlier kernel-wide interpretation of the local-OUTPUT experiment. Linux 5.10 can
  recompute a marked OUTPUT route, select an RPDB local route through loopback, and re-enter
  PREROUTING. ADR-0012 selects that two-hook transaction as the first conventional qualification
  candidate while keeping canonical lowering and the production driver fail-closed until the full
  mark, route, listener, escape, ownership, and cleanup contract is implemented and Android-
  qualified.
- Added `cargo xtask test-functional-canary-linux-output-tproxy`, an opt-in, mechanism-only
  disposable-namespace checkpoint for IPv4/IPv6 TCP and UDP mark-driven loopback reinjection,
  transparent-listener original-destination delivery, response loop escape, counters, negative
  controls, no-autoload refusal, and exact inverse cleanup. It does not combine the distinct-UID
  preflight, construct Generation/canary authority, run a production report producer, or qualify
  Android.

### Canonical xtables lowering
- Added a pure, non-authorizing schema-v1 canonical lowerer for forwarded-ingress Capture Programs.
  It validates the sealed family/clause shape, exact loopback safety, address families, input-
  interface tokens, wildcard bounds, and command expansion; preserves ordered direct decisions as
  uncached `RETURN`; expands terminal whole-set interface negation as positive proxy membership; and
  emits protocol-qualified TCP/UDP TPROXY rules into deterministic generation-namespaced but
  unattached prepare/retire mangle chains. Domain-separated lowering, family-pair, and artifact-set
  identities bind the source-program and restore-syntax digests, entry names, and resource
  accounting. Local OUTPUT is rejected because MARK-only OUTPUT lacks the reviewed RPDB local
  route, mark-qualified loopback PREROUTING TPROXY companion, and listener-delivery transaction.
  Established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS
  clamping are also explicit
  unsupported extensions. The artifacts do not attach built-in hooks, invoke restore, inspect live
  state, prove cleanup invertibility, perform readback/rollback, or grant mark, writer, ownership,
  prepared/active, coordinator, or activation authority.

### Bridge contract audit corrections
- Added Generation-bound attestation for Rust-generated legacy restore artifacts. Domain-separated
  plan, mandatory family apply/cleanup pair, and enabled-family set identities bind the exact
  renderer inputs, context-qualified artifact digests, and resource totals. The strict
  `fluxd attest-legacy-rules-set` command rebuilds one plan, safely byte-compares staged files, and
  emits a canonical receipt only for the allocated Generation/family shape. Shell invalidates old
  receipts before rebuilding shared cache artifacts, snapshots the accepted receipt into the immutable Generation
  before `engine.manifest`, and preserves the active Generation on rejection. This adds no restore,
  readback, rollback, writer, activation, device-parity, eBPF, or kernel-module authority.
- Moved Rust-owned bridge rule-cache preparation onto the validated `fluxd render-legacy-rules` adapter. `LegacyRulesPlan` preserves the frozen `scripts/rules` source shape—including ordered application UIDs, duplicate interface patterns, mark/CONNMARK fast paths, DIVERT, FakeIP, MSS, and symmetric cleanup—without pretending to lower `ShadowCaptureArtifact` or acquiring any restore/writer authority. The focused Rust suite differentially reproduces all four pinned IPv4/IPv6 apply/cleanup fixtures and rejects unsupported production profiles instead of silently changing mechanisms.
- Made rule-cache ownership explicit and mutually exclusive. Rust-owned preparation never sources `scripts/rules`, records `rust` as the cache producer, binds its packet/conntrack marks to the same exported shell PBR inputs, and fails preparation without disturbing the active Generation when rendering fails. Explicit legacy ownership alone sources the frozen shell generator, records `shell`, and remains the deliberate rollback path; there is no automatic Rust-to-shell fallback. `scripts/tproxy` remains the sole restore executor and kernel writer.
- Added `fluxd snapshot-legacy-packages --source PATH` for the preparation-scoped package inventory. When application resolution is required, the command opens the source without following symlinks, enforces bounded regular-file/stable-descriptor reads, and streams one immutable snapshot shared by every parallel family/action render and copied into the prepared Generation; inactive or empty application selection uses an empty snapshot without reading Android package state.
- Hardened explicit legacy restart so fresh settings, the replacement Sing-Box configuration, and all replacement rule caches are prepared and validated before the active runtime is stopped. Replacement preparation failure restores the prior cache authority, preserves the running legacy instance, and leaves an explicit stop available.
- Added the separately invoked, digest-pinned xtables shell/AWK oracle. `cargo xtask xtables-oracle --check` verifies four raw IPv4/IPv6 apply/cleanup restore fixtures, while explicit `--update` refreshes reviewed fixtures and their input/output metadata without changing the approved environment pins. `tests/oracle/xtables/manifest.json` is the sole canonical inventory for those identities and hashes. The bounded runner streams only the reviewed input snapshot into private tmpfs, applies inner/outer time and output limits, and has no host-workspace mount, container networking, live networking access, or restore execution. This profile does not cover configuration/kernel discovery, QUIC, PBR, forced cleanup, kernel acceptance, Android/Magisk parity, Generation, ownership, or activation.
- Added a bounded, observation-only xtables restore parser/canonical codec in `flux-platform`. It preserves repeated table transactions, command/token order, duplicates, apply/cleanup opcode separation, per-transaction mangle cleanup ordering, explicit family context with current family-marker validation, resource usage, and a domain-separated byte digest while exposing no shell execution, restore process, Capture-policy-to-restore renderer, Generation, writer, ownership, prepared/active, coordinator, or activation path. Current-shaped synthetic fixtures exercise the closed grammar; the pinned raw shell fixtures are a separate byte-characterization gate. The later legacy source-shape renderer uses that gate, while canonical Capture Program, kernel, and device parity remain open.
- Corrected the frozen shell oracle's IPv6 jump-tree classification for compressed zero-prefix destinations: `::1/128` and `::ffff:0:0/96` now enter the high-nibble-zero chain reached by `0000::/4`, instead of unreachable zone-1/zone-15 chains.
- Stabilized the frozen shell rule oracle across gawk and mawk by emitting multi-user UID rules in canonical numeric order and excluded-interface rules in configured order; cross-AWK regression coverage now protects both byte-order contracts before full restore fixtures are admitted.
- Added the bounded Phase-2 shadow Capture Program checkpoint and ADR-0010 migration boundary. Pure Rust compilation now targets deterministic, separately ordered local-OUTPUT/forwarded-ingress policy with a canonical mandatory safety baseline, optional inventory-host provenance, bounded resource accounting, semantic digest, and explicit assumptions/deferred prerequisites, while the frozen shell path remains the sole executed networking writer and compatibility oracle. Shadow artifacts have no Generation ID, Planning Authority, writer token, renderer, prepared/active conversion, Runtime Coordinator or functional-canary path, parity claim, eBPF attach/pin, TUN activation, implicit module request, or `.ko`/KPM loading; each legacy component requires an independently qualified single-writer cutover before retirement.
- Made `fluxctl status [--json]` delegate to authoritative live `fluxd` state instead of inferring the Rust-owned Sing-Box lifecycle from the legacy PID file.
- Completed installer migration for proxy mode, reserved TUN values, and Android multi-user scope; every backup/restore is checked, post-extraction failure restores the retained user configuration, and upgrade preservation is documented per file.
- Restricted the current development Phase-1 configuration to `PROXY_MODE=tproxy` and `BYPASS_SET_BACKEND=zone`; unsupported future choices now fail during configuration validation instead of being reported as active.
- Corrected the English and Chinese lifecycle, installed-layout, setting-name/default, and TPROXY-listener documentation.
- Split development module staging from strict package-consistency verification. `cargo xtask verify-package --stage <dir>` now binds clean root/submodule HEADs, exact source/package/binary inventories, reviewed licenses, file-backed AArch64 executable entries and Android interpreters, exact SPDX membership/checksums, payload/device/test-bound evidence, pinned build metadata, and recursive checksums; it rejects unreviewed Magisk root files, symlinks, and hidden or ordinary `.ko`/`.kpm` payloads. The current verifier still describes a temporary hybrid inventory and cannot authorize publication; the Rust-only runtime gate plus signed third-party and trusted device attestations remain later requirements.
- Removed the misleading one-shot `addrsyncd cleanup --mode tracked` surface; tracked cleanup remains owned by a live daemon during `stop`, while manual stale-rule cleanup uses the kernel dump.
- Re-gated the next local-OUTPUT canary as fail-closed integration plumbing until a concrete TPROXY capture mechanism and authoritative engine report producer are device-qualified; confined near-term `xt_bpf` work to isolated no-autoload test probes until Rust owns xtables state.
- Delivered the first fail-closed integration slice: `SingBoxChild` now opens an exact child-origin process handle, `EngineSupervisor` admits it only from matching ready ownership/specification/revision, and the coordinator binds a single-use opener to the request identity/revision/deadline. Prepared paths move the resulting non-cloneable authority into the sealed process-verifier boundary without transferring signal/wait/reap authority; the current xtables `Unsupported` path opens no pidfd authority. The pre-release bridge remains structural-only.
- Delivered the exact engine-observation-pair slice. `ProcessHandle::initial_observation` preserves the child-origin opening scan; the process verifier consumes the non-cloneable engine authority and reobserves the same retained pidfd after capture verification, binding both observations to the exact identity, snapshot revision, private opening ID, stable credentials, and exclusive deadline. Exit or deadline failure after preparation is cleanup-uncertain, the handle exposes no signal/wait/reap authority, and the slice cannot mint the process receipt. Driver-owned client/peer retirement, final verifier completion chronology, traffic, and device qualification remain pending.
- Delivered engine credential-policy and process-domain validation. `ProcessHandle` now obtains authoritative user, mount, and network namespace identities from opened descriptors for every observed thread, reads bounded canonical UID/GID maps twice, and binds domain-separated SHA-256 digests into the complete before/after process observations. The process verifier requires both observations to match the request's exact four-slot UID/GID policy, empty supplementary groups, zero capabilities, `NoNewPrivs`, namespace identities, map digests, and daemon network namespace. Drift or mismatch after preparation is cleanup-uncertain and cannot reach the evidence factory. Driver-owned client/peer retirement, final verifier completion chronology, and process-receipt minting remain pending; both production receipt authorities stay uninhabited, xtables stays `Unsupported`, and the pre-release bridge remains structural-only.

## [v1.5.0-alpha.1] - 2026-07-11

### Rust control-plane bridge
- Added the `fluxd` Rust daemon, versioned root-only `SOCK_SEQPACKET` control protocol, live status/ping, raw event forwarding, and serialized legacy control.
- Enforced the Linux 5.10 minimum while keeping unsupported devices queryable without networking mutation.
- Added boot-ID-scoped administrative-intent recovery, bounded concurrent clients, peer credential checks, graceful signal handling, and stale-socket recovery.
- Hardened startup admission with bounded request-result deduplication, symlink-safe durable state I/O, and process-wide signalfd delivery while preserving normal child-process signals.
- Replaced timed control polling with a bounded `epoll` reactor over the control listener, `signalfd`, and programmatic wakeups.
- Added the strict schema-1 `flux.toml` daemon configuration with bounded resource budgets and upgrade-safe preservation.
- Added a boot-scoped read-only Capability Profile for kernel gating, boot identity, SELinux state, and legacy bridge facts; control protocol v2 carries the coherent profile used for mutation decisions.
- Added the Stage-1 generation-scoped functional capture-canary model and coordinator gates for activation, publication retry, restart restoration, resynchronization, and rollback, with exact pre/post identity and bounded evidence validation. Production remains explicitly structural-only and Android-unqualified pending the privileged and device harnesses.
- Added the first Stage-2 privileged Linux namespace checkpoint and `cargo xtask test-functional-canary-linux`: an isolated, journaled topology exercises real IPv4/IPv6 TCP, UDP, DNS-over-UDP, and DNS-over-TCP flows with independent client/peer evidence and exact cleanup. This checkpoint is topology-only; TPROXY traversal, distinct-UID loop escape, collector-backed socket correlation, and authoritative schema-v2 evidence construction remain outside it.
- Added `cargo xtask test-functional-canary-linux-tproxy` and the ingress-only TPROXY traffic slice: a third probe namespace now exercises real IPv4/IPv6 TCP/UDP echo plus nonce-bound DNS over UDP/TCP through exact PREROUTING capture, accepted-socket and strict ancillary-data original-destination recovery, marked relay egress, source-preserving UDP replies, independent flow counters, route controls, and exact cleanup. Local-OUTPUT qualification, distinct UIDs, production listener/report factories, collector integration, and Android evidence remain pending.
- Added the strict Linux/Android `/proc` FD plus INET_DIAG socket collector and strengthened functional-canary correlation: one caller-supplied exclusive deadline bounds identical pre/post FD inventories and four complete diagnostic dumps, while evidence binds protocol, exact local/remote tuple, UID, socket mark, FD, matching `/proc` and INET_DIAG inode, INET_DIAG cookie, exact supervised-process identity, and the observed timing interval. Partial, drifting, ambiguous, stale, oversized, interrupted, or late observations fail closed. This delivers the outbound evidence prerequisite only; positive local-OUTPUT traffic/evidence production, listener/delivery construction, and Android qualification remain pending.
- Added prebound `SystemSocketDiagnosticsSession` support. Callers can open and bind the NETLINK_SOCK_DIAG socket before request construction, read its real nonzero port ID, and collect multiple serialized snapshots through the same handle with non-reused sequences. Collection consumes the session and returns it only on success, so every error retires the socket; sequence wrap fails closed, and later calls cannot extend the opening deadline. The original stateless collector remains as a temporary-session compatibility wrapper.
- Added the type-safe attempt-owned socket-observer handoff. A non-cloneable transport opens the real session under the immutable canary deadline, derives both its request authority and a private per-opening identity from that handle, and makes attempt inputs derive the same deadline. Checked preparation and execution envelopes reject copied numeric authority, reopened sessions, or deadline drift; the coordinator moves the resource once into prepared local-OUTPUT execution. A live regression proves the exact bound port reaches the driver by value. The real production attempt context, collector identity/revision source, traffic/report factories, and Android qualification remain pending, so production stays `structural_only`.
- Replaced boolean functional-canary cleanup claims with temporal retirement evidence. The gate now requires ordered client/peer retirement, pairwise-distinct selector/guard/counter retirement, authority-sensitive listener-report retirement or verified-never-created disposition plus exact absence readback, counter/report lifetime through their final observations, exact Generation/nonce attempt-record retirement, retained-facility observation, and completion/deadline bounds. Cleanup roles cannot reuse the supervised engine identity; the later process-ownership receipt closes the model-level handle binding, while real driver-owned child retirement remains pending.
- Recorded that REDIRECT or DNAT delivery cannot qualify the TPROXY backend. A local-OUTPUT adapter must prove delivery to the selected backend's generation-specific listener with its required destination semantics, or report that backend unsupported; production remains prohibited from publishing `functional_passed` from the host-only evidence.
- Bumped the internal functional-canary evidence model to schema v2 and required authoritative TPROXY listener delivery for every flow. Evidence now binds the exact Generation, engine, network namespace, Capture Program, selector, globally noncolliding listener FD/inode/cookie roles and socket options; transport-specific TCP accept or UDP `recvmsg` delivery with accepted children distinct from every listener; an attempt-owned supervised report schema/object or separately qualified cgroup-BPF authority; loss, timing, stable cross-flow listener identity and event/socket uniqueness; and exact inbound wire length/SHA-256 including DNS/TCP framing. Positive constructors remain private and test-only pending the real local-OUTPUT observer/report factories.
- Added `cargo xtask test-functional-canary-linux-output-preflight`, a credential-only opt-in checkpoint for the future positive local-OUTPUT producer/driver. It behaviorally verifies exact singleton controller/probe/engine UID and GID maps, delegated nonzero role identities, empty supplementary groups, exact namespace/map/credential readback, zero role capabilities, and `NoNewPrivs`; optional mode skips unavailable prerequisites and required mode fails. It installs no capture, sends no traffic, rejects root/root or same-UID fallback, and does not qualify Linux or Android functional capture.
- Added a TPROXY-only local-OUTPUT executor/driver/evidence-factory seam. Non-TPROXY requests fail as invalid evidence before driver preparation; pre-mutation availability maps to cleanup `NotRequired`; and post-preparation failures cannot claim that cleanup was unnecessary. The current zero-state xtables driver reports `Unsupported` before mutation because OUTPUT marking does not reach PREROUTING TPROXY, and its prepared/raw types are uninhabited, so no positive traffic or evidence path exists. This is fail-closed evidence admission, not a change to the user-selected fail-open connectivity policy; production remains `structural_only` pending the real attempt context, observer/report factories, capability-qualified execution, and Android qualification.
- Added the explicit per-flow local-OUTPUT TPROXY capture-receipt contract and a separate sealed verifier boundary. Drivers return unverified capture proof; only the verifier may mint a non-cloneable receipt-bound artifact for the evidence factory. The resulting gate record owns and revalidates the receipt against its exact flows and client cleanup lifetime. Validation binds the complete immutable request plus each required flow's probe UID, nonce, tuple, inbound payload, transparent-listener cookie, exact delivery event, unique sequence, unchanged loss baseline, and monotonic attempt/client/deadline chronology. The production verifier authority remains uninhabited, current xtables remains `Unsupported`, separately qualified cgroup-BPF remains optional, and production Flux neither loads nor unloads `.ko` modules. The later process-ownership receipt completes model-level UID/GID/PID/start-tick/handle binding; prepared-driver child integration, listener observation and report parsing/factories, actual prebound INET_DIAG collection, traffic, and Android qualification remain pending.
- Added the process-ownership receipt contract and Linux/Android child-origin pidfd substrate. The immutable canary request now binds explicit probe/engine UID+GID and exact user/mount namespace plus UID/GID-map digests; a second non-cloneable verifier receipt binds engine before/after and client/peer PID/start-tick/handle observations, restricted credentials, role network namespaces, exact cleanup retirements, distinct handle openings, and flow/cleanup/deadline chronology before the evidence factory can run. `ProcessHandle` opens only from a retained live `Child`, correlates pidfd/procfs identity, verifies stable credentials and process domains across every thread, distinguishes exit from parent reap, and is exercised by the no-traffic credential preflight. Production receipt authority remains uninhabited: prepared-driver child ownership/retirement, final verifier completion chronology, listener/report factories, actual collection/traffic, and Android qualification remain pending. Xtables stays `Unsupported`, production stays `structural_only`, optional cgroup-BPF remains separately qualified, and this checkpoint adds no explicit `.ko` load/unload path. The legacy structural bridge has not yet proven every xtables dependency already active without implicit module requests.
- Bumped the local control contract to protocol v3 with a required orthogonal runtime verification state (`structural_only`, `functional_pending`, `functional_passed`, or `functional_failed`); version-1 and version-2 requests are rejected explicitly.
- Moved boot launch to module-local `service.sh`; mutating `fluxctl` commands no longer bypass the daemon.
- Added pinned Android build and Magisk staging contracts while retaining `addrsyncd` as the bridge-release rollback binary.

## [v1.4.0] - 2026-02-23

### ⚠️ Correctness & Stability
- Fixed `UPDATE_INTERVAL=0` behavior: it now correctly disables boot-time auto update.
- Wired `UPDATE_TIMEOUT` into updater download requests (`curl --connect-timeout/--max-time`).
- Reordered init checks to allow missing `config.json` before updater/cache rebuild flow.
- Hardened cache validation: `cache_ok` now also requires required cache files to exist and be non-empty.
- Added strict parallel task result aggregation via `wait_pids` in init/dispatcher critical paths.

### 🔁 Runtime Lifecycle
- Refactored `scripts/addrsync` lifecycle to PID-based flow (no internal `status` polling loops).
- Implemented `addrsyncd stop` first, with `kill -9` fallback and deterministic pid cleanup.
- Added dispatcher handling for `addrsyncd.toml` change events.
- Added `init cache` action for cache-only rebuild path used by config hot-reload.

### 🧾 Config & Docs Alignment
- Removed `BYPASS_IPV4_LIST` / `BYPASS_IPV6_LIST` from `settings.ini` exposure; keep internal constants in `scripts/lib`.
- Updated installer migration key set to match current public settings.
- Synced README/README_zh with current addrsync-based architecture and real config keys.
- Removed stale documentation keys (`RULES_DEBUG_DUMP`, `INCLUDE_INTERFACES`) from README tables.

### 📦 Release Process
- Added `scripts/check_release.ps1` for lightweight pre-release consistency checks.
- Updated package workflow to:
  - run release checks before packaging
  - include `flux_service.sh` (instead of stale `service.sh`)
  - enforce required ZIP entries (including `conf/addrsyncd.toml`)

## [v1.3.3] - 2026-02-07

### ⚡ IP MONITOR PERFECTION
- **Unified AWK Engine**: Rewrote `ipmonitor` with a single-process architecture that combines initial IP sync and real-time monitoring, using three-layer filtering (semantic, memory-state, phase-based) for zero-redundancy rule operations

### 🔧 CONSTANTS CONSOLIDATION
- **Internal Network Constants**: Moved `TABLE_ID`, `IPV4_MARK`, `IPV6_MARK`, and `BYPASS_MARK` from user-configurable `settings.ini` to `scripts/const` as `readonly` system constants
- **Simplified Configuration**: Removed obsolete `MARK_VALUE`, `MARK_VALUE6`, and `TABLE_ID` from settings documentation

### 🛠️ CODE REFINEMENT
- **Merged Log Rotation**: Combined `_rotate_file` and `_rotate_log` into a single streamlined function in `scripts/init`

## [v1.3.2] - 2026-02-06

### ⚡ STARTUP OPTIMIZATION
- **Parallel IPMonitor**: `ipmonitor` now starts simultaneously with `core` and `tproxy`, reducing startup latency by eliminating unnecessary dependency wait
- **Simplified Readiness Logic**: Removed `READY_LOCK` mutex as concurrent safety is no longer needed with parallel component startup

### 🔧 CACHE SYSTEM REFACTORING
- **inotify-Based Invalidation**: Replaced mtime-based fingerprint validation with real-time configuration file monitoring
  - Configuration changes instantly invalidate cache via `rm meta_cache`
  - Eliminated ~50 lines of fingerprint calculation logic
- **Prioritized Config Loading**: All scripts now prefer `cache_config` (when meta exists) over `settings.ini` for faster initialization

### 🛠️ ROBUSTNESS IMPROVEMENTS
- **Updater Cleanup Fix**: Moved `trap _cleanup` to function entry, ensuring workspace cleanup even on early errors

### 🗂️ CODE ORGANIZATION
- **Inline Cache Validation**: Moved cache check logic from standalone script call to inline execution in `init`, reducing subprocess overhead

## [v1.3.1] - 2026-01-29

### ⚡ EXTREME PERFORMANCE
- **Ultimate Streamlined Proxy Chain**: Introduced `:ACTION_PROXY` and `:ACTION_BYPASS` sub-chains to deduplicate mangle rules.
- **Rule Count Optimization**: Reduced the number of rules in high-frequency chains (APP_CHAIN/BYPASS_IP) by ~50%, leading to faster kernel-space lookup.

### 🚀 PROTOCOL-AGNOSTIC ARCHITECTURE
- **Agnostic Proxy Chain**: Decoupled transport protocols from the decision logic. Flux now intercepts all traffic by default and dispatches it via a unified `TPROXY_GATE`.
- **Simplified Configuration**: Removed `PROXY_TCP` and `PROXY_UDP` settings. The system now automatically handles all supported transient traffic.
- **Unified Entry Points**: Refactored IPTables logic to use single-pass attachment for both `PREROUTING` and `OUTPUT` chains, reducing rule count and kernel overhead.

### 🛡️ REFINE & OPTIMIZE
- **Unified Proxy Port**: Consolidated `PROXY_TCP_PORT` and `PROXY_UDP_PORT` into a single `PROXY_PORT` for simplified configuration and rule management.
- **JQ Extraction Refinement**: Updated `jq` logic to exclusively recognize `tproxy` type inbounds, ensuring alignment with the project's focus on transparent proxying.

## [v1.3.0] - 2026-01-29

### ⚠️ BREAKING CHANGES
- **Updater Standardization**: Completely removed `subconverter` dependency. The `updater` script now relies purely on `jq` for robust and lightweight subscription handling.
- **Directory Structure Clean-up**: Removed the obsolete `tools/` and `scripts/iphandler` directories to streamline the package.
- **Auto-Detected Conntrack**: Removed `ENABLE_CONNTRACK` setting. It is now automatically enabled if the kernel supports `nf_conntrack`/`xt_conntrack`.

### ✨ NEW FEATURES
- **Emoji Cleanup Preference**: Introduced `PREF_CLEANUP_EMOJI` in `settings.ini` to optionally remove emojis from node names during subscription updates.
- **Strict Mode Enforcement**: All scripts now run with `set -u` (nounset) enabled, significantly improving error detection and preventing "silent failure" bugs caused by undefined variables.

### 🛡️ FIXES & OPTIMIZATIONS
- **Documentation Sync**: Fully aligned `README.md` and `README_zh.md` directory structures and configuration tables.
- **Fail-Fast Logic**: Helper functions in `scripts/rules` (`_build_loopback_block`, `_build_nat_extra`) now strictly require action arguments to prevent ambiguity.

## [v1.2.0] - 2026-01-27

### 🚀 EXTREME PERFORMANCE & ARCHITECTURE
- **16-Zone Jump Tree (IPv4/IPv6)**: Replaced linear O(N) IP bypass lookups with an O(1) tiered jump tree. Reduced CPU consumption by ~85% in high-CIDR environments.
- **SRI (State-driven Routing Injector)**: Replaced file-based IP polling with a FIFO-backed reactive engine in `ipmonitor`. Achieved sub-second routing synchronization.
- **Atomic Readiness Protocol**: Introduced a robust `mkdir`-based locking mechanism in `scripts/dispatcher` to prevent race conditions during concurrent state transitions.
- **Fast-Path Traffic Funnel**: Optimized IPTables logic to ensure established/reply packets exit the kernel mangle chain at the earliest possible entry point.

### 🛡️ RELIABILITY & REFINEMENT
- **Safe Log Rotation**: Implemented a "copy-truncate" strategy in `scripts/init` to ensure concurrent-safe log management without stream interruption.
- **Enhanced Configuration Validation**: Added multi-interface validator for `EXCLUDE_INTERFACES` and schema-driven type checking for all 30+ settings.

### 🧹 CLEANUP & STANDARDIZATION
- **Code Refinement**: Standardized all function prefixes, variable naming conventions, and logic orchestration patterns.
### ⚠️ BREAKING CHANGES
- **MAC Address Bypass Removal**: Deprecated MAC-based filtering to eliminate kernel overhead and maintain focus on O(1) IP-based routing.
- **Unified Application Filtering**: Consolidated `PROXY_APPS_LIST` and `BYPASS_APPS_LIST` into a single, highly efficient `APP_LIST` controlled by `APP_PROXY_MODE`.

### ⚙️ ENHANCED PROXY FLOW
- **Phase 1: Zero-Match Fast Path**: Established/Reply packets exit the kernel logic immediately (90% traffic optimization).
- **Phase 2: Tiered IP Decision**: New 16-Zone Jump Tree processes large bypass lists with near-constant time complexity.
- **Phase 3: Reactive Routing**: SRI 2.0 (State-driven Routing Injector) triggers sub-second route synchronization via FIFO pipes upon network state changes.
- **Phase 4: Unified DNS Orchestration**: Centralized DNS hijacking logic replaces redundant per-chain rules, ensuring consistent behavior across NAT and TProxy.

## [v1.1.0] - 2026-01-24

### Fixed
- **Shutting Down Interruption**: Resolved "Interrupted system call" noise in `ipmonitor` by optimizing signal traps and pipe cleanup order.
- **State Corruption Risks**: Implemented `mktemp` + `mv` strategy for `module.prop` and config updates to ensure atomic writes.
- **Kernel IPv6 Compatibility**: Added `KFEAT_IPV6_NAT` detection in `iphandler` to prevent crashes on older kernels.

### Refined
- **Solution A Logging**: Unified `stderr` redirection across all entry points for reliable inheritance and zero-redundancy log capture.
- **Variable Handling Syntax**: Hardened all conditional checks project-wide using safe string comparison `[ "$VAR" = "1" ]`.
- **Startup Resilience**: Integrated `kill -0` checks in the readiness loop for instant failure detection instead of hardcoded delays.

### Optimized
- **Zero-Fork UID Memoization**: Switched to native Shell parameter expansion for cache keying, eliminating expensive subshell overhead.
- **Component Lifecycle**: Termination and rollback flows are now fully parallelized for faster state transitions.

## [v1.0.0] - 2026-01-23

### ⚠️ MAJOR REWRITE
Flux v1.0.0 is a near-total rewrite aimed at professionalism, robustness, and maximum hardware efficiency. This version breaks away from legacy shell patterns to provide a more industrial-grade experience on Android.

### Added
- **Multi-tier Cache System**: A high-performance caching engine that eliminates redundant processing:
  - **Kernel Cache**: Persistent detection of kernel capabilities (`KFEAT_*`).
  - **Rules Cache**: Pre-generated, atomic IPTables rule sets for sub-second application.
  - **Config Cache**: Normalized and pre-validated configuration state.
  - **Meta Cache**: Environment fingerprinting (vCode, mtimes, kernel) for intelligent cache invalidation.
- **Event-Driven Orchestration**: Transitioned to a reactive architecture using `inotifyd` and a central `dispatcher` for sub-second response to state changes.
- **Atomic Reliability Layer**: All critical file operations (configs, prop) now use a temp-and-swap strategy for 100% integrity.
- **Intelligent Config Extraction**: robust `jq`-based inbound/port detection for complex `sing-box` configurations.

### Changed
- **Architectural Rewrite**: Decoupled monolithic logic into focused, role-based components.
- **Stream-Optimized Rule Engine**: Refactored `rules` to use direct data streams, minimizing memory pressure.
- **Enhanced Diagnostics**: Captured and streamed granular error output from `iptables-restore` for immediate troubleshooting.
- **Documentation Optimization**: Refined `README.md` focus and added multi-language support (English | [简体中文](README_zh.md)).

### Removed
- **Legacy Prefixes**: Cleaned up script directory by removing redundant `flux.*` prefixes and `flux_` function prefixes.
- **Obsolete Rules**: Removed "China IP Bypass" logic from core rules to keep the implementation lean and focused.

---

## [v0.9.0] - Previous Stable
- Original release with monolithic script architecture.
- Basis for the v1.0.0 complete overhaul.
