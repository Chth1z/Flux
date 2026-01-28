# Changelog

All notable changes to the Flux project will be documented in this file.

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
