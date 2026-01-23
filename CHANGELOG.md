# Changelog

All notable changes to the Flux project will be documented in this file.

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
