# Changelog

All notable changes to the Flux project will be documented in this file.

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
- **Flash-Wear Protection**: Optimized status persistence with "compare-before-write" logic to protect NAND longevity.
- **Atomic Reliability Layer**: All critical file operations (configs, prop) now use a temp-and-swap strategy for 100% integrity.
- **Intelligent Config Extraction**: robust `jq`-based inbound/port detection for complex `sing-box` configurations.

### Changed
- **Architectural Rewrite**: Decoupled monolithic logic into focused, role-based components.
- **Stream-Optimized Rule Engine**: Refactored `rules` to use direct data streams, minimizing memory pressure.
- **Enhanced Diagnostics**: Captured and streamed granular error output from `iptables-restore` for immediate troubleshooting.
- **Standardized Execution Environment**: Unified shebangs (`/system/bin/sh`), professional headers, and atomic variable exports.

### Removed
- **Legacy Prefixes**: Cleaned up script directory by removing redundant `flux.*` prefixes and `flux_` function prefixes.
- **Obsolete Rules**: Removed "China IP Bypass" logic from core rules to keep the implementation lean and focused.
- **Redundant CLI Helpers**: Removed unnecessary binary version checking to maintain module simplicity.

---

## [v0.9.0] - Previous Stable
- Original release with monolithic script architecture.
- Basis for the v1.0.0 complete overhaul.
