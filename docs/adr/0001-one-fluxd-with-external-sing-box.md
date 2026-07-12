---
status: accepted
decision_date: 2026-07-13
---

# Use one Flux daemon while keeping Sing-Box external

Flux will absorb `addrsyncd` and runtime functional scripts into one Rust `fluxd` process, but will supervise Sing-Box as a separately versioned Proxy Engine. This removes split ownership of Flux state while avoiding a Go-in-Rust embedding boundary, preserving independent Sing-Box upgrades, and keeping validation tied to the exact packaged Sing-Box binary.
