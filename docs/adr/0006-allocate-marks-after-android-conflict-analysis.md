---
status: proposed
---

# Allocate Flux marks after Android conflict analysis

New installations will not reuse the current `0xff` low-byte mask because AOSP netd uses bits 0–15 for `netId`. Flux will observe Android and vendor mark/rule usage, allocate a disjoint field where possible, preserve all non-Flux bits on every operation, and remap or reject unsafe legacy values during migration.
