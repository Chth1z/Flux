---
status: proposed
---

# Reconcile immutable Generations instead of executing lifecycle scripts

Flux will compile Desired State into immutable Generations and move each through prepare, activate, verify, and retire phases recorded in a durable journal. This is more machinery than imperative start/stop scripts, but it makes cross-subsystem partial failure, crash recovery, drift repair, and rollback explicit and testable.
