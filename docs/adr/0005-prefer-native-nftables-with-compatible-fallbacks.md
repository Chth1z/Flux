---
status: accepted
decision_date: 2026-07-13
---

# Prefer native nftables with xtables and TUN fallbacks

In automatic mode Flux will prefer a directly programmed nftables TPROXY adapter when all required
expressions and batch behavior pass active probes, then xtables TPROXY with ipset or a bounded-tree
set adapter, then a managed Sing-Box TUN path. Explicit backend requests fail with evidence rather
than silently changing mechanism.

Capability discovery precedes every backend-specific probe. The running-kernel configuration,
already-active registrations/modules, userspace tool identity, privileges, SELinux policy, and
behavioral probes are distinct evidence. Kernel configuration can prove that a feature is missing
or eligible; it cannot by itself qualify a Capture Path or grant mutation authority. Flux must not
load a module, or send a request that may implicitly request one, merely to test availability.

Each candidate is reported as `Qualified`, `Missing`, `Denied`, `Conflicting`, `Broken`, or
`Unqualified`. Automatic mode selects only the first `Qualified` candidate in the fixed order above.
When none is qualified, it remains inactive and reports the first `Unqualified` candidate as the
next qualification task. An explicit request never falls back. Optional eBPF and ipset capabilities
are selected independently and may not become correctness dependencies.

The first Rust-only release may still ship only the qualified xtables mutation adapter. That staged
delivery constraint does not change the target architecture or permit an xtables-only capability
model.
