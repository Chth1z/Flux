---
status: accepted
decision_date: 2026-07-13
---

# Enforce kernel 5.10 and select features through active probes

Flux will reject kernels older than 5.10, then use version metadata only to bound a registry of side-effect-contained active probes. Android vendor configuration, SELinux policy, userspace tools, and backports make version or config hints insufficient evidence that nftables, TUN, eBPF, ipset, pidfd, or a specific hook can actually be used.
