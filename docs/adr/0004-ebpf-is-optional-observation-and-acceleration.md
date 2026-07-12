---
status: accepted
decision_date: 2026-07-13
---

# Keep eBPF optional to the correctness Capture Path

Flux will introduce eBPF first for bounded observation and later for verified positive decision caching/mark acceleration while nftables, xtables, or TUN remains correct without it. The first integration is `xt_bpf` inside Flux-owned xtables chains: observation always returns false, and later acceleration recognizes only proxy-positive decisions while every miss uses the complete classic classifier. TC observation follows on verified Generation-scoped TUN interfaces using either a legacy Flux-owned `clsact`/filter lease or a verified qdisc-less TCX link, even when Sing-Box owns the link and queue FDs.

That ordering is delivery priority, not a runtime prerequisite: once implemented, a TUN TC or proxy-child observation role is independently eligible from its own domain, attachment, probe, and conventional-fallback evidence and does not require xtables or active `xt_bpf`.

eBPF is planned per Traffic Domain, mechanism, role, and attachment owner rather than as one global on/off backend. AOSP root-cgroup attachments normally prevent equivalent descendant hooks, and netd may remove `clsact` from every extant interface, so cgroup and TC roles require exact program/flag inventory plus Network Epoch revalidation. TUN ioctl steering remains gated on future queue-FD ownership. Physical/tether TC, XDP, netns-wide hooks, and TC socket assignment remain experimental. Making TC socket assignment correctness-bearing requires a separate ADR with local-route, miss, fallback, and Android coexistence proofs.
