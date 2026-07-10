---
status: proposed
---

# Keep eBPF optional to the correctness Capture Path

Flux will introduce eBPF first for bounded observation and later for verified decision caching/mark acceleration while nftables, xtables, or TUN remains correct without it. TC defaults to verified Generation-scoped TUN interfaces under a Flux-owned qdisc/filter lease, even when Sing-Box owns the link and queue FDs. TUN ioctl eBPF steering remains gated on future queue-FD ownership. AOSP netd may remove physical-interface `clsact` qdiscs and tethering offload can share that path, so physical TC/XDP remains experimental.
