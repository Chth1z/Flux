---
status: proposed
---

# Prefer native nftables with xtables and TUN fallbacks

In automatic mode Flux will prefer a directly programmed nftables TPROXY adapter when all required expressions and batch behavior pass active probes, then xtables TPROXY with ipset or a bounded-tree set adapter, then a managed Sing-Box TUN path. Explicit backend requests fail with evidence rather than silently changing mechanism.
