# Flux Rewrite Research Index

Research was performed against pinned primary-source checkouts and official documentation. Upstream repositories were cloned into the operating-system temporary directory and were not vendored into Flux.

## Cross-cutting conclusions

1. The current runtime has split ownership: 3,508 lines of shell coordinate a 7,654-line Rust `addrsyncd`, Sing-Box, xtables, routes, configuration, and updates without one durable desired-state owner.
2. The current `0xff` mark mask overlaps AOSP netd's `netId` field, and priority `2025` runs ahead of Android's normal VPN/default-network policy lattice. The rewrite needs audited mark and priority leases plus `respect_android_vpn = true` by default.
3. Linux 5.10 is a support floor, not a feature manifest. Android's 5.10 baseline requires useful legacy xtables, TUN, and BPF ingredients, but not nftables, ipset, BTF, every BPF hook, or permission to use them.
4. Capability selection must use a contained create/use/observe/delete probe and distinguish unsupported, denied, conflicting, broken, and transient results.
5. Netlink notifications are lossy. Initial/full dumps, `ENOBUFS`, interrupted dumps, sequence validation, and resynchronization are correctness requirements.
6. Sing-Box should remain an external supervised Proxy Engine. Its Clash API is not a full reload interface, and its current reload paths do not provide old-generation rollback.
7. nftables is the preferred target because of atomic batches and sets, but the first Rust implementation should use a fingerprinted `nft` JSON Adapter as an oracle before promoting a narrow native nfnetlink codec.
8. Android's legacy xtables path remains the guaranteed compatibility baseline; generation-specific ipsets are an optional set-population accelerator, while the stable xtables jump performs cutover and the bounded jump structure remains the last fallback.
9. TUN must be a first-class managed Capture Path. Flux owns route/policy lifecycle and direct UAPI probes; Sing-Box remains the practical packet-stack owner until a supported FD handoff exists.
10. eBPF is safest first on verified Generation-scoped TUN links under Flux-owned attachment leases: observation, per-CPU counters, probed ring/perf events, and flow caches. TUN ioctl multiqueue steering requires the future `FluxOwnedTunFd` contract. Physical-interface TC/XDP and Android root-cgroup hooks are not automatic targets.
11. The existing custom `epoll`/batched-netlink reactor is worth retaining. `io_uring` is an optional TUN optimization only after future queue-FD ownership, a live probe, and a device benchmark.
12. Magisk startup should use a module-local `service.sh`; runtime policy does not belong in `post-fs-data.sh` or a globally installed `/data/adb/service.d` script.

## Notes

### [Current system baseline](current-system-baseline.md)

Maps the checked-in module, lifecycle, configuration, rule compiler, updater, PBR, and `addrsyncd` behavior. It records strengths to preserve, rewrite drivers, and the script-to-Rust migration map.

### [Android networking and kernel constraints](android-network-kernel.md)

Pins AOSP netd, Connectivity, framework, sepolicy, kernel config, legacy iptables, Magisk, and Linux 5.10 sources. It covers fwmark layout, Android RPDB/VPN semantics, UID/user models, net namespaces, Magisk boot, netlink loss, TUN, netfilter, eBPF ownership, SELinux/capabilities, and device conformance.

### [Sing-Box and adjacent projects](sing-box-and-projects.md)

Pins Sing-Box/Sing-Tun/SFA and studies Box4Magisk, AndroidTProxyShell, tun2socks, gVisor, tun-rs, smoltcp, HEV, and dae. It covers control surfaces, reload, TUN stacks, Android package/route handling, DNS/fake-IP/rule sets, nftables/NFQUEUE patterns, eBPF architecture, licensing, and validation.

### [Rust, eBPF, netfilter, and TUN](rust-ebpf-netfilter.md)

Pins Linux 5.10, Aya, libbpf-rs/libbpf, rtnetlink, netfilter crates, nftables implementations, ipset, Rust TUN, and io_uring. It recommends the retained reactor, staged nft implementation, direct TUN UAPI, Aya, no-CO-RE baseline programs, adaptive 5.10/6.4/6.6 gates, capability/security models, Android builds, and differential/fault tests.

## Cloned source families

- AOSP: `system/netd`, `packages/modules/Connectivity`, `frameworks/base`, `system/core`, `system/sepolicy`, `kernel/configs`, `external/iptables`.
- Linux stable 5.10 source.
- Magisk, Box4Magisk, AndroidTProxyShell.
- Sing-Box, Sing-Tun, Sing-Box for Android.
- tun2socks, gVisor netstack, tun-rs/rust-tun, smoltcp, HEV.
- dae.
- Aya, libbpf-rs, libbpf.
- rtnetlink and Rust netfilter/nftables candidates.
- nftables userspace, ipset, io_uring/liburing.

Exact commits, tags, source paths, license notes, and URLs are recorded in the individual research notes.
