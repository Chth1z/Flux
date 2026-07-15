# Flux Rewrite Research Index

Research was performed against pinned primary-source checkouts and official documentation. Upstream repositories were cloned into the operating-system temporary directory and were not vendored into Flux.

> **Planning status:** these notes preserve research evidence and historical recommendations; they
> are not the execution plan. ADR-0011 and the current implementation roadmap supersede any advice
> to preserve bridge compatibility, publish an intermediate hybrid, or prioritize optional eBPF/
> kernel work ahead of the Rust ownership/removal lane.

## Cross-cutting conclusions

1. The current runtime is a migration hybrid: Rust `fluxd` now owns administrative intent, serialized lifecycle, Proxy Engine supervision, Generation recovery, and failure compensation, while shell remains the sole networking writer and standalone `addrsyncd` still owns address-derived rules.
2. The current `0xff` mark mask overlaps AOSP netd's `netId` field, and priority `2025` runs ahead of Android's normal VPN/default-network policy lattice. The rewrite needs audited mark and priority leases plus `respect_android_vpn = true` by default.
3. Linux 5.10 is a support floor, not a feature manifest. Android's 5.10 baseline requires useful legacy xtables, TUN, and BPF ingredients, but not nftables, ipset, BTF, every BPF hook, or permission to use them.
4. Capability selection must use a contained create/use/observe/delete probe. Durable availability is classified as supported, unsupported, denied, conflicting, broken, or unknown; transient failures remain attempt evidence with bounded retry/backoff rather than becoming a durable capability class.
5. Netlink notifications are lossy. Initial/full dumps, `ENOBUFS`, interrupted dumps, sequence validation, and resynchronization are correctness requirements.
6. Sing-Box should remain an external supervised Proxy Engine. Its Clash API is not a full reload interface, and its current reload paths do not provide old-generation rollback.
7. nftables is the preferred target because of atomic batches and sets, but the first Rust implementation should use a fingerprinted `nft` JSON Adapter as an oracle before promoting a narrow native nfnetlink codec.
8. Android's legacy xtables path remains the guaranteed compatibility baseline; generation-specific ipsets are an optional set-population accelerator, while the stable xtables jump performs cutover and the bounded jump structure remains the last fallback.
9. TUN must be a first-class managed Capture Path. Flux owns route/policy lifecycle and direct UAPI probes; Sing-Box remains the practical packet-stack owner until a supported FD handoff exists.
10. eBPF must stay optional to correctness. The first sequence is `xt_bpf` observation and proxy-positive matching inside Flux-owned xtables chains, followed by TC observation on verified Generation-scoped TUN links. TUN ioctl steering still requires the future `FluxOwnedTunFd` contract; physical-interface TC/XDP and Android root-cgroup hooks are not automatic targets.
11. The existing custom `epoll`/batched-netlink reactor is worth retaining. `io_uring` is an optional TUN optimization only after future queue-FD ownership, a live probe, and a device benchmark.
12. Magisk startup should use a module-local `service.sh`; runtime policy does not belong in `post-fs-data.sh` or a globally installed `/data/adb/service.d` script.
13. Android's 5.10 base configs make `xt_bpf` a credible experiment, not a guaranteed feature. Flux still needs exact map/program/helper, bpffs, userspace-extension, SELinux, packet-context, and cleanup probes.
14. LKM injection is not a general compatibility tier. Re:Kernel and IPSET_LKM demonstrate useful boot-quarantine and kernel-lifecycle ideas, but also expose KMI, rollback, authorization, provenance, and boot-loop costs that a broadly distributed proxy module should avoid.
15. eBPF roles must be planned per Traffic Domain and attachment owner. A low-conflict `xt_bpf` matcher for Flux-owned xtables, TUN TC observation, proxy-child `sockops` telemetry, and experimental tether TC socket assignment have different coverage and failure contracts and must not be hidden behind one global Boolean or mode.
16. Production Flux must not load or unload `.ko`/KPM payloads. An already-loaded OEM/custom-kernel extension may be consumed only as optional exact-device read-only observation through independently verified platform/module identity plus a versioned, strictly validated interface; decision-bearing use requires a concrete partner and separate ADR.

## Notes

### [Current system baseline](current-system-baseline.md)

Maps the checked-in module, lifecycle, configuration, rule compiler, updater, PBR, and `addrsyncd` behavior. It records strengths to preserve, rewrite drivers, and the script-to-Rust migration map.

### [Android networking and kernel constraints](android-network-kernel.md)

Pins AOSP netd, Connectivity, framework, sepolicy, kernel config, legacy iptables, Magisk, and Linux 5.10 sources. It covers fwmark layout, Android RPDB/VPN semantics, UID/user models, net namespaces, Magisk boot, netlink loss, TUN, netfilter, eBPF ownership, SELinux/capabilities, and device conformance.

### [Sing-Box and adjacent projects](sing-box-and-projects.md)

Pins Sing-Box/Sing-Tun/SFA and studies Box4Magisk, AndroidTProxyShell, tun2socks, gVisor, tun-rs, smoltcp, HEV, and dae. It covers control surfaces, reload, TUN stacks, Android package/route handling, DNS/fake-IP/rule sets, nftables/NFQUEUE patterns, eBPF architecture, licensing, and validation.

### [Rust, eBPF, netfilter, and TUN](rust-ebpf-netfilter.md)

Pins Linux 5.10, Aya, libbpf-rs/libbpf, rtnetlink, netfilter crates, nftables implementations, ipset, Rust TUN, and io_uring. It recommends the retained reactor, staged nft implementation, direct TUN UAPI, Aya, no-CO-RE baseline programs, adaptive 5.10/6.4/6.6 gates, capability/security models, Android builds, and differential/fault tests.

### [Current implementation follow-up (2026-07, Chinese)](current-system-follow-up-2026-07.zh-CN.md)

Re-checks the Rust/Shell hybrid at the historical `4360d79` snapshot, adds a progress section through `868729f`, and identifies concrete mark/RPDB, verification, readiness, TUN, rule-semantics, migration, and supply-chain gaps.

### [dae, Re:Kernel, peer modules, and `xt_bpf` (2026-07, Chinese)](peer-kernel-projects-2026-07.zh-CN.md)

Pins current dae, Re:Kernel/ReKernel-X, NetProxy-Magisk, Box for Root, AndroidTProxyShell, MagicNet, IPSET_LKM, Linux 5.10, and AOSP sources. It separates proxy data planes from adjacent kernel-event projects and proposes a Generation-scoped `xt_bpf` observation/positive-fast-path experiment.

### [Expanded eBPF and kernel-extension assessment (2026-07)](ebpf-and-kernel-extensions-2026-07.md)

Reconciles the peer-project findings with Linux/AOSP primary sources. It defines the per-domain eBPF mechanism ladder, corrects child-cgroup and `clsact` lifecycle assumptions, evaluates TC socket assignment and newer hooks, and records why Flux must not make `.ko` loading a production fallback.

## Cloned source families

- AOSP: `system/netd`, `packages/modules/Connectivity`, `frameworks/base`, `system/core`, `system/sepolicy`, `kernel/configs`, `external/iptables`.
- Linux stable 5.10 source.
- Magisk, Box4Magisk, Box for Root, NetProxy-Magisk, AndroidTProxyShell, MagicNet.
- Sing-Box, Sing-Tun, Sing-Box for Android.
- tun2socks, gVisor netstack, tun-rs/rust-tun, smoltcp, HEV.
- dae.
- Re:Kernel, ReKernel-X, IPSET_LKM.
- Aya, libbpf-rs, libbpf.
- rtnetlink and Rust netfilter/nftables candidates.
- nftables userspace, ipset, io_uring/liburing.

Exact commits, tags, source paths, license notes, and URLs are recorded in the individual research notes.
