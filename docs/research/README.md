# Flux Rewrite Research Index

Research was performed against pinned primary-source checkouts and official documentation. Upstream repositories were cloned into the operating-system temporary directory and were not vendored into Flux.

> **Planning status:** these notes preserve research evidence and historical recommendations; they
> are not the execution plan. ADR-0011 and the current implementation roadmap supersede any advice
> to preserve bridge compatibility, publish an intermediate hybrid, or prioritize optional eBPF/
> kernel work ahead of the Rust ownership/removal lane.

## Cross-cutting conclusions

1. The current runtime is a migration hybrid: Rust `fluxd` now owns administrative intent, serialized lifecycle, Proxy Engine supervision, Generation recovery, and failure compensation, while shell remains the sole production bridge networking writer and standalone `addrsyncd` still owns address-derived rules.
2. The current `0xff` mark mask overlaps AOSP netd's `netId` field, and priority `2025` runs ahead of Android's normal VPN/default-network policy lattice. The rewrite needs audited mark and priority leases plus `respect_android_vpn = true` by default.
3. Linux 5.10 is a support floor, not a feature manifest. Android's 5.10 baseline requires useful legacy xtables, TUN, and BPF ingredients, but not nftables, ipset, BTF, every BPF hook, or permission to use them.
4. Capability selection must use a contained create/use/observe/delete probe. Durable availability is classified as supported, unsupported, denied, conflicting, broken, or unknown; transient failures remain attempt evidence with bounded retry/backoff rather than becoming a durable capability class.
5. Netlink notifications are lossy. Initial/full dumps, `ENOBUFS`, interrupted dumps, sequence validation, and resynchronization are correctness requirements.
6. Sing-Box should remain an external supervised Proxy Engine. Its Clash API is not a full reload interface, and its current reload paths do not provide old-generation rollback.
7. nftables remains the preferred long-term backend because of atomic batches and sets, but it
   follows the first Rust-only xtables release. Its first implementation should use a fingerprinted
   `nft` JSON Adapter as an oracle before promoting a narrow native nfnetlink codec.
8. Android's legacy xtables path remains the guaranteed compatibility baseline; generation-specific ipsets are an optional set-population accelerator, while the stable xtables jump performs cutover and the bounded jump structure remains the last fallback.
9. TUN must be a first-class managed Capture Path. Flux owns route/policy lifecycle and direct UAPI probes; Sing-Box remains the practical packet-stack owner until a supported FD handoff exists.
10. eBPF must stay optional to correctness. The first sequence is `xt_bpf` observation and proxy-positive matching inside Flux-owned xtables chains, followed by TC observation on verified Generation-scoped TUN links. TUN ioctl steering still requires the future `FluxOwnedTunFd` contract; physical-interface TC/XDP and Android root-cgroup hooks are not automatic targets.
11. The existing custom `epoll`/batched-netlink reactor is worth retaining. `io_uring` is an optional TUN optimization only after future queue-FD ownership, a live probe, and a device benchmark.
12. Magisk startup should use a module-local `service.sh`; runtime policy does not belong in `post-fs-data.sh` or a globally installed `/data/adb/service.d` script.
13. Android's 5.10 base configs make `xt_bpf` a credible experiment, not a guaranteed feature. Flux still needs exact map/program/helper, bpffs, userspace-extension, SELinux, packet-context, and cleanup probes.
14. LKM injection is not a general compatibility tier. Re:Kernel and IPSET_LKM demonstrate useful boot-quarantine and kernel-lifecycle ideas, but also expose KMI, rollback, authorization, provenance, and boot-loop costs that a broadly distributed proxy module should avoid.
15. eBPF roles must be planned per Traffic Domain and attachment owner. A low-conflict `xt_bpf` matcher for Flux-owned xtables, TUN TC observation, proxy-child `sockops` telemetry, and experimental tether TC socket assignment have different coverage and failure contracts and must not be hidden behind one global Boolean or mode.
16. Production Flux must not load or unload `.ko`/KPM payloads. An already-loaded OEM/custom-kernel extension may be consumed only as optional exact-device read-only observation through independently verified platform/module identity plus a versioned, strictly validated interface; decision-bearing use requires a concrete partner and separate ADR.
17. Linux 5.10 permits a conventional local-OUTPUT transaction through mangle/OUTPUT mark-driven
    rerouting, an RPDB local route through loopback, and mark-qualified loopback PREROUTING TPROXY.
    The exact checkpoint now passes on one rooted x86_64 WSA Android 13 development profile while
    preserving Android-owned mark bits and cleanup boundaries. MARK alone remains insufficient,
    Android 5.10/ARM64 production and release qualification remain open, TC `bpf_sk_assign()` is a
    separate experimental candidate requiring its own ADR, and production `.ko` loading remains
    prohibited.
18. The shortest safe ownership path is the already-built native xtables/rtnetlink owner, not a new
    nftables implementation. One nft ruleset batch is atomic, but routes, RPDB, listener readiness,
    process identity, and Generation publication remain outside it; the durable transaction model is
    still required.
19. Root-owned proxy sockets do not automatically inherit an intercepted application's Android
    VPN/network context. `respect_android_vpn` needs capture exclusion or an exact per-origin,
    profile-probed egress adapter. The pinned NDK r27d package also needs an explicit 16 KB ELF
    alignment gate.

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

### [Local-origin transparent-capture mechanisms on Linux 5.10 (2026-07)](local-output-capture-mechanisms-2026-07.md)

Traces local OUTPUT through Linux 5.10 routing and loopback receive processing, compares conventional
TPROXY, `sk_lookup`, cgroup rewriting, TC `bpf_sk_assign()`, and LKM options, and defines the exact
dual-stack TCP/UDP qualification and cleanup evidence. It also records the successful rooted
x86_64 WSA mechanism run and the remaining Android 5.10/ARM64 production gates.

### [Open-source architecture comparison for the Rust cutover (2026-07)](open-source-architecture-comparison-2026-07.md)

Compares current Sing-Box/Sing-Tun, mihomo, dae, Netavark, active rooted-Android proxy modules,
Linux/Netfilter, AOSP netd/xtables, Magisk, and Android build contracts against Flux's actual
composition. It concludes that the existing native xtables owner is the fastest safe Rust cutover,
records exact source refs and licenses, and adds VPN egress, netd restart, and 16 KB ELF gates.

### [Android 16 KiB ELF compatibility with NDK r27 (2026-07)](android-16kb-elf-compatibility-2026-07.md)

Pins the Android, NDK r27d, LLVM LLD, Bionic loader, AOSP helper, and Cargo sources behind B3.1.
It requires both maximum/common 16 KiB linker page-size options for raw Cargo links and structured
inspection of every `PT_LOAD`, while keeping 4 KiB WSA execution separate from 16 KiB runtime
qualification.

### [Rust HTTP/TLS dependency spike for P0-B1 (2026-07)](rust-http-tls-dependency-spike-2026-07.md)

Compares exact `ureq` and `minreq` releases for the bounded synchronous subscription Adapter,
including redirect, timeout, compression, encoded/decoded size, proxy-environment, Android TLS,
cross-build, licensing, and RustSec constraints. It recommends exact `ureq 3.3.0` with Rustls,
pending explicit production-dependency approval.

### [Rust dependency assurance for P1-R2 (2026-07)](rust-dependency-assurance-2026-07.md)

Pins cargo-deny, RustSec, the exact locked workspace graph, its allowed license expressions, and
the one version-scoped root-certificate data exception. It defines a digest-verified required CI
gate while keeping the excluded `addrsyncd` bridge outside any release-license claim.

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
