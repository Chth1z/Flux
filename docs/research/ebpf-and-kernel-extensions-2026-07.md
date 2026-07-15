# Expanded eBPF and kernel-extension assessment (2026-07)

- Status: design research for the Rust `fluxd` rewrite
- Research date: 2026-07-13 (Asia/Singapore)
- Flux baseline: `868729fcce4d076b11e7746d8ec39369f26159f2`

This note reconciles the existing [Android/kernel](android-network-kernel.md), [Rust/eBPF](rust-ebpf-netfilter.md), and [peer-project](peer-kernel-projects-2026-07.zh-CN.md) research with additional Linux and AOSP source review. It changes the ordering and granularity of the plan; it does not replace the conventional xtables, nftables, TUN, or rtnetlink correctness paths.

> **Non-normative priority notice:** the implementation order in this research snapshot is
> superseded by ADR-0011 and the current roadmap. Optional eBPF and preloaded-extension work remains
> valid design input, but it must not delay canonical lowering, native ownership, or legacy-runtime
> removal and cannot create an intermediate release.

## Executive conclusions

1. `xt_bpf` should be Flux's first eBPF integration. It runs a pinned socket-filter program inside a Flux-owned xtables rule, avoids claiming a qdisc or Android root cgroup, and is present in AOSP's 5.10 base configuration. Availability still requires a complete program/map/pin/userspace-extension/packet-context/cleanup probe. [B1] [B2] [B3]
2. The first program must be observation-only and always return false. The first acceleration may recognize only positive proxy decisions; every miss, parse ambiguity, `bpf_get_socket_uid() == overflowuid`, stale Generation, or map failure continues through the complete classic classifier. `overflowuid` is ambiguous because it can mean no full socket or a legitimate socket UID.
3. eBPF cannot be represented by one global `Off | Observe | Accelerate` backend choice. Each mechanism has different Traffic Domain coverage, attachment ownership, fallback, and failure semantics. Planning must be per domain and per role.
4. A Flux child cgroup does not automatically create a safe attach point. AOSP attaches several program types at the root cgroup with default attach flags, which normally prevents the same attach type in descendants. Child `sockops` telemetry is plausible only after exact attach-state and flag probes; connect/sendmsg/socket-create hooks are not a general production assumption. [B4] [B5]
5. TC on a Generation-scoped TUN remains safer than TC on a physical/tether interface, but legacy TC is not immune to netd restart. The inspected NetworkController removes `clsact` from every extant interface, so a legacy TUN attachment is bound to Network Epoch and reverified after netd lifecycle changes. A verified TCX link is qdisc-less but retains link/order freshness requirements. [B6]
6. Linux 5.10 supports `bpf_sk_lookup_tcp`/`udp` plus `bpf_sk_assign` at TC ingress. This can form a narrow BPF-TPROXY experiment for an exact tether domain, but it still needs a correct local route and safe miss behavior. It is not a general mark or RPDB replacement. [B7] [B8]
7. Netfilter BPF (6.4+) and TCX (6.6+) are optional experiments, not reasons to raise the support floor. TCX is qdisc-less and removes legacy `clsact` ownership, but link identity, foreign-program ordering, and offload semantics still require proof; netfilter BPF does not by itself provide Flux's complete transparent-proxy semantics. [B9] [B10] [B13]
8. Loading `.ko` modules can add powerful functionality, but Flux must not make module loading a production fallback. KMI, symbol allowlists, modversions, signatures, SELinux, AVB/DLKM lifecycle, teardown safety, and boot-loop risk are exact-device properties. Production `fluxd` should neither load nor unload modules. [K1] [K2] [K3] [K4]

## Required architecture adjustments

| Existing plan | Adjustment | Reason |
|---|---|---|
| One global eBPF mode | Compile mechanism/role plans per Traffic Domain | OUTPUT, tether ingress, TUN, and proxy-child sockets expose different facts and hooks |
| TUN TC is the first eBPF hook | Implement `xt_bpf` observation, then proxy-positive parity, before TUN TC observation | `xt_bpf` reuses a Flux-owned chain and has a smaller Android ownership surface |
| Any child-cgroup hook may be used when a child cgroup exists | Query programs and attach flags across the full ancestor chain plus child; use only an actually unoccupied/compatible attach type | An attachment at any ancestor can constrain descendants; AOSP root defaults generally block the same type |
| A successful eBPF load permits `auto` acceleration | Require device-qualified parity, canaries, map/resource bounds, and measured benefit | Verifier acceptance proves syntax/safety, not Flux policy equivalence or performance value |
| Legacy TUN TC attachment survives as long as the TUN link exists | Bind it to link identity and Network Epoch; reverify after netd lifecycle events | netd can delete `clsact` from all extant interfaces; a verified TCX link is qdisc-less but still follows link/order freshness |
| Kernel modules could be a last-resort compatibility backend | Exclude module loading from production; optionally consume a preloaded exact-device extension | Userspace rollback cannot repair a kernel panic or an unload that cannot complete |

The correctness priorities remain unchanged: exact device/artifact identity and reviewed mark authority, the complete 27-cell mark census, safe routing topology, conventional Capture Program parity, and functional canaries precede any decision-bearing eBPF path.

The mechanism order in this note is implementation priority, not runtime coupling. Once a TUN TC,
proxy-child telemetry, or other observation role is implemented, it is independently selectable
from its own domain/attachment probes and conventional fallback; it does not require xtables or an
active `xt_bpf` accelerator.

## eBPF mechanism matrix

| Mechanism | Floor / eligibility | Useful Flux role | Ownership and coverage boundary | Planned position |
|---|---:|---|---|---|
| `xt_bpf` pinned socket filter | Present in the Android 5.10 base configs | Counters, positive proxy matcher, later bounded flow cache | Executes only where a Flux-owned xtables rule references it; OUTPUT socket UID is context-dependent, `overflowuid` is ambiguous, and PREROUTING normally has no app UID | Probe in Phase 4; observe in Phase 7; positive acceleration first in Phase 8 |
| Classic TC `sched_cls` | Older than the 5.10 floor | TUN observation, masked mark/cache acceleration | Requires exact `clsact`/filter ownership; all-interface netd cleanup and tether offload can conflict | Phase 8 after positive `xt_bpf` parity, with continuous revalidation |
| TC ingress `bpf_sk_assign` | Linux 5.7+ | Exact-domain transparent listener assignment | Same netns, compatible transparent socket, local route still required; tether/physical hook has high Android conflict risk | Phase 8 lab experiment only |
| Cgroup `sockops` | Linux 4.13+ | Proxy-child TCP cookie/RTT/retransmit/connection and read-only socket-mark telemetry through validated `ctx->sk->mark` | The full ancestor chain must permit child attachment; TCP-only timing is too late to be the only initial route/loop proof | Phase 8 follow-on canary paired with userspace TCP/UDP mark evidence |
| Cgroup socket-create / connect4/6 | Available on the floor | Socket-create can read/write `bpf_sock.mark`; connect can inspect the socket mark and use `bpf_setsockopt(SO_MARK)` | Any ancestor attachment may block the descendant hook; never replace platform programs | Deferred device-specific mark canary/writer experiment |
| Cgroup bind/sendmsg | Available on the floor by hook | Local socket observation or policy | Linux 5.10 does not expose the same `SO_MARK` setsockopt helper contract here; any ancestor may also block attachment | Observation-only lab experiment |
| Netns `sk_lookup` | Linux 5.9+ | Narrow local listener selection | Netns-global attachment; does not solve OUTPUT classification, routing, established TCP, or connected UDP [B11] | Phase 8 experiment |
| Reuseport BPF | Available at the floor | Select a new listener Generation without changing a public port | Valuable only if Flux controls the listener FD/group or Sing-Box exposes an inheritance contract | Future listener-handoff phase |
| Ring buffer / perf-event array | 5.8+ / older | Sampled exceptional telemetry | Loss and overflow are normal; never correctness-bearing | Phase 7 |
| TUN steering socket filter | Available at the floor | Flow-stable multiqueue selection | Requires `FluxOwnedTunFd`; filtering remains deferred because zero drops | Phase 8 after FD handoff |
| Netfilter BPF | Linux 6.4+ | Low-priority observation/drop research | Newer-kernel, BTF/attach semantics, incomplete TPROXY role | Lab only |
| TCX | Linux 6.6+ | Qdisc-less link-owned TC lifecycle and ordered multi-program attachment | Must inventory foreign programs, preserve ordering, and revalidate link/offload semantics; netd `clsact` deletion does not itself remove the TCX link | Optional Phase 8 attachment adapter |
| XDP / flow dissector / global BPF LSM | Kernel-dependent | Diagnostics or narrowly scoped hardening research | Missing local OUTPUT/UID/route semantics or netns/system-wide failure radius [B12] | Excluded from automatic production selection |

## 1. `xt_bpf`: lowest-conflict first integration

Linux 5.10's `xt_bpf` revision 1 obtains a pinned `BPF_PROG_TYPE_SOCKET_FILTER`; a nonzero return matches the rule and rule destruction drops the program reference. AOSP's `libxt_bpf` exposes `--object-pinned`. [B1] [B2]

The safe sequence is:

1. Build Generation-scoped maps and four baseline programs where supported: OUTPUT/PREROUTING × IPv4/IPv6.
2. Insert an observation rule in a private Flux chain. It updates bounded counters and always returns zero, so the ordinary classifier remains authoritative.
3. Send controlled packets through the exact hook contexts and compare packet parsing, UID availability, counters, rule references, and cleanup.
4. After parity evidence, add a separate positive-proxy rule. Only an unambiguous proxy decision returns nonzero and jumps to the existing TPROXY/MARK action.
5. Treat every miss or ambiguity as “continue classic classification,” never as bypass.
6. Add a bounded LRU flow cache only after first-packet and Generation-transition parity tests.

An `xt_bpf` probe must cover bpffs ownership/label, hash/LPM/per-CPU map operations, socket-filter load and helpers, pin/get, AOSP/vendor iptables revision 1, IPv4/IPv6 packet parsing, OUTPUT `bpf_get_socket_uid` behavior including the ambiguous `overflowuid` value, PREROUTING absence cases, a real packet canary, rule removal before unpinning, and crash cleanup. Config or command presence is only a hint.

Native nftables remains preferred when it is the better proven Capture Backend. Flux must not downgrade a correct nftables plan to xtables solely to obtain `xt_bpf`.

## 2. TC paths and domain-specific socket assignment

### TUN observation and acceleration

A Generation-scoped TUN gives Flux a narrow interface identity and avoids broad physical-interface policy. TC observation may collect counters and sampled flow evidence without changing forwarding. Later masked mark writes can accelerate only a domain for which the conventional classifier, mark authority, local route, and parity oracle are already complete.

The attachment record must include Network Epoch, namespace, ifindex plus link identity, direction, legacy qdisc/filter priority and handle or TCX link ID, attach flags, program ID/tag, policy-map digest, expected Generation, and foreign-program inventory. A netd restart invalidates legacy TC evidence because `clsact` may be removed. TCX is qdisc-less and is not demoted merely because `clsact` disappeared, but link recreation, foreign TCX ordering drift, attachment disappearance, or tag mismatch invalidates either role without changing TUN correctness.

### TC ingress socket assignment

`bpf_sk_assign` lets a TC ingress program assign a compatible TCP listener or unconnected UDP socket selected with BPF socket-lookup helpers. Upstream describes this as a BPF transparent-proxy building block, but the packet still must be routed locally. [B7] [B8]

A possible markless tether experiment is:

```text
exact ingress-interface RPDB selector
  -> direct/bypass prefixes use throw or normal forwarding routes
  -> proxy-positive prefixes use a local route
  -> TC ingress assigns only the verified transparent proxy socket
```

This is safe only if a miss cannot fall into a proxy-local default and blackhole traffic. It does not naturally solve local OUTPUT, UID policy, arbitrary ports, VPN handoff, CLAT, fragments, dynamic default networks, or mixed direct/proxy policy. Reuseport sockets are rejected by the 5.10 TC assignment path, the socket must be in the same network namespace, and later redirect/routing actions can invalidate delivery assumptions.

Consequently this path remains an exact-device tether-domain experiment after positive `xt_bpf` acceleration. Making it correctness-bearing would require a separate ADR, complete domain coverage/fallback proof, and Android end-to-end canaries.

## 3. Proxy-child cgroup evidence

AOSP's BPF loader attaches multiple programs at the root cgroup using ordinary attach behavior. Linux cgroup BPF hierarchy rules mean a descendant normally cannot attach the same type unless the ancestor attachment deliberately permits compatible override or multi-program semantics. [B4] [B5]

Flux should therefore:

- create and verify the Sing-Box child cgroup before the child creates sockets;
- query program inventory and attach flags at every ancestor plus the child for every requested type;
- prefer an actually unoccupied `sockops` hook for optional TCP telemetry;
- report socket cookie, endpoints, state, RTT/retransmit evidence, validated read-only `ctx->sk->mark`, and Generation;
- pair it with controlled TCP and UDP userspace `getsockopt`/INET_DIAG canaries because `sockops` is TCP-only and timing-limited;
- never treat absence of a BPF event as proof of loop escape;
- keep the loop-escape mechanism in conventional userspace/socket marking and routing policy.

Socket-create and connect mark writers remain technically interesting, but are lab-only unless exact device evidence proves that every ancestor is absent or explicitly compatible. Bind/sendmsg hooks on the 5.10 floor are observation/policy experiments, not equivalent `SO_MARK` writers. Flux must never replace an Android cgroup program.

## 4. Backend Plan must be traffic-domain aware

The Phase 3 topology work already distinguishes residual local OUTPUT from exact tether ingress domains. A single capture/routing/eBPF tuple can no longer express the design safely. The target model should resemble:

```rust
struct BackendPlan {
    domains: Vec<DomainBackendPlan>,
    tun: Option<TunBackendPlan>,
    ebpf: EbpfPlan,
    degraded: Vec<DegradedFeature>,
    rejected: Vec<RejectedBackend>,
}

struct DomainBackendPlan {
    domain: TrafficDomain,
    capture: CaptureBackend,
    address_sets: AddressSetBackend,
    routing: RoutingBackend,
    coverage: DomainCoverageProof,
}

struct EbpfPlan {
    requested: EbpfMode,
    roles: Vec<EbpfRolePlan>,
}

struct EbpfRolePlan {
    domains: TrafficDomainSet,
    mechanism: EbpfMechanism,
    role: EbpfRole,
    attachment: AttachmentLeasePlan,
    fallback: ConventionalFallbackProof,
}
```

The compiler must prove domain fragments are bounded, exhaustive for the requested Traffic Scope, selector-disjoint, non-overlapping, and compatible in engine/listener, mark, route, address-set, activation, and cleanup ownership. This model permits heterogeneous plans; it does not make any heterogeneous combination automatically safe.

## 5. Loading `.ko` modules

### What a module could provide

A purpose-built module can reach facilities unavailable to portable userspace or current BPF, including:

- an ipset/xtables compatibility implementation;
- a narrow custom netfilter hook or target;
- typed kernel events through Generic Netlink;
- OEM-specific offload or socket observability;
- an exact custom-kernel service for positive-only acceleration.

That power comes with a kernel-wide failure radius. A bad module can panic or corrupt the running kernel; a userspace journal cannot restore the current boot. Module unload is not a dependable rollback primitive because references, dependencies, live callbacks, disabled unload, or missing teardown can prevent it. [K5] [K6]

### Android portability barriers

Android 12/13 5.10 base configs include module support, unload, modversions, and strict module RWX settings, but this is only eligibility. GKI's stable KMI is scoped to a particular Android release/LTS/config/toolchain and exported symbol list. Signatures and Android's module-signature protection further constrain which symbols an unsigned or non-platform module may use. Vendor/ODM DLKM partitions are AVB-mounted and participate in the device's OTA and depmod lifecycle; a `.ko` under `/data/adb/flux` does not inherit that trust or update contract. [B3] [K1] [K2] [K3] [K4]

Root frameworks may make `insmod` possible by altering policy, but they do not manufacture ABI compatibility, a trusted signature, safe hooks, or reversible behavior. APatch KPM/inline/syscall hooks add a separate private ABI and are outside Flux's acceptable production boundary.

### Production policy

Production Flux must:

- package no `.ko`, KPM, or opaque kernel payload;
- call neither `init_module` nor `finit_module`, and never unload a module;
- never bypass vermagic, modversion, symbol, or signature validation;
- treat an already-loaded module as a capability hint until behavior is probed;
- never infer mark ownership or device-policy authenticity from module presence;
- keep a complete non-module correctness fallback.

An already-loaded, reviewed OEM/custom-kernel extension may be consumed only as an optional exact-device read-only observation facility. The target `KernelExtensionProfile` binds boot and netns identity; architecture and exact kernel/build/KMI; Android build and security patch; owner/provenance/digest/license/signer; independently observed AVB/module-signature/measurement identity; module/built-in live identity; Generic Netlink family/protocol/NLA-policy revision; hook priorities; observed mark planes/masks; active canary; and runtime demotions.

The interface handshake resolves the family through Generic Netlink control, validates kernel sender/sequence/command/reserved fields and strict attributes, and exchanges a nonce plus expected protocol/boot/netns identity for origin and correlation. Echoed build/digest fields are claims, not authentication. Trust requires independently observed AVB/module-signature/measurement evidence matching a reviewed catalog or explicit expert record, followed by a nonpersistent behavioral canary. [K7]

Even this preloaded-extension path is expert/experimental read-only observation. Positive acceleration requires a concrete partner, a separate ADR, a passive-by-default Generation lease with heartbeat expiry, verified enable/disable canaries, and conventional fallback. A custom direct Capture Path, custom xtables/nft expression, new BPF helper/kfunc, or Flux-managed module loader remains lab-only.

## Recommended implementation order

1. Finish exact Android/device/artifact identity and the reviewed positive mark-policy catalog.
2. Complete the remaining mark census fragments and point-in-time 27-cell coordinator.
3. In parallel, fix bridge safety: special-use prefixes, empty allowlist semantics, TUN route ownership, readiness, and functional canaries.
4. Add exact `xt_bpf` probing to the Rust xtables phase and keep the generated classic program complete.
5. Ship observation-only `xt_bpf`; collect real-device context and overhead evidence.
6. Add positive-proxy `xt_bpf` plus a sampled parity oracle; add flow caching only after parity and resource tests.
7. Add TUN TC observation with Network Epoch revalidation, then optional proxy-child `sockops` canaries.
8. Add masked TC acceleration only for independently proven Traffic Domains.
9. Evaluate TC socket assignment, TCX, netfilter BPF, netns `sk_lookup`, and listener reuseport as separate experiments.
10. Keep `.ko` loading outside all production phases; keep any generic preloaded-extension consumer read-only, and define a decision-bearing contract only if a concrete OEM/custom-kernel partner justifies a separate ADR.

## Primary sources

[B1]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/xt_bpf.c
[B2]: https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/extensions/libxt_bpf.c
[B3]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/s/android-5.10/android-base.config
[B4]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/netd/BpfHandler.cpp
[B5]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/bpf/cgroup.c
[B6]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/NetworkController.cpp
[B7]: https://github.com/torvalds/linux/commit/cf7fbe660f2dbd738ab58aea8e9b0ca6ad232449
[B8]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/core/filter.c
[B9]: https://github.com/torvalds/linux/commit/e420bed02507
[B10]: https://github.com/torvalds/linux/commit/84601d6ee68a
[B13]: https://github.com/torvalds/linux/blob/v6.4/net/netfilter/nf_bpf_link.c
[B11]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/bpf/prog_sk_lookup.rst
[B12]: https://github.com/torvalds/linux/blob/v6.18/Documentation/bpf/prog_lsm.rst

[K1]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/t/android-5.10/android-base.config
[K2]: https://source.android.com/docs/core/architecture/kernel/stable-kmi
[K3]: https://source.android.com/docs/core/architecture/kernel/vendor-module-guidelines
[K4]: https://source.android.com/docs/core/architecture/partitions/vendor-odm-dlkm-partition
[K5]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/module.c
[K6]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/admin-guide/module-signing.rst
[K7]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netlink/genetlink.c
