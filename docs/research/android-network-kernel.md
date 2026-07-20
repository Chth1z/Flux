# Android networking and kernel constraints for the Flux rewrite

- Status: research note for the Rust `fluxd` architecture
- Last researched: 2026-07-13
- Minimum supported kernel required by the project: Linux 5.10

## Executive findings

1. Android's packet/socket mark is shared platform state, not a free-form tag. AOSP uses bits 0-15 for the Android network ID and additional bits for explicit network selection, VPN protection, permissions, billing, vendor use, and wakeup accounting. Generic AOSP grants Flux no mark field; even bits 21–30 are only a device-qualified candidate envelope. The current Flux values `0x14`, `0x19`, and `0x11` under mask `0xff` overlap Android's network-ID field and are unsafe for the rewrite. [S8], [S9]

2. Android's routing policy database is part of ConnectivityService/netd's control plane. Current AOSP priorities 10000-32000 encode secure VPN, per-UID, explicit-network, local-network, tethering, default-network, and unreachable behavior. A Flux rule at priority 2025 precedes all of them; once Flux marks a packet, that placement can bypass Android VPN/lockdown decisions. The rewrite needs an explicit policy such as `respect_android_vpn = true`, a runtime rule audit, and a tested placement strategy rather than a fixed global priority. [S10]

3. AOSP Android 5.10 kernel requirements include BPF, cgroup BPF, legacy xtables TPROXY/socket matching, TC BPF classifiers, ingress/clsact support, and TUN. They do **not** require nftables, nft TPROXY/socket expressions, ipset, BTF, or BPF LSM. Those features are valid optional accelerators but cannot be assumed merely because `uname` reports 5.10 or newer. [S19]

4. Android's platform `iptables` binary is deliberately built as the **legacy** xtables implementation, and netd invokes `/system/bin/iptables-restore`. An nftables backend therefore creates a separate netfilter control plane; Flux must select exactly one Flux-owned backend at a time and leave Android/netd chains intact. [S11], [S20]

5. Android already owns global eBPF hooks. AOSP attaches cgroup programs to the root cgroup with ordinary attach flags for accounting/firewall behavior, which normally prevents the same hook type in descendants, and netd deletes `clsact` qdiscs from every extant interface during its own startup. Flux must not replace Android programs or assume that a child cgroup makes connect/socket-create hooks available. `xt_bpf` inside a Flux-owned xtables chain is the lowest-conflict first experiment; the project implements proxy-positive `xt_bpf` parity before TUN TC observation, but the latter is independently eligible at runtime from its own Network Epoch/link-order evidence. Physical/tether TC/XDP and netns-wide `sk_lookup` remain experimental. [S12], [S21], [S32], [S48]

6. Magisk's module `service.sh` runs in non-blocking late-start mode; `post-fs-data.sh` is blocking and should be kept free of networking work. Upstream Magisk injects its callbacks under `u:r:magisk:s0` and makes its root domain permissive/unconstrained, but Android capabilities, LSM hooks, device nodes, cgroup ownership, module signatures, and vendor forks can still make individual operations fail. Every privileged feature needs an operation-level probe with the failure classified as absent, policy-denied, or conflicting. [S1], [S2], [S4], [S5]

7. Netlink notifications are lossy. The kernel reports receive overruns with `ENOBUFS` unless suppression is requested, and dumps may carry `NLM_F_DUMP_INTR`. A correct address/rule synchronizer uses initial dumps plus multicast, detects loss/inconsistent dumps, and schedules a complete reconciliation. Notifications are triggers, never the durable source of truth. [S28], [S33], [S34]

8. Crash safety requires desired-state reconciliation. Publish interception hooks last; remove them first. Query and modify only exactly identified Flux objects. nftables changes should use one atomic batch, while rtnetlink and legacy xtables require staged, idempotent reconciliation. A supervisor must remain alive when the proxy worker crashes so it can remove hooks immediately.

## Research method and pinned sources

Relevant upstream repositories were cloned with shallow/sparse checkouts into:

`C:\Users\Chth1z\AppData\Local\Temp\flux-upstream-research-20260711`

No upstream source was vendored into Flux. The inspected revisions were:

| Repository | Revision | Commit date / note |
|---|---|---|
| AOSP `system/netd` | `e11b8688b1f99292ade06f89f957c1f7e76ceae9` | 2025-03-24 |
| AOSP `packages/modules/Connectivity` | `2519a78731526d2eb20ae8812acdcab6ef7a09b6` | 2025-03-27 |
| AOSP `frameworks/base` | `1cdfff555f4a21f71ccc978290e2e212e2f8b168` | 2025-03-26 |
| AOSP `system/core` | `a3b721a32242006b59cb12bd62c9133632af3a2d` | 2025-03-26 |
| AOSP `system/sepolicy` | `4571ddd9440721fec583c906a337de949a77749e` | 2025-03-27 |
| AOSP `kernel/configs` | `bd79f38685cf939ab836dd8ddd2e01506ccff47a` | 2025-03-27 |
| AOSP `external/iptables` | `672d4a9452846646a3017d255fae319e12d92295` | 2025-03-04 |
| Magisk | `14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c` | 2026-05-05 |
| Linux stable 5.10.y | `738ac465e4e900d4a391a27da4e20c090eaa1e75` | Linux 5.10.260, 2026-07-04 |

Windows checkout limitations were encountered but did not block inspection: the sparse `frameworks/base` worktree hit long paths, and the Linux worktree hit the Windows-reserved filename `aux.c`. Both object databases were complete enough to inspect exact blobs with `git show` and `git grep`.

## 1. Android boot and Magisk service lifecycle

Magisk exposes two module boot stages:

- `post-fs-data.sh` is blocking, runs before Zygote, and can pause boot for up to 40 seconds. Magisk explicitly recommends using it only when necessary.
- `service.sh` runs in non-blocking late-start mode and is the recommended stage for normal module work.
- Scripts execute in Magisk BusyBox `ash` standalone mode. [S1]

Magisk injects init callbacks for `post-fs-data`, service/late-start, and `sys.boot_completed=1` under `u:r:magisk:s0`. Its boot-complete callback resets Magisk's boot-loop state; upstream does not invoke a separate per-module `boot-completed.sh` from that callback. [S2], [S3]

AOSP init starts service classes in phases; `main` and `late_start` are started during normal boot, while `sys.boot_completed=1` is a later framework milestone. Init also supports putting a service into a named network namespace with `enter_namespace net <path>`, but netd's AOSP service definition does not use it. [S5], [S6], [S7]

### Recommended Flux lifecycle

1. Omit `post-fs-data.sh` unless a future migration absolutely requires pre-mount work. It must never install routes, rules, netfilter hooks, TUN devices, or BPF programs.
2. Keep `service.sh` as minimal glue that `exec`s one long-lived `fluxd daemon` process. Avoid a chain of background shells and PID files.
3. `fluxd` starts in **observe-only** mode. It verifies the boot ID and network namespace, opens route-netlink, loads configuration, probes capabilities, and waits for netd/readiness signals.
4. Activation requires all hard prerequisites, a ready proxy listener/TUN worker, and a successful dry reconciliation. `sys.boot_completed=1` is a useful readiness signal, not a guarantee that networking will stop changing.
5. Proxy engine failure is handled inside the still-running supervisor. The supervisor removes capture hooks immediately, then restarts the worker with bounded backoff.
6. A second module invocation must acquire an advisory singleton lock and hand control to the existing daemon rather than create another dataplane.

Readiness should be state-based, not a fixed sleep:

- `/proc/1/ns/net` matches `/proc/self/ns/net`;
- `init.svc.netd=running` when that property is available;
- route-netlink link/address/rule dumps succeed;
- Android's BPF boot has completed where the platform exposes the property/path;
- the selected netfilter/TUN backend passes a functional probe;
- the proxy listener or TUN worker reports ready.

## 2. Android's network control plane

### 2.1 netd is an Android-owned privileged controller

AOSP runs netd as a root `class main` service with a deliberately enumerated capability set including `NET_ADMIN`, `NET_RAW`, and `NET_BIND_SERVICE`. It owns the `fwmarkd` socket, invokes legacy `iptables-restore`, manages routing policy, and is tightly coupled to system-server: netd restart requests Zygote restarts. [S7], [S11]

Flux must treat netd as a peer owner of kernel state, never as an implementation detail to replace or patch. In particular:

- do not flush built-in tables, Android chains, root cgroup programs, or shared qdiscs;
- do not restart or signal netd;
- do not depend on undocumented timing between netd, Zygote, Connectivity mainline modules, and vendor services;
- perform a full Flux reconciliation after every observed netd restart.

### 2.2 UID model, users, profiles, and isolated processes

Android composes a Linux UID from `userId * 100000 + appId`. Normal application app IDs are 10000-19999. Isolated and app-Zygote isolated processes use separate app-ID ranges, and SDK sandboxes have mapped UIDs. Therefore a package name, app ID, UID, and user/profile are not interchangeable. [S13], [S14]

Consequences:

- A per-app policy must expand to concrete UIDs for every selected user/profile.
- Work profiles and secondary users require separate UIDs even for the same package.
- Isolated and SDK-sandbox traffic may not carry the parent application's UID. Treating it as automatically equivalent can either leak or over-capture traffic.
- UID ownership matches apply to locally generated socket traffic. Forwarded hotspot/tethering packets generally have no meaningful originating Android app UID at the `FORWARD`/prerouting hook, so hotspot policy needs a distinct interface/client policy.
- Package/user changes are control-plane events. Recompute desired UID sets on configuration change and user/package lifecycle, then atomically replace the set; do not incrementally append forever.

### 2.3 Network namespaces

Baseline AOSP does not isolate each app in a separate network namespace. Apps share the Android network namespace and are separated primarily through UID rules, socket marks, cgroups/eBPF, firewall policy, and SELinux. AOSP init can explicitly enter a netns, so vendor services and test environments can differ. [S5], [S10], [S32]

At startup, Flux must record:

- boot ID from `/proc/sys/kernel/random/boot_id`;
- self and PID 1 network-namespace inode;
- mount-namespace inode, because bpffs and module paths can be namespace-sensitive;
- effective/permitted/bounding capabilities from `/proc/self/status`.

The default policy is to refuse activation if Flux is not in PID 1's network namespace. Silently installing a complete ruleset into the wrong namespace produces a false-success failure mode. Automatic `setns` should be an explicit, separately probed recovery option, not a default.

## 3. fwmark, policy routing, and VPN semantics

### 3.1 Android mark layout

At the inspected netd revision, `Fwmark` is a 32-bit union containing:

| Bits | AOSP meaning |
|---|---|
| 0-15 | `netId` |
| 16 | explicitly selected network |
| 17 | protected from VPN |
| 18-19 | network permission |
| 20 | UID billing completed |
| 21-28 | AOSP reserved |
| 29-30 | vendor reserved |
| 31 | ingress CPU wakeup |

netd reads the existing `SO_MARK`, updates selected fields, and writes the merged mark back. Android also copies a defined subset of fwmark into connmark, while other Android components use additional connmark flag bits. [S8], [S9], [S11]

There is no public allocator for third-party mark bits. Even AOSP-reserved bits are not a perpetual promise to Magisk modules, and OEM QoS/security code may use additional masks.

### 3.2 Required positive mark authority

Negative conflict analysis cannot allocate a mark field. Generic AOSP has no public allocator and is modeled as an explicit zero grant. The inclusive bits 21–30 mask (`0x7fe0_0000`) is only a syntactic envelope in which an exact device-qualified policy may name a candidate; it is not a reservation, and taking the complement of observed masks is forbidden.

A positive grant can be constructed inside `flux-core` only after exact selection from the compiled reviewed-policy catalog; external adapters cannot inject one directly. It binds the exact mask/proxy/bypass candidate, exact atomic TPROXY topology scope, full `CapabilityProfile` with verified boot identity, network-namespace identity, a named cooperative policy with a nonzero SHA-256 artifact digest and policy revision, and the exact nonempty mark-plane set asserted by that policy. A partial plane assertion is representable but insufficient: planning authorization requires packet, socket, and conntrack coverage. Automatic and explicit mark configuration supply candidates only and require the same grant; explicit input is not an override.

Live authorization consumes one point-in-time, non-cloneable complete census. It requires exactly nine sources across all three planes, or 27 complete-present/complete-absent coverage records:

1. Android `netId`;
2. RPDB selectors;
3. device mark policy;
4. legacy xtables;
5. nftables;
6. TC/BPF;
7. XFRM;
8. connmark/socket transfers;
9. existing Flux ownership.

RPDB `fwmark` rules do not read an intrinsically packet-only field. Linux FIB-rule matching compares
the selector with transient `flowi_mark`; IPv4 and IPv6 packet-origin paths populate that value from
`skb->mark`, while local socket-output paths populate it from `sk->sk_mark`. The first bounded RPDB
fragment therefore records each observed selector mask as both a packet-plane and socket-plane
predicate read. It records the RPDB conntrack cell as complete-absent because FIB rules do not
directly read ctmark; any ctmark-to-packet influence belongs to the separate transfer evidence
source. Opaque rule attributes make both flow-origin cells opaque without discarding known
selectors. [S43], [S44], [S45], [S46], [S47]

The second source fragment models Android `netId` only under an explicitly selected, source-pinned
AOSP netd profile shared with RPDB classification. The inspected Android 12 r1, Android 13 r1, and
March 2025 sources all define bits 0-15 as `netId`, but `modifyIncomingPacketMark` deliberately uses
a wider xtables mask. Android 12/13 preserve only UID billing and therefore write `0xffef_ffff`; the
pinned 2025 source also preserves ingress CPU wakeup and writes `0x7fef_ffff`. Both masks intersect
every bit in Flux's `0x7fe0_0000` device-qualified candidate envelope. `FwmarkServer` separately
reads the existing socket mark, consults `netId`, updates the low-16-bit field, and writes the merged
mark back. The fragment therefore records the exact profile-specific packet `MaskedWrite` plus
low-16-bit socket `PredicateRead` and `MaskedWrite`. Direct conntrack coverage is complete-absent
because AOSP's packet-to-conntrack save rules are represented by the separate transfer source. This
static source profile does not authenticate the runtime netd binary or select itself for a device.
[S8], [S9], [S40], [S53], [S54], [S55], [S56]

The packet overlap has an important lifetime boundary. All three pinned sources append the
incoming-packet writer to `routectrl_mangle_INPUT`; netd creates that child below the built-in
mangle INPUT hook. Linux IPv4 and IPv6 receive paths run PREROUTING, complete the input route lookup,
and reach LOCAL_IN afterward. Canonical Flux forwarded capture consumes its candidate during
PREROUTING plus local route selection, while local OUTPUT consumes it during output rerouting and
the loopback-reinjected PREROUTING route decision. The exact Android `netId` packet masked writer is
therefore a known ordered late write, not by itself a proven simultaneous routing collision.
[S11], [S57], [S58]

That static ordering still grants no compatibility. The later INPUT rewrite can affect the mark
seen by the transparent listener or an observer, and source text does not bind the live netd
artifact, chain shape, or input-interface selector to one device Traffic Domain. The exact overlap
must remain fail-closed until a physical Android ARM64 profile proves runtime source/chain binding,
listener and observer continuity, VPN/netd coexistence, and mark preservation. Definite or unknown
overlaps retain conflict precedence. The remaining 21 source-plane cells should not displace this
gate and are paused until that target and qualification procedure are viable.

Unsupported, duplicate, incomplete, opaque, denied, unknown, inconsistent, over-budget, or transient-attempt coverage grants no authority. The census accepts at most 512 raw predicate-read, masked-write, transfer-read, or transfer-write records before canonical sorting and deduplication, and binds the exact inventory snapshot identity/epoch, full capability facts and boot, namespace, policy identity/revision, collector revision, and durable ownership-journal identity/revision. Every candidate-mask overlap still rejects regardless of compared values: definite or unknown uses are conflicts, while only the exact Android `netId` packet masked writer receives the ordered-qualification diagnostic. Opaque RPDB evidence rejects even if another census cell claims completeness, and definite conflicts are decided before ordered writes or an otherwise incomplete topology report.

The resulting `AndroidMarkPlanningAuthority` is privately constructed, non-`Clone`, and limited to pure planning. It exposes no `MarkLease`, rule priority, route table, route intent, encoder, writer, ownership operation, mutation authority, or activation conversion. Reauthorization consumes it and requires a newly collected census. Exact writer semantics, authenticated runtime hook/profile ordering, listener and mark-observer continuity, and a physical-device mark-preservation/coexistence canary remain mark-specific prerequisites; Capture Program ordering, domain/network-selection handoff, route reachability, topology observer continuity, durable ownership, exact mutation identity, engine loop escape, and shape-specific one-rule address handling remain separate topology prerequisites.

All writes use masked merge semantics:

```text
new_mark = (old_mark & ~flux_mask) | (flux_value & flux_mask)
```

This formula is arithmetic, not write authority. A userspace socket writer must read `SO_MARK` with `getsockopt` before masked `setsockopt`. A 5.10 cgroup socket-create program can read/write `bpf_sock.mark` directly; a connect4/6 program reads `ctx->sk->mark` and may use `bpf_setsockopt(SO_MARK)`—`bpf_getsockopt(SO_MARK)` is not the read path. xtables must use `--set-xmark value/mask` and explicit `--nfmask/--ctmask` on CONNMARK operations. Never save, restore, or overwrite all 32 bits.

### 3.3 Android RPDB and VPN policy

netd defines a priority lattice beginning with VPN override/output rules, secure VPN and prohibit-non-VPN rules, followed by explicit-network, local/tethering, implicit/default-network, and unreachable rules. It can match UID ranges, fwmark/mask, interfaces, and tables through rtnetlink attributes. [S10], [S29]

The release families relevant to Flux are not one lattice. Android 12/12L and Android 13+ require separate closed grammars, while Android 14+ additionally permits a dynamic physical-local rule at priority `20000`. [S37], [S38], [S39], [S40]

| Role | Android 12/12L | Android 13+ |
|---|---:|---:|
| VPN override system/OIF/output-local | `10000` / `11000` / `12000` | same |
| Secure VPN / prohibit non-VPN | `13000` / `14000` | same |
| UID explicit / explicit / output-interface | `15000..15999` / `16000..16999` / `17000..17999` | same |
| Legacy system/network / local / tethering | `18000` / `19000` / `20000` / `21000` | same |
| UID implicit / implicit / bypassable VPN | `22000..22999` / `23000` / `24000..24999` | same |
| UID-local / local-route / local-exclusion VPN | absent | `25000` / `26000` / `27000..27999` |
| VPN fallthrough | `26000` | `28000` |
| UID default network | `27000..27999` | `29000..29998` |
| UID default unreachable | `28000..28999` | `30000..30998` |
| Default network / final unreachable | `29000` / `32000` | `31000` / `32000` |

The netd rule builder is otherwise strict: it creates paired IPv4/IPv6 rules with wildcard source/destination, zero TOS and flags, `RTPROT_UNSPEC`, and only the expected table, fwmark/mask, UID, input-interface, or output-interface attributes. It emits no GOTO, tunnel, suppressor, L3MDEV, IP-protocol, port-range, or flow selector. Priority alone is never role evidence; every modeled field must match the selected source-pinned grammar. [S41]

Two structural consequences affect the current Flux routing program. First, Android 12 leaves no priority after the maximum UID-default-unreachable subpriority and before default-network; Android 13+ leaves only `30999`, while Flux currently requires two distinct priorities. Second, one global proxy rule cannot both run after per-UID local-output policy near `29000`/`31000` and before tethering at `21000`. Empty observed slots are not leases: equal-priority insertions are ordered after existing equal-priority rules, and netd may add a later security rule without colliding at creation time. [S42]

The first safe model consequence is to split domains instead of moving one global rule. Residual local OUTPUT is anchored to an exact observed default-network rule and its `iif lo` plus fwmark selector; a tether domain is anchored to an exact priority-`21000` tethering rule and the same present, administratively-up ingress interface. This yields no local slot on Android 12, only `30999` on Android 13+, and `20001..20999` for one exact tether ingress. A table number alone is not a stable network identity, and capture before either anchor still needs explicit per-connection domain identity plus Android network-selection handoff. Multiple overlapping anchors that name different tables are therefore ambiguous rather than evidence for a choice.

Address-derived local hosts can be selected independently of an RPDB realization. Compiling those hosts into a pre-mark Capture Policy bypass would reduce the local structural requirement from two priorities to one, but it is safe only after the selected backend proves that address bypass precedes connmark restoration, every mark write, and proxy action during atomic address churn. Private-table `throw` host routes remain a possible probed fallback, not an assumed design property.

Requested domains must also be assessed as one atomic scope rather than as unrelated favorable examples. The current pure model binds one routing shape to a bounded set of residual-local address families and exact tether ingress interfaces, discovers every recognized matching anchor, and retains each anchor's own selector and priority interval. Missing or ambiguous anchors reject the scope; known incompatibility or slot exhaustion remains definite even when another anchor is incomplete. A scope containing only residual candidate windows is still not an allocation: no common priority is inferred across domains, and full freshness reassessment is required after any inventory or classifier change.

Design requirements:

- Default to `respect_android_vpn = true`. A transparent proxy must not accidentally turn lockdown into bypass.
- Detect an active Android VPN and expose the interaction in status.
- Do not select a rule priority from a constant alone. Audit existing rules and run integration tests for no VPN, bypassable VPN, always-on VPN, lockdown VPN, per-app VPN, and explicit-bound networks.
- Route the proxy's own outbound sockets through an explicit escape path that preserves Android's network selection. Avoid a global root-UID bypass because it exempts unrelated root traffic.
- Consider using Android's fwmark service semantics for network selection/protection only behind a versioned adapter. `fwmarkd` is an internal protocol, not a stable third-party API.
- Treat changes to default network, VPN network, and per-UID preferences as reconciliation triggers.

## 4. VPN and TUN

Android's public VPN API creates a TUN interface, returns its file descriptor, and requires the VPN process to protect its own upstream sockets to avoid recursive tunnelling. AOSP's native implementation opens `/dev/tun` with nonblocking/close-on-exec flags, requests `IFF_TUN | IFF_NO_PI` with `TUNSETIFF`, brings the interface up, and sets MTU/addresses. [S15], [S16], [S17]

Upstream Linux describes TUN as an IP packet device and documents multiqueue support via multiple `TUNSETIFF` calls with `IFF_MULTI_QUEUE`. Closing all nonpersistent TUN file descriptors removes the device; however, independently installed policy rules and netfilter state still require reconciliation. [S25]

### Recommended TUN backend

- Ship `EngineOwnedTun`: a version-qualified Sing-Box creates the interface and owns queue FDs/packet I/O, while `fluxd` verifies exact link identity and owns surrounding routes, rules, exclusions, and recovery.
- Keep a direct Rust UAPI adapter for contained probes and the future `FluxOwnedTunFd` contract. Probe Android's `/dev/tun` first and Linux's conventional `/dev/net/tun` second.
- Use route-netlink for link observation and address/route/rule configuration; avoid parsing `ip` output in the daemon.
- Resolve Sing-Box multiqueue/offload toggles from the Engine Capability Profile. Direct queue-count control requires future Flux FD ownership and a two-queue create/close/packet test.
- When Flux owns queues in that future plan, size them from CPU count and measured contention, not one queue per CPU unconditionally.
- Keep MTU adaptive to the selected underlying network and IPv6 minimum requirements.
- Exclude the proxy's upstream sockets before publishing the TUN routes.
- On worker crash, remove capture/routing to TUN before closing or replacing the worker.
- Reserve and collision-check Generation-scoped TUN interface names even though Sing-Box creates the shipping link.

Two operating modes should remain distinct:

1. **TPROXY mode**: preserves original destination and uses a local-route policy table; best when xtables/nft TPROXY is fully available.
2. **TUN mode**: captures through routes into a userspace IP device; more portable across netfilter variants but requires careful route/VPN coexistence and packet-loop prevention.

Do not combine both capture paths for the same traffic class.

## 5. Legacy iptables, nftables, and ipset

### 5.1 Android baseline is legacy xtables

AOSP netd hardcodes `/system/bin/iptables-restore` and `ip6tables-restore`. The Android build of external/iptables uses `xtables-legacy-multi.c` and builds the legacy `iptables`/`ip6tables` save/restore symlinks. netd's chain setup explicitly preserves unknown/vendor rules in shared chains across a crash/restart instead of flushing and recreating them. [S11], [S20]

The Flux legacy backend should:

- use a dedicated chain namespace and exact jump comments;
- use `iptables-restore --wait`/the Android xtables lock rather than racing netd;
- install or replace only Flux chains and exact parent jumps;
- snapshot enough identity to remove stale Flux revisions without deleting vendor rules;
- apply one family/table payload at a time and verify the result;
- never invoke `iptables -F`, flush built-ins, or replace an Android-owned chain.

### 5.2 nftables is optional on Android 5.10

Linux 5.10 supports nftables, native sets/maps, socket matching, and TPROXY. The kernel documentation states nft TPROXY is available since Linux 4.18 and requires `NFT_SOCKET` and `NFT_TPROXY`. nftables commits batched changes through a generation-based transaction path. [S24], [S26], [S35]

However, the Android S/T 5.10 base fragments do not require `CONFIG_NF_TABLES` or those expressions, and AOSP does not build `nft` as its platform firewall frontend. [S19], [S36], [S20]

If enabled, Flux should:

- use one dedicated table per family or an `inet` table only after functional validation;
- use one atomic netlink batch for table/chain/set/rule replacement;
- tag tables/chains/rules with Flux names and nft userdata;
- choose explicit hook priorities after inspecting Android legacy hooks;
- never install the equivalent Flux legacy rules simultaneously;
- listen for nft generation notifications where available, while still doing periodic verified reconciliation.

Legacy iptables and nftables can both register netfilter hooks. A rule that exists in both is not a migration aid; it is duplicate interception with order-dependent behavior.

### 5.3 ipset is also optional

Linux 5.10's `CONFIG_IP_SET` provides nfnetlink-managed set types such as `hash:ip` and `hash:net`, but Android's 5.10 base fragments do not require it. [S19], [S27]

Backend order for large bypass collections:

1. nft native interval/hash sets when the nft backend is active;
2. ipset only after protocol/version and required set-type create/destroy probes;
3. a bounded legacy rule/zone fallback;
4. reject an oversized configuration rather than silently installing an unbounded linear ruleset.

`fluxd` should speak nfnetlink directly for ipset if implemented; shipping a helper binary is acceptable, but command presence is not proof of kernel support.

## 6. eBPF opportunities and boundaries

### 6.1 Android already has a BPF control plane

Android's network accounting/firewall design loads programs at boot, pins maps in bpffs, and attaches cgroup programs at the root cgroup. AOSP netd checks kernel/platform versions, attaches ingress/egress, socket-create/release, connect, bind, sendmsg/recvmsg, and sockopt programs according to availability, and treats BPF-loader failure as boot-critical. [S21], [S23], [S32]

AOSP also uses TC BPF for tethering offload. netd's `NetworkController` constructor deletes `clsact` qdiscs on every enumerated interface during startup, so both physical and TUN legacy-TC attachments can disappear when netd restarts. A verified TCX link is qdisc-less but still requires link-identity and program-order freshness. [S12]

### 6.2 Safe default BPF scope

The production default may use eBPF only where Flux owns the effective attachment point:

- a pinned `xt_bpf` socket-filter referenced only from a Flux-owned xtables rule, first for observation that always returns false and later for proxy-positive decisions with complete classic fallback;
- after proxy-positive `xt_bpf` parity, TC ingress/egress observation on a verified Generation-scoped TUN interface under a legacy Flux-owned qdisc/filter lease or verified TCX link;
- ring-buffer telemetry from a Flux-owned program;
- maps pinned under a unique Flux bpffs directory only after verifying ownership and mount visibility;
- optional proxy-child `sockops` telemetry only if program inventory and attach flags across the full cgroup ancestor chain plus child prove that exact hook available.

Do not replace Android cgroup programs. AOSP currently uses `BPF_PROG_ATTACH` with default flags for several root hooks, and an attachment at any ancestor can constrain descendants. A child cgroup is therefore a scope boundary only after the full ancestor chain plus child proves the exact hook unoccupied or explicitly compatible. [S21], [S48]

### 6.3 Experimental BPF features

| Feature | Possible value | Constraint |
|---|---|---|
| BPF ring buffer | Ordered, low-copy telemetry across CPUs | Probe `BPF_MAP_TYPE_RINGBUF`, mmap, epoll, verifier, SELinux, and 32/64-bit compatibility; never make forwarding depend on telemetry. [S30] |
| `BPF_PROG_TYPE_SK_LOOKUP` | Select a local TCP/UDP socket for an L7 proxy over wide address/port ranges | Attaches to the whole netns through `BPF_LINK_CREATE`; global scope and program ordering make it experimental. It does not itself perform policy routing. [S30] |
| TC clsact BPF | Fast classification, mark merge, counters, possible redirect on Flux TUN | Restrict to Flux TUN by default. Physical interfaces conflict with netd/tethering and require restart reconciliation. |
| XDP | Very early filtering/telemetry | Driver support is fragmented, it does not cover local output, and it can interfere with vendor offload. Lab-only for this project. |
| cgroup sock_addr/sockops | Per-proxy-socket policy, upstream selection telemetry | Use only after full ancestor-chain plus child inventory proves the exact hook compatible. |
| TC ingress socket assignment | Assign a compatible transparent listener for an exact tether domain | Linux still requires a correct local route and safe miss behavior; physical/tether TC ownership, CLAT, VPN, fragments, and offload make this a lab-only exact-device path. [S49] |
| CO-RE/BTF | Fewer per-kernel object variants | `CONFIG_DEBUG_INFO_BTF` and readable `/sys/kernel/btf/vmlinux` are not Android 5.10 base requirements. Keep a UAPI-only/no-BTF path. |

Linux's BPF design documentation is explicit that the only reliable way to know whether the verifier accepts a program is to load it. Version and Kconfig checks are prefilters, not activation decisions. [S30]

## 7. SELinux, capabilities, and kernel modules

AOSP grants netd operation-specific SELinux permissions for BPF maps/programs, TUN ioctls, route/netfilter netlink sockets, and `NET_ADMIN`/`NET_RAW` capabilities. The policy also states that netd should not request module loading and that required kernel features should be built in. [S18]

Upstream Magisk creates a permissive, broadly allowed root domain for its processes, but the rewrite must not collapse all failures into “kernel unsupported.” [S2], [S4]

Capability probe results need separate classes:

| Result class | Typical evidence | Meaning |
|---|---|---|
| `supported` | minimal real operation succeeds | Safe to consider for activation |
| `unsupported` | `ENOPROTOOPT`, `EOPNOTSUPP`, missing device, unknown nft expression | Kernel/config/userspace feature absent |
| `denied` | `EACCES`/`EPERM` plus capability/AVC evidence | Kernel may support it, execution context does not |
| `conflicting` | existing hook, mark-mask, qdisc, table, or rule ownership collision | Feature exists but is unsafe to claim |
| `broken` | verifier/kernel error inconsistent with the advertised baseline | Vendor backport/ABI defect; disable and report |
| `unknown` | no safe conclusive probe is possible | Do not select a decision-bearing role |

Timeout, interruption, busy/resource pressure, and racing state are probe-attempt outcomes with bounded retry/backoff evidence, not a durable `transient` capability class.

Flux must not automatically load or unload kernel modules. Android's 5.10 base configs enable modules, unload, modversions, and strict module RWX, but that does not make a portable `.ko`: GKI KMI is scoped to one Android release/LTS/config/toolchain and exported symbol list; signature protection, SELinux loader domains, read-only AVB/DLKM placement, dependencies, live references, and teardown remain exact-device constraints. A module can panic the kernel, and userspace rollback cannot repair the current boot. [S19], [S31], [S50], [S51], [S52]

Production Flux packages no `.ko`, KPM, or opaque kernel payload and calls no module load/unload syscall. It may consume an already-loaded reviewed OEM/custom-kernel extension only as optional read-only observation through a freshness-bound exact-device profile, independently verified AVB/module-signature/measurement identity, a versioned strictly validated Generic Netlink contract, and an active canary. Sender/sequence/nonce checks provide origin and correlation, not source-build authentication. Decision-bearing use requires a concrete partner and separate ADR. Module presence cannot grant mark ownership or authenticate its own device policy. The detailed assessment is in [`ebpf-and-kernel-extensions-2026-07.md`](ebpf-and-kernel-extensions-2026-07.md).

## 8. Netlink notifications and synchronization

Route-netlink provides link, IPv4/IPv6 address, route, and rule multicast groups and messages. The kernel can drop multicast messages when a receiver overruns, setting `ENOBUFS` and a drop counter. Dumps can be inconsistent and marked `NLM_F_DUMP_INTR`. [S28], [S33], [S34]

The correct Flux synchronization loop is:

1. Open the multicast socket with a large receive buffer. Do **not** enable `NETLINK_NO_ENOBUFS` because Flux needs to know when state was lost.
2. Subscribe to at least link, IPv4/IPv6 address, IPv4/IPv6 route, and IPv4/IPv6 rule groups needed by the active backend.
3. Take initial full dumps with unique sequence numbers.
4. Buffer or coalesce multicast events while a dump is in flight.
5. Reject/retry a dump with `NLM_F_DUMP_INTR`, truncated messages, missing `NLMSG_DONE`, sequence mismatch, or decode errors.
6. Apply buffered events, then compare observed state with desired state.
7. On `ENOBUFS`, receive truncation, interface-index reuse suspicion, netd restart, resume, or periodic audit expiry, schedule a complete dump/reconciliation.
8. Use `NETLINK_EXT_ACK` for mutation sockets and log the offending attribute/message.

Coalescing should be keyed by stable object identity, not only interface name. Interface indices can be reused, and Android dynamically creates VPN, CLAT, tethering, and virtual interfaces.

## 9. Adaptive kernel feature gates

### 9.1 Gate policy

`uname >= 5.10` is a hard admission check because it is the project's support contract. It is not a feature oracle. Android GKI backports features and fixes; vendor kernels can disable optional Kconfig symbols, restrict operations through policy, or ship userspace tools that do not match the active kernel backend. AOSP itself combines platform/API and kernel-version checks with real program/object access. [S19], [S21], [S22], [S31]

Each gate should record:

```text
Capability {
    name,
    state: supported | unsupported | denied | conflicting | broken | unknown,
    kernel_release,
    android_sdk,
    first_api_level,
    probe_version,
    errno,
    evidence,
    fallback,
}
```

Cache only within the current boot and network namespace. Re-probe after OTA/kernel change, boot-ID change, namespace change, or an operation that returns a capability-related error.

### 9.2 Capability matrix

| Capability | Android 5.10 baseline | Functional probe | Fallback |
|---|---|---|---|
| Route-netlink dump/mutate | Required for design | Dump links/addrs/routes/rules; create/delete one exact private route/rule with extended ACK | No activation |
| Legacy xtables TPROXY/socket | Required by Android S/T 5.10 base | Atomic private chain with socket/TPROXY rule, verify, delete; use `--wait` | TUN mode |
| nftables base | Not required | `NFT_MSG_GETGEN` plus atomic create/delete of private table | Legacy xtables |
| nft socket + TPROXY | Not required | Create/delete private base chain and exact expressions | Legacy TPROXY or TUN |
| ipset required set types | Not required | Protocol handshake and create/destroy private `hash:net` set | nft set or bounded legacy rules |
| TUN single queue | Required by Android 5.10 base | Open device, `TUNGETFEATURES`, create temporary `IFF_TUN + IFF_NO_PI`, close | TPROXY mode |
| TUN multiqueue | Upstream 5.10 supports; not required as a behavior | Create two queues for one temporary device and exchange packets | Single queue |
| eBPF syscall/map/program | Required baseline configs, policy still matters | Create map, load minimal program, query FD info, close | Userspace/netfilter path |
| BPF ring buffer | Present upstream 5.10; not an Android contract | Create ringbuf map and run mmap/epoll smoke test | Userspace counters/perf buffer |
| TC BPF on Flux TUN | Required config ingredients in Android 5.10 base | Add private clsact/filter to temporary Flux TUN, send test packet, detach | Userspace TUN processing |
| Netns-wide `sk_lookup` link | Present upstream 5.10 | Explicit opt-in attach/query/detach with conflict audit | TPROXY listener |
| BTF/CO-RE | Not required | Read and validate `/sys/kernel/btf/vmlinux`; load CO-RE smoke program | UAPI-only object variants |
| pidfd supervision | Present upstream 5.10 | `pidfd_open` worker and poll exit | `waitpid`/signal checks |

### 9.3 Backend selection

Recommended deterministic selection:

1. Enforce kernel >= 5.10 and hard safety probes.
2. If the user explicitly requests TUN, use TUN if its hard probe succeeds.
3. If `backend = auto`:
   - prefer nft TPROXY only when nft base, socket, TPROXY, atomic replacement, and coexistence audit all pass;
   - otherwise use Android legacy xtables TPROXY;
   - otherwise use TUN;
   - otherwise remain inactive with a precise diagnostic.
4. Optional BPF accelerators are selected independently and may never be required for correctness.
5. A degraded optional feature must not silently change routing/VPN semantics.

## 10. Crash-safe desired-state reconciliation

### 10.1 Ownership

Every kernel object must have an ownership descriptor:

- netns inode and boot ID;
- backend and address family;
- mark value/mask;
- rule priority/table/action/protocol;
- route destination/type/table/oif/protocol;
- chain/table/set name plus comment/userdata;
- qdisc/filter handle, priority, and program ID;
- TUN name, ifindex, and controlling FD generation.

Deletion requires an exact ownership match. If an object has the expected name but unexpected semantics, report a conflict and leave it untouched.

### 10.2 Activation order

1. Validate config and capability report.
2. Start proxy worker and establish its bypass/upstream sockets.
3. Create TUN/listener and verify readiness.
4. Create private sets/maps/chains without parent hooks.
5. Create local route table and exact policy rules.
6. Atomically publish the Flux parent hook/jump last.
7. Verify with kernel dumps and a local canary flow.
8. Commit the runtime manifest atomically.

### 10.3 Deactivation order

1. Remove capture hooks/jumps first.
2. Wait a short bounded drain interval.
3. Remove Flux policy rules and routes.
4. Detach Flux BPF links/filters and remove private sets/chains/tables.
5. Close TUN and stop the worker.
6. Verify no owned state remains, then remove the manifest.

This ordering makes failure tend toward direct connectivity rather than a dead proxy.

### 10.4 Reconciliation triggers

- boot/restart and boot-ID change;
- netd state transition or socket/property replacement;
- route-netlink loss or inconsistent dump;
- link/address/route/rule change;
- VPN/default-network change;
- proxy worker crash/readiness loss;
- config or UID-set change;
- suspend/resume audit;
- periodic low-frequency full audit;
- manual `fluxctl reconcile`.

### 10.5 Transactions and journals

- nftables: one atomic batch for the complete Flux-owned ruleset generation.
- legacy xtables: complete `iptables-restore` payloads for Flux-owned chains, serialized with the xtables lock.
- rtnetlink: idempotent create/replace/delete operations with ACK classification; no assumption of multi-message atomicity.
- BPF: prefer unpinned FD-owned links where process death should auto-detach. Pin only durable objects that the reconciler can identify and garbage-collect.
- runtime journal: store desired generation, not a list of inverse shell commands. On restart, query the kernel and converge.

## 11. Vendor fragmentation and test requirements

GKI reduces core-kernel fragmentation and provides a stable KMI, but SoC/board support remains in vendor modules and devices still differ in launch API, kernel LTS, backports, SELinux policy, netfilter modules, offload, cgroups, and userspace tools. Android's kernel-config repository explicitly distinguishes required base fragments from optional/recommended/device configuration and requires graceful degradation for features not guaranteed across upgrade paths. [S19], [S31]

Minimum validation matrix:

- arm64 GKI 5.10, 5.15, 6.1, and 6.6 where available;
- Android 12 through current supported releases;
- AOSP/emulator plus at least Qualcomm, MediaTek, Samsung, and one heavily modified OEM ROM;
- nft absent, nft base-only, full nft TPROXY, ipset absent/present;
- SELinux enforcing and policy-denied probes;
- no VPN, bypassable VPN, per-app VPN, always-on VPN, lockdown VPN;
- primary user, secondary user, work profile, isolated process, SDK sandbox;
- Wi-Fi/cellular handover, dual-SIM, IPv6-only + CLAT, captive portal;
- hotspot/tethering, USB tether, and VPN-over-hotspot cases;
- netd restart, Connectivity mainline update/restart where reproducible;
- interface deletion/index reuse and netlink receive overrun;
- crash injection after every activation phase;
- proxy worker crash while TCP/UDP flows are active;
- OTA reboot with stale runtime files from the previous boot;
- Magisk disable/remove and safe-mode boot.

Acceptance invariants:

- no Android-owned rule/mark/chain/program is modified or removed;
- VPN lockdown cannot be bypassed in the default policy;
- daemon/worker death converges to fail-open direct networking unless the user explicitly selected fail-closed;
- no duplicate capture across backends;
- all optional-feature failures are visible in `fluxctl status`;
- repeated apply/cleanup/reconcile operations are idempotent.

## 12. Recommended architecture decisions for the blueprint

1. Make `fluxd` the single desired-state owner for address sync, RPDB, TUN, netfilter, capability probing, supervision, and status. Shell scripts only enter the Magisk lifecycle and provide emergency glue.
2. Replace fixed marks with device-qualified positive planning authority and fixed priorities with topology-qualified routing candidates; keep both separate from activation leases and preserve the documented Android-VPN policy.
3. Keep Android legacy xtables as the compatibility baseline; add nftables as an atomic optional backend, not a simultaneous overlay.
4. Prefer nft native sets over ipset in the nft backend; retain ipset only as an optional legacy accelerator.
5. Implement TUN as a first-class backend with engine-owned queues first; adapt engine multiqueue/offloads through its version-qualified profile and reserve direct queue control for a future FD-handoff contract.
6. Restrict production eBPF to Flux-owned attachment leases. Use probed ringbuf/perf-event telemetry and TC BPF on a verified Generation-scoped TUN link only after functional probes.
7. Treat physical-interface TC/XDP, root-cgroup BPF, and netns-wide `sk_lookup` as opt-in experiments with conflict detection and automatic rollback.
8. Make netlink loss, netd restart, and worker crash normal reconciliation events.
9. Persist capability evidence and desired generation per boot, but always rebuild observed state from the kernel.
10. Add a “compatibility report” command that explains why each feature is active, degraded, denied, or conflicting.

## Primary sources

[S1]: https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/docs/guides.md
[S2]: https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/native/src/init/rootdir.rs
[S3]: https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/native/src/core/bootstages.rs
[S4]: https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/native/src/sepolicy/rules.rs
[S5]: https://android.googlesource.com/platform/system/core/+/a3b721a32242006b59cb12bd62c9133632af3a2d/init/README.md
[S6]: https://android.googlesource.com/platform/system/core/+/a3b721a32242006b59cb12bd62c9133632af3a2d/rootdir/init.rc
[S7]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/netd.rc
[S8]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/include/Fwmark.h
[S9]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/FwmarkServer.cpp
[S10]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.h
[S11]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/Controllers.cpp
[S12]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/NetworkController.cpp
[S13]: https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/java/android/os/UserHandle.java
[S14]: https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/java/android/os/Process.java
[S15]: https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/core/java/android/net/VpnService.java
[S16]: https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/services/core/java/com/android/server/connectivity/Vpn.java
[S17]: https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168/services/core/jni/com_android_server_connectivity_Vpn.cpp
[S18]: https://android.googlesource.com/platform/system/sepolicy/+/4571ddd9440721fec583c906a337de949a77749e/private/netd.te
[S19]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/s/android-5.10/android-base.config
[S20]: https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/Android.bp
[S21]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/netd/BpfHandler.cpp
[S22]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/headers/include/bpf/KernelUtils.h
[S23]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/loader/netbpfload.rc
[S24]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/networking/tproxy.rst?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S25]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/networking/tuntap.rst?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S26]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/netfilter/Kconfig?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S27]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/netfilter/ipset/Kconfig?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S28]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/netlink/af_netlink.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S29]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/fib_rules.h?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S30]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/Documentation/bpf?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S31]: https://source.android.com/docs/core/architecture/kernel/generic-kernel-image
[S32]: https://source.android.com/docs/core/data/ebpf-traffic-monitor
[S33]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/netlink.h?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S34]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/uapi/linux/rtnetlink.h?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S35]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/netfilter/nf_tables_api.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S36]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/t/android-5.10/android-base.config
[S37]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-12.0.0_r1/server/RouteController.h
[S38]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-13.0.0_r1/server/RouteController.h
[S39]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-13.0.0_r1/server/UidRanges.h
[S40]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.cpp
[S41]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.cpp#256
[S42]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/core/fib_rules.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n812
[S43]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/core/fib_rules.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n259
[S44]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/net/route.h?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n151
[S45]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/route.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n2218
[S46]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv6/datagram.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n41
[S47]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv6/route.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75#n2434
[S48]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/bpf/cgroup.c
[S49]: https://github.com/torvalds/linux/commit/cf7fbe660f2dbd738ab58aea8e9b0ca6ad232449
[S50]: https://source.android.com/docs/core/architecture/kernel/stable-kmi
[S51]: https://source.android.com/docs/core/architecture/kernel/vendor-module-guidelines
[S52]: https://source.android.com/docs/core/architecture/partitions/vendor-odm-dlkm-partition
[S53]: https://android.googlesource.com/platform/system/netd/+/5ca3d903c0253ec29fb4c3e3390f292494612e88/server/RouteController.cpp
[S54]: https://android.googlesource.com/platform/system/netd/+/03311137011f7ca55f263b61a8c86681c1581518/server/RouteController.cpp
[S55]: https://android.googlesource.com/platform/system/netd/+/5ca3d903c0253ec29fb4c3e3390f292494612e88/include/Fwmark.h
[S56]: https://android.googlesource.com/platform/system/netd/+/03311137011f7ca55f263b61a8c86681c1581518/include/Fwmark.h
[S57]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv4/ip_input.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
[S58]: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/net/ipv6/ip6_input.c?id=738ac465e4e900d4a391a27da4e20c090eaa1e75
