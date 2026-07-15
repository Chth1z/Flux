# Local-origin transparent capture mechanisms on Linux 5.10 (2026-07)

- Status: design research for the Rust `fluxd` rewrite; not runtime qualification
- Research date: 2026-07-15 (Asia/Singapore)
- Upstream baseline: Linux `v5.10`, commit `2c85ebc57b3e1817b6ce1a6b703928e113a90442`
- Android evidence: Android S/T 5.10 base configuration at `kernel/configs`
  commit `bd79f38685cf939ab836dd8ddd2e01506ccff47a`, plus the
  `android12-5.10` common-kernel snapshot
  `bf430f0bd02bfb2f7904bd652d7423f4f6b50d9c`

This note answers one narrow question: how can locally originated IPv4/IPv6 TCP and UDP be
delivered to one logical transparent-proxy inbound while keeping the packet's original destination?
“One logical inbound” still means protocol-compatible kernel sockets: at minimum one TCP listening
socket and one unconnected UDP socket, with separate IPv4/IPv6 sockets when a dual-stack socket is
not suitable. Linux requires the socket selected for a packet to have the same L4 protocol. [L14]

The evidence below establishes kernel mechanisms, not support on an Android product. A release
decision still requires active proof on the exact boot image, network namespace, SELinux policy,
Android network/VPN state, Proxy Engine build, and listener configuration.

## Result

The preferred conventional Linux-5.10 qualification candidate is:

```text
local socket
  -> xtables mangle/OUTPUT classifies and sets a masked packet mark
  -> OUTPUT route recomputation
  -> RPDB mark rule selects a local default route through loopback
  -> loopback transmit reinjects the packet without NAT-rewriting its destination tuple
  -> PREROUTING matches the loopback packet and applies TPROXY
  -> transparent TCP listener / unconnected UDP socket
```

The same topology can use an nftables `type route hook output` chain and a prerouting `tproxy`
expression on devices where nftables is actively qualified. Android S/T's 5.10 base configuration,
however, requires the legacy xtables ingredients and does not require nftables, so xtables is the
first Android-5.10 base-config-eligible conventional candidate. [A1] [A2]

This conclusion corrects one over-broad design assumption while preserving the current lowerer's
fail-closed behavior:

- A bare OUTPUT `MARK` rule is not a Capture Program and does not prove listener delivery.
- The Linux 5.10 source nevertheless shows that a mark change in xtables `mangle/OUTPUT` causes an
  output-route recomputation; a matching `RTN_LOCAL` route uses loopback; the loopback driver calls
  `netif_rx()`; and IPv4/IPv6 receive entry then invokes `NF_INET_PRE_ROUTING`. [L2] [L3] [L4]
  [L5] [L6] [L7] [L8] [L30] [L31] [L32]
- Therefore, a previous development observation that did not see PREROUTING or listener delivery
  must be treated as arrangement-specific negative evidence, not as proof that Linux 5.10 cannot
  perform the loop. The checked-in ingress harness does not retain a local-OUTPUT attempt and its
  capture selector is tied to a veth ingress interface. In the frozen shell source shape, an
  optional connmark-qualified TPROXY fast path precedes the generic loopback bypass. That historical
  variant may encode a related path, but it does not define or qualify the selected mandatory
  packet-mark contract. Neither artifact qualifies or disproves the complete candidate.
- The existing schema-v1 lowerer is still correct to reject local OUTPUT because it emits neither
  the OUTPUT mark/reroute half nor a loopback-reachable PREROUTING TPROXY half as one authorized,
  reversible program.

If conventional TPROXY is absent or unusable but BPF and traffic-control ownership are proven, the
bounded experimental fallback to investigate is the same OUTPUT mark plus local-route loop, with a
TC ingress program on loopback using `bpf_sk_assign()` instead of the TPROXY target. Adopting it
would require a separate ADR. It is not yet qualified on Android and has a larger attachment-
ownership surface.

`BPF_SK_LOOKUP` is a secondary experiment, not the first fallback: it runs only after the packet is
already routed locally; its 5.10 context has no packet mark or ingress ifindex; assigning a known
listener normally requires `SOCKMAP`/`SOCKHASH`; and Android S/T's required 5.10 fragments do not
mandate `CONFIG_BPF_STREAM_PARSER`, which provides those map types. The pinned Android 12 GKI
defconfig also omits it. [L12] [L13] [L15] [A1] [A2] [A9]

Cgroup connect/sendmsg address rewriting does not meet the transparent-listener contract because it
changes the destination presented to the socket operation. An LKM can force additional paths on a
custom kernel, but it is not a portable or recoverable Android fallback.

## Comparison

| Mechanism | Present in upstream 5.10 | Can preserve the on-packet destination | What it still needs | Decision |
|---|---|---|---|---|
| xtables `mangle/OUTPUT` mark + RPDB local route + PREROUTING TPROXY | Yes | Yes; TPROXY does not NAT the destination | Exact masked mark authority, policy route, loopback-reachable TPROXY rule, transparent listener, loop escape | First conventional qualification candidate |
| nftables route/OUTPUT mark + local route + prerouting `tproxy` | Yes; nft TPROXY exists since 4.18 | Yes | `NF_TABLES`, `NFT_TPROXY`, correct route-chain type, userspace support, same routing/listener proof | Preferred only where device-qualified; not Android-5.10 baseline |
| Netns `BPF_SK_LOOKUP` assignment | Yes | Yes after the packet is local | A route to local delivery, safe socket registry, tuple authorization, netns-global attach ownership | Secondary lab experiment |
| Cgroup `connect4/6` plus UDP `sendmsg4/6` rewrite | Yes | No, not without a separate out-of-band original-destination protocol | Cgroup attach authority, map lifecycle, proxy cooperation, race-free TCP/UDP correlation | Not a transparent-capture backend |
| TC ingress `bpf_sk_assign()` on loopback | Yes | Yes | OUTPUT classification, local route, `clsact`, BPF load/attach, same-netns compatible listener, continuous qdisc/link proof | Separate-ADR experimental fallback |
| TC egress BPF | Yes | Not as a standalone path | A separate redirect/reinjection design; `bpf_sk_assign()` is invalid at egress | Observation/classification only for this problem |
| Custom LKM using netfilter/TPROXY internals | Technically possible in an in-tree or exact custom kernel | Potentially | Exact KMI/symbol/signature/SELinux/boot integration and kernel-safe rollback | Excluded as a production fallback |

## 1. Conventional OUTPUT-to-loopback-to-TPROXY path

### 1.1 Why it works in Linux 5.10

For IPv4, the xtables mangle OUTPUT hook snapshots the route-relevant fields, runs the rules, and
calls `ip_route_me_harder()` when the mark, addresses, or TOS change. The reroute lookup includes
`skb->mark`; it also retains a socket's bound output interface when one is present. [L2] [L3]

When the RPDB selects a table containing a local default route, the IPv4 output lookup resolves an
`RTN_LOCAL` result to the network namespace's loopback device. The route still has `ip_output` as
its output function and `ip_local_deliver` as its input function. Sending it through loopback calls
`netif_rx()`, which returns the skb to receive processing; `ip_rcv()` then runs PRE_ROUTING. [L4]
[L5] [L6]

IPv6 has the equivalent behavior: `ip6table_mangle` calls `ip6_route_me_harder()` after a mark or
address change; local routes resolve to loopback; the route has `ip6_output` and `ip6_input`; and
`ipv6_rcv()` invokes PRE_ROUTING. [L8] [L30] [L31] [L32]

This is a two-hook program. The OUTPUT half selects which local traffic is captured and forces the
receive-path loop. The PRE_ROUTING half selects the proxy socket. Neither half is sufficient alone.

For nftables, route recomputation is tied to a `type route` OUTPUT chain. The 5.10 route-chain hook
explicitly calls `ip_route_me_harder()`/`ip6_route_me_harder()` when route-relevant fields change.
Changing a mark in an ordinary filter-type OUTPUT chain is not equivalent. [L9]

### 1.2 Original-destination behavior

The upstream TPROXY documentation contrasts TPROXY with REDIRECT: REDIRECT changes the packet's
destination, whereas TPROXY assigns a transparent socket without relying on NAT. [L1]

The xtables target looks up an established socket or the configured transparent listener and then
stores that socket in `skb->sk`; the registered xtables target is hard-limited to
`NF_INET_PRE_ROUTING` and TCP/UDP. [L10] [L11]

For TCP, request-socket construction uses the packet's destination address and port, and the cloned
accepted socket inherits that request destination, so the accepted socket carries the intercepted
local tuple. For UDP, enabling `IP_RECVORIGDSTADDR` or `IPV6_RECVORIGDSTADDR` produces a control
message from the packet destination fields. [L18] [L19] [L38] [L40] [L42]

The listener must enable `IP_TRANSPARENT`/`IPV6_TRANSPARENT`. Linux 5.10 permits that only with
`CAP_NET_RAW` or `CAP_NET_ADMIN` in the socket network namespace. Routing/netfilter changes require
`CAP_NET_ADMIN`. [L1] [L17] [L39]

### 1.3 Required kernel configuration

At minimum:

- IPv4/IPv6 policy routing: `CONFIG_IP_MULTIPLE_TABLES` and
  `CONFIG_IPV6_MULTIPLE_TABLES`;
- xtables path: `CONFIG_IP_NF_MANGLE`, IPv6 iptables where required,
  `CONFIG_NETFILTER_XT_TARGET_MARK`, and `CONFIG_NETFILTER_XT_TARGET_TPROXY`;
- transparent-socket DIVERT, if used: `CONFIG_NETFILTER_XT_MATCH_SOCKET`;
- nft path instead: `CONFIG_NF_TABLES`, `CONFIG_NFT_TPROXY`, and
  `CONFIG_NFT_SOCKET` when socket matching is used. [L1] [L20] [L33]

Kernel config is only eligibility. The userspace restore extensions, module state without implicit
autoload, SELinux permissions, exact listener behavior, and packet path must all be probed.

### 1.4 Conditions that can make a test fail

A negative listener result does not identify which stage failed. A qualifying canary must separate:

1. OUTPUT selector hit;
2. exact masked mark after OUTPUT;
3. output reroute to the intended local table and loopback device;
4. loopback receive/PREROUTING hit before any interface-specific selector;
5. TPROXY/socket-assignment hit;
6. TCP accept or UDP receive on the exact Generation listener;
7. TCP accepted local tuple or UDP original-destination control message;
8. return traffic and proxy-upstream loop escape;
9. exact inverse cleanup.

Common failure causes include placing an nft mark in a filter chain rather than a route chain,
matching PREROUTING only on a tether interface instead of loopback, a socket bound to an output
interface that constrains the reroute, mark overlap with Android's `netId` or VPN bits, an RPDB rule
ordered behind an earlier Android decision, reverse-path/vendor policy, or a listener that did not
actually enable transparent mode.

Android's `Fwmark` reserves bits 0-15 for `netId` and additional bits for explicit selection, VPN
protection, permissions, billing, vendor use, and wakeup accounting. Flux therefore cannot choose
a capture mark from an apparently unused constant; it needs the existing mark-census and masked
allocation authority. [A3]

## 2. Netns `BPF_SK_LOOKUP`

**Original-destination verdict:** yes at the packet/socket-tuple level, provided the packet has
already entered local input. `bpf_sk_assign()` selects the socket; it does not rewrite the IP or
transport headers. Linux then constructs TCP request/accepted-socket local identity from those
packet destination fields, while UDP can report the same fields through the original-destination
control message. [L14] [L18] [L19] [L38] [L40] [L42]

Linux 5.10's `BPF_PROG_TYPE_SK_LOOKUP` attaches to a network namespace. It runs when TCP needs a
listener or UDP needs an unconnected socket for a packet already being delivered locally, and a
program can select the receiving socket with `bpf_sk_assign()`. Established TCP and connected UDP
bypass the hook. [L12]

The upstream 5.10 selftest redirects both TCP and UDP to a socket bound at a different address or
port. Its UDP echo path enables original-destination control messages and replies from the packet's
original destination, demonstrating that socket lookup assignment itself need not rewrite the
packet tuple. [L16]

It does not solve local-origin routing. A locally generated packet must first be made local by the
RPDB/local-route loop or another reinjection mechanism.

It also has important 5.10 limitations for Flux:

- `struct bpf_sk_lookup` exposes family, protocol, source/destination addresses and ports, and the
  selected socket. It exposes neither `skb->mark` nor ingress ifindex, so it cannot directly prove
  that a packet is a Flux-marked loopback reinjection. [L13]
- The standard way to supply the listener is `SOCKMAP`/`SOCKHASH`. Those map types are compiled only
  with `CONFIG_BPF_STREAM_PARSER`. [L15]
- Programs are netns-global and multiple programs run in attach order. They must not steal unrelated
  local ingress that happens to match a broad destination policy. [L12]
- TCP listeners and UDP unconnected sockets are eligible; connected sockets are rejected. [L14]

Consequently a decision-bearing design needs a bounded tuple-authorization map populated before
the packet reaches local socket lookup, freshness/eviction rules, exact listener-FD lifecycle, and
foreign-program ordering evidence. That is more state than the conventional mark plus TPROXY path.

These are fatal blockers to treating `sk_lookup` as a standalone, portable Android-5.10 backend:
it cannot make an output packet local; it cannot directly test the Flux packet mark or loopback
ingress identity; and the published S/T baseline does not guarantee the socket-map facility needed
for Flux to supply its listener. A vendor kernel that enables the missing config and passes an exact
tuple-authorization canary may still qualify it as an optional backend.

Program loading requires `CONFIG_BPF_SYSCALL` and `CAP_BPF` or `CAP_SYS_ADMIN` in upstream 5.10.
Using a socket map additionally requires `CONFIG_BPF_STREAM_PARSER`; Android SELinux can still deny
the load, map, pin, or attach operations. [L15] [L21]

## 3. Cgroup socket-address rewriting

Linux 5.10 supports `BPF_CGROUP_INET4_CONNECT`, `BPF_CGROUP_INET6_CONNECT`, and UDP
`BPF_CGROUP_UDP4_SENDMSG`/`BPF_CGROUP_UDP6_SENDMSG` through
`BPF_PROG_TYPE_CGROUP_SOCK_ADDR`. The context deliberately permits writes to `user_ip4`,
`user_ip6`, and `user_port`; upstream selftests rewrite connect and sendmsg destinations. [L22]
[L23] [L35]

This can make selected processes connect or send to a local proxy address, but it is redirection of
the socket operation, not transparent delivery of the original packet. The proxy sees the rewritten
destination unless Flux and the proxy implement a separate original-destination map/protocol.

That separate protocol is especially hard for UDP: one unconnected socket can send concurrent
datagrams to different destinations, so a socket-cookie-only last-value map is insufficient. It
also changes application-visible connect/send error and peer semantics unless getpeername hooks are
added. Therefore cgroup rewriting may be useful for a tightly controlled child process or loop
escape, but it must not qualify the requested TPROXY listener contract.

This path requires `CONFIG_CGROUP_BPF`, `CONFIG_BPF_SYSCALL`, BPF load authority, and a compatible
cgroup attachment point. Upstream 5.10 refuses a descendant attach when an ancestor has the same
type without `BPF_F_ALLOW_OVERRIDE` or `BPF_F_ALLOW_MULTI`. [L24]

AOSP attaches version-dependent BPF programs at the root cgroup. The cited Connectivity source
attaches ingress, egress, socket-create, and bind programs, and on newer platform conditions also
connect, sendmsg, recvmsg, and sockopt programs. Device qualification must query every ancestor and
the exact attach flags instead of assuming a Flux child cgroup is free. [A4]

## 4. TC BPF

### 4.1 Ingress socket assignment

Linux 5.10 exposes `bpf_sk_lookup_tcp()`/`bpf_sk_lookup_udp()` and `bpf_sk_assign()` to TC
classifier/action programs. `bpf_sk_assign()` assigns the socket carried by the skb and, with a
route that delivers the packet locally, causes delivery to that socket. The helper is valid only at
TC ingress, requires the socket to be in the same network namespace, and rejects reuseport sockets.
Later redirects can invalidate the assignment. The upstream 5.10 selftest exercises TCP and UDP
lookup followed by TC socket assignment. [L14] [L43]

For local OUTPUT, the narrow experiment is:

```text
xtables mangle/OUTPUT mark
  -> RPDB local route through lo
  -> clsact ingress on lo
  -> verify Flux mark and exact TCP/UDP selector
  -> look up the Generation listener and bpf_sk_assign()
  -> continue to normal IPv4/IPv6 local input
```

This need not NAT-rewrite the packet's L3/L4 destination and can replace the PREROUTING TPROXY
target while retaining the same local-route requirement. The upstream selftest first looks up the
packet's original tuple so established TCP or connected UDP can retain their socket, then obtains
the fallback listener from a `BPF_MAP_TYPE_SOCKMAP`. Looking up a reviewed Generation listener
through a constructed proxy tuple is only a design hypothesis and requires its own focused canary.
Every socket state, returned reference, map/helper result, and error must fail closed.

The required 5.10 config includes `CONFIG_BPF_SYSCALL`, `CONFIG_NET_CLS_BPF`,
`CONFIG_NET_CLS_ACT`, and `CONFIG_NET_SCH_INGRESS`/`clsact`. Loading a SCHED_CLS program requires
both BPF privilege and `CAP_NET_ADMIN` (or the upstream `CAP_SYS_ADMIN` fallback); installing the
qdisc/filter requires `CAP_NET_ADMIN`. [L21] [L25] [L34]

This fallback has meaningful Android costs: loopback `clsact` is shared namespace state; foreign
filters and ordering must be inventoried; platform lifecycle may remove/recreate qdiscs; offload,
GSO, checksum, fragments, IPv4/IPv6 extension headers, TCP TIME_WAIT, UDP connected state, and
listener compatibility need live tests. It remains an experiment until a real device proves all of
those properties and exact cleanup.

### 4.2 Why TC egress is not equivalent

TC egress runs in the transmit path after the route has already been selected. Changing only
`skb->mark` there does not invoke the xtables/nft route-recompute callbacks. More importantly,
`bpf_sk_assign()` returns `-EOPNOTSUPP` outside TC ingress. [L14] [L25]

An egress program could redirect a packet to another device, but that creates a new mechanism with
device ownership, recursion, MTU/GSO, and delivery semantics to prove. It is not a smaller
substitute for the OUTPUT route loop and should be limited to observation or bounded
classification experiments.

## 5. xtables and nftables TPROXY hook boundaries

The xtables 5.10 target registers only for mangle-table PRE_ROUTING and rejects protocols other
than TCP or UDP. It cannot be attached to OUTPUT. [L10]

The nftables 5.10 `tproxy` expression does not contain an equivalent hook-mask validator. That does
not make OUTPUT a working transparent-delivery hook: the expression performs socket lookup and
stores the selected socket in `skb->sk`; it does not convert an output skb into an input skb or
reroute it locally. The upstream documentation demonstrates nft TPROXY in a prerouting chain.
[L1] [L11] [L26]

The supported design is therefore not “put TPROXY in OUTPUT.” It is “use OUTPUT to select and
reroute, then perform socket assignment on the receive side.”

## 6. Optional LKM using netfilter/TPROXY helpers

An in-tree or exact custom-kernel module can register netfilter hooks, call the IPv4/IPv6 TPROXY
lookup helpers, and assign a socket. Upstream 5.10 exports `nf_register_net_hook()`,
`ip_route_me_harder()`, and the `nf_tproxy_*` lookup helpers; the TPROXY helpers are GPL-only
exports. [L27] [L36] [L37]

That power does not remove the packet-path requirement. Assigning `skb->sk` in LOCAL_OUT and
returning `NF_ACCEPT` still leaves the skb on the output path. A module would need to do one of:

- mark and explicitly reroute the skb, then use a PRE_ROUTING hook after loopback reinjection;
- steal and reinject the skb into receive processing; or
- implement a larger custom transport interception path.

The first option duplicates the conventional mechanism. The latter options make skb ownership,
netfilter/conntrack ordering, checksum/GSO/fragment state, socket references, recursion, and failure
cleanup kernel-module responsibilities.

This is not a portable GKI option. Android's stable-KMI rules state that vendor modules may use only
symbols in the applicable KMI symbol list, within the same Android version/LTS/config/toolchain
contract. At the pinned `android12-5.10` snapshot, the generic arm64 symbol list includes
`netif_rx` but not `nf_register_net_hook`, `ip_route_me_harder`, `sock_edemux`, or the
`nf_tproxy_*` helpers. An OEM-specific symbol list or protected/in-tree module may differ, but a
generic third-party `.ko` cannot assume those interfaces. [A5] [A6]

Upstream module loading also requires `CAP_SYS_MODULE`, can be disabled globally, can enforce
signatures, and cannot guarantee unload: dependencies, references, missing exit support, and module
state can return `EWOULDBLOCK` or `EBUSY`. [L28] [L29] [L41]

Android S/T's base config enables modules, unload, modversions, and strict module RWX, but that only
describes build eligibility. Android documents protected/unprotected GKI modules, vendor modules,
symbol allowlists, signatures, and boot-image/vendor-DLKM integration as platform-controlled
contracts. A module copied under an app or root-framework data directory does not acquire those
contracts. [A1] [A2] [A6] [A7]

Flux should therefore neither package nor load/unload such a module. A reviewed OEM/custom-kernel
module may be studied as an already-present exact-device backend, but only behind a versioned
handshake, independent identity evidence, passive-by-default behavior, and a complete conventional
fallback. It is not the recommended fallback for local OUTPUT.

## 7. Android 5.10 evidence and remaining proof

### 7.1 What AOSP requires

The Android S and T 5.10 base configs require the following relevant options:

- `CONFIG_BPF_JIT=y`, `CONFIG_BPF_SYSCALL=y`, and `CONFIG_CGROUP_BPF=y`;
- IPv4/IPv6 multiple routing tables and IPv4/IPv6 legacy iptables;
- `CONFIG_IP_NF_MANGLE=y`, xtables mark match/target, socket match, and TPROXY target;
- `CONFIG_NET_CLS_ACT=y`, `CONFIG_NET_CLS_BPF=y`, and
  `CONFIG_NET_SCH_INGRESS=y`;
- `CONFIG_MODULES=y`, `CONFIG_MODULE_UNLOAD=y`, `CONFIG_MODVERSIONS=y`, and
  `CONFIG_STRICT_MODULE_RWX=y`. [A1] [A2]

Those required fragments do not mandate `CONFIG_NF_TABLES`, `CONFIG_NFT_TPROXY`, or
`CONFIG_BPF_STREAM_PARSER`; the pinned Android 12 GKI defconfig also omits those entries. A product
kernel may add them, but Flux must not infer them from a 5.10 version string. [A9]

### 7.2 Why config and root are not enough

AOSP SELinux grants netd explicit BPF, netlink, and network capabilities and deliberately does not
grant it `SYS_MODULE`; the policy comment says required kernel features should be built in. These
permissions are domain-specific. A root or root-framework process still needs exact SELinux and
capability proof for each operation. [A8]

For every candidate device, Flux must actively prove:

1. exact kernel build/config and boot identity;
2. userspace xtables/nft extension availability without implicit module autoload;
3. exact masked Android mark allocation and RPDB priority/table ownership;
4. coexistence with default-network, explicitly selected network, bypassable VPN, always-on VPN,
   lockdown VPN, and per-app VPN rules;
5. dual-stack local-route-to-loopback behavior for unbound and explicitly network-bound clients;
6. loopback PRE_ROUTING visibility before interface-restricted rules;
7. transparent TCP/UDP listener options and original-destination observations;
8. proxy-upstream loop escape that preserves Android network selection;
9. BPF program/map/helper/verifier support and SELinux authorization where applicable;
10. cgroup ancestor programs/flags or TC qdisc/filter/link ownership and foreign ordering;
11. bounded failure injection, observer loss handling, readback, and exact inverse cleanup.

No Android device execution evidence was collected for this note.

## 8. Recommended implementation checkpoint

Before native writer activation, implement one disposable Linux namespace canary for the complete
conventional path rather than another mark-only model:

1. Create Generation-scoped IPv4 and IPv6 TCP listeners and unconnected UDP sockets with
   transparent mode and original-destination reception enabled.
2. Create a distinct-UID local client and an independently observed proxy process.
3. Install exact OUTPUT selectors in xtables mangle, using a test-only non-conflicting masked mark.
4. Install exact RPDB rules and local default routes through loopback.
5. Install separate loopback-reachable PRE_ROUTING TPROXY selectors; do not reuse tether-interface
   selectors.
6. Record independent counters at OUTPUT, early loopback PREROUTING, TPROXY, listener delivery, and
   bypass/escape points.
7. Prove TCP accepted local tuples and UDP original-destination control messages for both families,
   plus reply traffic and no peer-server leakage.
8. Remove every object by exact identity and prove absence.

Only after that can the design decide whether the earlier negative harness result was caused by
rule placement, route-chain behavior, interface selection, socket binding, or environment policy.
The test result must remain Linux-harness evidence until repeated on reviewed Android device
profiles.

If conventional TPROXY genuinely fails on a device while TC BPF is authorized, run a second,
separate loopback-TC `bpf_sk_assign()` canary. Do not combine the two mechanisms in one proof.

## Primary sources

### Linux 5.10

[L1]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/networking/tproxy.rst
[L2]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/netfilter/iptable_mangle.c#L39-L68
[L3]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/netfilter.c#L20-L81
[L4]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/route.c#L2362-L2482
[L5]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/route.c#L2514-L2682
[L6]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/drivers/net/loopback.c#L68-L91
[L7]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/ip_input.c#L527-L542
[L8]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/netfilter/ip6table_mangle.c#L35-L63
[L9]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/nft_chain_route.c#L15-L100
[L10]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/xt_TPROXY.c#L205-L255
[L11]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/net/netfilter/nf_tproxy.h#L20-L26
[L12]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/bpf/prog_sk_lookup.rst
[L13]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/bpf.h#L5007-L5019
[L14]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/bpf.h#L3146-L3194
[L15]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/Kconfig#L308-L321
[L16]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/tools/testing/selftests/bpf/prog_tests/sk_lookup.c#L320-L390
[L17]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/ip_sockglue.c#L1339-L1348
[L18]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/tcp_ipv4.c#L1435-L1445
[L19]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/ip_sockglue.c#L150-L169
[L20]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/Kconfig#L619-L643
[L21]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/bpf/syscall.c#L2047-L2140
[L22]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/bpf.h#L4458-L4483
[L23]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/tools/testing/selftests/bpf/progs/connect4_prog.c#L186-L197
[L24]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/bpf/cgroup.c#L194-L268
[L25]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/sched/Kconfig#L382-L397
[L26]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/nft_tproxy.c#L21-L176
[L27]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/netfilter/nf_tproxy_ipv4.c
[L28]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/module.c#L2880-L2931
[L29]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/module.c#L929-L1034
[L30]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/netfilter.c#L23-L75
[L31]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/route.c#L1018-L1113
[L32]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/ip6_input.c#L300-L309
[L33]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/Kconfig#L1029-L1049
[L34]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/sched/Kconfig#L613-L621
[L35]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/tools/testing/selftests/bpf/progs/sendmsg4_prog.c#L30-L42
[L36]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/netfilter/core.c#L513-L568
[L37]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/netfilter.c#L19-L83
[L38]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/inet_connection_sock.c#L826-L847
[L39]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/ipv6_sockglue.c#L625-L635
[L40]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv6/datagram.c#L718-L736
[L41]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/kernel/module.c#L3717-L3723
[L42]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/ipv4/tcp_input.c#L6603-L6625
[L43]: https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/tools/testing/selftests/bpf/progs/test_sk_assign.c#L90-L185

### Android / AOSP

[A1]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/s/android-5.10/android-base.config
[A2]: https://android.googlesource.com/kernel/configs/+/bd79f38685cf939ab836dd8ddd2e01506ccff47a/t/android-5.10/android-base.config
[A3]: https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/include/Fwmark.h
[A4]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/2519a78731526d2eb20ae8812acdcab6ef7a09b6/bpf/netd/BpfHandler.cpp
[A5]: https://source.android.com/docs/core/architecture/kernel/stable-kmi
[A6]: https://android.googlesource.com/kernel/common/+/bf430f0bd02bfb2f7904bd652d7423f4f6b50d9c/android/abi_gki_aarch64_generic
[A7]: https://source.android.com/docs/core/architecture/kernel/modules
[A8]: https://android.googlesource.com/platform/system/sepolicy/+/4571ddd9440721fec583c906a337de949a77749e/private/netd.te
[A9]: https://android.googlesource.com/kernel/common/+/bf430f0bd02bfb2f7904bd652d7423f4f6b50d9c/arch/arm64/configs/gki_defconfig
