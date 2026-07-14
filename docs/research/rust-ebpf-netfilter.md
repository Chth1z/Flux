# Rust, eBPF, Netfilter, and TUN Research for `fluxd`

- Status: original research complete; amended for the current design
- Original research date: 2026-07-11
- Last updated: 2026-07-13
- Original repository baseline: `c978b75d879a9d155e46197dd86bf7cd9dc1b519`
- Current design baseline: `868729fcce4d076b11e7746d8ec39369f26159f2`
- Minimum supported kernel: Linux 5.10

## Scope

This note evaluates implementation options for a privileged Rust daemon on rooted Android. It covers eBPF, nftables and netfilter netlink, ipset and xtables compatibility, rtnetlink, TUN and multiqueue I/O, `epoll` and `io_uring`, runtime capability probing, Linux capabilities and seccomp, Android cross-compilation, observability, and testing.

The intended consumer is the `fluxd` rewrite. `fluxd` will absorb the current `addrsyncd` binary and runtime-critical shell logic while continuing to supervise Sing-Box as a separate proxy engine. The note does not propose reimplementing Sing-Box's protocol stacks.

The central conclusion is:

> Linux 5.10 is a support floor, not a feature manifest. `fluxd` should reject older kernels, then select every optional backend by a contained create/use/observe/delete probe under the device's actual capabilities, SELinux policy, cgroup layout, loaded modules, and vendor kernel implementation.

## Research method and pinned source snapshots

The conclusions were checked against upstream kernel source, project-owned documentation, and the source trees of the candidate Rust libraries. Versioned source links are used so later upstream changes do not silently change the evidence.

| Source | Audited snapshot | Purpose |
|---|---:|---|
| Flux | `c978b75d879a9d155e46197dd86bf7cd9dc1b519` | Current reactor, rtnetlink, and xtables baseline |
| Linux | `v5.10`, commit `2c85ebc57b3e1817b6ce1a6b703928e113a90442` | Minimum-kernel UAPI and implementation |
| Aya | `2f09011af04527218f744e79ed1e8edc85e1972c` | Pure-Rust eBPF loader/program framework |
| libbpf-rs | `db7d45732a9309adb4854f371dcd6904fe4ed0c2` | Rust bindings and skeleton workflow |
| libbpf | `34e3ebf0f062cf81882c51ac95dce720101ca5cc` | CO-RE and native dependency model |
| rtnetlink | `e7799b6ee24267586e6aadc0e3fb415b4d921dd4` | Async route-netlink alternative |
| netlink-packet-netfilter 0.2.0 | `591a4b228faa6b4e629abccfc12597f1baf6bd78` | Available Rust netfilter codecs |
| nftables userspace 1.1.6 | `8d97995b030fb48a1cd2bd5f1a7c5bd18303c76e` | Canonical nft syntax, JSON, and netlink behavior |
| nftables-rs 0.6.3 | `ca4b9cf81d6e8719e7d511dc64b97a35439087ac` | Rust JSON model and `nft` process adapter |
| Mullvad nftnl-rs 0.9.2 | `e4b18e5355208f19e396d47ddca8f2fb3659e71c` | libnftnl-backed Rust API |
| pure-Rust nftnl-rs 0.5.1 | `d98b5e8d719ffe32fbd22cf422911612fbb966cd` | Experimental native Rust nft API |
| ipset 7.24 | `5c1debb08873ba6d56c073f34e4b09cd9c56e5d5` | Userspace protocol and swap behavior |
| rust-tun 0.8.13 | `b1bd15829836f483e6813af2ee14e7a37f3afb28` | Android TUN support boundary |
| io-uring 0.7.13 | `a52c1c07ffa7ab64750fd6a39f2f0a922f205815` | Rust `io_uring` API and opcode probing |
| liburing | `e50e32a6b9030faba2e30fa0ba999571a0cffe28` | Upstream userspace behavior and tests |

## Existing Flux baseline worth preserving

The current implementation already contains a strong low-level foundation:

- `addrsyncd` uses a single `epoll + timerfd + signalfd + NETLINK_ROUTE` reactor, batched acknowledgements, bounded maintenance work, and full resynchronization paths.
- policy routing is already programmed with direct rtnetlink messages;
- xtables rules are compiled before application and committed with `iptables-restore` rather than one subprocess per rule;
- the pure-iptables fallback bounds large address lists through a fixed jump tree;
- the shell layer already detects several kernel facilities, but those checks are descriptive rather than authoritative.

The relevant local sources are [`addrsyncd/src`](../../addrsyncd/src), [`addrsyncd/README.md`](../../addrsyncd/README.md), [`scripts/config`](../../scripts/config), [`scripts/rules`](../../scripts/rules), and [`scripts/tproxy`](../../scripts/tproxy).

The rewrite should move these behaviors behind `fluxd` modules instead of replacing a proven event loop with a large dependency stack merely for abstraction. In particular, the existing rtnetlink codec and reactor are a reasonable production baseline for Android, where binary size, C-library dependencies, vendor behavior, and debuggability matter.

## Executive recommendation

1. Keep one privileged `fluxd` process as the sole owner and reconciler of Flux kernel state. Shell should be limited to Magisk boot glue and carefully bounded process invocation during migration.
2. Preserve and deepen the existing custom rtnetlink reactor for address, route, rule, and link hot paths. It already fits Android and handles the reliability model that a generic stream abstraction can obscure.
3. Prefer nftables for capture rules only after a real transactional canary proves the exact required table, set, socket, mark, counter, and TPROXY operations. Use one uniquely named Flux-owned `inet` table and never flush foreign state.
4. Fall back to one detected xtables implementation. Within that path, prefer generation-specific ipsets populated through verified restore/optional swap and cut over through the stable xtables jump; fall back again to the current bounded pure-iptables tree.
5. Treat `epoll` as the mandatory I/O baseline. Enable `io_uring` only under the future `FluxOwnedTunFd` handoff contract and only when setup, required opcodes, a real TUN read/write smoke test, cancellation, and device benchmarks all succeed.
6. Implement `/dev/net/tun` probing and future ownership in a narrow Rust UAPI module. The current `tun` crate's Android backend wraps a caller-supplied raw file descriptor and therefore does not remove the need for contained privileged probes or future creation/configuration code.[29]
7. Use Aya as the default eBPF loader and Rust eBPF framework. It avoids libbpf, BCC, libelf, and zlib at runtime; includes program/map/helper feature probes; and supports the TC, cgroup, socket, ring-buffer, and map capabilities needed here.[12][13]
8. Retain libbpf-rs as an optional engineering or experimental backend, especially for newer-kernel netfilter BPF experiments. Its CO-RE and skeleton workflow is mature, and its tree contains a netfilter example, but the native C build and Android dependency chain are materially more complex.[15][16][17][18]
9. Make eBPF optional to correctness in the first production rewrite. It should first observe, then accelerate verified classifications or mark writes while nftables, xtables, or TUN remains a complete fallback.
10. Expose the complete capability decision as `fluxctl capabilities --json`, including kernel version, probe operation, result, errno, extack/verifier log, selected fallback, and the boot epoch in which the probe was run.

## Recommended kernel-plane decomposition

The implementation should separate intent from mechanism:

```text
CapturePolicy / RoutePolicy / TelemetryPolicy
                     |
              Generation compiler
                     |
      +--------------+----------------+
      |              |                |
 nftables/xtables  rtnetlink       TUN adapter
      |              |                |
      +---------- optional eBPF -------+
```

The compiler produces an immutable generation. Adapters then prepare temporary resources, activate them in a defined order, verify observed state, and retire the prior generation. One task owns all kernel mutation. Observers may decode events concurrently, but they never write directly.

Rust should encode the transition order in types rather than comments:

```rust
struct Planned<G>(G);
struct Prepared<G> {
    generation: G,
    cleanup: CleanupPlan,
}
struct Active<G> {
    generation: G,
    observed: KernelIdentity,
}

trait KernelBackend {
    fn prepare(&mut self, plan: Planned<KernelPlan>)
        -> Result<Prepared<KernelPlan>, KernelError>;
    fn activate(&mut self, prepared: Prepared<KernelPlan>)
        -> Result<Active<KernelPlan>, KernelError>;
}
```

The exact API may be asynchronous, but the ownership rule is more important than the syntax: no object becomes active without a cleanup identity, and no failed activation is allowed to forget temporary state.

## eBPF on an Android 5.10+ proxy

### What eBPF is good for here

The most useful 5.10-compatible role is classification and observation close to a stable hook, followed by a conventional routing/capture mechanism. Upstream Linux 5.10 exposes the required program and map types in `bpf.h`; the verifier implementation permits writes to `__sk_buff.mark` for relevant skb program types.[2][3] This makes a TC or cgroup skb program a viable producer of Flux-owned mark bits, provided the program preserves every non-Flux bit and policy routing/netfilter remains the consumer.

eBPF is also valuable for:

- low-contention per-CPU counters;
- sampled flow and exceptional-event telemetry;
- bounded LRU flow-decision caches;
- prefix lookup with LPM tries;
- atomic policy generation changes through map-of-maps or a generation-indexed configuration map;
- future flow-stable TUN multiqueue steering under `FluxOwnedTunFd`;
- attach-time experiments on newer kernels without changing the baseline backend.

It is not, on its own, equivalent to Android transparent proxying. No single baseline hook simultaneously supplies local OUTPUT coverage, forwarded/tethered traffic, UID identity, conntrack semantics, route context, and transparent TCP/UDP socket behavior.

### Hook applicability

| Hook or facility | 5.10 baseline | Useful scope | Important limitations | Flux recommendation |
|---|---|---|---|---|
| xtables `xt_bpf` pinned socket filter | Enabled by AOSP 5.10 base configs; still probe exact device/userspace | Observation and positive proxy matching inside Flux-owned chains | Only covers packets traversing the referencing rule; OUTPUT UID depends on socket association, `overflowuid` is ambiguous, and PREROUTING normally has no app UID | First eBPF integration: observation always returns false, then positive proxy hits with complete classic fallback |
| TC `sched_cls` ingress/egress | Yes in upstream 5.10 | Packet classification, counters, Flux mark-bit writes, TUN observation | Attachment owns or shares qdisc/filter state; physical Android interfaces may be managed by netd/vendor offload; no inherent app UID | First TC hook after `xt_bpf`: use a verified Generation-scoped TUN link under a Flux-owned qdisc/filter lease; physical NIC use opt-in after coexistence probe |
| TC ingress socket assignment | `bpf_sk_assign` is present at the floor | Exact-domain transparent listener assignment | Still needs a correct local route, same-netns compatible socket, and safe miss behavior; high conflict risk on tether/physical hooks | Project-roadmap Phase 8 exact-device experiment only |
| cgroup skb ingress/egress | Yes | Cgroup-scoped packet policy and accounting | A program at any ancestor can constrain descendants; AOSP root defaults normally block the same hook | Optional only after full ancestor-chain plus child program/flag inventory |
| cgroup sock-address programs | Yes | Observe or influence locally originated bind/connect/sendmsg syscalls | Standard AOSP root attachments normally block descendants; does not cover forwarded/tethered packets | Device-specific lab path, never a general loop-escape mechanism |
| cgroup `sockops` | Yes | Proxy-child TCP cookie, RTT, retransmit, connection-state, and read-only socket-mark telemetry through validated `ctx->sk->mark` | Attach type must be genuinely available; TCP-only timing is too late to prove initial route selection | Optional child-cgroup canary paired with userspace TCP/UDP mark evidence |
| `sk_lookup` | Present in 5.10; documented upstream | Select a local TCP listening or unconnected UDP socket during socket lookup | Does not run for established TCP or connected UDP; cannot replace all netfilter routing and forwarding behavior | Experimental local-proxy ingress path only[5] |
| XDP | Yes | Earliest ingress telemetry, coarse prefilter/drop, explicit redirect experiments | No local OUTPUT, socket UID, conntrack, or normal route context; driver/generic mode differs | Never the primary transparent-proxy path |
| TUN steering/filter socket BPF | Yes in upstream 5.10 | Select a TUN queue; trim/drop before userspace | Applies only to queue FDs owned by Flux and needs dedicated socket-filter programs | Steering is a future `FluxOwnedTunFd` feature; filtering is deferred because it lacks an automatic fail-open guarantee[7][8] |
| `BPF_PROG_TYPE_NETFILTER` | No at 5.10; upstream introduction is 6.4 | Native BPF program at netfilter hooks | Too new for the baseline; vendor backports and attach semantics vary | Optional experimental backend only on a successful >=6.4 load/attach probe[36][37] |
| TCX links | No at 5.10; upstream introduction is 6.6 | Link-based TC attachment with improved lifecycle semantics | Not available on the support floor | Prefer on verified >=6.6; fall back to legacy TC[14][38] |
| sockmap/sk_msg/sockops | Program types exist on relevant kernels | Connected-socket acceleration and message redirection | Requires controlled sockets and does not transparently cover arbitrary Android traffic | Research only, not first-generation scope |
| LWT BPF / flow dissector | Kernel dependent | Route or classifier specialization | Broad system impact and difficult coexistence with Android routing | Do not use automatically |

### TC and mark handling

The safe acceleration contract is narrow:

```text
new_mark = (old_mark & !flux_mask) | (flux_value & flux_mask)
```

The program must never assign a whole mark. Android uses marks for network identity and routing decisions, and vendor builds may allocate additional bits. Observing a free-looking mask is not allocation authority. `fluxd` may publish mark bits to eBPF only after exact device-qualified positive policy, a fresh complete 27-cell packet/socket/conntrack census, topology and preservation proofs, and a later activation lease; every other case rejects decision-bearing mark writes.

TC programs should initially attach only to verified Generation-scoped TUN netdevices, including a Sing-Box-created link whose queue FDs remain engine-owned. AOSP netd can delete `clsact` from every extant interface during startup, so legacy TC uses a Flux-owned qdisc/filter lease bound to Network Epoch and reverified after netd lifecycle changes. On 6.6+ Aya can select qdisc-less TCX, but a failed TCX attach is returned to Flux; after probe failure or runtime demotion Flux explicitly retries the legacy netlink adapter.[14] Netd `clsact` deletion does not itself remove TCX, but link identity and foreign-program ordering still require revalidation. The selected attach kind, interface index, direction, legacy priority/handle or TCX link ID, attach flags, foreign-program inventory, program tag, policy-map digest, and Generation must be recorded.

### TC socket assignment is a narrow BPF-TPROXY experiment

Linux 5.10 supports `bpf_sk_lookup_tcp`/`udp` plus `bpf_sk_assign` at TC ingress. A program can select a compatible transparent TCP listener or unconnected UDP socket, but the packet still must reach a local route. A markless design is conceivable for an exact tether ingress with an input-interface RPDB selector, ordinary/throw routes for direct prefixes, and local routes only for proxy-positive prefixes.

This is not a general mark replacement. If a miss can still enter a proxy-local default, ordinary forwarding is blackholed. The socket must be in the same netns, reuseport sockets are not accepted by the 5.10 TC assignment path, and later redirects can invalidate delivery. CLAT, fragments, conntrack, VPN policy, dynamic networks, and netd/offload conflicts require real-device canaries. Keep this after positive `xt_bpf` acceleration and require a separate ADR before it becomes correctness-bearing.

### `sk_lookup` is promising but deliberately narrow

Linux documents `sk_lookup` as a socket-selection hook for incoming TCP connections and unconnected UDP datagrams. The program may assign a matching socket, but the hook is bypassed once TCP is established or UDP is connected.[5] Consequently it may support an experimental local ingress design in which a proxy listener is selected without an nft/xtables TPROXY rule for a tightly defined scope. It does not solve:

- local application OUTPUT classification;
- tethered/forwarded traffic;
- policy-route installation;
- connected UDP after lookup;
- transparent handling for every Sing-Box mode;
- Android UID and VPN policy by itself.

It should therefore be measured as a specialized optimization, not presented as an eBPF replacement for TPROXY.

### XDP should remain an explicit experiment

XDP runs before the normal network stack on ingress. That is useful for inexpensive accounting, dropping known-invalid traffic, or redirecting packets into a deliberately designed AF_XDP path. It is a poor default for Flux because transparent proxy policy depends on facts that do not exist at XDP, and XDP does not cover locally generated traffic. Driver mode is also NIC/driver-specific while generic mode has different cost and semantics. An XDP probe must be per interface and per mode, must inspect existing attachments first, and must never replace an unknown program.

### Maps and generation updates

Recommended map use:

| Need | Map | Design rule |
|---|---|---|
| IPv4/IPv6 CIDR policy | LPM trie | Build an inactive generation, then switch a small outer/config reference; do not rewrite a large active trie entry by entry |
| Bounded flow cache | LRU hash or LRU per-CPU hash | Treat eviction as normal; cache cannot be the sole correctness source |
| Packet/byte/reason counters | Per-CPU array/hash | Aggregate periodically in userspace; keep packet path lock-free |
| Current generation and mark mask | Array | One small, validated, atomically replaceable configuration record |
| Multi-generation policy | Array-of-maps or hash-of-maps | Populate and validate new inner maps before publishing them |
| Exceptional events | Ring buffer | Bound payloads and sampling; poll with the existing reactor |
| Fallback events | Perf-event array | Use when ring-buffer map creation or mmap/poll fails |

Linux's ring-buffer design specifically addresses memory efficiency and ordering across CPUs, and the ring-buffer FD is suitable for polling from the same event loop.[4] Ring buffers landed before the 5.10 floor, but `fluxd` must still create, mmap, submit, consume, and overflow-test a canary. A vendor kernel can disable BPF entirely or SELinux can deny access even when the UAPI constant exists.

Map pinning is optional. If `bpffs` is mounted and the process can create an owned directory such as `/sys/fs/bpf/flux`, pin only under that namespace and include program/map identity in the recovery journal. Never scan and remove unrelated pinned objects. When pinning is unavailable, keep owned FDs for the daemon lifetime and reconstruct state after restart.

### BTF and CO-RE strategy

CO-RE relocates field access against target-kernel BTF and is one of libbpf's main portability mechanisms.[15] Android vendor kernels cannot be assumed to expose usable `/sys/kernel/btf/vmlinux`, even when their base GKI version usually supports BTF.

Ship at least two eBPF object classes:

1. **5.10 no-CO-RE baseline.** Programs use stable UAPI contexts such as `__sk_buff`, explicit packet parsing, fixed-width shared types, and no target-kernel struct field access.
2. **Optional CO-RE objects.** Programs that genuinely need kernel types load only after BTF discovery, parse validation, relocation, verifier load, and real attach succeed.

Do not create a combinatorial object matrix for every kernel version. Partition objects by actual ABI need. A verifier rejection is capability evidence, not a reason to keep retrying the same object on every reconciliation.

### Aya versus libbpf-rs

| Criterion | Aya | libbpf-rs |
|---|---|---|
| Runtime implementation | Rust; explicitly avoids libbpf/BCC dependency[12] | Rust API over libbpf |
| eBPF program language | Rust `no_std` is a first-class workflow | Normally C compiled by Clang, although other ELF producers can be used |
| CO-RE/skeleton maturity | Supports BTF/relocations and Rust-side APIs; less tied to canonical C skeleton workflow | Strong libbpf CO-RE and generated skeleton model[15] |
| Feature probing | Source contains program/map/helper probes[13] | libbpf probing APIs are available, with custom integration required |
| TC lifecycle | Version-selected TCX or legacy TC; TCX failure is returned, so Flux explicitly retries legacy after probe/demotion[14] | libbpf/link and netlink facilities; application supplies lifecycle policy |
| Netfilter BPF example | Framework support evolves; validate the exact release | Audited tree includes `netfilter_blocklist` example[18] |
| Android cross-build | No mandatory libelf/zlib/libbpf runtime chain | Cargo features help static/vendored builds, but libbpf and its native build/dependencies remain[16][17] |
| Recommended role | Default production loader and Rust eBPF programs | Optional lab/tooling backend and newer-kernel netfilter prototype |

Aya is the better default for a Magisk module because it reduces C ABI and packaging risk while keeping the loader and shared types in Rust. That recommendation is conditional on a spike proving that the exact 5.10 baseline programs load on representative vendor devices. libbpf-rs remains valuable as a differential implementation: if an Aya object fails while a small libbpf CO-RE equivalent succeeds, the comparison can distinguish kernel/verifier limitations from loader bugs.

### eBPF program engineering rules

- Keep baseline programs small and tail-call only when the call graph and failure behavior are explicit.
- Parse Ethernet, VLAN, IPv4, IPv6, and extension headers with verifier-visible bounds checks.
- Keep policy payloads in maps; do not compile user rules into enormous instruction streams.
- Bound loops even though upstream 5.10 supports bounded loops; vendor verifier behavior and instruction budgets vary.
- Define shared `#[repr(C)]` types in a no-`std` crate and assert size/alignment from userspace tests.
- Treat every map lookup as nullable and every LRU miss as a normal fallback.
- Include a generation number in configuration and emitted events so stale programs fail safe and telemetry can be correlated.
- Capture the complete verifier log, truncated only by an explicit diagnostic limit.
- Use `BPF_PROG_TEST_RUN` where the program type supports it, followed by a real attach/detach test; a successful test run is not proof that attachment is permitted.[2]
- Keep an equivalent non-eBPF decision path active until acceleration parity is demonstrated on the device matrix.

## nftables and netfilter implementation options

### Why nftables is the preferred rules backend

nftables provides named sets, interval sets, typed expressions, counters, and batched netlink transactions. The project documentation describes atomic ruleset replacement when commands are submitted as one ruleset transaction.[23][24][25] These properties map well to generation-based reconciliation and avoid the current need to compile large address lists into a fixed xtables jump tree.

The preferred design owns exactly one uniquely named `inet` table, for example `flux_<installation-id>`. It must never flush or rewrite Android/vendor tables. Every chain, set, rule comment, and generation marker must be reconstructible from the active journal.

The owned table should contain:

- stable entry chains or one atomically replaced generation;
- separate classification for local OUTPUT and PREROUTING/forwarded traffic;
- named IPv4 and IPv6 interval sets with auto-merge where supported;
- explicit counters for decision reasons;
- mark operations constrained to the allocated mask;
- socket-transparent and TPROXY expressions only where the canary proved them;
- a generation tag/comment and a deterministic object-name budget.

### Current Rust library gap

No audited crate is a complete, low-risk native solution for the required nftables TPROXY rules:

| Option | Audited capability | Decision |
|---|---|---|
| `netlink-packet-netfilter` 0.2.0 | Source currently covers conntrack and NFLOG-oriented messages; it does not expose a complete nftables or ipset codec[19] | Useful dependency family, not the rules backend |
| `nftables` 0.6.3 | Models nft JSON, including TPROXY expressions, and invokes an `nft` userspace binary[20] | Best first implementation if Flux ships or verifies a compatible `nft` binary |
| Mullvad `nftnl` 0.9.2 | Rust wrapper over libnftnl with batches/tables/chains/sets/rules; audited public expressions do not provide the required TPROXY wrapper[21] | Native dependencies plus a local extension still required |
| pure-Rust `nftnl-rs` 0.5.1 | Its own README calls it early/unmaintained and limits support primarily to set-element operations[22] | Do not adopt for production |
| Narrow in-tree nfnetlink codec | Can implement exactly the objects Flux owns | Long-term native direction after differential tests against official `nft` |

The practical sequence is:

1. Implement a backend-neutral capture policy compiler.
2. Add an `nft` JSON adapter using argument arrays and stdin, never `sh -c` and never concatenated user syntax.
3. Bundle and fingerprint a known `nft` build when licensing and Android C-library compatibility are acceptable, or select the backend only when a compatible system binary passes the complete canary.
4. Record JSON input, normalized `nft -j list` output, stderr, and exit status in bounded diagnostics.
5. Later replace the process adapter with a narrow in-tree netlink encoder, using official nftables source and JSON behavior as the oracle.[23][24]

The in-tree codec should not attempt to become a generic nftables library. It needs only owned table/chain/set/rule create, replace, list, and delete operations; batch begin/end; nested attributes; sequence/ack/extack processing; and expressions used by Flux. Fuzz the decoder and differentially compare generated state with the official `nft` binary.

### nftables active probe

Command presence or `KFEAT_NFT=1` is insufficient. The probe should:

1. create a uniquely named temporary `inet` table;
2. create an IPv4 or dual-stack named set with the intended flags;
3. create a deliberately non-matching canary base chain or otherwise side-effect-contained hook;
4. add rules using the exact required operations: set lookup, counter, masked mark update, socket-transparent match, and TCP/UDP TPROXY expression;
5. commit as one batch and require all acknowledgements;
6. list the owned table back and verify the normalized expression tree;
7. delete the table and verify absence;
8. preserve errno, netlink extended acknowledgement, or `nft` stderr when any step fails.

The canary must be constructed so no real packet can match. The cleanup is an RAII/recovery-journal obligation, not a `finally` comment. A crash on the probe must leave a recognizable temporary name that the next boot can remove without touching foreign state.

Classify stable availability rather than reducing failures to false:

- **unsupported:** family/expression/revision is absent;
- **denied:** capability or SELinux policy denied the operation;
- **conflicting:** name, hook, or other owner prevents safe installation;
- **broken:** kernel rejected Flux's valid encoding, or Flux/`nft` generation violated the specified contract;
- **unknown:** no safe conclusive probe is possible.

ENOBUFS, interrupted dump, lock/resource pressure, or racing network state are transient probe-attempt outcomes with bounded retry/backoff evidence. Automatic mode may try the next safe backend after a stable non-supported result or exhausted retry policy, but diagnostics retain both stable state and attempt evidence. An explicit `backend = "nftables"` request fails rather than silently switching mechanisms.

### Native netfilter BPF is not the nftables replacement

`BPF_PROG_TYPE_NETFILTER` was added upstream for Linux 6.4, as shown by the introduction commit and the UAPI difference between 6.3 and 6.4.[36][37] It is therefore outside the 5.10 baseline. On eligible kernels it can be an experimental hook for bounded filtering or classification, but it does not remove the need for sets, transparent socket semantics, policy routing, ownership, and fallbacks. It should be guarded by:

- parsed kernel >= 6.4 as a coarse eligibility gate;
- program-type and helper probes;
- a minimal load and real hook attach/detach;
- coexistence inspection;
- packet-path conformance against the nft/xtables result;
- automatic demotion for the boot on structural failure.

## ipset and xtables compatibility

### ipset protocol and update model

ipset remains useful when the compatible capture backend is xtables. Its source defines a userspace/kernel protocol negotiation command and type revisions rather than one timeless ABI.[26][27] `fluxd` should probe the protocol and the exact `hash:net` family/revision it intends to use.

For each family and generation:

1. create a generation-specific target `hash:net` set and a uniquely named temporary set with bounded `hashsize`/`maxelem`;
2. populate the temporary set through a restore stream or native protocol adapter;
3. verify element count and representative entries;
4. optionally `swap` the temporary set into the still-unreferenced generation-specific target name;
5. compile the candidate generation chain against that immutable target;
6. cut over only by replacing the stable xtables jump with the candidate generation jump;
7. destroy the retired generation's sets only after no chain references them.

An `ipset restore` stream is not a whole-session transaction. `swap` may publish populated contents into an unreferenced generation-specific target, but it is not the active-Generation cutover. The stable xtables jump is that cutover, which prevents the old Generation from observing new set contents.

IPv4 and IPv6 need distinct sets unless the exact userspace/kernel type proves another supported representation. Treat memory allocation failure or a type-revision mismatch as a backend/resource result, not as an excuse to emit a partially populated set.

### xtables implementation selection

Android devices may expose iptables-legacy, iptables-nft, wrapper binaries, or vendor-specific combinations. `fluxd` must select exactly one coherent family for a generation:

- inspect `iptables -V` and `ip6tables -V` output;
- verify `iptables-restore`/`ip6tables-restore` belongs to the same implementation;
- exercise a temporary owned chain containing the exact socket, owner, connmark/mark, and TPROXY matches/targets;
- test xtables lock behavior and use a bounded wait;
- test ipset integration through the actual `set` match when ipset is selected;
- never manage the same Flux rules through both legacy and nft variants.

The existing `iptables-restore --noflush` compiler remains the compatibility baseline. Stable dispatch chains and generation-specific implementation chains allow prepare/activate/retire without flushing foreign rules. If ipset is unavailable, retain the current bounded jump-tree generator and its hard rule/chain budgets.

External binaries must be invoked directly with fixed executable paths, argument arrays, controlled environment, bounded stdin/stdout/stderr, and a timeout. No user-derived field may become shell syntax.

## rtnetlink and Android network observation

### Keep the current reactor as the baseline

The Rust `rtnetlink` project offers a broad asynchronous API over the rust-netlink packet crates.[28] It is useful as a reference and could be adopted selectively. Flux already has a smaller Android-tested design with direct message control, batching, `NETLINK_EXT_ACK`, one reactor, and explicit resynchronization. Replacing that code wholesale would create migration and binary-size risk without automatically improving correctness.

Recommended direction:

- move the current codecs and socket ownership into an internal `flux-platform` module;
- add link, address, route, rule, and required neighbor decoding incrementally;
- keep borrowed decode views over receive buffers where lifetime rules can prove validity;
- convert only validated messages into owned domain facts;
- keep one single-writer mutation queue for rules/routes/links;
- use a complete dump to establish a new network epoch after loss or ambiguity.

### Reliability rules

Netlink is not a reliable event log. Socket receive overflow can report `ENOBUFS`, and multipart dumps can be interrupted; applications must resynchronize rather than assuming the next multicast event repairs the missing state.[35]

The reactor should:

- allocate a unique sequence for every request and match every acknowledgement;
- preserve the local netlink port ID and validate senders;
- enable `NETLINK_EXT_ACK` when the setsockopt probe succeeds;
- enable strict dump checking where supported and record when it is not;
- size receive buffers but retain loss notification rather than hiding it;
- treat `ENOBUFS`, malformed/truncated messages, sequence gaps, and interrupted dumps as inventory invalidation;
- retry a full dump with a bounded backoff and publish no new generation from a partial inventory;
- coalesce multicast bursts by network epoch instead of spawning work per event;
- classify idempotent kernel errors separately from ownership conflicts.

The address-to-rule behavior currently owned by `addrsyncd` becomes one policy producer inside this inventory. It should no longer have a separate process lifecycle or independent route writer.

## TUN implementation

### Direct UAPI probes and future ownership

Upstream TUN/TAP documentation defines the core sequence: open `/dev/net/tun`, issue `TUNSETIFF`, and request `IFF_TUN | IFF_NO_PI` for layer-3 packets without the extra packet-information header.[6][8] TUN creation/configuration requires `CAP_NET_ADMIN` in the governing user namespace.[6]

Implement this in a small reviewed Rust module using `OwnedFd` and `#[repr(C)]` UAPI types. The shipping `EngineOwnedTun` plan uses it for contained probes; the future `FluxOwnedTunFd` plan uses it for production ownership. Required operations are:

- open with `O_RDWR | O_NONBLOCK | O_CLOEXEC`;
- `TUNGETFEATURES` before selecting flags;
- `TUNSETIFF` with a deterministic, collision-checked name;
- read back interface index/name/flags through rtnetlink;
- configure MTU, addresses, routes, and rules through rtnetlink rather than shell `ip`;
- keep persistence off unless a recovery design explicitly requires it;
- close all queue FDs on rollback, then verify link disappearance or remove only the owned device;
- prevent the Sing-Box child from inheriting unrelated TUN/netlink/BPF FDs.

The Android implementation in `tun` 0.8.13 requires `Configuration::raw_fd`; it errors when no FD is supplied.[29] That crate can wrap an already-created descriptor, but it is not the privileged device factory required by `fluxd`. A direct adapter is smaller and makes multiqueue, eBPF steering, offload, ownership, and probing explicit.

### A TUN FD is not a proxy engine

Creating a TUN interface only delivers IP packets to userspace. Something must parse, route, proxy, and return them. The first rewrite should continue using Sing-Box for that packet-stack function. Flux may:

- let a verified Sing-Box version create its own TUN while `fluxd` owns surrounding routes/rules and observes the device; or
- create the device and hand off queue FDs only if Sing-Box exposes a supported, version-tested FD handoff mechanism.

Do not invent an undocumented FD-passing contract. Direct `fluxd` packet processing would require a userspace TCP/IP stack and is a separate project.

### Multiqueue

Linux supports multiqueue TUN by opening multiple `/dev/net/tun` descriptors and applying `TUNSETIFF` with the same interface name and `IFF_MULTI_QUEUE` on each descriptor.[6] `TUNSETQUEUE` can attach or detach queues.[8]

Recommended design:

- For `EngineOwnedTun`, resolve multiqueue through the exact Sing-Box Engine Capability Profile and leave queue FDs/workers inside Sing-Box.
- Apply the remaining direct queue rules only to the future `FluxOwnedTunFd` plan.
- start with one queue during capability and correctness testing;
- create additional queues only after the same-name ioctl succeeds for each FD;
- use one bounded worker per active queue, normally capped below or at the number of useful CPUs;
- allocate fixed-capacity packet buffers from per-worker pools;
- maintain flow affinity, either through the kernel's default hash or a verified steering program;
- benchmark one, two, four, and CPU-count queues instead of assuming more queues improve Android power/performance;
- support live queue detach only after packet-loss and ordering tests.

### TUN eBPF steering and filtering

Linux 5.10's TUN driver implements `TUNSETSTEERINGEBPF` and `TUNSETFILTEREBPF` using socket-filter BPF program FDs.[7][8] The steering program's result is used to choose a queue, while the filter program can accept, trim, or reject packets according to socket-filter semantics.

This is one of the strongest future advanced eBPF opportunities when `FluxOwnedTunFd` gives Flux the queue FDs. A steering program can hash a normalized IPv4/IPv6 flow tuple with a generation seed and return a stable queue choice. The design must handle:

- fragments that lack transport ports;
- IPv6 extension headers;
- queue-count changes;
- non-power-of-two queue counts;
- program detach during rollback;
- a verifier/load failure that falls back to kernel default steering;
- differential tests proving no flow reordering regression.

Defer `TUNSETFILTEREBPF` from the production plan. A zero return drops traffic and the kernel cannot distinguish a logic bug from an intended policy decision, so an attached filter has no automatic fail-open guarantee.

### Offloads

Probe `TUNGETFEATURES` and treat `TUNSETOFFLOAD`, virtual-net headers, checksum, segmentation, and related flags as a negotiated end-to-end contract.[7][8] Kernel support alone is insufficient: Sing-Box or any other queue consumer must parse and produce the exact metadata correctly. Enable one offload at a time, validate packet captures and checksums for IPv4/IPv6 TCP/UDP, and retain a plain-packet fallback.

## `epoll`, async Rust, and `io_uring`

### `epoll` remains the mandatory baseline

The existing reactor is a good fit for:

- rtnetlink and netfilter netlink sockets;
- control sockets;
- `timerfd` deadlines;
- `signalfd` or pidfds for lifecycle;
- nonblocking TUN queues only in the future `FluxOwnedTunFd` plan;
- pollable BPF ring-buffer/perf-buffer FDs;
- child stdout/stderr pipes.

Use edge-triggering only where every handler drains until `EAGAIN` and has focused tests; level-triggered operation is simpler for low-rate control FDs. Packet workers should not create one async task per packet. They should drain bounded batches, publish aggregate counters, and yield after a work budget so control and reconciliation remain responsive.

An async runtime can still be useful for the control API, process supervision, timers, and subscription I/O. Two reasonable designs are:

1. retain the custom reactor for all local kernel I/O and expose bounded channels to higher-level async code; or
2. place owned FDs behind a runtime's `AsyncFd` while preserving the single-writer and drain-until-`EAGAIN` rules.

Do not make the network hot path depend on a multi-thread scheduler before benchmarks demonstrate a benefit. Rust's ownership types, bounded channels, cancellation tokens, and structured task scopes are more important than choosing a fashionable executor.

### `io_uring` is an optimization, not a requirement

The Rust `io-uring` crate exposes runtime opcode registration/probing rather than assuming every header-defined operation works.[30] Upstream 5.10 contains the basic read/write interface and fast-poll feature machinery, but a vendor device may differ, TUN file operations may reject a path, seccomp may block setup/register/enter, and a supported opcode can still behave poorly for this workload.[31]

Enable an `io_uring` TUN worker only after the exact Sing-Box version provides the `FluxOwnedTunFd` handoff contract and all of the following succeed in the running boot:

1. `io_uring_setup` with conservative flags;
2. inspection of returned feature bits;
3. registered-probe confirmation for required opcodes;
4. real nonblocking read and write against a temporary/owned TUN queue;
5. cancellation and shutdown without leaked buffers or stuck completions;
6. sustained packet correctness under backpressure;
7. a benchmark showing a material improvement in throughput, CPU time, or wakeups over epoll.

Use epoll automatically if any step fails. Do not enable SQPOLL by default on 5.10: it creates a dedicated kernel polling thread, consumes resources continuously, and has additional privilege/operational constraints. Fixed buffers and registered files should be separate probes because SELinux, memlock, and vendor limits may reject registration even when basic rings work.

## Adaptive capability selection

### Kernel version policy

Parse the leading numeric `major.minor.patch` from `uname` and ignore Android/vendor suffixes for ordering. Reject a parsed version below 5.10 before mutating anything. If parsing fails, report unsupported rather than guessing.

After that check, version is only an eligibility hint:

- 5.10 permits attempts at the baseline facilities described in this note;
- >=6.4 permits attempting netfilter BPF;
- >=6.6 permits attempting TCX;
- a vendor backport may make a feature work earlier;
- a vendor configuration, SELinux rule, missing module, or incomplete backport may make a nominally old-enough feature unusable.

The code should therefore keep version gates and operational probes separate.

### Capability evidence model

Avoid a bag of booleans. A useful model is:

```rust
enum CapabilityStatus {
    Supported,
    Unsupported,
    Denied,
    Conflicting,
    Broken,
    Unknown,
}

struct CapabilityEvidence {
    feature: FeatureId,
    status: CapabilityStatus,
    kernel: KernelRelease,
    probe: ProbeKind,
    errno: Option<i32>,
    extack: Option<String>,
    verifier_log: Option<String>,
    reason: String,
    observed_at_boot: BootId,
}
```

The compiler consumes this evidence plus user policy. It should never call probes while constructing a pure generation.

### Probe matrix

| Feature | Coarse gate | Authoritative contained probe | Fallback or result |
|---|---|---|---|
| Kernel support floor | parsed release | none | `<5.10` is unsupported |
| rtnetlink mutation | 5.10 floor | create/read/delete an owned harmless route/rule in a reserved test context where safe; otherwise use production operation with strict identity | No safe capture plan if required PBR cannot be installed |
| netlink extack | none | `setsockopt(NETLINK_EXT_ACK)` plus malformed canary in test mode | Plain errno/ack diagnostics |
| strict netlink checking | none | setsockopt and strict dump | Decoder validation plus full resync |
| nftables | none beyond floor | owned transaction with set, counter, mark, socket-transparent, TPROXY; list and delete | xtables or TUN |
| ipset | none | protocol query, exact type/revision create, populate, swap, destroy | Bounded xtables jump tree |
| xtables TPROXY | none | temporary owned chain with exact matches/targets and restore tool | TUN or unsupported explicit TPROXY request |
| BPF syscall/map | none | minimal map create/update/lookup/delete and tiny program load | eBPF off |
| ring buffer | nominally available at floor | create, mmap, submit, epoll wakeup, consume, overflow behavior | perf-event array, then polling counters |
| kernel BTF | none | open and parse `/sys/kernel/btf/vmlinux`, then relocate/load a CO-RE canary | no-CO-RE object |
| TC | none | inspect existing qdisc/filters; attach/query/detach a no-op classifier on an owned interface | eBPF TC off |
| TCX | parsed >=6.6, or backport attempt policy | link create/query/detach | legacy TC |
| cgroup skb/sock-addr | none | identify the intended child and every ancestor, inspect direct programs/flags, then attach/query/detach a no-op only when the chain permits it | hook off |
| `sk_lookup` | 5.10 baseline eligibility | load, attach through a controlled network-namespace FD, prove TCP and UDP socket selection in a canary namespace/device test | normal TPROXY/TUN path |
| XDP | per interface | inspect program, attempt non-replacing attach in requested mode, query, detach | XDP off |
| netfilter BPF | parsed >=6.4, or explicit backport attempt | program/helper load plus real hook attach/query/detach | nftables/xtables |
| `/dev/net/tun` | none | open, `TUNGETFEATURES`, `TUNSETIFF`, rtnetlink readback, packet round trip, cleanup | TPROXY or unsupported TUN request |
| Direct TUN multiqueue control | future `FluxOwnedTunFd`; feature bits are advisory | create second queue on same name and round-trip concurrent packets | engine-qualified multiqueue behavior or a single Flux-owned queue |
| TUN eBPF steering | future `FluxOwnedTunFd`; ioctl constants are advisory | load socket-filter canary, set steering ioctl, verify behavior, detach | kernel default steering |
| TUN offloads | engine-qualified setting or future `FluxOwnedTunFd`; feature bits are advisory | enable one flag and verify end-to-end packet metadata/checksums | offloads off |
| `io_uring` | future `FluxOwnedTunFd` | setup, feature bits, opcode probe, real TUN I/O, cancel/shutdown, benchmark | epoll |

Capability results should be cached only for the current boot. Invalidate a selected capability after a structural runtime failure such as `EOPNOTSUPP`, verifier rejection after policy change, disappeared interface, changed cgroup mount, or backend binary replacement. Recompile the generation using the next safe path.

The stable capability state should be `supported`, `unsupported`, `denied`, `conflicting`, `broken`, or `unknown`. Retryable timeout/busy/interruption evidence belongs to an individual probe attempt with bounded backoff; it should not persist as a seventh `transient` availability class.

## Privileges, capabilities, and seccomp

### Required privilege classes

Linux 5.10 split BPF privilege into dedicated capabilities. The UAPI descriptions assign privileged BPF operations to `CAP_BPF`, networking administration to `CAP_NET_ADMIN`, and performance/tracing operations to `CAP_PERFMON`; `CAP_SYS_ADMIN` remains a backward-compatible broad fallback in relevant checks.[10] In practical terms:

- TUN creation, routes/rules, nftables/xtables/ipset, TC/XDP attachment, and transparent-network setup need `CAP_NET_ADMIN`;
- BPF map/program creation generally needs `CAP_BPF` on 5.10, with `CAP_SYS_ADMIN` fallback behavior depending on the operation/kernel;
- tracing/perf-style programs and some event facilities can require `CAP_PERFMON`;
- raising hard resource limits may require additional privilege;
- Android SELinux can deny any of these operations even to UID 0.[34]

Do not infer authority from `geteuid() == 0`. The active probes are the authority test.

### BPF memory accounting

Linux 5.10-era BPF deployments must plan for `RLIMIT_MEMLOCK`. Upstream later moved BPF allocation accounting toward memory cgroups, but that change is after the support-floor implementation.[39] Before dropping privilege, `fluxd` should set a bounded memlock budget derived from its map plan, then prove allocation with real map creation. Unlimited memlock is unnecessary and hides leaks.

Map sizing must be part of generation validation:

- maximum CIDR elements;
- maximum flow-cache entries;
- per-CPU multiplier;
- ring-buffer bytes;
- duplicate memory during generation swap;
- verifier/object and page overhead;
- a device-level hard ceiling.

### Privilege separation

`fluxd` must retain the ability to repair kernel state after network changes, so a simple drop-all-capabilities-after-boot model is insufficient. Two viable designs are:

1. one carefully constrained controller retaining the minimal effective capabilities and applying backend-specific seccomp after initialization; or
2. a small privileged kernel broker with a narrow typed protocol, plus less-privileged controller, telemetry, and packet workers.

The second design has a stronger boundary but increases lifecycle complexity. It should follow only after the single-process rewrite is stable and the broker protocol can be exhaustively validated.

Regardless of model:

- mark every sensitive FD `CLOEXEC`;
- explicitly construct Sing-Box's inherited FD set;
- clear supplementary groups not required by policy;
- do not give Sing-Box BPF/netfilter FDs;
- avoid inheritable and ambient capabilities unless a documented child contract needs them;
- retain a root compatibility mode only with an explicit diagnostic warning.

### Kernel extensions are not the privilege fallback

A `.ko` can implement custom netfilter hooks, ipset/xtables compatibility, or a typed Generic Netlink service, but it bypasses the verifier-governed eBPF safety model and has a kernel-wide failure radius. Android module support does not establish matching KMI/modversions, exported symbols, signature acceptance, SELinux permission, or unload safety. Production Flux should call no module load/unload syscall and package no kernel payload. It may consume an already-loaded reviewed OEM/custom-kernel extension only for exact-profiled read-only observation with independently verified AVB/module-signature/measurement identity; Generic Netlink checks provide origin/correlation, not source-build authentication. Decision-bearing use requires a concrete partner, passive-by-default lease semantics, and a separate ADR. See the [expanded assessment](ebpf-and-kernel-extensions-2026-07.md).

### Seccomp

Linux seccomp filters are additive: later filters can only further restrict the process. The kernel documentation requires checking the architecture in the filter because syscall numbers differ between architectures, and it describes `PR_SET_NO_NEW_PRIVS` as the unprivileged filter prerequisite.[11]

Apply seccomp only after backend selection and initialization. Use backend-specific policies:

- baseline controller: epoll, timer/signals, Unix sockets, files, process supervision, netlink, required ioctls;
- eBPF extension: `bpf`, mmap/poll, resource-limit calls needed before lock-down;
- TUN extension: the exact TUN and network-interface ioctls;
- io_uring extension only when selected;
- subscription updater, if in-process: narrowly scoped network/file syscalls or a separate worker.
- production profiles explicitly deny `init_module`, `finit_module`, and `delete_module`.

A bad seccomp policy can boot-loop a networking module. Ship audit/learning fixtures, test every backend combination, install the filter after recovery resources are open, and retain a configuration-controlled safe mode for diagnosis. Seccomp reduces syscall surface; it is not a complete sandbox and does not replace SELinux or filesystem validation.

### Android SELinux

Android SELinux enforces mandatory policy independently of Unix UID/capabilities.[34] Rooted environments vary in the domain assigned to module processes and in vendor allow rules. `fluxd` should:

- record `/proc/self/attr/current` in diagnostics;
- map `EACCES`/`EPERM` probe failures to a policy-denied state rather than unsupported;
- include a bounded hint to inspect AVC denials, without scraping or leaking unrelated logs by default;
- never recommend globally disabling SELinux;
- test release devices in enforcing mode.

## Android Rust build and linking strategy

Rust officially supports Android targets such as `aarch64-linux-android` and expects the Android NDK toolchain/linker setup.[32] Android's ABI documentation defines the device ABI names and native calling conventions, including `arm64-v8a` for 64-bit Arm.[33]

Recommended release targets:

- `aarch64-linux-android` as the primary physical-device target;
- `x86_64-linux-android` for Cuttlefish/emulator conformance;
- add `armv7-linux-androideabi` only if the product explicitly supports 32-bit devices and the whole dependency graph is tested there.

Build rules:

- use a pinned Rust toolchain and pinned NDK revision;
- link against Android/bionic with the NDK Clang driver, not glibc artifacts from a desktop Linux build;
- produce a PIE-compatible executable and verify it with Android tooling on each target;
- select an Android API level compatible with the desired userspace libc surface; invoke newer Linux facilities through reviewed raw syscalls/UAPI where bionic headers or wrappers lag;
- keep checked-in/generated UAPI bindings tied to a documented kernel header snapshot;
- never execute target-built helpers from `build.rs`;
- use LTO, `panic = "abort"`, and stripping only after preserving separate symbols/build IDs for diagnostics;
- generate an SBOM and record crate, native-library, kernel-UAPI, Rust, NDK, and eBPF object versions in the module manifest.

Aya's absence of mandatory libbpf/libelf/zlib is a significant Android advantage.[12] A libbpf-rs build can use vendoring/static features, but it still requires a working native Clang/C toolchain and dependency strategy.[16][17] The same concern applies to libnftnl/libmnl-backed nftables APIs. Every native dependency increases ABI, license, binary-size, CVE, and reproducibility work.

Compile Rust eBPF programs as separate no-`std` BPF objects, then embed or package immutable objects with hashes. Do not compile BPF on the phone. Keep userspace shared types versioned, and reject an object whose schema/hash does not match the loader.

## Observability requirements

The capability report is part of correctness, not a debug afterthought. `fluxctl capabilities --json` should expose:

- parsed kernel release and raw `uname` string;
- Android build fingerprint, ABI, SELinux context, net namespace, and boot ID;
- selected capture/set/eBPF/TUN/I/O backends;
- every probe status and last evidence;
- exact errno, netlink extack, nft/xtables/ipset stderr category, and verifier log digest;
- discovered BTF/cgroup/bpffs state;
- attached program IDs/tags/link kinds and owned nft/xtables/ipset identities;
- TUN feature bits, queues, offloads, and selected I/O driver;
- rejected alternatives and their reasons;
- whether the result is fresh, cached for this boot, or invalidated.

Runtime metrics should include:

- reconciliation duration and rollback count;
- netlink receive overflow, interrupted dump, resync count, and ack latency;
- nft batch/xtables restore/ipset swap duration;
- BPF map allocation, verifier, attach, ring overflow/lost events, and sampled-event drop counts;
- per-reason packet/byte counters, aggregated rather than per-packet logs;
- TUN queue depth/wakeups/read-write batches/errors;
- `io_uring` submission/completion/cancellation failures when selected;
- child health and capture-detach latency on failure.

Telemetry should not export packet payloads, DNS names, or destination tuples by default. High-cardinality flow details belong behind an explicit bounded diagnostic mode with redaction and expiry.

## Testing strategy

### Pure Rust tests

- kernel-release parsing, including Android/vendor suffixes and malformed input;
- mark-mask preservation and conflict allocation;
- CIDR normalization, IPv4/IPv6 prefix ordering, and LPM key encoding;
- nft JSON and native netlink encoders/decoders;
- ipset restore planning and post-swap ownership;
- rtnetlink alignment, nesting, extack parsing, and multipart state machines;
- TUN ioctl structure size/alignment per target ABI;
- eBPF/userspace shared type layout;
- deterministic generation output and idempotent reconciliation plans;
- typestate/cleanup behavior under injected failure at every transition.

Use property tests for prefix-set equivalence, mark composition, transaction ordering, and repeated reconcile/rollback. Fuzz all binary decoders and JSON/config inputs with strict size limits.

### Linux namespace integration

Run privileged tests in disposable network namespaces with veth pairs, loopback, TUN, and an isolated cgroup when available. Cover:

- IPv4 and IPv6 TCP;
- connected and unconnected UDP, including QUIC-shaped traffic;
- fragments, IPv6 extension headers, PMTU, and ICMP errors;
- DNS interception and bypass;
- local OUTPUT and forwarded/tethered PREROUTING equivalents;
- UID/cgroup bypass policy;
- transparent listener behavior and original-destination recovery;
- nft transaction replacement and rollback;
- generation-specific ipset population/optional swap plus stable-jump cutover;
- xtables bounded-tree equivalence;
- single- and multiqueue TUN behavior;
- eBPF mark preservation and map-generation swaps.

After every test, assert that the namespace contains no Flux-owned objects and that deliberately created foreign objects are byte-for-byte unchanged.

### Kernel matrix

At minimum test upstream or distribution kernels representing:

- 5.10: support floor, ring buffer, legacy TC, sk_lookup, TUN eBPF;
- 5.15: common Android generation and later fixes;
- 6.1: newer LTS without netfilter BPF baseline assumption;
- 6.6: TCX-capable LTS and netfilter BPF eligibility.

Use QEMU, virtme-ng, or equivalent reproducible VMs for fast CI. Then run Cuttlefish/GKI and real vendor devices because desktop kernels cannot reproduce Android SELinux, netd coexistence, vendor modules, cgroup layout, tethering offload, or BTF omissions.

### eBPF-specific tests

- feature-probe result versus real program load/attach;
- `BPF_PROG_TEST_RUN` vectors where supported;
- verifier rejection with complete bounded log capture;
- map full/eviction behavior;
- ring-buffer wrap, overflow, ordering, and lost-event accounting;
- legacy TC attach/detach and explicit legacy retry after TCX probe failure;
- existing foreign program detection and non-replacement;
- interface disappearance/recreation;
- TUN steering flow stability and queue-count changes;
- eBPF failure while the conventional correctness path remains active.

### Differential tests

- Compare the nft JSON/process backend and future native encoder by normalizing `nft -j list ruleset` output.
- Compare capture-policy decisions across nftables, xtables+ipset, xtables+jump, and an in-memory reference evaluator.
- Compare route/rule dumps produced by current `addrsyncd` behavior and the in-process rewrite.
- Compare Aya and a minimal libbpf-rs program for selected loader/CO-RE failures.
- Compare epoll and `io_uring` TUN workers for packet bytes, ordering, backpressure, shutdown, CPU, and wakeups.

### Fault injection

Inject:

- `ENOBUFS` and interrupted netlink dumps;
- missing acknowledgements and malformed extacks;
- nft batch rejection at each operation;
- xtables lock timeout;
- ipset full/revision mismatch/failure before and after swap;
- BPF verifier rejection, absent BTF/bpffs/cgroup v2, and attach conflicts;
- SELinux-style `EACCES`/`EPERM`;
- TUN queue failure and interface rename/disappearance;
- `io_uring` setup/register/enter failures;
- Sing-Box port collision, slow readiness, crash, and stale process identity;
- `kill -9` after every prepare/activate/verify/retire journal step.

The acceptance property is convergence to exactly one of three states: the previous known-good generation, the target generation, or a clean documented fail-open state. Partial capture with no healthy proxy engine is not acceptable.

## Local research-stage sequence

The labels below are local ordering for this research note, not Flux product phases. The
authoritative product phase numbers and activation gates remain in
`docs/architecture/implementation-roadmap.md`.

### Research stage 1: common contracts and retained baseline

- Move `addrsyncd` reactor/rtnetlink code in-process.
- Define typed marks, masks, table/priority IDs, interface identities, generation IDs, and capability evidence.
- Add the 5.10 floor check and JSON capability registry.
- Preserve xtables restore and bounded-tree behavior behind an adapter.
- Establish a crash-recovery journal and single kernel writer.

### Research stage 2: ipset and nftables

- Add exact ipset protocol/type/swap probing and the generation-swap adapter.
- Add the nft JSON/process adapter with a bundled or fingerprinted binary.
- Implement the full nft canary and owned-table reconciliation.
- Differentially test capture policy across all rule backends.
- Begin the narrow native nft netlink codec only after the process backend is an oracle.

### Research stage 3: managed TUN

- Ship `EngineOwnedTun`; implement direct TUN UAPI for contained probes and the future FD-handoff plan.
- Move TUN routes/rules and device observation under the generation transaction.
- Resolve engine-owned multiqueue/offloads only through the exact Engine Capability Profile; integrate direct queues only through a supported FD contract.
- Add conservative direct multiqueue/offload probes for the future `FluxOwnedTunFd` plan.
- Keep epoll as the shipping I/O path.

### Research stage 4: eBPF observation

- Add Aya loader, no-CO-RE baseline object, capability probes, and verifier diagnostics.
- Probe exact `xt_bpf` map/program/pin/iptables/packet/cleanup behavior and attach an observation rule that always returns false.
- Add ring-buffer sampled events with perf-buffer fallback.
- Test map generation swap and stale-generation fail-safe behavior.
- Ship physical-interface TC, cgroup, sk_lookup, and XDP only as explicit experiments.

### Research stage 5: eBPF acceleration and newer-kernel paths

This local research sequence records mechanism priority only. Once implemented, TUN TC observation and child
telemetry are independently eligible from their own probes and do not require an active `xt_bpf`
path at runtime.

- Add `xt_bpf` proxy-positive matching first; every miss, parse ambiguity, `overflowuid`, stale Generation, or map failure continues through the complete classic classifier.
- Attach TC counters next to a verified Generation-scoped TUN link; use Network-Epoch-bound legacy TC or a verified qdisc-less TCX link.
- Add optional proxy-child `sockops` telemetry only after full ancestor-chain attach-state proof, paired with userspace TCP/UDP mark evidence.
- Add bounded flow caching and masked TC mark acceleration only where per-domain decision parity is proven.
- Prototype TC ingress socket assignment only for an exact domain with safe local-route/miss behavior.
- Under `FluxOwnedTunFd`, add TUN steering eBPF and measure multiqueue stability; keep TUN filtering deferred.
- Prefer TCX on verified 6.6+ kernels.
- Prototype netfilter BPF on verified 6.4+ kernels, optionally using libbpf-rs as a reference.
- Under `FluxOwnedTunFd`, enable `io_uring` only on devices where the complete probe and benchmark gate passes.

## Risks and open questions

1. **Android netd coexistence.** Exact rule priorities, mark ownership, qdisc behavior, cgroup attachment points, and tethering offload differ across Android/vendor versions. The device matrix must determine safe defaults.
2. **Sing-Box TUN ownership.** Confirm whether supported packaged versions can accept externally created queue FDs. If not, Flux should own routes and observation while Sing-Box owns the TUN FD.
3. **Bundled nft userspace.** Evaluate bionic build, transitive libraries, size, license notices, and compatibility. If the cost is excessive, prioritize the narrow native encoder while retaining xtables fallback.
4. **nft TPROXY expression encoding.** The future native encoder needs kernel-version and family conformance tests, not only serialization unit tests.
5. **eBPF verifier variance.** Vendor 5.10 trees may contain backports or older verifier limits. Baseline objects must be tested on real devices and stay intentionally conservative.
6. **BTF availability.** GKI expectations are not enough; capability reports need to show the exact BTF source and object that loaded.
7. **SELinux domains.** Installation frameworks may launch the same binary under different domains. Policy denial must lead to a clean fallback, not advice to disable enforcement.
8. **Privilege separation timing.** Splitting a broker before interfaces stabilize could add more failure modes than security value. Design the typed protocol now; implement it after the single-owner reconciler is reliable.
9. **TUN performance ownership.** Engine-owned multiqueue/offloads require version-qualified Sing-Box evidence; direct multiqueue, offloads, and `io_uring` additionally require `FluxOwnedTunFd`. They can increase throughput but also power draw and complexity, so they need release-device benchmarks, not desktop assumptions.
10. **Foreign attachment discovery.** TC/XDP/cgroup coexistence APIs and permissions vary. If Flux cannot prove non-destructive attachment, it must leave the hook unused.

## Final technical position

The production correctness stack should be:

```text
preferred:  nftables TPROXY + rtnetlink PBR
fallback:   coherent xtables TPROXY + generation-specific ipsets + stable-jump cutover
fallback:   coherent xtables TPROXY + bounded jump tree
alternate:  managed Sing-Box TUN + fluxd-owned route lifecycle
optional:   `xt_bpf` observation then proxy-positive acceleration; TUN TC observation; later per-domain mark/cache experiments; TUN steering only with future FluxOwnedTunFd
baseline I/O: epoll
optional I/O: io_uring only with future FluxOwnedTunFd plus live TUN probe and benchmark
```

This design uses advanced Rust and kernel facilities where they deepen the module: ownership/typestate around kernel transactions, zero-copy bounded decoding, one-writer concurrency, direct rtnetlink and TUN UAPI, atomic nft/ipset generations, and optional eBPF map/program lifecycles. It avoids making a 5.10 device depend on features introduced in 6.4 or 6.6, and it avoids treating root, a kernel config, a command on `PATH`, or a UAPI constant as proof that a feature is usable.

## Primary sources

1. Flux repository baseline at `c978b75d879a9d155e46197dd86bf7cd9dc1b519`: local [`addrsyncd`](../../addrsyncd), [`scripts`](../../scripts), and [`README.md`](../../README.md).
2. Linux v5.10 BPF UAPI, program/map types, commands, and test-run API: [include/uapi/linux/bpf.h](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/bpf.h).
3. Linux v5.10 verifier access rules for networking program contexts, including skb mark access: [net/core/filter.c](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/net/core/filter.c).
4. Linux v5.10 BPF ring-buffer design and ordering/polling model: [Documentation/bpf/ringbuf.rst](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/bpf/ringbuf.rst).
5. Linux v5.10 `sk_lookup` program semantics and socket coverage: [Documentation/bpf/prog_sk_lookup.rst](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/bpf/prog_sk_lookup.rst).
6. Linux v5.10 TUN/TAP creation and multiqueue documentation: [Documentation/networking/tuntap.rst](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/networking/tuntap.rst).
7. Linux v5.10 TUN implementation, queue selection, eBPF, and offload behavior: [drivers/net/tun.c](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/drivers/net/tun.c).
8. Linux v5.10 TUN UAPI flags and ioctls: [include/uapi/linux/if_tun.h](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/if_tun.h).
9. Linux v5.10 transparent proxy documentation: [Documentation/networking/tproxy.rst](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/networking/tproxy.rst).
10. Linux v5.10 capability definitions for `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_PERFMON`, and `CAP_BPF`: [include/uapi/linux/capability.h](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/capability.h).
11. Linux v5.10 seccomp filter semantics, architecture checks, and `no_new_privs`: [Documentation/userspace-api/seccomp_filter.rst](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/Documentation/userspace-api/seccomp_filter.rst).
12. Aya's Rust implementation and no-libbpf/BCC positioning: [Aya README at `2f09011`](https://github.com/aya-rs/aya/blob/2f09011af04527218f744e79ed1e8edc85e1972c/README.md).
13. Aya runtime program/map/helper probes: [aya/src/sys/feature_probe.rs](https://github.com/aya-rs/aya/blob/2f09011af04527218f744e79ed1e8edc85e1972c/aya/src/sys/feature_probe.rs).
14. Aya TC attach implementation and version-based TCX selection (Flux supplies explicit legacy retry): [aya/src/programs/tc.rs](https://github.com/aya-rs/aya/blob/2f09011af04527218f744e79ed1e8edc85e1972c/aya/src/programs/tc.rs).
15. libbpf CO-RE and application model: [docs/libbpf_overview.rst](https://github.com/libbpf/libbpf/blob/34e3ebf0f062cf81882c51ac95dce720101ca5cc/docs/libbpf_overview.rst).
16. libbpf build prerequisites and native dependencies: [libbpf README](https://github.com/libbpf/libbpf/blob/34e3ebf0f062cf81882c51ac95dce720101ca5cc/README.md).
17. libbpf-rs static/vendored feature surface: [libbpf-rs/Cargo.toml](https://github.com/libbpf/libbpf-rs/blob/db7d45732a9309adb4854f371dcd6904fe4ed0c2/libbpf-rs/Cargo.toml).
18. libbpf-rs netfilter example: [examples/netfilter_blocklist](https://github.com/libbpf/libbpf-rs/tree/db7d45732a9309adb4854f371dcd6904fe4ed0c2/examples/netfilter_blocklist).
19. Audited netfilter packet crate surface: [netlink-packet-netfilter `src`](https://github.com/rust-netlink/netlink-packet-netfilter/tree/591a4b228faa6b4e629abccfc12597f1baf6bd78/src).
20. Rust nft JSON model/process adapter: [nftables-rs at `ca4b9cf`](https://github.com/namib-project/nftables-rs/tree/ca4b9cf81d6e8719e7d511dc64b97a35439087ac).
21. Mullvad libnftnl Rust wrapper: [nftnl-rs at `e4b18e5`](https://github.com/mullvad/nftnl-rs/tree/e4b18e5355208f19e396d47ddca8f2fb3659e71c).
22. Pure-Rust nftnl project's support warning and scope: [nftnl-rs README at `d98b5e8`](https://codeberg.org/4neko/nftnl-rs/src/commit/d98b5e8d719ffe32fbd22cf422911612fbb966cd/README.md).
23. Official nftables userspace source at 1.1.6: [nftables tree](https://git.netfilter.org/nftables/tree/?id=8d97995b030fb48a1cd2bd5f1a7c5bd18303c76e).
24. Official libnftables JSON schema: [doc/libnftables-json.adoc](https://git.netfilter.org/nftables/tree/doc/libnftables-json.adoc?id=8d97995b030fb48a1cd2bd5f1a7c5bd18303c76e).
25. nftables project documentation for atomic ruleset replacement: [Atomic rule replacement](https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement).
26. Official ipset 7.24 source: [ipset tree](https://git.netfilter.org/ipset/tree/?id=5c1debb08873ba6d56c073f34e4b09cd9c56e5d5).
27. ipset kernel/userspace protocol and commands: [include/libipset/linux_ip_set.h](https://git.netfilter.org/ipset/tree/include/libipset/linux_ip_set.h?id=5c1debb08873ba6d56c073f34e4b09cd9c56e5d5).
28. Rust rtnetlink implementation: [rtnetlink at `e7799b6`](https://github.com/rust-netlink/rtnetlink/tree/e7799b6ee24267586e6aadc0e3fb415b4d921dd4).
29. `tun` crate Android backend requiring a supplied raw FD: [src/platform/android/device.rs](https://github.com/meh/rust-tun/blob/b1bd15829836f483e6813af2ee14e7a37f3afb28/src/platform/android/device.rs).
30. Rust `io-uring` implementation and runtime probe API: [tokio-rs/io-uring at `a52c1c0`](https://github.com/tokio-rs/io-uring/tree/a52c1c07ffa7ab64750fd6a39f2f0a922f205815).
31. Linux v5.10 io_uring UAPI and implementation: [include/uapi/linux/io_uring.h](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/include/uapi/linux/io_uring.h) and [fs/io_uring.c](https://github.com/torvalds/linux/blob/2c85ebc57b3e1817b6ce1a6b703928e113a90442/fs/io_uring.c).
32. Rust platform support for Android targets: [Rust Android platform support](https://doc.rust-lang.org/rustc/platform-support/android.html).
33. Android NDK ABI definitions: [Android ABIs](https://developer.android.com/ndk/guides/abis).
34. Android SELinux architecture and enforcing model: [Android SELinux documentation](https://source.android.com/docs/security/features/selinux).
35. Linux netlink reliability and `ENOBUFS`: [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html).
36. Upstream introduction of BPF netfilter program type: [Linux commit `84601d6ee68a`](https://github.com/torvalds/linux/commit/84601d6ee68ae820dec97450934797046d62db4b).
37. BPF UAPI boundary for netfilter program type: [Linux v6.3 `bpf.h`](https://raw.githubusercontent.com/torvalds/linux/v6.3/include/uapi/linux/bpf.h) and [Linux v6.4 `bpf.h`](https://raw.githubusercontent.com/torvalds/linux/v6.4/include/uapi/linux/bpf.h).
38. TCX introduction and UAPI boundary: [Linux commit `e420bed02507`](https://github.com/torvalds/linux/commit/e420bed02507), [v6.5 `bpf.h`](https://raw.githubusercontent.com/torvalds/linux/v6.5/include/uapi/linux/bpf.h), and [v6.6 `bpf.h`](https://raw.githubusercontent.com/torvalds/linux/v6.6/include/uapi/linux/bpf.h).
39. Upstream BPF memory-accounting change after the 5.10 baseline: [Linux commit `d5299b67dd59`](https://github.com/torvalds/linux/commit/d5299b67dd59445902cd30cbc60a03c869cf1adb).
