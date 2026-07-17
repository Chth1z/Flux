---
status: accepted
decision_date: 2026-07-15
last_reviewed: 2026-07-17
---

# Qualify local OUTPUT through loopback-reinjected PREROUTING TPROXY

Flux selects the conventional Linux two-hook path as the first local-OUTPUT qualification
candidate:

```text
reviewed local OUTPUT selector
  -> masked packet mark in mangle/OUTPUT
  -> output-route recomputation
  -> Flux-owned RPDB rule and local default route through loopback
  -> mark-qualified, loopback-reachable mangle/PREROUTING TPROXY
  -> exact Generation transparent TCP/UDP listener
```

This is one transaction. An OUTPUT `MARK` rule, route lookup, counter, or absence of peer traffic is
not capture evidence by itself. The PREROUTING half must match the reviewed Flux mark on `lo` before
any generic loopback bypass, select the exact TPROXY port, and deliver TCP and UDP without
NAT-rewriting the packet destination tuple. The Proxy Engine's upstream sockets must use an
independently authorized bypass identity so their responses and outbound connections cannot recurse
through the capture path.

Linux 5.10 source establishes why the candidate is viable: xtables mangle/OUTPUT recomputes the
route after a relevant mark change; an RPDB-selected `RTN_LOCAL` route resolves to loopback;
loopback transmission re-enters receive processing; and IPv4/IPv6 receive processing invokes
PRE_ROUTING. The earlier negative development observation is therefore arrangement-specific, not a
kernel-wide impossibility result. The checked-in ingress harness does not exercise local OUTPUT,
and a PREROUTING selector tied to a veth/tether interface cannot see loopback reinjection.

Canonical xtables lowering now represents this dependency shape without authorizing it. Forwarded-
only input preserves the exact schema-v1 bytes, `FLX{4|6}F{generation:010}` names, accounting, and
digests. Any local-OUTPUT input selects schema v2. Its `FLX{4|6}O{generation:010}` private chain is
a MARK-only classifier reached by typed `OUTPUT` selector `mark 0/mask`; when proxy traffic exists,
`FLX{4|6}P{generation:010}` is a separate TCP/UDP TPROXY chain reached by typed `PREROUTING`
selector `-i lo` plus `mark proxy/mask`. A mixed family keeps the unchanged `F` forwarded role.
The private restore artifacts declare/fill and flush/delete those chains only; they never mutate a
built-in hook.

Schema v2 also records the exact caller-selected per-family RPDB priority, route table, explicit
nonzero route metric, nonzero route and rule protocols, proxy mark/mask, and loopback identity. Its
local `/0` route is `RTN_LOCAL` with IPv4 `HOST` scope or IPv6 `UNIVERSE` scope. It also records the
unspecified-address transparent listener family, port, and protocol set and the compatibility engine
credentials plus bypass mark/mask required for loop escape. These are typed descriptive
requirements, not Android-safe allocation, readiness, lease, or ownership evidence. The lifecycle metadata prepares private
`O`, `P`, and optional `F` objects plus listener, routing, and escape, then orders attachment as `P`,
optional `F`, and `O` last. Retirement orders detachment as `O`, optional `F`, and `P`, followed by
escape, routing, listener, and private-object retirement.

The production functional-canary driver remains fail-closed and returns `Unsupported` before
mutation. The delivered private owner now supplies stable-hook activation, restore/rtnetlink
mutation, exact readback, rollback, cleanup proof, crash recovery, and the transition lease for an
independently admitted target. Canonical lowering alone still supplies none of those authorities,
and production composition supplies neither target admission nor receipt and Android release
qualification. A disposable privileged Linux checkpoint is supporting evidence only; it cannot
construct production gate evidence or qualify any production Android device profile.
Established-flow caching, transparent-socket DIVERT, FakeIP ICMP, QUIC rejection, and MSS clamping
remain independently unsupported extensions and are not part of this first canonical transaction.

A second development-only lane now cross-builds that exact ignored Rust checkpoint for
`x86_64-linux-android` and runs it on one explicit rooted ADB serial:

```text
cargo xtask test-functional-canary-android-x86_64-output-tproxy --serial SERIAL
```

On 2026-07-15 it passed on WSA 2407.40000.4.0, Android 13 / SDK 33, with Magisk 30.6,
SELinux enforcing, legacy iptables 1.8.7, and kernel
`5.15.104-windows-subsystem-for-android-20230927+`. The Android branch uses real UID 0 plus an
exact live-parent PID and changed mount/network namespace proof because that kernel exposes no user
namespace procfs. It also demonstrates that Android may replace a pre-connect socket mark with its
own network-selection value; the checkpoint therefore uses the disposable masked field
`0x00600000`, merges proxy `0x00200000` or bypass `0x00400000`, and proves every outside Android bit
is preserved. This is test-only mechanism evidence, not a production mark allocation.

The WSA lane also records bounded userspace differences: its old `ip` omits JSON for route/rule
commands and cannot encode a rule-protocol attribute, built-in xtables facilities require
`/proc/config.gz` evidence instead of `/sys/module`, per-namespace built-in table initialization may
add only `mangle` to the otherwise preserved registration baseline (the observed WSA baseline was
empty), an intentional UDP drop may return `EPERM`, and fresh-loopback initialization has a
namespace-local inactive-qdisc normalization before the namespace is retired. The runner forces
required mode, selects the exact test, uses a private
`/data/local/tmp` directory, binds fingerprint plus boot ID across the build and cleanup boundaries,
bounds every host command with kill/reap handling, and independently proves removal. This is useful
Android mechanism evidence, but that earlier traffic-canary run is not Android 5.10/ARM64,
distinct-UID, Generation, supervised-engine, VPN/netd-coexistence, owner crash recovery, or release
qualification. The later native-owner run recorded below separately exercises active-journal
recovery without adding traffic or production authority.

Qualification requires all of the following under one boot, network namespace, mark allocation,
and attempt identity:

- coherent IPv4/IPv6 xtables support already built in or active, with no implicit module autoload;
- foreign-state refusal for every chain, rule priority, route table, mark/mask, listener, and hook;
- PREROUTING preparation before OUTPUT activation, and OUTPUT detachment before listener teardown;
- exact masked-mark and route readback plus positive OUTPUT, early-loopback, TPROXY, delivery, and
  loop-escape counters;
- IPv4 and IPv6 TCP accept plus UDP original-destination delivery on the exact transparent listener;
- unmarked, safe-miss, unrelated-ingress, and bypass-mark negative controls;
- successful replies without peer leakage or proxy recapture;
- exact inverse cleanup and byte-equivalent restoration of the observed xtables, RPDB, and route
  baselines;
- repetition on reviewed Android device profiles, including mark authority, RPDB ordering, VPN and
  explicit-network coexistence, SELinux, userspace extension, boot, and namespace evidence.

The frozen shell source-shape oracle is historical behavior, not canonical authority for this
mechanism. Its generic selector path reaches an unconditional loopback bypass after an optional
connmark-qualified fast path. That related historical variant does not define or qualify the
required packet-mark-qualified loopback transaction. ADR-0010 continues to protect single-writer
rollback safety, while ADR-0011 permits the Rust compiler to intentionally diverge after executable
qualification instead of preserving a historical variant solely for compatibility.

If conventional TPROXY is unavailable on an exact device, loopback TC ingress with
`bpf_sk_assign()` may be investigated as a separate capability-gated experiment after this canary.
Network-namespace `sk_lookup` remains a secondary lab mechanism because routing must already be
local and its Linux 5.10 context lacks the Flux mark and ingress identity. Cgroup destination
rewriting does not satisfy transparent destination semantics. ADR-0009 continues to prohibit
production `.ko`/KPM packaging, loading, or unloading.

The primary-source analysis and mechanism comparison are recorded in
[`local-output-capture-mechanisms-2026-07.md`](../research/local-output-capture-mechanisms-2026-07.md).

## 2026-07-17 native transaction status

The conventional mechanism is now consumed by a complete private native transaction owner. It
prepares the generation-specific `P`/optional-`F`/`O` chains, installs stable
`FLX{4|6}SP` PREROUTING roots before `FLX{4|6}SO` OUTPUT activation, creates the exact local route
before the fwmark rule, performs full save plus rtnetlink readback, and reverses the transaction as
OUTPUT detach, rule delete, route delete, remaining-root detach, then private-chain retirement.
Replacement keeps the built-in jumps stable and atomically rebinds the durable Generation journal
without releasing the component lease.

Owner-payload schema 2 binds the target and optional previous Generation to artifact/tool digests and
a domain-separated digest of the complete IPv4/IPv6 routing audit, including the exact loopback
name/index identity. The real Adapter proves that live identity in both directions before every
route/rule observation or mutation. Both xtables families and both routing audit identities are read
before `Active` or `CleanAbsent`; any opposite-family residue blocks publication rather than being
ignored because a family is absent from the target.

Current terminal-journal recovery retains the native guard, shared writer fence, and optional lease
through a fresh global IPv4/IPv6 xtables plus policy absence proof, then retires the terminal
artifacts. The exact previous-boot revision-1 `Activating` `JournalDurable`/`JournalBeforeLease`
boundary is also recoverable when its native-owner scope matches the journal; same-boot or mismatched
missing-lease state remains fail-closed.

Shell-owner v2 retains parent plus optional child PID/start identities and boot ID. Either live
participant blocks. One serialized parent-bound mutating `addrsync` or `tproxy` phase child changes
only the child slot and remains blocking after parent death; a live parent may reclaim a dead child.
Both-dead, PID-reused, and previous-boot records retire only after exact revalidation. Ambient state
is discarded, release is authenticated, signals exit through cleanup, and bare, malformed, mixed,
and unverifiable locks remain fail-closed. Legacy start, stop, restart, and failure cleanup hold the
same fence before `addrsync` or `tproxy` mutation; the standalone daemon remains a later cutover duty.

The same real process/netlink Adapter passed apply, active-journal recovery, stop, and exact absence
in a rooted disposable WSA Android 13 x86_64 namespace. That run also established two bounded legacy
readback normalizations: a zero-byte full save in a never-initialized namespace means exact empty
state, and kernel-emitted default TPROXY `--on-ip 0.0.0.0`/`::` is equivalent to the canonical
omission. Nonempty missing-mangle output and nondefault `--on-ip` remain conflicts.

Production remains `Unsupported`: this mechanism test does not supply Android 5.10/ARM64 mark
authority, RPDB/VPN/netd coexistence, distinct engine identity, functional receipts, or release
qualification, and it does not authorize shell-duty removal before the item-3 cutover gate. eBPF
remains an optional separately qualified mechanism, and production loads no `.ko`/KPM payload.
