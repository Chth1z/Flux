---
status: accepted
decision_date: 2026-07-15
last_reviewed: 2026-07-16
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

The current schema-v1 lowerer and production functional-canary driver remain fail-closed. They do
not model, own, or authorize the complete mark, RPDB rule, local route, loopback PREROUTING rule,
listener, escape, activation, and cleanup transaction. A disposable privileged Linux checkpoint is
supporting evidence only; it cannot construct production gate evidence or qualify any production
Android device profile.

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
Android mechanism evidence, but it is not Android 5.10/ARM64, distinct-UID, Generation,
supervised-engine, VPN/netd-coexistence, crash-recovery, or release qualification.

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
