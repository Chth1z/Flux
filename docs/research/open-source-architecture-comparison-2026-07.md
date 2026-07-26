# Open-source architecture comparison for the Rust `fluxd` cutover

- Status: decision-support research note
- Repository state reviewed: `d4b08be1898d42e36b435a6416c35e1be0bc1715`
- External sources accessed: 2026-07-22
- Scope: architecture and sequencing for the shortest safe path to one Rust-owned `fluxd`

This note is evidence for the current roadmap, not a replacement for it. The release gate remains
[ADR-0011](../adr/0011-pre-release-rust-only-release-gate.md), and the authoritative execution order
remains the [implementation roadmap](../architecture/implementation-roadmap.md).

The labels **Fact**, **Inference**, and **Recommendation** are used deliberately. A fact is directly
supported by the cited source. An inference combines sources or applies them to Flux. A
recommendation is a proposed project decision.

## Conclusion

**Recommendation:** productionize the existing Rust `NativeXtablesOwner` first. Do not delay Rust
ownership while building a native nftables backend. In the first supported release, one `fluxd`
should own reconciliation, address-derived policy, RPDB/routes, xtables capture, recovery,
subscriptions/configuration, and Sing-Box supervision. Sing-Box remains an external Go engine, and
Android's descriptor-pinned `iptables`/`ip6tables` restore/save programs may remain platform
adapters. "Rust-owned" means one Rust process holds planning and mutation authority; it does not
mean reimplementing every platform utility or the proxy protocol engine in Rust.

**Fact:** nftables can atomically replace an nft ruleset in one batch, but that transaction does not
include RPDB rules, routes, address inventory, engine listener readiness, child-process identity, or
publication of Flux's durable active Generation. Legacy xtables restore commits per table, and
`iproute2` operations are also outside an nft transaction. [S-NFT-ATOMIC] [S-IPT-LEGACY]
[S-IPT-NFT]

**Inference:** nftables reduces one failure window; it does not remove Flux's need for staged
activation, exact readback, durable compensation, crash recovery, or attach-last/detach-first
ordering. Those are already the strongest parts of the Rust xtables owner. Waiting for nftables
would preserve the current Shell writer and standalone `addrsyncd` longer without eliminating the
cross-subsystem transaction problem.

**Recommendation:** freeze optional backend work until one narrowly defined Android 5.10/ARM64
profile passes the complete Rust xtables transaction and the old networking runtime is deleted.
Native nftables, TUN expansion, and eBPF are post-cutover capabilities, not prerequisites for Rust
unification.

## Method and source limits

The comparison used official repositories, source files, kernel/AOSP documentation, and exact Git
refs. GitHub's REST API was rate-limited during the review, so current status was cross-checked with
Git refs, release redirects, Atom feeds, raw files, and shallow checkouts. The observed heads below
are evidence snapshots, not floating dependency recommendations.

| Project | Ref inspected | Last observed activity | Role in this comparison |
|---|---:|---:|---|
| Sing-Box | `e013b424fc9ea8254d79fa9622903eb06689f7d6` (`testing`) | 2026-07-22 | External engine lifecycle and control surface |
| Sing-Tun | `8cededca4cc1ab55c8b2979c009e54fbb51a56c2` (`dev`) | 2026-07-22 | TUN/redirect and platform routing behavior |
| mihomo | `978d25ae859661c11796facf09a40957753f0a04` (`Alpha`) | 2026-07-22 | Rich live control and unsafe built-in TPROXY precedent |
| dae | `09c6c8cadda8250fb5bc85d4b40510a9544b6235` | 2026-07-17 | Staged reload, policy IR, and eBPF boundary |
| Netavark | `77bdd21ed358aa64228e2d900ade2a061ff5f381` | 2026-07-20 | Rust networking controller and compensation |
| NetProxy-Magisk | `24dfb96c5f2fa4ec89f98e282aae6bfa9cfc1074` | 2026-07-19 | Current Android root feature coverage and `xt_bpf` |
| AndroidTProxyShell | `4b6ddd8779651a9a8316c96c04a79c7fb2157c64` | 2026-07-19 | Android TPROXY compatibility behavior |
| MagicNet | `7df0bdcd484a509fdc22d4cc93819c950dc3f43e` | 2026-07-21 | One-engine product direction and control-plane ergonomics |
| Box4Magisk | `1aabf31ad837b6ebff11d46fda585f63230de9f8` | 2026-04-10 | Broad rooted-Android mode/ROM coverage |

**Uncertainty:** upstream Linux and AOSP sources cannot prove an OEM device's kernel configuration,
backports, SELinux policy, xtables backend/lock behavior, netd modifications, mark writers, or VPN
rules. Every production admission remains device-artifact-specific and operation-probed.

## Flux design interpreted against the comparators

### What the current design gets right

**Fact:** Flux's target architecture assigns one Rust `fluxd` all administrative intent,
Generation reconciliation, capture and routing ownership, recovery, address synchronization,
subscriptions, and Sing-Box supervision. Sing-Box stays an external engine. The current release
policy permits omitting native nftables, managed TUN, and eBPF from the first Rust-only release.
[L-DOCS] [L-ADR-0001] [L-ADR-0011]

**Inference:** this boundary is stronger than the surveyed Android root modules and proxy engines:

- immutable Generation artifacts make intent and rollback targets explicit;
- one serialized writer plus a durable journal/lease prevents two controllers from assuming
  authority over the same kernel objects;
- exact readback and compensation handle failure across netfilter and routing, where no single
  kernel transaction exists;
- attach-last and detach-first ordering keeps a ready engine behind capture and removes capture
  before terminating the engine;
- capability probes and device-qualified mark/RPDB planning acknowledge Android vendor variance;
- the private control socket avoids making a dashboard-compatible HTTP API the authority boundary.

Sing-Box, dae, and Netavark each demonstrate parts of this model, but none provides the complete
Android shared-root-namespace ownership and crash-recovery contract that Flux is building.

### Where the design is currently weak

**Fact:** the bounded native xtables owner exists and has host/WSA mechanism evidence, but production
target admission is intentionally uninhabited. Shell is still the production networking writer,
and standalone `addrsyncd` still owns dynamic address reconciliation. The native owner cannot
coexist with either writer. [L-ROADMAP]

**Inference:** the project has accumulated more proof infrastructure than executable product
surface. The safety model is valuable, but four conditions now create schedule risk:

1. the intended one-process architecture still has two legacy runtime ownership islands;
2. optional nftables, eBPF, TUN, and broad policy-model work can distract from inhabiting one
   complete production target;
3. a large number of non-authorizing evidence types can grow without bringing the first device
   closer to activation;
4. compatibility bridge schemas have little release value because ADR-0011 forbids releasing the
   bridge state.

**Recommendation:** retain the safety invariants but narrow their first inhabitant. Support one or
two named ARM64/API 31+/Linux 5.10+ device profiles first. A bounded, reviewed admission catalog is
preferable to another general backend abstraction before cutover.

## Comparator matrix

| Comparator | Strong evidence to reuse | Boundary or weakness | Flux decision |
|---|---|---|---|
| Sing-Box / Sing-Tun | Typed engine configuration, ordered internal start/close, Android package/UID models, mature protocol engine | CLI `SIGHUP` closes the active instance before replacement; Clash `PUT /configs` is a no-op and `PATCH` is narrow; engine-managed routes would create a second networking owner | Keep external and pinned; `fluxd` owns prepare, readiness, swap, rollback, and networking |
| mihomo | Rich policy/config model and in-process listener reconfiguration | Built-in TPROXY uses sequential command strings, fixed mark/table `0x2d0`, IPv4-only route commands, sysctl mutation, and best-effort errors | Use only as API/policy precedent; reject its host-network mutation model |
| dae | Prepared replacement, handoff, bounded old-generation drain, normalized policy concepts | Linux 5.17+/BTF/cgroup/TC assumptions and AGPL-3.0; not an Android 5.10 baseline | Reimplement lifecycle ideas; defer its eBPF datapath |
| Netavark | Typed JSON input, validate-before-mutate, ordered setup, compensation, state lock, Rust netlink, nft batches | One-shot Podman/netns model; teardown compensation is best effort and does not solve daemon crash recovery in Android's shared namespace | Closest Rust controller precedent; preserve Flux's stronger journal/readback model |
| Box4Magisk / AndroidTProxyShell | Wide Android ROM, UID, DNS, hotspot, TPROXY/REDIRECT/TUN compatibility knowledge | Shell/PID/config-snapshot lifecycle, fixed global IDs, sequential mutation, capability inference, vendor-chain side effects | Convert scenarios to fixtures/device tests; do not copy runtime ownership |
| NetProxy-Magisk | Current sing-box-only feature coverage and optional positive `xt_bpf` matcher | Opaque/prebuilt matcher and optional kernel-module payloads, Shell orchestration, fixed IDs, weak artifact provenance | Use as feature-discovery evidence only; reject its supply-chain model |
| MagicNet | Independently supports one-engine convergence and a local control surface | Rust-facing product still delegates substantial networking orchestration to Shell | Confirms direction, not final ownership architecture |
| AOSP netd / iptables | Real Android lock, restore, mark, RPDB, restart, and VPN semantics | Platform behavior varies by artifact and private APIs are not stable NDK contracts | Use system tools and live probes behind a profile-bound Rust adapter |

## Detailed findings

### Sing-Box is the right engine and the wrong transaction owner

**Fact:** current Sing-Box has a staged internal component lifecycle, but its CLI reload validates the
new configuration, cancels and closes the active instance, and only then reads/creates the
replacement. A failed replacement does not automatically restore the previous running instance.
[S-SB-RUN] Its Clash-compatible `PUT /configs` handler returns success without applying a
configuration, while `PATCH` changes only a small runtime subset such as mode. [S-SB-CONFIG]

**Fact:** current TUN documentation says `auto_redirect` works on Android only as simple IPv4 TCP
forwarding because nftables and ip6tables are not assumed; hotspot/repeater sharing is delegated to
VPNHotspot. It also states that `auto_redirect` conflicts with routing marks. [S-SB-TUN]

**Inference:** Sing-Tun contains valuable Android/Linux routing knowledge, but delegating automatic
route/firewall mutation to it would create an unjournaled second writer and weaken Flux's
Generation boundary. The correct engine contract is: `fluxd` renders and validates immutable local
assets, starts a pinned Sing-Box child, proves exact identity/listener readiness, owns external
capture/routing, and can restore the previous Generation.

### mihomo shows why rich APIs do not imply safe host ownership

**Fact:** the inspected `Alpha` proxy-core branch supports config parsing and live listener changes,
but its built-in TPROXY helper executes sequential command strings, uses fixed fwmark/table
`0x2d0`, configures only IPv4 routes, mutates `ip_forward`, and continues after individual command
errors. Cleanup is name-based inverse command execution. [S-MIHOMO-TPROXY] The config API applies
subsystem changes in place rather than publishing a crash-recoverable host-network Generation.
[S-MIHOMO-CONFIG]

**Fact:** the repository's default `main` branch was unrelated to the proxy core during this review;
the proxy code was verified on the exact `Alpha` ref. [S-MIHOMO]

**Recommendation:** pin exact repository, branch, commit, release artifact, and digest for every
engine input. Never resolve a product dependency from a default branch or floating GitHub asset.

### dae contributes reload semantics, not a baseline datapath

**Fact:** dae prepares replacement control-plane state, performs a staged handoff, retires the old
plane, and bounds draining/cleanup; current user documentation says reload usually preserves
connections. [S-DAE-RELOAD] Its required eBPF datapath assumes a substantially newer and more
featureful Linux environment than Flux's Android 5.10 floor. [S-DAE-DOCS]

**Inference:** Flux should adopt the lifecycle shape: prepare, validate, prove readiness, switch one
authority pointer, retain the old Generation until the new one is proven, then perform bounded
retirement. It should not adopt dae's TC/cgroup/BTF baseline or copy AGPL-3.0 code into the
controller without a specific license decision.

### Netavark is the closest Rust implementation precedent

**Fact:** Netavark parses typed JSON, constructs all network drivers, validates every driver before
mutation, applies them in order, and tears down already-applied drivers if a later setup fails.
[S-NETAVARK-SETUP] It locks access to persisted firewall state so reload cannot race state removal,
and uses Rust netlink packet types plus nftables batches. [S-NETAVARK-STATE] [S-NETAVARK-NFT]
[S-NETAVARK-CARGO]

**Inference:** this validates Flux's typed planning, ordered mutation, and compensation choices. It
does not make Netavark a reusable controller: Podman invokes it for bounded container/network
operations, while `fluxd` must survive netd restarts, network epochs, child death, and partial state
in Android's shared root namespace. Flux's exact ownership journal and recovery remain necessary.

### Android root modules are compatibility catalogs, not ownership models

**Fact:** Box4Magisk and AndroidTProxyShell cover many Android capture modes and ROM workarounds, but
their core networking paths are Shell command sequences with fixed marks/tables. Box4 supervision
also relies on process names/PID files, and its inspected networking path contains device-specific
global vendor-chain flushes. [S-BOX4] [S-ATP]

**Fact:** NetProxy-Magisk demonstrates a useful optional pattern: a pinned socket-filter program can
act as a positive `xt_bpf` matcher while conventional xtables still performs TPROXY/REDIRECT. Its
distribution also includes opaque/prebuilt matcher and optional kernel-module artifacts.
[S-NETPROXY]

**Inference:** these projects are high-value sources for device test cases, mode semantics, UID
behavior, DNS and hotspot expectations, and failure injection. They are poor sources for durable
ownership, artifact provenance, or crash recovery. Flux should translate observed behavior into
independent fixtures and probes rather than porting their Shell.

## Android and Linux constraints that change the plan

### Keep the system xtables interface for the first cutover

**Fact:** current AOSP builds `xtables-legacy-multi` and the `iptables`/`ip6tables` save/restore
symlinks. AOSP's configured xtables lock is `/system/etc/xtables.lock`, not upstream's default
`/run/xtables.lock`. netd runs long-lived restore processes with `--noflush -w -v`.
[S-AOSP-IPTABLES] [S-AOSP-XTABLES-LOCK] [S-AOSP-NETD-RESTORE]

**Inference:** invoking verified, descriptor-pinned system restore/save binaries with `-w` is the
most compatible first Rust adapter. It coordinates with the Android platform's actual userspace
contract and avoids writing a new raw xtables codec during the ownership cutover. The Rust process
must still validate executable identity, backend/version, lock behavior, output, and exact readback.

**Fact:** Linux TPROXY requires policy routing and an `IP_TRANSPARENT` listener. Native nft TPROXY
has kernel configuration requirements in addition to a version floor, so a kernel version alone is
not capability evidence. [S-LINUX-TPROXY]

### Keep only a minimal platform launcher/watchdog

**Fact:** Magisk launches module `service.sh` work through a detached process path; it does not
provide the persistent child supervision and network-state recovery required by Flux.
[S-MAGISK-SERVICE]

**Recommendation:** retain a bounded module-local launcher/watchdog, but keep policy, process
identity, restart decisions, recovery, and cleanup inside `fluxd`. The remaining Shell must not
mutate networking state.

### Treat marks, RPDB, and netd restart as one admitted profile

**Fact:** Linux evaluates lower numeric RPDB priorities first. AOSP's policy lattice uses explicit
ordered ranges for VPN, network selection, UID policy, local/default routing, and unreachable
behavior. Android's 32-bit fwmark layout assigns meanings across the word; a low-byte mask is not a
generic free namespace. [S-AOSP-ROUTE] [S-AOSP-FWMARK]

**Fact:** netd's route-controller initialization flushes nonzero-priority policy rules and rebuilds
Android-owned policy. [S-AOSP-ROUTE-CPP]

**Recommendation:** preserve the device-qualified mark/mask/RPDB authority in ADR-0013. Bind the
selected mark, mask, priorities, tables, netd artifacts, boot/namespace identity, and operation
probes into one admission profile. After netlink loss or netd restart, `fluxd` must redump and
reconcile before declaring the Generation active.

### Add an outbound VPN/network-context gate

**Fact:** AOSP's fwmark service selects implicit network context using the calling UID. Sockets
created by root-owned `fluxd` or Sing-Box do not automatically inherit an intercepted app's
per-UID VPN/network selection. AOSP has private system-proxy behavior for selecting a network on
behalf of another UID, but it is not a public NDK contract. [S-AOSP-FWMARK-SERVER]
[S-AOSP-NETD-CLIENT]

**Recommendation:** define a profile-specific egress policy for `respect_android_vpn=true` and fail
closed when it cannot be proven. Test secure, bypassable, lockdown, per-app, and work-profile VPNs,
including the accepted socket and outbound `SO_MARK`. Keep any private netd integration behind an
exact artifact adapter and a runtime probe.

### Add 16 KB ELF compatibility to release qualification

**Fact:** Android 15 supports devices with 16 KB pages. NDK r27 and earlier require explicit linker
alignment flags; NDK r28 and later align compatible builds by default. [S-ANDROID-PAGES]

**Recommendation:** retain the project's pinned toolchain unless changing it is separately justified,
but verify every packaged ELF program header has at least `2**14` LOAD alignment. This is a packaging
gate, not a reason to delay controller ownership.

## Why nftables atomicity does not justify waiting

### Facts

1. One `nft -f` batch can atomically replace the targeted nft ruleset. Separate invocations are
   separate transactions. [S-NFT-ATOMIC]
2. RPDB and route changes use rtnetlink/iproute2 and are not part of that nft batch.
3. Engine creation, listener readiness, address convergence, durable journal publication, and
   Generation handoff are userspace operations outside both nft and xtables transactions.
4. Legacy `iptables-restore` commits per table; `iptables-nft-restore` currently preserves that
   per-table behavior even though a wider nft commit is technically possible. [S-IPT-LEGACY]
   [S-IPT-NFT]
5. AOSP's baseline userspace is xtables-compatible, while native nftables capability varies by
   device and SELinux policy. [S-AOSP-IPTABLES]
6. Flux already has a bounded Rust xtables owner with journal, lease, exact readback, compensation,
   and recovery; what is missing is a production-admitted target and complete in-process inputs.
   [L-ROADMAP]

### Inference

nftables improves atomicity inside one subsystem but cannot be Flux's activation transaction. The
real transaction is a state machine with durable intent and compensation. The already-built owner
implements that higher-level boundary. Replacing its backend before cutover trades known,
device-compatible mechanics for a new adapter while leaving the hard cross-subsystem problem
unchanged.

### Recommendation

- Cut over with the existing Rust xtables/rtnetlink path on a small admitted device catalog.
- Keep rules in private Flux chains, attach stable roots last, and detach roots first.
- Use the platform xtables lock, exact save/readback, idempotent convergence, and durable recovery.
- Add one private native nft `inet` backend only after the Rust-only baseline is stable and exact
  create/use/observe/delete probes pass on a target device.
- Never overlay nft and xtables capture for the same Generation and never flush Android's global
  ruleset.

## Reusable and non-transferable lessons

| Pattern | Classification | Flux use |
|---|---|---|
| Prepared replacement plus bounded old-generation retirement | Reuse | Adopt from dae conceptually; keep Flux's durable Generation record |
| Typed validate-before-mutate input | Reuse | Preserve from Flux and Netavark |
| Ordered setup with compensation | Reuse and strengthen | Require exact readback and durable crash recovery, not only best-effort teardown |
| Engine as external, pinned worker | Reuse | Keep Sing-Box outside the trust/transaction boundary |
| Rich Clash-compatible diagnostics | Reuse narrowly | Read-only/operational compatibility, never planning authority |
| Android module ROM/mode knowledge | Reuse as tests | Convert to fixtures, device profiles, and failure scenarios |
| Fixed global marks/tables/priorities | Reject | Allocate only from fresh, profile-bound authority |
| Shell command strings as transaction log | Reject | Use typed desired state, journal, query, and converge |
| PID/name/socket-presence readiness | Reject | Bind child identity and prove the exact listener/capture path |
| Engine-owned automatic route/firewall changes | Reject in xtables mode | Prevent a second writer; allow only in a separately qualified TUN ownership mode |
| Opaque matcher/kernel-module bundles | Reject | Preserve reproducible provenance and ADR-0009 |
| dae-style required eBPF datapath | Defer | Linux 5.17+/BTF/TC/cgroup assumptions do not fit Android 5.10 |
| Native nftables | Defer, then add | Useful atomic backend after exact device capability and coexistence probes |

## Revised shortest-path work order

### P0: finish Rust ownership now

1. **Freeze the first release target.** Name one or two physical ARM64, API 31+, Linux 5.10+
   profiles. Freeze optional nftables, TUN, eBPF, updater UX, and broad OEM work.
2. **Finish one canonical target object.** Bind engine identity/listener, device and artifact identity,
   mark/mask, RPDB priorities/tables, routes, loopback identity, address-derived policy, namespace,
   netd epoch, VPN egress policy, and exact capability receipts.
3. **Move address synchronization into `fluxd`.** Complete initial dump before readiness, handle
   loss/redump and netd restart, and reconcile address-derived rules through the same Generation
   queue. Do not preserve standalone `addrsyncd` as an internal compatibility service.
4. **Admit the existing native owner.** Use verified system xtables restore/save descriptors with
   the Android lock and `-w`; retain Rust rtnetlink, journal, exact readback, rollback, and cleanup.
5. **Qualify one complete transaction on physical devices.** Cover local and forwarded TCP/UDP,
   IPv4/IPv6, DNS, hotspot, mark preservation, VPN modes, network churn, netd restart, engine death,
   daemon death at each mutation boundary, reboot recovery, and exact cleanup.
6. **Perform one atomic ownership handoff.** Stop standalone address sync and every Shell networking
   writer, acquire the transition lease, make the first Rust mutation, and never permit a
   dual-writer interval.
7. **Delete replaced runtime duties in the same milestone.** Remove Shell rule generation/restore,
   route/address policy, dispatcher policy, `addrsyncd`, and `jq`/AWK runtime generation. Retain only
   installation, boot launch/watchdog, disable, and uninstall glue with no networking decisions.
8. **Pass the Rust-only release gate.** Include artifact hashes/provenance, SBOM/license checks,
   reproducible ARM64 packaging, and 16 KB ELF alignment alongside the runtime tests.

### P1: simplify after cutover

9. Delete obsolete bridge schemas, public compatibility seams, and test-only production admission
   bypasses that no longer protect a shipped path.
10. Add a private native nftables `inet` backend behind exact operation probes and the same owner
    contract. Do not change policy semantics or run it beside xtables.
11. Expand the admitted device catalog only from captured evidence and repeatable qualification,
    not kernel-version heuristics.

### P2: optional capabilities

12. Evaluate TUN as a separately owned mode only after one routing owner passes forced-death and
    cleanup canaries.
13. Evaluate `xt_bpf` as observation and then proxy-positive acceleration while the full classic
    classifier remains authoritative.
14. Revisit direct nf_tables libraries, broader eBPF/TC paths, and removal of the xtables adapter
    only after they reduce measured product risk or cost.

## License, provenance, and maintenance risks

**Fact:** Sing-Box is GPL-3.0-or-later with an additional project-name/association term;
AndroidTProxyShell, Box4Magisk, and NetProxy-Magisk are GPL-3.0; dae is AGPL-3.0; Netavark is
Apache-2.0; MagicNet is MIT. [S-SB-LICENSE] [S-ATP-LICENSE] [S-BOX4-LICENSE]
[S-NETPROXY-LICENSE] [S-DAE-LICENSE] [S-NETAVARK-CARGO] [S-MAGICNET-LICENSE]

**Recommendation:** treat comparator implementations as behavioral evidence unless a deliberate
license/provenance review approves code reuse. Preserve notices and exact source pins for all
copied material. Do not ship floating GitHub downloads, opaque eBPF matchers, optional `.ko`
collections, or engine self-update paths. Flux should validate a pinned candidate and retain a
known-good previous artifact; publication should remain an external, signed/digested packaging
operation.

Maintenance activity is not architecture quality. The active Android peers demonstrate user demand
and compatibility breadth, but their recent commits do not compensate for weak ownership or
recovery. Conversely, AOSP and kernel sources define reference behavior but cannot substitute for
OEM-device qualification.

## Source index

All external sources below were accessed on 2026-07-22.

### Local authority

- [L-DOCS] [Documentation authority and reading order](../README.md)
- [L-ROADMAP] [Fluxd rewrite implementation roadmap](../architecture/implementation-roadmap.md)
- [L-ADR-0001] [ADR-0001: one `fluxd` with external Sing-Box](../adr/0001-one-fluxd-with-external-sing-box.md)
- [L-ADR-0011] [ADR-0011: Rust-only release gate](../adr/0011-pre-release-rust-only-release-gate.md)

### Proxy engines and controllers

- [S-SB] [Sing-Box source at `e013b424`](https://github.com/SagerNet/sing-box/tree/e013b424fc9ea8254d79fa9622903eb06689f7d6)
- [S-SB-RUN] [Sing-Box CLI run/reload lifecycle](https://github.com/SagerNet/sing-box/blob/e013b424fc9ea8254d79fa9622903eb06689f7d6/cmd/sing-box/cmd_run.go)
- [S-SB-CONFIG] [Sing-Box Clash config handlers](https://github.com/SagerNet/sing-box/blob/e013b424fc9ea8254d79fa9622903eb06689f7d6/experimental/clashapi/configs.go)
- [S-SB-TUN] [Sing-Box TUN and Android `auto_redirect` documentation](https://github.com/SagerNet/sing-box/blob/e013b424fc9ea8254d79fa9622903eb06689f7d6/docs/configuration/inbound/tun.md)
- [S-SB-LICENSE] [Sing-Box license](https://github.com/SagerNet/sing-box/blob/e013b424fc9ea8254d79fa9622903eb06689f7d6/LICENSE)
- [S-ST] [Sing-Tun source at `8cededca`](https://github.com/SagerNet/sing-tun/tree/8cededca4cc1ab55c8b2979c009e54fbb51a56c2)
- [S-MIHOMO] [mihomo proxy core, exact `Alpha` ref](https://github.com/MetaCubeX/mihomo/tree/978d25ae859661c11796facf09a40957753f0a04)
- [S-MIHOMO-TPROXY] [mihomo built-in TPROXY commands](https://github.com/MetaCubeX/mihomo/blob/978d25ae859661c11796facf09a40957753f0a04/listener/tproxy/tproxy_iptables.go)
- [S-MIHOMO-CONFIG] [mihomo config control surface](https://github.com/MetaCubeX/mihomo/blob/978d25ae859661c11796facf09a40957753f0a04/hub/route/configs.go)
- [S-DAE] [dae source at `09c6c8ca`](https://github.com/daeuniverse/dae/tree/09c6c8cadda8250fb5bc85d4b40510a9544b6235)
- [S-DAE-RELOAD] [dae staged reload manager](https://github.com/daeuniverse/dae/blob/09c6c8cadda8250fb5bc85d4b40510a9544b6235/cmd/reload_manager.go)
- [S-DAE-DOCS] [dae requirements and architecture](https://github.com/daeuniverse/dae/blob/09c6c8cadda8250fb5bc85d4b40510a9544b6235/docs/en/README.md)
- [S-DAE-LICENSE] [dae AGPL-3.0 license](https://github.com/daeuniverse/dae/blob/09c6c8cadda8250fb5bc85d4b40510a9544b6235/LICENSE)
- [S-NETAVARK] [Netavark source at `77bdd21e`](https://github.com/containers/netavark/tree/77bdd21ed358aa64228e2d900ade2a061ff5f381)
- [S-NETAVARK-SETUP] [Netavark validation and setup compensation](https://github.com/containers/netavark/blob/77bdd21ed358aa64228e2d900ade2a061ff5f381/src/commands/setup.rs)
- [S-NETAVARK-STATE] [Netavark firewall state lock](https://github.com/containers/netavark/blob/77bdd21ed358aa64228e2d900ade2a061ff5f381/src/firewall/state.rs)
- [S-NETAVARK-NFT] [Netavark nftables batching](https://github.com/containers/netavark/blob/77bdd21ed358aa64228e2d900ade2a061ff5f381/src/firewall/nft.rs)
- [S-NETAVARK-CARGO] [Netavark Rust dependencies and license](https://github.com/containers/netavark/blob/77bdd21ed358aa64228e2d900ade2a061ff5f381/Cargo.toml)

### Android root projects

- [S-BOX4] [Box4Magisk source at `1aabf31a`](https://github.com/CHIZI-0618/box4magisk/tree/1aabf31ad837b6ebff11d46fda585f63230de9f8)
- [S-BOX4-LICENSE] [Box4Magisk license](https://github.com/CHIZI-0618/box4magisk/blob/1aabf31ad837b6ebff11d46fda585f63230de9f8/LICENSE)
- [S-ATP] [AndroidTProxyShell source at `4b6ddd87`](https://github.com/CHIZI-0618/AndroidTProxyShell/tree/4b6ddd8779651a9a8316c96c04a79c7fb2157c64)
- [S-ATP-LICENSE] [AndroidTProxyShell license](https://github.com/CHIZI-0618/AndroidTProxyShell/blob/4b6ddd8779651a9a8316c96c04a79c7fb2157c64/LICENSE)
- [S-NETPROXY] [NetProxy-Magisk source at `24dfb96c`](https://github.com/Fanju6/NetProxy-Magisk/tree/24dfb96c5f2fa4ec89f98e282aae6bfa9cfc1074)
- [S-NETPROXY-LICENSE] [NetProxy-Magisk license](https://github.com/Fanju6/NetProxy-Magisk/blob/24dfb96c5f2fa4ec89f98e282aae6bfa9cfc1074/LICENSE)
- [S-MAGICNET] [MagicNet source at `7df0bdcd`](https://github.com/LIghtJUNction/MagicNet/tree/7df0bdcd484a509fdc22d4cc93819c950dc3f43e)
- [S-MAGICNET-LICENSE] [MagicNet license](https://github.com/LIghtJUNction/MagicNet/blob/7df0bdcd484a509fdc22d4cc93819c950dc3f43e/LICENSE)

### Linux, AOSP, and build contracts

- [S-NFT-ATOMIC] [nftables atomic rule replacement, revision 693](https://wiki.nftables.org/wiki-nftables/index.php?title=Atomic_rule_replacement&oldid=693)
- [S-IPT-LEGACY] [Current legacy `iptables-restore` implementation](https://git.netfilter.org/iptables/plain/iptables/iptables-restore.c?id=84faa6b539e79156a29f375a4eb14c24ec60be0b)
- [S-IPT-NFT] [Current `iptables-nft-restore` implementation](https://git.netfilter.org/iptables/plain/iptables/xtables-restore.c?id=84faa6b539e79156a29f375a4eb14c24ec60be0b)
- [S-LINUX-TPROXY] [Linux TPROXY documentation](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/Documentation/networking/tproxy.rst?id=248951ddc14de84de3910f9b13f51491a8cd91df)
- [S-LINUX-NETLINK] [Linux netlink userspace API](https://docs.kernel.org/userspace-api/netlink/intro.html)
- [S-AOSP-IPTABLES] [AOSP iptables build definition](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/iptables/Android.bp)
- [S-AOSP-XTABLES-LOCK] [AOSP xtables lock configuration](https://android.googlesource.com/platform/external/iptables/+/672d4a9452846646a3017d255fae319e12d92295/config.h)
- [S-AOSP-NETD-RESTORE] [AOSP netd iptables restore controller](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/IptablesRestoreController.cpp)
- [S-AOSP-ROUTE] [AOSP RouteController priorities](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.h)
- [S-AOSP-ROUTE-CPP] [AOSP RouteController initialization](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.cpp)
- [S-AOSP-FWMARK] [AOSP fwmark layout](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/include/Fwmark.h)
- [S-AOSP-FWMARK-SERVER] [AOSP fwmark service behavior](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/FwmarkServer.cpp)
- [S-AOSP-NETD-CLIENT] [AOSP client network-selection hooks](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/client/NetdClient.cpp)
- [S-RUST-ANDROID] [Rust Android target support](https://doc.rust-lang.org/rustc/platform-support/android.html)
- [S-ANDROID-NDK] [Android NDK with other build systems](https://developer.android.com/ndk/guides/other_build_systems)
- [S-ANDROID-PAGES] [Android 16 KB page-size build guidance](https://developer.android.com/guide/practices/page-sizes#compile-r27-lower)
- [S-MAGISK] [Magisk module guide at `14ea5cfb`](https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/docs/guides.md)
- [S-MAGISK-SERVICE] [Magisk module-script launch implementation](https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/native/src/core/scripting.cpp)
