# Sing-Box and adjacent-project research for the Flux Rust rewrite

- Original research date: 2026-07-11 (Asia/Singapore)
- Last updated: 2026-07-13
- Current Flux design baseline: `868729fcce4d076b11e7746d8ec39369f26159f2`

This note studies Sing-Box and adjacent Android transparent-proxy, TUN, userspace-network-stack, and eBPF projects as design inputs for the Flux rewrite. It is intentionally implementation-oriented: it records what the projects actually do, where the relevant code lives, what is safe to reuse conceptually, and what Flux should avoid copying.

> **Non-normative priority notice:** lifecycle and ownership findings remain design evidence, but
> compatibility/migration sequencing in this historical note is superseded by ADR-0011 and the
> current roadmap. The release package may keep platform bootstrap glue only; emergency networking
> cleanup is a Rust offline command, not shell compatibility behavior.

The study used upstream documentation and source repositories cloned into the operating-system temporary directory. Nothing from those repositories was vendored into Flux. The current stable Sing-Box release at the time of research was `v1.13.14`; the upstream default branch was `testing`, already carrying 1.14-era work. Stable behavior and forward-looking behavior are separated below.

## Executive conclusions

1. **Keep Sing-Box as a supervised protocol engine in the first Rust architecture.** `fluxd` should own Android lifecycle, capability detection, routing/firewall state, TUN policy/link verification, address synchronization, configuration generations, and recovery. In the shipping `EngineOwnedTun` plan, Sing-Box remains the child process that creates and owns the TUN queue FDs and provides proxy protocols, outbound selection, rule evaluation, DNS transports, and its userspace TUN stack. Reimplementing that protocol surface in Rust is a different project.

2. **Do not use the Clash API as the daemon-management API.** Sing-Box's Clash-compatible API is useful for traffic/log streams, connection inspection, selector changes, URL tests, provider refresh, DNS/cache flushes, and Clash mode. It does not perform a full config reload: `PUT /configs` is a no-op, and `PATCH /configs` only changes Clash mode in the inspected source. Full lifecycle control belongs in a private Flux control socket and should call a validated reload path.

3. **Treat reload as a generation transition, not “kill and start.”** Sing-Box CLI `SIGHUP` validates the config, closes the old instance, then constructs the replacement. Its libbox `StartOrReloadService` path closes the old instance before constructing the new one. Both can still create an outage if the new generation fails during start. `dae` demonstrates the stronger pattern: prepare a new control plane, clone or stage listeners, switch, drain the old generation, and retain rollback information.

4. **Use runtime capability probes, never kernel version or Android identity alone.** Sing-Tun deliberately disables nftables on `GOOS=android`, even when a custom Android kernel might support it; AndroidTProxyShell largely infers features from `/proc/config.gz` and a few loaded modules. Flux should use the kernel version only as a coarse eligibility bound, then perform non-destructive behavioral probes for TUN, nftables transactions, iptables targets/matches, ipset types, policy rules, NFQUEUE, and eBPF program/map/helper support.

5. **Make native TUN a Flux subsystem, but do not confuse a TUN device crate with a TCP/IP stack.** `tun-rs` is a strong candidate for file-descriptor I/O abstractions, async/vectored I/O, interruption, and Linux offload code. On Android, however, its current conditional compilation selects the generic Unix FD backend, not the Linux device/offload backend. `smoltcp` is an excellent Rust stack for constrained systems but explicitly omits widely deployed TCP features; it should not be the default general-purpose Android proxy stack. Sing-Box's `system`, `gvisor`, and `mixed` stacks remain the practical near-term choices.

6. **Prefer the kernel system-stack/TUN path on rooted Android when it is healthy, with gVisor/mixed as explicit fallbacks.** Sing-Tun's mixed mode uses its system translation for TCP and gVisor for UDP. This is a useful operational compromise, not a reason to embed gVisor into `fluxd`: gVisor is Go, substantial, and already integrated by Sing-Box.

7. **DNS is part of routing state, not a sidecar afterthought.** Flux must coordinate DNS hijacking, bootstrap resolution, fake-IP/cache persistence, reverse mapping, rule-set updates, Private DNS policy, and reload behavior. DNS interception must have an explicit loop-avoidance model. Domain-to-IP correlation is inherently ambiguous, as `dae` documents; it should be treated as evidence with TTL/scope, not a permanent truth.

8. **The eBPF datapath must be an optional high-capability tier.** `dae v2.0.0` requires Linux 5.17 for its LAN/WAN binding modes plus a large set of BPF, cgroup, tc, and BTF options. Flux's 5.10 minimum therefore cannot make a `dae`-class datapath mandatory. Use nftables/iptables/TUN as the baseline and activate eBPF only after program-load probes succeed. Borrow architectural ideas, not AGPL source.

9. **Licensing is a design constraint.** Flux is GPL-3.0. Sing-Box, Sing-Tun, SFA, Magisk, Box4Magisk, and AndroidTProxyShell are GPL-family projects; `dae` is AGPL-3.0; tun2socks and HEV are MIT; gVisor and tun-rs are Apache-2.0; smoltcp is 0BSD. Directly copying `dae` code would materially change distribution obligations. Sing-Box and SFA also carry an additional project-name/association restriction in their license text. This note is not legal advice, but the implementation should preserve provenance and obtain a license review before copying code rather than reimplementing behavior.

## Source snapshot

| Project | Inspected snapshot | Relevant role | License observed |
|---|---|---|---|
| Sing-Box | stable `v1.13.14` at `25a600db24f7680ad9806ce5427bd0ab8afe1114`; default `testing` at `725d2254dc067189ac871291b817cb979cf7901e` | Proxy engine, DNS, rules, TUN integration, APIs, lifecycle | GPL-3.0-or-later plus additional name/association term |
| Sing-Tun | stable `v0.8.11` at `b1c48c12e2c667a880d9682636ae68145ca06df1`; `dev` at `375e9ae639c53844d31fe4a319de75d6606ecdce` | TUN device, stacks, auto-route, nftables/iptables, Android UID/interface handling | GPL-3.0-or-later |
| Sing-Box for Android (SFA) | `edd0d9cafb56aa2edb65429f4812d7017665b661` (`dev`, version bump 1.14.0-alpha.42) | Android `VpnService`, default-network monitoring, service control | GPL-3.0-or-later plus additional name/association term |
| Magisk | `14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c` (`master`) | Official module and boot-script semantics | GPL-3.0 |
| Box4Magisk | `1aabf31ad837b6ebff11d46fda585f63230de9f8` (`Prerelease`) | Root module launcher, TPROXY/TUN integration, inotify lifecycle | GPL-3.0 |
| AndroidTProxyShell | `303f3c66db9ce9b052dbacfa5a58957fd1943d84` (`main`) | Android iptables/TPROXY/REDIRECT/ipset patterns | GPL-3.0 |
| tun2socks | `dda1b1058db86dd0ef40d1b007de0ce86cf16a46` (`main`) | gVisor TUN-to-proxy engine, marks/bind-to-device, statistics API | MIT |
| gVisor | `37973046f14084385abe058597a5acd0cb1a5478` (`master`, sparse `pkg/tcpip`) | Userspace TCP/IP netstack | Apache-2.0 |
| tun-rs | `2.8.7`, `5d97ac38a505f47a7161b24f714318c84e3dc024` | Rust TUN/TAP I/O and Linux offloads | Apache-2.0 |
| smoltcp | `764ef3a8cc38d543f407555772f495d4810c8895`, crate version `0.13.1` | Pure-Rust event-driven TCP/IP stack | 0BSD |
| HevSocks5Tunnel | `c6e4c72246fb0f20bda299f0efc7814bb3098d57` | Lightweight Android-capable lwIP tun2socks and FD API | MIT |
| dae | `v2.0.0`, `fee4c8661059bfc5a60ca8eaad59a1030cb35128` | tc/cgroup eBPF transparent proxy and staged reload | AGPL-3.0-only |

## 1. Sing-Box architecture and integration surfaces

### 1.1 There are three different control surfaces

Sing-Box exposes three operationally distinct surfaces that should not be conflated:

1. **CLI process control**: `sing-box run`, `check`, `format`, `merge`, and the `rule-set` tool family. `run` listens for `SIGINT`, `SIGTERM`, and `SIGHUP`. On `SIGHUP`, it runs the config check, cancels the instance context, closes the existing `Box`, and loops to create another instance. This is a complete process-level reload, not an in-place mutation. ([SB-CLI-RUN], [SB-CLI-CHECK])
2. **Clash-compatible HTTP API**: operational telemetry and selected live mutations. It exposes logs, traffic, connections, rules, proxies, providers, cache/DNS operations, and mode/selector changes. It is designed for dashboards and Clash clients, not authoritative daemon orchestration. ([SB-CLASH-SERVER], [SB-CLASH-CONFIGS])
3. **Daemon/libbox gRPC API**: typed service status, logs, traffic status, groups, Clash mode, connections, outbounds, network tests, plus managed stop/reload calls. SFA uses this path through `CommandServer.startOrReloadService`. ([SB-DAEMON-PROTO], [SB-MANAGED-PROTO], [SB-COMMAND-SERVER], [SFA-BOX-SERVICE])

Flux should mirror this separation:

- a private, authenticated `fluxd` control socket is authoritative for start/stop/reload/status/capabilities;
- the Clash API is an optional compatibility facade proxied or exposed by Sing-Box;
- shell scripts perform only Magisk entrypoint and recovery glue.

### 1.2 Lifecycle is explicitly staged, but reload is not transactional

`box.Box` creates registries and managers for endpoints, inbounds, outbounds, DNS transports, services, certificate providers, networking, routing, connections, cache, Clash API, and optional APIs. Startup progresses through `Initialize`, `Start`, `PostStart`, and `Started` stages. Shutdown closes service/inbound/endpoint/outbound/router/DNS/network components in a deliberate order and aggregates errors. This staged lifecycle is worth copying as a Rust trait/state-machine design. ([SB-BOX])

The reload implementations are weaker than a generation swap:

- CLI `SIGHUP` performs a pre-check, then closes the current instance before the next `create()`/`Start()` cycle. A configuration can pass construction/check and still fail at start because a route, TUN, listener, firewall primitive, or remote resource is unavailable. ([SB-CLI-RUN])
- `daemon.StartedService.StartOrReloadService` moves the service to `STOPPING`, closes the old instance, frees memory, then parses/constructs/starts the new instance. If new construction or start fails, status becomes `FATAL`; there is no old-generation rollback. ([SB-STARTED-SERVICE])

The design implication is precise: **Flux should not delegate its own firewall/TUN generation safety to Sing-Box reload semantics.** At minimum, `fluxd` should validate and precompute everything it owns before signaling Sing-Box. For TPROXY/redirect operation, a stronger design can run a candidate Sing-Box generation on a new internal port, verify readiness, atomically switch the firewall jump or nftables verdict map to that port, then drain and stop the previous child. Native TUN cannot generally run two owners over the same routing state; it needs a shorter stop/swap window or a future architecture in which `fluxd` owns the TUN FD and hands it to an embeddable engine.

### 1.3 A Rust rewrite should supervise, not link, Sing-Box initially

Sing-Box is designed as both an executable and a Go library. SFA proves the library route is powerful: a platform interface supplies TUN creation and socket protection, while a gRPC command server provides structured control. But linking a Go archive into a Rust/Android daemon adds a Go runtime, FFI ownership, panic boundaries, signal coordination, allocator/RSS behavior, and cross-toolchain release complexity. It also creates a single combined GPL work and imports Sing-Box's additional license term.

The lower-risk first architecture is:

- `fluxd` is PID 1 for the module's application-level processes;
- Sing-Box remains a child executable with a generated config and loopback-only control API;
- `fluxd` validates with `sing-box check`, launches with an explicit working directory, records the exact executable/config hashes, verifies readiness using both process identity and a functional probe, and terminates with `SIGTERM` plus a bounded escalation;
- a later optional “embedded engine” can be evaluated only after the Rust control plane is stable.

This also matches the user's requirement that shell may glue binaries together while core orchestration moves into `fluxd`.

## 2. TUN, routing, and Android-specific behavior

### 2.1 Sing-Box TUN behavior worth preserving

Stable Sing-Box 1.13 exposes a mature TUN model:

- IPv4/IPv6 interface addresses and MTU;
- automatic routes with dedicated iproute2 table and rule indices;
- strict routing;
- include/exclude route prefixes and rule-set-derived address sets;
- interface, UID, Android user, and package inclusion/exclusion;
- loopback-address behavior;
- system, gVisor, and mixed stacks;
- endpoint-independent NAT and UDP timeout;
- nftables-based `auto_redirect`, connection marks, NFQUEUE pre-match, MPTCP exclusion, and a fallback policy-rule index. ([SB-TUN-DOC], [ST-TUN], [ST-RULES])

The stack choices are concrete, not marketing labels:

- `system` performs L3-to-L4 translation using OS sockets and Sing-Tun's packet/NAT machinery;
- `gvisor` terminates TCP/UDP/ICMP in gVisor netstack;
- `mixed` uses Sing-Tun's system path for TCP and gVisor for UDP. Its implementation instantiates the system stack, creates a gVisor channel endpoint for UDP, and dispatches packets by L4 protocol. ([ST-STACK], [ST-MIXED], [ST-GVISOR])

For rooted Android, the recommended order is:

1. `system` where compatibility tests pass, because it avoids a second full TCP stack and generally gives the kernel more control over congestion behavior;
2. `mixed` when UDP behavior needs gVisor while retaining system TCP;
3. `gvisor` as an explicit compatibility fallback or when a fully userspace stack is required.

The choice must remain configuration- and probe-driven. It should not be silently changed by kernel version alone.

### 2.2 Auto-route must pair with explicit loop prevention

Sing-Box documentation explicitly requires `route.auto_detect_interface`, `route.default_interface`, or outbound interface binding when `auto_route` is used, to prevent the proxy's own outbound sockets from returning to the TUN. `auto_detect_interface` binds outbound connections to the current default NIC; `default_interface` binds to a configured NIC; `default_mark` supplies a routing mark. ([SB-ROUTE-DOC])

This should become a Flux invariant:

- every traffic-capture backend declares its loop-prevention mechanism;
- every outbound child socket path is either bound to an upstream interface, marked into a bypass rule/table, or protected through an engine-specific API;
- activation fails closed if no loop-prevention mechanism is available;
- the status API reports the chosen upstream interface, ifindex, mark, rule priority, and last transition reason.

### 2.3 Sing-Tun's Android route detection encodes useful platform knowledge

On Android, Sing-Tun does not merely inspect the lowest-metric default route. Its default-interface monitor scans policy rules and recognizes Android rule masks: a `0x20000` mask indicates the VPN/protected path and a `0xFFFF` mask identifies the normal default-network rule. With `override_android_vpn`, the VPN table may become the selected upstream. It then resolves the table's route to a link and emits interface updates. When Android VPN state changes, TUN rules are reset. ([ST-MONITOR-ANDROID], [ST-TUN-LINUX])

Flux should implement this knowledge in a dedicated Android network model rather than shell-parsing `dumpsys` output. The model should consume rtnetlink events for links, addresses, routes, and rules; maintain a coherent snapshot; debounce bursts; and publish a monotonic network-generation number to TUN, firewall, DNS, and child supervision components.

### 2.4 Android package selection belongs in the daemon

Sing-Tun reads `/data/system/packages.xml`, supports both text XML and Android binary XML (ABX), watches the package database for updates, maps packages/shared users to app IDs, and expands Android user IDs using the `user * 100000 + appId` UID convention. It then converts include/exclude package policy into UID ranges used by policy rules. ([ST-PACKAGES], [ST-RULES])

This is a direct fit for the Rust rewrite:

- merge the current address/package synchronization responsibilities into `fluxd`;
- parse both XML and ABX without spawning `pm` once per package;
- watch the authoritative files but retain periodic reconciliation because vendor updates can replace files or suppress expected inotify events;
- model shared UIDs explicitly, since one UID can represent several packages;
- expose resolution results and unresolved package names through status diagnostics;
- compile package policy into backend-neutral UID sets/ranges, then render to nftables, iptables owner matches, or policy rules according to capability.

### 2.5 Native TUN creation details

Sing-Tun checks `/dev/tun` first on Android and otherwise uses `/dev/net/tun`; it opens the device, applies `TUNSETIFF` with `IFF_TUN | IFF_NO_PI`, configures nonblocking I/O, addresses, MTU, routes, and rules through netlink, and performs cleanup on close. Its Linux path also contains batched I/O and checksum/GRO/GSO handling. ([ST-TUN-LINUX])

For `fluxd`, native TUN should be a deep module with an explicit ownership split:

- `EngineOwnedTunLease`: exact Sing-Box/link identity, resolved stack/offload/multiqueue capabilities, and lifecycle evidence without queue-FD access;
- `FluxOwnedTunFd`: future ownership of FD, name, flags, MTU, queues, offload state, and read/write strategy after a documented engine handoff exists;
- `TunConfigurator`: netlink address/link/route/rule transactions and exact inverse operations;
- `TunDatapath`: packet dispatch owned by Sing-Box initially and by Flux only under the future FD contract;
- `TunPolicy`: desired included/excluded routes, users, packages, interfaces, DNS mode, and loop prevention;
- `TunLease`: generation-scoped resource record used for crash recovery.

Do not let a generic `Drop` implementation blindly delete routes or reset sysctls that it did not create. Every mutation needs an ownership token or a before/after snapshot.

### 2.6 Android `VpnService` is useful reference material, but not the root-module architecture

SFA's `VPNService.openTun` demonstrates the non-root Android contract: it builds the TUN, adds addresses/DNS/routes, uses Android 13's `excludeRoute` when available, applies allowed/disallowed application lists, optionally installs an HTTP proxy, calls `establish()`, and passes the FD to libbox. Outbound sockets are excluded from the VPN with `VpnService.protect(fd)`. ([SFA-VPN])

Flux is a root/Magisk module, so it should not depend on user-consented `VpnService` for its primary mode. Still, the SFA design is valuable for a future unrooted companion mode and for testing the engine with an externally supplied TUN FD.

## 3. nftables, iptables, ipset, and NFQUEUE patterns

### 3.1 Sing-Tun's nftables path is the best semantic reference

Sing-Tun creates an `inet` nftables table, address sets, local-address sets, loopback sets, output/prerouting chains, route/filter/NAT chains, marks, and dynamic updates on network changes. It also integrates with OpenWrt and Docker-specific firewall behavior. The route address sets can be updated without rebuilding unrelated state. ([ST-NFT])

Its NFQUEUE pre-match path is particularly interesting. It queues TCP SYN packets (and, in newer mark mode, UDP and echo ICMP), asks the rule engine for a flow verdict, then uses marks plus `NF_REPEAT` to re-enter nftables so bypass/reset decisions can be saved into conntrack or converted into TCP RST. The queue is configured fail-open. ([ST-NFQUEUE])

Patterns to adopt:

- one namespaced table per Flux generation or one stable table with generation-scoped chains/maps;
- sets/maps for large address and policy data rather than one rule per prefix;
- atomic batch replacement through netlink;
- explicit conntrack mark ownership and masks;
- bounded NFQUEUE with fail-open/fail-closed chosen per policy, queue-pressure metrics, and a fast bypass path;
- local/interface-address sets refreshed from the authoritative network snapshot;
- idempotent cleanup by handle/table identity rather than textual command replay.

### 3.2 Do not inherit Sing-Tun's compile-time Android nftables exclusion

At both Sing-Tun `v0.8.11` and the inspected `dev` revision, `NewAutoRedirect` sets `useNFTables` only when `runtime.GOOS != "android"`. Android then uses `/system/bin/iptables`, enables IPv4, and falls back to a simple TCP redirect path. This matches stock-device assumptions, but it leaves performance/features unused on Android kernels that do expose nf_tables. ([ST-REDIRECT])

Flux should replace this with capability selection:

1. attempt an isolated nftables `inet` table/set/chain transaction through netlink;
2. verify hook/type/expression support actually needed by the selected profile;
3. remove the probe table;
4. choose native nftables only after success;
5. otherwise detect iptables frontend/backend and required targets/matches;
6. degrade to REDIRECT or TUN only according to a documented policy.

The existence of an `nft` executable is not sufficient, and neither is `CONFIG_NF_TABLES=y`.

### 3.3 AndroidTProxyShell and Box4Magisk contain good compatibility knowledge

The shell projects cover practical rooted-Android cases: TPROXY with REDIRECT fallback, independent mobile/Wi-Fi/hotspot/USB interface policy, per-app owner rules, multi-user package notation, DNS hijack, QUIC blocking, IPv6 capability checks, MAC filters, ipset bulk restore, marks and policy routing, runtime cleanup snapshots, dry-run, and configurable hooks. ([ATP-README], [ATP-SCRIPT], [BOX4-README], [BOX4-SERVICE], [BOX4-TPROXY])

Useful patterns:

- prefer TPROXY for TCP+UDP and clearly label REDIRECT as TCP-limited;
- build large ipsets with a restore file instead of thousands of subprocesses;
- retain the active generation's cleanup inputs rather than using newly edited config during stop;
- expose a dry-run/plan view;
- treat hotspot/tether traffic separately from local-device traffic;
- preserve original source/destination semantics when the backend supports them;
- validate the Sing-Box config before installing traffic-capture rules.

Patterns to reject or replace:

- inferring support mainly from `/proc/config.gz`; many Android kernels omit `IKCONFIG_PROC`, compile options can exist without usable userspace ABI, and vendor SELinux can still deny operations;
- rule-by-rule shell mutation instead of atomic backend transactions;
- hard-coded module paths and boot polling;
- inotify over `/data/misc/net/rt_tables` as a proxy for all network changes;
- setting global forwarding to `0` during cleanup without restoring the prior value (the scripts include variants of this problem);
- flushing vendor firewall chains as a compatibility “fix”;
- exposing a dashboard API on all interfaces with a default or empty secret;
- recursive shell retry and process lookup by basename instead of owned PIDs/pidfds.

Flux's existing scripts already improve several of these points by snapshotting previous sysctl/Private-DNS values, keeping active cleanup files, hashing them, and using `iptables-restore --noflush`. The rewrite should preserve those semantics in Rust and make the transaction journal authoritative.

## 4. DNS, fake IP, and rule sets

### 4.1 Sing-Box's DNS router is a policy engine

Sing-Box DNS has tagged transports, ordered rules, a final server, IP-family strategy, cache controls, reverse mapping, EDNS client subnet, fake IP, and per-rule actions/options. In the 1.14 development docs, optimistic stale-while-revalidate caching and explicit query timeouts are added while older cache options are being migrated. ([SB-DNS-DOC], [SB-DNS-ACTIONS])

The architectural lesson is to keep four layers separate:

1. **capture**: which port-53/TUN traffic is intercepted and how replies preserve the original tuple;
2. **policy**: which resolver/outbound handles a question and whether the response is accepted, rejected, or re-evaluated;
3. **transport**: UDP/TCP/DoT/DoH/HTTP3/local/fake-IP mechanics and bootstrap resolution;
4. **state**: positive/negative cache, fake-IP allocation, reverse mappings, and domain-to-IP routing evidence.

`fluxd` should own capture and lifecycle state; Sing-Box can own DNS policy and transport in the first version. Flux must nevertheless know enough to prevent loops and preserve/restore Android Private DNS settings only when a selected compatibility profile explicitly requires it.

### 4.2 TUN DNS handling is evolving

Stable 1.13 TUN behavior derives DNS interception from TUN addressing and route rules. The 1.14 testing branch adds explicit TUN `dns_mode` (`disabled`, `native`, `hijack`) and `dns_address`. On Linux, the documented hijack behavior differs depending on `auto_redirect`: policy routing can force non-local port-53 traffic through the TUN, while nftables mode can DNAT to the configured DNS address. Local destinations such as `127.0.0.53` have kernel-local-routing caveats. ([SB-TUN-DOC])

Flux should therefore represent DNS capture as a first-class capability, not infer it only from “TUN enabled.” It must distinguish local-output DNS, forwarded/hotspot DNS, TCP vs UDP 53, local-address destinations, encrypted DNS that cannot be transparently rewritten, and vendor Private DNS behavior.

### 4.3 Fake IP and reverse mapping have correctness limits

Fake IP is useful because the routing engine can recover a domain at connection time, but it creates state that must persist consistently across restarts. Reverse mapping similarly relies on observing the application's DNS resolution before its connection. Sing-Box documents that reverse mapping can be unreliable where a system proxy/cache breaks this causal link. `dae` documents the broader limitation of DNS-derived domain routing: shared IPs, browser caches, and DNS paths that bypass the proxy can all cause misclassification. ([SB-DNS-DOC], [DAE-HOW])

Required Flux behavior:

- persist fake-IP state atomically with a schema/version and corruption fallback;
- never reuse a fake IP while an active connection or unexpired mapping may still refer to it;
- scope domain-to-IP evidence by resolver view, network generation, TTL, and preferably UID/profile;
- provide a “domain unknown” path rather than guessing;
- flush or migrate caches deliberately on DNS-policy changes;
- record cache generation in diagnostics.

### 4.4 Rule-set lifecycle is strong and should inform Flux assets

Sing-Box rule sets can be inline, local, or remote, in source JSON or compiled binary SRS format. Local files are automatically reloaded when modified. Remote rule sets are cached when the experimental cache file is enabled and default to a one-day update interval. The testing branch introduces a named HTTP client for downloads and deprecates `download_detour`, making bootstrap/detour behavior more explicit. ([SB-RULESET-DOC], [SB-RULESET-REMOTE])

Recommended Flux asset model:

- content-address every downloaded asset and keep the previous known-good version;
- download to a temporary file, verify size/format/optional digest/signature, fsync, then rename;
- compile source rule sets offline where possible and validate with Sing-Box's `rule-set` tools;
- update assets independently from the active service generation;
- trigger a targeted rule-set refresh when supported, otherwise a validated service generation reload;
- never let a failed remote update erase the active cached asset;
- expose source URL, resolved IP, outbound used, ETag/Last-Modified, digest, last success/failure, and next retry.

## 5. Clash API: use it narrowly and secure it

Sing-Box's Clash API mounts endpoints for logs, traffic, configs, proxies, rules, connections, providers, scripts, profile tracing, cache, DNS, and Meta-compatible extensions. It supports Bearer authentication and websocket token query parameters. Documentation says a secret must always be set when listening on `0.0.0.0`; CORS defaults to `*` when no allow-list is configured. ([SB-CLASH-DOC], [SB-CLASH-SERVER])

The critical source-level limitation is in `experimental/clashapi/configs.go`:

- `PATCH /configs` decodes the schema and changes only `Mode`;
- `PUT /configs` immediately returns `204 No Content` and performs no reload. ([SB-CLASH-CONFIGS])

Flux policy should be:

- default bind: Unix socket or `127.0.0.1` only;
- non-loopback bind: explicit opt-in, generated strong secret, restricted origins, and a prominent status warning;
- treat websocket query tokens as sensitive and avoid logging full URLs;
- never make Clash API reachability the only readiness probe;
- do not map `fluxd reload` to `/configs`; use the `fluxd` control protocol;
- proxy only the compatibility endpoints that the bundled UI needs, if Flux places an authorization layer in front.

## 6. Adjacent TUN and userspace-stack projects

### 6.1 tun2socks and gVisor

Tun2socks constructs a gVisor stack with IPv4/IPv6/TCP/UDP/ICMP, installs transport forwarders before creating the NIC, enables promiscuous mode and spoofing so arbitrary intercepted destinations can terminate in the stack, and installs default IPv4/IPv6 routes. Its Linux dialer can bind upstream sockets to an interface and set `SO_MARK`. It accepts TUN pre/post commands and exposes traffic/connection statistics over an HTTP/websocket API. ([T2S-STACK], [T2S-ENGINE], [T2S-REST])

Patterns to adopt:

- install packet handlers before the device begins dispatching to avoid startup races;
- separate link endpoint, network stack, transport handler, and proxy transport;
- use interface binding/marks as explicit loop prevention;
- publish connection closure and traffic statistics;
- allow an externally created FD endpoint.

Patterns to reject:

- package-global mutable engine state guarded by one mutex;
- fatal process exits inside reusable lifecycle code;
- no generation-aware config reload;
- shell hooks as the primary route manager;
- permissive CORS or an unauthenticated statistics server when exposed beyond loopback;
- relying on `net.DefaultResolver` mutation as a complete DNS subsystem.

The gVisor repository describes an application kernel written in Go and running in userspace. Its `pkg/tcpip` build rules explicitly try to keep netstack separable as a library. Sing-Box and tun2socks demonstrate that it is featureful enough for transparent proxying, but bringing it directly into a Rust daemon would require a Go boundary. Let Sing-Box own that integration unless a later benchmark proves a compelling need. ([GVISOR-README], [GVISOR-TCPIP])

### 6.2 tun-rs

Tun-rs provides synchronous and Tokio/async-io APIs, owned and borrowed raw-FD construction, vectored and interruptible I/O, multiple addresses, and Linux TSO/GSO/GRO/multi-queue support. Its API shape is a good reference for a safe Rust TUN wrapper. ([TUNRS-README], [TUNRS-PLATFORM], [TUNRS-LINUX])

Important Android caveat: the current `platform/mod.rs` exports the specialized Linux backend only for `target_os = "linux"`; Android falls through to the generic Unix `DeviceImpl`. The generic path supports wrapping an existing FD and ordinary/vectored async I/O, but not the crate's Linux builder, netlink configuration, or Linux offload/multi-queue methods. A rooted Android `fluxd` would need one of:

- a small upstream contribution making selected Linux TUN code available under Android where the ABI matches;
- a Flux-owned Android/Linux backend around `rustix`/`libc` and netlink;
- use tun-rs only for FD I/O while Flux owns creation/configuration/offload.

The third option is the least risky initially.

### 6.3 smoltcp

Smoltcp is a standalone, event-driven Rust TCP/IP stack designed for bare-metal/real-time systems and can run without heap allocation. Its documentation is unusually honest about omissions: TCP selective acknowledgements, timestamps, and packetization-layer PMTU discovery are not implemented in the inspected version, among other limitations. ([SMOLTCP-README])

It is attractive for deterministic tests, packet parsers, constrained side functions, and perhaps a minimal UDP/ICMP fallback. It is not the recommended default Internet-facing TUN stack for a phone expected to handle arbitrary applications, long-lived mobile TCP, congestion variation, and unusual middleboxes. Adopting it as the primary stack would make Flux responsible for years of TCP interoperability work.

### 6.4 HevSocks5Tunnel

HEV is a compact lwIP-based tun2socks supporting Android, IPv4/IPv6, TCP, UDP full-cone modes, multi-queue, socket marks, mapped DNS, and low-memory tuning. Its library API accepts either a config file or config string plus an external TUN FD, blocks until an explicit quit call, and exposes aggregate packet/byte statistics. ([HEV-README], [HEV-API])

The most reusable idea is the small embedding contract:

```text
start(config bytes, tun fd) -> running/error
stop()
stats() -> counters
```

Flux's internal engine interface should be similarly narrow even if the implementation is a child process. HEV itself is C/lwIP and is not a reason to replace Sing-Box, but it is a good reference for low-memory knobs and test harnesses.

## 7. eBPF lessons from dae

`dae` places classifiers at tc ingress/egress, uses cgroup socket hooks to associate process identity with socket cookies, and employs maps including LPM tries, socket hashes, ring buffers, per-CPU arrays, and connection/routing state. Its source contains tc programs for LAN/WAN/virtual-link paths and cgroup programs for socket create/release, connect4/connect6, and sendmsg4/sendmsg6. Newer code also selects helpers such as `bpf_redirect_peer` only under appropriate kernel conditions. ([DAE-BPF], [DAE-HOW])

Concepts worth adopting in an optional Flux backend:

- tc classification before netfilter/userspace to let definitely-direct traffic remain in kernel space;
- socket-cookie to UID/PID/process metadata maps populated by cgroup hooks;
- LPM trie or map-of-maps rule data with generation switching;
- per-CPU counters and a ring buffer for low-overhead observability;
- userspace as policy compiler/control plane, BPF as bounded dataplane;
- explicit map capacity/overflow behavior and janitors;
- feature-specific object variants rather than one verifier-hostile universal program;
- a kill switch that detaches hooks without relying on daemon shutdown completing normally.

Limitations that matter for Flux:

- dae's own quick-start documentation requires kernel 5.17 for LAN and WAN binding, plus BPF JIT, cgroups, tc ingress/egress, cls_bpf/act, BTF/debug info, kprobe/BPF events, and related options. ([DAE-REQ])
- Android 5.10 vendor kernels commonly lack BTF, cgroup v2 layouts, helpers, or permissions expected by desktop Linux projects.
- the inspected BPF program uses `bpf_loop`, a helper unavailable on a generic 5.10 baseline, and has newer helper-specific branches.
- verifier limits, vendor backports, SELinux, and locked-down sysctls make version comparison insufficient.
- dae is AGPL-3.0-only; copying its Go/C code is not a neutral dependency choice.

Therefore:

- **5.10 correctness baseline:** nftables/iptables/TUN provide full functional service without eBPF;
- **5.10-probeable `xt_bpf` tier:** first observe inside Flux-owned xtables chains with an always-false matcher, then allow proxy-positive hits while every miss continues through the complete classic classifier;
- **higher-risk dae-style TC/cgroup tier:** enabled only when each required map type, program type, attach point, helper, BTF/CO-RE strategy, memlock behavior, full cgroup ancestor-chain attachment state, qdisc owner, and packet context passes a probe;
- **5.17+ is an eligibility hint for dae-style facilities, not proof**, while `xt_bpf` can be attempted on the 5.10 floor;
- bind legacy TUN TC to Network Epoch because netd can delete `clsact` from every extant interface; a verified TCX link is qdisc-less but retains link/order freshness; treat physical/tether TC as a separate conflict-checked experiment;
- keep the backend detachable and semantically equivalent to a non-eBPF policy path.

### Reload pattern to borrow from dae

`dae v2.0.0` contains a staged reload path that prepares a new control plane, clones a same-port listener, switches generations, and retires the old control plane after active sessions drain or a timeout expires. It also tracks reload progress and rollback/error state. ([DAE-RELOAD])

Flux should adopt this state model even where exact zero-downtime handoff is impossible:

```text
Idle -> Preparing -> ReadyToSwitch -> Switching -> DrainingOld -> Active
                   \-> Failed (old remains active)
Switching failure  -> RollingBack -> Active(old) or Degraded
```

Every stage must be observable through `fluxd status --json`, and a crash-recovery journal must say which generation owns which kernel objects.

## 8. Magisk lifecycle requirements

Official Magisk guidance says module scripts run in BusyBox `ash` standalone mode, recommends the module's own `service.sh` for most boot work, recommends `resetprop -w sys.boot_completed 0` when boot completion is required, requires `MODDIR=${0%/*}` instead of a hard-coded module path, and explicitly says modules should not install general `/data/adb/service.d` scripts. Late-start service mode is non-blocking and is the recommended stage for most scripts. ([MAGISK-GUIDE])

Flux rewrite implications:

- package a minimal module-local `service.sh` that resolves `MODDIR`, checks the disable flag, and `exec`s or backgrounds `fluxd daemon`;
- avoid installing a separate global service script during `customize.sh`;
- let `fluxd` wait on Android readiness using properties/netlink/files as appropriate instead of shell polling loops;
- keep `post-fs-data.sh` empty unless an operation truly must occur before Zygote and is safe inside Magisk's blocking deadline;
- make `uninstall.sh` request best-effort Flux cleanup, but also make kernel-object cleanup recoverable on the next boot if uninstall-time execution is interrupted;
- use a tiny `action.sh` or WebUI bridge that talks to `fluxd`, not one that independently manipulates firewall state.

## 9. Recommended Flux component split

### 9.1 `fluxd` owns

- process supervision and PID/pidfd identity;
- boot/readiness state and Magisk enable/disable transitions;
- desired configuration parsing, schema migration, validation, redaction, and generation hashes;
- kernel capability inventory and behavioral probes;
- rtnetlink link/address/route/rule monitoring;
- Android package/shared-UID/user resolution;
- nftables, iptables, ipset, policy-routing, sysctl, and TUN transactions;
- address synchronization currently handled by `addrsyncd`;
- transaction journal, rollback, stale-object recovery, and exact cleanup;
- Sing-Box config rendering, preflight, launch, readiness, reload, and drain;
- private control API, structured events, metrics, and diagnostics;
- asset/rule-set update orchestration if Flux owns those URLs.

### 9.2 Sing-Box owns

- proxy protocol implementations and transports;
- outbound groups, health checks, and selection;
- Sing-Box route/DNS rule evaluation;
- DNS transports/cache/fake-IP when configured in Sing-Box;
- system/gVisor/mixed userspace stack when Sing-Box owns the TUN inbound;
- Clash-compatible API and dashboard data;
- per-connection metadata emitted through its APIs/logs.

### 9.3 Shell owns only

- Magisk installer customization that cannot be expressed by the standard installer;
- module-local boot entrypoint;
- disable/uninstall glue that may invoke `fluxd cleanup --offline` but never implements networking
  policy or removes kernel objects itself;
- ABI selection/copy at install time if needed.

## 10. Proposed control and lifecycle contract

### 10.1 Private control API

Use a Unix-domain socket under `/data/adb/flux/run`, with peer-credential checks and restrictive mode. A compact framed protocol, JSON-RPC, or protobuf is acceptable; local debuggability matters more than network interoperability. Suggested operations:

- `GetStatus`, `WatchEvents`, `GetCapabilities`, `GetActiveGeneration`;
- `ValidateConfig`, `PlanConfig`, `ApplyConfig`, `Rollback`;
- `Start`, `Stop`, `Reload`, `Resync`, `Recover`;
- `ListKernelObjects`, `RunProbe`, `CollectDiagnostics`;
- `UpdateAssets`, `FlushDnsState`, `SetSelector`, `SetClashMode`;
- `GetConnections`, `CloseConnection`, `CloseAllConnections` (forwarded to Sing-Box where available).

All mutating requests should accept an idempotency key and return an operation ID. Long operations should stream state transitions rather than block an unstructured shell process.

### 10.2 Readiness

“PID exists” and “port is listening” are insufficient. A Sing-Box child is ready only after:

- its PID still matches the owned process handle;
- expected listener/TUN resources exist;
- the Clash or private health endpoint responds with the expected version/generation, when enabled;
- a loop-prevention probe confirms an outbound test socket does not re-enter capture;
- required routes/rules/firewall objects match the active generation;
- DNS capture/resolution passes an optional profile-specific smoke test.

### 10.3 TPROXY generation swap

Recommended sequence:

1. parse and validate desired config;
2. probe required backend features;
3. allocate a candidate generation ID and, where feasible, a new internal TPROXY port;
4. render candidate Sing-Box config and run `sing-box check`;
5. create inactive nftables chains/maps or iptables chains and candidate policy routes;
6. launch candidate Sing-Box and verify functional readiness;
7. atomically switch one stable jump/map to the candidate generation;
8. persist the `Activating` record and run mandatory post-cutover engine, kernel-object, route, mark, loop-prevention, and family checks;
9. publish the authoritative `Active` record and `active.json` only after those checks pass;
10. stop admitting new flows to the old generation;
11. drain or time out old connections;
12. retire old kernel objects and child, retaining its immutable record as the rollback candidate.

With legacy iptables, the atomicity is weaker, but `iptables-restore --noflush` can still install a complete chain set before switching the parent jump.

### 10.4 Native TUN reload

If Sing-Box owns the TUN, full dual-generation handoff is usually unavailable. Use:

1. complete config/kernel preflight;
2. retain the current generation untouched until all non-binding steps pass;
3. stop capture admission or install a short fail-safe bypass;
4. stop old Sing-Box and remove only its generation's TUN routes/rules;
5. start the candidate and verify;
6. on failure, restart the prior known-good config and restore its recorded kernel state;
7. report the outage duration and rollback result.

A future advanced mode can have `fluxd` own the TUN FD and attach an engine through a stable FD/IPC contract, inspired by SFA, tun-rs, and HEV. That is the path to safer engine restarts without recreating the interface.

## 11. Capability tiers for a 5.10 minimum

Kernel version is recorded for diagnostics and coarse gating, but feature selection is the conjunction of version, config/module evidence, userspace availability, SELinux permission, and a behavioral probe.

| Tier | Eligibility | Datapath | Required fallback |
|---|---|---|---|
| A: baseline | Linux/Android kernel `>= 5.10`; native TUN and/or required xtables operations probe successfully | iptables TPROXY for TCP+UDP where available; REDIRECT for TCP otherwise; native TUN as full-protocol fallback; ipset optional | Must provide functional proxy service without nftables/eBPF |
| B: nftables | nf_tables netlink transaction, required hooks/expressions/sets/maps, and permissions probe successfully | `inet` table, atomic batches, sets/maps, optional NFQUEUE pre-match | Fall back to Tier A without changing policy semantics |
| C: `xt_bpf` | Android/Linux 5.10 eligibility plus exact maps, pinned socket-filter, iptables revision-1 extension, SELinux, packet-context, canary, and cleanup probes | observation, then proxy-positive matching in Flux-owned xtables chains | Remove the optional match and retain the complete Tier A classifier |
| D: advanced TC/cgroup eBPF | recommended dae-style eligibility `>= 5.17`, then exact hook/program/helper/map/BTF or no-CO-RE strategy, full ancestor-chain attach flags, qdisc ownership, and permissions pass | TUN observation; later per-domain mark/cache acceleration; device-qualified socket-assignment research | Detach and revert to Tier B/A/C after verified failure |
| E: newer-helper acceleration | feature-specific probes, including TCX at 6.6+ or netfilter BPF at 6.4+ | improved attachment lifecycle or narrow experiments | Never required for correctness |

Probe examples:

- TUN: open correct device, create a temporary named TUN, query flags, set nonblocking, remove it;
- nftables: create/delete a private table with the exact required family, chains, set/map types, and expressions;
- xtables: install/delete a private temporary chain containing the exact target/match, not just read `/proc/config.gz`;
- ipset: create/swap/destroy the exact `hash:net` families required;
- policy routing: add/delete a private rule/table in the reserved Flux range and verify dump results;
- NFQUEUE: bind a private queue and test queue expression acceptance without capturing production traffic;
- `xt_bpf`: create maps, load/pin the exact socket filters, reference them in private IPv4/IPv6 OUTPUT/PREROUTING chains, send canary packets, inspect counters/UID context, delete rules, then unpin;
- TC/cgroup eBPF: inventory foreign programs and attach flags, load minimal programs for each type/helper/map, and attach/query/detach only at a disposable or controlled hook;
- offload: negotiate TUN flags/ioctls, then run a packet-format smoke test before enabling batch/GSO paths.

Probe results should be cached per boot and invalidated after kernel/module changes or a failed operation.

## 12. Adoption decision matrix

| Source pattern | Decision | Reason |
|---|---|---|
| Sing-Box staged component lifecycle | Adopt | Maps cleanly to Rust traits and ordered start/close with error aggregation |
| Sing-Box CLI pre-check before reload | Adopt, strengthen | Necessary but not sufficient; add candidate readiness and rollback |
| Sing-Box Clash API for dashboards | Adopt narrowly | Strong compatibility surface; not authoritative control/reload |
| Sing-Tun route/interface/package models | Reimplement in Rust | High-value Android/Linux knowledge; avoid Go dependency in `fluxd` |
| Sing-Tun nftables sets/maps and NFQUEUE pre-match | Reimplement selectively | Strong datapath concepts; runtime-gate on Android |
| Sing-Tun `GOOS=android` nftables exclusion | Reject | Capability should be probed, not assumed |
| SFA external TUN FD/platform interface | Plan as future engine contract | Enables safer ownership separation and unrooted mode |
| Box4/AndroidTProxyShell compatibility profiles | Adopt semantics | Broad device knowledge; replace shell mutation with transactions |
| Box4 global service.d installation/hard-coded paths | Reject | Conflicts with current Magisk guidance |
| tun2socks global engine | Reject | Poor isolation and reloadability |
| gVisor stack through Sing-Box | Adopt as selectable engine feature | Mature and already integrated |
| Direct gVisor embedding in `fluxd` | Defer | Go runtime/FFI and binary-size complexity |
| tun-rs FD/async/interruption API shape | Adopt or wrap | Good Rust ergonomics; Android backend needs work |
| smoltcp as default proxy stack | Reject for production default | Documented TCP feature gaps |
| HEV's small FD/config/quit/stats embedding contract | Adopt as interface inspiration | Clean engine boundary |
| dae tc/cgroup map architecture | Prototype in optional tier | High performance potential; kernel and licensing constraints |
| dae staged generation handoff | Adopt conceptually | Best reload model among inspected projects |

## 13. Licensing and provenance notes

| Dependency/source | Safe high-level use | Direct-copy concern |
|---|---|---|
| Sing-Box / Sing-Tun / SFA | Run executable, study behavior, interoperate through documented config/APIs | GPL source-copy obligations; Sing-Box/SFA additional naming term; linking creates combined-work questions |
| Magisk / Box4 / AndroidTProxyShell | Follow documented module contract; reimplement compatible behavior | GPL provenance and preservation of notices/source obligations |
| tun2socks / HEV | MIT concepts or code with notice | Preserve copyright/license text |
| gVisor / tun-rs | Apache-2.0 concepts or code | Preserve notices; review patent/license requirements |
| smoltcp | 0BSD concepts or code | Minimal notice burden, still preserve provenance |
| dae | Study architecture and independently implement | AGPL network-source obligations can apply to derivatives; do not copy casually |

Maintain a `THIRD_PARTY.md`/SBOM in the implementation phase, record exact versions and build flags, and distinguish “inspired by” clean implementations from copied/adapted files.

## 14. Validation plan derived from the research

Test at least these kernel/device classes:

- Android GKI-derived 5.10 with minimal vendor netfilter;
- 5.10 custom kernel with nftables exposed;
- 5.15 Android kernel;
- 5.17+ kernel with partial BPF but no BTF;
- Android/common 6.1+ with nftables and newer BPF;
- devices with active Android VPN, Private DNS, work profile, multiple users, hotspot, USB tethering, Wi-Fi/mobile handoff, and IPv6-only/NAT64 networks.

For each backend, verify:

- cold boot, enable/disable toggle, crash recovery, uninstall cleanup;
- config syntax failure, bind failure, TUN failure, firewall transaction failure, and rollback;
- outbound loop prevention during every network transition;
- TCP/UDP/ICMP, IPv4/IPv6, fragmented packets, PMTU, DNS UDP/TCP, DoH/Private DNS coexistence;
- per-package/shared-UID/multi-user policy;
- hotspot client source preservation and MAC policy where supported;
- rule-set update failure and cache fallback;
- fake-IP persistence and restart behavior;
- API authentication and non-loopback exposure;
- memory pressure, queue saturation, NFQUEUE fail behavior, and eBPF map overflow;
- stale kernel objects after `SIGKILL`/reboot and deterministic recovery.

Benchmark separate dimensions rather than a single throughput number: CPU per Gbit, p50/p99 connect latency, UDP packet rate/loss, DNS p50/p99, memory/RSS, wakeups, battery impact, reload interruption time, and direct-bypass overhead.

## 15. Questions carried into the detailed blueprint

The architecture phase resolved the investigation questions as follows:

1. Ship `EngineOwnedTun`; defer `FluxOwnedTunFd` until an exact Sing-Box version provides a documented, tested FD-handoff contract.
2. Use staged dual-child cutover for TPROXY where the Engine Capability Profile permits it; accept a bounded, measured fail-open stop/swap window for engine-owned TUN reload.
3. Do not add a generic Clash API proxy. Keep any enabled API loopback-only with generated authentication and expose supported status/selector operations through typed Flux authorization.
4. Prefer native nftables only after the full TPROXY canary succeeds; fall back to one coherent xtables implementation, then managed TUN where it satisfies Traffic Scope.
5. Prototype eBPF observation first. Acceleration remains optional and must preserve a complete non-eBPF correctness path.
6. Move subscription and rule-set download, validation, content addressing, and known-good rollback into `fluxd`; Sing-Box consumes validated local assets.
7. Keep global Private DNS changes disabled by default and require an explicit, reversible policy choice with visible diagnostics.

These decisions are specified in the [rewrite blueprint](../architecture/fluxd-blueprint.md) and [technical specification](../architecture/fluxd-technical-specification.md).

## Primary-source index

### Sing-Box

- [SB-REPO] Repository snapshot (`testing` commit `725d2254dc067189ac871291b817cb979cf7901e`): https://github.com/SagerNet/sing-box/tree/725d2254dc067189ac871291b817cb979cf7901e
- Stable tag `v1.13.14` (`25a600db24f7680ad9806ce5427bd0ab8afe1114`): https://github.com/SagerNet/sing-box/tree/v1.13.14
- [SB-TUN-DOC] TUN documentation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/inbound/tun.md and rendered docs https://sing-box.sagernet.org/configuration/inbound/tun/
- [SB-ROUTE-DOC] Route documentation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/route/index.md and rendered docs https://sing-box.sagernet.org/configuration/route/
- [SB-DNS-DOC] DNS documentation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/dns/index.md and rendered docs https://sing-box.sagernet.org/configuration/dns/
- [SB-DNS-ACTIONS] DNS rule actions: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/dns/rule_action.md
- [SB-RULESET-DOC] Rule-set documentation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/rule-set/index.md and rendered docs https://sing-box.sagernet.org/configuration/rule-set/
- [SB-RULESET-REMOTE] Remote rule-set implementation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/route/rule/rule_set_remote.go
- [SB-CLASH-DOC] Clash API documentation: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/docs/configuration/experimental/clash-api.md and rendered docs https://sing-box.sagernet.org/configuration/experimental/clash-api/
- [SB-CLASH-SERVER] Clash API server/routes/authentication: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/experimental/clashapi/server.go
- [SB-CLASH-CONFIGS] Clash `/configs` behavior: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/experimental/clashapi/configs.go#L53-L71
- [SB-CLI-RUN] CLI signals/reload loop: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/cmd/sing-box/cmd_run.go#L169-L199
- [SB-CLI-CHECK] Config check: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/cmd/sing-box/cmd_check.go
- [SB-BOX] Box staged start/close: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/box.go#L466-L625
- [SB-STARTED-SERVICE] Libbox/daemon start-or-reload: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/daemon/started_service.go#L181-L253
- [SB-DAEMON-PROTO] Started-service gRPC schema: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/daemon/started_service.proto
- [SB-MANAGED-PROTO] Managed-service gRPC schema: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/daemon/managed_service.proto
- [SB-COMMAND-SERVER] Libbox command server: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/experimental/libbox/command_server.go
- License: https://github.com/SagerNet/sing-box/blob/725d2254dc067189ac871291b817cb979cf7901e/LICENSE

### Sing-Tun

- `dev` snapshot `375e9ae639c53844d31fe4a319de75d6606ecdce`: https://github.com/SagerNet/sing-tun/tree/375e9ae639c53844d31fe4a319de75d6606ecdce
- Stable `v0.8.11`: https://github.com/SagerNet/sing-tun/tree/v0.8.11
- [ST-TUN] Core TUN options/interfaces: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/tun.go
- [ST-TUN-LINUX] Linux/Android TUN creation, routes, rules, updates: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/tun_linux.go
- [ST-RULES] Android UID/package and route-range compilation: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/tun_rules.go
- [ST-PACKAGES] Android package XML/ABX reader: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/packages_android.go
- [ST-MONITOR-ANDROID] Android policy-rule/default-interface detection: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/monitor_android.go
- [ST-REDIRECT] Android nftables exclusion and iptables fallback: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/redirect_linux.go#L51-L177
- [ST-NFT] nftables setup/update/cleanup: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/redirect_nftables.go
- [ST-NFQUEUE] NFQUEUE pre-match: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/nfqueue_linux.go#L253-L296
- [ST-STACK] Stack selection: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/stack.go
- [ST-MIXED] Mixed system-TCP/gVisor-UDP implementation: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/stack_mixed.go
- [ST-GVISOR] gVisor stack setup: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/stack_gvisor.go
- License: https://github.com/SagerNet/sing-tun/blob/375e9ae639c53844d31fe4a319de75d6606ecdce/LICENSE

### Android and Magisk projects

- SFA snapshot `edd0d9cafb56aa2edb65429f4812d7017665b661`: https://github.com/SagerNet/sing-box-for-android/tree/edd0d9cafb56aa2edb65429f4812d7017665b661
- [SFA-BOX-SERVICE] Android service/libbox lifecycle: https://github.com/SagerNet/sing-box-for-android/blob/edd0d9cafb56aa2edb65429f4812d7017665b661/app/src/main/java/io/nekohasekai/sfa/bg/BoxService.kt
- [SFA-VPN] `VpnService` TUN FD, routes, apps, and socket protection: https://github.com/SagerNet/sing-box-for-android/blob/edd0d9cafb56aa2edb65429f4812d7017665b661/app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt#L52-L187
- SFA default-network monitor: https://github.com/SagerNet/sing-box-for-android/blob/edd0d9cafb56aa2edb65429f4812d7017665b661/app/src/main/java/io/nekohasekai/sfa/bg/DefaultNetworkMonitor.kt
- [MAGISK-GUIDE] Official module/boot-script guide at `14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c`: https://github.com/topjohnwu/Magisk/blob/14ea5cfb4a5771c742f7c3fd1e685bdbfac7aa8c/docs/guides.md#L1-L267
- Box4Magisk snapshot `1aabf31ad837b6ebff11d46fda585f63230de9f8`: https://github.com/CHIZI-0618/box4magisk/tree/1aabf31ad837b6ebff11d46fda585f63230de9f8
- [BOX4-README] Box4Magisk behavior/configuration: https://github.com/CHIZI-0618/box4magisk/blob/1aabf31ad837b6ebff11d46fda585f63230de9f8/README.md
- [BOX4-SERVICE] Core lifecycle/hotspot TUN rules: https://github.com/CHIZI-0618/box4magisk/blob/1aabf31ad837b6ebff11d46fda585f63230de9f8/box/scripts/box.service
- [BOX4-TPROXY] Transparent-proxy script: https://github.com/CHIZI-0618/box4magisk/blob/1aabf31ad837b6ebff11d46fda585f63230de9f8/box/scripts/box.tproxy
- AndroidTProxyShell snapshot `303f3c66db9ce9b052dbacfa5a58957fd1943d84`: https://github.com/CHIZI-0618/AndroidTProxyShell/tree/303f3c66db9ce9b052dbacfa5a58957fd1943d84
- [ATP-README] AndroidTProxyShell features: https://github.com/CHIZI-0618/AndroidTProxyShell/blob/303f3c66db9ce9b052dbacfa5a58957fd1943d84/README.md
- [ATP-SCRIPT] AndroidTProxyShell implementation: https://github.com/CHIZI-0618/AndroidTProxyShell/blob/303f3c66db9ce9b052dbacfa5a58957fd1943d84/tproxy.sh

### TUN and network stacks

- tun2socks snapshot `dda1b1058db86dd0ef40d1b007de0ce86cf16a46`: https://github.com/xjasonlyu/tun2socks/tree/dda1b1058db86dd0ef40d1b007de0ce86cf16a46
- [T2S-STACK] gVisor stack construction: https://github.com/xjasonlyu/tun2socks/blob/dda1b1058db86dd0ef40d1b007de0ce86cf16a46/core/stack.go
- [T2S-ENGINE] Engine lifecycle, marks, bind, hooks: https://github.com/xjasonlyu/tun2socks/blob/dda1b1058db86dd0ef40d1b007de0ce86cf16a46/engine/engine.go
- [T2S-REST] REST/statistics API: https://github.com/xjasonlyu/tun2socks/blob/dda1b1058db86dd0ef40d1b007de0ce86cf16a46/restapi/server.go
- [GVISOR-README] gVisor snapshot `37973046f14084385abe058597a5acd0cb1a5478`: https://github.com/google/gvisor/blob/37973046f14084385abe058597a5acd0cb1a5478/README.md
- [GVISOR-TCPIP] Netstack package and separable-library build note: https://github.com/google/gvisor/tree/37973046f14084385abe058597a5acd0cb1a5478/pkg/tcpip and https://github.com/google/gvisor/blob/37973046f14084385abe058597a5acd0cb1a5478/pkg/tcpip/BUILD#L61-L67
- tun-rs `2.8.7`, commit `5d97ac38a505f47a7161b24f714318c84e3dc024`: https://github.com/tun-rs/tun-rs/tree/2.8.7
- [TUNRS-README] tun-rs features/Android FD API: https://github.com/tun-rs/tun-rs/blob/5d97ac38a505f47a7161b24f714318c84e3dc024/README.md
- [TUNRS-PLATFORM] Platform conditional compilation and raw FD API: https://github.com/tun-rs/tun-rs/blob/5d97ac38a505f47a7161b24f714318c84e3dc024/src/platform/mod.rs#L1-L25 and https://github.com/tun-rs/tun-rs/blob/5d97ac38a505f47a7161b24f714318c84e3dc024/src/platform/mod.rs#L165-L179
- [TUNRS-LINUX] Linux offload/batch backend: https://github.com/tun-rs/tun-rs/blob/5d97ac38a505f47a7161b24f714318c84e3dc024/src/platform/linux/device.rs
- smoltcp snapshot `764ef3a8cc38d543f407555772f495d4810c8895`, crate 0.13.1: https://github.com/smoltcp-rs/smoltcp/tree/764ef3a8cc38d543f407555772f495d4810c8895
- [SMOLTCP-README] Features and explicit omissions: https://github.com/smoltcp-rs/smoltcp/blob/764ef3a8cc38d543f407555772f495d4810c8895/README.md#L9-L139
- HEV snapshot `c6e4c72246fb0f20bda299f0efc7814bb3098d57`: https://github.com/heiher/hev-socks5-tunnel/tree/c6e4c72246fb0f20bda299f0efc7814bb3098d57
- [HEV-README] Features/config/low-memory guidance: https://github.com/heiher/hev-socks5-tunnel/blob/c6e4c72246fb0f20bda299f0efc7814bb3098d57/README.md
- [HEV-API] Embedding API: https://github.com/heiher/hev-socks5-tunnel/blob/c6e4c72246fb0f20bda299f0efc7814bb3098d57/include/hev-socks5-tunnel.h

### dae / eBPF

- dae `v2.0.0`, commit `fee4c8661059bfc5a60ca8eaad59a1030cb35128`: https://github.com/daeuniverse/dae/tree/v2.0.0
- [DAE-HOW] Working-principle documentation: https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/docs/en/how-it-works.md
- [DAE-REQ] Kernel version/config requirements: https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/docs/en/README.md#L5-L63
- [DAE-BPF] tc/cgroup programs and map definitions: https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/control/kern/tproxy.c
- [DAE-RELOAD] Staged reload/handoff and retirement: https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/cmd/run.go#L448-L650 and https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/cmd/run.go#L911-L940
- License: https://github.com/daeuniverse/dae/blob/fee4c8661059bfc5a60ca8eaad59a1030cb35128/LICENSE
