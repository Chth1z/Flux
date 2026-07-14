# Flux Transparent Networking

Flux manages transparent proxy behavior on a rooted Android device while preserving the device's direct-connect behavior outside the configured traffic scope.

## State and lifecycle

**Desired State**:
The complete user-requested Flux behavior, including whether Flux is enabled, which traffic is in scope, and which proxy behavior should apply.
_Avoid_: Settings, target configuration

**Observed State**:
The facts Flux can verify about the proxy engine, Android networks, and Flux-owned networking state at a point in time.
_Avoid_: Current config, runtime cache

**Reconciliation**:
The act of moving Observed State toward Desired State while repairing partial or externally disturbed changes.
_Avoid_: Restart, apply script

**Generation**:
An immutable, uniquely identified compilation of Desired State that Flux can prepare, activate, verify, and retire as one logical revision.
_Avoid_: Cache version, rules file

**Degraded State**:
A running state in which Flux intentionally provides a documented subset of Desired State because the device lacks an optional capability.
_Avoid_: Partial success, fallback mode

## Traffic model

**Traffic Scope**:
The set of device, application, user, interface, address-family, and tethering traffic that Flux is allowed to classify.
_Avoid_: Match list, app list

**Traffic Domain**:
A bounded, explicitly anchored and selector-disjoint portion of Traffic Scope, such as residual local OUTPUT for one family or forwarded traffic from one exact tether ingress. Backend planning may differ by domain only after exhaustive coverage and non-overlap are proven.
_Avoid_: Rule bucket, interface case

**Capture Policy**:
The ordered decisions that determine whether in-scope traffic is sent to the Proxy Engine or continues directly.
_Avoid_: Firewall rules, routing script

**Capture Program**:
A deterministic backend-neutral compilation of Capture Policy into separate ordered local-OUTPUT and forwarded-ingress programs, with a canonical mandatory safety baseline, optional inventory-host provenance, bounded resources, and a semantic digest. A Capture Program describes decisions; a backend renderer and an authorized Generation are still required before it can become device state.
_Avoid_: Restore file, active rules

**Shadow Capture Artifact**:
An observation-only Phase 2 Capture Program used to explain and compare compatibility semantics before a native renderer or activation path exists. It has no Generation ID, Planning Authority, writer token, ownership lease, prepared/active conversion, or functional-canary authority.
_Avoid_: Dry-run Generation, staged rules

**Bypass Policy**:
The portion of Capture Policy that identifies traffic which remains direct. It distinguishes mandatory loop/device-local safety exclusions from configurable private, CGNAT, and other special-use direct defaults.
_Avoid_: Exclusion list, direct rules

**Capture Path**:
The selected device mechanism that realizes Capture Policy for a Generation.
_Avoid_: Proxy mode, rule backend

**Proxy Engine**:
The data-plane program that accepts captured traffic and executes proxy, DNS, and outbound-routing behavior.
_Avoid_: Core, daemon

**Compatibility Oracle**:
The frozen, still-executed shell networking implementation and its pinned semantic fixtures used to review Rust replacement behavior during the bridge releases. It remains the sole networking writer until ownership transfers through a component-specific cutover gate; it is not the final architecture.
_Avoid_: Second backend, permanent shell path

## Device model

**Network Epoch**:
A period during which the Android network topology relevant to Flux is stable; a material topology change begins a new epoch.
_Avoid_: Interface event, resync window

**Capability Profile**:
Verified facts about what the current device permits Flux to use, distinct from what its kernel version or configuration merely claims to support.
_Avoid_: Kernel flags, device preset

**Engine Capability Profile**:
Verified, version-qualified facts about what the exact Proxy Engine binary and configuration dialect permit Flux to stage, supervise, and hand off.
_Avoid_: Sing-Box version check, engine feature flags

**Kernel Extension Profile**:
Freshness-bound identity, protocol, semantics, and canary evidence for an already-loaded reviewed OEM/custom-kernel extension. It never authorizes Flux to load or unload a module and never replaces a conventional correctness path.
_Avoid_: Module detected, kernel plugin available

**Backend Plan**:
The explainable selection of a Capture Path and supporting mechanisms for one Capability Profile, Engine Capability Profile, and Desired State.
_Avoid_: Auto mode, fallback chain

**Managed Object**:
A device networking object that Flux can identify as its own, reconstruct from a Generation, and safely remove without disturbing Android-owned state.
_Avoid_: Flux rule, temporary state

**Planning Authority**:
Freshness-bound positive evidence that permits a later pure planning step while exposing every remaining prerequisite; it is never an activation lease or mutation capability.
_Avoid_: Approval, safe-to-apply flag

**Device-qualified Mark Grant**:
An externally established cooperative device-policy assertion binding one exact mark candidate to its topology, Capability Profile, boot, network namespace, policy artifact, revision, and storage planes.
_Avoid_: Free bits, expert override

**Mark Census**:
A bounded, consumed point-in-time assertion covering every required mark source and packet, socket, and conntrack plane, including explicit complete absence.
_Avoid_: Mark cache, available-bit scan

## Configuration sources

**Subscription Snapshot**:
An immutable, validated set of proxy endpoints produced from one subscription retrieval before it is merged into Desired State.
_Avoid_: Downloaded config, node file
