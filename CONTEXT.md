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

**Capture Policy**:
The ordered decisions that determine whether in-scope traffic is sent to the Proxy Engine or continues directly.
_Avoid_: Firewall rules, routing script

**Bypass Policy**:
The portion of Capture Policy that identifies traffic which must remain direct, including loop prevention and device-local connectivity.
_Avoid_: Exclusion list, direct rules

**Capture Path**:
The selected device mechanism that realizes Capture Policy for a Generation.
_Avoid_: Proxy mode, rule backend

**Proxy Engine**:
The data-plane program that accepts captured traffic and executes proxy, DNS, and outbound-routing behavior.
_Avoid_: Core, daemon

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

**Backend Plan**:
The explainable selection of a Capture Path and supporting mechanisms for one Capability Profile, Engine Capability Profile, and Desired State.
_Avoid_: Auto mode, fallback chain

**Managed Object**:
A device networking object that Flux can identify as its own, reconstruct from a Generation, and safely remove without disturbing Android-owned state.
_Avoid_: Flux rule, temporary state

## Configuration sources

**Subscription Snapshot**:
An immutable, validated set of proxy endpoints produced from one subscription retrieval before it is merged into Desired State.
_Avoid_: Downloaded config, node file
