# Samsung SM-S9180 FZDP observed-behavior mark policy v1

## Assurance

This reviewed policy has assurance class `ExactArtifactObservedBehavior`. It is not source-
authenticated and must not be described as proving Samsung or AOSP source provenance. The exact
runtime artifacts and bounded behavior below are the authority boundary.

## Stable selector

- Android product: `samsung/dm3qzhx/dm3q`
- Android build: `samsung/dm3qzhx/dm3q:16/BP4A.251205.006/S9180ZHU7FZDP:user/release-keys`
- Vendor build: `samsung/dm3qzhx/dm3q:13/TP1A.220624.014/S9180ZHU7FZDP:user/release-keys`
- Security patch: `2026-04-05`
- Kernel build: `5.15.207-Qkernel-ga2c4e0b796 #3 SMP PREEMPT Fri May 22 14:03:17 UTC 2026`
- SELinux policy: SHA-256
  `d90a3e32fc844a714bf37ceadc6ea5b7574862900e43f1419e37a008dd63c01f`, 2,825,193 bytes
- `/system/bin/netd`: SHA-256
  `aabeab176d29a2ef299fdda318002dde253e00a1c47506f3af062b73112d0add`, 1,033,576 bytes
- active Connectivity APEX: SHA-256
  `ec4d66b24a5d7bf2fe4f0aff2204dd51b4049748569ee0c0bc850104bf0d7549`, 36,827,136 bytes

The executing Flux ELF, verified boot identity, boot ID, and network namespace remain runtime
freshness bindings. They are deliberately not compile-time selector fields. Any selector mismatch
returns the generic zero-grant policy.

## Semantic policy

- `AndroidNetdSourceProfile::AospNetd20250324` is used only as the reviewed RPDB and netd-behavior
  grammar. It is not a provenance claim for the Samsung `netd` binary.
- Candidate mask: `0x03000000`
- Proxy value: `0x01000000`
- Bypass value: `0x02000000`
- Required census planes: packet, socket, and conntrack

Exact selection creates only a device-policy assertion. Planning still requires a complete current
27-cell census, an exact topology classified with the selected semantic profile, and all boot,
namespace, tool, ownership-journal, and collector bindings.

## Ordered writes

Version 1 admits no ordered-late-write exception. The observed Android INPUT writers and Samsung
IPv6 POSTROUTING full-mask writers therefore continue to reject planning until a later reviewed
revision binds every exact family, hook, child chain, hook/rule ordinal, and selector digest and
proves packet-only lifetime, no earlier matching overlap, and placement after Flux's final routing
or capture use. Unknown, earlier, socket, conntrack, or transferred overlaps always reject.

Even a future structural ordered-write qualification remains below activation. Listener/observer
continuity, mark-preservation and VPN/netd coexistence canaries, rollback, recovery, and verified
cleanup are mandatory before writer transfer.

## Operational boundary

Qualification may inspect only the facts named by the checked-in collector and may mutate only
generated owner-only Flux test paths or Flux-owned kernel objects under a reviewed canary. It must
not reboot, flash, remount, change SELinux or persistent settings, install packages, or inspect
unrelated application/user data. Every mutation must end with independent absence and baseline
drift checks.
