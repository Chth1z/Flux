# Authentication boundary for the observed Samsung Android netd artifacts

- Status: Q2.2 source-authentication decision; negative result
- Target: sanitized `physical-arm64-01` qualification profile; no hardware serial or raw boot ID
  retained here
- Source profile under review: `AndroidNetdSourceProfile::AospNetd20250324`, pinned to AOSP netd
  commit `e11b8688b1f99292ade06f89f957c1f7e76ceae9`
- External sources accessed: 2026-07-27
- Source policy: AOSP repositories and official Android documentation only
- Device boundary: this review used previously collected, sanitized evidence and performed no
  device access or mutation

## Conclusion

**Fact.** The observations identify the runtime files byte-for-byte by SHA-256 and size. They also
show a dual-stack `routectrl_mangle_INPUT` topology and incoming-mark mask compatible with the
pinned AOSP source. The system build identifier belongs to the Android 16 r4 release family, while
the pinned netd tree is byte-identical to the Android 16 r1 netd tree. [A1] [A2] [A3] [A4]

**Inference.** None of those facts authenticates the Samsung `/system/bin/netd` or active
Connectivity APEX to exact Git commit `e11b8688...`. The same rule and mask occur across multiple
AOSP revisions, the ELF Build ID is derived from output content rather than a source revision, and
the APEX version is a release-supplied package version rather than a public commit identifier.
The unlocked/orange Verified Boot state also prevents the on-device observation from serving as a
manufacturer-authenticated supply-chain statement.

**Recommendation.** Do not add this target to the positive reviewed Android mark-policy catalog and
do not use the artifacts to assert `AospNetd20250324` as authenticated source. Keep the catalog at
zero grant. If Flux needs to consume the compatible live semantics before exact source provenance
is available, represent that conclusion separately as an `ObservedBehaviorProfile`; do not weaken
the meaning of the source-pinned profile.

## Observed evidence

The following values came from the bounded Q2.1 profile collection and subsequent read-only
artifact inspection. They are exact selectors for the observed runtime state, not source
provenance:

| Observed object or field | Exact observation | What it establishes |
|---|---|---|
| Loaded SELinux policy | SHA-256 `d90a3e32fc844a714bf37ceadc6ea5b7574862900e43f1419e37a008dd63c01f`; 2,825,193 bytes | Exact policy bytes used by the profile selector |
| `/system/bin/netd` | SHA-256 `aabeab176d29a2ef299fdda318002dde253e00a1c47506f3af062b73112d0add`; 1,033,576 bytes | Exact observed ELF bytes |
| `netd` ELF Build ID | `fb8c21b22c6e934e9f132623d1af3237` | Secondary artifact lookup key only |
| Active Connectivity APEX | Module `com.android.tethering`; version `371021120`; SHA-256 `ec4d66b24a5d7bf2fe4f0aff2204dd51b4049748569ee0c0bc850104bf0d7549`; 36,827,136 bytes | Exact observed package bytes and declared runtime version |
| System release context | API 36; build ID `BP4A.251205.006`; security patch level `2026-04-05` | Android 16 r4 release-family and patch-level context |
| Partition context | Samsung system/product identity plus a separately reported Android 13-family vendor fingerprint | A mixed partition history permitted by Android's partition model |
| Boot state | Verified Boot orange; device unlocked | Freshness context, but not an authenticated OEM trust boundary |
| Live incoming-mark shape | IPv4 and IPv6 `routectrl_mangle_INPUT`; three interface-scoped writers; mask `0x7fefffff`; no unknown child rules in the bounded observation | Strong behavior-compatibility evidence |

**Fact.** Whole-file SHA-256 is stronger than the ELF Build ID for selecting the exact observed
file. Neither value carries an authenticated statement about the source manifest, downstream
patches, compiler, link inputs, or build configuration.

**Inference.** Re-observing the same values can bind later evidence to this exact runtime profile.
It cannot convert the profile into a positive source-provenance claim.

## Source snapshot and release-family comparison

| Source snapshot | Commit | Tree | Relevant result |
|---|---|---|---|
| Repository pin dated 2025-03-24 | `e11b8688b1f99292ade06f89f957c1f7e76ceae9` | `9be804fefb810053f280f61bbe68f0e60736a365` | Source snapshot named by `AospNetd20250324` [A1] |
| `android-16.0.0_r1` netd | `68859d33e9bfe9ddb1afdc282905c63339c1928d` | `9be804fefb810053f280f61bbe68f0e60736a365` | Repository content is identical to the pin [A2] |
| `android-16.0.0_r4` netd | `8d4a0b7420e67cec340dc37a88815d99a16abfa7` | `e715331f2d071b3c262e50c3b20caaa0eaec25bc` | Different later repository tree; relevant incoming-mark implementation remains the same [A3] [N6] |

**Fact.** The pinned commit is a Treehugger merge whose first-parent change concerns
`tests/kernel_test.cpp`, not the incoming-mark implementation. Its tree is nevertheless exactly
the tree later tagged for Android 16 r1. [A1] [A2]

**Fact.** Google's official build table maps `BP4A.251205.006` to `android-16.0.0_r4`, dated
2025-12-05. The observed Samsung build therefore points to an r4 release family, not uniquely to
the March 2025 source snapshot. [A4]

**Inference.** Tree equality proves that the pin and r1 expose the same checked-in netd content.
It does not prove which manifest, downstream patch stack, or repository revision Samsung used.
Conversely, an r4-family build string does not prove that every Samsung partition or binary was
built unmodified from the public r4 tag.

## What the live rule does and does not prove

At the pinned commit, `modifyIncomingPacketMark` constructs a `Fwmark`, sets `netId`,
`explicitlySelected`, and `protectedFromVpn`, excludes `uidBillingDone` and
`ingress_cpu_wakeup` from the write mask, and appends an interface-scoped MARK rule to
`routectrl_mangle_INPUT` for both IPv4 and IPv6. [N1] `Fwmark.h` assigns the excluded fields to
bit 20 and bit 31, so their 32-bit complement is:

```text
~(0x00100000 | 0x80000000) = 0x7fefffff
```

The pinned integration test checks that exact mask in both `iptables` and `ip6tables`. The top-level
mangle INPUT children are ordered as connection-mark restore, wakeup handling, then route control;
the controller creates those chains in declared order. [N2] [N3] [N4]

**Fact.** The final mask predates the pin. Commit `0a47ca4f...` added preservation of the ingress
CPU-wakeup bit, and Android 15 r1 already contains the same `routectrl_mangle_INPUT` rule and
`0x7fefffff` mask. Earlier commits introduced the route-control child chain and preservation of the
UID-billing bit. [N5] [N7] [N8] [N9]

**Inference.** The chain, dual-stack shape, and mask strongly support compatibility with the pinned
logic, but identify only a broad post-`0a47ca4f...` implementation family. The three observed
interfaces and their order reflect runtime network creation and are not a source-revision
fingerprint.

### Literal zero-value ambiguity (resolved by follow-up observation)

The supplied live-rule summary rendered the rules as
`--set-xmark 0x0/0x7fefffff`. Taken literally, that value is not an exact match for the cited AOSP
function: AOSP constructs a nonzero value from the network ID, explicit-selection bit, and
VPN-protection bit before applying the mask. Repository fixtures likewise use nonzero network IDs.
An xtables save/restore round trip may normalize `--set-mark` to `--set-xmark`; that spelling is not
the discrepancy. The complete numeric value is.

After this source review, a fresh explicit-serial, read-only snapshot retained the complete bounded
mark expressions without retaining unrelated traffic data. Both families exposed the same three
nonzero incoming values, respectively `0xf0065`, `0x30066`, and `0xf0067`, with mask
`0x7fefffff`. The earlier `0x0` was therefore a lossy projection rather than the literal MARK value.

**Fact.** This resolves the live-value ambiguity and strengthens behavior compatibility with the
reviewed AOSP implementation family. It still does not authenticate the binary to one source
revision. The same snapshot also found IPv6 vendor `MARK --set-xmark` operations with mask
`0xffffffff`; under Flux's current complete-census contract, those are definite candidate-field
overlaps rather than source-authentication evidence.

## Why the remaining identifiers do not authenticate source

### ELF Build ID

Android 16 Soong passes `-Wl,--build-id=md5` for device links. LLD documents Build IDs as values
calculated from output/object contents, and its implementation hashes final output sections; the
documentation explicitly does not assign a security property to the value. [B1] [B2] [B3]

**Inference.** Build ID `fb8c21b22c6e934e9f132623d1af3237` is useful for a trusted Samsung
symbol or build index, if one exists. Without such a producer mapping it cannot identify a Git
revision, and it is weaker than the already recorded full-file SHA-256 as an artifact identity.

### Build fingerprints, partitions, and patch level

AOSP describes `BUILD_FINGERPRINT` as a unique identifier for the combined product/build while
also allowing it to be overridden. The build emits partition-specific fingerprints, including the
vendor fingerprint. Android's partition model permits the generic system to be updated separately
from hardware-specific vendor code. [F1] [F2] [F3]

The April 2026 Android Security Bulletin defines `2026-04-05` as inclusion of all applicable April
5 and earlier bulletin fixes. It does not map each platform project or binary to a source commit.
[S1]

**Inference.** API level, system build ID, vendor fingerprint, and security patch level are useful
release and compatibility context. None authenticates the source of `/system/bin/netd`.

### Connectivity APEX

AOSP builds `/system/bin/netd` as the `netd` binary from `platform/system/netd`. The Connectivity
APEX is a distinct `com.android.tethering` package containing `libnetd_updatable`, Connectivity JNI,
BPF programs, and other components. Its digest is therefore important runtime-environment evidence
but is not the digest of the source or binary under review. [B4] [C1]

Connectivity's checked-in APEX manifest uses version `0` as a build-time placeholder. Soong
replaces zero with `RELEASE_DEFAULT_UPDATABLE_MODULE_VERSION` and permits an environment override.
The public Android 16 release flag inspected for the r1-era branch is `360499999`, not the observed
`371021120`. [C2] [C3] [C4]

Official APEX documentation states that the manifest name/version identifies a package, updates
compare package name and version, and an APEX is signed both at the payload AVB layer and as an
outer APK. Mainline modules can be updated outside the normal OS release cycle. [C5] [C6]

**Inference.** Version `371021120` is a release-injected package identifier, not a public
Connectivity commit ID. The two signing layers can authenticate a signer and update channel after
their keys are checked against an approved trust anchor; they still do not attest which source
revision produced the payload.

## Fail-closed evidence contract

**Recommendation.** Keep source provenance and runtime behavior as two independently required
classes. A future positive catalog entry should require all applicable fields below and return
`Unknown`/zero grant for any missing, malformed, stale, untrusted, or mismatched field.

### `AuthenticatedSourceProfile`

- Exact `/system/bin/netd` SHA-256 and byte size, with ELF Build ID as a secondary selector.
- Exact active Connectivity APEX SHA-256, byte size, name, and version.
- Outer APEX APK certificate digest, embedded APEX AVB public-key digest or key ID, and payload root
  digest, all checked against an approved producer/update trust anchor.
- A producer-signed attestation or SBOM binding those artifact digests to an exact `repo manifest
  -r`, downstream patches, build configuration, and toolchain; alternatively, a reproducible build
  from those complete inputs whose final SHA-256 matches.
- Locked/green Verified Boot with an approved vbmeta identity, or independent acquisition and
  signature verification of the exact signed firmware artifacts. Orange/unlocked on-device hashes
  alone are insufficient.

### `ObservedBehaviorProfile`

- Exact dual-stack chain declarations, hooks, complete rule order, values, masks, interfaces, and
  parent references.
- Complete RPDB, route, and 27-cell fwmark census, including packet, socket, and conntrack reads,
  writes, and transfers.
- Functional canaries for mark preservation and VPN/netd coexistence.
- One boot, network namespace, inventory snapshot, and collection generation binding every input.

**Recommendation.** Never infer an authenticated source profile from API level, build ID, security
patch level, ELF Build ID, APEX version, chain name, mask, or signer identity alone. The currently
available evidence satisfies neither a trusted artifact-to-source mapping nor the complete live
behavior contract, so Q2.2 ends with no positive profile and no mutation authority.

## Primary sources

| ID | Primary source | Relevance |
|---|---|---|
| **[A1]** | [AOSP netd commit `e11b8688...`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9) | Commit metadata, tree, parents, and message |
| **[A2]** | [AOSP netd tag `android-16.0.0_r1`](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1) | r1 commit and tree identity |
| **[A3]** | [AOSP netd tag `android-16.0.0_r4`](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r4) | r4 commit and distinct tree identity |
| **[A4]** | [Android source-code tags and builds](https://source.android.com/docs/setup/reference/build-numbers#source-code-tags-and-builds) | Official `BP4A.251205.006` to r4 mapping |
| **[N1]** | [`RouteController.cpp`, `modifyIncomingPacketMark`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/RouteController.cpp#483) | Rule value, mask, interface, chain, and dual-stack construction |
| **[N2]** | [`Fwmark.h`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/include/Fwmark.h#24) | UID-billing and ingress-wakeup bit positions |
| **[N3]** | [`binder_test.cpp`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/tests/binder_test.cpp#1738) | Exact IPv4/IPv6 rule-mask expectation |
| **[N4]** | [`Controllers.cpp`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/Controllers.cpp#94) | Parent-chain ordering and ordered child creation |
| **[N5]** | [Commit `0a47ca4f...`](https://android.googlesource.com/platform/system/netd/+/0a47ca4f15f5e66f3271fd214ecdd87fef4ae27a%5E%21/) | Introduction of ingress-wakeup preservation |
| **[N6]** | [`android-16.0.0_r4` `RouteController.cpp`](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r4/server/RouteController.cpp#483) | Relevant implementation remains unchanged in r4 |
| **[N7]** | [`android-15.0.0_r1` `RouteController.cpp`](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-15.0.0_r1/server/RouteController.cpp#483) | Same rule and mask in an earlier release |
| **[N8]** | [Commit `d78843eb...`](https://android.googlesource.com/platform/system/netd/+/d78843eb11fdde1611598fd27d347912070c0555) | Incoming mark moved into the route-control child chain |
| **[N9]** | [Commit `b9baf267...`](https://android.googlesource.com/platform/system/netd/+/b9baf26777415ce2791fd86f4dd359ac7aab596c) | Masked MARK preserving UID billing |
| **[B1]** | [Android 16 Soong device link flags](https://android.googlesource.com/platform/build/soong/+/refs/tags/android-16.0.0_r1/cc/config/global.go#190) | `--build-id=md5` configuration |
| **[B2]** | [LLD `ld.lld` documentation](https://android.googlesource.com/toolchain/llvm-project/+/97a699bf4812a18fb657c2779f5296a4ab2694d2/lld/docs/ld.lld.1#96) | Build-ID meaning and non-security boundary |
| **[B3]** | [LLD ELF writer](https://android.googlesource.com/toolchain/llvm-project/+/97a699bf4812a18fb657c2779f5296a4ab2694d2/lld/ELF/Writer.cpp#3094) | Build-ID calculation from output sections |
| **[B4]** | [AOSP netd `Android.bp`](https://android.googlesource.com/platform/system/netd/+/e11b8688b1f99292ade06f89f957c1f7e76ceae9/server/Android.bp#154) | `/system/bin/netd` build target and source graph |
| **[F1]** | [AOSP build fingerprint construction](https://android.googlesource.com/platform/build/+/refs/tags/android-16.0.0_r4/core/config.mk#1305) | Combined build identifier and override support |
| **[F2]** | [AOSP partition property generation](https://android.googlesource.com/platform/build/+/refs/tags/android-16.0.0_r4/core/sysprop.mk#69) | Partition-specific fingerprints |
| **[F3]** | [Android partition overview](https://source.android.com/docs/core/architecture/partitions) | Separate system and vendor update boundaries |
| **[C1]** | [Connectivity APEX `Android.bp`](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/Tethering/apex/Android.bp#50) | `com.android.tethering` contents and boundary |
| **[C2]** | [Connectivity APEX manifest](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/Tethering/apex/manifest.json) | Checked-in version-zero placeholder |
| **[C3]** | [Soong APEX manifest version substitution](https://android.googlesource.com/platform/build/soong/+/refs/tags/android-16.0.0_r1/apex/builder.go#343) | Release default and environment override |
| **[C4]** | [Android 16 r1 release module-version flag](https://android.googlesource.com/platform/build/release/+/refs/tags/android-16.0.0_r1/flag_values/bp2a/RELEASE_DEFAULT_UPDATABLE_MODULE_VERSION.textproto) | Public value `360499999` |
| **[C5]** | [Android APEX format](https://source.android.com/docs/core/ota/apex) | Name/version and two signing layers |
| **[C6]** | [Android modular system components](https://source.android.com/docs/core/ota/modular-system) | Mainline update independence |
| **[S1]** | [Android Security Bulletin, April 2026](https://source.android.com/docs/security/bulletin/2026/2026-04-01) | Meaning of patch level `2026-04-05` |
