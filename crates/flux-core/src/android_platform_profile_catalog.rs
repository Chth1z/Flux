use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::android_mark_authority::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, AndroidMarkDevicePolicy,
    AndroidMarkDevicePolicyArtifactDigest, AndroidMarkDevicePolicyError,
    AndroidMarkDevicePolicyName, AndroidMarkDevicePolicyRevision, AndroidMarkPolicyAssuranceClass,
    FwmarkExactMarkSentinelQualification, FwmarkNetfilterBuiltinHook, FwmarkNetfilterChainName,
    FwmarkOrderedLateWritePlacement, FwmarkOrderedLateWriteQualification,
    FwmarkPacketSelectorDigest, FwmarkPlaneSet, FwmarkUseOperation, FwmarkUseRecord,
    ReviewedPolicyCatalogEntryId,
};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_tproxy_topology::AndroidTproxyTopologyScopeReport;
use crate::canary_facility_policy::ReviewedCanaryFacilityPolicy;
use crate::capability::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, CapabilityProfile,
    KernelBuildIdentity, NetworkNamespaceIdentity, ObservationKind, ReviewedPolicySelector,
    SecurityPatchLevel, SelinuxPolicyIdentity, Sha256Digest, VendorBuildIdentity,
};
#[cfg(flux_android_qualification)]
use crate::capture_path::CapturePathQualificationState;
use crate::capture_path::{
    CapturePathBehavioralEvidence, CapturePathQualifications,
    ReviewedCapturePathEvidenceArtifactDigest, ReviewedCapturePathEvidenceRevision,
};
use crate::fwmark_audit::{FwmarkCandidate, FwmarkEvidenceSource};
use crate::network_route::NetworkAddressFamily;

/// Maximum number of independently reviewed exact Android platform profiles.
pub const MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES: usize = 64;

const SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1: ReviewedAndroidPlatformProfileCatalogEntry =
    ReviewedAndroidPlatformProfileCatalogEntry {
        id: "samsung-sm-s9180-fzdp-observed-behavior-v1",
        selector: ReviewedPolicySelectorLiteral {
            android_product: "samsung/dm3qzhx/dm3q",
            android_build: "samsung/dm3qzhx/dm3q:16/BP4A.251205.006/S9180ZHU7FZDP:user/release-keys",
            vendor_build: "samsung/dm3qzhx/dm3q:13/TP1A.220624.014/S9180ZHU7FZDP:user/release-keys",
            security_patch: "2026-04-05",
            kernel_build: "5.15.207-Qkernel-ga2c4e0b796 #3 SMP PREEMPT Fri May 22 14:03:17 UTC 2026",
            selinux_policy: ReviewedArtifactLiteral {
                digest: [
                    0xd9, 0x0a, 0x3e, 0x32, 0xfc, 0x84, 0x4a, 0x71, 0x4b, 0xf3, 0x7c, 0xea, 0xdc,
                    0x6e, 0xa5, 0xb7, 0x57, 0x48, 0x62, 0x90, 0x0e, 0x43, 0xf1, 0x41, 0x9e, 0x37,
                    0xa0, 0x08, 0xdd, 0x63, 0xc0, 0x1f,
                ],
                size: 2_825_193,
            },
            netd: ReviewedArtifactLiteral {
                digest: [
                    0xaa, 0xbe, 0xab, 0x17, 0x6d, 0x29, 0xa2, 0xef, 0x29, 0x9f, 0xdd, 0xa3, 0x18,
                    0x00, 0x2d, 0xde, 0x25, 0x3e, 0x00, 0xa1, 0xc4, 0x75, 0x06, 0xf3, 0xaf, 0x06,
                    0x2b, 0x73, 0x11, 0x2d, 0x0a, 0xdd,
                ],
                size: 1_033_576,
            },
            connectivity: ReviewedArtifactLiteral {
                digest: [
                    0xec, 0x4d, 0x66, 0xb2, 0x4a, 0x5d, 0x7b, 0xf2, 0xfe, 0x4f, 0x0a, 0xff, 0x22,
                    0x04, 0xdd, 0x51, 0xb4, 0x04, 0x97, 0x48, 0x56, 0x9e, 0xe0, 0xc0, 0xbc, 0x85,
                    0x01, 0x04, 0xbf, 0x0d, 0x75, 0x49,
                ],
                size: 36_827_136,
            },
        },
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            assurance_class: AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior,
            name: "Samsung SM-S9180 FZDP observed behavior",
            revision: 1,
            artifact_digest: [
                0xfc, 0x69, 0xfb, 0x25, 0xbd, 0x35, 0x08, 0x57, 0x52, 0x50, 0xb8, 0xcc, 0x8d, 0x52,
                0xcc, 0x6a, 0xc8, 0xb0, 0x08, 0xe8, 0xf0, 0xf6, 0x26, 0x6f, 0xad, 0x8e, 0xed, 0x36,
                0xf7, 0x7a, 0xfc, 0x87,
            ],
            netd_source_profile: AndroidNetdSourceProfile::AospNetd20250324,
            candidate_mask: 0x0300_0000,
            proxy_value: 0x0100_0000,
            bypass_value: 0x0200_0000,
            planes: FwmarkPlaneSet::ALL.bits(),
            ordered_late_writes: &[],
            ordered_late_write_alternatives: &[],
            exact_mark_sentinels: &[],
        }),
        // This exact device has reviewed mark behavior only. Capture Path authority remains absent
        // until a rooted ARM64 behavioral artifact is independently reviewed.
        capture_path: None,
        canary_facility: None,
    };

#[cfg(any(test, flux_android_qualification))]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELINUX_POLICY_DIGEST: [u8; 32] = [
    0x01, 0xa2, 0xe2, 0x16, 0xac, 0xe3, 0x76, 0x34, 0xfd, 0x90, 0x1c, 0x5e, 0x8b, 0x66, 0xa0, 0xb7,
    0x7a, 0xcb, 0x9d, 0xd8, 0x07, 0xb9, 0x94, 0x59, 0x8b, 0x01, 0xee, 0x5b, 0x21, 0xd5, 0xea, 0xbb,
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELINUX_POLICY_SHA256: &str =
    "01a2e216ace37634fd901c5e8b66a0b77acb9dd807b994598b01ee5b21d5eabb";

#[cfg(any(test, flux_android_qualification))]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR: ReviewedPolicySelectorLiteral =
    ReviewedPolicySelectorLiteral {
        android_product: "samsung/dm3qzhx/dm3q",
        android_build: "samsung/dm3qzhx/dm3q:16/BP4A.251205.006/S9180ZHU7FZDP:user/release-keys",
        vendor_build: "samsung/dm3qzhx/dm3q:13/TP1A.220624.014/S9180ZHU7FZDP:user/release-keys",
        security_patch: "2026-04-05",
        kernel_build: "5.15.211-Qkernel-g9dd1df9bde #2 SMP PREEMPT Wed Jul 22 14:51:28 UTC 2026",
        selinux_policy: ReviewedArtifactLiteral {
            digest: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELINUX_POLICY_DIGEST,
            size: 2_825_262,
        },
        netd: ReviewedArtifactLiteral {
            digest: [
                0xaa, 0xbe, 0xab, 0x17, 0x6d, 0x29, 0xa2, 0xef, 0x29, 0x9f, 0xdd, 0xa3, 0x18, 0x00,
                0x2d, 0xde, 0x25, 0x3e, 0x00, 0xa1, 0xc4, 0x75, 0x06, 0xf3, 0xaf, 0x06, 0x2b, 0x73,
                0x11, 0x2d, 0x0a, 0xdd,
            ],
            size: 1_033_576,
        },
        connectivity: ReviewedArtifactLiteral {
            digest: [
                0xec, 0x4d, 0x66, 0xb2, 0x4a, 0x5d, 0x7b, 0xf2, 0xfe, 0x4f, 0x0a, 0xff, 0x22, 0x04,
                0xdd, 0x51, 0xb4, 0x04, 0x97, 0x48, 0x56, 0x9e, 0xe0, 0xc0, 0xbc, 0x85, 0x01, 0x04,
                0xbf, 0x0d, 0x75, 0x49,
            ],
            size: 36_827_136,
        },
    };

#[cfg(any(test, flux_android_qualification))]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ARTIFACT_DIGEST: [u8; 32] = [
    0x7d, 0x95, 0x2f, 0x8a, 0x32, 0x15, 0xcf, 0x33, 0x8f, 0x07, 0x8b, 0x34, 0xea, 0x7a, 0x06, 0x96,
    0x1c, 0x3a, 0x55, 0x1b, 0x46, 0x75, 0x10, 0x60, 0x3e, 0xc3, 0x8d, 0x74, 0x07, 0x3a, 0x59, 0xbd,
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ADDRESSES:
    &[ReviewedCanaryFacilityAddressLiteral] = &[
    ReviewedCanaryFacilityAddressLiteral {
        daemon_ipv4: Ipv4Addr::new(9, 254, 254, 252),
        peer_ipv4: Ipv4Addr::new(9, 254, 254, 253),
        daemon_ipv6: Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0xf110)),
        peer_ipv6: Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0xf111)),
    },
    ReviewedCanaryFacilityAddressLiteral {
        daemon_ipv4: Ipv4Addr::new(11, 254, 254, 252),
        peer_ipv4: Ipv4Addr::new(11, 254, 254, 253),
        daemon_ipv6: Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0xf120)),
        peer_ipv6: Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0xf121)),
    },
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_PORTS:
    &[ReviewedCanaryResponderPortsLiteral] = &[
    ReviewedCanaryResponderPortsLiteral {
        tcp_echo: 41_801,
        udp_echo: 41_802,
        dns: 41_803,
    },
    ReviewedCanaryResponderPortsLiteral {
        tcp_echo: 42_801,
        udp_echo: 42_802,
        dns: 42_803,
    },
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES:
    [ReviewedOrderedLateWriteLiteral; 10] = [
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv4,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 1,
        selector_digest: [
            0x82, 0xa5, 0x86, 0xae, 0x7f, 0xff, 0x9e, 0xb6, 0x85, 0x1b, 0x8b, 0xbd, 0x49, 0xf0,
            0xcd, 0x05, 0xe9, 0xd2, 0xd4, 0xbc, 0x52, 0x13, 0x2b, 0x50, 0xb8, 0x85, 0xef, 0xf3,
            0xa1, 0xa8, 0x01, 0x82,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv4,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 2,
        selector_digest: [
            0x63, 0x21, 0x92, 0x13, 0x6f, 0x67, 0xfe, 0x46, 0x50, 0x78, 0x0d, 0x6c, 0x1d, 0x81,
            0xc1, 0x3c, 0xd7, 0xf3, 0xf7, 0x64, 0x2b, 0x41, 0xee, 0x46, 0x6e, 0xf9, 0x7e, 0x31,
            0xdb, 0xc1, 0xa5, 0xa6,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv4,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 3,
        selector_digest: [
            0x76, 0x51, 0xf9, 0x34, 0xf1, 0x1e, 0x62, 0xa3, 0x70, 0x2a, 0x70, 0x8a, 0xfc, 0xd6,
            0x7c, 0x09, 0xa7, 0xd7, 0x37, 0xee, 0xea, 0x73, 0x86, 0x6b, 0x23, 0x79, 0x33, 0x2e,
            0xd5, 0x0e, 0xb7, 0x84,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 1,
        selector_digest: [
            0xe0, 0x59, 0x93, 0x19, 0xcc, 0xc1, 0x66, 0xc1, 0x77, 0x53, 0xe7, 0x2b, 0xa3, 0x07,
            0xaf, 0xa8, 0xaf, 0xe6, 0xfe, 0x22, 0x96, 0x9b, 0x7a, 0x65, 0x95, 0xba, 0x13, 0x46,
            0x52, 0xc6, 0x82, 0xf7,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 2,
        selector_digest: [
            0x73, 0x0c, 0x92, 0xb2, 0xa9, 0xeb, 0xff, 0xf8, 0x32, 0xbb, 0x54, 0x5e, 0xab, 0x7f,
            0x7f, 0x1f, 0x0f, 0xa2, 0xa8, 0xc0, 0xed, 0x8a, 0x97, 0xdb, 0x14, 0xe5, 0x01, 0x75,
            0x8e, 0xe4, 0xaa, 0x75,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 3,
        selector_digest: [
            0x6b, 0x0b, 0x5a, 0xfe, 0x52, 0x28, 0x1f, 0xf1, 0xb2, 0xfb, 0x8b, 0xa1, 0xa2, 0xc1,
            0xe9, 0xd1, 0x05, 0xe9, 0x9a, 0x92, 0xfe, 0xae, 0xcc, 0x70, 0x6d, 0x27, 0xcc, 0x02,
            0x4a, 0xc0, 0x45, 0xb2,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::Xtables,
        family: NetworkAddressFamily::Ipv4,
        hook: FwmarkNetfilterBuiltinHook::Postrouting,
        child_chain: "qcom_qos_reset_POSTROUTING",
        hook_ordinal: 4,
        rule_ordinal: 1,
        selector_digest: [
            0x87, 0x72, 0xb6, 0xc4, 0x24, 0x43, 0x11, 0x78, 0xf8, 0xb1, 0x9e, 0x34, 0x5e, 0x4e,
            0xbf, 0x97, 0x38, 0x20, 0x3e, 0xd3, 0x7f, 0x0a, 0x39, 0x42, 0xa9, 0xa3, 0x01, 0x21,
            0xee, 0x86, 0x46, 0x81,
        ],
        placement: FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
        mask: u32::MAX,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::Xtables,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Postrouting,
        child_chain: "qcom_qos_reset_POSTROUTING",
        hook_ordinal: 4,
        rule_ordinal: 1,
        selector_digest: [
            0x8e, 0x10, 0x06, 0x5a, 0x93, 0xf8, 0xa5, 0x0a, 0x07, 0xcd, 0x7f, 0x0a, 0xc6, 0x3a,
            0x3d, 0x1a, 0x58, 0xbd, 0x29, 0x47, 0x07, 0x70, 0x41, 0x54, 0x40, 0x57, 0x7e, 0xe5,
            0x91, 0xf0, 0xfc, 0x48,
        ],
        placement: FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
        mask: u32::MAX,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::Xtables,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Postrouting,
        child_chain: "qcom_qos_reset_POSTROUTING",
        hook_ordinal: 4,
        rule_ordinal: 2,
        selector_digest: [
            0x1b, 0x45, 0xda, 0x63, 0x0d, 0x26, 0xc1, 0x21, 0xa8, 0xf8, 0x8c, 0x77, 0x24, 0x78,
            0xa9, 0x7f, 0x0f, 0xcb, 0xb2, 0x4a, 0xa0, 0xba, 0x8f, 0x4b, 0x7f, 0x9b, 0x6b, 0x07,
            0xc3, 0xe0, 0xfa, 0x48,
        ],
        placement: FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
        mask: u32::MAX,
    },
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::Xtables,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Postrouting,
        child_chain: "qcom_qos_reset_POSTROUTING",
        hook_ordinal: 4,
        rule_ordinal: 3,
        selector_digest: [
            0xe2, 0x9e, 0x51, 0x6c, 0x49, 0xac, 0x16, 0xac, 0xbf, 0x0e, 0x4a, 0xc8, 0x74, 0x6e,
            0x2c, 0xfd, 0x5c, 0x83, 0xe8, 0x1f, 0xe4, 0x89, 0x8b, 0x3f, 0xee, 0x77, 0xff, 0x6b,
            0x1f, 0x28, 0xfa, 0xd9,
        ],
        placement: FwmarkOrderedLateWritePlacement::PostroutingAfterFinalFluxUse,
        mask: u32::MAX,
    },
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES_12:
    [ReviewedOrderedLateWriteLiteral; 12] = [
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[0],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[1],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[2],
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv4,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 4,
        selector_digest: [
            0xba, 0xf9, 0x86, 0x5a, 0xb7, 0x8a, 0xc5, 0xe6, 0x28, 0x37, 0x91, 0xa4, 0x86, 0x70,
            0x8d, 0x22, 0x3b, 0xaf, 0x6b, 0xd2, 0xfb, 0x1e, 0xc7, 0x5a, 0x76, 0x0c, 0x95, 0x4a,
            0xd9, 0xb5, 0x9e, 0x93,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[3],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[4],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[5],
    ReviewedOrderedLateWriteLiteral {
        source: FwmarkEvidenceSource::AndroidNetId,
        family: NetworkAddressFamily::Ipv6,
        hook: FwmarkNetfilterBuiltinHook::Input,
        child_chain: "routectrl_mangle_INPUT",
        hook_ordinal: 3,
        rule_ordinal: 4,
        selector_digest: [
            0x22, 0x32, 0xad, 0xf0, 0x83, 0x30, 0x62, 0x1c, 0x21, 0xc9, 0x34, 0xf8, 0x28, 0x11,
            0x96, 0xb0, 0xf1, 0x33, 0x80, 0x5e, 0x1e, 0xd0, 0x8d, 0xfd, 0x19, 0xd8, 0xdf, 0xa7,
            0xfa, 0xde, 0x0b, 0xa1,
        ],
        placement: FwmarkOrderedLateWritePlacement::InputAfterRouting,
        mask: 0x7fef_ffff,
    },
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[6],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[7],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[8],
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES[9],
];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITE_ALTERNATIVES:
    &[&[ReviewedOrderedLateWriteLiteral]] =
    &[&SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES_12];

#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_EXACT_MARK_SENTINELS:
    &[ReviewedExactMarkSentinelLiteral] = &[
    ReviewedExactMarkSentinelLiteral {
        family: NetworkAddressFamily::Ipv4,
        child_chain: "bw_raw_PREROUTING",
        hook_ordinal: 2,
        rule_ordinal: 1,
        selector_digest: [
            0xd1, 0x7b, 0xaf, 0xab, 0x41, 0xe2, 0x67, 0xb3, 0x13, 0x67, 0xe9, 0xf9, 0x8f, 0x4a,
            0x2a, 0x13, 0x62, 0x8e, 0xd6, 0xc6, 0xe4, 0x2d, 0x05, 0x90, 0x03, 0xc2, 0xe6, 0x1b,
            0x1d, 0x6d, 0xda, 0xec,
        ],
        sentinel: 0xdeadc1a7,
    },
    ReviewedExactMarkSentinelLiteral {
        family: NetworkAddressFamily::Ipv6,
        child_chain: "bw_raw_PREROUTING",
        hook_ordinal: 2,
        rule_ordinal: 1,
        selector_digest: [
            0x4c, 0x77, 0x4d, 0x28, 0xef, 0x9f, 0x17, 0x7c, 0x30, 0x05, 0xe0, 0xf9, 0x09, 0x37,
            0xff, 0x06, 0x2a, 0x04, 0x78, 0xbd, 0xd5, 0xf3, 0x2a, 0xa7, 0x65, 0x60, 0x6e, 0x6e,
            0xbb, 0xfb, 0xd2, 0x92,
        ],
        sentinel: 0xdeadc1a7,
    },
];

// This entry is deliberately absent from every ordinary build, including `--all-features`.
// Only the repository-owned non-shipping Android qualification command adds the custom cfg.
#[cfg(flux_android_qualification)]
const SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_V1:
    ReviewedAndroidPlatformProfileCatalogEntry = ReviewedAndroidPlatformProfileCatalogEntry {
    id: "samsung-sm-s9180-fzdp-qkernel-20260722-qualification-v1",
    selector: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR,
    mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
        assurance_class: AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior,
        name: "Samsung SM-S9180 FZDP Qkernel qualification",
        revision: 4,
        artifact_digest: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ARTIFACT_DIGEST,
        netd_source_profile: AndroidNetdSourceProfile::AospNetd20250324,
        candidate_mask: 0x0c00_0000,
        proxy_value: 0x0400_0000,
        bypass_value: 0x0800_0000,
        planes: FwmarkPlaneSet::ALL.bits(),
        ordered_late_writes: &SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITES,
        ordered_late_write_alternatives:
            SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ORDERED_WRITE_ALTERNATIVES,
        exact_mark_sentinels:
            SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_EXACT_MARK_SENTINELS,
    }),
    capture_path: Some(ReviewedCapturePathEvidenceLiteral {
        revision: 1,
        artifact_digest: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ARTIFACT_DIGEST,
        qualifications: CapturePathQualifications::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Qualified,
            CapturePathQualificationState::Unqualified,
        ),
    }),
    canary_facility: Some(ReviewedCanaryFacilityPolicyLiteral {
        revision: 3,
        artifact_digest: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ARTIFACT_DIGEST,
        daemon_veth_name: "fxq11d0",
        peer_veth_name: "fxq11p0",
        probe_uid: 2_900_001,
        probe_gid: 2_900_001,
        engine_uid: 2_900_002,
        engine_gid: 2_900_002,
        addresses: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_ADDRESSES,
        ports: SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_PORTS,
        netd_source_profile: AndroidNetdSourceProfile::AospNetd20250324,
        early_uid_lookup_priorities: &[],
        proxy_rule_priority: 30_997,
        peer_rule_priority: 30_998,
        proxy_capture_table: 20_253,
        peer_table: 20_254,
        peer_return_table: 254,
        rule_protocol: 186,
        route_protocol: 186,
        route_metric: 1_031,
        proxy_mark_value: 0x0400_0000,
        proxy_mark_mask: 0x0c00_0000,
    }),
};

/// Exact reviewed Android platform profiles compiled into production selection.
#[cfg(not(flux_android_qualification))]
const REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG: &[ReviewedAndroidPlatformProfileCatalogEntry] =
    &[SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1];

/// Exact reviewed profiles compiled only into the non-shipping qualification executable.
#[cfg(flux_android_qualification)]
const REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG: &[ReviewedAndroidPlatformProfileCatalogEntry] = &[
    SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1,
    SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_V1,
];

/// First-stage exact selection against the compiled Android platform-profile catalog.
///
/// Selection exposes only pre-observation context. It must be consumed by [`Self::bind_topology`]
/// after the surrounding platform transaction proves freshness. An unmatched exact selector has
/// no mark grant and produces explicit all-`Unqualified` Capture Path behavior.
#[derive(Debug, Eq, PartialEq)]
pub struct ReviewedAndroidPlatformProfileSelection {
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    matched: Option<MatchedReviewedAndroidPlatformProfile>,
}

impl ReviewedAndroidPlatformProfileSelection {
    #[must_use]
    pub fn catalog_entry(&self) -> Option<&ReviewedPolicyCatalogEntryId> {
        self.matched.as_ref().map(|matched| &matched.catalog_entry)
    }

    #[must_use]
    pub fn mark_policy_catalog_entry(&self) -> Option<&ReviewedPolicyCatalogEntryId> {
        self.matched
            .as_ref()
            .filter(|matched| matched.mark_policy.is_some())
            .map(|matched| &matched.catalog_entry)
    }

    #[must_use]
    pub fn is_match(&self) -> bool {
        self.matched.is_some()
    }

    #[must_use]
    pub fn netd_source_profile(&self) -> Option<AndroidNetdSourceProfile> {
        self.matched
            .as_ref()
            .and_then(|matched| matched.mark_policy.as_ref())
            .map(|policy| policy.netd_source_profile)
    }

    #[must_use]
    pub fn assurance_class(&self) -> Option<AndroidMarkPolicyAssuranceClass> {
        self.matched
            .as_ref()
            .and_then(|matched| matched.mark_policy.as_ref())
            .map(|policy| policy.assurance_class)
    }

    /// Returns the exact candidate named by the selected reviewed policy.
    ///
    /// This is configuration identity only. It does not replace topology binding or the complete
    /// live census required to construct planning authority.
    #[must_use]
    pub fn mark_candidate(&self) -> Option<FwmarkCandidate> {
        self.matched
            .as_ref()
            .and_then(|matched| matched.mark_policy.as_ref())
            .map(|policy| policy.candidate)
    }

    #[must_use]
    pub fn has_reviewed_capture_path_evidence(&self) -> bool {
        self.matched
            .as_ref()
            .is_some_and(|matched| matched.capture_path.is_some())
    }

    #[must_use]
    pub fn canary_facility_policy(&self) -> Option<&ReviewedCanaryFacilityPolicy> {
        self.matched
            .as_ref()
            .and_then(|matched| matched.canary_facility.as_ref())
    }

    /// Projects the Capture Path aspect without binding the independent mark-policy aspect.
    ///
    /// The returned fact still binds the complete current Capability Profile and namespace. A
    /// caller must provide its own freshness transaction before treating that fact as current.
    #[must_use]
    pub fn capture_path_evidence(&self) -> CapturePathBehavioralEvidence {
        let capability_digest = self.capability_profile.digest();
        let Some(matched) = &self.matched else {
            return CapturePathBehavioralEvidence::unqualified(
                capability_digest,
                self.network_namespace,
            );
        };
        match matched.capture_path {
            Some(capture_path) => CapturePathBehavioralEvidence::reviewed(
                capture_path.qualifications,
                capability_digest,
                self.network_namespace,
                matched.catalog_entry.clone(),
                capture_path.revision,
                capture_path.artifact_digest,
            ),
            None => CapturePathBehavioralEvidence::unqualified(
                capability_digest,
                self.network_namespace,
            ),
        }
    }

    /// Consumes exact selection and binds both optional profile aspects to the stable topology.
    pub fn bind_topology(
        self,
        topology_scope: &AndroidTproxyTopologyScopeReport,
    ) -> Result<BoundReviewedAndroidPlatformProfile, ReviewedAndroidPlatformProfileCatalogError>
    {
        let capture_path_evidence = self.capture_path_evidence();
        let Some(matched) = self.matched else {
            return Ok(BoundReviewedAndroidPlatformProfile {
                mark_policy: AndroidMarkDevicePolicy::generic_aosp(),
                capture_path_evidence,
                canary_facility_policy: None,
            });
        };
        let mark_policy = match matched.mark_policy {
            Some(policy) => AndroidMarkDevicePolicy::device_qualified_cooperative(
                policy.assurance_class,
                matched.catalog_entry.clone(),
                policy.name,
                policy.revision,
                policy.artifact_digest,
                policy.candidate,
                policy.netd_source_profile,
                topology_scope,
                &self.capability_profile,
                self.network_namespace,
                policy.planes,
                policy.ordered_late_writes,
                policy.ordered_late_write_alternatives,
                policy.exact_mark_sentinels,
            )
            .map_err(ReviewedAndroidPlatformProfileCatalogError::MarkPolicyConstruction)?,
            None => AndroidMarkDevicePolicy::generic_aosp(),
        };

        Ok(BoundReviewedAndroidPlatformProfile {
            mark_policy,
            capture_path_evidence,
            canary_facility_policy: matched.canary_facility,
        })
    }
}

/// Read-only contract for the exact ordered-write cohorts compiled into the non-shipping Android
/// qualification profile.
///
/// This value can reject an incompatible xtables observation before a qualification transaction
/// consumes credentials or creates a boot facility. It cannot select a platform profile, bind a
/// topology, construct an [`AndroidMarkDevicePolicy`], or grant planning or mutation authority.
#[cfg(flux_android_qualification)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationAndroidOrderedWriteRelation {
    Exact,
    MissingOnly,
    AdditionalOnly,
    OrderOnly,
    Substitution,
    Ambiguous,
}

/// Identity-free difference from the nearest reviewed ordered-write cohort.
///
/// Counts are bounded by the ordered-write constructor limit. No record, chain, selector, device,
/// or namespace identity crosses this qualification-only diagnostic boundary.
#[cfg(flux_android_qualification)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAndroidOrderedWriteComparison {
    relation: QualificationAndroidOrderedWriteRelation,
    observed_count: usize,
    expected_count: usize,
    missing_count: usize,
    additional_count: usize,
    equally_close_cohort_count: usize,
}

#[cfg(flux_android_qualification)]
impl QualificationAndroidOrderedWriteComparison {
    #[must_use]
    pub const fn relation(self) -> QualificationAndroidOrderedWriteRelation {
        self.relation
    }

    #[must_use]
    pub const fn observed_count(self) -> usize {
        self.observed_count
    }

    #[must_use]
    pub const fn expected_count(self) -> usize {
        self.expected_count
    }

    #[must_use]
    pub const fn missing_count(self) -> usize {
        self.missing_count
    }

    #[must_use]
    pub const fn additional_count(self) -> usize {
        self.additional_count
    }

    #[must_use]
    pub const fn equally_close_cohort_count(self) -> usize {
        self.equally_close_cohort_count
    }
}

#[cfg(flux_android_qualification)]
#[derive(Debug, Eq, PartialEq)]
pub struct QualificationAndroidOrderedWritePreflight {
    netd_source_profile: AndroidNetdSourceProfile,
    candidate: FwmarkCandidate,
    reviewed_cohorts: Box<[Box<[FwmarkOrderedLateWriteQualification]>]>,
}

#[cfg(flux_android_qualification)]
impl QualificationAndroidOrderedWritePreflight {
    #[must_use]
    pub const fn netd_source_profile(&self) -> AndroidNetdSourceProfile {
        self.netd_source_profile
    }

    #[must_use]
    pub const fn candidate(&self) -> FwmarkCandidate {
        self.candidate
    }

    /// Returns true only for byte-exact equality with one complete reviewed cohort.
    ///
    /// Subsets, supersets, unions, reordered records, and hybrids all reject. A positive result is
    /// diagnostic compatibility only; the production coordinator must still repeat the complete
    /// census and every authority check.
    #[must_use]
    pub fn accepts(&self, observed: &[FwmarkOrderedLateWriteQualification]) -> bool {
        self.reviewed_cohorts
            .iter()
            .any(|cohort| cohort.as_ref() == observed)
    }

    /// Reduces an exact rejection to bounded counts and one fixed relation class.
    ///
    /// The closest cohort minimizes the total missing-plus-additional multiset distance. A tie is
    /// deliberately ambiguous; the result never exposes either cohort's records.
    #[must_use]
    pub fn compare(
        &self,
        observed: &[FwmarkOrderedLateWriteQualification],
    ) -> QualificationAndroidOrderedWriteComparison {
        if let Some(exact) = self
            .reviewed_cohorts
            .iter()
            .find(|cohort| cohort.as_ref() == observed)
        {
            return QualificationAndroidOrderedWriteComparison {
                relation: QualificationAndroidOrderedWriteRelation::Exact,
                observed_count: observed.len(),
                expected_count: exact.len(),
                missing_count: 0,
                additional_count: 0,
                equally_close_cohort_count: 1,
            };
        }

        let mut sorted_observed = observed.to_vec();
        sorted_observed.sort_unstable();
        let mut nearest: Option<(
            usize,
            usize,
            usize,
            usize,
            QualificationAndroidOrderedWriteRelation,
        )> = None;
        let mut equally_close_cohort_count = 0_usize;
        for cohort in &self.reviewed_cohorts {
            let (missing_count, additional_count) =
                ordered_write_multiset_difference(cohort, &sorted_observed);
            let distance = missing_count + additional_count;
            let relation = if distance == 0 {
                QualificationAndroidOrderedWriteRelation::OrderOnly
            } else if missing_count == 0 {
                QualificationAndroidOrderedWriteRelation::AdditionalOnly
            } else if additional_count == 0 {
                QualificationAndroidOrderedWriteRelation::MissingOnly
            } else {
                QualificationAndroidOrderedWriteRelation::Substitution
            };
            match nearest {
                Some((nearest_distance, _, _, _, _)) if distance > nearest_distance => {}
                Some((nearest_distance, _, _, _, _)) if distance == nearest_distance => {
                    equally_close_cohort_count += 1;
                }
                _ => {
                    nearest = Some((
                        distance,
                        cohort.len(),
                        missing_count,
                        additional_count,
                        relation,
                    ));
                    equally_close_cohort_count = 1;
                }
            }
        }
        let (_, expected_count, missing_count, additional_count, nearest_relation) =
            nearest.expect("qualification contract always contains its primary reviewed cohort");
        QualificationAndroidOrderedWriteComparison {
            relation: if equally_close_cohort_count == 1 {
                nearest_relation
            } else {
                QualificationAndroidOrderedWriteRelation::Ambiguous
            },
            observed_count: observed.len(),
            expected_count,
            missing_count,
            additional_count,
            equally_close_cohort_count,
        }
    }
}

#[cfg(flux_android_qualification)]
fn ordered_write_multiset_difference(
    expected: &[FwmarkOrderedLateWriteQualification],
    observed: &[FwmarkOrderedLateWriteQualification],
) -> (usize, usize) {
    let mut expected_index = 0_usize;
    let mut observed_index = 0_usize;
    let mut missing_count = 0_usize;
    let mut additional_count = 0_usize;
    while expected_index < expected.len() && observed_index < observed.len() {
        match expected[expected_index].cmp(&observed[observed_index]) {
            std::cmp::Ordering::Less => {
                missing_count += 1;
                expected_index += 1;
            }
            std::cmp::Ordering::Equal => {
                expected_index += 1;
                observed_index += 1;
            }
            std::cmp::Ordering::Greater => {
                additional_count += 1;
                observed_index += 1;
            }
        }
    }
    missing_count += expected.len().saturating_sub(expected_index);
    additional_count += observed.len().saturating_sub(observed_index);
    (missing_count, additional_count)
}

/// Builds the read-only exact-cohort contract from the same validated catalog entry used by the
/// non-shipping qualification daemon.
#[cfg(flux_android_qualification)]
pub fn qualification_android_ordered_write_preflight()
-> Result<QualificationAndroidOrderedWritePreflight, ReviewedAndroidPlatformProfileCatalogError> {
    let validated = validate_entry(0, &SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_V1)?;
    let policy =
        validated
            .mark_policy
            .ok_or(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
                index: 0,
                field: ReviewedAndroidPlatformProfileCatalogField::MarkOrderedLateWrites,
            })?;
    let mut reviewed_cohorts = Vec::with_capacity(policy.ordered_late_write_alternatives.len() + 1);
    reviewed_cohorts.push(policy.ordered_late_writes);
    reviewed_cohorts.extend(policy.ordered_late_write_alternatives);
    Ok(QualificationAndroidOrderedWritePreflight {
        netd_source_profile: policy.netd_source_profile,
        candidate: policy.candidate,
        reviewed_cohorts: reviewed_cohorts.into_boxed_slice(),
    })
}

/// Both independently reviewed aspects after exact selection and topology binding.
#[derive(Debug, Eq, PartialEq)]
pub struct BoundReviewedAndroidPlatformProfile {
    mark_policy: AndroidMarkDevicePolicy,
    capture_path_evidence: CapturePathBehavioralEvidence,
    canary_facility_policy: Option<ReviewedCanaryFacilityPolicy>,
}

impl BoundReviewedAndroidPlatformProfile {
    #[must_use]
    pub const fn mark_policy(&self) -> &AndroidMarkDevicePolicy {
        &self.mark_policy
    }

    #[must_use]
    pub const fn capture_path_evidence(&self) -> &CapturePathBehavioralEvidence {
        &self.capture_path_evidence
    }

    #[must_use]
    pub const fn canary_facility_policy(&self) -> Option<&ReviewedCanaryFacilityPolicy> {
        self.canary_facility_policy.as_ref()
    }

    #[must_use]
    pub fn into_parts(self) -> (AndroidMarkDevicePolicy, CapturePathBehavioralEvidence) {
        (self.mark_policy, self.capture_path_evidence)
    }

    #[must_use]
    pub fn into_parts_with_canary(
        self,
    ) -> (
        AndroidMarkDevicePolicy,
        CapturePathBehavioralEvidence,
        Option<ReviewedCanaryFacilityPolicy>,
    ) {
        (
            self.mark_policy,
            self.capture_path_evidence,
            self.canary_facility_policy,
        )
    }
}

#[derive(Debug, Eq, PartialEq)]
struct MatchedReviewedAndroidPlatformProfile {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    mark_policy: Option<ValidatedAndroidMarkPolicy>,
    capture_path: Option<ValidatedCapturePathEvidence>,
    canary_facility: Option<ReviewedCanaryFacilityPolicy>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedAndroidPlatformProfileCatalogField {
    CatalogEntryId,
    AndroidProduct,
    AndroidBuild,
    VendorBuild,
    SecurityPatch,
    KernelBuild,
    SelinuxPolicy,
    Netd,
    Connectivity,
    ProfileAspects,
    MarkPolicyName,
    MarkPolicyRevision,
    MarkPolicyArtifactDigest,
    MarkCandidate,
    MarkPlanes,
    MarkOrderedLateWrites,
    MarkExactMarkSentinels,
    CapturePathEvidenceRevision,
    CapturePathEvidenceArtifactDigest,
    CapturePathQualifications,
    CanaryFacilityPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedAndroidPlatformProfileCatalogError {
    TooManyEntries {
        maximum: usize,
        required_at_least: usize,
    },
    InvalidEntry {
        index: usize,
        field: ReviewedAndroidPlatformProfileCatalogField,
    },
    DuplicateEntryId {
        first: usize,
        second: usize,
    },
    DuplicateSelector {
        first: usize,
        second: usize,
    },
    UnverifiedBootIdentity {
        observation: ObservationKind,
    },
    UnverifiedDeviceIdentity {
        observation: ObservationKind,
    },
    NetworkNamespaceMismatch {
        profile: NetworkNamespaceIdentity,
        observed: NetworkNamespaceIdentity,
    },
    MarkPolicyConstruction(AndroidMarkDevicePolicyError),
}

impl fmt::Display for ReviewedAndroidPlatformProfileCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "reviewed Android platform-profile catalog has at least {required_at_least} entries but its limit is {maximum}"
            ),
            Self::InvalidEntry { index, field } => write!(
                formatter,
                "reviewed Android platform-profile catalog entry {index} has an invalid {field:?} field"
            ),
            Self::DuplicateEntryId { first, second } => write!(
                formatter,
                "reviewed Android platform-profile catalog entries {first} and {second} repeat one entry ID"
            ),
            Self::DuplicateSelector { first, second } => write!(
                formatter,
                "reviewed Android platform-profile catalog entries {first} and {second} repeat one exact device selector"
            ),
            Self::UnverifiedBootIdentity { observation } => write!(
                formatter,
                "reviewed Android platform-profile selection requires verified boot identity, not {observation:?}"
            ),
            Self::UnverifiedDeviceIdentity { observation } => write!(
                formatter,
                "reviewed Android platform-profile selection requires verified device identity, not {observation:?}"
            ),
            Self::NetworkNamespaceMismatch { profile, observed } => write!(
                formatter,
                "reviewed Android platform-profile selection observed network namespace {}:{} rather than profile {}:{}",
                observed.device(),
                observed.inode(),
                profile.device(),
                profile.inode()
            ),
            Self::MarkPolicyConstruction(error) => error.fmt(formatter),
        }
    }
}

impl Error for ReviewedAndroidPlatformProfileCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::MarkPolicyConstruction(error) => Some(error),
            Self::TooManyEntries { .. }
            | Self::InvalidEntry { .. }
            | Self::DuplicateEntryId { .. }
            | Self::DuplicateSelector { .. }
            | Self::UnverifiedBootIdentity { .. }
            | Self::UnverifiedDeviceIdentity { .. }
            | Self::NetworkNamespaceMismatch { .. } => None,
        }
    }
}

/// Selects one exact reviewed Android platform profile from the compiled catalog.
///
/// An unmatched verified device receives an explicit zero mark grant and all-`Unqualified`
/// Capture Path evidence. Runtime manifests, WSA observations, and caller-supplied catalog entries
/// are not accepted by this interface.
///
/// External crates cannot bypass the selector through crate-private positive constructors:
///
/// ```compile_fail
/// use flux_core::CapturePathBehavioralEvidence;
///
/// let _ = CapturePathBehavioralEvidence::reviewed;
/// ```
pub fn select_reviewed_android_platform_profile(
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
) -> Result<ReviewedAndroidPlatformProfileSelection, ReviewedAndroidPlatformProfileCatalogError> {
    select_from_catalog(
        REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG,
        capability_profile,
        network_namespace,
    )
}

/// Returns only the stable selector field names that differ from the non-shipping qualification
/// profile. This diagnostic surface is absent from ordinary builds and conveys no policy grant or
/// observed identity value.
#[cfg(flux_android_qualification)]
#[must_use]
pub fn qualification_selector_mismatch_fields(
    capability_profile: &CapabilityProfile,
) -> Vec<&'static str> {
    let Some(device_identity) = capability_profile.device_identity().verified() else {
        return vec!["device_identity"];
    };
    let expected = &SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELECTOR;
    let mut mismatches = Vec::with_capacity(11);
    if device_identity.android_product().as_str() != expected.android_product {
        mismatches.push("android_product");
    }
    if device_identity.android_build().as_str() != expected.android_build {
        mismatches.push("android_build");
    }
    if device_identity.vendor_build().as_str() != expected.vendor_build {
        mismatches.push("vendor_build");
    }
    if device_identity.security_patch().as_str() != expected.security_patch {
        mismatches.push("security_patch");
    }
    if device_identity.kernel_build().as_str() != expected.kernel_build {
        mismatches.push("kernel_build");
    }
    if qualification_hex_digest(device_identity.selinux_policy().digest())
        != SAMSUNG_SM_S9180_FZDP_QKERNEL_20260722_QUALIFICATION_SELINUX_POLICY_SHA256
    {
        mismatches.push("selinux_policy_sha256");
    }
    if device_identity.selinux_policy().size() != expected.selinux_policy.size {
        mismatches.push("selinux_policy_size");
    }
    if qualification_digest_differs(
        device_identity.netd().digest().as_bytes(),
        &expected.netd.digest,
    ) {
        mismatches.push("netd_sha256");
    }
    if device_identity.netd().size() != expected.netd.size {
        mismatches.push("netd_size");
    }
    if qualification_digest_differs(
        device_identity.connectivity().digest().as_bytes(),
        &expected.connectivity.digest,
    ) {
        mismatches.push("connectivity_sha256");
    }
    if device_identity.connectivity().size() != expected.connectivity.size {
        mismatches.push("connectivity_size");
    }
    mismatches
}

#[cfg(flux_android_qualification)]
fn qualification_digest_differs(actual: &[u8; 32], expected: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    let mut index = 0;
    while index < actual.len() {
        difference |= actual[index] ^ expected[index];
        index += 1;
    }
    difference != 0
}

#[cfg(flux_android_qualification)]
fn qualification_hex_digest(digest: Sha256Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn select_from_catalog(
    entries: &[ReviewedAndroidPlatformProfileCatalogEntry],
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
) -> Result<ReviewedAndroidPlatformProfileSelection, ReviewedAndroidPlatformProfileCatalogError> {
    let validated = validate_catalog(entries)?;
    if capability_profile.boot_identity().verified().is_none() {
        return Err(
            ReviewedAndroidPlatformProfileCatalogError::UnverifiedBootIdentity {
                observation: capability_profile.boot_identity().kind(),
            },
        );
    }
    let device_identity = capability_profile.device_identity().verified().ok_or(
        ReviewedAndroidPlatformProfileCatalogError::UnverifiedDeviceIdentity {
            observation: capability_profile.device_identity().kind(),
        },
    )?;
    if device_identity.network_namespace() != network_namespace {
        return Err(
            ReviewedAndroidPlatformProfileCatalogError::NetworkNamespaceMismatch {
                profile: device_identity.network_namespace(),
                observed: network_namespace,
            },
        );
    }

    let selector = ReviewedPolicySelector::from_device_identity(device_identity);
    let matched = validated
        .into_iter()
        .find(|entry| entry.selector == selector)
        .map(|entry| MatchedReviewedAndroidPlatformProfile {
            catalog_entry: entry.catalog_entry,
            mark_policy: entry.mark_policy,
            capture_path: entry.capture_path,
            canary_facility: entry.canary_facility,
        });

    Ok(ReviewedAndroidPlatformProfileSelection {
        capability_profile: capability_profile.clone(),
        network_namespace,
        matched,
    })
}

fn validate_catalog(
    entries: &[ReviewedAndroidPlatformProfileCatalogEntry],
) -> Result<Vec<ValidatedCatalogEntry>, ReviewedAndroidPlatformProfileCatalogError> {
    if entries.len() > MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES {
        return Err(ReviewedAndroidPlatformProfileCatalogError::TooManyEntries {
            maximum: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES,
            required_at_least: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES + 1,
        });
    }

    let mut validated: Vec<ValidatedCatalogEntry> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry = validate_entry(index, entry)?;
        for (previous_index, previous) in validated.iter().enumerate() {
            if previous.catalog_entry == entry.catalog_entry {
                return Err(
                    ReviewedAndroidPlatformProfileCatalogError::DuplicateEntryId {
                        first: previous_index,
                        second: index,
                    },
                );
            }
            if previous.selector == entry.selector {
                return Err(
                    ReviewedAndroidPlatformProfileCatalogError::DuplicateSelector {
                        first: previous_index,
                        second: index,
                    },
                );
            }
        }
        validated.push(entry);
    }
    Ok(validated)
}

fn validate_entry(
    index: usize,
    entry: &ReviewedAndroidPlatformProfileCatalogEntry,
) -> Result<ValidatedCatalogEntry, ReviewedAndroidPlatformProfileCatalogError> {
    let invalid = |field| ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index, field };
    let catalog_entry = ReviewedPolicyCatalogEntryId::new(entry.id)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::CatalogEntryId))?;
    let selector = validate_selector(&entry.selector, index)?;
    if entry.mark_policy.is_none()
        && entry.capture_path.is_none()
        && entry.canary_facility.is_none()
    {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::ProfileAspects,
        ));
    }
    let mark_policy = entry
        .mark_policy
        .map(|policy| validate_mark_policy(policy, index))
        .transpose()?;
    let capture_path = entry
        .capture_path
        .map(|evidence| validate_capture_path_evidence(evidence, index))
        .transpose()?;
    let canary_facility = entry
        .canary_facility
        .map(|policy| validate_canary_facility_policy(policy, index, catalog_entry.clone()))
        .transpose()?;
    if let (Some(mark), Some(canary)) = (&mark_policy, &canary_facility)
        && (mark.netd_source_profile != canary.netd_source_profile()
            || mark.candidate.proxy_value() != canary.rpdb().proxy_mark_value()
            || mark.candidate.mask() != canary.rpdb().proxy_mark_mask().get())
    {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::CanaryFacilityPolicy,
        ));
    }

    Ok(ValidatedCatalogEntry {
        catalog_entry,
        selector,
        mark_policy,
        capture_path,
        canary_facility,
    })
}

fn validate_mark_policy(
    policy: ReviewedAndroidMarkPolicyLiteral,
    index: usize,
) -> Result<ValidatedAndroidMarkPolicy, ReviewedAndroidPlatformProfileCatalogError> {
    let invalid = |field| ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index, field };
    let name = AndroidMarkDevicePolicyName::new(policy.name)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::MarkPolicyName))?;
    if name.as_str() != policy.name {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::MarkPolicyName,
        ));
    }
    let revision = AndroidMarkDevicePolicyRevision::new(policy.revision)
        .ok_or_else(|| invalid(ReviewedAndroidPlatformProfileCatalogField::MarkPolicyRevision))?;
    let artifact_digest = AndroidMarkDevicePolicyArtifactDigest::new(policy.artifact_digest)
        .map_err(|_| {
            invalid(ReviewedAndroidPlatformProfileCatalogField::MarkPolicyArtifactDigest)
        })?;
    let candidate = FwmarkCandidate::new(
        policy.candidate_mask,
        policy.proxy_value,
        policy.bypass_value,
    )
    .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::MarkCandidate))?;
    if candidate.mask() & !ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK != 0 {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::MarkCandidate,
        ));
    }
    let planes = FwmarkPlaneSet::from_bits(policy.planes)
        .filter(|planes| !planes.is_empty())
        .ok_or_else(|| invalid(ReviewedAndroidPlatformProfileCatalogField::MarkPlanes))?;
    let ordered_late_writes = validate_ordered_late_writes(policy.ordered_late_writes)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::MarkOrderedLateWrites))?;
    if ordered_late_writes
        .iter()
        .any(|record| record.mark_use().mask() & candidate.mask() == 0)
    {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::MarkOrderedLateWrites,
        ));
    }
    let mut ordered_late_write_alternatives =
        Vec::with_capacity(policy.ordered_late_write_alternatives.len());
    for literals in policy.ordered_late_write_alternatives {
        let cohort = validate_ordered_late_writes(literals).map_err(|_| {
            invalid(ReviewedAndroidPlatformProfileCatalogField::MarkOrderedLateWrites)
        })?;
        if cohort.is_empty()
            || cohort == ordered_late_writes
            || cohort
                .iter()
                .any(|record| record.mark_use().mask() & candidate.mask() == 0)
            || ordered_late_write_alternatives.contains(&cohort)
        {
            return Err(invalid(
                ReviewedAndroidPlatformProfileCatalogField::MarkOrderedLateWrites,
            ));
        }
        ordered_late_write_alternatives.push(cohort);
    }
    let exact_mark_sentinels =
        validate_exact_mark_sentinels(policy.exact_mark_sentinels, candidate).map_err(|_| {
            invalid(ReviewedAndroidPlatformProfileCatalogField::MarkExactMarkSentinels)
        })?;

    Ok(ValidatedAndroidMarkPolicy {
        assurance_class: policy.assurance_class,
        name,
        revision,
        artifact_digest,
        candidate,
        netd_source_profile: policy.netd_source_profile,
        planes,
        ordered_late_writes,
        ordered_late_write_alternatives: ordered_late_write_alternatives.into_boxed_slice(),
        exact_mark_sentinels,
    })
}

fn validate_capture_path_evidence(
    evidence: ReviewedCapturePathEvidenceLiteral,
    index: usize,
) -> Result<ValidatedCapturePathEvidence, ReviewedAndroidPlatformProfileCatalogError> {
    let invalid = |field| ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index, field };
    let revision =
        ReviewedCapturePathEvidenceRevision::new(evidence.revision).ok_or_else(|| {
            invalid(ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceRevision)
        })?;
    let artifact_digest = ReviewedCapturePathEvidenceArtifactDigest::new(evidence.artifact_digest)
        .ok_or_else(|| {
            invalid(ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceArtifactDigest)
        })?;
    if !evidence.qualifications.has_reviewed_outcome() {
        return Err(invalid(
            ReviewedAndroidPlatformProfileCatalogField::CapturePathQualifications,
        ));
    }
    Ok(ValidatedCapturePathEvidence {
        revision,
        artifact_digest,
        qualifications: evidence.qualifications,
    })
}

fn validate_canary_facility_policy(
    policy: ReviewedCanaryFacilityPolicyLiteral,
    index: usize,
    catalog_entry: ReviewedPolicyCatalogEntryId,
) -> Result<ReviewedCanaryFacilityPolicy, ReviewedAndroidPlatformProfileCatalogError> {
    let invalid = || ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
        index,
        field: ReviewedAndroidPlatformProfileCatalogField::CanaryFacilityPolicy,
    };
    ReviewedCanaryFacilityPolicy::reviewed(
        catalog_entry,
        policy.revision,
        policy.artifact_digest,
        policy.daemon_veth_name.as_bytes(),
        policy.peer_veth_name.as_bytes(),
        policy.probe_uid,
        policy.probe_gid,
        policy.engine_uid,
        policy.engine_gid,
        policy.addresses.iter().map(|candidate| {
            (
                candidate.daemon_ipv4,
                candidate.peer_ipv4,
                candidate.daemon_ipv6,
                candidate.peer_ipv6,
            )
        }),
        policy
            .ports
            .iter()
            .map(|candidate| (candidate.tcp_echo, candidate.udp_echo, candidate.dns)),
        policy.netd_source_profile,
        policy.early_uid_lookup_priorities.iter().copied(),
        policy.proxy_rule_priority,
        policy.peer_rule_priority,
        policy.proxy_capture_table,
        policy.peer_table,
        policy.peer_return_table,
        policy.rule_protocol,
        policy.route_protocol,
        policy.route_metric,
        policy.proxy_mark_value,
        policy.proxy_mark_mask,
    )
    .map_err(|_| invalid())
}

fn validate_selector(
    selector: &ReviewedPolicySelectorLiteral,
    index: usize,
) -> Result<ReviewedPolicySelector, ReviewedAndroidPlatformProfileCatalogError> {
    let invalid = |field| ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index, field };
    let android_product = AndroidProductIdentity::new(selector.android_product)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::AndroidProduct))?;
    let android_build = AndroidBuildIdentity::new(selector.android_build)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::AndroidBuild))?;
    let vendor_build = VendorBuildIdentity::new(selector.vendor_build)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::VendorBuild))?;
    let security_patch = SecurityPatchLevel::new(selector.security_patch)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::SecurityPatch))?;
    let kernel_build = KernelBuildIdentity::new(selector.kernel_build)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::KernelBuild))?;
    let selinux_policy = validate_artifact(selector.selinux_policy)
        .map(SelinuxPolicyIdentity::from)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::SelinuxPolicy))?;
    let netd = validate_artifact(selector.netd)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::Netd))?;
    let connectivity = validate_artifact(selector.connectivity)
        .map_err(|_| invalid(ReviewedAndroidPlatformProfileCatalogField::Connectivity))?;
    Ok(ReviewedPolicySelector::from_exact_parts(
        android_product,
        android_build,
        vendor_build,
        security_patch,
        kernel_build,
        selinux_policy,
        netd,
        connectivity,
    ))
}

fn validate_artifact(literal: ReviewedArtifactLiteral) -> Result<ArtifactIdentity, ()> {
    let digest = Sha256Digest::new(literal.digest).map_err(|_| ())?;
    ArtifactIdentity::new(digest, literal.size).map_err(|_| ())
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedCatalogEntry {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    selector: ReviewedPolicySelector,
    mark_policy: Option<ValidatedAndroidMarkPolicy>,
    capture_path: Option<ValidatedCapturePathEvidence>,
    canary_facility: Option<ReviewedCanaryFacilityPolicy>,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedAndroidMarkPolicy {
    assurance_class: AndroidMarkPolicyAssuranceClass,
    name: AndroidMarkDevicePolicyName,
    revision: AndroidMarkDevicePolicyRevision,
    artifact_digest: AndroidMarkDevicePolicyArtifactDigest,
    candidate: FwmarkCandidate,
    netd_source_profile: AndroidNetdSourceProfile,
    planes: FwmarkPlaneSet,
    ordered_late_writes: Box<[FwmarkOrderedLateWriteQualification]>,
    ordered_late_write_alternatives: Box<[Box<[FwmarkOrderedLateWriteQualification]>]>,
    exact_mark_sentinels: Box<[FwmarkExactMarkSentinelQualification]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedCapturePathEvidence {
    revision: ReviewedCapturePathEvidenceRevision,
    artifact_digest: ReviewedCapturePathEvidenceArtifactDigest,
    qualifications: CapturePathQualifications,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedArtifactLiteral {
    digest: [u8; 32],
    size: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedPolicySelectorLiteral {
    android_product: &'static str,
    android_build: &'static str,
    vendor_build: &'static str,
    security_patch: &'static str,
    kernel_build: &'static str,
    selinux_policy: ReviewedArtifactLiteral,
    netd: ReviewedArtifactLiteral,
    connectivity: ReviewedArtifactLiteral,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedAndroidPlatformProfileCatalogEntry {
    id: &'static str,
    selector: ReviewedPolicySelectorLiteral,
    mark_policy: Option<ReviewedAndroidMarkPolicyLiteral>,
    capture_path: Option<ReviewedCapturePathEvidenceLiteral>,
    canary_facility: Option<ReviewedCanaryFacilityPolicyLiteral>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedAndroidMarkPolicyLiteral {
    assurance_class: AndroidMarkPolicyAssuranceClass,
    name: &'static str,
    revision: u64,
    artifact_digest: [u8; 32],
    netd_source_profile: AndroidNetdSourceProfile,
    candidate_mask: u32,
    proxy_value: u32,
    bypass_value: u32,
    planes: u8,
    ordered_late_writes: &'static [ReviewedOrderedLateWriteLiteral],
    ordered_late_write_alternatives: &'static [&'static [ReviewedOrderedLateWriteLiteral]],
    exact_mark_sentinels: &'static [ReviewedExactMarkSentinelLiteral],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedCapturePathEvidenceLiteral {
    revision: u64,
    artifact_digest: [u8; 32],
    qualifications: CapturePathQualifications,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedCanaryFacilityAddressLiteral {
    daemon_ipv4: Ipv4Addr,
    peer_ipv4: Ipv4Addr,
    daemon_ipv6: Option<Ipv6Addr>,
    peer_ipv6: Option<Ipv6Addr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedCanaryResponderPortsLiteral {
    tcp_echo: u16,
    udp_echo: u16,
    dns: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedCanaryFacilityPolicyLiteral {
    revision: u64,
    artifact_digest: [u8; 32],
    daemon_veth_name: &'static str,
    peer_veth_name: &'static str,
    probe_uid: u32,
    probe_gid: u32,
    engine_uid: u32,
    engine_gid: u32,
    addresses: &'static [ReviewedCanaryFacilityAddressLiteral],
    ports: &'static [ReviewedCanaryResponderPortsLiteral],
    netd_source_profile: AndroidNetdSourceProfile,
    early_uid_lookup_priorities: &'static [u32],
    proxy_rule_priority: u32,
    peer_rule_priority: u32,
    proxy_capture_table: u32,
    peer_table: u32,
    peer_return_table: u32,
    rule_protocol: u8,
    route_protocol: u8,
    route_metric: u32,
    proxy_mark_value: u32,
    proxy_mark_mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedOrderedLateWriteLiteral {
    source: FwmarkEvidenceSource,
    family: NetworkAddressFamily,
    hook: FwmarkNetfilterBuiltinHook,
    child_chain: &'static str,
    hook_ordinal: u32,
    rule_ordinal: u32,
    selector_digest: [u8; 32],
    placement: FwmarkOrderedLateWritePlacement,
    mask: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedExactMarkSentinelLiteral {
    family: NetworkAddressFamily,
    child_chain: &'static str,
    hook_ordinal: u32,
    rule_ordinal: u32,
    selector_digest: [u8; 32],
    sentinel: u32,
}

fn validate_ordered_late_writes(
    literals: &[ReviewedOrderedLateWriteLiteral],
) -> Result<Box<[FwmarkOrderedLateWriteQualification]>, ()> {
    if literals.len() > crate::android_mark_authority::MAX_ORDERED_LATE_PACKET_WRITES {
        return Err(());
    }
    let mut records = Vec::with_capacity(literals.len());
    for literal in literals {
        let mark_use = FwmarkUseRecord::new(
            literal.source,
            crate::android_mark_authority::FwmarkPlane::Packet,
            FwmarkUseOperation::MaskedWrite,
            literal.mask,
        )
        .map_err(|_| ())?;
        let chain = FwmarkNetfilterChainName::new(literal.child_chain).map_err(|_| ())?;
        let selector_digest =
            FwmarkPacketSelectorDigest::new(literal.selector_digest).map_err(|_| ())?;
        let record = FwmarkOrderedLateWriteQualification::new(
            mark_use,
            literal.family,
            literal.hook,
            chain,
            literal.hook_ordinal,
            literal.rule_ordinal,
            selector_digest,
            literal.placement,
            false,
            false,
            false,
        )
        .map_err(|_| ())?;
        if records.contains(&record) {
            return Err(());
        }
        records.push(record);
    }
    records.sort_unstable();
    Ok(records.into_boxed_slice())
}

fn validate_exact_mark_sentinels(
    literals: &[ReviewedExactMarkSentinelLiteral],
    candidate: FwmarkCandidate,
) -> Result<Box<[FwmarkExactMarkSentinelQualification]>, ()> {
    if literals.len() > crate::android_mark_authority::MAX_EXACT_MARK_SENTINEL_QUALIFICATIONS {
        return Err(());
    }
    let mark_use = FwmarkUseRecord::new(
        FwmarkEvidenceSource::Xtables,
        crate::android_mark_authority::FwmarkPlane::Packet,
        FwmarkUseOperation::PredicateRead,
        u32::MAX,
    )
    .map_err(|_| ())?;
    let mut records = Vec::with_capacity(literals.len());
    for literal in literals {
        let record = FwmarkExactMarkSentinelQualification::new(
            mark_use,
            literal.sentinel,
            candidate,
            literal.family,
            FwmarkNetfilterBuiltinHook::Prerouting,
            FwmarkNetfilterChainName::new(literal.child_chain).map_err(|_| ())?,
            literal.hook_ordinal,
            literal.rule_ordinal,
            FwmarkPacketSelectorDigest::new(literal.selector_digest).map_err(|_| ())?,
            false,
        )
        .map_err(|_| ())?;
        if records.contains(&record) {
            return Err(());
        }
        records.push(record);
    }
    records.sort_unstable();
    Ok(records.into_boxed_slice())
}

#[cfg(test)]
mod tests;
