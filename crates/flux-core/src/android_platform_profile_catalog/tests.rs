use super::*;
use crate::android_mark_authority::{AndroidMarkDeviceGrantKind, FwmarkPlaneSet};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_rpdb::classify_android_rpdb;
use crate::android_tproxy_topology::{
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, assess_android_tproxy_topology_scope,
};
use crate::capability::{
    BootIdentity, CapabilityProfileRevision, DeviceIdentity, KernelFacts, KernelRelease,
    Observation, SelinuxMode, ToolId, VerifiedBootIdentity, VerifiedBootState,
};
use crate::capture_path::{CapturePathId, CapturePathQualificationState};
use crate::network_inventory::{
    InterfaceHardwareType, InterfaceIndex, InterfaceLinkFlags, InterfaceLinkRecord, InterfaceName,
    NetworkInventoryTracker,
};
use crate::network_route::NetworkAddressFamily;
use crate::network_rule::{
    NetworkRuleRecord, RuleAction, RuleFlags, RuleFwMark, RulePrefix, RulePriority, RuleProperties,
    RuleProtocol, RuleTableId,
};
use sha2::{Digest, Sha256};

const NET_ID_MASK: u32 = 0x0000_ffff;
const EXPLICIT_NETWORK: u32 = 0x0001_0000;
const NETWORK_PERMISSION: u32 = 0x0004_0000;
const SYSTEM_PERMISSION: u32 = 0x000c_0000;
const CANDIDATE_MASK: u32 = 0x0300_0000;
const PROXY_VALUE: u32 = 0x0100_0000;
const BYPASS_VALUE: u32 = 0x0200_0000;

const SELECTOR: ReviewedPolicySelectorLiteral = ReviewedPolicySelectorLiteral {
    android_product: "google/redfin/redfin",
    android_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/1:user/release-keys",
    security_patch: "2023-08-05",
    kernel_build: "5.10.198-android13-gki synthetic-build",
    selinux_policy: artifact_literal(0x21, 4_096),
    netd: artifact_literal(0x22, 8_192),
    connectivity: artifact_literal(0x23, 16_384),
};
const MARK_POLICY: ReviewedAndroidMarkPolicyLiteral = ReviewedAndroidMarkPolicyLiteral {
    assurance_class: AndroidMarkPolicyAssuranceClass::AuthenticatedSource,
    name: "synthetic cooperative policy",
    revision: 1,
    artifact_digest: [0x31; 32],
    netd_source_profile: AndroidNetdSourceProfile::AospAndroid13R1,
    candidate_mask: CANDIDATE_MASK,
    proxy_value: PROXY_VALUE,
    bypass_value: BYPASS_VALUE,
    planes: FwmarkPlaneSet::ALL.bits(),
    ordered_late_writes: &[],
};
const CAPTURE_PATH_EVIDENCE: ReviewedCapturePathEvidenceLiteral =
    ReviewedCapturePathEvidenceLiteral {
        revision: 7,
        artifact_digest: [0x41; 32],
        qualifications: CapturePathQualifications::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Qualified,
            CapturePathQualificationState::Unqualified,
        ),
    };
const ENTRY: ReviewedAndroidPlatformProfileCatalogEntry =
    ReviewedAndroidPlatformProfileCatalogEntry {
        id: "google-redfin-tq3a-20230805-v1",
        selector: SELECTOR,
        mark_policy: Some(MARK_POLICY),
        capture_path: Some(CAPTURE_PATH_EVIDENCE),
    };

#[test]
fn unmatched_production_selector_returns_explicit_zero_grants() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("compiled platform catalog is valid");

    assert!(!selection.is_match());
    assert!(selection.catalog_entry().is_none());
    assert!(selection.netd_source_profile().is_none());
    assert!(!selection.has_reviewed_capture_path_evidence());
    let bound = selection
        .bind_topology(&topology)
        .expect("zero grant binds without positive topology authority");
    let (policy, capture_path) = bound.into_parts();
    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::NoGrant);
    assert_eq!(
        capture_path.qualifications(),
        CapturePathQualifications::default()
    );
    assert!(capture_path.reviewed_identity().is_none());
    assert_eq!(capture_path.capability_profile_digest(), profile.digest());
    assert_eq!(capture_path.network_namespace(), namespace);
}

#[test]
fn exact_entry_selects_positive_policy_and_retains_catalog_provenance() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let topology = topology_scope();

    let selection = select_from_catalog(&[ENTRY], &profile, namespace).expect("exact match");

    assert!(selection.is_match());
    assert!(selection.has_reviewed_capture_path_evidence());
    assert_eq!(
        selection.netd_source_profile(),
        Some(AndroidNetdSourceProfile::AospAndroid13R1)
    );
    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("google-redfin-tq3a-20230805-v1")
    );
    let projected_capture_path = selection.capture_path_evidence();
    let bound = selection
        .bind_topology(&topology)
        .expect("selected profile binds matching topology");
    let (policy, capture_path) = bound.into_parts();
    let grant = policy.positive_grant().expect("matched positive policy");

    assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::Positive);
    assert_eq!(policy.revision().get(), 1);
    assert_eq!(grant.candidate().mask(), CANDIDATE_MASK);
    assert_eq!(
        grant.netd_source_profile(),
        AndroidNetdSourceProfile::AospAndroid13R1
    );
    assert_eq!(grant.planes(), FwmarkPlaneSet::ALL);
    assert_eq!(
        grant.assurance_class(),
        AndroidMarkPolicyAssuranceClass::AuthenticatedSource
    );
    assert_eq!(grant.capability_profile(), &profile);
    assert_eq!(grant.network_namespace(), namespace);
    assert_eq!(
        policy
            .identity()
            .artifact_digest()
            .expect("policy artifact")
            .as_bytes(),
        &[0x31; 32]
    );
    assert_eq!(
        capture_path
            .qualifications()
            .state(CapturePathId::XtablesTproxy),
        CapturePathQualificationState::Qualified
    );
    let reviewed = capture_path
        .reviewed_identity()
        .expect("synthetic profile includes reviewed Capture Path evidence");
    assert_eq!(
        reviewed.catalog_entry().as_str(),
        "google-redfin-tq3a-20230805-v1"
    );
    assert_eq!(reviewed.revision().get(), 7);
    assert_eq!(reviewed.artifact_digest().as_bytes(), &[0x41; 32]);
    assert_eq!(projected_capture_path, capture_path);
}

#[test]
fn exact_production_samsung_selector_grants_marks_but_not_capture_path_behavior() {
    let namespace = namespace(20, 234_673);
    let selector = SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1.selector;
    let profile = capability_profile_for_selector(namespace, 0x71, selector);
    let selection = select_reviewed_android_platform_profile(&profile, namespace)
        .expect("exact reviewed Samsung platform selector");

    assert_eq!(
        selection.assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior)
    );
    assert_eq!(
        selection
            .catalog_entry()
            .map(ReviewedPolicyCatalogEntryId::as_str),
        Some("samsung-sm-s9180-fzdp-observed-behavior-v1")
    );
    assert_eq!(
        selection.netd_source_profile(),
        Some(AndroidNetdSourceProfile::AospNetd20250324),
        "the source-named profile is a semantic grammar under observed-behavior assurance"
    );
    assert!(!selection.has_reviewed_capture_path_evidence());

    let bound = selection
        .bind_topology(&topology_scope_for(
            AndroidNetdSourceProfile::AospNetd20250324,
        ))
        .expect("matching reviewed semantic topology");
    let (policy, capture_path) = bound.into_parts();
    let grant = policy.positive_grant().expect("exact positive assertion");
    assert_eq!(
        grant.assurance_class(),
        AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior
    );
    assert!(grant.ordered_late_writes().is_empty());
    assert_eq!(
        capture_path.qualifications(),
        CapturePathQualifications::default()
    );
    assert!(capture_path.reviewed_identity().is_none());
}

#[test]
fn policy_artifact_digest_is_compiled_from_the_exact_reviewed_document() {
    let bytes = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/samsung-sm-s9180-fzdp-observed-behavior-v1.md"
    ));
    let digest = Sha256::digest(bytes);
    assert_eq!(
        digest.as_slice(),
        SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1
            .mark_policy
            .expect("Samsung profile has a mark-policy aspect")
            .artifact_digest
    );
}

#[test]
fn assurance_classes_remain_distinct_for_otherwise_identical_entries() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let authenticated = select_from_catalog(&[ENTRY], &profile, namespace)
        .expect("authenticated synthetic policy")
        .bind_topology(&topology_scope())
        .expect("matching authenticated topology")
        .into_parts()
        .0;
    let observed_entry = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            assurance_class: AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    let observed = select_from_catalog(&[observed_entry], &profile, namespace)
        .expect("observed-behavior synthetic policy")
        .bind_topology(&topology_scope())
        .expect("matching observed topology")
        .into_parts()
        .0;

    assert_ne!(authenticated.identity(), observed.identity());
    assert_eq!(
        authenticated.identity().assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::AuthenticatedSource)
    );
    assert_eq!(
        observed.identity().assurance_class(),
        Some(AndroidMarkPolicyAssuranceClass::ExactArtifactObservedBehavior)
    );
}

#[test]
fn runtime_tool_identity_binds_the_grant_without_becoming_a_self_hash_selector() {
    let namespace = namespace(4, 40);
    let first = capability_profile_with_tool(namespace, 0x24);
    let changed = capability_profile_with_tool(namespace, 0x25);
    let first_identity = first.device_identity().verified().expect("first identity");
    let changed_identity = changed
        .device_identity()
        .verified()
        .expect("changed identity");

    assert_ne!(first, changed);
    assert_eq!(
        ReviewedPolicySelector::from_device_identity(first_identity),
        ReviewedPolicySelector::from_device_identity(changed_identity),
        "the compile-time selector cannot contain the executing ELF's self-referential digest"
    );

    let selection = select_from_catalog(&[ENTRY], &changed, namespace).expect("platform match");
    let policy = selection
        .bind_topology(&topology_scope())
        .expect("matching topology")
        .into_parts()
        .0;
    assert_eq!(
        policy
            .positive_grant()
            .expect("positive grant")
            .capability_profile(),
        &changed,
        "the exact executing-tool artifact remains freshness-bound after selection"
    );
}

#[test]
fn selected_netd_profile_must_build_the_bound_topology() {
    let namespace = namespace(4, 40);
    let selection =
        select_from_catalog(&[ENTRY], &capability_profile(namespace), namespace).expect("match");
    let topology = topology_scope_for(AndroidNetdSourceProfile::AospNetd20250324);

    assert_eq!(
        selection.bind_topology(&topology),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::MarkPolicyConstruction(
                AndroidMarkDevicePolicyError::NetdSourceProfileMismatch {
                    selected: AndroidNetdSourceProfile::AospAndroid13R1,
                    topology: AndroidNetdSourceProfile::AospNetd20250324,
                }
            )
        )
    );
}

#[test]
fn every_stable_selector_fact_drift_returns_zero_grant() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let changed_selectors = [
        ReviewedPolicySelectorLiteral {
            android_product: "google/redfin/other",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            vendor_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            security_patch: "2023-09-05",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            kernel_build: "5.10.198-android13-gki other-build",
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            selinux_policy: artifact_literal(0x41, 4_096),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            netd: artifact_literal(0x42, 8_192),
            ..SELECTOR
        },
        ReviewedPolicySelectorLiteral {
            connectivity: artifact_literal(0x43, 16_384),
            ..SELECTOR
        },
    ];

    for selector in changed_selectors {
        let changed = ReviewedAndroidPlatformProfileCatalogEntry { selector, ..ENTRY };
        let selection = select_from_catalog(&[changed], &profile, namespace)
            .expect("valid nonmatching catalog");

        assert!(!selection.is_match());
        let bound = selection
            .bind_topology(&topology_scope())
            .expect("nonmatch remains a zero grant");
        let (policy, capture_path) = bound.into_parts();
        assert_eq!(policy.grant_kind(), AndroidMarkDeviceGrantKind::NoGrant);
        assert_eq!(
            capture_path.qualifications(),
            CapturePathQualifications::default()
        );
        assert!(capture_path.reviewed_identity().is_none());
    }
}

#[test]
fn optional_aspects_are_independent_and_share_one_exact_selector() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let mark_only = ReviewedAndroidPlatformProfileCatalogEntry {
        capture_path: None,
        ..ENTRY
    };
    let capture_only = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: None,
        ..ENTRY
    };

    let mark_bound = select_from_catalog(&[mark_only], &profile, namespace)
        .expect("mark-only profile")
        .bind_topology(&topology_scope())
        .expect("mark-only topology");
    assert_eq!(
        mark_bound.mark_policy().grant_kind(),
        AndroidMarkDeviceGrantKind::Positive
    );
    assert_eq!(
        mark_bound.capture_path_evidence().qualifications(),
        CapturePathQualifications::default()
    );
    assert!(
        mark_bound
            .capture_path_evidence()
            .reviewed_identity()
            .is_none()
    );

    let capture_bound = select_from_catalog(&[capture_only], &profile, namespace)
        .expect("capture-only profile")
        .bind_topology(&topology_scope())
        .expect("capture-only topology");
    assert_eq!(
        capture_bound.mark_policy().grant_kind(),
        AndroidMarkDeviceGrantKind::NoGrant
    );
    assert_eq!(
        capture_bound
            .capture_path_evidence()
            .qualifications()
            .state(CapturePathId::XtablesTproxy),
        CapturePathQualificationState::Qualified
    );
    assert!(
        capture_bound
            .capture_path_evidence()
            .reviewed_identity()
            .is_some()
    );
}

#[test]
fn behavioral_evidence_digest_binds_fresh_capability_and_reviewed_provenance() {
    let namespace = namespace(4, 40);
    let first = capability_profile_with_tool(namespace, 0x24);
    let changed_tool = capability_profile_with_tool(namespace, 0x25);
    let first_evidence = select_from_catalog(&[ENTRY], &first, namespace)
        .expect("first exact profile")
        .bind_topology(&topology_scope())
        .expect("first bound profile")
        .into_parts()
        .1;
    let changed_evidence = select_from_catalog(&[ENTRY], &changed_tool, namespace)
        .expect("same stable selector with changed running tool")
        .bind_topology(&topology_scope())
        .expect("changed bound profile")
        .into_parts()
        .1;
    let revised_capture = ReviewedAndroidPlatformProfileCatalogEntry {
        capture_path: Some(ReviewedCapturePathEvidenceLiteral {
            revision: 8,
            ..CAPTURE_PATH_EVIDENCE
        }),
        ..ENTRY
    };
    let revised_evidence = select_from_catalog(&[revised_capture], &first, namespace)
        .expect("revised reviewed evidence")
        .bind_topology(&topology_scope())
        .expect("revised bound profile")
        .into_parts()
        .1;

    assert_ne!(first_evidence.digest(), changed_evidence.digest());
    assert_ne!(first_evidence.digest(), revised_evidence.digest());
    assert_ne!(
        first_evidence.capability_profile_digest(),
        changed_evidence.capability_profile_digest()
    );
}

#[test]
fn duplicate_ids_selectors_and_oversized_catalogs_fail_closed() {
    let different_selector = ReviewedPolicySelectorLiteral {
        android_build: "google/redfin/redfin:13/TQ3A.230805.001/2:user/release-keys",
        ..SELECTOR
    };
    let repeated_id = ReviewedAndroidPlatformProfileCatalogEntry {
        selector: different_selector,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_id]),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::DuplicateEntryId {
                first: 0,
                second: 1,
            }
        )
    );

    let repeated_selector = ReviewedAndroidPlatformProfileCatalogEntry {
        id: "google-redfin-tq3a-20230805-v2",
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ENTRY, repeated_selector]),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::DuplicateSelector {
                first: 0,
                second: 1,
            }
        )
    );

    let oversized = [ENTRY; MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES + 1];
    assert_eq!(
        validate_catalog(&oversized),
        Err(ReviewedAndroidPlatformProfileCatalogError::TooManyEntries {
            maximum: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES,
            required_at_least: MAX_REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG_ENTRIES + 1,
        })
    );
}

#[test]
fn malformed_candidate_and_planes_fail_closed() {
    let ineligible_candidate = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            candidate_mask: 0xc000_0000,
            proxy_value: 0x8000_0000,
            bypass_value: 0x4000_0000,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[ineligible_candidate]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkCandidate,
        })
    );

    let unknown_planes = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            planes: 0x80,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[unknown_planes]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPlanes,
        })
    );

    let empty_planes = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            planes: 0,
            ..MARK_POLICY
        }),
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[empty_planes]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPlanes,
        })
    );
}

#[test]
fn empty_or_malformed_capture_aspects_fail_closed() {
    let empty = ReviewedAndroidPlatformProfileCatalogEntry {
        mark_policy: None,
        capture_path: None,
        ..ENTRY
    };
    assert_eq!(
        validate_catalog(&[empty]),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 0,
            field: ReviewedAndroidPlatformProfileCatalogField::ProfileAspects,
        })
    );

    for (capture_path, field) in [
        (
            ReviewedCapturePathEvidenceLiteral {
                revision: 0,
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceRevision,
        ),
        (
            ReviewedCapturePathEvidenceLiteral {
                artifact_digest: [0; 32],
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathEvidenceArtifactDigest,
        ),
        (
            ReviewedCapturePathEvidenceLiteral {
                qualifications: CapturePathQualifications::default(),
                ..CAPTURE_PATH_EVIDENCE
            },
            ReviewedAndroidPlatformProfileCatalogField::CapturePathQualifications,
        ),
    ] {
        let malformed = ReviewedAndroidPlatformProfileCatalogEntry {
            capture_path: Some(capture_path),
            ..ENTRY
        };
        assert_eq!(
            validate_catalog(&[malformed]),
            Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry { index: 0, field })
        );
    }
}

#[test]
fn malformed_unrelated_entry_poisoning_is_rejected_before_exact_selection() {
    let namespace = namespace(4, 40);
    let profile = capability_profile(namespace);
    let malformed_unrelated = ReviewedAndroidPlatformProfileCatalogEntry {
        id: "unrelated-invalid-entry",
        selector: ReviewedPolicySelectorLiteral {
            android_product: "other/product/device",
            ..SELECTOR
        },
        mark_policy: Some(ReviewedAndroidMarkPolicyLiteral {
            revision: 0,
            ..MARK_POLICY
        }),
        ..ENTRY
    };

    assert_eq!(
        select_from_catalog(&[ENTRY, malformed_unrelated], &profile, namespace),
        Err(ReviewedAndroidPlatformProfileCatalogError::InvalidEntry {
            index: 1,
            field: ReviewedAndroidPlatformProfileCatalogField::MarkPolicyRevision,
        })
    );
}

#[test]
fn selection_rejects_unverified_boot_identity_and_namespace_drift() {
    let profile_namespace = namespace(4, 40);
    let verified = capability_profile(profile_namespace);
    let unavailable_boot = CapabilityProfile::initial(
        Observation::Unavailable,
        verified.device_identity().clone(),
        verified.kernel().clone(),
        verified.selinux().clone(),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &unavailable_boot, profile_namespace,),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::UnverifiedBootIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let unavailable = CapabilityProfile::initial(
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Unavailable,
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new("5.10.198-android13-gki").expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
    );
    assert_eq!(
        select_from_catalog(&[ENTRY], &unavailable, profile_namespace),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::UnverifiedDeviceIdentity {
                observation: ObservationKind::Unavailable,
            }
        )
    );

    let profile = capability_profile(profile_namespace);
    let other_namespace = namespace(4, 41);
    assert_eq!(
        select_from_catalog(&[ENTRY], &profile, other_namespace),
        Err(
            ReviewedAndroidPlatformProfileCatalogError::NetworkNamespaceMismatch {
                profile: profile_namespace,
                observed: other_namespace,
            }
        )
    );
}

const fn artifact_literal(byte: u8, size: u64) -> ReviewedArtifactLiteral {
    ReviewedArtifactLiteral {
        digest: [byte; 32],
        size,
    }
}

fn namespace(device: u64, inode: u64) -> NetworkNamespaceIdentity {
    NetworkNamespaceIdentity::new(device, inode).expect("nonzero namespace inode")
}

fn capability_profile(network_namespace: NetworkNamespaceIdentity) -> CapabilityProfile {
    capability_profile_with_tool(network_namespace, 0x24)
}

fn capability_profile_with_tool(
    network_namespace: NetworkNamespaceIdentity,
    tool_digest_byte: u8,
) -> CapabilityProfile {
    capability_profile_for_selector(network_namespace, tool_digest_byte, SELECTOR)
}

fn capability_profile_for_selector(
    network_namespace: NetworkNamespaceIdentity,
    tool_digest_byte: u8,
    selector: ReviewedPolicySelectorLiteral,
) -> CapabilityProfile {
    CapabilityProfile::new(
        CapabilityProfileRevision::INITIAL,
        Observation::Verified(
            BootIdentity::parse("00112233-4455-6677-8899-aabbccddeeff").expect("boot identity"),
        ),
        Observation::Verified(
            DeviceIdentity::new(
                AndroidProductIdentity::new(selector.android_product).expect("product"),
                AndroidBuildIdentity::new(selector.android_build).expect("Android build"),
                VendorBuildIdentity::new(selector.vendor_build).expect("vendor build"),
                SecurityPatchLevel::new(selector.security_patch).expect("security patch"),
                VerifiedBootIdentity::new(
                    VerifiedBootState::Green,
                    true,
                    Sha256Digest::new([0x11; 32]).expect("vbmeta digest"),
                ),
                KernelBuildIdentity::new(selector.kernel_build).expect("kernel build"),
                SelinuxPolicyIdentity::from(artifact_from_literal(selector.selinux_policy)),
                artifact_from_literal(selector.netd),
                artifact_from_literal(selector.connectivity),
                [(
                    ToolId::new("fluxd").expect("tool ID"),
                    artifact(tool_digest_byte, 32_768),
                )],
                network_namespace,
            )
            .expect("device identity"),
        ),
        KernelFacts::from_release(Observation::Verified(
            KernelRelease::new(
                selector
                    .kernel_build
                    .split_once(' ')
                    .map_or(selector.kernel_build, |(release, _)| release),
            )
            .expect("kernel release"),
        )),
        Observation::Verified(SelinuxMode::Enforcing),
    )
}

fn artifact_from_literal(literal: ReviewedArtifactLiteral) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new(literal.digest).expect("artifact digest"),
        literal.size,
    )
    .expect("nonempty artifact")
}

fn artifact(byte: u8, size: u64) -> ArtifactIdentity {
    ArtifactIdentity::new(
        Sha256Digest::new([byte; 32]).expect("artifact digest"),
        size,
    )
    .expect("nonempty artifact")
}

fn topology_scope() -> AndroidTproxyTopologyScopeReport {
    topology_scope_for(AndroidNetdSourceProfile::AospAndroid13R1)
}

fn topology_scope_for(profile: AndroidNetdSourceProfile) -> AndroidTproxyTopologyScopeReport {
    let mut tracker = NetworkInventoryTracker::new();
    let inventory = tracker
        .publish_complete_with_routing(
            [InterfaceLinkRecord::new(
                InterfaceIndex::new(1).expect("loopback index"),
                InterfaceName::new(b"lo").expect("loopback name"),
                InterfaceHardwareType::from_raw(1),
                InterfaceLinkFlags::UP | InterfaceLinkFlags::LOOPBACK,
            )],
            [],
            [],
            android_13_rules(),
        )
        .expect("complete inventory")
        .clone();
    let classification = classify_android_rpdb(&inventory, profile);
    let request = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [AndroidTproxyTrafficDomainRequest::residual_local_output(
            NetworkAddressFamily::Ipv4,
        )],
    )
    .expect("topology request");
    assess_android_tproxy_topology_scope(&inventory, &classification, &request)
        .expect("trusted residual local-output scope")
}

fn android_13_rules() -> Vec<NetworkRuleRecord> {
    let mut rules = vec![
        RuleSpec::netd(0, 255, RuleAction::TO_TABLE)
            .protocol(2)
            .build(),
        RuleSpec::netd(10_000, 99, RuleAction::TO_TABLE)
            .mark(SYSTEM_PERMISSION, EXPLICIT_NETWORK | SYSTEM_PERMISSION)
            .build(),
        RuleSpec::netd(16_000, 97, RuleAction::TO_TABLE)
            .mark(99 | EXPLICIT_NETWORK, NET_ID_MASK | EXPLICIT_NETWORK)
            .input(b"lo")
            .build(),
        RuleSpec::netd(18_000, 99, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(19_000, 98, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(20_000, 97, RuleAction::TO_TABLE)
            .mark(0, EXPLICIT_NETWORK)
            .build(),
        RuleSpec::netd(31_000, 1_003, RuleAction::TO_TABLE)
            .mark(NETWORK_PERMISSION, NET_ID_MASK | NETWORK_PERMISSION)
            .input(b"lo")
            .build(),
        RuleSpec::netd(32_000, 0, RuleAction::UNREACHABLE).build(),
    ];
    rules.sort_by_key(NetworkRuleRecord::priority);
    rules
}

struct RuleSpec {
    priority: u32,
    table: u32,
    action: RuleAction,
    protocol: u8,
    fwmark: Option<RuleFwMark>,
    input: Option<InterfaceName>,
}

impl RuleSpec {
    fn netd(priority: u32, table: u32, action: RuleAction) -> Self {
        Self {
            priority,
            table,
            action,
            protocol: 0,
            fwmark: None,
            input: None,
        }
    }

    fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = protocol;
        self
    }

    fn mark(mut self, value: u32, mask: u32) -> Self {
        self.fwmark = RuleFwMark::new(value, mask);
        self
    }

    fn input(mut self, name: &[u8]) -> Self {
        self.input = Some(InterfaceName::new(name).expect("interface name"));
        self
    }

    fn build(self) -> NetworkRuleRecord {
        let family = NetworkAddressFamily::Ipv4;
        let mut record = NetworkRuleRecord::new(
            RulePrefix::unspecified(family),
            RulePrefix::unspecified(family),
            RuleProperties::new(
                0,
                RuleTableId::from_raw(self.table),
                self.action,
                RuleProtocol::from_raw(self.protocol),
                RuleFlags::default(),
            ),
            RulePriority::from_raw(self.priority),
            None,
        )
        .expect("rule fixture");
        if let Some(fwmark) = self.fwmark {
            record = record.with_fwmark(fwmark);
        }
        if let Some(input) = self.input {
            record = record.with_input_interface(input);
        }
        record
    }
}
