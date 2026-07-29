use std::error::Error;
use std::fmt;

use crate::android_mark_authority::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, AndroidMarkDevicePolicy,
    AndroidMarkDevicePolicyArtifactDigest, AndroidMarkDevicePolicyError,
    AndroidMarkDevicePolicyName, AndroidMarkDevicePolicyRevision, AndroidMarkPolicyAssuranceClass,
    FwmarkNetfilterBuiltinHook, FwmarkNetfilterChainName, FwmarkOrderedLateWritePlacement,
    FwmarkOrderedLateWriteQualification, FwmarkPacketSelectorDigest, FwmarkPlaneSet,
    FwmarkUseOperation, FwmarkUseRecord, ReviewedPolicyCatalogEntryId,
};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_tproxy_topology::AndroidTproxyTopologyScopeReport;
use crate::capability::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, CapabilityProfile,
    KernelBuildIdentity, NetworkNamespaceIdentity, ObservationKind, ReviewedPolicySelector,
    SecurityPatchLevel, SelinuxPolicyIdentity, Sha256Digest, VendorBuildIdentity,
};
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
        }),
        // This exact device has reviewed mark behavior only. Capture Path authority remains absent
        // until a rooted ARM64 behavioral artifact is independently reviewed.
        capture_path: None,
    };

/// Exact reviewed Android platform profiles compiled into production selection.
const REVIEWED_ANDROID_PLATFORM_PROFILE_CATALOG: &[ReviewedAndroidPlatformProfileCatalogEntry] =
    &[SAMSUNG_SM_S9180_FZDP_PLATFORM_PROFILE_V1];

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

    #[must_use]
    pub fn has_reviewed_capture_path_evidence(&self) -> bool {
        self.matched
            .as_ref()
            .is_some_and(|matched| matched.capture_path.is_some())
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
            });
        };
        let mark_policy = match matched.mark_policy {
            Some(policy) => AndroidMarkDevicePolicy::device_qualified_cooperative(
                policy.assurance_class,
                matched.catalog_entry,
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
            )
            .map_err(ReviewedAndroidPlatformProfileCatalogError::MarkPolicyConstruction)?,
            None => AndroidMarkDevicePolicy::generic_aosp(),
        };

        Ok(BoundReviewedAndroidPlatformProfile {
            mark_policy,
            capture_path_evidence,
        })
    }
}

/// Both independently reviewed aspects after exact selection and topology binding.
#[derive(Debug, Eq, PartialEq)]
pub struct BoundReviewedAndroidPlatformProfile {
    mark_policy: AndroidMarkDevicePolicy,
    capture_path_evidence: CapturePathBehavioralEvidence,
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
    pub fn into_parts(self) -> (AndroidMarkDevicePolicy, CapturePathBehavioralEvidence) {
        (self.mark_policy, self.capture_path_evidence)
    }
}

#[derive(Debug, Eq, PartialEq)]
struct MatchedReviewedAndroidPlatformProfile {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    mark_policy: Option<ValidatedAndroidMarkPolicy>,
    capture_path: Option<ValidatedCapturePathEvidence>,
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
    CapturePathEvidenceRevision,
    CapturePathEvidenceArtifactDigest,
    CapturePathQualifications,
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
    if entry.mark_policy.is_none() && entry.capture_path.is_none() {
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

    Ok(ValidatedCatalogEntry {
        catalog_entry,
        selector,
        mark_policy,
        capture_path,
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

    Ok(ValidatedAndroidMarkPolicy {
        assurance_class: policy.assurance_class,
        name,
        revision,
        artifact_digest,
        candidate,
        netd_source_profile: policy.netd_source_profile,
        planes,
        ordered_late_writes,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReviewedCapturePathEvidenceLiteral {
    revision: u64,
    artifact_digest: [u8; 32],
    qualifications: CapturePathQualifications,
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

#[cfg(test)]
mod tests;
