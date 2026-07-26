use std::error::Error;
use std::fmt;

use crate::android_mark_authority::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, AndroidMarkDevicePolicy,
    AndroidMarkDevicePolicyArtifactDigest, AndroidMarkDevicePolicyError,
    AndroidMarkDevicePolicyName, AndroidMarkDevicePolicyRevision, FwmarkPlaneSet,
    ReviewedPolicyCatalogEntryId,
};
use crate::android_netd::AndroidNetdSourceProfile;
use crate::android_tproxy_topology::AndroidTproxyTopologyScopeReport;
use crate::capability::{
    AndroidBuildIdentity, AndroidProductIdentity, ArtifactIdentity, CapabilityProfile,
    KernelBuildIdentity, NetworkNamespaceIdentity, ObservationKind, ReviewedPolicySelector,
    SecurityPatchLevel, SelinuxPolicyIdentity, Sha256Digest, VendorBuildIdentity,
};
use crate::fwmark_audit::FwmarkCandidate;

/// Maximum number of source-reviewed entries admitted by the compiled Android policy catalog.
pub const MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES: usize = 64;

/// The production catalog deliberately starts empty.
///
/// A positive entry may be added only after independent physical-device review supplies every
/// exact selector fact plus the cooperative policy digest, revision, candidate, and plane set.
const REVIEWED_ANDROID_MARK_POLICY_CATALOG: &[ReviewedAndroidMarkPolicyCatalogEntry] = &[];

/// First-stage exact selection against the compiled Android mark-policy catalog.
///
/// A match exposes only the reviewed netd source profile needed to classify RPDB/topology. The
/// selection must then be consumed by [`Self::bind_topology`] before a positive policy exists. No
/// match binds to the explicit generic-AOSP zero-grant policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewedAndroidMarkPolicySelection {
    matched: Option<MatchedReviewedAndroidMarkPolicy>,
}

impl ReviewedAndroidMarkPolicySelection {
    #[must_use]
    pub fn catalog_entry(&self) -> Option<&ReviewedPolicyCatalogEntryId> {
        self.matched.as_ref().map(|matched| &matched.catalog_entry)
    }

    #[must_use]
    pub fn is_match(&self) -> bool {
        self.matched.is_some()
    }

    #[must_use]
    pub fn netd_source_profile(&self) -> Option<AndroidNetdSourceProfile> {
        self.matched
            .as_ref()
            .map(|matched| matched.netd_source_profile)
    }

    /// Consumes the selection and binds topology classified with the selected netd profile.
    pub fn bind_topology(
        self,
        topology_scope: &AndroidTproxyTopologyScopeReport,
    ) -> Result<AndroidMarkDevicePolicy, ReviewedAndroidMarkPolicyCatalogError> {
        let Some(matched) = self.matched else {
            return Ok(AndroidMarkDevicePolicy::generic_aosp());
        };
        AndroidMarkDevicePolicy::device_qualified_cooperative(
            matched.catalog_entry,
            matched.policy_name,
            matched.policy_revision,
            matched.policy_artifact_digest,
            matched.candidate,
            matched.netd_source_profile,
            topology_scope,
            &matched.capability_profile,
            matched.network_namespace,
            matched.planes,
        )
        .map_err(ReviewedAndroidMarkPolicyCatalogError::PolicyConstruction)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchedReviewedAndroidMarkPolicy {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    policy_name: AndroidMarkDevicePolicyName,
    policy_revision: AndroidMarkDevicePolicyRevision,
    policy_artifact_digest: AndroidMarkDevicePolicyArtifactDigest,
    candidate: FwmarkCandidate,
    netd_source_profile: AndroidNetdSourceProfile,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    planes: FwmarkPlaneSet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedAndroidMarkPolicyCatalogField {
    CatalogEntryId,
    AndroidProduct,
    AndroidBuild,
    VendorBuild,
    SecurityPatch,
    KernelBuild,
    SelinuxPolicy,
    Netd,
    Connectivity,
    PolicyName,
    PolicyRevision,
    PolicyArtifactDigest,
    Candidate,
    Planes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewedAndroidMarkPolicyCatalogError {
    TooManyEntries {
        maximum: usize,
        required_at_least: usize,
    },
    InvalidEntry {
        index: usize,
        field: ReviewedAndroidMarkPolicyCatalogField,
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
    PolicyConstruction(AndroidMarkDevicePolicyError),
}

impl fmt::Display for ReviewedAndroidMarkPolicyCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries {
                maximum,
                required_at_least,
            } => write!(
                formatter,
                "reviewed Android mark-policy catalog has at least {required_at_least} entries but its limit is {maximum}"
            ),
            Self::InvalidEntry { index, field } => write!(
                formatter,
                "reviewed Android mark-policy catalog entry {index} has an invalid {field:?} field"
            ),
            Self::DuplicateEntryId { first, second } => write!(
                formatter,
                "reviewed Android mark-policy catalog entries {first} and {second} repeat one entry ID"
            ),
            Self::DuplicateSelector { first, second } => write!(
                formatter,
                "reviewed Android mark-policy catalog entries {first} and {second} repeat one exact device selector"
            ),
            Self::UnverifiedBootIdentity { observation } => write!(
                formatter,
                "reviewed Android mark-policy selection requires verified boot identity, not {observation:?}"
            ),
            Self::UnverifiedDeviceIdentity { observation } => write!(
                formatter,
                "reviewed Android mark-policy selection requires verified device identity, not {observation:?}"
            ),
            Self::NetworkNamespaceMismatch { profile, observed } => write!(
                formatter,
                "reviewed Android mark-policy selection observed network namespace {}:{} rather than profile {}:{}",
                observed.device(),
                observed.inode(),
                profile.device(),
                profile.inode()
            ),
            Self::PolicyConstruction(error) => error.fmt(formatter),
        }
    }
}

impl Error for ReviewedAndroidMarkPolicyCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PolicyConstruction(error) => Some(error),
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

/// Selects one exact source-reviewed Android platform profile from the compiled catalog.
///
/// The current production catalog is empty, so a verified device receives the explicit generic-
/// AOSP zero grant. Runtime manifests, WSA observations, and caller-supplied catalog entries are not
/// accepted by this API.
///
/// External crates cannot bypass the selector through the crate-private positive constructor:
///
/// ```compile_fail
/// use flux_core::AndroidMarkDevicePolicy;
///
/// let _ = AndroidMarkDevicePolicy::device_qualified_cooperative;
/// ```
pub fn select_reviewed_android_mark_policy(
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
) -> Result<ReviewedAndroidMarkPolicySelection, ReviewedAndroidMarkPolicyCatalogError> {
    select_from_catalog(
        REVIEWED_ANDROID_MARK_POLICY_CATALOG,
        capability_profile,
        network_namespace,
    )
}

fn select_from_catalog(
    entries: &[ReviewedAndroidMarkPolicyCatalogEntry],
    capability_profile: &CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
) -> Result<ReviewedAndroidMarkPolicySelection, ReviewedAndroidMarkPolicyCatalogError> {
    let validated = validate_catalog(entries)?;
    if capability_profile.boot_identity().verified().is_none() {
        return Err(
            ReviewedAndroidMarkPolicyCatalogError::UnverifiedBootIdentity {
                observation: capability_profile.boot_identity().kind(),
            },
        );
    }
    let device_identity = capability_profile.device_identity().verified().ok_or(
        ReviewedAndroidMarkPolicyCatalogError::UnverifiedDeviceIdentity {
            observation: capability_profile.device_identity().kind(),
        },
    )?;
    if device_identity.network_namespace() != network_namespace {
        return Err(
            ReviewedAndroidMarkPolicyCatalogError::NetworkNamespaceMismatch {
                profile: device_identity.network_namespace(),
                observed: network_namespace,
            },
        );
    }

    let selector = ReviewedPolicySelector::from_device_identity(device_identity);
    let Some(validated) = validated
        .into_iter()
        .find(|entry| entry.selector == selector)
    else {
        return Ok(ReviewedAndroidMarkPolicySelection { matched: None });
    };

    Ok(ReviewedAndroidMarkPolicySelection {
        matched: Some(MatchedReviewedAndroidMarkPolicy {
            catalog_entry: validated.catalog_entry,
            policy_name: validated.policy_name,
            policy_revision: validated.policy_revision,
            policy_artifact_digest: validated.policy_artifact_digest,
            candidate: validated.candidate,
            netd_source_profile: validated.netd_source_profile,
            capability_profile: capability_profile.clone(),
            network_namespace,
            planes: validated.planes,
        }),
    })
}

fn validate_catalog(
    entries: &[ReviewedAndroidMarkPolicyCatalogEntry],
) -> Result<Vec<ValidatedCatalogEntry>, ReviewedAndroidMarkPolicyCatalogError> {
    if entries.len() > MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES {
        return Err(ReviewedAndroidMarkPolicyCatalogError::TooManyEntries {
            maximum: MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES,
            required_at_least: MAX_REVIEWED_ANDROID_MARK_POLICY_CATALOG_ENTRIES + 1,
        });
    }

    let mut validated: Vec<ValidatedCatalogEntry> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let entry = validate_entry(index, entry)?;
        for (previous_index, previous) in validated.iter().enumerate() {
            if previous.catalog_entry == entry.catalog_entry {
                return Err(ReviewedAndroidMarkPolicyCatalogError::DuplicateEntryId {
                    first: previous_index,
                    second: index,
                });
            }
            if previous.selector == entry.selector {
                return Err(ReviewedAndroidMarkPolicyCatalogError::DuplicateSelector {
                    first: previous_index,
                    second: index,
                });
            }
        }
        validated.push(entry);
    }
    Ok(validated)
}

fn validate_entry(
    index: usize,
    entry: &ReviewedAndroidMarkPolicyCatalogEntry,
) -> Result<ValidatedCatalogEntry, ReviewedAndroidMarkPolicyCatalogError> {
    let invalid = |field| ReviewedAndroidMarkPolicyCatalogError::InvalidEntry { index, field };
    let catalog_entry = ReviewedPolicyCatalogEntryId::new(entry.id)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::CatalogEntryId))?;
    let selector = validate_selector(&entry.selector, index)?;
    let policy_name = AndroidMarkDevicePolicyName::new(entry.policy_name)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::PolicyName))?;
    if policy_name.as_str() != entry.policy_name {
        return Err(invalid(ReviewedAndroidMarkPolicyCatalogField::PolicyName));
    }
    let policy_revision = AndroidMarkDevicePolicyRevision::new(entry.policy_revision)
        .ok_or_else(|| invalid(ReviewedAndroidMarkPolicyCatalogField::PolicyRevision))?;
    let policy_artifact_digest =
        AndroidMarkDevicePolicyArtifactDigest::new(entry.policy_artifact_digest)
            .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::PolicyArtifactDigest))?;
    let candidate =
        FwmarkCandidate::new(entry.candidate_mask, entry.proxy_value, entry.bypass_value)
            .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::Candidate))?;
    if candidate.mask() & !ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK != 0 {
        return Err(invalid(ReviewedAndroidMarkPolicyCatalogField::Candidate));
    }
    let planes = FwmarkPlaneSet::from_bits(entry.planes)
        .filter(|planes| !planes.is_empty())
        .ok_or_else(|| invalid(ReviewedAndroidMarkPolicyCatalogField::Planes))?;

    Ok(ValidatedCatalogEntry {
        catalog_entry,
        selector,
        policy_name,
        policy_revision,
        policy_artifact_digest,
        candidate,
        netd_source_profile: entry.netd_source_profile,
        planes,
    })
}

fn validate_selector(
    selector: &ReviewedPolicySelectorLiteral,
    index: usize,
) -> Result<ReviewedPolicySelector, ReviewedAndroidMarkPolicyCatalogError> {
    let invalid = |field| ReviewedAndroidMarkPolicyCatalogError::InvalidEntry { index, field };
    let android_product = AndroidProductIdentity::new(selector.android_product)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::AndroidProduct))?;
    let android_build = AndroidBuildIdentity::new(selector.android_build)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::AndroidBuild))?;
    let vendor_build = VendorBuildIdentity::new(selector.vendor_build)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::VendorBuild))?;
    let security_patch = SecurityPatchLevel::new(selector.security_patch)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::SecurityPatch))?;
    let kernel_build = KernelBuildIdentity::new(selector.kernel_build)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::KernelBuild))?;
    let selinux_policy = validate_artifact(selector.selinux_policy)
        .map(SelinuxPolicyIdentity::from)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::SelinuxPolicy))?;
    let netd = validate_artifact(selector.netd)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::Netd))?;
    let connectivity = validate_artifact(selector.connectivity)
        .map_err(|_| invalid(ReviewedAndroidMarkPolicyCatalogField::Connectivity))?;
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedCatalogEntry {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    selector: ReviewedPolicySelector,
    policy_name: AndroidMarkDevicePolicyName,
    policy_revision: AndroidMarkDevicePolicyRevision,
    policy_artifact_digest: AndroidMarkDevicePolicyArtifactDigest,
    candidate: FwmarkCandidate,
    netd_source_profile: AndroidNetdSourceProfile,
    planes: FwmarkPlaneSet,
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
struct ReviewedAndroidMarkPolicyCatalogEntry {
    id: &'static str,
    selector: ReviewedPolicySelectorLiteral,
    policy_name: &'static str,
    policy_revision: u64,
    policy_artifact_digest: [u8; 32],
    netd_source_profile: AndroidNetdSourceProfile,
    candidate_mask: u32,
    proxy_value: u32,
    bypass_value: u32,
    planes: u8,
}

#[cfg(test)]
mod tests;
