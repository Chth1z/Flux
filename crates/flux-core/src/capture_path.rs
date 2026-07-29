use sha2::{Digest, Sha256};

use crate::{CapabilityProfileDigest, NetworkNamespaceIdentity, ReviewedPolicyCatalogEntryId};

pub const CAPTURE_PATH_COUNT: usize = CapturePathId::ALL.len();
pub const CAPTURE_PATH_BEHAVIORAL_EVIDENCE_DIGEST_BYTES: usize = 32;
pub const REVIEWED_CAPTURE_PATH_EVIDENCE_ARTIFACT_DIGEST_BYTES: usize = 32;

const CAPTURE_PATH_BEHAVIORAL_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"Flux Capture Path behavioral evidence\0canonical-schema-v1\0sha256-v1\0";

/// Stable product identity of the mechanism that realizes one Capture Program.
///
/// This identifies the selected data path, not the mechanism used to observe it. For example, an
/// eBPF counter source observing an xtables Generation still reports `XtablesTproxy`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapturePathId {
    NftablesTproxy,
    XtablesTproxy,
    ManagedTun,
}

impl CapturePathId {
    pub const ALL: [Self; 3] = [Self::NftablesTproxy, Self::XtablesTproxy, Self::ManagedTun];

    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::NftablesTproxy => "nftables_tproxy",
            Self::XtablesTproxy => "xtables_tproxy",
            Self::ManagedTun => "managed_tun",
        }
    }
}

/// Desired State request for automatic or exact Capture Path selection.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapturePathRequest {
    Auto,
    Exact(CapturePathId),
}

impl CapturePathRequest {
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Exact(path) => path.as_token(),
        }
    }
}

/// Reviewed behavioral result for one Capture Path on one exact platform profile.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CapturePathQualificationState {
    Qualified,
    Unsupported,
    Denied,
    Conflicting,
    Broken,
    Unqualified,
}

/// Complete behavioral qualification set for the closed Capture Path inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CapturePathQualifications {
    nftables_tproxy: CapturePathQualificationState,
    xtables_tproxy: CapturePathQualificationState,
    managed_tun: CapturePathQualificationState,
}

impl CapturePathQualifications {
    #[must_use]
    pub const fn new(
        nftables_tproxy: CapturePathQualificationState,
        xtables_tproxy: CapturePathQualificationState,
        managed_tun: CapturePathQualificationState,
    ) -> Self {
        Self {
            nftables_tproxy,
            xtables_tproxy,
            managed_tun,
        }
    }

    #[must_use]
    pub const fn state(self, path: CapturePathId) -> CapturePathQualificationState {
        match path {
            CapturePathId::NftablesTproxy => self.nftables_tproxy,
            CapturePathId::XtablesTproxy => self.xtables_tproxy,
            CapturePathId::ManagedTun => self.managed_tun,
        }
    }

    pub(crate) fn has_reviewed_outcome(self) -> bool {
        CapturePathId::ALL
            .into_iter()
            .any(|path| self.state(path) != CapturePathQualificationState::Unqualified)
    }
}

impl Default for CapturePathQualifications {
    fn default() -> Self {
        Self::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Unqualified,
        )
    }
}

/// Nonzero revision of one reviewed Capture Path behavioral-evidence artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ReviewedCapturePathEvidenceRevision(u64);

impl ReviewedCapturePathEvidenceRevision {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// SHA-256 identity of one independently reviewed behavioral-evidence artifact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct ReviewedCapturePathEvidenceArtifactDigest(
    [u8; REVIEWED_CAPTURE_PATH_EVIDENCE_ARTIFACT_DIGEST_BYTES],
);

impl ReviewedCapturePathEvidenceArtifactDigest {
    pub(crate) fn new(
        bytes: [u8; REVIEWED_CAPTURE_PATH_EVIDENCE_ARTIFACT_DIGEST_BYTES],
    ) -> Option<Self> {
        bytes.iter().any(|byte| *byte != 0).then_some(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; REVIEWED_CAPTURE_PATH_EVIDENCE_ARTIFACT_DIGEST_BYTES] {
        &self.0
    }
}

/// Provenance attached only when an exact compiled profile contains reviewed behavior.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReviewedCapturePathEvidenceIdentity {
    catalog_entry: ReviewedPolicyCatalogEntryId,
    revision: ReviewedCapturePathEvidenceRevision,
    artifact_digest: ReviewedCapturePathEvidenceArtifactDigest,
}

impl ReviewedCapturePathEvidenceIdentity {
    #[must_use]
    pub const fn catalog_entry(&self) -> &ReviewedPolicyCatalogEntryId {
        &self.catalog_entry
    }

    #[must_use]
    pub const fn revision(&self) -> ReviewedCapturePathEvidenceRevision {
        self.revision
    }

    #[must_use]
    pub const fn artifact_digest(&self) -> ReviewedCapturePathEvidenceArtifactDigest {
        self.artifact_digest
    }
}

/// Domain-separated identity of a complete Capture Path behavioral fact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CapturePathBehavioralEvidenceDigest([u8; CAPTURE_PATH_BEHAVIORAL_EVIDENCE_DIGEST_BYTES]);

impl CapturePathBehavioralEvidenceDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CAPTURE_PATH_BEHAVIORAL_EVIDENCE_DIGEST_BYTES] {
        &self.0
    }
}

/// Exact-profile Capture Path behavior retained by one coherent platform observation.
///
/// Only the compiled reviewed platform-profile catalog can attach positive provenance. An exact
/// profile without a Capture Path aspect and an unmatched profile both produce an explicit
/// all-`Unqualified` value with no reviewed identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturePathBehavioralEvidence {
    qualifications: CapturePathQualifications,
    capability_profile: CapabilityProfileDigest,
    network_namespace: NetworkNamespaceIdentity,
    reviewed_identity: Option<ReviewedCapturePathEvidenceIdentity>,
    digest: CapturePathBehavioralEvidenceDigest,
}

impl CapturePathBehavioralEvidence {
    pub(crate) fn unqualified(
        capability_profile: CapabilityProfileDigest,
        network_namespace: NetworkNamespaceIdentity,
    ) -> Self {
        Self::new(
            CapturePathQualifications::default(),
            capability_profile,
            network_namespace,
            None,
        )
    }

    pub(crate) fn reviewed(
        qualifications: CapturePathQualifications,
        capability_profile: CapabilityProfileDigest,
        network_namespace: NetworkNamespaceIdentity,
        catalog_entry: ReviewedPolicyCatalogEntryId,
        revision: ReviewedCapturePathEvidenceRevision,
        artifact_digest: ReviewedCapturePathEvidenceArtifactDigest,
    ) -> Self {
        Self::new(
            qualifications,
            capability_profile,
            network_namespace,
            Some(ReviewedCapturePathEvidenceIdentity {
                catalog_entry,
                revision,
                artifact_digest,
            }),
        )
    }

    fn new(
        qualifications: CapturePathQualifications,
        capability_profile: CapabilityProfileDigest,
        network_namespace: NetworkNamespaceIdentity,
        reviewed_identity: Option<ReviewedCapturePathEvidenceIdentity>,
    ) -> Self {
        let digest = digest_behavioral_evidence(
            qualifications,
            capability_profile,
            network_namespace,
            reviewed_identity.as_ref(),
        );
        Self {
            qualifications,
            capability_profile,
            network_namespace,
            reviewed_identity,
            digest,
        }
    }

    #[must_use]
    pub const fn qualifications(&self) -> CapturePathQualifications {
        self.qualifications
    }

    #[must_use]
    pub const fn capability_profile_digest(&self) -> CapabilityProfileDigest {
        self.capability_profile
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn reviewed_identity(&self) -> Option<&ReviewedCapturePathEvidenceIdentity> {
        self.reviewed_identity.as_ref()
    }

    #[must_use]
    pub const fn digest(&self) -> CapturePathBehavioralEvidenceDigest {
        self.digest
    }
}

fn digest_behavioral_evidence(
    qualifications: CapturePathQualifications,
    capability_profile: CapabilityProfileDigest,
    network_namespace: NetworkNamespaceIdentity,
    reviewed_identity: Option<&ReviewedCapturePathEvidenceIdentity>,
) -> CapturePathBehavioralEvidenceDigest {
    let mut digest = Sha256::new();
    digest.update(CAPTURE_PATH_BEHAVIORAL_EVIDENCE_DIGEST_DOMAIN);
    digest.update(capability_profile.as_bytes());
    digest.update(network_namespace.device().to_be_bytes());
    digest.update(network_namespace.inode().to_be_bytes());
    for path in CapturePathId::ALL {
        digest.update([
            capture_path_tag(path),
            qualification_state_tag(qualifications.state(path)),
        ]);
    }
    match reviewed_identity {
        Some(identity) => {
            digest.update([1]);
            update_digest_field(&mut digest, identity.catalog_entry.as_str().as_bytes());
            digest.update(identity.revision.get().to_be_bytes());
            digest.update(identity.artifact_digest.as_bytes());
        }
        None => digest.update([0]),
    }
    CapturePathBehavioralEvidenceDigest(digest.finalize().into())
}

fn update_digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update(value.len().to_be_bytes());
    digest.update(value);
}

const fn capture_path_tag(path: CapturePathId) -> u8 {
    match path {
        CapturePathId::NftablesTproxy => 0,
        CapturePathId::XtablesTproxy => 1,
        CapturePathId::ManagedTun => 2,
    }
}

const fn qualification_state_tag(state: CapturePathQualificationState) -> u8 {
    match state {
        CapturePathQualificationState::Qualified => 0,
        CapturePathQualificationState::Unsupported => 1,
        CapturePathQualificationState::Denied => 2,
        CapturePathQualificationState::Conflicting => 3,
        CapturePathQualificationState::Broken => 4,
        CapturePathQualificationState::Unqualified => 5,
    }
}

/// Closed inventory of complete mutation Adapters available to the selector.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct ImplementedCaptureAdapters {
    nftables_tproxy: bool,
    xtables_tproxy: bool,
    managed_tun: bool,
}

impl ImplementedCaptureAdapters {
    #[must_use]
    pub const fn new(nftables_tproxy: bool, xtables_tproxy: bool, managed_tun: bool) -> Self {
        Self {
            nftables_tproxy,
            xtables_tproxy,
            managed_tun,
        }
    }

    #[must_use]
    pub const fn contains(self, path: CapturePathId) -> bool {
        match path {
            CapturePathId::NftablesTproxy => self.nftables_tproxy,
            CapturePathId::XtablesTproxy => self.xtables_tproxy,
            CapturePathId::ManagedTun => self.managed_tun,
        }
    }

    #[must_use]
    pub fn count(self) -> u8 {
        u8::from(self.nftables_tproxy) + u8::from(self.xtables_tproxy) + u8::from(self.managed_tun)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_path_tokens_are_stable_and_unique() {
        let mut tokens = CapturePathId::ALL.map(CapturePathId::as_token);
        tokens.sort_unstable();
        assert_eq!(tokens, ["managed_tun", "nftables_tproxy", "xtables_tproxy"]);
    }

    #[test]
    fn path_requests_have_one_current_token_grammar() {
        assert_eq!(CapturePathRequest::Auto.as_token(), "auto");
        for path in CapturePathId::ALL {
            assert_eq!(CapturePathRequest::Exact(path).as_token(), path.as_token());
        }
    }

    #[test]
    fn implemented_adapter_inventory_is_closed_over_every_path() {
        let adapters = ImplementedCaptureAdapters::new(false, true, false);
        assert_eq!(adapters.count(), 1);
        assert!(!adapters.contains(CapturePathId::NftablesTproxy));
        assert!(adapters.contains(CapturePathId::XtablesTproxy));
        assert!(!adapters.contains(CapturePathId::ManagedTun));
    }

    #[test]
    fn default_qualifications_are_explicitly_non_authorizing() {
        let qualifications = CapturePathQualifications::default();
        assert!(CapturePathId::ALL.into_iter().all(|path| {
            qualifications.state(path) == CapturePathQualificationState::Unqualified
        }));
        assert!(!qualifications.has_reviewed_outcome());
    }
}
