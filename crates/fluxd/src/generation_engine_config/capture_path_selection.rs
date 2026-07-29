use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use flux_core::{
    AddressHostFamilySelection, CAPTURE_PATH_COUNT, CaptureConfig, CapturePathBehavioralEvidence,
    CapturePathId, CapturePathQualificationState, CapturePathQualifications, CapturePathRequest,
    CaptureTrafficDomain, CaptureTransportProtocol, ImplementedCaptureAdapters,
};
use flux_platform::{
    AndroidCapturePathState, AndroidKernelConfigSnapshot, AndroidKernelFeature,
    AndroidKernelFeatureState, select_android_capture_path,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::candidate::TproxyGenerationCandidate;

pub const CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES: usize = 32;
pub(crate) const CAPTURE_PATH_QUALIFICATION_EVIDENCE_MAX_AGE: Duration =
    Duration::from_secs(5 * 60);

const CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_DOMAIN: &[u8] =
    b"Flux Capture Path decision\0canonical-schema-v2\0sha256-v1\0";

pub(crate) const PRODUCTION_IMPLEMENTED_CAPTURE_ADAPTERS: ImplementedCaptureAdapters =
    ImplementedCaptureAdapters::new(false, true, false);
pub(crate) const PRODUCTION_CAPTURE_PATH_SELECTOR: CapturePathSelector =
    CapturePathSelector::new(PRODUCTION_IMPLEMENTED_CAPTURE_ADAPTERS);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapturePathQualificationEvidence {
    source: CapturePathQualificationSource,
    observed_at: Instant,
    valid_until: Instant,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CapturePathQualificationSource {
    Android(CapturePathBehavioralEvidence),
    #[cfg(test)]
    HostInspection(CapturePathQualifications),
}

impl CapturePathQualificationEvidence {
    fn from_source(
        source: CapturePathQualificationSource,
        observed_at: Instant,
        valid_until: Instant,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        let lifetime = valid_until
            .checked_duration_since(observed_at)
            .filter(|lifetime| !lifetime.is_zero())
            .ok_or(CapturePathQualificationEvidenceError::NonPositiveLifetime)?;
        if lifetime > CAPTURE_PATH_QUALIFICATION_EVIDENCE_MAX_AGE {
            return Err(CapturePathQualificationEvidenceError::LifetimeExceedsMaximum { lifetime });
        }
        Ok(Self {
            source,
            observed_at,
            valid_until,
        })
    }

    pub(crate) fn with_maximum_lifetime(
        evidence: CapturePathBehavioralEvidence,
        observed_at: Instant,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        Self::from_source_with_maximum_lifetime(
            CapturePathQualificationSource::Android(evidence),
            observed_at,
        )
    }

    fn from_source_with_maximum_lifetime(
        source: CapturePathQualificationSource,
        observed_at: Instant,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        let valid_until = observed_at
            .checked_add(CAPTURE_PATH_QUALIFICATION_EVIDENCE_MAX_AGE)
            .ok_or(CapturePathQualificationEvidenceError::DeadlineOverflow)?;
        Self::from_source(source, observed_at, valid_until)
    }

    #[cfg(test)]
    pub(crate) fn host_inspection(
        qualifications: CapturePathQualifications,
        observed_at: Instant,
        valid_until: Instant,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        Self::from_source(
            CapturePathQualificationSource::HostInspection(qualifications),
            observed_at,
            valid_until,
        )
    }

    #[cfg(test)]
    pub(crate) fn host_inspection_with_maximum_lifetime(
        qualifications: CapturePathQualifications,
        observed_at: Instant,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        Self::from_source_with_maximum_lifetime(
            CapturePathQualificationSource::HostInspection(qualifications),
            observed_at,
        )
    }

    pub(crate) const fn qualifications(&self) -> CapturePathQualifications {
        match &self.source {
            CapturePathQualificationSource::Android(evidence) => evidence.qualifications(),
            #[cfg(test)]
            CapturePathQualificationSource::HostInspection(qualifications) => *qualifications,
        }
    }

    pub(crate) const fn valid_until(&self) -> Instant {
        self.valid_until
    }

    fn matches_candidate(&self, candidate: &TproxyGenerationCandidate) -> bool {
        match &self.source {
            CapturePathQualificationSource::Android(evidence) => {
                let profile = candidate.device_profile();
                evidence.capability_profile_digest() == profile.digest()
                    && profile
                        .device_identity()
                        .verified()
                        .is_some_and(|identity| {
                            evidence.network_namespace() == identity.network_namespace()
                        })
            }
            #[cfg(test)]
            CapturePathQualificationSource::HostInspection(_) => true,
        }
    }

    pub(crate) fn behavioral_digest(&self) -> Option<[u8; 32]> {
        match &self.source {
            CapturePathQualificationSource::Android(evidence) => {
                Some(*evidence.digest().as_bytes())
            }
            #[cfg(test)]
            CapturePathQualificationSource::HostInspection(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapturePathQualificationEvidenceError {
    NonPositiveLifetime,
    LifetimeExceedsMaximum { lifetime: Duration },
    DeadlineOverflow,
}

impl fmt::Display for CapturePathQualificationEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonPositiveLifetime => {
                formatter.write_str("Capture Path qualification lifetime must be positive")
            }
            Self::LifetimeExceedsMaximum { lifetime } => write!(
                formatter,
                "Capture Path qualification lifetime {lifetime:?} exceeds the five-minute maximum",
            ),
            Self::DeadlineOverflow => formatter
                .write_str("Capture Path qualification deadline exceeds the monotonic clock"),
        }
    }
}

impl Error for CapturePathQualificationEvidenceError {}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct CapturePathSelectionEvidenceDigest([u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES]);

impl CapturePathSelectionEvidenceDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES] {
        &self.0
    }

    #[must_use]
    pub(crate) const fn from_bytes(
        bytes: [u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES],
    ) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for CapturePathSelectionEvidenceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePathSelectionReason {
    AutomaticHighestRankedQualified,
    ExactRequestQualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapturePathKernelGap {
    feature: AndroidKernelFeature,
    state: AndroidKernelFeatureState,
}

impl CapturePathKernelGap {
    #[must_use]
    pub const fn feature(self) -> AndroidKernelFeature {
        self.feature
    }

    #[must_use]
    pub const fn state(self) -> AndroidKernelFeatureState {
        self.state
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    into = "SerializedCapturePathCandidate",
    try_from = "SerializedCapturePathCandidate"
)]
pub struct CapturePathCandidateStatus {
    path: CapturePathId,
    state: AndroidCapturePathState,
    qualification_state: CapturePathQualificationState,
    first_kernel_gap: Option<CapturePathKernelGap>,
}

impl CapturePathCandidateStatus {
    #[must_use]
    pub const fn path(self) -> CapturePathId {
        self.path
    }

    #[must_use]
    pub const fn state(self) -> AndroidCapturePathState {
        self.state
    }

    #[must_use]
    pub const fn qualification_state(self) -> CapturePathQualificationState {
        self.qualification_state
    }

    #[must_use]
    pub const fn first_kernel_gap(self) -> Option<CapturePathKernelGap> {
        self.first_kernel_gap
    }

    #[must_use]
    pub(crate) const fn from_status_parts(
        path: CapturePathId,
        state: AndroidCapturePathState,
        qualification_state: CapturePathQualificationState,
        first_kernel_gap: Option<CapturePathKernelGap>,
    ) -> Self {
        Self {
            path,
            state,
            qualification_state,
            first_kernel_gap,
        }
    }

    fn has_coherent_authorizing_evidence(self) -> bool {
        self.state != AndroidCapturePathState::Qualified
            || (self.qualification_state == CapturePathQualificationState::Qualified
                && !matches!(
                    self.first_kernel_gap,
                    Some(CapturePathKernelGap {
                        state: AndroidKernelFeatureState::Disabled,
                        ..
                    })
                ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    into = "SerializedCapturePathSelection",
    try_from = "SerializedCapturePathSelection"
)]
pub struct CapturePathSelection {
    request: CapturePathRequest,
    selected: CapturePathId,
    reason: CapturePathSelectionReason,
    candidates: [CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
    evidence_digest: CapturePathSelectionEvidenceDigest,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    into = "SerializedCapturePathRejection",
    try_from = "SerializedCapturePathRejection"
)]
pub struct CapturePathRejection {
    request: CapturePathRequest,
    reason: CapturePathRejectionReason,
    candidates: [CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
    evidence_digest: CapturePathSelectionEvidenceDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapturePathRejectionReason {
    NoQualifiedPath,
    ExactPathUnavailable {
        path: CapturePathId,
        state: AndroidCapturePathState,
    },
    QualificationEvidenceNotYetObserved,
    QualificationEvidenceExpired,
    QualificationEvidenceContextMismatch,
    InvalidDecision,
}

impl CapturePathQualificationEvidence {
    fn rejection_at(&self, evaluated_at: Instant) -> Option<CapturePathRejectionReason> {
        if evaluated_at < self.observed_at {
            Some(CapturePathRejectionReason::QualificationEvidenceNotYetObserved)
        } else if evaluated_at >= self.valid_until {
            Some(CapturePathRejectionReason::QualificationEvidenceExpired)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CapturePathDecision {
    Selected { selection: CapturePathSelection },
    Rejected { rejection: CapturePathRejection },
}

#[derive(Debug)]
pub struct CapturePathSelectionDecodeError {
    detail: &'static str,
}

impl fmt::Display for CapturePathSelectionDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.detail)
    }
}

impl Error for CapturePathSelectionDecodeError {}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapturePathSelection {
    request: String,
    selected: String,
    reason: SerializedCapturePathSelectionReason,
    candidates: [SerializedCapturePathCandidate; CAPTURE_PATH_COUNT],
    evidence_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapturePathRejection {
    request: String,
    reason: SerializedCapturePathRejectionReason,
    candidates: [SerializedCapturePathCandidate; CAPTURE_PATH_COUNT],
    evidence_digest: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
enum SerializedCapturePathRejectionReason {
    NoQualifiedPath,
    ExactPathUnavailable {
        path: String,
        state: SerializedCapturePathState,
    },
    QualificationEvidenceNotYetObserved,
    QualificationEvidenceExpired,
    QualificationEvidenceContextMismatch,
    InvalidDecision,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SerializedCapturePathSelectionReason {
    AutomaticHighestRankedQualified,
    ExactRequestQualified,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapturePathCandidate {
    path: String,
    state: SerializedCapturePathState,
    qualification_state: SerializedCapturePathQualificationState,
    first_kernel_gap: Option<SerializedCapturePathKernelGap>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SerializedCapturePathQualificationState {
    Qualified,
    Unsupported,
    Denied,
    Conflicting,
    Broken,
    Unqualified,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SerializedCapturePathState {
    Qualified,
    Unimplemented,
    Missing,
    Denied,
    Conflicting,
    Broken,
    Unqualified,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SerializedCapturePathKernelGap {
    config_symbol: String,
    state: SerializedKernelFeatureState,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SerializedKernelFeatureState {
    BuiltIn,
    Module,
    Disabled,
    Configured,
    Unreported,
}

impl From<CapturePathSelection> for SerializedCapturePathSelection {
    fn from(selection: CapturePathSelection) -> Self {
        Self {
            request: selection.request.as_token().to_owned(),
            selected: selection.selected.as_token().to_owned(),
            reason: match selection.reason {
                CapturePathSelectionReason::AutomaticHighestRankedQualified => {
                    SerializedCapturePathSelectionReason::AutomaticHighestRankedQualified
                }
                CapturePathSelectionReason::ExactRequestQualified => {
                    SerializedCapturePathSelectionReason::ExactRequestQualified
                }
            },
            candidates: selection.candidates.map(Into::into),
            evidence_digest: selection.evidence_digest.to_string(),
        }
    }
}

impl TryFrom<SerializedCapturePathSelection> for CapturePathSelection {
    type Error = CapturePathSelectionDecodeError;

    fn try_from(selection: SerializedCapturePathSelection) -> Result<Self, Self::Error> {
        let [first, second, third] = selection.candidates;
        let candidates = [first.try_into()?, second.try_into()?, third.try_into()?];
        Self::try_from_status_parts(
            parse_capture_path_request(&selection.request)?,
            parse_capture_path(&selection.selected)?,
            match selection.reason {
                SerializedCapturePathSelectionReason::AutomaticHighestRankedQualified => {
                    CapturePathSelectionReason::AutomaticHighestRankedQualified
                }
                SerializedCapturePathSelectionReason::ExactRequestQualified => {
                    CapturePathSelectionReason::ExactRequestQualified
                }
            },
            candidates,
            CapturePathSelectionEvidenceDigest::from_bytes(decode_digest(
                &selection.evidence_digest,
            )?),
        )
        .map_err(|_| decode_error("Capture Path selection is structurally incoherent"))
    }
}

impl From<CapturePathRejection> for SerializedCapturePathRejection {
    fn from(rejection: CapturePathRejection) -> Self {
        Self {
            request: rejection.request.as_token().to_owned(),
            reason: rejection.reason.into(),
            candidates: rejection.candidates.map(Into::into),
            evidence_digest: rejection.evidence_digest.to_string(),
        }
    }
}

impl TryFrom<SerializedCapturePathRejection> for CapturePathRejection {
    type Error = CapturePathSelectionDecodeError;

    fn try_from(rejection: SerializedCapturePathRejection) -> Result<Self, Self::Error> {
        let [first, second, third] = rejection.candidates;
        Self::try_from_status_parts(
            parse_capture_path_request(&rejection.request)?,
            rejection.reason.try_into()?,
            [first.try_into()?, second.try_into()?, third.try_into()?],
            CapturePathSelectionEvidenceDigest::from_bytes(decode_digest(
                &rejection.evidence_digest,
            )?),
        )
        .map_err(|_| decode_error("Capture Path rejection is structurally incoherent"))
    }
}

impl From<CapturePathRejectionReason> for SerializedCapturePathRejectionReason {
    fn from(reason: CapturePathRejectionReason) -> Self {
        match reason {
            CapturePathRejectionReason::NoQualifiedPath => Self::NoQualifiedPath,
            CapturePathRejectionReason::ExactPathUnavailable { path, state } => {
                Self::ExactPathUnavailable {
                    path: path.as_token().to_owned(),
                    state: state.into(),
                }
            }
            CapturePathRejectionReason::QualificationEvidenceNotYetObserved => {
                Self::QualificationEvidenceNotYetObserved
            }
            CapturePathRejectionReason::QualificationEvidenceExpired => {
                Self::QualificationEvidenceExpired
            }
            CapturePathRejectionReason::QualificationEvidenceContextMismatch => {
                Self::QualificationEvidenceContextMismatch
            }
            CapturePathRejectionReason::InvalidDecision => Self::InvalidDecision,
        }
    }
}

impl TryFrom<SerializedCapturePathRejectionReason> for CapturePathRejectionReason {
    type Error = CapturePathSelectionDecodeError;

    fn try_from(reason: SerializedCapturePathRejectionReason) -> Result<Self, Self::Error> {
        Ok(match reason {
            SerializedCapturePathRejectionReason::NoQualifiedPath => Self::NoQualifiedPath,
            SerializedCapturePathRejectionReason::ExactPathUnavailable { path, state } => {
                Self::ExactPathUnavailable {
                    path: parse_capture_path(&path)?,
                    state: state.into(),
                }
            }
            SerializedCapturePathRejectionReason::QualificationEvidenceNotYetObserved => {
                Self::QualificationEvidenceNotYetObserved
            }
            SerializedCapturePathRejectionReason::QualificationEvidenceExpired => {
                Self::QualificationEvidenceExpired
            }
            SerializedCapturePathRejectionReason::QualificationEvidenceContextMismatch => {
                Self::QualificationEvidenceContextMismatch
            }
            SerializedCapturePathRejectionReason::InvalidDecision => Self::InvalidDecision,
        })
    }
}

impl From<CapturePathCandidateStatus> for SerializedCapturePathCandidate {
    fn from(candidate: CapturePathCandidateStatus) -> Self {
        Self {
            path: candidate.path.as_token().to_owned(),
            state: candidate.state.into(),
            qualification_state: candidate.qualification_state.into(),
            first_kernel_gap: candidate.first_kernel_gap.map(|gap| {
                SerializedCapturePathKernelGap {
                    config_symbol: gap.feature.config_symbol().to_owned(),
                    state: gap.state.into(),
                }
            }),
        }
    }
}

impl TryFrom<SerializedCapturePathCandidate> for CapturePathCandidateStatus {
    type Error = CapturePathSelectionDecodeError;

    fn try_from(candidate: SerializedCapturePathCandidate) -> Result<Self, Self::Error> {
        let candidate = Self::from_status_parts(
            parse_capture_path(&candidate.path)?,
            candidate.state.into(),
            candidate.qualification_state.into(),
            candidate
                .first_kernel_gap
                .map(|gap| {
                    Ok(CapturePathKernelGap {
                        feature: flux_platform::ALL_ANDROID_KERNEL_FEATURES
                            .into_iter()
                            .find(|feature| feature.config_symbol() == gap.config_symbol)
                            .ok_or_else(|| {
                                decode_error("Capture Path kernel gap has an unknown feature")
                            })?,
                        state: gap.state.into(),
                    })
                })
                .transpose()?,
        );
        if !candidate.has_coherent_authorizing_evidence() {
            return Err(decode_error(
                "qualified Capture Path candidate has contradictory evidence",
            ));
        }
        Ok(candidate)
    }
}

impl From<CapturePathQualificationState> for SerializedCapturePathQualificationState {
    fn from(state: CapturePathQualificationState) -> Self {
        match state {
            CapturePathQualificationState::Qualified => Self::Qualified,
            CapturePathQualificationState::Unsupported => Self::Unsupported,
            CapturePathQualificationState::Denied => Self::Denied,
            CapturePathQualificationState::Conflicting => Self::Conflicting,
            CapturePathQualificationState::Broken => Self::Broken,
            CapturePathQualificationState::Unqualified => Self::Unqualified,
        }
    }
}

impl From<SerializedCapturePathQualificationState> for CapturePathQualificationState {
    fn from(state: SerializedCapturePathQualificationState) -> Self {
        match state {
            SerializedCapturePathQualificationState::Qualified => Self::Qualified,
            SerializedCapturePathQualificationState::Unsupported => Self::Unsupported,
            SerializedCapturePathQualificationState::Denied => Self::Denied,
            SerializedCapturePathQualificationState::Conflicting => Self::Conflicting,
            SerializedCapturePathQualificationState::Broken => Self::Broken,
            SerializedCapturePathQualificationState::Unqualified => Self::Unqualified,
        }
    }
}

impl From<AndroidCapturePathState> for SerializedCapturePathState {
    fn from(state: AndroidCapturePathState) -> Self {
        match state {
            AndroidCapturePathState::Qualified => Self::Qualified,
            AndroidCapturePathState::Unimplemented => Self::Unimplemented,
            AndroidCapturePathState::Missing => Self::Missing,
            AndroidCapturePathState::Denied => Self::Denied,
            AndroidCapturePathState::Conflicting => Self::Conflicting,
            AndroidCapturePathState::Broken => Self::Broken,
            AndroidCapturePathState::Unqualified => Self::Unqualified,
        }
    }
}

impl From<SerializedCapturePathState> for AndroidCapturePathState {
    fn from(state: SerializedCapturePathState) -> Self {
        match state {
            SerializedCapturePathState::Qualified => Self::Qualified,
            SerializedCapturePathState::Unimplemented => Self::Unimplemented,
            SerializedCapturePathState::Missing => Self::Missing,
            SerializedCapturePathState::Denied => Self::Denied,
            SerializedCapturePathState::Conflicting => Self::Conflicting,
            SerializedCapturePathState::Broken => Self::Broken,
            SerializedCapturePathState::Unqualified => Self::Unqualified,
        }
    }
}

impl From<AndroidKernelFeatureState> for SerializedKernelFeatureState {
    fn from(state: AndroidKernelFeatureState) -> Self {
        match state {
            AndroidKernelFeatureState::BuiltIn => Self::BuiltIn,
            AndroidKernelFeatureState::Module => Self::Module,
            AndroidKernelFeatureState::Disabled => Self::Disabled,
            AndroidKernelFeatureState::Configured => Self::Configured,
            AndroidKernelFeatureState::Unreported => Self::Unreported,
        }
    }
}

impl From<SerializedKernelFeatureState> for AndroidKernelFeatureState {
    fn from(state: SerializedKernelFeatureState) -> Self {
        match state {
            SerializedKernelFeatureState::BuiltIn => Self::BuiltIn,
            SerializedKernelFeatureState::Module => Self::Module,
            SerializedKernelFeatureState::Disabled => Self::Disabled,
            SerializedKernelFeatureState::Configured => Self::Configured,
            SerializedKernelFeatureState::Unreported => Self::Unreported,
        }
    }
}

fn parse_capture_path_request(
    token: &str,
) -> Result<CapturePathRequest, CapturePathSelectionDecodeError> {
    if token == CapturePathRequest::Auto.as_token() {
        return Ok(CapturePathRequest::Auto);
    }
    parse_capture_path(token).map(CapturePathRequest::Exact)
}

fn parse_capture_path(token: &str) -> Result<CapturePathId, CapturePathSelectionDecodeError> {
    CapturePathId::ALL
        .into_iter()
        .find(|path| path.as_token() == token)
        .ok_or_else(|| decode_error("Capture Path selection has an unknown path token"))
}

fn decode_digest(
    encoded: &str,
) -> Result<[u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES], CapturePathSelectionDecodeError> {
    if encoded.len() != CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES * 2 {
        return Err(decode_error(
            "Capture Path selection digest is not lowercase SHA-256 hex",
        ));
    }
    let mut decoded = [0_u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES];
    for (target, pair) in decoded.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            decode_error("Capture Path selection digest is not lowercase SHA-256 hex")
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            decode_error("Capture Path selection digest is not lowercase SHA-256 hex")
        })?;
        *target = high << 4 | low;
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

const fn decode_error(detail: &'static str) -> CapturePathSelectionDecodeError {
    CapturePathSelectionDecodeError { detail }
}

impl CapturePathSelection {
    #[must_use]
    pub const fn request(self) -> CapturePathRequest {
        self.request
    }

    #[must_use]
    pub const fn selected(self) -> CapturePathId {
        self.selected
    }

    #[must_use]
    pub const fn reason(self) -> CapturePathSelectionReason {
        self.reason
    }

    #[must_use]
    pub const fn candidates(&self) -> &[CapturePathCandidateStatus; CAPTURE_PATH_COUNT] {
        &self.candidates
    }

    #[must_use]
    pub const fn evidence_digest(self) -> CapturePathSelectionEvidenceDigest {
        self.evidence_digest
    }

    pub(crate) fn try_from_status_parts(
        request: CapturePathRequest,
        selected: CapturePathId,
        reason: CapturePathSelectionReason,
        candidates: [CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
        evidence_digest: CapturePathSelectionEvidenceDigest,
    ) -> Result<Self, CapturePathSelectionStatusError> {
        if candidates.map(CapturePathCandidateStatus::path) != CapturePathId::ALL {
            return Err(CapturePathSelectionStatusError::CandidateOrder);
        }
        if candidates
            .iter()
            .any(|candidate| !candidate.has_coherent_authorizing_evidence())
        {
            return Err(CapturePathSelectionStatusError::QualifiedEvidenceMismatch);
        }
        if candidates
            .iter()
            .find(|candidate| candidate.path == selected)
            .is_none_or(|candidate| candidate.state != AndroidCapturePathState::Qualified)
        {
            return Err(CapturePathSelectionStatusError::SelectedPathNotQualified);
        }
        match (request, reason) {
            (
                CapturePathRequest::Auto,
                CapturePathSelectionReason::AutomaticHighestRankedQualified,
            ) => {
                let first_qualified = candidates
                    .iter()
                    .find(|candidate| candidate.state == AndroidCapturePathState::Qualified)
                    .map(|candidate| candidate.path);
                if first_qualified != Some(selected) {
                    return Err(CapturePathSelectionStatusError::AutomaticOrder);
                }
            }
            (
                CapturePathRequest::Exact(requested),
                CapturePathSelectionReason::ExactRequestQualified,
            ) if requested == selected => {}
            _ => return Err(CapturePathSelectionStatusError::RequestReasonMismatch),
        }
        Ok(Self {
            request,
            selected,
            reason,
            candidates,
            evidence_digest,
        })
    }
}

impl CapturePathRejection {
    #[must_use]
    pub const fn request(self) -> CapturePathRequest {
        self.request
    }

    #[must_use]
    pub const fn reason(self) -> CapturePathRejectionReason {
        self.reason
    }

    #[must_use]
    pub const fn candidates(&self) -> &[CapturePathCandidateStatus; CAPTURE_PATH_COUNT] {
        &self.candidates
    }

    #[must_use]
    pub const fn evidence_digest(self) -> CapturePathSelectionEvidenceDigest {
        self.evidence_digest
    }

    fn try_from_status_parts(
        request: CapturePathRequest,
        reason: CapturePathRejectionReason,
        candidates: [CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
        evidence_digest: CapturePathSelectionEvidenceDigest,
    ) -> Result<Self, CapturePathSelectionStatusError> {
        if candidates.map(CapturePathCandidateStatus::path) != CapturePathId::ALL {
            return Err(CapturePathSelectionStatusError::CandidateOrder);
        }
        if candidates
            .iter()
            .any(|candidate| !candidate.has_coherent_authorizing_evidence())
        {
            return Err(CapturePathSelectionStatusError::QualifiedEvidenceMismatch);
        }
        match (request, reason) {
            (CapturePathRequest::Auto, CapturePathRejectionReason::NoQualifiedPath)
                if candidates
                    .iter()
                    .all(|candidate| candidate.state != AndroidCapturePathState::Qualified) => {}
            (
                CapturePathRequest::Exact(requested),
                CapturePathRejectionReason::ExactPathUnavailable { path, state },
            ) if requested == path
                && state != AndroidCapturePathState::Qualified
                && candidates
                    .iter()
                    .any(|candidate| candidate.path == path && candidate.state == state) => {}
            (
                _,
                CapturePathRejectionReason::QualificationEvidenceNotYetObserved
                | CapturePathRejectionReason::QualificationEvidenceExpired
                | CapturePathRejectionReason::QualificationEvidenceContextMismatch,
            ) => {}
            (_, CapturePathRejectionReason::InvalidDecision) => {}
            _ => return Err(CapturePathSelectionStatusError::RejectionMismatch),
        }
        Ok(Self {
            request,
            reason,
            candidates,
            evidence_digest,
        })
    }
}

impl CapturePathDecision {
    #[must_use]
    pub const fn request(self) -> CapturePathRequest {
        match self {
            Self::Selected { selection } => selection.request(),
            Self::Rejected { rejection } => rejection.request(),
        }
    }

    #[must_use]
    pub const fn selection(self) -> Option<CapturePathSelection> {
        match self {
            Self::Selected { selection } => Some(selection),
            Self::Rejected { .. } => None,
        }
    }

    #[must_use]
    pub const fn rejection(self) -> Option<CapturePathRejection> {
        match self {
            Self::Selected { .. } => None,
            Self::Rejected { rejection } => Some(rejection),
        }
    }

    #[must_use]
    pub const fn candidates(&self) -> &[CapturePathCandidateStatus; CAPTURE_PATH_COUNT] {
        match self {
            Self::Selected { selection } => selection.candidates(),
            Self::Rejected { rejection } => rejection.candidates(),
        }
    }

    #[must_use]
    pub const fn evidence_digest(self) -> CapturePathSelectionEvidenceDigest {
        match self {
            Self::Selected { selection } => selection.evidence_digest(),
            Self::Rejected { rejection } => rejection.evidence_digest(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapturePathSelectionStatusError {
    CandidateOrder,
    QualifiedEvidenceMismatch,
    SelectedPathNotQualified,
    AutomaticOrder,
    RequestReasonMismatch,
    RejectionMismatch,
}

#[derive(Clone, Copy)]
pub(crate) struct CapturePathSelectionInput<'a> {
    capture: CaptureConfig,
    candidate: &'a TproxyGenerationCandidate,
    kernel_config: &'a AndroidKernelConfigSnapshot,
    qualification_evidence: &'a CapturePathQualificationEvidence,
    planning_evidence_digest: &'a [u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES],
}

impl<'a> CapturePathSelectionInput<'a> {
    #[must_use]
    pub(crate) const fn new(
        capture: CaptureConfig,
        candidate: &'a TproxyGenerationCandidate,
        kernel_config: &'a AndroidKernelConfigSnapshot,
        qualification_evidence: &'a CapturePathQualificationEvidence,
        planning_evidence_digest: &'a [u8; CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_BYTES],
    ) -> Self {
        Self {
            capture,
            candidate,
            kernel_config,
            qualification_evidence,
            planning_evidence_digest,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapturePathSelector {
    implemented_adapters: ImplementedCaptureAdapters,
}

impl CapturePathSelector {
    #[must_use]
    pub(crate) const fn new(implemented_adapters: ImplementedCaptureAdapters) -> Self {
        Self {
            implemented_adapters,
        }
    }

    pub(crate) fn select(
        self,
        input: CapturePathSelectionInput<'_>,
    ) -> Result<CapturePathSelection, CapturePathSelectionError> {
        let decision = select_android_capture_path(
            input.kernel_config,
            self.implemented_adapters,
            input.qualification_evidence.qualifications(),
            input.capture.path_request(),
        );
        let candidates = decision
            .candidates()
            .map(|candidate| CapturePathCandidateStatus {
                path: candidate.path(),
                state: candidate.state(),
                qualification_state: candidate.qualification_state(),
                first_kernel_gap: candidate
                    .first_kernel_gap()
                    .map(|(feature, state)| CapturePathKernelGap { feature, state }),
            });
        if !input
            .qualification_evidence
            .matches_candidate(input.candidate)
        {
            return Err(selection_error(
                input,
                self.implemented_adapters,
                CapturePathRejectionReason::QualificationEvidenceContextMismatch,
                candidates,
            ));
        }
        if let Some(reason) = input.qualification_evidence.rejection_at(Instant::now()) {
            return Err(selection_error(
                input,
                self.implemented_adapters,
                reason,
                candidates,
            ));
        }
        let Some(selected) = decision.selected() else {
            let reason = match input.capture.path_request() {
                CapturePathRequest::Auto => CapturePathRejectionReason::NoQualifiedPath,
                CapturePathRequest::Exact(path) => {
                    CapturePathRejectionReason::ExactPathUnavailable {
                        path,
                        state: decision.candidate(path).state(),
                    }
                }
            };
            return Err(selection_error(
                input,
                self.implemented_adapters,
                reason,
                candidates,
            ));
        };
        let reason = match input.capture.path_request() {
            CapturePathRequest::Auto => CapturePathSelectionReason::AutomaticHighestRankedQualified,
            CapturePathRequest::Exact(_) => CapturePathSelectionReason::ExactRequestQualified,
        };
        let evidence_digest = digest_capture_path_decision(
            input,
            self.implemented_adapters,
            CapturePathDecisionDigestOutcome::Selected { selected, reason },
            &candidates,
        );
        CapturePathSelection::try_from_status_parts(
            input.capture.path_request(),
            selected,
            reason,
            candidates,
            evidence_digest,
        )
        .map_err(|_| CapturePathSelectionError {
            rejection: CapturePathRejection {
                request: input.capture.path_request(),
                reason: CapturePathRejectionReason::InvalidDecision,
                candidates,
                evidence_digest,
            },
        })
    }
}

fn selection_error(
    input: CapturePathSelectionInput<'_>,
    implemented_adapters: ImplementedCaptureAdapters,
    reason: CapturePathRejectionReason,
    candidates: [CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
) -> CapturePathSelectionError {
    let evidence_digest = digest_capture_path_decision(
        input,
        implemented_adapters,
        CapturePathDecisionDigestOutcome::Rejected(reason),
        &candidates,
    );
    let rejection = CapturePathRejection::try_from_status_parts(
        input.capture.path_request(),
        reason,
        candidates,
        evidence_digest,
    )
    .unwrap_or(CapturePathRejection {
        request: input.capture.path_request(),
        reason: CapturePathRejectionReason::InvalidDecision,
        candidates,
        evidence_digest,
    });
    CapturePathSelectionError { rejection }
}

#[cfg(test)]
pub(crate) type CapturePathSelectionErrorKind = CapturePathRejectionReason;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapturePathSelectionError {
    rejection: CapturePathRejection,
}

impl CapturePathSelectionError {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn kind(self) -> CapturePathSelectionErrorKind {
        self.rejection.reason()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn candidates(&self) -> &[CapturePathCandidateStatus; CAPTURE_PATH_COUNT] {
        self.rejection.candidates()
    }

    #[must_use]
    pub(crate) const fn rejection(self) -> CapturePathRejection {
        self.rejection
    }
}

impl fmt::Display for CapturePathSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.rejection.reason() {
            CapturePathRejectionReason::NoQualifiedPath => formatter
                .write_str("automatic Capture Path selection found no implemented qualified path"),
            CapturePathRejectionReason::QualificationEvidenceNotYetObserved => {
                formatter.write_str("Capture Path qualification evidence is not yet observable")
            }
            CapturePathRejectionReason::QualificationEvidenceExpired => {
                formatter.write_str("Capture Path qualification evidence expired")
            }
            CapturePathRejectionReason::QualificationEvidenceContextMismatch => formatter
                .write_str(
                    "Capture Path qualification evidence identifies a different runtime context",
                ),
            CapturePathRejectionReason::ExactPathUnavailable { path, state } => write!(
                formatter,
                "exact Capture Path {} is unavailable ({state:?}); no fallback is permitted",
                path.as_token(),
            ),
            CapturePathRejectionReason::InvalidDecision => {
                formatter.write_str("Capture Path classifier returned an incoherent decision")
            }
        }
    }
}

impl Error for CapturePathSelectionError {}

#[cfg(test)]
pub(crate) fn qualified_xtables_kernel_config() -> AndroidKernelConfigSnapshot {
    flux_platform::parse_android_kernel_config(
        b"CONFIG_NETFILTER=y\n\
CONFIG_IP_MULTIPLE_TABLES=y\n\
CONFIG_IPV6=y\n\
CONFIG_IPV6_MULTIPLE_TABLES=y\n\
CONFIG_NETFILTER_XTABLES=y\n\
CONFIG_IP_NF_IPTABLES=y\n\
CONFIG_IP6_NF_IPTABLES=y\n\
CONFIG_IP_NF_MANGLE=y\n\
CONFIG_IP6_NF_MANGLE=y\n\
CONFIG_NETFILTER_XT_MATCH_OWNER=y\n\
CONFIG_NETFILTER_XT_MATCH_MARK=y\n\
CONFIG_NETFILTER_XT_TARGET_MARK=y\n\
CONFIG_NETFILTER_XT_MATCH_COMMENT=y\n\
CONFIG_NETFILTER_XT_TARGET_TPROXY=y\n\
CONFIG_NF_TPROXY_IPV4=y\n\
CONFIG_NF_TPROXY_IPV6=y\n",
    )
    .expect("test xtables kernel configuration is canonical")
}

#[cfg(test)]
pub(crate) fn qualified_xtables_capture_path_evidence() -> CapturePathQualificationEvidence {
    CapturePathQualificationEvidence::host_inspection_with_maximum_lifetime(
        CapturePathQualifications::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Qualified,
            CapturePathQualificationState::Unqualified,
        ),
        Instant::now(),
    )
    .expect("test Capture Path qualification evidence has a bounded lifetime")
}

#[cfg(test)]
pub(crate) fn test_xtables_capture_path_selection() -> CapturePathSelection {
    CapturePathSelection::try_from_status_parts(
        CapturePathRequest::Auto,
        CapturePathId::XtablesTproxy,
        CapturePathSelectionReason::AutomaticHighestRankedQualified,
        [
            CapturePathCandidateStatus::from_status_parts(
                CapturePathId::NftablesTproxy,
                AndroidCapturePathState::Unimplemented,
                CapturePathQualificationState::Unqualified,
                None,
            ),
            CapturePathCandidateStatus::from_status_parts(
                CapturePathId::XtablesTproxy,
                AndroidCapturePathState::Qualified,
                CapturePathQualificationState::Qualified,
                None,
            ),
            CapturePathCandidateStatus::from_status_parts(
                CapturePathId::ManagedTun,
                AndroidCapturePathState::Unimplemented,
                CapturePathQualificationState::Unqualified,
                None,
            ),
        ],
        CapturePathSelectionEvidenceDigest::from_bytes([0x5a; 32]),
    )
    .expect("test xtables Capture Path selection is coherent")
}

#[cfg(test)]
pub(crate) fn test_xtables_capture_path_decision() -> CapturePathDecision {
    CapturePathDecision::Selected {
        selection: test_xtables_capture_path_selection(),
    }
}

#[cfg(test)]
pub(crate) fn test_unqualified_capture_path_decision() -> CapturePathDecision {
    CapturePathDecision::Rejected {
        rejection: CapturePathRejection::try_from_status_parts(
            CapturePathRequest::Auto,
            CapturePathRejectionReason::NoQualifiedPath,
            [
                CapturePathCandidateStatus::from_status_parts(
                    CapturePathId::NftablesTproxy,
                    AndroidCapturePathState::Unimplemented,
                    CapturePathQualificationState::Unqualified,
                    None,
                ),
                CapturePathCandidateStatus::from_status_parts(
                    CapturePathId::XtablesTproxy,
                    AndroidCapturePathState::Unqualified,
                    CapturePathQualificationState::Unqualified,
                    None,
                ),
                CapturePathCandidateStatus::from_status_parts(
                    CapturePathId::ManagedTun,
                    AndroidCapturePathState::Unimplemented,
                    CapturePathQualificationState::Unqualified,
                    None,
                ),
            ],
            CapturePathSelectionEvidenceDigest::from_bytes([0x6b; 32]),
        )
        .expect("test unqualified Capture Path rejection is coherent"),
    }
}

#[derive(Clone, Copy)]
enum CapturePathDecisionDigestOutcome {
    Selected {
        selected: CapturePathId,
        reason: CapturePathSelectionReason,
    },
    Rejected(CapturePathRejectionReason),
}

fn digest_capture_path_decision(
    input: CapturePathSelectionInput<'_>,
    implemented_adapters: ImplementedCaptureAdapters,
    outcome: CapturePathDecisionDigestOutcome,
    candidates: &[CapturePathCandidateStatus; CAPTURE_PATH_COUNT],
) -> CapturePathSelectionEvidenceDigest {
    let mut digest = Sha256::new();
    digest.update(CAPTURE_PATH_SELECTION_EVIDENCE_DIGEST_DOMAIN);
    digest.update([capture_request_tag(input.capture.path_request())]);
    if let CapturePathRequest::Exact(path) = input.capture.path_request() {
        digest.update([capture_path_tag(path)]);
    }
    let scope = input.capture.scope();
    digest.update([match scope.families() {
        AddressHostFamilySelection::Ipv4 => 0,
        AddressHostFamilySelection::Ipv6 => 1,
        AddressHostFamilySelection::DualStack => 2,
    }]);
    digest.update([
        u8::from(scope.includes_domain(CaptureTrafficDomain::LocalOutput)),
        u8::from(scope.includes_domain(CaptureTrafficDomain::ForwardedIngress)),
        u8::from(
            input
                .capture
                .protocols()
                .contains(CaptureTransportProtocol::Tcp),
        ),
        u8::from(
            input
                .capture
                .protocols()
                .contains(CaptureTransportProtocol::Udp),
        ),
    ]);
    for path in CapturePathId::ALL {
        digest.update([u8::from(implemented_adapters.contains(path))]);
    }
    update_field(&mut digest, input.kernel_config.digest().as_bytes());
    update_field(
        &mut digest,
        &input
            .candidate
            .device_profile()
            .revision()
            .get()
            .to_be_bytes(),
    );
    update_field(
        &mut digest,
        input.candidate.device_profile().digest().as_bytes(),
    );
    update_field(
        &mut digest,
        &input.candidate.inventory_snapshot().get().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &input.candidate.inventory_epoch().get().to_be_bytes(),
    );
    update_field(
        &mut digest,
        input.candidate.engine_profile().revision().as_bytes(),
    );
    update_field(
        &mut digest,
        input.candidate.engine_config().digest().as_bytes(),
    );
    update_field(&mut digest, input.planning_evidence_digest);
    match input.qualification_evidence.behavioral_digest() {
        Some(evidence_digest) => {
            digest.update([1]);
            update_field(&mut digest, &evidence_digest);
        }
        None => digest.update([0]),
    }
    match outcome {
        CapturePathDecisionDigestOutcome::Selected { selected, reason } => {
            digest.update([0, capture_path_tag(selected), selection_reason_tag(reason)]);
        }
        CapturePathDecisionDigestOutcome::Rejected(reason) => {
            digest.update([1, rejection_reason_tag(reason)]);
            if let CapturePathRejectionReason::ExactPathUnavailable { path, state } = reason {
                digest.update([capture_path_tag(path), capture_path_state_tag(state)]);
            }
        }
    }
    for candidate in candidates {
        digest.update([
            capture_path_tag(candidate.path),
            capture_path_state_tag(candidate.state),
            capture_path_qualification_state_tag(candidate.qualification_state),
        ]);
        match candidate.first_kernel_gap {
            Some(gap) => {
                digest.update([1, kernel_feature_state_tag(gap.state)]);
                update_field(&mut digest, gap.feature.config_symbol().as_bytes());
            }
            None => digest.update([0]),
        }
    }
    CapturePathSelectionEvidenceDigest(digest.finalize().into())
}

fn update_field(digest: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("canonical evidence field length fits u64");
    digest.update(length.to_be_bytes());
    digest.update(bytes);
}

const fn capture_request_tag(request: CapturePathRequest) -> u8 {
    match request {
        CapturePathRequest::Auto => 0,
        CapturePathRequest::Exact(_) => 1,
    }
}

const fn capture_path_tag(path: CapturePathId) -> u8 {
    match path {
        CapturePathId::NftablesTproxy => 0,
        CapturePathId::XtablesTproxy => 1,
        CapturePathId::ManagedTun => 2,
    }
}

const fn selection_reason_tag(reason: CapturePathSelectionReason) -> u8 {
    match reason {
        CapturePathSelectionReason::AutomaticHighestRankedQualified => 0,
        CapturePathSelectionReason::ExactRequestQualified => 1,
    }
}

const fn rejection_reason_tag(reason: CapturePathRejectionReason) -> u8 {
    match reason {
        CapturePathRejectionReason::NoQualifiedPath => 0,
        CapturePathRejectionReason::ExactPathUnavailable { .. } => 1,
        CapturePathRejectionReason::QualificationEvidenceNotYetObserved => 2,
        CapturePathRejectionReason::QualificationEvidenceExpired => 3,
        CapturePathRejectionReason::QualificationEvidenceContextMismatch => 4,
        CapturePathRejectionReason::InvalidDecision => 5,
    }
}

const fn capture_path_qualification_state_tag(state: CapturePathQualificationState) -> u8 {
    match state {
        CapturePathQualificationState::Qualified => 0,
        CapturePathQualificationState::Unsupported => 1,
        CapturePathQualificationState::Denied => 2,
        CapturePathQualificationState::Conflicting => 3,
        CapturePathQualificationState::Broken => 4,
        CapturePathQualificationState::Unqualified => 5,
    }
}

const fn capture_path_state_tag(state: AndroidCapturePathState) -> u8 {
    match state {
        AndroidCapturePathState::Qualified => 0,
        AndroidCapturePathState::Unimplemented => 1,
        AndroidCapturePathState::Missing => 2,
        AndroidCapturePathState::Denied => 3,
        AndroidCapturePathState::Conflicting => 4,
        AndroidCapturePathState::Broken => 5,
        AndroidCapturePathState::Unqualified => 6,
    }
}

const fn kernel_feature_state_tag(state: AndroidKernelFeatureState) -> u8 {
    match state {
        AndroidKernelFeatureState::BuiltIn => 0,
        AndroidKernelFeatureState::Module => 1,
        AndroidKernelFeatureState::Disabled => 2,
        AndroidKernelFeatureState::Configured => 3,
        AndroidKernelFeatureState::Unreported => 4,
    }
}

#[cfg(test)]
mod qualification_evidence_tests {
    use super::*;

    fn qualifications() -> CapturePathQualifications {
        CapturePathQualifications::new(
            CapturePathQualificationState::Unqualified,
            CapturePathQualificationState::Qualified,
            CapturePathQualificationState::Unqualified,
        )
    }

    #[test]
    fn zero_lifetime_is_rejected() {
        let observed_at = Instant::now();

        assert_eq!(
            CapturePathQualificationEvidence::host_inspection(
                qualifications(),
                observed_at,
                observed_at,
            ),
            Err(CapturePathQualificationEvidenceError::NonPositiveLifetime)
        );
    }

    #[test]
    fn lifetime_above_five_minutes_is_rejected() {
        let observed_at = Instant::now();
        let lifetime = CAPTURE_PATH_QUALIFICATION_EVIDENCE_MAX_AGE
            .checked_add(Duration::from_nanos(1))
            .expect("test lifetime remains representable");
        let valid_until = observed_at
            .checked_add(lifetime)
            .expect("test deadline remains representable");

        assert_eq!(
            CapturePathQualificationEvidence::host_inspection(
                qualifications(),
                observed_at,
                valid_until,
            ),
            Err(CapturePathQualificationEvidenceError::LifetimeExceedsMaximum { lifetime })
        );
    }

    #[test]
    fn evaluation_must_be_within_the_original_half_open_lease() {
        let observed_at = Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("test observation remains representable");
        let valid_until = observed_at
            .checked_add(Duration::from_secs(30))
            .expect("test deadline remains representable");
        let evidence = CapturePathQualificationEvidence::host_inspection(
            qualifications(),
            observed_at,
            valid_until,
        )
        .expect("test evidence lifetime is valid");

        assert_eq!(
            evidence.rejection_at(
                observed_at
                    .checked_sub(Duration::from_nanos(1))
                    .expect("test pre-observation instant remains representable")
            ),
            Some(CapturePathRejectionReason::QualificationEvidenceNotYetObserved)
        );
        assert_eq!(evidence.rejection_at(observed_at), None);
        assert_eq!(
            evidence.rejection_at(
                valid_until
                    .checked_sub(Duration::from_nanos(1))
                    .expect("test pre-deadline instant remains representable")
            ),
            None
        );
        assert_eq!(
            evidence.rejection_at(valid_until),
            Some(CapturePathRejectionReason::QualificationEvidenceExpired)
        );
    }
}
