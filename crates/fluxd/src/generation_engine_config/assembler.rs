use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use flux_core::{
    AddressHostFamilySelection, AndroidMarkPlanningAuthority, AndroidUserSelection,
    CapabilityProfile, CaptureApplicationMode, CaptureInterfaceSelectorKind, CapturePathId,
    CapturePathRequest, CaptureTrafficDomain, CaptureTransportProtocol, FluxConfig,
    FwmarkCandidate, GenerationId, NetworkAddressFamily, NetworkEpoch, NetworkInventory,
    NetworkInventorySnapshotId, NetworkNamespaceIdentity, RpdbPlacementLease,
    StaleRpdbPlacementLease,
};
use flux_platform::{
    AndroidFwmarkCensusPlanningEvidence, AndroidKernelConfigSnapshot, SingBoxPrivilege,
    SingBoxReadiness, XtablesCaptureArtifactSet, XtablesCaptureLoweringError,
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesLocalOutputRoutingSpec,
    XtablesTproxyTarget, lower_xtables_capture, plan_native_xtables_local_output_routing,
};
use sha2::{Digest, Sha256};

use super::capture_path_selection::{
    CapturePathQualificationEvidence, CapturePathQualificationEvidenceError, CapturePathSelection,
    CapturePathSelectionError, CapturePathSelectionInput, PRODUCTION_CAPTURE_PATH_SELECTOR,
};
use super::{
    DesiredStateArtifacts, EngineCapabilityProfile, EngineCapabilityProfileRevision,
    EngineConfigBindingError, EngineSupervisedDeliveryReportContract, SelectedEngineSourceIdentity,
    TproxyGenerationCandidate, TproxyGenerationCandidateError, bind_engine_config_to_spec,
    compile_tproxy_generation_candidate,
};
use crate::functional_canary::FunctionalCanaryGateMode;
use crate::{EngineSpec, RestartPolicy, RestartPolicyError};

pub(crate) const ADMITTED_GENERATION_SCHEMA_VERSION: u16 = 4;
const GENERATION_ASSEMBLY_DIGEST_BYTES: usize = 32;
const GENERATION_ASSEMBLY_DIGEST_DOMAIN: &[u8] =
    b"Flux coordinator-facing admitted Generation\0sha256-v2\0";
const GENERATION_PLANNING_DIGEST_DOMAIN: &[u8] =
    b"Flux complete Generation planning authority\0canonical-schema-v2\0sha256-v1\0";
const PRODUCT_DESIRED_STATE_DIGEST_DOMAIN: &[u8] =
    b"Flux product Desired State\0schema-v5\0sha256-v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct GenerationAssemblyDigest([u8; GENERATION_ASSEMBLY_DIGEST_BYTES]);

impl GenerationAssemblyDigest {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; GENERATION_ASSEMBLY_DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; GENERATION_ASSEMBLY_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for GenerationAssemblyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub(crate) struct GenerationPlanningDigest([u8; GENERATION_ASSEMBLY_DIGEST_BYTES]);

impl GenerationPlanningDigest {
    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; GENERATION_ASSEMBLY_DIGEST_BYTES] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct AdmittedGenerationIdentity {
    generation: GenerationId,
    digest: GenerationAssemblyDigest,
}

impl AdmittedGenerationIdentity {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn new(generation: GenerationId, digest: GenerationAssemblyDigest) -> Self {
        Self { generation, digest }
    }

    #[must_use]
    pub(crate) const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub(crate) const fn digest(self) -> GenerationAssemblyDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationAdmissionKind {
    #[cfg(test)]
    HostInspectionOnly,
    AndroidPlanningEvidence,
}

/// Explicitly non-authorizing host input for deterministic assembly and inspection.
///
/// This value can never construct a native target. It binds caller-selected mechanics to one
/// exact capability and inventory snapshot so stale host fixtures fail through the same seam.
#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostInspectionPlanningAuthority {
    capability_profile: CapabilityProfile,
    kernel_config: AndroidKernelConfigSnapshot,
    capture_path_evidence: CapturePathQualificationEvidence,
    inventory_snapshot: NetworkInventorySnapshotId,
    inventory_epoch: NetworkEpoch,
    network_namespace: NetworkNamespaceIdentity,
    mark: FwmarkCandidate,
    routing: Option<XtablesLocalOutputRoutingSpec>,
}

#[cfg(test)]
impl HostInspectionPlanningAuthority {
    #[must_use]
    pub(crate) fn new(
        capability_profile: &CapabilityProfile,
        kernel_config: AndroidKernelConfigSnapshot,
        capture_path_evidence: CapturePathQualificationEvidence,
        inventory: &NetworkInventory,
        network_namespace: NetworkNamespaceIdentity,
        mark: FwmarkCandidate,
        routing: Option<XtablesLocalOutputRoutingSpec>,
    ) -> Self {
        Self {
            capability_profile: capability_profile.clone(),
            kernel_config,
            capture_path_evidence,
            inventory_snapshot: inventory.snapshot_id(),
            inventory_epoch: inventory.epoch(),
            network_namespace,
            mark,
            routing,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum GenerationPlanningAuthority {
    #[cfg(test)]
    HostInspection(Box<HostInspectionPlanningAuthority>),
    Android {
        mark: Box<AndroidMarkPlanningAuthority>,
        kernel_config: Arc<AndroidKernelConfigSnapshot>,
        capture_path_evidence: Box<CapturePathQualificationEvidence>,
        placement: Option<RpdbPlacementLease>,
    },
}

impl GenerationPlanningAuthority {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn host_inspection(authority: HostInspectionPlanningAuthority) -> Self {
        Self::HostInspection(Box::new(authority))
    }

    pub(crate) fn android(
        census: AndroidFwmarkCensusPlanningEvidence,
        observed_at: Instant,
        placement: Option<RpdbPlacementLease>,
    ) -> Result<Self, CapturePathQualificationEvidenceError> {
        let (mark, kernel_config, behavioral_evidence) = census.into_parts();
        let capture_path_evidence = CapturePathQualificationEvidence::with_maximum_lifetime(
            behavioral_evidence,
            observed_at,
        )?;
        Ok(Self::Android {
            mark: Box::new(mark),
            kernel_config,
            capture_path_evidence: Box::new(capture_path_evidence),
            placement,
        })
    }

    #[cfg(test)]
    const fn kind(&self) -> GenerationAdmissionKind {
        match self {
            Self::HostInspection(_) => GenerationAdmissionKind::HostInspectionOnly,
            Self::Android { .. } => GenerationAdmissionKind::AndroidPlanningEvidence,
        }
    }

    #[must_use]
    pub(crate) const fn capability_profile(&self) -> &CapabilityProfile {
        match self {
            #[cfg(test)]
            Self::HostInspection(authority) => &authority.capability_profile,
            Self::Android { mark, .. } => mark.capability_profile(),
        }
    }

    #[must_use]
    pub(crate) fn kernel_config(&self) -> &AndroidKernelConfigSnapshot {
        match self {
            #[cfg(test)]
            Self::HostInspection(authority) => &authority.kernel_config,
            Self::Android { kernel_config, .. } => kernel_config,
        }
    }

    #[must_use]
    pub(crate) const fn capture_path_evidence(&self) -> &CapturePathQualificationEvidence {
        match self {
            #[cfg(test)]
            Self::HostInspection(authority) => &authority.capture_path_evidence,
            Self::Android {
                capture_path_evidence,
                ..
            } => capture_path_evidence,
        }
    }

    #[must_use]
    pub(crate) const fn android_runtime_binding(
        &self,
    ) -> Option<(&AndroidMarkPlanningAuthority, RpdbPlacementLease)> {
        match self {
            Self::Android {
                mark,
                placement: Some(placement),
                ..
            } => Some((mark, *placement)),
            #[cfg(test)]
            Self::HostInspection(_) => None,
            Self::Android {
                placement: None, ..
            } => None,
        }
    }
}

pub(crate) struct GenerationAssemblyRequest<'a> {
    desired_state: DesiredStateArtifacts,
    engine_spec: EngineSpec,
    capability_profile: CapabilityProfile,
    inventory: &'a NetworkInventory,
    engine_profile: EngineCapabilityProfile,
    planning: GenerationPlanningAuthority,
    prior_owned: Option<AdmittedGenerationIdentity>,
}

impl<'a> GenerationAssemblyRequest<'a> {
    #[must_use]
    pub(crate) const fn new(
        desired_state: DesiredStateArtifacts,
        engine_spec: EngineSpec,
        capability_profile: CapabilityProfile,
        inventory: &'a NetworkInventory,
        engine_profile: EngineCapabilityProfile,
        planning: GenerationPlanningAuthority,
    ) -> Self {
        Self {
            desired_state,
            engine_spec,
            capability_profile,
            inventory,
            engine_profile,
            planning,
            prior_owned: None,
        }
    }

    #[must_use]
    pub(crate) const fn with_prior_owned(
        mut self,
        prior_owned: AdmittedGenerationIdentity,
    ) -> Self {
        self.prior_owned = Some(prior_owned);
        self
    }
}

/// Complete coordinator-facing, non-mutating Generation.
///
/// The private planning field retains the evidence consumed during assembly. This type exposes no
/// native-target conversion, writer token, activation lease, or mutation method.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct AdmittedGeneration {
    identity: AdmittedGenerationIdentity,
    prior_owned: Option<AdmittedGenerationIdentity>,
    desired_state: FluxConfig,
    candidate: TproxyGenerationCandidate,
    engine_spec: EngineSpec,
    capture: flux_core::CaptureProgramCompilation,
    engine_source: SelectedEngineSourceIdentity,
    xtables: XtablesCaptureArtifactSet,
    planning_digest: GenerationPlanningDigest,
    capture_path_selection: CapturePathSelection,
    capture_path_evidence_deadline: Instant,
    functional_canary_mode: FunctionalCanaryGateMode,
    planning: GenerationPlanningAuthority,
}

impl AdmittedGeneration {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        ADMITTED_GENERATION_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> AdmittedGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> GenerationId {
        self.identity.generation
    }

    #[must_use]
    pub(crate) const fn engine_profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.candidate.engine_profile().revision()
    }

    #[must_use]
    pub(crate) const fn supervised_delivery_report(
        &self,
    ) -> Option<EngineSupervisedDeliveryReportContract> {
        self.candidate.engine_profile().supervised_delivery_report()
    }

    #[must_use]
    pub(crate) const fn functional_canary_mode(&self) -> FunctionalCanaryGateMode {
        self.functional_canary_mode
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn admission_kind(&self) -> GenerationAdmissionKind {
        self.planning.kind()
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn prior_owned(&self) -> Option<AdmittedGenerationIdentity> {
        self.prior_owned
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn desired_state(&self) -> &FluxConfig {
        &self.desired_state
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn candidate(&self) -> &TproxyGenerationCandidate {
        &self.candidate
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn engine_spec(&self) -> &EngineSpec {
        &self.engine_spec
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn capture(&self) -> &flux_core::CaptureProgramCompilation {
        &self.capture
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn engine_source(&self) -> SelectedEngineSourceIdentity {
        self.engine_source
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn xtables(&self) -> &XtablesCaptureArtifactSet {
        &self.xtables
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn planning_digest(&self) -> GenerationPlanningDigest {
        self.planning_digest
    }

    #[must_use]
    pub(crate) const fn capture_path_selection(&self) -> CapturePathSelection {
        self.capture_path_selection
    }

    #[must_use]
    pub(crate) const fn capture_path_evidence_deadline(&self) -> Instant {
        self.capture_path_evidence_deadline
    }

    pub(crate) fn into_native_target_request(
        self,
    ) -> Result<NativeGenerationTargetRequest, NativeGenerationPromotionError> {
        match self.planning {
            #[cfg(test)]
            GenerationPlanningAuthority::HostInspection(_) => {
                Err(NativeGenerationPromotionError::HostInspectionNonPromotable)
            }
            GenerationPlanningAuthority::Android {
                mark, placement, ..
            } => {
                let placement =
                    placement.ok_or(NativeGenerationPromotionError::MissingAndroidPlacement)?;
                Ok(NativeGenerationTargetRequest {
                    mark: *mark,
                    placement,
                    xtables: self.xtables,
                })
            }
        }
    }

    #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
    pub(crate) fn into_linux_composition_test_request(
        self,
    ) -> Result<LinuxCompositionTestTargetRequest, LinuxCompositionTestPromotionError> {
        match self.planning {
            GenerationPlanningAuthority::HostInspection(authority) => {
                Ok(LinuxCompositionTestTargetRequest {
                    network_namespace: authority.network_namespace,
                    xtables: self.xtables,
                })
            }
            GenerationPlanningAuthority::Android { .. } => {
                Err(LinuxCompositionTestPromotionError::AndroidAuthorityForbidden)
            }
        }
    }
}

pub(crate) struct NativeGenerationTargetRequest {
    pub(crate) mark: AndroidMarkPlanningAuthority,
    pub(crate) placement: RpdbPlacementLease,
    pub(crate) xtables: XtablesCaptureArtifactSet,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) struct LinuxCompositionTestTargetRequest {
    pub(crate) network_namespace: NetworkNamespaceIdentity,
    pub(crate) xtables: XtablesCaptureArtifactSet,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxCompositionTestPromotionError {
    AndroidAuthorityForbidden,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl fmt::Display for LinuxCompositionTestPromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "Android planning evidence cannot enter the Linux native-composition test seam",
        )
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl Error for LinuxCompositionTestPromotionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeGenerationPromotionError {
    #[cfg(test)]
    HostInspectionNonPromotable,
    MissingAndroidPlacement,
}

impl fmt::Display for NativeGenerationPromotionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::HostInspectionNonPromotable => formatter.write_str(
                "host inspection evidence cannot be promoted to native mutation authority",
            ),
            Self::MissingAndroidPlacement => formatter.write_str(
                "Android planning evidence has no RPDB placement for native target admission",
            ),
        }
    }
}

impl Error for NativeGenerationPromotionError {}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationPlanningErrorKind {
    CapabilityProfileMismatch,
    InventorySnapshotMismatch,
    InventoryEpochMismatch,
    StalePlacement,
    MissingLocalOutputRouting,
    UnexpectedLocalOutputRouting,
    RoutingFamilyMismatch { family: NetworkAddressFamily },
}

#[derive(Debug)]
pub(crate) enum GenerationPlanningError {
    CapabilityProfileMismatch,
    InventorySnapshotMismatch,
    InventoryEpochMismatch,
    StalePlacement(StaleRpdbPlacementLease),
    MissingLocalOutputRouting,
    UnexpectedLocalOutputRouting,
    RoutingFamilyMismatch { family: NetworkAddressFamily },
}

impl GenerationPlanningError {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn kind(&self) -> GenerationPlanningErrorKind {
        match self {
            Self::CapabilityProfileMismatch => {
                GenerationPlanningErrorKind::CapabilityProfileMismatch
            }
            Self::InventorySnapshotMismatch => {
                GenerationPlanningErrorKind::InventorySnapshotMismatch
            }
            Self::InventoryEpochMismatch => GenerationPlanningErrorKind::InventoryEpochMismatch,
            Self::StalePlacement(_) => GenerationPlanningErrorKind::StalePlacement,
            Self::MissingLocalOutputRouting => {
                GenerationPlanningErrorKind::MissingLocalOutputRouting
            }
            Self::UnexpectedLocalOutputRouting => {
                GenerationPlanningErrorKind::UnexpectedLocalOutputRouting
            }
            Self::RoutingFamilyMismatch { family } => {
                GenerationPlanningErrorKind::RoutingFamilyMismatch { family: *family }
            }
        }
    }
}

impl fmt::Display for GenerationPlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityProfileMismatch => {
                formatter.write_str("planning evidence identifies a different Capability Profile")
            }
            Self::InventorySnapshotMismatch => formatter
                .write_str("planning evidence identifies a different Network Inventory snapshot"),
            Self::InventoryEpochMismatch => formatter
                .write_str("planning evidence identifies a different Network Inventory epoch"),
            Self::StalePlacement(source) => source.fmt(formatter),
            Self::MissingLocalOutputRouting => {
                formatter.write_str("local-OUTPUT capture requires snapshot-bound routing evidence")
            }
            Self::UnexpectedLocalOutputRouting => formatter
                .write_str("routing evidence was supplied for capture without local OUTPUT"),
            Self::RoutingFamilyMismatch { family } => write!(
                formatter,
                "routing evidence does not exactly match the enabled {family:?} capture family"
            ),
        }
    }
}

impl Error for GenerationPlanningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::StalePlacement(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) enum GenerationAssemblyError {
    DesiredStateEngine(DesiredStateEngineBindingError),
    EngineConfig(EngineConfigBindingError),
    Candidate(TproxyGenerationCandidateError),
    Planning(GenerationPlanningError),
    CapturePath(CapturePathSelectionError),
    RequiredFunctionalCanaryReportUnavailable,
    CapturePathAdapterMismatch { selected: CapturePathId },
    GenerationSequenceExhausted,
    Xtables(XtablesCaptureLoweringError),
}

impl fmt::Display for GenerationAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DesiredStateEngine(source) => source.fmt(formatter),
            Self::EngineConfig(source) => source.fmt(formatter),
            Self::Candidate(source) => source.fmt(formatter),
            Self::Planning(source) => source.fmt(formatter),
            Self::CapturePath(source) => source.fmt(formatter),
            Self::RequiredFunctionalCanaryReportUnavailable => formatter.write_str(
                "require_functional_canary needs an exact engine profile with the canonical supervised-delivery report contract",
            ),
            Self::CapturePathAdapterMismatch { selected } => write!(
                formatter,
                "Capture Path selector chose {} without a matching Generation assembler",
                selected.as_token(),
            ),
            Self::GenerationSequenceExhausted => {
                formatter.write_str("Generation sequence is exhausted")
            }
            Self::Xtables(source) => source.fmt(formatter),
        }
    }
}

impl Error for GenerationAssemblyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DesiredStateEngine(source) => Some(source),
            Self::EngineConfig(source) => Some(source),
            Self::Candidate(source) => Some(source),
            Self::Planning(source) => Some(source),
            Self::CapturePath(source) => Some(source),
            Self::Xtables(source) => Some(source),
            Self::RequiredFunctionalCanaryReportUnavailable
            | Self::GenerationSequenceExhausted
            | Self::CapturePathAdapterMismatch { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GenerationAssembler;

impl GenerationAssembler {
    pub(crate) fn assemble(
        &self,
        request: GenerationAssemblyRequest<'_>,
    ) -> Result<AdmittedGeneration, GenerationAssemblyError> {
        let GenerationAssemblyRequest {
            desired_state,
            engine_spec,
            capability_profile,
            inventory,
            engine_profile,
            planning,
            prior_owned,
        } = request;
        let (desired_state, engine_source, capture) = desired_state.into_parts();
        let engine_source_identity = engine_source.identity();
        let engine_spec = bind_engine_spec_to_desired_state(&desired_state, engine_spec)
            .map_err(GenerationAssemblyError::DesiredStateEngine)?;
        let binding = bind_engine_config_to_spec(engine_source.into_artifact(), &engine_spec)
            .map_err(GenerationAssemblyError::EngineConfig)?;
        let candidate = compile_tproxy_generation_candidate(
            capability_profile,
            inventory,
            engine_profile,
            binding,
        )
        .map_err(GenerationAssemblyError::Candidate)?;
        let functional_canary_mode = if desired_state.safety().require_functional_canary() {
            if candidate
                .engine_profile()
                .supervised_delivery_report()
                .is_none()
            {
                return Err(GenerationAssemblyError::RequiredFunctionalCanaryReportUnavailable);
            }
            FunctionalCanaryGateMode::RequiredUnqualified
        } else {
            FunctionalCanaryGateMode::StructuralVerificationOnly
        };
        let planning_context = validate_planning(&planning, &candidate, inventory, &desired_state)
            .map_err(GenerationAssemblyError::Planning)?;
        let capture_path_evidence = planning.capture_path_evidence();
        let capture_path_selection = PRODUCTION_CAPTURE_PATH_SELECTOR
            .select(CapturePathSelectionInput::new(
                *desired_state.capture(),
                &candidate,
                planning.kernel_config(),
                capture_path_evidence,
                planning_context.digest.as_bytes(),
            ))
            .map_err(GenerationAssemblyError::CapturePath)?;
        if capture_path_selection.selected() != CapturePathId::XtablesTproxy {
            return Err(GenerationAssemblyError::CapturePathAdapterMismatch {
                selected: capture_path_selection.selected(),
            });
        }
        let generation = next_generation(prior_owned)?;
        let mut lowering = XtablesCaptureLoweringRequest::new(
            capture.program(),
            XtablesCaptureNamespace::new(generation),
            XtablesTproxyTarget::new(desired_state.listener().port(), planning_context.mark),
        );
        if let Some(routing) = planning_context.routing {
            lowering = lowering.with_local_output_routing(routing);
        }
        let xtables = lower_xtables_capture(lowering).map_err(GenerationAssemblyError::Xtables)?;
        let digest = digest_generation(GenerationDigestInput {
            generation,
            prior_owned,
            desired_state: &desired_state,
            candidate: &candidate,
            engine_spec: &engine_spec,
            engine_source_identity,
            xtables: &xtables,
            planning_context,
            capture_path_selection,
        });

        Ok(AdmittedGeneration {
            identity: AdmittedGenerationIdentity { generation, digest },
            prior_owned,
            desired_state,
            candidate,
            engine_spec,
            capture,
            engine_source: engine_source_identity,
            xtables,
            planning_digest: planning_context.digest,
            capture_path_selection,
            capture_path_evidence_deadline: capture_path_evidence.valid_until(),
            functional_canary_mode,
            planning,
        })
    }
}

#[derive(Clone, Copy)]
struct PlanningContext {
    kind: GenerationAdmissionKind,
    network_namespace: NetworkNamespaceIdentity,
    mark: FwmarkCandidate,
    routing: Option<XtablesLocalOutputRoutingSpec>,
    digest: GenerationPlanningDigest,
}

fn validate_planning(
    planning: &GenerationPlanningAuthority,
    candidate: &TproxyGenerationCandidate,
    inventory: &NetworkInventory,
    desired_state: &FluxConfig,
) -> Result<PlanningContext, GenerationPlanningError> {
    let local_output = desired_state
        .capture()
        .scope()
        .includes_domain(CaptureTrafficDomain::LocalOutput);
    let digest = digest_generation_planning_authority(planning);
    match planning {
        #[cfg(test)]
        GenerationPlanningAuthority::HostInspection(authority) => {
            ensure_common_planning_binding(
                &authority.capability_profile,
                authority.inventory_snapshot,
                authority.inventory_epoch,
                candidate,
            )?;
            validate_routing_shape(
                local_output,
                desired_state.capture().scope().families(),
                authority.routing,
            )?;
            Ok(PlanningContext {
                kind: GenerationAdmissionKind::HostInspectionOnly,
                network_namespace: authority.network_namespace,
                mark: authority.mark,
                routing: authority.routing,
                digest,
            })
        }
        GenerationPlanningAuthority::Android {
            mark, placement, ..
        } => {
            ensure_common_planning_binding(
                mark.capability_profile(),
                mark.topology_scope().snapshot_id(),
                mark.topology_scope().epoch(),
                candidate,
            )?;
            let routing = if local_output {
                let placement =
                    placement.ok_or(GenerationPlanningError::MissingLocalOutputRouting)?;
                placement
                    .ensure_current(inventory, mark.topology_scope().classifier_revision())
                    .map_err(GenerationPlanningError::StalePlacement)?;
                Some(routing_from_placement(
                    placement,
                    desired_state.capture().scope().families(),
                )?)
            } else {
                if placement.is_some() {
                    return Err(GenerationPlanningError::UnexpectedLocalOutputRouting);
                }
                None
            };
            Ok(PlanningContext {
                kind: GenerationAdmissionKind::AndroidPlanningEvidence,
                network_namespace: mark.network_namespace(),
                mark: mark.candidate(),
                routing,
                digest,
            })
        }
    }
}

fn digest_generation_planning_authority(
    planning: &GenerationPlanningAuthority,
) -> GenerationPlanningDigest {
    let mut digest = Sha256::new();
    digest.update(GENERATION_PLANNING_DIGEST_DOMAIN);
    match planning {
        #[cfg(test)]
        GenerationPlanningAuthority::HostInspection(authority) => {
            digest.update([0]);
            update_field(
                &mut digest,
                authority.capability_profile.digest().as_bytes(),
            );
            update_field(&mut digest, authority.kernel_config.digest().as_bytes());
            update_field(
                &mut digest,
                &authority.inventory_snapshot.get().to_be_bytes(),
            );
            update_field(&mut digest, &authority.inventory_epoch.get().to_be_bytes());
            update_field(
                &mut digest,
                &authority.network_namespace.device().to_be_bytes(),
            );
            update_field(
                &mut digest,
                &authority.network_namespace.inode().to_be_bytes(),
            );
            update_mark(&mut digest, authority.mark);
            update_routing(&mut digest, authority.routing);
        }
        GenerationPlanningAuthority::Android {
            mark,
            kernel_config,
            capture_path_evidence,
            placement,
        } => {
            digest.update([1]);
            update_field(&mut digest, mark.evidence_digest().as_bytes());
            update_field(&mut digest, kernel_config.digest().as_bytes());
            let behavioral_digest = capture_path_evidence
                .behavioral_digest()
                .expect("Android planning retains reviewed Capture Path evidence identity");
            update_field(&mut digest, &behavioral_digest);
            update_placement(&mut digest, *placement);
        }
    }
    GenerationPlanningDigest(digest.finalize().into())
}

fn update_placement(digest: &mut Sha256, placement: Option<RpdbPlacementLease>) {
    let Some(placement) = placement else {
        digest.update([0]);
        return;
    };
    digest.update([1]);
    update_field(digest, &placement.snapshot_id().get().to_be_bytes());
    update_field(digest, &placement.epoch().get().to_be_bytes());
    update_field(digest, &placement.classifier_revision().get().to_be_bytes());
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        match placement.family(family) {
            Some(family_placement) => {
                digest.update([1]);
                match family_placement.address_bypass_priority() {
                    Some(priority) => {
                        digest.update([1]);
                        update_field(digest, &priority.get().to_be_bytes());
                    }
                    None => digest.update([0]),
                }
                update_field(
                    digest,
                    &family_placement.proxy_priority().get().to_be_bytes(),
                );
                update_field(
                    digest,
                    &family_placement.private_table().get().to_be_bytes(),
                );
            }
            None => digest.update([0]),
        }
        match placement.window(family) {
            Some(window) => {
                digest.update([1]);
                update_field(digest, &window.last_must_precede().get().to_be_bytes());
                update_field(digest, &window.first_terminal_barrier().get().to_be_bytes());
            }
            None => digest.update([0]),
        }
    }
}

fn ensure_common_planning_binding(
    capability_profile: &CapabilityProfile,
    inventory_snapshot: NetworkInventorySnapshotId,
    inventory_epoch: NetworkEpoch,
    candidate: &TproxyGenerationCandidate,
) -> Result<(), GenerationPlanningError> {
    if capability_profile != candidate.device_profile() {
        return Err(GenerationPlanningError::CapabilityProfileMismatch);
    }
    if inventory_snapshot != candidate.inventory_snapshot() {
        return Err(GenerationPlanningError::InventorySnapshotMismatch);
    }
    if inventory_epoch != candidate.inventory_epoch() {
        return Err(GenerationPlanningError::InventoryEpochMismatch);
    }
    Ok(())
}

#[cfg(test)]
fn validate_routing_shape(
    local_output: bool,
    families: AddressHostFamilySelection,
    routing: Option<XtablesLocalOutputRoutingSpec>,
) -> Result<(), GenerationPlanningError> {
    if !local_output {
        return if routing.is_some() {
            Err(GenerationPlanningError::UnexpectedLocalOutputRouting)
        } else {
            Ok(())
        };
    }
    let routing = routing.ok_or(GenerationPlanningError::MissingLocalOutputRouting)?;
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        if routing.routing_for(family).is_some() != families.includes(family) {
            return Err(GenerationPlanningError::RoutingFamilyMismatch { family });
        }
    }
    Ok(())
}

fn routing_from_placement(
    placement: RpdbPlacementLease,
    families: AddressHostFamilySelection,
) -> Result<XtablesLocalOutputRoutingSpec, GenerationPlanningError> {
    plan_native_xtables_local_output_routing(placement, families).map_err(|source| match source {
        flux_platform::NativeXtablesRoutingPlanError::FamilyMismatch { family } => {
            GenerationPlanningError::RoutingFamilyMismatch { family }
        }
        flux_platform::NativeXtablesRoutingPlanError::NoEnabledFamilies => {
            GenerationPlanningError::MissingLocalOutputRouting
        }
    })
}

fn next_generation(
    prior_owned: Option<AdmittedGenerationIdentity>,
) -> Result<GenerationId, GenerationAssemblyError> {
    match prior_owned {
        Some(prior) => prior.generation.checked_next(),
        None => Some(GenerationId::INITIAL),
    }
    .ok_or(GenerationAssemblyError::GenerationSequenceExhausted)
}

#[derive(Debug)]
pub(crate) enum DesiredStateEngineBindingError {
    Binary,
    StartupTimeout,
    StopTimeout,
    Privilege,
    RestartPolicy(RestartPolicyError),
}

impl fmt::Display for DesiredStateEngineBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Binary => "prepared Proxy Engine binary does not match the current Desired State",
            Self::StartupTimeout => {
                "prepared Proxy Engine startup timeout does not match the current Desired State"
            }
            Self::StopTimeout => {
                "prepared Proxy Engine stop timeout does not match the current Desired State"
            }
            Self::Privilege => {
                "prepared Proxy Engine privilege identity does not match the current Desired State"
            }
            Self::RestartPolicy(_) => {
                "current Desired State cannot construct a Proxy Engine restart policy"
            }
        })
    }
}

impl Error for DesiredStateEngineBindingError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RestartPolicy(source) => Some(source),
            Self::Binary | Self::StartupTimeout | Self::StopTimeout | Self::Privilege => None,
        }
    }
}

pub(crate) fn bind_engine_spec_to_desired_state(
    desired_state: &FluxConfig,
    spec: EngineSpec,
) -> Result<EngineSpec, DesiredStateEngineBindingError> {
    let configured = desired_state.engine();
    let process = spec.process();
    if process.binary != configured.binary() {
        return Err(DesiredStateEngineBindingError::Binary);
    }
    if process.startup_timeout != configured.startup_timeout() {
        return Err(DesiredStateEngineBindingError::StartupTimeout);
    }
    if process.stop_timeout != configured.stop_timeout() {
        return Err(DesiredStateEngineBindingError::StopTimeout);
    }
    let credentials = configured.credentials();
    if process.privilege != SingBoxPrivilege::TransparentProxy(credentials) {
        return Err(DesiredStateEngineBindingError::Privilege);
    }

    let configured_restart = configured.restart();
    let restart = RestartPolicy::new(
        configured_restart.max_attempts(),
        configured_restart.window(),
        configured_restart.initial_backoff(),
        configured_restart.maximum_backoff(),
        configured_restart.stable_reset(),
    )
    .map_err(DesiredStateEngineBindingError::RestartPolicy)?;
    Ok(spec.with_restart_policy(restart))
}

struct GenerationDigestInput<'a> {
    generation: GenerationId,
    prior_owned: Option<AdmittedGenerationIdentity>,
    desired_state: &'a FluxConfig,
    candidate: &'a TproxyGenerationCandidate,
    engine_spec: &'a EngineSpec,
    engine_source_identity: SelectedEngineSourceIdentity,
    xtables: &'a XtablesCaptureArtifactSet,
    planning_context: PlanningContext,
    capture_path_selection: CapturePathSelection,
}

fn digest_generation(input: GenerationDigestInput<'_>) -> GenerationAssemblyDigest {
    let GenerationDigestInput {
        generation,
        prior_owned,
        desired_state,
        candidate,
        engine_spec,
        engine_source_identity,
        xtables,
        planning_context,
        capture_path_selection,
    } = input;
    let mut digest = Sha256::new();
    digest.update(GENERATION_ASSEMBLY_DIGEST_DOMAIN);
    update_field(
        &mut digest,
        &ADMITTED_GENERATION_SCHEMA_VERSION.to_be_bytes(),
    );
    update_field(&mut digest, &generation.get().to_be_bytes());
    match prior_owned {
        Some(prior) => {
            digest.update([1]);
            update_field(&mut digest, &prior.generation().get().to_be_bytes());
            update_field(&mut digest, prior.digest().as_bytes());
        }
        None => digest.update([0]),
    }
    update_field(&mut digest, &digest_product_desired_state(desired_state));
    update_field(&mut digest, candidate.engine_config().digest().as_bytes());
    match engine_source_identity {
        SelectedEngineSourceIdentity::Template { template_digest } => {
            digest.update([0]);
            update_field(&mut digest, &template_digest);
        }
        SelectedEngineSourceIdentity::Subscription {
            snapshot_digest,
            subscription_source,
        } => {
            digest.update([1]);
            update_field(&mut digest, &snapshot_digest);
            update_field(&mut digest, &subscription_source);
        }
    }
    update_field(
        &mut digest,
        candidate.engine_profile().revision().as_bytes(),
    );
    update_field(
        &mut digest,
        &candidate.device_profile().revision().get().to_be_bytes(),
    );
    update_field(&mut digest, candidate.device_profile().digest().as_bytes());
    update_field(
        &mut digest,
        &candidate.inventory_snapshot().get().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &candidate.inventory_epoch().get().to_be_bytes(),
    );
    update_field(&mut digest, xtables.digest().as_bytes());
    update_engine_spec(&mut digest, engine_spec);
    update_field(&mut digest, planning_context.digest.as_bytes());
    update_field(
        &mut digest,
        capture_path_selection.evidence_digest().as_bytes(),
    );
    digest.update([match planning_context.kind {
        #[cfg(test)]
        GenerationAdmissionKind::HostInspectionOnly => 0,
        GenerationAdmissionKind::AndroidPlanningEvidence => 1,
    }]);
    update_field(
        &mut digest,
        &planning_context.network_namespace.device().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &planning_context.network_namespace.inode().to_be_bytes(),
    );
    update_mark(&mut digest, planning_context.mark);
    update_routing(&mut digest, planning_context.routing);
    GenerationAssemblyDigest(digest.finalize().into())
}

fn digest_product_desired_state(config: &FluxConfig) -> [u8; GENERATION_ASSEMBLY_DIGEST_BYTES] {
    let mut digest = Sha256::new();
    digest.update(PRODUCT_DESIRED_STATE_DIGEST_DOMAIN);
    update_field(&mut digest, &config.schema().to_be_bytes());

    let daemon = *config.daemon();
    digest.update([0]);
    update_field(
        &mut digest,
        &duration_millis(daemon.reconcile_debounce().get()).to_be_bytes(),
    );
    update_field(
        &mut digest,
        &daemon.event_queue_capacity().get().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &daemon.generation_history().get().to_be_bytes(),
    );

    let engine = config.engine();
    update_path(&mut digest, engine.binary());
    update_path(&mut digest, engine.template());
    update_field(&mut digest, &engine.credentials().uid().get().to_be_bytes());
    update_field(&mut digest, &engine.credentials().gid().get().to_be_bytes());
    update_field(
        &mut digest,
        &duration_millis(engine.startup_timeout()).to_be_bytes(),
    );
    update_field(
        &mut digest,
        &duration_millis(engine.stop_timeout()).to_be_bytes(),
    );
    let restart = engine.restart();
    update_field(&mut digest, &restart.max_attempts().to_be_bytes());
    for duration in [
        restart.window(),
        restart.initial_backoff(),
        restart.maximum_backoff(),
        restart.stable_reset(),
    ] {
        update_field(&mut digest, &duration_millis(duration).to_be_bytes());
    }

    let capture = *config.capture();
    match capture.path_request() {
        CapturePathRequest::Auto => digest.update([0]),
        CapturePathRequest::Exact(path) => digest.update([1, capture_path_tag(path)]),
    }
    let scope = capture.scope();
    digest.update([family_tag(scope.families())]);
    digest.update([
        u8::from(scope.includes_domain(CaptureTrafficDomain::LocalOutput)),
        u8::from(scope.includes_domain(CaptureTrafficDomain::ForwardedIngress)),
        u8::from(capture.protocols().contains(CaptureTransportProtocol::Tcp)),
        u8::from(capture.protocols().contains(CaptureTransportProtocol::Udp)),
    ]);
    update_field(&mut digest, &config.listener().port().get().to_be_bytes());

    let applications = config.applications();
    digest.update([application_mode_tag(applications.mode())]);
    match applications.android_users() {
        AndroidUserSelection::Owner => digest.update([0]),
        AndroidUserSelection::All => digest.update([1]),
        AndroidUserSelection::List(user_ids) => {
            digest.update([2]);
            update_count(&mut digest, user_ids.len());
            for user_id in user_ids {
                update_field(&mut digest, &user_id.to_be_bytes());
            }
        }
    }
    update_count(&mut digest, applications.packages().len());
    for package in applications.packages() {
        update_field(&mut digest, package.as_str().as_bytes());
    }

    let interfaces = config.interfaces().policy();
    for selectors in [
        interfaces.excluded(),
        interfaces.forwarded_proxy(),
        interfaces.local_bypass(),
    ] {
        update_count(&mut digest, selectors.len());
        for selector in selectors {
            digest.update([match selector.kind() {
                CaptureInterfaceSelectorKind::Exact => 0,
                CaptureInterfaceSelectorKind::Prefix => 1,
            }]);
            update_field(&mut digest, selector.name().as_bytes());
        }
    }

    let prefixes = config.bypass().policy().prefixes();
    update_count(&mut digest, prefixes.len());
    for prefix in prefixes {
        update_ip(&mut digest, prefix.network());
        digest.update([prefix.prefix_length()]);
    }

    let subscription = config.subscription();
    digest.update([u8::from(subscription.enabled())]);
    update_path(&mut digest, subscription.url_file());
    update_field(
        &mut digest,
        &subscription.update_interval().as_secs().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &subscription.download_timeout().as_secs().to_be_bytes(),
    );
    update_field(
        &mut digest,
        &subscription.max_download_bytes().to_be_bytes(),
    );
    update_field(&mut digest, &subscription.max_decoded_bytes().to_be_bytes());
    update_field(&mut digest, &subscription.max_nodes().to_be_bytes());

    let safety = config.safety();
    digest.update([
        u8::from(safety.respect_android_vpn()),
        u8::from(safety.require_functional_canary()),
    ]);
    digest.finalize().into()
}

fn update_engine_spec(digest: &mut Sha256, spec: &EngineSpec) {
    let process = spec.process();
    update_path(digest, &process.binary);
    update_path(digest, &process.config);
    update_path(digest, &process.working_directory);
    update_path(digest, &process.log);
    match process.privilege {
        SingBoxPrivilege::Inherit => digest.update([0]),
        SingBoxPrivilege::TransparentProxy(credentials) => {
            digest.update([1]);
            update_field(digest, &credentials.uid().get().to_be_bytes());
            update_field(digest, &credentials.gid().get().to_be_bytes());
        }
    }
    match &process.readiness {
        SingBoxReadiness::Listener { port } => {
            digest.update([0]);
            update_field(digest, &port.get().to_be_bytes());
        }
        SingBoxReadiness::TunInterface { name } => {
            digest.update([1]);
            update_field(digest, name.as_bytes());
        }
    }
    update_field(
        digest,
        &duration_millis(process.startup_timeout).to_be_bytes(),
    );
    update_field(digest, &duration_millis(process.stop_timeout).to_be_bytes());
    let restart = spec.restart_policy();
    update_field(digest, &restart.max_attempts().to_be_bytes());
    for duration in [
        restart.window(),
        restart.initial_backoff(),
        restart.maximum_backoff(),
        restart.stable_reset(),
    ] {
        update_field(digest, &duration_millis(duration).to_be_bytes());
    }
}

fn update_mark(digest: &mut Sha256, mark: FwmarkCandidate) {
    for value in [mark.mask(), mark.proxy_value(), mark.bypass_value()] {
        update_field(digest, &value.to_be_bytes());
    }
}

fn update_routing(digest: &mut Sha256, routing: Option<XtablesLocalOutputRoutingSpec>) {
    for family in [NetworkAddressFamily::Ipv4, NetworkAddressFamily::Ipv6] {
        match routing.and_then(|routing| routing.routing_for(family)) {
            Some(target) => {
                digest.update([1]);
                update_field(digest, &target.priority().get().to_be_bytes());
                update_field(digest, &target.table().get().to_be_bytes());
                update_field(digest, &target.route_metric().get().to_be_bytes());
                digest.update([target.route_protocol().raw(), target.rule_protocol().raw()]);
            }
            None => digest.update([0]),
        }
    }
}

fn update_ip(digest: &mut Sha256, address: IpAddr) {
    match address {
        IpAddr::V4(address) => {
            digest.update([4]);
            update_field(digest, &address.octets());
        }
        IpAddr::V6(address) => {
            digest.update([6]);
            update_field(digest, &address.octets());
        }
    }
}

fn family_tag(families: AddressHostFamilySelection) -> u8 {
    match families {
        AddressHostFamilySelection::Ipv4 => 0,
        AddressHostFamilySelection::Ipv6 => 1,
        AddressHostFamilySelection::DualStack => 2,
    }
}

fn application_mode_tag(mode: CaptureApplicationMode) -> u8 {
    match mode {
        CaptureApplicationMode::All => 0,
        CaptureApplicationMode::Allowlist => 1,
        CaptureApplicationMode::Denylist => 2,
    }
}

const fn capture_path_tag(path: CapturePathId) -> u8 {
    match path {
        CapturePathId::NftablesTproxy => 0,
        CapturePathId::XtablesTproxy => 1,
        CapturePathId::ManagedTun => 2,
    }
}

fn duration_millis(duration: std::time::Duration) -> u128 {
    duration.as_millis()
}

fn update_path(digest: &mut Sha256, path: &Path) {
    update_os_str(digest, path.as_os_str());
}

#[cfg(unix)]
fn update_os_str(digest: &mut Sha256, value: &OsStr) {
    use std::os::unix::ffi::OsStrExt;
    update_field(digest, value.as_bytes());
}

#[cfg(not(unix))]
fn update_os_str(digest: &mut Sha256, value: &OsStr) {
    update_field(digest, value.to_string_lossy().as_bytes());
}

fn update_field(digest: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).expect("canonical evidence field length fits u64");
    digest.update(length.to_be_bytes());
    digest.update(bytes);
}

fn update_count(digest: &mut Sha256, count: usize) {
    let count = u64::try_from(count).expect("canonical collection length fits u64");
    update_field(digest, &count.to_be_bytes());
}
