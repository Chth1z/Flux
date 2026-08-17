use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AddressHostFamilySelection, AndroidMarkPlanningAuthorizationError, AndroidNetdSourceProfile,
    AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, CaptureTrafficDomain, CompleteFwmarkCensusError, FluxConfig,
    FwmarkCandidate, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane, GenerationId,
    NetworkAddressFamily, NetworkInventory, Reason, ReviewedCanaryFacilityPolicy,
    ReviewedCanaryFacilitySelection, ReviewedCanaryRoleCredentials, RpdbFamilyPlacement,
    RpdbPlacementRequest, RulePriority, RuleTableId, classify_android_rpdb,
    classify_android_rpdb_with_reviewed_canary_facility, plan_android_rpdb_placement,
    plan_android_rpdb_placement_with_reviewed_canary_facility,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use flux_core::{CapabilityProfile, NetworkNamespaceIdentity};
use flux_platform::{
    AndroidFwmarkCensusCollectionStage, AndroidFwmarkCensusCoordinatorError,
    AndroidFwmarkCensusCoordinatorOutcome, AndroidFwmarkCensusCoordinatorPurpose,
    AndroidFwmarkCensusCoordinatorRequest, AndroidFwmarkCensusExternalPhase,
    NativeXtablesCaptureAdmission, NativeXtablesCaptureAdmissionError, NativeXtablesCaptureTarget,
    NetworkInventorySource, SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness,
    SystemAndroidFwmarkCensusSource, SystemAndroidFwmarkCensusSourceError,
    SystemAndroidFwmarkCensusSourceErrorKind, coordinate_android_fwmark_census_for_inventory,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use flux_platform::{
    NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestError,
    XtablesLocalOutputRoutingSpec,
};

use crate::functional_canary::{CanaryBindingError, CanaryFacilityIdentity};
use crate::generation_engine_config::{
    AddressReconciledGenerationInputs, AddressReconciliationError, AddressReconciliationInspection,
    AdmittedGeneration, AdmittedGenerationIdentity, CapturePathDecision,
    CapturePathQualificationEvidenceError, DesiredStateCompileError, EngineCapabilityProfile,
    EngineCapabilityProfileError, EngineConfigCompileError, EngineConfigLaunchBinding,
    GenerationAssembler, GenerationAssemblyError, GenerationAssemblyRequest,
    GenerationPlanningAuthority, SelectedEngineSource, TproxyCanaryEngineRoute,
    TproxyEngineConfigRequest, bind_engine_config_to_spec,
    collect_tproxy_engine_capability_profile, compile_address_reconciliation,
    compile_tproxy_engine_config, read_bounded_regular_file,
};
#[cfg(test)]
use crate::generation_engine_config::{
    EngineCapabilityProfileRevision, declare_supervised_delivery_report_profile_fixture,
    rebind_engine_capability_profile_fixture,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use crate::generation_engine_config::{
    HostInspectionPlanningAuthority, qualified_xtables_capture_path_evidence,
    qualified_xtables_kernel_config,
};
use crate::intent_store::record_io;
use crate::native_runtime_writer::{NativeGenerationSource, PreparedNativeGeneration};
use crate::runtime_coordinator::{PreparedGeneration, PublishedRuntimeState};
use crate::subscription::ValidatedSubscriptionEngineConfig;
use crate::{EngineSpec, EngineSpecError, IntentStoreError, RestartPolicy, RestartPolicyError};

pub(crate) trait CompleteNativeInventorySource: Send + 'static {
    fn snapshot(&mut self) -> Option<Arc<NetworkInventory>>;
}

impl CompleteNativeInventorySource for NetworkInventorySource {
    fn snapshot(&mut self) -> Option<Arc<NetworkInventory>> {
        NetworkInventorySource::snapshot(self)
    }
}

pub(crate) trait NativeGenerationPlanningSource: Send + 'static {
    type Error: Error + Send + Sync + 'static;

    fn plan(
        &mut self,
        desired_state: &FluxConfig,
        inventory: &NetworkInventory,
    ) -> Result<GenerationPlanningAuthority, Self::Error>;
}

trait EngineCapabilityProfileSource: Send + 'static {
    fn collect(
        &mut self,
        binding: &EngineConfigLaunchBinding,
        spec: &EngineSpec,
    ) -> Result<EngineCapabilityProfile, EngineCapabilityProfileError>;
}

#[derive(Default)]
struct ProcessEngineCapabilityProfileSource;

impl EngineCapabilityProfileSource for ProcessEngineCapabilityProfileSource {
    fn collect(
        &mut self,
        binding: &EngineConfigLaunchBinding,
        spec: &EngineSpec,
    ) -> Result<EngineCapabilityProfile, EngineCapabilityProfileError> {
        collect_tproxy_engine_capability_profile(binding, spec)
    }
}

#[cfg(test)]
#[derive(Default)]
struct InheritedEngineProfileSource;

#[cfg(test)]
impl EngineCapabilityProfileSource for InheritedEngineProfileSource {
    fn collect(
        &mut self,
        binding: &EngineConfigLaunchBinding,
        spec: &EngineSpec,
    ) -> Result<EngineCapabilityProfile, EngineCapabilityProfileError> {
        let mut process = spec.process().clone();
        process.privilege = SingBoxPrivilege::Inherit;
        let probe_spec = EngineSpec::new(process, spec.restart_policy())
            .expect("inspect inherited engine-profile fixture");
        let probe_binding = bind_engine_config_to_spec(binding.artifact().clone(), &probe_spec)
            .expect("bind inherited engine-profile fixture");
        let profile = collect_tproxy_engine_capability_profile(&probe_binding, &probe_spec)?;
        Ok(declare_supervised_delivery_report_profile_fixture(
            rebind_engine_capability_profile_fixture(profile, binding),
        ))
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) struct LinuxNativeCompositionPlanningSource {
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    routing: XtablesLocalOutputRoutingSpec,
    mark: FwmarkCandidate,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl LinuxNativeCompositionPlanningSource {
    #[must_use]
    pub(crate) const fn new(
        capability_profile: CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        routing: XtablesLocalOutputRoutingSpec,
        mark: FwmarkCandidate,
    ) -> Self {
        Self {
            capability_profile,
            network_namespace,
            routing,
            mark,
        }
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl NativeGenerationPlanningSource for LinuxNativeCompositionPlanningSource {
    type Error = std::convert::Infallible;

    fn plan(
        &mut self,
        _desired_state: &FluxConfig,
        inventory: &NetworkInventory,
    ) -> Result<GenerationPlanningAuthority, Self::Error> {
        Ok(GenerationPlanningAuthority::host_inspection(
            HostInspectionPlanningAuthority::new(
                &self.capability_profile,
                qualified_xtables_kernel_config(),
                qualified_xtables_capture_path_evidence(),
                inventory,
                self.network_namespace,
                self.mark,
                Some(self.routing),
            ),
        ))
    }
}

const SYSTEM_ANDROID_CANDIDATE_MASK: u32 = 0x0300_0000;
const SYSTEM_ANDROID_CENSUS_BOUND: Duration = Duration::from_secs(30);
const SYSTEM_ANDROID_PROXY_VALUE: u32 = 0x0100_0000;
const SYSTEM_ANDROID_BYPASS_VALUE: u32 = 0x0200_0000;
const SYSTEM_ANDROID_PROXY_PRIORITY: u32 = 30_999;
const SYSTEM_ANDROID_PRIVATE_TABLE: u32 = 20_253;

/// Production Android planning adapter backed by the complete system census coordinator.
pub(crate) struct SystemAndroidGenerationPlanningSource {
    census: SystemAndroidFwmarkCensusSource,
    reviewed_canary_facility: Option<(
        ReviewedCanaryFacilityPolicy,
        ReviewedCanaryFacilitySelection,
        FwmarkCandidate,
    )>,
    initial: Option<(FluxConfig, GenerationPlanningAuthority)>,
}

impl SystemAndroidGenerationPlanningSource {
    #[must_use]
    pub(crate) fn for_current_daemon(durable_root: impl AsRef<Path>) -> Self {
        Self {
            census: SystemAndroidFwmarkCensusSource::for_current_daemon(durable_root),
            reviewed_canary_facility: None,
            initial: None,
        }
    }

    #[must_use]
    pub(crate) fn with_reviewed_canary_facility(
        mut self,
        policy: ReviewedCanaryFacilityPolicy,
        selection: ReviewedCanaryFacilitySelection,
        candidate: FwmarkCandidate,
    ) -> Self {
        self.reviewed_canary_facility = Some((policy, selection, candidate));
        self
    }

    pub(crate) fn plan_initial(
        &mut self,
        desired_state: &FluxConfig,
        inventory: &Arc<NetworkInventory>,
    ) -> Result<GenerationPlanningAuthority, SystemAndroidGenerationPlanningError> {
        self.plan_fresh(desired_state, Arc::clone(inventory))
    }

    pub(crate) fn accept_initial(
        &mut self,
        desired_state: &FluxConfig,
        planning: GenerationPlanningAuthority,
    ) -> Result<(), SystemAndroidGenerationPlanningError> {
        if self
            .initial
            .replace((desired_state.clone(), planning))
            .is_some()
        {
            return Err(SystemAndroidGenerationPlanningError::InitialAlreadyAccepted);
        }
        Ok(())
    }

    fn plan_fresh(
        &mut self,
        desired_state: &FluxConfig,
        inventory: Arc<NetworkInventory>,
    ) -> Result<GenerationPlanningAuthority, SystemAndroidGenerationPlanningError> {
        if !desired_state
            .capture()
            .scope()
            .includes_domain(CaptureTrafficDomain::LocalOutput)
        {
            return Err(SystemAndroidGenerationPlanningError::LocalOutputRequired);
        }
        if desired_state
            .capture()
            .scope()
            .includes_domain(CaptureTrafficDomain::ForwardedIngress)
        {
            return Err(SystemAndroidGenerationPlanningError::ForwardedIngressUnsupported);
        }
        let candidate = self.reviewed_canary_facility.as_ref().map_or_else(
            || {
                FwmarkCandidate::new(
                    SYSTEM_ANDROID_CANDIDATE_MASK,
                    SYSTEM_ANDROID_PROXY_VALUE,
                    SYSTEM_ANDROID_BYPASS_VALUE,
                )
                .expect("compiled Android mark candidate is structurally valid")
            },
            |(_, _, candidate)| *candidate,
        );
        let topology = AndroidTproxyTopologyScopeRequest::new(
            AndroidTproxyRoutingShape::PreMarkAddressHostSet,
            [
                AndroidTproxyTrafficDomainRequest::residual_local_output(
                    NetworkAddressFamily::Ipv4,
                ),
                AndroidTproxyTrafficDomainRequest::residual_local_output(
                    NetworkAddressFamily::Ipv6,
                ),
            ],
        )
        .expect("compiled Android topology request is structurally valid");
        let netd_source_profile = self.reviewed_canary_facility.as_ref().map_or(
            AndroidNetdSourceProfile::AospNetd20250324,
            |(policy, _, _)| policy.netd_source_profile(),
        );
        let mut request = AndroidFwmarkCensusCoordinatorRequest::new(
            netd_source_profile,
            candidate,
            topology,
            SYSTEM_ANDROID_CENSUS_BOUND,
        )
        .expect("compiled Android census request is structurally valid");
        if let Some((policy, selection, _)) = self.reviewed_canary_facility.as_ref() {
            request = request.with_reviewed_canary_facility(policy.clone(), *selection);
        }
        let outcome = coordinate_android_fwmark_census_for_inventory(
            &mut self.census,
            &request,
            AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
            Arc::clone(&inventory),
        )
        .map_err(|source| {
            SystemAndroidGenerationPlanningError::Census(
                SystemAndroidGenerationPlanningCensusError::new(source),
            )
        })?;
        let evidence = match outcome {
            AndroidFwmarkCensusCoordinatorOutcome::PlanningAuthority(evidence) => *evidence,
            AndroidFwmarkCensusCoordinatorOutcome::Diagnostic(_) => {
                return Err(SystemAndroidGenerationPlanningError::UnexpectedDiagnostic);
            }
        };

        let family = match self.reviewed_canary_facility.as_ref() {
            Some((policy, _, _)) => RpdbFamilyPlacement::proxy_only(
                policy.rpdb().proxy_rule_priority(),
                RuleTableId::from_raw(policy.rpdb().proxy_capture_table().get()),
            ),
            None => RpdbFamilyPlacement::proxy_only(
                RulePriority::from_raw(SYSTEM_ANDROID_PROXY_PRIORITY),
                RuleTableId::from_raw(SYSTEM_ANDROID_PRIVATE_TABLE),
            ),
        }
        .expect("reviewed or compiled Android one-rule placement is structurally valid");
        let ipv6_placement = self
            .reviewed_canary_facility
            .as_ref()
            .map_or(Some(family), |(_, selection, _)| {
                selection.peer_ipv6().map(|_| family)
            });
        let placement_request = RpdbPlacementRequest::new(Some(family), ipv6_placement)
            .expect("compiled Android placement always enables IPv4");
        let classification = match self.reviewed_canary_facility.as_ref() {
            Some((policy, selection, _)) => classify_android_rpdb_with_reviewed_canary_facility(
                &inventory,
                netd_source_profile,
                policy,
                *selection,
            )
            .map_err(|source| {
                SystemAndroidGenerationPlanningError::Placement(
                    SystemAndroidGenerationPlanningPlacementError::new(
                        SystemAndroidGenerationPlanningPlacementFailureClass::ReviewedClassification,
                        source,
                    ),
                )
            })?,
            None => classify_android_rpdb(&inventory, netd_source_profile),
        };
        let placement = match self.reviewed_canary_facility.as_ref() {
            Some((policy, selection, _)) => {
                plan_android_rpdb_placement_with_reviewed_canary_facility(
                    &inventory,
                    &classification,
                    placement_request,
                    policy,
                    *selection,
                )
                .map_err(|source| {
                    SystemAndroidGenerationPlanningError::Placement(
                        SystemAndroidGenerationPlanningPlacementError::new(
                            SystemAndroidGenerationPlanningPlacementFailureClass::ReviewedPlanning,
                            source,
                        ),
                    )
                })?
            }
            None => plan_android_rpdb_placement(&inventory, &classification, placement_request)
                .map_err(|source| {
                    SystemAndroidGenerationPlanningError::Placement(
                        SystemAndroidGenerationPlanningPlacementError::new(
                            SystemAndroidGenerationPlanningPlacementFailureClass::GenericPlanning,
                            source,
                        ),
                    )
                })?,
        };
        GenerationPlanningAuthority::android(evidence, Instant::now(), Some(placement))
            .map_err(SystemAndroidGenerationPlanningError::CapturePathEvidence)
    }
}

impl NativeGenerationPlanningSource for SystemAndroidGenerationPlanningSource {
    type Error = SystemAndroidGenerationPlanningError;

    fn plan(
        &mut self,
        desired_state: &FluxConfig,
        inventory: &NetworkInventory,
    ) -> Result<GenerationPlanningAuthority, Self::Error> {
        if let Some((planned_desired_state, initial)) = self.initial.take() {
            if &planned_desired_state != desired_state {
                return Err(SystemAndroidGenerationPlanningError::InitialDesiredStateChanged);
            }
            return Ok(initial);
        }
        self.plan_fresh(desired_state, Arc::new(inventory.clone()))
    }
}

#[cfg(any(test, flux_android_qualification))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningFailureClass {
    LocalOutputRequired,
    ForwardedIngressUnsupported,
    InitialAlreadyAccepted,
    InitialDesiredStateChanged,
    UnexpectedDiagnostic,
    CapturePathEvidence,
    Census(SystemAndroidGenerationPlanningCensusFailureClass),
    Placement(SystemAndroidGenerationPlanningPlacementFailureClass),
}

#[cfg(any(test, flux_android_qualification))]
impl fmt::Display for SystemAndroidGenerationPlanningFailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::LocalOutputRequired => formatter.write_str("local-output-required"),
            Self::ForwardedIngressUnsupported => {
                formatter.write_str("forwarded-ingress-unsupported")
            }
            Self::InitialAlreadyAccepted => formatter.write_str("initial-already-accepted"),
            Self::InitialDesiredStateChanged => {
                formatter.write_str("initial-desired-state-changed")
            }
            Self::UnexpectedDiagnostic => formatter.write_str("unexpected-diagnostic"),
            Self::CapturePathEvidence => formatter.write_str("capture-path-evidence"),
            Self::Census(class) => class.fmt_token(formatter),
            Self::Placement(class) => class.fmt_token(formatter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningCensusFailureClass {
    Collection {
        stage: AndroidFwmarkCensusCollectionStage,
        source: SystemAndroidFwmarkCensusSourceErrorKind,
    },
    CapabilityDeviceIdentityUnavailable,
    CapabilityDrift,
    ExternalSnapshotContextMismatch(AndroidFwmarkCensusExternalPhase),
    ExternalSnapshotDrift,
    PlatformProfile,
    SelectedNetdSourceProfileMismatch,
    ReviewedCanaryFacilityPolicyMismatch,
    ReviewedCanaryRpdb,
    Topology,
    Rpdb,
    Assembly,
    CompleteCensus(SystemAndroidGenerationPlanningCompleteCensusFailureClass),
    Authorization(SystemAndroidGenerationPlanningAuthorizationFailureClass),
}

impl SystemAndroidGenerationPlanningCensusFailureClass {
    fn from_error(
        error: &AndroidFwmarkCensusCoordinatorError<SystemAndroidFwmarkCensusSourceError>,
    ) -> Self {
        match error {
            AndroidFwmarkCensusCoordinatorError::Collection { stage, source } => Self::Collection {
                stage: *stage,
                source: source.kind(),
            },
            AndroidFwmarkCensusCoordinatorError::CapabilityDeviceIdentityUnavailable { .. } => {
                Self::CapabilityDeviceIdentityUnavailable
            }
            AndroidFwmarkCensusCoordinatorError::CapabilityDrift { .. } => Self::CapabilityDrift,
            AndroidFwmarkCensusCoordinatorError::ExternalSnapshotContextMismatch {
                phase, ..
            } => Self::ExternalSnapshotContextMismatch(*phase),
            AndroidFwmarkCensusCoordinatorError::ExternalSnapshotDrift { .. } => {
                Self::ExternalSnapshotDrift
            }
            AndroidFwmarkCensusCoordinatorError::PlatformProfile(_) => Self::PlatformProfile,
            AndroidFwmarkCensusCoordinatorError::SelectedNetdSourceProfileMismatch { .. } => {
                Self::SelectedNetdSourceProfileMismatch
            }
            AndroidFwmarkCensusCoordinatorError::ReviewedCanaryFacilityPolicyMismatch => {
                Self::ReviewedCanaryFacilityPolicyMismatch
            }
            AndroidFwmarkCensusCoordinatorError::ReviewedCanaryRpdb(_) => Self::ReviewedCanaryRpdb,
            AndroidFwmarkCensusCoordinatorError::Topology(_) => Self::Topology,
            AndroidFwmarkCensusCoordinatorError::Rpdb(_) => Self::Rpdb,
            AndroidFwmarkCensusCoordinatorError::Assembly(_) => Self::Assembly,
            AndroidFwmarkCensusCoordinatorError::CompleteCensus(error) => Self::CompleteCensus(
                SystemAndroidGenerationPlanningCompleteCensusFailureClass::from_error(error),
            ),
            AndroidFwmarkCensusCoordinatorError::Authorization(error) => Self::Authorization(
                SystemAndroidGenerationPlanningAuthorizationFailureClass::from_error(error),
            ),
        }
    }

    #[cfg(any(test, flux_android_qualification))]
    fn fmt_token(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collection { stage, source } => write!(
                formatter,
                "census/collection/{}/{}",
                stage.as_str(),
                system_android_census_source_error_kind_token(source)
            ),
            Self::CapabilityDeviceIdentityUnavailable => {
                formatter.write_str("census/capability-device-identity-unavailable")
            }
            Self::CapabilityDrift => formatter.write_str("census/capability-drift"),
            Self::ExternalSnapshotContextMismatch(phase) => write!(
                formatter,
                "census/external-snapshot-context-mismatch/{}",
                android_fwmark_external_phase_token(phase)
            ),
            Self::ExternalSnapshotDrift => formatter.write_str("census/external-snapshot-drift"),
            Self::PlatformProfile => formatter.write_str("census/platform-profile"),
            Self::SelectedNetdSourceProfileMismatch => {
                formatter.write_str("census/selected-netd-source-profile-mismatch")
            }
            Self::ReviewedCanaryFacilityPolicyMismatch => {
                formatter.write_str("census/reviewed-canary-facility-policy-mismatch")
            }
            Self::ReviewedCanaryRpdb => formatter.write_str("census/reviewed-canary-rpdb"),
            Self::Topology => formatter.write_str("census/topology"),
            Self::Rpdb => formatter.write_str("census/rpdb"),
            Self::Assembly => formatter.write_str("census/assembly"),
            Self::CompleteCensus(error) => fmt_complete_census_error_token(error, formatter),
            Self::Authorization(class) => class.fmt_token(formatter),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningCompleteCensusFailureClass {
    UnverifiedBootIdentity,
    UnverifiedDeviceIdentity,
    NetworkNamespaceMismatch,
    TooManyCoverageRecords,
    DuplicateCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    MissingCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    NonCompleteCoverage {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
        state: FwmarkCensusCoverageState,
    },
    TooManyMarkUseRecords,
    TooManyOrderedLateWrites,
    DuplicateOrderedLateWrite,
    OrderedLateWriteHasNoMarkUse,
    TooManyExactMarkSentinels,
    DuplicateExactMarkSentinel,
    ExactMarkSentinelHasNoMarkUse,
    PresentCoverageHasNoMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    AbsentCoverageHasMarkUse {
        source: FwmarkEvidenceSource,
        plane: FwmarkPlane,
    },
    ObservationIdExhausted,
}

impl SystemAndroidGenerationPlanningCompleteCensusFailureClass {
    fn from_error(error: &CompleteFwmarkCensusError) -> Self {
        match error {
            CompleteFwmarkCensusError::UnverifiedBootIdentity { .. } => {
                Self::UnverifiedBootIdentity
            }
            CompleteFwmarkCensusError::UnverifiedDeviceIdentity { .. } => {
                Self::UnverifiedDeviceIdentity
            }
            CompleteFwmarkCensusError::NetworkNamespaceMismatch { .. } => {
                Self::NetworkNamespaceMismatch
            }
            CompleteFwmarkCensusError::TooManyCoverageRecords { .. } => {
                Self::TooManyCoverageRecords
            }
            CompleteFwmarkCensusError::DuplicateCoverage { source, plane } => {
                Self::DuplicateCoverage {
                    source: *source,
                    plane: *plane,
                }
            }
            CompleteFwmarkCensusError::MissingCoverage { source, plane } => Self::MissingCoverage {
                source: *source,
                plane: *plane,
            },
            CompleteFwmarkCensusError::NonCompleteCoverage {
                source,
                plane,
                state,
            } => Self::NonCompleteCoverage {
                source: *source,
                plane: *plane,
                state: *state,
            },
            CompleteFwmarkCensusError::TooManyMarkUseRecords { .. } => Self::TooManyMarkUseRecords,
            CompleteFwmarkCensusError::TooManyOrderedLateWrites { .. } => {
                Self::TooManyOrderedLateWrites
            }
            CompleteFwmarkCensusError::DuplicateOrderedLateWrite => Self::DuplicateOrderedLateWrite,
            CompleteFwmarkCensusError::OrderedLateWriteHasNoMarkUse => {
                Self::OrderedLateWriteHasNoMarkUse
            }
            CompleteFwmarkCensusError::TooManyExactMarkSentinels { .. } => {
                Self::TooManyExactMarkSentinels
            }
            CompleteFwmarkCensusError::DuplicateExactMarkSentinel => {
                Self::DuplicateExactMarkSentinel
            }
            CompleteFwmarkCensusError::ExactMarkSentinelHasNoMarkUse => {
                Self::ExactMarkSentinelHasNoMarkUse
            }
            CompleteFwmarkCensusError::PresentCoverageHasNoMarkUse { source, plane } => {
                Self::PresentCoverageHasNoMarkUse {
                    source: *source,
                    plane: *plane,
                }
            }
            CompleteFwmarkCensusError::AbsentCoverageHasMarkUse { source, plane } => {
                Self::AbsentCoverageHasMarkUse {
                    source: *source,
                    plane: *plane,
                }
            }
            CompleteFwmarkCensusError::ObservationIdExhausted => Self::ObservationIdExhausted,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningAuthorizationFailureClass {
    NoPositiveDeviceGrant,
    IneligibleCandidate,
    UnverifiedBootIdentity,
    StaleTopologyScope,
    TopologyScopeNotAllResidual,
    MalformedPositiveGrant,
    GrantCandidateMismatch,
    GrantTopologyScopeMismatch,
    GrantBootIdentityMismatch,
    GrantNetworkNamespaceMismatch,
    GrantCapabilityProfileMismatch,
    GrantMissingPlanes,
    CensusInventoryMismatch,
    CensusBootIdentityMismatch,
    CensusNetworkNamespaceMismatch,
    CensusCapabilityProfileMismatch,
    CensusDevicePolicyIdentityMismatch,
    CensusDevicePolicyRevisionMismatch,
    CensusCollectorRevisionMismatch,
    CensusOwnershipJournalIdentityMismatch,
    CensusOwnershipJournalRevisionMismatch,
    PartialAuditConflict,
    PartialAuditEvidenceNotAvailable,
    CensusConflict,
    OrderedPacketWriteQualificationRequired,
    OrderedLateWriteQualificationMismatch,
    ExactMarkSentinelQualificationMismatch,
    NonFreshCensusObservation,
}

impl SystemAndroidGenerationPlanningAuthorizationFailureClass {
    fn from_error(error: &AndroidMarkPlanningAuthorizationError) -> Self {
        match error {
            AndroidMarkPlanningAuthorizationError::NoPositiveDeviceGrant { .. } => {
                Self::NoPositiveDeviceGrant
            }
            AndroidMarkPlanningAuthorizationError::IneligibleCandidate(_) => {
                Self::IneligibleCandidate
            }
            AndroidMarkPlanningAuthorizationError::UnverifiedBootIdentity { .. } => {
                Self::UnverifiedBootIdentity
            }
            AndroidMarkPlanningAuthorizationError::StaleTopologyScope(_) => {
                Self::StaleTopologyScope
            }
            AndroidMarkPlanningAuthorizationError::TopologyScopeNotAllResidual { .. } => {
                Self::TopologyScopeNotAllResidual
            }
            AndroidMarkPlanningAuthorizationError::MalformedPositiveGrant => {
                Self::MalformedPositiveGrant
            }
            AndroidMarkPlanningAuthorizationError::GrantCandidateMismatch { .. } => {
                Self::GrantCandidateMismatch
            }
            AndroidMarkPlanningAuthorizationError::GrantTopologyScopeMismatch => {
                Self::GrantTopologyScopeMismatch
            }
            AndroidMarkPlanningAuthorizationError::GrantBootIdentityMismatch => {
                Self::GrantBootIdentityMismatch
            }
            AndroidMarkPlanningAuthorizationError::GrantNetworkNamespaceMismatch { .. } => {
                Self::GrantNetworkNamespaceMismatch
            }
            AndroidMarkPlanningAuthorizationError::GrantCapabilityProfileMismatch { .. } => {
                Self::GrantCapabilityProfileMismatch
            }
            AndroidMarkPlanningAuthorizationError::GrantMissingPlanes { .. } => {
                Self::GrantMissingPlanes
            }
            AndroidMarkPlanningAuthorizationError::CensusInventoryMismatch { .. } => {
                Self::CensusInventoryMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusBootIdentityMismatch => {
                Self::CensusBootIdentityMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusNetworkNamespaceMismatch { .. } => {
                Self::CensusNetworkNamespaceMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusCapabilityProfileMismatch { .. } => {
                Self::CensusCapabilityProfileMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusDevicePolicyIdentityMismatch => {
                Self::CensusDevicePolicyIdentityMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusDevicePolicyRevisionMismatch {
                ..
            } => Self::CensusDevicePolicyRevisionMismatch,
            AndroidMarkPlanningAuthorizationError::CensusCollectorRevisionMismatch { .. } => {
                Self::CensusCollectorRevisionMismatch
            }
            AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalIdentityMismatch {
                ..
            } => Self::CensusOwnershipJournalIdentityMismatch,
            AndroidMarkPlanningAuthorizationError::CensusOwnershipJournalRevisionMismatch {
                ..
            } => Self::CensusOwnershipJournalRevisionMismatch,
            AndroidMarkPlanningAuthorizationError::PartialAuditConflict { .. } => {
                Self::PartialAuditConflict
            }
            AndroidMarkPlanningAuthorizationError::PartialAuditEvidenceNotAvailable { .. } => {
                Self::PartialAuditEvidenceNotAvailable
            }
            AndroidMarkPlanningAuthorizationError::CensusConflict { .. } => Self::CensusConflict,
            AndroidMarkPlanningAuthorizationError::OrderedPacketWriteQualificationRequired {
                ..
            } => Self::OrderedPacketWriteQualificationRequired,
            AndroidMarkPlanningAuthorizationError::OrderedLateWriteQualificationMismatch {
                ..
            } => Self::OrderedLateWriteQualificationMismatch,
            AndroidMarkPlanningAuthorizationError::ExactMarkSentinelQualificationMismatch {
                ..
            } => Self::ExactMarkSentinelQualificationMismatch,
            AndroidMarkPlanningAuthorizationError::NonFreshCensusObservation { .. } => {
                Self::NonFreshCensusObservation
            }
        }
    }

    #[cfg(any(test, flux_android_qualification))]
    fn fmt_token(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::NoPositiveDeviceGrant => "no-positive-device-grant",
            Self::IneligibleCandidate => "ineligible-candidate",
            Self::UnverifiedBootIdentity => "unverified-boot-identity",
            Self::StaleTopologyScope => "stale-topology-scope",
            Self::TopologyScopeNotAllResidual => "topology-scope-not-all-residual",
            Self::MalformedPositiveGrant => "malformed-positive-grant",
            Self::GrantCandidateMismatch => "grant-candidate-mismatch",
            Self::GrantTopologyScopeMismatch => "grant-topology-scope-mismatch",
            Self::GrantBootIdentityMismatch => "grant-boot-identity-mismatch",
            Self::GrantNetworkNamespaceMismatch => "grant-network-namespace-mismatch",
            Self::GrantCapabilityProfileMismatch => "grant-capability-profile-mismatch",
            Self::GrantMissingPlanes => "grant-missing-planes",
            Self::CensusInventoryMismatch => "census-inventory-mismatch",
            Self::CensusBootIdentityMismatch => "census-boot-identity-mismatch",
            Self::CensusNetworkNamespaceMismatch => "census-network-namespace-mismatch",
            Self::CensusCapabilityProfileMismatch => "census-capability-profile-mismatch",
            Self::CensusDevicePolicyIdentityMismatch => "census-device-policy-identity-mismatch",
            Self::CensusDevicePolicyRevisionMismatch => "census-device-policy-revision-mismatch",
            Self::CensusCollectorRevisionMismatch => "census-collector-revision-mismatch",
            Self::CensusOwnershipJournalIdentityMismatch => {
                "census-ownership-journal-identity-mismatch"
            }
            Self::CensusOwnershipJournalRevisionMismatch => {
                "census-ownership-journal-revision-mismatch"
            }
            Self::PartialAuditConflict => "partial-audit-conflict",
            Self::PartialAuditEvidenceNotAvailable => "partial-audit-evidence-not-available",
            Self::CensusConflict => "census-conflict",
            Self::OrderedPacketWriteQualificationRequired => {
                "ordered-packet-write-qualification-required"
            }
            Self::OrderedLateWriteQualificationMismatch => {
                "ordered-late-write-qualification-mismatch"
            }
            Self::ExactMarkSentinelQualificationMismatch => {
                "exact-mark-sentinel-qualification-mismatch"
            }
            Self::NonFreshCensusObservation => "non-fresh-census-observation",
        };
        write!(formatter, "census/authorization/{token}")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningPlacementFailureClass {
    ReviewedClassification,
    ReviewedPlanning,
    GenericPlanning,
}

impl SystemAndroidGenerationPlanningPlacementFailureClass {
    #[cfg(any(test, flux_android_qualification))]
    fn fmt_token(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ReviewedClassification => "placement/reviewed-classification",
            Self::ReviewedPlanning => "placement/reviewed-planning",
            Self::GenericPlanning => "placement/generic-planning",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemAndroidGenerationPlanningCensusError {
    class: SystemAndroidGenerationPlanningCensusFailureClass,
    detail: Box<str>,
}

impl SystemAndroidGenerationPlanningCensusError {
    fn new(
        source: AndroidFwmarkCensusCoordinatorError<SystemAndroidFwmarkCensusSourceError>,
    ) -> Self {
        Self {
            class: SystemAndroidGenerationPlanningCensusFailureClass::from_error(&source),
            detail: source.to_string().into_boxed_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SystemAndroidGenerationPlanningPlacementError {
    class: SystemAndroidGenerationPlanningPlacementFailureClass,
    detail: Box<str>,
}

impl SystemAndroidGenerationPlanningPlacementError {
    fn new(
        class: SystemAndroidGenerationPlanningPlacementFailureClass,
        source: impl fmt::Display,
    ) -> Self {
        Self {
            class,
            detail: source.to_string().into_boxed_str(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningError {
    LocalOutputRequired,
    ForwardedIngressUnsupported,
    InitialAlreadyAccepted,
    InitialDesiredStateChanged,
    UnexpectedDiagnostic,
    CapturePathEvidence(CapturePathQualificationEvidenceError),
    Census(SystemAndroidGenerationPlanningCensusError),
    Placement(SystemAndroidGenerationPlanningPlacementError),
}

impl SystemAndroidGenerationPlanningError {
    #[cfg(any(test, flux_android_qualification))]
    #[must_use]
    pub(crate) const fn failure_class(&self) -> SystemAndroidGenerationPlanningFailureClass {
        match self {
            Self::LocalOutputRequired => {
                SystemAndroidGenerationPlanningFailureClass::LocalOutputRequired
            }
            Self::ForwardedIngressUnsupported => {
                SystemAndroidGenerationPlanningFailureClass::ForwardedIngressUnsupported
            }
            Self::InitialAlreadyAccepted => {
                SystemAndroidGenerationPlanningFailureClass::InitialAlreadyAccepted
            }
            Self::InitialDesiredStateChanged => {
                SystemAndroidGenerationPlanningFailureClass::InitialDesiredStateChanged
            }
            Self::UnexpectedDiagnostic => {
                SystemAndroidGenerationPlanningFailureClass::UnexpectedDiagnostic
            }
            Self::CapturePathEvidence(_) => {
                SystemAndroidGenerationPlanningFailureClass::CapturePathEvidence
            }
            Self::Census(error) => SystemAndroidGenerationPlanningFailureClass::Census(error.class),
            Self::Placement(error) => {
                SystemAndroidGenerationPlanningFailureClass::Placement(error.class)
            }
        }
    }
}

impl fmt::Display for SystemAndroidGenerationPlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalOutputRequired => formatter
                .write_str("native Android production planning requires local-OUTPUT capture"),
            Self::ForwardedIngressUnsupported => formatter.write_str(
                "native Android production planning does not yet admit forwarded-ingress capture",
            ),
            Self::InitialAlreadyAccepted => {
                formatter.write_str("initial Android planning authority was already accepted")
            }
            Self::InitialDesiredStateChanged => formatter.write_str(
                "Desired State changed between initial Android planning and Generation assembly",
            ),
            Self::UnexpectedDiagnostic => {
                formatter.write_str("Android planning census returned a diagnostic-only projection")
            }
            Self::CapturePathEvidence(source) => source.fmt(formatter),
            Self::Census(error) => write!(
                formatter,
                "Android planning census failed: {}",
                error.detail
            ),
            Self::Placement(error) => {
                write!(
                    formatter,
                    "Android proxy-only RPDB placement failed: {}",
                    error.detail
                )
            }
        }
    }
}

#[cfg(any(test, flux_android_qualification))]
fn fmt_complete_census_error_token(
    error: SystemAndroidGenerationPlanningCompleteCensusFailureClass,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match error {
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::UnverifiedBootIdentity => {
            formatter.write_str("census/complete/unverified-boot-identity")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::UnverifiedDeviceIdentity => {
            formatter.write_str("census/complete/unverified-device-identity")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::NetworkNamespaceMismatch => {
            formatter.write_str("census/complete/network-namespace-mismatch")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::TooManyCoverageRecords => {
            formatter.write_str("census/complete/too-many-coverage-records")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::DuplicateCoverage {
            source,
            plane,
        } => write!(
            formatter,
            "census/complete/duplicate-coverage/{}/{}",
            fwmark_evidence_source_token(source),
            fwmark_plane_token(plane)
        ),
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::MissingCoverage {
            source,
            plane,
        } => write!(
            formatter,
            "census/complete/missing-coverage/{}/{}",
            fwmark_evidence_source_token(source),
            fwmark_plane_token(plane)
        ),
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::NonCompleteCoverage {
            source,
            plane,
            state,
        } => write!(
            formatter,
            "census/complete/noncomplete-coverage/{}/{}/{}",
            fwmark_evidence_source_token(source),
            fwmark_plane_token(plane),
            fwmark_coverage_state_token(state)
        ),
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::TooManyMarkUseRecords => {
            formatter.write_str("census/complete/too-many-mark-use-records")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::TooManyOrderedLateWrites => {
            formatter.write_str("census/complete/too-many-ordered-late-writes")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::DuplicateOrderedLateWrite => {
            formatter.write_str("census/complete/duplicate-ordered-late-write")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::OrderedLateWriteHasNoMarkUse => {
            formatter.write_str("census/complete/ordered-late-write-has-no-mark-use")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::TooManyExactMarkSentinels => {
            formatter.write_str("census/complete/too-many-exact-mark-sentinels")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::DuplicateExactMarkSentinel => {
            formatter.write_str("census/complete/duplicate-exact-mark-sentinel")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::ExactMarkSentinelHasNoMarkUse => {
            formatter.write_str("census/complete/exact-mark-sentinel-has-no-mark-use")
        }
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::PresentCoverageHasNoMarkUse {
            source,
            plane,
        } => write!(
            formatter,
            "census/complete/present-coverage-has-no-mark-use/{}/{}",
            fwmark_evidence_source_token(source),
            fwmark_plane_token(plane)
        ),
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::AbsentCoverageHasMarkUse {
            source,
            plane,
        } => write!(
            formatter,
            "census/complete/absent-coverage-has-mark-use/{}/{}",
            fwmark_evidence_source_token(source),
            fwmark_plane_token(plane)
        ),
        SystemAndroidGenerationPlanningCompleteCensusFailureClass::ObservationIdExhausted => {
            formatter.write_str("census/complete/observation-id-exhausted")
        }
    }
}

#[cfg(any(test, flux_android_qualification))]
const fn android_fwmark_external_phase_token(
    phase: AndroidFwmarkCensusExternalPhase,
) -> &'static str {
    match phase {
        AndroidFwmarkCensusExternalPhase::Before => "before",
        AndroidFwmarkCensusExternalPhase::After => "after",
    }
}

#[cfg(any(test, flux_android_qualification))]
const fn system_android_census_source_error_kind_token(
    kind: SystemAndroidFwmarkCensusSourceErrorKind,
) -> &'static str {
    match kind {
        SystemAndroidFwmarkCensusSourceErrorKind::InvalidCapabilityStage => {
            "invalid-capability-stage"
        }
        SystemAndroidFwmarkCensusSourceErrorKind::InvalidBound => "invalid-bound",
        SystemAndroidFwmarkCensusSourceErrorKind::DeadlineExceeded => "deadline-exceeded",
        SystemAndroidFwmarkCensusSourceErrorKind::KernelConfig => "kernel-config",
        SystemAndroidFwmarkCensusSourceErrorKind::NftablesGate => "nftables-gate",
        SystemAndroidFwmarkCensusSourceErrorKind::XtablesProcess => "xtables-process",
        SystemAndroidFwmarkCensusSourceErrorKind::XtablesObservation => "xtables-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::NftablesObservation => "nftables-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::TrafficControlBpfObservation => {
            "traffic-control-bpf-observation"
        }
        SystemAndroidFwmarkCensusSourceErrorKind::XfrmObservation => "xfrm-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::NetworkInventory => "network-inventory",
        SystemAndroidFwmarkCensusSourceErrorKind::ExistingFluxOwnership => {
            "existing-flux-ownership"
        }
    }
}

#[cfg(any(test, flux_android_qualification))]
const fn fwmark_evidence_source_token(source: FwmarkEvidenceSource) -> &'static str {
    match source {
        FwmarkEvidenceSource::AndroidNetId => "android-net-id",
        FwmarkEvidenceSource::Rpdb => "rpdb",
        FwmarkEvidenceSource::DeviceMarkPolicy => "device-mark-policy",
        FwmarkEvidenceSource::Xtables => "xtables",
        FwmarkEvidenceSource::Nftables => "nftables",
        FwmarkEvidenceSource::TrafficControlAndBpf => "traffic-control-and-bpf",
        FwmarkEvidenceSource::Xfrm => "xfrm",
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers => "connmark-and-socket-transfers",
        FwmarkEvidenceSource::ExistingFluxOwnership => "existing-flux-ownership",
    }
}

#[cfg(any(test, flux_android_qualification))]
const fn fwmark_plane_token(plane: FwmarkPlane) -> &'static str {
    match plane {
        FwmarkPlane::Packet => "packet",
        FwmarkPlane::Socket => "socket",
        FwmarkPlane::Conntrack => "conntrack",
    }
}

#[cfg(any(test, flux_android_qualification))]
const fn fwmark_coverage_state_token(state: FwmarkCensusCoverageState) -> &'static str {
    match state {
        FwmarkCensusCoverageState::CompletePresent => "complete-present",
        FwmarkCensusCoverageState::CompleteAbsent => "complete-absent",
        FwmarkCensusCoverageState::Incomplete => "incomplete",
        FwmarkCensusCoverageState::Opaque => "opaque",
        FwmarkCensusCoverageState::Denied => "denied",
        FwmarkCensusCoverageState::Transient => "transient",
        FwmarkCensusCoverageState::Unavailable => "unavailable",
    }
}

impl Error for SystemAndroidGenerationPlanningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CapturePathEvidence(source) => Some(source),
            _ => None,
        }
    }
}

pub(crate) trait NativeGenerationTargetAdmission: Send + 'static {
    type Target: Clone + Send + 'static;
    type Error: Error + Send + Sync + 'static;

    fn admit(&mut self, generation: AdmittedGeneration) -> Result<Self::Target, Self::Error>;
}

pub(crate) struct PlatformNativeGenerationTargetAdmission {
    platform: NativeXtablesCaptureAdmission,
}

impl PlatformNativeGenerationTargetAdmission {
    #[must_use]
    pub(crate) const fn new(platform: NativeXtablesCaptureAdmission) -> Self {
        Self { platform }
    }
}

impl NativeGenerationTargetAdmission for PlatformNativeGenerationTargetAdmission {
    type Target = NativeXtablesCaptureTarget;
    type Error = PlatformNativeGenerationAdmissionError;

    fn admit(&mut self, generation: AdmittedGeneration) -> Result<Self::Target, Self::Error> {
        let request = generation
            .into_native_target_request()
            .map_err(PlatformNativeGenerationAdmissionError::Promotion)?;
        self.platform
            .admit_android(request.mark, request.placement, request.xtables)
            .map_err(PlatformNativeGenerationAdmissionError::Platform)
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) struct PlatformNativeLinuxCompositionTestAdmission {
    platform: NativeLinuxCompositionTestAdmission,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl PlatformNativeLinuxCompositionTestAdmission {
    #[must_use]
    pub(crate) const fn new(platform: NativeLinuxCompositionTestAdmission) -> Self {
        Self { platform }
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl NativeGenerationTargetAdmission for PlatformNativeLinuxCompositionTestAdmission {
    type Target = NativeXtablesCaptureTarget;
    type Error = PlatformNativeLinuxCompositionTestAdmissionError;

    fn admit(&mut self, generation: AdmittedGeneration) -> Result<Self::Target, Self::Error> {
        let request = generation
            .into_linux_composition_test_request()
            .map_err(PlatformNativeLinuxCompositionTestAdmissionError::Promotion)?;
        self.platform
            .admit_linux_test(request.network_namespace, request.xtables)
            .map_err(PlatformNativeLinuxCompositionTestAdmissionError::Platform)
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
#[derive(Debug)]
pub(crate) enum PlatformNativeLinuxCompositionTestAdmissionError {
    Promotion(crate::generation_engine_config::LinuxCompositionTestPromotionError),
    Platform(NativeLinuxCompositionTestError),
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl fmt::Display for PlatformNativeLinuxCompositionTestAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promotion(source) => source.fmt(formatter),
            Self::Platform(source) => source.fmt(formatter),
        }
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl Error for PlatformNativeLinuxCompositionTestAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Promotion(source) => Some(source),
            Self::Platform(source) => Some(source),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PlatformNativeGenerationAdmissionError {
    Promotion(crate::generation_engine_config::NativeGenerationPromotionError),
    Platform(NativeXtablesCaptureAdmissionError),
}

impl fmt::Display for PlatformNativeGenerationAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promotion(source) => source.fmt(formatter),
            Self::Platform(source) => source.fmt(formatter),
        }
    }
}

impl Error for PlatformNativeGenerationAdmissionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Promotion(source) => Some(source),
            Self::Platform(source) => Some(source),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeGenerationSourcePaths {
    desired_state: PathBuf,
    state_root: PathBuf,
    working_directory: PathBuf,
    engine_log: PathBuf,
}

impl NativeGenerationSourcePaths {
    #[must_use]
    pub(crate) fn new(
        desired_state: impl AsRef<Path>,
        state_root: impl AsRef<Path>,
        working_directory: impl AsRef<Path>,
        engine_log: impl AsRef<Path>,
    ) -> Self {
        Self {
            desired_state: desired_state.as_ref().to_owned(),
            state_root: state_root.as_ref().to_owned(),
            working_directory: working_directory.as_ref().to_owned(),
            engine_log: engine_log.as_ref().to_owned(),
        }
    }

    #[must_use]
    pub(crate) fn from_runtime_layout(
        desired_state: impl AsRef<Path>,
        layout: &crate::runtime_layout::RuntimeLayout,
        working_directory: impl AsRef<Path>,
        engine_log: impl AsRef<Path>,
    ) -> Self {
        Self::new(
            desired_state,
            layout.state_path(),
            working_directory,
            engine_log,
        )
    }

    fn generation_config(&self, generation: GenerationId) -> PathBuf {
        self.state_root
            .join("generations")
            .join(format!("engine-{}.json", generation.get()))
    }
}

struct PendingGeneration {
    identity: AdmittedGenerationIdentity,
    desired_state: FluxConfig,
    engine_source: SelectedEngineSource,
    address: AddressReconciliationInspection,
    config_path: PathBuf,
    subscription: Option<ValidatedSubscriptionEngineConfig>,
}

struct CommittedGeneration<I> {
    identity: AdmittedGenerationIdentity,
    target: I,
    desired_state: FluxConfig,
    engine_source: SelectedEngineSource,
    address: AddressReconciliationInspection,
    config_path: PathBuf,
}

/// Production Generation source for the native coordinator seam.
///
/// The source owns selected engine-source state, immutable engine files, lineage, and candidate
/// settlement. External adapters supply only complete inventory, one-shot planning authority, and
/// opaque platform target admission.
pub(crate) struct AssembledNativeGenerationSource<V, P, A, I>
where
    V: CompleteNativeInventorySource,
    P: NativeGenerationPlanningSource,
    A: NativeGenerationTargetAdmission,
{
    paths: NativeGenerationSourcePaths,
    inventory: V,
    planning: P,
    admission: A,
    engine_profiles: Box<dyn EngineCapabilityProfileSource>,
    canary_facility: Option<CanaryFacilityIdentity>,
    reviewed_canary_credentials: Option<ReviewedCanaryRoleCredentials>,
    #[cfg(test)]
    allow_test_root_canary_credentials: bool,
    accepted_subscription: Option<ValidatedSubscriptionEngineConfig>,
    latest_capture_path_decision: Option<CapturePathDecision>,
    pending: Option<PendingGeneration>,
    committed: Option<CommittedGeneration<I>>,
    retired_config_path: Option<PathBuf>,
    identity: PhantomData<fn() -> I>,
}

impl<V, P, A, I> AssembledNativeGenerationSource<V, P, A, I>
where
    V: CompleteNativeInventorySource,
    P: NativeGenerationPlanningSource,
    A: NativeGenerationTargetAdmission,
    I: Copy + Eq,
{
    #[must_use]
    pub(crate) fn new(
        paths: NativeGenerationSourcePaths,
        inventory: V,
        planning: P,
        admission: A,
        accepted_subscription: Option<ValidatedSubscriptionEngineConfig>,
    ) -> Self {
        Self::with_engine_profile_source(
            paths,
            inventory,
            planning,
            admission,
            accepted_subscription,
            Box::new(ProcessEngineCapabilityProfileSource),
        )
    }

    #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
    #[must_use]
    pub(crate) fn for_linux_native_composition_test(
        paths: NativeGenerationSourcePaths,
        inventory: V,
        planning: P,
        admission: A,
        accepted_subscription: Option<ValidatedSubscriptionEngineConfig>,
    ) -> Self {
        Self::with_engine_profile_source(
            paths,
            inventory,
            planning,
            admission,
            accepted_subscription,
            Box::new(InheritedEngineProfileSource),
        )
    }

    fn with_engine_profile_source(
        paths: NativeGenerationSourcePaths,
        inventory: V,
        planning: P,
        admission: A,
        accepted_subscription: Option<ValidatedSubscriptionEngineConfig>,
        engine_profiles: Box<dyn EngineCapabilityProfileSource>,
    ) -> Self {
        Self {
            paths,
            inventory,
            planning,
            admission,
            engine_profiles,
            canary_facility: None,
            reviewed_canary_credentials: None,
            #[cfg(test)]
            allow_test_root_canary_credentials: false,
            accepted_subscription,
            latest_capture_path_decision: None,
            pending: None,
            committed: None,
            retired_config_path: None,
            identity: PhantomData,
        }
    }

    /// Bind an already-validated facility without granting this source network mutation authority.
    #[must_use]
    pub(crate) fn with_retained_canary_facility(
        mut self,
        facility: CanaryFacilityIdentity,
        credentials: ReviewedCanaryRoleCredentials,
    ) -> Self {
        self.canary_facility = Some(facility);
        self.reviewed_canary_credentials = Some(credentials);
        self
    }

    #[cfg(test)]
    #[must_use]
    fn with_test_retained_canary_facility(mut self, facility: CanaryFacilityIdentity) -> Self {
        self.canary_facility = Some(facility);
        self.allow_test_root_canary_credentials = true;
        self
    }

    fn prepare_current(
        &mut self,
        prior: Option<I>,
    ) -> Result<PreparedNativeGeneration<A::Target>, NativeGenerationSourceError> {
        let inputs = self.current_inputs()?;
        let (engine_source, subscription) = self.select_current_engine_source(&inputs)?;
        self.prepare_candidate(&inputs, engine_source, subscription, prior)
    }

    fn current_inputs(
        &mut self,
    ) -> Result<AddressReconciledGenerationInputs, NativeGenerationSourceError> {
        let inventory = self
            .inventory
            .snapshot()
            .ok_or(NativeGenerationSourceError::InventoryUnavailable)?;
        compile_address_reconciliation(&self.paths.desired_state, inventory)
            .map_err(NativeGenerationSourceError::Address)
    }

    fn select_current_engine_source(
        &self,
        inputs: &AddressReconciledGenerationInputs,
    ) -> Result<
        (
            SelectedEngineSource,
            Option<ValidatedSubscriptionEngineConfig>,
        ),
        NativeGenerationSourceError,
    > {
        let desired_state = inputs.desired_state();
        self.validate_configured_engine_credentials(desired_state)?;
        let canary_route = self.required_canary_route(desired_state)?;
        if desired_state.subscription().enabled() {
            let subscription = self
                .accepted_subscription
                .as_ref()
                .ok_or(NativeGenerationSourceError::SubscriptionUnavailable)?;
            if subscription.desired_state() != desired_state {
                return Err(NativeGenerationSourceError::SelectedSourceDrift);
            }
            let stored_artifact = subscription
                .reconstruct_artifact(desired_state.listener().port())
                .map_err(NativeGenerationSourceError::EngineConfig)?;
            let artifact = match canary_route {
                Some(route) => compile_tproxy_engine_config(
                    TproxyEngineConfigRequest::new(
                        stored_artifact.bytes(),
                        desired_state.listener().port(),
                        desired_state.capture().scope().families(),
                    )
                    .with_canary_route(route),
                )
                .map_err(NativeGenerationSourceError::EngineConfig)?,
                None => stored_artifact,
            };
            return Ok((
                SelectedEngineSource::subscription(
                    artifact,
                    subscription.snapshot_digest(),
                    subscription.subscription_source(),
                ),
                Some(subscription.clone()),
            ));
        }

        let template_path = desired_state.engine().template();
        let template = read_bounded_regular_file(template_path).map_err(|source| {
            NativeGenerationSourceError::Template {
                path: template_path.to_owned(),
                source,
            }
        })?;
        let request = TproxyEngineConfigRequest::new(
            &template,
            desired_state.listener().port(),
            desired_state.capture().scope().families(),
        );
        let request = match canary_route {
            Some(route) => request.with_canary_route(route),
            None => request,
        };
        let artifact = compile_tproxy_engine_config(request)
            .map_err(NativeGenerationSourceError::EngineConfig)?;
        Ok((SelectedEngineSource::template(artifact), None))
    }

    fn required_canary_route(
        &self,
        desired_state: &FluxConfig,
    ) -> Result<Option<TproxyCanaryEngineRoute>, NativeGenerationSourceError> {
        if !desired_state.safety().require_functional_canary() {
            return Ok(None);
        }
        let facility = self
            .canary_facility
            .ok_or(NativeGenerationSourceError::CanaryFacilityUnavailable)?;
        let ipv6_peer = match desired_state.capture().scope().families() {
            AddressHostFamilySelection::Ipv4 => None,
            AddressHostFamilySelection::DualStack => Some(
                facility
                    .ipv6()
                    .ok_or(NativeGenerationSourceError::CanaryBinding(
                        CanaryBindingError::MissingIpv6Facility,
                    ))?
                    .peer(),
            ),
            AddressHostFamilySelection::Ipv6 => {
                return Err(NativeGenerationSourceError::UnsupportedCanaryAddressFamilies);
            }
        };
        let ports = facility.ports();
        Ok(Some(TproxyCanaryEngineRoute::new(
            facility.ipv4().peer(),
            ipv6_peer,
            ports.tcp_echo(),
            ports.udp_echo(),
            ports.dns(),
        )))
    }

    fn validate_configured_engine_credentials(
        &self,
        desired_state: &FluxConfig,
    ) -> Result<(), NativeGenerationSourceError> {
        let configured = desired_state.engine().credentials();
        if !desired_state.safety().require_functional_canary() {
            return if configured.uid().get() == 0 && configured.gid().get() == 0 {
                Ok(())
            } else {
                Err(NativeGenerationSourceError::UnsupportedEngineIdentity)
            };
        }

        let Some(reviewed) = self.reviewed_canary_credentials else {
            #[cfg(test)]
            if self.allow_test_root_canary_credentials
                && configured.uid().get() == 0
                && configured.gid().get() == 0
            {
                return Ok(());
            }
            return Err(NativeGenerationSourceError::CanaryCredentialAuthorityUnavailable);
        };
        if configured.uid().get() != reviewed.engine_uid().get()
            || configured.gid().get() != reviewed.engine_gid().get()
        {
            return Err(NativeGenerationSourceError::CanaryEngineIdentityDrift);
        }
        Ok(())
    }

    fn prepare_candidate(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
        engine_source: SelectedEngineSource,
        subscription: Option<ValidatedSubscriptionEngineConfig>,
        prior: Option<I>,
    ) -> Result<PreparedNativeGeneration<A::Target>, NativeGenerationSourceError> {
        self.require_prior(prior)?;
        if self.pending.is_some() {
            return Err(NativeGenerationSourceError::Invariant(
                "a native Generation candidate is already pending settlement",
            ));
        }
        if self.retired_config_path.is_some() {
            return Err(NativeGenerationSourceError::Invariant(
                "retired native Generation file cleanup is still pending",
            ));
        }
        let prior_owned = self.committed.as_ref().map(|current| current.identity);
        let next = prior_owned
            .map_or(Some(GenerationId::INITIAL), |prior| {
                prior.generation().checked_next()
            })
            .ok_or(NativeGenerationSourceError::GenerationSequenceExhausted)?;
        let config_path = self.paths.generation_config(next);
        record_io::write(&config_path, engine_source.artifact().bytes())
            .map_err(NativeGenerationSourceError::State)?;

        let result = self.assemble_candidate(
            inputs,
            engine_source.clone(),
            subscription.clone(),
            prior_owned,
            next,
            config_path.clone(),
        );
        if result.is_err() {
            let _ = record_io::remove(&config_path);
        }
        result
    }

    fn assemble_candidate(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
        engine_source: SelectedEngineSource,
        subscription: Option<ValidatedSubscriptionEngineConfig>,
        prior_owned: Option<AdmittedGenerationIdentity>,
        expected_generation: GenerationId,
        config_path: PathBuf,
    ) -> Result<PreparedNativeGeneration<A::Target>, NativeGenerationSourceError> {
        let desired_state = inputs.desired_state().clone();
        let spec = build_engine_spec(&desired_state, &config_path, &self.paths)?;
        let binding = bind_engine_config_to_spec(engine_source.artifact().clone(), &spec)
            .map_err(NativeGenerationSourceError::EngineBinding)?;
        let engine_profile = self
            .engine_profiles
            .collect(&binding, &spec)
            .map_err(NativeGenerationSourceError::EngineProfile)?;
        let planning = self
            .planning
            .plan(&desired_state, inputs.inventory())
            .map_err(|source| NativeGenerationSourceError::Planning(Box::new(source)))?;
        let capability_profile = planning.capability_profile().clone();
        let artifacts = inputs
            .capture()
            .clone()
            .with_engine_source(engine_source.clone())
            .map_err(NativeGenerationSourceError::DesiredState)?;
        let request = GenerationAssemblyRequest::new(
            artifacts,
            spec.clone(),
            capability_profile,
            inputs.inventory(),
            engine_profile,
            planning,
        );
        let request = match prior_owned {
            Some(prior) => request.with_prior_owned(prior),
            None => request,
        };
        let admitted = match GenerationAssembler.assemble(request) {
            Ok(admitted) => {
                self.latest_capture_path_decision = Some(CapturePathDecision::Selected {
                    selection: admitted.capture_path_selection(),
                });
                admitted
            }
            Err(error) => {
                if let GenerationAssemblyError::CapturePath(source) = &error {
                    self.latest_capture_path_decision = Some(CapturePathDecision::Rejected {
                        rejection: source.rejection(),
                    });
                }
                return Err(NativeGenerationSourceError::Assembly(error));
            }
        };
        if admitted.generation() != expected_generation {
            return Err(NativeGenerationSourceError::Invariant(
                "Generation assembler returned an unexpected successor identifier",
            ));
        }
        let identity = admitted.identity();
        let engine_profile_revision = admitted.engine_profile_revision();
        let functional_canary_mode = admitted.functional_canary_mode();
        let supervised_delivery_report = admitted.supervised_delivery_report();
        let capture_path_selection = admitted.capture_path_selection();
        let capture_path_evidence_deadline = admitted.capture_path_evidence_deadline();
        let prepared_canary_generation = admitted
            .prepared_canary_generation_binding()
            .map_err(NativeGenerationSourceError::CanaryBinding)?;
        let retained_canary_facility = match functional_canary_mode {
            crate::functional_canary::FunctionalCanaryGateMode::RequiredUnqualified => Some(
                self.canary_facility
                    .ok_or(NativeGenerationSourceError::CanaryFacilityUnavailable)?,
            ),
            crate::functional_canary::FunctionalCanaryGateMode::StructuralVerificationOnly => None,
        };
        let target = self
            .admission
            .admit(admitted)
            .map_err(|source| NativeGenerationSourceError::Admission(Box::new(source)))?;
        self.pending = Some(PendingGeneration {
            identity,
            desired_state,
            engine_source,
            address: inputs.inspection(),
            config_path,
            subscription,
        });
        let runtime = PreparedGeneration::new(
            expected_generation,
            spec,
            engine_profile_revision,
            functional_canary_mode,
            supervised_delivery_report,
            capture_path_selection,
            capture_path_evidence_deadline,
        )
        .with_prepared_canary_generation(prepared_canary_generation);
        let runtime = match retained_canary_facility {
            Some(facility) => runtime.with_retained_canary_facility(facility),
            None => runtime,
        };
        Ok(PreparedNativeGeneration::new(runtime, target))
    }

    fn require_prior(&self, prior: Option<I>) -> Result<(), NativeGenerationSourceError> {
        if self.committed.as_ref().map(|current| current.target) == prior {
            Ok(())
        } else {
            Err(NativeGenerationSourceError::Invariant(
                "native coordinator prior target differs from source lineage",
            ))
        }
    }

    fn settle_running(
        &mut self,
        generation: GenerationId,
        target: Option<I>,
    ) -> Result<(), NativeGenerationSourceError> {
        let target = target.ok_or(NativeGenerationSourceError::Invariant(
            "running source settlement omitted the active target identity",
        ))?;
        if let Some(pending) = self.pending.as_ref() {
            if pending.identity.generation() != generation {
                return Err(NativeGenerationSourceError::Invariant(
                    "running source settlement identified a different candidate",
                ));
            }
            if self.retired_config_path.is_some() {
                return Err(NativeGenerationSourceError::Invariant(
                    "running source settlement overlapped retired file cleanup",
                ));
            }
            let pending = self
                .pending
                .take()
                .expect("validated pending native Generation remains present");
            let previous = self.committed.replace(CommittedGeneration {
                identity: pending.identity,
                target,
                desired_state: pending.desired_state,
                engine_source: pending.engine_source,
                address: pending.address,
                config_path: pending.config_path,
            });
            self.accepted_subscription = pending.subscription;
            self.retired_config_path = previous.map(|generation| generation.config_path);
        }
        match self.committed.as_ref() {
            Some(committed)
                if committed.identity.generation() == generation && committed.target == target =>
            {
                self.discard_retired_config()
            }
            _ => Err(NativeGenerationSourceError::Invariant(
                "running source settlement has no matching committed or pending Generation",
            )),
        }
    }

    fn discard_pending(&mut self) -> Result<(), NativeGenerationSourceError> {
        if let Some(pending) = self.pending.as_ref() {
            remove_generation_file(&pending.config_path)?;
        }
        self.pending = None;
        Ok(())
    }

    fn discard_retired_config(&mut self) -> Result<(), NativeGenerationSourceError> {
        if let Some(path) = self.retired_config_path.as_ref() {
            remove_generation_file(path)?;
        }
        self.retired_config_path = None;
        Ok(())
    }

    fn reject_pending(
        &mut self,
        generation: GenerationId,
        prior: Option<I>,
    ) -> Result<(), NativeGenerationSourceError> {
        self.require_prior(prior)?;
        let pending = self
            .pending
            .as_ref()
            .ok_or(NativeGenerationSourceError::Invariant(
                "prepared rejection has no pending native Generation",
            ))?;
        if pending.identity.generation() != generation {
            return Err(NativeGenerationSourceError::Invariant(
                "prepared rejection identified a different native Generation",
            ));
        }
        remove_generation_file(&pending.config_path)?;
        self.pending = None;
        Ok(())
    }

    #[cfg(test)]
    fn committed_engine_source(
        &self,
    ) -> Option<crate::generation_engine_config::SelectedEngineSourceIdentity> {
        self.committed
            .as_ref()
            .map(|generation| generation.engine_source.identity())
    }

    #[cfg(test)]
    fn committed_address(&self) -> Option<AddressReconciliationInspection> {
        self.committed.as_ref().map(|generation| generation.address)
    }

    #[cfg(test)]
    fn committed_desired_state(&self) -> Option<&FluxConfig> {
        self.committed
            .as_ref()
            .map(|generation| &generation.desired_state)
    }
}

impl<V, P, A, I> NativeGenerationSource<A::Target, I>
    for AssembledNativeGenerationSource<V, P, A, I>
where
    V: CompleteNativeInventorySource,
    P: NativeGenerationPlanningSource,
    A: NativeGenerationTargetAdmission,
    I: Copy + Eq + Send + 'static,
{
    type Error = NativeGenerationSourceError;

    fn prepare(
        &mut self,
        _reason: Reason,
        prior: Option<I>,
    ) -> Result<PreparedNativeGeneration<A::Target>, Self::Error> {
        self.prepare_current(prior)
    }

    fn prepare_address_successor(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
        prior: I,
    ) -> Result<Option<PreparedNativeGeneration<A::Target>>, Self::Error> {
        self.require_prior(Some(prior))?;
        let committed = self
            .committed
            .as_ref()
            .ok_or(NativeGenerationSourceError::Invariant(
                "address successor requires one committed Generation",
            ))?;
        if inputs.desired_state() != &committed.desired_state {
            return Err(NativeGenerationSourceError::SelectedSourceDrift);
        }
        if inputs.inspection() == committed.address {
            return Ok(None);
        }
        let engine_source = committed.engine_source.clone();
        let subscription = self.accepted_subscription.clone();
        self.prepare_candidate(inputs, engine_source, subscription, Some(prior))
            .map(Some)
    }

    fn prepare_subscription(
        &mut self,
        config: &ValidatedSubscriptionEngineConfig,
        prior: Option<I>,
    ) -> Result<Option<PreparedNativeGeneration<A::Target>>, Self::Error> {
        let inputs = self.current_inputs()?;
        if config.desired_state() != inputs.desired_state() {
            return Err(NativeGenerationSourceError::SelectedSourceDrift);
        }
        self.validate_configured_engine_credentials(inputs.desired_state())?;
        let stored_artifact = config
            .reconstruct_artifact(inputs.desired_state().listener().port())
            .map_err(NativeGenerationSourceError::EngineConfig)?;
        let artifact = match self.required_canary_route(inputs.desired_state())? {
            Some(route) => compile_tproxy_engine_config(
                TproxyEngineConfigRequest::new(
                    stored_artifact.bytes(),
                    inputs.desired_state().listener().port(),
                    inputs.desired_state().capture().scope().families(),
                )
                .with_canary_route(route),
            )
            .map_err(NativeGenerationSourceError::EngineConfig)?,
            None => stored_artifact,
        };
        let selected = SelectedEngineSource::subscription(
            artifact,
            config.snapshot_digest(),
            config.subscription_source(),
        );
        self.prepare_candidate(&inputs, selected, Some(config.clone()), prior)
            .map(Some)
    }

    fn accept_deferred_subscription(&mut self, config: ValidatedSubscriptionEngineConfig) -> bool {
        if self.committed.is_some() || self.pending.is_some() {
            return false;
        }
        self.accepted_subscription = Some(config);
        true
    }

    fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
        self.latest_capture_path_decision
    }

    fn invalidate_latest_capture_path_decision(&mut self) {
        self.latest_capture_path_decision = None;
    }

    fn reject_prepared(
        &mut self,
        generation: GenerationId,
        prior: Option<I>,
    ) -> Result<(), Self::Error> {
        self.reject_pending(generation, prior)
    }

    fn settle(
        &mut self,
        phase: PublishedRuntimeState,
        target: Option<I>,
    ) -> Result<(), Self::Error> {
        match phase {
            PublishedRuntimeState::Running { generation } => {
                self.settle_running(generation, target)
            }
            PublishedRuntimeState::Failed => self.discard_pending(),
            PublishedRuntimeState::Stopped => {
                self.discard_pending()?;
                self.discard_retired_config()?;
                if let Some(committed) = self.committed.as_ref() {
                    remove_generation_file(&committed.config_path)?;
                }
                self.committed = None;
                Ok(())
            }
        }
    }
}

fn build_engine_spec(
    desired_state: &FluxConfig,
    config_path: &Path,
    paths: &NativeGenerationSourcePaths,
) -> Result<EngineSpec, NativeGenerationSourceError> {
    let configured_restart = desired_state.engine().restart();
    let restart = RestartPolicy::new(
        configured_restart.max_attempts(),
        configured_restart.window(),
        configured_restart.initial_backoff(),
        configured_restart.maximum_backoff(),
        configured_restart.stable_reset(),
    )
    .map_err(NativeGenerationSourceError::RestartPolicy)?;
    EngineSpec::new(
        SingBoxLaunchSpec {
            binary: desired_state.engine().binary().to_owned(),
            config: config_path.to_owned(),
            working_directory: paths.working_directory.clone(),
            log: paths.engine_log.clone(),
            privilege: SingBoxPrivilege::transparent_proxy(desired_state.engine().credentials()),
            readiness: SingBoxReadiness::Listener {
                port: desired_state.listener().port(),
            },
            startup_timeout: desired_state.engine().startup_timeout(),
            stop_timeout: desired_state.engine().stop_timeout(),
        },
        restart,
    )
    .map_err(NativeGenerationSourceError::EngineSpec)
}

fn remove_generation_file(path: &Path) -> Result<(), NativeGenerationSourceError> {
    record_io::remove(path)
        .map(|_| ())
        .map_err(NativeGenerationSourceError::State)
}

#[derive(Debug)]
pub(crate) enum NativeGenerationSourceError {
    InventoryUnavailable,
    Address(AddressReconciliationError),
    SubscriptionUnavailable,
    CanaryFacilityUnavailable,
    CanaryCredentialAuthorityUnavailable,
    CanaryEngineIdentityDrift,
    UnsupportedCanaryAddressFamilies,
    SelectedSourceDrift,
    Template {
        path: PathBuf,
        source: std::io::Error,
    },
    EngineConfig(EngineConfigCompileError),
    State(IntentStoreError),
    UnsupportedEngineIdentity,
    RestartPolicy(RestartPolicyError),
    EngineSpec(EngineSpecError),
    EngineBinding(crate::generation_engine_config::EngineConfigBindingError),
    EngineProfile(EngineCapabilityProfileError),
    DesiredState(DesiredStateCompileError),
    Planning(Box<dyn Error + Send + Sync>),
    Assembly(GenerationAssemblyError),
    CanaryBinding(CanaryBindingError),
    Admission(Box<dyn Error + Send + Sync>),
    GenerationSequenceExhausted,
    Invariant(&'static str),
}

impl fmt::Display for NativeGenerationSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InventoryUnavailable => {
                formatter.write_str("complete network inventory is unavailable")
            }
            Self::Address(source) => source.fmt(formatter),
            Self::SubscriptionUnavailable => formatter
                .write_str("subscription-enabled Desired State has no accepted engine source"),
            Self::CanaryFacilityUnavailable => formatter
                .write_str("required functional-canary Generation has no retained native facility"),
            Self::CanaryCredentialAuthorityUnavailable => formatter.write_str(
                "required functional-canary Generation has no reviewed engine credential authority",
            ),
            Self::CanaryEngineIdentityDrift => formatter.write_str(
                "required functional-canary engine UID/GID differ from the reviewed boot facility",
            ),
            Self::UnsupportedCanaryAddressFamilies => formatter.write_str(
                "required functional-canary Generation supports IPv4 or dual-stack capture",
            ),
            Self::SelectedSourceDrift => formatter.write_str(
                "current Desired State differs from the selected engine-source transaction",
            ),
            Self::Template { path, source } => write!(
                formatter,
                "cannot read native Generation template {}: {source}",
                path.display()
            ),
            Self::EngineConfig(source) => source.fmt(formatter),
            Self::State(source) => write!(formatter, "native Generation state: {source}"),
            Self::UnsupportedEngineIdentity => formatter.write_str(
                "the first native Generation profile requires a root-owned direct Proxy Engine",
            ),
            Self::RestartPolicy(source) => source.fmt(formatter),
            Self::EngineSpec(source) => source.fmt(formatter),
            Self::EngineBinding(source) => source.fmt(formatter),
            Self::EngineProfile(source) => source.fmt(formatter),
            Self::DesiredState(source) => source.fmt(formatter),
            Self::Planning(source) => write!(formatter, "native Generation planning: {source}"),
            Self::Assembly(source) => source.fmt(formatter),
            Self::CanaryBinding(source) => source.fmt(formatter),
            Self::Admission(source) => write!(formatter, "native target admission: {source}"),
            Self::GenerationSequenceExhausted => {
                formatter.write_str("native Generation sequence is exhausted")
            }
            Self::Invariant(message) => formatter.write_str(message),
        }
    }
}

impl Error for NativeGenerationSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Address(source) => Some(source),
            Self::Template { source, .. } => Some(source),
            Self::EngineConfig(source) => Some(source),
            Self::State(source) => Some(source),
            Self::RestartPolicy(source) => Some(source),
            Self::EngineSpec(source) => Some(source),
            Self::EngineBinding(source) => Some(source),
            Self::EngineProfile(source) => Some(source),
            Self::DesiredState(source) => Some(source),
            Self::Planning(source) | Self::Admission(source) => Some(source.as_ref()),
            Self::Assembly(source) => Some(source),
            Self::CanaryBinding(source) => Some(source),
            Self::InventoryUnavailable
            | Self::SubscriptionUnavailable
            | Self::CanaryFacilityUnavailable
            | Self::CanaryCredentialAuthorityUnavailable
            | Self::CanaryEngineIdentityDrift
            | Self::UnsupportedCanaryAddressFamilies
            | Self::SelectedSourceDrift
            | Self::UnsupportedEngineIdentity
            | Self::GenerationSequenceExhausted
            | Self::Invariant(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::num::{NonZeroU16, NonZeroU32};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    use flux_core::{
        CapabilityProfile, CapturePathQualifications, FwmarkCandidate, InterfaceAddressFlags,
        InterfaceAddressRecord, InterfaceIndex, InterfaceName, NetworkInventoryTracker,
        NetworkNamespaceIdentity, RouteProtocol, RouteScope, RouteTableId, RulePriority,
        RuleProtocol,
    };
    use flux_platform::{XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingTarget};
    use flux_testkit::CapabilityProfileFixture;

    use super::*;
    use crate::functional_canary::{
        CanaryIpv4AddressPair, CanaryIpv6AddressPair, CanaryPeerVethTopology, CanaryResponderPorts,
        CanaryRouteShape, CanaryVethFamilyTopology, CanaryVethIdentity,
    };
    use crate::generation_engine_config::{
        CapturePathQualificationEvidence, HostInspectionPlanningAuthority,
        SelectedEngineSourceIdentity, qualified_xtables_capture_path_evidence,
        qualified_xtables_kernel_config,
    };

    const PACKAGED_DESIRED_STATE: &str = include_str!("../../../conf/flux.toml");
    const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../conf/template.json");

    #[test]
    fn android_planning_failure_token_keeps_complete_census_cell_identity_free() {
        let class = SystemAndroidGenerationPlanningFailureClass::Census(
            SystemAndroidGenerationPlanningCensusFailureClass::CompleteCensus(
                SystemAndroidGenerationPlanningCompleteCensusFailureClass::NonCompleteCoverage {
                    source: FwmarkEvidenceSource::DeviceMarkPolicy,
                    plane: FwmarkPlane::Packet,
                    state: FwmarkCensusCoverageState::Unavailable,
                },
            ),
        );
        let token = class.to_string();

        assert_eq!(
            token,
            "census/complete/noncomplete-coverage/device-mark-policy/packet/unavailable"
        );
        assert!(token.chars().all(|character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '-' | '/')));

        let error = SystemAndroidGenerationPlanningError::Census(
            SystemAndroidGenerationPlanningCensusError {
                class: match class {
                    SystemAndroidGenerationPlanningFailureClass::Census(class) => class,
                    _ => unreachable!("test class is census-scoped"),
                },
                detail: "secret=/device/private provider=credential".into(),
            },
        );
        assert_eq!(error.failure_class(), class);
        assert!(!error.failure_class().to_string().contains("secret"));
        assert!(!error.failure_class().to_string().contains("device/private"));
    }

    #[test]
    fn android_planning_failure_class_discards_namespace_identity_fields() {
        let profile = NetworkNamespaceIdentity::new(17, 19).expect("profile namespace identity");
        let observed = NetworkNamespaceIdentity::new(23, 29).expect("observed namespace identity");
        let class = SystemAndroidGenerationPlanningCompleteCensusFailureClass::from_error(
            &CompleteFwmarkCensusError::NetworkNamespaceMismatch { profile, observed },
        );

        assert_eq!(
            class,
            SystemAndroidGenerationPlanningCompleteCensusFailureClass::NetworkNamespaceMismatch
        );
        let token = SystemAndroidGenerationPlanningFailureClass::Census(
            SystemAndroidGenerationPlanningCensusFailureClass::CompleteCensus(class),
        )
        .to_string();
        assert_eq!(token, "census/complete/network-namespace-mismatch");
        for identity_component in [17_u64, 19, 23, 29] {
            assert!(!token.contains(&identity_component.to_string()));
        }
    }

    #[test]
    fn android_planning_failure_token_distinguishes_ordered_write_authorization() {
        let class = SystemAndroidGenerationPlanningFailureClass::Census(
            SystemAndroidGenerationPlanningCensusFailureClass::Authorization(
                SystemAndroidGenerationPlanningAuthorizationFailureClass::
                    OrderedLateWriteQualificationMismatch,
            ),
        );
        assert_eq!(
            class.to_string(),
            "census/authorization/ordered-late-write-qualification-mismatch"
        );
    }
    const PROFILE_SCRIPT: &[u8] = br#"#!/bin/sh
case "$1" in
    version)
        printf '%s\n' 'sing-box version 1.13.14'
        ;;
    check)
        exit 0
        ;;
    *)
        exit 64
        ;;
esac
"#;

    #[derive(Clone)]
    struct ReplayInventory {
        current: Arc<Mutex<Option<Arc<NetworkInventory>>>>,
    }

    impl ReplayInventory {
        fn new(current: Option<Arc<NetworkInventory>>) -> Self {
            Self {
                current: Arc::new(Mutex::new(current)),
            }
        }

        fn publish(&self, current: Option<Arc<NetworkInventory>>) {
            *self.current.lock().expect("inventory replay lock") = current;
        }
    }

    impl CompleteNativeInventorySource for ReplayInventory {
        fn snapshot(&mut self) -> Option<Arc<NetworkInventory>> {
            self.current.lock().expect("inventory replay lock").clone()
        }
    }

    struct HostPlanning {
        capability_profile: CapabilityProfile,
        capture_path_qualifications: CapturePathQualifications,
        capture_path_observed_at: Instant,
        capture_path_valid_until: Instant,
    }

    impl NativeGenerationPlanningSource for HostPlanning {
        type Error = io::Error;

        fn plan(
            &mut self,
            _desired_state: &FluxConfig,
            inventory: &NetworkInventory,
        ) -> Result<GenerationPlanningAuthority, Self::Error> {
            Ok(GenerationPlanningAuthority::host_inspection(
                HostInspectionPlanningAuthority::new(
                    &self.capability_profile,
                    qualified_xtables_kernel_config(),
                    CapturePathQualificationEvidence::host_inspection(
                        self.capture_path_qualifications,
                        self.capture_path_observed_at,
                        self.capture_path_valid_until,
                    )
                    .expect("host Capture Path evidence has a bounded lifetime"),
                    inventory,
                    NetworkNamespaceIdentity::new(10, 20).expect("network namespace identity"),
                    FwmarkCandidate::new(0x00ff_0000, 0x0080_0000, 0x0040_0000).expect("test mark"),
                    Some(test_routing()),
                ),
            ))
        }
    }

    #[derive(Default)]
    struct RecordingAdmission {
        admitted_sources: Vec<SelectedEngineSourceIdentity>,
        admitted_engine_profile_revisions: Vec<EngineCapabilityProfileRevision>,
    }

    impl NativeGenerationTargetAdmission for RecordingAdmission {
        type Target = u64;
        type Error = io::Error;

        fn admit(&mut self, generation: AdmittedGeneration) -> Result<Self::Target, Self::Error> {
            self.admitted_sources.push(generation.engine_source());
            self.admitted_engine_profile_revisions
                .push(generation.engine_profile_revision());
            Ok(u64::from(generation.generation().get()))
        }
    }

    type TestSource =
        AssembledNativeGenerationSource<ReplayInventory, HostPlanning, RecordingAdmission, u64>;

    struct SourceFixture {
        _directory: tempfile::TempDir,
        source: TestSource,
        inventory: ReplayInventory,
        desired_state_path: PathBuf,
        state_root: PathBuf,
        desired_state: FluxConfig,
        capture_path_evidence_deadline: Instant,
    }

    impl SourceFixture {
        fn new(subscription_enabled: bool) -> Self {
            let directory = tempfile::tempdir().expect("native Generation source fixture");
            let binary = directory.path().join("sing-box");
            let template = directory.path().join("template.json");
            let desired_state_path = directory.path().join("flux.toml");
            let state_root = directory.path().join("state");
            fs::create_dir_all(state_root.join("generations"))
                .expect("create immutable Generation directory");
            fs::write(&binary, PROFILE_SCRIPT).expect("write fake Sing-Box");
            fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))
                .expect("make fake Sing-Box executable");
            fs::write(&template, PACKAGED_ENGINE_TEMPLATE).expect("write engine template");

            let mut source = PACKAGED_DESIRED_STATE
                .replacen(
                    "/data/adb/flux/bin/sing-box",
                    binary.to_str().expect("UTF-8 binary path"),
                    1,
                )
                .replacen(
                    "/data/adb/flux/conf/template.json",
                    template.to_str().expect("UTF-8 template path"),
                    1,
                );
            if subscription_enabled {
                source = source.replacen("enabled = false", "enabled = true", 1);
            }
            fs::write(&desired_state_path, &source).expect("write fixture Desired State");
            let desired_state = FluxConfig::parse(&source).expect("parse fixture Desired State");
            let accepted_subscription = subscription_enabled.then(|| {
                subscription_config(
                    desired_state.clone(),
                    br#"{"inbounds":[],"log":{"level":"warn"}}"#,
                    [1; 32],
                )
            });

            let mut tracker = NetworkInventoryTracker::new();
            let initial = Arc::new(
                tracker
                    .publish_complete([], [])
                    .expect("publish empty inventory")
                    .clone(),
            );
            let inventory = ReplayInventory::new(Some(initial));
            let paths = NativeGenerationSourcePaths::new(
                &desired_state_path,
                &state_root,
                directory.path(),
                directory.path().join("sing-box.log"),
            );
            let capture_path_evidence = qualified_xtables_capture_path_evidence();
            let capture_path_evidence_deadline = capture_path_evidence.valid_until();
            let capture_path_observed_at = capture_path_evidence_deadline
                .checked_sub(Duration::from_secs(5 * 60))
                .expect("test Capture Path observation is representable");
            let assembled = AssembledNativeGenerationSource::with_engine_profile_source(
                paths,
                inventory.clone(),
                HostPlanning {
                    capability_profile: CapabilityProfileFixture::device_qualified(),
                    capture_path_qualifications: capture_path_evidence.qualifications(),
                    capture_path_observed_at,
                    capture_path_valid_until: capture_path_evidence_deadline,
                },
                RecordingAdmission::default(),
                accepted_subscription,
                Box::new(InheritedEngineProfileSource),
            )
            .with_test_retained_canary_facility(test_canary_facility());

            Self {
                _directory: directory,
                source: assembled,
                inventory,
                desired_state_path,
                state_root,
                desired_state,
                capture_path_evidence_deadline,
            }
        }

        fn generation_path(&self, generation: u32) -> PathBuf {
            self.state_root
                .join("generations")
                .join(format!("engine-{generation}.json"))
        }

        fn commit_initial(&mut self) -> PreparedNativeGeneration<u64> {
            let prepared = self
                .source
                .prepare(Reason::Boot, None)
                .expect("prepare initial native Generation");
            self.source
                .settle(
                    PublishedRuntimeState::Running {
                        generation: prepared.runtime().id(),
                    },
                    Some(*prepared.target()),
                )
                .expect("commit initial native Generation");
            prepared
        }

        fn changed_inventory(&self) -> Arc<NetworkInventory> {
            let mut tracker = NetworkInventoryTracker::new();
            tracker
                .publish_complete([], [])
                .expect("seed inventory identity");
            let address = InterfaceAddressRecord::new(
                InterfaceIndex::new(7).expect("interface index"),
                "8.8.8.8".parse::<IpAddr>().expect("test address"),
                32,
                InterfaceAddressFlags::from_bits(0),
            )
            .expect("interface address");
            Arc::new(
                tracker
                    .publish_complete([], [address])
                    .expect("publish changed inventory")
                    .clone(),
            )
        }
    }

    #[test]
    fn initial_desired_state_drift_rejects_the_cached_android_authority() {
        let mut fixture = SourceFixture::new(false);
        let inventory = fixture
            .inventory
            .snapshot()
            .expect("fixture publishes a complete inventory");
        let capture_path_observed_at = Instant::now();
        let mut host_planning = HostPlanning {
            capability_profile: CapabilityProfileFixture::device_qualified(),
            capture_path_qualifications: qualified_xtables_capture_path_evidence().qualifications(),
            capture_path_observed_at,
            capture_path_valid_until: capture_path_observed_at
                .checked_add(Duration::from_secs(5 * 60))
                .expect("test Capture Path deadline is representable"),
        };
        let initial = host_planning
            .plan(&fixture.desired_state, &inventory)
            .expect("construct test planning authority");
        let mut planning =
            SystemAndroidGenerationPlanningSource::for_current_daemon(&fixture.state_root);
        planning
            .accept_initial(&fixture.desired_state, initial)
            .expect("accept initial planning authority");

        let source = fs::read_to_string(&fixture.desired_state_path)
            .expect("read fixture Desired State")
            .replacen(
                "event_queue_capacity = 256",
                "event_queue_capacity = 257",
                1,
            );
        let changed = FluxConfig::parse(&source).expect("parse changed Desired State");
        let error = planning
            .plan(&changed, &inventory)
            .expect_err("Desired State drift must consume no cached authority");

        assert_eq!(
            error,
            SystemAndroidGenerationPlanningError::InitialDesiredStateChanged
        );
    }

    #[test]
    fn forwarded_ingress_is_rejected_before_android_census() {
        let mut fixture = SourceFixture::new(false);
        let inventory = fixture
            .inventory
            .snapshot()
            .expect("fixture publishes a complete inventory");
        let source = fs::read_to_string(&fixture.desired_state_path)
            .expect("read fixture Desired State")
            .replacen("forwarded_ingress = false", "forwarded_ingress = true", 1);
        let forwarded = FluxConfig::parse(&source).expect("parse forwarded-ingress Desired State");
        let missing_durable_root = fixture.state_root.join("not-created");
        let mut planning =
            SystemAndroidGenerationPlanningSource::for_current_daemon(missing_durable_root);

        let error = planning
            .plan_initial(&forwarded, &inventory)
            .expect_err("forwarded ingress must be rejected before census collection");

        assert_eq!(
            error,
            SystemAndroidGenerationPlanningError::ForwardedIngressUnsupported
        );
    }

    #[test]
    fn prepared_runtime_preserves_the_planning_evidence_deadline() {
        let mut fixture = SourceFixture::new(false);

        let prepared = fixture.commit_initial();

        assert_eq!(
            prepared.runtime().capture_path_evidence_deadline(),
            fixture.capture_path_evidence_deadline
        );
        assert_eq!(
            prepared.runtime().engine_profile_revision(),
            fixture.source.admission.admitted_engine_profile_revisions[0],
            "the exact admitted engine profile revision reaches runtime canary binding"
        );
        assert_eq!(
            prepared.runtime().functional_canary_mode(),
            crate::functional_canary::FunctionalCanaryGateMode::RequiredUnqualified
        );
        assert!(
            prepared
                .runtime()
                .supervised_delivery_report()
                .expect("required native Generation retains the sealed report contract")
                .is_canonical_schema_v1()
        );
    }

    #[test]
    fn required_template_and_subscription_sources_bind_the_retained_facility_route() {
        for subscription_enabled in [false, true] {
            let mut fixture = SourceFixture::new(subscription_enabled);
            let prepared = fixture.commit_initial();
            let document: serde_json::Value = serde_json::from_slice(
                &fs::read(fixture.generation_path(1)).expect("read routed Generation source"),
            )
            .expect("parse routed Generation source");

            assert_eq!(
                prepared.runtime().retained_canary_facility(),
                Some(test_canary_facility())
            );

            assert_eq!(
                document["outbounds"][0],
                serde_json::json!({"tag":"flux-canary-direct-v1","type":"direct"})
            );
            assert_eq!(
                document["route"]["rules"][0],
                serde_json::json!({
                    "action":"route",
                    "ip_cidr":["11.0.0.2/32"],
                    "network":"tcp",
                    "outbound":"flux-canary-direct-v1",
                    "port":[41001,41003]
                })
            );
            assert_eq!(
                document["route"]["rules"][1],
                serde_json::json!({
                    "action":"route",
                    "ip_cidr":["11.0.0.2/32"],
                    "network":"udp",
                    "outbound":"flux-canary-direct-v1",
                    "port":[41002,41003]
                })
            );

            if subscription_enabled {
                let stored = fixture
                    .source
                    .accepted_subscription
                    .as_ref()
                    .expect("fixture retains its subscription source")
                    .reconstruct_artifact(fixture.desired_state.listener().port())
                    .expect("stored subscription identity remains valid");
                assert!(
                    !stored
                        .bytes()
                        .windows(b"flux-canary-direct-v1".len())
                        .any(|window| window == b"flux-canary-direct-v1"),
                    "the persisted subscription source remains route-disabled"
                );
            }
        }
    }

    #[test]
    fn required_source_without_a_retained_facility_fails_before_artifact_creation() {
        let mut fixture = SourceFixture::new(false);
        fixture.source.canary_facility = None;

        let error = match fixture.source.prepare(Reason::Boot, None) {
            Ok(_) => panic!("required source cannot prepare without a retained facility"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NativeGenerationSourceError::CanaryFacilityUnavailable
        ));
        assert!(!fixture.generation_path(1).exists());
        assert!(fixture.source.pending.is_none());
    }

    #[test]
    fn required_source_without_reviewed_credentials_rejects_root_engine_before_artifact_creation() {
        let mut fixture = SourceFixture::new(false);
        fixture.source.allow_test_root_canary_credentials = false;

        let error = match fixture.source.prepare(Reason::Boot, None) {
            Ok(_) => panic!("required source cannot infer credential authority from root config"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NativeGenerationSourceError::CanaryCredentialAuthorityUnavailable
        ));
        assert!(!fixture.generation_path(1).exists());
        assert!(fixture.source.pending.is_none());
    }

    #[test]
    fn required_route_matches_the_generation_address_families() {
        let fixture = SourceFixture::new(false);
        let dual_state = FluxConfig::parse(
            &fs::read_to_string(&fixture.desired_state_path)
                .expect("read fixture Desired State")
                .replacen("ipv6 = false", "ipv6 = true", 1),
        )
        .expect("parse dual-stack Desired State");
        let route = fixture
            .source
            .required_canary_route(&dual_state)
            .expect("dual-stack facility satisfies dual-stack Generation")
            .expect("required Generation has a route");
        let artifact = compile_tproxy_engine_config(
            TproxyEngineConfigRequest::new(
                b"{}",
                dual_state.listener().port(),
                dual_state.capture().scope().families(),
            )
            .with_canary_route(route),
        )
        .expect("compile dual-stack Generation route");
        let document: serde_json::Value =
            serde_json::from_slice(artifact.bytes()).expect("parse dual-stack Generation route");

        assert_eq!(
            document["route"]["rules"][0]["ip_cidr"],
            serde_json::json!(["11.0.0.2/32", "2001:4860::2/128"])
        );
    }

    #[test]
    fn structural_source_without_a_facility_preserves_route_disabled_output() {
        let mut fixture = SourceFixture::new(false);
        fixture.source.canary_facility = None;
        let source = fs::read_to_string(&fixture.desired_state_path)
            .expect("read fixture Desired State")
            .replacen(
                "require_functional_canary = true",
                "require_functional_canary = false",
                1,
            );
        fs::write(&fixture.desired_state_path, source).expect("disable the fixture canary gate");

        let prepared = fixture
            .source
            .prepare(Reason::Boot, None)
            .expect("structural source does not require a facility");
        let bytes =
            fs::read(fixture.generation_path(1)).expect("read structural Generation source");

        assert_eq!(
            prepared.runtime().functional_canary_mode(),
            crate::functional_canary::FunctionalCanaryGateMode::StructuralVerificationOnly
        );
        assert_eq!(prepared.runtime().retained_canary_facility(), None);
        assert!(
            !bytes
                .windows(b"flux-canary-direct-v1".len())
                .any(|window| window == b"flux-canary-direct-v1")
        );
    }

    #[test]
    fn unchanged_address_input_preserves_the_accepted_subscription_source() {
        let mut fixture = SourceFixture::new(true);
        fixture.commit_initial();
        let first_path = fixture.generation_path(1);
        let first_bytes = fs::read(&first_path).expect("read committed engine source");
        let expected_source = fixture.source.committed_engine_source();
        let inputs = fixture
            .source
            .current_inputs()
            .expect("current address inputs");

        let successor = fixture
            .source
            .prepare_address_successor(&inputs, 1)
            .expect("evaluate unchanged address input");

        assert!(successor.is_none());
        assert_eq!(fixture.source.committed_engine_source(), expected_source);
        assert_eq!(fs::read(first_path).unwrap(), first_bytes);
        assert!(!fixture.generation_path(2).exists());
    }

    #[test]
    fn address_successor_preserves_exact_subscription_artifact_and_prunes_predecessor() {
        let mut fixture = SourceFixture::new(true);
        fixture.commit_initial();
        let first_path = fixture.generation_path(1);
        let first_bytes = fs::read(&first_path).expect("read first engine source");
        let first_source = fixture.source.committed_engine_source();
        let changed = fixture.changed_inventory();
        fixture.inventory.publish(Some(Arc::clone(&changed)));
        let inputs = compile_address_reconciliation(&fixture.desired_state_path, changed)
            .expect("compile changed address inputs");

        let successor = fixture
            .source
            .prepare_address_successor(&inputs, 1)
            .expect("prepare address successor")
            .expect("changed address input needs a successor");
        let second_path = fixture.generation_path(2);

        assert_eq!(successor.runtime().id().get(), 2);
        assert_eq!(fs::read(&second_path).unwrap(), first_bytes);
        assert!(first_path.exists(), "predecessor remains until publication");
        fixture
            .source
            .settle(
                PublishedRuntimeState::Running {
                    generation: successor.runtime().id(),
                },
                Some(*successor.target()),
            )
            .expect("commit address successor");
        assert_eq!(fixture.source.committed_engine_source(), first_source);
        assert_eq!(
            fixture.source.committed_address(),
            Some(inputs.inspection())
        );
        assert!(!first_path.exists(), "published predecessor is pruned");
        assert!(second_path.exists(), "active immutable source remains");
    }

    #[test]
    fn running_settlement_retains_predecessor_file_ownership_until_deletion_succeeds() {
        let mut fixture = SourceFixture::new(true);
        fixture.commit_initial();
        let first_path = fixture.generation_path(1);
        let displaced = fixture.state_root.join("displaced-engine-1.json");
        fs::rename(&first_path, &displaced).expect("displace predecessor source");
        fs::create_dir(&first_path).expect("replace predecessor source with a directory");
        let changed = fixture.changed_inventory();
        fixture.inventory.publish(Some(Arc::clone(&changed)));
        let inputs = compile_address_reconciliation(&fixture.desired_state_path, changed)
            .expect("compile changed address inputs");
        let successor = fixture
            .source
            .prepare_address_successor(&inputs, 1)
            .expect("prepare address successor")
            .expect("changed address input needs a successor");

        fixture
            .source
            .settle(
                PublishedRuntimeState::Running {
                    generation: successor.runtime().id(),
                },
                Some(*successor.target()),
            )
            .expect_err("directory cannot be removed as an immutable source file");

        assert_eq!(
            fixture.source.retired_config_path.as_deref(),
            Some(first_path.as_path())
        );
        assert_eq!(
            fixture
                .source
                .committed
                .as_ref()
                .map(|generation| generation.identity.generation()),
            GenerationId::new(2)
        );
        assert!(matches!(
            fixture.source.prepare(Reason::UserControl, Some(2)),
            Err(NativeGenerationSourceError::Invariant(_))
        ));

        fs::remove_dir(&first_path).expect("remove injected predecessor directory");
        fs::rename(&displaced, &first_path).expect("restore predecessor source");
        fixture
            .source
            .settle(
                PublishedRuntimeState::Running {
                    generation: successor.runtime().id(),
                },
                Some(*successor.target()),
            )
            .expect("retry predecessor cleanup");

        assert!(fixture.source.retired_config_path.is_none());
        assert!(!first_path.exists());
        assert!(fixture.generation_path(2).exists());
    }

    #[test]
    fn failed_subscription_candidate_keeps_the_prior_selected_source_active() {
        let mut fixture = SourceFixture::new(true);
        fixture.commit_initial();
        let first_path = fixture.generation_path(1);
        let first_bytes = fs::read(&first_path).expect("read accepted source");
        let first_source = fixture.source.committed_engine_source();
        let replacement = subscription_config(
            fixture.desired_state.clone(),
            br#"{"inbounds":[],"log":{"level":"error"}}"#,
            [2; 32],
        );

        let candidate = fixture
            .source
            .prepare_subscription(&replacement, Some(1))
            .expect("prepare replacement subscription")
            .expect("replacement produces a candidate");
        assert_eq!(candidate.runtime().id().get(), 2);
        assert_ne!(fs::read(fixture.generation_path(2)).unwrap(), first_bytes);

        fixture
            .source
            .settle(PublishedRuntimeState::Failed, Some(1))
            .expect("discard failed subscription candidate");
        assert_eq!(fixture.source.committed_engine_source(), first_source);
        assert_eq!(fs::read(&first_path).unwrap(), first_bytes);
        assert!(!fixture.generation_path(2).exists());

        let retry = fixture
            .source
            .prepare(Reason::UserControl, Some(1))
            .expect("retry from accepted source");
        assert_eq!(fs::read(fixture.generation_path(2)).unwrap(), first_bytes);
        fixture
            .source
            .settle(PublishedRuntimeState::Failed, Some(*retry.target()))
            .expect("discard retry fixture");
    }

    #[test]
    fn rejected_initial_candidate_removes_its_file_and_releases_the_pending_slot() {
        let mut fixture = SourceFixture::new(false);

        let rejected = fixture
            .source
            .prepare(Reason::Boot, None)
            .expect("prepare initial candidate");
        let candidate_path = fixture.generation_path(1);
        assert_eq!(rejected.runtime().id(), GenerationId::INITIAL);
        assert!(candidate_path.exists(), "prepared source file must exist");

        fixture
            .source
            .settle(PublishedRuntimeState::Failed, None)
            .expect("reject initial candidate");
        assert!(!candidate_path.exists(), "rejected source file is removed");

        let retry = fixture
            .source
            .prepare(Reason::DaemonRecovery, None)
            .expect("pending slot is reusable after rejection");
        assert_eq!(retry.runtime().id(), GenerationId::INITIAL);
        assert!(
            candidate_path.exists(),
            "retry recreates the candidate file"
        );
        fixture
            .source
            .settle(PublishedRuntimeState::Failed, None)
            .expect("clean retry fixture");
        assert!(!candidate_path.exists());
    }

    #[test]
    fn prepared_rejection_requires_the_exact_generation_and_prior_lineage() {
        let mut fixture = SourceFixture::new(false);
        let rejected = fixture
            .source
            .prepare(Reason::Boot, None)
            .expect("prepare initial candidate");
        let candidate_path = fixture.generation_path(1);

        assert!(matches!(
            fixture.source.reject_prepared(
                GenerationId::new(2).expect("nonzero mismatched Generation"),
                None,
            ),
            Err(NativeGenerationSourceError::Invariant(_))
        ));
        assert!(candidate_path.exists());
        assert!(fixture.source.pending.is_some());
        assert!(matches!(
            fixture
                .source
                .reject_prepared(rejected.runtime().id(), Some(99)),
            Err(NativeGenerationSourceError::Invariant(_))
        ));
        assert!(candidate_path.exists());
        assert!(fixture.source.pending.is_some());

        fixture
            .source
            .reject_prepared(rejected.runtime().id(), None)
            .expect("exact candidate rejection succeeds");
        assert!(!candidate_path.exists());
        assert!(fixture.source.pending.is_none());
    }

    #[test]
    fn prepared_rejection_cannot_discard_a_committed_generation() {
        let mut fixture = SourceFixture::new(false);
        let committed = fixture.commit_initial();
        let committed_path = fixture.generation_path(1);

        assert!(matches!(
            fixture
                .source
                .reject_prepared(committed.runtime().id(), Some(*committed.target())),
            Err(NativeGenerationSourceError::Invariant(_))
        ));

        assert!(committed_path.exists());
        assert!(fixture.source.pending.is_none());
        assert_eq!(
            fixture
                .source
                .committed
                .as_ref()
                .map(|generation| generation.identity.generation()),
            Some(committed.runtime().id())
        );
    }

    #[test]
    fn failure_before_selection_preserves_the_latest_capture_path_decision() {
        let mut fixture = SourceFixture::new(false);
        fixture.commit_initial();
        let selected = fixture
            .source
            .latest_capture_path_decision()
            .expect("initial selected Capture Path decision");

        let error = match fixture.source.prepare(Reason::UserControl, None) {
            Ok(_) => panic!("incorrect prior target passed before Capture Path selection"),
            Err(error) => error,
        };

        assert!(matches!(error, NativeGenerationSourceError::Invariant(_)));
        assert_eq!(
            fixture.source.latest_capture_path_decision(),
            Some(selected)
        );
    }

    #[test]
    fn rollback_republishes_the_exact_prior_source_without_reselection() {
        let mut fixture = SourceFixture::new(true);
        fixture.commit_initial();
        let first_path = fixture.generation_path(1);
        let first_bytes = fs::read(&first_path).expect("read rollback source");
        let first_source = fixture.source.committed_engine_source();
        let replacement = subscription_config(
            fixture.desired_state.clone(),
            br#"{"inbounds":[],"log":{"level":"trace"}}"#,
            [3; 32],
        );
        fixture
            .source
            .prepare_subscription(&replacement, Some(1))
            .expect("prepare replacement")
            .expect("replacement candidate");

        fixture
            .source
            .settle(PublishedRuntimeState::Failed, Some(1))
            .expect("settle candidate failure");
        fixture
            .source
            .settle(
                PublishedRuntimeState::Running {
                    generation: GenerationId::INITIAL,
                },
                Some(1),
            )
            .expect("republish prior Generation");

        assert_eq!(fixture.source.committed_engine_source(), first_source);
        assert_eq!(fs::read(first_path).unwrap(), first_bytes);
        assert!(!fixture.generation_path(2).exists());
    }

    #[test]
    fn unavailable_complete_inventory_defers_without_creating_a_candidate() {
        let mut fixture = SourceFixture::new(false);
        fixture.inventory.publish(None);

        let error = match fixture.source.prepare(Reason::Boot, None) {
            Ok(_) => panic!("missing inventory cannot prepare a Generation"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            NativeGenerationSourceError::InventoryUnavailable
        ));
        assert!(!fixture.generation_path(1).exists());
        assert_eq!(fixture.source.committed_engine_source(), None);
    }

    #[test]
    fn stopped_settlement_removes_the_last_immutable_engine_source() {
        let mut fixture = SourceFixture::new(false);
        fixture.commit_initial();
        assert!(fixture.generation_path(1).exists());

        fixture
            .source
            .settle(PublishedRuntimeState::Stopped, None)
            .expect("settle stopped source");

        assert!(!fixture.generation_path(1).exists());
        assert_eq!(fixture.source.committed_engine_source(), None);
        assert_eq!(fixture.source.committed_desired_state(), None);
    }

    #[test]
    fn stopped_settlement_retains_committed_file_ownership_until_deletion_succeeds() {
        let mut fixture = SourceFixture::new(false);
        fixture.commit_initial();
        let committed_path = fixture.generation_path(1);
        let displaced = fixture.state_root.join("displaced-stopped-engine-1.json");
        fs::rename(&committed_path, &displaced).expect("displace committed source");
        fs::create_dir(&committed_path).expect("replace committed source with a directory");

        fixture
            .source
            .settle(PublishedRuntimeState::Stopped, None)
            .expect_err("directory cannot be removed as an immutable source file");

        assert!(fixture.source.committed.is_some());
        fs::remove_dir(&committed_path).expect("remove injected committed directory");
        fs::rename(&displaced, &committed_path).expect("restore committed source");
        fixture
            .source
            .settle(PublishedRuntimeState::Stopped, None)
            .expect("retry committed source cleanup");

        assert!(!committed_path.exists());
        assert!(fixture.source.committed.is_none());
    }

    fn subscription_config(
        desired_state: FluxConfig,
        template: &[u8],
        digest: [u8; 32],
    ) -> ValidatedSubscriptionEngineConfig {
        let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            template,
            desired_state.listener().port(),
            desired_state.capture().scope().families(),
        ))
        .expect("compile subscription engine source");
        ValidatedSubscriptionEngineConfig::for_test(desired_state, artifact, digest, 1)
    }

    fn test_canary_facility() -> CanaryFacilityIdentity {
        CanaryFacilityIdentity::new(
            CanaryVethIdentity::new(
                InterfaceIndex::new(101).expect("daemon veth index"),
                InterfaceName::new(b"fluxc0").expect("daemon veth name"),
            ),
            CanaryVethIdentity::new(
                InterfaceIndex::new(102).expect("peer veth index"),
                InterfaceName::new(b"fluxp0").expect("peer veth name"),
            ),
            CanaryIpv4AddressPair::new(Ipv4Addr::new(11, 0, 0, 1), Ipv4Addr::new(11, 0, 0, 2))
                .expect("test canary IPv4 pair"),
            Some(
                CanaryIpv6AddressPair::new(
                    Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 1),
                    Ipv6Addr::new(0x2001, 0x4860, 0, 0, 0, 0, 0, 2),
                )
                .expect("test canary IPv6 pair"),
            ),
            CanaryPeerVethTopology::new(
                CanaryVethFamilyTopology::ipv4(
                    32,
                    32,
                    test_canary_route_shape(20_253, 1_031),
                    test_canary_route_shape(20_262, 1_032),
                )
                .expect("test IPv4 veth topology"),
                Some(
                    CanaryVethFamilyTopology::ipv6(
                        128,
                        128,
                        test_canary_route_shape(20_253, 1_033),
                        test_canary_route_shape(20_264, 1_034),
                    )
                    .expect("test IPv6 veth topology"),
                ),
            )
            .expect("test dual-stack peer-veth topology"),
            CanaryResponderPorts::new(
                NonZeroU16::new(41_001).expect("TCP responder port"),
                NonZeroU16::new(41_002).expect("UDP responder port"),
                NonZeroU16::new(41_003).expect("DNS responder port"),
            )
            .expect("test responder ports"),
        )
        .expect("test canary facility")
    }

    fn test_canary_route_shape(table: u32, metric: u32) -> CanaryRouteShape {
        CanaryRouteShape::new(
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(99),
            RouteScope::from_raw(0),
            NonZeroU32::new(metric).expect("nonzero test canary route metric"),
        )
        .expect("test canary route shape")
    }

    fn test_routing() -> XtablesLocalOutputRoutingSpec {
        let target = XtablesLocalOutputRoutingTarget::new(
            RulePriority::from_raw(30_999),
            RouteTableId::from_raw(20_253),
            NonZeroU32::new(1_024).expect("route metric"),
            RouteProtocol::from_raw(4),
            RuleProtocol::from_raw(99),
        )
        .expect("routing target");
        XtablesLocalOutputRoutingSpec::new(Some(target), None).expect("IPv4 routing")
    }
}
