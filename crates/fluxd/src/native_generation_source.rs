use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AndroidNetdSourceProfile, AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, CaptureTrafficDomain, FluxConfig, FwmarkCandidate,
    GenerationId, NetworkAddressFamily, NetworkInventory, Reason, RpdbFamilyPlacement,
    RpdbPlacementRequest, RulePriority, RuleTableId, classify_android_rpdb,
    plan_android_rpdb_placement,
};
use flux_platform::{
    AndroidCapturePathQualifications, AndroidFwmarkCensusCoordinatorOutcome,
    AndroidFwmarkCensusCoordinatorPurpose, AndroidFwmarkCensusCoordinatorRequest,
    NativeXtablesCaptureAdmission, NativeXtablesCaptureAdmissionError, NativeXtablesCaptureTarget,
    NetworkInventorySource, SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness,
    SystemAndroidFwmarkCensusSource, coordinate_android_fwmark_census_for_inventory,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use flux_platform::{NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestError};

use crate::generation_engine_config::{
    AddressReconciledGenerationInputs, AddressReconciliationError, AddressReconciliationInspection,
    AdmittedGeneration, AdmittedGenerationIdentity, CapturePathDecision,
    CapturePathQualificationEvidence, CapturePathQualificationEvidenceError,
    DesiredStateCompileError, EngineCapabilityProfileError, EngineConfigCompileError,
    GenerationAssembler, GenerationAssemblyError, GenerationAssemblyRequest,
    GenerationPlanningAuthority, SelectedEngineSource, TproxyEngineConfigRequest,
    bind_engine_config_to_spec, collect_tproxy_engine_capability_profile,
    compile_address_reconciliation, compile_tproxy_engine_config, read_bounded_regular_file,
};
use crate::intent_store::record_io;
use crate::native_runtime_writer::{NativeGenerationSource, PreparedNativeGeneration};
use crate::runtime_coordinator::PublishedRuntimeState;
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

const SYSTEM_ANDROID_CANDIDATE_MASK: u32 = 0x0300_0000;
const SYSTEM_ANDROID_CENSUS_BOUND: Duration = Duration::from_secs(30);
const SYSTEM_ANDROID_PROXY_VALUE: u32 = 0x0100_0000;
const SYSTEM_ANDROID_BYPASS_VALUE: u32 = 0x0200_0000;
const SYSTEM_ANDROID_PROXY_PRIORITY: u32 = 30_999;
const SYSTEM_ANDROID_PRIVATE_TABLE: u32 = 20_253;

/// Production Android planning adapter backed by the complete system census coordinator.
pub(crate) struct SystemAndroidGenerationPlanningSource {
    census: SystemAndroidFwmarkCensusSource,
    initial: Option<(FluxConfig, GenerationPlanningAuthority)>,
}

impl SystemAndroidGenerationPlanningSource {
    #[must_use]
    pub(crate) fn for_current_daemon(durable_root: impl AsRef<Path>) -> Self {
        Self {
            census: SystemAndroidFwmarkCensusSource::for_current_daemon(durable_root),
            initial: None,
        }
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
        let candidate = FwmarkCandidate::new(
            SYSTEM_ANDROID_CANDIDATE_MASK,
            SYSTEM_ANDROID_PROXY_VALUE,
            SYSTEM_ANDROID_BYPASS_VALUE,
        )
        .expect("compiled Android mark candidate is structurally valid");
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
        let request = AndroidFwmarkCensusCoordinatorRequest::new(
            AndroidNetdSourceProfile::AospNetd20250324,
            candidate,
            topology,
            SYSTEM_ANDROID_CENSUS_BOUND,
        )
        .expect("compiled Android census request is structurally valid");
        let outcome = coordinate_android_fwmark_census_for_inventory(
            &mut self.census,
            &request,
            AndroidFwmarkCensusCoordinatorPurpose::PlanningAuthority,
            Arc::clone(&inventory),
        )
        .map_err(|source| {
            SystemAndroidGenerationPlanningError::Census(source.to_string().into_boxed_str())
        })?;
        let evidence = match outcome {
            AndroidFwmarkCensusCoordinatorOutcome::PlanningAuthority(evidence) => *evidence,
            AndroidFwmarkCensusCoordinatorOutcome::Diagnostic(_) => {
                return Err(SystemAndroidGenerationPlanningError::UnexpectedDiagnostic);
            }
        };

        let family = RpdbFamilyPlacement::proxy_only(
            RulePriority::from_raw(SYSTEM_ANDROID_PROXY_PRIORITY),
            RuleTableId::from_raw(SYSTEM_ANDROID_PRIVATE_TABLE),
        )
        .expect("compiled Android one-rule placement is structurally valid");
        let placement_request = RpdbPlacementRequest::new(Some(family), Some(family))
            .expect("compiled Android placement enables both families");
        let classification =
            classify_android_rpdb(&inventory, AndroidNetdSourceProfile::AospNetd20250324);
        let placement = plan_android_rpdb_placement(&inventory, &classification, placement_request)
            .map_err(|source| {
                SystemAndroidGenerationPlanningError::Placement(source.to_string().into_boxed_str())
            })?;
        let capture_path_evidence = CapturePathQualificationEvidence::with_maximum_lifetime(
            AndroidCapturePathQualifications::default(),
            Instant::now(),
        )
        .map_err(SystemAndroidGenerationPlanningError::CapturePathEvidence)?;
        Ok(GenerationPlanningAuthority::android(
            evidence,
            capture_path_evidence,
            Some(placement),
        ))
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SystemAndroidGenerationPlanningError {
    LocalOutputRequired,
    ForwardedIngressUnsupported,
    InitialAlreadyAccepted,
    InitialDesiredStateChanged,
    UnexpectedDiagnostic,
    CapturePathEvidence(CapturePathQualificationEvidenceError),
    Census(Box<str>),
    Placement(Box<str>),
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
            Self::Census(detail) => write!(formatter, "Android planning census failed: {detail}"),
            Self::Placement(detail) => {
                write!(
                    formatter,
                    "Android proxy-only RPDB placement failed: {detail}"
                )
            }
        }
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
        Self {
            paths,
            inventory,
            planning,
            admission,
            accepted_subscription,
            latest_capture_path_decision: None,
            pending: None,
            committed: None,
            retired_config_path: None,
            identity: PhantomData,
        }
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
        if desired_state.subscription().enabled() {
            let subscription = self
                .accepted_subscription
                .as_ref()
                .ok_or(NativeGenerationSourceError::SubscriptionUnavailable)?;
            if subscription.desired_state() != desired_state {
                return Err(NativeGenerationSourceError::SelectedSourceDrift);
            }
            let artifact = subscription
                .reconstruct_artifact(desired_state.listener().port())
                .map_err(NativeGenerationSourceError::EngineConfig)?;
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
        let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            &template,
            desired_state.listener().port(),
        ))
        .map_err(NativeGenerationSourceError::EngineConfig)?;
        Ok((SelectedEngineSource::template(artifact), None))
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
        let engine_profile = collect_tproxy_engine_capability_profile(&binding, &spec)
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
        let capture_path_selection = admitted.capture_path_selection();
        let capture_path_evidence_deadline = admitted.capture_path_evidence_deadline();
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
        Ok(PreparedNativeGeneration::new(
            expected_generation,
            spec,
            capture_path_selection,
            capture_path_evidence_deadline,
            target,
        ))
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
        let artifact = config
            .reconstruct_artifact(inputs.desired_state().listener().port())
            .map_err(NativeGenerationSourceError::EngineConfig)?;
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
    let credentials = desired_state.engine().credentials();
    if credentials.uid().get() != 0 || credentials.gid().get() != 0 {
        return Err(NativeGenerationSourceError::UnsupportedEngineIdentity);
    }
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
            launcher: SingBoxLauncher::Direct,
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
            Self::InventoryUnavailable
            | Self::SubscriptionUnavailable
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
    use std::net::IpAddr;
    use std::num::NonZeroU32;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};

    use flux_core::{
        CapabilityProfile, FwmarkCandidate, InterfaceAddressFlags, InterfaceAddressRecord,
        InterfaceIndex, NetworkInventoryTracker, NetworkNamespaceIdentity, RouteProtocol,
        RouteTableId, RulePriority, RuleProtocol,
    };
    use flux_platform::{XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingTarget};
    use flux_testkit::CapabilityProfileFixture;

    use super::*;
    use crate::generation_engine_config::{
        HostInspectionPlanningAuthority, SelectedEngineSourceIdentity,
        qualified_xtables_capture_path_evidence, qualified_xtables_kernel_config,
    };

    const PACKAGED_DESIRED_STATE: &str = include_str!("../../../conf/flux.toml");
    const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../conf/template.json");
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
        capture_path_evidence: CapturePathQualificationEvidence,
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
                    self.capture_path_evidence,
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
    }

    impl NativeGenerationTargetAdmission for RecordingAdmission {
        type Target = u64;
        type Error = io::Error;

        fn admit(&mut self, generation: AdmittedGeneration) -> Result<Self::Target, Self::Error> {
            self.admitted_sources.push(generation.engine_source());
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
            let assembled = AssembledNativeGenerationSource::new(
                paths,
                inventory.clone(),
                HostPlanning {
                    capability_profile: CapabilityProfileFixture::device_qualified(),
                    capture_path_evidence,
                },
                RecordingAdmission::default(),
                accepted_subscription,
            );

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
        let mut host_planning = HostPlanning {
            capability_profile: CapabilityProfileFixture::device_qualified(),
            capture_path_evidence: qualified_xtables_capture_path_evidence(),
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
        ))
        .expect("compile subscription engine source");
        ValidatedSubscriptionEngineConfig::for_test(desired_state, artifact, digest, 1)
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
