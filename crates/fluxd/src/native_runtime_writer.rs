use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use flux_core::{AddressResyncDisposition, GenerationId, Reason};
use flux_platform::{
    NativeCaptureCanaryAttempt, NativeCaptureCanarySelector, NativeCaptureConvergedState,
    NativeCaptureConvergence, NativeCaptureDesired, NativeCaptureTargetIdentity,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::{NativeXtablesCaptureConverger, NativeXtablesCaptureTarget};

#[cfg(test)]
use crate::EngineSpec;
use crate::EngineSupervisor;
#[cfg(test)]
use crate::functional_canary::FunctionalCanaryGateMode;
use crate::functional_canary::{CanaryAddressFamilies, CanaryAttemptRequest};
#[cfg(test)]
use crate::generation_engine_config::EngineCapabilityProfileRevision;
use crate::generation_engine_config::{AddressReconciledGenerationInputs, CapturePathDecision};
use crate::runtime_coordinator::{
    AddressResyncStrategy, CanarySelectorSession, PreparedGeneration, PublishedRuntimeState,
    RetiredCanarySelectorSession, RuntimeCoordinator, RuntimeFunctionalCanary, RuntimeWriter,
};
use crate::subscription::ValidatedSubscriptionEngineConfig;

pub(crate) trait NativeCoordinatorGenerationIdentity {
    fn coordinator_generation(self) -> Option<GenerationId>;

    fn native_capture_target_identity(self) -> Option<NativeCaptureTargetIdentity>
    where
        Self: Sized,
    {
        None
    }
}

impl NativeCoordinatorGenerationIdentity for NativeCaptureTargetIdentity {
    fn coordinator_generation(self) -> Option<GenerationId> {
        Some(self.generation())
    }

    fn native_capture_target_identity(self) -> Option<NativeCaptureTargetIdentity> {
        Some(self)
    }
}

pub(crate) struct PreparedNativeGeneration<T> {
    runtime: PreparedGeneration,
    target: T,
}

impl<T> PreparedNativeGeneration<T> {
    #[must_use]
    pub(crate) const fn new(runtime: PreparedGeneration, target: T) -> Self {
        Self { runtime, target }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn runtime(&self) -> &PreparedGeneration {
        &self.runtime
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn target(&self) -> &T {
        &self.target
    }
}

/// Lazy source accepted only after native recovery has reached verified clean absence.
pub(crate) trait NativeGenerationSource<T, I>: Send + 'static {
    type Error: Error + Send + Sync + 'static;

    fn prepare(
        &mut self,
        reason: Reason,
        prior: Option<I>,
    ) -> Result<PreparedNativeGeneration<T>, Self::Error>;

    fn prepare_address_successor(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
        prior: I,
    ) -> Result<Option<PreparedNativeGeneration<T>>, Self::Error>;

    fn prepare_subscription(
        &mut self,
        _config: &ValidatedSubscriptionEngineConfig,
        _prior: Option<I>,
    ) -> Result<Option<PreparedNativeGeneration<T>>, Self::Error> {
        Ok(None)
    }

    fn accept_deferred_subscription(&mut self, _config: ValidatedSubscriptionEngineConfig) -> bool {
        false
    }

    fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
        None
    }

    fn invalidate_latest_capture_path_decision(&mut self) {}

    fn reject_prepared(
        &mut self,
        generation: GenerationId,
        prior: Option<I>,
    ) -> Result<(), Self::Error> {
        let _ = generation;
        self.settle(PublishedRuntimeState::Failed, prior)
    }

    fn settle(
        &mut self,
        _phase: PublishedRuntimeState,
        _target: Option<I>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct RetainedNativeGeneration<T> {
    runtime: PreparedGeneration,
    target: T,
}

fn native_canary_attempt(
    request: &CanaryAttemptRequest,
) -> Result<NativeCaptureCanaryAttempt, NativeCoordinatorWriterError> {
    let environment = request.pre_binding().environment();
    let facility = environment.facility();
    let ipv6_peer = match request.families() {
        CanaryAddressFamilies::Ipv4Only => None,
        CanaryAddressFamilies::Ipv4AndIpv6 => Some(
            facility
                .ipv6()
                .ok_or(NativeCoordinatorWriterError::Invariant(
                    "dual-stack canary selector request has no admitted IPv6 peer",
                ))?
                .peer(),
        ),
    };
    let ports = facility.ports();
    let selector = NativeCaptureCanarySelector::new(
        environment.probe_uid(),
        facility.ipv4().peer(),
        ipv6_peer,
        ports.tcp_echo(),
        ports.udp_echo(),
        ports.dns(),
    )
    .ok_or(NativeCoordinatorWriterError::Invariant(
        "canary selector request has colliding responder ports",
    ))?;
    let attempt_objects = environment.attempt_objects();
    let facility_digest = environment.facility_admission().scope().facility_digest();
    NativeCaptureCanaryAttempt::new(
        selector,
        *request.nonce().as_bytes(),
        *attempt_objects.selector().as_bytes(),
        *facility_digest.as_bytes(),
    )
    .ok_or(NativeCoordinatorWriterError::Invariant(
        "native canary attempt has an invalid selector identity or facility digest",
    ))
}

/// Coordinator adapter for the deep native `recover`/`converge` interface.
///
/// The adapter has no dispatcher or state-file dependency. It retains only the committed target
/// and one candidate so coordinator rollback can reactivate the prior immutable Generation, plus
/// at most one request-bound selector session while a canary executes.
pub(crate) struct NativeCoordinatorWriter<C, S>
where
    C: NativeCaptureConvergence,
    C::Identity: NativeCoordinatorGenerationIdentity,
    S: NativeGenerationSource<C::Target, C::Identity>,
{
    convergence: C,
    source: S,
    retained: Vec<RetainedNativeGeneration<C::Target>>,
    committed_generation: Option<GenerationId>,
    converged_identity: Option<C::Identity>,
    active_canary_selector_session: Option<CanaryAttemptRequest>,
    recovery_required: bool,
}

impl<C, S> NativeCoordinatorWriter<C, S>
where
    C: NativeCaptureConvergence,
    C::Identity: NativeCoordinatorGenerationIdentity,
    S: NativeGenerationSource<C::Target, C::Identity>,
{
    pub(crate) fn recover_then_accept_source<F>(
        mut convergence: C,
        source_factory: F,
    ) -> Result<Self, NativeCoordinatorWriterError>
    where
        F: FnOnce() -> S,
    {
        let recovery = convergence.recover().map_err(|source| {
            NativeCoordinatorWriterError::convergence("recover native capture", source)
        })?;
        let clean = match *recovery.state() {
            NativeCaptureConvergedState::CleanAbsent => true,
            NativeCaptureConvergedState::Active(_) => {
                let cleanup = convergence
                    .converge(NativeCaptureDesired::Stopped)
                    .map_err(|source| {
                        NativeCoordinatorWriterError::convergence(
                            "clean recovered native capture before configuration access",
                            source,
                        )
                    })?;
                matches!(cleanup.state(), NativeCaptureConvergedState::CleanAbsent)
            }
        };
        if !clean {
            return Err(NativeCoordinatorWriterError::Invariant(
                "startup native cleanup did not report verified clean absence",
            ));
        }

        Ok(Self {
            convergence,
            source: source_factory(),
            retained: Vec::with_capacity(2),
            committed_generation: None,
            converged_identity: None,
            active_canary_selector_session: None,
            recovery_required: false,
        })
    }

    fn prior_identity(&self) -> Option<C::Identity> {
        let generation = self.committed_generation?;
        self.retained
            .iter()
            .find(|retained| retained.runtime.id() == generation)
            .map(|retained| C::target_identity(&retained.target))
    }

    fn retain_candidate(
        &mut self,
        prepared: PreparedNativeGeneration<C::Target>,
    ) -> Result<PreparedGeneration, NativeCoordinatorWriterError> {
        let PreparedNativeGeneration { runtime, target } = prepared;
        if C::target_identity(&target).coordinator_generation() != Some(runtime.id()) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native capture target Generation does not match its coordinator Generation",
            ));
        }
        if self
            .retained
            .iter()
            .any(|retained| retained.runtime.id() == runtime.id())
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native Generation source repeated a retained Generation identifier",
            ));
        }
        self.retained
            .retain(|retained| self.committed_generation == Some(retained.runtime.id()));
        if self.retained.len() >= 2 {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native coordinator retained more than active plus candidate",
            ));
        }
        let coordinator = runtime.clone();
        self.retained
            .push(RetainedNativeGeneration { runtime, target });
        Ok(coordinator)
    }

    fn retained(
        &self,
        generation: GenerationId,
    ) -> Result<&RetainedNativeGeneration<C::Target>, NativeCoordinatorWriterError> {
        self.retained
            .iter()
            .find(|retained| retained.runtime.id() == generation)
            .ok_or(NativeCoordinatorWriterError::Invariant(
                "coordinator referenced a native Generation that is no longer retained",
            ))
    }

    fn recover_if_required(&mut self) -> Result<(), NativeCoordinatorWriterError> {
        if !self.recovery_required {
            return Ok(());
        }
        let report = self.convergence.recover().map_err(|source| {
            NativeCoordinatorWriterError::convergence(
                "recover native capture after an uncertain convergence",
                source,
            )
        })?;
        self.converged_identity = match *report.state() {
            NativeCaptureConvergedState::Active(identity) => Some(identity),
            NativeCaptureConvergedState::CleanAbsent => None,
        };
        self.active_canary_selector_session = None;
        self.recovery_required = false;
        Ok(())
    }

    fn converge_active(
        &mut self,
        generation: GenerationId,
    ) -> Result<(), NativeCoordinatorWriterError> {
        self.recover_if_required()?;
        let retained = self.retained(generation)?;
        let target = retained.target.clone();
        let expected = C::target_identity(&target);
        let report = match self
            .convergence
            .converge(NativeCaptureDesired::Active(target))
        {
            Ok(report) => report,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "converge native capture active",
                    source,
                ));
            }
        };
        match *report.state() {
            NativeCaptureConvergedState::Active(actual) if actual == expected => {
                self.converged_identity = Some(actual);
                Ok(())
            }
            NativeCaptureConvergedState::Active(_) | NativeCaptureConvergedState::CleanAbsent => {
                self.recovery_required = true;
                Err(NativeCoordinatorWriterError::Invariant(
                    "native active convergence reported a different settled target",
                ))
            }
        }
    }

    fn converge_stopped(&mut self) -> Result<(), NativeCoordinatorWriterError> {
        self.recover_if_required()?;
        if self.active_canary_selector_session.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native capture cannot stop before the active canary selector session retires",
            ));
        }
        let report = match self.convergence.converge(NativeCaptureDesired::Stopped) {
            Ok(report) => report,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "converge native capture stopped",
                    source,
                ));
            }
        };
        if !matches!(report.state(), NativeCaptureConvergedState::CleanAbsent) {
            self.recovery_required = true;
            return Err(NativeCoordinatorWriterError::Invariant(
                "native stop convergence did not report verified clean absence",
            ));
        }
        self.converged_identity = None;
        Ok(())
    }

    fn commit_running(
        &mut self,
        generation: GenerationId,
    ) -> Result<(), NativeCoordinatorWriterError> {
        let expected = C::target_identity(&self.retained(generation)?.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to commit a native Generation that is not exact active",
            ));
        }
        self.committed_generation = Some(generation);
        self.retained
            .retain(|retained| retained.runtime.id() == generation);
        Ok(())
    }

    fn commit_terminal(&mut self) -> Result<(), NativeCoordinatorWriterError> {
        if self.converged_identity.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to commit a terminal state while native capture is active",
            ));
        }
        self.committed_generation = None;
        self.retained.clear();
        Ok(())
    }

    fn commit_failed_activation(&mut self) -> Result<(), NativeCoordinatorWriterError> {
        if self.converged_identity.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to commit failure while native capture is active",
            ));
        }
        if let Some(committed) = self.committed_generation {
            self.retained
                .retain(|retained| retained.runtime.id() == committed);
        } else {
            self.retained.clear();
        }
        Ok(())
    }
}

/// Production-shaped native runtime composition with direct typed ownership dependencies.
///
/// The caller supplies only an already composed opaque platform converger and a lazy Generation
/// source. Recovery reaches verified clean absence before the source factory can observe any
/// configuration. Production daemon selection remains separately fenced in `daemon`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn compose_native_runtime<S, F>(
    convergence: NativeXtablesCaptureConverger,
    source_factory: F,
    maintenance_interval: Duration,
    functional_canary: RuntimeFunctionalCanary,
) -> Result<
    RuntimeCoordinator<NativeCoordinatorWriter<NativeXtablesCaptureConverger, S>, EngineSupervisor>,
    NativeCoordinatorWriterError,
>
where
    S: NativeGenerationSource<NativeXtablesCaptureTarget, NativeCaptureTargetIdentity>,
    F: FnOnce() -> S,
{
    compose_native_runtime_with_engine(
        convergence,
        source_factory,
        maintenance_interval,
        functional_canary,
        EngineSupervisor::new(),
    )
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) fn compose_linux_native_composition_test_runtime<S, F>(
    convergence: NativeXtablesCaptureConverger,
    source_factory: F,
    maintenance_interval: Duration,
    functional_canary: RuntimeFunctionalCanary,
) -> Result<
    RuntimeCoordinator<NativeCoordinatorWriter<NativeXtablesCaptureConverger, S>, EngineSupervisor>,
    NativeCoordinatorWriterError,
>
where
    S: NativeGenerationSource<NativeXtablesCaptureTarget, NativeCaptureTargetIdentity>,
    F: FnOnce() -> S,
{
    compose_native_runtime_with_engine(
        convergence,
        source_factory,
        maintenance_interval,
        functional_canary,
        EngineSupervisor::for_linux_native_composition_test(),
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn compose_native_runtime_with_engine<S, F>(
    convergence: NativeXtablesCaptureConverger,
    source_factory: F,
    maintenance_interval: Duration,
    functional_canary: RuntimeFunctionalCanary,
    engine: EngineSupervisor,
) -> Result<
    RuntimeCoordinator<NativeCoordinatorWriter<NativeXtablesCaptureConverger, S>, EngineSupervisor>,
    NativeCoordinatorWriterError,
>
where
    S: NativeGenerationSource<NativeXtablesCaptureTarget, NativeCaptureTargetIdentity>,
    F: FnOnce() -> S,
{
    let writer = NativeCoordinatorWriter::recover_then_accept_source(convergence, source_factory)?;
    Ok(RuntimeCoordinator::with_dependencies(
        writer,
        engine,
        maintenance_interval,
        functional_canary,
    ))
}

impl<C, S> RuntimeWriter for NativeCoordinatorWriter<C, S>
where
    C: NativeCaptureConvergence,
    C::Identity: NativeCoordinatorGenerationIdentity,
    S: NativeGenerationSource<C::Target, C::Identity>,
{
    type Error = NativeCoordinatorWriterError;

    fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
        self.source.latest_capture_path_decision()
    }

    fn invalidate_latest_capture_path_decision(&mut self) {
        self.source.invalidate_latest_capture_path_decision();
    }

    fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        let generation_id = generation.id();
        if self.committed_generation == Some(generation_id) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to reject the committed native Generation",
            ));
        }
        let retained = self
            .retained
            .iter()
            .find(|retained| retained.runtime.id() == generation_id)
            .ok_or(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to reject a native Generation that is not retained",
            ))?;
        let candidate_identity = C::target_identity(&retained.target);
        if self.converged_identity == Some(candidate_identity) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "coordinator attempted to reject an active native Generation",
            ));
        }

        let prior = self.prior_identity();
        self.source
            .reject_prepared(generation_id, prior)
            .map_err(|source| {
                NativeCoordinatorWriterError::preparation(
                    "reject prepared native Generation source transaction",
                    source,
                )
            })?;
        self.retained
            .retain(|retained| retained.runtime.id() != generation_id);
        Ok(())
    }

    fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
        let prior = self.prior_identity();
        let prepared = self.source.prepare(reason, prior).map_err(|source| {
            NativeCoordinatorWriterError::preparation("prepare native Generation", source)
        })?;
        self.retain_candidate(prepared)
    }

    fn prepare_address_successor(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
    ) -> Result<Option<PreparedGeneration>, Self::Error> {
        let Some(prior) = self.prior_identity() else {
            return Ok(None);
        };
        let prepared = self
            .source
            .prepare_address_successor(inputs, prior)
            .map_err(|source| {
                NativeCoordinatorWriterError::preparation(
                    "prepare address-driven native Generation",
                    source,
                )
            })?;
        prepared
            .map(|prepared| self.retain_candidate(prepared))
            .transpose()
    }

    fn prepare_subscription(
        &mut self,
        config: &ValidatedSubscriptionEngineConfig,
    ) -> Result<Option<PreparedGeneration>, Self::Error> {
        let prior = self.prior_identity();
        let prepared = self
            .source
            .prepare_subscription(config, prior)
            .map_err(|source| {
                NativeCoordinatorWriterError::preparation(
                    "prepare subscription-backed native Generation",
                    source,
                )
            })?;
        prepared
            .map(|prepared| self.retain_candidate(prepared))
            .transpose()
    }

    fn accept_deferred_subscription(&mut self, config: ValidatedSubscriptionEngineConfig) -> bool {
        self.source.accept_deferred_subscription(config)
    }

    fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        self.converge_active(generation.id())
    }

    fn capture_stop(&mut self) -> Result<(), Self::Error> {
        self.converge_stopped()
    }

    fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        let expected = C::target_identity(&self.retained(generation.id())?.target);
        if self.converged_identity == Some(expected) {
            Ok(())
        } else {
            Err(NativeCoordinatorWriterError::Invariant(
                "native structural verification has no matching successful convergence report",
            ))
        }
    }

    fn observe_active_canary_generation(
        &mut self,
        generation: &PreparedGeneration,
    ) -> Result<Option<crate::functional_canary::ActiveCanaryGenerationBinding>, Self::Error> {
        if self.active_canary_selector_session.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary ownership cannot be observed before the active selector session retires",
            ));
        }
        let retained = self.retained(generation.id())?;
        let expected = C::target_identity(&retained.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary observation has no matching successful convergence report",
            ));
        }
        let Some(prepared) = retained.runtime.prepared_canary_generation().cloned() else {
            return Ok(None);
        };
        let facility = retained.runtime.retained_canary_facility().ok_or(
            NativeCoordinatorWriterError::Invariant(
                "native canary Generation has no route-bound retained facility",
            ),
        )?;
        let expected = expected.native_capture_target_identity().ok_or(
            NativeCoordinatorWriterError::Invariant(
                "native canary facts were retained for a non-native capture identity",
            ),
        )?;
        let observation = match self.convergence.observe_active_ownership() {
            Ok(observation) => observation,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "observe active native ownership for functional canary",
                    source,
                ));
            }
        };
        observation
            .map(|observation| prepared.bind_active_ownership(expected, &observation, facility))
            .transpose()
            .map_err(|source| {
                NativeCoordinatorWriterError::convergence(
                    "bind active native ownership to functional canary Generation",
                    source,
                )
            })
    }

    fn reserve_canary_selector_session(
        &mut self,
        generation: &PreparedGeneration,
        request: &CanaryAttemptRequest,
    ) -> Result<Option<CanarySelectorSession>, Self::Error> {
        if self.active_canary_selector_session.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector session overlaps an active attempt",
            ));
        }
        let retained = self.retained(generation.id())?;
        let expected = C::target_identity(&retained.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector session has no matching successful convergence report",
            ));
        }
        if !retained.runtime.matches_canary_selector_request(request) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector session does not match the retained Generation and facility",
            ));
        }
        let target = retained.target.clone();
        let attempt = native_canary_attempt(request)?;
        let populated = match self.convergence.populate_canary_selector(&target, attempt) {
            Ok(populated) => populated,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "populate native functional-canary selector",
                    source,
                ));
            }
        };
        if !populated {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native capture converger has no canary selector population authority",
            ));
        }

        self.active_canary_selector_session = Some(request.clone());
        Ok(Some(CanarySelectorSession::reserved_for(request)))
    }

    fn retire_canary_selector_session(
        &mut self,
        generation: &PreparedGeneration,
        session: CanarySelectorSession,
    ) -> Result<Option<RetiredCanarySelectorSession>, Self::Error> {
        let active = self.active_canary_selector_session.as_ref().ok_or(
            NativeCoordinatorWriterError::Invariant(
                "native canary selector session retirement has no active reservation",
            ),
        )?;
        if session.request().pre_binding().engine().generation() != generation.id()
            || active != session.request()
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector session retirement substituted the active request",
            ));
        }
        let retained = self.retained(generation.id())?;
        let expected = C::target_identity(&retained.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector retirement has no matching successful convergence report",
            ));
        }
        if !retained
            .runtime
            .matches_canary_selector_request(session.request())
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector retirement does not match the retained Generation and facility",
            ));
        }
        let target = retained.target.clone();
        let attempt = native_canary_attempt(session.request())?;
        let retired = match self.convergence.retire_canary_selector(&target, attempt) {
            Ok(retired) => retired,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "retire native functional-canary selector",
                    source,
                ));
            }
        };
        if !retired {
            self.recovery_required = true;
            return Err(NativeCoordinatorWriterError::Invariant(
                "native capture converger did not retire the populated canary selector",
            ));
        }

        // A positive converger result already includes exact selector-absence readback.
        let retired_at = Instant::now();
        let absent_observed_at = Instant::now();
        self.active_canary_selector_session = None;
        Ok(Some(session.retire(retired_at, absent_observed_at)))
    }

    fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
        match phase {
            PublishedRuntimeState::Running { generation } => self.commit_running(generation),
            PublishedRuntimeState::Stopped => self.commit_terminal(),
            PublishedRuntimeState::Failed => self.commit_failed_activation(),
        }?;
        let target = match phase {
            PublishedRuntimeState::Running { generation } => {
                Some(C::target_identity(&self.retained(generation)?.target))
            }
            PublishedRuntimeState::Failed => self.prior_identity(),
            PublishedRuntimeState::Stopped => None,
        };
        self.source.settle(phase, target).map_err(|source| {
            NativeCoordinatorWriterError::preparation(
                "settle native Generation source transaction",
                source,
            )
        })
    }

    fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
        Err(NativeCoordinatorWriterError::Invariant(
            "native address resync must use coordinator-owned synchronous reconciliation",
        ))
    }

    fn address_resync_strategy(&self) -> AddressResyncStrategy {
        AddressResyncStrategy::CoordinatorSynchronous
    }
}

#[derive(Debug)]
pub(crate) enum NativeCoordinatorWriterError {
    Convergence {
        operation: &'static str,
        source: Box<dyn Error + Send + Sync>,
    },
    Preparation {
        operation: &'static str,
        source: Box<dyn Error + Send + Sync>,
    },
    Invariant(&'static str),
}

impl NativeCoordinatorWriterError {
    fn convergence(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self::Convergence {
            operation,
            source: Box::new(source),
        }
    }

    fn preparation(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self::Preparation {
            operation,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for NativeCoordinatorWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Convergence { operation, source } | Self::Preparation { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
            Self::Invariant(message) => formatter.write_str(message),
        }
    }
}

impl Error for NativeCoordinatorWriterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Convergence { source, .. } | Self::Preparation { source, .. } => {
                Some(source.as_ref())
            }
            Self::Invariant(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::net::IpAddr;
    use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use flux_core::{
        InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex, NetworkInventoryTracker,
        OwnershipJournalRevision, RuntimeDispatcher, RuntimeIntent,
    };
    use flux_platform::{
        NativeCaptureConvergenceReport, ReadinessEvidence, SingBoxLaunchSpec, SingBoxPrivilege,
        SingBoxReadiness,
    };

    use super::*;
    use crate::engine_supervisor::{
        EngineCanaryReportHandoffError, EngineChildAuthority, EngineChildAuthorityError,
    };
    use crate::functional_canary::tests::request_with_engine_identity;
    use crate::functional_canary::{
        CanaryAddressFamilies, CanaryAttemptRequest, CanaryNonce, FUNCTIONAL_CANARY_NONCE_BYTES,
        InstalledSupervisedDeliveryReportProducer, PreparedCanaryGenerationBinding,
        SupervisedDeliveryReportEngineHandoff,
    };
    use crate::generation_engine_config::{
        AddressReconciler, EngineSupervisedDeliveryReportContract,
        qualified_xtables_capture_path_evidence, test_xtables_capture_path_selection,
    };
    use crate::runtime_coordinator::{EngineRuntime, RuntimeCoordinator, RuntimeFunctionalCanary};
    use crate::{
        CaptureObservation, DesiredEngine, EngineReport, EngineSnapshot, EngineSupervisorError,
        OwnedEngineIdentity, RestartPolicy, RuntimeCaptureState, RuntimeEngineState, RuntimePhase,
        RuntimeVerificationState,
    };

    const PACKAGED_DESIRED_STATE: &str = include_str!("../../../conf/flux.toml");

    impl NativeCoordinatorGenerationIdentity for u64 {
        fn coordinator_generation(self) -> Option<GenerationId> {
            u32::try_from(self).ok().and_then(GenerationId::new)
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct ScriptedTarget(u64);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Recovered(Option<u64>),
        ConvergedActive(u64),
        ConvergedStopped,
        SourceAccepted,
        PreparedIntent {
            reason: Reason,
            generation: u32,
            prior: Option<u64>,
        },
        PreparedAddress {
            generation: u32,
            prior: u64,
        },
        SelectorPopulated {
            target: u64,
            attempt: NativeCaptureCanaryAttempt,
        },
        SelectorRetired {
            target: u64,
            attempt: NativeCaptureCanaryAttempt,
        },
        EngineRunning(CaptureObservation),
        EngineStopped(CaptureObservation),
    }

    struct ScriptedConvergence {
        events: Arc<Mutex<Vec<Event>>>,
        active: Option<u64>,
        fail_active_once: Option<u64>,
        selector: Option<(u64, NativeCaptureCanaryAttempt)>,
        fail_recover_once: bool,
        fail_populate_once: bool,
        fail_retire_once: bool,
        unsupported_populate_once: bool,
        unsupported_retire_once: bool,
        selector_retired_observed_at: Option<Instant>,
    }

    impl NativeCaptureConvergence for ScriptedConvergence {
        type Target = ScriptedTarget;
        type Identity = u64;
        type Error = io::Error;

        fn target_identity(target: &Self::Target) -> Self::Identity {
            target.0
        }

        fn recover(
            &mut self,
        ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
            if self.fail_recover_once {
                self.fail_recover_once = false;
                return Err(io::Error::other(
                    "injected native selector recovery failure",
                ));
            }
            if self.selector.take().is_some() {
                self.active = None;
            }
            self.events
                .lock()
                .expect("native events lock")
                .push(Event::Recovered(self.active));
            Ok(match self.active {
                Some(identity) => NativeCaptureConvergenceReport::new(
                    NativeCaptureConvergedState::Active(identity),
                    false,
                ),
                None => NativeCaptureConvergenceReport::new(
                    NativeCaptureConvergedState::CleanAbsent,
                    false,
                ),
            })
        }

        fn populate_canary_selector(
            &mut self,
            target: &Self::Target,
            attempt: NativeCaptureCanaryAttempt,
        ) -> Result<bool, Self::Error> {
            if self.unsupported_populate_once {
                self.unsupported_populate_once = false;
                return Ok(false);
            }
            if self.active != Some(target.0) || self.selector.is_some() {
                return Err(io::Error::other(
                    "scripted selector population found a different active state",
                ));
            }
            self.selector = Some((target.0, attempt));
            self.events
                .lock()
                .expect("native events lock")
                .push(Event::SelectorPopulated {
                    target: target.0,
                    attempt,
                });
            if self.fail_populate_once {
                self.fail_populate_once = false;
                return Err(io::Error::other(
                    "injected uncertain native selector population failure",
                ));
            }
            Ok(true)
        }

        fn retire_canary_selector(
            &mut self,
            target: &Self::Target,
            attempt: NativeCaptureCanaryAttempt,
        ) -> Result<bool, Self::Error> {
            if self.unsupported_retire_once {
                self.unsupported_retire_once = false;
                return Ok(false);
            }
            if self.active != Some(target.0) || self.selector != Some((target.0, attempt)) {
                return Err(io::Error::other(
                    "scripted selector retirement found a different active state",
                ));
            }
            if self.fail_retire_once {
                self.fail_retire_once = false;
                return Err(io::Error::other(
                    "injected uncertain native selector retirement failure",
                ));
            }
            self.selector = None;
            self.events
                .lock()
                .expect("native events lock")
                .push(Event::SelectorRetired {
                    target: target.0,
                    attempt,
                });
            self.selector_retired_observed_at = Some(Instant::now());
            Ok(true)
        }

        fn converge(
            &mut self,
            desired: NativeCaptureDesired<Self::Target>,
        ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
            match desired {
                NativeCaptureDesired::Active(target) => {
                    self.events
                        .lock()
                        .expect("native events lock")
                        .push(Event::ConvergedActive(target.0));
                    if self.fail_active_once == Some(target.0) {
                        self.fail_active_once = None;
                        return Err(io::Error::other(
                            "injected native candidate convergence failure",
                        ));
                    }
                    let changed = self.active != Some(target.0);
                    self.active = Some(target.0);
                    self.selector = None;
                    Ok(NativeCaptureConvergenceReport::new(
                        NativeCaptureConvergedState::Active(target.0),
                        changed,
                    ))
                }
                NativeCaptureDesired::Stopped => {
                    self.events
                        .lock()
                        .expect("native events lock")
                        .push(Event::ConvergedStopped);
                    let changed = self.active.take().is_some();
                    self.selector = None;
                    Ok(NativeCaptureConvergenceReport::new(
                        NativeCaptureConvergedState::CleanAbsent,
                        changed,
                    ))
                }
            }
        }
    }

    struct ScriptedGenerationSource {
        events: Arc<Mutex<Vec<Event>>>,
        intent: VecDeque<PreparedNativeGeneration<ScriptedTarget>>,
        address: VecDeque<PreparedNativeGeneration<ScriptedTarget>>,
    }

    impl NativeGenerationSource<ScriptedTarget, u64> for ScriptedGenerationSource {
        type Error = io::Error;

        fn prepare(
            &mut self,
            reason: Reason,
            prior: Option<u64>,
        ) -> Result<PreparedNativeGeneration<ScriptedTarget>, Self::Error> {
            let prepared = self
                .intent
                .pop_front()
                .ok_or_else(|| io::Error::other("no scripted native Generation remains"))?;
            self.events
                .lock()
                .expect("native events lock")
                .push(Event::PreparedIntent {
                    reason,
                    generation: prepared.runtime.id().get(),
                    prior,
                });
            Ok(prepared)
        }

        fn prepare_address_successor(
            &mut self,
            _inputs: &AddressReconciledGenerationInputs,
            prior: u64,
        ) -> Result<Option<PreparedNativeGeneration<ScriptedTarget>>, Self::Error> {
            let Some(prepared) = self.address.pop_front() else {
                return Ok(None);
            };
            self.events
                .lock()
                .expect("native events lock")
                .push(Event::PreparedAddress {
                    generation: prepared.runtime.id().get(),
                    prior,
                });
            Ok(Some(prepared))
        }
    }

    struct ScriptedEngine {
        events: Arc<Mutex<Vec<Event>>>,
        snapshot: Arc<Mutex<Arc<EngineSnapshot>>>,
    }

    impl EngineRuntime for ScriptedEngine {
        fn reconcile(
            &mut self,
            desired: DesiredEngine<'_>,
            capture: CaptureObservation,
        ) -> Result<EngineReport, EngineSupervisorError> {
            match desired {
                DesiredEngine::Running(_) => {
                    self.events
                        .lock()
                        .expect("native events lock")
                        .push(Event::EngineRunning(capture));
                    let readiness = ReadinessEvidence::Listener {
                        port: NonZeroU16::new(1536).expect("nonzero test port"),
                        table: PathBuf::from("/proc/1/net/tcp"),
                    };
                    *self.snapshot.lock().expect("engine snapshot lock") =
                        Arc::new(EngineSnapshot::ready_for_test(
                            NonZeroU64::new(1).expect("nonzero engine revision"),
                            OwnedEngineIdentity::new(
                                NonZeroU32::new(1).expect("nonzero engine PID"),
                                NonZeroU64::new(1).expect("nonzero engine start ticks"),
                            ),
                            readiness.clone(),
                        ));
                    Ok(EngineReport::Started {
                        revision: 1,
                        owned_resource_readiness: readiness,
                    })
                }
                DesiredEngine::Stopped => {
                    self.events
                        .lock()
                        .expect("native events lock")
                        .push(Event::EngineStopped(capture));
                    *self.snapshot.lock().expect("engine snapshot lock") =
                        Arc::new(EngineSnapshot::default());
                    Ok(EngineReport::Stopped { revision: 1 })
                }
            }
        }

        fn snapshot(&self) -> Arc<EngineSnapshot> {
            Arc::clone(&self.snapshot.lock().expect("engine snapshot lock"))
        }

        fn open_canary_child_authority(
            &self,
            _expected: OwnedEngineIdentity,
            _expected_snapshot_revision: NonZeroU64,
            _expected_spec: &EngineSpec,
        ) -> Result<EngineChildAuthority, EngineChildAuthorityError> {
            Err(EngineChildAuthorityError::state_changed(
                "structural native test engine has no canary authority",
            ))
        }

        fn install_canary_report_handoff(
            &self,
            _expected_request: &CanaryAttemptRequest,
            _expected_spec: &EngineSpec,
            _handoff: SupervisedDeliveryReportEngineHandoff,
        ) -> Result<InstalledSupervisedDeliveryReportProducer, EngineCanaryReportHandoffError>
        {
            Err(EngineCanaryReportHandoffError::RetainedChild {
                source: EngineChildAuthorityError::state_changed(
                    "structural native test engine has no report handoff",
                ),
            })
        }
    }

    struct EngineFixture {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl EngineFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create native engine fixture");
            let binary = directory.path().join("sing-box");
            let config = directory.path().join("config.json");
            fs::write(&binary, b"sing-box").expect("write native test engine");
            fs::write(&config, b"{}").expect("write native test engine config");
            let restart = RestartPolicy::new(
                3,
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::from_secs(10),
            )
            .expect("valid native test restart policy");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary,
                    config,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    privilege: SingBoxPrivilege::Inherit,
                    readiness: SingBoxReadiness::Listener {
                        port: NonZeroU16::new(1536).expect("nonzero test port"),
                    },
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                restart,
            )
            .expect("inspect native test engine");
            Self {
                spec,
                _directory: directory,
            }
        }
    }

    fn generation(id: u32, fixture: &EngineFixture) -> PreparedNativeGeneration<ScriptedTarget> {
        PreparedNativeGeneration::new(
            PreparedGeneration::new(
                GenerationId::new(id).expect("nonzero native Generation"),
                fixture.spec.clone(),
                test_engine_profile_revision(),
                FunctionalCanaryGateMode::StructuralVerificationOnly,
                None,
                test_xtables_capture_path_selection(),
                qualified_xtables_capture_path_evidence().valid_until(),
            ),
            ScriptedTarget(u64::from(id)),
        )
    }

    fn required_canary_generation(
        id: u32,
        fixture: &EngineFixture,
        request: &CanaryAttemptRequest,
    ) -> PreparedNativeGeneration<ScriptedTarget> {
        let generation = GenerationId::new(id).expect("nonzero native Generation");
        let authority = request.pre_binding().environment().authority();
        let network = authority.network();
        let ownership = authority.ownership();
        let prepared = PreparedCanaryGenerationBinding::new(
            generation,
            authority.boot_identity().clone(),
            authority.capability_profile_revision(),
            network.daemon_network_namespace(),
            network.network_epoch(),
            network.network_inventory_snapshot_id(),
            *authority.capture_program_digest().as_bytes(),
            ownership.journal_identity(),
            OwnershipJournalRevision::INITIAL,
        )
        .expect("prepared canary Generation binding");
        PreparedNativeGeneration::new(
            PreparedGeneration::new(
                generation,
                fixture.spec.clone(),
                request.pre_binding().engine().engine_profile_revision(),
                FunctionalCanaryGateMode::RequiredUnqualified,
                Some(EngineSupervisedDeliveryReportContract::schema_v1_fixture()),
                test_xtables_capture_path_selection(),
                qualified_xtables_capture_path_evidence().valid_until(),
            )
            .with_prepared_canary_generation(Some(prepared))
            .with_retained_canary_facility(request.pre_binding().environment().facility()),
            ScriptedTarget(u64::from(id)),
        )
    }

    fn test_engine_profile_revision() -> EngineCapabilityProfileRevision {
        EngineCapabilityProfileRevision::from_fixture_bytes([0x31; 32])
    }

    fn selector_request(fixture: &EngineFixture, nonce_byte: u8) -> CanaryAttemptRequest {
        selector_request_with_families(fixture, nonce_byte, CanaryAddressFamilies::Ipv4Only)
    }

    fn selector_request_with_families(
        fixture: &EngineFixture,
        nonce_byte: u8,
        families: CanaryAddressFamilies,
    ) -> CanaryAttemptRequest {
        request_with_engine_identity(
            &fixture.spec,
            families,
            Instant::now(),
            CanaryNonce::from_bytes([nonce_byte; FUNCTIONAL_CANARY_NONCE_BYTES]),
            GenerationId::new(17).expect("selector-session Generation"),
            NonZeroU32::new(4242).expect("engine PID"),
            NonZeroU64::new(98_765).expect("engine start ticks"),
            NonZeroU64::new(23).expect("engine snapshot revision"),
        )
    }

    fn writer(
        events: &Arc<Mutex<Vec<Event>>>,
        active: Option<u64>,
        fail_active_once: Option<u64>,
        intent: impl IntoIterator<Item = PreparedNativeGeneration<ScriptedTarget>>,
        address: impl IntoIterator<Item = PreparedNativeGeneration<ScriptedTarget>>,
    ) -> NativeCoordinatorWriter<ScriptedConvergence, ScriptedGenerationSource> {
        let convergence = ScriptedConvergence {
            events: Arc::clone(events),
            active,
            fail_active_once,
            selector: None,
            fail_recover_once: false,
            fail_populate_once: false,
            fail_retire_once: false,
            unsupported_populate_once: false,
            unsupported_retire_once: false,
            selector_retired_observed_at: None,
        };
        let source = ScriptedGenerationSource {
            events: Arc::clone(events),
            intent: intent.into_iter().collect(),
            address: address.into_iter().collect(),
        };
        let accepted = Arc::clone(events);
        NativeCoordinatorWriter::recover_then_accept_source(convergence, move || {
            accepted
                .lock()
                .expect("native events lock")
                .push(Event::SourceAccepted);
            source
        })
        .expect("native writer startup recovery")
    }

    fn coordinator(
        writer: NativeCoordinatorWriter<ScriptedConvergence, ScriptedGenerationSource>,
        events: &Arc<Mutex<Vec<Event>>>,
    ) -> RuntimeCoordinator<
        NativeCoordinatorWriter<ScriptedConvergence, ScriptedGenerationSource>,
        ScriptedEngine,
    > {
        RuntimeCoordinator::with_dependencies(
            writer,
            ScriptedEngine {
                events: Arc::clone(events),
                snapshot: Arc::new(Mutex::new(Arc::new(EngineSnapshot::default()))),
            },
            Duration::from_millis(100),
            RuntimeFunctionalCanary::StructuralVerificationOnly,
        )
    }

    #[test]
    fn recovery_and_stale_cleanup_precede_generation_source_acceptance() {
        let events = Arc::new(Mutex::new(Vec::new()));

        let _writer = writer(&events, Some(99), None, [], []);

        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::Recovered(Some(99)),
                Event::ConvergedStopped,
                Event::SourceAccepted,
            ]
        );
    }

    #[test]
    fn native_selector_session_rejects_overlap_missing_retirement_and_substitution() {
        let fixture = EngineFixture::new();
        let request = selector_request(&fixture, 71);
        let alternate = selector_request(&fixture, 72);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");

        let missing = RuntimeWriter::retire_canary_selector_session(
            &mut writer,
            &generation,
            CanarySelectorSession::reserved_for(&request),
        )
        .expect_err("retirement without a reservation must fail");
        assert_eq!(
            missing.to_string(),
            "native canary selector session retirement has no active reservation"
        );

        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");
        let populated = writer
            .convergence
            .selector
            .expect("reservation populates one exact platform selector");
        let environment = request.pre_binding().environment();
        let facility = environment.facility();
        let ports = facility.ports();
        assert_eq!(populated.0, 17);
        let selector = populated.1.selector();
        assert_eq!(selector.probe_uid(), environment.probe_uid());
        assert_eq!(selector.ipv4_peer(), facility.ipv4().peer());
        assert_eq!(selector.ipv6_peer(), None);
        assert_eq!(selector.tcp_echo_port(), ports.tcp_echo());
        assert_eq!(selector.udp_echo_port(), ports.udp_echo());
        assert_eq!(selector.dns_port(), ports.dns());
        assert_eq!(populated.1.nonce(), request.nonce().as_bytes());
        let overlap =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &alternate)
                .expect_err("overlapping selector sessions must fail");
        assert_eq!(
            overlap.to_string(),
            "native canary selector session overlaps an active attempt"
        );

        let substituted = RuntimeWriter::retire_canary_selector_session(
            &mut writer,
            &generation,
            CanarySelectorSession::reserved_for(&alternate),
        )
        .expect_err("a different request cannot retire the active session");
        assert_eq!(
            substituted.to_string(),
            "native canary selector session retirement substituted the active request"
        );
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request),
            "a substituted retirement must leave the exact reservation active"
        );

        let retired =
            RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
                .expect("retire exact selector session")
                .expect("native writer returns exact retirement");
        assert!(retired.matches_request(&request));
        let selector_retirement = retired.selector_retirement();
        assert_eq!(
            selector_retirement.object(),
            request
                .pre_binding()
                .environment()
                .attempt_objects()
                .selector()
        );
        assert!(
            selector_retirement.retired_at()
                >= writer
                    .convergence
                    .selector_retired_observed_at
                    .expect("platform retirement/readback observation")
        );
        assert!(selector_retirement.absent_observed_at() >= selector_retirement.retired_at());
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
    }

    #[test]
    fn native_selector_session_maps_the_exact_dual_stack_request() {
        let fixture = EngineFixture::new();
        let request =
            selector_request_with_families(&fixture, 74, CanaryAddressFamilies::Ipv4AndIpv6);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare dual-stack required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate dual-stack required native Generation");

        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("populate dual-stack selector session")
                .expect("native writer returns dual-stack selector ownership");

        let attempt = writer
            .convergence
            .selector
            .expect("dual-stack reservation populates one selector")
            .1;
        let selector = attempt.selector();
        let environment = request.pre_binding().environment();
        let facility = environment.facility();
        assert_eq!(selector.probe_uid(), environment.probe_uid());
        assert_eq!(selector.ipv4_peer(), facility.ipv4().peer());
        assert_eq!(
            selector.ipv6_peer(),
            Some(facility.ipv6().expect("dual-stack facility").peer())
        );
        let ports = facility.ports();
        assert_eq!(selector.tcp_echo_port(), ports.tcp_echo());
        assert_eq!(selector.udp_echo_port(), ports.udp_echo());
        assert_eq!(selector.dns_port(), ports.dns());
        assert_eq!(attempt.nonce(), request.nonce().as_bytes());
        assert_eq!(
            attempt.selector_identity(),
            environment.attempt_objects().selector().as_bytes()
        );
        assert_eq!(
            attempt.facility_digest(),
            environment
                .facility_admission()
                .scope()
                .facility_digest()
                .as_bytes()
        );

        RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
            .expect("retire dual-stack selector session")
            .expect("native writer returns dual-stack retirement proof");
        assert!(writer.convergence.selector.is_none());
    }

    #[test]
    fn uncertain_selector_population_recovers_before_capture_stop() {
        let fixture = EngineFixture::new();
        let request = selector_request(&fixture, 75);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        writer.convergence.fail_populate_once = true;

        let error =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("uncertain selector population must not return session ownership");

        assert_eq!(
            error.to_string(),
            "populate native functional-canary selector: injected uncertain native selector population failure"
        );
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_some());
        assert!(writer.recovery_required);
        events.lock().expect("native events lock").clear();

        RuntimeWriter::capture_stop(&mut writer)
            .expect("capture stop must recover uncertain population before detaching");

        assert_eq!(
            *events.lock().expect("native events lock"),
            [Event::Recovered(None), Event::ConvergedStopped]
        );
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
        assert!(!writer.recovery_required);
        assert_eq!(writer.converged_identity, None);
    }

    #[test]
    fn uncertain_selector_retirement_recovers_before_the_session_guard() {
        let fixture = EngineFixture::new();
        let request = selector_request(&fixture, 76);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("populate exact selector session")
                .expect("native writer returns selector ownership");
        writer.convergence.fail_retire_once = true;

        let error =
            RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
                .expect_err("uncertain selector retirement must not return a retirement proof");

        assert_eq!(
            error.to_string(),
            "retire native functional-canary selector: injected uncertain native selector retirement failure"
        );
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        assert!(writer.convergence.selector.is_some());
        assert!(writer.recovery_required);
        writer.convergence.fail_recover_once = true;
        events.lock().expect("native events lock").clear();

        let recovery = RuntimeWriter::capture_stop(&mut writer)
            .expect_err("failed recovery must retain the uncertain selector session");
        assert_eq!(
            recovery.to_string(),
            "recover native capture after an uncertain convergence: injected native selector recovery failure"
        );
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        assert!(writer.convergence.selector.is_some());
        assert!(writer.recovery_required);
        assert!(events.lock().expect("native events lock").is_empty());

        RuntimeWriter::capture_stop(&mut writer)
            .expect("stop recovery must run before rejecting the retained uncertain session");

        assert_eq!(
            *events.lock().expect("native events lock"),
            [Event::Recovered(None), Event::ConvergedStopped]
        );
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
        assert!(!writer.recovery_required);
        assert_eq!(writer.converged_identity, None);
    }

    #[test]
    fn native_selector_session_requires_positive_platform_receipts() {
        let fixture = EngineFixture::new();
        let request = selector_request(&fixture, 77);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        writer.convergence.unsupported_populate_once = true;

        let unsupported =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("unsupported population must not become selector ownership");

        assert_eq!(
            unsupported.to_string(),
            "native capture converger has no canary selector population authority"
        );
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
        assert!(!writer.recovery_required);

        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("retry exact selector population")
                .expect("native writer returns selector ownership");
        writer.convergence.unsupported_retire_once = true;
        let unsupported =
            RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
                .expect_err("unsupported retirement must not become a retirement proof");

        assert_eq!(
            unsupported.to_string(),
            "native capture converger did not retire the populated canary selector"
        );
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        assert!(writer.convergence.selector.is_some());
        assert!(writer.recovery_required);
        RuntimeWriter::capture_stop(&mut writer)
            .expect("unsupported retirement must recover before capture stop");
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
    }

    #[test]
    fn native_selector_session_must_retire_before_ownership_observation_or_capture_stop() {
        let fixture = EngineFixture::new();
        let request = selector_request(&fixture, 73);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        );
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");

        let observation = RuntimeWriter::observe_active_canary_generation(&mut writer, &generation)
            .expect_err("post-attempt observation must wait for exact retirement");
        assert_eq!(
            observation.to_string(),
            "native canary ownership cannot be observed before the active selector session retires"
        );
        let stop = RuntimeWriter::capture_stop(&mut writer)
            .expect_err("capture cannot detach around an active selector session");
        assert_eq!(
            stop.to_string(),
            "native capture cannot stop before the active canary selector session retires"
        );

        RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
            .expect("retire exact selector session")
            .expect("native writer returns exact retirement");
        RuntimeWriter::capture_stop(&mut writer)
            .expect("capture can stop after exact selector-session retirement");
    }

    #[test]
    fn mismatched_capture_and_coordinator_generations_are_rejected() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mismatched = PreparedNativeGeneration::new(
            PreparedGeneration::new(
                GenerationId::INITIAL,
                fixture.spec.clone(),
                test_engine_profile_revision(),
                FunctionalCanaryGateMode::StructuralVerificationOnly,
                None,
                test_xtables_capture_path_selection(),
                qualified_xtables_capture_path_evidence().valid_until(),
            ),
            ScriptedTarget(2),
        );
        let mut writer = writer(&events, None, None, [mismatched], []);

        let error = match writer.prepare(Reason::Boot) {
            Ok(_) => panic!("mismatched native Generation must be rejected"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "native capture target Generation does not match its coordinator Generation"
        );
    }

    #[test]
    fn coordinator_starts_engine_before_native_capture_without_out_of_band_events() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(&events, None, None, [generation(1, &fixture)], []);
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events);

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("native start converges");

        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::PreparedIntent {
                    reason: Reason::Boot,
                    generation: 1,
                    prior: None,
                },
                Event::EngineRunning(CaptureObservation::Detached),
                Event::ConvergedActive(1),
            ],
            "the native path exposes no out-of-band publication operation"
        );
        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Published);
        assert_eq!(snapshot.engine, RuntimeEngineState::Ready);
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::StructuralOnly
        );
        assert_eq!(snapshot.generation(), GenerationId::new(1));
    }

    #[test]
    fn rejected_native_candidate_releases_the_retained_slot_for_the_same_generation_retry() {
        let rejected = EngineFixture::new();
        let retry = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [generation(1, &rejected), generation(1, &retry)],
            [],
        );

        let candidate =
            RuntimeWriter::prepare(&mut writer, Reason::Boot).expect("prepare native candidate");
        assert_eq!(writer.retained.len(), 1);
        RuntimeWriter::reject_prepared(&mut writer, &candidate)
            .expect("reject native candidate transaction");
        assert!(writer.retained.is_empty());

        let retried = RuntimeWriter::prepare(&mut writer, Reason::DaemonRecovery)
            .expect("same Generation identifier is reusable after rejection");
        assert_eq!(retried.id(), GenerationId::INITIAL);
        RuntimeWriter::reject_prepared(&mut writer, &retried).expect("clean retry fixture");
        assert!(writer.retained.is_empty());
    }

    #[test]
    fn native_candidate_rejection_requires_the_exact_retained_generation() {
        let retained = EngineFixture::new();
        let mismatched = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(&events, None, None, [generation(1, &retained)], []);
        let candidate = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare retained native candidate");
        let other = PreparedGeneration::new(
            GenerationId::new(2).expect("nonzero mismatched Generation"),
            mismatched.spec,
            test_engine_profile_revision(),
            FunctionalCanaryGateMode::StructuralVerificationOnly,
            None,
            test_xtables_capture_path_selection(),
            qualified_xtables_capture_path_evidence().valid_until(),
        );

        let error = RuntimeWriter::reject_prepared(&mut writer, &other)
            .expect_err("mismatched Generation cannot reject the retained candidate");

        assert_eq!(
            error.to_string(),
            "coordinator attempted to reject a native Generation that is not retained"
        );
        assert_eq!(writer.retained.len(), 1);
        assert_eq!(writer.retained[0].runtime.id(), candidate.id());
        RuntimeWriter::reject_prepared(&mut writer, &candidate)
            .expect("exact retained candidate remains rejectable");
    }

    #[test]
    fn native_candidate_rejection_cannot_discard_the_committed_generation() {
        let committed = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(&events, None, None, [generation(1, &committed)], []);
        let generation =
            RuntimeWriter::prepare(&mut writer, Reason::Boot).expect("prepare native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation).expect("activate native Generation");
        RuntimeWriter::publish(
            &mut writer,
            PublishedRuntimeState::Running {
                generation: generation.id(),
            },
        )
        .expect("commit native Generation");

        let error = RuntimeWriter::reject_prepared(&mut writer, &generation)
            .expect_err("committed Generation cannot be rejected as a candidate");

        assert_eq!(
            error.to_string(),
            "coordinator attempted to reject the committed native Generation"
        );
        assert_eq!(writer.committed_generation, Some(generation.id()));
        assert_eq!(writer.retained.len(), 1);
        RuntimeWriter::capture_stop(&mut writer).expect("stop committed native Generation");
        RuntimeWriter::publish(&mut writer, PublishedRuntimeState::Stopped)
            .expect("clean committed writer fixture");
    }

    #[test]
    fn failed_native_candidate_returns_to_the_previous_generation() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(
            &events,
            None,
            Some(2),
            [generation(1, &active), generation(2, &candidate)],
            [],
        );
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        events.lock().expect("native events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("injected native candidate failure is reported");

        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::PreparedIntent {
                    reason: Reason::UserControl,
                    generation: 2,
                    prior: Some(1),
                },
                Event::ConvergedStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::ConvergedActive(2),
                Event::Recovered(None),
                Event::ConvergedStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::ConvergedActive(1),
            ]
        );
        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Degraded);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Published);
        assert_eq!(snapshot.engine, RuntimeEngineState::Ready);
        assert_eq!(snapshot.generation(), GenerationId::new(1));
        assert!(snapshot.last_error.is_some());

        events.lock().expect("native events lock").clear();
        coordinator.maintain();
        assert_eq!(
            *events.lock().expect("native events lock"),
            [Event::EngineRunning(CaptureObservation::Published)]
        );
        let settled = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(settled.phase, RuntimePhase::Running);
        assert_eq!(settled.generation(), GenerationId::new(1));
        assert_eq!(settled.last_error, None);
    }

    #[test]
    fn reconciled_addresses_enter_the_same_prepared_reload_path() {
        let active = EngineFixture::new();
        let successor = EngineFixture::new();
        let (_configuration, desired_state_path) = desired_state_fixture();
        let (inventory_source, reconciler) = AddressReconciler::replay(&desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(
            &events,
            None,
            None,
            [generation(1, &active)],
            [generation(2, &successor)],
        );
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events).with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        events.lock().expect("native events lock").clear();
        inventory_source.publish(Some(complete_inventory()));

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::PreparedAddress {
                    generation: 2,
                    prior: 1,
                },
                Event::ConvergedStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::ConvergedActive(2),
            ]
        );
        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.generation(), GenerationId::new(2));
    }

    #[test]
    fn explicit_native_resync_defers_while_complete_inventory_is_unavailable() {
        let active = EngineFixture::new();
        let (_configuration, desired_state_path) = desired_state_fixture();
        let (_inventory_source, reconciler) = AddressReconciler::replay(&desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(&events, None, None, [generation(1, &active)], []);
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events).with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        events.lock().expect("native events lock").clear();

        let completion = coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("missing inventory is a deferred resync");

        assert_eq!(
            completion,
            flux_core::DispatcherCompletion::AddressResync(
                AddressResyncDisposition::AcceptedDeferred
            )
        );
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[test]
    fn explicit_native_resync_reports_complete_no_change_only_after_fresh_compilation() {
        let active = EngineFixture::new();
        let (_configuration, desired_state_path) = desired_state_fixture();
        let (inventory_source, reconciler) = AddressReconciler::replay(&desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(&events, None, None, [generation(1, &active)], []);
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events).with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        events.lock().expect("native events lock").clear();
        inventory_source.publish(Some(complete_inventory()));

        let completion = coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("fresh no-change resync");

        assert_eq!(
            completion,
            flux_core::DispatcherCompletion::AddressResync(
                AddressResyncDisposition::CompleteNoChange
            )
        );
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[test]
    fn explicit_native_resync_reports_success_only_after_successor_convergence() {
        let active = EngineFixture::new();
        let successor = EngineFixture::new();
        let (_configuration, desired_state_path) = desired_state_fixture();
        let (inventory_source, reconciler) = AddressReconciler::replay(&desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(
            &events,
            None,
            None,
            [generation(1, &active)],
            [generation(2, &successor)],
        );
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events).with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        events.lock().expect("native events lock").clear();
        inventory_source.publish(Some(complete_inventory()));

        let completion = coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("address successor converges synchronously");

        assert_eq!(
            completion,
            flux_core::DispatcherCompletion::AddressResync(
                AddressResyncDisposition::SuccessorConverged
            )
        );
        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::PreparedAddress {
                    generation: 2,
                    prior: 1,
                },
                Event::ConvergedStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::ConvergedActive(2),
            ]
        );
        assert_eq!(
            coordinator
                .runtime_snapshot_source()
                .snapshot()
                .generation(),
            GenerationId::new(2)
        );
    }

    #[test]
    fn explicit_native_resync_does_not_claim_queued_success_before_runtime_readiness() {
        let active = EngineFixture::new();
        let failed = EngineFixture::new();
        let successor = EngineFixture::new();
        let (_configuration, desired_state_path) = desired_state_fixture();
        let (inventory_source, reconciler) = AddressReconciler::replay(&desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(
            &events,
            None,
            Some(2),
            [generation(1, &active), generation(2, &failed)],
            [generation(2, &successor)],
        );
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events).with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial native Generation converges");
        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("injected candidate failure degrades the active runtime");
        assert_eq!(
            coordinator.runtime_snapshot_source().snapshot().phase,
            RuntimePhase::Degraded
        );
        events.lock().expect("native events lock").clear();
        inventory_source.publish(Some(complete_inventory()));

        let completion = coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("unready runtime queues address reconciliation");

        assert_eq!(
            completion,
            flux_core::DispatcherCompletion::AddressResync(
                AddressResyncDisposition::AcceptedDeferred
            )
        );
        assert!(events.lock().expect("native events lock").is_empty());

        coordinator.maintain();
        assert_eq!(
            coordinator
                .runtime_snapshot_source()
                .snapshot()
                .generation(),
            GenerationId::new(2)
        );
    }

    #[test]
    fn stop_reaches_clean_absence_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = writer(&events, None, None, [generation(1, &fixture)], []);
        events.lock().expect("native events lock").clear();
        let mut coordinator = coordinator(writer, &events);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("native start converges");
        events.lock().expect("native events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect("native stop converges");

        assert_eq!(
            *events.lock().expect("native events lock"),
            [
                Event::ConvergedStopped,
                Event::EngineStopped(CaptureObservation::Detached),
            ]
        );
        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Stopped);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Detached);
        assert_eq!(snapshot.engine, RuntimeEngineState::Stopped);
        assert_eq!(snapshot.generation(), None);
    }

    fn desired_state_fixture() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("create address Desired State fixture");
        let binary = directory.path().join("sing-box");
        let template = directory.path().join("template.json");
        let desired_state = directory.path().join("flux.toml");
        fs::write(&binary, b"sing-box").expect("write address fixture engine");
        fs::write(
            &template,
            br#"{
                "dns":{"servers":[{"type":"fakeip","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}]},
                "inbounds":[{"type":"tun","tag":"removed"}],
                "log":{"level":"warn"}
            }"#,
        )
        .expect("write address fixture template");
        let config = PACKAGED_DESIRED_STATE
            .replacen(
                "/data/adb/flux/bin/sing-box",
                binary.to_str().expect("UTF-8 address fixture engine path"),
                1,
            )
            .replacen(
                "/data/adb/flux/conf/template.json",
                template
                    .to_str()
                    .expect("UTF-8 address fixture template path"),
                1,
            );
        fs::write(&desired_state, config).expect("write address fixture Desired State");
        (directory, desired_state)
    }

    fn complete_inventory() -> Arc<flux_core::NetworkInventory> {
        let mut tracker = NetworkInventoryTracker::new();
        let interface = InterfaceIndex::new(7).expect("test interface index");
        let address = InterfaceAddressRecord::new(
            interface,
            "8.8.8.8".parse::<IpAddr>().expect("test address"),
            32,
            InterfaceAddressFlags::from_bits(0),
        )
        .expect("test interface address");
        Arc::new(
            tracker
                .publish_complete([], [address])
                .expect("publish complete test inventory")
                .clone(),
        )
    }
}
