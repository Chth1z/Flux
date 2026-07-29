use std::error::Error;
use std::fmt;
use std::io;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AddressResyncDisposition, ControlError, DispatcherCompletion, GenerationId, Reason,
    RuntimeDispatcher, RuntimeIntent,
};
use flux_platform::NetworkInventoryRefreshDisposition;

use crate::engine_supervisor::{
    EngineChildAuthority, EngineChildAuthorityError, EngineChildAuthorityErrorKind,
};
use crate::functional_canary::{
    CanaryAddressFamilies, CanaryAttemptBinding, CanaryAttemptRequest,
    CanaryAttemptSocketObserverSession, CanaryCounterDeltaBounds, CanaryDeadline,
    CanaryEngineBinding, CanaryEnvironmentBinding, CanaryNonce, FunctionalCanaryDisposition,
    FunctionalCanaryError, FunctionalCanaryGateMode, UnqualifiedFunctionalCanaryExecution,
    UnqualifiedFunctionalCanaryExecutor,
};
use crate::generation_engine_config::{
    AddressReconciler, AddressReconciliationOutcome, CapturePathDecision, CapturePathSelection,
};
#[cfg(test)]
use crate::generation_engine_config::{AdmittedGeneration, PreparedGenerationRecord};
use crate::runtime_logging::{LogSeverity, runtime_log};
use crate::subscription::{
    SubscriptionRefreshCompletion, SubscriptionRefreshDecision, SubscriptionRefreshError,
    SubscriptionRefreshReport,
};
use crate::subscription::{SubscriptionRefreshRuntime, ValidatedSubscriptionEngineConfig};
use crate::{
    CaptureObservation, DesiredEngine, EnginePhase, EngineReport, EngineSnapshot, EngineSpec,
    EngineSupervisor, EngineSupervisorError, RuntimeCaptureState, RuntimeEngineState,
    RuntimeFailure, RuntimeGenerationBinding, RuntimePhase, RuntimeSnapshot, RuntimeSnapshotSource,
    RuntimeVerificationState,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublishedRuntimeState {
    Running { generation: GenerationId },
    Stopped,
    Failed,
}

#[derive(Clone)]
pub(crate) struct PreparedGeneration {
    id: GenerationId,
    spec: EngineSpec,
    capture_path_selection: CapturePathSelection,
    capture_path_evidence_deadline: Instant,
}

impl PreparedGeneration {
    #[must_use]
    pub(crate) fn new(
        id: GenerationId,
        spec: EngineSpec,
        capture_path_selection: CapturePathSelection,
        capture_path_evidence_deadline: Instant,
    ) -> Self {
        Self {
            id,
            spec,
            capture_path_selection,
            capture_path_evidence_deadline,
        }
    }

    #[must_use]
    pub(crate) const fn id(&self) -> GenerationId {
        self.id
    }

    const fn runtime_binding(&self) -> RuntimeGenerationBinding {
        RuntimeGenerationBinding::new(self.id, self.capture_path_selection)
    }

    fn capture_path_evidence_expired(&self, now: Instant) -> bool {
        now >= self.capture_path_evidence_deadline
    }

    #[cfg(test)]
    pub(crate) const fn capture_path_evidence_deadline(&self) -> Instant {
        self.capture_path_evidence_deadline
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePathRefreshRequestState {
    Pending,
    Accepted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePathRecoveryIntent {
    AutomaticRestart,
    RemainStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapturePathRefreshState {
    Current,
    Required {
        request: CapturePathRefreshRequestState,
        recovery: CapturePathRecoveryIntent,
    },
}

impl CapturePathRefreshState {
    const fn required(recovery: CapturePathRecoveryIntent) -> Self {
        Self::Required {
            request: CapturePathRefreshRequestState::Pending,
            recovery,
        }
    }

    const fn require_automatic_recovery() -> Self {
        Self::required(CapturePathRecoveryIntent::AutomaticRestart)
    }

    const fn requires_fresh_evidence(self) -> bool {
        matches!(self, Self::Required { .. })
    }

    const fn request_pending(self) -> bool {
        matches!(
            self,
            Self::Required {
                request: CapturePathRefreshRequestState::Pending,
                ..
            }
        )
    }

    const fn awaiting_fresh_evidence(self) -> bool {
        matches!(
            self,
            Self::Required {
                request: CapturePathRefreshRequestState::Accepted,
                ..
            }
        )
    }

    fn accept_request(&mut self) {
        if let Self::Required { request, .. } = self {
            *request = CapturePathRefreshRequestState::Accepted;
        }
    }

    fn cancel_automatic_recovery(&mut self) {
        if let Self::Required { recovery, .. } = self {
            *recovery = CapturePathRecoveryIntent::RemainStopped;
        }
    }

    fn accept_fresh_evidence(&mut self) -> bool {
        let previous = std::mem::replace(self, Self::Current);
        matches!(
            previous,
            Self::Required {
                recovery: CapturePathRecoveryIntent::AutomaticRestart,
                ..
            }
        )
    }
}

/// Read-only projection of an admitted native Generation.
#[cfg(test)]
pub(crate) fn inspect_admitted_generation(
    generation: &AdmittedGeneration,
) -> PreparedGenerationRecord {
    PreparedGenerationRecord::from_admitted(generation)
}

pub(crate) trait RuntimeWriter: Send + 'static {
    type Error: Error + Send + Sync + 'static;

    fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error>;
    fn prepare_address_successor(
        &mut self,
        _inputs: &crate::generation_engine_config::AddressReconciledGenerationInputs,
    ) -> Result<Option<PreparedGeneration>, Self::Error> {
        Ok(None)
    }
    fn prepare_subscription(
        &mut self,
        _config: &ValidatedSubscriptionEngineConfig,
    ) -> Result<Option<PreparedGeneration>, Self::Error> {
        Ok(None)
    }
    fn accept_deferred_subscription(&mut self, _config: ValidatedSubscriptionEngineConfig) -> bool {
        false
    }
    fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
        None
    }
    fn invalidate_latest_capture_path_decision(&mut self) {}
    fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error>;
    fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error>;
    fn capture_stop(&mut self) -> Result<(), Self::Error>;
    fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error>;
    fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error>;
    fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error>;
    fn address_resync_strategy(&self) -> AddressResyncStrategy {
        AddressResyncStrategy::WriterManaged
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressResyncStrategy {
    WriterManaged,
    CoordinatorSynchronous,
}

trait CapturePathEvidenceClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemCapturePathEvidenceClock;

impl CapturePathEvidenceClock for SystemCapturePathEvidenceClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(crate) trait EngineRuntime: Send + 'static {
    fn reconcile(
        &mut self,
        desired: DesiredEngine<'_>,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError>;

    fn snapshot(&self) -> Arc<EngineSnapshot>;

    fn open_canary_child_authority(
        &self,
        expected: crate::OwnedEngineIdentity,
        expected_snapshot_revision: NonZeroU64,
        expected_spec: &EngineSpec,
    ) -> Result<EngineChildAuthority, EngineChildAuthorityError>;
}

pub(crate) struct UnqualifiedFunctionalCanaryAttemptInputs {
    environment: CanaryEnvironmentBinding,
    socket_observer: CanaryAttemptSocketObserverSession,
    nonce: CanaryNonce,
    deadline: CanaryDeadline,
    families: CanaryAddressFamilies,
    counter_bounds: CanaryCounterDeltaBounds,
}

impl UnqualifiedFunctionalCanaryAttemptInputs {
    // Production remains explicitly structural-only until the Android adapter
    // is qualified; the required constructor is exercised by the Linux/test seam.
    #[allow(dead_code)]
    pub(crate) fn new(
        environment: CanaryEnvironmentBinding,
        socket_observer: CanaryAttemptSocketObserverSession,
        nonce: CanaryNonce,
        families: CanaryAddressFamilies,
        counter_bounds: CanaryCounterDeltaBounds,
    ) -> Result<Self, FunctionalCanaryError> {
        if environment.authority().socket_observer_binding() != socket_observer.binding() {
            return Err(FunctionalCanaryError::new(
                crate::functional_canary::CanaryErrorKind::IdentityChanged,
                crate::functional_canary::CanaryCleanupStatus::NotRequired,
                "prepared socket observer does not match the canary environment authority",
            ));
        }
        let deadline = socket_observer.deadline();
        Ok(Self {
            environment,
            socket_observer,
            nonce,
            deadline,
            families,
            counter_bounds,
        })
    }
}

pub(crate) trait UnqualifiedFunctionalCanaryAttemptContext: Send + 'static {
    fn prepare_attempt(
        &mut self,
        generation: GenerationId,
    ) -> Result<UnqualifiedFunctionalCanaryAttemptInputs, FunctionalCanaryError>;

    fn reobserve_environment(
        &mut self,
        request: &CanaryAttemptRequest,
    ) -> Result<CanaryEnvironmentBinding, FunctionalCanaryError>;

    fn monotonic_now(&mut self) -> Instant;
}

pub(crate) enum RuntimeFunctionalCanary {
    StructuralVerificationOnly,
    // Kept available for the privileged Linux harness and future qualified
    // Android adapter; daemon composition deliberately selects the other arm.
    #[allow(dead_code)]
    RequiredUnqualified {
        context: Box<dyn UnqualifiedFunctionalCanaryAttemptContext>,
        executor: Box<dyn UnqualifiedFunctionalCanaryExecutor>,
    },
}

impl RuntimeFunctionalCanary {
    const fn mode(&self) -> FunctionalCanaryGateMode {
        match self {
            Self::StructuralVerificationOnly => {
                FunctionalCanaryGateMode::StructuralVerificationOnly
            }
            Self::RequiredUnqualified { .. } => FunctionalCanaryGateMode::RequiredUnqualified,
        }
    }
}

impl EngineRuntime for EngineSupervisor {
    fn reconcile(
        &mut self,
        desired: DesiredEngine<'_>,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError> {
        EngineSupervisor::reconcile(self, desired, capture)
    }

    fn snapshot(&self) -> Arc<EngineSnapshot> {
        EngineSupervisor::snapshot(self)
    }

    fn open_canary_child_authority(
        &self,
        expected: crate::OwnedEngineIdentity,
        expected_snapshot_revision: NonZeroU64,
        expected_spec: &EngineSpec,
    ) -> Result<EngineChildAuthority, EngineChildAuthorityError> {
        EngineSupervisor::open_child_authority(
            self,
            expected,
            expected_snapshot_revision,
            expected_spec,
        )
    }
}

enum RuntimeOwnership {
    Stopped,
    Engine {
        generation: Box<PreparedGeneration>,
        capture: CaptureObservation,
    },
    CaptureRepairPending {
        generation: Box<PreparedGeneration>,
    },
    DetachPending {
        generation: Box<PreparedGeneration>,
        settlement: RetirementSettlement,
        rollback: Option<Box<PreparedGeneration>>,
    },
    Retiring {
        generation: Box<PreparedGeneration>,
        settlement: RetirementSettlement,
        rollback: Option<Box<PreparedGeneration>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RejectedPreparedContinuation {
    AwaitRollback,
    PublishFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetirementSettlement {
    Publish(PublishedRuntimeState),
    RejectPrepared(RejectedPreparedContinuation),
}

impl RuntimeOwnership {
    fn active_capture_path_authority(&self) -> Option<&PreparedGeneration> {
        match self {
            Self::Engine { generation, .. }
            | Self::CaptureRepairPending { generation }
            | Self::DetachPending { generation, .. } => Some(generation),
            Self::Stopped | Self::Retiring { .. } => None,
        }
    }

    fn capture_path_expiry_recovery(&self) -> Option<CapturePathRecoveryIntent> {
        match self {
            Self::Engine { .. } | Self::CaptureRepairPending { .. } => {
                Some(CapturePathRecoveryIntent::AutomaticRestart)
            }
            Self::DetachPending { settlement, .. } => Some(match settlement {
                RetirementSettlement::Publish(PublishedRuntimeState::Stopped) => {
                    CapturePathRecoveryIntent::RemainStopped
                }
                RetirementSettlement::Publish(
                    PublishedRuntimeState::Running { .. } | PublishedRuntimeState::Failed,
                )
                | RetirementSettlement::RejectPrepared(_) => {
                    CapturePathRecoveryIntent::AutomaticRestart
                }
            }),
            Self::Stopped | Self::Retiring { .. } => None,
        }
    }
}

enum CaptureAuthorityFailure {
    EvidenceExpired,
    EvidenceExpiredAfterRunningCommit,
    Writer(ControlError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationRole {
    Candidate { predecessor_available: bool },
    Rollback,
}

struct ActivationFailure {
    error: ControlError,
    rollback_eligible: bool,
}

impl ActivationFailure {
    const fn before_running_commit(role: ActivationRole, error: ControlError) -> Self {
        Self {
            error,
            rollback_eligible: matches!(
                role,
                ActivationRole::Candidate {
                    predecessor_available: true
                }
            ),
        }
    }

    const fn committed(error: ControlError) -> Self {
        Self {
            error,
            rollback_eligible: false,
        }
    }

    fn into_error(self) -> ControlError {
        self.error
    }
}

impl ActivationRole {
    const fn failed_activation_settlement(self) -> RetirementSettlement {
        match self {
            Self::Candidate {
                predecessor_available: true,
            } => RetirementSettlement::RejectPrepared(RejectedPreparedContinuation::AwaitRollback),
            Self::Candidate {
                predecessor_available: false,
            } => RetirementSettlement::RejectPrepared(RejectedPreparedContinuation::PublishFailed),
            Self::Rollback => RetirementSettlement::Publish(PublishedRuntimeState::Failed),
        }
    }
}

enum RetirementProgress {
    Settled,
    Pending(EngineReport),
}

struct QualifiedRunningGeneration {
    generation: RuntimeGenerationBinding,
    capture_path_evidence_deadline: Instant,
    disposition: FunctionalCanaryDisposition,
}

struct PendingSubscriptionActivation {
    completion: SubscriptionRefreshCompletion,
    candidate: GenerationId,
    node_count: u32,
    cleanup_pending: bool,
    failure: SubscriptionRefreshError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubscriptionActivationSettlement {
    Accepted,
    Pending,
    Rejected,
}

impl QualifiedRunningGeneration {
    fn capture_path_evidence_expired(&self, now: Instant) -> bool {
        now >= self.capture_path_evidence_deadline
    }

    const fn verification(&self) -> RuntimeVerificationState {
        match &self.disposition {
            FunctionalCanaryDisposition::StructuralVerificationOnly => {
                RuntimeVerificationState::StructuralOnly
            }
            FunctionalCanaryDisposition::AttemptPassedUnqualified(_) => {
                RuntimeVerificationState::FunctionalPassed
            }
        }
    }
}

pub(crate) struct RuntimeCoordinator<W, E = EngineSupervisor> {
    writer: W,
    engine: E,
    functional_canary: RuntimeFunctionalCanary,
    ownership: RuntimeOwnership,
    maintenance_interval: Duration,
    address_reconciler: Option<AddressReconciler>,
    address_reconciliation_pending: bool,
    capture_path_refresh: CapturePathRefreshState,
    capture_path_evidence_clock: Box<dyn CapturePathEvidenceClock>,
    runtime: RuntimeSnapshotSource,
    pending_publication: Option<PublishedRuntimeState>,
    pending_prepared_rejection: Option<Box<PreparedGeneration>>,
    subscription_refresh: Option<SubscriptionRefreshRuntime>,
    pending_subscription_activation: Option<PendingSubscriptionActivation>,
}

impl<W, E> RuntimeCoordinator<W, E>
where
    W: RuntimeWriter,
    E: EngineRuntime,
{
    pub(crate) fn with_dependencies(
        writer: W,
        engine: E,
        maintenance_interval: Duration,
        functional_canary: RuntimeFunctionalCanary,
    ) -> Self {
        let runtime = RuntimeSnapshotSource::new(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Stopped,
            capture: RuntimeCaptureState::Detached,
            engine: RuntimeEngineState::Stopped,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: None,
            latest_capture_path_decision: None,
            last_error: None,
        });
        Self {
            writer,
            engine,
            functional_canary,
            ownership: RuntimeOwnership::Stopped,
            maintenance_interval,
            address_reconciler: None,
            address_reconciliation_pending: false,
            capture_path_refresh: CapturePathRefreshState::Current,
            capture_path_evidence_clock: Box::new(SystemCapturePathEvidenceClock),
            runtime,
            pending_publication: None,
            pending_prepared_rejection: None,
            subscription_refresh: None,
            pending_subscription_activation: None,
        }
    }

    #[must_use]
    pub(crate) fn with_address_reconciler(mut self, reconciler: AddressReconciler) -> Self {
        self.address_reconciler = Some(reconciler);
        self
    }

    #[must_use]
    pub(crate) fn with_subscription_runtime(mut self, runtime: SubscriptionRefreshRuntime) -> Self {
        self.subscription_refresh = Some(runtime);
        self
    }

    #[cfg(test)]
    fn with_structural_dependencies(writer: W, engine: E, maintenance_interval: Duration) -> Self {
        Self::with_dependencies(
            writer,
            engine,
            maintenance_interval,
            RuntimeFunctionalCanary::StructuralVerificationOnly,
        )
    }

    #[cfg(test)]
    fn with_capture_path_evidence_clock(
        mut self,
        clock: impl CapturePathEvidenceClock + 'static,
    ) -> Self {
        self.capture_path_evidence_clock = Box::new(clock);
        self
    }

    pub(crate) fn runtime_snapshot_source(&self) -> RuntimeSnapshotSource {
        self.runtime.clone()
    }

    fn start(&mut self, reason: Reason) -> Result<(), ControlError> {
        self.expire_active_capture_path_if_needed(
            "active Capture Path evidence expired before start",
        )?;
        self.settle_pending_prepared_rejection()?;
        self.require_current_capture_path_evidence("start runtime generation")?;
        if matches!(self.ownership, RuntimeOwnership::Engine { .. }) {
            return self.reload(reason);
        }
        if matches!(
            self.ownership,
            RuntimeOwnership::CaptureRepairPending { .. }
                | RuntimeOwnership::DetachPending { .. }
                | RuntimeOwnership::Retiring { .. }
        ) {
            return Err(retirement_pending_error("start runtime"));
        }
        self.publish_runtime(
            RuntimePhase::Preparing,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            None,
            None,
        );
        let generation = self.writer.prepare(reason).map_err(|source| {
            runtime_writer_error(
                "prepare runtime generation",
                source,
                "leave the current generation untouched and repair preparation inputs",
            )
        })?;
        let generation =
            self.accept_prepared_capture_path_evidence(generation, "start runtime generation")?;
        self.request_address_reconciliation();
        self.activate_prepared(
            generation,
            ActivationRole::Candidate {
                predecessor_available: false,
            },
        )
        .map_err(ActivationFailure::into_error)?;
        Ok(())
    }

    fn reload(&mut self, reason: Reason) -> Result<(), ControlError> {
        self.expire_active_capture_path_if_needed(
            "active Capture Path evidence expired before reload",
        )?;
        self.settle_pending_prepared_rejection()?;
        self.require_current_capture_path_evidence("reload runtime generation")?;
        if matches!(
            self.ownership,
            RuntimeOwnership::CaptureRepairPending { .. }
                | RuntimeOwnership::DetachPending { .. }
                | RuntimeOwnership::Retiring { .. }
        ) {
            return Err(retirement_pending_error("reload runtime"));
        }
        let (capture_state, active_generation) = self.ownership_summary();
        self.publish_runtime(
            RuntimePhase::Preparing,
            capture_state,
            self.observed_engine_state(),
            active_generation,
            None,
        );
        let candidate = self.writer.prepare(reason).map_err(|source| {
            runtime_writer_error(
                "prepare replacement runtime generation",
                source,
                "leave the active generation untouched and repair preparation inputs",
            )
        })?;
        self.request_address_reconciliation();
        self.reload_prepared(candidate)
    }

    fn reload_prepared(&mut self, candidate: PreparedGeneration) -> Result<(), ControlError> {
        if let Err(error) = self.expire_active_capture_path_if_needed(
            "active Capture Path evidence expired while preparing a replacement",
        ) {
            return Err(self.reject_prepared_after_failure(candidate, error));
        }
        if let Err(error) =
            self.require_current_capture_path_evidence("reload prepared runtime generation")
        {
            self.invalidate_latest_capture_path_decision();
            return Err(self.reject_prepared_after_failure(candidate, error));
        }
        let candidate =
            self.accept_prepared_capture_path_evidence(candidate, "reload runtime generation")?;
        if matches!(
            self.ownership,
            RuntimeOwnership::CaptureRepairPending { .. }
                | RuntimeOwnership::DetachPending { .. }
                | RuntimeOwnership::Retiring { .. }
        ) {
            let error = retirement_pending_error("reload prepared runtime");
            return Err(self.reject_prepared_after_failure(candidate, error));
        }
        let candidate_id = candidate.id;
        self.mark_functional_gate_pending();
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (previous, capture) = match ownership {
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Stopped => {
                return self
                    .activate_prepared(
                        candidate,
                        ActivationRole::Candidate {
                            predecessor_available: false,
                        },
                    )
                    .map_err(ActivationFailure::into_error);
            }
            RuntimeOwnership::Retiring {
                generation,
                settlement,
                rollback,
            } => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    settlement,
                    rollback,
                };
                let error = retirement_pending_error("reload runtime");
                return Err(self.reject_prepared_after_failure(candidate, error));
            }
            RuntimeOwnership::DetachPending {
                generation,
                settlement,
                rollback,
            } => {
                self.ownership = RuntimeOwnership::DetachPending {
                    generation,
                    settlement,
                    rollback,
                };
                let error = retirement_pending_error("reload runtime");
                return Err(self.reject_prepared_after_failure(candidate, error));
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
                let error = retirement_pending_error("reload runtime");
                return Err(self.reject_prepared_after_failure(candidate, error));
            }
        };

        if capture == CaptureObservation::Published
            && let Err(source) = self.writer.capture_stop()
        {
            self.ownership = RuntimeOwnership::CaptureRepairPending {
                generation: previous,
            };
            let failure = runtime_writer_error(
                "detach active capture before replacement",
                source,
                "retain the active proxy engine and retry capture detachment",
            );
            return Err(self.reject_prepared_after_failure(candidate, failure));
        }
        self.ownership = RuntimeOwnership::Engine {
            generation: previous.clone(),
            capture: CaptureObservation::Detached,
        };
        match self.activate_prepared(
            candidate,
            ActivationRole::Candidate {
                predecessor_available: true,
            },
        ) {
            Ok(()) => Ok(()),
            Err(candidate_failure) if !candidate_failure.rollback_eligible => {
                Err(candidate_failure.into_error())
            }
            Err(candidate_failure) => {
                let candidate_failure = candidate_failure.into_error();
                match &mut self.ownership {
                    RuntimeOwnership::Engine {
                        generation,
                        capture: CaptureObservation::Published,
                    } if generation.id == candidate_id => Err(candidate_failure),
                    RuntimeOwnership::DetachPending {
                        generation,
                        rollback,
                        ..
                    } if generation.id == candidate_id => {
                        *rollback = Some(previous);
                        Err(candidate_failure)
                    }
                    RuntimeOwnership::Retiring {
                        generation,
                        rollback,
                        ..
                    } if generation.id == candidate_id => {
                        *rollback = Some(previous);
                        Err(candidate_failure)
                    }
                    RuntimeOwnership::Engine {
                        generation,
                        capture: CaptureObservation::Detached,
                    } if generation.id == previous.id
                        && self.pending_prepared_rejection.is_some() =>
                    {
                        Err(candidate_failure)
                    }
                    _ => {
                        self.ownership = RuntimeOwnership::Stopped;
                        match self.activate_prepared(*previous, ActivationRole::Rollback) {
                            Ok(()) => Err(candidate_failure),
                            Err(rollback_failure) => {
                                Err(rollback_failure_error(rollback_failure.into_error()))
                            }
                        }
                    }
                }
            }
        }
    }

    fn activate_prepared(
        &mut self,
        generation: PreparedGeneration,
        role: ActivationRole,
    ) -> Result<(), ActivationFailure> {
        let generation = match role {
            ActivationRole::Candidate { .. } => self
                .accept_prepared_capture_path_evidence(generation, "activate runtime generation")
                .map_err(|error| ActivationFailure::before_running_commit(role, error))?,
            ActivationRole::Rollback
                if generation
                    .capture_path_evidence_expired(self.capture_path_evidence_clock.now()) =>
            {
                let error = self.expire_cleanup_only_rollback(
                    generation,
                    "rollback Capture Path evidence expired before activation",
                );
                return Err(ActivationFailure::committed(error));
            }
            ActivationRole::Rollback => generation,
        };
        self.publish_runtime_with_verification(
            RuntimePhase::Activating,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Starting,
            self.pending_verification(),
            Some(generation.runtime_binding()),
            None,
        );
        self.ownership = RuntimeOwnership::Engine {
            generation: Box::new(generation.clone()),
            capture: CaptureObservation::Detached,
        };
        let report = match self.engine.reconcile(
            DesiredEngine::Running(&generation.spec),
            CaptureObservation::Detached,
        ) {
            Ok(report) => report,
            Err(source) => {
                let failure = ControlError::runtime(
                    "start proxy engine",
                    source,
                    "keep capture detached and retry engine reconciliation",
                );
                return Err(ActivationFailure::before_running_commit(
                    role,
                    self.compensate_failed_activation(
                        generation,
                        role,
                        CaptureObservation::Detached,
                        failure,
                    ),
                ));
            }
        };
        if !matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        ) {
            let failure = ControlError::runtime(
                "start proxy engine",
                io::Error::other(format!("engine did not become ready: {report:?}")),
                "keep capture detached and retry after the supervisor settles",
            );
            return Err(ActivationFailure::before_running_commit(
                role,
                self.compensate_failed_activation(
                    generation,
                    role,
                    CaptureObservation::Detached,
                    failure,
                ),
            ));
        }
        match self.capture_start_with_current_evidence(
            &generation,
            "publish capture",
            "detach partial capture before retrying activation",
        ) {
            Ok(()) => {}
            Err(CaptureAuthorityFailure::EvidenceExpired) => {
                let error = match role {
                    ActivationRole::Candidate {
                        predecessor_available,
                    } => self.expire_candidate_activation(
                        generation,
                        predecessor_available,
                        CaptureObservation::Detached,
                        "publish capture",
                    ),
                    ActivationRole::Rollback => {
                        return Err(ActivationFailure::committed(
                            self.expire_cleanup_only_rollback(
                                generation,
                                "rollback Capture Path evidence expired before capture publication",
                            ),
                        ));
                    }
                };
                return Err(ActivationFailure::before_running_commit(role, error));
            }
            Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                unreachable!("capture start cannot commit Running state")
            }
            Err(CaptureAuthorityFailure::Writer(failure)) => {
                return Err(ActivationFailure::before_running_commit(
                    role,
                    self.compensate_failed_activation(
                        generation,
                        role,
                        CaptureObservation::Published,
                        failure,
                    ),
                ));
            }
        }
        self.publish_runtime_with_verification(
            RuntimePhase::Verifying,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            self.pending_verification(),
            Some(generation.runtime_binding()),
            None,
        );
        let qualification = match self.verify_running_gate(
            &generation,
            "verify published capture",
            "detach capture before retiring the proxy engine",
        ) {
            Ok(qualification) => qualification,
            Err(failure) => {
                self.mark_functional_gate_failed();
                return Err(ActivationFailure::before_running_commit(
                    role,
                    self.compensate_failed_activation(
                        generation,
                        role,
                        CaptureObservation::Published,
                        failure,
                    ),
                ));
            }
        };
        self.ownership = RuntimeOwnership::Engine {
            generation: Box::new(generation.clone()),
            capture: CaptureObservation::Published,
        };
        match self.publish_qualified_running(
            qualification,
            "publish running state",
            "retain the verified data path and retry state publication",
        ) {
            Ok(()) => {}
            Err(CaptureAuthorityFailure::EvidenceExpired) => {
                let error = match role {
                    ActivationRole::Candidate {
                        predecessor_available,
                    } => self.expire_candidate_activation(
                        generation,
                        predecessor_available,
                        CaptureObservation::Published,
                        "publish running state",
                    ),
                    ActivationRole::Rollback => {
                        return Err(ActivationFailure::committed(
                            self.expire_cleanup_only_rollback(
                                generation,
                                "rollback Capture Path evidence expired before Running publication",
                            ),
                        ));
                    }
                };
                return Err(ActivationFailure::before_running_commit(role, error));
            }
            Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                let error = match self.expire_capture_path_selection(
                    "Capture Path evidence expired while publishing Running state",
                ) {
                    Err(error) => error,
                    Ok(()) => expired_capture_path_evidence_error("publish running state"),
                };
                return Err(ActivationFailure::committed(error));
            }
            Err(CaptureAuthorityFailure::Writer(failure)) => {
                return Err(ActivationFailure::committed(failure));
            }
        }
        Ok(())
    }

    fn compensate_failed_activation(
        &mut self,
        generation: PreparedGeneration,
        role: ActivationRole,
        capture: CaptureObservation,
        activation_failure: ControlError,
    ) -> ControlError {
        if capture == CaptureObservation::Published
            && let Err(source) = self.writer.capture_stop()
        {
            self.ownership = RuntimeOwnership::DetachPending {
                generation: Box::new(generation),
                settlement: role.failed_activation_settlement(),
                rollback: None,
            };
            return runtime_writer_error(
                "detach failed capture",
                FailedActivationCompensation {
                    activation: activation_failure,
                    compensation: source,
                },
                "retain the proxy engine until capture detachment can be proven",
            );
        }
        match self.reconcile_retirement(
            Box::new(generation),
            role.failed_activation_settlement(),
            None,
            "stop engine after failed activation",
            "keep capture detached and retry engine cleanup",
        ) {
            Ok(RetirementProgress::Settled) => activation_failure,
            Ok(RetirementProgress::Pending(report)) => ControlError::runtime(
                "stop engine after failed activation",
                io::Error::other(format!("engine cleanup did not settle: {report:?}")),
                "keep capture detached and retry engine cleanup",
            ),
            Err(error) => error,
        }
    }

    fn maintain_runtime(&mut self) -> Result<(), ControlError> {
        self.expire_active_capture_path_if_needed(
            "Capture Path behavioral evidence deadline expired",
        )?;
        self.settle_pending_prepared_rejection()?;
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (generation, capture) = match ownership {
            RuntimeOwnership::Stopped => {
                self.retry_pending_terminal_publication()?;
                return Ok(());
            }
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Retiring {
                generation,
                settlement,
                rollback,
            } => {
                return match self.reconcile_retirement(
                    generation,
                    settlement,
                    rollback,
                    "complete proxy engine retirement",
                    "keep capture detached and retry bounded engine cleanup",
                )? {
                    RetirementProgress::Settled | RetirementProgress::Pending(_) => Ok(()),
                };
            }
            RuntimeOwnership::DetachPending {
                generation,
                settlement,
                rollback,
            } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    settlement,
                    rollback,
                    "complete capture detachment",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled | RetirementProgress::Pending(_) => Ok(()),
                };
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                return self.reconcile_capture_repair(generation);
            }
        };
        let report = match self
            .engine
            .reconcile(DesiredEngine::Running(&generation.spec), capture)
        {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                self.mark_functional_gate_pending();
                return Err(ControlError::runtime(
                    "maintain proxy engine",
                    source,
                    "preserve current ownership and retry reconciliation",
                ));
            }
        };

        if !matches!(report, EngineReport::NoChange { .. }) {
            self.mark_functional_gate_pending();
        }

        if matches!(report, EngineReport::AwaitingCaptureRemoval { .. }) {
            self.publish_runtime_with_verification(
                RuntimePhase::Repairing,
                runtime_capture_state(capture),
                RuntimeEngineState::Exited,
                self.pending_verification(),
                Some(generation.runtime_binding()),
                None,
            );
            if capture == CaptureObservation::Published
                && let Err(source) = self.writer.capture_stop()
            {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                return Err(runtime_writer_error(
                    "detach capture after engine exit",
                    source,
                    "retain supervisor ownership and retry capture detachment",
                ));
            }
            let report = match self.engine.reconcile(
                DesiredEngine::Running(&generation.spec),
                CaptureObservation::Detached,
            ) {
                Ok(report) => report,
                Err(source) => {
                    self.ownership = RuntimeOwnership::Engine {
                        generation,
                        capture: CaptureObservation::Detached,
                    };
                    return Err(ControlError::runtime(
                        "restart proxy engine after capture detachment",
                        source,
                        "keep capture detached and retry supervisor reconciliation",
                    ));
                }
            };
            let generation_binding = generation.runtime_binding();
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture: CaptureObservation::Detached,
            };
            if matches!(
                report,
                EngineReport::Started { .. } | EngineReport::NoChange { .. }
            ) {
                return self.restore_capture_after_maintenance();
            }
            self.publish_runtime(
                runtime_phase_for_report(&report),
                RuntimeCaptureState::Detached,
                runtime_engine_for_report(&report),
                Some(generation_binding),
                None,
            );
            return Ok(());
        }

        let generation_binding = generation.runtime_binding();
        let generation_id = generation_binding.generation;
        let engine_ready = matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        );
        let pending_running_publication = matches!(
            self.pending_publication,
            Some(PublishedRuntimeState::Running { generation }) if generation == generation_id
        );
        let functional_requalification_pending = self.functional_canary.mode()
            == FunctionalCanaryGateMode::RequiredUnqualified
            && self.current_verification() == RuntimeVerificationState::FunctionalPending;
        if capture == CaptureObservation::Published
            && engine_ready
            && (pending_running_publication || functional_requalification_pending)
        {
            self.publish_runtime_with_verification(
                RuntimePhase::Verifying,
                RuntimeCaptureState::Published,
                RuntimeEngineState::Ready,
                self.pending_verification(),
                Some(generation_binding),
                None,
            );
            if self.functional_canary.mode() == FunctionalCanaryGateMode::RequiredUnqualified {
                match self.capture_start_with_current_evidence(
                    &generation,
                    "reassert capture before functional running retry",
                    "detach and restore the active generation before retrying publication",
                ) {
                    Ok(()) => {}
                    Err(CaptureAuthorityFailure::EvidenceExpired) => {
                        self.ownership = RuntimeOwnership::Engine {
                            generation,
                            capture,
                        };
                        return self.expire_capture_path_selection(
                            "Capture Path evidence expired before capture reassertion",
                        );
                    }
                    Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                        unreachable!("capture reassertion cannot commit Running state")
                    }
                    Err(CaptureAuthorityFailure::Writer(failure)) => {
                        self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
                        return Err(failure);
                    }
                }
            }
            let qualification = match self.verify_running_gate(
                &generation,
                "reverify capture before running publication",
                "detach and restore the active generation before retrying publication",
            ) {
                Ok(qualification) => qualification,
                Err(error) => {
                    self.mark_functional_gate_failed();
                    self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
                    return Err(error);
                }
            };
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture,
            };
            match self.publish_qualified_running(
                qualification,
                "retry running state publication",
                "retain the verified data path and retry publication",
            ) {
                Ok(()) => {}
                Err(CaptureAuthorityFailure::EvidenceExpired) => {
                    return self.expire_capture_path_selection(
                        "Capture Path evidence expired before running republication",
                    );
                }
                Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                    return self.expire_capture_path_selection(
                        "Capture Path evidence expired while republishing Running state",
                    );
                }
                Err(CaptureAuthorityFailure::Writer(failure)) => return Err(failure),
            }
            return Ok(());
        }
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture,
        };
        if capture == CaptureObservation::Detached && engine_ready {
            self.restore_capture_after_maintenance()?;
        } else {
            self.publish_runtime(
                runtime_phase_for_report(&report),
                runtime_capture_state(capture),
                runtime_engine_for_report(&report),
                Some(generation_binding),
                None,
            );
        }
        Ok(())
    }

    fn request_address_reconciliation(&mut self) {
        if let Some(reconciler) = self.address_reconciler.as_mut() {
            reconciler.request_reconciliation();
        }
    }

    fn require_current_capture_path_evidence(
        &self,
        operation: &'static str,
    ) -> Result<(), ControlError> {
        if !self.capture_path_refresh.requires_fresh_evidence() {
            return Ok(());
        }
        Err(ControlError::runtime(
            operation,
            io::Error::other("Capture Path evidence refresh is still pending"),
            "wait for a fresh complete Network Inventory transaction",
        ))
    }

    fn accept_prepared_capture_path_evidence(
        &mut self,
        generation: PreparedGeneration,
        operation: &'static str,
    ) -> Result<PreparedGeneration, ControlError> {
        if !generation.capture_path_evidence_expired(self.capture_path_evidence_clock.now()) {
            return Ok(generation);
        }

        if self.ownership.active_capture_path_authority().is_none()
            && matches!(self.capture_path_refresh, CapturePathRefreshState::Current)
        {
            self.capture_path_refresh = CapturePathRefreshState::require_automatic_recovery();
        }
        self.invalidate_latest_capture_path_decision();
        let failure = expired_capture_path_evidence_error(operation);
        Err(self.reject_prepared_after_failure(generation, failure))
    }

    fn reject_prepared_after_failure(
        &mut self,
        generation: PreparedGeneration,
        failure: ControlError,
    ) -> ControlError {
        if let Err(source) = self.writer.reject_prepared(&generation) {
            self.pending_prepared_rejection = Some(Box::new(generation));
            return runtime_writer_error(
                "reject unactivated prepared runtime Generation",
                FailedPreparedRejection {
                    initiating_failure: failure,
                    rejection: source,
                },
                "retry prepared-candidate settlement before accepting another Generation",
            );
        }
        failure
    }

    fn settle_pending_prepared_rejection(&mut self) -> Result<(), ControlError> {
        if self.pending_prepared_rejection.is_some()
            && matches!(self.ownership, RuntimeOwnership::Stopped)
            && matches!(
                self.pending_publication,
                Some(PublishedRuntimeState::Stopped | PublishedRuntimeState::Failed)
            )
        {
            self.retry_pending_terminal_publication()?;
        }
        let Some(generation) = self.pending_prepared_rejection.take() else {
            return Ok(());
        };
        if let Err(source) = self.writer.reject_prepared(&generation) {
            self.pending_prepared_rejection = Some(generation);
            return Err(runtime_writer_error(
                "retry prepared runtime Generation rejection",
                source,
                "keep the candidate cleanup-only and retry settlement",
            ));
        }
        Ok(())
    }

    fn expire_active_capture_path_if_needed(
        &mut self,
        cause: &'static str,
    ) -> Result<(), ControlError> {
        if self
            .ownership
            .active_capture_path_authority()
            .is_some_and(|generation| {
                generation.capture_path_evidence_expired(self.capture_path_evidence_clock.now())
            })
        {
            return self.expire_capture_path_selection(cause);
        }
        Ok(())
    }

    fn capture_start_with_current_evidence(
        &mut self,
        generation: &PreparedGeneration,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<(), CaptureAuthorityFailure> {
        if generation.capture_path_evidence_expired(self.capture_path_evidence_clock.now()) {
            return Err(CaptureAuthorityFailure::EvidenceExpired);
        }
        self.writer.capture_start(generation).map_err(|source| {
            CaptureAuthorityFailure::Writer(runtime_writer_error(operation, source, recovery))
        })
    }

    fn expire_candidate_activation(
        &mut self,
        generation: PreparedGeneration,
        predecessor_available: bool,
        capture: CaptureObservation,
        operation: &'static str,
    ) -> ControlError {
        self.invalidate_latest_capture_path_decision();
        if !predecessor_available
            && matches!(self.capture_path_refresh, CapturePathRefreshState::Current)
        {
            self.capture_path_refresh = CapturePathRefreshState::require_automatic_recovery();
        }
        let failure = expired_capture_path_evidence_error(operation);
        self.compensate_failed_activation(
            generation,
            ActivationRole::Candidate {
                predecessor_available,
            },
            capture,
            failure,
        )
    }

    fn expire_cleanup_only_rollback(
        &mut self,
        generation: PreparedGeneration,
        cause: &'static str,
    ) -> ControlError {
        self.ownership = RuntimeOwnership::Engine {
            generation: Box::new(generation),
            capture: CaptureObservation::Detached,
        };
        match self.expire_capture_path_selection(cause) {
            Err(error) => error,
            Ok(()) => ControlError::runtime(
                "expire rollback Capture Path selection",
                io::Error::other("expired rollback lost its cleanup ownership"),
                "keep capture detached and repair runtime ownership",
            ),
        }
    }

    fn maintain_address_reconciliation(&mut self) -> Result<(), ControlError> {
        let active_generation = self.ownership_summary().1;
        let mut complete_inventory_recovered = false;
        let mut selection_evidence_lost = false;
        {
            let Some(reconciler) = self.address_reconciler.as_mut() else {
                return Ok(());
            };
            match reconciler.reconcile() {
                Ok(AddressReconciliationOutcome::Reconciled(_)) => {
                    self.address_reconciliation_pending = true;
                    complete_inventory_recovered = true;
                }
                Ok(AddressReconciliationOutcome::Invalidated(previous)) => {
                    self.address_reconciliation_pending = false;
                    selection_evidence_lost = true;
                    runtime_log(
                        LogSeverity::Warn,
                        "address_reconciliation",
                        active_generation.map(|binding| binding.generation),
                        format_args!(
                            "network inventory snapshot {} at epoch {} invalidated; awaiting full resynchronization",
                            previous.snapshot_id().get(),
                            previous.epoch().get()
                        ),
                    );
                }
                Ok(
                    AddressReconciliationOutcome::Unchanged(_)
                    | AddressReconciliationOutcome::Blocked { .. },
                ) => {}
                Ok(AddressReconciliationOutcome::AwaitingCompleteSnapshot) => {
                    self.address_reconciliation_pending = false;
                    selection_evidence_lost = true;
                }
                Err(error) => {
                    self.address_reconciliation_pending = false;
                    runtime_log(
                        LogSeverity::Warn,
                        "address_reconciliation",
                        active_generation.map(|binding| binding.generation),
                        format_args!("non-mutating reconciliation blocked: {error}"),
                    );
                }
            }
        }
        if selection_evidence_lost {
            self.invalidate_latest_capture_path_decision();
            if active_generation.is_some() {
                return self
                    .expire_capture_path_selection("complete Network Inventory evidence was lost");
            }
        }
        if complete_inventory_recovered
            && self.capture_path_refresh.awaiting_fresh_evidence()
            && matches!(self.ownership, RuntimeOwnership::Stopped)
        {
            let recover = self.capture_path_refresh.accept_fresh_evidence();
            if recover {
                return self.start(Reason::DaemonRecovery);
            }
        }
        let runtime = self.runtime.snapshot();
        let can_reload = matches!(
            self.ownership,
            RuntimeOwnership::Engine {
                capture: CaptureObservation::Published,
                ..
            }
        ) && runtime.phase == RuntimePhase::Running
            && runtime.capture == RuntimeCaptureState::Published
            && runtime.engine == RuntimeEngineState::Ready;
        if !can_reload || !self.address_reconciliation_pending {
            return Ok(());
        }
        let reconciled = self
            .address_reconciler
            .as_ref()
            .and_then(AddressReconciler::current)
            .cloned()
            .ok_or_else(|| {
                ControlError::runtime(
                    "load pending address reconciliation",
                    io::Error::other(
                        "pending address reconciliation has no complete compiled inputs",
                    ),
                    "wait for a fresh complete network inventory snapshot",
                )
            })?;
        self.address_reconciliation_pending = false;
        let candidate = self
            .writer
            .prepare_address_successor(&reconciled)
            .map_err(|source| {
                runtime_writer_error(
                    "prepare address-driven runtime Generation",
                    source,
                    "retain the active Generation and retry after fresh complete inventory",
                )
            })?;
        let Some(candidate) = candidate else {
            return Ok(());
        };
        let (capture_state, active_generation) = self.ownership_summary();
        self.publish_runtime(
            RuntimePhase::Preparing,
            capture_state,
            self.observed_engine_state(),
            active_generation,
            None,
        );
        self.reload_prepared(candidate)
    }

    fn maintain_capture_path_refresh(&mut self) -> Result<(), ControlError> {
        if !self.capture_path_refresh.request_pending()
            || !matches!(self.ownership, RuntimeOwnership::Stopped)
        {
            return Ok(());
        }
        let reconciler = self.address_reconciler.as_mut().ok_or_else(|| {
            ControlError::runtime(
                "request fresh Capture Path evidence",
                io::Error::other("runtime has no Network Inventory refresh authority"),
                "keep capture detached and restore the inventory reactor attachment",
            )
        })?;
        let disposition = reconciler.request_fresh_snapshot().map_err(|source| {
            ControlError::runtime(
                "request fresh Capture Path evidence",
                source,
                "keep capture detached until a fresh complete inventory is available",
            )
        })?;
        match disposition {
            NetworkInventoryRefreshDisposition::Requested
            | NetworkInventoryRefreshDisposition::AlreadyPending => {
                self.capture_path_refresh.accept_request();
                Ok(())
            }
            NetworkInventoryRefreshDisposition::Unavailable => Err(ControlError::runtime(
                "request fresh Capture Path evidence",
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "Network Inventory reactor is unavailable",
                ),
                "keep capture detached and restore the inventory reactor attachment",
            )),
        }
    }

    fn maintain_subscription_refresh(&mut self) {
        if self.settle_pending_subscription_activation() {
            return;
        }
        let completion = self
            .subscription_refresh
            .as_mut()
            .and_then(SubscriptionRefreshRuntime::poll);
        let Some(completion) = completion else {
            if let Some(runtime) = self.subscription_refresh.as_mut() {
                runtime.schedule_observed_refresh();
                runtime.schedule_periodic(Instant::now());
            }
            return;
        };
        self.handle_subscription_refresh_completion(completion);
    }

    fn handle_subscription_refresh_completion(
        &mut self,
        completion: SubscriptionRefreshCompletion,
    ) {
        if let Some(terminal) = completion.terminal() {
            match terminal {
                Ok(report) => completion.respond(SubscriptionRefreshDecision::Accept(report)),
                Err(error) => completion.respond(SubscriptionRefreshDecision::Reject(error)),
            }
            if let Some(runtime) = self.subscription_refresh.as_mut() {
                runtime.schedule_periodic(Instant::now());
            }
            return;
        }
        let Some((source, cleanup_pending)) = completion.published() else {
            completion.respond(SubscriptionRefreshDecision::Reject(
                SubscriptionRefreshError::activation(
                    "subscription worker returned no terminal result or published candidate",
                ),
            ));
            return;
        };
        let source = source.clone();
        let node_count = source.node_count();
        if matches!(self.ownership, RuntimeOwnership::Stopped) {
            if self.writer.accept_deferred_subscription(source) {
                completion.respond(SubscriptionRefreshDecision::Accept(
                    SubscriptionRefreshReport::updated_deferred(node_count, cleanup_pending),
                ));
            } else {
                completion.respond(SubscriptionRefreshDecision::Reject(
                    SubscriptionRefreshError::activation(
                        "runtime writer cannot retain a deferred subscription snapshot",
                    ),
                ));
            }
            return;
        }

        let candidate = match self.writer.prepare_subscription(&source) {
            Ok(Some(candidate)) => candidate,
            Ok(None) => {
                completion.respond(SubscriptionRefreshDecision::Reject(
                    SubscriptionRefreshError::activation(
                        "runtime writer does not support validated subscription preparation",
                    ),
                ));
                return;
            }
            Err(source) => {
                completion.respond(SubscriptionRefreshDecision::Reject(
                    SubscriptionRefreshError::activation(
                        runtime_writer_error(
                            "prepare subscription-driven runtime Generation",
                            source,
                            "retain the active Generation and repair subscription preparation",
                        )
                        .to_string(),
                    ),
                ));
                return;
            }
        };
        let candidate_id = candidate.id;
        let (capture_state, active_generation) = self.ownership_summary();
        self.publish_runtime(
            RuntimePhase::Preparing,
            capture_state,
            self.observed_engine_state(),
            active_generation,
            None,
        );
        match self.reload_prepared(candidate) {
            Ok(()) => completion.respond(SubscriptionRefreshDecision::Accept(
                SubscriptionRefreshReport::updated(candidate_id, node_count, cleanup_pending),
            )),
            Err(error) => {
                let failure = SubscriptionRefreshError::activation(error.to_string());
                match self.subscription_activation_settlement(candidate_id) {
                    SubscriptionActivationSettlement::Accepted => completion.respond(
                        SubscriptionRefreshDecision::Accept(SubscriptionRefreshReport::updated(
                            candidate_id,
                            node_count,
                            cleanup_pending,
                        )),
                    ),
                    SubscriptionActivationSettlement::Pending => {
                        self.pending_subscription_activation =
                            Some(PendingSubscriptionActivation {
                                completion,
                                candidate: candidate_id,
                                node_count,
                                cleanup_pending,
                                failure,
                            });
                    }
                    SubscriptionActivationSettlement::Rejected => {
                        completion.respond(SubscriptionRefreshDecision::Reject(failure));
                    }
                }
            }
        }
    }

    #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
    pub(crate) fn inject_subscription_refresh_for_native_composition_test(
        &mut self,
        config: ValidatedSubscriptionEngineConfig,
        cleanup_pending: bool,
    ) -> std::sync::mpsc::Receiver<SubscriptionRefreshDecision> {
        let (completion, decision) =
            SubscriptionRefreshCompletion::published_for_test(config, cleanup_pending);
        self.handle_subscription_refresh_completion(completion);
        decision
    }

    fn settle_pending_subscription_activation(&mut self) -> bool {
        let Some(pending) = self.pending_subscription_activation.take() else {
            return false;
        };
        match self.subscription_activation_settlement(pending.candidate) {
            SubscriptionActivationSettlement::Accepted => {
                pending
                    .completion
                    .respond(SubscriptionRefreshDecision::Accept(
                        SubscriptionRefreshReport::updated(
                            pending.candidate,
                            pending.node_count,
                            pending.cleanup_pending,
                        ),
                    ));
                false
            }
            SubscriptionActivationSettlement::Pending => {
                self.pending_subscription_activation = Some(pending);
                true
            }
            SubscriptionActivationSettlement::Rejected => {
                pending
                    .completion
                    .respond(SubscriptionRefreshDecision::Reject(pending.failure));
                false
            }
        }
    }

    fn subscription_activation_settlement(
        &self,
        candidate: GenerationId,
    ) -> SubscriptionActivationSettlement {
        let runtime = self.runtime.snapshot();
        if matches!(
            &self.ownership,
            RuntimeOwnership::Engine {
                generation,
                capture: CaptureObservation::Published,
            } if generation.id == candidate
        ) && runtime.phase == RuntimePhase::Running
            && runtime.capture == RuntimeCaptureState::Published
            && runtime.engine == RuntimeEngineState::Ready
            && runtime
                .active_generation
                .is_some_and(|binding| binding.generation() == candidate)
        {
            return SubscriptionActivationSettlement::Accepted;
        }
        let candidate_owned = match &self.ownership {
            RuntimeOwnership::Stopped => false,
            RuntimeOwnership::Engine { generation, .. }
            | RuntimeOwnership::CaptureRepairPending { generation }
            | RuntimeOwnership::DetachPending { generation, .. }
            | RuntimeOwnership::Retiring { generation, .. } => generation.id == candidate,
        };
        if candidate_owned {
            SubscriptionActivationSettlement::Pending
        } else {
            SubscriptionActivationSettlement::Rejected
        }
    }

    fn reconcile_capture_repair(
        &mut self,
        generation: Box<PreparedGeneration>,
    ) -> Result<(), ControlError> {
        self.mark_functional_gate_pending();
        if let Err(source) = self.writer.capture_stop() {
            self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
            return Err(runtime_writer_error(
                "prove capture detachment before repair",
                source,
                "retain the active proxy engine and retry capture detachment",
            ));
        }
        let report = match self.engine.reconcile(
            DesiredEngine::Running(&generation.spec),
            CaptureObservation::Detached,
        ) {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture: CaptureObservation::Detached,
                };
                return Err(ControlError::runtime(
                    "maintain proxy engine during capture repair",
                    source,
                    "keep capture detached and retry supervisor reconciliation",
                ));
            }
        };
        let generation_binding = generation.runtime_binding();
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture: CaptureObservation::Detached,
        };
        if matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        ) {
            return self.restore_capture_after_maintenance();
        }
        self.publish_runtime(
            runtime_phase_for_report(&report),
            RuntimeCaptureState::Detached,
            runtime_engine_for_report(&report),
            Some(generation_binding),
            None,
        );
        Ok(())
    }

    fn restore_capture_after_maintenance(&mut self) -> Result<(), ControlError> {
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let RuntimeOwnership::Engine {
            generation,
            capture,
        } = ownership
        else {
            return Err(ControlError::runtime(
                "restore capture",
                io::Error::other("runtime lost its desired engine while restoring capture"),
                "leave capture detached and retry reconciliation",
            ));
        };
        if capture == CaptureObservation::Published {
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture,
            };
            return Ok(());
        }
        self.mark_functional_gate_pending();
        match self.capture_start_with_current_evidence(
            &generation,
            "restore capture after engine restart",
            "keep capture detached and retry publication",
        ) {
            Ok(()) => {}
            Err(CaptureAuthorityFailure::EvidenceExpired) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                return self.expire_capture_path_selection(
                    "Capture Path evidence expired before capture restoration",
                );
            }
            Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                unreachable!("capture restoration cannot commit Running state")
            }
            Err(CaptureAuthorityFailure::Writer(failure)) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                return Err(failure);
            }
        }
        self.publish_runtime_with_verification(
            RuntimePhase::Verifying,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            self.pending_verification(),
            Some(generation.runtime_binding()),
            None,
        );
        let qualification = match self.verify_running_gate(
            &generation,
            "verify restored capture",
            "detach capture before retiring the restarted engine",
        ) {
            Ok(qualification) => qualification,
            Err(failure) => {
                self.mark_functional_gate_failed();
                return Err(self.compensate_failed_activation(
                    *generation,
                    ActivationRole::Rollback,
                    CaptureObservation::Published,
                    failure,
                ));
            }
        };
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture: CaptureObservation::Published,
        };
        match self.publish_qualified_running(
            qualification,
            "republish running state",
            "retain the verified path and retry state publication",
        ) {
            Ok(()) => {}
            Err(CaptureAuthorityFailure::EvidenceExpired) => {
                return self.expire_capture_path_selection(
                    "Capture Path evidence expired before restored running publication",
                );
            }
            Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit) => {
                return self.expire_capture_path_selection(
                    "Capture Path evidence expired while publishing restored Running state",
                );
            }
            Err(CaptureAuthorityFailure::Writer(failure)) => return Err(failure),
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ControlError> {
        self.invalidate_latest_selected_capture_path_decision();
        self.capture_path_refresh.cancel_automatic_recovery();
        self.reset_verification();
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (generation, capture) = match ownership {
            RuntimeOwnership::Stopped => {
                self.publish_runtime_state(
                    PublishedRuntimeState::Stopped,
                    "publish stopped state",
                    "retry runtime reconciliation",
                )?;
                self.publish_runtime_with_verification(
                    RuntimePhase::Stopped,
                    RuntimeCaptureState::Detached,
                    RuntimeEngineState::Stopped,
                    RuntimeVerificationState::StructuralOnly,
                    None,
                    None,
                );
                return Ok(());
            }
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Retiring { generation, .. } => {
                return match self.reconcile_retirement(
                    generation,
                    RetirementSettlement::Publish(PublishedRuntimeState::Stopped),
                    None,
                    "stop proxy engine",
                    "keep capture detached and retry engine reconciliation",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
            RuntimeOwnership::DetachPending { generation, .. } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    RetirementSettlement::Publish(PublishedRuntimeState::Stopped),
                    None,
                    "detach capture",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    RetirementSettlement::Publish(PublishedRuntimeState::Stopped),
                    None,
                    "detach capture",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
        };

        self.publish_runtime_with_verification(
            RuntimePhase::Stopping,
            runtime_capture_state(capture),
            RuntimeEngineState::Stopping,
            RuntimeVerificationState::StructuralOnly,
            Some(generation.runtime_binding()),
            None,
        );
        if capture == CaptureObservation::Published
            && let Err(source) = self.writer.capture_stop()
        {
            self.ownership = RuntimeOwnership::DetachPending {
                generation,
                settlement: RetirementSettlement::Publish(PublishedRuntimeState::Stopped),
                rollback: None,
            };
            return Err(runtime_writer_error(
                "detach capture",
                source,
                "retain the proxy engine until capture detachment can be proven",
            ));
        }
        match self.reconcile_retirement(
            generation,
            RetirementSettlement::Publish(PublishedRuntimeState::Stopped),
            None,
            "stop proxy engine",
            "keep capture detached and retry engine reconciliation",
        )? {
            RetirementProgress::Settled => Ok(()),
            RetirementProgress::Pending(report) => Err(ControlError::runtime(
                "stop proxy engine",
                io::Error::other(format!("engine did not stop: {report:?}")),
                "keep capture detached and retry after the supervisor settles",
            )),
        }
    }

    fn reconcile_pending_detachment(
        &mut self,
        generation: Box<PreparedGeneration>,
        settlement: RetirementSettlement,
        rollback: Option<Box<PreparedGeneration>>,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<RetirementProgress, ControlError> {
        if let Err(source) = self.writer.capture_stop() {
            self.ownership = RuntimeOwnership::DetachPending {
                generation,
                settlement,
                rollback,
            };
            return Err(runtime_writer_error(operation, source, recovery));
        }
        self.reconcile_retirement(
            generation,
            settlement,
            rollback,
            "retire proxy engine after capture detachment",
            "keep capture detached and retry bounded engine cleanup",
        )
    }

    fn reconcile_retirement(
        &mut self,
        generation: Box<PreparedGeneration>,
        settlement: RetirementSettlement,
        rollback: Option<Box<PreparedGeneration>>,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<RetirementProgress, ControlError> {
        let generation_binding = generation.runtime_binding();
        let report = match self
            .engine
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
        {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    settlement,
                    rollback,
                };
                return Err(ControlError::runtime(operation, source, recovery));
            }
        };
        if !matches!(
            report,
            EngineReport::Stopped { .. } | EngineReport::NoChange { .. }
        ) {
            self.ownership = RuntimeOwnership::Retiring {
                generation,
                settlement,
                rollback,
            };
            self.publish_runtime(
                RuntimePhase::Stopping,
                RuntimeCaptureState::Detached,
                runtime_engine_for_report(&report),
                Some(generation_binding),
                None,
            );
            return Ok(RetirementProgress::Pending(report));
        }

        let terminal = match settlement {
            RetirementSettlement::RejectPrepared(continuation) => {
                if let Err(source) = self.writer.reject_prepared(&generation) {
                    self.ownership = RuntimeOwnership::Retiring {
                        generation,
                        settlement,
                        rollback,
                    };
                    return Err(runtime_writer_error(
                        "reject cleaned-up runtime Generation candidate",
                        source,
                        "keep the candidate cleanup-only and retry exact source settlement",
                    ));
                }
                if let Some(previous) = rollback {
                    self.ownership = RuntimeOwnership::Stopped;
                    return match self.activate_prepared(*previous, ActivationRole::Rollback) {
                        Ok(()) => Ok(RetirementProgress::Settled),
                        Err(rollback_failure) => {
                            Err(rollback_failure_error(rollback_failure.into_error()))
                        }
                    };
                }
                match continuation {
                    RejectedPreparedContinuation::AwaitRollback => {
                        self.ownership = RuntimeOwnership::Stopped;
                        return Ok(RetirementProgress::Settled);
                    }
                    RejectedPreparedContinuation::PublishFailed => PublishedRuntimeState::Failed,
                }
            }
            RetirementSettlement::Publish(terminal) => {
                if rollback.is_some() {
                    self.ownership = RuntimeOwnership::Retiring {
                        generation,
                        settlement,
                        rollback,
                    };
                    return Err(ControlError::runtime(
                        "settle retired runtime Generation",
                        io::Error::other("terminal retirement cannot retain a rollback Generation"),
                        "repair the retirement settlement before retrying cleanup",
                    ));
                }
                terminal
            }
        };

        let (phase, publish_operation, publish_recovery) = match terminal {
            PublishedRuntimeState::Stopped => (
                RuntimePhase::Stopped,
                "publish stopped state",
                "retry state publication while the runtime remains stopped",
            ),
            PublishedRuntimeState::Failed => (
                RuntimePhase::Failed,
                "publish failed state",
                "retry state publication while capture remains detached",
            ),
            PublishedRuntimeState::Running { .. } => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    settlement,
                    rollback: None,
                };
                return Err(ControlError::runtime(
                    "retire proxy engine",
                    io::Error::other("running is not a valid retirement terminal state"),
                    "retry with stopped or failed terminal publication",
                ));
            }
        };
        self.ownership = RuntimeOwnership::Stopped;
        self.publish_runtime_state(terminal, publish_operation, publish_recovery)?;
        let verification = match terminal {
            PublishedRuntimeState::Stopped => RuntimeVerificationState::StructuralOnly,
            PublishedRuntimeState::Failed | PublishedRuntimeState::Running { .. } => {
                self.current_verification()
            }
        };
        self.publish_runtime_with_verification(
            phase,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            verification,
            None,
            None,
        );
        Ok(RetirementProgress::Settled)
    }

    fn ownership_summary(&self) -> (RuntimeCaptureState, Option<RuntimeGenerationBinding>) {
        match &self.ownership {
            RuntimeOwnership::Stopped => (RuntimeCaptureState::Detached, None),
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (
                runtime_capture_state(*capture),
                Some(generation.runtime_binding()),
            ),
            RuntimeOwnership::DetachPending { generation, .. } => (
                RuntimeCaptureState::Published,
                Some(generation.runtime_binding()),
            ),
            RuntimeOwnership::CaptureRepairPending { generation } => (
                RuntimeCaptureState::Published,
                Some(generation.runtime_binding()),
            ),
            RuntimeOwnership::Retiring { generation, .. } => (
                RuntimeCaptureState::Detached,
                Some(generation.runtime_binding()),
            ),
        }
    }

    fn verify_running_gate(
        &mut self,
        generation: &PreparedGeneration,
        structural_operation: &'static str,
        structural_recovery: &'static str,
    ) -> Result<QualifiedRunningGeneration, ControlError> {
        self.writer.verify_capture(generation).map_err(|source| {
            runtime_writer_error(structural_operation, source, structural_recovery)
        })?;

        if self.functional_canary.mode() == FunctionalCanaryGateMode::StructuralVerificationOnly {
            return Ok(QualifiedRunningGeneration {
                generation: generation.runtime_binding(),
                capture_path_evidence_deadline: generation.capture_path_evidence_deadline,
                disposition: FunctionalCanaryDisposition::StructuralVerificationOnly,
            });
        }

        let pre_engine = self.reconcile_canary_engine(
            generation,
            "observe proxy engine before functional canary",
            "detach capture before repairing the proxy engine and canary environment",
        )?;
        let attempt = match &mut self.functional_canary {
            RuntimeFunctionalCanary::RequiredUnqualified { context, .. } => {
                context.prepare_attempt(generation.id).map_err(|source| {
                    functional_canary_error(
                        "prepare functional canary attempt",
                        source,
                        "detach capture before repairing canary attempt inputs",
                    )
                })?
            }
            RuntimeFunctionalCanary::StructuralVerificationOnly => {
                unreachable!("functional canary mode was checked before attempt preparation")
            }
        };
        let UnqualifiedFunctionalCanaryAttemptInputs {
            environment,
            socket_observer,
            nonce,
            deadline,
            families,
            counter_bounds,
        } = attempt;
        let pre_binding = CanaryAttemptBinding::new(pre_engine, environment);
        let request =
            CanaryAttemptRequest::new(pre_binding, nonce, deadline, families, counter_bounds)
                .map_err(|source| {
                    functional_canary_error(
                        "construct functional canary attempt",
                        source,
                        "detach capture before repairing canary attempt construction",
                    )
                })?;
        let expected_engine = request.pre_binding().engine().engine();
        let expected_snapshot_revision = request.pre_binding().engine().engine_snapshot_revision();
        let engine = &self.engine;
        let expected_spec = &generation.spec;
        let open_engine_child = Box::new(move || {
            engine
                .open_canary_child_authority(
                    expected_engine,
                    expected_snapshot_revision,
                    expected_spec,
                )
                .map_err(engine_child_authority_error)
        });
        let execution_input =
            UnqualifiedFunctionalCanaryExecution::new(&request, socket_observer, open_engine_child)
                .map_err(|source| {
                    functional_canary_error(
                        "bind functional canary attempt-owned authorities",
                        source,
                        "detach capture before preparing fresh canary authorities",
                    )
                })?;
        let execution = match &mut self.functional_canary {
            RuntimeFunctionalCanary::RequiredUnqualified { executor, .. } => {
                executor.execute(execution_input)
            }
            RuntimeFunctionalCanary::StructuralVerificationOnly => {
                unreachable!("functional canary mode was checked before execution")
            }
        };
        let post_engine = self.reconcile_canary_engine(
            generation,
            "observe proxy engine after functional canary",
            "detach capture before repairing the proxy engine and canary environment",
        );
        let (post_environment, observed_at) = match &mut self.functional_canary {
            RuntimeFunctionalCanary::RequiredUnqualified { context, .. } => {
                let environment = context.reobserve_environment(&request);
                let observed_at = context.monotonic_now();
                (environment, observed_at)
            }
            RuntimeFunctionalCanary::StructuralVerificationOnly => {
                unreachable!("functional canary mode was checked before post-attempt observation")
            }
        };
        let post_engine = post_engine?;
        let post_environment = post_environment.map_err(|source| {
            functional_canary_error(
                "reobserve functional canary environment",
                source,
                "detach capture before repairing the canary environment",
            )
        })?;
        let post_binding = CanaryAttemptBinding::new(post_engine, post_environment);
        if request.pre_binding() != &post_binding {
            return Err(ControlError::runtime(
                "validate functional canary post-attempt identity",
                io::Error::other(
                    "functional canary engine or environment identity changed during the attempt",
                ),
                "detach capture before starting a fresh functional canary attempt",
            ));
        }
        let evidence = execution.map_err(|source| {
            functional_canary_error(
                "execute functional capture canary",
                source,
                "detach capture before repairing the proxy engine and canary environment",
            )
        })?;
        let validated = evidence
            .validate_for(&request, &post_binding, observed_at)
            .map_err(|source| {
                functional_canary_error(
                    "validate functional capture canary",
                    source,
                    "detach capture before starting a fresh functional canary attempt",
                )
            })?;
        Ok(QualifiedRunningGeneration {
            generation: generation.runtime_binding(),
            capture_path_evidence_deadline: generation.capture_path_evidence_deadline,
            disposition: FunctionalCanaryDisposition::AttemptPassedUnqualified(Box::new(validated)),
        })
    }

    fn reconcile_canary_engine(
        &mut self,
        generation: &PreparedGeneration,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<CanaryEngineBinding, ControlError> {
        let report = self
            .engine
            .reconcile(
                DesiredEngine::Running(&generation.spec),
                CaptureObservation::Published,
            )
            .map_err(|source| ControlError::runtime(operation, source, recovery))?;
        if !matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        ) {
            return Err(ControlError::runtime(
                operation,
                io::Error::other(format!(
                    "proxy engine did not remain ready for the functional canary: {report:?}"
                )),
                recovery,
            ));
        }
        let snapshot = self.engine.snapshot();
        if snapshot.phase() != EnginePhase::Ready {
            return Err(ControlError::runtime(
                operation,
                io::Error::other(format!(
                    "proxy engine is not ready for a functional canary: {:?}",
                    snapshot.phase()
                )),
                recovery,
            ));
        }
        let identity = snapshot.owned_identity().ok_or_else(|| {
            ControlError::runtime(
                operation,
                io::Error::other("ready proxy engine has no owned identity"),
                recovery,
            )
        })?;
        let revision = NonZeroU64::new(snapshot.revision()).ok_or_else(|| {
            ControlError::runtime(
                operation,
                io::Error::other("ready proxy engine snapshot has zero revision"),
                recovery,
            )
        })?;
        let readiness = snapshot.owned_resource_readiness().ok_or_else(|| {
            ControlError::runtime(
                operation,
                io::Error::other("ready proxy engine has no owned-resource readiness evidence"),
                recovery,
            )
        })?;
        CanaryEngineBinding::new(
            generation.id,
            identity,
            revision,
            &generation.spec,
            readiness,
        )
        .map_err(|source| ControlError::runtime(operation, source, recovery))
    }

    fn publish_qualified_running(
        &mut self,
        qualification: QualifiedRunningGeneration,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<(), CaptureAuthorityFailure> {
        if qualification.capture_path_evidence_expired(self.capture_path_evidence_clock.now()) {
            return Err(CaptureAuthorityFailure::EvidenceExpired);
        }
        let generation = qualification.generation;
        let verification = qualification.verification();
        match &qualification.disposition {
            FunctionalCanaryDisposition::StructuralVerificationOnly
            | FunctionalCanaryDisposition::AttemptPassedUnqualified(_) => {}
        }
        self.publish_runtime_state(
            PublishedRuntimeState::Running {
                generation: generation.generation,
            },
            operation,
            recovery,
        )
        .map_err(CaptureAuthorityFailure::Writer)?;
        if qualification.capture_path_evidence_expired(self.capture_path_evidence_clock.now()) {
            return Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit);
        }
        self.publish_runtime_with_verification(
            RuntimePhase::Running,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            verification,
            Some(generation),
            None,
        );
        if qualification.capture_path_evidence_expired(self.capture_path_evidence_clock.now()) {
            return Err(CaptureAuthorityFailure::EvidenceExpiredAfterRunningCommit);
        }
        Ok(())
    }

    fn publish_runtime_state(
        &mut self,
        state: PublishedRuntimeState,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<(), ControlError> {
        self.pending_publication = Some(state);
        self.writer
            .publish(state)
            .map_err(|source| runtime_writer_error(operation, source, recovery))?;
        self.pending_publication = None;
        if matches!(
            state,
            PublishedRuntimeState::Stopped | PublishedRuntimeState::Failed
        ) {
            self.pending_prepared_rejection = None;
        }
        Ok(())
    }

    fn expire_capture_path_selection(&mut self, cause: &'static str) -> Result<(), ControlError> {
        let Some(recovery) = self.ownership.capture_path_expiry_recovery() else {
            return Ok(());
        };
        let refresh = match self.capture_path_refresh {
            CapturePathRefreshState::Current => {
                self.invalidate_latest_capture_path_decision();
                CapturePathRefreshState::required(recovery)
            }
            required @ CapturePathRefreshState::Required { .. } => required,
        };
        let stop_result = self.stop();
        self.capture_path_refresh = refresh;
        stop_result?;
        Err(ControlError::runtime(
            "expire Capture Path selection",
            io::Error::other(cause),
            "remain fail-open until fresh complete evidence qualifies a successor",
        ))
    }

    fn retry_pending_terminal_publication(&mut self) -> Result<(), ControlError> {
        let Some(state) = self.pending_publication else {
            return Ok(());
        };
        let (phase, operation, recovery) = match state {
            PublishedRuntimeState::Stopped => (
                RuntimePhase::Stopped,
                "retry stopped state publication",
                "keep the runtime stopped and retry publication",
            ),
            PublishedRuntimeState::Failed => (
                RuntimePhase::Failed,
                "retry failed state publication",
                "keep capture detached and retry publication",
            ),
            PublishedRuntimeState::Running { generation } => {
                return Err(ControlError::runtime(
                    "retry terminal state publication",
                    io::Error::other(format!(
                        "running state for generation {generation} is pending without runtime ownership"
                    )),
                    "repair runtime ownership before retrying state publication",
                ));
            }
        };
        self.publish_runtime_state(state, operation, recovery)?;
        let verification = match state {
            PublishedRuntimeState::Stopped => RuntimeVerificationState::StructuralOnly,
            PublishedRuntimeState::Failed | PublishedRuntimeState::Running { .. } => {
                self.current_verification()
            }
        };
        self.publish_runtime_with_verification(
            phase,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            verification,
            None,
            None,
        );
        Ok(())
    }

    fn observed_engine_state(&self) -> RuntimeEngineState {
        runtime_engine_state(self.engine.snapshot().phase())
    }

    fn resync_active_addresses(&mut self) -> Result<AddressResyncDisposition, ControlError> {
        self.request_address_reconciliation();
        if self.writer.address_resync_strategy() == AddressResyncStrategy::CoordinatorSynchronous {
            return self.resync_coordinator_addresses();
        }
        if self.functional_canary.mode() == FunctionalCanaryGateMode::StructuralVerificationOnly {
            return self.writer.resync_addresses().map_err(|source| {
                runtime_writer_error(
                    "resynchronize addresses",
                    source,
                    "retry after repairing the runtime writer",
                )
            });
        }

        self.mark_functional_gate_pending();
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (generation, capture) = match ownership {
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            other => {
                self.ownership = other;
                return Ok(AddressResyncDisposition::CompleteNoChange);
            }
        };
        self.pending_publication = Some(PublishedRuntimeState::Running {
            generation: generation.id,
        });
        match self.writer.resync_addresses() {
            Ok(disposition) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                Ok(disposition)
            }
            Err(source) => {
                self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
                Err(runtime_writer_error(
                    "resynchronize addresses",
                    source,
                    "detach and restore capture before requalifying the active generation",
                ))
            }
        }
    }

    fn resync_coordinator_addresses(&mut self) -> Result<AddressResyncDisposition, ControlError> {
        let outcome = {
            let Some(reconciler) = self.address_reconciler.as_mut() else {
                return Ok(AddressResyncDisposition::AcceptedDeferred);
            };
            reconciler.reconcile().map_err(|source| {
                ControlError::runtime(
                    "compile fresh address reconciliation",
                    source,
                    "retain the active Generation and retry after fresh complete inventory",
                )
            })?
        };
        match outcome {
            AddressReconciliationOutcome::Reconciled(_)
            | AddressReconciliationOutcome::Unchanged(_) => {
                self.address_reconciliation_pending = true;
            }
            AddressReconciliationOutcome::Invalidated(_)
            | AddressReconciliationOutcome::AwaitingCompleteSnapshot
            | AddressReconciliationOutcome::Blocked { .. } => {
                self.address_reconciliation_pending = false;
                return Ok(AddressResyncDisposition::AcceptedDeferred);
            }
        }

        if !self.can_reload_address_successor() {
            return Ok(AddressResyncDisposition::AcceptedDeferred);
        }
        let reconciled = self
            .address_reconciler
            .as_ref()
            .and_then(AddressReconciler::current)
            .cloned()
            .ok_or_else(|| {
                ControlError::runtime(
                    "load explicit address reconciliation",
                    io::Error::other(
                        "fresh address reconciliation has no complete compiled inputs",
                    ),
                    "retry after a complete network inventory snapshot is available",
                )
            })?;
        self.address_reconciliation_pending = false;
        let candidate = self
            .writer
            .prepare_address_successor(&reconciled)
            .map_err(|source| {
                runtime_writer_error(
                    "prepare explicit address-driven runtime Generation",
                    source,
                    "retain the active Generation and retry after fresh complete inventory",
                )
            })?;
        let Some(candidate) = candidate else {
            return Ok(AddressResyncDisposition::CompleteNoChange);
        };

        let (capture_state, active_generation) = self.ownership_summary();
        self.publish_runtime(
            RuntimePhase::Preparing,
            capture_state,
            self.observed_engine_state(),
            active_generation,
            None,
        );
        self.reload_prepared(candidate)?;
        Ok(AddressResyncDisposition::SuccessorConverged)
    }

    fn can_reload_address_successor(&self) -> bool {
        let runtime = self.runtime.snapshot();
        matches!(
            self.ownership,
            RuntimeOwnership::Engine {
                capture: CaptureObservation::Published,
                ..
            }
        ) && runtime.phase == RuntimePhase::Running
            && runtime.capture == RuntimeCaptureState::Published
            && runtime.engine == RuntimeEngineState::Ready
    }

    fn current_verification(&self) -> RuntimeVerificationState {
        self.runtime.snapshot().verification
    }

    const fn pending_verification(&self) -> RuntimeVerificationState {
        match self.functional_canary.mode() {
            FunctionalCanaryGateMode::StructuralVerificationOnly => {
                RuntimeVerificationState::StructuralOnly
            }
            FunctionalCanaryGateMode::RequiredUnqualified => {
                RuntimeVerificationState::FunctionalPending
            }
        }
    }

    const fn normalize_verification(
        &self,
        verification: RuntimeVerificationState,
    ) -> RuntimeVerificationState {
        match self.functional_canary.mode() {
            FunctionalCanaryGateMode::StructuralVerificationOnly => {
                RuntimeVerificationState::StructuralOnly
            }
            FunctionalCanaryGateMode::RequiredUnqualified => verification,
        }
    }

    fn mark_functional_gate_failed(&self) {
        if self.functional_canary.mode() != FunctionalCanaryGateMode::RequiredUnqualified {
            return;
        }
        let mut snapshot = self.runtime.snapshot().as_ref().clone();
        snapshot.verification = RuntimeVerificationState::FunctionalFailed;
        self.runtime.publish(snapshot);
    }

    fn mark_functional_gate_pending(&self) {
        if self.functional_canary.mode() != FunctionalCanaryGateMode::RequiredUnqualified {
            return;
        }
        let mut snapshot = self.runtime.snapshot().as_ref().clone();
        snapshot.verification = RuntimeVerificationState::FunctionalPending;
        self.runtime.publish(snapshot);
    }

    fn reset_verification(&self) {
        let mut snapshot = self.runtime.snapshot().as_ref().clone();
        snapshot.verification = RuntimeVerificationState::StructuralOnly;
        self.runtime.publish(snapshot);
    }

    fn publish_runtime(
        &self,
        phase: RuntimePhase,
        capture: RuntimeCaptureState,
        engine: RuntimeEngineState,
        generation: Option<RuntimeGenerationBinding>,
        last_error: Option<RuntimeFailure>,
    ) {
        self.publish_runtime_with_verification(
            phase,
            capture,
            engine,
            self.current_verification(),
            generation,
            last_error,
        );
    }

    fn publish_runtime_with_verification(
        &self,
        phase: RuntimePhase,
        capture: RuntimeCaptureState,
        engine: RuntimeEngineState,
        verification: RuntimeVerificationState,
        generation: Option<RuntimeGenerationBinding>,
        last_error: Option<RuntimeFailure>,
    ) {
        self.runtime.publish(RuntimeSnapshot {
            revision: 0,
            phase,
            capture,
            engine,
            verification: self.normalize_verification(verification),
            active_generation: generation,
            latest_capture_path_decision: self.writer.latest_capture_path_decision(),
            last_error,
        });
    }

    fn publish_runtime_error(&self, error: &ControlError) {
        let (capture, generation) = self.ownership_summary();
        let phase = if capture == RuntimeCaptureState::Published {
            RuntimePhase::Degraded
        } else {
            RuntimePhase::Failed
        };
        self.publish_runtime(
            phase,
            capture,
            self.observed_engine_state(),
            generation,
            Some(runtime_failure(error)),
        );
    }

    fn invalidate_latest_capture_path_decision(&mut self) {
        if self.writer.latest_capture_path_decision().is_none()
            && self
                .runtime
                .snapshot()
                .latest_capture_path_decision
                .is_none()
        {
            return;
        }
        self.writer.invalidate_latest_capture_path_decision();
        let mut snapshot = self.runtime.snapshot().as_ref().clone();
        snapshot.latest_capture_path_decision = None;
        self.runtime.publish(snapshot);
    }

    fn invalidate_latest_selected_capture_path_decision(&mut self) {
        let writer_selected = self
            .writer
            .latest_capture_path_decision()
            .is_some_and(|decision| decision.selection().is_some());
        let runtime_selected = self
            .runtime
            .snapshot()
            .latest_capture_path_decision
            .is_some_and(|decision| decision.selection().is_some());
        if writer_selected || runtime_selected {
            self.invalidate_latest_capture_path_decision();
        }
    }
}

impl<W, E> RuntimeDispatcher for RuntimeCoordinator<W, E>
where
    W: RuntimeWriter,
    E: EngineRuntime,
{
    fn execute(&mut self, intent: &RuntimeIntent) -> Result<DispatcherCompletion, ControlError> {
        let result = match *intent {
            RuntimeIntent::Running { reason } => {
                self.start(reason).map(|()| DispatcherCompletion::Completed)
            }
            RuntimeIntent::Reload { reason } => {
                let result = self.reload(reason);
                if result.is_ok()
                    && reason == Reason::ConfigChanged
                    && let Some(runtime) = self.subscription_refresh.as_mut()
                {
                    runtime.request_observed_refresh();
                }
                result.map(|()| DispatcherCompletion::Completed)
            }
            RuntimeIntent::Stopped { .. } => self.stop().map(|()| DispatcherCompletion::Completed),
            RuntimeIntent::ResyncAddresses { .. }
                if !matches!(&self.ownership, RuntimeOwnership::Engine { .. }) =>
            {
                Ok(DispatcherCompletion::AddressResync(
                    AddressResyncDisposition::CompleteNoChange,
                ))
            }
            RuntimeIntent::ResyncAddresses { .. } => self
                .resync_active_addresses()
                .map(DispatcherCompletion::AddressResync),
        };
        if let Err(error) = &result {
            self.publish_runtime_error(error);
        }
        result
    }

    fn configuration_inputs_consumed(&mut self) {
        if let Some(runtime) = self.subscription_refresh.as_mut() {
            runtime.request_observed_refresh();
        }
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        Some(self.maintenance_interval)
    }

    fn maintain(&mut self) {
        if let Err(error) = self.maintain_runtime() {
            self.publish_runtime_error(&error);
            runtime_log(
                LogSeverity::Error,
                "runtime_coordinator",
                self.ownership_summary().1.map(|binding| binding.generation),
                format_args!("runtime maintenance failed: {error}"),
            );
            return;
        }
        if let Err(error) = self.maintain_capture_path_refresh() {
            self.publish_runtime_error(&error);
            runtime_log(
                LogSeverity::Error,
                "capture_path",
                self.ownership_summary().1.map(|binding| binding.generation),
                format_args!("Capture Path evidence refresh failed: {error}"),
            );
            return;
        }
        if let Err(error) = self.maintain_address_reconciliation() {
            self.publish_runtime_error(&error);
            runtime_log(
                LogSeverity::Error,
                "runtime_coordinator",
                self.ownership_summary().1.map(|binding| binding.generation),
                format_args!("address-driven Generation reconciliation failed: {error}"),
            );
        }
        self.maintain_subscription_refresh();
    }

    fn shutdown(&mut self) {
        const MAX_SHUTDOWN_DRAIN_ATTEMPTS: usize = 10;
        const MAX_SHUTDOWN_RETRY_DELAY: Duration = Duration::from_millis(50);

        let mut last_error = None;
        for attempt in 0..MAX_SHUTDOWN_DRAIN_ATTEMPTS {
            match self.stop() {
                Ok(()) => return,
                Err(error) => last_error = Some(error),
            }
            let cleanup_remains = matches!(
                self.ownership,
                RuntimeOwnership::Engine { .. }
                    | RuntimeOwnership::CaptureRepairPending { .. }
                    | RuntimeOwnership::DetachPending { .. }
                    | RuntimeOwnership::Retiring { .. }
            ) || self.pending_publication.is_some()
                || self.pending_prepared_rejection.is_some();
            if !cleanup_remains || attempt + 1 == MAX_SHUTDOWN_DRAIN_ATTEMPTS {
                break;
            }
            std::thread::sleep(self.maintenance_interval.min(MAX_SHUTDOWN_RETRY_DELAY));
        }
        if let Some(error) = last_error {
            self.publish_runtime_error(&error);
            runtime_log(
                LogSeverity::Error,
                "runtime_coordinator",
                self.ownership_summary().1.map(|binding| binding.generation),
                format_args!("runtime shutdown failed: {error}"),
            );
        }
    }
}

const fn runtime_capture_state(capture: CaptureObservation) -> RuntimeCaptureState {
    match capture {
        CaptureObservation::Detached => RuntimeCaptureState::Detached,
        CaptureObservation::Published => RuntimeCaptureState::Published,
    }
}

const fn runtime_engine_state(phase: EnginePhase) -> RuntimeEngineState {
    match phase {
        EnginePhase::Stopped => RuntimeEngineState::Stopped,
        EnginePhase::Checking | EnginePhase::Starting => RuntimeEngineState::Starting,
        EnginePhase::Ready => RuntimeEngineState::Ready,
        EnginePhase::AwaitingCaptureRemoval => RuntimeEngineState::Exited,
        EnginePhase::Stopping => RuntimeEngineState::Stopping,
        EnginePhase::BackingOff => RuntimeEngineState::BackingOff,
        EnginePhase::Failed => RuntimeEngineState::Failed,
    }
}

const fn runtime_phase_for_report(report: &EngineReport) -> RuntimePhase {
    match report {
        EngineReport::NoChange { .. } | EngineReport::Started { .. } => RuntimePhase::Running,
        EngineReport::Stopped { .. } => RuntimePhase::Stopped,
        EngineReport::AwaitingCaptureRemoval { .. }
        | EngineReport::Stopping { .. }
        | EngineReport::BackingOff { .. } => RuntimePhase::Repairing,
        EngineReport::Failed { .. } => RuntimePhase::Failed,
    }
}

const fn runtime_engine_for_report(report: &EngineReport) -> RuntimeEngineState {
    match report {
        EngineReport::NoChange { .. } | EngineReport::Started { .. } => RuntimeEngineState::Ready,
        EngineReport::Stopped { .. } => RuntimeEngineState::Stopped,
        EngineReport::AwaitingCaptureRemoval { .. } => RuntimeEngineState::Exited,
        EngineReport::Stopping { .. } => RuntimeEngineState::Stopping,
        EngineReport::BackingOff { .. } => RuntimeEngineState::BackingOff,
        EngineReport::Failed { .. } => RuntimeEngineState::Failed,
    }
}

fn runtime_failure(error: &ControlError) -> RuntimeFailure {
    match error {
        ControlError::Runtime {
            operation,
            source,
            recovery,
        }
        | ControlError::Persistence {
            operation,
            source,
            recovery,
        } => RuntimeFailure {
            operation: bounded_runtime_text(operation),
            message: bounded_runtime_text(&source.to_string()),
            recovery: bounded_runtime_text(recovery),
        },
        _ => RuntimeFailure {
            operation: "control runtime".to_owned(),
            message: bounded_runtime_text(&error.to_string()),
            recovery: "inspect Flux diagnostics and retry the requested reconciliation".to_owned(),
        },
    }
}

fn bounded_runtime_text(value: &str) -> String {
    const MAX_RUNTIME_STATUS_CHARS: usize = 512;
    value.chars().take(MAX_RUNTIME_STATUS_CHARS).collect()
}

fn retirement_pending_error(operation: &'static str) -> ControlError {
    ControlError::runtime(
        operation,
        io::Error::other("proxy engine retirement is still pending"),
        "wait for bounded maintenance cleanup and retry",
    )
}

fn rollback_failure_error(rollback_failure: ControlError) -> ControlError {
    ControlError::runtime(
        "restore previous runtime generation",
        rollback_failure,
        "keep capture detached and retry restoration or settle into failed state",
    )
}

fn engine_child_authority_error(source: EngineChildAuthorityError) -> FunctionalCanaryError {
    let permission_denied = matches!(
        &source,
        EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::SystemCall { source, .. },
        } if source.kind() == io::ErrorKind::PermissionDenied
    );
    let kind = if permission_denied {
        crate::functional_canary::CanaryErrorKind::Availability(
            crate::functional_canary::CanaryAvailability::Denied,
        )
    } else {
        match source.kind() {
            EngineChildAuthorityErrorKind::StateChanged => {
                crate::functional_canary::CanaryErrorKind::IdentityChanged
            }
            EngineChildAuthorityErrorKind::ProcessHandle(
                flux_platform::ProcessHandleErrorKind::Unsupported,
            ) => crate::functional_canary::CanaryErrorKind::Availability(
                crate::functional_canary::CanaryAvailability::Unsupported,
            ),
            EngineChildAuthorityErrorKind::ProcessHandle(
                flux_platform::ProcessHandleErrorKind::Exited
                | flux_platform::ProcessHandleErrorKind::IdentityChanged,
            ) => crate::functional_canary::CanaryErrorKind::IdentityChanged,
            EngineChildAuthorityErrorKind::ProcessHandle(
                flux_platform::ProcessHandleErrorKind::Parse,
            ) => crate::functional_canary::CanaryErrorKind::Availability(
                crate::functional_canary::CanaryAvailability::Broken,
            ),
            EngineChildAuthorityErrorKind::ProcessHandle(
                flux_platform::ProcessHandleErrorKind::SystemCall,
            ) => crate::functional_canary::CanaryErrorKind::AdapterFailure,
            EngineChildAuthorityErrorKind::OpeningIdentityExhausted => {
                crate::functional_canary::CanaryErrorKind::AdapterFailure
            }
        }
    };
    FunctionalCanaryError::new(
        kind,
        crate::functional_canary::CanaryCleanupStatus::NotRequired,
        &source.to_string(),
    )
}

fn runtime_writer_error<E>(
    operation: &'static str,
    source: E,
    recovery: &'static str,
) -> ControlError
where
    E: Error + Send + Sync + 'static,
{
    ControlError::runtime(operation, source, recovery)
}

fn expired_capture_path_evidence_error(operation: &'static str) -> ControlError {
    ControlError::runtime(
        operation,
        io::Error::other("prepared Capture Path evidence expired before authorization"),
        "keep the Generation cleanup-only and collect fresh behavioral qualification evidence",
    )
}

#[derive(Debug)]
struct FailedActivationCompensation<E> {
    activation: ControlError,
    compensation: E,
}

#[derive(Debug)]
struct FailedPreparedRejection<E> {
    initiating_failure: ControlError,
    rejection: E,
}

impl<E> fmt::Display for FailedPreparedRejection<E>
where
    E: Error,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "initiating operation failed: {}; prepared candidate rejection failed: {}",
            self.initiating_failure, self.rejection
        )
    }
}

impl<E> Error for FailedPreparedRejection<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.rejection)
    }
}

impl<E> fmt::Display for FailedActivationCompensation<E>
where
    E: Error,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "activation failed: {}; capture compensation failed: {}",
            self.activation, self.compensation
        )
    }
}

impl<E> Error for FailedActivationCompensation<E>
where
    E: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.compensation)
    }
}

fn functional_canary_error<E>(
    operation: &'static str,
    source: E,
    recovery: &'static str,
) -> ControlError
where
    E: Error + Send + Sync + 'static,
{
    ControlError::runtime(operation, source, recovery)
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
        FluxConfig, InterfaceAddressFlags, InterfaceAddressRecord, InterfaceIndex,
        NetworkInventoryTracker, Reason, RuntimeDispatcher, RuntimeIntent,
    };
    use flux_platform::{ReadinessEvidence, SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};

    use super::*;
    use crate::functional_canary::local_output::xtables_tproxy_local_output_executor;
    use crate::functional_canary::tests::{
        Fixture as FunctionalCanaryFixture,
        request_with_engine_identity as functional_request_with_engine_identity,
        request_with_nonce as functional_request_with_nonce,
    };
    use crate::functional_canary::{
        CanaryAddressFamilies, CanaryCleanupStatus, CanaryErrorKind, CanaryNonce,
        CanarySocketObserverBinding, FUNCTIONAL_CANARY_NONCE_BYTES, UnqualifiedCanaryGateEvidence,
    };
    use crate::generation_engine_config::{
        TproxyEngineConfigRequest, compile_tproxy_engine_config,
        qualified_xtables_capture_path_evidence, test_xtables_capture_path_decision,
        test_xtables_capture_path_selection,
    };
    use crate::{EngineReport, OwnedEngineIdentity, RestartPolicy};

    const PACKAGED_DESIRED_STATE: &str = include_str!("../../../conf/flux.toml");
    const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../conf/template.json");

    #[derive(Clone)]
    struct ReplayCapturePathEvidenceClock {
        state: Arc<Mutex<ReplayCapturePathEvidenceClockState>>,
    }

    struct ReplayCapturePathEvidenceClockState {
        now: Instant,
        queued: VecDeque<Instant>,
    }

    impl ReplayCapturePathEvidenceClock {
        fn new(now: Instant) -> Self {
            Self {
                state: Arc::new(Mutex::new(ReplayCapturePathEvidenceClockState {
                    now,
                    queued: VecDeque::new(),
                })),
            }
        }

        fn queue(&self, readings: impl IntoIterator<Item = Instant>) {
            self.state
                .lock()
                .expect("Capture Path evidence clock lock")
                .queued
                .extend(readings);
        }
    }

    impl CapturePathEvidenceClock for ReplayCapturePathEvidenceClock {
        fn now(&self) -> Instant {
            let mut state = self.state.lock().expect("Capture Path evidence clock lock");
            if let Some(now) = state.queued.pop_front() {
                state.now = now;
            }
            state.now
        }
    }

    #[test]
    fn runtime_snapshots_preserve_the_generation_capture_path_pair() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events,
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
            .expect("start Generation");
        let running = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(running.generation(), GenerationId::new(1));
        assert_eq!(
            running.active_capture_path_selection(),
            Some(test_xtables_capture_path_selection())
        );

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect("stop Generation");
        let stopped = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(stopped.generation(), None);
        assert_eq!(stopped.active_capture_path_selection(), None);
    }

    #[test]
    fn expired_prepared_start_is_rejected_and_a_fresh_retry_succeeds() {
        let first = EngineFixture::new();
        let retry = EngineFixture::new();
        let now = Instant::now();
        let fresh_deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("fresh test deadline");
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([first.spec, retry.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([now, fresh_deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(ReplayCapturePathEvidenceClock::new(now));

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
            .expect_err("deadline is exclusive at initial start");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::PreparedRejected(generation(1)),
            ]
        );
        assert!(coordinator.pending_prepared_rejection.is_none());
        assert_eq!(coordinator.writer.invalidations, 1);
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());

        coordinator.capture_path_refresh = CapturePathRefreshState::Current;
        events.lock().expect("events lock").clear();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::DaemonRecovery,
            })
            .expect("fresh retry converges");

        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.generation(), GenerationId::new(2));
    }

    #[test]
    fn expired_prepared_reload_preserves_the_predecessor_and_a_fresh_retry_succeeds() {
        let active = EngineFixture::new();
        let expired = EngineFixture::new();
        let retry = EngineFixture::new();
        let now = Instant::now();
        let fresh_deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("fresh test deadline");
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec, expired.spec, retry.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([fresh_deadline, now, fresh_deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(ReplayCapturePathEvidenceClock::new(now));
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial Generation converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("expired replacement is rejected before detachment");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::PreparedRejected(generation(2)),
            ]
        );
        assert!(coordinator.pending_prepared_rejection.is_none());
        assert_eq!(coordinator.writer.invalidations, 1);
        let active_snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(active_snapshot.capture, RuntimeCaptureState::Published);
        assert_eq!(active_snapshot.generation(), GenerationId::new(1));

        events.lock().expect("events lock").clear();
        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect("fresh replacement converges");

        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.generation(), GenerationId::new(3));
    }

    #[test]
    fn evidence_expiring_at_capture_start_seam_never_mutates_capture() {
        let fixture = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        clock.queue([now, now, deadline]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock);

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("capture authorization expires at the mutation seam");

        let events = events.lock().expect("events lock");
        assert!(!events.contains(&Event::CaptureStarted));
        assert_eq!(
            *events,
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(1)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn evidence_expiring_before_running_commit_rejects_the_candidate() {
        let fixture = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        clock.queue([now, now, now, deadline]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock);

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("final qualification expires before Running commit");

        let events = events.lock().expect("events lock");
        assert!(!events.iter().any(|event| matches!(
            event,
            Event::Published(PublishedRuntimeState::Running { .. })
        )));
        assert!(events.contains(&Event::PreparedRejected(generation(1))));
        assert!(events.contains(&Event::CaptureStopped));
    }

    #[test]
    fn evidence_expiring_after_writer_running_commit_cleans_up_without_rollback() {
        let fixture = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        clock.queue([now, now, now, now, deadline]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock);

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("evidence expires after persistent Running commit");

        let events = events.lock().expect("events lock");
        assert!(
            events.contains(&Event::Published(PublishedRuntimeState::Running {
                generation: generation(1),
            }))
        );
        assert!(!events.contains(&Event::PreparedRejected(generation(1))));
        assert_eq!(
            events.last(),
            Some(&Event::Published(PublishedRuntimeState::Stopped))
        );
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());
    }

    #[test]
    fn evidence_expiring_after_runtime_running_snapshot_is_immediately_removed() {
        let fixture = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        clock.queue([now, now, now, now, now, deadline]);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock);
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("evidence expires after internal Running publication");

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.revision, 8);
        assert_eq!(snapshot.phase, RuntimePhase::Failed);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Detached);
        assert_eq!(snapshot.generation(), None);
        assert_eq!(snapshot.latest_capture_path_decision, None);
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert!(
            !events
                .lock()
                .expect("events lock")
                .contains(&Event::PreparedRejected(generation(1)))
        );
    }

    #[test]
    fn active_evidence_expiring_during_reload_rejects_the_prepared_successor() {
        let active = EngineFixture::new();
        let successor = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec, successor.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline, deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock.clone());
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial Generation converges");
        events.lock().expect("events lock").clear();
        clock.queue([now, deadline]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("active evidence expires after successor preparation");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
                Event::PreparedRejected(generation(2)),
            ]
        );
        assert!(coordinator.pending_prepared_rejection.is_none());
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert_eq!(coordinator.writer.invalidations, 1);
    }

    #[test]
    fn failed_expired_candidate_rejection_retains_both_failures_and_retries_first() {
        let rejected = EngineFixture::new();
        let retry = EngineFixture::new();
        let now = Instant::now();
        let fresh_deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("fresh test deadline");
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([rejected.spec, retry.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([now, fresh_deadline])
        .with_rejection_failures(1);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(ReplayCapturePathEvidenceClock::new(now));

        let error = coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
            .expect_err("expired candidate rejection fails once");
        let message = error.to_string();
        assert!(message.contains("prepared Capture Path evidence expired before authorization"));
        assert!(message.contains("injected prepared candidate rejection failure"));
        assert!(coordinator.pending_prepared_rejection.is_some());
        assert_eq!(
            *events.lock().expect("events lock"),
            [Event::Prepared(Reason::UserControl)]
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::DaemonRecovery,
            })
            .expect_err("fresh evidence is still required after rejection retry");
        assert!(coordinator.pending_prepared_rejection.is_none());
        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::PreparedRejected(generation(1)),
            ]
        );

        coordinator.capture_path_refresh = CapturePathRefreshState::Current;
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::DaemonRecovery,
            })
            .expect("fresh candidate converges after exact rejection retry");
        assert_eq!(
            coordinator
                .runtime_snapshot_source()
                .snapshot()
                .generation(),
            GenerationId::new(2)
        );
    }

    #[test]
    fn expired_capture_path_evidence_stops_fail_open_and_clears_the_decision() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        let RuntimeOwnership::Engine { generation, .. } = &mut coordinator.ownership else {
            panic!("running runtime must own its Generation");
        };
        generation.capture_path_evidence_deadline = Instant::now();
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
        assert_eq!(coordinator.writer.invalidations, 1);
        assert!(matches!(
            coordinator.capture_path_refresh,
            CapturePathRefreshState::Required {
                recovery: CapturePathRecoveryIntent::AutomaticRestart,
                ..
            }
        ));
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Failed);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Detached);
        assert_eq!(snapshot.generation(), None);
        assert_eq!(snapshot.active_capture_path_selection(), None);
        assert_eq!(snapshot.latest_capture_path_decision, None);

        events.lock().expect("events lock").clear();
        coordinator.maintain();
        assert!(events.lock().expect("events lock").is_empty());
        assert_eq!(coordinator.writer.invalidations, 1);
    }

    #[test]
    fn expired_selection_retains_only_the_active_binding_until_detachment_is_proven() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events,
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        let RuntimeOwnership::Engine { generation, .. } = &mut coordinator.ownership else {
            panic!("running runtime must own its Generation");
        };
        generation.capture_path_evidence_deadline = Instant::now();

        coordinator.maintain();

        assert!(matches!(
            coordinator.ownership,
            RuntimeOwnership::DetachPending { .. }
        ));
        let pending = runtime.snapshot();
        assert_eq!(pending.phase, RuntimePhase::Degraded);
        assert_eq!(pending.capture, RuntimeCaptureState::Published);
        assert_eq!(pending.generation(), GenerationId::new(1));
        assert_eq!(
            pending.active_capture_path_selection(),
            Some(test_xtables_capture_path_selection())
        );
        assert_eq!(pending.latest_capture_path_decision, None);
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());

        coordinator.maintain();

        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        let stopped = runtime.snapshot();
        assert_eq!(stopped.generation(), None);
        assert_eq!(stopped.active_capture_path_selection(), None);
        assert_eq!(stopped.latest_capture_path_decision, None);
    }

    #[test]
    fn expired_selection_cannot_be_restored_from_capture_repair() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        let RuntimeOwnership::Engine { mut generation, .. } =
            std::mem::replace(&mut coordinator.ownership, RuntimeOwnership::Stopped)
        else {
            panic!("running runtime must own its Generation");
        };
        generation.capture_path_evidence_deadline = Instant::now();
        coordinator.ownership = RuntimeOwnership::CaptureRepairPending { generation };
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
        assert_eq!(coordinator.writer.invalidations, 1);
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.capture, RuntimeCaptureState::Detached);
        assert_eq!(snapshot.generation(), None);
        assert_eq!(snapshot.latest_capture_path_decision, None);
    }

    #[test]
    fn expired_selection_blocks_reload_and_stop_start_until_fresh_evidence_arrives() {
        let first = EngineFixture::new();
        let second = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([first.spec, second.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        let RuntimeOwnership::Engine { generation, .. } = &mut coordinator.ownership else {
            panic!("running runtime must own its Generation");
        };
        generation.capture_path_evidence_deadline = Instant::now();
        coordinator.maintain();
        events.lock().expect("events lock").clear();

        assert!(
            coordinator
                .execute(&RuntimeIntent::Reload {
                    reason: Reason::UserControl,
                })
                .is_err(),
            "Reload must not prepare from pre-refresh evidence"
        );
        assert!(events.lock().expect("events lock").is_empty());

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect("manual Stop remains idempotent while freshness is required");
        events.lock().expect("events lock").clear();
        assert!(
            coordinator
                .execute(&RuntimeIntent::Running {
                    reason: Reason::UserControl,
                })
                .is_err(),
            "Stop followed by Start must not restore stale authority"
        );
        assert!(events.lock().expect("events lock").is_empty());
    }

    #[test]
    fn expired_explicit_stop_detach_pending_invalidates_once_and_remains_stopped() {
        let fixture = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        })
        .with_deadlines([deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(ReplayCapturePathEvidenceClock::new(now));
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial Generation converges");
        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect_err("first explicit detachment remains uncertain");
        let RuntimeOwnership::DetachPending { generation, .. } = &mut coordinator.ownership else {
            panic!("failed explicit Stop must retain detachment ownership");
        };
        generation.capture_path_evidence_deadline = now;
        events.lock().expect("events lock").clear();

        coordinator
            .maintain_runtime()
            .expect_err("expired uncertain detachment is reported after cleanup");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
        assert_eq!(coordinator.writer.invalidations, 1);
        assert!(matches!(
            coordinator.capture_path_refresh,
            CapturePathRefreshState::Required {
                recovery: CapturePathRecoveryIntent::RemainStopped,
                ..
            }
        ));
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));

        events.lock().expect("events lock").clear();
        coordinator
            .maintain_runtime()
            .expect("repeated cleanup remains settled");
        assert!(events.lock().expect("events lock").is_empty());
        assert_eq!(coordinator.writer.invalidations, 1);
    }

    #[test]
    fn expired_rollback_is_cleanup_only_and_never_restarts_capture() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let now = Instant::now();
        let deadline = now
            .checked_add(Duration::from_secs(60))
            .expect("test deadline");
        let clock = ReplayCapturePathEvidenceClock::new(now);
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec, candidate.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        })
        .with_deadlines([deadline, deadline]);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_capture_path_evidence_clock(clock.clone());
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial Generation converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Failed { revision: 2 },
            EngineReport::Stopped { revision: 3 },
        ]);
        clock.queue([now, now, now, now, deadline]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("expired rollback cannot reactivate");

        let events = events.lock().expect("events lock");
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::EngineRunning(_)))
                .count(),
            1,
            "only the failed candidate reaches engine activation"
        );
        assert!(!events.contains(&Event::CaptureStarted));
        assert!(events.contains(&Event::PreparedRejected(generation(2))));
        assert_eq!(
            events.last(),
            Some(&Event::Published(PublishedRuntimeState::Stopped))
        );
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());
        assert_eq!(coordinator.writer.invalidations, 1);
    }

    #[test]
    fn user_stop_cancels_automatic_recovery_without_clearing_the_freshness_barrier() {
        let fixture = EngineFixture::new();
        let (_directory, desired_state_path) = desired_state_fixture();
        let (source, mut reconciler) = AddressReconciler::replay(desired_state_path);
        let mut tracker = NetworkInventoryTracker::new();
        let initial = Arc::new(
            tracker
                .publish_complete([], [])
                .expect("publish initial complete inventory")
                .clone(),
        );
        source.publish(Some(initial));
        assert!(matches!(
            reconciler.reconcile(),
            Ok(AddressReconciliationOutcome::Reconciled(_))
        ));
        assert_eq!(
            reconciler
                .request_fresh_snapshot()
                .expect("request a freshness transaction"),
            NetworkInventoryRefreshDisposition::Requested
        );
        let refreshed = Arc::new(
            tracker
                .publish_complete([], [])
                .expect("publish fresh complete inventory")
                .clone(),
        );
        source.publish(Some(refreshed));

        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_address_reconciler(reconciler);
        coordinator.capture_path_refresh = CapturePathRefreshState::require_automatic_recovery();
        coordinator.capture_path_refresh.accept_request();

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect("user Stop remains idempotent while evidence is refreshing");
        assert!(matches!(
            coordinator.capture_path_refresh,
            CapturePathRefreshState::Required {
                request: CapturePathRefreshRequestState::Accepted,
                recovery: CapturePathRecoveryIntent::RemainStopped,
            }
        ));
        events.lock().expect("events lock").clear();

        assert!(
            coordinator
                .execute(&RuntimeIntent::Running {
                    reason: Reason::UserControl,
                })
                .is_err()
        );
        assert!(
            coordinator
                .execute(&RuntimeIntent::Reload {
                    reason: Reason::UserControl,
                })
                .is_err()
        );
        assert!(events.lock().expect("events lock").is_empty());

        coordinator.maintain();

        assert_eq!(
            coordinator.capture_path_refresh,
            CapturePathRefreshState::Current
        );
        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert!(events.lock().expect("events lock").is_empty());

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::UserControl,
            })
            .expect("fresh evidence permits a later explicit Start");
        assert!(
            events
                .lock()
                .expect("events lock")
                .contains(&Event::Prepared(Reason::UserControl))
        );
    }

    #[test]
    fn inventory_loss_expires_the_path_and_fresh_inventory_attempts_recovery_once() {
        let first = EngineFixture::new();
        let second = EngineFixture::new();
        let (_directory, desired_state_path) = desired_state_fixture();
        let (source, reconciler) = AddressReconciler::replay(desired_state_path);
        let mut tracker = NetworkInventoryTracker::new();
        let inventory = Arc::new(
            tracker
                .publish_complete([], [])
                .expect("publish initial complete inventory")
                .clone(),
        );
        source.publish(Some(Arc::clone(&inventory)));
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([first.spec, second.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_address_reconciler(reconciler);
        let runtime = coordinator.runtime_snapshot_source();
        coordinator.maintain();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        events.lock().expect("events lock").clear();

        source.publish(None);
        coordinator.maintain();

        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());
        assert_eq!(coordinator.writer.invalidations, 1);
        assert_eq!(runtime.snapshot().latest_capture_path_decision, None);
        assert_eq!(runtime.snapshot().generation(), None);
        assert_eq!(source.refresh_requests(), 0);

        source.set_refresh_disposition(NetworkInventoryRefreshDisposition::Unavailable);
        coordinator.maintain();
        assert_eq!(source.refresh_requests(), 1);
        assert!(coordinator.capture_path_refresh.request_pending());
        source.set_refresh_disposition(NetworkInventoryRefreshDisposition::Requested);
        coordinator.maintain();
        assert_eq!(
            source.refresh_requests(),
            2,
            "an unavailable refresh request must remain pending for retry"
        );
        assert!(
            coordinator
                .execute(&RuntimeIntent::Running {
                    reason: Reason::UserControl,
                })
                .is_err(),
            "manual start must not reuse pre-refresh evidence"
        );
        assert!(
            coordinator
                .execute(&RuntimeIntent::Reload {
                    reason: Reason::UserControl,
                })
                .is_err(),
            "manual Reload must not reuse pre-refresh evidence"
        );

        source.publish(Some(inventory));
        coordinator.maintain();
        assert!(coordinator.capture_path_refresh.requires_fresh_evidence());
        assert_eq!(runtime.snapshot().generation(), None);

        let refreshed_inventory = Arc::new(
            tracker
                .publish_complete([], [])
                .expect("publish refreshed complete inventory")
                .clone(),
        );
        source.publish(Some(refreshed_inventory));
        coordinator.maintain();

        assert_eq!(
            coordinator.capture_path_refresh,
            CapturePathRefreshState::Current
        );
        assert_eq!(
            runtime.snapshot().latest_capture_path_decision,
            Some(test_xtables_capture_path_decision())
        );
        assert_eq!(runtime.snapshot().generation(), GenerationId::new(2));
        coordinator.maintain();
        assert_eq!(
            events
                .lock()
                .expect("events lock")
                .iter()
                .filter(|event| **event == Event::Prepared(Reason::DaemonRecovery))
                .count(),
            1
        );
    }

    #[test]
    fn normal_stop_invalidates_latest_selection_while_retaining_detachment_ownership() {
        let fixture = EngineFixture::new();
        let (_directory, desired_state_path) = desired_state_fixture();
        let (source, reconciler) = AddressReconciler::replay(desired_state_path);
        let mut tracker = NetworkInventoryTracker::new();
        source.publish(Some(Arc::new(
            tracker
                .publish_complete([], [])
                .expect("publish initial complete inventory")
                .clone(),
        )));
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CapturePathDecisionWriter::new(ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        });
        let engine = ScriptedEngine {
            events,
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_address_reconciler(reconciler);
        let runtime = coordinator.runtime_snapshot_source();
        coordinator.maintain();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect_err("uncertain detachment keeps exact Generation ownership");
        let pending = runtime.snapshot();
        assert!(matches!(
            coordinator.ownership,
            RuntimeOwnership::DetachPending { .. }
        ));
        assert_eq!(
            pending.active_capture_path_selection(),
            Some(test_xtables_capture_path_selection())
        );
        assert_eq!(pending.latest_capture_path_decision, None);
        assert_eq!(coordinator.writer.invalidations, 1);

        coordinator.maintain();

        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert_eq!(runtime.snapshot().active_capture_path_selection(), None);
        assert_eq!(runtime.snapshot().latest_capture_path_decision, None);

        source.publish(None);
        coordinator.maintain();

        assert!(matches!(coordinator.ownership, RuntimeOwnership::Stopped));
        assert_eq!(coordinator.writer.invalidations, 1);
        assert_eq!(runtime.snapshot().latest_capture_path_decision, None);
    }

    #[test]
    fn maintenance_reconciles_inventory_without_invoking_writer_managed_resync() {
        let (_directory, desired_state_path) = desired_state_fixture();
        let (source, reconciler) = AddressReconciler::replay(desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::new(),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_address_reconciler(reconciler);
        let mut tracker = NetworkInventoryTracker::new();
        let interface = InterfaceIndex::new(7).expect("test interface index");
        let address = InterfaceAddressRecord::new(
            interface,
            "8.8.8.8".parse::<IpAddr>().expect("test address"),
            32,
            InterfaceAddressFlags::from_bits(0),
        )
        .expect("test interface address");
        let inventory = Arc::new(
            tracker
                .publish_complete([], [address])
                .expect("publish replay inventory")
                .clone(),
        );
        source.publish(Some(Arc::clone(&inventory)));

        coordinator.maintain();

        let current = coordinator
            .address_reconciler
            .as_ref()
            .and_then(AddressReconciler::current)
            .expect("maintenance reconciles the replay inventory");
        assert_eq!(current.inventory(), inventory.as_ref());
        assert_eq!(current.host_bypass().hosts().len(), 1);
        assert!(
            coordinator.address_reconciliation_pending,
            "a reconciled snapshot must remain pending while runtime ownership is stopped"
        );
        assert!(
            !events
                .lock()
                .expect("events lock")
                .contains(&Event::AddressesResynchronized),
            "observed inventory must not invoke writer-managed address resync"
        );

        let fixture = EngineFixture::new();
        let capture_path_selection = test_xtables_capture_path_selection();
        coordinator.ownership = RuntimeOwnership::Engine {
            generation: Box::new(PreparedGeneration::new(
                generation(1),
                fixture.spec.clone(),
                capture_path_selection,
                qualified_xtables_capture_path_evidence().valid_until(),
            )),
            capture: CaptureObservation::Published,
        };
        coordinator.publish_runtime(
            RuntimePhase::Running,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(RuntimeGenerationBinding {
                generation: generation(1),
                capture_path_selection,
            }),
            None,
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::AddressSuccessorPrepared,
            ]
        );
        assert!(!coordinator.address_reconciliation_pending);
    }

    #[test]
    fn stopped_subscription_refresh_is_accepted_only_as_deferred_source() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(None));
        let writer = SubscriptionScriptedWriter::new(
            ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::new(),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            Arc::clone(&accepted),
        );
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let source = validated_subscription_config([41; 32], 7);
        let (completion, decision) =
            SubscriptionRefreshCompletion::published_for_test(source, true);

        coordinator.handle_subscription_refresh_completion(completion);

        let report = match decision
            .recv_timeout(Duration::from_secs(1))
            .expect("decision")
        {
            SubscriptionRefreshDecision::Accept(report) => report,
            SubscriptionRefreshDecision::Reject(error) => {
                panic!("deferred refresh was rejected: {error}")
            }
        };
        assert_eq!(
            report.disposition(),
            crate::subscription::SubscriptionRefreshDisposition::UpdatedDeferred
        );
        assert_eq!(report.node_count(), Some(7));
        assert!(report.cleanup_pending());
        assert_eq!(
            *accepted.lock().expect("accepted source lock"),
            Some([41; 32])
        );
        assert_eq!(
            *events.lock().expect("events lock"),
            [Event::SubscriptionDeferred]
        );
    }

    #[test]
    fn running_subscription_refresh_commits_only_the_verified_successor() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(Some([40; 32])));
        let writer = SubscriptionScriptedWriter::new(
            ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            Arc::clone(&accepted),
        );
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial Generation");
        events.lock().expect("events lock").clear();
        let source = validated_subscription_config([42; 32], 8);
        let (completion, decision) =
            SubscriptionRefreshCompletion::published_for_test(source, false);

        coordinator.handle_subscription_refresh_completion(completion);

        let report = match decision
            .recv_timeout(Duration::from_secs(1))
            .expect("decision")
        {
            SubscriptionRefreshDecision::Accept(report) => report,
            SubscriptionRefreshDecision::Reject(error) => {
                panic!("running refresh was rejected: {error}")
            }
        };
        assert_eq!(
            report.disposition(),
            crate::subscription::SubscriptionRefreshDisposition::Updated
        );
        assert_eq!(report.generation(), Some(generation(2)));
        assert_eq!(report.node_count(), Some(8));
        assert_eq!(
            *accepted.lock().expect("accepted source lock"),
            Some([42; 32])
        );
        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::SubscriptionPrepared,
                Event::Prepared(Reason::ConfigChanged),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(2),
                }),
            ]
        );
    }

    #[test]
    fn failed_subscription_activation_restores_prior_generation_before_rejection() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(Some([43; 32])));
        let mut writer = SubscriptionScriptedWriter::new(
            ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([candidate.spec.clone()]),
                next_generation_id: 2,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            Arc::clone(&accepted),
        );
        writer.fail_capture_start_on = Some(1);
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let capture_path_selection = test_xtables_capture_path_selection();
        coordinator.ownership = RuntimeOwnership::Engine {
            generation: Box::new(PreparedGeneration::new(
                generation(1),
                active.spec.clone(),
                capture_path_selection,
                qualified_xtables_capture_path_evidence().valid_until(),
            )),
            capture: CaptureObservation::Published,
        };
        coordinator.publish_runtime(
            RuntimePhase::Running,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(RuntimeGenerationBinding {
                generation: generation(1),
                capture_path_selection,
            }),
            None,
        );
        let source = validated_subscription_config([44; 32], 9);
        let (completion, decision) =
            SubscriptionRefreshCompletion::published_for_test(source, false);

        coordinator.handle_subscription_refresh_completion(completion);

        let error = match decision
            .recv_timeout(Duration::from_secs(1))
            .expect("decision")
        {
            SubscriptionRefreshDecision::Accept(report) => {
                panic!("failed refresh was accepted: {report:?}")
            }
            SubscriptionRefreshDecision::Reject(error) => error,
        };
        assert_eq!(
            error.kind(),
            crate::subscription::SubscriptionRefreshErrorKind::Activation
        );
        assert_eq!(
            *accepted.lock().expect("accepted source lock"),
            Some([43; 32])
        );
        assert!(matches!(
            coordinator.ownership,
            RuntimeOwnership::Engine {
                generation: active_generation,
                capture: CaptureObservation::Published,
            } if active_generation.id == generation(1)
        ));
        assert!(matches!(
            events.lock().expect("events lock").last(),
            Some(Event::Published(PublishedRuntimeState::Running { generation: id }))
                if *id == generation(1)
        ));
    }

    #[test]
    fn failed_runtime_maintenance_blocks_address_replacement_until_runtime_recovers() {
        let fixture = EngineFixture::new();
        let (_directory, desired_state_path) = desired_state_fixture();
        let (source, reconciler) = AddressReconciler::replay(desired_state_path);
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::empty::<Arc<EngineSnapshot>>(),
        );
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        )
        .with_address_reconciler(reconciler);
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial runtime converges");
        coordinator.engine.fail_next_running = true;

        let mut tracker = NetworkInventoryTracker::new();
        let interface = InterfaceIndex::new(7).expect("test interface index");
        let address = InterfaceAddressRecord::new(
            interface,
            "8.8.4.4".parse::<IpAddr>().expect("test address"),
            32,
            InterfaceAddressFlags::from_bits(0),
        )
        .expect("test interface address");
        source.publish(Some(Arc::new(
            tracker
                .publish_complete([], [address])
                .expect("publish replay inventory")
                .clone(),
        )));
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [Event::EngineRunning(CaptureObservation::Published)]
        );
        assert!(
            coordinator
                .address_reconciler
                .as_ref()
                .and_then(AddressReconciler::current)
                .is_none(),
            "failed runtime maintenance must leave the inventory update unconsumed"
        );

        events.lock().expect("events lock").clear();
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::AddressSuccessorPrepared,
            ]
        );
    }

    #[test]
    fn start_orders_prepare_engine_capture_verify_and_publication() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn successful_start_publishes_an_observed_running_snapshot() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events,
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");

        let snapshot = runtime.snapshot();
        assert!(snapshot.revision > 0);
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Published);
        assert_eq!(snapshot.engine, RuntimeEngineState::Ready);
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::StructuralOnly
        );
        assert_eq!(snapshot.generation(), Some(generation(1)));
        assert_eq!(snapshot.last_error, None);
    }

    #[test]
    fn required_canary_start_orders_complete_gate_before_running_publication() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            started_at,
            CanaryNonce::from_bytes([21; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let authority_openings = engine.authority_openings();
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("required functional canary converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(17),
                }),
            ]
        );
        assert_eq!(canary_script.lock().expect("canary script").executions, 1);
        assert_eq!(
            *authority_openings.lock().expect("authority openings lock"),
            [OwnedEngineIdentity::new(
                NonZeroU32::new(4242).expect("nonzero engine PID"),
                NonZeroU64::new(98_765).expect("nonzero engine start ticks"),
            )]
        );
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn required_reload_prepare_failure_preserves_the_active_functional_pass() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([41; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(canary_script, events),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("active generation converges");

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate preparation fails before active binding changes");

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.generation(), Some(generation(17)));
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn required_reload_detachment_failure_invalidates_the_active_functional_pass() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &active.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([42; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(canary_script, events),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("active generation converges");

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("uncertain capture detachment blocks replacement");

        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.generation(), Some(generation(17)));
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::FunctionalPending
        );
    }

    #[test]
    fn required_reconcile_error_requalifies_after_a_later_ready_observation() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([43; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([44; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::repeat_with(|| ready_canary_snapshot(98_765)).take(5),
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), events),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        coordinator.engine.fail_next_running = true;

        coordinator.maintain();

        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPending
        );
        coordinator
            .engine
            .reports
            .push_back(EngineReport::NoChange { revision: 24 });

        coordinator.maintain();

        assert_eq!(canary_script.lock().expect("canary script").executions, 2);
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn required_started_report_runs_a_fresh_canary_before_restoring_passed_status() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([45; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([46; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::repeat_with(|| ready_canary_snapshot(98_765)).take(4),
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), events),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        coordinator.engine.reports.push_back(EngineReport::Started {
            revision: 24,
            owned_resource_readiness: ReadinessEvidence::Listener {
                port: NonZeroU16::new(1536).expect("port"),
                table: PathBuf::from("/proc/4242/net/tcp"),
            },
        });

        coordinator.maintain();

        assert_eq!(canary_script.lock().expect("canary script").executions, 2);
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn required_address_resync_schedules_a_fresh_running_gate() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([47; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([48; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::repeat_with(|| ready_canary_snapshot(98_765)).take(4),
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), events),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");

        coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("address resync completes");

        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPending
        );
        coordinator.maintain();
        assert_eq!(canary_script.lock().expect("canary script").executions, 2);
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn stale_post_canary_engine_identity_compensates_capture_first() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([22; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_766)],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(canary_script, Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("stale post-attempt engine identity prevents running");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(17)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalFailed
        );
    }

    #[test]
    fn uncertain_canary_cleanup_post_observes_then_compensates_capture_first() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([23; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::failing(
                request,
                CanaryErrorKind::CleanupUncertain,
                CanaryCleanupStatus::Uncertain,
            ),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(canary_script, Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("uncertain canary cleanup prevents running");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(17)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalFailed
        );
    }

    #[test]
    fn xtables_local_output_executor_never_reaches_running() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([49; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let authority_openings = engine.authority_openings();
        let functional_canary = RuntimeFunctionalCanary::RequiredUnqualified {
            context: Box::new(ScriptedCanaryContext {
                script: Arc::clone(&canary_script),
                events: Arc::clone(&events),
            }),
            executor: xtables_tproxy_local_output_executor(),
        };
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            functional_canary,
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("unsupported local-OUTPUT TPROXY prevents running");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(17)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalFailed
        );
        assert_eq!(
            *authority_openings.lock().expect("authority openings lock"),
            []
        );
    }

    #[test]
    fn failed_engine_authority_opening_still_post_observes_and_retires_the_attempt() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([51; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(request),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let mut engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [ready_canary_snapshot(98_765), ready_canary_snapshot(98_765)],
        );
        let authority_openings = engine.authority_openings();
        engine.fail_next_authority_opening(io::ErrorKind::PermissionDenied);
        engine.fail_running_on_call = Some(3);
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("denied engine authority prevents running");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(17)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalFailed
        );
        assert_eq!(canary_script.lock().expect("canary script").executions, 0);
        assert!(
            canary_script
                .lock()
                .expect("canary script")
                .active
                .is_none(),
            "post-attempt finalization must retire the active attempt even when post-engine observation fails"
        );
        assert!(
            authority_openings
                .lock()
                .expect("authority openings lock")
                .is_empty()
        );
    }

    #[test]
    fn attempt_inputs_reject_an_observer_not_bound_to_the_environment() {
        let fixture = EngineFixture::new();
        let request = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            Instant::now(),
            CanaryNonce::from_bytes([50; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let environment = request.pre_binding().environment().clone();
        let authority = environment.authority().socket_observer();

        let error = match UnqualifiedFunctionalCanaryAttemptInputs::new(
            environment,
            CanaryAttemptSocketObserverSession::scripted(
                CanarySocketObserverBinding::scripted(
                    authority,
                    NonZeroU64::new(999).expect("scripted opening ID"),
                ),
                request.deadline(),
            ),
            request.nonce(),
            request.families(),
            request.counter_bounds(),
        ) {
            Ok(_) => panic!("mismatched prepared observer cannot become attempt inputs"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), CanaryErrorKind::IdentityChanged);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
    }

    #[test]
    fn engine_child_authority_errors_preserve_canary_availability_classes() {
        let mapped = |source| engine_child_authority_error(source);
        let denied = mapped(EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::SystemCall {
                operation: "test denied process observation",
                path: None,
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            },
        });
        assert_eq!(
            denied.kind(),
            CanaryErrorKind::Availability(crate::functional_canary::CanaryAvailability::Denied)
        );

        let unsupported = mapped(EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::UnsupportedPlatform("test"),
        });
        assert_eq!(
            unsupported.kind(),
            CanaryErrorKind::Availability(
                crate::functional_canary::CanaryAvailability::Unsupported
            )
        );

        let exited = mapped(EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::Exited {
                pid: NonZeroU32::new(4242).expect("nonzero PID"),
            },
        });
        assert_eq!(exited.kind(), CanaryErrorKind::IdentityChanged);

        let malformed = mapped(EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::MalformedProcStat {
                path: PathBuf::from("/proc/4242/stat"),
            },
        });
        assert_eq!(
            malformed.kind(),
            CanaryErrorKind::Availability(crate::functional_canary::CanaryAvailability::Broken)
        );

        let system = mapped(EngineChildAuthorityError::ProcessHandle {
            source: flux_platform::ProcessHandleError::SystemCall {
                operation: "test process observation",
                path: None,
                source: io::Error::other("injected non-permission failure"),
            },
        });
        assert_eq!(system.kind(), CanaryErrorKind::AdapterFailure);
        assert_eq!(system.cleanup(), CanaryCleanupStatus::NotRequired);
    }

    #[test]
    fn running_publication_retry_reasserts_capture_and_runs_fresh_canary() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let first = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            started_at,
            CanaryNonce::from_bytes([24; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let second = functional_request_with_nonce(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            started_at,
            CanaryNonce::from_bytes([25; FUNCTIONAL_CANARY_NONCE_BYTES]),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(first),
            ScriptedCanaryAttempt::passing(second),
        ])));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 17,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::repeat_with(|| ready_canary_snapshot(98_765)).take(8),
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial running publication fails");
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPending
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(17),
                }),
            ]
        );
        let script = canary_script.lock().expect("canary script");
        assert_eq!(script.requests.len(), 2);
        assert_ne!(script.requests[0].nonce(), script.requests[1].nonce());
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn failed_functional_canary_during_running_retry_enters_capture_repair() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let attempts = [
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([26; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
            ScriptedCanaryAttempt::failing(
                functional_request_with_nonce(
                    &fixture.spec,
                    CanaryAddressFamilies::Ipv4Only,
                    started_at,
                    CanaryNonce::from_bytes([27; FUNCTIONAL_CANARY_NONCE_BYTES]),
                ),
                CanaryErrorKind::ResponseMismatch,
                CanaryCleanupStatus::VerifiedAbsent,
            ),
            ScriptedCanaryAttempt::passing(functional_request_with_nonce(
                &fixture.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([28; FUNCTIONAL_CANARY_NONCE_BYTES]),
            )),
        ];
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new(attempts)));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 17,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            std::iter::repeat_with(|| ready_canary_snapshot(98_765)).take(12),
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial running publication fails");
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPending
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();
        let failed_retry_events = events.lock().expect("events lock").clone();
        assert_eq!(
            failed_retry_events,
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
            ]
        );
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalFailed
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(17),
                }),
            ]
        );
        let script = canary_script.lock().expect("canary script");
        assert_eq!(script.requests.len(), 3);
        assert_ne!(script.requests[1].nonce(), script.requests[2].nonce());
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn restart_restoration_runs_fresh_canary_for_new_engine_identity() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let first = functional_request_with_engine_identity(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            started_at,
            CanaryNonce::from_bytes([29; FUNCTIONAL_CANARY_NONCE_BYTES]),
            generation(17),
            NonZeroU32::new(4242).expect("PID"),
            NonZeroU64::new(98_765).expect("start ticks"),
            NonZeroU64::new(23).expect("revision"),
        );
        let second = functional_request_with_engine_identity(
            &fixture.spec,
            CanaryAddressFamilies::Ipv4Only,
            started_at,
            CanaryNonce::from_bytes([30; FUNCTIONAL_CANARY_NONCE_BYTES]),
            generation(17),
            NonZeroU32::new(4343).expect("PID"),
            NonZeroU64::new(99_999).expect("start ticks"),
            NonZeroU64::new(24).expect("revision"),
        );
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new([
            ScriptedCanaryAttempt::passing(first),
            ScriptedCanaryAttempt::passing(second),
        ])));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [
                ready_canary_snapshot_for(4242, 98_765, 23),
                ready_canary_snapshot_for(4242, 98_765, 23),
                ready_canary_snapshot_for(4343, 99_999, 24),
                ready_canary_snapshot_for(4343, 99_999, 24),
            ],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        events.lock().expect("events lock").clear();
        coordinator.engine.reports.extend([
            EngineReport::AwaitingCaptureRemoval { revision: 25 },
            EngineReport::Started {
                revision: 26,
                owned_resource_readiness: ReadinessEvidence::Listener {
                    port: NonZeroU16::new(1536).expect("port"),
                    table: PathBuf::from("/proc/4343/net/tcp"),
                },
            },
        ]);

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(17),
                }),
            ]
        );
        let script = canary_script.lock().expect("canary script");
        assert_eq!(script.requests.len(), 2);
        assert_eq!(
            script.requests[1].pre_binding().engine().engine().pid(),
            4343
        );
        assert_ne!(script.requests[0].nonce(), script.requests[1].nonce());
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn candidate_canary_evidence_never_authorizes_rollback_publication() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let started_at = Instant::now();
        let attempts = [
            ScriptedCanaryAttempt::passing(functional_request_with_engine_identity(
                &active.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([31; FUNCTIONAL_CANARY_NONCE_BYTES]),
                generation(17),
                NonZeroU32::new(4242).expect("PID"),
                NonZeroU64::new(98_765).expect("start ticks"),
                NonZeroU64::new(23).expect("revision"),
            )),
            ScriptedCanaryAttempt::passing(functional_request_with_engine_identity(
                &candidate.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([32; FUNCTIONAL_CANARY_NONCE_BYTES]),
                generation(18),
                NonZeroU32::new(5252).expect("PID"),
                NonZeroU64::new(111_111).expect("start ticks"),
                NonZeroU64::new(31).expect("revision"),
            )),
            ScriptedCanaryAttempt::passing(functional_request_with_engine_identity(
                &active.spec,
                CanaryAddressFamilies::Ipv4Only,
                started_at,
                CanaryNonce::from_bytes([33; FUNCTIONAL_CANARY_NONCE_BYTES]),
                generation(17),
                NonZeroU32::new(6262).expect("PID"),
                NonZeroU64::new(222_222).expect("start ticks"),
                NonZeroU64::new(41).expect("revision"),
            )),
        ];
        let canary_script = Arc::new(Mutex::new(ScriptedCanary::new(attempts)));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 17,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = RequiredScriptedEngine::new(
            Arc::clone(&events),
            [
                ready_canary_snapshot_for(4242, 98_765, 23),
                ready_canary_snapshot_for(4242, 98_765, 23),
                ready_canary_snapshot_for(4242, 98_765, 23),
                ready_canary_snapshot_for(5252, 111_111, 31),
                ready_canary_snapshot_for(5252, 111_112, 31),
                ready_canary_snapshot_for(5252, 111_112, 31),
                ready_canary_snapshot_for(6262, 222_222, 41),
                ready_canary_snapshot_for(6262, 222_222, 41),
            ],
        );
        let mut coordinator = RuntimeCoordinator::with_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
            scripted_required_canary(Arc::clone(&canary_script), Arc::clone(&events)),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("active generation converges");
        events.lock().expect("events lock").clear();
        coordinator.engine.reports.extend([
            EngineReport::Started {
                revision: 30,
                owned_resource_readiness: ReadinessEvidence::Listener {
                    port: NonZeroU16::new(1536).expect("port"),
                    table: PathBuf::from("/proc/5252/net/tcp"),
                },
            },
            EngineReport::NoChange { revision: 31 },
            EngineReport::NoChange { revision: 31 },
            EngineReport::BackingOff {
                revision: 32,
                retry_after: Duration::from_millis(1),
            },
            EngineReport::Stopped { revision: 33 },
        ]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate post-attempt identity changed");

        let reload_events = events.lock().expect("events lock").clone();
        assert!(!reload_events.iter().any(|event| matches!(
            event,
            Event::Published(PublishedRuntimeState::Running { generation })
                if *generation == crate::runtime_coordinator::tests::generation(18)
        )));
        assert_eq!(
            reload_events,
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(18)),
                Event::CanaryExecuted(generation(18)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(18)),
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
            ]
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(18)),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryPrepared(generation(17)),
                Event::CanaryExecuted(generation(17)),
                Event::EngineRunning(CaptureObservation::Published),
                Event::CanaryReobserved(generation(17)),
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(17),
                }),
            ]
        );
        let script = canary_script.lock().expect("canary script");
        let observed_generations: Vec<_> = script
            .requests
            .iter()
            .map(|request| request.pre_binding().engine().generation())
            .collect();
        assert_eq!(
            observed_generations,
            [generation(17), generation(18), generation(17)]
        );
        assert_ne!(script.requests[0].nonce(), script.requests[2].nonce());
        assert_ne!(script.requests[1].nonce(), script.requests[2].nonce());
        assert_eq!(
            runtime.snapshot().verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }

    #[test]
    fn maintenance_retries_running_publication_without_tearing_down_the_data_path() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        let degraded = runtime.snapshot();
        assert_eq!(degraded.phase, RuntimePhase::Degraded);
        assert_eq!(degraded.capture, RuntimeCaptureState::Published);

        events.lock().expect("events lock").clear();
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
        let recovered = runtime.snapshot();
        assert_eq!(recovered.phase, RuntimePhase::Running);
        assert_eq!(recovered.capture, RuntimeCaptureState::Published);
        assert_eq!(recovered.last_error, None);
    }

    #[test]
    fn failed_running_retry_verification_repairs_capture_before_publication() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        coordinator.writer.inner.verify_failure = true;
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureVerified,
            ]
        );
        coordinator.writer.inner.verify_failure = false;
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn engine_exit_prevents_pending_running_publication_until_repaired() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::AwaitingCaptureRemoval { revision: 2 },
            EngineReport::BackingOff {
                revision: 3,
                retry_after: Duration::from_secs(1),
            },
        ]);

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
            ]
        );
    }

    #[test]
    fn reload_publication_failure_retains_the_verified_candidate_for_maintenance_retry() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 2,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate state publication fails");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(2),
                }),
            ]
        );
        let degraded = runtime.snapshot();
        assert_eq!(degraded.phase, RuntimePhase::Degraded);
        assert_eq!(degraded.capture, RuntimeCaptureState::Published);
        assert_eq!(degraded.generation(), Some(generation(2)));
    }

    #[test]
    fn stop_detaches_capture_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect("stop converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn failed_stop_detachment_is_retried_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect_err("uncertain detachment keeps stop pending");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn maintenance_finishes_a_pending_stop_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(1),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::BackingOff {
                revision: 2,
                retry_after: Duration::from_millis(1),
            },
            EngineReport::Stopped { revision: 3 },
        ]);

        coordinator
            .execute(&RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .expect_err("first bounded stop remains pending");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn address_resync_is_a_noop_while_the_runtime_is_stopped() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::ResyncAddresses {
                reason: Reason::UserControl,
            })
            .expect("stopped address resync is idempotent");

        assert!(events.lock().expect("events lock").is_empty());
    }

    #[test]
    fn shutdown_detaches_capture_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator.shutdown();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn shutdown_retries_unsettled_engine_cleanup_within_its_bounded_drain() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(1),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::BackingOff {
                revision: 2,
                retry_after: Duration::from_millis(1),
            },
            EngineReport::Stopped { revision: 3 },
        ]);

        coordinator.shutdown();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn failed_capture_verification_detaches_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: true,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed verification rolls back");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(1)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn failed_activation_detachment_is_retried_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: true,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed verification leaves detachment pending");
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(1)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn failed_capture_start_detaches_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: true,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );

        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed capture publication rolls back");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(1)),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn reload_prepares_candidate_before_detaching_and_replacing_the_engine() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect("reload converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(2),
                }),
            ]
        );
    }

    #[test]
    fn failed_reload_settles_candidate_then_fresh_rollback_restores_previous_generation() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Failed { revision: 2 },
            EngineReport::Stopped { revision: 3 },
            EngineReport::Started {
                revision: 4,
                owned_resource_readiness: ReadinessEvidence::Listener {
                    port: NonZeroU16::new(1536).expect("nonzero port"),
                    table: PathBuf::from("/proc/1/net/tcp"),
                },
            },
        ]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate failure is reported after rollback");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(2)),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn failed_reload_and_failed_rollback_settle_fail_open_and_publish_failed() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Failed { revision: 2 },
            EngineReport::Stopped { revision: 3 },
            EngineReport::Failed { revision: 4 },
            EngineReport::Stopped { revision: 5 },
        ]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("failed rollback is reported");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(2)),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        let failed = runtime.snapshot();
        assert_eq!(failed.phase, RuntimePhase::Failed);
        assert_eq!(failed.capture, RuntimeCaptureState::Detached);
    }

    #[test]
    fn failed_reload_detachment_retains_the_active_engine_and_blocks_replacement() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("uncertain capture detachment blocks replacement");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::PreparedRejected(generation(2)),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn failed_candidate_compensation_waits_for_detachment_before_previous_restart() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CandidateActivationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            capture_start_calls: 0,
            capture_stop_calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate capture and its compensation both fail");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureStopped,
            ]
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(2)),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn pending_candidate_retirement_defers_previous_restart_until_settled() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        coordinator.writer.verify_failure = true;
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Started {
                revision: 2,
                owned_resource_readiness: ReadinessEvidence::Listener {
                    port: NonZeroU16::new(1536).expect("nonzero port"),
                    table: PathBuf::from("/proc/1/net/tcp"),
                },
            },
            EngineReport::BackingOff {
                revision: 3,
                retry_after: Duration::from_secs(1),
            },
        ]);

        coordinator
            .execute(&RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .expect_err("candidate verification failure is reported");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::UserControl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
            ]
        );
        coordinator.writer.verify_failure = false;
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineStopped(CaptureObservation::Detached),
                Event::PreparedRejected(generation(2)),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn maintenance_detaches_capture_before_abnormal_exit_restart() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator = RuntimeCoordinator::with_structural_dependencies(
            writer,
            engine,
            Duration::from_millis(100),
        );
        coordinator
            .execute(&RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::AwaitingCaptureRemoval { revision: 2 },
            EngineReport::BackingOff {
                revision: 3,
                retry_after: Duration::from_secs(1),
            },
        ]);

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
            ]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Prepared(Reason),
        EngineRunning(CaptureObservation),
        EngineStopped(CaptureObservation),
        CaptureStarted,
        CaptureStopped,
        CaptureVerified,
        CanaryPrepared(GenerationId),
        CanaryExecuted(GenerationId),
        CanaryReobserved(GenerationId),
        AddressesResynchronized,
        AddressSuccessorPrepared,
        SubscriptionPrepared,
        SubscriptionDeferred,
        PreparedRejected(GenerationId),
        Published(PublishedRuntimeState),
    }

    fn validated_subscription_config(
        snapshot_digest: [u8; 32],
        node_count: u32,
    ) -> ValidatedSubscriptionEngineConfig {
        let desired_state = FluxConfig::parse(PACKAGED_DESIRED_STATE)
            .expect("packaged subscription test Desired State");
        let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            PACKAGED_ENGINE_TEMPLATE,
            desired_state.listener().port(),
        ))
        .expect("subscription test artifact");
        ValidatedSubscriptionEngineConfig::for_test(
            desired_state,
            artifact,
            snapshot_digest,
            node_count,
        )
    }

    fn desired_state_fixture() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("Desired State fixture");
        let path = directory.path().join("flux.toml");
        fs::write(&path, PACKAGED_DESIRED_STATE).expect("write Desired State fixture");
        (directory, path)
    }

    fn generation(value: u32) -> GenerationId {
        GenerationId::new(value).expect("test generation must be nonzero")
    }

    struct ScriptedWriter {
        events: Arc<Mutex<Vec<Event>>>,
        prepared: VecDeque<EngineSpec>,
        next_generation_id: u32,
        capture_start_failure: bool,
        capture_stop_failures: usize,
        verify_failure: bool,
    }

    struct CapturePathDecisionWriter {
        inner: ScriptedWriter,
        decision: Option<CapturePathDecision>,
        invalidations: usize,
        deadlines: VecDeque<Instant>,
        rejection_failures: usize,
    }

    impl CapturePathDecisionWriter {
        fn new(inner: ScriptedWriter) -> Self {
            Self {
                inner,
                decision: None,
                invalidations: 0,
                deadlines: VecDeque::new(),
                rejection_failures: 0,
            }
        }

        fn with_deadlines(mut self, deadlines: impl IntoIterator<Item = Instant>) -> Self {
            self.deadlines = deadlines.into_iter().collect();
            self
        }

        fn with_rejection_failures(mut self, failures: usize) -> Self {
            self.rejection_failures = failures;
            self
        }
    }

    struct PublicationFailingWriter {
        inner: ScriptedWriter,
        fail_on_call: usize,
        calls: usize,
    }

    struct CandidateActivationFailingWriter {
        inner: ScriptedWriter,
        capture_start_calls: usize,
        capture_stop_calls: usize,
    }

    struct SubscriptionScriptedWriter {
        inner: ScriptedWriter,
        accepted: Arc<Mutex<Option<[u8; 32]>>>,
        pending: Option<[u8; 32]>,
        capture_start_calls: usize,
        fail_capture_start_on: Option<usize>,
    }

    impl SubscriptionScriptedWriter {
        fn new(inner: ScriptedWriter, accepted: Arc<Mutex<Option<[u8; 32]>>>) -> Self {
            Self {
                inner,
                accepted,
                pending: None,
                capture_start_calls: 0,
                fail_capture_start_on: None,
            }
        }
    }

    impl RuntimeWriter for SubscriptionScriptedWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            self.inner.prepare(reason)
        }

        fn prepare_subscription(
            &mut self,
            source: &ValidatedSubscriptionEngineConfig,
        ) -> Result<Option<PreparedGeneration>, Self::Error> {
            self.inner
                .events
                .lock()
                .expect("events lock")
                .push(Event::SubscriptionPrepared);
            let prepared = self.inner.prepare(Reason::ConfigChanged)?;
            self.pending = Some(source.snapshot_digest());
            Ok(Some(prepared))
        }

        fn accept_deferred_subscription(
            &mut self,
            source: ValidatedSubscriptionEngineConfig,
        ) -> bool {
            self.inner
                .events
                .lock()
                .expect("events lock")
                .push(Event::SubscriptionDeferred);
            *self.accepted.lock().expect("accepted source lock") = Some(source.snapshot_digest());
            true
        }

        fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.reject_prepared(generation)?;
            self.pending = None;
            Ok(())
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)?;
            self.capture_start_calls += 1;
            if self.fail_capture_start_on == Some(self.capture_start_calls) {
                Err(io::Error::other(
                    "injected subscription capture publication failure",
                ))
            } else {
                Ok(())
            }
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)?;
            match phase {
                PublishedRuntimeState::Running { .. } => {
                    if let Some(pending) = self.pending.take() {
                        *self.accepted.lock().expect("accepted source lock") = Some(pending);
                    }
                }
                PublishedRuntimeState::Stopped | PublishedRuntimeState::Failed => {
                    self.pending = None;
                }
            }
            Ok(())
        }

        fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl RuntimeWriter for CandidateActivationFailingWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            self.inner.prepare(reason)
        }

        fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.reject_prepared(generation)
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)?;
            self.capture_start_calls += 1;
            if self.capture_start_calls == 2 {
                Err(io::Error::other(
                    "injected candidate capture publication failure",
                ))
            } else {
                Ok(())
            }
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()?;
            self.capture_stop_calls += 1;
            if self.capture_stop_calls == 2 {
                Err(io::Error::other(
                    "injected candidate capture detachment failure",
                ))
            } else {
                Ok(())
            }
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)
        }

        fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl RuntimeWriter for PublicationFailingWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            self.inner.prepare(reason)
        }

        fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.reject_prepared(generation)
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)?;
            self.calls += 1;
            if self.calls == self.fail_on_call {
                Err(io::Error::other("injected state publication failure"))
            } else {
                Ok(())
            }
        }

        fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl RuntimeWriter for CapturePathDecisionWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            let mut prepared = self.inner.prepare(reason)?;
            if let Some(deadline) = self.deadlines.pop_front() {
                prepared.capture_path_evidence_deadline = deadline;
            }
            self.decision = Some(test_xtables_capture_path_decision());
            Ok(prepared)
        }

        fn prepare_address_successor(
            &mut self,
            inputs: &crate::generation_engine_config::AddressReconciledGenerationInputs,
        ) -> Result<Option<PreparedGeneration>, Self::Error> {
            self.inner.prepare_address_successor(inputs)
        }

        fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
            self.decision
        }

        fn invalidate_latest_capture_path_decision(&mut self) {
            self.decision = None;
            self.invalidations = self.invalidations.saturating_add(1);
        }

        fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            if self.rejection_failures > 0 {
                self.rejection_failures -= 1;
                return Err(io::Error::other(
                    "injected prepared candidate rejection failure",
                ));
            }
            self.inner.reject_prepared(generation)
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)
        }

        fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl RuntimeWriter for ScriptedWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            let id = GenerationId::new(self.next_generation_id)
                .ok_or_else(|| io::Error::other("scripted generation must be nonzero"))?;
            self.next_generation_id = id
                .get()
                .checked_add(1)
                .ok_or_else(|| io::Error::other("scripted generation counter exhausted"))?;
            self.events
                .lock()
                .expect("events lock")
                .push(Event::Prepared(reason));
            let spec = self
                .prepared
                .pop_front()
                .ok_or_else(|| io::Error::other("no scripted generation remains"))?;
            Ok(PreparedGeneration::new(
                id,
                spec,
                test_xtables_capture_path_selection(),
                qualified_xtables_capture_path_evidence().valid_until(),
            ))
        }

        fn prepare_address_successor(
            &mut self,
            _inputs: &crate::generation_engine_config::AddressReconciledGenerationInputs,
        ) -> Result<Option<PreparedGeneration>, Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::AddressSuccessorPrepared);
            Ok(None)
        }

        fn reject_prepared(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::PreparedRejected(generation.id()));
            Ok(())
        }

        fn capture_start(&mut self, _generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureStarted);
            if self.capture_start_failure {
                Err(io::Error::other("injected capture publication failure"))
            } else {
                Ok(())
            }
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureStopped);
            if self.capture_stop_failures > 0 {
                self.capture_stop_failures -= 1;
                Err(io::Error::other("injected capture detachment failure"))
            } else {
                Ok(())
            }
        }

        fn verify_capture(&mut self, _generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureVerified);
            if self.verify_failure {
                Err(io::Error::other("injected capture verification failure"))
            } else {
                Ok(())
            }
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::Published(phase));
            Ok(())
        }

        fn resync_addresses(&mut self) -> Result<AddressResyncDisposition, Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::AddressesResynchronized);
            Ok(AddressResyncDisposition::AcceptedDeferred)
        }
    }

    struct ScriptedEngine {
        events: Arc<Mutex<Vec<Event>>>,
        reports: Arc<Mutex<VecDeque<EngineReport>>>,
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
                        .expect("events lock")
                        .push(Event::EngineRunning(capture));
                    if let Some(report) = self.reports.lock().expect("reports lock").pop_front() {
                        return Ok(report);
                    }
                    Ok(EngineReport::Started {
                        revision: 1,
                        owned_resource_readiness: ReadinessEvidence::Listener {
                            port: NonZeroU16::new(1536).expect("nonzero port"),
                            table: PathBuf::from("/proc/1/net/tcp"),
                        },
                    })
                }
                DesiredEngine::Stopped => {
                    self.events
                        .lock()
                        .expect("events lock")
                        .push(Event::EngineStopped(capture));
                    if let Some(report) = self.reports.lock().expect("reports lock").pop_front() {
                        return Ok(report);
                    }
                    Ok(EngineReport::Stopped { revision: 1 })
                }
            }
        }

        fn snapshot(&self) -> Arc<EngineSnapshot> {
            Arc::new(EngineSnapshot::default())
        }

        fn open_canary_child_authority(
            &self,
            _expected: OwnedEngineIdentity,
            _expected_snapshot_revision: NonZeroU64,
            _expected_spec: &EngineSpec,
        ) -> Result<EngineChildAuthority, EngineChildAuthorityError> {
            Err(EngineChildAuthorityError::state_changed(
                "structural-only scripted engine has no canary child authority",
            ))
        }
    }

    #[derive(Clone, Copy)]
    enum ScriptedCanaryOutcome {
        Pass,
        Fail {
            kind: CanaryErrorKind,
            cleanup: CanaryCleanupStatus,
        },
    }

    struct ScriptedCanaryAttempt {
        request: CanaryAttemptRequest,
        outcome: ScriptedCanaryOutcome,
    }

    impl ScriptedCanaryAttempt {
        fn passing(request: CanaryAttemptRequest) -> Self {
            Self {
                request,
                outcome: ScriptedCanaryOutcome::Pass,
            }
        }

        fn failing(
            request: CanaryAttemptRequest,
            kind: CanaryErrorKind,
            cleanup: CanaryCleanupStatus,
        ) -> Self {
            Self {
                request,
                outcome: ScriptedCanaryOutcome::Fail { kind, cleanup },
            }
        }
    }

    struct ActiveCanaryAttempt {
        request: CanaryAttemptRequest,
        outcome: ScriptedCanaryOutcome,
    }

    struct ScriptedCanary {
        attempts: VecDeque<ScriptedCanaryAttempt>,
        active: Option<ActiveCanaryAttempt>,
        requests: Vec<CanaryAttemptRequest>,
        executions: usize,
    }

    impl ScriptedCanary {
        fn new(attempts: impl IntoIterator<Item = ScriptedCanaryAttempt>) -> Self {
            Self {
                attempts: attempts.into_iter().collect(),
                active: None,
                requests: Vec::new(),
                executions: 0,
            }
        }
    }

    struct ScriptedCanaryContext {
        script: Arc<Mutex<ScriptedCanary>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl UnqualifiedFunctionalCanaryAttemptContext for ScriptedCanaryContext {
        fn prepare_attempt(
            &mut self,
            generation: GenerationId,
        ) -> Result<UnqualifiedFunctionalCanaryAttemptInputs, FunctionalCanaryError> {
            let mut script = self.script.lock().expect("canary script");
            let attempt = script.attempts.pop_front().ok_or_else(|| {
                FunctionalCanaryError::new(
                    CanaryErrorKind::AdapterFailure,
                    CanaryCleanupStatus::NotRequired,
                    "no scripted functional canary attempt remains",
                )
            })?;
            if attempt.request.pre_binding().engine().generation() != generation {
                return Err(FunctionalCanaryError::new(
                    CanaryErrorKind::IdentityChanged,
                    CanaryCleanupStatus::NotRequired,
                    "scripted canary generation does not match the active generation",
                ));
            }
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CanaryPrepared(generation));
            let environment = attempt.request.pre_binding().environment().clone();
            let socket_observer = CanaryAttemptSocketObserverSession::scripted(
                environment.authority().socket_observer_binding(),
                attempt.request.deadline(),
            );
            let inputs = UnqualifiedFunctionalCanaryAttemptInputs::new(
                environment,
                socket_observer,
                attempt.request.nonce(),
                attempt.request.families(),
                attempt.request.counter_bounds(),
            )?;
            script.active = Some(ActiveCanaryAttempt {
                request: attempt.request,
                outcome: attempt.outcome,
            });
            Ok(inputs)
        }

        fn reobserve_environment(
            &mut self,
            request: &CanaryAttemptRequest,
        ) -> Result<CanaryEnvironmentBinding, FunctionalCanaryError> {
            let script = self.script.lock().expect("canary script");
            let active = script.active.as_ref().ok_or_else(|| {
                FunctionalCanaryError::new(
                    CanaryErrorKind::AdapterFailure,
                    CanaryCleanupStatus::NotRequired,
                    "functional canary has no active scripted attempt",
                )
            })?;
            if &active.request != request {
                return Err(FunctionalCanaryError::new(
                    CanaryErrorKind::IdentityChanged,
                    CanaryCleanupStatus::NotRequired,
                    "post-attempt observation received a different request",
                ));
            }
            let generation = request.pre_binding().engine().generation();
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CanaryReobserved(generation));
            Ok(request.pre_binding().environment().clone())
        }

        fn monotonic_now(&mut self) -> Instant {
            let mut script = self.script.lock().expect("canary script");
            let active = script
                .active
                .take()
                .expect("post-attempt clock requires an active canary");
            FunctionalCanaryFixture::from_request(active.request).observed_at()
        }
    }

    struct ScriptedCanaryExecutor {
        script: Arc<Mutex<ScriptedCanary>>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    impl UnqualifiedFunctionalCanaryExecutor for ScriptedCanaryExecutor {
        fn execute(
            &mut self,
            execution: UnqualifiedFunctionalCanaryExecution<'_>,
        ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
            let request = execution.request();
            if execution.socket_observer_authority()
                != request
                    .pre_binding()
                    .environment()
                    .authority()
                    .socket_observer()
            {
                return Err(FunctionalCanaryError::new(
                    CanaryErrorKind::IdentityChanged,
                    CanaryCleanupStatus::NotRequired,
                    "scripted executor received the wrong attempt-owned socket observer",
                ));
            }
            let (request, _socket_observer, engine_child) = execution.into_parts()?;
            debug_assert_eq!(
                engine_child.identity(),
                request.pre_binding().engine().engine()
            );
            debug_assert_ne!(engine_child.opening_id().get(), 0);
            let mut script = self.script.lock().expect("canary script");
            let active = script.active.as_ref().ok_or_else(|| {
                FunctionalCanaryError::new(
                    CanaryErrorKind::AdapterFailure,
                    CanaryCleanupStatus::NotRequired,
                    "functional canary executor has no active attempt",
                )
            })?;
            if &active.request != request {
                return Err(FunctionalCanaryError::new(
                    CanaryErrorKind::IdentityChanged,
                    CanaryCleanupStatus::NotRequired,
                    "functional canary executor received a different request",
                ));
            }
            let outcome = active.outcome;
            let generation = request.pre_binding().engine().generation();
            script.requests.push(request.clone());
            script.executions += 1;
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CanaryExecuted(generation));
            match outcome {
                ScriptedCanaryOutcome::Pass => Ok(FunctionalCanaryFixture::from_request(
                    request.clone(),
                )
                .successful_evidence()),
                ScriptedCanaryOutcome::Fail { kind, cleanup } => Err(FunctionalCanaryError::new(
                    kind,
                    cleanup,
                    "injected functional canary failure",
                )),
            }
        }
    }

    fn scripted_required_canary(
        script: Arc<Mutex<ScriptedCanary>>,
        events: Arc<Mutex<Vec<Event>>>,
    ) -> RuntimeFunctionalCanary {
        RuntimeFunctionalCanary::RequiredUnqualified {
            context: Box::new(ScriptedCanaryContext {
                script: Arc::clone(&script),
                events: Arc::clone(&events),
            }),
            executor: Box::new(ScriptedCanaryExecutor { script, events }),
        }
    }

    struct RequiredScriptedEngine {
        events: Arc<Mutex<Vec<Event>>>,
        reports: VecDeque<EngineReport>,
        fail_next_running: bool,
        fail_running_on_call: Option<usize>,
        running_calls: usize,
        snapshots: Arc<Mutex<VecDeque<Arc<EngineSnapshot>>>>,
        current_snapshot: Arc<Mutex<Arc<EngineSnapshot>>>,
        authority_openings: Arc<Mutex<Vec<OwnedEngineIdentity>>>,
        authority_failure: Arc<Mutex<Option<io::ErrorKind>>>,
    }

    impl RequiredScriptedEngine {
        fn new(
            events: Arc<Mutex<Vec<Event>>>,
            snapshots: impl IntoIterator<Item = Arc<EngineSnapshot>>,
        ) -> Self {
            Self {
                events,
                reports: VecDeque::new(),
                fail_next_running: false,
                fail_running_on_call: None,
                running_calls: 0,
                snapshots: Arc::new(Mutex::new(snapshots.into_iter().collect())),
                current_snapshot: Arc::new(Mutex::new(Arc::new(EngineSnapshot::default()))),
                authority_openings: Arc::new(Mutex::new(Vec::new())),
                authority_failure: Arc::new(Mutex::new(None)),
            }
        }

        fn authority_openings(&self) -> Arc<Mutex<Vec<OwnedEngineIdentity>>> {
            Arc::clone(&self.authority_openings)
        }

        fn fail_next_authority_opening(&self, kind: io::ErrorKind) {
            *self
                .authority_failure
                .lock()
                .expect("authority failure lock") = Some(kind);
        }
    }

    impl EngineRuntime for RequiredScriptedEngine {
        fn reconcile(
            &mut self,
            desired: DesiredEngine<'_>,
            capture: CaptureObservation,
        ) -> Result<EngineReport, EngineSupervisorError> {
            match desired {
                DesiredEngine::Running(_) => {
                    self.running_calls += 1;
                    self.events
                        .lock()
                        .expect("events lock")
                        .push(Event::EngineRunning(capture));
                    if std::mem::take(&mut self.fail_next_running) {
                        return Err(EngineSupervisorError::InvariantViolation {
                            diagnostic: "injected required-engine reconciliation failure"
                                .to_owned(),
                        });
                    }
                    if self.fail_running_on_call == Some(self.running_calls) {
                        return Err(EngineSupervisorError::InvariantViolation {
                            diagnostic: "injected scheduled required-engine reconciliation failure"
                                .to_owned(),
                        });
                    }
                    Ok(self.reports.pop_front().unwrap_or(EngineReport::Started {
                        revision: 1,
                        owned_resource_readiness: ReadinessEvidence::Listener {
                            port: NonZeroU16::new(1536).expect("nonzero port"),
                            table: PathBuf::from("/proc/4242/net/tcp"),
                        },
                    }))
                }
                DesiredEngine::Stopped => {
                    self.events
                        .lock()
                        .expect("events lock")
                        .push(Event::EngineStopped(capture));
                    Ok(self
                        .reports
                        .pop_front()
                        .unwrap_or(EngineReport::Stopped { revision: 1 }))
                }
            }
        }

        fn snapshot(&self) -> Arc<EngineSnapshot> {
            if let Some(snapshot) = self.snapshots.lock().expect("snapshots lock").pop_front() {
                *self.current_snapshot.lock().expect("current snapshot lock") =
                    Arc::clone(&snapshot);
                snapshot
            } else {
                Arc::clone(&self.current_snapshot.lock().expect("current snapshot lock"))
            }
        }

        fn open_canary_child_authority(
            &self,
            expected: OwnedEngineIdentity,
            expected_snapshot_revision: NonZeroU64,
            _expected_spec: &EngineSpec,
        ) -> Result<EngineChildAuthority, EngineChildAuthorityError> {
            if let Some(kind) = self
                .authority_failure
                .lock()
                .expect("authority failure lock")
                .take()
            {
                return Err(EngineChildAuthorityError::ProcessHandle {
                    source: flux_platform::ProcessHandleError::SystemCall {
                        operation: "open scripted engine child authority",
                        path: None,
                        source: io::Error::from(kind),
                    },
                });
            }
            let snapshot = self.current_snapshot.lock().expect("current snapshot lock");
            if snapshot.phase() != EnginePhase::Ready
                || snapshot.owned_identity() != Some(expected)
                || snapshot.revision() != expected_snapshot_revision.get()
            {
                return Err(EngineChildAuthorityError::state_changed(
                    "scripted engine snapshot changed before authority opening",
                ));
            }
            self.authority_openings
                .lock()
                .expect("authority openings lock")
                .push(expected);
            Ok(EngineChildAuthority::scripted(
                expected,
                expected_snapshot_revision,
                Instant::now(),
            ))
        }
    }

    fn ready_canary_snapshot(start_time_ticks: u64) -> Arc<EngineSnapshot> {
        ready_canary_snapshot_for(4242, start_time_ticks, 23)
    }

    fn ready_canary_snapshot_for(
        pid: u32,
        start_time_ticks: u64,
        revision: u64,
    ) -> Arc<EngineSnapshot> {
        Arc::new(EngineSnapshot::ready_for_test(
            NonZeroU64::new(revision).expect("nonzero engine revision"),
            OwnedEngineIdentity::new(
                NonZeroU32::new(pid).expect("nonzero engine PID"),
                NonZeroU64::new(start_time_ticks).expect("nonzero engine start ticks"),
            ),
            ReadinessEvidence::Listener {
                port: NonZeroU16::new(1536).expect("nonzero listener port"),
                table: PathBuf::from(format!("/proc/{pid}/net/tcp")),
            },
        ))
    }

    struct EngineFixture {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl EngineFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create engine fixture");
            let binary = directory.path().join("sing-box");
            let config = directory.path().join("config.json");
            fs::write(&binary, b"sing-box").expect("write binary");
            fs::write(&config, b"{}").expect("write config");
            let restart = RestartPolicy::new(
                3,
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::from_secs(10),
            )
            .expect("valid restart policy");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary,
                    config,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    launcher: SingBoxLauncher::Direct,
                    readiness: SingBoxReadiness::Listener {
                        port: NonZeroU16::new(1536).expect("nonzero port"),
                    },
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                restart,
            )
            .expect("inspect engine spec");
            Self {
                spec,
                _directory: directory,
            }
        }
    }
}
