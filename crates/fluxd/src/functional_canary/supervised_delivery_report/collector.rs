use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use flux_platform::{PlatformError, SeqpacketConnection, SeqpacketReceive};

#[cfg(test)]
use super::SupervisedDeliveryReportSchemaV2FixtureAuthority;
use super::{
    CompletedSupervisedDeliveryReport, SupervisedDeliveryReportBindError,
    SupervisedDeliveryReportDatagram, SupervisedDeliveryReportError,
    SupervisedDeliveryReportParser, SupervisedDeliveryReportParserAuthority,
};
use crate::functional_canary::{
    CanaryAttemptObjectIdentity, CanaryAttemptObjectRetirementEvidence, CanaryAttemptRequest,
    CanaryProcessRetirementEvidence,
};
#[cfg(test)]
use crate::functional_canary::{
    CanaryEvidenceError, CanaryFlow, UnqualifiedCanaryGateEvidence,
    UnqualifiedCanaryInboundListenerDeliveryEvidence, ValidatedUnqualifiedCanaryGateEvidence,
};
use crate::generation_engine_config::{
    ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES, EngineCapabilityProfile,
    EngineCapabilityProfileRevision,
};

#[derive(Debug)]
pub(super) enum SupervisedDeliveryReportCollectorError {
    Bind(SupervisedDeliveryReportBindError),
    Transport(PlatformError),
    OpeningIdentityExhausted,
    DeadlineExpired,
    InvalidReport(SupervisedDeliveryReportError),
    ClientRetirementAuthorityMismatch,
    InvalidClientRetirement,
    InvalidReceiverRetirement,
}

impl fmt::Display for SupervisedDeliveryReportCollectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(error) => error.fmt(formatter),
            Self::Transport(error) => write!(
                formatter,
                "supervised delivery-report seqpacket transport failed: {error}"
            ),
            Self::OpeningIdentityExhausted => formatter
                .write_str("supervised delivery-report transport opening identity exhausted"),
            Self::DeadlineExpired => {
                formatter.write_str("supervised delivery-report collection deadline expired")
            }
            Self::InvalidReport(error) => error.fmt(formatter),
            Self::ClientRetirementAuthorityMismatch => formatter.write_str(
                "supervised delivery-report client retirement belongs to another request",
            ),
            Self::InvalidClientRetirement => formatter.write_str(
                "supervised delivery-report receiver cannot retire from invalid client evidence",
            ),
            Self::InvalidReceiverRetirement => formatter
                .write_str("supervised delivery-report receiver retirement chronology is invalid"),
        }
    }
}

impl Error for SupervisedDeliveryReportCollectorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::InvalidReport(error) => Some(error),
            Self::OpeningIdentityExhausted
            | Self::DeadlineExpired
            | Self::ClientRetirementAuthorityMismatch
            | Self::InvalidClientRetirement
            | Self::InvalidReceiverRetirement => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CanaryListenerDeliveryReportCleanupEvidence {
    disposition: CanaryListenerDeliveryReportCleanupDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::functional_canary) enum CanaryListenerDeliveryReportCleanupDisposition {
    Retired(CanaryAttemptObjectRetirementEvidence),
    VerifiedNeverCreated {
        object: CanaryAttemptObjectIdentity,
        absent_observed_at: Instant,
    },
}

impl CanaryListenerDeliveryReportCleanupEvidence {
    const fn from_retired_collector(evidence: CanaryAttemptObjectRetirementEvidence) -> Self {
        Self {
            disposition: CanaryListenerDeliveryReportCleanupDisposition::Retired(evidence),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn retired(evidence: CanaryAttemptObjectRetirementEvidence) -> Self {
        Self::from_retired_collector(evidence)
    }

    #[must_use]
    pub(crate) const fn verified_never_created(
        object: CanaryAttemptObjectIdentity,
        absent_observed_at: Instant,
    ) -> Self {
        Self {
            disposition: CanaryListenerDeliveryReportCleanupDisposition::VerifiedNeverCreated {
                object,
                absent_observed_at,
            },
        }
    }

    #[must_use]
    pub(in crate::functional_canary) const fn disposition(
        self,
    ) -> CanaryListenerDeliveryReportCleanupDisposition {
        self.disposition
    }

    #[cfg(test)]
    pub(crate) const fn retired_mut(
        &mut self,
    ) -> Option<&mut CanaryAttemptObjectRetirementEvidence> {
        match &mut self.disposition {
            CanaryListenerDeliveryReportCleanupDisposition::Retired(evidence) => Some(evidence),
            CanaryListenerDeliveryReportCleanupDisposition::VerifiedNeverCreated { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn never_created_absence_mut(&mut self) -> Option<&mut Instant> {
        match &mut self.disposition {
            CanaryListenerDeliveryReportCleanupDisposition::Retired(_) => None,
            CanaryListenerDeliveryReportCleanupDisposition::VerifiedNeverCreated {
                absent_observed_at,
                ..
            } => Some(absent_observed_at),
        }
    }
}

pub(super) struct SupervisedDeliveryReportTransportBinding {
    opening_id: NonZeroU64,
    report_object: CanaryAttemptObjectIdentity,
    profile_revision: EngineCapabilityProfileRevision,
    request: CanaryAttemptRequest,
}

impl SupervisedDeliveryReportTransportBinding {
    #[must_use]
    const fn request(&self) -> &CanaryAttemptRequest {
        &self.request
    }

    #[must_use]
    const fn report_object(&self) -> CanaryAttemptObjectIdentity {
        self.report_object
    }

    #[must_use]
    const fn profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.profile_revision
    }
}

impl fmt::Debug for SupervisedDeliveryReportTransportBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedDeliveryReportTransportBinding")
            .field("opening_id", &self.opening_id)
            .field("report_object", &self.report_object)
            .field("profile_revision", &self.profile_revision)
            .finish_non_exhaustive()
    }
}

static NEXT_SUPERVISED_DELIVERY_REPORT_OPENING_ID: AtomicU64 = AtomicU64::new(1);

/// Single-use authority for opening the report object named by one immutable attempt.
///
/// Production construction remains deliberately unavailable until the prepared driver owns an
/// authoritative report producer. The test constructor models that future consumed authority.
#[must_use = "the report-object prebind authority must be consumed exactly once"]
pub(super) struct SupervisedDeliveryReportPrebindAuthority {
    profile: EngineCapabilityProfile,
    request: CanaryAttemptRequest,
}

impl SupervisedDeliveryReportPrebindAuthority {
    #[cfg(test)]
    pub(super) fn fixture(
        profile: &EngineCapabilityProfile,
        request: &CanaryAttemptRequest,
    ) -> Self {
        Self {
            profile: profile.clone(),
            request: request.clone(),
        }
    }
}

/// Prebound producer endpoint that can be handed to the supervised engine only once.
#[must_use = "the prebound producer must be consumed into its engine handoff"]
pub(super) struct SupervisedDeliveryReportProducer {
    connection: SeqpacketConnection,
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
}

impl SupervisedDeliveryReportProducer {
    pub(super) fn into_engine_handoff(self) -> SupervisedDeliveryReportEngineHandoff {
        SupervisedDeliveryReportEngineHandoff {
            connection: self.connection,
            binding: self.binding,
        }
    }
}

/// Identity-bearing writer endpoint consumed by the supervised report producer.
///
/// This interface intentionally exposes record send rather than a raw descriptor. A future
/// prepared-child adapter may consume this type without reopening socket ownership in `fluxd`.
#[must_use = "the engine report handoff must remain owned until the producer has stopped"]
pub(super) struct SupervisedDeliveryReportEngineHandoff {
    connection: SeqpacketConnection,
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
}

impl SupervisedDeliveryReportEngineHandoff {
    #[must_use]
    pub(super) fn request(&self) -> &CanaryAttemptRequest {
        self.binding.request()
    }

    #[must_use]
    pub(super) fn report_object(&self) -> CanaryAttemptObjectIdentity {
        self.binding.report_object()
    }

    #[must_use]
    pub(super) fn profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.binding.profile_revision()
    }

    pub(super) fn send_frame(&self, frame: &[u8]) -> Result<(), PlatformError> {
        self.connection.send_packet(frame)
    }
}

impl fmt::Debug for SupervisedDeliveryReportEngineHandoff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupervisedDeliveryReportEngineHandoff")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

struct PendingSupervisedDeliveryReportReceiver<C> {
    connection: SeqpacketConnection,
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    clock: C,
}

/// Request/profile-bound owner of the sole report receiver and parser.
pub(super) struct SupervisedDeliveryReportCollector<C> {
    receiver: PendingSupervisedDeliveryReportReceiver<C>,
    parser: SupervisedDeliveryReportParser,
}

/// Prebinds one parser and one anonymous record transport from consumed attempt authority.
pub(super) fn prebind<C>(
    authority: SupervisedDeliveryReportPrebindAuthority,
    clock: C,
) -> Result<
    (
        SupervisedDeliveryReportProducer,
        SupervisedDeliveryReportCollector<C>,
    ),
    SupervisedDeliveryReportCollectorError,
>
where
    C: FnMut() -> Instant,
{
    let SupervisedDeliveryReportPrebindAuthority { profile, request } = authority;
    let parser = SupervisedDeliveryReportParser::bind(
        SupervisedDeliveryReportParserAuthority::collector(),
        &profile,
        &request,
    )
    .map_err(SupervisedDeliveryReportCollectorError::Bind)?;
    let binding = Arc::new(SupervisedDeliveryReportTransportBinding {
        opening_id: next_report_opening_id()?,
        report_object: request
            .pre_binding()
            .environment()
            .attempt_objects()
            .listener_delivery_report(),
        profile_revision: profile.revision(),
        request,
    });
    let (producer, receiver) =
        SeqpacketConnection::pair().map_err(SupervisedDeliveryReportCollectorError::Transport)?;
    Ok((
        SupervisedDeliveryReportProducer {
            connection: producer,
            binding: Arc::clone(&binding),
        },
        SupervisedDeliveryReportCollector {
            receiver: PendingSupervisedDeliveryReportReceiver {
                connection: receiver,
                binding,
                clock,
            },
            parser,
        },
    ))
}

fn next_report_opening_id() -> Result<NonZeroU64, SupervisedDeliveryReportCollectorError> {
    let raw = NEXT_SUPERVISED_DELIVERY_REPORT_OPENING_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| SupervisedDeliveryReportCollectorError::OpeningIdentityExhausted)?;
    NonZeroU64::new(raw).ok_or(SupervisedDeliveryReportCollectorError::OpeningIdentityExhausted)
}

impl<C> SupervisedDeliveryReportCollector<C>
where
    C: FnMut() -> Instant,
{
    pub(super) fn drain(
        self,
    ) -> Result<
        DrainedSupervisedDeliveryReportCollector<C>,
        Box<FailedSupervisedDeliveryReportCollector<C>>,
    > {
        let Self {
            mut receiver,
            mut parser,
        } = self;
        let expires_at = receiver.binding.request().deadline().expires_at();
        loop {
            let received = match receiver.connection.recv_record_until(
                usize::from(ENGINE_SUPERVISED_DELIVERY_REPORT_MAX_FRAME_BYTES),
                expires_at,
            ) {
                Ok(received) => received,
                Err(error) => {
                    return Err(Box::new(FailedSupervisedDeliveryReportCollector::new(
                        receiver,
                        SupervisedDeliveryReportCollectorError::Transport(error),
                    )));
                }
            };
            match received {
                None => {
                    return Err(Box::new(FailedSupervisedDeliveryReportCollector::new(
                        receiver,
                        SupervisedDeliveryReportCollectorError::DeadlineExpired,
                    )));
                }
                Some(SeqpacketReceive::Record { bytes, truncated }) => {
                    if let Err(error) = parser.ingest(SupervisedDeliveryReportDatagram::new(
                        &bytes,
                        truncated,
                        (receiver.clock)(),
                    )) {
                        return Err(Box::new(FailedSupervisedDeliveryReportCollector::new(
                            receiver,
                            SupervisedDeliveryReportCollectorError::InvalidReport(error),
                        )));
                    }
                }
                Some(SeqpacketReceive::Eof) => {
                    let report = match parser.observe_drained_eof((receiver.clock)()) {
                        Ok(report) => report,
                        Err(error) => {
                            return Err(Box::new(FailedSupervisedDeliveryReportCollector::new(
                                receiver,
                                SupervisedDeliveryReportCollectorError::InvalidReport(error),
                            )));
                        }
                    };
                    return Ok(DrainedSupervisedDeliveryReportCollector { receiver, report });
                }
            }
        }
    }
}

/// Failed collection that still owns the receiver required for ordered cleanup.
#[must_use = "failed report collection still owns a receiver that must be retired"]
pub(super) struct FailedSupervisedDeliveryReportCollector<C> {
    receiver: PendingSupervisedDeliveryReportReceiver<C>,
    collection_error: SupervisedDeliveryReportCollectorError,
}

impl<C> FailedSupervisedDeliveryReportCollector<C> {
    fn new(
        receiver: PendingSupervisedDeliveryReportReceiver<C>,
        collection_error: SupervisedDeliveryReportCollectorError,
    ) -> Self {
        Self {
            receiver,
            collection_error,
        }
    }

    #[must_use]
    pub(super) const fn collection_error(&self) -> &SupervisedDeliveryReportCollectorError {
        &self.collection_error
    }

    #[must_use]
    pub(super) fn binding(&self) -> Arc<SupervisedDeliveryReportTransportBinding> {
        Arc::clone(&self.receiver.binding)
    }
}

impl<C> fmt::Debug for FailedSupervisedDeliveryReportCollector<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FailedSupervisedDeliveryReportCollector")
            .field("binding", &self.receiver.binding)
            .field("collection_error", &self.collection_error)
            .finish_non_exhaustive()
    }
}

impl<C> fmt::Display for FailedSupervisedDeliveryReportCollector<C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.collection_error.fmt(formatter)
    }
}

impl<C> Error for FailedSupervisedDeliveryReportCollector<C> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.collection_error)
    }
}

/// Completed report that deliberately retains the sole receiver until cleanup retirement.
pub(super) struct DrainedSupervisedDeliveryReportCollector<C> {
    receiver: PendingSupervisedDeliveryReportReceiver<C>,
    report: CompletedSupervisedDeliveryReport,
}

impl<C> DrainedSupervisedDeliveryReportCollector<C> {
    #[must_use]
    pub(super) fn binding(&self) -> Arc<SupervisedDeliveryReportTransportBinding> {
        Arc::clone(&self.receiver.binding)
    }

    #[must_use]
    pub(super) const fn report_object(&self) -> CanaryAttemptObjectIdentity {
        self.report.report_object()
    }

    #[must_use]
    pub(super) const fn profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.report.profile_revision()
    }

    #[must_use]
    pub(super) const fn terminal_observed_at(&self) -> Instant {
        self.report.terminal_observed_at()
    }

    #[must_use]
    pub(super) const fn eof_observed_at(&self) -> Instant {
        self.report.eof_observed_at()
    }
}

/// Non-cloneable request-bound proof that the exact attempt client was parent-reaped.
///
/// Production construction remains unavailable until the prepared driver returns its retained
/// child-origin proof. Tests can model that future authority without opening production code.
#[must_use = "client retirement authority must be consumed by receiver retirement"]
pub(super) struct SupervisedDeliveryReportClientRetirementAuthority {
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    retirement: CanaryProcessRetirementEvidence,
}

impl SupervisedDeliveryReportClientRetirementAuthority {
    #[cfg(test)]
    pub(super) fn fixture(
        binding: Arc<SupervisedDeliveryReportTransportBinding>,
        retirement: CanaryProcessRetirementEvidence,
    ) -> Self {
        Self {
            binding,
            retirement,
        }
    }
}

/// Retirement failure that distinguishes a still-owned receiver from a resource already closed.
#[must_use = "retirement failure may still own the report receiver"]
pub(super) struct SupervisedDeliveryReportRetirementFailure<T> {
    state: SupervisedDeliveryReportRetirementFailureState<T>,
}

enum SupervisedDeliveryReportRetirementFailureState<T> {
    ReceiverRetained {
        owner: Box<T>,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
        error: SupervisedDeliveryReportCollectorError,
    },
    ReceiverRetiredWithoutCleanupEvidence(Box<UnverifiedSupervisedDeliveryReportRetirement>),
}

pub(super) enum SupervisedDeliveryReportRetirementFailureDisposition<T> {
    ReceiverRetained {
        owner: Box<T>,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
    },
    ReceiverRetiredWithoutCleanupEvidence(Box<UnverifiedSupervisedDeliveryReportRetirement>),
}

enum UnverifiedSupervisedDeliveryReportOutcome {
    Completed(Box<CompletedSupervisedDeliveryReport>),
    CollectionFailed(SupervisedDeliveryReportCollectorError),
}

/// A receiver that was destroyed but whose post-drop observation failed validation.
///
/// This terminal state retains chronology and collection diagnostics, but deliberately exposes no
/// cleanup evidence and cannot be converted into a promotable report.
pub(super) struct UnverifiedSupervisedDeliveryReportRetirement {
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    client_retirement: CanaryProcessRetirementEvidence,
    retired_at: Instant,
    absent_observed_at: Instant,
    error: SupervisedDeliveryReportCollectorError,
    outcome: UnverifiedSupervisedDeliveryReportOutcome,
}

impl UnverifiedSupervisedDeliveryReportRetirement {
    #[must_use]
    pub(super) const fn error(&self) -> &SupervisedDeliveryReportCollectorError {
        &self.error
    }

    #[must_use]
    pub(super) fn report_object(&self) -> CanaryAttemptObjectIdentity {
        self.binding.report_object()
    }

    #[must_use]
    pub(super) fn profile_revision(&self) -> EngineCapabilityProfileRevision {
        self.binding.profile_revision()
    }

    #[must_use]
    pub(super) const fn client_retirement(&self) -> CanaryProcessRetirementEvidence {
        self.client_retirement
    }

    #[must_use]
    pub(super) const fn retired_at(&self) -> Instant {
        self.retired_at
    }

    #[must_use]
    pub(super) const fn absent_observed_at(&self) -> Instant {
        self.absent_observed_at
    }

    #[must_use]
    pub(super) fn completed_report(&self) -> Option<&CompletedSupervisedDeliveryReport> {
        match &self.outcome {
            UnverifiedSupervisedDeliveryReportOutcome::Completed(report) => Some(report.as_ref()),
            UnverifiedSupervisedDeliveryReportOutcome::CollectionFailed(_) => None,
        }
    }

    #[must_use]
    pub(super) const fn collection_error(&self) -> Option<&SupervisedDeliveryReportCollectorError> {
        match &self.outcome {
            UnverifiedSupervisedDeliveryReportOutcome::Completed(_) => None,
            UnverifiedSupervisedDeliveryReportOutcome::CollectionFailed(error) => Some(error),
        }
    }
}

impl<T> SupervisedDeliveryReportRetirementFailure<T> {
    fn retained(
        owner: T,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
        error: SupervisedDeliveryReportCollectorError,
    ) -> Self {
        Self {
            state: SupervisedDeliveryReportRetirementFailureState::ReceiverRetained {
                owner: Box::new(owner),
                authority,
                error,
            },
        }
    }

    fn retired_without_cleanup_evidence(
        retirement: UnverifiedPendingReceiverRetirement,
        outcome: UnverifiedSupervisedDeliveryReportOutcome,
    ) -> Self {
        let UnverifiedPendingReceiverRetirement {
            binding,
            client_retirement,
            retired_at,
            absent_observed_at,
            error,
        } = retirement;
        Self {
            state:
                SupervisedDeliveryReportRetirementFailureState::ReceiverRetiredWithoutCleanupEvidence(
                    Box::new(UnverifiedSupervisedDeliveryReportRetirement {
                        binding,
                        client_retirement,
                        retired_at,
                        absent_observed_at,
                        error,
                        outcome,
                    }),
                ),
        }
    }

    #[must_use]
    pub(super) const fn error(&self) -> &SupervisedDeliveryReportCollectorError {
        match &self.state {
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetained { error, .. } => error,
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ) => retirement.error(),
        }
    }

    pub(super) fn into_disposition(
        self,
    ) -> SupervisedDeliveryReportRetirementFailureDisposition<T> {
        match self.state {
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetained {
                owner, authority, ..
            } => SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetained {
                owner,
                authority,
            },
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ) => SupervisedDeliveryReportRetirementFailureDisposition::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ),
        }
    }
}

impl<T> fmt::Debug for SupervisedDeliveryReportRetirementFailure<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.state {
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetained { error, .. } => formatter
                .debug_struct("SupervisedDeliveryReportRetirementFailure::ReceiverRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            SupervisedDeliveryReportRetirementFailureState::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            ) => formatter
                .debug_struct(
                    "SupervisedDeliveryReportRetirementFailure::ReceiverRetiredWithoutCleanupEvidence",
                )
                .field("binding", &retirement.binding)
                .field("client_retirement", &retirement.client_retirement)
                .field("retired_at", &retirement.retired_at)
                .field("absent_observed_at", &retirement.absent_observed_at)
                .field("error", &retirement.error)
                .finish(),
        }
    }
}

impl<T> fmt::Display for SupervisedDeliveryReportRetirementFailure<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error().fmt(formatter)
    }
}

impl<T> Error for SupervisedDeliveryReportRetirementFailure<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.error())
    }
}

impl<C> DrainedSupervisedDeliveryReportCollector<C>
where
    C: FnMut() -> Instant,
{
    pub(super) fn retire_after_client(
        self,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
    ) -> Result<RetiredSupervisedDeliveryReport, SupervisedDeliveryReportRetirementFailure<Self>>
    {
        if self.receiver.binding.report_object() != self.report.report_object()
            || self.receiver.binding.profile_revision() != self.report.profile_revision()
        {
            return Err(SupervisedDeliveryReportRetirementFailure::retained(
                self,
                authority,
                SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement,
            ));
        }
        let Self { receiver, report } = self;
        let requirements = ReceiverRetirementRequirements::completed(
            report.eof_observed_at(),
            receiver.binding.request().deadline().expires_at(),
        );
        match receiver.retire_after_client(authority, requirements) {
            Ok(retirement) => Ok(RetiredSupervisedDeliveryReport {
                report,
                binding: retirement.binding,
                client_retirement: retirement.client_retirement,
                report_cleanup: retirement.report_cleanup,
            }),
            Err(PendingReceiverRetirementFailure::ReceiverRetained {
                receiver,
                authority,
                error,
            }) => Err(SupervisedDeliveryReportRetirementFailure::retained(
                Self { receiver, report },
                authority,
                error,
            )),
            Err(PendingReceiverRetirementFailure::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            )) => Err(
                SupervisedDeliveryReportRetirementFailure::retired_without_cleanup_evidence(
                    *retirement,
                    UnverifiedSupervisedDeliveryReportOutcome::Completed(Box::new(report)),
                ),
            ),
        }
    }
}

impl<C> FailedSupervisedDeliveryReportCollector<C>
where
    C: FnMut() -> Instant,
{
    pub(super) fn retire_after_client(
        self,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
    ) -> Result<
        RetiredFailedSupervisedDeliveryReport,
        SupervisedDeliveryReportRetirementFailure<Self>,
    > {
        let Self {
            receiver,
            collection_error,
        } = self;
        match receiver.retire_after_client(authority, ReceiverRetirementRequirements::failed()) {
            Ok(retirement) => Ok(RetiredFailedSupervisedDeliveryReport {
                collection_error,
                client_retirement: retirement.client_retirement,
                report_cleanup: retirement.report_cleanup,
            }),
            Err(PendingReceiverRetirementFailure::ReceiverRetained {
                receiver,
                authority,
                error,
            }) => Err(SupervisedDeliveryReportRetirementFailure::retained(
                Self {
                    receiver,
                    collection_error,
                },
                authority,
                error,
            )),
            Err(PendingReceiverRetirementFailure::ReceiverRetiredWithoutCleanupEvidence(
                retirement,
            )) => Err(
                SupervisedDeliveryReportRetirementFailure::retired_without_cleanup_evidence(
                    *retirement,
                    UnverifiedSupervisedDeliveryReportOutcome::CollectionFailed(collection_error),
                ),
            ),
        }
    }
}

#[derive(Clone, Copy)]
struct ReceiverRetirementRequirements {
    earliest_retired_at: Option<Instant>,
    exclusive_deadline: Option<Instant>,
}

impl ReceiverRetirementRequirements {
    const fn completed(eof_observed_at: Instant, exclusive_deadline: Instant) -> Self {
        Self {
            earliest_retired_at: Some(eof_observed_at),
            exclusive_deadline: Some(exclusive_deadline),
        }
    }

    const fn failed() -> Self {
        Self {
            earliest_retired_at: None,
            exclusive_deadline: None,
        }
    }
}

struct VerifiedPendingReceiverRetirement {
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    client_retirement: CanaryProcessRetirementEvidence,
    report_cleanup: CanaryListenerDeliveryReportCleanupEvidence,
}

struct UnverifiedPendingReceiverRetirement {
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    client_retirement: CanaryProcessRetirementEvidence,
    retired_at: Instant,
    absent_observed_at: Instant,
    error: SupervisedDeliveryReportCollectorError,
}

enum PendingReceiverRetirementFailure<C> {
    ReceiverRetained {
        receiver: PendingSupervisedDeliveryReportReceiver<C>,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
        error: SupervisedDeliveryReportCollectorError,
    },
    ReceiverRetiredWithoutCleanupEvidence(Box<UnverifiedPendingReceiverRetirement>),
}

impl<C> PendingSupervisedDeliveryReportReceiver<C>
where
    C: FnMut() -> Instant,
{
    fn retire_after_client(
        mut self,
        authority: SupervisedDeliveryReportClientRetirementAuthority,
        requirements: ReceiverRetirementRequirements,
    ) -> Result<VerifiedPendingReceiverRetirement, PendingReceiverRetirementFailure<C>> {
        let client_retirement = match validate_client_retirement(
            &self.binding,
            &authority,
            requirements.exclusive_deadline.is_some(),
        ) {
            Ok(retirement) => retirement,
            Err(error) => {
                return Err(PendingReceiverRetirementFailure::ReceiverRetained {
                    receiver: self,
                    authority,
                    error,
                });
            }
        };
        let retired_at = (self.clock)();
        if retired_at < client_retirement.reaped_at
            || requirements
                .earliest_retired_at
                .is_some_and(|earliest| retired_at < earliest)
            || requirements
                .exclusive_deadline
                .is_some_and(|deadline| retired_at >= deadline)
        {
            return Err(PendingReceiverRetirementFailure::ReceiverRetained {
                receiver: self,
                authority,
                error: SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement,
            });
        }

        let Self {
            connection,
            binding,
            mut clock,
        } = self;
        drop(connection);
        let absent_observed_at = clock();
        if absent_observed_at < retired_at
            || requirements
                .exclusive_deadline
                .is_some_and(|deadline| absent_observed_at >= deadline)
        {
            return Err(
                PendingReceiverRetirementFailure::ReceiverRetiredWithoutCleanupEvidence(Box::new(
                    UnverifiedPendingReceiverRetirement {
                        binding,
                        client_retirement,
                        retired_at,
                        absent_observed_at,
                        error: SupervisedDeliveryReportCollectorError::InvalidReceiverRetirement,
                    },
                )),
            );
        }

        let report_cleanup = CanaryListenerDeliveryReportCleanupEvidence::from_retired_collector(
            CanaryAttemptObjectRetirementEvidence::new(
                binding.report_object(),
                retired_at,
                absent_observed_at,
            ),
        );
        Ok(VerifiedPendingReceiverRetirement {
            binding,
            client_retirement,
            report_cleanup,
        })
    }
}

fn validate_client_retirement(
    binding: &Arc<SupervisedDeliveryReportTransportBinding>,
    authority: &SupervisedDeliveryReportClientRetirementAuthority,
    require_before_deadline: bool,
) -> Result<CanaryProcessRetirementEvidence, SupervisedDeliveryReportCollectorError> {
    if !Arc::ptr_eq(&authority.binding, binding) {
        return Err(SupervisedDeliveryReportCollectorError::ClientRetirementAuthorityMismatch);
    }
    let retirement = authority.retirement;
    let deadline = binding.request().deadline();
    if retirement.quiesced_at > retirement.terminated_at
        || retirement.terminated_at > retirement.reaped_at
        || retirement.quiesced_at < deadline.started_at()
        || (require_before_deadline && retirement.reaped_at >= deadline.expires_at())
    {
        return Err(SupervisedDeliveryReportCollectorError::InvalidClientRetirement);
    }
    Ok(retirement)
}

/// Completed report plus cleanup evidence minted by consuming its receiver resource.
pub(super) struct RetiredSupervisedDeliveryReport {
    report: CompletedSupervisedDeliveryReport,
    binding: Arc<SupervisedDeliveryReportTransportBinding>,
    client_retirement: CanaryProcessRetirementEvidence,
    report_cleanup: CanaryListenerDeliveryReportCleanupEvidence,
}

impl RetiredSupervisedDeliveryReport {
    #[must_use]
    pub(super) const fn client_retirement(&self) -> CanaryProcessRetirementEvidence {
        self.client_retirement
    }

    #[must_use]
    pub(super) const fn report_cleanup(&self) -> CanaryListenerDeliveryReportCleanupEvidence {
        self.report_cleanup
    }
}

/// Failed report collection after ordered receiver destruction.
pub(super) struct RetiredFailedSupervisedDeliveryReport {
    collection_error: SupervisedDeliveryReportCollectorError,
    client_retirement: CanaryProcessRetirementEvidence,
    report_cleanup: CanaryListenerDeliveryReportCleanupEvidence,
}

impl RetiredFailedSupervisedDeliveryReport {
    #[must_use]
    pub(super) const fn collection_error(&self) -> &SupervisedDeliveryReportCollectorError {
        &self.collection_error
    }

    #[must_use]
    pub(super) const fn client_retirement(&self) -> CanaryProcessRetirementEvidence {
        self.client_retirement
    }

    #[must_use]
    pub(super) const fn report_cleanup(&self) -> CanaryListenerDeliveryReportCleanupEvidence {
        self.report_cleanup
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(super) enum SupervisedDeliveryReportFixtureError {
    RequestMismatch,
    ClientRetirementMismatch,
    TransportBindingMismatch,
    MissingFlow(CanaryFlow),
    UnexpectedFlow(CanaryFlow),
    MissingListener(CanaryFlow),
    NonTproxyListener(CanaryFlow),
    InvalidReport(SupervisedDeliveryReportError),
    InvalidGate(CanaryEvidenceError),
}

#[cfg(test)]
impl fmt::Display for SupervisedDeliveryReportFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cannot construct supervised delivery-report schema-v2 fixture: {self:?}"
        )
    }
}

#[cfg(test)]
impl Error for SupervisedDeliveryReportFixtureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidReport(error) => Some(error),
            Self::InvalidGate(error) => Some(error),
            Self::RequestMismatch
            | Self::ClientRetirementMismatch
            | Self::TransportBindingMismatch
            | Self::MissingFlow(_)
            | Self::UnexpectedFlow(_)
            | Self::MissingListener(_)
            | Self::NonTproxyListener(_) => None,
        }
    }
}

#[cfg(test)]
pub(super) fn validate_schema_v2_fixture(
    retired: RetiredSupervisedDeliveryReport,
    mut fixture: UnqualifiedCanaryGateEvidence,
    coordinator_observed_at: Instant,
) -> Result<ValidatedUnqualifiedCanaryGateEvidence, SupervisedDeliveryReportFixtureError> {
    let RetiredSupervisedDeliveryReport {
        mut report,
        binding,
        client_retirement,
        report_cleanup,
    } = retired;
    let request = binding.request();
    if fixture.request != *request {
        return Err(SupervisedDeliveryReportFixtureError::RequestMismatch);
    }
    if fixture.cleanup.client != client_retirement {
        return Err(SupervisedDeliveryReportFixtureError::ClientRetirementMismatch);
    }
    if binding.report_object() != report.report_object()
        || binding.profile_revision() != report.profile_revision()
    {
        return Err(SupervisedDeliveryReportFixtureError::TransportBindingMismatch);
    }

    let authority = SupervisedDeliveryReportSchemaV2FixtureAuthority::fixture();
    for flow in CanaryFlow::ALL {
        let parsed = report.take_event(flow);
        if !request.requires_flow(flow) {
            if parsed.is_some() {
                return Err(SupervisedDeliveryReportFixtureError::UnexpectedFlow(flow));
            }
            continue;
        }
        let parsed = parsed.ok_or(SupervisedDeliveryReportFixtureError::MissingFlow(flow))?;
        let flow_evidence = fixture.flows.slots[flow.index()]
            .as_mut()
            .ok_or(SupervisedDeliveryReportFixtureError::MissingFlow(flow))?;
        let existing = flow_evidence
            .inbound_listener_delivery
            .take()
            .ok_or(SupervisedDeliveryReportFixtureError::MissingListener(flow))?;
        let listener = match existing {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { listener, .. }
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { listener, .. } => {
                listener
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::Redirect
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::Dnat => {
                return Err(SupervisedDeliveryReportFixtureError::NonTproxyListener(
                    flow,
                ));
            }
        };
        flow_evidence.inbound_listener_delivery = Some(
            parsed
                .into_schema_v2_fixture(authority, listener)
                .map_err(SupervisedDeliveryReportFixtureError::InvalidReport)?,
        );
    }

    fixture.cleanup.listener_delivery_report = report_cleanup;
    fixture.local_output_capture_receipt =
        crate::functional_canary::local_output::TproxyLocalOutputCaptureReceipt::scripted(
            request,
            &fixture.flows,
        );
    fixture.local_output_process_ownership_receipt =
        crate::functional_canary::local_output::TproxyLocalOutputProcessOwnershipReceipt::scripted(
            request,
            &fixture.flows,
            &fixture.cleanup,
            fixture.completed_at,
        );
    fixture
        .validate_for(request, request.pre_binding(), coordinator_observed_at)
        .map_err(SupervisedDeliveryReportFixtureError::InvalidGate)
}
