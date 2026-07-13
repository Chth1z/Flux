//! Fail-closed local-OUTPUT functional-canary executor boundary.
//!
//! The selected request backend is always TPROXY. The current xtables capture
//! program can mark local OUTPUT, but its TPROXY action exists only in
//! PREROUTING, and the privileged harness proved that local policy routing does
//! not make those packets re-enter PREROUTING. Consequently the xtables driver
//! below has no prepared-attempt value and reports `Unsupported` before it can
//! acquire a networking writer or mutate capture state.
//!
//! Future device-specific drivers return raw observations only. Promotion into
//! schema-v2 gate evidence remains behind the private evidence-factory trait so
//! an adapter cannot substitute REDIRECT, DNAT, ingress traffic, counters, or a
//! route lookup for authoritative local-OUTPUT TPROXY listener delivery.
//! Attempt preparation also carries the exact non-cloneable socket-observer
//! session separately from the pure request. Read-only availability sees only
//! the request; a prepared driver receives the bound session once by value.

use std::convert::Infallible;

use super::{
    CanaryAttemptRequest, CanaryAttemptSocketObserverSession, CanaryAvailability,
    CanaryCaptureBackend, CanaryCleanupStatus, CanaryErrorKind, FunctionalCanaryError,
    UnqualifiedCanaryGateEvidence, UnqualifiedFunctionalCanaryExecution,
    UnqualifiedFunctionalCanaryExecutor, bounded_prefix,
};

const XTABLES_LOCAL_OUTPUT_UNSUPPORTED: &str = "the xtables capture program marks local OUTPUT but applies TPROXY only in PREROUTING; local routing does not re-enter that hook, and REDIRECT, DNAT, ingress traffic, counters, and route lookups are prohibited substitutes";
const NON_TPROXY_REQUEST: &str =
    "the local-OUTPUT functional-canary executor accepts only the request-selected TPROXY backend";

/// Build the deliberately unsupported xtables local-OUTPUT executor.
///
/// This function is production-compiled so runtime composition has one
/// explicit fail-closed seam when required mode is wired later. The current
/// daemon deliberately continues to select structural-only compatibility.
#[allow(dead_code)]
pub(crate) fn xtables_tproxy_local_output_executor() -> Box<dyn UnqualifiedFunctionalCanaryExecutor>
{
    Box::new(TproxyLocalOutputExecutor::new(
        XtablesTproxyLocalOutputDriver,
        TproxyCanaryEvidenceFactory,
    ))
}

struct TproxyLocalOutputExecutor<D, F> {
    driver: D,
    evidence_factory: F,
}

impl<D, F> TproxyLocalOutputExecutor<D, F> {
    const fn new(driver: D, evidence_factory: F) -> Self {
        Self {
            driver,
            evidence_factory,
        }
    }
}

trait TproxyLocalOutputDriver: Send + 'static {
    type Prepared: PreparedTproxyLocalOutputAttempt;

    /// Complete every availability check before returning a prepared attempt.
    ///
    /// This phase must not mutate networking state. Therefore an error from
    /// this method may claim `NotRequired` cleanup only. Once a prepared value
    /// exists, the executor conservatively treats all later failures as
    /// potentially post-mutation.
    fn prepare_tproxy_local_output(
        &self,
        request: &CanaryAttemptRequest,
    ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable>;
}

struct TproxyLocalOutputUnavailable {
    availability: CanaryAvailability,
    diagnostic: String,
}

impl TproxyLocalOutputUnavailable {
    fn new(availability: CanaryAvailability, diagnostic: &str) -> Self {
        Self {
            availability,
            diagnostic: bounded_prefix(diagnostic),
        }
    }

    fn into_functional_error(self) -> FunctionalCanaryError {
        FunctionalCanaryError::new(
            CanaryErrorKind::Availability(self.availability),
            CanaryCleanupStatus::NotRequired,
            &self.diagnostic,
        )
    }
}

trait PreparedTproxyLocalOutputAttempt {
    type RawObservations;

    /// Execute the attempt and return raw observations, never validated gate
    /// evidence. The private factory is the only promotion boundary.
    fn execute_tproxy_local_output(
        self,
        request: &CanaryAttemptRequest,
        socket_observer: CanaryAttemptSocketObserverSession,
    ) -> Result<RawTproxyLocalOutputArtifacts<Self::RawObservations>, FunctionalCanaryError>;
}

trait TproxyLocalOutputEvidenceFactory<R>: Send + 'static {
    fn promote(
        &mut self,
        request: &CanaryAttemptRequest,
        raw: RawTproxyLocalOutputArtifacts<R>,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError>;
}

/// Factory-issued proof that raw observations came from the local-OUTPUT
/// TPROXY domain selected by this request.
///
/// The receipt is intentionally uninhabited until a real capture-receipt
/// verifier exists. Replacing `Infallible` is therefore an explicit reviewed
/// step rather than an accidental consequence of adding an inhabited driver.
struct TproxyLocalOutputCaptureReceipt {
    _never: Infallible,
}

struct RawTproxyLocalOutputArtifacts<R> {
    _capture_receipt: TproxyLocalOutputCaptureReceipt,
    observations: R,
}

impl<D, F> UnqualifiedFunctionalCanaryExecutor for TproxyLocalOutputExecutor<D, F>
where
    D: TproxyLocalOutputDriver,
    F: TproxyLocalOutputEvidenceFactory<
            <<D as TproxyLocalOutputDriver>::Prepared as PreparedTproxyLocalOutputAttempt>::RawObservations,
        >,
{
    fn execute(
        &mut self,
        execution: UnqualifiedFunctionalCanaryExecution<'_>,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
        let request = execution.request();
        require_tproxy_request(request)?;

        let prepared = self
            .driver
            .prepare_tproxy_local_output(request)
            .map_err(TproxyLocalOutputUnavailable::into_functional_error)?;
        let (request, socket_observer) = execution.into_parts();
        let raw = prepared
            .execute_tproxy_local_output(request, socket_observer)
            .map_err(normalize_post_preparation_failure)?;
        self.evidence_factory
            .promote(request, raw)
            .map_err(normalize_post_preparation_failure)
    }
}

fn require_tproxy_request(request: &CanaryAttemptRequest) -> Result<(), FunctionalCanaryError> {
    if request.capture_backend() == CanaryCaptureBackend::Tproxy {
        return Ok(());
    }
    Err(FunctionalCanaryError::new(
        CanaryErrorKind::InvalidEvidence,
        CanaryCleanupStatus::NotRequired,
        NON_TPROXY_REQUEST,
    ))
}

fn normalize_post_preparation_failure(error: FunctionalCanaryError) -> FunctionalCanaryError {
    match error.cleanup() {
        CanaryCleanupStatus::VerifiedAbsent
            if error.kind() != CanaryErrorKind::CleanupUncertain =>
        {
            error
        }
        CanaryCleanupStatus::Uncertain if error.kind() == CanaryErrorKind::CleanupUncertain => {
            error
        }
        CanaryCleanupStatus::NotRequired
        | CanaryCleanupStatus::VerifiedAbsent
        | CanaryCleanupStatus::Uncertain => contract_failure(
            CanaryErrorKind::CleanupUncertain,
            CanaryCleanupStatus::Uncertain,
            "local-OUTPUT attempt failed after preparation without authoritative cleanup proof",
            &error,
        ),
    }
}

fn contract_failure(
    kind: CanaryErrorKind,
    cleanup: CanaryCleanupStatus,
    contract: &str,
    source: &FunctionalCanaryError,
) -> FunctionalCanaryError {
    let diagnostic = format!("{contract}: {}", source.diagnostic());
    FunctionalCanaryError::new(kind, cleanup, &diagnostic)
}

/// The legacy xtables program has no device-supported local-OUTPUT TPROXY
/// mechanism. This zero-state driver intentionally owns no mutation handle.
#[derive(Clone, Copy, Debug, Default)]
struct XtablesTproxyLocalOutputDriver;

impl TproxyLocalOutputDriver for XtablesTproxyLocalOutputDriver {
    type Prepared = Infallible;

    fn prepare_tproxy_local_output(
        &self,
        request: &CanaryAttemptRequest,
    ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
        debug_assert_eq!(request.capture_backend(), CanaryCaptureBackend::Tproxy);
        Err(TproxyLocalOutputUnavailable::new(
            CanaryAvailability::Unsupported,
            XTABLES_LOCAL_OUTPUT_UNSUPPORTED,
        ))
    }
}

impl PreparedTproxyLocalOutputAttempt for Infallible {
    type RawObservations = Infallible;

    fn execute_tproxy_local_output(
        self,
        _request: &CanaryAttemptRequest,
        _socket_observer: CanaryAttemptSocketObserverSession,
    ) -> Result<RawTproxyLocalOutputArtifacts<Self::RawObservations>, FunctionalCanaryError> {
        match self {}
    }
}

/// Placeholder authority boundary for the later real observer/report factory.
///
/// Its current raw type is uninhabited, so production has no positive evidence
/// construction path through this seam.
#[derive(Clone, Copy, Debug, Default)]
struct TproxyCanaryEvidenceFactory;

impl TproxyLocalOutputEvidenceFactory<Infallible> for TproxyCanaryEvidenceFactory {
    fn promote(
        &mut self,
        _request: &CanaryAttemptRequest,
        raw: RawTproxyLocalOutputArtifacts<Infallible>,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
        match raw.observations {}
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Arc;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::super::tests::Fixture;
    use super::super::{CanarySocketObserverAuthority, CanarySocketObserverBinding};
    use super::*;
    use crate::functional_canary::{CanaryAddressFamilies, CanaryDeadline};

    #[test]
    fn xtables_reports_unsupported_before_mutation() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut executor = xtables_tproxy_local_output_executor();

        let error = executor
            .execute(execution(fixture.request()))
            .expect_err("xtables has no qualifying local-OUTPUT TPROXY mechanism");

        assert_eq!(
            error.kind(),
            CanaryErrorKind::Availability(CanaryAvailability::Unsupported)
        );
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
        assert!(error.diagnostic().contains("TPROXY only in PREROUTING"));
        assert!(error.diagnostic().contains("prohibited substitutes"));
    }

    #[test]
    fn redirect_and_dnat_requests_are_rejected_before_driver_preparation() {
        for backend in [CanaryCaptureBackend::Redirect, CanaryCaptureBackend::Dnat] {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let mut request = fixture.request().clone();
            request.capture_backend = backend;
            let preparation_calls = Arc::new(AtomicUsize::new(0));
            let driver = CountingUnsupportedDriver {
                preparation_calls: Arc::clone(&preparation_calls),
            };
            let mut executor = TproxyLocalOutputExecutor::new(driver, TproxyCanaryEvidenceFactory);

            let error = executor
                .execute(execution(&request))
                .expect_err("substitute request backends cannot enter the driver");

            assert_eq!(error.kind(), CanaryErrorKind::InvalidEvidence);
            assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
            assert_eq!(preparation_calls.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn availability_is_mapped_to_not_required_without_execution() {
        for availability in [
            CanaryAvailability::Unsupported,
            CanaryAvailability::Denied,
            CanaryAvailability::Conflicting,
            CanaryAvailability::Broken,
            CanaryAvailability::Unknown,
        ] {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let mut executor = TproxyLocalOutputExecutor::new(
                UnavailableDriver { availability },
                TproxyCanaryEvidenceFactory,
            );

            let error = executor
                .execute(execution(fixture.request()))
                .expect_err("pre-mutation unavailability cannot execute an attempt");

            assert_eq!(error.kind(), CanaryErrorKind::Availability(availability));
            assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
            assert_eq!(error.diagnostic(), "synthetic pre-mutation unavailability");
        }
    }

    #[test]
    fn unavailable_diagnostic_is_a_bounded_utf8_prefix() {
        let diagnostic = "界".repeat(super::super::MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
        let error = TproxyLocalOutputUnavailable::new(CanaryAvailability::Unknown, &diagnostic)
            .into_functional_error();

        assert!(error.diagnostic().len() <= super::super::MAX_FUNCTIONAL_CANARY_DIAGNOSTIC_BYTES);
        assert!(
            error
                .diagnostic()
                .is_char_boundary(error.diagnostic().len())
        );
    }

    #[test]
    fn post_preparation_failure_requires_authoritative_cleanup_status() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut executor = TproxyLocalOutputExecutor::new(
            PreparedFailureDriver {
                kind: CanaryErrorKind::AdapterFailure,
                cleanup: CanaryCleanupStatus::NotRequired,
            },
            NeverCalledEvidenceFactory,
        );

        let error = executor
            .execute(execution(fixture.request()))
            .expect_err("NotRequired is invalid after a prepared attempt exists");

        assert_eq!(error.kind(), CanaryErrorKind::CleanupUncertain);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
        assert!(error.diagnostic().contains("after preparation"));

        let mut contradictory = TproxyLocalOutputExecutor::new(
            PreparedFailureDriver {
                kind: CanaryErrorKind::CleanupUncertain,
                cleanup: CanaryCleanupStatus::VerifiedAbsent,
            },
            NeverCalledEvidenceFactory,
        );
        let error = contradictory
            .execute(execution(fixture.request()))
            .expect_err("cleanup-uncertain kind cannot claim verified absence");
        assert_eq!(error.kind(), CanaryErrorKind::CleanupUncertain);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
        assert!(error.diagnostic().contains("after preparation"));
    }

    #[test]
    fn post_preparation_failure_preserves_authoritative_cleanup() {
        for (kind, cleanup) in [
            (
                CanaryErrorKind::ResponseMismatch,
                CanaryCleanupStatus::VerifiedAbsent,
            ),
            (
                CanaryErrorKind::CleanupUncertain,
                CanaryCleanupStatus::Uncertain,
            ),
        ] {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let mut executor = TproxyLocalOutputExecutor::new(
                PreparedFailureDriver { kind, cleanup },
                NeverCalledEvidenceFactory,
            );

            let error = executor
                .execute(execution(fixture.request()))
                .expect_err("prepared attempt injects a failure");

            assert_eq!(error.kind(), kind);
            assert_eq!(error.cleanup(), cleanup);
            assert_eq!(error.diagnostic(), "synthetic post-preparation failure");
        }
    }

    struct CountingUnsupportedDriver {
        preparation_calls: Arc<AtomicUsize>,
    }

    impl TproxyLocalOutputDriver for CountingUnsupportedDriver {
        type Prepared = Infallible;

        fn prepare_tproxy_local_output(
            &self,
            _request: &CanaryAttemptRequest,
        ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
            self.preparation_calls.fetch_add(1, Ordering::SeqCst);
            Err(TproxyLocalOutputUnavailable::new(
                CanaryAvailability::Broken,
                "counting driver should not be called for a substitute backend",
            ))
        }
    }

    struct UnavailableDriver {
        availability: CanaryAvailability,
    }

    impl TproxyLocalOutputDriver for UnavailableDriver {
        type Prepared = Infallible;

        fn prepare_tproxy_local_output(
            &self,
            _request: &CanaryAttemptRequest,
        ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
            Err(TproxyLocalOutputUnavailable::new(
                self.availability,
                "synthetic pre-mutation unavailability",
            ))
        }
    }

    struct PreparedFailureDriver {
        kind: CanaryErrorKind,
        cleanup: CanaryCleanupStatus,
    }

    impl TproxyLocalOutputDriver for PreparedFailureDriver {
        type Prepared = PreparedFailure;

        fn prepare_tproxy_local_output(
            &self,
            _request: &CanaryAttemptRequest,
        ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
            Ok(PreparedFailure {
                kind: self.kind,
                cleanup: self.cleanup,
            })
        }
    }

    struct PreparedFailure {
        kind: CanaryErrorKind,
        cleanup: CanaryCleanupStatus,
    }

    impl PreparedTproxyLocalOutputAttempt for PreparedFailure {
        type RawObservations = ();

        fn execute_tproxy_local_output(
            self,
            _request: &CanaryAttemptRequest,
            _socket_observer: CanaryAttemptSocketObserverSession,
        ) -> Result<RawTproxyLocalOutputArtifacts<Self::RawObservations>, FunctionalCanaryError>
        {
            Err(FunctionalCanaryError::new(
                self.kind,
                self.cleanup,
                "synthetic post-preparation failure",
            ))
        }
    }

    struct NeverCalledEvidenceFactory;

    impl TproxyLocalOutputEvidenceFactory<()> for NeverCalledEvidenceFactory {
        fn promote(
            &mut self,
            _request: &CanaryAttemptRequest,
            _raw: RawTproxyLocalOutputArtifacts<()>,
        ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
            panic!("the factory must not run after driver failure")
        }
    }

    fn execution(request: &CanaryAttemptRequest) -> UnqualifiedFunctionalCanaryExecution<'_> {
        let socket_observer = CanaryAttemptSocketObserverSession::scripted(
            request
                .pre_binding()
                .environment()
                .authority()
                .socket_observer_binding(),
            request.deadline(),
        );
        UnqualifiedFunctionalCanaryExecution::new(request, socket_observer)
            .expect("scripted observer matches request authority")
    }

    #[test]
    fn copied_numeric_authority_cannot_replace_the_owned_attempt_session() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let request = fixture.request();
        let authority = request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer();
        let observer = CanaryAttemptSocketObserverSession::scripted(
            CanarySocketObserverBinding::scripted(
                authority,
                NonZeroU64::new(999).expect("replacement opening ID"),
            ),
            request.deadline(),
        );

        let error = match UnqualifiedFunctionalCanaryExecution::new(request, observer) {
            Ok(_) => panic!("copied numeric authority cannot replace the original opening"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), CanaryErrorKind::IdentityChanged);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
    }

    #[test]
    fn observer_opening_deadline_must_equal_the_request_deadline() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let request = fixture.request();
        let different_deadline =
            CanaryDeadline::new(request.deadline().started_at(), Duration::from_millis(1))
                .expect("shorter scripted deadline");
        let observer = CanaryAttemptSocketObserverSession::scripted(
            request
                .pre_binding()
                .environment()
                .authority()
                .socket_observer_binding(),
            different_deadline,
        );

        let error = match UnqualifiedFunctionalCanaryExecution::new(request, observer) {
            Ok(_) => panic!("observer and request deadlines cannot diverge"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), CanaryErrorKind::IdentityChanged);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
        assert!(error.diagnostic().contains("deadline"));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn exact_prebound_observer_session_reaches_the_driver_by_value() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut request = fixture.request().clone();
        let (collector_identity, collector_revision) = match request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer()
        {
            CanarySocketObserverAuthority::ProcFdInetDiag {
                collector_identity,
                collector_revision,
                ..
            } => (collector_identity, collector_revision),
            CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
                panic!("fixture uses the INET_DIAG observer")
            }
        };
        let observer = CanaryAttemptSocketObserverSession::open_proc_fd_inet_diag(
            collector_identity,
            collector_revision,
            request.deadline(),
        )
        .expect("open prebound observer");
        let binding = observer.binding();
        let authority = observer.authority();
        request.pre_binding.environment.authority.socket_observer = authority;
        request
            .pre_binding
            .environment
            .authority
            .socket_observer_opening = binding.opening_id;
        let reached_driver = Arc::new(AtomicBool::new(false));
        let driver = PreboundObserverPreparedDriver {
            binding,
            reached_driver: Arc::clone(&reached_driver),
        };
        let mut executor = TproxyLocalOutputExecutor::new(driver, NeverCalledEvidenceFactory);

        let error = executor
            .execute(
                UnqualifiedFunctionalCanaryExecution::new(&request, observer)
                    .expect("prebound observer matches request authority"),
            )
            .expect_err("test prepared attempt injects a verified-clean failure");

        assert_eq!(error.kind(), CanaryErrorKind::ResponseMismatch);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::VerifiedAbsent);
        assert!(reached_driver.load(Ordering::SeqCst));
    }

    struct PreboundObserverPreparedDriver {
        binding: CanarySocketObserverBinding,
        reached_driver: Arc<AtomicBool>,
    }

    impl TproxyLocalOutputDriver for PreboundObserverPreparedDriver {
        type Prepared = PreboundObserverPreparedFailure;

        fn prepare_tproxy_local_output(
            &self,
            request: &CanaryAttemptRequest,
        ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
            assert_eq!(
                request
                    .pre_binding()
                    .environment()
                    .authority()
                    .socket_observer_binding(),
                self.binding
            );
            Ok(PreboundObserverPreparedFailure {
                binding: self.binding,
                reached_driver: Arc::clone(&self.reached_driver),
            })
        }
    }

    struct PreboundObserverPreparedFailure {
        binding: CanarySocketObserverBinding,
        reached_driver: Arc<AtomicBool>,
    }

    impl PreparedTproxyLocalOutputAttempt for PreboundObserverPreparedFailure {
        type RawObservations = ();

        fn execute_tproxy_local_output(
            self,
            request: &CanaryAttemptRequest,
            socket_observer: CanaryAttemptSocketObserverSession,
        ) -> Result<RawTproxyLocalOutputArtifacts<Self::RawObservations>, FunctionalCanaryError>
        {
            assert_eq!(
                request
                    .pre_binding()
                    .environment()
                    .authority()
                    .socket_observer_binding(),
                self.binding
            );
            assert_eq!(socket_observer.binding(), self.binding);
            let session = socket_observer
                .into_proc_fd_inet_diag()
                .expect("driver received the real prebound session");
            let CanarySocketObserverAuthority::ProcFdInetDiag {
                netlink_port_id, ..
            } = self.binding.authority()
            else {
                panic!("test authority is INET_DIAG")
            };
            assert_eq!(session.netlink_port_id(), netlink_port_id);
            drop(session);
            self.reached_driver.store(true, Ordering::SeqCst);
            Err(FunctionalCanaryError::new(
                CanaryErrorKind::ResponseMismatch,
                CanaryCleanupStatus::VerifiedAbsent,
                "synthetic prepared attempt consumed the exact observer session",
            ))
        }
    }
}
