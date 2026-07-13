//! Fail-closed local-OUTPUT functional-canary executor boundary.
//!
//! The selected request backend is always TPROXY. The current xtables capture
//! program can mark local OUTPUT, but its TPROXY action exists only in
//! PREROUTING, and the privileged harness proved that local policy routing does
//! not make those packets re-enter PREROUTING. Consequently the xtables driver
//! below has no prepared-attempt value and reports `Unsupported` before it can
//! acquire a networking writer or mutate capture state.
//!
//! Future device-specific drivers return an unverified capture proof alongside
//! raw observations. A separate verifier must bind those two values to the
//! immutable request before promotion into schema-v2 gate evidence, so a
//! driver cannot self-label REDIRECT, DNAT, ingress traffic, counters, or a
//! route lookup as authoritative local-OUTPUT TPROXY delivery.
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
        TproxyCanaryCaptureVerifier,
        TproxyCanaryEvidenceFactory,
    ))
}

struct TproxyLocalOutputExecutor<D, V, F> {
    driver: D,
    verifier: V,
    evidence_factory: F,
}

impl<D, V, F> TproxyLocalOutputExecutor<D, V, F> {
    const fn new(driver: D, verifier: V, evidence_factory: F) -> Self {
        Self {
            driver,
            verifier,
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
    type CaptureProof;
    type RawObservations;

    /// Execute the attempt and return only an unverified capture proof plus raw
    /// observations. The driver cannot mint a capture receipt or gate evidence.
    fn execute_tproxy_local_output(
        self,
        request: &CanaryAttemptRequest,
        socket_observer: CanaryAttemptSocketObserverSession,
    ) -> Result<
        UnverifiedTproxyLocalOutputArtifacts<Self::CaptureProof, Self::RawObservations>,
        FunctionalCanaryError,
    >;
}

trait TproxyLocalOutputCaptureVerifier<P, R>: Send + 'static {
    /// Correlate the mechanism-specific proof with the exact raw observation
    /// batch and immutable request, then mint the single-use capture receipt.
    fn verify(
        &mut self,
        request: &CanaryAttemptRequest,
        raw: UnverifiedTproxyLocalOutputArtifacts<P, R>,
    ) -> Result<ReceiptBoundTproxyLocalOutputArtifacts<R>, FunctionalCanaryError>;
}

trait TproxyLocalOutputEvidenceFactory<R>: Send + 'static {
    fn promote(
        &mut self,
        request: &CanaryAttemptRequest,
        verified: ReceiptBoundTproxyLocalOutputArtifacts<R>,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError>;
}

mod capture_receipt {
    #[cfg(not(test))]
    use std::convert::Infallible;
    use std::num::{NonZeroU32, NonZeroU64};
    use std::time::Instant;

    use super::super::{
        CanaryAttemptRequest, CanaryCaptureBackend, CanaryFlow, CanaryFlowTuple,
        CanaryInboundDeliveryEvent, CanaryInboundPayloadIdentity, CanaryInetDiagCookie,
        FUNCTIONAL_CANARY_FLOW_SLOTS, UnqualifiedCanaryFlowEvidence,
        UnqualifiedCanaryFlowEvidenceSlots, UnqualifiedCanaryInboundListenerDeliveryEvidence,
    };

    /// Sealed authority proving that a verifier, rather than a capture driver,
    /// minted the receipt from direct local-OUTPUT observations.
    ///
    /// Production remains deliberately uninhabited. A future concrete
    /// verifier must replace the `Infallible` field with a reviewed,
    /// mechanism-specific authority that proves the local-OUTPUT TPROXY
    /// domain and its loss/readback contract. Unit tests receive a scripted
    /// authority without opening a production construction path.
    #[derive(Debug, Eq, PartialEq)]
    struct TproxyLocalOutputCaptureAuthority {
        #[cfg(not(test))]
        _never: Infallible,
        #[cfg(test)]
        _scripted: (),
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TproxyLocalOutputCaptureEvent {
        flow: CanaryFlow,
        nonce: super::super::CanaryNonce,
        client_tuple: CanaryFlowTuple,
        observed_socket_uid: NonZeroU32,
        payload: CanaryInboundPayloadIdentity,
        listener_cookie: CanaryInetDiagCookie,
        delivery_event: CanaryInboundDeliveryEvent,
        sequence: NonZeroU64,
        observed_at: Instant,
    }

    /// Immutable proof that every required flow originated in the exact
    /// local-OUTPUT TPROXY attempt and was correlated to the same authoritative
    /// transparent-listener delivery retained by schema-v2 gate evidence.
    ///
    /// This type is intentionally non-`Clone`: a verifier moves one receipt
    /// into one gate record. It stores the complete immutable request so boot,
    /// Generation, namespace, Network Epoch/snapshot, Capture Program,
    /// ownership, selector, engine, listener, nonce, and deadline cannot be
    /// replayed independently.
    #[derive(Debug, Eq, PartialEq)]
    pub(in super::super) struct TproxyLocalOutputCaptureReceipt {
        _authority: TproxyLocalOutputCaptureAuthority,
        request: CanaryAttemptRequest,
        observation_started_at: Instant,
        observation_completed_at: Instant,
        lost_events_before: u64,
        lost_events_after: u64,
        events: [Option<TproxyLocalOutputCaptureEvent>; FUNCTIONAL_CANARY_FLOW_SLOTS],
        unexpected_event_count: u8,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in super::super) enum TproxyLocalOutputCaptureReceiptError {
        RequestBackendMismatch,
        RequestMismatch,
        ObservationTimingInvalid,
        ObservationLoss,
        UnexpectedEvents {
            count: u8,
        },
        MissingFlow {
            flow: CanaryFlow,
        },
        UnexpectedFlow {
            flow: CanaryFlow,
        },
        MissingGateFlow {
            flow: CanaryFlow,
        },
        FlowSlotMismatch {
            expected: CanaryFlow,
            observed: CanaryFlow,
        },
        FlowNonceMismatch {
            flow: CanaryFlow,
        },
        FlowUidMismatch {
            flow: CanaryFlow,
        },
        FlowTupleMismatch {
            flow: CanaryFlow,
        },
        FlowPayloadMismatch {
            flow: CanaryFlow,
        },
        FlowListenerMismatch {
            flow: CanaryFlow,
        },
        FlowDeliveryMismatch {
            flow: CanaryFlow,
        },
        FlowTimingInvalid {
            flow: CanaryFlow,
        },
        FlowSequenceReused {
            first: CanaryFlow,
            second: CanaryFlow,
        },
    }

    impl TproxyLocalOutputCaptureReceipt {
        pub(in super::super) fn validate_for(
            &self,
            expected: &CanaryAttemptRequest,
            flows: &UnqualifiedCanaryFlowEvidenceSlots,
            attempt_completed_at: Instant,
            client_quiesced_at: Instant,
        ) -> Result<(), TproxyLocalOutputCaptureReceiptError> {
            if expected.capture_backend() != CanaryCaptureBackend::Tproxy {
                return Err(TproxyLocalOutputCaptureReceiptError::RequestBackendMismatch);
            }
            if &self.request != expected {
                return Err(TproxyLocalOutputCaptureReceiptError::RequestMismatch);
            }
            let deadline = expected.deadline();
            if self.observation_started_at < deadline.started_at()
                || self.observation_completed_at < self.observation_started_at
                || self.observation_completed_at >= deadline.expires_at()
                || self.observation_completed_at > attempt_completed_at
                || self.observation_completed_at > client_quiesced_at
            {
                return Err(TproxyLocalOutputCaptureReceiptError::ObservationTimingInvalid);
            }
            if self.lost_events_before != self.lost_events_after {
                return Err(TproxyLocalOutputCaptureReceiptError::ObservationLoss);
            }
            if self.unexpected_event_count != 0 {
                return Err(TproxyLocalOutputCaptureReceiptError::UnexpectedEvents {
                    count: self.unexpected_event_count,
                });
            }

            let mut earliest_flow_started_at = None;
            let mut latest_flow_completed_at = None;
            let mut sequences: [Option<(CanaryFlow, NonZeroU64)>; FUNCTIONAL_CANARY_FLOW_SLOTS] =
                [None; FUNCTIONAL_CANARY_FLOW_SLOTS];
            for expected_flow in CanaryFlow::ALL {
                let event = self.events[expected_flow.index()].as_ref();
                if !expected.requires_flow(expected_flow) {
                    if event.is_some() {
                        return Err(TproxyLocalOutputCaptureReceiptError::UnexpectedFlow {
                            flow: expected_flow,
                        });
                    }
                    continue;
                }
                let event = event.ok_or(TproxyLocalOutputCaptureReceiptError::MissingFlow {
                    flow: expected_flow,
                })?;
                if event.flow != expected_flow {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowSlotMismatch {
                        expected: expected_flow,
                        observed: event.flow,
                    });
                }
                let flow = flows.slots[expected_flow.index()].as_ref().ok_or(
                    TproxyLocalOutputCaptureReceiptError::MissingGateFlow {
                        flow: expected_flow,
                    },
                )?;
                earliest_flow_started_at = Some(match earliest_flow_started_at {
                    Some(current) => std::cmp::min(current, flow.started_at),
                    None => flow.started_at,
                });
                latest_flow_completed_at = Some(match latest_flow_completed_at {
                    Some(current) => std::cmp::max(current, flow.completed_at),
                    None => flow.completed_at,
                });
                if event.nonce != expected.nonce() {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowNonceMismatch {
                        flow: expected_flow,
                    });
                }
                if event.observed_socket_uid != expected.pre_binding().environment().probe_uid() {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowUidMismatch {
                        flow: expected_flow,
                    });
                }
                if event.client_tuple != flow.client_tuple {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowTupleMismatch {
                        flow: expected_flow,
                    });
                }
                let (listener_cookie, delivery_event, payload) = tproxy_delivery_binding(flow)
                    .ok_or(TproxyLocalOutputCaptureReceiptError::FlowDeliveryMismatch {
                        flow: expected_flow,
                    })?;
                if event.payload != payload {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowPayloadMismatch {
                        flow: expected_flow,
                    });
                }
                if event.listener_cookie != listener_cookie {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowListenerMismatch {
                        flow: expected_flow,
                    });
                }
                if event.delivery_event != delivery_event {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowDeliveryMismatch {
                        flow: expected_flow,
                    });
                }
                if event.observed_at < flow.started_at
                    || event.observed_at > delivery_event.observed_at
                    || event.observed_at < self.observation_started_at
                    || event.observed_at > self.observation_completed_at
                    || event.observed_at >= deadline.expires_at()
                {
                    return Err(TproxyLocalOutputCaptureReceiptError::FlowTimingInvalid {
                        flow: expected_flow,
                    });
                }
                for previous in sequences.iter().flatten() {
                    if previous.1 == event.sequence {
                        return Err(TproxyLocalOutputCaptureReceiptError::FlowSequenceReused {
                            first: previous.0,
                            second: expected_flow,
                        });
                    }
                }
                sequences[expected_flow.index()] = Some((expected_flow, event.sequence));
            }

            let earliest_flow_started_at = earliest_flow_started_at
                .expect("request validation always requires IPv4 canary flows");
            let latest_flow_completed_at = latest_flow_completed_at
                .expect("request validation always requires IPv4 canary flows");
            if self.observation_started_at > earliest_flow_started_at
                || self.observation_completed_at < latest_flow_completed_at
            {
                return Err(TproxyLocalOutputCaptureReceiptError::ObservationTimingInvalid);
            }
            Ok(())
        }

        #[cfg(test)]
        pub(in super::super) fn scripted(
            request: &CanaryAttemptRequest,
            flows: &UnqualifiedCanaryFlowEvidenceSlots,
        ) -> Self {
            let events = std::array::from_fn(|index| {
                let flow = flows.slots[index].as_ref()?;
                let (listener_cookie, delivery_event, payload) = tproxy_delivery_binding(flow)
                    .expect("scripted receipt requires TPROXY listener delivery");
                Some(TproxyLocalOutputCaptureEvent {
                    flow: flow.flow,
                    nonce: request.nonce(),
                    client_tuple: flow.client_tuple,
                    observed_socket_uid: request.pre_binding().environment().probe_uid(),
                    payload,
                    listener_cookie,
                    delivery_event,
                    sequence: NonZeroU64::new(
                        u64::try_from(index + 1).expect("flow slot fits u64"),
                    )
                    .expect("flow sequence is nonzero"),
                    observed_at: flow.started_at,
                })
            });
            let observation_completed_at = flows
                .slots
                .iter()
                .flatten()
                .map(|flow| flow.completed_at)
                .max()
                .expect("request validation always requires IPv4 canary flows");
            Self {
                _authority: TproxyLocalOutputCaptureAuthority { _scripted: () },
                request: request.clone(),
                observation_started_at: request.deadline().started_at(),
                observation_completed_at,
                lost_events_before: 0,
                lost_events_after: 0,
                events,
                unexpected_event_count: 0,
            }
        }
    }

    fn tproxy_delivery_binding(
        flow: &UnqualifiedCanaryFlowEvidence,
    ) -> Option<(
        CanaryInetDiagCookie,
        CanaryInboundDeliveryEvent,
        CanaryInboundPayloadIdentity,
    )> {
        match flow.inbound_listener_delivery.as_ref()? {
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyTcp { accepted, .. } => {
                Some((accepted.listener_cookie, accepted.event, accepted.payload))
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::TproxyUdp { datagram, .. } => {
                Some((datagram.listener_cookie, datagram.event, datagram.payload))
            }
            UnqualifiedCanaryInboundListenerDeliveryEvidence::Redirect
            | UnqualifiedCanaryInboundListenerDeliveryEvidence::Dnat => None,
        }
    }

    #[cfg(test)]
    mod tests {
        use std::num::NonZeroU32;
        use std::time::Duration;

        use super::super::super::tests::Fixture;
        use super::super::super::{
            CanaryAddressFamilies, CanaryAttemptRequest, CanaryCaptureBackend, CanaryFlow,
            CanaryInetDiagCookie, FUNCTIONAL_CANARY_NONCE_BYTES, UnqualifiedCanaryGateEvidence,
        };
        use super::*;

        fn validate(
            evidence: &UnqualifiedCanaryGateEvidence,
            expected: &CanaryAttemptRequest,
        ) -> Result<(), TproxyLocalOutputCaptureReceiptError> {
            evidence.local_output_capture_receipt.validate_for(
                expected,
                &evidence.flows,
                evidence.completed_at,
                evidence.cleanup.client.quiesced_at,
            )
        }

        fn assert_expected_request_rejected(
            mutate: impl FnOnce(&mut CanaryAttemptRequest),
            expected_error: TproxyLocalOutputCaptureReceiptError,
        ) {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let evidence = fixture.successful_evidence();
            let mut expected = fixture.request().clone();
            mutate(&mut expected);

            assert_eq!(validate(&evidence, &expected), Err(expected_error));
        }

        #[test]
        fn scripted_receipt_accepts_exact_ipv4_and_dual_stack_evidence() {
            for families in [
                CanaryAddressFamilies::Ipv4Only,
                CanaryAddressFamilies::Ipv4AndIpv6,
            ] {
                let fixture = Fixture::new(families);
                let evidence = fixture.successful_evidence();

                assert_eq!(validate(&evidence, fixture.request()), Ok(()));
            }
        }

        #[test]
        fn receipt_rejects_backend_and_request_scope_replay() {
            assert_expected_request_rejected(
                |request| request.capture_backend = CanaryCaptureBackend::Redirect,
                TproxyLocalOutputCaptureReceiptError::RequestBackendMismatch,
            );
            assert_expected_request_rejected(
                |request| {
                    request.nonce = super::super::super::CanaryNonce::from_bytes(
                        [8; FUNCTIONAL_CANARY_NONCE_BYTES],
                    )
                },
                TproxyLocalOutputCaptureReceiptError::RequestMismatch,
            );
            assert_expected_request_rejected(
                |request| {
                    request.pre_binding.engine.generation =
                        NonZeroU32::new(2).expect("nonzero generation")
                },
                TproxyLocalOutputCaptureReceiptError::RequestMismatch,
            );
            assert_expected_request_rejected(
                |request| {
                    request.pre_binding.environment.probe_uid =
                        NonZeroU32::new(65_530).expect("nonzero probe UID")
                },
                TproxyLocalOutputCaptureReceiptError::RequestMismatch,
            );
        }

        #[test]
        fn receipt_requires_exact_flow_slots_and_unique_sequences() {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let mut missing = fixture.successful_evidence();
            missing.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()] = None;
            assert_eq!(
                validate(&missing, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::MissingFlow {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut extra = fixture.successful_evidence();
            let mut extra_event = extra.local_output_capture_receipt.events
                [CanaryFlow::Ipv4TcpEcho.index()]
            .expect("IPv4 TCP receipt event");
            extra_event.flow = CanaryFlow::Ipv6TcpEcho;
            extra.local_output_capture_receipt.events[CanaryFlow::Ipv6TcpEcho.index()] =
                Some(extra_event);
            assert_eq!(
                validate(&extra, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::UnexpectedFlow {
                    flow: CanaryFlow::Ipv6TcpEcho,
                })
            );

            let mut unexpected = fixture.successful_evidence();
            unexpected
                .local_output_capture_receipt
                .unexpected_event_count = 1;
            assert_eq!(
                validate(&unexpected, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::UnexpectedEvents { count: 1 })
            );

            let mut wrong_slot = fixture.successful_evidence();
            wrong_slot.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .flow = CanaryFlow::Ipv4UdpEcho;
            assert_eq!(
                validate(&wrong_slot, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowSlotMismatch {
                    expected: CanaryFlow::Ipv4TcpEcho,
                    observed: CanaryFlow::Ipv4UdpEcho,
                })
            );

            let mut reused_sequence = fixture.successful_evidence();
            let sequence = reused_sequence.local_output_capture_receipt.events
                [CanaryFlow::Ipv4TcpEcho.index()]
            .expect("IPv4 TCP receipt event")
            .sequence;
            reused_sequence.local_output_capture_receipt.events[CanaryFlow::Ipv4UdpEcho.index()]
                .as_mut()
                .expect("IPv4 UDP receipt event")
                .sequence = sequence;
            assert_eq!(
                validate(&reused_sequence, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowSequenceReused {
                    first: CanaryFlow::Ipv4TcpEcho,
                    second: CanaryFlow::Ipv4UdpEcho,
                })
            );
        }

        #[test]
        fn receipt_rejects_per_flow_identity_and_delivery_mismatches() {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);

            let mut nonce = fixture.successful_evidence();
            nonce.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .nonce =
                super::super::super::CanaryNonce::from_bytes([9; FUNCTIONAL_CANARY_NONCE_BYTES]);
            assert_eq!(
                validate(&nonce, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowNonceMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut uid = fixture.successful_evidence();
            uid.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .observed_socket_uid = NonZeroU32::new(65_529).expect("nonzero UID");
            assert_eq!(
                validate(&uid, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowUidMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut tuple = fixture.successful_evidence();
            let alternate_tuple = tuple.local_output_capture_receipt.events
                [CanaryFlow::Ipv4UdpEcho.index()]
            .expect("IPv4 UDP receipt event")
            .client_tuple;
            tuple.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .client_tuple = alternate_tuple;
            assert_eq!(
                validate(&tuple, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowTupleMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut payload = fixture.successful_evidence();
            let alternate_payload = payload.local_output_capture_receipt.events
                [CanaryFlow::Ipv4DnsUdp.index()]
            .expect("IPv4 DNS receipt event")
            .payload;
            payload.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .payload = alternate_payload;
            assert_eq!(
                validate(&payload, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowPayloadMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut listener = fixture.successful_evidence();
            listener.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .listener_cookie =
                CanaryInetDiagCookie::new(99, 1).expect("nonzero listener cookie");
            assert_eq!(
                validate(&listener, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowListenerMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );

            let mut delivery = fixture.successful_evidence();
            let alternate_delivery = delivery.local_output_capture_receipt.events
                [CanaryFlow::Ipv4UdpEcho.index()]
            .expect("IPv4 UDP receipt event")
            .delivery_event;
            delivery.local_output_capture_receipt.events[CanaryFlow::Ipv4TcpEcho.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .delivery_event = alternate_delivery;
            assert_eq!(
                validate(&delivery, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowDeliveryMismatch {
                    flow: CanaryFlow::Ipv4TcpEcho,
                })
            );
        }

        #[test]
        fn receipt_rejects_invalid_observation_chronology_and_loss() {
            let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
            let flow = CanaryFlow::Ipv4TcpEcho;

            let mut before_start = fixture.successful_evidence();
            before_start.local_output_capture_receipt.events[flow.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .observed_at = before_start.flows.slots[flow.index()]
                .as_ref()
                .expect("IPv4 TCP gate flow")
                .started_at
                - Duration::from_nanos(1);
            assert_eq!(
                validate(&before_start, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowTimingInvalid { flow })
            );

            let mut after_delivery = fixture.successful_evidence();
            let delivered_at = after_delivery.local_output_capture_receipt.events[flow.index()]
                .expect("IPv4 TCP receipt event")
                .delivery_event
                .observed_at;
            after_delivery.local_output_capture_receipt.events[flow.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .observed_at = delivered_at + Duration::from_nanos(1);
            assert_eq!(
                validate(&after_delivery, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowTimingInvalid { flow })
            );

            let mut at_deadline = fixture.successful_evidence();
            at_deadline.local_output_capture_receipt.events[flow.index()]
                .as_mut()
                .expect("IPv4 TCP receipt event")
                .observed_at = fixture.request().deadline().expires_at();
            assert_eq!(
                validate(&at_deadline, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::FlowTimingInvalid { flow })
            );

            let mut batch_at_deadline = fixture.successful_evidence();
            batch_at_deadline
                .local_output_capture_receipt
                .observation_completed_at = fixture.request().deadline().expires_at();
            assert_eq!(
                validate(&batch_at_deadline, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::ObservationTimingInvalid)
            );

            let after_quiescence = fixture.successful_evidence();
            let quiesced_before_observation = after_quiescence
                .local_output_capture_receipt
                .observation_completed_at
                - Duration::from_nanos(1);
            assert_eq!(
                after_quiescence.local_output_capture_receipt.validate_for(
                    fixture.request(),
                    &after_quiescence.flows,
                    after_quiescence.completed_at,
                    quiesced_before_observation,
                ),
                Err(TproxyLocalOutputCaptureReceiptError::ObservationTimingInvalid)
            );

            let mut loss = fixture.successful_evidence();
            loss.local_output_capture_receipt.lost_events_after = 1;
            assert_eq!(
                validate(&loss, fixture.request()),
                Err(TproxyLocalOutputCaptureReceiptError::ObservationLoss)
            );
        }
    }
}

pub(super) use capture_receipt::TproxyLocalOutputCaptureReceipt;

const _: fn() = || {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<TproxyLocalOutputCaptureReceipt>();
};

struct UnverifiedTproxyLocalOutputArtifacts<P, R> {
    capture_proof: P,
    observations: R,
}

struct ReceiptBoundTproxyLocalOutputArtifacts<R> {
    capture_receipt: TproxyLocalOutputCaptureReceipt,
    observations: R,
}

impl<D, V, F> UnqualifiedFunctionalCanaryExecutor for TproxyLocalOutputExecutor<D, V, F>
where
    D: TproxyLocalOutputDriver,
    V: TproxyLocalOutputCaptureVerifier<
            <<D as TproxyLocalOutputDriver>::Prepared as PreparedTproxyLocalOutputAttempt>::CaptureProof,
            <<D as TproxyLocalOutputDriver>::Prepared as PreparedTproxyLocalOutputAttempt>::RawObservations,
        >,
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
        let verified = self
            .verifier
            .verify(request, raw)
            .map_err(normalize_post_preparation_failure)?;
        self.evidence_factory
            .promote(request, verified)
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
    type CaptureProof = Infallible;
    type RawObservations = Infallible;

    fn execute_tproxy_local_output(
        self,
        _request: &CanaryAttemptRequest,
        _socket_observer: CanaryAttemptSocketObserverSession,
    ) -> Result<
        UnverifiedTproxyLocalOutputArtifacts<Self::CaptureProof, Self::RawObservations>,
        FunctionalCanaryError,
    > {
        match self {}
    }
}

/// Placeholder verifier for a later, separately qualified direct-observation
/// mechanism. Both inputs remain uninhabited in production, so it cannot mint
/// a positive capture receipt.
#[derive(Clone, Copy, Debug, Default)]
struct TproxyCanaryCaptureVerifier;

impl TproxyLocalOutputCaptureVerifier<Infallible, Infallible> for TproxyCanaryCaptureVerifier {
    fn verify(
        &mut self,
        _request: &CanaryAttemptRequest,
        raw: UnverifiedTproxyLocalOutputArtifacts<Infallible, Infallible>,
    ) -> Result<ReceiptBoundTproxyLocalOutputArtifacts<Infallible>, FunctionalCanaryError> {
        match raw.capture_proof {}
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
        verified: ReceiptBoundTproxyLocalOutputArtifacts<Infallible>,
    ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
        match verified.observations {}
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::sync::Arc;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use super::super::tests::Fixture;
    use super::super::{CanarySocketObserverAuthority, CanarySocketObserverBinding};
    use super::*;
    use crate::functional_canary::{
        CanaryAddressFamilies, CanaryDeadline, UnqualifiedCanaryFlowEvidenceSlots,
    };

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
            let mut executor = TproxyLocalOutputExecutor::new(
                driver,
                TproxyCanaryCaptureVerifier,
                TproxyCanaryEvidenceFactory,
            );

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
                TproxyCanaryCaptureVerifier,
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
            NeverCalledCaptureVerifier,
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
            NeverCalledCaptureVerifier,
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
                NeverCalledCaptureVerifier,
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

    #[test]
    fn capture_verifier_binds_driver_proof_before_factory_promotion() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let seed = fixture.successful_evidence();
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let driver = ScriptedProofDriver::new(fixture.request(), &seed);
        let verifier = ScriptedCaptureVerifier {
            calls: Arc::clone(&verifier_calls),
        };
        let factory = RecordingEvidenceFactory {
            verifier_calls: Arc::clone(&verifier_calls),
            calls: Arc::clone(&factory_calls),
            panic_on_call: false,
        };
        let mut executor = TproxyLocalOutputExecutor::new(driver, verifier, factory);

        let error = executor
            .execute(execution(fixture.request()))
            .expect_err("recording factory deliberately stops after observing the receipt");

        assert_eq!(error.kind(), CanaryErrorKind::ResponseMismatch);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::VerifiedAbsent);
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn verifier_failure_is_post_preparation_and_never_calls_factory() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let seed = fixture.successful_evidence();
        let mut driver = ScriptedProofDriver::new(fixture.request(), &seed);
        let alternate_tuple = driver.prepared.observations.flows.slots
            [super::super::CanaryFlow::Ipv4UdpEcho.index()]
        .as_ref()
        .expect("IPv4 UDP observation")
        .client_tuple;
        driver.prepared.observations.flows.slots[super::super::CanaryFlow::Ipv4TcpEcho.index()]
            .as_mut()
            .expect("IPv4 TCP observation")
            .client_tuple = alternate_tuple;
        let verifier_calls = Arc::new(AtomicUsize::new(0));
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let verifier = ScriptedCaptureVerifier {
            calls: Arc::clone(&verifier_calls),
        };
        let factory = RecordingEvidenceFactory {
            verifier_calls: Arc::clone(&verifier_calls),
            calls: Arc::clone(&factory_calls),
            panic_on_call: true,
        };
        let mut executor = TproxyLocalOutputExecutor::new(driver, verifier, factory);

        let error = executor
            .execute(execution(fixture.request()))
            .expect_err("a capture proof cannot bless a different raw observation batch");

        assert_eq!(error.kind(), CanaryErrorKind::CleanupUncertain);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
        assert!(error.diagnostic().contains("capture proof"));
        assert_eq!(verifier_calls.load(Ordering::SeqCst), 1);
        assert_eq!(factory_calls.load(Ordering::SeqCst), 0);
    }

    #[derive(Clone)]
    struct ScriptedCaptureProof {
        request: CanaryAttemptRequest,
        flows: UnqualifiedCanaryFlowEvidenceSlots,
    }

    #[derive(Clone)]
    struct ScriptedRawObservations {
        flows: UnqualifiedCanaryFlowEvidenceSlots,
        completed_at: Instant,
        client_quiesced_at: Instant,
    }

    #[derive(Clone)]
    struct ScriptedPreparedAttempt {
        proof: ScriptedCaptureProof,
        observations: ScriptedRawObservations,
    }

    struct ScriptedProofDriver {
        prepared: ScriptedPreparedAttempt,
    }

    impl ScriptedProofDriver {
        fn new(request: &CanaryAttemptRequest, evidence: &UnqualifiedCanaryGateEvidence) -> Self {
            Self {
                prepared: ScriptedPreparedAttempt {
                    proof: ScriptedCaptureProof {
                        request: request.clone(),
                        flows: evidence.flows.clone(),
                    },
                    observations: ScriptedRawObservations {
                        flows: evidence.flows.clone(),
                        completed_at: evidence.completed_at,
                        client_quiesced_at: evidence.cleanup.client.quiesced_at,
                    },
                },
            }
        }
    }

    impl TproxyLocalOutputDriver for ScriptedProofDriver {
        type Prepared = ScriptedPreparedAttempt;

        fn prepare_tproxy_local_output(
            &self,
            request: &CanaryAttemptRequest,
        ) -> Result<Self::Prepared, TproxyLocalOutputUnavailable> {
            assert_eq!(&self.prepared.proof.request, request);
            Ok(self.prepared.clone())
        }
    }

    impl PreparedTproxyLocalOutputAttempt for ScriptedPreparedAttempt {
        type CaptureProof = ScriptedCaptureProof;
        type RawObservations = ScriptedRawObservations;

        fn execute_tproxy_local_output(
            self,
            _request: &CanaryAttemptRequest,
            _socket_observer: CanaryAttemptSocketObserverSession,
        ) -> Result<
            UnverifiedTproxyLocalOutputArtifacts<Self::CaptureProof, Self::RawObservations>,
            FunctionalCanaryError,
        > {
            Ok(UnverifiedTproxyLocalOutputArtifacts {
                capture_proof: self.proof,
                observations: self.observations,
            })
        }
    }

    struct ScriptedCaptureVerifier {
        calls: Arc<AtomicUsize>,
    }

    impl TproxyLocalOutputCaptureVerifier<ScriptedCaptureProof, ScriptedRawObservations>
        for ScriptedCaptureVerifier
    {
        fn verify(
            &mut self,
            request: &CanaryAttemptRequest,
            raw: UnverifiedTproxyLocalOutputArtifacts<
                ScriptedCaptureProof,
                ScriptedRawObservations,
            >,
        ) -> Result<
            ReceiptBoundTproxyLocalOutputArtifacts<ScriptedRawObservations>,
            FunctionalCanaryError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if &raw.capture_proof.request != request
                || raw.capture_proof.flows != raw.observations.flows
            {
                return Err(FunctionalCanaryError::new(
                    CanaryErrorKind::InvalidEvidence,
                    CanaryCleanupStatus::NotRequired,
                    "synthetic capture proof does not match the raw observation batch",
                ));
            }
            let capture_receipt =
                TproxyLocalOutputCaptureReceipt::scripted(request, &raw.capture_proof.flows);
            Ok(ReceiptBoundTproxyLocalOutputArtifacts {
                capture_receipt,
                observations: raw.observations,
            })
        }
    }

    struct RecordingEvidenceFactory {
        verifier_calls: Arc<AtomicUsize>,
        calls: Arc<AtomicUsize>,
        panic_on_call: bool,
    }

    impl TproxyLocalOutputEvidenceFactory<ScriptedRawObservations> for RecordingEvidenceFactory {
        fn promote(
            &mut self,
            request: &CanaryAttemptRequest,
            verified: ReceiptBoundTproxyLocalOutputArtifacts<ScriptedRawObservations>,
        ) -> Result<UnqualifiedCanaryGateEvidence, FunctionalCanaryError> {
            if self.panic_on_call {
                panic!("the evidence factory must not run after verifier failure");
            }
            assert_eq!(self.verifier_calls.load(Ordering::SeqCst), 1);
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(
                verified.capture_receipt.validate_for(
                    request,
                    &verified.observations.flows,
                    verified.observations.completed_at,
                    verified.observations.client_quiesced_at,
                ),
                Ok(())
            );
            Err(FunctionalCanaryError::new(
                CanaryErrorKind::ResponseMismatch,
                CanaryCleanupStatus::VerifiedAbsent,
                "recording factory observed the verifier-issued capture receipt",
            ))
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
        type CaptureProof = ();
        type RawObservations = ();

        fn execute_tproxy_local_output(
            self,
            _request: &CanaryAttemptRequest,
            _socket_observer: CanaryAttemptSocketObserverSession,
        ) -> Result<
            UnverifiedTproxyLocalOutputArtifacts<Self::CaptureProof, Self::RawObservations>,
            FunctionalCanaryError,
        > {
            Err(FunctionalCanaryError::new(
                self.kind,
                self.cleanup,
                "synthetic post-preparation failure",
            ))
        }
    }

    struct NeverCalledCaptureVerifier;

    impl TproxyLocalOutputCaptureVerifier<(), ()> for NeverCalledCaptureVerifier {
        fn verify(
            &mut self,
            _request: &CanaryAttemptRequest,
            _raw: UnverifiedTproxyLocalOutputArtifacts<(), ()>,
        ) -> Result<ReceiptBoundTproxyLocalOutputArtifacts<()>, FunctionalCanaryError> {
            panic!("the verifier must not run after driver failure")
        }
    }

    struct NeverCalledEvidenceFactory;

    impl TproxyLocalOutputEvidenceFactory<()> for NeverCalledEvidenceFactory {
        fn promote(
            &mut self,
            _request: &CanaryAttemptRequest,
            _verified: ReceiptBoundTproxyLocalOutputArtifacts<()>,
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
        let mut executor = TproxyLocalOutputExecutor::new(
            driver,
            NeverCalledCaptureVerifier,
            NeverCalledEvidenceFactory,
        );

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
        type CaptureProof = ();
        type RawObservations = ();

        fn execute_tproxy_local_output(
            self,
            request: &CanaryAttemptRequest,
            socket_observer: CanaryAttemptSocketObserverSession,
        ) -> Result<
            UnverifiedTproxyLocalOutputArtifacts<Self::CaptureProof, Self::RawObservations>,
            FunctionalCanaryError,
        > {
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
