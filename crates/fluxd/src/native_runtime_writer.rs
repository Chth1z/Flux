use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use flux_core::{AddressResyncDisposition, GenerationId, NetworkNamespaceIdentity, Reason};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::socket_diagnostics::{
    ListenerConflictSnapshot, ListenerConflictTarget, SystemSocketDiagnosticsSource,
};
use flux_platform::{
    NativeCaptureCanaryAttempt, NativeCaptureCanaryRouteOutcome, NativeCaptureCanaryRouteQuery,
    NativeCaptureCanarySelector, NativeCaptureConvergedState, NativeCaptureConvergence,
    NativeCaptureDesired, NativeCaptureOwnershipObservation, NativeCaptureTargetIdentity,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_platform::{
    NativeXtablesCaptureConverger, NativeXtablesCaptureTarget, collect_network_inventory_once,
};

#[cfg(test)]
use crate::EngineSpec;
use crate::EngineSupervisor;
#[cfg(test)]
use crate::functional_canary::FunctionalCanaryGateMode;
use crate::functional_canary::{
    CanaryAddressFamilies, CanaryAttemptRequest, CanaryFlow, CanaryFlowAddressFamily,
    PeerReapedCanaryAttemptAuthority, RetainedCanaryFacilityObservation,
    RetainedCanaryFacilityReadback, RetainedCanaryFacilityValidationError,
    canonical_listener_conflict_targets, validate_retained_canary_facility_observation,
};
#[cfg(test)]
use crate::generation_engine_config::EngineCapabilityProfileRevision;
use crate::generation_engine_config::{AddressReconciledGenerationInputs, CapturePathDecision};
use crate::runtime_coordinator::{
    ActiveCaptureAudit, ActiveCaptureAuditError, ActiveCaptureAuditRequest, AddressResyncStrategy,
    CanaryCounterReadback, CanaryCounterRetirementReadback, CanaryRouteReadback,
    CanarySelectorSession, PreparedGeneration, PublishedRuntimeState, RetiredCanarySelectorSession,
    RuntimeCoordinator, RuntimeFunctionalCanary, RuntimeWriter,
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

#[derive(Debug, Eq, PartialEq)]
enum LiveCaptureReadbackFailure<E> {
    Observation(E),
    Missing,
    TargetMismatch,
}

#[cfg(test)]
fn verify_live_capture_readback<I, E>(
    expected: I,
    observation: Result<Option<I>, E>,
) -> Result<(), LiveCaptureReadbackFailure<E>>
where
    I: Eq,
{
    match observation {
        Err(source) => Err(LiveCaptureReadbackFailure::Observation(source)),
        Ok(Some(observed)) if observed == expected => Ok(()),
        Ok(Some(_)) => Err(LiveCaptureReadbackFailure::TargetMismatch),
        Ok(None) => Err(LiveCaptureReadbackFailure::Missing),
    }
}

fn verify_live_capture_observation<E>(
    expected: NativeCaptureTargetIdentity,
    observation: Result<Option<NativeCaptureOwnershipObservation>, E>,
) -> Result<NativeCaptureOwnershipObservation, LiveCaptureReadbackFailure<E>> {
    match observation {
        Err(source) => Err(LiveCaptureReadbackFailure::Observation(source)),
        Ok(Some(observation)) if observation.target() == expected => Ok(observation),
        Ok(Some(_)) => Err(LiveCaptureReadbackFailure::TargetMismatch),
        Ok(None) => Err(LiveCaptureReadbackFailure::Missing),
    }
}

/// Close the native ownership bracket before classifying the source audit result.
///
/// The post-readback is deliberately evaluated before the source result is mapped. A planning
/// error is retryable only when the exact owner remained stable for the whole bounded transaction;
/// a post-readback failure or owner drift invalidates the safety proof immediately.
fn close_active_capture_audit_bracket<O, S, E>(
    ownership_before: &O,
    audit: Result<ActiveCaptureAudit, S>,
    post_readback: impl FnOnce() -> Result<O, E>,
    map_source_error: impl FnOnce(S) -> E,
    drift_error: impl FnOnce() -> E,
) -> Result<ActiveCaptureAudit, ActiveCaptureAuditError<E>>
where
    O: Eq,
{
    let ownership_after = post_readback().map_err(ActiveCaptureAuditError::SafetyInvalidated)?;
    if ownership_after != *ownership_before {
        return Err(ActiveCaptureAuditError::SafetyInvalidated(drift_error()));
    }
    audit.map_err(|source| ActiveCaptureAuditError::Retryable(map_source_error(source)))
}

fn require_active_capture_audit_time<E>(
    complete_before: Instant,
    now: Instant,
    deadline_error: impl FnOnce() -> E,
) -> Result<(), ActiveCaptureAuditError<E>> {
    if now >= complete_before {
        Err(ActiveCaptureAuditError::Retryable(deadline_error()))
    } else {
        Ok(())
    }
}

/// Close the native ownership bracket only while the immutable audit deadline remains usable.
///
/// The deadline check immediately before the post-readback is intentionally separate from the
/// final check after the bracket: once the old lease has expired, another ownership readback no
/// longer contributes to a safe extension and the coordinator will fail open. A safety
/// invalidation already proved by the bracket still takes precedence over lateness.
fn close_active_capture_audit_bracket_until<O, E>(
    ownership_before: &O,
    complete_before: Instant,
    mut now: impl FnMut() -> Instant,
    audit: Result<ActiveCaptureAudit, E>,
    post_readback: impl FnOnce() -> Result<O, E>,
    deadline_error: impl Fn() -> E,
    drift_error: impl FnOnce() -> E,
) -> Result<ActiveCaptureAudit, ActiveCaptureAuditError<E>>
where
    O: Eq,
{
    require_active_capture_audit_time(complete_before, now(), &deadline_error)?;
    let result = close_active_capture_audit_bracket(
        ownership_before,
        audit,
        post_readback,
        |source| source,
        drift_error,
    );
    if matches!(result, Err(ActiveCaptureAuditError::SafetyInvalidated(_))) {
        return result;
    }
    if now() >= complete_before {
        return Err(ActiveCaptureAuditError::Retryable(deadline_error()));
    }
    result
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

    /// Prepare an ordinary immutable successor forced by an active Capture Path audit. Unlike
    /// address-driven reconciliation, this must not collapse an unchanged inspection into `None`.
    fn prepare_audit_successor(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
        prior: I,
    ) -> Result<Option<PreparedNativeGeneration<T>>, Self::Error> {
        self.prepare_address_successor(inputs, prior)
    }

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

    /// Audit fresh inputs against one exact committed native runtime. The ownership observation
    /// is borrowed into the source's private platform transaction; retained-owner material never
    /// crosses this trait boundary.
    ///
    /// Implementations must not prepare or admit a successor, write Generation state, converge
    /// capture, or alter committed lineage. A successor result leaves the old deadline untouched.
    fn audit_active_capture(
        &mut self,
        _request: &ActiveCaptureAuditRequest<'_>,
        _target: I,
        _ownership: &NativeCaptureOwnershipObservation,
    ) -> Result<ActiveCaptureAudit, Self::Error> {
        Ok(ActiveCaptureAudit::SuccessorRequired)
    }

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

/// Linear boot-facility authority retained by the serialized native writer.
///
/// The identity values do not authorize reopening a namespace. The original descriptor remains
/// writer-owned, and an attempt receives only a freshly validated duplicate.
pub(crate) struct RetainedCanaryFacilityAuthority {
    facility: crate::functional_canary::CanaryFacilityIdentity,
    peer_network_namespace: NetworkNamespaceIdentity,
    _cleanup: Option<crate::native_canary_facility::NativeCanaryFacilityCleanup>,
    peer_network_namespace_handle: File,
}

impl RetainedCanaryFacilityAuthority {
    pub(crate) fn new(
        facility: crate::functional_canary::CanaryFacilityIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace_handle: File,
    ) -> Result<Self, NativeCoordinatorWriterError> {
        validate_peer_network_namespace_handle(
            &peer_network_namespace_handle,
            peer_network_namespace,
        )?;
        Ok(Self {
            facility,
            peer_network_namespace,
            peer_network_namespace_handle,
            _cleanup: None,
        })
    }

    pub(crate) fn new_with_cleanup(
        facility: crate::functional_canary::CanaryFacilityIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace_handle: File,
        cleanup: crate::native_canary_facility::NativeCanaryFacilityCleanup,
    ) -> Result<Self, NativeCoordinatorWriterError> {
        let mut authority = Self::new(
            facility,
            peer_network_namespace,
            peer_network_namespace_handle,
        )?;
        authority._cleanup = Some(cleanup);
        Ok(authority)
    }

    fn matches_request(&self, request: &CanaryAttemptRequest) -> bool {
        let environment = request.pre_binding().environment();
        self.facility == environment.facility()
            && self.peer_network_namespace
                == environment.authority().network().peer_network_namespace()
    }

    fn duplicate_for(
        &self,
        request: &CanaryAttemptRequest,
    ) -> Result<File, NativeCoordinatorWriterError> {
        let environment = request.pre_binding().environment();
        if self.facility != environment.facility() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained canary facility authority does not match the immutable request",
            ));
        }
        if self.peer_network_namespace != environment.authority().network().peer_network_namespace()
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained peer network namespace authority does not match the immutable request",
            ));
        }
        validate_peer_network_namespace_handle(
            &self.peer_network_namespace_handle,
            self.peer_network_namespace,
        )?;
        let duplicate = self
            .peer_network_namespace_handle
            .try_clone()
            .map_err(|source| {
                NativeCoordinatorWriterError::authority(
                    "duplicate retained peer network namespace",
                    source,
                )
            })?;
        validate_peer_network_namespace_handle(&duplicate, self.peer_network_namespace)?;
        Ok(duplicate)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn reobserve_for(
        &self,
        request: &CanaryAttemptRequest,
        peer_reaped: &PeerReapedCanaryAttemptAuthority,
    ) -> Result<RetainedCanaryFacilityReadback, NativeCoordinatorWriterError> {
        if !self.matches_request(request) || peer_reaped.request() != request {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained canary facility reobservation substituted its immutable request",
            ));
        }
        let deadline = request.deadline().expires_at();
        let peer_namespace_handle = self.duplicate_for(request)?;
        let expected_network = request.pre_binding().environment().authority().network();
        let expected_daemon_namespace = expected_network.daemon_network_namespace();
        let expected_peer_namespace = expected_network.peer_network_namespace();

        let daemon_namespace_before = current_network_namespace_identity()?;
        if daemon_namespace_before != expected_daemon_namespace {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained facility observer is not in the immutable daemon network namespace",
            ));
        }
        let (daemon_inventory, daemon_started_at, daemon_completed_at) =
            collect_inventory_until(deadline)?;
        if current_network_namespace_identity()? != expected_daemon_namespace {
            return Err(NativeCoordinatorWriterError::Invariant(
                "daemon network namespace changed during retained facility inventory",
            ));
        }

        let targets = canonical_listener_conflict_targets(request);
        let peer_observer = std::thread::Builder::new()
            .name("flux-canary-peer-observer".to_owned())
            .spawn(move || {
                collect_peer_facility_observation(
                    peer_namespace_handle,
                    expected_peer_namespace,
                    targets,
                    deadline,
                )
            })
            .map_err(|source| {
                NativeCoordinatorWriterError::observation(
                    "spawn retained peer network namespace observer",
                    source,
                )
            })?;
        let peer = peer_observer.join().map_err(|_| {
            NativeCoordinatorWriterError::observation(
                "join retained peer network namespace observer",
                io::Error::other("retained peer observer panicked"),
            )
        })??;

        let daemon_namespace_after = current_network_namespace_identity()?;
        if daemon_namespace_after != expected_daemon_namespace {
            return Err(NativeCoordinatorWriterError::Invariant(
                "daemon network namespace changed across retained facility reobservation",
            ));
        }
        let observation = RetainedCanaryFacilityObservation::new(
            daemon_namespace_before,
            daemon_namespace_after,
            peer.namespace,
            daemon_inventory,
            peer.inventory,
            daemon_started_at,
            daemon_completed_at,
            peer.inventory_started_at,
            peer.inventory_completed_at,
            &peer.listener_conflicts,
        );
        let validated =
            validate_retained_canary_facility_observation(request, peer_reaped, &observation)
                .map_err(|source| {
                    NativeCoordinatorWriterError::observation(
                        "validate retained canary facility observation",
                        source,
                    )
                })?;
        let observed_at = Instant::now();
        if observed_at >= deadline {
            return Err(NativeCoordinatorWriterError::observation(
                "finalize retained canary facility observation",
                RetainedCanaryFacilityValidationError::InvalidObservationChronology,
            ));
        }
        validated.finalize_at(observed_at).map_err(|source| {
            NativeCoordinatorWriterError::observation(
                "finalize retained canary facility observation",
                source,
            )
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn reobserve_for(
        &self,
        _request: &CanaryAttemptRequest,
        _peer_reaped: &PeerReapedCanaryAttemptAuthority,
    ) -> Result<RetainedCanaryFacilityReadback, NativeCoordinatorWriterError> {
        Err(NativeCoordinatorWriterError::Invariant(
            "retained canary facility reobservation requires Linux or Android",
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
struct PeerFacilityObservation {
    namespace: NetworkNamespaceIdentity,
    inventory: std::sync::Arc<flux_core::NetworkInventory>,
    inventory_started_at: Instant,
    inventory_completed_at: Instant,
    listener_conflicts: ListenerConflictSnapshot,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn collect_inventory_until(
    deadline: Instant,
) -> Result<
    (
        std::sync::Arc<flux_core::NetworkInventory>,
        Instant,
        Instant,
    ),
    NativeCoordinatorWriterError,
> {
    let started_at = Instant::now();
    let remaining = deadline.saturating_duration_since(started_at);
    if remaining.is_zero() {
        return Err(NativeCoordinatorWriterError::Invariant(
            "retained facility inventory started at or after the immutable deadline",
        ));
    }
    // The platform one-shot entry point accepts a relative timeout. Bracketing
    // its result against the immutable deadline prevents admitting late data,
    // but does not claim that the internal wait itself used the same absolute
    // instant.
    let inventory = collect_network_inventory_once(remaining.min(Duration::from_secs(30)))
        .map_err(|source| {
            NativeCoordinatorWriterError::observation(
                "collect retained canary facility inventory",
                source,
            )
        })?;
    let completed_at = Instant::now();
    if completed_at >= deadline {
        return Err(NativeCoordinatorWriterError::Invariant(
            "retained facility inventory completed at or after the immutable deadline",
        ));
    }
    Ok((inventory, started_at, completed_at))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn current_network_namespace_identity()
-> Result<NetworkNamespaceIdentity, NativeCoordinatorWriterError> {
    let metadata = std::fs::metadata("/proc/thread-self/ns/net").map_err(|source| {
        NativeCoordinatorWriterError::observation(
            "inspect current thread network namespace",
            source,
        )
    })?;
    NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino()).ok_or(
        NativeCoordinatorWriterError::Invariant(
            "current thread network namespace has a zero inode",
        ),
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn collect_peer_facility_observation(
    namespace_handle: File,
    expected_namespace: NetworkNamespaceIdentity,
    targets: Vec<ListenerConflictTarget>,
    deadline: Instant,
) -> Result<PeerFacilityObservation, NativeCoordinatorWriterError> {
    if Instant::now() >= deadline {
        return Err(NativeCoordinatorWriterError::Invariant(
            "peer network namespace observation started at or after the immutable deadline",
        ));
    }
    // SAFETY: this dedicated thread owns the duplicated nsfs descriptor. It
    // performs no work before `setns`, never lends the thread, and terminates
    // after returning owned observations, so namespace restoration is neither
    // required nor attempted.
    if unsafe { libc::setns(namespace_handle.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(NativeCoordinatorWriterError::observation(
            "enter retained peer network namespace",
            io::Error::last_os_error(),
        ));
    }
    let namespace = current_network_namespace_identity()?;
    if namespace != expected_namespace {
        return Err(NativeCoordinatorWriterError::Invariant(
            "dedicated peer observer entered a substituted network namespace",
        ));
    }
    let (inventory, inventory_started_at, inventory_completed_at) =
        collect_inventory_until(deadline)?;
    if current_network_namespace_identity()? != expected_namespace {
        return Err(NativeCoordinatorWriterError::Invariant(
            "peer network namespace changed during retained facility inventory",
        ));
    }
    let diagnostics = SystemSocketDiagnosticsSource
        .open_until(deadline)
        .map_err(|source| {
            NativeCoordinatorWriterError::observation(
                "open retained peer listener-conflict observer",
                source,
            )
        })?;
    let (_diagnostics, listener_conflicts) = diagnostics
        .collect_listener_conflicts_until(&targets, deadline)
        .map_err(|source| {
            NativeCoordinatorWriterError::observation(
                "collect retained peer listener conflicts",
                source,
            )
        })?;
    if current_network_namespace_identity()? != expected_namespace {
        return Err(NativeCoordinatorWriterError::Invariant(
            "peer network namespace changed during listener-conflict observation",
        ));
    }
    if Instant::now() >= deadline {
        return Err(NativeCoordinatorWriterError::Invariant(
            "peer network namespace observation completed at or after the immutable deadline",
        ));
    }
    Ok(PeerFacilityObservation {
        namespace,
        inventory,
        inventory_started_at,
        inventory_completed_at,
        listener_conflicts,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_peer_network_namespace_handle(
    handle: &File,
    expected: NetworkNamespaceIdentity,
) -> Result<(), NativeCoordinatorWriterError> {
    const NSFS_MAGIC: u64 = 0x6e73_6673;

    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `filesystem` points to writable storage for one `statfs`; `handle` remains borrowed
    // for the syscall and therefore keeps its descriptor open.
    if unsafe { libc::fstatfs(handle.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(NativeCoordinatorWriterError::authority(
            "inspect retained peer network namespace filesystem",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful `fstatfs` initialized the complete structure.
    let filesystem = unsafe { filesystem.assume_init() };
    if filesystem.f_type as u64 != NSFS_MAGIC {
        return Err(NativeCoordinatorWriterError::Invariant(
            "retained peer network namespace descriptor is not an nsfs handle",
        ));
    }

    let metadata = handle.metadata().map_err(|source| {
        NativeCoordinatorWriterError::authority(
            "inspect retained peer network namespace identity",
            source,
        )
    })?;
    let observed = NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino()).ok_or(
        NativeCoordinatorWriterError::Invariant(
            "retained peer network namespace descriptor has a zero inode",
        ),
    )?;
    if observed != expected {
        return Err(NativeCoordinatorWriterError::Invariant(
            "retained peer network namespace descriptor identity changed",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_peer_network_namespace_handle(
    _handle: &File,
    _expected: NetworkNamespaceIdentity,
) -> Result<(), NativeCoordinatorWriterError> {
    Err(NativeCoordinatorWriterError::Invariant(
        "retained peer network namespaces require Linux or Android",
    ))
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
/// at most one request-bound selector session while a canary executes. A separately supplied boot
/// facility authority remains writer-owned across those attempt sessions.
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
    retained_canary_facility_authority: Option<RetainedCanaryFacilityAuthority>,
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
            retained_canary_facility_authority: None,
            active_canary_selector_session: None,
            recovery_required: false,
        })
    }

    pub(crate) fn with_retained_canary_facility_authority(
        mut self,
        authority: RetainedCanaryFacilityAuthority,
    ) -> Result<Self, NativeCoordinatorWriterError> {
        if self.retained_canary_facility_authority.is_some() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native writer already retains a canary facility authority",
            ));
        }
        self.retained_canary_facility_authority = Some(authority);
        Ok(self)
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

    fn observe_exact_native_ownership(
        &mut self,
        expected: NativeCaptureTargetIdentity,
        operation: &'static str,
    ) -> Result<NativeCaptureOwnershipObservation, NativeCoordinatorWriterError> {
        match verify_live_capture_observation(expected, self.convergence.observe_active_ownership())
        {
            Ok(observation) => Ok(observation),
            Err(LiveCaptureReadbackFailure::Observation(source)) => {
                self.recovery_required = true;
                Err(NativeCoordinatorWriterError::convergence(operation, source))
            }
            Err(LiveCaptureReadbackFailure::TargetMismatch) => {
                self.recovery_required = true;
                Err(NativeCoordinatorWriterError::Invariant(
                    "live native ownership differs from the published Generation",
                ))
            }
            Err(LiveCaptureReadbackFailure::Missing) => {
                self.recovery_required = true;
                Err(NativeCoordinatorWriterError::Invariant(
                    "live native ownership readback is absent for a published Generation",
                ))
            }
        }
    }

    fn active_canary_attempt(
        &self,
        generation: &PreparedGeneration,
        session: &CanarySelectorSession,
    ) -> Result<(C::Target, NativeCaptureCanaryAttempt), NativeCoordinatorWriterError> {
        if self.recovery_required {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation requires capture recovery",
            ));
        }
        let active = self.active_canary_selector_session.as_ref().ok_or(
            NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation has no active selector session",
            ),
        )?;
        if session.request().pre_binding().engine().generation() != generation.id()
            || active != session.request()
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation substituted the active request",
            ));
        }
        let retained = self.retained(generation.id())?;
        let expected = C::target_identity(&retained.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation has no matching successful convergence report",
            ));
        }
        if !generation.matches_canary_selector_request(session.request())
            || !retained
                .runtime
                .matches_canary_selector_request(session.request())
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation does not match the retained Generation and facility",
            ));
        }
        Ok((
            retained.target.clone(),
            native_canary_attempt(session.request())?,
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
    retained_canary_facility_authority: Option<RetainedCanaryFacilityAuthority>,
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
        retained_canary_facility_authority,
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
        None,
        EngineSupervisor::for_linux_native_composition_test(),
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn compose_native_runtime_with_engine<S, F>(
    convergence: NativeXtablesCaptureConverger,
    source_factory: F,
    maintenance_interval: Duration,
    functional_canary: RuntimeFunctionalCanary,
    retained_canary_facility_authority: Option<RetainedCanaryFacilityAuthority>,
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
    let writer = match retained_canary_facility_authority {
        Some(authority) => writer.with_retained_canary_facility_authority(authority)?,
        None => writer,
    };
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

    fn prepare_audit_successor(
        &mut self,
        inputs: &AddressReconciledGenerationInputs,
    ) -> Result<Option<PreparedGeneration>, Self::Error> {
        let Some(prior) = self.prior_identity() else {
            return Ok(None);
        };
        let prepared = self
            .source
            .prepare_audit_successor(inputs, prior)
            .map_err(|source| {
                NativeCoordinatorWriterError::preparation(
                    "prepare active Capture Path audit successor",
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

    fn verify_live_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        let expected = C::target_identity(&self.retained(generation.id())?.target);
        if self.converged_identity != Some(expected) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native structural verification has no matching successful convergence report",
            ));
        }

        let Some(expected_native) = expected.native_capture_target_identity() else {
            // Synthetic non-native convergence implementations used by host tests do not expose
            // a platform ownership readback. Production native identities always do.
            return Ok(());
        };
        self.observe_exact_native_ownership(
            expected_native,
            "observe live native ownership during structural verification",
        )
        .map(|_| ())
    }

    fn audit_active_capture(
        &mut self,
        request: ActiveCaptureAuditRequest<'_>,
    ) -> Result<ActiveCaptureAudit, ActiveCaptureAuditError<Self::Error>> {
        if self.recovery_required {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit requires capture recovery",
                ),
            ));
        }
        if self.active_canary_selector_session.is_some() {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit overlapped an active canary selector session",
                ),
            ));
        }

        let generation = request.active();
        if self.committed_generation != Some(generation.generation()) {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit does not identify the committed Generation",
                ),
            ));
        }
        let expected = C::target_identity(
            &self
                .retained(generation.generation())
                .map_err(ActiveCaptureAuditError::Retryable)?
                .target,
        );
        if expected.coordinator_generation() != Some(generation.generation())
            || self.converged_identity != Some(expected)
        {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit has no exact active committed target",
                ),
            ));
        }

        if request.started_at() >= request.complete_before() {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit began at or after its prior deadline",
                ),
            ));
        }

        require_active_capture_audit_time(request.complete_before(), Instant::now(), || {
            NativeCoordinatorWriterError::Invariant(
                "active Capture Path audit reached its prior deadline before ownership readback",
            )
        })?;

        let Some(expected_native) = expected.native_capture_target_identity() else {
            // A synthetic convergence identity has no descriptor-anchored ownership evidence and
            // therefore cannot authorize a live evidence lease extension.
            return Ok(ActiveCaptureAudit::SuccessorRequired);
        };
        let ownership_before = self
            .observe_exact_native_ownership(
                expected_native,
                "observe native ownership before active Capture Path audit",
            )
            .map_err(ActiveCaptureAuditError::SafetyInvalidated)?;

        require_active_capture_audit_time(request.complete_before(), Instant::now(), || {
            NativeCoordinatorWriterError::Invariant(
                "active Capture Path audit reached its prior deadline before source planning",
            )
        })?;

        let audit = self
            .source
            .audit_active_capture(&request, expected, &ownership_before);

        // Always close the readback bracket, including after a planning error. A source failure
        // cannot hide simultaneous native ownership drift.
        let audit = close_active_capture_audit_bracket_until(
            &ownership_before,
            request.complete_before(),
            Instant::now,
            audit.map_err(|source| {
                NativeCoordinatorWriterError::preparation(
                    "audit committed native Capture Path evidence",
                    source,
                )
            }),
            || {
                self.observe_exact_native_ownership(
                    expected_native,
                    "observe native ownership after active Capture Path audit",
                )
            },
            || {
                NativeCoordinatorWriterError::Invariant(
                    "active Capture Path audit reached its prior deadline before ownership post-readback",
                )
            },
            || {
                NativeCoordinatorWriterError::Invariant(
                    "descriptor-anchored native ownership changed during active Capture Path audit",
                )
            },
        );
        if matches!(audit, Err(ActiveCaptureAuditError::SafetyInvalidated(_))) {
            self.recovery_required = true;
        }
        let audit = audit?;

        require_active_capture_audit_time(request.complete_before(), Instant::now(), || {
            NativeCoordinatorWriterError::Invariant(
                "active Capture Path audit completed after its prior deadline",
            )
        })?;

        if let ActiveCaptureAudit::Extended {
            generation: audited_generation,
            observed_at,
            valid_until,
        } = audit
            && (audited_generation != request.active()
                || observed_at < request.started_at()
                || valid_until <= observed_at)
        {
            return Err(ActiveCaptureAuditError::Retryable(
                NativeCoordinatorWriterError::Invariant(
                    "native source returned mismatched active Capture Path audit",
                ),
            ));
        }
        Ok(audit)
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
        if !generation.matches_canary_selector_request(request)
            || !retained.runtime.matches_canary_selector_request(request)
        {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary selector session does not match the retained Generation and facility",
            ));
        }
        let peer_network_namespace = self
            .retained_canary_facility_authority
            .as_ref()
            .ok_or(NativeCoordinatorWriterError::Invariant(
                "native canary selector session has no retained facility authority",
            ))?
            .duplicate_for(request)?;
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
        Ok(Some(
            CanarySelectorSession::reserved_with_peer_network_namespace(
                request,
                peer_network_namespace,
            ),
        ))
    }

    fn observe_canary_route(
        &mut self,
        generation: &PreparedGeneration,
        session: &CanarySelectorSession,
        family: CanaryFlowAddressFamily,
    ) -> Result<Option<CanaryRouteReadback>, Self::Error> {
        let (target, attempt) = self.active_canary_attempt(generation, session)?;
        let request = session.request();
        let flow = match family {
            CanaryFlowAddressFamily::Ipv4 => CanaryFlow::Ipv4TcpEcho,
            CanaryFlowAddressFamily::Ipv6 => CanaryFlow::Ipv6TcpEcho,
        };
        if !request.requires_flow(flow) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary route observation requested a disabled address family",
            ));
        }
        let rpdb = request.pre_binding().environment().rpdb();
        let query = NativeCaptureCanaryRouteQuery::new(
            std::net::SocketAddr::new(
                request.peer_address(flow),
                request.responder_port(flow).get(),
            ),
            rpdb.engine_uid(),
            rpdb.proxy_mark_value(),
            request.deadline().expires_at(),
        )
        .ok_or(NativeCoordinatorWriterError::Invariant(
            "native canary request could not produce its fixed route query",
        ))?;
        let outcome = match self
            .convergence
            .observe_canary_route(&target, attempt, query)
        {
            Ok(outcome) => outcome,
            Err(source) => {
                self.recovery_required = true;
                return Err(NativeCoordinatorWriterError::convergence(
                    "observe native functional-canary route",
                    source,
                ));
            }
        };
        let Some(outcome) = outcome else {
            return Ok(None);
        };
        match outcome {
            NativeCaptureCanaryRouteOutcome::Resolved(observation) => {
                if observation.query() != query
                    || observation.observed_at() < request.deadline().started_at()
                    || observation.observed_at() >= request.deadline().expires_at()
                {
                    self.recovery_required = true;
                    return Err(NativeCoordinatorWriterError::Invariant(
                        "native canary route receipt does not match the immutable query and deadline",
                    ));
                }
                Ok(Some(CanaryRouteReadback::Resolved {
                    destination: query.destination(),
                    queried_uid: query.uid(),
                    mark: query.mark(),
                    selected_table: observation.selected_table(),
                    observed_at: observation.observed_at(),
                }))
            }
            NativeCaptureCanaryRouteOutcome::Rejected(rejection) => {
                Ok(Some(CanaryRouteReadback::Rejected(rejection.errno())))
            }
        }
    }

    fn observe_canary_counters(
        &mut self,
        generation: &PreparedGeneration,
        session: &CanarySelectorSession,
    ) -> Result<Option<CanaryCounterReadback>, Self::Error> {
        let (target, attempt) = self.active_canary_attempt(generation, session)?;
        let deadline = session.request().deadline();
        let snapshot =
            match self
                .convergence
                .observe_canary_counters(&target, attempt, deadline.expires_at())
            {
                Ok(snapshot) => snapshot,
                Err(source) => {
                    self.recovery_required = true;
                    return Err(NativeCoordinatorWriterError::convergence(
                        "observe native functional-canary counters",
                        source,
                    ));
                }
            };
        if snapshot.is_some_and(|snapshot| {
            snapshot.observed_at() < deadline.started_at()
                || snapshot.observed_at() >= deadline.expires_at()
        }) {
            self.recovery_required = true;
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary counter snapshot falls outside the immutable deadline",
            ));
        }
        Ok(snapshot.map(|snapshot| {
            CanaryCounterReadback::new(
                snapshot.capture_packets(),
                snapshot.bypass_packets(),
                snapshot.recapture_packets(),
                snapshot.observed_at(),
            )
        }))
    }

    fn retire_canary_counters(
        &mut self,
        generation: &PreparedGeneration,
        session: &CanarySelectorSession,
    ) -> Result<Option<CanaryCounterRetirementReadback>, Self::Error> {
        let (target, attempt) = self.active_canary_attempt(generation, session)?;
        let deadline = session.request().deadline();
        let retirement =
            match self
                .convergence
                .retire_canary_counters(&target, attempt, deadline.expires_at())
            {
                Ok(retirement) => retirement,
                Err(source) => {
                    self.recovery_required = true;
                    return Err(NativeCoordinatorWriterError::convergence(
                        "retire native functional-canary counters",
                        source,
                    ));
                }
            };
        if retirement.is_some_and(|retirement| {
            retirement.retired_at() < deadline.started_at()
                || retirement.absent_observed_at() < retirement.retired_at()
                || retirement.absent_observed_at() >= deadline.expires_at()
        }) {
            self.recovery_required = true;
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary counter retirement falls outside the immutable cleanup chronology",
            ));
        }
        Ok(retirement.map(|retirement| {
            CanaryCounterRetirementReadback::new(
                retirement.retired_at(),
                retirement.absent_observed_at(),
            )
        }))
    }

    fn reobserve_retained_canary_facility(
        &mut self,
        generation: &PreparedGeneration,
        session: &CanarySelectorSession,
        peer_reaped: &PeerReapedCanaryAttemptAuthority,
    ) -> Result<Option<RetainedCanaryFacilityReadback>, Self::Error> {
        // All substitution checks precede descriptor inspection or live-state
        // observation. A rejected borrowed authority poisons only the caller's
        // attempt phase; it does not manufacture a live drift claim here.
        let _ = self.active_canary_attempt(generation, session)?;
        if peer_reaped.request() != session.request() {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained facility reobservation substituted peer-reap authority",
            ));
        }
        let authority = self.retained_canary_facility_authority.as_ref().ok_or(
            NativeCoordinatorWriterError::Invariant(
                "retained facility reobservation has no writer-owned facility authority",
            ),
        )?;
        if !authority.matches_request(session.request()) {
            return Err(NativeCoordinatorWriterError::Invariant(
                "retained facility reobservation substituted the writer-owned facility",
            ));
        }

        // Descriptor validation is the first live-observation action. Any
        // failure from this point requires recovery and deliberately retains
        // the active selector session.
        match authority.reobserve_for(session.request(), peer_reaped) {
            Ok(readback) => Ok(Some(readback)),
            Err(source) => {
                self.recovery_required = true;
                Err(source)
            }
        }
    }

    fn retire_canary_selector_session(
        &mut self,
        generation: &PreparedGeneration,
        session: CanarySelectorSession,
    ) -> Result<Option<RetiredCanarySelectorSession>, Self::Error> {
        if self.recovery_required {
            return Err(NativeCoordinatorWriterError::Invariant(
                "native canary attempt operation requires capture recovery",
            ));
        }
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
        if !generation.matches_canary_selector_request(session.request())
            || !retained
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
    Authority {
        operation: &'static str,
        source: io::Error,
    },
    Observation {
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

    fn authority(operation: &'static str, source: io::Error) -> Self {
        Self::Authority { operation, source }
    }

    fn observation(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self::Observation {
            operation,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for NativeCoordinatorWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Convergence { operation, source }
            | Self::Preparation { operation, source }
            | Self::Observation { operation, source } => {
                write!(formatter, "{operation}: {source}")
            }
            Self::Authority { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Invariant(message) => formatter.write_str(message),
        }
    }
}

impl Error for NativeCoordinatorWriterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Convergence { source, .. }
            | Self::Preparation { source, .. }
            | Self::Observation { source, .. } => Some(source.as_ref()),
            Self::Authority { source, .. } => Some(source),
            Self::Invariant(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use crate::functional_canary::tests::request_with_engine_identity_and_network_namespaces;
    use crate::functional_canary::{
        CanaryAddressFamilies, CanaryAttemptRequest, CanaryFacilityIdentity, CanaryNonce,
        CanaryProcessIdentity, CanaryProcessRetirementEvidence, CanaryResponderPorts,
        FUNCTIONAL_CANARY_NONCE_BYTES, InstalledSupervisedDeliveryReportProducer,
        PeerReapedCanaryAttemptAuthority, PreparedCanaryGenerationBinding,
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
        fail_counter_observation_once: bool,
        route_queries: Vec<NativeCaptureCanaryRouteQuery>,
        counter_observation_deadlines: Vec<Instant>,
        counter_retirement_deadlines: Vec<Instant>,
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

        fn observe_canary_counters(
            &mut self,
            _target: &Self::Target,
            _attempt: NativeCaptureCanaryAttempt,
            deadline: Instant,
        ) -> Result<Option<flux_platform::NativeCaptureCanaryCounterSnapshot>, Self::Error>
        {
            self.counter_observation_deadlines.push(deadline);
            if self.fail_counter_observation_once {
                self.fail_counter_observation_once = false;
                return Err(io::Error::other(
                    "injected uncertain native counter observation failure",
                ));
            }
            Ok(None)
        }

        fn observe_canary_route(
            &mut self,
            _target: &Self::Target,
            _attempt: NativeCaptureCanaryAttempt,
            query: NativeCaptureCanaryRouteQuery,
        ) -> Result<Option<NativeCaptureCanaryRouteOutcome>, Self::Error> {
            self.route_queries.push(query);
            Ok(None)
        }

        fn retire_canary_counters(
            &mut self,
            _target: &Self::Target,
            _attempt: NativeCaptureCanaryAttempt,
            deadline: Instant,
        ) -> Result<Option<flux_platform::NativeCaptureCanaryCounterRetirement>, Self::Error>
        {
            self.counter_retirement_deadlines.push(deadline);
            Ok(None)
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn selector_request(
        fixture: &EngineFixture,
        nonce_byte: u8,
    ) -> (CanaryAttemptRequest, RetainedCanaryFacilityAuthority) {
        selector_request_with_families(fixture, nonce_byte, CanaryAddressFamilies::Ipv4Only)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn selector_request_with_families(
        fixture: &EngineFixture,
        nonce_byte: u8,
        families: CanaryAddressFamilies,
    ) -> (CanaryAttemptRequest, RetainedCanaryFacilityAuthority) {
        use std::os::unix::fs::MetadataExt as _;

        let peer_network_namespace_handle = fs::File::open("/proc/self/ns/net")
            .expect("open current network namespace for native writer test");
        let metadata = peer_network_namespace_handle
            .metadata()
            .expect("inspect current network namespace for native writer test");
        let peer_network_namespace = NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino())
            .expect("current network namespace has nonzero identity");
        let daemon_inode = if peer_network_namespace.inode() == u64::MAX {
            peer_network_namespace.inode() - 1
        } else {
            peer_network_namespace.inode() + 1
        };
        let daemon_network_namespace =
            NetworkNamespaceIdentity::new(peer_network_namespace.device(), daemon_inode)
                .expect("synthetic daemon network namespace has nonzero identity");
        let request = selector_request_for_network_namespaces(
            fixture,
            nonce_byte,
            families,
            daemon_network_namespace,
            peer_network_namespace,
        );
        let authority = RetainedCanaryFacilityAuthority::new(
            request.pre_binding().environment().facility(),
            peer_network_namespace,
            peer_network_namespace_handle,
        )
        .expect("retain current peer network namespace authority");
        (request, authority)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn selector_request_for_network_namespaces(
        fixture: &EngineFixture,
        nonce_byte: u8,
        families: CanaryAddressFamilies,
        daemon_network_namespace: NetworkNamespaceIdentity,
        peer_network_namespace: NetworkNamespaceIdentity,
    ) -> CanaryAttemptRequest {
        request_with_engine_identity_and_network_namespaces(
            &fixture.spec,
            families,
            Instant::now(),
            CanaryNonce::from_bytes([nonce_byte; FUNCTIONAL_CANARY_NONCE_BYTES]),
            GenerationId::new(17).expect("selector-session Generation"),
            NonZeroU32::new(4242).expect("engine PID"),
            NonZeroU64::new(98_765).expect("engine start ticks"),
            NonZeroU64::new(23).expect("engine snapshot revision"),
            daemon_network_namespace,
            peer_network_namespace,
        )
    }

    fn peer_reaped_authority(request: &CanaryAttemptRequest) -> PeerReapedCanaryAttemptAuthority {
        let started_at = request.deadline().started_at();
        let retirement = |slot: u32, offset: u64| {
            CanaryProcessRetirementEvidence::new(
                CanaryProcessIdentity::new(
                    NonZeroU32::new(70_000 + slot).expect("peer PID"),
                    NonZeroU64::new(80_000 + u64::from(slot)).expect("peer start ticks"),
                ),
                started_at + Duration::from_millis(offset),
                started_at + Duration::from_millis(offset + 1),
                started_at + Duration::from_millis(offset + 2),
            )
        };
        PeerReapedCanaryAttemptAuthority::fixture(
            request,
            [retirement(1, 100), retirement(2, 110), retirement(3, 120)],
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
            fail_counter_observation_once: false,
            route_queries: Vec::new(),
            counter_observation_deadlines: Vec::new(),
            counter_retirement_deadlines: Vec::new(),
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
    fn live_capture_readback_accepts_an_exact_target() {
        assert_eq!(
            verify_live_capture_readback::<u64, &str>(17, Ok(Some(17))),
            Ok(())
        );
    }

    #[test]
    fn live_capture_readback_rejects_a_missing_target() {
        assert_eq!(
            verify_live_capture_readback::<u64, &str>(17, Ok(None)),
            Err(LiveCaptureReadbackFailure::Missing)
        );
    }

    #[test]
    fn live_capture_readback_rejects_a_substituted_target() {
        assert_eq!(
            verify_live_capture_readback::<u64, &str>(17, Ok(Some(18))),
            Err(LiveCaptureReadbackFailure::TargetMismatch)
        );
    }

    #[test]
    fn live_capture_readback_preserves_an_observation_error() {
        assert_eq!(
            verify_live_capture_readback::<u64, &str>(17, Err("injected readback failure")),
            Err(LiveCaptureReadbackFailure::Observation(
                "injected readback failure"
            ))
        );
    }

    #[test]
    fn active_audit_bracket_closes_after_a_source_failure() {
        let post_readbacks = Cell::new(0);
        let result = close_active_capture_audit_bracket(
            &17_u64,
            Err::<ActiveCaptureAudit, _>("source failure"),
            || {
                post_readbacks.set(post_readbacks.get() + 1);
                Ok(17_u64)
            },
            |source| source,
            || "owner drift",
        );

        assert_eq!(post_readbacks.get(), 1);
        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::Retryable("source failure"))
        ));
    }

    #[test]
    fn active_audit_bracket_classifies_post_readback_failure_as_safety_invalidation() {
        let result = close_active_capture_audit_bracket(
            &17_u64,
            Ok::<_, &str>(ActiveCaptureAudit::SuccessorRequired),
            || Err("post-readback failure"),
            |source| source,
            || "owner drift",
        );

        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::SafetyInvalidated(
                "post-readback failure"
            ))
        ));
    }

    #[test]
    fn active_audit_bracket_classifies_owner_drift_as_safety_invalidation() {
        let result = close_active_capture_audit_bracket(
            &17_u64,
            Ok::<_, &str>(ActiveCaptureAudit::SuccessorRequired),
            || Ok(18_u64),
            |source| source,
            || "owner drift",
        );

        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::SafetyInvalidated("owner drift"))
        ));
    }

    #[test]
    fn active_audit_deadline_rejects_before_first_ownership_readback() {
        let deadline = Instant::now() - Duration::from_millis(1);
        let readbacks = Cell::new(0);
        let result = require_active_capture_audit_time(deadline, deadline, || "expired")
            .map(|()| readbacks.set(readbacks.get() + 1));

        assert_eq!(readbacks.get(), 0);
        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::Retryable("expired"))
        ));
    }

    #[test]
    fn active_audit_deadline_does_not_start_post_readback_after_expiry() {
        let deadline = Instant::now();
        let post_readbacks = Cell::new(0);
        let result = close_active_capture_audit_bracket_until(
            &17_u64,
            deadline,
            || deadline,
            Ok::<_, &str>(ActiveCaptureAudit::SuccessorRequired),
            || {
                post_readbacks.set(post_readbacks.get() + 1);
                Ok(17_u64)
            },
            || "expired",
            || "owner drift",
        );

        assert_eq!(post_readbacks.get(), 0);
        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::Retryable("expired"))
        ));
    }

    #[test]
    fn active_audit_deadline_preserves_post_readback_on_source_error() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let post_readbacks = Cell::new(0);
        let result = close_active_capture_audit_bracket_until(
            &17_u64,
            deadline,
            || now,
            Err::<ActiveCaptureAudit, _>("source failure"),
            || {
                post_readbacks.set(post_readbacks.get() + 1);
                Ok(17_u64)
            },
            || "expired",
            || "owner drift",
        );

        assert_eq!(post_readbacks.get(), 1);
        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::Retryable("source failure"))
        ));
    }

    #[test]
    fn active_audit_deadline_rejects_a_result_that_finishes_late() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let now_calls = Cell::new(0);
        let post_readbacks = Cell::new(0);
        let result = close_active_capture_audit_bracket_until(
            &17_u64,
            deadline,
            || {
                let call = now_calls.get();
                now_calls.set(call + 1);
                if call == 0 { now } else { deadline }
            },
            Ok::<_, &str>(ActiveCaptureAudit::SuccessorRequired),
            || {
                post_readbacks.set(post_readbacks.get() + 1);
                Ok(17_u64)
            },
            || "expired",
            || "owner drift",
        );

        assert_eq!(post_readbacks.get(), 1);
        assert!(matches!(
            result,
            Err(ActiveCaptureAuditError::Retryable("expired"))
        ));
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn retained_canary_facility_rejects_regular_files() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = EngineFixture::new();
        let (request, _authority) = selector_request(&fixture, 65);
        let regular_file = tempfile::tempfile().expect("create regular descriptor fixture");
        let metadata = regular_file
            .metadata()
            .expect("inspect regular descriptor fixture");
        let regular_identity = NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino())
            .expect("regular descriptor fixture has nonzero identity");

        let error = match RetainedCanaryFacilityAuthority::new(
            request.pre_binding().environment().facility(),
            regular_identity,
            regular_file,
        ) {
            Ok(_) => panic!("a regular file must not become network namespace authority"),
            Err(error) => error,
        };

        assert_eq!(
            error.to_string(),
            "retained peer network namespace descriptor is not an nsfs handle"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_requires_retained_facility_authority_before_population() {
        let fixture = EngineFixture::new();
        let (request, _authority) = selector_request(&fixture, 66);
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
        events.lock().expect("native events lock").clear();

        let error =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("missing retained facility authority must fail closed");

        assert_eq!(
            error.to_string(),
            "native canary selector session has no retained facility authority"
        );
        assert!(writer.convergence.selector.is_none());
        assert!(writer.active_canary_selector_session.is_none());
        assert!(!writer.recovery_required);
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_revalidates_the_retained_descriptor_before_population() {
        use std::os::unix::fs::MetadataExt as _;

        let fixture = EngineFixture::new();
        let (request, mut authority) = selector_request(&fixture, 67);
        let changed_handle =
            fs::File::open("/proc/self/ns/mnt").expect("open a distinct nsfs descriptor fixture");
        let changed = changed_handle
            .metadata()
            .expect("inspect distinct nsfs descriptor fixture");
        let changed = NetworkNamespaceIdentity::new(changed.dev(), changed.ino())
            .expect("distinct nsfs descriptor has nonzero identity");
        assert_ne!(changed, authority.peer_network_namespace);
        authority.peer_network_namespace_handle = changed_handle;
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach initially validated facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        events.lock().expect("native events lock").clear();

        let error =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("changed retained descriptor must fail before population");

        assert_eq!(
            error.to_string(),
            "retained peer network namespace descriptor identity changed"
        );
        assert!(writer.convergence.selector.is_none());
        assert!(writer.active_canary_selector_session.is_none());
        assert!(!writer.recovery_required);
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_rejects_retained_facility_substitution_before_population() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 68);
        let facility = request.pre_binding().environment().facility();
        let substituted_facility = CanaryFacilityIdentity::new(
            facility.daemon_veth(),
            facility.peer_veth(),
            facility.ipv4(),
            facility.ipv6(),
            facility.peer_veth_topology(),
            CanaryResponderPorts::new(
                NonZeroU16::new(42_001).expect("substituted TCP port"),
                NonZeroU16::new(42_002).expect("substituted UDP port"),
                NonZeroU16::new(42_003).expect("substituted DNS port"),
            )
            .expect("distinct substituted responder ports"),
        )
        .expect("valid substituted facility identity");
        let authority = RetainedCanaryFacilityAuthority::new(
            substituted_facility,
            authority.peer_network_namespace,
            authority.peer_network_namespace_handle,
        )
        .expect("retain substituted facility over the exact namespace descriptor");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach substituted facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        events.lock().expect("native events lock").clear();

        let error =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("facility substitution must fail before selector population");

        assert_eq!(
            error.to_string(),
            "retained canary facility authority does not match the immutable request"
        );
        assert!(writer.convergence.selector.is_none());
        assert!(writer.active_canary_selector_session.is_none());
        assert!(!writer.recovery_required);
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_rejects_peer_namespace_substitution_before_population() {
        let fixture = EngineFixture::new();
        let (original, authority) = selector_request(&fixture, 69);
        let retained_peer = authority.peer_network_namespace;
        let substituted_peer = NetworkNamespaceIdentity::new(
            retained_peer.device().wrapping_add(1),
            retained_peer.inode(),
        )
        .expect("substituted peer network namespace identity");
        let substituted_daemon = NetworkNamespaceIdentity::new(
            retained_peer.device().wrapping_add(2),
            retained_peer.inode(),
        )
        .expect("substituted daemon network namespace identity");
        let request = selector_request_for_network_namespaces(
            &fixture,
            69,
            CanaryAddressFamilies::Ipv4Only,
            substituted_daemon,
            substituted_peer,
        );
        assert_eq!(
            original.pre_binding().environment().facility(),
            request.pre_binding().environment().facility()
        );
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach exact retained namespace authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        events.lock().expect("native events lock").clear();

        let error =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect_err("peer namespace substitution must fail before selector population");

        assert_eq!(
            error.to_string(),
            "retained peer network namespace authority does not match the immutable request"
        );
        assert!(writer.convergence.selector.is_none());
        assert!(writer.active_canary_selector_session.is_none());
        assert!(!writer.recovery_required);
        assert!(events.lock().expect("native events lock").is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_rejects_overlap_missing_retirement_and_substitution() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 71);
        let (alternate, _alternate_authority) = selector_request(&fixture, 72);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
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

        let mut session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");
        let peer_network_namespace = session
            .take_peer_network_namespace()
            .expect("native writer lends one peer network namespace duplicate");
        validate_peer_network_namespace_handle(
            &peer_network_namespace,
            request
                .pre_binding()
                .environment()
                .authority()
                .network()
                .peer_network_namespace(),
        )
        .expect("lent peer network namespace remains exact");
        assert!(
            session.take_peer_network_namespace().is_none(),
            "the namespace duplicate is take-once"
        );
        drop(peer_network_namespace);
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

        let mut next =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &alternate)
                .expect("reuse original authority for a later attempt")
                .expect("native writer lends a fresh later-attempt duplicate");
        assert!(next.take_peer_network_namespace().is_some());
        RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, next)
            .expect("retire later selector session")
            .expect("later selector retirement remains exact");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_maps_the_exact_dual_stack_request() {
        let fixture = EngineFixture::new();
        let (request, authority) =
            selector_request_with_families(&fixture, 74, CanaryAddressFamilies::Ipv4AndIpv6);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained dual-stack facility authority");
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

        for family in [CanaryFlowAddressFamily::Ipv4, CanaryFlowAddressFamily::Ipv6] {
            assert_eq!(
                RuntimeWriter::observe_canary_route(&mut writer, &generation, &session, family,)
                    .expect("the exact dual-stack route query is a definite operation"),
                None,
                "the scripted converger intentionally has no typed route receipt"
            );
        }
        let rpdb = request.pre_binding().environment().rpdb();
        assert_eq!(writer.convergence.route_queries.len(), 2);
        for (query, flow) in writer
            .convergence
            .route_queries
            .iter()
            .zip([CanaryFlow::Ipv4TcpEcho, CanaryFlow::Ipv6TcpEcho])
        {
            assert_eq!(
                query.destination(),
                std::net::SocketAddr::new(
                    request.peer_address(flow),
                    request.responder_port(flow).get(),
                )
            );
            assert_eq!(query.uid(), rpdb.engine_uid());
            assert_eq!(query.mark(), rpdb.proxy_mark_value());
            assert_eq!(query.deadline(), request.deadline().expires_at());
        }

        RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
            .expect("retire dual-stack selector session")
            .expect("native writer returns dual-stack retirement proof");
        assert!(writer.convergence.selector.is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn retained_facility_live_failure_poisons_recovery_and_retains_the_selector() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 82);
        let (alternate, _alternate_authority) = selector_request(&fixture, 83);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");

        let substituted = RuntimeWriter::reobserve_retained_canary_facility(
            &mut writer,
            &generation,
            &session,
            &peer_reaped_authority(&alternate),
        )
        .expect_err("a substituted peer-reap authority must reject before live observation");
        assert_eq!(
            substituted.to_string(),
            "retained facility reobservation substituted peer-reap authority"
        );
        assert!(!writer.recovery_required);

        let failure = RuntimeWriter::reobserve_retained_canary_facility(
            &mut writer,
            &generation,
            &session,
            &peer_reaped_authority(&request),
        )
        .expect_err("the synthetic daemon namespace must fail after descriptor validation");
        assert_eq!(
            failure.to_string(),
            "retained facility observer is not in the immutable daemon network namespace"
        );
        assert!(writer.recovery_required);
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        assert!(writer.convergence.selector.is_some());

        let retirement =
            RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
                .expect_err("poisoned observation cannot mint selector retirement");
        assert_eq!(
            retirement.to_string(),
            "native canary attempt operation requires capture recovery"
        );
        RuntimeWriter::capture_stop(&mut writer)
            .expect("capture stop recovers the poisoned retained facility observation");
        assert!(!writer.recovery_required);
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    #[ignore = "requires network-namespace creation and setns authority"]
    fn retained_facility_observer_thread_never_changes_the_caller_namespace() {
        use std::os::unix::fs::MetadataExt as _;

        let caller_namespace = current_network_namespace_identity()
            .expect("inspect caller network namespace before privileged smoke");
        let peer_thread = std::thread::Builder::new()
            .name("flux-canary-peer-fixture".to_owned())
            .spawn(|| {
                // SAFETY: this dedicated fixture thread terminates after opening
                // an owned descriptor for the new namespace; it is never reused.
                if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                let handle = fs::File::open("/proc/thread-self/ns/net")?;
                let metadata = handle.metadata()?;
                let identity = NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino())
                    .ok_or_else(|| io::Error::other("peer namespace has a zero inode"))?;
                Ok((handle, identity))
            })
            .expect("spawn privileged peer namespace fixture");
        let (peer_handle, peer_namespace) = peer_thread
            .join()
            .expect("join privileged peer namespace fixture")
            .expect("create privileged peer network namespace");
        assert_ne!(peer_namespace, caller_namespace);

        let fixture = EngineFixture::new();
        let request = selector_request_for_network_namespaces(
            &fixture,
            84,
            CanaryAddressFamilies::Ipv4Only,
            caller_namespace,
            peer_namespace,
        );
        let authority = RetainedCanaryFacilityAuthority::new(
            request.pre_binding().environment().facility(),
            peer_namespace,
            peer_handle,
        )
        .expect("retain privileged peer namespace authority");
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach privileged retained facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare privileged required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate privileged required native Generation");
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve privileged selector session")
                .expect("native writer supplies privileged selector ownership");

        RuntimeWriter::reobserve_retained_canary_facility(
            &mut writer,
            &generation,
            &session,
            &peer_reaped_authority(&request),
        )
        .expect_err("empty fixture namespace has no declared canary veth facility");
        assert_eq!(
            current_network_namespace_identity()
                .expect("inspect caller namespace after observer thread termination"),
            caller_namespace
        );
        assert!(writer.recovery_required);
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        RuntimeWriter::capture_stop(&mut writer)
            .expect("recover privileged smoke state after namespace-isolation proof");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn uncertain_selector_population_recovers_before_capture_stop() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 75);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn uncertain_selector_retirement_recovers_before_the_session_guard() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 76);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_requires_positive_platform_receipts() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 77);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
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

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_attempt_observations_remain_request_bound_and_explicitly_unsupported() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 79);
        let (alternate, _alternate_authority) = selector_request(&fixture, 80);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        let substituted_generation = PreparedGeneration::new(
            generation.id(),
            fixture.spec.clone(),
            EngineCapabilityProfileRevision::from_fixture_bytes([0xA5; 32]),
            FunctionalCanaryGateMode::RequiredUnqualified,
            Some(EngineSupervisedDeliveryReportContract::schema_v1_fixture()),
            test_xtables_capture_path_selection(),
            qualified_xtables_capture_path_evidence().valid_until(),
        )
        .with_prepared_canary_generation(generation.prepared_canary_generation().cloned())
        .with_retained_canary_facility(
            generation
                .retained_canary_facility()
                .expect("required Generation retains the admitted facility"),
        );
        let substituted_reservation = RuntimeWriter::reserve_canary_selector_session(
            &mut writer,
            &substituted_generation,
            &request,
        )
        .expect_err("a same-ID substituted Generation cannot reserve the selector");
        assert_eq!(
            substituted_reservation.to_string(),
            "native canary selector session does not match the retained Generation and facility"
        );
        assert!(writer.convergence.selector.is_none());
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");

        let substituted_observation = RuntimeWriter::observe_canary_route(
            &mut writer,
            &substituted_generation,
            &session,
            CanaryFlowAddressFamily::Ipv4,
        )
        .expect_err("a same-ID substituted Generation cannot observe the active attempt");
        assert_eq!(
            substituted_observation.to_string(),
            "native canary attempt operation does not match the retained Generation and facility"
        );
        assert!(writer.convergence.route_queries.is_empty());

        assert_eq!(
            RuntimeWriter::observe_canary_route(
                &mut writer,
                &generation,
                &session,
                CanaryFlowAddressFamily::Ipv4,
            )
            .expect("unsupported route observation is a definite result"),
            None
        );
        let disabled = RuntimeWriter::observe_canary_route(
            &mut writer,
            &generation,
            &session,
            CanaryFlowAddressFamily::Ipv6,
        )
        .expect_err("IPv6 observation must be rejected for an IPv4-only request");
        assert_eq!(
            disabled.to_string(),
            "native canary route observation requested a disabled address family"
        );
        assert_eq!(
            RuntimeWriter::observe_canary_counters(&mut writer, &generation, &session)
                .expect("unsupported counter observation is a definite result"),
            None
        );
        assert_eq!(
            RuntimeWriter::retire_canary_counters(&mut writer, &generation, &session)
                .expect("unsupported counter retirement is a definite result"),
            None
        );
        let route_query = writer.convergence.route_queries[0];
        let rpdb = request.pre_binding().environment().rpdb();
        assert_eq!(
            route_query.destination(),
            std::net::SocketAddr::new(
                request.peer_address(CanaryFlow::Ipv4TcpEcho),
                request.responder_port(CanaryFlow::Ipv4TcpEcho).get(),
            )
        );
        assert_eq!(route_query.uid(), rpdb.engine_uid());
        assert_eq!(route_query.mark(), rpdb.proxy_mark_value());
        assert_eq!(route_query.deadline(), request.deadline().expires_at());
        assert_eq!(
            writer.convergence.counter_observation_deadlines,
            [request.deadline().expires_at()]
        );
        assert_eq!(
            writer.convergence.counter_retirement_deadlines,
            [request.deadline().expires_at()]
        );

        let substitute = CanarySelectorSession::reserved_for(&alternate);
        let substituted =
            RuntimeWriter::observe_canary_counters(&mut writer, &generation, &substitute)
                .expect_err("counter observation cannot substitute the active request");
        assert_eq!(
            substituted.to_string(),
            "native canary attempt operation substituted the active request"
        );
        assert!(!writer.recovery_required);

        let substituted_retirement = RuntimeWriter::retire_canary_selector_session(
            &mut writer,
            &substituted_generation,
            CanarySelectorSession::reserved_for(&request),
        )
        .expect_err("a same-ID substituted Generation cannot retire the active attempt");
        assert_eq!(
            substituted_retirement.to_string(),
            "native canary selector retirement does not match the retained Generation and facility"
        );
        assert_eq!(
            writer.active_canary_selector_session.as_ref(),
            Some(&request)
        );
        assert!(writer.convergence.selector.is_some());

        RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
            .expect("retire exact selector session")
            .expect("native writer returns exact retirement");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn uncertain_attempt_observation_requires_recovery_before_selector_cleanup() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 81);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
        let generation = RuntimeWriter::prepare(&mut writer, Reason::Boot)
            .expect("prepare required native Generation");
        RuntimeWriter::capture_start(&mut writer, &generation)
            .expect("activate required native Generation");
        let session =
            RuntimeWriter::reserve_canary_selector_session(&mut writer, &generation, &request)
                .expect("reserve exact selector session")
                .expect("native writer supplies selector-session ownership");
        writer.convergence.fail_counter_observation_once = true;

        let observation =
            RuntimeWriter::observe_canary_counters(&mut writer, &generation, &session)
                .expect_err("an uncertain counter observation must fail closed");
        assert!(
            observation
                .to_string()
                .contains("injected uncertain native counter observation failure")
        );
        assert!(writer.recovery_required);
        let retirement =
            RuntimeWriter::retire_canary_selector_session(&mut writer, &generation, session)
                .expect_err("uncertain observation cannot mint selector-retirement evidence");
        assert_eq!(
            retirement.to_string(),
            "native canary attempt operation requires capture recovery"
        );

        RuntimeWriter::capture_stop(&mut writer)
            .expect("capture stop recovers the uncertain active attempt");
        assert!(!writer.recovery_required);
        assert!(writer.active_canary_selector_session.is_none());
        assert!(writer.convergence.selector.is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn native_selector_session_must_retire_before_ownership_observation_or_capture_stop() {
        let fixture = EngineFixture::new();
        let (request, authority) = selector_request(&fixture, 73);
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut writer = writer(
            &events,
            None,
            None,
            [required_canary_generation(17, &fixture, &request)],
            [],
        )
        .with_retained_canary_facility_authority(authority)
        .expect("attach retained canary facility authority");
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
