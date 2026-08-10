use std::error::Error;
use std::fmt;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use flux_platform::{
    ProcessHandle, ProcessHandleErrorKind, ProcessHandleObservationError, ProcessHandleOpenError,
    ProcessIdentity, ProcessObservation,
};

use super::super::{
    CANARY_PEER_SERVER_SLOTS, CanaryProcessIdentity, CanaryProcessRetirementEvidence,
    InstalledSupervisedDeliveryReportProducer,
};
use super::insert_distinct_role_key;
use crate::functional_canary::supervised_delivery_report::collector::SupervisedDeliveryReportClientRetirementAuthority;
use crate::process_authority::{ProcessAuthorityOpeningId, ProcessAuthorityOpeningIdExhausted};

const CHILD_REAP_POLL_INTERVAL: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DriverProcessRole {
    Client,
    PeerServer { slot: usize },
}

impl fmt::Display for DriverProcessRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client => formatter.write_str("client"),
            Self::PeerServer { slot } => write!(formatter, "peer-server[{slot}]"),
        }
    }
}

/// Driver-owned live child authority. There is deliberately no constructor
/// from PID/start ticks and no operation that releases the raw `Child`.
pub(super) struct RetainedDriverChild {
    role: DriverProcessRole,
    child: Option<Child>,
    handle: Option<ProcessHandle>,
    opening_id: ProcessAuthorityOpeningId,
    opened_at: Instant,
}

impl RetainedDriverChild {
    pub(super) fn open(
        role: DriverProcessRole,
        child: Child,
    ) -> Result<Self, DriverProcessAuthorityError> {
        let mut child = ChildReapGuard(Some(child));
        let handle = ProcessHandle::open_child(
            child
                .0
                .as_ref()
                .expect("child guard is populated until authority construction succeeds"),
        )
        .map_err(|source| DriverProcessAuthorityError::OpenProcessHandle { role, source })?;
        let opening_id = ProcessAuthorityOpeningId::allocate()
            .map_err(|source| DriverProcessAuthorityError::OpeningIdentity { role, source })?;
        Ok(Self {
            role,
            child: child.0.take(),
            handle: Some(handle),
            opening_id,
            opened_at: Instant::now(),
        })
    }

    #[must_use]
    pub(super) fn identity(&self) -> ProcessIdentity {
        self.handle
            .as_ref()
            .expect("live retained authority owns its process handle")
            .identity()
    }

    #[must_use]
    pub(super) const fn opening_id(&self) -> ProcessAuthorityOpeningId {
        self.opening_id
    }

    pub(super) fn terminate_and_reap(
        mut self,
        quiesced_at: Instant,
        exclusive_deadline: Instant,
    ) -> Result<ReapedDriverChild, DriverProcessAuthorityError> {
        if quiesced_at < self.opened_at || quiesced_at >= exclusive_deadline {
            return Err(DriverProcessAuthorityError::InvalidQuiescence { role: self.role });
        }
        let child = self
            .child
            .as_mut()
            .expect("live retained authority owns its child");
        let first_status =
            child
                .try_wait()
                .map_err(|source| DriverProcessAuthorityError::ChildOperation {
                    role: self.role,
                    operation: "inspect before termination",
                    source,
                })?;
        let first_observed_at = Instant::now();
        if first_observed_at >= exclusive_deadline {
            return Err(DriverProcessAuthorityError::DeadlineExpired {
                role: self.role,
                operation: "termination",
            });
        }
        if first_observed_at < quiesced_at {
            return Err(DriverProcessAuthorityError::InvalidQuiescence { role: self.role });
        }
        if first_status.is_some() {
            return Err(DriverProcessAuthorityError::ExitedBeforeQuiescence { role: self.role });
        }

        child
            .kill()
            .map_err(|source| DriverProcessAuthorityError::ChildOperation {
                role: self.role,
                operation: "terminate",
                source,
            })?;
        let terminated_at = Instant::now();
        if terminated_at >= exclusive_deadline {
            return Err(DriverProcessAuthorityError::DeadlineExpired {
                role: self.role,
                operation: "termination",
            });
        }
        let reaped_at = loop {
            let status =
                child
                    .try_wait()
                    .map_err(|source| DriverProcessAuthorityError::ChildOperation {
                        role: self.role,
                        operation: "parent reap",
                        source,
                    })?;
            let observed_at = Instant::now();
            if let Some(_status) = status {
                break observed_at;
            }
            if observed_at >= exclusive_deadline {
                return Err(DriverProcessAuthorityError::DeadlineExpired {
                    role: self.role,
                    operation: "parent reap",
                });
            }
            sleep_until_reap_poll(exclusive_deadline);
        };

        if terminated_at < quiesced_at
            || reaped_at < terminated_at
            || reaped_at >= exclusive_deadline
        {
            return Err(DriverProcessAuthorityError::InvalidRetirement { role: self.role });
        }
        let handle = self
            .handle
            .take()
            .expect("live retained authority owns its process handle");
        let identity = handle.identity();
        let retirement = CanaryProcessRetirementEvidence::new(
            CanaryProcessIdentity::new(identity.pid(), identity.start_time_ticks()),
            quiesced_at,
            terminated_at,
            reaped_at,
        );
        drop(self.child.take());
        Ok(ReapedDriverChild {
            role: self.role,
            handle,
            opening_id: self.opening_id,
            opened_at: self.opened_at,
            retirement,
        })
    }

    /// Compensates a failed pre-proof child transaction without minting
    /// retirement evidence. Success means this parent reaped the exact child.
    pub(super) fn abort_and_reap(
        mut self,
        exclusive_deadline: Instant,
    ) -> Result<(), DriverProcessAuthorityError> {
        let child = self
            .child
            .as_mut()
            .expect("live retained authority owns its child");
        abort_child_and_reap(
            child,
            self.role,
            "inspect failed child transaction",
            "abort failed child transaction",
            "reap failed child transaction",
            exclusive_deadline,
        )?;
        drop(self.child.take());
        Ok(())
    }
}

/// Compensate a child that failed before retained process authority could be
/// opened. This deliberately shares the exact bounded kill/reap primitive used
/// after authority construction instead of growing a second raw-child loop in
/// the packaged protocol.
pub(super) fn abort_unready_driver_child(
    role: DriverProcessRole,
    child: &mut Child,
    exclusive_deadline: Instant,
) -> Result<(), DriverProcessAuthorityError> {
    abort_child_and_reap(
        child,
        role,
        "inspect unready driver child",
        "abort unready driver child",
        "reap unready driver child",
        exclusive_deadline,
    )
}

fn abort_child_and_reap(
    child: &mut Child,
    role: DriverProcessRole,
    inspect_operation: &'static str,
    abort_operation: &'static str,
    reap_operation: &'static str,
    exclusive_deadline: Instant,
) -> Result<(), DriverProcessAuthorityError> {
    match child
        .try_wait()
        .map_err(|source| DriverProcessAuthorityError::ChildOperation {
            role,
            operation: inspect_operation,
            source,
        })? {
        Some(_) => return Ok(()),
        None => child
            .kill()
            .map_err(|source| DriverProcessAuthorityError::ChildOperation {
                role,
                operation: abort_operation,
                source,
            })?,
    }
    loop {
        if child
            .try_wait()
            .map_err(|source| DriverProcessAuthorityError::ChildOperation {
                role,
                operation: reap_operation,
                source,
            })?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= exclusive_deadline {
            return Err(DriverProcessAuthorityError::DeadlineExpired {
                role,
                operation: reap_operation,
            });
        }
        sleep_until_reap_poll(exclusive_deadline);
    }
}

impl Drop for RetainedDriverChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            retire_child_without_blocking(child);
        }
    }
}

/// Non-cloneable proof returned only after the driver-owned `Child` has been
/// parent-reaped. The retained pidfd is still unobserved at this stage.
pub(super) struct ReapedDriverChild {
    role: DriverProcessRole,
    handle: ProcessHandle,
    opening_id: ProcessAuthorityOpeningId,
    opened_at: Instant,
    retirement: CanaryProcessRetirementEvidence,
}

impl ReapedDriverChild {
    #[must_use]
    pub(super) const fn retirement(&self) -> CanaryProcessRetirementEvidence {
        self.retirement
    }

    pub(super) fn bind_supervised_report_retirement(
        &self,
        installed: InstalledSupervisedDeliveryReportProducer,
    ) -> Result<
        SupervisedDeliveryReportClientRetirementAuthority,
        (
            InstalledSupervisedDeliveryReportProducer,
            DriverProcessAuthorityError,
        ),
    > {
        if let Err(error) = require_role(self.role, DriverProcessRole::Client) {
            return Err((installed, error));
        }
        let authority = installed.into_client_retirement_authority(self.retirement);
        Ok(authority)
    }

    pub(super) fn verify_post_reap_exit(
        self,
        exclusive_deadline: Instant,
    ) -> Result<VerifiedDriverChild, DriverProcessAuthorityError> {
        let exit = self.handle.reobserve();
        let exit_observed_at = Instant::now();
        if exit_observed_at >= exclusive_deadline {
            return Err(DriverProcessAuthorityError::DeadlineExpired {
                role: self.role,
                operation: "post-reap pidfd observation",
            });
        }
        match exit {
            Err(source) if source.kind() == ProcessHandleErrorKind::Exited => {}
            Err(source) => {
                return Err(DriverProcessAuthorityError::PostReapObservation {
                    role: self.role,
                    source,
                });
            }
            Ok(_) => {
                return Err(DriverProcessAuthorityError::ProcessLiveAfterParentReap {
                    role: self.role,
                });
            }
        }
        let observation = self.handle.initial_observation();
        Ok(VerifiedDriverChild {
            role: self.role,
            handle: self.handle,
            opening_id: self.opening_id,
            observation,
            observed_at: self.opened_at,
            retirement: self.retirement,
            exit_observed_at,
        })
    }
}

/// Consumed child-origin observation plus independently verified parent-reap
/// and post-reap pidfd-exit chronology.
pub(super) struct VerifiedDriverChild {
    role: DriverProcessRole,
    handle: ProcessHandle,
    opening_id: ProcessAuthorityOpeningId,
    observation: ProcessObservation,
    observed_at: Instant,
    retirement: CanaryProcessRetirementEvidence,
    exit_observed_at: Instant,
}

impl VerifiedDriverChild {
    #[must_use]
    pub(super) fn identity(&self) -> ProcessIdentity {
        self.observation.identity()
    }

    #[must_use]
    pub(super) const fn opening_id(&self) -> ProcessAuthorityOpeningId {
        self.opening_id
    }

    #[must_use]
    pub(super) const fn observation(&self) -> &ProcessObservation {
        &self.observation
    }

    #[must_use]
    pub(super) const fn observed_at(&self) -> Instant {
        self.observed_at
    }

    #[must_use]
    pub(super) const fn retirement(&self) -> CanaryProcessRetirementEvidence {
        self.retirement
    }

    #[must_use]
    pub(super) const fn exit_observed_at(&self) -> Instant {
        self.exit_observed_at
    }
}

impl fmt::Debug for VerifiedDriverChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedDriverChild")
            .field("role", &self.role)
            .field("opening_id", &self.opening_id)
            .field("observation", &self.observation)
            .field("observed_at", &self.observed_at)
            .field("retirement", &self.retirement)
            .field("exit_observed_at", &self.exit_observed_at)
            .finish_non_exhaustive()
    }
}

/// Single-use collection of every driver-owned child after exact parent reap.
pub(super) struct DriverProcessProof {
    client: ReapedDriverChild,
    peer_servers: [ReapedDriverChild; CANARY_PEER_SERVER_SLOTS],
}

impl DriverProcessProof {
    pub(super) fn new(
        client: ReapedDriverChild,
        peer_servers: [ReapedDriverChild; CANARY_PEER_SERVER_SLOTS],
    ) -> Result<Self, DriverProcessAuthorityError> {
        require_role(client.role, DriverProcessRole::Client)?;
        for (slot, peer) in peer_servers.iter().enumerate() {
            require_role(peer.role, DriverProcessRole::PeerServer { slot })?;
        }

        let mut identities: [Option<(DriverProcessRole, ProcessIdentity)>;
            CANARY_PEER_SERVER_SLOTS + 1] = [None; CANARY_PEER_SERVER_SLOTS + 1];
        let mut openings: [Option<(DriverProcessRole, ProcessAuthorityOpeningId)>;
            CANARY_PEER_SERVER_SLOTS + 1] = [None; CANARY_PEER_SERVER_SLOTS + 1];
        for (index, child) in std::iter::once(&client)
            .chain(peer_servers.iter())
            .enumerate()
        {
            let observed = child.handle.identity();
            let claimed = process_identity(child.retirement.process);
            if observed != claimed {
                return Err(DriverProcessAuthorityError::IdentityMismatch {
                    role: child.role,
                    observed,
                    claimed,
                });
            }
            insert_identity(&mut identities, index, child.role, observed)?;
            insert_opening(&mut openings, index, child.role, child.opening_id)?;
        }
        Ok(Self {
            client,
            peer_servers,
        })
    }

    pub(super) fn verify_post_reap_exit(
        self,
        exclusive_deadline: Instant,
    ) -> Result<VerifiedDriverProcessProof, DriverProcessAuthorityError> {
        let client = self.client.verify_post_reap_exit(exclusive_deadline)?;
        let [peer_0, peer_1, peer_2] = self.peer_servers;
        let peer_servers = [
            peer_0.verify_post_reap_exit(exclusive_deadline)?,
            peer_1.verify_post_reap_exit(exclusive_deadline)?,
            peer_2.verify_post_reap_exit(exclusive_deadline)?,
        ];
        Ok(VerifiedDriverProcessProof {
            client,
            peer_servers,
        })
    }
}

/// All driver child observations after parent reap and retained-pidfd exit
/// verification. Consuming this value is the only production route to the
/// client/peer portion of process-receipt authority.
pub(super) struct VerifiedDriverProcessProof {
    client: VerifiedDriverChild,
    peer_servers: [VerifiedDriverChild; CANARY_PEER_SERVER_SLOTS],
}

impl VerifiedDriverProcessProof {
    #[must_use]
    pub(super) fn latest_observed_at(&self) -> Instant {
        self.peer_servers
            .iter()
            .fold(self.client.exit_observed_at(), |latest, peer| {
                std::cmp::max(latest, peer.exit_observed_at())
            })
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        VerifiedDriverChild,
        [VerifiedDriverChild; CANARY_PEER_SERVER_SLOTS],
    ) {
        (self.client, self.peer_servers)
    }
}

fn require_role(
    observed: DriverProcessRole,
    expected: DriverProcessRole,
) -> Result<(), DriverProcessAuthorityError> {
    if observed == expected {
        Ok(())
    } else {
        Err(DriverProcessAuthorityError::RoleMismatch { expected, observed })
    }
}

fn process_identity(identity: CanaryProcessIdentity) -> ProcessIdentity {
    ProcessIdentity::new(identity.pid(), identity.start_time_ticks())
}

fn insert_identity(
    identities: &mut [Option<(DriverProcessRole, ProcessIdentity)>; CANARY_PEER_SERVER_SLOTS + 1],
    index: usize,
    role: DriverProcessRole,
    identity: ProcessIdentity,
) -> Result<(), DriverProcessAuthorityError> {
    insert_distinct_role_key(identities, index, role, identity).map_err(|first| {
        DriverProcessAuthorityError::IdentityReused {
            first,
            second: role,
        }
    })
}

fn insert_opening(
    openings: &mut [Option<(DriverProcessRole, ProcessAuthorityOpeningId)>;
             CANARY_PEER_SERVER_SLOTS + 1],
    index: usize,
    role: DriverProcessRole,
    opening_id: ProcessAuthorityOpeningId,
) -> Result<(), DriverProcessAuthorityError> {
    insert_distinct_role_key(openings, index, role, opening_id).map_err(|first| {
        DriverProcessAuthorityError::HandleReused {
            first,
            second: role,
        }
    })
}

#[derive(Debug)]
pub(super) enum DriverProcessAuthorityError {
    OpenProcessHandle {
        role: DriverProcessRole,
        source: ProcessHandleOpenError,
    },
    OpeningIdentity {
        role: DriverProcessRole,
        source: ProcessAuthorityOpeningIdExhausted,
    },
    InvalidQuiescence {
        role: DriverProcessRole,
    },
    ExitedBeforeQuiescence {
        role: DriverProcessRole,
    },
    ChildOperation {
        role: DriverProcessRole,
        operation: &'static str,
        source: std::io::Error,
    },
    DeadlineExpired {
        role: DriverProcessRole,
        operation: &'static str,
    },
    InvalidRetirement {
        role: DriverProcessRole,
    },
    PostReapObservation {
        role: DriverProcessRole,
        source: ProcessHandleObservationError,
    },
    ProcessLiveAfterParentReap {
        role: DriverProcessRole,
    },
    RoleMismatch {
        expected: DriverProcessRole,
        observed: DriverProcessRole,
    },
    IdentityMismatch {
        role: DriverProcessRole,
        observed: ProcessIdentity,
        claimed: ProcessIdentity,
    },
    IdentityReused {
        first: DriverProcessRole,
        second: DriverProcessRole,
    },
    HandleReused {
        first: DriverProcessRole,
        second: DriverProcessRole,
    },
}

impl fmt::Display for DriverProcessAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenProcessHandle { role, source } => {
                write!(formatter, "open exact {role} process authority: {source}")
            }
            Self::OpeningIdentity { role, .. } => {
                write!(
                    formatter,
                    "allocate exact {role} process-authority opening identity"
                )
            }
            Self::InvalidQuiescence { role } => {
                write!(
                    formatter,
                    "{role} quiescence is outside its live authority interval"
                )
            }
            Self::ExitedBeforeQuiescence { role } => {
                write!(
                    formatter,
                    "exact {role} child exited before post-quiescence liveness was observed"
                )
            }
            Self::ChildOperation {
                role,
                operation,
                source,
            } => write!(formatter, "{operation} for exact {role} child: {source}"),
            Self::DeadlineExpired { role, operation } => {
                write!(
                    formatter,
                    "{operation} for exact {role} child reached the deadline"
                )
            }
            Self::InvalidRetirement { role } => {
                write!(
                    formatter,
                    "exact {role} child retirement chronology is invalid"
                )
            }
            Self::PostReapObservation { role, source } => {
                write!(
                    formatter,
                    "observe exact {role} pidfd after parent reap: {source}"
                )
            }
            Self::ProcessLiveAfterParentReap { role } => {
                write!(
                    formatter,
                    "exact {role} pidfd remained live after parent reap"
                )
            }
            Self::RoleMismatch { expected, observed } => {
                write!(
                    formatter,
                    "expected {expected} child authority, observed {observed}"
                )
            }
            Self::IdentityMismatch {
                role,
                observed,
                claimed,
            } => write!(
                formatter,
                "exact {role} child identity {observed:?} does not match retirement identity {claimed:?}"
            ),
            Self::IdentityReused { first, second } => {
                write!(
                    formatter,
                    "process identity is reused by {first} and {second}"
                )
            }
            Self::HandleReused { first, second } => {
                write!(
                    formatter,
                    "process-handle opening is reused by {first} and {second}"
                )
            }
        }
    }
}

impl Error for DriverProcessAuthorityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::OpenProcessHandle { source, .. } => Some(source),
            Self::ChildOperation { source, .. } => Some(source),
            Self::PostReapObservation { source, .. } => Some(source),
            Self::OpeningIdentity { .. }
            | Self::InvalidQuiescence { .. }
            | Self::ExitedBeforeQuiescence { .. }
            | Self::DeadlineExpired { .. }
            | Self::InvalidRetirement { .. }
            | Self::ProcessLiveAfterParentReap { .. }
            | Self::RoleMismatch { .. }
            | Self::IdentityMismatch { .. }
            | Self::IdentityReused { .. }
            | Self::HandleReused { .. } => None,
        }
    }
}

struct ChildReapGuard(Option<Child>);

impl Drop for ChildReapGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            retire_child_without_blocking(child);
        }
    }
}

pub(super) fn retire_child_without_blocking(mut child: Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    let _ = child.kill();
    let pid = child.id();
    if let Ok(handle) = thread::Builder::new()
        .name(format!("flux-canary-reap-{pid}"))
        .spawn(move || {
            let _ = child.wait();
        })
    {
        drop(handle);
    }
}

fn sleep_until_reap_poll(exclusive_deadline: Instant) {
    let remaining = exclusive_deadline.saturating_duration_since(Instant::now());
    thread::sleep(CHILD_REAP_POLL_INTERVAL.min(remaining));
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::num::NonZeroU64;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::{DriverProcessProof, DriverProcessRole, RetainedDriverChild};
    use crate::engine_supervisor::EngineChildAuthority;
    use crate::functional_canary::CanaryAddressFamilies;
    use crate::functional_canary::local_output::process_ownership_receipt::{
        TproxyLocalOutputProcessOwnershipAuthority, TproxyLocalOutputProcessOwnershipReceipt,
        TproxyLocalOutputProcessOwnershipReceiptError,
    };
    use crate::functional_canary::supervised_delivery_report::{
        AdmittedSupervisedDeliveryReportBinding, collector,
    };
    use crate::functional_canary::tests::Fixture;
    use crate::functional_canary::{
        CANARY_PEER_SERVER_SLOTS, CanaryAttemptRequest, CanaryProcessIdentity,
        CanaryProcessRetirementEvidence, InstalledSupervisedDeliveryReportProducer,
    };
    use crate::generation_engine_config::EngineSupervisedDeliveryReportContract;
    use flux_platform::ProcessHandle;

    fn sleeping_child(role: DriverProcessRole) -> RetainedDriverChild {
        let child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn retained-driver-child fixture");
        RetainedDriverChild::open(role, child).expect("open exact child-origin authority")
    }

    fn reaped_processes() -> (super::ReapedDriverChild, [super::ReapedDriverChild; 3]) {
        let client = sleeping_child(DriverProcessRole::Client);
        let peers =
            std::array::from_fn(|slot| sleeping_child(DriverProcessRole::PeerServer { slot }));
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = client
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and reap client fixture");
        let peers = peers.map(|peer| {
            peer.terminate_and_reap(Instant::now(), deadline)
                .expect("terminate and reap peer fixture")
        });
        (client, peers)
    }

    fn installed_report_fixture(
        request: &CanaryAttemptRequest,
    ) -> InstalledSupervisedDeliveryReportProducer {
        let engine = request.pre_binding().engine();
        let admitted = AdmittedSupervisedDeliveryReportBinding::new(
            engine.artifacts(),
            engine.engine_profile_revision(),
            EngineSupervisedDeliveryReportContract::schema_v1_fixture(),
        )
        .expect("fixture report binding is canonical");
        let authority =
            collector::SupervisedDeliveryReportPrebindAuthority::admitted(admitted, request)
                .expect("fixture report binding matches the request");
        let (producer, collector) =
            collector::prebind(authority, Instant::now).expect("prebind installed-report fixture");
        drop(collector);
        producer.into_engine_handoff().into_installed_fixture()
    }

    #[test]
    fn installed_report_proof_binds_only_a_reaped_client_role() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = sleeping_child(DriverProcessRole::Client)
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and reap exact client fixture");
        let peer = sleeping_child(DriverProcessRole::PeerServer { slot: 0 })
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and reap exact peer fixture");

        let (installed, error) = match peer
            .bind_supervised_report_retirement(installed_report_fixture(fixture.request()))
        {
            Ok(_) => panic!("a peer role cannot bind client report retirement"),
            Err(failure) => failure,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::RoleMismatch {
                expected: DriverProcessRole::Client,
                observed: DriverProcessRole::PeerServer { slot: 0 },
            }
        ));
        let authority = match client.bind_supervised_report_retirement(installed) {
            Ok(authority) => authority,
            Err(_) => panic!("the exact client consumes the proof preserved by peer rejection"),
        };
        drop(authority);
    }

    #[test]
    fn retained_children_reap_before_their_pidfds_verify_exit() {
        let client = sleeping_child(DriverProcessRole::Client);
        let peer = sleeping_child(DriverProcessRole::PeerServer { slot: 0 });
        let client_identity = client.identity();
        let peer_identity = peer.identity();
        let client_opening = client.opening_id();
        let peer_opening = peer.opening_id();
        let deadline = Instant::now() + Duration::from_secs(2);

        assert_ne!(client_identity, peer_identity);
        assert_ne!(client_opening, peer_opening);

        let client = client
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and parent-reap client");
        let peer = peer
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and parent-reap peer");
        let client = client
            .verify_post_reap_exit(deadline)
            .expect("client pidfd reports exit only after reap");
        let peer = peer
            .verify_post_reap_exit(deadline)
            .expect("peer pidfd reports exit only after reap");

        assert_eq!(client.identity(), client_identity);
        assert_eq!(peer.identity(), peer_identity);
        assert_eq!(client.opening_id(), client_opening);
        assert_eq!(peer.opening_id(), peer_opening);
        assert!(client.retirement().quiesced_at <= client.retirement().terminated_at);
        assert!(client.retirement().terminated_at <= client.retirement().reaped_at);
        assert!(client.retirement().reaped_at <= client.exit_observed_at());
        assert!(peer.retirement().reaped_at <= peer.exit_observed_at());
    }

    #[test]
    fn dropping_live_child_authority_cannot_produce_a_reaped_proof() {
        let child = sleeping_child(DriverProcessRole::Client);
        let identity = child.identity();
        let drop_started_at = Instant::now();
        drop(child);
        assert!(drop_started_at.elapsed() < Duration::from_secs(1));

        let pid = i32::try_from(identity.pid().get()).expect("test PID fits pid_t");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let mut status = 0;
            // SAFETY: the positive PID came from the retained child. WNOHANG
            // does not block and the status pointer is valid for this call.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == -1 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
                break;
            }
            assert!(Instant::now() < deadline, "deferred child reap timed out");
            std::thread::yield_now();
        }
    }

    #[test]
    fn child_exited_before_quiescence_cannot_produce_a_reaped_proof() {
        let mut child = sleeping_child(DriverProcessRole::Client);
        child
            .child
            .as_mut()
            .expect("retained authority owns its live child")
            .kill()
            .expect("kill retained child before quiescence");
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = child
                .child
                .as_mut()
                .expect("retained authority owns its child until retirement")
                .try_wait()
                .expect("observe retained child exit");
            if status.is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "retained child did not exit before the test deadline"
            );
            std::thread::yield_now();
        }
        let quiesced_at = Instant::now();

        let error = match child.terminate_and_reap(quiesced_at, deadline) {
            Ok(_) => panic!("a child already dead at quiescence cannot produce retirement proof"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::ExitedBeforeQuiescence {
                role: DriverProcessRole::Client
            }
        ));
    }

    #[test]
    fn copied_process_identity_cannot_replace_child_origin_authority() {
        let (mut client, peers) = reaped_processes();
        let retirement = client.retirement;
        client.retirement = CanaryProcessRetirementEvidence::new(
            CanaryProcessIdentity::new(
                retirement.process.pid(),
                retirement
                    .process
                    .start_time_ticks()
                    .checked_add(1)
                    .expect("alternate copied start ticks"),
            ),
            retirement.quiesced_at,
            retirement.terminated_at,
            retirement.reaped_at,
        );

        let error = match DriverProcessProof::new(client, peers) {
            Ok(_) => panic!("copied process identity must not produce driver process proof"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::IdentityMismatch {
                role: DriverProcessRole::Client,
                ..
            }
        ));
    }

    #[test]
    fn misplaced_driver_role_cannot_enter_driver_process_proof() {
        let (client, mut peers) = reaped_processes();
        peers.swap(0, 1);

        let error = match DriverProcessProof::new(client, peers) {
            Ok(_) => panic!("misplaced peer authority must not produce driver process proof"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::RoleMismatch {
                expected: DriverProcessRole::PeerServer { slot: 0 },
                observed: DriverProcessRole::PeerServer { slot: 1 }
            }
        ));
    }

    #[test]
    fn duplicate_process_identity_cannot_enter_driver_process_proof() {
        let client = sleeping_child(DriverProcessRole::Client);
        let duplicate_handle = ProcessHandle::open_child(
            client
                .child
                .as_ref()
                .expect("retained client owns the live child"),
        )
        .expect("open a second handle to the exact client child");
        let duplicate_opening = crate::process_authority::ProcessAuthorityOpeningId::allocate()
            .expect("allocate distinct duplicate-identity opening");
        let duplicate_opened_at = Instant::now();
        let peers =
            std::array::from_fn(|slot| sleeping_child(DriverProcessRole::PeerServer { slot }));
        let deadline = Instant::now() + Duration::from_secs(2);
        let client = client
            .terminate_and_reap(Instant::now(), deadline)
            .expect("terminate and reap client fixture");
        let mut peers = peers.map(|peer| {
            peer.terminate_and_reap(Instant::now(), deadline)
                .expect("terminate and reap peer fixture")
        });
        peers[0] = super::ReapedDriverChild {
            role: DriverProcessRole::PeerServer { slot: 0 },
            handle: duplicate_handle,
            opening_id: duplicate_opening,
            opened_at: duplicate_opened_at,
            retirement: client.retirement,
        };

        let error = match DriverProcessProof::new(client, peers) {
            Ok(_) => panic!("one process identity must not fill two driver roles"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::IdentityReused {
                first: DriverProcessRole::Client,
                second: DriverProcessRole::PeerServer { slot: 0 }
            }
        ));
    }

    #[test]
    fn reused_handle_opening_cannot_enter_driver_process_proof() {
        assert_eq!(CANARY_PEER_SERVER_SLOTS, 3);
        let (client, mut peers) = reaped_processes();
        peers[1].opening_id = client.opening_id;

        let error = match DriverProcessProof::new(client, peers) {
            Ok(_) => panic!("reused opening identity must not produce driver process proof"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            super::DriverProcessAuthorityError::HandleReused {
                first: DriverProcessRole::Client,
                second: DriverProcessRole::PeerServer { slot: 1 }
            }
        ));
    }

    #[test]
    fn pending_receipt_authority_consumes_real_engine_and_reaped_driver_handles() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let evidence = fixture.successful_evidence();
        let (client, peers) = reaped_processes();
        let verified = DriverProcessProof::new(client, peers)
            .expect("bind exact driver roles")
            .verify_post_reap_exit(fixture.request().deadline().expires_at())
            .expect("verify every retained pidfd after parent reap");
        let final_driver_observation_at = verified.latest_observed_at();

        let engine = super::ChildReapGuard(Some(
            Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("spawn engine authority fixture"),
        ));
        let handle = ProcessHandle::open_child(
            engine
                .0
                .as_ref()
                .expect("engine child guard remains populated"),
        )
        .expect("open exact engine fixture handle");
        let engine_authority = EngineChildAuthority::from_process_handle_for_test(
            handle,
            NonZeroU64::new(1).expect("engine revision"),
        )
        .expect("bind engine fixture authority");
        let engine_observations = engine_authority
            .observe_after_until(fixture.request().deadline().expires_at())
            .expect("observe exact engine fixture twice through one pidfd");
        let final_engine_observation_at = engine_observations.after().observed_at();

        let authority = TproxyLocalOutputProcessOwnershipAuthority::from_verified(
            fixture.request(),
            engine_observations,
            verified,
        )
        .expect("consume all child-origin authority into one pending receipt");
        assert_eq!(
            authority.final_verifier_observed_at(),
            std::cmp::max(final_engine_observation_at, final_driver_observation_at)
        );
        let completed_at = std::cmp::max(
            evidence.completed_at,
            authority.final_verifier_observed_at(),
        );
        let error = TproxyLocalOutputProcessOwnershipReceipt::mint(
            authority,
            fixture.request(),
            &evidence.flows,
            &evidence.cleanup,
            completed_at,
        )
        .expect_err("copied fixture identities cannot replace the consumed real handles");

        assert_eq!(
            error,
            TproxyLocalOutputProcessOwnershipReceiptError::EngineIdentityMismatch
        );
    }
}
