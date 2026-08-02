//! Test-only authoritative listener observation for the local-OUTPUT canary.
//!
//! The packaged adapter remains uninhabited. This module exercises the exact
//! request/session/snapshot seam that a future device-qualified driver must
//! use, without exposing a production constructor for positive evidence.

use std::net::SocketAddr;
use std::num::NonZeroU64;

use flux_platform::socket_diagnostics::{
    CorrelatedProcessSocket, InetSocketAddressFamily, InetSocketProtocol, ProcessSocketDiagnostics,
};

use super::super::{
    CANARY_LISTENER_ROLE_SLOTS, CanaryAttemptRequest, CanaryAttemptSocketObserverSession,
    CanaryCleanupStatus, CanaryErrorKind, CanaryFlowAddressFamily, CanaryFlowProtocol,
    CanaryInetDiagCookie, CanaryInetDiagListenerSnapshot, CanaryListenerObservationLoss,
    CanaryListenerRole, CanaryListenerSocketObservation, CanaryProcFd,
    CanarySocketObserverAuthority, CanaryTproxyListenerSocketIdentity, FunctionalCanaryError,
};

/// Fixed listener role order: IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP.
pub(super) type ListenerObservationSlots =
    [Option<CanaryTproxyListenerSocketIdentity>; CANARY_LISTENER_ROLE_SLOTS];

const ROLES: [CanaryListenerRole; CANARY_LISTENER_ROLE_SLOTS] = CanaryListenerRole::ALL;

/// Collect and map all required transparent listener roles from one exact
/// prebound observer session. The session is returned so later phases cannot
/// silently replace the collector with a newly opened socket.
pub(super) fn collect(
    request: &CanaryAttemptRequest,
    observer: CanaryAttemptSocketObserverSession,
) -> Result<(CanaryAttemptSocketObserverSession, ListenerObservationSlots), FunctionalCanaryError> {
    if observer.binding()
        != request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer_binding()
    {
        return Err(invalid(
            "listener observer session does not match the immutable request authority",
        ));
    }
    if observer.deadline() != request.deadline() {
        return Err(invalid(
            "listener observer session deadline does not match the immutable request deadline",
        ));
    }

    let (observer, snapshot) = observer.collect_process_and_listeners_until(
        request.pre_binding().engine().engine(),
        request.pre_binding().engine().listener().port(),
    )?;
    let snapshot_authority = validate_snapshot_authority(request, &observer, &snapshot)?;

    let mut correlations = [None; CANARY_LISTENER_ROLE_SLOTS];
    for role in ROLES {
        if !role_is_required(request, role) {
            continue;
        }
        let family = inet_address_family(role);
        let protocol = inet_protocol(role);
        let correlated = snapshot
            .correlate_transparent_listener(
                family,
                protocol,
                request.pre_binding().engine().listener().port(),
            )
            .map_err(|error| {
                let diagnostic = format!(
                    "listener role {family:?}/{protocol:?} failed exact correlation: {error}"
                );
                invalid(&diagnostic)
            })?;
        correlations[role.index()] = Some(ListenerRoleCorrelation::from_correlated(correlated)?);
    }
    let slots = assemble_listener_slots(
        request,
        observer.authority(),
        snapshot_authority,
        correlations,
    )?;
    Ok((observer, slots))
}

fn assemble_listener_slots(
    request: &CanaryAttemptRequest,
    observer: CanarySocketObserverAuthority,
    snapshot: CanaryInetDiagListenerSnapshot,
    correlations: [Option<ListenerRoleCorrelation>; CANARY_LISTENER_ROLE_SLOTS],
) -> Result<ListenerObservationSlots, FunctionalCanaryError> {
    let mut slots: ListenerObservationSlots = std::array::from_fn(|_| None);
    let mut listener_identities = [None; CANARY_LISTENER_ROLE_SLOTS];
    for role in ROLES {
        let index = role.index();
        if !role_is_required(request, role) {
            if correlations[index].is_some() {
                return Err(invalid(
                    "listener correlations contain a role disabled by the immutable request",
                ));
            }
            continue;
        }
        let correlated = correlations[index]
            .ok_or_else(|| invalid("listener correlations omitted a required role"))?;
        if correlated.sequence != snapshot.role_sequence_for(role) {
            return Err(invalid(
                "listener role does not match its exact snapshot dump sequence",
            ));
        }
        record_distinct_listener_identity(&mut listener_identities, index, correlated.identity())?;
        let observation = CanaryListenerSocketObservation::from_complete_inet_diag_snapshot(
            observer,
            correlated.sequence,
            snapshot,
        );
        slots[index] = Some(CanaryTproxyListenerSocketIdentity::new(
            request.pre_binding().engine().generation(),
            request.pre_binding().engine().engine(),
            request.pre_binding().engine().listener().clone(),
            request
                .pre_binding()
                .environment()
                .authority()
                .network()
                .daemon_network_namespace(),
            request
                .pre_binding()
                .environment()
                .authority()
                .capture_program_digest(),
            request
                .pre_binding()
                .environment()
                .attempt_objects()
                .selector(),
            role.protocol(),
            role.address_family(),
            correlated.process_fd,
            correlated.inode,
            correlated.cookie,
            correlated.bind,
            correlated.transparent,
            correlated.ipv6_only,
            observation,
        ));
    }
    Ok(slots)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerRoleCorrelation {
    process_fd: CanaryProcFd,
    inode: NonZeroU64,
    cookie: CanaryInetDiagCookie,
    bind: SocketAddr,
    transparent: bool,
    ipv6_only: Option<bool>,
    sequence: NonZeroU64,
}

impl ListenerRoleCorrelation {
    fn from_correlated(correlated: CorrelatedProcessSocket) -> Result<Self, FunctionalCanaryError> {
        let diagnostic = correlated.diagnostic();
        let process_fd = CanaryProcFd::new(correlated.process_fd().fd())
            .ok_or_else(|| invalid("listener correlation returned an invalid process FD"))?;
        let inode = NonZeroU64::new(diagnostic.inode())
            .ok_or_else(|| invalid("listener correlation returned a zero inode"))?;
        let cookie_words = diagnostic.cookie().words();
        let cookie = CanaryInetDiagCookie::new(cookie_words[0], cookie_words[1])
            .ok_or_else(|| invalid("listener correlation returned an invalid cookie"))?;
        let transparent = diagnostic
            .transparent()
            .ok_or_else(|| invalid("listener correlation omitted transparency"))?;
        if !transparent {
            return Err(invalid(
                "listener correlation returned a non-transparent socket",
            ));
        }
        let sequence = snapshot_sequence(diagnostic.dump_sequence().get());
        Ok(Self {
            process_fd,
            inode,
            cookie,
            bind: diagnostic.local_address(),
            transparent,
            ipv6_only: diagnostic.ipv6_only(),
            sequence,
        })
    }

    const fn identity(self) -> ListenerSocketIdentityKey {
        ListenerSocketIdentityKey {
            process_fd: self.process_fd,
            inode: self.inode,
            cookie: self.cookie,
        }
    }
}

fn role_is_required(request: &CanaryAttemptRequest, role: CanaryListenerRole) -> bool {
    role.address_family() == CanaryFlowAddressFamily::Ipv4
        || request.families() == super::super::CanaryAddressFamilies::Ipv4AndIpv6
}

const fn inet_address_family(role: CanaryListenerRole) -> InetSocketAddressFamily {
    match role.address_family() {
        CanaryFlowAddressFamily::Ipv4 => InetSocketAddressFamily::Ipv4,
        CanaryFlowAddressFamily::Ipv6 => InetSocketAddressFamily::Ipv6,
    }
}

const fn inet_protocol(role: CanaryListenerRole) -> InetSocketProtocol {
    match role.protocol() {
        CanaryFlowProtocol::Tcp => InetSocketProtocol::Tcp,
        CanaryFlowProtocol::Udp => InetSocketProtocol::Udp,
    }
}

fn validate_snapshot_authority(
    request: &CanaryAttemptRequest,
    observer: &CanaryAttemptSocketObserverSession,
    snapshot: &ProcessSocketDiagnostics,
) -> Result<CanaryInetDiagListenerSnapshot, FunctionalCanaryError> {
    let expected_process = request.pre_binding().engine().engine();
    if snapshot.process().pid().get() != expected_process.pid()
        || snapshot.process().start_time_ticks().get() != expected_process.start_time_ticks()
    {
        return Err(invalid(
            "listener snapshot process identity does not match the immutable engine identity",
        ));
    }
    let expected_port = match observer.authority() {
        super::super::CanarySocketObserverAuthority::ProcFdInetDiag {
            netlink_port_id, ..
        } => netlink_port_id,
        super::super::CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
            return Err(invalid(
                "listener observer requires the prebound INET_DIAG authority",
            ));
        }
    };
    if snapshot.netlink_port_id() != expected_port
        || snapshot.listener_dumps().len() != 2
        || snapshot.dumps().len() != 4
        || snapshot.listener_port() != Some(request.pre_binding().engine().listener().port())
        || !snapshot.diag_dumps_complete()
        || !snapshot.listener_diag_dumps_complete()
        || snapshot.started_at() < request.deadline().started_at()
        || snapshot.completed_at() >= request.deadline().expires_at()
    {
        return Err(invalid(
            "listener snapshot is incomplete, replaced, or outside the immutable deadline",
        ));
    }
    let mut sequences = snapshot
        .dumps()
        .iter()
        .chain(snapshot.listener_dumps())
        .map(|dump| u64::from(dump.sequence().get()));
    let first = sequences
        .next()
        .and_then(NonZeroU64::new)
        .ok_or_else(|| invalid("listener snapshot omitted its first diagnostic sequence"))?;
    let mut last = first;
    for sequence in sequences {
        if last.get().checked_add(1) != Some(sequence) {
            return Err(invalid(
                "listener snapshot diagnostic sequences are not one exact contiguous transaction",
            ));
        }
        last = NonZeroU64::new(sequence)
            .ok_or_else(|| invalid("listener snapshot contains a zero diagnostic sequence"))?;
    }
    let mut role_sequences = [first; CANARY_LISTENER_ROLE_SLOTS];
    for role in ROLES {
        let sequence = snapshot
            .listener_role_sequence(inet_address_family(role), inet_protocol(role))
            .ok_or_else(|| invalid("listener snapshot omitted exact role provenance"))?;
        role_sequences[role.index()] = snapshot_sequence(sequence.get());
    }
    Ok(CanaryInetDiagListenerSnapshot::new(
        observer.binding(),
        expected_process,
        request.pre_binding().engine().listener().port(),
        snapshot.started_at(),
        snapshot.completed_at(),
        first,
        last,
        role_sequences,
    ))
}

fn snapshot_sequence(sequence: u32) -> NonZeroU64 {
    NonZeroU64::new(u64::from(sequence)).expect("validated diagnostic sequence is nonzero")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ListenerSocketIdentityKey {
    process_fd: CanaryProcFd,
    inode: NonZeroU64,
    cookie: CanaryInetDiagCookie,
}

fn record_distinct_listener_identity(
    identities: &mut [Option<ListenerSocketIdentityKey>; ROLES.len()],
    index: usize,
    candidate: ListenerSocketIdentityKey,
) -> Result<(), FunctionalCanaryError> {
    if identities[..index].iter().flatten().any(|existing| {
        existing.process_fd == candidate.process_fd
            || existing.inode == candidate.inode
            || existing.cookie == candidate.cookie
    }) {
        return Err(invalid(
            "listener roles reused a process FD, socket inode, or INET_DIAG cookie",
        ));
    }
    identities[index] = Some(candidate);
    Ok(())
}

fn invalid(diagnostic: &str) -> FunctionalCanaryError {
    FunctionalCanaryError::new(
        CanaryErrorKind::InvalidEvidence,
        CanaryCleanupStatus::Uncertain,
        diagnostic,
    )
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::net::{Ipv4Addr, TcpListener, UdpSocket};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::num::{NonZeroU16, NonZeroU64};
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::os::fd::AsRawFd;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::os::unix::process::CommandExt;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    use std::process::{Child, Command};
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    use flux_platform::ProcessHandle;

    use super::super::super::CanaryAddressFamilies;
    use super::super::super::tests::Fixture;
    use super::*;

    #[test]
    fn scripted_session_cannot_mint_listener_observations() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let request = fixture.request();
        let observer = CanaryAttemptSocketObserverSession::scripted(
            request
                .pre_binding()
                .environment()
                .authority()
                .socket_observer_binding(),
            request.deadline(),
        );

        let error = match collect(request, observer) {
            Ok(_) => panic!("scripted transport is not authoritative"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), CanaryErrorKind::InvalidEvidence);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::NotRequired);
    }

    #[test]
    fn listener_roles_reject_fd_inode_or_cookie_reuse() {
        let first = ListenerSocketIdentityKey {
            process_fd: CanaryProcFd::new(10).unwrap(),
            inode: NonZeroU64::new(100).unwrap(),
            cookie: CanaryInetDiagCookie::new(1, 10).unwrap(),
        };
        let mut identities = [None; ROLES.len()];
        record_distinct_listener_identity(&mut identities, 0, first).unwrap();

        for duplicate in [
            ListenerSocketIdentityKey {
                process_fd: first.process_fd,
                inode: NonZeroU64::new(101).unwrap(),
                cookie: CanaryInetDiagCookie::new(2, 10).unwrap(),
            },
            ListenerSocketIdentityKey {
                process_fd: CanaryProcFd::new(11).unwrap(),
                inode: first.inode,
                cookie: CanaryInetDiagCookie::new(2, 10).unwrap(),
            },
            ListenerSocketIdentityKey {
                process_fd: CanaryProcFd::new(11).unwrap(),
                inode: NonZeroU64::new(101).unwrap(),
                cookie: first.cookie,
            },
        ] {
            let error = record_distinct_listener_identity(&mut identities, 1, duplicate)
                .expect_err("cross-role identity reuse cannot pass");
            assert_eq!(error.kind(), CanaryErrorKind::InvalidEvidence);
            assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
        }
    }

    #[test]
    fn complete_dual_stack_snapshot_assembles_all_listener_roles() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4AndIpv6);
        let request = fixture.request();
        let observer = request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer_binding();
        let role_sequences = [1, 5, 3, 6]
            .map(|sequence| NonZeroU64::new(sequence).expect("listener role dump sequence"));
        let snapshot = CanaryInetDiagListenerSnapshot::new(
            observer,
            request.pre_binding().engine().engine(),
            request.pre_binding().engine().listener().port(),
            request.deadline().started_at(),
            request.deadline().started_at() + Duration::from_millis(1),
            NonZeroU64::new(1).expect("first listener dump sequence"),
            NonZeroU64::new(6).expect("last listener dump sequence"),
            role_sequences,
        );
        let port = request.pre_binding().engine().listener().port().get();
        let correlations = CanaryListenerRole::ALL.map(|role| {
            let index = role.index();
            let bind = match role.address_family() {
                CanaryFlowAddressFamily::Ipv4 => {
                    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port)
                }
                CanaryFlowAddressFamily::Ipv6 => {
                    SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), port)
                }
            };
            Some(ListenerRoleCorrelation {
                process_fd: CanaryProcFd::new(10 + u32::try_from(index).unwrap()).unwrap(),
                inode: NonZeroU64::new(100 + u64::try_from(index).unwrap()).unwrap(),
                cookie: CanaryInetDiagCookie::new(1 + u32::try_from(index).unwrap(), 10).unwrap(),
                bind,
                transparent: true,
                ipv6_only: (role.address_family() == CanaryFlowAddressFamily::Ipv6).then_some(true),
                sequence: snapshot.role_sequence_for(role),
            })
        });

        let slots = assemble_listener_slots(request, observer.authority(), snapshot, correlations)
            .expect("one complete dual-stack snapshot maps every listener role");
        for role in CanaryListenerRole::ALL {
            let listener = slots[role.index()]
                .as_ref()
                .expect("required listener role");
            let correlated = correlations[role.index()].expect("required correlation");
            assert_eq!(listener.protocol, role.protocol());
            assert_eq!(listener.address_family, role.address_family());
            assert_eq!(listener.listener_fd, correlated.process_fd);
            assert_eq!(listener.listener_inode, correlated.inode);
            assert_eq!(listener.listener_cookie, correlated.cookie);
            assert_eq!(listener.bind, correlated.bind);
            assert_eq!(listener.ipv6_only, correlated.ipv6_only);
            assert_eq!(
                listener.observation.sequence,
                snapshot.role_sequence_for(role)
            );
            assert_eq!(
                listener.observation.loss,
                CanaryListenerObservationLoss::CompleteInetDiagSnapshot(snapshot)
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn real_prebound_collection_rejects_a_nontransparent_listener_without_positive_fabrication() {
        let fixture = Fixture::new(CanaryAddressFamilies::Ipv4Only);
        let mut request = fixture.request().clone();
        let tcp_listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = NonZeroU16::new(tcp_listener.local_addr().unwrap().port()).unwrap();
        let udp_listener = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port.get())).unwrap();
        let listener_owner = ListenerOwnerChild::spawn(&tcp_listener, &udp_listener);
        let process_handle = ProcessHandle::open_child(listener_owner.child())
            .expect("open listener-owner process handle");
        let identity = process_handle.identity();
        drop((tcp_listener, udp_listener));
        let process = crate::engine_supervisor::OwnedEngineIdentity::new(
            identity.pid(),
            identity.start_time_ticks(),
        );
        request.pre_binding.engine.engine = process;
        request.pre_binding.engine.listener.port = port;

        let (collector_identity, collector_revision) = match request
            .pre_binding()
            .environment()
            .authority()
            .socket_observer()
        {
            super::super::super::CanarySocketObserverAuthority::ProcFdInetDiag {
                collector_identity,
                collector_revision,
                ..
            } => (collector_identity, collector_revision),
            super::super::super::CanarySocketObserverAuthority::QualifiedCgroupBpf { .. } => {
                panic!("fixture uses the INET_DIAG observer")
            }
        };
        let observer = CanaryAttemptSocketObserverSession::open_proc_fd_inet_diag(
            collector_identity,
            collector_revision,
            request.deadline(),
        )
        .unwrap();
        let binding = observer.binding();
        request.pre_binding.environment.authority.socket_observer = observer.authority();
        request
            .pre_binding
            .environment
            .authority
            .socket_observer_opening = binding.opening_id;

        let error = match collect(&request, observer) {
            Ok(_) => panic!("a nontransparent listener cannot mint positive identity"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), CanaryErrorKind::InvalidEvidence);
        assert_eq!(error.cleanup(), CanaryCleanupStatus::Uncertain);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    struct ListenerOwnerChild(Option<Child>);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    impl ListenerOwnerChild {
        fn spawn(tcp_listener: &TcpListener, udp_listener: &UdpSocket) -> Self {
            let descriptors = [tcp_listener.as_raw_fd(), udp_listener.as_raw_fd()];
            let flags = descriptors.map(|descriptor| {
                // SAFETY: each descriptor is borrowed from a live socket for this call.
                let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
                assert!(flags >= 0, "read listener descriptor flags");
                flags
            });
            let mut command = Command::new("sleep");
            command.arg("30");
            // SAFETY: the closure calls only async-signal-safe `fcntl` with borrowed descriptors
            // that remain live through spawn. It clears close-on-exec only in the child process.
            unsafe {
                command.pre_exec(move || {
                    for (descriptor, flags) in descriptors.into_iter().zip(flags) {
                        if libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
            Self(Some(command.spawn().expect("spawn listener-owner child")))
        }

        fn child(&self) -> &Child {
            self.0.as_ref().expect("listener-owner child is retained")
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    impl Drop for ListenerOwnerChild {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}
