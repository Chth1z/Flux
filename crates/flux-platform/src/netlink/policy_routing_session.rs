use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::time::{Duration, Instant};

use super::policy_routing::{
    MAX_POLICY_ROUTING_ACK_BYTES, MAX_POLICY_ROUTING_READBACK_BYTES,
    MAX_POLICY_ROUTING_READBACK_MESSAGES, ManagedPolicyRoutingIdentity,
    ManagedPolicyRoutingObservation, PolicyRoutingAck, PolicyRoutingAckDecodeErrorKind,
    PolicyRoutingAckSender, PolicyRoutingAckStatus, PolicyRoutingEncodeError,
    PolicyRoutingMutation, PolicyRoutingMutationKind, PolicyRoutingReadbackErrorKind,
    decode_policy_routing_ack, encode_policy_routing_mutation, observe_managed_policy_routing,
};
use super::socket::{NetlinkSequenceAllocator, RouteDumpRequest, RuleDumpRequest};
use super::{NLMSG_DONE, NLMSG_ERROR, NLMSG_OVERRUN, NetlinkMessageIter};

const DEFAULT_POLICY_ROUTING_IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_POLICY_ROUTING_IO_TIMEOUT: Duration = Duration::from_secs(30);
const POLICY_ROUTING_DATAGRAM_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingSessionEvidence {
    local_port_id: NonZeroU32,
    groups: u32,
    extended_ack: bool,
    capped_ack: bool,
}

impl PolicyRoutingSessionEvidence {
    #[must_use]
    pub(crate) const fn local_port_id(self) -> NonZeroU32 {
        self.local_port_id
    }

    #[must_use]
    pub(crate) const fn groups(self) -> u32 {
        self.groups
    }

    #[must_use]
    pub(crate) const fn extended_ack(self) -> bool {
        self.extended_ack
    }

    #[must_use]
    pub(crate) const fn capped_ack(self) -> bool {
        self.capped_ack
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingSessionFailureKind {
    UnsupportedPlatform,
    InvalidTimeout,
    TimedOut,
    SystemCall { raw_os_error: Option<i32> },
    ShortWrite { expected: usize, actual: usize },
    DatagramTooLarge { limit: usize, actual: usize },
    UnexpectedSender,
    InvalidFrame,
    UnexpectedSequence { expected: u32, actual: u32 },
    UnexpectedPortId { expected: u32, actual: u32 },
    UnexpectedControlMessage { message_type: u16 },
    MessageAfterCompletion,
    DumpBytesExceeded,
    TooManyMessages,
    Encode(PolicyRoutingEncodeError),
    AckDecode(PolicyRoutingAckDecodeErrorKind),
    Readback(PolicyRoutingReadbackErrorKind),
    FreshSessionRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingSessionFailure {
    operation: &'static str,
    kind: PolicyRoutingSessionFailureKind,
    offset: usize,
}

impl PolicyRoutingSessionFailure {
    const fn new(
        operation: &'static str,
        kind: PolicyRoutingSessionFailureKind,
        offset: usize,
    ) -> Self {
        Self {
            operation,
            kind,
            offset,
        }
    }

    #[must_use]
    pub(crate) const fn operation(self) -> &'static str {
        self.operation
    }

    #[must_use]
    pub(crate) const fn kind(self) -> PolicyRoutingSessionFailureKind {
        self.kind
    }

    #[must_use]
    pub(crate) const fn offset(self) -> usize {
        self.offset
    }
}

impl fmt::Display for PolicyRoutingSessionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "policy-routing session {} failed at byte {}: {:?}",
            self.operation, self.offset, self.kind
        )
    }
}

impl Error for PolicyRoutingSessionFailure {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRoutingStepOutcome {
    Accepted(PolicyRoutingAck),
    Rejected(PolicyRoutingAck),
    NotSent(PolicyRoutingSessionFailure),
    MayHaveMutated(PolicyRoutingSessionFailure),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingStepReceipt {
    mutation: PolicyRoutingMutationKind,
    outcome: PolicyRoutingStepOutcome,
}

impl PolicyRoutingStepReceipt {
    #[must_use]
    pub(crate) const fn mutation(&self) -> PolicyRoutingMutationKind {
        self.mutation
    }

    #[must_use]
    pub(crate) const fn outcome(&self) -> &PolicyRoutingStepOutcome {
        &self.outcome
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyRoutingTransactionReceipt {
    steps: Box<[PolicyRoutingStepReceipt]>,
}

impl PolicyRoutingTransactionReceipt {
    #[must_use]
    pub(crate) const fn steps(&self) -> &[PolicyRoutingStepReceipt] {
        &self.steps
    }

    #[must_use]
    pub(crate) fn is_complete(&self) -> bool {
        self.steps.len() == 2
            && self
                .steps
                .iter()
                .all(|step| matches!(step.outcome, PolicyRoutingStepOutcome::Accepted(_)))
    }

    #[must_use]
    pub(crate) fn may_have_mutated(&self) -> bool {
        self.steps.iter().any(|step| {
            matches!(
                step.outcome,
                PolicyRoutingStepOutcome::Accepted(_) | PolicyRoutingStepOutcome::MayHaveMutated(_)
            )
        })
    }
}

#[derive(Clone, Debug)]
struct ReceivedPolicyRoutingDatagram {
    bytes: Box<[u8]>,
    sender: PolicyRoutingAckSender,
}

trait PolicyRoutingTransport {
    fn evidence(&self) -> PolicyRoutingSessionEvidence;

    fn send_datagram(
        &mut self,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PolicyRoutingSessionFailure>;

    fn receive_datagram(
        &mut self,
        maximum_bytes: usize,
        deadline: Instant,
    ) -> Result<ReceivedPolicyRoutingDatagram, PolicyRoutingSessionFailure>;
}

pub(crate) struct PolicyRoutingSession {
    transport: Box<dyn PolicyRoutingTransport>,
    sequences: NetlinkSequenceAllocator,
    io_timeout: Duration,
    requires_fresh_session: bool,
}

impl PolicyRoutingSession {
    pub(crate) fn open() -> Result<Self, PolicyRoutingSessionFailure> {
        Self::open_with_timeout(DEFAULT_POLICY_ROUTING_IO_TIMEOUT)
    }

    pub(crate) fn open_with_timeout(
        io_timeout: Duration,
    ) -> Result<Self, PolicyRoutingSessionFailure> {
        if io_timeout.is_zero() || io_timeout > MAX_POLICY_ROUTING_IO_TIMEOUT {
            return Err(PolicyRoutingSessionFailure::new(
                "open",
                PolicyRoutingSessionFailureKind::InvalidTimeout,
                0,
            ));
        }
        Ok(Self {
            transport: open_live_transport()?,
            sequences: NetlinkSequenceAllocator::default(),
            io_timeout,
            requires_fresh_session: false,
        })
    }

    #[cfg(test)]
    fn from_transport(
        transport: impl PolicyRoutingTransport + 'static,
        io_timeout: Duration,
    ) -> Self {
        assert!(!io_timeout.is_zero());
        Self {
            transport: Box::new(transport),
            sequences: NetlinkSequenceAllocator::default(),
            io_timeout,
            requires_fresh_session: false,
        }
    }

    #[must_use]
    pub(crate) fn evidence(&self) -> PolicyRoutingSessionEvidence {
        self.transport.evidence()
    }

    pub(crate) fn apply(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<PolicyRoutingTransactionReceipt, PolicyRoutingSessionFailure> {
        self.execute_transaction([
            PolicyRoutingMutation::AddRoute(identity.route()),
            PolicyRoutingMutation::AddRule(identity.rule()),
        ])
    }

    pub(crate) fn delete(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<PolicyRoutingTransactionReceipt, PolicyRoutingSessionFailure> {
        self.execute_transaction([
            PolicyRoutingMutation::DeleteRule(identity.rule()),
            PolicyRoutingMutation::DeleteRoute(identity.route()),
        ])
    }

    /// Executes exactly one owner-journaled mutation boundary.
    ///
    /// The native owner uses this instead of `apply`/`delete` so it can durably publish the next
    /// route or rule operation before each individual netlink request.
    pub(crate) fn mutate_one(
        &mut self,
        mutation: PolicyRoutingMutation,
    ) -> Result<PolicyRoutingStepReceipt, PolicyRoutingSessionFailure> {
        self.require_usable("mutate one")?;
        Ok(PolicyRoutingStepReceipt {
            mutation: mutation.kind(),
            outcome: self.execute_mutation(mutation),
        })
    }

    pub(crate) fn observe(
        &mut self,
        identity: ManagedPolicyRoutingIdentity,
    ) -> Result<ManagedPolicyRoutingObservation, PolicyRoutingSessionFailure> {
        self.require_usable("observe")?;
        let mut remaining_bytes = MAX_POLICY_ROUTING_READBACK_BYTES;
        let mut remaining_messages = MAX_POLICY_ROUTING_READBACK_MESSAGES;

        let route_sequence = self.sequences.allocate();
        let route_request = RouteDumpRequest::all(route_sequence);
        let route_dump = self.exchange_dump(
            route_request.as_bytes(),
            route_sequence,
            "route dump",
            &mut remaining_bytes,
            &mut remaining_messages,
        )?;

        let rule_sequence = self.sequences.allocate();
        let rule_request = RuleDumpRequest::all(rule_sequence);
        let rule_dump = self.exchange_dump(
            rule_request.as_bytes(),
            rule_sequence,
            "rule dump",
            &mut remaining_bytes,
            &mut remaining_messages,
        )?;

        observe_managed_policy_routing(
            identity,
            &route_dump,
            route_sequence,
            &rule_dump,
            rule_sequence,
        )
        .map_err(|error| {
            PolicyRoutingSessionFailure::new(
                "readback",
                PolicyRoutingSessionFailureKind::Readback(error.kind()),
                error.offset(),
            )
        })
    }

    fn execute_transaction(
        &mut self,
        mutations: [PolicyRoutingMutation; 2],
    ) -> Result<PolicyRoutingTransactionReceipt, PolicyRoutingSessionFailure> {
        self.require_usable("mutate")?;
        let mut steps = Vec::with_capacity(mutations.len());
        for mutation in mutations {
            let mutation_kind = mutation.kind();
            let outcome = self.execute_mutation(mutation);
            let should_continue = matches!(outcome, PolicyRoutingStepOutcome::Accepted(_));
            steps.push(PolicyRoutingStepReceipt {
                mutation: mutation_kind,
                outcome,
            });
            if !should_continue {
                break;
            }
        }
        Ok(PolicyRoutingTransactionReceipt {
            steps: steps.into_boxed_slice(),
        })
    }

    fn execute_mutation(&mut self, mutation: PolicyRoutingMutation) -> PolicyRoutingStepOutcome {
        let sequence = self.sequences.allocate();
        let request = match encode_policy_routing_mutation(mutation, sequence) {
            Ok(request) => request,
            Err(error) => {
                return PolicyRoutingStepOutcome::NotSent(PolicyRoutingSessionFailure::new(
                    "encode mutation",
                    PolicyRoutingSessionFailureKind::Encode(error),
                    0,
                ));
            }
        };
        let deadline = self.deadline();
        if let Err(error) = self.transport.send_datagram(request.bytes(), deadline) {
            return PolicyRoutingStepOutcome::NotSent(error);
        }

        let datagram = match self
            .transport
            .receive_datagram(MAX_POLICY_ROUTING_ACK_BYTES, deadline)
        {
            Ok(datagram) => datagram,
            Err(error) => return self.uncertain(error),
        };
        match decode_policy_routing_ack(
            &datagram.bytes,
            datagram.sender,
            self.evidence().local_port_id(),
            &request,
        ) {
            Ok(ack) => match ack.status() {
                PolicyRoutingAckStatus::Accepted => PolicyRoutingStepOutcome::Accepted(ack),
                PolicyRoutingAckStatus::Rejected { .. } => PolicyRoutingStepOutcome::Rejected(ack),
            },
            Err(error) => self.uncertain(PolicyRoutingSessionFailure::new(
                "decode mutation ACK",
                PolicyRoutingSessionFailureKind::AckDecode(error.kind()),
                error.offset(),
            )),
        }
    }

    fn exchange_dump(
        &mut self,
        request: &[u8],
        sequence: NonZeroU32,
        operation: &'static str,
        remaining_bytes: &mut usize,
        remaining_messages: &mut usize,
    ) -> Result<Box<[u8]>, PolicyRoutingSessionFailure> {
        let deadline = self.deadline();
        self.transport.send_datagram(request, deadline)?;
        match self.collect_dump(
            sequence,
            operation,
            deadline,
            remaining_bytes,
            remaining_messages,
        ) {
            Ok(dump) => Ok(dump),
            Err(error) => {
                // A timed-out or malformed dump can leave late fragments queued.
                // Reopening is cheaper and safer than trying to drain an unknown stream.
                self.requires_fresh_session = true;
                Err(error)
            }
        }
    }

    fn collect_dump(
        &mut self,
        sequence: NonZeroU32,
        operation: &'static str,
        deadline: Instant,
        remaining_bytes: &mut usize,
        remaining_messages: &mut usize,
    ) -> Result<Box<[u8]>, PolicyRoutingSessionFailure> {
        let mut dump = Vec::new();
        loop {
            let datagram = self
                .transport
                .receive_datagram(POLICY_ROUTING_DATAGRAM_BYTES, deadline)?;
            if !datagram.sender.is_kernel_unicast() {
                return Err(PolicyRoutingSessionFailure::new(
                    operation,
                    PolicyRoutingSessionFailureKind::UnexpectedSender,
                    dump.len(),
                ));
            }
            if datagram.bytes.len() > *remaining_bytes {
                return Err(PolicyRoutingSessionFailure::new(
                    operation,
                    PolicyRoutingSessionFailureKind::DumpBytesExceeded,
                    dump.len(),
                ));
            }

            let mut datagram_messages = 0_usize;
            let mut completion = false;
            for message in NetlinkMessageIter::new(&datagram.bytes) {
                let message = message.map_err(|error| {
                    PolicyRoutingSessionFailure::new(
                        operation,
                        PolicyRoutingSessionFailureKind::InvalidFrame,
                        dump.len() + error.offset(),
                    )
                })?;
                if completion {
                    return Err(PolicyRoutingSessionFailure::new(
                        operation,
                        PolicyRoutingSessionFailureKind::MessageAfterCompletion,
                        dump.len() + message.offset(),
                    ));
                }
                datagram_messages = datagram_messages.saturating_add(1);
                if datagram_messages > *remaining_messages {
                    return Err(PolicyRoutingSessionFailure::new(
                        operation,
                        PolicyRoutingSessionFailureKind::TooManyMessages,
                        dump.len() + message.offset(),
                    ));
                }
                let header = message.header();
                if header.sequence() != sequence.get() {
                    return Err(PolicyRoutingSessionFailure::new(
                        operation,
                        PolicyRoutingSessionFailureKind::UnexpectedSequence {
                            expected: sequence.get(),
                            actual: header.sequence(),
                        },
                        dump.len() + message.offset() + 8,
                    ));
                }
                let expected_port = self.evidence().local_port_id().get();
                if header.port_id() != expected_port {
                    return Err(PolicyRoutingSessionFailure::new(
                        operation,
                        PolicyRoutingSessionFailureKind::UnexpectedPortId {
                            expected: expected_port,
                            actual: header.port_id(),
                        },
                        dump.len() + message.offset() + 12,
                    ));
                }
                match header.message_type() {
                    NLMSG_DONE => completion = true,
                    NLMSG_ERROR | NLMSG_OVERRUN => {
                        return Err(PolicyRoutingSessionFailure::new(
                            operation,
                            PolicyRoutingSessionFailureKind::UnexpectedControlMessage {
                                message_type: header.message_type(),
                            },
                            dump.len() + message.offset(),
                        ));
                    }
                    _ => {}
                }
            }
            if datagram_messages == 0 {
                return Err(PolicyRoutingSessionFailure::new(
                    operation,
                    PolicyRoutingSessionFailureKind::InvalidFrame,
                    dump.len(),
                ));
            }
            *remaining_bytes -= datagram.bytes.len();
            *remaining_messages -= datagram_messages;
            dump.extend_from_slice(&datagram.bytes);
            if completion {
                return Ok(dump.into_boxed_slice());
            }
        }
    }

    fn uncertain(&mut self, error: PolicyRoutingSessionFailure) -> PolicyRoutingStepOutcome {
        self.requires_fresh_session = true;
        PolicyRoutingStepOutcome::MayHaveMutated(error)
    }

    fn require_usable(&self, operation: &'static str) -> Result<(), PolicyRoutingSessionFailure> {
        if self.requires_fresh_session {
            Err(PolicyRoutingSessionFailure::new(
                operation,
                PolicyRoutingSessionFailureKind::FreshSessionRequired,
                0,
            ))
        } else {
            Ok(())
        }
    }

    fn deadline(&self) -> Instant {
        Instant::now()
            .checked_add(self.io_timeout)
            .expect("bounded policy-routing timeout fits Instant")
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_live_transport() -> Result<Box<dyn PolicyRoutingTransport>, PolicyRoutingSessionFailure> {
    Ok(Box::new(live::LivePolicyRoutingTransport::open()?))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_live_transport() -> Result<Box<dyn PolicyRoutingTransport>, PolicyRoutingSessionFailure> {
    Err(PolicyRoutingSessionFailure::new(
        "open",
        PolicyRoutingSessionFailureKind::UnsupportedPlatform,
        0,
    ))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod live {
    use std::mem;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    const AF_NETLINK: u16 = 16;
    const SOCKADDR_NL_LENGTH: libc::socklen_t = 12;
    const NETLINK_CAP_ACK: i32 = 10;
    const NETLINK_EXT_ACK: i32 = 11;

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    #[repr(C)]
    struct RawNetlinkSocketAddress {
        family: u16,
        padding: u16,
        port_id: u32,
        groups: u32,
    }

    const _: () = assert!(AF_NETLINK == libc::AF_NETLINK as u16);
    const _: () = assert!(SOCKADDR_NL_LENGTH as usize == mem::size_of::<libc::sockaddr_nl>());
    const _: () =
        assert!(mem::size_of::<RawNetlinkSocketAddress>() == mem::size_of::<libc::sockaddr_nl>());
    const _: () =
        assert!(mem::align_of::<RawNetlinkSocketAddress>() == mem::align_of::<libc::sockaddr_nl>());

    pub(super) struct LivePolicyRoutingTransport {
        fd: OwnedFd,
        evidence: PolicyRoutingSessionEvidence,
    }

    impl LivePolicyRoutingTransport {
        pub(super) fn open() -> Result<Self, PolicyRoutingSessionFailure> {
            // SAFETY: socket has no pointer arguments and returns a new owned
            // descriptor. CLOEXEC and NONBLOCK are applied atomically.
            let descriptor = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_ROUTE,
                )
            };
            if descriptor < 0 {
                return Err(last_system_failure("create NETLINK_ROUTE socket"));
            }
            // SAFETY: the successful socket call returned a new owned FD.
            let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
            set_required_option(fd.as_raw_fd(), NETLINK_EXT_ACK, "enable NETLINK_EXT_ACK")?;
            set_required_option(fd.as_raw_fd(), NETLINK_CAP_ACK, "enable NETLINK_CAP_ACK")?;

            let address = RawNetlinkSocketAddress {
                family: AF_NETLINK,
                ..RawNetlinkSocketAddress::default()
            };
            // SAFETY: address has the sockaddr_nl ABI and is readable for its
            // exact declared size while fd owns a NETLINK_ROUTE socket.
            if unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    std::ptr::from_ref(&address).cast::<libc::sockaddr>(),
                    SOCKADDR_NL_LENGTH,
                )
            } != 0
            {
                return Err(last_system_failure("bind groups-zero NETLINK_ROUTE socket"));
            }

            let mut local = RawNetlinkSocketAddress::default();
            let mut local_length = SOCKADDR_NL_LENGTH;
            // SAFETY: local and local_length point to writable storage of the
            // declared sockaddr_nl size for the bound owned descriptor.
            if unsafe {
                libc::getsockname(
                    fd.as_raw_fd(),
                    std::ptr::from_mut(&mut local).cast::<libc::sockaddr>(),
                    &raw mut local_length,
                )
            } != 0
            {
                return Err(last_system_failure("read NETLINK_ROUTE local address"));
            }
            let local_port_id = NonZeroU32::new(local.port_id).ok_or_else(|| {
                PolicyRoutingSessionFailure::new(
                    "verify NETLINK_ROUTE local address",
                    PolicyRoutingSessionFailureKind::InvalidFrame,
                    0,
                )
            })?;
            if local_length != SOCKADDR_NL_LENGTH || local.family != AF_NETLINK || local.groups != 0
            {
                return Err(PolicyRoutingSessionFailure::new(
                    "verify NETLINK_ROUTE local address",
                    PolicyRoutingSessionFailureKind::UnexpectedSender,
                    0,
                ));
            }

            Ok(Self {
                fd,
                evidence: PolicyRoutingSessionEvidence {
                    local_port_id,
                    groups: 0,
                    extended_ack: true,
                    capped_ack: true,
                },
            })
        }
    }

    impl PolicyRoutingTransport for LivePolicyRoutingTransport {
        fn evidence(&self) -> PolicyRoutingSessionEvidence {
            self.evidence
        }

        fn send_datagram(
            &mut self,
            bytes: &[u8],
            deadline: Instant,
        ) -> Result<(), PolicyRoutingSessionFailure> {
            let destination = RawNetlinkSocketAddress {
                family: AF_NETLINK,
                ..RawNetlinkSocketAddress::default()
            };
            loop {
                wait_ready(self.fd.as_raw_fd(), libc::POLLOUT, deadline, "send")?;
                // SAFETY: bytes remain readable for the syscall, destination
                // has the sockaddr_nl ABI, and the owned descriptor is valid.
                let sent = unsafe {
                    libc::sendto(
                        self.fd.as_raw_fd(),
                        bytes.as_ptr().cast::<libc::c_void>(),
                        bytes.len(),
                        libc::MSG_DONTWAIT,
                        std::ptr::from_ref(&destination).cast::<libc::sockaddr>(),
                        SOCKADDR_NL_LENGTH,
                    )
                };
                if sent >= 0 {
                    let actual = usize::try_from(sent).map_err(|_| {
                        PolicyRoutingSessionFailure::new(
                            "send",
                            PolicyRoutingSessionFailureKind::ShortWrite {
                                expected: bytes.len(),
                                actual: 0,
                            },
                            0,
                        )
                    })?;
                    if actual == bytes.len() {
                        return Ok(());
                    }
                    return Err(PolicyRoutingSessionFailure::new(
                        "send",
                        PolicyRoutingSessionFailureKind::ShortWrite {
                            expected: bytes.len(),
                            actual,
                        },
                        0,
                    ));
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR)
                    || error.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue;
                }
                return Err(system_failure("send", error));
            }
        }

        fn receive_datagram(
            &mut self,
            maximum_bytes: usize,
            deadline: Instant,
        ) -> Result<ReceivedPolicyRoutingDatagram, PolicyRoutingSessionFailure> {
            let mut bytes = vec![0_u8; maximum_bytes];
            loop {
                wait_ready(self.fd.as_raw_fd(), libc::POLLIN, deadline, "receive")?;
                let mut sender = RawNetlinkSocketAddress::default();
                let mut sender_length = SOCKADDR_NL_LENGTH;
                // SAFETY: bytes and sender are exclusively writable for their
                // declared sizes, and the descriptor remains valid.
                let received = unsafe {
                    libc::recvfrom(
                        self.fd.as_raw_fd(),
                        bytes.as_mut_ptr().cast::<libc::c_void>(),
                        bytes.len(),
                        libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                        std::ptr::from_mut(&mut sender).cast::<libc::sockaddr>(),
                        &raw mut sender_length,
                    )
                };
                if received >= 0 {
                    let actual = usize::try_from(received).map_err(|_| {
                        PolicyRoutingSessionFailure::new(
                            "receive",
                            PolicyRoutingSessionFailureKind::InvalidFrame,
                            0,
                        )
                    })?;
                    if actual > maximum_bytes {
                        return Err(PolicyRoutingSessionFailure::new(
                            "receive",
                            PolicyRoutingSessionFailureKind::DatagramTooLarge {
                                limit: maximum_bytes,
                                actual,
                            },
                            0,
                        ));
                    }
                    bytes.truncate(actual);
                    return Ok(ReceivedPolicyRoutingDatagram {
                        bytes: bytes.into_boxed_slice(),
                        sender: PolicyRoutingAckSender::new(
                            sender_length,
                            sender.family,
                            sender.port_id,
                            sender.groups,
                        ),
                    });
                }
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR)
                    || error.kind() == std::io::ErrorKind::WouldBlock
                {
                    continue;
                }
                return Err(system_failure("receive", error));
            }
        }
    }

    fn set_required_option(
        fd: i32,
        option: i32,
        operation: &'static str,
    ) -> Result<(), PolicyRoutingSessionFailure> {
        let enabled = 1_i32;
        // SAFETY: enabled is readable for one i32 and fd owns a netlink socket.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                option,
                std::ptr::from_ref(&enabled).cast::<libc::c_void>(),
                mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } != 0
        {
            return Err(last_system_failure(operation));
        }
        Ok(())
    }

    fn wait_ready(
        fd: i32,
        events: i16,
        deadline: Instant,
        operation: &'static str,
    ) -> Result<(), PolicyRoutingSessionFailure> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(PolicyRoutingSessionFailure::new(
                    operation,
                    PolicyRoutingSessionFailureKind::TimedOut,
                    0,
                ));
            }
            let remaining = deadline.duration_since(now);
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            // SAFETY: pollfd points to one initialized descriptor for the
            // duration of the bounded poll call.
            let result = unsafe { libc::poll(&raw mut pollfd, 1, millis) };
            if result > 0 {
                return Ok(());
            }
            if result == 0 {
                return Err(PolicyRoutingSessionFailure::new(
                    operation,
                    PolicyRoutingSessionFailureKind::TimedOut,
                    0,
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(system_failure(operation, error));
        }
    }

    fn last_system_failure(operation: &'static str) -> PolicyRoutingSessionFailure {
        system_failure(operation, std::io::Error::last_os_error())
    }

    fn system_failure(
        operation: &'static str,
        error: std::io::Error,
    ) -> PolicyRoutingSessionFailure {
        PolicyRoutingSessionFailure::new(
            operation,
            PolicyRoutingSessionFailureKind::SystemCall {
                raw_os_error: error.raw_os_error(),
            },
            0,
        )
    }
}

#[cfg(test)]
#[path = "policy_routing_session_tests.rs"]
mod tests;
