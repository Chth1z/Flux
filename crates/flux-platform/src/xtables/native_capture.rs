use std::error::Error;
use std::fmt::{self, Debug};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::{NonZeroI32, NonZeroU16, NonZeroU32, NonZeroU64};
use std::time::Instant;

use flux_core::{
    BootIdentity, GenerationId, NetworkAddressFamily, NetworkNamespaceIdentity,
    OwnershipJournalIdentity, OwnershipJournalRevision, RouteTableId,
};

use super::save::XtablesExpectedState;
use crate::netlink::policy_routing::ManagedPolicyRoutingIdentity;

/// Opaque identity of one exact native capture target.
///
/// The digests bind platform-private xtables, tool, and policy-routing material. They are
/// diagnostic identity only and do not grant mutation authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NativeCaptureTargetIdentity {
    generation: GenerationId,
    target_digest: [u8; 32],
    tool_digest: [u8; 32],
    routing_digest: [u8; 32],
}

impl NativeCaptureTargetIdentity {
    #[must_use]
    pub(crate) const fn new(
        generation: GenerationId,
        target_digest: [u8; 32],
        tool_digest: [u8; 32],
        routing_digest: [u8; 32],
    ) -> Self {
        Self {
            generation,
            target_digest,
            tool_digest,
            routing_digest,
        }
    }

    #[must_use]
    pub const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn target_digest(self) -> [u8; 32] {
        self.target_digest
    }

    #[must_use]
    pub const fn tool_digest(self) -> [u8; 32] {
        self.tool_digest
    }

    #[must_use]
    pub const fn routing_digest(self) -> [u8; 32] {
        self.routing_digest
    }
}

/// Descriptor-anchored read-only evidence for one exact active native capture owner.
///
/// Construction remains platform-private. The value carries no writer, lease, target, or cleanup
/// authority and can only be observed through [`NativeCaptureConvergence`].
#[derive(Clone, Eq, PartialEq)]
pub struct NativeCaptureOwnershipObservation {
    target: NativeCaptureTargetIdentity,
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    journal_identity: OwnershipJournalIdentity,
    journal_revision: OwnershipJournalRevision,
    record_schema_version: NonZeroU16,
    record_device: u64,
    record_inode: NonZeroU64,
    record_digest: [u8; 32],
    retained_owner: NativeCaptureRetainedOwner,
}

impl fmt::Debug for NativeCaptureOwnershipObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeCaptureOwnershipObservation")
            .field("target", &self.target)
            .field("boot_identity", &self.boot_identity)
            .field("network_namespace", &self.network_namespace)
            .field("journal_identity", &self.journal_identity)
            .field("journal_revision", &self.journal_revision)
            .field("record_schema_version", &self.record_schema_version)
            .field("record_device", &self.record_device)
            .field("record_inode", &self.record_inode)
            .field("record_digest", &self.record_digest)
            .field("retained_owner", &"<redacted>")
            .finish()
    }
}

/// Opaque, read-only ownership cohort minted only after an exact active native readback.
///
/// The cohort carries the target's private xtables expectations and exact managed routing
/// identities. It is intentionally non-authorizing: it can only narrow a census projection, and
/// it cannot be used to restore, converge, or open any durable state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeCaptureRetainedOwner {
    target: NativeCaptureTargetIdentity,
    ipv4: Option<XtablesExpectedState>,
    ipv6: Option<XtablesExpectedState>,
    routing: Box<[ManagedPolicyRoutingIdentity]>,
}

impl NativeCaptureRetainedOwner {
    pub(crate) fn new(
        target: NativeCaptureTargetIdentity,
        ipv4: Option<XtablesExpectedState>,
        ipv6: Option<XtablesExpectedState>,
        routing: impl IntoIterator<Item = ManagedPolicyRoutingIdentity>,
    ) -> Self {
        Self {
            target,
            ipv4,
            ipv6,
            routing: routing.into_iter().collect(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub const fn target(&self) -> NativeCaptureTargetIdentity {
        self.target
    }

    #[must_use]
    pub(crate) const fn xtables_expected_state(
        &self,
        family: NetworkAddressFamily,
    ) -> Option<&XtablesExpectedState> {
        match family {
            NetworkAddressFamily::Ipv4 => self.ipv4.as_ref(),
            NetworkAddressFamily::Ipv6 => self.ipv6.as_ref(),
        }
    }

    #[must_use]
    pub(crate) fn routing(&self) -> &[ManagedPolicyRoutingIdentity] {
        &self.routing
    }
}

impl NativeCaptureOwnershipObservation {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new(
        target: NativeCaptureTargetIdentity,
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
        journal_identity: OwnershipJournalIdentity,
        journal_revision: OwnershipJournalRevision,
        record_schema_version: NonZeroU16,
        record_device: u64,
        record_inode: NonZeroU64,
        record_digest: [u8; 32],
        retained_owner: NativeCaptureRetainedOwner,
    ) -> Self {
        Self {
            target,
            boot_identity,
            network_namespace,
            journal_identity,
            journal_revision,
            record_schema_version,
            record_device,
            record_inode,
            record_digest,
            retained_owner,
        }
    }

    #[must_use]
    pub const fn target(&self) -> NativeCaptureTargetIdentity {
        self.target
    }

    #[must_use]
    pub const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub const fn journal_identity(&self) -> OwnershipJournalIdentity {
        self.journal_identity
    }

    #[must_use]
    pub const fn journal_revision(&self) -> OwnershipJournalRevision {
        self.journal_revision
    }

    #[must_use]
    pub const fn record_schema_version(&self) -> NonZeroU16 {
        self.record_schema_version
    }

    #[must_use]
    pub const fn record_device(&self) -> u64 {
        self.record_device
    }

    #[must_use]
    pub const fn record_inode(&self) -> NonZeroU64 {
        self.record_inode
    }

    #[must_use]
    pub const fn record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    #[must_use]
    pub(crate) const fn retained_owner(&self) -> &NativeCaptureRetainedOwner {
        &self.retained_owner
    }
}

/// Exact traffic selector for one bounded native functional-canary attempt.
///
/// Chain identity and packet-mark values remain admitted target material. This value carries only
/// the request facts needed to populate that target's already-reserved selector slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanarySelector {
    probe_uid: NonZeroU32,
    ipv4_peer: Ipv4Addr,
    ipv6_peer: Option<Ipv6Addr>,
    tcp_echo_port: NonZeroU16,
    udp_echo_port: NonZeroU16,
    dns_port: NonZeroU16,
}

impl NativeCaptureCanarySelector {
    #[must_use]
    pub const fn new(
        probe_uid: NonZeroU32,
        ipv4_peer: Ipv4Addr,
        ipv6_peer: Option<Ipv6Addr>,
        tcp_echo_port: NonZeroU16,
        udp_echo_port: NonZeroU16,
        dns_port: NonZeroU16,
    ) -> Option<Self> {
        if tcp_echo_port.get() == dns_port.get() || udp_echo_port.get() == dns_port.get() {
            return None;
        }
        Some(Self {
            probe_uid,
            ipv4_peer,
            ipv6_peer,
            tcp_echo_port,
            udp_echo_port,
            dns_port,
        })
    }

    #[must_use]
    pub const fn probe_uid(self) -> NonZeroU32 {
        self.probe_uid
    }

    #[must_use]
    pub const fn ipv4_peer(self) -> Ipv4Addr {
        self.ipv4_peer
    }

    #[must_use]
    pub const fn ipv6_peer(self) -> Option<Ipv6Addr> {
        self.ipv6_peer
    }

    #[must_use]
    pub const fn tcp_echo_port(self) -> NonZeroU16 {
        self.tcp_echo_port
    }

    #[must_use]
    pub const fn udp_echo_port(self) -> NonZeroU16 {
        self.udp_echo_port
    }

    #[must_use]
    pub const fn dns_port(self) -> NonZeroU16 {
        self.dns_port
    }
}

/// Exact request identity for one serialized native canary mutation session.
///
/// The owner derives Generation-scoped chain and mark identities from the admitted target. This
/// value supplies only request-owned facts that cannot be reconstructed after a restart. Nonce
/// bytes are intentionally redacted from `Debug` output.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NativeCaptureCanaryAttempt {
    selector: NativeCaptureCanarySelector,
    nonce: [u8; 32],
    selector_identity: [u8; 32],
    facility_digest: [u8; 32],
}

impl NativeCaptureCanaryAttempt {
    #[must_use]
    pub const fn new(
        selector: NativeCaptureCanarySelector,
        nonce: [u8; 32],
        selector_identity: [u8; 32],
        facility_digest: [u8; 32],
    ) -> Option<Self> {
        if bytes_are_zero(&selector_identity) || bytes_are_zero(&facility_digest) {
            return None;
        }
        Some(Self {
            selector,
            nonce,
            selector_identity,
            facility_digest,
        })
    }

    #[must_use]
    pub const fn selector(self) -> NativeCaptureCanarySelector {
        self.selector
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    #[must_use]
    pub const fn selector_identity(&self) -> &[u8; 32] {
        &self.selector_identity
    }

    #[must_use]
    pub const fn facility_digest(&self) -> &[u8; 32] {
        &self.facility_digest
    }
}

impl fmt::Debug for NativeCaptureCanaryAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeCaptureCanaryAttempt")
            .field("selector", &self.selector)
            .field("nonce", &"<redacted>")
            .field("selector_identity", &self.selector_identity)
            .field("facility_digest", &self.facility_digest)
            .finish()
    }
}

const fn bytes_are_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

/// Exact fixed-purpose TCP route lookup for one active canary selector.
///
/// The destination port must be nonzero. Source address and source port are deliberately absent:
/// this negative control completes before the supervised engine creates its outbound socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanaryRouteQuery {
    destination: SocketAddr,
    uid: NonZeroU32,
    mark: u32,
    deadline: Instant,
}

impl NativeCaptureCanaryRouteQuery {
    #[must_use]
    pub fn new(
        destination: SocketAddr,
        uid: NonZeroU32,
        mark: u32,
        deadline: Instant,
    ) -> Option<Self> {
        NonZeroU16::new(destination.port())?;
        Some(Self {
            destination,
            uid,
            mark,
            deadline,
        })
    }

    #[must_use]
    pub const fn destination(self) -> SocketAddr {
        self.destination
    }

    #[must_use]
    pub fn responder_port(self) -> NonZeroU16 {
        NonZeroU16::new(self.destination.port())
            .expect("canary route query construction rejects port zero")
    }

    #[must_use]
    pub const fn uid(self) -> NonZeroU32 {
        self.uid
    }

    #[must_use]
    pub const fn mark(self) -> u32 {
        self.mark
    }

    #[must_use]
    pub const fn deadline(self) -> Instant {
        self.deadline
    }
}

/// Strict kernel-selected table observation for one exact canary query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanaryRouteObservation {
    query: NativeCaptureCanaryRouteQuery,
    selected_table: RouteTableId,
    observed_at: Instant,
}

impl NativeCaptureCanaryRouteObservation {
    #[must_use]
    pub(crate) const fn new(
        query: NativeCaptureCanaryRouteQuery,
        selected_table: RouteTableId,
        observed_at: Instant,
    ) -> Self {
        Self {
            query,
            selected_table,
            observed_at,
        }
    }

    #[must_use]
    pub const fn query(self) -> NativeCaptureCanaryRouteQuery {
        self.query
    }

    #[must_use]
    pub const fn selected_table(self) -> RouteTableId {
        self.selected_table
    }

    #[must_use]
    pub const fn observed_at(self) -> Instant {
        self.observed_at
    }
}

/// Definite bounded kernel rejection for a read-only canary route lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanaryRouteRejection {
    errno: NonZeroI32,
}

impl NativeCaptureCanaryRouteRejection {
    #[must_use]
    pub(crate) const fn new(errno: NonZeroI32) -> Self {
        Self { errno }
    }

    #[must_use]
    pub const fn errno(self) -> NonZeroI32 {
        self.errno
    }
}

/// One definite response from the fixed-purpose route lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCaptureCanaryRouteOutcome {
    Resolved(NativeCaptureCanaryRouteObservation),
    Rejected(NativeCaptureCanaryRouteRejection),
}

/// One exact aggregate readback of the active canary observation chains.
///
/// Packet counts cover every address family enabled by the admitted target. `observed_at` is
/// sampled locally only after the complete counted readback and owner-state revalidation finish.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanaryCounterSnapshot {
    capture_packets: u64,
    bypass_packets: u64,
    recapture_packets: u64,
    observed_at: Instant,
}

impl NativeCaptureCanaryCounterSnapshot {
    #[must_use]
    pub(crate) const fn new(
        capture_packets: u64,
        bypass_packets: u64,
        recapture_packets: u64,
        observed_at: Instant,
    ) -> Self {
        Self {
            capture_packets,
            bypass_packets,
            recapture_packets,
            observed_at,
        }
    }

    #[must_use]
    pub const fn capture_packets(self) -> u64 {
        self.capture_packets
    }

    #[must_use]
    pub const fn bypass_packets(self) -> u64 {
        self.bypass_packets
    }

    #[must_use]
    pub const fn recapture_packets(self) -> u64 {
        self.recapture_packets
    }

    #[must_use]
    pub const fn observed_at(self) -> Instant {
        self.observed_at
    }
}

/// Exact retirement of the active canary counter object while its selector remains owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureCanaryCounterRetirement {
    retired_at: Instant,
    absent_observed_at: Instant,
}

impl NativeCaptureCanaryCounterRetirement {
    #[must_use]
    pub(crate) const fn new(retired_at: Instant, absent_observed_at: Instant) -> Self {
        Self {
            retired_at,
            absent_observed_at,
        }
    }

    #[must_use]
    pub const fn retired_at(self) -> Instant {
        self.retired_at
    }

    #[must_use]
    pub const fn absent_observed_at(self) -> Instant {
        self.absent_observed_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCaptureDesired<T> {
    Active(T),
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCaptureConvergedState<I> {
    Active(I),
    CleanAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCaptureConvergenceReport<I> {
    state: NativeCaptureConvergedState<I>,
    changed: bool,
}

impl<I> NativeCaptureConvergenceReport<I> {
    #[must_use]
    pub const fn new(state: NativeCaptureConvergedState<I>, changed: bool) -> Self {
        Self { state, changed }
    }

    #[must_use]
    pub const fn state(&self) -> &NativeCaptureConvergedState<I> {
        &self.state
    }

    #[must_use]
    pub const fn changed(&self) -> bool {
        self.changed
    }
}

/// Coordinator-facing native capture interface.
///
/// Implementations own recovery, exact readback, mutation ordering, compensation, and durable
/// state. Callers can request startup recovery, convergence to one opaque target/absence, or one
/// bounded selector population/retirement inside that admitted target.
pub trait NativeCaptureConvergence: Send + 'static {
    type Target: Clone + Send + 'static;
    type Identity: Copy + Debug + Eq + Send + Sync + 'static;
    type Error: Error + Send + Sync + 'static;

    fn target_identity(target: &Self::Target) -> Self::Identity;

    fn recover(&mut self) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error>;

    /// Observes the exact active native ownership record without granting mutation authority.
    ///
    /// Non-native implementations remain unsupported by default. A missing observation must not
    /// be interpreted as positive evidence by a caller that requires a functional canary.
    fn observe_active_ownership(
        &mut self,
    ) -> Result<Option<NativeCaptureOwnershipObservation>, Self::Error> {
        Ok(None)
    }

    /// Populates the admitted target's reserved canary selector and proves exact readback.
    ///
    /// `false` means this implementation has no selector mutation authority. It must not be
    /// interpreted as a successful no-op by a required functional-canary caller.
    fn populate_canary_selector(
        &mut self,
        _target: &Self::Target,
        _attempt: NativeCaptureCanaryAttempt,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Flushes the admitted target's exact canary selector and proves its absence.
    ///
    /// `false` has the same unsupported meaning as [`Self::populate_canary_selector`].
    fn retire_canary_selector(
        &mut self,
        _target: &Self::Target,
        _attempt: NativeCaptureCanaryAttempt,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    /// Resolves one exact canary TCP route while the matching selector remains active.
    ///
    /// `None` means this implementation has no route-observation authority. A definite kernel
    /// rejection is a typed outcome so callers may perform normal cleanup; ambiguous transport or
    /// framing failures remain implementation errors and require recovery.
    fn observe_canary_route(
        &mut self,
        _target: &Self::Target,
        _attempt: NativeCaptureCanaryAttempt,
        _query: NativeCaptureCanaryRouteQuery,
    ) -> Result<Option<NativeCaptureCanaryRouteOutcome>, Self::Error> {
        Ok(None)
    }

    /// Reads the exact active canary observation chains before one immutable deadline.
    ///
    /// `None` means this implementation has no counter-observation authority. A supported
    /// implementation must bind the readback to the exact active target and attempt and reject a
    /// snapshot completed at or after `deadline`.
    fn observe_canary_counters(
        &mut self,
        _target: &Self::Target,
        _attempt: NativeCaptureCanaryAttempt,
        _deadline: Instant,
    ) -> Result<Option<NativeCaptureCanaryCounterSnapshot>, Self::Error> {
        Ok(None)
    }

    /// Retires the exact canary counter object while retaining the active selector session.
    ///
    /// `None` means this implementation cannot provide the intermediate cleanup boundary. A
    /// supported implementation must prove counter absence before `deadline`; final selector and
    /// recovery-record retirement remain owned by [`Self::retire_canary_selector`].
    fn retire_canary_counters(
        &mut self,
        _target: &Self::Target,
        _attempt: NativeCaptureCanaryAttempt,
        _deadline: Instant,
    ) -> Result<Option<NativeCaptureCanaryCounterRetirement>, Self::Error> {
        Ok(None)
    }

    fn converge(
        &mut self,
        desired: NativeCaptureDesired<Self::Target>,
    ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error>;
}
