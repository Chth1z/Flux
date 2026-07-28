use std::io;
use std::num::NonZeroUsize;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::BorrowedFd;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::NetworkEpoch;
#[cfg(any(target_os = "linux", target_os = "android"))]
use flux_core::NetworkInventory;

use crate::PlatformError;
use crate::address_sync::{AddressEventPolicy, RtnetlinkAddressEventDecoder};
use crate::netlink::link::RtnetlinkLinkEventDecoder;
use crate::netlink::route::RtnetlinkRouteEventDecoder;
use crate::netlink::rule::RtnetlinkRuleEventDecoder;
use crate::netlink::socket::{
    AddressDumpRequest, LinkDumpRequest, NetlinkReceiveLoss, NetlinkReceiveOutcome,
    NetlinkReceiveRing, NetlinkSendOutcome, NetlinkSequenceAllocator, RECEIVE_BATCH_SLOTS,
    ROUTE_DATAGRAM_CAPACITY, RouteDumpRequest, RouteNetlinkSocket, RouteNetlinkSocketEvidence,
    RuleDumpRequest,
};
use crate::netlink::terminal_sequences;

use super::{
    InventoryDatagramObservation, InventoryDatagramOrigin, MAX_RACE_QUEUE_BYTES,
    MAX_RACE_QUEUE_CAPACITY, NetworkInventoryObserver, NetworkInventorySource, ObserverConfig,
    ObserverDriveOutcome, ObserverFault, ObserverLoss, deadline_after,
};

const DEFAULT_DUMP_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_QUIET_DEBOUNCE: Duration = Duration::from_millis(50);
const DEFAULT_MAXIMUM_DEBOUNCE: Duration = Duration::from_millis(250);
const DEFAULT_DUMP_SEND_RETRY: Duration = Duration::from_millis(50);
const DEFAULT_READY_DATAGRAM_BUDGET: usize = 16;
const DEFAULT_READY_BYTE_BUDGET: usize = 1024 * 1024;
#[cfg(any(target_os = "linux", target_os = "android"))]
const MAX_ONE_SHOT_INVENTORY_TIMEOUT: Duration = Duration::from_secs(30);

/// A hard per-turn receive budget for the route inventory driver.
///
/// The byte budget must reserve at least one complete 256 KiB netlink
/// datagram. The driver conservatively limits each `recvmmsg` invocation by
/// the remaining worst-case slot capacity, so an accepted batch can always be
/// consumed atomically without exceeding this budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteNetworkInventoryWorkBudget {
    max_datagrams: usize,
    max_bytes: usize,
}

impl RouteNetworkInventoryWorkBudget {
    pub(crate) const fn new(max_datagrams: usize, max_bytes: usize) -> Option<Self> {
        if max_datagrams == 0 || max_bytes < ROUTE_DATAGRAM_CAPACITY {
            return None;
        }
        Some(Self {
            max_datagrams,
            max_bytes,
        })
    }

    pub(crate) const fn max_datagrams(self) -> usize {
        self.max_datagrams
    }

    pub(crate) const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

impl Default for RouteNetworkInventoryWorkBudget {
    fn default() -> Self {
        Self {
            max_datagrams: DEFAULT_READY_DATAGRAM_BUDGET,
            max_bytes: DEFAULT_READY_BYTE_BUDGET,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteNetworkInventoryDriveDisposition {
    Idle,
    Progress,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RouteNetworkInventoryDriveReport {
    disposition: RouteNetworkInventoryDriveDisposition,
    datagrams: usize,
    bytes: usize,
    published_epoch: Option<NetworkEpoch>,
    resync_fault: Option<ObserverFault>,
}

impl RouteNetworkInventoryDriveReport {
    pub(crate) const fn disposition(self) -> RouteNetworkInventoryDriveDisposition {
        self.disposition
    }

    pub(crate) const fn datagrams(self) -> usize {
        self.datagrams
    }

    pub(crate) const fn bytes(self) -> usize {
        self.bytes
    }

    pub(crate) const fn published_epoch(self) -> Option<NetworkEpoch> {
        self.published_epoch
    }

    pub(crate) const fn resync_fault(self) -> Option<ObserverFault> {
        self.resync_fault
    }
}

/// Opaque owner of the read-only route-netlink inventory pipeline.
///
/// The socket is opened and subscribed before `open` attempts the initial
/// `RTM_GETLINK`, `AF_UNSPEC RTM_GETADDR`, `RTM_GETROUTE`, and `RTM_GETRULE`
/// dumps in strict sequence.
/// Raw framing, sequence allocation, receive storage, decoding, loss recovery,
/// and publication remain private. Any returned error is permanent for this
/// driver instance: the source is made stale before the error reaches the
/// caller, allowing the daemon to disable observation without disturbing its
/// other facilities.
pub(crate) struct RouteNetworkInventoryDriver {
    inner: RouteNetworkInventoryDriverInner<SystemRouteNetworkInventoryTransport>,
}

impl RouteNetworkInventoryDriver {
    pub(crate) fn open(
        policy: AddressEventPolicy,
        now: Instant,
    ) -> Result<(Self, NetworkInventorySource), PlatformError> {
        let transport = SystemRouteNetworkInventoryTransport::open(policy)?;
        let (inner, source) = RouteNetworkInventoryDriverInner::start(
            transport,
            production_observer_config(),
            DEFAULT_DUMP_SEND_RETRY,
            now,
        )?;
        Ok((Self { inner }, source))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn open_primed(
        policy: AddressEventPolicy,
        timeout: Duration,
    ) -> Result<(Self, NetworkInventorySource, Arc<NetworkInventory>), PlatformError> {
        validate_inventory_timeout(timeout)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(timeout)
            .ok_or_else(invalid_inventory_timeout)?;
        let (mut driver, source) = Self::open(policy, started)?;
        let snapshot = driver.prime_until_complete(&source, deadline)?;
        Ok((driver, source, snapshot))
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn readiness_fd(&self) -> BorrowedFd<'_> {
        self.inner.transport.readiness_fd()
    }

    pub(crate) fn evidence(&self) -> RouteNetlinkSocketEvidence {
        self.inner.transport.evidence()
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.inner.next_deadline()
    }

    pub(crate) fn drive_ready(
        &mut self,
        budget: RouteNetworkInventoryWorkBudget,
        now: Instant,
    ) -> Result<RouteNetworkInventoryDriveReport, PlatformError> {
        self.inner.drive_ready(budget, now)
    }

    pub(crate) fn drive_due(
        &mut self,
        now: Instant,
    ) -> Result<RouteNetworkInventoryDriveReport, PlatformError> {
        self.inner.drive_due(now)
    }

    /// Immediately invalidates all cloned public sources.
    ///
    /// This operation is idempotent. It is used before removing the socket
    /// from the sole reactor and is also performed automatically on drop and
    /// before any permanent transport error is returned.
    pub(crate) fn disable(&mut self) {
        self.inner.disable();
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn prime_until_complete(
        &mut self,
        source: &NetworkInventorySource,
        deadline: Instant,
    ) -> Result<Arc<NetworkInventory>, PlatformError> {
        loop {
            if let Some(snapshot) = source.snapshot() {
                return Ok(snapshot);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(inventory_timeout());
            }
            self.drive_due(now)?;
            if let Some(snapshot) = source.snapshot() {
                return Ok(snapshot);
            }

            wait_for_inventory_readiness(
                self.readiness_fd(),
                self.next_deadline()
                    .map_or(deadline, |next| next.min(deadline)),
            )?;
            loop {
                if Instant::now() >= deadline {
                    return Err(inventory_timeout());
                }
                let report =
                    self.drive_ready(RouteNetworkInventoryWorkBudget::default(), Instant::now())?;
                if report.disposition() != RouteNetworkInventoryDriveDisposition::BudgetExhausted {
                    break;
                }
            }
        }
    }
}

/// Collects one complete subscribed route-netlink inventory within an explicit bound.
///
/// This drives the same loss-aware LINK, ADDRESS, ROUTE, and RULE transaction as the daemon's
/// long-lived observer. The socket is subscribed before the first dump request, and no partial or
/// stale inventory is returned.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn collect_network_inventory_once(
    timeout: Duration,
) -> Result<Arc<NetworkInventory>, PlatformError> {
    let (_driver, _source, snapshot) =
        RouteNetworkInventoryDriver::open_primed(AddressEventPolicy::new(true), timeout)?;
    Ok(snapshot)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn wait_for_inventory_readiness(
    descriptor: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<(), PlatformError> {
    use std::os::fd::AsRawFd;

    let mut poll_fd = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `poll_fd` points to one initialized poll descriptor borrowed for this call.
        let result = unsafe { libc::poll(&raw mut poll_fd, 1, timeout_ms) };
        if result >= 0 {
            if poll_fd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err(PlatformError::SystemCall {
                    operation: "wait for initial route-netlink inventory",
                    source: io::Error::other(format!(
                        "route-netlink descriptor reported events {:#x}",
                        poll_fd.revents
                    )),
                });
            }
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(libc::EINTR) {
            return Err(PlatformError::SystemCall {
                operation: "wait for initial route-netlink inventory",
                source,
            });
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_inventory_timeout(timeout: Duration) -> Result<(), PlatformError> {
    if timeout.is_zero() || timeout > MAX_ONE_SHOT_INVENTORY_TIMEOUT {
        Err(invalid_inventory_timeout())
    } else {
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn invalid_inventory_timeout() -> PlatformError {
    PlatformError::SystemCall {
        operation: "validate initial route-netlink inventory timeout",
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("timeout must be nonzero and at most {MAX_ONE_SHOT_INVENTORY_TIMEOUT:?}"),
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn inventory_timeout() -> PlatformError {
    PlatformError::SystemCall {
        operation: "collect initial route-netlink inventory",
        source: io::Error::new(
            io::ErrorKind::TimedOut,
            "complete LINK/ADDRESS/ROUTE/RULE inventory was not published before the deadline",
        ),
    }
}

fn production_observer_config() -> ObserverConfig {
    ObserverConfig::new(
        MAX_RACE_QUEUE_CAPACITY,
        MAX_RACE_QUEUE_BYTES,
        DEFAULT_DUMP_TIMEOUT,
        DEFAULT_QUIET_DEBOUNCE,
        DEFAULT_MAXIMUM_DEBOUNCE,
    )
    .expect("hard-coded route inventory observer configuration is valid")
}

fn inventory_datagram_origin(sender_groups: u32) -> InventoryDatagramOrigin {
    if sender_groups == 0 {
        InventoryDatagramOrigin::Response
    } else {
        InventoryDatagramOrigin::Notification
    }
}

struct SystemRouteNetworkInventoryTransport {
    socket: RouteNetlinkSocket,
    ring: NetlinkReceiveRing,
    link_decoder: RtnetlinkLinkEventDecoder,
    address_decoder: RtnetlinkAddressEventDecoder,
    route_decoder: RtnetlinkRouteEventDecoder,
    rule_decoder: RtnetlinkRuleEventDecoder,
}

impl SystemRouteNetworkInventoryTransport {
    fn open(policy: AddressEventPolicy) -> Result<Self, PlatformError> {
        // RouteNetlinkSocket::open binds all multicast subscriptions before it
        // returns. No dump can be sent until this fully constructed owner is
        // handed to the driver state machine below.
        let socket = RouteNetlinkSocket::open()?;
        Ok(Self {
            socket,
            ring: NetlinkReceiveRing::new(),
            link_decoder: RtnetlinkLinkEventDecoder::new(),
            address_decoder: RtnetlinkAddressEventDecoder::new(policy),
            route_decoder: RtnetlinkRouteEventDecoder::new(true),
            rule_decoder: RtnetlinkRuleEventDecoder::new(true),
        })
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn readiness_fd(&self) -> BorrowedFd<'_> {
        self.socket.readiness_fd()
    }

    fn evidence(&self) -> RouteNetlinkSocketEvidence {
        self.socket.evidence()
    }
}

impl RouteNetworkInventoryTransport for SystemRouteNetworkInventoryTransport {
    fn send_link_dump(
        &mut self,
        request: &LinkDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError> {
        self.socket.send_link_dump(request)
    }

    fn send_address_dump(
        &mut self,
        request: &AddressDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError> {
        self.socket.send_address_dump(request)
    }

    fn send_route_dump(
        &mut self,
        request: &RouteDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError> {
        self.socket.send_route_dump(request)
    }

    fn send_rule_dump(
        &mut self,
        request: &RuleDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError> {
        self.socket.send_rule_dump(request)
    }

    fn receive_decoded_batch(
        &mut self,
        max_datagrams: NonZeroUsize,
    ) -> Result<RouteNetworkInventoryReceiveOutcome, PlatformError> {
        let Self {
            socket,
            ring,
            link_decoder,
            address_decoder,
            route_decoder,
            rule_decoder,
        } = self;
        match socket.receive_batch(ring, max_datagrams)? {
            NetlinkReceiveOutcome::WouldBlock => {
                Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock)
            }
            NetlinkReceiveOutcome::Loss {
                loss,
                terminal_sequences,
            } => Ok(RouteNetworkInventoryReceiveOutcome::Loss {
                cause: match loss {
                    NetlinkReceiveLoss::Enobufs => ObserverLoss::Enobufs,
                    NetlinkReceiveLoss::Truncated(_) => ObserverLoss::Truncated,
                    NetlinkReceiveLoss::UnexpectedSender(_) => ObserverLoss::UnexpectedSender,
                },
                terminal_sequences,
            }),
            NetlinkReceiveOutcome::Datagrams(batch) => {
                let count = batch.len();
                let mut bytes = 0_usize;
                let mut datagrams = Vec::with_capacity(count);
                for index in 0..count {
                    let datagram = batch
                        .datagram(index)
                        .expect("validated receive batch index is present");
                    let wire_bytes = datagram.bytes().len();
                    bytes = bytes.saturating_add(wire_bytes);
                    let origin = inventory_datagram_origin(datagram.metadata().sender().groups());
                    datagrams.push(InventoryDatagramObservation::from_decoded(
                        link_decoder.decode_datagram(datagram.bytes()),
                        address_decoder.decode_datagram(datagram.bytes()),
                        route_decoder.decode_datagram(datagram.bytes()),
                        rule_decoder.decode_datagram(datagram.bytes()),
                        origin,
                        wire_bytes,
                        terminal_sequences(datagram.bytes()),
                    ));
                }
                Ok(RouteNetworkInventoryReceiveOutcome::Batch(
                    DecodedRouteNetworkInventoryBatch { datagrams, bytes },
                ))
            }
        }
    }
}

trait RouteNetworkInventoryTransport {
    fn send_link_dump(
        &mut self,
        request: &LinkDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError>;

    fn send_address_dump(
        &mut self,
        request: &AddressDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError>;

    fn send_route_dump(
        &mut self,
        request: &RouteDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError>;

    fn send_rule_dump(
        &mut self,
        request: &RuleDumpRequest,
    ) -> Result<NetlinkSendOutcome, PlatformError>;

    fn receive_decoded_batch(
        &mut self,
        max_datagrams: NonZeroUsize,
    ) -> Result<RouteNetworkInventoryReceiveOutcome, PlatformError>;
}

enum RouteNetworkInventoryReceiveOutcome {
    WouldBlock,
    Batch(DecodedRouteNetworkInventoryBatch),
    Loss {
        cause: ObserverLoss,
        terminal_sequences: Box<[u32]>,
    },
}

struct DecodedRouteNetworkInventoryBatch {
    datagrams: Vec<InventoryDatagramObservation>,
    bytes: usize,
}

#[derive(Clone, Copy, Debug)]
enum PendingDumpRequest {
    Link {
        request: LinkDumpRequest,
        retry_at: Instant,
    },
    Address {
        request: AddressDumpRequest,
        retry_at: Instant,
    },
    Route {
        request: RouteDumpRequest,
        retry_at: Instant,
    },
    Rule {
        request: RuleDumpRequest,
        retry_at: Instant,
    },
}

impl PendingDumpRequest {
    const fn retry_at(self) -> Instant {
        match self {
            Self::Link { retry_at, .. }
            | Self::Address { retry_at, .. }
            | Self::Route { retry_at, .. }
            | Self::Rule { retry_at, .. } => retry_at,
        }
    }

    fn with_retry_at(self, retry_at: Instant) -> Self {
        match self {
            Self::Link { request, .. } => Self::Link { request, retry_at },
            Self::Address { request, .. } => Self::Address { request, retry_at },
            Self::Route { request, .. } => Self::Route { request, retry_at },
            Self::Rule { request, .. } => Self::Rule { request, retry_at },
        }
    }
}

struct RouteNetworkInventoryDriverInner<T> {
    transport: T,
    observer: NetworkInventoryObserver,
    sequences: NetlinkSequenceAllocator,
    pending_dump: Option<PendingDumpRequest>,
    dump_send_retry: Duration,
    disabled: bool,
}

impl<T: RouteNetworkInventoryTransport> RouteNetworkInventoryDriverInner<T> {
    fn start(
        transport: T,
        observer_config: ObserverConfig,
        dump_send_retry: Duration,
        now: Instant,
    ) -> Result<(Self, NetworkInventorySource), PlatformError> {
        debug_assert!(!dump_send_retry.is_zero());
        let observer = NetworkInventoryObserver::new(observer_config);
        let source = observer.source();
        let mut driver = Self {
            transport,
            observer,
            sequences: NetlinkSequenceAllocator::default(),
            pending_dump: None,
            dump_send_retry,
            disabled: false,
        };
        driver.schedule_resync(now);
        let mut progress = DriveProgress::default();
        driver.try_send_dump(now, &mut progress)?;
        Ok((driver, source))
    }

    fn next_deadline(&self) -> Option<Instant> {
        if self.disabled {
            return None;
        }
        earliest_deadline(
            self.observer.next_deadline(),
            self.pending_dump.map(PendingDumpRequest::retry_at),
        )
    }

    fn drive_ready(
        &mut self,
        budget: RouteNetworkInventoryWorkBudget,
        now: Instant,
    ) -> Result<RouteNetworkInventoryDriveReport, PlatformError> {
        if self.disabled {
            return Ok(DriveProgress::default().finish(false));
        }

        let mut progress = DriveProgress::default();
        loop {
            let Some(max_datagrams) = receive_allowance(budget, &progress) else {
                return Ok(progress.finish(true));
            };

            let received = match self.transport.receive_decoded_batch(max_datagrams) {
                Ok(received) => received,
                Err(error) => {
                    self.disable();
                    return Err(error);
                }
            };
            match received {
                RouteNetworkInventoryReceiveOutcome::WouldBlock => {
                    return Ok(progress.finish(false));
                }
                RouteNetworkInventoryReceiveOutcome::Loss {
                    cause,
                    terminal_sequences,
                } => {
                    progress.made_progress = true;
                    let outcome = self.observer.note_loss(cause, &terminal_sequences, now);
                    self.apply_observer_outcome(outcome, now, &mut progress)?;
                    self.try_send_dump(now, &mut progress)?;
                    return Ok(progress.finish(false));
                }
                RouteNetworkInventoryReceiveOutcome::Batch(batch) => {
                    let datagrams = batch.datagrams.len();
                    let remaining_bytes = budget.max_bytes.saturating_sub(progress.bytes);
                    if datagrams == 0
                        || datagrams > max_datagrams.get()
                        || batch.bytes > remaining_bytes
                        || batch.bytes > datagrams.saturating_mul(ROUTE_DATAGRAM_CAPACITY)
                    {
                        self.disable();
                        return Err(invalid_transport_batch());
                    }

                    progress.datagrams += datagrams;
                    progress.bytes += batch.bytes;
                    progress.made_progress = true;
                    let outcome = self.observer.consume_batch(batch.datagrams, now);
                    let resync = self.apply_observer_outcome(outcome, now, &mut progress)?;
                    self.try_send_dump(now, &mut progress)?;
                    if resync {
                        return Ok(progress.finish(false));
                    }
                }
            }
        }
    }

    fn drive_due(
        &mut self,
        now: Instant,
    ) -> Result<RouteNetworkInventoryDriveReport, PlatformError> {
        if self.disabled {
            return Ok(DriveProgress::default().finish(false));
        }

        let mut progress = DriveProgress::default();
        let outcome = self.observer.poll(now);
        self.apply_observer_outcome(outcome, now, &mut progress)?;
        self.try_send_dump(now, &mut progress)?;
        Ok(progress.finish(false))
    }

    fn apply_observer_outcome(
        &mut self,
        outcome: ObserverDriveOutcome,
        now: Instant,
        progress: &mut DriveProgress,
    ) -> Result<bool, PlatformError> {
        Ok(match outcome {
            ObserverDriveOutcome::Idle => false,
            ObserverDriveOutcome::Published(epoch) => {
                progress.made_progress = true;
                progress.published_epoch = Some(epoch);
                false
            }
            ObserverDriveOutcome::RequestAddressDump => {
                progress.made_progress = true;
                self.schedule_address_dump(now);
                false
            }
            ObserverDriveOutcome::RequestRouteDump => {
                progress.made_progress = true;
                self.schedule_route_dump(now);
                false
            }
            ObserverDriveOutcome::RequestRuleDump => {
                progress.made_progress = true;
                self.schedule_rule_dump(now);
                false
            }
            ObserverDriveOutcome::DrainDump(fault) => {
                progress.made_progress = true;
                progress.resync_fault.get_or_insert(fault);
                false
            }
            ObserverDriveOutcome::RequestDump(fault) => {
                progress.made_progress = true;
                progress.resync_fault.get_or_insert(fault);
                self.schedule_resync(now);
                true
            }
            ObserverDriveOutcome::PermanentFailure(fault) => {
                self.disable();
                return Err(observer_failure(fault));
            }
        })
    }

    fn schedule_resync(&mut self, now: Instant) {
        if self.disabled {
            return;
        }
        let sequence = self.sequences.allocate();
        self.pending_dump = Some(PendingDumpRequest::Link {
            request: LinkDumpRequest::all(sequence),
            retry_at: now,
        });
    }

    fn schedule_address_dump(&mut self, now: Instant) {
        debug_assert!(!self.disabled);
        debug_assert!(self.pending_dump.is_none());
        let sequence = self.sequences.allocate();
        self.pending_dump = Some(PendingDumpRequest::Address {
            request: AddressDumpRequest::all(sequence),
            retry_at: now,
        });
    }

    fn schedule_route_dump(&mut self, now: Instant) {
        debug_assert!(!self.disabled);
        debug_assert!(self.pending_dump.is_none());
        let sequence = self.sequences.allocate();
        self.pending_dump = Some(PendingDumpRequest::Route {
            request: RouteDumpRequest::all(sequence),
            retry_at: now,
        });
    }

    fn schedule_rule_dump(&mut self, now: Instant) {
        debug_assert!(!self.disabled);
        debug_assert!(self.pending_dump.is_none());
        let sequence = self.sequences.allocate();
        self.pending_dump = Some(PendingDumpRequest::Rule {
            request: RuleDumpRequest::all(sequence),
            retry_at: now,
        });
    }

    fn try_send_dump(
        &mut self,
        now: Instant,
        progress: &mut DriveProgress,
    ) -> Result<(), PlatformError> {
        let Some(pending) = self.pending_dump else {
            return Ok(());
        };
        if now < pending.retry_at() {
            return Ok(());
        }

        let send_result = match pending {
            PendingDumpRequest::Link { request, .. } => self.transport.send_link_dump(&request),
            PendingDumpRequest::Address { request, .. } => {
                self.transport.send_address_dump(&request)
            }
            PendingDumpRequest::Route { request, .. } => self.transport.send_route_dump(&request),
            PendingDumpRequest::Rule { request, .. } => self.transport.send_rule_dump(&request),
        };
        let sent = match send_result {
            Ok(sent) => sent,
            Err(error) => {
                let _ = self.observer.note_dump_request_failure(now);
                self.disable();
                return Err(error);
            }
        };
        progress.made_progress = true;
        match sent {
            NetlinkSendOutcome::Sent => {
                self.pending_dump = None;
                match pending {
                    PendingDumpRequest::Link { request, .. } => {
                        self.observer.begin_link_dump(request.sequence(), now);
                    }
                    PendingDumpRequest::Address { request, .. } => {
                        self.observer.begin_address_dump(request.sequence(), now);
                    }
                    PendingDumpRequest::Route { request, .. } => {
                        self.observer.begin_route_dump(request.sequence(), now);
                    }
                    PendingDumpRequest::Rule { request, .. } => {
                        self.observer.begin_rule_dump(request.sequence(), now);
                    }
                }
            }
            NetlinkSendOutcome::WouldBlock => {
                self.pending_dump =
                    Some(pending.with_retry_at(deadline_after(now, self.dump_send_retry)));
            }
        }
        Ok(())
    }

    fn disable(&mut self) {
        self.invalidate();
    }
}

impl<T> RouteNetworkInventoryDriverInner<T> {
    fn invalidate(&mut self) {
        self.disabled = true;
        self.pending_dump = None;
        self.observer.disable();
    }
}

impl<T> Drop for RouteNetworkInventoryDriverInner<T> {
    fn drop(&mut self) {
        self.invalidate();
    }
}

#[derive(Default)]
struct DriveProgress {
    datagrams: usize,
    bytes: usize,
    made_progress: bool,
    published_epoch: Option<NetworkEpoch>,
    resync_fault: Option<ObserverFault>,
}

impl DriveProgress {
    fn finish(self, budget_exhausted: bool) -> RouteNetworkInventoryDriveReport {
        RouteNetworkInventoryDriveReport {
            disposition: if budget_exhausted {
                RouteNetworkInventoryDriveDisposition::BudgetExhausted
            } else if self.made_progress {
                RouteNetworkInventoryDriveDisposition::Progress
            } else {
                RouteNetworkInventoryDriveDisposition::Idle
            },
            datagrams: self.datagrams,
            bytes: self.bytes,
            published_epoch: self.published_epoch,
            resync_fault: self.resync_fault,
        }
    }
}

fn receive_allowance(
    budget: RouteNetworkInventoryWorkBudget,
    progress: &DriveProgress,
) -> Option<NonZeroUsize> {
    let remaining_datagrams = budget.max_datagrams.saturating_sub(progress.datagrams);
    let remaining_bytes = budget.max_bytes.saturating_sub(progress.bytes);
    let remaining_worst_case_slots = remaining_bytes / ROUTE_DATAGRAM_CAPACITY;
    NonZeroUsize::new(
        remaining_datagrams
            .min(remaining_worst_case_slots)
            .min(RECEIVE_BATCH_SLOTS),
    )
}

fn earliest_deadline(first: Option<Instant>, second: Option<Instant>) -> Option<Instant> {
    match (first, second) {
        (Some(first), Some(second)) => Some(first.min(second)),
        (Some(first), None) => Some(first),
        (None, Some(second)) => Some(second),
        (None, None) => None,
    }
}

fn invalid_transport_batch() -> PlatformError {
    PlatformError::SystemCall {
        operation: "validate route-netlink receive batch",
        source: io::Error::new(
            io::ErrorKind::InvalidData,
            "transport violated the bounded complete-batch contract",
        ),
    }
}

fn observer_failure(fault: ObserverFault) -> PlatformError {
    PlatformError::SystemCall {
        operation: "recover route-netlink inventory observer",
        source: io::Error::new(
            io::ErrorKind::TimedOut,
            format!("route-netlink dump drain failed: {fault:?}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::address_sync::AddressEventPolicy;

    const NLMSG_DONE: u16 = 3;
    const RTM_NEWLINK: u16 = 16;
    const RTM_NEWADDR: u16 = 20;
    const AF_UNSPEC: u8 = 0;
    const AF_INET: u8 = 2;
    const IFLA_IFNAME: u16 = 3;
    const IFA_ADDRESS: u16 = 1;

    #[test]
    fn default_work_budget_is_bounded() {
        let budget = RouteNetworkInventoryWorkBudget::default();

        assert_eq!(budget.max_datagrams(), 16);
        assert_eq!(budget.max_bytes(), 1024 * 1024);
        assert_eq!(
            receive_allowance(budget, &DriveProgress::default())
                .unwrap()
                .get(),
            4
        );
        assert!(RouteNetworkInventoryWorkBudget::new(0, 1024 * 1024).is_none());
        assert!(RouteNetworkInventoryWorkBudget::new(1, ROUTE_DATAGRAM_CAPACITY - 1).is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn one_shot_timeout_bounds_fail_before_socket_open() {
        for timeout in [Duration::ZERO, Duration::from_secs(31)] {
            let error = collect_network_inventory_once(timeout)
                .expect_err("invalid bounds must fail before opening route netlink");
            assert!(matches!(
                error,
                PlatformError::SystemCall {
                    operation: "validate initial route-netlink inventory timeout",
                    source,
                } if source.kind() == io::ErrorKind::InvalidInput
            ));
        }
    }

    #[test]
    fn sender_multicast_groups_are_authoritative_for_datagram_origin() {
        assert_eq!(
            inventory_datagram_origin(0),
            InventoryDatagramOrigin::Response
        );
        assert_eq!(
            inventory_datagram_origin(0x40),
            InventoryDatagramOrigin::Notification
        );
    }

    #[test]
    fn initial_dump_is_sent_once_and_rule_completion_publishes_source() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        let link = link(1);
        let address = address(2);
        let expected_bytes = link.len() + address.len() + 4 * 16;
        fake.receives.push_back(Ok(batch([link, done(1)])));
        fake.receives.push_back(Ok(batch([address, done(2)])));
        fake.receives.push_back(Ok(batch([done(3)])));
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        let (mut driver, source) = start(fake, now);

        assert!(source.snapshot().is_none());
        assert_eq!(driver.transport.sent_requests, [TestDumpRequest::Link(1)]);
        assert_eq!(driver.transport.send_saw_subscription, [true]);

        let before_rule_done = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("drive through route completion");

        assert_eq!(
            before_rule_done.disposition(),
            RouteNetworkInventoryDriveDisposition::Progress
        );
        assert_eq!(before_rule_done.datagrams(), 5);
        assert_eq!(before_rule_done.bytes(), expected_bytes - 16);
        assert_eq!(before_rule_done.published_epoch(), None);
        assert_eq!(before_rule_done.resync_fault(), None);
        assert_eq!(driver.transport.receive_limits[0], 4);
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );
        assert!(source.snapshot().is_none());

        driver.transport.receives.push_back(Ok(batch([done(4)])));
        let published = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("complete rule phase");

        assert_eq!(published.datagrams(), 1);
        assert_eq!(published.bytes(), 16);
        assert_eq!(published.published_epoch(), Some(NetworkEpoch::INITIAL));
        assert_eq!(published.resync_fault(), None);
        let snapshot = source.snapshot().expect("combined driver snapshot");
        assert_eq!(snapshot.links().len(), 1);
        assert_eq!(snapshot.links()[0].name().as_bytes(), b"wlan0");
        assert_eq!(snapshot.addresses().len(), 1);
        assert!(snapshot.routes().is_empty());
        assert!(snapshot.rules().is_empty());
    }

    #[test]
    fn followup_send_would_block_retries_each_sequence_and_retains_prior_facts() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        fake.sends.push_back(Ok(NetlinkSendOutcome::WouldBlock));
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        fake.sends.push_back(Ok(NetlinkSendOutcome::WouldBlock));
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        fake.sends.push_back(Ok(NetlinkSendOutcome::WouldBlock));
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        fake.receives.push_back(Ok(batch([link(1), done(1)])));
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        let (mut driver, source) = start(fake, now);

        let first = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("complete link phase and defer address send");
        let retry_at = now + DEFAULT_DUMP_SEND_RETRY;
        assert_eq!(first.published_epoch(), None);
        assert_eq!(first.resync_fault(), None);
        assert!(source.snapshot().is_none());
        assert_eq!(driver.next_deadline(), Some(retry_at));
        assert_eq!(
            driver.transport.sent_requests,
            [TestDumpRequest::Link(1), TestDumpRequest::Address(2)]
        );

        driver.drive_due(retry_at).expect("retry address send");
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Address(2),
            ]
        );

        driver
            .transport
            .receives
            .push_back(Ok(batch([address(2), done(2)])));
        driver
            .transport
            .receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        let route_pending = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), retry_at)
            .expect("complete address phase and defer route send");
        let route_retry_at = retry_at + DEFAULT_DUMP_SEND_RETRY;
        assert_eq!(route_pending.published_epoch(), None);
        assert_eq!(driver.next_deadline(), Some(route_retry_at));
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
            ]
        );
        assert!(source.snapshot().is_none());

        driver.drive_due(route_retry_at).expect("retry route send");
        driver.transport.receives.push_back(Ok(batch([done(3)])));
        driver
            .transport
            .receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        let rule_pending = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), route_retry_at)
            .expect("complete route phase and defer rule send");
        let rule_retry_at = route_retry_at + DEFAULT_DUMP_SEND_RETRY;
        assert_eq!(rule_pending.published_epoch(), None);
        assert_eq!(driver.next_deadline(), Some(rule_retry_at));
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );
        assert!(source.snapshot().is_none());

        driver.drive_due(rule_retry_at).expect("retry rule send");
        driver.transport.receives.push_back(Ok(batch([done(4)])));
        let published = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), rule_retry_at)
            .expect("complete rule phase");
        assert_eq!(published.published_epoch(), Some(NetworkEpoch::INITIAL));
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
                TestDumpRequest::Rule(4),
            ]
        );
        let snapshot = source.snapshot().expect("retained link facts");
        assert_eq!(snapshot.links().len(), 1);
        assert_eq!(snapshot.links()[0].name().as_bytes(), b"wlan0");
        assert_eq!(snapshot.addresses().len(), 1);
    }

    #[test]
    fn fault_while_address_send_is_pending_restarts_from_fresh_link_sequence() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        fake.sends.push_back(Ok(NetlinkSendOutcome::WouldBlock));
        fake.receives.push_back(Ok(batch([done(1)])));
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::Loss {
                cause: ObserverLoss::Enobufs,
                terminal_sequences: Box::default(),
            }));
        let (mut driver, source) = start(fake, now);

        let report = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("loss replaces pending address request");

        assert!(source.snapshot().is_none());
        assert_eq!(
            report.resync_fault(),
            Some(ObserverFault::ReceiveLoss(ObserverLoss::Enobufs))
        );
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Link(3),
            ]
        );
        assert_eq!(driver.next_deadline(), Some(now + test_dump_timeout()));
    }

    #[test]
    fn receive_loss_stales_source_and_starts_one_compensating_link_dump() {
        for loss in [
            ObserverLoss::Enobufs,
            ObserverLoss::Truncated,
            ObserverLoss::UnexpectedSender,
        ] {
            let now = Instant::now();
            let mut fake = FakeTransport::default();
            fake.receives.push_back(Ok(batch([done(1)])));
            fake.receives.push_back(Ok(batch([done(2)])));
            fake.receives.push_back(Ok(batch([done(3)])));
            fake.receives.push_back(Ok(batch([done(4)])));
            fake.receives
                .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
            let (mut driver, source) = start(fake, now);
            driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .expect("publish initial dump");
            assert!(source.snapshot().is_some());

            driver
                .transport
                .receives
                .push_back(Ok(RouteNetworkInventoryReceiveOutcome::Loss {
                    cause: loss,
                    terminal_sequences: Box::default(),
                }));
            let idle_loss = driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .expect("start a compensating link dump");

            assert!(source.snapshot().is_none());
            assert_eq!(
                driver.transport.sent_requests,
                [
                    TestDumpRequest::Link(1),
                    TestDumpRequest::Address(2),
                    TestDumpRequest::Route(3),
                    TestDumpRequest::Rule(4),
                    TestDumpRequest::Link(5),
                ]
            );
            assert_eq!(
                idle_loss.resync_fault(),
                Some(ObserverFault::ReceiveLoss(loss))
            );
        }
    }

    #[test]
    fn active_phase_loss_drains_matching_done_before_restarting_from_link() {
        for active_sequence in 1..=4 {
            let now = Instant::now();
            let mut fake = FakeTransport::default();
            for completed_sequence in 1..active_sequence {
                fake.receives
                    .push_back(Ok(batch([done(completed_sequence)])));
            }
            fake.receives
                .push_back(Ok(RouteNetworkInventoryReceiveOutcome::Loss {
                    cause: ObserverLoss::Enobufs,
                    terminal_sequences: Box::default(),
                }));
            let (mut driver, source) = start(fake, now);

            let faulted = driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .expect("taint the active dump");
            let mut expected = vec![TestDumpRequest::Link(1)];
            if active_sequence >= 2 {
                expected.push(TestDumpRequest::Address(2));
            }
            if active_sequence >= 3 {
                expected.push(TestDumpRequest::Route(3));
            }
            if active_sequence >= 4 {
                expected.push(TestDumpRequest::Rule(4));
            }
            assert!(source.snapshot().is_none());
            assert_eq!(
                faulted.resync_fault(),
                Some(ObserverFault::ReceiveLoss(ObserverLoss::Enobufs))
            );
            assert_eq!(
                driver.transport.sent_requests, expected,
                "loss during sequence {active_sequence} must not overlap the active dump"
            );

            driver.transport.receives.push_back(Ok(batch([done(99)])));
            driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .expect("ignore a foreign terminal while draining");
            assert_eq!(
                driver.transport.sent_requests, expected,
                "only the matching terminal may end the drain"
            );

            driver
                .transport
                .receives
                .push_back(Ok(batch([done(active_sequence)])));
            let drained = driver
                .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
                .expect("drain the matching terminal and restart from link");
            expected.push(TestDumpRequest::Link(active_sequence + 1));
            assert_eq!(
                drained.resync_fault(),
                Some(ObserverFault::ReceiveLoss(ObserverLoss::Enobufs))
            );
            assert_eq!(driver.transport.sent_requests, expected);
        }
    }

    #[test]
    fn lossy_batch_terminal_hint_restarts_without_waiting_for_a_drain_timeout() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::Loss {
                cause: ObserverLoss::Truncated,
                terminal_sequences: vec![1].into_boxed_slice(),
            }));
        let (mut driver, source) = start(fake, now);

        let report = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("matching terminal evidence permits an immediate safe resync");

        assert!(source.snapshot().is_none());
        assert_eq!(
            report.resync_fault(),
            Some(ObserverFault::ReceiveLoss(ObserverLoss::Truncated))
        );
        assert_eq!(
            driver.transport.sent_requests,
            [TestDumpRequest::Link(1), TestDumpRequest::Link(2)]
        );
    }

    #[test]
    fn foreign_sequence_fault_drains_matching_active_dump_before_resync() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(99)])));
        let (mut driver, source) = start(fake, now);

        let report = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("drive foreign sequence");

        assert!(source.snapshot().is_none());
        assert_eq!(
            driver.transport.sent_requests,
            [TestDumpRequest::Link(1)],
            "a foreign response must not overlap the active link dump"
        );
        assert_eq!(
            report.resync_fault(),
            Some(ObserverFault::ForeignSequence {
                expected: Some(1),
                actual: Some(99),
            })
        );

        driver.transport.receives.push_back(Ok(batch([done(1)])));
        let drained = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("drain the matching link terminal");
        assert_eq!(
            drained.resync_fault(),
            Some(ObserverFault::ForeignSequence {
                expected: Some(1),
                actual: Some(99),
            })
        );
        assert_eq!(
            driver.transport.sent_requests,
            [TestDumpRequest::Link(1), TestDumpRequest::Link(2)]
        );
    }

    #[test]
    fn drain_timeout_degrades_observation_without_overlapping_the_active_dump() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(99)])));
        let (mut driver, source) = start(fake, now);

        driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("enter dirty drain after foreign terminal");
        let error = driver
            .drive_due(now + test_dump_timeout())
            .expect_err("missing owned terminal permanently degrades this socket owner");

        assert!(matches!(error, PlatformError::SystemCall { .. }));
        assert!(source.snapshot().is_none());
        assert_eq!(driver.transport.sent_requests, [TestDumpRequest::Link(1)]);
        assert_eq!(driver.next_deadline(), None);
    }

    #[test]
    fn dump_send_would_block_retries_only_when_due_with_same_sequence() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.sends.push_back(Ok(NetlinkSendOutcome::WouldBlock));
        fake.sends.push_back(Ok(NetlinkSendOutcome::Sent));
        let (mut driver, source) = start(fake, now);
        let retry_at = now + DEFAULT_DUMP_SEND_RETRY;

        assert_eq!(driver.transport.sent_requests, [TestDumpRequest::Link(1)]);
        assert_eq!(driver.next_deadline(), Some(retry_at));
        assert_eq!(
            driver
                .drive_due(now)
                .expect("idempotent early due drive")
                .disposition(),
            RouteNetworkInventoryDriveDisposition::Idle
        );
        assert_eq!(driver.transport.sent_requests, [TestDumpRequest::Link(1)]);

        driver.drive_due(retry_at).expect("retry dump send");
        driver
            .drive_due(retry_at)
            .expect("same instant cannot resend active dump");
        assert_eq!(
            driver.transport.sent_requests,
            [TestDumpRequest::Link(1), TestDumpRequest::Link(1)]
        );
        assert!(source.snapshot().is_none());
        assert_eq!(driver.next_deadline(), Some(retry_at + test_dump_timeout()));
    }

    #[test]
    fn byte_budget_is_hard_and_never_splits_a_received_batch() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(1)])));
        fake.receives.push_back(Ok(batch([done(2)])));
        fake.receives.push_back(Ok(batch([done(3)])));
        fake.receives.push_back(Ok(batch([done(4)])));
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        let large = decoded_batch(
            [unknown(0), unknown(0), unknown(0), unknown(0)],
            4 * ROUTE_DATAGRAM_CAPACITY,
        );
        fake.receives.push_back(Ok(large));
        let (mut driver, _source) = start(fake, now);
        driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("publish initial dump");
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );

        let report = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("consume one maximum-size batch");

        assert_eq!(
            report.disposition(),
            RouteNetworkInventoryDriveDisposition::BudgetExhausted
        );
        assert_eq!(report.datagrams(), 4);
        assert_eq!(report.bytes(), DEFAULT_READY_BYTE_BUDGET);
        assert_eq!(driver.transport.receive_limits.last(), Some(&4));
    }

    #[test]
    fn explicit_disable_and_drop_immediately_stale_all_source_clones() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(1)])));
        fake.receives.push_back(Ok(batch([done(2)])));
        fake.receives.push_back(Ok(batch([done(3)])));
        fake.receives.push_back(Ok(batch([done(4)])));
        let (mut driver, source) = start(fake, now);
        driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("publish initial dump");
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );
        let clone = source.clone();
        assert!(source.snapshot().is_some());

        driver.disable();
        driver.disable();
        assert!(source.snapshot().is_none());
        assert!(clone.snapshot().is_none());

        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(1)])));
        fake.receives.push_back(Ok(batch([done(2)])));
        fake.receives.push_back(Ok(batch([done(3)])));
        fake.receives.push_back(Ok(batch([done(4)])));
        let (mut dropped, dropped_source) = start(fake, now);
        dropped
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("publish source before drop");
        assert_eq!(
            dropped.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );
        assert!(dropped_source.snapshot().is_some());
        drop(dropped);
        assert!(dropped_source.snapshot().is_none());
    }

    #[test]
    fn permanent_transport_error_is_returned_after_source_is_staled() {
        let now = Instant::now();
        let mut fake = FakeTransport::default();
        fake.receives.push_back(Ok(batch([done(1)])));
        fake.receives.push_back(Ok(batch([address(2)])));
        fake.receives.push_back(Ok(batch([done(2)])));
        fake.receives.push_back(Ok(batch([done(3)])));
        fake.receives.push_back(Ok(batch([done(4)])));
        fake.receives
            .push_back(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock));
        fake.receives
            .push_back(Err(PlatformError::UnsupportedPlatform(
                "scripted permanent route-netlink failure",
            )));
        let (mut driver, source) = start(fake, now);
        driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect("publish initial four-phase dump");
        assert!(source.snapshot().is_some());
        assert_eq!(
            driver.transport.sent_requests,
            [
                TestDumpRequest::Link(1),
                TestDumpRequest::Address(2),
                TestDumpRequest::Route(3),
                TestDumpRequest::Rule(4),
            ]
        );

        let error = driver
            .drive_ready(RouteNetworkInventoryWorkBudget::default(), now)
            .expect_err("transport failure is fatal to observation");

        assert!(matches!(error, PlatformError::UnsupportedPlatform(_)));
        assert!(source.snapshot().is_none());
        assert_eq!(driver.next_deadline(), None);
    }

    fn start(
        fake: FakeTransport,
        now: Instant,
    ) -> (
        RouteNetworkInventoryDriverInner<FakeTransport>,
        NetworkInventorySource,
    ) {
        RouteNetworkInventoryDriverInner::start(
            fake,
            test_observer_config(),
            DEFAULT_DUMP_SEND_RETRY,
            now,
        )
        .expect("start fake route inventory driver")
    }

    fn test_observer_config() -> ObserverConfig {
        ObserverConfig::new(
            8,
            MAX_RACE_QUEUE_BYTES,
            test_dump_timeout(),
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .expect("valid test observer configuration")
    }

    const fn test_dump_timeout() -> Duration {
        Duration::from_millis(100)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestDumpRequest {
        Link(u32),
        Address(u32),
        Route(u32),
        Rule(u32),
    }

    struct FakeTransport {
        subscribed: bool,
        sends: VecDeque<Result<NetlinkSendOutcome, PlatformError>>,
        receives: VecDeque<Result<RouteNetworkInventoryReceiveOutcome, PlatformError>>,
        sent_requests: Vec<TestDumpRequest>,
        send_saw_subscription: Vec<bool>,
        receive_limits: Vec<usize>,
    }

    impl Default for FakeTransport {
        fn default() -> Self {
            Self {
                subscribed: true,
                sends: VecDeque::new(),
                receives: VecDeque::new(),
                sent_requests: Vec::new(),
                send_saw_subscription: Vec::new(),
                receive_limits: Vec::new(),
            }
        }
    }

    impl RouteNetworkInventoryTransport for FakeTransport {
        fn send_link_dump(
            &mut self,
            request: &LinkDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            self.sent_requests
                .push(TestDumpRequest::Link(request.sequence().get()));
            self.send_saw_subscription.push(self.subscribed);
            self.sends
                .pop_front()
                .unwrap_or(Ok(NetlinkSendOutcome::Sent))
        }

        fn send_address_dump(
            &mut self,
            request: &AddressDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            self.sent_requests
                .push(TestDumpRequest::Address(request.sequence().get()));
            self.send_saw_subscription.push(self.subscribed);
            self.sends
                .pop_front()
                .unwrap_or(Ok(NetlinkSendOutcome::Sent))
        }

        fn send_route_dump(
            &mut self,
            request: &RouteDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            self.sent_requests
                .push(TestDumpRequest::Route(request.sequence().get()));
            self.send_saw_subscription.push(self.subscribed);
            self.sends
                .pop_front()
                .unwrap_or(Ok(NetlinkSendOutcome::Sent))
        }

        fn send_rule_dump(
            &mut self,
            request: &RuleDumpRequest,
        ) -> Result<NetlinkSendOutcome, PlatformError> {
            self.sent_requests
                .push(TestDumpRequest::Rule(request.sequence().get()));
            self.send_saw_subscription.push(self.subscribed);
            self.sends
                .pop_front()
                .unwrap_or(Ok(NetlinkSendOutcome::Sent))
        }

        fn receive_decoded_batch(
            &mut self,
            max_datagrams: NonZeroUsize,
        ) -> Result<RouteNetworkInventoryReceiveOutcome, PlatformError> {
            self.receive_limits.push(max_datagrams.get());
            self.receives
                .pop_front()
                .unwrap_or(Ok(RouteNetworkInventoryReceiveOutcome::WouldBlock))
        }
    }

    fn batch<const N: usize>(datagrams: [Vec<u8>; N]) -> RouteNetworkInventoryReceiveOutcome {
        let bytes = datagrams.iter().map(Vec::len).sum();
        decoded_batch(datagrams, bytes)
    }

    fn decoded_batch<const N: usize>(
        datagrams: [Vec<u8>; N],
        bytes: usize,
    ) -> RouteNetworkInventoryReceiveOutcome {
        let link_decoder = RtnetlinkLinkEventDecoder::new();
        let address_decoder = RtnetlinkAddressEventDecoder::new(AddressEventPolicy::new(true));
        let route_decoder = RtnetlinkRouteEventDecoder::new(true);
        let rule_decoder = RtnetlinkRuleEventDecoder::new(true);
        RouteNetworkInventoryReceiveOutcome::Batch(DecodedRouteNetworkInventoryBatch {
            datagrams: datagrams
                .into_iter()
                .map(|datagram| {
                    let origin = if datagram
                        .get(8..12)
                        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                        .is_some_and(|sequence| u32::from_ne_bytes(sequence) == 0)
                    {
                        InventoryDatagramOrigin::Notification
                    } else {
                        InventoryDatagramOrigin::Response
                    };
                    InventoryDatagramObservation::from_decoded(
                        link_decoder.decode_datagram(&datagram),
                        address_decoder.decode_datagram(&datagram),
                        route_decoder.decode_datagram(&datagram),
                        rule_decoder.decode_datagram(&datagram),
                        origin,
                        datagram.len(),
                        terminal_sequences(&datagram),
                    )
                })
                .collect(),
            bytes,
        })
    }

    fn done(sequence: u32) -> Vec<u8> {
        netlink_message(NLMSG_DONE, sequence, &[])
    }

    fn unknown(sequence: u32) -> Vec<u8> {
        netlink_message(99, sequence, &[])
    }

    fn address(sequence: u32) -> Vec<u8> {
        let address = Ipv4Addr::new(192, 0, 2, 9).octets();
        let mut payload = vec![AF_INET, 24, 0, 0];
        payload.extend(7_u32.to_ne_bytes());
        payload.extend(8_u16.to_ne_bytes());
        payload.extend(IFA_ADDRESS.to_ne_bytes());
        payload.extend(address);
        netlink_message(RTM_NEWADDR, sequence, &payload)
    }

    fn link(sequence: u32) -> Vec<u8> {
        let mut payload = vec![AF_UNSPEC, 0];
        payload.extend(1_u16.to_ne_bytes());
        payload.extend(7_i32.to_ne_bytes());
        payload.extend(1_u32.to_ne_bytes());
        payload.extend(u32::MAX.to_ne_bytes());
        append_attribute(&mut payload, IFLA_IFNAME, b"wlan0\0");
        netlink_message(RTM_NEWLINK, sequence, &payload)
    }

    fn append_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
        let length = 4 + value.len();
        message.extend((length as u16).to_ne_bytes());
        message.extend(attribute_type.to_ne_bytes());
        message.extend(value);
        message.resize((message.len() + 3) & !3, 0);
    }

    fn netlink_message(message_type: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let length = 16 + payload.len();
        let mut message = Vec::with_capacity(length);
        message.extend((length as u32).to_ne_bytes());
        message.extend(message_type.to_ne_bytes());
        message.extend(0_u16.to_ne_bytes());
        message.extend(sequence.to_ne_bytes());
        message.extend(0_u32.to_ne_bytes());
        message.extend(payload);
        message
    }
}
