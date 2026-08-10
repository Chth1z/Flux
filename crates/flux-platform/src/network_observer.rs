use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use flux_core::{
    InterfaceAddressRecord, InterfaceIndex, InterfaceLinkRecord, NetworkEpoch, NetworkInventory,
    NetworkInventoryError, NetworkInventoryTracker, NetworkRouteRecord, NetworkRuleRecord,
};

use crate::address_sync::{
    AddressDatagram, AddressEventDecodeError, AddressEventKind, InterfaceAddressEvent,
};
use crate::netlink::NetlinkMessageHeader;
use crate::netlink::link::{InterfaceLinkEvent, LinkDatagram, LinkEventDecodeError};
use crate::netlink::route::{InterfaceRouteEvent, RouteDatagram, RouteEventDecodeError};
use crate::netlink::rule::{NetworkRuleEvent, RuleDatagram, RuleEventDecodeError};

pub(crate) mod driver;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use driver::collect_network_inventory_once;

/// A cloneable view of the latest complete network inventory.
///
/// Clones share immutable snapshots. `snapshot` returns `None` before the
/// first loss-free link/address/route/rule transaction and whenever loss or an
/// in-progress resynchronization makes the retained inventory stale.
#[derive(Clone, Debug)]
pub struct NetworkInventorySource {
    shared: Arc<SharedInventory>,
}

impl NetworkInventorySource {
    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<NetworkInventory>> {
        read_unpoisoned(&self.shared.state).current.clone()
    }

    pub(crate) fn begin_explicit_refresh(&self) -> Option<u64> {
        let mut state = write_unpoisoned(&self.shared.state);
        state.refresh_revision = state.refresh_revision.checked_add(1)?;
        state.current = None;
        Some(state.refresh_revision)
    }

    fn refresh_revision(&self) -> u64 {
        read_unpoisoned(&self.shared.state).refresh_revision
    }
}

#[derive(Debug, Default)]
struct SharedInventory {
    state: RwLock<SharedInventoryState>,
}

#[derive(Debug, Default)]
struct SharedInventoryState {
    current: Option<Arc<NetworkInventory>>,
    refresh_revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryDatagramOrigin {
    Response,
    Notification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryDecodeErrorKind {
    Link(LinkEventDecodeError),
    Address(AddressEventDecodeError),
    Route(RouteEventDecodeError),
    Rule(RuleEventDecodeError),
    MetadataMismatch,
    NotificationCompletion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InventoryDecodeError {
    kind: InventoryDecodeErrorKind,
}

impl InventoryDecodeError {
    const fn new(kind: InventoryDecodeErrorKind) -> Self {
        Self { kind }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InventoryDatagramObservation {
    decoded: Result<InventoryDatagram, InventoryDecodeError>,
    terminal_sequences: Box<[u32]>,
}

impl InventoryDatagramObservation {
    pub(crate) fn from_decoded(
        link: Result<LinkDatagram, LinkEventDecodeError>,
        address: Result<AddressDatagram, AddressEventDecodeError>,
        route: Result<RouteDatagram, RouteEventDecodeError>,
        rule: Result<RuleDatagram, RuleEventDecodeError>,
        origin: InventoryDatagramOrigin,
        wire_bytes: usize,
        terminal_sequences: Box<[u32]>,
    ) -> Self {
        Self {
            decoded: InventoryDatagram::from_decoded(
                link, address, route, rule, origin, wire_bytes,
            ),
            terminal_sequences: if origin == InventoryDatagramOrigin::Response {
                terminal_sequences
            } else {
                Box::default()
            },
        }
    }

    fn terminates_sequence(&self, expected_sequence: u32) -> bool {
        self.terminal_sequences.contains(&expected_sequence)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InventoryDatagram {
    origin: InventoryDatagramOrigin,
    sequence: Option<u32>,
    completion: Option<NetlinkMessageHeader>,
    link_events: Vec<InterfaceLinkEvent>,
    address_events: Vec<InterfaceAddressEvent>,
    route_events: Vec<InterfaceRouteEvent>,
    rule_events: Vec<NetworkRuleEvent>,
    wire_bytes: usize,
}

impl InventoryDatagram {
    pub(crate) fn from_decoded(
        link: Result<LinkDatagram, LinkEventDecodeError>,
        address: Result<AddressDatagram, AddressEventDecodeError>,
        route: Result<RouteDatagram, RouteEventDecodeError>,
        rule: Result<RuleDatagram, RuleEventDecodeError>,
        origin: InventoryDatagramOrigin,
        wire_bytes: usize,
    ) -> Result<Self, InventoryDecodeError> {
        let link =
            link.map_err(|error| InventoryDecodeError::new(InventoryDecodeErrorKind::Link(error)))?;
        let address = address
            .map_err(|error| InventoryDecodeError::new(InventoryDecodeErrorKind::Address(error)))?;
        let route = route
            .map_err(|error| InventoryDecodeError::new(InventoryDecodeErrorKind::Route(error)))?;
        let rule =
            rule.map_err(|error| InventoryDecodeError::new(InventoryDecodeErrorKind::Rule(error)))?;
        if link.sequence() != address.sequence()
            || link.sequence() != route.sequence()
            || link.sequence() != rule.sequence()
            || link.completion() != address.completion()
            || link.completion() != route.completion()
            || link.completion() != rule.completion()
        {
            return Err(InventoryDecodeError::new(
                InventoryDecodeErrorKind::MetadataMismatch,
            ));
        }
        if origin == InventoryDatagramOrigin::Notification && link.completion().is_some() {
            return Err(InventoryDecodeError::new(
                InventoryDecodeErrorKind::NotificationCompletion,
            ));
        }
        Ok(Self {
            origin,
            sequence: link.sequence(),
            completion: link.completion(),
            link_events: link.events().to_vec(),
            address_events: address.events().to_vec(),
            route_events: route.events().to_vec(),
            rule_events: rule.events().to_vec(),
            wire_bytes,
        })
    }

    #[must_use]
    pub(crate) const fn origin(&self) -> InventoryDatagramOrigin {
        self.origin
    }

    #[must_use]
    pub(crate) const fn sequence(&self) -> Option<u32> {
        self.sequence
    }

    #[must_use]
    pub(crate) const fn completion(&self) -> Option<NetlinkMessageHeader> {
        self.completion
    }

    #[must_use]
    pub(crate) fn link_events(&self) -> &[InterfaceLinkEvent] {
        &self.link_events
    }

    #[must_use]
    pub(crate) fn address_events(&self) -> &[InterfaceAddressEvent] {
        &self.address_events
    }

    #[must_use]
    pub(crate) fn route_events(&self) -> &[InterfaceRouteEvent] {
        &self.route_events
    }

    #[must_use]
    pub(crate) fn rule_events(&self) -> &[NetworkRuleEvent] {
        &self.rule_events
    }

    #[must_use]
    pub(crate) const fn wire_bytes(&self) -> usize {
        self.wire_bytes
    }
}

pub(crate) const MAX_RACE_QUEUE_CAPACITY: usize = 4_096;
pub(crate) const MAX_RACE_QUEUE_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverConfig {
    race_queue_capacity: usize,
    race_queue_byte_capacity: usize,
    dump_timeout: Duration,
    quiet_debounce: Duration,
    maximum_debounce: Duration,
}

impl ObserverConfig {
    pub(crate) fn new(
        race_queue_capacity: usize,
        race_queue_byte_capacity: usize,
        dump_timeout: Duration,
        quiet_debounce: Duration,
        maximum_debounce: Duration,
    ) -> Result<Self, ObserverConfigError> {
        if !(1..=MAX_RACE_QUEUE_CAPACITY).contains(&race_queue_capacity) {
            return Err(ObserverConfigError::InvalidRaceQueueCapacity {
                actual: race_queue_capacity,
            });
        }
        if !(1..=MAX_RACE_QUEUE_BYTES).contains(&race_queue_byte_capacity) {
            return Err(ObserverConfigError::InvalidRaceQueueByteCapacity {
                actual: race_queue_byte_capacity,
            });
        }
        if dump_timeout.is_zero() {
            return Err(ObserverConfigError::ZeroDumpTimeout);
        }
        if quiet_debounce.is_zero() {
            return Err(ObserverConfigError::ZeroQuietDebounce);
        }
        if maximum_debounce.is_zero() {
            return Err(ObserverConfigError::ZeroMaximumDebounce);
        }
        if quiet_debounce > maximum_debounce {
            return Err(ObserverConfigError::QuietExceedsMaximum);
        }
        Ok(Self {
            race_queue_capacity,
            race_queue_byte_capacity,
            dump_timeout,
            quiet_debounce,
            maximum_debounce,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverConfigError {
    InvalidRaceQueueCapacity { actual: usize },
    InvalidRaceQueueByteCapacity { actual: usize },
    ZeroDumpTimeout,
    ZeroQuietDebounce,
    ZeroMaximumDebounce,
    QuietExceedsMaximum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverFault {
    MissingSequence,
    Decode(InventoryDecodeError),
    ForeignSequence {
        expected: Option<u32>,
        actual: Option<u32>,
    },
    RaceQueueOverflow {
        capacity: usize,
    },
    RaceQueueByteOverflow {
        capacity: usize,
    },
    ConflictingLinkDumpFact {
        interface_index: InterfaceIndex,
    },
    ConflictingDumpFact {
        first: InterfaceAddressRecord,
        first_kind: AddressEventKind,
        second: InterfaceAddressRecord,
        second_kind: AddressEventKind,
    },
    UnexpectedDumpFact {
        phase: ObserverDumpPhase,
        fact: InventoryFactClass,
    },
    UnexpectedRouteRemovalInDump,
    UnexpectedRuleRemovalInDump,
    RouteNotificationAfterDumpStarted,
    RuleNotificationAfterDumpStarted,
    ReceiveLoss(ObserverLoss),
    DumpRequestFailed,
    DumpTimeout,
    DumpDrainTimeout,
    DumpMessageAfterCompletion,
    Inventory(NetworkInventoryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverDumpPhase {
    Link,
    Address,
    Route,
    Rule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InventoryFactClass {
    Link,
    Address,
    Route,
    Rule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverDriveOutcome {
    Idle,
    Superseded,
    Published(NetworkEpoch),
    RequestAddressDump,
    RequestRouteDump,
    RequestRuleDump,
    DrainDump(ObserverFault),
    RequestDump(ObserverFault),
    PermanentFailure(ObserverFault),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverLoss {
    Enobufs,
    Truncated,
    UnexpectedSender,
}

#[derive(Debug)]
pub(crate) struct NetworkInventoryObserver {
    source: NetworkInventorySource,
    config: ObserverConfig,
    tracker: NetworkInventoryTracker,
    dump: Option<DumpState>,
    pending: Option<PendingState>,
    synchronized: bool,
    active_refresh_revision: Option<u64>,
    synchronized_refresh_revision: Option<u64>,
}

impl NetworkInventoryObserver {
    pub(crate) fn new(config: ObserverConfig) -> Self {
        Self {
            source: NetworkInventorySource {
                shared: Arc::new(SharedInventory::default()),
            },
            config,
            tracker: NetworkInventoryTracker::new(),
            dump: None,
            pending: None,
            synchronized: false,
            active_refresh_revision: None,
            synchronized_refresh_revision: None,
        }
    }

    pub(crate) fn source(&self) -> NetworkInventorySource {
        self.source.clone()
    }

    pub(crate) const fn refresh_in_progress(&self) -> bool {
        self.dump.is_some()
    }

    pub(crate) fn current_refresh_revision_is_satisfied(&self) -> bool {
        let current_revision = self.source.refresh_revision();
        self.synchronized_refresh_revision == Some(current_revision)
            || (self
                .dump
                .as_ref()
                .is_some_and(|dump| !matches!(dump, DumpState::Draining(_)))
                && self.active_refresh_revision == Some(current_revision))
    }

    pub(crate) fn begin_refresh(&mut self) {
        debug_assert!(self.dump.is_none());
        self.mark_unsynchronized();
    }

    pub(crate) fn begin_link_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        self.mark_unsynchronized();
        self.active_refresh_revision = Some(self.source.refresh_revision());
        self.dump = Some(DumpState::Link(LinkDumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            links: BTreeMap::new(),
            seen: BTreeMap::new(),
            raced: RacedEvents::default(),
        }));
    }

    pub(crate) fn begin_address_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        let Some(DumpState::AwaitingAddress(waiting)) = self.dump.take() else {
            panic!("address dump requires a completed link dump");
        };
        self.dump = Some(DumpState::Address(AddressDumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            links: waiting.links,
            addresses: BTreeMap::new(),
            seen: BTreeMap::new(),
            raced: waiting.raced,
            publish_on_completion: false,
        }));
    }

    pub(crate) fn begin_route_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        let Some(DumpState::AwaitingRoute(waiting)) = self.dump.take() else {
            panic!("route dump requires a completed address dump");
        };
        self.dump = Some(DumpState::Route(RouteDumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            links: waiting.links,
            addresses: waiting.addresses,
            routes: Vec::new(),
            raced: waiting.raced,
        }));
    }

    pub(crate) fn begin_rule_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        let Some(DumpState::AwaitingRule(waiting)) = self.dump.take() else {
            panic!("rule dump requires a completed route dump");
        };
        self.dump = Some(DumpState::Rule(RuleDumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            links: waiting.links,
            addresses: waiting.addresses,
            routes: waiting.routes,
            rules: Vec::new(),
            raced: waiting.raced,
        }));
    }

    #[cfg(test)]
    pub(crate) fn begin_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        self.mark_unsynchronized();
        self.active_refresh_revision = Some(self.source.refresh_revision());
        self.dump = Some(DumpState::Address(AddressDumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            links: BTreeMap::new(),
            addresses: BTreeMap::new(),
            seen: BTreeMap::new(),
            raced: RacedEvents::default(),
            publish_on_completion: true,
        }));
    }

    #[cfg(test)]
    pub(crate) fn consume(
        &mut self,
        datagram: InventoryDatagramObservation,
        now: Instant,
    ) -> ObserverDriveOutcome {
        self.consume_batch(std::iter::once(datagram), now)
    }

    /// Ingests one complete socket receive batch as an atomic publication unit.
    ///
    /// A later fault invalidates every earlier datagram in the batch. LINK
    /// completion advances to the ADDRESS request only after the whole batch is
    /// valid, and RULE completion publishes only after the same check.
    pub(crate) fn consume_batch(
        &mut self,
        datagrams: impl IntoIterator<Item = InventoryDatagramObservation>,
        now: Instant,
    ) -> ObserverDriveOutcome {
        let mut deferred_outcome = None;
        if self.dump_deadline().is_some_and(|deadline| now >= deadline) {
            let outcome = self.handle_dump_deadline(now);
            if matches!(outcome, ObserverDriveOutcome::DrainDump(_)) {
                deferred_outcome = Some(outcome);
            } else {
                return outcome;
            }
        }

        let mut dump_completed = false;
        for datagram in datagrams {
            if let Err(fault) = self.ingest_datagram(datagram, now, &mut dump_completed) {
                let outcome = self.invalidate(fault, now, dump_completed);
                if matches!(outcome, ObserverDriveOutcome::DrainDump(_)) {
                    deferred_outcome = Some(outcome);
                    dump_completed = false;
                    continue;
                }
                return outcome;
            }
        }
        if dump_completed {
            return self.complete_dump_phase(now);
        }
        deferred_outcome.unwrap_or_else(|| self.poll(now))
    }

    fn ingest_datagram(
        &mut self,
        observation: InventoryDatagramObservation,
        now: Instant,
        dump_completed: &mut bool,
    ) -> Result<(), ObserverFault> {
        if matches!(self.dump, Some(DumpState::Draining(_))) {
            self.ingest_draining_datagram(observation, dump_completed);
            return Ok(());
        }
        let terminal_observed = self
            .dump
            .as_ref()
            .and_then(DumpState::expected_sequence)
            .is_some_and(|expected| observation.terminates_sequence(expected));
        let datagram = match observation.decoded {
            Ok(datagram) => datagram,
            Err(error) => {
                if terminal_observed {
                    *dump_completed = true;
                }
                return Err(ObserverFault::Decode(error));
            }
        };
        if datagram.sequence().is_none() {
            return Err(ObserverFault::MissingSequence);
        }
        if datagram.origin() == InventoryDatagramOrigin::Notification {
            if !datagram.route_events().is_empty()
                && (self.synchronized
                    || self
                        .dump
                        .as_ref()
                        .is_some_and(DumpState::route_dump_started))
            {
                return Err(ObserverFault::RouteNotificationAfterDumpStarted);
            }
            if !datagram.rule_events().is_empty()
                && (self.synchronized
                    || self.dump.as_ref().is_some_and(DumpState::rule_dump_started))
            {
                return Err(ObserverFault::RuleNotificationAfterDumpStarted);
            }
            if let Some(raced) = self.dump.as_mut().and_then(DumpState::raced_mut) {
                raced.push(&datagram, self.config)?;
            } else if self.synchronized {
                self.stage_live_events(datagram.link_events(), datagram.address_events(), now);
            }
            return Ok(());
        }

        let expected = self.dump.as_ref().and_then(DumpState::expected_sequence);
        if datagram.sequence() != expected {
            return Err(ObserverFault::ForeignSequence {
                expected,
                actual: datagram.sequence(),
            });
        }
        if *dump_completed {
            return Err(ObserverFault::DumpMessageAfterCompletion);
        }
        if datagram.completion().is_some() {
            *dump_completed = true;
        }

        let dump = self
            .dump
            .as_mut()
            .expect("matching response sequence requires an active dump");
        match dump {
            DumpState::Link(link) => {
                if !datagram.address_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Link,
                        InventoryFactClass::Address,
                    ));
                }
                if !datagram.route_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Link,
                        InventoryFactClass::Route,
                    ));
                }
                if !datagram.rule_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Link,
                        InventoryFactClass::Rule,
                    ));
                }
                for event in datagram.link_events() {
                    apply_link_dump_event(&mut link.links, &mut link.seen, event.clone())?;
                }
            }
            DumpState::Address(address) => {
                if !datagram.link_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Address,
                        InventoryFactClass::Link,
                    ));
                }
                if !datagram.route_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Address,
                        InventoryFactClass::Route,
                    ));
                }
                if !datagram.rule_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Address,
                        InventoryFactClass::Rule,
                    ));
                }
                for event in datagram.address_events() {
                    apply_address_dump_event(&mut address.addresses, &mut address.seen, *event)?;
                }
            }
            DumpState::Route(route) => {
                if !datagram.link_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Route,
                        InventoryFactClass::Link,
                    ));
                }
                if !datagram.address_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Route,
                        InventoryFactClass::Address,
                    ));
                }
                if !datagram.rule_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Route,
                        InventoryFactClass::Rule,
                    ));
                }
                for event in datagram.route_events() {
                    apply_route_dump_event(&mut route.routes, event)?;
                }
            }
            DumpState::Rule(rule) => {
                if !datagram.link_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Rule,
                        InventoryFactClass::Link,
                    ));
                }
                if !datagram.address_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Rule,
                        InventoryFactClass::Address,
                    ));
                }
                if !datagram.route_events().is_empty() {
                    return Err(unexpected_dump_fact(
                        ObserverDumpPhase::Rule,
                        InventoryFactClass::Route,
                    ));
                }
                for event in datagram.rule_events() {
                    apply_rule_dump_event(&mut rule.rules, event)?;
                }
            }
            DumpState::AwaitingAddress(_)
            | DumpState::AwaitingRoute(_)
            | DumpState::AwaitingRule(_)
            | DumpState::Draining(_) => {
                unreachable!("an inter-phase wait has no matching response sequence")
            }
        }
        Ok(())
    }

    fn ingest_draining_datagram(
        &mut self,
        observation: InventoryDatagramObservation,
        dump_completed: &mut bool,
    ) {
        let Some(DumpState::Draining(draining)) = self.dump.as_ref() else {
            unreachable!("drain ingestion requires a dirty active dump");
        };
        let terminal_observed = observation.terminates_sequence(draining.expected_sequence.get());
        let datagram = match observation.decoded {
            Ok(datagram) => datagram,
            Err(_) => {
                if terminal_observed {
                    *dump_completed = true;
                }
                return;
            }
        };
        if datagram.origin() == InventoryDatagramOrigin::Notification {
            return;
        }
        if datagram.sequence() == Some(draining.expected_sequence.get())
            && datagram.completion().is_some()
        {
            *dump_completed = true;
        }
    }

    fn complete_dump_phase(&mut self, now: Instant) -> ObserverDriveOutcome {
        match self.dump.take().expect("matching dump is active") {
            DumpState::Link(link) => {
                self.dump = Some(DumpState::AwaitingAddress(AddressWaitState {
                    deadline: deadline_after(now, self.config.dump_timeout),
                    links: link.links,
                    raced: link.raced,
                }));
                ObserverDriveOutcome::RequestAddressDump
            }
            DumpState::Address(mut address) => {
                if !address.publish_on_completion {
                    self.dump = Some(DumpState::AwaitingRoute(RouteWaitState {
                        deadline: deadline_after(now, self.config.dump_timeout),
                        links: address.links,
                        addresses: address.addresses,
                        raced: address.raced,
                    }));
                    return ObserverDriveOutcome::RequestRouteDump;
                }
                for event in address.raced.links {
                    apply_link_event(&mut address.links, event);
                }
                for event in address.raced.addresses {
                    apply_address_event(&mut address.addresses, event);
                }
                let refresh_revision = self
                    .active_refresh_revision
                    .take()
                    .expect("active address dump has one refresh revision");
                self.publish(
                    CompleteFacts {
                        links: address.links,
                        addresses: address.addresses,
                        routes: Vec::new(),
                        rules: Vec::new(),
                    },
                    refresh_revision,
                )
            }
            DumpState::Route(route) => {
                self.dump = Some(DumpState::AwaitingRule(RuleWaitState {
                    deadline: deadline_after(now, self.config.dump_timeout),
                    links: route.links,
                    addresses: route.addresses,
                    routes: route.routes,
                    raced: route.raced,
                }));
                ObserverDriveOutcome::RequestRuleDump
            }
            DumpState::Rule(mut rule) => {
                for event in rule.raced.links {
                    apply_link_event(&mut rule.links, event);
                }
                for event in rule.raced.addresses {
                    apply_address_event(&mut rule.addresses, event);
                }
                let refresh_revision = self
                    .active_refresh_revision
                    .take()
                    .expect("active rule dump has one refresh revision");
                self.publish(
                    CompleteFacts {
                        links: rule.links,
                        addresses: rule.addresses,
                        routes: rule.routes,
                        rules: rule.rules,
                    },
                    refresh_revision,
                )
            }
            DumpState::Draining(draining) => {
                self.mark_unsynchronized();
                ObserverDriveOutcome::RequestDump(draining.fault)
            }
            DumpState::AwaitingAddress(_)
            | DumpState::AwaitingRoute(_)
            | DumpState::AwaitingRule(_) => {
                unreachable!("an inter-phase wait cannot complete a dump")
            }
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.dump_deadline()
            .or_else(|| self.pending.as_ref().map(PendingState::next_deadline))
    }

    pub(crate) fn poll(&mut self, now: Instant) -> ObserverDriveOutcome {
        if self.dump_deadline().is_some_and(|deadline| now >= deadline) {
            return self.handle_dump_deadline(now);
        }
        let Some(pending) = self.pending.as_ref() else {
            return ObserverDriveOutcome::Idle;
        };
        if now < pending.next_deadline() {
            return ObserverDriveOutcome::Idle;
        }

        let pending = self.pending.take().expect("due pending state is present");
        self.publish(pending.facts, pending.refresh_revision)
    }

    pub(crate) fn note_loss(
        &mut self,
        cause: ObserverLoss,
        terminal_sequences: &[u32],
        now: Instant,
    ) -> ObserverDriveOutcome {
        let terminal_observed = self
            .dump
            .as_ref()
            .and_then(DumpState::expected_sequence)
            .is_some_and(|expected| terminal_sequences.contains(&expected));
        self.invalidate(ObserverFault::ReceiveLoss(cause), now, terminal_observed)
    }

    pub(crate) fn note_truncation(&mut self, now: Instant) -> ObserverDriveOutcome {
        self.note_loss(ObserverLoss::Truncated, &[], now)
    }

    pub(crate) fn note_dump_request_failure(&mut self, now: Instant) -> ObserverDriveOutcome {
        self.invalidate(ObserverFault::DumpRequestFailed, now, false)
    }

    pub(crate) fn disable(&mut self) {
        self.mark_unsynchronized();
    }

    fn dump_deadline(&self) -> Option<Instant> {
        self.dump.as_ref().map(DumpState::deadline)
    }

    fn publish(&mut self, facts: CompleteFacts, refresh_revision: u64) -> ObserverDriveOutcome {
        let mut state = write_unpoisoned(&self.source.shared.state);
        if state.refresh_revision != refresh_revision {
            self.synchronized = false;
            self.synchronized_refresh_revision = None;
            return ObserverDriveOutcome::Superseded;
        }
        let previous_epoch = self.tracker.current().map(NetworkInventory::epoch);
        let was_synchronized = self.synchronized;
        let inventory = match self.tracker.publish_complete_with_routing(
            facts.links.into_values(),
            facts.addresses.into_values(),
            facts.routes,
            facts.rules,
        ) {
            Ok(inventory) => Arc::new(inventory.clone()),
            Err(error) => {
                drop(state);
                return self.invalidate_without_active(ObserverFault::Inventory(error));
            }
        };
        let epoch = inventory.epoch();
        state.current = Some(inventory);
        self.synchronized = true;
        self.synchronized_refresh_revision = Some(refresh_revision);
        if !was_synchronized || previous_epoch != Some(epoch) {
            ObserverDriveOutcome::Published(epoch)
        } else {
            ObserverDriveOutcome::Idle
        }
    }

    fn stage_live_events(
        &mut self,
        link_events: &[InterfaceLinkEvent],
        address_events: &[InterfaceAddressEvent],
        now: Instant,
    ) {
        if link_events.is_empty() && address_events.is_empty() {
            return;
        }

        let previous_pending = self.pending.take();
        let maximum_deadline = previous_pending
            .as_ref()
            .map(|pending| pending.maximum_deadline)
            .unwrap_or_else(|| deadline_after(now, self.config.maximum_debounce));
        let refresh_revision = previous_pending.as_ref().map_or_else(
            || {
                self.synchronized_refresh_revision
                    .expect("synchronized observer has a publication revision")
            },
            |pending| pending.refresh_revision,
        );
        let mut facts = previous_pending
            .map(|pending| pending.facts)
            .unwrap_or_else(|| facts_from_inventory(self.tracker.current()));
        for event in link_events {
            apply_link_event(&mut facts.links, event.clone());
        }
        for event in address_events {
            apply_address_event(&mut facts.addresses, *event);
        }
        if facts_match_inventory(&facts, self.tracker.current()) {
            self.pending = None;
            return;
        }

        self.pending = Some(PendingState {
            facts,
            quiet_deadline: deadline_after(now, self.config.quiet_debounce),
            maximum_deadline,
            refresh_revision,
        });
    }

    fn handle_dump_deadline(&mut self, now: Instant) -> ObserverDriveOutcome {
        if matches!(self.dump, Some(DumpState::Draining(_))) {
            self.mark_unsynchronized();
            return ObserverDriveOutcome::PermanentFailure(ObserverFault::DumpDrainTimeout);
        }
        self.invalidate(ObserverFault::DumpTimeout, now, false)
    }

    fn invalidate(
        &mut self,
        fault: ObserverFault,
        now: Instant,
        terminal_observed: bool,
    ) -> ObserverDriveOutcome {
        self.mark_stale();
        if terminal_observed {
            let fault = match self.dump.take() {
                Some(DumpState::Draining(draining)) => draining.fault,
                _ => fault,
            };
            return ObserverDriveOutcome::RequestDump(fault);
        }

        match self.dump.take() {
            Some(DumpState::Draining(draining)) => {
                let original_fault = draining.fault;
                self.dump = Some(DumpState::Draining(draining));
                ObserverDriveOutcome::DrainDump(original_fault)
            }
            Some(dump) => {
                let Some(expected_sequence) = dump.active_sequence() else {
                    self.dump = None;
                    return ObserverDriveOutcome::RequestDump(fault);
                };
                self.dump = Some(DumpState::Draining(DrainState {
                    expected_sequence,
                    deadline: deadline_after(now, self.config.dump_timeout),
                    fault,
                }));
                ObserverDriveOutcome::DrainDump(fault)
            }
            None => ObserverDriveOutcome::RequestDump(fault),
        }
    }

    fn invalidate_without_active(&mut self, fault: ObserverFault) -> ObserverDriveOutcome {
        self.mark_unsynchronized();
        ObserverDriveOutcome::RequestDump(fault)
    }

    fn mark_unsynchronized(&mut self) {
        self.dump = None;
        self.active_refresh_revision = None;
        self.mark_stale();
    }

    fn mark_stale(&mut self) {
        self.pending = None;
        self.synchronized = false;
        self.synchronized_refresh_revision = None;
        write_unpoisoned(&self.source.shared.state).current = None;
    }
}

#[derive(Debug)]
enum DumpState {
    Link(LinkDumpState),
    AwaitingAddress(AddressWaitState),
    Address(AddressDumpState),
    AwaitingRoute(RouteWaitState),
    Route(RouteDumpState),
    AwaitingRule(RuleWaitState),
    Rule(RuleDumpState),
    Draining(DrainState),
}

impl DumpState {
    fn deadline(&self) -> Instant {
        match self {
            Self::Link(link) => link.deadline,
            Self::AwaitingAddress(waiting) => waiting.deadline,
            Self::Address(address) => address.deadline,
            Self::AwaitingRoute(waiting) => waiting.deadline,
            Self::Route(route) => route.deadline,
            Self::AwaitingRule(waiting) => waiting.deadline,
            Self::Rule(rule) => rule.deadline,
            Self::Draining(draining) => draining.deadline,
        }
    }

    fn expected_sequence(&self) -> Option<u32> {
        match self {
            Self::Link(link) => Some(link.expected_sequence.get()),
            Self::AwaitingAddress(_) => None,
            Self::Address(address) => Some(address.expected_sequence.get()),
            Self::AwaitingRoute(_) => None,
            Self::Route(route) => Some(route.expected_sequence.get()),
            Self::AwaitingRule(_) => None,
            Self::Rule(rule) => Some(rule.expected_sequence.get()),
            Self::Draining(draining) => Some(draining.expected_sequence.get()),
        }
    }

    fn active_sequence(&self) -> Option<NonZeroU32> {
        match self {
            Self::Link(link) => Some(link.expected_sequence),
            Self::Address(address) => Some(address.expected_sequence),
            Self::Route(route) => Some(route.expected_sequence),
            Self::Rule(rule) => Some(rule.expected_sequence),
            Self::Draining(draining) => Some(draining.expected_sequence),
            Self::AwaitingAddress(_) | Self::AwaitingRoute(_) | Self::AwaitingRule(_) => None,
        }
    }

    fn raced_mut(&mut self) -> Option<&mut RacedEvents> {
        match self {
            Self::Link(link) => Some(&mut link.raced),
            Self::AwaitingAddress(waiting) => Some(&mut waiting.raced),
            Self::Address(address) => Some(&mut address.raced),
            Self::AwaitingRoute(waiting) => Some(&mut waiting.raced),
            Self::Route(route) => Some(&mut route.raced),
            Self::AwaitingRule(waiting) => Some(&mut waiting.raced),
            Self::Rule(rule) => Some(&mut rule.raced),
            Self::Draining(_) => None,
        }
    }

    fn route_dump_started(&self) -> bool {
        matches!(
            self,
            Self::Route(_) | Self::AwaitingRule(_) | Self::Rule(_) | Self::Draining(_)
        )
    }

    fn rule_dump_started(&self) -> bool {
        matches!(self, Self::Rule(_) | Self::Draining(_))
    }
}

#[derive(Debug)]
struct LinkDumpState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    seen: BTreeMap<InterfaceIndex, InterfaceLinkEvent>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct AddressWaitState {
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct AddressDumpState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    seen: BTreeMap<AddressIdentity, InterfaceAddressEvent>,
    raced: RacedEvents,
    publish_on_completion: bool,
}

#[derive(Debug)]
struct RouteWaitState {
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct RouteDumpState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    routes: Vec<NetworkRouteRecord>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct RuleWaitState {
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    routes: Vec<NetworkRouteRecord>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct RuleDumpState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    routes: Vec<NetworkRouteRecord>,
    rules: Vec<NetworkRuleRecord>,
    raced: RacedEvents,
}

#[derive(Debug)]
struct DrainState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    fault: ObserverFault,
}

#[derive(Debug, Default)]
struct RacedEvents {
    links: VecDeque<InterfaceLinkEvent>,
    addresses: VecDeque<InterfaceAddressEvent>,
    event_count: usize,
    wire_bytes: usize,
}

impl RacedEvents {
    fn push(
        &mut self,
        datagram: &InventoryDatagram,
        config: ObserverConfig,
    ) -> Result<(), ObserverFault> {
        let additional_events = datagram
            .link_events()
            .len()
            .saturating_add(datagram.address_events().len());
        if additional_events == 0 {
            return Ok(());
        }
        if self.event_count.saturating_add(additional_events) > config.race_queue_capacity {
            return Err(ObserverFault::RaceQueueOverflow {
                capacity: config.race_queue_capacity,
            });
        }
        if self.wire_bytes.saturating_add(datagram.wire_bytes()) > config.race_queue_byte_capacity {
            return Err(ObserverFault::RaceQueueByteOverflow {
                capacity: config.race_queue_byte_capacity,
            });
        }
        self.links.extend(datagram.link_events().iter().cloned());
        self.addresses
            .extend(datagram.address_events().iter().copied());
        self.event_count += additional_events;
        self.wire_bytes += datagram.wire_bytes();
        Ok(())
    }
}

#[derive(Debug, Default)]
struct CompleteFacts {
    links: BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    addresses: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    routes: Vec<NetworkRouteRecord>,
    rules: Vec<NetworkRuleRecord>,
}

#[derive(Debug)]
struct PendingState {
    facts: CompleteFacts,
    quiet_deadline: Instant,
    maximum_deadline: Instant,
    refresh_revision: u64,
}

impl PendingState {
    fn next_deadline(&self) -> Instant {
        self.quiet_deadline.min(self.maximum_deadline)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AddressIdentity {
    interface_index: InterfaceIndex,
    address: IpAddr,
    prefix_length: u8,
}

impl From<InterfaceAddressRecord> for AddressIdentity {
    fn from(record: InterfaceAddressRecord) -> Self {
        Self {
            interface_index: record.interface_index(),
            address: record.address(),
            prefix_length: record.prefix_length(),
        }
    }
}

fn apply_link_event(
    facts: &mut BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    event: InterfaceLinkEvent,
) {
    match event {
        InterfaceLinkEvent::Upsert(update) => {
            let index = update.interface_index();
            let merged = merge_link_record(facts.get(&index), &update);
            facts.insert(index, merged);
        }
        InterfaceLinkEvent::Remove(interface_index) => {
            facts.remove(&interface_index);
        }
    }
}

fn merge_link_record(
    existing: Option<&InterfaceLinkRecord>,
    update: &InterfaceLinkRecord,
) -> InterfaceLinkRecord {
    let mut merged = InterfaceLinkRecord::new(
        update.interface_index(),
        *update.name(),
        update.hardware_type(),
        update.flags(),
    );
    if let Some(reference) = update.link_reference() {
        merged = merged.with_link_reference(reference);
    }
    if let Some(mtu) = update
        .mtu()
        .or_else(|| existing.and_then(InterfaceLinkRecord::mtu))
    {
        merged = merged.with_mtu(mtu);
    }
    if let Some(state) = update
        .operational_state()
        .or_else(|| existing.and_then(InterfaceLinkRecord::operational_state))
    {
        merged = merged.with_operational_state(state);
    }
    if let Some(carrier) = update
        .carrier()
        .or_else(|| existing.and_then(InterfaceLinkRecord::carrier))
    {
        merged = merged.with_carrier(carrier);
    }
    if let Some(kind) = update
        .kind()
        .or_else(|| existing.and_then(InterfaceLinkRecord::kind))
    {
        merged = merged.with_kind(kind.clone());
    }
    merged
}

fn apply_link_dump_event(
    facts: &mut BTreeMap<InterfaceIndex, InterfaceLinkRecord>,
    seen: &mut BTreeMap<InterfaceIndex, InterfaceLinkEvent>,
    event: InterfaceLinkEvent,
) -> Result<(), ObserverFault> {
    let interface_index = event.interface_index();
    if let Some(first) = seen.get(&interface_index) {
        if first != &event {
            return Err(ObserverFault::ConflictingLinkDumpFact { interface_index });
        }
        return Ok(());
    }
    seen.insert(interface_index, event.clone());
    apply_link_event(facts, event);
    Ok(())
}

fn apply_address_event(
    facts: &mut BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    event: InterfaceAddressEvent,
) {
    let record = event.record();
    let identity = AddressIdentity::from(record);
    match event.kind() {
        AddressEventKind::Add => {
            facts.insert(identity, record);
        }
        AddressEventKind::Remove => {
            facts.remove(&identity);
        }
    }
}

fn apply_address_dump_event(
    facts: &mut BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    seen: &mut BTreeMap<AddressIdentity, InterfaceAddressEvent>,
    event: InterfaceAddressEvent,
) -> Result<(), ObserverFault> {
    let record = event.record();
    let identity = AddressIdentity::from(record);
    if let Some(first) = seen.get(&identity).copied() {
        if first != event {
            return Err(ObserverFault::ConflictingDumpFact {
                first: first.record(),
                first_kind: first.kind(),
                second: record,
                second_kind: event.kind(),
            });
        }
        return Ok(());
    }
    seen.insert(identity, event);
    apply_address_event(facts, event);
    Ok(())
}

fn apply_route_dump_event(
    facts: &mut Vec<NetworkRouteRecord>,
    event: &InterfaceRouteEvent,
) -> Result<(), ObserverFault> {
    match event {
        InterfaceRouteEvent::Upsert { record, .. } => facts.push(record.clone()),
        InterfaceRouteEvent::Remove(_) => {
            return Err(ObserverFault::UnexpectedRouteRemovalInDump);
        }
    }
    Ok(())
}

fn apply_rule_dump_event(
    facts: &mut Vec<NetworkRuleRecord>,
    event: &NetworkRuleEvent,
) -> Result<(), ObserverFault> {
    match event {
        NetworkRuleEvent::Upsert(record) => facts.push(record.clone()),
        NetworkRuleEvent::Remove(_) => {
            return Err(ObserverFault::UnexpectedRuleRemovalInDump);
        }
    }
    Ok(())
}

const fn unexpected_dump_fact(phase: ObserverDumpPhase, fact: InventoryFactClass) -> ObserverFault {
    ObserverFault::UnexpectedDumpFact { phase, fact }
}

fn deadline_after(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration).unwrap_or(now)
}

fn facts_from_inventory(inventory: Option<&NetworkInventory>) -> CompleteFacts {
    let links = inventory
        .into_iter()
        .flat_map(NetworkInventory::links)
        .cloned()
        .map(|record| (record.interface_index(), record))
        .collect();
    let addresses = inventory
        .into_iter()
        .flat_map(NetworkInventory::addresses)
        .copied()
        .map(|record| (AddressIdentity::from(record), record))
        .collect();
    let routes = inventory
        .into_iter()
        .flat_map(NetworkInventory::routes)
        .cloned()
        .collect();
    let rules = inventory
        .into_iter()
        .flat_map(NetworkInventory::rules)
        .cloned()
        .collect();
    CompleteFacts {
        links,
        addresses,
        routes,
        rules,
    }
}

fn facts_match_inventory(facts: &CompleteFacts, inventory: Option<&NetworkInventory>) -> bool {
    let Some(inventory) = inventory else {
        return false;
    };
    facts.links.len() == inventory.links().len()
        && facts.links.values().eq(inventory.links().iter())
        && facts.addresses.len() == inventory.addresses().len()
        && facts.addresses.values().eq(inventory.addresses().iter())
        && facts.routes == inventory.routes()
        && facts.rules == inventory.rules()
}

fn read_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_unpoisoned<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
