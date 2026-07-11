use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use flux_core::{
    InterfaceAddressRecord, InterfaceIndex, NetworkEpoch, NetworkInventory, NetworkInventoryError,
    NetworkInventoryTracker,
};

use crate::address_sync::{
    AddressDatagram, AddressEventDecodeError, AddressEventKind, InterfaceAddressEvent,
};

/// A cloneable view of the latest complete network inventory.
///
/// Clones share immutable snapshots. `snapshot` returns `None` before the
/// first loss-free dump and whenever loss or an in-progress resynchronization
/// makes the retained inventory stale.
#[derive(Clone, Debug)]
pub struct NetworkInventorySource {
    shared: Arc<SharedInventory>,
}

impl NetworkInventorySource {
    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<NetworkInventory>> {
        read_unpoisoned(&self.shared.current).clone()
    }
}

#[derive(Debug, Default)]
struct SharedInventory {
    current: RwLock<Option<Arc<NetworkInventory>>>,
}

pub(crate) const MAX_RACE_QUEUE_CAPACITY: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ObserverConfig {
    race_queue_capacity: usize,
    dump_timeout: Duration,
    quiet_debounce: Duration,
    maximum_debounce: Duration,
}

impl ObserverConfig {
    pub(crate) fn new(
        race_queue_capacity: usize,
        dump_timeout: Duration,
        quiet_debounce: Duration,
        maximum_debounce: Duration,
    ) -> Result<Self, ObserverConfigError> {
        if !(1..=MAX_RACE_QUEUE_CAPACITY).contains(&race_queue_capacity) {
            return Err(ObserverConfigError::InvalidRaceQueueCapacity {
                actual: race_queue_capacity,
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
            dump_timeout,
            quiet_debounce,
            maximum_debounce,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverConfigError {
    InvalidRaceQueueCapacity { actual: usize },
    ZeroDumpTimeout,
    ZeroQuietDebounce,
    ZeroMaximumDebounce,
    QuietExceedsMaximum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverFault {
    MissingSequence,
    Decode(AddressEventDecodeError),
    ForeignSequence {
        expected: Option<u32>,
        actual: Option<u32>,
    },
    RaceQueueOverflow {
        capacity: usize,
    },
    ConflictingDumpFact {
        first: InterfaceAddressRecord,
        first_kind: AddressEventKind,
        second: InterfaceAddressRecord,
        second_kind: AddressEventKind,
    },
    ReceiveLoss(ObserverLoss),
    DumpRequestFailed,
    DumpTimeout,
    DumpMessageAfterCompletion,
    EventWithoutCompleteSnapshot,
    Inventory(NetworkInventoryError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObserverDriveOutcome {
    Idle,
    Published(NetworkEpoch),
    RequestDump(ObserverFault),
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
        }
    }

    pub(crate) fn source(&self) -> NetworkInventorySource {
        self.source.clone()
    }

    /// Starts one address inventory transaction.
    ///
    /// `expected_sequence` must identify a single `AF_UNSPEC RTM_GETADDR`
    /// dump. Splitting IPv4 and IPv6 across independently completable dumps
    /// would permit a half-inventory publication and is intentionally not
    /// represented by this interface.
    pub(crate) fn begin_dump(&mut self, expected_sequence: NonZeroU32, now: Instant) {
        self.mark_unsynchronized();
        self.dump = Some(DumpState {
            expected_sequence,
            deadline: deadline_after(now, self.config.dump_timeout),
            facts: BTreeMap::new(),
            seen: BTreeMap::new(),
            raced_events: VecDeque::with_capacity(self.config.race_queue_capacity),
        });
    }

    #[cfg(test)]
    pub(crate) fn consume(
        &mut self,
        datagram: Result<AddressDatagram, AddressEventDecodeError>,
        now: Instant,
    ) -> ObserverDriveOutcome {
        self.consume_batch(std::iter::once(datagram), now)
    }

    /// Ingests one complete socket receive batch as an atomic publication unit.
    ///
    /// A later fault invalidates every earlier datagram in the batch, and dump
    /// completion or due debounce work is published only after the entire
    /// iterator succeeds.
    pub(crate) fn consume_batch(
        &mut self,
        datagrams: impl IntoIterator<Item = Result<AddressDatagram, AddressEventDecodeError>>,
        now: Instant,
    ) -> ObserverDriveOutcome {
        if self.dump.as_ref().is_some_and(|dump| now >= dump.deadline) {
            return self.invalidate(ObserverFault::DumpTimeout);
        }

        let mut dump_completed = false;
        for datagram in datagrams {
            if let Err(fault) = self.ingest_datagram(datagram, now, &mut dump_completed) {
                return self.invalidate(fault);
            }
        }
        if dump_completed {
            return self.complete_dump();
        }
        self.poll(now)
    }

    fn ingest_datagram(
        &mut self,
        datagram: Result<AddressDatagram, AddressEventDecodeError>,
        now: Instant,
        dump_completed: &mut bool,
    ) -> Result<(), ObserverFault> {
        let datagram = match datagram {
            Ok(datagram) => datagram,
            Err(error) => return Err(ObserverFault::Decode(error)),
        };
        if datagram.sequence().is_none() {
            return Err(ObserverFault::MissingSequence);
        }
        let expected = self.dump.as_ref().map(|dump| dump.expected_sequence.get());
        if datagram.sequence() == Some(0) && expected.is_some() {
            if datagram.completion().is_some() {
                return Err(ObserverFault::ForeignSequence {
                    expected,
                    actual: datagram.sequence(),
                });
            }
            let dump = self.dump.as_mut().expect("active dump was observed above");
            let Some(remaining) = self
                .config
                .race_queue_capacity
                .checked_sub(dump.raced_events.len())
            else {
                return Err(ObserverFault::RaceQueueOverflow {
                    capacity: self.config.race_queue_capacity,
                });
            };
            if datagram.events().len() > remaining {
                return Err(ObserverFault::RaceQueueOverflow {
                    capacity: self.config.race_queue_capacity,
                });
            }
            dump.raced_events.extend(datagram.events().iter().copied());
            return Ok(());
        }
        if expected.is_none() && datagram.sequence() == Some(0) {
            if datagram.completion().is_some() {
                return Err(ObserverFault::ForeignSequence {
                    expected,
                    actual: datagram.sequence(),
                });
            }
            if !self.synchronized {
                return Err(ObserverFault::EventWithoutCompleteSnapshot);
            }
            self.stage_live_events(datagram.events(), now);
            return Ok(());
        }
        if datagram.sequence() != expected {
            return Err(ObserverFault::ForeignSequence {
                expected,
                actual: datagram.sequence(),
            });
        }
        if *dump_completed {
            return Err(ObserverFault::DumpMessageAfterCompletion);
        }

        let dump = self
            .dump
            .as_mut()
            .expect("matching sequence requires a dump");
        for event in datagram.events() {
            apply_dump_event(&mut dump.facts, &mut dump.seen, *event)?;
        }
        if datagram.completion().is_some() {
            *dump_completed = true;
        }
        Ok(())
    }

    fn complete_dump(&mut self) -> ObserverDriveOutcome {
        let mut completed = self.dump.take().expect("matching dump is active");
        for event in completed.raced_events {
            apply_event(&mut completed.facts, event);
        }
        let facts = completed.facts;
        self.publish(facts)
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.dump
            .as_ref()
            .map(|dump| dump.deadline)
            .or_else(|| self.pending.as_ref().map(PendingState::next_deadline))
    }

    pub(crate) fn poll(&mut self, now: Instant) -> ObserverDriveOutcome {
        if self.dump.as_ref().is_some_and(|dump| now >= dump.deadline) {
            return self.invalidate(ObserverFault::DumpTimeout);
        }
        let Some(pending) = self.pending.as_ref() else {
            return ObserverDriveOutcome::Idle;
        };
        if now < pending.next_deadline() {
            return ObserverDriveOutcome::Idle;
        }

        let pending = self.pending.take().expect("due pending state is present");
        self.publish(pending.facts)
    }

    pub(crate) fn note_loss(&mut self, cause: ObserverLoss) -> ObserverDriveOutcome {
        self.invalidate(ObserverFault::ReceiveLoss(cause))
    }

    pub(crate) fn note_truncation(&mut self) -> ObserverDriveOutcome {
        self.note_loss(ObserverLoss::Truncated)
    }

    pub(crate) fn note_dump_request_failure(&mut self) -> ObserverDriveOutcome {
        self.invalidate(ObserverFault::DumpRequestFailed)
    }

    fn publish(
        &mut self,
        facts: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    ) -> ObserverDriveOutcome {
        let previous_epoch = self.tracker.current().map(NetworkInventory::epoch);
        let was_synchronized = self.synchronized;
        let inventory = match self.tracker.publish_complete(facts.into_values()) {
            Ok(inventory) => Arc::new(inventory.clone()),
            Err(error) => return self.invalidate(ObserverFault::Inventory(error)),
        };
        let epoch = inventory.epoch();
        *write_unpoisoned(&self.source.shared.current) = Some(inventory);
        self.synchronized = true;
        if !was_synchronized || previous_epoch != Some(epoch) {
            ObserverDriveOutcome::Published(epoch)
        } else {
            ObserverDriveOutcome::Idle
        }
    }

    fn stage_live_events(&mut self, events: &[InterfaceAddressEvent], now: Instant) {
        if events.is_empty() {
            return;
        }

        let previous_pending = self.pending.take();
        let maximum_deadline = previous_pending
            .as_ref()
            .map(|pending| pending.maximum_deadline)
            .unwrap_or_else(|| deadline_after(now, self.config.maximum_debounce));
        let mut facts = previous_pending
            .map(|pending| pending.facts)
            .unwrap_or_else(|| facts_from_inventory(self.tracker.current()));
        for event in events {
            apply_event(&mut facts, *event);
        }
        if facts_match_inventory(&facts, self.tracker.current()) {
            self.pending = None;
            return;
        }

        self.pending = Some(PendingState {
            facts,
            quiet_deadline: deadline_after(now, self.config.quiet_debounce),
            maximum_deadline,
        });
    }

    fn invalidate(&mut self, fault: ObserverFault) -> ObserverDriveOutcome {
        self.mark_unsynchronized();
        ObserverDriveOutcome::RequestDump(fault)
    }

    fn mark_unsynchronized(&mut self) {
        self.dump = None;
        self.pending = None;
        self.synchronized = false;
        *write_unpoisoned(&self.source.shared.current) = None;
    }
}

#[derive(Debug)]
struct DumpState {
    expected_sequence: NonZeroU32,
    deadline: Instant,
    facts: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    seen: BTreeMap<AddressIdentity, InterfaceAddressEvent>,
    raced_events: VecDeque<InterfaceAddressEvent>,
}

#[derive(Debug)]
struct PendingState {
    facts: BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    quiet_deadline: Instant,
    maximum_deadline: Instant,
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

fn apply_event(
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

fn apply_dump_event(
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
    apply_event(facts, event);
    Ok(())
}

fn deadline_after(now: Instant, duration: Duration) -> Instant {
    now.checked_add(duration).unwrap_or(now)
}

fn facts_from_inventory(
    inventory: Option<&NetworkInventory>,
) -> BTreeMap<AddressIdentity, InterfaceAddressRecord> {
    inventory
        .into_iter()
        .flat_map(NetworkInventory::addresses)
        .copied()
        .map(|record| (AddressIdentity::from(record), record))
        .collect()
}

fn facts_match_inventory(
    facts: &BTreeMap<AddressIdentity, InterfaceAddressRecord>,
    inventory: Option<&NetworkInventory>,
) -> bool {
    let Some(inventory) = inventory else {
        return false;
    };
    facts.len() == inventory.addresses().len()
        && facts
            .values()
            .copied()
            .eq(inventory.addresses().iter().copied())
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
