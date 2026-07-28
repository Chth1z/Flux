use std::error::Error;
use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::Arc;
use std::time::Duration;

use crate::capture_path::CapturePathId;
use crate::capture_program::{
    CaptureClauseDecision, CaptureDecisionStage, CaptureTrafficDomain, CaptureTransportProtocol,
};
use crate::generation::GenerationId;
use crate::network_route::NetworkAddressFamily;

/// Absolute number of rows in the closed aggregate-dimension product.
///
/// The protocol factor is three because aggregate coverage is mutually exclusive with the three
/// exact protocols for any domain/family/stage/decision group.
pub const MAX_TRAFFIC_COUNTER_CELLS: u16 = 2 * 2 * 3 * 10 * 2;
/// Absolute decoded-size ceiling for one source sample.
pub const MAX_TRAFFIC_SAMPLE_DECODED_BYTES: u32 = 64 * 1024;
/// Fixed validation work charged for every sample.
pub const TRAFFIC_UPDATE_BASE_WORK_UNITS: u16 = 1;
/// Validation and accumulation work charged for every sample cell.
pub const TRAFFIC_UPDATE_WORK_UNITS_PER_CELL: u16 = 4;
/// Absolute work ceiling for one statistics update.
pub const MAX_TRAFFIC_UPDATE_WORK_UNITS: u16 =
    TRAFFIC_UPDATE_BASE_WORK_UNITS + MAX_TRAFFIC_COUNTER_CELLS * TRAFFIC_UPDATE_WORK_UNITS_PER_CELL;
/// Number of immutable snapshots retained internally by the accumulator.
pub const TRAFFIC_STATISTICS_INTERNAL_SNAPSHOT_RETENTION: usize = 1;

/// Whether a counter covers every transport or one proven transport protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TrafficProtocolScope {
    AllTransports,
    Exact(CaptureTransportProtocol),
}

/// Privacy-reduced dimensions of one public aggregate row.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TrafficAggregateKey {
    domain: CaptureTrafficDomain,
    family: NetworkAddressFamily,
    protocol: TrafficProtocolScope,
    stage: CaptureDecisionStage,
    decision: CaptureClauseDecision,
}

impl TrafficAggregateKey {
    #[must_use]
    pub const fn new(
        domain: CaptureTrafficDomain,
        family: NetworkAddressFamily,
        protocol: TrafficProtocolScope,
        stage: CaptureDecisionStage,
        decision: CaptureClauseDecision,
    ) -> Self {
        Self {
            domain,
            family,
            protocol,
            stage,
            decision,
        }
    }

    #[must_use]
    pub const fn domain(self) -> CaptureTrafficDomain {
        self.domain
    }

    #[must_use]
    pub const fn family(self) -> NetworkAddressFamily {
        self.family
    }

    #[must_use]
    pub const fn protocol(self) -> TrafficProtocolScope {
        self.protocol
    }

    #[must_use]
    pub const fn stage(self) -> CaptureDecisionStage {
        self.stage
    }

    #[must_use]
    pub const fn decision(self) -> CaptureClauseDecision {
        self.decision
    }

    fn same_protocol_group(self, other: Self) -> bool {
        self.domain == other.domain
            && self.family == other.family
            && self.stage == other.stage
            && self.decision == other.decision
    }
}

/// Nonzero identity of one Generation-bound counter plan.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TrafficCounterPlanId(NonZeroU64);

impl TrafficCounterPlanId {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Opaque, plan-local identity assigned to one aggregate counter cell.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TrafficCounterCellId(NonZeroU16);

impl TrafficCounterCellId {
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// Ordered mapping from one opaque cell identity to its aggregate dimensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficCounterPlanCell {
    id: TrafficCounterCellId,
    key: TrafficAggregateKey,
}

impl TrafficCounterPlanCell {
    #[must_use]
    pub const fn id(self) -> TrafficCounterCellId {
        self.id
    }

    #[must_use]
    pub const fn key(self) -> TrafficAggregateKey {
        self.key
    }
}

/// Exact bounded counter layout compiled for one Generation and Capture Path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficCounterPlan {
    id: TrafficCounterPlanId,
    generation: GenerationId,
    capture_path: CapturePathId,
    cells: Arc<[TrafficCounterPlanCell]>,
}

impl TrafficCounterPlan {
    pub fn compile(
        id: TrafficCounterPlanId,
        generation: GenerationId,
        capture_path: CapturePathId,
        keys: impl IntoIterator<Item = TrafficAggregateKey>,
    ) -> Result<Self, TrafficCounterPlanError> {
        let mut keys = keys.into_iter();
        let mut bounded = Vec::new();
        for key in keys.by_ref() {
            if bounded.len() == usize::from(MAX_TRAFFIC_COUNTER_CELLS) {
                return Err(TrafficCounterPlanError::CellLimitExceeded {
                    maximum: MAX_TRAFFIC_COUNTER_CELLS,
                });
            }
            bounded.push(key);
        }
        if bounded.is_empty() {
            return Err(TrafficCounterPlanError::Empty);
        }

        for (index, key) in bounded.iter().copied().enumerate() {
            if bounded[..index].contains(&key) {
                return Err(TrafficCounterPlanError::DuplicateKey(key));
            }
            if bounded[..index].iter().copied().any(|other| {
                key.same_protocol_group(other)
                    && matches!(
                        (key.protocol, other.protocol),
                        (
                            TrafficProtocolScope::AllTransports,
                            TrafficProtocolScope::Exact(_)
                        ) | (
                            TrafficProtocolScope::Exact(_),
                            TrafficProtocolScope::AllTransports
                        )
                    )
            }) {
                return Err(TrafficCounterPlanError::MixedProtocolCoverage {
                    domain: key.domain,
                    family: key.family,
                    stage: key.stage,
                    decision: key.decision,
                });
            }
        }

        let cells = bounded
            .into_iter()
            .enumerate()
            .map(|(index, key)| TrafficCounterPlanCell {
                id: TrafficCounterCellId(
                    NonZeroU16::new(u16::try_from(index + 1).expect("cell bound fits u16"))
                        .expect("cell indices start at one"),
                ),
                key,
            })
            .collect::<Vec<_>>();
        Ok(Self {
            id,
            generation,
            capture_path,
            cells: cells.into(),
        })
    }

    #[must_use]
    pub const fn id(&self) -> TrafficCounterPlanId {
        self.id
    }

    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn capture_path(&self) -> CapturePathId {
        self.capture_path
    }

    #[must_use]
    pub fn cells(&self) -> &[TrafficCounterPlanCell] {
        &self.cells
    }
}

/// Counter-plan compilation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficCounterPlanError {
    Empty,
    CellLimitExceeded {
        maximum: u16,
    },
    DuplicateKey(TrafficAggregateKey),
    MixedProtocolCoverage {
        domain: CaptureTrafficDomain,
        family: NetworkAddressFamily,
        stage: CaptureDecisionStage,
        decision: CaptureClauseDecision,
    },
}

impl fmt::Display for TrafficCounterPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("traffic counter plan is empty"),
            Self::CellLimitExceeded { maximum } => write!(
                formatter,
                "traffic counter plan exceeds the absolute {maximum}-cell bound"
            ),
            Self::DuplicateKey(key) => {
                write!(
                    formatter,
                    "traffic counter plan repeats aggregate key {key:?}"
                )
            }
            Self::MixedProtocolCoverage {
                domain,
                family,
                stage,
                decision,
            } => write!(
                formatter,
                "traffic counter plan mixes aggregate and exact protocol coverage for {domain:?}/{family:?}/{stage:?}/{decision:?}"
            ),
        }
    }
}

impl Error for TrafficCounterPlanError {}

/// Configured ceilings constrained by the module's absolute resource limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficStatisticsLimits {
    max_cells: NonZeroU16,
    max_sample_decoded_bytes: NonZeroU32,
    max_work_units_per_update: NonZeroU16,
}

impl TrafficStatisticsLimits {
    #[must_use]
    pub const fn new(
        max_cells: u16,
        max_sample_decoded_bytes: u32,
        max_work_units_per_update: u16,
    ) -> Option<Self> {
        let Some(max_cells) = NonZeroU16::new(max_cells) else {
            return None;
        };
        let Some(max_sample_decoded_bytes) = NonZeroU32::new(max_sample_decoded_bytes) else {
            return None;
        };
        let Some(max_work_units_per_update) = NonZeroU16::new(max_work_units_per_update) else {
            return None;
        };
        if max_cells.get() > MAX_TRAFFIC_COUNTER_CELLS
            || max_sample_decoded_bytes.get() > MAX_TRAFFIC_SAMPLE_DECODED_BYTES
            || max_work_units_per_update.get() > MAX_TRAFFIC_UPDATE_WORK_UNITS
        {
            return None;
        }
        Some(Self {
            max_cells,
            max_sample_decoded_bytes,
            max_work_units_per_update,
        })
    }

    #[must_use]
    pub const fn max_cells(self) -> u16 {
        self.max_cells.get()
    }

    #[must_use]
    pub const fn max_sample_decoded_bytes(self) -> u32 {
        self.max_sample_decoded_bytes.get()
    }

    #[must_use]
    pub const fn max_work_units_per_update(self) -> u16 {
        self.max_work_units_per_update.get()
    }
}

/// Nonzero identity of one concrete source instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TrafficCounterSourceId(NonZeroU64);

impl TrafficCounterSourceId {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// Monotonic sequence emitted by one source instance.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TrafficSampleSequence(NonZeroU64);

impl TrafficSampleSequence {
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Source-reported loss whose exact count may be unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficReportedLoss {
    Unknown,
    Events(NonZeroU64),
}

impl TrafficReportedLoss {
    #[must_use]
    pub const fn events(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self::Events(value)),
            None => None,
        }
    }
}

/// Continuity signal attached to a complete cumulative sample.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficSampleSignal {
    Continuous,
    SourceReset,
    Loss(TrafficReportedLoss),
}

/// Cumulative packet and byte values supplied by a source cell.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficCumulativeCounters {
    packets: u64,
    bytes: u64,
}

impl TrafficCumulativeCounters {
    #[must_use]
    pub const fn new(packets: u64, bytes: u64) -> Self {
        Self { packets, bytes }
    }

    #[must_use]
    pub const fn packets(self) -> u64 {
        self.packets
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }

    const fn is_saturated(self) -> bool {
        self.packets == u64::MAX || self.bytes == u64::MAX
    }

    const fn regressed_from(self, previous: Self) -> bool {
        self.packets < previous.packets || self.bytes < previous.bytes
    }
}

/// One opaque cell and its cumulative source counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficCounterSampleCell {
    id: TrafficCounterCellId,
    counters: TrafficCumulativeCounters,
}

impl TrafficCounterSampleCell {
    #[must_use]
    pub const fn new(id: TrafficCounterCellId, counters: TrafficCumulativeCounters) -> Self {
        Self { id, counters }
    }

    #[must_use]
    pub const fn id(self) -> TrafficCounterCellId {
        self.id
    }

    #[must_use]
    pub const fn counters(self) -> TrafficCumulativeCounters {
        self.counters
    }
}

/// Complete, bounded cumulative observation for one counter plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficCounterSample {
    plan: TrafficCounterPlanId,
    source: TrafficCounterSourceId,
    sequence: TrafficSampleSequence,
    sampled_at: Duration,
    signal: TrafficSampleSignal,
    decoded_bytes: u32,
    cells: Box<[TrafficCounterSampleCell]>,
}

impl TrafficCounterSample {
    pub fn new(
        plan: TrafficCounterPlanId,
        source: TrafficCounterSourceId,
        sequence: TrafficSampleSequence,
        sampled_at: Duration,
        signal: TrafficSampleSignal,
        decoded_bytes: u32,
        cells: impl IntoIterator<Item = TrafficCounterSampleCell>,
    ) -> Result<Self, TrafficCounterSampleError> {
        if decoded_bytes > MAX_TRAFFIC_SAMPLE_DECODED_BYTES {
            return Err(TrafficCounterSampleError::DecodedBytesLimitExceeded {
                maximum: MAX_TRAFFIC_SAMPLE_DECODED_BYTES,
                actual: decoded_bytes,
            });
        }
        let mut cells = cells.into_iter();
        let mut bounded = Vec::new();
        for cell in cells.by_ref() {
            if bounded.len() == usize::from(MAX_TRAFFIC_COUNTER_CELLS) {
                return Err(TrafficCounterSampleError::CellLimitExceeded {
                    maximum: MAX_TRAFFIC_COUNTER_CELLS,
                });
            }
            bounded.push(cell);
        }
        if bounded.is_empty() {
            return Err(TrafficCounterSampleError::Empty);
        }
        Ok(Self {
            plan,
            source,
            sequence,
            sampled_at,
            signal,
            decoded_bytes,
            cells: bounded.into_boxed_slice(),
        })
    }
}

/// Sample construction failure at an absolute resource bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficCounterSampleError {
    Empty,
    CellLimitExceeded { maximum: u16 },
    DecodedBytesLimitExceeded { maximum: u32, actual: u32 },
}

impl fmt::Display for TrafficCounterSampleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("traffic counter sample is empty"),
            Self::CellLimitExceeded { maximum } => write!(
                formatter,
                "traffic counter sample exceeds the absolute {maximum}-cell bound"
            ),
            Self::DecodedBytesLimitExceeded { maximum, actual } => write!(
                formatter,
                "traffic counter sample has {actual} decoded bytes but the absolute bound is {maximum}"
            ),
        }
    }
}

impl Error for TrafficCounterSampleError {}

/// Monotonic identity of an immutable published statistics snapshot.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct StatisticsRevision(NonZeroU64);

impl StatisticsRevision {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Nonzero continuity epoch; totals never cross an epoch boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct StatisticsEpoch(NonZeroU64);

impl StatisticsEpoch {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    #[must_use]
    pub const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => Self::new(value),
            None => None,
        }
    }
}

/// Cause of discontinuity represented by a snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatisticsLoss {
    None,
    InitialBaseline,
    PlanReplaced,
    SourceReplaced,
    SourceReset,
    SequenceGap { missed_samples: NonZeroU64 },
    Reported(TrafficReportedLoss),
    CounterRegression,
    CounterSaturated,
    TotalExhausted,
}

/// Readiness of the active source within the current statistics epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficStatisticsSourceState {
    AwaitingBaseline,
    Primed,
    Reporting,
}

/// One cumulative, privacy-reduced traffic row in the current epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficAggregate {
    key: TrafficAggregateKey,
    packets: u64,
    bytes: u64,
}

impl TrafficAggregate {
    #[must_use]
    pub const fn key(self) -> TrafficAggregateKey {
        self.key
    }

    #[must_use]
    pub const fn packets(self) -> u64 {
        self.packets
    }

    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// Complete immutable replacement view of the active traffic aggregates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficAggregateSnapshot {
    revision: StatisticsRevision,
    generation: GenerationId,
    capture_path: CapturePathId,
    epoch: StatisticsEpoch,
    sampled_at: Duration,
    interval: Duration,
    loss: StatisticsLoss,
    source_state: TrafficStatisticsSourceState,
    rows: Arc<[TrafficAggregate]>,
}

impl TrafficAggregateSnapshot {
    #[must_use]
    pub const fn revision(&self) -> StatisticsRevision {
        self.revision
    }

    #[must_use]
    pub const fn generation(&self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn capture_path(&self) -> CapturePathId {
        self.capture_path
    }

    #[must_use]
    pub const fn epoch(&self) -> StatisticsEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn sampled_at(&self) -> Duration {
        self.sampled_at
    }

    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    #[must_use]
    pub const fn loss(&self) -> StatisticsLoss {
        self.loss
    }

    #[must_use]
    pub const fn source_state(&self) -> TrafficStatisticsSourceState {
        self.source_state
    }

    #[must_use]
    pub fn rows(&self) -> &[TrafficAggregate] {
        &self.rows
    }
}

/// Result of observing one validated source sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatisticsUpdate {
    Primed(Arc<TrafficAggregateSnapshot>),
    Published(Arc<TrafficAggregateSnapshot>),
    IgnoredDuplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidatedTrafficCounterSample {
    source: TrafficCounterSourceId,
    sequence: TrafficSampleSequence,
    sampled_at: Duration,
    signal: TrafficSampleSignal,
    decoded_bytes: u32,
    counters: Box<[TrafficCumulativeCounters]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TrafficCounterBaseline {
    sample: ValidatedTrafficCounterSample,
}

#[derive(Clone, Copy)]
struct TrafficSnapshotMetadata {
    revision: StatisticsRevision,
    epoch: StatisticsEpoch,
    sampled_at: Duration,
    interval: Duration,
    loss: StatisticsLoss,
    source_state: TrafficStatisticsSourceState,
}

/// Synchronous bounded accumulator for one active Generation-bound counter plan.
pub struct TrafficStatisticsAccumulator {
    plan: TrafficCounterPlan,
    limits: TrafficStatisticsLimits,
    not_before: Duration,
    epoch: StatisticsEpoch,
    baseline: Option<TrafficCounterBaseline>,
    totals: Vec<TrafficCumulativeCounters>,
    snapshot: Option<Arc<TrafficAggregateSnapshot>>,
}

impl TrafficStatisticsAccumulator {
    pub fn new(
        plan: TrafficCounterPlan,
        limits: TrafficStatisticsLimits,
        started_at: Duration,
    ) -> Result<Self, TrafficStatisticsError> {
        validate_plan_budget(&plan, limits)?;
        let totals = vec![TrafficCumulativeCounters::default(); plan.cells().len()];
        Ok(Self {
            plan,
            limits,
            not_before: started_at,
            epoch: StatisticsEpoch::INITIAL,
            baseline: None,
            totals,
            snapshot: None,
        })
    }

    #[must_use]
    pub fn plan(&self) -> &TrafficCounterPlan {
        &self.plan
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<TrafficAggregateSnapshot>> {
        self.snapshot.as_ref().map(Arc::clone)
    }

    pub fn observe(
        &mut self,
        sample: TrafficCounterSample,
    ) -> Result<StatisticsUpdate, TrafficStatisticsError> {
        let sample = self.validate_sample(sample)?;
        let Some(baseline) = self.baseline.as_ref() else {
            if self
                .snapshot
                .as_ref()
                .is_some_and(|snapshot| sample.sampled_at <= snapshot.sampled_at)
                || (self.snapshot.is_none() && sample.sampled_at < self.not_before)
            {
                return Err(TrafficStatisticsError::NonMonotonicTimestamp);
            }
            let loss = match sample.signal {
                TrafficSampleSignal::SourceReset => StatisticsLoss::SourceReset,
                TrafficSampleSignal::Loss(loss) => StatisticsLoss::Reported(loss),
                TrafficSampleSignal::Continuous
                    if sample
                        .counters
                        .iter()
                        .copied()
                        .any(TrafficCumulativeCounters::is_saturated) =>
                {
                    StatisticsLoss::CounterSaturated
                }
                TrafficSampleSignal::Continuous if self.snapshot.is_none() => {
                    StatisticsLoss::InitialBaseline
                }
                TrafficSampleSignal::Continuous => StatisticsLoss::None,
            };
            let advance_epoch = self.snapshot.is_some() && loss != StatisticsLoss::None;
            return self.prime(sample, loss, advance_epoch, Duration::ZERO);
        };

        if sample.source == baseline.sample.source && sample.sequence == baseline.sample.sequence {
            return if sample == baseline.sample {
                Ok(StatisticsUpdate::IgnoredDuplicate)
            } else {
                Err(TrafficStatisticsError::ConflictingReplay {
                    sequence: sample.sequence,
                })
            };
        }
        if sample.sampled_at <= baseline.sample.sampled_at {
            return Err(TrafficStatisticsError::NonMonotonicTimestamp);
        }
        let interval = sample
            .sampled_at
            .checked_sub(baseline.sample.sampled_at)
            .ok_or(TrafficStatisticsError::NonMonotonicTimestamp)?;

        if let Some(loss) = sample_signal_loss(sample.signal) {
            return self.prime(sample, loss, true, interval);
        }
        if sample.source != baseline.sample.source {
            return self.prime(sample, StatisticsLoss::SourceReplaced, true, interval);
        }
        if sample.sequence == baseline.sample.sequence {
            return Err(TrafficStatisticsError::ConflictingReplay {
                sequence: sample.sequence,
            });
        }
        let expected = baseline
            .sample
            .sequence
            .checked_next()
            .ok_or(TrafficStatisticsError::SequenceExhausted)?;
        if sample.sequence < expected {
            return Err(TrafficStatisticsError::OutOfOrderSample {
                current: baseline.sample.sequence,
                received: sample.sequence,
            });
        }
        if sample.sequence != expected {
            let missed_samples = sample
                .sequence
                .get()
                .checked_sub(expected.get())
                .and_then(NonZeroU64::new)
                .ok_or(TrafficStatisticsError::OutOfOrderSample {
                    current: baseline.sample.sequence,
                    received: sample.sequence,
                })?;
            return self.prime(
                sample,
                StatisticsLoss::SequenceGap { missed_samples },
                true,
                interval,
            );
        }
        if sample
            .counters
            .iter()
            .copied()
            .any(TrafficCumulativeCounters::is_saturated)
        {
            return self.prime(sample, StatisticsLoss::CounterSaturated, true, interval);
        }
        if sample
            .counters
            .iter()
            .copied()
            .zip(baseline.sample.counters.iter().copied())
            .any(|(current, previous)| current.regressed_from(previous))
        {
            return self.prime(sample, StatisticsLoss::CounterRegression, true, interval);
        }

        let mut totals = self.totals.clone();
        for (((total, current), previous), _) in totals
            .iter_mut()
            .zip(sample.counters.iter().copied())
            .zip(baseline.sample.counters.iter().copied())
            .zip(self.plan.cells())
        {
            let packet_delta = current
                .packets
                .checked_sub(previous.packets)
                .expect("counter regression was checked");
            let byte_delta = current
                .bytes
                .checked_sub(previous.bytes)
                .expect("counter regression was checked");
            let Some(packets) = total.packets.checked_add(packet_delta) else {
                return self.prime(sample, StatisticsLoss::TotalExhausted, true, interval);
            };
            let Some(bytes) = total.bytes.checked_add(byte_delta) else {
                return self.prime(sample, StatisticsLoss::TotalExhausted, true, interval);
            };
            *total = TrafficCumulativeCounters { packets, bytes };
        }

        let revision = self.next_revision()?;
        let snapshot = self.build_snapshot(
            TrafficSnapshotMetadata {
                revision,
                epoch: self.epoch,
                sampled_at: sample.sampled_at,
                interval,
                loss: StatisticsLoss::None,
                source_state: TrafficStatisticsSourceState::Reporting,
            },
            &totals,
        );
        self.totals = totals;
        self.baseline = Some(TrafficCounterBaseline { sample });
        self.snapshot = Some(Arc::clone(&snapshot));
        Ok(StatisticsUpdate::Published(snapshot))
    }

    pub fn replace_plan(
        &mut self,
        successor: TrafficCounterPlan,
        changed_at: Duration,
    ) -> Result<Arc<TrafficAggregateSnapshot>, TrafficStatisticsError> {
        validate_plan_budget(&successor, self.limits)?;
        if successor.id == self.plan.id {
            return Err(TrafficStatisticsError::RepeatedPlanId(successor.id));
        }
        let expected = self
            .plan
            .generation
            .checked_next()
            .ok_or(TrafficStatisticsError::GenerationExhausted)?;
        if successor.generation != expected {
            return Err(TrafficStatisticsError::NonSuccessorGeneration {
                current: self.plan.generation,
                successor: successor.generation,
            });
        }
        let minimum = self
            .snapshot
            .as_ref()
            .map_or(self.not_before, |snapshot| snapshot.sampled_at);
        if changed_at <= minimum {
            return Err(TrafficStatisticsError::NonMonotonicTimestamp);
        }
        let epoch = self
            .epoch
            .checked_next()
            .ok_or(TrafficStatisticsError::EpochExhausted)?;
        let revision = self.next_revision()?;
        let totals = vec![TrafficCumulativeCounters::default(); successor.cells().len()];
        let snapshot = build_snapshot_for_plan(
            &successor,
            TrafficSnapshotMetadata {
                revision,
                epoch,
                sampled_at: changed_at,
                interval: Duration::ZERO,
                loss: StatisticsLoss::PlanReplaced,
                source_state: TrafficStatisticsSourceState::AwaitingBaseline,
            },
            &totals,
        );

        self.plan = successor;
        self.not_before = changed_at;
        self.epoch = epoch;
        self.baseline = None;
        self.totals = totals;
        self.snapshot = Some(Arc::clone(&snapshot));
        Ok(snapshot)
    }

    fn validate_sample(
        &self,
        sample: TrafficCounterSample,
    ) -> Result<ValidatedTrafficCounterSample, TrafficStatisticsError> {
        if sample.plan != self.plan.id {
            return Err(TrafficStatisticsError::PlanMismatch {
                expected: self.plan.id,
                received: sample.plan,
            });
        }
        if sample.decoded_bytes > self.limits.max_sample_decoded_bytes() {
            return Err(TrafficStatisticsError::DecodedBytesLimitExceeded {
                maximum: self.limits.max_sample_decoded_bytes(),
                actual: sample.decoded_bytes,
            });
        }
        if sample.cells.len() != self.plan.cells().len() {
            return Err(TrafficStatisticsError::CellCoverageMismatch {
                expected: u16::try_from(self.plan.cells().len()).expect("plan bound fits u16"),
                actual: u16::try_from(sample.cells.len()).expect("sample bound fits u16"),
            });
        }
        let mut counters = vec![None; self.plan.cells().len()];
        for cell in sample.cells.iter().copied() {
            let index = usize::from(cell.id.get() - 1);
            let Some(slot) = counters.get_mut(index) else {
                return Err(TrafficStatisticsError::UnknownCell(cell.id));
            };
            if slot.replace(cell.counters).is_some() {
                return Err(TrafficStatisticsError::DuplicateCell(cell.id));
            }
        }
        let counters = counters
            .into_iter()
            .map(|counter| {
                counter.ok_or(TrafficStatisticsError::CellCoverageMismatch {
                    expected: u16::try_from(self.plan.cells().len()).expect("plan bound fits u16"),
                    actual: u16::try_from(sample.cells.len()).expect("sample bound fits u16"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ValidatedTrafficCounterSample {
            source: sample.source,
            sequence: sample.sequence,
            sampled_at: sample.sampled_at,
            signal: sample.signal,
            decoded_bytes: sample.decoded_bytes,
            counters: counters.into_boxed_slice(),
        })
    }

    fn prime(
        &mut self,
        sample: ValidatedTrafficCounterSample,
        loss: StatisticsLoss,
        advance_epoch: bool,
        interval: Duration,
    ) -> Result<StatisticsUpdate, TrafficStatisticsError> {
        let epoch = if advance_epoch {
            self.epoch
                .checked_next()
                .ok_or(TrafficStatisticsError::EpochExhausted)?
        } else {
            self.epoch
        };
        let revision = self.next_revision()?;
        let totals = vec![TrafficCumulativeCounters::default(); self.plan.cells().len()];
        let snapshot = self.build_snapshot(
            TrafficSnapshotMetadata {
                revision,
                epoch,
                sampled_at: sample.sampled_at,
                interval,
                loss,
                source_state: TrafficStatisticsSourceState::Primed,
            },
            &totals,
        );
        self.epoch = epoch;
        self.totals = totals;
        self.baseline = Some(TrafficCounterBaseline { sample });
        self.snapshot = Some(Arc::clone(&snapshot));
        Ok(StatisticsUpdate::Primed(snapshot))
    }

    fn next_revision(&self) -> Result<StatisticsRevision, TrafficStatisticsError> {
        match self.snapshot.as_ref() {
            Some(snapshot) => snapshot
                .revision
                .checked_next()
                .ok_or(TrafficStatisticsError::RevisionExhausted),
            None => Ok(StatisticsRevision::INITIAL),
        }
    }

    fn build_snapshot(
        &self,
        metadata: TrafficSnapshotMetadata,
        totals: &[TrafficCumulativeCounters],
    ) -> Arc<TrafficAggregateSnapshot> {
        build_snapshot_for_plan(&self.plan, metadata, totals)
    }
}

fn validate_plan_budget(
    plan: &TrafficCounterPlan,
    limits: TrafficStatisticsLimits,
) -> Result<(), TrafficStatisticsError> {
    let cells = u16::try_from(plan.cells().len()).expect("absolute plan bound fits u16");
    if cells > limits.max_cells() {
        return Err(TrafficStatisticsError::PlanCellLimitExceeded {
            maximum: limits.max_cells(),
            actual: cells,
        });
    }
    let required = TRAFFIC_UPDATE_BASE_WORK_UNITS
        .checked_add(
            cells
                .checked_mul(TRAFFIC_UPDATE_WORK_UNITS_PER_CELL)
                .expect("absolute work bound fits u16"),
        )
        .expect("absolute work bound fits u16");
    if required > limits.max_work_units_per_update() {
        return Err(TrafficStatisticsError::WorkLimitExceeded {
            maximum: limits.max_work_units_per_update(),
            required,
        });
    }
    Ok(())
}

const fn sample_signal_loss(signal: TrafficSampleSignal) -> Option<StatisticsLoss> {
    match signal {
        TrafficSampleSignal::Continuous => None,
        TrafficSampleSignal::SourceReset => Some(StatisticsLoss::SourceReset),
        TrafficSampleSignal::Loss(loss) => Some(StatisticsLoss::Reported(loss)),
    }
}

fn build_snapshot_for_plan(
    plan: &TrafficCounterPlan,
    metadata: TrafficSnapshotMetadata,
    totals: &[TrafficCumulativeCounters],
) -> Arc<TrafficAggregateSnapshot> {
    debug_assert_eq!(plan.cells().len(), totals.len());
    let rows = plan
        .cells()
        .iter()
        .copied()
        .zip(totals.iter().copied())
        .map(|(cell, counters)| TrafficAggregate {
            key: cell.key,
            packets: counters.packets,
            bytes: counters.bytes,
        })
        .collect::<Vec<_>>();
    Arc::new(TrafficAggregateSnapshot {
        revision: metadata.revision,
        generation: plan.generation,
        capture_path: plan.capture_path,
        epoch: metadata.epoch,
        sampled_at: metadata.sampled_at,
        interval: metadata.interval,
        loss: metadata.loss,
        source_state: metadata.source_state,
        rows: rows.into(),
    })
}

/// Validation or continuity failure that leaves the last accepted state unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficStatisticsError {
    PlanCellLimitExceeded {
        maximum: u16,
        actual: u16,
    },
    WorkLimitExceeded {
        maximum: u16,
        required: u16,
    },
    PlanMismatch {
        expected: TrafficCounterPlanId,
        received: TrafficCounterPlanId,
    },
    DecodedBytesLimitExceeded {
        maximum: u32,
        actual: u32,
    },
    CellCoverageMismatch {
        expected: u16,
        actual: u16,
    },
    UnknownCell(TrafficCounterCellId),
    DuplicateCell(TrafficCounterCellId),
    ConflictingReplay {
        sequence: TrafficSampleSequence,
    },
    OutOfOrderSample {
        current: TrafficSampleSequence,
        received: TrafficSampleSequence,
    },
    NonMonotonicTimestamp,
    SequenceExhausted,
    GenerationExhausted,
    EpochExhausted,
    RevisionExhausted,
    RepeatedPlanId(TrafficCounterPlanId),
    NonSuccessorGeneration {
        current: GenerationId,
        successor: GenerationId,
    },
}

impl fmt::Display for TrafficStatisticsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlanCellLimitExceeded { maximum, actual } => write!(
                formatter,
                "traffic counter plan has {actual} cells but the configured bound is {maximum}"
            ),
            Self::WorkLimitExceeded { maximum, required } => write!(
                formatter,
                "traffic statistics update requires {required} work units but the configured bound is {maximum}"
            ),
            Self::PlanMismatch { expected, received } => write!(
                formatter,
                "traffic counter sample names plan {} but active plan is {}",
                received.get(),
                expected.get()
            ),
            Self::DecodedBytesLimitExceeded { maximum, actual } => write!(
                formatter,
                "traffic counter sample has {actual} decoded bytes but the configured bound is {maximum}"
            ),
            Self::CellCoverageMismatch { expected, actual } => write!(
                formatter,
                "traffic counter sample covers {actual} cells but the active plan requires {expected}"
            ),
            Self::UnknownCell(cell) => write!(
                formatter,
                "traffic counter sample names unknown cell {}",
                cell.get()
            ),
            Self::DuplicateCell(cell) => write!(
                formatter,
                "traffic counter sample repeats cell {}",
                cell.get()
            ),
            Self::ConflictingReplay { sequence } => write!(
                formatter,
                "traffic counter sample conflicts with accepted sequence {}",
                sequence.get()
            ),
            Self::OutOfOrderSample { current, received } => write!(
                formatter,
                "traffic counter sample sequence {} is older than accepted sequence {}",
                received.get(),
                current.get()
            ),
            Self::NonMonotonicTimestamp => formatter.write_str(
                "traffic counter sample time does not advance the active monotonic timeline",
            ),
            Self::SequenceExhausted => {
                formatter.write_str("traffic counter sample sequence is exhausted")
            }
            Self::GenerationExhausted => {
                formatter.write_str("traffic counter plan Generation is exhausted")
            }
            Self::EpochExhausted => formatter.write_str("traffic statistics epoch is exhausted"),
            Self::RevisionExhausted => {
                formatter.write_str("traffic statistics revision is exhausted")
            }
            Self::RepeatedPlanId(plan) => write!(
                formatter,
                "replacement traffic counter plan repeats active identity {}",
                plan.get()
            ),
            Self::NonSuccessorGeneration { current, successor } => write!(
                formatter,
                "replacement traffic counter plan Generation {successor} does not succeed active Generation {current}"
            ),
        }
    }
}

impl Error for TrafficStatisticsError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn generation(value: u32) -> GenerationId {
        GenerationId::new(value).expect("test Generation")
    }

    fn plan_id(value: u64) -> TrafficCounterPlanId {
        TrafficCounterPlanId::new(value).expect("test plan identity")
    }

    fn source_id(value: u64) -> TrafficCounterSourceId {
        TrafficCounterSourceId::new(value).expect("test source identity")
    }

    fn sequence(value: u64) -> TrafficSampleSequence {
        TrafficSampleSequence::new(value).expect("test sample sequence")
    }

    fn key(
        protocol: TrafficProtocolScope,
        stage: CaptureDecisionStage,
        decision: CaptureClauseDecision,
    ) -> TrafficAggregateKey {
        TrafficAggregateKey::new(
            CaptureTrafficDomain::LocalOutput,
            NetworkAddressFamily::Ipv4,
            protocol,
            stage,
            decision,
        )
    }

    fn keys() -> [TrafficAggregateKey; 2] {
        [
            key(
                TrafficProtocolScope::Exact(CaptureTransportProtocol::Tcp),
                CaptureDecisionStage::ProxyAction,
                CaptureClauseDecision::Proxy,
            ),
            key(
                TrafficProtocolScope::Exact(CaptureTransportProtocol::Udp),
                CaptureDecisionStage::DirectDefault,
                CaptureClauseDecision::Direct,
            ),
        ]
    }

    fn plan_for(id: u64, generation_id: u32, capture_path: CapturePathId) -> TrafficCounterPlan {
        TrafficCounterPlan::compile(plan_id(id), generation(generation_id), capture_path, keys())
            .expect("test counter plan")
    }

    fn limits(cells: u16) -> TrafficStatisticsLimits {
        TrafficStatisticsLimits::new(
            cells,
            1_024,
            TRAFFIC_UPDATE_BASE_WORK_UNITS + cells * TRAFFIC_UPDATE_WORK_UNITS_PER_CELL,
        )
        .expect("test statistics limits")
    }

    fn sample(
        plan: &TrafficCounterPlan,
        source: u64,
        sample_sequence: u64,
        sampled_at_secs: u64,
        signal: TrafficSampleSignal,
        decoded_bytes: u32,
        counters: &[(u64, u64)],
    ) -> TrafficCounterSample {
        assert_eq!(plan.cells().len(), counters.len());
        TrafficCounterSample::new(
            plan.id(),
            source_id(source),
            sequence(sample_sequence),
            Duration::from_secs(sampled_at_secs),
            signal,
            decoded_bytes,
            plan.cells()
                .iter()
                .copied()
                .zip(counters.iter().copied())
                .map(|(cell, (packets, bytes))| {
                    TrafficCounterSampleCell::new(
                        cell.id(),
                        TrafficCumulativeCounters::new(packets, bytes),
                    )
                }),
        )
        .expect("test counter sample")
    }

    fn snapshot(update: StatisticsUpdate) -> Arc<TrafficAggregateSnapshot> {
        match update {
            StatisticsUpdate::Primed(snapshot) | StatisticsUpdate::Published(snapshot) => snapshot,
            StatisticsUpdate::IgnoredDuplicate => panic!("expected published statistics update"),
        }
    }

    #[test]
    fn plan_compiles_ordered_opaque_cells_and_rejects_ambiguous_coverage() {
        let plan = plan_for(7, 1, CapturePathId::XtablesTproxy);

        assert_eq!(plan.id(), plan_id(7));
        assert_eq!(plan.generation(), generation(1));
        assert_eq!(plan.capture_path(), CapturePathId::XtablesTproxy);
        assert_eq!(plan.cells()[0].id().get(), 1);
        assert_eq!(plan.cells()[1].id().get(), 2);
        assert_eq!(plan.cells()[0].key(), keys()[0]);
        assert_eq!(plan.cells()[1].key(), keys()[1]);

        assert_eq!(
            TrafficCounterPlan::compile(
                plan_id(8),
                generation(1),
                CapturePathId::XtablesTproxy,
                [],
            ),
            Err(TrafficCounterPlanError::Empty)
        );
        assert!(matches!(
            TrafficCounterPlan::compile(
                plan_id(8),
                generation(1),
                CapturePathId::XtablesTproxy,
                [keys()[0], keys()[0]],
            ),
            Err(TrafficCounterPlanError::DuplicateKey(_))
        ));
        assert!(matches!(
            TrafficCounterPlan::compile(
                plan_id(8),
                generation(1),
                CapturePathId::XtablesTproxy,
                [
                    key(
                        TrafficProtocolScope::AllTransports,
                        CaptureDecisionStage::ProxyAction,
                        CaptureClauseDecision::Proxy,
                    ),
                    key(
                        TrafficProtocolScope::Exact(CaptureTransportProtocol::Tcp),
                        CaptureDecisionStage::ProxyAction,
                        CaptureClauseDecision::Proxy,
                    ),
                ],
            ),
            Err(TrafficCounterPlanError::MixedProtocolCoverage { .. })
        ));
        assert_eq!(
            TrafficCounterPlan::compile(
                plan_id(8),
                generation(1),
                CapturePathId::XtablesTproxy,
                vec![keys()[0]; usize::from(MAX_TRAFFIC_COUNTER_CELLS) + 1],
            ),
            Err(TrafficCounterPlanError::CellLimitExceeded {
                maximum: MAX_TRAFFIC_COUNTER_CELLS,
            })
        );
    }

    #[test]
    fn first_sample_primes_zero_totals_and_later_samples_publish_monotonic_deltas() {
        let plan = plan_for(11, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::from_secs(1))
                .unwrap();
        assert!(statistics.snapshot().is_none());

        let primed = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    21,
                    1,
                    10,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(100, 1_000), (200, 2_000)],
                ))
                .unwrap(),
        );
        assert_eq!(primed.revision(), StatisticsRevision::INITIAL);
        assert_eq!(primed.epoch(), StatisticsEpoch::INITIAL);
        assert_eq!(primed.generation(), generation(1));
        assert_eq!(primed.capture_path(), CapturePathId::XtablesTproxy);
        assert_eq!(primed.loss(), StatisticsLoss::InitialBaseline);
        assert_eq!(primed.source_state(), TrafficStatisticsSourceState::Primed);
        assert_eq!(primed.interval(), Duration::ZERO);
        assert_eq!(primed.rows().len(), 2);
        assert!(
            primed
                .rows()
                .iter()
                .all(|row| row.packets() == 0 && row.bytes() == 0)
        );
        assert_eq!(
            primed.rows()[0].key().domain(),
            CaptureTrafficDomain::LocalOutput
        );
        assert_eq!(primed.rows()[0].key().family(), NetworkAddressFamily::Ipv4);
        assert_eq!(
            primed.rows()[0].key().protocol(),
            TrafficProtocolScope::Exact(CaptureTransportProtocol::Tcp)
        );
        assert_eq!(
            primed.rows()[0].key().stage(),
            CaptureDecisionStage::ProxyAction
        );
        assert_eq!(
            primed.rows()[0].key().decision(),
            CaptureClauseDecision::Proxy
        );

        let published = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    21,
                    2,
                    15,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(103, 1_300), (205, 2_050)],
                ))
                .unwrap(),
        );
        assert_eq!(published.revision().get(), 2);
        assert_eq!(published.epoch(), StatisticsEpoch::INITIAL);
        assert_eq!(published.loss(), StatisticsLoss::None);
        assert_eq!(
            published.source_state(),
            TrafficStatisticsSourceState::Reporting
        );
        assert_eq!(published.interval(), Duration::from_secs(5));
        assert_eq!(published.rows()[0].packets(), 3);
        assert_eq!(published.rows()[0].bytes(), 300);
        assert_eq!(published.rows()[1].packets(), 5);
        assert_eq!(published.rows()[1].bytes(), 50);

        let published = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    21,
                    3,
                    19,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(110, 1_500), (208, 2_100)],
                ))
                .unwrap(),
        );
        assert_eq!(published.revision().get(), 3);
        assert_eq!(published.rows()[0].packets(), 10);
        assert_eq!(published.rows()[0].bytes(), 500);
        assert_eq!(published.rows()[1].packets(), 8);
        assert_eq!(published.rows()[1].bytes(), 100);
    }

    #[test]
    fn duplicates_are_idempotent_and_conflicting_or_older_replays_do_not_publish() {
        let plan = plan_for(12, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        let baseline = sample(
            &plan,
            22,
            2,
            10,
            TrafficSampleSignal::Continuous,
            64,
            &[(10, 100), (20, 200)],
        );
        statistics.observe(baseline.clone()).unwrap();
        let before = statistics.snapshot().unwrap();

        assert_eq!(
            statistics.observe(baseline).unwrap(),
            StatisticsUpdate::IgnoredDuplicate
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let conflict = sample(
            &plan,
            22,
            2,
            10,
            TrafficSampleSignal::Continuous,
            64,
            &[(11, 100), (20, 200)],
        );
        assert_eq!(
            statistics.observe(conflict),
            Err(TrafficStatisticsError::ConflictingReplay {
                sequence: sequence(2),
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let older = sample(
            &plan,
            22,
            1,
            11,
            TrafficSampleSignal::Continuous,
            64,
            &[(11, 101), (21, 201)],
        );
        assert_eq!(
            statistics.observe(older),
            Err(TrafficStatisticsError::OutOfOrderSample {
                current: sequence(2),
                received: sequence(1),
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let stale_time = sample(
            &plan,
            22,
            3,
            10,
            TrafficSampleSignal::Continuous,
            64,
            &[(11, 101), (21, 201)],
        );
        assert_eq!(
            statistics.observe(stale_time),
            Err(TrafficStatisticsError::NonMonotonicTimestamp)
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));
    }

    #[test]
    fn gaps_source_changes_resets_and_reported_loss_start_explicit_epochs() {
        let plan = plan_for(13, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &plan,
                23,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();

        let gap = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    23,
                    4,
                    4,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(14, 140), (24, 240)],
                ))
                .unwrap(),
        );
        assert_eq!(gap.epoch().get(), 2);
        assert_eq!(
            gap.loss(),
            StatisticsLoss::SequenceGap {
                missed_samples: NonZeroU64::new(2).unwrap(),
            }
        );
        assert!(gap.rows().iter().all(|row| row.packets() == 0));

        let recovered = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    23,
                    5,
                    5,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(16, 160), (25, 250)],
                ))
                .unwrap(),
        );
        assert_eq!(recovered.epoch().get(), 2);
        assert_eq!(recovered.rows()[0].packets(), 2);
        assert_eq!(recovered.rows()[1].packets(), 1);

        let replacement = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    24,
                    5,
                    6,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(100, 1_000), (200, 2_000)],
                ))
                .unwrap(),
        );
        assert_eq!(replacement.epoch().get(), 3);
        assert_eq!(replacement.loss(), StatisticsLoss::SourceReplaced);

        let reset = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    24,
                    1,
                    7,
                    TrafficSampleSignal::SourceReset,
                    64,
                    &[(1, 10), (2, 20)],
                ))
                .unwrap(),
        );
        assert_eq!(reset.epoch().get(), 4);
        assert_eq!(reset.loss(), StatisticsLoss::SourceReset);

        let reported = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    24,
                    2,
                    8,
                    TrafficSampleSignal::Loss(TrafficReportedLoss::events(7).unwrap()),
                    64,
                    &[(3, 30), (4, 40)],
                ))
                .unwrap(),
        );
        assert_eq!(reported.epoch().get(), 5);
        assert_eq!(
            reported.loss(),
            StatisticsLoss::Reported(TrafficReportedLoss::events(7).unwrap())
        );
    }

    #[test]
    fn regressions_saturation_and_total_exhaustion_discard_uncertain_deltas() {
        let plan = plan_for(14, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &plan,
                25,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();

        let regression = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    25,
                    2,
                    2,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(9, 101), (21, 201)],
                ))
                .unwrap(),
        );
        assert_eq!(regression.epoch().get(), 2);
        assert_eq!(regression.loss(), StatisticsLoss::CounterRegression);
        assert!(regression.rows().iter().all(|row| row.packets() == 0));

        let saturated = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    25,
                    3,
                    3,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(u64::MAX, 102), (22, 202)],
                ))
                .unwrap(),
        );
        assert_eq!(saturated.epoch().get(), 3);
        assert_eq!(saturated.loss(), StatisticsLoss::CounterSaturated);

        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &plan,
                25,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();
        statistics.totals[0] = TrafficCumulativeCounters::new(u64::MAX - 1, 0);

        let exhausted = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    25,
                    2,
                    2,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(12, 101), (21, 201)],
                ))
                .unwrap(),
        );
        assert_eq!(exhausted.epoch().get(), 2);
        assert_eq!(exhausted.loss(), StatisticsLoss::TotalExhausted);
        assert!(
            exhausted
                .rows()
                .iter()
                .all(|row| row.packets() == 0 && row.bytes() == 0)
        );
    }

    #[test]
    fn invalid_coverage_plan_or_decode_budget_cannot_partially_publish() {
        let plan = plan_for(15, 1, CapturePathId::XtablesTproxy);
        let mut statistics = TrafficStatisticsAccumulator::new(
            plan.clone(),
            TrafficStatisticsLimits::new(2, 64, 9).unwrap(),
            Duration::ZERO,
        )
        .unwrap();
        statistics
            .observe(sample(
                &plan,
                26,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();
        let before = statistics.snapshot().unwrap();

        let missing = TrafficCounterSample::new(
            plan.id(),
            source_id(26),
            sequence(2),
            Duration::from_secs(2),
            TrafficSampleSignal::Continuous,
            64,
            [TrafficCounterSampleCell::new(
                plan.cells()[0].id(),
                TrafficCumulativeCounters::new(11, 101),
            )],
        )
        .unwrap();
        assert_eq!(
            statistics.observe(missing),
            Err(TrafficStatisticsError::CellCoverageMismatch {
                expected: 2,
                actual: 1,
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let duplicate = TrafficCounterSample::new(
            plan.id(),
            source_id(26),
            sequence(2),
            Duration::from_secs(2),
            TrafficSampleSignal::Continuous,
            64,
            [
                TrafficCounterSampleCell::new(
                    plan.cells()[0].id(),
                    TrafficCumulativeCounters::new(11, 101),
                ),
                TrafficCounterSampleCell::new(
                    plan.cells()[0].id(),
                    TrafficCumulativeCounters::new(21, 201),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            statistics.observe(duplicate),
            Err(TrafficStatisticsError::DuplicateCell(plan.cells()[0].id()))
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let unknown = TrafficCounterCellId(NonZeroU16::new(99).unwrap());
        let unknown_sample = TrafficCounterSample::new(
            plan.id(),
            source_id(26),
            sequence(2),
            Duration::from_secs(2),
            TrafficSampleSignal::Continuous,
            64,
            [
                TrafficCounterSampleCell::new(unknown, TrafficCumulativeCounters::new(11, 101)),
                TrafficCounterSampleCell::new(
                    plan.cells()[1].id(),
                    TrafficCumulativeCounters::new(21, 201),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            statistics.observe(unknown_sample),
            Err(TrafficStatisticsError::UnknownCell(unknown))
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let wrong_plan = TrafficCounterSample::new(
            plan_id(999),
            source_id(26),
            sequence(2),
            Duration::from_secs(2),
            TrafficSampleSignal::Continuous,
            64,
            plan.cells().iter().copied().map(|cell| {
                TrafficCounterSampleCell::new(cell.id(), TrafficCumulativeCounters::new(11, 101))
            }),
        )
        .unwrap();
        assert_eq!(
            statistics.observe(wrong_plan),
            Err(TrafficStatisticsError::PlanMismatch {
                expected: plan.id(),
                received: plan_id(999),
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let oversized = sample(
            &plan,
            26,
            2,
            2,
            TrafficSampleSignal::Continuous,
            65,
            &[(11, 101), (21, 201)],
        );
        assert_eq!(
            statistics.observe(oversized),
            Err(TrafficStatisticsError::DecodedBytesLimitExceeded {
                maximum: 64,
                actual: 65,
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let reversed = TrafficCounterSample::new(
            plan.id(),
            source_id(26),
            sequence(2),
            Duration::from_secs(2),
            TrafficSampleSignal::Continuous,
            64,
            [
                TrafficCounterSampleCell::new(
                    plan.cells()[1].id(),
                    TrafficCumulativeCounters::new(21, 201),
                ),
                TrafficCounterSampleCell::new(
                    plan.cells()[0].id(),
                    TrafficCumulativeCounters::new(11, 101),
                ),
            ],
        )
        .unwrap();
        let published = snapshot(statistics.observe(reversed).unwrap());
        assert_eq!(published.rows()[0].packets(), 1);
        assert_eq!(published.rows()[1].packets(), 1);
    }

    #[test]
    fn constructors_and_runtime_limits_bound_cells_bytes_work_and_retention() {
        assert!(TrafficStatisticsLimits::new(0, 1, 1).is_none());
        assert!(TrafficStatisticsLimits::new(1, 0, 1).is_none());
        assert!(TrafficStatisticsLimits::new(1, 1, 0).is_none());
        assert!(TrafficStatisticsLimits::new(MAX_TRAFFIC_COUNTER_CELLS + 1, 1, 1).is_none());
        assert!(TrafficStatisticsLimits::new(1, MAX_TRAFFIC_SAMPLE_DECODED_BYTES + 1, 1).is_none());
        assert!(TrafficStatisticsLimits::new(1, 1, MAX_TRAFFIC_UPDATE_WORK_UNITS + 1).is_none());
        assert_eq!(TRAFFIC_STATISTICS_INTERNAL_SNAPSHOT_RETENTION, 1);

        let plan = plan_for(16, 1, CapturePathId::XtablesTproxy);
        assert!(matches!(
            TrafficStatisticsAccumulator::new(plan.clone(), limits(1), Duration::ZERO),
            Err(TrafficStatisticsError::PlanCellLimitExceeded {
                maximum: 1,
                actual: 2,
            })
        ));
        let insufficient_work = TrafficStatisticsLimits::new(2, 1_024, 8).unwrap();
        assert!(matches!(
            TrafficStatisticsAccumulator::new(plan.clone(), insufficient_work, Duration::ZERO),
            Err(TrafficStatisticsError::WorkLimitExceeded {
                maximum: 8,
                required: 9,
            })
        ));

        let cell = TrafficCounterSampleCell::new(
            plan.cells()[0].id(),
            TrafficCumulativeCounters::default(),
        );
        assert_eq!(
            TrafficCounterSample::new(
                plan.id(),
                source_id(27),
                sequence(1),
                Duration::ZERO,
                TrafficSampleSignal::Continuous,
                0,
                [],
            ),
            Err(TrafficCounterSampleError::Empty)
        );
        assert_eq!(
            TrafficCounterSample::new(
                plan.id(),
                source_id(27),
                sequence(1),
                Duration::ZERO,
                TrafficSampleSignal::Continuous,
                0,
                vec![cell; usize::from(MAX_TRAFFIC_COUNTER_CELLS) + 1],
            ),
            Err(TrafficCounterSampleError::CellLimitExceeded {
                maximum: MAX_TRAFFIC_COUNTER_CELLS,
            })
        );
        assert_eq!(
            TrafficCounterSample::new(
                plan.id(),
                source_id(27),
                sequence(1),
                Duration::ZERO,
                TrafficSampleSignal::Continuous,
                MAX_TRAFFIC_SAMPLE_DECODED_BYTES + 1,
                [cell],
            ),
            Err(TrafficCounterSampleError::DecodedBytesLimitExceeded {
                maximum: MAX_TRAFFIC_SAMPLE_DECODED_BYTES,
                actual: MAX_TRAFFIC_SAMPLE_DECODED_BYTES + 1,
            })
        );
    }

    #[test]
    fn replacement_is_generation_bound_and_primes_without_joining_epochs() {
        let first = plan_for(17, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(first.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &first,
                28,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();

        let successor = plan_for(18, 2, CapturePathId::ManagedTun);
        let replacement = statistics
            .replace_plan(successor.clone(), Duration::from_secs(2))
            .unwrap();
        assert_eq!(replacement.revision().get(), 2);
        assert_eq!(replacement.epoch().get(), 2);
        assert_eq!(replacement.generation(), generation(2));
        assert_eq!(replacement.capture_path(), CapturePathId::ManagedTun);
        assert_eq!(replacement.loss(), StatisticsLoss::PlanReplaced);
        assert_eq!(
            replacement.source_state(),
            TrafficStatisticsSourceState::AwaitingBaseline
        );
        assert!(replacement.rows().iter().all(|row| row.packets() == 0));

        let primed = snapshot(
            statistics
                .observe(sample(
                    &successor,
                    29,
                    7,
                    3,
                    TrafficSampleSignal::Continuous,
                    64,
                    &[(1_000, 10_000), (2_000, 20_000)],
                ))
                .unwrap(),
        );
        assert_eq!(primed.revision().get(), 3);
        assert_eq!(primed.epoch().get(), 2);
        assert_eq!(primed.loss(), StatisticsLoss::None);
        assert_eq!(primed.source_state(), TrafficStatisticsSourceState::Primed);

        let before = statistics.snapshot().unwrap();
        let same_generation = plan_for(19, 2, CapturePathId::NftablesTproxy);
        assert_eq!(
            statistics.replace_plan(same_generation, Duration::from_secs(4)),
            Err(TrafficStatisticsError::NonSuccessorGeneration {
                current: generation(2),
                successor: generation(2),
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let skipped_generation = plan_for(20, 4, CapturePathId::NftablesTproxy);
        assert_eq!(
            statistics.replace_plan(skipped_generation, Duration::from_secs(4)),
            Err(TrafficStatisticsError::NonSuccessorGeneration {
                current: generation(2),
                successor: generation(4),
            })
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let repeated_id = plan_for(18, 3, CapturePathId::NftablesTproxy);
        assert_eq!(
            statistics.replace_plan(repeated_id, Duration::from_secs(4)),
            Err(TrafficStatisticsError::RepeatedPlanId(plan_id(18)))
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));
    }

    #[test]
    fn generation_exhaustion_rejects_plan_replacement_without_mutation() {
        let terminal = plan_for(26, u32::MAX, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(terminal.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &terminal,
                36,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();
        let before = statistics.snapshot().unwrap();

        let replacement = plan_for(27, 1, CapturePathId::ManagedTun);
        assert_eq!(
            statistics.replace_plan(replacement, Duration::from_secs(2)),
            Err(TrafficStatisticsError::GenerationExhausted)
        );
        assert_eq!(statistics.plan(), &terminal);
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));
    }

    #[test]
    fn loss_while_waiting_for_a_replacement_baseline_advances_again() {
        let first = plan_for(20, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(first.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &first,
                30,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();
        let successor = plan_for(21, 2, CapturePathId::ManagedTun);
        statistics
            .replace_plan(successor.clone(), Duration::from_secs(2))
            .unwrap();

        let primed = snapshot(
            statistics
                .observe(sample(
                    &successor,
                    31,
                    1,
                    3,
                    TrafficSampleSignal::Loss(TrafficReportedLoss::Unknown),
                    64,
                    &[(10, 100), (20, 200)],
                ))
                .unwrap(),
        );
        assert_eq!(primed.epoch().get(), 3);
        assert_eq!(
            primed.loss(),
            StatisticsLoss::Reported(TrafficReportedLoss::Unknown)
        );
    }

    #[test]
    fn epoch_and_revision_exhaustion_leave_the_last_snapshot_unchanged() {
        let plan = plan_for(22, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &plan,
                32,
                1,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();

        statistics.epoch = StatisticsEpoch::new(u64::MAX).unwrap();
        let before = statistics.snapshot().unwrap();
        assert_eq!(
            statistics.observe(sample(
                &plan,
                32,
                3,
                3,
                TrafficSampleSignal::Continuous,
                64,
                &[(12, 102), (22, 202)],
            )),
            Err(TrafficStatisticsError::EpochExhausted)
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        statistics.epoch = StatisticsEpoch::INITIAL;
        let mut exhausted = (*before).clone();
        exhausted.revision = StatisticsRevision::new(u64::MAX).unwrap();
        statistics.snapshot = Some(Arc::new(exhausted));
        let before = statistics.snapshot().unwrap();
        assert_eq!(
            statistics.observe(sample(
                &plan,
                32,
                2,
                2,
                TrafficSampleSignal::Continuous,
                64,
                &[(11, 101), (21, 201)],
            )),
            Err(TrafficStatisticsError::RevisionExhausted)
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));
    }

    #[test]
    fn exact_sequence_exhaustion_requires_a_reset_or_replacement_source() {
        let plan = plan_for(23, 1, CapturePathId::XtablesTproxy);
        let mut statistics =
            TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
        statistics
            .observe(sample(
                &plan,
                33,
                u64::MAX,
                1,
                TrafficSampleSignal::Continuous,
                64,
                &[(10, 100), (20, 200)],
            ))
            .unwrap();
        let before = statistics.snapshot().unwrap();

        assert_eq!(
            statistics.observe(sample(
                &plan,
                33,
                1,
                2,
                TrafficSampleSignal::Continuous,
                64,
                &[(11, 101), (21, 201)],
            )),
            Err(TrafficStatisticsError::SequenceExhausted)
        );
        assert!(Arc::ptr_eq(&before, &statistics.snapshot().unwrap()));

        let reset = snapshot(
            statistics
                .observe(sample(
                    &plan,
                    33,
                    1,
                    2,
                    TrafficSampleSignal::SourceReset,
                    64,
                    &[(1, 10), (2, 20)],
                ))
                .unwrap(),
        );
        assert_eq!(reset.epoch().get(), 2);
        assert_eq!(reset.loss(), StatisticsLoss::SourceReset);
    }

    #[test]
    fn synthetic_backends_normalize_to_the_same_bounded_aggregate_contract() {
        fn collect(
            path: CapturePathId,
            plan_identity: u64,
            source_identity: u64,
        ) -> Arc<TrafficAggregateSnapshot> {
            let plan = plan_for(plan_identity, 1, path);
            let mut statistics =
                TrafficStatisticsAccumulator::new(plan.clone(), limits(2), Duration::ZERO).unwrap();
            statistics
                .observe(sample(
                    &plan,
                    source_identity,
                    1,
                    1,
                    TrafficSampleSignal::Continuous,
                    32,
                    &[(50, 500), (70, 700)],
                ))
                .unwrap();
            snapshot(
                statistics
                    .observe(sample(
                        &plan,
                        source_identity,
                        2,
                        2,
                        TrafficSampleSignal::Continuous,
                        32,
                        &[(55, 550), (77, 770)],
                    ))
                    .unwrap(),
            )
        }

        let xtables = collect(CapturePathId::XtablesTproxy, 24, 34);
        let tun = collect(CapturePathId::ManagedTun, 25, 35);

        assert_eq!(xtables.rows(), tun.rows());
        assert_eq!(xtables.interval(), tun.interval());
        assert_eq!(xtables.loss(), tun.loss());
        assert_eq!(xtables.source_state(), tun.source_state());
        assert_ne!(xtables.capture_path(), tun.capture_path());
    }
}
