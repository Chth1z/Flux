use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use flux_core::{
    AdministrativeState, CapturePathId, ControlError, GenerationId, Reason, RuntimeControl,
    RuntimeIntent, StatisticsEpoch, StatisticsLoss, StatisticsRevision, StatisticsUpdate,
    TrafficAggregateSnapshot, TrafficCounterPlan, TrafficCounterSample,
    TrafficStatisticsAccumulator, TrafficStatisticsError, TrafficStatisticsLimits,
    TrafficStatisticsSourceState,
};

/// Absolute bound for retained automation decision records.
pub const MAX_AUTOMATION_DECISION_JOURNAL_ENTRIES: u16 = 128;
/// Absolute bound for accepted-action duplicate suppression.
pub const MAX_AUTOMATION_ACCEPTED_ACTION_ENTRIES: u16 = 128;

/// Nonzero daemon-owned revision of the installed policy implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AutomationPolicyRevision(NonZeroU64);

impl AutomationPolicyRevision {
    const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => match NonZeroU64::new(value) {
                Some(value) => Some(Self(value)),
                None => None,
            },
            None => None,
        }
    }
}

/// Nonzero identity chosen by a policy for one stable automation rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AutomationRuleId(NonZeroU32);

impl AutomationRuleId {
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Maintenance action that an observation policy may request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AutomationAction {
    Reload,
    ResyncAddresses,
}

impl AutomationAction {
    const fn into_runtime_intent(self) -> RuntimeIntent {
        match self {
            Self::Reload => RuntimeIntent::Reload {
                reason: Reason::Automation,
            },
            Self::ResyncAddresses => RuntimeIntent::ResyncAddresses {
                reason: Reason::Automation,
            },
        }
    }
}

/// Unbound rule/action request returned by an [`AutomationPolicy`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationActionRequest {
    rule: AutomationRuleId,
    action: AutomationAction,
}

impl AutomationActionRequest {
    #[must_use]
    pub const fn new(rule: AutomationRuleId, action: AutomationAction) -> Self {
        Self { rule, action }
    }

    #[must_use]
    pub const fn rule(self) -> AutomationRuleId {
        self.rule
    }

    #[must_use]
    pub const fn action(self) -> AutomationAction {
        self.action
    }
}

/// At most one action request produced from one immutable snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationPolicyDecision {
    NoChange,
    Propose(AutomationActionRequest),
}

/// Replaceable least-authority policy evaluated synchronously by the daemon.
///
/// Implementations receive no runtime control, kernel, filesystem, clock, or persistence handle.
/// They must complete within the caller's bounded update budget; the Module never schedules or
/// offloads policy work.
pub trait AutomationPolicy: Send {
    fn evaluate(&mut self, snapshot: &TrafficAggregateSnapshot) -> AutomationPolicyDecision;
}

/// Freshness, decision-journal, and accepted-action limits for one installed automation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationLimits {
    maximum_snapshot_age: Duration,
    decision_journal_entries: NonZeroU16,
    accepted_action_entries: NonZeroU16,
}

impl AutomationLimits {
    #[must_use]
    pub const fn new(
        maximum_snapshot_age: Duration,
        decision_journal_entries: u16,
        accepted_action_entries: u16,
    ) -> Option<Self> {
        let Some(decision_journal_entries) = NonZeroU16::new(decision_journal_entries) else {
            return None;
        };
        let Some(accepted_action_entries) = NonZeroU16::new(accepted_action_entries) else {
            return None;
        };
        if decision_journal_entries.get() > MAX_AUTOMATION_DECISION_JOURNAL_ENTRIES
            || accepted_action_entries.get() > MAX_AUTOMATION_ACCEPTED_ACTION_ENTRIES
        {
            return None;
        }
        Some(Self {
            maximum_snapshot_age,
            decision_journal_entries,
            accepted_action_entries,
        })
    }

    #[must_use]
    pub const fn maximum_snapshot_age(self) -> Duration {
        self.maximum_snapshot_age
    }

    #[must_use]
    pub const fn decision_journal_entries(self) -> u16 {
        self.decision_journal_entries.get()
    }

    #[must_use]
    pub const fn accepted_action_entries(self) -> u16 {
        self.accepted_action_entries.get()
    }
}

/// Daemon-bound identity and freshness facts used for one policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationEvaluationContext {
    policy_revision: AutomationPolicyRevision,
    statistics_revision: StatisticsRevision,
    generation: GenerationId,
    capture_path: CapturePathId,
    epoch: StatisticsEpoch,
    sampled_at: Duration,
    evaluated_at: Duration,
    maximum_snapshot_age: Duration,
}

impl AutomationEvaluationContext {
    fn from_snapshot(
        policy_revision: AutomationPolicyRevision,
        snapshot: &TrafficAggregateSnapshot,
        evaluated_at: Duration,
        maximum_snapshot_age: Duration,
    ) -> Self {
        Self {
            policy_revision,
            statistics_revision: snapshot.revision(),
            generation: snapshot.generation(),
            capture_path: snapshot.capture_path(),
            epoch: snapshot.epoch(),
            sampled_at: snapshot.sampled_at(),
            evaluated_at,
            maximum_snapshot_age,
        }
    }

    #[must_use]
    pub const fn policy_revision(self) -> AutomationPolicyRevision {
        self.policy_revision
    }

    #[must_use]
    pub const fn statistics_revision(self) -> StatisticsRevision {
        self.statistics_revision
    }

    #[must_use]
    pub const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn capture_path(self) -> CapturePathId {
        self.capture_path
    }

    #[must_use]
    pub const fn epoch(self) -> StatisticsEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn sampled_at(self) -> Duration {
        self.sampled_at
    }

    #[must_use]
    pub const fn evaluated_at(self) -> Duration {
        self.evaluated_at
    }

    #[must_use]
    pub const fn maximum_snapshot_age(self) -> Duration {
        self.maximum_snapshot_age
    }
}

/// Typed action request after the daemon has bound complete provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationProposal {
    context: AutomationEvaluationContext,
    rule: AutomationRuleId,
    action: AutomationAction,
}

impl AutomationProposal {
    #[must_use]
    pub const fn context(self) -> AutomationEvaluationContext {
        self.context
    }

    #[must_use]
    pub const fn rule(self) -> AutomationRuleId {
        self.rule
    }

    #[must_use]
    pub const fn action(self) -> AutomationAction {
        self.action
    }
}

/// Reason a policy was not called or its proposal was not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationRejection {
    ObservationNotContinuous,
    EvaluationBeforeSample,
    StaleSnapshot,
    RuntimeNotRunning,
    DuplicateProposal,
    ControlQueueFull,
    RuntimeStopped,
    ControlRejected,
}

/// Terminal disposition of one bounded automation decision record.
///
/// `Accepted` means the existing `RuntimeControl` queue accepted the action. Runtime convergence
/// remains owned and reported by `RuntimeControl`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomationDecisionDisposition {
    NoChange,
    Rejected(AutomationRejection),
    Accepted,
}

/// Nonzero daemon-local sequence of an automation decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AutomationDecisionSequence(NonZeroU64);

impl AutomationDecisionSequence {
    const INITIAL: Self = Self(NonZeroU64::MIN);

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    const fn checked_next(self) -> Option<Self> {
        match self.get().checked_add(1) {
            Some(value) => match NonZeroU64::new(value) {
                Some(value) => Some(Self(value)),
                None => None,
            },
            None => None,
        }
    }
}

/// Immutable audit record for one policy decision or pre-policy rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AutomationDecisionRecord {
    sequence: AutomationDecisionSequence,
    context: AutomationEvaluationContext,
    proposal: Option<AutomationProposal>,
    disposition: AutomationDecisionDisposition,
}

impl AutomationDecisionRecord {
    #[must_use]
    pub const fn sequence(self) -> AutomationDecisionSequence {
        self.sequence
    }

    #[must_use]
    pub const fn context(self) -> AutomationEvaluationContext {
        self.context
    }

    #[must_use]
    pub const fn proposal(self) -> Option<AutomationProposal> {
        self.proposal
    }

    #[must_use]
    pub const fn disposition(self) -> AutomationDecisionDisposition {
        self.disposition
    }
}

/// Immutable bounded copy of the current in-memory decision journal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationDecisionJournalSnapshot {
    latest_sequence: Option<AutomationDecisionSequence>,
    records: Arc<[AutomationDecisionRecord]>,
}

impl AutomationDecisionJournalSnapshot {
    #[must_use]
    pub const fn latest_sequence(&self) -> Option<AutomationDecisionSequence> {
        self.latest_sequence
    }

    #[must_use]
    pub fn records(&self) -> &[AutomationDecisionRecord] {
        &self.records
    }
}

/// Outcome of the optional automation stage for one published snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AutomationEvaluation {
    NotConfigured,
    DecisionSequenceExhausted,
    Recorded(Arc<AutomationDecisionRecord>),
}

/// Cloneable read-only source for the latest whole immutable statistics snapshot.
#[derive(Clone, Debug, Default)]
pub struct TrafficStatisticsSnapshotSource {
    current: Arc<RwLock<Option<Arc<TrafficAggregateSnapshot>>>>,
}

impl TrafficStatisticsSnapshotSource {
    #[must_use]
    pub fn snapshot(&self) -> Option<Arc<TrafficAggregateSnapshot>> {
        match self.current.read() {
            Ok(snapshot) => snapshot.as_ref().map(Arc::clone),
            Err(poisoned) => poisoned.into_inner().as_ref().map(Arc::clone),
        }
    }

    fn publish(&self, snapshot: Arc<TrafficAggregateSnapshot>) {
        let mut current = match self.current.write() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        *current = Some(snapshot);
    }
}

/// One complete statistics publication and its optional automation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrafficObservationPublication {
    snapshot: Arc<TrafficAggregateSnapshot>,
    automation: AutomationEvaluation,
}

impl TrafficObservationPublication {
    #[must_use]
    pub fn snapshot(&self) -> Arc<TrafficAggregateSnapshot> {
        Arc::clone(&self.snapshot)
    }

    #[must_use]
    pub const fn automation(&self) -> &AutomationEvaluation {
        &self.automation
    }
}

/// Result of one caller-driven source observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrafficObservationUpdate {
    IgnoredDuplicate,
    Published(TrafficObservationPublication),
}

/// Configuration or statistics error at the daemon observation seam.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficObservationError {
    Disabled,
    AutomationAlreadyConfigured,
    AutomationNotConfigured,
    PolicyRevisionExhausted,
    Statistics(TrafficStatisticsError),
}

impl fmt::Display for TrafficObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("traffic observation is disabled"),
            Self::AutomationAlreadyConfigured => {
                formatter.write_str("traffic automation is already configured")
            }
            Self::AutomationNotConfigured => {
                formatter.write_str("traffic automation is not configured")
            }
            Self::PolicyRevisionExhausted => {
                formatter.write_str("traffic automation policy revision is exhausted")
            }
            Self::Statistics(error) => error.fmt(formatter),
        }
    }
}

impl Error for TrafficObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Statistics(error) => Some(error),
            Self::Disabled
            | Self::AutomationAlreadyConfigured
            | Self::AutomationNotConfigured
            | Self::PolicyRevisionExhausted => None,
        }
    }
}

impl From<TrafficStatisticsError> for TrafficObservationError {
    fn from(error: TrafficStatisticsError) -> Self {
        Self::Statistics(error)
    }
}

/// Caller-driven daemon Module that publishes statistics and optionally evaluates automation.
///
/// The disabled state owns only its empty snapshot source. Neither state creates a timer, thread,
/// collector, queue, persistence store, or wakeup source.
pub struct TrafficObservationModule {
    snapshots: TrafficStatisticsSnapshotSource,
    enabled: Option<EnabledTrafficObservation>,
}

impl TrafficObservationModule {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            snapshots: TrafficStatisticsSnapshotSource::default(),
            enabled: None,
        }
    }

    pub fn enabled(
        plan: TrafficCounterPlan,
        limits: TrafficStatisticsLimits,
        started_at: Duration,
    ) -> Result<Self, TrafficStatisticsError> {
        Ok(Self {
            snapshots: TrafficStatisticsSnapshotSource::default(),
            enabled: Some(EnabledTrafficObservation {
                statistics: TrafficStatisticsAccumulator::new(plan, limits, started_at)?,
                automation: None,
            }),
        })
    }

    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled.is_some()
    }

    #[must_use]
    pub fn automation_is_configured(&self) -> bool {
        self.enabled
            .as_ref()
            .is_some_and(|enabled| enabled.automation.is_some())
    }

    #[must_use]
    pub fn snapshot_source(&self) -> TrafficStatisticsSnapshotSource {
        self.snapshots.clone()
    }

    pub fn configure_automation(
        &mut self,
        limits: AutomationLimits,
        control: Arc<RuntimeControl>,
        policy: Box<dyn AutomationPolicy>,
    ) -> Result<AutomationPolicyRevision, TrafficObservationError> {
        let enabled = self
            .enabled
            .as_mut()
            .ok_or(TrafficObservationError::Disabled)?;
        if enabled.automation.is_some() {
            return Err(TrafficObservationError::AutomationAlreadyConfigured);
        }
        let revision = AutomationPolicyRevision::INITIAL;
        enabled.automation = Some(AutomationRuntime::new(revision, limits, control, policy));
        Ok(revision)
    }

    pub fn replace_automation_policy(
        &mut self,
        policy: Box<dyn AutomationPolicy>,
    ) -> Result<AutomationPolicyRevision, TrafficObservationError> {
        let automation = self
            .enabled
            .as_mut()
            .ok_or(TrafficObservationError::Disabled)?
            .automation
            .as_mut()
            .ok_or(TrafficObservationError::AutomationNotConfigured)?;
        automation.replace_policy(policy)
    }

    #[must_use]
    pub fn automation_journal(&self) -> Option<AutomationDecisionJournalSnapshot> {
        self.enabled
            .as_ref()?
            .automation
            .as_ref()
            .map(AutomationRuntime::journal_snapshot)
    }

    pub fn observe(
        &mut self,
        sample: TrafficCounterSample,
        evaluated_at: Duration,
    ) -> Result<TrafficObservationUpdate, TrafficObservationError> {
        let enabled = self
            .enabled
            .as_mut()
            .ok_or(TrafficObservationError::Disabled)?;
        let update = enabled.statistics.observe(sample)?;
        let snapshot = match update {
            StatisticsUpdate::IgnoredDuplicate => {
                return Ok(TrafficObservationUpdate::IgnoredDuplicate);
            }
            StatisticsUpdate::Primed(snapshot) | StatisticsUpdate::Published(snapshot) => snapshot,
        };
        self.snapshots.publish(Arc::clone(&snapshot));
        let automation = enabled
            .automation
            .as_mut()
            .map_or(AutomationEvaluation::NotConfigured, |automation| {
                automation.evaluate(&snapshot, evaluated_at)
            });
        Ok(TrafficObservationUpdate::Published(
            TrafficObservationPublication {
                snapshot,
                automation,
            },
        ))
    }

    pub fn replace_plan(
        &mut self,
        successor: TrafficCounterPlan,
        changed_at: Duration,
    ) -> Result<TrafficObservationPublication, TrafficObservationError> {
        let enabled = self
            .enabled
            .as_mut()
            .ok_or(TrafficObservationError::Disabled)?;
        let snapshot = enabled.statistics.replace_plan(successor, changed_at)?;
        self.snapshots.publish(Arc::clone(&snapshot));
        let automation = enabled
            .automation
            .as_mut()
            .map_or(AutomationEvaluation::NotConfigured, |automation| {
                automation.evaluate(&snapshot, changed_at)
            });
        Ok(TrafficObservationPublication {
            snapshot,
            automation,
        })
    }
}

impl Default for TrafficObservationModule {
    fn default() -> Self {
        Self::disabled()
    }
}

struct EnabledTrafficObservation {
    statistics: TrafficStatisticsAccumulator,
    automation: Option<AutomationRuntime>,
}

struct AutomationRuntime {
    revision: AutomationPolicyRevision,
    limits: AutomationLimits,
    control: Arc<RuntimeControl>,
    policy: Box<dyn AutomationPolicy>,
    next_sequence: Option<AutomationDecisionSequence>,
    journal: VecDeque<AutomationDecisionRecord>,
    accepted: VecDeque<AcceptedProposalKey>,
}

impl AutomationRuntime {
    fn new(
        revision: AutomationPolicyRevision,
        limits: AutomationLimits,
        control: Arc<RuntimeControl>,
        policy: Box<dyn AutomationPolicy>,
    ) -> Self {
        let journal_capacity = usize::from(limits.decision_journal_entries());
        let accepted_capacity = usize::from(limits.accepted_action_entries());
        Self {
            revision,
            limits,
            control,
            policy,
            next_sequence: Some(AutomationDecisionSequence::INITIAL),
            journal: VecDeque::with_capacity(journal_capacity),
            accepted: VecDeque::with_capacity(accepted_capacity),
        }
    }

    fn replace_policy(
        &mut self,
        policy: Box<dyn AutomationPolicy>,
    ) -> Result<AutomationPolicyRevision, TrafficObservationError> {
        let revision = self
            .revision
            .checked_next()
            .ok_or(TrafficObservationError::PolicyRevisionExhausted)?;
        self.revision = revision;
        self.policy = policy;
        Ok(revision)
    }

    fn evaluate(
        &mut self,
        snapshot: &TrafficAggregateSnapshot,
        evaluated_at: Duration,
    ) -> AutomationEvaluation {
        if self.next_sequence.is_none() {
            return AutomationEvaluation::DecisionSequenceExhausted;
        }
        let context = AutomationEvaluationContext::from_snapshot(
            self.revision,
            snapshot,
            evaluated_at,
            self.limits.maximum_snapshot_age(),
        );
        if snapshot.source_state() != TrafficStatisticsSourceState::Reporting
            || snapshot.loss() != StatisticsLoss::None
        {
            return self.record(
                context,
                None,
                AutomationDecisionDisposition::Rejected(
                    AutomationRejection::ObservationNotContinuous,
                ),
            );
        }
        let Some(age) = evaluated_at.checked_sub(snapshot.sampled_at()) else {
            return self.record(
                context,
                None,
                AutomationDecisionDisposition::Rejected(
                    AutomationRejection::EvaluationBeforeSample,
                ),
            );
        };
        if age > self.limits.maximum_snapshot_age() {
            return self.record(
                context,
                None,
                AutomationDecisionDisposition::Rejected(AutomationRejection::StaleSnapshot),
            );
        }
        if self.control.snapshot().administrative_state != AdministrativeState::Running {
            return self.record(
                context,
                None,
                AutomationDecisionDisposition::Rejected(AutomationRejection::RuntimeNotRunning),
            );
        }

        match self.policy.evaluate(snapshot) {
            AutomationPolicyDecision::NoChange => {
                self.record(context, None, AutomationDecisionDisposition::NoChange)
            }
            AutomationPolicyDecision::Propose(request) => {
                let proposal = AutomationProposal {
                    context,
                    rule: request.rule,
                    action: request.action,
                };
                let key = AcceptedProposalKey::from(proposal);
                if self.accepted.contains(&key) {
                    return self.record(
                        context,
                        Some(proposal),
                        AutomationDecisionDisposition::Rejected(
                            AutomationRejection::DuplicateProposal,
                        ),
                    );
                }
                let disposition = match self.control.submit(request.action.into_runtime_intent()) {
                    Ok(handle) => {
                        drop(handle);
                        self.remember_accepted(key);
                        AutomationDecisionDisposition::Accepted
                    }
                    Err(ControlError::QueueFull) => AutomationDecisionDisposition::Rejected(
                        AutomationRejection::ControlQueueFull,
                    ),
                    Err(ControlError::RuntimeStopped) => {
                        AutomationDecisionDisposition::Rejected(AutomationRejection::RuntimeStopped)
                    }
                    Err(_) => AutomationDecisionDisposition::Rejected(
                        AutomationRejection::ControlRejected,
                    ),
                };
                self.record(context, Some(proposal), disposition)
            }
        }
    }

    fn record(
        &mut self,
        context: AutomationEvaluationContext,
        proposal: Option<AutomationProposal>,
        disposition: AutomationDecisionDisposition,
    ) -> AutomationEvaluation {
        let sequence = self
            .next_sequence
            .expect("decision sequence presence was checked before evaluation");
        self.next_sequence = sequence.checked_next();
        let record = AutomationDecisionRecord {
            sequence,
            context,
            proposal,
            disposition,
        };
        push_bounded(
            &mut self.journal,
            record,
            self.limits.decision_journal_entries(),
        );
        AutomationEvaluation::Recorded(Arc::new(record))
    }

    fn remember_accepted(&mut self, key: AcceptedProposalKey) {
        push_bounded(
            &mut self.accepted,
            key,
            self.limits.accepted_action_entries(),
        );
    }

    fn journal_snapshot(&self) -> AutomationDecisionJournalSnapshot {
        AutomationDecisionJournalSnapshot {
            latest_sequence: self.journal.back().map(|record| record.sequence),
            records: self.journal.iter().copied().collect::<Vec<_>>().into(),
        }
    }
}

fn push_bounded<T>(items: &mut VecDeque<T>, item: T, capacity: u16) {
    if items.len() == usize::from(capacity) {
        items.pop_front();
    }
    items.push_back(item);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedProposalKey {
    policy_revision: AutomationPolicyRevision,
    generation: GenerationId,
    capture_path: CapturePathId,
    epoch: StatisticsEpoch,
    rule: AutomationRuleId,
    action: AutomationAction,
}

impl From<AutomationProposal> for AcceptedProposalKey {
    fn from(proposal: AutomationProposal) -> Self {
        Self {
            policy_revision: proposal.context.policy_revision,
            generation: proposal.context.generation,
            capture_path: proposal.context.capture_path,
            epoch: proposal.context.epoch,
            rule: proposal.rule,
            action: proposal.action,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;

    use flux_core::{
        CaptureClauseDecision, CaptureDecisionStage, CaptureTrafficDomain,
        CaptureTransportProtocol, DispatcherCompletion, NetworkAddressFamily, RuntimeDispatcher,
        TrafficAggregateKey, TrafficCounterPlanId, TrafficCounterSampleCell,
        TrafficCounterSourceId, TrafficCumulativeCounters, TrafficProtocolScope,
        TrafficSampleSequence, TrafficSampleSignal,
    };

    use super::*;

    fn generation(value: u32) -> GenerationId {
        GenerationId::new(value).expect("test Generation")
    }

    fn plan(identity: u64, generation_value: u32) -> TrafficCounterPlan {
        TrafficCounterPlan::compile(
            TrafficCounterPlanId::new(identity).expect("test plan identity"),
            generation(generation_value),
            CapturePathId::XtablesTproxy,
            [TrafficAggregateKey::new(
                CaptureTrafficDomain::LocalOutput,
                NetworkAddressFamily::Ipv4,
                TrafficProtocolScope::Exact(CaptureTransportProtocol::Tcp),
                CaptureDecisionStage::ProxyAction,
                CaptureClauseDecision::Proxy,
            )],
        )
        .expect("test counter plan")
    }

    fn statistics_limits() -> TrafficStatisticsLimits {
        TrafficStatisticsLimits::new(1, 64, 5).expect("test statistics limits")
    }

    fn sample(
        plan: &TrafficCounterPlan,
        sequence: u64,
        sampled_at: u64,
        signal: TrafficSampleSignal,
        packets: u64,
    ) -> TrafficCounterSample {
        TrafficCounterSample::new(
            plan.id(),
            TrafficCounterSourceId::new(1).expect("test source identity"),
            TrafficSampleSequence::new(sequence).expect("test sequence"),
            Duration::from_secs(sampled_at),
            signal,
            32,
            [TrafficCounterSampleCell::new(
                plan.cells()[0].id(),
                TrafficCumulativeCounters::new(packets, packets * 10),
            )],
        )
        .expect("test sample")
    }

    fn publication(update: TrafficObservationUpdate) -> TrafficObservationPublication {
        match update {
            TrafficObservationUpdate::Published(publication) => publication,
            TrafficObservationUpdate::IgnoredDuplicate => panic!("expected publication"),
        }
    }

    fn recorded(evaluation: &AutomationEvaluation) -> AutomationDecisionRecord {
        match evaluation {
            AutomationEvaluation::Recorded(record) => **record,
            AutomationEvaluation::NotConfigured
            | AutomationEvaluation::DecisionSequenceExhausted => {
                panic!("expected decision record")
            }
        }
    }

    fn automation_limits(age: u64, records: u16) -> AutomationLimits {
        automation_limits_with_capacities(age, records, records)
    }

    fn automation_limits_with_capacities(
        age: u64,
        decision_records: u16,
        accepted_actions: u16,
    ) -> AutomationLimits {
        AutomationLimits::new(Duration::from_secs(age), decision_records, accepted_actions)
            .expect("test automation limits")
    }

    #[test]
    fn whole_arc_publication_is_cloneable_and_duplicates_do_not_replace_it() {
        let plan = plan(1, 1);
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        let source = module.snapshot_source();
        assert!(source.snapshot().is_none());

        let baseline_sample = sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10);
        let baseline = publication(
            module
                .observe(baseline_sample.clone(), Duration::from_secs(1))
                .unwrap(),
        );
        let retained_baseline = source.snapshot().unwrap();
        assert!(Arc::ptr_eq(&retained_baseline, &baseline.snapshot()));
        assert_eq!(baseline.automation(), &AutomationEvaluation::NotConfigured);

        assert_eq!(
            module
                .observe(baseline_sample, Duration::from_secs(1))
                .unwrap(),
            TrafficObservationUpdate::IgnoredDuplicate
        );
        assert!(Arc::ptr_eq(&retained_baseline, &source.snapshot().unwrap()));

        let next = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 12),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        let retained_next = source.snapshot().unwrap();
        assert!(Arc::ptr_eq(&retained_next, &next.snapshot()));
        assert!(!Arc::ptr_eq(&retained_baseline, &retained_next));
        assert_eq!(retained_baseline.rows()[0].packets(), 0);
        assert_eq!(retained_next.rows()[0].packets(), 2);
    }

    #[test]
    fn disabled_composition_has_no_runtime_resources_or_publication_path() {
        let plan = plan(2, 1);
        let mut module = TrafficObservationModule::disabled();
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 1).expect("start control"));

        assert!(!module.is_enabled());
        assert!(!module.automation_is_configured());
        assert!(module.snapshot_source().snapshot().is_none());
        assert!(module.automation_journal().is_none());
        assert_eq!(
            module.configure_automation(
                automation_limits(1, 1),
                Arc::clone(&control),
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::new(AtomicUsize::new(0)),
                )),
            ),
            Err(TrafficObservationError::Disabled)
        );
        assert_eq!(
            module.replace_automation_policy(Box::new(FixedPolicy::new(
                AutomationPolicyDecision::NoChange,
                Arc::new(AtomicUsize::new(0)),
            ))),
            Err(TrafficObservationError::Disabled)
        );
        assert_eq!(
            module.observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 1),
                Duration::from_secs(1),
            ),
            Err(TrafficObservationError::Disabled)
        );
        assert_eq!(
            module.replace_plan(plan, Duration::from_secs(1)),
            Err(TrafficObservationError::Disabled)
        );
    }

    #[test]
    fn automation_configuration_rejects_invalid_lifecycle_transitions() {
        let plan = plan(11, 1);
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 1).expect("start control"));
        let mut module =
            TrafficObservationModule::enabled(plan, statistics_limits(), Duration::ZERO).unwrap();

        assert_eq!(
            module.replace_automation_policy(Box::new(FixedPolicy::new(
                AutomationPolicyDecision::NoChange,
                Arc::new(AtomicUsize::new(0)),
            ))),
            Err(TrafficObservationError::AutomationNotConfigured)
        );
        assert_eq!(
            module
                .configure_automation(
                    automation_limits(1, 1),
                    Arc::clone(&control),
                    Box::new(FixedPolicy::new(
                        AutomationPolicyDecision::NoChange,
                        Arc::new(AtomicUsize::new(0)),
                    )),
                )
                .unwrap(),
            AutomationPolicyRevision::INITIAL
        );
        assert_eq!(
            module.configure_automation(
                automation_limits(1, 1),
                control,
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::new(AtomicUsize::new(0)),
                )),
            ),
            Err(TrafficObservationError::AutomationAlreadyConfigured)
        );
    }

    #[test]
    fn accepted_proposal_is_provenance_bound_and_enters_runtime_control_once() {
        let plan = plan(3, 7);
        let (intent_tx, intent_rx) = mpsc::channel();
        let control = Arc::new(
            RuntimeControl::start(RecordingDispatcher { intent_tx }, 4).expect("start control"),
        );
        control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap()
            .wait()
            .unwrap();
        assert_eq!(
            intent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            RuntimeIntent::Running {
                reason: Reason::Boot
            }
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        assert_eq!(
            module
                .configure_automation(
                    automation_limits(5, 8),
                    Arc::clone(&control),
                    Box::new(FixedPolicy::new(
                        AutomationPolicyDecision::Propose(AutomationActionRequest::new(
                            AutomationRuleId::new(9).unwrap(),
                            AutomationAction::ResyncAddresses,
                        )),
                        Arc::clone(&calls),
                    )),
                )
                .unwrap(),
            AutomationPolicyRevision::INITIAL
        );

        let primed = publication(
            module
                .observe(
                    sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                    Duration::from_secs(1),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(primed.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::ObservationNotContinuous)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let published = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(3),
                )
                .unwrap(),
        );
        let record = recorded(published.automation());
        assert_eq!(
            record.disposition(),
            AutomationDecisionDisposition::Accepted
        );
        let proposal = record.proposal().unwrap();
        assert_eq!(proposal.rule().get(), 9);
        assert_eq!(proposal.action(), AutomationAction::ResyncAddresses);
        assert_eq!(proposal.context().policy_revision().get(), 1);
        assert_eq!(proposal.context().statistics_revision().get(), 2);
        assert_eq!(proposal.context().generation(), generation(7));
        assert_eq!(
            proposal.context().capture_path(),
            CapturePathId::XtablesTproxy
        );
        assert_eq!(proposal.context().epoch(), StatisticsEpoch::INITIAL);
        assert_eq!(proposal.context().sampled_at(), Duration::from_secs(2));
        assert_eq!(proposal.context().evaluated_at(), Duration::from_secs(3));
        assert_eq!(
            intent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            RuntimeIntent::ResyncAddresses {
                reason: Reason::Automation
            }
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn accepted_proposals_are_deduplicated_across_new_statistics_revisions() {
        let plan = plan(4, 1);
        let (intent_tx, intent_rx) = mpsc::channel();
        let control = Arc::new(
            RuntimeControl::start(RecordingDispatcher { intent_tx }, 4).expect("start control"),
        );
        control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap()
            .wait()
            .unwrap();
        intent_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let decision = AutomationPolicyDecision::Propose(AutomationActionRequest::new(
            AutomationRuleId::new(10).unwrap(),
            AutomationAction::Reload,
        ));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(5, 4),
                control,
                Box::new(FixedPolicy::new(decision, Arc::clone(&calls))),
            )
            .unwrap();
        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();

        let accepted = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(accepted.automation()).disposition(),
            AutomationDecisionDisposition::Accepted
        );
        assert_eq!(
            intent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            RuntimeIntent::Reload {
                reason: Reason::Automation
            }
        );

        let duplicate = publication(
            module
                .observe(
                    sample(&plan, 3, 3, TrafficSampleSignal::Continuous, 12),
                    Duration::from_secs(3),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(duplicate.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::DuplicateProposal)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(intent_rx.try_recv().is_err());
    }

    #[test]
    fn accepted_action_eviction_is_independent_from_decision_journal_retention() {
        let plan = plan(12, 1);
        let (intent_tx, intent_rx) = mpsc::channel();
        let control = Arc::new(
            RuntimeControl::start(RecordingDispatcher { intent_tx }, 4).expect("start control"),
        );
        control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap()
            .wait()
            .unwrap();
        intent_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let first_rule = AutomationRuleId::new(21).unwrap();
        let second_rule = AutomationRuleId::new(22).unwrap();
        let request = |rule| {
            AutomationPolicyDecision::Propose(AutomationActionRequest::new(
                rule,
                AutomationAction::Reload,
            ))
        };
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits_with_capacities(5, 8, 1),
                control,
                Box::new(SequencedPolicy::new([
                    request(first_rule),
                    request(second_rule),
                    request(first_rule),
                ])),
            )
            .unwrap();

        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        for (sequence, rule) in [(2, first_rule), (3, second_rule), (4, first_rule)] {
            let observed = publication(
                module
                    .observe(
                        sample(
                            &plan,
                            sequence,
                            sequence,
                            TrafficSampleSignal::Continuous,
                            sequence + 9,
                        ),
                        Duration::from_secs(sequence),
                    )
                    .unwrap(),
            );
            let record = recorded(observed.automation());
            assert_eq!(record.sequence().get(), sequence);
            assert_eq!(record.proposal().unwrap().rule(), rule);
            assert_eq!(
                record.disposition(),
                AutomationDecisionDisposition::Accepted
            );
            assert_eq!(
                intent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                RuntimeIntent::Reload {
                    reason: Reason::Automation
                }
            );
        }

        let journal = module.automation_journal().unwrap();
        assert_eq!(journal.records().len(), 4);
        assert_eq!(journal.records()[0].sequence().get(), 1);
        assert_eq!(journal.latest_sequence().unwrap().get(), 4);
    }

    #[test]
    fn successor_generation_publishes_immediately_and_opens_a_new_dedup_domain() {
        let first = plan(9, 1);
        let (intent_tx, intent_rx) = mpsc::channel();
        let control = Arc::new(
            RuntimeControl::start(RecordingDispatcher { intent_tx }, 4).expect("start control"),
        );
        control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap()
            .wait()
            .unwrap();
        intent_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let decision = AutomationPolicyDecision::Propose(AutomationActionRequest::new(
            AutomationRuleId::new(12).unwrap(),
            AutomationAction::Reload,
        ));
        let mut module =
            TrafficObservationModule::enabled(first.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        let source = module.snapshot_source();
        module
            .configure_automation(
                automation_limits(5, 8),
                Arc::clone(&control),
                Box::new(FixedPolicy::new(decision, Arc::new(AtomicUsize::new(0)))),
            )
            .unwrap();
        module
            .observe(
                sample(&first, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let accepted = publication(
            module
                .observe(
                    sample(&first, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(accepted.automation()).disposition(),
            AutomationDecisionDisposition::Accepted
        );
        intent_rx.recv_timeout(Duration::from_secs(1)).unwrap();

        let successor = plan(10, 2);
        let replacement = module
            .replace_plan(successor.clone(), Duration::from_secs(3))
            .unwrap();
        let replacement_snapshot = replacement.snapshot();
        assert!(Arc::ptr_eq(
            &replacement_snapshot,
            &source.snapshot().unwrap()
        ));
        assert_eq!(replacement_snapshot.generation(), generation(2));
        assert_eq!(replacement_snapshot.loss(), StatisticsLoss::PlanReplaced);
        assert_eq!(
            replacement_snapshot.source_state(),
            TrafficStatisticsSourceState::AwaitingBaseline
        );
        let replacement_decision = recorded(replacement.automation());
        assert_eq!(replacement_decision.sequence().get(), 3);
        assert_eq!(replacement_decision.context().generation(), generation(2));
        assert_eq!(replacement_decision.context().epoch().get(), 2);
        assert_eq!(
            replacement_decision.disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::ObservationNotContinuous)
        );

        module
            .observe(
                sample(&successor, 1, 4, TrafficSampleSignal::Continuous, 20),
                Duration::from_secs(4),
            )
            .unwrap();
        let successor_accepted = publication(
            module
                .observe(
                    sample(&successor, 2, 5, TrafficSampleSignal::Continuous, 21),
                    Duration::from_secs(5),
                )
                .unwrap(),
        );
        let proposal = recorded(successor_accepted.automation())
            .proposal()
            .unwrap();
        assert_eq!(proposal.context().generation(), generation(2));
        assert_eq!(proposal.context().epoch().get(), 2);
        assert_eq!(
            intent_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            RuntimeIntent::Reload {
                reason: Reason::Automation
            }
        );
    }

    #[test]
    fn stale_discontinuous_and_clock_inconsistent_snapshots_bypass_the_policy() {
        let plan = plan(5, 1);
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 4).expect("start control"));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(2, 8),
                control,
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::clone(&calls),
                )),
            )
            .unwrap();

        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let stale = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(5),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(stale.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::StaleSnapshot)
        );

        let loss = publication(
            module
                .observe(
                    sample(
                        &plan,
                        3,
                        3,
                        TrafficSampleSignal::Loss(flux_core::TrafficReportedLoss::Unknown),
                        12,
                    ),
                    Duration::from_secs(3),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(loss.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::ObservationNotContinuous)
        );

        let future = publication(
            module
                .observe(
                    sample(&plan, 4, 4, TrafficSampleSignal::Continuous, 13),
                    Duration::from_secs(3),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(future.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::EvaluationBeforeSample)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn stopped_runtime_rejects_before_calling_the_policy() {
        let plan = plan(13, 1);
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 4).expect("start control"));
        control
            .submit(RuntimeIntent::Stopped {
                reason: Reason::UserControl,
            })
            .unwrap()
            .wait()
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(5, 4),
                Arc::clone(&control),
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::Propose(AutomationActionRequest::new(
                        AutomationRuleId::new(23).unwrap(),
                        AutomationAction::Reload,
                    )),
                    Arc::clone(&calls),
                )),
            )
            .unwrap();

        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let rejected = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        let record = recorded(rejected.automation());
        assert_eq!(record.proposal(), None);
        assert_eq!(
            record.disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::RuntimeNotRunning)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            control.snapshot().administrative_state,
            AdministrativeState::Stopped
        );
    }

    #[test]
    fn policy_replacement_advances_daemon_owned_revision_and_journal_is_bounded() {
        let plan = plan(6, 1);
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 4).expect("start control"));
        control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap()
            .wait()
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(5, 2),
                control,
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::clone(&calls),
                )),
            )
            .unwrap();
        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let first = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(first.automation())
                .context()
                .policy_revision()
                .get(),
            1
        );

        assert_eq!(
            module
                .replace_automation_policy(Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::clone(&calls),
                )))
                .unwrap()
                .get(),
            2
        );
        let second = publication(
            module
                .observe(
                    sample(&plan, 3, 3, TrafficSampleSignal::Continuous, 12),
                    Duration::from_secs(3),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(second.automation())
                .context()
                .policy_revision()
                .get(),
            2
        );

        let journal = module.automation_journal().unwrap();
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.records()[0].sequence().get(), 2);
        assert_eq!(journal.records()[1].sequence().get(), 3);
        assert_eq!(journal.latest_sequence().unwrap().get(), 3);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn full_runtime_queue_is_a_recorded_rejection_without_blocking_observation() {
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let control = Arc::new(
            RuntimeControl::start(
                BlockingFirstDispatcher {
                    started_tx,
                    release_rx,
                    blocked_once: false,
                },
                1,
            )
            .expect("start control"),
        );
        let first = control
            .submit(RuntimeIntent::Running {
                reason: Reason::Boot,
            })
            .unwrap();
        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first dispatch started");
        let queued = control
            .submit(RuntimeIntent::Reload {
                reason: Reason::UserControl,
            })
            .unwrap();

        let plan = plan(7, 1);
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(5, 4),
                Arc::clone(&control),
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::Propose(AutomationActionRequest::new(
                        AutomationRuleId::new(11).unwrap(),
                        AutomationAction::Reload,
                    )),
                    Arc::new(AtomicUsize::new(0)),
                )),
            )
            .unwrap();
        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let rejected = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        assert_eq!(
            recorded(rejected.automation()).disposition(),
            AutomationDecisionDisposition::Rejected(AutomationRejection::ControlQueueFull)
        );

        release_tx.send(()).unwrap();
        first.wait().unwrap();
        queued.wait().unwrap();
    }

    #[test]
    fn absolute_limits_and_checked_policy_or_decision_exhaustion_are_explicit() {
        assert!(AutomationLimits::new(Duration::ZERO, 0, 1).is_none());
        assert!(AutomationLimits::new(Duration::ZERO, 1, 0).is_none());
        assert!(
            AutomationLimits::new(
                Duration::ZERO,
                MAX_AUTOMATION_DECISION_JOURNAL_ENTRIES + 1,
                1,
            )
            .is_none()
        );
        assert!(
            AutomationLimits::new(
                Duration::ZERO,
                1,
                MAX_AUTOMATION_ACCEPTED_ACTION_ENTRIES + 1,
            )
            .is_none()
        );

        let plan = plan(8, 1);
        let control = Arc::new(RuntimeControl::start(NoopDispatcher, 1).expect("start control"));
        let calls = Arc::new(AtomicUsize::new(0));
        let mut module =
            TrafficObservationModule::enabled(plan.clone(), statistics_limits(), Duration::ZERO)
                .unwrap();
        module
            .configure_automation(
                automation_limits(5, 1),
                control,
                Box::new(FixedPolicy::new(
                    AutomationPolicyDecision::NoChange,
                    Arc::clone(&calls),
                )),
            )
            .unwrap();
        let automation = module
            .enabled
            .as_mut()
            .unwrap()
            .automation
            .as_mut()
            .unwrap();
        automation.revision = AutomationPolicyRevision(NonZeroU64::new(u64::MAX).unwrap());
        assert_eq!(
            module.replace_automation_policy(Box::new(FixedPolicy::new(
                AutomationPolicyDecision::NoChange,
                Arc::clone(&calls),
            ))),
            Err(TrafficObservationError::PolicyRevisionExhausted)
        );
        module
            .enabled
            .as_mut()
            .unwrap()
            .automation
            .as_mut()
            .unwrap()
            .next_sequence = None;

        module
            .observe(
                sample(&plan, 1, 1, TrafficSampleSignal::Continuous, 10),
                Duration::from_secs(1),
            )
            .unwrap();
        let exhausted = publication(
            module
                .observe(
                    sample(&plan, 2, 2, TrafficSampleSignal::Continuous, 11),
                    Duration::from_secs(2),
                )
                .unwrap(),
        );
        assert_eq!(
            exhausted.automation(),
            &AutomationEvaluation::DecisionSequenceExhausted
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    struct FixedPolicy {
        decision: AutomationPolicyDecision,
        calls: Arc<AtomicUsize>,
    }

    impl FixedPolicy {
        fn new(decision: AutomationPolicyDecision, calls: Arc<AtomicUsize>) -> Self {
            Self { decision, calls }
        }
    }

    impl AutomationPolicy for FixedPolicy {
        fn evaluate(&mut self, _snapshot: &TrafficAggregateSnapshot) -> AutomationPolicyDecision {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.decision
        }
    }

    struct SequencedPolicy {
        decisions: VecDeque<AutomationPolicyDecision>,
    }

    impl SequencedPolicy {
        fn new(decisions: impl IntoIterator<Item = AutomationPolicyDecision>) -> Self {
            Self {
                decisions: decisions.into_iter().collect(),
            }
        }
    }

    impl AutomationPolicy for SequencedPolicy {
        fn evaluate(&mut self, _snapshot: &TrafficAggregateSnapshot) -> AutomationPolicyDecision {
            self.decisions
                .pop_front()
                .expect("test policy has one decision per reporting snapshot")
        }
    }

    struct RecordingDispatcher {
        intent_tx: mpsc::Sender<RuntimeIntent>,
    }

    impl RuntimeDispatcher for RecordingDispatcher {
        fn execute(
            &mut self,
            intent: &RuntimeIntent,
        ) -> Result<DispatcherCompletion, ControlError> {
            self.intent_tx.send(*intent).expect("record intent");
            Ok(DispatcherCompletion::Completed)
        }
    }

    struct NoopDispatcher;

    impl RuntimeDispatcher for NoopDispatcher {
        fn execute(
            &mut self,
            _intent: &RuntimeIntent,
        ) -> Result<DispatcherCompletion, ControlError> {
            Ok(DispatcherCompletion::Completed)
        }
    }

    struct BlockingFirstDispatcher {
        started_tx: mpsc::Sender<()>,
        release_rx: mpsc::Receiver<()>,
        blocked_once: bool,
    }

    impl RuntimeDispatcher for BlockingFirstDispatcher {
        fn execute(
            &mut self,
            _intent: &RuntimeIntent,
        ) -> Result<DispatcherCompletion, ControlError> {
            if !self.blocked_once {
                self.blocked_once = true;
                self.started_tx.send(()).expect("signal dispatch start");
                self.release_rx.recv().expect("release first dispatch");
            }
            Ok(DispatcherCompletion::Completed)
        }
    }
}
