use std::sync::{Arc, RwLock};

use flux_core::GenerationId;
use serde::{Deserialize, Serialize};

use crate::generation_engine_config::{CapturePathDecision, CapturePathSelection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimePhase {
    Unknown,
    Bootstrapping,
    Stopped,
    Preparing,
    Activating,
    Verifying,
    Running,
    Degraded,
    Repairing,
    Stopping,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeCaptureState {
    Unknown,
    Detached,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeEngineState {
    Unknown,
    Stopped,
    Starting,
    Ready,
    Exited,
    BackingOff,
    Stopping,
    Failed,
}

/// The strongest capture verification currently associated with the observed runtime.
///
/// `StructuralOnly` is the conservative baseline: it means no functional pass currently
/// authorizes publication for this observation. It does not by itself claim that structural
/// verification has completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeVerificationState {
    StructuralOnly,
    FunctionalPending,
    FunctionalPassed,
    FunctionalFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFailure {
    pub operation: String,
    pub message: String,
    pub recovery: String,
}

/// One immutable runtime Generation and the Capture Path decision that authorized it.
///
/// Keeping these facts in one value makes an unpaired Generation or selection unrepresentable.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeGenerationBinding {
    pub(crate) generation: GenerationId,
    pub(crate) capture_path_selection: CapturePathSelection,
}

impl RuntimeGenerationBinding {
    #[must_use]
    pub const fn new(
        generation: GenerationId,
        capture_path_selection: CapturePathSelection,
    ) -> Self {
        Self {
            generation,
            capture_path_selection,
        }
    }

    #[must_use]
    pub const fn generation(self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub const fn capture_path_selection(self) -> CapturePathSelection {
        self.capture_path_selection
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    pub revision: u64,
    pub phase: RuntimePhase,
    pub capture: RuntimeCaptureState,
    pub engine: RuntimeEngineState,
    pub verification: RuntimeVerificationState,
    pub active_generation: Option<RuntimeGenerationBinding>,
    /// Latest completed selection evaluation, which may describe an attempted successor.
    pub latest_capture_path_decision: Option<CapturePathDecision>,
    pub last_error: Option<RuntimeFailure>,
}

impl RuntimeSnapshot {
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            revision: 0,
            phase: RuntimePhase::Unknown,
            capture: RuntimeCaptureState::Unknown,
            engine: RuntimeEngineState::Unknown,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: None,
            latest_capture_path_decision: None,
            last_error: None,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> Option<GenerationId> {
        match self.active_generation {
            Some(binding) => Some(binding.generation()),
            None => None,
        }
    }

    #[must_use]
    pub const fn active_capture_path_selection(&self) -> Option<CapturePathSelection> {
        match self.active_generation {
            Some(binding) => Some(binding.capture_path_selection()),
            None => None,
        }
    }
}

impl Default for RuntimeSnapshot {
    fn default() -> Self {
        Self::unknown()
    }
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshotSource {
    current: Arc<RwLock<Arc<RuntimeSnapshot>>>,
}

impl RuntimeSnapshotSource {
    #[must_use]
    pub fn new(mut initial: RuntimeSnapshot) -> Self {
        initial.revision = 0;
        Self {
            current: Arc::new(RwLock::new(Arc::new(initial))),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        match self.current.read() {
            Ok(snapshot) => Arc::clone(&snapshot),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// Atomically publishes a changed whole snapshot with the next source-local revision.
    ///
    /// The revision supplied on `snapshot` is replaced so concurrent publishers
    /// cannot create duplicate or out-of-order revisions. Re-publishing the
    /// same observation is a no-op.
    pub fn publish(&self, mut snapshot: RuntimeSnapshot) {
        let mut current = match self.current.write() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        snapshot.revision = current.revision;
        if current.as_ref() == &snapshot {
            return;
        }
        snapshot.revision = current.revision.saturating_add(1);
        *current = Arc::new(snapshot);
    }
}

impl Default for RuntimeSnapshotSource {
    fn default() -> Self {
        Self::new(RuntimeSnapshot::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation_engine_config::{
        test_xtables_capture_path_decision, test_xtables_capture_path_selection,
    };

    #[test]
    fn cloned_sources_publish_whole_immutable_snapshots() {
        let source = RuntimeSnapshotSource::default();
        let reader = source.clone();
        let previous = reader.snapshot();
        let replacement = RuntimeSnapshot {
            revision: 900,
            phase: RuntimePhase::Running,
            capture: RuntimeCaptureState::Published,
            engine: RuntimeEngineState::Ready,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: Some(RuntimeGenerationBinding::new(
                GenerationId::new(7).expect("nonzero Generation"),
                test_xtables_capture_path_selection(),
            )),
            latest_capture_path_decision: Some(test_xtables_capture_path_decision()),
            last_error: None,
        };

        source.publish(replacement.clone());

        assert_eq!(previous.as_ref(), &RuntimeSnapshot::unknown());
        let latest = reader.snapshot();
        assert_eq!(latest.revision, 1);
        assert_eq!(latest.phase, replacement.phase);
    }

    #[test]
    fn concurrent_publishers_receive_one_monotonic_revision_sequence() {
        let source = RuntimeSnapshotSource::default();
        let first = source.clone();
        let second = source.clone();
        let publish = |source: RuntimeSnapshotSource, phase| {
            std::thread::spawn(move || {
                source.publish(RuntimeSnapshot {
                    revision: 0,
                    phase,
                    ..RuntimeSnapshot::unknown()
                });
            })
        };
        let first = publish(first, RuntimePhase::Preparing);
        let second = publish(second, RuntimePhase::Activating);

        first.join().expect("first publisher");
        second.join().expect("second publisher");

        assert_eq!(source.snapshot().revision, 2);
    }

    #[test]
    fn identical_observation_does_not_advance_the_runtime_revision() {
        let source = RuntimeSnapshotSource::default();
        let stopped = RuntimeSnapshot {
            revision: 900,
            phase: RuntimePhase::Stopped,
            capture: RuntimeCaptureState::Detached,
            engine: RuntimeEngineState::Stopped,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: None,
            latest_capture_path_decision: None,
            last_error: None,
        };

        source.publish(stopped.clone());
        source.publish(stopped);

        assert_eq!(source.snapshot().revision, 1);
    }

    #[test]
    fn verification_only_change_advances_the_runtime_revision() {
        let source = RuntimeSnapshotSource::new(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Verifying,
            capture: RuntimeCaptureState::Published,
            engine: RuntimeEngineState::Ready,
            verification: RuntimeVerificationState::FunctionalPending,
            active_generation: Some(RuntimeGenerationBinding::new(
                GenerationId::new(7).expect("nonzero Generation"),
                test_xtables_capture_path_selection(),
            )),
            latest_capture_path_decision: Some(test_xtables_capture_path_decision()),
            last_error: None,
        });

        source.publish(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Verifying,
            capture: RuntimeCaptureState::Published,
            engine: RuntimeEngineState::Ready,
            verification: RuntimeVerificationState::FunctionalPassed,
            active_generation: Some(RuntimeGenerationBinding::new(
                GenerationId::new(7).expect("nonzero Generation"),
                test_xtables_capture_path_selection(),
            )),
            latest_capture_path_decision: Some(test_xtables_capture_path_decision()),
            last_error: None,
        });

        let snapshot = source.snapshot();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::FunctionalPassed
        );
        assert_eq!(
            snapshot
                .active_generation
                .map(RuntimeGenerationBinding::generation),
            GenerationId::new(7)
        );
    }
}
