use std::sync::{Arc, RwLock};

use flux_core::GenerationId;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    pub revision: u64,
    pub phase: RuntimePhase,
    pub capture: RuntimeCaptureState,
    pub engine: RuntimeEngineState,
    pub verification: RuntimeVerificationState,
    pub generation: Option<GenerationId>,
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
            generation: None,
            last_error: None,
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
            generation: GenerationId::new(7),
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
            generation: None,
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
            generation: GenerationId::new(7),
            last_error: None,
        });

        source.publish(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Verifying,
            capture: RuntimeCaptureState::Published,
            engine: RuntimeEngineState::Ready,
            verification: RuntimeVerificationState::FunctionalPassed,
            generation: GenerationId::new(7),
            last_error: None,
        });

        let snapshot = source.snapshot();
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            snapshot.verification,
            RuntimeVerificationState::FunctionalPassed
        );
    }
}
