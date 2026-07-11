use std::error::Error;
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use flux_core::{ControlError, LegacyDispatcher, LegacyIntent, Reason};
use flux_platform::{
    DispatcherPhaseCommand, PhaseDispatcherError, PhaseDispatcherPaths, ProcessPhaseDispatcher,
};

use crate::{
    CaptureObservation, DesiredEngine, EngineManifest, EngineManifestError, EnginePhase,
    EngineReport, EngineSnapshot, EngineSpec, EngineSupervisor, EngineSupervisorError,
    RuntimeCaptureState, RuntimeEngineState, RuntimeFailure, RuntimePhase, RuntimeSnapshot,
    RuntimeSnapshotSource,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublishedRuntimeState {
    Running { generation: NonZeroU32 },
    Stopped,
    Failed,
}

#[derive(Clone)]
pub(crate) struct PreparedGeneration {
    id: NonZeroU32,
    spec: EngineSpec,
}

pub(crate) trait LegacyRuntimeWriter: Send + 'static {
    type Error: Error + Send + Sync + 'static;

    fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error>;
    fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error>;
    fn capture_stop(&mut self) -> Result<(), Self::Error>;
    fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error>;
    fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error>;
    fn resync_addresses(&mut self) -> Result<(), Self::Error>;
}

pub(crate) trait EngineRuntime: Send + 'static {
    fn reconcile(
        &mut self,
        desired: DesiredEngine<'_>,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError>;

    fn snapshot(&self) -> Arc<EngineSnapshot> {
        Arc::new(EngineSnapshot::default())
    }
}

#[derive(Debug)]
pub(crate) enum ProcessRuntimeWriterError {
    Phase(PhaseDispatcherError),
    Manifest {
        path: PathBuf,
        source: Box<EngineManifestError>,
    },
}

impl fmt::Display for ProcessRuntimeWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Phase(error) => error.fmt(formatter),
            Self::Manifest { path, source } => {
                write!(
                    formatter,
                    "cannot load engine manifest {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for ProcessRuntimeWriterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Phase(error) => Some(error),
            Self::Manifest { source, .. } => Some(source),
        }
    }
}

pub(crate) struct ProcessRuntimeWriter {
    dispatcher: ProcessPhaseDispatcher,
    manifest_path: PathBuf,
}

impl ProcessRuntimeWriter {
    pub(crate) fn new(paths: PhaseDispatcherPaths, manifest_path: impl AsRef<Path>) -> Self {
        Self {
            dispatcher: ProcessPhaseDispatcher::new(paths),
            manifest_path: manifest_path.as_ref().to_path_buf(),
        }
    }

    fn execute_phase(
        &mut self,
        command: DispatcherPhaseCommand,
    ) -> Result<(), ProcessRuntimeWriterError> {
        self.dispatcher
            .execute(command)
            .map_err(ProcessRuntimeWriterError::Phase)
    }
}

impl LegacyRuntimeWriter for ProcessRuntimeWriter {
    type Error = ProcessRuntimeWriterError;

    fn prepare(&mut self, _reason: Reason) -> Result<PreparedGeneration, Self::Error> {
        self.execute_phase(DispatcherPhaseCommand::Prepare)?;
        let prepared = EngineManifest::load_prepared(&self.manifest_path).map_err(|source| {
            ProcessRuntimeWriterError::Manifest {
                path: self.manifest_path.clone(),
                source: Box::new(source),
            }
        })?;
        Ok(PreparedGeneration {
            id: prepared.generation(),
            spec: prepared.into_engine(),
        })
    }

    fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        self.dispatcher
            .execute_for_generation(DispatcherPhaseCommand::CaptureStart, generation.id)
            .map_err(ProcessRuntimeWriterError::Phase)
    }

    fn capture_stop(&mut self) -> Result<(), Self::Error> {
        self.execute_phase(DispatcherPhaseCommand::CaptureStop)
    }

    fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
        self.dispatcher
            .execute_for_generation(DispatcherPhaseCommand::CaptureVerify, generation.id)
            .map_err(ProcessRuntimeWriterError::Phase)
    }

    fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
        let command = match phase {
            PublishedRuntimeState::Running { generation } => {
                return self
                    .dispatcher
                    .execute_for_generation(DispatcherPhaseCommand::StateRunning, generation)
                    .map_err(ProcessRuntimeWriterError::Phase);
            }
            PublishedRuntimeState::Stopped => DispatcherPhaseCommand::StateStopped,
            PublishedRuntimeState::Failed => DispatcherPhaseCommand::StateFailed,
        };
        self.execute_phase(command)
    }

    fn resync_addresses(&mut self) -> Result<(), Self::Error> {
        self.execute_phase(DispatcherPhaseCommand::AddressResync)
    }
}

impl EngineRuntime for EngineSupervisor {
    fn reconcile(
        &mut self,
        desired: DesiredEngine<'_>,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError> {
        EngineSupervisor::reconcile(self, desired, capture)
    }

    fn snapshot(&self) -> Arc<EngineSnapshot> {
        EngineSupervisor::snapshot(self)
    }
}

enum RuntimeOwnership {
    Stopped,
    Engine {
        generation: Box<PreparedGeneration>,
        capture: CaptureObservation,
    },
    CaptureRepairPending {
        generation: Box<PreparedGeneration>,
    },
    DetachPending {
        generation: Box<PreparedGeneration>,
        terminal: PublishedRuntimeState,
    },
    Retiring {
        generation: Box<PreparedGeneration>,
        terminal: PublishedRuntimeState,
    },
}

enum RetirementProgress {
    Settled,
    Pending(EngineReport),
}

pub(crate) struct RuntimeCoordinator<W, E = EngineSupervisor> {
    writer: W,
    engine: E,
    ownership: RuntimeOwnership,
    maintenance_interval: Duration,
    runtime: RuntimeSnapshotSource,
    pending_publication: Option<PublishedRuntimeState>,
}

impl<W, E> RuntimeCoordinator<W, E>
where
    W: LegacyRuntimeWriter,
    E: EngineRuntime,
{
    pub(crate) fn with_dependencies(writer: W, engine: E, maintenance_interval: Duration) -> Self {
        let runtime = RuntimeSnapshotSource::new(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Stopped,
            capture: RuntimeCaptureState::Detached,
            engine: RuntimeEngineState::Stopped,
            generation: None,
            last_error: None,
        });
        Self {
            writer,
            engine,
            ownership: RuntimeOwnership::Stopped,
            maintenance_interval,
            runtime,
            pending_publication: None,
        }
    }

    pub(crate) fn runtime_snapshot_source(&self) -> RuntimeSnapshotSource {
        self.runtime.clone()
    }

    fn start(&mut self, reason: Reason) -> Result<(), ControlError> {
        if matches!(self.ownership, RuntimeOwnership::Engine { .. }) {
            return self.reload(reason);
        }
        if matches!(
            self.ownership,
            RuntimeOwnership::CaptureRepairPending { .. }
                | RuntimeOwnership::DetachPending { .. }
                | RuntimeOwnership::Retiring { .. }
        ) {
            return Err(retirement_pending_error("start runtime"));
        }
        self.publish_runtime(
            RuntimePhase::Preparing,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            None,
            None,
        );
        let generation = self.writer.prepare(reason).map_err(|source| {
            runtime_writer_error(
                "prepare runtime generation",
                source,
                "leave the current generation untouched and repair preparation inputs",
            )
        })?;
        self.activate_prepared(generation)
    }

    fn reload(&mut self, reason: Reason) -> Result<(), ControlError> {
        if matches!(
            self.ownership,
            RuntimeOwnership::CaptureRepairPending { .. }
                | RuntimeOwnership::DetachPending { .. }
                | RuntimeOwnership::Retiring { .. }
        ) {
            return Err(retirement_pending_error("reload runtime"));
        }
        let (capture_state, active_generation) = self.ownership_summary();
        self.publish_runtime(
            RuntimePhase::Preparing,
            capture_state,
            self.observed_engine_state(),
            active_generation,
            None,
        );
        let candidate = self.writer.prepare(reason).map_err(|source| {
            runtime_writer_error(
                "prepare replacement runtime generation",
                source,
                "leave the active generation untouched and repair preparation inputs",
            )
        })?;
        let candidate_id = candidate.id;
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (previous, capture) = match ownership {
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Stopped => return self.activate_prepared(candidate),
            RuntimeOwnership::Retiring {
                generation,
                terminal,
            } => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    terminal,
                };
                return Err(retirement_pending_error("reload runtime"));
            }
            RuntimeOwnership::DetachPending {
                generation,
                terminal,
            } => {
                self.ownership = RuntimeOwnership::DetachPending {
                    generation,
                    terminal,
                };
                return Err(retirement_pending_error("reload runtime"));
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
                return Err(retirement_pending_error("reload runtime"));
            }
        };

        if capture == CaptureObservation::Published
            && let Err(source) = self.writer.capture_stop()
        {
            self.ownership = RuntimeOwnership::CaptureRepairPending {
                generation: previous,
            };
            return Err(runtime_writer_error(
                "detach active capture before replacement",
                source,
                "retain the active proxy engine and retry capture detachment",
            ));
        }
        self.ownership = RuntimeOwnership::Engine {
            generation: previous.clone(),
            capture: CaptureObservation::Detached,
        };
        match self.activate_prepared(candidate) {
            Ok(()) => Ok(()),
            Err(candidate_failure)
                if matches!(
                    &self.ownership,
                    RuntimeOwnership::Engine {
                        generation,
                        capture: CaptureObservation::Published,
                    } | RuntimeOwnership::DetachPending {
                        generation,
                        terminal: _,
                    } if generation.id == candidate_id
                ) =>
            {
                Err(candidate_failure)
            }
            Err(candidate_failure) => match self.activate_prepared(*previous) {
                Ok(()) => Err(candidate_failure),
                Err(rollback_failure) => Err(self.settle_failed_rollback(rollback_failure)),
            },
        }
    }

    fn activate_prepared(&mut self, generation: PreparedGeneration) -> Result<(), ControlError> {
        self.publish_runtime(
            RuntimePhase::Activating,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Starting,
            Some(u64::from(generation.id.get())),
            None,
        );
        self.ownership = RuntimeOwnership::Engine {
            generation: Box::new(generation.clone()),
            capture: CaptureObservation::Detached,
        };
        let report = self
            .engine
            .reconcile(
                DesiredEngine::Running(&generation.spec),
                CaptureObservation::Detached,
            )
            .map_err(|source| {
                ControlError::runtime(
                    "start proxy engine",
                    source,
                    "keep capture detached and retry engine reconciliation",
                )
            })?;
        if !matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        ) {
            return Err(ControlError::runtime(
                "start proxy engine",
                io::Error::other(format!("engine did not become ready: {report:?}")),
                "keep capture detached and retry after the supervisor settles",
            ));
        }
        if let Err(source) = self.writer.capture_start(&generation) {
            let failure = runtime_writer_error(
                "publish capture",
                source,
                "detach partial capture before retrying activation",
            );
            return Err(self.compensate_failed_activation(generation, failure));
        }
        self.publish_runtime(
            RuntimePhase::Verifying,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(u64::from(generation.id.get())),
            None,
        );
        if let Err(source) = self.writer.verify_capture(&generation) {
            let failure = runtime_writer_error(
                "verify published capture",
                source,
                "detach capture before retiring the proxy engine",
            );
            return Err(self.compensate_failed_activation(generation, failure));
        }
        self.ownership = RuntimeOwnership::Engine {
            generation: Box::new(generation.clone()),
            capture: CaptureObservation::Published,
        };
        self.publish_legacy_state(
            PublishedRuntimeState::Running {
                generation: generation.id,
            },
            "publish running state",
            "retain the verified data path and retry state publication",
        )?;
        self.publish_runtime(
            RuntimePhase::Running,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(u64::from(generation.id.get())),
            None,
        );
        Ok(())
    }

    fn compensate_failed_activation(
        &mut self,
        generation: PreparedGeneration,
        activation_failure: ControlError,
    ) -> ControlError {
        if let Err(source) = self.writer.capture_stop() {
            self.ownership = RuntimeOwnership::DetachPending {
                generation: Box::new(generation),
                terminal: PublishedRuntimeState::Failed,
            };
            return runtime_writer_error(
                "detach failed capture",
                source,
                "retain the proxy engine until capture detachment can be proven",
            );
        }
        match self.reconcile_retirement(
            Box::new(generation),
            PublishedRuntimeState::Failed,
            "stop engine after failed activation",
            "keep capture detached and retry engine cleanup",
        ) {
            Ok(RetirementProgress::Settled) => activation_failure,
            Ok(RetirementProgress::Pending(report)) => ControlError::runtime(
                "stop engine after failed activation",
                io::Error::other(format!("engine cleanup did not settle: {report:?}")),
                "keep capture detached and retry engine cleanup",
            ),
            Err(error) => error,
        }
    }

    fn maintain_runtime(&mut self) -> Result<(), ControlError> {
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (generation, capture) = match ownership {
            RuntimeOwnership::Stopped => {
                self.retry_pending_terminal_publication()?;
                return Ok(());
            }
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Retiring {
                generation,
                terminal,
            } => {
                return match self.reconcile_retirement(
                    generation,
                    terminal,
                    "complete proxy engine retirement",
                    "keep capture detached and retry bounded engine cleanup",
                )? {
                    RetirementProgress::Settled | RetirementProgress::Pending(_) => Ok(()),
                };
            }
            RuntimeOwnership::DetachPending {
                generation,
                terminal,
            } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    terminal,
                    "complete capture detachment",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled | RetirementProgress::Pending(_) => Ok(()),
                };
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                return self.reconcile_capture_repair(generation);
            }
        };
        let report = match self
            .engine
            .reconcile(DesiredEngine::Running(&generation.spec), capture)
        {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                return Err(ControlError::runtime(
                    "maintain proxy engine",
                    source,
                    "preserve current ownership and retry reconciliation",
                ));
            }
        };

        if matches!(report, EngineReport::AwaitingCaptureRemoval { .. }) {
            if capture == CaptureObservation::Published
                && let Err(source) = self.writer.capture_stop()
            {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture,
                };
                return Err(runtime_writer_error(
                    "detach capture after engine exit",
                    source,
                    "retain supervisor ownership and retry capture detachment",
                ));
            }
            let report = match self.engine.reconcile(
                DesiredEngine::Running(&generation.spec),
                CaptureObservation::Detached,
            ) {
                Ok(report) => report,
                Err(source) => {
                    self.ownership = RuntimeOwnership::Engine {
                        generation,
                        capture: CaptureObservation::Detached,
                    };
                    return Err(ControlError::runtime(
                        "restart proxy engine after capture detachment",
                        source,
                        "keep capture detached and retry supervisor reconciliation",
                    ));
                }
            };
            let generation_id = generation.id;
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture: CaptureObservation::Detached,
            };
            if matches!(
                report,
                EngineReport::Started { .. } | EngineReport::NoChange { .. }
            ) {
                return self.restore_capture_after_maintenance();
            }
            self.publish_runtime(
                runtime_phase_for_report(&report),
                RuntimeCaptureState::Detached,
                runtime_engine_for_report(&report),
                Some(u64::from(generation_id.get())),
                None,
            );
            return Ok(());
        }

        let generation_id = generation.id;
        let engine_ready = matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        );
        let pending_running_retry = matches!(
            self.pending_publication,
            Some(PublishedRuntimeState::Running { generation }) if generation == generation_id
        );
        if capture == CaptureObservation::Published
            && engine_ready
            && pending_running_retry
            && let Err(source) = self.writer.verify_capture(&generation)
        {
            self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
            return Err(runtime_writer_error(
                "reverify capture before running publication",
                source,
                "detach and restore the active generation before retrying publication",
            ));
        }
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture,
        };
        if capture == CaptureObservation::Detached && engine_ready {
            self.restore_capture_after_maintenance()?;
        } else {
            if capture == CaptureObservation::Published && engine_ready {
                self.retry_pending_running_publication(generation_id)?;
            }
            self.publish_runtime(
                runtime_phase_for_report(&report),
                runtime_capture_state(capture),
                runtime_engine_for_report(&report),
                Some(u64::from(generation_id.get())),
                None,
            );
        }
        Ok(())
    }

    fn reconcile_capture_repair(
        &mut self,
        generation: Box<PreparedGeneration>,
    ) -> Result<(), ControlError> {
        if let Err(source) = self.writer.capture_stop() {
            self.ownership = RuntimeOwnership::CaptureRepairPending { generation };
            return Err(runtime_writer_error(
                "prove capture detachment before repair",
                source,
                "retain the active proxy engine and retry capture detachment",
            ));
        }
        let report = match self.engine.reconcile(
            DesiredEngine::Running(&generation.spec),
            CaptureObservation::Detached,
        ) {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture: CaptureObservation::Detached,
                };
                return Err(ControlError::runtime(
                    "maintain proxy engine during capture repair",
                    source,
                    "keep capture detached and retry supervisor reconciliation",
                ));
            }
        };
        let generation_id = generation.id;
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture: CaptureObservation::Detached,
        };
        if matches!(
            report,
            EngineReport::Started { .. } | EngineReport::NoChange { .. }
        ) {
            return self.restore_capture_after_maintenance();
        }
        self.publish_runtime(
            runtime_phase_for_report(&report),
            RuntimeCaptureState::Detached,
            runtime_engine_for_report(&report),
            Some(u64::from(generation_id.get())),
            None,
        );
        Ok(())
    }

    fn restore_capture_after_maintenance(&mut self) -> Result<(), ControlError> {
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let RuntimeOwnership::Engine {
            generation,
            capture,
        } = ownership
        else {
            return Err(ControlError::runtime(
                "restore capture",
                io::Error::other("runtime lost its desired engine while restoring capture"),
                "leave capture detached and retry reconciliation",
            ));
        };
        if capture == CaptureObservation::Published {
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture,
            };
            return Ok(());
        }
        if let Err(source) = self.writer.capture_start(&generation) {
            self.ownership = RuntimeOwnership::Engine {
                generation,
                capture,
            };
            return Err(runtime_writer_error(
                "restore capture after engine restart",
                source,
                "keep capture detached and retry publication",
            ));
        }
        self.publish_runtime(
            RuntimePhase::Verifying,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(u64::from(generation.id.get())),
            None,
        );
        if let Err(source) = self.writer.verify_capture(&generation) {
            let failure = runtime_writer_error(
                "verify restored capture",
                source,
                "detach capture before retiring the restarted engine",
            );
            return Err(self.compensate_failed_activation(*generation, failure));
        }
        let generation_id = generation.id;
        self.ownership = RuntimeOwnership::Engine {
            generation,
            capture: CaptureObservation::Published,
        };
        self.publish_legacy_state(
            PublishedRuntimeState::Running {
                generation: generation_id,
            },
            "republish running state",
            "retain the verified path and retry state publication",
        )?;
        self.publish_runtime(
            RuntimePhase::Running,
            RuntimeCaptureState::Published,
            RuntimeEngineState::Ready,
            Some(u64::from(generation_id.get())),
            None,
        );
        Ok(())
    }

    fn stop(&mut self) -> Result<(), ControlError> {
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let (generation, capture) = match ownership {
            RuntimeOwnership::Stopped => {
                self.publish_legacy_state(
                    PublishedRuntimeState::Stopped,
                    "publish stopped state",
                    "retry runtime reconciliation",
                )?;
                self.publish_runtime(
                    RuntimePhase::Stopped,
                    RuntimeCaptureState::Detached,
                    RuntimeEngineState::Stopped,
                    None,
                    None,
                );
                return Ok(());
            }
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (generation, capture),
            RuntimeOwnership::Retiring { generation, .. } => {
                return match self.reconcile_retirement(
                    generation,
                    PublishedRuntimeState::Stopped,
                    "stop proxy engine",
                    "keep capture detached and retry engine reconciliation",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
            RuntimeOwnership::DetachPending { generation, .. } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    PublishedRuntimeState::Stopped,
                    "detach capture",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                return match self.reconcile_pending_detachment(
                    generation,
                    PublishedRuntimeState::Stopped,
                    "detach capture",
                    "retain the proxy engine and retry capture detachment",
                )? {
                    RetirementProgress::Settled => Ok(()),
                    RetirementProgress::Pending(report) => Err(ControlError::runtime(
                        "stop proxy engine",
                        io::Error::other(format!("engine did not stop: {report:?}")),
                        "keep capture detached and retry after the supervisor settles",
                    )),
                };
            }
        };

        self.publish_runtime(
            RuntimePhase::Stopping,
            runtime_capture_state(capture),
            RuntimeEngineState::Stopping,
            Some(u64::from(generation.id.get())),
            None,
        );
        if capture == CaptureObservation::Published
            && let Err(source) = self.writer.capture_stop()
        {
            self.ownership = RuntimeOwnership::DetachPending {
                generation,
                terminal: PublishedRuntimeState::Stopped,
            };
            return Err(runtime_writer_error(
                "detach capture",
                source,
                "retain the proxy engine until capture detachment can be proven",
            ));
        }
        match self.reconcile_retirement(
            generation,
            PublishedRuntimeState::Stopped,
            "stop proxy engine",
            "keep capture detached and retry engine reconciliation",
        )? {
            RetirementProgress::Settled => Ok(()),
            RetirementProgress::Pending(report) => Err(ControlError::runtime(
                "stop proxy engine",
                io::Error::other(format!("engine did not stop: {report:?}")),
                "keep capture detached and retry after the supervisor settles",
            )),
        }
    }

    fn reconcile_pending_detachment(
        &mut self,
        generation: Box<PreparedGeneration>,
        terminal: PublishedRuntimeState,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<RetirementProgress, ControlError> {
        if let Err(source) = self.writer.capture_stop() {
            self.ownership = RuntimeOwnership::DetachPending {
                generation,
                terminal,
            };
            return Err(runtime_writer_error(operation, source, recovery));
        }
        self.reconcile_retirement(
            generation,
            terminal,
            "retire proxy engine after capture detachment",
            "keep capture detached and retry bounded engine cleanup",
        )
    }

    fn reconcile_retirement(
        &mut self,
        generation: Box<PreparedGeneration>,
        terminal: PublishedRuntimeState,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<RetirementProgress, ControlError> {
        let generation_id = generation.id;
        let report = match self
            .engine
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
        {
            Ok(report) => report,
            Err(source) => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    terminal,
                };
                return Err(ControlError::runtime(operation, source, recovery));
            }
        };
        if !matches!(
            report,
            EngineReport::Stopped { .. } | EngineReport::NoChange { .. }
        ) {
            self.ownership = RuntimeOwnership::Retiring {
                generation,
                terminal,
            };
            self.publish_runtime(
                RuntimePhase::Stopping,
                RuntimeCaptureState::Detached,
                runtime_engine_for_report(&report),
                Some(u64::from(generation_id.get())),
                None,
            );
            return Ok(RetirementProgress::Pending(report));
        }

        let (phase, publish_operation, publish_recovery) = match terminal {
            PublishedRuntimeState::Stopped => (
                RuntimePhase::Stopped,
                "publish stopped state",
                "retry state publication while the runtime remains stopped",
            ),
            PublishedRuntimeState::Failed => (
                RuntimePhase::Failed,
                "publish failed state",
                "retry state publication while capture remains detached",
            ),
            PublishedRuntimeState::Running { .. } => {
                self.ownership = RuntimeOwnership::Retiring {
                    generation,
                    terminal,
                };
                return Err(ControlError::runtime(
                    "retire proxy engine",
                    io::Error::other("running is not a valid retirement terminal state"),
                    "retry with stopped or failed terminal publication",
                ));
            }
        };
        self.ownership = RuntimeOwnership::Stopped;
        self.publish_legacy_state(terminal, publish_operation, publish_recovery)?;
        self.publish_runtime(
            phase,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            None,
            None,
        );
        Ok(RetirementProgress::Settled)
    }

    fn settle_failed_rollback(&mut self, rollback_failure: ControlError) -> ControlError {
        let ownership = std::mem::replace(&mut self.ownership, RuntimeOwnership::Stopped);
        let settlement = match ownership {
            RuntimeOwnership::Stopped => self
                .publish_legacy_state(
                    PublishedRuntimeState::Failed,
                    "publish failed state after rollback failure",
                    "retry failed-state publication while capture remains detached",
                )
                .map(|()| RetirementProgress::Settled),
            RuntimeOwnership::Engine {
                generation,
                capture: CaptureObservation::Published,
            } => {
                self.ownership = RuntimeOwnership::Engine {
                    generation,
                    capture: CaptureObservation::Published,
                };
                return rollback_failure_error(rollback_failure);
            }
            RuntimeOwnership::Engine {
                generation,
                capture: CaptureObservation::Detached,
            }
            | RuntimeOwnership::Retiring {
                generation,
                terminal: _,
            } => self.reconcile_retirement(
                generation,
                PublishedRuntimeState::Failed,
                "settle failed rollback",
                "keep capture detached and retry bounded engine cleanup",
            ),
            RuntimeOwnership::DetachPending { generation, .. } => {
                self.ownership = RuntimeOwnership::DetachPending {
                    generation,
                    terminal: PublishedRuntimeState::Failed,
                };
                return rollback_failure_error(rollback_failure);
            }
            RuntimeOwnership::CaptureRepairPending { generation } => {
                self.ownership = RuntimeOwnership::DetachPending {
                    generation,
                    terminal: PublishedRuntimeState::Failed,
                };
                return rollback_failure_error(rollback_failure);
            }
        };
        match settlement {
            Ok(RetirementProgress::Settled | RetirementProgress::Pending(_)) => {
                rollback_failure_error(rollback_failure)
            }
            Err(error) => error,
        }
    }

    fn ownership_summary(&self) -> (RuntimeCaptureState, Option<u64>) {
        match &self.ownership {
            RuntimeOwnership::Stopped => (RuntimeCaptureState::Detached, None),
            RuntimeOwnership::Engine {
                generation,
                capture,
            } => (
                runtime_capture_state(*capture),
                Some(u64::from(generation.id.get())),
            ),
            RuntimeOwnership::DetachPending { generation, .. } => (
                RuntimeCaptureState::Published,
                Some(u64::from(generation.id.get())),
            ),
            RuntimeOwnership::CaptureRepairPending { generation } => (
                RuntimeCaptureState::Published,
                Some(u64::from(generation.id.get())),
            ),
            RuntimeOwnership::Retiring { generation, .. } => (
                RuntimeCaptureState::Detached,
                Some(u64::from(generation.id.get())),
            ),
        }
    }

    fn publish_legacy_state(
        &mut self,
        state: PublishedRuntimeState,
        operation: &'static str,
        recovery: &'static str,
    ) -> Result<(), ControlError> {
        self.pending_publication = Some(state);
        self.writer
            .publish(state)
            .map_err(|source| runtime_writer_error(operation, source, recovery))?;
        self.pending_publication = None;
        Ok(())
    }

    fn retry_pending_running_publication(
        &mut self,
        generation: NonZeroU32,
    ) -> Result<(), ControlError> {
        let Some(state) = self.pending_publication else {
            return Ok(());
        };
        match state {
            PublishedRuntimeState::Running {
                generation: pending_generation,
            } if pending_generation == generation => self.publish_legacy_state(
                state,
                "retry running state publication",
                "retain the verified data path and retry publication",
            ),
            PublishedRuntimeState::Running {
                generation: pending_generation,
            } => Err(ControlError::runtime(
                "retry running state publication",
                io::Error::other(format!(
                    "pending generation {pending_generation} does not match active generation {generation}"
                )),
                "retain the verified data path and reconcile the active generation",
            )),
            PublishedRuntimeState::Stopped | PublishedRuntimeState::Failed => {
                Err(ControlError::runtime(
                    "retry running state publication",
                    io::Error::other("terminal state publication is pending for an active runtime"),
                    "reconcile the active generation before retrying state publication",
                ))
            }
        }
    }

    fn retry_pending_terminal_publication(&mut self) -> Result<(), ControlError> {
        let Some(state) = self.pending_publication else {
            return Ok(());
        };
        let (phase, operation, recovery) = match state {
            PublishedRuntimeState::Stopped => (
                RuntimePhase::Stopped,
                "retry stopped state publication",
                "keep the runtime stopped and retry publication",
            ),
            PublishedRuntimeState::Failed => (
                RuntimePhase::Failed,
                "retry failed state publication",
                "keep capture detached and retry publication",
            ),
            PublishedRuntimeState::Running { generation } => {
                return Err(ControlError::runtime(
                    "retry terminal state publication",
                    io::Error::other(format!(
                        "running state for generation {generation} is pending without runtime ownership"
                    )),
                    "repair runtime ownership before retrying state publication",
                ));
            }
        };
        self.publish_legacy_state(state, operation, recovery)?;
        self.publish_runtime(
            phase,
            RuntimeCaptureState::Detached,
            RuntimeEngineState::Stopped,
            None,
            None,
        );
        Ok(())
    }

    fn observed_engine_state(&self) -> RuntimeEngineState {
        runtime_engine_state(self.engine.snapshot().phase())
    }

    fn publish_runtime(
        &self,
        phase: RuntimePhase,
        capture: RuntimeCaptureState,
        engine: RuntimeEngineState,
        generation: Option<u64>,
        last_error: Option<RuntimeFailure>,
    ) {
        self.runtime.publish(RuntimeSnapshot {
            revision: 0,
            phase,
            capture,
            engine,
            generation,
            last_error,
        });
    }

    fn publish_runtime_error(&self, error: &ControlError) {
        let (capture, generation) = self.ownership_summary();
        let phase = if capture == RuntimeCaptureState::Published {
            RuntimePhase::Degraded
        } else {
            RuntimePhase::Failed
        };
        self.publish_runtime(
            phase,
            capture,
            self.observed_engine_state(),
            generation,
            Some(runtime_failure(error)),
        );
    }
}

impl<W, E> LegacyDispatcher for RuntimeCoordinator<W, E>
where
    W: LegacyRuntimeWriter,
    E: EngineRuntime,
{
    fn execute(&mut self, intent: &LegacyIntent) -> Result<(), ControlError> {
        let result = match *intent {
            LegacyIntent::Running { reason } => self.start(reason),
            LegacyIntent::Reload { reason } => self.reload(reason),
            LegacyIntent::Stopped { .. } => self.stop(),
            LegacyIntent::ResyncAddresses { .. }
                if !matches!(&self.ownership, RuntimeOwnership::Engine { .. }) =>
            {
                Ok(())
            }
            LegacyIntent::ResyncAddresses { .. } => {
                self.writer.resync_addresses().map_err(|source| {
                    runtime_writer_error(
                        "resynchronize addresses",
                        source,
                        "retry after repairing the legacy address writer",
                    )
                })
            }
        };
        if let Err(error) = &result {
            self.publish_runtime_error(error);
        }
        result
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        Some(self.maintenance_interval)
    }

    fn maintain(&mut self) {
        if let Err(error) = self.maintain_runtime() {
            self.publish_runtime_error(&error);
            eprintln!("Flux runtime maintenance failed: {error}");
        }
    }

    fn shutdown(&mut self) {
        const MAX_SHUTDOWN_DRAIN_ATTEMPTS: usize = 10;
        const MAX_SHUTDOWN_RETRY_DELAY: Duration = Duration::from_millis(50);

        let mut last_error = None;
        for attempt in 0..MAX_SHUTDOWN_DRAIN_ATTEMPTS {
            match self.stop() {
                Ok(()) => return,
                Err(error) => last_error = Some(error),
            }
            let cleanup_remains = matches!(
                self.ownership,
                RuntimeOwnership::Engine { .. }
                    | RuntimeOwnership::CaptureRepairPending { .. }
                    | RuntimeOwnership::DetachPending { .. }
                    | RuntimeOwnership::Retiring { .. }
            ) || self.pending_publication.is_some();
            if !cleanup_remains || attempt + 1 == MAX_SHUTDOWN_DRAIN_ATTEMPTS {
                break;
            }
            std::thread::sleep(self.maintenance_interval.min(MAX_SHUTDOWN_RETRY_DELAY));
        }
        if let Some(error) = last_error {
            self.publish_runtime_error(&error);
            eprintln!("Flux runtime shutdown failed: {error}");
        }
    }
}

const fn runtime_capture_state(capture: CaptureObservation) -> RuntimeCaptureState {
    match capture {
        CaptureObservation::Detached => RuntimeCaptureState::Detached,
        CaptureObservation::Published => RuntimeCaptureState::Published,
    }
}

const fn runtime_engine_state(phase: EnginePhase) -> RuntimeEngineState {
    match phase {
        EnginePhase::Stopped => RuntimeEngineState::Stopped,
        EnginePhase::Checking | EnginePhase::Starting => RuntimeEngineState::Starting,
        EnginePhase::Ready => RuntimeEngineState::Ready,
        EnginePhase::AwaitingCaptureRemoval => RuntimeEngineState::Exited,
        EnginePhase::Stopping => RuntimeEngineState::Stopping,
        EnginePhase::BackingOff => RuntimeEngineState::BackingOff,
        EnginePhase::Failed => RuntimeEngineState::Failed,
    }
}

const fn runtime_phase_for_report(report: &EngineReport) -> RuntimePhase {
    match report {
        EngineReport::NoChange { .. } | EngineReport::Started { .. } => RuntimePhase::Running,
        EngineReport::Stopped { .. } => RuntimePhase::Stopped,
        EngineReport::AwaitingCaptureRemoval { .. }
        | EngineReport::Stopping { .. }
        | EngineReport::BackingOff { .. } => RuntimePhase::Repairing,
        EngineReport::Failed { .. } => RuntimePhase::Failed,
    }
}

const fn runtime_engine_for_report(report: &EngineReport) -> RuntimeEngineState {
    match report {
        EngineReport::NoChange { .. } | EngineReport::Started { .. } => RuntimeEngineState::Ready,
        EngineReport::Stopped { .. } => RuntimeEngineState::Stopped,
        EngineReport::AwaitingCaptureRemoval { .. } => RuntimeEngineState::Exited,
        EngineReport::Stopping { .. } => RuntimeEngineState::Stopping,
        EngineReport::BackingOff { .. } => RuntimeEngineState::BackingOff,
        EngineReport::Failed { .. } => RuntimeEngineState::Failed,
    }
}

fn runtime_failure(error: &ControlError) -> RuntimeFailure {
    match error {
        ControlError::Runtime {
            operation,
            source,
            recovery,
        }
        | ControlError::Persistence {
            operation,
            source,
            recovery,
        } => RuntimeFailure {
            operation: bounded_runtime_text(operation),
            message: bounded_runtime_text(&source.to_string()),
            recovery: bounded_runtime_text(recovery),
        },
        _ => RuntimeFailure {
            operation: "control runtime".to_owned(),
            message: bounded_runtime_text(&error.to_string()),
            recovery: "inspect Flux diagnostics and retry the requested reconciliation".to_owned(),
        },
    }
}

fn bounded_runtime_text(value: &str) -> String {
    const MAX_RUNTIME_STATUS_CHARS: usize = 512;
    value.chars().take(MAX_RUNTIME_STATUS_CHARS).collect()
}

fn retirement_pending_error(operation: &'static str) -> ControlError {
    ControlError::runtime(
        operation,
        io::Error::other("proxy engine retirement is still pending"),
        "wait for bounded maintenance cleanup and retry",
    )
}

fn rollback_failure_error(rollback_failure: ControlError) -> ControlError {
    ControlError::runtime(
        "restore previous runtime generation",
        rollback_failure,
        "keep capture detached and retry restoration or settle into failed state",
    )
}

fn runtime_writer_error<E>(
    operation: &'static str,
    source: E,
    recovery: &'static str,
) -> ControlError
where
    E: Error + Send + Sync + 'static,
{
    ControlError::runtime(operation, source, recovery)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io;
    use std::num::NonZeroU16;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use flux_core::{LegacyDispatcher, LegacyIntent, Reason};
    use flux_platform::{ReadinessEvidence, SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};

    use super::*;
    use crate::{EngineReport, RestartPolicy};

    #[test]
    fn start_orders_prepare_engine_capture_verify_and_publication() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn successful_start_publishes_an_observed_running_snapshot() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events,
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");

        let snapshot = runtime.snapshot();
        assert!(snapshot.revision > 0);
        assert_eq!(snapshot.phase, RuntimePhase::Running);
        assert_eq!(snapshot.capture, RuntimeCaptureState::Published);
        assert_eq!(snapshot.engine, RuntimeEngineState::Ready);
        assert_eq!(snapshot.generation, Some(1));
        assert_eq!(snapshot.last_error, None);
    }

    #[test]
    fn maintenance_retries_running_publication_without_tearing_down_the_data_path() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        let runtime = coordinator.runtime_snapshot_source();

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        let degraded = runtime.snapshot();
        assert_eq!(degraded.phase, RuntimePhase::Degraded);
        assert_eq!(degraded.capture, RuntimeCaptureState::Published);

        events.lock().expect("events lock").clear();
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
        let recovered = runtime.snapshot();
        assert_eq!(recovered.phase, RuntimePhase::Running);
        assert_eq!(recovered.capture, RuntimeCaptureState::Published);
        assert_eq!(recovered.last_error, None);
    }

    #[test]
    fn failed_running_retry_verification_repairs_capture_before_publication() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        coordinator.writer.inner.verify_failure = true;
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureVerified,
            ]
        );
        coordinator.writer.inner.verify_failure = false;
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn engine_exit_prevents_pending_running_publication_until_repaired() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([fixture.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 1,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("initial state publication fails");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::AwaitingCaptureRemoval { revision: 2 },
            EngineReport::BackingOff {
                revision: 3,
                retry_after: Duration::from_secs(1),
            },
        ]);

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
            ]
        );
    }

    #[test]
    fn reload_publication_failure_retains_the_verified_candidate_for_maintenance_retry() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = PublicationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            fail_on_call: 2,
            calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect_err("candidate state publication fails");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(2),
                }),
            ]
        );
        let degraded = runtime.snapshot();
        assert_eq!(degraded.phase, RuntimePhase::Degraded);
        assert_eq!(degraded.capture, RuntimeCaptureState::Published);
        assert_eq!(degraded.generation, Some(2));
    }

    #[test]
    fn stop_detaches_capture_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Stopped {
                reason: Reason::Fluxctl,
            })
            .expect("stop converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn failed_stop_detachment_is_retried_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Stopped {
                reason: Reason::Fluxctl,
            })
            .expect_err("uncertain detachment keeps stop pending");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn maintenance_finishes_a_pending_stop_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(1));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::BackingOff {
                revision: 2,
                retry_after: Duration::from_millis(1),
            },
            EngineReport::Stopped { revision: 3 },
        ]);

        coordinator
            .execute(&LegacyIntent::Stopped {
                reason: Reason::Fluxctl,
            })
            .expect_err("first bounded stop remains pending");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn address_resync_is_a_noop_while_the_runtime_is_stopped() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));

        coordinator
            .execute(&LegacyIntent::ResyncAddresses {
                reason: Reason::Fluxctl,
            })
            .expect("stopped address resync is idempotent");

        assert!(events.lock().expect("events lock").is_empty());
    }

    #[test]
    fn shutdown_detaches_capture_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator.shutdown();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn shutdown_retries_unsettled_engine_cleanup_within_its_bounded_drain() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(1));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::BackingOff {
                revision: 2,
                retry_after: Duration::from_millis(1),
            },
            EngineReport::Stopped { revision: 3 },
        ]);

        coordinator.shutdown();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Stopped),
            ]
        );
    }

    #[test]
    fn failed_capture_verification_detaches_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: true,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed verification rolls back");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn failed_activation_detachment_is_retried_without_restarting_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: true,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed verification leaves detachment pending");
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn failed_capture_start_detaches_before_stopping_the_engine() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: true,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));

        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect_err("failed capture publication rolls back");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Boot),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn reload_prepares_candidate_before_detaching_and_replacing_the_engine() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect("reload converges");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(2),
                }),
            ]
        );
    }

    #[test]
    fn failed_reload_restores_the_previous_generation_before_returning() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Failed { revision: 2 },
            EngineReport::Started {
                revision: 3,
                owned_resource_readiness: ReadinessEvidence::Listener {
                    port: NonZeroU16::new(1536).expect("nonzero port"),
                    table: PathBuf::from("/proc/1/net/tcp"),
                },
            },
        ]);

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect_err("candidate failure is reported after rollback");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn failed_reload_and_failed_rollback_settle_fail_open_and_publish_failed() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        let runtime = coordinator.runtime_snapshot_source();
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::Failed { revision: 2 },
            EngineReport::Failed { revision: 3 },
            EngineReport::Stopped { revision: 4 },
        ]);

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect_err("failed rollback is reported");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineRunning(CaptureObservation::Detached),
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
        let failed = runtime.snapshot();
        assert_eq!(failed.phase, RuntimePhase::Failed);
        assert_eq!(failed.capture, RuntimeCaptureState::Detached);
    }

    #[test]
    fn failed_reload_detachment_retains_the_active_engine_and_blocks_replacement() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 1,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect_err("uncertain capture detachment blocks replacement");
        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureVerified,
                Event::Published(PublishedRuntimeState::Running {
                    generation: generation(1),
                }),
            ]
        );
    }

    #[test]
    fn failed_candidate_compensation_does_not_restart_the_previous_generation() {
        let active = EngineFixture::new();
        let candidate = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let writer = CandidateActivationFailingWriter {
            inner: ScriptedWriter {
                events: Arc::clone(&events),
                prepared: VecDeque::from([active.spec.clone(), candidate.spec.clone()]),
                next_generation_id: 1,
                capture_start_failure: false,
                capture_stop_failures: 0,
                verify_failure: false,
            },
            capture_start_calls: 0,
            capture_stop_calls: 0,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::new(Mutex::new(VecDeque::new())),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("initial generation converges");
        events.lock().expect("events lock").clear();

        coordinator
            .execute(&LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            })
            .expect_err("candidate capture and its compensation both fail");

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::Prepared(Reason::Fluxctl),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
                Event::CaptureStarted,
                Event::CaptureStopped,
            ]
        );
        events.lock().expect("events lock").clear();

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::CaptureStopped,
                Event::EngineStopped(CaptureObservation::Detached),
                Event::Published(PublishedRuntimeState::Failed),
            ]
        );
    }

    #[test]
    fn maintenance_detaches_capture_before_abnormal_exit_restart() {
        let fixture = EngineFixture::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let reports = Arc::new(Mutex::new(VecDeque::new()));
        let writer = ScriptedWriter {
            events: Arc::clone(&events),
            prepared: VecDeque::from([fixture.spec.clone()]),
            next_generation_id: 1,
            capture_start_failure: false,
            capture_stop_failures: 0,
            verify_failure: false,
        };
        let engine = ScriptedEngine {
            events: Arc::clone(&events),
            reports: Arc::clone(&reports),
        };
        let mut coordinator =
            RuntimeCoordinator::with_dependencies(writer, engine, Duration::from_millis(100));
        coordinator
            .execute(&LegacyIntent::Running {
                reason: Reason::Boot,
            })
            .expect("start converges");
        events.lock().expect("events lock").clear();
        reports.lock().expect("reports lock").extend([
            EngineReport::AwaitingCaptureRemoval { revision: 2 },
            EngineReport::BackingOff {
                revision: 3,
                retry_after: Duration::from_secs(1),
            },
        ]);

        coordinator.maintain();

        assert_eq!(
            *events.lock().expect("events lock"),
            [
                Event::EngineRunning(CaptureObservation::Published),
                Event::CaptureStopped,
                Event::EngineRunning(CaptureObservation::Detached),
            ]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Prepared(Reason),
        EngineRunning(CaptureObservation),
        EngineStopped(CaptureObservation),
        CaptureStarted,
        CaptureStopped,
        CaptureVerified,
        AddressesResynchronized,
        Published(PublishedRuntimeState),
    }

    fn generation(value: u32) -> NonZeroU32 {
        NonZeroU32::new(value).expect("test generation must be nonzero")
    }

    struct ScriptedWriter {
        events: Arc<Mutex<Vec<Event>>>,
        prepared: VecDeque<EngineSpec>,
        next_generation_id: u32,
        capture_start_failure: bool,
        capture_stop_failures: usize,
        verify_failure: bool,
    }

    struct PublicationFailingWriter {
        inner: ScriptedWriter,
        fail_on_call: usize,
        calls: usize,
    }

    struct CandidateActivationFailingWriter {
        inner: ScriptedWriter,
        capture_start_calls: usize,
        capture_stop_calls: usize,
    }

    impl LegacyRuntimeWriter for CandidateActivationFailingWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            self.inner.prepare(reason)
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)?;
            self.capture_start_calls += 1;
            if self.capture_start_calls == 2 {
                Err(io::Error::other(
                    "injected candidate capture publication failure",
                ))
            } else {
                Ok(())
            }
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()?;
            self.capture_stop_calls += 1;
            if self.capture_stop_calls == 2 {
                Err(io::Error::other(
                    "injected candidate capture detachment failure",
                ))
            } else {
                Ok(())
            }
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)
        }

        fn resync_addresses(&mut self) -> Result<(), Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl LegacyRuntimeWriter for PublicationFailingWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            self.inner.prepare(reason)
        }

        fn capture_start(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.capture_start(generation)
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.inner.capture_stop()
        }

        fn verify_capture(&mut self, generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.inner.verify_capture(generation)
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.inner.publish(phase)?;
            self.calls += 1;
            if self.calls == self.fail_on_call {
                Err(io::Error::other("injected state publication failure"))
            } else {
                Ok(())
            }
        }

        fn resync_addresses(&mut self) -> Result<(), Self::Error> {
            self.inner.resync_addresses()
        }
    }

    impl LegacyRuntimeWriter for ScriptedWriter {
        type Error = io::Error;

        fn prepare(&mut self, reason: Reason) -> Result<PreparedGeneration, Self::Error> {
            let id = NonZeroU32::new(self.next_generation_id)
                .ok_or_else(|| io::Error::other("scripted generation must be nonzero"))?;
            self.next_generation_id = id
                .get()
                .checked_add(1)
                .ok_or_else(|| io::Error::other("scripted generation counter exhausted"))?;
            self.events
                .lock()
                .expect("events lock")
                .push(Event::Prepared(reason));
            let spec = self
                .prepared
                .pop_front()
                .ok_or_else(|| io::Error::other("no scripted generation remains"))?;
            Ok(PreparedGeneration { id, spec })
        }

        fn capture_start(&mut self, _generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureStarted);
            if self.capture_start_failure {
                Err(io::Error::other("injected capture publication failure"))
            } else {
                Ok(())
            }
        }

        fn capture_stop(&mut self) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureStopped);
            if self.capture_stop_failures > 0 {
                self.capture_stop_failures -= 1;
                Err(io::Error::other("injected capture detachment failure"))
            } else {
                Ok(())
            }
        }

        fn verify_capture(&mut self, _generation: &PreparedGeneration) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::CaptureVerified);
            if self.verify_failure {
                Err(io::Error::other("injected capture verification failure"))
            } else {
                Ok(())
            }
        }

        fn publish(&mut self, phase: PublishedRuntimeState) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::Published(phase));
            Ok(())
        }

        fn resync_addresses(&mut self) -> Result<(), Self::Error> {
            self.events
                .lock()
                .expect("events lock")
                .push(Event::AddressesResynchronized);
            Ok(())
        }
    }

    struct ScriptedEngine {
        events: Arc<Mutex<Vec<Event>>>,
        reports: Arc<Mutex<VecDeque<EngineReport>>>,
    }

    impl EngineRuntime for ScriptedEngine {
        fn reconcile(
            &mut self,
            desired: DesiredEngine<'_>,
            capture: CaptureObservation,
        ) -> Result<EngineReport, EngineSupervisorError> {
            match desired {
                DesiredEngine::Running(_) => {
                    self.events
                        .lock()
                        .expect("events lock")
                        .push(Event::EngineRunning(capture));
                    if let Some(report) = self.reports.lock().expect("reports lock").pop_front() {
                        return Ok(report);
                    }
                    Ok(EngineReport::Started {
                        revision: 1,
                        owned_resource_readiness: ReadinessEvidence::Listener {
                            port: NonZeroU16::new(1536).expect("nonzero port"),
                            table: PathBuf::from("/proc/1/net/tcp"),
                        },
                    })
                }
                DesiredEngine::Stopped => {
                    self.events
                        .lock()
                        .expect("events lock")
                        .push(Event::EngineStopped(capture));
                    if let Some(report) = self.reports.lock().expect("reports lock").pop_front() {
                        return Ok(report);
                    }
                    Ok(EngineReport::Stopped { revision: 1 })
                }
            }
        }
    }

    struct EngineFixture {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl EngineFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("create engine fixture");
            let binary = directory.path().join("sing-box");
            let config = directory.path().join("config.json");
            fs::write(&binary, b"sing-box").expect("write binary");
            fs::write(&config, b"{}").expect("write config");
            let restart = RestartPolicy::new(
                3,
                Duration::from_secs(60),
                Duration::from_secs(1),
                Duration::from_secs(8),
                Duration::from_secs(10),
            )
            .expect("valid restart policy");
            let spec = EngineSpec::new(
                SingBoxLaunchSpec {
                    binary,
                    config,
                    working_directory: directory.path().to_path_buf(),
                    log: directory.path().join("sing-box.log"),
                    launcher: SingBoxLauncher::Direct,
                    readiness: SingBoxReadiness::Listener {
                        port: NonZeroU16::new(1536).expect("nonzero port"),
                    },
                    startup_timeout: Duration::from_secs(1),
                    stop_timeout: Duration::from_secs(1),
                },
                restart,
            )
            .expect("inspect engine spec");
            Self {
                spec,
                _directory: directory,
            }
        }
    }
}
