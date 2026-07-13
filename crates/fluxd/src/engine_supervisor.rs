use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use flux_platform::internal::{
    PinnedSingBoxLaunch, SingBoxChild, SingBoxProcessAdapter, SingBoxProcessError,
    TerminationOutcome,
};
use flux_platform::{ReadinessEvidence, SingBoxExit, SingBoxLaunchSpec, SingBoxLauncher};
use sha2::{Digest, Sha256};

pub const MAX_ENGINE_DIAGNOSTIC_BYTES: usize = 4 * 1024;
pub const MAX_ENGINE_BINARY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ENGINE_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
pub const SHA256_DIGEST_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EngineArtifactDigest([u8; SHA256_DIGEST_BYTES]);

impl EngineArtifactDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Display for EngineArtifactDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineArtifact {
    Binary,
    Config,
    Launcher,
}

impl fmt::Display for EngineArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Binary => "binary",
            Self::Config => "configuration",
            Self::Launcher => "launcher",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSpecIoOperation {
    InspectPath,
    Open,
    InspectDescriptor,
    Read,
}

impl fmt::Display for EngineSpecIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InspectPath => "inspect path",
            Self::Open => "open",
            Self::InspectDescriptor => "inspect descriptor",
            Self::Read => "read",
        })
    }
}

#[derive(Debug)]
pub enum EngineSpecError {
    Io {
        operation: EngineSpecIoOperation,
        artifact: EngineArtifact,
        path: PathBuf,
        source: io::Error,
    },
    UnsafeFileType {
        artifact: EngineArtifact,
        path: PathBuf,
        source: Option<io::Error>,
    },
    NonAbsolutePath {
        artifact: EngineArtifact,
        path: PathBuf,
    },
    TooLarge {
        artifact: EngineArtifact,
        path: PathBuf,
        observed: u64,
        limit: u64,
    },
    ChangedDuringInspection {
        artifact: EngineArtifact,
        path: PathBuf,
    },
    DigestMismatch {
        artifact: EngineArtifact,
        path: PathBuf,
        expected: EngineArtifactDigest,
        observed: EngineArtifactDigest,
    },
}

impl fmt::Display for EngineSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                artifact,
                path,
                source,
            } => write!(
                formatter,
                "cannot {operation} Sing-Box {artifact} {}: {source}",
                path.display()
            ),
            Self::UnsafeFileType { artifact, path, .. } => write!(
                formatter,
                "Sing-Box {artifact} {} must be a non-symbolic regular file",
                path.display()
            ),
            Self::NonAbsolutePath { artifact, path } => write!(
                formatter,
                "Sing-Box {artifact} path {} must be absolute",
                path.display()
            ),
            Self::TooLarge {
                artifact,
                path,
                observed,
                limit,
            } => write!(
                formatter,
                "Sing-Box {artifact} {} is {observed} bytes, exceeding {limit}",
                path.display()
            ),
            Self::ChangedDuringInspection { artifact, path } => write!(
                formatter,
                "Sing-Box {artifact} {} changed while it was inspected",
                path.display()
            ),
            Self::DigestMismatch {
                artifact,
                path,
                expected,
                observed,
            } => write!(
                formatter,
                "Sing-Box {artifact} {} changed: expected SHA-256 {expected}, observed {observed}",
                path.display()
            ),
        }
    }
}

impl Error for EngineSpecError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::UnsafeFileType {
                source: Some(source),
                ..
            } => Some(source),
            Self::UnsafeFileType { source: None, .. }
            | Self::NonAbsolutePath { .. }
            | Self::TooLarge { .. }
            | Self::ChangedDuringInspection { .. }
            | Self::DigestMismatch { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// An inspected launch request whose identity includes SHA-256 digests of every
/// executable and configuration artifact involved in the launch.
///
/// At launch time the Supervisor reopens, verifies, and pins these exact file
/// descriptors through configuration validation and process creation. The
/// owned child therefore cannot observe a different same-path replacement.
pub struct EngineSpec {
    process: SingBoxLaunchSpec,
    restart: RestartPolicy,
    binary_digest: EngineArtifactDigest,
    config_digest: EngineArtifactDigest,
    launcher_digest: Option<EngineArtifactDigest>,
}

impl EngineSpec {
    /// Inspect bounded regular artifacts and capture their content identity.
    pub fn new(
        process: SingBoxLaunchSpec,
        restart: RestartPolicy,
    ) -> Result<Self, EngineSpecError> {
        let binary_digest = inspect_artifact(
            &process.binary,
            EngineArtifact::Binary,
            MAX_ENGINE_BINARY_BYTES,
        )?;
        let config_digest = inspect_artifact(
            &process.config,
            EngineArtifact::Config,
            MAX_ENGINE_CONFIG_BYTES,
        )?;
        let launcher_digest = match &process.launcher {
            SingBoxLauncher::Direct => None,
            SingBoxLauncher::BusyBoxSetuidgid { busybox, .. } => Some(inspect_artifact(
                busybox,
                EngineArtifact::Launcher,
                MAX_ENGINE_BINARY_BYTES,
            )?),
        };
        Ok(Self {
            process,
            restart,
            binary_digest,
            config_digest,
            launcher_digest,
        })
    }

    #[must_use]
    pub const fn process(&self) -> &SingBoxLaunchSpec {
        &self.process
    }

    #[must_use]
    pub const fn restart_policy(&self) -> RestartPolicy {
        self.restart
    }

    #[must_use]
    pub const fn binary_digest(&self) -> EngineArtifactDigest {
        self.binary_digest
    }

    #[must_use]
    pub const fn config_digest(&self) -> EngineArtifactDigest {
        self.config_digest
    }

    #[must_use]
    pub const fn launcher_digest(&self) -> Option<EngineArtifactDigest> {
        self.launcher_digest
    }

    fn open_verified_artifacts(&self) -> Result<OpenedEngineArtifacts, EngineSpecError> {
        let binary = open_verified_artifact(
            &self.process.binary,
            EngineArtifact::Binary,
            MAX_ENGINE_BINARY_BYTES,
            self.binary_digest,
        )?;
        let config = open_verified_artifact(
            &self.process.config,
            EngineArtifact::Config,
            MAX_ENGINE_CONFIG_BYTES,
            self.config_digest,
        )?;
        let launcher = match (&self.process.launcher, self.launcher_digest) {
            (SingBoxLauncher::Direct, None) => None,
            (SingBoxLauncher::BusyBoxSetuidgid { busybox, .. }, Some(launcher_digest)) => {
                Some(open_verified_artifact(
                    busybox,
                    EngineArtifact::Launcher,
                    MAX_ENGINE_BINARY_BYTES,
                    launcher_digest,
                )?)
            }
            (SingBoxLauncher::Direct, Some(_))
            | (SingBoxLauncher::BusyBoxSetuidgid { .. }, None) => {
                unreachable!("EngineSpec constructor binds launcher shape and digest together")
            }
        };
        Ok(OpenedEngineArtifacts {
            binary,
            config,
            launcher,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DesiredEngine<'a> {
    Running(&'a EngineSpec),
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureObservation {
    Detached,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnginePhase {
    Stopped,
    Checking,
    Starting,
    Ready,
    AwaitingCaptureRemoval,
    Stopping,
    BackingOff,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedEngineIdentity {
    pid: u32,
    start_time_ticks: u64,
}

impl OwnedEngineIdentity {
    #[must_use]
    pub(crate) const fn new(pid: NonZeroU32, start_time_ticks: NonZeroU64) -> Self {
        Self {
            pid: pid.get(),
            start_time_ticks: start_time_ticks.get(),
        }
    }

    #[must_use]
    pub const fn pid(self) -> u32 {
        self.pid
    }

    #[must_use]
    pub const fn start_time_ticks(self) -> u64 {
        self.start_time_ticks
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineSnapshot {
    revision: u64,
    phase: EnginePhase,
    owned_identity: Option<OwnedEngineIdentity>,
    restart_attempts: u32,
    retry_delay: Option<Duration>,
    last_exit: Option<SingBoxExit>,
    readiness: Option<ReadinessEvidence>,
    last_diagnostic: Option<String>,
}

impl EngineSnapshot {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn phase(&self) -> EnginePhase {
        self.phase
    }

    #[must_use]
    pub const fn owned_identity(&self) -> Option<OwnedEngineIdentity> {
        self.owned_identity
    }

    #[must_use]
    pub const fn restart_attempts(&self) -> u32 {
        self.restart_attempts
    }

    #[must_use]
    pub const fn retry_delay(&self) -> Option<Duration> {
        self.retry_delay
    }

    #[must_use]
    pub const fn last_exit(&self) -> Option<SingBoxExit> {
        self.last_exit
    }

    /// Evidence that the exact owned child holds the configured listener or
    /// TUN resource. This is pre-capture evidence, not a functional traffic,
    /// loop-prevention, DNS, or post-capture health probe.
    #[must_use]
    pub fn owned_resource_readiness(&self) -> Option<&ReadinessEvidence> {
        self.readiness.as_ref()
    }

    #[must_use]
    pub fn last_diagnostic(&self) -> Option<&str> {
        self.last_diagnostic.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn ready_for_test(
        revision: NonZeroU64,
        owned_identity: OwnedEngineIdentity,
        readiness: ReadinessEvidence,
    ) -> Self {
        Self {
            revision: revision.get(),
            phase: EnginePhase::Ready,
            owned_identity: Some(owned_identity),
            restart_attempts: 0,
            retry_delay: None,
            last_exit: None,
            readiness: Some(readiness),
            last_diagnostic: None,
        }
    }
}

impl Default for EngineSnapshot {
    fn default() -> Self {
        Self {
            revision: 0,
            phase: EnginePhase::Stopped,
            owned_identity: None,
            restart_attempts: 0,
            retry_delay: None,
            last_exit: None,
            readiness: None,
            last_diagnostic: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EngineReport {
    NoChange {
        revision: u64,
    },
    /// The exact inspected artifacts started and the owned child holds its
    /// configured listener or TUN resource. Capture is not yet functionally
    /// verified by this report.
    Started {
        revision: u64,
        owned_resource_readiness: ReadinessEvidence,
    },
    Stopped {
        revision: u64,
    },
    AwaitingCaptureRemoval {
        revision: u64,
    },
    Stopping {
        revision: u64,
        identity: OwnedEngineIdentity,
    },
    BackingOff {
        revision: u64,
        retry_after: Duration,
    },
    Failed {
        revision: u64,
    },
}

impl EngineReport {
    #[must_use]
    pub const fn revision(&self) -> u64 {
        match self {
            Self::NoChange { revision }
            | Self::Started { revision, .. }
            | Self::Stopped { revision }
            | Self::AwaitingCaptureRemoval { revision }
            | Self::Stopping { revision, .. }
            | Self::BackingOff { revision, .. }
            | Self::Failed { revision } => *revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    max_attempts: NonZeroU32,
    window: Duration,
    initial_backoff: Duration,
    maximum_backoff: Duration,
    stable_reset: Duration,
}

impl RestartPolicy {
    pub fn new(
        max_attempts: u32,
        window: Duration,
        initial_backoff: Duration,
        maximum_backoff: Duration,
        stable_reset: Duration,
    ) -> Result<Self, RestartPolicyError> {
        let max_attempts =
            NonZeroU32::new(max_attempts).ok_or(RestartPolicyError::ZeroMaximumAttempts)?;
        if window.is_zero() {
            return Err(RestartPolicyError::ZeroWindow);
        }
        if initial_backoff.is_zero() {
            return Err(RestartPolicyError::ZeroInitialBackoff);
        }
        if maximum_backoff.is_zero() {
            return Err(RestartPolicyError::ZeroMaximumBackoff);
        }
        if stable_reset.is_zero() {
            return Err(RestartPolicyError::ZeroStableReset);
        }
        if initial_backoff > maximum_backoff {
            return Err(RestartPolicyError::InitialBackoffExceedsMaximum);
        }
        Ok(Self {
            max_attempts,
            window,
            initial_backoff,
            maximum_backoff,
            stable_reset,
        })
    }

    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts.get()
    }

    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }

    #[must_use]
    pub const fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    #[must_use]
    pub const fn maximum_backoff(self) -> Duration {
        self.maximum_backoff
    }

    #[must_use]
    pub const fn stable_reset(self) -> Duration {
        self.stable_reset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartPolicyError {
    ZeroMaximumAttempts,
    ZeroWindow,
    ZeroInitialBackoff,
    ZeroMaximumBackoff,
    ZeroStableReset,
    InitialBackoffExceedsMaximum,
}

impl fmt::Display for RestartPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroMaximumAttempts => {
                formatter.write_str("restart maximum attempts must be nonzero")
            }
            Self::ZeroWindow => formatter.write_str("restart window must be positive"),
            Self::ZeroInitialBackoff => {
                formatter.write_str("restart initial backoff must be positive")
            }
            Self::ZeroMaximumBackoff => {
                formatter.write_str("restart maximum backoff must be positive")
            }
            Self::ZeroStableReset => formatter.write_str("restart stable reset must be positive"),
            Self::InitialBackoffExceedsMaximum => {
                formatter.write_str("restart initial backoff exceeds maximum backoff")
            }
        }
    }
}

impl Error for RestartPolicyError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureBlockedAction {
    Stop,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineSupervisorErrorKind {
    CaptureStillPublished,
    ArtifactVerification,
    AdapterUnavailable,
    InvariantViolation,
}

#[derive(Debug)]
pub enum EngineSupervisorError {
    CaptureStillPublished {
        action: CaptureBlockedAction,
        identity: OwnedEngineIdentity,
    },
    ArtifactVerification {
        operation: &'static str,
        source: EngineSpecError,
    },
    AdapterUnavailable {
        operation: &'static str,
        diagnostic: String,
        source: Option<Box<SingBoxProcessError>>,
    },
    InvariantViolation {
        diagnostic: String,
    },
}

impl EngineSupervisorError {
    #[must_use]
    pub const fn kind(&self) -> EngineSupervisorErrorKind {
        match self {
            Self::CaptureStillPublished { .. } => EngineSupervisorErrorKind::CaptureStillPublished,
            Self::ArtifactVerification { .. } => EngineSupervisorErrorKind::ArtifactVerification,
            Self::AdapterUnavailable { .. } => EngineSupervisorErrorKind::AdapterUnavailable,
            Self::InvariantViolation { .. } => EngineSupervisorErrorKind::InvariantViolation,
        }
    }
}

impl fmt::Display for EngineSupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureStillPublished { action, identity } => write!(
                formatter,
                "capture is still published; cannot {action} owned Sing-Box child {}",
                identity.pid
            ),
            Self::ArtifactVerification { operation, source } => {
                write!(
                    formatter,
                    "engine artifact verification during {operation}: {source}"
                )
            }
            Self::AdapterUnavailable {
                operation,
                diagnostic,
                ..
            } => write!(
                formatter,
                "Sing-Box process adapter unavailable during {operation}: {diagnostic}"
            ),
            Self::InvariantViolation { diagnostic } => {
                write!(
                    formatter,
                    "engine supervisor invariant violated: {diagnostic}"
                )
            }
        }
    }
}

impl Error for EngineSupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ArtifactVerification { source, .. } => Some(source),
            Self::AdapterUnavailable {
                source: Some(source),
                ..
            } => Some(source.as_ref()),
            Self::CaptureStillPublished { .. }
            | Self::AdapterUnavailable { source: None, .. }
            | Self::InvariantViolation { .. } => None,
        }
    }
}

impl fmt::Display for CaptureBlockedAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stop => "stop",
            Self::Replace => "replace",
        })
    }
}

pub struct EngineSupervisor {
    host: Box<dyn EngineHost>,
    clock: Box<dyn Clock>,
    child: Option<HostChild>,
    active_spec: Option<EngineSpec>,
    target_spec: Option<EngineSpec>,
    owned_identity: Option<OwnedEngineIdentity>,
    readiness: Option<ReadinessEvidence>,
    ready_since: Option<Duration>,
    retry_at: Option<Duration>,
    pending_after_exit: Option<PendingAfterExit>,
    restart: RestartState,
    last_exit: Option<SingBoxExit>,
    last_diagnostic: Option<String>,
    snapshot: Arc<EngineSnapshot>,
}

impl EngineSupervisor {
    #[must_use]
    pub fn new() -> Self {
        Self::with_dependencies(
            Box::new(ProductionEngineHost::default()),
            Box::new(SystemClock::new()),
        )
    }

    pub fn reconcile(
        &mut self,
        desired: DesiredEngine<'_>,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError> {
        let now = self.clock.now();
        self.apply_stable_reset(now);
        let desired = match desired {
            DesiredEngine::Running(spec) => Some(spec.clone()),
            DesiredEngine::Stopped => None,
        };

        if let Some(exit) = self.observe_child_exit()? {
            let exited_spec = self.active_spec.take();
            self.owned_identity = None;
            self.readiness = None;
            self.ready_since = None;
            self.last_exit = Some(exit);

            if self.pending_after_exit.is_some() {
                return self.resolve_pending_after_exit(desired.as_ref(), capture, now);
            }

            self.last_diagnostic = Some(bounded_diagnostic(format!(
                "owned Sing-Box child exited unexpectedly with {exit}"
            )));

            let Some(spec) = desired.as_ref() else {
                self.target_spec = None;
                self.retry_at = None;
                self.restart.reset();
                return self.reconcile_stopped(capture);
            };

            let same_spec = exited_spec.as_ref() == Some(spec);
            self.set_target(spec);
            if same_spec {
                self.record_failure(now, spec.restart);
            } else {
                self.restart.reset();
                self.retry_at = None;
            }

            if capture == CaptureObservation::Published {
                let revision = self.publish(
                    EnginePhase::AwaitingCaptureRemoval,
                    self.remaining_retry_delay(now),
                );
                return Ok(EngineReport::AwaitingCaptureRemoval { revision });
            }
        }

        if self.child.is_some() && self.snapshot.phase == EnginePhase::Stopping {
            return self.stopping_report();
        }

        if self.child.is_none() && self.pending_after_exit.is_some() {
            return self.resolve_pending_after_exit(desired.as_ref(), capture, now);
        }

        match desired.as_ref() {
            Some(spec) => self.reconcile_running(spec, capture, now),
            None => self.reconcile_stopped(capture),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<EngineSnapshot> {
        Arc::clone(&self.snapshot)
    }

    fn with_dependencies(host: Box<dyn EngineHost>, clock: Box<dyn Clock>) -> Self {
        Self {
            host,
            clock,
            child: None,
            active_spec: None,
            target_spec: None,
            owned_identity: None,
            readiness: None,
            ready_since: None,
            retry_at: None,
            pending_after_exit: None,
            restart: RestartState::default(),
            last_exit: None,
            last_diagnostic: None,
            snapshot: Arc::new(EngineSnapshot::default()),
        }
    }

    fn reconcile_stopped(
        &mut self,
        capture: CaptureObservation,
    ) -> Result<EngineReport, EngineSupervisorError> {
        self.target_spec = None;
        self.retry_at = None;
        self.restart.reset();

        let Some(active_spec) = self.active_spec.clone() else {
            if self.child.is_some() || self.owned_identity.is_some() {
                return Err(self.invariant("owned child exists without its launch specification"));
            }
            if capture == CaptureObservation::Published {
                let revision = self.publish(EnginePhase::AwaitingCaptureRemoval, None);
                return Ok(EngineReport::AwaitingCaptureRemoval { revision });
            }
            if self.snapshot.phase == EnginePhase::Stopped {
                return Ok(EngineReport::NoChange {
                    revision: self.snapshot.revision,
                });
            }
            self.readiness = None;
            self.ready_since = None;
            let revision = self.publish(EnginePhase::Stopped, None);
            return Ok(EngineReport::Stopped { revision });
        };

        if capture == CaptureObservation::Published {
            let identity = self.require_identity()?;
            self.publish(EnginePhase::AwaitingCaptureRemoval, None);
            return Err(EngineSupervisorError::CaptureStillPublished {
                action: CaptureBlockedAction::Stop,
                identity,
            });
        }

        self.pending_after_exit = Some(PendingAfterExit::AdministrativeStop);
        match self.terminate_owned(active_spec.process.stop_timeout, "stop owned child")? {
            TerminationProgress::Exited => {
                self.pending_after_exit.take();
                let revision = self.publish(EnginePhase::Stopped, None);
                Ok(EngineReport::Stopped { revision })
            }
            TerminationProgress::Pending(report) => Ok(report),
        }
    }

    fn reconcile_running(
        &mut self,
        spec: &EngineSpec,
        capture: CaptureObservation,
        now: Duration,
    ) -> Result<EngineReport, EngineSupervisorError> {
        if let Some(active_spec) = self.active_spec.clone() {
            self.verify_spec(spec, "Desired State reconciliation")?;
            if active_spec == *spec {
                self.target_spec = Some(spec.clone());
                self.retry_at = None;
                let revision = self.publish(EnginePhase::Ready, None);
                return Ok(EngineReport::NoChange { revision });
            }

            self.target_spec = Some(spec.clone());
            if capture == CaptureObservation::Published {
                let identity = self.require_identity()?;
                self.publish(EnginePhase::AwaitingCaptureRemoval, None);
                return Err(EngineSupervisorError::CaptureStillPublished {
                    action: CaptureBlockedAction::Replace,
                    identity,
                });
            }

            self.pending_after_exit = Some(PendingAfterExit::AdministrativeReplace);
            match self.terminate_owned(active_spec.process.stop_timeout, "replace owned child")? {
                TerminationProgress::Exited => {
                    self.pending_after_exit.take();
                }
                TerminationProgress::Pending(report) => return Ok(report),
            }
            self.restart.reset();
            self.retry_at = None;
        }

        let target_changed = self.target_spec.as_ref() != Some(spec);
        self.set_target(spec);
        if target_changed {
            self.restart.reset();
            self.retry_at = None;
        }

        if self.snapshot.phase == EnginePhase::AwaitingCaptureRemoval
            && capture == CaptureObservation::Published
        {
            let revision = self.publish(
                EnginePhase::AwaitingCaptureRemoval,
                self.remaining_retry_delay(now),
            );
            return Ok(EngineReport::AwaitingCaptureRemoval { revision });
        }

        self.verify_spec(spec, "Desired State reconciliation")?;

        self.restart.prune(now, spec.restart.window);
        if self.restart.exhausted {
            if self.restart.attempt_count() >= spec.restart.max_attempts.get() {
                let revision = self.publish(EnginePhase::Failed, None);
                return Ok(EngineReport::Failed { revision });
            }
            self.restart.exhausted = false;
            self.retry_at = None;
        }

        if let Some(retry_after) = self.remaining_retry_delay(now) {
            let revision = self.publish(EnginePhase::BackingOff, Some(retry_after));
            return Ok(EngineReport::BackingOff {
                revision,
                retry_after,
            });
        }

        self.launch(spec)
    }

    fn launch(&mut self, spec: &EngineSpec) -> Result<EngineReport, EngineSupervisorError> {
        if self.child.is_some() || self.owned_identity.is_some() || self.active_spec.is_some() {
            return Err(self.host_error(
                "launch child",
                HostFailure::Invariant(
                    "refused to spawn while an owned child slot is occupied".to_owned(),
                ),
            ));
        }
        let prepared = self.prepare_spec(spec, "before Sing-Box configuration check")?;
        self.publish(EnginePhase::Checking, None);
        match self.host.validate(&spec.process, &prepared) {
            Ok(()) => {}
            Err(HostFailure::Expected(diagnostic)) => {
                return Ok(self.attempt_failed(spec.restart, diagnostic));
            }
            Err(HostFailure::Artifact(source)) => {
                return Err(self.artifact_failure(
                    "prepare artifacts for Sing-Box configuration check",
                    source,
                ));
            }
            Err(failure) => return Err(self.host_error("validate configuration", failure)),
        }

        self.reverify_prepared(spec, &prepared, "after configuration check before spawn")?;
        self.publish(EnginePhase::Starting, None);
        let child = match self.host.spawn(&spec.process, &prepared) {
            Ok(child) => child,
            Err(HostFailure::Expected(diagnostic)) => {
                return Ok(self.attempt_failed(spec.restart, diagnostic));
            }
            Err(HostFailure::Artifact(source)) => {
                return Err(self.artifact_failure("prepare artifacts for child spawn", source));
            }
            Err(failure) => return Err(self.host_error("spawn child", failure)),
        };
        let identity = child.identity();
        self.owned_identity = Some(identity);
        self.active_spec = Some(spec.clone());
        self.child = Some(child);
        self.publish(EnginePhase::Starting, None);

        if let Err(source) = self.host.reverify(spec, &prepared) {
            self.last_diagnostic = Some(bounded_diagnostic(source.to_string()));
            self.pending_after_exit = Some(PendingAfterExit::ArtifactFailure {
                operation: "after spawn before owned-resource readiness",
                source,
            });
            match self.terminate_owned(
                spec.process.stop_timeout,
                "terminate child after artifact verification failure",
            )? {
                TerminationProgress::Exited => {
                    let pending = self.pending_after_exit.take().ok_or_else(|| {
                        self.invariant("artifact cleanup lost its pending verification error")
                    })?;
                    return self.resolve_completed_pending(pending);
                }
                TerminationProgress::Pending(report) => return Ok(report),
            }
        }

        let readiness = {
            let child =
                self.child
                    .as_mut()
                    .ok_or_else(|| EngineSupervisorError::InvariantViolation {
                        diagnostic: "spawned child disappeared before readiness".to_owned(),
                    })?;
            self.host.wait_ready(child, &spec.process)
        };
        let readiness = match readiness {
            Ok(readiness) => readiness,
            Err(HostFailure::Expected(diagnostic)) => {
                self.last_diagnostic = Some(bounded_diagnostic(diagnostic.clone()));
                self.pending_after_exit = Some(PendingAfterExit::OperationalFailure {
                    diagnostic,
                    policy: spec.restart,
                });
                match self.terminate_owned(spec.process.stop_timeout, "terminate unready child")? {
                    TerminationProgress::Exited => {
                        let pending = self.pending_after_exit.take().ok_or_else(|| {
                            self.invariant("unready child cleanup lost its pending outcome")
                        })?;
                        return self.resolve_completed_pending(pending);
                    }
                    TerminationProgress::Pending(report) => return Ok(report),
                }
            }
            Err(failure) => {
                self.last_diagnostic = Some(bounded_diagnostic(failure.diagnostic_ref()));
                self.pending_after_exit = Some(PendingAfterExit::AdapterFailure {
                    operation: "wait for readiness",
                    failure,
                });
                match self.terminate_owned(
                    spec.process.stop_timeout,
                    "terminate after readiness adapter failure",
                )? {
                    TerminationProgress::Exited => {
                        let pending = self.pending_after_exit.take().ok_or_else(|| {
                            self.invariant("readiness cleanup lost its pending adapter error")
                        })?;
                        return self.resolve_completed_pending(pending);
                    }
                    TerminationProgress::Pending(report) => return Ok(report),
                }
            }
        };

        self.target_spec = Some(spec.clone());
        self.readiness = Some(readiness.clone());
        self.ready_since = Some(self.clock.now());
        self.retry_at = None;
        let revision = self.publish(EnginePhase::Ready, None);
        Ok(EngineReport::Started {
            revision,
            owned_resource_readiness: readiness,
        })
    }

    fn observe_child_exit(&mut self) -> Result<Option<SingBoxExit>, EngineSupervisorError> {
        let result = match self.child.as_mut() {
            Some(child) => self.host.try_wait(child),
            None => return Ok(None),
        };
        match result {
            Ok(Some(exit)) => {
                self.child.take();
                Ok(Some(exit))
            }
            Ok(None) => Ok(None),
            Err(failure) => Err(self.host_error("observe child exit", failure)),
        }
    }

    fn terminate_owned(
        &mut self,
        timeout: Duration,
        operation: &'static str,
    ) -> Result<TerminationProgress, EngineSupervisorError> {
        let result = match self.child.as_mut() {
            Some(child) => self.host.terminate(child, timeout),
            None => {
                return Err(self.invariant("launch specification exists without an owned child"));
            }
        };
        match result {
            Ok(HostTermination::Exited(exit)) => {
                self.child.take();
                self.owned_identity = None;
                self.active_spec = None;
                self.readiness = None;
                self.ready_since = None;
                self.last_exit = Some(exit);
                Ok(TerminationProgress::Exited)
            }
            Ok(HostTermination::Pending(diagnostic)) => {
                self.append_diagnostic(diagnostic);
                Ok(TerminationProgress::Pending(self.stopping_report()?))
            }
            Err(failure) => {
                Err(self.host_error_in_phase(operation, failure, EnginePhase::Stopping))
            }
        }
    }

    fn attempt_failed(&mut self, policy: RestartPolicy, diagnostic: String) -> EngineReport {
        self.active_spec = None;
        self.owned_identity = None;
        self.readiness = None;
        self.ready_since = None;
        self.last_diagnostic = Some(bounded_diagnostic(diagnostic));
        let now = self.clock.now();
        match self.record_failure(now, policy) {
            RetryDecision::RetryAfter(retry_after) => {
                let revision = self.publish(EnginePhase::BackingOff, Some(retry_after));
                EngineReport::BackingOff {
                    revision,
                    retry_after,
                }
            }
            RetryDecision::Exhausted => {
                let revision = self.publish(EnginePhase::Failed, None);
                EngineReport::Failed { revision }
            }
        }
    }

    fn record_failure(&mut self, now: Duration, policy: RestartPolicy) -> RetryDecision {
        self.restart.prune(now, policy.window);
        if self.restart.attempt_count() >= policy.max_attempts.get() {
            self.restart.exhausted = true;
            self.retry_at = None;
            return RetryDecision::Exhausted;
        }

        self.restart.attempts.push_back(now);
        self.restart.consecutive_failures = self.restart.consecutive_failures.saturating_add(1);
        self.restart.exhausted = false;
        let exponent = self.restart.consecutive_failures.saturating_sub(1).min(31);
        let multiplier = 1_u32 << exponent;
        let retry_after = policy
            .initial_backoff
            .saturating_mul(multiplier)
            .min(policy.maximum_backoff);
        self.retry_at = Some(now.saturating_add(retry_after));
        RetryDecision::RetryAfter(retry_after)
    }

    fn apply_stable_reset(&mut self, now: Duration) {
        let Some(ready_since) = self.ready_since else {
            return;
        };
        let Some(spec) = self.active_spec.as_ref() else {
            return;
        };
        if now.saturating_sub(ready_since) >= spec.restart.stable_reset {
            self.restart.consecutive_failures = 0;
            self.ready_since = None;
        }
    }

    fn set_target(&mut self, spec: &EngineSpec) {
        self.target_spec = Some(spec.clone());
    }

    fn remaining_retry_delay(&self, now: Duration) -> Option<Duration> {
        self.retry_at
            .and_then(|retry_at| retry_at.checked_sub(now))
            .filter(|delay| !delay.is_zero())
    }

    fn require_identity(&self) -> Result<OwnedEngineIdentity, EngineSupervisorError> {
        self.owned_identity
            .ok_or_else(|| self.invariant("owned child has no established identity"))
    }

    fn verify_spec(
        &mut self,
        spec: &EngineSpec,
        operation: &'static str,
    ) -> Result<(), EngineSupervisorError> {
        self.prepare_spec(spec, operation).map(drop)
    }

    fn prepare_spec(
        &mut self,
        spec: &EngineSpec,
        operation: &'static str,
    ) -> Result<HostPrepared, EngineSupervisorError> {
        match self.host.prepare(spec) {
            Ok(prepared) => Ok(prepared),
            Err(HostFailure::Artifact(source)) => Err(self.artifact_failure(operation, source)),
            Err(failure) => Err(self.host_error(operation, failure)),
        }
    }

    fn reverify_prepared(
        &mut self,
        spec: &EngineSpec,
        prepared: &HostPrepared,
        operation: &'static str,
    ) -> Result<(), EngineSupervisorError> {
        self.host
            .reverify(spec, prepared)
            .map_err(|source| self.artifact_failure(operation, source))
    }

    fn artifact_failure(
        &mut self,
        operation: &'static str,
        source: EngineSpecError,
    ) -> EngineSupervisorError {
        self.last_diagnostic = Some(bounded_diagnostic(source.to_string()));
        EngineSupervisorError::ArtifactVerification { operation, source }
    }

    fn stopping_report(&mut self) -> Result<EngineReport, EngineSupervisorError> {
        let identity = self.require_identity()?;
        let revision = self.publish(EnginePhase::Stopping, None);
        Ok(EngineReport::Stopping { revision, identity })
    }

    fn resolve_pending_after_exit(
        &mut self,
        desired: Option<&EngineSpec>,
        capture: CaptureObservation,
        now: Duration,
    ) -> Result<EngineReport, EngineSupervisorError> {
        let pending = self.pending_after_exit.take().ok_or_else(|| {
            self.invariant("pending child cleanup outcome disappeared before resolution")
        })?;
        let Some(spec) = desired else {
            self.target_spec = None;
            self.retry_at = None;
            self.restart.reset();
            return self.reconcile_stopped(capture);
        };

        if matches!(
            &pending,
            PendingAfterExit::AdministrativeStop | PendingAfterExit::AdministrativeReplace
        ) {
            self.set_target(spec);
            self.restart.reset();
            self.retry_at = None;
            if capture == CaptureObservation::Published {
                let revision = self.publish(EnginePhase::AwaitingCaptureRemoval, None);
                return Ok(EngineReport::AwaitingCaptureRemoval { revision });
            }
            return self.reconcile_running(spec, capture, now);
        }

        if self.target_spec.as_ref() != Some(spec) {
            self.set_target(spec);
            self.restart.reset();
            self.retry_at = None;
            if capture == CaptureObservation::Published {
                let revision = self.publish(EnginePhase::AwaitingCaptureRemoval, None);
                return Ok(EngineReport::AwaitingCaptureRemoval { revision });
            }
            return self.reconcile_running(spec, capture, now);
        }

        if capture == CaptureObservation::Published {
            self.pending_after_exit = Some(pending);
            let revision = self.publish(EnginePhase::AwaitingCaptureRemoval, None);
            return Ok(EngineReport::AwaitingCaptureRemoval { revision });
        }

        self.resolve_completed_pending(pending)
    }

    fn resolve_completed_pending(
        &mut self,
        pending: PendingAfterExit,
    ) -> Result<EngineReport, EngineSupervisorError> {
        match pending {
            PendingAfterExit::AdministrativeStop | PendingAfterExit::AdministrativeReplace => {
                Err(self
                    .invariant("administrative termination reached operational failure resolution"))
            }
            PendingAfterExit::OperationalFailure { diagnostic, policy } => {
                Ok(self.attempt_failed(policy, diagnostic))
            }
            PendingAfterExit::ArtifactFailure { operation, source } => {
                self.last_diagnostic = Some(bounded_diagnostic(source.to_string()));
                self.publish(EnginePhase::Failed, None);
                Err(EngineSupervisorError::ArtifactVerification { operation, source })
            }
            PendingAfterExit::AdapterFailure { operation, failure } => {
                Err(self.host_error(operation, failure))
            }
        }
    }

    fn append_diagnostic(&mut self, diagnostic: String) {
        let diagnostic = match self.last_diagnostic.take() {
            Some(existing) if !existing.is_empty() => format!("{existing}\n{diagnostic}"),
            Some(_) | None => diagnostic,
        };
        self.last_diagnostic = Some(bounded_diagnostic(diagnostic));
    }

    fn host_error(
        &mut self,
        operation: &'static str,
        failure: HostFailure,
    ) -> EngineSupervisorError {
        self.host_error_in_phase(operation, failure, EnginePhase::Failed)
    }

    fn host_error_in_phase(
        &mut self,
        operation: &'static str,
        failure: HostFailure,
        phase: EnginePhase,
    ) -> EngineSupervisorError {
        if let HostFailure::Artifact(source) = failure {
            return self.artifact_failure(operation, source);
        }
        let (kind, diagnostic, source) = match failure {
            HostFailure::Expected(diagnostic) => (
                EngineSupervisorErrorKind::InvariantViolation,
                format!("unexpected operational failure during {operation}: {diagnostic}"),
                None,
            ),
            HostFailure::Unavailable { summary, source } => (
                EngineSupervisorErrorKind::AdapterUnavailable,
                summary,
                source,
            ),
            HostFailure::Invariant(diagnostic) => (
                EngineSupervisorErrorKind::InvariantViolation,
                diagnostic,
                None,
            ),
            HostFailure::Artifact(_) => unreachable!("artifact failure returned above"),
        };
        let diagnostic = bounded_diagnostic(diagnostic);
        self.last_diagnostic = Some(diagnostic.clone());
        self.publish(phase, None);
        match kind {
            EngineSupervisorErrorKind::AdapterUnavailable => {
                EngineSupervisorError::AdapterUnavailable {
                    operation,
                    diagnostic,
                    source,
                }
            }
            EngineSupervisorErrorKind::InvariantViolation => {
                EngineSupervisorError::InvariantViolation { diagnostic }
            }
            EngineSupervisorErrorKind::CaptureStillPublished
            | EngineSupervisorErrorKind::ArtifactVerification => unreachable!(),
        }
    }

    fn invariant(&self, diagnostic: impl Into<String>) -> EngineSupervisorError {
        EngineSupervisorError::InvariantViolation {
            diagnostic: bounded_diagnostic(diagnostic.into()),
        }
    }

    fn publish(&mut self, phase: EnginePhase, retry_delay: Option<Duration>) -> u64 {
        let restart_attempts = self.restart.attempt_count();
        let current = self.snapshot.as_ref();
        if current.phase == phase
            && current.owned_identity == self.owned_identity
            && current.restart_attempts == restart_attempts
            && current.retry_delay == retry_delay
            && current.last_exit == self.last_exit
            && current.readiness == self.readiness
            && current.last_diagnostic == self.last_diagnostic
        {
            return current.revision;
        }

        let revision = current.revision.saturating_add(1);
        self.snapshot = Arc::new(EngineSnapshot {
            revision,
            phase,
            owned_identity: self.owned_identity,
            restart_attempts,
            retry_delay,
            last_exit: self.last_exit,
            readiness: self.readiness.clone(),
            last_diagnostic: self.last_diagnostic.clone(),
        });
        revision
    }
}

impl Default for EngineSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct RestartState {
    attempts: VecDeque<Duration>,
    consecutive_failures: u32,
    exhausted: bool,
}

impl RestartState {
    fn reset(&mut self) {
        self.attempts.clear();
        self.consecutive_failures = 0;
        self.exhausted = false;
    }

    fn prune(&mut self, now: Duration, window: Duration) {
        while self
            .attempts
            .front()
            .is_some_and(|attempt| now.saturating_sub(*attempt) >= window)
        {
            self.attempts.pop_front();
        }
    }

    fn attempt_count(&self) -> u32 {
        u32::try_from(self.attempts.len()).unwrap_or(u32::MAX)
    }
}

enum RetryDecision {
    RetryAfter(Duration),
    Exhausted,
}

enum PendingAfterExit {
    AdministrativeStop,
    AdministrativeReplace,
    OperationalFailure {
        diagnostic: String,
        policy: RestartPolicy,
    },
    ArtifactFailure {
        operation: &'static str,
        source: EngineSpecError,
    },
    AdapterFailure {
        operation: &'static str,
        failure: HostFailure,
    },
}

enum TerminationProgress {
    Exited,
    Pending(EngineReport),
}

enum HostTermination {
    Exited(SingBoxExit),
    Pending(String),
}

trait Clock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

trait EngineHost: Send {
    fn prepare(&mut self, spec: &EngineSpec) -> Result<HostPrepared, HostFailure>;
    fn reverify(
        &mut self,
        spec: &EngineSpec,
        prepared: &HostPrepared,
    ) -> Result<(), EngineSpecError>;
    fn validate(
        &mut self,
        spec: &SingBoxLaunchSpec,
        prepared: &HostPrepared,
    ) -> Result<(), HostFailure>;
    fn spawn(
        &mut self,
        spec: &SingBoxLaunchSpec,
        prepared: &HostPrepared,
    ) -> Result<HostChild, HostFailure>;
    fn wait_ready(
        &mut self,
        child: &mut HostChild,
        spec: &SingBoxLaunchSpec,
    ) -> Result<ReadinessEvidence, HostFailure>;
    fn try_wait(&mut self, child: &mut HostChild) -> Result<Option<SingBoxExit>, HostFailure>;
    fn terminate(
        &mut self,
        child: &mut HostChild,
        timeout: Duration,
    ) -> Result<HostTermination, HostFailure>;
}

enum HostPrepared {
    Production(Box<PreparedEngineArtifacts>),
    #[cfg(test)]
    Scripted,
}

enum HostChild {
    Production(SingBoxChild),
    #[cfg(test)]
    Scripted(ScriptedChild),
}

impl HostChild {
    fn identity(&self) -> OwnedEngineIdentity {
        match self {
            Self::Production(child) => OwnedEngineIdentity {
                pid: child.identity().pid(),
                start_time_ticks: child.identity().start_time_ticks(),
            },
            #[cfg(test)]
            Self::Scripted(child) => child.identity,
        }
    }
}

#[cfg(test)]
struct ScriptedChild {
    identity: OwnedEngineIdentity,
}

#[derive(Default)]
struct ProductionEngineHost {
    adapter: SingBoxProcessAdapter,
}

impl EngineHost for ProductionEngineHost {
    fn prepare(&mut self, spec: &EngineSpec) -> Result<HostPrepared, HostFailure> {
        let opened = spec
            .open_verified_artifacts()
            .map_err(HostFailure::Artifact)?;
        opened
            .pin()
            .map(Box::new)
            .map(HostPrepared::Production)
            .map_err(unavailable_process_error)
    }

    fn reverify(
        &mut self,
        _spec: &EngineSpec,
        prepared: &HostPrepared,
    ) -> Result<(), EngineSpecError> {
        match prepared {
            HostPrepared::Production(prepared) => prepared.reverify(),
            #[cfg(test)]
            HostPrepared::Scripted => {
                unreachable!("production host received scripted prepared artifacts")
            }
        }
    }

    fn validate(
        &mut self,
        spec: &SingBoxLaunchSpec,
        prepared: &HostPrepared,
    ) -> Result<(), HostFailure> {
        match prepared {
            HostPrepared::Production(prepared) => self
                .adapter
                .validate_pinned(&prepared.pinned, spec)
                .map(|_| ())
                .map_err(classify_validation_error),
            #[cfg(test)]
            HostPrepared::Scripted => Err(HostFailure::Invariant(
                "production host received scripted prepared artifacts".to_owned(),
            )),
        }
    }

    fn spawn(
        &mut self,
        spec: &SingBoxLaunchSpec,
        prepared: &HostPrepared,
    ) -> Result<HostChild, HostFailure> {
        match prepared {
            HostPrepared::Production(prepared) => self
                .adapter
                .spawn_pinned(&prepared.pinned, spec)
                .map(HostChild::Production)
                .map_err(classify_spawn_error),
            #[cfg(test)]
            HostPrepared::Scripted => Err(HostFailure::Invariant(
                "production host received scripted prepared artifacts".to_owned(),
            )),
        }
    }

    fn wait_ready(
        &mut self,
        child: &mut HostChild,
        spec: &SingBoxLaunchSpec,
    ) -> Result<ReadinessEvidence, HostFailure> {
        match child {
            HostChild::Production(child) => self
                .adapter
                .wait_ready(child, spec)
                .map_err(classify_readiness_error),
            #[cfg(test)]
            HostChild::Scripted(_) => Err(HostFailure::Invariant(
                "production host received a scripted child".to_owned(),
            )),
        }
    }

    fn try_wait(&mut self, child: &mut HostChild) -> Result<Option<SingBoxExit>, HostFailure> {
        match child {
            HostChild::Production(child) => self
                .adapter
                .try_wait(child)
                .map_err(unavailable_process_error),
            #[cfg(test)]
            HostChild::Scripted(_) => Err(HostFailure::Invariant(
                "production host received a scripted child".to_owned(),
            )),
        }
    }

    fn terminate(
        &mut self,
        child: &mut HostChild,
        timeout: Duration,
    ) -> Result<HostTermination, HostFailure> {
        match child {
            HostChild::Production(child) => self
                .adapter
                .terminate(child, timeout)
                .map(|outcome| HostTermination::Exited(termination_exit(outcome)))
                .or_else(|error| match error {
                    SingBoxProcessError::PostSignalReapTimedOut { .. } => {
                        Ok(HostTermination::Pending(safe_process_error_summary(&error)))
                    }
                    _ => Err(unavailable_process_error(error)),
                }),
            #[cfg(test)]
            HostChild::Scripted(_) => Err(HostFailure::Invariant(
                "production host received a scripted child".to_owned(),
            )),
        }
    }
}

enum HostFailure {
    Expected(String),
    Artifact(EngineSpecError),
    Unavailable {
        summary: String,
        source: Option<Box<SingBoxProcessError>>,
    },
    Invariant(String),
}

impl HostFailure {
    fn diagnostic_ref(&self) -> String {
        match self {
            Self::Expected(diagnostic) | Self::Invariant(diagnostic) => diagnostic.clone(),
            Self::Artifact(source) => source.to_string(),
            Self::Unavailable { summary, .. } => summary.clone(),
        }
    }

    #[cfg(test)]
    fn unavailable_without_source(summary: impl Into<String>) -> Self {
        Self::Unavailable {
            summary: summary.into(),
            source: None,
        }
    }
}

fn classify_validation_error(error: SingBoxProcessError) -> HostFailure {
    if matches!(
        &error,
        SingBoxProcessError::InvalidSpec { .. }
            | SingBoxProcessError::Spawn { .. }
            | SingBoxProcessError::CheckFailed { .. }
            | SingBoxProcessError::CheckTimedOut { .. }
    ) {
        HostFailure::Expected(safe_process_error_summary(&error))
    } else {
        unavailable_process_error(error)
    }
}

fn classify_spawn_error(error: SingBoxProcessError) -> HostFailure {
    if matches!(
        &error,
        SingBoxProcessError::InvalidSpec { .. }
            | SingBoxProcessError::OpenLog { .. }
            | SingBoxProcessError::Spawn { .. }
            | SingBoxProcessError::ReadChildIdentity { .. }
    ) {
        HostFailure::Expected(safe_process_error_summary(&error))
    } else {
        unavailable_process_error(error)
    }
}

fn classify_readiness_error(error: SingBoxProcessError) -> HostFailure {
    if matches!(
        &error,
        SingBoxProcessError::InvalidSpec { .. }
            | SingBoxProcessError::ExitedBeforeReady { .. }
            | SingBoxProcessError::ReadinessTimedOut { .. }
            | SingBoxProcessError::ReadinessProbe { .. }
    ) {
        HostFailure::Expected(safe_process_error_summary(&error))
    } else {
        unavailable_process_error(error)
    }
}

fn unavailable_process_error(error: SingBoxProcessError) -> HostFailure {
    HostFailure::Unavailable {
        summary: safe_process_error_summary(&error),
        source: Some(Box::new(error)),
    }
}

fn safe_process_error_summary(error: &SingBoxProcessError) -> String {
    bounded_diagnostic(error.to_string())
}

const fn termination_exit(outcome: TerminationOutcome) -> SingBoxExit {
    match outcome {
        TerminationOutcome::AlreadyExited { exit }
        | TerminationOutcome::Terminated { exit }
        | TerminationOutcome::Killed { exit } => exit,
    }
}

fn bounded_diagnostic(mut diagnostic: String) -> String {
    if diagnostic.len() <= MAX_ENGINE_DIAGNOSTIC_BYTES {
        return diagnostic;
    }
    let mut end = MAX_ENGINE_DIAGNOSTIC_BYTES;
    while !diagnostic.is_char_boundary(end) {
        end -= 1;
    }
    diagnostic.truncate(end);
    diagnostic
}

fn inspect_artifact(
    path: &Path,
    artifact: EngineArtifact,
    limit: u64,
) -> Result<EngineArtifactDigest, EngineSpecError> {
    open_inspected_artifact(path, artifact, limit).map(|opened| opened.observed)
}

struct ArtifactIdentity {
    path: PathBuf,
    artifact: EngineArtifact,
    limit: u64,
    expected: EngineArtifactDigest,
}

struct OpenedArtifact {
    file: File,
    identity: ArtifactIdentity,
    observed: EngineArtifactDigest,
}

struct OpenedEngineArtifacts {
    binary: OpenedArtifact,
    config: OpenedArtifact,
    launcher: Option<OpenedArtifact>,
}

struct PreparedEngineArtifacts {
    pinned: PinnedSingBoxLaunch,
    binary: ArtifactIdentity,
    config: ArtifactIdentity,
    launcher: Option<ArtifactIdentity>,
}

impl OpenedEngineArtifacts {
    fn pin(self) -> Result<PreparedEngineArtifacts, SingBoxProcessError> {
        let Self {
            binary,
            config,
            launcher,
        } = self;
        let OpenedArtifact {
            file: binary_file,
            identity: binary,
            ..
        } = binary;
        let OpenedArtifact {
            file: config_file,
            identity: config,
            ..
        } = config;
        let (busybox_file, launcher) = match launcher {
            Some(OpenedArtifact { file, identity, .. }) => (Some(file), Some(identity)),
            None => (None, None),
        };
        let pinned = PinnedSingBoxLaunch::new(binary_file, config_file, busybox_file)?;
        Ok(PreparedEngineArtifacts {
            pinned,
            binary,
            config,
            launcher,
        })
    }
}

impl PreparedEngineArtifacts {
    fn reverify(&self) -> Result<(), EngineSpecError> {
        reverify_opened_artifact(self.pinned.binary(), &self.binary)?;
        reverify_opened_artifact(self.pinned.config(), &self.config)?;
        match (self.pinned.busybox(), &self.launcher) {
            (None, None) => Ok(()),
            (Some(file), Some(identity)) => reverify_opened_artifact(file, identity),
            (None, Some(_)) | (Some(_), None) => {
                unreachable!("pinned launcher descriptor and identity are constructed together")
            }
        }
    }
}

fn open_verified_artifact(
    path: &Path,
    artifact: EngineArtifact,
    limit: u64,
    expected: EngineArtifactDigest,
) -> Result<OpenedArtifact, EngineSpecError> {
    let mut opened = open_inspected_artifact(path, artifact, limit)?;
    if opened.observed != expected {
        return Err(EngineSpecError::DigestMismatch {
            artifact,
            path: path.to_path_buf(),
            expected,
            observed: opened.observed,
        });
    }
    opened.identity.expected = expected;
    Ok(opened)
}

fn open_inspected_artifact(
    path: &Path,
    artifact: EngineArtifact,
    limit: u64,
) -> Result<OpenedArtifact, EngineSpecError> {
    if !path.is_absolute() {
        return Err(EngineSpecError::NonAbsolutePath {
            artifact,
            path: path.to_path_buf(),
        });
    }
    let path_metadata = fs::symlink_metadata(path).map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::InspectPath,
        artifact,
        path: path.to_path_buf(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(EngineSpecError::UnsafeFileType {
            artifact,
            path: path.to_path_buf(),
            source: None,
        });
    }
    if path_metadata.len() > limit {
        return Err(EngineSpecError::TooLarge {
            artifact,
            path: path.to_path_buf(),
            observed: path_metadata.len(),
            limit,
        });
    }

    let file = open_artifact(path).map_err(|source| {
        if is_symlink_open_error(&source) {
            EngineSpecError::UnsafeFileType {
                artifact,
                path: path.to_path_buf(),
                source: Some(source),
            }
        } else {
            EngineSpecError::Io {
                operation: EngineSpecIoOperation::Open,
                artifact,
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    let identity = ArtifactIdentity {
        path: path.to_path_buf(),
        artifact,
        limit,
        expected: EngineArtifactDigest([0; SHA256_DIGEST_BYTES]),
    };
    let observed = inspect_opened_artifact(&file, &identity)?;
    Ok(OpenedArtifact {
        file,
        identity,
        observed,
    })
}

fn reverify_opened_artifact(
    file: &File,
    identity: &ArtifactIdentity,
) -> Result<(), EngineSpecError> {
    let observed = inspect_opened_artifact(file, identity)?;
    if observed == identity.expected {
        Ok(())
    } else {
        Err(EngineSpecError::DigestMismatch {
            artifact: identity.artifact,
            path: identity.path.clone(),
            expected: identity.expected,
            observed,
        })
    }
}

fn inspect_opened_artifact(
    file: &File,
    identity: &ArtifactIdentity,
) -> Result<EngineArtifactDigest, EngineSpecError> {
    let ArtifactIdentity {
        path,
        artifact,
        limit,
        ..
    } = identity;
    let path_metadata = fs::symlink_metadata(path).map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::InspectPath,
        artifact: *artifact,
        path: path.clone(),
        source,
    })?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(EngineSpecError::UnsafeFileType {
            artifact: *artifact,
            path: path.clone(),
            source: None,
        });
    }
    if path_metadata.len() > *limit {
        return Err(EngineSpecError::TooLarge {
            artifact: *artifact,
            path: path.clone(),
            observed: path_metadata.len(),
            limit: *limit,
        });
    }
    let before = file.metadata().map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::InspectDescriptor,
        artifact: *artifact,
        path: path.clone(),
        source,
    })?;
    if !before.file_type().is_file() || !same_opened_file(&path_metadata, &before) {
        return Err(EngineSpecError::UnsafeFileType {
            artifact: *artifact,
            path: path.clone(),
            source: None,
        });
    }
    if metadata_changed(&path_metadata, &before) {
        return Err(EngineSpecError::ChangedDuringInspection {
            artifact: *artifact,
            path: path.clone(),
        });
    }
    if before.len() > *limit {
        return Err(EngineSpecError::TooLarge {
            artifact: *artifact,
            path: path.clone(),
            observed: before.len(),
            limit: *limit,
        });
    }

    let (digest, observed) = hash_opened_artifact(file, identity)?;

    let after = file.metadata().map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::InspectDescriptor,
        artifact: *artifact,
        path: path.clone(),
        source,
    })?;
    if metadata_changed(&before, &after) || observed != after.len() {
        return Err(EngineSpecError::ChangedDuringInspection {
            artifact: *artifact,
            path: path.clone(),
        });
    }
    let current_path = fs::symlink_metadata(path).map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::InspectPath,
        artifact: *artifact,
        path: path.clone(),
        source,
    })?;
    if current_path.file_type().is_symlink() || !current_path.file_type().is_file() {
        return Err(EngineSpecError::UnsafeFileType {
            artifact: *artifact,
            path: path.clone(),
            source: None,
        });
    }
    if !same_opened_file(&current_path, &after) || metadata_changed(&path_metadata, &current_path) {
        return Err(EngineSpecError::ChangedDuringInspection {
            artifact: *artifact,
            path: path.clone(),
        });
    }
    Ok(digest)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn hash_opened_artifact(
    file: &File,
    identity: &ArtifactIdentity,
) -> Result<(EngineArtifactDigest, u64), EngineSpecError> {
    use std::os::unix::fs::FileExt;

    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read_at(&mut buffer, observed)
            .map_err(|source| EngineSpecError::Io {
                operation: EngineSpecIoOperation::Read,
                artifact: identity.artifact,
                path: identity.path.clone(),
                source,
            })?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if observed > identity.limit {
            return Err(EngineSpecError::TooLarge {
                artifact: identity.artifact,
                path: identity.path.clone(),
                observed,
                limit: identity.limit,
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok((EngineArtifactDigest(hasher.finalize().into()), observed))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn hash_opened_artifact(
    file: &File,
    identity: &ArtifactIdentity,
) -> Result<(EngineArtifactDigest, u64), EngineSpecError> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = file.try_clone().map_err(|source| EngineSpecError::Io {
        operation: EngineSpecIoOperation::Open,
        artifact: identity.artifact,
        path: identity.path.clone(),
        source,
    })?;
    file.seek(SeekFrom::Start(0))
        .map_err(|source| EngineSpecError::Io {
            operation: EngineSpecIoOperation::Read,
            artifact: identity.artifact,
            path: identity.path.clone(),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| EngineSpecError::Io {
                operation: EngineSpecIoOperation::Read,
                artifact: identity.artifact,
                path: identity.path.clone(),
                source,
            })?;
        if read == 0 {
            break;
        }
        observed = observed.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if observed > identity.limit {
            return Err(EngineSpecError::TooLarge {
                artifact: identity.artifact,
                path: identity.path.clone(),
                observed,
                limit: identity.limit,
            });
        }
        hasher.update(&buffer[..read]);
    }
    Ok((EngineArtifactDigest(hasher.finalize().into()), observed))
}

fn open_artifact(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    options.open(path)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_symlink_open_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_symlink_open_error(_error: &io::Error) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn same_opened_file(path: &fs::Metadata, descriptor: &fs::Metadata) -> bool {
    path.dev() == descriptor.dev() && path.ino() == descriptor.ino()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn same_opened_file(_path: &fs::Metadata, _descriptor: &fs::Metadata) -> bool {
    true
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn metadata_changed(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn metadata_changed(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() != after.len() || before.modified().ok() != after.modified().ok()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::num::NonZeroU16;
    use std::ops::Deref;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex, MutexGuard};

    use flux_platform::{SingBoxLauncher, SingBoxReadiness};

    use super::*;

    #[test]
    fn running_reconciliation_reaches_ready_with_identity_and_evidence() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));

        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");

        assert!(matches!(report, EngineReport::Started { .. }));
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.phase(), EnginePhase::Ready);
        assert_eq!(
            snapshot.owned_identity().map(OwnedEngineIdentity::pid),
            Some(1000)
        );
        assert!(matches!(
            snapshot.owned_resource_readiness(),
            Some(ReadinessEvidence::Listener { port, .. }) if port.get() == 1536
        ));
        assert_eq!(snapshot.restart_attempts(), 0);
    }

    #[test]
    fn identical_running_reconciliation_is_idempotent() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        let revision = supervisor.snapshot().revision();

        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect("same Desired State is healthy");

        assert_eq!(report, EngineReport::NoChange { revision });
        assert_eq!(supervisor.snapshot().revision(), revision);
    }

    #[test]
    fn stop_refuses_to_kill_while_capture_is_published() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        let identity = supervisor.snapshot().owned_identity();

        let error = supervisor
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Published)
            .expect_err("capture must be detached first");

        assert!(matches!(
            error,
            EngineSupervisorError::CaptureStillPublished {
                action: CaptureBlockedAction::Stop,
                ..
            }
        ));
        assert_eq!(
            supervisor.snapshot().phase(),
            EnginePhase::AwaitingCaptureRemoval
        );
        assert_eq!(supervisor.snapshot().owned_identity(), identity);
    }

    #[test]
    fn changed_spec_refuses_to_replace_while_capture_is_published() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let first = test_spec(1536, restart_policy(3));
        let second = test_spec(2536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&first), CaptureObservation::Detached)
            .expect("start succeeds");
        let identity = supervisor.snapshot().owned_identity();

        let error = supervisor
            .reconcile(
                DesiredEngine::Running(&second),
                CaptureObservation::Published,
            )
            .expect_err("replacement must wait for capture detachment");

        assert!(matches!(
            error,
            EngineSupervisorError::CaptureStillPublished {
                action: CaptureBlockedAction::Replace,
                ..
            }
        ));
        assert_eq!(supervisor.snapshot().owned_identity(), identity);
    }

    #[test]
    fn unexpected_exit_waits_for_capture_detachment_before_restart() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.exit_next(SingBoxExit::Code(17));

        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect("exit is an observed outcome");

        assert!(matches!(
            report,
            EngineReport::AwaitingCaptureRemoval { .. }
        ));
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.phase(), EnginePhase::AwaitingCaptureRemoval);
        assert_eq!(snapshot.owned_identity(), None);
        assert_eq!(snapshot.last_exit(), Some(SingBoxExit::Code(17)));
    }

    #[test]
    fn exited_child_does_not_publish_stopped_until_capture_is_detached() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.exit_next(SingBoxExit::Code(0));

        let awaiting = supervisor
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Published)
            .expect("published capture must be removed");
        assert!(matches!(
            awaiting,
            EngineReport::AwaitingCaptureRemoval { .. }
        ));
        assert_eq!(
            supervisor.snapshot().phase(),
            EnginePhase::AwaitingCaptureRemoval
        );
        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Stopped, CaptureObservation::Published)
                .expect("repeated observation remains awaiting"),
            EngineReport::AwaitingCaptureRemoval { .. }
        ));

        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
                .expect("detached capture settles stopped"),
            EngineReport::Stopped { .. }
        ));
    }

    #[test]
    fn retries_use_exponential_capped_backoff() {
        let (mut supervisor, host, clock) = test_supervisor();
        let policy = RestartPolicy::new(
            4,
            Duration::from_secs(60),
            Duration::from_secs(2),
            Duration::from_secs(3),
            Duration::from_secs(30),
        )
        .expect("valid policy");
        let spec = test_spec(1536, policy);
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");

        host.exit_next(SingBoxExit::Code(1));
        assert_backoff(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("first exit backs off"),
            Duration::from_secs(2),
        );
        clock.advance(Duration::from_secs(2));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("first restart succeeds");

        host.exit_next(SingBoxExit::Code(2));
        assert_backoff(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("second exit backs off"),
            Duration::from_secs(3),
        );
        assert_eq!(supervisor.snapshot().restart_attempts(), 2);
    }

    #[test]
    fn restart_budget_exhaustion_becomes_failed() {
        let (mut supervisor, host, clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(1));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.exit_next(SingBoxExit::Code(1));
        let first = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("one restart is allowed");
        let delay = match first {
            EngineReport::BackingOff { retry_after, .. } => retry_after,
            other => panic!("expected backoff, got {other:?}"),
        };
        clock.advance(delay);
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("restart succeeds");
        host.exit_next(SingBoxExit::Code(2));

        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("exhaustion is a settled outcome");

        assert!(matches!(report, EngineReport::Failed { .. }));
        assert_eq!(supervisor.snapshot().phase(), EnginePhase::Failed);
        assert_eq!(supervisor.snapshot().restart_attempts(), 1);
    }

    #[test]
    fn exhausted_restart_attempts_expire_outside_the_policy_window() {
        let (mut supervisor, host, clock) = test_supervisor();
        let policy = RestartPolicy::new(
            1,
            Duration::from_secs(5),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .expect("valid policy");
        let spec = test_spec(1536, policy);
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.exit_next(SingBoxExit::Code(1));
        assert_backoff(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("one restart is scheduled"),
            Duration::from_secs(1),
        );
        clock.advance(Duration::from_secs(1));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("restart succeeds");
        host.exit_next(SingBoxExit::Code(2));
        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("budget exhaustion settles"),
            EngineReport::Failed { .. }
        ));

        clock.advance(Duration::from_secs(4));
        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("expired attempt permits recovery");

        assert!(matches!(report, EngineReport::Started { .. }));
        assert_eq!(supervisor.snapshot().restart_attempts(), 0);
    }

    #[test]
    fn stable_ready_period_resets_consecutive_backoff() {
        let (mut supervisor, host, clock) = test_supervisor();
        let policy = RestartPolicy::new(
            3,
            Duration::from_secs(60),
            Duration::from_secs(2),
            Duration::from_secs(8),
            Duration::from_secs(10),
        )
        .expect("valid policy");
        let spec = test_spec(1536, policy);
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.exit_next(SingBoxExit::Code(1));
        assert_backoff(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("first exit backs off"),
            Duration::from_secs(2),
        );
        clock.advance(Duration::from_secs(2));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("restart succeeds");
        clock.advance(Duration::from_secs(10));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect("stable child remains ready");
        host.exit_next(SingBoxExit::Code(2));

        assert_backoff(
            supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("stable period resets backoff"),
            Duration::from_secs(2),
        );
    }

    #[test]
    fn detached_stop_terminates_the_owned_child() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");

        let report = supervisor
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
            .expect("detached stop succeeds");

        assert!(matches!(report, EngineReport::Stopped { .. }));
        let snapshot = supervisor.snapshot();
        assert_eq!(snapshot.phase(), EnginePhase::Stopped);
        assert_eq!(snapshot.owned_identity(), None);
        assert_eq!(snapshot.last_exit(), Some(SingBoxExit::Signal(15)));
    }

    #[test]
    fn kill_pending_stop_stays_owned_until_exit_is_observed() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.terminate_pending_next("post-signal reap still pending");

        let report = supervisor
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
            .expect("pending termination is settled progress");
        assert!(matches!(
            report,
            EngineReport::Stopping { identity, .. } if identity.pid() == 1000
        ));
        assert_eq!(supervisor.snapshot().phase(), EnginePhase::Stopping);
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1000)
        );

        host.exit_next(SingBoxExit::Signal(9));
        let report = supervisor
            .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
            .expect("observed exit completes stop");
        assert!(matches!(report, EngineReport::Stopped { .. }));
        assert_eq!(supervisor.snapshot().owned_identity(), None);
        assert_eq!(supervisor.snapshot().restart_attempts(), 0);
    }

    #[test]
    fn pending_stop_exit_still_waits_for_published_capture_removal() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        host.terminate_pending_next("post-signal reap still pending");
        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
                .expect("stop enters progress"),
            EngineReport::Stopping { .. }
        ));
        host.exit_next(SingBoxExit::Signal(9));

        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Stopped, CaptureObservation::Published)
                .expect("pending exit still requires capture removal"),
            EngineReport::AwaitingCaptureRemoval { .. }
        ));
        assert!(matches!(
            supervisor
                .reconcile(DesiredEngine::Stopped, CaptureObservation::Detached)
                .expect("detached capture settles stopped"),
            EngineReport::Stopped { .. }
        ));
    }

    #[test]
    fn kill_pending_replacement_cannot_spawn_until_old_exit_is_observed() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let first = test_spec(1536, restart_policy(3));
        let second = test_spec(2536, restart_policy(3));
        supervisor
            .reconcile(DesiredEngine::Running(&first), CaptureObservation::Detached)
            .expect("start succeeds");
        host.terminate_pending_next("old child still awaiting reap");

        let first_report = supervisor
            .reconcile(
                DesiredEngine::Running(&second),
                CaptureObservation::Detached,
            )
            .expect("replacement enters stopping progress");
        assert!(matches!(first_report, EngineReport::Stopping { .. }));
        let second_report = supervisor
            .reconcile(
                DesiredEngine::Running(&second),
                CaptureObservation::Detached,
            )
            .expect("occupied child slot still blocks replacement");
        assert!(matches!(second_report, EngineReport::Stopping { .. }));
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1000)
        );

        host.exit_next(SingBoxExit::Signal(9));
        let report = supervisor
            .reconcile(
                DesiredEngine::Running(&second),
                CaptureObservation::Detached,
            )
            .expect("observed exit permits replacement");
        assert!(matches!(report, EngineReport::Started { .. }));
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1001)
        );
        assert_eq!(supervisor.snapshot().restart_attempts(), 0);
    }

    #[test]
    fn readiness_cleanup_cannot_spawn_a_second_child_while_kill_is_pending() {
        let (mut supervisor, host, clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        host.fail_next(LaunchFailure::Readiness, "readiness failed");
        host.terminate_pending_next("unready child still awaiting reap");

        let first = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("cleanup enters stopping progress");
        assert!(matches!(first, EngineReport::Stopping { .. }));
        let second = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("occupied child slot prevents retry");
        assert!(matches!(second, EngineReport::Stopping { .. }));
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1000)
        );

        host.exit_next(SingBoxExit::Signal(9));
        let backoff = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("observed cleanup exit resolves launch failure");
        let retry_after = match backoff {
            EngineReport::BackingOff { retry_after, .. } => retry_after,
            other => panic!("expected backoff, got {other:?}"),
        };
        clock.advance(retry_after);
        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("retry starts one fresh child");
        assert!(matches!(report, EngineReport::Started { .. }));
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1001)
        );
    }

    #[test]
    fn operational_launch_failures_are_bounded_outcomes() {
        for failure in [
            LaunchFailure::Validation,
            LaunchFailure::Spawn,
            LaunchFailure::Readiness,
        ] {
            let (mut supervisor, host, _clock) = test_supervisor();
            let spec = test_spec(1536, restart_policy(2));
            host.fail_next(failure, "scripted operational failure");

            let report = supervisor
                .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
                .expect("operational failure is not an adapter error");

            assert!(matches!(report, EngineReport::BackingOff { .. }));
            let snapshot = supervisor.snapshot();
            assert_eq!(snapshot.phase(), EnginePhase::BackingOff);
            assert_eq!(
                snapshot.last_diagnostic(),
                Some("scripted operational failure")
            );
            assert!(snapshot.last_diagnostic().unwrap().len() <= MAX_ENGINE_DIAGNOSTIC_BYTES);
        }
    }

    #[test]
    fn readiness_adapter_failure_cleans_up_before_a_later_reconcile() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(2));
        host.fail_readiness_adapter_next("readiness adapter unavailable");

        let error = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect_err("adapter failure is returned");

        assert_eq!(error.kind(), EngineSupervisorErrorKind::AdapterUnavailable);
        let failed = supervisor.snapshot();
        assert_eq!(failed.phase(), EnginePhase::Failed);
        assert_eq!(failed.owned_identity(), None);
        assert_eq!(
            failed.last_diagnostic(),
            Some("readiness adapter unavailable")
        );

        let report = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("a later reconcile can own one fresh child");
        assert!(matches!(report, EngineReport::Started { .. }));
        assert_eq!(
            supervisor
                .snapshot()
                .owned_identity()
                .map(OwnedEngineIdentity::pid),
            Some(1001)
        );
    }

    #[test]
    fn adapter_unavailable_error_preserves_the_process_error_source() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(2));
        host.fail_readiness_process_next(SingBoxProcessError::UnsupportedPlatform {
            platform: "scripted",
        });

        let error = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect_err("adapter error is returned after cleanup");

        assert_eq!(error.kind(), EngineSupervisorErrorKind::AdapterUnavailable);
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<SingBoxProcessError>())
                .is_some()
        );
        assert_eq!(
            supervisor.snapshot().last_diagnostic(),
            Some("Sing-Box process control is unsupported on 'scripted'")
        );
    }

    #[test]
    fn stale_reused_spec_is_rejected_without_disturbing_a_healthy_child() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(2));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        let ready = supervisor.snapshot();
        host.fail_artifact_verification_after(0, EngineArtifact::Config);

        let error = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect_err("stale inspected artifacts are rejected");

        assert_eq!(
            error.kind(),
            EngineSupervisorErrorKind::ArtifactVerification
        );
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<EngineSpecError>())
                .is_some()
        );
        assert_eq!(supervisor.snapshot().as_ref(), ready.as_ref());
    }

    #[test]
    fn same_path_content_change_produces_a_distinct_inspected_spec() {
        let (mut supervisor, _host, _clock) = test_supervisor();
        let original = test_spec(1536, restart_policy(2));
        supervisor
            .reconcile(
                DesiredEngine::Running(&original),
                CaptureObservation::Detached,
            )
            .expect("start succeeds");
        fs::write(
            &original.process().config,
            br#"{"inbounds":[{"type":"tproxy"}]}"#,
        )
        .expect("replace config contents");
        let refreshed = EngineSpec::new(original.process().clone(), original.restart_policy())
            .expect("inspect refreshed artifacts");
        assert_ne!(original.config_digest(), refreshed.config_digest());
        assert_ne!(&original.spec, &refreshed);

        let error = supervisor
            .reconcile(
                DesiredEngine::Running(&refreshed),
                CaptureObservation::Published,
            )
            .expect_err("fresh content identity requests replacement");
        assert!(matches!(
            error,
            EngineSupervisorError::CaptureStillPublished {
                action: CaptureBlockedAction::Replace,
                ..
            }
        ));
    }

    #[test]
    fn same_path_busybox_change_produces_a_distinct_inspected_spec() {
        let directory = tempfile::tempdir().expect("create BusyBox identity fixture");
        let binary = directory.path().join("sing-box");
        let config = directory.path().join("config.json");
        let busybox = directory.path().join("busybox");
        fs::write(&binary, b"sing-box").expect("write binary");
        fs::write(&config, b"{}").expect("write config");
        fs::write(&busybox, b"busybox-v1").expect("write BusyBox");
        let process = SingBoxLaunchSpec {
            binary,
            config,
            working_directory: directory.path().to_path_buf(),
            log: directory.path().join("sing-box.log"),
            launcher: SingBoxLauncher::BusyBoxSetuidgid {
                busybox: busybox.clone(),
                identity: "1000:1000".into(),
            },
            readiness: SingBoxReadiness::Listener {
                port: NonZeroU16::new(1536).expect("nonzero port"),
            },
            startup_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        };
        let original = EngineSpec::new(process.clone(), restart_policy(1))
            .expect("inspect original BusyBox launch");

        fs::write(&busybox, b"busybox-v2").expect("replace BusyBox contents");
        let refreshed =
            EngineSpec::new(process, restart_policy(1)).expect("inspect refreshed BusyBox launch");

        assert_ne!(original.launcher_digest(), refreshed.launcher_digest());
        assert_ne!(original, refreshed);
    }

    #[test]
    fn post_spawn_artifact_change_cleans_up_before_returning_error() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(2));
        host.fail_artifact_verification_after(3, EngineArtifact::Binary);

        let error = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect_err("post-spawn verification failure is returned");

        assert_eq!(
            error.kind(),
            EngineSupervisorErrorKind::ArtifactVerification
        );
        assert_eq!(supervisor.snapshot().phase(), EnginePhase::Failed);
        assert_eq!(supervisor.snapshot().owned_identity(), None);
    }

    #[test]
    fn post_check_artifact_change_prevents_spawn() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(2));
        host.fail_artifact_verification_after(2, EngineArtifact::Config);

        let error = supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect_err("post-check artifact change is rejected before spawn");

        assert_eq!(
            error.kind(),
            EngineSupervisorErrorKind::ArtifactVerification
        );
        assert_eq!(supervisor.snapshot().phase(), EnginePhase::Checking);
        assert_eq!(supervisor.snapshot().owned_identity(), None);
    }

    #[test]
    fn engine_spec_rejects_nonregular_oversized_and_missing_artifacts() {
        let directory = tempfile::tempdir().expect("create artifact fixture");
        let binary = directory.path().join("sing-box");
        fs::write(&binary, b"binary").expect("write binary");
        let process = |config: PathBuf| SingBoxLaunchSpec {
            binary: binary.clone(),
            config,
            working_directory: directory.path().to_path_buf(),
            log: directory.path().join("sing-box.log"),
            launcher: SingBoxLauncher::Direct,
            readiness: SingBoxReadiness::Listener {
                port: NonZeroU16::new(1536).expect("nonzero port"),
            },
            startup_timeout: Duration::from_secs(1),
            stop_timeout: Duration::from_secs(1),
        };

        assert!(matches!(
            EngineSpec::new(process(directory.path().to_path_buf()), restart_policy(1)),
            Err(EngineSpecError::UnsafeFileType {
                artifact: EngineArtifact::Config,
                ..
            })
        ));
        assert!(matches!(
            EngineSpec::new(process(PathBuf::from("relative.json")), restart_policy(1)),
            Err(EngineSpecError::NonAbsolutePath {
                artifact: EngineArtifact::Config,
                ..
            })
        ));

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            let target = directory.path().join("target.json");
            let link = directory.path().join("linked.json");
            fs::write(&target, b"{}").expect("write symlink target");
            std::os::unix::fs::symlink(&target, &link).expect("create config symlink");
            assert!(matches!(
                EngineSpec::new(process(link), restart_policy(1)),
                Err(EngineSpecError::UnsafeFileType {
                    artifact: EngineArtifact::Config,
                    ..
                })
            ));
        }

        let oversized = directory.path().join("oversized.json");
        File::create(&oversized)
            .expect("create oversized config")
            .set_len(MAX_ENGINE_CONFIG_BYTES + 1)
            .expect("size oversized config");
        assert!(matches!(
            EngineSpec::new(process(oversized), restart_policy(1)),
            Err(EngineSpecError::TooLarge {
                artifact: EngineArtifact::Config,
                ..
            })
        ));

        let missing = directory.path().join("missing.json");
        let error = EngineSpec::new(process(missing), restart_policy(1))
            .expect_err("missing config is rejected");
        assert!(std::error::Error::source(&error).is_some());

        let config = directory.path().join("valid.json");
        fs::write(&config, b"{}").expect("write valid config");
        let busybox_process = |busybox: PathBuf| {
            let mut process = process(config.clone());
            process.launcher = SingBoxLauncher::BusyBoxSetuidgid {
                busybox,
                identity: "1000:1000".into(),
            };
            process
        };
        assert!(matches!(
            EngineSpec::new(
                busybox_process(directory.path().to_path_buf()),
                restart_policy(1)
            ),
            Err(EngineSpecError::UnsafeFileType {
                artifact: EngineArtifact::Launcher,
                ..
            })
        ));

        let oversized_busybox = directory.path().join("oversized-busybox");
        File::create(&oversized_busybox)
            .expect("create oversized BusyBox")
            .set_len(MAX_ENGINE_BINARY_BYTES + 1)
            .expect("size oversized BusyBox");
        assert!(matches!(
            EngineSpec::new(busybox_process(oversized_busybox), restart_policy(1)),
            Err(EngineSpecError::TooLarge {
                artifact: EngineArtifact::Launcher,
                ..
            })
        ));

        let missing_busybox = directory.path().join("missing-busybox");
        let error = EngineSpec::new(busybox_process(missing_busybox), restart_policy(1))
            .expect_err("missing BusyBox is rejected");
        assert!(matches!(
            &error,
            EngineSpecError::Io {
                artifact: EngineArtifact::Launcher,
                ..
            }
        ));
        assert!(std::error::Error::source(&error).is_some());
    }

    #[test]
    fn revision_changes_only_with_observable_snapshot_evidence() {
        let (mut supervisor, host, _clock) = test_supervisor();
        let spec = test_spec(1536, restart_policy(3));
        let initial = supervisor.snapshot();
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Detached)
            .expect("start succeeds");
        let ready = supervisor.snapshot();
        assert!(ready.revision() > initial.revision());
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect("idempotent reconcile succeeds");
        assert_eq!(supervisor.snapshot().revision(), ready.revision());

        host.exit_next(SingBoxExit::Signal(9));
        supervisor
            .reconcile(DesiredEngine::Running(&spec), CaptureObservation::Published)
            .expect("exit is observed");
        assert!(supervisor.snapshot().revision() > ready.revision());
    }

    #[test]
    fn restart_policy_rejects_zero_and_inverted_limits() {
        let positive = Duration::from_secs(1);
        assert_eq!(
            RestartPolicy::new(0, positive, positive, positive, positive),
            Err(RestartPolicyError::ZeroMaximumAttempts)
        );
        assert_eq!(
            RestartPolicy::new(1, Duration::ZERO, positive, positive, positive),
            Err(RestartPolicyError::ZeroWindow)
        );
        assert_eq!(
            RestartPolicy::new(1, positive, Duration::ZERO, positive, positive),
            Err(RestartPolicyError::ZeroInitialBackoff)
        );
        assert_eq!(
            RestartPolicy::new(1, positive, positive, Duration::ZERO, positive),
            Err(RestartPolicyError::ZeroMaximumBackoff)
        );
        assert_eq!(
            RestartPolicy::new(1, positive, positive, positive, Duration::ZERO),
            Err(RestartPolicyError::ZeroStableReset)
        );
        assert_eq!(
            RestartPolicy::new(1, positive, Duration::from_secs(2), positive, positive,),
            Err(RestartPolicyError::InitialBackoffExceedsMaximum)
        );
    }

    fn assert_backoff(report: EngineReport, expected: Duration) {
        match report {
            EngineReport::BackingOff { retry_after, .. } => {
                assert_eq!(retry_after, expected);
            }
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    fn restart_policy(max_attempts: u32) -> RestartPolicy {
        RestartPolicy::new(
            max_attempts,
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_secs(8),
            Duration::from_secs(10),
        )
        .expect("test restart policy is valid")
    }

    struct TestEngineSpec {
        spec: EngineSpec,
        _directory: tempfile::TempDir,
    }

    impl Deref for TestEngineSpec {
        type Target = EngineSpec;

        fn deref(&self) -> &Self::Target {
            &self.spec
        }
    }

    fn test_spec(port: u16, restart: RestartPolicy) -> TestEngineSpec {
        let directory = tempfile::tempdir().expect("create engine fixture");
        let binary = directory.path().join("sing-box");
        let config = directory.path().join(format!("config-{port}.json"));
        fs::write(&binary, b"scripted sing-box binary").expect("write binary fixture");
        fs::write(&config, br#"{"inbounds":[]}"#).expect("write config fixture");
        let spec = EngineSpec::new(
            SingBoxLaunchSpec {
                binary,
                config,
                working_directory: directory.path().to_path_buf(),
                log: directory.path().join("sing-box.log"),
                launcher: SingBoxLauncher::Direct,
                readiness: SingBoxReadiness::Listener {
                    port: NonZeroU16::new(port).expect("test port is nonzero"),
                },
                startup_timeout: Duration::from_secs(5),
                stop_timeout: Duration::from_secs(5),
            },
            restart,
        )
        .expect("inspect test engine artifacts");
        TestEngineSpec {
            spec,
            _directory: directory,
        }
    }

    fn test_supervisor() -> (EngineSupervisor, ScriptedHostHandle, ManualClock) {
        let (host, handle) = ScriptedEngineHost::new();
        let clock = ManualClock::default();
        let supervisor =
            EngineSupervisor::with_dependencies(Box::new(host), Box::new(clock.clone()));
        (supervisor, handle, clock)
    }

    #[derive(Clone, Copy)]
    enum LaunchFailure {
        Validation,
        Spawn,
        Readiness,
    }

    #[derive(Default)]
    struct ScriptState {
        next_pid: u32,
        validation_failures: VecDeque<String>,
        spawn_failures: VecDeque<String>,
        readiness_failures: VecDeque<String>,
        readiness_adapter_failures: VecDeque<String>,
        readiness_process_errors: VecDeque<SingBoxProcessError>,
        artifact_verifications: VecDeque<Option<EngineArtifact>>,
        termination_pending: VecDeque<String>,
        exits: VecDeque<SingBoxExit>,
    }

    fn scripted_artifact_verification(
        state: &mut ScriptState,
        spec: &EngineSpec,
    ) -> Result<(), EngineSpecError> {
        let Some(Some(artifact)) = state.artifact_verifications.pop_front() else {
            return Ok(());
        };
        let (path, expected) = match artifact {
            EngineArtifact::Binary => (&spec.process.binary, spec.binary_digest),
            EngineArtifact::Config => (&spec.process.config, spec.config_digest),
            EngineArtifact::Launcher => match (&spec.process.launcher, spec.launcher_digest) {
                (SingBoxLauncher::BusyBoxSetuidgid { busybox, .. }, Some(launcher_digest)) => {
                    (busybox, launcher_digest)
                }
                (SingBoxLauncher::Direct, None) => {
                    return Err(EngineSpecError::ChangedDuringInspection {
                        artifact,
                        path: spec.process.binary.clone(),
                    });
                }
                _ => unreachable!("EngineSpec launcher identity is internally consistent"),
            },
        };
        let mut observed = *expected.as_bytes();
        observed[0] ^= 0xff;
        Err(EngineSpecError::DigestMismatch {
            artifact,
            path: path.clone(),
            expected,
            observed: EngineArtifactDigest(observed),
        })
    }

    struct ScriptedEngineHost {
        state: Arc<Mutex<ScriptState>>,
    }

    #[derive(Clone)]
    struct ScriptedHostHandle {
        state: Arc<Mutex<ScriptState>>,
    }

    impl ScriptedEngineHost {
        fn new() -> (Self, ScriptedHostHandle) {
            let state = Arc::new(Mutex::new(ScriptState {
                next_pid: 1000,
                ..ScriptState::default()
            }));
            (
                Self {
                    state: Arc::clone(&state),
                },
                ScriptedHostHandle { state },
            )
        }

        fn lock(&self) -> MutexGuard<'_, ScriptState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl ScriptedHostHandle {
        fn exit_next(&self, exit: SingBoxExit) {
            self.lock().exits.push_back(exit);
        }

        fn fail_next(&self, failure: LaunchFailure, diagnostic: &str) {
            let mut state = self.lock();
            let queue = match failure {
                LaunchFailure::Validation => &mut state.validation_failures,
                LaunchFailure::Spawn => &mut state.spawn_failures,
                LaunchFailure::Readiness => &mut state.readiness_failures,
            };
            queue.push_back(diagnostic.to_owned());
        }

        fn fail_readiness_adapter_next(&self, diagnostic: &str) {
            self.lock()
                .readiness_adapter_failures
                .push_back(diagnostic.to_owned());
        }

        fn fail_readiness_process_next(&self, error: SingBoxProcessError) {
            self.lock().readiness_process_errors.push_back(error);
        }

        fn terminate_pending_next(&self, diagnostic: &str) {
            self.lock()
                .termination_pending
                .push_back(diagnostic.to_owned());
        }

        fn fail_artifact_verification_after(
            &self,
            successful_verifications: usize,
            artifact: EngineArtifact,
        ) {
            let mut state = self.lock();
            state
                .artifact_verifications
                .extend(std::iter::repeat_n(None, successful_verifications));
            state.artifact_verifications.push_back(Some(artifact));
        }

        fn lock(&self) -> MutexGuard<'_, ScriptState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl EngineHost for ScriptedEngineHost {
        fn prepare(&mut self, spec: &EngineSpec) -> Result<HostPrepared, HostFailure> {
            scripted_artifact_verification(&mut self.lock(), spec)
                .map_err(HostFailure::Artifact)?;
            Ok(HostPrepared::Scripted)
        }

        fn reverify(
            &mut self,
            spec: &EngineSpec,
            prepared: &HostPrepared,
        ) -> Result<(), EngineSpecError> {
            if !matches!(prepared, HostPrepared::Scripted) {
                return Err(EngineSpecError::ChangedDuringInspection {
                    artifact: EngineArtifact::Binary,
                    path: spec.process.binary.clone(),
                });
            }
            scripted_artifact_verification(&mut self.lock(), spec)
        }

        fn validate(
            &mut self,
            _spec: &SingBoxLaunchSpec,
            prepared: &HostPrepared,
        ) -> Result<(), HostFailure> {
            if !matches!(prepared, HostPrepared::Scripted) {
                return Err(HostFailure::Invariant(
                    "scripted host received production prepared artifacts".to_owned(),
                ));
            }
            match self.lock().validation_failures.pop_front() {
                Some(diagnostic) => Err(HostFailure::Expected(diagnostic)),
                None => Ok(()),
            }
        }

        fn spawn(
            &mut self,
            _spec: &SingBoxLaunchSpec,
            prepared: &HostPrepared,
        ) -> Result<HostChild, HostFailure> {
            if !matches!(prepared, HostPrepared::Scripted) {
                return Err(HostFailure::Invariant(
                    "scripted host received production prepared artifacts".to_owned(),
                ));
            }
            let mut state = self.lock();
            if let Some(diagnostic) = state.spawn_failures.pop_front() {
                return Err(HostFailure::Expected(diagnostic));
            }
            let pid = state.next_pid;
            state.next_pid = state.next_pid.saturating_add(1);
            Ok(HostChild::Scripted(ScriptedChild {
                identity: OwnedEngineIdentity {
                    pid,
                    start_time_ticks: u64::from(pid) * 10,
                },
            }))
        }

        fn wait_ready(
            &mut self,
            child: &mut HostChild,
            spec: &SingBoxLaunchSpec,
        ) -> Result<ReadinessEvidence, HostFailure> {
            if !matches!(child, HostChild::Scripted(_)) {
                return Err(HostFailure::Invariant(
                    "scripted host received a production child".to_owned(),
                ));
            }
            if let Some(diagnostic) = self.lock().readiness_adapter_failures.pop_front() {
                return Err(HostFailure::unavailable_without_source(diagnostic));
            }
            if let Some(error) = self.lock().readiness_process_errors.pop_front() {
                return Err(unavailable_process_error(error));
            }
            if let Some(diagnostic) = self.lock().readiness_failures.pop_front() {
                return Err(HostFailure::Expected(diagnostic));
            }
            match &spec.readiness {
                SingBoxReadiness::Listener { port } => Ok(ReadinessEvidence::Listener {
                    port: *port,
                    table: PathBuf::from("/proc/net/tcp"),
                }),
                SingBoxReadiness::TunInterface { name } => Ok(ReadinessEvidence::TunInterface {
                    name: name.clone(),
                    path: PathBuf::from("/sys/class/net").join(name),
                }),
            }
        }

        fn try_wait(&mut self, child: &mut HostChild) -> Result<Option<SingBoxExit>, HostFailure> {
            if !matches!(child, HostChild::Scripted(_)) {
                return Err(HostFailure::Invariant(
                    "scripted host received a production child".to_owned(),
                ));
            }
            Ok(self.lock().exits.pop_front())
        }

        fn terminate(
            &mut self,
            child: &mut HostChild,
            _timeout: Duration,
        ) -> Result<HostTermination, HostFailure> {
            if !matches!(child, HostChild::Scripted(_)) {
                return Err(HostFailure::Invariant(
                    "scripted host received a production child".to_owned(),
                ));
            }
            match self.lock().termination_pending.pop_front() {
                Some(diagnostic) => Ok(HostTermination::Pending(diagnostic)),
                None => Ok(HostTermination::Exited(SingBoxExit::Signal(15))),
            }
        }
    }

    #[derive(Clone, Default)]
    struct ManualClock {
        now: Arc<Mutex<Duration>>,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            let mut now = self
                .now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *now = now.saturating_add(duration);
        }
    }

    impl Clock for ManualClock {
        fn now(&self) -> Duration {
            *self
                .now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }
}
