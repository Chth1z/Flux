use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use flux_core::{FluxConfig, GenerationId};
use flux_platform::{SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness};
use url::Url;

use crate::generation_engine_config::{
    EngineConfigArtifact, EngineConfigCompileError, reconstruct_canonical_tproxy_engine_config,
};
use crate::intent_store::record_io;
use crate::runtime_logging::{LogSeverity, runtime_log};
use crate::{EngineSpec, MAX_ENGINE_CONFIG_BYTES, RestartPolicy};

use super::assets::{
    PrepareSubscriptionError, PrepareSubscriptionRequest, RedactedSourceId,
    SubscriptionRefreshLimits, prepare_subscription_refresh, redacted_source_id,
};
use super::fetch::{FetchAdapter, UreqFetchAdapter};
use super::store::{
    SingBoxSnapshotValidator, SnapshotPublicationDisposition, SnapshotValidationErrorKind,
    SubscriptionSnapshotStore, SubscriptionSnapshotStoreError, SubscriptionSnapshotValidator,
    ValidatedSubscriptionSnapshot,
};

const REFRESH_CHANNEL_CAPACITY: usize = 1;
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const COORDINATOR_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SUBSCRIPTION_URL_FILE_BYTES: usize = 4 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionRefreshDisposition {
    Updated,
    UpdatedDeferred,
    Unchanged,
    Disabled,
    Busy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubscriptionRefreshReport {
    disposition: SubscriptionRefreshDisposition,
    generation: Option<GenerationId>,
    node_count: Option<u32>,
    cleanup_pending: bool,
}

impl SubscriptionRefreshReport {
    #[must_use]
    pub const fn disposition(self) -> SubscriptionRefreshDisposition {
        self.disposition
    }

    #[must_use]
    pub const fn generation(self) -> Option<GenerationId> {
        self.generation
    }

    #[must_use]
    pub const fn node_count(self) -> Option<u32> {
        self.node_count
    }

    #[must_use]
    pub const fn cleanup_pending(self) -> bool {
        self.cleanup_pending
    }

    #[must_use]
    pub const fn updated(generation: GenerationId, node_count: u32, cleanup_pending: bool) -> Self {
        Self {
            disposition: SubscriptionRefreshDisposition::Updated,
            generation: Some(generation),
            node_count: Some(node_count),
            cleanup_pending,
        }
    }

    #[must_use]
    pub const fn updated_deferred(node_count: u32, cleanup_pending: bool) -> Self {
        Self {
            disposition: SubscriptionRefreshDisposition::UpdatedDeferred,
            generation: None,
            node_count: Some(node_count),
            cleanup_pending,
        }
    }

    #[must_use]
    pub const fn unchanged(node_count: u32, cleanup_pending: bool) -> Self {
        Self {
            disposition: SubscriptionRefreshDisposition::Unchanged,
            generation: None,
            node_count: Some(node_count),
            cleanup_pending,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            disposition: SubscriptionRefreshDisposition::Disabled,
            generation: None,
            node_count: None,
            cleanup_pending: false,
        }
    }

    #[must_use]
    pub const fn busy() -> Self {
        Self {
            disposition: SubscriptionRefreshDisposition::Busy,
            generation: None,
            node_count: None,
            cleanup_pending: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SubscriptionRefreshErrorKind {
    Configuration,
    UnsupportedIdentity,
    Source,
    Preparation,
    Store,
    SourceChanged,
    WorkerUnavailable,
    Activation,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SubscriptionRefreshError {
    kind: SubscriptionRefreshErrorKind,
    detail: Arc<str>,
}

impl SubscriptionRefreshError {
    #[must_use]
    pub(crate) const fn kind(&self) -> SubscriptionRefreshErrorKind {
        self.kind
    }

    fn new(kind: SubscriptionRefreshErrorKind, detail: impl Into<Arc<str>>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub(crate) fn activation(detail: impl Into<Arc<str>>) -> Self {
        Self::new(SubscriptionRefreshErrorKind::Activation, detail)
    }

    fn rollback(source: impl fmt::Display) -> Self {
        Self::new(
            SubscriptionRefreshErrorKind::Rollback,
            format!("cannot restore the prior subscription snapshot: {source}"),
        )
    }
}

impl SubscriptionRefreshErrorKind {
    pub(crate) const fn rejection_code(self) -> &'static str {
        match self {
            Self::Configuration => "subscription_configuration_failed",
            Self::UnsupportedIdentity => "subscription_identity_unsupported",
            Self::Source => "subscription_source_failed",
            Self::Preparation => "subscription_preparation_failed",
            Self::Store => "subscription_store_failed",
            Self::SourceChanged => "subscription_source_changed",
            Self::WorkerUnavailable => "subscription_worker_unavailable",
            Self::Activation => "subscription_activation_failed",
            Self::Rollback => "subscription_rollback_failed",
        }
    }
}

impl fmt::Display for SubscriptionRefreshError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl Error for SubscriptionRefreshError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedSubscriptionEngineConfig {
    desired_state: Arc<FluxConfig>,
    bytes: Arc<[u8]>,
    content_sha256: [u8; 32],
    snapshot_digest: [u8; 32],
    subscription_source: RedactedSourceId,
    node_count: u32,
}

impl ValidatedSubscriptionEngineConfig {
    fn from_snapshot(snapshot: ValidatedSubscriptionSnapshot, desired_state: &FluxConfig) -> Self {
        Self {
            desired_state: Arc::new(desired_state.clone()),
            bytes: Arc::from(snapshot.bytes()),
            content_sha256: *snapshot.content_sha256(),
            snapshot_digest: *snapshot.digest(),
            subscription_source: snapshot.subscription_source(),
            node_count: snapshot.node_count(),
        }
    }

    pub(crate) fn reconstruct_artifact(
        &self,
        listener_port: std::num::NonZeroU16,
    ) -> Result<EngineConfigArtifact, EngineConfigCompileError> {
        let artifact = reconstruct_canonical_tproxy_engine_config(&self.bytes, listener_port)?;
        if artifact.content_sha256() != &self.content_sha256 {
            return Err(EngineConfigCompileError::content_digest_mismatch());
        }
        Ok(artifact)
    }

    pub(crate) fn desired_state(&self) -> &FluxConfig {
        &self.desired_state
    }

    pub(crate) const fn snapshot_digest(&self) -> [u8; 32] {
        self.snapshot_digest
    }

    pub(crate) const fn subscription_source(&self) -> [u8; 32] {
        self.subscription_source.as_bytes()
    }

    pub(crate) const fn node_count(&self) -> u32 {
        self.node_count
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        desired_state: FluxConfig,
        artifact: EngineConfigArtifact,
        snapshot_digest: [u8; 32],
        node_count: u32,
    ) -> Self {
        Self {
            desired_state: Arc::new(desired_state),
            bytes: Arc::from(artifact.bytes()),
            content_sha256: *artifact.content_sha256(),
            snapshot_digest,
            subscription_source: RedactedSourceId::from_bytes(snapshot_digest),
            node_count,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SubscriptionRuntimePaths {
    desired_state: PathBuf,
    store_root: PathBuf,
    working_directory: PathBuf,
    validation_log: PathBuf,
}

impl SubscriptionRuntimePaths {
    pub(crate) fn new(
        desired_state: impl AsRef<Path>,
        store_root: impl AsRef<Path>,
        working_directory: impl AsRef<Path>,
        validation_log: impl AsRef<Path>,
    ) -> Self {
        Self {
            desired_state: desired_state.as_ref().to_owned(),
            store_root: store_root.as_ref().to_owned(),
            working_directory: working_directory.as_ref().to_owned(),
            validation_log: validation_log.as_ref().to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefreshSchedule {
    Unchanged,
    Disabled,
    Enabled(Duration),
}

struct RefreshAttempt {
    schedule: RefreshSchedule,
    result: Result<RefreshPayload, SubscriptionRefreshError>,
}

enum RefreshPayload {
    Disabled,
    Unchanged {
        node_count: u32,
        cleanup_pending: bool,
    },
    Published {
        config: ValidatedSubscriptionEngineConfig,
        cleanup_pending: bool,
    },
}

trait RefreshOperation: Send + 'static {
    fn refresh(&mut self) -> RefreshAttempt;
    fn reject(&mut self, digest: [u8; 32]) -> Result<(), SubscriptionRefreshError>;
}

trait RefreshEngineValidator: Send + Sync + 'static {
    fn validate(
        &self,
        engine: &EngineSpec,
        config_path: &Path,
    ) -> Result<(), SnapshotValidationErrorKind>;
}

#[derive(Default)]
struct ProcessRefreshEngineValidator;

impl RefreshEngineValidator for ProcessRefreshEngineValidator {
    fn validate(
        &self,
        engine: &EngineSpec,
        config_path: &Path,
    ) -> Result<(), SnapshotValidationErrorKind> {
        SingBoxSnapshotValidator::from_engine(engine).validate(config_path)
    }
}

#[derive(Clone)]
struct RefreshSnapshotValidator {
    engine: Arc<Mutex<Option<EngineSpec>>>,
    validator: Arc<dyn RefreshEngineValidator>,
}

impl Default for RefreshSnapshotValidator {
    fn default() -> Self {
        Self {
            engine: Arc::default(),
            validator: Arc::new(ProcessRefreshEngineValidator),
        }
    }
}

impl RefreshSnapshotValidator {
    fn new(validator: Arc<dyn RefreshEngineValidator>) -> Self {
        Self {
            engine: Arc::default(),
            validator,
        }
    }

    fn install(&self, engine: EngineSpec) {
        match self.engine.lock() {
            Ok(mut slot) => *slot = Some(engine),
            Err(poisoned) => *poisoned.into_inner() = Some(engine),
        }
    }
}

impl SubscriptionSnapshotValidator for RefreshSnapshotValidator {
    fn validate(&self, config_path: &Path) -> Result<(), SnapshotValidationErrorKind> {
        let engine = match self.engine.lock() {
            Ok(engine) => engine.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
        .ok_or(SnapshotValidationErrorKind::Artifact)?;
        self.validator.validate(&engine, config_path)
    }
}

struct ProductionRefreshOperation<A> {
    paths: SubscriptionRuntimePaths,
    adapter: A,
    validator: RefreshSnapshotValidator,
    store: SubscriptionSnapshotStore<RefreshSnapshotValidator>,
}

impl<A: FetchAdapter + Send + 'static> ProductionRefreshOperation<A> {
    fn new(paths: SubscriptionRuntimePaths, adapter: A) -> Result<Self, SubscriptionRefreshError> {
        Self::with_engine_validator(paths, adapter, Arc::new(ProcessRefreshEngineValidator))
    }

    fn with_engine_validator(
        paths: SubscriptionRuntimePaths,
        adapter: A,
        engine_validator: Arc<dyn RefreshEngineValidator>,
    ) -> Result<Self, SubscriptionRefreshError> {
        let validator = RefreshSnapshotValidator::new(engine_validator);
        let store = SubscriptionSnapshotStore::new(&paths.store_root, validator.clone())
            .map_err(store_error)?;
        Ok(Self {
            paths,
            adapter,
            validator,
            store,
        })
    }

    fn recover(
        &mut self,
        desired_state: &FluxConfig,
    ) -> Result<(Option<ValidatedSubscriptionEngineConfig>, bool), SubscriptionRefreshError> {
        let report = self.store.recover().map_err(store_error)?;
        let cleanup_pending = report.cleanup_pending();
        if !desired_state.subscription().enabled() {
            return Ok((None, cleanup_pending));
        }
        let current_source = subscription_source(desired_state)?;
        Ok((
            report
                .into_active()
                .filter(|snapshot| snapshot.subscription_source() == current_source)
                .map(|snapshot| {
                    ValidatedSubscriptionEngineConfig::from_snapshot(snapshot, desired_state)
                }),
            cleanup_pending,
        ))
    }

    fn refresh_inner(
        &mut self,
        config: &FluxConfig,
    ) -> Result<RefreshPayload, SubscriptionRefreshError> {
        require_supported_identity(config)?;
        let template = read_required_file(
            config.engine().template(),
            usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap_or(usize::MAX),
            "engine template",
        )?;
        let validation_spec = validation_engine(config, &self.paths)?;
        self.validator.install(validation_spec.clone());
        let subscription_url = read_subscription_url(config.subscription().url_file())?;
        let expected_subscription_source = redacted_source_id(&subscription_url);
        let prepared = prepare_subscription_refresh(
            &self.adapter,
            PrepareSubscriptionRequest::new(
                &template,
                &subscription_url,
                &self.store.asset_root(),
                config.listener().port(),
                SubscriptionRefreshLimits::new(
                    config.subscription().download_timeout(),
                    config.subscription().max_download_bytes(),
                    config.subscription().max_decoded_bytes(),
                    config.subscription().max_nodes(),
                ),
            ),
        )
        .map_err(preparation_error)?;
        debug_assert_eq!(prepared.subscription_source(), expected_subscription_source);
        let candidate_digest = *prepared.digest();
        let report = self.store.publish(prepared).map_err(store_error)?;
        let publication = report.publication();
        let cleanup_pending = report.cleanup_pending();

        let sources_unchanged = (|| {
            let current_config = FluxConfig::load(&self.paths.desired_state)
                .map_err(|source| configuration_error(&self.paths.desired_state, source))?;
            let current_template = read_required_file(
                current_config.engine().template(),
                usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap_or(usize::MAX),
                "engine template",
            )?;
            let current_engine = validation_engine(&current_config, &self.paths)?;
            let current_subscription_source = subscription_source(&current_config)?;
            Ok::<bool, SubscriptionRefreshError>(
                &current_config == config
                    && current_template == template
                    && current_engine == validation_spec
                    && current_subscription_source == expected_subscription_source,
            )
        })();
        if !matches!(sources_unchanged, Ok(true)) {
            if publication == SnapshotPublicationDisposition::Published {
                self.store
                    .reject_active(candidate_digest)
                    .map_err(SubscriptionRefreshError::rollback)?;
            }
            return Err(SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::SourceChanged,
                "subscription inputs changed during refresh; the candidate was not accepted",
            ));
        }

        let active = report.into_active().ok_or_else(|| {
            SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::Store,
                "subscription publication returned no active validated snapshot",
            )
        })?;
        let config = ValidatedSubscriptionEngineConfig::from_snapshot(active, config);
        match publication {
            SnapshotPublicationDisposition::Published => Ok(RefreshPayload::Published {
                config,
                cleanup_pending,
            }),
            SnapshotPublicationDisposition::ValidatedNoChange => Ok(RefreshPayload::Unchanged {
                node_count: config.node_count(),
                cleanup_pending,
            }),
            SnapshotPublicationDisposition::Recovered
            | SnapshotPublicationDisposition::Rejected => Err(SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::Store,
                "subscription publication returned an impossible store disposition",
            )),
        }
    }
}

impl<A: FetchAdapter + Send + 'static> RefreshOperation for ProductionRefreshOperation<A> {
    fn refresh(&mut self) -> RefreshAttempt {
        let config = match FluxConfig::load(&self.paths.desired_state) {
            Ok(config) => config,
            Err(source) => {
                return RefreshAttempt {
                    schedule: RefreshSchedule::Unchanged,
                    result: Err(configuration_error(&self.paths.desired_state, source)),
                };
            }
        };
        if !config.subscription().enabled() {
            return RefreshAttempt {
                schedule: RefreshSchedule::Disabled,
                result: Ok(RefreshPayload::Disabled),
            };
        }
        let schedule = RefreshSchedule::Enabled(config.subscription().update_interval());
        RefreshAttempt {
            schedule,
            result: self.refresh_inner(&config),
        }
    }

    fn reject(&mut self, digest: [u8; 32]) -> Result<(), SubscriptionRefreshError> {
        self.store
            .reject_active(digest)
            .map(|_| ())
            .map_err(SubscriptionRefreshError::rollback)
    }
}

fn require_supported_identity(config: &FluxConfig) -> Result<(), SubscriptionRefreshError> {
    let credentials = config.engine().credentials();
    if credentials.uid().get() != 0 || credentials.gid().get() != 0 {
        return Err(SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::UnsupportedIdentity,
            "subscription assets currently require the root-owned Proxy Engine configured as UID/GID 0",
        ));
    }
    Ok(())
}

fn validation_engine(
    config: &FluxConfig,
    paths: &SubscriptionRuntimePaths,
) -> Result<EngineSpec, SubscriptionRefreshError> {
    require_supported_identity(config)?;
    let restart = config.engine().restart();
    let restart = RestartPolicy::new(
        restart.max_attempts(),
        restart.window(),
        restart.initial_backoff(),
        restart.maximum_backoff(),
        restart.stable_reset(),
    )
    .map_err(|source| {
        SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::Configuration,
            format!("invalid Proxy Engine restart policy: {source}"),
        )
    })?;
    EngineSpec::new(
        SingBoxLaunchSpec {
            binary: config.engine().binary().to_owned(),
            config: config.engine().template().to_owned(),
            working_directory: paths.working_directory.clone(),
            log: paths.validation_log.clone(),
            privilege: SingBoxPrivilege::transparent_proxy(config.engine().credentials()),
            readiness: SingBoxReadiness::Listener {
                port: config.listener().port(),
            },
            startup_timeout: config.engine().startup_timeout(),
            stop_timeout: config.engine().stop_timeout(),
        },
        restart,
    )
    .map_err(|source| {
        SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::Configuration,
            format!("cannot inspect subscription validation artifacts: {source}"),
        )
    })
}

fn read_subscription_url(path: &Path) -> Result<Url, SubscriptionRefreshError> {
    let bytes = read_required_file(
        path,
        MAX_SUBSCRIPTION_URL_FILE_BYTES,
        "subscription URL file",
    )?;
    let text = str::from_utf8(&bytes).map_err(|_| {
        SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::Source,
            "subscription URL file is not valid UTF-8",
        )
    })?;
    let value = text.trim_matches(|character: char| character.is_ascii_whitespace());
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::Source,
            "subscription URL file must contain exactly one nonempty URL",
        ));
    }
    Url::parse(value).map_err(|_| {
        SubscriptionRefreshError::new(
            SubscriptionRefreshErrorKind::Source,
            "subscription URL file does not contain a valid URL",
        )
    })
}

fn subscription_source(config: &FluxConfig) -> Result<RedactedSourceId, SubscriptionRefreshError> {
    read_subscription_url(config.subscription().url_file()).map(|url| redacted_source_id(&url))
}

fn read_required_file(
    path: &Path,
    maximum: usize,
    role: &'static str,
) -> Result<Vec<u8>, SubscriptionRefreshError> {
    record_io::read(path, maximum)
        .map_err(|source| {
            SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::Source,
                format!("cannot read {role} {}: {source}", path.display()),
            )
        })?
        .ok_or_else(|| {
            SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::Source,
                format!("required {role} {} is missing", path.display()),
            )
        })
}

fn configuration_error(path: &Path, source: impl fmt::Display) -> SubscriptionRefreshError {
    SubscriptionRefreshError::new(
        SubscriptionRefreshErrorKind::Configuration,
        format!("cannot load Desired State {}: {source}", path.display()),
    )
}

fn preparation_error(source: PrepareSubscriptionError) -> SubscriptionRefreshError {
    SubscriptionRefreshError::new(
        SubscriptionRefreshErrorKind::Preparation,
        source.to_string(),
    )
}

fn store_error(source: SubscriptionSnapshotStoreError) -> SubscriptionRefreshError {
    SubscriptionRefreshError::new(SubscriptionRefreshErrorKind::Store, source.to_string())
}

#[derive(Clone, Copy)]
enum RefreshTrigger {
    Manual,
    Periodic,
    Observed,
}

enum RefreshWorkerRequest {
    Refresh {
        trigger: RefreshTrigger,
        completion:
            Option<mpsc::SyncSender<Result<SubscriptionRefreshReport, SubscriptionRefreshError>>>,
    },
    SettleBootstrap {
        digest: [u8; 32],
        accept: bool,
        completion: mpsc::SyncSender<Result<(), SubscriptionRefreshError>>,
    },
}

pub(crate) enum SubscriptionRefreshDecision {
    Accept(SubscriptionRefreshReport),
    Reject(SubscriptionRefreshError),
}

pub(crate) struct SubscriptionRefreshCompletion {
    schedule: RefreshSchedule,
    payload: Result<RefreshPayload, SubscriptionRefreshError>,
    decision: mpsc::SyncSender<SubscriptionRefreshDecision>,
}

impl SubscriptionRefreshCompletion {
    pub(crate) fn published(&self) -> Option<(&ValidatedSubscriptionEngineConfig, bool)> {
        match &self.payload {
            Ok(RefreshPayload::Published {
                config,
                cleanup_pending,
            }) => Some((config, *cleanup_pending)),
            _ => None,
        }
    }

    pub(crate) fn terminal(
        &self,
    ) -> Option<Result<SubscriptionRefreshReport, SubscriptionRefreshError>> {
        match &self.payload {
            Ok(RefreshPayload::Disabled) => Some(Ok(SubscriptionRefreshReport::disabled())),
            Ok(RefreshPayload::Unchanged {
                node_count,
                cleanup_pending,
            }) => Some(Ok(SubscriptionRefreshReport::unchanged(
                *node_count,
                *cleanup_pending,
            ))),
            Ok(RefreshPayload::Published { .. }) => None,
            Err(error) => Some(Err(error.clone())),
        }
    }

    pub(crate) fn respond(self, decision: SubscriptionRefreshDecision) {
        let _ = self.decision.send(decision);
    }

    #[cfg(test)]
    pub(crate) fn published_for_test(
        config: ValidatedSubscriptionEngineConfig,
        cleanup_pending: bool,
    ) -> (Self, mpsc::Receiver<SubscriptionRefreshDecision>) {
        let (decision, receiver) = mpsc::sync_channel(1);
        (
            Self {
                schedule: RefreshSchedule::Unchanged,
                payload: Ok(RefreshPayload::Published {
                    config,
                    cleanup_pending,
                }),
                decision,
            },
            receiver,
        )
    }
}

#[derive(Clone)]
pub(crate) struct SubscriptionRefreshClient {
    request: mpsc::SyncSender<RefreshWorkerRequest>,
    busy: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

impl SubscriptionRefreshClient {
    pub(crate) fn refresh(&self) -> Result<SubscriptionRefreshReport, SubscriptionRefreshError> {
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        match self.try_start(RefreshTrigger::Manual, Some(completion_tx))? {
            false => Ok(SubscriptionRefreshReport::busy()),
            true => completion_rx.recv().map_err(|_| worker_unavailable())?,
        }
    }

    fn request_periodic(&self) -> Result<bool, SubscriptionRefreshError> {
        self.try_start(RefreshTrigger::Periodic, None)
    }

    fn request_observed(&self) -> Result<bool, SubscriptionRefreshError> {
        self.try_start(RefreshTrigger::Observed, None)
    }

    fn try_start(
        &self,
        trigger: RefreshTrigger,
        completion: Option<
            mpsc::SyncSender<Result<SubscriptionRefreshReport, SubscriptionRefreshError>>,
        >,
    ) -> Result<bool, SubscriptionRefreshError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(worker_unavailable());
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(false);
        }
        let request = RefreshWorkerRequest::Refresh {
            trigger,
            completion,
        };
        match self.request.try_send(request) {
            Ok(()) => Ok(true),
            Err(_) => {
                self.busy.store(false, Ordering::Release);
                Err(worker_unavailable())
            }
        }
    }

    pub(crate) fn reject_bootstrap(
        &self,
        digest: [u8; 32],
    ) -> Result<(), SubscriptionRefreshError> {
        self.settle_bootstrap(digest, false)
    }

    pub(crate) fn accept_bootstrap(
        &self,
        digest: [u8; 32],
    ) -> Result<(), SubscriptionRefreshError> {
        self.settle_bootstrap(digest, true)
    }

    fn settle_bootstrap(
        &self,
        digest: [u8; 32],
        accept: bool,
    ) -> Result<(), SubscriptionRefreshError> {
        if self.stopping.load(Ordering::Acquire) {
            return Err(worker_unavailable());
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(SubscriptionRefreshError::new(
                SubscriptionRefreshErrorKind::WorkerUnavailable,
                "subscription refresh worker is busy during startup settlement",
            ));
        }
        let (completion, result) = mpsc::sync_channel(1);
        if self
            .request
            .try_send(RefreshWorkerRequest::SettleBootstrap {
                digest,
                accept,
                completion,
            })
            .is_err()
        {
            self.busy.store(false, Ordering::Release);
            return Err(worker_unavailable());
        }
        result
            .recv_timeout(COORDINATOR_ACK_TIMEOUT)
            .map_err(|_| worker_unavailable())?
    }

    #[cfg(test)]
    pub(crate) fn for_test<F>(mut refresh: F) -> Self
    where
        F: FnMut() -> Result<SubscriptionRefreshReport, SubscriptionRefreshError> + Send + 'static,
    {
        let (request, requests) =
            mpsc::sync_channel::<RefreshWorkerRequest>(REFRESH_CHANNEL_CAPACITY);
        let busy = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_busy = Arc::clone(&busy);
        let _worker = thread::spawn(move || {
            while let Ok(request) = requests.recv() {
                match request {
                    RefreshWorkerRequest::Refresh { completion, .. } => {
                        if let Some(completion) = completion {
                            let _ = completion.send(refresh());
                        }
                    }
                    RefreshWorkerRequest::SettleBootstrap { completion, .. } => {
                        let _ = completion.send(Ok(()));
                    }
                }
                worker_busy.store(false, Ordering::Release);
            }
        });
        Self {
            request,
            busy,
            stopping,
        }
    }
}

fn worker_unavailable() -> SubscriptionRefreshError {
    SubscriptionRefreshError::new(
        SubscriptionRefreshErrorKind::WorkerUnavailable,
        "subscription refresh worker is unavailable",
    )
}

pub(crate) struct SubscriptionRefreshRuntime {
    client: SubscriptionRefreshClient,
    completion: mpsc::Receiver<SubscriptionRefreshCompletion>,
    worker: Option<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    interval: Option<Duration>,
    next_periodic: Option<Instant>,
    observed_refresh_pending: bool,
}

pub(crate) struct SubscriptionRuntimeBootstrap {
    pub(crate) runtime: SubscriptionRefreshRuntime,
    pub(crate) client: SubscriptionRefreshClient,
    pub(crate) active: Option<ValidatedSubscriptionEngineConfig>,
    pub(crate) bootstrap_digest: Option<[u8; 32]>,
}

impl SubscriptionRefreshRuntime {
    pub(crate) fn start(
        paths: SubscriptionRuntimePaths,
    ) -> Result<SubscriptionRuntimeBootstrap, SubscriptionRefreshError> {
        let mut operation = ProductionRefreshOperation::new(paths.clone(), UreqFetchAdapter)?;
        let initial_config = FluxConfig::load(&paths.desired_state)
            .map_err(|source| configuration_error(&paths.desired_state, source))?;
        if initial_config.subscription().enabled() {
            require_supported_identity(&initial_config)?;
        }
        let (mut active, cleanup_pending) = operation.recover(&initial_config)?;
        if cleanup_pending {
            runtime_log(
                LogSeverity::Warn,
                "subscription",
                None,
                format_args!("snapshot cleanup remains pending after recovery"),
            );
        }
        let mut bootstrap_digest = None;
        if initial_config.subscription().enabled() && active.is_none() {
            let bootstrap = thread::Builder::new()
                .name("flux-subscription-bootstrap".to_owned())
                .spawn(move || {
                    let attempt = operation.refresh();
                    (operation, attempt)
                })
                .map_err(|source| {
                    SubscriptionRefreshError::new(
                        SubscriptionRefreshErrorKind::WorkerUnavailable,
                        format!("cannot start subscription bootstrap worker: {source}"),
                    )
                })?;
            let result = bootstrap.join().map_err(|_| {
                SubscriptionRefreshError::new(
                    SubscriptionRefreshErrorKind::WorkerUnavailable,
                    "subscription bootstrap worker panicked",
                )
            })?;
            operation = result.0;
            active = match result.1.result? {
                RefreshPayload::Published { config, .. } => {
                    bootstrap_digest = Some(config.snapshot_digest());
                    Some(config)
                }
                RefreshPayload::Unchanged { .. } => operation.recover(&initial_config)?.0,
                RefreshPayload::Disabled => None,
            };
        }

        let current_config = FluxConfig::load(&paths.desired_state)
            .map_err(|source| configuration_error(&paths.desired_state, source))?;
        let interval = current_config
            .subscription()
            .enabled()
            .then(|| current_config.subscription().update_interval())
            .filter(|interval| !interval.is_zero());
        let runtime = Self::spawn_worker(
            Box::new(operation),
            interval,
            bootstrap_digest,
            COORDINATOR_ACK_TIMEOUT,
        )?;
        let client = runtime.client.clone();
        Ok(SubscriptionRuntimeBootstrap {
            runtime,
            client,
            active,
            bootstrap_digest,
        })
    }

    #[cfg(test)]
    fn spawn(
        operation: Box<dyn RefreshOperation>,
        interval: Option<Duration>,
    ) -> Result<Self, SubscriptionRefreshError> {
        Self::spawn_worker(operation, interval, None, COORDINATOR_ACK_TIMEOUT)
    }

    #[cfg(test)]
    fn spawn_with_ack_timeout(
        operation: Box<dyn RefreshOperation>,
        interval: Option<Duration>,
        acknowledgement_timeout: Duration,
    ) -> Result<Self, SubscriptionRefreshError> {
        Self::spawn_worker(operation, interval, None, acknowledgement_timeout)
    }

    fn spawn_worker(
        operation: Box<dyn RefreshOperation>,
        interval: Option<Duration>,
        pending_bootstrap: Option<[u8; 32]>,
        acknowledgement_timeout: Duration,
    ) -> Result<Self, SubscriptionRefreshError> {
        let (request_tx, request_rx) =
            mpsc::sync_channel::<RefreshWorkerRequest>(REFRESH_CHANNEL_CAPACITY);
        let (completion_tx, completion_rx) = mpsc::sync_channel(REFRESH_CHANNEL_CAPACITY);
        let busy = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_busy = Arc::clone(&busy);
        let worker_stopping = Arc::clone(&stopping);
        let worker_state = RefreshWorkerState {
            operation,
            pending_bootstrap,
        };
        let worker = thread::Builder::new()
            .name("flux-subscription-refresh".to_owned())
            .spawn(move || {
                refresh_worker_loop(
                    worker_state,
                    request_rx,
                    completion_tx,
                    &worker_busy,
                    &worker_stopping,
                    acknowledgement_timeout,
                );
            })
            .map_err(|source| {
                SubscriptionRefreshError::new(
                    SubscriptionRefreshErrorKind::WorkerUnavailable,
                    format!("cannot start subscription refresh worker: {source}"),
                )
            })?;
        let now = Instant::now();
        Ok(Self {
            client: SubscriptionRefreshClient {
                request: request_tx,
                busy,
                stopping: Arc::clone(&stopping),
            },
            completion: completion_rx,
            worker: Some(worker),
            stopping,
            interval,
            next_periodic: interval.and_then(|interval| now.checked_add(interval)),
            observed_refresh_pending: false,
        })
    }

    pub(crate) fn poll(&mut self) -> Option<SubscriptionRefreshCompletion> {
        match self.completion.try_recv() {
            Ok(completion) => {
                self.observe_schedule(completion.schedule);
                Some(completion)
            }
            Err(mpsc::TryRecvError::Empty | mpsc::TryRecvError::Disconnected) => None,
        }
    }

    pub(crate) fn schedule_periodic(&mut self, now: Instant) {
        let Some(deadline) = self.next_periodic else {
            return;
        };
        if now < deadline {
            return;
        }
        match self.client.request_periodic() {
            Ok(true) => {
                self.next_periodic = self.interval.and_then(|interval| now.checked_add(interval));
            }
            Ok(false) => {}
            Err(error) => runtime_log(
                LogSeverity::Warn,
                "subscription",
                None,
                format_args!("cannot schedule refresh: {error}"),
            ),
        }
    }

    pub(crate) fn request_observed_refresh(&mut self) {
        self.observed_refresh_pending = true;
        self.schedule_observed_refresh();
    }

    pub(crate) fn schedule_observed_refresh(&mut self) {
        if !self.observed_refresh_pending {
            return;
        }
        match self.client.request_observed() {
            Ok(true) => self.observed_refresh_pending = false,
            Ok(false) => {}
            Err(error) => runtime_log(
                LogSeverity::Warn,
                "subscription",
                None,
                format_args!("cannot schedule observed refresh: {error}"),
            ),
        }
    }

    fn observe_schedule(&mut self, schedule: RefreshSchedule) {
        match schedule {
            RefreshSchedule::Unchanged => {}
            RefreshSchedule::Disabled | RefreshSchedule::Enabled(Duration::ZERO) => {
                self.interval = None;
                self.next_periodic = None;
            }
            RefreshSchedule::Enabled(interval) => {
                self.interval = Some(interval);
                self.next_periodic = Instant::now().checked_add(interval);
            }
        }
    }
}

impl Drop for SubscriptionRefreshRuntime {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        while let Ok(completion) = self.completion.try_recv() {
            completion.respond(SubscriptionRefreshDecision::Reject(
                SubscriptionRefreshError::activation(
                    "daemon shutdown interrupted subscription activation",
                ),
            ));
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct RefreshWorkerState {
    operation: Box<dyn RefreshOperation>,
    pending_bootstrap: Option<[u8; 32]>,
}

impl Drop for RefreshWorkerState {
    fn drop(&mut self) {
        if let Some(digest) = self.pending_bootstrap
            && let Err(error) = self.operation.reject(digest)
        {
            runtime_log(
                LogSeverity::Error,
                "subscription",
                None,
                format_args!("cannot restore unadmitted startup snapshot: {error}"),
            );
        }
    }
}

fn refresh_worker_loop(
    mut state: RefreshWorkerState,
    request_rx: mpsc::Receiver<RefreshWorkerRequest>,
    completion_tx: mpsc::SyncSender<SubscriptionRefreshCompletion>,
    busy: &AtomicBool,
    stopping: &AtomicBool,
    acknowledgement_timeout: Duration,
) {
    while !stopping.load(Ordering::Acquire) {
        let request = match request_rx.recv_timeout(WORKER_POLL_INTERVAL) {
            Ok(request) => request,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let (trigger, completion) = match request {
            RefreshWorkerRequest::Refresh {
                trigger,
                completion,
            } => (trigger, completion),
            RefreshWorkerRequest::SettleBootstrap {
                digest,
                accept,
                completion,
            } => {
                let result = if state.pending_bootstrap == Some(digest) {
                    if accept {
                        Ok(())
                    } else {
                        state.operation.reject(digest)
                    }
                } else {
                    Err(SubscriptionRefreshError::new(
                        SubscriptionRefreshErrorKind::Rollback,
                        "startup subscription candidate no longer matches the pending digest",
                    ))
                };
                if result.is_ok() {
                    state.pending_bootstrap = None;
                }
                busy.store(false, Ordering::Release);
                let _ = completion.send(result);
                continue;
            }
        };
        let attempt = state.operation.refresh();
        let published_digest = match &attempt.result {
            Ok(RefreshPayload::Published { config, .. }) => Some(config.snapshot_digest()),
            _ => None,
        };
        if stopping.load(Ordering::Acquire) {
            let final_result = reject_if_published(
                state.operation.as_mut(),
                published_digest,
                SubscriptionRefreshError::activation(
                    "daemon shutdown interrupted subscription refresh",
                ),
            );
            if let Some(completion) = completion {
                let _ = completion.send(final_result);
            }
            busy.store(false, Ordering::Release);
            break;
        }
        let (decision_tx, decision_rx) = mpsc::sync_channel(1);
        let sent = completion_tx.send(SubscriptionRefreshCompletion {
            schedule: attempt.schedule,
            payload: attempt.result,
            decision: decision_tx,
        });
        let decision = if sent.is_ok() {
            wait_for_decision(&decision_rx, stopping, acknowledgement_timeout)
        } else {
            None
        };
        let final_result = match decision {
            Some(SubscriptionRefreshDecision::Accept(report)) => Ok(report),
            Some(SubscriptionRefreshDecision::Reject(error)) => {
                reject_if_published(state.operation.as_mut(), published_digest, error)
            }
            None => reject_if_published(
                state.operation.as_mut(),
                published_digest,
                SubscriptionRefreshError::activation(
                    "serialized runtime did not acknowledge subscription refresh",
                ),
            ),
        };
        busy.store(false, Ordering::Release);
        if let Some(completion) = completion {
            let _ = completion.send(final_result.clone());
        } else if let Err(error) = &final_result {
            let source = match trigger {
                RefreshTrigger::Manual => "manual",
                RefreshTrigger::Periodic => "periodic",
                RefreshTrigger::Observed => "observed",
            };
            runtime_log(
                LogSeverity::Error,
                "subscription",
                None,
                format_args!("{source} refresh failed: {error}"),
            );
        }
        if sent.is_err() {
            break;
        }
    }
    busy.store(false, Ordering::Release);
}

fn wait_for_decision(
    receiver: &mpsc::Receiver<SubscriptionRefreshDecision>,
    stopping: &AtomicBool,
    timeout: Duration,
) -> Option<SubscriptionRefreshDecision> {
    let started = Instant::now();
    loop {
        if stopping.load(Ordering::Acquire) {
            return None;
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return None;
        }
        match receiver.recv_timeout(remaining.min(WORKER_POLL_INTERVAL)) {
            Ok(decision) => return Some(decision),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

fn reject_if_published(
    operation: &mut dyn RefreshOperation,
    published_digest: Option<[u8; 32]>,
    error: SubscriptionRefreshError,
) -> Result<SubscriptionRefreshReport, SubscriptionRefreshError> {
    if let Some(digest) = published_digest {
        operation.reject(digest)?;
    }
    Err(error)
}

#[cfg(test)]
mod tests;
