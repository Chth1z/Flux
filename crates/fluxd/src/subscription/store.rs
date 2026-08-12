use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use flux_platform::internal::{ProcessDiagnostics, SingBoxProcessError};

use crate::engine_supervisor::EngineCapabilityProbeError;
use crate::intent_store::record_io;
use crate::{EngineSpec, IntentStoreError, MAX_ENGINE_CONFIG_BYTES};

use super::assets::{
    MAX_REMOTE_RULE_SETS, MAX_RULE_SET_TAG_BYTES, PreparedRuleSetAsset, PreparedRuleSetBinding,
    PreparedSubscriptionRefresh, RedactedSourceId,
};

const SNAPSHOT_INDEX_SCHEMA_VERSION: u16 = 1;
const MAX_SNAPSHOT_INDEX_BYTES: usize = 128 * 1_024;
const MAX_PERSISTED_ASSET_BYTES: usize = 64 * 1_024 * 1_024;
const MAX_STORE_PATH_BYTES: usize = 4_096;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const INDEX_FILE_NAME: &str = "index.json";
const CONFIG_DIRECTORY_NAME: &str = "configs";
const ASSET_DIRECTORY_NAME: &str = "assets";
const CONFIG_SUFFIX: &str = ".json";
const ASSET_SUFFIX: &str = ".srs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SubscriptionAssetAccess {
    engine_gid: u32,
}

impl SubscriptionAssetAccess {
    pub(super) const fn reviewed_engine(engine_gid: u32) -> Option<Self> {
        if engine_gid == 0 || engine_gid == u32::MAX {
            None
        } else {
            Some(Self { engine_gid })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotValidationErrorKind {
    Artifact,
    ProcessSpawn,
    ProcessSpawnPermissionDenied,
    ProcessCheckPermissionDenied,
    ProcessCheckPathUnavailable,
    ProcessCheckRejected,
    ProcessCheckTimedOut,
    ProcessCleanup,
    ProcessOther,
    #[cfg(test)]
    Rejected,
}

pub(super) trait SubscriptionSnapshotValidator {
    fn validate(&self, config_path: &Path) -> Result<(), SnapshotValidationErrorKind>;
}

#[derive(Clone, Debug)]
pub(super) struct SingBoxSnapshotValidator {
    engine: EngineSpec,
}

impl SingBoxSnapshotValidator {
    pub(super) fn from_engine(engine: &EngineSpec) -> Self {
        Self {
            engine: engine.clone(),
        }
    }
}

impl SubscriptionSnapshotValidator for SingBoxSnapshotValidator {
    fn validate(&self, config_path: &Path) -> Result<(), SnapshotValidationErrorKind> {
        let mut process = self.engine.process().clone();
        process.config = config_path.to_owned();
        let candidate = EngineSpec::new(process, self.engine.restart_policy())
            .map_err(|_| SnapshotValidationErrorKind::Artifact)?;
        if candidate.binary_digest() != self.engine.binary_digest() {
            return Err(SnapshotValidationErrorKind::Artifact);
        }
        candidate
            .validate_configuration()
            .map_err(|error| classify_validation_error(&error))
    }
}

fn classify_validation_error(error: &EngineCapabilityProbeError) -> SnapshotValidationErrorKind {
    let EngineCapabilityProbeError::Process { source } = error else {
        return SnapshotValidationErrorKind::Artifact;
    };
    match source {
        SingBoxProcessError::Spawn { source, .. }
            if matches!(source.raw_os_error(), Some(libc::EACCES | libc::EPERM)) =>
        {
            SnapshotValidationErrorKind::ProcessSpawnPermissionDenied
        }
        SingBoxProcessError::Spawn { .. } => SnapshotValidationErrorKind::ProcessSpawn,
        SingBoxProcessError::CheckFailed { diagnostics, .. }
            if diagnostics_contain(
                diagnostics,
                &["permission denied", "operation not permitted"],
            ) =>
        {
            SnapshotValidationErrorKind::ProcessCheckPermissionDenied
        }
        SingBoxProcessError::CheckFailed { diagnostics, .. }
            if diagnostics_contain(
                diagnostics,
                &["no such file or directory", "not a directory"],
            ) =>
        {
            SnapshotValidationErrorKind::ProcessCheckPathUnavailable
        }
        SingBoxProcessError::CheckFailed { .. } => {
            SnapshotValidationErrorKind::ProcessCheckRejected
        }
        SingBoxProcessError::CheckTimedOut { .. } => {
            SnapshotValidationErrorKind::ProcessCheckTimedOut
        }
        SingBoxProcessError::ValidationGroupSignal { .. }
        | SingBoxProcessError::ValidationGroupCleanupTimedOut { .. }
        | SingBoxProcessError::ProbeOutputDrainTimedOut { .. } => {
            SnapshotValidationErrorKind::ProcessCleanup
        }
        _ => SnapshotValidationErrorKind::ProcessOther,
    }
}

fn diagnostics_contain(diagnostics: &ProcessDiagnostics, needles: &[&str]) -> bool {
    [
        &diagnostics.stdout_tail(),
        &diagnostics.stderr_tail(),
        &diagnostics.log_tail(),
    ]
    .into_iter()
    .any(|text| {
        let text = text.to_ascii_lowercase();
        needles.iter().any(|needle| text.contains(needle))
    })
}

#[derive(Clone, Eq, PartialEq)]
pub(super) struct ValidatedSubscriptionSnapshot {
    prepared: PreparedSubscriptionRefresh,
}

impl fmt::Debug for ValidatedSubscriptionSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ValidatedSubscriptionSnapshot")
            .field(&self.prepared)
            .finish()
    }
}

impl ValidatedSubscriptionSnapshot {
    pub(super) fn bytes(&self) -> &[u8] {
        self.prepared.bytes()
    }

    pub(super) const fn content_sha256(&self) -> &[u8; 32] {
        self.prepared.content_sha256()
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        self.prepared.digest()
    }

    pub(super) const fn subscription_source(&self) -> RedactedSourceId {
        self.prepared.subscription_source()
    }

    pub(super) const fn node_count(&self) -> u32 {
        self.prepared.node_count()
    }

    #[cfg(test)]
    pub(super) fn assets(&self) -> &[PreparedRuleSetAsset] {
        self.prepared.assets()
    }

    #[cfg(test)]
    pub(super) fn bindings(&self) -> &[PreparedRuleSetBinding] {
        self.prepared.bindings()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotRecoveryDisposition {
    Unchanged,
    ClearedCorruptIndex,
    ClearedCorruptSnapshots,
    DroppedCorruptPredecessor,
    PromotedPredecessor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPublicationDisposition {
    Recovered,
    Published,
    ValidatedNoChange,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SubscriptionSnapshotStoreReport {
    active: Option<ValidatedSubscriptionSnapshot>,
    predecessor: Option<[u8; 32]>,
    recovery: SnapshotRecoveryDisposition,
    publication: SnapshotPublicationDisposition,
    cleanup_pending: bool,
}

impl SubscriptionSnapshotStoreReport {
    #[cfg(test)]
    pub(super) const fn active(&self) -> Option<&ValidatedSubscriptionSnapshot> {
        self.active.as_ref()
    }

    #[cfg(test)]
    pub(super) const fn predecessor(&self) -> Option<&[u8; 32]> {
        self.predecessor.as_ref()
    }

    #[cfg(test)]
    pub(super) const fn recovery(&self) -> SnapshotRecoveryDisposition {
        self.recovery
    }

    pub(super) const fn publication(&self) -> SnapshotPublicationDisposition {
        self.publication
    }

    pub(super) const fn cleanup_pending(&self) -> bool {
        self.cleanup_pending
    }

    pub(super) fn into_active(self) -> Option<ValidatedSubscriptionSnapshot> {
        self.active
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SubscriptionSnapshotStoreErrorKind {
    InvalidRoot,
    InvalidCandidate,
    InvalidIndex,
    UnsupportedSchema,
    Storage,
    Validation,
    CandidateChanged,
    RejectionConflict,
}

#[derive(Debug)]
pub(super) enum SubscriptionSnapshotStoreError {
    InvalidRoot(&'static str),
    InvalidCandidate(&'static str),
    InvalidIndex,
    UnsupportedSchema(u16),
    Storage {
        source: IntentStoreError,
        cleanup_pending: bool,
    },
    Validation {
        kind: SnapshotValidationErrorKind,
        cleanup_pending: bool,
    },
    CandidateChanged {
        cleanup_pending: bool,
    },
    RejectionConflict,
}

impl SubscriptionSnapshotStoreError {
    #[cfg(test)]
    pub(super) const fn kind(&self) -> SubscriptionSnapshotStoreErrorKind {
        match self {
            Self::InvalidRoot(_) => SubscriptionSnapshotStoreErrorKind::InvalidRoot,
            Self::InvalidCandidate(_) => SubscriptionSnapshotStoreErrorKind::InvalidCandidate,
            Self::InvalidIndex => SubscriptionSnapshotStoreErrorKind::InvalidIndex,
            Self::UnsupportedSchema(_) => SubscriptionSnapshotStoreErrorKind::UnsupportedSchema,
            Self::Storage { .. } => SubscriptionSnapshotStoreErrorKind::Storage,
            Self::Validation { .. } => SubscriptionSnapshotStoreErrorKind::Validation,
            Self::CandidateChanged { .. } => SubscriptionSnapshotStoreErrorKind::CandidateChanged,
            Self::RejectionConflict => SubscriptionSnapshotStoreErrorKind::RejectionConflict,
        }
    }

    #[cfg(test)]
    pub(super) const fn cleanup_pending(&self) -> bool {
        match self {
            Self::Storage {
                cleanup_pending, ..
            }
            | Self::Validation {
                cleanup_pending, ..
            }
            | Self::CandidateChanged { cleanup_pending } => *cleanup_pending,
            Self::InvalidRoot(_)
            | Self::InvalidCandidate(_)
            | Self::InvalidIndex
            | Self::UnsupportedSchema(_)
            | Self::RejectionConflict => false,
        }
    }

    fn storage(source: IntentStoreError) -> Self {
        Self::Storage {
            source,
            cleanup_pending: false,
        }
    }

    fn with_cleanup_pending(self, cleanup_pending: bool) -> Self {
        match self {
            Self::Storage {
                source,
                cleanup_pending: existing,
            } => Self::Storage {
                source,
                cleanup_pending: existing || cleanup_pending,
            },
            Self::Validation {
                kind,
                cleanup_pending: existing,
            } => Self::Validation {
                kind,
                cleanup_pending: existing || cleanup_pending,
            },
            Self::CandidateChanged {
                cleanup_pending: existing,
            } => Self::CandidateChanged {
                cleanup_pending: existing || cleanup_pending,
            },
            other => other,
        }
    }
}

impl fmt::Display for SubscriptionSnapshotStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot(detail) => {
                write!(formatter, "invalid subscription store root: {detail}")
            }
            Self::InvalidCandidate(detail) => {
                write!(
                    formatter,
                    "invalid prepared subscription snapshot: {detail}"
                )
            }
            Self::InvalidIndex => formatter.write_str("subscription snapshot index is invalid"),
            Self::UnsupportedSchema(version) => write!(
                formatter,
                "subscription snapshot index schema {version} is unsupported"
            ),
            Self::Storage { source, .. } => {
                write!(formatter, "subscription snapshot storage failed: {source}")
            }
            Self::Validation { kind, .. } => write!(
                formatter,
                "Sing-Box rejected the candidate subscription snapshot ({kind:?})"
            ),
            Self::CandidateChanged { .. } => formatter
                .write_str("candidate subscription snapshot changed during Sing-Box validation"),
            Self::RejectionConflict => formatter.write_str(
                "subscription snapshot rejection no longer matches the active candidate",
            ),
        }
    }
}

impl Error for SubscriptionSnapshotStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage { source, .. } => Some(source),
            Self::InvalidRoot(_)
            | Self::InvalidCandidate(_)
            | Self::InvalidIndex
            | Self::UnsupportedSchema(_)
            | Self::Validation { .. }
            | Self::CandidateChanged { .. }
            | Self::RejectionConflict => None,
        }
    }
}

pub(super) struct SubscriptionSnapshotStore<V> {
    root: PathBuf,
    validator: V,
    asset_access: Option<SubscriptionAssetAccess>,
}

impl<V> fmt::Debug for SubscriptionSnapshotStore<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SubscriptionSnapshotStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl<V: SubscriptionSnapshotValidator> SubscriptionSnapshotStore<V> {
    #[cfg(test)]
    pub(super) fn new(
        root: impl AsRef<Path>,
        validator: V,
    ) -> Result<Self, SubscriptionSnapshotStoreError> {
        Self::new_with_asset_access(root, validator, None)
    }

    pub(super) fn new_with_asset_access(
        root: impl AsRef<Path>,
        validator: V,
        asset_access: Option<SubscriptionAssetAccess>,
    ) -> Result<Self, SubscriptionSnapshotStoreError> {
        let root = root.as_ref();
        validate_store_root(root)?;
        let store = Self {
            root: root.to_owned(),
            validator,
            asset_access,
        };
        if let Some(access) = asset_access {
            store.bind_asset_directory_access(access)?;
        }
        Ok(store)
    }

    pub(super) fn asset_root(&self) -> PathBuf {
        self.root.join(ASSET_DIRECTORY_NAME)
    }

    pub(super) fn recover(
        &mut self,
    ) -> Result<SubscriptionSnapshotStoreReport, SubscriptionSnapshotStoreError> {
        self.require_asset_access()?;
        let recovered = self.recover_index()?;
        Ok(self.report(recovered, SnapshotPublicationDisposition::Recovered))
    }

    pub(super) fn publish(
        &mut self,
        prepared: PreparedSubscriptionRefresh,
    ) -> Result<SubscriptionSnapshotStoreReport, SubscriptionSnapshotStoreError> {
        self.require_asset_access()?;
        self.validate_candidate(&prepared)?;
        let recovered = self.recover_index()?;
        let candidate_record = SnapshotRecord::from_prepared(&prepared);

        if let Err(error) = self.persist_candidate(&prepared) {
            let retry_pending = self.prune(&recovered.index);
            return Err(error.with_cleanup_pending(recovered.cleanup_pending || retry_pending));
        }
        let before_validation = match self.load_snapshot(&candidate_record) {
            Ok(snapshot) => snapshot,
            Err(SnapshotLoadError::Corrupt) => {
                let retry_pending = self.prune(&recovered.index);
                let cleanup_pending = recovered.cleanup_pending || retry_pending;
                return Err(SubscriptionSnapshotStoreError::CandidateChanged { cleanup_pending });
            }
            Err(SnapshotLoadError::Storage(source)) => {
                let retry_pending = self.prune(&recovered.index);
                return Err(SubscriptionSnapshotStoreError::storage(source)
                    .with_cleanup_pending(recovered.cleanup_pending || retry_pending));
            }
        };
        if before_validation.prepared != prepared {
            let retry_pending = self.prune(&recovered.index);
            let cleanup_pending = recovered.cleanup_pending || retry_pending;
            return Err(SubscriptionSnapshotStoreError::CandidateChanged { cleanup_pending });
        }
        let config_path = self.config_path(candidate_record.content_sha256);
        if let Err(kind) = self.validator.validate(&config_path) {
            let retry_pending = self.prune(&recovered.index);
            let cleanup_pending = recovered.cleanup_pending || retry_pending;
            return Err(SubscriptionSnapshotStoreError::Validation {
                kind,
                cleanup_pending,
            });
        }
        let after_validation = match self.load_snapshot(&candidate_record) {
            Ok(snapshot) if snapshot == before_validation => snapshot,
            Ok(_) | Err(SnapshotLoadError::Corrupt) => {
                let retry_pending = self.prune(&recovered.index);
                let cleanup_pending = recovered.cleanup_pending || retry_pending;
                return Err(SubscriptionSnapshotStoreError::CandidateChanged { cleanup_pending });
            }
            Err(SnapshotLoadError::Storage(source)) => {
                let retry_pending = self.prune(&recovered.index);
                return Err(SubscriptionSnapshotStoreError::storage(source)
                    .with_cleanup_pending(recovered.cleanup_pending || retry_pending));
            }
        };

        let unchanged = recovered
            .index
            .active
            .as_ref()
            .is_some_and(|active| active.digest == candidate_record.digest);
        if unchanged {
            let publication_cleanup_pending = self.prune(&recovered.index);
            let cleanup_pending = recovered.cleanup_pending || publication_cleanup_pending;
            return Ok(SubscriptionSnapshotStoreReport {
                active: Some(after_validation),
                predecessor: recovered
                    .index
                    .predecessor
                    .as_ref()
                    .map(|snapshot| snapshot.digest),
                recovery: recovered.recovery,
                publication: SnapshotPublicationDisposition::ValidatedNoChange,
                cleanup_pending,
            });
        }

        let next_index = SnapshotIndex {
            active: Some(candidate_record),
            predecessor: recovered.index.active.clone(),
        };
        if let Err(error) = self.persist_index(&next_index) {
            let retry_pending = self.prune(&recovered.index);
            return Err(error.with_cleanup_pending(recovered.cleanup_pending || retry_pending));
        }
        let publication_cleanup_pending = self.prune(&next_index);
        let cleanup_pending = recovered.cleanup_pending || publication_cleanup_pending;
        Ok(SubscriptionSnapshotStoreReport {
            active: Some(after_validation),
            predecessor: next_index
                .predecessor
                .as_ref()
                .map(|snapshot| snapshot.digest),
            recovery: recovered.recovery,
            publication: SnapshotPublicationDisposition::Published,
            cleanup_pending,
        })
    }

    /// Conditionally remove one rejected active candidate and restore its verified predecessor.
    pub(super) fn reject_active(
        &mut self,
        rejected_digest: [u8; 32],
    ) -> Result<SubscriptionSnapshotStoreReport, SubscriptionSnapshotStoreError> {
        self.require_asset_access()?;
        let recovered = self.recover_index()?;
        let Some(active_record) = recovered.index.active.as_ref() else {
            return Err(SubscriptionSnapshotStoreError::RejectionConflict);
        };
        if active_record.digest != rejected_digest {
            return Err(SubscriptionSnapshotStoreError::RejectionConflict);
        }

        let (next_index, active) = match recovered.index.predecessor.as_ref() {
            Some(predecessor) => {
                let active = self
                    .load_snapshot(predecessor)
                    .map_err(|error| match error {
                        SnapshotLoadError::Storage(source) => {
                            SubscriptionSnapshotStoreError::storage(source)
                        }
                        SnapshotLoadError::Corrupt => SubscriptionSnapshotStoreError::InvalidIndex,
                    })?;
                (
                    SnapshotIndex {
                        active: Some(predecessor.clone()),
                        predecessor: None,
                    },
                    Some(active),
                )
            }
            None => (SnapshotIndex::default(), None),
        };
        self.persist_index(&next_index)?;
        let cleanup_pending = recovered.cleanup_pending || self.prune(&next_index);
        Ok(SubscriptionSnapshotStoreReport {
            active,
            predecessor: None,
            recovery: recovered.recovery,
            publication: SnapshotPublicationDisposition::Rejected,
            cleanup_pending,
        })
    }

    fn report(
        &self,
        recovered: RecoveredIndex,
        publication: SnapshotPublicationDisposition,
    ) -> SubscriptionSnapshotStoreReport {
        SubscriptionSnapshotStoreReport {
            active: recovered.active,
            predecessor: recovered
                .index
                .predecessor
                .as_ref()
                .map(|snapshot| snapshot.digest),
            recovery: recovered.recovery,
            publication,
            cleanup_pending: recovered.cleanup_pending,
        }
    }

    fn recover_index(&self) -> Result<RecoveredIndex, SubscriptionSnapshotStoreError> {
        let (mut index, mut recovery) = match self.read_index()? {
            ReadIndex::Missing => (
                SnapshotIndex::default(),
                SnapshotRecoveryDisposition::Unchanged,
            ),
            ReadIndex::Valid(index) => (*index, SnapshotRecoveryDisposition::Unchanged),
            ReadIndex::Corrupt { unlink_first } => {
                if unlink_first {
                    record_io::remove(&self.index_path())
                        .map_err(SubscriptionSnapshotStoreError::storage)?;
                }
                let index = SnapshotIndex::default();
                self.persist_index(&index)?;
                (index, SnapshotRecoveryDisposition::ClearedCorruptIndex)
            }
        };

        let active = match index.active.as_ref() {
            Some(record) => match self.load_snapshot(record) {
                Ok(snapshot) => Some(snapshot),
                Err(SnapshotLoadError::Corrupt) => match index.predecessor.as_ref() {
                    Some(predecessor) => match self.load_snapshot(predecessor) {
                        Ok(snapshot) => {
                            index.active = index.predecessor.take();
                            self.persist_index(&index)?;
                            recovery = SnapshotRecoveryDisposition::PromotedPredecessor;
                            Some(snapshot)
                        }
                        Err(SnapshotLoadError::Corrupt) => {
                            index = SnapshotIndex::default();
                            self.persist_index(&index)?;
                            recovery = SnapshotRecoveryDisposition::ClearedCorruptSnapshots;
                            None
                        }
                        Err(SnapshotLoadError::Storage(source)) => {
                            return Err(SubscriptionSnapshotStoreError::storage(source));
                        }
                    },
                    None => {
                        index = SnapshotIndex::default();
                        self.persist_index(&index)?;
                        recovery = SnapshotRecoveryDisposition::ClearedCorruptSnapshots;
                        None
                    }
                },
                Err(SnapshotLoadError::Storage(source)) => {
                    return Err(SubscriptionSnapshotStoreError::storage(source));
                }
            },
            None => None,
        };

        if active.is_some()
            && let Some(predecessor) = index.predecessor.as_ref()
        {
            match self.load_snapshot(predecessor) {
                Ok(_) => {}
                Err(SnapshotLoadError::Corrupt) => {
                    index.predecessor = None;
                    self.persist_index(&index)?;
                    recovery = SnapshotRecoveryDisposition::DroppedCorruptPredecessor;
                }
                Err(SnapshotLoadError::Storage(source)) => {
                    return Err(SubscriptionSnapshotStoreError::storage(source));
                }
            }
        }

        let cleanup_pending = self.prune(&index);
        Ok(RecoveredIndex {
            index,
            active,
            recovery,
            cleanup_pending,
        })
    }

    fn validate_candidate(
        &self,
        prepared: &PreparedSubscriptionRefresh,
    ) -> Result<(), SubscriptionSnapshotStoreError> {
        if !prepared.verify() {
            return Err(SubscriptionSnapshotStoreError::InvalidCandidate(
                "content identity or rule-set bindings do not verify",
            ));
        }
        if u64::try_from(prepared.bytes().len())
            .map_or(true, |length| length > MAX_ENGINE_CONFIG_BYTES)
        {
            return Err(SubscriptionSnapshotStoreError::InvalidCandidate(
                "configuration exceeds the engine byte limit",
            ));
        }
        if prepared.assets().len() > MAX_REMOTE_RULE_SETS
            || prepared.bindings().len() > MAX_REMOTE_RULE_SETS
        {
            return Err(SubscriptionSnapshotStoreError::InvalidCandidate(
                "rule-set count exceeds the persisted limit",
            ));
        }
        let mut total_asset_bytes = 0usize;
        for asset in prepared.assets() {
            total_asset_bytes = total_asset_bytes.checked_add(asset.bytes().len()).ok_or(
                SubscriptionSnapshotStoreError::InvalidCandidate(
                    "aggregate rule-set bytes overflow",
                ),
            )?;
            if total_asset_bytes > MAX_PERSISTED_ASSET_BYTES {
                return Err(SubscriptionSnapshotStoreError::InvalidCandidate(
                    "aggregate rule-set bytes exceed the persisted limit",
                ));
            }
            if asset.path() != self.asset_path(*asset.content_sha256()) {
                return Err(SubscriptionSnapshotStoreError::InvalidCandidate(
                    "rule-set path is outside the content-addressed store",
                ));
            }
        }
        Ok(())
    }

    fn persist_candidate(
        &self,
        prepared: &PreparedSubscriptionRefresh,
    ) -> Result<(), SubscriptionSnapshotStoreError> {
        for asset in prepared.assets() {
            record_io::write(asset.path(), asset.bytes())
                .map_err(SubscriptionSnapshotStoreError::storage)?;
            if let Some(access) = self.asset_access {
                record_io::bind_engine_read_only_file(asset.path(), access.engine_gid)
                    .map_err(SubscriptionSnapshotStoreError::storage)?;
            }
        }
        record_io::write(
            &self.config_path(*prepared.content_sha256()),
            prepared.bytes(),
        )
        .map_err(SubscriptionSnapshotStoreError::storage)
    }

    fn load_snapshot(
        &self,
        record: &SnapshotRecord,
    ) -> Result<ValidatedSubscriptionSnapshot, SnapshotLoadError> {
        let config = read_snapshot_object(
            &self.config_path(record.content_sha256),
            usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap_or(usize::MAX),
        )?;
        if config.is_empty() {
            return Err(SnapshotLoadError::Corrupt);
        }

        let mut assets = Vec::with_capacity(record.assets.len());
        let mut remaining = MAX_PERSISTED_ASSET_BYTES;
        for content_sha256 in &record.assets {
            let path = self.asset_path(*content_sha256);
            if let Some(access) = self.asset_access {
                record_io::verify_engine_read_only_file(&path, access.engine_gid)
                    .map_err(SnapshotLoadError::Storage)?;
            }
            let bytes = read_snapshot_object(&path, remaining)?;
            if bytes.is_empty() {
                return Err(SnapshotLoadError::Corrupt);
            }
            remaining = remaining
                .checked_sub(bytes.len())
                .ok_or(SnapshotLoadError::Corrupt)?;
            let asset = PreparedRuleSetAsset::restore(path, bytes, *content_sha256)
                .ok_or(SnapshotLoadError::Corrupt)?;
            assets.push(asset);
        }

        let bindings = record
            .bindings
            .iter()
            .map(|binding| {
                PreparedRuleSetBinding::restore(
                    binding.tag.clone(),
                    RedactedSourceId::from_bytes(binding.source),
                    binding.content_sha256,
                )
                .ok_or(SnapshotLoadError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let prepared = PreparedSubscriptionRefresh::restore(
            config,
            record.content_sha256,
            record.digest,
            RedactedSourceId::from_bytes(record.subscription_source),
            record.subscription_content_sha256,
            record.compiled_digest,
            record.node_count,
            assets,
            bindings,
        )
        .ok_or(SnapshotLoadError::Corrupt)?;
        Ok(ValidatedSubscriptionSnapshot { prepared })
    }

    fn read_index(&self) -> Result<ReadIndex, SubscriptionSnapshotStoreError> {
        let index_path = self.index_path();
        let encoded = match record_io::read(&index_path, MAX_SNAPSHOT_INDEX_BYTES) {
            Ok(Some(encoded)) => encoded,
            Ok(None) => return Ok(ReadIndex::Missing),
            Err(IntentStoreError::Symlink(path)) if path == index_path => {
                return Ok(ReadIndex::Corrupt { unlink_first: true });
            }
            Err(IntentStoreError::RecordTooLarge { .. })
            | Err(IntentStoreError::NotRegularFile(_)) => {
                return Ok(ReadIndex::Corrupt {
                    unlink_first: false,
                });
            }
            Err(source) => return Err(SubscriptionSnapshotStoreError::storage(source)),
        };
        let stored = match serde_json::from_slice::<StoredSnapshotIndex>(&encoded) {
            Ok(stored) => stored,
            Err(_) => {
                return Ok(ReadIndex::Corrupt {
                    unlink_first: false,
                });
            }
        };
        if stored.schema_version != SNAPSHOT_INDEX_SCHEMA_VERSION {
            return Err(SubscriptionSnapshotStoreError::UnsupportedSchema(
                stored.schema_version,
            ));
        }
        let index = match SnapshotIndex::try_from(stored) {
            Ok(index) => index,
            Err(()) => {
                return Ok(ReadIndex::Corrupt {
                    unlink_first: false,
                });
            }
        };
        Ok(ReadIndex::Valid(Box::new(index)))
    }

    fn persist_index(&self, index: &SnapshotIndex) -> Result<(), SubscriptionSnapshotStoreError> {
        let stored = StoredSnapshotIndex::from(index);
        let mut encoded = serde_json::to_vec(&stored)
            .map_err(|_| SubscriptionSnapshotStoreError::InvalidIndex)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_SNAPSHOT_INDEX_BYTES {
            return Err(SubscriptionSnapshotStoreError::InvalidIndex);
        }
        record_io::write(&self.index_path(), &encoded)
            .map_err(SubscriptionSnapshotStoreError::storage)
    }

    fn prune(&self, index: &SnapshotIndex) -> bool {
        let mut config_names = BTreeSet::new();
        let mut asset_names = BTreeSet::new();
        for snapshot in index.active.iter().chain(index.predecessor.iter()) {
            config_names.insert(object_name(snapshot.content_sha256, CONFIG_SUFFIX));
            for digest in &snapshot.assets {
                asset_names.insert(object_name(*digest, ASSET_SUFFIX));
            }
        }

        let configs_pending =
            prune_object_directory(&self.config_root(), CONFIG_SUFFIX, &config_names);
        let assets_pending = prune_object_directory(&self.asset_root(), ASSET_SUFFIX, &asset_names);
        let index_temps_pending = prune_index_temps(&self.root);
        configs_pending || assets_pending || index_temps_pending
    }

    fn index_path(&self) -> PathBuf {
        self.root.join(INDEX_FILE_NAME)
    }

    fn config_root(&self) -> PathBuf {
        self.root.join(CONFIG_DIRECTORY_NAME)
    }

    fn config_path(&self, digest: [u8; 32]) -> PathBuf {
        self.config_root().join(object_name(digest, CONFIG_SUFFIX))
    }

    fn asset_path(&self, digest: [u8; 32]) -> PathBuf {
        self.asset_root().join(object_name(digest, ASSET_SUFFIX))
    }

    fn bind_asset_directory_access(
        &self,
        access: SubscriptionAssetAccess,
    ) -> Result<(), SubscriptionSnapshotStoreError> {
        let asset_root = self.asset_root();
        for directory in [self.root.as_path(), asset_root.as_path()] {
            record_io::bind_engine_traversal_directory(directory, access.engine_gid)
                .map_err(SubscriptionSnapshotStoreError::storage)?;
        }
        Ok(())
    }

    fn verify_asset_directory_access(
        &self,
        access: SubscriptionAssetAccess,
    ) -> Result<(), SubscriptionSnapshotStoreError> {
        let asset_root = self.asset_root();
        for directory in [self.root.as_path(), asset_root.as_path()] {
            record_io::verify_engine_traversal_directory(directory, access.engine_gid)
                .map_err(SubscriptionSnapshotStoreError::storage)?;
        }
        Ok(())
    }

    fn require_asset_access(&self) -> Result<(), SubscriptionSnapshotStoreError> {
        if let Some(access) = self.asset_access {
            self.verify_asset_directory_access(access)?;
        }
        Ok(())
    }
}

struct RecoveredIndex {
    index: SnapshotIndex,
    active: Option<ValidatedSubscriptionSnapshot>,
    recovery: SnapshotRecoveryDisposition,
    cleanup_pending: bool,
}

enum ReadIndex {
    Missing,
    Valid(Box<SnapshotIndex>),
    Corrupt { unlink_first: bool },
}

enum SnapshotLoadError {
    Corrupt,
    Storage(IntentStoreError),
}

fn read_snapshot_object(path: &Path, maximum: usize) -> Result<Vec<u8>, SnapshotLoadError> {
    match record_io::read(path, maximum) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(SnapshotLoadError::Corrupt),
        Err(IntentStoreError::RecordTooLarge { .. }) | Err(IntentStoreError::NotRegularFile(_)) => {
            Err(SnapshotLoadError::Corrupt)
        }
        Err(IntentStoreError::Symlink(link)) if link == path => Err(SnapshotLoadError::Corrupt),
        Err(source) => Err(SnapshotLoadError::Storage(source)),
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct SnapshotIndex {
    active: Option<SnapshotRecord>,
    predecessor: Option<SnapshotRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SnapshotRecord {
    digest: [u8; 32],
    content_sha256: [u8; 32],
    subscription_source: [u8; 32],
    subscription_content_sha256: [u8; 32],
    compiled_digest: [u8; 32],
    node_count: u32,
    assets: Vec<[u8; 32]>,
    bindings: Vec<RuleSetBindingRecord>,
}

impl SnapshotRecord {
    fn from_prepared(prepared: &PreparedSubscriptionRefresh) -> Self {
        Self {
            digest: *prepared.digest(),
            content_sha256: *prepared.content_sha256(),
            subscription_source: prepared.subscription_source().as_bytes(),
            subscription_content_sha256: *prepared.subscription_content_sha256(),
            compiled_digest: *prepared.compiled_digest(),
            node_count: prepared.node_count(),
            assets: prepared
                .assets()
                .iter()
                .map(|asset| *asset.content_sha256())
                .collect(),
            bindings: prepared
                .bindings()
                .iter()
                .map(|binding| RuleSetBindingRecord {
                    tag: binding.tag().to_owned(),
                    source: binding.source().as_bytes(),
                    content_sha256: *binding.content_sha256(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuleSetBindingRecord {
    tag: String,
    source: [u8; 32],
    content_sha256: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshotIndex {
    schema_version: u16,
    active: Option<StoredSnapshotRecord>,
    predecessor: Option<StoredSnapshotRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSnapshotRecord {
    digest: String,
    content_sha256: String,
    subscription_source: String,
    subscription_content_sha256: String,
    compiled_digest: String,
    node_count: u32,
    assets: Vec<String>,
    bindings: Vec<StoredRuleSetBindingRecord>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredRuleSetBindingRecord {
    tag: String,
    source: String,
    content_sha256: String,
}

impl From<&SnapshotIndex> for StoredSnapshotIndex {
    fn from(index: &SnapshotIndex) -> Self {
        Self {
            schema_version: SNAPSHOT_INDEX_SCHEMA_VERSION,
            active: index.active.as_ref().map(StoredSnapshotRecord::from),
            predecessor: index.predecessor.as_ref().map(StoredSnapshotRecord::from),
        }
    }
}

impl From<&SnapshotRecord> for StoredSnapshotRecord {
    fn from(record: &SnapshotRecord) -> Self {
        Self {
            digest: hex_digest(record.digest),
            content_sha256: hex_digest(record.content_sha256),
            subscription_source: hex_digest(record.subscription_source),
            subscription_content_sha256: hex_digest(record.subscription_content_sha256),
            compiled_digest: hex_digest(record.compiled_digest),
            node_count: record.node_count,
            assets: record.assets.iter().copied().map(hex_digest).collect(),
            bindings: record
                .bindings
                .iter()
                .map(|binding| StoredRuleSetBindingRecord {
                    tag: binding.tag.clone(),
                    source: hex_digest(binding.source),
                    content_sha256: hex_digest(binding.content_sha256),
                })
                .collect(),
        }
    }
}

impl TryFrom<StoredSnapshotIndex> for SnapshotIndex {
    type Error = ();

    fn try_from(stored: StoredSnapshotIndex) -> Result<Self, Self::Error> {
        if stored.active.is_none() && stored.predecessor.is_some() {
            return Err(());
        }
        let active = stored.active.map(SnapshotRecord::try_from).transpose()?;
        let predecessor = stored
            .predecessor
            .map(SnapshotRecord::try_from)
            .transpose()?;
        if active
            .as_ref()
            .zip(predecessor.as_ref())
            .is_some_and(|(active, predecessor)| active.digest == predecessor.digest)
        {
            return Err(());
        }
        Ok(Self {
            active,
            predecessor,
        })
    }
}

impl TryFrom<StoredSnapshotRecord> for SnapshotRecord {
    type Error = ();

    fn try_from(stored: StoredSnapshotRecord) -> Result<Self, Self::Error> {
        if stored.node_count == 0
            || stored.assets.len() > MAX_REMOTE_RULE_SETS
            || stored.bindings.len() > MAX_REMOTE_RULE_SETS
        {
            return Err(());
        }
        let assets = stored
            .assets
            .into_iter()
            .map(|digest| decode_digest(&digest))
            .collect::<Result<Vec<_>, _>>()?;
        if assets.iter().copied().collect::<BTreeSet<_>>().len() != assets.len() {
            return Err(());
        }
        let bindings = stored
            .bindings
            .into_iter()
            .map(|binding| {
                if binding.tag.is_empty() || binding.tag.len() > MAX_RULE_SET_TAG_BYTES {
                    return Err(());
                }
                Ok(RuleSetBindingRecord {
                    tag: binding.tag,
                    source: decode_digest(&binding.source)?,
                    content_sha256: decode_digest(&binding.content_sha256)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if bindings
            .iter()
            .map(|binding| binding.tag.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != bindings.len()
            || bindings
                .iter()
                .any(|binding| !assets.contains(&binding.content_sha256))
        {
            return Err(());
        }
        Ok(Self {
            digest: decode_digest(&stored.digest)?,
            content_sha256: decode_digest(&stored.content_sha256)?,
            subscription_source: decode_digest(&stored.subscription_source)?,
            subscription_content_sha256: decode_digest(&stored.subscription_content_sha256)?,
            compiled_digest: decode_digest(&stored.compiled_digest)?,
            node_count: stored.node_count,
            assets,
            bindings,
        })
    }
}

fn validate_store_root(root: &Path) -> Result<(), SubscriptionSnapshotStoreError> {
    if !root.is_absolute() {
        return Err(SubscriptionSnapshotStoreError::InvalidRoot(
            "path must be absolute",
        ));
    }
    if root
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SubscriptionSnapshotStoreError::InvalidRoot(
            "path must be lexically normalized",
        ));
    }
    let root = root
        .to_str()
        .ok_or(SubscriptionSnapshotStoreError::InvalidRoot(
            "path must be UTF-8",
        ))?;
    if root
        .len()
        .saturating_add(1 + CONFIG_DIRECTORY_NAME.len() + 1 + 64 + CONFIG_SUFFIX.len())
        > MAX_STORE_PATH_BYTES
    {
        return Err(SubscriptionSnapshotStoreError::InvalidRoot(
            "path is too long",
        ));
    }
    Ok(())
}

fn prune_object_directory(directory: &Path, suffix: &str, referenced: &BTreeSet<String>) -> bool {
    let names = match record_io::list(directory, MAX_DIRECTORY_ENTRIES) {
        Ok(Some(names)) => names,
        Ok(None) => return false,
        Err(_) => return true,
    };
    let mut cleanup_pending = false;
    for name in names {
        let Some(text) = name.to_str() else {
            continue;
        };
        let remove = (is_object_name(text, suffix) && !referenced.contains(text))
            || is_managed_temp_name(text, suffix);
        if remove && record_io::remove(&directory.join(&name)).is_err() {
            cleanup_pending = true;
        }
    }
    cleanup_pending
}

fn prune_index_temps(root: &Path) -> bool {
    let names = match record_io::list(root, MAX_DIRECTORY_ENTRIES) {
        Ok(Some(names)) => names,
        Ok(None) => return false,
        Err(_) => return true,
    };
    let mut cleanup_pending = false;
    for name in names {
        let Some(text) = name.to_str() else {
            continue;
        };
        if is_temp_for_target(text, INDEX_FILE_NAME)
            && record_io::remove(&root.join(&name)).is_err()
        {
            cleanup_pending = true;
        }
    }
    cleanup_pending
}

fn is_object_name(name: &str, suffix: &str) -> bool {
    let Some(digest) = name.strip_suffix(suffix) else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_managed_temp_name(name: &str, suffix: &str) -> bool {
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut fields = body.rsplitn(3, '.');
    let Some(counter) = fields.next() else {
        return false;
    };
    let Some(pid) = fields.next() else {
        return false;
    };
    let Some(target) = fields.next() else {
        return false;
    };
    is_decimal(pid) && is_decimal(counter) && is_object_name(target, suffix)
}

fn is_temp_for_target(name: &str, target: &str) -> bool {
    let Some(body) = name
        .strip_prefix('.')
        .and_then(|name| name.strip_suffix(".tmp"))
    else {
        return false;
    };
    let mut fields = body.rsplitn(3, '.');
    let Some(counter) = fields.next() else {
        return false;
    };
    let Some(pid) = fields.next() else {
        return false;
    };
    fields.next() == Some(target) && is_decimal(pid) && is_decimal(counter)
}

fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn object_name(digest: [u8; 32], suffix: &str) -> String {
    let mut name = hex_digest(digest);
    name.push_str(suffix);
    name
}

fn decode_digest(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut digest = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Ok(digest)
}

fn decode_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(()),
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    let mut value = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to a String cannot fail");
    }
    value
}

#[cfg(test)]
mod tests;
