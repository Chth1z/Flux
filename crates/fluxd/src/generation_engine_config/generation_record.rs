use std::error::Error;
use std::fmt;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{
    ADMITTED_GENERATION_SCHEMA_VERSION, AdmittedGeneration, AdmittedGenerationIdentity,
    GenerationAdmissionKind, GenerationAssemblyDigest,
};
use crate::IntentStoreError;
use crate::intent_store::record_io;

pub(crate) const PREPARED_GENERATION_RECORD_SCHEMA_VERSION: u16 = 1;
pub(crate) const MAX_PREPARED_GENERATION_RECORD_BYTES: usize = 16 * 1_024;
const DIGEST_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedGenerationRecord {
    identity: AdmittedGenerationIdentity,
    previous: Option<AdmittedGenerationIdentity>,
    admission: GenerationAdmissionKind,
    capability_profile_revision: u64,
    capability_profile_digest: [u8; DIGEST_BYTES],
    inventory_snapshot: u64,
    inventory_epoch: u64,
    planning_evidence_digest: [u8; DIGEST_BYTES],
    engine_profile_revision: [u8; DIGEST_BYTES],
    engine_config_binding: [u8; DIGEST_BYTES],
    capture_program_digest: [u8; DIGEST_BYTES],
    xtables_artifact_digest: [u8; DIGEST_BYTES],
}

impl PreparedGenerationRecord {
    #[must_use]
    pub(crate) fn from_admitted(generation: &AdmittedGeneration) -> Self {
        Self {
            identity: generation.identity(),
            previous: generation.prior_owned(),
            admission: generation.admission_kind(),
            capability_profile_revision: generation.candidate().device_profile().revision().get(),
            capability_profile_digest: *generation.candidate().device_profile().digest().as_bytes(),
            inventory_snapshot: generation.candidate().inventory_snapshot().get(),
            inventory_epoch: generation.candidate().inventory_epoch().get(),
            planning_evidence_digest: *generation.planning_digest().as_bytes(),
            engine_profile_revision: *generation
                .candidate()
                .engine_profile()
                .revision()
                .as_bytes(),
            engine_config_binding: *generation.candidate().engine_config().digest().as_bytes(),
            capture_program_digest: *generation.capture().artifact().digest().as_bytes(),
            xtables_artifact_digest: *generation.xtables().digest().as_bytes(),
        }
    }

    #[must_use]
    pub(crate) const fn schema_version(&self) -> u16 {
        PREPARED_GENERATION_RECORD_SCHEMA_VERSION
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> AdmittedGenerationIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn previous(&self) -> Option<AdmittedGenerationIdentity> {
        self.previous
    }

    #[must_use]
    pub(crate) const fn admission(&self) -> GenerationAdmissionKind {
        self.admission
    }

    #[must_use]
    pub(crate) const fn capability_profile_revision(&self) -> u64 {
        self.capability_profile_revision
    }

    #[must_use]
    pub(crate) const fn capability_profile_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.capability_profile_digest
    }

    #[must_use]
    pub(crate) const fn inventory_snapshot(&self) -> u64 {
        self.inventory_snapshot
    }

    #[must_use]
    pub(crate) const fn inventory_epoch(&self) -> u64 {
        self.inventory_epoch
    }

    #[must_use]
    pub(crate) const fn planning_evidence_digest(&self) -> &[u8; DIGEST_BYTES] {
        &self.planning_evidence_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedGenerationRecordStore {
    record_path: PathBuf,
}

impl PreparedGenerationRecordStore {
    #[must_use]
    pub(crate) fn new(record_path: impl AsRef<Path>) -> Self {
        Self {
            record_path: record_path.as_ref().to_owned(),
        }
    }

    pub(crate) fn load(
        &self,
    ) -> Result<Option<PreparedGenerationRecord>, PreparedGenerationRecordError> {
        let Some(encoded) =
            record_io::read(&self.record_path, MAX_PREPARED_GENERATION_RECORD_BYTES)
                .map_err(PreparedGenerationRecordError::Storage)?
        else {
            return Ok(None);
        };
        let stored = serde_json::from_slice::<StoredPreparedGenerationRecord>(&encoded)
            .map_err(PreparedGenerationRecordError::InvalidRecord)?;
        PreparedGenerationRecord::try_from(stored).map(Some)
    }

    pub(crate) fn persist(
        &self,
        record: &PreparedGenerationRecord,
    ) -> Result<(), PreparedGenerationRecordError> {
        let stored = StoredPreparedGenerationRecord::from(record);
        let mut encoded =
            serde_json::to_vec(&stored).map_err(PreparedGenerationRecordError::EncodeRecord)?;
        encoded.push(b'\n');
        if encoded.len() > MAX_PREPARED_GENERATION_RECORD_BYTES {
            return Err(PreparedGenerationRecordError::RecordTooLarge {
                actual: encoded.len(),
                maximum: MAX_PREPARED_GENERATION_RECORD_BYTES,
            });
        }
        record_io::write(&self.record_path, &encoded)
            .map_err(PreparedGenerationRecordError::Storage)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredGenerationPhase {
    Prepared,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredGenerationAdmission {
    HostInspectionOnly,
    AndroidPlanningEvidence,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredGenerationIdentity {
    generation: u32,
    digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredPreparedGenerationRecord {
    schema_version: u16,
    generation_schema_version: u16,
    phase: StoredGenerationPhase,
    identity: StoredGenerationIdentity,
    previous: Option<StoredGenerationIdentity>,
    admission: StoredGenerationAdmission,
    capability_profile_revision: u64,
    capability_profile_digest: String,
    inventory_snapshot: u64,
    inventory_epoch: u64,
    planning_evidence_digest: String,
    engine_profile_revision: String,
    engine_config_binding: String,
    capture_program_digest: String,
    xtables_artifact_digest: String,
}

impl From<&PreparedGenerationRecord> for StoredPreparedGenerationRecord {
    fn from(record: &PreparedGenerationRecord) -> Self {
        Self {
            schema_version: PREPARED_GENERATION_RECORD_SCHEMA_VERSION,
            generation_schema_version: ADMITTED_GENERATION_SCHEMA_VERSION,
            phase: StoredGenerationPhase::Prepared,
            identity: stored_identity(record.identity),
            previous: record.previous.map(stored_identity),
            admission: match record.admission {
                GenerationAdmissionKind::HostInspectionOnly => {
                    StoredGenerationAdmission::HostInspectionOnly
                }
                GenerationAdmissionKind::AndroidPlanningEvidence => {
                    StoredGenerationAdmission::AndroidPlanningEvidence
                }
            },
            capability_profile_revision: record.capability_profile_revision,
            capability_profile_digest: hex(&record.capability_profile_digest),
            inventory_snapshot: record.inventory_snapshot,
            inventory_epoch: record.inventory_epoch,
            planning_evidence_digest: hex(&record.planning_evidence_digest),
            engine_profile_revision: hex(&record.engine_profile_revision),
            engine_config_binding: hex(&record.engine_config_binding),
            capture_program_digest: hex(&record.capture_program_digest),
            xtables_artifact_digest: hex(&record.xtables_artifact_digest),
        }
    }
}

impl TryFrom<StoredPreparedGenerationRecord> for PreparedGenerationRecord {
    type Error = PreparedGenerationRecordError;

    fn try_from(stored: StoredPreparedGenerationRecord) -> Result<Self, Self::Error> {
        if stored.schema_version != PREPARED_GENERATION_RECORD_SCHEMA_VERSION {
            return Err(PreparedGenerationRecordError::UnsupportedSchema {
                actual: stored.schema_version,
                supported: PREPARED_GENERATION_RECORD_SCHEMA_VERSION,
            });
        }
        if stored.generation_schema_version != ADMITTED_GENERATION_SCHEMA_VERSION {
            return Err(PreparedGenerationRecordError::UnsupportedGenerationSchema {
                actual: stored.generation_schema_version,
                supported: ADMITTED_GENERATION_SCHEMA_VERSION,
            });
        }
        let identity = decode_identity(stored.identity, "identity.digest")?;
        let previous = stored
            .previous
            .map(|identity| decode_identity(identity, "previous.digest"))
            .transpose()?;
        let has_valid_lineage = match previous {
            Some(previous) => previous
                .generation()
                .get()
                .checked_add(1)
                .is_some_and(|generation| generation == identity.generation().get()),
            None => identity.generation().get() == 1,
        };
        if !has_valid_lineage {
            return Err(PreparedGenerationRecordError::InvalidPreviousGeneration);
        }
        Ok(Self {
            identity,
            previous,
            admission: match stored.admission {
                StoredGenerationAdmission::HostInspectionOnly => {
                    GenerationAdmissionKind::HostInspectionOnly
                }
                StoredGenerationAdmission::AndroidPlanningEvidence => {
                    GenerationAdmissionKind::AndroidPlanningEvidence
                }
            },
            capability_profile_revision: nonzero_record_value(
                stored.capability_profile_revision,
                "capability_profile_revision",
            )?,
            capability_profile_digest: decode_digest(
                &stored.capability_profile_digest,
                "capability_profile_digest",
            )?,
            inventory_snapshot: nonzero_record_value(
                stored.inventory_snapshot,
                "inventory_snapshot",
            )?,
            inventory_epoch: nonzero_record_value(stored.inventory_epoch, "inventory_epoch")?,
            planning_evidence_digest: decode_digest(
                &stored.planning_evidence_digest,
                "planning_evidence_digest",
            )?,
            engine_profile_revision: decode_digest(
                &stored.engine_profile_revision,
                "engine_profile_revision",
            )?,
            engine_config_binding: decode_digest(
                &stored.engine_config_binding,
                "engine_config_binding",
            )?,
            capture_program_digest: decode_digest(
                &stored.capture_program_digest,
                "capture_program_digest",
            )?,
            xtables_artifact_digest: decode_digest(
                &stored.xtables_artifact_digest,
                "xtables_artifact_digest",
            )?,
        })
    }
}

#[derive(Debug)]
pub(crate) enum PreparedGenerationRecordError {
    Storage(IntentStoreError),
    InvalidRecord(serde_json::Error),
    EncodeRecord(serde_json::Error),
    UnsupportedSchema { actual: u16, supported: u16 },
    UnsupportedGenerationSchema { actual: u16, supported: u16 },
    InvalidGeneration,
    InvalidPreviousGeneration,
    InvalidDigest { field: &'static str },
    ZeroValue { field: &'static str },
    RecordTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for PreparedGenerationRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(source) => {
                write!(formatter, "durable Generation record I/O failed: {source}")
            }
            Self::InvalidRecord(source) => write!(formatter, "invalid Generation record: {source}"),
            Self::EncodeRecord(source) => {
                write!(formatter, "cannot encode Generation record: {source}")
            }
            Self::UnsupportedSchema { actual, supported } => write!(
                formatter,
                "Generation record schema {actual} is unsupported; expected {supported}"
            ),
            Self::UnsupportedGenerationSchema { actual, supported } => write!(
                formatter,
                "Generation artifact schema {actual} is unsupported; expected {supported}"
            ),
            Self::InvalidGeneration => formatter.write_str("Generation record ID must be nonzero"),
            Self::InvalidPreviousGeneration => formatter.write_str(
                "Generation 1 must have no predecessor and every later Generation must name its immediate predecessor",
            ),
            Self::InvalidDigest { field } => {
                write!(
                    formatter,
                    "Generation record field {field} is not lowercase SHA-256 hex"
                )
            }
            Self::ZeroValue { field } => {
                write!(formatter, "Generation record field {field} must be nonzero")
            }
            Self::RecordTooLarge { actual, maximum } => write!(
                formatter,
                "encoded Generation record is {actual} bytes, exceeding {maximum} bytes"
            ),
        }
    }
}

impl Error for PreparedGenerationRecordError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Storage(source) => Some(source),
            Self::InvalidRecord(source) | Self::EncodeRecord(source) => Some(source),
            _ => None,
        }
    }
}

fn stored_identity(identity: AdmittedGenerationIdentity) -> StoredGenerationIdentity {
    StoredGenerationIdentity {
        generation: identity.generation().get(),
        digest: hex(identity.digest().as_bytes()),
    }
}

fn decode_identity(
    stored: StoredGenerationIdentity,
    digest_field: &'static str,
) -> Result<AdmittedGenerationIdentity, PreparedGenerationRecordError> {
    let generation = NonZeroU32::new(stored.generation)
        .ok_or(PreparedGenerationRecordError::InvalidGeneration)?;
    let digest = GenerationAssemblyDigest::from_bytes(decode_digest(&stored.digest, digest_field)?);
    Ok(AdmittedGenerationIdentity::new(generation, digest))
}

fn nonzero_record_value(
    value: u64,
    field: &'static str,
) -> Result<u64, PreparedGenerationRecordError> {
    if value == 0 {
        Err(PreparedGenerationRecordError::ZeroValue { field })
    } else {
        Ok(value)
    }
}

fn decode_digest(
    encoded: &str,
    field: &'static str,
) -> Result<[u8; DIGEST_BYTES], PreparedGenerationRecordError> {
    if encoded.len() != DIGEST_BYTES * 2 {
        return Err(PreparedGenerationRecordError::InvalidDigest { field });
    }
    let mut decoded = [0_u8; DIGEST_BYTES];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high =
            hex_nibble(pair[0]).ok_or(PreparedGenerationRecordError::InvalidDigest { field })?;
        let low =
            hex_nibble(pair[1]).ok_or(PreparedGenerationRecordError::InvalidDigest { field })?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
