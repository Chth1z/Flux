use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flux_core::AdministrativeState;
use serde::{Deserialize, Serialize};

const INTENT_SCHEMA_VERSION: u16 = 1;
const MAX_BOOT_ID_BYTES: usize = 128;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeIntentStore {
    record_path: PathBuf,
    boot_id_path: PathBuf,
}

impl AdministrativeIntentStore {
    #[must_use]
    pub fn new(record_path: impl AsRef<Path>, boot_id_path: impl AsRef<Path>) -> Self {
        Self {
            record_path: record_path.as_ref().to_owned(),
            boot_id_path: boot_id_path.as_ref().to_owned(),
        }
    }

    pub fn load(&self) -> Result<AdministrativeState, IntentStoreError> {
        let boot_id = self.read_boot_id()?;
        reject_symlink(&self.record_path)?;
        let encoded = match fs::read(&self.record_path) {
            Ok(encoded) => encoded,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AdministrativeState::Unknown);
            }
            Err(error) => return Err(IntentStoreError::io("read intent record", error)),
        };
        let record = serde_json::from_slice::<IntentRecord>(&encoded)
            .map_err(IntentStoreError::InvalidRecord)?;
        if record.schema_version != INTENT_SCHEMA_VERSION {
            return Err(IntentStoreError::UnsupportedSchema(record.schema_version));
        }
        if record.boot_id != boot_id {
            return Ok(AdministrativeState::Unknown);
        }
        Ok(record.administrative_state.into())
    }

    pub fn persist(&self, state: AdministrativeState) -> Result<(), IntentStoreError> {
        let state = StoredAdministrativeState::try_from(state)?;
        let boot_id = self.read_boot_id()?;
        let parent = self
            .record_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| IntentStoreError::io("create intent directory", error))?;
        reject_symlink(&self.record_path)?;

        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{}.{}.{}.tmp",
            self.record_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fluxd-intent"),
            std::process::id(),
            temp_id
        );
        let temp_path = parent.join(temp_name);
        let result = (|| {
            let mut file = open_secure_new(&temp_path)?;
            let record = IntentRecord {
                schema_version: INTENT_SCHEMA_VERSION,
                boot_id,
                administrative_state: state,
            };
            serde_json::to_writer(&mut file, &record).map_err(IntentStoreError::EncodeRecord)?;
            file.write_all(b"\n")
                .map_err(|error| IntentStoreError::io("write intent record", error))?;
            file.flush()
                .map_err(|error| IntentStoreError::io("flush intent record", error))?;
            file.sync_all()
                .map_err(|error| IntentStoreError::io("sync intent record", error))?;
            replace_file(&temp_path, &self.record_path)?;
            sync_parent_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
    }

    fn read_boot_id(&self) -> Result<String, IntentStoreError> {
        let boot_id = fs::read_to_string(&self.boot_id_path)
            .map_err(|error| IntentStoreError::io("read boot identity", error))?;
        let boot_id = boot_id.trim();
        if boot_id.is_empty() || boot_id.len() > MAX_BOOT_ID_BYTES {
            return Err(IntentStoreError::InvalidBootIdentity);
        }
        Ok(boot_id.to_owned())
    }
}

#[derive(Deserialize, Serialize)]
struct IntentRecord {
    schema_version: u16,
    boot_id: String,
    administrative_state: StoredAdministrativeState,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredAdministrativeState {
    Running,
    Stopped,
}

impl TryFrom<AdministrativeState> for StoredAdministrativeState {
    type Error = IntentStoreError;

    fn try_from(state: AdministrativeState) -> Result<Self, Self::Error> {
        match state {
            AdministrativeState::Running => Ok(Self::Running),
            AdministrativeState::Stopped => Ok(Self::Stopped),
            AdministrativeState::Unknown => Err(IntentStoreError::UnknownState),
        }
    }
}

impl From<StoredAdministrativeState> for AdministrativeState {
    fn from(state: StoredAdministrativeState) -> Self {
        match state {
            StoredAdministrativeState::Running => Self::Running,
            StoredAdministrativeState::Stopped => Self::Stopped,
        }
    }
}

#[derive(Debug)]
pub enum IntentStoreError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidBootIdentity,
    InvalidRecord(serde_json::Error),
    EncodeRecord(serde_json::Error),
    UnsupportedSchema(u16),
    UnknownState,
    Symlink(PathBuf),
}

impl IntentStoreError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for IntentStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation} failed: {source}"),
            Self::InvalidBootIdentity => formatter.write_str("boot identity is empty or too large"),
            Self::InvalidRecord(error) => write!(formatter, "invalid intent record: {error}"),
            Self::EncodeRecord(error) => write!(formatter, "cannot encode intent record: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "intent record schema {version} is unsupported")
            }
            Self::UnknownState => {
                formatter.write_str("cannot persist unknown administrative intent")
            }
            Self::Symlink(path) => write!(
                formatter,
                "refusing symbolic-link intent path {}",
                path.display()
            ),
        }
    }
}

impl Error for IntentStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidRecord(error) | Self::EncodeRecord(error) => Some(error),
            Self::InvalidBootIdentity
            | Self::UnsupportedSchema(_)
            | Self::UnknownState
            | Self::Symlink(_) => None,
        }
    }
}

fn reject_symlink(path: &Path) -> Result<(), IntentStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(IntentStoreError::Symlink(path.to_owned()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(IntentStoreError::io("inspect intent record", error)),
    }
}

#[cfg(unix)]
fn open_secure_new(path: &Path) -> Result<File, IntentStoreError> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| IntentStoreError::io("create intent record", error))
}

#[cfg(not(unix))]
fn open_secure_new(path: &Path) -> Result<File, IntentStoreError> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| IntentStoreError::io("create intent record", error))
}

#[cfg(unix)]
fn replace_file(source: &Path, target: &Path) -> Result<(), IntentStoreError> {
    fs::rename(source, target).map_err(|error| IntentStoreError::io("publish intent record", error))
}

#[cfg(not(unix))]
fn replace_file(source: &Path, target: &Path) -> Result<(), IntentStoreError> {
    if target.exists() {
        fs::remove_file(target)
            .map_err(|error| IntentStoreError::io("replace intent record", error))?;
    }
    fs::rename(source, target).map_err(|error| IntentStoreError::io("publish intent record", error))
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<(), IntentStoreError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| IntentStoreError::io("sync intent directory", error))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<(), IntentStoreError> {
    Ok(())
}
