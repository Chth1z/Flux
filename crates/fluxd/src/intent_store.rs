use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flux_core::{AdministrativeState, BootIdentity};
use serde::{Deserialize, Serialize};

const INTENT_SCHEMA_VERSION: u16 = 1;
// The versioned intent record contains only a boot ID and a two-state enum.
// A 4 KiB budget leaves ample schema-growth headroom while bounding startup I/O.
const MAX_INTENT_RECORD_BYTES: usize = 4096;
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeIntentStore {
    record_path: PathBuf,
    boot_identity: BootIdentity,
}

impl AdministrativeIntentStore {
    #[must_use]
    pub fn new(record_path: impl AsRef<Path>, boot_identity: BootIdentity) -> Self {
        Self {
            record_path: record_path.as_ref().to_owned(),
            boot_identity,
        }
    }

    pub fn load(&self) -> Result<AdministrativeState, IntentStoreError> {
        let Some(encoded) = record_io::read(&self.record_path)? else {
            return Ok(AdministrativeState::Unknown);
        };
        let record = serde_json::from_slice::<IntentRecord>(&encoded)
            .map_err(IntentStoreError::InvalidRecord)?;
        if record.schema_version != INTENT_SCHEMA_VERSION {
            return Err(IntentStoreError::UnsupportedSchema(record.schema_version));
        }
        if record.boot_id != self.boot_identity.as_str() {
            return Ok(AdministrativeState::Unknown);
        }
        Ok(record.administrative_state.into())
    }

    pub fn persist(&self, state: AdministrativeState) -> Result<(), IntentStoreError> {
        let state = StoredAdministrativeState::try_from(state)?;
        let record = IntentRecord {
            schema_version: INTENT_SCHEMA_VERSION,
            boot_id: self.boot_identity.as_str().to_owned(),
            administrative_state: state,
        };
        let mut encoded = serde_json::to_vec(&record).map_err(IntentStoreError::EncodeRecord)?;
        encoded.push(b'\n');
        record_io::write(&self.record_path, &encoded)
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
    InvalidRecord(serde_json::Error),
    EncodeRecord(serde_json::Error),
    UnsupportedSchema(u16),
    RecordTooLarge {
        limit: usize,
    },
    NotRegularFile(PathBuf),
    UnknownState,
    Symlink(PathBuf),
}

impl IntentStoreError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io { source, .. } => source.raw_os_error(),
            Self::InvalidRecord(_)
            | Self::EncodeRecord(_)
            | Self::UnsupportedSchema(_)
            | Self::RecordTooLarge { .. }
            | Self::NotRegularFile(_)
            | Self::UnknownState
            | Self::Symlink(_) => None,
        }
    }
}

impl fmt::Display for IntentStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation} failed: {source}"),
            Self::InvalidRecord(error) => write!(formatter, "invalid intent record: {error}"),
            Self::EncodeRecord(error) => write!(formatter, "cannot encode intent record: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "intent record schema {version} is unsupported")
            }
            Self::RecordTooLarge { limit } => {
                write!(formatter, "intent record exceeds {limit}-byte limit")
            }
            Self::NotRegularFile(path) => {
                write!(
                    formatter,
                    "intent record {} is not a regular file",
                    path.display()
                )
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
            Self::UnsupportedSchema(_)
            | Self::RecordTooLarge { .. }
            | Self::NotRegularFile(_)
            | Self::UnknownState
            | Self::Symlink(_) => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod record_io {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};

    use super::{IntentStoreError, MAX_INTENT_RECORD_BYTES, NEXT_TEMP_ID, Ordering};

    struct ParentDirectory {
        directory: File,
        record_name: CString,
    }

    pub(super) fn read(path: &Path) -> Result<Option<Vec<u8>>, IntentStoreError> {
        let Some(parent) = open_parent_directory(path, false)? else {
            return Ok(None);
        };
        reject_symlink_at(parent.directory.as_raw_fd(), &parent.record_name, path)?;

        let descriptor = open_at(
            parent.directory.as_raw_fd(),
            &parent.record_name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            None,
        );
        let descriptor = match descriptor {
            Ok(descriptor) => descriptor,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(None),
            Err(error) => {
                return Err(classify_component_error(
                    parent.directory.as_raw_fd(),
                    &parent.record_name,
                    path,
                    "read intent record",
                    error,
                ));
            }
        };
        // SAFETY: `openat` returned a new owned descriptor on success.
        let mut file = unsafe { File::from_raw_fd(descriptor) };
        require_regular_file(&file, path)?;
        let encoded = read_bounded(&mut file)?;
        Ok(Some(encoded))
    }

    pub(super) fn write(path: &Path, encoded: &[u8]) -> Result<(), IntentStoreError> {
        let parent = open_parent_directory(path, true)?.ok_or_else(|| {
            IntentStoreError::io(
                "create intent directory",
                io::Error::from_raw_os_error(libc::ENOENT),
            )
        })?;
        reject_symlink_at(parent.directory.as_raw_fd(), &parent.record_name, path)?;

        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = CString::new(
            format!(
                ".{}.{}.{}.tmp",
                path.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("fluxd-intent"),
                std::process::id(),
                temp_id
            )
            .into_bytes(),
        )
        .expect("generated intent temp name contains no NUL");
        let mut temp_created = false;
        let result = (|| {
            let descriptor = open_at(
                parent.directory.as_raw_fd(),
                &temp_name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                Some(0o600),
            )
            .map_err(|error| IntentStoreError::io("create intent record", error))?;
            temp_created = true;
            // SAFETY: `openat` returned a new owned descriptor on success.
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            file.write_all(encoded)
                .map_err(|error| IntentStoreError::io("write intent record", error))?;
            file.flush()
                .map_err(|error| IntentStoreError::io("flush intent record", error))?;
            file.sync_all()
                .map_err(|error| IntentStoreError::io("sync intent record", error))?;

            reject_symlink_at(parent.directory.as_raw_fd(), &parent.record_name, path)?;
            rename_at(
                parent.directory.as_raw_fd(),
                &temp_name,
                &parent.record_name,
            )?;
            parent
                .directory
                .sync_all()
                .map_err(|error| IntentStoreError::io("sync intent directory", error))?;
            Ok(())
        })();
        if result.is_err() && temp_created {
            let _ = unlink_at(parent.directory.as_raw_fd(), &temp_name);
        }
        result
    }

    fn open_parent_directory(
        record_path: &Path,
        create: bool,
    ) -> Result<Option<ParentDirectory>, IntentStoreError> {
        let record_name = record_path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid_path("inspect intent record", record_path))?;
        let record_name = c_string(record_name, "inspect intent record")?;
        let parent = record_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut directory = File::open(if parent.is_absolute() { "/" } else { "." })
            .map_err(|error| IntentStoreError::io("open intent path anchor", error))?;
        let mut traversed = if parent.is_absolute() {
            PathBuf::from("/")
        } else {
            PathBuf::from(".")
        };

        for component in parent.components() {
            let Component::Normal(name) = component else {
                match component {
                    Component::RootDir | Component::CurDir => continue,
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(invalid_path("inspect intent record", record_path));
                    }
                    Component::Normal(_) => unreachable!(),
                }
            };
            traversed.push(name);
            let name = c_string(name, "inspect intent path component")?;
            let next = match open_at(
                directory.as_raw_fd(),
                &name,
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                None,
            ) {
                Ok(descriptor) => descriptor,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) && !create => {
                    return Ok(None);
                }
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                    make_directory_at(directory.as_raw_fd(), &name)?;
                    open_at(
                        directory.as_raw_fd(),
                        &name,
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                        None,
                    )
                    .map_err(|error| {
                        classify_component_error(
                            directory.as_raw_fd(),
                            &name,
                            &traversed,
                            "open intent directory",
                            error,
                        )
                    })?
                }
                Err(error) => {
                    return Err(classify_component_error(
                        directory.as_raw_fd(),
                        &name,
                        &traversed,
                        "open intent directory",
                        error,
                    ));
                }
            };
            // SAFETY: `openat` returned a new owned descriptor on success.
            directory = unsafe { File::from_raw_fd(next) };
        }

        Ok(Some(ParentDirectory {
            directory,
            record_name,
        }))
    }

    fn open_at(
        directory: RawFd,
        path: &CString,
        flags: libc::c_int,
        mode: Option<libc::mode_t>,
    ) -> io::Result<RawFd> {
        // SAFETY: `path` is NUL-terminated, `directory` is an open directory
        // descriptor, and a mode argument is supplied exactly when O_CREAT is set.
        let descriptor = unsafe {
            match mode {
                Some(mode) => libc::openat(directory, path.as_ptr(), flags, mode),
                None => libc::openat(directory, path.as_ptr(), flags),
            }
        };
        if descriptor >= 0 {
            Ok(descriptor)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn make_directory_at(directory: RawFd, path: &CString) -> Result<(), IntentStoreError> {
        // SAFETY: `path` is NUL-terminated and `directory` is an open directory descriptor.
        if unsafe { libc::mkdirat(directory, path.as_ptr(), 0o700) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            Ok(())
        } else {
            Err(IntentStoreError::io("create intent directory", error))
        }
    }

    fn reject_symlink_at(
        directory: RawFd,
        name: &CString,
        display_path: &Path,
    ) -> Result<(), IntentStoreError> {
        if is_symlink_at(directory, name)
            .map_err(|error| IntentStoreError::io("inspect intent record", error))?
        {
            Err(IntentStoreError::Symlink(display_path.to_owned()))
        } else {
            Ok(())
        }
    }

    fn classify_component_error(
        directory: RawFd,
        name: &CString,
        display_path: &Path,
        operation: &'static str,
        error: io::Error,
    ) -> IntentStoreError {
        if matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
        ) {
            match is_symlink_at(directory, name) {
                Ok(true) => return IntentStoreError::Symlink(display_path.to_owned()),
                Ok(false) => {}
                Err(inspect_error) => {
                    return IntentStoreError::io("inspect intent path component", inspect_error);
                }
            }
        }
        IntentStoreError::io(operation, error)
    }

    fn is_symlink_at(directory: RawFd, name: &CString) -> io::Result<bool> {
        let mut byte: libc::c_char = 0;
        // SAFETY: `name` is NUL-terminated, `directory` is an open directory
        // descriptor, and `byte` provides one writable byte for the call.
        let result = unsafe { libc::readlinkat(directory, name.as_ptr(), &raw mut byte, 1) };
        if result >= 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == libc::EINVAL || code == libc::ENOENT => Ok(false),
            _ => Err(error),
        }
    }

    fn rename_at(
        directory: RawFd,
        source: &CString,
        target: &CString,
    ) -> Result<(), IntentStoreError> {
        // SAFETY: both names are NUL-terminated and refer to entries relative
        // to the same open directory descriptor.
        if unsafe { libc::renameat(directory, source.as_ptr(), directory, target.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(IntentStoreError::io(
                "publish intent record",
                io::Error::last_os_error(),
            ))
        }
    }

    fn unlink_at(directory: RawFd, path: &CString) -> io::Result<()> {
        // SAFETY: `path` is NUL-terminated and `directory` is an open directory descriptor.
        if unsafe { libc::unlinkat(directory, path.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn c_string(path: &OsStr, operation: &'static str) -> Result<CString, IntentStoreError> {
        CString::new(path.as_bytes()).map_err(|_| {
            IntentStoreError::io(
                operation,
                io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"),
            )
        })
    }

    fn invalid_path(operation: &'static str, path: &Path) -> IntentStoreError {
        IntentStoreError::io(
            operation,
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsafe intent record path {}", path.display()),
            ),
        )
    }

    fn read_bounded(file: &mut File) -> Result<Vec<u8>, IntentStoreError> {
        let mut encoded = Vec::with_capacity(MAX_INTENT_RECORD_BYTES.min(256));
        file.take((MAX_INTENT_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|error| IntentStoreError::io("read intent record", error))?;
        if encoded.len() > MAX_INTENT_RECORD_BYTES {
            return Err(IntentStoreError::RecordTooLarge {
                limit: MAX_INTENT_RECORD_BYTES,
            });
        }
        Ok(encoded)
    }

    fn require_regular_file(file: &File, path: &Path) -> Result<(), IntentStoreError> {
        let metadata = file
            .metadata()
            .map_err(|error| IntentStoreError::io("inspect intent record", error))?;
        if metadata.is_file() {
            Ok(())
        } else {
            Err(IntentStoreError::NotRegularFile(path.to_owned()))
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod record_io {
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::path::Path;

    use super::{IntentStoreError, MAX_INTENT_RECORD_BYTES, NEXT_TEMP_ID, Ordering};

    pub(super) fn read(path: &Path) -> Result<Option<Vec<u8>>, IntentStoreError> {
        reject_symlink(path)?;
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(IntentStoreError::io("read intent record", error)),
        };
        require_regular_file(&file, path)?;
        let encoded = read_bounded(&mut file)?;
        Ok(Some(encoded))
    }

    pub(super) fn write(path: &Path, encoded: &[u8]) -> Result<(), IntentStoreError> {
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|error| IntentStoreError::io("create intent directory", error))?;
        reject_symlink(path)?;

        let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temp_name = format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fluxd-intent"),
            std::process::id(),
            temp_id
        );
        let temp_path = parent.join(temp_name);
        let result = (|| {
            let mut file = open_secure_new(&temp_path)?;
            file.write_all(encoded)
                .map_err(|error| IntentStoreError::io("write intent record", error))?;
            file.flush()
                .map_err(|error| IntentStoreError::io("flush intent record", error))?;
            file.sync_all()
                .map_err(|error| IntentStoreError::io("sync intent record", error))?;
            replace_file(&temp_path, path)?;
            sync_parent_directory(parent)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        result
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
        fs::rename(source, target)
            .map_err(|error| IntentStoreError::io("publish intent record", error))
    }

    #[cfg(not(unix))]
    fn replace_file(source: &Path, target: &Path) -> Result<(), IntentStoreError> {
        if target.exists() {
            fs::remove_file(target)
                .map_err(|error| IntentStoreError::io("replace intent record", error))?;
        }
        fs::rename(source, target)
            .map_err(|error| IntentStoreError::io("publish intent record", error))
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

    fn read_bounded(file: &mut File) -> Result<Vec<u8>, IntentStoreError> {
        let mut encoded = Vec::with_capacity(MAX_INTENT_RECORD_BYTES.min(256));
        file.take((MAX_INTENT_RECORD_BYTES + 1) as u64)
            .read_to_end(&mut encoded)
            .map_err(|error| IntentStoreError::io("read intent record", error))?;
        if encoded.len() > MAX_INTENT_RECORD_BYTES {
            return Err(IntentStoreError::RecordTooLarge {
                limit: MAX_INTENT_RECORD_BYTES,
            });
        }
        Ok(encoded)
    }

    fn require_regular_file(file: &File, path: &Path) -> Result<(), IntentStoreError> {
        let metadata = file
            .metadata()
            .map_err(|error| IntentStoreError::io("inspect intent record", error))?;
        if metadata.is_file() {
            Ok(())
        } else {
            Err(IntentStoreError::NotRegularFile(path.to_owned()))
        }
    }
}
