use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::num::{NonZeroU16, NonZeroU32};
use std::path::{Path, PathBuf};
use std::str;
use std::time::Duration;

use serde::Deserialize;

const SUPPORTED_SCHEMA: u16 = 1;
/// Maximum UTF-8 byte length accepted by the Phase-1 configuration seam.
pub const MAX_CONFIG_DOCUMENT_BYTES: usize = 64 * 1_024;
const LOAD_READ_LIMIT: u64 = MAX_CONFIG_DOCUMENT_BYTES as u64 + 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FluxConfig {
    schema: u16,
    daemon: DaemonConfig,
}

impl FluxConfig {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_DOCUMENT_BYTES {
            return Err(ConfigError::document_too_large());
        }
        let raw: RawFluxConfig = toml::from_str(input).map_err(ConfigError::toml)?;
        if raw.schema != i64::from(SUPPORTED_SCHEMA) {
            return Err(ConfigError::unsupported_schema(raw.schema));
        }
        Ok(Self {
            schema: SUPPORTED_SCHEMA,
            daemon: DaemonConfig {
                fail_policy: FailurePolicy::from_raw(raw.daemon.fail_policy)?,
                reconcile_debounce: ReconcileDebounce::from_raw(raw.daemon.reconcile_debounce_ms)?,
                event_queue_capacity: EventQueueCapacity::from_raw(
                    raw.daemon.event_queue_capacity,
                )?,
                generation_history: GenerationHistory::from_raw(raw.daemon.generation_history)?,
            },
        })
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let file = open_regular_config(path).map_err(|error| match error {
            ConfigOpenError::Io(source) => ConfigError::io(path, source),
            ConfigOpenError::UnsafeFileType(source) => ConfigError::unsafe_file_type(path, source),
        })?;
        let mut input = Vec::with_capacity(MAX_CONFIG_DOCUMENT_BYTES + 1);
        file.take(LOAD_READ_LIMIT)
            .read_to_end(&mut input)
            .map_err(|source| ConfigError::io(path, source))?;
        if input.len() > MAX_CONFIG_DOCUMENT_BYTES {
            return Err(ConfigError::document_too_large());
        }
        let input = str::from_utf8(&input).map_err(|source| ConfigError::utf8(path, source))?;
        Self::parse(input)
    }

    #[must_use]
    pub const fn schema(&self) -> u16 {
        self.schema
    }

    #[must_use]
    pub const fn daemon(&self) -> &DaemonConfig {
        &self.daemon
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_regular_config(path: &Path) -> Result<fs::File, ConfigOpenError> {
    use std::os::fd::AsRawFd;

    let (absolute, components) = validated_unix_components(path)?;
    let (final_name, parents) = components
        .split_last()
        .ok_or_else(|| ConfigOpenError::UnsafeFileType(invalid_config_path_error()))?;
    let anchor = if absolute { c"/" } else { c"." };
    let mut directory = open_at(
        libc::AT_FDCWD,
        anchor,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
    .map_err(ConfigOpenError::from_traversal_io)?;
    for component in parents {
        directory = open_at(
            directory.as_raw_fd(),
            component,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
        .map_err(ConfigOpenError::from_traversal_io)?;
    }

    let metadata = stat_at_no_follow(directory.as_raw_fd(), final_name)
        .map_err(ConfigOpenError::from_traversal_io)?;
    let file_type = metadata.st_mode & libc::S_IFMT;
    if file_type == libc::S_IFLNK {
        return Err(ConfigOpenError::UnsafeFileType(
            io::Error::from_raw_os_error(libc::ELOOP),
        ));
    }
    if file_type != libc::S_IFREG {
        return Err(ConfigOpenError::UnsafeFileType(non_regular_file_error()));
    }

    let descriptor = open_at(
        directory.as_raw_fd(),
        final_name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )
    .map_err(ConfigOpenError::from_traversal_io)?;
    let file = fs::File::from(descriptor);
    require_regular_file(&file)?;
    Ok(file)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_regular_config(path: &Path) -> Result<fs::File, ConfigOpenError> {
    let metadata = fs::symlink_metadata(path).map_err(ConfigOpenError::Io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ConfigOpenError::UnsafeFileType(non_regular_file_error()));
    }

    let file = fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(ConfigOpenError::Io)?;
    require_regular_file(&file)?;
    Ok(file)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validated_unix_components(
    path: &Path,
) -> Result<(bool, Vec<std::ffi::CString>), ConfigOpenError> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    if path.as_os_str().as_bytes().last() == Some(&b'/') {
        return Err(ConfigOpenError::UnsafeFileType(invalid_config_path_error()));
    }

    let absolute = path.is_absolute();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir if absolute => {}
            Component::CurDir => {}
            Component::Normal(name) => {
                components.push(std::ffi::CString::new(name.as_bytes()).map_err(|_| {
                    ConfigOpenError::Io(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Flux configuration path contains NUL",
                    ))
                })?)
            }
            Component::ParentDir | Component::Prefix(_) | Component::RootDir => {
                return Err(ConfigOpenError::UnsafeFileType(invalid_config_path_error()));
            }
        }
    }
    Ok((absolute, components))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_at(
    directory: std::os::fd::RawFd,
    path: &std::ffi::CStr,
    flags: libc::c_int,
) -> io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;

    // SAFETY: `directory` is either AT_FDCWD or a live directory descriptor,
    // `path` is NUL-terminated, and no creation flag requires a mode argument.
    let descriptor = unsafe { libc::openat(directory, path.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `openat` returned one new owned descriptor.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn stat_at_no_follow(
    directory: std::os::fd::RawFd,
    path: &std::ffi::CStr,
) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `directory` is a live directory descriptor, `path` is
    // NUL-terminated, and `metadata` has writable storage for one `stat`.
    if unsafe {
        libc::fstatat(
            directory,
            path.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized the complete `stat` value.
    Ok(unsafe { metadata.assume_init() })
}

fn require_regular_file(file: &fs::File) -> Result<(), ConfigOpenError> {
    // `File::metadata` is descriptor-relative (`fstat` on Unix), so the
    // validation applies to the object that was actually opened rather than
    // to an earlier pathname lookup.
    if file
        .metadata()
        .map_err(ConfigOpenError::Io)?
        .file_type()
        .is_file()
    {
        Ok(())
    } else {
        Err(ConfigOpenError::UnsafeFileType(non_regular_file_error()))
    }
}

enum ConfigOpenError {
    Io(io::Error),
    UnsafeFileType(io::Error),
}

impl ConfigOpenError {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn from_traversal_io(source: io::Error) -> Self {
        if matches!(
            source.raw_os_error(),
            Some(libc::ELOOP) | Some(libc::ENOTDIR)
        ) {
            Self::UnsafeFileType(source)
        } else {
            Self::Io(source)
        }
    }
}

fn non_regular_file_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Flux configuration path is not a regular file",
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn invalid_config_path_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "Flux configuration path contains an unsafe component",
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    fail_policy: FailurePolicy,
    reconcile_debounce: ReconcileDebounce,
    event_queue_capacity: EventQueueCapacity,
    generation_history: GenerationHistory,
}

impl DaemonConfig {
    #[must_use]
    pub const fn fail_policy(self) -> FailurePolicy {
        self.fail_policy
    }

    #[must_use]
    pub const fn reconcile_debounce(self) -> ReconcileDebounce {
        self.reconcile_debounce
    }

    #[must_use]
    pub const fn event_queue_capacity(self) -> EventQueueCapacity {
        self.event_queue_capacity
    }

    #[must_use]
    pub const fn generation_history(self) -> GenerationHistory {
        self.generation_history
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FailurePolicy {
    Open,
}

impl FailurePolicy {
    fn from_raw(raw: RawFailurePolicy) -> Result<Self, ConfigError> {
        match raw {
            RawFailurePolicy::Open => Ok(Self::Open),
            RawFailurePolicy::Closed => Err(ConfigError::unsupported_failure_policy("closed")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconcileDebounce(NonZeroU32);

impl ReconcileDebounce {
    pub const MIN_MILLISECONDS: u32 = 1;
    pub const MAX_MILLISECONDS: u32 = u32::MAX;

    fn from_raw(value: i64) -> Result<Self, ConfigError> {
        let value = u32::try_from(value)
            .ok()
            .filter(|value| (Self::MIN_MILLISECONDS..=Self::MAX_MILLISECONDS).contains(value))
            .and_then(NonZeroU32::new)
            .ok_or(ConfigError::value_out_of_range(
                "daemon.reconcile_debounce_ms",
                value,
                i64::from(Self::MIN_MILLISECONDS),
                i64::from(Self::MAX_MILLISECONDS),
            ))?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> Duration {
        Duration::from_millis(self.0.get() as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventQueueCapacity(NonZeroU32);

impl EventQueueCapacity {
    pub const MIN: u32 = 1;
    /// Phase-1 memory resource budget, not a kernel capability limit.
    pub const MAX: u32 = 4_096;

    fn from_raw(value: i64) -> Result<Self, ConfigError> {
        let value = u32::try_from(value)
            .ok()
            .filter(|value| (Self::MIN..=Self::MAX).contains(value))
            .and_then(NonZeroU32::new)
            .ok_or(ConfigError::value_out_of_range(
                "daemon.event_queue_capacity",
                value,
                i64::from(Self::MIN),
                i64::from(Self::MAX),
            ))?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenerationHistory(NonZeroU16);

impl GenerationHistory {
    pub const MIN: u16 = 1;
    /// Phase-1 disk-retention resource budget, not a kernel capability limit.
    pub const MAX: u16 = 32;

    fn from_raw(value: i64) -> Result<Self, ConfigError> {
        let value = u16::try_from(value)
            .ok()
            .filter(|value| (Self::MIN..=Self::MAX).contains(value))
            .and_then(NonZeroU16::new)
            .ok_or(ConfigError::value_out_of_range(
                "daemon.generation_history",
                value,
                i64::from(Self::MIN),
                i64::from(Self::MAX),
            ))?;
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfigErrorKind {
    Io,
    UnsafeFileType,
    InvalidUtf8,
    InvalidToml,
    DocumentTooLarge {
        maximum_bytes: usize,
    },
    UnsupportedSchema {
        found: i64,
        supported: i64,
    },
    UnsupportedFailurePolicy {
        policy: &'static str,
    },
    ValueOutOfRange {
        field: &'static str,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
}

#[derive(Debug)]
pub struct ConfigError(ConfigErrorRepr);

#[derive(Debug)]
enum ConfigErrorRepr {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    UnsafeFileType {
        path: PathBuf,
        source: io::Error,
    },
    Utf8 {
        path: PathBuf,
        source: str::Utf8Error,
    },
    Toml(toml::de::Error),
    DocumentTooLarge {
        maximum_bytes: usize,
    },
    UnsupportedSchema {
        found: i64,
        supported: i64,
    },
    UnsupportedFailurePolicy {
        policy: &'static str,
    },
    ValueOutOfRange {
        field: &'static str,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
}

impl ConfigError {
    #[must_use]
    pub fn kind(&self) -> ConfigErrorKind {
        match &self.0 {
            ConfigErrorRepr::Io { .. } => ConfigErrorKind::Io,
            ConfigErrorRepr::UnsafeFileType { .. } => ConfigErrorKind::UnsafeFileType,
            ConfigErrorRepr::Utf8 { .. } => ConfigErrorKind::InvalidUtf8,
            ConfigErrorRepr::Toml(_) => ConfigErrorKind::InvalidToml,
            ConfigErrorRepr::DocumentTooLarge { maximum_bytes } => {
                ConfigErrorKind::DocumentTooLarge {
                    maximum_bytes: *maximum_bytes,
                }
            }
            ConfigErrorRepr::UnsupportedSchema { found, supported } => {
                ConfigErrorKind::UnsupportedSchema {
                    found: *found,
                    supported: *supported,
                }
            }
            ConfigErrorRepr::UnsupportedFailurePolicy { policy } => {
                ConfigErrorKind::UnsupportedFailurePolicy { policy }
            }
            ConfigErrorRepr::ValueOutOfRange {
                field,
                value,
                minimum,
                maximum,
            } => ConfigErrorKind::ValueOutOfRange {
                field,
                value: *value,
                minimum: *minimum,
                maximum: *maximum,
            },
        }
    }

    fn io(path: &Path, source: io::Error) -> Self {
        Self(ConfigErrorRepr::Io {
            path: path.to_owned(),
            source,
        })
    }

    fn unsafe_file_type(path: &Path, source: io::Error) -> Self {
        Self(ConfigErrorRepr::UnsafeFileType {
            path: path.to_owned(),
            source,
        })
    }

    fn utf8(path: &Path, source: str::Utf8Error) -> Self {
        Self(ConfigErrorRepr::Utf8 {
            path: path.to_owned(),
            source,
        })
    }

    fn toml(source: toml::de::Error) -> Self {
        Self(ConfigErrorRepr::Toml(source))
    }

    fn document_too_large() -> Self {
        Self(ConfigErrorRepr::DocumentTooLarge {
            maximum_bytes: MAX_CONFIG_DOCUMENT_BYTES,
        })
    }

    fn unsupported_schema(found: i64) -> Self {
        Self(ConfigErrorRepr::UnsupportedSchema {
            found,
            supported: i64::from(SUPPORTED_SCHEMA),
        })
    }

    fn unsupported_failure_policy(policy: &'static str) -> Self {
        Self(ConfigErrorRepr::UnsupportedFailurePolicy { policy })
    }

    fn value_out_of_range(field: &'static str, value: i64, minimum: i64, maximum: i64) -> Self {
        Self(ConfigErrorRepr::ValueOutOfRange {
            field,
            value,
            minimum,
            maximum,
        })
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            ConfigErrorRepr::Io { path, source } => write!(
                formatter,
                "cannot read Flux configuration {}: {source}",
                path.display()
            ),
            ConfigErrorRepr::UnsafeFileType { path, .. } => write!(
                formatter,
                "Flux configuration {} must be a direct regular file",
                path.display()
            ),
            ConfigErrorRepr::Utf8 { path, source } => write!(
                formatter,
                "Flux configuration {} is not valid UTF-8: {source}",
                path.display()
            ),
            ConfigErrorRepr::Toml(source) => {
                write!(formatter, "invalid Flux configuration: {source}")
            }
            ConfigErrorRepr::DocumentTooLarge { maximum_bytes } => write!(
                formatter,
                "Flux configuration exceeds the {maximum_bytes}-byte Phase-1 limit"
            ),
            ConfigErrorRepr::UnsupportedSchema { found, supported } => write!(
                formatter,
                "unsupported Flux configuration schema {found}; supported schema is {supported}"
            ),
            ConfigErrorRepr::UnsupportedFailurePolicy { policy } => write!(
                formatter,
                "Flux failure policy {policy:?} requires an explicit safety acknowledgement and is not supported by schema 1"
            ),
            ConfigErrorRepr::ValueOutOfRange {
                field,
                value,
                minimum,
                maximum,
            } => write!(
                formatter,
                "Flux configuration field {field} is {value}; expected {minimum}..={maximum}"
            ),
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            ConfigErrorRepr::Io { source, .. } | ConfigErrorRepr::UnsafeFileType { source, .. } => {
                Some(source)
            }
            ConfigErrorRepr::Utf8 { source, .. } => Some(source),
            ConfigErrorRepr::Toml(source) => Some(source),
            ConfigErrorRepr::DocumentTooLarge { .. }
            | ConfigErrorRepr::UnsupportedSchema { .. }
            | ConfigErrorRepr::UnsupportedFailurePolicy { .. }
            | ConfigErrorRepr::ValueOutOfRange { .. } => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFluxConfig {
    schema: i64,
    daemon: RawDaemonConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDaemonConfig {
    fail_policy: RawFailurePolicy,
    reconcile_debounce_ms: i64,
    event_queue_capacity: i64,
    generation_history: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawFailurePolicy {
    Open,
    Closed,
}
