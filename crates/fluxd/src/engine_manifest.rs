use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::num::{NonZeroU16, NonZeroU32};
use std::path::{Path, PathBuf};
use std::str::Utf8Error;
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::OpenOptionsExt;

use flux_platform::{SingBoxLaunchSpec, SingBoxLauncher, SingBoxReadiness};

use crate::{EngineSpec, EngineSpecError, RestartPolicy};

pub const MAX_ENGINE_MANIFEST_BYTES: usize = 16 * 1024;
/// Phase-1 shell configuration bounds `CORE_TIMEOUT` to 60 seconds. Keeping
/// the Rust-owned lifecycle at the same ceiling prevents a manifest from
/// turning startup or shutdown into an effectively unbounded operation.
pub const MAX_ENGINE_TIMEOUT_MS: u32 = 60_000;

const MANIFEST_HEADER: &str = "FLUX_ENGINE_MANIFEST_V1";
const INTERFACE_NAME_MAX_BYTES: usize = 15;
const MAX_ENGINE_GENERATION: u32 = i32::MAX as u32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineManifestIoOperation {
    InspectPath,
    Open,
    InspectDescriptor,
    Read,
}

impl fmt::Display for EngineManifestIoOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InspectPath => "inspect path",
            Self::Open => "open",
            Self::InspectDescriptor => "inspect descriptor",
            Self::Read => "read",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineManifestErrorKind {
    Io,
    UnsafeFileType,
    DocumentTooLarge,
    InvalidUtf8,
    InvalidHeader,
    BlankLine,
    MalformedLine,
    DuplicateField,
    UnknownField,
    MissingField,
    InvalidValue,
    ForbiddenField,
    EngineSpec,
}

#[derive(Debug)]
pub enum EngineManifestError {
    Io {
        operation: EngineManifestIoOperation,
        path: PathBuf,
        source: io::Error,
    },
    UnsafeFileType {
        path: PathBuf,
        source: Option<io::Error>,
    },
    DocumentTooLarge {
        path: Option<PathBuf>,
        observed: u64,
        limit: usize,
    },
    InvalidUtf8 {
        source: Utf8Error,
    },
    InvalidHeader,
    BlankLine {
        line: usize,
    },
    MalformedLine {
        line: usize,
    },
    DuplicateField {
        field: String,
        first_line: usize,
        duplicate_line: usize,
    },
    UnknownField {
        field: String,
        line: usize,
    },
    MissingField {
        field: &'static str,
    },
    InvalidValue {
        field: &'static str,
        value: String,
        detail: &'static str,
    },
    ForbiddenField {
        field: &'static str,
        mode: &'static str,
    },
    EngineSpec {
        source: EngineSpecError,
    },
}

impl EngineManifestError {
    #[must_use]
    pub const fn kind(&self) -> EngineManifestErrorKind {
        match self {
            Self::Io { .. } => EngineManifestErrorKind::Io,
            Self::UnsafeFileType { .. } => EngineManifestErrorKind::UnsafeFileType,
            Self::DocumentTooLarge { .. } => EngineManifestErrorKind::DocumentTooLarge,
            Self::InvalidUtf8 { .. } => EngineManifestErrorKind::InvalidUtf8,
            Self::InvalidHeader => EngineManifestErrorKind::InvalidHeader,
            Self::BlankLine { .. } => EngineManifestErrorKind::BlankLine,
            Self::MalformedLine { .. } => EngineManifestErrorKind::MalformedLine,
            Self::DuplicateField { .. } => EngineManifestErrorKind::DuplicateField,
            Self::UnknownField { .. } => EngineManifestErrorKind::UnknownField,
            Self::MissingField { .. } => EngineManifestErrorKind::MissingField,
            Self::InvalidValue { .. } => EngineManifestErrorKind::InvalidValue,
            Self::ForbiddenField { .. } => EngineManifestErrorKind::ForbiddenField,
            Self::EngineSpec { .. } => EngineManifestErrorKind::EngineSpec,
        }
    }
}

impl fmt::Display for EngineManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "cannot {operation} Proxy Engine manifest {}: {source}",
                path.display()
            ),
            Self::UnsafeFileType { path, .. } => write!(
                formatter,
                "Proxy Engine manifest {} must be a non-symbolic regular file",
                path.display()
            ),
            Self::DocumentTooLarge {
                path,
                observed,
                limit,
            } => {
                if let Some(path) = path {
                    write!(
                        formatter,
                        "Proxy Engine manifest {} is {observed} bytes, exceeding {limit}",
                        path.display()
                    )
                } else {
                    write!(
                        formatter,
                        "Proxy Engine manifest is {observed} bytes, exceeding {limit}"
                    )
                }
            }
            Self::InvalidUtf8 { .. } => {
                formatter.write_str("Proxy Engine manifest is not valid UTF-8")
            }
            Self::InvalidHeader => write!(
                formatter,
                "Proxy Engine manifest must start with {MANIFEST_HEADER}"
            ),
            Self::BlankLine { line } => {
                write!(formatter, "Proxy Engine manifest line {line} is blank")
            }
            Self::MalformedLine { line } => write!(
                formatter,
                "Proxy Engine manifest line {line} must contain one nonempty key before '='"
            ),
            Self::DuplicateField {
                field,
                first_line,
                duplicate_line,
            } => write!(
                formatter,
                "Proxy Engine manifest field {field:?} is duplicated on line {duplicate_line} (first declared on line {first_line})"
            ),
            Self::UnknownField { field, line } => write!(
                formatter,
                "Proxy Engine manifest field {field:?} on line {line} is unknown"
            ),
            Self::MissingField { field } => {
                write!(
                    formatter,
                    "Proxy Engine manifest is missing field {field:?}"
                )
            }
            Self::InvalidValue {
                field,
                value,
                detail,
            } => write!(
                formatter,
                "Proxy Engine manifest field {field:?} has invalid value {value:?}: {detail}"
            ),
            Self::ForbiddenField { field, mode } => write!(
                formatter,
                "Proxy Engine manifest field {field:?} is forbidden when {mode}"
            ),
            Self::EngineSpec { source } => {
                write!(
                    formatter,
                    "Proxy Engine manifest artifact inspection failed: {source}"
                )
            }
        }
    }
}

impl Error for EngineManifestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. }
            | Self::UnsafeFileType {
                source: Some(source),
                ..
            } => Some(source),
            Self::InvalidUtf8 { source } => Some(source),
            Self::EngineSpec { source } => Some(source),
            Self::UnsafeFileType { source: None, .. }
            | Self::DocumentTooLarge { .. }
            | Self::InvalidHeader
            | Self::BlankLine { .. }
            | Self::MalformedLine { .. }
            | Self::DuplicateField { .. }
            | Self::UnknownField { .. }
            | Self::MissingField { .. }
            | Self::InvalidValue { .. }
            | Self::ForbiddenField { .. } => None,
        }
    }
}

pub struct EngineManifest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EngineManifestSummary {
    generation: NonZeroU32,
    log: PathBuf,
}

impl EngineManifestSummary {
    #[must_use]
    pub(crate) const fn generation(&self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub(crate) fn log(&self) -> &Path {
        &self.log
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedEngineManifest {
    generation: NonZeroU32,
    engine: EngineSpec,
}

impl PreparedEngineManifest {
    #[must_use]
    pub const fn generation(&self) -> NonZeroU32 {
        self.generation
    }

    #[must_use]
    pub const fn engine(&self) -> &EngineSpec {
        &self.engine
    }

    #[must_use]
    pub fn into_engine(self) -> EngineSpec {
        self.engine
    }
}

impl EngineManifest {
    pub fn load(path: &Path) -> Result<EngineSpec, EngineManifestError> {
        Self::load_prepared(path).map(PreparedEngineManifest::into_engine)
    }

    pub fn load_prepared(path: &Path) -> Result<PreparedEngineManifest, EngineManifestError> {
        let document = read_manifest_document(path)?;
        Self::parse_prepared(&document)
    }

    pub(crate) fn load_summary(path: &Path) -> Result<EngineManifestSummary, EngineManifestError> {
        let document = read_manifest_document(path)?;
        Self::parse_summary(&document)
    }

    pub fn parse(document: &[u8]) -> Result<EngineSpec, EngineManifestError> {
        Self::parse_prepared(document).map(PreparedEngineManifest::into_engine)
    }

    pub fn parse_prepared(document: &[u8]) -> Result<PreparedEngineManifest, EngineManifestError> {
        let parsed = parse_manifest_document(document)?;
        let engine = EngineSpec::new(parsed.process, phase_one_restart_policy())
            .map_err(|source| EngineManifestError::EngineSpec { source })?;
        Ok(PreparedEngineManifest {
            generation: parsed.generation,
            engine,
        })
    }

    fn parse_summary(document: &[u8]) -> Result<EngineManifestSummary, EngineManifestError> {
        let parsed = parse_manifest_document(document)?;
        Ok(EngineManifestSummary {
            generation: parsed.generation,
            log: parsed.process.log,
        })
    }
}

struct ParsedEngineManifest {
    generation: NonZeroU32,
    process: SingBoxLaunchSpec,
}

fn read_manifest_document(path: &Path) -> Result<Vec<u8>, EngineManifestError> {
    let mut file = open_manifest(path)?;
    let metadata = file.metadata().map_err(|source| EngineManifestError::Io {
        operation: EngineManifestIoOperation::InspectDescriptor,
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(EngineManifestError::UnsafeFileType {
            path: path.to_path_buf(),
            source: None,
        });
    }
    if metadata.len() > MAX_ENGINE_MANIFEST_BYTES as u64 {
        return Err(EngineManifestError::DocumentTooLarge {
            path: Some(path.to_path_buf()),
            observed: metadata.len(),
            limit: MAX_ENGINE_MANIFEST_BYTES,
        });
    }

    let mut document = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_ENGINE_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut document)
        .map_err(|source| EngineManifestError::Io {
            operation: EngineManifestIoOperation::Read,
            path: path.to_path_buf(),
            source,
        })?;
    if document.len() > MAX_ENGINE_MANIFEST_BYTES {
        return Err(EngineManifestError::DocumentTooLarge {
            path: Some(path.to_path_buf()),
            observed: document.len() as u64,
            limit: MAX_ENGINE_MANIFEST_BYTES,
        });
    }
    Ok(document)
}

fn parse_manifest_document(document: &[u8]) -> Result<ParsedEngineManifest, EngineManifestError> {
    if document.len() > MAX_ENGINE_MANIFEST_BYTES {
        return Err(EngineManifestError::DocumentTooLarge {
            path: None,
            observed: document.len() as u64,
            limit: MAX_ENGINE_MANIFEST_BYTES,
        });
    }
    let document = std::str::from_utf8(document)
        .map_err(|source| EngineManifestError::InvalidUtf8 { source })?;
    let document = document.strip_suffix('\n').unwrap_or(document);
    let mut lines = document.split('\n');
    if lines.next() != Some(MANIFEST_HEADER) {
        return Err(EngineManifestError::InvalidHeader);
    }

    let mut fields = BTreeMap::new();
    for (offset, line) in lines.enumerate() {
        let line_number = offset + 2;
        if line.is_empty() {
            return Err(EngineManifestError::BlankLine { line: line_number });
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(EngineManifestError::MalformedLine { line: line_number });
        };
        if key.is_empty() {
            return Err(EngineManifestError::MalformedLine { line: line_number });
        }
        if !is_known_field(key) {
            return Err(EngineManifestError::UnknownField {
                field: key.to_owned(),
                line: line_number,
            });
        }
        if let Some(previous) = fields.insert(
            key,
            ManifestField {
                value,
                line: line_number,
            },
        ) {
            return Err(EngineManifestError::DuplicateField {
                field: key.to_owned(),
                first_line: previous.line,
                duplicate_line: line_number,
            });
        }
    }

    let generation = parse_generation(required(&fields, "generation")?)?;
    let binary = parse_absolute_path("binary", required(&fields, "binary")?)?;
    let config = parse_absolute_path("config", required(&fields, "config")?)?;
    let working_directory =
        parse_absolute_path("working_directory", required(&fields, "working_directory")?)?;
    let log = parse_absolute_path("log", required(&fields, "log")?)?;
    let launcher = parse_launcher(&fields)?;
    let readiness = parse_readiness(&fields)?;
    let startup_timeout = parse_timeout(
        "startup_timeout_ms",
        required(&fields, "startup_timeout_ms")?,
    )?;
    let stop_timeout = parse_timeout("stop_timeout_ms", required(&fields, "stop_timeout_ms")?)?;

    let process = SingBoxLaunchSpec {
        binary,
        config,
        working_directory,
        log,
        launcher,
        readiness,
        startup_timeout,
        stop_timeout,
    };
    Ok(ParsedEngineManifest {
        generation,
        process,
    })
}

#[derive(Clone, Copy)]
struct ManifestField<'a> {
    value: &'a str,
    line: usize,
}

fn required<'a>(
    fields: &BTreeMap<&str, ManifestField<'a>>,
    field: &'static str,
) -> Result<&'a str, EngineManifestError> {
    fields
        .get(field)
        .map(|entry| entry.value)
        .ok_or(EngineManifestError::MissingField { field })
}

fn is_known_field(field: &str) -> bool {
    matches!(
        field,
        "generation"
            | "binary"
            | "config"
            | "working_directory"
            | "log"
            | "launcher"
            | "busybox"
            | "identity"
            | "readiness"
            | "listener_port"
            | "tun_interface"
            | "startup_timeout_ms"
            | "stop_timeout_ms"
    )
}

fn parse_generation(value: &str) -> Result<NonZeroU32, EngineManifestError> {
    let generation = if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        None
    } else {
        value
            .parse::<u32>()
            .ok()
            .filter(|value| (1..=MAX_ENGINE_GENERATION).contains(value))
            .and_then(NonZeroU32::new)
    };
    generation
        .ok_or_else(|| invalid_value("generation", value, "expected an integer in 1..=2147483647"))
}

fn parse_absolute_path(field: &'static str, value: &str) -> Result<PathBuf, EngineManifestError> {
    let path = PathBuf::from(value);
    if value.is_empty() || value.as_bytes().contains(&0) || !path.is_absolute() {
        Err(invalid_value(
            field,
            value,
            "expected a nonempty absolute path without NUL bytes",
        ))
    } else {
        Ok(path)
    }
}

fn parse_launcher(
    fields: &BTreeMap<&str, ManifestField<'_>>,
) -> Result<SingBoxLauncher, EngineManifestError> {
    match required(fields, "launcher")? {
        "direct" => {
            forbid(fields, "busybox", "launcher=direct")?;
            forbid(fields, "identity", "launcher=direct")?;
            Ok(SingBoxLauncher::Direct)
        }
        "busybox-setuidgid" => {
            let busybox = parse_absolute_path("busybox", required(fields, "busybox")?)?;
            let identity = required(fields, "identity")?;
            if !valid_setuidgid_identity(identity) {
                return Err(invalid_value(
                    "identity",
                    identity,
                    "expected USER:GROUP using decimal IDs or safe ASCII names",
                ));
            }
            Ok(SingBoxLauncher::BusyBoxSetuidgid {
                busybox,
                identity: OsString::from(identity),
            })
        }
        value => Err(invalid_value(
            "launcher",
            value,
            "expected direct or busybox-setuidgid",
        )),
    }
}

fn parse_readiness(
    fields: &BTreeMap<&str, ManifestField<'_>>,
) -> Result<SingBoxReadiness, EngineManifestError> {
    match required(fields, "readiness")? {
        "listener" => {
            forbid(fields, "tun_interface", "readiness=listener")?;
            let port = parse_port(required(fields, "listener_port")?)?;
            Ok(SingBoxReadiness::Listener { port })
        }
        "tun" => {
            forbid(fields, "listener_port", "readiness=tun")?;
            let name = required(fields, "tun_interface")?;
            if !valid_interface_name(name) {
                return Err(invalid_value(
                    "tun_interface",
                    name,
                    "expected a safe Linux interface name of at most 15 ASCII bytes",
                ));
            }
            Ok(SingBoxReadiness::TunInterface {
                name: name.to_owned(),
            })
        }
        value => Err(invalid_value(
            "readiness",
            value,
            "expected listener or tun",
        )),
    }
}

fn parse_port(value: &str) -> Result<NonZeroU16, EngineManifestError> {
    let port = if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        None
    } else {
        value.parse::<u16>().ok().and_then(NonZeroU16::new)
    };
    port.ok_or_else(|| invalid_value("listener_port", value, "expected an integer in 1..=65535"))
}

fn parse_timeout(field: &'static str, value: &str) -> Result<Duration, EngineManifestError> {
    let milliseconds = if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        None
    } else {
        value
            .parse::<u32>()
            .ok()
            .filter(|value| (1..=MAX_ENGINE_TIMEOUT_MS).contains(value))
    };
    milliseconds
        .map(|value| Duration::from_millis(u64::from(value)))
        .ok_or_else(|| {
            invalid_value(
                field,
                value,
                "expected an integer in 1..=60000 milliseconds",
            )
        })
}

fn forbid(
    fields: &BTreeMap<&str, ManifestField<'_>>,
    field: &'static str,
    mode: &'static str,
) -> Result<(), EngineManifestError> {
    if fields.contains_key(field) {
        Err(EngineManifestError::ForbiddenField { field, mode })
    } else {
        Ok(())
    }
}

fn valid_setuidgid_identity(identity: &str) -> bool {
    let Some((user, group)) = identity.split_once(':') else {
        return false;
    };
    !group.contains(':') && valid_identity_component(user) && valid_identity_component(group)
}

fn valid_identity_component(identity: &str) -> bool {
    if identity.is_empty() || identity.len() > 255 {
        return false;
    }
    if identity.bytes().all(|byte| byte.is_ascii_digit()) {
        return identity.parse::<u32>().is_ok();
    }
    let mut bytes = identity.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_interface_name(name: &str) -> bool {
    if name.is_empty() || name.len() > INTERFACE_NAME_MAX_BYTES || name == "." || name == ".." {
        return false;
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn invalid_value(field: &'static str, value: &str, detail: &'static str) -> EngineManifestError {
    EngineManifestError::InvalidValue {
        field,
        value: value.to_owned(),
        detail,
    }
}

fn phase_one_restart_policy() -> RestartPolicy {
    let Ok(policy) = RestartPolicy::new(
        3,
        Duration::from_secs(60),
        Duration::from_secs(1),
        Duration::from_secs(30),
        Duration::from_secs(30),
    ) else {
        unreachable!("the fixed Phase 1 restart policy is valid")
    };
    policy
}

fn open_manifest(path: &Path) -> Result<File, EngineManifestError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| EngineManifestError::Io {
        operation: EngineManifestIoOperation::InspectPath,
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(EngineManifestError::UnsafeFileType {
            path: path.to_path_buf(),
            source: None,
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    options.open(path).map_err(|source| {
        if is_symbolic_link_open_error(&source) {
            EngineManifestError::UnsafeFileType {
                path: path.to_path_buf(),
                source: Some(source),
            }
        } else {
            EngineManifestError::Io {
                operation: EngineManifestIoOperation::Open,
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn is_symbolic_link_open_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn is_symbolic_link_open_error(_error: &io::Error) -> bool {
    false
}
