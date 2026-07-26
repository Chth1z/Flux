use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime_layout::RuntimeLayout;

pub const MAX_RUNTIME_LOG_RECORD_BYTES: usize = 4 * 1024;
pub const MAX_RUNTIME_LOG_FILE_BYTES: u64 = 1024 * 1024;

const DAEMON_LOG_NAME: &str = "fluxd.log";
const RUNTIME_LOG_NAME: &str = "flux.log";
const LOG_FILE_MODE: libc::mode_t = 0o600;

static RUNTIME_LOGS: OnceLock<Mutex<Option<Arc<RuntimeLogs>>>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogSeverity {
    Info,
    Warn,
    Error,
}

impl LogSeverity {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLogErrorKind {
    AlreadyInstalled,
    Symlink,
    UnexpectedFileType,
    UnsafeMetadata,
    Synchronization,
    Io,
}

#[derive(Debug)]
pub enum RuntimeLogError {
    AlreadyInstalled,
    Symlink(PathBuf),
    UnexpectedFileType(PathBuf),
    UnsafeMetadata {
        path: PathBuf,
        reason: &'static str,
    },
    Synchronization(&'static str),
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl RuntimeLogError {
    #[must_use]
    pub const fn kind(&self) -> RuntimeLogErrorKind {
        match self {
            Self::AlreadyInstalled => RuntimeLogErrorKind::AlreadyInstalled,
            Self::Symlink(_) => RuntimeLogErrorKind::Symlink,
            Self::UnexpectedFileType(_) => RuntimeLogErrorKind::UnexpectedFileType,
            Self::UnsafeMetadata { .. } => RuntimeLogErrorKind::UnsafeMetadata,
            Self::Synchronization(_) => RuntimeLogErrorKind::Synchronization,
            Self::Io { .. } => RuntimeLogErrorKind::Io,
        }
    }

    fn io(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_owned(),
            source,
        }
    }
}

impl fmt::Display for RuntimeLogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInstalled => formatter.write_str("runtime logs are already installed"),
            Self::Symlink(path) => write!(
                formatter,
                "runtime log path must not be a symbolic link: {}",
                path.display()
            ),
            Self::UnexpectedFileType(path) => write!(
                formatter,
                "runtime log path is not a regular file: {}",
                path.display()
            ),
            Self::UnsafeMetadata { path, reason } => write!(
                formatter,
                "runtime log path has unsafe metadata ({}): {reason}",
                path.display()
            ),
            Self::Synchronization(reason) => {
                write!(formatter, "runtime log synchronization failed: {reason}")
            }
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl Error for RuntimeLogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::AlreadyInstalled
            | Self::Symlink(_)
            | Self::UnexpectedFileType(_)
            | Self::UnsafeMetadata { .. }
            | Self::Synchronization(_) => None,
        }
    }
}

struct RuntimeLogs {
    daemon: Mutex<BoundedLogSink>,
    runtime: Mutex<BoundedLogSink>,
}

impl RuntimeLogs {
    fn open(layout: &RuntimeLayout) -> Result<Self, RuntimeLogError> {
        let daemon = BoundedLogSink::open(
            layout.clone_run_directory().map_err(|source| {
                RuntimeLogError::io(
                    "duplicate daemon log directory descriptor",
                    layout.run_path(),
                    io::Error::other(source),
                )
            })?,
            layout.run_path(),
            DAEMON_LOG_NAME,
            MAX_RUNTIME_LOG_FILE_BYTES,
        )?;
        let runtime = BoundedLogSink::open(
            layout.clone_run_directory().map_err(|source| {
                RuntimeLogError::io(
                    "duplicate runtime log directory descriptor",
                    layout.run_path(),
                    io::Error::other(source),
                )
            })?,
            layout.run_path(),
            RUNTIME_LOG_NAME,
            MAX_RUNTIME_LOG_FILE_BYTES,
        )?;
        Ok(Self {
            daemon: Mutex::new(daemon),
            runtime: Mutex::new(runtime),
        })
    }

    fn write(
        &self,
        stream: RuntimeLogStream,
        severity: LogSeverity,
        component: &'static str,
        generation: Option<u64>,
        message: fmt::Arguments<'_>,
    ) -> Result<(), RuntimeLogError> {
        let record = encode_record(severity, component, generation, &message.to_string());
        let sink = match stream {
            RuntimeLogStream::Daemon => &self.daemon,
            RuntimeLogStream::Runtime => &self.runtime,
        };
        sink.lock()
            .map_err(|_| RuntimeLogError::Synchronization("runtime log lock is poisoned"))?
            .write_record(&record)
    }
}

#[derive(Clone, Copy)]
enum RuntimeLogStream {
    Daemon,
    Runtime,
}

pub(crate) struct RuntimeLogInstallation {
    logs: Arc<RuntimeLogs>,
}

impl Drop for RuntimeLogInstallation {
    fn drop(&mut self) {
        let Ok(mut installed) = runtime_log_registry().lock() else {
            return;
        };
        if installed
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.logs))
        {
            *installed = None;
        }
    }
}

pub(crate) fn install(layout: &RuntimeLayout) -> Result<RuntimeLogInstallation, RuntimeLogError> {
    let logs = Arc::new(RuntimeLogs::open(layout)?);
    let mut installed = runtime_log_registry()
        .lock()
        .map_err(|_| RuntimeLogError::Synchronization("installation lock is poisoned"))?;
    if installed.is_some() {
        return Err(RuntimeLogError::AlreadyInstalled);
    }
    *installed = Some(Arc::clone(&logs));
    Ok(RuntimeLogInstallation { logs })
}

pub(crate) fn daemon_log(
    severity: LogSeverity,
    component: &'static str,
    message: fmt::Arguments<'_>,
) {
    write_global(RuntimeLogStream::Daemon, severity, component, None, message);
}

pub(crate) fn runtime_log(
    severity: LogSeverity,
    component: &'static str,
    generation: Option<u64>,
    message: fmt::Arguments<'_>,
) {
    write_global(
        RuntimeLogStream::Runtime,
        severity,
        component,
        generation,
        message,
    );
}

fn write_global(
    stream: RuntimeLogStream,
    severity: LogSeverity,
    component: &'static str,
    generation: Option<u64>,
    message: fmt::Arguments<'_>,
) {
    let rendered = message.to_string();
    let fallback = || redact_message(&rendered);
    let logs = match runtime_log_registry().lock() {
        Ok(installed) => installed.clone(),
        Err(_) => {
            eprintln!("fluxd: {}", fallback());
            return;
        }
    };
    let Some(logs) = logs else {
        eprintln!("fluxd: {}", fallback());
        return;
    };
    if let Err(error) = logs.write(
        stream,
        severity,
        component,
        generation,
        format_args!("{rendered}"),
    ) {
        eprintln!(
            "fluxd: cannot write bounded runtime log: {error}; {}",
            fallback()
        );
    }
}

fn runtime_log_registry() -> &'static Mutex<Option<Arc<RuntimeLogs>>> {
    RUNTIME_LOGS.get_or_init(|| Mutex::new(None))
}

struct BoundedLogSink {
    directory: File,
    name: CString,
    predecessor: CString,
    path: PathBuf,
    predecessor_path: PathBuf,
    maximum_file_bytes: u64,
}

impl BoundedLogSink {
    fn open(
        directory: File,
        directory_path: &Path,
        name: &str,
        maximum_file_bytes: u64,
    ) -> Result<Self, RuntimeLogError> {
        let name = CString::new(name).expect("fixed runtime log name contains no NUL");
        let predecessor_name = format!("{name}.1", name = name.to_string_lossy());
        let predecessor =
            CString::new(predecessor_name.as_bytes()).expect("fixed predecessor contains no NUL");
        let path = directory_path.join(name.to_string_lossy().as_ref());
        let mut sink = Self {
            directory,
            name,
            predecessor,
            path,
            predecessor_path: directory_path.join(predecessor_name),
            maximum_file_bytes,
        };
        sink.normalize_predecessor()?;
        let file = sink.open_current()?;
        if file_metadata(&file, &sink.path)?.len() > maximum_file_bytes {
            drop(file);
            sink.remove_entry(&sink.name, &sink.path, "remove oversized runtime log")?;
            sink.remove_entry(
                &sink.predecessor,
                &sink.predecessor_path,
                "remove predecessor of oversized runtime log",
            )?;
            let _ = sink.open_current()?;
            sink.directory.sync_all().map_err(|source| {
                RuntimeLogError::io("sync runtime log directory", &sink.path, source)
            })?;
        }
        Ok(sink)
    }

    fn write_record(&mut self, record: &[u8]) -> Result<(), RuntimeLogError> {
        debug_assert!(record.len() <= MAX_RUNTIME_LOG_RECORD_BYTES);
        let mut file = self.open_current()?;
        let length = file_metadata(&file, &self.path)?.len();
        let record_length = u64::try_from(record.len()).unwrap_or(u64::MAX);
        if length.saturating_add(record_length) > self.maximum_file_bytes {
            drop(file);
            self.rotate()?;
            file = self.open_current()?;
        }
        file.write_all(record)
            .and_then(|()| file.flush())
            .map_err(|source| RuntimeLogError::io("append bounded runtime log", &self.path, source))
    }

    fn open_current(&self) -> Result<File, RuntimeLogError> {
        match entry_kind(self.directory.as_raw_fd(), &self.name)
            .map_err(|source| RuntimeLogError::io("inspect runtime log", &self.path, source))?
        {
            Some(EntryKind::Symlink) => return Err(RuntimeLogError::Symlink(self.path.clone())),
            Some(EntryKind::Directory | EntryKind::Other) => {
                return Err(RuntimeLogError::UnexpectedFileType(self.path.clone()));
            }
            Some(EntryKind::Regular) | None => {}
        }
        // SAFETY: `directory` is retained, `name` is one fixed NUL-terminated component, and
        // successful `openat` returns a new descriptor owned below.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_WRONLY
                    | libc::O_APPEND
                    | libc::O_CREAT
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW,
                LOG_FILE_MODE,
            )
        };
        if descriptor < 0 {
            let source = io::Error::last_os_error();
            return if source.raw_os_error() == Some(libc::ELOOP) {
                Err(RuntimeLogError::Symlink(self.path.clone()))
            } else {
                Err(RuntimeLogError::io(
                    "open bounded runtime log",
                    &self.path,
                    source,
                ))
            };
        }
        // SAFETY: successful `openat` returned one new owned descriptor.
        let file = unsafe { File::from_raw_fd(descriptor) };
        require_secure_file(&file, &self.path)?;
        Ok(file)
    }

    fn rotate(&mut self) -> Result<(), RuntimeLogError> {
        self.remove_entry(
            &self.predecessor,
            &self.predecessor_path,
            "remove prior runtime log predecessor",
        )?;
        // SAFETY: both names are fixed NUL-terminated components in the same retained directory.
        let result = unsafe {
            libc::renameat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                self.directory.as_raw_fd(),
                self.predecessor.as_ptr(),
            )
        };
        if result != 0 {
            let source = io::Error::last_os_error();
            if source.kind() != io::ErrorKind::NotFound {
                return Err(RuntimeLogError::io(
                    "rotate bounded runtime log",
                    &self.path,
                    source,
                ));
            }
        }
        self.directory.sync_all().map_err(|source| {
            RuntimeLogError::io("sync rotated runtime log directory", &self.path, source)
        })
    }

    fn normalize_predecessor(&mut self) -> Result<(), RuntimeLogError> {
        let kind = entry_kind(self.directory.as_raw_fd(), &self.predecessor).map_err(|source| {
            RuntimeLogError::io(
                "inspect runtime log predecessor",
                &self.predecessor_path,
                source,
            )
        })?;
        match kind {
            Some(EntryKind::Regular) => {
                let file = open_existing_regular(
                    self.directory.as_raw_fd(),
                    &self.predecessor,
                    &self.predecessor_path,
                )?;
                if file_metadata(&file, &self.predecessor_path)?.len() <= self.maximum_file_bytes {
                    return Ok(());
                }
            }
            None => return Ok(()),
            Some(EntryKind::Directory | EntryKind::Other) => {
                return Err(RuntimeLogError::UnexpectedFileType(
                    self.predecessor_path.clone(),
                ));
            }
            Some(EntryKind::Symlink) => {}
        }
        self.remove_entry(
            &self.predecessor,
            &self.predecessor_path,
            "remove unsafe runtime log predecessor",
        )
    }

    fn remove_entry(
        &self,
        name: &CString,
        path: &Path,
        operation: &'static str,
    ) -> Result<(), RuntimeLogError> {
        // SAFETY: `directory` is retained and `name` is one fixed NUL-terminated component.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(RuntimeLogError::io(operation, path, source))
            }
        }
    }
}

fn open_existing_regular(
    directory: RawFd,
    name: &CString,
    path: &Path,
) -> Result<File, RuntimeLogError> {
    // SAFETY: `directory` is open and `name` is one NUL-terminated component.
    let descriptor = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(RuntimeLogError::io(
            "open runtime log predecessor",
            path,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful `openat` returned one new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    require_secure_file(&file, path)?;
    Ok(file)
}

fn require_secure_file(file: &File, path: &Path) -> Result<(), RuntimeLogError> {
    let metadata = file_metadata(file, path)?;
    if !metadata.is_file() {
        return Err(RuntimeLogError::UnexpectedFileType(path.to_owned()));
    }
    // SAFETY: `geteuid` has no preconditions and does not retain state.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(RuntimeLogError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "log is not owned by the daemon effective user",
        });
    }
    if metadata.mode() & 0o777 != LOG_FILE_MODE {
        // SAFETY: `file` owns a valid regular-file descriptor and `fchmod` does not retain it.
        if unsafe { libc::fchmod(file.as_raw_fd(), LOG_FILE_MODE) } != 0 {
            return Err(RuntimeLogError::io(
                "set runtime log mode",
                path,
                io::Error::last_os_error(),
            ));
        }
    }
    Ok(())
}

fn file_metadata(file: &File, path: &Path) -> Result<std::fs::Metadata, RuntimeLogError> {
    file.metadata()
        .map_err(|source| RuntimeLogError::io("inspect opened runtime log", path, source))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

fn entry_kind(directory: RawFd, name: &CString) -> io::Result<Option<EntryKind>> {
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `directory` is open, `name` is NUL-terminated, and `metadata` is writable for one
    // complete `stat` value. The flag prevents symlink traversal.
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the complete value.
        let metadata = unsafe { metadata.assume_init() };
        let file_type = metadata.st_mode & libc::S_IFMT;
        Ok(Some(if file_type == libc::S_IFREG {
            EntryKind::Regular
        } else if file_type == libc::S_IFDIR {
            EntryKind::Directory
        } else if file_type == libc::S_IFLNK {
            EntryKind::Symlink
        } else {
            EntryKind::Other
        }))
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(source)
        }
    }
}

fn encode_record(
    severity: LogSeverity,
    component: &str,
    generation: Option<u64>,
    message: &str,
) -> Vec<u8> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let component = if component
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        component
    } else {
        "unknown"
    };
    let generation = generation.map_or_else(|| "-".to_owned(), |value| value.to_string());
    let prefix = format!(
        "timestamp_unix_ms={timestamp} severity={} component={component} generation={generation} message=",
        severity.as_str()
    );
    let sanitized = redact_message(message);
    let available = MAX_RUNTIME_LOG_RECORD_BYTES
        .saturating_sub(prefix.len())
        .saturating_sub(1);
    let mut record = prefix;
    if sanitized.len() <= available {
        record.push_str(&sanitized);
    } else {
        let marker = "...";
        let mut end = available.saturating_sub(marker.len());
        while !sanitized.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        record.push_str(&sanitized[..end]);
        record.push_str(marker);
    }
    record.push('\n');
    record.into_bytes()
}

fn redact_message(message: &str) -> String {
    message
        .split_whitespace()
        .map(redact_word)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_word(word: &str) -> String {
    const SENSITIVE_ASSIGNMENTS: [&str; 6] = [
        "token=",
        "password=",
        "secret=",
        "authorization=",
        "cookie=",
        "subscription_url=",
    ];
    let lower = word.to_ascii_lowercase();
    let scheme_end = word.find("://");
    if let Some(index) = SENSITIVE_ASSIGNMENTS
        .into_iter()
        .filter_map(|marker| lower.find(marker).map(|index| (index, marker.len())))
        .filter(|(index, _)| scheme_end.is_none_or(|scheme_end| *index < scheme_end))
        .min_by_key(|(index, _)| *index)
    {
        let end = index.0 + index.1;
        return format!("{}[REDACTED]", &word[..end]);
    }
    let Some(scheme_end) = scheme_end else {
        return word.to_owned();
    };
    let authority_start = scheme_end + 3;
    let authority_end = word[authority_start..]
        .find(['/', '?', '#'])
        .map_or(word.len(), |offset| authority_start + offset);
    let mut redacted = String::with_capacity(word.len());
    redacted.push_str(&word[..authority_start]);
    let authority = &word[authority_start..authority_end];
    if let Some(at) = authority.rfind('@') {
        redacted.push_str("[REDACTED]@");
        redacted.push_str(&authority[at + 1..]);
    } else {
        redacted.push_str(authority);
    }
    let suffix = &word[authority_end..];
    let sensitive_suffix = suffix.find(['?', '#']);
    if let Some(index) = sensitive_suffix {
        redacted.push_str(&suffix[..index]);
        redacted.push_str("?[REDACTED]");
    } else {
        redacted.push_str(suffix);
    }
    redacted
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn sink(directory: &tempfile::TempDir, limit: u64) -> BoundedLogSink {
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");
        BoundedLogSink::open(
            layout.clone_run_directory().expect("clone run directory"),
            layout.run_path(),
            DAEMON_LOG_NAME,
            limit,
        )
        .expect("open bounded log sink")
    }

    #[test]
    fn records_are_structured_bounded_and_redacted() {
        let secret = "https://alice:password@example.invalid/sub?token=topsecret";
        let record = encode_record(
            LogSeverity::Warn,
            "subscription",
            Some(42),
            &format!("refresh failed url={secret} authorization=BearerSecret\nnext"),
        );
        let text = String::from_utf8(record).expect("UTF-8 record");

        assert!(text.contains("severity=warn"));
        assert!(text.contains("component=subscription"));
        assert!(text.contains("generation=42"));
        assert!(text.contains("[REDACTED]@example.invalid/sub?[REDACTED]"));
        assert!(text.contains("authorization=[REDACTED]"));
        assert!(!text.contains("alice"));
        assert!(!text.contains("password"));
        assert!(!text.contains("topsecret"));
        assert!(!text.contains("BearerSecret"));
        assert_eq!(text.lines().count(), 1);

        let oversized = encode_record(LogSeverity::Error, "runtime", None, &"x".repeat(16_384));
        assert_eq!(oversized.len(), MAX_RUNTIME_LOG_RECORD_BYTES);
        assert!(oversized.ends_with(b"...\n"));
    }

    #[test]
    fn rotation_keeps_one_bounded_predecessor() {
        let directory = tempfile::tempdir().expect("runtime log fixture");
        let mut sink = sink(&directory, 220);
        let record = encode_record(LogSeverity::Info, "daemon", None, "bounded record");

        for _ in 0..12 {
            sink.write_record(&record).expect("append and rotate log");
        }

        let root = directory.path().join("flux/run");
        assert!(std::fs::metadata(root.join(DAEMON_LOG_NAME)).unwrap().len() <= 220);
        assert!(std::fs::metadata(root.join("fluxd.log.1")).unwrap().len() <= 220);
        assert!(!root.join("fluxd.log.2").exists());
    }

    #[test]
    fn current_log_symlinks_are_rejected_without_touching_the_target() {
        let directory = tempfile::tempdir().expect("runtime log fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");
        let target = directory.path().join("target");
        std::fs::write(&target, "secret\n").expect("write symlink target");
        symlink(&target, layout.run_path().join(DAEMON_LOG_NAME)).expect("link runtime log");

        let error = match BoundedLogSink::open(
            layout.clone_run_directory().expect("clone run directory"),
            layout.run_path(),
            DAEMON_LOG_NAME,
            220,
        ) {
            Ok(_) => panic!("runtime log symlink must fail"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), RuntimeLogErrorKind::Symlink);
        assert_eq!(std::fs::read_to_string(target).unwrap(), "secret\n");
    }

    #[test]
    fn current_log_replacement_is_revalidated_before_every_append() {
        let directory = tempfile::tempdir().expect("runtime log fixture");
        let mut sink = sink(&directory, 220);
        let current = directory.path().join("flux/run").join(DAEMON_LOG_NAME);
        let target = directory.path().join("target");
        std::fs::write(&target, "secret\n").expect("write replacement target");
        std::fs::remove_file(&current).expect("remove admitted current log");
        symlink(&target, &current).expect("replace current log with symlink");

        let error = sink
            .write_record(&encode_record(
                LogSeverity::Error,
                "daemon",
                None,
                "must not follow replacement",
            ))
            .expect_err("replacement symlink must fail closed");

        assert_eq!(error.kind(), RuntimeLogErrorKind::Symlink);
        assert_eq!(std::fs::read_to_string(target).unwrap(), "secret\n");
    }
}
