use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use flux_core::{CapabilityProfileSource, ObservationKind};
use flux_platform::{
    NativeCaptureConvergedState, NativeCaptureConvergence, NativeCaptureDesired,
    NativeXtablesAndroidRuntime, SystemCapabilityProfileSource,
};

use crate::daemon::DaemonOptions;
use crate::runtime_layout::{RuntimeLayout, RuntimeLayoutError};

pub const OFFLINE_CLEANUP_BUSY_EXIT: i32 = 75;
const EXIT_SUCCESS: i32 = 0;
const EXIT_RUNTIME_ERROR: i32 = 1;
const EXIT_USAGE: i32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonLeaseErrorKind {
    Busy,
    UnsafePath,
    Symlink,
    UnexpectedFileType,
    UnsafeMetadata,
    Io,
}

#[derive(Debug)]
pub enum DaemonLeaseError {
    Busy(PathBuf),
    UnsafePath(PathBuf),
    Symlink(PathBuf),
    UnexpectedFileType(PathBuf),
    UnsafeMetadata {
        path: PathBuf,
        reason: &'static str,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl DaemonLeaseError {
    #[must_use]
    pub const fn kind(&self) -> DaemonLeaseErrorKind {
        match self {
            Self::Busy(_) => DaemonLeaseErrorKind::Busy,
            Self::UnsafePath(_) => DaemonLeaseErrorKind::UnsafePath,
            Self::Symlink(_) => DaemonLeaseErrorKind::Symlink,
            Self::UnexpectedFileType(_) => DaemonLeaseErrorKind::UnexpectedFileType,
            Self::UnsafeMetadata { .. } => DaemonLeaseErrorKind::UnsafeMetadata,
            Self::Io { .. } => DaemonLeaseErrorKind::Io,
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

impl fmt::Display for DaemonLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy(path) => write!(
                formatter,
                "daemon lease {} is held by an active or starting daemon",
                path.display()
            ),
            Self::UnsafePath(path) => {
                write!(formatter, "daemon lease path is unsafe: {}", path.display())
            }
            Self::Symlink(path) => write!(
                formatter,
                "daemon lease path must not traverse or name a symbolic link: {}",
                path.display()
            ),
            Self::UnexpectedFileType(path) => write!(
                formatter,
                "daemon lease path is not a regular file or has a non-directory ancestor: {}",
                path.display()
            ),
            Self::UnsafeMetadata { path, reason } => write!(
                formatter,
                "daemon lease path has unsafe metadata ({}): {reason}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl Error for DaemonLeaseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Busy(_)
            | Self::UnsafePath(_)
            | Self::Symlink(_)
            | Self::UnexpectedFileType(_)
            | Self::UnsafeMetadata { .. } => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct DaemonLease {
    _file: File,
}

impl DaemonLease {
    pub(crate) fn acquire(path: &Path) -> Result<Self, DaemonLeaseError> {
        let parent = open_parent_directory(path)?;
        require_secure_parent(&parent.directory, &parent.path)?;
        let file = open_lease_file(&parent, path)?;
        require_secure_lease_file(&file, path)?;
        try_lock_exclusive(&file).map_err(|source| {
            if is_lock_busy(&source) {
                DaemonLeaseError::Busy(path.to_owned())
            } else {
                DaemonLeaseError::io("lock daemon lease", path, source)
            }
        })?;
        Ok(Self { _file: file })
    }
}

impl Drop for DaemonLease {
    fn drop(&mut self) {
        // A concurrent `fork` can briefly duplicate this open-file description before `exec`
        // applies `O_CLOEXEC`. Unlock explicitly so that duplicate cannot extend lease lifetime.
        // SAFETY: `_file` owns a valid descriptor for the complete duration of this call.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineCleanupDisposition {
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineCleanupReport {
    disposition: OfflineCleanupDisposition,
}

/// Proof returned only after recovery has verified that managed runtime state is cleanly absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedCleanAbsence(());

pub(crate) trait OfflineRecovery {
    type Error: Error + Send + Sync + 'static;

    fn recover_stopped(&mut self) -> Result<VerifiedCleanAbsence, Self::Error>;
}

/// Process-free offline recovery for the native composition.
///
/// Recovery is deliberately followed by an explicit stopped convergence even when observation is
/// already clean, then one final recovery proof retires the terminal cleanup journal. Only the
/// convergence implementation can interpret and remove stale/foreign durable state, and only exact
/// clean absence produces the cleanup proof.
pub(crate) struct NativeOfflineRecovery<C>
where
    C: NativeCaptureConvergence,
{
    convergence: C,
}

impl<C> NativeOfflineRecovery<C>
where
    C: NativeCaptureConvergence,
{
    #[must_use]
    pub(crate) const fn new(convergence: C) -> Self {
        Self { convergence }
    }
}

impl<C> OfflineRecovery for NativeOfflineRecovery<C>
where
    C: NativeCaptureConvergence,
{
    type Error = NativeOfflineRecoveryError;

    fn recover_stopped(&mut self) -> Result<VerifiedCleanAbsence, Self::Error> {
        self.convergence
            .recover()
            .map_err(|source| NativeOfflineRecoveryError::Recover(Box::new(source)))?;
        let stopped = self
            .convergence
            .converge(NativeCaptureDesired::Stopped)
            .map_err(|source| NativeOfflineRecoveryError::Stop(Box::new(source)))?;
        if !matches!(stopped.state(), NativeCaptureConvergedState::CleanAbsent) {
            return Err(NativeOfflineRecoveryError::NotCleanAbsent);
        }
        let settled = self
            .convergence
            .recover()
            .map_err(|source| NativeOfflineRecoveryError::Recover(Box::new(source)))?;
        if !matches!(settled.state(), NativeCaptureConvergedState::CleanAbsent) {
            return Err(NativeOfflineRecoveryError::NotCleanAbsent);
        }
        Ok(VerifiedCleanAbsence(()))
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeOfflineRecoveryErrorKind {
    Recover,
    Stop,
    NotCleanAbsent,
}

#[derive(Debug)]
pub(crate) enum NativeOfflineRecoveryError {
    Recover(Box<dyn Error + Send + Sync>),
    Stop(Box<dyn Error + Send + Sync>),
    NotCleanAbsent,
}

impl NativeOfflineRecoveryError {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn kind(&self) -> NativeOfflineRecoveryErrorKind {
        match self {
            Self::Recover(_) => NativeOfflineRecoveryErrorKind::Recover,
            Self::Stop(_) => NativeOfflineRecoveryErrorKind::Stop,
            Self::NotCleanAbsent => NativeOfflineRecoveryErrorKind::NotCleanAbsent,
        }
    }
}

impl fmt::Display for NativeOfflineRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Recover(source) => write!(formatter, "recover native capture: {source}"),
            Self::Stop(source) => write!(formatter, "converge native capture stopped: {source}"),
            Self::NotCleanAbsent => {
                formatter.write_str("native stopped convergence did not verify exact clean absence")
            }
        }
    }
}

impl Error for NativeOfflineRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Recover(source) | Self::Stop(source) => Some(source.as_ref()),
            Self::NotCleanAbsent => None,
        }
    }
}

impl OfflineCleanupReport {
    #[must_use]
    pub const fn disposition(self) -> OfflineCleanupDisposition {
        self.disposition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineCleanupErrorKind {
    Busy,
    RuntimeLayout,
    Lease,
    Recovery,
}

#[derive(Debug)]
pub enum OfflineCleanupError {
    RuntimeLayout(RuntimeLayoutError),
    Lease(DaemonLeaseError),
    Recovery(Box<dyn Error + Send + Sync>),
}

impl OfflineCleanupError {
    #[must_use]
    pub const fn kind(&self) -> OfflineCleanupErrorKind {
        match self {
            Self::RuntimeLayout(_) => OfflineCleanupErrorKind::RuntimeLayout,
            Self::Lease(error) if matches!(error.kind(), DaemonLeaseErrorKind::Busy) => {
                OfflineCleanupErrorKind::Busy
            }
            Self::Lease(_) => OfflineCleanupErrorKind::Lease,
            Self::Recovery(_) => OfflineCleanupErrorKind::Recovery,
        }
    }
}

impl fmt::Display for OfflineCleanupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeLayout(error) => write!(formatter, "runtime layout failed: {error}"),
            Self::Lease(error) => write!(formatter, "daemon exclusion failed: {error}"),
            Self::Recovery(error) => write!(formatter, "bounded recovery failed: {error}"),
        }
    }
}

impl Error for OfflineCleanupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RuntimeLayout(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::Recovery(error) => Some(error.as_ref()),
        }
    }
}

pub fn run_offline_cleanup(
    options: &DaemonOptions,
) -> Result<OfflineCleanupReport, OfflineCleanupError> {
    let layout = RuntimeLayout::bootstrap(&options.runtime_root)
        .map_err(OfflineCleanupError::RuntimeLayout)?;
    layout
        .require_run_child("daemon lease", &options.daemon_lease_path)
        .map_err(OfflineCleanupError::RuntimeLayout)?;
    let profile = SystemCapabilityProfileSource::new(options.capability_profile_paths())
        .collect_capability_profile();
    run_native_offline_cleanup(options, &layout, &profile)
}

fn run_native_offline_cleanup(
    options: &DaemonOptions,
    layout: &RuntimeLayout,
    profile: &flux_core::CapabilityProfile,
) -> Result<OfflineCleanupReport, OfflineCleanupError> {
    let boot_identity = profile.boot_identity().verified().cloned().ok_or_else(|| {
        OfflineCleanupError::Recovery(Box::new(NativeOfflineBootstrapError::MissingBootIdentity {
            observation: profile.boot_identity().kind(),
        }))
    })?;
    let network_namespace = profile
        .device_identity()
        .verified()
        .ok_or_else(|| {
            OfflineCleanupError::Recovery(Box::new(
                NativeOfflineBootstrapError::MissingDeviceIdentity {
                    observation: profile.device_identity().kind(),
                },
            ))
        })?
        .network_namespace();
    let config = options.native_xtables_runtime_config(layout);
    let recovery = while_holding_daemon_lease(&options.daemon_lease_path, || {
        let convergence =
            NativeXtablesAndroidRuntime::compose_recovery(config, boot_identity, network_namespace)
                .map_err(|source| NativeOfflineBootstrapError::Composition(Box::new(source)))?;
        match convergence {
            Some(convergence) => NativeOfflineRecovery::new(convergence)
                .recover_stopped()
                .map_err(NativeOfflineBootstrapError::Recovery),
            None => Ok(VerifiedCleanAbsence(())),
        }
    })
    .map_err(OfflineCleanupError::Lease)?;
    let _clean_absence =
        recovery.map_err(|source| OfflineCleanupError::Recovery(Box::new(source)))?;
    Ok(OfflineCleanupReport {
        disposition: OfflineCleanupDisposition::Complete,
    })
}

#[derive(Debug)]
enum NativeOfflineBootstrapError {
    MissingBootIdentity { observation: ObservationKind },
    MissingDeviceIdentity { observation: ObservationKind },
    Composition(Box<dyn Error + Send + Sync>),
    Recovery(NativeOfflineRecoveryError),
}

impl fmt::Display for NativeOfflineBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBootIdentity { observation } => write!(
                formatter,
                "native offline cleanup requires a verified boot identity, found {observation:?}"
            ),
            Self::MissingDeviceIdentity { observation } => write!(
                formatter,
                "native offline cleanup requires a verified device identity, found {observation:?}"
            ),
            Self::Composition(source) => write!(formatter, "compose native recovery: {source}"),
            Self::Recovery(source) => source.fmt(formatter),
        }
    }
}

impl Error for NativeOfflineBootstrapError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Composition(source) => Some(source.as_ref()),
            Self::Recovery(source) => Some(source),
            Self::MissingBootIdentity { .. } | Self::MissingDeviceIdentity { .. } => None,
        }
    }
}

#[cfg(test)]
fn run_offline_cleanup_with_recovery<R>(
    daemon_lease_path: &Path,
    recovery: &mut R,
) -> Result<OfflineCleanupReport, OfflineCleanupError>
where
    R: OfflineRecovery,
{
    let recovery = while_holding_daemon_lease(daemon_lease_path, || recovery.recover_stopped())
        .map_err(OfflineCleanupError::Lease)?;
    let _clean_absence =
        recovery.map_err(|source| OfflineCleanupError::Recovery(Box::new(source)))?;
    Ok(OfflineCleanupReport {
        disposition: OfflineCleanupDisposition::Complete,
    })
}

pub fn run_offline_cleanup_cli<I, T, O, E>(
    args: I,
    options: &DaemonOptions,
    stdout: &mut O,
    stderr: &mut E,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: AsRef<str>,
    O: Write,
    E: Write,
{
    let arguments = args
        .into_iter()
        .map(|argument| argument.as_ref().to_owned())
        .collect::<Vec<_>>();
    if arguments.len() != 3
        || arguments.get(1).map(String::as_str) != Some("cleanup")
        || arguments.get(2).map(String::as_str) != Some("--offline")
    {
        let _ = writeln!(stderr, "fluxd: cleanup requires exactly --offline");
        return EXIT_USAGE;
    }

    match run_offline_cleanup(options) {
        Ok(report) => {
            debug_assert_eq!(report.disposition(), OfflineCleanupDisposition::Complete);
            if writeln!(stdout, "cleanup complete").is_ok() {
                EXIT_SUCCESS
            } else {
                EXIT_RUNTIME_ERROR
            }
        }
        Err(error) if error.kind() == OfflineCleanupErrorKind::Busy => {
            let _ = writeln!(stderr, "fluxd: cleanup busy: {error}");
            OFFLINE_CLEANUP_BUSY_EXIT
        }
        Err(error) => {
            let _ = writeln!(stderr, "fluxd: offline cleanup failed: {error}");
            EXIT_RUNTIME_ERROR
        }
    }
}

fn while_holding_daemon_lease<T, E>(
    path: &Path,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<Result<T, E>, DaemonLeaseError> {
    let _lease = DaemonLease::acquire(path)?;
    Ok(operation())
}

struct ParentDirectory {
    directory: File,
    name: CString,
    path: PathBuf,
}

fn open_parent_directory(path: &Path) -> Result<ParentDirectory, DaemonLeaseError> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| DaemonLeaseError::UnsafePath(path.to_owned()))?;
    let name = c_string(name, path)?;
    let parent_path = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if parent_path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(DaemonLeaseError::UnsafePath(path.to_owned()));
    }
    let anchor = if parent_path.is_absolute() { "/" } else { "." };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(anchor)
        .map_err(|source| DaemonLeaseError::io("open daemon lease path anchor", path, source))?;
    let mut traversed = if parent_path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };

    for component in parent_path.components() {
        let Component::Normal(component) = component else {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(DaemonLeaseError::UnsafePath(path.to_owned()));
                }
                Component::Normal(_) => unreachable!(),
            }
        };
        traversed.push(component);
        let component = c_string(component, &traversed)?;
        let descriptor = open_at(
            directory.as_raw_fd(),
            &component,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            None,
        )
        .map_err(|source| classify_path_error(&directory, &component, &traversed, source))?;
        // SAFETY: `openat` returned a new owned descriptor on success.
        directory = unsafe { File::from_raw_fd(descriptor) };
    }

    Ok(ParentDirectory {
        directory,
        name,
        path: parent_path.to_owned(),
    })
}

fn open_lease_file(parent: &ParentDirectory, path: &Path) -> Result<File, DaemonLeaseError> {
    loop {
        match entry_kind_at(parent.directory.as_raw_fd(), &parent.name)
            .map_err(|source| DaemonLeaseError::io("inspect daemon lease", path, source))?
        {
            Some(EntryKind::Symlink) => return Err(DaemonLeaseError::Symlink(path.to_owned())),
            Some(EntryKind::Directory | EntryKind::Other) => {
                return Err(DaemonLeaseError::UnexpectedFileType(path.to_owned()));
            }
            Some(EntryKind::Regular) => {
                let descriptor = open_at(
                    parent.directory.as_raw_fd(),
                    &parent.name,
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    None,
                )
                .map_err(|source| DaemonLeaseError::io("open daemon lease", path, source))?;
                // SAFETY: `openat` returned a new owned descriptor on success.
                return Ok(unsafe { File::from_raw_fd(descriptor) });
            }
            None => match open_at(
                parent.directory.as_raw_fd(),
                &parent.name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                Some(0o600),
            ) {
                Ok(descriptor) => {
                    // SAFETY: `openat` returned a new owned descriptor on success.
                    return Ok(unsafe { File::from_raw_fd(descriptor) });
                }
                Err(source) if source.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(source) => {
                    return Err(DaemonLeaseError::io("create daemon lease", path, source));
                }
            },
        }
    }
}

fn require_secure_parent(directory: &File, path: &Path) -> Result<(), DaemonLeaseError> {
    let metadata = directory
        .metadata()
        .map_err(|source| DaemonLeaseError::io("inspect daemon lease directory", path, source))?;
    if !metadata.is_dir() {
        return Err(DaemonLeaseError::UnexpectedFileType(path.to_owned()));
    }
    if metadata.uid() != effective_uid() {
        return Err(DaemonLeaseError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "directory is not owned by the effective user",
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(DaemonLeaseError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "directory is writable by group or other",
        });
    }
    Ok(())
}

fn require_secure_lease_file(file: &File, path: &Path) -> Result<(), DaemonLeaseError> {
    let metadata = file
        .metadata()
        .map_err(|source| DaemonLeaseError::io("inspect daemon lease file", path, source))?;
    if !metadata.is_file() {
        return Err(DaemonLeaseError::UnexpectedFileType(path.to_owned()));
    }
    if metadata.nlink() != 1 {
        return Err(DaemonLeaseError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "file must have exactly one hard link",
        });
    }
    if metadata.uid() != effective_uid() {
        return Err(DaemonLeaseError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "file is not owned by the effective user",
        });
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(DaemonLeaseError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "file is writable by group or other",
        });
    }
    Ok(())
}

fn classify_path_error(
    directory: &File,
    name: &CString,
    path: &Path,
    source: io::Error,
) -> DaemonLeaseError {
    if matches!(
        source.raw_os_error(),
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
    ) {
        match entry_kind_at(directory.as_raw_fd(), name) {
            Ok(Some(EntryKind::Symlink)) => return DaemonLeaseError::Symlink(path.to_owned()),
            Ok(Some(_)) => return DaemonLeaseError::UnexpectedFileType(path.to_owned()),
            Ok(None) | Err(_) => {}
        }
    }
    DaemonLeaseError::io("open daemon lease directory", path, source)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

fn entry_kind_at(directory: RawFd, name: &CString) -> io::Result<Option<EntryKind>> {
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` is an open directory descriptor, `name` is NUL-terminated, and
    // `metadata` points to writable storage for one `stat` value.
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let source = io::Error::last_os_error();
        return if source.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(source)
        };
    }
    // SAFETY: `fstatat` initialized `metadata` on success.
    let metadata = unsafe { metadata.assume_init() };
    let kind = match metadata.st_mode & libc::S_IFMT {
        libc::S_IFREG => EntryKind::Regular,
        libc::S_IFDIR => EntryKind::Directory,
        libc::S_IFLNK => EntryKind::Symlink,
        _ => EntryKind::Other,
    };
    Ok(Some(kind))
}

fn open_at(
    directory: RawFd,
    path: &CString,
    flags: libc::c_int,
    mode: Option<libc::mode_t>,
) -> io::Result<RawFd> {
    // SAFETY: `path` is NUL-terminated, `directory` is an open directory descriptor, and a mode
    // argument is supplied exactly when `O_CREAT` is present.
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

fn try_lock_exclusive(file: &File) -> io::Result<()> {
    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_lock_busy(source: &io::Error) -> bool {
    matches!(source.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
}

fn c_string(value: &OsStr, path: &Path) -> Result<CString, DaemonLeaseError> {
    CString::new(value.as_bytes()).map_err(|_| DaemonLeaseError::UnsafePath(path.to_owned()))
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn daemon_and_offline_cleanup_are_mutually_exclusive() {
        let fixture = Fixture::new();
        let state = ScriptedNativeState::new(None);
        let mut recovery = NativeOfflineRecovery::new(state.convergence());
        let lease = DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("acquire daemon-side lease");

        let error =
            run_offline_cleanup_with_recovery(&fixture.options.daemon_lease_path, &mut recovery)
                .expect_err("offline cleanup must reject a live daemon lease");
        assert_eq!(error.kind(), OfflineCleanupErrorKind::Busy);

        drop(lease);
        let mut recovery = NativeOfflineRecovery::new(state.convergence());
        assert_eq!(
            run_offline_cleanup_with_recovery(&fixture.options.daemon_lease_path, &mut recovery,)
                .expect("unlocked persistent lease file must not block cleanup")
                .disposition(),
            OfflineCleanupDisposition::Complete
        );
    }

    #[test]
    fn stale_pid_socket_and_unlocked_lease_files_do_not_authorize_or_block_cleanup() {
        let fixture = Fixture::new();
        fs::write(fixture.run.join("fluxd.pid"), "999999\n").expect("write stale PID");
        fs::write(fixture.run.join("fluxd.sock"), "stale socket placeholder\n")
            .expect("write stale socket");
        fs::write(&fixture.options.daemon_lease_path, "stale unlocked lease\n")
            .expect("write unlocked lease");

        let state = ScriptedNativeState::new(None);
        let mut recovery = NativeOfflineRecovery::new(state.convergence());
        run_offline_cleanup_with_recovery(&fixture.options.daemon_lease_path, &mut recovery)
            .expect("cleanup ignores stale hints");

        assert!(!state.events().is_empty());
    }

    #[test]
    fn lease_rejects_symlink_nonregular_parent_traversal_and_unsafe_metadata() {
        let root = TempDir::new().expect("temporary root");
        let real = root.path().join("real");
        fs::create_dir(&real).expect("create real directory");
        let linked = root.path().join("linked");
        symlink(&real, &linked).expect("create directory symlink");
        let error = DaemonLease::acquire(&linked.join("fluxd.lease"))
            .expect_err("symlink ancestry must fail closed");
        assert_eq!(error.kind(), DaemonLeaseErrorKind::Symlink);

        let nonregular = real.join("nonregular");
        fs::create_dir(&nonregular).expect("create nonregular lease entry");
        let error =
            DaemonLease::acquire(&nonregular).expect_err("nonregular lease entry must fail closed");
        assert_eq!(error.kind(), DaemonLeaseErrorKind::UnexpectedFileType);

        let unsafe_path = real.join("child/../fluxd.lease");
        let error =
            DaemonLease::acquire(&unsafe_path).expect_err("parent traversal must fail closed");
        assert_eq!(error.kind(), DaemonLeaseErrorKind::UnsafePath);

        let writable = root.path().join("writable");
        fs::create_dir(&writable).expect("create writable directory");
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777))
            .expect("make directory unsafe");
        let error = DaemonLease::acquire(&writable.join("fluxd.lease"))
            .expect_err("group-writable lease parent must fail closed");
        assert_eq!(error.kind(), DaemonLeaseErrorKind::UnsafeMetadata);
    }

    #[test]
    fn lease_remains_held_for_the_complete_recovery_operation() {
        let fixture = Fixture::new();
        let nested = while_holding_daemon_lease(&fixture.options.daemon_lease_path, || {
            let error = DaemonLease::acquire(&fixture.options.daemon_lease_path)
                .expect_err("recovery must retain the daemon lease");
            assert_eq!(error.kind(), DaemonLeaseErrorKind::Busy);
            Ok::<_, ()>(())
        })
        .expect("acquire outer cleanup lease");
        nested.expect("synthetic recovery succeeds");

        DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("lease releases after recovery returns");
    }

    #[test]
    fn dropping_lease_unlocks_a_fork_inherited_open_file_description() {
        let fixture = Fixture::new();
        let lease = DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("acquire process lease");
        // `dup` models the shared open-file description that exists between `fork` and `exec`.
        // SAFETY: `lease` owns a valid descriptor and the duplicate is checked before ownership.
        let inherited_descriptor = unsafe { libc::dup(lease._file.as_raw_fd()) };
        assert!(
            inherited_descriptor >= 0,
            "duplicate process lease descriptor: {}",
            io::Error::last_os_error()
        );
        // SAFETY: `dup` returned a new owned descriptor on success.
        let inherited = unsafe { File::from_raw_fd(inherited_descriptor) };

        drop(lease);
        let reacquired = DaemonLease::acquire(&fixture.options.daemon_lease_path);
        drop(inherited);

        reacquired.expect("dropping the lease must unlock an inherited open-file description");
    }

    #[test]
    fn recovery_failure_is_typed_and_releases_the_lease() {
        let fixture = Fixture::new();
        let state = ScriptedNativeState::new(Some(7));
        state.fail_stop_once();
        let mut recovery = NativeOfflineRecovery::new(state.convergence());

        let error =
            run_offline_cleanup_with_recovery(&fixture.options.daemon_lease_path, &mut recovery)
                .expect_err("native recovery failure must remain a cleanup failure");
        assert_eq!(error.kind(), OfflineCleanupErrorKind::Recovery);

        DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("failed recovery must release the process lease");
    }

    #[test]
    fn public_cleanup_bootstraps_a_fresh_runtime_layout_before_leasing() {
        let fixture = Fixture::new();
        fs::remove_dir(&fixture.run).expect("remove precreated run directory");

        let error = run_offline_cleanup(&fixture.options)
            .expect_err("host fixture has no verified native device identity");

        assert_eq!(error.kind(), OfflineCleanupErrorKind::Recovery);
        assert!(fixture.run.is_dir());
        assert!(fixture.root.path().join("state").is_dir());
        assert!(!fixture.options.daemon_lease_path.exists());
    }

    #[test]
    fn public_cleanup_rejects_a_lease_outside_the_owned_run_directory() {
        let mut fixture = Fixture::new();
        fixture.options.daemon_lease_path = fixture.root.path().join("foreign.lease");

        let error = run_offline_cleanup(&fixture.options)
            .expect_err("cleanup lease outside run must fail closed");

        assert_eq!(error.kind(), OfflineCleanupErrorKind::RuntimeLayout);
        assert!(!fixture.options.daemon_lease_path.exists());
    }

    #[test]
    fn cleanup_cli_has_exact_syntax_and_fails_closed_without_native_identity() {
        let fixture = Fixture::new();
        fs::write(
            &fixture.options.boot_id_path,
            "01234567-89ab-cdef-0123-456789abcdef\n",
        )
        .expect("write verified boot identity");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_offline_cleanup_cli(
                ["fluxd", "cleanup", "--offline"],
                &fixture.options,
                &mut stdout,
                &mut stderr,
            ),
            EXIT_RUNTIME_ERROR
        );
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr.clone())
                .expect("UTF-8 error")
                .contains("verified device identity")
        );

        stdout.clear();
        stderr.clear();
        assert_eq!(
            run_offline_cleanup_cli(
                ["fluxd", "cleanup"],
                &fixture.options,
                &mut stdout,
                &mut stderr,
            ),
            EXIT_USAGE
        );
        assert!(stdout.is_empty());
        assert_eq!(stderr, b"fluxd: cleanup requires exactly --offline\n");
    }

    #[test]
    fn native_offline_recovery_is_idempotent_and_always_converges_stopped() {
        let state = ScriptedNativeState::new(None);
        let mut recovery = NativeOfflineRecovery::new(state.convergence());

        recovery
            .recover_stopped()
            .expect("first clean-absence recovery");
        recovery
            .recover_stopped()
            .expect("idempotent clean-absence recovery");

        assert_eq!(
            state.events(),
            [
                NativeRecoveryEvent::Recover(None),
                NativeRecoveryEvent::Stop,
                NativeRecoveryEvent::Recover(None),
                NativeRecoveryEvent::Recover(None),
                NativeRecoveryEvent::Stop,
                NativeRecoveryEvent::Recover(None),
            ]
        );
        assert_eq!(state.active(), None);
    }

    #[test]
    fn native_offline_recovery_removes_stale_or_foreign_active_state() {
        let state = ScriptedNativeState::new(Some(99));
        let mut recovery = NativeOfflineRecovery::new(state.convergence());

        recovery
            .recover_stopped()
            .expect("remove recovered foreign target");

        assert_eq!(
            state.events(),
            [
                NativeRecoveryEvent::Recover(Some(99)),
                NativeRecoveryEvent::Stop,
                NativeRecoveryEvent::Recover(None),
            ]
        );
        assert_eq!(state.active(), None);
    }

    #[test]
    fn native_offline_recovery_reports_partial_cleanup_without_proof() {
        let state = ScriptedNativeState::new(Some(7));
        state.fail_stop_once();
        let mut recovery = NativeOfflineRecovery::new(state.convergence());

        let error = recovery
            .recover_stopped()
            .expect_err("partial cleanup cannot issue clean-absence proof");

        assert_eq!(error.kind(), NativeOfflineRecoveryErrorKind::Stop);
        assert_eq!(state.active(), Some(7));
    }

    #[test]
    fn native_offline_recovery_resumes_after_a_crash_interrupted_cleanup() {
        let state = ScriptedNativeState::new(Some(11));
        state.fail_stop_once();
        let mut interrupted = NativeOfflineRecovery::new(state.convergence());
        interrupted
            .recover_stopped()
            .expect_err("first cleanup is interrupted");
        drop(interrupted);

        NativeOfflineRecovery::new(state.convergence())
            .recover_stopped()
            .expect("next process recovers and finishes cleanup");

        assert_eq!(state.active(), None);
        assert_eq!(
            state.events(),
            [
                NativeRecoveryEvent::Recover(Some(11)),
                NativeRecoveryEvent::Stop,
                NativeRecoveryEvent::Recover(Some(11)),
                NativeRecoveryEvent::Stop,
                NativeRecoveryEvent::Recover(None),
            ]
        );
    }

    #[test]
    fn native_offline_recovery_rejects_a_false_stopped_report() {
        let state = ScriptedNativeState::new(Some(13));
        state.report_active_after_stop();
        let mut recovery = NativeOfflineRecovery::new(state.convergence());

        let error = recovery
            .recover_stopped()
            .expect_err("active stopped report cannot issue proof");

        assert_eq!(error.kind(), NativeOfflineRecoveryErrorKind::NotCleanAbsent);
        assert_eq!(state.active(), Some(13));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum NativeRecoveryEvent {
        Recover(Option<u64>),
        Stop,
    }

    struct ScriptedNativeInner {
        active: Option<u64>,
        fail_stop_once: bool,
        report_active_after_stop: bool,
        events: Vec<NativeRecoveryEvent>,
    }

    #[derive(Clone)]
    struct ScriptedNativeState {
        inner: Arc<Mutex<ScriptedNativeInner>>,
    }

    impl ScriptedNativeState {
        fn new(active: Option<u64>) -> Self {
            Self {
                inner: Arc::new(Mutex::new(ScriptedNativeInner {
                    active,
                    fail_stop_once: false,
                    report_active_after_stop: false,
                    events: Vec::new(),
                })),
            }
        }

        fn convergence(&self) -> ScriptedNativeConvergence {
            ScriptedNativeConvergence {
                inner: Arc::clone(&self.inner),
            }
        }

        fn fail_stop_once(&self) {
            self.inner
                .lock()
                .expect("native recovery state")
                .fail_stop_once = true;
        }

        fn report_active_after_stop(&self) {
            self.inner
                .lock()
                .expect("native recovery state")
                .report_active_after_stop = true;
        }

        fn active(&self) -> Option<u64> {
            self.inner.lock().expect("native recovery state").active
        }

        fn events(&self) -> Vec<NativeRecoveryEvent> {
            self.inner
                .lock()
                .expect("native recovery state")
                .events
                .clone()
        }
    }

    struct ScriptedNativeConvergence {
        inner: Arc<Mutex<ScriptedNativeInner>>,
    }

    impl NativeCaptureConvergence for ScriptedNativeConvergence {
        type Target = u64;
        type Identity = u64;
        type Error = io::Error;

        fn target_identity(target: &Self::Target) -> Self::Identity {
            *target
        }

        fn recover(
            &mut self,
        ) -> Result<flux_platform::NativeCaptureConvergenceReport<Self::Identity>, Self::Error>
        {
            let mut inner = self.inner.lock().expect("native recovery state");
            let active = inner.active;
            inner.events.push(NativeRecoveryEvent::Recover(active));
            Ok(flux_platform::NativeCaptureConvergenceReport::new(
                match active {
                    Some(identity) => NativeCaptureConvergedState::Active(identity),
                    None => NativeCaptureConvergedState::CleanAbsent,
                },
                false,
            ))
        }

        fn converge(
            &mut self,
            desired: NativeCaptureDesired<Self::Target>,
        ) -> Result<flux_platform::NativeCaptureConvergenceReport<Self::Identity>, Self::Error>
        {
            assert_eq!(desired, NativeCaptureDesired::Stopped);
            let mut inner = self.inner.lock().expect("native recovery state");
            inner.events.push(NativeRecoveryEvent::Stop);
            if inner.fail_stop_once {
                inner.fail_stop_once = false;
                return Err(io::Error::other("injected partial cleanup"));
            }
            if inner.report_active_after_stop {
                let identity = inner.active.expect("active false-report fixture");
                return Ok(flux_platform::NativeCaptureConvergenceReport::new(
                    NativeCaptureConvergedState::Active(identity),
                    false,
                ));
            }
            let changed = inner.active.take().is_some();
            Ok(flux_platform::NativeCaptureConvergenceReport::new(
                NativeCaptureConvergedState::CleanAbsent,
                changed,
            ))
        }
    }

    struct Fixture {
        root: TempDir,
        run: PathBuf,
        options: DaemonOptions,
    }

    impl Fixture {
        fn new() -> Self {
            let root = TempDir::new().expect("temporary root");
            let run = root.path().join("run");
            fs::create_dir(&run).expect("create run directory");
            let options = DaemonOptions {
                runtime_root: root.path().to_path_buf(),
                socket_path: run.join("fluxd.sock"),
                daemon_lease_path: run.join("fluxd.lease"),
                config_path: root.path().join("conf/flux.toml"),
                subscription_store_path: root.path().join("state/subscription"),
                intent_path: root.path().join("state/administrative-intent.json"),
                boot_id_path: root.path().join("boot-id"),
                selinux_enforce_path: root.path().join("selinux-enforce"),
                disable_path: root.path().join("disable"),
            };
            Self { root, run, options }
        }
    }
}
