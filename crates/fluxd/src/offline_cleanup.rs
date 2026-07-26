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

use flux_platform::{DispatcherPhaseCommand, ProcessPhaseDispatcher};

use crate::daemon::DaemonOptions;

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

impl OfflineCleanupReport {
    #[must_use]
    pub const fn disposition(self) -> OfflineCleanupDisposition {
        self.disposition
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineCleanupErrorKind {
    Busy,
    Lease,
    Recovery,
}

#[derive(Debug)]
pub enum OfflineCleanupError {
    Lease(DaemonLeaseError),
    Recovery(flux_platform::PhaseDispatcherError),
}

impl OfflineCleanupError {
    #[must_use]
    pub const fn kind(&self) -> OfflineCleanupErrorKind {
        match self {
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
            Self::Lease(error) => write!(formatter, "daemon exclusion failed: {error}"),
            Self::Recovery(error) => write!(formatter, "bounded recovery failed: {error}"),
        }
    }
}

impl Error for OfflineCleanupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Lease(error) => Some(error),
            Self::Recovery(error) => Some(error),
        }
    }
}

pub fn run_offline_cleanup(
    options: &DaemonOptions,
) -> Result<OfflineCleanupReport, OfflineCleanupError> {
    let recovery = while_holding_daemon_lease(&options.daemon_lease_path, || {
        let mut dispatcher = ProcessPhaseDispatcher::new(options.phase_dispatcher_paths());
        dispatcher.execute(DispatcherPhaseCommand::StartupRecover)
    })
    .map_err(OfflineCleanupError::Lease)?;
    recovery.map_err(OfflineCleanupError::Recovery)?;
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

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn daemon_and_offline_cleanup_are_mutually_exclusive() {
        let fixture = Fixture::new("exit 0\n");
        let lease = DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("acquire daemon-side lease");

        let error = run_offline_cleanup(&fixture.options)
            .expect_err("offline cleanup must reject a live daemon lease");
        assert_eq!(error.kind(), OfflineCleanupErrorKind::Busy);

        drop(lease);
        assert_eq!(
            run_offline_cleanup(&fixture.options)
                .expect("unlocked persistent lease file must not block cleanup")
                .disposition(),
            OfflineCleanupDisposition::Complete
        );
    }

    #[test]
    fn stale_pid_socket_and_unlocked_lease_files_do_not_authorize_or_block_cleanup() {
        let fixture = Fixture::new(&format!(
            "[ \"${{1:-}}\" = startup-recover ] || exit 64\nprintf complete >{}\n",
            fixture_path_placeholder("recovered")
        ));
        fs::write(fixture.run.join("fluxd.pid"), "999999\n").expect("write stale PID");
        fs::write(fixture.run.join("fluxd.sock"), "stale socket placeholder\n")
            .expect("write stale socket");
        fs::write(&fixture.options.daemon_lease_path, "stale unlocked lease\n")
            .expect("write unlocked lease");

        run_offline_cleanup(&fixture.options).expect("cleanup ignores stale hints");

        assert!(fixture.root.path().join("recovered").is_file());
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
        let fixture = Fixture::new("exit 0\n");
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
        let fixture = Fixture::new("exit 0\n");
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
        let fixture = Fixture::new("exit 71\n");

        let error = run_offline_cleanup(&fixture.options)
            .expect_err("dispatcher failure must remain a cleanup failure");
        assert_eq!(error.kind(), OfflineCleanupErrorKind::Recovery);

        DaemonLease::acquire(&fixture.options.daemon_lease_path)
            .expect("failed recovery must release the process lease");
    }

    #[test]
    fn cleanup_cli_has_exact_syntax_and_stable_terminal_exits() {
        let fixture = Fixture::new("exit 0\n");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            run_offline_cleanup_cli(
                ["fluxd", "cleanup", "--offline"],
                &fixture.options,
                &mut stdout,
                &mut stderr,
            ),
            EXIT_SUCCESS
        );
        assert_eq!(stdout, b"cleanup complete\n");
        assert!(stderr.is_empty());

        let lease =
            DaemonLease::acquire(&fixture.options.daemon_lease_path).expect("hold daemon lease");
        stdout.clear();
        stderr.clear();
        assert_eq!(
            run_offline_cleanup_cli(
                ["fluxd", "cleanup", "--offline"],
                &fixture.options,
                &mut stdout,
                &mut stderr,
            ),
            OFFLINE_CLEANUP_BUSY_EXIT
        );
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr.clone())
                .expect("UTF-8 error")
                .contains("cleanup busy")
        );
        drop(lease);

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

    struct Fixture {
        root: TempDir,
        run: PathBuf,
        options: DaemonOptions,
    }

    impl Fixture {
        fn new(dispatcher_body: &str) -> Self {
            let root = TempDir::new().expect("temporary root");
            let run = root.path().join("run");
            let scripts = root.path().join("scripts");
            fs::create_dir(&run).expect("create run directory");
            fs::create_dir(&scripts).expect("create scripts directory");
            let dispatcher = scripts.join("dispatcher");
            let body = dispatcher_body.replace(
                &fixture_path_placeholder("recovered"),
                root.path().join("recovered").to_str().expect("UTF-8 path"),
            );
            fs::write(&dispatcher, format!("#!/bin/sh\n{body}")).expect("write dispatcher");
            let options = DaemonOptions {
                socket_path: run.join("fluxd.sock"),
                daemon_lease_path: run.join("fluxd.lease"),
                config_path: root.path().join("conf/flux.toml"),
                shell: PathBuf::from("/bin/sh"),
                dispatcher_script: dispatcher,
                addrsync_script: scripts.join("addrsync"),
                engine_manifest_path: run.join("engine.manifest"),
                engine_config_path: root.path().join("conf/config.json"),
                bridge_environment_path: run.join("desired-state.env"),
                subscription_store_path: root.path().join("state/subscription"),
                intent_path: root.path().join("state/administrative-intent.json"),
                boot_id_path: root.path().join("boot-id"),
                selinux_enforce_path: root.path().join("selinux-enforce"),
                disable_path: root.path().join("disable"),
            };
            Self { root, run, options }
        }
    }

    fn fixture_path_placeholder(name: &str) -> String {
        format!("__FIXTURE_PATH_{name}__")
    }
}
