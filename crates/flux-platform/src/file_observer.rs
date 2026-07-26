use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileObservationPaths {
    desired_state: PathBuf,
    engine_template: PathBuf,
    subscription_url: PathBuf,
    disable: PathBuf,
}

impl FileObservationPaths {
    #[must_use]
    pub fn new(
        desired_state: impl Into<PathBuf>,
        engine_template: impl Into<PathBuf>,
        subscription_url: impl Into<PathBuf>,
        disable: impl Into<PathBuf>,
    ) -> Self {
        Self {
            desired_state: desired_state.into(),
            engine_template: engine_template.into(),
            subscription_url: subscription_url.into(),
            disable: disable.into(),
        }
    }

    #[must_use]
    pub fn desired_state(&self) -> &Path {
        &self.desired_state
    }

    #[must_use]
    pub fn engine_template(&self) -> &Path {
        &self.engine_template
    }

    #[must_use]
    pub fn subscription_url(&self) -> &Path {
        &self.subscription_url
    }

    #[must_use]
    pub fn disable(&self) -> &Path {
        &self.disable
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FileObservationBatch {
    configuration_inputs_changed: bool,
    disable_state_changed: bool,
}

impl FileObservationBatch {
    pub(crate) const fn all() -> Self {
        Self {
            configuration_inputs_changed: true,
            disable_state_changed: true,
        }
    }

    #[must_use]
    pub const fn configuration_inputs_changed(self) -> bool {
        self.configuration_inputs_changed
    }

    #[must_use]
    pub const fn disable_state_changed(self) -> bool {
        self.disable_state_changed
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.configuration_inputs_changed && !self.disable_state_changed
    }

    pub(crate) fn include(&mut self, targets: TargetMask) {
        self.configuration_inputs_changed |= targets.configuration_inputs();
        self.disable_state_changed |= targets.disable_state();
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.configuration_inputs_changed |= other.configuration_inputs_changed;
        self.disable_state_changed |= other.disable_state_changed;
    }
}

#[derive(Debug)]
pub enum FileObservationError {
    InvalidPath {
        path: PathBuf,
        detail: &'static str,
    },
    Initialize(io::Error),
    OpenDirectory {
        directory: PathBuf,
        source: io::Error,
    },
    InspectDirectory {
        directory: PathBuf,
        source: io::Error,
    },
    AddWatch {
        directory: PathBuf,
        source: io::Error,
    },
    RemoveWatch {
        directory: PathBuf,
        source: io::Error,
    },
    Read(io::Error),
    MalformedEvent(&'static str),
}

impl fmt::Display for FileObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, detail } => {
                write!(
                    formatter,
                    "invalid observed path {}: {detail}",
                    path.display()
                )
            }
            Self::Initialize(source) => write!(formatter, "initialize inotify: {source}"),
            Self::OpenDirectory { directory, source } => write!(
                formatter,
                "open observed directory {} without following symbolic links: {source}",
                directory.display()
            ),
            Self::InspectDirectory { directory, source } => write!(
                formatter,
                "inspect observed directory {}: {source}",
                directory.display()
            ),
            Self::AddWatch { directory, source } => write!(
                formatter,
                "attach inotify watch to {}: {source}",
                directory.display()
            ),
            Self::RemoveWatch { directory, source } => write!(
                formatter,
                "remove inotify watch from {}: {source}",
                directory.display()
            ),
            Self::Read(source) => write!(formatter, "read inotify events: {source}"),
            Self::MalformedEvent(detail) => write!(formatter, "malformed inotify event: {detail}"),
        }
    }
}

impl Error for FileObservationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Initialize(source)
            | Self::OpenDirectory { source, .. }
            | Self::InspectDirectory { source, .. }
            | Self::AddWatch { source, .. }
            | Self::RemoveWatch { source, .. }
            | Self::Read(source) => Some(source),
            Self::InvalidPath { .. } | Self::MalformedEvent(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TargetMask(u8);

impl TargetMask {
    const CONFIGURATION: Self = Self(1 << 0);
    const DISABLE: Self = Self(1 << 1);

    const fn configuration_inputs(self) -> bool {
        self.0 & Self::CONFIGURATION.0 != 0
    }

    const fn disable_state(self) -> bool {
        self.0 & Self::DISABLE.0 != 0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod implementation {
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::{CString, OsStr, OsString};
    use std::io;
    use std::mem;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};
    use std::time::{Duration, Instant};

    use super::{FileObservationBatch, FileObservationError, FileObservationPaths, TargetMask};

    const MAX_READS_PER_TURN: usize = 8;
    const EVENT_BUFFER_BYTES: usize = 16 * 1_024;
    const WATCH_RETRY_INTERVAL: Duration = Duration::from_millis(250);
    const IDENTITY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
    const ISSUE_REPORT_INTERVAL: Duration = Duration::from_secs(30);
    const WATCH_MASK: u32 = libc::IN_CLOSE_WRITE
        | libc::IN_ATTRIB
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF
        | libc::IN_UNMOUNT
        | libc::IN_ONLYDIR
        | libc::IN_EXCL_UNLINK;
    const TARGET_EVENT_MASK: u32 = libc::IN_CLOSE_WRITE
        | libc::IN_ATTRIB
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO;
    const INVALIDATION_MASK: u32 =
        libc::IN_DELETE_SELF | libc::IN_MOVE_SELF | libc::IN_UNMOUNT | libc::IN_IGNORED;

    #[derive(Default)]
    pub(crate) struct FileObservationDriveReport {
        pub(crate) observation: FileObservationBatch,
        pub(crate) issues: Vec<FileObservationError>,
    }

    impl FileObservationDriveReport {
        fn merge(&mut self, other: Self) {
            self.observation.merge(other.observation);
            self.issues.extend(other.issues);
        }
    }

    #[derive(Clone, Debug, Default, Eq, PartialEq)]
    struct DesiredDirectory {
        targets: BTreeMap<OsString, TargetMask>,
    }

    impl DesiredDirectory {
        fn target_mask(&self) -> TargetMask {
            self.targets
                .values()
                .copied()
                .fold(TargetMask::default(), |mut combined, target| {
                    combined.insert(target);
                    combined
                })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DirectoryIdentity {
        device: libc::dev_t,
        inode: libc::ino_t,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct WatchRegistration {
        descriptor: libc::c_int,
        identity: DirectoryIdentity,
    }

    struct ObservedDirectory {
        desired: DesiredDirectory,
        watch: Option<WatchRegistration>,
        last_issue_at: Option<Instant>,
    }

    pub(crate) struct FileObserverDriver {
        descriptor: OwnedFd,
        directories: BTreeMap<PathBuf, ObservedDirectory>,
        watch_directories: HashMap<libc::c_int, PathBuf>,
        retry_at: Option<Instant>,
        identity_check_at: Instant,
    }

    impl FileObserverDriver {
        pub(crate) fn open(
            paths: &FileObservationPaths,
            now: Instant,
        ) -> Result<(Self, Vec<FileObservationError>), FileObservationError> {
            let desired = desired_directories(paths)?;
            // SAFETY: inotify_init1 has no pointer arguments and returns one
            // newly owned descriptor on success.
            let descriptor = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if descriptor < 0 {
                return Err(FileObservationError::Initialize(io::Error::last_os_error()));
            }
            let mut driver = Self {
                // SAFETY: successful inotify_init1 returned a new descriptor.
                descriptor: unsafe { OwnedFd::from_raw_fd(descriptor) },
                directories: desired
                    .into_iter()
                    .map(|(path, desired)| {
                        (
                            path,
                            ObservedDirectory {
                                desired,
                                watch: None,
                                last_issue_at: None,
                            },
                        )
                    })
                    .collect(),
                watch_directories: HashMap::new(),
                retry_at: None,
                identity_check_at: deadline_after(now, IDENTITY_CHECK_INTERVAL),
            };
            let mut issues = Vec::new();
            let directories = driver.directories.keys().cloned().collect::<Vec<_>>();
            for directory in directories {
                match driver.create_watch(&directory) {
                    Ok(registration) => driver.install_registration(&directory, registration),
                    Err(error) => {
                        if let Some(observed) = driver.directories.get_mut(&directory) {
                            observed.last_issue_at = Some(now);
                        }
                        issues.push(error);
                    }
                }
            }
            driver.retry_at = driver
                .directories
                .values()
                .any(|observed| observed.watch.is_none())
                .then(|| deadline_after(now, WATCH_RETRY_INTERVAL));
            Ok((driver, issues))
        }

        pub(crate) fn readiness_fd(&self) -> BorrowedFd<'_> {
            self.descriptor.as_fd()
        }

        pub(crate) fn next_deadline(&self) -> Instant {
            self.retry_at.map_or(self.identity_check_at, |retry| {
                retry.min(self.identity_check_at)
            })
        }

        pub(crate) fn drive_ready(
            &mut self,
            now: Instant,
        ) -> Result<FileObservationDriveReport, FileObservationError> {
            let mut report = FileObservationDriveReport::default();
            let mut buffer = [0_u8; EVENT_BUFFER_BYTES];
            for _ in 0..MAX_READS_PER_TURN {
                let count = match self.read_events(&mut buffer)? {
                    Some(count) => count,
                    None => break,
                };
                self.decode_events(&buffer[..count], now, &mut report)?;
            }
            report.merge(self.drive_due(now));
            Ok(report)
        }

        pub(crate) fn drive_due(&mut self, now: Instant) -> FileObservationDriveReport {
            let mut report = FileObservationDriveReport::default();
            if now >= self.identity_check_at {
                self.verify_directory_identities(now, &mut report);
                self.identity_check_at = deadline_after(now, IDENTITY_CHECK_INTERVAL);
            }
            if self.retry_at.is_some_and(|deadline| now >= deadline) {
                self.install_missing_watches(now, &mut report);
            }
            report
        }

        pub(crate) fn replace_paths(
            &mut self,
            paths: &FileObservationPaths,
            now: Instant,
        ) -> Result<Vec<FileObservationError>, FileObservationError> {
            let desired = desired_directories(paths)?;
            if self.matches_desired(&desired) {
                return Ok(Vec::new());
            }

            let mut issues = Vec::new();
            self.remove_all_watches(&mut issues);
            self.directories = desired
                .into_iter()
                .map(|(path, desired)| {
                    (
                        path,
                        ObservedDirectory {
                            desired,
                            watch: None,
                            last_issue_at: None,
                        },
                    )
                })
                .collect();
            self.retry_at = Some(now);
            let mut report = FileObservationDriveReport::default();
            self.install_missing_watches(now, &mut report);
            issues.extend(report.issues);
            Ok(issues)
        }

        fn matches_desired(&self, desired: &BTreeMap<PathBuf, DesiredDirectory>) -> bool {
            self.directories.len() == desired.len()
                && self.directories.iter().all(|(path, observed)| {
                    desired
                        .get(path)
                        .is_some_and(|candidate| candidate == &observed.desired)
                })
        }

        fn read_events(
            &self,
            buffer: &mut [u8; EVENT_BUFFER_BYTES],
        ) -> Result<Option<usize>, FileObservationError> {
            loop {
                // SAFETY: buffer is writable for its complete length and the
                // inotify descriptor remains owned by self for this call.
                let received = unsafe {
                    libc::read(
                        self.descriptor.as_raw_fd(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        buffer.len(),
                    )
                };
                if received > 0 {
                    return usize::try_from(received)
                        .map(Some)
                        .map_err(|_| FileObservationError::MalformedEvent("negative byte count"));
                }
                if received == 0 {
                    return Err(FileObservationError::MalformedEvent(
                        "unexpected end of inotify stream",
                    ));
                }
                let source = io::Error::last_os_error();
                match source.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => return Ok(None),
                    _ => return Err(FileObservationError::Read(source)),
                }
            }
        }

        fn decode_events(
            &mut self,
            bytes: &[u8],
            now: Instant,
            report: &mut FileObservationDriveReport,
        ) -> Result<(), FileObservationError> {
            let header_bytes = mem::size_of::<libc::inotify_event>();
            let mut offset = 0_usize;
            while offset < bytes.len() {
                let remaining = bytes.len() - offset;
                if remaining < header_bytes {
                    return Err(FileObservationError::MalformedEvent(
                        "truncated event header",
                    ));
                }
                // SAFETY: the bounds check above makes a complete event header
                // readable; inotify records need not be aligned in this byte buffer.
                let event = unsafe {
                    std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<libc::inotify_event>())
                };
                let name_bytes = usize::try_from(event.len).map_err(|_| {
                    FileObservationError::MalformedEvent("name length does not fit usize")
                })?;
                let event_bytes = header_bytes.checked_add(name_bytes).ok_or(
                    FileObservationError::MalformedEvent("event length overflow"),
                )?;
                if event_bytes > remaining {
                    return Err(FileObservationError::MalformedEvent("truncated event name"));
                }
                let encoded_name = &bytes[offset + header_bytes..offset + event_bytes];
                let name_end = encoded_name
                    .iter()
                    .position(|byte| *byte == 0)
                    .unwrap_or(encoded_name.len());
                self.classify_event(
                    event.wd,
                    event.mask,
                    OsStr::from_bytes(&encoded_name[..name_end]),
                    now,
                    report,
                );
                offset += event_bytes;
            }
            Ok(())
        }

        fn classify_event(
            &mut self,
            watch_descriptor: libc::c_int,
            mask: u32,
            name: &OsStr,
            now: Instant,
            report: &mut FileObservationDriveReport,
        ) {
            if mask & libc::IN_Q_OVERFLOW != 0 {
                report.observation.include(self.all_target_mask());
                self.identity_check_at = now;
                return;
            }

            let Some(directory) = self.watch_directories.get(&watch_descriptor).cloned() else {
                return;
            };
            let Some(observed) = self.directories.get(&directory) else {
                return;
            };
            if mask & INVALIDATION_MASK != 0 {
                report.observation.include(observed.desired.target_mask());
                self.invalidate_watch(&directory, mask & libc::IN_IGNORED == 0, report);
                self.retry_at = Some(now);
                return;
            }
            if mask & TARGET_EVENT_MASK == 0 || name.is_empty() {
                return;
            }
            if let Some(targets) = observed.desired.targets.get(name) {
                report.observation.include(*targets);
            }
        }

        fn verify_directory_identities(
            &mut self,
            now: Instant,
            report: &mut FileObservationDriveReport,
        ) {
            let directories = self.directories.keys().cloned().collect::<Vec<_>>();
            for directory in directories {
                let Some(registration) = self
                    .directories
                    .get(&directory)
                    .and_then(|observed| observed.watch)
                else {
                    continue;
                };
                match open_directory(&directory)
                    .and_then(|descriptor| inspect_directory(&directory, descriptor.as_raw_fd()))
                {
                    Ok(identity) if identity == registration.identity => {}
                    Ok(_) => {
                        report.observation.include(self.target_mask(&directory));
                        self.invalidate_watch(&directory, true, report);
                        self.retry_at = Some(now);
                    }
                    Err(error) => {
                        report.observation.include(self.target_mask(&directory));
                        self.invalidate_watch(&directory, true, report);
                        self.record_issue(&directory, error, now, report);
                        self.retry_at = Some(now);
                    }
                }
            }
        }

        fn install_missing_watches(
            &mut self,
            now: Instant,
            report: &mut FileObservationDriveReport,
        ) {
            let missing = self
                .directories
                .iter()
                .filter(|(_, observed)| observed.watch.is_none())
                .map(|(directory, _)| directory.clone())
                .collect::<Vec<_>>();
            for directory in missing {
                match self.create_watch(&directory) {
                    Ok(registration) => {
                        self.install_registration(&directory, registration);
                        report.observation.include(self.target_mask(&directory));
                    }
                    Err(error) => self.record_issue(&directory, error, now, report),
                }
            }
            self.retry_at = self
                .directories
                .values()
                .any(|observed| observed.watch.is_none())
                .then(|| deadline_after(now, WATCH_RETRY_INTERVAL));
        }

        fn create_watch(
            &self,
            directory: &Path,
        ) -> Result<WatchRegistration, FileObservationError> {
            let directory_descriptor = open_directory(directory)?;
            let identity = inspect_directory(directory, directory_descriptor.as_raw_fd())?;
            let proc_path = CString::new(format!(
                "/proc/self/fd/{}",
                directory_descriptor.as_raw_fd()
            ))
            .expect("numeric proc descriptor path does not contain NUL");
            // SAFETY: both descriptors are live, proc_path is NUL-terminated,
            // and WATCH_MASK contains only inotify watch flags.
            let watch_descriptor = unsafe {
                libc::inotify_add_watch(self.descriptor.as_raw_fd(), proc_path.as_ptr(), WATCH_MASK)
            };
            if watch_descriptor < 0 {
                return Err(FileObservationError::AddWatch {
                    directory: directory.to_owned(),
                    source: io::Error::last_os_error(),
                });
            }
            Ok(WatchRegistration {
                descriptor: watch_descriptor,
                identity,
            })
        }

        fn install_registration(&mut self, directory: &Path, registration: WatchRegistration) {
            if let Some(observed) = self.directories.get_mut(directory) {
                observed.watch = Some(registration);
                observed.last_issue_at = None;
                self.watch_directories
                    .insert(registration.descriptor, directory.to_owned());
            }
        }

        fn invalidate_watch(
            &mut self,
            directory: &Path,
            remove_from_kernel: bool,
            report: &mut FileObservationDriveReport,
        ) {
            let registration = self
                .directories
                .get_mut(directory)
                .and_then(|observed| observed.watch.take());
            let Some(registration) = registration else {
                return;
            };
            self.watch_directories.remove(&registration.descriptor);
            if remove_from_kernel
                && let Err(error) = self.remove_watch(directory, registration.descriptor)
            {
                report.issues.push(error);
            }
        }

        fn remove_watch(
            &self,
            directory: &Path,
            watch_descriptor: libc::c_int,
        ) -> Result<(), FileObservationError> {
            #[cfg(target_os = "android")]
            let watch_descriptor =
                u32::try_from(watch_descriptor).map_err(|_| FileObservationError::RemoveWatch {
                    directory: directory.to_owned(),
                    source: io::Error::from_raw_os_error(libc::EINVAL),
                })?;
            // SAFETY: self owns the inotify descriptor and the watch descriptor
            // was returned by inotify_add_watch for this instance.
            if unsafe { libc::inotify_rm_watch(self.descriptor.as_raw_fd(), watch_descriptor) } == 0
            {
                return Ok(());
            }
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EINVAL) {
                return Ok(());
            }
            Err(FileObservationError::RemoveWatch {
                directory: directory.to_owned(),
                source,
            })
        }

        fn remove_all_watches(&mut self, issues: &mut Vec<FileObservationError>) {
            let registrations = self
                .directories
                .iter_mut()
                .filter_map(|(directory, observed)| {
                    observed
                        .watch
                        .take()
                        .map(|registration| (directory.clone(), registration.descriptor))
                })
                .collect::<Vec<_>>();
            self.watch_directories.clear();
            for (directory, descriptor) in registrations {
                if let Err(error) = self.remove_watch(&directory, descriptor) {
                    issues.push(error);
                }
            }
        }

        fn record_issue(
            &mut self,
            directory: &Path,
            error: FileObservationError,
            now: Instant,
            report: &mut FileObservationDriveReport,
        ) {
            let Some(observed) = self.directories.get_mut(directory) else {
                report.issues.push(error);
                return;
            };
            let report_due = observed.last_issue_at.is_none_or(|reported| {
                now.saturating_duration_since(reported) >= ISSUE_REPORT_INTERVAL
            });
            if report_due {
                observed.last_issue_at = Some(now);
                report.issues.push(error);
            }
        }

        fn target_mask(&self, directory: &Path) -> TargetMask {
            self.directories
                .get(directory)
                .map_or(TargetMask::default(), |observed| {
                    observed.desired.target_mask()
                })
        }

        fn all_target_mask(&self) -> TargetMask {
            self.directories
                .values()
                .fold(TargetMask::default(), |mut combined, observed| {
                    combined.insert(observed.desired.target_mask());
                    combined
                })
        }
    }

    fn desired_directories(
        paths: &FileObservationPaths,
    ) -> Result<BTreeMap<PathBuf, DesiredDirectory>, FileObservationError> {
        let mut directories = BTreeMap::<PathBuf, DesiredDirectory>::new();
        for (path, target) in [
            (paths.desired_state(), TargetMask::CONFIGURATION),
            (paths.engine_template(), TargetMask::CONFIGURATION),
            (paths.subscription_url(), TargetMask::CONFIGURATION),
            (paths.disable(), TargetMask::DISABLE),
        ] {
            let (directory, name) = split_observed_path(path)?;
            directories
                .entry(directory)
                .or_default()
                .targets
                .entry(name)
                .and_modify(|existing| existing.insert(target))
                .or_insert(target);
        }
        Ok(directories)
    }

    fn split_observed_path(path: &Path) -> Result<(PathBuf, OsString), FileObservationError> {
        if !path.is_absolute() {
            return Err(FileObservationError::InvalidPath {
                path: path.to_owned(),
                detail: "path must be absolute",
            });
        }
        for component in path.components() {
            if matches!(component, Component::ParentDir | Component::Prefix(_)) {
                return Err(FileObservationError::InvalidPath {
                    path: path.to_owned(),
                    detail: "path contains an unsafe component",
                });
            }
        }
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| FileObservationError::InvalidPath {
                path: path.to_owned(),
                detail: "path has no file name",
            })?;
        if name.as_bytes().contains(&0) {
            return Err(FileObservationError::InvalidPath {
                path: path.to_owned(),
                detail: "file name contains NUL",
            });
        }
        let directory = path
            .parent()
            .filter(|parent| parent.is_absolute())
            .ok_or_else(|| FileObservationError::InvalidPath {
                path: path.to_owned(),
                detail: "path has no absolute parent directory",
            })?;
        Ok((directory.to_owned(), name.to_owned()))
    }

    fn open_directory(directory: &Path) -> Result<OwnedFd, FileObservationError> {
        let mut descriptor = open_at(libc::AT_FDCWD, c"/").map_err(|source| {
            FileObservationError::OpenDirectory {
                directory: directory.to_owned(),
                source,
            }
        })?;
        for component in directory.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes()).map_err(|_| {
                        FileObservationError::InvalidPath {
                            path: directory.to_owned(),
                            detail: "directory component contains NUL",
                        }
                    })?;
                    descriptor = open_at(descriptor.as_raw_fd(), &name).map_err(|source| {
                        FileObservationError::OpenDirectory {
                            directory: directory.to_owned(),
                            source,
                        }
                    })?;
                }
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(FileObservationError::InvalidPath {
                        path: directory.to_owned(),
                        detail: "directory contains an unsafe component",
                    });
                }
            }
        }
        Ok(descriptor)
    }

    fn open_at(directory: libc::c_int, name: &std::ffi::CStr) -> io::Result<OwnedFd> {
        // SAFETY: directory is AT_FDCWD or a live directory descriptor, name is
        // NUL-terminated, and no creation flag requires a mode argument.
        let descriptor = unsafe {
            libc::openat(
                directory,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returned one newly owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn inspect_directory(
        directory: &Path,
        descriptor: libc::c_int,
    ) -> Result<DirectoryIdentity, FileObservationError> {
        let mut metadata = mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: descriptor is live and metadata has writable storage for one stat.
        if unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
            return Err(FileObservationError::InspectDirectory {
                directory: directory.to_owned(),
                source: io::Error::last_os_error(),
            });
        }
        // SAFETY: successful fstat initialized the complete stat value.
        let metadata = unsafe { metadata.assume_init() };
        Ok(DirectoryIdentity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        })
    }

    fn deadline_after(now: Instant, duration: Duration) -> Instant {
        now.checked_add(duration).unwrap_or(now)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn desired_paths_coalesce_names_and_fact_kinds_by_parent_directory() {
            let paths = FileObservationPaths::new(
                "/data/adb/flux/conf/flux.toml",
                "/data/adb/flux/conf/template.json",
                "/data/adb/flux/conf/subscription-url.txt",
                "/data/adb/flux/conf/flux.toml",
            );

            let desired = desired_directories(&paths).expect("valid observed paths");

            assert_eq!(desired.len(), 1);
            let directory = desired
                .get(Path::new("/data/adb/flux/conf"))
                .expect("coalesced parent directory");
            assert_eq!(directory.targets.len(), 3);
            let shared = directory
                .targets
                .get(OsStr::new("flux.toml"))
                .copied()
                .expect("shared target");
            assert!(shared.configuration_inputs());
            assert!(shared.disable_state());
        }

        #[test]
        fn observed_paths_must_be_absolute_files_without_parent_traversal() {
            for path in ["flux.toml", "/", "/data/../flux.toml"] {
                assert!(
                    split_observed_path(Path::new(path)).is_err(),
                    "{path} must be rejected"
                );
            }
        }

        #[test]
        fn queue_overflow_requests_both_authoritative_state_reads() {
            let directory = tempfile::tempdir().expect("temporary directory");
            let paths = FileObservationPaths::new(
                directory.path().join("flux.toml"),
                directory.path().join("template.json"),
                directory.path().join("url.txt"),
                directory.path().join("disable"),
            );
            let now = Instant::now();
            let (mut driver, issues) =
                FileObserverDriver::open(&paths, now).expect("open observer");
            assert!(issues.is_empty());
            let mut report = FileObservationDriveReport::default();

            driver.classify_event(-1, libc::IN_Q_OVERFLOW, OsStr::new(""), now, &mut report);

            assert!(report.observation.configuration_inputs_changed());
            assert!(report.observation.disable_state_changed());
            assert_eq!(driver.next_deadline(), now);
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use implementation::{FileObservationDriveReport, FileObserverDriver};
