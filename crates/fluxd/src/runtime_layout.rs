use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use flux_core::EngineCredentials;

const RUNTIME_DIRECTORY_MODE: libc::mode_t = 0o700;
const ENGINE_TRAVERSAL_DIRECTORY_MODE: libc::mode_t = 0o710;
const ENGINE_WORK_DIRECTORY_NAME: &str = "engine";
const MAX_RUNTIME_ROOT_BYTES: usize = 4_096;
const MAX_RUNTIME_ROOT_COMPONENTS: usize = 64;
const MAX_RUNTIME_COMPONENT_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeLayoutErrorKind {
    UnsafePath,
    Symlink,
    UnexpectedFileType,
    UnsafeMetadata,
    UnexpectedOwnedPath,
    Io,
}

#[derive(Debug)]
pub enum RuntimeLayoutError {
    UnsafePath(PathBuf),
    Symlink(PathBuf),
    UnexpectedFileType(PathBuf),
    UnsafeMetadata {
        path: PathBuf,
        reason: &'static str,
    },
    UnexpectedOwnedPath {
        label: &'static str,
        path: PathBuf,
        parent: PathBuf,
    },
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

impl RuntimeLayoutError {
    #[must_use]
    pub const fn kind(&self) -> RuntimeLayoutErrorKind {
        match self {
            Self::UnsafePath(_) => RuntimeLayoutErrorKind::UnsafePath,
            Self::Symlink(_) => RuntimeLayoutErrorKind::Symlink,
            Self::UnexpectedFileType(_) => RuntimeLayoutErrorKind::UnexpectedFileType,
            Self::UnsafeMetadata { .. } => RuntimeLayoutErrorKind::UnsafeMetadata,
            Self::UnexpectedOwnedPath { .. } => RuntimeLayoutErrorKind::UnexpectedOwnedPath,
            Self::Io { .. } => RuntimeLayoutErrorKind::Io,
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

impl fmt::Display for RuntimeLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafePath(path) => {
                write!(formatter, "runtime root path is unsafe: {}", path.display())
            }
            Self::Symlink(path) => write!(
                formatter,
                "runtime layout must not traverse or name a symbolic link: {}",
                path.display()
            ),
            Self::UnexpectedFileType(path) => write!(
                formatter,
                "runtime layout path is not a directory: {}",
                path.display()
            ),
            Self::UnsafeMetadata { path, reason } => write!(
                formatter,
                "runtime layout path has unsafe metadata ({}): {reason}",
                path.display()
            ),
            Self::UnexpectedOwnedPath {
                label,
                path,
                parent,
            } => write!(
                formatter,
                "{label} path {} must be a direct child of {}",
                path.display(),
                parent.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "cannot {operation} {}: {source}", path.display()),
        }
    }
}

impl Error for RuntimeLayoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::UnsafePath(_)
            | Self::Symlink(_)
            | Self::UnexpectedFileType(_)
            | Self::UnsafeMetadata { .. }
            | Self::UnexpectedOwnedPath { .. } => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RuntimeLayout {
    root_path: PathBuf,
    run_path: PathBuf,
    state_path: PathBuf,
    root_directory: File,
    run_directory: File,
    state_directory: File,
}

impl RuntimeLayout {
    pub(crate) fn bootstrap(root_path: &Path) -> Result<Self, RuntimeLayoutError> {
        validate_absolute_path(root_path)?;
        let root_directory = open_absolute_directory(root_path)?;
        require_owned_secure_directory(&root_directory, root_path, false)?;

        let run_path = root_path.join("run");
        let state_path = root_path.join("state");
        let run_directory = open_or_create_owned_directory(&root_directory, "run", &run_path)?;
        let state_directory =
            open_or_create_owned_directory(&root_directory, "state", &state_path)?;

        Ok(Self {
            root_path: root_path.to_owned(),
            run_path,
            state_path,
            root_directory,
            run_directory,
            state_directory,
        })
    }

    #[must_use]
    pub(crate) fn root_path(&self) -> &Path {
        &self.root_path
    }

    #[must_use]
    pub(crate) fn run_path(&self) -> &Path {
        &self.run_path
    }

    #[must_use]
    pub(crate) fn state_path(&self) -> &Path {
        &self.state_path
    }

    #[must_use]
    pub(crate) fn runtime_log_path(&self) -> PathBuf {
        self.run_path.join("flux.log")
    }

    #[must_use]
    pub(crate) fn daemon_log_path(&self) -> PathBuf {
        self.run_path.join("fluxd.log")
    }

    pub(crate) fn clone_run_directory(&self) -> Result<File, RuntimeLayoutError> {
        self.run_directory
            .try_clone()
            .map_err(|source| Self::clone_directory_error(&self.run_path, source))
    }

    /// Grants one exact reviewed engine credential a search-only corridor to its private working
    /// directory and to the subscription asset store. No shared daemon directory becomes writable.
    pub(crate) fn bind_reviewed_engine_runtime(
        &self,
        credentials: EngineCredentials,
    ) -> Result<PathBuf, RuntimeLayoutError> {
        let uid = credentials.uid().get();
        let gid = credentials.gid().get();
        if uid == 0 || gid == 0 {
            return Err(RuntimeLayoutError::UnsafeMetadata {
                path: self.root_path.clone(),
                reason: "reviewed engine runtime credentials must be non-root",
            });
        }
        require_engine_traversal_prebinding(
            &self.root_directory,
            &self.root_path,
            gid,
            TraversalPrebinding::SecureRoot,
        )?;
        for (directory, directory_path) in [
            (&self.run_directory, self.run_path.as_path()),
            (&self.state_directory, self.state_path.as_path()),
        ] {
            require_engine_traversal_prebinding(
                directory,
                directory_path,
                gid,
                TraversalPrebinding::PrivateDirectory,
            )?;
        }
        let path = self.run_path.join(ENGINE_WORK_DIRECTORY_NAME);
        open_or_create_engine_work_directory(&self.run_directory, &path, uid, gid)?;
        bind_engine_traversal(
            &self.root_directory,
            &self.root_path,
            gid,
            TraversalPrebinding::SecureRoot,
        )?;
        for (directory, directory_path) in [
            (&self.run_directory, self.run_path.as_path()),
            (&self.state_directory, self.state_path.as_path()),
        ] {
            bind_engine_traversal(
                directory,
                directory_path,
                gid,
                TraversalPrebinding::PrivateDirectory,
            )?;
        }
        Ok(path)
    }

    pub(crate) fn require_run_child(
        &self,
        label: &'static str,
        path: &Path,
    ) -> Result<(), RuntimeLayoutError> {
        require_direct_child(label, path, &self.run_path)
    }

    pub(crate) fn require_state_child(
        &self,
        label: &'static str,
        path: &Path,
    ) -> Result<(), RuntimeLayoutError> {
        require_direct_child(label, path, &self.state_path)
    }

    fn clone_directory_error(path: &Path, source: io::Error) -> RuntimeLayoutError {
        RuntimeLayoutError::io("duplicate runtime directory descriptor", path, source)
    }
}

fn require_direct_child(
    label: &'static str,
    path: &Path,
    expected_parent: &Path,
) -> Result<(), RuntimeLayoutError> {
    if path.parent() == Some(expected_parent) && path.file_name().is_some() {
        Ok(())
    } else {
        Err(RuntimeLayoutError::UnexpectedOwnedPath {
            label,
            path: path.to_owned(),
            parent: expected_parent.to_owned(),
        })
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), RuntimeLayoutError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() > MAX_RUNTIME_ROOT_BYTES
        || path.components().count() > MAX_RUNTIME_ROOT_COMPONENTS
    {
        return Err(RuntimeLayoutError::UnsafePath(path.to_owned()));
    }
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name)
                if !name.as_bytes().is_empty()
                    && name.as_bytes().len() <= MAX_RUNTIME_COMPONENT_BYTES
                    && !name.as_bytes().contains(&0) => {}
            Component::Normal(_)
            | Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_) => {
                return Err(RuntimeLayoutError::UnsafePath(path.to_owned()));
            }
        }
    }
    Ok(())
}

fn open_absolute_directory(path: &Path) -> Result<File, RuntimeLayoutError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let mut directory = options.open("/").map_err(|source| {
        RuntimeLayoutError::io(
            "open filesystem root for runtime layout",
            Path::new("/"),
            source,
        )
    })?;
    let mut walked = PathBuf::from("/");
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        walked.push(name);
        let name = component_name(name, &walked)?;
        directory = open_directory_at(directory.as_raw_fd(), &name).map_err(|source| {
            classify_component_error(directory.as_raw_fd(), &name, &walked, source)
        })?;
    }
    Ok(directory)
}

fn open_or_create_owned_directory(
    root: &File,
    name: &str,
    path: &Path,
) -> Result<File, RuntimeLayoutError> {
    let name = component_name(OsStr::new(name), path)?;
    let mut created = false;
    match entry_kind(root.as_raw_fd(), &name)
        .map_err(|source| RuntimeLayoutError::io("inspect runtime directory", path, source))?
    {
        Some(EntryKind::Directory) => {}
        Some(EntryKind::Symlink) => return Err(RuntimeLayoutError::Symlink(path.to_owned())),
        Some(EntryKind::Other) => {
            return Err(RuntimeLayoutError::UnexpectedFileType(path.to_owned()));
        }
        None => {
            // SAFETY: `root` is an open directory and `name` is one validated NUL-terminated
            // component. `mkdirat` does not retain either pointer.
            if unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), RUNTIME_DIRECTORY_MODE) }
                != 0
            {
                let source = io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EEXIST) {
                    return Err(RuntimeLayoutError::io(
                        "create runtime directory",
                        path,
                        source,
                    ));
                }
            } else {
                created = true;
            }
        }
    }

    let directory = open_directory_at(root.as_raw_fd(), &name)
        .map_err(|source| classify_component_error(root.as_raw_fd(), &name, path, source))?;
    require_owned_secure_directory(&directory, path, true)?;
    if created {
        root.sync_all().map_err(|source| {
            RuntimeLayoutError::io("sync runtime root directory", path, source)
        })?;
    }
    Ok(directory)
}

fn require_owned_secure_directory(
    directory: &File,
    path: &Path,
    enforce_exact_mode: bool,
) -> Result<(), RuntimeLayoutError> {
    let metadata = directory
        .metadata()
        .map_err(|source| RuntimeLayoutError::io("inspect runtime directory", path, source))?;
    if !metadata.is_dir() {
        return Err(RuntimeLayoutError::UnexpectedFileType(path.to_owned()));
    }
    // SAFETY: `geteuid` has no preconditions and does not retain state.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "directory is not owned by the daemon effective user",
        });
    }
    let mode = metadata.mode() & 0o777;
    if enforce_exact_mode && mode != RUNTIME_DIRECTORY_MODE {
        // SAFETY: `directory` owns a valid directory descriptor and `fchmod` does not retain it.
        if unsafe { libc::fchmod(directory.as_raw_fd(), RUNTIME_DIRECTORY_MODE) } != 0 {
            return Err(RuntimeLayoutError::io(
                "set runtime directory mode",
                path,
                io::Error::last_os_error(),
            ));
        }
        directory
            .sync_all()
            .map_err(|source| RuntimeLayoutError::io("sync runtime directory", path, source))?;
    } else if !enforce_exact_mode && mode & 0o022 != 0 {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "runtime root is group- or other-writable",
        });
    }
    Ok(())
}

fn bind_engine_traversal(
    directory: &File,
    path: &Path,
    engine_gid: libc::gid_t,
    prebinding: TraversalPrebinding,
) -> Result<(), RuntimeLayoutError> {
    require_engine_traversal_prebinding(directory, path, engine_gid, prebinding)?;
    let metadata = directory.metadata().map_err(|source| {
        RuntimeLayoutError::io("inspect engine traversal directory", path, source)
    })?;
    if metadata.gid() == engine_gid && metadata.mode() & 0o777 == ENGINE_TRAVERSAL_DIRECTORY_MODE {
        return Ok(());
    }
    if metadata.gid() != engine_gid {
        // SAFETY: the descriptor denotes the exact no-follow directory inspected above; uid -1
        // preserves root/daemon ownership while binding only its group to the reviewed engine.
        if unsafe { libc::fchown(directory.as_raw_fd(), u32::MAX, engine_gid) } != 0 {
            return Err(RuntimeLayoutError::io(
                "bind engine traversal directory group",
                path,
                io::Error::last_os_error(),
            ));
        }
    }
    if metadata.mode() & 0o777 != ENGINE_TRAVERSAL_DIRECTORY_MODE {
        // SAFETY: the descriptor denotes the exact directory and `fchmod` retains no pointer.
        if unsafe { libc::fchmod(directory.as_raw_fd(), ENGINE_TRAVERSAL_DIRECTORY_MODE) } != 0 {
            return Err(RuntimeLayoutError::io(
                "set engine traversal directory mode",
                path,
                io::Error::last_os_error(),
            ));
        }
    }
    directory.sync_all().map_err(|source| {
        RuntimeLayoutError::io("sync engine traversal directory", path, source)
    })?;
    let metadata = directory.metadata().map_err(|source| {
        RuntimeLayoutError::io("reinspect engine traversal directory", path, source)
    })?;
    // SAFETY: `geteuid` has no preconditions and reads only the caller identity.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid
        || metadata.gid() != engine_gid
        || metadata.mode() & 0o777 != ENGINE_TRAVERSAL_DIRECTORY_MODE
    {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "engine traversal directory metadata changed during binding",
        });
    }
    Ok(())
}

fn require_engine_traversal_prebinding(
    directory: &File,
    path: &Path,
    engine_gid: libc::gid_t,
    prebinding: TraversalPrebinding,
) -> Result<(), RuntimeLayoutError> {
    let metadata = directory.metadata().map_err(|source| {
        RuntimeLayoutError::io("inspect engine traversal directory", path, source)
    })?;
    // SAFETY: `geteuid` has no preconditions and reads only the caller identity.
    let effective_uid = unsafe { libc::geteuid() };
    // SAFETY: `getegid` has no preconditions and reads only the caller identity.
    let effective_gid = unsafe { libc::getegid() };
    if !metadata.is_dir() || metadata.uid() != effective_uid {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "engine traversal directory is not owned by the daemon effective user",
        });
    }
    if metadata.gid() == engine_gid && metadata.mode() & 0o777 == ENGINE_TRAVERSAL_DIRECTORY_MODE {
        return Ok(());
    }
    let mode = metadata.mode() & 0o777;
    let prebinding_mode_is_safe = match prebinding {
        TraversalPrebinding::SecureRoot => {
            mode != ENGINE_TRAVERSAL_DIRECTORY_MODE && mode & 0o022 == 0
        }
        TraversalPrebinding::PrivateDirectory => mode == RUNTIME_DIRECTORY_MODE,
    };
    if !prebinding_mode_is_safe
        || (metadata.gid() != effective_gid && metadata.gid() != engine_gid && metadata.gid() != 0)
    {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "engine traversal directory has noncanonical pre-binding metadata",
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum TraversalPrebinding {
    SecureRoot,
    PrivateDirectory,
}

fn open_or_create_engine_work_directory(
    run: &File,
    path: &Path,
    engine_uid: libc::uid_t,
    engine_gid: libc::gid_t,
) -> Result<File, RuntimeLayoutError> {
    let name = component_name(OsStr::new(ENGINE_WORK_DIRECTORY_NAME), path)?;
    let mut created = false;
    match entry_kind(run.as_raw_fd(), &name)
        .map_err(|source| RuntimeLayoutError::io("inspect engine work directory", path, source))?
    {
        Some(EntryKind::Directory) => {}
        Some(EntryKind::Symlink) => return Err(RuntimeLayoutError::Symlink(path.to_owned())),
        Some(EntryKind::Other) => {
            return Err(RuntimeLayoutError::UnexpectedFileType(path.to_owned()));
        }
        None => {
            // SAFETY: `run` and `name` are validated no-follow directory/name anchors.
            if unsafe { libc::mkdirat(run.as_raw_fd(), name.as_ptr(), RUNTIME_DIRECTORY_MODE) } != 0
            {
                let source = io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::EEXIST) {
                    return Err(RuntimeLayoutError::io(
                        "create engine work directory",
                        path,
                        source,
                    ));
                }
            } else {
                created = true;
            }
        }
    }
    let directory = open_directory_at(run.as_raw_fd(), &name)
        .map_err(|source| classify_component_error(run.as_raw_fd(), &name, path, source))?;
    let metadata = directory
        .metadata()
        .map_err(|source| RuntimeLayoutError::io("inspect engine work directory", path, source))?;
    if !metadata.is_dir() {
        return Err(RuntimeLayoutError::UnexpectedFileType(path.to_owned()));
    }
    // SAFETY: `geteuid` reads only the current process identity.
    let effective_uid = unsafe { libc::geteuid() };
    if !created
        && (metadata.uid() != engine_uid
            || metadata.gid() != engine_gid
            || metadata.mode() & 0o777 != RUNTIME_DIRECTORY_MODE)
    {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "existing engine work directory has noncanonical metadata",
        });
    }
    if created && metadata.uid() != effective_uid {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "new engine work directory is not owned by the daemon effective user",
        });
    }
    // SAFETY: the exact directory descriptor is owned here and both scalar IDs were admitted by
    // Flux's reviewed credential authority.
    if created
        && (metadata.uid() != engine_uid || metadata.gid() != engine_gid)
        // SAFETY: `directory` is the exact newly created no-follow directory descriptor.
        && unsafe { libc::fchown(directory.as_raw_fd(), engine_uid, engine_gid) } != 0
    {
        return Err(RuntimeLayoutError::io(
            "assign engine work directory ownership",
            path,
            io::Error::last_os_error(),
        ));
    }
    if created
        && metadata.mode() & 0o777 != RUNTIME_DIRECTORY_MODE
        // SAFETY: `directory` is the exact newly created no-follow directory descriptor.
        && unsafe { libc::fchmod(directory.as_raw_fd(), RUNTIME_DIRECTORY_MODE) } != 0
    {
        return Err(RuntimeLayoutError::io(
            "set engine work directory mode",
            path,
            io::Error::last_os_error(),
        ));
    }
    let metadata = directory.metadata().map_err(|source| {
        RuntimeLayoutError::io("reinspect engine work directory", path, source)
    })?;
    if metadata.uid() != engine_uid
        || metadata.gid() != engine_gid
        || metadata.mode() & 0o777 != RUNTIME_DIRECTORY_MODE
    {
        return Err(RuntimeLayoutError::UnsafeMetadata {
            path: path.to_owned(),
            reason: "engine work directory metadata changed during binding",
        });
    }
    directory
        .sync_all()
        .map_err(|source| RuntimeLayoutError::io("sync engine work directory", path, source))?;
    run.sync_all()
        .map_err(|source| RuntimeLayoutError::io("sync runtime directory", path, source))?;
    Ok(directory)
}

fn component_name(name: &OsStr, path: &Path) -> Result<CString, RuntimeLayoutError> {
    CString::new(name.as_bytes()).map_err(|_| RuntimeLayoutError::UnsafePath(path.to_owned()))
}

fn open_directory_at(directory: RawFd, name: &CString) -> io::Result<File> {
    // SAFETY: `directory` is an open directory and `name` is a validated NUL-terminated component.
    let descriptor = unsafe {
        libc::openat(
            directory,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful `openat` returned one new owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn classify_component_error(
    directory: RawFd,
    name: &CString,
    path: &Path,
    source: io::Error,
) -> RuntimeLayoutError {
    if matches!(
        source.raw_os_error(),
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
    ) {
        return match entry_kind(directory, name) {
            Ok(Some(EntryKind::Symlink)) => RuntimeLayoutError::Symlink(path.to_owned()),
            Ok(Some(EntryKind::Directory)) => {
                RuntimeLayoutError::io("open runtime directory", path, source)
            }
            Ok(Some(EntryKind::Other)) => RuntimeLayoutError::UnexpectedFileType(path.to_owned()),
            Ok(None) | Err(_) => RuntimeLayoutError::io("open runtime directory", path, source),
        };
    }
    RuntimeLayoutError::io("open runtime directory", path, source)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Directory,
    Symlink,
    Other,
}

fn entry_kind(directory: RawFd, name: &CString) -> io::Result<Option<EntryKind>> {
    let mut metadata = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `directory` is open, `name` is NUL-terminated, and `metadata` is writable for one
    // `stat` value. `AT_SYMLINK_NOFOLLOW` inspects the entry rather than its target.
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
        Ok(Some(if file_type == libc::S_IFDIR {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_creates_only_exact_private_runtime_directories() {
        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");

        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");
        RuntimeLayout::bootstrap(&root).expect("bootstrap is idempotent");

        assert_eq!(layout.root_path(), root);
        assert_eq!(layout.run_path(), root.join("run"));
        assert_eq!(layout.state_path(), root.join("state"));
        assert_eq!(layout.runtime_log_path(), root.join("run/flux.log"));
        assert_eq!(layout.daemon_log_path(), root.join("run/fluxd.log"));
        assert_eq!(
            std::fs::metadata(layout.run_path()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(layout.state_path()).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            2,
            "bootstrap must not invent configuration or runtime files"
        );
    }

    #[test]
    fn bootstrap_rejects_relative_parent_and_non_directory_paths() {
        assert_eq!(
            RuntimeLayout::bootstrap(Path::new("relative/root"))
                .expect_err("relative root must fail")
                .kind(),
            RuntimeLayoutErrorKind::UnsafePath
        );

        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        std::fs::write(root.join("run"), "not a directory\n").expect("write hostile run path");
        assert_eq!(
            RuntimeLayout::bootstrap(&root)
                .expect_err("non-directory run path must fail")
                .kind(),
            RuntimeLayoutErrorKind::UnexpectedFileType
        );
        assert!(!root.join("state").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_rejects_final_and_ancestor_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let target = directory.path().join("target");
        let root = target.join("flux");
        std::fs::create_dir_all(&root).expect("create target root");
        let linked_root = directory.path().join("linked-root");
        symlink(&root, &linked_root).expect("link final root");
        assert_eq!(
            RuntimeLayout::bootstrap(&linked_root)
                .expect_err("final root symlink must fail")
                .kind(),
            RuntimeLayoutErrorKind::Symlink
        );

        let linked_ancestor = directory.path().join("linked-ancestor");
        symlink(&target, &linked_ancestor).expect("link root ancestor");
        assert_eq!(
            RuntimeLayout::bootstrap(&linked_ancestor.join("flux"))
                .expect_err("ancestor root symlink must fail")
                .kind(),
            RuntimeLayoutErrorKind::Symlink
        );

        symlink(directory.path(), root.join("run")).expect("link run directory");
        assert_eq!(
            RuntimeLayout::bootstrap(&root)
                .expect_err("run symlink must fail")
                .kind(),
            RuntimeLayoutErrorKind::Symlink
        );
    }

    #[test]
    fn owned_runtime_paths_must_be_direct_children() {
        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");

        layout
            .require_run_child("daemon lease", &root.join("run/fluxd.lease"))
            .expect("direct run child");
        layout
            .require_state_child("intent", &root.join("state/intent.json"))
            .expect("direct state child");
        assert_eq!(
            layout
                .require_run_child("daemon lease", &root.join("other/fluxd.lease"))
                .expect_err("foreign parent must fail")
                .kind(),
            RuntimeLayoutErrorKind::UnexpectedOwnedPath
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn reviewed_engine_binding_opens_only_a_search_corridor_and_private_work_directory() {
        use flux_core::{CaptureGroupId, CaptureUserId};
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");
        // The current unprivileged test identity is a safe stand-in for the reviewed engine role;
        // this test verifies exact metadata shape, while the Android qualification exercises the
        // distinct UID/GID transition.
        // SAFETY: these calls read only the current test-process identity.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: this call reads only the current test-process identity.
        let gid = unsafe { libc::getegid() };
        let credentials = EngineCredentials::new(
            CaptureUserId::new(uid).expect("non-root fixture UID"),
            CaptureGroupId::new(gid).expect("non-root fixture GID"),
        );

        let work = layout
            .bind_reviewed_engine_runtime(credentials)
            .expect("bind reviewed engine runtime");

        let run = root.join("run");
        let state = root.join("state");
        for path in [&root, &run, &state] {
            let metadata = std::fs::metadata(path).expect("traversal metadata");
            assert_eq!(metadata.uid(), uid);
            assert_eq!(metadata.gid(), gid);
            assert_eq!(metadata.mode() & 0o777, 0o710);
        }
        let work_metadata = std::fs::metadata(&work).expect("engine work metadata");
        assert_eq!(work, root.join("run/engine"));
        assert_eq!(work_metadata.uid(), uid);
        assert_eq!(work_metadata.gid(), gid);
        assert_eq!(work_metadata.mode() & 0o777, 0o700);

        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o710))
            .expect("inject engine work mode drift");
        assert_eq!(
            layout
                .bind_reviewed_engine_runtime(credentials)
                .expect_err("existing engine work metadata drift must fail closed")
                .kind(),
            RuntimeLayoutErrorKind::UnsafeMetadata
        );
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700))
            .expect("restore engine work mode");

        let other_gid = if gid == 1 { 2 } else { 1 };
        let wrong_group = EngineCredentials::new(
            CaptureUserId::new(uid).expect("fixture UID"),
            CaptureGroupId::new(other_gid).expect("different non-root fixture GID"),
        );
        assert_eq!(
            layout
                .bind_reviewed_engine_runtime(wrong_group)
                .expect_err("wrong engine GID must not rewrite an existing work directory")
                .kind(),
            RuntimeLayoutErrorKind::UnsafeMetadata
        );
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn root_engine_credentials_are_rejected_before_creating_a_work_directory() {
        use flux_core::{CaptureGroupId, CaptureUserId};

        let directory = tempfile::tempdir().expect("runtime layout fixture");
        let root = directory.path().join("flux");
        std::fs::create_dir(&root).expect("create runtime root");
        let layout = RuntimeLayout::bootstrap(&root).expect("bootstrap runtime layout");
        // SAFETY: this call reads only the current test-process identity.
        let gid = unsafe { libc::getegid() };
        let root_credentials = EngineCredentials::new(
            CaptureUserId::new(0).expect("root UID is representable"),
            CaptureGroupId::new(gid).expect("fixture GID"),
        );

        assert_eq!(
            layout
                .bind_reviewed_engine_runtime(root_credentials)
                .expect_err("root credentials must be rejected")
                .kind(),
            RuntimeLayoutErrorKind::UnsafeMetadata
        );
        assert!(!root.join("run/engine").exists());
        for path in [root.join("run"), root.join("state")] {
            assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o700);
        }
    }
}
