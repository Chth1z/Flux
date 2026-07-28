use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use flux_core::{
    BootIdentity, CapabilityProfile, CapabilityProfileSource, KernelFacts, KernelRelease,
    LegacyBridgeFacts, MAX_BOOT_IDENTITY_BYTES, Observation, SelinuxMode,
};

use crate::android_identity::observe_system_android_device_identity;
use crate::{PlatformError, system_kernel_release};

const DEFAULT_BOOT_IDENTITY_PATH: &str = "/proc/sys/kernel/random/boot_id";
const DEFAULT_SELINUX_ENFORCE_PATH: &str = "/sys/fs/selinux/enforce";
const MAX_SELINUX_ENFORCE_BYTES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityProfilePaths {
    boot_identity: PathBuf,
    selinux_enforce: PathBuf,
}

impl CapabilityProfilePaths {
    #[must_use]
    pub fn new(boot_identity: impl Into<PathBuf>, selinux_enforce: impl Into<PathBuf>) -> Self {
        Self {
            boot_identity: boot_identity.into(),
            selinux_enforce: selinux_enforce.into(),
        }
    }
}

impl Default for CapabilityProfilePaths {
    fn default() -> Self {
        Self::new(DEFAULT_BOOT_IDENTITY_PATH, DEFAULT_SELINUX_ENFORCE_PATH)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SystemCapabilityProfileSource {
    paths: CapabilityProfilePaths,
}

impl SystemCapabilityProfileSource {
    #[must_use]
    pub const fn new(paths: CapabilityProfilePaths) -> Self {
        Self { paths }
    }
}

impl CapabilityProfileSource for SystemCapabilityProfileSource {
    fn collect_capability_profile(&self) -> CapabilityProfile {
        let kernel = KernelFacts::from_release(observe_kernel_release());
        let boot_identity = observe_text(&self.paths.boot_identity, MAX_BOOT_IDENTITY_BYTES)
            .and_then(|value| {
                BootIdentity::parse(&value).map_or(Observation::Malformed, Observation::Verified)
            });
        let selinux = observe_text(&self.paths.selinux_enforce, MAX_SELINUX_ENFORCE_BYTES)
            .and_then(|value| match value.trim() {
                "1" => Observation::Verified(SelinuxMode::Enforcing),
                "0" => Observation::Verified(SelinuxMode::Permissive),
                _ => Observation::Malformed,
            });
        let legacy_bridge = LegacyBridgeFacts::new(
            Observation::Absent,
            Observation::Absent,
            Observation::Absent,
        );

        CapabilityProfile::initial(
            boot_identity,
            observe_system_android_device_identity(),
            kernel,
            selinux,
            legacy_bridge,
        )
    }
}

fn observe_kernel_release() -> Observation<KernelRelease> {
    match system_kernel_release() {
        Ok(release) => {
            KernelRelease::new(release).map_or(Observation::Malformed, Observation::Verified)
        }
        Err(PlatformError::InvalidKernelReleaseEncoding) => Observation::Malformed,
        Err(PlatformError::SystemCall { source, .. }) => observation_from_io_error(&source),
        Err(
            PlatformError::UnsupportedPlatform(_)
            | PlatformError::InvalidSocketPath(_)
            | PlatformError::PacketTooLarge { .. }
            | PlatformError::PeerClosed
            | PlatformError::PeerUidMismatch { .. }
            | PlatformError::ShortWrite { .. },
        ) => Observation::Unavailable,
    }
}

fn observe_text(path: &Path, limit: usize) -> Observation<String> {
    match read_bounded_regular_file(path, limit) {
        Ok(bytes) => String::from_utf8(bytes).map_or(Observation::Malformed, Observation::Verified),
        Err(failure) => failure.into_observation(),
    }
}

fn read_bounded_regular_file(path: &Path, limit: usize) -> Result<Vec<u8>, FactFailure> {
    let metadata = fs::symlink_metadata(path).map_err(FactFailure::from_io)?;
    // Reject stable special files before opening them. The descriptor-relative
    // check below remains authoritative if the path is replaced after this
    // metadata read.
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(FactFailure::Malformed);
    }

    let file = open_read_only_no_follow(path).map_err(FactFailure::from_open_io)?;
    if !file
        .metadata()
        .map_err(FactFailure::from_io)?
        .file_type()
        .is_file()
    {
        return Err(FactFailure::Malformed);
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1));
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(FactFailure::from_io)?;
    if bytes.len() > limit {
        return Err(FactFailure::Malformed);
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    fs::OpenOptions::new().read(true).open(path)
}

fn observation_from_io_error<T>(error: &std::io::Error) -> Observation<T> {
    match error.kind() {
        std::io::ErrorKind::NotFound => Observation::Absent,
        std::io::ErrorKind::PermissionDenied => Observation::Denied,
        _ => Observation::Unavailable,
    }
}

enum FactFailure {
    Absent,
    Denied,
    Malformed,
    Unavailable,
}

impl FactFailure {
    fn from_io(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::Absent,
            std::io::ErrorKind::PermissionDenied => Self::Denied,
            _ => Self::Unavailable,
        }
    }

    fn from_open_io(error: std::io::Error) -> Self {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Self::Malformed;
        }
        Self::from_io(error)
    }

    fn into_observation<T>(self) -> Observation<T> {
        match self {
            Self::Absent => Observation::Absent,
            Self::Denied => Observation::Denied,
            Self::Malformed => Observation::Malformed,
            Self::Unavailable => Observation::Unavailable,
        }
    }
}
