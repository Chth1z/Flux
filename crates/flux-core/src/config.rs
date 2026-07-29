use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::io::Read;
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};
use std::path::{Path, PathBuf};
use std::str;
use std::time::Duration;

use serde::Deserialize;

use crate::capture_program::{
    CaptureApplicationMode, CaptureBypassPolicy, CaptureInterfacePolicy, CaptureInterfaceSelector,
    CaptureIpPrefix, CaptureProtocolSet, CaptureTrafficScope, EngineCredentials,
    MAX_CAPTURE_INTERFACE_SELECTORS, MAX_CAPTURE_POLICY_PREFIX_INPUTS,
};
use crate::network_inventory::InterfaceName;
use crate::{
    AddressHostFamilySelection, CaptureGroupId, CapturePathId, CapturePathRequest, CaptureUserId,
};

const SUPPORTED_SCHEMA: u16 = 4;
/// Maximum UTF-8 byte length accepted by the Phase-1 configuration seam.
pub const MAX_CONFIG_DOCUMENT_BYTES: usize = 64 * 1_024;
const LOAD_READ_LIMIT: u64 = MAX_CONFIG_DOCUMENT_BYTES as u64 + 1;
const MAX_ABSOLUTE_PATH_BYTES: usize = 4_096;
const MAX_ANDROID_PACKAGE_NAME_BYTES: usize = 255;
const MAX_ANDROID_PACKAGES: usize = 4_096;
const MAX_ANDROID_USER_ID: u16 = 999;
const MAX_ANDROID_USER_IDS: usize = 100;
const MAX_ENGINE_TIMEOUT_MS: u32 = 60_000;
const MAX_RESTART_ATTEMPTS: u32 = 100;
const MAX_RESTART_DURATION_MS: u32 = 3_600_000;
const MAX_SUBSCRIPTION_INTERVAL_SECS: u32 = 31_536_000;
const MAX_SUBSCRIPTION_TIMEOUT_SECS: u32 = 300;
const MIN_SUBSCRIPTION_BYTES: u32 = 1_024;
const MAX_SUBSCRIPTION_BYTES: u32 = 64 * 1_024 * 1_024;
const MAX_SUBSCRIPTION_NODES: u32 = 100_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FluxConfig {
    schema: u16,
    daemon: DaemonConfig,
    engine: EngineConfig,
    capture: CaptureConfig,
    listener: ListenerConfig,
    applications: ApplicationConfig,
    interfaces: InterfaceConfig,
    bypass: BypassConfig,
    subscription: SubscriptionConfig,
    safety: SafetyConfig,
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
        let engine = EngineConfig::from_raw(raw.engine)?;
        let capture = CaptureConfig::from_raw(raw.capture)?;
        let listener = ListenerConfig::from_raw(raw.listener)?;
        let applications = ApplicationConfig::from_raw(raw.applications)?;
        let interfaces = InterfaceConfig::from_raw(raw.interfaces)?;
        let bypass = BypassConfig::from_raw(raw.bypass)?;
        let subscription = SubscriptionConfig::from_raw(raw.subscription)?;
        let safety = SafetyConfig::from_raw(raw.safety);
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
            engine,
            capture,
            listener,
            applications,
            interfaces,
            bypass,
            subscription,
            safety,
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

    #[must_use]
    pub const fn engine(&self) -> &EngineConfig {
        &self.engine
    }

    #[must_use]
    pub const fn capture(&self) -> &CaptureConfig {
        &self.capture
    }

    #[must_use]
    pub const fn listener(&self) -> ListenerConfig {
        self.listener
    }

    #[must_use]
    pub const fn applications(&self) -> &ApplicationConfig {
        &self.applications
    }

    #[must_use]
    pub const fn interfaces(&self) -> &InterfaceConfig {
        &self.interfaces
    }

    #[must_use]
    pub const fn bypass(&self) -> &BypassConfig {
        &self.bypass
    }

    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionConfig {
        &self.subscription
    }

    #[must_use]
    pub const fn safety(&self) -> SafetyConfig {
        self.safety
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EngineConfig {
    binary: PathBuf,
    template: PathBuf,
    credentials: EngineCredentials,
    startup_timeout: Duration,
    stop_timeout: Duration,
    restart: EngineRestartConfig,
}

impl EngineConfig {
    fn from_raw(raw: RawEngineConfig) -> Result<Self, ConfigError> {
        let runtime_uid = bounded_u32("engine.runtime_uid", raw.runtime_uid, 0, u32::MAX - 1)?;
        let runtime_gid = bounded_u32("engine.runtime_gid", raw.runtime_gid, 0, u32::MAX - 1)?;
        let uid = CaptureUserId::new(runtime_uid).ok_or(ConfigError::invalid_value(
            "engine.runtime_uid",
            "reserved UID",
        ))?;
        let gid = CaptureGroupId::new(runtime_gid).ok_or(ConfigError::invalid_value(
            "engine.runtime_gid",
            "reserved GID",
        ))?;
        let restart = EngineRestartConfig::from_raw(&raw)?;
        Ok(Self {
            binary: absolute_path("engine.binary", raw.binary)?,
            template: absolute_path("engine.template", raw.template)?,
            credentials: EngineCredentials::new(uid, gid),
            startup_timeout: bounded_duration_ms(
                "engine.startup_timeout_ms",
                raw.startup_timeout_ms,
                MAX_ENGINE_TIMEOUT_MS,
            )?,
            stop_timeout: bounded_duration_ms(
                "engine.stop_timeout_ms",
                raw.stop_timeout_ms,
                MAX_ENGINE_TIMEOUT_MS,
            )?,
            restart,
        })
    }

    #[must_use]
    pub fn binary(&self) -> &Path {
        &self.binary
    }

    #[must_use]
    pub fn template(&self) -> &Path {
        &self.template
    }

    #[must_use]
    pub const fn credentials(&self) -> EngineCredentials {
        self.credentials
    }

    #[must_use]
    pub const fn startup_timeout(&self) -> Duration {
        self.startup_timeout
    }

    #[must_use]
    pub const fn stop_timeout(&self) -> Duration {
        self.stop_timeout
    }

    #[must_use]
    pub const fn restart(&self) -> EngineRestartConfig {
        self.restart
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EngineRestartConfig {
    max_attempts: u32,
    window: Duration,
    initial_backoff: Duration,
    maximum_backoff: Duration,
    stable_reset: Duration,
}

impl EngineRestartConfig {
    fn from_raw(raw: &RawEngineConfig) -> Result<Self, ConfigError> {
        let max_attempts = bounded_u32(
            "engine.restart_max_attempts",
            raw.restart_max_attempts,
            1,
            MAX_RESTART_ATTEMPTS,
        )?;
        let window = bounded_duration_ms(
            "engine.restart_window_ms",
            raw.restart_window_ms,
            MAX_RESTART_DURATION_MS,
        )?;
        let initial_backoff = bounded_duration_ms(
            "engine.restart_initial_backoff_ms",
            raw.restart_initial_backoff_ms,
            MAX_RESTART_DURATION_MS,
        )?;
        let maximum_backoff = bounded_duration_ms(
            "engine.restart_maximum_backoff_ms",
            raw.restart_maximum_backoff_ms,
            MAX_RESTART_DURATION_MS,
        )?;
        if initial_backoff > maximum_backoff {
            return Err(ConfigError::invalid_value(
                "engine.restart_initial_backoff_ms",
                "must not exceed engine.restart_maximum_backoff_ms",
            ));
        }
        let stable_reset = bounded_duration_ms(
            "engine.restart_stable_reset_ms",
            raw.restart_stable_reset_ms,
            MAX_RESTART_DURATION_MS,
        )?;
        Ok(Self {
            max_attempts,
            window,
            initial_backoff,
            maximum_backoff,
            stable_reset,
        })
    }

    #[must_use]
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }

    #[must_use]
    pub const fn window(self) -> Duration {
        self.window
    }

    #[must_use]
    pub const fn initial_backoff(self) -> Duration {
        self.initial_backoff
    }

    #[must_use]
    pub const fn maximum_backoff(self) -> Duration {
        self.maximum_backoff
    }

    #[must_use]
    pub const fn stable_reset(self) -> Duration {
        self.stable_reset
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureConfig {
    path_request: CapturePathRequest,
    scope: CaptureTrafficScope,
    protocols: CaptureProtocolSet,
}

impl CaptureConfig {
    fn from_raw(raw: RawCaptureConfig) -> Result<Self, ConfigError> {
        let families = match (raw.ipv4, raw.ipv6) {
            (true, false) => AddressHostFamilySelection::Ipv4,
            (false, true) => AddressHostFamilySelection::Ipv6,
            (true, true) => AddressHostFamilySelection::DualStack,
            (false, false) => {
                return Err(ConfigError::invalid_value(
                    "capture.ipv4",
                    "at least one address family must be enabled",
                ));
            }
        };
        let scope = CaptureTrafficScope::new(families, raw.local_output, raw.forwarded_ingress)
            .map_err(|_| {
                ConfigError::invalid_value(
                    "capture.local_output",
                    "at least one traffic domain must be enabled",
                )
            })?;
        let protocols = CaptureProtocolSet::new(raw.tcp, raw.udp).map_err(|_| {
            ConfigError::invalid_value(
                "capture.tcp",
                "at least one transport protocol must be enabled",
            )
        })?;
        Ok(Self {
            path_request: match raw.path {
                RawCapturePathRequest::Auto => CapturePathRequest::Auto,
                RawCapturePathRequest::NftablesTproxy => {
                    CapturePathRequest::Exact(CapturePathId::NftablesTproxy)
                }
                RawCapturePathRequest::XtablesTproxy => {
                    CapturePathRequest::Exact(CapturePathId::XtablesTproxy)
                }
                RawCapturePathRequest::ManagedTun => {
                    CapturePathRequest::Exact(CapturePathId::ManagedTun)
                }
            },
            scope,
            protocols,
        })
    }

    #[must_use]
    pub const fn path_request(self) -> CapturePathRequest {
        self.path_request
    }

    #[must_use]
    pub const fn scope(self) -> CaptureTrafficScope {
        self.scope
    }

    #[must_use]
    pub const fn protocols(self) -> CaptureProtocolSet {
        self.protocols
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    port: NonZeroU16,
}

impl ListenerConfig {
    fn from_raw(raw: RawListenerConfig) -> Result<Self, ConfigError> {
        let port = u16::try_from(raw.port)
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or(ConfigError::value_out_of_range(
                "listener.port",
                raw.port,
                1,
                i64::from(u16::MAX),
            ))?;
        Ok(Self { port })
    }

    #[must_use]
    pub const fn port(self) -> NonZeroU16 {
        self.port
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AndroidPackageName(Box<str>);

impl AndroidPackageName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AndroidUserSelection {
    Owner,
    All,
    List(Box<[u16]>),
}

impl AndroidUserSelection {
    #[must_use]
    pub fn explicit_user_ids(&self) -> Option<&[u16]> {
        match self {
            Self::Owner | Self::All => None,
            Self::List(ids) => Some(ids),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationConfig {
    mode: CaptureApplicationMode,
    android_users: AndroidUserSelection,
    packages: Box<[AndroidPackageName]>,
}

impl ApplicationConfig {
    fn from_raw(raw: RawApplicationConfig) -> Result<Self, ConfigError> {
        let mode = match raw.mode {
            RawApplicationMode::All => CaptureApplicationMode::All,
            RawApplicationMode::Allowlist => CaptureApplicationMode::Allowlist,
            RawApplicationMode::Denylist => CaptureApplicationMode::Denylist,
        };
        let packages = parse_package_names(raw.packages)?;
        if mode == CaptureApplicationMode::All && !packages.is_empty() {
            return Err(ConfigError::invalid_value(
                "applications.packages",
                "must be empty when applications.mode is all",
            ));
        }
        let android_users = parse_android_users(raw.android_users, raw.user_ids)?;
        Ok(Self {
            mode,
            android_users,
            packages,
        })
    }

    #[must_use]
    pub const fn mode(&self) -> CaptureApplicationMode {
        self.mode
    }

    #[must_use]
    pub const fn android_users(&self) -> &AndroidUserSelection {
        &self.android_users
    }

    #[must_use]
    pub fn packages(&self) -> &[AndroidPackageName] {
        &self.packages
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    policy: CaptureInterfacePolicy,
}

impl InterfaceConfig {
    fn from_raw(raw: RawInterfaceConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            policy: parse_interface_policy(raw)?,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &CaptureInterfacePolicy {
        &self.policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BypassConfig {
    policy: CaptureBypassPolicy,
}

impl BypassConfig {
    fn from_raw(raw: RawBypassConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            policy: parse_bypass_policy(raw.cidrs)?,
        })
    }

    #[must_use]
    pub const fn policy(&self) -> &CaptureBypassPolicy {
        &self.policy
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionConfig {
    enabled: bool,
    url_file: PathBuf,
    update_interval: Duration,
    download_timeout: Duration,
    max_download_bytes: u32,
    max_decoded_bytes: u32,
    max_nodes: u32,
}

impl SubscriptionConfig {
    fn from_raw(raw: RawSubscriptionConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            enabled: raw.enabled,
            url_file: absolute_path("subscription.url_file", raw.url_file)?,
            update_interval: Duration::from_secs(u64::from(bounded_u32(
                "subscription.update_interval_secs",
                raw.update_interval_secs,
                0,
                MAX_SUBSCRIPTION_INTERVAL_SECS,
            )?)),
            download_timeout: Duration::from_secs(u64::from(bounded_u32(
                "subscription.download_timeout_secs",
                raw.download_timeout_secs,
                1,
                MAX_SUBSCRIPTION_TIMEOUT_SECS,
            )?)),
            max_download_bytes: bounded_u32(
                "subscription.max_download_bytes",
                raw.max_download_bytes,
                MIN_SUBSCRIPTION_BYTES,
                MAX_SUBSCRIPTION_BYTES,
            )?,
            max_decoded_bytes: bounded_u32(
                "subscription.max_decoded_bytes",
                raw.max_decoded_bytes,
                MIN_SUBSCRIPTION_BYTES,
                MAX_SUBSCRIPTION_BYTES,
            )?,
            max_nodes: bounded_u32(
                "subscription.max_nodes",
                raw.max_nodes,
                1,
                MAX_SUBSCRIPTION_NODES,
            )?,
        })
    }

    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    #[must_use]
    pub fn url_file(&self) -> &Path {
        &self.url_file
    }

    #[must_use]
    pub const fn update_interval(&self) -> Duration {
        self.update_interval
    }

    #[must_use]
    pub const fn download_timeout(&self) -> Duration {
        self.download_timeout
    }

    #[must_use]
    pub const fn max_download_bytes(&self) -> u32 {
        self.max_download_bytes
    }

    #[must_use]
    pub const fn max_decoded_bytes(&self) -> u32 {
        self.max_decoded_bytes
    }

    #[must_use]
    pub const fn max_nodes(&self) -> u32 {
        self.max_nodes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafetyConfig {
    respect_android_vpn: bool,
    require_functional_canary: bool,
}

impl SafetyConfig {
    const fn from_raw(raw: RawSafetyConfig) -> Self {
        Self {
            respect_android_vpn: raw.respect_android_vpn,
            require_functional_canary: raw.require_functional_canary,
        }
    }

    #[must_use]
    pub const fn respect_android_vpn(self) -> bool {
        self.respect_android_vpn
    }

    #[must_use]
    pub const fn require_functional_canary(self) -> bool {
        self.require_functional_canary
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
    InvalidValue {
        field: &'static str,
        detail: &'static str,
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
    InvalidValue {
        field: &'static str,
        detail: &'static str,
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
            ConfigErrorRepr::InvalidValue { field, detail } => {
                ConfigErrorKind::InvalidValue { field, detail }
            }
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

    fn invalid_value(field: &'static str, detail: &'static str) -> Self {
        Self(ConfigErrorRepr::InvalidValue { field, detail })
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
            ConfigErrorRepr::InvalidValue { field, detail } => {
                write!(
                    formatter,
                    "Flux configuration field {field} is invalid: {detail}"
                )
            }
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
            | ConfigErrorRepr::ValueOutOfRange { .. }
            | ConfigErrorRepr::InvalidValue { .. } => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFluxConfig {
    schema: i64,
    daemon: RawDaemonConfig,
    engine: RawEngineConfig,
    capture: RawCaptureConfig,
    listener: RawListenerConfig,
    applications: RawApplicationConfig,
    interfaces: RawInterfaceConfig,
    bypass: RawBypassConfig,
    subscription: RawSubscriptionConfig,
    safety: RawSafetyConfig,
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
#[serde(deny_unknown_fields)]
struct RawEngineConfig {
    binary: String,
    template: String,
    runtime_uid: i64,
    runtime_gid: i64,
    startup_timeout_ms: i64,
    stop_timeout_ms: i64,
    restart_max_attempts: i64,
    restart_window_ms: i64,
    restart_initial_backoff_ms: i64,
    restart_maximum_backoff_ms: i64,
    restart_stable_reset_ms: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCaptureConfig {
    path: RawCapturePathRequest,
    local_output: bool,
    forwarded_ingress: bool,
    ipv4: bool,
    ipv6: bool,
    tcp: bool,
    udp: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawCapturePathRequest {
    Auto,
    NftablesTproxy,
    XtablesTproxy,
    ManagedTun,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListenerConfig {
    port: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawApplicationConfig {
    mode: RawApplicationMode,
    android_users: RawAndroidUsers,
    user_ids: Vec<i64>,
    packages: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawApplicationMode {
    All,
    Allowlist,
    Denylist,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawAndroidUsers {
    Owner,
    All,
    List,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInterfaceConfig {
    forwarded_proxy: Vec<String>,
    local_bypass: Vec<String>,
    excluded: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBypassConfig {
    cidrs: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubscriptionConfig {
    enabled: bool,
    url_file: String,
    update_interval_secs: i64,
    download_timeout_secs: i64,
    max_download_bytes: i64,
    max_decoded_bytes: i64,
    max_nodes: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSafetyConfig {
    respect_android_vpn: bool,
    require_functional_canary: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum RawFailurePolicy {
    Open,
    Closed,
}

fn bounded_u32(
    field: &'static str,
    value: i64,
    minimum: u32,
    maximum: u32,
) -> Result<u32, ConfigError> {
    u32::try_from(value)
        .ok()
        .filter(|value| (minimum..=maximum).contains(value))
        .ok_or(ConfigError::value_out_of_range(
            field,
            value,
            i64::from(minimum),
            i64::from(maximum),
        ))
}

fn bounded_duration_ms(
    field: &'static str,
    value: i64,
    maximum: u32,
) -> Result<Duration, ConfigError> {
    bounded_u32(field, value, 1, maximum).map(|value| Duration::from_millis(u64::from(value)))
}

fn absolute_path(field: &'static str, value: String) -> Result<PathBuf, ConfigError> {
    if value.is_empty()
        || value.len() > MAX_ABSOLUTE_PATH_BYTES
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value.contains('\\')
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ConfigError::invalid_value(
            field,
            "expected a normalized absolute Android file path",
        ));
    }
    let path = PathBuf::from(&value);
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(ConfigError::invalid_value(
            field,
            "expected a normalized absolute Android file path",
        ));
    }
    Ok(path)
}

fn parse_package_names(raw: Vec<String>) -> Result<Box<[AndroidPackageName]>, ConfigError> {
    if raw.len() > MAX_ANDROID_PACKAGES {
        return Err(ConfigError::invalid_value(
            "applications.packages",
            "package count exceeds the configured resource limit",
        ));
    }
    let mut packages = BTreeSet::new();
    for package in raw {
        if !valid_android_package_name(&package) {
            return Err(ConfigError::invalid_value(
                "applications.packages",
                "contains an invalid Android package name",
            ));
        }
        if !packages.insert(package) {
            return Err(ConfigError::invalid_value(
                "applications.packages",
                "contains a duplicate Android package name",
            ));
        }
    }
    Ok(packages
        .into_iter()
        .map(|package| AndroidPackageName(package.into_boxed_str()))
        .collect())
}

fn valid_android_package_name(value: &str) -> bool {
    value.len() <= MAX_ANDROID_PACKAGE_NAME_BYTES
        && value.split('.').count() >= 2
        && value.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn parse_android_users(
    selection: RawAndroidUsers,
    raw_ids: Vec<i64>,
) -> Result<AndroidUserSelection, ConfigError> {
    if raw_ids.len() > MAX_ANDROID_USER_IDS {
        return Err(ConfigError::invalid_value(
            "applications.user_ids",
            "Android user count exceeds the configured resource limit",
        ));
    }
    let mut ids = BTreeSet::new();
    for raw_id in raw_ids {
        let id = u16::try_from(raw_id)
            .ok()
            .filter(|id| *id <= MAX_ANDROID_USER_ID)
            .ok_or(ConfigError::value_out_of_range(
                "applications.user_ids",
                raw_id,
                0,
                i64::from(MAX_ANDROID_USER_ID),
            ))?;
        if !ids.insert(id) {
            return Err(ConfigError::invalid_value(
                "applications.user_ids",
                "contains a duplicate Android user ID",
            ));
        }
    }
    match selection {
        RawAndroidUsers::Owner if ids.is_empty() => Ok(AndroidUserSelection::Owner),
        RawAndroidUsers::All if ids.is_empty() => Ok(AndroidUserSelection::All),
        RawAndroidUsers::List if !ids.is_empty() => {
            Ok(AndroidUserSelection::List(ids.into_iter().collect()))
        }
        RawAndroidUsers::Owner | RawAndroidUsers::All => Err(ConfigError::invalid_value(
            "applications.user_ids",
            "must be empty unless applications.android_users is list",
        )),
        RawAndroidUsers::List => Err(ConfigError::invalid_value(
            "applications.user_ids",
            "must be nonempty when applications.android_users is list",
        )),
    }
}

fn parse_interface_policy(raw: RawInterfaceConfig) -> Result<CaptureInterfacePolicy, ConfigError> {
    let total = raw
        .forwarded_proxy
        .len()
        .saturating_add(raw.local_bypass.len())
        .saturating_add(raw.excluded.len());
    if total > MAX_CAPTURE_INTERFACE_SELECTORS {
        return Err(ConfigError::invalid_value(
            "interfaces",
            "interface selector count exceeds the Capture Program limit",
        ));
    }

    let mut seen = BTreeMap::new();
    let forwarded_proxy =
        parse_interface_list("interfaces.forwarded_proxy", raw.forwarded_proxy, &mut seen)?;
    let local_bypass =
        parse_interface_list("interfaces.local_bypass", raw.local_bypass, &mut seen)?;
    let excluded = parse_interface_list("interfaces.excluded", raw.excluded, &mut seen)?;
    CaptureInterfacePolicy::new(excluded, forwarded_proxy, local_bypass).map_err(|_| {
        ConfigError::invalid_value(
            "interfaces",
            "interface selector count exceeds the Capture Program limit",
        )
    })
}

fn parse_interface_list(
    field: &'static str,
    raw: Vec<String>,
    seen: &mut BTreeMap<String, &'static str>,
) -> Result<Vec<CaptureInterfaceSelector>, ConfigError> {
    raw.into_iter()
        .map(|pattern| {
            if seen.insert(pattern.clone(), field).is_some() {
                return Err(ConfigError::invalid_value(
                    field,
                    "contains a selector already assigned to another interface role",
                ));
            }
            parse_interface_selector(field, &pattern)
        })
        .collect()
}

fn parse_interface_selector(
    field: &'static str,
    pattern: &str,
) -> Result<CaptureInterfaceSelector, ConfigError> {
    let (name, prefix) = match pattern.strip_suffix('*') {
        Some(prefix) if !prefix.contains('*') => (prefix, true),
        Some(_) => {
            return Err(ConfigError::invalid_value(
                field,
                "interface wildcard is valid only once at the end",
            ));
        }
        None if pattern.contains('*') => {
            return Err(ConfigError::invalid_value(
                field,
                "interface wildcard is valid only once at the end",
            ));
        }
        None => (pattern, false),
    };
    if name
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'/')
    {
        return Err(ConfigError::invalid_value(
            field,
            "contains an unsafe interface name",
        ));
    }
    let name = InterfaceName::new(name.as_bytes()).ok_or(ConfigError::invalid_value(
        field,
        "interface name must contain 1..=15 non-NUL bytes",
    ))?;
    Ok(if prefix {
        CaptureInterfaceSelector::prefix(name)
    } else {
        CaptureInterfaceSelector::exact(name)
    })
}

fn parse_bypass_policy(raw: Vec<String>) -> Result<CaptureBypassPolicy, ConfigError> {
    if raw.len() > MAX_CAPTURE_POLICY_PREFIX_INPUTS {
        return Err(ConfigError::invalid_value(
            "bypass.cidrs",
            "CIDR count exceeds the Capture Program limit",
        ));
    }
    let mut prefixes = BTreeSet::new();
    for raw_prefix in raw {
        let (address, prefix_length) = raw_prefix
            .split_once('/')
            .filter(|(_, suffix)| !suffix.contains('/'))
            .ok_or(ConfigError::invalid_value(
                "bypass.cidrs",
                "contains a CIDR without one prefix length",
            ))?;
        let address = address.parse::<IpAddr>().map_err(|_| {
            ConfigError::invalid_value("bypass.cidrs", "contains an invalid IP address")
        })?;
        let prefix_length = prefix_length.parse::<u8>().map_err(|_| {
            ConfigError::invalid_value("bypass.cidrs", "contains an invalid prefix length")
        })?;
        let prefix = CaptureIpPrefix::new(address, prefix_length).map_err(|_| {
            ConfigError::invalid_value("bypass.cidrs", "prefix length exceeds its family width")
        })?;
        if prefix.network() != address {
            return Err(ConfigError::invalid_value(
                "bypass.cidrs",
                "CIDR host bits must already be canonical",
            ));
        }
        if !prefixes.insert(prefix) {
            return Err(ConfigError::invalid_value(
                "bypass.cidrs",
                "contains a duplicate CIDR",
            ));
        }
    }
    CaptureBypassPolicy::new(prefixes).map_err(|_| {
        ConfigError::invalid_value(
            "bypass.cidrs",
            "CIDR count exceeds the Capture Program limit",
        )
    })
}
