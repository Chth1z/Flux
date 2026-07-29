use std::error::Error;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::OpenOptionsExt;

use flux_core::{
    AddressHostFamilySelection, CaptureApplicationMode, CapturePathId, CapturePathRequest,
    CaptureTrafficDomain, CaptureTransportProtocol, FluxConfig,
};
use serde::{Deserialize, Serialize};

use crate::generation_engine_config::{
    TproxyEngineConfigRequest, compile_tproxy_engine_config, read_bounded_regular_file,
};
use crate::{
    CapturePathDecision, CapturePathSelection, MAX_ENGINE_CONFIG_BYTES, RuntimeGenerationBinding,
    RuntimeSnapshotSource,
};

pub const DEFAULT_LOG_LINES: u16 = 120;
pub const MAX_LOG_LINES: u16 = 1_000;
pub const MAX_LOG_TAIL_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSTIC_DETAIL_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogStream {
    Runtime,
    Daemon,
    Engine,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LogReport {
    stream: LogStream,
    content: String,
    line_count: u16,
    truncated: bool,
}

impl LogReport {
    #[must_use]
    pub const fn stream(&self) -> LogStream {
        self.stream
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    #[must_use]
    pub const fn line_count(&self) -> u16 {
        self.line_count
    }

    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    pub(crate) fn validate(&self, requested_lines: u16) -> bool {
        requested_lines != 0
            && requested_lines <= MAX_LOG_LINES
            && self.line_count <= requested_lines
            && self.content.len() <= MAX_LOG_TAIL_BYTES.saturating_mul(3)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticState {
    Ready,
    Missing,
    Invalid,
    Unsafe,
    Unavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticItem {
    state: DiagnosticState,
    detail: String,
}

impl DiagnosticItem {
    fn new(state: DiagnosticState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: bounded_detail(detail.into()),
        }
    }

    #[must_use]
    pub const fn state(&self) -> DiagnosticState {
        self.state
    }

    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    fn is_valid(&self) -> bool {
        self.detail.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiagnosticReport {
    desired_state: DiagnosticItem,
    runtime_log: DiagnosticItem,
    daemon_log: DiagnosticItem,
    engine_log: DiagnosticItem,
}

impl DiagnosticReport {
    #[must_use]
    pub const fn desired_state(&self) -> &DiagnosticItem {
        &self.desired_state
    }

    #[must_use]
    pub const fn runtime_log(&self) -> &DiagnosticItem {
        &self.runtime_log
    }

    #[must_use]
    pub const fn daemon_log(&self) -> &DiagnosticItem {
        &self.daemon_log
    }

    #[must_use]
    pub const fn engine_log(&self) -> &DiagnosticItem {
        &self.engine_log
    }

    pub(crate) fn validate(&self) -> bool {
        [
            &self.desired_state,
            &self.runtime_log,
            &self.daemon_log,
            &self.engine_log,
        ]
        .into_iter()
        .all(DiagnosticItem::is_valid)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainAddressFamilies {
    Ipv4,
    Ipv6,
    DualStack,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainApplicationMode {
    All,
    Allowlist,
    Denylist,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExplainCapturePathRequestRelation {
    Unavailable,
    MatchesDesiredState,
    DiffersFromDesiredState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExplainReport {
    desired_state_schema: u16,
    capture_path_request: String,
    runtime_revision: u64,
    active_generation: Option<RuntimeGenerationBinding>,
    active_capture_path_request_relation: ExplainCapturePathRequestRelation,
    latest_capture_path_decision: Option<CapturePathDecision>,
    latest_capture_path_request_relation: ExplainCapturePathRequestRelation,
    listener_port: u16,
    address_families: ExplainAddressFamilies,
    local_output: bool,
    forwarded_ingress: bool,
    tcp: bool,
    udp: bool,
    application_mode: ExplainApplicationMode,
    application_packages: usize,
    configured_bypass_prefixes: usize,
    excluded_interfaces: usize,
    forwarded_proxy_interfaces: usize,
    local_bypass_interfaces: usize,
    subscription_enabled: bool,
    respect_android_vpn: bool,
    require_functional_canary: bool,
    engine_config_schema: u16,
    engine_config_digest: String,
    engine_config_bytes: usize,
    non_authorizing: bool,
}

impl ExplainReport {
    #[must_use]
    pub const fn desired_state_schema(&self) -> u16 {
        self.desired_state_schema
    }

    #[must_use]
    pub fn capture_path_request(&self) -> &str {
        &self.capture_path_request
    }

    #[must_use]
    pub const fn runtime_revision(&self) -> u64 {
        self.runtime_revision
    }

    #[must_use]
    pub const fn active_generation(&self) -> Option<RuntimeGenerationBinding> {
        self.active_generation
    }

    #[must_use]
    pub const fn active_capture_path_selection(&self) -> Option<CapturePathSelection> {
        match self.active_generation {
            Some(binding) => Some(binding.capture_path_selection()),
            None => None,
        }
    }

    #[must_use]
    pub const fn active_capture_path_request_relation(&self) -> ExplainCapturePathRequestRelation {
        self.active_capture_path_request_relation
    }

    #[must_use]
    pub const fn latest_capture_path_decision(&self) -> Option<CapturePathDecision> {
        self.latest_capture_path_decision
    }

    #[must_use]
    pub const fn latest_capture_path_request_relation(&self) -> ExplainCapturePathRequestRelation {
        self.latest_capture_path_request_relation
    }

    #[must_use]
    pub const fn listener_port(&self) -> u16 {
        self.listener_port
    }

    #[must_use]
    pub const fn address_families(&self) -> ExplainAddressFamilies {
        self.address_families
    }

    #[must_use]
    pub const fn local_output(&self) -> bool {
        self.local_output
    }

    #[must_use]
    pub const fn forwarded_ingress(&self) -> bool {
        self.forwarded_ingress
    }

    #[must_use]
    pub const fn tcp(&self) -> bool {
        self.tcp
    }

    #[must_use]
    pub const fn udp(&self) -> bool {
        self.udp
    }

    #[must_use]
    pub const fn application_mode(&self) -> ExplainApplicationMode {
        self.application_mode
    }

    #[must_use]
    pub const fn application_packages(&self) -> usize {
        self.application_packages
    }

    #[must_use]
    pub const fn configured_bypass_prefixes(&self) -> usize {
        self.configured_bypass_prefixes
    }

    #[must_use]
    pub const fn excluded_interfaces(&self) -> usize {
        self.excluded_interfaces
    }

    #[must_use]
    pub const fn forwarded_proxy_interfaces(&self) -> usize {
        self.forwarded_proxy_interfaces
    }

    #[must_use]
    pub const fn local_bypass_interfaces(&self) -> usize {
        self.local_bypass_interfaces
    }

    #[must_use]
    pub const fn subscription_enabled(&self) -> bool {
        self.subscription_enabled
    }

    #[must_use]
    pub const fn respect_android_vpn(&self) -> bool {
        self.respect_android_vpn
    }

    #[must_use]
    pub const fn require_functional_canary(&self) -> bool {
        self.require_functional_canary
    }

    #[must_use]
    pub const fn engine_config_schema(&self) -> u16 {
        self.engine_config_schema
    }

    #[must_use]
    pub fn engine_config_digest(&self) -> &str {
        &self.engine_config_digest
    }

    #[must_use]
    pub const fn engine_config_bytes(&self) -> usize {
        self.engine_config_bytes
    }

    #[must_use]
    pub const fn non_authorizing(&self) -> bool {
        self.non_authorizing
    }

    pub(crate) fn validate(&self) -> bool {
        self.desired_state_schema != 0
            && is_capture_path_request(&self.capture_path_request)
            && self.active_capture_path_request_relation
                == capture_path_request_relation(
                    &self.capture_path_request,
                    self.active_generation
                        .map(RuntimeGenerationBinding::capture_path_selection)
                        .map(CapturePathSelection::request),
                )
            && self.latest_capture_path_request_relation
                == capture_path_request_relation(
                    &self.capture_path_request,
                    self.latest_capture_path_decision
                        .map(CapturePathDecision::request),
                )
            && self.listener_port != 0
            && self.engine_config_schema != 0
            && self.engine_config_digest.len() == 64
            && self
                .engine_config_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && u64::try_from(self.engine_config_bytes)
                .is_ok_and(|bytes| bytes <= MAX_ENGINE_CONFIG_BYTES)
            && self.non_authorizing
    }
}

pub(crate) trait InspectionSource: Send + Sync {
    fn diagnose(&self) -> DiagnosticReport;
    fn logs(&self, stream: LogStream, lines: u16) -> Result<LogReport, InspectionError>;
    fn explain(&self) -> Result<ExplainReport, InspectionError>;
}

#[derive(Clone, Debug)]
pub(crate) struct ProcessInspectionSource {
    desired_state_path: PathBuf,
    runtime_log_path: PathBuf,
    daemon_log_path: PathBuf,
    engine_log_path: PathBuf,
    runtime: RuntimeSnapshotSource,
}

impl ProcessInspectionSource {
    #[must_use]
    pub(crate) fn new(
        desired_state_path: impl AsRef<Path>,
        runtime_log_path: impl AsRef<Path>,
        daemon_log_path: impl AsRef<Path>,
        engine_log_path: impl AsRef<Path>,
        runtime: RuntimeSnapshotSource,
    ) -> Self {
        Self {
            desired_state_path: desired_state_path.as_ref().to_path_buf(),
            runtime_log_path: runtime_log_path.as_ref().to_path_buf(),
            daemon_log_path: daemon_log_path.as_ref().to_path_buf(),
            engine_log_path: engine_log_path.as_ref().to_path_buf(),
            runtime,
        }
    }
}

impl InspectionSource for ProcessInspectionSource {
    fn diagnose(&self) -> DiagnosticReport {
        let desired_state = match FluxConfig::load(&self.desired_state_path) {
            Ok(config) => DiagnosticItem::new(
                DiagnosticState::Ready,
                format!("schema={}", config.schema()),
            ),
            Err(error) => {
                classify_desired_state_error(&self.desired_state_path, &error.to_string())
            }
        };
        DiagnosticReport {
            desired_state,
            runtime_log: observe_file(&self.runtime_log_path),
            daemon_log: observe_file(&self.daemon_log_path),
            engine_log: observe_file(&self.engine_log_path),
        }
    }

    fn logs(&self, stream: LogStream, lines: u16) -> Result<LogReport, InspectionError> {
        if lines == 0 || lines > MAX_LOG_LINES {
            return Err(InspectionError::InvalidLineCount { lines });
        }
        let path = match stream {
            LogStream::Runtime => self.runtime_log_path.clone(),
            LogStream::Daemon => self.daemon_log_path.clone(),
            LogStream::Engine => self.engine_log_path.clone(),
        };
        read_log_tail(&path, stream, lines)
    }

    fn explain(&self) -> Result<ExplainReport, InspectionError> {
        let config = FluxConfig::load(&self.desired_state_path).map_err(|source| {
            InspectionError::DesiredState {
                source: source.to_string(),
            }
        })?;
        let template = read_bounded_regular_file(config.engine().template()).map_err(|source| {
            InspectionError::Template {
                source: source.to_string(),
            }
        })?;
        let engine = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            &template,
            config.listener().port(),
        ))
        .map_err(|source| InspectionError::Compile {
            source: source.to_string(),
        })?;
        let scope = config.capture().scope();
        let protocols = config.capture().protocols();
        let interfaces = config.interfaces().policy();
        let runtime = self.runtime.snapshot();
        let capture_path_request = config.capture().path_request();
        Ok(ExplainReport {
            desired_state_schema: config.schema(),
            capture_path_request: capture_path_request.as_token().to_owned(),
            runtime_revision: runtime.revision,
            active_generation: runtime.active_generation,
            active_capture_path_request_relation: capture_path_request_relation(
                capture_path_request.as_token(),
                runtime
                    .active_capture_path_selection()
                    .map(CapturePathSelection::request),
            ),
            latest_capture_path_decision: runtime.latest_capture_path_decision,
            latest_capture_path_request_relation: capture_path_request_relation(
                capture_path_request.as_token(),
                runtime
                    .latest_capture_path_decision
                    .map(CapturePathDecision::request),
            ),
            listener_port: config.listener().port().get(),
            address_families: match scope.families() {
                AddressHostFamilySelection::Ipv4 => ExplainAddressFamilies::Ipv4,
                AddressHostFamilySelection::Ipv6 => ExplainAddressFamilies::Ipv6,
                AddressHostFamilySelection::DualStack => ExplainAddressFamilies::DualStack,
            },
            local_output: scope.includes_domain(CaptureTrafficDomain::LocalOutput),
            forwarded_ingress: scope.includes_domain(CaptureTrafficDomain::ForwardedIngress),
            tcp: protocols.contains(CaptureTransportProtocol::Tcp),
            udp: protocols.contains(CaptureTransportProtocol::Udp),
            application_mode: match config.applications().mode() {
                CaptureApplicationMode::All => ExplainApplicationMode::All,
                CaptureApplicationMode::Allowlist => ExplainApplicationMode::Allowlist,
                CaptureApplicationMode::Denylist => ExplainApplicationMode::Denylist,
            },
            application_packages: config.applications().packages().len(),
            configured_bypass_prefixes: config.bypass().policy().prefixes().len(),
            excluded_interfaces: interfaces.excluded().len(),
            forwarded_proxy_interfaces: interfaces.forwarded_proxy().len(),
            local_bypass_interfaces: interfaces.local_bypass().len(),
            subscription_enabled: config.subscription().enabled(),
            respect_android_vpn: config.safety().respect_android_vpn(),
            require_functional_canary: config.safety().require_functional_canary(),
            engine_config_schema: engine.schema_version(),
            engine_config_digest: engine.digest().to_string(),
            engine_config_bytes: engine.usage().output_bytes(),
            non_authorizing: true,
        })
    }
}

fn is_capture_path_request(value: &str) -> bool {
    value == CapturePathRequest::Auto.as_token()
        || CapturePathId::ALL
            .into_iter()
            .any(|path| value == path.as_token())
}

fn capture_path_request_relation(
    desired_state_request: &str,
    runtime_request: Option<CapturePathRequest>,
) -> ExplainCapturePathRequestRelation {
    match runtime_request {
        None => ExplainCapturePathRequestRelation::Unavailable,
        Some(request) if request.as_token() == desired_state_request => {
            ExplainCapturePathRequestRelation::MatchesDesiredState
        }
        Some(_) => ExplainCapturePathRequestRelation::DiffersFromDesiredState,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InspectionErrorKind {
    InvalidRequest,
    Missing,
    Unsafe,
    Io,
    DesiredState,
    Template,
    Compile,
}

impl InspectionErrorKind {
    pub(crate) const fn rejection_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "inspection_invalid_request",
            Self::Missing => "inspection_missing",
            Self::Unsafe => "inspection_unsafe_file",
            Self::Io => "inspection_io_failed",
            Self::DesiredState => "inspection_desired_state_failed",
            Self::Template => "inspection_template_failed",
            Self::Compile => "inspection_compile_failed",
        }
    }
}

#[derive(Debug)]
pub(crate) enum InspectionError {
    InvalidLineCount {
        lines: u16,
    },
    Missing {
        path: PathBuf,
    },
    Unsafe {
        path: PathBuf,
    },
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    DesiredState {
        source: String,
    },
    Template {
        source: String,
    },
    Compile {
        source: String,
    },
}

impl InspectionError {
    pub(crate) const fn kind(&self) -> InspectionErrorKind {
        match self {
            Self::InvalidLineCount { .. } => InspectionErrorKind::InvalidRequest,
            Self::Missing { .. } => InspectionErrorKind::Missing,
            Self::Unsafe { .. } => InspectionErrorKind::Unsafe,
            Self::Io { .. } => InspectionErrorKind::Io,
            Self::DesiredState { .. } => InspectionErrorKind::DesiredState,
            Self::Template { .. } => InspectionErrorKind::Template,
            Self::Compile { .. } => InspectionErrorKind::Compile,
        }
    }
}

impl fmt::Display for InspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLineCount { lines } => write!(
                formatter,
                "requested log line count {lines} is outside 1..={MAX_LOG_LINES}"
            ),
            Self::Missing { path } => write!(formatter, "log file {} is missing", path.display()),
            Self::Unsafe { path } => write!(
                formatter,
                "log file {} must be a regular non-symbolic-link file",
                path.display()
            ),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "cannot read log file {}: {source}",
                    path.display()
                )
            }
            Self::DesiredState { source } => {
                write!(
                    formatter,
                    "cannot load Desired State for explanation: {source}"
                )
            }
            Self::Template { source } => {
                write!(
                    formatter,
                    "cannot read engine template for explanation: {source}"
                )
            }
            Self::Compile { source } => {
                write!(
                    formatter,
                    "cannot compile Desired State explanation: {source}"
                )
            }
        }
    }
}

impl Error for InspectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidLineCount { .. }
            | Self::Missing { .. }
            | Self::Unsafe { .. }
            | Self::DesiredState { .. }
            | Self::Template { .. }
            | Self::Compile { .. } => None,
        }
    }
}

fn read_log_tail(path: &Path, stream: LogStream, lines: u16) -> Result<LogReport, InspectionError> {
    let before = fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            InspectionError::Missing {
                path: path.to_path_buf(),
            }
        } else {
            InspectionError::Io {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(InspectionError::Unsafe {
            path: path.to_path_buf(),
        });
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path).map_err(|source| InspectionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let opened = file.metadata().map_err(|source| InspectionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !opened.is_file() {
        return Err(InspectionError::Unsafe {
            path: path.to_path_buf(),
        });
    }

    let offset = opened.len().saturating_sub(MAX_LOG_TAIL_BYTES as u64);
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| InspectionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    let snapshot_bytes = opened.len().saturating_sub(offset);
    let mut bytes = Vec::with_capacity(snapshot_bytes as usize);
    file.by_ref()
        .take(snapshot_bytes)
        .read_to_end(&mut bytes)
        .map_err(|source| InspectionError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    let mut truncated = offset != 0;
    if offset != 0 {
        if let Some(first_newline) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=first_newline);
        } else {
            bytes.clear();
        }
    }
    let tail_start = tail_start(&bytes, usize::from(lines));
    if tail_start != 0 {
        truncated = true;
    }
    let content = String::from_utf8_lossy(&bytes[tail_start..]).into_owned();
    let line_count = u16::try_from(content.lines().count())
        .unwrap_or(lines)
        .min(lines);
    Ok(LogReport {
        stream,
        content,
        line_count,
        truncated,
    })
}

fn tail_start(bytes: &[u8], lines: usize) -> usize {
    let mut end = bytes.len();
    if bytes.last() == Some(&b'\n') {
        end = end.saturating_sub(1);
    }
    let mut seen = 0;
    for index in (0..end).rev() {
        if bytes[index] == b'\n' {
            seen += 1;
            if seen == lines {
                return index + 1;
            }
        }
    }
    0
}

fn observe_file(path: &Path) -> DiagnosticItem {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            DiagnosticItem::new(
                DiagnosticState::Unsafe,
                "path is not a regular non-symbolic-link file",
            )
        }
        Ok(metadata) => {
            DiagnosticItem::new(DiagnosticState::Ready, format!("bytes={}", metadata.len()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DiagnosticItem::new(DiagnosticState::Missing, "file is absent")
        }
        Err(error) => DiagnosticItem::new(DiagnosticState::Unavailable, error.to_string()),
    }
}

fn classify_desired_state_error(path: &Path, detail: &str) -> DiagnosticItem {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            DiagnosticItem::new(DiagnosticState::Missing, "Desired State is absent")
        }
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            DiagnosticItem::new(
                DiagnosticState::Unsafe,
                "Desired State is not a regular non-symbolic-link file",
            )
        }
        _ => DiagnosticItem::new(DiagnosticState::Invalid, detail),
    }
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() <= MAX_DIAGNOSTIC_DETAIL_BYTES {
        return detail;
    }
    let mut end = MAX_DIAGNOSTIC_DETAIL_BYTES;
    while !detail.is_char_boundary(end) {
        end -= 1;
    }
    detail.truncate(end);
    detail
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;

    use tempfile::tempdir;

    use super::*;
    use crate::generation_engine_config::{
        test_unqualified_capture_path_decision, test_xtables_capture_path_decision,
        test_xtables_capture_path_selection,
    };
    use crate::{
        RuntimeCaptureState, RuntimeEngineState, RuntimePhase, RuntimeSnapshot,
        RuntimeVerificationState,
    };

    #[test]
    fn log_tail_is_line_and_byte_bounded() {
        let directory = tempdir().expect("temporary directory");
        let path = directory.path().join("flux.log");
        let mut file = File::create(&path).expect("create log");
        for line in 0..2_000 {
            writeln!(file, "line-{line:04}").expect("write log line");
        }

        let report = read_log_tail(&path, LogStream::Runtime, 3).expect("read log tail");
        assert_eq!(report.content(), "line-1997\nline-1998\nline-1999\n");
        assert_eq!(report.line_count(), 3);
        assert!(report.truncated());
        assert!(report.validate(3));
    }

    #[cfg(unix)]
    #[test]
    fn log_tail_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let target = directory.path().join("target.log");
        fs::write(&target, "secret\n").expect("write target");
        let path = directory.path().join("flux.log");
        symlink(&target, &path).expect("create symlink");

        assert!(matches!(
            read_log_tail(&path, LogStream::Runtime, 1),
            Err(InspectionError::Unsafe { .. })
        ));
    }

    #[test]
    fn explanation_compiles_without_publishing_runtime_artifacts() {
        let directory = tempdir().expect("temporary directory");
        let template_path = directory.path().join("template.json");
        fs::write(
            &template_path,
            include_bytes!("../../../conf/template.json"),
        )
        .expect("write template");
        let config_path = directory.path().join("flux.toml");
        let config = include_str!("../../../conf/flux.toml").replace(
            "/data/adb/flux/conf/template.json",
            template_path.to_str().expect("UTF-8 path"),
        );
        fs::write(&config_path, config).expect("write config");
        let engine_log_path = directory.path().join("sing-box.log");
        let capture_path_selection = test_xtables_capture_path_selection();
        let runtime = RuntimeSnapshotSource::default();
        runtime.publish(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Running,
            capture: RuntimeCaptureState::Published,
            engine: RuntimeEngineState::Ready,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: Some(RuntimeGenerationBinding::new(
                flux_core::GenerationId::new(1).expect("nonzero Generation"),
                capture_path_selection,
            )),
            latest_capture_path_decision: Some(test_xtables_capture_path_decision()),
            last_error: None,
        });
        let source = ProcessInspectionSource::new(
            &config_path,
            directory.path().join("flux.log"),
            directory.path().join("fluxd.log"),
            &engine_log_path,
            runtime.clone(),
        );

        let report = source.explain().expect("compile explanation");

        assert_eq!(report.capture_path_request(), "auto");
        assert_eq!(
            report.active_capture_path_selection(),
            Some(capture_path_selection)
        );
        assert_eq!(
            report.active_capture_path_request_relation(),
            ExplainCapturePathRequestRelation::MatchesDesiredState
        );
        assert_eq!(
            report.latest_capture_path_request_relation(),
            ExplainCapturePathRequestRelation::MatchesDesiredState
        );
        assert!(report.non_authorizing());
        assert!(report.validate());
        assert!(!engine_log_path.exists());
        assert_eq!(fs::read_dir(&directory).expect("list fixture").count(), 2);

        let drifted_config = fs::read_to_string(&config_path)
            .expect("read Desired State")
            .replace("path = \"auto\"", "path = \"managed_tun\"");
        fs::write(&config_path, drifted_config).expect("write drifted Desired State");
        let drifted = source.explain().expect("compile drifted explanation");
        assert_eq!(drifted.capture_path_request(), "managed_tun");
        assert_eq!(
            drifted.active_capture_path_selection(),
            Some(capture_path_selection)
        );
        assert_eq!(
            drifted.active_capture_path_request_relation(),
            ExplainCapturePathRequestRelation::DiffersFromDesiredState
        );
        assert_eq!(
            drifted.latest_capture_path_request_relation(),
            ExplainCapturePathRequestRelation::DiffersFromDesiredState
        );
        assert!(drifted.validate());

        let rejected_decision = test_unqualified_capture_path_decision();
        runtime.publish(RuntimeSnapshot {
            revision: 0,
            phase: RuntimePhase::Failed,
            capture: RuntimeCaptureState::Detached,
            engine: RuntimeEngineState::Stopped,
            verification: RuntimeVerificationState::StructuralOnly,
            active_generation: None,
            latest_capture_path_decision: Some(rejected_decision),
            last_error: None,
        });
        let rejected = source.explain().expect("compile rejected explanation");
        let rejection = rejected
            .latest_capture_path_decision()
            .and_then(CapturePathDecision::rejection)
            .expect("rejected Capture Path evidence");
        assert_eq!(rejected.active_capture_path_selection(), None);
        assert_eq!(
            rejection.reason(),
            crate::CapturePathRejectionReason::NoQualifiedPath
        );
        assert_eq!(
            rejection.candidates()[1].state(),
            flux_platform::AndroidCapturePathState::Unqualified
        );
        assert_eq!(
            rejection.candidates()[1].probe_state(),
            flux_platform::AndroidCapturePathProbeState::Unqualified
        );
    }

    #[cfg(unix)]
    #[test]
    fn explanation_rejects_a_symbolic_link_template_ancestor() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().expect("temporary directory");
        let target_directory = directory.path().join("template-target");
        fs::create_dir(&target_directory).expect("create template target directory");
        fs::write(
            target_directory.join("template.json"),
            include_bytes!("../../../conf/template.json"),
        )
        .expect("write template");
        let linked_directory = directory.path().join("template-source");
        symlink(&target_directory, &linked_directory).expect("link template ancestor");
        let template_path = linked_directory.join("template.json");
        let config_path = directory.path().join("flux.toml");
        let config = include_str!("../../../conf/flux.toml").replace(
            "/data/adb/flux/conf/template.json",
            template_path.to_str().expect("UTF-8 path"),
        );
        fs::write(&config_path, config).expect("write config");
        let source = ProcessInspectionSource::new(
            &config_path,
            directory.path().join("flux.log"),
            directory.path().join("fluxd.log"),
            directory.path().join("sing-box.log"),
            RuntimeSnapshotSource::default(),
        );

        let error = source
            .explain()
            .expect_err("template ancestor symlink must fail closed");

        assert_eq!(error.kind(), InspectionErrorKind::Template);
    }

    #[test]
    fn diagnostics_read_the_fixed_engine_log_without_launch_artifacts() {
        let directory = tempdir().expect("temporary directory");
        let log_path = directory.path().join("sing-box.log");
        fs::write(&log_path, "engine ready\n").expect("write engine log");
        let source = ProcessInspectionSource::new(
            directory.path().join("missing-flux.toml"),
            directory.path().join("flux.log"),
            directory.path().join("fluxd.log"),
            &log_path,
            RuntimeSnapshotSource::default(),
        );

        let diagnostics = source.diagnose();
        let logs = source
            .logs(LogStream::Engine, 1)
            .expect("read resolved engine log");

        assert_eq!(diagnostics.engine_log().state(), DiagnosticState::Ready);
        assert_eq!(logs.content(), "engine ready\n");

        fs::remove_file(&log_path).expect("remove engine log");
        assert_eq!(
            source.diagnose().engine_log().state(),
            DiagnosticState::Missing
        );
        assert!(matches!(
            source.logs(LogStream::Engine, 1),
            Err(InspectionError::Missing { .. })
        ));
    }
}
