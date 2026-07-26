use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use flux_core::{ConfigError, FluxConfig};

use super::{
    BridgeEnvironmentArtifact, BridgeEnvironmentCompileError, EngineConfigArtifact,
    EngineConfigCompileError, TproxyEngineConfigRequest, compile_bridge_environment,
    compile_tproxy_engine_config, compile_validated_subscription_bridge_environment,
};
use crate::MAX_ENGINE_CONFIG_BYTES;
use crate::intent_store::{IntentStoreError, record_io};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CanonicalEngineConfigPreparationErrorKind {
    DesiredState,
    DesiredStateChanged,
    Template,
    Compile,
    BridgeEnvironment,
    Publish,
}

#[derive(Debug)]
pub(crate) enum CanonicalEngineConfigPreparationError {
    DesiredState { path: PathBuf, source: ConfigError },
    DesiredStateChanged { path: PathBuf },
    Template { path: PathBuf, source: io::Error },
    Compile(EngineConfigCompileError),
    BridgeEnvironment(BridgeEnvironmentCompileError),
    Publish { path: PathBuf, source: io::Error },
}

impl CanonicalEngineConfigPreparationError {
    #[must_use]
    pub(crate) const fn kind(&self) -> CanonicalEngineConfigPreparationErrorKind {
        match self {
            Self::DesiredState { .. } => CanonicalEngineConfigPreparationErrorKind::DesiredState,
            Self::DesiredStateChanged { .. } => {
                CanonicalEngineConfigPreparationErrorKind::DesiredStateChanged
            }
            Self::Template { .. } => CanonicalEngineConfigPreparationErrorKind::Template,
            Self::Compile(_) => CanonicalEngineConfigPreparationErrorKind::Compile,
            Self::BridgeEnvironment(_) => {
                CanonicalEngineConfigPreparationErrorKind::BridgeEnvironment
            }
            Self::Publish { .. } => CanonicalEngineConfigPreparationErrorKind::Publish,
        }
    }
}

impl fmt::Display for CanonicalEngineConfigPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DesiredState { path, source } => {
                write!(
                    formatter,
                    "cannot load Desired State {}: {source}",
                    path.display()
                )
            }
            Self::DesiredStateChanged { path } => write!(
                formatter,
                "Desired State {} changed after subscription validation",
                path.display()
            ),
            Self::Template { path, source } => {
                write!(
                    formatter,
                    "cannot load engine template {}: {source}",
                    path.display()
                )
            }
            Self::Compile(source) => source.fmt(formatter),
            Self::BridgeEnvironment(source) => source.fmt(formatter),
            Self::Publish { path, source } => write!(
                formatter,
                "cannot atomically publish canonical engine configuration {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for CanonicalEngineConfigPreparationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::DesiredState { source, .. } => Some(source),
            Self::Template { source, .. } | Self::Publish { source, .. } => Some(source),
            Self::Compile(source) => Some(source),
            Self::BridgeEnvironment(source) => Some(source),
            Self::DesiredStateChanged { .. } => None,
        }
    }
}

/// One freshly loaded Desired State and the exact canonical engine artifact published from it.
pub(crate) struct CanonicalEngineConfigPublication {
    desired_state: FluxConfig,
    artifact: EngineConfigArtifact,
}

/// Rust-owned artifacts published before the fenced shell writer prepares one Generation.
pub(crate) struct BridgePreparationPublication {
    desired_state: FluxConfig,
    engine_config: EngineConfigArtifact,
    bridge_environment: BridgeEnvironmentArtifact,
}

impl BridgePreparationPublication {
    pub(crate) fn into_parts(
        self,
    ) -> (FluxConfig, EngineConfigArtifact, BridgeEnvironmentArtifact) {
        (
            self.desired_state,
            self.engine_config,
            self.bridge_environment,
        )
    }
}

impl CanonicalEngineConfigPublication {
    pub(crate) fn into_parts(self) -> (FluxConfig, EngineConfigArtifact) {
        (self.desired_state, self.artifact)
    }
}

/// Load current sources, compile the canonical TPROXY config, and atomically publish its bytes.
pub(crate) fn publish_canonical_engine_config(
    desired_state_path: &Path,
    output_path: &Path,
) -> Result<CanonicalEngineConfigPublication, CanonicalEngineConfigPreparationError> {
    let desired_state = FluxConfig::load(desired_state_path).map_err(|source| {
        CanonicalEngineConfigPreparationError::DesiredState {
            path: desired_state_path.to_path_buf(),
            source,
        }
    })?;
    let template_path = desired_state.engine().template();
    let template = read_bounded_regular_file(template_path).map_err(|source| {
        CanonicalEngineConfigPreparationError::Template {
            path: template_path.to_path_buf(),
            source,
        }
    })?;
    let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        &template,
        desired_state.listener().port(),
    ))
    .map_err(CanonicalEngineConfigPreparationError::Compile)?;
    atomic_publish(output_path, artifact.bytes()).map_err(|source| {
        CanonicalEngineConfigPreparationError::Publish {
            path: output_path.to_path_buf(),
            source,
        }
    })?;
    Ok(CanonicalEngineConfigPublication {
        desired_state,
        artifact,
    })
}

/// Compile and publish every Rust-owned input consumed by bridge preparation.
pub(crate) fn publish_bridge_preparation(
    desired_state_path: &Path,
    engine_output_path: &Path,
    environment_output_path: &Path,
) -> Result<BridgePreparationPublication, CanonicalEngineConfigPreparationError> {
    let desired_state = FluxConfig::load(desired_state_path).map_err(|source| {
        CanonicalEngineConfigPreparationError::DesiredState {
            path: desired_state_path.to_path_buf(),
            source,
        }
    })?;
    let template_path = desired_state.engine().template();
    let template = read_bounded_regular_file(template_path).map_err(|source| {
        CanonicalEngineConfigPreparationError::Template {
            path: template_path.to_path_buf(),
            source,
        }
    })?;
    let engine_config = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        &template,
        desired_state.listener().port(),
    ))
    .map_err(CanonicalEngineConfigPreparationError::Compile)?;
    let bridge_environment = compile_bridge_environment(&desired_state, &engine_config)
        .map_err(CanonicalEngineConfigPreparationError::BridgeEnvironment)?;

    atomic_publish(engine_output_path, engine_config.bytes()).map_err(|source| {
        CanonicalEngineConfigPreparationError::Publish {
            path: engine_output_path.to_path_buf(),
            source,
        }
    })?;
    atomic_publish(environment_output_path, bridge_environment.bytes()).map_err(|source| {
        CanonicalEngineConfigPreparationError::Publish {
            path: environment_output_path.to_path_buf(),
            source,
        }
    })?;
    Ok(BridgePreparationPublication {
        desired_state,
        engine_config,
        bridge_environment,
    })
}

/// Publish one bridge preparation from an exact store-validated subscription artifact.
pub(crate) fn publish_validated_subscription_bridge_preparation(
    desired_state_path: &Path,
    expected_desired_state: &FluxConfig,
    engine_config: EngineConfigArtifact,
    engine_output_path: &Path,
    environment_output_path: &Path,
) -> Result<BridgePreparationPublication, CanonicalEngineConfigPreparationError> {
    let desired_state = FluxConfig::load(desired_state_path).map_err(|source| {
        CanonicalEngineConfigPreparationError::DesiredState {
            path: desired_state_path.to_path_buf(),
            source,
        }
    })?;
    if &desired_state != expected_desired_state {
        return Err(CanonicalEngineConfigPreparationError::DesiredStateChanged {
            path: desired_state_path.to_path_buf(),
        });
    }
    let bridge_environment =
        compile_validated_subscription_bridge_environment(&desired_state, &engine_config)
            .map_err(CanonicalEngineConfigPreparationError::BridgeEnvironment)?;

    atomic_publish(engine_output_path, engine_config.bytes()).map_err(|source| {
        CanonicalEngineConfigPreparationError::Publish {
            path: engine_output_path.to_path_buf(),
            source,
        }
    })?;
    atomic_publish(environment_output_path, bridge_environment.bytes()).map_err(|source| {
        CanonicalEngineConfigPreparationError::Publish {
            path: environment_output_path.to_path_buf(),
            source,
        }
    })?;
    Ok(BridgePreparationPublication {
        desired_state,
        engine_config,
        bridge_environment,
    })
}

pub(crate) fn read_bounded_regular_file(path: &Path) -> io::Result<Vec<u8>> {
    let maximum = usize::try_from(MAX_ENGINE_CONFIG_BYTES).unwrap_or(usize::MAX);
    match record_io::read(path, maximum) {
        Ok(Some(bytes)) => Ok(bytes),
        Ok(None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("engine template {} is missing", path.display()),
        )),
        Err(source) => {
            let kind = match source {
                IntentStoreError::Symlink(_) | IntentStoreError::NotRegularFile(_) => {
                    io::ErrorKind::InvalidInput
                }
                IntentStoreError::RecordTooLarge { .. } => io::ErrorKind::InvalidData,
                _ => io::ErrorKind::Other,
            };
            Err(io::Error::new(kind, source))
        }
    }
}

fn atomic_publish(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical engine configuration path must be absolute",
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "canonical engine configuration has no parent directory",
            )
        })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "canonical engine configuration has no file name",
        )
    })?;
    let temp_id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    temp_name.push(file_name);
    temp_name.push(format!(".fluxd-{}-{temp_id}.tmp", std::process::id()));
    let temp_path = parent.join(temp_name);

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        let mut file = options.open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o444))?;
        #[cfg(not(unix))]
        {
            let mut permissions = file.metadata()?.permissions();
            permissions.set_readonly(true);
            file.set_permissions(permissions)?;
        }
        drop(file);
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}
