use std::error::Error;
use std::fmt;

use flux_core::{
    AddressHostSetPlan, CaptureApplicationMode, CaptureApplicationPolicy, FluxConfig,
    ShadowCaptureCompileError, ShadowCaptureProgramRequest, ShadowCompilationReport,
    compile_shadow_capture_program,
};

use super::compiler::{
    EngineConfigArtifact, EngineConfigCompileError, EngineConfigCompileErrorKind,
    TproxyEngineConfigRequest, compile_tproxy_engine_config,
};

/// Complete pure inputs for compiling one immutable Desired State snapshot.
///
/// Application package/user resolution and inventory host selection happen before this seam. Their
/// typed results are consumed here without granting Android planning or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesiredStateCompileRequest {
    config: FluxConfig,
    application_policy: CaptureApplicationPolicy,
    host_bypass: Option<AddressHostSetPlan>,
}

impl DesiredStateCompileRequest {
    #[must_use]
    pub(crate) const fn new(
        config: FluxConfig,
        application_policy: CaptureApplicationPolicy,
        host_bypass: Option<AddressHostSetPlan>,
    ) -> Self {
        Self {
            config,
            application_policy,
            host_bypass,
        }
    }
}

/// Non-authorizing engine and capture artifacts bound to one owned Desired State snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesiredStateArtifacts {
    desired_state: FluxConfig,
    engine_config: EngineConfigArtifact,
    capture: ShadowCompilationReport,
}

impl DesiredStateArtifacts {
    #[must_use]
    pub(crate) const fn desired_state(&self) -> &FluxConfig {
        &self.desired_state
    }

    #[must_use]
    pub(crate) const fn engine_config(&self) -> &EngineConfigArtifact {
        &self.engine_config
    }

    #[must_use]
    pub(crate) const fn capture(&self) -> &ShadowCompilationReport {
        &self.capture
    }

    pub(crate) fn into_parts(self) -> (FluxConfig, EngineConfigArtifact, ShadowCompilationReport) {
        (self.desired_state, self.engine_config, self.capture)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesiredStateCompileErrorKind {
    ApplicationModeMismatch {
        configured: CaptureApplicationMode,
        resolved: CaptureApplicationMode,
    },
    EngineConfig(EngineConfigCompileErrorKind),
    Capture,
}

#[derive(Debug)]
pub(crate) enum DesiredStateCompileError {
    ApplicationModeMismatch {
        configured: CaptureApplicationMode,
        resolved: CaptureApplicationMode,
    },
    EngineConfig(EngineConfigCompileError),
    Capture(ShadowCaptureCompileError),
}

impl DesiredStateCompileError {
    #[must_use]
    pub(crate) const fn kind(&self) -> DesiredStateCompileErrorKind {
        match self {
            Self::ApplicationModeMismatch {
                configured,
                resolved,
            } => DesiredStateCompileErrorKind::ApplicationModeMismatch {
                configured: *configured,
                resolved: *resolved,
            },
            Self::EngineConfig(error) => DesiredStateCompileErrorKind::EngineConfig(error.kind()),
            Self::Capture(_) => DesiredStateCompileErrorKind::Capture,
        }
    }
}

impl fmt::Display for DesiredStateCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApplicationModeMismatch {
                configured,
                resolved,
            } => write!(
                formatter,
                "resolved application mode {resolved:?} does not match configured mode {configured:?}"
            ),
            Self::EngineConfig(error) => error.fmt(formatter),
            Self::Capture(error) => error.fmt(formatter),
        }
    }
}

impl Error for DesiredStateCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ApplicationModeMismatch { .. } => None,
            Self::EngineConfig(error) => Some(error),
            Self::Capture(error) => Some(error),
        }
    }
}

/// Compile one Desired State without I/O, subprocesses, or activation authority.
pub(crate) fn compile_desired_state(
    request: DesiredStateCompileRequest,
    engine_template: &[u8],
) -> Result<DesiredStateArtifacts, DesiredStateCompileError> {
    let DesiredStateCompileRequest {
        config,
        application_policy,
        host_bypass,
    } = request;
    let configured_mode = config.applications().mode();
    let resolved_mode = application_policy.mode();
    if configured_mode != resolved_mode {
        return Err(DesiredStateCompileError::ApplicationModeMismatch {
            configured: configured_mode,
            resolved: resolved_mode,
        });
    }

    let engine_config = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        engine_template,
        config.listener().port(),
    ))
    .map_err(DesiredStateCompileError::EngineConfig)?;
    let capture = compile_shadow_capture_program(ShadowCaptureProgramRequest::new(
        config.capture().scope(),
        config.engine().credentials(),
        config.bypass().policy().clone(),
        host_bypass,
        config.interfaces().policy().clone(),
        application_policy,
        config.capture().protocols(),
    ))
    .map_err(DesiredStateCompileError::Capture)?;

    Ok(DesiredStateArtifacts {
        desired_state: config,
        engine_config,
        capture,
    })
}
