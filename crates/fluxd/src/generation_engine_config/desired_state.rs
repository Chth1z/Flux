use std::error::Error;
use std::fmt;
use std::num::NonZeroU16;

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
    engine_source: SelectedEngineSource,
    capture: ShadowCompilationReport,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) enum SelectedEngineSourceIdentity {
    Template {
        template_digest: [u8; 32],
    },
    Subscription {
        snapshot_digest: [u8; 32],
        subscription_source: [u8; 32],
    },
}

/// Exact accepted engine artifact and the source identity that selected it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SelectedEngineSource {
    identity: SelectedEngineSourceIdentity,
    artifact: EngineConfigArtifact,
}

impl SelectedEngineSource {
    #[must_use]
    pub(crate) fn template(artifact: EngineConfigArtifact) -> Self {
        Self {
            identity: SelectedEngineSourceIdentity::Template {
                template_digest: *artifact.template_digest(),
            },
            artifact,
        }
    }

    #[must_use]
    pub(crate) const fn subscription(
        artifact: EngineConfigArtifact,
        snapshot_digest: [u8; 32],
        subscription_source: [u8; 32],
    ) -> Self {
        Self {
            identity: SelectedEngineSourceIdentity::Subscription {
                snapshot_digest,
                subscription_source,
            },
            artifact,
        }
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> SelectedEngineSourceIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) const fn artifact(&self) -> &EngineConfigArtifact {
        &self.artifact
    }

    pub(crate) fn into_artifact(self) -> EngineConfigArtifact {
        self.artifact
    }
}

/// Realization-neutral capture half of one Desired State snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DesiredStateCaptureArtifacts {
    desired_state: FluxConfig,
    capture: ShadowCompilationReport,
}

impl DesiredStateCaptureArtifacts {
    #[must_use]
    pub(crate) const fn desired_state(&self) -> &FluxConfig {
        &self.desired_state
    }

    #[must_use]
    pub(crate) const fn capture(&self) -> &ShadowCompilationReport {
        &self.capture
    }

    pub(crate) fn with_engine_source(
        self,
        engine_source: SelectedEngineSource,
    ) -> Result<DesiredStateArtifacts, DesiredStateCompileError> {
        let configured = self.desired_state.listener().port();
        let selected = engine_source.artifact().listener_port();
        if configured != selected {
            return Err(DesiredStateCompileError::EngineSourceListenerPortMismatch {
                configured,
                selected,
            });
        }
        Ok(DesiredStateArtifacts {
            desired_state: self.desired_state,
            engine_source,
            capture: self.capture,
        })
    }
}

impl DesiredStateArtifacts {
    #[must_use]
    pub(crate) const fn desired_state(&self) -> &FluxConfig {
        &self.desired_state
    }

    #[must_use]
    pub(crate) const fn engine_config(&self) -> &EngineConfigArtifact {
        self.engine_source.artifact()
    }

    #[must_use]
    pub(crate) const fn engine_source(&self) -> &SelectedEngineSource {
        &self.engine_source
    }

    #[must_use]
    pub(crate) const fn capture(&self) -> &ShadowCompilationReport {
        &self.capture
    }

    pub(crate) fn into_parts(self) -> (FluxConfig, SelectedEngineSource, ShadowCompilationReport) {
        (self.desired_state, self.engine_source, self.capture)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DesiredStateCompileErrorKind {
    ApplicationModeMismatch {
        configured: CaptureApplicationMode,
        resolved: CaptureApplicationMode,
    },
    EngineConfig(EngineConfigCompileErrorKind),
    EngineSourceListenerPortMismatch {
        configured: NonZeroU16,
        selected: NonZeroU16,
    },
    Capture,
}

#[derive(Debug)]
pub(crate) enum DesiredStateCompileError {
    ApplicationModeMismatch {
        configured: CaptureApplicationMode,
        resolved: CaptureApplicationMode,
    },
    EngineConfig(EngineConfigCompileError),
    EngineSourceListenerPortMismatch {
        configured: NonZeroU16,
        selected: NonZeroU16,
    },
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
            Self::EngineSourceListenerPortMismatch {
                configured,
                selected,
            } => DesiredStateCompileErrorKind::EngineSourceListenerPortMismatch {
                configured: *configured,
                selected: *selected,
            },
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
            Self::EngineSourceListenerPortMismatch {
                configured,
                selected,
            } => write!(
                formatter,
                "selected engine source listener port {selected} does not match Desired State port {configured}"
            ),
            Self::Capture(error) => error.fmt(formatter),
        }
    }
}

impl Error for DesiredStateCompileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ApplicationModeMismatch { .. }
            | Self::EngineSourceListenerPortMismatch { .. } => None,
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
    let listener_port = request.config.listener().port();
    let engine_config = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
        engine_template,
        listener_port,
    ))
    .map_err(DesiredStateCompileError::EngineConfig)?;
    compile_desired_state_capture(request)?
        .with_engine_source(SelectedEngineSource::template(engine_config))
}

/// Compile the capture half without selecting or reopening an engine source.
pub(crate) fn compile_desired_state_capture(
    request: DesiredStateCompileRequest,
) -> Result<DesiredStateCaptureArtifacts, DesiredStateCompileError> {
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

    Ok(DesiredStateCaptureArtifacts {
        desired_state: config,
        capture,
    })
}
