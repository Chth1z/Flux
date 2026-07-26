use std::error::Error;
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{
    DurableNativeXtablesTargetResolver, NativeXtablesAdmittedTarget, NativeXtablesConvergedState,
    NativeXtablesConvergenceReport, NativeXtablesDesiredTarget, NativeXtablesEnvironment,
    NativeXtablesOwner, NativeXtablesOwnerAdapter, NativeXtablesOwnerError,
    NativeXtablesProcessOwnerAdapter, NativeXtablesTargetArchiveError, NativeXtablesTargetIdentity,
};
use crate::xtables::native::{
    XtablesRestoreProcessConfig, XtablesRestoreProcessError, XtablesToolSetProcessAdapter,
};
use crate::xtables::owner_durable::{
    NativeXtablesDurableError, NativeXtablesDurableStore, NativeXtablesRuntimeGuard,
};
use crate::xtables::{
    NativeCaptureConvergedState, NativeCaptureConvergence, NativeCaptureConvergenceReport,
    NativeCaptureDesired, NativeCaptureTargetIdentity,
};

pub(crate) struct NativeXtablesRuntimeWriter<A>
where
    A: NativeXtablesOwnerAdapter,
{
    owner: NativeXtablesOwner<A, DurableNativeXtablesTargetResolver>,
    resolver: DurableNativeXtablesTargetResolver,
    recovered: bool,
}

/// Opaque native target admitted inside `flux-platform`.
///
/// No public constructor exists. Host inspection and test evidence therefore cannot manufacture a
/// value accepted by the production process converger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeXtablesCaptureTarget {
    inner: NativeXtablesAdmittedTarget,
    identity: NativeCaptureTargetIdentity,
}

impl NativeXtablesCaptureTarget {
    #[allow(dead_code, reason = "C2 will consume qualified Android admission")]
    pub(crate) fn from_admitted(inner: NativeXtablesAdmittedTarget) -> Self {
        let identity = public_identity(inner.identity());
        Self { inner, identity }
    }

    #[must_use]
    pub const fn identity(&self) -> NativeCaptureTargetIdentity {
        self.identity
    }
}

/// Opaque production process converger. Construction remains platform-private until C2.
pub struct NativeXtablesCaptureConverger {
    inner: NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter>,
}

impl NativeXtablesCaptureConverger {
    #[allow(
        dead_code,
        reason = "C2 will construct the qualified production converger"
    )]
    pub(crate) const fn from_runtime_writer(
        inner: NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter>,
    ) -> Self {
        Self { inner }
    }
}

#[derive(Debug)]
pub struct NativeXtablesCaptureConvergenceError {
    source: NativeXtablesRuntimeWriterError,
}

impl fmt::Display for NativeXtablesCaptureConvergenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(formatter)
    }
}

impl Error for NativeXtablesCaptureConvergenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl NativeCaptureConvergence for NativeXtablesCaptureConverger {
    type Target = NativeXtablesCaptureTarget;
    type Identity = NativeCaptureTargetIdentity;
    type Error = NativeXtablesCaptureConvergenceError;

    fn target_identity(target: &Self::Target) -> Self::Identity {
        target.identity
    }

    fn recover(&mut self) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
        self.inner
            .recover()
            .map(public_report)
            .map_err(|source| NativeXtablesCaptureConvergenceError { source })
    }

    fn converge(
        &mut self,
        desired: NativeCaptureDesired<Self::Target>,
    ) -> Result<NativeCaptureConvergenceReport<Self::Identity>, Self::Error> {
        let desired = match desired {
            NativeCaptureDesired::Active(target) => {
                NativeXtablesDesiredTarget::Active(target.inner)
            }
            NativeCaptureDesired::Stopped => NativeXtablesDesiredTarget::Stopped,
        };
        self.inner
            .converge(desired)
            .map(public_report)
            .map_err(|source| NativeXtablesCaptureConvergenceError { source })
    }
}

fn public_report(
    report: NativeXtablesConvergenceReport,
) -> NativeCaptureConvergenceReport<NativeCaptureTargetIdentity> {
    let state = match report.state() {
        NativeXtablesConvergedState::Active(identity) => {
            NativeCaptureConvergedState::Active(public_identity(identity))
        }
        NativeXtablesConvergedState::CleanAbsent => NativeCaptureConvergedState::CleanAbsent,
    };
    NativeCaptureConvergenceReport::new(state, report.changed())
}

fn public_identity(identity: NativeXtablesTargetIdentity) -> NativeCaptureTargetIdentity {
    NativeCaptureTargetIdentity::new(
        NonZeroU64::new(identity.generation().get())
            .expect("native xtables target generations are nonzero"),
        identity.target_digest(),
        identity.tool_digest(),
        identity.routing_digest(),
    )
}

impl<A> NativeXtablesRuntimeWriter<A>
where
    A: NativeXtablesOwnerAdapter,
{
    pub(crate) fn new(
        adapter: A,
        durable: NativeXtablesDurableStore,
        environment: NativeXtablesEnvironment,
    ) -> Result<Self, NativeXtablesRuntimeWriterError> {
        let resolver = DurableNativeXtablesTargetResolver::open(durable.clone())
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?;
        let owner = NativeXtablesOwner::new(adapter, resolver.clone(), durable, environment);
        Ok(Self {
            owner,
            resolver,
            recovered: false,
        })
    }

    pub(crate) fn recover(
        &mut self,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesRuntimeWriterError> {
        let _transaction = self.begin_transaction()?;
        let report = match self.owner.recover() {
            Ok(report) => report,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
            }
        };
        if let Err(source) = self.settle_archive(report.state()) {
            self.recovered = false;
            return Err(source);
        }
        self.recovered = true;
        Ok(report)
    }

    pub(crate) fn converge(
        &mut self,
        target: NativeXtablesDesiredTarget,
    ) -> Result<NativeXtablesConvergenceReport, NativeXtablesRuntimeWriterError> {
        if !self.recovered {
            return Err(NativeXtablesRuntimeWriterError::RecoveryRequired);
        }
        let _transaction = self.begin_transaction()?;
        if let NativeXtablesDesiredTarget::Active(target) = &target {
            self.resolver.stage(target.clone()).map_err(|source| {
                NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source))
            })?;
        }
        let report = match self.owner.converge(target) {
            Ok(report) => report,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
            }
        };
        if let Err(source) = self.settle_archive(report.state()) {
            self.recovered = false;
            return Err(source);
        }
        Ok(report)
    }

    fn begin_transaction(
        &mut self,
    ) -> Result<NativeXtablesRuntimeGuard, NativeXtablesRuntimeWriterError> {
        let guard = match self.owner.durable.acquire_runtime_guard() {
            Ok(guard) => guard,
            Err(source) => {
                self.recovered = false;
                return Err(NativeXtablesRuntimeWriterError::Durable(Box::new(source)));
            }
        };
        if let Err(source) = self.resolver.refresh() {
            self.recovered = false;
            return Err(NativeXtablesRuntimeWriterError::TargetArchive(Box::new(
                source,
            )));
        }
        Ok(guard)
    }

    fn settle_archive(
        &self,
        state: NativeXtablesConvergedState,
    ) -> Result<(), NativeXtablesRuntimeWriterError> {
        if matches!(state, NativeXtablesConvergedState::CleanAbsent)
            && self
                .owner
                .durable
                .load_journal()
                .map_err(|source| NativeXtablesRuntimeWriterError::SettledDurable {
                    state,
                    source: Box::new(source),
                })?
                .is_some()
        {
            return Ok(());
        }
        self.resolver.retain_state(state).map_err(|source| {
            NativeXtablesRuntimeWriterError::SettledArchive {
                state,
                source: Box::new(source),
            }
        })
    }

    pub(crate) fn observe(
        &mut self,
        desired: NativeXtablesDryRunTarget<'_>,
    ) -> Result<NativeXtablesDryRunReport, NativeXtablesRuntimeWriterError> {
        self.resolver
            .refresh()
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?;
        let archived_targets = self
            .resolver
            .identities()
            .map_err(|source| NativeXtablesRuntimeWriterError::TargetArchive(Box::new(source)))?
            .into_boxed_slice();
        let journal_present = self
            .owner
            .durable
            .load_journal()
            .map_err(|source| NativeXtablesRuntimeWriterError::Durable(Box::new(source)))?
            .is_some();
        let desired_identity = match desired {
            NativeXtablesDryRunTarget::Active(target) => Some(target.identity()),
            NativeXtablesDryRunTarget::Stopped => None,
        };
        let tool_identity_matches = desired_identity
            .is_none_or(|identity| self.owner.adapter.tool_digest() == identity.tool_digest());

        let exact_desired = match desired {
            NativeXtablesDryRunTarget::Active(target) if tool_identity_matches => self
                .owner
                .target_is_exact_active(target)
                .map_err(|source| NativeXtablesRuntimeWriterError::Owner(Box::new(source)))?,
            NativeXtablesDryRunTarget::Active(_) => false,
            NativeXtablesDryRunTarget::Stopped => false,
        };
        let clean_absent = if exact_desired {
            false
        } else {
            match self
                .owner
                .require_global_xtables_absence()
                .and_then(|()| self.owner.require_recovery_policy_absence())
            {
                Ok(()) => true,
                Err(NativeXtablesOwnerError::LiveStateConflict(_)) => false,
                Err(source) => {
                    return Err(NativeXtablesRuntimeWriterError::Owner(Box::new(source)));
                }
            }
        };
        let disposition = match (desired, exact_desired, clean_absent, tool_identity_matches) {
            (NativeXtablesDryRunTarget::Active(_), true, _, true)
            | (NativeXtablesDryRunTarget::Stopped, _, true, _) => {
                NativeXtablesDryRunDisposition::NoChange
            }
            (NativeXtablesDryRunTarget::Active(_), false, true, true) => {
                NativeXtablesDryRunDisposition::Activate
            }
            (NativeXtablesDryRunTarget::Stopped, _, false, _) => {
                NativeXtablesDryRunDisposition::RecoverOrStop
            }
            (NativeXtablesDryRunTarget::Active(_), _, _, false)
            | (NativeXtablesDryRunTarget::Active(_), false, false, true) => {
                NativeXtablesDryRunDisposition::Blocked
            }
        };
        Ok(NativeXtablesDryRunReport {
            recovered: self.recovered,
            journal_present,
            archived_targets,
            desired_identity,
            tool_identity_matches,
            exact_desired,
            clean_absent,
            disposition,
        })
    }

    #[cfg(test)]
    pub(crate) fn into_parts(self) -> (A, NativeXtablesDurableStore, NativeXtablesEnvironment) {
        let environment = self.owner.environment.clone();
        let (adapter, _resolver, durable) = self.owner.into_parts();
        (adapter, durable, environment)
    }

    #[cfg(test)]
    pub(crate) const fn test_adapter(&self) -> &A {
        &self.owner.adapter
    }

    #[cfg(test)]
    pub(crate) const fn test_adapter_mut(&mut self) -> &mut A {
        &mut self.owner.adapter
    }

    #[cfg(test)]
    pub(crate) fn test_archived_identities(
        &self,
    ) -> Result<Vec<NativeXtablesTargetIdentity>, NativeXtablesTargetArchiveError> {
        self.resolver.identities()
    }
}

impl NativeXtablesRuntimeWriter<NativeXtablesProcessOwnerAdapter> {
    pub(crate) fn open_process(
        config: NativeXtablesProcessWriterConfig,
        environment: NativeXtablesEnvironment,
    ) -> Result<Self, NativeXtablesRuntimeWriterError> {
        let process = XtablesRestoreProcessConfig::new(config.wait_seconds, config.timeout)
            .map_err(|source| NativeXtablesRuntimeWriterError::ProcessAdapter(Box::new(source)))?;
        let tools = XtablesToolSetProcessAdapter::discover_standard(
            &config.tool_root,
            config.require_ipv6,
            process,
        )
        .map_err(|source| NativeXtablesRuntimeWriterError::ProcessAdapter(Box::new(source)))?;
        Self::new(
            NativeXtablesProcessOwnerAdapter::new(tools),
            NativeXtablesDurableStore::new(config.durable_root),
            environment,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesProcessWriterConfig {
    tool_root: PathBuf,
    durable_root: PathBuf,
    require_ipv6: bool,
    wait_seconds: u16,
    timeout: Duration,
}

impl NativeXtablesProcessWriterConfig {
    #[must_use]
    pub(crate) fn new(
        tool_root: impl AsRef<Path>,
        durable_root: impl AsRef<Path>,
        require_ipv6: bool,
        wait_seconds: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            tool_root: tool_root.as_ref().to_owned(),
            durable_root: durable_root.as_ref().to_owned(),
            require_ipv6,
            wait_seconds,
            timeout,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum NativeXtablesDryRunTarget<'a> {
    Active(&'a NativeXtablesAdmittedTarget),
    Stopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesDryRunDisposition {
    NoChange,
    Activate,
    RecoverOrStop,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesDryRunReport {
    recovered: bool,
    journal_present: bool,
    archived_targets: Box<[NativeXtablesTargetIdentity]>,
    desired_identity: Option<NativeXtablesTargetIdentity>,
    tool_identity_matches: bool,
    exact_desired: bool,
    clean_absent: bool,
    disposition: NativeXtablesDryRunDisposition,
}

impl NativeXtablesDryRunReport {
    #[must_use]
    pub(crate) const fn recovered(&self) -> bool {
        self.recovered
    }

    #[must_use]
    pub(crate) const fn journal_present(&self) -> bool {
        self.journal_present
    }

    #[must_use]
    pub(crate) const fn archived_targets(&self) -> &[NativeXtablesTargetIdentity] {
        &self.archived_targets
    }

    #[must_use]
    pub(crate) const fn desired_identity(&self) -> Option<NativeXtablesTargetIdentity> {
        self.desired_identity
    }

    #[must_use]
    pub(crate) const fn tool_identity_matches(&self) -> bool {
        self.tool_identity_matches
    }

    #[must_use]
    pub(crate) const fn exact_desired(&self) -> bool {
        self.exact_desired
    }

    #[must_use]
    pub(crate) const fn clean_absent(&self) -> bool {
        self.clean_absent
    }

    #[must_use]
    pub(crate) const fn disposition(&self) -> NativeXtablesDryRunDisposition {
        self.disposition
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesRuntimeWriterError {
    RecoveryRequired,
    TargetArchive(Box<NativeXtablesTargetArchiveError>),
    Durable(Box<NativeXtablesDurableError>),
    ProcessAdapter(Box<XtablesRestoreProcessError>),
    Owner(Box<NativeXtablesOwnerError>),
    SettledArchive {
        state: NativeXtablesConvergedState,
        source: Box<NativeXtablesTargetArchiveError>,
    },
    SettledDurable {
        state: NativeXtablesConvergedState,
        source: Box<NativeXtablesDurableError>,
    },
}

impl fmt::Display for NativeXtablesRuntimeWriterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecoveryRequired => formatter
                .write_str("native runtime recovery must complete before convergence is allowed"),
            Self::TargetArchive(source) => source.fmt(formatter),
            Self::Durable(source) => source.fmt(formatter),
            Self::ProcessAdapter(source) => source.fmt(formatter),
            Self::Owner(source) => source.fmt(formatter),
            Self::SettledArchive { state, source } => write!(
                formatter,
                "native runtime settled at {state:?}, but target-archive maintenance failed: {source}"
            ),
            Self::SettledDurable { state, source } => write!(
                formatter,
                "native runtime settled at {state:?}, but terminal-journal inspection failed: {source}"
            ),
        }
    }
}

impl Error for NativeXtablesRuntimeWriterError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TargetArchive(source) => Some(source.as_ref()),
            Self::Durable(source) => Some(source.as_ref()),
            Self::ProcessAdapter(source) => Some(source.as_ref()),
            Self::Owner(source) => Some(source.as_ref()),
            Self::SettledArchive { source, .. } => Some(source.as_ref()),
            Self::SettledDurable { source, .. } => Some(source.as_ref()),
            Self::RecoveryRequired => None,
        }
    }
}
