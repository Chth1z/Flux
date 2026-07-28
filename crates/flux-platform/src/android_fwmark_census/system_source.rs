use std::error::Error;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use flux_core::{
    AndroidNetdSourceProfile, CapabilityProfile, CapabilityProfileSource, FwmarkCandidate,
    NetworkInventory, NetworkNamespaceIdentity,
};

use super::nftables::{AndroidNftablesTransportErrorKind, collect_android_nftables_fwmarks};
use super::{
    AndroidExistingFluxOwnershipError, AndroidExistingFluxOwnershipErrorKind,
    AndroidExistingFluxOwnershipObservation, AndroidFwmarkCensusCollectionStage,
    AndroidFwmarkCensusCoordinatorSource, AndroidFwmarkCensusExternalPhase,
    AndroidFwmarkCensusExternalSnapshot, AndroidNftablesFwmarkObservationError,
    AndroidNftablesFwmarkObservationErrorKind, AndroidTrafficControlBpfFwmarkObservationError,
    AndroidXfrmFwmarkObservationError, AndroidXtablesFwmarkObservation,
    AndroidXtablesFwmarkObservationError, MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND,
    collect_android_existing_flux_ownership, collect_android_traffic_control_bpf_fwmarks,
    collect_android_xfrm_fwmarks, observe_android_xtables_fwmarks,
};
use crate::xtables::collect_android_xtables_save_snapshots;
use crate::{
    SystemAndroidKernelConfigError, SystemAndroidKernelConfigErrorClass,
    SystemAndroidKernelConfigErrorKind, SystemAndroidKernelConfigSource,
    SystemCapabilityProfileSource, collect_network_inventory_once,
};

const SYSTEM_XTABLES_TOOL_ROOT: &str = "/system/bin";
const SYSTEM_FLUX_DURABLE_ROOT: &str = "/data/adb/flux/run";
const MINIMUM_COLLECTOR_BOUND: Duration = Duration::from_millis(1);

/// Stable failure class from the fixed-path production Android census source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAndroidFwmarkCensusSourceErrorKind {
    InvalidCapabilityStage,
    InvalidBound,
    DeadlineExceeded,
    KernelConfig,
    NftablesGate,
    XtablesProcess,
    XtablesObservation,
    NftablesObservation,
    TrafficControlBpfObservation,
    XfrmObservation,
    NetworkInventory,
    ExistingFluxOwnership,
}

/// Privacy-safe native nftables failure class retained by the production source boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAndroidNftablesObservationErrorClass {
    InvalidBound,
    PermissionDenied,
    Transport,
    SystemCall,
    Timeout,
    ShortWrite,
    UnexpectedSender,
    MalformedDatagram,
    KernelRejected,
    KernelRejectedInvalidRequest,
    KernelRejectedUnsupported,
    KernelRejectedResource,
    KernelRejectedBusy,
    SnapshotDrift,
    InvalidMessageType,
    InvalidFamilyHeader,
    InvalidRule,
    InvalidExpression,
    LimitExceeded,
}

/// Sanitized production-source error.
///
/// Display and Debug expose only the stable class. The concrete source remains available through
/// the standard error chain for trusted local diagnostics and is never copied into census reports.
pub struct SystemAndroidFwmarkCensusSourceError {
    kind: SystemAndroidFwmarkCensusSourceErrorKind,
    kernel_config_class: Option<SystemAndroidKernelConfigErrorClass>,
    nftables_class: Option<SystemAndroidNftablesObservationErrorClass>,
    existing_flux_kind: Option<AndroidExistingFluxOwnershipErrorKind>,
    source: Option<Box<dyn Error + 'static>>,
}

impl SystemAndroidFwmarkCensusSourceError {
    #[must_use]
    pub const fn kind(&self) -> SystemAndroidFwmarkCensusSourceErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn nftables_class(&self) -> Option<SystemAndroidNftablesObservationErrorClass> {
        self.nftables_class
    }

    #[must_use]
    pub const fn kernel_config_kind(&self) -> Option<SystemAndroidKernelConfigErrorKind> {
        match self.kernel_config_class {
            Some(class) => Some(class.kind()),
            None => None,
        }
    }

    #[must_use]
    pub const fn kernel_config_class(&self) -> Option<SystemAndroidKernelConfigErrorClass> {
        self.kernel_config_class
    }

    #[must_use]
    pub const fn existing_flux_kind(&self) -> Option<AndroidExistingFluxOwnershipErrorKind> {
        self.existing_flux_kind
    }

    const fn new(kind: SystemAndroidFwmarkCensusSourceErrorKind) -> Self {
        Self {
            kind,
            kernel_config_class: None,
            nftables_class: None,
            existing_flux_kind: None,
            source: None,
        }
    }

    fn with_source(
        kind: SystemAndroidFwmarkCensusSourceErrorKind,
        source: impl Error + 'static,
    ) -> Self {
        Self {
            kind,
            kernel_config_class: None,
            nftables_class: None,
            existing_flux_kind: None,
            source: Some(Box::new(source)),
        }
    }

    fn with_kernel_config_source(source: SystemAndroidKernelConfigError) -> Self {
        Self {
            kind: SystemAndroidFwmarkCensusSourceErrorKind::KernelConfig,
            kernel_config_class: Some(source.class()),
            nftables_class: None,
            existing_flux_kind: None,
            source: Some(Box::new(source)),
        }
    }

    fn with_nftables_source(source: AndroidNftablesFwmarkObservationError) -> Self {
        Self {
            kind: SystemAndroidFwmarkCensusSourceErrorKind::NftablesObservation,
            kernel_config_class: None,
            nftables_class: Some(classify_nftables_observation_error(
                source.kind(),
                source.transport_kind(),
                source.raw_os_error(),
            )),
            existing_flux_kind: None,
            source: Some(Box::new(source)),
        }
    }

    fn with_existing_flux_source(source: AndroidExistingFluxOwnershipError) -> Self {
        Self {
            kind: SystemAndroidFwmarkCensusSourceErrorKind::ExistingFluxOwnership,
            kernel_config_class: None,
            nftables_class: None,
            existing_flux_kind: Some(source.kind()),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Debug for SystemAndroidFwmarkCensusSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemAndroidFwmarkCensusSourceError")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for SystemAndroidFwmarkCensusSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "system Android fwmark census source failed: {:?}",
            self.kind
        )
    }
}

impl Error for SystemAndroidFwmarkCensusSourceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
}

/// Fixed-path, read-only production source for the Android fwmark census coordinator.
#[derive(Debug, Default)]
pub struct SystemAndroidFwmarkCensusSource {
    capability_profile: SystemCapabilityProfileSource,
    kernel_config: SystemAndroidKernelConfigSource,
}

impl SystemAndroidFwmarkCensusSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AndroidFwmarkCensusCoordinatorSource for SystemAndroidFwmarkCensusSource {
    type Error = SystemAndroidFwmarkCensusSourceError;

    fn collect_capability_profile(
        &mut self,
        stage: AndroidFwmarkCensusCollectionStage,
    ) -> Result<CapabilityProfile, Self::Error> {
        if !matches!(
            stage,
            AndroidFwmarkCensusCollectionStage::CapabilityBefore
                | AndroidFwmarkCensusCollectionStage::CapabilityAfter
        ) {
            return Err(SystemAndroidFwmarkCensusSourceError::new(
                SystemAndroidFwmarkCensusSourceErrorKind::InvalidCapabilityStage,
            ));
        }
        Ok(self.capability_profile.collect_capability_profile())
    }

    fn collect_external_snapshot(
        &mut self,
        _phase: AndroidFwmarkCensusExternalPhase,
        netd_source_profile: AndroidNetdSourceProfile,
        candidate: FwmarkCandidate,
        bound: Duration,
    ) -> Result<AndroidFwmarkCensusExternalSnapshot, Self::Error> {
        let deadline = stage_deadline(bound)?;
        let kernel_config = self
            .kernel_config
            .collect()
            .map_err(SystemAndroidFwmarkCensusSourceError::with_kernel_config_source)?;
        ensure_before(deadline)?;
        let nftables_gate = kernel_config
            .nftables_observation_gate()
            .map_err(|source| {
                SystemAndroidFwmarkCensusSourceError::with_source(
                    SystemAndroidFwmarkCensusSourceErrorKind::NftablesGate,
                    source,
                )
            })?;
        let saves = collect_android_xtables_save_snapshots(
            Path::new(SYSTEM_XTABLES_TOOL_ROOT),
            remaining(deadline)?,
        )
        .map_err(|source| {
            SystemAndroidFwmarkCensusSourceError::with_source(
                SystemAndroidFwmarkCensusSourceErrorKind::XtablesProcess,
                source,
            )
        })?;
        let xtables = observe_android_xtables_fwmarks(
            saves.ipv4(),
            saves.ipv6(),
            netd_source_profile,
            candidate,
        )
        .map_err(map_xtables_observation)?;
        ensure_before(deadline)?;
        let nftables = collect_android_nftables_fwmarks(nftables_gate, remaining(deadline)?)
            .map_err(map_nftables_observation)?;
        let traffic_control_bpf = collect_android_traffic_control_bpf_fwmarks(remaining(deadline)?)
            .map_err(map_traffic_control_bpf_observation)?;
        let xfrm =
            collect_android_xfrm_fwmarks(remaining(deadline)?).map_err(map_xfrm_observation)?;
        ensure_before(deadline)?;
        Ok(AndroidFwmarkCensusExternalSnapshot::new(
            kernel_config.digest(),
            xtables,
            nftables,
            traffic_control_bpf,
            xfrm,
        ))
    }

    fn collect_network_inventory(
        &mut self,
        bound: Duration,
    ) -> Result<Arc<NetworkInventory>, Self::Error> {
        collect_network_inventory_once(bound).map_err(|source| {
            SystemAndroidFwmarkCensusSourceError::with_source(
                SystemAndroidFwmarkCensusSourceErrorKind::NetworkInventory,
                source,
            )
        })
    }

    fn collect_existing_flux_ownership(
        &mut self,
        inventory: &NetworkInventory,
        capability_profile: &CapabilityProfile,
        network_namespace: NetworkNamespaceIdentity,
        xtables: &AndroidXtablesFwmarkObservation,
    ) -> Result<AndroidExistingFluxOwnershipObservation, Self::Error> {
        collect_android_existing_flux_ownership(
            SYSTEM_FLUX_DURABLE_ROOT,
            inventory,
            capability_profile,
            network_namespace,
            xtables,
        )
        .map_err(SystemAndroidFwmarkCensusSourceError::with_existing_flux_source)
    }
}

fn stage_deadline(bound: Duration) -> Result<Instant, SystemAndroidFwmarkCensusSourceError> {
    if !(MINIMUM_COLLECTOR_BOUND..=MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND).contains(&bound) {
        return Err(SystemAndroidFwmarkCensusSourceError::new(
            SystemAndroidFwmarkCensusSourceErrorKind::InvalidBound,
        ));
    }
    Instant::now().checked_add(bound).ok_or_else(|| {
        SystemAndroidFwmarkCensusSourceError::new(
            SystemAndroidFwmarkCensusSourceErrorKind::InvalidBound,
        )
    })
}

fn remaining(deadline: Instant) -> Result<Duration, SystemAndroidFwmarkCensusSourceError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < MINIMUM_COLLECTOR_BOUND {
        Err(SystemAndroidFwmarkCensusSourceError::new(
            SystemAndroidFwmarkCensusSourceErrorKind::DeadlineExceeded,
        ))
    } else {
        Ok(remaining)
    }
}

fn ensure_before(deadline: Instant) -> Result<(), SystemAndroidFwmarkCensusSourceError> {
    remaining(deadline).map(|_| ())
}

fn map_xtables_observation(
    source: AndroidXtablesFwmarkObservationError,
) -> SystemAndroidFwmarkCensusSourceError {
    SystemAndroidFwmarkCensusSourceError::with_source(
        SystemAndroidFwmarkCensusSourceErrorKind::XtablesObservation,
        source,
    )
}

fn map_nftables_observation(
    source: AndroidNftablesFwmarkObservationError,
) -> SystemAndroidFwmarkCensusSourceError {
    SystemAndroidFwmarkCensusSourceError::with_nftables_source(source)
}

const fn classify_nftables_observation_error(
    kind: AndroidNftablesFwmarkObservationErrorKind,
    transport_kind: Option<AndroidNftablesTransportErrorKind>,
    raw_os_error: Option<i32>,
) -> SystemAndroidNftablesObservationErrorClass {
    match kind {
        AndroidNftablesFwmarkObservationErrorKind::InvalidBound => {
            SystemAndroidNftablesObservationErrorClass::InvalidBound
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(raw_os_error, Some(libc::EPERM) | Some(libc::EACCES)) =>
        {
            SystemAndroidNftablesObservationErrorClass::PermissionDenied
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::SystemCall)
            ) =>
        {
            SystemAndroidNftablesObservationErrorClass::SystemCall
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::Timeout)
            ) =>
        {
            SystemAndroidNftablesObservationErrorClass::Timeout
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::ShortWrite)
            ) =>
        {
            SystemAndroidNftablesObservationErrorClass::ShortWrite
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::UnexpectedSender)
            ) =>
        {
            SystemAndroidNftablesObservationErrorClass::UnexpectedSender
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::MalformedDatagram)
            ) =>
        {
            SystemAndroidNftablesObservationErrorClass::MalformedDatagram
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport
            if matches!(
                transport_kind,
                Some(AndroidNftablesTransportErrorKind::KernelRejected)
            ) =>
        {
            classify_nftables_kernel_rejection(raw_os_error)
        }
        AndroidNftablesFwmarkObservationErrorKind::Transport => {
            SystemAndroidNftablesObservationErrorClass::Transport
        }
        AndroidNftablesFwmarkObservationErrorKind::SnapshotDrift => {
            SystemAndroidNftablesObservationErrorClass::SnapshotDrift
        }
        AndroidNftablesFwmarkObservationErrorKind::InvalidMessageType => {
            SystemAndroidNftablesObservationErrorClass::InvalidMessageType
        }
        AndroidNftablesFwmarkObservationErrorKind::InvalidFamilyHeader => {
            SystemAndroidNftablesObservationErrorClass::InvalidFamilyHeader
        }
        AndroidNftablesFwmarkObservationErrorKind::InvalidRule => {
            SystemAndroidNftablesObservationErrorClass::InvalidRule
        }
        AndroidNftablesFwmarkObservationErrorKind::InvalidExpression => {
            SystemAndroidNftablesObservationErrorClass::InvalidExpression
        }
        AndroidNftablesFwmarkObservationErrorKind::LimitExceeded => {
            SystemAndroidNftablesObservationErrorClass::LimitExceeded
        }
    }
}

const fn classify_nftables_kernel_rejection(
    raw_os_error: Option<i32>,
) -> SystemAndroidNftablesObservationErrorClass {
    match raw_os_error {
        Some(libc::EINVAL | libc::EBADMSG | libc::EMSGSIZE | libc::EPROTO) => {
            SystemAndroidNftablesObservationErrorClass::KernelRejectedInvalidRequest
        }
        Some(libc::EAFNOSUPPORT | libc::ENODEV | libc::ENOSYS) => {
            SystemAndroidNftablesObservationErrorClass::KernelRejectedUnsupported
        }
        Some(libc::ENOBUFS | libc::ENOMEM | libc::ENOSPC) => {
            SystemAndroidNftablesObservationErrorClass::KernelRejectedResource
        }
        Some(libc::EAGAIN | libc::EBUSY | libc::EINTR) => {
            SystemAndroidNftablesObservationErrorClass::KernelRejectedBusy
        }
        _ => SystemAndroidNftablesObservationErrorClass::KernelRejected,
    }
}

fn map_traffic_control_bpf_observation(
    source: AndroidTrafficControlBpfFwmarkObservationError,
) -> SystemAndroidFwmarkCensusSourceError {
    SystemAndroidFwmarkCensusSourceError::with_source(
        SystemAndroidFwmarkCensusSourceErrorKind::TrafficControlBpfObservation,
        source,
    )
}

fn map_xfrm_observation(
    source: AndroidXfrmFwmarkObservationError,
) -> SystemAndroidFwmarkCensusSourceError {
    SystemAndroidFwmarkCensusSourceError::with_source(
        SystemAndroidFwmarkCensusSourceErrorKind::XfrmObservation,
        source,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlatformError;

    #[test]
    fn production_source_rejects_non_capability_stages_without_collecting() {
        let mut source = SystemAndroidFwmarkCensusSource::new();
        let error = source
            .collect_capability_profile(AndroidFwmarkCensusCollectionStage::NetworkInventory)
            .expect_err("only the two capability stages are accepted");
        assert_eq!(
            error.kind(),
            SystemAndroidFwmarkCensusSourceErrorKind::InvalidCapabilityStage
        );
    }

    #[test]
    fn production_source_bound_and_error_text_are_sanitized() {
        let error = stage_deadline(Duration::ZERO).expect_err("zero bound must fail");
        assert_eq!(
            error.kind(),
            SystemAndroidFwmarkCensusSourceErrorKind::InvalidBound
        );
        assert_eq!(
            error.to_string(),
            "system Android fwmark census source failed: InvalidBound"
        );
        assert_eq!(SYSTEM_XTABLES_TOOL_ROOT, "/system/bin");
        assert_eq!(SYSTEM_FLUX_DURABLE_ROOT, "/data/adb/flux/run");
    }

    #[test]
    fn network_inventory_errors_retain_a_private_source_chain() {
        let error = SystemAndroidFwmarkCensusSourceError::with_source(
            SystemAndroidFwmarkCensusSourceErrorKind::NetworkInventory,
            PlatformError::UnsupportedPlatform("fixture"),
        );
        assert!(error.source().is_some());
        assert!(!format!("{error:?}").contains("fixture"));
        assert!(!error.to_string().contains("fixture"));
    }

    #[test]
    fn nftables_error_class_preserves_semantics_without_raw_errno() {
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::EPERM),
            ),
            SystemAndroidNftablesObservationErrorClass::PermissionDenied
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::EINVAL),
            ),
            SystemAndroidNftablesObservationErrorClass::KernelRejectedInvalidRequest
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::EAFNOSUPPORT),
            ),
            SystemAndroidNftablesObservationErrorClass::KernelRejectedUnsupported
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::ENOBUFS),
            ),
            SystemAndroidNftablesObservationErrorClass::KernelRejectedResource
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::EBUSY),
            ),
            SystemAndroidNftablesObservationErrorClass::KernelRejectedBusy
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::KernelRejected),
                Some(libc::EIO),
            ),
            SystemAndroidNftablesObservationErrorClass::KernelRejected
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                Some(AndroidNftablesTransportErrorKind::Timeout),
                None,
            ),
            SystemAndroidNftablesObservationErrorClass::Timeout
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::Transport,
                None,
                Some(libc::EINVAL),
            ),
            SystemAndroidNftablesObservationErrorClass::Transport
        );
        assert_eq!(
            classify_nftables_observation_error(
                AndroidNftablesFwmarkObservationErrorKind::InvalidExpression,
                None,
                None,
            ),
            SystemAndroidNftablesObservationErrorClass::InvalidExpression
        );
    }
}
