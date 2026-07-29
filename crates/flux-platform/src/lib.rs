//! Linux and Android platform adapters for Flux.

use std::error::Error;
use std::fmt;

// This hardened parser is intentionally internal until the inventory source
// owns the higher-level snapshot interface that consumes it.
#[allow(dead_code)]
mod address_sync;
mod android_fwmark_census;
mod android_identity;
mod android_identity_properties;
mod android_kernel_capabilities;
mod capability;
mod child_process;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod engine_credential_probe;
mod file_observer;
mod netlink;
#[allow(dead_code)]
mod network_observer;
mod process;
mod reactor;
mod seqpacket;
mod shutdown;
mod sing_box;
pub mod socket_diagnostics;
mod xtables;

pub use android_fwmark_census::{
    ANDROID_FWMARK_CENSUS_COLLECTOR_REVISION, ANDROID_FWMARK_CENSUS_PROJECTION_CELLS,
    ANDROID_FWMARK_CENSUS_PROJECTION_METRICS, AndroidExistingFluxOwnershipDigest,
    AndroidExistingFluxOwnershipError, AndroidExistingFluxOwnershipErrorKind,
    AndroidExistingFluxOwnershipObservation, AndroidExistingFluxProcessObservationErrorClass,
    AndroidFwmarkCensusAssemblyError, AndroidFwmarkCensusCollectionStage,
    AndroidFwmarkCensusCoordinatorError, AndroidFwmarkCensusCoordinatorOutcome,
    AndroidFwmarkCensusCoordinatorPurpose, AndroidFwmarkCensusCoordinatorRequest,
    AndroidFwmarkCensusCoordinatorRequestError, AndroidFwmarkCensusCoordinatorSource,
    AndroidFwmarkCensusExternalPhase, AndroidFwmarkCensusExternalSnapshot,
    AndroidFwmarkCensusExternalSnapshotDigest, AndroidFwmarkCensusMetric,
    AndroidFwmarkCensusMetricKind, AndroidFwmarkCensusPlanningEvidence,
    AndroidFwmarkCensusProbeReports, AndroidFwmarkCensusProjection,
    AndroidFwmarkCensusProjectionDigest, AndroidFwmarkCensusReportPhase,
    AndroidNftablesFwmarkObservation, AndroidNftablesFwmarkObservationError,
    AndroidNftablesFwmarkObservationErrorKind, AndroidNftablesSnapshotDigest,
    AndroidTrafficControlBpfFwmarkObservation, AndroidTrafficControlBpfFwmarkObservationError,
    AndroidTrafficControlBpfFwmarkObservationErrorKind, AndroidTrafficControlBpfSnapshotDigest,
    AndroidXfrmFwmarkObservation, AndroidXfrmFwmarkObservationError,
    AndroidXfrmFwmarkObservationErrorKind, AndroidXfrmSnapshotDigest,
    AndroidXtablesFwmarkObservation, AndroidXtablesFwmarkObservationError,
    AndroidXtablesFwmarkObservationErrorKind, AndroidXtablesSnapshotDigest,
    MAX_ANDROID_FWMARK_CENSUS_STAGE_BOUND, assemble_android_fwmark_census_projection,
    coordinate_android_fwmark_census, coordinate_android_fwmark_census_for_inventory,
    observe_android_xtables_fwmarks, parse_android_fwmark_census_probe_reports,
    validate_android_fwmark_census_probe_reports, validate_android_fwmark_census_projection_report,
    write_android_fwmark_census_projection_report,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use android_fwmark_census::{
    SystemAndroidFwmarkCensusSource, SystemAndroidFwmarkCensusSourceError,
    SystemAndroidFwmarkCensusSourceErrorKind, SystemAndroidNftablesObservationErrorClass,
    collect_android_existing_flux_ownership, collect_android_traffic_control_bpf_fwmarks,
    collect_android_xfrm_fwmarks,
};
pub use android_kernel_capabilities::{
    ALL_ANDROID_KERNEL_FEATURES, ANDROID_KERNEL_CONFIG_DIGEST_BYTES, AndroidCapturePathCandidate,
    AndroidCapturePathDecision, AndroidCapturePathState, AndroidKernelConfigDigest,
    AndroidKernelConfigOptionState, AndroidKernelConfigParseError,
    AndroidKernelConfigParseErrorKind, AndroidKernelConfigSnapshot, AndroidKernelFeature,
    AndroidKernelFeatureState, AndroidNftablesObservationGate, AndroidNftablesObservationGateError,
    MAX_ANDROID_KERNEL_CONFIG_COMPRESSED_BYTES, MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES,
    MAX_ANDROID_KERNEL_CONFIG_LINE_BYTES, MAX_ANDROID_KERNEL_CONFIG_OPTIONS,
    parse_android_kernel_config, select_android_capture_path,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use android_kernel_capabilities::{
    SystemAndroidKernelConfigError, SystemAndroidKernelConfigErrorClass,
    SystemAndroidKernelConfigErrorKind, SystemAndroidKernelConfigSource,
};
pub use capability::{CapabilityProfilePaths, SystemCapabilityProfileSource};
pub use child_process::TRANSPARENT_PROXY_ENGINE_CAPABILITY_MASK;
pub use file_observer::{FileObservationBatch, FileObservationError, FileObservationPaths};
pub use network_observer::NetworkInventorySource;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use network_observer::collect_network_inventory_once;
pub use process::{
    PROCESS_CREDENTIAL_MAP_DIGEST_BYTES, ProcessCredentialMapDigest, ProcessCredentialMapKind,
    ProcessCredentials, ProcessDomainObservation, ProcessHandle, ProcessHandleError,
    ProcessHandleErrorKind, ProcessIdentity, ProcessNamespaceIdentity, ProcessObservation,
};
pub use reactor::{
    DaemonReactor, NetworkInventoryAttachment, NetworkInventoryDegradation,
    NetworkInventoryRefreshDisposition, NetworkInventoryRefreshHandle, ReactorError,
    ReactorStopHandle, StopDisposition,
};
pub use seqpacket::{PeerCredentials, SeqpacketConnection, SeqpacketListener, Uid};
pub use shutdown::ShutdownSignal;
pub use sing_box::{
    ReadinessEvidence, SingBoxExit, SingBoxLaunchSpec, SingBoxPrivilege, SingBoxReadiness,
};
pub use xtables::{
    MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT, MAX_XTABLES_RESTORE_BYTES,
    MAX_XTABLES_RESTORE_CHAIN_BYTES, MAX_XTABLES_RESTORE_COMMANDS, MAX_XTABLES_RESTORE_LINE_BYTES,
    MAX_XTABLES_RESTORE_LINES, MAX_XTABLES_RESTORE_TOKEN_BYTES,
    MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, MAX_XTABLES_RESTORE_TRANSACTIONS,
    NativeCaptureConvergedState, NativeCaptureConvergence, NativeCaptureConvergenceReport,
    NativeCaptureDesired, NativeCaptureTargetIdentity, XTABLES_CAPTURE_DIGEST_BYTES,
    XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION, XTABLES_RESTORE_DIGEST_BYTES,
    XTABLES_RESTORE_SCHEMA_VERSION, XtablesCaptureArtifactPair, XtablesCaptureArtifactPairDigest,
    XtablesCaptureArtifactSet, XtablesCaptureArtifactSetDigest, XtablesCaptureEntryPoint,
    XtablesCaptureEntryPointRole, XtablesCaptureEntrySelector, XtablesCaptureExtension,
    XtablesCaptureExtensions, XtablesCaptureHook, XtablesCaptureLoweringBudget,
    XtablesCaptureLoweringDigest, XtablesCaptureLoweringError, XtablesCaptureLoweringRequest,
    XtablesCaptureNamespace, XtablesCapturePredicateKind, XtablesCaptureResourceUsage,
    XtablesCaptureTransactionOrder, XtablesCaptureTransactionStep, XtablesChainDeclaration,
    XtablesInterfaceRenderErrorKind, XtablesLocalOutputRoutingRequirement,
    XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingSpecError,
    XtablesLocalOutputRoutingTarget, XtablesLocalOutputRoutingTargetError,
    XtablesLocalOutputTransactionRequirements, XtablesLoopEscapeRequirement, XtablesRestoreAction,
    XtablesRestoreArtifact, XtablesRestoreCommand, XtablesRestoreCommandKind,
    XtablesRestoreContext, XtablesRestoreDigest, XtablesRestoreEntry, XtablesRestoreFamily,
    XtablesRestoreLimit, XtablesRestoreParseError, XtablesRestoreParseErrorKind,
    XtablesRestoreResourceUsage, XtablesRestoreTable, XtablesRestoreToken,
    XtablesRestoreTransaction, XtablesTproxyTarget, XtablesTransparentListenerRequirement,
    lower_xtables_capture, parse_xtables_restore,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use xtables::{
    NativeXtablesAndroidRuntime, NativeXtablesAndroidRuntimeConfig,
    NativeXtablesAndroidRuntimeError, NativeXtablesCaptureAdmission,
    NativeXtablesCaptureAdmissionError, NativeXtablesCaptureConvergenceError,
    NativeXtablesCaptureConverger, NativeXtablesCaptureTarget, NativeXtablesRoutingPlanError,
    plan_native_xtables_local_output_routing,
};

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
pub use xtables::{
    NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestAuthority,
    NativeLinuxCompositionTestConfig, NativeLinuxCompositionTestError,
    NativeLinuxCompositionTestRuntime,
};

#[doc(hidden)]
pub mod internal {
    pub use crate::android_identity_properties::{
        ANDROID_IDENTITY_PROPERTY_NAMES, AndroidIdentityPropertyError,
        MAX_ANDROID_IDENTITY_PROPERTY_BYTES, validate_android_identity_properties,
        validate_android_verified_boot_properties,
    };
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub use crate::engine_credential_probe::{
        EngineCredentialProbeCapabilities, EngineCredentialProbeCommand,
        EngineCredentialProbeConfig, EngineCredentialProbePrivilege, EngineCredentialProbeReport,
        validate_engine_process_credentials,
    };
    pub use crate::sing_box::{
        PinnedSingBoxLaunch, ProcessDiagnostics, SingBoxChild, SingBoxChildIdentity,
        SingBoxExecutablePrivilegeAttribute, SingBoxProcessAdapter, SingBoxProcessError,
        SingBoxVersionReport, TerminationOutcome, ValidationReport,
    };
}

pub trait KernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemKernelReleaseSource;

impl KernelReleaseSource for SystemKernelReleaseSource {
    fn kernel_release(&self) -> Result<String, PlatformError> {
        system_kernel_release()
    }
}

#[derive(Debug)]
pub enum PlatformError {
    UnsupportedPlatform(&'static str),
    SystemCall {
        operation: &'static str,
        source: std::io::Error,
    },
    InvalidKernelReleaseEncoding,
    InvalidSocketPath(String),
    PacketTooLarge {
        actual: usize,
        limit: usize,
    },
    PeerClosed,
    PeerUidMismatch {
        expected_uid: Uid,
        pid: u32,
        uid: Uid,
        gid: u32,
    },
    ShortWrite {
        expected: usize,
        actual: usize,
    },
}

impl fmt::Display for PlatformError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(platform) => {
                write!(formatter, "unsupported host platform '{platform}'")
            }
            Self::SystemCall { operation, source } => {
                write!(formatter, "{operation} failed: {source}")
            }
            Self::InvalidKernelReleaseEncoding => {
                formatter.write_str("kernel release is not valid UTF-8")
            }
            Self::InvalidSocketPath(message) => {
                write!(formatter, "invalid Unix socket path: {message}")
            }
            Self::PacketTooLarge { actual, limit } => {
                write!(formatter, "packet of {actual} bytes exceeds {limit} bytes")
            }
            Self::PeerClosed => formatter.write_str("control peer closed the connection"),
            Self::PeerUidMismatch {
                expected_uid,
                pid,
                uid,
                gid,
            } => {
                write!(
                    formatter,
                    "control peer UID mismatch: expected uid={expected_uid}, pid={pid}, uid={uid}, gid={gid}"
                )
            }
            Self::ShortWrite { expected, actual } => {
                write!(
                    formatter,
                    "short packet write: expected {expected} bytes, wrote {actual}"
                )
            }
        }
    }
}

impl Error for PlatformError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SystemCall { source, .. } => Some(source),
            Self::UnsupportedPlatform(_)
            | Self::InvalidKernelReleaseEncoding
            | Self::InvalidSocketPath(_)
            | Self::PacketTooLarge { .. }
            | Self::PeerClosed
            | Self::PeerUidMismatch { .. }
            | Self::ShortWrite { .. } => None,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn system_kernel_release() -> Result<String, PlatformError> {
    use std::ffi::CStr;
    use std::mem::MaybeUninit;

    let mut name = MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: `name` points to writable storage for one `utsname`. A successful
    // `uname` call initializes the full structure before `assume_init`.
    if unsafe { libc::uname(name.as_mut_ptr()) } != 0 {
        return Err(PlatformError::SystemCall {
            operation: "uname",
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: the successful `uname` call above initialized `name`.
    let name = unsafe { name.assume_init() };
    // SAFETY: POSIX specifies `release` as a NUL-terminated character array
    // within the initialized `utsname` value.
    let release = unsafe { CStr::from_ptr(name.release.as_ptr()) };
    release
        .to_str()
        .map(str::to_owned)
        .map_err(|_| PlatformError::InvalidKernelReleaseEncoding)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn system_kernel_release() -> Result<String, PlatformError> {
    Err(PlatformError::UnsupportedPlatform(std::env::consts::OS))
}
