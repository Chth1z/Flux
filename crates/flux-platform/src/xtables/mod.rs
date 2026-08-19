mod lowering;
#[allow(dead_code)]
mod native;
mod native_capture;
#[allow(dead_code)]
mod owner;
#[cfg(any(target_os = "linux", target_os = "android"))]
#[allow(dead_code)]
mod owner_durable;
mod restore;
#[allow(dead_code)]
mod save;

#[cfg(test)]
pub(crate) use save::XtablesExpectedStatePhase;
pub(crate) use save::{
    XtablesExpectedState, XtablesRetainedMatcher, is_flux_owned_chain, project_xtables_save,
};

pub(crate) use native::collect_android_xtables_save_snapshots;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use owner::{
    NativeXtablesTargetArchiveObservation, observe_native_xtables_target_archive,
    observe_native_xtables_target_archive_for_active_owner,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use owner_durable::{
    NATIVE_XTABLES_JOURNAL_SCHEMA_VERSION, NativeXtablesDurableReadOnlyObservation,
    NativeXtablesDurableRootIdentity, NativeXtablesDurableStore, NativeXtablesJournalObservation,
    NativeXtablesJournalPhase, NativeXtablesLeaseScope,
};

pub use lowering::{
    MAX_XTABLES_CAPTURE_COMMANDS_PER_ARTIFACT, XTABLES_CAPTURE_DIGEST_BYTES,
    XTABLES_CAPTURE_LOWERING_SCHEMA_VERSION, XtablesCaptureArtifactPair,
    XtablesCaptureArtifactPairDigest, XtablesCaptureArtifactSet, XtablesCaptureArtifactSetDigest,
    XtablesCaptureEntryPoint, XtablesCaptureEntryPointRole, XtablesCaptureEntrySelector,
    XtablesCaptureExtension, XtablesCaptureExtensions, XtablesCaptureHook,
    XtablesCaptureLoweringBudget, XtablesCaptureLoweringDigest, XtablesCaptureLoweringError,
    XtablesCaptureLoweringRequest, XtablesCaptureNamespace, XtablesCapturePredicateKind,
    XtablesCaptureResourceUsage, XtablesCaptureTransactionOrder, XtablesCaptureTransactionStep,
    XtablesInterfaceRenderErrorKind, XtablesLocalOutputRoutingRequirement,
    XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingSpecError,
    XtablesLocalOutputRoutingTarget, XtablesLocalOutputRoutingTargetError,
    XtablesLocalOutputTransactionRequirements, XtablesLoopEscapeRequirement, XtablesTproxyTarget,
    XtablesTransparentListenerRequirement, lower_xtables_capture,
};

#[cfg(test)]
pub(crate) use native_capture::NativeCaptureRetainedOwner;
pub use native_capture::{
    NativeCaptureCanaryAttempt, NativeCaptureCanaryCounterRetirement,
    NativeCaptureCanaryCounterSnapshot, NativeCaptureCanaryRouteObservation,
    NativeCaptureCanaryRouteOutcome, NativeCaptureCanaryRouteQuery,
    NativeCaptureCanaryRouteRejection, NativeCaptureCanarySelector, NativeCaptureConvergedState,
    NativeCaptureConvergence, NativeCaptureConvergenceReport, NativeCaptureDesired,
    NativeCaptureOwnershipObservation, NativeCaptureTargetIdentity,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use owner::{
    NativeXtablesAndroidRuntime, NativeXtablesAndroidRuntimeConfig,
    NativeXtablesAndroidRuntimeError, NativeXtablesCaptureAdmission,
    NativeXtablesCaptureAdmissionError, NativeXtablesCaptureConvergenceError,
    NativeXtablesCaptureConverger, NativeXtablesCaptureTarget, NativeXtablesRoutingPlanError,
    plan_native_xtables_local_output_routing,
};

#[cfg(all(feature = "native-composition-test", target_os = "linux"))]
pub use owner::{
    NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestAuthority,
    NativeLinuxCompositionTestConfig, NativeLinuxCompositionTestError,
    NativeLinuxCompositionTestRuntime,
};

pub use restore::{
    MAX_XTABLES_RESTORE_BYTES, MAX_XTABLES_RESTORE_CHAIN_BYTES, MAX_XTABLES_RESTORE_COMMANDS,
    MAX_XTABLES_RESTORE_LINE_BYTES, MAX_XTABLES_RESTORE_LINES, MAX_XTABLES_RESTORE_TOKEN_BYTES,
    MAX_XTABLES_RESTORE_TOKENS_PER_COMMAND, MAX_XTABLES_RESTORE_TRANSACTIONS,
    XTABLES_RESTORE_DIGEST_BYTES, XTABLES_RESTORE_SCHEMA_VERSION, XtablesChainDeclaration,
    XtablesRestoreAction, XtablesRestoreArtifact, XtablesRestoreCommand, XtablesRestoreCommandKind,
    XtablesRestoreContext, XtablesRestoreDigest, XtablesRestoreEntry, XtablesRestoreFamily,
    XtablesRestoreLimit, XtablesRestoreParseError, XtablesRestoreParseErrorKind,
    XtablesRestoreResourceUsage, XtablesRestoreTable, XtablesRestoreToken,
    XtablesRestoreTransaction, parse_xtables_restore,
};
