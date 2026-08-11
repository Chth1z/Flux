use std::env;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::unix::fs::MetadataExt;

use flux_core::{
    AdministrativeState, CapabilityProfileSource, ConfigError, ConfigurationChangeClient,
    ConfigurationChangeReport, ControlClient, ControlError, ControlObservation,
    ControlObservationIngress, ControlSnapshot, ControlSnapshotSource, FluxConfig, OperationReport,
    Reason, RuntimeControl, RuntimeDispatcher, RuntimeIntent,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use flux_core::{CapabilityProfile, FwmarkCandidate};
use flux_platform::{
    CapabilityProfilePaths, DaemonReactor, FileObservationBatch, FileObservationPaths,
    NativeCaptureTargetIdentity, NativeXtablesAndroidRuntime, NativeXtablesAndroidRuntimeConfig,
    NativeXtablesCaptureConverger, NativeXtablesCaptureTarget, NetworkInventoryRefreshHandle,
    ShutdownSignal, collect_network_inventory_once,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use flux_platform::{
    NativeLinuxCompositionTestAdmission, NativeLinuxCompositionTestAuthority,
    NativeLinuxCompositionTestConfig, XtablesLocalOutputRoutingSpec,
};

use crate::generation_engine_config::AddressReconciler;
use crate::inspection::ProcessInspectionSource;
use crate::native_admission::{
    AdmittedNativeRuntime, ConfiguredNativeAdmission, NativeAdmissionCandidate,
    NativeAdmissionRejection, NativeAdmissionState,
};
use crate::native_canary_facility::{
    NativeCanaryRuntimeAuthorities, create_native_boot_canary_facility,
    recover_native_boot_canary_facility,
};
use crate::native_generation_source::{
    AssembledNativeGenerationSource, NativeGenerationPlanningSource, NativeGenerationSourcePaths,
    NativeGenerationTargetAdmission, PlatformNativeGenerationTargetAdmission,
    SystemAndroidGenerationPlanningSource,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use crate::native_generation_source::{
    LinuxNativeCompositionPlanningSource, PlatformNativeLinuxCompositionTestAdmission,
};
#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
use crate::native_runtime_writer::compose_linux_native_composition_test_runtime;
use crate::native_runtime_writer::compose_native_runtime;
use crate::offline_cleanup::{
    DaemonLease, DaemonLeaseError, NativeOfflineRecovery, OfflineRecovery,
};
use crate::runtime_layout::RuntimeLayout;
use crate::runtime_logging::{self, LogSeverity, daemon_log};
use crate::subscription::{
    SubscriptionRefreshClient, SubscriptionRefreshRuntime, SubscriptionRuntimePaths,
};
use crate::{
    AdministrativeIntentStore, CapturePathDecision, ControlConnectionHandler, ControlSocketError,
    IntentStoreError, RuntimeSnapshotSource,
};

const DEFAULT_ROOT: &str = "/data/adb/flux";
const DEFAULT_DISABLE_PATH: &str = "/data/adb/modules/flux/disable";
const DEFAULT_BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";
const DEFAULT_SELINUX_ENFORCE_PATH: &str = "/sys/fs/selinux/enforce";
const MIN_ENGINE_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(50);
const MAX_ENGINE_MAINTENANCE_INTERVAL: Duration = Duration::from_millis(250);
const NATIVE_XTABLES_TOOL_ROOT: &str = "/system/bin";
const NATIVE_XTABLES_WAIT_SECONDS: u16 = 2;
const NATIVE_XTABLES_PROCESS_TIMEOUT: Duration = Duration::from_secs(5);
const NATIVE_BOOT_INVENTORY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonOptions {
    pub runtime_root: PathBuf,
    pub socket_path: PathBuf,
    pub daemon_lease_path: PathBuf,
    pub config_path: PathBuf,
    pub subscription_store_path: PathBuf,
    pub intent_path: PathBuf,
    pub boot_id_path: PathBuf,
    pub selinux_enforce_path: PathBuf,
    pub disable_path: PathBuf,
}

impl DaemonOptions {
    pub fn from_environment() -> Result<Self, DaemonError> {
        let root = env::var_os("FLUX_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_ROOT));
        let socket_path = env::var_os("FLUXD_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("run/fluxd.sock"));
        let daemon_lease_path = env::var_os("FLUXD_LEASE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("run/fluxd.lease"));
        let config_path = env::var_os("FLUXD_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("conf/flux.toml"));
        let intent_path = env::var_os("FLUXD_INTENT_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join("state/administrative-intent.json"));
        let boot_id_path = env::var_os("FLUX_BOOT_ID_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BOOT_ID_PATH));
        let selinux_enforce_path = env::var_os("FLUX_SELINUX_ENFORCE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SELINUX_ENFORCE_PATH));
        let disable_path = env::var_os("FLUX_DISABLE_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DISABLE_PATH));

        Ok(Self {
            runtime_root: root.clone(),
            socket_path,
            daemon_lease_path,
            config_path,
            subscription_store_path: root.join("state/subscription"),
            intent_path,
            boot_id_path,
            selinux_enforce_path,
            disable_path,
        })
    }

    #[must_use]
    pub fn capability_profile_paths(&self) -> CapabilityProfilePaths {
        CapabilityProfilePaths::new(&self.boot_id_path, &self.selinux_enforce_path)
    }

    pub(crate) fn native_xtables_runtime_config(
        &self,
        layout: &RuntimeLayout,
    ) -> NativeXtablesAndroidRuntimeConfig {
        NativeXtablesAndroidRuntimeConfig::new(
            NATIVE_XTABLES_TOOL_ROOT,
            layout.run_path(),
            true,
            NATIVE_XTABLES_WAIT_SECONDS,
            NATIVE_XTABLES_PROCESS_TIMEOUT,
        )
    }
}

pub fn run_daemon<S>(profile_source: &S, options: DaemonOptions) -> Result<(), DaemonError>
where
    S: CapabilityProfileSource,
{
    run_daemon_with_platform(
        profile_source,
        options,
        AndroidNativeDaemonPlatform,
        NativeEngineExecution::Production,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeEngineExecution {
    Production,
    #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
    LinuxCompositionFixture,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) fn run_linux_native_composition_test_daemon<S>(
    profile_source: &S,
    options: DaemonOptions,
    platform: LinuxNativeCompositionDaemonPlatform,
) -> Result<(), DaemonError>
where
    S: CapabilityProfileSource,
{
    run_daemon_with_platform(
        profile_source,
        options,
        platform,
        NativeEngineExecution::LinuxCompositionFixture,
    )
}

fn run_daemon_with_platform<S, P>(
    profile_source: &S,
    options: DaemonOptions,
    mut platform: P,
    engine_execution: NativeEngineExecution,
) -> Result<(), DaemonError>
where
    S: CapabilityProfileSource,
    P: NativeDaemonPlatform,
{
    let runtime_layout =
        RuntimeLayout::bootstrap(&options.runtime_root).map_err(DaemonError::RuntimeLayout)?;
    validate_runtime_layout_paths(&runtime_layout, &options)?;
    let _daemon_lease =
        DaemonLease::acquire(&options.daemon_lease_path).map_err(DaemonError::Lease)?;
    let _runtime_logs =
        runtime_logging::install(&runtime_layout).map_err(DaemonError::RuntimeLog)?;
    daemon_log(
        LogSeverity::Info,
        "daemon",
        format_args!(
            "runtime layout admitted at {}",
            runtime_layout.root_path().display()
        ),
    );
    let result = (|| {
        // Block process-directed termination before any daemon worker can be
        // created. Every in-process thread then inherits the mask, leaving
        // signalfd as the sole shutdown consumer. Proxy Engine children
        // explicitly restore a clean mask before exec.
        let shutdown = ShutdownSignal::install()
            .map_err(|error| DaemonError::Socket(ControlSocketError::Platform(error)))?;
        let (mut reactor, _stop) = DaemonReactor::open(shutdown)
            .map_err(ControlSocketError::Reactor)
            .map_err(DaemonError::Socket)?;
        let profile = Arc::new(profile_source.collect_capability_profile());
        let pending_admission = match NativeAdmissionCandidate::evaluate(&profile) {
            Err(reason) => PendingNativeAdmission::Rejected(reason),
            Ok(candidate) => {
                let config =
                    FluxConfig::load(&options.config_path).map_err(DaemonError::FluxConfig)?;
                match candidate.configure(config) {
                    Ok(configured) => PendingNativeAdmission::Configured(Box::new(configured)),
                    Err(reason) => PendingNativeAdmission::Rejected(reason),
                }
            }
        };
        let facility_journal_path = runtime_layout.run_path().join("canary-facility.owner");
        let pending_admission = match pending_admission {
            PendingNativeAdmission::Configured(configured) => {
                recover_native_boot_canary_facility(
                    &facility_journal_path,
                    configured.boot_identity(),
                    configured.network_namespace(),
                )
                .map_err(|source| {
                    DaemonError::native("recover native boot canary facility", source)
                })?;
                PendingNativeAdmission::Configured(configured)
            }
            other => other,
        };
        let (pending_admission, boot_canary_facility) = match pending_admission {
            PendingNativeAdmission::Configured(configured)
                if configured.requires_functional_canary() =>
            {
                match configured.reviewed_canary_facility_policy() {
                    None => (
                        PendingNativeAdmission::Rejected(
                            NativeAdmissionRejection::FunctionalCanaryUnavailable,
                        ),
                        None,
                    ),
                    Some(policy) => {
                        let pre_mutation_inventory = collect_network_inventory_once(
                            NATIVE_BOOT_INVENTORY_TIMEOUT,
                        )
                        .map_err(|source| {
                            DaemonError::native("collect pre-facility network inventory", source)
                        })?;
                        let facility = create_native_boot_canary_facility(
                            policy,
                            configured.config(),
                            configured.boot_identity(),
                            configured.network_namespace(),
                            &pre_mutation_inventory,
                            &facility_journal_path,
                        )
                        .map_err(|source| {
                            DaemonError::native("create native boot canary facility", source)
                        })?;
                        (
                            PendingNativeAdmission::Configured(configured),
                            Some(facility),
                        )
                    }
                }
            }
            other => (other, None),
        };

        let network_inventory =
            if matches!(pending_admission, PendingNativeAdmission::Configured(_)) {
                reactor
                    .attach_network_inventory(|degradation| {
                        daemon_log(
                            LogSeverity::Warn,
                            "network_inventory",
                            format_args!("observation disabled: {degradation}"),
                        );
                    })
                    .map_err(ControlSocketError::Reactor)
                    .map_err(DaemonError::Socket)?
            } else {
                None
            };
        let (network_inventory, network_inventory_refresh) =
            network_inventory.map_or((None, None), |attachment| {
                let (source, refresh) = attachment.into_parts();
                (Some(source), Some(refresh))
            });
        let (native_admission, composition) = match pending_admission {
            PendingNativeAdmission::Rejected(reason) => (
                NativeAdmissionState::Rejected(reason),
                DaemonComposition::read_only(),
            ),
            PendingNativeAdmission::Configured(configured) => {
                let admitted =
                    match boot_canary_facility {
                        Some(facility) => {
                            let inventory = network_inventory.as_ref().cloned().ok_or(
                                DaemonError::Invariant(
                                    "boot canary facility omitted its final reactor inventory",
                                ),
                            )?;
                            let NativeCanaryRuntimeAuthorities {
                                facility: identity,
                                reviewed_policy,
                                reviewed_selection,
                                environment_owner,
                                writer,
                            } = facility
                                .into_runtime_authorities(inventory)
                                .map_err(|source| {
                                    DaemonError::native(
                                        "split native canary facility authority",
                                        source,
                                    )
                                })?;
                            configured
                                .admit_with_functional_canary_owner(
                                    network_inventory,
                                    Some(environment_owner),
                                )
                                .map(|mut admitted| {
                                    admitted.retained_canary_facility = Some(identity);
                                    admitted.reviewed_canary_facility_planning =
                                        Some((reviewed_policy, reviewed_selection));
                                    admitted.retained_canary_facility_authority = Some(writer);
                                    admitted
                                })
                        }
                        None => configured.admit(network_inventory),
                    };
                match admitted {
                    Ok(admitted) => {
                        let network_inventory_refresh =
                            network_inventory_refresh.ok_or(DaemonError::Invariant(
                                "admitted native runtime omitted its inventory refresh authority",
                            ))?;
                        platform.recover(&admitted, &options, &runtime_layout)?;
                        let platform = platform.compose(&admitted, &options, &runtime_layout)?;
                        (
                            NativeAdmissionState::Admitted,
                            compose_native_daemon(
                                admitted,
                                network_inventory_refresh,
                                &options,
                                &runtime_layout,
                                platform,
                                engine_execution,
                            )?,
                        )
                    }
                    Err(reason) => (
                        NativeAdmissionState::Rejected(reason),
                        DaemonComposition::read_only(),
                    ),
                }
            }
        };

        let runtime = composition.runtime.clone();
        let inspection = Arc::new(ProcessInspectionSource::new(
            &options.config_path,
            runtime_layout.runtime_log_path(),
            runtime_layout.daemon_log_path(),
            runtime_layout.run_path().join("sing-box.log"),
            runtime.clone(),
        ));
        let handler = ControlConnectionHandler::with_runtime_subscription_and_inspection(
            Arc::clone(&profile),
            native_admission,
            composition.control,
            runtime,
            composition.subscription_client,
            inspection,
        );
        let serve_connection = move |connection| {
            if let Err(error) = handler.serve(connection) {
                daemon_log(
                    LogSeverity::Warn,
                    "control",
                    format_args!("rejected control connection: {error}"),
                );
            }
        };
        reactor
            .bind_control(&options.socket_path, serve_connection)
            .map_err(ControlSocketError::Reactor)
            .map_err(DaemonError::Socket)?;
        if let Some((paths, mut controller)) = composition.file_observation {
            reactor
                .attach_file_observation(
                    &paths,
                    move |observation| controller.observe(observation),
                    |error| {
                        daemon_log(
                            LogSeverity::Warn,
                            "file_observer",
                            format_args!("observation interrupted; retrying: {error}"),
                        );
                    },
                )
                .map_err(ControlSocketError::Reactor)
                .map_err(DaemonError::Socket)?;
        }
        reactor
            .run()
            .map_err(ControlSocketError::Reactor)
            .map_err(DaemonError::Socket)
    })();
    match &result {
        Ok(()) => daemon_log(
            LogSeverity::Info,
            "daemon",
            format_args!("daemon shutdown completed"),
        ),
        Err(error) => daemon_log(
            LogSeverity::Error,
            "daemon",
            format_args!("daemon stopped with an error: {error}"),
        ),
    }
    result
}

enum PendingNativeAdmission {
    Rejected(NativeAdmissionRejection),
    Configured(Box<ConfiguredNativeAdmission>),
}

trait NativeDaemonPlatform {
    type Planning: NativeGenerationPlanningSource;
    type Admission: NativeGenerationTargetAdmission<Target = NativeXtablesCaptureTarget>;

    fn recover(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        options: &DaemonOptions,
        runtime_layout: &RuntimeLayout,
    ) -> Result<(), DaemonError>;

    fn compose(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        options: &DaemonOptions,
        runtime_layout: &RuntimeLayout,
    ) -> Result<NativeDaemonPlatformParts<Self::Planning, Self::Admission>, DaemonError>;
}

struct NativeDaemonPlatformParts<P, A> {
    planning: P,
    admission: A,
    convergence: NativeXtablesCaptureConverger,
}

impl<P, A> NativeDaemonPlatformParts<P, A> {
    const fn new(planning: P, admission: A, convergence: NativeXtablesCaptureConverger) -> Self {
        Self {
            planning,
            admission,
            convergence,
        }
    }
}

struct AndroidNativeDaemonPlatform;

struct DaemonComposition {
    control: DaemonControl,
    runtime: RuntimeSnapshotSource,
    subscription_client: Option<SubscriptionRefreshClient>,
    file_observation: Option<(FileObservationPaths, FileObservationController)>,
}

impl DaemonComposition {
    fn read_only() -> Self {
        Self {
            control: DaemonControl::ReadOnly,
            runtime: RuntimeSnapshotSource::default(),
            subscription_client: None,
            file_observation: None,
        }
    }
}

fn recover_native_startup(
    admitted: &AdmittedNativeRuntime,
    options: &DaemonOptions,
    runtime_layout: &RuntimeLayout,
) -> Result<(), DaemonError> {
    let platform_config = options.native_xtables_runtime_config(runtime_layout);
    if let Some(convergence) = NativeXtablesAndroidRuntime::compose_recovery(
        platform_config,
        admitted.boot_identity.clone(),
        admitted.network_namespace,
    )
    .map_err(|source| DaemonError::native("compose native startup recovery", source))?
    {
        NativeOfflineRecovery::new(convergence)
            .recover_stopped()
            .map_err(|source| DaemonError::native("recover native startup state", source))?;
    }
    Ok(())
}

impl NativeDaemonPlatform for AndroidNativeDaemonPlatform {
    type Planning = SystemAndroidGenerationPlanningSource;
    type Admission = PlatformNativeGenerationTargetAdmission;

    fn recover(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        options: &DaemonOptions,
        runtime_layout: &RuntimeLayout,
    ) -> Result<(), DaemonError> {
        recover_native_startup(admitted, options, runtime_layout)
    }

    fn compose(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        options: &DaemonOptions,
        runtime_layout: &RuntimeLayout,
    ) -> Result<NativeDaemonPlatformParts<Self::Planning, Self::Admission>, DaemonError> {
        let planning =
            SystemAndroidGenerationPlanningSource::for_current_daemon(runtime_layout.run_path());
        let mut planning = match admitted.reviewed_canary_facility_planning.as_ref() {
            Some((policy, selection)) => planning.with_reviewed_canary_facility(
                policy.clone(),
                *selection,
                admitted
                    .reviewed_mark_candidate
                    .ok_or(DaemonError::Invariant(
                        "reviewed canary facility omitted its exact mark candidate",
                    ))?,
            ),
            None => planning,
        };
        let initial_planning = planning
            .plan_initial(&admitted.config, &admitted.initial_inventory)
            .map_err(|source| {
                DaemonError::native("mint initial Android planning authority", source)
            })?;
        let (mark_authority, placement) =
            initial_planning
                .android_runtime_binding()
                .ok_or(DaemonError::Invariant(
                    "initial Android planning omitted the native runtime binding",
                ))?;
        if mark_authority.boot_identity() != &admitted.boot_identity
            || mark_authority.network_namespace() != admitted.network_namespace
        {
            return Err(DaemonError::Invariant(
                "native planning identity changed after startup recovery",
            ));
        }
        let platform = NativeXtablesAndroidRuntime::compose(
            options.native_xtables_runtime_config(runtime_layout),
            mark_authority,
            placement,
        )
        .map_err(|source| DaemonError::native("compose native Android runtime", source))?;
        planning
            .accept_initial(&admitted.config, initial_planning)
            .map_err(|source| {
                DaemonError::native("retain initial Android planning authority", source)
            })?;
        let (admission, convergence) = platform.into_parts();
        Ok(NativeDaemonPlatformParts::new(
            planning,
            PlatformNativeGenerationTargetAdmission::new(admission),
            convergence,
        ))
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
pub(crate) struct LinuxNativeCompositionDaemonPlatform {
    capability_profile: CapabilityProfile,
    tool_root: PathBuf,
    durable_root: PathBuf,
    routing: XtablesLocalOutputRoutingSpec,
    mark: FwmarkCandidate,
    wait_seconds: u16,
    timeout: Duration,
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl LinuxNativeCompositionDaemonPlatform {
    #[must_use]
    pub(crate) fn new(
        capability_profile: CapabilityProfile,
        tool_root: impl AsRef<Path>,
        durable_root: impl AsRef<Path>,
        routing: XtablesLocalOutputRoutingSpec,
        mark: FwmarkCandidate,
        wait_seconds: u16,
        timeout: Duration,
    ) -> Self {
        Self {
            capability_profile,
            tool_root: tool_root.as_ref().to_owned(),
            durable_root: durable_root.as_ref().to_owned(),
            routing,
            mark,
            wait_seconds,
            timeout,
        }
    }

    fn platform_parts(
        &self,
        admitted: &AdmittedNativeRuntime,
    ) -> Result<
        (
            NativeLinuxCompositionTestAdmission,
            NativeXtablesCaptureConverger,
        ),
        DaemonError,
    > {
        let authority = NativeLinuxCompositionTestAuthority::acquire()
            .map_err(|source| DaemonError::native("acquire Linux composition authority", source))?;
        if authority.boot_identity() != &admitted.boot_identity
            || authority.network_namespace() != admitted.network_namespace
        {
            return Err(DaemonError::Invariant(
                "Linux composition authority differs from admitted daemon identity",
            ));
        }
        authority
            .compose(
                NativeLinuxCompositionTestConfig::new(
                    &self.tool_root,
                    &self.durable_root,
                    self.wait_seconds,
                    self.timeout,
                ),
                self.routing,
                self.mark,
            )
            .map(|runtime| runtime.into_parts())
            .map_err(|source| DaemonError::native("compose Linux test runtime", source))
    }
}

#[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
impl NativeDaemonPlatform for LinuxNativeCompositionDaemonPlatform {
    type Planning = LinuxNativeCompositionPlanningSource;
    type Admission = PlatformNativeLinuxCompositionTestAdmission;

    fn recover(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        _options: &DaemonOptions,
        _runtime_layout: &RuntimeLayout,
    ) -> Result<(), DaemonError> {
        let (_admission, convergence) = self.platform_parts(admitted)?;
        NativeOfflineRecovery::new(convergence)
            .recover_stopped()
            .map(|_| ())
            .map_err(|source| DaemonError::native("recover Linux test startup state", source))
    }

    fn compose(
        &mut self,
        admitted: &AdmittedNativeRuntime,
        _options: &DaemonOptions,
        _runtime_layout: &RuntimeLayout,
    ) -> Result<NativeDaemonPlatformParts<Self::Planning, Self::Admission>, DaemonError> {
        let (admission, convergence) = self.platform_parts(admitted)?;
        let planning = LinuxNativeCompositionPlanningSource::new(
            self.capability_profile.clone(),
            admitted.network_namespace,
            self.routing,
            self.mark,
        );
        Ok(NativeDaemonPlatformParts::new(
            planning,
            PlatformNativeLinuxCompositionTestAdmission::new(admission),
            convergence,
        ))
    }
}

fn compose_native_daemon<P, A>(
    admitted: AdmittedNativeRuntime,
    network_inventory_refresh: NetworkInventoryRefreshHandle,
    options: &DaemonOptions,
    runtime_layout: &RuntimeLayout,
    platform: NativeDaemonPlatformParts<P, A>,
    engine_execution: NativeEngineExecution,
) -> Result<DaemonComposition, DaemonError>
where
    P: NativeGenerationPlanningSource,
    A: NativeGenerationTargetAdmission<Target = NativeXtablesCaptureTarget>,
{
    let AdmittedNativeRuntime {
        boot_identity,
        config,
        inventory,
        functional_canary,
        retained_canary_facility,
        reviewed_canary_facility_planning,
        retained_canary_facility_authority,
        ..
    } = admitted;
    let NativeDaemonPlatformParts {
        planning,
        admission,
        convergence,
    } = platform;
    let observation_paths =
        file_observation_paths(&options.config_path, &options.disable_path, &config);
    let observation_baseline = ObservedInputsFingerprint::capture(&observation_paths)
        .map_err(DaemonError::Configuration)?;
    let queue_capacity =
        usize::try_from(config.daemon().event_queue_capacity().get()).map_err(|_| {
            DaemonError::Configuration(
                "daemon.event_queue_capacity does not fit this target".to_owned(),
            )
        })?;
    let store = AdministrativeIntentStore::new(&options.intent_path, boot_identity.clone());
    let disable_present =
        inspect_disable_path(&options.disable_path).map_err(DaemonError::Configuration)?;
    let initial_intent = initial_intent(&store, disable_present)?;

    let reviewed_engine_credentials = reviewed_canary_facility_planning
        .as_ref()
        .map(|(policy, _)| policy.credentials());
    let subscription = SubscriptionRefreshRuntime::start(
        SubscriptionRuntimePaths::new(
            &options.config_path,
            &options.subscription_store_path,
            runtime_layout.run_path(),
            runtime_layout.run_path().join("subscription-check.log"),
        ),
        reviewed_engine_credentials,
    )
    .map_err(|source| DaemonError::native("start subscription runtime", source))?;
    let bootstrap_digest = subscription.bootstrap_digest;
    let subscription_client = subscription.client.clone();
    let accepted_subscription = subscription.active;
    let subscription_runtime = subscription.runtime;

    let source_paths = NativeGenerationSourcePaths::from_runtime_layout(
        &options.config_path,
        runtime_layout,
        &options.runtime_root,
        runtime_layout.run_path().join("sing-box.log"),
    );
    let source = match engine_execution {
        NativeEngineExecution::Production => {
            AssembledNativeGenerationSource::<_, _, _, NativeCaptureTargetIdentity>::new(
                source_paths,
                inventory.clone(),
                planning,
                admission,
                accepted_subscription,
            )
        }
        #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
        NativeEngineExecution::LinuxCompositionFixture => AssembledNativeGenerationSource::<
            _,
            _,
            _,
            NativeCaptureTargetIdentity,
        >::for_linux_native_composition_test(
            source_paths,
            inventory.clone(),
            planning,
            admission,
            accepted_subscription,
        ),
    };
    let source = match (retained_canary_facility, reviewed_canary_facility_planning) {
        (Some(facility), Some((policy, _))) => {
            source.with_retained_canary_facility(facility, policy.credentials())
        }
        (None, None) => source,
        _ => {
            return Err(DaemonError::Invariant(
                "native canary facility and reviewed credential authority diverged",
            ));
        }
    };
    let maintenance_interval =
        engine_maintenance_interval(config.daemon().reconcile_debounce().get());
    let address_reconciler = AddressReconciler::for_network_inventory(
        &options.config_path,
        inventory,
        network_inventory_refresh,
    );
    let dispatcher = match engine_execution {
        NativeEngineExecution::Production => compose_native_runtime(
            convergence,
            move || source,
            maintenance_interval,
            functional_canary,
            retained_canary_facility_authority,
        ),
        #[cfg(all(test, feature = "native-composition-test", target_os = "linux"))]
        NativeEngineExecution::LinuxCompositionFixture => {
            compose_linux_native_composition_test_runtime(
                convergence,
                move || source,
                maintenance_interval,
                functional_canary,
            )
        }
    }
    .map_err(|source| DaemonError::native("compose native runtime coordinator", source))?
    .with_address_reconciler(address_reconciler)
    .with_subscription_runtime(subscription_runtime);
    let runtime = dispatcher.runtime_snapshot_source();
    let dispatcher = PersistingRuntimeDispatcher { dispatcher, store };
    let control =
        RuntimeControl::start(dispatcher, queue_capacity).map_err(DaemonError::Control)?;
    let admission = control
        .submit(initial_intent)
        .and_then(flux_core::OperationHandle::wait);
    if let Err(admission_error) = admission {
        if initial_admission_can_remain_read_only(&runtime) {
            daemon_log(
                LogSeverity::Warn,
                "capture_path",
                format_args!(
                    "initial runtime remains read-only because no Capture Path qualified: {admission_error}"
                ),
            );
        } else {
            if let Some(digest) = bootstrap_digest
                && let Err(rollback_error) = subscription_client.reject_bootstrap(digest)
            {
                return Err(DaemonError::Configuration(format!(
                    "initial runtime admission failed ({admission_error}); cannot restore the unadmitted subscription snapshot ({rollback_error})"
                )));
            }
            return Err(DaemonError::Control(admission_error));
        }
    }
    if let Some(digest) = bootstrap_digest {
        subscription_client
            .accept_bootstrap(digest)
            .map_err(|error| {
                DaemonError::Configuration(format!(
                    "initial runtime was admitted but the subscription worker could not commit its startup snapshot: {error}"
                ))
            })?;
    }
    let observation_ingress = control
        .observation_ingress()
        .map_err(DaemonError::Control)?;
    let observation_controller = FileObservationController {
        desired_state_path: options.config_path.clone(),
        disable_path: options.disable_path.clone(),
        effective_disabled: disable_present,
        disable_path_invalid: false,
        initial_inputs: Some(observation_baseline),
        ingress: observation_ingress,
    };
    Ok(DaemonComposition {
        control: DaemonControl::Runtime(control),
        runtime,
        subscription_client: Some(subscription_client),
        file_observation: Some((observation_paths, observation_controller)),
    })
}

fn initial_admission_can_remain_read_only(runtime: &RuntimeSnapshotSource) -> bool {
    matches!(
        runtime.snapshot().latest_capture_path_decision,
        Some(CapturePathDecision::Rejected { .. })
    )
}

enum DaemonControl {
    Runtime(RuntimeControl),
    ReadOnly,
}

impl ControlClient for DaemonControl {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        match self {
            Self::Runtime(control) => control.submit_and_wait(intent),
            Self::ReadOnly => Err(ControlError::RuntimeStopped),
        }
    }
}

impl ControlSnapshotSource for DaemonControl {
    fn snapshot(&self) -> Arc<ControlSnapshot> {
        match self {
            Self::Runtime(control) => control.snapshot(),
            Self::ReadOnly => Arc::new(ControlSnapshot::default()),
        }
    }
}

impl ConfigurationChangeClient for DaemonControl {
    fn configuration_changed(
        &self,
        reason: Reason,
    ) -> Result<ConfigurationChangeReport, ControlError> {
        match self {
            Self::Runtime(control) => control.configuration_changed(reason),
            Self::ReadOnly => Err(ControlError::RuntimeStopped),
        }
    }
}

struct PersistingRuntimeDispatcher<D> {
    dispatcher: D,
    store: AdministrativeIntentStore,
}

impl<D> RuntimeDispatcher for PersistingRuntimeDispatcher<D>
where
    D: RuntimeDispatcher,
{
    fn execute(
        &mut self,
        intent: &RuntimeIntent,
    ) -> Result<flux_core::DispatcherCompletion, ControlError> {
        let state = match intent {
            RuntimeIntent::Running { .. } => Some(AdministrativeState::Running),
            RuntimeIntent::Stopped { .. } => Some(AdministrativeState::Stopped),
            RuntimeIntent::Reload { .. } | RuntimeIntent::ResyncAddresses { .. } => None,
        };
        if let Some(state) = state {
            self.store.persist(state).map_err(|error| {
                ControlError::persistence(
                    "write administrative intent",
                    error,
                    "repair the Flux state directory and restart fluxd",
                )
            })?;
        }
        self.dispatcher.execute(intent)
    }

    fn observation_failed(&mut self, observation: ControlObservation, error: &ControlError) {
        let fact = match observation {
            ControlObservation::ConfigurationInputsChanged => "configuration input change",
            ControlObservation::DisableStateChanged { disabled: true } => "disable activation",
            ControlObservation::DisableStateChanged { disabled: false } => "disable removal",
        };
        daemon_log(
            LogSeverity::Error,
            "observation",
            format_args!("observed {fact} could not be reconciled: {error}"),
        );
    }

    fn configuration_inputs_consumed(&mut self) {
        self.dispatcher.configuration_inputs_consumed();
    }

    fn maintenance_interval(&self) -> Option<Duration> {
        self.dispatcher.maintenance_interval()
    }

    fn maintain(&mut self) {
        self.dispatcher.maintain();
    }

    fn shutdown(&mut self) {
        self.dispatcher.shutdown();
    }
}

struct FileObservationController {
    desired_state_path: PathBuf,
    disable_path: PathBuf,
    effective_disabled: bool,
    disable_path_invalid: bool,
    initial_inputs: Option<ObservedInputsFingerprint>,
    ingress: ControlObservationIngress,
}

impl FileObservationController {
    fn observe(&mut self, observation: FileObservationBatch) -> Option<FileObservationPaths> {
        if observation.disable_state_changed() {
            let disabled = match inspect_disable_path(&self.disable_path) {
                Ok(disabled) => {
                    self.disable_path_invalid = false;
                    disabled
                }
                Err(error) => {
                    if !self.disable_path_invalid {
                        daemon_log(
                            LogSeverity::Warn,
                            "file_observer",
                            format_args!("{error}; treating the module as disabled"),
                        );
                    }
                    self.disable_path_invalid = true;
                    true
                }
            };
            if disabled != self.effective_disabled {
                if let Err(error) = self
                    .ingress
                    .submit(ControlObservation::DisableStateChanged { disabled })
                {
                    daemon_log(
                        LogSeverity::Error,
                        "file_observer",
                        format_args!("cannot enqueue observed disable state: {error}"),
                    );
                } else {
                    self.effective_disabled = disabled;
                }
            }
        }

        if !observation.configuration_inputs_changed() {
            return None;
        }
        match FluxConfig::load(&self.desired_state_path) {
            Ok(config) => {
                let paths = FileObservationPaths::new(
                    &self.desired_state_path,
                    config.engine().template(),
                    config.subscription().url_file(),
                    &self.disable_path,
                );
                let changed = self.initial_inputs.take().is_none_or(|baseline| {
                    ObservedInputsFingerprint::capture(&paths)
                        .map_or(true, |current| current != baseline)
                });
                if changed {
                    self.submit_configuration_observation();
                }
                Some(paths)
            }
            Err(error) => {
                self.initial_inputs.take();
                self.submit_configuration_observation();
                daemon_log(
                    LogSeverity::Warn,
                    "file_observer",
                    format_args!(
                        "cannot refresh observed paths from {}: {error}",
                        self.desired_state_path.display()
                    ),
                );
                None
            }
        }
    }

    fn submit_configuration_observation(&self) {
        if let Err(error) = self
            .ingress
            .submit(ControlObservation::ConfigurationInputsChanged)
        {
            daemon_log(
                LogSeverity::Error,
                "file_observer",
                format_args!("cannot enqueue observed configuration change: {error}"),
            );
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedInputsFingerprint {
    desired_state: ObservedFileStamp,
    engine_template: ObservedFileStamp,
    subscription_url: ObservedFileStamp,
}

impl ObservedInputsFingerprint {
    fn capture(paths: &FileObservationPaths) -> Result<Self, String> {
        Ok(Self {
            desired_state: ObservedFileStamp::capture(paths.desired_state())?,
            engine_template: ObservedFileStamp::capture(paths.engine_template())?,
            subscription_url: ObservedFileStamp::capture(paths.subscription_url())?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ObservedFileStamp {
    Missing,
    Present(ObservedFileMetadata),
}

impl ObservedFileStamp {
    fn capture(path: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Self::Present(ObservedFileMetadata::from_metadata(
                &metadata,
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::Missing),
            Err(error) => Err(format!(
                "cannot fingerprint observed input {}: {error}",
                path.display()
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedFileMetadata {
    kind: ObservedFileKind,
    length: u64,
    modified: Option<SystemTime>,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    device: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    inode: u64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    changed_seconds: i64,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    changed_nanoseconds: i64,
}

impl ObservedFileMetadata {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        let file_type = metadata.file_type();
        Self {
            kind: if file_type.is_file() {
                ObservedFileKind::Regular
            } else if file_type.is_dir() {
                ObservedFileKind::Directory
            } else if file_type.is_symlink() {
                ObservedFileKind::SymbolicLink
            } else {
                ObservedFileKind::Other
            },
            length: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            device: metadata.dev(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            inode: metadata.ino(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            changed_seconds: metadata.ctime(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedFileKind {
    Regular,
    Directory,
    SymbolicLink,
    Other,
}

fn file_observation_paths(
    desired_state_path: &Path,
    disable_path: &Path,
    config: &FluxConfig,
) -> FileObservationPaths {
    FileObservationPaths::new(
        desired_state_path,
        config.engine().template(),
        config.subscription().url_file(),
        disable_path,
    )
}

fn inspect_disable_path(disable_path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(disable_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "disable path {} must not be a symbolic link",
            disable_path.display()
        )),
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(format!(
            "disable path {} exists but is not a file",
            disable_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "cannot inspect disable path {}: {error}",
            disable_path.display()
        )),
    }
}

fn initial_intent(
    store: &AdministrativeIntentStore,
    disable_present: bool,
) -> Result<RuntimeIntent, DaemonError> {
    if disable_present {
        return Ok(RuntimeIntent::Stopped {
            reason: Reason::DisableCreated,
        });
    }
    match store.load().map_err(DaemonError::Intent)? {
        AdministrativeState::Running => Ok(RuntimeIntent::Running {
            reason: Reason::DaemonRecovery,
        }),
        AdministrativeState::Stopped => Ok(RuntimeIntent::Stopped {
            reason: Reason::DaemonRecovery,
        }),
        AdministrativeState::Unknown => Ok(RuntimeIntent::Running {
            reason: Reason::Boot,
        }),
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Configuration(String),
    FluxConfig(ConfigError),
    RuntimeLayout(crate::RuntimeLayoutError),
    RuntimeLog(crate::RuntimeLogError),
    Invariant(&'static str),
    Intent(IntentStoreError),
    Lease(DaemonLeaseError),
    NativeStartup {
        operation: &'static str,
        source: Box<dyn Error + Send + Sync>,
    },
    Control(ControlError),
    Socket(ControlSocketError),
}

impl DaemonError {
    fn native(operation: &'static str, source: impl Error + Send + Sync + 'static) -> Self {
        Self::NativeStartup {
            operation,
            source: Box::new(source),
        }
    }
}

impl fmt::Display for DaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "daemon configuration: {message}"),
            Self::FluxConfig(error) => write!(formatter, "daemon configuration: {error}"),
            Self::RuntimeLayout(error) => write!(formatter, "runtime layout: {error}"),
            Self::RuntimeLog(error) => write!(formatter, "runtime logging: {error}"),
            Self::Invariant(message) => write!(formatter, "daemon invariant: {message}"),
            Self::Intent(error) => write!(formatter, "administrative intent: {error}"),
            Self::Lease(error) => write!(formatter, "daemon exclusion: {error}"),
            Self::NativeStartup { operation, source } => {
                write!(formatter, "native startup cannot {operation}: {source}")
            }
            Self::Control(error) => write!(formatter, "runtime control: {error}"),
            Self::Socket(error) => error.fmt(formatter),
        }
    }
}

impl Error for DaemonError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FluxConfig(error) => Some(error),
            Self::RuntimeLayout(error) => Some(error),
            Self::RuntimeLog(error) => Some(error),
            Self::Control(error) => Some(error),
            Self::Intent(error) => Some(error),
            Self::Lease(error) => Some(error),
            Self::NativeStartup { source, .. } => Some(source.as_ref()),
            Self::Socket(error) => Some(error),
            Self::Configuration(_) | Self::Invariant(_) => None,
        }
    }
}

fn validate_runtime_layout_paths(
    layout: &RuntimeLayout,
    options: &DaemonOptions,
) -> Result<(), DaemonError> {
    for (label, path) in [
        ("control socket", options.socket_path.as_path()),
        ("daemon lease", options.daemon_lease_path.as_path()),
    ] {
        layout
            .require_run_child(label, path)
            .map_err(DaemonError::RuntimeLayout)?;
    }
    for (label, path) in [
        (
            "subscription store",
            options.subscription_store_path.as_path(),
        ),
        ("administrative intent", options.intent_path.as_path()),
    ] {
        layout
            .require_state_child(label, path)
            .map_err(DaemonError::RuntimeLayout)?;
    }
    Ok(())
}

fn engine_maintenance_interval(configured: Duration) -> Duration {
    configured.clamp(
        MIN_ENGINE_MAINTENANCE_INTERVAL,
        MAX_ENGINE_MAINTENANCE_INTERVAL,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeSnapshot;
    use crate::generation_engine_config::{
        test_unqualified_capture_path_decision, test_xtables_capture_path_decision,
    };

    #[test]
    fn engine_maintenance_interval_is_bounded_independently_of_config_debounce() {
        assert_eq!(
            engine_maintenance_interval(Duration::from_millis(1)),
            MIN_ENGINE_MAINTENANCE_INTERVAL
        );
        assert_eq!(
            engine_maintenance_interval(Duration::from_secs(u64::from(u32::MAX))),
            MAX_ENGINE_MAINTENANCE_INTERVAL
        );
    }

    #[test]
    fn only_a_typed_no_safe_capture_path_decision_allows_read_only_startup() {
        let runtime = RuntimeSnapshotSource::default();
        runtime.publish(RuntimeSnapshot {
            latest_capture_path_decision: Some(test_unqualified_capture_path_decision()),
            ..RuntimeSnapshot::unknown()
        });
        assert!(initial_admission_can_remain_read_only(&runtime));

        runtime.publish(RuntimeSnapshot {
            latest_capture_path_decision: Some(test_xtables_capture_path_decision()),
            ..RuntimeSnapshot::unknown()
        });
        assert!(!initial_admission_can_remain_read_only(&runtime));

        runtime.publish(RuntimeSnapshot::unknown());
        assert!(!initial_admission_can_remain_read_only(&runtime));
    }
}
