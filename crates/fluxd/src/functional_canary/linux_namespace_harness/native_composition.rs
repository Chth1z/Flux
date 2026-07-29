use std::env;
use std::fs;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, TcpListener};
use std::num::NonZeroU32;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use flux_core::{
    AddressResyncDisposition, AdministrativeState, CapabilityProfile, ControlClient,
    DispatcherCompletion, FluxConfig, FwmarkCandidate, GenerationId, InterfaceAddressFlags,
    InterfaceAddressRecord, InterfaceIndex, NetworkInventory, NetworkInventoryTracker,
    NetworkNamespaceIdentity, Reason, RouteProtocol, RouteTableId, RulePriority, RuleProtocol,
    RuntimeDispatcher, RuntimeIntent,
};
use flux_platform::{
    NativeCaptureTargetIdentity, NativeLinuxCompositionTestAdmission,
    NativeLinuxCompositionTestAuthority, NativeLinuxCompositionTestConfig,
    NativeXtablesCaptureConverger, XtablesLocalOutputRoutingSpec, XtablesLocalOutputRoutingTarget,
};
use flux_testkit::{CapabilityProfileFixture, StaticCapabilityProfileSource};

use super::{checked_command, network_namespace_identity, random_nonce, user_namespace_identity};
use crate::daemon::{
    DaemonOptions, LinuxNativeCompositionDaemonPlatform, run_linux_native_composition_test_daemon,
};
use crate::generation_engine_config::{
    AddressReconciler, ReplayNetworkInventorySource, TproxyEngineConfigRequest,
    compile_tproxy_engine_config,
};
use crate::native_generation_source::{
    AssembledNativeGenerationSource, CompleteNativeInventorySource,
    LinuxNativeCompositionPlanningSource, NativeGenerationSourcePaths,
    PlatformNativeLinuxCompositionTestAdmission,
};
use crate::native_runtime_writer::{NativeCoordinatorWriter, compose_native_runtime};
use crate::offline_cleanup::{NativeOfflineRecovery, OfflineRecovery};
use crate::runtime_coordinator::{RuntimeCoordinator, RuntimeFunctionalCanary};
use crate::subscription::{
    SubscriptionRefreshDecision, SubscriptionRefreshDisposition, ValidatedSubscriptionEngineConfig,
};
use crate::{
    EngineSupervisor, NativeAdmissionState, RuntimeCaptureState, RuntimeEngineState, RuntimePhase,
    SocketControlClient,
};

const TEST_NAME: &str = "functional_canary::linux_namespace_harness::privileged_native_composition_exercises_lifecycle_recovery_and_exact_cleanup";
const REQUIRED_ENV: &str = "FLUX_NATIVE_COMPOSITION_REQUIRED";
const MODE_ENV: &str = "FLUX_NATIVE_COMPOSITION_HARNESS_MODE";
const ROOT_ENV: &str = "FLUX_NATIVE_COMPOSITION_ROOT";
const TOKEN_ENV: &str = "FLUX_NATIVE_COMPOSITION_REENTRY_TOKEN";
const OUTER_NETNS_ENV: &str = "FLUX_NATIVE_COMPOSITION_OUTER_NETNS";
const OUTER_USERNS_ENV: &str = "FLUX_NATIVE_COMPOSITION_OUTER_USERNS";
const ENGINE_BIN_ENV: &str = "FLUX_NATIVE_COMPOSITION_ENGINE_BIN";
const EXEC_AUDIT_ENV: &str = "FLUX_NATIVE_COMPOSITION_EXEC_AUDIT";
const ENGINE_PID_LOG_ENV: &str = "FLUX_NATIVE_COMPOSITION_ENGINE_PID_LOG";
const FAIL_CHECK_ENV: &str = "FLUX_NATIVE_COMPOSITION_FAIL_CHECK";
const MODE_ISOLATED: &str = "isolated";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const MAINTENANCE_INTERVAL: Duration = Duration::from_millis(20);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(8);
const XTABLES_TOOL_NAMES: [&str; 6] = [
    "iptables",
    "iptables-restore",
    "iptables-save",
    "ip6tables",
    "ip6tables-restore",
    "ip6tables-save",
];
const ROUTING_TABLE: u32 = 20_253;
const ROUTING_PRIORITY: u32 = 30_999;
const MARK_MASK: u32 = 0x00ff_0000;
const PROXY_MARK: u32 = 0x0080_0000;
const BYPASS_MARK: u32 = 0x0040_0000;
const PACKAGED_DESIRED_STATE: &str = include_str!("../../../../../conf/flux.toml");
const PACKAGED_ENGINE_TEMPLATE: &[u8] = include_bytes!("../../../../../conf/template.json");

type TestSource = AssembledNativeGenerationSource<
    ReplayInventory,
    LinuxNativeCompositionPlanningSource,
    PlatformNativeLinuxCompositionTestAdmission,
    NativeCaptureTargetIdentity,
>;
type TestWriter = NativeCoordinatorWriter<NativeXtablesCaptureConverger, TestSource>;
type TestCoordinator = RuntimeCoordinator<TestWriter, EngineSupervisor>;

pub(super) fn run() {
    let result = match env::var(MODE_ENV).as_deref() {
        Err(env::VarError::NotPresent) => run_outer(),
        Ok(MODE_ISOLATED) => run_isolated(),
        Ok(other) => Err(format!("unsupported {MODE_ENV} value {other:?}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{MODE_ENV} must contain valid UTF-8")),
    };
    if let Err(error) = result {
        panic!("privileged native composition checkpoint failed: {error}");
    }
}

fn run_outer() -> Result<(), String> {
    let required = required_mode()?;
    for (program, arguments) in [
        ("unshare", &["--version"][..]),
        ("ip", &["-Version"][..]),
        ("iptables-save", &["--version"][..]),
        ("ip6tables-save", &["--version"][..]),
    ] {
        let mut command = Command::new(program);
        command.args(arguments);
        if let Err(reason) = checked_command(command, COMMAND_TIMEOUT) {
            return skip_or_fail(
                required,
                format!("required helper `{program}` is unavailable: {reason}"),
            );
        }
    }

    let mut probe = Command::new("unshare");
    probe.args([
        "--user",
        "--map-root-user",
        "--mount",
        "--net",
        "--",
        "true",
    ]);
    if let Err(reason) = checked_command(probe, COMMAND_TIMEOUT) {
        return skip_or_fail(
            required,
            format!("isolated user/mount/network namespaces are unavailable: {reason}"),
        );
    }

    let engine = match fixture_engine_binary() {
        Ok(engine) => engine,
        Err(reason) => return skip_or_fail(required, reason),
    };
    let directory = tempfile::Builder::new()
        .prefix("flux-native-composition-")
        .tempdir()
        .map_err(|error| format!("create native composition root: {error}"))?;
    let root = directory.path().to_owned();
    if let Err(reason) = stage_xtables_tools(&root.join("tools")) {
        return skip_or_fail(required, reason);
    }
    let audit = root.join("exec.audit");
    let pid_log = root.join("engine.pids");
    let fail_check = root.join("fail-check.once");
    fs::write(&audit, b"").map_err(|error| format!("create {}: {error}", audit.display()))?;
    fs::write(&pid_log, b"").map_err(|error| format!("create {}: {error}", pid_log.display()))?;

    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let mut command = Command::new("unshare");
    command
        .args(["--user", "--map-root-user", "--mount", "--net", "--"])
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_ISOLATED)
        .env(ROOT_ENV, &root)
        .env(TOKEN_ENV, random_nonce()?)
        .env(OUTER_NETNS_ENV, network_namespace_identity()?)
        .env(OUTER_USERNS_ENV, user_namespace_identity()?)
        .env(ENGINE_BIN_ENV, engine)
        .env(EXEC_AUDIT_ENV, &audit)
        .env(ENGINE_PID_LOG_ENV, &pid_log)
        .env(FAIL_CHECK_ENV, &fail_check);
    // SAFETY: the callback invokes only signal-set syscalls after fork and before exec. The
    // isolated libtest process and every daemon/controller worker inherit the blocked mask, so
    // signalfd is the sole SIGINT/SIGTERM consumer during the daemon lifecycle checkpoint.
    unsafe {
        command.pre_exec(block_shutdown_signals_before_exec);
    }
    checked_command(command, PROCESS_TIMEOUT).map(|_| ())
}

fn run_isolated() -> Result<(), String> {
    verify_reentry()?;
    let root = required_absolute_path(ROOT_ENV)?;
    let execution =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute_isolated(&root)))
            .unwrap_or_else(|payload| {
                Err(format!(
                    "native composition execution panicked: {}",
                    panic_message(payload)
                ))
            });
    if execution.is_err() {
        emergency_cleanup();
    }
    execution
}

fn execute_isolated(root: &Path) -> Result<(), String> {
    let mut loopback = Command::new("ip");
    loopback.args(["link", "set", "dev", "lo", "up"]);
    checked_command(loopback, COMMAND_TIMEOUT)?;

    let fixture = Fixture::new(root)?;
    assert_clean_state()?;

    let mut first = fixture.compose_runtime()?;
    execute(
        &mut first.coordinator,
        RuntimeIntent::Running {
            reason: Reason::Boot,
        },
        "start initial native Generation",
    )?;
    assert_running(&first.coordinator, generation(1))?;
    assert_active_kernel_state()?;

    execute(
        &mut first.coordinator,
        RuntimeIntent::Reload {
            reason: Reason::UserControl,
        },
        "reload native successor",
    )?;
    assert_running(&first.coordinator, generation(2))?;
    assert_active_kernel_state()?;

    let subscription = fixture.subscription_candidate([0x5a; 32], 7)?;
    let recovered_subscription = subscription.clone();
    let decision = first
        .coordinator
        .inject_subscription_refresh_for_native_composition_test(subscription, false);
    let report = match decision.recv_timeout(COMMAND_TIMEOUT) {
        Ok(SubscriptionRefreshDecision::Accept(report)) => report,
        Ok(SubscriptionRefreshDecision::Reject(error)) => {
            return Err(format!(
                "subscription-driven native successor was rejected: {error}"
            ));
        }
        Err(error) => {
            return Err(format!(
                "subscription-driven native successor did not settle: {error}"
            ));
        }
    };
    if report.disposition() != SubscriptionRefreshDisposition::Updated
        || report.generation() != Some(generation(3))
        || report.node_count() != Some(7)
        || report.cleanup_pending()
    {
        return Err(format!(
            "subscription-driven native successor returned an unexpected report: {report:?}"
        ));
    }
    fixture.accept_subscription(recovered_subscription);
    assert_running(&first.coordinator, generation(3))?;
    assert_active_kernel_state()?;

    fixture
        .inventory
        .publish(Some(Arc::clone(&fixture.changed_inventory)));
    first
        .address_inventory
        .publish(Some(Arc::clone(&fixture.changed_inventory)));
    let completion = execute(
        &mut first.coordinator,
        RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        },
        "converge address-driven native successor",
    )?;
    if completion
        != DispatcherCompletion::AddressResync(AddressResyncDisposition::SuccessorConverged)
    {
        return Err(format!(
            "address resync did not report synchronous successor convergence: {completion:?}"
        ));
    }
    assert_running(&first.coordinator, generation(4))?;
    assert_active_kernel_state()?;

    let exited_pid = latest_engine_pid(&fixture.pid_log)?;
    kill_engine(exited_pid)?;
    wait_for_engine_recovery(&mut first.coordinator, &fixture.pid_log, exited_pid)?;
    assert_running(&first.coordinator, generation(4))?;
    assert_active_kernel_state()?;

    fs::write(&fixture.fail_check, b"fail next check\n")
        .map_err(|error| format!("arm {}: {error}", fixture.fail_check.display()))?;
    if first
        .coordinator
        .execute(&RuntimeIntent::Reload {
            reason: Reason::UserControl,
        })
        .is_ok()
    {
        return Err("one-shot candidate validation failure unexpectedly succeeded".to_owned());
    }
    if fixture.fail_check.exists() {
        return Err("engine fixture did not consume the candidate failure marker".to_owned());
    }
    let failed = first.coordinator.runtime_snapshot_source().snapshot();
    if !matches!(
        failed.capture,
        RuntimeCaptureState::Published | RuntimeCaptureState::Detached
    ) {
        return Err(format!(
            "failed candidate settled in an unknown capture state: {failed:?}"
        ));
    }
    match failed.capture {
        RuntimeCaptureState::Published => assert_active_kernel_state()?,
        RuntimeCaptureState::Detached => assert_clean_state()?,
        RuntimeCaptureState::Unknown => unreachable!(),
    }

    execute(
        &mut first.coordinator,
        RuntimeIntent::Reload {
            reason: Reason::UserControl,
        },
        "reload after rejected candidate",
    )?;
    let recovered_generation = first
        .coordinator
        .runtime_snapshot_source()
        .snapshot()
        .generation()
        .ok_or_else(|| "recovered reload has no Generation".to_owned())?;
    if recovered_generation <= generation(4) {
        return Err(format!(
            "recovered reload did not advance the committed Generation: {recovered_generation}"
        ));
    }
    assert_active_kernel_state()?;

    execute(
        &mut first.coordinator,
        RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        },
        "stop native runtime",
    )?;
    assert_stopped(&first.coordinator)?;
    assert_clean_state()?;
    assert_no_durable_writer_fence(&fixture.durable_root)?;

    execute(
        &mut first.coordinator,
        RuntimeIntent::Running {
            reason: Reason::UserControl,
        },
        "restart before crash recovery",
    )?;
    assert_active_kernel_state()?;
    let dropped_pid = latest_engine_pid(&fixture.pid_log)?;
    drop(first);
    wait_for_process_absence(dropped_pid)?;

    let mut recovered = fixture.compose_runtime()?;
    assert_clean_state()?;
    execute(
        &mut recovered.coordinator,
        RuntimeIntent::Running {
            reason: Reason::Boot,
        },
        "start after durable crash recovery",
    )?;
    assert_active_kernel_state()?;
    execute(
        &mut recovered.coordinator,
        RuntimeIntent::Stopped {
            reason: Reason::UserControl,
        },
        "stop recovered native runtime",
    )?;
    assert_clean_state()?;

    execute(
        &mut recovered.coordinator,
        RuntimeIntent::Running {
            reason: Reason::UserControl,
        },
        "start before offline recovery",
    )?;
    assert_active_kernel_state()?;
    let offline_pid = latest_engine_pid(&fixture.pid_log)?;
    drop(recovered);
    wait_for_process_absence(offline_pid)?;

    run_offline_recovery(&fixture)?;
    assert_clean_state()?;
    assert_offline_durable_state(&fixture.durable_root)?;
    run_offline_recovery(&fixture)?;
    assert_clean_state()?;
    assert_offline_durable_state(&fixture.durable_root)?;
    exercise_daemon_lifecycle(&root.join("daemon"))?;
    assert_clean_state()?;
    assert_subprocess_audit(&fixture.audit)?;
    Ok(())
}

fn exercise_daemon_lifecycle(root: &Path) -> Result<(), String> {
    let fixture = Fixture::new(root)?;
    assert_clean_state()?;

    let socket_path = root.join("run/fluxd.sock");
    let daemon_options = daemon_options(root);
    let profile = fixture.capability_profile.clone();
    let profile_source = StaticCapabilityProfileSource::new(profile.clone());
    let platform = LinuxNativeCompositionDaemonPlatform::new(
        profile,
        &fixture.tool_root,
        &fixture.durable_root,
        fixture.routing,
        fixture.mark,
        2,
        COMMAND_TIMEOUT,
    );
    let controller_socket = socket_path.clone();
    let controller_pid_log = fixture.pid_log.clone();
    let controller = std::thread::Builder::new()
        .name("flux-native-daemon-controller".to_owned())
        .spawn(move || daemon_controller(&controller_socket, &controller_pid_log))
        .map_err(|error| format!("spawn native daemon controller: {error}"))?;

    let daemon =
        run_linux_native_composition_test_daemon(&profile_source, daemon_options, platform)
            .map_err(|error| format!("run admitted native daemon: {error}"));
    let controller = controller.join().map_err(|payload| {
        format!(
            "native daemon controller panicked: {}",
            panic_message(payload)
        )
    })?;
    daemon?;
    let final_engine_pid = controller?;

    wait_for_process_absence(final_engine_pid)?;
    if socket_path.exists() {
        return Err(format!(
            "control socket remains after daemon shutdown: {}",
            socket_path.display()
        ));
    }
    assert_clean_state()?;
    assert_no_durable_writer_fence(&fixture.durable_root)
}

fn daemon_options(root: &Path) -> DaemonOptions {
    let run = root.join("run");
    let state = root.join("state");
    DaemonOptions {
        runtime_root: root.to_owned(),
        socket_path: run.join("fluxd.sock"),
        daemon_lease_path: run.join("fluxd.lease"),
        config_path: root.join("conf/flux.toml"),
        subscription_store_path: state.join("subscription"),
        intent_path: state.join("administrative-intent.json"),
        boot_id_path: root.join("boot-id"),
        selinux_enforce_path: root.join("selinux-enforce"),
        disable_path: root.join("disable"),
    }
}

fn daemon_controller(socket_path: &Path, pid_log: &Path) -> Result<u32, String> {
    let result = daemon_controller_inner(socket_path, pid_log);
    if result.is_err() {
        let _ = signal_daemon_shutdown();
    }
    result
}

fn daemon_controller_inner(socket_path: &Path, pid_log: &Path) -> Result<u32, String> {
    let client = SocketControlClient::new(socket_path);
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    let initial_generation = loop {
        if socket_path.exists()
            && let Ok(snapshot) = client.status()
            && snapshot.native_admission == NativeAdmissionState::Admitted
            && snapshot.control.administrative_state == AdministrativeState::Running
            && snapshot.runtime.phase == RuntimePhase::Running
            && snapshot.runtime.capture == RuntimeCaptureState::Published
            && snapshot.runtime.engine == RuntimeEngineState::Ready
            && let Some(generation) = snapshot.runtime.generation()
        {
            break generation;
        }
        if Instant::now() >= deadline {
            return Err("admitted daemon did not become queryable and Running".to_owned());
        }
        std::thread::sleep(MAINTENANCE_INTERVAL);
    };
    assert_active_kernel_state()?;

    let mut address = Command::new("ip");
    address.args(["address", "add", "8.8.8.8/32", "dev", "lo"]);
    checked_command(address, COMMAND_TIMEOUT)?;
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        let _ = client.submit_and_wait(RuntimeIntent::ResyncAddresses {
            reason: Reason::UserControl,
        });
        if let Ok(snapshot) = client.status()
            && snapshot.native_admission == NativeAdmissionState::Admitted
            && snapshot.control.administrative_state == AdministrativeState::Running
            && snapshot.runtime.phase == RuntimePhase::Running
            && snapshot.runtime.capture == RuntimeCaptureState::Published
            && snapshot.runtime.engine == RuntimeEngineState::Ready
            && snapshot
                .runtime
                .generation()
                .is_some_and(|generation| generation > initial_generation)
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err(
                "reactor inventory change did not converge an address successor".to_owned(),
            );
        }
        std::thread::sleep(MAINTENANCE_INTERVAL);
    }
    assert_active_kernel_state()?;
    let final_engine_pid = latest_engine_pid(pid_log)?;
    signal_daemon_shutdown()?;
    Ok(final_engine_pid)
}

fn signal_daemon_shutdown() -> Result<(), String> {
    // SAFETY: `getpid` has no arguments and returns this isolated test process identifier.
    let process_id = unsafe { libc::getpid() };
    if process_id <= 1 {
        return Err(format!(
            "refusing to signal invalid daemon PID {process_id}"
        ));
    }
    // SAFETY: `process_id` names this live isolated process and SIGTERM has no pointer arguments.
    if unsafe { libc::kill(process_id, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "signal admitted daemon shutdown: {}",
            io::Error::last_os_error()
        ))
    }
}

fn block_shutdown_signals_before_exec() -> io::Result<()> {
    let mut mask = MaybeUninit::<libc::sigset_t>::zeroed();
    // SAFETY: `mask` points to writable storage for one signal set.
    if unsafe { libc::sigemptyset(mask.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `sigemptyset` initialized the set and both values are valid signal numbers.
        if unsafe { libc::sigaddset(mask.as_mut_ptr(), signal) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: `mask` is initialized and SIG_BLOCK accepts a null output pointer.
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, mask.as_ptr(), std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Fixture {
    desired_state: PathBuf,
    state_root: PathBuf,
    durable_root: PathBuf,
    working_directory: PathBuf,
    engine_log: PathBuf,
    tool_root: PathBuf,
    inventory: ReplayInventory,
    changed_inventory: Arc<NetworkInventory>,
    capability_profile: CapabilityProfile,
    network_namespace: NetworkNamespaceIdentity,
    routing: XtablesLocalOutputRoutingSpec,
    mark: FwmarkCandidate,
    audit: PathBuf,
    pid_log: PathBuf,
    fail_check: PathBuf,
    accepted_subscription: Arc<Mutex<Option<ValidatedSubscriptionEngineConfig>>>,
}

impl Fixture {
    fn new(root: &Path) -> Result<Self, String> {
        let engine_binary = required_absolute_path(ENGINE_BIN_ENV)?;
        let audit = required_absolute_path(EXEC_AUDIT_ENV)?;
        let pid_log = required_absolute_path(ENGINE_PID_LOG_ENV)?;
        let fail_check = required_absolute_path(FAIL_CHECK_ENV)?;
        let config_root = root.join("conf");
        let state_root = root.join("state");
        let durable_root = root.join("run/native");
        let working_directory = root.join("work");
        fs::create_dir_all(state_root.join("generations"))
            .and_then(|()| fs::create_dir_all(&working_directory))
            .map_err(|error| format!("create native fixture layout: {error}"))?;
        fs::create_dir_all(&config_root)
            .map_err(|error| format!("create {}: {error}", config_root.display()))?;
        let template = config_root.join("template.json");
        let desired_state = config_root.join("flux.toml");
        fs::write(&template, PACKAGED_ENGINE_TEMPLATE)
            .map_err(|error| format!("write {}: {error}", template.display()))?;
        let listener_port = reserve_listener_port()?;
        let source = PACKAGED_DESIRED_STATE
            .replacen(
                "/data/adb/flux/bin/sing-box",
                engine_binary
                    .to_str()
                    .ok_or_else(|| "engine fixture path is not UTF-8".to_owned())?,
                1,
            )
            .replacen(
                "/data/adb/flux/conf/template.json",
                template
                    .to_str()
                    .ok_or_else(|| "template fixture path is not UTF-8".to_owned())?,
                1,
            )
            .replacen("ipv6 = false", "ipv6 = true", 1)
            .replacen("port = 1536", &format!("port = {listener_port}"), 1)
            .replacen(
                "restart_initial_backoff_ms = 1000",
                "restart_initial_backoff_ms = 20",
                1,
            )
            .replacen(
                "restart_maximum_backoff_ms = 30000",
                "restart_maximum_backoff_ms = 100",
                1,
            )
            .replacen(
                "restart_stable_reset_ms = 30000",
                "restart_stable_reset_ms = 100",
                1,
            )
            .replacen(
                "respect_android_vpn = true",
                "respect_android_vpn = false",
                1,
            )
            .replacen(
                "require_functional_canary = true",
                "require_functional_canary = false",
                1,
            );
        FluxConfig::parse(&source)
            .map_err(|error| format!("parse native fixture config: {error}"))?;
        fs::write(&desired_state, source)
            .map_err(|error| format!("write {}: {error}", desired_state.display()))?;

        let authority = NativeLinuxCompositionTestAuthority::acquire()
            .map_err(|error| format!("acquire sealed Linux authority: {error}"))?;
        let boot_identity = authority.boot_identity().clone();
        let network_namespace = authority.network_namespace();
        drop(authority);
        let (initial_inventory, changed_inventory) = inventory_pair()?;
        let inventory = ReplayInventory::new(Some(Arc::clone(&initial_inventory)));
        Ok(Self {
            desired_state,
            state_root,
            durable_root,
            working_directory: working_directory.clone(),
            engine_log: working_directory.join("engine.log"),
            tool_root: required_absolute_path(ROOT_ENV)?.join("tools"),
            inventory,
            changed_inventory,
            capability_profile: CapabilityProfileFixture::device_qualified_for(
                boot_identity,
                network_namespace,
            ),
            network_namespace,
            routing: test_routing()?,
            mark: FwmarkCandidate::new(MARK_MASK, PROXY_MARK, BYPASS_MARK)
                .map_err(|error| format!("construct test mark: {error}"))?,
            audit,
            pid_log,
            fail_check,
            accepted_subscription: Arc::new(Mutex::new(None)),
        })
    }

    fn compose_runtime(&self) -> Result<RuntimeInstance, String> {
        let (admission, convergence) = self.platform_parts()?;
        let source = self.source(admission);
        let (address_inventory, reconciler) = AddressReconciler::replay(&self.desired_state);
        address_inventory.publish(self.inventory.snapshot());
        let coordinator = compose_native_runtime(
            convergence,
            || source,
            MAINTENANCE_INTERVAL,
            RuntimeFunctionalCanary::StructuralVerificationOnly,
        )
        .map_err(|error| format!("compose single-owner native runtime: {error}"))?
        .with_address_reconciler(reconciler);
        Ok(RuntimeInstance {
            coordinator,
            address_inventory,
        })
    }

    fn subscription_candidate(
        &self,
        snapshot_digest: [u8; 32],
        node_count: u32,
    ) -> Result<ValidatedSubscriptionEngineConfig, String> {
        let source = fs::read_to_string(&self.desired_state)
            .map_err(|error| format!("read {}: {error}", self.desired_state.display()))?;
        if source.matches("enabled = false").count() != 1 {
            return Err("native fixture has no unique disabled subscription field".to_owned());
        }
        let source = source.replacen("enabled = false", "enabled = true", 1);
        let desired_state = FluxConfig::parse(&source)
            .map_err(|error| format!("parse subscription-enabled native fixture: {error}"))?;
        fs::write(&self.desired_state, source)
            .map_err(|error| format!("write {}: {error}", self.desired_state.display()))?;
        let template = fs::read(desired_state.engine().template()).map_err(|error| {
            format!(
                "read subscription engine template {}: {error}",
                desired_state.engine().template().display()
            )
        })?;
        let artifact = compile_tproxy_engine_config(TproxyEngineConfigRequest::new(
            &template,
            desired_state.listener().port(),
        ))
        .map_err(|error| format!("compile subscription engine candidate: {error}"))?;
        Ok(ValidatedSubscriptionEngineConfig::for_test(
            desired_state,
            artifact,
            snapshot_digest,
            node_count,
        ))
    }

    fn platform_parts(
        &self,
    ) -> Result<
        (
            NativeLinuxCompositionTestAdmission,
            NativeXtablesCaptureConverger,
        ),
        String,
    > {
        let authority = NativeLinuxCompositionTestAuthority::acquire()
            .map_err(|error| format!("reacquire sealed Linux authority: {error}"))?;
        if authority.network_namespace() != self.network_namespace {
            return Err("network namespace changed during the composition checkpoint".to_owned());
        }
        authority
            .compose(
                NativeLinuxCompositionTestConfig::new(
                    &self.tool_root,
                    &self.durable_root,
                    2,
                    COMMAND_TIMEOUT,
                ),
                self.routing,
                self.mark,
            )
            .map(|runtime| runtime.into_parts())
            .map_err(|error| format!("compose real platform owner: {error}"))
    }

    fn source(&self, admission: NativeLinuxCompositionTestAdmission) -> TestSource {
        AssembledNativeGenerationSource::new(
            NativeGenerationSourcePaths::new(
                &self.desired_state,
                &self.state_root,
                &self.working_directory,
                &self.engine_log,
            ),
            self.inventory.clone(),
            LinuxNativeCompositionPlanningSource::new(
                self.capability_profile.clone(),
                self.network_namespace,
                self.routing,
                self.mark,
            ),
            PlatformNativeLinuxCompositionTestAdmission::new(admission),
            self.accepted_subscription
                .lock()
                .expect("accepted subscription lock")
                .clone(),
        )
    }

    fn accept_subscription(&self, subscription: ValidatedSubscriptionEngineConfig) {
        *self
            .accepted_subscription
            .lock()
            .expect("accepted subscription lock") = Some(subscription);
    }
}

struct RuntimeInstance {
    coordinator: TestCoordinator,
    address_inventory: ReplayNetworkInventorySource,
}

#[derive(Clone)]
struct ReplayInventory {
    current: Arc<Mutex<Option<Arc<NetworkInventory>>>>,
}

impl ReplayInventory {
    fn new(current: Option<Arc<NetworkInventory>>) -> Self {
        Self {
            current: Arc::new(Mutex::new(current)),
        }
    }

    fn publish(&self, current: Option<Arc<NetworkInventory>>) {
        *self.current.lock().expect("native inventory lock") = current;
    }

    fn snapshot(&self) -> Option<Arc<NetworkInventory>> {
        self.current.lock().expect("native inventory lock").clone()
    }
}

impl CompleteNativeInventorySource for ReplayInventory {
    fn snapshot(&mut self) -> Option<Arc<NetworkInventory>> {
        ReplayInventory::snapshot(self)
    }
}

fn execute(
    coordinator: &mut TestCoordinator,
    intent: RuntimeIntent,
    operation: &str,
) -> Result<DispatcherCompletion, String> {
    coordinator
        .execute(&intent)
        .map_err(|error| format!("{operation}: {error}"))
}

fn generation(value: u32) -> GenerationId {
    GenerationId::new(value).expect("test Generation must be nonzero")
}

fn assert_running(coordinator: &TestCoordinator, generation: GenerationId) -> Result<(), String> {
    let snapshot = coordinator.runtime_snapshot_source().snapshot();
    if snapshot.phase != RuntimePhase::Running
        || snapshot.capture != RuntimeCaptureState::Published
        || snapshot.engine != RuntimeEngineState::Ready
        || snapshot.generation() != Some(generation)
    {
        return Err(format!(
            "native runtime is not exact running Generation {generation}: {snapshot:?}"
        ));
    }
    Ok(())
}

fn assert_stopped(coordinator: &TestCoordinator) -> Result<(), String> {
    let snapshot = coordinator.runtime_snapshot_source().snapshot();
    if snapshot.phase != RuntimePhase::Stopped
        || snapshot.capture != RuntimeCaptureState::Detached
        || snapshot.engine != RuntimeEngineState::Stopped
        || snapshot.generation().is_some()
    {
        return Err(format!("native runtime is not exact stopped: {snapshot:?}"));
    }
    Ok(())
}

fn wait_for_engine_recovery(
    coordinator: &mut TestCoordinator,
    pid_log: &Path,
    exited_pid: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        coordinator.maintain();
        let snapshot = coordinator.runtime_snapshot_source().snapshot();
        if snapshot.phase == RuntimePhase::Running
            && snapshot.capture == RuntimeCaptureState::Published
            && snapshot.engine == RuntimeEngineState::Ready
            && latest_engine_pid(pid_log).is_ok_and(|pid| pid != exited_pid)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "engine did not recover within {RECOVERY_TIMEOUT:?}: {snapshot:?}"
            ));
        }
        std::thread::sleep(MAINTENANCE_INTERVAL);
    }
}

fn run_offline_recovery(fixture: &Fixture) -> Result<(), String> {
    let (_admission, convergence) = fixture.platform_parts()?;
    NativeOfflineRecovery::new(convergence)
        .recover_stopped()
        .map(|_| ())
        .map_err(|error| format!("native offline recovery: {error}"))
}

fn assert_active_kernel_state() -> Result<(), String> {
    let ipv4 = command_text("iptables-save", &["-t", "mangle"])?;
    let ipv6 = command_text("ip6tables-save", &["-t", "mangle"])?;
    if !ipv4.lines().any(|line| line.contains("FLX4"))
        || !ipv6.lines().any(|line| line.contains("FLX6"))
    {
        return Err("native active state lacks dual-stack FLX chains".to_owned());
    }
    for family in ["-4", "-6"] {
        let rules = command_text("ip", &[family, "rule", "show"])?;
        if !owned_rule_present(&rules) {
            return Err(format!("native {family} RPDB rule is absent: {rules}"));
        }
        let routes = command_text("ip", &[family, "route", "show", "table", "all"])?;
        if !owned_route_present(&routes) {
            return Err(format!("native {family} local route is absent: {routes}"));
        }
    }
    Ok(())
}

fn assert_clean_state() -> Result<(), String> {
    for program in ["iptables-save", "ip6tables-save"] {
        let save = command_text(program, &["-t", "mangle"])?;
        if save.lines().any(|line| line.contains("FLX")) {
            return Err(format!(
                "{program} retains native FLX state after cleanup: {save}"
            ));
        }
    }
    for family in ["-4", "-6"] {
        let rules = command_text("ip", &[family, "rule", "show"])?;
        if owned_rule_present(&rules) {
            return Err(format!(
                "{family} RPDB retains Flux identity after cleanup: {rules}"
            ));
        }
        let routes = command_text("ip", &[family, "route", "show", "table", "all"])?;
        if owned_route_present(&routes) {
            return Err(format!(
                "{family} routes retain Flux identity after cleanup: {routes}"
            ));
        }
    }
    Ok(())
}

fn owned_rule_present(rules: &str) -> bool {
    let prefix = format!("{ROUTING_PRIORITY}:");
    rules.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with(&prefix) || line.contains(&format!("lookup {ROUTING_TABLE}"))
    })
}

fn owned_route_present(routes: &str) -> bool {
    routes
        .lines()
        .any(|line| line.contains(&format!("table {ROUTING_TABLE}")))
}

fn assert_no_durable_writer_fence(root: &Path) -> Result<(), String> {
    for relative in ["native_xtables.lease", "xtables-writer.lock"] {
        let path = root.join(relative);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(format!(
                "native durable writer fence remains after clean settlement: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn assert_offline_durable_state(root: &Path) -> Result<(), String> {
    assert_no_durable_writer_fence(root)?;
    let journal = root.join("native_xtables.journal");
    if fs::symlink_metadata(&journal).is_ok() {
        return Err(format!(
            "native terminal journal remains after offline recovery: {}",
            journal.display()
        ));
    }
    let archive = root.join("native_xtables.targets");
    let metadata = fs::symlink_metadata(&archive)
        .map_err(|error| format!("inspect settled archive {}: {error}", archive.display()))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 1024 * 1024 {
        return Err(format!(
            "settled native target archive {} is not a bounded nonempty regular file",
            archive.display()
        ));
    }
    Ok(())
}

fn assert_subprocess_audit(path: &Path) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > 1024 * 1024 {
        return Err(format!("subprocess audit {} exceeds 1 MiB", path.display()));
    }
    let text = String::from_utf8(bytes)
        .map_err(|error| format!("subprocess audit {} is not UTF-8: {error}", path.display()))?;
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut fields = line.split('\t');
        if fields.next() != Some("v1") {
            return Err(format!(
                "subprocess audit line {} has no v1 prefix",
                index + 1
            ));
        }
        let decoded = fields.map(decode_hex).collect::<Result<Vec<_>, _>>()?;
        if decoded.is_empty() {
            return Err(format!(
                "subprocess audit line {} has no program",
                index + 1
            ));
        }
        records.push(decoded);
    }
    if records.len() < 10 {
        return Err(format!(
            "subprocess audit recorded only {} process executions",
            records.len()
        ));
    }
    for required in ["version", "check", "run"] {
        if !records
            .iter()
            .flatten()
            .any(|field| field.as_slice() == required.as_bytes())
        {
            return Err(format!(
                "subprocess audit did not record the engine `{required}` command"
            ));
        }
    }
    for record in &records {
        for field in record {
            let value = String::from_utf8_lossy(field).to_ascii_lowercase();
            let basename = Path::new(&value)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if matches!(
                basename,
                "sh" | "bash" | "dispatcher" | "addrsyncd" | "jq" | "curl" | "awk" | "fluxctl"
            ) || value
                .split(['/', '\\'])
                .any(|component| component == "scripts")
            {
                return Err(format!(
                    "forbidden runtime subprocess appeared in audit: {value:?}"
                ));
            }
        }
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("invalid subprocess audit hex field {value:?}"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("validated ASCII hex");
            u8::from_str_radix(pair, 16)
                .map_err(|error| format!("decode subprocess audit field: {error}"))
        })
        .collect()
}

fn command_text(program: &str, arguments: &[&str]) -> Result<String, String> {
    let mut command = Command::new(program);
    command.args(arguments).env("LC_ALL", "C");
    let output = checked_command(command, COMMAND_TIMEOUT)?;
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} output is not UTF-8: {error}"))
}

fn latest_engine_pid(path: &Path) -> Result<u32, String> {
    let text = fs::read_to_string(path)
        .map_err(|error| format!("read engine PID log {}: {error}", path.display()))?;
    text.lines()
        .rev()
        .find_map(|line| line.split_once('\t').map(|(pid, _)| pid))
        .ok_or_else(|| format!("engine PID log {} is empty", path.display()))?
        .parse::<u32>()
        .map_err(|error| format!("parse engine PID log {}: {error}", path.display()))
}

fn kill_engine(pid: u32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| format!("engine PID {pid} exceeds pid_t"))?;
    if pid <= 1 {
        return Err(format!("refusing to signal invalid engine PID {pid}"));
    }
    // SAFETY: `pid` is a validated positive child PID and SIGKILL has no pointer arguments.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
        Ok(())
    } else {
        Err(format!(
            "kill engine PID {pid}: {}",
            io::Error::last_os_error()
        ))
    }
}

fn wait_for_process_absence(pid: u32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| format!("engine PID {pid} exceeds pid_t"))?;
    let deadline = Instant::now() + RECOVERY_TIMEOUT;
    loop {
        // SAFETY: signal zero observes one validated positive PID and does not mutate it.
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "engine PID {pid} remained live after coordinator drop"
            ));
        }
        std::thread::sleep(MAINTENANCE_INTERVAL);
    }
}

fn inventory_pair() -> Result<(Arc<NetworkInventory>, Arc<NetworkInventory>), String> {
    let mut tracker = NetworkInventoryTracker::new();
    let initial = Arc::new(
        tracker
            .publish_complete([], [])
            .map_err(|error| format!("publish initial inventory: {error}"))?
            .clone(),
    );
    let address = InterfaceAddressRecord::new(
        InterfaceIndex::new(7).expect("fixture interface index is nonzero"),
        "8.8.8.8"
            .parse::<IpAddr>()
            .expect("fixture address is valid"),
        32,
        InterfaceAddressFlags::from_bits(0),
    )
    .map_err(|error| format!("construct changed inventory address: {error}"))?;
    let changed = Arc::new(
        tracker
            .publish_complete([], [address])
            .map_err(|error| format!("publish changed inventory: {error}"))?
            .clone(),
    );
    Ok((initial, changed))
}

fn test_routing() -> Result<XtablesLocalOutputRoutingSpec, String> {
    let target = XtablesLocalOutputRoutingTarget::new(
        RulePriority::from_raw(ROUTING_PRIORITY),
        RouteTableId::from_raw(ROUTING_TABLE),
        NonZeroU32::new(1_024).expect("native route metric is nonzero"),
        RouteProtocol::from_raw(4),
        RuleProtocol::from_raw(99),
    )
    .map_err(|error| format!("construct native routing target: {error}"))?;
    XtablesLocalOutputRoutingSpec::new(Some(target), Some(target))
        .map_err(|error| format!("construct dual-stack routing plan: {error}"))
}

fn reserve_listener_port() -> Result<u16, String> {
    TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| format!("reserve engine fixture listener port: {error}"))
}

fn fixture_engine_binary() -> Result<PathBuf, String> {
    let test = env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let debug_root = test
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| format!("cannot derive target directory from {}", test.display()))?;
    let binary = debug_root.join(format!(
        "flux-native-composition-engine{}",
        env::consts::EXE_SUFFIX
    ));
    let metadata = fs::metadata(&binary).map_err(|error| {
        format!(
            "native engine fixture {} is not built: {error}",
            binary.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "native engine fixture {} is not a file",
            binary.display()
        ));
    }
    Ok(binary)
}

fn stage_xtables_tools(destination_root: &Path) -> Result<(), String> {
    fs::create_dir(destination_root).map_err(|error| {
        format!(
            "create private xtables tool root {}: {error}",
            destination_root.display()
        )
    })?;
    for name in XTABLES_TOOL_NAMES {
        let source = resolve_program(name)?;
        let destination = destination_root.join(name);
        fs::copy(&source, &destination).map_err(|error| {
            format!(
                "stage real xtables tool {} as {}: {error}",
                source.display(),
                destination.display()
            )
        })?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).map_err(|error| {
            format!(
                "seal staged xtables tool {}: {error}",
                destination.display()
            )
        })?;
    }
    Ok(())
}

fn resolve_program(name: &str) -> Result<PathBuf, String> {
    let path = env::var_os("PATH").ok_or_else(|| "PATH is not set".to_owned())?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return fs::canonicalize(&candidate).map_err(|error| {
                format!("resolve installed helper {}: {error}", candidate.display())
            });
        }
    }
    Err(format!("required helper `{name}` is not present on PATH"))
}

fn required_absolute_path(variable: &str) -> Result<PathBuf, String> {
    let path = env::var_os(variable)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is required"))?;
    if !path.is_absolute() {
        return Err(format!(
            "{variable} must be absolute, found {}",
            path.display()
        ));
    }
    Ok(path)
}

fn verify_reentry() -> Result<(), String> {
    let token = env::var(TOKEN_ENV).map_err(|_| format!("{TOKEN_ENV} is required"))?;
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{TOKEN_ENV} is not a 128-bit hexadecimal token"));
    }
    let outer_net =
        env::var(OUTER_NETNS_ENV).map_err(|_| format!("{OUTER_NETNS_ENV} is required"))?;
    let outer_user =
        env::var(OUTER_USERNS_ENV).map_err(|_| format!("{OUTER_USERNS_ENV} is required"))?;
    let current_net = network_namespace_identity()?;
    let current_user = user_namespace_identity()?;
    if outer_net == current_net || outer_user == current_user {
        return Err(format!(
            "reentry did not isolate both namespaces: outer_net={outer_net} current_net={current_net} outer_user={outer_user} current_user={current_user}"
        ));
    }
    // SAFETY: `geteuid` has no arguments, does not dereference pointers, and cannot fail.
    let effective_uid = unsafe { libc::geteuid() };
    if effective_uid != 0 {
        return Err(format!(
            "isolated reentry effective UID is {effective_uid}, expected 0"
        ));
    }
    let uid_map = fs::read_to_string("/proc/self/uid_map")
        .map_err(|error| format!("read isolated UID map: {error}"))?;
    let fields = uid_map
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("parse isolated UID map: {error}"))?;
    if fields.len() != 3 || fields[0] != 0 || fields[2] != 1 {
        return Err(format!(
            "isolated reentry requires one mapped-root UID identity, found {:?}",
            uid_map.trim()
        ));
    }
    Ok(())
}

fn required_mode() -> Result<bool, String> {
    match env::var(REQUIRED_ENV) {
        Ok(value) if value == "0" => Ok(false),
        Ok(value) if value == "1" => Ok(true),
        Ok(_) => Err(format!("{REQUIRED_ENV} must be 0 or 1")),
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{REQUIRED_ENV} must be valid UTF-8")),
    }
}

fn skip_or_fail(required: bool, reason: String) -> Result<(), String> {
    if required {
        Err(reason)
    } else {
        eprintln!("SKIP: {reason}");
        Ok(())
    }
}

fn emergency_cleanup() {
    for (program, arguments) in [
        ("iptables", &["-t", "mangle", "-F"][..]),
        ("iptables", &["-t", "mangle", "-X"][..]),
        ("ip6tables", &["-t", "mangle", "-F"][..]),
        ("ip6tables", &["-t", "mangle", "-X"][..]),
        ("ip", &["-4", "route", "flush", "table", "20253"][..]),
        ("ip", &["-6", "route", "flush", "table", "20253"][..]),
    ] {
        let _ = Command::new(program).args(arguments).status();
    }
    for family in ["-4", "-6"] {
        for _ in 0..2 {
            let _ = Command::new("ip")
                .args([family, "rule", "delete", "priority", "30999"])
                .status();
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}
