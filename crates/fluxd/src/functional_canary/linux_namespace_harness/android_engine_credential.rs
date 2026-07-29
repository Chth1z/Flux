//! Rooted Android no-traffic qualification for the production engine privilege transition.

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::TcpListener;
use std::num::{NonZeroU16, NonZeroU32};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use flux_core::{CaptureGroupId, CaptureUserId, EngineCredentials};
use flux_platform::internal::{
    ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME, ENGINE_CREDENTIAL_PROBE_STAGE_TEMPORARY_NAME,
    EngineCredentialProbeConfig, EngineCredentialProbeReport, EngineCredentialProbeStage,
    PinnedSingBoxLaunch, SingBoxProcessAdapter, TerminationOutcome,
    validate_engine_process_credentials,
};
use flux_platform::{
    ProcessHandleErrorKind, ProcessHandleOpenStage, SingBoxExit, SingBoxLaunchSpec,
    SingBoxPrivilege, SingBoxReadiness,
};

use super::{
    ProcessIdentity, arm_parent_death_signal, combine_checkpoint_and_cleanup, kill_owned_process,
    owned_process_remains, parse_published_process_identity, verify_process_identity, wait_child,
};

const REQUIRED_ENV: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_REQUIRED";
const PROBE_PATH_ENV: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_PATH";
const DEVICE_GID_ENV: &str = "FLUX_ENGINE_CREDENTIAL_PROBE_GID";
const PARENT_DEATH_HELPER_ENV: &str = "FLUX_ENGINE_CREDENTIAL_PARENT_DEATH_HELPER";
const PARENT_DEATH_TEST: &str = "functional_canary::linux_namespace_harness::privileged_android_engine_credential_parent_death_helper";
const SOCKET_MARK: u32 = 0x0100_0000;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
const PARENT_DEATH_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

#[derive(Clone, Copy)]
struct CredentialLifecycleStages {
    validation: EngineCredentialProbeStage,
    spawn: EngineCredentialProbeStage,
    readiness: EngineCredentialProbeStage,
    process_handle: fn(ProcessHandleOpenStage) -> EngineCredentialProbeStage,
    initial_credentials: EngineCredentialProbeStage,
    reobservation: EngineCredentialProbeStage,
    report: EngineCredentialProbeStage,
    termination: EngineCredentialProbeStage,
    post_reap: EngineCredentialProbeStage,
}

const ROOT_LIFECYCLE_STAGES: CredentialLifecycleStages = CredentialLifecycleStages {
    validation: EngineCredentialProbeStage::RootValidation,
    spawn: EngineCredentialProbeStage::RootSpawn,
    readiness: EngineCredentialProbeStage::RootReadiness,
    process_handle: EngineCredentialProbeStage::RootProcessHandle,
    initial_credentials: EngineCredentialProbeStage::RootInitialCredentials,
    reobservation: EngineCredentialProbeStage::RootReobservation,
    report: EngineCredentialProbeStage::RootReport,
    termination: EngineCredentialProbeStage::RootTermination,
    post_reap: EngineCredentialProbeStage::RootPostReap,
};

const DEVICE_GID_LIFECYCLE_STAGES: CredentialLifecycleStages = CredentialLifecycleStages {
    validation: EngineCredentialProbeStage::DeviceGidValidation,
    spawn: EngineCredentialProbeStage::DeviceGidSpawn,
    readiness: EngineCredentialProbeStage::DeviceGidReadiness,
    process_handle: EngineCredentialProbeStage::DeviceGidProcessHandle,
    initial_credentials: EngineCredentialProbeStage::DeviceGidInitialCredentials,
    reobservation: EngineCredentialProbeStage::DeviceGidReobservation,
    report: EngineCredentialProbeStage::DeviceGidReport,
    termination: EngineCredentialProbeStage::DeviceGidTermination,
    post_reap: EngineCredentialProbeStage::DeviceGidPostReap,
};

pub(super) fn run() {
    if let Err(error) = run_checkpoint() {
        panic!("Android engine credential checkpoint failed: {error}");
    }
}

pub(super) fn run_parent_death_helper() {
    if let Err(error) = run_parent_death_helper_inner() {
        panic!("Android engine parent-death helper failed: {error}");
    }
}

fn run_checkpoint() -> Result<(), String> {
    require_authority()?;
    let probe = probe_path()?;
    let root = probe
        .parent()
        .ok_or_else(|| "credential probe has no parent directory".to_owned())?;
    let candidate_gid = canonical_u32(&required_env(DEVICE_GID_ENV)?, DEVICE_GID_ENV)?;
    if candidate_gid == 0 {
        return Err("device-qualified primary GID candidate must be nonzero".to_owned());
    }
    let root_credentials = credentials(0, 0)?;
    let device_gid_credentials = credentials(0, candidate_gid)?;
    exercise_lifecycle(
        root,
        &probe,
        "root",
        root_credentials,
        ROOT_LIFECYCLE_STAGES,
    )?;
    exercise_lifecycle(
        root,
        &probe,
        "device-gid",
        device_gid_credentials,
        DEVICE_GID_LIFECYCLE_STAGES,
    )?;
    exercise_parent_death(root, &probe, root_credentials)?;
    println!(
        "Android engine credential checkpoint passed for two credential profiles and parent-death containment"
    );
    Ok(())
}

fn require_authority() -> Result<(), String> {
    if env::var(REQUIRED_ENV).as_deref() == Ok("1") {
        Ok(())
    } else {
        Err("exact Android credential runner authority is required".to_owned())
    }
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} must be present and valid UTF-8"))
}

fn publish_credential_stage(root: &Path, stage: EngineCredentialProbeStage) -> Result<(), String> {
    let receipt = root
        .join("tmp")
        .join(ENGINE_CREDENTIAL_PROBE_STAGE_RECEIPT_NAME);
    let temporary = root
        .join("tmp")
        .join(ENGINE_CREDENTIAL_PROBE_STAGE_TEMPORARY_NAME);
    remove_files(&[receipt.clone(), temporary.clone()])?;
    let _temporary_cleanup = FileCleanup::new(vec![temporary.clone()]);
    write_new_file(&temporary, format!("{}\n", stage.as_str()).as_bytes())?;
    fs::rename(&temporary, &receipt)
        .map_err(|error| format!("publish credential stage atomically: {error}"))
}

fn probe_path() -> Result<PathBuf, String> {
    let path = PathBuf::from(required_env(PROBE_PATH_ENV)?);
    if !path.is_absolute()
        || path.file_name().and_then(|name| name.to_str()) != Some("flux-engine-credential-probe")
    {
        return Err("credential probe path is not the exact absolute artifact path".to_owned());
    }
    Ok(path)
}

fn credentials(uid: u32, gid: u32) -> Result<EngineCredentials, String> {
    let uid = CaptureUserId::new(uid).ok_or_else(|| "invalid engine UID".to_owned())?;
    let gid = CaptureGroupId::new(gid).ok_or_else(|| "invalid engine GID".to_owned())?;
    Ok(EngineCredentials::new(uid, gid))
}

fn exercise_lifecycle(
    root: &Path,
    probe: &Path,
    label: &str,
    expected: EngineCredentials,
    stages: CredentialLifecycleStages,
) -> Result<(), String> {
    let paths = ProbeCasePaths::new(root, label);
    let owned_paths = paths.all();
    let _cleanup = FileCleanup::new(owned_paths.clone());
    let checkpoint = exercise_lifecycle_inner(root, probe, &paths, expected, stages);
    combine_checkpoint_and_cleanup(checkpoint, remove_files(&owned_paths))
}

fn exercise_lifecycle_inner(
    root: &Path,
    probe: &Path,
    paths: &ProbeCasePaths,
    expected: EngineCredentials,
    stages: CredentialLifecycleStages,
) -> Result<(), String> {
    remove_files(&paths.all())?;
    publish_credential_stage(root, stages.validation)?;
    let listener_port = reserve_listener_port()?;
    write_config(&paths.config, expected, listener_port, &paths.report)?;
    let pinned = pin_probe(probe, &paths.config)?;
    let spec = launch_spec(root, probe, paths, expected, listener_port);
    let adapter = SingBoxProcessAdapter;
    let validation = adapter
        .validate_pinned(&pinned, &spec)
        .map_err(|error| format!("validate credential probe through pinned check: {error}"))?;
    if validation.exit != SingBoxExit::Code(0) || paths.report.exists() {
        return Err(
            "pinned credential check did not exit cleanly and without a run report".to_owned(),
        );
    }

    publish_credential_stage(root, stages.spawn)?;
    let mut child = adapter
        .spawn_pinned(&pinned, &spec)
        .map_err(|error| format!("spawn credential probe through production adapter: {error}"))?;
    let exercise = (|| {
        publish_credential_stage(root, stages.readiness)?;
        adapter
            .wait_ready(&mut child, &spec)
            .map_err(|error| format!("wait for credential probe listener: {error}"))?;
        publish_credential_stage(root, (stages.process_handle)(ProcessHandleOpenStage::Start))?;
        let handle = child.open_process_handle().map_err(|error| {
            let failure = format!("open exact credential-probe process handle: {error}");
            match publish_credential_stage(root, (stages.process_handle)(error.stage())) {
                Ok(()) => failure,
                Err(publication) => {
                    format!("{failure}; publish process-handle failure stage: {publication}")
                }
            }
        })?;
        publish_credential_stage(root, stages.initial_credentials)?;
        let initial = handle.initial_observation();
        validate_engine_process_credentials(initial.credentials(), expected)?;
        publish_credential_stage(root, stages.reobservation)?;
        thread::sleep(POLL_INTERVAL);
        let reobserved = handle
            .reobserve()
            .map_err(|error| format!("reobserve exact credential-probe process: {error}"))?;
        validate_engine_process_credentials(reobserved.credentials(), expected)?;
        if initial.identity() != reobserved.identity() || initial.domain() != reobserved.domain() {
            return Err(
                "pidfd-bound process identity or domain changed during reobservation".to_owned(),
            );
        }
        publish_credential_stage(root, stages.report)?;
        let report = read_report(&paths.report)?;
        report.validate_for(expected)?;
        Ok(handle)
    })();
    let exercise = exercise.and_then(|handle| {
        publish_credential_stage(root, stages.termination)?;
        Ok(handle)
    });
    let termination = adapter
        .terminate(&mut child, STOP_TIMEOUT)
        .map_err(|error| format!("terminate and reap credential probe: {error}"));
    let handle = match (exercise, termination) {
        (Ok(handle), Ok(TerminationOutcome::Terminated { .. })) => handle,
        (Ok(_), Ok(other)) => {
            return Err(format!(
                "credential probe did not accept bounded termination: {other:?}"
            ));
        }
        (Ok(_), Err(termination)) => return Err(termination),
        (Err(exercise), Ok(_)) => return Err(exercise),
        (Err(exercise), Err(termination)) => {
            return Err(format!(
                "{exercise}; mandatory credential-probe termination also failed: {termination}"
            ));
        }
    };
    publish_credential_stage(root, stages.post_reap)?;
    let exited = match handle.reobserve() {
        Ok(_) => return Err("reaped credential probe remains observable".to_owned()),
        Err(error) => error,
    };
    if exited.kind() != ProcessHandleErrorKind::Exited {
        return Err(format!(
            "post-reap process handle returned unexpected class {:?}",
            exited.kind()
        ));
    }
    Ok(())
}

fn exercise_parent_death(
    root: &Path,
    probe: &Path,
    expected: EngineCredentials,
) -> Result<(), String> {
    let paths = ProbeCasePaths::new(root, "parent-death");
    let identity_path = root.join("credential-parent-death-identity");
    let identity_temporary_path = root.join("credential-parent-death-identity-tmp");
    let mut owned_paths = paths.all();
    owned_paths.push(identity_path.clone());
    owned_paths.push(identity_temporary_path.clone());
    let _cleanup = FileCleanup::new(owned_paths.clone());
    let checkpoint = exercise_parent_death_inner(
        root,
        probe,
        expected,
        &paths,
        &identity_path,
        &identity_temporary_path,
        &owned_paths,
    );
    combine_checkpoint_and_cleanup(checkpoint, remove_files(&owned_paths))
}

fn exercise_parent_death_inner(
    root: &Path,
    probe: &Path,
    expected: EngineCredentials,
    paths: &ProbeCasePaths,
    identity_path: &Path,
    identity_temporary_path: &Path,
    owned_paths: &[PathBuf],
) -> Result<(), String> {
    remove_files(owned_paths)?;
    publish_credential_stage(root, EngineCredentialProbeStage::ParentDeathSupervisor)?;
    let listener_port = reserve_listener_port()?;
    write_config(&paths.config, expected, listener_port, &paths.report)?;

    let mut supervisor = Command::new(
        env::current_exe().map_err(|error| format!("resolve Android test executable: {error}"))?,
    );
    supervisor
        .args([
            "--ignored",
            "--exact",
            PARENT_DEATH_TEST,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PARENT_DEATH_HELPER_ENV, "1")
        .env(PROBE_PATH_ENV, probe)
        .env("FLUX_ENGINE_CREDENTIAL_CONFIG", &paths.config)
        .env("FLUX_ENGINE_CREDENTIAL_REPORT", &paths.report)
        .env("FLUX_ENGINE_CREDENTIAL_LOG", &paths.log)
        .env("FLUX_ENGINE_CREDENTIAL_IDENTITY", identity_path)
        .env(
            "FLUX_ENGINE_CREDENTIAL_IDENTITY_TMP",
            identity_temporary_path,
        )
        .env(
            "FLUX_ENGINE_CREDENTIAL_PORT",
            listener_port.get().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    arm_parent_death_signal(&mut supervisor)?;
    let mut supervisor = supervisor
        .spawn()
        .map_err(|error| format!("spawn parent-death supervisor: {error}"))?;
    let identity_stage =
        publish_credential_stage(root, EngineCredentialProbeStage::ParentDeathIdentity);
    let identity =
        wait_for_parent_death_identity(&mut supervisor, identity_path).and_then(|identity| {
            verify_process_identity(identity).map_err(|error| {
                format!(
                    "credential probe was not live immediately before supervisor death: {error}"
                )
            })?;
            Ok(identity)
        });
    match identity {
        Ok(identity) => {
            let containment_stage =
                publish_credential_stage(root, EngineCredentialProbeStage::ParentDeathContainment);
            let supervisor_cleanup = kill_and_reap_supervisor(&mut supervisor);
            let parent_death = require_parent_death_or_cleanup(identity);
            let result = combine_checkpoint_and_cleanup(identity_stage, containment_stage);
            let result = combine_checkpoint_and_cleanup(result, supervisor_cleanup);
            combine_checkpoint_and_cleanup(result, parent_death)
        }
        Err(error) => {
            let supervisor_cleanup = kill_and_reap_supervisor(&mut supervisor);
            let result = combine_checkpoint_and_cleanup::<()>(Err(error), identity_stage);
            combine_checkpoint_and_cleanup(result, supervisor_cleanup)
        }
    }
}

fn kill_and_reap_supervisor(supervisor: &mut Child) -> Result<(), String> {
    if supervisor
        .try_wait()
        .map_err(|error| format!("poll parent-death supervisor before kill: {error}"))?
        .is_some()
    {
        return Ok(());
    }
    let kill_error = supervisor.kill().err();
    match wait_child(supervisor, PARENT_DEATH_TIMEOUT) {
        Ok(_) => Ok(()),
        Err(reap_error) => match kill_error {
            Some(kill_error) => Err(format!(
                "kill parent-death supervisor: {kill_error}; bounded reap also failed: {reap_error}"
            )),
            None => Err(format!(
                "bounded reap of killed parent-death supervisor: {reap_error}"
            )),
        },
    }
}

fn require_parent_death_or_cleanup(identity: ProcessIdentity) -> Result<(), String> {
    let parent_death = wait_for_owned_process_absence(identity, PARENT_DEATH_TIMEOUT);
    if parent_death.is_ok() {
        return Ok(());
    }
    let parent_death = parent_death.expect_err("checked error branch");
    let cleanup = kill_owned_process(identity)
        .and_then(|()| wait_for_owned_process_absence(identity, PARENT_DEATH_TIMEOUT));
    match cleanup {
        Ok(()) => Err(parent_death),
        Err(cleanup) => Err(format!(
            "{parent_death}; mandatory exact-identity probe cleanup also failed: {cleanup}"
        )),
    }
}

fn wait_for_owned_process_absence(
    identity: ProcessIdentity,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if !owned_process_remains(identity)? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("credential probe survived its direct supervisor".to_owned());
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_parent_death_identity(
    supervisor: &mut Child,
    identity_path: &Path,
) -> Result<ProcessIdentity, String> {
    let deadline = Instant::now() + PARENT_DEATH_TIMEOUT;
    loop {
        match fs::read_to_string(identity_path) {
            Ok(record) => return parse_published_process_identity(&record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("read parent-death identity: {error}")),
        }
        if let Some(status) = supervisor
            .try_wait()
            .map_err(|error| format!("poll parent-death supervisor: {error}"))?
        {
            return Err(format!(
                "parent-death supervisor exited before publishing child identity: {status}"
            ));
        }
        if Instant::now() >= deadline {
            return Err(
                "parent-death supervisor did not publish child identity in time".to_owned(),
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn run_parent_death_helper_inner() -> Result<(), String> {
    require_authority()?;
    if env::var(PARENT_DEATH_HELPER_ENV).as_deref() != Ok("1") {
        return Err("parent-death helper authority is unavailable".to_owned());
    }
    let probe = probe_path()?;
    let config = PathBuf::from(required_env("FLUX_ENGINE_CREDENTIAL_CONFIG")?);
    let report = PathBuf::from(required_env("FLUX_ENGINE_CREDENTIAL_REPORT")?);
    let log = PathBuf::from(required_env("FLUX_ENGINE_CREDENTIAL_LOG")?);
    let identity_path = PathBuf::from(required_env("FLUX_ENGINE_CREDENTIAL_IDENTITY")?);
    let identity_temporary_path =
        PathBuf::from(required_env("FLUX_ENGINE_CREDENTIAL_IDENTITY_TMP")?);
    let listener_port = canonical_u16(
        &required_env("FLUX_ENGINE_CREDENTIAL_PORT")?,
        "parent-death listener port",
    )?;
    let listener_port = NonZeroU16::new(listener_port)
        .ok_or_else(|| "parent-death listener port must be nonzero".to_owned())?;
    let expected = credentials(0, 0)?;
    let root = probe
        .parent()
        .ok_or_else(|| "credential probe has no parent directory".to_owned())?;
    let paths = ProbeCasePaths {
        config,
        report,
        log,
    };
    let pinned = pin_probe(&probe, &paths.config)?;
    let spec = launch_spec(root, &probe, &paths, expected, listener_port);
    let adapter = SingBoxProcessAdapter;
    let mut child = adapter
        .spawn_pinned(&pinned, &spec)
        .map_err(|error| format!("spawn parent-death credential probe: {error}"))?;
    adapter
        .wait_ready(&mut child, &spec)
        .map_err(|error| format!("wait for parent-death credential probe: {error}"))?;
    let handle = child
        .open_process_handle()
        .map_err(|error| format!("open parent-death process handle: {error}"))?;
    validate_engine_process_credentials(handle.credentials(), expected)?;
    read_report(&paths.report)?.validate_for(expected)?;
    write_new_file(
        &identity_temporary_path,
        format!(
            "{}:{}\n",
            child.identity().pid(),
            child.identity().start_time_ticks()
        )
        .as_bytes(),
    )?;
    fs::rename(&identity_temporary_path, &identity_path)
        .map_err(|error| format!("publish parent-death identity atomically: {error}"))?;
    loop {
        std::hint::black_box((&child, &handle));
        thread::sleep(Duration::from_secs(1));
    }
}

fn pin_probe(probe: &Path, config: &Path) -> Result<PinnedSingBoxLaunch, String> {
    let binary = open_no_follow(probe)?;
    let config = open_no_follow(config)?;
    PinnedSingBoxLaunch::new(binary, config)
        .map_err(|error| format!("pin exact credential-probe artifacts: {error}"))
}

fn open_no_follow(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open exact credential-probe artifact: {error}"))
}

fn launch_spec(
    root: &Path,
    probe: &Path,
    paths: &ProbeCasePaths,
    credentials: EngineCredentials,
    listener_port: NonZeroU16,
) -> SingBoxLaunchSpec {
    SingBoxLaunchSpec {
        binary: probe.to_owned(),
        config: paths.config.clone(),
        working_directory: root.to_owned(),
        log: paths.log.clone(),
        privilege: SingBoxPrivilege::transparent_proxy(credentials),
        readiness: SingBoxReadiness::Listener {
            port: listener_port,
        },
        startup_timeout: STARTUP_TIMEOUT,
        stop_timeout: STOP_TIMEOUT,
    }
}

fn reserve_listener_port() -> Result<NonZeroU16, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("reserve credential-probe listener port: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("read reserved listener port: {error}"))?
        .port();
    NonZeroU16::new(port).ok_or_else(|| "reserved listener port is zero".to_owned())
}

fn write_config(
    path: &Path,
    credentials: EngineCredentials,
    listener_port: NonZeroU16,
    report_path: &Path,
) -> Result<(), String> {
    let report_name = report_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "credential report name is not canonical UTF-8".to_owned())?;
    let config = EngineCredentialProbeConfig::new(
        credentials,
        listener_port,
        NonZeroU32::new(SOCKET_MARK).expect("credential-probe socket mark is nonzero"),
        report_name,
    )?;
    write_new_file(path, config.render().as_bytes())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("create exact credential-probe file: {error}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write exact credential-probe file: {error}"))
}

fn read_report(path: &Path) -> Result<EngineCredentialProbeReport, String> {
    let bytes = fs::read(path).map_err(|error| format!("read credential-probe report: {error}"))?;
    EngineCredentialProbeReport::parse(&bytes)
}

fn canonical_u16(value: &str, field: &str) -> Result<u16, String> {
    if !canonical_decimal(value) {
        return Err(format!("{field} is not canonical decimal"));
    }
    value.parse().map_err(|_| format!("{field} exceeds u16"))
}

fn canonical_u32(value: &str, field: &str) -> Result<u32, String> {
    if !canonical_decimal(value) {
        return Err(format!("{field} is not canonical decimal"));
    }
    value.parse().map_err(|_| format!("{field} exceeds u32"))
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && (value == "0" || !value.starts_with('0'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

#[derive(Clone, Debug)]
struct ProbeCasePaths {
    config: PathBuf,
    report: PathBuf,
    log: PathBuf,
}

impl ProbeCasePaths {
    fn new(root: &Path, label: &str) -> Self {
        Self {
            config: root.join(format!("credential-{label}-config")),
            report: root.join(format!("credential-{label}-report")),
            log: root.join(format!("credential-{label}-log")),
        }
    }

    fn all(&self) -> Vec<PathBuf> {
        vec![self.config.clone(), self.report.clone(), self.log.clone()]
    }
}

struct FileCleanup {
    paths: Vec<PathBuf>,
}

impl FileCleanup {
    fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }
}

impl Drop for FileCleanup {
    fn drop(&mut self) {
        for path in &self.paths {
            let _ = fs::remove_file(path);
        }
    }
}

fn remove_files(paths: &[PathBuf]) -> Result<(), String> {
    let mut failures = Vec::new();
    for path in paths {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "remove exact credential-probe file {}: {error}",
                path.display()
            )),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
