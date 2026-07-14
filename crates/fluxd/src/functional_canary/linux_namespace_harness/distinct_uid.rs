//! Credential-only preflight for the future local-OUTPUT functional-canary executor.
//!
//! This checkpoint creates no capture rules and sends no traffic. It proves only that a
//! disposable user/mount/network namespace can map an owner identity plus two distinct nonzero
//! probe/engine identities, can execute children under those exact credentials, and can retain
//! exact child-origin process handles through live reobservation and parent-confirmed reap.

use super::*;
use flux_platform::{ProcessHandle, ProcessHandleError, ProcessHandleErrorKind};
use std::fmt;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const TEST_NAME: &str = "functional_canary::linux_namespace_harness::privileged_local_output_distinct_uid_capability_preflight";
const MODE_PREFLIGHT: &str = "distinct-uid-preflight";
const MODE_ROLE: &str = "distinct-uid-role";
const MODE_PROCESS_HANDLE_PROBE: &str = "distinct-uid-process-handle-probe";
const OUTER_MOUNTNS_ENV: &str = "FLUX_LINUX_CANARY_OUTER_MOUNTNS";
const EXPECTED_UID_MAP_ENV: &str = "FLUX_LINUX_CANARY_EXPECTED_UID_MAP";
const EXPECTED_GID_MAP_ENV: &str = "FLUX_LINUX_CANARY_EXPECTED_GID_MAP";
const MAPPING_MECHANISM_ENV: &str = "FLUX_LINUX_CANARY_MAPPING_MECHANISM";
const ROLE_UID_ENV: &str = "FLUX_LINUX_CANARY_ROLE_UID";
const ROLE_GID_ENV: &str = "FLUX_LINUX_CANARY_ROLE_GID";
const OUTER_SUPPLEMENTARY_GROUPS_ENV: &str = "FLUX_LINUX_CANARY_OUTER_SUPPLEMENTARY_GROUPS";
const INNER_NETNS_ENV: &str = "FLUX_LINUX_CANARY_INNER_NETNS";
const INNER_USERNS_ENV: &str = "FLUX_LINUX_CANARY_INNER_USERNS";
const INNER_MOUNTNS_ENV: &str = "FLUX_LINUX_CANARY_INNER_MOUNTNS";
const SUBORDINATE_ID_FILE_LIMIT: usize = 1024 * 1024;
const PROBE_UID: u32 = 20_001;
const PROBE_GID: u32 = 20_001;
const ENGINE_UID: u32 = 20_002;
const ENGINE_GID: u32 = 20_002;

pub(super) fn run() {
    let result = match env::var(MODE_ENV).as_deref() {
        Err(env::VarError::NotPresent) => run_outer(),
        Ok(MODE_PREFLIGHT) => run_preflight(),
        Ok(MODE_ROLE) => run_role(),
        Ok(MODE_PROCESS_HANDLE_PROBE) => run_process_handle_probe_child(),
        Ok(other) => Err(format!("unsupported {MODE_ENV} value {other:?}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{MODE_ENV} must contain valid UTF-8")),
    };
    if let Err(error) = result {
        panic!("Linux distinct-UID capability preflight failed: {error}");
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UnavailableKind {
    Unsupported,
    Denied,
    Broken,
    Conflicting,
}

impl fmt::Display for UnavailableKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => formatter.write_str("unsupported"),
            Self::Denied => formatter.write_str("denied"),
            Self::Broken => formatter.write_str("broken"),
            Self::Conflicting => formatter.write_str("conflicting"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PreflightUnavailable {
    kind: UnavailableKind,
    detail: String,
}

impl PreflightUnavailable {
    fn new(kind: UnavailableKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for PreflightUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "distinct-UID credential mechanism {}: {}",
            self.kind, self.detail
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Credential {
    uid: u32,
    gid: u32,
}

const PROBE_CREDENTIAL: Credential = Credential {
    uid: PROBE_UID,
    gid: PROBE_GID,
};
const ENGINE_CREDENTIAL: Credential = Credential {
    uid: ENGINE_UID,
    gid: ENGINE_GID,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IdMapEntry {
    inside: u64,
    outside: u64,
    length: u64,
}

impl IdMapEntry {
    const fn new(inside: u64, outside: u64, length: u64) -> Self {
        Self {
            inside,
            outside,
            length,
        }
    }

    fn contains_inside(self, id: u32) -> bool {
        let id = u64::from(id);
        id >= self.inside && id < self.inside.saturating_add(self.length)
    }

    fn contains_inside_range(self, start: u32, length: u32) -> bool {
        let start = u64::from(start);
        let end = start.saturating_add(u64::from(length));
        start >= self.inside && end <= self.inside.saturating_add(self.length)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MappingMechanism {
    DelegatedRootDirect,
    SubordinateHelpers,
}

impl MappingMechanism {
    const fn label(self) -> &'static str {
        match self {
            Self::DelegatedRootDirect => "delegated-root-direct",
            Self::SubordinateHelpers => "subordinate-helpers",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CredentialPlan {
    mechanism: MappingMechanism,
    unshare: PathBuf,
    availability_program: PathBuf,
    trusted_path: OsString,
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
    outer_had_supplementary_groups: bool,
}

impl CredentialPlan {
    fn new(
        mechanism: MappingMechanism,
        unshare: PathBuf,
        availability_program: PathBuf,
        trusted_path: OsString,
        mut uid_map: Vec<IdMapEntry>,
        mut gid_map: Vec<IdMapEntry>,
        outer_had_supplementary_groups: bool,
    ) -> Result<Self, PreflightUnavailable> {
        canonicalize_id_map(&mut uid_map);
        canonicalize_id_map(&mut gid_map);
        validate_role_credentials(PROBE_CREDENTIAL, ENGINE_CREDENTIAL)?;
        validate_exact_role_map(&uid_map, "UID")?;
        validate_exact_role_map(&gid_map, "GID")?;
        require_mapped_role(&uid_map, PROBE_UID, "probe UID")?;
        require_mapped_role(&uid_map, ENGINE_UID, "engine UID")?;
        require_mapped_role(&gid_map, PROBE_GID, "probe GID")?;
        require_mapped_role(&gid_map, ENGINE_GID, "engine GID")?;
        Ok(Self {
            mechanism,
            unshare,
            availability_program,
            trusted_path,
            uid_map,
            gid_map,
            outer_had_supplementary_groups,
        })
    }

    fn mapping_arguments(&self) -> Vec<String> {
        let mut arguments = vec!["--user".to_owned()];
        for entry in &self.uid_map {
            arguments.push(format!(
                "--map-users={},{},{}",
                entry.outside, entry.inside, entry.length
            ));
        }
        for entry in &self.gid_map {
            arguments.push(format!(
                "--map-groups={},{},{}",
                entry.outside, entry.inside, entry.length
            ));
        }
        arguments.extend(["--mount".to_owned(), "--net".to_owned(), "--".to_owned()]);
        arguments
    }
}

fn run_outer() -> Result<(), String> {
    let required = required_mode()?;
    let plan = match build_credential_plan() {
        Ok(plan) => plan,
        Err(unavailable) => return skip_or_fail(required, unavailable.to_string()),
    };
    if let Err(reason) = run_mapping_availability_probe(&plan) {
        return skip_or_fail(
            required,
            PreflightUnavailable::new(
                UnavailableKind::Denied,
                format!("disposable exact-map availability probe failed: {reason}"),
            )
            .to_string(),
        );
    }
    match run_process_handle_availability_probe() {
        Ok(()) => {}
        Err(ProcessHandleProbeFailure::Unavailable(reason)) => {
            return skip_or_fail(required, reason);
        }
        Err(ProcessHandleProbeFailure::Hard(reason)) => return Err(reason),
    }
    run_outer_reentry(&plan)
}

#[derive(Debug)]
enum ProcessHandleProbeFailure {
    Unavailable(String),
    Hard(String),
}

fn run_process_handle_availability_probe() -> Result<(), ProcessHandleProbeFailure> {
    let executable = env::current_exe().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!("resolve process-handle probe executable: {error}"))
    })?;
    let handshake_directory = tempfile::tempdir().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!(
            "create process-handle probe handshake directory: {error}"
        ))
    })?;
    let ready_path = handshake_directory.path().join("ready");
    let release_path = handshake_directory.path().join("release");
    let mut command = Command::new(executable);
    command
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_PROCESS_HANDLE_PROBE)
        .env(CONFIG_ENV, handshake_directory.path());
    let description = format_command(&command);
    command.process_group(0);
    arm_parent_death_signal(&mut command).map_err(ProcessHandleProbeFailure::Hard)?;
    let mut stdout_file = tempfile::tempfile().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!("create stdout capture for {description}: {error}"))
    })?;
    let mut stderr_file = tempfile::tempfile().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!("create stderr capture for {description}: {error}"))
    })?;
    let stdout_sink = stdout_file.try_clone().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!("clone stdout capture for {description}: {error}"))
    })?;
    let stderr_sink = stderr_file.try_clone().map_err(|error| {
        ProcessHandleProbeFailure::Hard(format!("clone stderr capture for {description}: {error}"))
    })?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_sink))
        .stderr(Stdio::from(stderr_sink))
        .spawn()
        .map_err(|error| {
            ProcessHandleProbeFailure::Hard(format!("spawn {description}: {error}"))
        })?;

    let execution = (|| {
        let expected_ready = format!("ready:process-handle-probe:{}\n", child.id());
        wait_for_role_signal(
            &ready_path,
            &expected_ready,
            &mut child,
            COMMAND_TIMEOUT,
            "process-handle probe readiness",
        )
        .map_err(ProcessHandleProbeFailure::Hard)?;
        let handle =
            ProcessHandle::open_child(&child).map_err(classify_process_handle_open_error)?;
        let initial_identity = handle.identity();
        let reobserved = handle.reobserve().map_err(|error| {
            ProcessHandleProbeFailure::Hard(format!(
                "reobserve live process-handle probe child: {error}"
            ))
        })?;
        if reobserved.identity() != initial_identity
            || reobserved.credentials() != handle.credentials()
        {
            return Err(ProcessHandleProbeFailure::Hard(format!(
                "process-handle probe drifted while live: opened={handle:?} reobserved={reobserved:?}"
            )));
        }
        write_role_signal(&release_path, "release:process-handle-probe\n")
            .map_err(ProcessHandleProbeFailure::Hard)?;
        // The pidfd is observation authority only. Parent-owned Child polling
        // performs and proves the reap before the exited pidfd is consulted.
        let status = wait_child(&mut child, COMMAND_TIMEOUT).map_err(|error| {
            ProcessHandleProbeFailure::Hard(format!("reap process-handle probe child: {error}"))
        })?;
        let exit_error = handle.reobserve().expect_err(
            "a reaped process-handle probe child must report exit through its retained pidfd",
        );
        if exit_error.kind() != ProcessHandleErrorKind::Exited {
            return Err(ProcessHandleProbeFailure::Hard(format!(
                "process-handle probe did not report exit after parent reap: {exit_error}"
            )));
        }
        if !status.success() {
            return Err(ProcessHandleProbeFailure::Hard(format!(
                "process-handle probe child exited with {status}"
            )));
        }
        Ok(())
    })();

    if let Err(error) = execution {
        let kill_error = kill_live_child_group(&mut child).err();
        let reap_error = wait_child(&mut child, COMMAND_TIMEOUT).err();
        let stdout = read_command_capture(&mut stdout_file, &description, "stdout").unwrap_or_else(
            |capture_error| format!("capture failed: {capture_error}").into_bytes(),
        );
        let stderr = read_command_capture(&mut stderr_file, &description, "stderr").unwrap_or_else(
            |capture_error| format!("capture failed: {capture_error}").into_bytes(),
        );
        if kill_error.is_some() || reap_error.is_some() {
            return Err(ProcessHandleProbeFailure::Hard(format!(
                "process-handle availability probe failed with {error:?}; cleanup failed: kill_error={kill_error:?} reap_error={reap_error:?}; stdout={} stderr={}",
                bounded_diagnostic(&stdout),
                bounded_diagnostic(&stderr)
            )));
        }
        return match error {
            ProcessHandleProbeFailure::Unavailable(reason) => {
                Err(ProcessHandleProbeFailure::Unavailable(format!(
                    "{reason}; probe child was killed and reaped; stdout={} stderr={}",
                    bounded_diagnostic(&stdout),
                    bounded_diagnostic(&stderr)
                )))
            }
            ProcessHandleProbeFailure::Hard(reason) => {
                Err(ProcessHandleProbeFailure::Hard(format!(
                    "{reason}; stdout={} stderr={}",
                    bounded_diagnostic(&stdout),
                    bounded_diagnostic(&stderr)
                )))
            }
        };
    }
    Ok(())
}

fn classify_process_handle_open_error(error: ProcessHandleError) -> ProcessHandleProbeFailure {
    match error {
        ProcessHandleError::UnsupportedPlatform(platform) => {
            ProcessHandleProbeFailure::Unavailable(
                PreflightUnavailable::new(
                    UnavailableKind::Unsupported,
                    format!("process handles are unsupported on {platform}"),
                )
                .to_string(),
            )
        }
        ProcessHandleError::PidFdUnsupported { source } => ProcessHandleProbeFailure::Unavailable(
            PreflightUnavailable::new(
                UnavailableKind::Unsupported,
                format!("pidfd_open is unavailable: {source}"),
            )
            .to_string(),
        ),
        ProcessHandleError::SystemCall {
            operation,
            path,
            source,
        } if source.kind() == std::io::ErrorKind::PermissionDenied
            || matches!(
                source.raw_os_error(),
                Some(libc::EACCES) | Some(libc::EPERM)
            ) =>
        {
            ProcessHandleProbeFailure::Unavailable(
                PreflightUnavailable::new(
                    UnavailableKind::Denied,
                    format!(
                        "process-handle acquisition was denied during {operation}{}: {source}",
                        path.as_ref()
                            .map_or_else(String::new, |path| format!(" {}", path.display()))
                    ),
                )
                .to_string(),
            )
        }
        error => ProcessHandleProbeFailure::Hard(format!(
            "process-handle availability probe produced invalid evidence: {error}"
        )),
    }
}

fn run_process_handle_probe_child() -> Result<(), String> {
    let handshake_directory = required_path_environment(CONFIG_ENV)?;
    let ready_path = handshake_directory.join("ready");
    let release_path = handshake_directory.join("release");
    write_role_signal(
        &ready_path,
        &format!("ready:process-handle-probe:{}\n", std::process::id()),
    )?;
    wait_for_role_release(
        &release_path,
        "release:process-handle-probe\n",
        PROCESS_TIMEOUT,
    )
}

fn build_credential_plan() -> Result<CredentialPlan, PreflightUnavailable> {
    let status = read_process_credentials("/proc/self/status")?;
    if status.uids.iter().any(|uid| *uid != status.uids[0])
        || status.gids.iter().any(|gid| *gid != status.gids[0])
    {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            format!(
                "outer real/effective/saved/filesystem credentials differ: Uid={:?} Gid={:?}",
                status.uids, status.gids
            ),
        ));
    }
    if status.uids[0] == u32::MAX
        || status.gids[0] == u32::MAX
        || status.uids[0] == 65_534
        || status.gids[0] == 65_534
    {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Unsupported,
            "outer owner is an unmapped/overflow credential",
        ));
    }
    let outer_had_supplementary_groups = !status.groups.is_empty();
    let outer_setgroups = fs::read_to_string("/proc/self/setgroups").map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Denied,
            format!("read outer /proc/self/setgroups: {error}"),
        )
    })?;
    match outer_setgroups.trim() {
        "allow" => {}
        "deny" if outer_had_supplementary_groups => {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Denied,
                format!(
                    "outer setgroups is denied while supplementary groups are inherited: {:?}",
                    status.groups
                ),
            ));
        }
        "deny" => {}
        other => {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("unsupported outer /proc/self/setgroups state {other:?}"),
            ));
        }
    }

    let unshare = resolve_trusted_executable("unshare")?;
    let availability_program = resolve_trusted_executable("true")?;
    let parent_uid_map = read_id_map("/proc/self/uid_map")?;
    let parent_gid_map = read_id_map("/proc/self/gid_map")?;
    let root_direct = status.uids[0] == 0 && status.gids[0] == 0;
    if root_direct
        && (!is_full_identity_map(&parent_uid_map) || !is_full_identity_map(&parent_gid_map))
    {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Unsupported,
            "effective root is itself confined by a non-full parent user-namespace map; it cannot create the exact delegated child identities",
        ));
    }
    let credential_helpers = if root_direct {
        Vec::new()
    } else {
        vec![
            resolve_trusted_executable("newuidmap")?,
            resolve_trusted_executable("newgidmap")?,
        ]
    };
    let mut trusted_executables = vec![unshare.clone(), availability_program.clone()];
    trusted_executables.extend(credential_helpers);
    let trusted_path = trusted_executable_path(&trusted_executables)?;

    let uid_owner = status.uids[0];
    let gid_owner = status.gids[0];
    let username = passwd_username(uid_owner)?;
    let uid_range = subordinate_range(
        Path::new("/etc/subuid"),
        uid_owner,
        username.as_deref(),
        &parent_uid_map,
        "UID",
    )?;
    let gid_range = subordinate_range(
        Path::new("/etc/subgid"),
        uid_owner,
        username.as_deref(),
        &parent_gid_map,
        "GID",
    )?;
    if uid_range.start == uid_owner || uid_range.start.saturating_add(1) == uid_owner {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            "selected subordinate UID identities overlap the outer owner UID",
        ));
    }
    if gid_range.start == gid_owner || gid_range.start.saturating_add(1) == gid_owner {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            "selected subordinate GID identities overlap the outer owner GID",
        ));
    }

    CredentialPlan::new(
        if root_direct {
            MappingMechanism::DelegatedRootDirect
        } else {
            MappingMechanism::SubordinateHelpers
        },
        unshare,
        availability_program,
        trusted_path,
        vec![
            IdMapEntry::new(0, u64::from(uid_owner), 1),
            IdMapEntry::new(u64::from(PROBE_UID), u64::from(uid_range.start), 1),
            IdMapEntry::new(
                u64::from(ENGINE_UID),
                u64::from(uid_range.start.saturating_add(1)),
                1,
            ),
        ],
        vec![
            IdMapEntry::new(0, u64::from(gid_owner), 1),
            IdMapEntry::new(u64::from(PROBE_GID), u64::from(gid_range.start), 1),
            IdMapEntry::new(
                u64::from(ENGINE_GID),
                u64::from(gid_range.start.saturating_add(1)),
                1,
            ),
        ],
        outer_had_supplementary_groups,
    )
}

fn run_mapping_availability_probe(plan: &CredentialPlan) -> Result<(), String> {
    let mut command = Command::new(&plan.unshare);
    command
        .args(plan.mapping_arguments())
        .arg(&plan.availability_program)
        .env("PATH", &plan.trusted_path);
    checked_command(command, COMMAND_TIMEOUT).map(|_| ())
}

fn run_outer_reentry(plan: &CredentialPlan) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let reentry_token = random_nonce()?;
    let outer_netns = network_namespace_identity()?;
    let outer_userns = user_namespace_identity()?;
    let outer_mountns = mount_namespace_identity()?;
    let mut command = Command::new(&plan.unshare);
    command
        .args(plan.mapping_arguments())
        .arg(executable)
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_PREFLIGHT)
        .env("PATH", &plan.trusted_path)
        .env(REENTRY_TOKEN_ENV, reentry_token)
        .env(OUTER_NETNS_ENV, outer_netns)
        .env(OUTER_USERNS_ENV, outer_userns)
        .env(OUTER_MOUNTNS_ENV, outer_mountns)
        .env(EXPECTED_UID_MAP_ENV, render_id_map(&plan.uid_map))
        .env(EXPECTED_GID_MAP_ENV, render_id_map(&plan.gid_map))
        .env(MAPPING_MECHANISM_ENV, plan.mechanism.label())
        .env(
            OUTER_SUPPLEMENTARY_GROUPS_ENV,
            if plan.outer_had_supplementary_groups {
                "1"
            } else {
                "0"
            },
        );
    checked_command(command, PROCESS_TIMEOUT).map(|_| ())
}

fn run_preflight() -> Result<(), String> {
    let mechanism = validate_mapped_controller()?;
    for (role, credential) in [("probe", PROBE_CREDENTIAL), ("engine", ENGINE_CREDENTIAL)] {
        run_role_child(role, credential)?;
    }
    eprintln!(
        "PREFLIGHT PASS: {mechanism} produced exact nonzero probe UID/GID {PROBE_UID}/{PROBE_GID} and engine UID/GID {ENGINE_UID}/{ENGINE_GID}, with exact parent-owned PID/start-tick/process-handle reobservation and parent-confirmed reap; credential/process-handle capability only, no local-OUTPUT traffic qualification"
    );
    Ok(())
}

fn validate_mapped_controller() -> Result<String, String> {
    clear_supplementary_groups()?;
    validate_reentry_boundary()?;
    let expected_uid_map = expected_map_from_environment(EXPECTED_UID_MAP_ENV)?;
    let expected_gid_map = expected_map_from_environment(EXPECTED_GID_MAP_ENV)?;
    validate_exact_role_map(&expected_uid_map, "UID").map_err(|error| error.to_string())?;
    validate_exact_role_map(&expected_gid_map, "GID").map_err(|error| error.to_string())?;
    validate_role_credentials(PROBE_CREDENTIAL, ENGINE_CREDENTIAL)
        .map_err(|error| error.to_string())?;
    require_mapped_role(&expected_uid_map, PROBE_UID, "probe UID")
        .map_err(|error| error.to_string())?;
    require_mapped_role(&expected_uid_map, ENGINE_UID, "engine UID")
        .map_err(|error| error.to_string())?;
    require_mapped_role(&expected_gid_map, PROBE_GID, "probe GID")
        .map_err(|error| error.to_string())?;
    require_mapped_role(&expected_gid_map, ENGINE_GID, "engine GID")
        .map_err(|error| error.to_string())?;

    let observed_uid_map = read_id_map("/proc/self/uid_map").map_err(|error| error.to_string())?;
    let observed_gid_map = read_id_map("/proc/self/gid_map").map_err(|error| error.to_string())?;
    if observed_uid_map != expected_uid_map || observed_gid_map != expected_gid_map {
        return Err(format!(
            "credential-map readback mismatch: expected_uid={} observed_uid={} expected_gid={} observed_gid={}",
            render_id_map(&expected_uid_map),
            render_id_map(&observed_uid_map),
            render_id_map(&expected_gid_map),
            render_id_map(&observed_gid_map),
        ));
    }
    let owner = read_process_credentials("/proc/self/status").map_err(|error| error.to_string())?;
    if owner.uids != [0; 4] || owner.gids != [0; 4] || !owner.groups.is_empty() {
        return Err(format!(
            "mapped owner must begin as root with no supplementary groups: Uid={:?} Gid={:?} Groups={:?}",
            owner.uids, owner.gids, owner.groups
        ));
    }

    let mechanism = env::var(MAPPING_MECHANISM_ENV)
        .map_err(|_| format!("{MAPPING_MECHANISM_ENV} is required"))?;
    if mechanism != MappingMechanism::DelegatedRootDirect.label()
        && mechanism != MappingMechanism::SubordinateHelpers.label()
    {
        return Err(format!(
            "unsupported {MAPPING_MECHANISM_ENV} value {mechanism:?}"
        ));
    }
    Ok(mechanism)
}

fn run_role_child(role: &str, credential: Credential) -> Result<(), String> {
    let executable =
        env::current_exe().map_err(|error| format!("resolve test executable: {error}"))?;
    let handshake_directory = tempfile::tempdir()
        .map_err(|error| format!("create {role} role handshake directory: {error}"))?;
    let ready_path = handshake_directory.path().join("ready");
    let release_path = handshake_directory.path().join("release");
    let mut release_file = create_role_handshake_files(
        handshake_directory.path(),
        &ready_path,
        &release_path,
        credential,
    )?;
    fs::set_permissions(
        handshake_directory.path(),
        fs::Permissions::from_mode(0o711),
    )
    .map_err(|error| format!("make {role} role handshake directory accessible: {error}"))?;
    let mut command = Command::new(executable);
    command
        .args([
            "--ignored",
            "--exact",
            TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(MODE_ENV, MODE_ROLE)
        .env(ROLE_UID_ENV, credential.uid.to_string())
        .env(ROLE_GID_ENV, credential.gid.to_string())
        .env(CONFIG_ENV, handshake_directory.path())
        .env(INNER_NETNS_ENV, network_namespace_identity()?)
        .env(INNER_USERNS_ENV, user_namespace_identity()?)
        .env(INNER_MOUNTNS_ENV, mount_namespace_identity()?)
        .uid(credential.uid)
        .gid(credential.gid);
    let description = format_command(&command);
    command.process_group(0);
    arm_parent_death_signal(&mut command)?;
    let mut stdout_file = tempfile::tempfile()
        .map_err(|error| format!("create stdout capture for {description}: {error}"))?;
    let mut stderr_file = tempfile::tempfile()
        .map_err(|error| format!("create stderr capture for {description}: {error}"))?;
    let stdout_sink = stdout_file
        .try_clone()
        .map_err(|error| format!("clone stdout capture for {description}: {error}"))?;
    let stderr_sink = stderr_file
        .try_clone()
        .map_err(|error| format!("clone stderr capture for {description}: {error}"))?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_sink))
        .stderr(Stdio::from(stderr_sink))
        .spawn()
        .map_err(|error| format!("spawn {description}: {error}"))?;

    let execution = (|| {
        let expected_ready = format!(
            "ready:{role}:{}:{}:{}\n",
            child.id(),
            credential.uid,
            credential.gid
        );
        wait_for_role_signal(
            &ready_path,
            &expected_ready,
            &mut child,
            COMMAND_TIMEOUT,
            &format!("{role} readiness"),
        )?;

        let handle = ProcessHandle::open_child(&child)
            .map_err(|error| format!("open exact {role} role process handle: {error}"))?;
        let proc_identity = capture_process_identity(child.id())?;
        let handle_identity = handle.identity();
        if handle_identity.pid().get() != child.id()
            || handle_identity.pid().get() != proc_identity.pid
            || handle_identity.start_time_ticks().get() != proc_identity.start_ticks
        {
            return Err(format!(
                "{role} role process-handle identity mismatch: child_pid={} proc_identity={proc_identity:?} handle_identity={handle_identity:?}",
                child.id()
            ));
        }
        validate_handle_credentials(role, credential, handle.credentials())?;
        let reobserved = handle
            .reobserve()
            .map_err(|error| format!("reobserve live {role} role process handle: {error}"))?;
        if reobserved.identity() != handle_identity
            || reobserved.credentials() != handle.credentials()
        {
            return Err(format!(
                "{role} role process handle drifted while the child waited: opened={handle:?} reobserved={reobserved:?}"
            ));
        }
        validate_handle_credentials(role, credential, reobserved.credentials())?;

        publish_role_signal(
            &mut release_file,
            &release_path,
            &format!("release:{role}\n"),
        )?;
        // The retained Child, not pidfd readability, is the reaping authority.
        let status = wait_child(&mut child, COMMAND_TIMEOUT)?;
        let exit_error = handle
            .reobserve()
            .expect_err("a reaped role child must report exit through its retained pidfd");
        if exit_error.kind() != ProcessHandleErrorKind::Exited {
            return Err(format!(
                "{role} role process handle did not report exit after parent reap: {exit_error}"
            ));
        }
        if !status.success() {
            return Err(format!("{role} role child exited with {status}"));
        }
        Ok(())
    })();

    if let Err(error) = execution {
        let kill_error = kill_live_child_group(&mut child).err();
        let reap_error = wait_child(&mut child, COMMAND_TIMEOUT).err();
        let stdout = read_command_capture(&mut stdout_file, &description, "stdout")?;
        let stderr = read_command_capture(&mut stderr_file, &description, "stderr")?;
        return Err(format!(
            "execute {role} credential role: {error}; kill_error={kill_error:?}; reap_error={reap_error:?}; stdout={} stderr={}",
            bounded_diagnostic(&stdout),
            bounded_diagnostic(&stderr)
        ));
    }
    Ok(())
}

fn validate_handle_credentials(
    role: &str,
    expected: Credential,
    observed: &flux_platform::ProcessCredentials,
) -> Result<(), String> {
    if observed.uids() != &[expected.uid; 4]
        || observed.gids() != &[expected.gid; 4]
        || !observed.supplementary_groups().is_empty()
        || observed.capability_inheritable() != 0
        || observed.capability_permitted() != 0
        || observed.capability_effective() != 0
        || observed.capability_ambient() != 0
        || !observed.no_new_privileges()
    {
        return Err(format!(
            "{role} role process-handle credential mismatch: expected_uid={} expected_gid={} observed={observed:?}",
            expected.uid, expected.gid
        ));
    }
    Ok(())
}

fn run_role() -> Result<(), String> {
    set_no_new_privileges()?;
    validate_reentry_boundary()?;
    for (label, variable, observed) in [
        ("network", INNER_NETNS_ENV, network_namespace_identity()?),
        ("user", INNER_USERNS_ENV, user_namespace_identity()?),
        ("mount", INNER_MOUNTNS_ENV, mount_namespace_identity()?),
    ] {
        let expected = env::var(variable).map_err(|_| format!("{variable} is required"))?;
        if observed != expected {
            return Err(format!(
                "{label} namespace changed before role execution: expected={expected} observed={observed}"
            ));
        }
    }
    let uid = required_u32_environment(ROLE_UID_ENV)?;
    let gid = required_u32_environment(ROLE_GID_ENV)?;
    let credential = Credential { uid, gid };
    if credential != PROBE_CREDENTIAL && credential != ENGINE_CREDENTIAL {
        return Err(format!(
            "role credential {uid}/{gid} is not the fixed probe or engine identity"
        ));
    }
    let status =
        read_process_credentials("/proc/self/status").map_err(|error| error.to_string())?;
    if status.uids != [uid; 4] || status.gids != [gid; 4] || !status.groups.is_empty() {
        return Err(format!(
            "credential transition mismatch for {uid}/{gid}: Uid={:?} Gid={:?} Groups={:?}",
            status.uids, status.gids, status.groups
        ));
    }
    if status.cap_inheritable != 0
        || status.cap_permitted != 0
        || status.cap_effective != 0
        || status.cap_ambient != 0
        || !status.no_new_privileges
    {
        return Err(format!(
            "role retained privilege after credential transition: CapInh={:x} CapPrm={:x} CapEff={:x} CapAmb={:x} NoNewPrivs={}",
            status.cap_inheritable,
            status.cap_permitted,
            status.cap_effective,
            status.cap_ambient,
            u8::from(status.no_new_privileges),
        ));
    }
    let uid_map = expected_map_from_environment(EXPECTED_UID_MAP_ENV)?;
    let gid_map = expected_map_from_environment(EXPECTED_GID_MAP_ENV)?;
    validate_exact_role_map(&uid_map, "UID").map_err(|error| error.to_string())?;
    validate_exact_role_map(&gid_map, "GID").map_err(|error| error.to_string())?;
    let observed_uid_map = read_id_map("/proc/self/uid_map").map_err(|error| error.to_string())?;
    let observed_gid_map = read_id_map("/proc/self/gid_map").map_err(|error| error.to_string())?;
    if observed_uid_map != uid_map || observed_gid_map != gid_map {
        return Err(format!(
            "role observed different credential maps: expected_uid={} observed_uid={} expected_gid={} observed_gid={}",
            render_id_map(&uid_map),
            render_id_map(&observed_uid_map),
            render_id_map(&gid_map),
            render_id_map(&observed_gid_map),
        ));
    }
    if !uid_map.iter().any(|entry| entry.contains_inside(uid))
        || !gid_map.iter().any(|entry| entry.contains_inside(gid))
    {
        return Err(format!(
            "credential transition {uid}/{gid} is not covered by the exact expected maps"
        ));
    }
    let (role, expected_credential) = match credential {
        PROBE_CREDENTIAL => ("probe", PROBE_CREDENTIAL),
        ENGINE_CREDENTIAL => ("engine", ENGINE_CREDENTIAL),
        _ => unreachable!("the fixed credential-role check above rejected unknown identities"),
    };
    if credential != expected_credential {
        return Err(format!(
            "credential role {role:?} expected {}/{}, observed {uid}/{gid}",
            expected_credential.uid, expected_credential.gid
        ));
    }
    let handshake_directory = required_path_environment(CONFIG_ENV)?;
    let ready_path = handshake_directory.join("ready");
    let release_path = handshake_directory.join("release");
    write_existing_role_signal(
        &ready_path,
        &format!("ready:{role}:{}:{uid}:{gid}\n", std::process::id()),
    )?;
    wait_for_role_release(&release_path, &format!("release:{role}\n"), PROCESS_TIMEOUT)?;
    Ok(())
}

fn required_path_environment(variable: &str) -> Result<PathBuf, String> {
    env::var_os(variable)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{variable} is required"))
}

fn write_role_signal(path: &Path, contents: &str) -> Result<(), String> {
    let pending = path.with_extension("pending");
    fs::write(&pending, contents)
        .map_err(|error| format!("write role handshake {}: {error}", pending.display()))?;
    fs::rename(&pending, path)
        .map_err(|error| format!("publish role handshake {}: {error}", path.display()))
}

fn create_role_handshake_files(
    directory: &Path,
    ready_path: &Path,
    release_path: &Path,
    credential: Credential,
) -> Result<File, String> {
    let ready_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(ready_path)
        .map_err(|error| format!("create role ready file {}: {error}", ready_path.display()))?;
    // SAFETY: the descriptor is owned by `ready_file`; the exact nonzero role
    // UID/GID are mapped in this disposable user namespace; fchown changes only
    // this newly created regular file and does not follow a path.
    if unsafe { libc::fchown(ready_file.as_raw_fd(), credential.uid, credential.gid) } != 0 {
        return Err(format!(
            "assign role ready file {} to {}/{}: {}",
            ready_path.display(),
            credential.uid,
            credential.gid,
            std::io::Error::last_os_error()
        ));
    }
    drop(ready_file);

    let release_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(release_path)
        .map_err(|error| {
            format!(
                "create parent-owned role release file {}: {error}",
                release_path.display()
            )
        })?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("inspect role handshake directory: {error}"))?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "role handshake path {} is not a directory",
            directory.display()
        ));
    }
    Ok(release_file)
}

fn write_existing_role_signal(path: &Path, contents: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("open existing role handshake {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("write role handshake {}: {error}", path.display()))?;
    file.sync_data()
        .map_err(|error| format!("sync role handshake {}: {error}", path.display()))
}

fn publish_role_signal(file: &mut File, path: &Path, contents: &str) -> Result<(), String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek role handshake {}: {error}", path.display()))?;
    file.set_len(0)
        .map_err(|error| format!("truncate role handshake {}: {error}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| format!("write role handshake {}: {error}", path.display()))?;
    file.sync_data()
        .map_err(|error| format!("sync role handshake {}: {error}", path.display()))
}

fn wait_for_role_signal(
    path: &Path,
    expected: &str,
    child: &mut Child,
    timeout: Duration,
    description: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(observed) if observed == expected => return Ok(()),
            Ok(observed) if expected.starts_with(&observed) => {}
            Ok(observed) => {
                return Err(format!(
                    "{description} signal mismatch at {}: expected={expected:?} observed={observed:?}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "read {description} signal {}: {error}",
                    path.display()
                ));
            }
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll child {} for {description}: {error}", child.id()))?
        {
            return Err(format!(
                "child {} exited with {status} before {description}",
                child.id()
            ));
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "child {} did not publish {description} within {timeout:?}",
                child.id()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_role_release(path: &Path, expected: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(observed) if observed == expected => return Ok(()),
            Ok(observed) if expected.starts_with(&observed) => {}
            Ok(observed) => {
                return Err(format!(
                    "role release signal mismatch at {}: expected={expected:?} observed={observed:?}",
                    path.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "read role release signal {}: {error}",
                    path.display()
                ));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "role release signal {} was not published within {timeout:?}",
                path.display()
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn validate_reentry_boundary() -> Result<(), String> {
    let reentry_token = env::var(REENTRY_TOKEN_ENV)
        .map_err(|_| format!("{MODE_PREFLIGHT} mode requires {REENTRY_TOKEN_ENV}"))?;
    if reentry_token.len() != 32 || !reentry_token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{REENTRY_TOKEN_ENV} is not a 128-bit hexadecimal token"
        ));
    }
    for (label, variable, observed) in [
        ("network", OUTER_NETNS_ENV, network_namespace_identity()?),
        ("user", OUTER_USERNS_ENV, user_namespace_identity()?),
        ("mount", OUTER_MOUNTNS_ENV, mount_namespace_identity()?),
    ] {
        let outer =
            env::var(variable).map_err(|_| format!("{MODE_PREFLIGHT} mode requires {variable}"))?;
        if observed == outer {
            return Err(format!(
                "distinct-UID preflight did not enter a new {label} namespace: {observed}"
            ));
        }
    }
    Ok(())
}

fn validate_role_credentials(
    probe: Credential,
    engine: Credential,
) -> Result<(), PreflightUnavailable> {
    if probe.uid == 0 || engine.uid == 0 {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            "probe and engine UIDs must both be nonzero",
        ));
    }
    if probe.uid == engine.uid {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            "probe and engine UIDs must be distinct",
        ));
    }
    if probe.gid == 0 || engine.gid == 0 || probe.gid == engine.gid {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            "probe and engine GIDs must be distinct and nonzero",
        ));
    }
    Ok(())
}

fn validate_exact_role_map(
    entries: &[IdMapEntry],
    label: &str,
) -> Result<(), PreflightUnavailable> {
    let expected_inside = [0, u64::from(PROBE_UID), u64::from(ENGINE_UID)];
    if entries.len() != 3
        || entries
            .iter()
            .zip(expected_inside)
            .any(|(entry, inside)| entry.inside != inside || entry.length != 1)
    {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!(
                "{label} map must contain exactly controller 0, probe {PROBE_UID}, and engine {ENGINE_UID} singleton entries"
            ),
        ));
    }
    if entries
        .iter()
        .any(|entry| entry.outside == u64::from(u32::MAX) || entry.outside == 65_534)
    {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{label} map contains an overflow/unmapped outside identity"),
        ));
    }
    let outside = entries
        .iter()
        .map(|entry| entry.outside)
        .collect::<BTreeSet<_>>();
    if outside.len() != entries.len() {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{label} map reuses an outside identity across roles"),
        ));
    }
    Ok(())
}

fn clear_supplementary_groups() -> Result<(), String> {
    let policy = fs::read_to_string("/proc/self/setgroups")
        .map_err(|error| format!("read /proc/self/setgroups: {error}"))?;
    let outer_had_supplementary_groups = match env::var(OUTER_SUPPLEMENTARY_GROUPS_ENV).as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        Ok(other) => {
            return Err(format!(
                "{OUTER_SUPPLEMENTARY_GROUPS_ENV} must be 0 or 1, found {other:?}"
            ));
        }
        Err(_) => return Err(format!("{OUTER_SUPPLEMENTARY_GROUPS_ENV} is required")),
    };
    match policy.trim() {
        "allow" => {
            // SAFETY: a zero count permits a null group-list pointer. This runs as mapped root in
            // the new user namespace before any role child is executed.
            if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
                return Err(format!(
                    "clear supplementary groups in distinct-UID namespace: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        "deny" if outer_had_supplementary_groups => {
            return Err(
                "setgroups is denied after an outer process with supplementary groups; inherited groups cannot be authoritative"
                    .to_owned(),
            );
        }
        "deny" => {}
        other => return Err(format!("unsupported /proc/self/setgroups state {other:?}")),
    }
    let status =
        read_process_credentials("/proc/self/status").map_err(|error| error.to_string())?;
    if status.groups.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "supplementary groups remain after credential preflight clearing: {:?}",
            status.groups
        ))
    }
}

fn require_mapped_role(
    entries: &[IdMapEntry],
    id: u32,
    label: &str,
) -> Result<(), PreflightUnavailable> {
    if entries.iter().any(|entry| entry.contains_inside(id)) {
        Ok(())
    } else {
        Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{label} {id} is absent from the planned namespace map"),
        ))
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ProcessCredentials {
    uids: [u32; 4],
    gids: [u32; 4],
    groups: Vec<u32>,
    cap_inheritable: u64,
    cap_permitted: u64,
    cap_effective: u64,
    cap_ambient: u64,
    no_new_privileges: bool,
}

fn read_process_credentials(path: &str) -> Result<ProcessCredentials, PreflightUnavailable> {
    let status = fs::read_to_string(path).map_err(|error| {
        PreflightUnavailable::new(UnavailableKind::Denied, format!("read {path}: {error}"))
    })?;
    parse_process_credentials(&status)
}

fn parse_process_credentials(status: &str) -> Result<ProcessCredentials, PreflightUnavailable> {
    let uids = parse_status_quad(status, "Uid:")?;
    let gids = parse_status_quad(status, "Gid:")?;
    let groups_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or_else(|| {
            PreflightUnavailable::new(UnavailableKind::Broken, "process status lacks Groups")
        })?;
    let groups = groups_line
        .split_whitespace()
        .map(|value| {
            value.parse::<u32>().map_err(|error| {
                PreflightUnavailable::new(
                    UnavailableKind::Broken,
                    format!("parse supplementary GID {value:?}: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let cap_inheritable = parse_status_hex(status, "CapInh:")?;
    let cap_permitted = parse_status_hex(status, "CapPrm:")?;
    let cap_effective = parse_status_hex(status, "CapEff:")?;
    let cap_ambient = parse_status_hex(status, "CapAmb:")?;
    let no_new_privileges = match parse_status_decimal(status, "NoNewPrivs:")? {
        0 => false,
        1 => true,
        value => {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("process status NoNewPrivs must be 0 or 1, found {value}"),
            ));
        }
    };
    Ok(ProcessCredentials {
        uids,
        gids,
        groups,
        cap_inheritable,
        cap_permitted,
        cap_effective,
        cap_ambient,
        no_new_privileges,
    })
}

fn parse_status_hex(status: &str, prefix: &str) -> Result<u64, PreflightUnavailable> {
    let value = status_value(status, prefix)?;
    u64::from_str_radix(value, 16).map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("parse process status {prefix} value {value:?}: {error}"),
        )
    })
}

fn parse_status_decimal(status: &str, prefix: &str) -> Result<u64, PreflightUnavailable> {
    let value = status_value(status, prefix)?;
    value.parse::<u64>().map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("parse process status {prefix} value {value:?}: {error}"),
        )
    })
}

fn status_value<'a>(status: &'a str, prefix: &str) -> Result<&'a str, PreflightUnavailable> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
        .ok_or_else(|| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("process status lacks one canonical {prefix} value"),
            )
        })
}

fn parse_status_quad(status: &str, prefix: &str) -> Result<[u32; 4], PreflightUnavailable> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or_else(|| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("process status lacks {prefix}"),
            )
        })?;
    let values = line
        .split_whitespace()
        .map(|value| {
            value.parse::<u32>().map_err(|error| {
                PreflightUnavailable::new(
                    UnavailableKind::Broken,
                    format!("parse {prefix} value {value:?}: {error}"),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    values.try_into().map_err(|values: Vec<u32>| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("process status {prefix} requires four values, found {values:?}"),
        )
    })
}

fn read_id_map(path: &str) -> Result<Vec<IdMapEntry>, PreflightUnavailable> {
    let contents = fs::read_to_string(path).map_err(|error| {
        PreflightUnavailable::new(UnavailableKind::Denied, format!("read {path}: {error}"))
    })?;
    parse_id_map(&contents, path)
}

fn parse_id_map(contents: &str, label: &str) -> Result<Vec<IdMapEntry>, PreflightUnavailable> {
    let mut entries = Vec::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let values = line
            .split_whitespace()
            .map(|value| {
                value.parse::<u64>().map_err(|error| {
                    PreflightUnavailable::new(
                        UnavailableKind::Broken,
                        format!("parse {label} line {line:?}: {error}"),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let [inside, outside, length] = values.as_slice() else {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("{label} line must contain exactly three fields: {line:?}"),
            ));
        };
        let maximum = u64::from(u32::MAX);
        if *length == 0
            || inside.saturating_add(*length) > maximum
            || outside.saturating_add(*length) > maximum
        {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("{label} line is outside the valid Linux ID domain: {line:?}"),
            ));
        }
        entries.push(IdMapEntry::new(*inside, *outside, *length));
    }
    if entries.is_empty() {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{label} is empty"),
        ));
    }
    for (index, entry) in entries.iter().enumerate() {
        for other in entries.iter().skip(index.saturating_add(1)) {
            if ranges_overlap(entry.inside, entry.length, other.inside, other.length)
                || ranges_overlap(entry.outside, entry.length, other.outside, other.length)
            {
                return Err(PreflightUnavailable::new(
                    UnavailableKind::Broken,
                    format!("{label} contains overlapping entries"),
                ));
            }
        }
    }
    canonicalize_id_map(&mut entries);
    Ok(entries)
}

fn canonicalize_id_map(entries: &mut [IdMapEntry]) {
    entries.sort_unstable_by_key(|entry| entry.inside);
}

fn ranges_overlap(first: u64, first_length: u64, second: u64, second_length: u64) -> bool {
    first < second.saturating_add(second_length) && second < first.saturating_add(first_length)
}

fn is_full_identity_map(entries: &[IdMapEntry]) -> bool {
    entries == [IdMapEntry::new(0, 0, u64::from(u32::MAX))]
}

fn render_map_entry(entry: IdMapEntry) -> String {
    format!("{}:{}:{}", entry.inside, entry.outside, entry.length)
}

fn render_id_map(entries: &[IdMapEntry]) -> String {
    let mut entries = entries.to_vec();
    canonicalize_id_map(&mut entries);
    entries
        .iter()
        .copied()
        .map(render_map_entry)
        .collect::<Vec<_>>()
        .join(",")
}

fn expected_map_from_environment(variable: &str) -> Result<Vec<IdMapEntry>, String> {
    let encoded = env::var(variable).map_err(|_| format!("{variable} is required"))?;
    let contents = encoded.replace(',', "\n").replace(':', " ");
    parse_id_map(&contents, variable).map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SubordinateRange {
    start: u32,
}

fn subordinate_range(
    path: &Path,
    numeric_owner: u32,
    username: Option<&str>,
    parent_map: &[IdMapEntry],
    label: &str,
) -> Result<SubordinateRange, PreflightUnavailable> {
    require_trusted_file(path, "subordinate-ID database")?;
    let contents = read_bounded(path, SUBORDINATE_ID_FILE_LIMIT)
        .map_err(|error| PreflightUnavailable::new(UnavailableKind::Denied, error))?;
    let contents = String::from_utf8(contents).map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{} is not UTF-8: {error}", path.display()),
        )
    })?;
    select_subordinate_range(&contents, numeric_owner, username, parent_map, label)
}

fn select_subordinate_range(
    contents: &str,
    numeric_owner: u32,
    username: Option<&str>,
    parent_map: &[IdMapEntry],
    label: &str,
) -> Result<SubordinateRange, PreflightUnavailable> {
    let numeric_owner = numeric_owner.to_string();
    let mut matching_but_too_small = false;
    let mut matching_but_unmapped = false;
    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let fields = line.split(':').collect::<Vec<_>>();
        let [owner, start, count] = fields.as_slice() else {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("{label} subordinate-ID line is malformed: {line:?}"),
            ));
        };
        if *owner != numeric_owner && username != Some(*owner) {
            continue;
        }
        let start = start.parse::<u64>().map_err(|error| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("parse {label} subordinate start in {line:?}: {error}"),
            )
        })?;
        let count = count.parse::<u64>().map_err(|error| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("parse {label} subordinate count in {line:?}: {error}"),
            )
        })?;
        if count < 2
            || start.saturating_add(2) > u64::from(u32::MAX)
            || start == 65_534
            || start.saturating_add(1) == 65_534
        {
            matching_but_too_small = true;
            continue;
        }
        let start = u32::try_from(start).map_err(|_| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("{label} subordinate start exceeds u32 in {line:?}"),
            )
        })?;
        if !parent_map
            .iter()
            .any(|entry| entry.contains_inside_range(start, 2))
        {
            matching_but_unmapped = true;
            continue;
        }
        return Ok(SubordinateRange { start });
    }
    let detail = if matching_but_unmapped {
        format!(
            "the current parent user namespace does not expose either complete {label} subordinate pair"
        )
    } else if matching_but_too_small {
        format!("no {label} subordinate range contains two usable IDs")
    } else {
        format!("no {label} subordinate range is assigned to the outer real user")
    };
    Err(PreflightUnavailable::new(
        UnavailableKind::Unsupported,
        detail,
    ))
}

fn passwd_username(uid: u32) -> Result<Option<String>, PreflightUnavailable> {
    let path = Path::new("/etc/passwd");
    require_trusted_file(path, "account database")?;
    let contents = read_bounded(path, SUBORDINATE_ID_FILE_LIMIT)
        .map_err(|error| PreflightUnavailable::new(UnavailableKind::Denied, error))?;
    let contents = String::from_utf8(contents).map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("{} is not UTF-8: {error}", path.display()),
        )
    })?;
    Ok(select_passwd_username(&contents, uid))
}

fn select_passwd_username(contents: &str, uid: u32) -> Option<String> {
    contents.lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 || fields[0].is_empty() || fields[2].parse::<u32>().ok() != Some(uid) {
            None
        } else {
            Some(fields[0].to_owned())
        }
    })
}

fn resolve_trusted_executable(program: &str) -> Result<PathBuf, PreflightUnavailable> {
    let path = env::var_os("PATH").ok_or_else(|| {
        PreflightUnavailable::new(UnavailableKind::Unsupported, "PATH is not set")
    })?;
    resolve_trusted_executable_in(program, &path)
}

fn resolve_trusted_executable_in(
    program: &str,
    path: &OsStr,
) -> Result<PathBuf, PreflightUnavailable> {
    for directory in env::split_paths(path) {
        if !directory.is_absolute() {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Conflicting,
                format!("PATH contains a relative entry before trusted `{program}` resolution"),
            ));
        }
        let candidate = directory.join(program);
        let metadata = match fs::metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(PreflightUnavailable::new(
                    UnavailableKind::Denied,
                    format!("inspect helper {}: {error}", candidate.display()),
                ));
            }
        };
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let canonical = fs::canonicalize(&candidate).map_err(|error| {
            PreflightUnavailable::new(
                UnavailableKind::Denied,
                format!("canonicalize helper {}: {error}", candidate.display()),
            )
        })?;
        require_trusted_file(&canonical, "credential helper")?;
        for ancestor in canonical.parent().into_iter().flat_map(Path::ancestors) {
            require_trusted_directory(ancestor, "credential-helper path")?;
        }
        return Ok(canonical);
    }
    Err(PreflightUnavailable::new(
        UnavailableKind::Unsupported,
        format!("required helper `{program}` is unavailable on PATH"),
    ))
}

fn trusted_executable_path(paths: &[PathBuf]) -> Result<OsString, PreflightUnavailable> {
    let mut directories = Vec::new();
    for path in paths {
        let parent = path.parent().ok_or_else(|| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!(
                    "trusted executable {} has no parent directory",
                    path.display()
                ),
            )
        })?;
        if !directories.iter().any(|directory| directory == parent) {
            directories.push(parent.to_path_buf());
        }
    }
    let encoded = env::join_paths(&directories).map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Broken,
            format!("construct trusted credential-helper PATH: {error}"),
        )
    })?;
    for path in paths {
        let program = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            PreflightUnavailable::new(
                UnavailableKind::Broken,
                format!("trusted executable name is not UTF-8: {}", path.display()),
            )
        })?;
        let resolved = resolve_trusted_executable_in(program, &encoded)?;
        if resolved != *path {
            return Err(PreflightUnavailable::new(
                UnavailableKind::Conflicting,
                format!(
                    "scrubbed PATH resolves `{program}` to {}, expected {}",
                    resolved.display(),
                    path.display()
                ),
            ));
        }
    }
    Ok(encoded)
}

fn set_no_new_privileges() -> Result<(), String> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes the scalar value 1 followed by unused zero arguments and
    // changes only the calling process. It is intentionally irreversible for the role helper.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "set no-new-privileges for credential role: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn require_trusted_file(path: &Path, purpose: &str) -> Result<(), PreflightUnavailable> {
    let metadata = fs::metadata(path).map_err(|error| {
        PreflightUnavailable::new(
            if error.kind() == std::io::ErrorKind::NotFound {
                UnavailableKind::Unsupported
            } else {
                UnavailableKind::Denied
            },
            format!("inspect {purpose} {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_file() {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            format!("{purpose} {} is not a regular file", path.display()),
        ));
    }
    require_trusted_metadata(path, &metadata, purpose)
}

fn require_trusted_directory(path: &Path, purpose: &str) -> Result<(), PreflightUnavailable> {
    let metadata = fs::metadata(path).map_err(|error| {
        PreflightUnavailable::new(
            UnavailableKind::Denied,
            format!("inspect {purpose} {}: {error}", path.display()),
        )
    })?;
    if !metadata.is_dir() {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            format!("{purpose} {} is not a directory", path.display()),
        ));
    }
    require_trusted_metadata(path, &metadata, purpose)
}

fn require_trusted_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    purpose: &str,
) -> Result<(), PreflightUnavailable> {
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
        return Err(PreflightUnavailable::new(
            UnavailableKind::Conflicting,
            format!(
                "{purpose} {} must be root-owned and not group/world writable (uid={} mode={:o})",
                path.display(),
                metadata.uid(),
                metadata.permissions().mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

fn mount_namespace_identity() -> Result<String, String> {
    fs::read_link("/proc/self/ns/mnt")
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| format!("read mount namespace identity: {error}"))
}

fn required_u32_environment(variable: &str) -> Result<u32, String> {
    env::var(variable)
        .map_err(|_| format!("{variable} is required"))?
        .parse::<u32>()
        .map_err(|error| format!("parse {variable}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_parent_map() -> Vec<IdMapEntry> {
        vec![IdMapEntry::new(0, 0, u64::from(u32::MAX))]
    }

    #[test]
    fn role_contract_rejects_root_and_same_uid_fallbacks() {
        assert!(
            validate_role_credentials(Credential { uid: 0, gid: 1 }, Credential { uid: 2, gid: 2 })
                .is_err()
        );
        assert!(
            validate_role_credentials(Credential { uid: 7, gid: 7 }, Credential { uid: 7, gid: 8 })
                .is_err()
        );
        validate_role_credentials(PROBE_CREDENTIAL, ENGINE_CREDENTIAL)
            .expect("fixed identities are distinct and nonzero");
    }

    #[test]
    fn subordinate_selection_requires_two_ids_exposed_by_the_parent_namespace() {
        let contents = "alice:100000:1\nalice:200000:4\n1000:300000:2\n";
        let narrow_parent = vec![IdMapEntry::new(1_000, 0, 1)];
        let error = select_subordinate_range(contents, 1_000, Some("alice"), &narrow_parent, "UID")
            .expect_err("one-entry parent map cannot expose subordinate IDs");
        assert_eq!(error.kind, UnavailableKind::Unsupported);
        assert!(error.detail.contains("parent user namespace"));

        let selected =
            select_subordinate_range(contents, 1_000, Some("alice"), &full_parent_map(), "UID")
                .expect("full parent map exposes the first usable pair");
        assert_eq!(selected, SubordinateRange { start: 200_000 });
    }

    #[test]
    fn exact_map_parser_rejects_zero_length_and_out_of_domain_entries() {
        assert_eq!(
            parse_id_map("0 1000 1\n1 100000 2\n", "uid_map").expect("valid exact map"),
            [IdMapEntry::new(0, 1000, 1), IdMapEntry::new(1, 100000, 2)]
        );
        assert!(parse_id_map("0 0 0\n", "uid_map").is_err());
        assert!(parse_id_map("4294967294 0 2\n", "uid_map").is_err());
    }

    #[test]
    fn reversed_util_linux_map_order_canonicalizes_before_exact_validation() {
        let reversed = format!("{ENGINE_UID} 100001 1\n{PROBE_UID} 100000 1\n0 1000 1\n");
        let parsed = parse_id_map(&reversed, "uid_map").expect("valid reversed exact map");
        assert_eq!(
            parsed,
            [
                IdMapEntry::new(0, 1000, 1),
                IdMapEntry::new(u64::from(PROBE_UID), 100000, 1),
                IdMapEntry::new(u64::from(ENGINE_UID), 100001, 1),
            ]
        );
        validate_exact_role_map(&parsed, "UID").expect("canonical exact role map");
        assert_eq!(
            render_id_map(&parsed),
            format!("0:1000:1,{PROBE_UID}:100000:1,{ENGINE_UID}:100001:1")
        );
    }

    #[test]
    fn process_status_parser_preserves_saved_filesystem_and_supplementary_ids() {
        let status = "Uid:\t1\t1\t1\t1\nGid:\t2\t2\t2\t2\nGroups:\t3 4\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
        assert_eq!(
            parse_process_credentials(status).expect("valid credential status"),
            ProcessCredentials {
                uids: [1; 4],
                gids: [2; 4],
                groups: vec![3, 4],
                cap_inheritable: 0,
                cap_permitted: 0,
                cap_effective: 0,
                cap_ambient: 0,
                no_new_privileges: true,
            }
        );
        assert!(parse_process_credentials("Uid:\t1 1 1\nGid:\t2 2 2 2\nGroups:\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n").is_err());
    }

    #[test]
    fn role_handshake_precreates_nofollow_files_without_a_world_writable_directory() {
        let directory = tempfile::tempdir().expect("role handshake directory");
        let ready_path = directory.path().join("ready");
        let release_path = directory.path().join("release");
        // SAFETY: geteuid has no arguments or failure mode and only reads the
        // current process identity for this unprivileged regression.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: getegid has no arguments or failure mode and only reads the
        // current process identity for this unprivileged regression.
        let gid = unsafe { libc::getegid() };
        let credential = Credential { uid, gid };
        let mut release =
            create_role_handshake_files(directory.path(), &ready_path, &release_path, credential)
                .expect("precreate secure role handshake files");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o711))
            .expect("restrict role handshake directory");

        assert_eq!(
            fs::symlink_metadata(directory.path())
                .expect("handshake metadata")
                .mode()
                & 0o777,
            0o711
        );
        let ready_metadata = fs::symlink_metadata(&ready_path).expect("ready metadata");
        assert!(ready_metadata.file_type().is_file());
        assert_eq!(ready_metadata.uid(), credential.uid);
        assert_eq!(ready_metadata.gid(), credential.gid);
        assert_eq!(ready_metadata.mode() & 0o777, 0o600);
        let release_metadata = fs::symlink_metadata(&release_path).expect("release metadata");
        assert!(release_metadata.file_type().is_file());
        assert_eq!(release_metadata.mode() & 0o777, 0o644);

        write_existing_role_signal(&ready_path, "ready:test\n")
            .expect("write through the precreated ready file");
        assert_eq!(
            fs::read_to_string(&ready_path).expect("read ready signal"),
            "ready:test\n"
        );
        publish_role_signal(&mut release, &release_path, "release:test\n")
            .expect("write through retained parent release descriptor");
        assert_eq!(
            fs::read_to_string(&release_path).expect("read release signal"),
            "release:test\n"
        );

        let target = directory.path().join("target");
        fs::write(&target, "unchanged").expect("write symlink target");
        let symlink = directory.path().join("symlink");
        std::os::unix::fs::symlink(&target, &symlink).expect("create test symlink");
        assert!(write_existing_role_signal(&symlink, "clobber").is_err());
        assert_eq!(
            fs::read_to_string(target).expect("read unchanged symlink target"),
            "unchanged"
        );
    }

    #[test]
    fn subordinate_mapping_arguments_never_request_root_roles_or_traffic_tools() {
        let plan = CredentialPlan::new(
            MappingMechanism::SubordinateHelpers,
            PathBuf::from("/usr/bin/unshare"),
            PathBuf::from("/usr/bin/true"),
            OsString::from("/usr/bin"),
            vec![
                IdMapEntry::new(0, 1000, 1),
                IdMapEntry::new(u64::from(PROBE_UID), 100000, 1),
                IdMapEntry::new(u64::from(ENGINE_UID), 100001, 1),
            ],
            vec![
                IdMapEntry::new(0, 1000, 1),
                IdMapEntry::new(u64::from(PROBE_GID), 100000, 1),
                IdMapEntry::new(u64::from(ENGINE_GID), 100001, 1),
            ],
            false,
        )
        .expect("valid subordinate plan");
        let arguments = plan.mapping_arguments();
        assert!(arguments.contains(&format!("--map-users=100000,{PROBE_UID},1")));
        assert!(arguments.contains(&format!("--map-users=100001,{ENGINE_UID},1")));
        assert!(arguments.contains(&format!("--map-groups=100000,{PROBE_GID},1")));
        assert!(arguments.contains(&format!("--map-groups=100001,{ENGINE_GID},1")));
        assert!(
            !arguments
                .iter()
                .any(|argument| { matches!(argument.as_str(), "--setuid=0" | "--setgid=0") })
        );
        assert!(!arguments.iter().any(|argument| {
            matches!(
                argument.as_str(),
                "sudo" | "modprobe" | "iptables" | "ip6tables"
            )
        }));
    }

    #[test]
    fn optional_and_required_modes_keep_unavailable_credentials_explicit() {
        assert!(skip_or_fail(false, "missing newuidmap".to_owned()).is_ok());
        assert_eq!(
            skip_or_fail(true, "missing newuidmap".to_owned()),
            Err("missing newuidmap".to_owned())
        );
    }

    #[test]
    fn process_handle_probe_softens_only_unsupported_or_permission_denied_opening() {
        for error in [
            ProcessHandleError::UnsupportedPlatform("test"),
            ProcessHandleError::PidFdUnsupported {
                source: std::io::Error::from_raw_os_error(libc::ENOSYS),
            },
            ProcessHandleError::SystemCall {
                operation: "open child pidfd",
                path: None,
                source: std::io::Error::from_raw_os_error(libc::EPERM),
            },
        ] {
            assert!(matches!(
                classify_process_handle_open_error(error),
                ProcessHandleProbeFailure::Unavailable(_)
            ));
        }

        let exited = ProcessHandleError::Exited {
            pid: std::num::NonZeroU32::new(1).expect("nonzero test PID"),
        };
        assert!(matches!(
            classify_process_handle_open_error(exited),
            ProcessHandleProbeFailure::Hard(_)
        ));
        assert!(matches!(
            classify_process_handle_open_error(ProcessHandleError::MalformedProcStat {
                path: PathBuf::from("/proc/1/stat"),
            }),
            ProcessHandleProbeFailure::Hard(_)
        ));
        assert!(matches!(
            classify_process_handle_open_error(ProcessHandleError::ChildReapContractUnavailable),
            ProcessHandleProbeFailure::Hard(_)
        ));
    }
}
