use std::sync::Mutex;

use flux_core::{
    AdministrativeState, CapabilityProfile, ControlClient, ControlError, ControlSnapshot,
    LegacyIntent, OperationReport,
};
use flux_testkit::{CapabilityProfileFixture, StaticKernelReleaseSource};
use fluxd::{
    DaemonClient, DaemonSnapshot, DiagnosticReport, EventDisposition, EventReport, ExplainReport,
    LogReport, LogStream, RuntimeCaptureState, RuntimeEngineState, RuntimeFailure, RuntimePhase,
    RuntimeSnapshot, RuntimeVerificationState, SubscriptionRefreshReport, run_cli_with_daemon,
};

#[test]
fn ping_uses_the_daemon_transport() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "ping"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert_eq!(String::from_utf8(stdout).expect("UTF-8 output"), "pong\n");
    assert!(stderr.is_empty());
    assert_eq!(client.pings(), 1);
}

#[test]
fn event_forwards_the_raw_inotify_fact_without_shell_policy_mapping() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "event", "y", "/data/adb/flux/conf", "settings.ini"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 output"),
        "event deferred revision 19\n"
    );
    assert!(stderr.is_empty());
    assert_eq!(
        client.events(),
        vec![(
            "y".to_owned(),
            "/data/adb/flux/conf".to_owned(),
            "settings.ini".to_owned(),
        )]
    );
}

#[test]
fn unsupported_kernel_event_uses_the_stable_unsupported_exit_code() {
    let source = StaticKernelReleaseSource::new("6.6.0");
    let client = RecordingDaemonClient::with_unsupported_events();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "event", "y", "/data/adb/flux/conf", "settings.ini"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 3);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 error"),
        "fluxd: control request rejected (unsupported_kernel): kernel 5.4.280 is below minimum 5.10.0\n"
    );
    assert!(client.events().is_empty());
}

#[test]
fn subscription_update_reports_every_terminal_disposition() {
    let cases = [
        (
            SubscriptionRefreshReport::updated(23, 41, false),
            0,
            "subscription updated generation=23 nodes=41 cleanup_pending=false\n",
            "",
        ),
        (
            SubscriptionRefreshReport::updated_deferred(42, true),
            0,
            "subscription updated_deferred nodes=42 cleanup_pending=true\n",
            "",
        ),
        (
            SubscriptionRefreshReport::unchanged(43, false),
            0,
            "subscription unchanged nodes=43 cleanup_pending=false\n",
            "",
        ),
        (
            SubscriptionRefreshReport::disabled(),
            0,
            "subscription disabled cleanup_pending=false\n",
            "",
        ),
        (
            SubscriptionRefreshReport::busy(),
            1,
            "",
            "fluxd: subscription busy\n",
        ),
    ];

    for (report, expected_exit, expected_stdout, expected_stderr) in cases {
        let source = StaticKernelReleaseSource::new("5.10.0");
        let client = RecordingDaemonClient::with_subscription_result(Ok(report));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run_cli_with_daemon(
            ["fluxd", "subscription", "update"],
            &source,
            &client,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(exit, expected_exit);
        assert_eq!(
            String::from_utf8(stdout).expect("UTF-8 output"),
            expected_stdout
        );
        assert_eq!(
            String::from_utf8(stderr).expect("UTF-8 error"),
            expected_stderr
        );
        assert_eq!(client.subscription_updates(), 1);
    }
}

#[test]
fn subscription_update_reports_typed_rejection_and_usage_errors() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client =
        RecordingDaemonClient::with_subscription_result(Err(ControlError::request_rejected(
            "subscription_source_changed",
            "subscription inputs changed during refresh",
        )));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "subscription", "update"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 1);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 error"),
        concat!(
            "fluxd: subscription update failed: control request rejected ",
            "(subscription_source_changed): subscription inputs changed during refresh\n"
        )
    );
    assert_eq!(client.subscription_updates(), 1);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_daemon(
        ["fluxd", "subscription", "refresh"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 usage error"),
        "fluxd: unknown subscription action 'refresh'\n"
    );
    assert_eq!(client.subscription_updates(), 1);
}

#[test]
fn json_status_comes_from_the_live_daemon_snapshot() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "status", "--json"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 output"),
        concat!(
            "{\"daemon\":\"running\",\"kernel\":{",
            "\"version\":\"5.10.198\",\"minimum\":\"5.10.0\",\"supported\":true},",
            "\"capability_profile\":{",
            "\"schema_version\":2,\"revision\":1,",
            "\"boot_identity\":{\"status\":\"verified\",",
            "\"value\":\"01234567-89ab-cdef-0123-456789abcdef\"},",
            "\"device_identity\":{\"status\":\"unavailable\"},",
            "\"kernel\":{\"release\":{\"status\":\"verified\",",
            "\"value\":\"5.10.198-android12-9-gki\"},",
            "\"version\":{\"status\":\"verified\",\"value\":\"5.10.198\"},",
            "\"minimum\":\"5.10.0\",\"gate\":{\"status\":\"allowed\"}},",
            "\"selinux\":{\"status\":\"verified\",\"value\":\"enforcing\"},",
            "\"legacy_bridge\":{\"mutation_writer\":\"dispatcher\",",
            "\"rule_backend\":\"iptables_restore\",",
            "\"address_synchronization\":\"standalone_addrsyncd_via_script\",",
            "\"shell\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}},",
            "\"dispatcher\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}},",
            "\"addrsync\":{\"status\":\"verified\",\"value\":{",
            "\"resolution\":\"direct\",\"ready\":true}}}},",
            "\"control\":{\"revision\":18,\"administrative_state\":\"stopped\",",
            "\"configuration_dirty\":true,\"in_flight\":null,",
            "\"last_completed\":null},",
            "\"runtime\":{\"revision\":7,\"phase\":\"repairing\",",
            "\"capture\":\"detached\",",
            "\"engine\":\"backing_off\",",
            "\"verification\":\"functional_failed\",\"generation\":19,",
            "\"last_error\":{\"operation\":\"maintain proxy engine\",",
            "\"message\":\"owned child exited unexpectedly\",",
            "\"recovery\":\"retry after bounded backoff\"}}}\n"
        )
    );
    assert_eq!(
        source.calls(),
        0,
        "live status must not synthesize local state"
    );
}

#[test]
fn json_status_keeps_the_legacy_kernel_summary_for_a_below_floor_kernel() {
    let source = StaticKernelReleaseSource::new("6.6.0");
    let client =
        RecordingDaemonClient::with_profile(CapabilityProfileFixture::unsupported_kernel());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "status", "--json"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&stdout).expect("JSON status");
    assert_eq!(document["daemon"], "unsupported_kernel");
    assert_eq!(
        document["kernel"],
        serde_json::json!({
            "version": "5.4.280",
            "minimum": "5.10.0",
            "supported": false,
        })
    );
    assert!(document.get("capability_profile").is_some());
    assert_eq!(source.calls(), 0);
}

#[test]
fn json_status_omits_the_legacy_kernel_summary_when_version_is_unverified() {
    let source = StaticKernelReleaseSource::new("6.6.0");
    let initial = CapabilityProfileFixture::supported();
    let unverified_kernel = CapabilityProfile::initial(
        initial.boot_identity().clone(),
        initial.device_identity().clone(),
        flux_core::KernelFacts::from_release(flux_core::Observation::Unavailable),
        initial.selinux().clone(),
        initial.legacy_bridge().clone(),
    );
    let client = RecordingDaemonClient::with_profile(unverified_kernel);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "status", "--json"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&stdout).expect("JSON status");
    assert_eq!(document["daemon"], "read_only_profile");
    assert!(document.get("kernel").is_none());
    assert_eq!(
        document["capability_profile"]["kernel"]["version"]["status"],
        "unavailable"
    );
    assert_eq!(source.calls(), 0);
}

#[test]
fn text_status_reports_the_capability_profile_evidence() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "status"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 output"),
        concat!(
            "daemon: running\n",
            "capability profile schema: 2\n",
            "capability profile revision: 1\n",
            "kernel release: 5.10.198-android12-9-gki (verified)\n",
            "kernel version: 5.10.198 (verified)\n",
            "minimum kernel: 5.10.0\n",
            "mutation gate: allowed\n",
            "boot identity: 01234567-89ab-cdef-0123-456789abcdef (verified)\n",
            "device identity: unavailable\n",
            "SELinux: enforcing (verified)\n",
            "legacy mutation writer: dispatcher\n",
            "legacy rule backend: iptables_restore\n",
            "legacy address synchronization: standalone_addrsyncd_via_script\n",
            "legacy shell: ready (direct, verified)\n",
            "legacy dispatcher: ready (direct, verified)\n",
            "legacy addrsync: ready (direct, verified)\n",
            "administrative state: stopped\n",
            "configuration dirty: yes\n",
            "revision: 18\n",
            "last address resync: none\n",
            "runtime revision: 7\n",
            "runtime phase: repairing\n",
            "runtime capture: detached\n",
            "runtime engine: backing_off\n",
            "runtime verification: functional_failed\n",
            "runtime generation: 19\n",
            "runtime last error: maintain proxy engine: owned child exited unexpectedly; ",
            "recovery: retry after bounded backoff\n"
        )
    );
    assert_eq!(source.calls(), 0);
}

#[test]
fn bounded_log_cli_uses_a_fixed_stream_and_rejects_arbitrary_paths() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "logs", "engine", "--lines", "2"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert_eq!(
        String::from_utf8(stdout).expect("UTF-8 log"),
        "first\nsecond\n"
    );
    assert!(stderr.is_empty());
    assert_eq!(client.log_requests(), vec![(LogStream::Engine, 2)]);

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let exit = run_cli_with_daemon(
        ["fluxd", "logs", "/data/local/tmp/secret"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );
    assert_eq!(exit, 2);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 usage error"),
        "fluxd: unknown logs option '/data/local/tmp/secret'\n"
    );
    assert_eq!(client.log_requests(), vec![(LogStream::Engine, 2)]);
}

#[test]
fn diagnostics_combine_authoritative_status_with_bounded_checks() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    let client = RecordingDaemonClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_daemon(
        ["fluxd", "diagnose", "--json"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 0);
    assert!(stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&stdout).expect("diagnostic JSON");
    assert_eq!(document["status"]["daemon"], "running");
    assert_eq!(document["status"]["runtime"]["generation"], 19);
    assert_eq!(document["diagnostics"]["desired_state"]["state"], "ready");
    assert_eq!(client.diagnoses(), 1);
    assert_eq!(source.calls(), 0);
}

#[test]
fn explain_aliases_return_the_same_non_authorizing_rust_plan() {
    let source = StaticKernelReleaseSource::new("5.10.0");
    for arguments in [
        vec!["fluxd", "backend", "explain"],
        vec!["fluxd", "plan", "--dry-run"],
        vec!["fluxd", "rules-preview"],
        vec!["fluxd", "preview"],
    ] {
        let client = RecordingDaemonClient::default();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let exit = run_cli_with_daemon(arguments, &source, &client, &mut stdout, &mut stderr);

        assert_eq!(exit, 0);
        assert!(stderr.is_empty());
        let output = String::from_utf8(stdout).expect("UTF-8 explanation");
        assert!(output.starts_with("authorization: non_authorizing\n"));
        assert!(output.contains("backend: xtables\n"));
        assert!(output.contains("bridge compatible: true"));
        assert_eq!(client.explanations(), 1);
    }
}

struct RecordingDaemonClient {
    pings: Mutex<usize>,
    events: Mutex<Vec<(String, String, String)>>,
    subscription_updates: Mutex<usize>,
    subscription_result: Mutex<Result<SubscriptionRefreshReport, ControlError>>,
    log_requests: Mutex<Vec<(LogStream, u16)>>,
    diagnoses: Mutex<usize>,
    explanations: Mutex<usize>,
    profile: CapabilityProfile,
    unsupported_events: bool,
}

impl Default for RecordingDaemonClient {
    fn default() -> Self {
        Self::with_profile(CapabilityProfileFixture::supported())
    }
}

impl RecordingDaemonClient {
    fn with_profile(profile: CapabilityProfile) -> Self {
        Self {
            pings: Mutex::new(0),
            events: Mutex::new(Vec::new()),
            subscription_updates: Mutex::new(0),
            subscription_result: Mutex::new(Ok(SubscriptionRefreshReport::disabled())),
            log_requests: Mutex::new(Vec::new()),
            diagnoses: Mutex::new(0),
            explanations: Mutex::new(0),
            profile,
            unsupported_events: false,
        }
    }

    fn with_subscription_result(result: Result<SubscriptionRefreshReport, ControlError>) -> Self {
        Self {
            subscription_result: Mutex::new(result),
            ..Self::default()
        }
    }

    fn with_unsupported_events() -> Self {
        Self {
            unsupported_events: true,
            ..Self::default()
        }
    }

    fn pings(&self) -> usize {
        *self.pings.lock().expect("pings lock")
    }

    fn events(&self) -> Vec<(String, String, String)> {
        self.events.lock().expect("events lock").clone()
    }

    fn subscription_updates(&self) -> usize {
        *self
            .subscription_updates
            .lock()
            .expect("subscription updates lock")
    }

    fn log_requests(&self) -> Vec<(LogStream, u16)> {
        self.log_requests.lock().expect("log requests lock").clone()
    }

    fn diagnoses(&self) -> usize {
        *self.diagnoses.lock().expect("diagnoses lock")
    }

    fn explanations(&self) -> usize {
        *self.explanations.lock().expect("explanations lock")
    }
}

impl ControlClient for RecordingDaemonClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        Ok(OperationReport {
            intent,
            revision: 17,
            address_resync: matches!(intent, LegacyIntent::ResyncAddresses { .. })
                .then_some(flux_core::AddressResyncDisposition::AcceptedDeferred),
        })
    }
}

impl DaemonClient for RecordingDaemonClient {
    fn ping(&self) -> Result<(), ControlError> {
        let mut pings = self.pings.lock().expect("pings lock");
        *pings = pings.saturating_add(1);
        Ok(())
    }

    fn status(&self) -> Result<DaemonSnapshot, ControlError> {
        Ok(DaemonSnapshot {
            capability_profile: self.profile.clone(),
            control: ControlSnapshot {
                revision: 18,
                administrative_state: AdministrativeState::Stopped,
                configuration_dirty: true,
                in_flight: None,
                last_completed: None,
            },
            runtime: observed_runtime(),
        })
    }

    fn update_subscription(&self) -> Result<SubscriptionRefreshReport, ControlError> {
        let mut updates = self
            .subscription_updates
            .lock()
            .expect("subscription updates lock");
        *updates = updates.saturating_add(1);
        self.subscription_result
            .lock()
            .expect("subscription result lock")
            .clone()
    }

    fn diagnose(&self) -> Result<DiagnosticReport, ControlError> {
        let mut calls = self.diagnoses.lock().expect("diagnoses lock");
        *calls = calls.saturating_add(1);
        Ok(diagnostic_report())
    }

    fn logs(&self, stream: LogStream, lines: u16) -> Result<LogReport, ControlError> {
        self.log_requests
            .lock()
            .expect("log requests lock")
            .push((stream, lines));
        serde_json::from_value(serde_json::json!({
            "stream": stream,
            "content": "first\nsecond\n",
            "line_count": 2,
            "truncated": true,
        }))
        .map_err(|error| ControlError::protocol(error.to_string()))
    }

    fn explain(&self) -> Result<ExplainReport, ControlError> {
        let mut calls = self.explanations.lock().expect("explanations lock");
        *calls = calls.saturating_add(1);
        serde_json::from_value(explain_value())
            .map_err(|error| ControlError::protocol(error.to_string()))
    }

    fn send_event(
        &self,
        event_type: &str,
        watched_path: &str,
        event_name: &str,
    ) -> Result<EventReport, ControlError> {
        if self.unsupported_events {
            return Err(ControlError::request_rejected(
                "unsupported_kernel",
                "kernel 5.4.280 is below minimum 5.10.0",
            ));
        }
        self.events.lock().expect("events lock").push((
            event_type.to_owned(),
            watched_path.to_owned(),
            event_name.to_owned(),
        ));
        Ok(EventReport {
            disposition: EventDisposition::Deferred,
            revision: 19,
        })
    }
}

fn diagnostic_report() -> DiagnosticReport {
    serde_json::from_value(serde_json::json!({
        "desired_state": {"state": "ready", "detail": "schema=3"},
        "engine_manifest": {"state": "ready", "detail": "generation=19"},
        "runtime_log": {"state": "ready", "detail": "bytes=120"},
        "daemon_log": {"state": "ready", "detail": "bytes=90"},
        "engine_log": {"state": "missing", "detail": "file is absent"},
    }))
    .expect("diagnostic fixture")
}

fn explain_value() -> serde_json::Value {
    serde_json::json!({
        "desired_state_schema": 3,
        "backend": "xtables",
        "listener_port": 9898,
        "address_families": "dual_stack",
        "local_output": true,
        "forwarded_ingress": true,
        "tcp": true,
        "udp": true,
        "application_mode": "all",
        "application_packages": 0,
        "configured_bypass_prefixes": 0,
        "excluded_interfaces": 1,
        "forwarded_proxy_interfaces": 2,
        "local_bypass_interfaces": 0,
        "subscription_enabled": false,
        "respect_android_vpn": false,
        "require_functional_canary": false,
        "engine_config_schema": 1,
        "engine_config_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "engine_config_bytes": 4096,
        "bridge_compatible": true,
        "bridge_detail": "representable by the fenced bridge",
        "non_authorizing": true,
    })
}

fn observed_runtime() -> RuntimeSnapshot {
    RuntimeSnapshot {
        revision: 7,
        phase: RuntimePhase::Repairing,
        capture: RuntimeCaptureState::Detached,
        engine: RuntimeEngineState::BackingOff,
        verification: RuntimeVerificationState::FunctionalFailed,
        generation: Some(19),
        last_error: Some(RuntimeFailure {
            operation: "maintain proxy engine".to_owned(),
            message: "owned child exited unexpectedly".to_owned(),
            recovery: "retry after bounded backoff".to_owned(),
        }),
    }
}
