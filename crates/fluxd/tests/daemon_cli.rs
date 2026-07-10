use std::sync::Mutex;

use flux_core::{
    AdministrativeState, ControlClient, ControlError, ControlSnapshot, KernelSupport, LegacyIntent,
    OperationReport,
};
use flux_testkit::StaticKernelReleaseSource;
use fluxd::{DaemonClient, DaemonSnapshot, EventDisposition, EventReport, run_cli_with_daemon};

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
            "\"version\":\"5.10.0\",\"minimum\":\"5.10.0\",\"supported\":true},",
            "\"control\":{\"revision\":18,\"administrative_state\":\"stopped\",",
            "\"configuration_dirty\":true,\"in_flight\":null,",
            "\"last_completed\":null}}\n"
        )
    );
    assert_eq!(
        source.calls(),
        0,
        "live status must not synthesize local state"
    );
}

#[derive(Default)]
struct RecordingDaemonClient {
    pings: Mutex<usize>,
    events: Mutex<Vec<(String, String, String)>>,
}

impl RecordingDaemonClient {
    fn pings(&self) -> usize {
        *self.pings.lock().expect("pings lock")
    }

    fn events(&self) -> Vec<(String, String, String)> {
        self.events.lock().expect("events lock").clone()
    }
}

impl ControlClient for RecordingDaemonClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        Ok(OperationReport {
            intent,
            revision: 17,
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
            kernel_support: KernelSupport::evaluate("5.10.0").expect("kernel release"),
            control: ControlSnapshot {
                revision: 18,
                administrative_state: AdministrativeState::Stopped,
                configuration_dirty: true,
                in_flight: None,
                last_completed: None,
            },
        })
    }

    fn send_event(
        &self,
        event_type: &str,
        watched_path: &str,
        event_name: &str,
    ) -> Result<EventReport, ControlError> {
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
