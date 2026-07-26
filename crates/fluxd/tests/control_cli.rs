use std::sync::Mutex;

use flux_core::{ControlClient, ControlError, LegacyIntent, OperationReport, Reason};
use flux_testkit::StaticKernelReleaseSource;
use fluxd::run_cli_with_control;

#[test]
fn control_commands_map_to_legacy_intents_and_wait_for_completion() {
    let cases = [
        (
            "start",
            LegacyIntent::Running {
                reason: Reason::Fluxctl,
            },
        ),
        (
            "stop",
            LegacyIntent::Stopped {
                reason: Reason::Fluxctl,
            },
        ),
        (
            "restart",
            LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            },
        ),
        (
            "reload",
            LegacyIntent::Reload {
                reason: Reason::Fluxctl,
            },
        ),
        (
            "resync",
            LegacyIntent::ResyncAddresses {
                reason: Reason::Fluxctl,
            },
        ),
    ];

    for (command, expected) in cases {
        for arguments in [vec!["fluxd", "control", command], vec!["fluxd", command]] {
            let source = StaticKernelReleaseSource::new("5.10.0-android12");
            let client = RecordingControlClient::default();
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            let exit = run_cli_with_control(arguments, &source, &client, &mut stdout, &mut stderr);

            assert_eq!(exit, 0, "command {command}");
            assert!(stderr.is_empty(), "command {command}");
            assert_eq!(
                String::from_utf8(stdout).expect("UTF-8 output"),
                "completed revision 41\n"
            );
            assert_eq!(client.intents(), vec![expected]);
        }
    }
}

#[test]
fn control_command_on_an_unsupported_kernel_never_reaches_the_writer() {
    let source = StaticKernelReleaseSource::new("5.9.18-vendor");
    let client = RecordingControlClient::default();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let exit = run_cli_with_control(
        ["fluxd", "control", "start"],
        &source,
        &client,
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(exit, 3);
    assert!(stdout.is_empty());
    assert_eq!(
        String::from_utf8(stderr).expect("UTF-8 error"),
        "fluxd: kernel 5.9.18 is below minimum 5.10.0\n"
    );
    assert!(client.intents().is_empty());
}

#[derive(Default)]
struct RecordingControlClient {
    intents: Mutex<Vec<LegacyIntent>>,
}

impl RecordingControlClient {
    fn intents(&self) -> Vec<LegacyIntent> {
        self.intents.lock().expect("intents lock").clone()
    }
}

impl ControlClient for RecordingControlClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        self.intents.lock().expect("intents lock").push(intent);
        Ok(OperationReport {
            intent,
            revision: 41,
        })
    }
}
