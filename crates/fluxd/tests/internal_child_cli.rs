use std::process::Command;

#[test]
fn hidden_canary_child_dispatch_precedes_public_cli_parsing() {
    let output = Command::new(env!("CARGO_BIN_EXE_fluxd"))
        .arg("__flux-canary-driver-child-v1")
        .output()
        .expect("run packaged fluxd binary");

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 internal-child diagnostic");
    assert!(stderr.starts_with("fluxd: internal canary driver child failed: "));
    assert!(stderr.contains("requires exactly five arguments"));
    assert!(!stderr.contains("unknown command"));
}

#[test]
fn ordinary_cli_commands_do_not_enter_hidden_dispatch() {
    let output = Command::new(env!("CARGO_BIN_EXE_fluxd"))
        .arg("--version")
        .output()
        .expect("run packaged fluxd version command");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 version output"),
        format!("fluxd {}\n", env!("CARGO_PKG_VERSION"))
    );
    assert!(output.stderr.is_empty());
}
