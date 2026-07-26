#![cfg(any(target_os = "linux", target_os = "android"))]

use std::fs;
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

use flux_core::AdministrativeState;
use fluxd::{
    RuntimeCaptureState, RuntimeEngineState, RuntimePhase, RuntimeVerificationState,
    SocketControlClient,
};

const SIGTERM: std::ffi::c_int = 15;
const PACKAGED_CONFIG: &str = include_str!("../../../conf/flux.toml");

unsafe extern "C" {
    fn kill(process: std::ffi::c_int, signal: std::ffi::c_int) -> std::ffi::c_int;
}

#[test]
fn native_file_observation_drives_lifecycle_and_sigterm_stops_daemon_cleanly() {
    let directory = tempdir().expect("temporary directory");
    let root = directory.path().join("flux");
    let socket_path = root.join("run/fluxd.sock");
    let dispatcher_record = root.join("run/dispatcher.record");
    let boot_id_path = directory.path().join("boot-id");
    let selinux_enforce_path = directory.path().join("selinux-enforce");
    let disable_path = directory.path().join("disable");
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve listener port");
    let listener_port = listener.local_addr().expect("listener address").port();
    drop(listener);

    fs::create_dir_all(root.join("scripts")).expect("create scripts directory");
    fs::create_dir_all(root.join("bin")).expect("create binary directory");
    fs::create_dir_all(root.join("conf")).expect("create config directory");
    fs::create_dir_all(root.join("state")).expect("create state directory");
    fs::create_dir_all(root.join("run")).expect("create run directory");
    let configured = PACKAGED_CONFIG
        .replacen(
            "/data/adb/flux/bin/sing-box",
            root.join("bin/sing-box")
                .to_str()
                .expect("UTF-8 engine fixture path"),
            1,
        )
        .replacen(
            "/data/adb/flux/conf/template.json",
            root.join("conf/template.json")
                .to_str()
                .expect("UTF-8 template fixture path"),
            1,
        )
        .replacen(
            "/data/adb/flux/conf/subscription.url",
            root.join("conf/subscription.url")
                .to_str()
                .expect("UTF-8 subscription URL fixture path"),
            1,
        )
        .replacen("port = 1536", &format!("port = {listener_port}"), 1);
    fs::write(root.join("conf/flux.toml"), configured).expect("write configuration");
    fs::write(
        root.join("conf/template.json"),
        concat!(
            "{\"dns\":{\"servers\":[{\"type\":\"fakeip\",",
            "\"inet4_range\":\"198.18.0.0/15\",",
            "\"inet6_range\":\"fc00::/18\"}]},\"inbounds\":[]}\n"
        ),
    )
    .expect("write engine template");
    fs::write(root.join("conf/subscription.url"), "").expect("write subscription URL file");
    fs::write(root.join("conf/config.json"), "{}\n").expect("write engine configuration");
    fs::write(&boot_id_path, "33333333-3333-4333-8333-333333333333\n").expect("write boot ID");
    fs::write(&selinux_enforce_path, "1\n").expect("write SELinux mode");
    write_script(
        &root.join("scripts/dispatcher"),
        &format!(
            "set -eu\n\
             command=${{1:-}}\n\
             printf '%s\\n' \"$command\" >> '{}'\n\
             if [ \"$command\" = prepare ]; then\n\
                 generation_file='{}'\n\
                 generation=0\n\
                 [ ! -f \"$generation_file\" ] || generation=$(cat \"$generation_file\")\n\
                 generation=$((generation + 1))\n\
                 printf '%s\\n' \"$generation\" > \"$generation_file\"\n\
                 cat > '{}' <<EOF\n\
FLUX_ENGINE_MANIFEST_V1\n\
generation=$generation\n\
binary={}\n\
config={}\n\
working_directory={}\n\
log={}\n\
launcher=direct\n\
readiness=listener\n\
startup_timeout_ms=5000\n\
stop_timeout_ms=5000\n\
listener_port={}\n\
EOF\n\
             fi\n\
             exit 0\n",
            dispatcher_record.display(),
            root.join("run/test-generation").display(),
            root.join("run/engine.manifest").display(),
            root.join("bin/sing-box").display(),
            root.join("conf/config.json").display(),
            root.join("run").display(),
            root.join("run/sing-box.log").display(),
            listener_port,
        ),
    );
    write_script(&root.join("scripts/addrsync"), "exit 0\n");
    write_script(
        &root.join("bin/sing-box"),
        &format!(
            "set -eu\n\
             case \"${{1:-}}\" in\n\
                 check) exit 0 ;;\n\
                 run) exec python3 -c 'import signal, socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"127.0.0.1\", {listener_port})); s.listen(); signal.pause()' ;;\n\
                 *) exit 64 ;;\n\
             esac\n"
        ),
    );

    let mut child = Command::new(fluxd_binary())
        .arg("daemon")
        .env("FLUX_ROOT", &root)
        .env("FLUXD_SOCKET", &socket_path)
        .env("FLUX_BOOT_ID_PATH", &boot_id_path)
        .env("FLUX_SELINUX_ENFORCE_PATH", &selinux_enforce_path)
        .env("FLUX_DISABLE_PATH", &disable_path)
        .env("FLUX_SHELL", "/bin/sh")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start fluxd daemon");

    wait_for_daemon_ready(&mut child, &socket_path, &dispatcher_record);
    let snapshot = SocketControlClient::new(&socket_path)
        .status()
        .expect("read live daemon status");
    assert_eq!(snapshot.runtime.phase, RuntimePhase::Running);
    assert_eq!(snapshot.runtime.capture, RuntimeCaptureState::Published);
    assert_eq!(snapshot.runtime.engine, RuntimeEngineState::Ready);
    assert_eq!(
        snapshot.runtime.verification,
        RuntimeVerificationState::StructuralOnly
    );
    assert_eq!(snapshot.runtime.generation, Some(1));

    fs::write(&disable_path, "").expect("create disable entry");
    wait_until(Duration::from_secs(3), || {
        SocketControlClient::new(&socket_path)
            .status()
            .is_ok_and(|snapshot| {
                snapshot.control.administrative_state == AdministrativeState::Stopped
                    && snapshot.runtime.phase == RuntimePhase::Stopped
            })
    });

    fs::remove_file(&disable_path).expect("remove disable entry");
    wait_until(Duration::from_secs(3), || {
        SocketControlClient::new(&socket_path)
            .status()
            .is_ok_and(|snapshot| {
                snapshot.control.administrative_state == AdministrativeState::Running
                    && snapshot.runtime.phase == RuntimePhase::Running
                    && snapshot.runtime.generation == Some(2)
            })
    });

    let template_replacement = root.join("conf/template.next");
    fs::write(
        &template_replacement,
        concat!(
            "{\"dns\":{\"servers\":[{\"type\":\"fakeip\",",
            "\"inet4_range\":\"198.18.0.0/15\",",
            "\"inet6_range\":\"fc00::/18\"}]},\"inbounds\":[]}\n\n"
        ),
    )
    .expect("write replacement engine template");
    fs::rename(&template_replacement, root.join("conf/template.json"))
        .expect("atomically replace engine template");
    wait_until(Duration::from_secs(3), || {
        SocketControlClient::new(&socket_path)
            .status()
            .is_ok_and(|snapshot| {
                snapshot.runtime.phase == RuntimePhase::Running
                    && snapshot.runtime.generation == Some(3)
            })
    });

    // SAFETY: `child.id()` names the live daemon process observed ready above.
    assert_eq!(unsafe { kill(child.id() as std::ffi::c_int, SIGTERM) }, 0);

    let status = wait_for_exit(&mut child, Duration::from_secs(3)).unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon did not stop after SIGTERM");
    });
    assert!(
        status.success(),
        "daemon must consume SIGTERM through signalfd, not terminate from signal {:?}: {status}",
        status.signal()
    );
    let phases = fs::read_to_string(&dispatcher_record).expect("dispatcher phase record");
    assert_eq!(
        phases.lines().collect::<Vec<_>>(),
        [
            "startup-recover",
            "prepare",
            "capture-start",
            "capture-verify",
            "state-running",
            "capture-stop",
            "state-stopped",
            "prepare",
            "capture-start",
            "capture-verify",
            "state-running",
            "prepare",
            "capture-stop",
            "capture-start",
            "capture-verify",
            "state-running",
            "capture-stop",
            "state-stopped",
        ]
    );
}

fn fluxd_binary() -> std::path::PathBuf {
    std::env::current_exe()
        .expect("current test executable")
        .parent()
        .and_then(Path::parent)
        .expect("Cargo target debug directory")
        .join("fluxd")
}

fn write_script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    let mut permissions = fs::metadata(path).expect("script metadata").permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).expect("script permissions");
}

fn wait_for_daemon_ready(child: &mut Child, socket_path: &Path, dispatcher_record: &Path) {
    let deadline = Instant::now() + Duration::from_secs(7);
    loop {
        if socket_path.exists() && dispatcher_record.exists() {
            return;
        }
        if let Some(status) = child.try_wait().expect("inspect daemon status") {
            panic!("daemon exited before becoming ready: {status}");
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("inspect daemon status") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + timeout;
    while !condition() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(10));
    }
}
