use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use flux_platform::SeqpacketConnectionHandoffReceive;
use flux_platform::internal::{SING_BOX_LAUNCH_CONTROL_FD_ENV, SingBoxLaunchControl};
use serde_json::Value;

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const FAIL_CHECK_ENV: &str = "FLUX_NATIVE_COMPOSITION_FAIL_CHECK";
const PID_LOG_ENV: &str = "FLUX_NATIVE_COMPOSITION_ENGINE_PID_LOG";
const CONTROL_EVIDENCE_FIELD: &str = "flux_test_launch_control_evidence";
const CONTROL_FRAME_FILE: &str = "frame.bin";
const CONTROL_SENDER_FILE: &str = "sender.txt";
const CONTROL_COMPLETE_FILE: &str = "complete";

fn main() {
    if let Err(error) = run(env::args_os().skip(1).collect()) {
        eprintln!("native composition engine fixture: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<std::ffi::OsString>) -> Result<(), String> {
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Err("missing UTF-8 command".to_owned());
    };
    match command {
        "version" if arguments.len() == 1 => {
            reject_probe_launch_control("version")?;
            println!("sing-box version 1.13.14");
            Ok(())
        }
        "check" => {
            reject_probe_launch_control("check")?;
            let (config, _working_directory) = parse_runtime_arguments(&arguments[1..])?;
            let _ = read_config(&config)?;
            if let Some(marker) = env::var_os(FAIL_CHECK_ENV).map(PathBuf::from)
                && marker.exists()
            {
                fs::remove_file(&marker).map_err(|error| {
                    format!(
                        "remove one-shot check failure marker {}: {error}",
                        marker.display()
                    )
                })?;
                return Err("injected one-shot candidate validation failure".to_owned());
            }
            Ok(())
        }
        "run" => {
            let (config, _working_directory) = parse_runtime_arguments(&arguments[1..])?;
            let config = read_config(&config)?;
            let port = listener_port(&config)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
                .map_err(|error| format!("bind fixture listener 127.0.0.1:{port}: {error}"))?;
            record_pid(port)?;
            if let Some(evidence) = control_evidence_path(&config)? {
                capture_launch_control(&evidence)?;
            }
            loop {
                std::thread::park();
                std::hint::black_box(&listener);
            }
        }
        _ => Err(format!("unsupported command or arguments: {arguments:?}")),
    }
}

fn parse_runtime_arguments(arguments: &[std::ffi::OsString]) -> Result<(PathBuf, PathBuf), String> {
    if arguments.len() != 4 || arguments[0] != "-c" || arguments[2] != "-D" {
        return Err(format!(
            "expected '-c CONFIG -D DIRECTORY', found {arguments:?}"
        ));
    }
    Ok((PathBuf::from(&arguments[1]), PathBuf::from(&arguments[3])))
}

fn read_config(path: &Path) -> Result<Value, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("inspect config {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(format!(
            "config {} must be a regular file no larger than {MAX_CONFIG_BYTES} bytes",
            path.display()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("read config {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse config {}: {error}", path.display()))
}

fn listener_port(config: &Value) -> Result<u16, String> {
    let port = config
        .get("inbounds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|inbound| inbound.get("type").and_then(Value::as_str) == Some("tproxy"))
        .and_then(|inbound| inbound.get("listen_port"))
        .and_then(Value::as_u64)
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or_else(|| "config has no nonzero tproxy listen_port".to_owned())?;
    Ok(port)
}

fn record_pid(port: u16) -> Result<(), String> {
    let Some(path) = env::var_os(PID_LOG_ENV).map(PathBuf::from) else {
        return Ok(());
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("open PID log {}: {error}", path.display()))?;
    writeln!(file, "{}\t{port}", std::process::id())
        .map_err(|error| format!("append PID log {}: {error}", path.display()))
}

fn control_evidence_path(config: &Value) -> Result<Option<PathBuf>, String> {
    let Some(value) = config.get(CONTROL_EVIDENCE_FIELD) else {
        return Ok(None);
    };
    let path = value
        .as_str()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("{CONTROL_EVIDENCE_FIELD} must be one nonempty string"))?;
    if !path.is_absolute() {
        return Err(format!("{CONTROL_EVIDENCE_FIELD} must be absolute"));
    }
    Ok(Some(path))
}

fn reject_probe_launch_control(command: &str) -> Result<(), String> {
    if env::var_os(SING_BOX_LAUNCH_CONTROL_FD_ENV).is_none() {
        Ok(())
    } else {
        Err(format!(
            "{command} probe inherited forbidden {SING_BOX_LAUNCH_CONTROL_FD_ENV}"
        ))
    }
}

fn capture_launch_control(evidence: &Path) -> Result<(), String> {
    // SAFETY: this exact exec fixture has not claimed any inherited descriptor. The pinned parent
    // supplies the fixed key for its sole admitted child endpoint before this single-threaded call.
    let control = unsafe { SingBoxLaunchControl::claim_inherited() }
        .map_err(|error| format!("claim launch control: {error}"))?
        .ok_or_else(|| "launch control descriptor environment is absent".to_owned())?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let received = control
        .recv_connection_until(4 * 1024, deadline)
        .map_err(|error| format!("receive launch handoff: {error}"))?
        .ok_or_else(|| "launch handoff deadline expired".to_owned())?;
    let SeqpacketConnectionHandoffReceive::Record {
        bytes,
        credentials,
        connection,
    } = received
    else {
        return Err("launch control reached EOF before attempt handoff".to_owned());
    };
    fs::create_dir_all(evidence).map_err(|error| {
        format!(
            "create launch-control evidence directory {}: {error}",
            evidence.display()
        )
    })?;
    fs::write(evidence.join(CONTROL_FRAME_FILE), bytes).map_err(|error| {
        format!(
            "write launch-control frame {}: {error}",
            evidence.join(CONTROL_FRAME_FILE).display()
        )
    })?;
    fs::write(
        evidence.join(CONTROL_SENDER_FILE),
        format!(
            "{}\t{}\t{}\n",
            credentials.pid(),
            credentials.uid(),
            credentials.gid()
        ),
    )
    .map_err(|error| {
        format!(
            "write launch-control sender {}: {error}",
            evidence.join(CONTROL_SENDER_FILE).display()
        )
    })?;
    connection
        .send_packet(b"flux-native-control-producer")
        .map_err(|error| format!("send producer endpoint proof: {error}"))?;
    drop(connection);
    drop(control);
    fs::write(evidence.join(CONTROL_COMPLETE_FILE), b"complete\n").map_err(|error| {
        format!(
            "publish launch-control completion {}: {error}",
            evidence.join(CONTROL_COMPLETE_FILE).display()
        )
    })
}
