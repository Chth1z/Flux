use flux_platform::{SystemCapabilityProfileSource, SystemKernelReleaseSource};

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args
        .get(1)
        .is_some_and(|command| command == "render-legacy-rules")
    {
        let exit = fluxd::run_legacy_rules_cli(
            &args,
            &fluxd::ProcessLegacyRulesEnvironment,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        );
        std::process::exit(exit);
    }
    if args
        .get(1)
        .is_some_and(|command| command == "snapshot-legacy-packages")
    {
        let exit = fluxd::run_legacy_package_snapshot_cli(
            &args,
            &mut std::io::stdout(),
            &mut std::io::stderr(),
        );
        std::process::exit(exit);
    }
    let source = SystemKernelReleaseSource;
    if args.get(1).is_some_and(|command| command == "daemon") {
        if args.len() != 2 {
            eprintln!("fluxd: daemon does not accept positional arguments");
            std::process::exit(2);
        }
        let options = match fluxd::DaemonOptions::from_environment() {
            Ok(options) => options,
            Err(error) => {
                eprintln!("fluxd: {error}");
                std::process::exit(1);
            }
        };
        let profile_source = SystemCapabilityProfileSource::new(options.capability_profile_paths());
        if let Err(error) = fluxd::run_daemon(&profile_source, options) {
            eprintln!("fluxd: {error}");
            std::process::exit(1);
        }
        return;
    }

    let socket_path = std::env::var_os("FLUXD_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/data/adb/flux/run/fluxd.sock"));
    let client = fluxd::SocketControlClient::new(socket_path);
    let exit = fluxd::run_cli_with_daemon(
        args,
        &source,
        &client,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(exit);
}
