use flux_platform::SystemKernelReleaseSource;

fn main() {
    let source = SystemKernelReleaseSource;
    let exit = fluxd::run_cli(
        std::env::args(),
        &source,
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(exit);
}
