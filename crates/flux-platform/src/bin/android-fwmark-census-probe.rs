#[cfg(target_os = "android")]
use std::io::{self, Write};
#[cfg(any(target_os = "android", test))]
use std::time::Duration;

#[cfg(any(target_os = "android", test))]
use flux_core::{
    AndroidNetdSourceProfile, AndroidTproxyRoutingShape, AndroidTproxyTopologyScopeRequest,
    AndroidTproxyTrafficDomainRequest, FwmarkCandidate, NetworkAddressFamily,
};
#[cfg(any(target_os = "android", test))]
use flux_platform::AndroidFwmarkCensusCoordinatorRequest;
#[cfg(target_os = "android")]
use flux_platform::{
    AndroidFwmarkCensusCoordinatorError, AndroidFwmarkCensusCoordinatorOutcome,
    AndroidFwmarkCensusCoordinatorPurpose, AndroidFwmarkCensusProjection,
    AndroidFwmarkCensusReportPhase, SystemAndroidFwmarkCensusSource,
    SystemAndroidFwmarkCensusSourceError, SystemAndroidFwmarkCensusSourceErrorKind,
    coordinate_android_fwmark_census, validate_android_fwmark_census_projection_report,
    write_android_fwmark_census_projection_report,
};

#[cfg(target_os = "android")]
const REQUIRED_ENV: &str = "FLUX_ANDROID_FWMARK_CENSUS_REQUIRED";
#[cfg(any(target_os = "android", test))]
const CANDIDATE_MASK: u32 = 0x0300_0000;
#[cfg(any(target_os = "android", test))]
const PROXY_VALUE: u32 = 0x0100_0000;
#[cfg(any(target_os = "android", test))]
const BYPASS_VALUE: u32 = 0x0200_0000;
#[cfg(any(target_os = "android", test))]
const STAGE_BOUND: Duration = Duration::from_secs(30);

#[cfg(not(target_os = "android"))]
fn main() {
    eprintln!("android-fwmark-census-probe is available only on Android");
    std::process::exit(2);
}

#[cfg(target_os = "android")]
fn main() {
    if std::env::var(REQUIRED_ENV).as_deref() != Ok("1") {
        eprintln!("Android fwmark census probe requires explicit runner authority");
        std::process::exit(2);
    }
    if let Err(error) = collect_print_and_validate() {
        eprintln!("Android fwmark census probe: {error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "android")]
fn collect_print_and_validate() -> Result<(), String> {
    let request = diagnostic_request()?;
    let primary = collect_diagnostic(&request)?;
    let cleanup = collect_diagnostic(&request)?;

    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    write_android_fwmark_census_projection_report(
        &mut output,
        AndroidFwmarkCensusReportPhase::Primary,
        &primary,
    )
    .map_err(|_| "write-primary-report".to_owned())?;
    write_android_fwmark_census_projection_report(
        &mut output,
        AndroidFwmarkCensusReportPhase::Cleanup,
        &cleanup,
    )
    .map_err(|_| "write-cleanup-report".to_owned())?;
    output.flush().map_err(|_| "flush-reports".to_owned())?;

    validate_android_fwmark_census_projection_report(
        AndroidFwmarkCensusReportPhase::Primary,
        &primary,
    )?;
    validate_android_fwmark_census_projection_report(
        AndroidFwmarkCensusReportPhase::Cleanup,
        &cleanup,
    )
}

#[cfg(any(target_os = "android", test))]
fn diagnostic_request() -> Result<AndroidFwmarkCensusCoordinatorRequest, String> {
    let candidate = FwmarkCandidate::new(CANDIDATE_MASK, PROXY_VALUE, BYPASS_VALUE)
        .map_err(|_| "invalid-compiled-candidate".to_owned())?;
    let topology_scope = AndroidTproxyTopologyScopeRequest::new(
        AndroidTproxyRoutingShape::PreMarkAddressHostSet,
        [
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv4),
            AndroidTproxyTrafficDomainRequest::residual_local_output(NetworkAddressFamily::Ipv6),
        ],
    )
    .map_err(|_| "invalid-compiled-topology".to_owned())?;
    AndroidFwmarkCensusCoordinatorRequest::new(
        AndroidNetdSourceProfile::AospNetd20250324,
        candidate,
        topology_scope,
        STAGE_BOUND,
    )
    .map_err(|_| "invalid-compiled-request".to_owned())
}

#[cfg(target_os = "android")]
fn collect_diagnostic(
    request: &AndroidFwmarkCensusCoordinatorRequest,
) -> Result<Box<AndroidFwmarkCensusProjection>, String> {
    let mut source = SystemAndroidFwmarkCensusSource::new();
    match coordinate_android_fwmark_census(
        &mut source,
        request,
        AndroidFwmarkCensusCoordinatorPurpose::Diagnostic,
    )
    .map_err(|error| coordinator_error_label(&error))?
    {
        AndroidFwmarkCensusCoordinatorOutcome::Diagnostic(projection) => Ok(projection),
        AndroidFwmarkCensusCoordinatorOutcome::PlanningAuthority(_) => {
            Err("unexpected-planning-authority".to_owned())
        }
    }
}

#[cfg(target_os = "android")]
fn coordinator_error_label(
    error: &AndroidFwmarkCensusCoordinatorError<SystemAndroidFwmarkCensusSourceError>,
) -> String {
    match error {
        AndroidFwmarkCensusCoordinatorError::Collection { stage, source } => format!(
            "collection-{}-{}",
            stage.as_str(),
            source_error_label(source.kind())
        ),
        AndroidFwmarkCensusCoordinatorError::CapabilityDeviceIdentityUnavailable { .. } => {
            "capability-device-identity-unavailable".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::CapabilityDrift { .. } => {
            "capability-drift".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::ExternalSnapshotContextMismatch { .. } => {
            "external-snapshot-context-mismatch".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::ExternalSnapshotDrift { .. } => {
            "external-snapshot-drift".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::Policy(_) => "policy-binding".to_owned(),
        AndroidFwmarkCensusCoordinatorError::SelectedNetdSourceProfileMismatch { .. } => {
            "selected-netd-source-profile-mismatch".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::Topology(_) => "topology-assessment".to_owned(),
        AndroidFwmarkCensusCoordinatorError::Rpdb(_) => "rpdb-projection".to_owned(),
        AndroidFwmarkCensusCoordinatorError::Assembly(_) => "projection-assembly".to_owned(),
        AndroidFwmarkCensusCoordinatorError::CompleteCensus(_) => {
            "unexpected-complete-census".to_owned()
        }
        AndroidFwmarkCensusCoordinatorError::Authorization(_) => {
            "unexpected-authorization".to_owned()
        }
    }
}

#[cfg(target_os = "android")]
const fn source_error_label(kind: SystemAndroidFwmarkCensusSourceErrorKind) -> &'static str {
    match kind {
        SystemAndroidFwmarkCensusSourceErrorKind::InvalidCapabilityStage => {
            "invalid-capability-stage"
        }
        SystemAndroidFwmarkCensusSourceErrorKind::InvalidBound => "invalid-bound",
        SystemAndroidFwmarkCensusSourceErrorKind::DeadlineExceeded => "deadline-exceeded",
        SystemAndroidFwmarkCensusSourceErrorKind::XtablesProcess => "xtables-process",
        SystemAndroidFwmarkCensusSourceErrorKind::XtablesObservation => "xtables-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::NftablesObservation => "nftables-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::TrafficControlBpfObservation => {
            "traffic-control-bpf-observation"
        }
        SystemAndroidFwmarkCensusSourceErrorKind::XfrmObservation => "xfrm-observation",
        SystemAndroidFwmarkCensusSourceErrorKind::NetworkInventory => "network-inventory",
        SystemAndroidFwmarkCensusSourceErrorKind::ExistingFluxOwnership => {
            "existing-flux-ownership"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_request_pins_profile_candidate_scope_and_bound() {
        let request = diagnostic_request().expect("compiled diagnostic request");
        assert_eq!(
            request.netd_source_profile(),
            AndroidNetdSourceProfile::AospNetd20250324
        );
        assert_eq!(request.candidate().mask(), CANDIDATE_MASK);
        assert_eq!(request.candidate().proxy_value(), PROXY_VALUE);
        assert_eq!(request.candidate().bypass_value(), BYPASS_VALUE);
        assert_eq!(request.stage_bound(), STAGE_BOUND);
        assert_eq!(
            request.topology_scope().shape(),
            AndroidTproxyRoutingShape::PreMarkAddressHostSet
        );
        assert_eq!(
            request.topology_scope().domains(),
            [
                AndroidTproxyTrafficDomainRequest::residual_local_output(
                    NetworkAddressFamily::Ipv4
                ),
                AndroidTproxyTrafficDomainRequest::residual_local_output(
                    NetworkAddressFamily::Ipv6
                ),
            ]
        );
    }
}
