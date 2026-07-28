use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use flux_core::{
    CapabilityProfile, ControlClient, ControlError, ControlService, OperationReport, RuntimeIntent,
};
use flux_platform::{PlatformError, ReactorError, SeqpacketConnection};

use crate::inspection::InspectionSource;
use crate::protocol::{
    decode_control_response, decode_diagnose_response, decode_explain_response,
    decode_logs_response, decode_ping_response, decode_status_response,
    decode_subscription_update_response, encode_control_request, encode_diagnose_request,
    encode_explain_request, encode_logs_request, encode_ping_request, encode_status_request,
    encode_subscription_update_request,
};
use crate::subscription::{SubscriptionRefreshClient, SubscriptionRefreshReport};
use crate::{
    DaemonSnapshot, DiagnosticReport, ExplainReport, LogReport, LogStream,
    MAX_CONTROL_PACKET_BYTES, NativeAdmissionState, ProtocolHandler, RequestPeerId,
    RuntimeSnapshotSource,
};

static NEXT_CONTROL_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub struct SocketControlClient {
    path: PathBuf,
}

impl SocketControlClient {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }

    pub fn ping(&self) -> Result<(), ControlError> {
        let request_id = self.next_request_id();
        let request = encode_ping_request(request_id)?;
        let response = self.exchange(&request)?;
        decode_ping_response(&response, request_id)
    }

    pub fn status(&self) -> Result<DaemonSnapshot, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_status_request(request_id)?;
        let response = self.exchange(&request)?;
        decode_status_response(&response, request_id)
    }

    pub fn update_subscription(&self) -> Result<SubscriptionRefreshReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_subscription_update_request(request_id)?;
        let response = self.exchange(&request)?;
        decode_subscription_update_response(&response, request_id)
    }

    pub fn diagnose(&self) -> Result<DiagnosticReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_diagnose_request(request_id)?;
        let response = self.exchange(&request)?;
        decode_diagnose_response(&response, request_id)
    }

    pub fn logs(&self, stream: LogStream, lines: u16) -> Result<LogReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_logs_request(request_id, stream, lines)?;
        let response = self.exchange(&request)?;
        decode_logs_response(&response, request_id, stream, lines)
    }

    pub fn explain(&self) -> Result<ExplainReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_explain_request(request_id)?;
        let response = self.exchange(&request)?;
        decode_explain_response(&response, request_id)
    }

    fn next_request_id(&self) -> u64 {
        NEXT_CONTROL_REQUEST_ID.fetch_add(1, Ordering::Relaxed)
    }

    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, ControlError> {
        if request.len() > MAX_CONTROL_PACKET_BYTES {
            return Err(ControlError::protocol(format!(
                "control request exceeds {MAX_CONTROL_PACKET_BYTES} bytes"
            )));
        }
        let connection =
            SeqpacketConnection::connect(&self.path).map_err(control_transport_error)?;
        connection
            .send_packet(request)
            .map_err(control_transport_error)?;
        connection
            .recv_packet(MAX_CONTROL_PACKET_BYTES)
            .map_err(control_transport_error)
    }
}

impl ControlClient for SocketControlClient {
    fn submit_and_wait(&self, intent: RuntimeIntent) -> Result<OperationReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_control_request(request_id, intent)?;
        let response = self.exchange(&request)?;
        decode_control_response(&response, request_id, intent)
    }
}

pub struct ControlConnectionHandler<C> {
    handler: ProtocolHandler<C>,
}

impl<C> ControlConnectionHandler<C>
where
    C: ControlService,
{
    #[must_use]
    pub fn new(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
    ) -> Self {
        Self {
            handler: ProtocolHandler::new(capability_profile, native_admission, control),
        }
    }

    #[must_use]
    pub fn with_runtime_snapshot_source(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
    ) -> Self {
        Self {
            handler: ProtocolHandler::with_runtime_snapshot_source(
                capability_profile,
                native_admission,
                control,
                runtime,
            ),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_runtime_snapshot_and_subscription(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
        subscription: Option<SubscriptionRefreshClient>,
    ) -> Self {
        Self {
            handler: ProtocolHandler::with_runtime_snapshot_and_subscription(
                capability_profile,
                native_admission,
                control,
                runtime,
                subscription,
            ),
        }
    }

    #[must_use]
    pub(crate) fn with_runtime_subscription_and_inspection(
        capability_profile: Arc<CapabilityProfile>,
        native_admission: NativeAdmissionState,
        control: C,
        runtime: RuntimeSnapshotSource,
        subscription: Option<SubscriptionRefreshClient>,
        inspection: Arc<dyn InspectionSource>,
    ) -> Self {
        Self {
            handler: ProtocolHandler::with_runtime_subscription_and_inspection(
                capability_profile,
                native_admission,
                control,
                runtime,
                subscription,
                Some(inspection),
            ),
        }
    }

    pub fn serve(&self, connection: SeqpacketConnection) -> Result<(), ControlSocketError> {
        let credentials = connection
            .require_same_effective_user()
            .map_err(ControlSocketError::Platform)?;
        let request = connection
            .recv_packet(MAX_CONTROL_PACKET_BYTES)
            .map_err(ControlSocketError::Platform)?;
        let peer = RequestPeerId::new(credentials.uid(), credentials.pid());
        let response = self.handler.handle_for_peer(&request, peer);
        connection
            .send_packet(&response)
            .map_err(ControlSocketError::Platform)
    }
}

#[derive(Debug)]
pub enum ControlSocketError {
    Platform(PlatformError),
    Reactor(ReactorError),
}

impl fmt::Display for ControlSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(formatter, "control socket: {error}"),
            Self::Reactor(error) => write!(formatter, "control reactor: {error}"),
        }
    }
}

impl Error for ControlSocketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
            Self::Reactor(error) => Some(error),
        }
    }
}

fn control_transport_error(error: PlatformError) -> ControlError {
    ControlError::transport(error.to_string())
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use flux_core::{DispatcherCompletion, RuntimeControl, RuntimeDispatcher};
    use flux_platform::{DaemonReactor, ShutdownSignal};
    use flux_testkit::CapabilityProfileFixture;
    use tempfile::tempdir;

    use super::*;
    use crate::SubscriptionRefreshReport;

    struct NoopDispatcher;

    impl RuntimeDispatcher for NoopDispatcher {
        fn execute(
            &mut self,
            intent: &RuntimeIntent,
        ) -> Result<DispatcherCompletion, ControlError> {
            Ok(match intent {
                RuntimeIntent::ResyncAddresses { .. } => DispatcherCompletion::AddressResync(
                    flux_core::AddressResyncDisposition::CompleteNoChange,
                ),
                _ => DispatcherCompletion::Completed,
            })
        }
    }

    #[test]
    fn seqpacket_subscription_update_round_trips_the_typed_report() {
        let directory = tempdir().expect("temporary directory");
        let socket_path = directory.path().join("fluxd.sock");
        let shutdown = ShutdownSignal::install().expect("install shutdown signal source");
        let refreshes = Arc::new(AtomicUsize::new(0));
        let refresh_calls = Arc::clone(&refreshes);
        let subscription = SubscriptionRefreshClient::for_test(move || {
            refresh_calls.fetch_add(1, Ordering::SeqCst);
            Ok(SubscriptionRefreshReport::updated(
                flux_core::GenerationId::new(82).expect("test Generation"),
                29,
                false,
            ))
        });
        let runtime = RuntimeControl::start(NoopDispatcher, 2).expect("start runtime");
        let handler = ControlConnectionHandler::with_runtime_snapshot_and_subscription(
            Arc::new(CapabilityProfileFixture::supported()),
            NativeAdmissionState::Admitted,
            runtime,
            RuntimeSnapshotSource::default(),
            Some(subscription),
        );
        let (reactor, stop) = DaemonReactor::bind(&socket_path, shutdown, move |connection| {
            handler.serve(connection).expect("serve control connection");
        })
        .expect("bind reactor");
        let client_path = socket_path.clone();
        let client_thread = thread::spawn(move || {
            let report = SocketControlClient::new(client_path)
                .update_subscription()
                .expect("subscription update");
            stop.request_stop().expect("request reactor stop");
            report
        });

        reactor.run().expect("run reactor");
        let report = client_thread.join().expect("client thread");

        assert_eq!(
            report,
            SubscriptionRefreshReport::updated(
                flux_core::GenerationId::new(82).expect("test Generation"),
                29,
                false,
            )
        );
        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    }
}
