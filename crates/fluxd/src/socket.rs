use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use flux_core::{
    CapabilityProfile, ControlClient, ControlError, ControlService, LegacyIntent, OperationReport,
};
use flux_platform::{PlatformError, ReactorError, SeqpacketConnection};

use crate::protocol::{
    decode_control_response, decode_event_response, decode_ping_response, decode_status_response,
    encode_control_request, encode_event_request, encode_ping_request, encode_status_request,
};
use crate::{
    DaemonSnapshot, EventReport, MAX_CONTROL_PACKET_BYTES, ProtocolHandler, RequestPeerId,
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

    pub fn send_event(
        &self,
        event_type: &str,
        watched_path: &str,
        event_name: &str,
    ) -> Result<EventReport, ControlError> {
        let request_id = self.next_request_id();
        let request = encode_event_request(request_id, event_type, watched_path, event_name)?;
        let response = self.exchange(&request)?;
        decode_event_response(&response, request_id)
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
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
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
    pub fn new(capability_profile: Arc<CapabilityProfile>, control: C) -> Self {
        Self {
            handler: ProtocolHandler::new(capability_profile, control),
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
