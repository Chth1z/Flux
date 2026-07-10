use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flux_core::{ControlClient, ControlError, KernelSupport, LegacyIntent, OperationReport};
use flux_platform::{PlatformError, SeqpacketConnection, SeqpacketListener};

use crate::protocol::{decode_control_response, encode_control_request};
use crate::{MAX_CONTROL_PACKET_BYTES, ProtocolHandler};

#[derive(Debug)]
pub struct SocketControlClient {
    path: PathBuf,
    next_request_id: AtomicU64,
}

impl SocketControlClient {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            next_request_id: AtomicU64::new(1),
        }
    }
}

impl ControlClient for SocketControlClient {
    fn submit_and_wait(&self, intent: LegacyIntent) -> Result<OperationReport, ControlError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let request = encode_control_request(request_id, intent)?;
        let connection =
            SeqpacketConnection::connect(&self.path).map_err(control_transport_error)?;
        connection
            .send_packet(&request)
            .map_err(control_transport_error)?;
        let response = connection
            .recv_packet(MAX_CONTROL_PACKET_BYTES)
            .map_err(control_transport_error)?;
        decode_control_response(&response, request_id, intent)
    }
}

pub struct ControlSocketServer<C> {
    listener: SeqpacketListener,
    handler: ProtocolHandler<C>,
}

impl<C> ControlSocketServer<C>
where
    C: ControlClient,
{
    pub fn bind(
        path: impl AsRef<Path>,
        kernel_support: KernelSupport,
        control: C,
    ) -> Result<Self, ControlSocketError> {
        Ok(Self {
            listener: SeqpacketListener::bind(path).map_err(ControlSocketError::Platform)?,
            handler: ProtocolHandler::new(kernel_support, control),
        })
    }

    pub fn serve_once(&self) -> Result<(), ControlSocketError> {
        let connection = self
            .listener
            .accept()
            .map_err(ControlSocketError::Platform)?;
        let request = connection
            .recv_packet(MAX_CONTROL_PACKET_BYTES)
            .map_err(ControlSocketError::Platform)?;
        let response = self.handler.handle(&request);
        connection
            .send_packet(&response)
            .map_err(ControlSocketError::Platform)
    }

    pub fn serve_forever(&self) -> Result<(), ControlSocketError> {
        loop {
            self.serve_once()?;
        }
    }
}

#[derive(Debug)]
pub enum ControlSocketError {
    Platform(PlatformError),
}

impl fmt::Display for ControlSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Platform(error) => write!(formatter, "control socket: {error}"),
        }
    }
}

impl Error for ControlSocketError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Platform(error) => Some(error),
        }
    }
}

fn control_transport_error(error: PlatformError) -> ControlError {
    ControlError::dispatcher(format!("control socket transport: {error}"))
}
