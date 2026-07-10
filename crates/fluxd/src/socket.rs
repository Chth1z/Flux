use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use flux_core::{
    ControlClient, ControlError, ControlService, KernelSupport, LegacyIntent, OperationReport,
};
use flux_platform::{PlatformError, SeqpacketConnection, SeqpacketListener};

use crate::protocol::{
    decode_control_response, decode_event_response, decode_ping_response, decode_status_response,
    encode_control_request, encode_event_request, encode_ping_request, encode_status_request,
};
use crate::{
    DaemonSnapshot, EventReport, MAX_CONTROL_PACKET_BYTES, ProtocolHandler, RequestPeerId,
};

const MAX_CONCURRENT_CONTROL_CLIENTS: usize = 16;
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
            return Err(ControlError::dispatcher(format!(
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

pub struct ControlSocketServer<C> {
    listener: SeqpacketListener,
    handler: Arc<ProtocolHandler<C>>,
    active_clients: Arc<AtomicUsize>,
}

impl<C> ControlSocketServer<C>
where
    C: ControlService + Send + Sync + 'static,
{
    pub fn bind(
        path: impl AsRef<Path>,
        kernel_support: KernelSupport,
        control: C,
    ) -> Result<Self, ControlSocketError> {
        let path = path.as_ref();
        let listener = SeqpacketListener::bind(path).map_err(ControlSocketError::Platform)?;
        Ok(Self {
            listener,
            handler: Arc::new(ProtocolHandler::new(kernel_support, control)),
            active_clients: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub fn serve_once(&self) -> Result<(), ControlSocketError> {
        let connection = self
            .listener
            .accept()
            .map_err(ControlSocketError::Platform)?;
        self.serve_connection(&connection)
    }

    pub fn serve_until<F>(&self, mut should_stop: F) -> Result<(), ControlSocketError>
    where
        F: FnMut() -> Result<bool, ControlSocketError>,
    {
        loop {
            if should_stop()? {
                return Ok(());
            }
            let Some(connection) = self
                .listener
                .accept_timeout(Duration::from_millis(250))
                .map_err(ControlSocketError::Platform)?
            else {
                continue;
            };
            self.dispatch_connection(connection);
        }
    }

    fn serve_connection(&self, connection: &SeqpacketConnection) -> Result<(), ControlSocketError> {
        serve_connection(self.handler.as_ref(), connection)
    }

    fn dispatch_connection(&self, connection: SeqpacketConnection) {
        if self
            .active_clients
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_CONTROL_CLIENTS).then_some(active.saturating_add(1))
            })
            .is_err()
        {
            eprintln!(
                "fluxd: rejected control connection: {} concurrent clients are already active",
                MAX_CONCURRENT_CONTROL_CLIENTS
            );
            return;
        }

        let handler = Arc::clone(&self.handler);
        let active_clients = Arc::clone(&self.active_clients);
        let spawn = thread::Builder::new()
            .name("flux-control-client".to_owned())
            .spawn(move || {
                let _guard = ActiveClientGuard(active_clients);
                if let Err(error) = serve_connection(handler.as_ref(), &connection) {
                    eprintln!("fluxd: rejected control connection: {error}");
                }
            });
        if let Err(error) = spawn {
            self.active_clients.fetch_sub(1, Ordering::AcqRel);
            eprintln!("fluxd: cannot start control client worker: {error}");
        }
    }

    pub fn serve_forever(&self) -> Result<(), ControlSocketError> {
        self.serve_until(|| Ok(false))
    }

    pub fn wait_for_idle(&self) {
        while self.active_clients.load(Ordering::Acquire) != 0 {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

struct ActiveClientGuard(Arc<AtomicUsize>);

impl Drop for ActiveClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_connection<C>(
    handler: &ProtocolHandler<C>,
    connection: &SeqpacketConnection,
) -> Result<(), ControlSocketError>
where
    C: ControlService,
{
    let credentials = connection
        .require_same_effective_user()
        .map_err(ControlSocketError::Platform)?;
    let request = connection
        .recv_packet(MAX_CONTROL_PACKET_BYTES)
        .map_err(ControlSocketError::Platform)?;
    let peer = RequestPeerId::new(credentials.uid(), credentials.pid());
    let response = handler.handle_for_peer(&request, peer);
    connection
        .send_packet(&response)
        .map_err(ControlSocketError::Platform)
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
