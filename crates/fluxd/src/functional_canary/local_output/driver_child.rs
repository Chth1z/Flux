use std::error::Error;
use std::fmt;
use std::fs::File;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use flux_core::NetworkNamespaceIdentity;
use flux_platform::internal::{
    RestrictedChildCredentials, claim_inherited_seqpacket_connection,
    configure_restricted_child_process, seqpacket_inherited_descriptor,
};
use flux_platform::{PeerCredentials, PlatformError, SeqpacketConnection, SeqpacketReceive};

use super::super::{
    CANARY_PEER_SERVER_SLOTS, CanaryAttemptRequest, CanaryFlow, CanaryProcessCredentialIdentity,
};
#[cfg(test)]
use super::driver_process::DriverProcessProof;
use super::driver_process::{
    DriverProcessAuthorityError, DriverProcessRole, ReapedDriverChild, RetainedDriverChild,
    abort_unready_driver_child, retire_child_without_blocking,
};

const PROC_SELF_EXE: &str = "/proc/self/exe";
const INTERNAL_CHILD_COMMAND: &str = "__flux-canary-driver-child-v1";
const CONTROL_MAGIC: [u8; 4] = *b"FCD1";
const CONTROL_FRAME_BYTES: usize = 8;
const MAX_CHILD_LIFETIME: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PackagedDriverChildRole {
    Client = 0,
    TcpEcho = 1,
    UdpEcho = 2,
    Dns = 3,
}

impl PackagedDriverChildRole {
    const PEERS: [Self; CANARY_PEER_SERVER_SLOTS] = [Self::TcpEcho, Self::UdpEcho, Self::Dns];

    const fn process_role(self) -> DriverProcessRole {
        match self {
            Self::Client => DriverProcessRole::Client,
            Self::TcpEcho => DriverProcessRole::PeerServer { slot: 0 },
            Self::UdpEcho => DriverProcessRole::PeerServer { slot: 1 },
            Self::Dns => DriverProcessRole::PeerServer { slot: 2 },
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::TcpEcho => "tcp-echo",
            Self::UdpEcho => "udp-echo",
            Self::Dns => "dns",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "client" => Some(Self::Client),
            "tcp-echo" => Some(Self::TcpEcho),
            "udp-echo" => Some(Self::UdpEcho),
            "dns" => Some(Self::Dns),
            _ => None,
        }
    }

    const fn binding_flows(self) -> Option<(CanaryFlow, CanaryFlow)> {
        match self {
            Self::Client => None,
            Self::TcpEcho => Some((CanaryFlow::Ipv4TcpEcho, CanaryFlow::Ipv6TcpEcho)),
            Self::UdpEcho => Some((CanaryFlow::Ipv4UdpEcho, CanaryFlow::Ipv6UdpEcho)),
            Self::Dns => Some((CanaryFlow::Ipv4DnsUdp, CanaryFlow::Ipv6DnsUdp)),
        }
    }
}

impl fmt::Display for PackagedDriverChildRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChildBindPlan {
    ipv4: SocketAddr,
    ipv6: Option<SocketAddr>,
}

impl ChildBindPlan {
    fn for_request(role: PackagedDriverChildRole, request: &CanaryAttemptRequest) -> Option<Self> {
        let (ipv4_flow, ipv6_flow) = role.binding_flows()?;
        Some(Self {
            ipv4: SocketAddr::new(
                request.peer_address(ipv4_flow),
                request.responder_port(ipv4_flow).get(),
            ),
            ipv6: request.requires_flow(ipv6_flow).then(|| {
                SocketAddr::new(
                    request.peer_address(ipv6_flow),
                    request.responder_port(ipv6_flow).get(),
                )
            }),
        })
    }

    fn parse(ipv4: &str, ipv6: &str) -> Result<Option<Self>, PackagedDriverChildError> {
        if ipv4 == "-" {
            if ipv6 != "-" {
                return Err(PackagedDriverChildError::InvalidArguments(
                    "a missing IPv4 binding cannot carry an IPv6 binding",
                ));
            }
            return Ok(None);
        }
        let ipv4 = ipv4.parse::<SocketAddr>().map_err(|_| {
            PackagedDriverChildError::InvalidArguments("invalid IPv4 child bind address")
        })?;
        if !ipv4.is_ipv4() {
            return Err(PackagedDriverChildError::InvalidArguments(
                "the primary child bind address must be IPv4",
            ));
        }
        let ipv6 = if ipv6 == "-" {
            None
        } else {
            let address = ipv6.parse::<SocketAddr>().map_err(|_| {
                PackagedDriverChildError::InvalidArguments("invalid IPv6 child bind address")
            })?;
            if !address.is_ipv6() {
                return Err(PackagedDriverChildError::InvalidArguments(
                    "the secondary child bind address must be IPv6",
                ));
            }
            Some(address)
        };
        Ok(Some(Self { ipv4, ipv6 }))
    }

    fn arguments(self) -> (String, String) {
        (
            self.ipv4.to_string(),
            self.ipv6
                .map_or_else(|| "-".to_owned(), |address| address.to_string()),
        )
    }
}

/// Parent-owned packaged children. No PID-only constructor or detached child
/// path exists; every successful spawn is immediately converted into the
/// existing retained process authority.
pub(super) struct PackagedDriverChildren {
    client: PackagedDriverChild,
    peer_servers: [PackagedDriverChild; CANARY_PEER_SERVER_SLOTS],
}

impl PackagedDriverChildren {
    pub(super) fn spawn(
        request: &CanaryAttemptRequest,
        peer_network_namespace: File,
    ) -> Result<Self, PackagedDriverChildError> {
        validate_network_namespaces(request, &peer_network_namespace)?;
        let credentials = request.pre_binding().environment().probe_credentials();
        let deadline = request.deadline().expires_at();
        let [peer_namespace_0, peer_namespace_1, peer_namespace_2] = [
            clone_namespace(&peer_network_namespace)?,
            clone_namespace(&peer_network_namespace)?,
            clone_namespace(&peer_network_namespace)?,
        ];
        let client = PackagedDriverChild::spawn(
            PackagedDriverChildRole::Client,
            credentials,
            None,
            None,
            deadline,
        )?;
        let peer_0 = match PackagedDriverChild::spawn(
            PackagedDriverChildRole::PEERS[0],
            credentials,
            Some(peer_namespace_0),
            ChildBindPlan::for_request(PackagedDriverChildRole::PEERS[0], request),
            deadline,
        ) {
            Ok(child) => child,
            Err(error) => {
                client.abort_and_reap(deadline)?;
                return Err(error);
            }
        };
        let peer_1 = match PackagedDriverChild::spawn(
            PackagedDriverChildRole::PEERS[1],
            credentials,
            Some(peer_namespace_1),
            ChildBindPlan::for_request(PackagedDriverChildRole::PEERS[1], request),
            deadline,
        ) {
            Ok(child) => child,
            Err(error) => {
                let [peer_0, client] = [
                    peer_0.abort_and_reap(deadline),
                    client.abort_and_reap(deadline),
                ];
                peer_0?;
                client?;
                return Err(error);
            }
        };
        let peer_2 = match PackagedDriverChild::spawn(
            PackagedDriverChildRole::PEERS[2],
            credentials,
            Some(peer_namespace_2),
            ChildBindPlan::for_request(PackagedDriverChildRole::PEERS[2], request),
            deadline,
        ) {
            Ok(child) => child,
            Err(error) => {
                let [peer_1, peer_0, client] = [
                    peer_1.abort_and_reap(deadline),
                    peer_0.abort_and_reap(deadline),
                    client.abort_and_reap(deadline),
                ];
                peer_1?;
                peer_0?;
                client?;
                return Err(error);
            }
        };
        Ok(Self {
            client,
            peer_servers: [peer_0, peer_1, peer_2],
        })
    }

    pub(super) fn quiesce_and_reap(
        self,
        exclusive_deadline: Instant,
    ) -> Result<ReapedPackagedDriverChildren, PackagedDriverChildError> {
        let [peer_0, peer_1, peer_2] = self.peer_servers;
        // Evaluate every retirement before propagating the first error. A
        // failed control exchange must not skip orderly cleanup for siblings.
        let [client, peer_0, peer_1, peer_2] = [
            self.client.quiesce_and_reap(exclusive_deadline),
            peer_0.quiesce_and_reap(exclusive_deadline),
            peer_1.quiesce_and_reap(exclusive_deadline),
            peer_2.quiesce_and_reap(exclusive_deadline),
        ];
        Ok(ReapedPackagedDriverChildren {
            client: client?,
            peer_servers: [peer_0?, peer_1?, peer_2?],
        })
    }
}

pub(super) struct ReapedPackagedDriverChildren {
    pub(super) client: ReapedDriverChild,
    pub(super) peer_servers: [ReapedDriverChild; CANARY_PEER_SERVER_SLOTS],
}

impl ReapedPackagedDriverChildren {
    #[cfg(test)]
    fn into_process_proof(self) -> Result<DriverProcessProof, PackagedDriverChildError> {
        DriverProcessProof::new(self.client, self.peer_servers).map_err(Into::into)
    }
}

struct PackagedDriverChild {
    role: PackagedDriverChildRole,
    control: SeqpacketConnection,
    retained: RetainedDriverChild,
    credentials: RestrictedChildCredentials,
}

impl PackagedDriverChild {
    fn abort_and_reap(self, exclusive_deadline: Instant) -> Result<(), PackagedDriverChildError> {
        self.retained
            .abort_and_reap(exclusive_deadline)
            .map_err(Into::into)
    }

    fn spawn(
        role: PackagedDriverChildRole,
        credentials: CanaryProcessCredentialIdentity,
        network_namespace: Option<File>,
        binding: Option<ChildBindPlan>,
        exclusive_deadline: Instant,
    ) -> Result<Self, PackagedDriverChildError> {
        let credentials = RestrictedChildCredentials::new(credentials.uid(), credentials.gid());
        let (control, inherited) =
            SeqpacketConnection::pair().map_err(|source| PackagedDriverChildError::Platform {
                operation: "create driver-child control pair",
                source,
            })?;
        let inherited_descriptor = seqpacket_inherited_descriptor(&inherited);
        let deadline_nanos = child_monotonic_deadline(exclusive_deadline)?;
        let (ipv4, ipv6) = binding.map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            ChildBindPlan::arguments,
        );
        let mut command = Command::new(PROC_SELF_EXE);
        command
            .args([
                INTERNAL_CHILD_COMMAND,
                role.label(),
                &inherited_descriptor.to_string(),
                &deadline_nanos.to_string(),
                &ipv4,
                &ipv6,
            ])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_restricted_child_process(
            &mut command,
            credentials,
            network_namespace,
            vec![inherited_descriptor],
        )
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "configure restricted driver child",
            source,
        })?;
        Self::finish_spawn(
            role,
            credentials,
            control,
            inherited,
            command,
            exclusive_deadline,
        )
    }

    fn finish_spawn(
        role: PackagedDriverChildRole,
        credentials: RestrictedChildCredentials,
        control: SeqpacketConnection,
        inherited: SeqpacketConnection,
        mut command: Command,
        exclusive_deadline: Instant,
    ) -> Result<Self, PackagedDriverChildError> {
        let mut child = command
            .spawn()
            .map_err(|source| PackagedDriverChildError::Io {
                operation: "spawn restricted driver child",
                source,
            })?;
        drop(inherited);
        if let Err(error) = receive_child_frame(
            &control,
            child.id(),
            credentials,
            role,
            ControlMessage::Ready,
            exclusive_deadline,
        ) {
            if let Err(cleanup) =
                abort_unready_driver_child(role.process_role(), &mut child, exclusive_deadline)
            {
                retire_child_without_blocking(child);
                return Err(cleanup.into());
            }
            return Err(error);
        }
        let retained = RetainedDriverChild::open(role.process_role(), child)?;
        Ok(Self {
            role,
            control,
            retained,
            credentials,
        })
    }

    fn quiesce_and_reap(
        self,
        exclusive_deadline: Instant,
    ) -> Result<ReapedDriverChild, PackagedDriverChildError> {
        let Self {
            role,
            control,
            retained,
            credentials,
        } = self;
        if let Err(error) = send_frame(&control, role, ControlMessage::Quiesce, exclusive_deadline)
        {
            retained.abort_and_reap(exclusive_deadline)?;
            return Err(error);
        }
        if let Err(error) = receive_child_frame(
            &control,
            retained.identity().pid().get(),
            credentials,
            role,
            ControlMessage::Quiesced,
            exclusive_deadline,
        ) {
            retained.abort_and_reap(exclusive_deadline)?;
            return Err(error);
        }
        let quiesced_at = Instant::now();
        retained
            .terminate_and_reap(quiesced_at, exclusive_deadline)
            .map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ControlMessage {
    Ready = 1,
    Quiesce = 2,
    Quiesced = 3,
}

fn control_frame(role: PackagedDriverChildRole, message: ControlMessage) -> [u8; 8] {
    [
        CONTROL_MAGIC[0],
        CONTROL_MAGIC[1],
        CONTROL_MAGIC[2],
        CONTROL_MAGIC[3],
        role as u8,
        message as u8,
        0,
        0,
    ]
}

fn send_frame(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    message: ControlMessage,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let sent = control
        .send_packet_until(&control_frame(role, message), exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "send driver-child control frame",
            source,
        })?;
    if sent {
        Ok(())
    } else {
        Err(PackagedDriverChildError::DeadlineExpired(
            "send driver-child control frame",
        ))
    }
}

fn receive_child_frame(
    control: &SeqpacketConnection,
    expected_pid: u32,
    credentials: RestrictedChildCredentials,
    role: PackagedDriverChildRole,
    expected: ControlMessage,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let received = control
        .recv_record_until(CONTROL_FRAME_BYTES, exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "receive driver-child control frame",
            source,
        })?
        .ok_or(PackagedDriverChildError::DeadlineExpired(
            "receive driver-child control frame",
        ))?;
    let SeqpacketReceive::Record {
        bytes,
        truncated,
        credentials: observed,
    } = received
    else {
        return Err(PackagedDriverChildError::Protocol(
            "driver child closed its control channel before retirement",
        ));
    };
    if truncated || bytes != control_frame(role, expected) {
        return Err(PackagedDriverChildError::Protocol(
            "driver child sent a malformed, substituted, or out-of-order control frame",
        ));
    }
    validate_child_credentials(expected_pid, credentials, observed)
}

fn validate_child_credentials(
    expected_pid: u32,
    expected: RestrictedChildCredentials,
    observed: PeerCredentials,
) -> Result<(), PackagedDriverChildError> {
    if observed.pid() != expected_pid
        || observed.uid().as_raw() != expected.uid().get()
        || observed.gid() != expected.gid().get()
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver-child control credentials do not match the retained child authority",
        ));
    }
    Ok(())
}

fn child_monotonic_deadline(exclusive_deadline: Instant) -> Result<u64, PackagedDriverChildError> {
    // Sample the shared clock first and `Instant` second. Any time between the
    // samples shortens, rather than extends, the absolute child deadline.
    let raw_now = monotonic_now_nanos()?;
    let remaining = exclusive_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || remaining > MAX_CHILD_LIFETIME {
        return Err(PackagedDriverChildError::InvalidArguments(
            "driver-child lifetime is zero or exceeds the bounded maximum",
        ));
    }
    let remaining_nanos = u64::try_from(remaining.as_nanos()).map_err(|_| {
        PackagedDriverChildError::InvalidArguments(
            "driver-child remaining lifetime does not fit the monotonic clock",
        )
    })?;
    raw_now
        .checked_add(remaining_nanos)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "driver-child monotonic deadline cannot be represented",
        ))
}

fn child_instant_deadline(deadline_nanos: u64) -> Result<Instant, PackagedDriverChildError> {
    // Sample `Instant` first and the shared process monotonic clock second. Any
    // time between the samples shortens, rather than extends, the child budget.
    let now = Instant::now();
    let raw_now = monotonic_now_nanos()?;
    let remaining = deadline_nanos
        .checked_sub(raw_now)
        .map(Duration::from_nanos)
        .filter(|remaining| !remaining.is_zero() && *remaining <= MAX_CHILD_LIFETIME)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "driver-child monotonic deadline is expired or exceeds the bounded maximum",
        ))?;
    now.checked_add(remaining)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "driver-child deadline cannot be represented",
        ))
}

fn monotonic_now_nanos() -> Result<u64, PackagedDriverChildError> {
    let mut time = std::mem::MaybeUninit::<libc::timespec>::zeroed();
    // SAFETY: `time` points to writable storage for one `timespec`, and
    // `CLOCK_MONOTONIC` has no caller-owned lifetime or aliasing requirements.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(PackagedDriverChildError::Io {
            operation: "read monotonic driver-child clock",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: a successful `clock_gettime` initialized the complete value.
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec).map_err(|_| {
        PackagedDriverChildError::InvalidArguments("driver-child monotonic clock is negative")
    })?;
    let nanos = u64::try_from(time.tv_nsec)
        .ok()
        .filter(|nanos| *nanos < 1_000_000_000)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "driver-child monotonic clock nanoseconds are invalid",
        ))?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "driver-child monotonic clock cannot be represented",
        ))
}

fn clone_namespace(namespace: &File) -> Result<File, PackagedDriverChildError> {
    namespace
        .try_clone()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "duplicate retained peer network namespace",
            source,
        })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn validate_network_namespaces(
    request: &CanaryAttemptRequest,
    namespace: &File,
) -> Result<(), PackagedDriverChildError> {
    use std::os::unix::fs::MetadataExt;

    let current = std::fs::metadata("/proc/thread-self/ns/net").map_err(|source| {
        PackagedDriverChildError::Io {
            operation: "observe current driver thread network namespace",
            source,
        }
    })?;
    let current = NetworkNamespaceIdentity::new(current.dev(), current.ino()).ok_or(
        PackagedDriverChildError::Protocol(
            "current driver thread has zero network namespace identity",
        ),
    )?;
    if current
        != request
            .pre_binding()
            .environment()
            .authority()
            .network()
            .daemon_network_namespace()
    {
        return Err(PackagedDriverChildError::Protocol(
            "current driver thread network namespace does not match the immutable request",
        ));
    }
    let metadata = namespace
        .metadata()
        .map_err(|source| PackagedDriverChildError::Io {
            operation: "observe retained peer network namespace",
            source,
        })?;
    let observed = NetworkNamespaceIdentity::new(metadata.dev(), metadata.ino()).ok_or(
        PackagedDriverChildError::Protocol("retained peer network namespace has zero identity"),
    )?;
    if observed
        != request
            .pre_binding()
            .environment()
            .authority()
            .network()
            .peer_network_namespace()
    {
        return Err(PackagedDriverChildError::Protocol(
            "retained peer network namespace does not match the immutable request",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn validate_network_namespaces(
    _request: &CanaryAttemptRequest,
    _namespace: &File,
) -> Result<(), PackagedDriverChildError> {
    Err(PackagedDriverChildError::InvalidArguments(
        "packaged driver children require Linux or Android",
    ))
}

pub(super) fn try_run_internal_child(args: &[String]) -> Option<i32> {
    if args.get(1).map(String::as_str) != Some(INTERNAL_CHILD_COMMAND) {
        return None;
    }
    Some(match run_internal_child(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("fluxd: internal canary driver child failed: {error}");
            1
        }
    })
}

fn run_internal_child(args: &[String]) -> Result<(), PackagedDriverChildError> {
    if args.len() != 7 {
        return Err(PackagedDriverChildError::InvalidArguments(
            "internal driver child requires exactly five arguments",
        ));
    }
    let role = PackagedDriverChildRole::parse(&args[2]).ok_or(
        PackagedDriverChildError::InvalidArguments("unknown internal driver-child role"),
    )?;
    let descriptor = args[3]
        .parse::<i32>()
        .ok()
        .filter(|descriptor| *descriptor >= 3)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "invalid inherited driver-child control descriptor",
        ))?;
    let deadline_nanos = args[4]
        .parse::<u64>()
        .ok()
        .filter(|deadline| *deadline > 0)
        .ok_or(PackagedDriverChildError::InvalidArguments(
            "invalid driver-child monotonic deadline",
        ))?;
    let binding = ChildBindPlan::parse(&args[5], &args[6])?;
    if role.binding_flows().is_some() != binding.is_some() {
        return Err(PackagedDriverChildError::InvalidArguments(
            "driver-child role and bind plan disagree",
        ));
    }
    let deadline = child_instant_deadline(deadline_nanos)?;
    // SAFETY: argument validation requires a non-standard descriptor and this
    // child has no Rust owner for the sole endpoint inherited across exec.
    let control =
        unsafe { claim_inherited_seqpacket_connection(descriptor) }.map_err(|source| {
            PackagedDriverChildError::Platform {
                operation: "claim inherited driver-child control endpoint",
                source,
            }
        })?;
    let resources = BoundChildResources::bind(role, binding)?;
    send_frame(&control, role, ControlMessage::Ready, deadline)?;
    receive_parent_quiesce(&control, role, deadline)?;
    drop(resources);
    send_frame(&control, role, ControlMessage::Quiesced, deadline)?;

    // Parent-owned kill/reap is part of the proof. Returning here would let the
    // child self-retire and invalidate the retained-child authority.
    loop {
        std::thread::park();
    }
}

fn receive_parent_quiesce(
    control: &SeqpacketConnection,
    role: PackagedDriverChildRole,
    exclusive_deadline: Instant,
) -> Result<(), PackagedDriverChildError> {
    let received = control
        .recv_record_until(CONTROL_FRAME_BYTES, exclusive_deadline)
        .map_err(|source| PackagedDriverChildError::Platform {
            operation: "receive driver-child quiescence command",
            source,
        })?
        .ok_or(PackagedDriverChildError::DeadlineExpired(
            "receive driver-child quiescence command",
        ))?;
    let SeqpacketReceive::Record {
        bytes,
        truncated,
        credentials,
    } = received
    else {
        return Err(PackagedDriverChildError::Protocol(
            "driver-child parent closed before quiescence",
        ));
    };
    // SAFETY: getppid has no arguments, pointers, or failure mode.
    let parent_pid = u32::try_from(unsafe { libc::getppid() }).map_err(|_| {
        PackagedDriverChildError::Protocol("driver child observed an invalid parent PID")
    })?;
    if truncated
        || bytes != control_frame(role, ControlMessage::Quiesce)
        || credentials.pid() != parent_pid
    {
        return Err(PackagedDriverChildError::Protocol(
            "driver child received a malformed command or substituted parent identity",
        ));
    }
    Ok(())
}

enum BoundChildResources {
    Client,
    Tcp(Vec<TcpListener>),
    Udp(Vec<UdpSocket>),
    Dns {
        tcp: Vec<TcpListener>,
        udp: Vec<UdpSocket>,
    },
}

impl BoundChildResources {
    fn bind(
        role: PackagedDriverChildRole,
        binding: Option<ChildBindPlan>,
    ) -> Result<Self, PackagedDriverChildError> {
        match (role, binding) {
            (PackagedDriverChildRole::Client, None) => Ok(Self::Client),
            (PackagedDriverChildRole::TcpEcho, Some(binding)) => bind_tcp(binding).map(Self::Tcp),
            (PackagedDriverChildRole::UdpEcho, Some(binding)) => bind_udp(binding).map(Self::Udp),
            (PackagedDriverChildRole::Dns, Some(binding)) => Ok(Self::Dns {
                tcp: bind_tcp(binding)?,
                udp: bind_udp(binding)?,
            }),
            _ => Err(PackagedDriverChildError::InvalidArguments(
                "driver-child role and resources disagree",
            )),
        }
    }
}

fn bind_tcp(binding: ChildBindPlan) -> Result<Vec<TcpListener>, PackagedDriverChildError> {
    binding
        .ipv6
        .into_iter()
        .chain(std::iter::once(binding.ipv4))
        .map(|address| {
            TcpListener::bind(address).map_err(|source| PackagedDriverChildError::Bind {
                protocol: "TCP",
                address,
                source,
            })
        })
        .collect()
}

fn bind_udp(binding: ChildBindPlan) -> Result<Vec<UdpSocket>, PackagedDriverChildError> {
    binding
        .ipv6
        .into_iter()
        .chain(std::iter::once(binding.ipv4))
        .map(|address| {
            UdpSocket::bind(address).map_err(|source| PackagedDriverChildError::Bind {
                protocol: "UDP",
                address,
                source,
            })
        })
        .collect()
}

#[derive(Debug)]
pub(super) enum PackagedDriverChildError {
    InvalidArguments(&'static str),
    DeadlineExpired(&'static str),
    Protocol(&'static str),
    Bind {
        protocol: &'static str,
        address: SocketAddr,
        source: std::io::Error,
    },
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
    Platform {
        operation: &'static str,
        source: PlatformError,
    },
    Process(DriverProcessAuthorityError),
}

impl From<DriverProcessAuthorityError> for PackagedDriverChildError {
    fn from(source: DriverProcessAuthorityError) -> Self {
        Self::Process(source)
    }
}

impl fmt::Display for PackagedDriverChildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArguments(reason) => {
                write!(formatter, "invalid child arguments: {reason}")
            }
            Self::DeadlineExpired(operation) => {
                write!(formatter, "{operation} reached the exclusive deadline")
            }
            Self::Protocol(reason) => write!(formatter, "driver-child protocol rejected: {reason}"),
            Self::Bind {
                protocol,
                address,
                source,
            } => write!(
                formatter,
                "bind {protocol} child socket {address}: {source}"
            ),
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Platform { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::Process(source) => source.fmt(formatter),
        }
    }
}

impl Error for PackagedDriverChildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Bind { source, .. } | Self::Io { source, .. } => Some(source),
            Self::Platform { source, .. } => Some(source),
            Self::Process(source) => Some(source),
            Self::InvalidArguments(_) | Self::DeadlineExpired(_) | Self::Protocol(_) => None,
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::env;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::num::NonZeroU32;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use super::*;

    const TEST_REENTRY: &str =
        "functional_canary::local_output::driver_child::tests::packaged_driver_child_reentry";
    const TEST_CHILD_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_CHILD";
    const TEST_ROLE_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_ROLE";
    const TEST_DESCRIPTOR_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_FD";
    const TEST_DEADLINE_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_DEADLINE_NS";
    const TEST_IPV4_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_IPV4";
    const TEST_IPV6_ENV: &str = "FLUX_TEST_PACKAGED_DRIVER_IPV6";

    #[test]
    fn hidden_dispatch_does_not_intercept_the_public_cli() {
        assert_eq!(
            try_run_internal_child(&["fluxd".to_owned(), "status".to_owned()]),
            None
        );
        let error = run_internal_child(&["fluxd".to_owned(), INTERNAL_CHILD_COMMAND.to_owned()])
            .expect_err("a truncated hidden invocation must fail closed");
        assert!(matches!(
            error,
            PackagedDriverChildError::InvalidArguments(_)
        ));
    }

    #[test]
    fn hidden_dispatch_rejects_substituted_roles_descriptors_deadlines_and_bindings() {
        let deadline = child_monotonic_deadline(Instant::now() + Duration::from_secs(1))
            .expect("bounded test child deadline")
            .to_string();
        let valid = [
            "fluxd",
            INTERNAL_CHILD_COMMAND,
            "client",
            "3",
            &deadline,
            "-",
            "-",
        ];
        let overlong_deadline = monotonic_now_nanos()
            .expect("read test monotonic clock")
            .checked_add(
                u64::try_from((MAX_CHILD_LIFETIME + Duration::from_secs(5)).as_nanos())
                    .expect("bounded maximum fits u64"),
            )
            .expect("overlong test deadline fits u64")
            .to_string();
        for (index, value) in [
            (2, "unknown"),
            (3, "2"),
            (4, "0"),
            (4, overlong_deadline.as_str()),
            (5, "[::1]:5300"),
            (6, "127.0.0.1:5300"),
        ] {
            let mut args = valid.map(str::to_owned);
            args[index] = value.to_owned();
            assert!(matches!(
                run_internal_child(&args),
                Err(PackagedDriverChildError::InvalidArguments(_))
            ));
        }

        let mut client_with_binding = valid.map(str::to_owned);
        client_with_binding[5] = "127.0.0.1:5300".to_owned();
        assert!(matches!(
            run_internal_child(&client_with_binding),
            Err(PackagedDriverChildError::InvalidArguments(_))
        ));

        let mut server_without_binding = valid.map(str::to_owned);
        server_without_binding[2] = "tcp-echo".to_owned();
        assert!(matches!(
            run_internal_child(&server_without_binding),
            Err(PackagedDriverChildError::InvalidArguments(_))
        ));
    }

    #[test]
    fn absolute_child_deadline_never_extends_the_parent_instant() {
        let parent_deadline = Instant::now() + Duration::from_millis(250);
        let encoded = child_monotonic_deadline(parent_deadline)
            .expect("encode one bounded absolute monotonic deadline");
        std::thread::sleep(Duration::from_millis(2));
        let decoded = child_instant_deadline(encoded)
            .expect("decode the still-live absolute monotonic deadline");
        assert!(decoded <= parent_deadline);

        let expired = monotonic_now_nanos()
            .expect("read monotonic clock")
            .saturating_sub(1);
        assert!(matches!(
            child_instant_deadline(expired),
            Err(PackagedDriverChildError::InvalidArguments(_))
        ));
    }

    #[test]
    fn packaged_self_exec_children_hold_quiesce_and_reap_exact_roles() {
        let deadline = Instant::now() + Duration::from_secs(20);
        let tcp_address =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, available_tcp_port()));
        let udp_address =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, available_udp_port()));
        let dns_address =
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, available_dns_port()));

        let client = spawn_test_child(PackagedDriverChildRole::Client, None, deadline);
        let tcp = spawn_test_child(
            PackagedDriverChildRole::TcpEcho,
            Some(ChildBindPlan {
                ipv4: tcp_address,
                ipv6: None,
            }),
            deadline,
        );
        let udp = spawn_test_child(
            PackagedDriverChildRole::UdpEcho,
            Some(ChildBindPlan {
                ipv4: udp_address,
                ipv6: None,
            }),
            deadline,
        );
        let dns = spawn_test_child(
            PackagedDriverChildRole::Dns,
            Some(ChildBindPlan {
                ipv4: dns_address,
                ipv6: None,
            }),
            deadline,
        );

        assert!(TcpListener::bind(tcp_address).is_err());
        assert!(UdpSocket::bind(udp_address).is_err());
        assert!(TcpListener::bind(dns_address).is_err());
        assert!(UdpSocket::bind(dns_address).is_err());

        let reaped = PackagedDriverChildren {
            client,
            peer_servers: [tcp, udp, dns],
        }
        .quiesce_and_reap(deadline)
        .expect("quiesce and parent-reap every exact child");
        let proof = reaped
            .into_process_proof()
            .expect("assemble distinct retained-child proof");
        let _verified = proof
            .verify_post_reap_exit(deadline)
            .expect("observe every retained pidfd exited after parent reap");

        TcpListener::bind(tcp_address).expect("TCP echo binding retired before acknowledgement");
        UdpSocket::bind(udp_address).expect("UDP echo binding retired before acknowledgement");
        TcpListener::bind(dns_address).expect("DNS/TCP binding retired before acknowledgement");
        UdpSocket::bind(dns_address).expect("DNS/UDP binding retired before acknowledgement");
    }

    #[test]
    #[ignore = "entered only by the parent-owned self-exec lifecycle regression"]
    fn packaged_driver_child_reentry() {
        if env::var_os(TEST_CHILD_ENV).is_none() {
            return;
        }
        let args = vec![
            "fluxd-test".to_owned(),
            INTERNAL_CHILD_COMMAND.to_owned(),
            required_test_env(TEST_ROLE_ENV),
            required_test_env(TEST_DESCRIPTOR_ENV),
            required_test_env(TEST_DEADLINE_ENV),
            required_test_env(TEST_IPV4_ENV),
            required_test_env(TEST_IPV6_ENV),
        ];
        run_internal_child(&args).expect("run self-exec child reentry");
    }

    fn spawn_test_child(
        role: PackagedDriverChildRole,
        binding: Option<ChildBindPlan>,
        exclusive_deadline: Instant,
    ) -> PackagedDriverChild {
        // SAFETY: the identity getters have no arguments or failure modes.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: see the effective-UID getter above.
        let gid = unsafe { libc::getegid() };
        let (uid, gid, drop_root) = if uid == 0 || gid == 0 {
            (65_534, 65_534, true)
        } else {
            (uid, gid, false)
        };
        let credentials = RestrictedChildCredentials::new(
            NonZeroU32::new(uid).expect("test child UID is nonzero"),
            NonZeroU32::new(gid).expect("test child GID is nonzero"),
        );
        let (control, inherited) = SeqpacketConnection::pair().expect("create test control pair");
        let inherited_descriptor = seqpacket_inherited_descriptor(&inherited);
        let deadline_nanos =
            child_monotonic_deadline(exclusive_deadline).expect("bounded test child deadline");
        let (ipv4, ipv6) = binding.map_or_else(
            || ("-".to_owned(), "-".to_owned()),
            ChildBindPlan::arguments,
        );
        // SAFETY: getpid has no arguments or failure mode.
        let expected_parent = unsafe { libc::getpid() };
        let mut command = Command::new(env::current_exe().expect("resolve test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                TEST_REENTRY,
                "--nocapture",
                "--test-threads=1",
            ])
            .env_clear()
            .env(TEST_CHILD_ENV, "1")
            .env(TEST_ROLE_ENV, role.label())
            .env(TEST_DESCRIPTOR_ENV, inherited_descriptor.to_string())
            .env(TEST_DEADLINE_ENV, deadline_nanos.to_string())
            .env(TEST_IPV4_ENV, ipv4)
            .env(TEST_IPV6_ENV, ipv6)
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if drop_root {
            command.uid(uid).gid(gid);
        }
        // SAFETY: the closure runs after fork and before exec. It touches only
        // copied scalar values and uses allocation-free fcntl/prctl/PID calls.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(inherited_descriptor, libc::F_GETFD);
                if flags < 0
                    || libc::fcntl(
                        inherited_descriptor,
                        libc::F_SETFD,
                        flags & !libc::FD_CLOEXEC,
                    ) < 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != expected_parent {
                    let _ = libc::kill(libc::getpid(), libc::SIGKILL);
                    return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                }
                Ok(())
            });
        }
        PackagedDriverChild::finish_spawn(
            role,
            credentials,
            control,
            inherited,
            command,
            exclusive_deadline,
        )
        .expect("spawn retained self-exec test child")
    }

    fn required_test_env(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("{name} is required in test child reentry"))
    }

    fn available_tcp_port() -> u16 {
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve TCP test port")
            .local_addr()
            .expect("read TCP test port")
            .port()
    }

    fn available_udp_port() -> u16 {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve UDP test port")
            .local_addr()
            .expect("read UDP test port")
            .port()
    }

    fn available_dns_port() -> u16 {
        for _ in 0..32 {
            let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .expect("reserve candidate DNS/TCP port");
            let port = tcp.local_addr().expect("read DNS/TCP port").port();
            if let Ok(udp) = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)) {
                drop(udp);
                drop(tcp);
                return port;
            }
        }
        panic!("could not reserve one shared DNS UDP/TCP test port")
    }
}
