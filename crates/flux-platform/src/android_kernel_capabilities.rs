use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use flux_core::CapturePathId;
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::fs::{self, File};
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::io::Read;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "android"))]
use flate2::read::MultiGzDecoder;

pub const ANDROID_KERNEL_CONFIG_DIGEST_BYTES: usize = 32;
pub const MAX_ANDROID_KERNEL_CONFIG_COMPRESSED_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_ANDROID_KERNEL_CONFIG_LINE_BYTES: usize = 4 * 1024;
pub const MAX_ANDROID_KERNEL_CONFIG_OPTIONS: usize = 65_536;
pub const ANDROID_CAPTURE_PATH_COUNT: usize = 3;

const MAX_ANDROID_KERNEL_CONFIG_SYMBOL_BYTES: usize = 192;
const DEFAULT_ANDROID_KERNEL_CONFIG_PATH: &str = "/proc/config.gz";
const KERNEL_CONFIG_DIGEST_DOMAIN: &[u8] =
    b"Flux complete Android kernel config\0canonical-schema-v1\0sha256-v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidKernelConfigOptionState {
    BuiltIn,
    Module,
    Disabled,
    Configured,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AndroidKernelConfigOption {
    state: AndroidKernelConfigOptionState,
    configured_value: Option<Box<[u8]>>,
}

impl AndroidKernelConfigOption {
    fn parse(value: &[u8]) -> Self {
        match value {
            b"y" => Self::boolean(AndroidKernelConfigOptionState::BuiltIn),
            b"m" => Self::boolean(AndroidKernelConfigOptionState::Module),
            b"n" => Self::boolean(AndroidKernelConfigOptionState::Disabled),
            _ => Self {
                state: AndroidKernelConfigOptionState::Configured,
                configured_value: Some(value.into()),
            },
        }
    }

    const fn boolean(state: AndroidKernelConfigOptionState) -> Self {
        Self {
            state,
            configured_value: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidKernelConfigDigest([u8; ANDROID_KERNEL_CONFIG_DIGEST_BYTES]);

impl AndroidKernelConfigDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ANDROID_KERNEL_CONFIG_DIGEST_BYTES] {
        &self.0
    }
}

/// Complete bounded projection of one decompressed running-kernel configuration.
///
/// Every `CONFIG_*` option is retained by name and typed state. Non-boolean values remain private
/// but are bound into the digest. This type is eligibility and drift evidence only; it cannot grant
/// backend qualification or mutation authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidKernelConfigSnapshot {
    digest: AndroidKernelConfigDigest,
    options: BTreeMap<Box<str>, AndroidKernelConfigOption>,
}

impl AndroidKernelConfigSnapshot {
    #[must_use]
    pub const fn digest(&self) -> AndroidKernelConfigDigest {
        self.digest
    }

    #[must_use]
    pub fn option_count(&self) -> usize {
        self.options.len()
    }

    #[must_use]
    pub fn option(&self, symbol: &str) -> Option<AndroidKernelConfigOptionState> {
        self.options.get(symbol).map(|option| option.state)
    }

    #[must_use]
    pub fn feature_state(&self, feature: AndroidKernelFeature) -> AndroidKernelFeatureState {
        match self.option(feature.config_symbol()) {
            Some(AndroidKernelConfigOptionState::BuiltIn) => AndroidKernelFeatureState::BuiltIn,
            Some(AndroidKernelConfigOptionState::Module) => AndroidKernelFeatureState::Module,
            Some(AndroidKernelConfigOptionState::Disabled) => AndroidKernelFeatureState::Disabled,
            Some(AndroidKernelConfigOptionState::Configured) => {
                AndroidKernelFeatureState::Configured
            }
            None => AndroidKernelFeatureState::Unreported,
        }
    }

    pub fn nftables_observation_gate(
        &self,
    ) -> Result<AndroidNftablesObservationGate, AndroidNftablesObservationGateError> {
        match self.feature_state(AndroidKernelFeature::NfTables) {
            AndroidKernelFeatureState::Disabled => {
                return Ok(AndroidNftablesObservationGate::CompleteAbsent);
            }
            AndroidKernelFeatureState::BuiltIn => {}
            state => {
                return Err(AndroidNftablesObservationGateError {
                    feature: AndroidKernelFeature::NfTables,
                    state,
                });
            }
        }
        for feature in [
            AndroidKernelFeature::Netfilter,
            AndroidKernelFeature::NetfilterNetlink,
        ] {
            let state = self.feature_state(feature);
            if state != AndroidKernelFeatureState::BuiltIn {
                return Err(AndroidNftablesObservationGateError { feature, state });
            }
        }
        Ok(AndroidNftablesObservationGate::Collect)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidKernelConfigParseErrorKind {
    Empty,
    LimitExceeded,
    MissingFinalLineFeed,
    NonAscii,
    InvalidLine,
    InvalidSymbol,
    DuplicateOption,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidKernelConfigParseError {
    kind: AndroidKernelConfigParseErrorKind,
    line: Option<usize>,
}

impl AndroidKernelConfigParseError {
    const fn global(kind: AndroidKernelConfigParseErrorKind) -> Self {
        Self { kind, line: None }
    }

    const fn at_line(kind: AndroidKernelConfigParseErrorKind, line: usize) -> Self {
        Self {
            kind,
            line: Some(line),
        }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidKernelConfigParseErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn line(self) -> Option<usize> {
        self.line
    }
}

impl fmt::Display for AndroidKernelConfigParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Android kernel config parse failed: {:?}",
            self.kind
        )?;
        if let Some(line) = self.line {
            write!(formatter, " at line {line}")?;
        }
        Ok(())
    }
}

impl Error for AndroidKernelConfigParseError {}

pub fn parse_android_kernel_config(
    bytes: &[u8],
) -> Result<AndroidKernelConfigSnapshot, AndroidKernelConfigParseError> {
    if bytes.is_empty() {
        return Err(AndroidKernelConfigParseError::global(
            AndroidKernelConfigParseErrorKind::Empty,
        ));
    }
    if bytes.len() > MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES {
        return Err(AndroidKernelConfigParseError::global(
            AndroidKernelConfigParseErrorKind::LimitExceeded,
        ));
    }
    if !bytes.ends_with(b"\n") {
        return Err(AndroidKernelConfigParseError::global(
            AndroidKernelConfigParseErrorKind::MissingFinalLineFeed,
        ));
    }
    if !bytes.is_ascii() {
        return Err(AndroidKernelConfigParseError::global(
            AndroidKernelConfigParseErrorKind::NonAscii,
        ));
    }

    let mut options = BTreeMap::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if line.len() > MAX_ANDROID_KERNEL_CONFIG_LINE_BYTES {
            return Err(AndroidKernelConfigParseError::at_line(
                AndroidKernelConfigParseErrorKind::LimitExceeded,
                line_number,
            ));
        }
        if line.is_empty() || (line.starts_with(b"#") && !line.starts_with(b"# CONFIG_")) {
            continue;
        }
        let (symbol, option) = if let Some(disabled) = line
            .strip_prefix(b"# ")
            .and_then(|line| line.strip_suffix(b" is not set"))
        {
            (
                disabled,
                AndroidKernelConfigOption::boolean(AndroidKernelConfigOptionState::Disabled),
            )
        } else if let Some(separator) = line.iter().position(|byte| *byte == b'=') {
            let (symbol, value) = line.split_at(separator);
            (symbol, AndroidKernelConfigOption::parse(&value[1..]))
        } else {
            return Err(AndroidKernelConfigParseError::at_line(
                AndroidKernelConfigParseErrorKind::InvalidLine,
                line_number,
            ));
        };
        if !valid_config_symbol(symbol) {
            return Err(AndroidKernelConfigParseError::at_line(
                AndroidKernelConfigParseErrorKind::InvalidSymbol,
                line_number,
            ));
        }
        if options.len() == MAX_ANDROID_KERNEL_CONFIG_OPTIONS {
            return Err(AndroidKernelConfigParseError::at_line(
                AndroidKernelConfigParseErrorKind::LimitExceeded,
                line_number,
            ));
        }
        let symbol: Box<str> = std::str::from_utf8(symbol)
            .expect("ASCII was validated before parsing")
            .into();
        if options.insert(symbol, option).is_some() {
            return Err(AndroidKernelConfigParseError::at_line(
                AndroidKernelConfigParseErrorKind::DuplicateOption,
                line_number,
            ));
        }
    }
    if options.is_empty() {
        return Err(AndroidKernelConfigParseError::global(
            AndroidKernelConfigParseErrorKind::Empty,
        ));
    }

    let mut digest = Sha256::new();
    digest.update(KERNEL_CONFIG_DIGEST_DOMAIN);
    digest_usize(&mut digest, options.len());
    for (symbol, option) in &options {
        digest_bytes(&mut digest, symbol.as_bytes());
        digest.update([config_state_tag(option.state)]);
        if let Some(value) = &option.configured_value {
            digest_bytes(&mut digest, value);
        }
    }
    Ok(AndroidKernelConfigSnapshot {
        digest: AndroidKernelConfigDigest(digest.finalize().into()),
        options,
    })
}

fn valid_config_symbol(symbol: &[u8]) -> bool {
    let Some(name) = symbol.strip_prefix(b"CONFIG_") else {
        return false;
    };
    !name.is_empty()
        && symbol.len() <= MAX_ANDROID_KERNEL_CONFIG_SYMBOL_BYTES
        && name
            .iter()
            .all(|byte| byte.is_ascii_alphabetic() || byte.is_ascii_digit() || *byte == b'_')
}

const fn config_state_tag(state: AndroidKernelConfigOptionState) -> u8 {
    match state {
        AndroidKernelConfigOptionState::BuiltIn => 1,
        AndroidKernelConfigOptionState::Module => 2,
        AndroidKernelConfigOptionState::Disabled => 3,
        AndroidKernelConfigOptionState::Configured => 4,
    }
}

fn digest_usize(digest: &mut Sha256, value: usize) {
    digest.update(
        u64::try_from(value)
            .expect("bounded kernel config values fit u64")
            .to_be_bytes(),
    );
}

fn digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest_usize(digest, bytes.len());
    digest.update(bytes);
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidKernelFeature {
    Netfilter,
    NetfilterNetlink,
    NfConntrack,
    NfConntrackMark,
    IpMultipleTables,
    Ipv6,
    Ipv6MultipleTables,
    NetfilterXtables,
    IpTables,
    Ip6Tables,
    IpMangle,
    Ip6Mangle,
    XtOwnerMatch,
    XtMarkMatch,
    XtMarkTarget,
    XtConntrackMatch,
    XtConnmarkMatch,
    XtConnmarkTarget,
    XtSocketMatch,
    XtCommentMatch,
    XtAddrtypeMatch,
    XtTproxyTarget,
    NfTproxyIpv4,
    NfTproxyIpv6,
    NfTables,
    NfTablesInet,
    NftCounter,
    NftCt,
    NftSocket,
    NftTproxy,
    NftFib,
    Tun,
    IpSet,
    IpSetHashNet,
    BpfSyscall,
    BpfJit,
    CgroupBpf,
    NetClsBpf,
    NetClsAct,
    NetSchIngress,
    BpfStreamParser,
    DebugInfoBtf,
    XtBpfMatch,
}

pub const ALL_ANDROID_KERNEL_FEATURES: [AndroidKernelFeature; 43] = [
    AndroidKernelFeature::Netfilter,
    AndroidKernelFeature::NetfilterNetlink,
    AndroidKernelFeature::NfConntrack,
    AndroidKernelFeature::NfConntrackMark,
    AndroidKernelFeature::IpMultipleTables,
    AndroidKernelFeature::Ipv6,
    AndroidKernelFeature::Ipv6MultipleTables,
    AndroidKernelFeature::NetfilterXtables,
    AndroidKernelFeature::IpTables,
    AndroidKernelFeature::Ip6Tables,
    AndroidKernelFeature::IpMangle,
    AndroidKernelFeature::Ip6Mangle,
    AndroidKernelFeature::XtOwnerMatch,
    AndroidKernelFeature::XtMarkMatch,
    AndroidKernelFeature::XtMarkTarget,
    AndroidKernelFeature::XtConntrackMatch,
    AndroidKernelFeature::XtConnmarkMatch,
    AndroidKernelFeature::XtConnmarkTarget,
    AndroidKernelFeature::XtSocketMatch,
    AndroidKernelFeature::XtCommentMatch,
    AndroidKernelFeature::XtAddrtypeMatch,
    AndroidKernelFeature::XtTproxyTarget,
    AndroidKernelFeature::NfTproxyIpv4,
    AndroidKernelFeature::NfTproxyIpv6,
    AndroidKernelFeature::NfTables,
    AndroidKernelFeature::NfTablesInet,
    AndroidKernelFeature::NftCounter,
    AndroidKernelFeature::NftCt,
    AndroidKernelFeature::NftSocket,
    AndroidKernelFeature::NftTproxy,
    AndroidKernelFeature::NftFib,
    AndroidKernelFeature::Tun,
    AndroidKernelFeature::IpSet,
    AndroidKernelFeature::IpSetHashNet,
    AndroidKernelFeature::BpfSyscall,
    AndroidKernelFeature::BpfJit,
    AndroidKernelFeature::CgroupBpf,
    AndroidKernelFeature::NetClsBpf,
    AndroidKernelFeature::NetClsAct,
    AndroidKernelFeature::NetSchIngress,
    AndroidKernelFeature::BpfStreamParser,
    AndroidKernelFeature::DebugInfoBtf,
    AndroidKernelFeature::XtBpfMatch,
];

impl AndroidKernelFeature {
    #[must_use]
    pub const fn config_symbol(self) -> &'static str {
        match self {
            Self::Netfilter => "CONFIG_NETFILTER",
            Self::NetfilterNetlink => "CONFIG_NETFILTER_NETLINK",
            Self::NfConntrack => "CONFIG_NF_CONNTRACK",
            Self::NfConntrackMark => "CONFIG_NF_CONNTRACK_MARK",
            Self::IpMultipleTables => "CONFIG_IP_MULTIPLE_TABLES",
            Self::Ipv6 => "CONFIG_IPV6",
            Self::Ipv6MultipleTables => "CONFIG_IPV6_MULTIPLE_TABLES",
            Self::NetfilterXtables => "CONFIG_NETFILTER_XTABLES",
            Self::IpTables => "CONFIG_IP_NF_IPTABLES",
            Self::Ip6Tables => "CONFIG_IP6_NF_IPTABLES",
            Self::IpMangle => "CONFIG_IP_NF_MANGLE",
            Self::Ip6Mangle => "CONFIG_IP6_NF_MANGLE",
            Self::XtOwnerMatch => "CONFIG_NETFILTER_XT_MATCH_OWNER",
            Self::XtMarkMatch => "CONFIG_NETFILTER_XT_MATCH_MARK",
            Self::XtMarkTarget => "CONFIG_NETFILTER_XT_TARGET_MARK",
            Self::XtConntrackMatch => "CONFIG_NETFILTER_XT_MATCH_CONNTRACK",
            Self::XtConnmarkMatch => "CONFIG_NETFILTER_XT_MATCH_CONNMARK",
            Self::XtConnmarkTarget => "CONFIG_NETFILTER_XT_TARGET_CONNMARK",
            Self::XtSocketMatch => "CONFIG_NETFILTER_XT_MATCH_SOCKET",
            Self::XtCommentMatch => "CONFIG_NETFILTER_XT_MATCH_COMMENT",
            Self::XtAddrtypeMatch => "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE",
            Self::XtTproxyTarget => "CONFIG_NETFILTER_XT_TARGET_TPROXY",
            Self::NfTproxyIpv4 => "CONFIG_NF_TPROXY_IPV4",
            Self::NfTproxyIpv6 => "CONFIG_NF_TPROXY_IPV6",
            Self::NfTables => "CONFIG_NF_TABLES",
            Self::NfTablesInet => "CONFIG_NF_TABLES_INET",
            Self::NftCounter => "CONFIG_NFT_COUNTER",
            Self::NftCt => "CONFIG_NFT_CT",
            Self::NftSocket => "CONFIG_NFT_SOCKET",
            Self::NftTproxy => "CONFIG_NFT_TPROXY",
            Self::NftFib => "CONFIG_NFT_FIB",
            Self::Tun => "CONFIG_TUN",
            Self::IpSet => "CONFIG_IP_SET",
            Self::IpSetHashNet => "CONFIG_IP_SET_HASH_NET",
            Self::BpfSyscall => "CONFIG_BPF_SYSCALL",
            Self::BpfJit => "CONFIG_BPF_JIT",
            Self::CgroupBpf => "CONFIG_CGROUP_BPF",
            Self::NetClsBpf => "CONFIG_NET_CLS_BPF",
            Self::NetClsAct => "CONFIG_NET_CLS_ACT",
            Self::NetSchIngress => "CONFIG_NET_SCH_INGRESS",
            Self::BpfStreamParser => "CONFIG_BPF_STREAM_PARSER",
            Self::DebugInfoBtf => "CONFIG_DEBUG_INFO_BTF",
            Self::XtBpfMatch => "CONFIG_NETFILTER_XT_MATCH_BPF",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidKernelFeatureState {
    BuiltIn,
    Module,
    Disabled,
    Configured,
    Unreported,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AndroidNftablesObservationGate {
    Collect,
    CompleteAbsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidNftablesObservationGateError {
    feature: AndroidKernelFeature,
    state: AndroidKernelFeatureState,
}

impl AndroidNftablesObservationGateError {
    #[must_use]
    pub const fn feature(self) -> AndroidKernelFeature {
        self.feature
    }

    #[must_use]
    pub const fn state(self) -> AndroidKernelFeatureState {
        self.state
    }
}

impl fmt::Display for AndroidNftablesObservationGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "nftables observation is not safe before autoload: {:?} is {:?}",
            self.feature, self.state
        )
    }
}

impl Error for AndroidNftablesObservationGateError {}

const AUTOMATIC_PATH_ORDER: [CapturePathId; ANDROID_CAPTURE_PATH_COUNT] = [
    CapturePathId::NftablesTproxy,
    CapturePathId::XtablesTproxy,
    CapturePathId::ManagedTun,
];

const NFTABLES_REQUIRED_FEATURES: &[AndroidKernelFeature] = &[
    AndroidKernelFeature::Netfilter,
    AndroidKernelFeature::NetfilterNetlink,
    AndroidKernelFeature::IpMultipleTables,
    AndroidKernelFeature::Ipv6,
    AndroidKernelFeature::Ipv6MultipleTables,
    AndroidKernelFeature::NfTables,
    AndroidKernelFeature::NfTablesInet,
    AndroidKernelFeature::NftCounter,
    AndroidKernelFeature::NftSocket,
    AndroidKernelFeature::NftTproxy,
    AndroidKernelFeature::NfTproxyIpv4,
    AndroidKernelFeature::NfTproxyIpv6,
];

const XTABLES_REQUIRED_FEATURES: &[AndroidKernelFeature] = &[
    AndroidKernelFeature::Netfilter,
    AndroidKernelFeature::IpMultipleTables,
    AndroidKernelFeature::Ipv6,
    AndroidKernelFeature::Ipv6MultipleTables,
    AndroidKernelFeature::NetfilterXtables,
    AndroidKernelFeature::IpTables,
    AndroidKernelFeature::Ip6Tables,
    AndroidKernelFeature::IpMangle,
    AndroidKernelFeature::Ip6Mangle,
    AndroidKernelFeature::XtOwnerMatch,
    AndroidKernelFeature::XtMarkMatch,
    AndroidKernelFeature::XtMarkTarget,
    AndroidKernelFeature::XtCommentMatch,
    AndroidKernelFeature::XtTproxyTarget,
    AndroidKernelFeature::NfTproxyIpv4,
    AndroidKernelFeature::NfTproxyIpv6,
];

const TUN_REQUIRED_FEATURES: &[AndroidKernelFeature] = &[
    AndroidKernelFeature::IpMultipleTables,
    AndroidKernelFeature::Ipv6,
    AndroidKernelFeature::Ipv6MultipleTables,
    AndroidKernelFeature::Tun,
];

fn required_features(path: CapturePathId) -> &'static [AndroidKernelFeature] {
    match path {
        CapturePathId::NftablesTproxy => NFTABLES_REQUIRED_FEATURES,
        CapturePathId::XtablesTproxy => XTABLES_REQUIRED_FEATURES,
        CapturePathId::ManagedTun => TUN_REQUIRED_FEATURES,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidCapturePathProbeState {
    Qualified,
    Unsupported,
    Denied,
    Conflicting,
    Broken,
    Unqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidCapturePathState {
    Qualified,
    Missing,
    Denied,
    Conflicting,
    Broken,
    Unqualified,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidCapturePathQualifications {
    nftables: AndroidCapturePathProbeState,
    xtables: AndroidCapturePathProbeState,
    tun: AndroidCapturePathProbeState,
}

impl AndroidCapturePathQualifications {
    #[must_use]
    pub const fn new(
        nftables: AndroidCapturePathProbeState,
        xtables: AndroidCapturePathProbeState,
        tun: AndroidCapturePathProbeState,
    ) -> Self {
        Self {
            nftables,
            xtables,
            tun,
        }
    }

    const fn for_path(self, path: CapturePathId) -> AndroidCapturePathProbeState {
        match path {
            CapturePathId::NftablesTproxy => self.nftables,
            CapturePathId::XtablesTproxy => self.xtables,
            CapturePathId::ManagedTun => self.tun,
        }
    }
}

impl Default for AndroidCapturePathQualifications {
    fn default() -> Self {
        Self::new(
            AndroidCapturePathProbeState::Unqualified,
            AndroidCapturePathProbeState::Unqualified,
            AndroidCapturePathProbeState::Unqualified,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidCapturePathPreference {
    Automatic,
    Explicit(CapturePathId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidCapturePathCandidate {
    path: CapturePathId,
    state: AndroidCapturePathState,
    probe_state: AndroidCapturePathProbeState,
    first_kernel_gap: Option<(AndroidKernelFeature, AndroidKernelFeatureState)>,
}

impl AndroidCapturePathCandidate {
    #[must_use]
    pub const fn path(self) -> CapturePathId {
        self.path
    }

    #[must_use]
    pub const fn state(self) -> AndroidCapturePathState {
        self.state
    }

    #[must_use]
    pub const fn probe_state(self) -> AndroidCapturePathProbeState {
        self.probe_state
    }

    #[must_use]
    pub const fn first_kernel_gap(
        self,
    ) -> Option<(AndroidKernelFeature, AndroidKernelFeatureState)> {
        self.first_kernel_gap
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidCapturePathDecision {
    preference: AndroidCapturePathPreference,
    candidates: [AndroidCapturePathCandidate; ANDROID_CAPTURE_PATH_COUNT],
    selected: Option<CapturePathId>,
    next_to_qualify: Option<CapturePathId>,
}

impl AndroidCapturePathDecision {
    #[must_use]
    pub const fn preference(self) -> AndroidCapturePathPreference {
        self.preference
    }

    #[must_use]
    pub const fn candidates(&self) -> &[AndroidCapturePathCandidate; ANDROID_CAPTURE_PATH_COUNT] {
        &self.candidates
    }

    #[must_use]
    pub const fn selected(self) -> Option<CapturePathId> {
        self.selected
    }

    #[must_use]
    pub const fn next_to_qualify(self) -> Option<CapturePathId> {
        self.next_to_qualify
    }

    #[must_use]
    pub fn candidate(&self, path: CapturePathId) -> AndroidCapturePathCandidate {
        self.candidates
            .iter()
            .copied()
            .find(|candidate| candidate.path == path)
            .expect("every decision contains each capture path exactly once")
    }
}

#[must_use]
pub fn select_android_capture_path(
    config: &AndroidKernelConfigSnapshot,
    qualifications: AndroidCapturePathQualifications,
    preference: AndroidCapturePathPreference,
) -> AndroidCapturePathDecision {
    let candidates = AUTOMATIC_PATH_ORDER
        .map(|path| capture_path_candidate(config, path, qualifications.for_path(path)));
    let selected = match preference {
        AndroidCapturePathPreference::Automatic => {
            AUTOMATIC_PATH_ORDER.iter().copied().find(|path| {
                candidate_has_state(&candidates, *path, AndroidCapturePathState::Qualified)
            })
        }
        AndroidCapturePathPreference::Explicit(path) => {
            candidate_has_state(&candidates, path, AndroidCapturePathState::Qualified)
                .then_some(path)
        }
    };
    let next_to_qualify = if selected.is_some() {
        None
    } else {
        match preference {
            AndroidCapturePathPreference::Automatic => {
                AUTOMATIC_PATH_ORDER.iter().copied().find(|path| {
                    candidate_has_state(&candidates, *path, AndroidCapturePathState::Unqualified)
                })
            }
            AndroidCapturePathPreference::Explicit(path) => {
                candidate_has_state(&candidates, path, AndroidCapturePathState::Unqualified)
                    .then_some(path)
            }
        }
    };
    AndroidCapturePathDecision {
        preference,
        candidates,
        selected,
        next_to_qualify,
    }
}

fn candidate_has_state(
    candidates: &[AndroidCapturePathCandidate; ANDROID_CAPTURE_PATH_COUNT],
    path: CapturePathId,
    state: AndroidCapturePathState,
) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.path == path && candidate.state == state)
}

fn capture_path_candidate(
    config: &AndroidKernelConfigSnapshot,
    path: CapturePathId,
    probe_state: AndroidCapturePathProbeState,
) -> AndroidCapturePathCandidate {
    let first_kernel_gap = required_features(path).iter().copied().find_map(|feature| {
        let state = config.feature_state(feature);
        (state != AndroidKernelFeatureState::BuiltIn).then_some((feature, state))
    });
    let disabled = required_features(path)
        .iter()
        .copied()
        .find(|feature| config.feature_state(*feature) == AndroidKernelFeatureState::Disabled);
    let state = if probe_state == AndroidCapturePathProbeState::Qualified {
        if disabled.is_some() {
            AndroidCapturePathState::Broken
        } else {
            AndroidCapturePathState::Qualified
        }
    } else if disabled.is_some() || probe_state == AndroidCapturePathProbeState::Unsupported {
        AndroidCapturePathState::Missing
    } else if first_kernel_gap.is_some() {
        AndroidCapturePathState::Unqualified
    } else {
        match probe_state {
            AndroidCapturePathProbeState::Qualified => AndroidCapturePathState::Qualified,
            AndroidCapturePathProbeState::Unsupported => AndroidCapturePathState::Missing,
            AndroidCapturePathProbeState::Denied => AndroidCapturePathState::Denied,
            AndroidCapturePathProbeState::Conflicting => AndroidCapturePathState::Conflicting,
            AndroidCapturePathProbeState::Broken => AndroidCapturePathState::Broken,
            AndroidCapturePathProbeState::Unqualified => AndroidCapturePathState::Unqualified,
        }
    };
    AndroidCapturePathCandidate {
        path,
        state,
        probe_state,
        first_kernel_gap,
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemAndroidKernelConfigSource {
    path: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Default for SystemAndroidKernelConfigSource {
    fn default() -> Self {
        Self {
            path: DEFAULT_ANDROID_KERNEL_CONFIG_PATH.into(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SystemAndroidKernelConfigSource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn for_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn collect(&self) -> Result<AndroidKernelConfigSnapshot, SystemAndroidKernelConfigError> {
        let compressed =
            read_bounded_regular_file(&self.path, MAX_ANDROID_KERNEL_CONFIG_COMPRESSED_BYTES)?;
        let mut decoder = MultiGzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::with_capacity(256 * 1024);
        decoder
            .by_ref()
            .take(
                u64::try_from(MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES)
                    .expect("kernel config limit fits u64")
                    + 1,
            )
            .read_to_end(&mut decompressed)
            .map_err(SystemAndroidKernelConfigError::gzip_decoding)?;
        if decompressed.len() > MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES {
            return Err(SystemAndroidKernelConfigError::limit_exceeded());
        }
        parse_android_kernel_config(&decompressed).map_err(SystemAndroidKernelConfigError::parse)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_bounded_regular_file(
    path: &Path,
    limit: usize,
) -> Result<Vec<u8>, SystemAndroidKernelConfigError> {
    let metadata = fs::symlink_metadata(path).map_err(SystemAndroidKernelConfigError::from_io)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(SystemAndroidKernelConfigError::malformed_message(
            SystemAndroidKernelConfigErrorClass::PathType,
            "kernel config source is not a direct regular file",
        ));
    }
    let file =
        open_read_only_no_follow(path).map_err(SystemAndroidKernelConfigError::from_open_io)?;
    if !file
        .metadata()
        .map_err(SystemAndroidKernelConfigError::from_io)?
        .file_type()
        .is_file()
    {
        return Err(SystemAndroidKernelConfigError::malformed_message(
            SystemAndroidKernelConfigErrorClass::PathType,
            "opened kernel config source is not a regular file",
        ));
    }
    let mut bytes = Vec::with_capacity(limit.saturating_add(1));
    file.take(u64::try_from(limit).expect("kernel config compressed limit fits u64") + 1)
        .read_to_end(&mut bytes)
        .map_err(SystemAndroidKernelConfigError::from_io)?;
    if bytes.len() > limit {
        return Err(SystemAndroidKernelConfigError::limit_exceeded());
    }
    Ok(bytes)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_read_only_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAndroidKernelConfigErrorKind {
    Absent,
    Denied,
    Malformed,
    LimitExceeded,
    Unavailable,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemAndroidKernelConfigErrorClass {
    Absent,
    Denied,
    PathType,
    NoFollowOpen,
    GzipDecoding,
    ParserEmpty,
    ParserMissingFinalLineFeed,
    ParserNonAscii,
    ParserInvalidLine,
    ParserInvalidSymbol,
    ParserDuplicateOption,
    LimitExceeded,
    Unavailable,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SystemAndroidKernelConfigErrorClass {
    #[must_use]
    pub const fn kind(self) -> SystemAndroidKernelConfigErrorKind {
        match self {
            Self::Absent => SystemAndroidKernelConfigErrorKind::Absent,
            Self::Denied => SystemAndroidKernelConfigErrorKind::Denied,
            Self::PathType
            | Self::NoFollowOpen
            | Self::GzipDecoding
            | Self::ParserEmpty
            | Self::ParserMissingFinalLineFeed
            | Self::ParserNonAscii
            | Self::ParserInvalidLine
            | Self::ParserInvalidSymbol
            | Self::ParserDuplicateOption => SystemAndroidKernelConfigErrorKind::Malformed,
            Self::LimitExceeded => SystemAndroidKernelConfigErrorKind::LimitExceeded,
            Self::Unavailable => SystemAndroidKernelConfigErrorKind::Unavailable,
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub struct SystemAndroidKernelConfigError {
    class: SystemAndroidKernelConfigErrorClass,
    source: Option<Box<dyn Error + Send + Sync>>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SystemAndroidKernelConfigError {
    #[must_use]
    pub const fn kind(&self) -> SystemAndroidKernelConfigErrorKind {
        self.class.kind()
    }

    #[must_use]
    pub const fn class(&self) -> SystemAndroidKernelConfigErrorClass {
        self.class
    }

    fn from_io(source: std::io::Error) -> Self {
        let class = match source.kind() {
            std::io::ErrorKind::NotFound => SystemAndroidKernelConfigErrorClass::Absent,
            std::io::ErrorKind::PermissionDenied => SystemAndroidKernelConfigErrorClass::Denied,
            _ => SystemAndroidKernelConfigErrorClass::Unavailable,
        };
        Self {
            class,
            source: Some(Box::new(source)),
        }
    }

    fn from_open_io(source: std::io::Error) -> Self {
        if source.raw_os_error() == Some(libc::ELOOP) {
            return Self::malformed(SystemAndroidKernelConfigErrorClass::NoFollowOpen, source);
        }
        Self::from_io(source)
    }

    fn gzip_decoding(source: impl Error + Send + Sync + 'static) -> Self {
        Self::malformed(SystemAndroidKernelConfigErrorClass::GzipDecoding, source)
    }

    fn malformed(
        class: SystemAndroidKernelConfigErrorClass,
        source: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            class,
            source: Some(Box::new(source)),
        }
    }

    fn malformed_message(
        class: SystemAndroidKernelConfigErrorClass,
        message: &'static str,
    ) -> Self {
        Self::malformed(class, StaticKernelConfigError(message))
    }

    const fn limit_exceeded() -> Self {
        Self {
            class: SystemAndroidKernelConfigErrorClass::LimitExceeded,
            source: None,
        }
    }

    fn parse(source: AndroidKernelConfigParseError) -> Self {
        let class = match source.kind() {
            AndroidKernelConfigParseErrorKind::Empty => {
                SystemAndroidKernelConfigErrorClass::ParserEmpty
            }
            AndroidKernelConfigParseErrorKind::LimitExceeded => {
                SystemAndroidKernelConfigErrorClass::LimitExceeded
            }
            AndroidKernelConfigParseErrorKind::MissingFinalLineFeed => {
                SystemAndroidKernelConfigErrorClass::ParserMissingFinalLineFeed
            }
            AndroidKernelConfigParseErrorKind::NonAscii => {
                SystemAndroidKernelConfigErrorClass::ParserNonAscii
            }
            AndroidKernelConfigParseErrorKind::InvalidLine => {
                SystemAndroidKernelConfigErrorClass::ParserInvalidLine
            }
            AndroidKernelConfigParseErrorKind::InvalidSymbol => {
                SystemAndroidKernelConfigErrorClass::ParserInvalidSymbol
            }
            AndroidKernelConfigParseErrorKind::DuplicateOption => {
                SystemAndroidKernelConfigErrorClass::ParserDuplicateOption
            }
        };
        Self {
            class,
            source: Some(Box::new(source)),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl fmt::Display for SystemAndroidKernelConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "system Android kernel config collection failed: {:?}",
            self.kind()
        )
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Error for SystemAndroidKernelConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn Error + 'static))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
struct StaticKernelConfigError(&'static str);

#[cfg(any(target_os = "linux", target_os = "android"))]
impl fmt::Display for StaticKernelConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Error for StaticKernelConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use tempfile::tempdir;

    fn complete_feature_config(
        overrides: &[(AndroidKernelFeature, AndroidKernelConfigOptionState)],
    ) -> AndroidKernelConfigSnapshot {
        let mut options = ALL_ANDROID_KERNEL_FEATURES
            .into_iter()
            .map(|feature| {
                (
                    feature.config_symbol(),
                    AndroidKernelConfigOptionState::BuiltIn,
                )
            })
            .collect::<BTreeMap<_, _>>();
        for (feature, state) in overrides {
            options.insert(feature.config_symbol(), *state);
        }
        let mut bytes = Vec::new();
        for (symbol, state) in options {
            match state {
                AndroidKernelConfigOptionState::BuiltIn => {
                    writeln!(bytes, "{symbol}=y").unwrap();
                }
                AndroidKernelConfigOptionState::Module => {
                    writeln!(bytes, "{symbol}=m").unwrap();
                }
                AndroidKernelConfigOptionState::Disabled => {
                    writeln!(bytes, "# {symbol} is not set").unwrap();
                }
                AndroidKernelConfigOptionState::Configured => {
                    writeln!(bytes, "{symbol}=42").unwrap();
                }
            }
        }
        parse_android_kernel_config(&bytes).unwrap()
    }

    #[test]
    fn parser_retains_every_option_state_and_canonicalizes_order() {
        let first = parse_android_kernel_config(
            b"# generated\nCONFIG_ZETA=\"value\"\nCONFIG_ALPHA=y\nCONFIG_BETA=m\n# CONFIG_GAMMA is not set\nCONFIG_vendor_feature=y\n",
        )
        .unwrap();
        let reordered = parse_android_kernel_config(
            b"CONFIG_BETA=m\n# CONFIG_GAMMA is not set\nCONFIG_vendor_feature=y\nCONFIG_ALPHA=y\nCONFIG_ZETA=\"value\"\n",
        )
        .unwrap();
        assert_eq!(first.option_count(), 5);
        assert_eq!(first.digest(), reordered.digest());
        assert_eq!(
            first.option("CONFIG_ALPHA"),
            Some(AndroidKernelConfigOptionState::BuiltIn)
        );
        assert_eq!(
            first.option("CONFIG_BETA"),
            Some(AndroidKernelConfigOptionState::Module)
        );
        assert_eq!(
            first.option("CONFIG_GAMMA"),
            Some(AndroidKernelConfigOptionState::Disabled)
        );
        assert_eq!(
            first.option("CONFIG_ZETA"),
            Some(AndroidKernelConfigOptionState::Configured)
        );
        assert_eq!(
            first.option("CONFIG_vendor_feature"),
            Some(AndroidKernelConfigOptionState::BuiltIn)
        );
    }

    #[test]
    fn parser_rejects_ambiguous_or_unbounded_input() {
        for (bytes, expected) in [
            (
                b"CONFIG_A=y\nCONFIG_A=m\n".as_slice(),
                AndroidKernelConfigParseErrorKind::DuplicateOption,
            ),
            (
                b"CONFIG_A=y".as_slice(),
                AndroidKernelConfigParseErrorKind::MissingFinalLineFeed,
            ),
            (
                b"CONFIG_BAD-NAME=y\n".as_slice(),
                AndroidKernelConfigParseErrorKind::InvalidSymbol,
            ),
            (
                b"not-a-config-line\n".as_slice(),
                AndroidKernelConfigParseErrorKind::InvalidLine,
            ),
        ] {
            assert_eq!(
                parse_android_kernel_config(bytes).unwrap_err().kind(),
                expected
            );
        }
        let oversized_line = [
            b"CONFIG_A=\"".as_slice(),
            vec![b'x'; MAX_ANDROID_KERNEL_CONFIG_LINE_BYTES].as_slice(),
            b"\"\n".as_slice(),
        ]
        .concat();
        assert_eq!(
            parse_android_kernel_config(&oversized_line)
                .unwrap_err()
                .kind(),
            AndroidKernelConfigParseErrorKind::LimitExceeded
        );
    }

    #[test]
    fn system_error_refines_every_parser_and_no_follow_class() {
        for (bytes, expected) in [
            (
                b"".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserEmpty,
            ),
            (
                b"CONFIG_A=y".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserMissingFinalLineFeed,
            ),
            (
                b"CONFIG_A=\xff\n".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserNonAscii,
            ),
            (
                b"not-a-config-line\n".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserInvalidLine,
            ),
            (
                b"CONFIG_BAD-NAME=y\n".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserInvalidSymbol,
            ),
            (
                b"CONFIG_A=y\nCONFIG_A=m\n".as_slice(),
                SystemAndroidKernelConfigErrorClass::ParserDuplicateOption,
            ),
        ] {
            let parse_error = parse_android_kernel_config(bytes).unwrap_err();
            let error = SystemAndroidKernelConfigError::parse(parse_error);
            assert_eq!(error.class(), expected);
            assert_eq!(error.kind(), SystemAndroidKernelConfigErrorKind::Malformed);
        }

        let no_follow = SystemAndroidKernelConfigError::from_open_io(
            std::io::Error::from_raw_os_error(libc::ELOOP),
        );
        assert_eq!(
            no_follow.class(),
            SystemAndroidKernelConfigErrorClass::NoFollowOpen
        );
        assert_eq!(
            no_follow.kind(),
            SystemAndroidKernelConfigErrorKind::Malformed
        );
    }

    #[test]
    fn nftables_gate_never_uses_a_dump_as_an_availability_probe() {
        let built_in = complete_feature_config(&[]);
        assert_eq!(
            built_in.nftables_observation_gate(),
            Ok(AndroidNftablesObservationGate::Collect)
        );
        let disabled = complete_feature_config(&[(
            AndroidKernelFeature::NfTables,
            AndroidKernelConfigOptionState::Disabled,
        )]);
        assert_eq!(
            disabled.nftables_observation_gate(),
            Ok(AndroidNftablesObservationGate::CompleteAbsent)
        );
        for state in [
            AndroidKernelConfigOptionState::Module,
            AndroidKernelConfigOptionState::Configured,
        ] {
            let config = complete_feature_config(&[(AndroidKernelFeature::NfTables, state)]);
            let error = config.nftables_observation_gate().unwrap_err();
            assert_eq!(error.feature(), AndroidKernelFeature::NfTables);
        }
        let unreported = parse_android_kernel_config(b"CONFIG_NETFILTER=y\n").unwrap();
        assert_eq!(
            unreported.nftables_observation_gate().unwrap_err().state(),
            AndroidKernelFeatureState::Unreported
        );
    }

    #[test]
    fn automatic_selection_prefers_the_first_qualified_path() {
        let config = complete_feature_config(&[]);
        let decision = select_android_capture_path(
            &config,
            AndroidCapturePathQualifications::new(
                AndroidCapturePathProbeState::Qualified,
                AndroidCapturePathProbeState::Qualified,
                AndroidCapturePathProbeState::Qualified,
            ),
            AndroidCapturePathPreference::Automatic,
        );
        assert_eq!(decision.selected(), Some(CapturePathId::NftablesTproxy));
        assert_eq!(decision.next_to_qualify(), None);
    }

    #[test]
    fn automatic_selection_falls_through_terminal_candidate_states() {
        let config = complete_feature_config(&[]);
        let decision = select_android_capture_path(
            &config,
            AndroidCapturePathQualifications::new(
                AndroidCapturePathProbeState::Denied,
                AndroidCapturePathProbeState::Conflicting,
                AndroidCapturePathProbeState::Qualified,
            ),
            AndroidCapturePathPreference::Automatic,
        );
        assert_eq!(decision.selected(), Some(CapturePathId::ManagedTun));
        assert_eq!(
            decision.candidate(CapturePathId::NftablesTproxy).state(),
            AndroidCapturePathState::Denied
        );
        assert_eq!(
            decision.candidate(CapturePathId::XtablesTproxy).state(),
            AndroidCapturePathState::Conflicting
        );
    }

    #[test]
    fn automatic_selection_matrix_is_deterministic() {
        let config = complete_feature_config(&[]);
        let states = [
            AndroidCapturePathProbeState::Qualified,
            AndroidCapturePathProbeState::Unsupported,
            AndroidCapturePathProbeState::Denied,
            AndroidCapturePathProbeState::Conflicting,
            AndroidCapturePathProbeState::Broken,
            AndroidCapturePathProbeState::Unqualified,
        ];
        for nftables in states {
            for xtables in states {
                for tun in states {
                    let probes = [nftables, xtables, tun];
                    let decision = select_android_capture_path(
                        &config,
                        AndroidCapturePathQualifications::new(nftables, xtables, tun),
                        AndroidCapturePathPreference::Automatic,
                    );
                    let expected_selected = probes
                        .iter()
                        .position(|state| *state == AndroidCapturePathProbeState::Qualified)
                        .map(|index| AUTOMATIC_PATH_ORDER[index]);
                    let expected_next = expected_selected
                        .is_none()
                        .then(|| {
                            probes
                                .iter()
                                .position(|state| {
                                    *state == AndroidCapturePathProbeState::Unqualified
                                })
                                .map(|index| AUTOMATIC_PATH_ORDER[index])
                        })
                        .flatten();
                    assert_eq!(decision.selected(), expected_selected, "probes={probes:?}");
                    assert_eq!(
                        decision.next_to_qualify(),
                        expected_next,
                        "probes={probes:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn current_device_shape_selects_xtables_as_the_next_qualification() {
        let config = complete_feature_config(&[(
            AndroidKernelFeature::NfTables,
            AndroidKernelConfigOptionState::Disabled,
        )]);
        let decision = select_android_capture_path(
            &config,
            AndroidCapturePathQualifications::default(),
            AndroidCapturePathPreference::Automatic,
        );
        assert_eq!(decision.selected(), None);
        assert_eq!(
            decision.next_to_qualify(),
            Some(CapturePathId::XtablesTproxy)
        );
        let nftables = decision.candidate(CapturePathId::NftablesTproxy);
        assert_eq!(nftables.state(), AndroidCapturePathState::Missing);
        assert_eq!(
            nftables.first_kernel_gap(),
            Some((
                AndroidKernelFeature::NfTables,
                AndroidKernelFeatureState::Disabled
            ))
        );
    }

    #[test]
    fn explicit_selection_never_falls_back() {
        let config = complete_feature_config(&[(
            AndroidKernelFeature::NfTables,
            AndroidKernelConfigOptionState::Disabled,
        )]);
        let decision = select_android_capture_path(
            &config,
            AndroidCapturePathQualifications::new(
                AndroidCapturePathProbeState::Unqualified,
                AndroidCapturePathProbeState::Qualified,
                AndroidCapturePathProbeState::Qualified,
            ),
            AndroidCapturePathPreference::Explicit(CapturePathId::NftablesTproxy),
        );
        assert_eq!(decision.selected(), None);
        assert_eq!(decision.next_to_qualify(), None);
    }

    #[test]
    fn contradictory_qualified_probe_is_broken_not_authoritative() {
        let config = complete_feature_config(&[(
            AndroidKernelFeature::NfTables,
            AndroidKernelConfigOptionState::Disabled,
        )]);
        let decision = select_android_capture_path(
            &config,
            AndroidCapturePathQualifications::new(
                AndroidCapturePathProbeState::Qualified,
                AndroidCapturePathProbeState::Unqualified,
                AndroidCapturePathProbeState::Unqualified,
            ),
            AndroidCapturePathPreference::Automatic,
        );
        assert_eq!(
            decision.candidate(CapturePathId::NftablesTproxy).state(),
            AndroidCapturePathState::Broken
        );
        assert_eq!(decision.selected(), None);
        assert_eq!(
            decision.next_to_qualify(),
            Some(CapturePathId::XtablesTproxy)
        );
    }

    #[test]
    fn relevant_feature_inventory_is_unique_and_queryable() {
        let symbols = ALL_ANDROID_KERNEL_FEATURES
            .iter()
            .map(|feature| feature.config_symbol())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(symbols.len(), ALL_ANDROID_KERNEL_FEATURES.len());
        assert!(symbols.contains("CONFIG_NF_TABLES"));
        assert!(symbols.contains("CONFIG_NETFILTER_XT_TARGET_TPROXY"));
        assert!(symbols.contains("CONFIG_TUN"));
        assert!(symbols.contains("CONFIG_BPF_SYSCALL"));
        assert!(symbols.contains("CONFIG_IP_SET"));
    }

    #[cfg(unix)]
    #[test]
    fn system_source_reads_gzip_and_rejects_final_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let config_path = directory.path().join("config.gz");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(b"CONFIG_NETFILTER=y\n# CONFIG_NF_TABLES is not set\n")
            .unwrap();
        std::fs::write(&config_path, encoder.finish().unwrap()).unwrap();
        let snapshot = SystemAndroidKernelConfigSource::for_path(&config_path)
            .collect()
            .unwrap();
        assert_eq!(snapshot.option_count(), 2);
        assert_eq!(
            snapshot.nftables_observation_gate(),
            Ok(AndroidNftablesObservationGate::CompleteAbsent)
        );

        let link_path = directory.path().join("config-link.gz");
        symlink(&config_path, &link_path).unwrap();
        assert_eq!(
            SystemAndroidKernelConfigSource::for_path(link_path)
                .collect()
                .unwrap_err()
                .class(),
            SystemAndroidKernelConfigErrorClass::PathType
        );
    }

    #[test]
    fn system_source_rejects_invalid_gzip_and_decompressed_overflow() {
        let directory = tempdir().unwrap();
        let invalid = directory.path().join("invalid.gz");
        std::fs::write(&invalid, b"not gzip").unwrap();
        assert_eq!(
            SystemAndroidKernelConfigSource::for_path(invalid)
                .collect()
                .unwrap_err()
                .class(),
            SystemAndroidKernelConfigErrorClass::GzipDecoding
        );

        let oversized = directory.path().join("oversized.gz");
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(&vec![
                b'x';
                MAX_ANDROID_KERNEL_CONFIG_DECOMPRESSED_BYTES + 1
            ])
            .unwrap();
        std::fs::write(&oversized, encoder.finish().unwrap()).unwrap();
        assert_eq!(
            SystemAndroidKernelConfigSource::for_path(oversized)
                .collect()
                .unwrap_err()
                .class(),
            SystemAndroidKernelConfigErrorClass::LimitExceeded
        );
    }
}
