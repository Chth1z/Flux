use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use flux_core::{
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane,
    FwmarkUseOperation, FwmarkUseRecord, MAX_COMPLETE_FWMARK_CENSUS_MARK_USES,
};
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "linux", target_os = "android"))]
use super::read_only_netlink::collect_read_only_netlink_dump;
use super::read_only_netlink::{
    ReadOnlyNetlinkError, ReadOnlyNetlinkErrorKind, ReadOnlyNetlinkMessage,
};
use crate::netlink::{NLA_F_NESTED, NetlinkAttribute, NetlinkAttributeIter};

const NFTABLES_SNAPSHOT_DIGEST_DOMAIN: &[u8] =
    b"Flux native nftables fwmark snapshot\0canonical-schema-v1\0sha256-v1\0";
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NFT_RULE_RESPONSE_TYPE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE;
const NFT_RULE_REQUEST_TYPE: u16 = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE;
const NFNLGRP_NFTABLES: u32 = 7;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NFNETLINK_V0: u8 = 0;
const NFGENMSG_BYTES: usize = 4;
const NFT_RULE_REQUEST_BYTES: usize = 16 + NFGENMSG_BYTES;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_MAX: u16 = 11;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;
const NFT_META_MARK: u32 = 3;
const NFTA_SOCKET_KEY: u16 = 1;
const NFTA_SOCKET_DREG: u16 = 2;
const NFT_SOCKET_MARK: u32 = 1;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFTA_CT_SREG: u16 = 4;
const NFT_CT_MARK: u32 = 3;
const NFTA_FIB_FLAGS: u16 = 3;
const NFT_FIB_F_MARK: u32 = 1 << 2;

const ALL_PLANES: [FwmarkPlane; 3] = [
    FwmarkPlane::Packet,
    FwmarkPlane::Socket,
    FwmarkPlane::Conntrack,
];

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct AndroidNftablesSnapshotDigest([u8; 32]);

impl AndroidNftablesSnapshotDigest {
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Privacy-reduced native nftables mark evidence collected without an `nft` executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidNftablesFwmarkObservation {
    digest: AndroidNftablesSnapshotDigest,
    kernel_supported: bool,
    coverage: [FwmarkCensusCoverageRecord; ALL_PLANES.len()],
    mark_uses: Box<[FwmarkUseRecord]>,
    transfer_coverage: [FwmarkCensusCoverageRecord; ALL_PLANES.len()],
    transfer_mark_uses: Box<[FwmarkUseRecord]>,
    table_count: usize,
    chain_count: usize,
    rule_count: usize,
    expression_count: usize,
    opaque_expression_count: usize,
}

impl AndroidNftablesFwmarkObservation {
    #[must_use]
    pub const fn digest(&self) -> AndroidNftablesSnapshotDigest {
        self.digest
    }

    #[must_use]
    pub const fn kernel_supported(&self) -> bool {
        self.kernel_supported
    }

    #[must_use]
    pub fn coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.coverage
    }

    #[must_use]
    pub fn mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.mark_uses
    }

    #[must_use]
    pub fn transfer_coverage(&self) -> &[FwmarkCensusCoverageRecord] {
        &self.transfer_coverage
    }

    #[must_use]
    pub fn transfer_mark_uses(&self) -> &[FwmarkUseRecord] {
        &self.transfer_mark_uses
    }

    #[must_use]
    pub const fn table_count(&self) -> usize {
        self.table_count
    }

    #[must_use]
    pub const fn chain_count(&self) -> usize {
        self.chain_count
    }

    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }

    #[must_use]
    pub const fn expression_count(&self) -> usize {
        self.expression_count
    }

    #[must_use]
    pub const fn opaque_expression_count(&self) -> usize {
        self.opaque_expression_count
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidNftablesFwmarkObservationErrorKind {
    InvalidBound,
    Transport,
    SnapshotDrift,
    InvalidMessageType,
    InvalidFamilyHeader,
    InvalidRule,
    InvalidExpression,
    LimitExceeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AndroidNftablesFwmarkObservationError {
    kind: AndroidNftablesFwmarkObservationErrorKind,
    raw_os_error: Option<i32>,
}

impl AndroidNftablesFwmarkObservationError {
    const fn new(kind: AndroidNftablesFwmarkObservationErrorKind) -> Self {
        Self {
            kind,
            raw_os_error: None,
        }
    }

    const fn transport(source: ReadOnlyNetlinkError) -> Self {
        let kind = match source.kind() {
            ReadOnlyNetlinkErrorKind::InvalidBound => {
                AndroidNftablesFwmarkObservationErrorKind::InvalidBound
            }
            ReadOnlyNetlinkErrorKind::ConcurrentNotification
            | ReadOnlyNetlinkErrorKind::DumpInterrupted => {
                AndroidNftablesFwmarkObservationErrorKind::SnapshotDrift
            }
            ReadOnlyNetlinkErrorKind::LimitExceeded
            | ReadOnlyNetlinkErrorKind::TruncatedDatagram => {
                AndroidNftablesFwmarkObservationErrorKind::LimitExceeded
            }
            ReadOnlyNetlinkErrorKind::SystemCall
            | ReadOnlyNetlinkErrorKind::Timeout
            | ReadOnlyNetlinkErrorKind::ShortWrite
            | ReadOnlyNetlinkErrorKind::UnexpectedSender
            | ReadOnlyNetlinkErrorKind::MalformedDatagram
            | ReadOnlyNetlinkErrorKind::KernelRejected => {
                AndroidNftablesFwmarkObservationErrorKind::Transport
            }
        };
        Self {
            kind,
            raw_os_error: source.raw_os_error(),
        }
    }

    #[must_use]
    pub const fn kind(self) -> AndroidNftablesFwmarkObservationErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn raw_os_error(self) -> Option<i32> {
        self.raw_os_error
    }
}

impl fmt::Display for AndroidNftablesFwmarkObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "native nftables fwmark observation failed: {:?}",
            self.kind
        )?;
        if let Some(raw_os_error) = self.raw_os_error {
            write!(formatter, " (errno {raw_os_error})")?;
        }
        Ok(())
    }
}

impl Error for AndroidNftablesFwmarkObservationError {}

/// Collects the complete native nf_tables rule dump through `NETLINK_NETFILTER`.
///
/// A missing `nft` executable is irrelevant. A kernel-level unsupported response is represented as
/// complete absence at this point in time; permission failures and all other errors remain errors.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn collect_android_nftables_fwmarks(
    bound: Duration,
) -> Result<AndroidNftablesFwmarkObservation, AndroidNftablesFwmarkObservationError> {
    let sequence = 1;
    let request = nft_rule_dump_request(sequence);
    let group_mask = 1_u32 << (NFNLGRP_NFTABLES - 1);
    match collect_read_only_netlink_dump(
        libc::NETLINK_NETFILTER,
        group_mask,
        &request,
        sequence,
        bound,
    ) {
        Ok(messages) => observe_android_nftables_messages(&messages, true),
        Err(error)
            if error.kind() == ReadOnlyNetlinkErrorKind::KernelRejected
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP) | Some(libc::EPROTONOSUPPORT) | Some(libc::ENOENT)
                ) =>
        {
            Ok(absent_observation(false))
        }
        Err(error) => Err(AndroidNftablesFwmarkObservationError::transport(error)),
    }
}

fn nft_rule_dump_request(sequence: u32) -> [u8; NFT_RULE_REQUEST_BYTES] {
    let mut request = [0_u8; NFT_RULE_REQUEST_BYTES];
    request[..4].copy_from_slice(&(NFT_RULE_REQUEST_BYTES as u32).to_ne_bytes());
    request[4..6].copy_from_slice(&NFT_RULE_REQUEST_TYPE.to_ne_bytes());
    request[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request[8..12].copy_from_slice(&sequence.to_ne_bytes());
    request[16] = libc::AF_UNSPEC as u8;
    request[17] = NFNETLINK_V0;
    request
}

fn observe_android_nftables_messages(
    messages: &[ReadOnlyNetlinkMessage],
    kernel_supported: bool,
) -> Result<AndroidNftablesFwmarkObservation, AndroidNftablesFwmarkObservationError> {
    if messages.is_empty() {
        return Ok(absent_observation(kernel_supported));
    }

    let mut digest = Sha256::new();
    digest.update(NFTABLES_SNAPSHOT_DIGEST_DOMAIN);
    digest.update([u8::from(kernel_supported)]);
    digest_usize(&mut digest, messages.len());
    let mut tables = BTreeSet::new();
    let mut chains = BTreeSet::new();
    let mut mark_uses = Vec::new();
    let mut transfer_mark_uses = Vec::new();
    let mut expression_count = 0_usize;
    let mut opaque_expression_count = 0_usize;
    let mut opaque_transfer_count = 0_usize;

    for (rule_ordinal, message) in messages.iter().enumerate() {
        if message.message_type() != NFT_RULE_RESPONSE_TYPE {
            return Err(AndroidNftablesFwmarkObservationError::new(
                AndroidNftablesFwmarkObservationErrorKind::InvalidMessageType,
            ));
        }
        if message.flags() & 0x10 != 0 || message.payload().len() < NFGENMSG_BYTES {
            return Err(AndroidNftablesFwmarkObservationError::new(
                AndroidNftablesFwmarkObservationErrorKind::InvalidFamilyHeader,
            ));
        }
        let family = message.payload()[0];
        if message.payload()[1] != NFNETLINK_V0 || message.payload()[2..4] != [0, 0] {
            return Err(AndroidNftablesFwmarkObservationError::new(
                AndroidNftablesFwmarkObservationErrorKind::InvalidFamilyHeader,
            ));
        }
        let parsed = parse_rule(&message.payload()[NFGENMSG_BYTES..])?;
        tables.insert((family, parsed.table.to_vec()));
        chains.insert((family, parsed.table.to_vec(), parsed.chain.to_vec()));

        digest.update([family]);
        digest_usize(&mut digest, rule_ordinal);
        digest_bytes(&mut digest, parsed.table);
        digest_bytes(&mut digest, parsed.chain);
        digest_usize(&mut digest, parsed.expressions.len());
        let mut rule_accesses = Vec::new();
        for (expression_ordinal, expression) in parsed.expressions.into_iter().enumerate() {
            expression_count = expression_count.checked_add(1).ok_or_else(|| {
                AndroidNftablesFwmarkObservationError::new(
                    AndroidNftablesFwmarkObservationErrorKind::LimitExceeded,
                )
            })?;
            let projection = parse_expression(expression)?;
            digest_bytes(&mut digest, projection.name);
            digest.update([u8::from(projection.opaque)]);
            if projection.opaque {
                opaque_expression_count =
                    opaque_expression_count.checked_add(1).ok_or_else(|| {
                        AndroidNftablesFwmarkObservationError::new(
                            AndroidNftablesFwmarkObservationErrorKind::LimitExceeded,
                        )
                    })?;
                digest_bytes(&mut digest, projection.data);
            }
            if let Some(mut access) = projection.mark_access {
                access.expression_ordinal = expression_ordinal;
                rule_accesses.push(access);
            }
            for mark_use in projection.mark_uses {
                if mark_uses.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
                    return Err(AndroidNftablesFwmarkObservationError::new(
                        AndroidNftablesFwmarkObservationErrorKind::LimitExceeded,
                    ));
                }
                digest.update([plane_tag(mark_use.plane())]);
                digest.update([operation_tag(mark_use.operation())]);
                digest.update(mark_use.mask().to_be_bytes());
                mark_uses.push(mark_use);
            }
        }
        let transfer = project_rule_transfers(&rule_accesses);
        opaque_transfer_count = opaque_transfer_count
            .checked_add(usize::from(transfer.opaque))
            .ok_or_else(limit_error)?;
        for mark_use in transfer.mark_uses {
            if transfer_mark_uses.len() == MAX_COMPLETE_FWMARK_CENSUS_MARK_USES {
                return Err(limit_error());
            }
            digest.update([0x80 | plane_tag(mark_use.plane())]);
            digest.update([operation_tag(mark_use.operation())]);
            digest.update(mark_use.mask().to_be_bytes());
            transfer_mark_uses.push(mark_use);
        }
    }

    let coverage = coverage_for(&mark_uses, opaque_expression_count != 0);
    let transfer_coverage = transfer_coverage_for(
        &transfer_mark_uses,
        opaque_transfer_count != 0 || opaque_expression_count != 0,
    );
    digest_usize(&mut digest, tables.len());
    digest_usize(&mut digest, chains.len());
    digest_usize(&mut digest, expression_count);
    digest_usize(&mut digest, opaque_expression_count);
    digest_usize(&mut digest, opaque_transfer_count);
    Ok(AndroidNftablesFwmarkObservation {
        digest: AndroidNftablesSnapshotDigest(digest.finalize().into()),
        kernel_supported,
        coverage,
        mark_uses: mark_uses.into_boxed_slice(),
        transfer_coverage,
        transfer_mark_uses: transfer_mark_uses.into_boxed_slice(),
        table_count: tables.len(),
        chain_count: chains.len(),
        rule_count: messages.len(),
        expression_count,
        opaque_expression_count,
    })
}

fn absent_observation(kernel_supported: bool) -> AndroidNftablesFwmarkObservation {
    let mut digest = Sha256::new();
    digest.update(NFTABLES_SNAPSHOT_DIGEST_DOMAIN);
    digest.update([u8::from(kernel_supported)]);
    digest_usize(&mut digest, 0);
    digest_usize(&mut digest, 0);
    digest_usize(&mut digest, 0);
    digest_usize(&mut digest, 0);
    digest_usize(&mut digest, 0);
    digest_usize(&mut digest, 0);
    AndroidNftablesFwmarkObservation {
        digest: AndroidNftablesSnapshotDigest(digest.finalize().into()),
        kernel_supported,
        coverage: ALL_PLANES.map(|plane| {
            FwmarkCensusCoverageRecord::new(
                FwmarkEvidenceSource::Nftables,
                plane,
                FwmarkCensusCoverageState::CompleteAbsent,
            )
        }),
        mark_uses: Box::default(),
        transfer_coverage: ALL_PLANES.map(|plane| {
            FwmarkCensusCoverageRecord::new(
                FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
                plane,
                FwmarkCensusCoverageState::CompleteAbsent,
            )
        }),
        transfer_mark_uses: Box::default(),
        table_count: 0,
        chain_count: 0,
        rule_count: 0,
        expression_count: 0,
        opaque_expression_count: 0,
    }
}

struct ParsedRule<'a> {
    table: &'a [u8],
    chain: &'a [u8],
    expressions: Vec<&'a [u8]>,
}

fn parse_rule(bytes: &[u8]) -> Result<ParsedRule<'_>, AndroidNftablesFwmarkObservationError> {
    let mut table = None;
    let mut chain = None;
    let mut expressions = None;
    for attribute in NetlinkAttributeIter::new(bytes, 0) {
        let attribute = attribute.map_err(|_| invalid_rule())?;
        if attribute.attribute_type() > NFTA_RULE_MAX {
            return Err(invalid_rule());
        }
        match attribute.attribute_type() {
            NFTA_RULE_TABLE => assign_once(&mut table, parse_nul_string(attribute)?)?,
            NFTA_RULE_CHAIN => assign_once(&mut chain, parse_nul_string(attribute)?)?,
            NFTA_RULE_EXPRESSIONS => {
                require_nested(attribute)?;
                let mut parsed = Vec::new();
                for element in NetlinkAttributeIter::new(attribute.value(), 0) {
                    let element = element.map_err(|_| invalid_rule())?;
                    if element.attribute_type() != NFTA_LIST_ELEM {
                        return Err(invalid_rule());
                    }
                    require_nested(element)?;
                    parsed.push(element.value());
                }
                assign_once(&mut expressions, parsed)?;
            }
            _ => {}
        }
    }
    Ok(ParsedRule {
        table: table.ok_or_else(invalid_rule)?,
        chain: chain.ok_or_else(invalid_rule)?,
        expressions: expressions.ok_or_else(invalid_rule)?,
    })
}

struct ExpressionProjection<'a> {
    name: &'a [u8],
    data: &'a [u8],
    opaque: bool,
    mark_uses: Vec<FwmarkUseRecord>,
    mark_access: Option<RegisterMarkAccess>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegisterMarkAccessKind {
    Load,
    Store,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegisterMarkAccess {
    kind: RegisterMarkAccessKind,
    plane: FwmarkPlane,
    register: u32,
    expression_ordinal: usize,
}

fn parse_expression(
    bytes: &[u8],
) -> Result<ExpressionProjection<'_>, AndroidNftablesFwmarkObservationError> {
    let mut name = None;
    let mut data = None;
    for attribute in NetlinkAttributeIter::new(bytes, 0) {
        let attribute = attribute.map_err(|_| invalid_expression())?;
        match attribute.attribute_type() {
            NFTA_EXPR_NAME => assign_once(&mut name, parse_nul_string(attribute)?)?,
            NFTA_EXPR_DATA => {
                require_nested(attribute)?;
                assign_once(&mut data, attribute.value())?;
            }
            _ => return Err(invalid_expression()),
        }
    }
    let name = name.ok_or_else(invalid_expression)?;
    let data = data.ok_or_else(invalid_expression)?;
    let name_text = std::str::from_utf8(name).map_err(|_| invalid_expression())?;
    let mut mark_uses = Vec::new();
    let mut mark_access = None;
    let opaque = match name_text {
        "meta" => {
            mark_access = parse_load_store_expression(
                data,
                NFTA_META_KEY,
                NFT_META_MARK,
                NFTA_META_DREG,
                Some(NFTA_META_SREG),
                FwmarkPlane::Packet,
                &mut mark_uses,
            )?;
            false
        }
        "socket" => {
            mark_access = parse_load_store_expression(
                data,
                NFTA_SOCKET_KEY,
                NFT_SOCKET_MARK,
                NFTA_SOCKET_DREG,
                None,
                FwmarkPlane::Socket,
                &mut mark_uses,
            )?;
            false
        }
        "ct" => {
            mark_access = parse_load_store_expression(
                data,
                NFTA_CT_KEY,
                NFT_CT_MARK,
                NFTA_CT_DREG,
                Some(NFTA_CT_SREG),
                FwmarkPlane::Conntrack,
                &mut mark_uses,
            )?;
            false
        }
        "fib" => {
            if let Some(flags) = unique_be_u32(data, NFTA_FIB_FLAGS)?
                && flags & NFT_FIB_F_MARK != 0
            {
                mark_uses.push(full_mark_use(
                    FwmarkPlane::Packet,
                    FwmarkUseOperation::PredicateRead,
                ));
            }
            false
        }
        "match" | "target" | "dynset" => true,
        name if KNOWN_NON_MARK_EXPRESSIONS.contains(&name) => false,
        _ => true,
    };
    Ok(ExpressionProjection {
        name,
        data,
        opaque,
        mark_uses,
        mark_access,
    })
}

const KNOWN_NON_MARK_EXPRESSIONS: &[&str] = &[
    "bitwise",
    "byteorder",
    "cmp",
    "connlimit",
    "counter",
    "dup",
    "exthdr",
    "flow_offload",
    "fwd",
    "hash",
    "immediate",
    "last",
    "limit",
    "log",
    "lookup",
    "masq",
    "nat",
    "notrack",
    "numgen",
    "objref",
    "osf",
    "payload",
    "queue",
    "quota",
    "range",
    "redir",
    "reject",
    "rt",
    "secmark",
    "synproxy",
    "tproxy",
    "xfrm",
];

fn parse_load_store_expression(
    data: &[u8],
    key_attribute: u16,
    mark_key: u32,
    destination_register_attribute: u16,
    source_register_attribute: Option<u16>,
    plane: FwmarkPlane,
    mark_uses: &mut Vec<FwmarkUseRecord>,
) -> Result<Option<RegisterMarkAccess>, AndroidNftablesFwmarkObservationError> {
    let Some(key) = unique_be_u32(data, key_attribute)? else {
        return Err(invalid_expression());
    };
    if key != mark_key {
        return Ok(None);
    }
    let destination = unique_be_u32(data, destination_register_attribute)?;
    let source = source_register_attribute
        .map(|attribute| unique_be_u32(data, attribute))
        .transpose()?
        .flatten();
    let access = match (destination, source) {
        (Some(register), None) => {
            mark_uses.push(full_mark_use(plane, FwmarkUseOperation::PredicateRead));
            RegisterMarkAccess {
                kind: RegisterMarkAccessKind::Load,
                plane,
                register,
                expression_ordinal: 0,
            }
        }
        (None, Some(register)) => {
            mark_uses.push(full_mark_use(plane, FwmarkUseOperation::MaskedWrite));
            RegisterMarkAccess {
                kind: RegisterMarkAccessKind::Store,
                plane,
                register,
                expression_ordinal: 0,
            }
        }
        (None, None) | (Some(_), Some(_)) => return Err(invalid_expression()),
    };
    Ok(Some(access))
}

struct RuleTransferProjection {
    mark_uses: Vec<FwmarkUseRecord>,
    opaque: bool,
}

fn project_rule_transfers(accesses: &[RegisterMarkAccess]) -> RuleTransferProjection {
    let cross_plane_pairs = accesses
        .windows(2)
        .filter(|pair| {
            pair[0].kind == RegisterMarkAccessKind::Load
                && pair[1].kind == RegisterMarkAccessKind::Store
                && pair[0].register == pair[1].register
                && pair[0].plane != pair[1].plane
                && pair[1].expression_ordinal == pair[0].expression_ordinal + 1
        })
        .collect::<Vec<_>>();
    let distinct_planes = accesses
        .iter()
        .map(|access| access.plane)
        .collect::<BTreeSet<_>>();
    let opaque = distinct_planes.len() > 1 && (accesses.len() != 2 || cross_plane_pairs.len() != 1);
    let mut mark_uses = Vec::new();
    for pair in cross_plane_pairs {
        mark_uses.push(transfer_mark_use(
            pair[0].plane,
            FwmarkUseOperation::TransferRead,
        ));
        mark_uses.push(transfer_mark_use(
            pair[1].plane,
            FwmarkUseOperation::TransferWrite,
        ));
    }
    RuleTransferProjection { mark_uses, opaque }
}

fn transfer_mark_use(plane: FwmarkPlane, operation: FwmarkUseOperation) -> FwmarkUseRecord {
    FwmarkUseRecord::new(
        FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
        plane,
        operation,
        u32::MAX,
    )
    .expect("the full mark mask is nonzero")
}

fn unique_be_u32(
    data: &[u8],
    expected: u16,
) -> Result<Option<u32>, AndroidNftablesFwmarkObservationError> {
    let mut value = None;
    for attribute in NetlinkAttributeIter::new(data, 0) {
        let attribute = attribute.map_err(|_| invalid_expression())?;
        if attribute.attribute_type() == expected {
            if attribute.value().len() != 4 || value.is_some() {
                return Err(invalid_expression());
            }
            value = Some(u32::from_be_bytes(
                attribute
                    .value()
                    .try_into()
                    .expect("validated four-byte nftables value"),
            ));
        }
    }
    Ok(value)
}

fn full_mark_use(plane: FwmarkPlane, operation: FwmarkUseOperation) -> FwmarkUseRecord {
    FwmarkUseRecord::new(FwmarkEvidenceSource::Nftables, plane, operation, u32::MAX)
        .expect("the full mark mask is nonzero")
}

fn coverage_for(
    mark_uses: &[FwmarkUseRecord],
    opaque: bool,
) -> [FwmarkCensusCoverageRecord; ALL_PLANES.len()] {
    ALL_PLANES.map(|plane| {
        let state = if opaque {
            FwmarkCensusCoverageState::Opaque
        } else if mark_uses.iter().any(|record| record.plane() == plane) {
            FwmarkCensusCoverageState::CompletePresent
        } else {
            FwmarkCensusCoverageState::CompleteAbsent
        };
        FwmarkCensusCoverageRecord::new(FwmarkEvidenceSource::Nftables, plane, state)
    })
}

fn transfer_coverage_for(
    mark_uses: &[FwmarkUseRecord],
    opaque: bool,
) -> [FwmarkCensusCoverageRecord; ALL_PLANES.len()] {
    ALL_PLANES.map(|plane| {
        let state = if opaque {
            FwmarkCensusCoverageState::Opaque
        } else if mark_uses.iter().any(|record| record.plane() == plane) {
            FwmarkCensusCoverageState::CompletePresent
        } else {
            FwmarkCensusCoverageState::CompleteAbsent
        };
        FwmarkCensusCoverageRecord::new(
            FwmarkEvidenceSource::ConnmarkAndSocketTransfers,
            plane,
            state,
        )
    })
}

fn parse_nul_string(
    attribute: NetlinkAttribute<'_>,
) -> Result<&[u8], AndroidNftablesFwmarkObservationError> {
    if attribute.flags() != 0
        || attribute.value().len() < 2
        || attribute.value().last() != Some(&0)
        || attribute.value()[..attribute.value().len() - 1].contains(&0)
    {
        return Err(invalid_rule());
    }
    Ok(&attribute.value()[..attribute.value().len() - 1])
}

fn require_nested(
    attribute: NetlinkAttribute<'_>,
) -> Result<(), AndroidNftablesFwmarkObservationError> {
    if attribute.flags() == NLA_F_NESTED {
        Ok(())
    } else {
        Err(invalid_rule())
    }
}

fn assign_once<T>(
    target: &mut Option<T>,
    value: T,
) -> Result<(), AndroidNftablesFwmarkObservationError> {
    if target.replace(value).is_some() {
        Err(invalid_rule())
    } else {
        Ok(())
    }
}

fn invalid_rule() -> AndroidNftablesFwmarkObservationError {
    AndroidNftablesFwmarkObservationError::new(
        AndroidNftablesFwmarkObservationErrorKind::InvalidRule,
    )
}

fn invalid_expression() -> AndroidNftablesFwmarkObservationError {
    AndroidNftablesFwmarkObservationError::new(
        AndroidNftablesFwmarkObservationErrorKind::InvalidExpression,
    )
}

fn limit_error() -> AndroidNftablesFwmarkObservationError {
    AndroidNftablesFwmarkObservationError::new(
        AndroidNftablesFwmarkObservationErrorKind::LimitExceeded,
    )
}

fn plane_tag(plane: FwmarkPlane) -> u8 {
    match plane {
        FwmarkPlane::Packet => 0,
        FwmarkPlane::Socket => 1,
        FwmarkPlane::Conntrack => 2,
    }
}

fn operation_tag(operation: FwmarkUseOperation) -> u8 {
    match operation {
        FwmarkUseOperation::PredicateRead => 0,
        FwmarkUseOperation::MaskedWrite => 1,
        FwmarkUseOperation::TransferRead => 2,
        FwmarkUseOperation::TransferWrite => 3,
    }
}

fn digest_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest_usize(digest, bytes.len());
    digest.update(bytes);
}

fn digest_usize(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_NET_ADMIN in the current network namespace"]
    fn privileged_native_nftables_dump_smoke() {
        collect_android_nftables_fwmarks(Duration::from_secs(2))
            .expect("collect native nftables state");
    }

    #[test]
    fn native_rule_projection_covers_packet_socket_conntrack_and_fib_marks() {
        let message = rule_message(vec![
            expression(
                "meta",
                vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_DREG, 1)],
            ),
            expression(
                "meta",
                vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_SREG, 1)],
            ),
            expression(
                "socket",
                vec![
                    be32(NFTA_SOCKET_KEY, NFT_SOCKET_MARK),
                    be32(NFTA_SOCKET_DREG, 1),
                ],
            ),
            expression(
                "ct",
                vec![be32(NFTA_CT_KEY, NFT_CT_MARK), be32(NFTA_CT_DREG, 1)],
            ),
            expression(
                "ct",
                vec![be32(NFTA_CT_KEY, NFT_CT_MARK), be32(NFTA_CT_SREG, 1)],
            ),
            expression("fib", vec![be32(NFTA_FIB_FLAGS, NFT_FIB_F_MARK)]),
        ]);
        let observation = observe_android_nftables_messages(&[message], true).unwrap();
        assert_eq!(observation.table_count(), 1);
        assert_eq!(observation.chain_count(), 1);
        assert_eq!(observation.rule_count(), 1);
        assert_eq!(observation.expression_count(), 6);
        assert_eq!(observation.opaque_expression_count(), 0);
        assert_eq!(observation.mark_uses().len(), 6);
        assert!(
            observation
                .coverage()
                .iter()
                .all(|record| { record.state() == FwmarkCensusCoverageState::CompletePresent })
        );
    }

    #[test]
    fn exact_adjacent_cross_plane_register_copy_is_separate_transfer_evidence() {
        let observation = observe_android_nftables_messages(
            &[rule_message(vec![
                expression(
                    "ct",
                    vec![be32(NFTA_CT_KEY, NFT_CT_MARK), be32(NFTA_CT_DREG, 9)],
                ),
                expression(
                    "meta",
                    vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_SREG, 9)],
                ),
            ])],
            true,
        )
        .unwrap();
        assert_eq!(
            observation.transfer_mark_uses(),
            [
                transfer_mark_use(FwmarkPlane::Conntrack, FwmarkUseOperation::TransferRead),
                transfer_mark_use(FwmarkPlane::Packet, FwmarkUseOperation::TransferWrite),
            ]
        );
        assert_eq!(
            observation.transfer_coverage()[0].state(),
            FwmarkCensusCoverageState::CompletePresent
        );
        assert_eq!(
            observation.transfer_coverage()[1].state(),
            FwmarkCensusCoverageState::CompleteAbsent
        );
        assert_eq!(
            observation.transfer_coverage()[2].state(),
            FwmarkCensusCoverageState::CompletePresent
        );
    }

    #[test]
    fn nonadjacent_cross_plane_register_flow_is_opaque_not_assumed_transfer() {
        let observation = observe_android_nftables_messages(
            &[rule_message(vec![
                expression(
                    "ct",
                    vec![be32(NFTA_CT_KEY, NFT_CT_MARK), be32(NFTA_CT_DREG, 9)],
                ),
                expression("counter", Vec::new()),
                expression(
                    "meta",
                    vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_SREG, 9)],
                ),
            ])],
            true,
        )
        .unwrap();
        assert!(observation.transfer_mark_uses().is_empty());
        assert!(
            observation
                .transfer_coverage()
                .iter()
                .all(|record| { record.state() == FwmarkCensusCoverageState::Opaque })
        );
    }

    #[test]
    fn empty_native_dump_is_complete_absence_even_when_kernel_support_differs() {
        let supported = observe_android_nftables_messages(&[], true).unwrap();
        let unsupported = absent_observation(false);
        assert!(supported.kernel_supported());
        assert!(!unsupported.kernel_supported());
        assert!(supported.mark_uses().is_empty());
        assert!(
            supported
                .coverage()
                .iter()
                .all(|record| { record.state() == FwmarkCensusCoverageState::CompleteAbsent })
        );
        assert_ne!(supported.digest(), unsupported.digest());
    }

    #[test]
    fn unknown_and_compat_expressions_make_every_plane_opaque() {
        for name in ["vendor_extension", "match", "target", "dynset"] {
            let observation = observe_android_nftables_messages(
                &[rule_message(vec![expression(name, Vec::new())])],
                true,
            )
            .unwrap();
            assert_eq!(observation.opaque_expression_count(), 1);
            assert!(
                observation
                    .coverage()
                    .iter()
                    .all(|record| { record.state() == FwmarkCensusCoverageState::Opaque })
            );
            assert!(
                observation
                    .transfer_coverage()
                    .iter()
                    .all(|record| { record.state() == FwmarkCensusCoverageState::Opaque })
            );
        }
    }

    #[test]
    fn malformed_or_ambiguous_mark_expressions_fail_closed() {
        for expression in [
            expression("meta", vec![be32(NFTA_META_KEY, NFT_META_MARK)]),
            expression(
                "meta",
                vec![
                    be32(NFTA_META_KEY, NFT_META_MARK),
                    be32(NFTA_META_DREG, 1),
                    be32(NFTA_META_SREG, 1),
                ],
            ),
            expression(
                "ct",
                vec![
                    be32(NFTA_CT_KEY, NFT_CT_MARK),
                    be32(NFTA_CT_DREG, 1),
                    be32(NFTA_CT_DREG, 2),
                ],
            ),
        ] {
            assert_eq!(
                observe_android_nftables_messages(&[rule_message(vec![expression])], true)
                    .unwrap_err()
                    .kind(),
                AndroidNftablesFwmarkObservationErrorKind::InvalidExpression
            );
        }
    }

    #[test]
    fn canonical_digest_binds_mark_semantics_and_ignores_nonmark_expression_data() {
        let read = observe_android_nftables_messages(
            &[rule_message(vec![expression(
                "meta",
                vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_DREG, 1)],
            )])],
            true,
        )
        .unwrap();
        let write = observe_android_nftables_messages(
            &[rule_message(vec![expression(
                "meta",
                vec![be32(NFTA_META_KEY, NFT_META_MARK), be32(NFTA_META_SREG, 1)],
            )])],
            true,
        )
        .unwrap();
        assert_ne!(read.digest(), write.digest());

        let first_counter = observe_android_nftables_messages(
            &[rule_message(vec![expression("counter", vec![be32(1, 1)])])],
            true,
        )
        .unwrap();
        let second_counter = observe_android_nftables_messages(
            &[rule_message(vec![expression("counter", vec![be32(1, 99)])])],
            true,
        )
        .unwrap();
        assert_eq!(first_counter.digest(), second_counter.digest());
    }

    fn rule_message(expressions: Vec<Vec<u8>>) -> ReadOnlyNetlinkMessage {
        let expression_list = expressions
            .into_iter()
            .flat_map(|expression| nla(NFTA_LIST_ELEM | NLA_F_NESTED, &expression))
            .collect::<Vec<_>>();
        let mut payload = vec![libc::AF_INET as u8, NFNETLINK_V0, 0, 0];
        payload.extend(nla(NFTA_RULE_TABLE, b"mangle\0"));
        payload.extend(nla(NFTA_RULE_CHAIN, b"output\0"));
        payload.extend(nla(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED, &expression_list));
        ReadOnlyNetlinkMessage::fixture(NFT_RULE_RESPONSE_TYPE, 0, payload)
    }

    fn expression(name: &str, data: Vec<Vec<u8>>) -> Vec<u8> {
        let data = data.into_iter().flatten().collect::<Vec<_>>();
        let mut bytes = nla(NFTA_EXPR_NAME, format!("{name}\0").as_bytes());
        bytes.extend(nla(NFTA_EXPR_DATA | NLA_F_NESTED, &data));
        bytes
    }

    fn be32(attribute_type: u16, value: u32) -> Vec<u8> {
        nla(attribute_type, &value.to_be_bytes())
    }

    fn nla(attribute_type: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let aligned = (length + 3) & !3;
        let mut bytes = vec![0_u8; aligned];
        bytes[..2].copy_from_slice(&(length as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&attribute_type.to_ne_bytes());
        bytes[4..length].copy_from_slice(value);
        bytes
    }
}
