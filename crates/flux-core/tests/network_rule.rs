use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flux_core::{
    InterfaceName, MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS, NetworkAddressFamily, NetworkRuleRecord,
    NetworkRuleRecordErrorKind, OpaqueRuleAttribute, RuleAction, RuleAttributeCoverage,
    RuleAttributeOpacity, RuleFlags, RuleFlowId, RuleFwMark, RuleIpProtocol,
    RuleOpaqueAttributeFingerprint, RulePortRange, RulePortRangeErrorKind, RulePrefix,
    RulePrefixErrorKind, RulePriority, RuleProperties, RuleProtocol, RuleSuppressInterfaceGroup,
    RuleSuppressPrefixLength, RuleTableId, RuleTunnelId, RuleUidRange, RuleUidRangeErrorKind,
};

#[test]
fn rule_prefixes_mask_host_bits_and_validate_family_width() {
    let ipv4 =
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 193)), 24).expect("IPv4 rule prefix");
    let ipv6 = RulePrefix::new("2001:db8:1:2:3:4:5:6".parse().expect("IPv6 address"), 48)
        .expect("IPv6 rule prefix");
    let ipv4_default =
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 0).expect("IPv4 default");
    let ipv6_default = RulePrefix::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0).expect("IPv6 default");
    let ipv4_host =
        RulePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 193)), 32).expect("IPv4 host");
    let ipv6_host =
        RulePrefix::new("2001:db8::1".parse().expect("IPv6 address"), 128).expect("IPv6 host");

    assert_eq!(ipv4.family(), NetworkAddressFamily::Ipv4);
    assert_eq!(ipv4.address(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
    assert_eq!(ipv4.prefix_length(), 24);
    assert_eq!(
        ipv6.address(),
        "2001:db8:1::".parse::<IpAddr>().expect("IPv6 network")
    );
    assert_eq!(ipv6.prefix_length(), 48);
    assert_eq!(
        ipv4_default,
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(
        ipv6_default,
        RulePrefix::unspecified(NetworkAddressFamily::Ipv6)
    );
    assert_eq!(
        ipv4_host.address(),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 193))
    );
    assert_eq!(
        ipv6_host.address(),
        "2001:db8::1".parse::<IpAddr>().expect("IPv6 host")
    );

    for (address, prefix_length) in [
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129),
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), u8::MAX),
    ] {
        let error = RulePrefix::new(address, prefix_length)
            .expect_err("prefix length must fit its address family");
        assert_eq!(error.kind(), RulePrefixErrorKind::InvalidPrefixLength);
        assert_eq!(error.address(), address);
        assert_eq!(error.prefix_length(), prefix_length);
    }
}

#[test]
fn ipv4_mapped_ipv6_rule_prefixes_remain_ipv6_when_canonicalized() {
    let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x02ff);
    let prefix = RulePrefix::new(IpAddr::V6(mapped), 120).expect("mapped IPv6 prefix");

    assert_eq!(prefix.family(), NetworkAddressFamily::Ipv6);
    assert_eq!(
        prefix.address(),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0200))
    );
    assert_eq!(prefix.prefix_length(), 120);
}

#[test]
fn rule_properties_preserve_unknown_kernel_values_and_dynamic_flags() {
    let properties = RuleProperties::new(
        0xfe,
        RuleTableId::from_raw(u32::MAX),
        RuleAction::from_raw(0xfa),
        RuleProtocol::from_raw(0xfb),
        RuleFlags::from_raw(0x8001_001f),
    );

    assert_eq!(properties.tos(), 0xfe);
    assert_eq!(properties.table().get(), u32::MAX);
    assert_eq!(properties.action().raw(), 0xfa);
    assert_eq!(properties.protocol().raw(), 0xfb);
    assert_eq!(properties.flags().raw(), 0x8001_001f);
    for known in [
        RuleFlags::PERMANENT,
        RuleFlags::INVERT,
        RuleFlags::UNRESOLVED,
        RuleFlags::INPUT_INTERFACE_DETACHED,
        RuleFlags::OUTPUT_INTERFACE_DETACHED,
        RuleFlags::FIND_SOURCE_ADDRESS,
    ] {
        assert_ne!(properties.flags().raw() & known.raw(), 0);
    }
    assert_eq!(RuleAction::UNSPECIFIED.raw(), 0);
    assert_eq!(RuleAction::TO_TABLE.raw(), 1);
    assert_eq!(RuleAction::GOTO.raw(), 2);
    assert_eq!(RuleAction::NOP.raw(), 3);
    assert_eq!(RuleAction::BLACKHOLE.raw(), 6);
    assert_eq!(RuleAction::UNREACHABLE.raw(), 7);
    assert_eq!(RuleAction::PROHIBIT.raw(), 8);
}

#[test]
fn firewall_marks_canonicalize_to_effective_masked_selection() {
    assert_eq!(RuleFwMark::new(0, 0), None);
    assert_eq!(RuleFwMark::new(u32::MAX, 0), None);

    let masked = RuleFwMark::new(0xf3, 0x0f).expect("material masked mark");
    let already_canonical = RuleFwMark::new(0x03, 0x0f).expect("canonical masked mark");
    let zero_value = RuleFwMark::new(0, 0xff00).expect("zero mark with material mask");

    assert_eq!(masked, already_canonical);
    assert_eq!(masked.value(), 3);
    assert_eq!(masked.mask(), 0x0f);
    assert_eq!(zero_value.value(), 0);
    assert_eq!(zero_value.mask(), 0xff00);
}

#[test]
fn raw_selector_differences_canonicalize_to_equal_records_without_implying_deduplication() {
    let first_destination = RulePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24)
        .expect("first raw destination");
    let second_destination = RulePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)), 24)
        .expect("second raw destination");
    let first_mark = RuleFwMark::new(0xffff_00f3, 0xff).expect("first raw mark");
    let second_mark = RuleFwMark::new(0xaaaa_55f3, 0xff).expect("second raw mark");

    let first = NetworkRuleRecord::new(
        first_destination,
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(0, 254, RuleAction::TO_TABLE),
        RulePriority::from_raw(100),
        None,
    )
    .expect("first canonical record")
    .with_fwmark(first_mark);
    let second = NetworkRuleRecord::new(
        second_destination,
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(0, 254, RuleAction::TO_TABLE),
        RulePriority::from_raw(100),
        None,
    )
    .expect("second canonical record")
    .with_fwmark(second_mark);

    assert_eq!(first, second);

    // Equal semantic records may coexist in Linux's ordered rule multiset. A future snapshot must
    // preserve both positions and must not infer deduplication from record equality.
    let ordered_multiset = [first, second];
    assert_eq!(ordered_multiset.len(), 2);
    assert_eq!(ordered_multiset[0], ordered_multiset[1]);
}

#[test]
fn rule_attribute_coverage_defaults_complete_and_opacity_changes_record_identity() {
    let complete = ipv4_record();
    assert_eq!(
        complete.attribute_coverage(),
        &RuleAttributeCoverage::Complete
    );
    assert!(complete.has_complete_attribute_coverage());

    let details = [
        OpaqueRuleAttribute::new(25, 0, 4),
        OpaqueRuleAttribute::new(25, 0x8000, 3),
    ];
    let first_fingerprint = RuleOpaqueAttributeFingerprint::from_bytes([0x11; 32]);
    let opacity = RuleAttributeOpacity::new(details, 2, first_fingerprint)
        .expect("bounded nonempty opacity evidence");
    assert_eq!(opacity.retained_details(), &details);
    assert_eq!(opacity.omitted_details(), 2);
    assert_eq!(opacity.total_attributes(), 4);
    assert_eq!(opacity.fingerprint(), first_fingerprint);

    let opaque = complete.clone().with_attribute_opacity(opacity);
    assert!(!opaque.has_complete_attribute_coverage());
    assert_ne!(opaque, complete);
    assert_eq!(
        opaque
            .attribute_coverage()
            .opacity()
            .expect("opaque coverage")
            .retained_details(),
        &details
    );

    let changed_payload_fingerprint = complete.with_attribute_opacity(
        RuleAttributeOpacity::new(
            details,
            2,
            RuleOpaqueAttributeFingerprint::from_bytes([0x22; 32]),
        )
        .expect("second opacity evidence"),
    );
    assert_ne!(opaque, changed_payload_fingerprint);

    assert!(
        RuleAttributeOpacity::new([], 0, first_fingerprint).is_none(),
        "opacity must retain at least one diagnostic detail"
    );
    assert!(
        RuleAttributeOpacity::new(
            std::iter::repeat_n(
                OpaqueRuleAttribute::new(30, 0, 1),
                MAX_OPAQUE_RULE_ATTRIBUTE_DETAILS + 1,
            ),
            0,
            first_fingerprint,
        )
        .is_none(),
        "callers cannot exceed the retained-detail bound"
    );
}

#[test]
fn uid_ranges_cover_the_complete_valid_kernel_domain() {
    for (start, end) in [(0, 0), (0, u32::MAX - 1), (u32::MAX - 1, u32::MAX - 1)] {
        let range = RuleUidRange::new(start, end).expect("valid inclusive UID range");
        assert_eq!(range.start(), start);
        assert_eq!(range.end(), end);
    }

    for (start, end, kind) in [
        (u32::MAX, u32::MAX, RuleUidRangeErrorKind::InvalidUid),
        (0, u32::MAX, RuleUidRangeErrorKind::InvalidUid),
        (7, 6, RuleUidRangeErrorKind::StartAfterEnd),
    ] {
        let error = RuleUidRange::new(start, end).expect_err("invalid UID range");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.start(), start);
        assert_eq!(error.end(), end);
    }
}

#[test]
fn port_ranges_enforce_linux_fib_rule_boundaries() {
    for (start, end) in [(1, 1), (1, u16::MAX - 1), (u16::MAX - 1, u16::MAX - 1)] {
        let range = RulePortRange::new(start, end).expect("valid inclusive port range");
        assert_eq!(range.start(), start);
        assert_eq!(range.end(), end);
    }

    for (start, end, kind) in [
        (0, 1, RulePortRangeErrorKind::ZeroPort),
        (1, 0, RulePortRangeErrorKind::ZeroPort),
        (1, u16::MAX, RulePortRangeErrorKind::MaximumPort),
        (8, 7, RulePortRangeErrorKind::StartAfterEnd),
    ] {
        let error = RulePortRange::new(start, end).expect_err("invalid port range");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.start(), start);
        assert_eq!(error.end(), end);
    }
}

#[test]
fn optional_numeric_selectors_canonicalize_kernel_absence_sentinels() {
    assert_eq!(RuleTunnelId::new(0), None);
    assert_eq!(
        RuleTunnelId::new(u64::MAX).map(RuleTunnelId::get),
        Some(u64::MAX)
    );
    assert_eq!(RuleIpProtocol::new(0), None);
    assert_eq!(
        RuleIpProtocol::new(u8::MAX).map(RuleIpProtocol::get),
        Some(u8::MAX)
    );
    assert_eq!(RuleFlowId::new(0), None);
    assert_eq!(
        RuleFlowId::new(u32::MAX).map(RuleFlowId::get),
        Some(u32::MAX)
    );
    assert_eq!(RuleSuppressInterfaceGroup::from_raw(u32::MAX), None);
    assert_eq!(
        RuleSuppressInterfaceGroup::from_raw(u32::MAX - 1).map(RuleSuppressInterfaceGroup::get),
        Some(u32::MAX - 1)
    );
    assert_eq!(
        RuleSuppressInterfaceGroup::from_raw(0).map(RuleSuppressInterfaceGroup::get),
        Some(0)
    );
    assert_eq!(RuleSuppressPrefixLength::from_raw(u32::MAX), None);
    assert_eq!(
        RuleSuppressPrefixLength::from_raw(u32::MAX - 1).map(RuleSuppressPrefixLength::get),
        Some(u32::MAX - 1)
    );
    assert_eq!(
        RuleSuppressPrefixLength::from_raw(0).map(RuleSuppressPrefixLength::get),
        Some(0)
    );
    assert_eq!(RuleTableId::from_raw(u32::MAX).get(), u32::MAX);
    assert_eq!(RulePriority::from_raw(u32::MAX).get(), u32::MAX);
}

#[test]
fn rule_records_reject_mixed_families_and_invalid_ipv4_tos() {
    let error = NetworkRuleRecord::new(
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv6),
        properties(0, 254, RuleAction::TO_TABLE),
        RulePriority::from_raw(100),
        None,
    )
    .expect_err("source and destination must have one family");
    assert_eq!(
        error.kind(),
        NetworkRuleRecordErrorKind::AddressFamilyMismatch
    );

    for tos in [0, 0x02, 0x1e] {
        let record = record(
            NetworkAddressFamily::Ipv4,
            tos,
            254,
            RuleAction::TO_TABLE,
            100,
            None,
        )
        .expect("valid IPv4 TOS");
        assert_eq!(record.properties().tos(), tos);
    }
    for tos in [0x01, 0x20, 0x80, u8::MAX] {
        let error = record(
            NetworkAddressFamily::Ipv4,
            tos,
            254,
            RuleAction::TO_TABLE,
            100,
            None,
        )
        .expect_err("IPv4 rule TOS only admits IPTOS_TOS_MASK bits");
        assert_eq!(error.kind(), NetworkRuleRecordErrorKind::InvalidIpv4Tos);
    }

    let ipv6 = record(
        NetworkAddressFamily::Ipv6,
        u8::MAX,
        254,
        RuleAction::TO_TABLE,
        100,
        None,
    )
    .expect("IPv6 traffic class preserves every bit");
    assert_eq!(ipv6.properties().tos(), u8::MAX);
}

#[test]
fn goto_rules_require_a_strictly_forward_target_and_other_actions_forbid_one() {
    let missing = record(
        NetworkAddressFamily::Ipv4,
        0,
        0,
        RuleAction::GOTO,
        100,
        None,
    )
    .expect_err("goto target is required");
    assert_eq!(
        missing.kind(),
        NetworkRuleRecordErrorKind::MissingGotoTarget
    );

    let unexpected = record(
        NetworkAddressFamily::Ipv4,
        0,
        254,
        RuleAction::TO_TABLE,
        100,
        Some(101),
    )
    .expect_err("non-goto action cannot have a target");
    assert_eq!(
        unexpected.kind(),
        NetworkRuleRecordErrorKind::UnexpectedGotoTarget
    );

    for target in [0, 99, 100] {
        let backward = record(
            NetworkAddressFamily::Ipv4,
            0,
            0,
            RuleAction::GOTO,
            100,
            Some(target),
        )
        .expect_err("goto target must be after current priority");
        assert_eq!(backward.kind(), NetworkRuleRecordErrorKind::BackwardGoto);
    }

    let target = u32::MAX;
    let goto = record(
        NetworkAddressFamily::Ipv4,
        0,
        0,
        RuleAction::GOTO,
        u32::MAX - 1,
        Some(target),
    )
    .expect("maximum forward goto target");
    assert_eq!(goto.goto_target().map(RulePriority::get), Some(target));
}

#[test]
fn l3mdev_and_flow_enforce_only_their_stable_cross_field_rules() {
    let table_conflict = ipv4_record()
        .with_l3mdev()
        .expect_err("l3mdev and a nonzero table are mutually exclusive");
    assert_eq!(
        table_conflict.kind(),
        NetworkRuleRecordErrorKind::L3mdevTableConflict
    );

    let l3mdev = record(
        NetworkAddressFamily::Ipv4,
        0,
        0,
        RuleAction::TO_TABLE,
        100,
        None,
    )
    .expect("table-zero rule")
    .with_l3mdev()
    .expect("valid l3mdev rule");
    assert!(l3mdev.l3mdev());

    let flow = RuleFlowId::new(u32::MAX).expect("nonzero flow ID");
    let ipv4 = ipv4_record().with_flow(flow).expect("IPv4 flow/class ID");
    assert_eq!(ipv4.flow(), Some(flow));

    let error = ipv6_record()
        .with_flow(flow)
        .expect_err("IPv6 does not carry FRA_FLOW");
    assert_eq!(error.kind(), NetworkRuleRecordErrorKind::FlowUnsupported);
}

#[test]
fn rule_record_carries_every_supported_selector_without_assuming_utf8() {
    let fwmark = RuleFwMark::new(0xffff_00f3, 0x0000_00ff).expect("effective fwmark");
    let input = InterfaceName::new(&[b'i', b'i', 0xff]).expect("raw input interface");
    let output = InterfaceName::new(&[b'o', b'i', 0xfe]).expect("raw output interface");
    let tunnel_id = RuleTunnelId::new(u64::MAX).expect("nonzero tunnel ID");
    let suppress_group = RuleSuppressInterfaceGroup::from_raw(0).expect("group zero");
    let suppress_prefix = RuleSuppressPrefixLength::from_raw(128).expect("prefix suppression");
    let uid_range = RuleUidRange::new(10_000, 19_999).expect("UID range");
    let ip_protocol = RuleIpProtocol::new(17).expect("UDP protocol number");
    let source_ports = RulePortRange::new(53, 53).expect("source port range");
    let destination_ports = RulePortRange::new(1024, 65_534).expect("destination port range");
    let flow = RuleFlowId::new(0x1234_5678).expect("flow ID");

    let record = ipv4_record()
        .with_fwmark(fwmark)
        .with_input_interface(input)
        .with_output_interface(output)
        .with_tunnel_id(tunnel_id)
        .with_suppress_interface_group(suppress_group)
        .with_suppress_prefix_length(suppress_prefix)
        .with_uid_range(uid_range)
        .with_ip_protocol(ip_protocol)
        .with_source_port_range(source_ports)
        .with_destination_port_range(destination_ports)
        .with_flow(flow)
        .expect("IPv4 flow ID");

    assert_eq!(
        record.destination(),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(
        record.source(),
        RulePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(record.priority().get(), 100);
    assert_eq!(record.goto_target(), None);
    assert_eq!(record.fwmark(), Some(fwmark));
    assert_eq!(record.fwmark().map(RuleFwMark::value), Some(0xf3));
    assert_eq!(record.input_interface(), Some(&input));
    assert_eq!(record.output_interface(), Some(&output));
    assert_eq!(record.tunnel_id(), Some(tunnel_id));
    assert_eq!(record.suppress_interface_group(), Some(suppress_group));
    assert_eq!(record.suppress_prefix_length(), Some(suppress_prefix));
    assert!(!record.l3mdev());
    assert_eq!(record.uid_range(), Some(uid_range));
    assert_eq!(record.ip_protocol(), Some(ip_protocol));
    assert_eq!(record.source_port_range(), Some(source_ports));
    assert_eq!(record.destination_port_range(), Some(destination_ports));
    assert_eq!(record.flow(), Some(flow));
}

#[test]
fn unknown_actions_and_minimal_selector_state_remain_representable() {
    let action = RuleAction::from_raw(0xff);
    let minimal = record(NetworkAddressFamily::Ipv6, 0, u32::MAX, action, 0, None)
        .expect("unknown action is a raw kernel fact");

    assert_eq!(minimal.properties().action(), action);
    assert_eq!(minimal.properties().table().get(), u32::MAX);
    assert_eq!(minimal.fwmark(), None);
    assert_eq!(minimal.input_interface(), None);
    assert_eq!(minimal.output_interface(), None);
    assert_eq!(minimal.tunnel_id(), None);
    assert_eq!(minimal.suppress_interface_group(), None);
    assert_eq!(minimal.suppress_prefix_length(), None);
    assert!(!minimal.l3mdev());
    assert_eq!(minimal.uid_range(), None);
    assert_eq!(minimal.ip_protocol(), None);
    assert_eq!(minimal.source_port_range(), None);
    assert_eq!(minimal.destination_port_range(), None);
    assert_eq!(minimal.flow(), None);
}

fn properties(tos: u8, table: u32, action: RuleAction) -> RuleProperties {
    RuleProperties::new(
        tos,
        RuleTableId::from_raw(table),
        action,
        RuleProtocol::from_raw(0),
        RuleFlags::default(),
    )
}

fn record(
    family: NetworkAddressFamily,
    tos: u8,
    table: u32,
    action: RuleAction,
    priority: u32,
    goto_target: Option<u32>,
) -> Result<NetworkRuleRecord, flux_core::NetworkRuleRecordError> {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(family),
        RulePrefix::unspecified(family),
        properties(tos, table, action),
        RulePriority::from_raw(priority),
        goto_target.map(RulePriority::from_raw),
    )
}

fn ipv4_record() -> NetworkRuleRecord {
    record(
        NetworkAddressFamily::Ipv4,
        0,
        254,
        RuleAction::TO_TABLE,
        100,
        None,
    )
    .expect("valid IPv4 rule")
}

fn ipv6_record() -> NetworkRuleRecord {
    record(
        NetworkAddressFamily::Ipv6,
        0,
        254,
        RuleAction::TO_TABLE,
        100,
        None,
    )
    .expect("valid IPv6 rule")
}
