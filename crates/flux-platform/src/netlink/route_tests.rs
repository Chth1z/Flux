use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::super::{
    NETLINK_ATTRIBUTE_HEADER_LENGTH, NLA_F_NESTED, NLA_F_NET_BYTEORDER, NLM_F_ACK_TLVS,
};
use super::*;

const RTM_NEWLINK: u16 = 16;
const AF_UNSPEC: u8 = 0;
const AF_BRIDGE: u8 = 7;

#[test]
fn ipv4_default_route_preserves_extended_table_and_raw_properties() {
    let gateway = Ipv4Addr::new(192, 0, 2, 1).octets();
    let table = 1_024_u32.to_ne_bytes();
    let output_interface = 7_u32.to_ne_bytes();
    let datagram = route_message(
        RTM_NEWROUTE,
        0,
        41,
        AF_INET as u8,
        0,
        0,
        0xfe,
        RT_TABLE_COMPAT,
        0xfd,
        0xfc,
        0xfb,
        0x8000_0400,
        &[
            (RTA_TABLE, &table),
            (RTA_OIF, &output_interface),
            (RTA_GATEWAY, &gateway),
        ],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid IPv4 default route");

    assert_eq!(decoded.sequence(), Some(41));
    assert!(decoded.completion().is_none());
    assert_eq!(decoded.events().len(), 1);
    let event = &decoded.events()[0];
    assert!(!event.replace());
    let record = event.record();
    assert_eq!(
        record.destination(),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(
        record.source(),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4)
    );
    assert_eq!(record.priority(), 0);
    assert_eq!(record.properties().tos(), 0xfe);
    assert_eq!(record.properties().table().get(), 1_024);
    assert_eq!(record.properties().protocol().raw(), 0xfd);
    assert_eq!(record.properties().scope().raw(), 0xfc);
    assert_eq!(record.properties().route_type().raw(), 0xfb);
    assert_eq!(record.properties().flags().raw(), 0x8000_0400);
    assert_eq!(
        record.path(),
        &RoutePath::Single {
            output_interface: InterfaceIndex::new(7),
            gateway: Some(RouteGateway::Direct(IpAddr::V4(Ipv4Addr::new(
                192, 0, 2, 1
            )))),
        }
    );
}

#[test]
fn ipv6_source_route_preserves_prefsrc_preference_and_cacheinfo() {
    let destination = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0).octets();
    let source = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0).octets();
    let preferred_source = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 7).octets();
    let priority = 123_u32.to_ne_bytes();
    let cacheinfo = [0xa5; ROUTE_CACHE_INFO_LENGTH];
    let datagram = route_message(
        RTM_NEWROUTE,
        0,
        7,
        AF_INET6 as u8,
        64,
        64,
        0,
        254,
        9,
        0,
        1,
        0,
        &[
            (RTA_DST, &destination),
            (RTA_SRC, &source),
            (RTA_PRIORITY, &priority),
            (RTA_PREFSRC, &preferred_source),
            (RTA_CACHEINFO, &cacheinfo),
            (RTA_PREF, &[2]),
        ],
    );

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid IPv6 source route");
    let record = decoded.events()[0].record();

    assert_eq!(
        record.destination(),
        RoutePrefix::new(IpAddr::V6(Ipv6Addr::from(destination)), 64).unwrap()
    );
    assert_eq!(
        record.source(),
        RoutePrefix::new(IpAddr::V6(Ipv6Addr::from(source)), 64).unwrap()
    );
    assert_eq!(record.priority(), 123);
    assert_eq!(
        record.preferred_source(),
        Some(IpAddr::V6(Ipv6Addr::from(preferred_source)))
    );
    assert_eq!(record.preference(), Some(RoutePreference::from_raw(2)));
    assert_eq!(record.path(), &RoutePath::None);
}

#[test]
fn multipath_preserves_order_hops_flags_gateways_and_optional_interfaces() {
    let first_gateway = Ipv4Addr::new(192, 0, 2, 1).octets();
    let second_gateway = Ipv4Addr::new(198, 51, 100, 1).octets();
    let first = nexthop(7, 0x85, 0, &[(RTA_GATEWAY, first_gateway.as_slice())]);
    let second = nexthop(0, 0x42, 9, &[(RTA_GATEWAY, second_gateway.as_slice())]);
    let mut multipath = first;
    multipath.extend_from_slice(&second);
    let datagram = basic_route(&[(RTA_MULTIPATH, &multipath)]);

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("valid two-path route");
    let RoutePath::Multipath(paths) = decoded.events()[0].record().path() else {
        panic!("expected multipath route");
    };

    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0].output_interface(), InterfaceIndex::new(7));
    assert_eq!(paths[0].flags().raw(), 0x85);
    assert_eq!(paths[0].hops(), 0);
    assert_eq!(
        paths[0].gateway(),
        Some(RouteGateway::Direct(IpAddr::V4(Ipv4Addr::from(
            first_gateway
        ))))
    );
    assert_eq!(paths[1].output_interface(), None);
    assert_eq!(paths[1].flags().raw(), 0x42);
    assert_eq!(paths[1].hops(), 9);
    assert_eq!(
        paths[1].gateway(),
        Some(RouteGateway::Direct(IpAddr::V4(Ipv4Addr::from(
            second_gateway
        ))))
    );
}

#[test]
fn ipv4_route_accepts_an_ipv6_via_gateway() {
    let via_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let via = via_value(AF_INET6, &via_address.octets());
    let datagram = basic_route(&[(RTA_VIA, &via)]);

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("IPv4 route using IPv6 via gateway");

    assert_eq!(
        decoded.events()[0].record().path(),
        &RoutePath::Single {
            output_interface: None,
            gateway: Some(RouteGateway::Via(IpAddr::V6(via_address))),
        }
    );
}

#[test]
fn nexthop_id_can_coexist_with_a_compatibility_expanded_path() {
    let nexthop_id = 77_u32.to_ne_bytes();
    let output_interface = 4_u32.to_ne_bytes();
    let gateway = Ipv4Addr::new(203, 0, 113, 1).octets();
    let datagram = basic_route(&[
        (RTA_NH_ID, &nexthop_id),
        (RTA_OIF, &output_interface),
        (RTA_GATEWAY, &gateway),
    ]);

    let decoded = decoder(true)
        .decode_datagram(&datagram)
        .expect("nexthop object with expanded path");
    let record = decoded.events()[0].record();

    assert_eq!(record.nexthop_id(), NonZeroU32::new(77));
    assert!(matches!(record.path(), RoutePath::Single { .. }));
}

#[test]
fn delete_and_replace_are_distinct_private_events() {
    let removed = route_message(
        RTM_DELROUTE,
        NLM_F_REPLACE,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    let decoded = decoder(true)
        .decode_datagram(&removed)
        .expect("valid delete route");
    assert!(matches!(
        decoded.events()[0],
        InterfaceRouteEvent::Remove(_)
    ));
    assert!(!decoded.events()[0].replace());

    let replaced = route_message(
        RTM_NEWROUTE,
        NLM_F_REPLACE,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    let decoded = decoder(true)
        .decode_datagram(&replaced)
        .expect("valid replace route");
    assert!(matches!(
        decoded.events()[0],
        InterfaceRouteEvent::Upsert { replace: true, .. }
    ));
}

#[test]
fn cloned_routes_are_validated_then_filtered() {
    let cloned = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        RouteFlags::CLONED.raw(),
        &[],
    );
    assert!(
        decoder(true)
            .decode_datagram(&cloned)
            .expect("valid cloned route")
            .events()
            .is_empty()
    );

    let malformed = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        RouteFlags::CLONED.raw(),
        &[(RTA_TABLE, &[0; 3])],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&malformed)
            .expect_err("malformed cloned route")
            .kind(),
        RouteEventDecodeErrorKind::InvalidTableLength
    );
}

#[test]
fn disabled_ipv6_routes_are_fully_validated_before_filtering() {
    let destination = Ipv6Addr::LOCALHOST.octets();
    let malformed = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET6 as u8,
        128,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_DST, &destination[..4])],
    );
    assert_eq!(
        decoder(false)
            .decode_datagram(&malformed)
            .expect_err("disabled family still rejects malformed address")
            .kind(),
        RouteEventDecodeErrorKind::InvalidDestinationLength
    );

    let valid = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET6 as u8,
        128,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_DST, &destination)],
    );
    assert!(
        decoder(false)
            .decode_datagram(&valid)
            .expect("valid disabled-family route")
            .events()
            .is_empty()
    );
}

#[test]
fn unknown_families_validate_only_top_level_attribute_framing() {
    let valid = route_message(
        RTM_NEWROUTE,
        0,
        9,
        AF_BRIDGE,
        u8::MAX,
        u8::MAX,
        0,
        0,
        0,
        0,
        0,
        0,
        &[(RTA_DST | NLA_F_NESTED, &[1, 2, 3])],
    );
    let decoded = decoder(true)
        .decode_datagram(&valid)
        .expect("well-framed unknown-family route");
    assert_eq!(decoded.sequence(), Some(9));
    assert!(decoded.events().is_empty());

    let mut payload = route_payload(AF_BRIDGE, 0, 0, 0, 0, 0, 0, 0, 0);
    payload.extend_from_slice(&3_u16.to_ne_bytes());
    payload.extend_from_slice(&RTA_DST.to_ne_bytes());
    let malformed = netlink_message(RTM_NEWROUTE, 0, 1, 0, &payload);
    assert_eq!(
        decoder(true)
            .decode_datagram(&malformed)
            .expect_err("malformed unknown-family framing")
            .kind(),
        RouteEventDecodeErrorKind::InvalidAttributeLength
    );
}

#[test]
fn unknown_route_attributes_remain_forward_compatible_through_android_5_10_max() {
    let type_after_android_5_10_max = RTA_NH_ID + 1;
    let decoded = decoder(true)
        .decode_datagram(&basic_route(&[(
            type_after_android_5_10_max | NLA_F_NESTED,
            &[0xde, 0xad, 0xbe],
        )]))
        .expect("well-framed future route attribute");
    assert_eq!(decoded.events().len(), 1);

    // RTA_NEWDST is family/encapsulation-specific binary data in 5.10. It has
    // no stable scalar width for this observer, so only outer NLA framing is
    // enforced until its semantics are modeled.
    let rta_newdst = 19;
    decoder(true)
        .decode_datagram(&basic_route(&[(
            rta_newdst | NLA_F_NET_BYTEORDER,
            &[1, 2, 3, 4, 5],
        )]))
        .expect("well-framed deferred RTA_NEWDST payload");
}

#[test]
fn extended_and_compact_route_tables_must_agree_with_the_header() {
    let compact = 100_u32.to_ne_bytes();
    let mismatch = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        101,
        0,
        0,
        1,
        0,
        &[(RTA_TABLE, &compact)],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&mismatch)
            .expect_err("compact table mismatch")
            .kind(),
        RouteEventDecodeErrorKind::InconsistentTable
    );

    let extended = 256_u32.to_ne_bytes();
    let wrong_header = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_TABLE, &extended)],
    );
    assert_eq!(
        decoder(true)
            .decode_datagram(&wrong_header)
            .expect_err("extended table requires RT_TABLE_COMPAT")
            .kind(),
        RouteEventDecodeErrorKind::InconsistentTable
    );
}

#[test]
fn route_prefixes_require_attributes_ranges_and_network_addresses() {
    let missing_destination = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        24,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    assert_eq!(
        error_kind(&missing_destination),
        RouteEventDecodeErrorKind::MissingDestination
    );

    let missing_source = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        24,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    assert_eq!(
        error_kind(&missing_source),
        RouteEventDecodeErrorKind::MissingSource
    );

    let invalid_length = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        33,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    assert_eq!(
        error_kind(&invalid_length),
        RouteEventDecodeErrorKind::InvalidDestinationPrefixLength
    );

    let destination_with_host_bits = [192, 0, 2, 1];
    let host_bits = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        24,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_DST, &destination_with_host_bits)],
    );
    assert_eq!(
        error_kind(&host_bits),
        RouteEventDecodeErrorKind::NonzeroDestinationHostBits
    );

    let source_with_host_bits = [198, 51, 100, 7];
    let host_bits = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        24,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_SRC, &source_with_host_bits)],
    );
    assert_eq!(
        error_kind(&host_bits),
        RouteEventDecodeErrorKind::NonzeroSourceHostBits
    );

    let explicit_nonzero_default = [1, 0, 0, 0];
    let host_bits = basic_route(&[(RTA_DST, &explicit_nonzero_default)]);
    assert_eq!(
        error_kind(&host_bits),
        RouteEventDecodeErrorKind::NonzeroDestinationHostBits
    );
}

#[test]
fn duplicate_and_conflicting_path_attributes_are_rejected() {
    let table = 254_u32.to_ne_bytes();
    let duplicate = basic_route(&[(RTA_TABLE, &table), (RTA_TABLE, &table)]);
    assert_eq!(
        error_kind(&duplicate),
        RouteEventDecodeErrorKind::DuplicateSemanticAttribute
    );

    let gateway = Ipv4Addr::new(192, 0, 2, 1).octets();
    let via = via_value(AF_INET, &Ipv4Addr::new(198, 51, 100, 1).octets());
    let conflict = basic_route(&[(RTA_GATEWAY, &gateway), (RTA_VIA, &via)]);
    assert_eq!(
        error_kind(&conflict),
        RouteEventDecodeErrorKind::ConflictingGatewayAttributes
    );

    let output_interface = 7_u32.to_ne_bytes();
    let path = nexthop(8, 0, 0, &[]);
    let conflict = basic_route(&[(RTA_OIF, &output_interface), (RTA_MULTIPATH, &path)]);
    assert_eq!(
        error_kind(&conflict),
        RouteEventDecodeErrorKind::ConflictingPathAttributes
    );
}

#[test]
fn recognized_scalars_require_exact_lengths_and_compatible_flags() {
    let cases: &[(u16, &[u8], RouteEventDecodeErrorKind)] = &[
        (
            RTA_OIF,
            &[0; 3],
            RouteEventDecodeErrorKind::InvalidOutputInterfaceLength,
        ),
        (
            RTA_PRIORITY,
            &[0; 3],
            RouteEventDecodeErrorKind::InvalidPriorityLength,
        ),
        (
            RTA_TABLE,
            &[0; 3],
            RouteEventDecodeErrorKind::InvalidTableLength,
        ),
        (
            RTA_CACHEINFO,
            &[0; 31],
            RouteEventDecodeErrorKind::InvalidCacheInfoLength,
        ),
        (
            RTA_PREF,
            &[0; 2],
            RouteEventDecodeErrorKind::InvalidPreferenceLength,
        ),
        (
            RTA_NH_ID,
            &[0; 3],
            RouteEventDecodeErrorKind::InvalidNexthopIdLength,
        ),
        (
            RTA_FLOW,
            &[0; 3],
            RouteEventDecodeErrorKind::InvalidScalarLength,
        ),
        (
            RTA_ENCAP_TYPE,
            &[0; 1],
            RouteEventDecodeErrorKind::InvalidScalarLength,
        ),
        (
            RTA_TTL_PROPAGATE,
            &[0; 2],
            RouteEventDecodeErrorKind::InvalidScalarLength,
        ),
    ];
    for (attribute_type, value, expected) in cases {
        let datagram = basic_route(&[(*attribute_type, *value)]);
        assert_eq!(error_kind(&datagram), *expected, "type {attribute_type}");
    }

    let zero_nexthop = 0_u32.to_ne_bytes();
    assert_eq!(
        error_kind(&basic_route(&[(RTA_NH_ID, &zero_nexthop)])),
        RouteEventDecodeErrorKind::InvalidNexthopId
    );

    let plain = 1_u32.to_ne_bytes();
    for attribute_type in [RTA_TABLE, RTA_OIF, RTA_FLOW, RTA_NH_ID] {
        assert_eq!(
            error_kind(&basic_route(&[(attribute_type | NLA_F_NESTED, &plain)])),
            RouteEventDecodeErrorKind::InvalidAttributeFlags
        );
    }
    let encap_type = 1_u16.to_ne_bytes();
    assert_eq!(
        error_kind(&basic_route(&[(
            RTA_ENCAP_TYPE | NLA_F_NET_BYTEORDER,
            &encap_type,
        )])),
        RouteEventDecodeErrorKind::InvalidAttributeFlags
    );

    for flags in [0, NLA_F_NESTED] {
        decoder(true)
            .decode_datagram(&basic_route(&[(RTA_METRICS | flags, &[])]))
            .expect("legacy or flagged nested metrics");
    }
    let port = 443_u16.to_be_bytes();
    for flags in [0, NLA_F_NET_BYTEORDER] {
        decoder(true)
            .decode_datagram(&basic_route(&[(RTA_DPORT | flags, &port)]))
            .expect("plain or flagged network-order lookup port");
    }

    decoder(true)
        .decode_datagram(&basic_route(&[(RTA_PAD, &[])]))
        .expect("empty plain RTA_PAD");
    decoder(true)
        .decode_datagram(&basic_route(&[(RTA_PAD, &[]), (RTA_PAD, &[])]))
        .expect("repeated empty padding attributes");
    assert_eq!(
        error_kind(&basic_route(&[(RTA_PAD, &[0])])),
        RouteEventDecodeErrorKind::InvalidScalarLength
    );
    assert_eq!(
        error_kind(&basic_route(&[(RTA_PAD | NLA_F_NESTED, &[])])),
        RouteEventDecodeErrorKind::InvalidAttributeFlags
    );
}

#[test]
fn output_interface_uses_the_positive_kernel_int_domain() {
    for invalid in [0_u32, i32::MAX as u32 + 1, u32::MAX] {
        assert_eq!(
            error_kind(&basic_route(&[(RTA_OIF, &invalid.to_ne_bytes())])),
            RouteEventDecodeErrorKind::InvalidOutputInterface
        );
    }

    let maximum = (i32::MAX as u32).to_ne_bytes();
    let decoded = decoder(true)
        .decode_datagram(&basic_route(&[(RTA_OIF, &maximum)]))
        .expect("maximum kernel interface index");
    let RoutePath::Single {
        output_interface, ..
    } = decoded.events()[0].record().path()
    else {
        panic!("expected single route path");
    };
    assert_eq!(
        output_interface.map(InterfaceIndex::get),
        Some(i32::MAX as u32)
    );
}

#[test]
fn ipv4_rejects_router_preference_and_ipv6_rejects_via_after_validation() {
    let preference = basic_route(&[(RTA_PREF, &[1])]);
    assert_eq!(
        error_kind(&preference),
        RouteEventDecodeErrorKind::PreferenceUnsupported
    );

    let malformed_via = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET6 as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_VIA, &[0])],
    );
    assert_eq!(
        error_kind(&malformed_via),
        RouteEventDecodeErrorKind::InvalidViaLength
    );

    let via = via_value(AF_INET, &Ipv4Addr::LOCALHOST.octets());
    let valid_but_unsupported = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET6 as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        &[(RTA_VIA, &via)],
    );
    assert_eq!(
        error_kind(&valid_but_unsupported),
        RouteEventDecodeErrorKind::ViaUnsupported
    );
}

#[test]
fn family_sized_addresses_and_via_values_are_strict() {
    let unknown_via = via_value(u16::from(AF_BRIDGE), &[0; 4]);
    let short_via = via_value(AF_INET, &[0; 3]);
    let cases = [
        (
            basic_route(&[(RTA_SRC, &[0; 3])]),
            RouteEventDecodeErrorKind::InvalidSourceLength,
        ),
        (
            basic_route(&[(RTA_GATEWAY, &[0; 3])]),
            RouteEventDecodeErrorKind::InvalidGatewayLength,
        ),
        (
            basic_route(&[(RTA_PREFSRC, &[0; 3])]),
            RouteEventDecodeErrorKind::InvalidPreferredSourceLength,
        ),
        (
            basic_route(&[(RTA_VIA, &unknown_via)]),
            RouteEventDecodeErrorKind::InvalidViaFamily,
        ),
        (
            basic_route(&[(RTA_VIA, &short_via)]),
            RouteEventDecodeErrorKind::InvalidViaLength,
        ),
    ];
    for (datagram, expected) in cases {
        assert_eq!(error_kind(&datagram), expected);
    }

    let invalid_source_prefix = route_message(
        RTM_NEWROUTE,
        0,
        1,
        AF_INET as u8,
        0,
        33,
        0,
        254,
        0,
        0,
        1,
        0,
        &[],
    );
    assert_eq!(
        error_kind(&invalid_source_prefix),
        RouteEventDecodeErrorKind::InvalidSourcePrefixLength
    );
}

#[test]
fn multipath_accepts_an_ipv6_via_gateway_for_an_ipv4_route() {
    let via_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
    let via = via_value(AF_INET6, &via_address.octets());
    let multipath = nexthop(11, 0x24, 3, &[(RTA_VIA, &via)]);

    let decoded = decoder(true)
        .decode_datagram(&basic_route(&[(RTA_MULTIPATH, &multipath)]))
        .expect("IPv4 multipath route using an IPv6 via gateway");
    let RoutePath::Multipath(paths) = decoded.events()[0].record().path() else {
        panic!("expected multipath route");
    };

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].output_interface(), InterfaceIndex::new(11));
    assert_eq!(paths[0].flags().raw(), 0x24);
    assert_eq!(paths[0].hops(), 3);
    assert_eq!(
        paths[0].gateway(),
        Some(RouteGateway::Via(IpAddr::V6(via_address)))
    );
}

#[test]
fn multipath_rejects_empty_short_bad_length_padding_and_negative_index() {
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &[])])),
        RouteEventDecodeErrorKind::EmptyMultipath
    );
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &[0; 7])])),
        RouteEventDecodeErrorKind::TruncatedNexthop
    );

    let mut short_length = vec![0; ROUTE_NEXTHOP_LENGTH];
    short_length[..2].copy_from_slice(&7_u16.to_ne_bytes());
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &short_length)])),
        RouteEventDecodeErrorKind::InvalidNexthopLength
    );

    let mut excessive_length = vec![0; ROUTE_NEXTHOP_LENGTH];
    excessive_length[..2].copy_from_slice(&9_u16.to_ne_bytes());
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &excessive_length)])),
        RouteEventDecodeErrorKind::InvalidNexthopLength
    );

    let mut missing_padding = vec![0; ROUTE_NEXTHOP_LENGTH + 1];
    missing_padding[..2].copy_from_slice(&9_u16.to_ne_bytes());
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &missing_padding)])),
        RouteEventDecodeErrorKind::MissingNexthopPadding
    );

    let negative = nexthop(-1, 0, 0, &[]);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &negative)])),
        RouteEventDecodeErrorKind::InvalidNexthopInterface
    );
}

#[test]
fn multipath_nested_attributes_reject_conflicts_and_validate_deferred_encap() {
    let gateway = Ipv4Addr::new(192, 0, 2, 1).octets();
    let via = via_value(AF_INET6, &Ipv6Addr::LOCALHOST.octets());
    let conflicting = nexthop(1, 0, 0, &[(RTA_GATEWAY, &gateway), (RTA_VIA, &via)]);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &conflicting)])),
        RouteEventDecodeErrorKind::ConflictingGatewayAttributes
    );

    let bad_flow = nexthop(1, 0, 0, &[(RTA_FLOW, &[0; 3])]);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &bad_flow)])),
        RouteEventDecodeErrorKind::InvalidScalarLength
    );

    let mut malformed_nested = Vec::new();
    malformed_nested.extend_from_slice(&3_u16.to_ne_bytes());
    malformed_nested.extend_from_slice(&1_u16.to_ne_bytes());
    let encap = nexthop(1, 0, 0, &[(RTA_ENCAP, &malformed_nested)]);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &encap)])),
        RouteEventDecodeErrorKind::InvalidAttributeLength
    );

    let repeated_padding = nexthop(1, 0, 0, &[(RTA_PAD, &[]), (RTA_PAD, &[])]);
    decoder(true)
        .decode_datagram(&basic_route(&[(RTA_MULTIPATH, &repeated_padding)]))
        .expect("repeated empty per-nexthop padding attributes");
    let malformed_padding = nexthop(1, 0, 0, &[(RTA_PAD, &[0])]);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &malformed_padding)])),
        RouteEventDecodeErrorKind::InvalidScalarLength
    );
}

#[test]
fn multipath_enforces_the_wire_derived_8191_nexthop_boundary() {
    let mut multipath = Vec::with_capacity(MAX_MULTIPATH_NEXTHOPS * ROUTE_NEXTHOP_LENGTH);
    for index in 0..MAX_MULTIPATH_NEXTHOPS {
        let interface = i32::try_from(index % 31 + 1).unwrap();
        multipath.extend_from_slice(&nexthop(interface, index as u8, (index / 31) as u8, &[]));
    }
    assert_eq!(multipath.len(), 65_528);

    let decoded = decoder(true)
        .decode_datagram(&basic_route(&[(RTA_MULTIPATH, &multipath)]))
        .expect("maximum wire-representable compact multipath");
    let RoutePath::Multipath(paths) = decoded.events()[0].record().path() else {
        panic!("expected multipath route");
    };
    assert_eq!(paths.len(), MAX_MULTIPATH_NEXTHOPS);
    assert_eq!(paths[0].output_interface(), InterfaceIndex::new(1));
    assert_eq!(paths[MAX_MULTIPATH_NEXTHOPS - 1].flags().raw(), 0xfe);

    let mut too_many = multipath.clone();
    too_many.extend_from_slice(&nexthop(1, 0, 0, &[]));
    let Err(error) = decode_multipath(NetworkAddressFamily::Ipv4, &too_many, 0, 0) else {
        panic!("8,192 compact nexthops must exceed the explicit decoder limit");
    };
    assert_eq!(error.kind(), RouteEventDecodeErrorKind::TooManyNexthops);

    multipath.push(0);
    assert_eq!(
        error_kind(&basic_route(&[(RTA_MULTIPATH, &multipath)])),
        RouteEventDecodeErrorKind::TruncatedNexthop
    );
}

#[test]
fn whole_datagram_loss_and_transaction_metadata_are_strict() {
    let first = basic_route_with_sequence(1, &[]);
    let second = basic_route_with_sequence(2, &[]);
    assert_eq!(
        error_kind(&concatenate(&[&first, &second])),
        RouteEventDecodeErrorKind::MixedSequence
    );

    for (message_type, expected) in [
        (NLMSG_ERROR, RouteEventDecodeErrorKind::NetlinkError),
        (NLMSG_OVERRUN, RouteEventDecodeErrorKind::NetlinkOverrun),
    ] {
        let datagram = netlink_message(message_type, 0, 1, 0, &[]);
        assert_eq!(error_kind(&datagram), expected);
    }

    let interrupted = netlink_message(RTM_NEWLINK, NLM_F_DUMP_INTR, 1, 0, &[]);
    assert_eq!(
        error_kind(&interrupted),
        RouteEventDecodeErrorKind::InterruptedDump
    );

    let done = netlink_message(NLMSG_DONE, 0, 7, 0, &[]);
    let decoded = decoder(true)
        .decode_datagram(&done)
        .expect("empty successful DONE");
    assert_eq!(decoded.sequence(), Some(7));
    assert!(decoded.completion().is_some());

    let mut extended_ack = 0_i32.to_ne_bytes().to_vec();
    append_attribute(&mut extended_ack, 1, b"diagnostic\0");
    let done = netlink_message(NLMSG_DONE, NLM_F_ACK_TLVS, 7, 0, &extended_ack);
    decoder(true)
        .decode_datagram(&done)
        .expect("valid extended-ack DONE");

    let failed_done = netlink_message(NLMSG_DONE, 0, 7, 0, &(-5_i32).to_ne_bytes());
    assert_eq!(
        error_kind(&failed_done),
        RouteEventDecodeErrorKind::DoneErrorStatus
    );

    let malformed_done = netlink_message(NLMSG_DONE, 0, 7, 0, &[0]);
    assert_eq!(
        error_kind(&malformed_done),
        RouteEventDecodeErrorKind::InvalidDonePayload
    );

    let duplicate_done = concatenate(&[&done, &done]);
    assert_eq!(
        error_kind(&duplicate_done),
        RouteEventDecodeErrorKind::DuplicateDone
    );

    let after_done = concatenate(&[&done, &basic_route_with_sequence(7, &[])]);
    assert_eq!(
        error_kind(&after_done),
        RouteEventDecodeErrorKind::MessageAfterDone
    );
}

#[test]
fn framing_failures_are_reported_without_partial_events() {
    let valid = basic_route(&[]);
    for length in 1..NETLINK_HEADER_LENGTH {
        assert_eq!(
            error_kind(&valid[..length]),
            RouteEventDecodeErrorKind::TruncatedHeader
        );
    }

    let mut truncated_route = route_payload(AF_INET as u8, 0, 0, 0, 254, 0, 0, 1, 0);
    truncated_route.pop();
    assert_eq!(
        error_kind(&netlink_message(RTM_NEWROUTE, 0, 1, 0, &truncated_route)),
        RouteEventDecodeErrorKind::TruncatedRouteMessage
    );

    let mut malformed = valid;
    malformed.extend_from_slice(&[1, 2, 3]);
    assert_eq!(
        error_kind(&malformed),
        RouteEventDecodeErrorKind::TruncatedHeader
    );
}

#[test]
fn unrelated_messages_are_ignored_but_keep_compatible_metadata() {
    let unrelated = netlink_message(RTM_NEWLINK, 0, 55, 99, &[1, 2, 3, 4]);
    let decoded = decoder(true)
        .decode_datagram(&unrelated)
        .expect("well-framed unrelated rtnetlink message");
    assert_eq!(decoded.sequence(), Some(55));
    assert!(decoded.events().is_empty());
    assert!(decoded.completion().is_none());

    let route = basic_route_with_sequence(55, &[]);
    let done = netlink_message(NLMSG_DONE, 0, 55, 99, &[]);
    let decoded = decoder(true)
        .decode_datagram(&concatenate(&[&unrelated, &route, &done]))
        .expect("mixed compatible transaction datagram");
    assert_eq!(decoded.events().len(), 1);
    assert_eq!(decoded.sequence(), Some(55));
    assert_eq!(decoded.completion().unwrap().port_id(), 99);
}

#[test]
fn deterministic_arbitrary_datagrams_never_panic() {
    const CASES: usize = 4_096;
    const MAX_LENGTH: usize = 768;

    let decoder = decoder(true);
    let mut state = 0xf731_15a9_cad4_207b_u64;
    for case in 0..CASES {
        let length = (next_random(&mut state) as usize) % (MAX_LENGTH + 1);
        let mut datagram = vec![0_u8; length];
        for byte in &mut datagram {
            *byte = next_random(&mut state) as u8;
        }
        let outcome = std::panic::catch_unwind(|| decoder.decode_datagram(&datagram));
        assert!(
            outcome.is_ok(),
            "decoder panicked for deterministic case {case}"
        );
    }
}

#[test]
fn complex_route_prefixes_and_structured_mutations_are_atomic_and_panic_free() {
    let fixture = complex_route_fixture();
    let declared_length = usize::try_from(u32::from_ne_bytes(
        fixture[..4].try_into().expect("netlink length field"),
    ))
    .expect("netlink length fits usize");
    assert_eq!(declared_length, fixture.len());

    let decoded = decoder(true)
        .decode_datagram(&fixture)
        .expect("complete complex route fixture");
    assert_eq!(decoded.events().len(), 1);

    for prefix_length in 0..fixture.len() {
        let mut prefix = fixture[..prefix_length].to_vec();
        if prefix_length >= NETLINK_HEADER_LENGTH {
            prefix[..4].copy_from_slice(
                &u32::try_from(prefix_length)
                    .expect("fixture prefix length fits u32")
                    .to_ne_bytes(),
            );
            prefix.resize(align4(prefix_length), 0);
        }

        let outcome = std::panic::catch_unwind(|| decoder(true).decode_datagram(&prefix));
        assert!(
            outcome.is_ok(),
            "decoder panicked for complex fixture prefix {prefix_length}"
        );
        if let Ok(decoded) = outcome.expect("panic outcome checked") {
            assert!(
                decoded.events().is_empty(),
                "truncated complex fixture emitted an event at {prefix_length}"
            );
        }
    }

    let mut state = 0x2685_7f13_c9a4_b06d_u64;
    let mut accepted = 0;
    let mut rejected = 0;
    for offset in NETLINK_HEADER_LENGTH..declared_length {
        let mut mutated = fixture.clone();
        let mask = (next_random(&mut state) as u8) | 1;
        mutated[offset] ^= mask;

        let outcome = std::panic::catch_unwind(|| decoder(true).decode_datagram(&mutated));
        assert!(
            outcome.is_ok(),
            "decoder panicked after mutating complex fixture byte {offset}"
        );
        match outcome.expect("panic outcome checked") {
            Ok(decoded) => {
                assert_eq!(decoded.sequence(), Some(73));
                assert!(decoded.completion().is_none());
                assert!(decoded.events().len() <= 1);
                accepted += 1;
            }
            Err(error) => {
                assert!(!matches!(
                    error.kind(),
                    RouteEventDecodeErrorKind::TruncatedHeader
                        | RouteEventDecodeErrorKind::InvalidMessageLength
                        | RouteEventDecodeErrorKind::MissingMessagePadding
                ));
                rejected += 1;
            }
        }
    }
    assert!(
        accepted > 0,
        "structured mutations should retain valid routes"
    );
    assert!(
        rejected > 0,
        "structured mutations should reach strict decoders"
    );
}

fn decoder(include_ipv6: bool) -> RtnetlinkRouteEventDecoder {
    RtnetlinkRouteEventDecoder::new(include_ipv6)
}

fn error_kind(datagram: &[u8]) -> RouteEventDecodeErrorKind {
    decoder(true)
        .decode_datagram(datagram)
        .expect_err("expected route decode failure")
        .kind()
}

fn basic_route(attributes: &[(u16, &[u8])]) -> Vec<u8> {
    basic_route_with_sequence(1, attributes)
}

fn basic_route_with_sequence(sequence: u32, attributes: &[(u16, &[u8])]) -> Vec<u8> {
    route_message(
        RTM_NEWROUTE,
        0,
        sequence,
        AF_INET as u8,
        0,
        0,
        0,
        254,
        0,
        0,
        1,
        0,
        attributes,
    )
}

fn complex_route_fixture() -> Vec<u8> {
    let destination = Ipv4Addr::new(203, 0, 113, 0).octets();
    let source = Ipv4Addr::new(198, 51, 100, 0).octets();
    let preferred_source = Ipv4Addr::new(198, 51, 100, 42).octets();
    let table = 1_024_u32.to_ne_bytes();
    let priority = 321_u32.to_ne_bytes();
    let nexthop_id = 91_u32.to_ne_bytes();
    let cacheinfo = [0x5a; ROUTE_CACHE_INFO_LENGTH];

    let mut metrics = Vec::new();
    append_attribute(&mut metrics, 2, &1_500_u32.to_ne_bytes());

    let first_gateway = Ipv4Addr::new(192, 0, 2, 1).octets();
    let first_flow = 17_u32.to_ne_bytes();
    let first = nexthop(
        7,
        0x04,
        0,
        &[
            (RTA_GATEWAY, first_gateway.as_slice()),
            (RTA_FLOW, first_flow.as_slice()),
        ],
    );

    let second_via_address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
    let second_via = via_value(AF_INET6, &second_via_address.octets());
    let encap_type = 1_u16.to_ne_bytes();
    let mut encap = Vec::new();
    append_attribute(&mut encap, 1, &[0xaa, 0xbb]);
    let second = nexthop(
        9,
        0x10,
        2,
        &[
            (RTA_VIA, second_via.as_slice()),
            (RTA_ENCAP_TYPE, encap_type.as_slice()),
            (RTA_ENCAP | NLA_F_NESTED, encap.as_slice()),
        ],
    );
    let mut multipath = first;
    multipath.extend_from_slice(&second);

    route_message(
        RTM_NEWROUTE,
        NLM_F_REPLACE,
        73,
        AF_INET as u8,
        24,
        24,
        0x20,
        RT_TABLE_COMPAT,
        0xfd,
        0xfc,
        1,
        0x8000_0400,
        &[
            (RTA_DST, destination.as_slice()),
            (RTA_METRICS | NLA_F_NESTED, metrics.as_slice()),
            (RTA_TABLE, table.as_slice()),
            (RTA_PRIORITY, priority.as_slice()),
            (RTA_PREFSRC, preferred_source.as_slice()),
            (RTA_CACHEINFO, cacheinfo.as_slice()),
            (RTA_NH_ID, nexthop_id.as_slice()),
            (RTA_MULTIPATH, multipath.as_slice()),
            // Keep the required source prefix last so no proper prefix of this
            // fixture can form a semantically complete route event.
            (RTA_SRC, source.as_slice()),
        ],
    )
}

#[allow(clippy::too_many_arguments)]
fn route_message(
    message_type: u16,
    message_flags: u16,
    sequence: u32,
    family: u8,
    destination_length: u8,
    source_length: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    route_flags: u32,
    attributes: &[(u16, &[u8])],
) -> Vec<u8> {
    let mut payload = route_payload(
        family,
        destination_length,
        source_length,
        tos,
        table,
        protocol,
        scope,
        route_type,
        route_flags,
    );
    for (attribute_type, value) in attributes {
        append_attribute(&mut payload, *attribute_type, value);
    }
    netlink_message(message_type, message_flags, sequence, 0, &payload)
}

#[allow(clippy::too_many_arguments)]
fn route_payload(
    family: u8,
    destination_length: u8,
    source_length: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    route_type: u8,
    route_flags: u32,
) -> Vec<u8> {
    let mut payload = vec![
        family,
        destination_length,
        source_length,
        tos,
        table,
        protocol,
        scope,
        route_type,
    ];
    payload.extend_from_slice(&route_flags.to_ne_bytes());
    payload
}

fn nexthop(interface_index: i32, flags: u8, hops: u8, attributes: &[(u16, &[u8])]) -> Vec<u8> {
    let mut value = vec![0, 0, flags, hops];
    value.extend_from_slice(&interface_index.to_ne_bytes());
    for (attribute_type, attribute_value) in attributes {
        append_attribute(&mut value, *attribute_type, attribute_value);
    }
    let length = u16::try_from(value.len()).expect("test nexthop length fits u16");
    value[..2].copy_from_slice(&length.to_ne_bytes());
    value
}

fn via_value(family: u16, address: &[u8]) -> Vec<u8> {
    let mut value = family.to_ne_bytes().to_vec();
    value.extend_from_slice(address);
    value
}

fn netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    port_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = NETLINK_HEADER_LENGTH + payload.len();
    let mut message = Vec::with_capacity(align4(length));
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&port_id.to_ne_bytes());
    message.extend_from_slice(payload);
    message.resize(align4(message.len()), 0);
    message
}

fn append_attribute(message: &mut Vec<u8>, attribute_type: u16, value: &[u8]) {
    let attribute_length = NETLINK_ATTRIBUTE_HEADER_LENGTH + value.len();
    let encoded_length = u16::try_from(attribute_length).expect("test attribute length fits u16");
    message.extend_from_slice(&encoded_length.to_ne_bytes());
    message.extend_from_slice(&attribute_type.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(align4(message.len()), 0);
}

fn concatenate(parts: &[&[u8]]) -> Vec<u8> {
    let mut joined = Vec::new();
    for part in parts {
        joined.extend_from_slice(part);
    }
    joined
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}
