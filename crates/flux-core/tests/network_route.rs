use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;

use flux_core::{
    InterfaceIndex, NetworkAddressFamily, NetworkRouteRecord, NetworkRouteRecordErrorKind,
    RouteFlags, RouteGateway, RouteNexthop, RouteNexthopFlags, RoutePath, RoutePreference,
    RoutePrefix, RoutePrefixErrorKind, RouteProperties, RouteProtocol, RouteScope, RouteTableId,
    RouteType,
};

#[test]
fn route_prefixes_validate_family_length_and_canonical_network_bits() {
    let ipv4 = RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24)
        .expect("canonical IPv4 route prefix");
    let ipv6 = RoutePrefix::new("2001:db8:1::".parse().expect("IPv6 address"), 48)
        .expect("canonical IPv6 route prefix");
    let ipv4_host = RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32)
        .expect("full-width IPv4 route prefix");
    let ipv6_host = RoutePrefix::new("2001:db8::1".parse().expect("IPv6 address"), 128)
        .expect("full-width IPv6 route prefix");
    let ipv4_default = RoutePrefix::unspecified(NetworkAddressFamily::Ipv4);
    let ipv6_default = RoutePrefix::unspecified(NetworkAddressFamily::Ipv6);

    assert_eq!(ipv4.family(), NetworkAddressFamily::Ipv4);
    assert_eq!(ipv4.address(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)));
    assert_eq!(ipv4.prefix_length(), 24);
    assert_eq!(ipv6.family(), NetworkAddressFamily::Ipv6);
    assert_eq!(ipv6.prefix_length(), 48);
    assert_eq!(ipv4_host.prefix_length(), 32);
    assert_eq!(ipv6_host.prefix_length(), 128);
    assert_eq!(ipv4_default.address(), IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert_eq!(ipv4_default.prefix_length(), 0);
    assert_eq!(ipv6_default.address(), IpAddr::V6(Ipv6Addr::UNSPECIFIED));
    assert_eq!(ipv6_default.prefix_length(), 0);
    for (address, prefix_length) in [
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129),
    ] {
        let error = RoutePrefix::new(address, prefix_length)
            .expect_err("prefix lengths cannot exceed the family width");
        assert_eq!(error.kind(), RoutePrefixErrorKind::InvalidPrefixLength);
        assert_eq!(error.address(), address);
        assert_eq!(error.prefix_length(), prefix_length);
    }

    for (address, prefix_length) in [
        (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
        ("2001:db8::1".parse().expect("IPv6 address"), 64),
        (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1)), 0),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    ] {
        let error = RoutePrefix::new(address, prefix_length)
            .expect_err("route prefixes cannot contain nonzero host bits");
        assert_eq!(error.kind(), RoutePrefixErrorKind::HostBitsSet);
    }
}

#[test]
fn ipv4_mapped_ipv6_prefixes_remain_ipv6() {
    let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0200);
    let prefix =
        RoutePrefix::new(IpAddr::V6(mapped), 120).expect("canonical IPv4-mapped IPv6 route prefix");

    assert_eq!(prefix.family(), NetworkAddressFamily::Ipv6);
    assert_eq!(prefix.address(), IpAddr::V6(mapped));
    assert_eq!(prefix.prefix_length(), 120);
}

#[test]
fn route_properties_preserve_unknown_raw_kernel_values() {
    let properties = RouteProperties::new(
        0xfe,
        RouteTableId::from_raw(70_000),
        RouteProtocol::from_raw(0xfd),
        RouteScope::from_raw(0xfc),
        RouteType::from_raw(0xfb),
        RouteFlags::from_raw(0x8000_0200),
    );
    let nexthop_flags = RouteNexthopFlags::from_raw(0xfa);
    let preference = RoutePreference::from_raw(0xf9);

    assert_eq!(properties.tos(), 0xfe);
    assert_eq!(properties.table().get(), 70_000);
    assert_eq!(properties.protocol().raw(), 0xfd);
    assert_eq!(properties.scope().raw(), 0xfc);
    assert_eq!(properties.route_type().raw(), 0xfb);
    assert_eq!(properties.flags().raw(), 0x8000_0200);
    assert_ne!(properties.flags().raw() & RouteFlags::CLONED.raw(), 0);
    assert_eq!(nexthop_flags.raw(), 0xfa);
    assert_eq!(preference.raw(), 0xf9);
}

#[test]
fn route_records_reject_mixed_address_families() {
    let destination =
        RoutePrefix::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).expect("IPv4 destination");
    let source = RoutePrefix::unspecified(NetworkAddressFamily::Ipv6);

    let error = NetworkRouteRecord::new(destination, source, properties(), 0, RoutePath::None)
        .expect_err("source and destination must use one family");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::AddressFamilyMismatch
    );

    let record = ipv4_record(RoutePath::None);
    let error = record
        .with_preferred_source(IpAddr::V6(Ipv6Addr::LOCALHOST))
        .expect_err("preferred source must use the route family");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::AddressFamilyMismatch
    );
}

#[test]
fn direct_and_via_gateways_enforce_their_family_rules() {
    let wrong_direct = RoutePath::Single {
        output_interface: None,
        gateway: Some(RouteGateway::Direct(IpAddr::V6(Ipv6Addr::LOCALHOST))),
    };
    let error = NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(),
        0,
        wrong_direct,
    )
    .expect_err("a direct gateway must use the route family");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::DirectGatewayFamilyMismatch
    );

    let ipv6_via = RoutePath::Single {
        output_interface: None,
        gateway: Some(RouteGateway::Via(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
    };
    let error = NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        properties(),
        0,
        ipv6_via,
    )
    .expect_err("IPv6 routes cannot use via gateways");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::ViaGatewayUnsupported
    );

    for gateway in [
        RouteGateway::Via(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        RouteGateway::Via(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ] {
        let record = ipv4_record(RoutePath::Single {
            output_interface: None,
            gateway: Some(gateway),
        });
        assert_eq!(
            record.path(),
            &RoutePath::Single {
                output_interface: None,
                gateway: Some(gateway),
            }
        );
    }
}

#[test]
fn multipath_gateways_enforce_route_family_rules() {
    let wrong_direct = RouteNexthop::new(
        None,
        Some(RouteGateway::Direct(IpAddr::V6(Ipv6Addr::LOCALHOST))),
        RouteNexthopFlags::default(),
        0,
    );
    let error = NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(),
        0,
        RoutePath::Multipath(vec![wrong_direct].into_boxed_slice()),
    )
    .expect_err("multipath direct gateways must use the route family");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::DirectGatewayFamilyMismatch
    );

    let ipv6_via = RouteNexthop::new(
        None,
        Some(RouteGateway::Via(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))),
        RouteNexthopFlags::default(),
        0,
    );
    let error = NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        properties(),
        0,
        RoutePath::Multipath(vec![ipv6_via].into_boxed_slice()),
    )
    .expect_err("IPv6 multipath routes cannot use via gateways");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::ViaGatewayUnsupported
    );
}

#[test]
fn router_preference_is_ipv6_only() {
    let preference = RoutePreference::from_raw(2);
    let error = ipv4_record(RoutePath::None)
        .with_preference(preference)
        .expect_err("IPv4 routes do not carry IPv6 router preference");
    assert_eq!(
        error.kind(),
        NetworkRouteRecordErrorKind::PreferenceUnsupported
    );

    let record = ipv6_record(RoutePath::None)
        .with_preference(preference)
        .expect("IPv6 router preference");
    assert_eq!(record.preference(), Some(preference));
}

#[test]
fn multipath_order_flags_and_wire_weights_are_material() {
    let first = RouteNexthop::new(
        InterfaceIndex::new(7),
        Some(RouteGateway::Direct(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 1,
        )))),
        RouteNexthopFlags::from_raw(0x04),
        0,
    );
    let second = RouteNexthop::new(
        InterfaceIndex::new(9),
        Some(RouteGateway::Direct(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 2,
        )))),
        RouteNexthopFlags::from_raw(0x08),
        3,
    );
    let ordered = ipv4_record(RoutePath::Multipath(vec![first, second].into_boxed_slice()));
    let reversed = ipv4_record(RoutePath::Multipath(vec![second, first].into_boxed_slice()));
    let changed_weight = ipv4_record(RoutePath::Multipath(
        vec![
            first,
            RouteNexthop::new(
                second.output_interface(),
                second.gateway(),
                second.flags(),
                4,
            ),
        ]
        .into_boxed_slice(),
    ));

    assert_ne!(ordered, reversed);
    assert_ne!(ordered, changed_weight);
    let RoutePath::Multipath(nexthops) = ordered.path() else {
        panic!("expected multipath route");
    };
    assert_eq!(nexthops.as_ref(), &[first, second]);
    assert_eq!(nexthops[1].hops(), 3);

    let error = NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(),
        0,
        RoutePath::Multipath(Box::new([])),
    )
    .expect_err("multipath must contain at least one nexthop");
    assert_eq!(error.kind(), NetworkRouteRecordErrorKind::EmptyMultipath);
}

#[test]
fn nexthop_id_and_compatibility_expanded_path_coexist() {
    let interface = InterfaceIndex::new(11).expect("nonzero interface index");
    let gateway = RouteGateway::Direct(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    let nexthop_id = NonZeroU32::new(42).expect("nonzero nexthop ID");
    let record = ipv4_record(RoutePath::Single {
        output_interface: Some(interface),
        gateway: Some(gateway),
    })
    .with_nexthop_id(nexthop_id);

    assert_eq!(record.nexthop_id(), Some(nexthop_id));
    assert_eq!(
        record.path(),
        &RoutePath::Single {
            output_interface: Some(interface),
            gateway: Some(gateway),
        }
    );
}

#[test]
fn empty_single_path_normalizes_to_no_path() {
    let record = ipv4_record(RoutePath::Single {
        output_interface: None,
        gateway: None,
    });

    assert_eq!(record.path(), &RoutePath::None);
}

fn properties() -> RouteProperties {
    RouteProperties::new(
        0,
        RouteTableId::from_raw(254),
        RouteProtocol::from_raw(2),
        RouteScope::from_raw(0),
        RouteType::from_raw(1),
        RouteFlags::default(),
    )
}

fn ipv4_record(path: RoutePath) -> NetworkRouteRecord {
    NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv4),
        properties(),
        100,
        path,
    )
    .expect("valid IPv4 route record")
}

fn ipv6_record(path: RoutePath) -> NetworkRouteRecord {
    NetworkRouteRecord::new(
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        RoutePrefix::unspecified(NetworkAddressFamily::Ipv6),
        properties(),
        100,
        path,
    )
    .expect("valid IPv6 route record")
}
