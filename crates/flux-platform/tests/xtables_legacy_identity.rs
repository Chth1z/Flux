use flux_platform::{
    LEGACY_RULES_IDENTITY_SCHEMA_VERSION, LegacyApplicationMode, LegacyApplicationPolicy,
    LegacyInterfacePattern, LegacyInterfacePolicy, LegacyInterfaceRole, LegacyKernelFeatures,
    LegacyMarkValues, LegacyOwnerMatch, LegacyOwnerToken, LegacyRulesArtifactPair, LegacyRulesPlan,
    LegacyRulesRenderError, LegacyRulesResourceTotals, XTABLES_RESTORE_SCHEMA_VERSION,
    XtablesRestoreAction, XtablesRestoreFamily, render_legacy_rules_pair, render_legacy_rules_set,
};

#[test]
fn maximal_set_is_deterministic_and_matches_every_pinned_artifact() {
    let plan = LegacyRulesPlan::maximal_zone_v1();
    let first = render_legacy_rules_set(&plan).expect("maximal set must render");
    let second = render_legacy_rules_set(&plan).expect("repeat render must succeed");

    assert_eq!(
        digest_hex(first.plan_digest().as_bytes()),
        "f5cc1f52f7f1938fa6a2ec94b5a46b35796b917e5903ecd8bfa62b591a5f2981"
    );
    assert_eq!(
        digest_hex(first.ipv4().digest().as_bytes()),
        "272b226c3845d7289a87142d5950a2b05beb4f043751e37ff1f29e251e1e62de"
    );
    assert_eq!(
        digest_hex(first.ipv6().unwrap().digest().as_bytes()),
        "1d910292c0f4e11ec8435a8532d9d521c81a3af4a0b65aacbbe988c0b39366c4"
    );
    assert_eq!(
        digest_hex(first.digest().as_bytes()),
        "93e6f53c5f0c147893caab4c6d851102c38ab117cc435e19df4afa07da2406f3"
    );

    assert_eq!(first, second);
    assert_eq!(first.schema_version(), LEGACY_RULES_IDENTITY_SCHEMA_VERSION);
    assert_eq!(first.plan_digest(), plan.digest());
    assert_pair_bytes(
        first.ipv4(),
        include_bytes!("../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-apply.restore"),
        include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv4-cleanup.restore"
        ),
    );
    assert_pair_bytes(
        first.ipv6().expect("maximal set enables IPv6"),
        include_bytes!("../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-apply.restore"),
        include_bytes!(
            "../../../tests/oracle/xtables/fixtures/maximal-zone-v1-ipv6-cleanup.restore"
        ),
    );

    assert_totals_sum(
        first.resource_totals(),
        first.ipv4().resource_totals(),
        first.ipv6().unwrap().resource_totals(),
    );
}

#[test]
fn renderer_pair_closes_family_action_schema_and_resource_identity() {
    let plan = LegacyRulesPlan::maximal_zone_v1();
    let pair = render_legacy_rules_pair(&plan, XtablesRestoreFamily::Ipv4).unwrap();

    assert_eq!(pair.schema_version(), LEGACY_RULES_IDENTITY_SCHEMA_VERSION);
    assert_eq!(pair.family(), XtablesRestoreFamily::Ipv4);
    assert_eq!(pair.plan_digest(), plan.digest());
    assert_eq!(
        pair.apply().schema_version(),
        XTABLES_RESTORE_SCHEMA_VERSION
    );
    assert_eq!(pair.apply().context().action(), XtablesRestoreAction::Apply);
    assert_eq!(pair.apply().context().family(), XtablesRestoreFamily::Ipv4);
    assert_eq!(
        pair.cleanup().schema_version(),
        XTABLES_RESTORE_SCHEMA_VERSION
    );
    assert_eq!(
        pair.cleanup().context().action(),
        XtablesRestoreAction::Cleanup
    );
    assert_eq!(
        pair.cleanup().context().family(),
        XtablesRestoreFamily::Ipv4
    );
    assert_pair_totals(&pair);
}

#[test]
fn plan_and_pair_identity_preserve_order_duplicates_and_other_source_fields() {
    let base = plan(
        &[10_123, 10_124],
        &["wlan+", "rmnet+"],
        1536,
        false,
        "fc00::/18",
    );
    let reordered = plan(
        &[10_124, 10_123],
        &["wlan+", "rmnet+"],
        1536,
        false,
        "fc00::/18",
    );
    let duplicated = plan(
        &[10_123, 10_124],
        &["wlan+", "rmnet+", "wlan+"],
        1536,
        false,
        "fc00::/18",
    );
    let different_port = plan(
        &[10_123, 10_124],
        &["wlan+", "rmnet+"],
        1537,
        false,
        "fc00::/18",
    );

    for candidate in [&reordered, &duplicated, &different_port] {
        assert_ne!(base.digest(), candidate.digest());
        assert_ne!(
            render_legacy_rules_pair(&base, XtablesRestoreFamily::Ipv4)
                .unwrap()
                .digest(),
            render_legacy_rules_pair(candidate, XtablesRestoreFamily::Ipv4)
                .unwrap()
                .digest()
        );
    }

    let base_text = render_legacy_rules_pair(&base, XtablesRestoreFamily::Ipv4)
        .unwrap()
        .apply()
        .render_canonical();
    let duplicate_text = render_legacy_rules_pair(&duplicated, XtablesRestoreFamily::Ipv4)
        .unwrap()
        .apply()
        .render_canonical();
    assert_eq!(
        std::str::from_utf8(&base_text)
            .unwrap()
            .matches("-A PROXY_PREROUTING -i wlan+ -j ACCEPT\n")
            .count(),
        1
    );
    assert_eq!(
        std::str::from_utf8(&duplicate_text)
            .unwrap()
            .matches("-A PROXY_PREROUTING -i wlan+ -j ACCEPT\n")
            .count(),
        2
    );
}

#[test]
fn plan_digest_binds_every_manually_encoded_input_field() {
    let base_fixture = LegacyPlanFixture::default();
    let base = base_fixture.build();
    let base_pair = render_legacy_rules_pair(&base, XtablesRestoreFamily::Ipv4).unwrap();

    let cases = [
        varied("proxy_port", |fixture| fixture.proxy_port = 1537),
        varied("mark_mask", |fixture| fixture.mark_mask = 0x1ff),
        varied("ipv4_proxy_mark", |fixture| fixture.marks[0] = 0x24),
        varied("ipv6_proxy_mark", |fixture| fixture.marks[1] = 0x29),
        varied("bypass_mark", |fixture| fixture.marks[2] = 0x21),
        varied("routing_mark", |fixture| fixture.routing_mark = Some(0x31)),
        varied("owner_uid", |fixture| fixture.owner_uid = "system"),
        varied("owner_gid", |fixture| fixture.owner_gid = "system"),
        varied("application_mode", |fixture| {
            fixture.application_mode = LegacyApplicationMode::Denylist;
        }),
        varied("application_uids", |fixture| {
            fixture.application_uids = vec![10_123, 10_125];
        }),
        varied("excluded_interfaces", |fixture| {
            fixture.excluded_interfaces = vec!["wlan+", "rmnet+", "tun+"];
        }),
        varied("mobile_pattern", |fixture| fixture.roles[0].0 = None),
        varied("mobile_proxy", |fixture| fixture.roles[0].1 = false),
        varied("wifi_pattern", |fixture| fixture.roles[1].0 = Some("wlan1")),
        varied("wifi_proxy", |fixture| fixture.roles[1].1 = true),
        varied("hotspot_pattern", |fixture| {
            fixture.roles[2].0 = Some("wlan3");
        }),
        varied("hotspot_proxy", |fixture| fixture.roles[2].1 = false),
        varied("usb_pattern", |fixture| fixture.roles[3].0 = Some("usb+")),
        varied("usb_proxy", |fixture| fixture.roles[3].1 = true),
        varied("feature_owner", |fixture| fixture.features[0] = false),
        varied("feature_mark", |fixture| fixture.features[1] = false),
        varied("feature_conntrack", |fixture| fixture.features[2] = false),
        varied("feature_socket_tcp", |fixture| fixture.features[3] = false),
        varied("feature_socket_udp", |fixture| fixture.features[4] = false),
        varied("feature_ipv6_nat", |fixture| fixture.features[5] = false),
        varied("feature_tproxy", |fixture| fixture.features[6] = false),
        varied("performance_mode", |fixture| {
            fixture.performance_mode = false
        }),
        varied("mss_clamp", |fixture| fixture.mss_clamp = false),
        varied("ipv6_enabled", |fixture| fixture.ipv6_enabled = false),
        varied("fake_ip_v4", |fixture| fixture.fake_ip_v4 = "198.19.0.0/16"),
        varied("fake_ip_v6", |fixture| fixture.fake_ip_v6 = "fd00::/8"),
    ];

    for (name, fixture) in cases {
        let candidate = fixture.build();
        assert_ne!(base.digest(), candidate.digest(), "plan field {name}");
        assert_ne!(
            base_pair.digest(),
            render_legacy_rules_pair(&candidate, XtablesRestoreFamily::Ipv4)
                .unwrap()
                .digest(),
            "pair identity did not inherit plan field {name}",
        );
    }
}

#[test]
fn pair_identity_rejects_mixed_plans_even_when_family_artifacts_match() {
    let first_plan = plan(&[10_123], &["wlan+"], 1536, false, "fc00::/18");
    let second_plan = plan(&[10_123], &["wlan+"], 1536, false, "fd00::/8");
    let first = render_legacy_rules_pair(&first_plan, XtablesRestoreFamily::Ipv4).unwrap();
    let second = render_legacy_rules_pair(&second_plan, XtablesRestoreFamily::Ipv4).unwrap();

    assert_eq!(first.apply().digest(), second.apply().digest());
    assert_eq!(first.cleanup().digest(), second.cleanup().digest());
    assert_ne!(first.plan_digest(), second.plan_digest());
    assert_ne!(first.digest(), second.digest());
    assert_ne!(first, second, "renderer identities must not mix plans");
}

#[test]
fn set_identity_binds_ipv6_presence_and_both_family_receipts() {
    let ipv4_only = plan(&[10_123], &["wlan+"], 1536, false, "fc00::/18");
    let dual_stack = plan(&[10_123], &["wlan+"], 1536, true, "fc00::/18");
    let ipv4_set = render_legacy_rules_set(&ipv4_only).unwrap();
    let dual_set = render_legacy_rules_set(&dual_stack).unwrap();

    assert!(ipv4_set.ipv6().is_none());
    assert_eq!(
        render_legacy_rules_pair(&ipv4_only, XtablesRestoreFamily::Ipv6),
        Err(LegacyRulesRenderError::FamilyDisabled)
    );
    let ipv6 = dual_set.ipv6().expect("dual-stack plan must include IPv6");
    assert_eq!(ipv6.family(), XtablesRestoreFamily::Ipv6);
    assert_eq!(ipv6.plan_digest(), dual_set.plan_digest());
    assert_eq!(dual_set.ipv4().plan_digest(), dual_set.plan_digest());
    assert_ne!(ipv4_set.plan_digest(), dual_set.plan_digest());
    assert_ne!(ipv4_set.digest(), dual_set.digest());
    assert_totals_sum(
        dual_set.resource_totals(),
        dual_set.ipv4().resource_totals(),
        ipv6.resource_totals(),
    );
}

fn assert_pair_bytes(pair: &LegacyRulesArtifactPair, apply: &[u8], cleanup: &[u8]) {
    assert_eq!(pair.apply().render_canonical().as_ref(), apply);
    assert_eq!(pair.cleanup().render_canonical().as_ref(), cleanup);
}

fn digest_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn assert_pair_totals(pair: &LegacyRulesArtifactPair) {
    let totals = pair.resource_totals();
    let apply = pair.apply().usage();
    let cleanup = pair.cleanup().usage();
    assert_eq!(
        totals.input_bytes(),
        apply.input_bytes() + cleanup.input_bytes(),
    );
    assert_eq!(totals.lines(), apply.lines() + cleanup.lines());
    assert_eq!(
        totals.transactions(),
        apply.transactions() + cleanup.transactions(),
    );
    assert_eq!(
        totals.chain_declarations(),
        apply.chain_declarations() + cleanup.chain_declarations(),
    );
    assert_eq!(totals.commands(), apply.commands() + cleanup.commands());
    assert_eq!(totals.tokens(), apply.tokens() + cleanup.tokens());
}

fn assert_totals_sum(
    actual: LegacyRulesResourceTotals,
    first: LegacyRulesResourceTotals,
    second: LegacyRulesResourceTotals,
) {
    assert_eq!(
        actual.input_bytes(),
        first.input_bytes() + second.input_bytes(),
    );
    assert_eq!(actual.lines(), first.lines() + second.lines());
    assert_eq!(
        actual.transactions(),
        first.transactions() + second.transactions(),
    );
    assert_eq!(
        actual.chain_declarations(),
        first.chain_declarations() + second.chain_declarations(),
    );
    assert_eq!(actual.commands(), first.commands() + second.commands());
    assert_eq!(actual.tokens(), first.tokens() + second.tokens());
}

fn plan(
    uids: &[u32],
    excluded: &[&str],
    proxy_port: u16,
    ipv6_enabled: bool,
    fake_ip_v6: &str,
) -> LegacyRulesPlan {
    LegacyRulesPlan::new(
        proxy_port,
        0xff,
        LegacyMarkValues::legacy_defaults(),
        None,
        LegacyOwnerMatch::new(
            LegacyOwnerToken::new("root").unwrap(),
            LegacyOwnerToken::new("root").unwrap(),
        ),
        LegacyApplicationPolicy::new(LegacyApplicationMode::Allowlist, uids.iter().copied())
            .unwrap(),
        LegacyInterfacePolicy::new(
            excluded.iter().map(|value| pattern(value)),
            LegacyInterfaceRole::new(Some(pattern("rmnet_data+")), true),
            LegacyInterfaceRole::new(Some(pattern("wlan0")), false),
            LegacyInterfaceRole::new(Some(pattern("wlan2")), true),
            LegacyInterfaceRole::new(Some(pattern("rndis+")), false),
        )
        .unwrap(),
        LegacyKernelFeatures::new(true, true, true, true, true, true, true),
        true,
        true,
        ipv6_enabled,
        "198.18.0.0/15",
        fake_ip_v6,
    )
    .unwrap()
}

fn pattern(value: &str) -> LegacyInterfacePattern {
    LegacyInterfacePattern::new(value).unwrap()
}

#[derive(Clone)]
struct LegacyPlanFixture {
    proxy_port: u16,
    mark_mask: u32,
    marks: [u32; 3],
    routing_mark: Option<u32>,
    owner_uid: &'static str,
    owner_gid: &'static str,
    application_mode: LegacyApplicationMode,
    application_uids: Vec<u32>,
    excluded_interfaces: Vec<&'static str>,
    roles: [(Option<&'static str>, bool); 4],
    features: [bool; 7],
    performance_mode: bool,
    mss_clamp: bool,
    ipv6_enabled: bool,
    fake_ip_v4: &'static str,
    fake_ip_v6: &'static str,
}

impl Default for LegacyPlanFixture {
    fn default() -> Self {
        Self {
            proxy_port: 1536,
            mark_mask: 0xff,
            marks: [0x14, 0x19, 0x11],
            routing_mark: None,
            owner_uid: "root",
            owner_gid: "root",
            application_mode: LegacyApplicationMode::Allowlist,
            application_uids: vec![10_123, 10_124],
            excluded_interfaces: vec!["wlan+", "rmnet+"],
            roles: [
                (Some("rmnet_data+"), true),
                (Some("wlan0"), false),
                (Some("wlan2"), true),
                (Some("rndis+"), false),
            ],
            features: [true; 7],
            performance_mode: true,
            mss_clamp: true,
            ipv6_enabled: true,
            fake_ip_v4: "198.18.0.0/15",
            fake_ip_v6: "fc00::/18",
        }
    }
}

impl LegacyPlanFixture {
    fn build(&self) -> LegacyRulesPlan {
        let [mobile, wifi, hotspot, usb] = self.roles;
        let role = |(value, proxy): (Option<&str>, bool)| {
            LegacyInterfaceRole::new(value.map(pattern), proxy)
        };
        LegacyRulesPlan::new(
            self.proxy_port,
            self.mark_mask,
            LegacyMarkValues::new(self.marks[0], self.marks[1], self.marks[2]),
            self.routing_mark,
            LegacyOwnerMatch::new(
                LegacyOwnerToken::new(self.owner_uid).unwrap(),
                LegacyOwnerToken::new(self.owner_gid).unwrap(),
            ),
            LegacyApplicationPolicy::new(
                self.application_mode,
                self.application_uids.iter().copied(),
            )
            .unwrap(),
            LegacyInterfacePolicy::new(
                self.excluded_interfaces.iter().map(|value| pattern(value)),
                role(mobile),
                role(wifi),
                role(hotspot),
                role(usb),
            )
            .unwrap(),
            LegacyKernelFeatures::new(
                self.features[0],
                self.features[1],
                self.features[2],
                self.features[3],
                self.features[4],
                self.features[5],
                self.features[6],
            ),
            self.performance_mode,
            self.mss_clamp,
            self.ipv6_enabled,
            self.fake_ip_v4,
            self.fake_ip_v6,
        )
        .unwrap()
    }
}

fn varied(
    name: &'static str,
    mutate: impl FnOnce(&mut LegacyPlanFixture),
) -> (&'static str, LegacyPlanFixture) {
    let mut fixture = LegacyPlanFixture::default();
    mutate(&mut fixture);
    (name, fixture)
}
