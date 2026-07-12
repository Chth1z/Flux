use flux_core::{
    DeferredRoutingPrerequisite, NetworkAddressFamily, NetworkInventory, NetworkInventoryTracker,
    NetworkRouteRecord, NetworkRuleRecord, OpaqueRuleAttribute, RouteFlags, RoutePath, RoutePrefix,
    RouteProperties, RouteProtocol, RouteScope, RouteTableId, RouteType, RpdbClassifierRevision,
    RpdbFamilyPlacement, RpdbFamilyPlacementError, RpdbPlacementPlanError, RpdbPlacementRequest,
    RpdbPlacementRequestError, RpdbPriorityRole, RpdbRuleAudit, RpdbRuleAuditError,
    RpdbRuleClassification, RuleAction, RuleAttributeOpacity, RuleFlags,
    RuleOpaqueAttributeFingerprint, RulePrefix, RulePriority, RuleProperties, RuleProtocol,
    RuleTableId, plan_rpdb_placement,
};

const GUARD_PRIORITY: u32 = 10_000;
const BYPASS_PRIORITY: u32 = 15_000;
const PROXY_PRIORITY: u32 = 16_000;
const BARRIER_PRIORITY: u32 = 20_000;
const PRIVATE_TABLE: u32 = 1_000;

#[test]
fn safe_dual_family_window_returns_snapshot_and_classifier_bound_evidence() {
    let rules = [
        rule(
            NetworkAddressFamily::Ipv4,
            9_000,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv6,
            8_000,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv4,
            GUARD_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv4,
            15_500,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv6,
            22_000,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv4,
            21_000,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv4,
            BARRIER_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
    ];
    let inventory = inventory([], rules);
    let revision = revision(7);
    let audit = RpdbRuleAudit::new(
        revision,
        &inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::TerminalBarrier,
            RpdbRuleClassification::TerminalBarrier,
            RpdbRuleClassification::TerminalBarrier,
        ],
    )
    .expect("aligned rule audit");
    let ipv4 = placement(BYPASS_PRIORITY, PROXY_PRIORITY, PRIVATE_TABLE);
    let ipv6 = placement(14_000, 17_000, PRIVATE_TABLE + 1);
    let request = RpdbPlacementRequest::new(Some(ipv4), Some(ipv6)).expect("dual-family request");

    let lease = plan_rpdb_placement(&inventory, &audit, request).expect("safe placement window");

    assert_eq!(audit.snapshot_id(), inventory.snapshot_id());
    assert_eq!(audit.epoch(), inventory.epoch());
    assert_eq!(audit.classifier_revision(), revision);
    assert_eq!(audit.classifications().len(), inventory.rules().len());
    assert_eq!(lease.snapshot_id(), inventory.snapshot_id());
    assert_eq!(lease.epoch(), inventory.epoch());
    assert_eq!(lease.classifier_revision(), revision);
    assert_eq!(lease.request(), request);
    assert_eq!(lease.family(NetworkAddressFamily::Ipv4), Some(ipv4));
    assert_eq!(lease.family(NetworkAddressFamily::Ipv6), Some(ipv6));
    let ipv4_window = lease
        .window(NetworkAddressFamily::Ipv4)
        .expect("IPv4 window");
    assert_eq!(ipv4_window.last_must_precede().get(), GUARD_PRIORITY);
    assert_eq!(ipv4_window.first_terminal_barrier().get(), BARRIER_PRIORITY);
    let ipv6_window = lease
        .window(NetworkAddressFamily::Ipv6)
        .expect("IPv6 window");
    assert_eq!(ipv6_window.last_must_precede().get(), 8_000);
    assert_eq!(ipv6_window.first_terminal_barrier().get(), 22_000);
    lease
        .ensure_current(&inventory, revision)
        .expect("same snapshot and classifier revision");

    let routing = lease
        .address_bypass_routing_spec(RuleProtocol::from_raw(99))
        .expect("lease projects structural bypass routing");
    assert_eq!(routing.lookup_table(), RuleTableId::from_raw(254));
    assert_eq!(routing.ipv4_priority(), Some(ipv4.bypass_priority()));
    assert_eq!(routing.ipv6_priority(), Some(ipv6.bypass_priority()));
    assert_eq!(routing.protocol(), RuleProtocol::from_raw(99));
    assert_eq!(
        lease.deferred_prerequisites(),
        &[
            DeferredRoutingPrerequisite::MarkLease,
            DeferredRoutingPrerequisite::BootIdentityBinding,
            DeferredRoutingPrerequisite::NetworkNamespaceBinding,
            DeferredRoutingPrerequisite::DurableOwnershipJournal,
            DeferredRoutingPrerequisite::ExactKernelMutationIdentity,
        ]
    );
}

#[test]
fn audit_requires_exactly_one_classification_per_ordered_rule() {
    let duplicate = rule(
        NetworkAddressFamily::Ipv4,
        GUARD_PRIORITY,
        254,
        RuleAction::TO_TABLE,
        None,
    );
    let inventory = inventory([], [duplicate.clone(), duplicate]);

    assert_eq!(
        RpdbRuleAudit::new(
            revision(1),
            &inventory,
            [RpdbRuleClassification::MustPrecedeFlux]
        )
        .expect_err("one classification is missing"),
        RpdbRuleAuditError::ClassificationCountMismatch {
            expected: 2,
            actual: 1,
        }
    );
    assert_eq!(
        RpdbRuleAudit::new(
            revision(1),
            &inventory,
            [
                RpdbRuleClassification::MustPrecedeFlux,
                RpdbRuleClassification::MustPrecedeFlux,
                RpdbRuleClassification::TerminalBarrier,
            ]
        )
        .expect_err("one classification is extra"),
        RpdbRuleAuditError::ClassificationCountMismatch {
            expected: 2,
            actual: 3,
        }
    );
}

#[test]
fn structural_constructors_reject_implicit_priorities_and_reserved_tables() {
    assert!(RpdbClassifierRevision::new(0).is_none());
    assert_eq!(revision(9).get(), 9);
    assert_eq!(
        RpdbFamilyPlacement::new(
            RulePriority::from_raw(0),
            RulePriority::from_raw(PROXY_PRIORITY),
            RuleTableId::from_raw(PRIVATE_TABLE),
        )
        .expect_err("zero bypass priority"),
        RpdbFamilyPlacementError::UnspecifiedPriority {
            role: RpdbPriorityRole::AddressBypass,
        }
    );
    assert_eq!(
        RpdbFamilyPlacement::new(
            RulePriority::from_raw(BYPASS_PRIORITY),
            RulePriority::from_raw(0),
            RuleTableId::from_raw(PRIVATE_TABLE),
        )
        .expect_err("zero proxy priority"),
        RpdbFamilyPlacementError::UnspecifiedPriority {
            role: RpdbPriorityRole::Proxy,
        }
    );
    for (bypass, proxy) in [(PROXY_PRIORITY, PROXY_PRIORITY), (17_000, 16_000)] {
        assert!(matches!(
            RpdbFamilyPlacement::new(
                RulePriority::from_raw(bypass),
                RulePriority::from_raw(proxy),
                RuleTableId::from_raw(PRIVATE_TABLE),
            ),
            Err(RpdbFamilyPlacementError::PriorityOrder { .. })
        ));
    }
    for table in [0, 253, 254, 255] {
        assert_eq!(
            RpdbFamilyPlacement::new(
                RulePriority::from_raw(BYPASS_PRIORITY),
                RulePriority::from_raw(PROXY_PRIORITY),
                RuleTableId::from_raw(table),
            )
            .expect_err("reserved table"),
            RpdbFamilyPlacementError::ReservedPrivateTable {
                table: RuleTableId::from_raw(table),
            }
        );
    }
    assert_eq!(
        RpdbPlacementRequest::new(None, None).expect_err("no family enabled"),
        RpdbPlacementRequestError::NoEnabledFamilies
    );
}

#[test]
fn unknown_rules_fail_closed_only_for_enabled_families() {
    let rules = [
        rule(
            NetworkAddressFamily::Ipv4,
            GUARD_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv4,
            BARRIER_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        ),
        rule(
            NetworkAddressFamily::Ipv6,
            12_000,
            PRIVATE_TABLE,
            RuleAction::TO_TABLE,
            None,
        ),
    ];
    let routes = [route(NetworkAddressFamily::Ipv6, PRIVATE_TABLE)];
    let disabled_family_inventory = inventory(routes, rules);
    let audit = RpdbRuleAudit::new(
        revision(1),
        &disabled_family_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
            RpdbRuleClassification::Unknown,
        ],
    )
    .expect("aligned audit");
    let request = RpdbPlacementRequest::new(
        Some(placement(BYPASS_PRIORITY, PROXY_PRIORITY, PRIVATE_TABLE)),
        None,
    )
    .expect("IPv4 request");
    plan_rpdb_placement(&disabled_family_inventory, &audit, request)
        .expect("disabled-family unknowns and occupancy are outside this lease");

    let enabled_inventory = inventory(
        [],
        [
            rule(
                NetworkAddressFamily::Ipv4,
                GUARD_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                12_000,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
        ],
    );
    let enabled_audit = RpdbRuleAudit::new(
        revision(1),
        &enabled_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::Unknown,
            RpdbRuleClassification::TerminalBarrier,
        ],
    )
    .expect("aligned audit");
    assert_eq!(
        plan_rpdb_placement(&enabled_inventory, &enabled_audit, request)
            .expect_err("enabled-family unknown blocks placement"),
        RpdbPlacementPlanError::UnknownRule {
            family: NetworkAddressFamily::Ipv4,
            dump_index: 1,
        }
    );
}

#[test]
fn opaque_rules_override_classification_only_for_enabled_families() {
    let request = ipv4_request();
    for classification in [
        RpdbRuleClassification::MustPrecedeFlux,
        RpdbRuleClassification::TerminalBarrier,
        RpdbRuleClassification::DoesNotConstrainFlux,
        RpdbRuleClassification::Unknown,
    ] {
        let inventory = inventory(
            [],
            [
                rule(
                    NetworkAddressFamily::Ipv4,
                    GUARD_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
                opaque_rule(NetworkAddressFamily::Ipv4, 12_000),
                rule(
                    NetworkAddressFamily::Ipv4,
                    BARRIER_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
            ],
        );
        let audit = audit(
            &inventory,
            [
                RpdbRuleClassification::MustPrecedeFlux,
                classification,
                RpdbRuleClassification::TerminalBarrier,
            ],
        );
        assert_eq!(
            plan_rpdb_placement(&inventory, &audit, request)
                .expect_err("opaque enabled-family rule blocks classifier trust"),
            RpdbPlacementPlanError::OpaqueRule {
                family: NetworkAddressFamily::Ipv4,
                dump_index: 1,
            }
        );
    }

    let disabled_inventory = inventory(
        [],
        [
            rule(
                NetworkAddressFamily::Ipv4,
                GUARD_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            opaque_rule(NetworkAddressFamily::Ipv6, 12_000),
        ],
    );
    let disabled_audit = audit(
        &disabled_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
            RpdbRuleClassification::DoesNotConstrainFlux,
        ],
    );
    plan_rpdb_placement(&disabled_inventory, &disabled_audit, request)
        .expect("opaque disabled-family rules remain outside an IPv4-only lease");

    let dual_request = RpdbPlacementRequest::new(
        Some(placement(BYPASS_PRIORITY, PROXY_PRIORITY, PRIVATE_TABLE)),
        Some(placement(
            BYPASS_PRIORITY,
            PROXY_PRIORITY,
            PRIVATE_TABLE + 1,
        )),
    )
    .expect("dual-family request");
    assert_eq!(
        plan_rpdb_placement(&disabled_inventory, &disabled_audit, dual_request)
            .expect_err("enabling the opaque IPv6 family rejects the atomic request"),
        RpdbPlacementPlanError::OpaqueRule {
            family: NetworkAddressFamily::Ipv6,
            dump_index: 2,
        }
    );
}

#[test]
fn both_external_policy_boundaries_are_required() {
    let request = ipv4_request();
    let barrier_only = inventory(
        [],
        [rule(
            NetworkAddressFamily::Ipv4,
            BARRIER_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        )],
    );
    let barrier_audit = audit(&barrier_only, [RpdbRuleClassification::TerminalBarrier]);
    assert_eq!(
        plan_rpdb_placement(&barrier_only, &barrier_audit, request)
            .expect_err("missing guard boundary"),
        RpdbPlacementPlanError::MissingMustPrecedeBoundary {
            family: NetworkAddressFamily::Ipv4,
        }
    );

    let guard_only = inventory(
        [],
        [rule(
            NetworkAddressFamily::Ipv4,
            GUARD_PRIORITY,
            254,
            RuleAction::TO_TABLE,
            None,
        )],
    );
    let guard_audit = audit(&guard_only, [RpdbRuleClassification::MustPrecedeFlux]);
    assert_eq!(
        plan_rpdb_placement(&guard_only, &guard_audit, request)
            .expect_err("missing terminal boundary"),
        RpdbPlacementPlanError::MissingTerminalBarrier {
            family: NetworkAddressFamily::Ipv4,
        }
    );
}

#[test]
fn every_existing_rule_at_a_requested_priority_is_foreign_occupancy() {
    for (priority, role) in [
        (BYPASS_PRIORITY, RpdbPriorityRole::AddressBypass),
        (PROXY_PRIORITY, RpdbPriorityRole::Proxy),
    ] {
        let inventory = inventory(
            [],
            [
                rule(
                    NetworkAddressFamily::Ipv4,
                    GUARD_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
                rule(
                    NetworkAddressFamily::Ipv4,
                    priority,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
                rule(
                    NetworkAddressFamily::Ipv4,
                    BARRIER_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
            ],
        );
        let audit = audit(
            &inventory,
            [
                RpdbRuleClassification::MustPrecedeFlux,
                RpdbRuleClassification::DoesNotConstrainFlux,
                RpdbRuleClassification::TerminalBarrier,
            ],
        );
        assert_eq!(
            plan_rpdb_placement(&inventory, &audit, ipv4_request())
                .expect_err("occupied priority cannot be adopted"),
            RpdbPlacementPlanError::PriorityOccupied {
                family: NetworkAddressFamily::Ipv4,
                role,
                dump_index: 1,
            }
        );
    }
}

#[test]
fn goto_edges_crossing_starting_or_landing_in_the_candidate_window_are_rejected() {
    for (source, target) in [(9_000, 17_000), (15_500, 19_000), (9_000, BYPASS_PRIORITY)] {
        let inventory = inventory(
            [],
            [
                rule(
                    NetworkAddressFamily::Ipv4,
                    GUARD_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
                rule(
                    NetworkAddressFamily::Ipv4,
                    source,
                    0,
                    RuleAction::GOTO,
                    Some(target),
                ),
                rule(
                    NetworkAddressFamily::Ipv4,
                    BARRIER_PRIORITY,
                    254,
                    RuleAction::TO_TABLE,
                    None,
                ),
            ],
        );
        let audit = audit(
            &inventory,
            [
                RpdbRuleClassification::MustPrecedeFlux,
                RpdbRuleClassification::DoesNotConstrainFlux,
                RpdbRuleClassification::TerminalBarrier,
            ],
        );
        assert_eq!(
            plan_rpdb_placement(&inventory, &audit, ipv4_request())
                .expect_err("GOTO intersects the candidate interval"),
            RpdbPlacementPlanError::GotoIntersectsCandidateWindow {
                family: NetworkAddressFamily::Ipv4,
                dump_index: 1,
                source: RulePriority::from_raw(source),
                target: RulePriority::from_raw(target),
                bypass: RulePriority::from_raw(BYPASS_PRIORITY),
                proxy: RulePriority::from_raw(PROXY_PRIORITY),
            }
        );
    }
}

#[test]
fn goto_edges_wholly_before_or_after_the_candidate_window_do_not_constrain_it() {
    let inventory = inventory(
        [],
        [
            rule(
                NetworkAddressFamily::Ipv4,
                GUARD_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                9_000,
                PRIVATE_TABLE,
                RuleAction::GOTO,
                Some(14_000),
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                17_000,
                0,
                RuleAction::GOTO,
                Some(19_000),
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
        ],
    );
    let audit = audit(
        &inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    plan_rpdb_placement(&inventory, &audit, ipv4_request())
        .expect("nonintersecting GOTO edges are outside the candidate interval");
}

#[test]
fn candidate_priorities_must_be_strictly_inside_the_classified_window() {
    let inventory = inventory(
        [],
        [
            rule(
                NetworkAddressFamily::Ipv4,
                15_500,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
        ],
    );
    let audit = audit(
        &inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    assert_eq!(
        plan_rpdb_placement(&inventory, &audit, ipv4_request())
            .expect_err("guard falls after bypass priority"),
        RpdbPlacementPlanError::PriorityWindowViolation {
            family: NetworkAddressFamily::Ipv4,
            last_must_precede: RulePriority::from_raw(15_500),
            bypass: RulePriority::from_raw(BYPASS_PRIORITY),
            proxy: RulePriority::from_raw(PROXY_PRIORITY),
            first_terminal_barrier: RulePriority::from_raw(BARRIER_PRIORITY),
        }
    );
}

#[test]
fn any_route_or_rule_occupying_the_candidate_private_table_blocks_placement() {
    let baseline = baseline_rules(NetworkAddressFamily::Ipv4);
    let route_inventory = inventory(
        [route(NetworkAddressFamily::Ipv4, PRIVATE_TABLE)],
        baseline.clone(),
    );
    let route_audit = audit(
        &route_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    assert_eq!(
        plan_rpdb_placement(&route_inventory, &route_audit, ipv4_request())
            .expect_err("private table contains a foreign route"),
        RpdbPlacementPlanError::PrivateTableRouteOccupied {
            family: NetworkAddressFamily::Ipv4,
            dump_index: 0,
            table: RuleTableId::from_raw(PRIVATE_TABLE),
        }
    );

    let rule_inventory = inventory(
        [],
        [
            baseline[0].clone(),
            rule(
                NetworkAddressFamily::Ipv4,
                12_000,
                PRIVATE_TABLE,
                RuleAction::TO_TABLE,
                None,
            ),
            baseline[1].clone(),
        ],
    );
    let rule_audit = audit(
        &rule_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    assert_eq!(
        plan_rpdb_placement(&rule_inventory, &rule_audit, ipv4_request())
            .expect_err("private table has a foreign rule reference"),
        RpdbPlacementPlanError::PrivateTableRuleOccupied {
            family: NetworkAddressFamily::Ipv4,
            dump_index: 1,
            table: RuleTableId::from_raw(PRIVATE_TABLE),
        }
    );

    let ambiguous_inventory = inventory(
        [],
        [
            baseline[0].clone(),
            rule(
                NetworkAddressFamily::Ipv4,
                12_000,
                PRIVATE_TABLE,
                RuleAction::from_raw(250),
                None,
            ),
            baseline[1].clone(),
        ],
    );
    let ambiguous_audit = audit(
        &ambiguous_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    assert_eq!(
        plan_rpdb_placement(&ambiguous_inventory, &ambiguous_audit, ipv4_request())
            .expect_err("unknown action cannot prove its table field irrelevant"),
        RpdbPlacementPlanError::PrivateTableRuleOccupied {
            family: NetworkAddressFamily::Ipv4,
            dump_index: 1,
            table: RuleTableId::from_raw(PRIVATE_TABLE),
        }
    );
}

#[test]
fn dual_family_requests_reject_atomically_when_either_family_fails() {
    let inventory = inventory(
        [],
        [
            rule(
                NetworkAddressFamily::Ipv4,
                GUARD_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv4,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv6,
                GUARD_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv6,
                PROXY_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
            rule(
                NetworkAddressFamily::Ipv6,
                BARRIER_PRIORITY,
                254,
                RuleAction::TO_TABLE,
                None,
            ),
        ],
    );
    let audit = audit(
        &inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::DoesNotConstrainFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    let request = RpdbPlacementRequest::new(
        Some(placement(BYPASS_PRIORITY, PROXY_PRIORITY, PRIVATE_TABLE)),
        Some(placement(
            BYPASS_PRIORITY,
            PROXY_PRIORITY,
            PRIVATE_TABLE + 1,
        )),
    )
    .expect("dual-family request");
    assert_eq!(
        plan_rpdb_placement(&inventory, &audit, request)
            .expect_err("IPv6 collision rejects the complete request"),
        RpdbPlacementPlanError::PriorityOccupied {
            family: NetworkAddressFamily::Ipv6,
            role: RpdbPriorityRole::Proxy,
            dump_index: 3,
        }
    );
}

#[test]
fn audits_cannot_cross_snapshot_or_epoch_boundaries() {
    let facts = baseline_rules(NetworkAddressFamily::Ipv4);
    let mut first_tracker = NetworkInventoryTracker::new();
    let first = first_tracker
        .publish_complete_with_routing([], [], [], facts.clone())
        .expect("first inventory")
        .clone();
    let first_audit = audit(
        &first,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );

    let mut unrelated_tracker = NetworkInventoryTracker::new();
    let unrelated = unrelated_tracker
        .publish_complete_with_routing([], [], [], facts.clone())
        .expect("unrelated inventory")
        .clone();
    assert_eq!(first.epoch(), unrelated.epoch());
    assert_ne!(first.snapshot_id(), unrelated.snapshot_id());
    assert_eq!(
        plan_rpdb_placement(&unrelated, &first_audit, ipv4_request())
            .expect_err("same epoch from another tracker is not the audited snapshot"),
        RpdbPlacementPlanError::AuditSnapshotMismatch {
            inventory: unrelated.snapshot_id(),
            audit: first.snapshot_id(),
        }
    );

    let changed = first_tracker
        .publish_complete_with_routing([], [], [route(NetworkAddressFamily::Ipv4, 500)], facts)
        .expect("changed inventory")
        .clone();
    assert_ne!(first.epoch(), changed.epoch());
    assert_eq!(
        plan_rpdb_placement(&changed, &first_audit, ipv4_request())
            .expect_err("audit epoch is stale"),
        RpdbPlacementPlanError::AuditEpochMismatch {
            inventory: changed.epoch(),
            audit: first.epoch(),
        }
    );
}

#[test]
fn leases_reject_stale_snapshots_and_classifier_revisions() {
    let leased_inventory = inventory([], baseline_rules(NetworkAddressFamily::Ipv4));
    let first_revision = revision(11);
    let audit = RpdbRuleAudit::new(
        first_revision,
        &leased_inventory,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    )
    .expect("aligned audit");
    let lease =
        plan_rpdb_placement(&leased_inventory, &audit, ipv4_request()).expect("safe placement");

    let second_revision = revision(12);
    let stale_revision = lease
        .ensure_current(&leased_inventory, second_revision)
        .expect_err("classifier revision changed");
    assert_eq!(
        stale_revision.leased_snapshot_id(),
        leased_inventory.snapshot_id()
    );
    assert_eq!(
        stale_revision.current_snapshot_id(),
        leased_inventory.snapshot_id()
    );
    assert_eq!(stale_revision.leased_epoch(), leased_inventory.epoch());
    assert_eq!(stale_revision.current_epoch(), leased_inventory.epoch());
    assert_eq!(stale_revision.leased_classifier_revision(), first_revision);
    assert_eq!(
        stale_revision.current_classifier_revision(),
        second_revision
    );

    let unrelated = inventory([], baseline_rules(NetworkAddressFamily::Ipv4));
    assert_eq!(unrelated.epoch(), leased_inventory.epoch());
    let stale_snapshot = lease
        .ensure_current(&unrelated, first_revision)
        .expect_err("snapshot identity changed");
    assert_eq!(
        stale_snapshot.leased_snapshot_id(),
        leased_inventory.snapshot_id()
    );
    assert_eq!(
        stale_snapshot.current_snapshot_id(),
        unrelated.snapshot_id()
    );
}

#[test]
fn newly_opaque_rule_attributes_stale_an_existing_placement_lease() {
    let rules = baseline_rules(NetworkAddressFamily::Ipv4);
    let mut tracker = NetworkInventoryTracker::new();
    let complete = tracker
        .publish_complete_with_routing([], [], [], rules.clone())
        .expect("complete rule inventory")
        .clone();
    let audit = audit(
        &complete,
        [
            RpdbRuleClassification::MustPrecedeFlux,
            RpdbRuleClassification::TerminalBarrier,
        ],
    );
    let lease = plan_rpdb_placement(&complete, &audit, ipv4_request())
        .expect("complete facts admit placement");

    let opaque_rules = [
        rules[0].clone(),
        rules[1].clone().with_attribute_opacity(test_opacity()),
    ];
    let opaque = tracker
        .publish_complete_with_routing([], [], [], opaque_rules)
        .expect("opaque rule inventory")
        .clone();
    let stale = lease
        .ensure_current(&opaque, audit.classifier_revision())
        .expect_err("newly opaque semantics invalidate the prior lease");
    assert_eq!(stale.leased_snapshot_id(), complete.snapshot_id());
    assert_eq!(stale.current_snapshot_id(), opaque.snapshot_id());
    assert_ne!(stale.leased_epoch(), stale.current_epoch());
}

fn revision(value: u64) -> RpdbClassifierRevision {
    RpdbClassifierRevision::new(value).expect("nonzero classifier revision")
}

fn placement(bypass: u32, proxy: u32, private_table: u32) -> RpdbFamilyPlacement {
    RpdbFamilyPlacement::new(
        RulePriority::from_raw(bypass),
        RulePriority::from_raw(proxy),
        RuleTableId::from_raw(private_table),
    )
    .expect("structurally valid family placement")
}

fn ipv4_request() -> RpdbPlacementRequest {
    RpdbPlacementRequest::new(
        Some(placement(BYPASS_PRIORITY, PROXY_PRIORITY, PRIVATE_TABLE)),
        None,
    )
    .expect("IPv4 placement request")
}

fn audit(
    inventory: &NetworkInventory,
    classifications: impl IntoIterator<Item = RpdbRuleClassification>,
) -> RpdbRuleAudit {
    RpdbRuleAudit::new(revision(1), inventory, classifications).expect("aligned rule audit")
}

fn inventory(
    routes: impl IntoIterator<Item = NetworkRouteRecord>,
    rules: impl IntoIterator<Item = NetworkRuleRecord>,
) -> NetworkInventory {
    let mut tracker = NetworkInventoryTracker::new();
    tracker
        .publish_complete_with_routing([], [], routes, rules)
        .expect("valid complete inventory")
        .clone()
}

fn baseline_rules(family: NetworkAddressFamily) -> Vec<NetworkRuleRecord> {
    vec![
        rule(family, GUARD_PRIORITY, 254, RuleAction::TO_TABLE, None),
        rule(family, BARRIER_PRIORITY, 254, RuleAction::TO_TABLE, None),
    ]
}

fn rule(
    family: NetworkAddressFamily,
    priority: u32,
    table: u32,
    action: RuleAction,
    goto_target: Option<u32>,
) -> NetworkRuleRecord {
    NetworkRuleRecord::new(
        RulePrefix::unspecified(family),
        RulePrefix::unspecified(family),
        RuleProperties::new(
            0,
            RuleTableId::from_raw(table),
            action,
            RuleProtocol::from_raw(2),
            RuleFlags::default(),
        ),
        RulePriority::from_raw(priority),
        goto_target.map(RulePriority::from_raw),
    )
    .expect("valid test rule")
}

fn opaque_rule(family: NetworkAddressFamily, priority: u32) -> NetworkRuleRecord {
    rule(family, priority, 254, RuleAction::TO_TABLE, None).with_attribute_opacity(test_opacity())
}

fn test_opacity() -> RuleAttributeOpacity {
    RuleAttributeOpacity::new(
        [OpaqueRuleAttribute::new(25, 0, 4)],
        0,
        RuleOpaqueAttributeFingerprint::from_bytes([0x25; 32]),
    )
    .expect("bounded test opacity evidence")
}

fn route(family: NetworkAddressFamily, table: u32) -> NetworkRouteRecord {
    NetworkRouteRecord::new(
        RoutePrefix::unspecified(family),
        RoutePrefix::unspecified(family),
        RouteProperties::new(
            0,
            RouteTableId::from_raw(table),
            RouteProtocol::from_raw(2),
            RouteScope::from_raw(0),
            RouteType::from_raw(1),
            RouteFlags::default(),
        ),
        0,
        RoutePath::None,
    )
    .expect("valid test route")
}
