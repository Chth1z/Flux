use flux_core::{
    ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK, ANDROID_NET_ID_FWMARK_MASK, AndroidNetdSourceProfile,
    FwmarkCensusCoverageRecord, FwmarkCensusCoverageState, FwmarkEvidenceSource, FwmarkPlane,
    FwmarkUseOperation, FwmarkUseRecord, project_android_net_id_fwmark_census_fragment,
};

#[test]
fn every_profile_projects_its_exact_packet_writer_and_shared_socket_netid_uses() {
    for profile in AndroidNetdSourceProfile::ALL {
        let fragment = project_android_net_id_fwmark_census_fragment(profile);
        let packet_write_mask = match profile {
            AndroidNetdSourceProfile::AospAndroid12R1
            | AndroidNetdSourceProfile::AospAndroid13R1 => 0xffef_ffff,
            AndroidNetdSourceProfile::AospNetd20250324 => 0x7fef_ffff,
        };

        assert_eq!(fragment.profile(), profile);
        assert_eq!(fragment.source_revision(), profile.source_revision());
        assert_eq!(
            packet_write_mask & ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK,
            ANDROID_DEVICE_QUALIFIED_CANDIDATE_MASK,
            "every pinned incoming-packet writer covers the complete candidate envelope"
        );
        assert_eq!(
            fragment.coverage(),
            [
                coverage(
                    FwmarkPlane::Packet,
                    FwmarkCensusCoverageState::CompletePresent,
                ),
                coverage(
                    FwmarkPlane::Socket,
                    FwmarkCensusCoverageState::CompletePresent,
                ),
                coverage(
                    FwmarkPlane::Conntrack,
                    FwmarkCensusCoverageState::CompleteAbsent,
                ),
            ]
        );
        assert_eq!(
            fragment.raw_mark_uses(),
            [
                mark_use(
                    FwmarkPlane::Packet,
                    FwmarkUseOperation::MaskedWrite,
                    packet_write_mask,
                ),
                mark_use(
                    FwmarkPlane::Socket,
                    FwmarkUseOperation::PredicateRead,
                    ANDROID_NET_ID_FWMARK_MASK,
                ),
                mark_use(
                    FwmarkPlane::Socket,
                    FwmarkUseOperation::MaskedWrite,
                    ANDROID_NET_ID_FWMARK_MASK,
                ),
            ]
        );
    }
}

#[test]
fn conntrack_transfers_are_not_misattributed_to_the_direct_netid_source() {
    let fragment =
        project_android_net_id_fwmark_census_fragment(AndroidNetdSourceProfile::AospNetd20250324);

    assert!(
        fragment
            .raw_mark_uses()
            .iter()
            .all(|record| record.plane() != FwmarkPlane::Conntrack)
    );
    assert!(fragment.raw_mark_uses().iter().all(|record| {
        record.source() == FwmarkEvidenceSource::AndroidNetId
            && !matches!(
                record.operation(),
                FwmarkUseOperation::TransferRead | FwmarkUseOperation::TransferWrite
            )
    }));
}

fn coverage(plane: FwmarkPlane, state: FwmarkCensusCoverageState) -> FwmarkCensusCoverageRecord {
    FwmarkCensusCoverageRecord::new(FwmarkEvidenceSource::AndroidNetId, plane, state)
}

fn mark_use(plane: FwmarkPlane, operation: FwmarkUseOperation, mask: u32) -> FwmarkUseRecord {
    FwmarkUseRecord::new(FwmarkEvidenceSource::AndroidNetId, plane, operation, mask)
        .expect("the source-pinned Android mask is nonzero")
}
