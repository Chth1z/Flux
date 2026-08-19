const MAGIC: &[u8; 8] = b"FLXQ13E1";
const SNAPSHOT_COUNT: usize = 4;
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const HEADER_BYTES: usize = MAGIC.len() + SNAPSHOT_COUNT * size_of::<u32>();
pub(crate) const MAX_FRAME_BYTES: usize = HEADER_BYTES + SNAPSHOT_COUNT * MAX_SNAPSHOT_BYTES;

/// Fixed, identity-free helper exit boundaries shared by the isolated validator and its host.
///
/// The numeric values are part of the private subprocess protocol. Keeping their mapping beside
/// the frame format prevents the producer and parent from drifting into different diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ValidationBoundary {
    InvalidInput,
    InvalidSnapshot,
    SnapshotDrift,
    UnreviewedCohort,
}

#[allow(dead_code)]
impl ValidationBoundary {
    pub(crate) const fn exit_code(self) -> i32 {
        match self {
            Self::InvalidInput => 70,
            Self::InvalidSnapshot => 71,
            Self::SnapshotDrift => 72,
            Self::UnreviewedCohort => 73,
        }
    }

    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid-input",
            Self::InvalidSnapshot => "invalid-xtables-snapshot",
            Self::SnapshotDrift => "snapshot-drift",
            Self::UnreviewedCohort => "unreviewed-ordered-cohort",
        }
    }

    pub(crate) const fn from_exit_code(code: i32) -> Option<Self> {
        match code {
            70 => Some(Self::InvalidInput),
            71 => Some(Self::InvalidSnapshot),
            72 => Some(Self::SnapshotDrift),
            73 => Some(Self::UnreviewedCohort),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// The parent xtask constructs frames while the isolated helper validates and decodes them.
#[allow(dead_code)]
pub(crate) enum FrameError {
    EmptySnapshot,
    SnapshotTooLarge,
    FrameTooLarge,
    InvalidMagic,
    InvalidLength,
    TrailingBytes,
}

#[allow(dead_code)]
pub(crate) struct DecodedFrame<'a> {
    snapshots: [&'a [u8]; SNAPSHOT_COUNT],
}

#[allow(dead_code)]
impl<'a> DecodedFrame<'a> {
    pub(crate) const fn snapshots(&self) -> [&'a [u8]; SNAPSHOT_COUNT] {
        self.snapshots
    }
}

pub(crate) fn encode(snapshots: [&[u8]; SNAPSHOT_COUNT]) -> Result<Vec<u8>, FrameError> {
    let payload_bytes = snapshots.iter().try_fold(0_usize, |total, snapshot| {
        validate_snapshot(snapshot)?;
        total
            .checked_add(snapshot.len())
            .ok_or(FrameError::FrameTooLarge)
    })?;
    let capacity = HEADER_BYTES
        .checked_add(payload_bytes)
        .filter(|size| *size <= MAX_FRAME_BYTES)
        .ok_or(FrameError::FrameTooLarge)?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(MAGIC);
    for snapshot in snapshots {
        let length = u32::try_from(snapshot.len()).map_err(|_| FrameError::SnapshotTooLarge)?;
        frame.extend_from_slice(&length.to_be_bytes());
    }
    for snapshot in snapshots {
        frame.extend_from_slice(snapshot);
    }
    Ok(frame)
}

#[allow(dead_code)]
pub(crate) fn decode(frame: &[u8]) -> Result<DecodedFrame<'_>, FrameError> {
    if frame.len() > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge);
    }
    if frame.get(..MAGIC.len()) != Some(MAGIC) {
        return Err(FrameError::InvalidMagic);
    }
    let mut cursor = MAGIC.len();
    let mut lengths = [0_usize; SNAPSHOT_COUNT];
    for length in &mut lengths {
        let end = cursor
            .checked_add(size_of::<u32>())
            .ok_or(FrameError::InvalidLength)?;
        let bytes: [u8; 4] = frame
            .get(cursor..end)
            .ok_or(FrameError::InvalidLength)?
            .try_into()
            .map_err(|_| FrameError::InvalidLength)?;
        *length =
            usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| FrameError::InvalidLength)?;
        cursor = end;
    }

    let mut snapshots = [&[][..]; SNAPSHOT_COUNT];
    for (snapshot, length) in snapshots.iter_mut().zip(lengths) {
        let end = cursor
            .checked_add(length)
            .ok_or(FrameError::InvalidLength)?;
        *snapshot = frame.get(cursor..end).ok_or(FrameError::InvalidLength)?;
        validate_snapshot(snapshot)?;
        cursor = end;
    }
    if cursor != frame.len() {
        return Err(FrameError::TrailingBytes);
    }
    Ok(DecodedFrame { snapshots })
}

fn validate_snapshot(snapshot: &[u8]) -> Result<(), FrameError> {
    if snapshot.is_empty() {
        Err(FrameError::EmptySnapshot)
    } else if snapshot.len() > MAX_SNAPSHOT_BYTES {
        Err(FrameError::SnapshotTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_four_exact_snapshots() {
        let snapshots = [
            b"ipv4-a\n".as_slice(),
            b"ipv6-a\n",
            b"ipv4-b\n",
            b"ipv6-b\n",
        ];
        let encoded = encode(snapshots).expect("bounded frame");
        assert_eq!(
            decode(&encoded).expect("canonical frame").snapshots(),
            snapshots
        );
    }

    #[test]
    fn frame_rejects_empty_truncated_and_trailing_inputs() {
        assert_eq!(
            encode([b"one".as_slice(), b"two", b"", b"four"]),
            Err(FrameError::EmptySnapshot)
        );
        let encoded =
            encode([b"one".as_slice(), b"two", b"three", b"four"]).expect("bounded frame");
        assert_eq!(
            decode(&encoded[..encoded.len() - 1]).err(),
            Some(FrameError::InvalidLength)
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(decode(&trailing).err(), Some(FrameError::TrailingBytes));
    }

    #[test]
    fn validation_boundaries_round_trip_through_private_exit_codes() {
        for boundary in [
            ValidationBoundary::InvalidInput,
            ValidationBoundary::InvalidSnapshot,
            ValidationBoundary::SnapshotDrift,
            ValidationBoundary::UnreviewedCohort,
        ] {
            assert_eq!(
                ValidationBoundary::from_exit_code(boundary.exit_code()),
                Some(boundary)
            );
            assert!(!boundary.label().is_empty());
        }
        assert_eq!(ValidationBoundary::from_exit_code(74), None);
    }
}
