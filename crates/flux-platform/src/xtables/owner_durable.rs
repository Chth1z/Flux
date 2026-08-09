use std::error::Error;
use std::ffi::{CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use flux_core::{
    BootIdentity, GenerationId, NetworkNamespaceIdentity, OWNERSHIP_JOURNAL_IDENTITY_BYTES,
    OwnershipJournalIdentity, OwnershipJournalRevision,
};
use sha2::{Digest, Sha256};

pub(crate) const NATIVE_XTABLES_JOURNAL_FILE_NAME: &str = "native_xtables.journal";
pub(crate) const NATIVE_XTABLES_LEASE_FILE_NAME: &str = "native_xtables.lease";
pub(crate) const NATIVE_XTABLES_ATTEMPT_FILE_NAME: &str = "native_xtables.attempt";
pub(crate) const NATIVE_XTABLES_TARGET_ARCHIVE_FILE_NAME: &str = "native_xtables.targets";
pub(crate) const XTABLES_WRITER_LOCK_DIRECTORY_NAME: &str = "xtables-writer.lock";
const NATIVE_XTABLES_OWNER_GUARD_FILE_NAME: &str = ".native_xtables.owner.lock";
const NATIVE_XTABLES_RUNTIME_GUARD_FILE_NAME: &str = ".native_xtables.runtime.lock";
const NATIVE_XTABLES_WRITER_OWNER_FILE_NAME: &str = "native-owner";
pub(crate) const MAX_NATIVE_XTABLES_OWNER_PAYLOAD_BYTES: usize = 4096;
pub(crate) const MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES: usize = 512;
pub(crate) const MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES: usize = 16 * 1024;
pub(crate) const MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES: usize = 12 * 1024 * 1024;

const JOURNAL_MAGIC: &str = "flux-native-xtables-journal-v1";
pub(crate) const NATIVE_XTABLES_JOURNAL_SCHEMA_VERSION: u16 = 1;
const LEASE_MAGIC: &str = "flux-native-xtables-lease-v1";
const ATTEMPT_MAGIC: &str = "flux-native-xtables-attempt-v1";
const WRITER_OWNER_MAGIC: &str = "flux-native-xtables-writer-owner-v1";
const COMPONENT_NAME: &str = "native_xtables";
const CHECKSUM_BYTES: usize = 32;
const MAX_TEMP_CREATE_ATTEMPTS: usize = 16;
const NATIVE_OWNER_GUARD_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(1);
const NATIVE_OWNER_GUARD_RETRY_INTERVAL: Duration = Duration::from_millis(2);
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesJournalBinding {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    generation: GenerationId,
    journal_identity: OwnershipJournalIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesLeaseScope {
    boot_identity: BootIdentity,
    network_namespace: NetworkNamespaceIdentity,
    journal_identity: OwnershipJournalIdentity,
}

impl NativeXtablesLeaseScope {
    #[must_use]
    pub(crate) const fn new(
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
        journal_identity: OwnershipJournalIdentity,
    ) -> Self {
        Self {
            boot_identity,
            network_namespace,
            journal_identity,
        }
    }

    #[must_use]
    fn from_journal(binding: &NativeXtablesJournalBinding) -> Self {
        Self {
            boot_identity: binding.boot_identity.clone(),
            network_namespace: binding.network_namespace,
            journal_identity: binding.journal_identity,
        }
    }

    #[must_use]
    pub(crate) const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub(crate) const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub(crate) const fn journal_identity(&self) -> OwnershipJournalIdentity {
        self.journal_identity
    }
}

impl NativeXtablesJournalBinding {
    #[must_use]
    pub(crate) const fn new(
        boot_identity: BootIdentity,
        network_namespace: NetworkNamespaceIdentity,
        generation: GenerationId,
        journal_identity: OwnershipJournalIdentity,
    ) -> Self {
        Self {
            boot_identity,
            network_namespace,
            generation,
            journal_identity,
        }
    }

    #[must_use]
    pub(crate) const fn boot_identity(&self) -> &BootIdentity {
        &self.boot_identity
    }

    #[must_use]
    pub(crate) const fn network_namespace(&self) -> NetworkNamespaceIdentity {
        self.network_namespace
    }

    #[must_use]
    pub(crate) const fn generation(&self) -> GenerationId {
        self.generation
    }

    #[must_use]
    pub(crate) const fn journal_identity(&self) -> OwnershipJournalIdentity {
        self.journal_identity
    }

    #[must_use]
    pub(crate) fn lease_scope(&self) -> NativeXtablesLeaseScope {
        NativeXtablesLeaseScope::from_journal(self)
    }
}

/// Exact phase durably published before one attempt-object mutation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesAttemptPhase {
    Reserved,
    PopulateSelectorIpv4,
    PopulateSelectorIpv6,
    PopulateObservationIpv4,
    PopulateObservationIpv6,
    Active,
    RetireObservationIpv4,
    RetireObservationIpv6,
    RetireSelectorIpv4,
    RetireSelectorIpv6,
}

impl NativeXtablesAttemptPhase {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::PopulateSelectorIpv4 => "populate_selector_ipv4",
            Self::PopulateSelectorIpv6 => "populate_selector_ipv6",
            Self::PopulateObservationIpv4 => "populate_observation_ipv4",
            Self::PopulateObservationIpv6 => "populate_observation_ipv6",
            Self::Active => "active",
            Self::RetireObservationIpv4 => "retire_observation_ipv4",
            Self::RetireObservationIpv6 => "retire_observation_ipv6",
            Self::RetireSelectorIpv4 => "retire_selector_ipv4",
            Self::RetireSelectorIpv6 => "retire_selector_ipv6",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "reserved" => Some(Self::Reserved),
            "populate_selector_ipv4" => Some(Self::PopulateSelectorIpv4),
            "populate_selector_ipv6" => Some(Self::PopulateSelectorIpv6),
            "populate_observation_ipv4" => Some(Self::PopulateObservationIpv4),
            "populate_observation_ipv6" => Some(Self::PopulateObservationIpv6),
            "active" => Some(Self::Active),
            "retire_observation_ipv4" => Some(Self::RetireObservationIpv4),
            "retire_observation_ipv6" => Some(Self::RetireObservationIpv6),
            "retire_selector_ipv4" => Some(Self::RetireSelectorIpv4),
            "retire_selector_ipv6" => Some(Self::RetireSelectorIpv6),
            _ => None,
        }
    }

    pub(crate) const fn rank(self) -> u8 {
        match self {
            Self::Reserved => 0,
            Self::PopulateSelectorIpv4 => 1,
            Self::PopulateSelectorIpv6 => 2,
            Self::PopulateObservationIpv4 => 3,
            Self::PopulateObservationIpv6 => 4,
            Self::Active => 5,
            Self::RetireObservationIpv4 => 6,
            Self::RetireObservationIpv6 => 7,
            Self::RetireSelectorIpv4 => 8,
            Self::RetireSelectorIpv6 => 9,
        }
    }

    const fn can_advance_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Reserved, Self::PopulateSelectorIpv4)
                | (
                    Self::PopulateSelectorIpv4,
                    Self::PopulateSelectorIpv6 | Self::PopulateObservationIpv4
                )
                | (Self::PopulateSelectorIpv6, Self::PopulateObservationIpv4)
                | (
                    Self::PopulateObservationIpv4,
                    Self::PopulateObservationIpv6 | Self::Active
                )
                | (Self::PopulateObservationIpv6, Self::Active)
                | (Self::Active, Self::RetireObservationIpv4)
                | (
                    Self::RetireObservationIpv4,
                    Self::RetireObservationIpv6 | Self::RetireSelectorIpv4
                )
                | (Self::RetireObservationIpv6, Self::RetireSelectorIpv4)
                | (Self::RetireSelectorIpv4, Self::RetireSelectorIpv6)
        )
    }

    const fn can_recover_to(self, next: Self) -> bool {
        matches!(next, Self::RetireObservationIpv4)
            && self.rank() < Self::RetireObservationIpv4.rank()
    }

    const fn permits_removal(self) -> bool {
        matches!(self, Self::RetireSelectorIpv4 | Self::RetireSelectorIpv6)
    }
}

/// Bounded canonical attempt identity encoded by the owner layer.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct NativeXtablesAttemptPayload(Box<[u8]>);

impl fmt::Debug for NativeXtablesAttemptPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeXtablesAttemptPayload")
            .field("len", &self.0.len())
            .finish()
    }
}

impl NativeXtablesAttemptPayload {
    pub(crate) fn new(bytes: impl Into<Box<[u8]>>) -> Result<Self, NativeXtablesDurableError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES {
            return Err(NativeXtablesDurableError::AttemptPayloadTooLarge {
                actual: bytes.len(),
                limit: MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One Generation-bound attempt sidecar. The primary owner journal remains unchanged while this
/// record advances independently under the same component lease and process-liveness guard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesAttemptRecord {
    binding: NativeXtablesJournalBinding,
    phase: NativeXtablesAttemptPhase,
    payload: NativeXtablesAttemptPayload,
}

impl NativeXtablesAttemptRecord {
    #[must_use]
    pub(crate) const fn new(
        binding: NativeXtablesJournalBinding,
        phase: NativeXtablesAttemptPhase,
        payload: NativeXtablesAttemptPayload,
    ) -> Self {
        Self {
            binding,
            phase,
            payload,
        }
    }

    #[must_use]
    pub(crate) const fn binding(&self) -> &NativeXtablesJournalBinding {
        &self.binding
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> NativeXtablesAttemptPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn payload(&self) -> &NativeXtablesAttemptPayload {
        &self.payload
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeXtablesJournalPhase {
    Activating,
    Active,
    Retiring,
    Uncertain,
    CleanAbsent,
}

impl NativeXtablesJournalPhase {
    const fn token(self) -> &'static str {
        match self {
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Retiring => "retiring",
            Self::Uncertain => "uncertain",
            Self::CleanAbsent => "clean_absent",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "activating" => Some(Self::Activating),
            "active" => Some(Self::Active),
            "retiring" => Some(Self::Retiring),
            "uncertain" => Some(Self::Uncertain),
            "clean_absent" => Some(Self::CleanAbsent),
            _ => None,
        }
    }

    const fn is_terminal(self) -> bool {
        matches!(self, Self::CleanAbsent)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesOwnerPayload(Box<[u8]>);

impl NativeXtablesOwnerPayload {
    pub(crate) fn new(bytes: impl Into<Box<[u8]>>) -> Result<Self, NativeXtablesDurableError> {
        let bytes = bytes.into();
        if bytes.len() > MAX_NATIVE_XTABLES_OWNER_PAYLOAD_BYTES {
            return Err(NativeXtablesDurableError::PayloadTooLarge {
                actual: bytes.len(),
                limit: MAX_NATIVE_XTABLES_OWNER_PAYLOAD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesJournalRecord {
    binding: NativeXtablesJournalBinding,
    revision: OwnershipJournalRevision,
    phase: NativeXtablesJournalPhase,
    owner_payload: NativeXtablesOwnerPayload,
}

/// Exact bytes and descriptor identity used to parse one durable journal record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesJournalObservation {
    record: NativeXtablesJournalRecord,
    file_device: u64,
    file_inode: NonZeroU64,
    digest: [u8; CHECKSUM_BYTES],
}

impl NativeXtablesJournalObservation {
    #[must_use]
    pub(crate) const fn record(&self) -> &NativeXtablesJournalRecord {
        &self.record
    }

    #[must_use]
    pub(crate) const fn file_device(&self) -> u64 {
        self.file_device
    }

    #[must_use]
    pub(crate) const fn file_inode(&self) -> NonZeroU64 {
        self.file_inode
    }

    #[must_use]
    pub(crate) const fn digest(&self) -> [u8; CHECKSUM_BYTES] {
        self.digest
    }
}

impl NativeXtablesJournalRecord {
    #[must_use]
    pub(crate) const fn new(
        binding: NativeXtablesJournalBinding,
        revision: OwnershipJournalRevision,
        phase: NativeXtablesJournalPhase,
        owner_payload: NativeXtablesOwnerPayload,
    ) -> Self {
        Self {
            binding,
            revision,
            phase,
            owner_payload,
        }
    }

    #[must_use]
    pub(crate) const fn binding(&self) -> &NativeXtablesJournalBinding {
        &self.binding
    }

    #[must_use]
    pub(crate) const fn revision(&self) -> OwnershipJournalRevision {
        self.revision
    }

    #[must_use]
    pub(crate) const fn phase(&self) -> NativeXtablesJournalPhase {
        self.phase
    }

    #[must_use]
    pub(crate) const fn owner_payload(&self) -> &NativeXtablesOwnerPayload {
        &self.owner_payload
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeXtablesDurableStore {
    root: PathBuf,
    #[cfg(test)]
    test_control: TestControl,
}

/// Stable identity of one descriptor-anchored durable root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesDurableRootIdentity {
    device: u64,
    inode: u64,
}

impl NativeXtablesDurableRootIdentity {
    #[must_use]
    pub(crate) const fn device(self) -> u64 {
        self.device
    }

    #[must_use]
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }
}

/// One strictly read-only, no-follow snapshot of native ownership artifacts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeXtablesDurableReadOnlyObservation {
    root_identity: Option<NativeXtablesDurableRootIdentity>,
    journal_present: bool,
    lease_present: bool,
    attempt_present: bool,
    writer_lock_present: bool,
    target_archive: Option<Box<[u8]>>,
}

impl NativeXtablesDurableReadOnlyObservation {
    #[must_use]
    pub(crate) const fn root_identity(&self) -> Option<NativeXtablesDurableRootIdentity> {
        self.root_identity
    }

    #[must_use]
    pub(crate) const fn journal_present(&self) -> bool {
        self.journal_present
    }

    #[must_use]
    pub(crate) const fn lease_present(&self) -> bool {
        self.lease_present
    }

    #[must_use]
    pub(crate) const fn attempt_present(&self) -> bool {
        self.attempt_present
    }

    #[must_use]
    pub(crate) const fn writer_lock_present(&self) -> bool {
        self.writer_lock_present
    }

    #[must_use]
    pub(crate) fn target_archive(&self) -> Option<&[u8]> {
        self.target_archive.as_deref()
    }
}

impl NativeXtablesDurableStore {
    #[must_use]
    pub(crate) fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_owned(),
            #[cfg(test)]
            test_control: TestControl::default(),
        }
    }

    #[must_use]
    pub(crate) fn journal_path(&self) -> PathBuf {
        self.root.join(NATIVE_XTABLES_JOURNAL_FILE_NAME)
    }

    #[must_use]
    pub(crate) fn lease_path(&self) -> PathBuf {
        self.root.join(NATIVE_XTABLES_LEASE_FILE_NAME)
    }

    #[must_use]
    pub(crate) fn attempt_path(&self) -> PathBuf {
        self.root.join(NATIVE_XTABLES_ATTEMPT_FILE_NAME)
    }

    #[must_use]
    pub(crate) fn writer_lock_path(&self) -> PathBuf {
        self.root.join(XTABLES_WRITER_LOCK_DIRECTORY_NAME)
    }

    #[must_use]
    pub(crate) fn target_archive_path(&self) -> PathBuf {
        self.root.join(NATIVE_XTABLES_TARGET_ARCHIVE_FILE_NAME)
    }

    /// Observes all ownership-bearing artifacts through one anchored root without creating,
    /// locking, parsing, renaming, or removing any path.
    pub(crate) fn observe_read_only(
        &self,
    ) -> Result<NativeXtablesDurableReadOnlyObservation, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(NativeXtablesDurableReadOnlyObservation {
                root_identity: None,
                journal_present: false,
                lease_present: false,
                attempt_present: false,
                writer_lock_present: false,
                target_archive: None,
            });
        };
        let metadata = root.metadata().map_err(|source| {
            NativeXtablesDurableError::io("inspect native xtables durable root", source)
        })?;
        let root_identity = Some(NativeXtablesDurableRootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        let journal_present = named_entry_exists(&root, NATIVE_XTABLES_JOURNAL_FILE_NAME)?;
        let lease_present = named_entry_exists(&root, NATIVE_XTABLES_LEASE_FILE_NAME)?;
        let attempt_present = named_entry_exists(&root, NATIVE_XTABLES_ATTEMPT_FILE_NAME)?;
        let writer_lock_present = named_entry_exists(&root, XTABLES_WRITER_LOCK_DIRECTORY_NAME)?;
        let target_archive = read_record_bounded(
            &root,
            NATIVE_XTABLES_TARGET_ARCHIVE_FILE_NAME,
            DurableArtifact::TargetArchive,
            MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES,
        )?
        .map(Vec::into_boxed_slice);
        Ok(NativeXtablesDurableReadOnlyObservation {
            root_identity,
            journal_present,
            lease_present,
            attempt_present,
            writer_lock_present,
            target_archive,
        })
    }

    pub(crate) fn load_target_archive(&self) -> Result<Option<Vec<u8>>, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(None);
        };
        read_record_bounded(
            &root,
            NATIVE_XTABLES_TARGET_ARCHIVE_FILE_NAME,
            DurableArtifact::TargetArchive,
            MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES,
        )
    }

    pub(crate) fn persist_target_archive(
        &self,
        encoded: &[u8],
    ) -> Result<(), NativeXtablesDurableError> {
        let root = open_root(&self.root, true)?.ok_or_else(|| {
            NativeXtablesDurableError::io(
                "create native xtables target-archive root",
                io::Error::from_raw_os_error(libc::ENOENT),
            )
        })?;
        atomic_write_bounded(
            &root,
            NATIVE_XTABLES_TARGET_ARCHIVE_FILE_NAME,
            encoded,
            DurableArtifact::TargetArchive,
            MAX_NATIVE_XTABLES_TARGET_ARCHIVE_BYTES,
            DurableEvent::TargetArchiveTempDurable,
            DurableEvent::TargetArchiveDurable,
            self,
        )
    }

    pub(crate) fn acquire_runtime_guard(
        &self,
    ) -> Result<NativeXtablesRuntimeGuard, NativeXtablesDurableError> {
        let root = open_root(&self.root, true)?.ok_or_else(|| {
            NativeXtablesDurableError::io(
                "create native xtables runtime-guard root",
                io::Error::from_raw_os_error(libc::ENOENT),
            )
        })?;
        acquire_advisory_guard(&root, RUNTIME_GUARD_SPEC)
            .map(|file| NativeXtablesRuntimeGuard { _file: file })
    }

    /// Publishes the activating journal and then the durable writer lease before returning any
    /// mutation authority. A returned error after lock acquisition deliberately leaves the lock
    /// directory in place when publication may have been interrupted.
    pub(crate) fn acquire(
        &self,
        initial: NativeXtablesJournalRecord,
    ) -> Result<NativeXtablesTransitionLease, NativeXtablesDurableError> {
        if initial.phase != NativeXtablesJournalPhase::Activating {
            return Err(NativeXtablesDurableError::InvalidInitialPhase(
                initial.phase,
            ));
        }
        let root = open_root(&self.root, true)?.ok_or_else(|| {
            NativeXtablesDurableError::io(
                "create native xtables durable root",
                io::Error::from_raw_os_error(libc::ENOENT),
            )
        })?;
        let lease_scope = initial.binding.lease_scope();
        let native_guard = match acquire_native_owner_guard(&root) {
            Ok(guard) => guard,
            Err(NativeXtablesDurableError::NativeOwnerBusy) => {
                return if read_lease(&root)?.is_some() {
                    Err(NativeXtablesDurableError::LeaseConflict)
                } else {
                    Err(NativeXtablesDurableError::NativeOwnerBusy)
                };
            }
            Err(error) => return Err(error),
        };
        let writer_lock = create_writer_lock(&root, &lease_scope, self)?;

        let existing_lease = read_lease(&root)?;
        if existing_lease.is_some() {
            remove_writer_lock(&root, writer_lock, self)?;
            return Err(NativeXtablesDurableError::LeaseConflict);
        }
        if let Some(existing) = read_journal(&root)?
            && !existing.phase.is_terminal()
        {
            return Err(NativeXtablesDurableError::UnresolvedJournal);
        }
        if read_attempt(&root)?.is_some() {
            return Err(NativeXtablesDurableError::OrphanedAttempt);
        }

        let encoded_journal = encode_journal(&initial);
        atomic_write(
            &root,
            NATIVE_XTABLES_JOURNAL_FILE_NAME,
            &encoded_journal,
            DurableEvent::JournalTempDurable,
            DurableEvent::JournalDurable,
            self,
        )?;
        checkpoint(self, DurableEvent::JournalBeforeLease)?;
        let encoded_lease = encode_lease(&lease_scope);
        atomic_write(
            &root,
            NATIVE_XTABLES_LEASE_FILE_NAME,
            &encoded_lease,
            DurableEvent::LeaseTempDurable,
            DurableEvent::LeaseDurable,
            self,
        )?;
        remove_writer_lock(&root, writer_lock, self)?;
        Ok(NativeXtablesTransitionLease {
            store: self.clone(),
            binding: initial.binding,
            lease_scope,
            _native_guard: native_guard,
        })
    }

    /// Reconstructs an exact lease for startup recovery. A pre-existing publication lock is
    /// adopted only when a complete matching journal+lease pair proves that the durable lease
    /// already blocks every competing writer. Partial publication stays blocked.
    pub(crate) fn recover(
        &self,
        expected: &NativeXtablesJournalBinding,
    ) -> Result<NativeXtablesRecovery, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(NativeXtablesRecovery::Empty);
        };
        let native_guard = acquire_native_owner_guard(&root)?;
        let lease_scope = expected.lease_scope();
        let (writer_lock, inherited_lock) =
            recover_or_create_writer_lock(&root, &lease_scope, self)?;

        let journal = read_journal(&root)?;
        let lease = read_lease(&root)?;
        let attempt = read_attempt(&root)?;
        match (journal, lease) {
            (None, None) if inherited_lock => {
                Err(NativeXtablesDurableError::InterruptedPublication)
            }
            (None, None) => {
                if attempt.is_some() {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                remove_writer_lock(&root, writer_lock, self)?;
                Ok(NativeXtablesRecovery::Empty)
            }
            (Some(journal), None) => {
                require_binding(expected, &journal.binding, DurableArtifact::Journal)?;
                if attempt.is_some() {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                if journal.phase.is_terminal() {
                    Ok(NativeXtablesRecovery::CleanAbsent {
                        record: journal.clone(),
                        fence: Box::new(NativeXtablesRecoveryFence {
                            store: self.clone(),
                            writer_lock,
                            retirement: Some(PreviousBootRetirement {
                                journal,
                                lease: None,
                                attempt: None,
                            }),
                            _native_guard: native_guard,
                        }),
                    })
                } else if inherited_lock {
                    Err(NativeXtablesDurableError::InterruptedPublication)
                } else {
                    Err(NativeXtablesDurableError::MissingLease)
                }
            }
            (None, Some(lease)) => {
                if attempt.is_some() {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                let result = require_lease_scope(&lease_scope, &lease)
                    .and(Err(NativeXtablesDurableError::MissingJournal));
                if !inherited_lock {
                    remove_writer_lock(&root, writer_lock, self)?;
                }
                result
            }
            (Some(journal), Some(lease)) => {
                let validation =
                    require_binding(expected, &journal.binding, DurableArtifact::Journal)
                        .and_then(|()| require_lease_scope(&lease_scope, &lease))
                        .and_then(|()| require_lease_scope(&journal.binding.lease_scope(), &lease));
                if let Err(error) = validation {
                    if !inherited_lock {
                        remove_writer_lock(&root, writer_lock, self)?;
                    }
                    return Err(error);
                }
                if let Some(attempt_record) = &attempt {
                    require_binding(
                        &journal.binding,
                        attempt_record.binding(),
                        DurableArtifact::Attempt,
                    )?;
                }
                if attempt.is_some() && journal.phase != NativeXtablesJournalPhase::Active {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                if journal.phase.is_terminal() {
                    Ok(NativeXtablesRecovery::CleanAbsent {
                        record: journal.clone(),
                        fence: Box::new(NativeXtablesRecoveryFence {
                            store: self.clone(),
                            writer_lock,
                            retirement: Some(PreviousBootRetirement {
                                journal,
                                lease: Some(lease),
                                attempt,
                            }),
                            _native_guard: native_guard,
                        }),
                    })
                } else {
                    remove_writer_lock(&root, writer_lock, self)?;
                    let lease = NativeXtablesTransitionLease {
                        store: self.clone(),
                        binding: expected.clone(),
                        lease_scope,
                        _native_guard: native_guard,
                    };
                    match attempt {
                        Some(record) => {
                            Ok(NativeXtablesRecovery::OutstandingAttempt { lease, record })
                        }
                        None => Ok(NativeXtablesRecovery::Leased(lease)),
                    }
                }
            }
        }
    }

    /// Serializes startup inspection even when no journal is present.
    ///
    /// `Vacant` is returned only while both the native advisory guard and the shared writer lock
    /// remain held. The caller must freshly prove xtables and policy-routing absence and then call
    /// [`NativeXtablesRecoveryFence::finish_clean`]. Dropping the fence without finishing retains
    /// the writer lock so failed or incomplete live-state inspection remains fail-closed.
    pub(crate) fn inspect_for_recovery(
        &self,
        current_scope: &NativeXtablesLeaseScope,
    ) -> Result<NativeXtablesRecoveryInspection, NativeXtablesDurableError> {
        let root = open_root(&self.root, true)?.ok_or_else(|| {
            NativeXtablesDurableError::io(
                "create native xtables durable root for recovery inspection",
                io::Error::from_raw_os_error(libc::ENOENT),
            )
        })?;
        let native_guard = acquire_native_owner_guard(&root)?;
        let (writer_lock, inherited_lock) =
            recover_or_create_writer_lock(&root, current_scope, self)?;
        let journal = read_journal(&root)?;
        let lease = read_lease(&root)?;
        let attempt = read_attempt(&root)?;

        match (journal, lease) {
            (None, None) => {
                if attempt.is_some() {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                Ok(NativeXtablesRecoveryInspection::Vacant(
                    NativeXtablesRecoveryFence {
                        store: self.clone(),
                        writer_lock,
                        retirement: None,
                        _native_guard: native_guard,
                    },
                ))
            }
            (None, Some(_)) => {
                if attempt.is_some() {
                    return Err(NativeXtablesDurableError::OrphanedAttempt);
                }
                Err(NativeXtablesDurableError::MissingJournal)
            }
            (Some(journal), lease) => {
                let recorded_scope = journal.binding.lease_scope();
                if let Some(attempt_record) = &attempt {
                    require_binding(
                        &journal.binding,
                        attempt_record.binding(),
                        DurableArtifact::Attempt,
                    )?;
                }
                if journal.binding.boot_identity == current_scope.boot_identity {
                    require_lease_scope(current_scope, &recorded_scope)?;
                    match &lease {
                        Some(lease) => require_lease_scope(&recorded_scope, lease)?,
                        None if !journal.phase.is_terminal() => {
                            return Err(NativeXtablesDurableError::MissingLease);
                        }
                        None => {}
                    }
                    if let Some(attempt) = attempt {
                        if journal.phase != NativeXtablesJournalPhase::Active {
                            return Err(NativeXtablesDurableError::OrphanedAttempt);
                        }
                        remove_writer_lock(&root, writer_lock, self)?;
                        return Ok(NativeXtablesRecoveryInspection::CurrentAttempt {
                            record: journal,
                            attempt,
                        });
                    }
                    if journal.phase.is_terminal() {
                        return Ok(NativeXtablesRecoveryInspection::CurrentTerminal {
                            record: journal.clone(),
                            fence: NativeXtablesRecoveryFence {
                                store: self.clone(),
                                writer_lock,
                                retirement: Some(PreviousBootRetirement {
                                    journal,
                                    lease,
                                    attempt: None,
                                }),
                                _native_guard: native_guard,
                            },
                        });
                    }
                    remove_writer_lock(&root, writer_lock, self)?;
                    Ok(NativeXtablesRecoveryInspection::CurrentJournal(journal))
                } else {
                    let inherited_recorded_lock = inherited_lock
                        && writer_lock.scope.boot_identity != current_scope.boot_identity;
                    if inherited_recorded_lock {
                        require_lease_scope(&recorded_scope, &writer_lock.scope)?;
                    }
                    match &lease {
                        Some(lease) => require_lease_scope(&recorded_scope, lease)?,
                        None if !(journal.phase.is_terminal()
                            || inherited_recorded_lock
                                && journal.phase == NativeXtablesJournalPhase::Activating
                                && journal.revision == OwnershipJournalRevision::INITIAL) =>
                        {
                            return Err(NativeXtablesDurableError::MissingLease);
                        }
                        None => {}
                    }
                    Ok(NativeXtablesRecoveryInspection::Vacant(
                        NativeXtablesRecoveryFence {
                            store: self.clone(),
                            writer_lock,
                            retirement: Some(PreviousBootRetirement {
                                journal,
                                lease,
                                attempt,
                            }),
                            _native_guard: native_guard,
                        },
                    ))
                }
            }
        }
    }

    pub(crate) fn load_journal(
        &self,
    ) -> Result<Option<NativeXtablesJournalRecord>, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(None);
        };
        read_journal(&root)
    }

    pub(crate) fn observe_journal(
        &self,
    ) -> Result<Option<NativeXtablesJournalObservation>, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(None);
        };
        read_journal_observation(&root)
    }

    pub(crate) fn load_lease(
        &self,
    ) -> Result<Option<NativeXtablesLeaseScope>, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(None);
        };
        read_lease(&root)
    }

    pub(crate) fn load_attempt(
        &self,
    ) -> Result<Option<NativeXtablesAttemptRecord>, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(None);
        };
        read_attempt(&root)
    }

    pub(crate) fn writer_lock_exists(&self) -> Result<bool, NativeXtablesDurableError> {
        let Some(root) = open_root(&self.root, false)? else {
            return Ok(false);
        };
        writer_lock_exists(&root)
    }

    #[cfg(test)]
    pub(crate) fn set_failpoint(&self, event: Option<DurableEvent>) {
        self.test_control.set_failpoint(event);
    }

    #[cfg(test)]
    pub(crate) fn pause_at(&self, event: DurableEvent) {
        self.test_control.pause_at(event);
    }

    #[cfg(test)]
    pub(crate) fn wait_until_paused(&self, event: DurableEvent) {
        self.test_control.wait_until_paused(event);
    }

    #[cfg(test)]
    pub(crate) fn release_pause(&self) {
        self.test_control.release_pause();
    }

    #[cfg(test)]
    fn take_events(&self) -> Vec<DurableEvent> {
        self.test_control.take_events()
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesRecovery {
    Empty,
    Leased(NativeXtablesTransitionLease),
    OutstandingAttempt {
        lease: NativeXtablesTransitionLease,
        record: NativeXtablesAttemptRecord,
    },
    CleanAbsent {
        record: NativeXtablesJournalRecord,
        fence: Box<NativeXtablesRecoveryFence>,
    },
}

#[derive(Debug)]
pub(crate) enum NativeXtablesRecoveryInspection {
    /// No durable owner artifacts remain, but live kernel absence still needs proof under `fence`.
    Vacant(NativeXtablesRecoveryFence),
    /// A current terminal journal still needs fresh global absence proof under `fence` before its
    /// durable artifacts and the shared writer boundary may be retired.
    CurrentTerminal {
        record: NativeXtablesJournalRecord,
        fence: NativeXtablesRecoveryFence,
    },
    /// A current durable journal exists and the caller must continue through exact journal recovery.
    CurrentJournal(NativeXtablesJournalRecord),
    /// A current active journal has an exact attempt that must be normalized before active state can
    /// be reported or another mutation can begin.
    CurrentAttempt {
        record: NativeXtablesJournalRecord,
        attempt: NativeXtablesAttemptRecord,
    },
}

#[derive(Debug)]
pub(crate) struct NativeXtablesRecoveryFence {
    store: NativeXtablesDurableStore,
    writer_lock: NativeWriterLock,
    retirement: Option<PreviousBootRetirement>,
    _native_guard: NativeOwnerGuard,
}

#[derive(Debug)]
struct PreviousBootRetirement {
    journal: NativeXtablesJournalRecord,
    lease: Option<NativeXtablesLeaseScope>,
    attempt: Option<NativeXtablesAttemptRecord>,
}

impl NativeXtablesRecoveryFence {
    /// Completes a read-only clean-absence proof by durably releasing the shared writer fence.
    pub(crate) fn finish_clean(self) -> Result<(), NativeXtablesDurableError> {
        let root = open_existing_root(&self.store.root)?;
        if let Some(retirement) = self.retirement {
            let terminal = if retirement.journal.phase.is_terminal() {
                retirement.journal
            } else {
                let revision = retirement
                    .journal
                    .revision
                    .get()
                    .checked_add(1)
                    .and_then(OwnershipJournalRevision::new)
                    .ok_or(NativeXtablesDurableError::RevisionExhausted)?;
                let terminal = NativeXtablesJournalRecord::new(
                    retirement.journal.binding,
                    revision,
                    NativeXtablesJournalPhase::CleanAbsent,
                    retirement.journal.owner_payload,
                );
                atomic_write(
                    &root,
                    NATIVE_XTABLES_JOURNAL_FILE_NAME,
                    &encode_journal(&terminal),
                    DurableEvent::JournalTempDurable,
                    DurableEvent::TerminalJournalDurable,
                    &self.store,
                )?;
                terminal
            };
            if let Some(attempt) = retirement.attempt {
                remove_attempt(&root, &attempt, &self.store)?;
            }
            if let Some(lease) = retirement.lease {
                remove_lease(&root, &lease, &self.store)?;
            }
            remove_journal(&root, &terminal, &self.store)?;
        }
        remove_writer_lock(&root, self.writer_lock, &self.store)
    }
}

#[derive(Debug)]
pub(crate) struct NativeXtablesTransitionLease {
    store: NativeXtablesDurableStore,
    binding: NativeXtablesJournalBinding,
    lease_scope: NativeXtablesLeaseScope,
    _native_guard: NativeOwnerGuard,
}

#[derive(Debug)]
pub(crate) struct NativeXtablesRuntimeGuard {
    _file: File,
}

impl NativeXtablesTransitionLease {
    #[must_use]
    pub(crate) const fn binding(&self) -> &NativeXtablesJournalBinding {
        &self.binding
    }

    /// Publishes one exact attempt sidecar without changing the primary owner journal.
    pub(crate) fn publish_attempt(
        &mut self,
        initial: NativeXtablesAttemptRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        if initial.phase != NativeXtablesAttemptPhase::Reserved {
            return Err(NativeXtablesDurableError::InvalidRecord {
                artifact: DurableArtifact::Attempt,
                reason: "initial attempt phase is not reserved",
            });
        }
        require_binding(&self.binding, &initial.binding, DurableArtifact::Attempt)?;
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        if let Err(error) = validate_primary_pair(&root, &self.binding, &self.lease_scope) {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        if read_attempt(&root)?.is_some() {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(NativeXtablesDurableError::AttemptConflict);
        }
        atomic_write_bounded(
            &root,
            NATIVE_XTABLES_ATTEMPT_FILE_NAME,
            &encode_attempt(&initial),
            DurableArtifact::Attempt,
            MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES,
            DurableEvent::AttemptTempDurable,
            DurableEvent::AttemptDurable,
            &self.store,
        )?;
        remove_writer_lock(&root, writer_lock, &self.store)
    }

    /// Advances the exact sidecar before the matching attempt-object mutation boundary.
    pub(crate) fn update_attempt(
        &mut self,
        current: &NativeXtablesAttemptRecord,
        next: NativeXtablesAttemptRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        require_binding(&self.binding, &current.binding, DurableArtifact::Attempt)?;
        require_binding(&self.binding, &next.binding, DurableArtifact::Attempt)?;
        if current.payload != next.payload || !current.phase.can_advance_to(next.phase) {
            return Err(NativeXtablesDurableError::InvalidRecord {
                artifact: DurableArtifact::Attempt,
                reason: "attempt update changed identity or is not an adjacent family-aware phase",
            });
        }
        self.replace_attempt(current, next)
    }

    /// Publishes the single permitted recovery jump before normalizing any attempt-owned chain.
    pub(crate) fn start_attempt_recovery(
        &mut self,
        current: &NativeXtablesAttemptRecord,
        next: NativeXtablesAttemptRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        require_binding(&self.binding, &current.binding, DurableArtifact::Attempt)?;
        require_binding(&self.binding, &next.binding, DurableArtifact::Attempt)?;
        if current.payload != next.payload || !current.phase.can_recover_to(next.phase) {
            return Err(NativeXtablesDurableError::InvalidRecord {
                artifact: DurableArtifact::Attempt,
                reason: "attempt recovery must preserve identity and enter retire_observation_ipv4",
            });
        }
        self.replace_attempt(current, next)
    }

    fn replace_attempt(
        &mut self,
        current: &NativeXtablesAttemptRecord,
        next: NativeXtablesAttemptRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        if let Err(error) = validate_primary_pair(&root, &self.binding, &self.lease_scope)
            .and_then(|()| require_exact_attempt(&root, current))
        {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        atomic_write_bounded(
            &root,
            NATIVE_XTABLES_ATTEMPT_FILE_NAME,
            &encode_attempt(&next),
            DurableArtifact::Attempt,
            MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES,
            DurableEvent::AttemptTempDurable,
            DurableEvent::AttemptDurable,
            &self.store,
        )?;
        remove_writer_lock(&root, writer_lock, &self.store)
    }

    /// Removes only the exact sidecar after the owner has proved all attempt objects absent.
    pub(crate) fn remove_attempt(
        &mut self,
        expected: &NativeXtablesAttemptRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        require_binding(&self.binding, &expected.binding, DurableArtifact::Attempt)?;
        if !expected.phase.permits_removal() {
            return Err(NativeXtablesDurableError::InvalidRecord {
                artifact: DurableArtifact::Attempt,
                reason: "attempt removal requires a completed selector-retirement phase",
            });
        }
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        if let Err(error) = validate_primary_pair(&root, &self.binding, &self.lease_scope)
            .and_then(|()| require_exact_attempt(&root, expected))
        {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        remove_attempt(&root, expected, &self.store)?;
        remove_writer_lock(&root, writer_lock, &self.store)
    }

    /// Atomically advances a nonterminal journal record while holding and revalidating the exact
    /// durable lease. Terminal publication must use `complete` so lease-release ordering cannot be
    /// bypassed.
    pub(crate) fn update(
        &mut self,
        next: NativeXtablesJournalRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        if next.phase.is_terminal() {
            return Err(NativeXtablesDurableError::TerminalUpdateRequiresCompletion);
        }
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        let result = require_attempt_absence(&root)
            .and_then(|()| validate_update(&root, &self.binding, &self.lease_scope, &next));
        if let Err(error) = result {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        let encoded = encode_journal(&next);
        atomic_write(
            &root,
            NATIVE_XTABLES_JOURNAL_FILE_NAME,
            &encoded,
            DurableEvent::JournalTempDurable,
            DurableEvent::JournalDurable,
            &self.store,
        )?;
        remove_writer_lock(&root, writer_lock, &self.store)
    }

    /// Atomically replaces the exact Generation-bound journal while retaining the component-scoped
    /// lease and the process-held native-owner guard. A crash therefore exposes either the old
    /// canonical journal or the replacement canonical journal, never a mixed lease binding.
    pub(crate) fn rebind(
        &mut self,
        replacement: NativeXtablesJournalRecord,
    ) -> Result<(), NativeXtablesDurableError> {
        validate_replacement_shape(&self.binding, &self.lease_scope, &replacement)?;
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        let result = require_attempt_absence(&root)
            .and_then(|()| validate_rebind(&root, &self.binding, &self.lease_scope, &replacement));
        if let Err(error) = result {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        let encoded = encode_journal(&replacement);
        atomic_write(
            &root,
            NATIVE_XTABLES_JOURNAL_FILE_NAME,
            &encoded,
            DurableEvent::JournalTempDurable,
            DurableEvent::JournalDurable,
            &self.store,
        )?;
        self.binding = replacement.binding;
        remove_writer_lock(&root, writer_lock, &self.store)
    }

    /// Durably publishes clean absence before deleting the writer lease. The transient writer lock
    /// remains after any interrupted boundary, keeping concurrent mutation blocked.
    pub(crate) fn complete(
        self,
        terminal: NativeXtablesJournalRecord,
    ) -> Result<NativeXtablesJournalRecord, NativeXtablesDurableError> {
        if !terminal.phase.is_terminal() {
            return Err(NativeXtablesDurableError::NonTerminalCompletion(
                terminal.phase,
            ));
        }
        let root = open_existing_root(&self.store.root)?;
        let writer_lock = create_writer_lock(&root, &self.lease_scope, &self.store)?;
        let result = require_attempt_absence(&root)
            .and_then(|()| validate_update(&root, &self.binding, &self.lease_scope, &terminal));
        if let Err(error) = result {
            remove_writer_lock(&root, writer_lock, &self.store)?;
            return Err(error);
        }
        let encoded = encode_journal(&terminal);
        atomic_write(
            &root,
            NATIVE_XTABLES_JOURNAL_FILE_NAME,
            &encoded,
            DurableEvent::JournalTempDurable,
            DurableEvent::TerminalJournalDurable,
            &self.store,
        )?;
        remove_lease(&root, &self.lease_scope, &self.store)?;
        remove_writer_lock(&root, writer_lock, &self.store)?;
        Ok(terminal)
    }
}

fn validate_update(
    root: &File,
    expected: &NativeXtablesJournalBinding,
    expected_scope: &NativeXtablesLeaseScope,
    next: &NativeXtablesJournalRecord,
) -> Result<(), NativeXtablesDurableError> {
    let lease = read_lease(root)?.ok_or(NativeXtablesDurableError::MissingLease)?;
    require_lease_scope(expected_scope, &lease)?;
    require_binding(expected, &next.binding, DurableArtifact::Journal)?;
    let current = read_journal(root)?.ok_or(NativeXtablesDurableError::MissingJournal)?;
    require_binding(expected, &current.binding, DurableArtifact::Journal)?;
    let expected_revision = current
        .revision
        .get()
        .checked_add(1)
        .and_then(OwnershipJournalRevision::new)
        .ok_or(NativeXtablesDurableError::RevisionExhausted)?;
    if next.revision != expected_revision {
        return Err(NativeXtablesDurableError::RevisionConflict {
            expected: expected_revision,
            actual: next.revision,
        });
    }
    Ok(())
}

fn validate_primary_pair(
    root: &File,
    expected: &NativeXtablesJournalBinding,
    expected_scope: &NativeXtablesLeaseScope,
) -> Result<(), NativeXtablesDurableError> {
    let lease = read_lease(root)?.ok_or(NativeXtablesDurableError::MissingLease)?;
    require_lease_scope(expected_scope, &lease)?;
    let journal = read_journal(root)?.ok_or(NativeXtablesDurableError::MissingJournal)?;
    require_binding(expected, &journal.binding, DurableArtifact::Journal)?;
    if journal.phase != NativeXtablesJournalPhase::Active {
        return Err(NativeXtablesDurableError::InvalidRecord {
            artifact: DurableArtifact::Journal,
            reason: "attempt sidecar requires an active primary journal",
        });
    }
    Ok(())
}

fn require_exact_attempt(
    root: &File,
    expected: &NativeXtablesAttemptRecord,
) -> Result<(), NativeXtablesDurableError> {
    let actual = read_attempt(root)?.ok_or(NativeXtablesDurableError::MissingAttempt)?;
    if actual == *expected {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::BindingMismatch {
            artifact: DurableArtifact::Attempt,
        })
    }
}

fn require_attempt_absence(root: &File) -> Result<(), NativeXtablesDurableError> {
    if read_attempt(root)?.is_none() {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::AttemptConflict)
    }
}

fn validate_replacement_shape(
    current: &NativeXtablesJournalBinding,
    lease_scope: &NativeXtablesLeaseScope,
    replacement: &NativeXtablesJournalRecord,
) -> Result<(), NativeXtablesDurableError> {
    if replacement.phase.is_terminal() {
        return Err(NativeXtablesDurableError::TerminalUpdateRequiresCompletion);
    }
    require_lease_scope(lease_scope, &replacement.binding.lease_scope())?;
    if replacement.binding.generation == current.generation {
        return Err(NativeXtablesDurableError::InvalidRebindIdentity);
    }
    Ok(())
}

fn validate_rebind(
    root: &File,
    current_binding: &NativeXtablesJournalBinding,
    lease_scope: &NativeXtablesLeaseScope,
    replacement: &NativeXtablesJournalRecord,
) -> Result<(), NativeXtablesDurableError> {
    let lease = read_lease(root)?.ok_or(NativeXtablesDurableError::MissingLease)?;
    require_lease_scope(lease_scope, &lease)?;
    let current = read_journal(root)?.ok_or(NativeXtablesDurableError::MissingJournal)?;
    require_binding(current_binding, &current.binding, DurableArtifact::Journal)?;
    validate_replacement_shape(current_binding, lease_scope, replacement)?;
    let expected_revision = current
        .revision
        .get()
        .checked_add(1)
        .and_then(OwnershipJournalRevision::new)
        .ok_or(NativeXtablesDurableError::RevisionExhausted)?;
    if replacement.revision != expected_revision {
        return Err(NativeXtablesDurableError::RevisionConflict {
            expected: expected_revision,
            actual: replacement.revision,
        });
    }
    Ok(())
}

fn require_binding(
    expected: &NativeXtablesJournalBinding,
    actual: &NativeXtablesJournalBinding,
    artifact: DurableArtifact,
) -> Result<(), NativeXtablesDurableError> {
    if expected == actual {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::BindingMismatch { artifact })
    }
}

fn require_lease_scope(
    expected: &NativeXtablesLeaseScope,
    actual: &NativeXtablesLeaseScope,
) -> Result<(), NativeXtablesDurableError> {
    if expected == actual {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::BindingMismatch {
            artifact: DurableArtifact::Lease,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableArtifact {
    Journal,
    Lease,
    Attempt,
    TargetArchive,
    WriterOwner,
}

impl fmt::Display for DurableArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal => formatter.write_str("journal"),
            Self::Lease => formatter.write_str("lease"),
            Self::Attempt => formatter.write_str("attempt sidecar"),
            Self::TargetArchive => formatter.write_str("target archive"),
            Self::WriterOwner => formatter.write_str("writer owner"),
        }
    }
}

#[derive(Debug)]
pub(crate) enum NativeXtablesDurableError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    UnsafePath(PathBuf),
    Symlink(PathBuf),
    UnexpectedFileType(PathBuf),
    RecordTooLarge {
        artifact: DurableArtifact,
        actual: usize,
        limit: usize,
    },
    PayloadTooLarge {
        actual: usize,
        limit: usize,
    },
    AttemptPayloadTooLarge {
        actual: usize,
        limit: usize,
    },
    InvalidRecord {
        artifact: DurableArtifact,
        reason: &'static str,
    },
    NativeOwnerBusy,
    NativeRuntimeBusy,
    LeaseConflict,
    UnresolvedJournal,
    InterruptedPublication,
    MissingJournal,
    MissingLease,
    AttemptConflict,
    OrphanedAttempt,
    MissingAttempt,
    BindingMismatch {
        artifact: DurableArtifact,
    },
    RevisionConflict {
        expected: OwnershipJournalRevision,
        actual: OwnershipJournalRevision,
    },
    RevisionExhausted,
    InvalidInitialPhase(NativeXtablesJournalPhase),
    InvalidRebindIdentity,
    TerminalUpdateRequiresCompletion,
    NonTerminalCompletion(NativeXtablesJournalPhase),
    InterruptedAt(DurableEvent),
}

impl NativeXtablesDurableError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for NativeXtablesDurableError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation} failed: {source}"),
            Self::UnsafePath(path) => {
                write!(
                    formatter,
                    "unsafe native xtables durable path {}",
                    path.display()
                )
            }
            Self::Symlink(path) => write!(
                formatter,
                "refusing symbolic-link native xtables durable path {}",
                path.display()
            ),
            Self::UnexpectedFileType(path) => write!(
                formatter,
                "native xtables durable path {} has an unexpected file type",
                path.display()
            ),
            Self::RecordTooLarge {
                artifact,
                actual,
                limit,
            } => write!(
                formatter,
                "native xtables {artifact} is {actual} bytes, exceeding {limit}-byte limit"
            ),
            Self::PayloadTooLarge { actual, limit } => write!(
                formatter,
                "native xtables owner payload is {actual} bytes, exceeding {limit}-byte limit"
            ),
            Self::AttemptPayloadTooLarge { actual, limit } => write!(
                formatter,
                "native xtables attempt payload is {actual} bytes, exceeding {limit}-byte limit"
            ),
            Self::InvalidRecord { artifact, reason } => {
                write!(formatter, "invalid native xtables {artifact}: {reason}")
            }
            Self::NativeOwnerBusy => formatter
                .write_str("another live native xtables owner holds the process-liveness guard"),
            Self::NativeRuntimeBusy => formatter.write_str(
                "another live native xtables runtime writer holds the archive transaction guard",
            ),
            Self::LeaseConflict => formatter.write_str("native xtables lease already exists"),
            Self::UnresolvedJournal => {
                formatter.write_str("nonterminal native xtables journal exists without a lease")
            }
            Self::InterruptedPublication => formatter.write_str(
                "native xtables writer lock records an interrupted or concurrent publication",
            ),
            Self::MissingJournal => {
                formatter.write_str("native xtables lease exists without its journal")
            }
            Self::MissingLease => {
                formatter.write_str("nonterminal native xtables journal has no matching lease")
            }
            Self::AttemptConflict => {
                formatter.write_str("a native xtables attempt sidecar already exists")
            }
            Self::OrphanedAttempt => formatter.write_str(
                "native xtables attempt sidecar has no matching active journal and lease",
            ),
            Self::MissingAttempt => {
                formatter.write_str("the expected native xtables attempt sidecar is missing")
            }
            Self::BindingMismatch { artifact } => write!(
                formatter,
                "native xtables {artifact} scope or exact journal binding is stale"
            ),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "native xtables journal revision must advance to {}, not {}",
                expected.get(),
                actual.get()
            ),
            Self::RevisionExhausted => {
                formatter.write_str("native xtables journal revision is exhausted")
            }
            Self::InvalidInitialPhase(phase) => write!(
                formatter,
                "native xtables acquisition requires activating phase, found {}",
                phase.token()
            ),
            Self::InvalidRebindIdentity => formatter
                .write_str("native xtables Generation rebind requires a distinct Generation"),
            Self::TerminalUpdateRequiresCompletion => formatter.write_str(
                "terminal native xtables journal publication must release through completion",
            ),
            Self::NonTerminalCompletion(phase) => write!(
                formatter,
                "native xtables completion requires clean_absent phase, found {}",
                phase.token()
            ),
            Self::InterruptedAt(event) => {
                write!(formatter, "injected interruption at {event:?}")
            }
        }
    }
}

impl Error for NativeXtablesDurableError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn encode_journal(record: &NativeXtablesJournalRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(512 + record.owner_payload.as_bytes().len() * 2);
    push_line(&mut encoded, JOURNAL_MAGIC);
    push_line(&mut encoded, &format!("component={COMPONENT_NAME}"));
    encode_binding_lines(&mut encoded, &record.binding);
    push_line(&mut encoded, &format!("revision={}", record.revision.get()));
    push_line(&mut encoded, &format!("phase={}", record.phase.token()));
    push_line(
        &mut encoded,
        &format!("payload_bytes={}", record.owner_payload.as_bytes().len()),
    );
    push_line(
        &mut encoded,
        &format!(
            "payload_hex={}",
            encode_hex(record.owner_payload.as_bytes())
        ),
    );
    append_checksum(&mut encoded);
    encoded
}

fn encode_lease(scope: &NativeXtablesLeaseScope) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(384);
    push_line(&mut encoded, LEASE_MAGIC);
    push_line(&mut encoded, &format!("component={COMPONENT_NAME}"));
    encode_scope_lines(&mut encoded, scope);
    append_checksum(&mut encoded);
    encoded
}

fn encode_attempt(record: &NativeXtablesAttemptRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(512 + record.payload.as_bytes().len() * 2);
    push_line(&mut encoded, ATTEMPT_MAGIC);
    push_line(&mut encoded, &format!("component={COMPONENT_NAME}"));
    encode_binding_lines(&mut encoded, &record.binding);
    push_line(&mut encoded, &format!("phase={}", record.phase.token()));
    push_line(
        &mut encoded,
        &format!("payload_bytes={}", record.payload.as_bytes().len()),
    );
    push_line(
        &mut encoded,
        &format!("payload_hex={}", encode_hex(record.payload.as_bytes())),
    );
    append_checksum(&mut encoded);
    encoded
}

fn encode_binding_lines(encoded: &mut Vec<u8>, binding: &NativeXtablesJournalBinding) {
    push_line(encoded, &format!("boot={}", binding.boot_identity.as_str()));
    push_line(
        encoded,
        &format!("netns_device={}", binding.network_namespace.device()),
    );
    push_line(
        encoded,
        &format!("netns_inode={}", binding.network_namespace.inode()),
    );
    push_line(encoded, &format!("generation={}", binding.generation.get()));
    push_line(
        encoded,
        &format!(
            "journal={}",
            encode_hex(binding.journal_identity.as_bytes())
        ),
    );
}

fn encode_scope_lines(encoded: &mut Vec<u8>, scope: &NativeXtablesLeaseScope) {
    push_line(encoded, &format!("boot={}", scope.boot_identity.as_str()));
    push_line(
        encoded,
        &format!("netns_device={}", scope.network_namespace.device()),
    );
    push_line(
        encoded,
        &format!("netns_inode={}", scope.network_namespace.inode()),
    );
    push_line(
        encoded,
        &format!("owner={}", encode_hex(scope.journal_identity.as_bytes())),
    );
}

fn encode_writer_owner(scope: &NativeXtablesLeaseScope) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(256);
    push_line(&mut encoded, WRITER_OWNER_MAGIC);
    push_line(&mut encoded, &format!("component={COMPONENT_NAME}"));
    encode_scope_lines(&mut encoded, scope);
    append_checksum(&mut encoded);
    encoded
}

fn append_checksum(encoded: &mut Vec<u8>) {
    let checksum = Sha256::digest(&*encoded);
    push_line(encoded, &format!("sha256={}", encode_hex(&checksum)));
}

fn push_line(encoded: &mut Vec<u8>, line: &str) {
    encoded.extend_from_slice(line.as_bytes());
    encoded.push(b'\n');
}

fn parse_journal(encoded: &[u8]) -> Result<NativeXtablesJournalRecord, NativeXtablesDurableError> {
    ensure_record_bound(encoded, DurableArtifact::Journal)?;
    let lines = canonical_lines(encoded, DurableArtifact::Journal, 12)?;
    if lines[0] != JOURNAL_MAGIC || lines[1] != format!("component={COMPONENT_NAME}") {
        return Err(invalid_record(
            DurableArtifact::Journal,
            "wrong schema or component",
        ));
    }
    validate_checksum(encoded, &lines, DurableArtifact::Journal)?;
    let binding = parse_binding(&lines[2..7], DurableArtifact::Journal)?;
    let revision = parse_nonzero_u64(field(lines[7], "revision", DurableArtifact::Journal)?)
        .and_then(OwnershipJournalRevision::new)
        .ok_or_else(|| invalid_record(DurableArtifact::Journal, "invalid revision"))?;
    let phase =
        NativeXtablesJournalPhase::parse(field(lines[8], "phase", DurableArtifact::Journal)?)
            .ok_or_else(|| invalid_record(DurableArtifact::Journal, "invalid phase"))?;
    let payload_len =
        parse_canonical_usize(field(lines[9], "payload_bytes", DurableArtifact::Journal)?)
            .ok_or_else(|| invalid_record(DurableArtifact::Journal, "invalid payload length"))?;
    if payload_len > MAX_NATIVE_XTABLES_OWNER_PAYLOAD_BYTES {
        return Err(NativeXtablesDurableError::PayloadTooLarge {
            actual: payload_len,
            limit: MAX_NATIVE_XTABLES_OWNER_PAYLOAD_BYTES,
        });
    }
    let payload = decode_hex(field(lines[10], "payload_hex", DurableArtifact::Journal)?)
        .ok_or_else(|| invalid_record(DurableArtifact::Journal, "invalid payload encoding"))?;
    if payload.len() != payload_len {
        return Err(invalid_record(
            DurableArtifact::Journal,
            "payload length does not match encoding",
        ));
    }
    let record = NativeXtablesJournalRecord::new(
        binding,
        revision,
        phase,
        NativeXtablesOwnerPayload::new(payload)?,
    );
    if encode_journal(&record) != encoded {
        return Err(invalid_record(
            DurableArtifact::Journal,
            "record is not canonical",
        ));
    }
    Ok(record)
}

fn parse_attempt(encoded: &[u8]) -> Result<NativeXtablesAttemptRecord, NativeXtablesDurableError> {
    ensure_record_bound(encoded, DurableArtifact::Attempt)?;
    let lines = canonical_lines(encoded, DurableArtifact::Attempt, 11)?;
    if lines[0] != ATTEMPT_MAGIC || lines[1] != format!("component={COMPONENT_NAME}") {
        return Err(invalid_record(
            DurableArtifact::Attempt,
            "wrong schema or component",
        ));
    }
    validate_checksum(encoded, &lines, DurableArtifact::Attempt)?;
    let binding = parse_binding(&lines[2..7], DurableArtifact::Attempt)?;
    let phase =
        NativeXtablesAttemptPhase::parse(field(lines[7], "phase", DurableArtifact::Attempt)?)
            .ok_or_else(|| invalid_record(DurableArtifact::Attempt, "invalid phase"))?;
    let payload_len =
        parse_canonical_usize(field(lines[8], "payload_bytes", DurableArtifact::Attempt)?)
            .ok_or_else(|| invalid_record(DurableArtifact::Attempt, "invalid payload length"))?;
    if payload_len > MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES {
        return Err(NativeXtablesDurableError::AttemptPayloadTooLarge {
            actual: payload_len,
            limit: MAX_NATIVE_XTABLES_ATTEMPT_PAYLOAD_BYTES,
        });
    }
    let payload = decode_hex(field(lines[9], "payload_hex", DurableArtifact::Attempt)?)
        .ok_or_else(|| invalid_record(DurableArtifact::Attempt, "invalid payload encoding"))?;
    if payload.len() != payload_len {
        return Err(invalid_record(
            DurableArtifact::Attempt,
            "payload length does not match encoding",
        ));
    }
    let record =
        NativeXtablesAttemptRecord::new(binding, phase, NativeXtablesAttemptPayload::new(payload)?);
    if encode_attempt(&record) != encoded {
        return Err(invalid_record(
            DurableArtifact::Attempt,
            "record is not canonical",
        ));
    }
    Ok(record)
}

fn parse_lease(encoded: &[u8]) -> Result<NativeXtablesLeaseScope, NativeXtablesDurableError> {
    ensure_record_bound(encoded, DurableArtifact::Lease)?;
    let lines = canonical_lines(encoded, DurableArtifact::Lease, 7)?;
    if lines[0] != LEASE_MAGIC || lines[1] != format!("component={COMPONENT_NAME}") {
        return Err(invalid_record(
            DurableArtifact::Lease,
            "wrong schema or component",
        ));
    }
    validate_checksum(encoded, &lines, DurableArtifact::Lease)?;
    let scope = parse_scope(&lines[2..6], DurableArtifact::Lease)?;
    if encode_lease(&scope) != encoded {
        return Err(invalid_record(
            DurableArtifact::Lease,
            "record is not canonical",
        ));
    }
    Ok(scope)
}

fn parse_writer_owner(
    encoded: &[u8],
) -> Result<NativeXtablesLeaseScope, NativeXtablesDurableError> {
    ensure_record_bound(encoded, DurableArtifact::WriterOwner)?;
    let lines = canonical_lines(encoded, DurableArtifact::WriterOwner, 7)?;
    if lines[0] != WRITER_OWNER_MAGIC || lines[1] != format!("component={COMPONENT_NAME}") {
        return Err(invalid_record(
            DurableArtifact::WriterOwner,
            "wrong schema or component",
        ));
    }
    validate_checksum(encoded, &lines, DurableArtifact::WriterOwner)?;
    let scope = parse_scope(&lines[2..6], DurableArtifact::WriterOwner)?;
    if encode_writer_owner(&scope) != encoded {
        return Err(invalid_record(
            DurableArtifact::WriterOwner,
            "record is not canonical",
        ));
    }
    Ok(scope)
}

fn parse_binding(
    lines: &[&str],
    artifact: DurableArtifact,
) -> Result<NativeXtablesJournalBinding, NativeXtablesDurableError> {
    if lines.len() != 5 {
        return Err(invalid_record(artifact, "wrong binding field count"));
    }
    let boot_text = field(lines[0], "boot", artifact)?;
    let boot_identity = BootIdentity::parse(boot_text)
        .map_err(|_| invalid_record(artifact, "invalid boot identity"))?;
    let device = parse_canonical_u64(field(lines[1], "netns_device", artifact)?)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace device"))?;
    let inode = parse_nonzero_u64(field(lines[2], "netns_inode", artifact)?)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace inode"))?;
    let network_namespace = NetworkNamespaceIdentity::new(device, inode)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace identity"))?;
    let generation = parse_nonzero_u64(field(lines[3], "generation", artifact)?)
        .and_then(|value| u32::try_from(value).ok())
        .and_then(GenerationId::new)
        .ok_or_else(|| invalid_record(artifact, "invalid generation"))?;
    let identity_bytes =
        decode_fixed_hex::<OWNERSHIP_JOURNAL_IDENTITY_BYTES>(field(lines[4], "journal", artifact)?)
            .ok_or_else(|| invalid_record(artifact, "invalid journal identity"))?;
    let journal_identity = OwnershipJournalIdentity::new(identity_bytes)
        .map_err(|_| invalid_record(artifact, "zero journal identity"))?;
    Ok(NativeXtablesJournalBinding::new(
        boot_identity,
        network_namespace,
        generation,
        journal_identity,
    ))
}

fn parse_scope(
    lines: &[&str],
    artifact: DurableArtifact,
) -> Result<NativeXtablesLeaseScope, NativeXtablesDurableError> {
    if lines.len() != 4 {
        return Err(invalid_record(artifact, "wrong scope field count"));
    }
    let boot_text = field(lines[0], "boot", artifact)?;
    let boot_identity = BootIdentity::parse(boot_text)
        .map_err(|_| invalid_record(artifact, "invalid boot identity"))?;
    let device = parse_canonical_u64(field(lines[1], "netns_device", artifact)?)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace device"))?;
    let inode = parse_nonzero_u64(field(lines[2], "netns_inode", artifact)?)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace inode"))?;
    let network_namespace = NetworkNamespaceIdentity::new(device, inode)
        .ok_or_else(|| invalid_record(artifact, "invalid namespace identity"))?;
    let identity_bytes =
        decode_fixed_hex::<OWNERSHIP_JOURNAL_IDENTITY_BYTES>(field(lines[3], "owner", artifact)?)
            .ok_or_else(|| invalid_record(artifact, "invalid owner identity"))?;
    let journal_identity = OwnershipJournalIdentity::new(identity_bytes)
        .map_err(|_| invalid_record(artifact, "zero owner identity"))?;
    Ok(NativeXtablesLeaseScope {
        boot_identity,
        network_namespace,
        journal_identity,
    })
}

fn canonical_lines(
    encoded: &[u8],
    artifact: DurableArtifact,
    expected: usize,
) -> Result<Vec<&str>, NativeXtablesDurableError> {
    let text = std::str::from_utf8(encoded)
        .map_err(|_| invalid_record(artifact, "record is not UTF-8"))?;
    if !text.ends_with('\n') || text.contains('\r') {
        return Err(invalid_record(
            artifact,
            "record is truncated or has noncanonical lines",
        ));
    }
    let lines = text[..text.len() - 1].split('\n').collect::<Vec<_>>();
    if lines.len() != expected || lines.iter().any(|line| line.is_empty()) {
        return Err(invalid_record(artifact, "wrong line count"));
    }
    Ok(lines)
}

fn validate_checksum(
    encoded: &[u8],
    lines: &[&str],
    artifact: DurableArtifact,
) -> Result<(), NativeXtablesDurableError> {
    let checksum_line = lines
        .last()
        .ok_or_else(|| invalid_record(artifact, "missing checksum"))?;
    let expected = decode_fixed_hex::<CHECKSUM_BYTES>(field(checksum_line, "sha256", artifact)?)
        .ok_or_else(|| invalid_record(artifact, "invalid checksum encoding"))?;
    let prefix_len = encoded
        .len()
        .checked_sub(checksum_line.len() + 1)
        .ok_or_else(|| invalid_record(artifact, "invalid checksum boundary"))?;
    let actual: [u8; CHECKSUM_BYTES] = Sha256::digest(&encoded[..prefix_len]).into();
    if actual == expected {
        Ok(())
    } else {
        Err(invalid_record(artifact, "checksum mismatch"))
    }
}

fn field<'a>(
    line: &'a str,
    name: &str,
    artifact: DurableArtifact,
) -> Result<&'a str, NativeXtablesDurableError> {
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .ok_or_else(|| invalid_record(artifact, "unexpected field"))
}

fn parse_nonzero_u64(value: &str) -> Option<u64> {
    parse_canonical_u64(value).filter(|value| *value != 0)
}

fn parse_canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fn parse_canonical_usize(value: &str) -> Option<usize> {
    parse_canonical_u64(value).and_then(|value| usize::try_from(value).ok())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Option<Box<[u8]>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        decoded.push((decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?);
    }
    Some(decoded.into_boxed_slice())
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (decode_nibble(pair[0])? << 4) | decode_nibble(pair[1])?;
    }
    Some(decoded)
}

const fn decode_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn ensure_record_bound(
    encoded: &[u8],
    artifact: DurableArtifact,
) -> Result<(), NativeXtablesDurableError> {
    ensure_record_bound_with_limit(encoded, artifact, MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES)
}

fn ensure_record_bound_with_limit(
    encoded: &[u8],
    artifact: DurableArtifact,
    maximum_bytes: usize,
) -> Result<(), NativeXtablesDurableError> {
    if encoded.len() > maximum_bytes {
        Err(NativeXtablesDurableError::RecordTooLarge {
            artifact,
            actual: encoded.len(),
            limit: maximum_bytes,
        })
    } else {
        Ok(())
    }
}

fn invalid_record(artifact: DurableArtifact, reason: &'static str) -> NativeXtablesDurableError {
    NativeXtablesDurableError::InvalidRecord { artifact, reason }
}

fn open_existing_root(path: &Path) -> Result<File, NativeXtablesDurableError> {
    open_root(path, false)?.ok_or_else(|| {
        NativeXtablesDurableError::io(
            "open native xtables durable root",
            io::Error::from_raw_os_error(libc::ENOENT),
        )
    })
}

fn open_root(path: &Path, create: bool) -> Result<Option<File>, NativeXtablesDurableError> {
    if path.as_os_str().is_empty() {
        return Err(NativeXtablesDurableError::UnsafePath(path.to_owned()));
    }
    let mut directory = File::open(if path.is_absolute() { "/" } else { "." })
        .map_err(|source| NativeXtablesDurableError::io("open durable path anchor", source))?;
    let mut traversed = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::from(".")
    };
    for component in path.components() {
        let Component::Normal(name) = component else {
            match component {
                Component::RootDir | Component::CurDir => continue,
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(NativeXtablesDurableError::UnsafePath(path.to_owned()));
                }
                Component::Normal(_) => unreachable!(),
            }
        };
        traversed.push(name);
        let name = c_string(name, &traversed)?;
        let descriptor = match open_at(
            directory.as_raw_fd(),
            &name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            None,
        ) {
            Ok(descriptor) => descriptor,
            Err(source) if source.raw_os_error() == Some(libc::ENOENT) && !create => {
                return Ok(None);
            }
            Err(source) if source.raw_os_error() == Some(libc::ENOENT) => {
                make_directory_at(directory.as_raw_fd(), &name, 0o700)?;
                directory.sync_all().map_err(|source| {
                    NativeXtablesDurableError::io("sync durable parent directory", source)
                })?;
                open_at(
                    directory.as_raw_fd(),
                    &name,
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                    None,
                )
                .map_err(|source| classify_path_error(&directory, &name, &traversed, source))?
            }
            Err(source) => {
                return Err(classify_path_error(&directory, &name, &traversed, source));
            }
        };
        // SAFETY: `openat` returned a new owned descriptor.
        directory = unsafe { File::from_raw_fd(descriptor) };
    }
    Ok(Some(directory))
}

fn classify_path_error(
    directory: &File,
    name: &CString,
    path: &Path,
    source: io::Error,
) -> NativeXtablesDurableError {
    if matches!(
        source.raw_os_error(),
        Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
    ) {
        match entry_kind(directory.as_raw_fd(), name) {
            Ok(Some(EntryKind::Symlink)) => {
                return NativeXtablesDurableError::Symlink(path.to_owned());
            }
            Ok(Some(_)) => {
                return NativeXtablesDurableError::UnexpectedFileType(path.to_owned());
            }
            Ok(None) | Err(_) => {}
        }
    }
    NativeXtablesDurableError::io("open native xtables durable path", source)
}

fn named_entry_exists(root: &File, name: &str) -> Result<bool, NativeXtablesDurableError> {
    let name = static_c_string(name);
    entry_kind(root.as_raw_fd(), &name)
        .map(|kind| kind.is_some())
        .map_err(|source| {
            NativeXtablesDurableError::io("inspect native xtables durable artifact", source)
        })
}

fn read_journal(
    root: &File,
) -> Result<Option<NativeXtablesJournalRecord>, NativeXtablesDurableError> {
    read_record(
        root,
        NATIVE_XTABLES_JOURNAL_FILE_NAME,
        DurableArtifact::Journal,
    )?
    .map(|encoded| parse_journal(&encoded))
    .transpose()
}

fn read_journal_observation(
    root: &File,
) -> Result<Option<NativeXtablesJournalObservation>, NativeXtablesDurableError> {
    let Some(observation) = read_record_bounded_observation(
        root,
        NATIVE_XTABLES_JOURNAL_FILE_NAME,
        DurableArtifact::Journal,
        MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES,
    )?
    else {
        return Ok(None);
    };
    let record = parse_journal(&observation.encoded)?;
    Ok(Some(NativeXtablesJournalObservation {
        record,
        file_device: observation.file_device,
        file_inode: observation.file_inode,
        digest: Sha256::digest(&observation.encoded).into(),
    }))
}

fn read_lease(root: &File) -> Result<Option<NativeXtablesLeaseScope>, NativeXtablesDurableError> {
    read_record(root, NATIVE_XTABLES_LEASE_FILE_NAME, DurableArtifact::Lease)?
        .map(|encoded| parse_lease(&encoded))
        .transpose()
}

fn read_attempt(
    root: &File,
) -> Result<Option<NativeXtablesAttemptRecord>, NativeXtablesDurableError> {
    read_record(
        root,
        NATIVE_XTABLES_ATTEMPT_FILE_NAME,
        DurableArtifact::Attempt,
    )?
    .map(|encoded| parse_attempt(&encoded))
    .transpose()
}

fn read_record(
    root: &File,
    name: &str,
    artifact: DurableArtifact,
) -> Result<Option<Vec<u8>>, NativeXtablesDurableError> {
    read_record_bounded(
        root,
        name,
        artifact,
        MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES,
    )
}

fn read_record_bounded(
    root: &File,
    name: &str,
    artifact: DurableArtifact,
    maximum_bytes: usize,
) -> Result<Option<Vec<u8>>, NativeXtablesDurableError> {
    read_record_bounded_observation(root, name, artifact, maximum_bytes)
        .map(|observation| observation.map(|observation| observation.encoded))
}

struct DurableRecordObservation {
    encoded: Vec<u8>,
    file_device: u64,
    file_inode: NonZeroU64,
}

fn read_record_bounded_observation(
    root: &File,
    name: &str,
    artifact: DurableArtifact,
    maximum_bytes: usize,
) -> Result<Option<DurableRecordObservation>, NativeXtablesDurableError> {
    let name = static_c_string(name);
    let path = durable_child_path(root, name.as_c_str());
    match entry_kind(root.as_raw_fd(), &name).map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables durable record", source)
    })? {
        None => return Ok(None),
        Some(EntryKind::Symlink) => return Err(NativeXtablesDurableError::Symlink(path)),
        Some(EntryKind::Regular) => {}
        Some(EntryKind::Directory | EntryKind::Other) => {
            return Err(NativeXtablesDurableError::UnexpectedFileType(path));
        }
    }
    let descriptor = open_at(
        root.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
        None,
    )
    .map_err(|source| {
        NativeXtablesDurableError::io("open native xtables durable record", source)
    })?;
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    require_regular_file(&file, &path)?;
    let metadata = file.metadata().map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables durable record", source)
    })?;
    let file_inode = NonZeroU64::new(metadata.ino())
        .ok_or_else(|| invalid_record(artifact, "record inode is zero"))?;
    let actual = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if actual > maximum_bytes {
        return Err(NativeXtablesDurableError::RecordTooLarge {
            artifact,
            actual,
            limit: maximum_bytes,
        });
    }
    let mut encoded = Vec::with_capacity(actual.min(512));
    file.take(
        u64::try_from(maximum_bytes)
            .expect("native durable record limit fits u64")
            .saturating_add(1),
    )
    .read_to_end(&mut encoded)
    .map_err(|source| {
        NativeXtablesDurableError::io("read native xtables durable record", source)
    })?;
    ensure_record_bound_with_limit(&encoded, artifact, maximum_bytes)?;
    Ok(Some(DurableRecordObservation {
        encoded,
        file_device: metadata.dev(),
        file_inode,
    }))
}

fn atomic_write(
    root: &File,
    target_name: &str,
    encoded: &[u8],
    temp_event: DurableEvent,
    published_event: DurableEvent,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    let artifact = if target_name == NATIVE_XTABLES_LEASE_FILE_NAME {
        DurableArtifact::Lease
    } else {
        DurableArtifact::Journal
    };
    atomic_write_bounded(
        root,
        target_name,
        encoded,
        artifact,
        MAX_NATIVE_XTABLES_DURABLE_RECORD_BYTES,
        temp_event,
        published_event,
        store,
    )
}

#[allow(clippy::too_many_arguments)]
fn atomic_write_bounded(
    root: &File,
    target_name: &str,
    encoded: &[u8],
    artifact: DurableArtifact,
    maximum_bytes: usize,
    temp_event: DurableEvent,
    published_event: DurableEvent,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    ensure_record_bound_with_limit(encoded, artifact, maximum_bytes)?;
    let target = static_c_string(target_name);
    reject_nonregular_target(root, &target)?;
    let (temporary, mut file) = create_temporary(root, target_name)?;
    let result = (|| {
        file.write_all(encoded).map_err(|source| {
            NativeXtablesDurableError::io("write native xtables durable record", source)
        })?;
        file.flush().map_err(|source| {
            NativeXtablesDurableError::io("flush native xtables durable record", source)
        })?;
        file.sync_all().map_err(|source| {
            NativeXtablesDurableError::io("sync native xtables durable record", source)
        })?;
        checkpoint(store, temp_event)?;
        reject_nonregular_target(root, &target)?;
        rename_at(root.as_raw_fd(), &temporary, &target)?;
        root.sync_all().map_err(|source| {
            NativeXtablesDurableError::io("sync native xtables durable directory", source)
        })?;
        checkpoint(store, published_event)
    })();
    if result.is_err() && !matches!(result, Err(NativeXtablesDurableError::InterruptedAt(_))) {
        let _ = unlink_at(root.as_raw_fd(), &temporary, 0);
    }
    result
}

fn create_temporary(
    root: &File,
    target_name: &str,
) -> Result<(CString, File), NativeXtablesDurableError> {
    for _ in 0..MAX_TEMP_CREATE_ATTEMPTS {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(".{target_name}.{}.{}.tmp", std::process::id(), id))
            .expect("generated durable temporary name contains no NUL");
        match open_at(
            root.as_raw_fd(),
            &name,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            Some(0o600),
        ) {
            Ok(descriptor) => {
                // SAFETY: `openat` returned a new owned descriptor.
                let file = unsafe { File::from_raw_fd(descriptor) };
                return Ok((name, file));
            }
            Err(source) if source.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(source) => {
                return Err(NativeXtablesDurableError::io(
                    "create native xtables durable temporary",
                    source,
                ));
            }
        }
    }
    Err(NativeXtablesDurableError::io(
        "create native xtables durable temporary",
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "temporary-name budget exhausted",
        ),
    ))
}

fn reject_nonregular_target(root: &File, name: &CString) -> Result<(), NativeXtablesDurableError> {
    let path = durable_child_path(root, name.as_c_str());
    match entry_kind(root.as_raw_fd(), name).map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables durable target", source)
    })? {
        None | Some(EntryKind::Regular) => Ok(()),
        Some(EntryKind::Symlink) => Err(NativeXtablesDurableError::Symlink(path)),
        Some(EntryKind::Directory | EntryKind::Other) => {
            Err(NativeXtablesDurableError::UnexpectedFileType(path))
        }
    }
}

#[derive(Debug)]
struct NativeOwnerGuard {
    _file: File,
}

#[derive(Debug)]
struct NativeWriterLock {
    directory: File,
    scope: NativeXtablesLeaseScope,
}

fn acquire_native_owner_guard(root: &File) -> Result<NativeOwnerGuard, NativeXtablesDurableError> {
    acquire_advisory_guard(root, OWNER_GUARD_SPEC).map(|file| NativeOwnerGuard { _file: file })
}

#[derive(Clone, Copy)]
struct AdvisoryGuardSpec {
    file_name: &'static str,
    inspect_operation: &'static str,
    open_operation: &'static str,
    create_operation: &'static str,
    sync_operation: &'static str,
    sync_directory_operation: &'static str,
    lock_operation: &'static str,
    busy_error: fn() -> NativeXtablesDurableError,
}

const OWNER_GUARD_SPEC: AdvisoryGuardSpec = AdvisoryGuardSpec {
    file_name: NATIVE_XTABLES_OWNER_GUARD_FILE_NAME,
    inspect_operation: "inspect native xtables owner guard",
    open_operation: "open native xtables owner guard",
    create_operation: "create native xtables owner guard",
    sync_operation: "sync native xtables owner guard",
    sync_directory_operation: "sync native xtables owner-guard directory",
    lock_operation: "lock native xtables owner guard",
    busy_error: || NativeXtablesDurableError::NativeOwnerBusy,
};

const RUNTIME_GUARD_SPEC: AdvisoryGuardSpec = AdvisoryGuardSpec {
    file_name: NATIVE_XTABLES_RUNTIME_GUARD_FILE_NAME,
    inspect_operation: "inspect native xtables runtime guard",
    open_operation: "open native xtables runtime guard",
    create_operation: "create native xtables runtime guard",
    sync_operation: "sync native xtables runtime guard",
    sync_directory_operation: "sync native xtables runtime-guard directory",
    lock_operation: "lock native xtables runtime guard",
    busy_error: || NativeXtablesDurableError::NativeRuntimeBusy,
};

fn acquire_advisory_guard(
    root: &File,
    spec: AdvisoryGuardSpec,
) -> Result<File, NativeXtablesDurableError> {
    let name = static_c_string(spec.file_name);
    let path = durable_child_path(root, name.as_c_str());
    let (descriptor, created) = loop {
        match entry_kind(root.as_raw_fd(), &name)
            .map_err(|source| NativeXtablesDurableError::io(spec.inspect_operation, source))?
        {
            Some(EntryKind::Symlink) => return Err(NativeXtablesDurableError::Symlink(path)),
            Some(EntryKind::Directory | EntryKind::Other) => {
                return Err(NativeXtablesDurableError::UnexpectedFileType(path));
            }
            Some(EntryKind::Regular) => {
                let descriptor = open_at(
                    root.as_raw_fd(),
                    &name,
                    libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    None,
                )
                .map_err(|source| NativeXtablesDurableError::io(spec.open_operation, source))?;
                break (descriptor, false);
            }
            None => match open_at(
                root.as_raw_fd(),
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                Some(0o600),
            ) {
                Ok(descriptor) => break (descriptor, true),
                Err(source) if source.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(source) => {
                    return Err(NativeXtablesDurableError::io(spec.create_operation, source));
                }
            },
        }
    };
    // SAFETY: `openat` returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    require_regular_file(&file, &path)?;
    let deadline = Instant::now() + NATIVE_OWNER_GUARD_ACQUIRE_TIMEOUT;
    loop {
        match try_lock_exclusive(&file) {
            Ok(()) => break,
            Err(source) if is_lock_busy(&source) && Instant::now() < deadline => {
                // `flock` follows an open file description across `fork`. An unrelated child
                // spawned by another thread can therefore retain a just-released guard for the
                // short pre-exec window even though the descriptor is CLOEXEC. Bounded retry
                // absorbs only that transient; a live owner still returns Busy at the deadline.
                std::thread::sleep(NATIVE_OWNER_GUARD_RETRY_INTERVAL);
            }
            Err(source) if is_lock_busy(&source) => return Err((spec.busy_error)()),
            Err(source) => {
                return Err(NativeXtablesDurableError::io(spec.lock_operation, source));
            }
        }
    }
    if created {
        file.sync_all()
            .map_err(|source| NativeXtablesDurableError::io(spec.sync_operation, source))?;
        root.sync_all().map_err(|source| {
            NativeXtablesDurableError::io(spec.sync_directory_operation, source)
        })?;
    }
    Ok(file)
}

fn try_lock_exclusive(file: &File) -> io::Result<()> {
    // SAFETY: `file` owns a valid descriptor for the duration of this call.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn is_lock_busy(source: &io::Error) -> bool {
    matches!(source.raw_os_error(), Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK)
}

fn create_writer_lock(
    root: &File,
    scope: &NativeXtablesLeaseScope,
    store: &NativeXtablesDurableStore,
) -> Result<NativeWriterLock, NativeXtablesDurableError> {
    let name = static_c_string(XTABLES_WRITER_LOCK_DIRECTORY_NAME);
    match make_directory_at(root.as_raw_fd(), &name, 0o700) {
        Ok(()) => {}
        Err(NativeXtablesDurableError::Io { source, .. })
            if source.raw_os_error() == Some(libc::EEXIST) =>
        {
            return match entry_kind(root.as_raw_fd(), &name).map_err(|source| {
                NativeXtablesDurableError::io("inspect native xtables writer lock", source)
            })? {
                Some(EntryKind::Directory) => {
                    Err(NativeXtablesDurableError::InterruptedPublication)
                }
                Some(EntryKind::Symlink) => Err(NativeXtablesDurableError::Symlink(
                    durable_child_path(root, name.as_c_str()),
                )),
                Some(EntryKind::Regular | EntryKind::Other) | None => {
                    Err(NativeXtablesDurableError::UnexpectedFileType(
                        durable_child_path(root, name.as_c_str()),
                    ))
                }
            };
        }
        Err(error) => return Err(error),
    }
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer-lock parent", source)
    })?;
    let directory = open_writer_lock_directory(root)?;
    let owner_name = static_c_string(NATIVE_XTABLES_WRITER_OWNER_FILE_NAME);
    let descriptor = open_at(
        directory.as_raw_fd(),
        &owner_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        Some(0o600),
    )
    .map_err(|source| {
        NativeXtablesDurableError::io("create native xtables writer owner", source)
    })?;
    // SAFETY: `openat` returned a new owned descriptor.
    let mut owner_file = unsafe { File::from_raw_fd(descriptor) };
    owner_file
        .write_all(&encode_writer_owner(scope))
        .map_err(|source| {
            NativeXtablesDurableError::io("write native xtables writer owner", source)
        })?;
    owner_file.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer owner", source)
    })?;
    directory.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer-lock directory", source)
    })?;
    checkpoint(store, DurableEvent::WriterLockDurable)?;
    Ok(NativeWriterLock {
        directory,
        scope: scope.clone(),
    })
}

fn recover_or_create_writer_lock(
    root: &File,
    expected: &NativeXtablesLeaseScope,
    store: &NativeXtablesDurableStore,
) -> Result<(NativeWriterLock, bool), NativeXtablesDurableError> {
    if !writer_lock_exists(root)? {
        return create_writer_lock(root, expected, store).map(|lock| (lock, false));
    }
    let directory = open_writer_lock_directory(root)?;
    let encoded = read_record(
        &directory,
        NATIVE_XTABLES_WRITER_OWNER_FILE_NAME,
        DurableArtifact::WriterOwner,
    )?
    .ok_or(NativeXtablesDurableError::InterruptedPublication)?;
    require_exact_native_writer_directory(&directory)?;
    let scope = parse_writer_owner(&encoded)?;
    if scope.boot_identity == expected.boot_identity {
        require_lease_scope(expected, &scope)?;
    }
    Ok((NativeWriterLock { directory, scope }, true))
}

fn open_writer_lock_directory(root: &File) -> Result<File, NativeXtablesDurableError> {
    let name = static_c_string(XTABLES_WRITER_LOCK_DIRECTORY_NAME);
    let path = durable_child_path(root, name.as_c_str());
    let descriptor = open_at(
        root.as_raw_fd(),
        &name,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        None,
    )
    .map_err(|source| classify_path_error(root, &name, &path, source))?;
    // SAFETY: `openat` returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn remove_writer_lock(
    root: &File,
    writer_lock: NativeWriterLock,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    let name = static_c_string(XTABLES_WRITER_LOCK_DIRECTORY_NAME);
    match entry_kind(root.as_raw_fd(), &name).map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables writer lock", source)
    })? {
        Some(EntryKind::Directory) => {}
        Some(EntryKind::Symlink) => {
            return Err(NativeXtablesDurableError::Symlink(durable_child_path(
                root,
                name.as_c_str(),
            )));
        }
        Some(EntryKind::Regular | EntryKind::Other) => {
            return Err(NativeXtablesDurableError::UnexpectedFileType(
                durable_child_path(root, name.as_c_str()),
            ));
        }
        None => return Err(NativeXtablesDurableError::InterruptedPublication),
    }
    let encoded = read_record(
        &writer_lock.directory,
        NATIVE_XTABLES_WRITER_OWNER_FILE_NAME,
        DurableArtifact::WriterOwner,
    )?
    .ok_or(NativeXtablesDurableError::InterruptedPublication)?;
    let actual_scope = parse_writer_owner(&encoded)?;
    require_lease_scope(&writer_lock.scope, &actual_scope)?;
    require_exact_native_writer_directory(&writer_lock.directory)?;
    require_same_entry(root, &name, &writer_lock.directory)?;

    let tombstone = unique_writer_lock_tombstone(root)?;
    rename_at(root.as_raw_fd(), &name, &tombstone)?;
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer-lock removal", source)
    })?;
    let owner_name = static_c_string(NATIVE_XTABLES_WRITER_OWNER_FILE_NAME);
    unlink_at(writer_lock.directory.as_raw_fd(), &owner_name, 0).map_err(|source| {
        NativeXtablesDurableError::io("remove native xtables writer owner", source)
    })?;
    writer_lock.directory.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer-owner removal", source)
    })?;
    unlink_at(root.as_raw_fd(), &tombstone, libc::AT_REMOVEDIR).map_err(|source| {
        NativeXtablesDurableError::io("remove native xtables writer-lock tombstone", source)
    })?;
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables writer-lock tombstone removal", source)
    })?;
    checkpoint(store, DurableEvent::WriterLockReleased)
}

fn require_exact_native_writer_directory(
    directory: &File,
) -> Result<(), NativeXtablesDurableError> {
    let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    let entries = std::fs::read_dir(path).map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables writer-lock directory", source)
    })?;
    let mut owner_seen = false;
    for entry in entries {
        let entry = entry.map_err(|source| {
            NativeXtablesDurableError::io("inspect native xtables writer-lock entry", source)
        })?;
        if entry.file_name().as_bytes() == NATIVE_XTABLES_WRITER_OWNER_FILE_NAME.as_bytes()
            && !owner_seen
        {
            owner_seen = true;
        } else {
            return Err(NativeXtablesDurableError::InterruptedPublication);
        }
    }
    if owner_seen {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::InterruptedPublication)
    }
}

fn unique_writer_lock_tombstone(root: &File) -> Result<CString, NativeXtablesDurableError> {
    for _ in 0..MAX_TEMP_CREATE_ATTEMPTS {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(
            ".{XTABLES_WRITER_LOCK_DIRECTORY_NAME}.{}.{}.released",
            std::process::id(),
            id
        ))
        .expect("generated writer-lock tombstone contains no NUL");
        if entry_kind(root.as_raw_fd(), &name)
            .map_err(|source| {
                NativeXtablesDurableError::io("inspect writer-lock tombstone", source)
            })?
            .is_none()
        {
            return Ok(name);
        }
    }
    Err(NativeXtablesDurableError::io(
        "allocate native xtables writer-lock tombstone",
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "writer-lock tombstone-name budget exhausted",
        ),
    ))
}

fn require_same_entry(
    root: &File,
    name: &CString,
    opened: &File,
) -> Result<(), NativeXtablesDurableError> {
    let opened = opened.metadata().map_err(|source| {
        NativeXtablesDurableError::io("inspect opened native xtables writer lock", source)
    })?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated, `root` is an open directory, and `stat` is writable.
    if unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(NativeXtablesDurableError::io(
            "revalidate native xtables writer lock",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: successful `fstatat` initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    use std::os::unix::fs::MetadataExt;
    if opened.dev() == stat.st_dev && opened.ino() == stat.st_ino {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::InterruptedPublication)
    }
}

fn writer_lock_exists(root: &File) -> Result<bool, NativeXtablesDurableError> {
    let name = static_c_string(XTABLES_WRITER_LOCK_DIRECTORY_NAME);
    match entry_kind(root.as_raw_fd(), &name).map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables writer lock", source)
    })? {
        None => Ok(false),
        Some(EntryKind::Directory) => Ok(true),
        Some(EntryKind::Symlink) => Err(NativeXtablesDurableError::Symlink(durable_child_path(
            root,
            name.as_c_str(),
        ))),
        Some(EntryKind::Regular | EntryKind::Other) => {
            Err(NativeXtablesDurableError::UnexpectedFileType(
                durable_child_path(root, name.as_c_str()),
            ))
        }
    }
}

fn remove_lease(
    root: &File,
    expected: &NativeXtablesLeaseScope,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    let lease = read_lease(root)?.ok_or(NativeXtablesDurableError::MissingLease)?;
    require_lease_scope(expected, &lease)?;
    let name = static_c_string(NATIVE_XTABLES_LEASE_FILE_NAME);
    unlink_at(root.as_raw_fd(), &name, 0)
        .map_err(|source| NativeXtablesDurableError::io("remove native xtables lease", source))?;
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables lease removal", source)
    })?;
    checkpoint(store, DurableEvent::LeaseRemovedDurable)
}

fn remove_attempt(
    root: &File,
    expected: &NativeXtablesAttemptRecord,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    require_exact_attempt(root, expected)?;
    let name = static_c_string(NATIVE_XTABLES_ATTEMPT_FILE_NAME);
    unlink_at(root.as_raw_fd(), &name, 0).map_err(|source| {
        NativeXtablesDurableError::io("remove native xtables attempt sidecar", source)
    })?;
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables attempt sidecar removal", source)
    })?;
    checkpoint(store, DurableEvent::AttemptRemovedDurable)
}

fn remove_journal(
    root: &File,
    expected: &NativeXtablesJournalRecord,
    store: &NativeXtablesDurableStore,
) -> Result<(), NativeXtablesDurableError> {
    let journal = read_journal(root)?.ok_or(NativeXtablesDurableError::MissingJournal)?;
    if &journal != expected {
        return Err(NativeXtablesDurableError::BindingMismatch {
            artifact: DurableArtifact::Journal,
        });
    }
    let name = static_c_string(NATIVE_XTABLES_JOURNAL_FILE_NAME);
    unlink_at(root.as_raw_fd(), &name, 0)
        .map_err(|source| NativeXtablesDurableError::io("remove native xtables journal", source))?;
    root.sync_all().map_err(|source| {
        NativeXtablesDurableError::io("sync native xtables journal removal", source)
    })?;
    checkpoint(store, DurableEvent::JournalRemovedDurable)
}

fn require_regular_file(file: &File, path: &Path) -> Result<(), NativeXtablesDurableError> {
    let metadata = file.metadata().map_err(|source| {
        NativeXtablesDurableError::io("inspect native xtables durable record", source)
    })?;
    if metadata.is_file() {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::UnexpectedFileType(
            path.to_owned(),
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

fn entry_kind(directory: RawFd, name: &CString) -> io::Result<Option<EntryKind>> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `name` is NUL-terminated, `directory` is an open directory descriptor, and `stat`
    // points to enough writable storage for `fstatat`.
    let result = unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the complete structure.
        let stat = unsafe { stat.assume_init() };
        let kind = match stat.st_mode & libc::S_IFMT {
            libc::S_IFREG => EntryKind::Regular,
            libc::S_IFDIR => EntryKind::Directory,
            libc::S_IFLNK => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        Ok(Some(kind))
    } else {
        let source = io::Error::last_os_error();
        if source.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(source)
        }
    }
}

fn open_at(
    directory: RawFd,
    name: &CString,
    flags: libc::c_int,
    mode: Option<libc::mode_t>,
) -> io::Result<RawFd> {
    // SAFETY: `name` is NUL-terminated, `directory` is open, and `mode` is supplied exactly for
    // calls that include `O_CREAT`.
    let descriptor = unsafe {
        match mode {
            Some(mode) => libc::openat(directory, name.as_ptr(), flags, mode),
            None => libc::openat(directory, name.as_ptr(), flags),
        }
    };
    if descriptor >= 0 {
        Ok(descriptor)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn make_directory_at(
    directory: RawFd,
    name: &CString,
    mode: libc::mode_t,
) -> Result<(), NativeXtablesDurableError> {
    // SAFETY: `name` is NUL-terminated and `directory` is an open directory descriptor.
    if unsafe { libc::mkdirat(directory, name.as_ptr(), mode) } == 0 {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::io(
            "create native xtables durable directory",
            io::Error::last_os_error(),
        ))
    }
}

fn rename_at(
    directory: RawFd,
    source: &CString,
    target: &CString,
) -> Result<(), NativeXtablesDurableError> {
    // SAFETY: both names are NUL-terminated and relative to the same open directory descriptor.
    if unsafe { libc::renameat(directory, source.as_ptr(), directory, target.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(NativeXtablesDurableError::io(
            "publish native xtables durable record",
            io::Error::last_os_error(),
        ))
    }
}

fn unlink_at(directory: RawFd, name: &CString, flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated and `directory` is an open directory descriptor.
    if unsafe { libc::unlinkat(directory, name.as_ptr(), flags) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn c_string(name: &OsStr, path: &Path) -> Result<CString, NativeXtablesDurableError> {
    CString::new(name.as_bytes())
        .map_err(|_| NativeXtablesDurableError::UnsafePath(path.to_owned()))
}

fn static_c_string(name: &str) -> CString {
    CString::new(name).expect("static durable entry name contains no NUL")
}

fn durable_child_path(_root: &File, name: &std::ffi::CStr) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(name.to_bytes()).into_owned())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableEvent {
    WriterLockDurable,
    TargetArchiveTempDurable,
    TargetArchiveDurable,
    AttemptTempDurable,
    AttemptDurable,
    AttemptRemovedDurable,
    JournalTempDurable,
    JournalDurable,
    JournalBeforeLease,
    LeaseTempDurable,
    LeaseDurable,
    TerminalJournalDurable,
    LeaseRemovedDurable,
    JournalRemovedDurable,
    WriterLockReleased,
}

#[cfg(test)]
fn checkpoint(
    store: &NativeXtablesDurableStore,
    event: DurableEvent,
) -> Result<(), NativeXtablesDurableError> {
    store.test_control.checkpoint(event)
}

#[cfg(not(test))]
fn checkpoint(
    store: &NativeXtablesDurableStore,
    event: DurableEvent,
) -> Result<(), NativeXtablesDurableError> {
    let _ = (store, event);
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct TestControl {
    inner: std::sync::Arc<TestControlInner>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestControlInner {
    state: std::sync::Mutex<TestState>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestState {
    failpoint: Option<DurableEvent>,
    pausepoint: Option<DurableEvent>,
    paused: Option<DurableEvent>,
    pause_released: bool,
    events: Vec<DurableEvent>,
}

#[cfg(test)]
impl TestControl {
    fn checkpoint(&self, event: DurableEvent) -> Result<(), NativeXtablesDurableError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("test durability control poisoned");
        state.events.push(event);
        if state.pausepoint == Some(event) {
            state.paused = Some(event);
            self.inner.changed.notify_all();
            while !state.pause_released {
                state = self
                    .inner
                    .changed
                    .wait(state)
                    .expect("test durability control poisoned while paused");
            }
            state.pausepoint = None;
            state.paused = None;
            state.pause_released = false;
        }
        if state.failpoint == Some(event) {
            state.failpoint = None;
            Err(NativeXtablesDurableError::InterruptedAt(event))
        } else {
            Ok(())
        }
    }

    fn set_failpoint(&self, event: Option<DurableEvent>) {
        self.inner
            .state
            .lock()
            .expect("test durability control poisoned")
            .failpoint = event;
    }

    fn pause_at(&self, event: DurableEvent) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("test durability control poisoned");
        state.pausepoint = Some(event);
        state.paused = None;
        state.pause_released = false;
    }

    fn wait_until_paused(&self, event: DurableEvent) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut state = self
            .inner
            .state
            .lock()
            .expect("test durability control poisoned");
        while state.paused != Some(event) {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("timed out waiting for durability pausepoint");
            let (next, timeout) = self
                .inner
                .changed
                .wait_timeout(state, remaining)
                .expect("test durability control poisoned while waiting");
            state = next;
            assert!(
                !timeout.timed_out() || state.paused == Some(event),
                "timed out waiting for durability pausepoint {event:?}"
            );
        }
    }

    fn release_pause(&self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("test durability control poisoned");
        state.pause_released = true;
        self.inner.changed.notify_all();
    }

    fn take_events(&self) -> Vec<DurableEvent> {
        std::mem::take(
            &mut self
                .inner
                .state
                .lock()
                .expect("test durability control poisoned")
                .events,
        )
    }
}

#[cfg(test)]
#[path = "owner_durable_tests.rs"]
mod tests;
