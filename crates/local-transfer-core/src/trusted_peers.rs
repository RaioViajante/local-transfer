//! Durable trusted-peer records and their filesystem persistence boundary.
//!
//! This module owns only the *durable* side of the trusted-peer model in
//! `docs/trust.md`: the minimum record that recognises a previously
//! authenticated and explicitly trusted cryptographic peer identity across a
//! restart, and a small versioned, bounded store for those records.
//!
//! It does **not** establish trust. There is no public way to construct a
//! [`TrustedPeerRecord`] or call [`TrustedPeerStore::store`]; a record is only
//! ever produced in-crate by the completed verified-pairing transition (a later
//! issue) or reconstructed by validating a record this store previously wrote.
//! Discovery metadata, display names, hostnames, addresses, endpoints, discovery
//! keys, and pairing-attempt identifiers are never persisted as trusted
//! identity. Effective runtime trust — including disabling it immediately on
//! reset or revocation, per `docs/trust.md` — is a separate concern layered
//! above this boundary; the store's responsibility is to report durable
//! write/remove success or failure truthfully.
//!
//! A loaded store file is untrusted local input. The read has a hard allocation
//! ceiling ([`MAX_TRUSTED_PEERS_STORE_BYTES`] + 1 byte), then the bytes are
//! decoded, version-checked, and fully validated before any record is returned;
//! malformed, truncated, oversized, unsupported, duplicated, or conflicting
//! content fails the whole load closed and never yields an effectively trusted
//! record.
//!
//! Mutations ([`store`](TrustedPeerStore::store),
//! [`remove`](TrustedPeerStore::remove)) run as one exclusively locked
//! load-modify-atomic-replace transaction, serialised across processes by an OS
//! advisory lock on a persistent sibling `trusted-peers.lock` file, so two
//! concurrent writers cannot lose each other's change (a removed record cannot
//! be resurrected by a stale writer). A lock held by another process is
//! reported as [`TrustedPeerStoreError::StoreBusy`], never a silent wait.
//! Reads are lock-free — atomic replacement plus reading through a pinned open
//! descriptor gives a reader the whole previous or whole next file.
//!
//! Filesystem indirection is rejected, not followed: a symbolic link at the
//! store or lock path is a typed error and its target is never read, written,
//! or `chmod`ed. This defends the ordinary case; it does not claim to withstand
//! a same-user process racing every filesystem operation.

use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read};
use std::path::PathBuf;
use std::str;

use directories::ProjectDirs;

use crate::persistence::{
    PersistenceError, PersistenceOperation, create_synced_temporary, ensure_hardened_parent,
    harden_existing_file, harden_existing_parent, sync_parent_directory,
};

/// The maximum number of trusted-peer records one store may hold.
pub const MAX_TRUSTED_PEERS: usize = 128;
/// The maximum size, in bytes, of authenticated peer key-identity material.
pub const MAX_PEER_IDENTITY_BYTES: usize = 64;
/// The maximum length, in Unicode scalar values, of a trusted-peer label.
pub const MAX_TRUSTED_PEER_LABEL_CHARS: usize = 64;
/// The maximum size, in bytes, of the encoded trusted-peer store file.
pub const MAX_TRUSTED_PEERS_STORE_BYTES: usize = 64 * 1024;

const MAX_TRUSTED_PEER_LABEL_BYTES: usize = 256;
const MAX_RECORD_LINE_BYTES: usize = 512;
const STORE_FORMAT_VERSION: u16 = 1;
const STORE_HEADER: &str = "local-transfer-trusted-peers";
const STORE_FILE_NAME: &str = "trusted-peers";
const LOCK_FILE_SUFFIX: &str = ".lock";

/// Opaque authenticated peer key-identity material — a *persisted recognition
/// token*, not a usable authenticated identity.
///
/// `scheme` is a namespace/discriminator for the future authenticated-identity
/// representation; this issue assigns no values and treats every `u16` as
/// structurally valid. `material` is 1–[`MAX_PEER_IDENTITY_BYTES`] opaque bytes.
///
/// Structural validity here proves nothing about cryptography:
///
/// - successful decoding does **not** authenticate the bytes;
/// - this type never asserts that arbitrary bytes are authenticated;
/// - a `scheme` this build has never heard of still loads (whole-store
///   fail-closed is about *structure*, not scheme support);
/// - whether the running system can actually *use* a given scheme, and whether
///   a stored token still matches a peer, is decided by the future
///   authenticated-pairing / identity layer re-establishing authentication and
///   comparing — never by this module.
///
/// It has no public constructor. It is the single security-relevant binding of
/// a trusted record and the only key the store uses for lookup, deduplication,
/// and removal; a display name or any other advisory value is never promoted
/// into it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerKeyIdentity {
    scheme: u16,
    material: Vec<u8>,
}

impl PeerKeyIdentity {
    /// Validates already-authenticated key-identity material against its bounds.
    pub(crate) fn new(scheme: u16, material: Vec<u8>) -> Result<Self, PeerKeyIdentityError> {
        if material.is_empty() {
            return Err(PeerKeyIdentityError::Empty);
        }
        if material.len() > MAX_PEER_IDENTITY_BYTES {
            return Err(PeerKeyIdentityError::TooLarge {
                size: material.len(),
                maximum: MAX_PEER_IDENTITY_BYTES,
            });
        }
        Ok(Self { scheme, material })
    }

    /// Returns the key-identity scheme discriminator.
    #[must_use]
    pub const fn scheme(&self) -> u16 {
        self.scheme
    }

    /// Returns the bounded key-identity bytes.
    #[must_use]
    pub fn material(&self) -> &[u8] {
        &self.material
    }

    #[cfg(test)]
    pub(crate) fn for_test(scheme: u16, material: &[u8]) -> Self {
        Self::new(scheme, material.to_vec()).expect("valid test key identity")
    }
}

impl fmt::Display for PeerKeyIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:", self.scheme)?;
        for byte in &self.material {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Authenticated key-identity material is empty or exceeds its bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerKeyIdentityError {
    Empty,
    TooLarge { size: usize, maximum: usize },
}

/// A validated, presentation-only label for a trusted peer.
///
/// The label helps a person recognise a record; it is never an identity, never
/// a lookup key, and never participates in a trust decision. It may be set
/// locally, seeded from a discovery hint at pairing time, and edited later
/// without changing the record's key-identity binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPeerLabel(String);

impl TrustedPeerLabel {
    /// Validates and normalises a presentation label.
    ///
    /// Control characters are rejected before surrounding Unicode whitespace is
    /// trimmed; the result must contain 1 to [`MAX_TRUSTED_PEER_LABEL_CHARS`]
    /// scalar values.
    pub(crate) fn new(value: impl AsRef<str>) -> Result<Self, TrustedPeerLabelError> {
        let value = value.as_ref();
        if value.chars().any(char::is_control) {
            return Err(TrustedPeerLabelError::ControlCharacter);
        }
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(TrustedPeerLabelError::Empty);
        }
        let chars = normalized.chars().count();
        if chars > MAX_TRUSTED_PEER_LABEL_CHARS {
            return Err(TrustedPeerLabelError::TooLong {
                chars,
                maximum: MAX_TRUSTED_PEER_LABEL_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    /// Returns the normalised label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: &str) -> Self {
        Self::new(value).expect("valid test label")
    }
}

impl fmt::Display for TrustedPeerLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A trusted-peer label is empty, over length, or contains a control character.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TrustedPeerLabelError {
    Empty,
    ControlCharacter,
    TooLong { chars: usize, maximum: usize },
}

/// The minimum durable record recognising one trusted cryptographic peer.
///
/// It binds an authenticated [`PeerKeyIdentity`] — the only security-relevant
/// field — to an optional presentation label. No discovery data, endpoint,
/// hostname, timestamp, pairing-attempt identifier, or separate local record
/// identifier is stored: the key identity is itself the stable, unambiguous
/// handle. There is no public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPeerRecord {
    identity: PeerKeyIdentity,
    label: Option<TrustedPeerLabel>,
}

impl TrustedPeerRecord {
    pub(crate) const fn new(identity: PeerKeyIdentity, label: Option<TrustedPeerLabel>) -> Self {
        Self { identity, label }
    }

    /// Returns the authenticated key identity this record trusts.
    #[must_use]
    pub const fn identity(&self) -> &PeerKeyIdentity {
        &self.identity
    }

    /// Returns the optional, presentation-only label.
    #[must_use]
    pub const fn label(&self) -> Option<&TrustedPeerLabel> {
        self.label.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(identity: PeerKeyIdentity, label: Option<&str>) -> Self {
        Self::new(identity, label.map(TrustedPeerLabel::for_test))
    }
}

/// A fully validated, deduplicated set of trusted-peer records.
///
/// Every record has a distinct [`PeerKeyIdentity`]; records are ordered by that
/// identity for deterministic output. Lookup keys on the identity only, never on
/// the label.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedPeers {
    records: Vec<TrustedPeerRecord>,
}

impl TrustedPeers {
    fn empty() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Returns the number of trusted-peer records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Reports whether no trusted-peer records are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Iterates the records in deterministic key-identity order.
    pub fn iter(&self) -> impl Iterator<Item = &TrustedPeerRecord> {
        self.records.iter()
    }

    /// Returns the record for an authenticated key identity, if trusted.
    #[must_use]
    pub fn get(&self, identity: &PeerKeyIdentity) -> Option<&TrustedPeerRecord> {
        self.records
            .binary_search_by(|record| record.identity.cmp(identity))
            .ok()
            .map(|index| &self.records[index])
    }

    /// Reports whether an authenticated key identity is trusted.
    #[must_use]
    pub fn contains(&self, identity: &PeerKeyIdentity) -> bool {
        self.get(identity).is_some()
    }
}

/// The outcome of a durable trusted-peer removal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum TrustedPeerRemoval {
    /// A matching record existed and was durably removed.
    Removed,
    /// No matching record existed; the durable store already lacks this identity.
    AlreadyAbsent,
}

/// Why a stored trusted-peer record is unusable.
///
/// Values describe store structure and bounds only, never record contents.
#[derive(Debug)]
pub enum TrustedPeerStoreError {
    /// The operating system provided no application configuration directory.
    ConfigDirectoryUnavailable,
    /// The configured store path has no parent directory.
    InvalidStorePath { path: PathBuf },
    /// A filesystem operation failed.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The store or lock path exists but is not a regular file.
    NotRegularFile { path: PathBuf },
    /// The store or lock path is a symbolic link; the store refuses to read,
    /// write, or change permissions through filesystem indirection.
    SymlinkNotAllowed { path: PathBuf },
    /// Another process holds the store's exclusive mutation lock.
    StoreBusy,
    /// The store file exceeds its byte budget.
    StoreTooLarge { size: u64, maximum: usize },
    /// One record line exceeds its byte budget.
    RecordTooLarge { size: usize, maximum: usize },
    /// The store format version is well formed but unsupported.
    UnsupportedVersion { version: u16 },
    /// The store holds more records than the supported maximum.
    CapacityExceeded { count: usize, maximum: usize },
    /// Two records bind the same authenticated key identity.
    DuplicateIdentity,
    /// The store is structurally malformed.
    MalformedStore { reason: MalformedStoreReason },
}

/// The structural category of a malformed trusted-peer store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedStoreReason {
    /// The store bytes are not valid UTF-8.
    NotUtf8,
    /// The header line is missing, truncated, or unrecognised.
    Header,
    /// A record line does not have the expected field structure.
    RecordSyntax,
    /// A record's key-identity material is not canonical lowercase hex.
    IdentityEncoding,
    /// A record's key-identity material is empty or over length.
    IdentityBounds,
    /// A record's label is not canonical lowercase hex or valid UTF-8.
    LabelEncoding,
    /// A record's decoded label is empty, over length, or has a control byte.
    LabelValue,
}

impl fmt::Display for TrustedPeerStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfigDirectoryUnavailable => {
                formatter.write_str("the local configuration directory is unavailable")
            }
            Self::InvalidStorePath { path } => write!(
                formatter,
                "trusted-peer store path has no parent: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} at {}: {source}",
                path.display()
            ),
            Self::NotRegularFile { path } => write!(
                formatter,
                "trusted-peer store path {} is not a regular file",
                path.display()
            ),
            Self::SymlinkNotAllowed { path } => write!(
                formatter,
                "trusted-peer store path {} is a symbolic link",
                path.display()
            ),
            Self::StoreBusy => {
                formatter.write_str("the trusted-peer store is locked by another process")
            }
            Self::StoreTooLarge { size, maximum } => write!(
                formatter,
                "trusted-peer store is {size} bytes; maximum is {maximum}"
            ),
            Self::RecordTooLarge { size, maximum } => write!(
                formatter,
                "a trusted-peer record is {size} bytes; maximum is {maximum}"
            ),
            Self::UnsupportedVersion { version } => {
                write!(
                    formatter,
                    "unsupported trusted-peer store version {version}"
                )
            }
            Self::CapacityExceeded { count, maximum } => write!(
                formatter,
                "trusted-peer store holds {count} records; maximum is {maximum}"
            ),
            Self::DuplicateIdentity => {
                formatter.write_str("trusted-peer store binds one key identity more than once")
            }
            Self::MalformedStore { reason } => {
                write!(formatter, "malformed trusted-peer store ({reason:?})")
            }
        }
    }
}

impl Error for TrustedPeerStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

const fn malformed(reason: MalformedStoreReason) -> TrustedPeerStoreError {
    TrustedPeerStoreError::MalformedStore { reason }
}

/// A filesystem-backed store for durable trusted-peer records.
///
/// One versioned, bounded store file holds every record and is replaced
/// atomically on each mutation. `load` returns only fully validated records;
/// any corruption fails the whole load closed rather than silently dropping a
/// security-significant record.
#[derive(Clone, Debug)]
pub struct TrustedPeerStore {
    path: PathBuf,
    harden_existing_parent: bool,
}

/// RAII guard holding the store's exclusive mutation lock.
///
/// The guard owns the sole [`File`] handle for the lock; the OS advisory lock is
/// released when that handle is closed, which happens automatically when the
/// guard drops (on every path, including a mutation error `?` and a panic) and
/// on process exit. The `Drop` also calls `unlock` for an eager, deterministic
/// release, but correctness does not depend on that call succeeding — holding
/// the handle for the guard's lifetime is the invariant.
struct StoreLock {
    file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        // Drop cannot report an error; the handle close below releases the lock
        // regardless.
        let _ = self.file.unlock();
    }
}

impl TrustedPeerStore {
    /// Opens the store in the current user's `local-transfer` configuration
    /// directory, alongside the local device identity files.
    pub fn for_current_user() -> Result<Self, TrustedPeerStoreError> {
        let project_dirs = ProjectDirs::from("", "", "local-transfer")
            .ok_or(TrustedPeerStoreError::ConfigDirectoryUnavailable)?;
        Ok(Self {
            path: project_dirs.config_dir().join(STORE_FILE_NAME),
            harden_existing_parent: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            harden_existing_parent: false,
        }
    }

    /// Test-only: acquire and hold the exclusive mutation lock, so a test can
    /// prove that a competing store instance is reported busy. Not part of the
    /// production API.
    #[cfg(test)]
    fn hold_exclusive_lock(&self) -> Result<StoreLock, TrustedPeerStoreError> {
        self.lock_exclusive()
    }

    /// Loads and validates every durable trusted-peer record.
    ///
    /// A missing store is an empty store. A store path that is a symbolic link
    /// or not a regular file, an oversized file, invalid UTF-8, an unrecognised
    /// or unsupported header, a malformed record, an over-count store, or a
    /// key identity bound twice is returned as a typed error and yields no
    /// records — corruption never falls back to a partial set or to
    /// presentation metadata.
    ///
    /// Reads are lock-free: the store file is only ever replaced atomically by a
    /// rename, and this reads through a pinned open file descriptor, so a
    /// concurrent mutation is observed as either the whole previous file or the
    /// whole next one. Serialising read-modify-write mutations (which a
    /// lock-free reader cannot corrupt) is [`store`](Self::store)'s and
    /// [`remove`](Self::remove)'s job via an exclusive OS lock.
    pub fn load(&self) -> Result<TrustedPeers, TrustedPeerStoreError> {
        if self.harden_existing_parent {
            harden_existing_parent(&self.path).map_err(Self::persistence_error)?;
            harden_existing_file(&self.path).map_err(Self::persistence_error)?;
        }
        match self.read_store_bytes()? {
            Some(bytes) => decode(&bytes),
            None => Ok(TrustedPeers::empty()),
        }
    }

    /// Durably stores a trusted-peer record, keyed by its authenticated key
    /// identity.
    ///
    /// If the identity is already present, its record is replaced — which can
    /// only change the presentation label, never the identity binding. The
    /// whole operation (acquire the exclusive lock, load, mutate, encode,
    /// atomic replacement, and durability sync) runs as one locked transaction,
    /// so two concurrent mutations cannot lose each other's change. `Ok(())` is
    /// returned only after the replacement and its flushes complete; a failure
    /// never reports a record as durably stored, and another process holding
    /// the lock is reported as [`TrustedPeerStoreError::StoreBusy`] rather than
    /// blocking.
    ///
    /// There is no public constructor for [`TrustedPeerRecord`]: only the
    /// in-crate verified-pairing transition can supply one. That transition is a
    /// later issue, so for now this method is reached only through tests.
    #[allow(
        dead_code,
        reason = "in-crate seam for the future verified-pairing commit; tested now"
    )]
    pub(crate) fn store(&self, record: TrustedPeerRecord) -> Result<(), TrustedPeerStoreError> {
        let _lock = self.lock_exclusive()?;
        let current = self.load()?;
        let mut records: Vec<TrustedPeerRecord> = current
            .iter()
            .filter(|existing| existing.identity() != record.identity())
            .cloned()
            .collect();
        records.push(record);
        self.write_all(records)
    }

    /// Durably removes the trusted-peer record for an authenticated key
    /// identity.
    ///
    /// Removal is idempotent: an absent identity is [`TrustedPeerRemoval::AlreadyAbsent`],
    /// not an error. It runs as one exclusively locked load-modify-replace
    /// transaction, so a stale concurrent writer cannot resurrect a record this
    /// call removed. If the atomic replacement fails a typed error is returned
    /// and the durable record is unchanged — a failed durable removal is never
    /// reported as success. Disabling effective runtime trust is a separate step
    /// performed by trust orchestration before this call, per `docs/trust.md`.
    pub fn remove(
        &self,
        identity: &PeerKeyIdentity,
    ) -> Result<TrustedPeerRemoval, TrustedPeerStoreError> {
        let _lock = self.lock_exclusive()?;
        let current = self.load()?;
        if !current.contains(identity) {
            return Ok(TrustedPeerRemoval::AlreadyAbsent);
        }
        let records: Vec<TrustedPeerRecord> = current
            .iter()
            .filter(|existing| existing.identity() != identity)
            .cloned()
            .collect();
        self.write_all(records)?;
        Ok(TrustedPeerRemoval::Removed)
    }

    /// Reads the store file's bytes with a hard allocation ceiling, or `None`
    /// when the file does not exist.
    fn read_store_bytes(&self) -> Result<Option<Vec<u8>>, TrustedPeerStoreError> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TrustedPeerStoreError::SymlinkNotAllowed {
                    path: self.path.clone(),
                });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(TrustedPeerStoreError::NotRegularFile {
                    path: self.path.clone(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io_error("inspect trusted-peer store", source)),
        }

        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(self.io_error("open trusted-peer store", source)),
        };
        let metadata = file
            .metadata()
            .map_err(|source| self.io_error("inspect open trusted-peer store", source))?;
        if !metadata.is_file() {
            return Err(TrustedPeerStoreError::NotRegularFile {
                path: self.path.clone(),
            });
        }
        if metadata.len() > MAX_TRUSTED_PEERS_STORE_BYTES as u64 {
            return Err(TrustedPeerStoreError::StoreTooLarge {
                size: metadata.len(),
                maximum: MAX_TRUSTED_PEERS_STORE_BYTES,
            });
        }

        // Cap the allocation at one byte past the limit regardless of the
        // file's real size, so a file that grows or is swapped after the
        // metadata check still cannot force an unbounded read.
        let ceiling = MAX_TRUSTED_PEERS_STORE_BYTES as u64 + 1;
        let mut bytes = Vec::new();
        file.take(ceiling)
            .read_to_end(&mut bytes)
            .map_err(|source| self.io_error("read trusted-peer store", source))?;
        if bytes.len() > MAX_TRUSTED_PEERS_STORE_BYTES {
            return Err(TrustedPeerStoreError::StoreTooLarge {
                size: bytes.len() as u64,
                maximum: MAX_TRUSTED_PEERS_STORE_BYTES,
            });
        }
        Ok(Some(bytes))
    }

    fn write_all(&self, mut records: Vec<TrustedPeerRecord>) -> Result<(), TrustedPeerStoreError> {
        if records.len() > MAX_TRUSTED_PEERS {
            return Err(TrustedPeerStoreError::CapacityExceeded {
                count: records.len(),
                maximum: MAX_TRUSTED_PEERS,
            });
        }
        records.sort_by(|a, b| a.identity.cmp(&b.identity));

        let bytes = encode(&records);
        if bytes.len() > MAX_TRUSTED_PEERS_STORE_BYTES {
            return Err(TrustedPeerStoreError::StoreTooLarge {
                size: bytes.len() as u64,
                maximum: MAX_TRUSTED_PEERS_STORE_BYTES,
            });
        }

        let temporary = create_synced_temporary(&self.path, &bytes, self.harden_existing_parent)
            .map_err(Self::persistence_error)?;
        let file = temporary
            .persist(&self.path)
            .map_err(|error| self.io_error("replace trusted-peer store", error.error))?;
        file.sync_all()
            .map_err(|source| self.io_error("sync trusted-peer store", source))?;
        sync_parent_directory(&self.path)
            .map_err(|source| self.io_error("sync trusted-peer store directory", source))?;
        Ok(())
    }

    /// The path of the persistent sibling lock file.
    fn lock_path(&self) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_else(|| OsString::from(STORE_FILE_NAME));
        name.push(LOCK_FILE_SUFFIX);
        self.path.with_file_name(name)
    }

    /// Acquires the store's exclusive mutation lock via a persistent sibling
    /// lock file, without blocking.
    ///
    /// The OS lock is released automatically when the returned guard drops (on
    /// any path, including an error), and when the process exits — a crash
    /// leaves no stale application-level lock. The `.lock` file itself is left
    /// in place as a stable coordination anchor.
    fn lock_exclusive(&self) -> Result<StoreLock, TrustedPeerStoreError> {
        let file = self.open_lock_file()?;
        match file.try_lock() {
            Ok(()) => Ok(StoreLock { file }),
            Err(TryLockError::WouldBlock) => Err(TrustedPeerStoreError::StoreBusy),
            Err(TryLockError::Error(source)) => {
                Err(self.lock_io_error("lock the trusted-peer store", source))
            }
        }
    }

    fn open_lock_file(&self) -> Result<File, TrustedPeerStoreError> {
        let lock_path = self.lock_path();
        match fs::symlink_metadata(&lock_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TrustedPeerStoreError::SymlinkNotAllowed { path: lock_path });
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(TrustedPeerStoreError::NotRegularFile { path: lock_path });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(self.io_error_at(lock_path, "inspect the trusted-peer lock", source));
            }
        }

        ensure_hardened_parent(&lock_path, self.harden_existing_parent)
            .map_err(Self::persistence_error)?;

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&lock_path).map_err(|source| {
            self.io_error_at(lock_path.clone(), "open the trusted-peer lock", source)
        })?;

        let metadata = file.metadata().map_err(|source| {
            self.io_error_at(lock_path.clone(), "inspect the trusted-peer lock", source)
        })?;
        if !metadata.is_file() {
            return Err(TrustedPeerStoreError::NotRegularFile { path: lock_path });
        }
        harden_existing_file(&lock_path).map_err(Self::persistence_error)?;
        Ok(file)
    }

    fn io_error(&self, operation: &'static str, source: io::Error) -> TrustedPeerStoreError {
        self.io_error_at(self.path.clone(), operation, source)
    }

    fn lock_io_error(&self, operation: &'static str, source: io::Error) -> TrustedPeerStoreError {
        self.io_error_at(self.lock_path(), operation, source)
    }

    #[allow(clippy::unused_self)]
    fn io_error_at(
        &self,
        path: PathBuf,
        operation: &'static str,
        source: io::Error,
    ) -> TrustedPeerStoreError {
        TrustedPeerStoreError::Io {
            operation,
            path,
            source,
        }
    }

    fn persistence_error(error: PersistenceError) -> TrustedPeerStoreError {
        match error {
            PersistenceError::InvalidPath { path } => {
                TrustedPeerStoreError::InvalidStorePath { path }
            }
            PersistenceError::Io {
                operation,
                path,
                source,
            } => TrustedPeerStoreError::Io {
                operation: match operation {
                    PersistenceOperation::InspectDirectory => {
                        "inspect trusted-peer store directory"
                    }
                    PersistenceOperation::CreateDirectory => "create trusted-peer store directory",
                    PersistenceOperation::HardenDirectory => {
                        "harden trusted-peer store directory permissions"
                    }
                    PersistenceOperation::HardenFile => {
                        "harden trusted-peer store file permissions"
                    }
                    PersistenceOperation::CreateTemporary => "create temporary trusted-peer store",
                    PersistenceOperation::WriteTemporary => "write temporary trusted-peer store",
                    PersistenceOperation::SyncTemporary => "sync temporary trusted-peer store",
                },
                path,
                source,
            },
        }
    }
}

/// Encodes the records as `header\n` then one `scheme material-hex label-hex`
/// line each. Hex is used for canonical, delimiter-free, deterministic parsing;
/// it is a reversible encoding and provides no confidentiality for the label.
/// Callers pass a set with unique identities; this sorts by identity for stable
/// output.
fn encode(records: &[TrustedPeerRecord]) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(STORE_HEADER);
    out.push_str(" v");
    out.push_str(&STORE_FORMAT_VERSION.to_string());
    out.push('\n');
    for record in records {
        out.push_str(&record.identity.scheme.to_string());
        out.push(' ');
        push_hex(&mut out, &record.identity.material);
        out.push(' ');
        match &record.label {
            None => out.push('-'),
            Some(label) => push_hex(&mut out, label.as_str().as_bytes()),
        }
        out.push('\n');
    }
    out.into_bytes()
}

fn decode(bytes: &[u8]) -> Result<TrustedPeers, TrustedPeerStoreError> {
    if bytes.len() > MAX_TRUSTED_PEERS_STORE_BYTES {
        return Err(TrustedPeerStoreError::StoreTooLarge {
            size: bytes.len() as u64,
            maximum: MAX_TRUSTED_PEERS_STORE_BYTES,
        });
    }
    let text = str::from_utf8(bytes).map_err(|_| malformed(MalformedStoreReason::NotUtf8))?;
    let body = text
        .strip_suffix('\n')
        .ok_or_else(|| malformed(MalformedStoreReason::Header))?;

    let mut lines = body.split('\n');
    let header = lines
        .next()
        .ok_or_else(|| malformed(MalformedStoreReason::Header))?;
    parse_header(header)?;

    let record_lines: Vec<&str> = lines.collect();
    if record_lines.len() > MAX_TRUSTED_PEERS {
        return Err(TrustedPeerStoreError::CapacityExceeded {
            count: record_lines.len(),
            maximum: MAX_TRUSTED_PEERS,
        });
    }

    let mut records = Vec::with_capacity(record_lines.len());
    for line in record_lines {
        records.push(parse_record(line)?);
    }
    records.sort_by(|a, b| a.identity.cmp(&b.identity));
    if records
        .windows(2)
        .any(|pair| pair[0].identity == pair[1].identity)
    {
        return Err(TrustedPeerStoreError::DuplicateIdentity);
    }
    Ok(TrustedPeers { records })
}

fn parse_header(line: &str) -> Result<(), TrustedPeerStoreError> {
    let version_text = line
        .strip_prefix(STORE_HEADER)
        .and_then(|rest| rest.strip_prefix(" v"))
        .ok_or_else(|| malformed(MalformedStoreReason::Header))?;
    let version =
        parse_canonical_u16(version_text).ok_or_else(|| malformed(MalformedStoreReason::Header))?;
    if version != STORE_FORMAT_VERSION {
        return Err(TrustedPeerStoreError::UnsupportedVersion { version });
    }
    Ok(())
}

fn parse_record(line: &str) -> Result<TrustedPeerRecord, TrustedPeerStoreError> {
    if line.len() > MAX_RECORD_LINE_BYTES {
        return Err(TrustedPeerStoreError::RecordTooLarge {
            size: line.len(),
            maximum: MAX_RECORD_LINE_BYTES,
        });
    }

    let mut fields = line.split(' ');
    let scheme_text = fields
        .next()
        .ok_or_else(|| malformed(MalformedStoreReason::RecordSyntax))?;
    let material_hex = fields
        .next()
        .ok_or_else(|| malformed(MalformedStoreReason::RecordSyntax))?;
    let label_hex = fields
        .next()
        .ok_or_else(|| malformed(MalformedStoreReason::RecordSyntax))?;
    if fields.next().is_some() {
        return Err(malformed(MalformedStoreReason::RecordSyntax));
    }

    let scheme = parse_canonical_u16(scheme_text)
        .ok_or_else(|| malformed(MalformedStoreReason::RecordSyntax))?;

    if material_hex.len() > MAX_PEER_IDENTITY_BYTES * 2 {
        return Err(malformed(MalformedStoreReason::IdentityBounds));
    }
    let material = decode_hex(material_hex)
        .ok_or_else(|| malformed(MalformedStoreReason::IdentityEncoding))?;
    let identity = PeerKeyIdentity::new(scheme, material)
        .map_err(|_| malformed(MalformedStoreReason::IdentityBounds))?;

    let label = if label_hex == "-" {
        None
    } else {
        if label_hex.len() > MAX_TRUSTED_PEER_LABEL_BYTES {
            return Err(malformed(MalformedStoreReason::LabelValue));
        }
        let label_bytes =
            decode_hex(label_hex).ok_or_else(|| malformed(MalformedStoreReason::LabelEncoding))?;
        let label_text = String::from_utf8(label_bytes)
            .map_err(|_| malformed(MalformedStoreReason::LabelEncoding))?;
        Some(
            TrustedPeerLabel::new(&label_text)
                .map_err(|_| malformed(MalformedStoreReason::LabelValue))?,
        )
    };

    Ok(TrustedPeerRecord::new(identity, label))
}

fn parse_canonical_u16(text: &str) -> Option<u16> {
    let value = text.parse::<u16>().ok()?;
    (value.to_string() == text).then_some(value)
}

fn push_hex(out: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return None;
    }
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    let mut out = Vec::with_capacity(pairs.len());
    for &[high, low] in pairs {
        out.push((hex_value(high)? << 4) | hex_value(low)?);
    }
    Some(out)
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    fn key(scheme: u16, byte: u8, len: usize) -> PeerKeyIdentity {
        PeerKeyIdentity::for_test(scheme, &vec![byte; len])
    }

    fn record(scheme: u16, byte: u8, label: Option<&str>) -> TrustedPeerRecord {
        TrustedPeerRecord::for_test(key(scheme, byte, 32), label)
    }

    /// A store at a not-yet-created nested directory, so directory creation and
    /// hardening are exercised.
    fn nested_store(dir: &Path) -> TrustedPeerStore {
        TrustedPeerStore::at(dir.join("nested/trusted-peers"))
    }

    fn write_raw(path: &Path, contents: impl AsRef<[u8]>) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }

    fn malformed_reason(error: &TrustedPeerStoreError) -> Option<MalformedStoreReason> {
        match error {
            TrustedPeerStoreError::MalformedStore { reason } => Some(*reason),
            _ => None,
        }
    }

    #[test]
    fn a_missing_store_loads_as_an_empty_set() {
        let directory = tempdir().unwrap();
        let peers = nested_store(directory.path()).load().unwrap();

        assert!(peers.is_empty());
        assert_eq!(peers.len(), 0);
        assert_eq!(peers.iter().count(), 0);
    }

    #[test]
    fn a_record_round_trips_across_a_fresh_store_object() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        let written = record(7, 0xab, Some("Studio Workstation"));

        TrustedPeerStore::at(&path).store(written.clone()).unwrap();

        // A brand-new store object stands in for a process restart.
        let reloaded = TrustedPeerStore::at(&path).load().unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.contains(written.identity()));
        assert_eq!(reloaded.get(written.identity()), Some(&written));
        assert_eq!(
            reloaded
                .get(written.identity())
                .and_then(TrustedPeerRecord::label)
                .map(TrustedPeerLabel::as_str),
            Some("Studio Workstation")
        );
    }

    #[test]
    fn a_record_without_a_label_round_trips() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        let written = record(1, 0x01, None);

        store.store(written.clone()).unwrap();

        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.get(written.identity()), Some(&written));
        assert!(reloaded.get(written.identity()).unwrap().label().is_none());
    }

    #[test]
    fn the_persisted_form_holds_only_the_key_identity_and_an_encoded_label() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        TrustedPeerStore::at(&path)
            .store(record(9, 0xcd, Some("Kitchen")))
            .unwrap();

        let raw = fs::read_to_string(&path).unwrap();

        // The label is written as canonical lowercase hex for deterministic
        // parsing (NOT for confidentiality -- "Kitchen" is 4b6974636865 6e in
        // UTF-8 and anyone who can read the file can decode it). What matters
        // here is that no discovery-derived value -- address, hostname,
        // endpoint, discovery key, attempt id -- is a persisted field.
        assert_eq!(
            raw,
            format!(
                "local-transfer-trusted-peers v1\n9 {} 4b69746368656e\n",
                "cd".repeat(32)
            )
        );
        for forbidden in ["192.", "10.0", ".local", "http", "lt-", "_local-transfer"] {
            assert!(
                !raw.contains(forbidden),
                "unexpected `{forbidden}` in store"
            );
        }
    }

    #[test]
    fn storing_an_existing_identity_replaces_only_the_label() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        let id = key(4, 0x22, 32);

        store
            .store(TrustedPeerRecord::for_test(id.clone(), Some("First Name")))
            .unwrap();
        store
            .store(TrustedPeerRecord::for_test(id.clone(), Some("Renamed")))
            .unwrap();

        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.len(), 1);
        assert_eq!(
            reloaded
                .get(&id)
                .and_then(TrustedPeerRecord::label)
                .map(TrustedPeerLabel::as_str),
            Some("Renamed")
        );
        // The identity binding is unchanged; only the label moved.
        assert_eq!(reloaded.get(&id).unwrap().identity(), &id);
    }

    #[test]
    fn lookup_and_dedup_key_on_identity_never_on_the_label() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        // Two distinct identities that deliberately share a display label.
        store.store(record(1, 0x01, Some("Laptop"))).unwrap();
        store.store(record(2, 0x02, Some("Laptop"))).unwrap();

        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.len(), 2);
        assert!(reloaded.contains(&key(1, 0x01, 32)));
        assert!(reloaded.contains(&key(2, 0x02, 32)));
        assert!(!reloaded.contains(&key(3, 0x03, 32)));
    }

    #[test]
    fn removal_is_deterministic_and_idempotent() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        let kept = record(1, 0x11, Some("Keep"));
        let gone = record(2, 0x22, Some("Drop"));
        store.store(kept.clone()).unwrap();
        store.store(gone.clone()).unwrap();

        assert_eq!(
            store.remove(gone.identity()).unwrap(),
            TrustedPeerRemoval::Removed
        );
        let after = store.load().unwrap();
        assert_eq!(after.len(), 1);
        assert!(!after.contains(gone.identity()));
        assert!(after.contains(kept.identity()));

        // Removing again, or removing an unknown identity, is absent-not-error.
        assert_eq!(
            store.remove(gone.identity()).unwrap(),
            TrustedPeerRemoval::AlreadyAbsent
        );
        assert_eq!(
            store.remove(&key(9, 0x99, 32)).unwrap(),
            TrustedPeerRemoval::AlreadyAbsent
        );
    }

    #[test]
    fn removing_the_last_record_leaves_a_valid_empty_store() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        let only = record(1, 0x01, None);
        store.store(only.clone()).unwrap();

        assert_eq!(
            store.remove(only.identity()).unwrap(),
            TrustedPeerRemoval::Removed
        );
        assert!(store.load().unwrap().is_empty());
        // A reopened store still reads the empty file cleanly.
        assert!(store.load().unwrap().is_empty());
    }

    #[test]
    fn the_store_bytes_are_deterministic_regardless_of_insertion_order() {
        let directory = tempdir().unwrap();
        let first = directory.path().join("a/trusted-peers");
        let second = directory.path().join("b/trusted-peers");

        let store_a = TrustedPeerStore::at(&first);
        store_a.store(record(5, 0x05, Some("e"))).unwrap();
        store_a.store(record(1, 0x01, None)).unwrap();
        store_a.store(record(3, 0x03, Some("c"))).unwrap();

        let store_b = TrustedPeerStore::at(&second);
        store_b.store(record(3, 0x03, Some("c"))).unwrap();
        store_b.store(record(5, 0x05, Some("e"))).unwrap();
        store_b.store(record(1, 0x01, None)).unwrap();

        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
        let schemes: Vec<u16> = store_a
            .load()
            .unwrap()
            .iter()
            .map(|record| record.identity().scheme())
            .collect();
        assert_eq!(schemes, [1, 3, 5]);
    }

    #[test]
    fn structural_corruption_fails_the_whole_load_closed() {
        let directory = tempdir().unwrap();
        let valid = format!("1 {} -\n", "aa".repeat(32));

        // Empty file, bare newline, and a truncated header all fail.
        for contents in ["", "\n", "local-transfer-trusted-peers v1"] {
            let path = directory
                .path()
                .join(format!("s{}/trusted-peers", contents.len()));
            write_raw(&path, contents);
            assert!(TrustedPeerStore::at(&path).load().is_err());
        }

        // Unrecognised header.
        let path = directory.path().join("other-header/trusted-peers");
        write_raw(&path, "local-transfer-other v1\n");
        assert_eq!(
            malformed_reason(&TrustedPeerStore::at(&path).load().unwrap_err()),
            Some(MalformedStoreReason::Header)
        );

        // Unsupported but well-formed version.
        let path = directory.path().join("v2/trusted-peers");
        write_raw(&path, "local-transfer-trusted-peers v2\n");
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::UnsupportedVersion { version: 2 }
        ));

        // Non-canonical version text.
        let path = directory.path().join("v01/trusted-peers");
        write_raw(&path, "local-transfer-trusted-peers v01\n");
        assert_eq!(
            malformed_reason(&TrustedPeerStore::at(&path).load().unwrap_err()),
            Some(MalformedStoreReason::Header)
        );

        // Trailing garbage after a valid record.
        let path = directory.path().join("trailing/trusted-peers");
        write_raw(
            &path,
            format!("local-transfer-trusted-peers v1\n{valid}garbage"),
        );
        assert!(TrustedPeerStore::at(&path).load().is_err());

        // Not UTF-8.
        let path = directory.path().join("utf8/trusted-peers");
        write_raw(&path, [b'l', 0xff, b'\n']);
        assert_eq!(
            malformed_reason(&TrustedPeerStore::at(&path).load().unwrap_err()),
            Some(MalformedStoreReason::NotUtf8)
        );
    }

    #[test]
    fn record_level_corruption_is_categorised_and_never_yields_a_record() {
        let directory = tempdir().unwrap();
        let long_material = format!("1 {} -\n", "aa".repeat(MAX_PEER_IDENTITY_BYTES + 1));
        let control_label = format!("1 {} 09\n", "aa".repeat(32));
        let bad_utf8_label = format!("1 {} ff\n", "aa".repeat(32));

        let cases: &[(&str, MalformedStoreReason)] = &[
            ("1 aa\n", MalformedStoreReason::RecordSyntax),
            ("1 aa - extra\n", MalformedStoreReason::RecordSyntax),
            ("x aa -\n", MalformedStoreReason::RecordSyntax),
            ("01 aa -\n", MalformedStoreReason::RecordSyntax),
            ("1  -\n", MalformedStoreReason::IdentityEncoding),
            ("1 az -\n", MalformedStoreReason::IdentityEncoding),
            ("1 AA -\n", MalformedStoreReason::IdentityEncoding),
            ("1 aaa -\n", MalformedStoreReason::IdentityEncoding),
            (long_material.as_str(), MalformedStoreReason::IdentityBounds),
            (
                concat!("1 ", "aa", " zz\n"),
                MalformedStoreReason::LabelEncoding,
            ),
            (bad_utf8_label.as_str(), MalformedStoreReason::LabelEncoding),
            (control_label.as_str(), MalformedStoreReason::LabelValue),
        ];

        for (index, (line, reason)) in cases.iter().enumerate() {
            let path = directory.path().join(format!("rec{index}/trusted-peers"));
            write_raw(&path, format!("local-transfer-trusted-peers v1\n{line}"));
            let error = TrustedPeerStore::at(&path).load().unwrap_err();
            assert_eq!(
                malformed_reason(&error),
                Some(*reason),
                "wrong category for {line:?}: {error:?}"
            );
        }
    }

    #[test]
    fn duplicate_and_conflicting_identity_records_fail_closed() {
        let directory = tempdir().unwrap();
        let material = "bb".repeat(32);

        // Exact duplicate.
        let path = directory.path().join("dup/trusted-peers");
        write_raw(
            &path,
            format!("local-transfer-trusted-peers v1\n1 {material} -\n1 {material} -\n"),
        );
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::DuplicateIdentity
        ));

        // Same identity, conflicting label (0x41 "A" vs 0x42 "B").
        let path = directory.path().join("conflict/trusted-peers");
        write_raw(
            &path,
            format!("local-transfer-trusted-peers v1\n1 {material} 41\n1 {material} 42\n"),
        );
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::DuplicateIdentity
        ));

        // Records unsorted in the file are still deduplicated deterministically.
        let other = "cc".repeat(32);
        let path = directory.path().join("unsorted-dup/trusted-peers");
        write_raw(
            &path,
            format!("local-transfer-trusted-peers v1\n2 {other} -\n1 {material} -\n2 {other} -\n"),
        );
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::DuplicateIdentity
        ));
    }

    #[test]
    fn oversized_stores_and_record_counts_are_rejected_before_full_parsing() {
        let directory = tempdir().unwrap();

        // Whole-store byte budget, checked from metadata before the read.
        let path = directory.path().join("big/trusted-peers");
        write_raw(&path, vec![b'x'; MAX_TRUSTED_PEERS_STORE_BYTES + 1]);
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::StoreTooLarge { .. }
        ));

        // Record-count budget.
        let mut contents = String::from("local-transfer-trusted-peers v1\n");
        for index in 0..=MAX_TRUSTED_PEERS {
            contents.push_str(&format!("{index} {} -\n", "aa".repeat(4)));
        }
        let path = directory.path().join("many/trusted-peers");
        write_raw(&path, &contents);
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::CapacityExceeded { .. }
        ));

        // One over-long record line.
        let path = directory.path().join("longrec/trusted-peers");
        write_raw(
            &path,
            format!(
                "local-transfer-trusted-peers v1\n1 {} {}\n",
                "aa".repeat(32),
                "62".repeat(300)
            ),
        );
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::RecordTooLarge { .. }
        ));
    }

    #[test]
    fn a_write_over_capacity_is_rejected_and_leaves_the_durable_store_untouched() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        let store = TrustedPeerStore::at(&path);
        for index in 0..MAX_TRUSTED_PEERS {
            store
                .store(record(u16::try_from(index).unwrap(), 0x01, None))
                .unwrap();
        }
        let full = fs::read(&path).unwrap();

        let error = store
            .store(record(
                u16::try_from(MAX_TRUSTED_PEERS).unwrap(),
                0x01,
                None,
            ))
            .unwrap_err();

        assert!(matches!(
            error,
            TrustedPeerStoreError::CapacityExceeded { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), full);
        assert_eq!(store.load().unwrap().len(), MAX_TRUSTED_PEERS);
    }

    #[test]
    fn key_identity_and_label_bounds_hold_at_the_exact_limit() {
        assert!(matches!(
            PeerKeyIdentity::new(0, vec![]),
            Err(PeerKeyIdentityError::Empty)
        ));
        assert!(PeerKeyIdentity::new(0, vec![0; MAX_PEER_IDENTITY_BYTES]).is_ok());
        assert!(matches!(
            PeerKeyIdentity::new(0, vec![0; MAX_PEER_IDENTITY_BYTES + 1]),
            Err(PeerKeyIdentityError::TooLarge { .. })
        ));

        assert!(TrustedPeerLabel::new("").is_err());
        assert!(TrustedPeerLabel::new("   ").is_err());
        assert!(TrustedPeerLabel::new("bad\nlabel").is_err());
        let exact = "x".repeat(MAX_TRUSTED_PEER_LABEL_CHARS);
        assert_eq!(TrustedPeerLabel::new(&exact).unwrap().as_str(), exact);
        assert!(matches!(
            TrustedPeerLabel::new("x".repeat(MAX_TRUSTED_PEER_LABEL_CHARS + 1)),
            Err(TrustedPeerLabelError::TooLong { .. })
        ));
    }

    #[test]
    fn a_maximum_length_identity_and_multibyte_label_round_trip() {
        let directory = tempdir().unwrap();
        let store = nested_store(directory.path());
        let big_identity = PeerKeyIdentity::for_test(65_535, &[0xff; MAX_PEER_IDENTITY_BYTES]);
        let big_label = "é".repeat(MAX_TRUSTED_PEER_LABEL_CHARS);
        let written = TrustedPeerRecord::for_test(big_identity.clone(), Some(&big_label));

        store.store(written.clone()).unwrap();

        assert_eq!(store.load().unwrap().get(&big_identity), Some(&written));
    }

    #[test]
    fn a_non_regular_store_path_is_a_typed_error_not_a_panic() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("trusted-peers");
        fs::create_dir(&path).unwrap();

        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::NotRegularFile { .. }
        ));
    }

    #[test]
    fn key_identity_display_is_a_stable_scheme_and_hex_string() {
        let id = PeerKeyIdentity::for_test(9, &[0x0a, 0xbc]);
        assert_eq!(id.to_string(), "9:0abc");
        assert_eq!(id.scheme(), 9);
        assert_eq!(id.material(), &[0x0a, 0xbc]);
    }

    #[test]
    fn no_public_api_manufactures_trust_or_promotes_advisory_data() {
        // The read side is public; the write and record-construction side is not.
        let _: fn(&TrustedPeerStore) -> Result<TrustedPeers, TrustedPeerStoreError> =
            TrustedPeerStore::load;
        let _: fn(
            &TrustedPeerStore,
            &PeerKeyIdentity,
        ) -> Result<TrustedPeerRemoval, TrustedPeerStoreError> = TrustedPeerStore::remove;
        // `TrustedPeerStore::store`, `TrustedPeerRecord::new`, `PeerKeyIdentity::new`,
        // and `TrustedPeerLabel::new` are crate-private, and there is no
        // `From`/`TryFrom` from any discovery type into any of these. A
        // discovered peer therefore cannot be turned into a trusted record.
    }

    #[test]
    fn errors_preserve_their_io_source_and_never_echo_record_contents() {
        let directory = tempdir().unwrap();
        // Parent of the store path is a regular file: temp-file creation fails.
        let occupied = directory.path().join("occupied");
        fs::write(&occupied, "x").unwrap();
        let store = TrustedPeerStore::at(occupied.join("trusted-peers"));

        let error = store
            .store(record(1, 0x01, Some("Secret Label")))
            .unwrap_err();

        assert!(error.source().is_some());
        assert!(!error.to_string().contains("Secret Label"));
    }

    #[cfg(unix)]
    #[test]
    fn a_written_store_and_its_new_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        TrustedPeerStore::at(&path)
            .store(record(1, 0x01, Some("Desk")))
            .unwrap();

        let file_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let dir_mode = fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_write_or_remove_failure_never_reports_false_durable_success() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let store_dir = directory.path().join("store");
        fs::create_dir(&store_dir).unwrap();
        let path = store_dir.join("trusted-peers");
        let store = TrustedPeerStore::at(&path);
        store.store(record(1, 0x01, Some("Original"))).unwrap();
        let durable = fs::read(&path).unwrap();

        // A read-only directory blocks the atomic replacement entirely.
        fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o500)).unwrap();

        let store_error = store.store(record(2, 0x02, Some("New"))).unwrap_err();
        let remove_error = store.remove(&key(1, 0x01, 32)).unwrap_err();
        assert!(matches!(store_error, TrustedPeerStoreError::Io { .. }));
        assert!(matches!(remove_error, TrustedPeerStoreError::Io { .. }));

        fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o700)).unwrap();
        // Nothing partial was written; the previously durable record stands.
        assert_eq!(fs::read(&path).unwrap(), durable);
        let reloaded = store.load().unwrap();
        assert_eq!(reloaded.len(), 1);
        assert!(reloaded.contains(&key(1, 0x01, 32)));
    }

    // ----- cross-process mutation locking -----

    #[test]
    fn a_competing_mutation_is_reported_busy_and_changes_nothing() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        let owner = TrustedPeerStore::at(&path);
        owner.store(record(1, 0x11, Some("A"))).unwrap();
        owner.store(record(2, 0x22, Some("B"))).unwrap();
        let durable = fs::read(&path).unwrap();

        // Hold the exclusive lock, standing in for another process mid-mutation.
        let guard = owner.hold_exclusive_lock().unwrap();

        // A separate store instance cannot start any read-modify-write.
        let competitor = TrustedPeerStore::at(&path);
        assert!(matches!(
            competitor.store(record(3, 0x33, None)).unwrap_err(),
            TrustedPeerStoreError::StoreBusy
        ));
        assert!(matches!(
            competitor.remove(&key(1, 0x11, 32)).unwrap_err(),
            TrustedPeerStoreError::StoreBusy
        ));
        // The durable file is byte-for-byte unchanged.
        assert_eq!(fs::read(&path).unwrap(), durable);
        // Lock-free reads still work through the pinned descriptor.
        assert_eq!(competitor.load().unwrap().len(), 2);

        // Releasing the lock lets the competitor proceed; no stale lock remains.
        drop(guard);
        competitor.store(record(3, 0x33, None)).unwrap();
        assert_eq!(owner.load().unwrap().len(), 3);
    }

    #[test]
    fn a_stale_concurrent_writer_cannot_resurrect_a_removed_record() {
        // Reproduces the lost-update scenario from the review: the lock forces
        // the second mutation to load *after* the first one has fully committed.
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        let store = TrustedPeerStore::at(&path);
        let alice = record(1, 0xaa, Some("Alice"));
        let bob = record(2, 0xbb, Some("Bob"));
        store.store(alice.clone()).unwrap();
        store.store(bob.clone()).unwrap();

        // Process A holds the lock and removes Alice.
        let a = TrustedPeerStore::at(&path);
        let guard = a.hold_exclusive_lock().unwrap();

        // Process B tries to relabel Bob from its own (now soon-to-be-stale)
        // view. It cannot even begin until A is done.
        let b = TrustedPeerStore::at(&path);
        assert!(matches!(
            b.store(TrustedPeerRecord::for_test(key(2, 0xbb, 32), Some("Bob 2")))
                .unwrap_err(),
            TrustedPeerStoreError::StoreBusy
        ));

        // A completes the removal (still under its guard) and releases.
        drop(guard);
        assert_eq!(
            a.remove(alice.identity()).unwrap(),
            TrustedPeerRemoval::Removed
        );

        // Only now can B run, and it necessarily loads the post-removal store.
        b.store(TrustedPeerRecord::for_test(key(2, 0xbb, 32), Some("Bob 2")))
            .unwrap();

        let final_state = store.load().unwrap();
        assert_eq!(final_state.len(), 1);
        assert!(!final_state.contains(alice.identity()));
        assert_eq!(
            final_state
                .get(bob.identity())
                .and_then(TrustedPeerRecord::label)
                .map(TrustedPeerLabel::as_str),
            Some("Bob 2")
        );
    }

    #[test]
    fn a_mutation_error_path_still_releases_the_lock() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        let store = TrustedPeerStore::at(&path);
        for index in 0..MAX_TRUSTED_PEERS {
            store
                .store(record(u16::try_from(index).unwrap(), 0x01, None))
                .unwrap();
        }

        // This mutation fails the capacity check inside `write_all`, after the
        // lock is taken. The `?` unwinds through the RAII guard.
        assert!(matches!(
            store
                .store(record(
                    u16::try_from(MAX_TRUSTED_PEERS).unwrap(),
                    0x01,
                    None
                ))
                .unwrap_err(),
            TrustedPeerStoreError::CapacityExceeded { .. }
        ));

        // The lock is free again: a fresh instance can immediately mutate.
        let other = TrustedPeerStore::at(&path);
        assert_eq!(
            other.remove(&key(0, 0x01, 32)).unwrap(),
            TrustedPeerRemoval::Removed
        );
    }

    // ----- bounded reads and filesystem indirection -----

    #[test]
    fn an_oversized_file_never_forces_an_unbounded_read() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        write_raw(&path, vec![b'x'; MAX_TRUSTED_PEERS_STORE_BYTES * 4]);

        // Rejected via the open-handle metadata check before any large read.
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::StoreTooLarge { size, .. }
                if size as usize == MAX_TRUSTED_PEERS_STORE_BYTES * 4
        ));

        // A file exactly at the limit is read; one byte over is rejected.
        let at_limit = format!(
            "local-transfer-trusted-peers v1\n{}",
            "x".repeat(MAX_TRUSTED_PEERS_STORE_BYTES - "local-transfer-trusted-peers v1\n".len())
        );
        assert_eq!(at_limit.len(), MAX_TRUSTED_PEERS_STORE_BYTES);
        write_raw(&path, &at_limit);
        // (Malformed content, but it was read rather than size-rejected.)
        assert!(matches!(
            TrustedPeerStore::at(&path).load().unwrap_err(),
            TrustedPeerStoreError::MalformedStore { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_store_path_is_rejected_and_never_hardened_through() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempdir().unwrap();
        let real = directory.path().join("real-file");
        fs::write(&real, "local-transfer-trusted-peers v1\n").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();

        let link = directory.path().join("nested/trusted-peers");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&real, &link).unwrap();

        // Production hardening path is on; it must not chmod the link target.
        let store = TrustedPeerStore {
            path: link.clone(),
            harden_existing_parent: true,
        };
        assert!(matches!(
            store.load().unwrap_err(),
            TrustedPeerStoreError::SymlinkNotAllowed { .. }
        ));
        assert!(matches!(
            store.store(record(1, 0x01, None)).unwrap_err(),
            TrustedPeerStoreError::SymlinkNotAllowed { .. }
        ));
        // The link target keeps its original loose permissions -- untouched.
        assert_eq!(
            fs::metadata(&real).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_lock_path_is_rejected() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let elsewhere = directory.path().join("elsewhere");
        fs::write(&elsewhere, "x").unwrap();
        let path = directory.path().join("nested/trusted-peers");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        symlink(&elsewhere, path.with_file_name("trusted-peers.lock")).unwrap();

        assert!(matches!(
            TrustedPeerStore::at(&path)
                .store(record(1, 0x01, None))
                .unwrap_err(),
            TrustedPeerStoreError::SymlinkNotAllowed { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn the_lock_file_and_its_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempdir().unwrap();
        let path = directory.path().join("nested/trusted-peers");
        TrustedPeerStore::at(&path)
            .store(record(1, 0x01, None))
            .unwrap();

        let lock = path.with_file_name("trusted-peers.lock");
        assert_eq!(
            fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(lock.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}
