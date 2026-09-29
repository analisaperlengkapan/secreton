//! Secreton Storage Abstraction Layer
//!
//! Provides unified interface for different storage backends including
//! PostgreSQL, Redis, file-based storage, and Raft integrated storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

pub mod backends;
pub mod cache;
pub mod factory;
pub mod models;
#[cfg(test)]
pub(crate) mod test_support;

#[cfg(feature = "postgres")]
pub use backends::PostgresBackend;
#[cfg(feature = "redis")]
pub use backends::RedisBackend;
pub use backends::{FileBackend, MemoryBackend};
#[cfg(feature = "raft")]
pub use backends::{RaftConfig, RaftStorageBackend};

pub use factory::{StorageBackendType, StorageFactory, StorageFactoryConfig};

use secreton_domain::OAuthState;

/// Encryption metadata for secreton entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key ID used for encryption
    pub key_id: String,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Authentication tag for AEAD ciphers.
    /// Note: For AES-GCM and ChaCha20-Poly1305 as implemented in `secreton_crypto`,
    /// the auth tag is appended to the ciphertext by the underlying crates, so this
    /// field is `None`. It is kept for ciphers that produce a separate tag.
    pub auth_tag: Option<Vec<u8>>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    /// Key derivation parameters
    pub kdf_params: Option<HashMap<String, String>>,
}

/// Security classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Public information - no security controls required
    Public = 0,
    /// Internal use - basic access controls
    Internal = 1,
    /// Confidential - restricted access
    Confidential = 2,
    /// Secret - highly restricted access
    Secret = 3,
    /// Top Secret - maximum security controls
    TopSecret = 4,
}

/// Secret entry for storing secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Unique identifier for the entry
    pub id: Uuid,
    /// Path to the secret
    pub path: String,
    /// Encrypted secret data
    pub encrypted_data: Vec<u8>,
    /// Encryption metadata
    pub encryption_metadata: EncryptionMetadata,
    /// Security level of the data
    pub security_level: SecurityLevel,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Version number
    pub version: u32,
    /// Owner of the entry
    pub owner_id: Uuid,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretEntry {
    /// Create a new secreton entry
    pub fn new(
        path: String,
        encrypted_data: Vec<u8>,
        encryption_metadata: EncryptionMetadata,
        security_level: SecurityLevel,
        owner_id: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            path,
            encrypted_data,
            encryption_metadata,
            security_level,
            metadata: HashMap::new(),
            tags: Vec::new(),
            version: 1,
            owner_id,
            created_at: now,
            updated_at: now,
            expires_at: None,
        }
    }

    /// Check if the entry is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add metadata
    pub fn add_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add tag
    pub fn add_tag(mut self, tag: String) -> Self {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }

    /// Tag this entry with the identifier of the operation that owns it.
    ///
    /// Used by [`StorageBackend::compare_and_set`] and
    /// [`StorageBackend::delete_owned`] as the fencing token: a conditional write or a
    /// conditional delete only applies while the record still carries this value. The
    /// token identifies an attempt, never a user, secret or credential, and is stored in
    /// the entry's ordinary metadata map so every backend already persists it.
    pub fn owned_by(mut self, token: &str) -> Self {
        self.metadata
            .insert(OWNER_TOKEN_KEY.to_string(), token.to_string());
        self
    }

    /// The owner token recorded by [`Self::owned_by`], if any.
    pub fn owner_token(&self) -> Option<&str> {
        self.metadata.get(OWNER_TOKEN_KEY).map(String::as_str)
    }

    /// Whether this entry is owned by `token`.
    pub fn has_owner(&self, token: &str) -> bool {
        self.owner_token() == Some(token)
    }
}

/// Metadata key under which [`SecretEntry::owned_by`] records its owner token.
pub const OWNER_TOKEN_KEY: &str = "storage_owner";

/// Metadata key under which a fenced record records its own absolute deadline, in Unix
/// seconds.
///
/// A fence is evaluated as "the record still exists and still carries this token". That is
/// not the whole of holding a lease: the lease also carries an expiry, and a holder whose
/// deadline has passed no longer legitimately holds it even if no replacement has taken it
/// over yet. The expiry lives in the record's *body* (which the caller encrypts), so a
/// backend cannot read it and an owner-only fence would authorise a write from a lease that
/// has already lapsed. Recording the deadline in this ordinary metadata key — persisted by
/// every backend alongside the owner token — is what lets the fence reject it *in the same
/// indivisible step* as the token check. See [`lease_has_not_expired`].
pub const LEASE_EXPIRES_AT_KEY: &str = "lease_expires_at";

/// Whether the fenced record's recorded lease deadline is still in the future at `now`
/// (Unix seconds).
///
/// Fails closed: a record that records no deadline, or a value that does not parse as an
/// integer, is treated as expired. A fence must never authorise a write it cannot prove is
/// backed by a live lease, and "missing" is the absence of that proof, not permission.
pub fn lease_has_not_expired(entry: &SecretEntry, now: i64) -> bool {
    match entry
        .metadata
        .get(LEASE_EXPIRES_AT_KEY)
        .and_then(|value| value.parse::<i64>().ok())
    {
        Some(expires_at) => expires_at > now,
        None => false,
    }
}

/// Precondition for [`StorageBackend::compare_and_set`].
///
/// The variants are the whole contract: a caller states what must already be true at the
/// path, and the backend performs the check and the write as one indivisible step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect<'a> {
    /// No record may exist at the path. This is insert-if-absent.
    Absent,
    /// No record may exist at `entry.path`, *and* the record at `fence.path` must still
    /// carry `fence.token` — the two checks and the write are one indivisible step.
    ///
    /// This is the conjunction of [`Self::Absent`] and [`StorageBackend::store_fenced`],
    /// and it exists because a caller can need both at once. Creating the bootstrap root
    /// identity is exactly that case: the account must be insert-if-absent so it cannot
    /// overwrite a concurrently registered user, and it must be fenced on the
    /// initialization lease so an attempt that has already lost the lease cannot create a
    /// privileged account at all. Expressing them as one call is what makes the pair
    /// atomic; a caller that performed `compare_and_set(Absent)` and then `store_fenced`
    /// would reopen the very window between the two that the fence closes.
    AbsentFenced(StorageFence<'a>),
    /// The record at the path must carry this exact owner token.
    Owner(&'a str),
    /// The record at the path must carry this exact owner token **and** its recorded lease
    /// deadline must still be in the future — checked against the backend's own clock, in
    /// the same indivisible step as the write.
    ///
    /// This is [`Self::Owner`] with the deadline check folded in, and it exists because
    /// [`Self::Owner`] alone is not enough to renew a lease. A renewal that reads the lease,
    /// observes it live, and then writes it back is a read-then-write: an arbitrary window —
    /// a scheduling pause, a slow round trip, a lock the writer waited on — separates the two,
    /// and the lease can lapse inside it. Replacing the record is conditioned only on the
    /// token, which a lapsed-but-not-yet-taken-over lease still carries, so the owner-conditional
    /// write silently extends a deadline the holder had already exceeded. A second replica that
    /// read the expiry in that window and is taking the lease over then races an attempt that
    /// believes it still holds a live lease — the overlap the lease exists to prevent.
    ///
    /// Folding the deadline check into the precondition, evaluated in the same atomic step as
    /// the write, closes that window: the write lands only if the record is both owned and
    /// still live at the instant it is replaced, and a lapsed lease is never revived. Fails
    /// closed on a missing or unparseable deadline, exactly as [`LEASE_EXPIRES_AT_KEY`] does.
    UnexpiredOwner(&'a str),
    /// The record at the path must carry this exact owner token **and** its own recorded
    /// expiration (`expires_at`) must already have passed — checked against the backend's
    /// own clock, in the same indivisible step as the write.
    ///
    /// This is [`Self::Owner`] with the opposite deadline condition, and it exists because a
    /// read-then-replace is not enough to reclaim a lapsed reservation. A caller that reads
    /// an expired claim, confirms its owner, and then replaces it with an owner-conditional
    /// write can be overtaken between the read and the write: another reader also sees the
    /// record expired, the original owner extends it back to life (the extension is an
    /// owner-conditional *replacement* that does not change the owner token), and the
    /// reclaimer's write — conditioned only on the token, which the extended record still
    /// carries — then replaces a live claim. The record that had just been extended is gone,
    /// and the token it guarded can be exchanged a second time.
    ///
    /// Folding "still expired" into the precondition closes that window: the takeover lands
    /// only while the record is both owned and unexpired-free at the instant it is replaced,
    /// so a claim that became live in between is left alone and the reclaimer reports
    /// `Ok(false)`. Fails closed on a record with no `expires_at`, exactly as it treats a
    /// live record: "missing" is not proof of expiry.
    ExpiredOwner(&'a str),
    /// No precondition. The write is still a single atomic replacement, which is what
    /// distinguishes it from a read followed by a separate `store`.
    Any,
}

impl<'a> Expect<'a> {
    /// The fence to evaluate alongside the precondition, if this variant carries one.
    ///
    /// Backends that support [`Self::AbsentFenced`] consult this; the ones that cannot make
    /// a fenced write indivisible return [`StorageError::Unsupported`] rather than silently
    /// ignoring the fence, which would replace a locked write with an unlocked one.
    pub fn fence(&self) -> Option<StorageFence<'a>> {
        match self {
            Expect::AbsentFenced(fence) => Some(*fence),
            _ => None,
        }
    }
}

/// A cross-process fencing token: the durable record a write must still be holding.
///
/// `check()`-then-write is not a guarantee. A snapshot of "I still own the lease" taken in
/// one process says nothing about durable state by the time the next write lands, and the
/// two are separated by an arbitrary window — a renewal that failed, a lease that expired
/// and was taken over, a holder that lost a race it never observed. The only way to close
/// that window is to make the write itself conditional on the fence *in the shared
/// backend*, which is what [`StorageBackend::store_fenced`] does with this value.
///
/// It names the path and the owner token of the record that must still be present and
/// still carry that token for the write to happen. Initialization fences on the lease
/// record, not on the artifact's own token: an artifact's token is self-asserted by the
/// writer and proves nothing, whereas the lease is the record a *winner* also has to hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageFence<'a> {
    /// Path of the record that must still exist and still be owned.
    pub path: &'a str,
    /// The owner token that record must still carry.
    pub token: &'a str,
}

impl<'a> StorageFence<'a> {
    pub fn new(path: &'a str, token: &'a str) -> Self {
        Self { path, token }
    }
}

/// What coordination a backend can actually provide between callers.
///
/// This is a property of the backend, not a configuration knob, and it is what lets the
/// seal service decide whether an operation needs a cross-process lease or can rely on its
/// in-process mutex alone. A durable backend that two replicas may share must report
/// [`Coordination::CrossProcess`] and implement [`StorageBackend::compare_and_set`],
/// [`StorageBackend::delete_owned`] and [`StorageBackend::store_fenced`] for real; a backend
/// that is inherently process-local reports [`Coordination::SingleProcess`], and the caller
/// treats its in-process lock as the whole guarantee rather than inventing a fake
/// cross-process one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coordination {
    /// Guarantees hold only within one process. Every `MemoryBackend` is a distinct map
    /// and the single-node Raft state machine lives in memory, so neither can be shared
    /// between replicas at all.
    SingleProcess,
    /// The backend can arbitrate between processes that share it, through
    /// `compare_and_set`/`delete_owned`. Durable stores fall here.
    CrossProcess,
}

impl Default for EncryptionMetadata {
    fn default() -> Self {
        Self {
            algorithm: "plaintext".to_string(),
            key_id: String::new(),
            iv: Vec::new(),
            auth_tag: None,
            aad: None,
            kdf_params: None,
        }
    }
}

/// Query parameters for filtering secreton entries
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    /// Filter by path prefix
    pub path_prefix: Option<String>,

    /// Exclude entries whose path starts with any of these prefixes.
    ///
    /// Used by the lifecycle sweep to skip reserved namespaces (e.g. `sys/`,
    /// `keys/`) at the storage layer instead of paying for them with the
    /// query's `limit` budget. Backends that ignore this field are not
    /// incorrect — callers must still apply their own in-memory exclusion as
    /// a fallback — but on backends that honor it (e.g. PostgreSQL), reserved
    /// entries no longer consume rows from `limit`.
    pub excluded_path_prefixes: Vec<String>,

    /// Filter by security level (minimum)
    pub security_level: Option<SecurityLevel>,

    /// Filter by tags
    pub tags: Vec<String>,

    /// Filter by owner
    pub owner_id: Option<Uuid>,

    /// Filter by metadata
    pub metadata_filters: HashMap<String, String>,

    /// Include expired entries
    pub include_expired: bool,

    /// Maximum number of results
    pub limit: Option<u32>,

    /// Results offset
    pub offset: Option<u32>,

    /// Sort order
    pub sort_by: Option<String>,

    /// Sort direction (asc/desc)
    pub sort_order: Option<String>,
}

impl QueryParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path_prefix(mut self, prefix: String) -> Self {
        self.path_prefix = Some(prefix);
        self
    }

    pub fn with_excluded_path_prefixes<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excluded_path_prefixes = prefixes.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = Some(level);
        self
    }

    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn with_owner(mut self, owner_id: Uuid) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Apply this query's filters, sort and pagination to an in-memory slice.
    ///
    /// A backend that cannot express a filter server-side (Redis enumerates by scanning)
    /// uses this so its results match the backends that can, rather than returning
    /// everything and leaving the caller to notice.
    pub fn apply_to(&self, mut entries: Vec<SecretEntry>) -> Vec<SecretEntry> {
        entries.retain(|entry| {
            if let Some(prefix) = &self.path_prefix
                && !entry.path.starts_with(prefix)
            {
                return false;
            }
            if self
                .excluded_path_prefixes
                .iter()
                .any(|p| entry.path.starts_with(p))
            {
                return false;
            }
            if let Some(min_level) = self.security_level
                && entry.security_level < min_level
            {
                return false;
            }
            if !self.tags.is_empty() {
                let entry_tags: std::collections::HashSet<_> = entry.tags.iter().collect();
                let filter_tags: std::collections::HashSet<_> = self.tags.iter().collect();
                if !filter_tags.is_subset(&entry_tags) {
                    return false;
                }
            }
            if let Some(owner_id) = self.owner_id
                && entry.owner_id != owner_id
            {
                return false;
            }
            for (key, value) in &self.metadata_filters {
                if entry.metadata.get(key) != Some(value) {
                    return false;
                }
            }
            if !self.include_expired && entry.is_expired() {
                return false;
            }
            true
        });

        if let Some(sort_by) = &self.sort_by {
            let descending = self
                .sort_order
                .as_deref()
                .is_some_and(|o| o.eq_ignore_ascii_case("desc"));
            if sort_by == "expires_at" {
                // Rank by the entry's own `expires_at`, not by a metadata lookup. The
                // lifecycle sweep orders by `expires_at` precisely so a `limit` keeps the
                // records closest to expiry: without this branch the sweep fell through to
                // the metadata fallback, every entry keyed `""`, and the sort became a no-op
                // — so the limit truncated arbitrary records and expired secrets past the
                // cutoff were never swept. A `None` deadline means "never expires", which
                // must sort last ascending rather than first.
                entries.sort_by(|a, b| {
                    match (a.expires_at, b.expires_at) {
                        (Some(x), Some(y)) => x.cmp(&y),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => std::cmp::Ordering::Equal,
                    }
                    // Tie-break on the id, matching the PostgreSQL backend's `, id ASC`. Two
                    // records with the same deadline are otherwise ordered by the incoming
                    // (arbitrary) order, so a paginated query could repeat or skip a record.
                    .then_with(|| a.id.cmp(&b.id))
                });
            } else if sort_by == "security_level" {
                // Compare the level as its integer discriminant, matching the PostgreSQL
                // backend's integer `security_level` column. Stringifying it would order
                // "10" before "9", so the two backends would disagree on the same page as
                // soon as a level above 9 exists. The id tie-break matches PostgreSQL's
                // `, id <dir>`.
                entries.sort_by(|a, b| {
                    (a.security_level as i32)
                        .cmp(&(b.security_level as i32))
                        .then_with(|| a.id.cmp(&b.id))
                });
            } else {
                let key = |entry: &SecretEntry| match sort_by.as_str() {
                    "path" => entry.path.clone(),
                    "created_at" => entry.created_at.to_rfc3339(),
                    "updated_at" => entry.updated_at.to_rfc3339(),
                    other => entry.metadata.get(other).cloned().unwrap_or_default(),
                };
                entries.sort_by(|a, b| key(a).cmp(&key(b)).then_with(|| a.id.cmp(&b.id)));
            }
            if descending {
                entries.reverse();
            }
        }

        let offset = self.offset.unwrap_or(0) as usize;
        if offset > 0 {
            entries.drain(..offset.min(entries.len()));
        }
        if let Some(limit) = self.limit {
            entries.truncate(limit as usize);
        }
        entries
    }
}

/// Storage operation errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Query failed: {message}")]
    QueryFailed { message: String },

    #[error("Transaction failed: {message}")]
    TransactionFailed { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Not found: {resource_type} with ID {id}")]
    NotFound { resource_type: String, id: String },

    #[error("Duplicate entry: {resource_type} with ID {id}")]
    Duplicate { resource_type: String, id: String },

    #[error("Constraint violation: {constraint} - {message}")]
    ConstraintViolation { constraint: String, message: String },

    #[error("Permission denied for operation: {operation}")]
    PermissionDenied { operation: String },

    #[error("Storage backend error: {backend} - {message}")]
    BackendError { backend: String, message: String },

    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },

    #[error("Migration error: {message}")]
    MigrationError { message: String },

    /// The backend cannot provide an operation with the guarantee its contract names.
    ///
    /// Returned instead of silently degrading, so a caller that needs atomicity or
    /// cross-process coordination fails loudly rather than building on a promise the
    /// backend did not keep.
    #[error("Unsupported operation: {operation} is not supported by the {backend} backend")]
    Unsupported { operation: String, backend: String },
}

impl StorageError {
    /// Whether this error means a precondition did not hold rather than that storage
    /// failed.
    ///
    /// [`StorageBackend::compare_and_set`] normally reports a lost race as `Ok(false)`, but
    /// a backend whose precondition is a database constraint may surface it as an error
    /// instead. A caller that registered an identity and must tell "someone else already
    /// took this name" apart from "storage is broken" needs that distinction, and a storage
    /// outage must never be reported to a user as "already exists". Only errors a backend
    /// raises specifically for a failed precondition are classified here; a generic
    /// [`Self::QueryFailed`] or [`Self::ConnectionFailed`] is not, so it cannot masquerade
    /// as a duplicate.
    pub fn is_precondition_failure(&self) -> bool {
        matches!(self, StorageError::Duplicate { .. })
    }
}

// impl From<azure_storage::Error> for StorageError {
//     fn from(error: azure_storage::Error) -> Self {
//         StorageError::BackendError {
//             backend: "Azure Blob Storage".to_string(),
//             message: error.to_string(),
//         }
//     }
// }

// impl From<google_cloud_storage::Error> for StorageError {
//     fn from(error: google_cloud_storage::Error) -> Self {
//         StorageError::BackendError {
//             backend: "Google Cloud Storage".to_string(),
//             message: error.to_string(),
//         }
//     }
// }

/// Type alias for Results with StorageError
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage backend trait for different implementations
#[async_trait]
pub trait StorageBackend: std::fmt::Debug + Send + Sync {
    /// Store a secreton entry
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()>;

    /// Retrieve a secreton entry by ID
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>>;

    /// Retrieve a secreton entry by path
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>>;

    /// Update an existing secreton entry
    async fn update(&self, entry: &SecretEntry) -> StorageResult<()>;

    /// Store an entry, replacing any existing entry at the same path.
    ///
    /// `store` is an insert: the backends disagree about what a second write to the same
    /// path does. In-memory and the file backend overwrite silently; PostgreSQL has a
    /// `UNIQUE(path)` constraint and the insert fails, and Raft's replicated store would
    /// likewise create a second record for one path. A caller that can write the same path
    /// twice — such as initialization recording its progress — therefore cannot use
    /// `store` portably.
    ///
    /// This is the portable replacement, expressed only in terms of the two operations
    /// every backend implements: it looks the path up, and either `update`s the entry that
    /// is already there (keeping its id and creation time so `update`, which is keyed by
    /// id on PostgreSQL and by path on the others, targets the same record) or `store`s a
    /// new one. It is a read-then-write and so not atomic; the trait offers no
    /// compare-and-swap, and the seal service serializes its own writes on top of it.
    async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
        match self.get_by_path(&entry.path).await? {
            Some(existing) => {
                let mut updated = entry.clone();
                updated.id = existing.id;
                updated.created_at = existing.created_at;
                self.update(&updated).await
            }
            None => self.store(entry).await,
        }
    }

    /// Delete a secreton entry by ID
    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool>;

    /// What coordination this backend can provide between separate processes.
    ///
    /// Callers that need cross-process serialisation — initialization on a durable backend
    /// two replicas may share — must consult this and refuse to proceed when it is
    /// [`Coordination::SingleProcess`], rather than trusting an in-process mutex that the
    /// other replica does not hold. See [`Coordination`].
    fn coordination(&self) -> Coordination {
        Coordination::SingleProcess
    }

    /// Delete a secreton entry by path.
    ///
    /// The `bool` answers exactly one question: **did a record at this path exist and get
    /// removed by this call?** `Ok(true)` means this call removed it; `Ok(false)` means no
    /// record was there to remove. It is not a statement that the path is now absent: a
    /// backend that attempts the removal but fails reports the same `false` as one that
    /// found nothing. A caller that needs "the path is now gone" must read it back rather
    /// than trust `false`; a caller that needs "my record was removed" must use
    /// [`Self::delete_owned`], which is conditional and therefore meaningful even when
    /// this operation cannot report what happened.
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool>;

    /// Atomically write `entry` at its path, but only if `expect` still holds.
    ///
    /// This is the compare-and-set the trait otherwise lacks. It is expressed with an
    /// explicit precondition so a caller can build an inter-process lock or a fenced
    /// update without a read-then-write window: `Expect::Absent` is insert-if-absent,
    /// `Expect::Owner(token)` is "replace the record I still own".
    ///
    /// Returns `Ok(true)` when the write happened and `Ok(false)` when the precondition
    /// did not hold — the caller lost the race and must not treat its own state as
    /// committed. An error is a real storage failure, not a lost race.
    ///
    /// The default implementation is deliberately **not** atomic and refuses the two uses
    /// that need atomicity, because a silently non-atomic default is how a fake lock
    /// ships. Backends that can make the operation genuinely indivisible override this;
    /// the ones that cannot return [`StorageError::Unsupported`], and callers that require
    /// coordination must treat that as a hard stop rather than fall back.
    async fn compare_and_set(
        &self,
        entry: &SecretEntry,
        expect: Expect<'_>,
    ) -> StorageResult<bool> {
        let _ = (entry, expect);
        Err(StorageError::Unsupported {
            operation: "compare_and_set".to_string(),
            backend: "default".to_string(),
        })
    }

    /// Atomically write `entry` at its path, but only while `fence` still holds.
    ///
    /// This is the primitive that closes the `check()`-then-write window. A caller that has
    /// taken a lease reads it in one step and writes an artifact in another; between those
    /// steps the lease can expire, a renewal can fail, or a second process can legitimately
    /// take it over. The check on its own cannot see any of that. This operation asks the
    /// shared backend to evaluate the fence and perform the write **as one indivisible
    /// step**, so the write either happens while the caller demonstrably still holds the
    /// record, or it does not happen at all.
    ///
    /// Returns `Ok(true)` when the write landed and `Ok(false)` when the fence did not hold
    /// — the caller has lost ownership and must treat its own attempt as failed rather than
    /// published. An `Err` is a real storage failure. Neither of the non-`true` outcomes
    /// authorises a fallback to an unconditional write: failing to prove ownership is the
    /// answer, and the operation must fail closed.
    ///
    /// The default refuses, for the same reason [`Self::compare_and_set`] does: a
    /// read-then-write default is exactly the race this exists to exclude, and a silent
    /// non-atomic implementation is how a fake lock ships. A backend that reports
    /// [`Coordination::CrossProcess`] must override this for real.
    async fn store_fenced(
        &self,
        entry: &SecretEntry,
        fence: StorageFence<'_>,
    ) -> StorageResult<bool> {
        let _ = (entry, fence);
        Err(StorageError::Unsupported {
            operation: "store_fenced".to_string(),
            backend: "default".to_string(),
        })
    }

    /// Delete the record at `path`, but only while it is still owned by `token`.
    ///
    /// Rollback and cleanup must never delete an artifact another attempt now owns, and a
    /// path that has since been rewritten by someone else must survive. Returns
    /// `Ok(true)` only when this call removed a record still carrying `token`;
    /// `Ok(false)` means the record was absent *or* no longer owned by `token`, and in
    /// either case this call removed nothing. `Ok(false)` therefore never authorises
    /// cleanup to claim a path is gone — read it back.
    ///
    /// Like [`Self::compare_and_set`], the default refuses rather than pretending to be
    /// conditional: a read-then-delete would race exactly the writer this exists to exclude.
    async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
        let _ = (path, token);
        Err(StorageError::Unsupported {
            operation: "delete_owned".to_string(),
            backend: "default".to_string(),
        })
    }

    /// List secreton entries with filtering
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>>;

    /// Count secreton entries matching query.
    ///
    /// This counts *what `list` would return for the same params*, pagination included: the
    /// `limit` and `offset` are applied here exactly as they are there. Memory, file and Redis
    /// already define `count` as `list(params).len()`, and the lifecycle sweep and session
    /// churn checks depend on the two methods agreeing on the same page. A backend that
    /// ignored pagination here would report a total the caller never receives, so a sweep
    /// that sizes its work from `count` would over- or under-read.
    async fn count(&self, params: &QueryParams) -> StorageResult<u64>;

    /// Check if path exists
    async fn exists(&self, path: &str) -> StorageResult<bool>;

    /// Begin a transaction
    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>>;

    /// Perform health check
    async fn health_check(&self) -> StorageResult<HealthStatus>;

    /// Get storage statistics
    async fn get_stats(&self) -> StorageResult<StorageStats>;

    /// Run migrations
    async fn migrate(&self) -> StorageResult<()>;

    /// Compact the storage backend to reclaim space
    async fn compact(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Perform a vacuum/cleanup operation on the database
    async fn vacuum(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Delete expired entries
    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let params = QueryParams {
            path_prefix,
            include_expired: true,
            ..Default::default()
        };

        let entries = self.list(&params).await?;
        let mut deleted_count = 0;
        let now = Utc::now();

        for entry in entries {
            if let Some(expires_at) = entry.expires_at
                && expires_at < now
                && self.delete_by_id(entry.id).await?
            {
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    /// Delete a secret entry directly by path (convenience wrapper for delete_by_path)
    async fn delete_secret(&self, path: &str) -> StorageResult<bool> {
        self.delete_by_path(path).await
    }

    /// Store OAuth state.
    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()>;

    /// Retrieve and consume OAuth state.
    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>>;

    /// Delete expired OAuth states.
    async fn delete_expired_oauth_states(&self) -> StorageResult<u64>;
}

/// Transaction interface for atomic operations
#[async_trait]
pub trait StorageTransaction: std::fmt::Debug + Send + Sync {
    /// Store entry within transaction
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()>;

    /// Update entry within transaction
    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()>;

    /// Delete entry within transaction
    async fn delete(&mut self, id: Uuid) -> StorageResult<bool>;

    /// Commit the transaction
    async fn commit(self: Box<Self>) -> StorageResult<()>;

    /// Rollback the transaction
    async fn rollback(self: Box<Self>) -> StorageResult<()>;
}

/// Storage health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub response_time_ms: f64,
    pub connections_active: u32,
    pub connections_idle: u32,
    pub last_error: Option<String>,
    pub uptime_seconds: u64,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_entries: u64,
    pub total_size_bytes: u64,
    pub average_entry_size: f64,
    pub entries_by_security_level: HashMap<SecurityLevel, u64>,
    pub entries_created_today: u64,
    pub entries_updated_today: u64,
    pub expired_entries: u64,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type (postgres, redis, file)
    pub backend_type: String,

    /// Connection string or path
    pub connection_string: String,

    /// Connection pool settings
    pub pool_settings: PoolSettings,

    /// Encryption settings
    pub encryption_enabled: bool,

    /// Compression settings
    pub compression_enabled: bool,

    /// Backup settings
    pub backup_enabled: bool,

    /// Cache settings
    pub cache_enabled: bool,
}

/// Connection pool settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            connection_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_secreton_entry_initialization_defaults() {
        let owner = Uuid::new_v4();
        let entry = SecretEntry::new(
            "secret/path".to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-123".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Secret,
            owner,
        );

        assert_eq!(entry.path, "secret/path");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.security_level, SecurityLevel::Secret);
        assert_eq!(entry.owner_id, owner);
        assert!(entry.metadata.is_empty());
        assert!(entry.tags.is_empty());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_secreton_entry_tag_and_metadata_helpers() {
        let owner = Uuid::new_v4();
        let entry = SecretEntry::new(
            "secret/path".to_string(),
            vec![],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-123".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Confidential,
            owner,
        )
        .add_metadata("env".to_string(), "prod".to_string())
        .add_metadata("region".to_string(), "apac".to_string())
        .add_tag("finance".to_string())
        .add_tag("finance".to_string())
        .add_tag("internal".to_string());

        assert_eq!(entry.metadata.get("env"), Some(&"prod".to_string()));
        assert_eq!(entry.metadata.get("region"), Some(&"apac".to_string()));

        let tag_set: HashSet<String> = entry.tags.iter().cloned().collect();
        assert_eq!(tag_set.len(), 2);
        assert!(tag_set.contains("finance"));
        assert!(tag_set.contains("internal"));
    }

    #[test]
    fn test_query_params_helpers() {
        let owner = Uuid::new_v4();
        let params = QueryParams::new()
            .with_path_prefix("apps/".to_string())
            .with_security_level(SecurityLevel::Internal)
            .with_tag("pci".to_string())
            .with_tag("finance".to_string())
            .with_owner(owner)
            .with_limit(50);

        assert_eq!(params.path_prefix.as_deref(), Some("apps/"));
        assert_eq!(params.security_level, Some(SecurityLevel::Internal));
        assert_eq!(params.tags.len(), 2);
        assert_eq!(params.owner_id, Some(owner));
        assert_eq!(params.limit, Some(50));
    }

    #[test]
    fn test_storage_error_debug_and_display() {
        let error = StorageError::NotFound {
            resource_type: "secreton_entry".to_string(),
            id: "123".to_string(),
        };

        let display = format!("{}", error);
        assert!(display.contains("Not found"));
        assert!(display.contains("secreton_entry"));
        assert!(display.contains("123"));

        let debug = format!("{:?}", error);
        assert!(debug.contains("NotFound"));
    }

    fn query_entry(path: &str, expires_in_minutes: Option<i64>) -> SecretEntry {
        let mut entry = SecretEntry::new(
            path.to_string(),
            vec![1, 2, 3],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        );
        entry.expires_at = expires_in_minutes.map(|m| Utc::now() + chrono::Duration::minutes(m));
        entry
    }

    #[test]
    fn expires_at_sort_orders_by_the_entries_own_deadline() {
        // `expires_at` is not a metadata key, so it used to fall through to the metadata
        // fallback, keying every entry `""` and leaving the ordering untouched. The
        // lifecycle sweep relies on this ordering to keep the records closest to expiry
        // inside its `limit`, so a no-op sort silently made the sweep miss expired secrets.
        let far = query_entry("kv/far", Some(10_000));
        let near = query_entry("kv/near", Some(1));
        let never = query_entry("kv/never", None);

        let params = QueryParams {
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            include_expired: true,
            ..Default::default()
        };

        let ordered = params.apply_to(vec![never.clone(), far.clone(), near.clone()]);
        let paths: Vec<&str> = ordered.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["kv/near", "kv/far", "kv/never"],
            "ascending `expires_at` must order by the real deadline with no-deadline last"
        );

        let params_desc = QueryParams {
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("desc".to_string()),
            include_expired: true,
            ..Default::default()
        };
        let ordered_desc = params_desc.apply_to(vec![never, far, near]);
        let paths: Vec<&str> = ordered_desc.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["kv/never", "kv/far", "kv/near"]);
    }

    #[test]
    fn excluded_prefixes_are_applied_before_the_limit_truncates() {
        // The sweep asks for reserved namespaces to be excluded *and* a limit while sorting
        // by expiry. A backend that counts reserved entries against the limit truncates live
        // records before the expired one, so the expired secret is never returned and never
        // swept.
        let expired = query_entry("apps/expired", Some(-1));
        let reserved: Vec<SecretEntry> = (0..5)
            .map(|i| query_entry(&format!("sys/reserved/{i}"), None))
            .collect();

        let params = QueryParams {
            include_expired: true,
            limit: Some(2),
            sort_by: Some("expires_at".to_string()),
            sort_order: Some("asc".to_string()),
            excluded_path_prefixes: vec!["sys/".to_string()],
            ..Default::default()
        };

        let mut all = reserved.clone();
        all.push(expired.clone());
        let listed = params.apply_to(all);

        assert!(
            listed.iter().any(|e| e.path == "apps/expired"),
            "the expired user secret must survive the limit once reserved entries are \
             excluded first; got {:?}",
            listed.iter().map(|e| e.path.as_str()).collect::<Vec<_>>()
        );
        assert!(
            listed.iter().all(|e| !e.path.starts_with("sys/")),
            "reserved entries must not be returned at all"
        );
    }

    #[test]
    fn security_level_sort_is_numeric_and_matches_postgres() {
        // `security_level` used `sort_by_key` on the enum, which orders by discriminant, but
        // PostgreSQL orders its integer `security_level` column — so the two backends agreed
        // only by accident of the variant order. A `sort_by` of that name also used to fall
        // through to the metadata fallback in `apply_to`. Pin the numeric ordering and the
        // id tie-break that PostgreSQL adds with `, id <dir>`.
        let mut low = query_entry("kv/low", None);
        low.security_level = SecurityLevel::Public;
        low.id = Uuid::from_u128(2);
        let mut high = query_entry("kv/high", None);
        high.security_level = SecurityLevel::TopSecret;
        high.id = Uuid::from_u128(1);
        // A record above 9 in a hypothetical expansion: string comparison would order it
        // before a two-digit level and diverge from the integer column.
        let mut mid = query_entry("kv/mid", None);
        mid.security_level = SecurityLevel::Confidential;
        mid.id = Uuid::from_u128(3);

        let params = QueryParams {
            sort_by: Some("security_level".to_string()),
            sort_order: Some("asc".to_string()),
            ..Default::default()
        };
        let ordered = params.apply_to(vec![high.clone(), low.clone(), mid.clone()]);
        let paths: Vec<&str> = ordered.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["kv/low", "kv/mid", "kv/high"],
            "ascending `security_level` must order by the numeric level"
        );
    }

    #[test]
    fn equal_sort_keys_are_broken_by_id_like_postgres() {
        // Two records sharing the sort key are otherwise ordered by the arbitrary incoming
        // order, which can differ between backends and between queries — so pagination can
        // repeat or skip a record. PostgreSQL appends `, id <dir>`; `apply_to` must too.
        let mut a = query_entry("kv/a", None);
        a.id = Uuid::from_u128(30);
        let mut b = query_entry("kv/b", None);
        b.id = Uuid::from_u128(10);
        let mut c = query_entry("kv/c", None);
        c.id = Uuid::from_u128(20);
        // Force the sort keys equal so only the tie-break decides the order, and present the
        // records in a non-id order so a stable sort on the incoming order would differ.
        let stamp = a.created_at;
        b.created_at = stamp;
        c.created_at = stamp;

        let params = QueryParams {
            sort_by: Some("created_at".to_string()),
            sort_order: Some("asc".to_string()),
            ..Default::default()
        };
        let ordered = params.apply_to(vec![a.clone(), b.clone(), c.clone()]);
        let ids: Vec<Uuid> = ordered.iter().map(|e| e.id).collect();
        assert_eq!(
            ids,
            vec![b.id, c.id, a.id],
            "equal sort keys must tie-break on the id, matching PostgreSQL's `, id ASC`"
        );
    }
}
