//! Secret service for business logic operations.

use anyhow::Result;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

use crate::performance::{AccessType, SecretPerformanceOptimizer};
use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::crypto::CryptoService;
use secreton_auth::policies::service::PolicyService;
use secreton_auth::{IdentityService, policies::model::EvaluationContext};
use secreton_crypto::EncryptedData;
use secreton_storage::StorageBackend;
use uuid::Uuid;

/// Policy metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyMetadata {
    pub description: Option<String>,
    pub created_by: String,
    pub owner: Option<String>,
    pub tags: std::collections::HashMap<String, String>,
}

/// Secret metadata
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct SecretMetadata {
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub classification: Option<String>,
}

/// Signing result
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignResult {
    pub signature: String,
    pub key_version: u32,
    pub algorithm: String,
}

/// Exact paths the seal service owns and writes directly through the storage backend.
///
/// The secret API resolves a path to whatever record is newest at it, so an ordinary write
/// to one of these names would silently replace an initialization artifact — or race the
/// initialization that is writing it. `store`/`upsert` on the file backend are not serialised
/// by the advisory lock the seal's fenced writes hold, so a concurrent ordinary write could
/// interleave with `init` and publish over its config, root key, staging marker, lease or
/// root identity. Rejecting these paths at the secret API boundary keeps initialization
/// artifacts reachable only by the seal service, which is the only writer that fences them.
const RESERVED_INITIALIZATION_PATHS: &[&str] = &[
    "sys/init",
    "sys/init_staging",
    "sys/init_lease",
    "sys/root_key_enc",
    "sys/root_identity",
];

/// Reject an ordinary secret write or delete aimed at an initialization artifact path.
fn reject_reserved_initialization_path(path: &str) -> Result<(), SecretError> {
    if RESERVED_INITIALIZATION_PATHS.contains(&path) {
        return Err(SecretError::InvalidOperation(format!(
            "'{}' is a reserved initialization path and cannot be written through the secret API",
            path
        )));
    }
    Ok(())
}

/// Policy definition
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: PolicyMetadata,
}

/// Secret service errors
#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found: {path}")]
    SecretNotFound { path: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Policy not found: {name}")]
    PolicyNotFound { name: String },

    #[error("Backup not found: {id}")]
    BackupNotFound { id: String },

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] secreton_crypto::CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] secreton_storage::StorageError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Secret service for business logic operations.
//
// NOTE: intentionally NOT `#[derive(Clone)]`. `SecretService` is only ever
// shared via `Arc<SecretService>` (see `ApiServiceContainer::new` and
// `api_server::main`), so exposing `Clone` would expand the public API
// surface with no caller — a one-way change that would later be breaking
// to walk back. `with_lifecycle(mut self)` below works by move semantics
// and does not require `Clone`.
pub struct SecretService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    audit: Arc<AuditLogger>,
    _identity: Arc<dyn IdentityService + Send + Sync>,
    policy_service: Arc<PolicyService>,
    performance: Arc<SecretPerformanceOptimizer>,
    lifecycle: Option<Arc<crate::services::lifecycle::LifecycleService>>,

    /// Serializes concurrent structured policy upserts.
    ///
    /// `_upsert_policy` performs a read-modify-write over `sys/policies/{name}`.
    /// Two concurrent `create_policy`/`update_policy` requests for the same
    /// policy name could both observe `existing_entry = None` and both call
    /// `storage.store()`, which on backends without a unique constraint on
    /// `path` would create duplicate rows.  Holding this lock across the
    /// whole RMW sequence closes the TOCTOU window.  Structured-policy
    /// upserts are admin-only and rare, so a single global mutex is fine —
    /// mirrors `AdminService::policy_content_write_lock`.
    policy_write_lock: Arc<tokio::sync::Mutex<()>>,
}

impl SecretService {
    /// Create new secret service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
        identity: Arc<dyn IdentityService + Send + Sync>,
        policy_service: Arc<PolicyService>,
        performance: Arc<SecretPerformanceOptimizer>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            crypto,
            audit,
            _identity: identity,
            policy_service,
            performance,
            lifecycle: None,
            policy_write_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Set lifecycle service
    pub fn with_lifecycle(
        mut self,
        lifecycle: Arc<crate::services::lifecycle::LifecycleService>,
    ) -> Self {
        self.lifecycle = Some(lifecycle);
        self
    }

    /// Helper to parse user ID to UUID
    fn get_user_uuid(user: &secreton_auth::User) -> Uuid {
        Uuid::parse_str(&user.id).unwrap_or_default()
    }

    /// Check permission for an action on a path
    async fn check_permission(
        &self,
        user: &secreton_auth::User,
        path: &str,
        action: &str,
    ) -> Result<(), SecretError> {
        // Strict Secret Isolation: Admin/Superuser cannot bypass data access policies.
        // They can only manage system configurations or resources they explicitly own.
        // Exception: "sys/" paths might be administrative.

        // RBAC Check
        // Resolve role IDs
        let mut role_ids = Vec::new();
        for role_name in &user.roles {
            if let Some(role_id) = self.policy_service.get_role_id_by_name(role_name).await {
                role_ids.push(role_id);
            }
        }

        // Resolve policy IDs
        let mut policy_ids = Vec::new();
        for policy_name in &user.policies {
            if let Some(policy_id) = self.policy_service.get_policy_id_by_name(policy_name).await {
                policy_ids.push(policy_id);
            }
        }

        let context = EvaluationContext {
            subject: HashMap::from([("id".to_string(), user.id.clone())]),
            resource: HashMap::from([("path".to_string(), path.to_string())]),
            action: action.to_string(),
            environment: HashMap::new(),
        };

        match self
            .policy_service
            .evaluate_access(&context, &role_ids, &policy_ids)
            .await
        {
            Ok(result) if result.allowed => Ok(()),
            _ => Err(SecretError::PermissionDenied(format!(
                "Action '{}' denied on '{}'",
                action, path
            ))),
        }
    }

    /// Check if a secret exists without decrypting or logging audit access
    pub async fn exists_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
        action: &str,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, path, action).await?;

        let entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(encrypted_entry) = entry {
            // Strict Ownership Check
            let user_uuid = Self::get_user_uuid(user);
            if encrypted_entry.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get secret by path
    pub async fn get_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
        version: Option<u32>,
    ) -> Result<SecretData, SecretError> {
        let start_time = std::time::Instant::now();
        self.check_permission(user, path, "read").await?;

        // Optimize fetch strategy:
        // 1. Fetch from main path first (most likely case)
        // 2. If version specified and doesn't match current, fetch from history

        let mut encrypted_entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        // Always check ownership against the CURRENT secret if it exists.
        // This prevents access to orphaned history entries by previous owners
        // or access if the secret was deleted.
        let user_uuid = Self::get_user_uuid(user);

        if let Some(current_entry) = &encrypted_entry {
            if current_entry.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
        } else {
            // If the current secret doesn't exist, we should not allow fetching history.
            // This prevents access to orphaned history entries from failed deletions.
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // If specific version requested
        if let Some(v) = version {
            // Check if we have a current entry and if it matches the version
            let current_matches = encrypted_entry.as_ref().is_some_and(|e| e.version == v);

            if !current_matches {
                // Fetch from history
                let history_path = format!("sys/history/{}::v{}", path, v);
                encrypted_entry = self
                    .storage
                    .get_by_path(&history_path)
                    .await
                    .map_err(SecretError::Storage)?;

                // Re-verify that the history entry exists
                if encrypted_entry.is_none() {
                    return Err(SecretError::SecretNotFound {
                        path: format!("{} (version {})", path, v),
                    });
                }
            }
        }

        // Both branches above return `SecretNotFound` when this is `None`, but the guard
        // and the use were fifteen lines apart. Bind it so a future edit to either branch
        // cannot leave a panic behind.
        let Some(encrypted_entry) = encrypted_entry else {
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        };

        // Try to get decrypted data from cache first (only if fetching current version implicitly)
        // To avoid race conditions where cache has newer data than our DB read, we only use cache if NO specific version was requested.
        let is_current = version.is_none();

        if is_current && let Ok(Some(cached_data)) = self.performance.get_cached(path).await {
            // Parse version from cache (first 4 bytes)
            if cached_data.len() > 4 {
                let (ver_bytes, data_bytes) = cached_data.split_at(4);
                let cached_ver = u32::from_be_bytes(ver_bytes.try_into().unwrap_or([0; 4]));

                // Only use cache if version matches the Source of Truth (DB metadata)
                if cached_ver == encrypted_entry.version {
                    match serde_json::from_slice::<HashMap<String, String>>(data_bytes) {
                        Ok(secret_map) => {
                            // Log access in performance optimizer (cache hit)
                            self.performance
                                .record_access(path, AccessType::Read, start_time.elapsed(), true)
                                .await;

                            let metadata = SecretMetadata {
                                description: encrypted_entry.metadata.get("description").cloned(),
                                tags: encrypted_entry.tags.clone(),
                                owner: encrypted_entry.metadata.get("owner").cloned(),
                                classification: encrypted_entry
                                    .metadata
                                    .get("classification")
                                    .cloned(),
                            };

                            return Ok(SecretData {
                                path: path.to_string(),
                                data: secret_map,
                                metadata,
                                version: encrypted_entry.version, // Use actual version from storage
                                previous_version: None,
                                created_at: encrypted_entry.created_at,
                                updated_at: encrypted_entry.updated_at,
                                expires_at: encrypted_entry.expires_at,
                            });
                        }
                        Err(_) => {
                            // If cached data is invalid, remove it
                            let _ = self.performance.invalidate_cached(path).await;
                        }
                    }
                }
            } else {
                // Invalid cache format, remove it
                let _ = self.performance.invalidate_cached(path).await;
            }
        }

        // Decrypt the secret data
        let decrypted_data = self
            .crypto
            .decrypt(&encrypted_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse the decrypted data as JSON
        let secret_map: HashMap<String, String> =
            serde_json::from_slice(&decrypted_data).map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Failed to parse secret data: {}", e))
            })?;

        // Cache the decrypted data (only if current)
        // Store version + data to allow validation on retrieval
        if is_current {
            let mut cache_payload = encrypted_entry.version.to_be_bytes().to_vec();
            cache_payload.extend_from_slice(&decrypted_data);
            let _ = self
                .performance
                .put_cached(path.to_string(), cache_payload)
                .await;
        }

        // Log access in performance optimizer (cache miss)
        self.performance
            .record_access(path, AccessType::Read, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretAccess {
                secret_path: path.to_string(),
                user: user.id.to_string(),
                action: "read".to_string(),
            })
            .await;

        let metadata = SecretMetadata {
            description: encrypted_entry.metadata.get("description").cloned(),
            tags: encrypted_entry.tags.clone(),
            owner: encrypted_entry.metadata.get("owner").cloned(),
            classification: encrypted_entry.metadata.get("classification").cloned(),
        };

        Ok(SecretData {
            path: path.to_string(),
            data: secret_map,
            metadata,
            version: encrypted_entry.version,
            previous_version: None,
            created_at: encrypted_entry.created_at,
            updated_at: encrypted_entry.updated_at,
            expires_at: encrypted_entry.expires_at,
        })
    }

    /// Create or update secret.
    ///
    /// `ttl` semantics (in seconds):
    /// * `Some(n)` — set `expires_at = now + n`.
    /// * `None`    — **carry forward** the existing entry's `expires_at`
    ///   (or leave it unset for a brand-new entry).
    ///
    /// There is intentionally no value of `ttl` that *clears* a previously
    /// set expiration through this public method: the carry-forward branch
    /// is what allows TTL-unaware callers (gRPC and internal
    /// rollback) to update a secret's data without silently stripping its
    /// expiration.  Callers that genuinely want to remove an expiration from
    /// an existing secret should route through `put_secret_internal` with
    /// `expires_at_override = Some(None)` — this is what the REST handlers
    /// do when a request carries `clear_ttl: true` (see
    /// `CreateSecretRequest::clear_ttl` in `crates/api/src/handlers/secret.rs`).
    ///
    /// API contract for handler authors: the REST `POST /secrets/{path}` and
    /// `PUT /secrets/{path}` endpoints expose three TTL modes via the request
    /// body:
    /// * `ttl: Some(n)`                     — set `expires_at = now + n`.
    /// * `ttl: None, clear_ttl: false/unset` — carry forward existing TTL.
    /// * `ttl: None, clear_ttl: true`        — clear TTL (non-expiring).
    ///
    /// `ttl: Some(_)` together with `clear_ttl: true` is contradictory and
    /// must be rejected by handlers with a 400.  TTL-unaware update paths
    /// (gRPC, and any client that predates the flag) cannot clear TTLs and will
    /// always carry-forward — this is intentional, since silently stripping
    /// expirations on those paths is a worse failure mode than "rotate
    /// through the REST API to drop a TTL".
    pub async fn put_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
        metadata: Option<SecretMetadata>,
        user: &secreton_auth::User,
        ttl: Option<u64>,
    ) -> Result<SecretData, SecretError> {
        self.put_secret_internal(path, data, metadata, user, ttl, None)
            .await
    }

    /// Internal put_secret that allows callers (e.g. `rollback_secret`) to
    /// supply an absolute `expires_at` value that takes precedence over both
    /// the TTL and the carry-forward-from-existing logic.
    ///
    /// `expires_at_override` semantics:
    /// * `None`              — use the normal `ttl` / carry-forward logic.
    /// * `Some(None)`        — explicitly clear the expiration on the new entry
    ///   (e.g. rolling back to a historical version that had no TTL).
    /// * `Some(Some(when))`  — set `expires_at = when` exactly, preserving absolute
    ///   timestamps from historical versions without a lossy now-relative conversion.
    ///
    /// Write without re-running the caller-facing policy check.
    #[allow(clippy::too_many_arguments)]
    /// `pub` because the lifecycle and rotation handlers in `secreton-server` need it, but
    /// the name is deliberately explicit: callers must have already authorised the write.
    pub async fn put_secret_internal(
        &self,
        path: &str,
        data: HashMap<String, String>,
        metadata: Option<SecretMetadata>,
        user: &secreton_auth::User,
        ttl: Option<u64>,
        expires_at_override: Option<Option<chrono::DateTime<chrono::Utc>>>,
    ) -> Result<SecretData, SecretError> {
        let start_time = std::time::Instant::now();
        reject_reserved_initialization_path(path)?;
        self.check_permission(user, path, "write").await?;

        // Validate TTL upper bound before any unchecked numeric casts below
        // (`as i64` for `chrono::Duration::seconds`, `as u32` for the
        // lifecycle manager's `ttl_days`).  Without this guard, an
        // attacker-controlled u64 above `i64::MAX` would silently wrap to a
        // negative `Duration`, producing a `expires_at` in the past and
        // marking the secret as immediately expired.  100 years is far
        // above any realistic operational TTL while staying well within
        // both `i64` seconds and `u32` days.
        const MAX_TTL_SECONDS: u64 = 100 * 365 * 86_400;
        if let Some(ttl_secs) = ttl {
            // Reject `ttl == 0`, which would compute `expires_at = now + 0s`
            // and mark the just-written entry as immediately expired — the
            // next lifecycle sweep tick would then delete the data the user
            // just stored, with no indication in the success response that
            // anything is wrong.  An explicit error is far less surprising
            // than silent data loss.  Callers that want a non-expiring
            // secret should pass `ttl = None`.
            if ttl_secs == 0 {
                return Err(SecretError::InvalidOperation(
                    "TTL of 0 seconds would create an immediately-expired secret. \
                     Use a positive TTL, or omit `ttl` for a non-expiring secret."
                        .to_string(),
                ));
            }
            if ttl_secs > MAX_TTL_SECONDS {
                return Err(SecretError::InvalidOperation(format!(
                    "TTL of {} seconds exceeds the maximum of {} seconds (~100 years)",
                    ttl_secs, MAX_TTL_SECONDS
                )));
            }
        }

        // Validate path for reserved delimiter. We only block paths that end with ::v followed by digits
        // or paths that attempt to write directly into the sys/history/ namespace.
        if path.starts_with("sys/history/") {
            return Err(SecretError::InvalidOperation(
                "Cannot write directly to reserved sys/history/ namespace".to_string(),
            ));
        }

        if let Some(idx) = path.rfind("::v") {
            let suffix = &path[idx + 3..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return Err(SecretError::InvalidOperation(
                    "Secret path cannot end with '::v' followed by a version number".to_string(),
                ));
            }
        }

        // Serialize data to JSON for storage
        let json_data = serde_json::to_vec(&data).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize secret data: {}", e))
        })?;

        // Encrypt the data
        let encrypted_data = self
            .crypto
            .encrypt_data(&json_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = Self::get_user_uuid(user);

        // Get existing secret to check for version and ownership atomically (avoid TOCTOU)
        let (
            version,
            _existing_owner,
            previous_version,
            existing_metadata,
            existing_tags,
            existing_created_at,
            existing_expires_at,
        ) = if let Ok(Some(existing)) = self.storage.get_by_path(path).await {
            // Check ownership first
            if existing.owner_id != owner_id {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }

            // Capture existing metadata, tags, created_at, and expires_at before archiving
            let prev_metadata = existing.metadata.clone();
            let prev_tags = existing.tags.clone();
            let prev_created_at = existing.created_at;
            let prev_expires_at = existing.expires_at;

            // Archive the existing version
            let archive_path = format!("sys/history/{}::v{}", existing.path, existing.version);
            let mut archive_entry = existing.clone();
            archive_entry.path = archive_path;
            // Ensure unique ID for the archived entry to avoid PK collisions
            archive_entry.id = Uuid::new_v4();

            // Store the archived version
            if let Err(e) = self.storage.store(&archive_entry).await {
                return Err(SecretError::Storage(e));
            }

            (
                existing.version + 1,
                Some(existing.owner_id),
                Some(existing.version),
                Some(prev_metadata),
                Some(prev_tags),
                Some(prev_created_at),
                Some(prev_expires_at),
            )
        } else {
            (1, None, None, None, None, None, None)
        };

        // Create SecretEntry
        let mut entry = secreton_storage::SecretEntry::new(
            path.to_string(),
            encrypted_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Confidential,
            owner_id,
        );
        entry.version = version;

        // Preserve original creation timestamp across updates so that
        // `created_at` reflects when the secret was first written, not the
        // time of the latest version.
        if let Some(ts) = existing_created_at {
            entry.created_at = ts;
        }

        // When the caller provides metadata (Some), it represents the complete
        // desired metadata state (full replacement semantics): Some fields set
        // the value, None fields clear it.  This ensures rollback correctly
        // restores historical metadata without leaking values from the current
        // version.
        //
        // When metadata is None, carry forward existing metadata/tags so that
        // updates through APIs that don't support metadata (gRPC) don't
        // silently erase previously stored values.
        if let Some(meta) = &metadata {
            if let Some(desc) = &meta.description {
                entry
                    .metadata
                    .insert("description".to_string(), desc.clone());
            } else {
                entry.metadata.remove("description");
            }
            if let Some(owner) = &meta.owner {
                entry.metadata.insert("owner".to_string(), owner.clone());
            } else {
                entry.metadata.remove("owner");
            }
            if let Some(class) = &meta.classification {
                entry
                    .metadata
                    .insert("classification".to_string(), class.clone());
            } else {
                entry.metadata.remove("classification");
            }
            // Replace tags entirely when caller provides metadata
            entry.tags = meta.tags.clone();
        } else {
            // Carry forward existing metadata as defaults
            if let Some(prev_meta) = &existing_metadata {
                for (k, v) in prev_meta {
                    entry.metadata.insert(k.clone(), v.clone());
                }
            }
            if let Some(prev_tags) = &existing_tags {
                for tag in prev_tags {
                    entry = entry.add_tag(tag.clone());
                }
            }
        }

        // Apply TTL to the storage entry so that `is_expired()` and the
        // lifecycle sweep work against the authoritative storage record.
        // We use second precision here to match the API contract (TTL is
        // expressed in seconds).
        //
        // When the caller does not supply a TTL (`ttl == None`), carry
        // forward the existing entry's `expires_at` so that updates
        // through APIs that don't expose a TTL parameter (gRPC,
        // internal rollback) don't silently strip a previously-set
        // expiration.  This mirrors the carry-forward semantics already
        // applied to metadata/tags above.
        if let Some(override_value) = expires_at_override {
            // Caller explicitly specified the expiration (e.g. rollback
            // restoring a historical version's absolute timestamp).
            entry.expires_at = override_value;
        } else if let Some(ttl_secs) = ttl {
            entry.expires_at =
                Some(chrono::Utc::now() + chrono::Duration::seconds(ttl_secs as i64));
        } else if let Some(prev_expires_at) = existing_expires_at {
            // Carry forward the existing entry's expiration, BUT only when it
            // is still in the future.  If the previous version's `expires_at`
            // is already in the past (e.g. the user is updating a secret
            // whose TTL elapsed before the lifecycle sweep ran, or a
            // TTL-unaware caller — gRPC, say — is rotating an expired
            // secret's value), blindly copying the stale timestamp would
            // make the just-written entry immediately eligible for deletion
            // on the next sweep tick, silently destroying the data the user
            // just wrote.  Treat a past `expires_at` the same as no
            // expiration: the new entry becomes non-expiring until the
            // caller sets a fresh TTL.
            match prev_expires_at {
                Some(prev) if prev > chrono::Utc::now() => {
                    entry.expires_at = Some(prev);
                }
                _ => {
                    // Past or unset — leave entry.expires_at as None.
                }
            }
        }

        // Store encrypted data
        self.storage
            .store(&entry)
            .await
            .map_err(SecretError::Storage)?;

        // Sync the in-memory lifecycle manager with the authoritative
        // storage-level `entry.expires_at`.  We compute `ttl_days` from
        // the *final* expiration on the entry (rather than only from the
        // `ttl` parameter) so that carry-forward updates and rollbacks —
        // which both leave `ttl == None` but still produce a meaningful
        // `entry.expires_at` — keep the lifecycle dashboard / stats in
        // sync.  An entry with no expiration is intentionally left
        // un-tracked by the lifecycle manager.
        //
        // Round up to whole days so that sub-day TTLs (e.g. 1 hour) are
        // not silently truncated to 0, and partial-day TTLs (e.g. 1.5
        // days) are not rounded down.  The lifecycle manager tracks
        // day-granular expirations; the authoritative second-precision
        // expiration lives on `entry.expires_at` above.
        //
        // CAVEAT: `SecretLifecycleManagement` keeps its tracking state in
        // an in-memory `HashMap`, so on every server restart this side of
        // the world is wiped.  The storage-level `expires_at` is
        // persistent (so the sweep keeps working correctly), but the
        // lifecycle stats / `get_lifecycle` / `extend_ttl` API surface is
        // ephemeral until those endpoints are rebuilt to read from
        // storage directly.  See the lifecycle handler stubs in
        // `crates/api/src/handlers/lifecycle.rs`.
        if let Some(lifecycle_svc) = &self.lifecycle {
            if let Some(expires_at) = entry.expires_at {
                let now = chrono::Utc::now();
                let remaining_secs =
                    u64::try_from((expires_at - now).num_seconds().max(0)).unwrap_or(0);
                let ttl_days =
                    u32::try_from(remaining_secs.div_ceil(86_400).max(1)).unwrap_or(u32::MAX);
                if let Err(e) = lifecycle_svc
                    .manager()
                    .set_expiration(path.to_string(), ttl_days)
                    .await
                {
                    warn!("Failed to update lifecycle for {}: {}", path, e);
                }
            } else {
                // The new entry has no expiration (either it never had one,
                // or a rollback / explicit override cleared it).  Remove any
                // stale lifecycle tracking entry for this path so that
                // dashboard stats and `list_by_status` don't continue to
                // report a now-non-expiring secret as Active/Expiring.
                if let Err(e) = lifecycle_svc.manager().remove_expiration(path).await {
                    warn!("Failed to clear lifecycle for {}: {}", path, e);
                }
            }
        }

        // Update cache with plaintext data PREPENDED with version
        let mut cache_payload = entry.version.to_be_bytes().to_vec();
        cache_payload.extend_from_slice(&json_data);
        let _ = self
            .performance
            .put_cached(path.to_string(), cache_payload)
            .await;

        self.performance
            .record_access(path, AccessType::Write, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretCreation {
                secret_path: path.to_string(),
                user: user.id.to_string(),
            })
            .await;

        // Reconstruct metadata from the actual stored entry to ensure accuracy
        let stored_metadata = SecretMetadata {
            description: entry.metadata.get("description").cloned(),
            tags: entry.tags.clone(),
            owner: entry.metadata.get("owner").cloned(),
            classification: entry.metadata.get("classification").cloned(),
        };

        Ok(SecretData {
            path: path.to_string(),
            data,
            metadata: stored_metadata,
            version: entry.version,
            previous_version,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
            expires_at: entry.expires_at,
        })
    }

    /// Delete secret
    pub async fn delete_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
    ) -> Result<(), SecretError> {
        self.delete_secret_internal(path, user, true, true).await
    }

    /// Delete secret with option to preserve history (used for rollbacks)
    /// `check_perms`: If true, checks the "delete" permission. If false, bypasses RBAC (e.g. for internal rollback).
    /// Delete without re-running the caller-facing policy check. See
    /// [`Self::put_secret_internal`] for the contract.
    pub async fn delete_secret_internal(
        &self,
        path: &str,
        user: &secreton_auth::User,
        delete_history: bool,
        check_perms: bool,
    ) -> Result<(), SecretError> {
        let start_time = std::time::Instant::now();
        reject_reserved_initialization_path(path)?;

        if check_perms {
            self.check_permission(user, path, "delete").await?;
        }

        // Check if secret exists and check ownership
        let entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(e) = entry {
            let user_uuid = Self::get_user_uuid(user);
            // Ownership check: Only owner can delete (unless it's a system admin action which deletes the USER, handled elsewhere)
            // But prompt says "root/admin cannot... delete... unless deleting user data".
            // So direct secret deletion must be owner-only.
            if e.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
        } else {
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // Delete from storage using delete_by_path
        self.storage
            .delete_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        // Delete history if requested
        if delete_history {
            // Cap the scan with an explicit upper bound. Before the
            // PostgreSQL backend's default `LIMIT 100` was removed (in the
            // lifecycle PR), this scan was implicitly bounded; without an
            // explicit limit it would now perform an unbounded scan of the
            // history namespace on every delete. 10k history entries for a
            // single secret is far above realistic usage.
            const HISTORY_DELETE_MAX_ENTRIES: u32 = 10_000;
            let history_prefix = format!("sys/history/{}::v", path);
            // `include_expired: true` is critical here. History entries are
            // archived via `put_secret` as a clone of the parent secret
            // (see the `existing.clone()` block above), so they inherit the
            // parent's `expires_at`. If the parent secret is past its
            // expiration, the history rows are also expired — and the
            // PostgreSQL backend's default `include_expired: false` filter
            // (`AND (expires_at IS NULL OR expires_at > NOW())`) would
            // silently exclude them from this query, leaving orphaned
            // entries under `sys/history/` after the user-initiated delete.
            let query = secreton_storage::QueryParams {
                path_prefix: Some(history_prefix),
                owner_id: Some(Self::get_user_uuid(user)),
                limit: Some(HISTORY_DELETE_MAX_ENTRIES),
                include_expired: true,
                ..Default::default()
            };

            if let Ok(entries) = self.storage.list(&query).await {
                for entry in entries {
                    if let Err(e) = self.storage.delete_by_path(&entry.path).await {
                        warn!("Failed to delete history entry {}: {}", entry.path, e);
                    }
                }
            }
        }

        // Invalidate cache
        let _ = self.performance.invalidate_cached(path).await;

        // Drop any in-memory lifecycle tracking entry for the deleted path
        // so that dashboard stats and `list_by_status` don't continue to
        // report a deleted secret.  The lifecycle manager is best-effort
        // (in-memory only) and may not contain an entry for this path,
        // which is fine — `remove_expiration` is a no-op in that case.
        if let Some(lifecycle_svc) = &self.lifecycle
            && let Err(e) = lifecycle_svc.manager().remove_expiration(path).await
        {
            warn!("Failed to clear lifecycle for {}: {}", path, e);
        }

        self.performance
            .record_access(path, AccessType::Delete, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretDeletion {
                secret_path: path.to_string(),
                user: user.id.to_string(),
            })
            .await;

        Ok(())
    }

    /// Rollback secret to a previous version
    pub async fn rollback_secret(
        &self,
        path: &str,
        version: u32,
        user: &secreton_auth::User,
    ) -> Result<SecretData, SecretError> {
        self.check_permission(user, path, "write").await?;

        // Prevent no-op rollback to the current version, which would waste a
        // version number and create a redundant history entry.
        let current = self.get_secret(path, user, None).await?;
        if current.version == version {
            return Err(SecretError::InvalidOperation(format!(
                "Version {} is already the current version — rollback is a no-op",
                version
            )));
        }

        // 1. Fetch the historical version
        let historical_data = self.get_secret(path, user, Some(version)).await?;

        // Reject rollback when the historical version's `expires_at` is
        // already in the past.  Without this guard we would faithfully
        // restore the absolute timestamp (so rollback round-trips
        // losslessly), but the lifecycle sweep — which reads the same
        // authoritative `expires_at` — would then delete the entry on its
        // next tick.  Users initiating a rollback rarely expect "restore
        // and immediately delete" behaviour; failing loudly here lets
        // them either re-set a TTL via a follow-up `put_secret` call or
        // pick a different version.
        if let Some(historical_expires_at) = historical_data.expires_at
            && historical_expires_at <= chrono::Utc::now()
        {
            return Err(SecretError::InvalidOperation(format!(
                "Cannot rollback to version {}: its expires_at ({}) is in the past, \
                     which would make the rolled-back secret immediately eligible for \
                     lifecycle cleanup. Update the secret with a fresh TTL after rollback, \
                     or rollback to a different version.",
                version, historical_expires_at
            )));
        }

        // 2. Promotion: Put it as the new latest version.
        // `put_secret_internal` handles archiving the current one and
        // incrementing the version.  We pass the historical version's
        // `expires_at` as an explicit override so that rollback restores the
        // historical expiration verbatim instead of inheriting the *current*
        // version's `expires_at` via the carry-forward branch in
        // `put_secret_internal` (which fires whenever `ttl` is None).
        let rolled_back = self
            .put_secret_internal(
                path,
                historical_data.data,
                Some(historical_data.metadata),
                user,
                None,
                Some(historical_data.expires_at),
            )
            .await?;

        // Log audit trail for rollback specifically
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretVersionChange {
                secret_path: path.to_string(),
                old_version: rolled_back.previous_version.unwrap_or(0),
                new_version: rolled_back.version,
                user: user.id.to_string(),
            })
            .await;

        Ok(rolled_back)
    }

    /// Create a new policy
    pub async fn create_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        // Self-permission check (can user create policy?)
        self.check_permission(user, &format!("sys/policies/{}", name), "create")
            .await?;
        self._upsert_policy(name, rules, metadata).await
    }

    /// Check whether the user has the given permission on a policy path.
    ///
    /// This is a thin wrapper around `check_permission` exposed publicly so
    /// that handlers can perform an explicit RBAC check without loading the
    /// full policy object.  It is intentionally cheap (in-memory RBAC
    /// evaluation, no storage I/O).
    pub async fn check_policy_permission(
        &self,
        name: &str,
        user: &secreton_auth::User,
        action: &str,
    ) -> Result<(), SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), action)
            .await
    }

    /// Get policy by name
    pub async fn get_policy(
        &self,
        name: &str,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "read")
            .await?;

        let path = format!("sys/policies/{}", name);
        let entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(entry) = entry {
            let decrypted = self
                .crypto
                .decrypt(&entry.encrypted_data)
                .await
                .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;
            let policy: Policy = serde_json::from_slice(&decrypted).map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Deserialization error: {}", e))
            })?;
            Ok(policy)
        } else {
            Err(SecretError::PolicyNotFound {
                name: name.to_string(),
            })
        }
    }

    /// Delete policy
    pub async fn delete_policy(
        &self,
        name: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "delete")
            .await?;

        // Serialize with `_upsert_policy` so that a concurrent upsert cannot
        // observe `existing_entry = Some(...)` and then `storage.update()` a
        // now-deleted entry, nor observe `existing_entry = None` after this
        // delete has started and race ahead of the delete with a `store()`.
        // See `policy_write_lock` field doc for the full rationale.
        let _write_guard = self.policy_write_lock.lock().await;

        let path = format!("sys/policies/{}", name);
        let entry = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(entry) = entry {
            self.storage
                .delete_by_id(entry.id)
                .await
                .map_err(SecretError::Storage)?;
            Ok(true)
        } else {
            Err(SecretError::PolicyNotFound {
                name: name.to_string(),
            })
        }
    }

    pub async fn list_secret_versions(
        &self,
        path: &str,
        user: &secreton_auth::User,
    ) -> Result<Vec<SecretVersionInfo>, SecretError> {
        self.check_permission(user, path, "list_versions").await?;

        let user_uuid = Self::get_user_uuid(user);
        let mut versions = Vec::new();

        // 1. Get current version
        match self.storage.get_by_path(path).await {
            Ok(Some(current)) => {
                // Check ownership
                if current.owner_id == user_uuid {
                    versions.push(SecretVersionInfo {
                        version: current.version,
                        created_at: current.created_at,
                    });
                } else {
                    return Err(SecretError::PermissionDenied(format!(
                        "Access restricted: User is not the owner of '{}'",
                        path
                    )));
                }
            }
            Err(e) => return Err(SecretError::Storage(e)),
            Ok(None) => {
                // If the current secret doesn't exist, block access to history
                // to prevent leaking orphaned history metadata. This matches the behavior of get_secret.
                return Err(SecretError::SecretNotFound {
                    path: path.to_string(),
                });
            }
        }

        // 2. Get history versions
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now perform an unbounded scan of the history namespace on
        // every list call. 10k versions for a single secret is far above
        // realistic usage.
        const HISTORY_LIST_MAX_ENTRIES: u32 = 10_000;
        let history_prefix = format!("sys/history/{}::v", path);
        // We use query with owner to let backend filter, but we also double check
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(history_prefix)
            .with_owner(user_uuid)
            .with_limit(HISTORY_LIST_MAX_ENTRIES);

        let history_entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        for entry in history_entries {
            versions.push(SecretVersionInfo {
                version: entry.version,
                created_at: entry.created_at,
            });
        }

        // If we found absolutely nothing (no current, no history), the secret does not exist
        if versions.is_empty() {
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // Sort descending
        versions.sort_by(|a, b| b.version.cmp(&a.version));

        Ok(versions)
    }

    pub async fn list_secrets(
        &self,
        prefix: Option<&str>,
        user: &secreton_auth::User,
        limit: Option<u32>,
        offset: Option<u32>,
    ) -> Result<Vec<SecretData>, SecretError> {
        // Parse user_id as UUID for ownership check
        let user_uuid = Uuid::parse_str(&user.id).unwrap_or_default();

        // Strict isolation: always filter by owner ID.
        //
        // Cap the scan with an explicit upper bound. 10k secrets per user is
        // well above typical usage while still bounding worst-case memory and crypto work.
        const DEFAULT_LIMIT: u32 = 100;
        const MAX_LIMIT: u32 = 10_000;

        let final_limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

        let mut query = secreton_storage::QueryParams::new()
            .with_owner(user_uuid)
            .with_limit(final_limit);

        if let Some(o) = offset {
            query.offset = Some(o);
        }

        if let Some(p) = prefix {
            query = query.with_path_prefix(p.to_string());
        }

        // Get secrets from storage
        // The storage backend handles filtering by owner_id if set in query
        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        // Convert entries to SecretData
        let mut accessible_secrets = Vec::new();
        for entry in entries {
            // Skip archived history entries
            if entry.path.starts_with("sys/history/") {
                continue;
            }

            if self
                .check_permission(user, &entry.path, "read")
                .await
                .is_ok()
            {
                // Decrypt the secret data
                match self.crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted_data) => {
                        // Parse the decrypted data as JSON
                        match serde_json::from_slice::<HashMap<String, String>>(&decrypted_data) {
                            Ok(secret_map) => {
                                let metadata = SecretMetadata {
                                    description: entry.metadata.get("description").cloned(),
                                    tags: entry.tags.clone(),
                                    owner: entry.metadata.get("owner").cloned(),
                                    classification: entry.metadata.get("classification").cloned(),
                                };

                                accessible_secrets.push(SecretData {
                                    path: entry.path.clone(),
                                    data: secret_map,
                                    metadata,
                                    version: entry.version,
                                    previous_version: None,
                                    created_at: entry.created_at,
                                    updated_at: entry.updated_at,
                                    expires_at: entry.expires_at,
                                });
                            }
                            Err(e) => {
                                warn!("Failed to parse secret data for {}: {}", entry.path, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to decrypt secret data for {}: {}", entry.path, e);
                    }
                }
            }
        }

        Ok(accessible_secrets)
    }

    /// Create encryption key
    pub async fn create_key(
        &self,
        key_name: &str,
        key_type: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        // Reject key names that end with `_v` followed by digits.
        // The versioned storage scheme uses `key_data/{uid}/{name}_v{N}` paths,
        // so a key named e.g. "mykey_v1" would collide with key "mykey"'s
        // version 1 data path.
        if let Some(pos) = key_name.rfind("_v") {
            let suffix = &key_name[pos + 2..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return Err(SecretError::InvalidOperation(format!(
                    "Key name '{}' must not end with '_v' followed by digits (reserved for versioning)",
                    key_name
                )));
            }
        }

        let key_path = format!("keys/{}/{}", user.id, key_name);
        self.check_permission(user, &key_path, "create").await?;

        // Check if key already exists to prevent silent overwrites
        if let Ok(Some(_)) = self.storage.get_by_path(&key_path).await {
            return Err(SecretError::InvalidOperation(format!(
                "Key '{}' already exists. Delete it first or use a different name.",
                key_name
            )));
        }

        // Map key type to algorithm.
        // Some key types (xchacha20-poly1305, ecdsa-secp256k1, x25519) are only
        // supported via the transit engine, which manages its own in-memory keys.
        // Reject them here because the secret service's encrypt/decrypt/sign/verify
        // methods cannot operate on these types, so creating them would produce
        // unusable keys.
        let algorithm = match key_type {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "xchacha20-poly1305" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'xchacha20-poly1305' is only supported via the transit engine. \
                     Use POST /api/v1/transit/keys/{name} instead."
                        .to_string(),
                ));
            }
            // RSA was removed with the `rsa` crate (RUSTSEC-2023-0071, an unfixed
            // timing side channel). Reject it explicitly so a caller gets a clear
            // message instead of a confusing "unknown key type".
            "rsa-2048" | "rsa-4096" => {
                return Err(SecretError::InvalidOperation(
                    "RSA keys are not supported. Use 'ed25519' for signatures or \
                     'ecdsa-p256'/'ecdsa-p384' where interoperability requires a NIST curve."
                        .to_string(),
                ));
            }
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ecdsa-secp256k1" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'ecdsa-secp256k1' is only supported via the transit engine. \
                     Use POST /api/v1/transit/keys/{name} instead."
                        .to_string(),
                ));
            }
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            "x25519" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'x25519' is only supported via the transit engine. \
                     Use POST /api/v1/transit/keys/{name} instead."
                        .to_string(),
                ));
            }
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type: {}",
                    key_type
                )));
            }
        };

        // Generate key using crypto service
        let key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Generate unique key ID
        let key_id = format!("key_{}", Uuid::new_v4().simple());

        // Parse user_id as UUID
        let owner_id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4());

        // Store key metadata as SecretEntry
        let algorithm_str = format!("{:?}", algorithm);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": key_type,
            "algorithm": algorithm_str,
            "created_by": user.id,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": 1
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e))
        })?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path.clone(),
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        // Encrypt the key data before storing
        let encrypted_key_data = self
            .crypto
            .encrypt_data(&key_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Store key data BEFORE metadata so that if key data storage fails,
        // no metadata entry references a nonexistent key version.
        let key_data_path = format!("key_data/{}/{}_v1", user.id, key_name);
        let key_data_entry = secreton_storage::SecretEntry::new(
            key_data_path,
            encrypted_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage
            .store(&key_data_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Now store metadata — key material is already safely persisted
        self.storage
            .store(&metadata_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::KeyGeneration {
                key_id: key_id.clone(),
                key_type: key_type.to_string(),
                algorithm: key_type.to_string(),
                user: user.id.to_string(),
            })
            .await;

        Ok(KeyInfo {
            id: key_id,
            name: key_name.to_string(),
            key_type: key_type.to_string(),
            version: 1,
            status: "active".to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    /// Get key information
    pub async fn get_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "read").await?;

        // Retrieve key metadata from storage
        let entry = self
            .storage
            .get_by_path(&key_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

        let metadata: serde_json::Value =
            serde_json::from_slice(&entry.encrypted_data).map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Failed to deserialize key metadata: {}", e))
            })?;

        // Extract key information.
        // `key_id` in the metadata JSON is the internal UUID-based identifier
        // (e.g. "key_abc123"), while the `key_id` parameter to this function
        // is the user-friendly name (from the URL path).  Match the field
        // assignment used by `create_key` and `list_keys`:
        //   id   = internal key_id from metadata
        //   name = user-friendly name (the path parameter)
        let internal_id = metadata
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or(key_id)
            .to_string();

        let key_type = metadata
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = metadata
            .get("version")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(1);

        let default_time = chrono::Utc::now().to_rfc3339();
        let created_at_str = metadata
            .get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&default_time);

        let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        Ok(KeyInfo {
            id: internal_id,
            name: key_id.to_string(),
            key_type,
            version,
            status: "active".to_string(),
            created_at,
        })
    }

    /// List keys for a user
    #[allow(clippy::collapsible_if)]
    pub async fn list_keys(
        &self,
        user: &secreton_auth::User,
        filter: Option<&str>,
    ) -> Result<Vec<KeyInfo>, SecretError> {
        self.check_permission(user, &format!("keys/{}/", user.id), "list")
            .await?;

        // Build query params for keys.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now perform an unbounded scan of the keys namespace on every
        // list call. 10k keys per user is far above realistic usage.
        const KEY_LIST_MAX_ENTRIES: u32 = 10_000;
        let keys_prefix = format!("keys/{}/", user.id);
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(keys_prefix.clone())
            .with_limit(KEY_LIST_MAX_ENTRIES);

        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        let mut keys = Vec::new();
        for entry in entries {
            // Extract key name from path
            if let Some(key_name) = entry.path.strip_prefix(&keys_prefix) {
                // Apply filter if provided
                if let Some(filter_str) = filter
                    && !key_name.contains(filter_str)
                {
                    continue;
                }

                // Parse key metadata
                match serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data) {
                    Ok(metadata) => {
                        let key_id = metadata
                            .get("key_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(key_name)
                            .to_string();

                        let key_type = metadata
                            .get("key_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let version = metadata
                            .get("version")
                            .and_then(|v| v.as_u64())
                            .and_then(|v| u32::try_from(v).ok())
                            .unwrap_or(1);

                        let default_time = chrono::Utc::now().to_rfc3339();
                        let created_at_str = metadata
                            .get("created_at")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&default_time);

                        let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(|_| chrono::Utc::now());

                        keys.push(KeyInfo {
                            id: key_id,
                            name: key_name.to_string(),
                            key_type,
                            version,
                            status: "active".to_string(),
                            created_at,
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to deserialize key metadata for {}: {}",
                            entry.path, e
                        );
                        continue;
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Rotate a key (create new version)
    pub async fn rotate_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "rotate").await?;

        // Get current key metadata
        let current_key = self.get_key(key_id, user).await?;

        // Generate new key with same type (must match create_key's type mapping).
        // Transit-only key types (xchacha20-poly1305, ecdsa-secp256k1, x25519)
        // should never appear here because create_key rejects them. Guard
        // against legacy data by returning an error if they are encountered.
        let algorithm = match current_key.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "xchacha20-poly1305" | "ecdsa-secp256k1" | "x25519" => {
                return Err(SecretError::InvalidOperation(format!(
                    "Key type '{}' is only supported via the transit engine and cannot be rotated here.",
                    current_key.key_type
                )));
            }
            // RSA was removed with the `rsa` crate (RUSTSEC-2023-0071, an unfixed
            // timing side channel). Reject it explicitly so a caller gets a clear
            // message instead of a confusing "unknown key type".
            "rsa-2048" | "rsa-4096" => {
                return Err(SecretError::InvalidOperation(
                    "RSA keys are not supported. Use 'ed25519' for signatures or \
                     'ecdsa-p256'/'ecdsa-p384' where interoperability requires a NIST curve."
                        .to_string(),
                ));
            }
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type: {}",
                    current_key.key_type
                )));
            }
        };

        // Generate new key data
        let new_key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4());

        // Update metadata with new version
        let new_version = current_key.version + 1;
        let key_path = format!("keys/{}/{}", user.id, key_id);
        let algorithm_str = format!("{:?}", algorithm);
        let key_metadata = serde_json::json!({
            "key_id": current_key.id,
            "key_type": current_key.key_type,
            "algorithm": algorithm_str,
            "created_by": user.id,
            "created_at": current_key.created_at.to_rfc3339(),
            "version": new_version,
            "rotated_at": chrono::Utc::now().to_rfc3339()
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e))
        })?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path,
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        // Encrypt the new key data before storing (must match create_key behavior)
        let encrypted_new_key_data = self
            .crypto
            .encrypt_data(&new_key_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Store key data BEFORE metadata to reduce the window where metadata
        // references a version whose key material doesn't exist yet. If the
        // key data store fails, we haven't touched metadata so the key stays
        // at its previous version.
        let new_key_data_path = format!("key_data/{}/{}_v{}", user.id, key_id, new_version);
        let key_data_entry = secreton_storage::SecretEntry::new(
            new_key_data_path,
            encrypted_new_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage
            .store(&key_data_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Now update metadata — key material is already safely stored
        self.storage
            .store(&metadata_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::KeyRotation {
                old_key_id: key_id.to_string(),
                new_key_id: format!("{}_v{}", key_id, new_version),
                algorithm: current_key.key_type.clone(),
                user: user.id.to_string(),
            })
            .await;

        Ok(KeyInfo {
            id: current_key.id,
            name: current_key.name,
            key_type: current_key.key_type,
            version: new_version,
            status: "active".to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    /// Update key metadata
    pub async fn update_key_metadata(
        &self,
        key_id: &str,
        _metadata: &HashMap<String, String>,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_id), "update")
            .await?;
        // Retrieve current key info
        let key_info = self.get_key(key_id, user).await?;

        // In a real implementation we would update the metadata in storage
        // For now, we just return the existing key info since we can't easily modify the mock storage

        Ok(key_info)
    }

    /// Update policy
    pub async fn update_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "update")
            .await?;
        self._upsert_policy(name, rules, metadata).await
    }

    async fn _upsert_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
    ) -> Result<Policy, SecretError> {
        // Serialize the read-modify-write sequence so that two concurrent
        // upserts cannot both observe `existing_entry = None` and both call
        // `storage.store()`.  See `policy_write_lock` field doc for the full
        // rationale.  The guard is held across the entire RMW sequence below
        // and released when it drops at function end.
        let _write_guard = self.policy_write_lock.lock().await;

        // Read the existing entry FIRST so that `created_at` can be preserved
        // in both the serialized `Policy` JSON and on the outer `SecretEntry`.
        // Previously the `Policy` struct was constructed with
        // `created_at: chrono::Utc::now()` on every upsert, so subsequent
        // `get_policy` reads (which deserialize this JSON — see
        // `Self::get_policy`) would report the wrong creation timestamp after
        // every update.  This also brings the structured-policy path in line
        // with the raw-content path added in this PR
        // (`AdminService::update_policy_content`), which correctly preserves
        // `created_at` from the existing entry.
        let policy_path = format!("sys/policies/{}", name);
        let existing_entry = self
            .storage
            .get_by_path(&policy_path)
            .await
            .map_err(SecretError::Storage)?;
        let entry_id = existing_entry
            .as_ref()
            .map(|e| e.id)
            .unwrap_or_else(uuid::Uuid::new_v4);
        let created_at = existing_entry
            .as_ref()
            .map(|e| e.created_at)
            .unwrap_or_else(chrono::Utc::now);
        let version = existing_entry.as_ref().map(|e| e.version + 1).unwrap_or(1);

        let policy = Policy {
            name: name.to_string(),
            rules,
            created_at,
            updated_at: chrono::Utc::now(),
            metadata,
        };

        let data = serde_json::to_vec(&policy).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize policy: {}", e))
        })?;

        let encrypted_data = self.crypto.encrypt_data(&data).await.map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to encrypt policy: {}", e))
        })?;

        let mut entry = secreton_storage::SecretEntry::new(
            policy_path,
            encrypted_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        entry.id = entry_id;
        entry.created_at = created_at;
        entry.version = version;

        // Use `update()` for existing entries and `store()` for new ones.
        // Storage backends with a unique constraint on `path` (e.g. PostgreSQL)
        // would otherwise reject `store()` on an existing entry, and backends
        // that treat `store()` as INSERT could silently create duplicate rows.
        // This mirrors the pattern in `AdminService::update_policy_content`.
        if existing_entry.is_some() {
            self.storage
                .update(&entry)
                .await
                .map_err(SecretError::Storage)?;
        } else {
            self.storage
                .store(&entry)
                .await
                .map_err(SecretError::Storage)?;
        }

        Ok(policy)
    }

    pub async fn list_policies(&self, filter: Option<&str>) -> Result<Vec<Policy>, SecretError> {
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now perform an unbounded scan of the policy namespace and
        // decrypt every entry on every list call. 10k policies is far above
        // realistic deployments while still bounding worst-case memory and
        // crypto work.
        const POLICY_LIST_MAX_ENTRIES: u32 = 10_000;
        let query_params = secreton_storage::QueryParams {
            path_prefix: Some("sys/policies/".to_string()),
            limit: Some(POLICY_LIST_MAX_ENTRIES),
            offset: None,
            ..Default::default()
        };

        let entries = self
            .storage
            .list(&query_params)
            .await
            .map_err(SecretError::Storage)?;
        let mut policies = Vec::new();

        // Structured policies live at `sys/policies/{name}` and raw-content
        // policies live at `sys/policies/content/{name}`.  The path prefix
        // query matches both namespaces, so explicitly skip the raw-content
        // sub-prefix — those entries are not `Policy` structs and are
        // surfaced separately via `AdminService::list_policy_content_metadata`
        // (see the admin-only merge in the `list_policies` handler).
        //
        // Without this filter, every raw-content entry would fail
        // `serde_json::from_slice::<Policy>` and emit a spurious WARN log
        // on every listing call.
        const RAW_CONTENT_PREFIX: &str = "sys/policies/content/";

        for entry in entries {
            if entry.path.starts_with(RAW_CONTENT_PREFIX) {
                continue;
            }
            match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => {
                    match serde_json::from_slice::<Policy>(&decrypted) {
                        Ok(policy) => {
                            // Apply substring filter on the policy name,
                            // mirroring the semantics used in the handler's
                            // merge of raw-content policies so that both
                            // sources filter consistently.
                            if let Some(f) = filter
                                && !policy.name.contains(f)
                            {
                                continue;
                            }
                            policies.push(policy);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to deserialize policy at {}: {}", entry.path, e)
                        }
                    }
                }
                Err(e) => tracing::warn!("Failed to decrypt policy at {}: {}", entry.path, e),
            }
        }

        Ok(policies)
    }

    /// List key versions
    pub async fn list_key_versions(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<Vec<KeyInfo>, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "list_versions")
            .await?;

        // Get current key info to ensure it exists and get base metadata
        let current_key = self.get_key(key_id, user).await?;

        // Build query params for key versions in key_data.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now perform an unbounded scan of the key_data namespace on
        // every call. 10k versions per key is far above realistic usage.
        const KEY_VERSION_LIST_MAX_ENTRIES: u32 = 10_000;
        let key_data_prefix = format!("key_data/{}/{}_v", user.id, key_id);
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(key_data_prefix.clone())
            .with_limit(KEY_VERSION_LIST_MAX_ENTRIES);

        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        let mut versions = Vec::new();
        for entry in entries {
            // Extract version from path suffix
            if let Some(v_str) = entry.path.strip_prefix(&key_data_prefix)
                && let Ok(version) = v_str.parse::<u32>()
            {
                // Guard against prefix collision: the entry path
                // `key_data/{uid}/{key_id}_v{N}` could also be the legacy
                // (non-versioned) data of a *different* key whose name is
                // literally `{key_id}_v{N}`.  For example, listing versions
                // of key "mykey" with prefix `key_data/{uid}/mykey_v` would
                // match `key_data/{uid}/mykey_v1` — but that path may belong
                // to a pre-existing key named "mykey_v1" (created before the
                // `_v{digits}` name validation was added).  Skip the entry
                // when such a colliding key exists.
                let potential_key_name = format!("{}_v{}", key_id, version);
                let potential_meta = format!("keys/{}/{}", user.id, potential_key_name);
                if let Ok(Some(_)) = self.storage.get_by_path(&potential_meta).await {
                    continue;
                }

                versions.push(KeyInfo {
                    id: current_key.id.clone(),
                    name: current_key.name.clone(),
                    key_type: current_key.key_type.clone(),
                    version,
                    status: if version == current_key.version {
                        "active"
                    } else {
                        "historical"
                    }
                    .to_string(),
                    created_at: entry.created_at,
                });
            }
        }

        // Also check for the non-versioned (legacy) entry.
        //
        // Guard against path collision: if key_id matches `{other}_v{N}`, the
        // legacy path `key_data/{uid}/{key_id}` could actually be another key's
        // versioned data. Only consider it as a legacy entry when no such parent
        // key exists.
        let legacy_path = format!("key_data/{}/{}", user.id, key_id);
        let mut check_legacy = true;
        if let Some(pos) = key_id.rfind("_v") {
            let suffix = &key_id[pos + 2..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                let parent_key = &key_id[..pos];
                let parent_meta_path = format!("keys/{}/{}", user.id, parent_key);
                if let Ok(Some(_)) = self.storage.get_by_path(&parent_meta_path).await {
                    check_legacy = false;
                }
            }
        }
        if check_legacy && let Ok(Some(entry)) = self.storage.get_by_path(&legacy_path).await {
            // Only add if we don't already have a v1 entry from the versioned search
            if !versions.iter().any(|v| v.version == 1) {
                versions.push(KeyInfo {
                    id: current_key.id.clone(),
                    name: current_key.name.clone(),
                    key_type: current_key.key_type.clone(),
                    version: 1,
                    status: if current_key.version == 1 {
                        "active"
                    } else {
                        "historical"
                    }
                    .to_string(),
                    created_at: entry.created_at,
                });
            }
        }

        // Sort by version descending
        versions.sort_by(|a, b| b.version.cmp(&a.version));

        Ok(versions)
    }

    /// Delete a key
    pub async fn delete_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "delete").await?;

        // 1. Verify metadata exists (but don't delete it yet).
        //    Delete key material BEFORE metadata so that if the process crashes
        //    mid-way, metadata still references the key and a retry can clean up.
        //    Deleting metadata first would leave orphaned key material with no
        //    metadata pointing to it.
        let metadata_entry = self
            .storage
            .get_by_path(&key_path)
            .await
            .map_err(SecretError::Storage)?;
        if metadata_entry.is_none() {
            return Err(SecretError::KeyNotFound {
                key_id: key_id.to_string(),
            });
        }

        // 2. Delete all versioned key material.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now perform an unbounded scan of the key_data namespace on
        // every delete. 10k versions per key is far above realistic usage.
        const KEY_VERSION_DELETE_MAX_ENTRIES: u32 = 10_000;
        let key_data_prefix = format!("key_data/{}/{}_v", user.id, key_id);
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(key_data_prefix.clone())
            .with_limit(KEY_VERSION_DELETE_MAX_ENTRIES);
        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        for entry in entries {
            // Only delete entries whose suffix after the prefix is a pure version number
            if let Some(v_str) = entry.path.strip_prefix(&key_data_prefix)
                && let Ok(version) = v_str.parse::<u32>()
            {
                // Guard against prefix collision: `key_data/{uid}/{key_id}_v{N}`
                // could also be the legacy data of a different key named
                // `{key_id}_v{N}` (created before the `_v{digits}` name
                // validation was added). Skip if such a colliding key exists.
                let potential_key_name = format!("{}_v{}", key_id, version);
                let potential_meta = format!("keys/{}/{}", user.id, potential_key_name);
                if let Ok(Some(_)) = self.storage.get_by_path(&potential_meta).await {
                    continue;
                }

                self.storage
                    .delete_by_id(entry.id)
                    .await
                    .map_err(SecretError::Storage)?;
            }
        }

        // 3. Delete legacy non-versioned key material if any.
        //
        // Guard against path collision: the versioned scheme stores key data at
        // `key_data/{uid}/{name}_v{N}`. If the key being deleted is itself named
        // `{other_key}_v{N}` (e.g. "mykey_v1"), the legacy path
        // `key_data/{uid}/mykey_v1` is identical to key "mykey"'s version 1 data.
        // Only delete the legacy entry when the key_id cannot be interpreted as
        // another key's versioned data path.
        let legacy_path = format!("key_data/{}/{}", user.id, key_id);
        let mut safe_to_delete_legacy = true;
        if let Some(pos) = key_id.rfind("_v") {
            let suffix = &key_id[pos + 2..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                let parent_key = &key_id[..pos];
                // Check if a different key's metadata exists that would own this path
                let parent_meta_path = format!("keys/{}/{}", user.id, parent_key);
                if let Ok(Some(_)) = self.storage.get_by_path(&parent_meta_path).await {
                    // Another key exists whose versioned data path collides — skip
                    safe_to_delete_legacy = false;
                }
            }
        }
        if safe_to_delete_legacy
            && let Ok(Some(entry)) = self.storage.get_by_path(&legacy_path).await
        {
            self.storage
                .delete_by_id(entry.id)
                .await
                .map_err(SecretError::Storage)?;
        }

        // 4. Delete metadata last — all key material is already removed.
        if let Some(entry) = metadata_entry {
            self.storage
                .delete_by_id(entry.id)
                .await
                .map_err(SecretError::Storage)?;
        }

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::KeyDeletion {
                key_id: key_id.to_string(),
                user: user.id.to_string(),
            })
            .await;

        Ok(true)
    }

    /// Decrypt stored key material, with fallback for legacy unencrypted entries.
    ///
    /// Before this versioning change, `rotate_key` stored raw (unencrypted) key
    /// bytes at `key_data/{uid}/{name}_v{N}`. After the fix, all key data is
    /// encrypted via `crypto.encrypt_data()` (producing a JSON `CryptoPacket`).
    /// To avoid breaking keys that were rotated before the fix, we try
    /// `crypto.decrypt()` first and, if it fails (e.g. because the stored bytes
    /// are not valid JSON), fall back to using the raw bytes directly.
    ///
    /// **Important:** If the stored bytes ARE a valid CryptoPacket (i.e. they
    /// parse as JSON with a `key_id` field), the decryption error is real — for
    /// example the system key may have been rotated or become unavailable. In
    /// that case we must NOT fall back to using the raw CryptoPacket JSON bytes
    /// as key material, because that would produce garbage encryption/signatures
    /// that can never be reversed.
    async fn decrypt_key_material(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, SecretError> {
        match self.crypto.decrypt(encrypted_data).await {
            Ok(key_data) => Ok(key_data),
            Err(decrypt_err) => {
                // Check if the stored data looks like an encrypted CryptoPacket
                // (JSON with a "key_id" field). If so, the decryption failure is
                // genuine (e.g. system key unavailable) — propagate the error
                // instead of silently using the raw JSON bytes as key material.
                if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(encrypted_data)
                    && parsed.get("key_id").is_some()
                {
                    return Err(SecretError::Internal(anyhow::anyhow!(
                        "Failed to decrypt key material (CryptoPacket detected but \
                             decryption failed — system key may be unavailable): {}",
                        decrypt_err
                    )));
                }

                // Legacy fallback: the key material was stored unencrypted
                // (pre-fix rotate_key). Use the raw bytes directly.
                warn!(
                    "Key data could not be decrypted as CryptoPacket; \
                     treating as legacy unencrypted key material"
                );
                Ok(encrypted_data.to_vec())
            }
        }
    }

    /// Delete a backup
    pub async fn delete_backup(
        &self,
        _backup_id: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, "sys/backups", "delete").await?;
        // Placeholder
        Ok(true)
    }

    /// Encrypt data using a key
    ///
    /// If `key_version` is `Some(v)`, the key material at version `v` is used.
    /// Otherwise the latest version from key metadata is used.
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        user: &secreton_auth::User,
        key_version: Option<u32>,
    ) -> Result<(EncryptedData, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "encrypt")
            .await?;

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user).await?;

        // Use the caller-specified version, or fall back to the latest version
        let version = key_version.unwrap_or(key_info.version);

        // Retrieve key from storage - try versioned path first, then legacy
        let key_data_path = format!("key_data/{}/{}_v{}", user.id, key_name, version);
        let mut key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?;

        if key_entry.is_none() && version == 1 {
            let legacy_path = format!("key_data/{}/{}", user.id, key_name);
            key_entry = self
                .storage
                .get_by_path(&legacy_path)
                .await
                .map_err(SecretError::Storage)?;
        }

        let key_entry = key_entry.ok_or_else(|| SecretError::KeyNotFound {
            key_id: format!("{} (v{})", key_name, version),
        })?;

        // Decrypt the stored key data (with legacy fallback for unencrypted entries)
        let key_data = self.decrypt_key_material(&key_entry.encrypted_data).await?;

        // Encrypt data using crypto engine.
        // `self.crypto.encrypt` returns an `EncryptedData` that already contains
        // the internally-generated nonce, ciphertext, and tag. Use it directly
        // instead of substituting a separately-generated nonce (which would cause
        // a nonce mismatch on decryption).
        //
        // Map the key type to the correct encryption algorithm so that keys
        // created as chacha20-poly1305 actually encrypt with ChaCha20-Poly1305
        // instead of always defaulting to AES-256-GCM.
        // Reject asymmetric key types that cannot be used for symmetric encryption.
        let algorithm = match key_info.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "xchacha20-poly1305" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'xchacha20-poly1305' encryption is only supported via the transit engine.".to_string(),
                ));
            }
            "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ecdsa-secp256k1"
            | "ed25519" => {
                return Err(SecretError::InvalidOperation(format!(
                    "Key type '{}' does not support encryption. Use sign/verify instead.",
                    key_info.key_type
                )));
            }
            "x25519" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'x25519' is for key agreement, not direct encryption.".to_string(),
                ));
            }
            other => {
                // Legacy metadata may not have a key_type field, defaulting to
                // "unknown". Fall back to AES-256-GCM for backward compatibility
                // but warn so callers can fix their metadata.
                if other != "unknown" {
                    return Err(SecretError::InvalidOperation(format!(
                        "Unsupported key type for encryption: {}",
                        key_info.key_type
                    )));
                }
                warn!(
                    "Key '{}' has unknown key_type in metadata; defaulting to AES-256-GCM",
                    key_name
                );
                secreton_crypto::AlgorithmId::Aes256Gcm
            }
        };
        let encrypted_data = self
            .crypto
            .encrypt_with_algorithm(&key_data, plaintext, algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Create key ID for audit
        let key_id = format!("{}/{}", user.id, key_name);

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::EncryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        Ok((encrypted_data, version))
    }

    /// Decrypt data using a key
    ///
    /// If `key_version` is `Some(v)`, the key material at version `v` is used.
    /// Otherwise the latest version from key metadata is used.
    pub async fn decrypt(
        &self,
        key_name: &str,
        encrypted_data: &EncryptedData,
        user: &secreton_auth::User,
        key_version: Option<u32>,
    ) -> Result<(Vec<u8>, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "decrypt")
            .await?;

        // Get key info to retrieve latest version metadata
        let key_info = self.get_key(key_name, user).await?;

        // Use the caller-specified version, or fall back to the latest version
        let version = key_version.unwrap_or(key_info.version);

        // Retrieve key from storage - try versioned path first, then legacy
        let key_data_path = format!("key_data/{}/{}_v{}", user.id, key_name, version);
        let mut key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?;

        if key_entry.is_none() && version == 1 {
            let legacy_path = format!("key_data/{}/{}", user.id, key_name);
            key_entry = self
                .storage
                .get_by_path(&legacy_path)
                .await
                .map_err(SecretError::Storage)?;
        }

        let key_entry = key_entry.ok_or_else(|| SecretError::KeyNotFound {
            key_id: format!("{} (v{})", key_name, version),
        })?;

        // Decrypt the stored key data (with legacy fallback for unencrypted entries)
        let key_data = self.decrypt_key_material(&key_entry.encrypted_data).await?;

        // Decrypt the user data using the key.
        // `decrypt_full` is deprecated and always returns an error.
        // Use `decrypt_with_key` which accepts the full `EncryptedData` struct.
        let plaintext = self
            .crypto
            .decrypt_with_key(&key_data, encrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::DecryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        Ok((plaintext, version))
    }

    /// Sign data using a key
    ///
    /// If `key_version` is `Some(v)`, the key material at version `v` is used.
    /// Otherwise the latest version from key metadata is used.
    pub async fn sign_data(
        &self,
        key_name: &str,
        data: &[u8],
        user: &secreton_auth::User,
        key_version: Option<u32>,
    ) -> Result<SignResult, SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "sign")
            .await?;

        let key_info = self.get_key(key_name, user).await?;

        // Map key type to algorithm.
        // Symmetric key types (aes256-gcm, chacha20-poly1305, xchacha20-poly1305)
        // and key-agreement types (x25519) don't support signing.
        let algorithm = match key_info.key_type.as_str() {
            // RSA was removed with the `rsa` crate (RUSTSEC-2023-0071, an unfixed
            // timing side channel). Reject it explicitly so a caller gets a clear
            // message instead of a confusing "unknown key type".
            "rsa-2048" | "rsa-4096" => {
                return Err(SecretError::InvalidOperation(
                    "RSA keys are not supported. Use 'ed25519' for signatures or \
                     'ecdsa-p256'/'ecdsa-p384' where interoperability requires a NIST curve."
                        .to_string(),
                ));
            }
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            "ecdsa-secp256k1" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'ecdsa-secp256k1' signing is only supported via the transit engine."
                        .to_string(),
                ));
            }
            "aes256-gcm" | "chacha20-poly1305" | "xchacha20-poly1305" => {
                return Err(SecretError::InvalidOperation(format!(
                    "Key type '{}' does not support signing. Use encrypt/decrypt instead.",
                    key_info.key_type
                )));
            }
            "x25519" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'x25519' is for key agreement, not signing.".to_string(),
                ));
            }
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type for signing: {}",
                    key_info.key_type
                )));
            }
        };

        // Use the caller-specified version, or fall back to the latest version
        let version = key_version.unwrap_or(key_info.version);

        // Retrieve key from storage - try versioned path first, then legacy
        let key_data_path = format!("key_data/{}/{}_v{}", user.id, key_name, version);
        let mut key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?;

        if key_entry.is_none() && version == 1 {
            let legacy_path = format!("key_data/{}/{}", user.id, key_name);
            key_entry = self
                .storage
                .get_by_path(&legacy_path)
                .await
                .map_err(SecretError::Storage)?;
        }

        let key_entry = key_entry.ok_or_else(|| SecretError::KeyNotFound {
            key_id: format!("{} (v{})", key_name, version),
        })?;

        // Decrypt the stored key data (with legacy fallback for unencrypted entries)
        let key_data = self.decrypt_key_material(&key_entry.encrypted_data).await?;

        // Sign data using crypto engine
        let signature = self
            .crypto
            .sign_data(&key_data, data, algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Return base64 encoded signature
        use base64::Engine;
        let signature_str = base64::engine::general_purpose::STANDARD.encode(signature);

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::SigningOperation {
                key_id: key_id.clone(),
                data_size: data.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        // Map the AlgorithmId back to a human-readable algorithm name so the
        // handler can report the actual algorithm used (instead of a hardcoded
        // default that may not match the key type).
        let algorithm_name = match algorithm {
            secreton_crypto::AlgorithmId::EcdsaP256 => "ECDSA-P256",
            secreton_crypto::AlgorithmId::EcdsaP384 => "ECDSA-P384",
            secreton_crypto::AlgorithmId::Ed25519 => "ED25519",
            other => {
                // Fallback for any future algorithm variants
                return Ok(SignResult {
                    signature: signature_str,
                    key_version: version,
                    algorithm: format!("{:?}", other),
                });
            }
        };

        Ok(SignResult {
            signature: signature_str,
            key_version: version,
            algorithm: algorithm_name.to_string(),
        })
    }

    /// Verify signature using a key
    ///
    /// If `key_version` is `Some(v)`, the key material at version `v` is used.
    /// Otherwise the latest version from key metadata is used.
    pub async fn verify_data(
        &self,
        key_name: &str,
        data: &[u8],
        signature_b64: &[u8],
        user: &secreton_auth::User,
        key_version: Option<u32>,
    ) -> Result<(bool, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "verify")
            .await?;

        // Get key info to retrieve version and algorithm
        let key_info = self.get_key(key_name, user).await?;

        // Map key type to algorithm.
        // Symmetric key types and key-agreement types don't support verification.
        let algorithm = match key_info.key_type.as_str() {
            // RSA was removed with the `rsa` crate (RUSTSEC-2023-0071, an unfixed
            // timing side channel). Reject it explicitly so a caller gets a clear
            // message instead of a confusing "unknown key type".
            "rsa-2048" | "rsa-4096" => {
                return Err(SecretError::InvalidOperation(
                    "RSA keys are not supported. Use 'ed25519' for signatures or \
                     'ecdsa-p256'/'ecdsa-p384' where interoperability requires a NIST curve."
                        .to_string(),
                ));
            }
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            "ecdsa-secp256k1" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'ecdsa-secp256k1' verification is only supported via the transit engine.".to_string(),
                ));
            }
            "aes256-gcm" | "chacha20-poly1305" | "xchacha20-poly1305" => {
                return Err(SecretError::InvalidOperation(format!(
                    "Key type '{}' does not support verification. Use encrypt/decrypt instead.",
                    key_info.key_type
                )));
            }
            "x25519" => {
                return Err(SecretError::InvalidOperation(
                    "Key type 'x25519' is for key agreement, not verification.".to_string(),
                ));
            }
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type for verification: {}",
                    key_info.key_type
                )));
            }
        };

        // Decode base64 signature
        use base64::Engine;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| {
                SecretError::InvalidOperation(format!("Invalid base64 signature: {}", e))
            })?;

        // Use the caller-specified version, or fall back to the latest version
        let version = key_version.unwrap_or(key_info.version);

        // Retrieve key from storage - try versioned path first, then legacy
        let key_data_path = format!("key_data/{}/{}_v{}", user.id, key_name, version);
        let mut key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?;

        if key_entry.is_none() && version == 1 {
            let legacy_path = format!("key_data/{}/{}", user.id, key_name);
            key_entry = self
                .storage
                .get_by_path(&legacy_path)
                .await
                .map_err(SecretError::Storage)?;
        }

        let key_entry = key_entry.ok_or_else(|| SecretError::KeyNotFound {
            key_id: format!("{} (v{})", key_name, version),
        })?;

        // Decrypt the stored key data (with legacy fallback for unencrypted entries)
        let key_data = self.decrypt_key_material(&key_entry.encrypted_data).await?;

        // Verify signature
        let is_valid = self
            .crypto
            .verify_signature(&key_data, data, &signature, algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::VerificationOperation {
                key_id: key_id.clone(),
                data_size: data.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
                valid: is_valid,
            })
            .await;

        Ok((is_valid, version))
    }

    /// Compute hash of data
    pub async fn hash_data(
        &self,
        data: &[u8],
        algorithm: &str,
        user: &secreton_auth::User,
    ) -> Result<String, SecretError> {
        self.check_permission(user, "sys/crypto", "hash").await?;

        // Compute hash based on algorithm
        let hash_hex = match algorithm {
            "SHA-256" | "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            "SHA-512" | "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            "SHA3-256" | "sha3-256" => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported hash algorithm: {}",
                    algorithm
                )));
            }
        };

        Ok(hash_hex)
    }
}

/// Secret data structure
#[derive(Debug, Serialize)]
pub struct SecretData {
    pub path: String,
    pub data: HashMap<String, String>,
    pub metadata: SecretMetadata,
    pub version: u32,
    pub previous_version: Option<u32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Secret version info
#[derive(Debug, Serialize)]
pub struct SecretVersionInfo {
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Key information
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub version: u32,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Encryption result
#[derive(Debug, Serialize)]
pub struct EncryptResult {
    pub ciphertext: String,
    pub key_version: u32,
}

/// Decryption result
#[derive(Debug, Serialize)]
pub struct DecryptResult {
    pub plaintext: String,
}

// Tests in `services/secret.rs` also need updates because signatures changed.
// I will update the tests to create a mock user and pass it.

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_storage::{
        EncryptionMetadata, MemoryBackend, SecretEntry, SecurityLevel, StorageBackend,
    };

    use crate::services::audit::AuditLogger;
    use base64::Engine;

    // Mock user helper
    fn mock_user() -> secreton_auth::User {
        let id = Uuid::new_v4().to_string();
        secreton_auth::User {
            id: id.clone(),
            username: "user1".to_string(),
            email: Some("user1@example.com".to_string()),
            display_name: None,
            full_name: None,
            roles: vec!["admin".to_string()],
            permissions: vec![],
            policies: vec![],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
            mfa_enabled: false,
            mfa_secret: None,
            password_hash: "".to_string(),
            password_login_disabled: false,
            disabled: false,
            enabled: true,
            is_active: true,
            is_superuser: false,
        }
    }

    async fn seed_admin_policy(policy_service: &secreton_auth::PolicyService) {
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "admin_policy".to_string(),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "allow_all".to_string(),
                conditions: vec![],
                actions: vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "list".to_string(),
                    "list_versions".to_string(),
                    "rotate".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "sign".to_string(),
                    "verify".to_string(),
                    "hash".to_string(),
                    "write".to_string(),
                ],
                resources: vec![
                    "app/".to_string(),
                    "keys/".to_string(),
                    "sys/".to_string(),
                    "key_data/".to_string(),
                    "users/".to_string(),
                ],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };
        let p = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: None,
            parent_role: None,
            policies: vec![p.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let _ = policy_service.create_role(role).await;
    }

    #[tokio::test]
    async fn test_secreton_service_creation() {
        // Set root key for crypto service auto-unseal
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let secreton_service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await;
        assert!(secreton_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_secret_with_permission() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        // Seed secret
        let mut data = HashMap::new();
        data.insert("key1".to_string(), "value1".to_string());

        let user = mock_user();
        let user_uuid = Uuid::parse_str(&user.id).unwrap();

        let secret_entry = SecretEntry::new(
            "app/config".to_string(),
            crypto
                .encrypt_data(&serde_json::to_vec(&data).unwrap())
                .await
                .unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user_uuid,
        );
        let _ = storage.store(&secret_entry).await;

        let service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let secret = service.get_secret("app/config", &user, None).await.unwrap();
        assert_eq!(secret.path, "app/config");
        assert!(secret.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_put_secret_placeholder() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        let user = mock_user();
        let secret = service
            .put_secret("app/admin", data, None, &user, None)
            .await
            .unwrap();
        assert_eq!(secret.path, "app/admin");
        assert!(secret.data.contains_key("username"));
    }

    #[tokio::test]
    async fn secret_api_cannot_write_or_delete_an_initialization_artifact() {
        // Regression: the secret API wrote through `store`/`upsert`, which the file backend
        // does not serialise with the seal's fenced writes. An ordinary `put_secret` at
        // `sys/init` (or `sys/init_staging`, `sys/init_lease`, `sys/root_key_enc`,
        // `sys/root_identity`) could therefore overwrite or race an initialization artifact
        // — replacing the init config, the lease, or the root identity of a live vault.
        // Those paths are reachable only by the seal service, so the secret API must refuse
        // them before doing any work.
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());
        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let user = mock_user();

        for path in [
            "sys/init",
            "sys/init_staging",
            "sys/init_lease",
            "sys/root_key_enc",
            "sys/root_identity",
        ] {
            let mut data = HashMap::new();
            data.insert("tampered".to_string(), "true".to_string());
            let put = service.put_secret(path, data, None, &user, None).await;
            assert!(
                matches!(put, Err(SecretError::InvalidOperation(_))),
                "a write to the reserved initialization path '{}' must be refused, got {:?}",
                path,
                put.as_ref().map(|_| ())
            );
            let delete = service.delete_secret(path, &user).await;
            assert!(
                matches!(delete, Err(SecretError::InvalidOperation(_))),
                "a delete of the reserved initialization path '{}' must be refused, got {:?}",
                path,
                delete
            );
            assert!(
                storage.get_by_path(path).await.expect("storage").is_none(),
                "the refused write must not have created '{}'",
                path
            );
        }
    }

    #[tokio::test]
    async fn test_encrypt_placeholder_response() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        // On-disk JSON layout the secret service reads back for a stored key.
        // Declared locally: it previously came from the deleted core crate, and the
        // test is the only consumer.
        #[derive(serde::Serialize)]
        struct KeyEntry {
            id: String,
            key: String,
            salt: String,
            version: u32,
            created_at: u64,
            rotated_at: u64,
            active: bool,
            metadata: std::collections::HashMap<String, String>,
            expires_at: u64,
        }

        let key_entry = KeyEntry {
            id: "key1".to_string(),
            key: base64::engine::general_purpose::STANDARD.encode(vec![0u8; 32]),
            salt: base64::engine::general_purpose::STANDARD.encode(vec![0u8; 16]),
            version: 1,
            created_at: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
            rotated_at: u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0),
            active: true,
            metadata: Default::default(),
            expires_at: 0,
        };

        // Encrypt the raw key data using CryptoService
        let raw_key = vec![0u8; 32];
        let encrypted_key = crypto
            .encrypt_data(&raw_key)
            .await
            .expect("failed to encrypt key data");

        let user = mock_user();

        // Seed Key Metadata (required by get_key) using user.id
        let key_metadata_entry = SecretEntry::new(
            format!("keys/{}/key1", user.id),
            serde_json::to_vec(&key_entry).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_metadata_entry).await;

        let key_storage_entry = SecretEntry::new(
            format!("key_data/{}/key1", user.id),
            encrypted_key,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_storage_entry).await;

        let service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let (result, key_version) = service
            .encrypt("key1", "plaintext".as_bytes(), &user, None)
            .await
            .unwrap();
        assert!(!result.ciphertext.is_empty());
        assert_eq!(key_version, 1);
    }

    #[tokio::test]
    async fn test_create_key_permission_denied() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let user = secreton_auth::User {
            id: "user_no_role".to_string(),
            username: "user_no_role".to_string(),
            email: None,
            roles: vec![],
            permissions: vec![],
            policies: vec![],
            display_name: None,
            full_name: None,
            password_hash: "".to_string(),
            password_login_disabled: false,
            is_active: true,
            is_superuser: false,
            disabled: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        };

        let result = service.create_key("test_key", "aes256-gcm", &user).await;

        assert!(matches!(result, Err(SecretError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_create_key_permission_allowed() {
        let _env = crate::test_support::with_root_key();
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service.clone(),
            performance,
        )
        .await
        .unwrap();

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "allow_create_key".to_string(),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "rule_allow_create".to_string(),
                conditions: vec![],
                actions: vec!["create".to_string()],
                resources: vec!["keys/".to_string()],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };

        let created_policy = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: "key_creator".to_string(),
            description: None,
            parent_role: None,
            policies: vec![created_policy.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        policy_service.create_role(role.clone()).await.unwrap();

        let user = secreton_auth::User {
            id: "user_with_role".to_string(),
            username: "user_with_role".to_string(),
            email: None,
            roles: vec!["key_creator".to_string()],
            permissions: vec![],
            policies: vec![],
            display_name: None,
            full_name: None,
            password_hash: "".to_string(),
            password_login_disabled: false,
            is_active: true,
            is_superuser: false,
            disabled: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        };

        let result = service
            .create_key("test_key_allowed", "aes256-gcm", &user)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_secret_versioning() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let user = mock_user();

        // 1. Create Secret (v1)
        let mut data1 = HashMap::new();
        data1.insert("k".to_string(), "v1".to_string());
        let s1 = service
            .put_secret("app/ver", data1, None, &user, None)
            .await
            .unwrap();
        assert_eq!(s1.version, 1);

        // 2. Update Secret (v2)
        let mut data2 = HashMap::new();
        data2.insert("k".to_string(), "v2".to_string());
        let s2 = service
            .put_secret("app/ver", data2, None, &user, None)
            .await
            .unwrap();
        assert_eq!(s2.version, 2);

        // 3. Get Current (v2)
        let get_curr = service.get_secret("app/ver", &user, None).await.unwrap();
        assert_eq!(get_curr.version, 2);
        assert_eq!(get_curr.data.get("k").unwrap(), "v2");

        // 4. Get Old (v1)
        let get_v1 = service.get_secret("app/ver", &user, Some(1)).await.unwrap();
        assert_eq!(get_v1.version, 1);
        assert_eq!(get_v1.data.get("k").unwrap(), "v1");

        // 5. List Versions
        let versions = service
            .list_secret_versions("app/ver", &user)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2); // Sorted desc
        assert_eq!(versions[1].version, 1);
    }

    #[tokio::test]
    async fn test_cache_version_mismatch() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let user = mock_user();

        // 1. Create Secret (v1)
        let mut data = HashMap::new();
        data.insert("k".to_string(), "v1".to_string());
        service
            .put_secret("app/race", data, None, &user, None)
            .await
            .unwrap();

        // 2. Pollute cache with "future" version (v2)
        // We need to construct the cache payload: [v2_bytes] + [json_data]
        let v2: u32 = 2;
        let mut cache_payload = v2.to_be_bytes().to_vec();
        let fake_data =
            serde_json::to_vec(&HashMap::from([("k".to_string(), "fake_v2".to_string())])).unwrap();
        cache_payload.extend_from_slice(&fake_data);

        service
            .performance
            .put_cached("app/race".to_string(), cache_payload)
            .await
            .unwrap();

        // 3. Get Secret (current). Storage still has v1.
        let result = service.get_secret("app/race", &user, None).await.unwrap();

        // 4. Assert we got v1 (from storage), NOT fake_v2 (from cache)
        assert_eq!(result.version, 1);
        assert_eq!(result.data.get("k").unwrap(), "v1");

        // 5. Assert cache is now corrected to v1
        let cached = service
            .performance
            .get_cached("app/race")
            .await
            .unwrap()
            .unwrap();
        let (ver_bytes, _) = cached.split_at(4);
        let cached_ver = u32::from_be_bytes(ver_bytes.try_into().unwrap());
        assert_eq!(cached_ver, 1);
    }
}

#[cfg(test)]
mod list_secrets_tests {
    use super::*;
    use crate::services::audit::AuditLogger;
    use secreton_storage::{
        EncryptionMetadata, MemoryBackend, SecretEntry, SecurityLevel, StorageBackend,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_mock_user(id: &str, roles: Vec<String>) -> secreton_auth::User {
        secreton_auth::User {
            id: id.to_string(),
            username: format!("user_{}", id),
            email: Some(format!("user_{}@example.com", id)),
            roles,
            permissions: vec![],
            policies: vec![],
            display_name: None,
            full_name: None,
            password_hash: "".to_string(),
            password_login_disabled: false,
            is_active: true,
            is_superuser: false, // Strict check
            disabled: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        }
    }

    // Helper to seed policy
    async fn seed_allow_all_policy(policy_service: &secreton_auth::PolicyService, role_name: &str) {
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let policy = Policy {
            id: Uuid::new_v4(),
            name: format!("{}_policy", role_name),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "allow_all".to_string(),
                conditions: vec![],
                actions: vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "list".to_string(),
                    "list_versions".to_string(),
                    "rotate".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "sign".to_string(),
                    "verify".to_string(),
                    "hash".to_string(),
                    "write".to_string(),
                ],
                resources: vec![
                    "*".to_string(),
                    "app/".to_string(),
                    "keys/".to_string(),
                    "sys/".to_string(),
                    "key_data/".to_string(),
                    "users/".to_string(),
                ],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };
        let p = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: role_name.to_string(),
            description: None,
            parent_role: None,
            policies: vec![p.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let _ = policy_service.create_role(role).await;
    }

    #[tokio::test]
    async fn test_list_secrets_permissions() {
        let _env = crate::test_support::with_root_key();
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(
            AuditLogger::new(storage.clone(), 2555, 1000, true)
                .await
                .unwrap(),
        );
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policies for user and admin
        seed_allow_all_policy(&policy_service, "user").await;
        seed_allow_all_policy(&policy_service, "admin").await;

        let service = SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let user1_uuid = Uuid::new_v4();
        let user2_uuid = Uuid::new_v4();

        // Create secrets for user1
        let entry1 = SecretEntry::new(
            "app/user1/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).await.unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user1_uuid,
        );
        storage.store(&entry1).await.unwrap();

        // Create secrets for user2
        let entry2 = SecretEntry::new(
            "app/user2/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).await.unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user2_uuid,
        );
        storage.store(&entry2).await.unwrap();

        // Test user1 accessing list (should only see their own)
        let user1 = create_mock_user(&user1_uuid.to_string(), vec!["user".to_string()]);
        let secrets_user1 = service
            .list_secrets(None, &user1, None, None)
            .await
            .unwrap();
        assert_eq!(secrets_user1.len(), 1);
        assert_eq!(secrets_user1[0].path, "app/user1/secret1");

        // Test user2 accessing list
        let user2 = create_mock_user(&user2_uuid.to_string(), vec!["user".to_string()]);
        let secrets_user2 = service
            .list_secrets(None, &user2, None, None)
            .await
            .unwrap();
        assert_eq!(secrets_user2.len(), 1);
        assert_eq!(secrets_user2[0].path, "app/user2/secret1");

        // Test admin accessing list (should see ZERO, because strict isolation is enforced)
        let admin_uuid = Uuid::new_v4();
        let admin = create_mock_user(&admin_uuid.to_string(), vec!["admin".to_string()]);
        let secrets_admin = service
            .list_secrets(None, &admin, None, None)
            .await
            .unwrap();

        // Expectation changed from 2 to 0 to reflect strict Zero Trust isolation
        assert_eq!(secrets_admin.len(), 0);
    }
}

impl From<SecretError> for secreton_domain::SecretonError {
    fn from(e: SecretError) -> Self {
        use secreton_domain::SecretonError as S;
        match e {
            SecretError::SecretNotFound { path } => S::NotFound { resource: path },
            SecretError::KeyNotFound { key_id } => S::NotFound { resource: key_id },
            SecretError::PolicyNotFound { name } => S::PolicyNotFound { policy_id: name },
            SecretError::BackupNotFound { id } => S::NotFound { resource: id },
            SecretError::PermissionDenied(message) => S::Authorization { message },
            SecretError::InvalidOperation(message) => S::Validation { message },
            // Everything else is an internal failure. The HTTP layer replaces 5xx
            // bodies wholesale, so the detail below only ever reaches the log.
            other => S::Internal {
                message: other.to_string(),
            },
        }
    }
}
