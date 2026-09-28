use crate::services::audit_storage::StorageAuditDevice;
use anyhow::Result;
use secreton_auth::governance::policies::audit::{
    AuditEvent, AuditEventType as CoreAuditEventType, AuditService, AuditStatus,
};
use secreton_storage::StorageBackend;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Audit logger service adapter
pub struct AuditLogger {
    service: Arc<AuditService>,
    storage: Arc<dyn StorageBackend + Send + Sync>,
    enabled: bool,
}

impl AuditLogger {
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        retention_days: u32,
        max_batch_size: usize,
        enabled: bool,
    ) -> Result<Self> {
        let service = Arc::new(AuditService::new(max_batch_size));
        if enabled {
            let device = StorageAuditDevice::new(storage.clone(), retention_days);
            service.add_device(Box::new(device)).await;
        }
        Ok(Self {
            service,
            storage,
            enabled,
        })
    }

    pub async fn flush(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        self.service
            .flush()
            .await
            .map_err(|e| anyhow::anyhow!("Audit flush failed: {}", e))
    }

    pub async fn log_event(&self, event: SecurityEventType) {
        if !self.enabled {
            return;
        }
        let (core_type, status, user, resource, op, metadata) = match event {
            SecurityEventType::SecretAccess {
                secret_path,
                user,
                action,
            } => (
                CoreAuditEventType::SecretRead,
                AuditStatus::Success,
                user,
                secret_path,
                action,
                None,
            ),
            SecurityEventType::SecretAccessDenied {
                secret_path,
                user,
                action,
                reason,
            } => (
                CoreAuditEventType::Custom(format!("secret.{}", action.to_lowercase())),
                AuditStatus::Denied,
                user,
                secret_path,
                action,
                Some(vec![("reason".to_string(), reason)].into_iter().collect()),
            ),
            SecurityEventType::SecretCreation { secret_path, user } => (
                CoreAuditEventType::SecretWrite,
                AuditStatus::Success,
                user,
                secret_path,
                "create".to_string(),
                None,
            ),
            SecurityEventType::SecretVersionChange {
                secret_path,
                old_version,
                new_version,
                user,
            } => (
                CoreAuditEventType::SecretWrite,
                AuditStatus::Success,
                user,
                secret_path,
                "update_version".to_string(),
                Some(
                    vec![
                        ("old_version".to_string(), old_version.to_string()),
                        ("new_version".to_string(), new_version.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SecretDeletion { secret_path, user } => (
                CoreAuditEventType::SecretDelete,
                AuditStatus::Success,
                user,
                secret_path,
                "delete".to_string(),
                None,
            ),
            SecurityEventType::KeyGeneration {
                key_type,
                key_id,
                algorithm,
                user,
            } => (
                CoreAuditEventType::Custom("key.generate".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "generate".to_string(),
                Some(
                    vec![
                        ("key_type".to_string(), key_type.to_string()),
                        ("algorithm".to_string(), algorithm.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::KeyRotation {
                old_key_id,
                new_key_id,
                algorithm,
                user,
            } => (
                CoreAuditEventType::Custom("key.rotate".to_string()),
                AuditStatus::Success,
                user,
                new_key_id,
                "rotate".to_string(),
                Some(
                    vec![
                        ("old_key_id".to_string(), old_key_id),
                        ("algorithm".to_string(), algorithm.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::EncryptionOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.encrypt".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "encrypt".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::DecryptionOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.decrypt".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "decrypt".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::KeyDeletion { key_id, user } => (
                CoreAuditEventType::Custom("key.delete".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "delete".to_string(),
                None,
            ),
            SecurityEventType::AuthenticationSuccess { user, method } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Success,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::AuthenticationFailure {
                user,
                method,
                reason,
            } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Failure,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(
                    vec![
                        ("method".to_string(), method),
                        ("reason".to_string(), reason),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SessionTerminated {
                user,
                session_id,
                reason,
            } => (
                CoreAuditEventType::AuthLogout,
                AuditStatus::Success,
                user,
                "session".to_string(),
                "terminate".to_string(),
                Some(
                    vec![
                        ("session_id".to_string(), session_id),
                        ("reason".to_string(), reason),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::MfaSetup { user, method } => (
                CoreAuditEventType::Custom("mfa.setup".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "setup".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::MFASuccess { user, method } => (
                CoreAuditEventType::Custom("mfa.verify".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "verify".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::MFARemoval { user, method } => (
                CoreAuditEventType::Custom("mfa.remove".to_string()),
                AuditStatus::Success,
                user,
                "mfa".to_string(),
                "remove".to_string(),
                Some(vec![("method".to_string(), method)].into_iter().collect()),
            ),
            SecurityEventType::LoginSuccess {
                user,
                method,
                ip_address,
            } => (
                CoreAuditEventType::AuthLogin,
                AuditStatus::Success,
                user,
                "auth".to_string(),
                "login".to_string(),
                Some(
                    vec![
                        ("method".to_string(), method),
                        ("ip_address".to_string(), ip_address.unwrap_or_default()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::Logout {
                user,
                session_id,
                ip_address,
                user_agent,
            } => (
                CoreAuditEventType::AuthLogout,
                AuditStatus::Success,
                user,
                "session".to_string(),
                "logout".to_string(),
                Some(
                    vec![
                        ("session_id".to_string(), session_id),
                        ("ip_address".to_string(), ip_address.unwrap_or_default()),
                        ("user_agent".to_string(), user_agent.unwrap_or_default()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SshCaGeneration { user } => (
                CoreAuditEventType::Custom("ssh.ca.generate".to_string()),
                AuditStatus::Success,
                user,
                "ssh/ca".to_string(),
                "generate".to_string(),
                None,
            ),
            SecurityEventType::SshKeySign {
                user,
                principals,
                ttl,
            } => (
                CoreAuditEventType::Custom("ssh.key.sign".to_string()),
                AuditStatus::Success,
                user,
                "ssh/sign".to_string(),
                "sign".to_string(),
                Some(
                    vec![
                        ("principals".to_string(), principals.join(",")),
                        ("ttl".to_string(), ttl.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::SigningOperation {
                key_id,
                user,
                data_size,
            } => (
                CoreAuditEventType::Custom("crypto.sign".to_string()),
                AuditStatus::Success,
                user,
                key_id,
                "sign".to_string(),
                Some(
                    vec![("data_size".to_string(), data_size.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::VerificationOperation {
                key_id,
                user,
                data_size,
                valid,
            } => (
                CoreAuditEventType::Custom("crypto.verify".to_string()),
                if valid {
                    AuditStatus::Success
                } else {
                    AuditStatus::Failure
                },
                user,
                key_id,
                "verify".to_string(),
                Some(
                    vec![
                        ("data_size".to_string(), data_size.to_string()),
                        ("valid".to_string(), valid.to_string()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            SecurityEventType::PolicyChange {
                policy_name,
                user,
                action,
            } => (
                CoreAuditEventType::Custom("policy.change".to_string()),
                AuditStatus::Success,
                user,
                policy_name,
                action,
                None,
            ),
            SecurityEventType::ConfigChange { user, changed_keys } => (
                CoreAuditEventType::Custom("config.change".to_string()),
                AuditStatus::Success,
                user,
                "config".to_string(),
                "change".to_string(),
                Some(
                    vec![("changed_keys".to_string(), changed_keys.join(","))]
                        .into_iter()
                        .collect(),
                ),
            ),
            SecurityEventType::SealOperation {
                operation,
                user,
                success,
            } => (
                CoreAuditEventType::Custom("seal.operation".to_string()),
                if success {
                    AuditStatus::Success
                } else {
                    AuditStatus::Failure
                },
                user,
                "seal".to_string(),
                operation,
                Some(
                    vec![("success".to_string(), success.to_string())]
                        .into_iter()
                        .collect(),
                ),
            ),
        };

        let mut audit_event = AuditEvent::new(core_type, status, user, resource, op);
        if let Some(meta) = metadata {
            audit_event.metadata = meta;
        }
        self.service.log(audit_event).await;
    }
}

pub enum SecurityEventType {
    SecretAccess {
        secret_path: String,
        user: String,
        action: String,
    },
    /// A secret operation the API refused before touching storage.
    ///
    /// The rejection paths that never reach the storage layer — an attempt to write or
    /// delete a seal initialization artifact through the secret API, for instance — would
    /// otherwise leave no trace at all, so they are recorded here rather than only returned
    /// to the caller.
    SecretAccessDenied {
        secret_path: String,
        user: String,
        action: String,
        reason: String,
    },
    SecretCreation {
        secret_path: String,
        user: String,
    },
    SecretVersionChange {
        secret_path: String,
        old_version: u32,
        new_version: u32,
        user: String,
    },
    SecretDeletion {
        secret_path: String,
        user: String,
    },
    KeyGeneration {
        key_type: String,
        key_id: String,
        algorithm: String,
        user: String,
    },
    KeyRotation {
        old_key_id: String,
        new_key_id: String,
        algorithm: String,
        user: String,
    },
    EncryptionOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    DecryptionOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    SigningOperation {
        key_id: String,
        user: String,
        data_size: u64,
    },
    VerificationOperation {
        key_id: String,
        user: String,
        data_size: u64,
        valid: bool,
    },
    PolicyChange {
        policy_name: String,
        user: String,
        action: String,
    },
    ConfigChange {
        user: String,
        changed_keys: Vec<String>,
    },
    SealOperation {
        operation: String,
        user: String,
        success: bool,
    },
    AuthenticationSuccess {
        user: String,
        method: String,
    },
    AuthenticationFailure {
        user: String,
        method: String,
        reason: String,
    },
    SessionTerminated {
        user: String,
        session_id: String,
        reason: String,
    },
    MfaSetup {
        user: String,
        method: String,
    },
    MFASuccess {
        user: String,
        method: String,
    },
    MFARemoval {
        user: String,
        method: String,
    },
    KeyDeletion {
        key_id: String,
        user: String,
    },
    LoginSuccess {
        user: String,
        method: String,
        ip_address: Option<String>,
    },
    Logout {
        user: String,
        session_id: String,
        ip_address: Option<String>,
        user_agent: Option<String>,
    },
    SshCaGeneration {
        user: String,
    },
    SshKeySign {
        user: String,
        principals: Vec<String>,
        ttl: u64,
    },
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    CSV,
    JSON,
}

/// Wrapper that pairs an `AuditEntry` with the original username string.
///
/// `AuditEntry.user_id` is a `Uuid`, but the source `AuditEvent.user` is a
/// free-form string (e.g. `"admin"`) that almost never parses as a valid UUID.
/// This struct carries the original value so callers don't have to rely on a
/// convention key stashed inside `details`.
#[derive(Debug, Clone)]
pub struct RichAuditEntry {
    /// The original username from the audit event.
    pub original_user: String,
    /// The underlying storage-level audit entry.
    pub entry: secreton_storage::models::storage_models::AuditEntry,
}

#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    pub user: Option<String>,
    pub action: Option<String>,
    pub path: Option<String>,
    pub start_date: Option<chrono::DateTime<chrono::Utc>>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Maximum number of storage entries to scan. `None` falls back to
    /// [`AUDIT_QUERY_DEFAULT_MAX_ENTRIES`] inside `get_entries`. Compliance
    /// callers (e.g. `export_data`) override this to a much higher value to
    /// avoid silently truncating the export.
    pub limit: Option<u32>,
}

/// Default safety cap for `get_entries` scans when `AuditFilters.limit` is
/// `None`. Bounds memory use on large audit logs (PostgreSQL no longer
/// imposes an implicit `LIMIT 100` after the lifecycle PR).
pub const AUDIT_QUERY_DEFAULT_MAX_ENTRIES: u32 = 10_000;

/// Higher cap used by `export_data` so that compliance exports are not
/// silently truncated at the default 10k. If the export ever returns
/// exactly this many rows the operator is warned (see `export_data`).
pub const AUDIT_EXPORT_MAX_ENTRIES: u32 = 1_000_000;

impl AuditFilters {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn by_user(user: String) -> Self {
        Self {
            user: Some(user),
            ..Default::default()
        }
    }
    pub fn by_path(path: String) -> Self {
        Self {
            path: Some(path),
            ..Default::default()
        }
    }
}

impl AuditLogger {
    /// Get audit entries based on filters
    pub async fn get_entries(&self, filters: AuditFilters) -> Result<Vec<RichAuditEntry>> {
        // Optimize query by using a more specific prefix if time range allows
        use chrono::Datelike;
        let prefix = if let (Some(start), Some(end)) = (filters.start_date, filters.end_date) {
            if start.year() == end.year() {
                if start.month() == end.month() {
                    if start.day() == end.day() {
                        format!(
                            "sys/audit/{}/{:02}/{:02}/",
                            start.year(),
                            start.month(),
                            start.day()
                        )
                    } else {
                        format!("sys/audit/{}/{:02}/", start.year(), start.month())
                    }
                } else {
                    format!("sys/audit/{}/", start.year())
                }
            } else {
                "sys/audit/".to_string()
            }
        } else {
            "sys/audit/".to_string()
        };

        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this query was implicitly bounded; without an explicit limit it
        // would now perform an unbounded full-table scan on a busy audit
        // log (potentially millions of entries) and load the entire result
        // set into memory.
        //
        // The cap is overridable via `AuditFilters.limit` so that compliance
        // callers (e.g. `export_data`) can request a much larger window
        // without silently truncating. When the cap is hit we log a WARN so
        // operators notice that results may be incomplete.
        //
        // TODO: Replace the in-memory filter loop below with backend-level
        // filtering on user/action/path/timestamp so this cap is no longer
        // necessary.
        let scan_limit = filters.limit.unwrap_or(AUDIT_QUERY_DEFAULT_MAX_ENTRIES);
        // Set `include_expired: true` so the storage layer does not filter out
        // audit entries whose `expires_at` (set to `now + retention_days` by
        // `StorageAuditDevice`) has passed. The audit subsystem owns its own
        // retention via dedicated cleanup paths; the query layer must not
        // silently drop entries that are still on disk and still within the
        // caller's requested time window. Without this flag, the PostgreSQL
        // backend (which now honors `include_expired`) would hide post-retention
        // audit rows from compliance exports while older backends (InMemory,
        // MySQL, etc.) would behave consistently — but only because PostgreSQL
        // previously had no expiration filter. This makes that consistency
        // explicit instead of relying on backend-specific quirks.
        let query_params = secreton_storage::QueryParams {
            path_prefix: Some(prefix),
            limit: Some(scan_limit),
            include_expired: true,
            ..Default::default()
        };

        // Flush buffered events to storage before querying so recent entries are visible.
        // Only flush when auditing is enabled — when disabled, no devices are registered
        // so there is nothing to flush, but we still want to query historical data.
        if self.enabled
            && let Err(e) = self.service.flush().await
        {
            tracing::warn!(
                "Audit flush failed before query, recent events may be missing: {}",
                e
            );
        }

        let entries = self.storage.list(&query_params).await?;
        // Warn when the storage scan returns exactly `scan_limit` rows: this
        // strongly suggests the cap was hit and additional matching entries
        // exist beyond it. Filtering happens client-side below, so a rare
        // filter could legitimately drop everything and produce zero results
        // even though matches exist past the cap — operators relying on
        // user/action/path filters should be aware that the cap applies
        // *before* filtering.
        if u32::try_from(entries.len()).unwrap_or(u32::MAX) >= scan_limit {
            tracing::warn!(
                "Audit query reached scan limit of {} entries; results may be incomplete. \
                 Pass `AuditFilters.limit` to widen the window or narrow the time range.",
                scan_limit,
            );
        }
        let mut results = Vec::new();

        for entry in entries {
            if let Some(log_data) = entry.metadata.get("log_data")
                && let Ok(event) = serde_json::from_str::<AuditEvent>(log_data)
            {
                // Apply filters
                if let Some(user) = &filters.user
                    && &event.user != user
                {
                    continue;
                }
                if let Some(action) = &filters.action
                    && &event.operation != action
                {
                    continue;
                }
                if let Some(path) = &filters.path
                    && &event.resource != path
                {
                    continue;
                }
                if let Some(start) = filters.start_date
                    && event.timestamp < start
                {
                    continue;
                }
                if let Some(end) = filters.end_date
                    && event.timestamp > end
                {
                    continue;
                }

                let id = Uuid::parse_str(&event.id).unwrap_or_default();
                let user_id = Uuid::parse_str(&event.user).unwrap_or_default();
                let original_user = event.user.clone();
                let timestamp = event.timestamp;
                let action = event.operation.clone();
                let resource_type = event.resource.clone();
                let ip_address = event.client_ip.clone();
                let success = matches!(event.status, AuditStatus::Success);
                let details: HashMap<String, serde_json::Value> = event
                    .metadata
                    .into_iter()
                    .map(|(k, v)| (k, serde_json::Value::String(v)))
                    .collect();
                results.push(RichAuditEntry {
                    original_user,
                    entry: secreton_storage::models::storage_models::AuditEntry {
                        id,
                        timestamp,
                        user_id,
                        action,
                        resource_type,
                        resource_id: None,
                        details,
                        ip_address,
                        user_agent: None,
                        success,
                        error_message: None,
                    },
                });
            }
        }

        results.sort_by(|a, b| b.entry.timestamp.cmp(&a.entry.timestamp));
        Ok(results)
    }

    /// Export audit data
    ///
    /// Compliance-oriented exports widen the storage scan cap to
    /// [`AUDIT_EXPORT_MAX_ENTRIES`] when the caller has not specified one,
    /// so that the default `get_entries` cap (10k) does not silently
    /// truncate exports of large audit logs. Callers who need different
    /// behaviour can pre-populate `filters.limit`.
    pub async fn export_data(
        &self,
        format: ExportFormat,
        mut filters: AuditFilters,
    ) -> Result<Vec<u8>> {
        if filters.limit.is_none() {
            filters.limit = Some(AUDIT_EXPORT_MAX_ENTRIES);
        }
        let entries = self.get_entries(filters).await?;

        match format {
            ExportFormat::JSON => {
                // Build export-friendly structs with the real username
                let export_entries: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|rich| {
                        let e = &rich.entry;
                        serde_json::json!({
                            "id": e.id.to_string(),
                            "timestamp": e.timestamp,
                            "user": rich.original_user,
                            "action": e.action,
                            "resource_type": e.resource_type,
                            "resource_id": e.resource_id,
                            "details": e.details,
                            "ip_address": e.ip_address,
                            "user_agent": e.user_agent,
                            "success": e.success,
                            "error_message": e.error_message,
                        })
                    })
                    .collect();
                let json = serde_json::to_vec_pretty(&export_entries)?;
                Ok(json)
            }
            ExportFormat::CSV => {
                let mut csv = String::from(
                    "timestamp,user,action,resource,resource_id,ip_address,user_agent,success\n",
                );
                for rich in &entries {
                    let e = &rich.entry;
                    csv.push_str(&format!(
                        "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"\n",
                        e.timestamp.to_string().replace('"', "\"\""),
                        rich.original_user.replace('"', "\"\""),
                        e.action.replace('"', "\"\""),
                        e.resource_type.replace('"', "\"\""),
                        e.resource_id
                            .as_deref()
                            .unwrap_or_default()
                            .replace('"', "\"\""),
                        e.ip_address
                            .as_deref()
                            .unwrap_or_default()
                            .replace('"', "\"\""),
                        e.user_agent
                            .as_deref()
                            .unwrap_or_default()
                            .replace('"', "\"\""),
                        e.success
                    ));
                }
                Ok(csv.into_bytes())
            }
        }
    }
}
