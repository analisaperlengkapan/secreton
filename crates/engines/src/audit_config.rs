//! Audit configuration.
//!
//! Lifted out of the former 2111-line `secreton-config` crate, which defined a second,
//! competing `ServerConfig` that nothing in the running server ever read. These are the only
//! types from it that the live configuration actually uses.

use serde::{Deserialize, Serialize};

/// Audit configuration
///
/// `default` so that a `[audit]` table needs only the keys it wants to change. Without it
/// serde demands every field, and the committed `secreton.toml` — which sets `enabled`,
/// `retention_days` and `max_batch_size` — failed to deserialize with "missing field
/// `level`", stopping the server before it bound a port. Every other config struct here
/// carries the same attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,

    /// Audit log level
    pub level: AuditLevel,

    /// Storage backend for audit logs
    pub storage: AuditStorage,

    /// Retention period in days
    pub retention_days: u32,

    /// Maximum audit entries per batch
    pub max_batch_size: usize,

    /// Audit filters
    pub filters: Vec<AuditFilter>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: AuditLevel::Detailed,
            storage: AuditStorage::File,
            retention_days: 2555,
            max_batch_size: 100,
            filters: Vec::new(),
        }
    }
}

/// Audit log levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditLevel {
    Minimal,
    Standard,
    Detailed,
}

/// Audit storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditStorage {
    File,
    Database,
    Syslog,
    External,
}

/// Audit filters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter name
    pub name: String,

    /// Filter rules
    pub rules: Vec<AuditRule>,
}

/// Audit rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRule {
    /// Field to filter on
    pub field: String,

    /// Operator
    pub operator: AuditOperator,

    /// Value to match
    pub value: String,
}

/// Audit operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    Regex,
}
