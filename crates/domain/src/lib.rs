//! # Secreton Domain
//!
//! The shared vocabulary of the workspace: the unified error type, the API envelope, and the
//! value types every other crate agrees on.
//!
//! This crate is deliberately **pure** — no I/O, no database drivers, no web framework. That is
//! what lets it be depended on by the Axum server *and* by the Leptos UI compiled to
//! `wasm32-unknown-unknown`. Anything that needs a socket, a file handle, or a `tokio` runtime
//! belongs in a crate above this one.

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod csp;
pub mod dto;
pub mod error;
pub mod models;
pub mod password;
pub mod proxy;
pub mod security;
pub mod session;

pub use api::{ApiResponse, PaginationParams, QueryParams};
pub use audit::AuditEvent;
pub use error::{Result, SecretonError};
pub use models::oauth_state::OAuthState;
pub use password::PasswordPolicy;
pub use security::SecurityLevel;

/// Health of a single subsystem, reported by `/health` and the readiness probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum ServiceHealth {
    Healthy,
    Degraded(String),
    Unhealthy(String),
}

impl ServiceHealth {
    /// Whether the subsystem can still serve traffic. `Degraded` is intentionally
    /// considered serving: a slow cache should not fail a readiness probe.
    pub fn is_serving(&self) -> bool {
        !matches!(self, ServiceHealth::Unhealthy(_))
    }
}
