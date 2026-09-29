//! Authentication service facade for the API layer.
//!
//! This service provides a simplified interface to the unified authentication system,
//! delegating actual authentication logic to the auth crate while maintaining
//! API-specific concerns like session management and storage integration.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::services::crypto::CryptoService;
use secreton_auth::MfaService; // Import MfaService trait
use secreton_auth::{
    AuthResult, AuthService as UnifiedAuthService, JwtTokenService, LoginRequest, TokenConfig,
    User, UserPassAuthMethod,
};
use secreton_storage::{
    EncryptionMetadata, QueryParams, SecretEntry, SecurityLevel, StorageBackend, StorageFence,
};
use thiserror::Error;

pub const USER_STORAGE_PREFIX: &str = "users/";
const SESSION_STORAGE_PREFIX: &str = "sys/auth/sessions/";
/// Storage prefix for persisted revoked tokens.  Each entry is keyed by the
/// SHA-256 hash of the token so the raw token material is never written to
/// storage.  Entries carry `expires_at` equal to the token's own expiry and
/// are cleaned up via `delete_expired`.
const REVOKED_TOKEN_STORAGE_PREFIX: &str = "sys/auth/revoked-tokens/";

/// Storage prefix for refresh-token *reservations*: the single-use slot claimed before a
/// refresh exchange does its fallible work, and converted into a permanent revocation once
/// a new session exists.
///
/// Keyed, like [`REVOKED_TOKEN_STORAGE_PREFIX`], by the SHA-256 hash of the token, so no
/// token material is written. It is a distinct path from the revocation entry because the
/// two states are different: a reservation can still be released, a revocation cannot.
const REFRESH_RESERVATION_STORAGE_PREFIX: &str = "sys/auth/refresh-reservations/";

/// How long the initial single-use claim over a refresh token lasts.
///
/// The claim is taken before the exchange's fallible work and — on a successful exchange —
/// extended to the token's own `exp` once, and only once, a new session is durable. If the
/// exchange dies between the claim and the extension, the claim lapses after this window
/// instead of occupying the slot for the token's whole (potentially multi-day) lifetime, so
/// a later retry is not refused by an orphaned claim. It is deliberately short: the window
/// only has to cover a single exchange's work, and a longer one re-creates the lockout the
/// short TTL exists to avoid.
const REFRESH_CLAIM_TTL_SECS: i64 = 120;

/// How long a bootstrap credential stays valid: the token an unseal hands back, and the
/// session record behind it.
///
/// Fixed rather than taken from the interactive session policy, because the two are not
/// the same credential. `system/config` can raise an ordinary session timeout to 24 hours,
/// which is a defensible choice for a human at a keyboard; the root token returned by an
/// unseal is the most privileged credential in the system and should not inherit it by
/// accident. One hour matches the compiled-in default for `auth.jwt.expiration`.
pub const BOOTSTRAP_TOKEN_TTL_SECS: u64 = 3600;

#[derive(Debug, Deserialize)]
pub struct ApiLoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

/// JWT Claims structure
///
/// NOTE: The `email` field is `Option<String>` to match the canonical
/// `secreton_auth::jwt::Claims` struct.  Tokens created with
/// `email: None` serialize as `"email": null`; using a bare `String`
/// here would cause deserialization to fail for those tokens.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Email
    pub email: Option<String>,
    /// Roles
    pub roles: Vec<String>,
    /// Associated policies
    #[serde(default)]
    pub policies: Vec<String>,
    /// MFA required flag
    #[serde(default)]
    pub mfa_required: bool,
    /// Issued at
    pub iat: usize,
    /// Expiration time
    pub exp: usize,
    /// JWT ID
    pub jti: String,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
}

/// Authentication service errors
#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("User not found")]
    UserNotFound,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("MFA not configured for user '{0}'; please enroll in MFA before logging in")]
    MfaNotConfigured(String),

    #[error("Permission denied")]
    PermissionDenied,

    #[error("Storage error: {0}")]
    Storage(#[from] secreton_storage::StorageError),

    #[error("Crypto error: {0}")]
    Crypto(#[from] secreton_crypto::CryptoError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

// User is now imported from secreton_core::models

/// Role definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token: String,
    pub refresh_token: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed: chrono::DateTime<chrono::Utc>,
}

/// Authentication token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub user: User,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiLoginResponse {
    pub token: AuthToken,
}

/// Cached effective configuration (session timeout + global MFA flag).
///
/// Avoids a storage round-trip on every authentication call by caching
/// the result of `get_effective_config()` with a short TTL.
struct CachedEffectiveConfig {
    session_timeout: u64,
    mfa_enabled: bool,
    fetched_at: std::time::Instant,
}

/// Authentication service facade
pub struct AuthenticationService {
    /// Unified authentication service
    auth_service: Arc<UnifiedAuthService>,

    /// UserPass method (kept for direct user management)
    userpass_method: Arc<UserPassAuthMethod>,

    /// Token service for JWT operations
    token_service: JwtTokenService,

    /// Storage backend for sessions
    storage: Arc<dyn StorageBackend + Send + Sync>,

    /// Configuration
    config: AuthConfig,

    /// Token blacklist
    token_blacklist: Arc<tokio::sync::RwLock<HashMap<String, chrono::DateTime<chrono::Utc>>>>,

    /// Crypto service
    crypto: Arc<CryptoService>,

    /// Audit logger
    audit: Option<Arc<crate::services::audit::AuditLogger>>,

    /// MFA service
    mfa_service: Option<Arc<secreton_auth::mfa::CombinedMfaService>>,

    /// Cached effective config to avoid per-request storage reads.
    /// Protected by an RwLock so concurrent auth calls can share the
    /// cached value; only one caller refreshes when the TTL expires.
    effective_config_cache: Arc<tokio::sync::RwLock<Option<CachedEffectiveConfig>>>,

    /// Test-only override for [`REFRESH_CLAIM_TTL_SECS`], so a test can drive the claim past
    /// its deadline without sleeping for the production two minutes.
    #[cfg(test)]
    refresh_claim_ttl_override: std::sync::atomic::AtomicI64,
}

/// TTL for the effective-config cache.  30 seconds is short enough that
/// admin config changes propagate quickly, but long enough to avoid a
/// storage round-trip on every authentication call in high-throughput
/// deployments.
const EFFECTIVE_CONFIG_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

impl AuthenticationService {
    /// Get current security config from storage, merging with defaults.
    ///
    /// Results are cached for [`EFFECTIVE_CONFIG_CACHE_TTL`] to avoid a
    /// storage round-trip on every call to `login()`, `authenticate()`,
    /// `refresh_token()`, and `generate_token()`.
    async fn get_effective_config(&self) -> (u64, bool) {
        // Fast path: return cached value if still fresh.
        {
            let cache = self.effective_config_cache.read().await;
            if let Some(ref cached) = *cache
                && cached.fetched_at.elapsed() < EFFECTIVE_CONFIG_CACHE_TTL
            {
                return (cached.session_timeout, cached.mfa_enabled);
            }
        }

        // Slow path: read from storage and update the cache.
        let (session_timeout, mfa_enabled) = self.fetch_effective_config_from_storage().await;

        {
            let mut cache = self.effective_config_cache.write().await;
            *cache = Some(CachedEffectiveConfig {
                session_timeout,
                mfa_enabled,
                fetched_at: std::time::Instant::now(),
            });
        }

        (session_timeout, mfa_enabled)
    }

    /// Read `system/config` from storage and merge with static defaults.
    ///
    /// This is the uncached inner implementation of [`get_effective_config`].
    async fn fetch_effective_config_from_storage(&self) -> (u64, bool) {
        let config_path = "system/config";
        let mut session_timeout = self.config.jwt.expiration;
        let mut mfa_enabled = self.config.mfa.enabled;

        match self.storage.get_by_path(config_path).await {
            Ok(Some(entry)) => {
                if let Some(config_data) = entry.metadata.get("config_data") {
                    match serde_json::from_str::<serde_json::Value>(config_data) {
                        Ok(config) => {
                            if let Some(timeout) =
                                config.get("session_timeout").and_then(|v| v.as_u64())
                            {
                                // Apply the same validation range (60-86400 seconds)
                                // that the admin service enforces during updates.
                                if (60..=86400).contains(&timeout) {
                                    session_timeout = timeout;
                                } else {
                                    tracing::warn!(
                                        "Dynamic session_timeout {} is outside valid range \
                                         (60-86400); using static default {}",
                                        timeout,
                                        self.config.jwt.expiration,
                                    );
                                }
                            }
                            if let Some(mfa) = config.get("enable_mfa").and_then(|v| v.as_bool()) {
                                mfa_enabled = mfa;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse system/config config_data as JSON: {}; \
                                 using static defaults",
                                e,
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                // No dynamic config stored yet — use static defaults (not an error)
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to read system/config from storage: {}; \
                     using static defaults",
                    e,
                );
            }
        }

        (session_timeout, mfa_enabled)
    }

    /// Get current password policy from storage, merging with defaults
    pub async fn get_password_policy(&self) -> secreton_domain::password::PasswordPolicy {
        let config_path = "system/config";

        // Defaults
        let mut policy = secreton_domain::password::PasswordPolicy {
            min_length: 8,
            max_length: None,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            allowed_special_chars: None,
        };

        match self.storage.get_by_path(config_path).await {
            Ok(Some(entry)) => {
                if let Some(config_data) = entry.metadata.get("config_data") {
                    match serde_json::from_str::<serde_json::Value>(config_data) {
                        Ok(config) => {
                            if let Some(v) = config
                                .get("password_policy_min_length")
                                .and_then(|v| v.as_u64())
                            {
                                // Clamp to usize::MAX to avoid silent truncation on 32-bit platforms.
                                policy.min_length = usize::try_from(v).unwrap_or(usize::MAX);
                            }
                            if let Some(v) = config
                                .get("password_policy_require_uppercase")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_uppercase = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_lowercase")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_lowercase = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_numbers")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_digit = v;
                            }
                            if let Some(v) = config
                                .get("password_policy_require_special")
                                .and_then(|v| v.as_bool())
                            {
                                policy.require_special = v;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to parse system/config config_data for password policy: {}; \
                                 using defaults",
                                e,
                            );
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Failed to read system/config for password policy: {}; using defaults",
                    e,
                );
            }
        }

        policy
    }

    /// Create new authentication service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        config: &AuthConfig,
    ) -> Result<Self> {
        // Startup validation already requires this, but propagating beats panicking: a
        // config path that reaches here without a secret should report which setting is
        // missing, not abort.
        let jwt_secret = config.jwt.secret.clone().ok_or_else(|| {
            anyhow!("auth.jwt.secret is not configured; set SECRETON__AUTH__JWT__SECRET")
        })?;

        // Create token service
        let token_config = TokenConfig {
            jwt_secret: jwt_secret.clone(),
            // Access and refresh tokens are signed with the same key. See
            // `validate_refresh_token` — it distinguishes the two by claim shape, not by
            // key, so this is not a separation boundary.
            jwt_refresh_secret: jwt_secret,
            access_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(
                config.jwt.expiration,
            ))
            .unwrap_or(chrono::Duration::hours(1)),
            refresh_token_duration: chrono::Duration::from_std(std::time::Duration::from_secs(
                config.jwt.refresh_expiration,
            ))
            .unwrap_or(chrono::Duration::days(7)),
            issuer: config.jwt.issuer.clone(),
            audience: config.jwt.audience.clone(),
        };
        let token_service = JwtTokenService::new(token_config);

        // Create unified auth service
        let auth_service = Arc::new(UnifiedAuthService::new());

        // Register default authentication methods
        let mut userpass_method_impl = UserPassAuthMethod::new();
        // Initialize/Enable the method
        // Manually enable as we are skipping the full init flow for built-in method
        use secreton_auth::service::AuthMethodImpl;
        let _ = userpass_method_impl
            .init(&secreton_auth::model::AuthMethod {
                method_type: secreton_auth::model::AuthMethodType::UserPass,
                enabled: true,
                config: HashMap::new(),
            })
            .await;

        let userpass_method = Arc::new(userpass_method_impl);
        auth_service
            .register_method("userpass".to_string(), userpass_method.clone())
            .await;

        // Load existing users from storage.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded to 100 users; without an explicit
        // limit it would now load every user row into memory (and decrypt
        // each one) on every service construction. 50k is generous enough
        // for typical deployments while still bounding worst-case startup
        // memory.
        //
        // TODO: Move user-cache hydration off the startup path entirely so
        // that `UserPassAuthMethod` lazy-loads users on first authentication
        // instead of bulk-loading them up front.
        const USER_LOAD_MAX_ENTRIES: u32 = 50_000;
        let params = QueryParams::new()
            .with_path_prefix(USER_STORAGE_PREFIX.to_string())
            .with_limit(USER_LOAD_MAX_ENTRIES);
        if let Ok(entries) = storage.list(&params).await {
            for entry in entries {
                // Try decrypting the data, strictly requiring encryption
                let user_data = match crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => decrypted,
                    Err(_) => {
                        // Skip users with invalid encryption (removes plaintext fallback weakness)
                        continue;
                    }
                };

                if let Ok(user) = serde_json::from_slice::<User>(&user_data) {
                    userpass_method
                        .add_user(
                            user.username.clone(),
                            user.password_hash.clone(),
                            user.id.clone(),
                            user.roles.clone(),
                            user.policies.clone(),
                            user.permissions.clone(),
                            user.password_login_disabled,
                        )
                        .await;
                }
            }
        }

        Ok(Self {
            auth_service,
            userpass_method,
            token_service,
            storage,
            config: config.clone(),
            token_blacklist: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            audit: None,
            mfa_service: None,
            crypto,
            effective_config_cache: Arc::new(tokio::sync::RwLock::new(None)),
            #[cfg(test)]
            refresh_claim_ttl_override: std::sync::atomic::AtomicI64::new(REFRESH_CLAIM_TTL_SECS),
        })
    }

    pub fn with_audit(mut self, audit: Arc<crate::services::audit::AuditLogger>) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn with_mfa(mut self, mfa: Arc<secreton_auth::mfa::CombinedMfaService>) -> Self {
        self.mfa_service = Some(mfa);
        self
    }

    /// Enforce MFA for the given user, returning `Ok(mfa_verified)` if the
    /// user is allowed to proceed.
    ///
    /// The boolean indicates whether MFA was actually verified:
    /// - `true`  — MFA code was validated successfully.
    /// - `false` — MFA was not required (non-privileged + global MFA off), or TOFU
    ///   applies (privileged user without MFA configured).
    ///
    /// Callers should set `mfa_required: true` on issued tokens when the
    /// return value is `false` and the user is privileged (TOFU), so that
    /// downstream authorization middleware can restrict scope until MFA
    /// enrollment is completed.
    ///
    /// This is the single source of truth for MFA enforcement so that
    /// `login()` and `authenticate()` stay in sync.
    /// Create and store a new session, returning the session ID and expiry.
    ///
    /// This helper encapsulates the session object creation, serialization,
    /// encryption, and storage, ensuring consistent metadata handling across
    /// all authentication flows.
    #[allow(
        clippy::too_many_arguments,
        reason = "a session record's fields, passed individually because the caller \
                  assembles them from three different sources"
    )]
    async fn create_and_store_session(
        &self,
        user_id: &str,
        session_id: String,
        access_token: String,
        refresh_token: Option<String>,
        ip_address: String,
        user_agent: String,
        duration_secs: u64,
    ) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
        let now = chrono::Utc::now();
        let expires_at = now
            + chrono::Duration::from_std(std::time::Duration::from_secs(duration_secs))
                .unwrap_or(chrono::Duration::hours(1));

        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            token: access_token,
            refresh_token,
            ip_address,
            user_agent,
            created_at: now,
            expires_at,
            last_accessed: now,
        };

        let session_json = serde_json::to_vec(&session).map_err(|e| {
            AuthError::Internal(anyhow::anyhow!("Failed to serialize session: {}", e))
        })?;

        let session_data = self.crypto.encrypt_data(&session_json).await.map_err(|e| {
            AuthError::Internal(anyhow::anyhow!("Failed to encrypt session: {}", e))
        })?;

        let entry = SecretEntry::new(
            format!("{}{}", SESSION_STORAGE_PREFIX, session_id),
            session_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(user_id).unwrap_or_default(),
        )
        .with_expiration(expires_at);

        self.storage
            .store(&entry)
            .await
            .map_err(AuthError::Storage)?;

        Ok(expires_at)
    }

    async fn enforce_mfa(
        &self,
        username: &str,
        user_id: &str,
        is_privileged: bool,
        global_mfa_enabled: bool,
        mfa_code: Option<String>,
    ) -> Result<bool, AuthError> {
        if !(is_privileged || global_mfa_enabled) {
            return Ok(false);
        }

        let mut mfa_verified = false;

        if let Some(mfa) = &self.mfa_service {
            let user_uuid = Uuid::parse_str(user_id).map_err(|_| {
                tracing::error!(
                    "enforce_mfa: failed to parse user_id '{}' as UUID for user '{}'; \
                     denying access to prevent nil-UUID TOFU bypass",
                    user_id,
                    username
                );
                AuthError::Internal(anyhow::anyhow!(
                    "Cannot enforce MFA: invalid user ID format"
                ))
            })?;
            let mfa_configured = match mfa.is_mfa_required(user_uuid).await {
                Ok(configured) => configured,
                Err(e) => {
                    // Fail-safe: treat MFA service errors as "MFA is required"
                    // rather than silently bypassing.  A transient MFA service
                    // failure should not allow a privileged user through without
                    // MFA when they have already configured it.
                    tracing::warn!(
                        "MFA service error for user '{}': {}; \
                         treating as MFA-required (fail-safe)",
                        username,
                        e
                    );
                    true
                }
            };

            if mfa_configured {
                let code = mfa_code.ok_or_else(|| AuthError::MfaRequired)?;

                use secreton_auth::mfa::{MfaMethod, MfaValidationRequest};
                let validation_request = MfaValidationRequest {
                    entity_id: user_uuid,
                    method: MfaMethod::Totp,
                    code: Some(code),
                    hardware_request: None,
                    push_notification_id: None,
                    push_response: None,
                    webauthn_response: None,
                };

                if !mfa.validate(validation_request).await.unwrap_or(false) {
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: username.to_string(),
                                    method: "totp".to_string(),
                                    reason: "Invalid MFA code".to_string(),
                                },
                            )
                            .await;
                    }
                    return Err(AuthError::InvalidMfaCode);
                }
                mfa_verified = true;
            } else {
                // TOFU (Trust On First Use) — the user has not yet
                // configured MFA, but MFA is required (either because the
                // user is privileged or because global MFA is enabled).
                //
                // Rather than hard-denying the login — which would lock
                // out every non-privileged user the moment an admin flips
                // on global MFA, since there is no self-service enrollment
                // path without an authenticated session — we issue a
                // restricted-scope token.  The callers (`login()` and
                // `authenticate()`) set `mfa_required: true` on the issued
                // token when TOFU applies (`!mfa_verified` and MFA was
                // required), and the `enforce_mfa_pending` middleware
                // restricts the token's scope to MFA-enrollment and
                // logout endpoints only.  The user must complete MFA
                // enrollment before the token grants access to anything
                // else.
                let reason = if is_privileged {
                    "privileged user authenticated without MFA"
                } else {
                    "global MFA enabled but user has not enrolled; \
                     granting restricted token for enrollment"
                };
                tracing::warn!(
                    "TOFU: user '{}' — {}; MFA enrollment should be completed immediately",
                    username,
                    reason
                );
                if let Some(audit) = &self.audit {
                    let _ = audit
                        .log_event(
                            crate::services::audit::SecurityEventType::AuthenticationSuccess {
                                user: username.to_string(),
                                method: "password_no_mfa_setup".to_string(),
                            },
                        )
                        .await;
                }
            }
        } else if is_privileged {
            return Err(AuthError::Internal(anyhow::anyhow!(
                "MFA service not configured but required for privileged access"
            )));
        } else {
            // Global MFA is enabled but the MFA service is not registered.
            // Fail-safe: deny login rather than silently bypassing the
            // admin's explicit MFA enforcement.
            tracing::error!(
                "Global MFA enabled but MFA service not configured; \
                 denying login for user '{}'",
                username
            );
            return Err(AuthError::Internal(anyhow::anyhow!(
                "MFA service not configured but global MFA is enabled; \
                 please contact your administrator"
            )));
        }

        Ok(mfa_verified)
    }

    /// Authenticate user with username and password
    pub async fn login(
        &self,
        req: ApiLoginRequest,
        ip_address: String,
        user_agent: String,
    ) -> secreton_domain::Result<ApiLoginResponse> {
        // Get effective config for session timeout and MFA enforcement
        let (session_timeout_secs, global_mfa_enabled) = self.get_effective_config().await;

        // The bootstrap root identity is barred from password login because the account is
        // persisted as non-password-authenticatable, not because of how it is named.
        //
        // A literal `req.username == "root"` check used to stand here. It was the entire
        // guard, and it stopped covering the account the moment `init` accepted a custom
        // `root_username`: a root account created as, say, `vault-operator` walked straight
        // through with its generated password hash. It also denied an ordinary admin who
        // merely chose the name "root". The check below reads the account's own record, so
        // it covers the identity `init` created under any name and leaves an ordinary
        // account of the same name alone.
        if let Ok(Some(user)) = self.find_user_by_username(&req.username).await
            && user.password_login_disabled
        {
            if let Some(audit) = &self.audit {
                let _ = audit
                    .log_event(
                        crate::services::audit::SecurityEventType::AuthenticationFailure {
                            user: req.username.clone(),
                            method: "userpass".to_string(),
                            reason: "Account is not password-authenticatable".to_string(),
                        },
                    )
                    .await;
            }
            // Generic, identical to a wrong password: the refusal must not become a
            // username oracle that reveals which account is the bootstrap root.
            return Err(secreton_domain::SecretonError::Authentication {
                message: "Invalid credentials".to_string(),
            });
        }

        // Check lockout status before attempting login.
        // Propagate storage errors so that a transient failure does not
        // silently skip the lockout check (which would allow a locked-out
        // user to authenticate).  This mirrors the fail-closed approach
        // used in `authenticate()`.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, req.username);
        let user_entry = match self.storage.get_by_path(&user_path).await {
            Ok(entry) => entry,
            Err(e) => {
                tracing::warn!(
                    "Failed to load user '{}' from storage during login: {}",
                    req.username,
                    e
                );
                return Err(secreton_domain::SecretonError::Internal {
                    message: "An internal error occurred during authentication".to_string(),
                });
            }
        };
        let mut stored_user: Option<User> = None;

        if let Some(ref entry) = user_entry {
            // Decrypt and deserialize user
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await
                && let Ok(u) = serde_json::from_slice::<User>(&decrypted)
            {
                stored_user = Some(u.clone());
                // Republish the durable record so an account omitted by the capped startup
                // hydration can still be verified by `UserPassAuthMethod`.
                self.hydrate_userpass_identity(&u).await;
                if let Some(locked_until) = u.locked_until
                    && locked_until > chrono::Utc::now()
                {
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked".to_string(),
                                },
                            )
                            .await;
                    }
                    return Err(secreton_domain::SecretonError::Authentication {
                        message: "Account is locked. Please try again later.".to_string(),
                    });
                }

                // Also check disabled/inactive status — mirrors authenticate()
                if u.disabled || !u.enabled || !u.is_active {
                    return Err(secreton_domain::SecretonError::Authentication {
                        message: "Invalid credentials".to_string(),
                    });
                }
            }
        }

        // Create login request.
        // Do NOT pass mfa_code to auth_service.login() — MFA is validated
        // explicitly below via `enforce_mfa()`.  Passing it here could cause
        // double-validation issues if the underlying auth service ever starts
        // consuming TOTP codes (which are single-use).  This mirrors the same
        // pattern used in `authenticate()`.
        let request = LoginRequest {
            username: req.username.clone(),
            password: req.password.clone(),
            mfa_code: None,
            remember_me: Some(false),
        };

        // Authenticate using unified auth service
        let response = self.auth_service.login(&request).await.map_err(|e| {
            secreton_domain::SecretonError::Authentication {
                message: e.to_string(),
            }
        })?;

        if !response.success {
            // Handle failed login attempt
            if let Some(mut u) = stored_user {
                u.failed_login_attempts += 1;

                // Max attempts check (e.g. 5), but exempt privileged users from auto-lockout (DoS protection)
                if !u.is_privileged() && u.failed_login_attempts >= 5 {
                    u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                    // Log lockout
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Encrypt and update user in storage
                if let Ok(user_data) = serde_json::to_vec(&u)
                    && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
                    && let Some(mut entry) = user_entry
                {
                    entry.encrypted_data = encrypted;
                    let _ = self.storage.store(&entry).await;
                }
            }

            return Err(secreton_domain::SecretonError::Authentication {
                message: "Invalid credentials".to_string(),
            });
        }

        let user_info =
            response
                .user_info
                .ok_or_else(|| secreton_domain::SecretonError::Internal {
                    message: "No user info returned".to_string(),
                })?;

        // Convert UserInfo to User (simplified)
        let mut user = if let Some(u) = stored_user {
            u
        } else {
            User {
                id: user_info.id.clone().unwrap_or_default(),
                username: user_info.username.clone(),
                email: user_info.email,
                display_name: user_info.display_name.clone(),
                full_name: user_info.display_name,
                password_hash: "".to_string(), // Not used in API responses
                password_login_disabled: false,
                is_active: true,
                is_superuser: false,
                disabled: false,
                roles: user_info.roles.clone(),
                permissions: vec![],
                policies: vec!["default".to_string()], // Default policies as UserInfo lacks them
                enabled: true,
                mfa_enabled: false,
                mfa_secret: None,
                last_login: None,               // UserInfo lacks last_login
                created_at: chrono::Utc::now(), // UserInfo lacks created_at
                updated_at: chrono::Utc::now(),
                metadata: user_info.metadata.clone(),
                failed_login_attempts: 0,
                locked_until: None,
            }
        };

        // Enforce MFA for privileged users (admin/root) or if globally enabled.
        // Delegates to the shared `enforce_mfa()` helper so that `login()` and
        // `authenticate()` use identical enforcement logic.
        let is_privileged =
            user.roles.contains(&"admin".to_string()) || user.roles.contains(&"root".to_string());

        // Guard against empty user IDs for privileged users — mirrors the
        // check in `authenticate()` at lines 1624-1632.  An empty user ID
        // would cause `Uuid::parse_str("").unwrap_or_default()` inside
        // `enforce_mfa()` to yield `Uuid::nil()`, making
        // `is_mfa_required(nil_uuid)` return `false` and triggering the
        // TOFU path — silently bypassing MFA for the privileged user.
        if user.id.is_empty() && is_privileged {
            return Err(secreton_domain::SecretonError::Internal {
                message: "Cannot enforce MFA: no valid user ID available for privileged user"
                    .to_string(),
            });
        }

        let mfa_verified = match self
            .enforce_mfa(
                &req.username,
                &user.id,
                is_privileged,
                global_mfa_enabled,
                req.mfa_code.clone(),
            )
            .await
        {
            Ok(verified) => verified,
            Err(mfa_err) => {
                // Increment failed_login_attempts on MFA failure so that the
                // lockout mechanism also covers MFA brute-force attempts.
                // Without this, an attacker who knows the password could try
                // unlimited MFA codes without ever triggering account lockout.
                //
                // Only count `InvalidMfaCode` — an actual wrong code — toward
                // lockout.  `MfaRequired` (first step of a two-step login) and
                // `MfaNotConfigured` (user hasn't enrolled yet) are NOT attack
                // indicators and should not accumulate lockout attempts:
                //   - MfaRequired fires on every first-step login attempt in a
                //     two-step flow; counting it would lock out legitimate users
                //     after a few page refreshes.
                //   - MfaNotConfigured fires every time a user who hasn't
                //     enrolled tries to log in; counting it would permanently
                //     lock them out before they can ever enroll.
                if matches!(mfa_err, AuthError::InvalidMfaCode) {
                    user.failed_login_attempts += 1;

                    if !user.is_privileged() && user.failed_login_attempts >= 5 {
                        user.locked_until =
                            Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                        if let Some(audit) = &self.audit {
                            let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: req.username.clone(),
                                    method: "mfa".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                        }
                    }

                    // Persist the updated counter
                    if let Ok(user_data) = serde_json::to_vec(&user)
                        && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
                        && let Some(mut entry) = user_entry
                    {
                        entry.encrypted_data = encrypted;
                        let _ = self.storage.store(&entry).await;
                    }
                }

                return Err(match mfa_err {
                    AuthError::MfaRequired => secreton_domain::SecretonError::MfaRequired,
                    AuthError::MfaNotConfigured(ref user) => {
                        secreton_domain::SecretonError::MfaNotConfigured { user: user.clone() }
                    }
                    AuthError::InvalidMfaCode => secreton_domain::SecretonError::Authentication {
                        message: "Authentication failed".to_string(),
                    },
                    AuthError::Internal(ref inner) => {
                        secreton_domain::SecretonError::Configuration {
                            message: inner.to_string(),
                        }
                    }
                    other => secreton_domain::SecretonError::Authentication {
                        message: other.to_string(),
                    },
                });
            }
        };

        // Reset failed login attempts on success
        // Also ensure user is persisted if it didn't exist (new user)
        let should_persist =
            user_entry.is_none() || user.failed_login_attempts > 0 || user.locked_until.is_some();

        if user.failed_login_attempts > 0 || user.locked_until.is_some() {
            user.failed_login_attempts = 0;
            user.locked_until = None;
        }

        if should_persist {
            // Update user in storage
            if let Ok(user_data) = serde_json::to_vec(&user)
                && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
            {
                let entry = if let Some(mut e) = user_entry {
                    e.encrypted_data = encrypted;
                    e
                } else {
                    SecretEntry::new(
                        user_path,
                        encrypted,
                        EncryptionMetadata::default(),
                        SecurityLevel::Secret,
                        Uuid::parse_str(&user.id).unwrap_or_default(),
                    )
                };
                let _ = self.storage.store(&entry).await;
            }
        }

        // Create token pair with session binding, using the dynamic timeout so
        // that the JWT `exp` claim stays in sync with the session `expires_at`.
        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Set mfa_required on the token when TOFU was used (user
        // authenticated without MFA but MFA was required — either because
        // they are privileged or because global MFA is enabled).  This
        // allows downstream authorization middleware (`enforce_mfa_pending`)
        // to restrict token scope to MFA-enrollment endpoints until the
        // user completes enrollment.
        let token_mfa_required = (is_privileged || global_mfa_enabled) && !mfa_verified;

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                &user.id,
                &user.username,
                user.email.as_deref(), // Convert Option<&String> to Option<&str>
                &user.roles,
                &user.policies, // Use user.policies which we just created
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|e| secreton_domain::SecretonError::Authentication {
                message: e.to_string(),
            })?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &user.id,
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await
            .map_err(|e| match e {
                AuthError::MfaRequired => secreton_domain::SecretonError::MfaRequired,
                AuthError::MfaNotConfigured(u) => {
                    secreton_domain::SecretonError::MfaNotConfigured { user: u }
                }
                AuthError::InvalidMfaCode => secreton_domain::SecretonError::Authentication {
                    message: "Authentication failed".to_string(),
                },
                _ => secreton_domain::SecretonError::Authentication {
                    message: "Authentication failed".to_string(),
                },
            })?;

        Ok(ApiLoginResponse {
            token: AuthToken {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: token_pair.token_type,
                expires_in: token_pair.expires_in,
                user,
            },
        })
    }

    /// Validate access token.
    ///
    /// # Contract: MFA-pending metadata propagation
    ///
    /// When the JWT carries `mfa_required: true` (a TOFU token issued to a
    /// user who has not yet completed MFA enrollment), this method **must**
    /// insert `metadata["mfa_pending"] = "true"` on the returned `User`.
    ///
    /// Downstream authorization layers rely on this contract:
    ///   - `crate::middleware::enforce_mfa_pending` (`crates/api/src/middleware.rs`)
    ///     reads `metadata["mfa_pending"]` to restrict the token's scope to
    ///     MFA-enrollment endpoints.
    ///   - The refresh handler (`crates/api/src/handlers/auth.rs`) propagates
    ///     the flag onto refreshed tokens so TOFU users cannot escape the
    ///     restriction by refreshing.
    ///
    /// Removing or changing this propagation silently disables the entire
    /// TOFU MFA enforcement chain — any change here must be accompanied by
    /// matching changes in both call sites above.
    pub async fn validate_token(&self, token: &str) -> Result<User, AuthError> {
        // Check blacklist
        if self.is_token_revoked(token).await {
            return Err(AuthError::InvalidToken);
        }

        let claims = self
            .token_service
            .validate_access_token(token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Verify session binding (Security hardening)
        // Ensure the session associated with this token still exists and is valid
        let session_path = format!("{}{}", SESSION_STORAGE_PREFIX, claims.claims.jti);
        if !self.storage.exists(&session_path).await.unwrap_or(false) {
            return Err(AuthError::InvalidToken);
        }

        // Track TOFU MFA enrollment status on the returned User via
        // metadata so that callers (middleware, handlers) can enforce
        // restricted scope for privileged users who have not yet
        // completed MFA enrollment.
        //
        // We do NOT reject TOFU tokens here because doing so creates a
        // deadlock: the user needs an authenticated session to reach the
        // `/mfa/setup` endpoint, but `validate_token` is called by both
        // the global `auth_middleware` and the `AuthenticatedUser`
        // extractor.  Blanket rejection would lock the user out of every
        // endpoint — including the one they need to complete enrollment.
        //
        // Instead, the `mfa_pending` metadata flag is set so that
        // authorization layers can selectively deny access to sensitive
        // operations while still allowing MFA enrollment endpoints.
        let mfa_pending = claims.claims.mfa_required;

        // Convert claims to User — use the roles AND policies embedded in the
        // JWT so that authorization checks after token validation see the same
        // claims the token was issued with.  Previously `policies` was hardcoded
        // to `["default"]`, which stripped any non-default policies the user had
        // at login time.
        let mut metadata = HashMap::new();
        if mfa_pending {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }

        Ok(User {
            id: claims.claims.sub,
            username: claims.claims.username.clone(),
            email: claims.claims.email.clone(),
            password_hash: "".to_string(),
            password_login_disabled: false,
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: claims.claims.roles.clone(),
            permissions: vec![],
            policies: claims.claims.policies.clone(),
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
            failed_login_attempts: 0,
            locked_until: None,
        })
    }

    /// Compute the storage path for a revoked-token entry.
    ///
    /// Uses SHA-256 so the raw token material is never written to storage —
    /// we only persist a hash that's sufficient to detect replay of the same
    /// token.
    fn revoked_token_path(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        format!("{}{}", REVOKED_TOKEN_STORAGE_PREFIX, hex::encode(digest))
    }

    /// Revoke a token.
    ///
    /// Writes the revocation to both the in-memory blacklist (fast path for
    /// the local instance) and the shared storage backend (so other
    /// instances see the revocation).  Storage failures are logged but do
    /// not fail the call — the in-memory entry still prevents replay on
    /// this instance, and the session-binding check in `validate_token`
    /// provides additional defense when sessions are deleted.
    pub async fn revoke_token(&self, token: String, expires_at: chrono::DateTime<chrono::Utc>) {
        // In-memory update (fast path).
        {
            let mut blacklist = self.token_blacklist.write().await;
            // Clean up expired entries while we're at it
            blacklist.retain(|_, &mut exp| exp > chrono::Utc::now());
            blacklist.insert(token.clone(), expires_at);
        }

        // Persist the revocation so other instances see it.  We store an
        // empty encrypted payload — the presence of the entry at the
        // hash-keyed path is what signals revocation, and `expires_at`
        // drives automatic cleanup via `delete_expired`.
        let path = Self::revoked_token_path(&token);
        let entry = SecretEntry::new(
            path,
            Vec::new(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .with_expiration(expires_at);

        if let Err(e) = self.storage.store(&entry).await {
            tracing::warn!(
                "Failed to persist revoked token to storage: {}; \
                 revocation is still active on this instance but may not \
                 propagate to other instances",
                e
            );
        }
    }

    /// Check if a token is revoked.
    ///
    /// Checks the in-memory blacklist first (fast path), then falls back to
    /// the shared storage backend so revocations made on other instances
    /// are honored.  A storage lookup failure is treated as "not revoked"
    /// (fail-open) so that a transient storage hiccup does not lock out
    /// every user — the session-binding check in `validate_token` remains
    /// the authoritative defense.
    pub async fn is_token_revoked(&self, token: &str) -> bool {
        // In-memory fast path.
        {
            let blacklist = self.token_blacklist.read().await;
            if let Some(expires_at) = blacklist.get(token)
                && *expires_at > chrono::Utc::now()
            {
                return true;
            }
        }

        // Shared-storage fallback: check whether another instance has
        // persisted a revocation for this token.
        let path = Self::revoked_token_path(token);
        match self.storage.get_by_path(&path).await {
            Ok(Some(entry)) => {
                // If the entry exists and has not yet expired, the token is
                // revoked.  Populate the in-memory cache so subsequent
                // checks hit the fast path.
                let still_valid = entry
                    .expires_at
                    .map(|exp| exp > chrono::Utc::now())
                    .unwrap_or(true);
                if still_valid {
                    if let Some(exp) = entry.expires_at {
                        let mut blacklist = self.token_blacklist.write().await;
                        blacklist.insert(token.to_string(), exp);
                    }
                    return true;
                }
                false
            }
            Ok(None) => false,
            Err(e) => {
                tracing::warn!(
                    "Failed to check persisted revoked-token store: {}; \
                     falling back to in-memory check only",
                    e
                );
                false
            }
        }
    }

    /// Refresh access token
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthToken, AuthError> {
        // Fast-path early reject for a previously-exchanged refresh token.
        // This is purely an optimisation — the authoritative single-use
        // check is the atomic check-and-insert on the in-memory blacklist
        // below, which closes the TOCTOU window between this check and the
        // eventual `revoke_token` call.
        if self.is_token_revoked(refresh_token).await {
            return Err(AuthError::InvalidToken);
        }

        // Validate first to get user info for session creation.  Validation
        // is side-effect-free so performing it before the CAS is safe —
        // two concurrent requests will both validate, but only one will win
        // the atomic insert below.
        let claims = self
            .token_service
            .validate_refresh_token(refresh_token)
            .map_err(|_| AuthError::InvalidToken)?;

        // Reserve the single-use slot atomically, before the fallible work below.
        //
        // This is the authority for reuse detection. The in-memory check-and-insert was
        // sufficient for one process, but two replicas sharing a backend each have their own
        // map: both pass the fast-path check and both believe they won, so the same refresh
        // token was exchanged twice and two token pairs were issued. The reservation is
        // therefore taken in the *shared* backend first, as an insert-if-absent write at a
        // path derived from the token's hash, and only a caller that actually created the
        // record may proceed. The in-memory map is kept as a fast path for this process.
        //
        // A reservation is not a revocation: it is released if the exchange ends without a
        // new session (see `release_refresh_token_reservation`), and only a completed
        // exchange commits the permanent revocation. Writing the revocation here instead, as
        // this used to, meant a later failure (a storage hiccup loading the user, an MFA
        // service error, a failed session write) returned an error while the old token was
        // already blacklisted: the caller held no new token and could never retry with the
        // old one, so a transient fault permanently logged them out.
        // The reservation and the later revocation must outlive the token they guard for the
        // token's whole life. A fixed eight-day window did not: when an operator configured
        // `auth.jwt.refresh_expiration` longer than eight days, an exchanged token outlived
        // both records, and once they expired a replay won the insert-if-absent race and was
        // issued a fresh session — a reuse window that grew with the configured lifetime.
        // Deriving the deadline from the token's own `exp` makes the guard last exactly as
        // long as the token; `validate_refresh_token` already rejects the token past that
        // point, so this can never under-reserve. The fallback is effectively unreachable
        // (validation proved `exp` a live timestamp), but it is kept so a malformed value
        // cannot shorten the guard.
        let refresh_expiry = i64::try_from(claims.exp)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            .filter(|exp| *exp > chrono::Utc::now())
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(8));
        let Some(reservation_owner) = self
            .reserve_refresh_token(refresh_token, refresh_expiry)
            .await?
        else {
            // Another caller — in this process or another replica sharing the backend —
            // holds the single-use slot, so this must not exchange the token again.
            return Err(AuthError::InvalidToken);
        };

        // Everything from here can fail for a non-security reason: reading the user,
        // verifying MFA, minting the pair, persisting the new session. The reservation above
        // must be released if the caller ends up with no new token, or a transient fault
        // consumes the refresh token and logs them out permanently. The `Err` arm below is
        // the only place that releases it; a security denial returns from inside without a
        // reservation leak because those paths deliberately keep the token revoked.
        let rotation: Result<AuthToken, AuthError> = async {
        // Get effective config for session timeout
        let (session_timeout_secs, _) = self.get_effective_config().await;

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Load user from storage to get current roles/policies instead of
        // using empty slices which would strip all authorization claims.
        // A storage or decryption failure here is treated as an error rather
        // than silently downgrading the token to empty roles — a transient
        // storage hiccup should not strip a user's authorization.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, claims.username);
        let user_entry = self
            .storage
            .get_by_path(&user_path)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to load user '{}' during token refresh: {}",
                    claims.username,
                    e
                );
                AuthError::Storage(e)
            })?
            .ok_or_else(|| {
                tracing::warn!(
                    "User '{}' not found in storage during token refresh",
                    claims.username
                );
                AuthError::UserNotFound
            })?;
        let decrypted = self
            .crypto
            .decrypt(&user_entry.encrypted_data)
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Failed to decrypt user '{}' during token refresh: {}",
                    claims.username,
                    e
                );
                AuthError::Internal(anyhow::anyhow!("Failed to decrypt user data: {}", e))
            })?;
        let stored_user: User = serde_json::from_slice(&decrypted).map_err(|e| {
            tracing::warn!(
                "Failed to deserialize user '{}' during token refresh: {}",
                claims.username,
                e
            );
            AuthError::Internal(anyhow::anyhow!("Failed to deserialize user data: {}", e))
        })?;

        // Reject token refresh for disabled or locked accounts.
        // Without this check a user whose account was disabled/locked after
        // login could keep refreshing tokens indefinitely.
        if stored_user.disabled || !stored_user.enabled || !stored_user.is_active {
            tracing::warn!(
                "Token refresh denied for user '{}': account is disabled/inactive",
                claims.username
            );
            return Err(AuthError::InvalidCredentials);
        }
        if let Some(locked_until) = stored_user.locked_until
            && locked_until > chrono::Utc::now()
        {
            tracing::warn!(
                "Token refresh denied for user '{}': account is locked until {}",
                claims.username,
                locked_until
            );
            return Err(AuthError::InvalidCredentials);
        }

        let is_privileged = stored_user.roles.contains(&"admin".to_string())
            || stored_user.roles.contains(&"root".to_string());

        // Re-read the global MFA flag so that a user who authenticated under
        // the TOFU path (non-privileged + global MFA on) cannot escape the
        // `mfa_pending` restriction simply by refreshing their token.
        let (_, global_mfa_enabled_for_refresh) = self.get_effective_config().await;

        // Check whether the user still needs MFA enrollment.  If MFA is
        // required for this user (privileged or global MFA enabled) and
        // they have not yet configured it, the refreshed token must carry
        // `mfa_required: true` so that the auth_middleware continues to
        // restrict scope.  Without this, a TOFU user could call the refresh
        // endpoint (which does not go through validate_token) to obtain a
        // new access token with `mfa_required: false`, completely bypassing
        // MFA enforcement.
        let token_mfa_required = if is_privileged || global_mfa_enabled_for_refresh {
            if let Some(mfa) = &self.mfa_service {
                let user_uuid = Uuid::parse_str(&stored_user.id).map_err(|_| {
                    tracing::error!(
                        "refresh_token: failed to parse user_id '{}' as UUID for user '{}'; \
                         denying refresh to prevent nil-UUID TOFU bypass",
                        stored_user.id,
                        claims.username
                    );
                    AuthError::Internal(anyhow::anyhow!(
                        "Cannot check MFA status: invalid user ID format"
                    ))
                })?;
                let mfa_configured = match mfa.is_mfa_required(user_uuid).await {
                    Ok(configured) => configured,
                    Err(e) => {
                        // Fail-safe: treat MFA service errors as "MFA is
                        // required" and deny the refresh entirely, consistent
                        // with `enforce_mfa()`.  A transient MFA service
                        // failure should not allow a privileged user to obtain
                        // a new token — even a restricted one — when their MFA
                        // enrollment status cannot be verified.
                        tracing::warn!(
                            "MFA service error during token refresh for user '{}': {}; \
                             denying refresh (fail-safe)",
                            claims.username,
                            e
                        );
                        return Err(AuthError::Internal(anyhow::anyhow!(
                            "Cannot verify MFA status during token refresh; please try again later"
                        )));
                    }
                };
                !mfa_configured // mfa_required = true when NOT configured
            } else {
                // MFA service not available — fail-safe: deny the refresh
                // rather than issuing a token without MFA verification.
                return Err(AuthError::Internal(anyhow::anyhow!(
                    "MFA service not configured but required for privileged token refresh"
                )));
            }
        } else {
            false
        };

        let (user_roles, user_policies, user_email) =
            (stored_user.roles, stored_user.policies, stored_user.email);

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                &claims.sub,
                &claims.username,
                user_email.as_deref(),
                &user_roles,
                &user_policies,
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|_| AuthError::InvalidToken)?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &claims.sub,
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await?;

        // Build the User from the data we already loaded from storage
        // (or from the token claims as a fallback).
        //
        // Propagate the `mfa_pending` metadata flag when the refreshed token
        // carries `mfa_required: true`, matching the contract documented on
        // `validate_token`.  This lets the refresh handler (and any other
        // caller that consumes `AuthToken.user` directly) read the TOFU flag
        // without having to re-validate the just-issued access token.
        let mut metadata = HashMap::new();
        if token_mfa_required {
            metadata.insert("mfa_pending".to_string(), "true".to_string());
        }
        let user = User {
            id: claims.sub.clone(),
            username: claims.username.clone(),
            email: user_email,
            display_name: None,
            disabled: false,
            password_hash: "".to_string(),
            password_login_disabled: false,
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: user_roles,
            permissions: vec![],
            policies: user_policies,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
            failed_login_attempts: 0,
            locked_until: None,
        };

        Ok(AuthToken {
            access_token: token_pair.access_token,
            refresh_token: token_pair.refresh_token,
            token_type: token_pair.token_type,
            expires_in: token_pair.expires_in,
            user,
        })
        }
        .await;

        match rotation {
            Ok(token) => {
                // The new session is durable, so the old refresh token can be revoked for
                // real. This is the step that makes reuse fail: `commit_refresh_token_rotation`
                // persists the revocation and invalidates the old session that carried this
                // token, so a replay after a successful exchange is rejected by both the
                // in-memory reservation and the durable record.
                //
                // The claim is extended to the token's own `exp` here, after the session
                // exists and before the token is returned. Until this point the claim carried
                // only the short `REFRESH_CLAIM_TTL_SECS` deadline, so an exchange that died
                // mid-flight would stop locking the token out. The extension closes the
                // single-use window: a subsequent claim must fail until the token's own
                // expiry, not merely until the short claim lapses.
                if !self
                    .extend_refresh_claim(refresh_token, &reservation_owner, refresh_expiry)
                    .await
                {
                    // The claim is no longer ours to extend — another attempt took the slot,
                    // which means a concurrent rotation is in progress. Do not return a
                    // second token: the whole point of the single-use claim is that only one
                    // exchange can commit, and this one can no longer prove it holds the
                    // slot. Fail closed and surface a token error.
                    self.release_refresh_token_reservation(refresh_token, &reservation_owner)
                        .await;
                    return Err(AuthError::InvalidToken);
                }
                self.commit_refresh_token_rotation(refresh_token, refresh_expiry)
                    .await;
                Ok(token)
            }
            Err(e) => {
                // Nothing was issued, so the reservation must not consume the token: release
                // the in-memory slot and remove any durable shadow a racing attempt may have
                // written, then return the original error. A retry with the same refresh
                // token succeeds if the fault was transient; a genuine reuse still fails,
                // because a successful rotation would have committed the revocation.
                self.release_refresh_token_reservation(refresh_token, &reservation_owner)
                    .await;
                Err(e)
            }
        }
    }

    /// Persist a completed refresh rotation: revoke the exchanged refresh token durably and
    /// invalidate the old session that carried it.
    async fn commit_refresh_token_rotation(
        &self,
        refresh_token: &str,
        refresh_expiry: chrono::DateTime<chrono::Utc>,
    ) {
        self.revoke_token(refresh_token.to_string(), refresh_expiry)
            .await;

        // The reservation is deliberately *not* removed here. Deleting it on success would
        // reopen the very window this fix closes: a second replica whose claim attempt
        // arrives after the delete but before it has observed the revocation would win the
        // insert-if-absent race and exchange the token again. Leaving the reservation in
        // place keeps the slot occupied for the token's whole lifetime, so the shared
        // backend refuses every later claim; it expires with the token, exactly as the
        // revocation entry does.

        // Best-effort: find and delete the old session whose refresh_token
        // matches the one being exchanged.  This is a scan over the
        // session prefix — acceptable because refresh is infrequent.
        //
        // Cap the scan with an explicit upper bound.  Before the
        // PostgreSQL backend's default `LIMIT 100` was removed (in the
        // lifecycle PR), this scan was implicitly bounded; without an
        // explicit limit it would now load every active session into
        // memory on every refresh.
        //
        // TODO: Index sessions by refresh-token hash so this scan can be
        // replaced with a direct lookup.
        const SESSION_REFRESH_SCAN_MAX_ENTRIES: u32 = 10_000;
        let params = secreton_storage::QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            include_expired: false,
            limit: Some(SESSION_REFRESH_SCAN_MAX_ENTRIES),
            ..Default::default()
        };
        if let Ok(entries) = self.storage.list(&params).await {
            for entry in entries {
                let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => decrypted,
                    Err(decrypt_err) => {
                        // Only fall back to raw bytes if they look like
                        // valid JSON (legacy plaintext session).
                        if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data)
                            .is_ok()
                        {
                            tracing::warn!(
                                "Session '{}': decryption failed, using legacy plaintext fallback",
                                entry.path
                            );
                            entry.encrypted_data.clone()
                        } else {
                            tracing::warn!(
                                "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                                 skipping corrupt entry",
                                entry.path,
                                decrypt_err
                            );
                            continue; // skip corrupt entries
                        }
                    }
                };
                if let Ok(session) = serde_json::from_slice::<Session>(&session_bytes)
                    && session.refresh_token.as_deref() == Some(refresh_token)
                {
                    // Revoke the old access token
                    self.revoke_token(session.token.clone(), session.expires_at)
                        .await;
                    // Delete the old session record
                    let _ = self.storage.delete_by_path(&entry.path).await;
                    break;
                }
            }
        }
    }

    /// The storage path of the reservation slot for a refresh token.
    ///
    /// Derived from the SHA-256 hash of the token, exactly like
    /// [`Self::revoked_token_path`], so the reservation is content-addressed and no token
    /// material reaches storage. It is deliberately a different prefix from the revocation
    /// path: the two records mean different things and are removed by different code.
    fn refresh_reservation_path(token: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        format!(
            "{}{}",
            REFRESH_RESERVATION_STORAGE_PREFIX,
            hex::encode(digest)
        )
    }

    /// Claim the single-use reservation for a refresh token, in shared storage.
    ///
    /// Returns the reservation's owner token when *this* call created it and may proceed,
    /// or `None` when another holder (in this process or another replica) already has it and
    /// the caller must be refused. On a backend that reports
    /// [`secreton_storage::Coordination::SingleProcess`] the atomic insert is not
    /// available, so the in-process blacklist is the reservation — the same guarantee the
    /// service already had, and the honest one for a backend no second replica can share.
    ///
    /// The claim is written with a *short* deadline ([`REFRESH_CLAIM_TTL_SECS`], capped by
    /// the token's own expiry) rather than the token's whole lifetime. The exchange extends
    /// it to the token's `exp` only once a new session is durable (see
    /// [`Self::commit_refresh_token_rotation`]). A claim that never reaches that point — the
    /// exchange died, or its release failed — therefore lapses on its own and stops locking
    /// the token out, instead of occupying the slot for days until `delete_expired` sweeps
    /// it.
    async fn reserve_refresh_token(
        &self,
        refresh_token: &str,
        refresh_expiry: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<String>, AuthError> {
        // In-memory fast path and single-process authority. Check and insert under one
        // write guard, so two tasks on this instance cannot both win. The in-memory slot
        // carries the *claim* TTL too, so a claim whose durable counterpart lapses is also
        // claimable again on this instance after the same window.
        let claim_ttl = self.refresh_claim_ttl();
        let claim_expiry =
            (chrono::Utc::now() + chrono::Duration::seconds(claim_ttl)).min(refresh_expiry);
        {
            let mut blacklist = self.token_blacklist.write().await;
            if let Some(expires_at) = blacklist.get(refresh_token)
                && *expires_at > chrono::Utc::now()
            {
                return Ok(None);
            }
            blacklist.insert(refresh_token.to_string(), claim_expiry);
        }

        // The owner token is unique to this claim, so a release can never remove a
        // reservation another attempt re-took after this one's record expired.
        let owner = Uuid::new_v4().to_string();

        if self.storage.coordination() == secreton_storage::Coordination::SingleProcess {
            // A process-local backend is a separate map per process, so no second replica
            // can hold this token. The in-memory reservation above is the complete
            // guarantee, and pretending to take a durable one would be the fake lock the
            // storage trait refuses to fake.
            return Ok(Some(owner));
        }

        let path = Self::refresh_reservation_path(refresh_token);
        let entry = SecretEntry::new(
            path.clone(),
            Vec::new(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .owned_by(&owner)
        .with_expiration(claim_expiry);

        // A completed rotation revokes the refresh token durably at a *different* path from
        // the reservation, and that revocation outlives the short claim window (it is written
        // with the token's own expiry). Reclaiming a lapsed reservation must therefore not be
        // enough to exchange the token again: a replay whose `is_token_revoked` fast path
        // missed (a different replica, or a storage read that failed open) would otherwise
        // delete the expired reservation and re-claim the slot, and be handed a second session
        // for a token that was already exchanged. Check the durable revocation here, at the
        // point of reclaiming, and refuse — fail *closed* on a read error, because the
        // alternative is admitting a replay of a single-use token.
        match self
            .storage
            .get_by_path(&Self::revoked_token_path(refresh_token))
            .await
        {
            Ok(Some(revocation)) => {
                let live = revocation
                    .expires_at
                    .map(|exp| exp > chrono::Utc::now())
                    .unwrap_or(true);
                if live {
                    // Undo the in-memory slot this call just inserted, exactly as the
                    // `Ok(false)` arm below does, so this process does not carry a reservation
                    // for a token it must refuse.
                    let mut blacklist = self.token_blacklist.write().await;
                    blacklist.remove(refresh_token);
                    return Ok(None);
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(
                    "Failed to read the durable revocation record while reserving a refresh \
                     token; refusing the exchange rather than risk replaying an already-rotated \
                     token: {e}"
                );
                let mut blacklist = self.token_blacklist.write().await;
                blacklist.remove(refresh_token);
                return Err(AuthError::Storage(e));
            }
        }

        // A lapsed claim must not block a retry. `compare_and_set(Absent)` does not by
        // itself reclaim a record at the path, and the reservation is deliberately *not*
        // deleted on a successful exchange, so a claim whose short deadline passed — an
        // exchange that died before it could be extended — would otherwise keep the slot
        // occupied until `delete_expired` happened to sweep it. Deleting it here can only
        // remove an already-expired record: a live claim (owner-conditional) is left alone,
        // and `delete_owned` on a *stale* owner token is a no-op, so another holder's slot
        // is never touched.
        if let Ok(Some(existing)) = self.storage.get_by_path(&path).await
            && existing.is_expired()
            && let Some(existing_owner) = existing.owner_token().map(str::to_string)
        {
            let _ = self.storage.delete_owned(&path, &existing_owner).await;
        }

        // Insert-if-absent is the atomic claim. A backend that reports cross-process
        // coordination but cannot perform it returns `Unsupported`, and this fails closed:
        // refusing the refresh is correct, silently falling back to a per-process check
        // would reopen the race.
        match self
            .storage
            .compare_and_set(&entry, secreton_storage::Expect::Absent)
            .await
        {
            Ok(true) => Ok(Some(owner)),
            Ok(false) => {
                // Another replica already holds it. Drop the in-memory slot this call just
                // inserted so this process does not carry a reservation it did not win.
                let mut blacklist = self.token_blacklist.write().await;
                blacklist.remove(refresh_token);
                Ok(None)
            }
            Err(e) => {
                // The shared claim did not complete, so this process did not win the slot
                // either. The in-memory insert above must be undone, exactly as the
                // `Ok(false)` arm does: leaving it behind made a transient storage fault —
                // a brief Redis or PostgreSQL disconnect — consume the refresh token on this
                // instance for the reservation's whole lifetime, so every retry returned
                // `InvalidToken` without ever consulting the recovered backend.
                let mut blacklist = self.token_blacklist.write().await;
                blacklist.remove(refresh_token);
                Err(AuthError::Storage(e))
            }
        }
    }

    /// Drop the single-use reservation for a refresh token whose exchange failed.
    ///
    /// Only called when the exchange issued no session; a completed rotation never releases.
    /// Both the in-memory slot and the durable reservation are removed — the latter only
    /// through the owner-conditional delete, so a reservation another attempt re-took after
    /// this one's record expired is never destroyed. A durable revocation a racing attempt
    /// may have written for this token is left in place: that is a completed rotation by
    /// someone else, and releasing it would revive a token that was successfully exchanged.
    ///
    /// There is deliberately **no** read-then-unconditional-delete fallback. Reading the
    /// record and then deleting by path reopens the exact window `delete_owned` closes: a
    /// second replica can take the slot in between, and the unconditional delete removes
    /// *its* reservation, letting the same token be exchanged twice. When the conditional
    /// delete does not complete — an unsupported backend, or a transient fault — the record
    /// is left in place and this logs the fact. That is not a lockout: the claim carries the
    /// short [`REFRESH_CLAIM_TTL_SECS`] deadline, so it lapses on its own and the token
    /// becomes claimable again. Logs never include token material.
    async fn release_refresh_token_reservation(&self, refresh_token: &str, owner: &str) {
        {
            let mut blacklist = self.token_blacklist.write().await;
            blacklist.remove(refresh_token);
        }
        let path = Self::refresh_reservation_path(refresh_token);

        match self.storage.delete_owned(&path, owner).await {
            // Removed, or there was nothing of ours to remove.
            Ok(_) => {}
            Err(secreton_storage::StorageError::Unsupported { .. }) => {
                tracing::warn!(
                    "Backend cannot delete a refresh-token reservation conditionally; \
                     leaving the claim in place to lapse on its own rather than risking \
                     another attempt's reservation"
                );
            }
            Err(e) => {
                tracing::error!(
                    "Failed to release the refresh-token reservation with an owner-conditional \
                     delete; leaving the claim in place to lapse on its own: {e}"
                );
            }
        }
    }

    /// The claim TTL in force: the production constant, or the test override.
    fn refresh_claim_ttl(&self) -> i64 {
        #[cfg(test)]
        {
            self.refresh_claim_ttl_override
                .load(std::sync::atomic::Ordering::SeqCst)
        }
        #[cfg(not(test))]
        {
            REFRESH_CLAIM_TTL_SECS
        }
    }

    /// Extend the single-use claim on a refresh token to the token's own expiry, once its
    /// exchange has produced a durable session.
    ///
    /// The claim is taken with the short [`REFRESH_CLAIM_TTL_SECS`] window so a stalled
    /// exchange cannot lock the token out for days. Once a new session exists, the claim
    /// must last as long as the token it guards, or the same refresh token could be claimed
    /// and exchanged *again* after the short window elapsed — the exact reuse the
    /// reservation exists to prevent. The extension is owner-conditional
    /// ([`secreton_storage::Expect::Owner`]), so a slot another attempt has taken over is
    /// not rewritten and this reports `false` for the caller to fail closed on. Never logs
    /// token material.
    async fn extend_refresh_claim(
        &self,
        refresh_token: &str,
        owner: &str,
        refresh_expiry: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        // In-memory slot: the whole guarantee on a single-process backend, and the fast
        // path on a shared one. Upgrade it to the token's expiry so it cannot lapse early.
        {
            let mut blacklist = self.token_blacklist.write().await;
            blacklist.insert(refresh_token.to_string(), refresh_expiry);
        }

        if self.storage.coordination() == secreton_storage::Coordination::SingleProcess {
            return true;
        }

        let path = Self::refresh_reservation_path(refresh_token);
        let entry = SecretEntry::new(
            path,
            Vec::new(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .owned_by(owner)
        .with_expiration(refresh_expiry);

        match self
            .storage
            .compare_and_set(&entry, secreton_storage::Expect::Owner(owner))
            .await
        {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                tracing::error!(
                    "Failed to extend the refresh-token claim; refusing the exchange: {e}"
                );
                false
            }
        }
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        username: &str,
        password: &str,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let user_id = Uuid::new_v4().to_string();

        // Hash first: hashing is expensive and must not run while another writer is
        // committing the same username, and it must not register anything in memory before
        // storage has decided whether the name is free.
        let password_hash = self.userpass_method.hash_password(password).map_err(|_| {
            AuthError::Internal(anyhow::anyhow!("Failed to hash the user password"))
        })?;

        let user = User {
            id: user_id.clone(),
            username: username.to_string(),
            email: email.clone(),
            password_hash: password_hash.clone(),
            password_login_disabled: false,
            full_name: None,
            is_active: true,
            is_superuser: roles.contains(&"admin".to_string())
                || roles.contains(&"root".to_string()),
            roles: roles.clone(),
            permissions: permissions.clone(),
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };

        let user_data = serde_json::to_vec(&user)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;
        let encrypted_data = self.crypto.encrypt_data(&user_data).await.map_err(|e| {
            AuthError::Crypto(secreton_crypto::CryptoError::Internal(e.to_string()))
        })?;

        let entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&user.id).unwrap_or_default(),
        );

        // The existence check and the write are one atomic insert-if-absent, not a read
        // followed by a `store`. The read-then-write let an ordinary registration and the
        // bootstrap-root registration both pass the same `exists` check and then both write
        // the path: whichever landed last silently replaced the other identity — for the
        // bootstrap path that meant an attacker's concurrent registration could displace the
        // privileged account initialized moments earlier (or vice versa), with no error
        // reported to either caller. `compare_and_set(Absent)` makes the second writer see
        // the occupied path and stop.
        match self
            .storage
            .compare_and_set(&entry, secreton_storage::Expect::Absent)
            .await
        {
            Ok(true) => {}
            Ok(false) => return Err(AuthError::UserAlreadyExists),
            Err(e) if e.is_precondition_failure() => return Err(AuthError::UserAlreadyExists),
            Err(e) => return Err(AuthError::Storage(e)),
        }

        // Publish the in-memory login identity only after the durable write wins. Registering
        // it before the write would leave a login that works until the process restarts when
        // the write then fails or loses the race.
        self.userpass_method
            .add_user(
                username.to_string(),
                password_hash,
                user_id,
                roles,
                vec!["default".to_string()],
                permissions,
                false,
            )
            .await;

        Ok(user)
    }

    /// Create user (wrapper for register_user)
    pub async fn create_user(
        &self,
        username: &str,
        email: &str,
        password: &str,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        self.register_user(
            username,
            password,
            Some(email.to_string()),
            roles,
            permissions,
        )
        .await
    }

    /// Create the bootstrap root identity `init` owns the vault through.
    ///
    /// Deliberately not `register_user` with a random password. That is what the previous
    /// implementation did, and it left a privileged account holding an active password
    /// hash: the only thing keeping it out of the password path was a literal `"root"`
    /// username check, which stopped covering the account the moment `init` accepted a
    /// custom `root_username`. This creates the account with an explicitly
    /// non-password-authenticatable identity instead — no hash is generated or stored, and
    /// `password_login_disabled` is persisted — so the boundary is the account's own
    /// property rather than its name.
    pub async fn register_bootstrap_root(
        &self,
        username: &str,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
    ) -> Result<User, AuthError> {
        self.register_bootstrap_root_owned(username, email, roles, permissions, None, None)
            .await
    }

    /// [`Self::register_bootstrap_root`], stamping the persisted account with an owner
    /// token and optionally fencing the write.
    ///
    /// Initialization passes its cross-process lease token here so a failed attempt's
    /// cleanup can remove the account it created: on a shared backend the cleanup deletes
    /// with `delete_owned`, which only removes records carrying that token. An account
    /// written without one is invisible to that path, so the rollback would leave a
    /// privileged account behind while reporting success. Callers outside initialization
    /// pass `None`, the same way the ordinary MFA setup path leaves an enrollment unowned.
    ///
    /// When `fence` is supplied the account is written through an atomic
    /// insert-if-absent that also evaluates the fence, so the write only lands while the
    /// initialization still holds the lease it names *and* only while the path is free. The
    /// owner token alone would only make the account removable afterwards; the fence is what
    /// stops an attempt that has already lost the lease from creating a privileged account
    /// at all, and the insert-if-absent is what stops a concurrent ordinary registration of
    /// the same username from replacing the account after initialization commits.
    pub async fn register_bootstrap_root_owned(
        &self,
        username: &str,
        email: Option<String>,
        roles: Vec<String>,
        permissions: Vec<String>,
        owner: Option<&str>,
        fence: Option<StorageFence<'_>>,
    ) -> Result<User, AuthError> {
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let user_id = Uuid::new_v4().to_string();

        // Register the identity with the userpass method so token issuance sees it, but
        // with no password hash and the flag set: there is nothing for a verifier to
        // accept even if the in-memory entry were tampered with.
        let account = User {
            id: user_id.clone(),
            username: username.to_string(),
            email: email.clone(),
            password_hash: String::new(),
            password_login_disabled: true,
            full_name: None,
            is_active: true,
            is_superuser: true,
            roles: roles.clone(),
            permissions: permissions.clone(),
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };
        let user_id = account.id.clone();

        let user_data = serde_json::to_vec(&account)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;
        let encrypted_data = self.crypto.encrypt_data(&user_data).await.map_err(|e| {
            AuthError::Crypto(secreton_crypto::CryptoError::Internal(e.to_string()))
        })?;
        let entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::parse_str(&account.id).unwrap_or_default(),
        );
        let entry = match owner {
            Some(owner) => entry.owned_by(owner),
            None => entry,
        };

        // The write comes first, and the in-memory userpass identity only second. The other
        // order registers a login identity in memory for an account whose durable write then
        // fails — a login that works until the process restarts, and, on the fenced path, a
        // login for an attempt that had already lost its lease.
        //
        // The write is an atomic insert-if-absent in both arms. With a fence it is
        // `AbsentFenced`, which evaluates the path's emptiness and the lease together:
        // `store_fenced` alone would overwrite a user registered concurrently under the same
        // username, and a separate `exists` check followed by `store_fenced` would reopen the
        // check-then-write window the fence exists to close.
        let expectation = match fence {
            Some(fence) => secreton_storage::Expect::AbsentFenced(fence),
            None => secreton_storage::Expect::Absent,
        };
        match self.storage.compare_and_set(&entry, expectation).await {
            Ok(true) => {}
            // The path is already occupied: an ordinary account of this username exists, or
            // won the race to create it. Never replace it.
            Ok(false) if fence.is_none() => return Err(AuthError::UserAlreadyExists),
            // A fenced `Ok(false)` means the lease is gone, not that the name is taken; the
            // two must not be conflated, so it stays an internal failure.
            Ok(false) => {
                return Err(AuthError::Internal(anyhow::anyhow!(
                    "the initialization lease was lost before the root account could \
                     be written"
                )));
            }
            Err(e) if e.is_precondition_failure() => return Err(AuthError::UserAlreadyExists),
            Err(e) => return Err(AuthError::Storage(e)),
        }

        self.userpass_method
            .add_bootstrap_root(
                username.to_string(),
                user_id,
                roles,
                vec!["default".to_string()],
                permissions,
            )
            .await;

        Ok(account)
    }

    /// Mark an existing account as not password-authenticatable, in storage *and* in the
    /// in-memory userpass cache the login path reads.
    ///
    /// Used by the seal service to upgrade a vault initialised before the flag existed:
    /// that vault's root account was created with a generated password and can only be
    /// identified by reading the real record, so the upgrade persists the same boundary a
    /// fresh `init` now writes directly.
    pub async fn mark_password_login_disabled(&self, username: &str) -> Result<(), AuthError> {
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let Some(entry) = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AuthError::Storage)?
        else {
            return Err(AuthError::UserNotFound);
        };
        let bytes = self.crypto.decrypt(&entry.encrypted_data).await?;
        let mut user: User = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("corrupt user record: {}", e)))?;
        if user.password_login_disabled {
            return Ok(());
        }
        user.password_login_disabled = true;
        user.updated_at = chrono::Utc::now();

        let data = serde_json::to_vec(&user)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Serialization error: {}", e)))?;
        let encrypted = self.crypto.encrypt_data(&data).await.map_err(|e| {
            AuthError::Crypto(secreton_crypto::CryptoError::Internal(e.to_string()))
        })?;
        let mut updated = entry;
        updated.encrypted_data = encrypted;
        self.storage
            .update(&updated)
            .await
            .map_err(AuthError::Storage)?;

        // The login path checks the cached `UserEntry`, which was built at startup. With
        // the hash cleared it cannot accept a password either way, but keeping the two in
        // step is what makes the flags agree.
        self.userpass_method
            .add_bootstrap_root(
                user.username.clone(),
                user.id.clone(),
                user.roles.clone(),
                user.policies.clone(),
                user.permissions.clone(),
            )
            .await;
        Ok(())
    }

    /// Ensure the in-memory userpass identity for `user` reflects its durable record.
    ///
    /// [`AuthenticationService::new`] hydrates `UserPassAuthMethod` from storage, but that
    /// scan is capped (`USER_LOAD_MAX_ENTRIES`), so on a deployment with more accounts than
    /// the cap the users beyond it are absent from the map. `UserPassAuthMethod` is the only
    /// thing that verifies a password, so a stored account omitted at startup could never
    /// sign in. The login paths already read the account's durable record for lockout and
    /// status checks; re-publishing that same record into the map here makes authentication
    /// independent of the startup cap.
    async fn hydrate_userpass_identity(&self, user: &User) {
        self.userpass_method
            .add_user(
                user.username.clone(),
                user.password_hash.clone(),
                user.id.clone(),
                user.roles.clone(),
                user.policies.clone(),
                user.permissions.clone(),
                user.password_login_disabled,
            )
            .await;
    }

    /// Look up a user by username, decrypting the stored record.
    ///
    /// `Ok(None)` means the record is absent; an error means it exists but could not be
    /// read. Callers must not collapse the two — "no such user" and "storage is broken"
    /// are different situations.
    pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AuthError> {
        let path = format!("{}{}", USER_STORAGE_PREFIX, username);
        let Some(entry) = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AuthError::Storage)?
        else {
            return Ok(None);
        };
        let bytes = self.crypto.decrypt(&entry.encrypted_data).await?;
        let user = serde_json::from_slice(&bytes)
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("corrupt user record: {}", e)))?;
        Ok(Some(user))
    }

    /// Record a session and mint an access token bound to it, for a flow that has
    /// already established the caller's identity.
    ///
    /// The returned token carries the session's `jti`, which is what `validate_token`
    /// requires; a token minted without one is rejected on every request, so this is the
    /// only supported way to hand out a credential outside the login path.
    ///
    /// `duration_secs` is explicit and *required*, deliberately. This method previously
    /// read the effective session timeout, which an operator can raise to 24 hours through
    /// `system/config`. That made the credential returned by an unseal silently inherit
    /// whatever the interactive-session policy was, so the one credential that can
    /// reconfigure the vault lived for a day. Bootstrap credentials take
    /// [`BOOTSTRAP_TOKEN_TTL_SECS`] and the caller says so.
    ///
    /// The session is **access-only**: no refresh token is minted and none is stored. The
    /// only caller is the unseal path, and the root bootstrap credential must not be
    /// extendable — a refresh token would let the holder mint a fresh root access token
    /// indefinitely, outliving the one-hour bootstrap TTL the whole design rests on. Because
    /// the session record carries `refresh_token: None`, there is nothing to exchange, and
    /// `refresh_token()` cannot rotate this credential.
    pub async fn issue_session_token(
        &self,
        user: &User,
        ip_address: String,
        user_agent: String,
        duration_secs: u64,
    ) -> Result<String, AuthError> {
        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(duration_secs))
                .unwrap_or(chrono::Duration::hours(1));

        let session_id = Uuid::new_v4().to_string();
        // Mint the access token directly rather than a pair, so no refresh token exists even
        // transiently. `create_token_pair_with_duration` would sign one that, while unstored,
        // remains a valid signed refresh JWT to anyone who received it.
        let access_token = self
            .token_service
            .create_access_token_with_duration(
                &user.id,
                &user.username,
                user.email.as_deref(),
                &user.roles,
                &user.policies,
                false,
                Some(session_id.clone()),
                Some(session_duration),
            )
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("failed to mint token: {}", e)))?;

        self.create_and_store_session(
            &user.id,
            session_id,
            access_token.clone(),
            None,
            ip_address,
            user_agent,
            duration_secs,
        )
        .await?;

        Ok(access_token)
    }

    /// Check if user has permission (simplified)
    pub async fn has_permission(&self, user: &User, permission: &str) -> Result<bool, AuthError> {
        // Simplified permission check based on roles
        // In production, this would use a proper RBAC system
        if user.is_admin() {
            return Ok(true);
        }

        // Check for specific permissions based on roles
        match permission {
            "secreton:read" | "secreton:list" => Ok(user.roles.contains(&"user".to_string())
                || user.roles.contains(&"viewer".to_string())),
            "secreton:write" => Ok(user.roles.contains(&"user".to_string())),
            _ => Ok(false),
        }
    }

    /// Get total user count
    pub async fn get_user_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams::new().with_path_prefix(USER_STORAGE_PREFIX.to_string());
        let count = self.storage.count(&params).await?;
        Ok(count)
    }

    /// Get active session count
    pub async fn get_active_session_count(&self) -> Result<u64, AuthError> {
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            ..Default::default()
        };

        let count = self
            .storage
            .count(&params)
            .await
            .map_err(AuthError::Storage)?;

        Ok(count)
    }

    /// List sessions for a specific user
    pub async fn list_user_sessions(&self, user_id: &str) -> Result<Vec<Session>, AuthError> {
        // We scan all sessions and filter by user_id
        // In a real DB we would index this or use a secondary index.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now load every active session into memory and decrypt each
        // one. 10k is generous for a single user's session list while still
        // bounding worst-case memory.
        //
        // TODO: Index sessions by `user_id` so this scan can be replaced
        // with a direct lookup.
        const SESSION_LIST_MAX_ENTRIES: u32 = 10_000;
        let params = QueryParams {
            path_prefix: Some(SESSION_STORAGE_PREFIX.to_string()),
            include_expired: false,
            limit: Some(SESSION_LIST_MAX_ENTRIES),
            ..Default::default()
        };

        let entries = self
            .storage
            .list(&params)
            .await
            .map_err(AuthError::Storage)?;

        let mut sessions = Vec::new();
        for entry in entries {
            // Decrypt session data, with fallback for legacy plaintext entries.
            let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => decrypted,
                Err(decrypt_err) => {
                    // Only fall back to raw bytes if they look like valid JSON
                    // (i.e. a legacy plaintext session).  If the raw bytes are
                    // NOT valid JSON either, this is genuine data corruption —
                    // log it and skip the entry rather than silently producing
                    // a garbage Session.
                    if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data).is_ok() {
                        tracing::warn!(
                            "Session '{}': decryption failed, using legacy plaintext fallback",
                            entry.path
                        );
                        entry.encrypted_data.clone()
                    } else {
                        tracing::warn!(
                            "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                             skipping corrupt entry",
                            entry.path,
                            decrypt_err
                        );
                        continue;
                    }
                }
            };
            if let Ok(session) = serde_json::from_slice::<Session>(&session_bytes)
                && session.user_id == user_id
            {
                sessions.push(session);
            }
        }

        Ok(sessions)
    }

    /// Revoke a specific user session
    pub async fn revoke_user_session(
        &self,
        session_id: &str,
        user_id: &str,
    ) -> Result<(), AuthError> {
        let path = format!("{}{}", SESSION_STORAGE_PREFIX, session_id);

        // Verify ownership
        if let Some(entry) = self
            .storage
            .get_by_path(&path)
            .await
            .map_err(AuthError::Storage)?
        {
            // Decrypt session data, with fallback for legacy plaintext entries.
            let session_bytes = match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => decrypted,
                Err(decrypt_err) => {
                    // Only fall back to raw bytes if they look like valid JSON
                    // (i.e. a legacy plaintext session).  If the raw bytes are
                    // NOT valid JSON either, this is genuine data corruption —
                    // deny the request rather than risking a failed ownership check.
                    if serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data).is_ok() {
                        tracing::warn!(
                            "Session '{}': decryption failed, using legacy plaintext fallback",
                            session_id
                        );
                        entry.encrypted_data.clone()
                    } else {
                        tracing::warn!(
                            "Session '{}': decryption failed ({}) and raw data is not valid JSON; \
                             cannot verify ownership",
                            session_id,
                            decrypt_err
                        );
                        return Err(AuthError::Internal(anyhow::anyhow!(
                            "Cannot verify session ownership: failed to decrypt session data"
                        )));
                    }
                }
            };
            // The ownership check is security-critical: we MUST verify that
            // the caller owns this session before deleting it.  If
            // deserialization fails (e.g. because the encrypted data could
            // not be decrypted and the raw ciphertext is not valid JSON),
            // deny the request rather than skipping the ownership check and
            // allowing any authenticated user to delete arbitrary sessions.
            let session = serde_json::from_slice::<Session>(&session_bytes).map_err(|e| {
                tracing::warn!(
                    "Failed to deserialize session '{}' during revocation \
                     (ownership check cannot be performed): {}",
                    session_id,
                    e
                );
                AuthError::Internal(anyhow::anyhow!(
                    "Cannot verify session ownership: failed to read session data"
                ))
            })?;
            if session.user_id != user_id {
                return Err(AuthError::PermissionDenied);
            }
            // Revoke the token associated with this session
            self.revoke_token(session.token, session.expires_at).await;
        } else {
            return Err(AuthError::Storage(
                secreton_storage::StorageError::NotFound {
                    resource_type: "session".to_string(),
                    id: session_id.to_string(),
                },
            ));
        }

        self.storage
            .delete_by_path(&path)
            .await
            .map_err(AuthError::Storage)?;

        Ok(())
    }

    /// Cleanup expired sessions and revoked-token entries.
    ///
    /// Also prunes stale revocations from the shared storage backend so the
    /// revoked-token store does not grow unboundedly.  The in-memory
    /// blacklist is self-cleaning on every `revoke_token` call.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, AuthError> {
        let deleted_count = self
            .storage
            .delete_expired(Some(SESSION_STORAGE_PREFIX.to_string()))
            .await
            .map_err(AuthError::Storage)?;

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired sessions", deleted_count);
        }

        // Also prune expired revocation entries.  Failures are logged but
        // not propagated — session cleanup succeeding is still useful even
        // if the revocation store is temporarily unavailable.
        match self
            .storage
            .delete_expired(Some(REVOKED_TOKEN_STORAGE_PREFIX.to_string()))
            .await
        {
            Ok(n) if n > 0 => {
                tracing::info!("Cleaned up {} expired token revocations", n);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up expired token revocations: {}", e);
            }
        }

        // And prune expired refresh reservations. Each one carries the refresh token's own
        // `exp`, so it is reclaimable once that passes. Without this sweep the prefix grew
        // without bound on every backend that persists it: a reservation is deliberately
        // left in place after a successful exchange (removing it re-opens the replay race
        // it exists to close), so *every* refresh left a record behind and nothing ever
        // removed it — not even `delete_expired`, which was only ever asked for the
        // session and revocation prefixes.
        match self
            .storage
            .delete_expired(Some(REFRESH_RESERVATION_STORAGE_PREFIX.to_string()))
            .await
        {
            Ok(n) if n > 0 => {
                tracing::info!("Cleaned up {} expired refresh reservations", n);
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("Failed to clean up expired refresh reservations: {}", e);
            }
        }

        Ok(deleted_count)
    }

    /// Verify password for a user
    pub async fn verify_password(&self, username: &str, password: &str) -> Result<bool, AuthError> {
        // The bootstrap root identity has no password to verify, and asking must not
        // become an oracle for which account it is: the answer is the same as a wrong
        // password. The persisted flag is the boundary; a nil hash would already fail
        // `check_password`, but relying on that alone would be relying on the absence of a
        // value rather than on a stated property.
        if let Ok(Some(user)) = self.find_user_by_username(username).await {
            // Republish the durable record before the check: the capped startup hydration
            // (`USER_LOAD_MAX_ENTRIES`) may have omitted this account, and
            // `UserPassAuthMethod` is what verifies the password. Without this, a valid
            // account beyond the cap is rejected here even though its stored hash matches.
            self.hydrate_userpass_identity(&user).await;
            if user.password_login_disabled {
                return Ok(false);
            }
        }

        let request = LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
            mfa_code: None,
            remember_me: None,
        };

        match self.auth_service.login(&request).await {
            Ok(response) => Ok(response.success),
            Err(_) => Ok(false),
        }
    }

    /// Generate access token for user
    pub async fn generate_token(
        &self,
        user: &User,
        ip_address: String,
        user_agent: String,
    ) -> Result<String, AuthError> {
        // Get effective config for session timeout
        let (session_timeout_secs, _) = self.get_effective_config().await;

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token = self
            .token_service
            .create_access_token_with_duration(
                &user.id,
                &user.username,
                user.email.as_deref(),
                &user.roles,
                &user.policies,
                false, // MFA not required for simple token generation
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|e| AuthError::Internal(anyhow::anyhow!("Token generation failed: {}", e)))?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                &user.id,
                temp_session_id,
                token.clone(),
                None,
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await?;

        Ok(token)
    }

    /// Generate refresh token for user
    ///
    /// Uses the token service's `create_refresh_token` method to produce a
    /// `RefreshTokenClaims`-based token signed with `jwt_refresh_secret`.
    /// This ensures the token can be validated by `validate_refresh_token`
    /// (which expects `RefreshTokenClaims` and uses `jwt_refresh_secret`).
    ///
    /// Previously this method used the API-local `Claims` struct and signed
    /// with `jwt_secret`, creating a structural and key mismatch that would
    /// cause `refresh_token()` → `validate_refresh_token()` to fail.
    pub async fn generate_refresh_token(&self, user: &User) -> Result<String, AuthError> {
        self.token_service
            .create_refresh_token(&user.id, &user.username)
            .map_err(|e| {
                AuthError::Internal(anyhow::anyhow!("Refresh token generation failed: {}", e))
            })
    }

    /// Authenticate user
    pub async fn authenticate(
        &self,
        credentials: crate::services::auth::LoginRequest,
        ip_address: String,
        user_agent: String,
    ) -> Result<AuthResult, AuthError> {
        // Same boundary as `login()`: the bootstrap root identity is barred because the
        // account is persisted as non-password-authenticatable, not by username. The
        // literal check this replaces only covered the default name and let a root account
        // created under a custom `root_username` authenticate with its generated password.
        //
        // Checked after the user is loaded below so the denial reads the real record; the
        // generic error keeps it from revealing which account is the bootstrap root.
        //
        // Load user from storage ONCE at the start so that lockout checks,
        // failed-attempt increments, policy loading, and counter resets all
        // operate on the same snapshot.  This eliminates the TOCTOU window
        // that existed when the user was re-read up to 3 times, and avoids
        // the extra storage + decryption overhead.
        let user_path = format!("{}{}", USER_STORAGE_PREFIX, credentials.username);
        let (mut pre_auth_user, mut pre_auth_entry) = match self
            .storage
            .get_by_path(&user_path)
            .await
        {
            Ok(Some(entry)) => {
                let decrypted = self
                    .crypto
                    .decrypt(&entry.encrypted_data)
                    .await
                    .map_err(|e| {
                        tracing::warn!(
                            "Failed to decrypt user '{}' during authenticate: {}",
                            credentials.username,
                            e
                        );
                        AuthError::Internal(anyhow::anyhow!("Failed to decrypt user data: {}", e))
                    })?;
                let u: User = serde_json::from_slice(&decrypted).map_err(|e| {
                    tracing::warn!(
                        "Failed to deserialize user '{}' during authenticate: {}",
                        credentials.username,
                        e
                    );
                    AuthError::Internal(anyhow::anyhow!("Failed to deserialize user data: {}", e))
                })?;
                (Some(u), Some(entry))
            }
            Ok(None) => (None, None),
            Err(e) => {
                tracing::warn!(
                    "Failed to load user '{}' from storage during authenticate: {}",
                    credentials.username,
                    e
                );
                return Err(AuthError::Storage(e));
            }
        };

        // The bootstrap root identity cannot password-authenticate. Checked against the
        // loaded record so the boundary follows the account, and answered with the same
        // generic error a wrong password gets.
        //
        // Republish the durable record first: the capped startup hydration may have omitted
        // this account, and `UserPassAuthMethod` is what verifies its password.
        if let Some(ref u) = pre_auth_user {
            self.hydrate_userpass_identity(u).await;
        }
        if let Some(ref u) = pre_auth_user
            && u.password_login_disabled
        {
            if let Some(audit) = &self.audit {
                let _ = audit
                    .log_event(
                        crate::services::audit::SecurityEventType::AuthenticationFailure {
                            user: credentials.username.clone(),
                            method: "userpass".to_string(),
                            reason: "Account is not password-authenticatable".to_string(),
                        },
                    )
                    .await;
            }
            return Err(AuthError::InvalidCredentials);
        }

        // Check lockout status before attempting login — mirrors the check in
        // `login()` so that locked accounts cannot authenticate through this
        // code path.
        if let Some(ref u) = pre_auth_user {
            if let Some(locked_until) = u.locked_until
                && locked_until > chrono::Utc::now()
            {
                if let Some(audit) = &self.audit {
                    let _ = audit
                        .log_event(
                            crate::services::audit::SecurityEventType::AuthenticationFailure {
                                user: credentials.username.clone(),
                                method: "userpass".to_string(),
                                reason: "Account locked".to_string(),
                            },
                        )
                        .await;
                }
                return Err(AuthError::InvalidCredentials);
            }
            if u.disabled || !u.enabled || !u.is_active {
                return Err(AuthError::InvalidCredentials);
            }
        }

        // Do NOT pass mfa_code to auth_service.login() — MFA is validated
        // explicitly below.  Passing it here could cause double-validation
        // issues if the underlying auth service ever starts consuming TOTP
        // codes (which are single-use).
        let request = secreton_auth::LoginRequest {
            username: credentials.username.clone(),
            password: credentials.password,
            mfa_code: None,
            remember_me: credentials.remember_me,
        };

        let result = self
            .auth_service
            .login(&request)
            .await
            // A wrong password is a client error, not a fault. Folding it into
            // `Internal` here made every failed login answer 500 — which is both the wrong
            // status and a lie about the server's health, and it buried real login failures
            // in the server-error log where nobody looks for a typo.
            .map_err(|e| match e {
                secreton_domain::SecretonError::InvalidCredentials
                | secreton_domain::SecretonError::UserNotFound { .. }
                | secreton_domain::SecretonError::AccountDisabled { .. }
                | secreton_domain::SecretonError::AccountLocked { .. } => {
                    AuthError::InvalidCredentials
                }
                other => AuthError::Internal(anyhow::anyhow!("Auth failed: {}", other)),
            })?;

        if !result.success {
            // Increment failed_login_attempts and persist — mirrors the logic
            // in `login()` so that the lockout check at the top of this method
            // actually triggers after repeated failures.
            if let Some(ref mut u) = pre_auth_user {
                u.failed_login_attempts += 1;

                // Max attempts check (e.g. 5), but exempt privileged
                // users from auto-lockout (DoS protection).
                if !u.is_privileged() && u.failed_login_attempts >= 5 {
                    u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                    if let Some(audit) = &self.audit {
                        let _ = audit
                            .log_event(
                                crate::services::audit::SecurityEventType::AuthenticationFailure {
                                    user: credentials.username.clone(),
                                    method: "userpass".to_string(),
                                    reason: "Account locked due to too many failed attempts"
                                        .to_string(),
                                },
                            )
                            .await;
                    }
                }

                // Encrypt and update user in storage
                if let Ok(user_data) = serde_json::to_vec(&u)
                    && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
                    && let Some(mut entry) = pre_auth_entry.take()
                {
                    entry.encrypted_data = encrypted;
                    let _ = self.storage.store(&entry).await;
                }
            }

            return Err(AuthError::InvalidCredentials);
        }

        // Generate token explicitly if not part of AuthResult yet in this version,
        // or ensure AuthResult has what we need.
        // Logic in login() (line 175) generates tokens using self.token_service.
        // We should replicate that or use it.

        let user_info = result
            .user_info
            .as_ref()
            .ok_or(AuthError::Internal(anyhow::anyhow!("No user info")))?;

        let user_roles = &user_info.roles;

        // Use the user loaded at the start of the method for policies and
        // the MFA / counter-reset logic below.  Fall back to ["default"]
        // only when the user is not yet persisted (e.g. first login via
        // external auth).
        //
        // NOTE: The failed_login_attempts counter is reset AFTER MFA
        // enforcement (below) so that failed MFA attempts still count toward
        // the lockout threshold.  This matches the order used in `login()`.
        //
        // Capture the stored user's ID before moving pre_auth_user into
        // stored_user_entry.  This is used for MFA enforcement below so
        // that we always pass a real user ID to `enforce_mfa()` instead of
        // relying on `user_info.id` which may be `None` for external auth
        // methods.  A nil UUID would cause `is_mfa_required` to return
        // `false`, triggering the TOFU path and bypassing MFA for
        // privileged users.
        let stored_user_id: Option<String> = pre_auth_user.as_ref().map(|u| u.id.clone());
        let (policies, stored_user_entry) = match (pre_auth_user, pre_auth_entry) {
            (Some(u), Some(entry)) => (u.policies.clone(), Some((u, entry))),
            _ => (vec!["default".to_string()], None),
        };

        // Generate session ID
        let _session_id = Uuid::new_v4().to_string();

        // Get effective config for session timeout and MFA enforcement
        let (session_timeout_secs, global_mfa_enabled) = self.get_effective_config().await;

        // Enforce MFA for privileged users (admin/root) or if globally enabled.
        // Uses the shared `enforce_mfa()` helper so that `login()` and
        // `authenticate()` have identical enforcement logic.
        //
        // This MUST happen BEFORE resetting failed_login_attempts so that
        // failed MFA attempts still count toward the lockout threshold,
        // preventing unlimited MFA brute-force.
        let is_privileged =
            user_roles.contains(&"admin".to_string()) || user_roles.contains(&"root".to_string());

        // Prefer the user ID loaded from storage (which is always a valid
        // UUID) over `user_info.id` (which may be `None` for external auth
        // providers).  An empty/nil UUID would cause `enforce_mfa` to query
        // the MFA service for the nil UUID, get `mfa_configured = false`,
        // and take the TOFU path — silently bypassing MFA for privileged
        // users.
        let effective_user_id = stored_user_id
            .as_deref()
            .or(user_info.id.as_deref())
            .unwrap_or_default();

        if effective_user_id.is_empty() && is_privileged {
            // A privileged user with no resolvable user ID is a serious
            // configuration error — deny login rather than risk an MFA
            // bypass via the nil-UUID TOFU path.
            return Err(AuthError::Internal(anyhow::anyhow!(
                "Cannot enforce MFA: no valid user ID available for privileged user '{}'",
                credentials.username
            )));
        }

        let mfa_verified = match self
            .enforce_mfa(
                &credentials.username,
                effective_user_id,
                is_privileged,
                global_mfa_enabled,
                credentials.mfa_code,
            )
            .await
        {
            Ok(verified) => verified,
            Err(mfa_err) => {
                // Only count `InvalidMfaCode` toward lockout — see the
                // matching comment in `login()` for the full rationale.
                if matches!(mfa_err, AuthError::InvalidMfaCode)
                    && let Some((mut u, entry)) = stored_user_entry
                {
                    u.failed_login_attempts += 1;

                    if !u.is_privileged() && u.failed_login_attempts >= 5 {
                        u.locked_until = Some(chrono::Utc::now() + chrono::Duration::minutes(15));
                        if let Some(audit) = &self.audit {
                            let _ = audit
                                .log_event(
                                    crate::services::audit::SecurityEventType::AuthenticationFailure {
                                        user: credentials.username.clone(),
                                        method: "mfa".to_string(),
                                        reason: "Account locked due to too many failed attempts"
                                            .to_string(),
                                    },
                                )
                                .await;
                        }
                    }

                    // Persist the updated counter
                    if let Ok(user_data) = serde_json::to_vec(&u)
                        && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
                    {
                        let mut updated_entry = entry;
                        updated_entry.encrypted_data = encrypted;
                        let _ = self.storage.store(&updated_entry).await;
                    }
                }

                return Err(mfa_err);
            }
        };

        // Reset failed login attempts on success — mirrors the logic in
        // `login()` so that the counter does not accumulate across
        // successful logins, which would cause premature lockout on the
        // next failure.  This runs AFTER MFA enforcement so that a failed
        // MFA code does not reset the counter.
        if let Some((mut u, entry)) = stored_user_entry
            && (u.failed_login_attempts > 0 || u.locked_until.is_some())
        {
            u.failed_login_attempts = 0;
            u.locked_until = None;

            if let Ok(user_data) = serde_json::to_vec(&u)
                && let Ok(encrypted) = self.crypto.encrypt_data(&user_data).await
            {
                let mut updated_entry = entry;
                updated_entry.encrypted_data = encrypted;
                let _ = self.storage.store(&updated_entry).await;
            }
        }

        let session_duration =
            chrono::Duration::from_std(std::time::Duration::from_secs(session_timeout_secs))
                .unwrap_or(chrono::Duration::hours(1));

        // Generate tokens with session binding, using the dynamic timeout so
        // that the JWT `exp` claim stays in sync with the session `expires_at`.
        // Set mfa_required on the token when TOFU was used (user
        // authenticated without MFA but MFA was required), mirroring the
        // logic in `login()`.  Uses the same formula as `login()` —
        // `(is_privileged || global_mfa_enabled) && !mfa_verified`.
        // Previously this also OR'd in `result.mfa_required` from the underlying
        // auth service, but `login()` did not, creating an inconsistency.  Since
        // we pass `mfa_code: None` to `auth_service.login()` and handle MFA
        // entirely via `enforce_mfa()`, `result.mfa_required` is not meaningful
        // here and would only cause divergent behavior if the auth service
        // evolves to set it independently.
        let token_mfa_required = (is_privileged || global_mfa_enabled) && !mfa_verified;

        // Generate temporary session ID to bind it to the token up-front
        let temp_session_id = Uuid::new_v4().to_string();

        let token_pair = self
            .token_service
            .create_token_pair_with_duration(
                user_info.id.as_deref().unwrap_or_default(),
                &user_info.username,
                user_info.email.as_deref(),
                user_roles,
                &policies,
                token_mfa_required,
                Some(temp_session_id.clone()),
                Some(session_duration),
            )
            .map_err(|_| AuthError::Internal(anyhow::anyhow!("Token generation failed")))?;

        // Persist the session using the same ID bound to the token
        let _ = self
            .create_and_store_session(
                user_info.id.as_deref().unwrap_or_default(),
                temp_session_id,
                token_pair.access_token.clone(),
                Some(token_pair.refresh_token.clone()),
                ip_address,
                user_agent,
                session_timeout_secs,
            )
            .await?;

        let mut result_metadata = std::collections::HashMap::new();
        result_metadata.insert("expires_in".to_string(), token_pair.expires_in.to_string());

        Ok(AuthResult {
            success: true,
            token: Some(token_pair.access_token),
            refresh_token: Some(token_pair.refresh_token),
            user_info: result.user_info,
            policies,
            metadata: result_metadata,
            mfa_required: token_mfa_required,
        })
    }

    /// OAuth login - create or update user from OAuth info
    pub async fn oauth_login(&self, oauth_user: &OAuthUserInfo) -> Result<User, AuthError> {
        // Try to find existing user by OAuth ID or email
        // For now, create a stub user
        let user = User {
            id: oauth_user.id.clone(),
            username: if oauth_user.username.is_empty() {
                // Fall back to the email, then to the provider id, so a provider that
                // omits a username can still produce a usable account rather than one
                // with an empty primary identifier.
                if oauth_user.email.is_empty() {
                    oauth_user.id.clone()
                } else {
                    oauth_user.email.clone()
                }
            } else {
                oauth_user.username.clone()
            },
            email: (!oauth_user.email.is_empty()).then(|| oauth_user.email.clone()),
            display_name: (!oauth_user.name.is_empty()).then(|| oauth_user.name.clone()),
            disabled: false,
            password_hash: "".to_string(), // OAuth users don't have password
            password_login_disabled: false,
            full_name: (!oauth_user.name.is_empty()).then(|| oauth_user.name.clone()),
            is_active: true,
            is_superuser: false,
            roles: vec!["user".to_string()],
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: std::collections::HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::services::crypto::CryptoService;
    // use secreton_crypto::SecurityParams;
    use crate::services::mfa_persistence::PersistentTotpService;
    use secreton_auth::mfa::{
        CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
        EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    };
    use secreton_storage::StorageResult;
    use secreton_storage::backends::MemoryBackend;

    #[tokio::test]
    async fn test_auth_service_creation() {
        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let auth_service = AuthenticationService::new(storage, crypto, &config).await;
        assert!(auth_service.is_ok());
    }

    /// A user absent from the capped startup hydration must still authenticate: the login
    /// path re-publishes the durable record, so the `USER_LOAD_MAX_ENTRIES` scan cannot
    /// exclude a valid account from password verification.
    #[tokio::test]
    async fn a_user_omitted_by_startup_hydration_can_still_authenticate() {
        use secreton_storage::{EncryptionMetadata, SecurityLevel};
        use uuid::Uuid;

        let (storage, service, _root_key) = auth_with_open_barrier().await;

        // Hash a password and persist a user record directly, without going through
        // `register_user` — that would publish the in-memory identity and mask the bug.
        let password = crate::test_support::generated_password();
        let password_hash = service
            .userpass_method
            .hash_password(&password)
            .expect("hash");
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: "beyond-the-cap".to_string(),
            email: None,
            password_hash,
            password_login_disabled: false,
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: vec!["user".to_string()],
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };
        let path = format!("{}{}", USER_STORAGE_PREFIX, user.username);
        let encrypted = service
            .crypto
            .encrypt_data(&serde_json::to_vec(&user).unwrap())
            .await
            .unwrap();
        let entry = SecretEntry::new(
            path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        storage.store(&entry).await.unwrap();

        // The service was constructed before the account existed, so its startup hydration
        // never saw it — exactly the state of an account beyond `USER_LOAD_MAX_ENTRIES` on a
        // fresh process. The durable record is readable by path but absent from the in-memory
        // password map. Without on-demand hydration the password cannot be verified.
        let result = service
            .authenticate(
                crate::services::auth::LoginRequest {
                    username: user.username.clone(),
                    password: password.to_string(),
                    mfa_code: None,
                    remember_me: Some(false),
                },
                "127.0.0.1".to_string(),
                "test".to_string(),
            )
            .await;
        assert!(
            result.is_ok(),
            "a stored account absent from the in-memory map must still authenticate: {result:?}"
        );
    }

    /// `verify_password` backs re-authentication (for example before disabling MFA), so an
    /// account beyond the capped startup hydration must pass it too. Otherwise the account
    /// can sign in but cannot re-authenticate for a sensitive change.
    #[tokio::test]
    async fn verify_password_accepts_an_account_absent_from_startup_hydration() {
        use secreton_storage::{EncryptionMetadata, SecurityLevel};
        use uuid::Uuid;

        let (storage, service, _root_key) = auth_with_open_barrier().await;

        let password = crate::test_support::generated_password();
        let wrong_password = crate::test_support::generated_password();
        let password_hash = service
            .userpass_method
            .hash_password(&password)
            .expect("hash");
        let user = User {
            id: Uuid::new_v4().to_string(),
            username: "beyond-the-cap-verify".to_string(),
            email: None,
            password_hash,
            password_login_disabled: false,
            full_name: None,
            is_active: true,
            is_superuser: false,
            roles: vec!["user".to_string()],
            permissions: vec![],
            policies: vec!["default".to_string()],
            enabled: true,
            disabled: false,
            display_name: None,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            failed_login_attempts: 0,
            locked_until: None,
        };
        let path = format!("{}{}", USER_STORAGE_PREFIX, user.username);
        let encrypted = service
            .crypto
            .encrypt_data(&serde_json::to_vec(&user).unwrap())
            .await
            .unwrap();
        storage
            .store(&SecretEntry::new(
                path,
                encrypted,
                EncryptionMetadata::default(),
                SecurityLevel::Secret,
                Uuid::new_v4(),
            ))
            .await
            .unwrap();

        assert!(
            service
                .verify_password(&user.username, &password)
                .await
                .expect("verify"),
            "a stored account absent from the in-memory map must still verify its password"
        );
        assert!(
            !service
                .verify_password(&user.username, &wrong_password)
                .await
                .expect("verify"),
            "a wrong password must still be rejected"
        );
    }

    #[tokio::test]
    async fn test_cleanup_expired_sessions() {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};
        use uuid::Uuid;

        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config)
            .await
            .unwrap();

        // Add expired session
        let expired_session = SecretEntry::new(
            "sys/auth/sessions/expired1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&expired_session).await.unwrap();

        // Add active session
        let active_session = SecretEntry::new(
            "sys/auth/sessions/active1".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() + chrono::Duration::hours(1));
        storage.store(&active_session).await.unwrap();

        // Add unrelated expired entry
        let unrelated_expired = SecretEntry::new(
            "other/path/expired2".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::new_v4(),
        )
        .with_expiration(chrono::Utc::now() - chrono::Duration::hours(1));
        storage.store(&unrelated_expired).await.unwrap();

        // Run cleanup
        let cleaned_count = auth_service.cleanup_expired_sessions().await.unwrap();

        // Verify results
        assert_eq!(cleaned_count, 1, "Should cleanup exactly 1 session");

        // Check storage state
        assert!(
            !storage.exists("sys/auth/sessions/expired1").await.unwrap(),
            "Expired session should be removed"
        );
        assert!(
            storage.exists("sys/auth/sessions/active1").await.unwrap(),
            "Active session should remain"
        );
        assert!(
            storage.exists("other/path/expired2").await.unwrap(),
            "Unrelated expired entry should remain"
        );
    }

    #[tokio::test]
    async fn cleanup_reclaims_expired_refresh_reservations() {
        // Regression: a refresh reservation is deliberately left in place after a
        // successful exchange, so *every* refresh wrote one and nothing ever removed it.
        // `cleanup_expired_sessions` swept the session and revocation prefixes only, so on
        // any backend that persists reservations the prefix grew without bound. The
        // reservation carries the refresh token's own `exp`, which makes it reclaimable
        // once that passes — the sweep just had to ask for the prefix.
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};
        use uuid::Uuid;

        let storage = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let auth_service = AuthenticationService::new(storage.clone(), crypto, &config)
            .await
            .unwrap();

        let reservation = |suffix: &str, expires: chrono::DateTime<chrono::Utc>| {
            SecretEntry::new(
                format!("{}{}", REFRESH_RESERVATION_STORAGE_PREFIX, suffix),
                vec![],
                EncryptionMetadata::default(),
                SecurityLevel::Internal,
                Uuid::new_v4(),
            )
            .with_expiration(expires)
        };

        let expired = format!("{}{}", REFRESH_RESERVATION_STORAGE_PREFIX, "expired");
        let live = format!("{}{}", REFRESH_RESERVATION_STORAGE_PREFIX, "live");
        storage
            .store(&reservation(
                "expired",
                chrono::Utc::now() - chrono::Duration::hours(1),
            ))
            .await
            .unwrap();
        storage
            .store(&reservation(
                "live",
                chrono::Utc::now() + chrono::Duration::hours(1),
            ))
            .await
            .unwrap();

        auth_service
            .cleanup_expired_sessions()
            .await
            .expect("cleanup runs");

        assert!(
            !storage.exists(&expired).await.unwrap(),
            "an expired refresh reservation must be reclaimed by session cleanup"
        );
        assert!(
            storage.exists(&live).await.unwrap(),
            "a reservation whose refresh token is still live must be kept"
        );
    }

    #[tokio::test]
    async fn test_get_user_count() {
        use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel};

        let storage = Arc::new(MemoryBackend::new());

        // Add some dummy users
        let user1 = SecretEntry::new(
            format!("{}user1", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let user2 = SecretEntry::new(
            format!("{}user2", USER_STORAGE_PREFIX),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let other = SecretEntry::new(
            "secrets/something".to_string(),
            vec![],
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        storage.store(&user1).await.unwrap();
        storage.store(&user2).await.unwrap();
        storage.store(&other).await.unwrap();

        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        let auth_service = AuthenticationService::new(storage, crypto, &config)
            .await
            .unwrap();

        let count = auth_service.get_user_count().await.unwrap();
        assert_eq!(count, 2);
    }

    /// Build a service graph with the root key installed, so a test can create the
    /// bootstrap root account and then attempt to log in as it. Returns the root key
    /// bytes too, so a test can rebuild the service over the same storage (a restart)
    /// without invalidating the records it wrote.
    async fn auth_with_open_barrier() -> (
        Arc<dyn StorageBackend + Send + Sync>,
        Arc<AuthenticationService>,
        Vec<u8>,
    ) {
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(MemoryBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let root_key = secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm)
            .expect("root key");
        crypto
            .set_root_key(root_key.clone())
            .await
            .expect("install root key");

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();

        let mfa = Arc::new(CombinedMfaService::new(
            Arc::new(PersistentTotpService::new(
                storage.clone(),
                crypto.clone(),
                "secreton-test".to_string(),
            )),
            Arc::new(InMemorySmsService::new(SmsConfig::default())),
            Arc::new(InMemoryEmailService::new(EmailConfig::default())),
            Arc::new(InMemoryHardwareService::new()),
            Arc::new(DefaultPushService::new_mock()),
            Arc::new(DefaultWebAuthnService::new_default()),
            Arc::new(DefaultRecoveryCodeService::new()),
        ));

        let service = Arc::new(
            AuthenticationService::new(storage.clone(), crypto, &config)
                .await
                .unwrap()
                .with_mfa(mfa),
        );
        (storage, service, root_key)
    }

    /// A backend that fails the *next* `store` of a session record, so a test can prove a
    /// failure after a refresh token is reserved does not permanently consume it.
    #[derive(Debug)]
    struct FailingSessionStore {
        inner: MemoryBackend,
        armed: std::sync::atomic::AtomicBool,
        fired: std::sync::atomic::AtomicBool,
    }

    impl FailingSessionStore {
        fn new() -> Self {
            Self {
                inner: MemoryBackend::new(),
                armed: std::sync::atomic::AtomicBool::new(false),
                fired: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for FailingSessionStore {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            if self.armed.load(std::sync::atomic::Ordering::SeqCst)
                && entry.path.starts_with(SESSION_STORAGE_PREFIX)
            {
                self.armed.store(false, std::sync::atomic::Ordering::SeqCst);
                self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(secreton_storage::StorageError::BackendError {
                    backend: "fault-injected".to_string(),
                    message: "injected session store failure".to_string(),
                });
            }
            self.inner.store(entry).await
        }
        /// `register_user` now writes the account with `compare_and_set(Absent)`; forward it
        /// to the inner memory backend so this fault-injection wrapper stays transparent for
        /// everything it does not deliberately intercept.
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            self.inner.compare_and_set(entry, expect).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
    }

    /// A backend that wraps another and holds the first two `compare_and_set` calls at the
    /// refresh-reservation path until *both* have arrived.
    ///
    /// Without the rendezvous the race in this area is not deterministic: the first
    /// replica can finish its whole exchange — including the durable revocation — before
    /// the second even reads the token, so the second is rejected by the revocation rather
    /// than by the reservation, and the test passes whether or not the reservation is
    /// authoritative. Parking both attempts at the claim point forces the interleaving the
    /// property is about: both have passed the fast-path check, and only the shared
    /// insert-if-absent can decide the winner.
    #[derive(Debug)]
    struct ReservationRendezvousBackend {
        inner: secreton_storage::FileBackend,
        arrived: tokio::sync::Barrier,
    }

    impl ReservationRendezvousBackend {
        fn new(inner: secreton_storage::FileBackend) -> Self {
            Self {
                inner,
                arrived: tokio::sync::Barrier::new(2),
            }
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for ReservationRendezvousBackend {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            self.inner.delete_by_path(path).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            if entry.path.starts_with(REFRESH_RESERVATION_STORAGE_PREFIX)
                && expect == secreton_storage::Expect::Absent
            {
                self.arrived.wait().await;
            }
            self.inner.compare_and_set(entry, expect).await
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            self.inner.delete_owned(path, token).await
        }
        async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
        fn coordination(&self) -> secreton_storage::Coordination {
            self.inner.coordination()
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
    }

    /// A cross-process backend that fails the *first* reservation claim once, modelling a
    /// brief storage outage at the moment a refresh is being exchanged.
    #[derive(Debug)]
    struct FailingReservationBackend {
        inner: secreton_storage::FileBackend,
        armed: std::sync::atomic::AtomicBool,
        fired: std::sync::atomic::AtomicBool,
        /// When set, the next owner-conditional delete reports `Unsupported`, as a backend
        /// that coordinates across processes but cannot delete conditionally would. Used to
        /// prove the reservation refund is verified rather than trusted.
        fail_next_delete_owned: std::sync::atomic::AtomicBool,
        /// Counts `delete_by_path` calls on a refresh-reservation path. The release must
        /// never remove a reservation by path — that is the read-then-delete fallback which
        /// can destroy another attempt's slot — so a non-zero count is the defect.
        unconditional_reservation_deletes: std::sync::atomic::AtomicU64,
        /// When planted, the next `get_by_path` for this path returns the planted (stale)
        /// record instead of the live one. This models the TOCTOU window the rejected
        /// fallback opened: a release reads the record, sees *its own* owner token, and is
        /// preempted before the delete — in that window another replica takes the slot, and
        /// the unconditional delete then destroys the new owner's reservation. The stale
        /// read is what lets a test reproduce that interleaving deterministically instead of
        /// hoping for the scheduling.
        stale_readback: std::sync::Mutex<Option<(String, SecretEntry)>>,
    }

    impl FailingReservationBackend {
        fn new(inner: secreton_storage::FileBackend) -> Self {
            Self {
                inner,
                armed: std::sync::atomic::AtomicBool::new(false),
                fired: std::sync::atomic::AtomicBool::new(false),
                fail_next_delete_owned: std::sync::atomic::AtomicBool::new(false),
                unconditional_reservation_deletes: std::sync::atomic::AtomicU64::new(0),
                stale_readback: std::sync::Mutex::new(None),
            }
        }

        fn unconditional_reservation_deletes(&self) -> u64 {
            self.unconditional_reservation_deletes
                .load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Make the next read of `path` report `entry`, as a replica that read before
        /// another attempt took the slot would have seen.
        fn plant_stale_readback(&self, path: &str, entry: SecretEntry) {
            *self.stale_readback.lock().expect("stale readback lock") =
                Some((path.to_string(), entry));
        }
    }

    #[async_trait::async_trait]
    impl StorageBackend for FailingReservationBackend {
        async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.store(entry).await
        }
        async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
            self.inner.get_by_id(id).await
        }
        async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
            if let Some((stale_path, entry)) = self
                .stale_readback
                .lock()
                .expect("stale readback lock")
                .take()
                && stale_path == path
            {
                return Ok(Some(entry));
            }
            self.inner.get_by_path(path).await
        }
        async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.update(entry).await
        }
        async fn upsert(&self, entry: &SecretEntry) -> StorageResult<()> {
            self.inner.upsert(entry).await
        }
        async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
            self.inner.delete_by_id(id).await
        }
        async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
            if path.starts_with(REFRESH_RESERVATION_STORAGE_PREFIX) {
                self.unconditional_reservation_deletes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.inner.delete_by_path(path).await
        }
        async fn compare_and_set(
            &self,
            entry: &SecretEntry,
            expect: secreton_storage::Expect<'_>,
        ) -> StorageResult<bool> {
            if entry.path.starts_with(REFRESH_RESERVATION_STORAGE_PREFIX)
                && expect == secreton_storage::Expect::Absent
                && self.armed.load(std::sync::atomic::Ordering::SeqCst)
            {
                self.armed.store(false, std::sync::atomic::Ordering::SeqCst);
                self.fired.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(secreton_storage::StorageError::ConnectionFailed {
                    message: "injected reservation write failure".to_string(),
                });
            }
            self.inner.compare_and_set(entry, expect).await
        }
        async fn delete_owned(&self, path: &str, token: &str) -> StorageResult<bool> {
            if self
                .fail_next_delete_owned
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(secreton_storage::StorageError::Unsupported {
                    operation: "delete_owned".to_string(),
                    backend: "fault-injected".to_string(),
                });
            }
            self.inner.delete_owned(path, token).await
        }
        async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
            self.inner.list(params).await
        }
        async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
            self.inner.count(params).await
        }
        async fn exists(&self, path: &str) -> StorageResult<bool> {
            self.inner.exists(path).await
        }
        async fn begin_transaction(
            &self,
        ) -> StorageResult<Box<dyn secreton_storage::StorageTransaction>> {
            self.inner.begin_transaction().await
        }
        async fn store_oauth_state(
            &self,
            state: &secreton_domain::OAuthState,
        ) -> StorageResult<()> {
            self.inner.store_oauth_state(state).await
        }
        async fn get_oauth_state(
            &self,
            state: &str,
        ) -> StorageResult<Option<secreton_domain::OAuthState>> {
            self.inner.get_oauth_state(state).await
        }
        async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
            self.inner.delete_expired_oauth_states().await
        }
        fn coordination(&self) -> secreton_storage::Coordination {
            secreton_storage::Coordination::CrossProcess
        }
        async fn health_check(&self) -> StorageResult<secreton_storage::HealthStatus> {
            self.inner.health_check().await
        }
        async fn get_stats(&self) -> StorageResult<secreton_storage::StorageStats> {
            self.inner.get_stats().await
        }
        async fn migrate(&self) -> StorageResult<()> {
            self.inner.migrate().await
        }
    }

    /// A service over a caller-supplied backend, with the root key installed so record
    /// encryption works — the same graph [`auth_with_open_barrier`] builds.
    async fn auth_with_storage(
        storage: Arc<dyn StorageBackend + Send + Sync>,
    ) -> Arc<AuthenticationService> {
        let root_key = secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm)
            .expect("root key");
        auth_with_storage_and_root_key(storage, root_key).await
    }

    /// The same graph, with a caller-supplied root key.
    ///
    /// Two service instances that share a backend must share the key that encrypts the
    /// system's own records, or one cannot read what the other wrote. A caller that wants
    /// two cooperating replicas uses this and passes the one key to both.
    async fn auth_with_storage_and_root_key(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        root_key: Vec<u8>,
    ) -> Arc<AuthenticationService> {
        auth_with_storage_root_key_and_refresh_ttl(storage, root_key, 86400 * 7).await
    }

    /// The same graph, with an explicit refresh-token lifetime so a test can exercise a
    /// deployment whose `auth.jwt.refresh_expiration` differs from the default.
    async fn auth_with_storage_root_key_and_refresh_ttl(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        root_key: Vec<u8>,
        refresh_expiration_secs: u64,
    ) -> Arc<AuthenticationService> {
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        crypto
            .set_root_key(root_key)
            .await
            .expect("install root key");

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        config.jwt.issuer = "secreton".to_string();
        config.jwt.audience = "secreton-api".to_string();
        config.jwt.refresh_expiration = refresh_expiration_secs;

        let mfa = Arc::new(CombinedMfaService::new(
            Arc::new(PersistentTotpService::new(
                storage.clone(),
                crypto.clone(),
                "secreton-test".to_string(),
            )),
            Arc::new(InMemorySmsService::new(SmsConfig::default())),
            Arc::new(InMemoryEmailService::new(EmailConfig::default())),
            Arc::new(InMemoryHardwareService::new()),
            Arc::new(DefaultPushService::new_mock()),
            Arc::new(DefaultWebAuthnService::new_default()),
            Arc::new(DefaultRecoveryCodeService::new()),
        ));

        Arc::new(
            AuthenticationService::new(storage, crypto, &config)
                .await
                .unwrap()
                .with_mfa(mfa),
        )
    }

    #[tokio::test]
    async fn a_failed_session_write_does_not_consume_the_refresh_token() {
        // Regression: `refresh_token` blacklisted the old refresh token *before* doing the
        // fallible work — loading the user, minting the pair, storing the new session. A
        // storage fault after that point returned an error while the old token was already
        // revoked, so the caller held no new token and could never retry with the old one:
        // a transient fault logged them out permanently.
        //
        // The property: after a failed exchange the same refresh token still works once,
        // and once it has been exchanged successfully, replaying it is still refused.
        let _env = crate::test_support::without_root_key();
        let storage = Arc::new(FailingSessionStore::new());
        let storage_dyn: Arc<dyn StorageBackend + Send + Sync> = storage.clone();
        let service = auth_with_storage(storage_dyn).await;

        let password = crate::test_support::generated_password();
        service
            .register_user(
                "refresh-user",
                &password,
                None,
                vec!["user".to_string()],
                vec![],
            )
            .await
            .expect("register user");

        let login = service
            .login(
                ApiLoginRequest {
                    username: "refresh-user".to_string(),
                    password,
                    mfa_code: None,
                },
                "192.0.2.1".to_string(),
                "test".to_string(),
            )
            .await
            .expect("login");
        let refresh = login.token.refresh_token.clone();

        // Inject a storage fault on the next session write, which is exactly the step after
        // the old token is reserved.
        storage
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let failed = service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await;
        assert!(
            failed.is_err(),
            "the injected storage failure must surface to the caller"
        );
        assert!(
            storage.fired.load(std::sync::atomic::Ordering::SeqCst),
            "the session-write fault must actually have fired, or this test proves nothing"
        );

        // The retry with the same refresh token must succeed — the failed attempt released
        // its reservation rather than consuming the token.
        let exchanged = service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await
            .expect("the retry must succeed with the same refresh token");
        assert!(!exchanged.access_token.is_empty());

        // And now that the exchange committed, replaying the old token is refused: releasing
        // the reservation on failure must not weaken reuse detection after success.
        let replay = service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await;
        assert!(
            replay.is_err(),
            "a refresh token exchanged successfully must not be replayable"
        );
    }

    #[tokio::test]
    async fn two_instances_sharing_a_backend_admit_exactly_one_refresh_exchange() {
        // Regression (CWE-362): the single-use refresh reservation lived only in the
        // in-memory `token_blacklist`. Two replicas sharing PostgreSQL, Redis or a file
        // directory each have their own map, so both passed the check and both inserted,
        // and the same refresh token was exchanged twice, issuing two token pairs.
        //
        // The property: with the reservation taken in the backend the two replicas share,
        // exactly one exchange succeeds and the other observes "already used".
        let _env = crate::test_support::without_root_key();

        // A file backend reports `Coordination::CrossProcess` and really implements
        // `compare_and_set`, so the reservation is arbitrated between the two service
        // instances exactly as it would be between two server processes. The wrapper parks
        // both claim attempts at the reservation point, so the race is forced rather than
        // hoped for — otherwise the first replica can finish its whole exchange (including
        // the durable revocation) before the second reads the token, and the test would pass
        // even without the shared reservation.
        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let storage: Arc<dyn StorageBackend + Send + Sync> =
            Arc::new(ReservationRendezvousBackend::new(file_storage));
        assert_eq!(
            storage.coordination(),
            secreton_storage::Coordination::CrossProcess,
            "this test is only meaningful on a backend that arbitrates across instances"
        );

        // Two independent service graphs — two "replicas" — over the one backend, sharing
        // the root key that encrypts the system's own records. Sharing the key is what a
        // real multi-replica deployment does (all replicas unseal with the same vault), and
        // it is what lets either read the user the other registered.
        let shared_root_key =
            secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm)
                .expect("root key");
        let replica_a =
            auth_with_storage_and_root_key(storage.clone(), shared_root_key.clone()).await;
        let replica_b = auth_with_storage_and_root_key(storage.clone(), shared_root_key).await;

        let password = crate::test_support::generated_password();
        replica_a
            .register_user(
                "shared-user",
                &password,
                None,
                vec!["user".to_string()],
                vec![],
            )
            .await
            .expect("register user");

        // Sign in through replica A, which registered the account. The point of this test
        // is the reservation race, not cross-replica login caching.
        let login = replica_a
            .login(
                ApiLoginRequest {
                    username: "shared-user".to_string(),
                    password,
                    mfa_code: None,
                },
                "192.0.2.1".to_string(),
                "test".to_string(),
            )
            .await
            .expect("login");
        let refresh = login.token.refresh_token.clone();

        // Both replicas claim the reservation for the same refresh token at once. The claim
        // is the single-use gate; asserting on it directly — rather than on the whole
        // exchange — is what makes this test falsifiable. Reverting the shared reservation
        // to the per-process map does not make two *exchanges* both succeed here, because a
        // second defense (the session-binding check that follows the rotation) would still
        // reject the loser; it makes two *claims* both succeed, which is the race. Both
        // claims are parked at the rendezvous point above until both have arrived, so the
        // loser's `None` can only come from the shared insert-if-absent.
        let expiry = chrono::Utc::now() + chrono::Duration::days(8);
        let (claim_a, claim_b) = tokio::join!(
            replica_a.reserve_refresh_token(&refresh, expiry),
            replica_b.reserve_refresh_token(&refresh, expiry),
        );
        let winners = [claim_a.as_ref(), claim_b.as_ref()]
            .iter()
            .filter(|claim| matches!(claim, Ok(Some(_))))
            .count();
        assert_eq!(
            winners, 1,
            "exactly one replica may hold the single-use reservation; got a={claim_a:?} b={claim_b:?}",
        );
    }

    #[tokio::test]
    async fn a_failed_conditional_release_never_deletes_another_attempts_reservation() {
        // Regression (Finding 2): `release_refresh_token_reservation` read the record's owner
        // and then called an *unconditional* `delete_by_path`. A second replica can take the
        // slot between those two calls, and the unconditional delete then removes *its*
        // reservation — letting the same refresh token be exchanged twice, which is exactly
        // what the single-use reservation exists to prevent. The fix removes the
        // read-then-delete fallback entirely: only `delete_owned` may remove a reservation,
        // and a failed release leaves the record in place (it lapses on its own via the short
        // claim TTL; see `a_reservation_whose_release_failed_is_usable_again_after_the_claim_ttl`).
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let backend = Arc::new(FailingReservationBackend::new(file_storage));
        let storage: Arc<dyn StorageBackend + Send + Sync> = backend.clone();
        let service = auth_with_storage(storage).await;

        let expiry = chrono::Utc::now() + chrono::Duration::days(8);
        let token = "release-me-refresh-token";
        let owner = service
            .reserve_refresh_token(token, expiry)
            .await
            .expect("reserve")
            .expect("the first claim wins");

        // The owner-conditional delete is unavailable on this backend, exactly as it is on a
        // backend that reports `CrossProcess` without implementing conditional deletion.
        backend
            .fail_next_delete_owned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        service
            .release_refresh_token_reservation(token, &owner)
            .await;

        let path = AuthenticationService::refresh_reservation_path(token);
        assert!(
            service
                .storage
                .get_by_path(&path)
                .await
                .expect("read reservation")
                .is_some(),
            "a failed conditional release must not fall back to an unconditional delete; the \
             record is left to lapse rather than risk destroying another attempt's reservation"
        );
        assert_eq!(
            backend.unconditional_reservation_deletes(),
            0,
            "the release must never delete a reservation by path: that read-then-delete \
             fallback can remove a slot another attempt took in between, letting the same \
             refresh token be exchanged twice"
        );

        // The token is still blocked while the (now unowned) claim is live, which is the
        // correct fail-closed behaviour — the slot is not silently freed by an unconditional
        // delete.
        assert!(
            service
                .reserve_refresh_token(token, expiry)
                .await
                .expect("re-claim while the claim is live")
                .is_none(),
            "a live claim must keep the token single-use even after a failed release"
        );
    }

    impl AuthenticationService {
        /// Test-only: force the short refresh-claim window, so a test can drive a claim past
        /// its deadline without sleeping for the production two minutes.
        fn force_short_claim_ttl(&self) {
            self.refresh_claim_ttl_override
                .store(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_reservation_whose_release_failed_is_usable_again_after_the_claim_ttl() {
        // Regression (Finding 3): when the durable release failed, the reservation occupied
        // the slot for the refresh token's whole (potentially multi-day) lifetime, so a retry
        // after storage recovered was refused by the insert-if-absent until `delete_expired`
        // swept the record. The claim is now taken with a short TTL
        // (`REFRESH_CLAIM_TTL_SECS`) and extended to the token's `exp` only once an exchange
        // succeeds, so an orphaned claim lapses and the token is claimable again.
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let backend = Arc::new(FailingReservationBackend::new(file_storage));
        let storage: Arc<dyn StorageBackend + Send + Sync> = backend.clone();
        // A one-second claim window stands in for the production two minutes.
        let service = auth_with_storage(storage).await;
        service.force_short_claim_ttl();

        // The token's own expiry is far in the future, so only the claim TTL can free it.
        let expiry = chrono::Utc::now() + chrono::Duration::days(8);
        let token = "orphaned-claim-refresh-token";
        let owner = service
            .reserve_refresh_token(token, expiry)
            .await
            .expect("reserve")
            .expect("the first claim wins");

        // The release fails (storage is down / the backend cannot delete conditionally), so
        // the durable claim is left behind — an orphan occupying the slot.
        backend
            .fail_next_delete_owned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        service
            .release_refresh_token_reservation(token, &owner)
            .await;

        // While the orphaned claim is live the token is single-use.
        assert!(
            service
                .reserve_refresh_token(token, expiry)
                .await
                .expect("re-claim while the orphan is live")
                .is_none(),
            "an orphaned claim must keep the token single-use while it is within its window"
        );

        // Past the claim window the orphan lapses, and a retry must succeed rather than being
        // locked out until the token's own expiry.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            service
                .reserve_refresh_token(token, expiry)
                .await
                .expect("re-claim after the orphan lapsed")
                .is_some(),
            "a claim whose release failed must not lock the refresh token out past its claim TTL"
        );
    }

    #[tokio::test]
    async fn a_stale_release_never_removes_a_new_owners_reservation() {
        // Regression (Finding 2/3), the interleaving the fallback opened: owner A claims the
        // token with a short window, its claim lapses, owner B takes the slot, and only then
        // does A run a release that fails. A's release must not delete B's reservation — the
        // record must still exist and still be owned by B — or the same token could be
        // exchanged twice.
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let backend = Arc::new(FailingReservationBackend::new(file_storage));
        let storage: Arc<dyn StorageBackend + Send + Sync> = backend.clone();
        let service = auth_with_storage(storage).await;
        service.force_short_claim_ttl();

        let expiry = chrono::Utc::now() + chrono::Duration::days(8);
        let token = "stale-release-refresh-token";
        let owner_a = service
            .reserve_refresh_token(token, expiry)
            .await
            .expect("reserve")
            .expect("A claims the token");
        let path = AuthenticationService::refresh_reservation_path(token);

        // A's claim lapses; B takes the now-free slot.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let owner_b = service
            .reserve_refresh_token(token, expiry)
            .await
            .expect("B re-claims the lapsed slot")
            .expect("B wins the freed slot");
        assert_ne!(owner_a, owner_b, "B must hold a fresh owner token");

        // Reproduce the interleaving the fallback opens: A's release reads the record and is
        // preempted *before* its delete, and in that window B takes the slot. The stale
        // readback hands A the record as it looked while A still owned it, so the fallback's
        // ownership check passes and its unconditional delete then removes B's live slot.
        // Without the stale read, the readback would simply observe B's record and the
        // fallback would (correctly) decline; the defect only bites in the window.
        let stale_a_record = SecretEntry::new(
            path.clone(),
            Vec::new(),
            EncryptionMetadata::default(),
            SecurityLevel::Internal,
            Uuid::nil(),
        )
        .owned_by(&owner_a)
        .with_expiration(chrono::Utc::now() - chrono::Duration::seconds(1));
        backend.plant_stale_readback(&path, stale_a_record);

        // A's release runs late and its conditional delete fails. It must be a no-op against
        // B's record.
        backend
            .fail_next_delete_owned
            .store(true, std::sync::atomic::Ordering::SeqCst);
        service
            .release_refresh_token_reservation(token, &owner_a)
            .await;

        // Read ground truth through the inner backend: the injected stale readback models the
        // read the *fallback* performs, and the fixed release performs none, so reading back
        // through the wrapper would consume the injection and misreport B's live slot.
        let record = backend
            .inner
            .get_by_path(&path)
            .await
            .expect("read reservation")
            .expect("B's reservation must survive A's stale release");
        assert!(
            record.has_owner(&owner_b),
            "the surviving reservation must still belong to B, not A"
        );
        assert_eq!(
            backend.unconditional_reservation_deletes(),
            0,
            "a release must never remove a reservation by path — that read-then-delete \
             fallback is exactly what lets a stale release destroy another attempt's slot"
        );
    }

    #[tokio::test]
    async fn a_reclaimed_reservation_still_honors_a_live_durable_revocation() {
        // Regression (Auth Bypass): `reserve_refresh_token` reclaimed a lapsed reservation by
        // deleting the expired record and re-claiming the slot, without ever consulting the
        // durable *revocation* a completed rotation had written at a different path. A replay
        // whose early `is_token_revoked` check missed — another replica, or a storage read that
        // failed open — therefore obtained a second session for an already-exchanged token once
        // its short claim window elapsed. The property: a lapsed reservation is not reclaimable
        // while a live revocation for the same token exists.
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let backend = Arc::new(FailingReservationBackend::new(file_storage));
        let storage: Arc<dyn StorageBackend + Send + Sync> = backend.clone();
        let service = auth_with_storage(storage).await;
        // A one-second claim window stands in for the production two minutes.
        service.force_short_claim_ttl();

        let expiry = chrono::Utc::now() + chrono::Duration::days(8);
        let token = "revoked-but-reclaimable-refresh-token";
        service
            .reserve_refresh_token(token, expiry)
            .await
            .expect("reserve")
            .expect("the first claim wins");

        // A completed rotation writes the durable revocation and leaves the reservation, with
        // its short claim window, to lapse.
        service.revoke_token(token.to_string(), expiry).await;

        // Clear the in-memory fast path, modelling a different replica (or an instance that
        // never saw the revocation) whose only record of the revocation is durable storage.
        {
            let mut blacklist = service.token_blacklist.write().await;
            blacklist.remove(token);
        }

        // Let the claim lapse, then attempt to reclaim it. The durable revocation must win.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            service
                .reserve_refresh_token(token, expiry)
                .await
                .expect("re-claim a lapsed but revoked reservation")
                .is_none(),
            "a live durable revocation must refuse the reclaimed slot, \
             or a replay of an exchanged token is issued a second session"
        );

        // Guard the other direction: a token with no durable revocation is still reclaimable
        // after its claim lapses, so the check did not simply disable reclaiming altogether.
        let fresh_token = "unrevoked-reclaimable-refresh-token";
        let _first = service
            .reserve_refresh_token(fresh_token, expiry)
            .await
            .expect("first reserve")
            .expect("the first claim wins");
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        assert!(
            service
                .reserve_refresh_token(fresh_token, expiry)
                .await
                .expect("re-claim an unrevoked lapsed reservation")
                .is_some(),
            "a lapsed reservation with no durable revocation must remain reclaimable"
        );
    }

    #[tokio::test]
    async fn a_transient_reservation_failure_does_not_consume_the_refresh_token() {
        // Regression: when the shared reservation write failed, `reserve_refresh_token`
        // returned the error but left the in-memory slot it had just inserted. The next
        // request for the same token hit that slot and returned `InvalidToken` without ever
        // retrying the backend, so a brief Redis/PostgreSQL blip during a refresh logged the
        // user out for the whole reservation lifetime even after storage recovered. The
        // error path must undo the local slot exactly as the `Ok(false)` path does.
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let backend = Arc::new(FailingReservationBackend::new(file_storage));
        let storage: Arc<dyn StorageBackend + Send + Sync> = backend.clone();
        let service = auth_with_storage(storage).await;

        let password = crate::test_support::generated_password();
        service
            .register_user("reservation-user", &password, None, vec![], vec![])
            .await
            .expect("register user");
        let login = service
            .login(
                ApiLoginRequest {
                    username: "reservation-user".to_string(),
                    password,
                    mfa_code: None,
                },
                "192.0.2.1".to_string(),
                "test".to_string(),
            )
            .await
            .expect("login");
        let refresh = login.token.refresh_token.clone();

        // The next reservation claim fails once, standing in for a storage outage.
        backend
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let failed = service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await;
        assert!(
            failed.is_err(),
            "the injected storage failure must surface to the caller"
        );
        assert!(
            backend.fired.load(std::sync::atomic::Ordering::SeqCst),
            "the reservation fault must actually have fired, or this test proves nothing"
        );

        // Storage has recovered; the same refresh token must still be exchangeable. Before
        // the fix the local slot was left behind and this returned `InvalidToken`.
        let exchanged = service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await
            .expect("a retry after a transient reservation failure must succeed");
        assert!(!exchanged.access_token.is_empty());

        // Reuse detection still holds: the exchanged token is now revoked.
        assert!(
            service
                .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
                .await
                .is_err(),
            "a successfully exchanged refresh token must not be replayable"
        );
    }

    #[tokio::test]
    async fn a_refresh_token_outlives_its_reservation_only_until_its_own_expiry() {
        // Regression (CWE-613): the reservation and the revocation were pinned to a fixed
        // eight days. When `auth.jwt.refresh_expiration` was configured longer, the token
        // outlived both guards, and a replay after eight days won the insert-if-absent race
        // and was issued a fresh session. The guard is now derived from the token's own
        // `exp`, so it lasts as long as the token remains valid and no longer.
        //
        // The deployment here is deliberately one of those: a 30-day refresh lifetime. The
        // observable is the durable reservation the exchange leaves behind — it must reach
        // the token's own deadline, not a shorter fixed window.
        let _env = crate::test_support::without_root_key();

        let dir = tempfile::tempdir().expect("tempdir");
        let file_storage =
            secreton_storage::FileBackend::new(dir.path().to_str().expect("utf-8 path"))
                .expect("file backend");
        let storage: Arc<dyn StorageBackend + Send + Sync> = Arc::new(file_storage);
        let root_key = secreton_crypto::generate_key(secreton_crypto::AlgorithmId::Aes256Gcm)
            .expect("root key");
        let service =
            auth_with_storage_root_key_and_refresh_ttl(storage.clone(), root_key, 86_400 * 30)
                .await;

        let password = crate::test_support::generated_password();
        service
            .register_user("long-lived-user", &password, None, vec![], vec![])
            .await
            .expect("register user");
        let login = service
            .login(
                ApiLoginRequest {
                    username: "long-lived-user".to_string(),
                    password,
                    mfa_code: None,
                },
                "192.0.2.1".to_string(),
                "test".to_string(),
            )
            .await
            .expect("login");
        let refresh = login.token.refresh_token.clone();

        // The token really does carry the configured 30-day lifetime, so a fixed eight-day
        // guard would be strictly shorter — this is the defect's precondition, asserted
        // rather than assumed.
        let claims = service
            .token_service
            .validate_refresh_token(&refresh)
            .expect("refresh claims");
        let token_expiry = i64::try_from(claims.exp)
            .ok()
            .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
            .expect("token expiry as a timestamp");
        assert!(
            token_expiry > chrono::Utc::now() + chrono::Duration::days(8),
            "precondition: the refresh lifetime must exceed the old fixed guard"
        );

        // Exchange it. A successful rotation leaves the reservation in place for the
        // token's whole life (that permanence is what closes the cross-replica race).
        service
            .refresh_token(&refresh, "192.0.2.1".to_string(), "test".to_string())
            .await
            .expect("refresh");

        // Read the durable reservation back. Before the fix its deadline was `now + 8 days`
        // and the token outlived it; now it is the token's own deadline.
        let path = AuthenticationService::refresh_reservation_path(&refresh);
        let stored = storage
            .get_by_path(&path)
            .await
            .expect("read reservation")
            .expect("a successful exchange must leave its reservation in place");
        let recorded = stored.expires_at.expect("the reservation must expire");
        assert!(
            recorded >= token_expiry - chrono::Duration::seconds(1),
            "the reservation must last as long as the token, not on a shorter fixed \
             window: recorded={recorded} token={token_expiry}"
        );
    }

    #[tokio::test]
    async fn a_bootstrap_root_created_under_a_custom_name_cannot_password_login() {
        // CWE-287 regression: the root boundary was the literal username `"root"`. Once
        // `init` accepted a custom `root_username`, the privileged account it created under
        // another name kept a generated password hash and could log in with it. The
        // boundary is now the account's persisted `password_login_disabled` flag.
        let _env = crate::test_support::without_root_key();
        let (storage, service, root_key) = auth_with_open_barrier().await;

        const ROOT_USERNAME: &str = "vault-operator";
        let root = service
            .register_bootstrap_root(
                ROOT_USERNAME,
                Some("root@system.local".to_string()),
                vec!["root".to_string(), "admin".to_string()],
                vec!["*".to_string()],
            )
            .await
            .expect("bootstrap root");
        assert!(root.is_admin());
        assert!(
            root.password_hash.is_empty(),
            "the bootstrap root must store no password hash at all"
        );

        // Plant a *valid* password hash on the record and in the in-memory userpass cache,
        // so the account looks exactly like one that held a generated password. An empty
        // hash alone would make this pass without the flag doing any work; a real hash
        // proves the flag is the boundary the denial stands on. The password is generated
        // per test rather than a literal: a fixed one is not a credential, but it reads
        // like one to a scanner and models production wrongly.
        let generated: String = crate::test_support::generated_password();
        // The denial is not "this one known password is refused": it is that no password is
        // accepted for this account. Probe with a spread of fresh random values plus the
        // empty string, none of them a literal that reads like a committed credential.
        let probes: Vec<String> = std::iter::once(String::new())
            .chain(std::iter::once(generated.clone()))
            .chain((0..3).map(|_| crate::test_support::generated_password()))
            .collect();
        // Control: the same password on an ordinary account really does log in, so a
        // denial below cannot be explained by a password nobody can use.
        service
            .register_user(
                "password-control",
                &generated,
                None,
                vec!["admin".to_string()],
                vec![],
            )
            .await
            .expect("control account");
        assert!(
            service
                .login(
                    ApiLoginRequest {
                        username: "password-control".to_string(),
                        password: generated.clone(),
                        mfa_code: None,
                    },
                    "192.0.2.1".to_string(),
                    "test".to_string(),
                )
                .await
                .is_ok(),
            "the control account must be able to log in with the generated password"
        );

        // Now give the bootstrap root that same password: a valid hash both in the record
        // and in the cache the login path reads.
        let valid_hash = service
            .userpass_method
            .create_user(
                "hash-probe".to_string(),
                &generated,
                "probe-id".to_string(),
                vec![],
                vec![],
                vec![],
            )
            .await
            .expect("hash the probe password");
        service
            .userpass_method
            .add_user(
                ROOT_USERNAME.to_string(),
                valid_hash.clone(),
                root.id.clone(),
                root.roles.clone(),
                root.policies.clone(),
                root.permissions.clone(),
                true,
            )
            .await;
        let mut stored = root.clone();
        stored.password_hash = valid_hash;
        let bytes = serde_json::to_vec(&stored).expect("serialize");
        let encrypted = service.crypto.encrypt_data(&bytes).await.expect("encrypt");
        storage
            .upsert(&secreton_storage::SecretEntry::new(
                format!("{}{}", USER_STORAGE_PREFIX, ROOT_USERNAME),
                encrypted,
                secreton_storage::EncryptionMetadata::default(),
                secreton_storage::SecurityLevel::Secret,
                uuid::Uuid::parse_str(&root.id).unwrap_or_default(),
            ))
            .await
            .expect("plant the hash on the record");
        let _ = root_key;

        // Every password-login entry point refuses it with the generic error.
        for password in probes.iter().map(String::as_str) {
            let login = service
                .login(
                    ApiLoginRequest {
                        username: ROOT_USERNAME.to_string(),
                        password: password.to_string(),
                        mfa_code: None,
                    },
                    "192.0.2.1".to_string(),
                    "test".to_string(),
                )
                .await;
            let err = login.expect_err("password login must be refused");
            let text = err.to_string();
            assert!(
                text.to_lowercase().contains("invalid credentials")
                    || text.to_lowercase().contains("authentication failed"),
                "the denial must stay generic, not name the account: {text}"
            );
            assert!(
                !text.contains(ROOT_USERNAME),
                "the denial must not echo the privileged username: {text}"
            );

            let authenticate = service
                .authenticate(
                    secreton_auth::LoginRequest {
                        username: ROOT_USERNAME.to_string(),
                        password: password.to_string(),
                        mfa_code: None,
                        remember_me: None,
                    },
                    "192.0.2.1".to_string(),
                    "test".to_string(),
                )
                .await;
            assert!(
                authenticate.is_err(),
                "authenticate() must refuse the bootstrap root too"
            );

            assert!(
                !service
                    .verify_password(ROOT_USERNAME, password)
                    .await
                    .expect("verify_password"),
                "verify_password() must not accept a password for the bootstrap root"
            );
        }

        // The account is untouched by those attempts: not locked, not mutated.
        let reloaded = service
            .find_user_by_username(ROOT_USERNAME)
            .await
            .expect("find")
            .expect("the root account still exists");
        assert_eq!(reloaded.failed_login_attempts, 0);
        assert!(reloaded.locked_until.is_none());
    }

    #[tokio::test]
    async fn an_ordinary_admin_named_root_can_still_password_login() {
        // The boundary is the account, not the name. An ordinary admin who happens to be
        // called "root" is not the bootstrap identity and must not be denied its password.
        let _env = crate::test_support::without_root_key();
        let (_storage, service, _root_key) = auth_with_open_barrier().await;

        let ordinary_password = crate::test_support::generated_password();
        service
            .register_user(
                "root",
                &ordinary_password,
                Some("ops@example.com".to_string()),
                vec!["admin".to_string()],
                vec![],
            )
            .await
            .expect("ordinary admin");

        assert!(
            service
                .verify_password("root", &ordinary_password)
                .await
                .expect("verify"),
            "an ordinary admin account named 'root' is password-authenticatable"
        );
        let login = service
            .login(
                ApiLoginRequest {
                    username: "root".to_string(),
                    password: ordinary_password.clone(),
                    mfa_code: None,
                },
                "192.0.2.1".to_string(),
                "test".to_string(),
            )
            .await;
        assert!(
            login.is_ok(),
            "an ordinary admin named 'root' must be able to log in: {:?}",
            login.err().map(|e| e.to_string())
        );
    }

    #[tokio::test]
    async fn the_bootstrap_root_flag_survives_a_restart() {
        // The denial must not depend on in-memory state: a service rebuilt over the same
        // storage (a restart) must still refuse the bootstrap root, and the flag must be
        // what does it. Deserialization of a record written before the field existed
        // defaults to false, so this also proves the flag is actually persisted.
        let _env = crate::test_support::without_root_key();
        let (storage, service, root_key) = auth_with_open_barrier().await;

        const ROOT_USERNAME: &str = "persisted-root";
        service
            .register_bootstrap_root(
                ROOT_USERNAME,
                None,
                vec!["root".to_string(), "admin".to_string()],
                vec!["*".to_string()],
            )
            .await
            .expect("bootstrap root");

        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        crypto
            .set_root_key(root_key)
            .await
            .expect("reinstall the same root key so the existing records still decrypt");

        let mut config = AuthConfig::default();
        config.jwt.secret = Some("test_secret".to_string());
        let restarted = AuthenticationService::new(storage.clone(), crypto, &config)
            .await
            .expect("rebuild the service over the same storage");

        // The persisted record carries the flag, and the rebuilt service refuses login.
        let user = restarted
            .find_user_by_username(ROOT_USERNAME)
            .await
            .expect("find")
            .expect("user");
        assert!(
            user.password_login_disabled,
            "the non-password-authenticatable flag must be persisted on the record"
        );
        assert!(
            !restarted
                .verify_password(ROOT_USERNAME, &crate::test_support::generated_password())
                .await
                .expect("verify")
        );
    }
}

/// Profile returned by an OAuth provider's userinfo endpoint.
///
/// Defined here rather than in the HTTP layer: the service consumes it, so the service
/// crate owns it and the handler merely deserialises into it.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OAuthUserInfo {
    pub id: String,
    pub username: String,
    /// Some providers do not return an address, or return an unverified one; empty
    /// means "not supplied" rather than a fabricated placeholder.
    pub email: String,
    pub name: String,
    /// Which provider issued this profile, e.g. `google` or `github`.
    pub provider: String,
}
