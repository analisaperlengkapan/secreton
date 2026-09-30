//! Authentication and authorization handlers.
//!
//! Provides endpoints for user login, token management, MFA,
//! and OAuth2 integration.

use secreton_domain::SecretonError;

use crate::extractors::AuthenticatedUser;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Json,
    routing::{delete, get, post},
};

use secreton_domain::OAuthState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub user_id: String,
    pub ip_address: String,
    pub user_agent: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub is_current: bool,
    pub metadata: HashMap<String, String>,
}

// Use types from secreton_auth
use secreton_auth::{LoginRequest, MfaService, RefreshTokenRequest, UserInfo};

use crate::error::ApiResult;
use crate::router::AppState;
use secreton_domain::ApiResponse;
use secreton_engines::Services;
use secreton_engines::services::audit::SecurityEventType;
use secreton_engines::services::auth::AuthError;
use secreton_engines::services::auth::OAuthUserInfo;

// Import Claims from auth service for JWT decoding
use secreton_engines::services::auth::Claims;

/// Create authentication routes
/// Routes reachable without a session.
///
/// These are mounted outside the auth layer in [`crate::router`], which is what makes the
/// routing tree the allowlist. The previous design listed the same paths as exact strings
/// inside the middleware, so adding one here without editing there produced a login
/// endpoint that demanded a session.
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/oauth/{provider}", get(oauth_login))
        .route("/oauth/{provider}/callback", get(oauth_callback))
}

/// Routes that require an authenticated session.
///
/// `verify` is here rather than in `public_routes`: it exists to confirm a credential, so
/// letting it answer unauthenticated turns it into a free token-validation oracle.
pub fn authenticated_routes() -> Router<AppState> {
    Router::new()
        .route("/logout", post(logout))
        .route("/verify", post(verify_token))
        .route("/mfa/setup", post(setup_mfa))
        .route("/mfa/setup/complete", post(complete_mfa_setup))
        .route("/mfa/verify", post(verify_mfa))
        .route("/mfa/disable", post(disable_mfa))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{session_id}", delete(revoke_session))
        .route("/users", post(create_user))
}

// LoginRequest, RefreshTokenRequest, UserInfo imported from secreton_auth

/// Login response for API
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserInfo,
    pub mfa_required: bool,
}

/// Token verification request
#[derive(Debug, Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
}

/// MFA setup request
#[derive(Debug, Deserialize, Serialize)]
pub struct MfaSetupRequest {
    pub method: String, // "totp", "sms", "email", "webauthn"
    pub phone_number: Option<String>,
    pub email: Option<String>,
}

/// MFA setup response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub method: String,
    pub secret: Option<String>,  // For TOTP
    pub qr_code: Option<String>, // For TOTP
    pub webauthn_challenge: Option<secreton_auth::mfa::webauthn::RegistrationChallenge>, // For WebAuthn
    pub backup_codes: Vec<String>,
}

/// MFA setup completion request (for WebAuthn, SMS, Email)
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupCompleteRequest {
    pub method: String,
    pub webauthn_response: Option<secreton_auth::mfa::webauthn::RegistrationResponse>,
    pub code: Option<String>,
}

/// MFA verification request
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub method: String,
    pub code: String,
    pub backup_code: Option<String>,
}

/// MFA disable request
#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    pub password: String, // Require password confirmation for security
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub email: Option<String>,
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// OAuth provider configuration
#[derive(Debug, Clone)]
struct OAuthProvider {
    client_id: String,
    /// The provider's client secret. The field name keeps the `client` qualifier so
    /// it does not read as a bare `secret`; it is only ever used to build the
    /// token-exchange request body.
    oauth_client_secret: String,
    token_url: String,
    user_info_url: String,
    redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvidersConfig {
    pub providers: HashMap<String, String>,
}

impl OAuthProvider {
    fn new(
        provider: &str,
        config: Option<&secreton_engines::config::OAuth2Config>,
    ) -> Option<Self> {
        let config = config?;

        // Find the provider in the providers vector
        let provider_config = config
            .providers
            .iter()
            .find(|p| p.name.to_lowercase() == provider.to_lowercase())?;

        // Build URLs based on provider type
        let (token_url, user_info_url) = match provider {
            "google" => (
                "https://oauth2.googleapis.com/token".to_string(),
                "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            ),
            "github" => (
                "https://github.com/login/oauth/access_token".to_string(),
                "https://api.github.com/user".to_string(),
            ),
            "microsoft" => (
                "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                "https://graph.microsoft.com/v1.0/me".to_string(),
            ),
            "okta" => (
                provider_config.token_url.clone(),
                provider_config.user_info_url.clone(),
            ),
            _ => (
                provider_config.token_url.clone(),
                provider_config.user_info_url.clone(),
            ),
        };

        // Build redirect URI - use provider-specific if available, otherwise use config default
        let redirect_uri = if provider_config.auth_url.is_empty() {
            config.redirect_url.clone()
        } else {
            format!("{}/{}/callback", config.redirect_url, provider)
        };

        Some(Self {
            client_id: provider_config.client_id.clone(),
            oauth_client_secret: provider_config.client_secret.clone(),
            token_url,
            user_info_url,
            redirect_uri,
        })
    }

    async fn exchange_code_for_token(
        &self,
        code: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let params = [
            ("client_id", &self.client_id),
            ("client_secret", &self.oauth_client_secret),
            ("code", &code.to_string()),
            ("grant_type", &"authorization_code".to_string()),
            ("redirect_uri", &self.redirect_uri),
        ];

        let response: reqwest::Response = client
            .post(&self.token_url)
            .form(&params)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Token exchange failed: {}", response.status()).into());
        }

        let token_data: serde_json::Value = response.json().await?;
        Ok(token_data)
    }

    async fn get_user_info(
        &self,
        access_token: &str,
    ) -> Result<OAuthUserInfo, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let response = client
            .get(&self.user_info_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("User info fetch failed: {}", response.status()).into());
        }

        let user_data: serde_json::Value = response.json().await?;

        let oauth_user = match self.user_info_url.as_str() {
            url if url.contains("googleapis.com") => OAuthUserInfo {
                id: user_data["id"].as_str().unwrap_or("google_id").to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["email"]
                    .as_str()
                    .unwrap_or("")
                    .split('@')
                    .next()
                    .unwrap_or("google_user")
                    .to_string(),
                name: user_data["name"]
                    .as_str()
                    .unwrap_or("Google User")
                    .to_string(),
                provider: "google".to_string(),
            },
            url if url.contains("api.github.com") => OAuthUserInfo {
                id: user_data["id"].to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["login"]
                    .as_str()
                    .unwrap_or("github_user")
                    .to_string(),
                name: user_data["name"]
                    .as_str()
                    .unwrap_or("GitHub User")
                    .to_string(),
                provider: "github".to_string(),
            },
            url if url.contains("graph.microsoft.com") => OAuthUserInfo {
                id: user_data["id"]
                    .as_str()
                    .unwrap_or("microsoft_id")
                    .to_string(),
                email: user_data["userPrincipalName"]
                    .as_str()
                    .or(user_data["mail"].as_str())
                    .unwrap_or("")
                    .to_string(),
                username: user_data["userPrincipalName"]
                    .as_str()
                    .unwrap_or("")
                    .split('@')
                    .next()
                    .unwrap_or("microsoft_user")
                    .to_string(),
                name: user_data["displayName"]
                    .as_str()
                    .unwrap_or("Microsoft User")
                    .to_string(),
                provider: "microsoft".to_string(),
            },
            url if url.contains("okta.com") => OAuthUserInfo {
                id: user_data["sub"].as_str().unwrap_or("okta_id").to_string(),
                email: user_data["email"].as_str().unwrap_or("").to_string(),
                username: user_data["preferred_username"]
                    .as_str()
                    .unwrap_or("okta_user")
                    .to_string(),
                name: user_data["name"]
                    .as_str()
                    .unwrap_or("Okta User")
                    .to_string(),
                provider: "okta".to_string(),
            },
            _ => return Err("Unsupported OAuth provider".into()),
        };

        Ok(oauth_user)
    }
}

/// User login endpoint
pub async fn login(
    State(state): State<Services>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract client information from headers
    let _ip_address = extract_client_ip(&headers);
    let _user_agent = extract_user_agent(&headers);

    // Authenticate user
    let login_request = secreton_auth::model::LoginRequest {
        username: request.username.clone(),
        password: request.password.clone(),
        mfa_code: request.mfa_code.clone(),
        remember_me: request.remember_me,
    };

    // Extract client information from headers
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    let auth_result = state
        .auth
        .authenticate(login_request, ip_address, user_agent)
        .await;

    match auth_result {
        Ok(auth_token) => {
            // AuthResult.token is Option<String>, use it as access_token
            let access_token = auth_token.token.clone().unwrap_or_default();
            let user_info = auth_token.user_info.as_ref().ok_or_else(|| {
                crate::error::ApiError(SecretonError::Authentication {
                    message: "User info not available".to_string(),
                })
            })?;

            // Read dynamic expires_in from AuthResult metadata (set by
            // authenticate()), falling back to 3600 for backward compat.
            let expires_in: i64 = auth_token
                .metadata
                .get("expires_in")
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(3600);

            let response = LoginResponse {
                access_token: Some(access_token.clone()),
                refresh_token: auth_token.refresh_token.clone(),
                token_type: "Bearer".to_string(),
                expires_in,
                user: UserInfo {
                    id: user_info.id.clone(),
                    username: user_info.username.clone(),
                    email: user_info.email.clone(),
                    display_name: user_info.display_name.clone(),
                    roles: user_info.roles.clone(),
                    permissions: user_info.permissions.clone(),
                    metadata: user_info.metadata.clone(),
                    last_login: user_info.last_login,
                },
                mfa_required: auth_token.mfa_required,
            };

            // Audit: authentication success
            let _ = state
                .audit
                .log_event(SecurityEventType::AuthenticationSuccess {
                    user: response.user.username.clone(),
                    method: "password".to_string(),
                })
                .await;

            Ok(Json(ApiResponse::success(response)))
        }
        Err(e) => {
            // Audit: log authentication failures, but skip errors that are
            // already audited inside `enforce_mfa()` to avoid duplicate
            // entries in security dashboards:
            //   - MfaRequired: normal first step in a two-step MFA flow
            //     (not a real failure; no audit is emitted by enforce_mfa
            //     either, matching the design — MFA-required prompts are
            //     not security events).
            //   - InvalidMfaCode: already logged by `enforce_mfa()` as
            //     `AuthenticationFailure { method: "totp", reason:
            //     "Invalid MFA code" }` at crates/api/src/services/auth.rs.
            //     Skipping the duplicate keeps a single canonical entry so
            //     brute-force MFA attempts remain accurately counted in
            //     security dashboards.
            //   - MfaNotConfigured: `enforce_mfa()` does NOT currently emit
            //     this variant (TOFU users take a different code path), so
            //     this arm is a defensive no-op.  It is retained so that if
            //     `enforce_mfa()` is ever changed to return
            //     `MfaNotConfigured`, the login handler will not duplicate
            //     the audit entry.
            if !matches!(
                e,
                AuthError::MfaRequired | AuthError::InvalidMfaCode | AuthError::MfaNotConfigured(_)
            ) {
                let _ = state
                    .audit
                    .log_event(SecurityEventType::AuthenticationFailure {
                        user: request.username.clone(),
                        method: "password".to_string(),
                        reason: e.to_string(),
                    })
                    .await;
            }

            // Map specific auth errors to appropriate HTTP status codes.
            match e {
                AuthError::MfaNotConfigured(_) => {
                    // Return 401 with a generic message identical to invalid
                    // credentials to prevent credential enumeration.
                    // MfaNotConfigured only fires after successful password
                    // verification, so a distinct message would confirm that
                    // the credentials are valid.
                    Err(crate::error::ApiError(SecretonError::Authentication {
                        message: "Authentication failed".to_string(),
                    }))
                }
                AuthError::MfaRequired => {
                    // NOTE: "MFA required" implicitly confirms valid credentials
                    // (it only fires after successful password verification).
                    // This is an inherent limitation of two-step MFA flows — the
                    // client needs to know when to prompt for a code.  We use a
                    // dedicated SecretonError variant so the HTTP layer returns
                    // the correct 401 status with the MFA-specific message.
                    Err(crate::error::ApiError(
                        secreton_domain::SecretonError::MfaRequired,
                    ))
                }
                AuthError::Internal(ref inner) => {
                    tracing::error!(
                        "Internal error during login for '{}': {}",
                        request.username,
                        inner
                    );
                    Err(crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during authentication".to_string(),
                    }))
                }
                AuthError::Storage(ref inner) => {
                    tracing::error!(
                        "Storage error during login for '{}': {}",
                        request.username,
                        inner
                    );
                    Err(crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during authentication".to_string(),
                    }))
                }
                AuthError::Crypto(ref inner) => {
                    tracing::error!(
                        "Crypto error during login for '{}': {}",
                        request.username,
                        inner
                    );
                    Err(crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during authentication".to_string(),
                    }))
                }
                // InvalidMfaCode only fires after successful password
                // verification, so returning "Invalid MFA code" would
                // confirm that the credentials are valid.  Use a generic
                // message consistent with MfaNotConfigured handling above.
                AuthError::InvalidMfaCode => {
                    Err(crate::error::ApiError(SecretonError::Authentication {
                        message: "Authentication failed".to_string(),
                    }))
                }
                // UserNotFound / UserAlreadyExists — return a generic
                // message to prevent user enumeration.
                AuthError::UserNotFound | AuthError::UserAlreadyExists => {
                    Err(crate::error::ApiError(SecretonError::Authentication {
                        message: "Authentication failed".to_string(),
                    }))
                }
                _ => Err(crate::error::ApiError(SecretonError::Authentication {
                    message: "Authentication failed".to_string(),
                })),
            }
        }
    }
}

/// User logout endpoint
pub async fn logout(
    State(state): State<Services>,
    headers: HeaderMap,
    AuthenticatedUser(user): AuthenticatedUser,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract token from Authorization header
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Missing or invalid authorization header".to_string(),
            })
        })?;

    // Extract session ID from token for accurate auditing
    let session_id = extract_jti_from_token(token, &state).unwrap_or_else(|| "unknown".to_string());

    // Revoke the current session
    if session_id != "unknown" {
        let _ = state.auth.revoke_user_session(&session_id, &user.id).await;
    } else {
        // Fallback: revoke the token only if session ID unknown (shouldn't happen with valid token)
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);
        state.auth.revoke_token(token.to_string(), expires_at).await;
    }

    let data = serde_json::json!({
        "message": "Successfully logged out"
    });

    // Audit: session terminated
    let _ = state
        .audit
        .log_event(SecurityEventType::SessionTerminated {
            user: user.username,
            session_id,
            reason: "logout".to_string(),
        })
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Refresh access token
pub async fn refresh_token(
    State(state): State<Services>,
    headers: HeaderMap,
    Json(request): Json<RefreshTokenRequest>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract client information from headers
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    // Validate refresh token and get new tokens
    let auth_token = match state
        .auth
        .refresh_token(&request.refresh_token, ip_address, user_agent)
        .await
    {
        Ok(token) => token,
        Err(e) => {
            // Map specific auth errors to appropriate HTTP responses,
            // sanitizing internal details to prevent information leakage.
            // This mirrors the error handling in the login handler.
            return Err(match e {
                AuthError::Storage(ref inner) => {
                    tracing::error!("Storage error during token refresh: {}", inner);
                    crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during token refresh".to_string(),
                    })
                }
                AuthError::Internal(ref inner) => {
                    tracing::error!("Internal error during token refresh: {}", inner);
                    crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during token refresh".to_string(),
                    })
                }
                AuthError::Crypto(ref inner) => {
                    tracing::error!("Crypto error during token refresh: {}", inner);
                    crate::error::ApiError(SecretonError::Internal {
                        message: "An internal error occurred during token refresh".to_string(),
                    })
                }
                // InvalidCredentials covers disabled/locked accounts and
                // UserNotFound — return a generic auth failure message to
                // avoid confirming whether the account exists or its status.
                AuthError::InvalidCredentials | AuthError::UserNotFound => {
                    crate::error::ApiError(SecretonError::Authentication {
                        message: "Token refresh failed".to_string(),
                    })
                }
                AuthError::InvalidToken | AuthError::TokenExpired => {
                    crate::error::ApiError(SecretonError::Authentication {
                        message: e.to_string(),
                    })
                }
                _ => crate::error::ApiError(SecretonError::Authentication {
                    message: "Token refresh failed".to_string(),
                }),
            });
        }
    };

    // Use the User embedded in the refreshed AuthToken directly instead of
    // re-validating the just-issued access token.  `refresh_token()` populates
    // `auth_token.user` with the current roles/policies loaded from storage
    // and sets `metadata["mfa_pending"] = "true"` when the refreshed token
    // carries `mfa_required: true`, so we can read the TOFU flag without
    // another JWT decode + session lookup round-trip.
    let user = &auth_token.user;

    // Propagate the mfa_pending flag from the refreshed token so that
    // clients know whether the user still needs to complete MFA enrollment.
    let mfa_required = user
        .metadata
        .get("mfa_pending")
        .map(|v| v == "true")
        .unwrap_or(false);

    let response = LoginResponse {
        access_token: Some(auth_token.access_token.clone()),
        refresh_token: Some(auth_token.refresh_token.clone()),
        token_type: auth_token.token_type.clone(),
        expires_in: auth_token.expires_in as i64,
        user: UserInfo {
            id: Some(user.id.to_string()),
            username: user.username.clone(),
            email: user.email.clone(),
            display_name: user.display_name.clone(),
            roles: user.roles.clone(),
            permissions: vec![],
            metadata: user.metadata.clone(),
            last_login: user.last_login,
        },
        mfa_required,
    };

    // Audit: token refresh
    let _ = state
        .audit
        .log_event(SecurityEventType::AuthenticationSuccess {
            user: response.user.username.clone(),
            method: "refresh_token".to_string(),
            // ip_address removed from variant
        })
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Verify token validity
pub async fn verify_token(
    State(state): State<Services>,
    Json(request): Json<VerifyTokenRequest>,
) -> ApiResult<Json<ApiResponse<UserInfo>>> {
    // Validate token and get user information
    let user: secreton_auth::User =
        state
            .auth
            .validate_token(&request.token)
            .await
            .map_err(|e| {
                crate::error::ApiError(SecretonError::Authentication {
                    message: e.to_string(),
                })
            })?;

    let user_info = UserInfo {
        id: Some(user.id.clone()),
        username: user.username.clone(),
        email: user.email.clone(),
        display_name: user.display_name.clone(),
        roles: user.roles.clone(),
        permissions: vec![], // User struct doesn't have permissions
        metadata: user.metadata.clone(),
        last_login: user.last_login,
    };

    Ok(Json(ApiResponse::success(user_info)))
}

/// Setup MFA for user
pub async fn setup_mfa(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<MfaSetupRequest>,
) -> ApiResult<Json<ApiResponse<MfaSetupResponse>>> {
    // Parse user ID to UUID
    let user_id = Uuid::parse_str(&user.id).map_err(|_| {
        crate::error::ApiError(SecretonError::Authentication {
            message: "Invalid user ID".to_string(),
        })
    })?;

    let mut response = MfaSetupResponse {
        method: request.method.clone(),
        secret: None,
        qr_code: None,
        webauthn_challenge: None,
        backup_codes: Vec::new(),
    };

    match request.method.as_str() {
        "totp" => {
            let totp_config = state
                .mfa
                .enable_totp(user_id, user.username.clone())
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to setup MFA: {}", e),
                    })
                })?;

            response.secret = Some(totp_config.secret);
            response.qr_code = Some(totp_config.url);
        }
        "sms" => {
            let phone_number = request.phone_number.ok_or_else(|| {
                crate::error::ApiError(SecretonError::Validation {
                    message: "Phone number is required for SMS MFA".to_string(),
                })
            })?;

            state
                .mfa
                .enable_sms(user_id, phone_number)
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to setup SMS MFA: {}", e),
                    })
                })?;
        }
        "email" => {
            let email = request.email.ok_or_else(|| {
                crate::error::ApiError(SecretonError::Validation {
                    message: "Email is required for Email MFA".to_string(),
                })
            })?;

            state.mfa.enable_email(user_id, email).await.map_err(|e| {
                crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to setup Email MFA: {}", e),
                })
            })?;
        }
        "webauthn" => {
            let challenge = state
                .mfa
                .start_webauthn_registration(
                    user_id,
                    &user.username,
                    &user.display_name.unwrap_or_else(|| user.username.clone()),
                )
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to start WebAuthn registration: {}", e),
                    })
                })?;

            response.webauthn_challenge = Some(challenge);
        }
        _ => {
            return Err(crate::error::ApiError(SecretonError::Validation {
                message: "Unsupported MFA method".to_string(),
            }));
        }
    }

    // Generate backup codes if not just starting webauthn
    if request.method != "webauthn" {
        let codes = state
            .mfa
            .regenerate_recovery_codes(user_id)
            .await
            .map_err(|e| {
                crate::error::ApiError(SecretonError::Internal {
                    message: format!("Failed to generate recovery codes: {}", e),
                })
            })?;
        response.backup_codes = codes;
    }

    // Audit: MFA setup
    let _ = state
        .audit
        .log_event(SecurityEventType::MfaSetup {
            user: user.username,
            method: request.method,
        })
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Complete MFA setup (e.g. for WebAuthn, SMS, Email)
pub async fn complete_mfa_setup(
    State(state): State<Services>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<MfaSetupCompleteRequest>,
) -> ApiResult<Json<ApiResponse<MfaSetupResponse>>> {
    // Parse user ID to UUID
    let user_id = Uuid::parse_str(&user.id).map_err(|_| {
        crate::error::ApiError(SecretonError::Authentication {
            message: "Invalid user ID".to_string(),
        })
    })?;

    match request.method.as_str() {
        "webauthn" => {
            if let Some(response) = request.webauthn_response {
                state
                    .mfa
                    .complete_webauthn_registration(response)
                    .await
                    .map_err(|e| {
                        crate::error::ApiError(SecretonError::Internal {
                            message: format!("Failed to complete WebAuthn registration: {}", e),
                        })
                    })?;
            } else {
                return Err(crate::error::ApiError(SecretonError::Validation {
                    message: "Missing WebAuthn response".to_string(),
                }));
            }
        }
        "sms" => {
            let code = request.code.ok_or_else(|| {
                crate::error::ApiError(SecretonError::Validation {
                    message: "Missing code".to_string(),
                })
            })?;
            let valid = state
                .mfa
                .verify_and_enable_sms(user_id, code)
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to verify SMS code: {}", e),
                    })
                })?;
            if !valid {
                return Err(crate::error::ApiError(SecretonError::Validation {
                    message: "Invalid SMS code".to_string(),
                }));
            }
        }
        "email" => {
            let code = request.code.ok_or_else(|| {
                crate::error::ApiError(SecretonError::Validation {
                    message: "Missing code".to_string(),
                })
            })?;
            let valid = state
                .mfa
                .verify_and_enable_email(user_id, code)
                .await
                .map_err(|e| {
                    crate::error::ApiError(SecretonError::Internal {
                        message: format!("Failed to verify Email code: {}", e),
                    })
                })?;
            if !valid {
                return Err(crate::error::ApiError(SecretonError::Validation {
                    message: "Invalid Email code".to_string(),
                }));
            }
        }
        _ => {
            return Err(crate::error::ApiError(SecretonError::Validation {
                message: "Unsupported MFA method for completion".to_string(),
            }));
        }
    }

    // Generate backup codes
    let codes = state
        .mfa
        .regenerate_recovery_codes(user_id)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to generate recovery codes: {}", e),
            })
        })?;

    let response = MfaSetupResponse {
        method: request.method.clone(),
        secret: None,
        qr_code: None,
        webauthn_challenge: None,
        backup_codes: codes,
    };

    // Audit: MFA setup complete
    let _ = state
        .audit
        .log_event(SecurityEventType::MfaSetup {
            user: user.username,
            method: request.method,
        })
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// Verify MFA code
pub async fn verify_mfa(
    State(state): State<Services>,
    headers: HeaderMap,
    Json(request): Json<MfaVerifyRequest>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Missing or invalid authorization header".to_string(),
            })
        })?;

    // Get user from token
    let user = state.auth.validate_token(token).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Authentication {
            message: e.to_string(),
        })
    })?;

    // Parse user ID to UUID
    let user_id = Uuid::parse_str(&user.id).map_err(|_| {
        crate::error::ApiError(SecretonError::Authentication {
            message: "Invalid user ID".to_string(),
        })
    })?;

    use secreton_auth::mfa::{MfaMethod, MfaValidationRequest};

    let validation_request = match request.method.as_str() {
        "totp" => MfaValidationRequest {
            entity_id: user_id,
            method: MfaMethod::Totp,
            code: Some(request.code.clone()),
            hardware_request: None,
            push_notification_id: None,
            push_response: None,
            webauthn_response: None,
        },
        "recovery" => MfaValidationRequest {
            entity_id: user_id,
            method: MfaMethod::Recovery,
            code: Some(request.code.clone()),
            hardware_request: None,
            push_notification_id: None,
            push_response: None,
            webauthn_response: None,
        },
        _ => {
            return Err(crate::error::ApiError(SecretonError::Validation {
                message: "Unsupported MFA method for verification".to_string(),
            }));
        }
    };

    // Validate using the MFA service
    let is_valid = state.mfa.validate(validation_request).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: format!("MFA validation failed: {}", e),
        })
    })?;

    if !is_valid {
        return Err(crate::error::ApiError(SecretonError::Authentication {
            message: "Invalid MFA code".to_string(),
        }));
    }

    let data = serde_json::json!({
        "message": "MFA successfully verified and enabled",
        "method": request.method
    });

    // Audit: MFA success
    let _ = state
        .audit
        .log_event(SecurityEventType::MFASuccess {
            user: user.username,
            method: request.method,
        })
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Disable MFA for user
pub async fn disable_mfa(
    State(state): State<Services>,
    headers: HeaderMap,
    Json(request): Json<MfaDisableRequest>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Missing or invalid authorization header".to_string(),
            })
        })?;

    // Get user from token
    let user = state.auth.validate_token(token).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Authentication {
            message: e.to_string(),
        })
    })?;

    // Verify password for additional security
    let password_valid: bool = state
        .auth
        .verify_password(&user.username, &request.password)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Authentication {
                message: e.to_string(),
            })
        })?;

    if !password_valid {
        return Err(crate::error::ApiError(SecretonError::Authentication {
            message: "Invalid password".to_string(),
        }));
    }

    // Parse UUID
    let user_uuid = Uuid::parse_str(&user.id).map_err(|_| {
        crate::error::ApiError(SecretonError::Internal {
            message: "Invalid user ID format".to_string(),
        })
    })?;

    // Disable MFA (specific logic from mfa-integration tailored to use user_uuid)
    state.mfa.disable_totp(user_uuid).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to disable MFA: {}", e),
        })
    })?;

    // Remove MFA enrollment (disables all methods)
    state.mfa.remove_enrollment(user_uuid).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: format!("Failed to disable MFA: {}", e),
        })
    })?;

    let method = "all"; // All MFA methods disabled

    let data = serde_json::json!({
        "message": "MFA successfully disabled",
        "method": method
    });

    // Audit: MFA removal
    let _ = state
        .audit
        .log_event(SecurityEventType::MFARemoval {
            user: user.username,
            method: method.to_string(),
        })
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// OAuth login redirect
pub async fn oauth_login(
    State(state): State<Services>,
    Path(provider): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Validate supported providers
    let supported_providers = ["google", "github", "microsoft", "okta"];
    if !supported_providers.contains(&provider.as_str()) {
        return Err(crate::error::ApiError(SecretonError::Validation {
            message: format!("Unsupported OAuth provider: {}", provider),
        }));
    }

    // Generate secure random state
    use rand::distributions::Alphanumeric;
    use rand::{Rng, thread_rng};
    let oauth_state_str: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Store state in the database with expiration (10 minutes)
    // Clean up expired states before storing a new one.
    // This is a simple cleanup strategy. A better approach might be a background job.
    if let Err(e) = state.storage.delete_expired_oauth_states().await {
        tracing::error!("Failed to delete expired OAuth states: {}", e);
    }

    // Store state in the database with expiration (10 minutes)
    let oauth_state = OAuthState {
        provider: provider.clone(),
        state: oauth_state_str.clone(),
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    };

    state
        .storage
        .store_oauth_state(&oauth_state)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to store OAuth state: {}", e),
            })
        })?;

    // Build authorization URL based on provider
    let auth_url = if let Some(federated_login) = state.config.auth.federated_login.as_ref() {
        // Find the provider in the providers vector
        let provider_config = federated_login
            .providers
            .iter()
            .find(|p| p.name.to_lowercase() == provider.to_lowercase())
            .ok_or_else(|| {
                crate::error::ApiError(SecretonError::Validation {
                    message: format!("OAuth provider '{}' not configured", provider),
                })
            })?;

        // Build redirect URI
        let redirect_uri = format!("{}/{}/callback", federated_login.redirect_url, provider);

        // Build scopes string
        let scopes = federated_login.scopes.join("%20");

        // Build authorization URL based on provider type or use config URL
        if provider_config.auth_url.is_empty() {
            // Use well-known URLs for common providers
            match provider.as_str() {
                "google" => format!(
                    "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                    provider_config.client_id, redirect_uri, scopes, oauth_state_str
                ),
                "github" => format!(
                    "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
                    provider_config.client_id, redirect_uri, oauth_state_str
                ),
                "microsoft" => format!(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                    provider_config.client_id, redirect_uri, scopes, oauth_state_str
                ),
                _ => format!(
                    "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                    provider_config.auth_url,
                    provider_config.client_id,
                    redirect_uri,
                    scopes,
                    oauth_state_str
                ),
            }
        } else {
            // Use provider's configured auth URL
            format!(
                "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
                provider_config.auth_url,
                provider_config.client_id,
                redirect_uri,
                scopes,
                oauth_state_str
            )
        }
    } else {
        return Err(crate::error::ApiError(SecretonError::Validation {
            message: "OAuth providers not configured".to_string(),
        }));
    };

    let data = serde_json::json!({
        "provider": provider,
        "auth_url": auth_url,
        "state": oauth_state_str
    });

    Ok(Json(ApiResponse::success(data)))
}

/// OAuth callback handler
pub async fn oauth_callback(
    State(state): State<Services>,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> ApiResult<Json<ApiResponse<LoginResponse>>> {
    // Extract OAuth parameters
    let code: &String = params.get("code").ok_or_else(|| {
        crate::error::ApiError(SecretonError::Validation {
            message: "OAuth state mismatch".to_string(),
        })
    })?;

    let state_param: &String = params.get("state").ok_or_else(|| {
        crate::error::ApiError(SecretonError::Validation {
            message: "Missing authorization code".to_string(),
        })
    })?;

    // Verify state parameter against stored state for CSRF protection
    let stored_state = state
        .storage
        .get_oauth_state(state_param)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: format!("Failed to get OAuth state: {}", e),
            })
        })?
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Invalid or expired OAuth state".to_string(),
            })
        })?;

    // Verify the state matches the expected provider
    if stored_state.provider != provider {
        return Err(crate::error::ApiError(SecretonError::Authentication {
            message: "OAuth state provider mismatch".to_string(),
        }));
    }

    if let Some(error) = params.get("error") {
        return Err(crate::error::ApiError(SecretonError::Authentication {
            message: format!("OAuth error: {}", error),
        }));
    }

    // Get OAuth provider configuration
    let federated_login = state.config.auth.federated_login.as_ref().ok_or_else(|| {
        crate::error::ApiError(SecretonError::Validation {
            message: "OAuth providers not configured".to_string(),
        })
    })?;

    let authenticator = OAuthProvider::new(&provider, Some(federated_login)).ok_or_else(|| {
        crate::error::ApiError(SecretonError::Validation {
            message: format!("Unsupported OAuth provider: {}", provider),
        })
    })?;

    // Exchange authorization code for access token
    let token_data: serde_json::Value =
        authenticator
            .exchange_code_for_token(code)
            .await
            .map_err(|e| {
                crate::error::ApiError(SecretonError::Authentication {
                    message: format!("Token exchange failed: {}", e),
                })
            })?;

    let access_token = token_data["access_token"].as_str().ok_or_else(|| {
        crate::error::ApiError(SecretonError::Authentication {
            message: "No access token in response".to_string(),
        })
    })?;

    // Fetch user information from provider
    let oauth_user: OAuthUserInfo =
        authenticator
            .get_user_info(access_token)
            .await
            .map_err(|e| {
                crate::error::ApiError(SecretonError::Authentication {
                    message: format!("User info fetch failed: {}", e),
                })
            })?;

    // Create or update user account
    let user = state.auth.oauth_login(&oauth_user).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Authentication {
            message: format!("OAuth login failed: {}", e),
        })
    })?;

    // Extract client information from headers
    let ip_address = extract_client_ip(&headers);
    let user_agent = extract_user_agent(&headers);

    // Generate JWT tokens
    let jwt_access_token = state
        .auth
        .generate_token(&user, ip_address, user_agent)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Authentication {
                message: format!("Token generation failed: {}", e),
            })
        })?;

    let refresh_token = state
        .auth
        .generate_refresh_token(&user)
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Authentication {
                message: format!("Refresh token generation failed: {}", e),
            })
        })?;

    let response = LoginResponse {
        access_token: Some(jwt_access_token),
        refresh_token: Some(refresh_token),
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
        user: UserInfo {
            id: Some(user.id.to_string()),
            username: user.username.clone(),
            email: user.email.clone(),
            display_name: user.display_name,
            roles: user.roles,
            permissions: vec![],
            metadata: user.metadata,
            last_login: Some(chrono::Utc::now()),
        },
        mfa_required: false, // OAuth users might not need MFA initially
    };

    // Audit: OAuth login success
    let _ = state
        .audit
        .log_event(SecurityEventType::LoginSuccess {
            user: user.username.clone(),
            method: format!("oauth_{}", provider),
            ip_address: Some(extract_client_ip(&headers)),
        })
        .await;

    Ok(Json(ApiResponse::success(response)))
}

/// List user sessions
pub async fn list_sessions(
    State(state): State<Services>,
    headers: HeaderMap,
) -> ApiResult<Json<ApiResponse<Vec<SessionInfo>>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Missing or invalid authorization header".to_string(),
            })
        })?;

    // Get user from token
    let user = state.auth.validate_token(token).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Authentication {
            message: e.to_string(),
        })
    })?;

    // Extract JTI from current token to identify current session
    let current_jti = extract_jti_from_token(token, &state);

    // Get all sessions for the user from backend storage
    let sessions = state.auth.list_user_sessions(&user.id).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Internal {
            message: e.to_string(),
        })
    })?;

    // Mark the current session based on JTI match
    let sessions_info: Vec<SessionInfo> = sessions
        .into_iter()
        .map(|session| {
            let is_current = current_jti
                .as_ref()
                .map(|jti| jti == &session.id)
                .unwrap_or(false);
            SessionInfo {
                id: session.id,
                user_id: session.user_id,
                ip_address: session.ip_address,
                user_agent: session.user_agent,
                last_accessed: session.last_accessed,
                created_at: session.created_at,
                expires_at: session.expires_at,
                is_current,
                metadata: HashMap::new(), // Service Session currently doesn't export metadata publicly, using empty
            }
        })
        .collect();

    Ok(Json(ApiResponse::success(sessions_info)))
}

/// Revoke a user session
pub async fn revoke_session(
    State(state): State<Services>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResult<Json<ApiResponse<serde_json::Value>>> {
    // Extract and validate token
    let token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::ApiError(SecretonError::Authentication {
                message: "Missing or invalid authorization header".to_string(),
            })
        })?;

    // Get user from token
    let user = state.auth.validate_token(token).await.map_err(|e| {
        crate::error::ApiError(SecretonError::Authentication {
            message: e.to_string(),
        })
    })?;

    // Revoke the session via service
    state
        .auth
        .revoke_user_session(&session_id, &user.id)
        .await
        .map_err(|e| match e {
            AuthError::PermissionDenied => crate::error::ApiError(SecretonError::Authorization {
                message: "Access denied".to_string(),
            }),
            _ => crate::error::ApiError(SecretonError::NotFound {
                resource: "Session not found".to_string(),
            }),
        })?;

    let data = serde_json::json!({
        "message": "Session successfully revoked",
        "session_id": session_id
    });

    // Audit: Session revocation
    let _ = state
        .audit
        .log_event(SecurityEventType::Logout {
            user: user.username,
            session_id: session_id.clone(),
            ip_address: Some(extract_client_ip(&headers)),
            user_agent: Some(extract_user_agent(&headers)),
        })
        .await;

    Ok(Json(ApiResponse::success(data)))
}

/// Create a new user (admin only)
pub async fn create_user(
    State(state): State<Services>,
    AuthenticatedUser(admin_user): AuthenticatedUser,
    Json(request): Json<CreateUserRequest>,
) -> ApiResult<Json<ApiResponse<UserInfo>>> {
    // Check permissions
    if !admin_user.is_superuser
        && !admin_user.roles.contains(&"admin".to_string())
        && !admin_user.roles.contains(&"root".to_string())
    {
        return Err(crate::error::ApiError(SecretonError::Authorization {
            message: "Insufficient permissions".to_string(),
        }));
    }

    // Create user
    let user = state
        .auth
        .register_user(
            &request.username,
            &request.password,
            request.email,
            request.roles,
            request.permissions,
        )
        .await
        .map_err(|e| {
            crate::error::ApiError(SecretonError::Internal {
                message: e.to_string(),
            })
        })?;

    // Return info
    let user_info = UserInfo {
        id: Some(user.id),
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        roles: user.roles,
        permissions: user.permissions,
        metadata: user.metadata,
        last_login: user.last_login,
    };
    Ok(Json(ApiResponse::success(user_info)))
}

/// Extract client IP address from request headers
fn extract_client_ip(headers: &HeaderMap) -> String {
    // Try X-Forwarded-For first (for proxies/load balancers)
    if let Some(x_forwarded_for) = headers.get("x-forwarded-for")
        && let Ok(value) = x_forwarded_for.to_str()
    {
        // X-Forwarded-For can contain multiple IPs, take the first one
        if let Some(first_ip) = value.split(',').next() {
            return first_ip.trim().to_string();
        }
    }

    // Try X-Real-IP (for nginx)
    if let Some(x_real_ip) = headers.get("x-real-ip")
        && let Ok(value) = x_real_ip.to_str()
    {
        return value.to_string();
    }

    // Try X-Client-IP (for some proxies)
    if let Some(x_client_ip) = headers.get("x-client-ip")
        && let Ok(value) = x_client_ip.to_str()
    {
        return value.to_string();
    }

    // Fallback to unknown
    "unknown".to_string()
}

/// Extract user agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Extract JTI from JWT token
fn extract_jti_from_token(token: &str, state: &Services) -> Option<String> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
    let secret = state.config.auth.jwt.secret.as_ref()?;
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&state.config.auth.jwt.issuer]);
    validation.set_audience(&[&state.config.auth.jwt.audience]);

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|data| data.claims.jti)
        .ok()
}
