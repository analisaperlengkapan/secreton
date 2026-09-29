use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

/// User information structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: Option<String>,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub last_login: Option<DateTime<Utc>>,
}

/// MFA method enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    Hardware,
    Push,
    WebAuthn,
    Recovery,
}

impl MfaMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            MfaMethod::Totp => "totp",
            MfaMethod::Sms => "sms",
            MfaMethod::Email => "email",
            MfaMethod::Hardware => "hardware",
            MfaMethod::Push => "push",
            MfaMethod::WebAuthn => "webauthn",
            MfaMethod::Recovery => "recovery",
        }
    }
}

impl FromStr for MfaMethod {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "totp" => Ok(MfaMethod::Totp),
            "sms" => Ok(MfaMethod::Sms),
            "email" => Ok(MfaMethod::Email),
            "hardware" => Ok(MfaMethod::Hardware),
            "push" => Ok(MfaMethod::Push),
            "webauthn" => Ok(MfaMethod::WebAuthn),
            "recovery" => Ok(MfaMethod::Recovery),
            _ => Err(format!("Unknown MFA method: {}", s)),
        }
    }
}

/// MFA configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaConfig {
    pub enabled: bool,
    pub method: MfaMethod,
    pub secret: Option<String>,
    pub recovery_codes: Vec<String>,
}

/// MFA setup request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupRequest {
    pub method: MfaMethod,
    pub email: Option<String>, // Required if method is Email
}

/// MFA setup response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetupResponse {
    pub qr_code_url: Option<String>,                          // For TOTP
    pub secret: Option<String>,                               // For TOTP
    pub webauthn_register_options: Option<serde_json::Value>, // For WebAuthn
}

/// MFA verification request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerifyRequest {
    pub code: String, // TOTP code or recovery code
}

/// MFA status response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaStatusResponse {
    pub is_enabled: bool,
    pub method: Option<String>,
    pub setup_required: bool,
    pub enabled_methods: Vec<String>,
}

/// MFA login request
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaLoginRequest {
    pub username: String,
    pub password: String,
    pub code: Option<String>, // MFA code if MFA is enabled
}

/// MFA recovery codes response
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaRecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

/// MFA verification result
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    pub is_valid: bool,
    pub method: MfaMethod,
    pub message: Option<String>,
}

/// Refresh token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Authentication request (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthRequest {
    Token { token: String },
    UserPass { username: String, password: String },
    Ldap { username: String, password: String },
    Oidc { code: String, state: String },
    Okta { username: String, password: String },
    Github { token: String },
    Radius { username: String, password: String },
    AppRole { role_id: String, secret_id: String },
    Kubernetes { jwt: String },
}

/// Authentication response (legacy compatibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub authenticated: bool,
    pub user_info: UserInfo,
    pub policies: Vec<String>,
    pub lease_duration: i64,
    pub renewable: bool,
    pub token: String,
    pub accessor: String,
    pub metadata: HashMap<String, String>,
}

/// Legacy token structure for backward compatibility
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyToken {
    pub token: String,
    pub user: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub orphan: bool,
    pub batch: bool,
    pub locked: bool,
    pub created_at: DateTime<Utc>,
}

/// Authentication method type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthMethodType {
    Token,
    UserPass,
    Ldap,
    Oidc,
    OAuth2,
    AppRole,
    Kubernetes,
    AwsIam,
    Github,
    Okta,
    Radius,
    Saml,
    Certificate,
}

/// Authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthCredentials {
    Token {
        token: String,
    },
    UserPass {
        username: String,
        password: String,
    },
    Ldap {
        username: String,
        password: String,
    },
    Oidc {
        code: String,
        state: String,
    },
    OAuth2 {
        code: String,
        state: String,
    },
    AppRole {
        role_id: String,
        secret_id: String,
    },
    Kubernetes {
        jwt: String,
        role: Option<String>,
    },
    AwsIam {
        iam_request_url: String,
        iam_request_body: String,
        iam_request_headers: String,
    },
    Github {
        token: String,
    },
    Okta {
        username: String,
        password: String,
    },
    Radius {
        username: String,
        password: String,
    },
    Saml {
        saml_response: String,
    },
    Certificate {
        certificate: String,
    },
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub user_info: Option<UserInfo>,
    pub token: Option<String>,
    pub refresh_token: Option<String>,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub mfa_required: bool,
}

/// Login request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
    pub remember_me: Option<bool>,
}

/// Login response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub user_info: Option<UserInfo>,
    pub mfa_required: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Authentication method configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthMethod {
    pub method_type: AuthMethodType,
    pub enabled: bool,
    pub config: HashMap<String, serde_json::Value>,
}

/// User entity
///
/// `Default` is derived so tests and builders can construct one without listing twenty
/// fields. A defaulted user is inert: not active, not enabled, no roles, empty password
/// hash — so an accidentally-defaulted user cannot authenticate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub disabled: bool,
    pub password_hash: String,
    /// True for the bootstrap root identity `init` creates: an account that owns the
    /// vault but was never given a password it could authenticate with.
    ///
    /// The boundary that keeps this account out of the password-login path is this
    /// persisted property of the account, not the spelling of the username it was created
    /// under. A literal `"root"` check was the whole guard before custom root usernames
    /// existed, and it silently stopped covering the account the moment the name became
    /// configurable. Defaults to false so records written before the field existed
    /// deserialize as ordinary password-authenticatable accounts.
    #[serde(default)]
    pub password_login_disabled: bool,
    pub full_name: Option<String>,
    pub is_active: bool,
    pub is_superuser: bool,
    pub enabled: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub last_login: Option<DateTime<Utc>>,
    #[serde(default)]
    pub failed_login_attempts: u32,
    #[serde(default)]
    pub locked_until: Option<DateTime<Utc>>,
}

impl User {
    /// Check if the user is a superuser (Root)
    pub fn is_root(&self) -> bool {
        self.is_superuser || self.roles.contains(&"root".to_string())
    }

    /// Check if the user is an administrator
    pub fn is_admin(&self) -> bool {
        self.is_root() || self.roles.contains(&"admin".to_string())
    }

    /// Check if the user is a privileged user (Admin or Root)
    pub fn is_privileged(&self) -> bool {
        self.is_admin()
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}
