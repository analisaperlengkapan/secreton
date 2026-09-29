//! User/password authentication method

use crate::model::*;
use crate::service::*;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::phc::Salt};
use async_trait::async_trait;
use chrono::Utc;
use secreton_domain::SecretonError;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// User/password authentication method
pub struct UserPassAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    users: RwLock<HashMap<String, UserEntry>>,
}

impl UserPassAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            users: RwLock::new(HashMap::new()),
        }
    }

    /// Add a user with hashed password.
    ///
    /// `password_login_disabled` marks the bootstrap root identity: an account that owns
    /// the vault but was never issued a password. The flag is the boundary, not the
    /// username — a deployment that renamed root still gets the same protection.
    // Named like the record it populates; a wrapper type would add a conversion at every
    // call site for no clarity.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_user(
        &self,
        username: String,
        password_hash: String,
        id: String,
        groups: Vec<String>,
        policies: Vec<String>,
        permissions: Vec<String>,
        password_login_disabled: bool,
    ) {
        let user_entry = UserEntry {
            username: username.to_string(),
            password_hash,
            id,
            groups,
            policies,
            roles: vec![], // Added roles
            permissions,
            metadata: HashMap::new(),
            password_login_disabled,
        };

        let mut users = self.users.write().await;
        users.insert(username, user_entry);
    }

    /// Hash a raw password and return the PHC string, without registering anything.
    ///
    /// Registration is a durable-write decision, not a hashing one. Exposing hashing alone
    /// lets the caller build the account record and commit it atomically (insert-if-absent),
    /// then publish the in-memory login identity only after the durable write wins. Keeping
    /// hashing and registration together forced that caller to register in memory *before*
    /// storage could refuse a duplicate, which is how an in-memory identity for an account
    /// that was never written could exist.
    pub fn hash_password(&self, password: &str) -> AuthMethodResult<String> {
        let salt = Salt::generate();
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password_with_salt(password.as_bytes(), salt.as_ref())
            .map_err(|_| SecretonError::Internal {
                message: "Password hashing failed".to_string(),
            })?
            .to_string();
        Ok(password_hash)
    }

    /// Create a user with raw password (hashes it), registering it in the in-memory map.
    ///
    /// Kept for callers that only manage the in-memory method; the durable registration path
    /// uses [`Self::hash_password`] so it can publish the identity after storage commits.
    pub async fn create_user(
        &self,
        username: String,
        password: &str,
        id: String,
        groups: Vec<String>,
        policies: Vec<String>,
        permissions: Vec<String>,
    ) -> AuthMethodResult<String> {
        let password_hash = self.hash_password(password)?;
        self.add_user(
            username,
            password_hash.clone(),
            id,
            groups,
            policies,
            permissions,
            false,
        )
        .await;
        Ok(password_hash)
    }

    /// Register the bootstrap root identity: a privileged account with no password.
    ///
    /// No hash is stored at all, so there is no generated credential to leak and nothing
    /// for a password verifier to accept. Combined with `password_login_disabled` this
    /// holds even if a hash were later planted on the record.
    pub async fn add_bootstrap_root(
        &self,
        username: String,
        id: String,
        groups: Vec<String>,
        policies: Vec<String>,
        permissions: Vec<String>,
    ) {
        self.add_user(
            username,
            String::new(),
            id,
            groups,
            policies,
            permissions,
            true,
        )
        .await;
    }

    /// Verify password against hash
    fn check_password(&self, password: &str, hash: &str) -> AuthMethodResult<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|_| SecretonError::InvalidCredentials)?;

        let argon2 = Argon2::default();
        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Get user entry
    async fn get_user(&self, username: &str) -> Option<UserEntry> {
        let users = self.users.read().await;
        users.get(username).cloned()
    }
}

impl Default for UserPassAuthMethod {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthMethodImpl for UserPassAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::UserPass
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());
        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(SecretonError::AuthMethodDisabled);
        }

        match credentials {
            AuthCredentials::UserPass { username, password } => {
                if let Some(user_entry) = self.get_user(username).await {
                    // The bootstrap root identity is never password-authenticatable. The
                    // check is on the account's persisted property, so it covers the
                    // account regardless of the name it was created under, and it fails
                    // closed before a hash is even considered.
                    if user_entry.password_login_disabled {
                        return Err(SecretonError::InvalidCredentials);
                    }
                    if self.check_password(password, &user_entry.password_hash)? {
                        let user_info = UserInfo {
                            id: Some(user_entry.id.clone()),
                            username: user_entry.username.to_string(),
                            email: None,
                            display_name: None,
                            roles: user_entry.groups.clone(), // Map groups to roles
                            permissions: user_entry.permissions.clone(),
                            metadata: user_entry.metadata.clone(),
                            last_login: Some(Utc::now()),
                        };

                        Ok(AuthResult {
                            success: true,
                            user_info: Some(user_info),
                            token: None, // Token will be generated by the service
                            refresh_token: None,
                            policies: user_entry.policies.clone(),
                            metadata: HashMap::new(),
                            mfa_required: false, // Could be extended for MFA
                        })
                    } else {
                        Err(SecretonError::InvalidCredentials)
                    }
                } else {
                    Err(SecretonError::InvalidCredentials)
                }
            }
            _ => Err(SecretonError::InvalidCredentials),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        // Token validation is handled by the token method
        Err(SecretonError::AuthMethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        // Token revocation is handled by the token method
        Err(SecretonError::AuthMethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// User entry for userpass authentication
#[derive(Clone, Debug)]
pub struct UserEntry {
    pub username: String,
    pub password_hash: String,
    pub id: String,
    pub groups: Vec<String>,
    pub policies: Vec<String>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub metadata: HashMap<String, String>,
    /// Mirrors `User::password_login_disabled`: the bootstrap root identity is not
    /// password-authenticatable, whether or not a hash were present.
    pub password_login_disabled: bool,
}
