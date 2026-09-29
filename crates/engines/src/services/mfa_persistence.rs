use crate::services::crypto::CryptoService;
use async_trait::async_trait;
use chrono::Utc;
use rand::Rng;
use secreton_auth::mfa::{TotpConfig, TotpEnrollment, TotpService, TotpValidationRequest};
use secreton_domain::SecretonError;
use secreton_storage::{
    EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend, StorageFence,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use totp_rs::{Algorithm, TOTP};
use uuid::Uuid;

pub struct PersistentTotpService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    config: TotpConfig,
    // Per-user locks to prevent replay race conditions within this instance
    user_locks: Arc<Mutex<HashMap<Uuid, Arc<Mutex<()>>>>>,
}

pub(crate) const TOTP_PREFIX: &str = "sys/mfa/totp/";

impl PersistentTotpService {
    pub fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        issuer: String,
    ) -> Self {
        Self {
            storage,
            crypto,
            config: TotpConfig {
                issuer,
                period: 30,
                digits: 6,
                algorithm: "SHA1".to_string(),
            },
            user_locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a random secret using totp-rs which handles Base32 encoding securely
    fn generate_secret() -> String {
        // Use standard RNG + Base32
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..20).map(|_| rng.r#gen()).collect();
        base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    // Internal helper to create TOTP instance
    fn create_totp_instance(&self, secret: &str) -> Result<TOTP, SecretonError> {
        let secret_bytes = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| SecretonError::Configuration {
                message: "Invalid base32 secret".to_string(),
            })?;

        let algorithm = match self.config.algorithm.as_str() {
            "SHA1" => Algorithm::SHA1,
            "SHA256" => Algorithm::SHA256,
            "SHA512" => Algorithm::SHA512,
            _ => Algorithm::SHA1,
        };

        TOTP::new(
            algorithm,
            self.config.digits as usize,
            1, // skew
            self.config.period as u64,
            secret_bytes,
            Some(self.config.issuer.clone()),
            "".to_string(), // account_name not strictly needed for validation logic
        )
        .map_err(|e| SecretonError::Configuration {
            message: format!("Failed to create TOTP instance: {}", e),
        })
    }

    // Helper to acquire a lock for a specific user
    async fn acquire_user_lock(&self, user_id: Uuid) -> Arc<Mutex<()>> {
        let mut locks = self.user_locks.lock().await;
        locks
            .entry(user_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[async_trait]
impl TotpService for PersistentTotpService {
    async fn enroll(
        &self,
        entity_id: Uuid,
        account_name: String,
    ) -> Result<TotpEnrollment, SecretonError> {
        self.enroll_owned(entity_id, account_name, None, None).await
    }

    /// Persist the enrollment with the attempt's owner token when one is supplied.
    ///
    /// `enable_totp` from the ordinary MFA setup path passes `None`, which keeps the
    /// record unowned and therefore ineligible for an ownership-conditional cleanup — the
    /// right behaviour for a user-managed enrollment, which no rollback should remove.
    /// Initialization passes its lease token so a failed attempt's cleanup can remove the
    /// enrollment it created; on a shared backend that cleanup only deletes records whose
    /// token matches, so a token-less enrollment would be invisible to it.
    ///
    /// When `fence` is supplied the record is written through
    /// [`StorageBackend::store_fenced`] rather than `store`, so the write itself only lands
    /// while the named lease record still carries the token. That is the difference between
    /// "removable afterwards" and "cannot be written at all once the lease is gone", and it
    /// is what stops a stale attempt from leaving an orphaned second factor behind.
    async fn enroll_owned(
        &self,
        entity_id: Uuid,
        account_name: String,
        owner: Option<&str>,
        fence: Option<StorageFence<'_>>,
    ) -> Result<TotpEnrollment, SecretonError> {
        let _user_lock = self.acquire_user_lock(entity_id).await;
        let _guard = _user_lock.lock().await;

        let secret = Self::generate_secret();

        let url = format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            self.config.issuer,
            account_name,
            secret,
            self.config.issuer,
            self.config.algorithm,
            self.config.digits,
            self.config.period
        );

        let enrollment = TotpEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            secret: secret.clone(),
            url,
            creation_time: Utc::now(),
            last_used: None,
        };

        // Serialize
        let data = serde_json::to_vec(&enrollment).map_err(|e| SecretonError::Internal {
            message: format!("Failed to serialize enrollment: {}", e),
        })?;

        // Encrypt data
        let encrypted_data =
            self.crypto
                .encrypt_data(&data)
                .await
                .map_err(|e| SecretonError::Encryption {
                    message: format!("Failed to encrypt TOTP data: {}", e),
                })?;

        let path = format!("{}{}", TOTP_PREFIX, entity_id);

        let mut entry = SecretEntry::new(
            path,
            encrypted_data,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            entity_id,
        );
        if let Some(owner) = owner {
            entry = entry.owned_by(owner);
        }

        match fence {
            Some(fence) => {
                let written = self
                    .storage
                    .store_fenced(&entry, fence)
                    .await
                    .map_err(|e| SecretonError::Database {
                        message: format!("Failed to store enrollment: {}", e),
                    })?;
                if !written {
                    return Err(SecretonError::Database {
                        message: "the initialization lease was lost before the TOTP \
                                  enrollment could be written"
                            .to_string(),
                    });
                }
            }
            None => {
                self.storage
                    .store(&entry)
                    .await
                    .map_err(|e| SecretonError::Database {
                        message: format!("Failed to store enrollment: {}", e),
                    })?;
            }
        }

        Ok(enrollment)
    }

    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError> {
        // Serialize validation requests for the same user to prevent replay race conditions
        let _user_lock = self.acquire_user_lock(request.entity_id).await;
        let _guard = _user_lock.lock().await;

        let path = format!("{}{}", TOTP_PREFIX, request.entity_id);

        if let Some(entry) =
            self.storage
                .get_by_path(&path)
                .await
                .map_err(|e| SecretonError::Database {
                    message: e.to_string(),
                })?
        {
            // Decrypt data
            let decrypted_data = self
                .crypto
                .decrypt(&entry.encrypted_data)
                .await
                .map_err(|e| SecretonError::Decryption {
                    message: format!("Failed to decrypt TOTP data: {}", e),
                })?;

            let mut enrollment: TotpEnrollment =
                serde_json::from_slice(&decrypted_data).map_err(|e| SecretonError::Internal {
                    message: format!("Failed to deserialize enrollment: {}", e),
                })?;

            let current_time = Utc::now();
            let current_timestamp = u64::try_from(current_time.timestamp()).unwrap_or(0);

            // Replay protection: Check last_used against current time window
            // Allow a small grace period or strictly check if used within the same window
            if let Some(last_used) = enrollment.last_used {
                let window_size = self.config.period as i64;
                // If used within the last window (or slightly more to be safe), reject.
                // A stricter check is: (current / period) <= (last_used / period)
                // If last used was in the same or future window (clock skew?), reject.
                let last_window = last_used.timestamp() / window_size;
                let current_window = current_timestamp as i64 / window_size;

                if last_window >= current_window {
                    tracing::warn!("TOTP Replay detected for user {}", request.entity_id);
                    return Ok(false);
                }
            }

            // Use totp-rs for validation (it handles constant-time comparison internally)
            let totp = self.create_totp_instance(&enrollment.secret)?;

            // Validate against current time (totp-rs handles skew if configured, we passed skew=1)
            let is_valid = totp.check(&request.code, current_timestamp);

            if is_valid {
                // Update last used time
                enrollment.last_used = Some(current_time);

                let data =
                    serde_json::to_vec(&enrollment).map_err(|e| SecretonError::Internal {
                        message: format!("Failed to serialize enrollment: {}", e),
                    })?;

                // Encrypt again
                let encrypted_data = self.crypto.encrypt_data(&data).await.map_err(|e| {
                    SecretonError::Encryption {
                        message: format!("Failed to encrypt updated TOTP data: {}", e),
                    }
                })?;

                let mut updated_entry = entry.clone();
                updated_entry.encrypted_data = encrypted_data;

                self.storage
                    .store(&updated_entry)
                    .await
                    .map_err(|e| SecretonError::Database {
                        message: format!("Failed to update enrollment: {}", e),
                    })?;

                return Ok(true);
            }
            // Code is invalid
            Ok(false)
        } else {
            // Enrollment not found
            // Return error to distinguish from invalid code, as suggested by review
            Err(SecretonError::NotFound {
                resource: format!("MFA enrollment for user {}", request.entity_id),
            })
        }
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError> {
        let path = format!("{}{}", TOTP_PREFIX, entity_id);

        if let Some(entry) =
            self.storage
                .get_by_path(&path)
                .await
                .map_err(|e| SecretonError::Database {
                    message: e.to_string(),
                })?
        {
            // Decrypt data
            let decrypted_data = self
                .crypto
                .decrypt(&entry.encrypted_data)
                .await
                .map_err(|e| SecretonError::Decryption {
                    message: format!("Failed to decrypt TOTP data: {}", e),
                })?;

            let enrollment: TotpEnrollment =
                serde_json::from_slice(&decrypted_data).map_err(|e| SecretonError::Internal {
                    message: format!("Failed to deserialize enrollment: {}", e),
                })?;
            Ok(Some(enrollment))
        } else {
            Ok(None)
        }
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError> {
        let _user_lock = self.acquire_user_lock(entity_id).await;
        let _guard = _user_lock.lock().await;

        let path = format!("{}{}", TOTP_PREFIX, entity_id);
        self.storage
            .delete_by_path(&path)
            .await
            .map_err(|e| SecretonError::Database {
                message: format!("Failed to delete enrollment: {}", e),
            })?;
        Ok(())
    }
}
