//! TOTP (Time-based One-Time Password) MFA implementation

use async_trait::async_trait;
use base32::{decode, encode};
use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use rand::Rng;
use sha1::Sha1;
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    pub issuer: String,
    pub period: u32,       // Time step in seconds (usually 30)
    pub digits: u32,       // Number of digits (usually 6)
    pub algorithm: String, // Usually "SHA1"
}

/// TOTP enrollment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpEnrollment {
    pub id: Uuid,
    pub entity_id: Uuid,
    pub secret: String, // Base32 encoded secret
    pub url: String,    // otpauth:// URL
    pub creation_time: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
}

/// TOTP validation request
#[derive(Debug)]
pub struct TotpValidationRequest {
    pub entity_id: Uuid,
    pub code: String,
}

/// TOTP service trait
#[async_trait]
pub trait TotpService: Send + Sync {
    /// Enroll an entity for TOTP
    async fn enroll(
        &self,
        entity_id: Uuid,
        issuer: String,
    ) -> Result<TotpEnrollment, SecretonError>;

    /// Enroll an entity for TOTP, stamping the persisted enrollment with an owner token.
    ///
    /// Initialization enrolls the root account's TOTP through this, so the record carries
    /// the same fencing token as the rest of the attempt. Cleanup removes an attempt's
    /// artifacts with `delete_owned`, which matches on that token; an enrollment written
    /// without one is invisible to that path on a shared backend, which is what left an
    /// orphaned second factor behind a rollback that reported success. Backends without a
    /// conditional delete ignore the token and delegate to `enroll`.
    ///
    /// When `fence` is supplied the write is performed *through* it — the enrollment lands
    /// only while the named durable record still carries the token — so a caller that has
    /// lost its lease cannot write an enrollment at all. `owner` alone would only make the
    /// record removable afterwards; it would not stop the stale write. Backends without a
    /// fenced write must refuse rather than fall back to an unconditional store.
    ///
    /// This default implements exactly that refusal: a fence is a promise the trait cannot
    /// keep without a conditional write, so honouring it by delegating to `enroll` would
    /// silently discard it. The callers that pass a fence are the initialization sequence,
    /// where the fence is the only thing standing between a stale attempt and an orphaned
    /// second factor for a privileged account — a service that inherited this default and
    /// ignored the fence would create that enrollment anyway. A fence-free call (the
    /// ordinary user enrollment, and every single-process backend where no lease record
    /// exists) is unaffected. The persistent service in `secreton-engines` overrides this
    /// with a real fenced write; `InMemoryTotpService` does not, and is therefore only
    /// usable where no fence is ever supplied.
    async fn enroll_owned(
        &self,
        entity_id: Uuid,
        account_name: String,
        owner: Option<&str>,
        fence: Option<secreton_storage::StorageFence<'_>>,
    ) -> Result<TotpEnrollment, SecretonError> {
        let _ = owner;
        if fence.is_some() {
            return Err(SecretonError::Internal {
                message: "this TOTP service has no fenced write, so it cannot honour a \
                          lease fence; refusing rather than creating an unfenced \
                          enrollment for an initialization attempt"
                    .to_string(),
            });
        }
        self.enroll(entity_id, account_name).await
    }

    /// Validate a TOTP code
    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError>;

    /// Get enrollment for an entity
    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError>;

    /// Remove TOTP enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError>;
}

/// In-memory TOTP service implementation
pub struct InMemoryTotpService {
    enrollments: RwLock<HashMap<Uuid, TotpEnrollment>>,
    config: TotpConfig,
}

impl InMemoryTotpService {
    pub fn new(issuer: String) -> Self {
        Self {
            enrollments: RwLock::new(HashMap::new()),
            config: TotpConfig {
                issuer,
                period: 30,
                digits: 6,
                algorithm: "SHA1".to_string(),
            },
        }
    }

    /// Generate a random secret
    fn generate_secret() -> String {
        let mut rng = rand::thread_rng();
        let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
        encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
    }

    /// Generate TOTP code from secret and time
    fn generate_totp(
        secret: &str,
        time: u64,
        period: u32,
        digits: u32,
    ) -> Result<String, SecretonError> {
        let secret_bytes = decode(base32::Alphabet::Rfc4648 { padding: false }, secret)
            .ok_or_else(|| SecretonError::Configuration {
                message: "Invalid base32 secret".to_string(),
            })?;

        let counter = time / period as u64;

        // HMAC-SHA1
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes).map_err(|_| {
            SecretonError::Configuration {
                message: "Failed to create HMAC".to_string(),
            }
        })?;

        mac.update(&counter.to_be_bytes());
        let result = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (result[19] & 0xf) as usize;
        let code = ((result[offset] & 0x7f) as u32) << 24
            | (u32::from(result[offset + 1])) << 16
            | (u32::from(result[offset + 2])) << 8
            | u32::from(result[offset + 3]);

        let modulus = 10u32.pow(digits);
        let totp = code % modulus;

        Ok(format!("{:0width$}", totp, width = digits as usize))
    }

    /// Generate otpauth URL
    fn generate_url(&self, secret: &str, account_name: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm={}&digits={}&period={}",
            self.config.issuer,
            account_name,
            secret,
            self.config.issuer,
            self.config.algorithm,
            self.config.digits,
            self.config.period
        )
    }
}

#[async_trait]
impl TotpService for InMemoryTotpService {
    async fn enroll(
        &self,
        entity_id: Uuid,
        account_name: String,
    ) -> Result<TotpEnrollment, SecretonError> {
        let secret = Self::generate_secret();
        let url = self.generate_url(&secret, &account_name);

        let enrollment = TotpEnrollment {
            id: Uuid::new_v4(),
            entity_id,
            secret: secret.clone(),
            url,
            creation_time: Utc::now(),
            last_used: None,
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn validate(&self, request: TotpValidationRequest) -> Result<bool, SecretonError> {
        let enrollments = self.enrollments.read().await;

        if let Some(enrollment) = enrollments.get(&request.entity_id) {
            // Signed throughout, then converted once. Going through `as u64` and back
            // meant a clock at or before the epoch wrapped into an enormous value, and the
            // skew window then checked nonsense time steps.
            let current_time = Utc::now().timestamp();
            let period = i64::from(self.config.period);

            // Check current time window and adjacent windows for clock skew
            for time_offset in [-1i64, 0, 1].iter() {
                let Some(check_time) = current_time
                    .checked_add(time_offset * period)
                    .and_then(|t| u64::try_from(t).ok())
                else {
                    continue;
                };
                let expected_code = Self::generate_totp(
                    &enrollment.secret,
                    check_time,
                    self.config.period,
                    self.config.digits,
                )?;

                if expected_code == request.code {
                    // Update last used time
                    drop(enrollments);
                    let mut enrollments = self.enrollments.write().await;
                    if let Some(enrollment) = enrollments.get_mut(&request.entity_id) {
                        enrollment.last_used = Some(Utc::now());
                    }
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn get_enrollment(
        &self,
        entity_id: Uuid,
    ) -> Result<Option<TotpEnrollment>, SecretonError> {
        let enrollments = self.enrollments.read().await;
        Ok(enrollments.get(&entity_id).cloned())
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> Result<(), SecretonError> {
        let mut enrollments = self.enrollments.write().await;
        enrollments.remove(&entity_id);
        Ok(())
    }
}
