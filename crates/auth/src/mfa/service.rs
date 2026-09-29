//! Unified MFA service combining all MFA methods

use crate::service::AuthMethodResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secreton_domain::SecretonError;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::email::*;
use super::hardware::*;
use super::push::*;
use super::recovery::*;
use super::sms::*;
use super::totp::*;
use super::webauthn::*;

/// MFA method types
#[derive(Debug, Clone, PartialEq)]
pub enum MfaMethod {
    Totp,
    Sms,
    Email,
    Hardware,
    Push,
    WebAuthn,
    Recovery,
}

/// MFA enrollment status
#[derive(Debug, Clone)]
pub struct MfaEnrollment {
    pub entity_id: Uuid,
    pub methods: Vec<MfaMethod>,
    pub required_methods: Vec<MfaMethod>,
    pub enrolled_at: DateTime<Utc>,
}

/// MFA validation request
#[derive(Debug)]
pub struct MfaValidationRequest {
    pub entity_id: Uuid,
    pub method: MfaMethod,
    pub code: Option<String>,
    pub hardware_request: Option<HardwareAuthenticationRequest>,
    pub push_notification_id: Option<Uuid>,
    pub push_response: Option<PushResponse>,
    pub webauthn_response: Option<AuthenticationResponse>,
}

/// MFA service trait
#[async_trait]
pub trait MfaService: Send + Sync {
    /// Enroll an entity for MFA with specific methods
    async fn enroll_entity(
        &self,
        entity_id: Uuid,
        methods: Vec<MfaMethod>,
    ) -> AuthMethodResult<MfaEnrollment>;

    /// Get MFA enrollment for an entity
    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<MfaEnrollment>>;

    /// Update MFA enrollment for an entity
    async fn update_enrollment(
        &self,
        entity_id: Uuid,
        methods: Vec<MfaMethod>,
    ) -> AuthMethodResult<MfaEnrollment>;

    /// Remove MFA enrollment for an entity
    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Validate MFA code for an entity
    async fn validate(&self, request: MfaValidationRequest) -> AuthMethodResult<bool>;

    /// Check if MFA is required for an entity
    async fn is_mfa_required(&self, entity_id: Uuid) -> AuthMethodResult<bool>;

    /// Enable TOTP for an entity
    async fn enable_totp(
        &self,
        entity_id: Uuid,
        issuer: String,
        account_name: String,
    ) -> AuthMethodResult<crate::mfa::totp::TotpEnrollment>;

    /// Disable TOTP for an entity
    async fn disable_totp(&self, entity_id: Uuid) -> AuthMethodResult<()>;

    /// Enable SMS for an entity
    async fn enable_sms(&self, entity_id: Uuid, phone_number: String) -> AuthMethodResult<()>;

    /// Enable Email for an entity
    async fn enable_email(&self, entity_id: Uuid, email: String) -> AuthMethodResult<()>;

    /// Start WebAuthn registration
    async fn start_webauthn_registration(
        &self,
        entity_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> AuthMethodResult<crate::mfa::webauthn::RegistrationChallenge>;

    /// Complete WebAuthn registration
    async fn complete_webauthn_registration(
        &self,
        response: crate::mfa::webauthn::RegistrationResponse,
    ) -> AuthMethodResult<crate::mfa::webauthn::WebAuthnCredential>;

    /// Regenerate recovery codes for an entity
    async fn regenerate_recovery_codes(&self, entity_id: Uuid) -> AuthMethodResult<Vec<String>>;
}

/// Combined MFA service implementation
pub struct CombinedMfaService {
    totp_service: Arc<dyn TotpService>,
    sms_service: Arc<dyn SmsService>,
    email_service: Arc<dyn EmailService>,
    hardware_service: Arc<dyn HardwareService>,
    push_service: Arc<dyn PushService>,
    webauthn_service: Arc<dyn WebAuthnService>,
    recovery_service: Arc<dyn RecoveryCodeService>,
    enrollments: RwLock<HashMap<Uuid, MfaEnrollment>>,
}

impl CombinedMfaService {
    pub fn new(
        totp_service: Arc<dyn TotpService>,
        sms_service: Arc<dyn SmsService>,
        email_service: Arc<dyn EmailService>,
        hardware_service: Arc<dyn HardwareService>,
        push_service: Arc<dyn PushService>,
        webauthn_service: Arc<dyn WebAuthnService>,
        recovery_service: Arc<dyn RecoveryCodeService>,
    ) -> Self {
        Self {
            totp_service,
            sms_service,
            email_service,
            hardware_service,
            push_service,
            webauthn_service,
            recovery_service,
            enrollments: RwLock::new(HashMap::new()),
        }
    }

    /// Enable TOTP for an entity
    pub async fn enable_totp(
        &self,
        entity_id: Uuid,
        account_name: String,
    ) -> AuthMethodResult<TotpEnrollment> {
        self.enable_totp_owned(entity_id, account_name, None, None)
            .await
    }

    /// Enable TOTP for an entity, stamping the persisted enrollment with `owner`.
    ///
    /// Initialization uses this so the enrollment it creates is removable by the same
    /// ownership-conditional cleanup that removes the rest of a failed attempt's artifacts.
    /// Passing `fence` also makes the write itself conditional on the attempt still holding
    /// its lease, so an attempt that has lost it cannot create the enrollment at all — see
    /// [`TotpService::enroll_owned`].
    pub async fn enable_totp_owned(
        &self,
        entity_id: Uuid,
        account_name: String,
        owner: Option<&str>,
        fence: Option<secreton_storage::StorageFence<'_>>,
    ) -> AuthMethodResult<TotpEnrollment> {
        // Enroll in TOTP service
        let enrollment = self
            .totp_service
            .enroll_owned(entity_id, account_name, owner, fence)
            .await
            .map_err(|e| SecretonError::Internal {
                message: e.to_string(),
            })?;

        // Update central enrollment
        let mut enrollments = self.enrollments.write().await;
        let user_enrollment = enrollments
            .entry(entity_id)
            .or_insert_with(|| MfaEnrollment {
                entity_id,
                methods: Vec::new(),
                required_methods: Vec::new(),
                enrolled_at: Utc::now(),
            });

        if !user_enrollment.methods.contains(&MfaMethod::Totp) {
            user_enrollment.methods.push(MfaMethod::Totp);
        }

        Ok(enrollment)
    }

    /// Regenerate recovery codes
    pub async fn regenerate_recovery_codes(
        &self,
        entity_id: Uuid,
    ) -> AuthMethodResult<Vec<String>> {
        let response = self.recovery_service.generate_codes(entity_id).await?;

        // Update central enrollment
        let mut enrollments = self.enrollments.write().await;
        let user_enrollment = enrollments
            .entry(entity_id)
            .or_insert_with(|| MfaEnrollment {
                entity_id,
                methods: Vec::new(),
                required_methods: Vec::new(),
                enrolled_at: Utc::now(),
            });

        if !user_enrollment.methods.contains(&MfaMethod::Recovery) {
            user_enrollment.methods.push(MfaMethod::Recovery);
        }

        Ok(response.codes)
    }

    /// Verify TOTP code
    pub async fn verify_totp(&self, entity_id: Uuid, code: &str) -> AuthMethodResult<bool> {
        let request = MfaValidationRequest {
            entity_id,
            method: MfaMethod::Totp,
            code: Some(code.to_string()),
            hardware_request: None,
            push_notification_id: None,
            push_response: None,
            webauthn_response: None,
        };
        self.validate(request).await
    }

    /// Disable TOTP for an entity
    pub async fn disable_totp(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        if let Some(enrollment) = enrollments.get_mut(&entity_id) {
            enrollment.methods.retain(|m| *m != MfaMethod::Totp);
            enrollment
                .required_methods
                .retain(|m| *m != MfaMethod::Totp);
        }
        drop(enrollments);

        self.totp_service
            .remove_enrollment(entity_id)
            .await
            .map_err(|e| SecretonError::Internal {
                message: e.to_string(),
            })?;
        Ok(())
    }

    /// Enable SMS for an entity (initiate enrollment)
    pub async fn enable_sms_impl(
        &self,
        entity_id: Uuid,
        phone_number: String,
    ) -> AuthMethodResult<()> {
        self.sms_service.enroll(entity_id, phone_number).await?;
        self.sms_service.send_code(entity_id).await?;
        Ok(())
    }

    /// Verify and finalize SMS enrollment
    pub async fn verify_and_enable_sms(
        &self,
        entity_id: Uuid,
        code: String,
    ) -> AuthMethodResult<bool> {
        let request = SmsValidationRequest { entity_id, code };
        let is_valid = self.sms_service.validate(request).await?;

        if is_valid {
            let mut enrollments = self.enrollments.write().await;
            let entry = enrollments.entry(entity_id).or_insert(MfaEnrollment {
                entity_id,
                methods: Vec::new(),
                required_methods: Vec::new(),
                enrolled_at: Utc::now(),
            });

            if !entry.methods.contains(&MfaMethod::Sms) {
                entry.methods.push(MfaMethod::Sms);
            }
        }

        Ok(is_valid)
    }

    /// Enable Email for an entity (initiate enrollment)
    pub async fn enable_email_impl(&self, entity_id: Uuid, email: String) -> AuthMethodResult<()> {
        self.email_service.enroll(entity_id, email).await?;
        self.email_service.send_code(entity_id).await?;
        Ok(())
    }

    /// Verify and finalize Email enrollment
    pub async fn verify_and_enable_email(
        &self,
        entity_id: Uuid,
        code: String,
    ) -> AuthMethodResult<bool> {
        let request = EmailValidationRequest { entity_id, code };
        let is_valid = self.email_service.validate(request).await?;

        if is_valid {
            let mut enrollments = self.enrollments.write().await;
            let entry = enrollments.entry(entity_id).or_insert(MfaEnrollment {
                entity_id,
                methods: Vec::new(),
                required_methods: Vec::new(),
                enrolled_at: Utc::now(),
            });

            if !entry.methods.contains(&MfaMethod::Email) {
                entry.methods.push(MfaMethod::Email);
            }
        }

        Ok(is_valid)
    }

    /// Start WebAuthn registration
    pub async fn start_webauthn_registration_impl(
        &self,
        entity_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> AuthMethodResult<crate::mfa::webauthn::RegistrationChallenge> {
        self.webauthn_service
            .start_registration(entity_id, user_name, display_name)
            .await
    }

    /// Complete WebAuthn registration
    pub async fn complete_webauthn_registration_impl(
        &self,
        response: crate::mfa::webauthn::RegistrationResponse,
    ) -> AuthMethodResult<crate::mfa::webauthn::WebAuthnCredential> {
        let credential = self
            .webauthn_service
            .complete_registration(response)
            .await?;

        let mut enrollments = self.enrollments.write().await;
        let entry = enrollments
            .entry(credential.entity_id)
            .or_insert(MfaEnrollment {
                entity_id: credential.entity_id,
                methods: Vec::new(),
                required_methods: Vec::new(),
                enrolled_at: Utc::now(),
            });

        if !entry.methods.contains(&MfaMethod::WebAuthn) {
            entry.methods.push(MfaMethod::WebAuthn);
        }

        Ok(credential)
    }

    /// Validate based on MFA method
    async fn validate_method(&self, request: &MfaValidationRequest) -> AuthMethodResult<bool> {
        match &request.method {
            MfaMethod::Totp => {
                if let Some(code) = &request.code {
                    let totp_request = TotpValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.totp_service.validate(totp_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Sms => {
                if let Some(code) = &request.code {
                    let sms_request = SmsValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.sms_service.validate(sms_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Email => {
                if let Some(code) = &request.code {
                    let email_request = EmailValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                    };
                    self.email_service.validate(email_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Hardware => {
                if let Some(hw_request) = &request.hardware_request {
                    self.hardware_service.authenticate(hw_request.clone()).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Push => {
                // Push notification MFA validation
                if let (Some(notification_id), Some(response)) =
                    (&request.push_notification_id, &request.push_response)
                {
                    let push_request = PushValidationRequest {
                        entity_id: request.entity_id,
                        notification_id: *notification_id,
                        response: response.clone(),
                    };
                    self.push_service.validate(push_request).await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::WebAuthn => {
                // WebAuthn MFA validation
                if let Some(webauthn_response) = &request.webauthn_response {
                    self.webauthn_service
                        .complete_authentication(webauthn_response.clone())
                        .await
                } else {
                    Ok(false)
                }
            }
            MfaMethod::Recovery => {
                // Recovery code MFA validation
                if let Some(code) = &request.code {
                    let recovery_request = RecoveryCodeValidationRequest {
                        entity_id: request.entity_id,
                        code: code.clone(),
                        request_ip: None,
                    };
                    self.recovery_service.validate(recovery_request).await
                } else {
                    Ok(false)
                }
            }
        }
    }
}

#[async_trait]
impl MfaService for CombinedMfaService {
    async fn enroll_entity(
        &self,
        entity_id: Uuid,
        methods: Vec<MfaMethod>,
    ) -> AuthMethodResult<MfaEnrollment> {
        let enrollment = MfaEnrollment {
            entity_id,
            methods: methods.clone(),
            required_methods: methods, // All enrolled methods are required by default
            enrolled_at: Utc::now(),
        };

        let mut enrollments = self.enrollments.write().await;
        enrollments.insert(entity_id, enrollment.clone());

        Ok(enrollment)
    }

    async fn validate(&self, request: MfaValidationRequest) -> AuthMethodResult<bool> {
        // Try in-memory cache first for performance
        let enrollments = self.enrollments.read().await;
        let has_memory_enrollment = enrollments
            .get(&request.entity_id)
            .map(|e| e.methods.contains(&request.method))
            .unwrap_or(false);
        drop(enrollments);

        // If found in memory, proceed with validation logic that delegates to underlying service
        if has_memory_enrollment {
            return self.validate_method(&request).await;
        }

        // If not in memory, check if we should fallback to persistence
        // Specifically for TOTP, the PersistentTotpService manages its own storage.
        if request.method == MfaMethod::Totp {
            // Attempt to validate directly against the persistent service
            // This handles the case where the server restarted and memory cache is empty
            return self.validate_method(&request).await;
        }

        // For other methods, default to false if no enrollment found in memory (assuming they don't have persistence implemented same way yet)
        Ok(false)
    }

    async fn get_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<Option<MfaEnrollment>> {
        // Try in-memory first
        let enrollments = self.enrollments.read().await;
        if let Some(enrollment) = enrollments.get(&entity_id) {
            return Ok(Some(enrollment.clone()));
        }
        drop(enrollments);

        // Fallback to persistence for TOTP
        // This constructs a partial MfaEnrollment if TOTP exists
        if let Ok(Some(totp_enrollment)) = self.totp_service.get_enrollment(entity_id).await {
            // Construct enrollment object
            let enrollment = MfaEnrollment {
                entity_id,
                methods: vec![MfaMethod::Totp],
                required_methods: vec![MfaMethod::Totp], // Assume required if enrolled
                enrolled_at: totp_enrollment.creation_time,
            };

            // Populate cache for future use
            let mut enrollments_write = self.enrollments.write().await;
            enrollments_write.insert(entity_id, enrollment.clone());

            return Ok(Some(enrollment));
        }

        Ok(None)
    }

    async fn update_enrollment(
        &self,
        entity_id: Uuid,
        methods: Vec<MfaMethod>,
    ) -> AuthMethodResult<MfaEnrollment> {
        let mut enrollments = self.enrollments.write().await;

        if let Some(enrollment) = enrollments.get_mut(&entity_id) {
            enrollment.methods = methods.clone();
            enrollment.required_methods = methods;
            Ok(enrollment.clone())
        } else {
            Err(SecretonError::NotFound {
                resource: format!("mfa-enrollment:{}", entity_id),
            })
        }
    }

    async fn remove_enrollment(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        let mut enrollments = self.enrollments.write().await;
        enrollments.remove(&entity_id);
        drop(enrollments);

        // Also remove from individual services
        let _ = self.totp_service.remove_enrollment(entity_id).await;
        let _ = self.sms_service.remove_enrollment(entity_id).await;
        let _ = self.email_service.remove_enrollment(entity_id).await;

        // Remove all hardware enrollments for this entity
        if let Ok(hw_enrollments) = self.hardware_service.list_enrollments(entity_id).await {
            for enrollment in hw_enrollments {
                let _ = self
                    .hardware_service
                    .remove_enrollment(entity_id, enrollment.credential_id)
                    .await;
            }
        }

        // Remove push device enrollments
        if let Ok(push_devices) = self.push_service.list_devices(entity_id).await {
            for device in push_devices {
                let _ = self
                    .push_service
                    .remove_enrollment(entity_id, &device.device_id)
                    .await;
            }
        }

        // Remove WebAuthn credentials
        if let Ok(webauthn_creds) = self.webauthn_service.list_credentials(entity_id).await {
            for cred in webauthn_creds {
                let _ = self
                    .webauthn_service
                    .remove_credential(entity_id, &cred.credential_id)
                    .await;
            }
        }

        // Revoke recovery codes
        let _ = self.recovery_service.revoke_codes(entity_id).await;

        Ok(())
    }

    async fn is_mfa_required(&self, entity_id: Uuid) -> AuthMethodResult<bool> {
        // Try in-memory first
        let enrollments = self.enrollments.read().await;
        if enrollments.contains_key(&entity_id) {
            return Ok(true);
        }
        drop(enrollments);

        // Fallback to persistence check for TOTP
        // Using get_enrollment instead of exists logic for now as interface doesn't strictly have `exists`
        // Optimization: Could add `has_enrollment` to TotpService trait
        if let Ok(Some(_)) = self.totp_service.get_enrollment(entity_id).await {
            // Found in persistence, so MFA is required
            // We should ideally populate the cache here too, or let get_enrollment do it next time
            // For now, just return true
            return Ok(true);
        }

        Ok(false)
    }

    async fn enable_totp(
        &self,
        entity_id: Uuid,
        _issuer: String,
        account_name: String,
    ) -> AuthMethodResult<crate::mfa::totp::TotpEnrollment> {
        let enrollment = self.totp_service.enroll(entity_id, account_name).await?;

        // Update enrollment methods
        let mut enrollments = self.enrollments.write().await;
        let entry = enrollments.entry(entity_id).or_insert(MfaEnrollment {
            entity_id,
            methods: Vec::new(),
            required_methods: Vec::new(),
            enrolled_at: Utc::now(),
        });

        if !entry.methods.contains(&MfaMethod::Totp) {
            entry.methods.push(MfaMethod::Totp);
        }

        Ok(enrollment)
    }

    async fn disable_totp(&self, entity_id: Uuid) -> AuthMethodResult<()> {
        self.totp_service.remove_enrollment(entity_id).await?;

        // Update enrollment methods
        let mut enrollments = self.enrollments.write().await;
        if let Some(entry) = enrollments.get_mut(&entity_id) {
            entry.methods.retain(|m| *m != MfaMethod::Totp);

            // If no methods left, remove enrollment
            if entry.methods.is_empty() {
                enrollments.remove(&entity_id);
            }
        }

        Ok(())
    }

    async fn regenerate_recovery_codes(&self, entity_id: Uuid) -> AuthMethodResult<Vec<String>> {
        let response = self.recovery_service.generate_codes(entity_id).await?;

        // Ensure Recovery method is added to enrollment
        let mut enrollments = self.enrollments.write().await;
        let entry = enrollments.entry(entity_id).or_insert(MfaEnrollment {
            entity_id,
            methods: Vec::new(),
            required_methods: Vec::new(),
            enrolled_at: Utc::now(),
        });

        if !entry.methods.contains(&MfaMethod::Recovery) {
            entry.methods.push(MfaMethod::Recovery);
        }

        Ok(response.codes)
    }

    async fn enable_sms(&self, entity_id: Uuid, phone_number: String) -> AuthMethodResult<()> {
        self.enable_sms_impl(entity_id, phone_number).await
    }

    async fn enable_email(&self, entity_id: Uuid, email: String) -> AuthMethodResult<()> {
        self.enable_email_impl(entity_id, email).await
    }

    async fn start_webauthn_registration(
        &self,
        entity_id: Uuid,
        user_name: &str,
        display_name: &str,
    ) -> AuthMethodResult<crate::mfa::webauthn::RegistrationChallenge> {
        self.start_webauthn_registration_impl(entity_id, user_name, display_name)
            .await
    }

    async fn complete_webauthn_registration(
        &self,
        response: crate::mfa::webauthn::RegistrationResponse,
    ) -> AuthMethodResult<crate::mfa::webauthn::WebAuthnCredential> {
        self.complete_webauthn_registration_impl(response).await
    }
}
