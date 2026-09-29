//! Typed service graph.
//!
//! Replaces the previous `ApiServiceContainer`, which paired these same fields with a
//! `HashMap<String, Box<dyn Any>>` registry and resolved services by string name. Every
//! lookup was a runtime downcast that could fail — and did: the router resolved
//! `"admin"` from a field that actually held the audit service. Handlers now take
//! `Services` directly, so a wiring mistake is a compile error.

pub mod admin;
pub mod audit;
pub mod audit_storage;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod database;
pub mod lifecycle;
pub mod mfa_persistence;
pub mod pki;
pub mod seal;
pub mod secret;
pub mod ssh;
#[cfg(test)]
pub mod tests_audit_integration;
pub mod totp_engine;

use std::sync::Arc;

use anyhow::Result;
use secreton_auth::mfa::{
    CombinedMfaService, DefaultPushService, DefaultRecoveryCodeService, DefaultWebAuthnService,
    EmailConfig, InMemoryEmailService, InMemoryHardwareService, InMemorySmsService, SmsConfig,
    SmsProvider,
};
use secreton_auth::policies::service::PolicyService;
use secreton_auth::{IdentityService, InMemoryIdentityService};
use secreton_storage::{StorageBackend, StorageFactory};

use crate::config::ServerConfig;
use crate::lifecycle::LifecycleConfig;
use crate::performance::{SecretPerformanceConfig, SecretPerformanceOptimizer};
use crate::services::audit::AuditLogger;
use crate::services::auth::AuthenticationService;
use crate::services::crypto::CryptoService;
use crate::services::seal::SealService;
use crate::telemetry::{TelemetryCollector, TelemetryConfig};

/// Every service the server needs, constructed once at startup and shared by `Arc`.
#[derive(Clone)]
pub struct Services {
    pub config: Arc<ServerConfig>,
    pub storage: Arc<dyn StorageBackend + Send + Sync>,
    pub crypto: Arc<CryptoService>,
    pub seal: Arc<SealService>,
    pub audit: Arc<AuditLogger>,
    pub auth: Arc<AuthenticationService>,
    pub policy: Arc<PolicyService>,
    pub secret: Arc<secret::SecretService>,
    pub admin: Arc<admin::AdminService>,
    pub database: Arc<database::DatabaseService>,
    pub pki: Arc<pki::PkiPersistentService>,
    pub ssh: Arc<ssh::SshPersistentService>,
    pub transit: Arc<secreton_crypto::transit::TransitEngine>,
    pub totp_engine: Arc<totp_engine::TotpEngineService>,
    pub performance: Arc<SecretPerformanceOptimizer>,
    pub mfa: Arc<CombinedMfaService>,
    pub telemetry: Arc<TelemetryCollector>,
    pub identity: Arc<dyn IdentityService + Send + Sync>,
    pub lifecycle: Arc<lifecycle::LifecycleService>,
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: several of these hold key material, and `Services` ends up
        // inside axum state that gets `Debug`-formatted in error paths.
        f.write_str("Services { .. }")
    }
}

impl Services {
    /// Build the whole service graph from configuration.
    pub async fn new(config: &ServerConfig) -> Result<Self> {
        let mut config_clone = config.clone();
        if config_clone.audit.enabled {
            if config_clone.audit.retention_days == 0 {
                tracing::error!("Audit retention_days is 0, enforcing safe default of 2555");
                config_clone.audit.retention_days = 2555;
            }
            if config_clone.audit.max_batch_size == 0 {
                tracing::error!("Audit max_batch_size is 0, enforcing safe default of 100");
                config_clone.audit.max_batch_size = 100;
            }
        }

        // Initialize storage backend
        let storage = StorageFactory::create(config.storage.clone()).await?;

        // Initialize crypto service
        let crypto = Arc::new(CryptoService::new(storage.clone()).await?);

        // A missing JWT secret must stop the process at startup rather than panic deep
        // inside service construction, and must never be silently generated: a secret
        // invented at boot invalidates every token the moment the process restarts.
        // The value itself is read by the auth and token services; this call only asserts
        // that it is present.
        config.auth.jwt.secret.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "auth.jwt.secret is not configured. Set SECRETON__AUTH__JWT__SECRET or the \
                 `secret` key under [auth.jwt]; refusing to start with a generated one."
            )
        })?;

        // Initialize seal service. It is handed the auth service below, once that exists,
        // because it needs it to record the session behind the root token it issues.
        let seal = Arc::new(SealService::new(storage.clone(), crypto.clone()));

        // Initialize audit logger
        let audit = Arc::new(
            AuditLogger::new(
                storage.clone(),
                config_clone.audit.retention_days,
                config_clone.audit.max_batch_size,
                config_clone.audit.enabled,
            )
            .await?,
        );

        // Initialize MFA Services first (needed for Auth)
        let mfa_config = &config.auth.mfa;

        let totp_service = Arc::new(mfa_persistence::PersistentTotpService::new(
            storage.clone(),
            crypto.clone(),
            mfa_config.totp.issuer.clone(),
        ));

        // Configure SMS Config
        let sms_config = if let Some(sms) = &mfa_config.sms {
            SmsConfig {
                provider: match sms.provider.to_lowercase().as_str() {
                    "twilio" => SmsProvider::Twilio,
                    "awssns" | "aws_sns" => SmsProvider::AwsSns,
                    "nexmo" => SmsProvider::Nexmo,
                    _ => SmsProvider::Custom {
                        url: "http://localhost/sms".to_string(),
                    },
                },
                api_key: sms.api_key.clone(),
                api_secret: None,
                from_number: sms.from_number.clone(),
                message_template: "Your Secreton code is {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        } else {
            SmsConfig::default()
        };
        let sms_service = Arc::new(InMemorySmsService::new(sms_config));

        // Configure Email Config
        let email_config = if let Some(email) = &mfa_config.email {
            EmailConfig {
                smtp_server: email.smtp_server.clone(),
                smtp_port: email.smtp_port,
                smtp_username: email.username.clone(),
                smtp_password: email.password.clone(),
                from_email: email.from_address.clone(),
                subject_template: "Secreton Verification Code".to_string(),
                body_template: "Your verification code is: {code}".to_string(),
                code_length: 6,
                code_expiry_seconds: 300,
            }
        } else {
            EmailConfig::default()
        };
        let email_service = Arc::new(InMemoryEmailService::new(email_config));

        let hardware_service = Arc::new(InMemoryHardwareService::new());
        let push_service = Arc::new(DefaultPushService::new_mock());
        let webauthn_service = Arc::new(DefaultWebAuthnService::new_default());
        let recovery_service = Arc::new(DefaultRecoveryCodeService::new());

        let mfa = Arc::new(CombinedMfaService::new(
            totp_service,
            sms_service,
            email_service,
            hardware_service,
            push_service,
            webauthn_service,
            recovery_service,
        ));

        // Initialize authentication service
        let auth = Arc::new(
            AuthenticationService::new(storage.clone(), crypto.clone(), &config.auth)
                .await?
                .with_audit(audit.clone())
                .with_mfa(mfa.clone()),
        );

        // Give the seal service the auth service, so a successful unseal can issue a root
        // token that is bound to a real session and therefore actually usable.
        let seal = seal.with_auth(auth.clone());
        // And the audit logger, so both the success and the failure of an unseal are
        // recorded — the failure is the one a reviewer needs to see.
        let seal = seal.with_audit(audit.clone());

        // Initialize policy service
        let policy_service = Arc::new(PolicyService::new());
        // Initialize identity service
        let identity: Arc<dyn IdentityService + Send + Sync> =
            Arc::new(InMemoryIdentityService::new());

        // Initialize secret performance optimizer
        let performance = Arc::new(SecretPerformanceOptimizer::new(
            SecretPerformanceConfig::default(),
        ));

        // Initialize secret service.
        let secreton_inner = secret::SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            identity.clone(),
            policy_service.clone(),
            performance.clone(),
        )
        .await?;

        // Initialize database service
        let database = Arc::new(database::DatabaseService::new(
            storage.clone(),
            crypto.clone(),
        ));

        // Initialize PKI service
        let pki = Arc::new(pki::PkiPersistentService::new(
            storage.clone(),
            crypto.clone(),
        ));

        // Initialize SSH service
        let ssh = Arc::new(ssh::SshPersistentService::new(
            storage.clone(),
            crypto.clone(),
        ));

        // Initialize TOTP Engine service
        let totp_engine = Arc::new(totp_engine::TotpEngineService::new(
            storage.clone(),
            crypto.clone(),
        ));

        // Initialize admin service
        let admin = Arc::new(
            admin::AdminService::new(
                storage.clone(),
                auth.clone(),
                performance.clone(),
                audit.clone(),
            )
            .await?
            .with_crypto(crypto.clone()),
        );

        // Initialize Transit Engine
        let transit = Arc::new(secreton_crypto::transit::TransitEngine::new());

        // Initialize Telemetry
        let telemetry = Arc::new(TelemetryCollector::new(TelemetryConfig::default()));
        if let Err(e) = telemetry.start_collection().await {
            tracing::warn!("Failed to start telemetry collection: {}", e);
        }

        // Initialize Secret Lifecycle service.
        // Conservative defaults: the sweeper must be opted into explicitly so a fresh
        // deployment cannot silently delete expired secrets before an operator has
        // reviewed the retention policy.
        let lifecycle_config = LifecycleConfig {
            enabled: false,
            default_ttl_days: 90,
            grace_period_days: 7,
            auto_archive_enabled: false,
            cleanup_enabled: false,
        };
        let lifecycle = Arc::new(lifecycle::LifecycleService::new(
            storage.clone(),
            crypto.clone(),
            audit.clone(),
            lifecycle_config,
        ));

        // Inject lifecycle into secret service
        let secreton = Arc::new(secreton_inner.with_lifecycle(lifecycle.clone()));

        Ok(Self {
            config: Arc::new(config.clone()),
            storage,
            crypto,
            seal,
            audit,
            auth,
            policy: policy_service,
            secret: secreton,
            admin,
            database,
            pki,
            ssh,
            transit,
            totp_engine,
            performance,
            mfa,
            telemetry,
            identity,
            lifecycle,
        })
    }

    /// Start background workers. Call once, after construction.
    pub async fn start(&self) {
        self.lifecycle.spawn_worker().await;
    }

    /// Drain background workers and flush buffered audit events.
    ///
    /// Order matters: the lifecycle worker is drained first, because a sweep in flight
    /// can still emit audit events, and flushing before it finishes would lose them.
    pub async fn shutdown(&self) {
        self.lifecycle.shutdown_and_wait().await;
        if let Err(e) = self.audit.flush().await {
            tracing::warn!("Failed to flush audit logs on shutdown: {e}");
        }
    }
}
