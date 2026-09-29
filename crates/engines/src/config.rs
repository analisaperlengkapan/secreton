//! Configuration management for the Secreton API server.
//!
//! Provides comprehensive configuration options for HTTP/gRPC servers,
//! authentication, authorization, rate limiting, and security features.

use std::net::SocketAddr;
use std::path::PathBuf;

use crate::audit_config::AuditConfig;
use secreton_storage::StorageFactoryConfig;
use serde::{Deserialize, Serialize};

/// Main API configuration
///
/// Every table here is `#[serde(default)]`, so a configuration file names only the
/// settings it wants to change. That is what a configuration file is for, and without it
/// serde demands every field of every struct: the committed `secreton.toml` omits
/// `auth.jwt.expiration` and declined to deserialize, taking the server down before it
/// bound a port.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ServerConfig {
    /// HTTP server configuration
    pub http: HttpConfig,

    /// gRPC server configuration  
    pub grpc: GrpcConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Audit logging configuration
    #[serde(default)]
    pub audit: AuditConfig,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// TLS configuration
    pub tls: Option<TlsConfig>,

    /// Monitoring configuration
    pub monitoring: MonitoringConfig,

    /// CORS configuration
    pub cors: CorsConfig,

    /// Logging configuration
    pub logging: LoggingConfig,

    /// Storage configuration
    pub storage: StorageFactoryConfig,
}

/// HTTP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    /// Address to bind HTTP server
    pub bind_address: SocketAddr,

    /// Request timeout (seconds)
    pub timeout: u64,

    /// Maximum request body size (bytes)
    pub max_body_size: usize,

    /// Keep-alive timeout (seconds)
    pub keep_alive: u64,

    /// Enable compression
    pub compression: bool,

    /// Enable static file serving
    pub static_files: Option<StaticFilesConfig>,

    /// How many reverse proxies sit in front of this process.
    ///
    /// Used to resolve the client address from `X-Forwarded-For`. Zero — the default —
    /// means the header is ignored entirely and the socket peer address is used, which is
    /// correct when the process is exposed directly. Setting it higher than the real
    /// number lets a client forge its own address by prepending entries.
    #[serde(default)]
    pub trusted_proxies: usize,

    /// Declare that every connection into this process arrives over TLS even though the
    /// request itself cannot say so.
    ///
    /// The URI does not report TLS reliably: an HTTP/1.1 request in origin-form carries no
    /// scheme, and an HTTP/2 `:scheme` is client-supplied. A TLS-terminating listener marks
    /// the connection instead, and this setting is for a deployment where that marker is
    /// unavailable — for example a TLS terminator on the same host that forwards a stream
    /// the runtime does not identify as TLS. When true, the session cookie carries `Secure`
    /// and responses assert HSTS. It does not make the process trust `X-Forwarded-Proto`;
    /// that is still gated by `trusted_proxies`.
    #[serde(default)]
    pub https_only: bool,
}

/// gRPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcConfig {
    /// Enable gRPC server
    pub enabled: bool,

    /// Address to bind gRPC server
    pub bind_address: SocketAddr,

    /// Request timeout (seconds)
    pub timeout: u64,

    /// Maximum message size (bytes)
    pub max_message_size: usize,

    /// Enable reflection
    pub reflection: bool,

    /// Enable health check service
    pub health_check: bool,
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    /// JWT configuration
    pub jwt: JwtConfig,

    /// OAuth2 configuration
    pub oauth2: Option<OAuth2Config>,

    /// mTLS configuration
    pub mtls: Option<MtlsConfig>,

    /// Session configuration
    pub session: SessionConfig,

    /// Multi-factor authentication
    pub mfa: MfaConfig,
}

/// JWT configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JwtConfig {
    /// JWT signing secret (auto-generated if not provided)
    pub secret: Option<String>,

    /// Token expiration time (seconds)
    pub expiration: u64,

    /// Refresh token expiration (seconds)
    pub refresh_expiration: u64,

    /// JWT algorithm
    pub algorithm: String,

    /// Issuer
    pub issuer: String,

    /// Audience
    pub audience: String,
}

/// OAuth2 configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    /// OAuth2 provider URLs
    pub providers: Vec<OAuth2Provider>,

    /// Redirect URL
    pub redirect_url: String,

    /// Scopes to request
    pub scopes: Vec<String>,
}

/// OAuth2 provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Provider {
    /// Provider name
    pub name: String,

    /// Client ID
    pub client_id: String,

    /// Client secret
    pub client_secret: String,

    /// Authorization URL
    pub auth_url: String,

    /// Token URL
    pub token_url: String,

    /// User info URL
    pub user_info_url: String,
}

/// mTLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Require client certificates
    pub required: bool,

    /// CA certificate path
    pub ca_cert: PathBuf,

    /// Allowed client certificate subjects
    pub allowed_subjects: Vec<String>,

    /// Certificate revocation list
    pub crl: Option<PathBuf>,
}

/// Session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Session timeout (seconds)
    pub timeout: u64,

    /// Session store type
    pub store: SessionStore,

    /// Cookie configuration
    pub cookie: CookieConfig,
}

/// Session store types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SessionStore {
    Memory,
    Redis { url: String },
    Database { table: String },
}

/// Cookie configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CookieConfig {
    /// Cookie name
    pub name: String,

    /// Cookie domain
    pub domain: Option<String>,

    /// Cookie path
    pub path: String,

    /// Secure flag
    pub secure: bool,

    /// HttpOnly flag
    pub http_only: bool,

    /// SameSite policy
    pub same_site: String,
}

/// Multi-factor authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MfaConfig {
    /// Enable MFA
    pub enabled: bool,

    /// TOTP configuration
    pub totp: TotpConfig,

    /// SMS configuration
    pub sms: Option<SmsConfig>,

    /// Email configuration
    pub email: Option<EmailConfig>,

    /// WebAuthn configuration
    pub webauthn: Option<WebAuthnConfig>,
}

/// TOTP configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TotpConfig {
    /// Issuer name
    pub issuer: String,

    /// Secret length
    pub secret_length: usize,

    /// Time step (seconds)
    pub time_step: u64,

    /// Code length
    pub code_length: usize,

    /// Clock skew tolerance
    pub skew_tolerance: u64,
}

/// SMS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsConfig {
    /// SMS provider
    pub provider: String,

    /// API key
    pub api_key: String,

    /// From number
    pub from_number: String,
}

/// Email configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server
    pub smtp_server: String,

    /// SMTP port
    pub smtp_port: u16,

    /// Username
    pub username: String,

    /// Password
    pub password: String,

    /// From address
    pub from_address: String,

    /// Use TLS
    pub use_tls: bool,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party name
    pub rp_name: String,

    /// Relying party ID
    pub rp_id: String,

    /// Origin
    pub origin: String,
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,

    /// Global rate limits
    pub global: RateLimitRule,

    /// Per-endpoint rate limits
    pub endpoints: Vec<EndpointRateLimit>,

    /// Per-user rate limits
    pub per_user: Option<RateLimitRule>,

    /// Per-IP rate limits
    pub per_ip: Option<RateLimitRule>,
}

/// Rate limit rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitRule {
    /// Requests per time window
    pub requests: u32,

    /// Time window duration (seconds)
    pub window: u64,

    /// Burst size
    pub burst: Option<u32>,
}

/// Endpoint-specific rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointRateLimit {
    /// Endpoint pattern
    pub pattern: String,

    /// Rate limit rule
    pub rule: RateLimitRule,
}

/// TLS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Certificate file path
    pub cert_file: PathBuf,

    /// Private key file path
    pub key_file: PathBuf,

    /// CA certificate file path
    pub ca_file: Option<PathBuf>,

    /// Minimum TLS version
    pub min_version: String,

    /// Cipher suites
    pub cipher_suites: Vec<String>,

    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

/// Jaeger tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JaegerConfig {
    /// Jaeger endpoint URL
    pub endpoint: String,

    /// Service name for tracing
    pub service_name: String,

    /// Sampling rate (0.0 to 1.0)
    pub sample_rate: f64,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    /// Enable metrics
    pub metrics: bool,

    /// Metrics endpoint
    pub metrics_path: String,

    /// Health check endpoint
    pub health_path: String,

    /// Enable tracing
    pub tracing: bool,

    /// Jaeger configuration
    pub jaeger: Option<JaegerConfig>,
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    /// Enable CORS
    pub enabled: bool,

    /// Allowed origins
    pub allowed_origins: Vec<String>,

    /// Allowed methods
    pub allowed_methods: Vec<String>,

    /// Allowed headers
    pub allowed_headers: Vec<String>,

    /// Exposed headers
    pub exposed_headers: Vec<String>,

    /// Max age (seconds)
    pub max_age: Option<u64>,

    /// Allow credentials
    pub allow_credentials: bool,
}

/// Static files configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticFilesConfig {
    /// Static files directory
    pub directory: PathBuf,

    /// URL path prefix
    pub path_prefix: String,

    /// Enable directory listing
    pub directory_listing: bool,

    /// Default index file
    pub index_file: Option<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level
    pub level: String,

    /// Log format
    pub format: String,

    /// Enable JSON logging
    pub json: bool,

    /// Log file path
    pub file: Option<PathBuf>,

    /// Log rotation
    pub rotation: Option<LogRotationConfig>,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum file size
    pub max_size: u64,

    /// Maximum number of files
    pub max_files: u32,

    /// Rotation frequency
    pub frequency: String,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1:8080".parse().expect("literal socket address"),
            timeout: 30,
            max_body_size: 16 * 1024 * 1024, // 16MB
            keep_alive: 75,
            compression: true,
            static_files: None,
            trusted_proxies: 0,
            https_only: false,
        }
    }
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: "127.0.0.1:9090".parse().expect("literal socket address"),
            timeout: 30,
            max_message_size: 4 * 1024 * 1024, // 4MB
            reflection: false,
            health_check: true,
        }
    }
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            secret: None,
            expiration: 3600,              // 1 hour
            refresh_expiration: 86400 * 7, // 7 days
            algorithm: "HS256".to_string(),
            issuer: "secreton".to_string(),
            audience: "secreton-api".to_string(),
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout: 3600, // 1 hour
            store: SessionStore::Memory,
            cookie: CookieConfig::default(),
        }
    }
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "secreton-session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: false,
            http_only: true,
            same_site: "Strict".to_string(),
        }
    }
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "Secreton".to_string(),
            secret_length: 32,
            time_step: 30,
            code_length: 6,
            skew_tolerance: 1,
        }
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global: RateLimitRule {
                requests: 1000,
                window: 60,
                burst: Some(100),
            },
            endpoints: vec![],
            per_user: Some(RateLimitRule {
                requests: 100,
                window: 60,
                burst: Some(10),
            }),
            per_ip: Some(RateLimitRule {
                requests: 200,
                window: 60,
                burst: Some(20),
            }),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics: true,
            metrics_path: "/metrics".to_string(),
            health_path: "/health".to_string(),
            tracing: true,
            jaeger: None,
        }
    }
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            // Empty means same-origin only. The default used to be `["*"]`, which let any
            // page on the internet script this API with the visitor's credentials — on a
            // secrets manager, out of the box. Same-origin is now correct by default
            // because the UI is served by this same process.
            allowed_origins: Vec::new(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec![
                "Content-Type".to_string(),
                "Authorization".to_string(),
                "X-Requested-With".to_string(),
            ],
            exposed_headers: vec![],
            max_age: Some(3600),
            allow_credentials: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "pretty".to_string(),
            json: false,
            file: None,
            rotation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sample_api_config() -> ServerConfig {
        ServerConfig {
            http: HttpConfig {
                trusted_proxies: 0,
                https_only: false,
                bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8200),
                timeout: 30,
                max_body_size: 5 * 1024 * 1024,
                keep_alive: 15,
                compression: true,
                static_files: None,
            },
            grpc: GrpcConfig {
                enabled: true,
                bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8201),
                timeout: 30,
                max_message_size: 16 * 1024 * 1024,
                reflection: true,
                health_check: true,
            },
            auth: AuthConfig {
                jwt: JwtConfig {
                    secret: Some("super-secret-key".to_string()),
                    expiration: 3600,
                    refresh_expiration: 86400,
                    algorithm: "HS256".to_string(),
                    issuer: "secreton".to_string(),
                    audience: "secreton-users".to_string(),
                },
                oauth2: None,
                mtls: Some(MtlsConfig {
                    required: true,
                    ca_cert: PathBuf::from("/etc/ssl/ca.pem"),
                    allowed_subjects: vec!["CN=trusted".to_string()],
                    crl: None,
                }),
                session: SessionConfig {
                    timeout: 1800,
                    store: SessionStore::Memory,
                    cookie: CookieConfig {
                        name: "secreton-session".to_string(),
                        domain: Some("example.com".to_string()),
                        path: "/".to_string(),
                        secure: true,
                        http_only: true,
                        same_site: "Strict".to_string(),
                    },
                },
                mfa: MfaConfig {
                    enabled: true,
                    totp: TotpConfig {
                        issuer: "Secreton Secret".to_string(),
                        secret_length: 32,
                        time_step: 30,
                        code_length: 6,
                        skew_tolerance: 1,
                    },
                    sms: None,
                    email: None,
                    webauthn: Some(WebAuthnConfig {
                        rp_name: "Secreton Secret".to_string(),
                        rp_id: "secreton.example.com".to_string(),
                        origin: "https://secreton.example.com".to_string(),
                    }),
                },
            },
            audit: AuditConfig::default(),
            rate_limit: RateLimitConfig {
                enabled: true,
                global: RateLimitRule {
                    requests: 1000,
                    window: 60,
                    burst: Some(100),
                },
                endpoints: vec![EndpointRateLimit {
                    pattern: "/v1/auth/login".to_string(),
                    rule: RateLimitRule {
                        requests: 20,
                        window: 60,
                        burst: Some(10),
                    },
                }],
                per_user: Some(RateLimitRule {
                    requests: 200,
                    window: 60,
                    burst: None,
                }),
                per_ip: None,
            },
            tls: Some(TlsConfig {
                cert_file: PathBuf::from("/etc/tls/server.crt"),
                key_file: PathBuf::from("/etc/tls/server.key"),
                ca_file: None,
                min_version: "TLS1.3".to_string(),
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
                alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
            }),
            monitoring: MonitoringConfig {
                metrics: true,
                metrics_path: "/metrics".to_string(),
                health_path: "/health".to_string(),
                tracing: true,
                jaeger: Some(JaegerConfig {
                    endpoint: "http://jaeger:14268/api/traces".to_string(),
                    service_name: "secreton-api".to_string(),
                    sample_rate: 0.5,
                }),
            },
            cors: CorsConfig {
                enabled: true,
                allowed_origins: vec!["https://secreton.example.com".to_string()],
                allowed_methods: vec!["GET".to_string(), "POST".to_string()],
                allowed_headers: vec!["Authorization".to_string()],
                exposed_headers: vec![],
                max_age: Some(600),
                allow_credentials: true,
            },
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "json".to_string(),
                json: true,
                file: None,
                rotation: None,
            },
            storage: StorageFactoryConfig::default(),
        }
    }

    #[test]
    fn test_api_config_structure() {
        let config = sample_api_config();
        assert_eq!(config.http.bind_address.port(), 8200);
        assert!(config.grpc.enabled);
        assert_eq!(config.auth.jwt.algorithm, "HS256");
        assert!(config.auth.mfa.enabled);
        assert!(config.rate_limit.enabled);
        assert!(config.tls.is_some());
        assert!(config.monitoring.metrics);
        assert_eq!(config.cors.allowed_origins.len(), 1);
        assert!(config.logging.json);
    }

    #[test]
    fn test_rate_limit_rule_burst_defaults() {
        let rule = RateLimitRule {
            requests: 50,
            window: 10,
            burst: None,
        };
        assert_eq!(rule.requests, 50);
        assert!(rule.burst.is_none());
    }

    #[test]
    fn test_cookie_config_flags() {
        let cookie = CookieConfig {
            name: "session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: "Lax".to_string(),
        };

        assert!(cookie.secure);
        assert!(cookie.http_only);
        assert_eq!(cookie.same_site, "Lax");
    }
}

impl ServerConfig {
    /// Load configuration, layering file over defaults and environment over both.
    ///
    /// A missing file is not an error: the defaults plus environment variables are enough
    /// to start with in-memory storage, which is what makes `cargo leptos serve` work on a
    /// fresh checkout. A file that exists but cannot be parsed *is* an error — silently
    /// falling back to defaults would start the server with a different configuration than
    /// the operator wrote.
    pub fn load(path: &str) -> Result<Self, secreton_domain::SecretonError> {
        let mut config = if std::path::Path::new(path).exists() {
            let text = std::fs::read_to_string(path)?;
            toml::from_str::<Self>(&text)?
        } else {
            tracing::info!(
                path,
                "no configuration file found; using defaults and environment"
            );
            Self::default()
        };

        // `SECRETON__AUTH__JWT__SECRET` and friends override the file, so a secret never
        // has to be written to disk.
        config.apply_environment();
        Ok(config)
    }

    fn apply_environment(&mut self) {
        if let Ok(secret) = std::env::var("SECRETON__AUTH__JWT__SECRET") {
            self.auth.jwt.secret = Some(secret);
        }
        if let Ok(addr) = std::env::var("SECRETON__HTTP__BIND_ADDRESS")
            && let Ok(parsed) = addr.parse()
        {
            self.http.bind_address = parsed;
        }
        if let Ok(n) = std::env::var("SECRETON__HTTP__TRUSTED_PROXIES")
            && let Ok(parsed) = n.parse()
        {
            self.http.trusted_proxies = parsed;
        }
    }

    /// Reject a configuration that cannot serve traffic safely.
    ///
    /// Run at startup so a mistake stops the process rather than surfacing on a user's
    /// first request — or worse, not surfacing at all.
    pub fn validate(&self) -> Result<(), secreton_domain::SecretonError> {
        use secreton_domain::SecretonError;
        let reject = |message: String| Err(SecretonError::Configuration { message });

        match self.auth.jwt.secret.as_deref() {
            None | Some("") => {
                return reject(
                    "auth.jwt.secret is not set. Set SECRETON__AUTH__JWT__SECRET or the \
                     `secret` key under [auth.jwt]. It is never generated automatically: a \
                     secret invented at boot invalidates every issued token on restart."
                        .into(),
                );
            }
            // 32 bytes is the smallest key that gives HS256 its full security margin.
            Some(s) if s.len() < 32 => {
                return reject(format!(
                    "auth.jwt.secret is {} bytes; at least 32 are required",
                    s.len()
                ));
            }
            Some(_) => {}
        }

        if self.http.timeout == 0 {
            return reject("http.timeout must be greater than zero".into());
        }
        if self.http.max_body_size == 0 {
            return reject("http.max_body_size must be greater than zero".into());
        }
        if self.cors.allowed_origins.iter().any(|o| o == "*") {
            return reject(
                "cors.allowed_origins contains \"*\". A wildcard origin lets any site \
                 script this API with the visitor's credentials; list origins explicitly, \
                 or leave the list empty for same-origin only."
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn valid() -> ServerConfig {
        let mut c = ServerConfig::default();
        c.auth.jwt.secret = Some("x".repeat(32));
        c
    }

    #[test]
    fn a_valid_configuration_is_accepted() {
        assert!(valid().validate().is_ok());
    }

    #[test]
    fn a_missing_or_short_jwt_secret_stops_startup() {
        let mut c = valid();
        c.auth.jwt.secret = None;
        assert!(c.validate().is_err());

        c.auth.jwt.secret = Some(String::new());
        assert!(c.validate().is_err());

        c.auth.jwt.secret = Some("too-short".into());
        let err = c.validate().unwrap_err().to_string();
        assert!(
            err.contains("32"),
            "message should state the requirement: {err}"
        );
    }

    #[test]
    fn a_wildcard_cors_origin_is_rejected() {
        let mut c = valid();
        c.cors.allowed_origins = vec!["*".into()];
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("wildcard") || err.contains("*"), "{err}");
    }

    #[test]
    fn zero_timeout_or_body_limit_is_rejected() {
        let mut c = valid();
        c.http.timeout = 0;
        assert!(c.validate().is_err());

        let mut c = valid();
        c.http.max_body_size = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn a_missing_file_falls_back_to_defaults_but_a_malformed_one_does_not() {
        assert!(ServerConfig::load("/nonexistent/secreton.toml").is_ok());

        let dir = std::env::temp_dir().join("secreton-config-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.toml");
        std::fs::write(&path, "this is not = valid toml [[[").unwrap();
        assert!(
            ServerConfig::load(path.to_str().unwrap()).is_err(),
            "a malformed file must fail loudly, not silently fall back to defaults"
        );
    }

    /// The file in the repository is the one every new checkout runs with, so it has to
    /// parse. It did not: `[audit]` set three of `AuditConfig`'s six fields and the struct
    /// had no `#[serde(default)]`, so `cargo leptos serve` died with "missing field
    /// `level`" before binding a port. A partial-table test is what catches that class of
    /// drift, since a struct-level default makes every omitted key legal.
    #[test]
    fn the_committed_configuration_file_loads() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../secreton.toml");
        let config = ServerConfig::load(path)
            .expect("the committed secreton.toml must deserialize; CI runs with it");
        // A `[storage]` table that only sets `backend_type` relies on the same defaulting.
        assert_eq!(config.audit.retention_days, 2555);
    }

    /// A table that sets none of an optional struct's fields must still deserialize.
    #[test]
    fn a_partial_table_falls_back_to_its_struct_default() {
        let parsed: ServerConfig =
            toml::from_str("[audit]\nenabled = false\n").expect("partial [audit] must parse");
        assert!(!parsed.audit.enabled);
        assert_eq!(parsed.audit.retention_days, 2555);
        assert_eq!(parsed.audit.max_batch_size, 100);
    }
}
