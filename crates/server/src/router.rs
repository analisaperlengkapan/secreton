//! The single Axum router.
//!
//! Everything the process serves is assembled here: the REST API under `/api/v1`, health
//! and metrics, the Leptos application and its server functions, and — with the `grpc`
//! feature — the gRPC services. One router means one listener, one TLS configuration, one
//! middleware stack and one port to expose in Kubernetes.
//!
//! Before this refactor the process ran warp on the configured port and Axum on that port
//! plus ten, because warp is built on hyper 0.14 and Axum on hyper 1.0. That forced two
//! TLS configurations, two sets of middleware, a hardcoded offset duplicated into the
//! frontend's proxy config, and two major versions of Axum in the dependency tree.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use axum::routing::get;
use axum::{Router, middleware as axum_middleware};
use secreton_engines::{ServerConfig, Services};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware;
use crate::middleware::rate_limit::RateLimit;

/// State shared by every handler and server function.
///
/// `Services` is a typed struct, so a handler that asks for the wrong service does not
/// compile. This replaces a string-keyed `Box<dyn Any>` registry where the same mistake
/// surfaced at runtime — or worse, downcast successfully to the wrong service, which is
/// exactly what happened with the admin and audit services.
#[derive(Clone, Debug)]
pub struct AppState {
    pub services: Services,
    pub rate_limit: RateLimit,
    #[cfg(feature = "ui")]
    pub leptos_options: leptos::prelude::LeptosOptions,
}

impl FromRef<AppState> for Services {
    fn from_ref(state: &AppState) -> Self {
        state.services.clone()
    }
}

impl FromRef<AppState> for RateLimit {
    fn from_ref(state: &AppState) -> Self {
        state.rate_limit.clone()
    }
}

#[cfg(feature = "ui")]
impl FromRef<AppState> for leptos::prelude::LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}

/// Build the complete application router.
pub fn build_router(state: AppState) -> Router {
    let cfg = Arc::clone(&state.services.config);

    let app = Router::new()
        .merge(public_routes())
        .nest("/api/v1/auth", unauthenticated_routes(&state))
        .nest("/api/v1", protected_routes(&state));

    #[cfg(feature = "grpc")]
    let app = app.merge(crate::grpc::routes(&state.services));

    #[cfg(feature = "ui")]
    let app = app.merge(crate::ui::routes(&state));

    // Layers are applied one at a time rather than through a `ServiceBuilder`: axum's
    // `from_fn` needs to infer the inner service type, and a builder chain leaves it
    // ambiguous. Applied bottom-up, so the last `.layer` here is the outermost.
    app.with_state(state.clone())
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(cfg.http.max_body_size))
        .layer(TimeoutLayer::with_status_code(
            http::StatusCode::GATEWAY_TIMEOUT,
            Duration::from_secs(cfg.http.timeout),
        ))
        .layer(cors_layer(&cfg))
        .layer(axum_middleware::from_fn_with_state(
            state.rate_limit.clone(),
            middleware::rate_limit::enforce,
        ))
        .layer(axum_middleware::from_fn_with_state(
            middleware::security_headers::SchemePolicy {
                trusted_proxies: cfg.http.trusted_proxies,
                https_only: cfg.http.https_only,
            },
            middleware::security_headers::apply,
        ))
        .layer(TraceLayer::new_for_http())
        // Outermost, so every request — including one rejected by rate limiting —
        // carries an id that ties the client's 429 to a log line.
        .layer(axum_middleware::from_fn(middleware::request_id::attach))
}

/// Routes that answer with no credential and while the barrier is sealed.
///
/// These live outside both layers by construction. The previous implementation kept a
/// hand-maintained list of exact path strings *inside* each middleware, which had to be
/// kept in sync with the router by hand — and drifted, so the liveness probe required a
/// bearer token.
fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/health", get(handlers::health::liveness))
        .route("/health/ready", get(handlers::health::readiness))
        .route("/metrics", get(handlers::health::metrics))
        .route(
            "/api-docs/openapi.json",
            get(crate::openapi::openapi_document),
        )
        .nest("/api/v1/sys", handlers::sys::unsealed_routes())
}

/// Login and refresh: no credential required, but the barrier must be open.
///
/// These sit behind the seal gate and outside the auth gate. Login *cannot* succeed while
/// sealed — the credential store is encrypted at rest — so leaving it outside the gate
/// meant a login attempt against a sealed server hit a decryption failure deep in the
/// service and surfaced as a 500. It now returns the same actionable 503 as everything
/// else, telling the caller to unseal.
fn unauthenticated_routes(state: &AppState) -> Router<AppState> {
    handlers::auth::public_routes().route_layer(axum_middleware::from_fn_with_state(
        state.services.clone(),
        middleware::seal::reject_when_sealed,
    ))
}

/// Everything behind authentication and the seal gate.
fn protected_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .nest("/secret", handlers::secret::routes())
        .nest("/database", handlers::database::routes())
        .nest("/pki", handlers::pki::routes())
        .nest("/ssh", handlers::ssh::routes())
        .nest("/totp", handlers::totp_engine::routes())
        .nest("/transit", handlers::transit::routes())
        .nest("/lifecycle", handlers::lifecycle::routes())
        .nest("/admin", handlers::admin::routes())
        .nest("/sys", handlers::sys::routes())
        .nest("/auth", handlers::auth::authenticated_routes())
        // `route_layer` runs only on a matched route, so an unknown path under /api/v1
        // returns 404 rather than 401. A 401 there tells an unauthenticated caller which
        // paths exist.
        .route_layer(axum_middleware::from_fn_with_state(
            state.services.clone(),
            middleware::auth::require_authentication,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.services.clone(),
            middleware::seal::reject_when_sealed,
        ))
}

/// CORS policy.
///
/// The previous router applied `allow_origin(Any).allow_methods(Any).allow_headers(Any)`
/// to a secrets manager, which lets any page on the internet script the API with the
/// visitor's credentials. Origins are an explicit allowlist; an empty list means
/// same-origin only, which is the right default now that the UI is served by this process.
fn cors_layer(cfg: &ServerConfig) -> CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};

    if cfg.cors.allowed_origins.is_empty() {
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = cfg
        .cors
        .allowed_origins
        .iter()
        .filter_map(|o| match o.parse::<HeaderValue>() {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(origin = %o, "ignoring unparseable CORS origin");
                None
            }
        })
        .collect();

    let methods: Vec<Method> = cfg
        .cors
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse::<Method>().ok())
        .collect();

    let headers: Vec<HeaderName> = cfg
        .cors
        .allowed_headers
        .iter()
        .filter_map(|h| h.parse::<HeaderName>().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers)
        // Session cookies only travel cross-origin with this on, and it is only sound
        // because the origin list above is explicit — browsers and tower-http both reject
        // `Any` combined with credentials.
        .allow_credentials(true)
}
