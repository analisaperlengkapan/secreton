//! End-to-end tests against the real router.
//!
//! These build the actual `build_router` output over in-memory storage and drive it with
//! `axum-test`, so they cover the wiring that unit tests cannot: which routes sit outside
//! the auth layer, what an unauthenticated caller learns, and what a 5xx body contains.
//!
//! This file used to open with `#![cfg(not(feature = "ui"))]`, on the reasoning that the
//! frontend toolchain was not needed to test the API. `ui` is in the crate's default
//! feature set, so the attribute compiled all twelve tests out of every ordinary
//! `cargo test` — including CI's. `cargo test -p secreton-server --test e2e` reported
//! "running 0 tests" and passed. Tests that never run are worse than no tests: they read
//! as coverage.
//!
//! The suite now builds the router with whatever features are enabled, which is the point
//! of an end-to-end test — the router under test is the one that ships.

use secreton_engines::{ServerConfig, Services};
use secreton_server::build_router;
use secreton_server::middleware::rate_limit::RateLimit;
use secreton_server::router::AppState;

/// A server backed by in-memory storage, with the seal already open.
async fn test_server() -> axum_test::TestServer {
    let mut config = ServerConfig::default();
    config.auth.jwt.secret = Some("test-secret-that-is-at-least-32-bytes!".to_string());
    // Generous, so a burst of test requests is never mistaken for abuse.
    config.rate_limit.global.requests = 10_000;
    config
        .validate()
        .expect("the test configuration must be valid");

    let services = Services::new(&config)
        .await
        .expect("services must construct over in-memory storage");

    let state = AppState {
        rate_limit: RateLimit::new(config.rate_limit.global.requests, 0),
        services,
        // Only the SSR side is exercised here. `site_root` points at a directory that the
        // tests never populate, which is deliberate: the asset handler is the last
        // fallback, so a request reaching it means routing went wrong, and an empty
        // directory makes that show up as a miss rather than a stale hit.
        #[cfg(feature = "ui")]
        leptos_options: leptos::prelude::LeptosOptions::builder()
            .output_name("secreton-e2e")
            .site_root("target/site-e2e".to_string())
            .build(),
    };

    // `TestServer::new` panics on failure since axum-test 19; `try_new` returns the
    // error so the test reports which part of the server failed to build.
    axum_test::TestServer::try_new(build_router(state)).expect("test server")
}

#[tokio::test]
async fn liveness_answers_without_a_credential() {
    let server = test_server().await;
    let response = server.get("/health").await;
    response.assert_status_ok();
    assert_eq!(response.json::<serde_json::Value>()["status"], "ok");
}

#[tokio::test]
async fn readiness_answers_without_a_credential() {
    let server = test_server().await;
    // Must not 401. A readiness probe behind authentication is one Kubernetes can never
    // satisfy, which is exactly the bug the old middleware allowlist had.
    let response = server.get("/health/ready").await;
    assert_ne!(response.status_code(), http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_reports_real_values_not_hardcoded_zeros() {
    let server = test_server().await;
    let body = server.get("/metrics").await.text();

    assert!(
        body.contains("secreton_sealed"),
        "missing seal gauge:\n{body}"
    );
    assert!(body.contains("secreton_secrets_total"));
    assert!(body.contains("secreton_uptime_seconds"));
    // The previous handler returned a fixed string with `api_requests_total{...} 0`.
    assert!(
        !body.contains("api_requests_total"),
        "the hardcoded metric block is back:\n{body}"
    );
}

#[tokio::test]
async fn the_openapi_document_is_served_and_describes_both_credential_shapes() {
    let server = test_server().await;
    let doc = server
        .get("/api-docs/openapi.json")
        .await
        .json::<serde_json::Value>();

    assert_eq!(doc["info"]["title"], "Secreton API");
    let schemes = &doc["components"]["securitySchemes"];
    assert_eq!(schemes["bearer"]["scheme"], "bearer");
    assert_eq!(schemes["session"]["in"], "cookie");
}

#[tokio::test]
async fn a_sealed_server_refuses_protected_routes() {
    let server = test_server().await;
    // The seal gate sits outside the auth layer, so a sealed server answers 503 rather
    // than letting the request reach a handler that would fail with a confusing
    // decryption error.
    let response = server.get("/api/v1/secret/secrets/kv/app").await;
    assert_eq!(
        response.status_code(),
        http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        response.text().contains("sealed"),
        "the response should say what to do: {}",
        response.text()
    );
}

#[tokio::test]
async fn the_seal_status_endpoint_answers_while_sealed() {
    let server = test_server().await;
    // Mounted outside the seal gate. If it were not, the only endpoint that reports the
    // problem would itself be refused for the problem.
    let response = server.get("/api/v1/sys/seal-status").await;
    assert_ne!(
        response.status_code(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "seal-status must be reachable while sealed"
    );
}

#[tokio::test]
async fn an_unknown_path_under_the_api_is_a_404_not_a_401() {
    let server = test_server().await;
    let response = server.get("/api/v1/this/route/does/not/exist").await;
    // `route_layer` runs only on matched routes. A 401 here would tell an
    // unauthenticated caller which paths exist.
    assert_eq!(
        response.status_code(),
        http::StatusCode::NOT_FOUND,
        "an unmatched path must not reveal whether it would have required auth"
    );
}

#[tokio::test]
async fn login_is_routed_and_needs_no_session() {
    let server = test_server().await;
    let response = server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({ "username": "nobody", "password": "wrong" }))
        .await;

    // It must be *reachable*: a login endpoint behind the auth layer is a deadlock, and
    // that is what the drifted middleware allowlist produced.
    assert_ne!(
        response.status_code(),
        http::StatusCode::NOT_FOUND,
        "login must be routed"
    );
    assert_ne!(
        response.status_code(),
        http::StatusCode::UNAUTHORIZED,
        "login must not itself require a session"
    );
}

#[tokio::test]
async fn login_against_a_sealed_server_says_so_instead_of_failing_opaquely() {
    let server = test_server().await;
    let response = server
        .post("/api/v1/auth/login")
        .json(&serde_json::json!({ "username": "root", "password": "whatever" }))
        .await;

    // Login cannot succeed while sealed: the credential store is encrypted at rest.
    // Before the seal gate covered this route, the attempt reached the service and
    // surfaced as an opaque 500.
    assert_eq!(
        response.status_code(),
        http::StatusCode::SERVICE_UNAVAILABLE,
        "expected a sealed response, got {}: {}",
        response.status_code(),
        response.text()
    );
    assert!(response.text().contains("sealed"));
}

#[tokio::test]
async fn every_response_carries_security_headers_and_a_request_id() {
    let server = test_server().await;
    let response = server.get("/health").await;

    assert_eq!(response.header("x-content-type-options"), "nosniff");
    assert_eq!(response.header("x-frame-options"), "DENY");
    assert!(
        response
            .header("content-security-policy")
            .to_str()
            .unwrap()
            .contains("frame-ancestors 'none'")
    );
    assert!(
        !response.header("x-request-id").is_empty(),
        "a request id is what makes the opaque 5xx body diagnosable"
    );
}

#[tokio::test]
async fn a_supplied_request_id_is_propagated_when_it_is_well_formed() {
    let server = test_server().await;
    let response = server
        .get("/health")
        .add_header("x-request-id", "trace-abc-123")
        .await;
    assert_eq!(response.header("x-request-id"), "trace-abc-123");
}

#[tokio::test]
async fn no_cross_origin_headers_are_emitted_by_default() {
    let server = test_server().await;
    let response = server
        .get("/health")
        .add_header("origin", "https://evil.example")
        .await;

    // The default origin list is empty, meaning same-origin only. The old default was
    // `["*"]` with `allow_credentials`, which lets any site script the API with the
    // visitor's session.
    assert!(
        response
            .maybe_header("access-control-allow-origin")
            .is_none(),
        "a wildcard CORS response reached an untrusted origin"
    );
}

/// A trusted-proxy configuration for the scheme tests, since the default server declares
/// no proxies.
async fn test_server_with_trusted_proxies(trusted_proxies: usize) -> axum_test::TestServer {
    let mut config = ServerConfig::default();
    config.auth.jwt.secret = Some("test-secret-that-is-at-least-32-bytes!".to_string());
    config.rate_limit.global.requests = 10_000;
    config.http.trusted_proxies = trusted_proxies;
    config
        .validate()
        .expect("the test configuration must be valid");

    let services = Services::new(&config)
        .await
        .expect("services must construct over in-memory storage");

    let state = AppState {
        rate_limit: RateLimit::new(config.rate_limit.global.requests, trusted_proxies),
        services,
        #[cfg(feature = "ui")]
        leptos_options: leptos::prelude::LeptosOptions::builder()
            .output_name("secreton-e2e")
            .site_root("target/site-e2e".to_string())
            .build(),
    };

    // `TestServer::new` panics on failure since axum-test 19; `try_new` returns the
    // error so the test reports which part of the server failed to build.
    axum_test::TestServer::try_new(build_router(state)).expect("test server")
}

#[tokio::test]
async fn a_forwarded_proto_header_from_a_direct_client_does_not_turn_hsts_on() {
    // Direct listener, no trusted proxy declared. A client sending this over plain HTTP
    // must not be able to have its request treated as secure.
    let server = test_server().await;
    let response = server
        .get("/health")
        .add_header("x-forwarded-proto", "https")
        .await;

    assert!(
        response.maybe_header("strict-transport-security").is_none(),
        "a forgeable forwarded header turned HSTS on"
    );
}

#[tokio::test]
async fn a_trusted_proxy_can_report_that_the_client_used_tls() {
    // With one proxy declared, the forwarded scheme is the answer the middleware acts on.
    let server = test_server_with_trusted_proxies(1).await;
    let response = server
        .get("/health")
        .add_header("x-forwarded-proto", "https")
        .await;

    assert!(
        response.maybe_header("strict-transport-security").is_some(),
        "the forwarded https scheme should assert HSTS through a trusted proxy"
    );
}

#[cfg(feature = "ui")]
#[tokio::test]
async fn the_ssr_document_carries_a_csp_naming_the_nonce_its_inline_scripts_use() {
    // The renderer's nonce and the policy's nonce must be the same value, or hydration
    // silently fails. Walk the login page and prove both halves agree.
    let server = test_server().await;
    let response = server.get("/login").await;
    let html = response.text();

    let csp = response
        .maybe_header("content-security-policy")
        .expect("every response carries a CSP")
        .to_str()
        .unwrap()
        .to_string();

    // Extract the nonce the policy names.
    let nonce = csp
        .split("'nonce-")
        .nth(1)
        .and_then(|rest| rest.split('\'').next())
        .expect("an SSR document's policy must name a nonce");
    assert!(
        nonce.len() >= 16,
        "a nonce shorter than 128 bits is guessable: {nonce}"
    );

    // The inline scripts on the page must carry that same nonce.
    assert!(
        html.contains(&format!("nonce=\"{nonce}\"")) || html.contains(&format!("nonce={nonce}")),
        "the document's inline scripts do not carry the nonce the policy names; \
         hydration would silently fail"
    );
}
