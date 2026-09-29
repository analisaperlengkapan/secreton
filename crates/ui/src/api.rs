//! Data access from the UI, over Leptos server functions.
//!
//! Every call here runs **on the server**. Under `ssr` the body executes directly against
//! `secreton-engines`; under `hydrate` the `#[server]` macro generates the HTTP call for
//! the browser. Two things follow, and both were problems before:
//!
//! 1. **The browser never holds a token.** The session cookie is `HttpOnly`, so the
//!    request carries it automatically and no script can read it. The old code kept a JWT
//!    in `localStorage` and attached it by hand.
//! 2. **Request and response types are shared.** A mismatch between the UI and the API is
//!    a compile error. The old client parsed responses by trying `ApiResponse<T>` and
//!    falling back to raw `T`, because the warp and Axum halves of the API disagreed on
//!    the envelope.

use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[cfg(feature = "ssr")]
use secreton_engines::Services;

/// Health of the system, as shown on the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    pub sealed: bool,
    pub version: String,
    pub storage_backend: String,
    pub secret_count: u64,
}

/// Look up the services from the request-scoped Leptos context.
///
/// `secreton-server` provides them for every server-function call, so a handler that
/// forgets to is a startup failure rather than a silent `None` at request time.
#[cfg(feature = "ssr")]
fn services() -> Result<Services, ServerFnError> {
    use_context::<Services>().ok_or_else(|| {
        ServerFnError::new("services were not provided to the server-function context")
    })
}

/// The request headers this server function is answering.
///
/// Leptos' Axum integration provides the request's [`Parts`], not a bare `HeaderMap` —
/// the headers live inside it. Reading `HeaderMap` from context therefore always returned
/// `None`, which silently reduced every cookie lookup to "no session": the browser held a
/// valid `HttpOnly` session cookie and the server still reported the visitor signed out,
/// so login appeared to succeed and then bounced straight back to the form. Both types are
/// accepted here so the helper keeps working if an integration provides either.
#[cfg(feature = "ssr")]
fn request_headers() -> Option<axum::http::HeaderMap> {
    use_context::<axum::http::request::Parts>()
        .map(|parts| parts.headers)
        .or_else(use_context::<axum::http::HeaderMap>)
}

#[server(name = GetSystemStatus, prefix = "/api/sfn")]
pub async fn system_status() -> Result<SystemStatus, ServerFnError> {
    let services = services()?;
    Ok(SystemStatus {
        sealed: services.seal.is_sealed().await,
        version: env!("CARGO_PKG_VERSION").to_string(),
        storage_backend: format!("{:?}", services.config.storage.backend_type),
        secret_count: services
            .storage
            .count(&Default::default())
            .await
            .unwrap_or(0),
    })
}

/// Credentials submitted by the login form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub mfa_code: Option<String>,
}

/// What the UI needs to know about the signed-in user. Deliberately not the full
/// `User` record: password hashes and MFA secrets must never cross to the browser.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionUser {
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
    pub mfa_pending: bool,
}

#[server(name = Login, prefix = "/api/sfn")]
pub async fn login(credentials: Credentials) -> Result<SessionUser, ServerFnError> {
    use secreton_engines::services::auth::ApiLoginRequest;

    let services = services()?;
    let (client_ip, user_agent) = client_metadata();

    let response = services
        .auth
        .login(
            ApiLoginRequest {
                username: credentials.username,
                password: credentials.password,
                mfa_code: credentials.mfa_code.filter(|c| !c.is_empty()),
            },
            client_ip,
            user_agent,
        )
        .await
        // The error is deliberately not forwarded verbatim: distinguishing "no such user"
        // from "wrong password" turns the login form into a username oracle.
        .map_err(|e| {
            tracing::warn!(error = %e, "login failed");
            ServerFnError::new("invalid credentials")
        })?;

    let token = response.token;

    // The cookie is set here, inside the server function, so the token is issued and
    // stored without ever being handed to the page.
    set_session_cookie(
        &token.access_token,
        i64::try_from(token.expires_in).unwrap_or(i64::MAX),
    )?;

    Ok(SessionUser {
        mfa_pending: token
            .user
            .metadata
            .get("mfa_pending")
            .map(|v| v == "true")
            .unwrap_or(false),
        username: token.user.username,
        display_name: token.user.display_name,
        roles: token.user.roles,
    })
}

/// Client address and user agent, recorded on the session for auditing.
#[cfg(feature = "ssr")]
fn client_metadata() -> (String, String) {
    let headers = request_headers();
    let header = |name: &str| {
        headers
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string()
    };
    (header("x-forwarded-for"), header("user-agent"))
}

// Unused on the client build: only the `#[server]` bodies call these, and those compile
// only under `ssr`. The stub keeps the name resolvable in both builds.
#[allow(dead_code)]
#[cfg(not(feature = "ssr"))]
fn client_metadata() -> (String, String) {
    (String::new(), String::new())
}

#[server(name = Logout, prefix = "/api/sfn")]
pub async fn logout() -> Result<(), ServerFnError> {
    let services = services()?;
    if let Some(token) = current_token() {
        // Revoke server-side as well as clearing the cookie. Clearing alone would leave
        // a still-valid token that anyone who captured it could keep using.
        services
            .auth
            .revoke_token(token, chrono::Utc::now() + chrono::Duration::days(1))
            .await;
    }
    clear_session_cookie()?;
    Ok(())
}

#[server(name = CurrentSession, prefix = "/api/sfn")]
pub async fn current_session() -> Result<Option<SessionUser>, ServerFnError> {
    let services = services()?;
    let Some(token) = current_token() else {
        return Ok(None);
    };
    let Ok(user) = services.auth.validate_token(&token).await else {
        return Ok(None);
    };
    Ok(Some(SessionUser {
        mfa_pending: user
            .metadata
            .get("mfa_pending")
            .map(|v| v == "true")
            .unwrap_or(false),
        username: user.username,
        display_name: user.display_name,
        roles: user.roles,
    }))
}

// ---------------------------------------------------------------------------
// Server-only cookie plumbing
// ---------------------------------------------------------------------------

// The cookie's name and attributes come from `secreton-domain`, which the Axum middleware
// in `secreton-server` reads too. A local copy of the name here is what let this file and
// that middleware drift apart in the first place.
#[cfg(feature = "ssr")]
use secreton_domain::session::{self, SESSION_COOKIE};

#[cfg(feature = "ssr")]
fn current_token() -> Option<String> {
    let headers = request_headers()?;
    let cookies = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookies.split(';').find_map(|c| {
        let (name, value) = c.trim().split_once('=')?;
        (name == SESSION_COOKIE).then(|| value.to_string())
    })
}

// Unused on the client build: only the `#[server]` bodies call these, and those compile
// only under `ssr`. The stub keeps the name resolvable in both builds.
#[allow(dead_code)]
#[cfg(not(feature = "ssr"))]
fn current_token() -> Option<String> {
    None
}

/// Whether the request arrived over TLS, which decides the cookie's `Secure` attribute.
///
/// This server does not terminate TLS; a proxy does and may report the original scheme in
/// `x-forwarded-proto`. The decision is never read from that header here: the
/// security-header middleware resolves the effective scheme against the configured proxy
/// trust and publishes it as [`ResolvedScheme`], and this reads that. Reading the raw
/// header directly, which this used to do, meant a directly exposed server believed any
/// client that sent `X-Forwarded-Proto: https` — and the cookie and the HSTS header then
/// disagreed about whether the request was secure.
#[cfg(feature = "ssr")]
fn cookie_secure() -> bool {
    cookie_secure_from(use_context::<secreton_domain::proxy::ResolvedScheme>())
}

/// The cookie decision, separated from the context lookup so it can be tested directly.
///
/// Absence of a resolved scheme means no trusted resolution happened, which is not the
/// same as "the request was secure" — so it is treated as insecure rather than assumed.
#[cfg(feature = "ssr")]
fn cookie_secure_from(resolved: Option<secreton_domain::proxy::ResolvedScheme>) -> bool {
    resolved.map(|r| r.0.is_https()).unwrap_or(false)
}

/// Attach a `Set-Cookie` to the response this server function is producing.
#[cfg(feature = "ssr")]
fn put_set_cookie(value: String) -> Result<(), ServerFnError> {
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.insert_header(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&value)
                .map_err(|e| ServerFnError::new(format!("invalid session cookie: {e}")))?,
        );
    }
    Ok(())
}

#[cfg(feature = "ssr")]
fn set_session_cookie(token: &str, ttl_seconds: i64) -> Result<(), ServerFnError> {
    let value = session::session_cookie(token, ttl_seconds, cookie_secure())
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    put_set_cookie(value)
}

// Unused on the client build: only the `#[server]` bodies call these, and those compile
// only under `ssr`. The stub keeps the name resolvable in both builds.
#[allow(dead_code)]
#[cfg(not(feature = "ssr"))]
fn set_session_cookie(_token: &str, _ttl_seconds: i64) -> Result<(), ServerFnError> {
    Ok(())
}

#[cfg(feature = "ssr")]
fn clear_session_cookie() -> Result<(), ServerFnError> {
    // `clearing_cookie` reads its attributes from the same place `session_cookie` does, so
    // this cannot drift from the header that set the cookie.
    put_set_cookie(session::clearing_cookie(cookie_secure()))
}

// Unused on the client build: only the `#[server]` bodies call these, and those compile
// only under `ssr`. The stub keeps the name resolvable in both builds.
#[allow(dead_code)]
#[cfg(not(feature = "ssr"))]
fn clear_session_cookie() -> Result<(), ServerFnError> {
    Ok(())
}

#[cfg(all(test, feature = "ssr"))]
mod tests {
    use super::*;
    use secreton_domain::proxy::{ResolvedScheme, Scheme};

    #[test]
    fn a_directly_exposed_request_is_never_secure() {
        // No resolved scheme means no trusted resolution ran. The old code read
        // `X-Forwarded-Proto` straight from the request headers, so a client could turn
        // `Secure` on for itself; absence now means "insecure", never "assume secure".
        assert!(!cookie_secure_from(None));
    }

    #[test]
    fn the_cookie_follows_the_resolved_scheme_not_a_header() {
        assert!(cookie_secure_from(Some(ResolvedScheme(Scheme::Https))));
        assert!(!cookie_secure_from(Some(ResolvedScheme(Scheme::Http))));
    }
}
