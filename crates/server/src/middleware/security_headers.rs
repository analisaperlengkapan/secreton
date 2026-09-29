//! Response security headers.
//!
//! The application renders secrets in a browser, so the headers that constrain what the
//! page may load and where it may be embedded are part of the security boundary, not
//! decoration.
//!
//! The Content-Security-Policy is built *here*, not accepted from whatever the handler
//! happened to set. A downstream response must not be able to weaken the policy that
//! protects the page. It may only name a nonce, and only ever the one the trusted renderer
//! actually stamped onto the document — signalled by echoing that nonce under a private
//! response header the client never receives ([`RENDERED_NONCE_HEADER`]). Every other
//! response, including any that carries a policy of its own, is overwritten with the
//! script-free policy.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

use secreton_domain::csp::{
    RENDERED_NONCE_HEADER, csp_with_nonce, csp_without_nonce, is_well_formed_nonce,
};
use secreton_domain::proxy::{ResolvedScheme, Scheme, effective_scheme};

/// How the scheme is resolved: how many proxy hops are trusted, and whether every
/// connection this process accepts is already TLS.
///
/// Carried as middleware state rather than read from the environment, so the middleware and
/// the rest of the process share one configured value.
#[derive(Debug, Clone, Copy)]
pub struct SchemePolicy {
    /// Proxy hops in front of this process trusted for `X-Forwarded-Proto`. Zero — the
    /// default — means the header is ignored entirely and only the observed connection
    /// decides.
    pub trusted_proxies: usize,
    /// Declare that the connection into this process is TLS even though the request cannot
    /// say so. Set this only when the listener itself terminates TLS or a same-host
    /// terminator hands the process a TLS connection; a proxy that forwards to this process
    /// over plain HTTP is described by `trusted_proxies`, not this.
    pub https_only: bool,
}

pub async fn apply(
    State(SchemePolicy {
        trusted_proxies,
        https_only,
    }): State<SchemePolicy>,
    mut request: Request,
    next: Next,
) -> Response {
    // Decide the scheme once, from the connection and the configured trust in proxies.
    // This is the same resolution `crates/ui` uses for the cookie's `Secure` attribute, so
    // the two headers cannot disagree about whether a request was secure.
    //
    // The transport's TLS state is never read from the URI. `request.uri().scheme_str()`
    // is empty for an HTTP/1.1 request in origin-form — which is every request a browser
    // sends — so a process serving TLS saw "not https" and dropped both `Secure` and HSTS;
    // and on HTTP/2 the scheme is a client-supplied `:scheme` pseudo-header, so trusting it
    // let a cleartext client forge one. `https_only` is the operator's declaration that the
    // listener terminates TLS, which the URI cannot express.
    let scheme = effective_scheme(
        https_only,
        request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok()),
        trusted_proxies,
    );
    // Publish the answer for anyone downstream that needs it — the renderer cannot see the
    // connection, but it must make the same cookie decision this middleware makes.
    request.extensions_mut().insert(ResolvedScheme(scheme));

    let mut response = next.run(request).await;

    // The nonce the renderer names is the one its inline scripts carry. It is read from
    // the response, not from the request, so a client cannot supply it; and it is only
    // honoured on an HTML document, because a nonce is meaningless anywhere else.
    let rendered_nonce = if is_html(&response) {
        response
            .headers()
            .get(RENDERED_NONCE_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|value| is_well_formed_nonce(value))
            .map(str::to_string)
    } else {
        None
    };

    let headers = response.headers_mut();

    let policy = match rendered_nonce {
        Some(nonce) => csp_with_nonce(&nonce),
        None => csp_without_nonce(),
    };

    headers.remove(RENDERED_NONCE_HEADER);
    headers.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).expect("CSP is a valid header value"),
    );

    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    if scheme == Scheme::Https {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    response
}

fn is_html(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::{Router, middleware};
    use tower::ServiceExt;

    /// A renderer nonce as Leptos mints one: fresh per response, entropy from the OS, and
    /// never a literal baked into production code.
    fn fresh_nonce() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let mut out = String::new();
        for byte in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        out
    }

    /// Build a router whose one handler answers `text/html` (or `text/plain`) and either
    /// echoes a renderer nonce under the marker header, sets a policy of its own, or does
    /// neither — then drive one request through the real middleware.
    async fn response_for(
        trusted_proxies: usize,
        forwarded: Option<&str>,
        behaviour: Behaviour,
    ) -> Response {
        response_for_policy(
            SchemePolicy {
                trusted_proxies,
                https_only: false,
            },
            forwarded,
            behaviour,
        )
        .await
    }

    /// The full-policy variant, so a test can set `https_only` and the TLS marker.
    async fn response_for_policy(
        policy: SchemePolicy,
        forwarded: Option<&str>,
        behaviour: Behaviour,
    ) -> Response {
        let app = Router::new()
            .route(
                "/",
                get(move || {
                    let behaviour = behaviour.clone();
                    async move {
                        let builder = Response::builder();
                        match behaviour {
                            Behaviour::Rendered {
                                nonce,
                                content_type,
                            } => builder
                                .header(CONTENT_TYPE, content_type)
                                .header(RENDERED_NONCE_HEADER, nonce)
                                .body(Body::from("ok")),
                            Behaviour::Plain => builder
                                .header(CONTENT_TYPE, "application/json")
                                .body(Body::from("{}")),
                            Behaviour::HandlerPolicy { policy } => builder
                                .header(CONTENT_TYPE, "text/html")
                                .header(CONTENT_SECURITY_POLICY, policy)
                                .body(Body::from("ok")),
                            Behaviour::MalformedMarker { value } => builder
                                .header(CONTENT_TYPE, "text/html")
                                .header(RENDERED_NONCE_HEADER, value)
                                .body(Body::from("ok")),
                        }
                        .expect("response")
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(policy, apply));

        let mut builder = Request::builder().uri("/");
        if let Some(value) = forwarded {
            builder = builder.header("x-forwarded-proto", value);
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("response")
    }

    #[derive(Clone)]
    enum Behaviour {
        Rendered {
            nonce: String,
            content_type: &'static str,
        },
        Plain,
        HandlerPolicy {
            policy: &'static str,
        },
        MalformedMarker {
            value: &'static str,
        },
    }

    fn csp_of(response: &Response) -> &str {
        response.headers()[CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("CSP header")
    }

    #[tokio::test]
    async fn sets_the_headers_that_constrain_the_page() {
        let resp = response_for(0, None, Behaviour::Plain).await;
        let h = resp.headers();
        assert_eq!(h[X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[REFERRER_POLICY], "no-referrer");
        assert!(csp_of(&resp).contains("frame-ancestors 'none'"));
        assert!(csp_of(&resp).contains("object-src 'none'"));
    }

    #[tokio::test]
    async fn the_hardening_directives_are_present_on_every_response() {
        let nonce = fresh_nonce();
        for behaviour in [
            Behaviour::Plain,
            Behaviour::Rendered {
                nonce: nonce.clone(),
                content_type: "text/html",
            },
            Behaviour::HandlerPolicy {
                policy: "default-src *",
            },
        ] {
            let resp = response_for(0, None, behaviour).await;
            let policy = csp_of(&resp);
            for directive in [
                "frame-ancestors 'none'",
                "object-src 'none'",
                "base-uri 'none'",
                "form-action 'self'",
            ] {
                assert!(
                    policy.contains(directive),
                    "missing {directive} in {policy}"
                );
            }
        }
    }

    #[tokio::test]
    async fn csp_allows_wasm_but_not_arbitrary_inline_script() {
        let nonce = fresh_nonce();
        let resp = response_for(
            0,
            None,
            Behaviour::Rendered {
                nonce,
                content_type: "text/html",
            },
        )
        .await;
        let csp = csp_of(&resp);
        assert!(
            csp.contains("'wasm-unsafe-eval'"),
            "the Leptos WASM bundle needs wasm-unsafe-eval: {csp}"
        );
        assert!(
            !csp.contains("script-src 'self' 'unsafe-inline'"),
            "inline script must be admitted only through a nonce: {csp}"
        );
    }

    #[tokio::test]
    async fn a_handler_cannot_weaken_the_content_security_policy() {
        // A downstream response that sets a permissive policy must not survive: the
        // middleware overwrites it with the mandatory one.
        let resp = response_for(
            0,
            None,
            Behaviour::HandlerPolicy {
                policy: "default-src *; script-src 'unsafe-inline'",
            },
        )
        .await;
        let csp = csp_of(&resp);
        assert!(
            !csp.contains("default-src *"),
            "a handler-supplied policy was preserved: {csp}"
        );
        assert!(
            !csp.contains("script-src 'unsafe-inline'"),
            "a handler loosened script-src: {csp}"
        );
        assert!(
            !csp.contains("'nonce-"),
            "a handler policy earned a nonce: {csp}"
        );
    }

    #[tokio::test]
    async fn a_trusted_renderer_keeps_the_nonce_its_scripts_carry() {
        let nonce = fresh_nonce();
        let resp = response_for(
            0,
            None,
            Behaviour::Rendered {
                nonce: nonce.clone(),
                content_type: "text/html",
            },
        )
        .await;
        let csp = csp_of(&resp);
        assert!(
            csp.contains(&format!("'nonce-{nonce}'")),
            "the renderer's nonce was dropped: {csp}"
        );
        assert!(
            !resp.headers().contains_key(RENDERED_NONCE_HEADER),
            "the internal marker must not reach the client"
        );
    }

    #[tokio::test]
    async fn a_malformed_nonce_marker_is_rejected_rather_than_substituted() {
        // A value outside the base64url alphabet could terminate the header or smuggle a
        // directive; it must fall back to the script-free policy.
        let resp = response_for(
            0,
            None,
            Behaviour::MalformedMarker {
                value: "abc'; script-src *; x='",
            },
        )
        .await;
        let csp = csp_of(&resp);
        assert!(!csp.contains("'nonce-"), "{csp}");
        assert!(!csp.contains("script-src *"), "{csp}");
    }

    #[tokio::test]
    async fn a_nonce_marker_on_a_non_html_response_is_ignored() {
        let resp = response_for(
            0,
            None,
            Behaviour::Rendered {
                nonce: fresh_nonce(),
                content_type: "application/json",
            },
        )
        .await;
        assert!(!csp_of(&resp).contains("'nonce-"), "{}", csp_of(&resp));
    }

    #[tokio::test]
    async fn hsts_is_only_asserted_over_trusted_tls() {
        let plain = response_for(0, None, Behaviour::Plain).await;
        assert!(
            !plain.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "HSTS on plain HTTP would pin http://localhost in the developer's browser"
        );

        // A directly exposed process must not believe a client-supplied forwarded header:
        // doing so would let an attacker on plain HTTP have their request marked secure.
        let spoofed = response_for(0, Some("https"), Behaviour::Plain).await;
        assert!(
            !spoofed.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "a forgeable forwarded header turned HSTS on"
        );

        // With a proxy declared, its forwarded scheme is honoured.
        let proxied = response_for(1, Some("https"), Behaviour::Plain).await;
        assert!(proxied.headers().contains_key(STRICT_TRANSPORT_SECURITY));
    }

    #[tokio::test]
    async fn a_direct_tls_connection_asserts_hsts_without_a_forwarded_header() {
        // Regression (CWE-614): the transport TLS state was read from
        // `request.uri().scheme_str()`, which is `None` for an HTTP/1.1 request in
        // origin-form — every browser request. A process serving TLS therefore classified
        // the connection as plain HTTP and dropped HSTS (and, through the shared
        // `ResolvedScheme`, the cookie's `Secure`). With no marker to read on the URI, the
        // operator's `https_only` is what now tells the middleware the listener is TLS.
        let secure = response_for_policy(
            SchemePolicy {
                trusted_proxies: 0,
                https_only: true,
            },
            None,
            Behaviour::Plain,
        )
        .await;
        assert!(
            secure.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "a TLS connection must assert HSTS even with no forwarded header"
        );

        // And the same policy must not believe a forged forwarded header on a plain
        // connection: the fix adds a declaration, it does not trust the header more.
        let spoofed = response_for_policy(
            SchemePolicy {
                trusted_proxies: 0,
                https_only: false,
            },
            Some("https"),
            Behaviour::Plain,
        )
        .await;
        assert!(
            !spoofed.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "a client-supplied forwarded header must not turn HSTS on"
        );

        // The declaration defaults off, so a plain listener must not assert HSTS.
        let off_by_default = response_for(0, None, Behaviour::Plain).await;
        assert!(
            !off_by_default
                .headers()
                .contains_key(STRICT_TRANSPORT_SECURITY),
            "https_only defaults off"
        );
    }

    #[tokio::test]
    async fn an_https_uri_scheme_is_not_evidence_of_tls() {
        // The previous implementation read the scheme off the request URI. On HTTP/2 that
        // is a client-supplied `:scheme` pseudo-header, so a cleartext h2c client could
        // send `:scheme: https` and have its request marked secure. The middleware must not
        // consult the URI at all, so a request whose URI literally says `https` — driven
        // through the real middleware — still yields no HSTS when the transport is plain and
        // no proxy is trusted.
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    Response::builder()
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from("{}"))
                        .expect("response")
                }),
            )
            .layer(middleware::from_fn_with_state(
                SchemePolicy {
                    trusted_proxies: 0,
                    https_only: false,
                },
                apply,
            ));

        let forged = app
            .oneshot(
                Request::builder()
                    .uri("https://attacker.example/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("response");
        assert!(
            !forged.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "a URI scheme is attacker-controlled and must not turn HSTS on"
        );
    }

    #[tokio::test]
    async fn https_only_asserts_hsts_for_a_listener_that_cannot_mark_the_connection() {
        // An operator whose TLS terminator runs in-process on another port, or hands this
        // process a TLS stream that does not surface as a URI scheme, declares the fact in
        // configuration. With `trusted_proxies == 0` a forged header still cannot turn HSTS
        // on; only the declaration can.
        let declared = response_for_policy(
            SchemePolicy {
                trusted_proxies: 0,
                https_only: true,
            },
            None,
            Behaviour::Plain,
        )
        .await;
        assert!(
            declared.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "https_only must assert HSTS"
        );

        let off_by_default = response_for(0, None, Behaviour::Plain).await;
        assert!(
            !off_by_default
                .headers()
                .contains_key(STRICT_TRANSPORT_SECURITY),
            "https_only defaults off, so a plain listener must not assert HSTS"
        );
    }
}
