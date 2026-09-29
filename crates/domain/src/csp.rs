//! The Content-Security-Policy text.
//!
//! The policy lives here, in the crate that has no web framework, because two sides need
//! to agree on it exactly: the server's header middleware, which sets the policy on every
//! response, and the UI shell, which raises the rendered document's nonce so the policy can
//! name it. A policy assembled independently in two crates is a policy that drifts, and a
//! policy whose nonce does not match the document silently kills every inline script.

/// The policy with `{nonce}` as the substitution point for a document's nonce.
///
/// `wasm-unsafe-eval` is required: instantiating a WebAssembly module counts as eval, and
/// the Leptos client bundle is WASM. `'unsafe-inline'` for styles is required by Leptos'
/// hydration, which emits inline style attributes.
///
/// The `script-src` nonce is what lets the inline scripts Leptos writes run. Without it the
/// page renders but never hydrates: those scripts boot the WASM bundle and open the
/// hydration stream, so every control stays inert and a filled-in login form will not even
/// submit. Naming the nonce is strictly better than adding `'unsafe-inline'`, which would
/// also admit an injected script.
pub const CSP_TEMPLATE: &str = "default-src 'self'; \
     script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; \
     font-src 'self'; \
     connect-src 'self'; \
     object-src 'none'; \
     base-uri 'none'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// The policy for a rendered document, naming the nonce its inline scripts carry.
pub fn csp_with_nonce(nonce: &str) -> String {
    CSP_TEMPLATE.replace("{nonce}", nonce)
}

/// The policy for a response that embeds no scripts: API JSON, static files and errors.
/// No nonce is issued because there is nothing to authorise.
pub fn csp_without_nonce() -> String {
    CSP_TEMPLATE.replace("'nonce-{nonce}' ", "")
}

/// The nonce issued for one rendered response.
///
/// The policy that authorises a document's inline scripts and the nonce those scripts
/// carry must be the same value, or the browser refuses to run them and the page never
/// hydrates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedNonce(String);

/// Response header under which the trusted renderer echoes the nonce its inline scripts
/// carry.
///
/// The security-header middleware reads it, builds the policy from it, and removes it, so
/// the client never sees it. It exists to draw the line between a document the renderer
/// actually built and any other response: only a match earns a nonce-bearing policy. A
/// response that merely carries a CSP header, or a marker whose value is not this
/// request's nonce, gets the script-free policy instead, and every response gets the
/// mandatory hardening directives.
pub const RENDERED_NONCE_HEADER: &str = "x-secreton-rendered-nonce";

/// Whether a value is usable as a nonce in a policy and as a header value.
///
/// A nonce is substituted into a header, so anything outside the base64url alphabet could
/// terminate it or smuggle a directive. Rejecting rather than sanitising keeps the policy
/// text unambiguous.
pub fn is_well_formed_nonce(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl RenderedNonce {
    /// Mint a nonce from 16 bytes of OS randomness. Fresh per response: a value an
    /// attacker can predict is not a nonce.
    pub fn generate() -> Self {
        use rand::RngCore;

        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let mut out = String::with_capacity(32);
        for byte in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{byte:02x}");
        }
        Self(out)
    }

    /// Wrap a nonce minted elsewhere, such as by the renderer.
    pub fn from_value(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The nonce as it appears in a policy and in a `nonce` attribute.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RenderedNonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    /// A nonce as the server produces one: fresh random bytes per response, never a
    /// literal. A hard-coded value here would model production incorrectly, and reads to
    /// a scanner as a real nonce baked into the source.
    fn fresh_nonce() -> String {
        let mut bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_nonced_policy_names_that_nonce_and_still_allows_wasm() {
        let nonce = fresh_nonce();
        let policy = csp_with_nonce(&nonce);
        assert!(policy.contains(&format!("'nonce-{nonce}'")), "{policy}");
        assert!(policy.contains("'wasm-unsafe-eval'"), "{policy}");
        assert!(!policy.contains("{nonce}"), "{policy}");
    }

    #[test]
    fn a_nonced_policy_does_not_admit_arbitrary_inline_script() {
        let policy = csp_with_nonce(&fresh_nonce());
        assert!(
            !policy.contains("script-src 'self' 'unsafe-inline'"),
            "inline script must be admitted only through the nonce: {policy}"
        );
    }

    #[test]
    fn a_documentless_policy_carries_no_nonce() {
        let policy = csp_without_nonce();
        assert!(!policy.contains("nonce-"), "{policy}");
        assert!(!policy.contains("{nonce}"), "{policy}");
        assert!(
            policy.contains("script-src 'self' 'wasm-unsafe-eval'"),
            "{policy}"
        );
    }

    #[test]
    fn the_hardening_directives_survive_substitution() {
        for policy in [csp_with_nonce(&fresh_nonce()), csp_without_nonce()] {
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
}
