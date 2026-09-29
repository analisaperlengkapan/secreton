//! Deciding the scheme a request actually arrived over.
//!
//! Two security decisions depend on this — whether the session cookie carries `Secure`,
//! and whether the response asserts HSTS — and they must never disagree. They are answered
//! once, here, from both the directly observed connection and the forwarded metadata a
//! trusted proxy may have supplied.
//!
//! The forwarded header is attacker-controlled until a trusted hop appends to it, so it is
//! only consulted when proxies are declared and only at the position that hop owns. The
//! rule matches [`rate limit`]'s treatment of `X-Forwarded-For`: entry count is measured
//! back from the right, because everything a client can prepend sits to the left.
//!
//! [`rate limit`]: ../../secreton_server/middleware/rate_limit

/// The scheme a request was made over, as far as this process can establish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plain HTTP.
    Http,
    /// TLS, whether terminated here or by a trusted proxy.
    Https,
}

impl Scheme {
    /// Whether this scheme is TLS.
    pub fn is_https(self) -> bool {
        matches!(self, Scheme::Https)
    }
}

/// The resolved scheme, carried on the request so every decision that depends on it reads
/// the same answer.
///
/// The security-header middleware resolves it once, from the connection and the configured
/// proxy trust, and inserts this into request extensions. A consumer that only needs the
/// answer — the cookie's `Secure` attribute, for one — reads it here rather than
/// re-deriving it from the raw header, which is where the two sides drifted apart before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedScheme(pub Scheme);

/// Resolve the scheme the *client* used.
///
/// `transport_is_tls` is the scheme of the connection into this process, which the runtime
/// observes directly and no client can forge. `forwarded_proto` is the raw
/// `X-Forwarded-Proto` value, if any.
///
/// - With `trusted_proxies == 0` the forwarded header is ignored entirely and only the
///   observed transport decides. A directly exposed process must never let a client claim
///   it arrived over TLS: doing so would let an attacker on plain HTTP have their request
///   marked secure, which is the decision that gates `Secure` cookies and HSTS.
/// - With `trusted_proxies == n` the scheme is read from the `n`-th entry counted from the
///   right — the value appended by the outermost trusted proxy, which reflects what the
///   client actually used. Entries further left were supplied by the client.
/// - When a trusted proxy is declared but the header is absent or malformed, the observed
///   transport is the fallback.
pub fn effective_scheme(
    transport_is_tls: bool,
    forwarded_proto: Option<&str>,
    trusted_proxies: usize,
) -> Scheme {
    if trusted_proxies > 0
        && let Some(value) = forwarded_proto
        && let Some(entry) = trusted_hop_entry(value, trusted_proxies)
    {
        return if entry.eq_ignore_ascii_case("https") {
            Scheme::Https
        } else {
            Scheme::Http
        };
    }

    if transport_is_tls {
        Scheme::Https
    } else {
        Scheme::Http
    }
}

/// The entry in a comma-separated forwarded list that the outermost trusted proxy wrote.
///
/// `X-Forwarded-Proto` is a list because each hop that chooses to append contributes one
/// entry; a hop that overwrites the header contributes only its own. Counting from the
/// right is the only position a client cannot occupy: anything it prepends shifts the
/// trusted entries left, but never past the end.
fn trusted_hop_entry(forwarded: &str, trusted_proxies: usize) -> Option<&str> {
    let entries: Vec<&str> = forwarded.split(',').map(str::trim).collect();
    let index = entries.len().checked_sub(trusted_proxies)?;
    entries.get(index).copied().filter(|e| !e.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_trusted_proxies_the_forwarded_header_is_ignored() {
        // The direct-listener case. A client sending this over plain HTTP must not have
        // its request treated as secure.
        assert_eq!(effective_scheme(false, Some("https"), 0), Scheme::Http);
        assert_eq!(effective_scheme(false, Some("http"), 0), Scheme::Http);
        assert_eq!(effective_scheme(false, None, 0), Scheme::Http);
    }

    #[test]
    fn a_directly_terminated_tls_connection_is_secure() {
        assert_eq!(effective_scheme(true, None, 0), Scheme::Https);
        // A forged header cannot downgrade what was observed directly, nor is it believed
        // over the observation.
        assert_eq!(effective_scheme(true, Some("http"), 0), Scheme::Https);
    }

    #[test]
    fn one_trusted_proxy_reports_the_scheme_the_client_used() {
        assert_eq!(effective_scheme(false, Some("https"), 1), Scheme::Https);
        assert_eq!(effective_scheme(false, Some("http"), 1), Scheme::Http);
    }

    #[test]
    fn a_spoofed_prefix_cannot_change_the_resolved_scheme() {
        // The client wrote "https"; the trusted proxy appended what it saw. Counting from
        // the right ignores the forged prefix.
        assert_eq!(
            effective_scheme(false, Some("https, http"), 1),
            Scheme::Http,
            "taking the leftmost entry would let any client choose its own scheme"
        );
    }

    #[test]
    fn two_trusted_proxies_count_two_back() {
        assert_eq!(
            effective_scheme(false, Some("http, https, http"), 2),
            Scheme::Https
        );
    }

    #[test]
    fn a_short_header_falls_back_to_the_observed_transport() {
        // Fewer entries than declared proxies means the chain is not what was configured;
        // the observed connection is the trustworthy fallback rather than a panic or a
        // guess.
        assert_eq!(effective_scheme(false, Some("https"), 3), Scheme::Http);
        assert_eq!(effective_scheme(true, Some("https"), 3), Scheme::Https);
    }

    #[test]
    fn an_empty_hop_entry_falls_back_rather_than_matching() {
        assert_eq!(
            effective_scheme(false, Some("https, , https"), 2),
            Scheme::Http
        );
    }

    #[test]
    fn casing_and_whitespace_do_not_change_the_verdict() {
        assert_eq!(effective_scheme(false, Some(" HTTPS "), 1), Scheme::Https);
    }
}
