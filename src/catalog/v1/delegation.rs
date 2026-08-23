//! Parsing of the `X-Iceberg-Access-Delegation` request header.
//!
//! The Iceberg REST spec makes credential delegation something a client **asks
//! for**, not something a server does by default. A client that has its own
//! credentials — an engine already running with an instance role, say — never
//! wants the catalog to mint more, and a server that vends unrequested
//! credentials hands out authority nobody asked for and widens the blast radius
//! of every response it sends.
//!
//! The header carries a comma-separated list of the delegation forms the client
//! is willing to accept:
//!
//! ```text
//! X-Iceberg-Access-Delegation: vended-credentials
//! X-Iceberg-Access-Delegation: vended-credentials, remote-signing
//! ```
//!
//! Unknown values are ignored rather than rejected, so a client that asks for a
//! form this server does not implement still gets the forms it does.

use axum::http::HeaderMap;

/// Header through which a client requests credential delegation.
pub const ACCESS_DELEGATION_HEADER: &str = "x-iceberg-access-delegation";

/// Delegation form: the catalog mints short-lived storage credentials.
const VENDED_CREDENTIALS: &str = "vended-credentials";

/// Delegation form: the catalog signs each storage request on the client's behalf.
const REMOTE_SIGNING: &str = "remote-signing";

/// What the client asked the catalog to delegate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccessDelegation {
    /// The client accepts vended credentials.
    pub vended_credentials: bool,
    /// The client accepts remote request signing.
    pub remote_signing: bool,
}

impl AccessDelegation {
    /// Reads the delegation request from `headers`.
    ///
    /// An absent header means no delegation was requested, and nothing is
    /// vended. Absence is the common case for clients that carry their own
    /// storage credentials.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut delegation = Self::default();

        // Every occurrence, not just the first. A comma-separated list header
        // may legally be split across repeated header lines, and Iceberg clients
        // do send it that way — `get` would read one form and silently discard
        // the rest, so a client asking for both would be told it asked for one.
        for value in headers.get_all(ACCESS_DELEGATION_HEADER) {
            let Ok(value) = value.to_str() else { continue };
            for form in value.split(',') {
                // Values are case-insensitive and may be padded, and an unknown
                // one must not discard the rest of the list.
                match form.trim().to_ascii_lowercase().as_str() {
                    VENDED_CREDENTIALS => delegation.vended_credentials = true,
                    REMOTE_SIGNING => delegation.remote_signing = true,
                    _ => {}
                }
            }
        }
        delegation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(ACCESS_DELEGATION_HEADER, value.parse().unwrap());
        h
    }

    #[test]
    fn absent_header_requests_nothing() {
        let d = AccessDelegation::from_headers(&HeaderMap::new());
        assert!(!d.vended_credentials && !d.remote_signing);
        assert!(!d.vended_credentials);
    }

    #[test]
    fn parses_vended_credentials() {
        let d = AccessDelegation::from_headers(&headers("vended-credentials"));
        assert!(d.vended_credentials);
        assert!(!d.remote_signing);
    }

    #[test]
    fn parses_multiple_forms() {
        let d = AccessDelegation::from_headers(&headers("vended-credentials, remote-signing"));
        assert!(d.vended_credentials);
        assert!(d.remote_signing);
    }

    #[test]
    fn is_case_and_whitespace_insensitive() {
        let d = AccessDelegation::from_headers(&headers("  Vended-Credentials  "));
        assert!(d.vended_credentials);
    }

    /// An unrecognised form must not discard the ones alongside it.
    #[test]
    fn ignores_unknown_forms() {
        let d = AccessDelegation::from_headers(&headers("future-thing, vended-credentials"));
        assert!(d.vended_credentials);

        let d = AccessDelegation::from_headers(&headers("future-thing"));
        assert!(!d.vended_credentials && !d.remote_signing);
    }

    /// A list header may arrive as repeated lines. Reading only the first threw
    /// away every form after it.
    #[test]
    fn repeated_header_lines_are_all_read() {
        let mut h = HeaderMap::new();
        h.append(
            ACCESS_DELEGATION_HEADER,
            "vended-credentials".parse().unwrap(),
        );
        h.append(ACCESS_DELEGATION_HEADER, "remote-signing".parse().unwrap());

        let d = AccessDelegation::from_headers(&h);
        assert!(d.vended_credentials);
        assert!(d.remote_signing);
    }

    #[test]
    fn empty_header_requests_nothing() {
        let d = AccessDelegation::from_headers(&headers(""));
        assert!(!d.vended_credentials && !d.remote_signing);
    }
}
