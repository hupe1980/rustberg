//! Authentication trait and implementations.
//!
//! This module defines the core authentication interface and provides
//! several authenticator implementations including API key authentication.
//!
//! # Security
//!
//! API keys are 256-bit random tokens hashed with SHA-256 and compared in
//! constant time. See [`hash_api_key`](super::hash_api_key) for why a password
//! KDF is the wrong tool for a high-entropy bearer token, and what it cost when
//! one was used here.

use async_trait::async_trait;
use axum::http::HeaderMap;
use std::sync::Arc;

use super::error::{AuthError, Result};
use super::principal::{AuthMethod, Principal, PrincipalBuilder, PrincipalType};
use super::store::{ApiKey, ApiKeyStore, extract_key_prefix, verify_api_key};

/// Header name for API key authentication.
pub const API_KEY_HEADER: &str = "X-API-Key";

/// Header name for bearer token authentication.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// A well-formed hash that no key can match, verified when no candidate key
/// exists so that "unknown prefix" and "wrong secret" take the same path.
///
/// SHA-256 of a value never issued as a key.
const DUMMY_HASH_FOR_TIMING: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Trait for authenticating incoming requests.
///
/// Implementors extract credentials from requests and validate them,
/// returning a Principal on success or an AuthError on failure.
#[async_trait]
pub trait Authenticator: Send + Sync {
    /// Attempts to authenticate using request headers.
    ///
    /// Returns `Ok(Principal)` if authentication succeeds, or `Err(AuthError)`
    /// if authentication fails. Returns `Err(AuthError::Unauthenticated)` if
    /// no credentials are present.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal>;

    /// Returns the authentication method this authenticator handles.
    fn auth_method(&self) -> AuthMethod;
}

// ============================================================================
// AllowAllAuthenticator
// ============================================================================

/// Authenticator that allows all requests (for development/testing only).
///
/// **WARNING**: This should never be used in production. It returns an
/// anonymous principal for every request.
pub struct AllowAllAuthenticator;

#[async_trait]
impl Authenticator for AllowAllAuthenticator {
    async fn authenticate(&self, _headers: &HeaderMap) -> Result<Principal> {
        Ok(Principal::anonymous())
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::None
    }
}

// ============================================================================
// DenyAllAuthenticator
// ============================================================================

/// Authenticator that denies all requests.
///
/// Useful for testing error handling or as a placeholder.
pub struct DenyAllAuthenticator;

#[async_trait]
impl Authenticator for DenyAllAuthenticator {
    async fn authenticate(&self, _headers: &HeaderMap) -> Result<Principal> {
        Err(AuthError::Unauthenticated)
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::None
    }
}

// ============================================================================
// ApiKeyAuthenticator
// ============================================================================

/// Authenticator that validates API keys from the X-API-Key header.
///
/// Validation is two steps:
/// 1. Extract the key prefix for an O(1) lookup in the store
/// 2. Compare the full key's hash against the stored hash, in constant time
///
/// A key whose prefix matches nothing still runs a dummy verification, so
/// "no such key" and "wrong key" are indistinguishable by timing.
pub struct ApiKeyAuthenticator {
    store: Arc<dyn ApiKeyStore>,
}

/// Maximum length of an API key.
/// Format: `rb_` prefix (3 chars) + 43 chars base64url = 46 total
/// We allow some margin for flexibility.
const MAX_API_KEY_LENGTH: usize = 64;

/// Minimum length of an API key (prefix + some key material).
const MIN_API_KEY_LENGTH: usize = 10;

/// API key prefix for Rustberg keys.
const API_KEY_PREFIX: &str = "rb_";

impl ApiKeyAuthenticator {
    /// Creates a new API key authenticator with the given store.
    pub fn new(store: Arc<dyn ApiKeyStore>) -> Self {
        Self { store }
    }

    /// Validates the format of an API key.
    ///
    /// Returns `Ok(())` if the key is valid, `Err` with a description otherwise.
    fn validate_key_format(key: &str) -> std::result::Result<(), &'static str> {
        // Check length bounds (fast fail before any other processing)
        if key.len() > MAX_API_KEY_LENGTH {
            return Err("API key too long");
        }

        if key.len() < MIN_API_KEY_LENGTH {
            return Err("API key too short");
        }

        // Check prefix
        if !key.starts_with(API_KEY_PREFIX) {
            return Err("Invalid API key format");
        }

        // Check that the key material contains only valid base64url characters
        // Valid chars: A-Z, a-z, 0-9, -, _
        let key_material = &key[API_KEY_PREFIX.len()..];
        if !key_material
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("API key contains invalid characters");
        }

        Ok(())
    }

    /// Extracts the API key from request headers.
    ///
    /// Two forms are accepted, in this order:
    ///
    /// 1. `X-API-Key: rb_…` — explicit, and what `curl` examples use.
    /// 2. `Authorization: Bearer rb_…` — **what Iceberg clients actually send.**
    ///
    /// The second is not a convenience. PyIceberg, Spark and Trino all carry a
    /// catalog credential in their `token` property and transmit it as
    /// `Authorization: Bearer`; none of them offers a way to set an arbitrary
    /// header. Accepting only `X-API-Key` therefore made API keys unusable from
    /// every standard client — the documented Spark and PyIceberg examples all
    /// returned `401`.
    ///
    /// Reading a bearer token here does not conflict with JWT authentication.
    /// [`ChainAuthenticator`] tries the JWT authenticator first, and a value that
    /// is not a well-formed token falls through to here. An API key is
    /// unambiguous anyway: it carries the `rb_` prefix, which no JWT has, and
    /// [`validate_key_format`](Self::validate_key_format) rejects anything else
    /// before the value is used.
    fn extract_key(headers: &HeaderMap) -> Option<String> {
        if let Some(key) = headers.get(API_KEY_HEADER).and_then(|v| v.to_str().ok()) {
            return Some(key.to_string());
        }

        headers
            .get(AUTHORIZATION_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|value| {
                // The scheme is case-insensitive per RFC 7235.
                let (scheme, token) = value.split_once(' ')?;
                scheme
                    .eq_ignore_ascii_case("Bearer")
                    .then(|| token.trim().to_string())
            })
    }

    /// Creates a principal from a validated API key.
    fn key_to_principal(api_key: &ApiKey) -> Principal {
        let mut builder = PrincipalBuilder::new(
            api_key.id.to_string(),
            api_key.name.clone(),
            PrincipalType::ApiKey,
            api_key.tenant_id.clone(),
            AuthMethod::ApiKey,
        );

        for role in &api_key.roles {
            builder = builder.with_role(role.clone());
        }

        if let Some(expires_at) = api_key.expires_at {
            builder = builder.expires_at(expires_at);
        }

        builder.build()
    }
}

#[async_trait]
impl Authenticator for ApiKeyAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal> {
        // Extract the API key from the header
        let raw_key = Self::extract_key(headers).ok_or(AuthError::Unauthenticated)?;

        if raw_key.is_empty() {
            return Err(AuthError::InvalidCredentials("Empty API key".into()));
        }

        // Validate key format BEFORE any processing (prevents DoS via large inputs)
        if let Err(reason) = Self::validate_key_format(&raw_key) {
            return Err(AuthError::InvalidCredentials(reason.into()));
        }

        // Extract prefix for O(1) lookup
        let key_prefix = extract_key_prefix(&raw_key)
            .ok_or_else(|| AuthError::InvalidCredentials("Invalid key format".into()))?;

        // Look up candidate keys by prefix (may return multiple if prefix collides)
        let candidates = self.store.get_by_prefix(&key_prefix).await;

        // SECURITY: Always run a verification to prevent timing attacks.
        // If no candidates exist, we run a dummy verification against a fake hash
        // to ensure constant-time behavior regardless of key existence.
        let api_key = if candidates.is_empty() {
            // Run a dummy verification so the timing matches a real miss.
            // The hash format is valid but will never match any real key.
            let _ = verify_api_key(&raw_key, DUMMY_HASH_FOR_TIMING);
            return Err(AuthError::ApiKeyNotFound);
        } else {
            // Find the matching key by constant-time hash comparison
            // This is constant-time per key to prevent timing attacks
            candidates
                .into_iter()
                .find(|k| verify_api_key(&raw_key, &k.key_hash))
                .ok_or(AuthError::ApiKeyNotFound)?
        };

        // Check if the key is enabled
        if !api_key.enabled {
            return Err(AuthError::ApiKeyDisabled);
        }

        // Check expiration
        if api_key.is_expired() {
            return Err(AuthError::TokenExpired);
        }

        // Record the usage
        let _ = self.store.record_usage(&api_key.id).await;

        Ok(Self::key_to_principal(&api_key))
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::ApiKey
    }
}

// ============================================================================
// ChainAuthenticator
// ============================================================================

/// Authenticator that tries multiple authenticators in order.
///
/// The first authenticator to successfully authenticate the request wins.
/// If all authenticators fail, the error from the last one is returned.
pub struct ChainAuthenticator {
    authenticators: Vec<Arc<dyn Authenticator>>,
}

impl ChainAuthenticator {
    /// Creates a new chain authenticator with the given authenticators.
    pub fn new(authenticators: Vec<Arc<dyn Authenticator>>) -> Self {
        Self { authenticators }
    }

    /// Adds an authenticator to the chain.
    pub fn with(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticators.push(authenticator);
        self
    }
}

#[async_trait]
impl Authenticator for ChainAuthenticator {
    async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal> {
        let mut last_error = AuthError::Unauthenticated;

        for auth in &self.authenticators {
            match auth.authenticate(headers).await {
                Ok(principal) => return Ok(principal),
                Err(AuthError::Unauthenticated) => continue,
                Err(e) => {
                    last_error = e;
                    continue;
                }
            }
        }

        Err(last_error)
    }

    fn auth_method(&self) -> AuthMethod {
        // Return the method of the first authenticator
        self.authenticators
            .first()
            .map(|a| a.auth_method())
            .unwrap_or(AuthMethod::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allow_all_authenticator() {
        let auth = AllowAllAuthenticator;
        let headers = HeaderMap::new();

        let result = auth.authenticate(&headers).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_anonymous());
    }

    #[tokio::test]
    async fn test_deny_all_authenticator() {
        let auth = DenyAllAuthenticator;
        let headers = HeaderMap::new();

        let result = auth.authenticate(&headers).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_api_key_hashing_is_deterministic() {
        use super::super::store::{hash_api_key, verify_api_key};

        let key = "rb_test-api-key-12345";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);

        // Unsalted, so the same key always yields the same hash. That is what
        // lets a config-declared key be matched without storing per-key state.
        assert_eq!(hash1, hash2);
        assert!(verify_api_key(key, &hash1));
        assert!(hash1.starts_with("sha256:"));
    }

    /// The whole point of dropping Argon2: verification must be cheap enough to
    /// sit on every request. A password KDF at OWASP parameters takes tens of
    /// milliseconds and allocates 19 MiB; this must not.
    #[test]
    fn test_api_key_verification_is_fast() {
        use super::super::store::{hash_api_key, verify_api_key};
        use std::time::Instant;

        let key = "rb_test-api-key-12345";
        let hash = hash_api_key(key);

        let start = Instant::now();
        for _ in 0..1_000 {
            assert!(verify_api_key(key, &hash));
        }
        let elapsed = start.elapsed();

        // Generous by three orders of magnitude against Argon2, so this fails
        // only if a password KDF reappears on the hot path — not on a slow CI box.
        assert!(
            elapsed.as_millis() < 500,
            "1000 verifications took {elapsed:?}; a KDF is back on the request path"
        );
    }

    /// A wrong key must not verify against the dummy hash either.
    #[test]
    fn test_dummy_hash_never_matches() {
        use super::super::store::verify_api_key;

        assert!(!verify_api_key("rb_anything-at-all", DUMMY_HASH_FOR_TIMING));
    }

    #[test]
    fn test_api_key_verification() {
        use super::super::store::{hash_api_key, verify_api_key};

        let key = "rb_correct-key-12345";
        let hash = hash_api_key(key);

        // Correct key verifies
        assert!(verify_api_key(key, &hash));

        // Wrong key doesn't verify
        assert!(!verify_api_key("rb_wrong-key-54321", &hash));
    }

    // ========================================================================
    // Input Validation Tests
    // ========================================================================

    #[test]
    fn test_validate_key_format_valid() {
        // Valid key format: rb_ + base64url characters
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abcdefghij").is_ok());
        assert!(ApiKeyAuthenticator::validate_key_format("rb_ABC123xyz-_").is_ok());
        assert!(
            ApiKeyAuthenticator::validate_key_format("rb_0123456789abcdefghijklmnopqrstuvwxyz")
                .is_ok()
        );
    }

    #[test]
    fn test_validate_key_format_too_short() {
        assert!(ApiKeyAuthenticator::validate_key_format("rb_").is_err());
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc").is_err());
        assert!(ApiKeyAuthenticator::validate_key_format("short").is_err());
    }

    #[test]
    fn test_validate_key_format_too_long() {
        // Create a key that's too long (> 64 chars)
        let long_key = format!("rb_{}", "a".repeat(100));
        assert!(ApiKeyAuthenticator::validate_key_format(&long_key).is_err());
    }

    #[test]
    fn test_validate_key_format_wrong_prefix() {
        assert!(ApiKeyAuthenticator::validate_key_format("sk_abcdefghij").is_err());
        assert!(ApiKeyAuthenticator::validate_key_format("api_abcdefghij").is_err());
        assert!(ApiKeyAuthenticator::validate_key_format("abcdefghijklmnop").is_err());
    }

    #[test]
    fn test_validate_key_format_invalid_chars() {
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc def").is_err()); // space
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc@def").is_err()); // @
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc!def").is_err()); // !
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc+def").is_err()); // + (not base64url)
        assert!(ApiKeyAuthenticator::validate_key_format("rb_abc/def").is_err());
        // / (not base64url)
    }

    // ── Credential transport ──────────────────────────────────────────────

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (name, value) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn extracts_key_from_the_explicit_header() {
        let h = headers(&[("x-api-key", "rb_abc123")]);
        assert_eq!(
            ApiKeyAuthenticator::extract_key(&h).as_deref(),
            Some("rb_abc123")
        );
    }

    /// PyIceberg, Spark and Trino all send their catalog credential as
    /// `Authorization: Bearer` and offer no way to set a custom header. Reading
    /// only `X-API-Key` made API keys unusable from every standard client.
    #[test]
    fn extracts_key_from_a_bearer_token() {
        let h = headers(&[("authorization", "Bearer rb_abc123")]);
        assert_eq!(
            ApiKeyAuthenticator::extract_key(&h).as_deref(),
            Some("rb_abc123")
        );
    }

    #[test]
    fn bearer_scheme_is_case_insensitive() {
        // RFC 7235 makes the scheme case-insensitive, and clients vary.
        for value in ["bearer rb_abc", "BEARER rb_abc", "BeArEr rb_abc"] {
            let h = headers(&[("authorization", value)]);
            assert_eq!(
                ApiKeyAuthenticator::extract_key(&h).as_deref(),
                Some("rb_abc"),
                "failed for {value}"
            );
        }
    }

    /// The explicit header wins, so a client sending both gets predictable
    /// behaviour rather than depending on header ordering.
    #[test]
    fn the_explicit_header_takes_precedence() {
        let h = headers(&[
            ("x-api-key", "rb_explicit"),
            ("authorization", "Bearer rb_bearer"),
        ]);
        assert_eq!(
            ApiKeyAuthenticator::extract_key(&h).as_deref(),
            Some("rb_explicit")
        );
    }

    #[test]
    fn other_authorization_schemes_are_ignored() {
        // Basic auth is not an API key, and must not be read as one.
        let h = headers(&[("authorization", "Basic dXNlcjpwYXNz")]);
        assert_eq!(ApiKeyAuthenticator::extract_key(&h), None);

        // A bare value with no scheme is not a bearer token.
        let h = headers(&[("authorization", "rb_abc123")]);
        assert_eq!(ApiKeyAuthenticator::extract_key(&h), None);
    }

    #[test]
    fn absent_credentials_extract_nothing() {
        assert_eq!(ApiKeyAuthenticator::extract_key(&HeaderMap::new()), None);
    }
}
