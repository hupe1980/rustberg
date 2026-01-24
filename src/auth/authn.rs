//! Authentication trait and implementations.
//!
//! This module defines the core authentication interface and provides
//! several authenticator implementations including API key authentication.
//!
//! # Security
//!
//! API keys are hashed using Argon2id, which provides:
//! - Memory-hard computation (resistant to GPU/ASIC attacks)
//! - Side-channel resistance
//! - Protection against database breaches
//!
//! The tradeoff is ~50-100ms verification time per request, but this is
//! acceptable for API key auth which is typically cached or used sparingly.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Request};
use std::sync::Arc;

use super::error::{AuthError, Result};
use super::principal::{AuthMethod, Principal, PrincipalBuilder, PrincipalType};
use super::store::{extract_key_prefix, verify_api_key, ApiKey, ApiKeyStore};

/// Header name for API key authentication.
pub const API_KEY_HEADER: &str = "X-API-Key";

/// Header name for bearer token authentication.
pub const AUTHORIZATION_HEADER: &str = "Authorization";

/// Pre-computed Argon2id hash used for timing attack mitigation.
/// This is verified when no candidates are found to ensure constant-time behavior.
/// The hash corresponds to the string "timing_attack_dummy_key_never_matches"
/// with our standard Argon2id parameters (19 MiB, 2 iterations, 1 parallelism).
const DUMMY_HASH_FOR_TIMING: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$YTJiM2M0ZDVlNmY3ZzhoOQ$0X9ULfbvJjTfCNxvkXqWJ9Y7Pz8eS6fQrKhW4mN3dA0";

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

/// Helper trait to extract headers from a request.
#[allow(dead_code)]
pub trait RequestAuthExt {
    fn headers_for_auth(&self) -> &HeaderMap;
}

impl RequestAuthExt for Request<Body> {
    fn headers_for_auth(&self) -> &HeaderMap {
        self.headers()
    }
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
/// API keys are validated against the provided ApiKeyStore. The key is
/// hashed using Argon2id for secure storage and verification, providing
/// protection against database breaches.
/// Authenticator that validates API keys from the X-API-Key header.
///
/// API keys are validated using a two-step process:
/// 1. Extract the key prefix for O(1) lookup in the store
/// 2. Verify the full key against the Argon2id hash
///
/// This provides both performance (fast prefix lookup) and security
/// (Argon2id password hashing with unique salts per key).
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

    /// Extracts and validates the API key from request headers.
    fn extract_key(headers: &HeaderMap) -> Option<String> {
        headers
            .get(API_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
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

        // SECURITY: Always run Argon2 verification to prevent timing attacks.
        // If no candidates exist, we run a dummy verification against a fake hash
        // to ensure constant-time behavior regardless of key existence.
        let api_key = if candidates.is_empty() {
            // Run dummy Argon2 verification to prevent timing leak.
            // The hash format is valid but will never match any real key.
            let _ = verify_api_key(&raw_key, DUMMY_HASH_FOR_TIMING);
            return Err(AuthError::ApiKeyNotFound);
        } else {
            // Find the matching key using Argon2id verification
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
    fn test_api_key_hashing_argon2() {
        use super::super::store::{hash_api_key, verify_api_key};

        let key = "rb_test-api-key-12345";
        let hash1 = hash_api_key(key);
        let hash2 = hash_api_key(key);

        // Argon2 hashes are different each time (unique salt)
        assert_ne!(hash1, hash2);

        // But both should verify against the original key
        assert!(verify_api_key(key, &hash1));
        assert!(verify_api_key(key, &hash2));

        // Hash is in PHC format: $argon2id$v=19$m=...
        assert!(hash1.starts_with("$argon2id$"));
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
        assert!(ApiKeyAuthenticator::validate_key_format(
            "rb_0123456789abcdefghijklmnopqrstuvwxyz"
        )
        .is_ok());
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
}
