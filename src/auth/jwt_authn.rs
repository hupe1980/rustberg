use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, TokenData, Validation};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::authn::Authenticator;
use super::error::AuthError;
use super::principal::{AuthMethod, Principal, PrincipalBuilder};

/// JWKS (JSON Web Key Set) response from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// Individual JSON Web Key
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Jwk {
    #[serde(rename = "kid")]
    key_id: String,
    #[serde(rename = "kty")]
    key_type: String,
    #[serde(rename = "alg")]
    algorithm: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

/// Standard JWT claims that we validate
#[derive(Debug, Serialize, Deserialize)]
struct StandardClaims {
    sub: String,      // Subject (user ID)
    iss: String,      // Issuer
    aud: StringOrVec, // Audience
    exp: u64,         // Expiration time
    iat: Option<u64>, // Issued at
    nbf: Option<u64>, // Not before
}

/// Custom claims we extract from JWT
#[derive(Debug, Serialize, Deserialize)]
struct CustomClaims {
    #[serde(flatten)]
    standard: StandardClaims,

    // Custom claims for Rustberg
    #[serde(default)]
    tenant_id: Option<String>,

    #[serde(default)]
    roles: Vec<String>,

    #[serde(default)]
    name: Option<String>,

    #[serde(default)]
    email: Option<String>,

    // Additional claims (stored but not used for authz)
    #[serde(flatten)]
    extra: HashMap<String, serde_json::Value>,
}

/// Helper for audience field (can be string or array)
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum StringOrVec {
    String(String),
    Vec(Vec<String>),
}

impl StringOrVec {
    /// Checks if the audience field contains a specific value.
    #[cfg(test)]
    fn contains(&self, value: &str) -> bool {
        match self {
            StringOrVec::String(s) => s == value,
            StringOrVec::Vec(v) => v.iter().any(|s| s == value),
        }
    }
}

/// Configuration for JWT authentication
#[derive(Debug, Clone)]
pub struct JwtConfig {
    /// OIDC issuer URL (e.g., "<https://accounts.google.com>")
    pub issuer: String,

    /// Expected audience (e.g., "rustberg-api")
    pub audience: String,

    /// JWKS endpoint URL (e.g., "<https://accounts.google.com/.well-known/jwks.json>")
    pub jwks_url: String,

    /// Default tenant ID if not in JWT claims
    pub default_tenant_id: String,

    /// Claim name for tenant ID (default: "tenant_id")
    pub tenant_claim: String,

    /// Claim name for roles (default: "roles")
    pub roles_claim: String,

    /// JWKS cache TTL (default: 1 hour)
    pub jwks_cache_ttl: Duration,

    /// Allowed algorithms (default: RS256 only)
    pub allowed_algorithms: Vec<Algorithm>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audience: String::new(),
            jwks_url: String::new(),
            default_tenant_id: "default".to_string(),
            tenant_claim: "tenant_id".to_string(),
            roles_claim: "roles".to_string(),
            jwks_cache_ttl: Duration::from_secs(3600),
            allowed_algorithms: vec![Algorithm::RS256],
        }
    }
}

/// Cached JWKS data with expiration
struct CachedJwks {
    jwks: Jwks,
    expires_at: SystemTime,
}

/// JWT authenticator with JWKS caching
pub struct JwtAuthenticator {
    config: JwtConfig,
    jwks_cache: RwLock<Option<CachedJwks>>,
    decoding_keys: DashMap<String, DecodingKey>,
    http_client: reqwest::Client,
}

impl std::fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtAuthenticator")
            .field("config", &self.config)
            .field("http_client", &"<reqwest::Client>")
            .finish()
    }
}

impl JwtAuthenticator {
    /// Create a new JWT authenticator
    pub fn new(config: JwtConfig) -> Result<Self, AuthError> {
        if config.issuer.is_empty() {
            return Err(AuthError::Configuration(
                "JWT issuer is required".to_string(),
            ));
        }
        if config.audience.is_empty() {
            return Err(AuthError::Configuration(
                "JWT audience is required".to_string(),
            ));
        }
        if config.jwks_url.is_empty() {
            return Err(AuthError::Configuration("JWKS URL is required".to_string()));
        }

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| {
                AuthError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            config,
            jwks_cache: RwLock::new(None),
            decoding_keys: DashMap::new(),
            http_client,
        })
    }

    /// Fetch JWKS from the OIDC provider
    async fn fetch_jwks(&self) -> Result<Jwks, AuthError> {
        let response = self
            .http_client
            .get(&self.config.jwks_url)
            .send()
            .await
            .map_err(|e| AuthError::External(format!("Failed to fetch JWKS: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::External(format!(
                "JWKS endpoint returned status {}",
                response.status()
            )));
        }

        let jwks: Jwks = response
            .json()
            .await
            .map_err(|e| AuthError::External(format!("Failed to parse JWKS: {}", e)))?;

        Ok(jwks)
    }

    /// Get JWKS with caching
    async fn get_jwks(&self) -> Result<Jwks, AuthError> {
        // Check cache first
        {
            let cache = self.jwks_cache.read();
            if let Some(cached) = cache.as_ref() {
                if SystemTime::now() < cached.expires_at {
                    return Ok(cached.jwks.clone());
                }
            }
        }

        // Cache miss or expired - fetch new JWKS
        let jwks = self.fetch_jwks().await?;

        // SECURITY: Clear stale decoding keys when JWKS is refreshed.
        // This ensures revoked/rotated signing keys are not honored after
        // the JWKS cache TTL expires. Without this, a compromised key that
        // has been removed from the provider's JWKS would still be accepted.
        self.decoding_keys.clear();
        tracing::debug!(
            jwks_keys = jwks.keys.len(),
            "Refreshed JWKS and purged cached decoding keys"
        );

        // Update cache
        {
            let mut cache = self.jwks_cache.write();
            *cache = Some(CachedJwks {
                jwks: jwks.clone(),
                expires_at: SystemTime::now() + self.config.jwks_cache_ttl,
            });
        }

        Ok(jwks)
    }

    /// Get or create decoding key for a specific key ID
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Check cache first
        if let Some(key) = self.decoding_keys.get(kid) {
            return Ok(key.clone());
        }

        // Fetch JWKS to find the key
        let jwks = self.get_jwks().await?;

        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.key_id == kid)
            .ok_or_else(|| AuthError::InvalidToken("Key ID not found in JWKS".to_string()))?;

        // Only support RSA keys for now
        if jwk.key_type != "RSA" {
            return Err(AuthError::InvalidToken(format!(
                "Unsupported key type: {}",
                jwk.key_type
            )));
        }

        let n = jwk
            .n
            .as_ref()
            .ok_or_else(|| AuthError::InvalidToken("Missing RSA modulus".to_string()))?;
        let e = jwk
            .e
            .as_ref()
            .ok_or_else(|| AuthError::InvalidToken("Missing RSA exponent".to_string()))?;

        let decoding_key = DecodingKey::from_rsa_components(n, e)
            .map_err(|e| AuthError::InvalidToken(format!("Invalid RSA key: {}", e)))?;

        // Cache the decoding key
        self.decoding_keys
            .insert(kid.to_string(), decoding_key.clone());

        Ok(decoding_key)
    }

    /// Maximum allowed JWT token size in bytes (16 KB).
    /// Prevents denial-of-service via extremely large tokens.
    const MAX_TOKEN_SIZE: usize = 16 * 1024;

    /// Validate and decode a JWT token
    async fn validate_token(&self, token: &str) -> Result<TokenData<CustomClaims>, AuthError> {
        // SECURITY: Reject oversized tokens before any parsing to prevent
        // memory exhaustion and CPU abuse from base64 decoding / JSON parsing.
        if token.len() > Self::MAX_TOKEN_SIZE {
            return Err(AuthError::InvalidToken(format!(
                "Token exceeds maximum size of {} bytes",
                Self::MAX_TOKEN_SIZE,
            )));
        }

        // Decode header to get key ID
        let header = decode_header(token)
            .map_err(|e| AuthError::InvalidToken(format!("Failed to decode header: {}", e)))?;

        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("Missing key ID in token".to_string()))?;

        // Check algorithm is allowed
        let alg = header.alg;
        if !self.config.allowed_algorithms.contains(&alg) {
            return Err(AuthError::InvalidToken(format!(
                "Algorithm {:?} not allowed",
                alg
            )));
        }

        // Get decoding key
        let decoding_key = self.get_decoding_key(&kid).await?;

        // Set up validation
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        // Decode and validate token
        let token_data = decode::<CustomClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(format!("Token validation failed: {}", e)))?;

        Ok(token_data)
    }

    /// Extract principal from validated JWT claims
    fn claims_to_principal(&self, claims: CustomClaims) -> Result<Principal, AuthError> {
        // Extract tenant ID (from claim or use default)
        let tenant_id = claims
            .tenant_id
            .clone()
            .unwrap_or_else(|| self.config.default_tenant_id.clone());

        // Use email as name if name not provided
        let name = claims
            .name
            .clone()
            .or_else(|| claims.email.clone())
            .unwrap_or_else(|| claims.standard.sub.clone());

        // Create principal using the builder
        let mut builder = PrincipalBuilder::new(
            claims.standard.sub.clone(),
            name,
            super::principal::PrincipalType::User,
            tenant_id,
            AuthMethod::Bearer,
        );

        // Add roles
        if claims.roles.is_empty() {
            builder = builder.with_role("user"); // Default role
        } else {
            builder = builder.with_roles(claims.roles.clone());
        }

        Ok(builder.build())
    }

    /// Extract JWT token from Authorization header
    fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
    }
}

#[async_trait::async_trait]
impl Authenticator for JwtAuthenticator {
    async fn authenticate(&self, headers: &axum::http::HeaderMap) -> Result<Principal, AuthError> {
        // Extract token from Authorization header
        let token = match Self::extract_token(headers) {
            Some(t) => t,
            None => return Err(AuthError::Unauthenticated), // No token present
        };

        // Validate token
        let token_data = self.validate_token(&token).await?;

        // Convert claims to principal
        let principal = self.claims_to_principal(token_data.claims)?;

        Ok(principal)
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::Bearer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_jwt_config_validation() {
        let config = JwtConfig::default();
        let result = JwtAuthenticator::new(config);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthError::Configuration(_)));
    }

    #[test]
    fn test_extract_token_from_bearer_header() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer test_token_123".parse().unwrap(),
        );

        let token = JwtAuthenticator::extract_token(&headers);
        assert_eq!(token, Some("test_token_123".to_string()));
    }

    #[test]
    fn test_extract_token_no_bearer_prefix() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "test_token_123".parse().unwrap(),
        );

        let token = JwtAuthenticator::extract_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_extract_token_missing_header() {
        use axum::http::HeaderMap;

        let headers = HeaderMap::new();
        let token = JwtAuthenticator::extract_token(&headers);
        assert_eq!(token, None);
    }

    #[test]
    fn test_string_or_vec_contains() {
        let single = StringOrVec::String("test".to_string());
        assert!(single.contains("test"));
        assert!(!single.contains("other"));

        let multiple = StringOrVec::Vec(vec!["test1".to_string(), "test2".to_string()]);
        assert!(multiple.contains("test1"));
        assert!(multiple.contains("test2"));
        assert!(!multiple.contains("test3"));
    }

    #[tokio::test]
    async fn test_claims_to_principal() {
        let config = JwtConfig {
            issuer: "https://issuer.example.com".to_string(),
            audience: "rustberg-api".to_string(),
            jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            default_tenant_id: "default".to_string(),
            ..Default::default()
        };

        let authenticator = JwtAuthenticator::new(config).unwrap();

        let claims = CustomClaims {
            standard: StandardClaims {
                sub: "user123".to_string(),
                iss: "https://issuer.example.com".to_string(),
                aud: StringOrVec::String("rustberg-api".to_string()),
                exp: (Utc::now().timestamp() + 3600) as u64,
                iat: Some(Utc::now().timestamp() as u64),
                nbf: None,
            },
            tenant_id: Some("tenant1".to_string()),
            roles: vec!["admin".to_string()],
            name: Some("Test User".to_string()),
            email: Some("test@example.com".to_string()),
            extra: HashMap::new(),
        };

        let principal = authenticator.claims_to_principal(claims).unwrap();

        assert_eq!(principal.id(), "user123");
        assert_eq!(principal.name(), "Test User");
        assert_eq!(principal.tenant_id(), "tenant1");
        assert!(principal.roles().contains("admin"));
        assert_eq!(principal.roles().len(), 1);
        assert_eq!(principal.auth_method(), &AuthMethod::Bearer);
    }

    #[tokio::test]
    async fn test_claims_to_principal_with_defaults() {
        let config = JwtConfig {
            issuer: "https://issuer.example.com".to_string(),
            audience: "rustberg-api".to_string(),
            jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            default_tenant_id: "default".to_string(),
            ..Default::default()
        };

        let authenticator = JwtAuthenticator::new(config).unwrap();

        let claims = CustomClaims {
            standard: StandardClaims {
                sub: "user123".to_string(),
                iss: "https://issuer.example.com".to_string(),
                aud: StringOrVec::String("rustberg-api".to_string()),
                exp: (Utc::now().timestamp() + 3600) as u64,
                iat: Some(Utc::now().timestamp() as u64),
                nbf: None,
            },
            tenant_id: None,
            roles: vec![],
            name: None,
            email: None,
            extra: HashMap::new(),
        };

        let principal = authenticator.claims_to_principal(claims).unwrap();

        assert_eq!(principal.id(), "user123");
        assert_eq!(principal.name(), "user123"); // Defaults to sub
        assert_eq!(principal.tenant_id(), "default"); // Uses default tenant
        assert!(principal.roles().contains("user")); // Default role
        assert_eq!(principal.roles().len(), 1);
        assert_eq!(principal.auth_method(), &AuthMethod::Bearer);
    }
}
