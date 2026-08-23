use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
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

/// The claims of a validated token, kept as JSON.
///
/// # Why this is not a struct with named fields
///
/// It was, and the two configuration values that select where identity comes
/// from — `tenant_claim` and `roles_claim` — could not possibly have worked:
/// serde binds a field name at compile time, so the deserializer always read
/// `tenant_id` and `roles` no matter what the operator configured. Setting
/// `roles_claim = "groups"`, which is what the documentation itself showed,
/// produced a principal with no group memberships at all, so every group-scoped
/// policy silently stopped matching. It failed closed, which is why nobody saw
/// it, and the natural repair is to widen the policies until access comes back.
///
/// A claim whose *name* is configuration has to be looked up at runtime, so the
/// payload stays a map and [`JwtAuthenticator::claims_to_principal`] reads the
/// configured names out of it.
///
/// `sub` and `exp` are the two the token cannot be useful without, so they are
/// the only ones named here; `iss`, `aud`, `exp` and `nbf` are enforced by
/// `jsonwebtoken` during `decode`, against the configured issuer and audience.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    /// Subject: the principal's stable id.
    sub: String,

    /// Every other claim, read by configured name.
    #[serde(flatten)]
    rest: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// The claim at `name`, as a string.
    ///
    /// Dotted names address nested objects, because an identity provider that
    /// carries tenancy in a structured claim is ordinary — Entra puts it under
    /// `resource_access`, Auth0 under a namespaced object — and the alternative
    /// is telling operators to flatten their token.
    fn string_at(&self, name: &str) -> Option<String> {
        match self.value_at(name)? {
            serde_json::Value::String(s) if !s.is_empty() => Some(s.clone()),
            _ => None,
        }
    }

    /// The claim at `name`, as a list of strings.
    ///
    /// A single string is one role rather than an error: `roles: "admin"` is
    /// common enough that rejecting it would only produce a principal with no
    /// roles, which is the silent failure this whole type exists to end. A
    /// non-string element of an array *is* dropped, because a role that is a
    /// number or an object has no name to match a Cedar group against.
    fn strings_at(&self, name: &str) -> Vec<String> {
        match self.value_at(name) {
            Some(serde_json::Value::Array(items)) => items
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
            Some(serde_json::Value::String(s)) if !s.is_empty() => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    /// Resolves a claim name against the payload, descending into objects.
    ///
    /// # Why the longest literal key wins
    ///
    /// A dot means "descend" — `realm_access.roles` is Keycloak's group claim —
    /// and a dot is also an ordinary character in a claim *name*, because the
    /// namespaced claims OIDC providers emit are URLs:
    /// `https://acme.example/claims`. Splitting on every dot turns that into a
    /// lookup for `https://acme`, which misses, and the operator is told their
    /// claim is absent when it is right there.
    ///
    /// So the longest prefix of the dotted segments that exists as a literal key
    /// is matched first, and only the remainder is traversed. `tenant_id`
    /// resolves as itself; `realm_access.roles` finds `realm_access` and then
    /// descends; `https://acme.example/claims.tenant` finds the whole URL and
    /// then descends to `tenant`. Every one of those is a real provider's shape,
    /// and no configuration has to say which kind it is.
    fn value_at(&self, name: &str) -> Option<&serde_json::Value> {
        let segments: Vec<&str> = name.split('.').collect();

        for split in (1..=segments.len()).rev() {
            let key = segments[..split].join(".");
            let Some(root) = self.rest.get(&key) else {
                continue;
            };
            let mut current = root;
            for part in &segments[split..] {
                // A miss here ends the whole lookup rather than falling back to
                // a shorter prefix. The literal key matched, so this *is* the
                // claim the operator named; resolving something else that
                // happens to share a prefix would be worse than reporting the
                // path absent.
                current = current.get(part)?;
            }
            return Some(current);
        }

        None
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
    /// When the last unknown-`kid` refetch happened, so a caller cannot turn
    /// invented key ids into load on the identity provider.
    last_forced_refetch: RwLock<Option<std::time::Instant>>,
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
            last_forced_refetch: RwLock::new(None),
        })
    }

    /// Shortest gap between two refetches provoked by an unknown key id.
    ///
    /// A rotation is noticed within this long; a caller inventing key ids gets
    /// one upstream request per interval no matter how many tokens it sends.
    const MIN_JWKS_REFETCH_INTERVAL: Duration = Duration::from_secs(30);

    /// Whether an unknown-`kid` refetch may run now, claiming the slot if so.
    fn may_refetch_jwks(&self) -> bool {
        let now = std::time::Instant::now();
        let mut last = self.last_forced_refetch.write();
        match *last {
            Some(at) if now.duration_since(at) < Self::MIN_JWKS_REFETCH_INTERVAL => false,
            _ => {
                *last = Some(now);
                true
            }
        }
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

    /// Get JWKS with caching.
    ///
    /// `force` bypasses the cache, which is what a token bearing an unknown
    /// `kid` asks for — see [`Self::get_decoding_key`].
    async fn get_jwks(&self, force: bool) -> Result<Jwks, AuthError> {
        // Check cache first
        if !force {
            let cache = self.jwks_cache.read();
            if let Some(cached) = cache.as_ref()
                && SystemTime::now() < cached.expires_at
            {
                return Ok(cached.jwks.clone());
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

    /// Get or create decoding key for a specific key ID.
    ///
    /// # An unknown key id forces a refetch
    ///
    /// A provider that rotates its signing key publishes the new one under a new
    /// `kid` and starts signing with it immediately. Serving the answer from a
    /// cache keyed on a TTL means every token signed with the new key is rejected
    /// until that TTL expires — an hour of `401`s by default, for a rotation that
    /// is routine and gives no notice. The documentation called this "background
    /// key rotation"; nothing rotated anything.
    ///
    /// So an unknown `kid` refetches once, immediately. The refetch is bounded by
    /// [`Self::MIN_JWKS_REFETCH_INTERVAL`] so that a flood of tokens bearing
    /// invented key ids cannot turn into a flood of requests at the identity
    /// provider — the rejection is cheap, and making it expensive would hand an
    /// unauthenticated caller an amplifier.
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        // Check cache first
        if let Some(key) = self.decoding_keys.get(kid) {
            return Ok(key.clone());
        }

        // Fetch JWKS to find the key
        let jwks = match self.get_jwks(false).await {
            Ok(jwks) if jwks.keys.iter().any(|k| k.key_id == kid) => jwks,
            // Either the cached set predates a rotation, or this id was never
            // real. One refetch distinguishes them, at most once per interval.
            Ok(stale) => {
                if self.may_refetch_jwks() {
                    self.get_jwks(true).await?
                } else {
                    stale
                }
            }
            Err(e) => return Err(e),
        };

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
    async fn validate_token(&self, token: &str) -> Result<TokenData<Claims>, AuthError> {
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
        let token_data = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::InvalidToken(format!("Token validation failed: {}", e)))?;

        Ok(token_data)
    }

    /// Builds the principal a validated token stands for.
    ///
    /// Tenant and roles are read from the claims the configuration *names*, so
    /// `tenant_claim = "https://acme.example/tenant"` and `roles_claim =
    /// "groups"` do what they say. Both accept a dotted path into a nested
    /// object.
    ///
    /// # No role is invented
    ///
    /// An absent claim yields an absent group. Cedar reads roles as group
    /// membership, so synthesising a default role would make
    /// `permit(principal in Group::"user", …)` — which reads as a policy about
    /// ordinary users — match every caller the provider never described.
    fn claims_to_principal(&self, claims: &Claims) -> Result<Principal, AuthError> {
        let tenant_id = claims
            .string_at(&self.config.tenant_claim)
            .unwrap_or_else(|| self.config.default_tenant_id.clone());

        // `name` then `email` then `sub`: a display name is cosmetic, and the
        // subject is the one claim guaranteed present.
        let name = claims
            .string_at("name")
            .or_else(|| claims.string_at("email"))
            .unwrap_or_else(|| claims.sub.clone());

        let roles = claims.strings_at(&self.config.roles_claim);
        if roles.is_empty() {
            tracing::debug!(
                subject = %claims.sub,
                roles_claim = %self.config.roles_claim,
                "Token carries no roles; the principal joins no Cedar group"
            );
        }

        Ok(PrincipalBuilder::new(
            claims.sub.clone(),
            name,
            super::principal::PrincipalType::User,
            tenant_id,
            AuthMethod::Bearer,
        )
        .with_roles(roles)
        .build())
    }

    /// Extract JWT token from Authorization header.
    ///
    /// The scheme is matched case-insensitively, because RFC 9110 defines it
    /// that way and clients spell it `bearer` often enough that a case-sensitive
    /// match reads to an operator as "my token is being ignored".
    fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
        let value = headers
            .get(axum::http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let (scheme, token) = value.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case("Bearer") {
            return None;
        }
        let token = token.trim();
        (!token.is_empty()).then(|| token.to_string())
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
        let principal = self.claims_to_principal(&token_data.claims)?;

        Ok(principal)
    }

    fn auth_method(&self) -> AuthMethod {
        AuthMethod::Bearer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> JwtConfig {
        JwtConfig {
            issuer: "https://issuer.example.com".to_string(),
            audience: "rustberg-api".to_string(),
            jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            default_tenant_id: "default".to_string(),
            ..Default::default()
        }
    }

    fn claims(json: serde_json::Value) -> Claims {
        serde_json::from_value(json).expect("valid claims")
    }

    fn headers_with(value: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
        headers
    }

    // ── Configuration ─────────────────────────────────────────────────────

    #[test]
    fn an_authenticator_needs_issuer_audience_and_jwks() {
        for missing in ["issuer", "audience", "jwks_url"] {
            let mut cfg = config();
            match missing {
                "issuer" => cfg.issuer.clear(),
                "audience" => cfg.audience.clear(),
                _ => cfg.jwks_url.clear(),
            }
            assert!(
                matches!(
                    JwtAuthenticator::new(cfg).unwrap_err(),
                    AuthError::Configuration(_)
                ),
                "{missing} must be required"
            );
        }
    }

    // ── The Authorization header ──────────────────────────────────────────

    #[test]
    fn a_bearer_token_is_extracted() {
        assert_eq!(
            JwtAuthenticator::extract_token(&headers_with("Bearer test_token_123")),
            Some("test_token_123".to_string())
        );
    }

    /// RFC 9110 makes the scheme case-insensitive, and clients spell it every
    /// way. Rejecting `bearer` reads to an operator as a token being ignored.
    #[test]
    fn the_bearer_scheme_is_case_insensitive() {
        for spelling in ["bearer", "BEARER", "BeArEr"] {
            assert_eq!(
                JwtAuthenticator::extract_token(&headers_with(&format!("{spelling} tok"))),
                Some("tok".to_string()),
                "{spelling} must be accepted"
            );
        }
    }

    #[test]
    fn another_scheme_is_not_a_bearer_token() {
        assert_eq!(
            JwtAuthenticator::extract_token(&headers_with("Basic dXNlcjpwdw==")),
            None
        );
        assert_eq!(
            JwtAuthenticator::extract_token(&headers_with("test_token_123")),
            None
        );
        assert_eq!(
            JwtAuthenticator::extract_token(&headers_with("Bearer ")),
            None
        );
        assert_eq!(
            JwtAuthenticator::extract_token(&axum::http::HeaderMap::new()),
            None
        );
    }

    // ── Claims are read by configured name ────────────────────────────────

    /// The defaults, so the ordinary case keeps working.
    #[test]
    fn the_default_claim_names_are_read() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "user123",
                "tenant_id": "tenant1",
                "roles": ["admin", "writer"],
                "name": "Test User",
            })))
            .unwrap();

        assert_eq!(principal.id(), "user123");
        assert_eq!(principal.name(), "Test User");
        assert_eq!(principal.tenant_id(), "tenant1");
        assert!(principal.roles().contains("admin"));
        assert!(principal.roles().contains("writer"));
        assert_eq!(principal.auth_method(), &AuthMethod::Bearer);
    }

    /// Claims are looked up by the *configured* name at runtime. Binding them
    /// as serde field names would make `roles_claim = "groups"` produce a
    /// principal in no group at all, and every group-scoped policy would
    /// silently stop matching.
    #[test]
    fn configured_claim_names_are_honoured() {
        let auth = JwtAuthenticator::new(JwtConfig {
            tenant_claim: "org".to_string(),
            roles_claim: "groups".to_string(),
            ..config()
        })
        .unwrap();

        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "user123",
                "org": "acme",
                "groups": ["analysts"],
                // The default names are present and must be ignored, or this
                // would pass on a build that hardcoded them.
                "tenant_id": "wrong",
                "roles": ["admin"],
            })))
            .unwrap();

        assert_eq!(principal.tenant_id(), "acme");
        assert!(principal.roles().contains("analysts"));
        assert!(
            !principal.roles().contains("admin"),
            "the unconfigured claim must not be read"
        );
    }

    /// Providers that carry tenancy in a structured claim are ordinary, and the
    /// alternative is telling an operator to flatten their token. The namespaced
    /// claim is the sharp case: its *name* contains dots, so splitting on every
    /// dot would look for `https://acme` and report the claim absent.
    #[test]
    fn a_dotted_claim_name_addresses_a_nested_object() {
        let auth = JwtAuthenticator::new(JwtConfig {
            tenant_claim: "https://acme.example/claims.tenant".to_string(),
            roles_claim: "realm_access.roles".to_string(),
            ..config()
        })
        .unwrap();

        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "user123",
                "https://acme.example/claims": { "tenant": "acme" },
                "realm_access": { "roles": ["reader"] },
            })))
            .unwrap();

        assert_eq!(principal.tenant_id(), "acme");
        assert!(principal.roles().contains("reader"));
    }

    /// `roles: "admin"` is common enough that rejecting it would only produce a
    /// principal with no roles — the silent failure this all exists to end.
    #[test]
    fn a_single_string_role_is_one_role() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "u", "roles": "admin",
            })))
            .unwrap();
        assert!(principal.roles().contains("admin"));
        assert_eq!(principal.roles().len(), 1);
    }

    #[test]
    fn non_string_roles_are_dropped_rather_than_stringified() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "u", "roles": ["reader", 7, {"a": 1}, ""],
            })))
            .unwrap();
        assert_eq!(principal.roles().len(), 1, "only `reader` names a group");
        assert!(principal.roles().contains("reader"));
    }

    /// A namespaced claim that is itself a flat string, not an object. The
    /// literal key has to win outright, or the dot in the hostname sends the
    /// lookup somewhere that does not exist.
    #[test]
    fn a_claim_name_that_is_a_url_resolves_literally() {
        let auth = JwtAuthenticator::new(JwtConfig {
            tenant_claim: "https://acme.example/tenant".to_string(),
            ..config()
        })
        .unwrap();

        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "u",
                "https://acme.example/tenant": "acme",
            })))
            .unwrap();
        assert_eq!(principal.tenant_id(), "acme");
    }

    /// Naming a path that does not exist is an absent claim, not a match on
    /// whatever shorter prefix happens to resolve.
    #[test]
    fn a_path_that_misses_beneath_a_matched_key_is_absent() {
        let auth = JwtAuthenticator::new(JwtConfig {
            tenant_claim: "org.tenant".to_string(),
            ..config()
        })
        .unwrap();

        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "u", "org": { "name": "acme" },
            })))
            .unwrap();
        assert_eq!(principal.tenant_id(), "default");
    }

    // ── Nothing is invented ───────────────────────────────────────────────

    /// Synthesising a role asserts something the identity provider did not, and
    /// `permit(principal in Group::"user", …)` would then match every caller.
    #[test]
    fn a_token_without_roles_joins_no_group() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({ "sub": "user123" })))
            .unwrap();

        assert_eq!(principal.id(), "user123");
        assert_eq!(principal.name(), "user123", "falls back to the subject");
        assert_eq!(principal.tenant_id(), "default");
        assert!(
            principal.roles().is_empty(),
            "no role may be synthesised from an absent claim"
        );
    }

    #[test]
    fn an_email_stands_in_for_a_missing_name() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({
                "sub": "u", "email": "test@example.com",
            })))
            .unwrap();
        assert_eq!(principal.name(), "test@example.com");
    }

    /// An empty string is an absent claim, not a tenant named "".
    #[test]
    fn an_empty_claim_falls_back_to_the_default() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({ "sub": "u", "tenant_id": "" })))
            .unwrap();
        assert_eq!(principal.tenant_id(), "default");
    }

    /// A claim of the wrong shape must not become a tenant id: `tenant_id: 42`
    /// naming the tenant `"42"` would let a token's type confusion pick a
    /// neighbour's resource tree.
    #[test]
    fn a_claim_of_the_wrong_type_is_absent() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        let principal = auth
            .claims_to_principal(&claims(serde_json::json!({ "sub": "u", "tenant_id": 42 })))
            .unwrap();
        assert_eq!(principal.tenant_id(), "default");
    }

    // ── JWKS refetch ──────────────────────────────────────────────────────

    /// An unknown key id may provoke one refetch, and then not again for the
    /// interval — otherwise invented key ids become load on the identity
    /// provider, which is an amplifier handed to an unauthenticated caller.
    #[test]
    fn an_unknown_key_id_may_force_one_refetch_per_interval() {
        let auth = JwtAuthenticator::new(config()).unwrap();
        assert!(auth.may_refetch_jwks(), "the first is allowed");
        assert!(!auth.may_refetch_jwks(), "the second is rate limited");
    }
}
