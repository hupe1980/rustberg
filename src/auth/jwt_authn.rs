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

/// Individual JSON Web Key.
///
/// Three key types are read, because between them they cover what identity
/// providers publish: `RSA` (RS256/384/512, PS256/384/512), `EC` (ES256/ES384)
/// and `OKP` (Ed25519). A provider rotating onto a new key type announces it in a
/// changelog nobody's catalog reads, so a reader that handled only RSA would go
/// down on a routine rotation.
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
    /// RSA modulus.
    n: Option<String>,
    /// RSA public exponent.
    e: Option<String>,
    /// EC curve, or the OKP curve for Ed25519.
    crv: Option<String>,
    /// EC x coordinate; for OKP, the whole public key.
    x: Option<String>,
    /// EC y coordinate.
    y: Option<String>,
}

impl Jwk {
    /// The decoding key this JWK carries.
    ///
    /// # Errors
    ///
    /// [`AuthError::InvalidToken`] naming the key type or the missing component.
    /// A key this cannot read is a key no token signed with may be accepted, so
    /// there is no fallback here by design.
    fn decoding_key(&self) -> Result<DecodingKey, AuthError> {
        let missing = |component: &str| {
            AuthError::InvalidToken(format!(
                "JWKS key '{}' is a {} key with no '{component}'",
                self.key_id, self.key_type
            ))
        };

        let key = match self.key_type.as_str() {
            "RSA" => DecodingKey::from_rsa_components(
                self.n.as_deref().ok_or_else(|| missing("n"))?,
                self.e.as_deref().ok_or_else(|| missing("e"))?,
            ),
            "EC" => DecodingKey::from_ec_components(
                self.x.as_deref().ok_or_else(|| missing("x"))?,
                self.y.as_deref().ok_or_else(|| missing("y"))?,
            ),
            // RFC 8037. `crv` is checked because `OKP` also covers X25519,
            // which is a key-agreement key and signs nothing.
            "OKP" if self.crv.as_deref() == Some("Ed25519") => {
                DecodingKey::from_ed_components(self.x.as_deref().ok_or_else(|| missing("x"))?)
            }
            other => {
                return Err(AuthError::InvalidToken(format!(
                    "JWKS key '{}' has key type '{other}', which this catalog cannot verify \
                     signatures with. RSA, EC (P-256/P-384) and OKP (Ed25519) are supported.",
                    self.key_id
                )));
            }
        };

        key.map_err(|e| {
            AuthError::InvalidToken(format!("JWKS key '{}' is malformed: {e}", self.key_id))
        })
    }

    /// Whether this key may be used to verify a signature.
    ///
    /// A JWKS may publish encryption keys alongside signing keys, and RFC 7517
    /// says `use` and `key_ops` are the fields that say which is which. Selecting
    /// an encryption key by `kid` alone and verifying against it is a category
    /// error the library would report as a signature mismatch, naming nothing.
    fn is_signing_key(&self) -> bool {
        self.key_use
            .as_deref()
            .is_none_or(|purpose| purpose == "sig")
    }
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

    /// Audiences a token may name.
    ///
    /// A token is accepted when its `aud` matches **any** of these. More than
    /// one is ordinary rather than exotic: an identity provider issues one
    /// audience per client application, and a catalog is reached from Spark,
    /// Trino and a notebook — three registered clients, three audiences, one
    /// catalog. A single-valued field forced those deployments to either share
    /// one client registration between every engine or run a catalog each.
    ///
    /// Never empty: [`JwtAuthenticator::new`] refuses that, because
    /// `jsonwebtoken` reads an empty audience list as "do not check the
    /// audience", and an unchecked `aud` accepts any token the same issuer
    /// minted for any other service.
    pub audiences: Vec<String>,

    /// JWKS endpoint URL.
    ///
    /// `None` discovers it from the issuer's OpenID Provider Metadata document.
    /// Setting it explicitly skips discovery, for a provider with a non-standard
    /// document layout or a deployment where that document is unreachable.
    pub jwks_url: Option<String>,

    /// Tenant for a token whose `tenant_claim` is absent.
    ///
    /// A default *tenant* is safe in a way a default *role* is not, which is why
    /// one exists and the other does not. It never
    /// places a caller in somebody else's tenant: it names one tenant, which is
    /// a resource tree like any other and which a policy must grant into
    /// explicitly. A single-tenant deployment wants exactly this; a
    /// multi-tenant one sets `tenant_claim` and every token carries it.
    ///
    /// A default *role*, by contrast, would be an assertion the identity
    /// provider never made: Cedar reads roles as group membership, so
    /// synthesising one makes `permit(principal in Group::"user", …)` — which
    /// reads as a policy about ordinary users — match every caller. An absent
    /// roles claim therefore yields no groups at all.
    pub default_tenant_id: String,

    /// Claim name for tenant ID (default: "tenant_id")
    pub tenant_claim: String,

    /// Claim name for roles (default: "roles")
    pub roles_claim: String,

    /// JWKS cache TTL (default: 1 hour)
    pub jwks_cache_ttl: Duration,

    /// Signature algorithms this catalog accepts.
    ///
    /// The default is the three asymmetric families in wide use — RS256, ES256
    /// and EdDSA — and deliberately excludes every `HS*`. An HMAC algorithm
    /// verifies with the same secret it signs with, so accepting one over a JWKS
    /// is the classic confusion: the public modulus a provider publishes becomes
    /// a shared secret anyone can read and forge with. There is no configuration
    /// that turns that on, because there is no deployment it is right for.
    pub allowed_algorithms: Vec<Algorithm>,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            audiences: Vec::new(),
            jwks_url: None,
            default_tenant_id: "default".to_string(),
            tenant_claim: "tenant_id".to_string(),
            roles_claim: "roles".to_string(),
            jwks_cache_ttl: Duration::from_secs(3600),
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA],
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
    /// Where the keys are, once known. Either configured or discovered.
    jwks_url: RwLock<Option<String>>,
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
    /// Create a new JWT authenticator.
    ///
    /// # Errors
    ///
    /// [`AuthError::Configuration`] for a missing issuer or audience, an
    /// algorithm list containing an HMAC family, or an HTTP client that cannot
    /// be built. Each is a startup failure rather than a runtime one: an
    /// authenticator that cannot check a claim must never be the thing standing
    /// between a caller and the catalog.
    ///
    /// The JWKS URL is *not* required here. When it is absent it is discovered
    /// from the issuer at the first token, so a provider that is unreachable at
    /// boot — which, in Kubernetes, is most of them — does not prevent the pod
    /// from starting.
    pub fn new(config: JwtConfig) -> Result<Self, AuthError> {
        if config.issuer.is_empty() {
            return Err(AuthError::Configuration(
                "JWT issuer is required".to_string(),
            ));
        }
        // Empty means "check nothing" to `jsonwebtoken`, which would accept any
        // token this issuer minted for any other service.
        if config.audiences.iter().all(|a| a.trim().is_empty()) {
            return Err(AuthError::Configuration(
                "At least one JWT audience is required. An empty audience list would accept \
                 every token this issuer has minted, including ones addressed to other \
                 services."
                    .to_string(),
            ));
        }
        if config.allowed_algorithms.is_empty() {
            return Err(AuthError::Configuration(
                "At least one JWT signature algorithm must be allowed".to_string(),
            ));
        }
        // See `JwtConfig::allowed_algorithms`. Refused rather than filtered out:
        // an operator who wrote `HS256` believes something about this deployment
        // that is not true, and silently ignoring it leaves them believing it.
        if let Some(symmetric) = config
            .allowed_algorithms
            .iter()
            .find(|alg| matches!(alg, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512))
        {
            return Err(AuthError::Configuration(format!(
                "{symmetric:?} is a shared-secret algorithm and cannot be used with keys from a \
                 JWKS: the key an identity provider publishes is public, so anyone who can read \
                 it could mint tokens this catalog would accept."
            )));
        }

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // A JWKS document does not legitimately redirect across hosts, and
            // following one would fetch signing keys from wherever the response
            // pointed — the same rule the federated `rest` mount applies to a
            // catalog it does not own.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| {
                AuthError::Configuration(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            jwks_url: RwLock::new(config.jwks_url.clone().filter(|u| !u.trim().is_empty())),
            config,
            jwks_cache: RwLock::new(None),
            decoding_keys: DashMap::new(),
            http_client,
            last_forced_refetch: RwLock::new(None),
        })
    }

    /// Largest JWKS or discovery document read, in bytes.
    ///
    /// The identity provider is trusted to say who a caller is; it is not
    /// trusted to bound this server's memory. A body read to the end is a body
    /// whose size the sender chooses.
    const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

    /// Where this issuer publishes its signing keys.
    ///
    /// Resolves once and is then remembered. `jwks_url` in configuration wins;
    /// otherwise the issuer's OpenID Provider Metadata document
    /// (`{issuer}/.well-known/openid-configuration`, RFC 8414 §3) is fetched and
    /// its `jwks_uri` used.
    ///
    /// Discovery is the reason an operator can configure an identity provider by
    /// naming it once. Every provider moves this URL — Google, Entra, Okta,
    /// Keycloak and Auth0 all publish different paths, and Keycloak's changes
    /// with the realm — so a required `jwks_url` made the most common
    /// configuration in the file the one most likely to be wrong.
    ///
    /// # The document's own issuer is checked
    ///
    /// A discovery document names the issuer it describes, and OpenID Connect
    /// Discovery requires it to equal the issuer that was asked. Checking it is
    /// what stops a redirect or a misconfigured URL from silently pointing this
    /// catalog at somebody else's keys — at which case every token that provider
    /// signs would authenticate here.
    ///
    /// # Errors
    ///
    /// [`AuthError::External`] when the document cannot be fetched, read, or
    /// does not describe the configured issuer.
    async fn discover_jwks_url(&self) -> Result<String, AuthError> {
        if let Some(url) = self.jwks_url.read().clone() {
            return Ok(url);
        }

        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );

        #[derive(Deserialize)]
        struct ProviderMetadata {
            issuer: String,
            jwks_uri: String,
        }

        let metadata: ProviderMetadata = self.fetch_json(&url, "OIDC discovery document").await?;

        // Trailing slashes are the one difference providers are inconsistent
        // about and that nothing turns on.
        if metadata.issuer.trim_end_matches('/') != self.config.issuer.trim_end_matches('/') {
            return Err(AuthError::External(format!(
                "The discovery document at {url} describes issuer '{}', not the configured \
                 '{}'. Refusing to take signing keys from it: a document naming another \
                 issuer would make every token that issuer signs valid here.",
                metadata.issuer, self.config.issuer
            )));
        }

        *self.jwks_url.write() = Some(metadata.jwks_uri.clone());
        tracing::info!(
            issuer = %self.config.issuer,
            jwks_uri = %metadata.jwks_uri,
            "Discovered the identity provider's signing keys"
        );
        Ok(metadata.jwks_uri)
    }

    /// Fetches a JSON document, refusing one larger than
    /// [`Self::MAX_DOCUMENT_BYTES`].
    ///
    /// # Errors
    ///
    /// [`AuthError::External`] for a transport failure, a non-success status, a
    /// body past the ceiling, or a body that is not the expected shape.
    async fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        what: &str,
    ) -> Result<T, AuthError> {
        use futures::StreamExt;

        let response = self
            .http_client
            .get(url)
            .send()
            .await
            .map_err(|e| AuthError::External(format!("Failed to fetch the {what}: {e}")))?;

        if !response.status().is_success() {
            return Err(AuthError::External(format!(
                "The {what} at {url} answered {}",
                response.status()
            )));
        }

        // Read with a ceiling rather than to the end of the stream: a provider
        // answering with an endless body would otherwise take this server down.
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk
                .map_err(|e| AuthError::External(format!("Failed to read the {what}: {e}")))?;
            if body.len() + chunk.len() > Self::MAX_DOCUMENT_BYTES {
                return Err(AuthError::External(format!(
                    "The {what} at {url} is larger than {} bytes and was not read.",
                    Self::MAX_DOCUMENT_BYTES
                )));
            }
            body.extend_from_slice(&chunk);
        }

        serde_json::from_slice(&body)
            .map_err(|e| AuthError::External(format!("Failed to parse the {what}: {e}")))
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

    /// Fetch JWKS from the OIDC provider.
    async fn fetch_jwks(&self) -> Result<Jwks, AuthError> {
        let url = self.discover_jwks_url().await?;
        self.fetch_json(&url, "JWKS").await
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
            .find(|k| k.key_id == kid && k.is_signing_key())
            .ok_or_else(|| AuthError::InvalidToken("Key ID not found in JWKS".to_string()))?;

        let decoding_key = jwk.decoding_key()?;

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

        // The header's `alg` selects the key, and decides nothing else.
        //
        // Reading it and then building `Validation::new(header.alg)` is the
        // shape of every JWT algorithm-confusion bug ever written: it lets the
        // token nominate how it will be verified. It is checked against the
        // configured list here so an unexpected algorithm is refused with a
        // message naming it, and the validation below is built from the
        // *configuration* regardless, so even if this check were removed the
        // token could still only be verified as something the operator allowed.
        if !self.config.allowed_algorithms.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!(
                "Token is signed with {:?}, which this catalog does not accept. Allowed: {:?}.",
                header.alg, self.config.allowed_algorithms
            )));
        }

        // Get decoding key
        let decoding_key = self.get_decoding_key(&kid).await?;

        // Set up validation.
        //
        // `required_spec_claims` is set explicitly rather than left at its
        // default of `{exp}`. Setting an issuer and an audience makes those
        // claims *checked when present*; it does not make them mandatory, so a
        // token omitting `aud` entirely would pass an audience check it never
        // took part in. `sub` is required for the same reason: it is the
        // principal id, and a token without one would be authenticated as the
        // empty string.
        //
        // `validate_nbf` is off by default, so a token issued for later use is
        // accepted before it is valid. Turning it on costs nothing and closes
        // the gap between `nbf` and `exp`.
        let mut validation = Validation {
            algorithms: self.config.allowed_algorithms.clone(),
            ..Validation::default()
        };
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&self.config.audiences);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_nbf = true;

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

        // A signed token is not a validated one.
        //
        // The tenant id becomes the *first segment* of every Cedar entity id the
        // authorizer builds, so it is a path segment joined with `␟` exactly like
        // a namespace level — and every other input to that id was validated on
        // the way in through a request path. This one arrives through a claim,
        // where nothing had looked at it. A tenant called `acme␟analytics` builds
        // the same entity ids as tenant `acme`'s namespace `analytics`, so a
        // policy written for one would silently cover the other.
        //
        // The subject is checked by the weaker rule: it is never joined into a
        // path, but it is written into every audit record and log line.
        crate::names::validate_tenant_id(&tenant_id)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        crate::names::validate_principal_id(&claims.sub)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        // `name` then `email` then `sub`: a display name is cosmetic, and the
        // subject is the one claim guaranteed present.
        let name = claims
            .string_at("name")
            .or_else(|| claims.string_at("email"))
            .unwrap_or_else(|| claims.sub.clone());

        // A role is the third thing a token supplies that becomes a Cedar entity
        // id — `Group::"analysts"` — so it is held to the same rendering rule as
        // the tenant and the subject above. Unlike those two it is *dropped*
        // rather than failing the credential: see `names::unusable_role_char`.
        let roles = crate::names::usable_roles(
            claims.strings_at(&self.config.roles_claim),
            &self.config.roles_claim,
        );
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
            audiences: vec!["rustberg-api".to_string()],
            jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
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
    fn an_authenticator_needs_an_issuer_and_an_audience() {
        for missing in ["issuer", "audiences"] {
            let mut cfg = config();
            match missing {
                "issuer" => cfg.issuer.clear(),
                _ => cfg.audiences.clear(),
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

    /// The JWKS URL is discovered from the issuer when it is not configured, so
    /// a deployment naming only its provider must still build.
    #[test]
    fn the_jwks_url_is_optional_because_it_is_discoverable() {
        let cfg = JwtConfig {
            jwks_url: None,
            ..config()
        };
        assert!(JwtAuthenticator::new(cfg).is_ok());
    }

    /// A JWKS publishes *public* keys, so accepting an HMAC algorithm would make
    /// the published key a shared secret anyone could forge with.
    #[test]
    fn a_shared_secret_algorithm_is_refused_at_startup() {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let cfg = JwtConfig {
                allowed_algorithms: vec![Algorithm::RS256, alg],
                ..config()
            };
            let err = JwtAuthenticator::new(cfg).unwrap_err();
            assert!(
                matches!(err, AuthError::Configuration(_)),
                "{alg:?} must be refused: {err}"
            );
        }
    }

    #[test]
    fn an_empty_algorithm_list_is_refused() {
        let cfg = JwtConfig {
            allowed_algorithms: Vec::new(),
            ..config()
        };
        assert!(JwtAuthenticator::new(cfg).is_err());
    }

    // ── JWKS keys ─────────────────────────────────────────────────────────

    fn jwk(json: serde_json::Value) -> Jwk {
        serde_json::from_value(json).expect("a JWK")
    }

    /// A provider rotating onto ES256 or Ed25519 must not take this
    /// authenticator down.
    #[test]
    fn every_asymmetric_key_type_a_provider_publishes_is_read() {
        // P-256 test vector coordinates, base64url, from RFC 7515 Appendix A.3.
        assert!(
            jwk(serde_json::json!({
                "kid": "ec", "kty": "EC", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
            }))
            .decoding_key()
            .is_ok(),
            "EC P-256"
        );

        assert!(
            jwk(serde_json::json!({
                "kid": "ed", "kty": "OKP", "crv": "Ed25519",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            }))
            .decoding_key()
            .is_ok(),
            "Ed25519"
        );
    }

    /// X25519 is a key-agreement key. It signs nothing, and reading it as a
    /// verification key would be a category error the library reports only as a
    /// signature mismatch.
    #[test]
    fn a_key_that_cannot_verify_a_signature_is_refused() {
        assert!(
            jwk(serde_json::json!({
                "kid": "x", "kty": "OKP", "crv": "X25519", "x": "aaaa"
            }))
            .decoding_key()
            .is_err()
        );
        assert!(
            jwk(serde_json::json!({ "kid": "o", "kty": "oct", "k": "c2VjcmV0" }))
                .decoding_key()
                .is_err(),
            "a symmetric key in a JWKS is not a verification key"
        );
    }

    /// A JWKS may carry encryption keys beside signing keys, and `use` is what
    /// distinguishes them.
    #[test]
    fn only_signing_keys_are_selected() {
        assert!(
            jwk(serde_json::json!({ "kid": "a", "kty": "RSA", "use": "sig" })).is_signing_key()
        );
        assert!(
            jwk(serde_json::json!({ "kid": "a", "kty": "RSA" })).is_signing_key(),
            "an absent `use` means unrestricted, per RFC 7517"
        );
        assert!(
            !jwk(serde_json::json!({ "kid": "a", "kty": "RSA", "use": "enc" })).is_signing_key()
        );
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
