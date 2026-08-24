//! `Idempotency-Key` support, so a retried mutation executes once.
//!
//! A handler authorizes, then looks the key up, then acts, then stores the
//! response. That order is the correctness argument: a cache hit answers
//! without touching the catalog, so consulting it first would serve a request
//! that was never authorized — and keep serving it after the grant was revoked.
//!
//! # Keys are scoped to a principal
//!
//! The key is client-chosen, so without scoping the header is a cross-tenant
//! read primitive: anyone could supply another tenant's value and be handed
//! their cached `createTable` response, metadata and vended credentials
//! included. The scope joins principal, tenant, method and path with the unit
//! separator, which none of them can contain.
//!
//! # A retry, not a race
//!
//! The receipt is written *after* the operation, so two requests carrying the
//! same key **concurrently** both execute. That is deliberate. Reserving the key
//! first would need a second round trip to the shared store on the happy path of
//! every mutation, plus a lease with an expiry, plus a rule for what a caller
//! sees while the first attempt is still in flight — and it would buy protection
//! against a case that is not what the header is for. `Idempotency-Key` exists
//! for a *retry*: a client that did not hear the answer and asks again. Two
//! genuinely simultaneous attempts at the same commit are already resolved,
//! correctly, by compare-and-swap — the loser gets a `409`.
//!
//! # Replicas share the store
//!
//! The cache is in-process, and behind a load balancer a retry lands on a
//! different replica and executes a second time — which is the one thing the
//! key exists to prevent, while `/v1/config` advertises a reuse window. So a
//! deployment that can have replicas at all (Postgres; redb takes an exclusive
//! file lock) backs the cache with a [`SharedIdempotencyStore`], and the local
//! cache becomes a read-through in front of it.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use moka::sync::Cache;
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::auth::Principal;

/// Header name for idempotency keys.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Response header marking a response that was **replayed** rather than executed.
///
/// Set by [`CachedResponse::into_axum_response`] and nowhere else. Setting it on
/// the response that did the work as well would put it on every response
/// carrying a key, and it would then distinguish nothing — which is the one
/// thing it exists to do.
pub const IDEMPOTENCY_KEY_USED_HEADER: &str = "idempotency-key-used";

/// Default TTL for idempotency keys (24 hours).
pub const DEFAULT_TTL: Duration = Duration::from_secs(86400);

/// Maximum length for idempotency keys.
const MAX_KEY_LENGTH: usize = 256;

/// Joins the parts of a cache scope.
///
/// The unit separator cannot appear in a principal id, a tenant, or a validated
/// path segment, so no two distinct scopes render to the same string. Joining
/// with `:` would let a principal named `a:b` collide with tenant `b`.
/// Separates the fields of an idempotency key's scope.
///
/// Deliberately *not* [`crate::names::PART_SEPARATOR`], despite being the same
/// byte. That constant is the namespace-part separator and has one job; this
/// joins a principal, a tenant, a method and a path, which are not namespace
/// parts and never become one. Importing it would couple two rules that have no
/// reason to change together — the mirror of the copy that constant exists to
/// prevent. What matters here is only that no field can contain it: an id and a
/// tenant are held to the name rule, a method is a fixed token, and a path
/// arrives percent-encoded.
const SCOPE_SEPARATOR: &str = "\u{1F}";

/// Most entries the in-process cache holds.
///
/// Bounded because the key is client-chosen: without a ceiling a caller could
/// mint receipts until the process ran out of memory. Eviction costs the evicted
/// key its idempotency, which is the same outcome as never having sent one.
const MAX_CACHE_SIZE: u64 = 100_000;

// ============================================================================
// Idempotency Key
// ============================================================================

/// A validated idempotency key, scoped to one principal and one operation.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct IdempotencyKey {
    key: String,
    /// Principal, tenant, method and path. See the module docs for why the
    /// principal belongs here.
    scope: String,
}

impl IdempotencyKey {
    /// Creates an idempotency key scoped to `principal` and the operation.
    ///
    /// Returns `None` when the client-supplied value is empty, over
    /// the maximum key length, or contains anything but ASCII alphanumerics, `-` and
    /// `_`. A rejected key is treated as absent, so the request proceeds
    /// normally rather than failing — a malformed key costs the caller
    /// idempotency, not the operation.
    pub fn new(
        key: impl Into<String>,
        method: &str,
        path: &str,
        principal: &Principal,
    ) -> Option<Self> {
        let key = key.into();

        if key.is_empty() || key.len() > MAX_KEY_LENGTH {
            return None;
        }

        // The alphabet covers the UUIDv7 the spec asks for and the shapes
        // clients actually send, and excludes the separator below — so a key
        // cannot forge a scope boundary.
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }

        // The unit separator cannot appear in a principal id, a tenant, or a
        // validated path segment, so no two distinct scopes can render to the
        // same string. Joining with `:` would let a principal named `a:b` collide
        // with tenant `b`.
        Some(Self {
            key,
            scope: [principal.id(), principal.tenant_id(), method, path].join(SCOPE_SEPARATOR),
        })
    }

    /// Extracts an idempotency key from request headers.
    pub fn from_headers(
        headers: &HeaderMap,
        method: &str,
        path: &str,
        principal: &Principal,
    ) -> Option<Self> {
        headers
            .get(IDEMPOTENCY_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|key| Self::new(key, method, path, principal))
    }

    /// Returns the raw key value.
    pub fn value(&self) -> &str {
        &self.key
    }

    /// The single string a shared store keys on.
    ///
    /// Scope and key joined by the same separator the scope itself uses, so the
    /// mapping is injective for the same reason.
    pub fn storage_key(&self) -> String {
        format!("{}{SCOPE_SEPARATOR}{}", self.scope, self.key)
    }
}

// ============================================================================
// Cached Response
// ============================================================================

/// A cached response for idempotent requests.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response body.
    pub body: Bytes,
    /// Content-Type header.
    pub content_type: Option<String>,
    /// When this response was cached.
    pub cached_at: Instant,
}

impl CachedResponse {
    /// Creates a new cached response.
    pub fn new(status: StatusCode, body: Bytes, content_type: Option<String>) -> Self {
        Self {
            status,
            body,
            content_type,
            cached_at: Instant::now(),
        }
    }

    /// Creates a cached response from JSON.
    ///
    /// Returns `None` if the value cannot be serialized (logged as warning).
    pub fn from_json<T: Serialize>(status: StatusCode, value: &T) -> Option<Self> {
        match serde_json::to_vec(value) {
            Ok(body) => Some(Self {
                status,
                body: Bytes::from(body),
                content_type: Some("application/json".to_string()),
                cached_at: Instant::now(),
            }),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to serialize response for idempotency cache");
                None
            }
        }
    }

    /// Converts to an Axum response.
    pub fn into_axum_response(self) -> axum::response::Response {
        use axum::http::header::CONTENT_TYPE;
        use axum::response::IntoResponse;

        let mut response = (self.status, self.body).into_response();

        if let Some(content_type) = self.content_type
            && let Ok(value) = HeaderValue::from_str(&content_type)
        {
            response.headers_mut().insert(CONTENT_TYPE, value);
        }

        // Says the response was replayed rather than executed, so a client can
        // tell a successful retry from a first attempt.
        response.headers_mut().insert(
            IDEMPOTENCY_KEY_USED_HEADER,
            HeaderValue::from_static("true"),
        );

        response
    }
}

// ============================================================================
// Shared store
// ============================================================================

/// A store replicas share, so a retry that lands elsewhere still sees the first
/// response.
///
/// Implemented by the Postgres catalog, which is the only backend a multi-replica
/// deployment can use.
#[async_trait::async_trait]
pub trait SharedIdempotencyStore: Send + Sync + std::fmt::Debug {
    /// The response recorded for `key`, if one is and has not expired.
    ///
    /// # Errors
    ///
    /// Whatever the backing store reported.
    async fn get(&self, key: &str) -> Result<Option<CachedResponse>, String>;

    /// Records `response` for `key`, expiring after `ttl`.
    ///
    /// # Errors
    ///
    /// Whatever the backing store reported.
    async fn put(&self, key: &str, response: &CachedResponse, ttl: Duration) -> Result<(), String>;
}

// ============================================================================
// Idempotency Cache
// ============================================================================

/// Idempotent responses, in process and optionally shared across replicas.
#[derive(Clone)]
pub struct IdempotencyCache {
    /// Bounded, TTL-evicting local cache. Also the read-through in front of
    /// `shared`.
    cache: Cache<IdempotencyKey, CachedResponse>,
    /// Where replicas agree, when there is more than one.
    shared: Option<Arc<dyn SharedIdempotencyStore>>,
    ttl: Duration,
}

impl std::fmt::Debug for IdempotencyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdempotencyCache")
            .field("ttl", &self.ttl)
            .field("shared", &self.shared.is_some())
            .finish()
    }
}

impl IdempotencyCache {
    /// An in-process cache with the given TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(MAX_CACHE_SIZE)
                .time_to_live(ttl)
                .build(),
            shared: None,
            ttl,
        }
    }

    /// The same cache, backed by a store every replica can read.
    pub fn with_shared_store(mut self, store: Arc<dyn SharedIdempotencyStore>) -> Self {
        self.shared = Some(store);
        self
    }

    /// Whether replicas share this cache.
    pub fn is_shared(&self) -> bool {
        self.shared.is_some()
    }

    /// The response recorded for `key`, if any.
    ///
    /// A shared-store failure is reported as a miss rather than as an error: the
    /// request then executes, which for a commit means a `409` at worst, while
    /// refusing it would turn a cache outage into a write outage.
    pub async fn get(&self, key: &IdempotencyKey) -> Option<CachedResponse> {
        if let Some(hit) = self.cache.get(key) {
            return Some(hit);
        }

        let shared = self.shared.as_ref()?;
        match shared.get(&key.storage_key()).await {
            Ok(Some(response)) => {
                self.cache.insert(key.clone(), response.clone());
                Some(response)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!(error = %e, "Idempotency store unavailable; treating as a miss");
                None
            }
        }
    }

    /// Records `response` for `key`.
    ///
    /// Best-effort against the shared store, for the same reason: a write that
    /// succeeded must not be reported as failed because its receipt could not be
    /// filed.
    pub async fn set(&self, key: IdempotencyKey, response: CachedResponse) {
        if let Some(shared) = self.shared.as_ref()
            && let Err(e) = shared.put(&key.storage_key(), &response, self.ttl).await
        {
            tracing::warn!(error = %e, "Failed to record an idempotency key");
        }
        self.cache.insert(key, response);
    }

    /// The configured TTL, which `/v1/config` advertises.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::new(DEFAULT_TTL)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMethod, PrincipalBuilder, PrincipalType};

    /// A principal to scope test keys with.
    fn who(id: &str) -> Principal {
        PrincipalBuilder::new(id, id, PrincipalType::ApiKey, "acme", AuthMethod::ApiKey).build()
    }
    use std::collections::HashMap;
    use std::thread;

    #[test]
    fn test_idempotency_key_validation() {
        // Valid keys
        assert!(IdempotencyKey::new("abc123", "POST", "/v1/tables", &who("alice")).is_some());
        assert!(
            IdempotencyKey::new("uuid-with-dashes", "POST", "/v1/tables", &who("alice")).is_some()
        );
        assert!(
            IdempotencyKey::new("key_with_underscores", "POST", "/v1/tables", &who("alice"))
                .is_some()
        );

        // Invalid keys
        assert!(IdempotencyKey::new("", "POST", "/v1/tables", &who("alice")).is_none()); // Empty
        assert!(
            IdempotencyKey::new("key with spaces", "POST", "/v1/tables", &who("alice")).is_none()
        ); // Spaces
        assert!(IdempotencyKey::new("key@symbol", "POST", "/v1/tables", &who("alice")).is_none()); // Invalid char

        // Too long
        let long_key = "a".repeat(MAX_KEY_LENGTH + 1);
        assert!(IdempotencyKey::new(&long_key, "POST", "/v1/tables", &who("alice")).is_none());
    }

    /// The client chooses the key, so two principals routinely pick the same one.
    /// Without the principal in the scope, the header is a cross-tenant read
    /// primitive: send someone else's key and receive their cached response.
    #[test]
    fn the_same_key_from_two_principals_is_two_entries() {
        let alice = IdempotencyKey::new("shared", "POST", "/v1/tables", &who("alice")).unwrap();
        let bob = IdempotencyKey::new("shared", "POST", "/v1/tables", &who("bob")).unwrap();
        assert_ne!(
            alice, bob,
            "one principal could read another's cached response"
        );
    }

    /// Scope parts are joined with a separator no part may contain, so a
    /// principal named `a:b` cannot be made to collide with another scope.
    #[test]
    fn scope_parts_cannot_be_confused() {
        let odd = IdempotencyKey::new("k", "POST", "/v1/tables", &who("alice:acme")).unwrap();
        let plain = IdempotencyKey::new("k", "POST", "/v1/tables", &who("alice")).unwrap();
        assert_ne!(odd, plain);
    }

    #[test]
    fn test_idempotency_key_scoping() {
        let key1 = IdempotencyKey::new("same-key", "POST", "/v1/tables", &who("alice")).unwrap();
        let key2 = IdempotencyKey::new("same-key", "DELETE", "/v1/tables", &who("alice")).unwrap();
        let key3 =
            IdempotencyKey::new("same-key", "POST", "/v1/namespaces", &who("alice")).unwrap();

        // Same key value but different scopes should be different
        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_idempotency_key_from_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            IDEMPOTENCY_KEY_HEADER,
            HeaderValue::from_static("test-key-123"),
        );

        let key =
            IdempotencyKey::from_headers(&headers, "POST", "/v1/tables", &who("alice")).unwrap();
        assert_eq!(key.value(), "test-key-123");
    }

    /// Expiry belongs to the cache, not to the entry: the local cache is
    /// TTL-evicting and the shared store filters on `expires_at_ms`. An entry
    /// that could be asked whether it had expired was a third answer nobody
    /// consulted, and a place for the three to disagree.
    #[tokio::test]
    async fn an_entry_expires_with_the_cache_that_holds_it() {
        let cache = IdempotencyCache::new(Duration::from_millis(50));
        let key = IdempotencyKey::new("expiring", "POST", "/v1/tables", &who("alice")).unwrap();
        cache
            .set(
                key.clone(),
                CachedResponse::new(StatusCode::OK, Bytes::from("body"), None),
            )
            .await;

        assert!(cache.get(&key).await.is_some());
        tokio::time::sleep(Duration::from_millis(120)).await;
        cache.cache.run_pending_tasks();
        assert!(cache.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn a_stored_response_comes_back() {
        let cache = IdempotencyCache::new(Duration::from_secs(60));
        let key = IdempotencyKey::new("test-key", "POST", "/v1/tables", &who("alice")).unwrap();

        assert!(cache.get(&key).await.is_none());

        cache
            .set(
                key.clone(),
                CachedResponse::new(
                    StatusCode::CREATED,
                    Bytes::from(r#"{"result": "ok"}"#),
                    Some("application/json".to_string()),
                ),
            )
            .await;

        assert_eq!(cache.get(&key).await.unwrap().status, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn a_response_stops_coming_back_after_the_ttl() {
        let cache = IdempotencyCache::new(Duration::from_millis(10));
        let key = IdempotencyKey::new("test-key", "POST", "/v1/tables", &who("alice")).unwrap();

        cache
            .set(
                key.clone(),
                CachedResponse::new(StatusCode::OK, Bytes::from("test"), None),
            )
            .await;
        assert!(cache.get(&key).await.is_some());

        thread::sleep(Duration::from_millis(20));
        assert!(cache.get(&key).await.is_none());
    }

    /// Replicas share a store; the local cache is a read-through in front of it.
    #[tokio::test]
    async fn a_shared_store_answers_a_replica_that_never_saw_the_request() {
        #[derive(Debug, Default)]
        struct Memory(std::sync::Mutex<HashMap<String, (u16, Vec<u8>)>>);

        #[async_trait::async_trait]
        impl SharedIdempotencyStore for Memory {
            async fn get(&self, key: &str) -> Result<Option<CachedResponse>, String> {
                Ok(self.0.lock().unwrap().get(key).map(|(status, body)| {
                    CachedResponse::new(
                        StatusCode::from_u16(*status).unwrap(),
                        Bytes::from(body.clone()),
                        None,
                    )
                }))
            }

            async fn put(
                &self,
                key: &str,
                response: &CachedResponse,
                _ttl: Duration,
            ) -> Result<(), String> {
                self.0.lock().unwrap().insert(
                    key.to_string(),
                    (response.status.as_u16(), response.body.to_vec()),
                );
                Ok(())
            }
        }

        let shared = Arc::new(Memory::default());
        let key = IdempotencyKey::new("shared", "POST", "/v1/tables", &who("alice")).unwrap();

        let first =
            IdempotencyCache::new(Duration::from_secs(60)).with_shared_store(shared.clone());
        first
            .set(
                key.clone(),
                CachedResponse::new(StatusCode::OK, Bytes::from("once"), None),
            )
            .await;

        // A different replica: same store, cold local cache.
        let second = IdempotencyCache::new(Duration::from_secs(60)).with_shared_store(shared);
        let hit = second
            .get(&key)
            .await
            .expect("the retry must see the first response");
        assert_eq!(hit.body, Bytes::from("once"));
    }

    /// A store that cannot answer must not refuse the write it was recording.
    #[tokio::test]
    async fn a_broken_shared_store_is_a_miss_rather_than_a_failure() {
        #[derive(Debug)]
        struct Broken;

        #[async_trait::async_trait]
        impl SharedIdempotencyStore for Broken {
            async fn get(&self, _: &str) -> Result<Option<CachedResponse>, String> {
                Err("down".to_string())
            }
            async fn put(&self, _: &str, _: &CachedResponse, _: Duration) -> Result<(), String> {
                Err("down".to_string())
            }
        }

        let cache =
            IdempotencyCache::new(Duration::from_secs(60)).with_shared_store(Arc::new(Broken));
        let key = IdempotencyKey::new("k", "POST", "/v1/tables", &who("alice")).unwrap();

        cache
            .set(
                key.clone(),
                CachedResponse::new(StatusCode::OK, Bytes::from("x"), None),
            )
            .await;
        // The local half still works, and nothing panicked.
        assert!(cache.get(&key).await.is_some());
    }

    #[test]
    fn test_cached_response_from_json() {
        #[derive(Serialize)]
        struct TestResponse {
            message: String,
        }

        let value = TestResponse {
            message: "success".to_string(),
        };

        let response = CachedResponse::from_json(StatusCode::CREATED, &value).unwrap();
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.content_type, Some("application/json".to_string()));
        assert!(
            std::str::from_utf8(&response.body)
                .unwrap()
                .contains("success")
        );
    }

    /// The cache is bounded, so a caller cannot exhaust memory by sending keys.
    #[tokio::test]
    async fn the_cache_is_bounded() {
        let cache = IdempotencyCache::new(Duration::from_secs(3600));

        for i in 0..MAX_CACHE_SIZE + 1_000 {
            let key =
                IdempotencyKey::new(format!("key-{i}"), "POST", "/v1/t", &who("alice")).unwrap();
            cache
                .set(
                    key,
                    CachedResponse::new(StatusCode::OK, Bytes::from("test"), None),
                )
                .await;
        }

        cache.cache.run_pending_tasks();
        assert!(cache.cache.entry_count() <= MAX_CACHE_SIZE);
    }
}
