//! Idempotency key support for safe retries.
//!
//! This module provides idempotency key handling to enable safe retries of
//! mutation operations (create, update, delete). When a client sends a request
//! with an `Idempotency-Key` header, the server:
//!
//! 1. Checks if a response for that key already exists
//! 2. If yes, returns the cached response
//! 3. If no, processes the request and caches the response
//!
//! # Security
//!
//! The cache has a bounded size (`MAX_CACHE_SIZE`) to prevent memory exhaustion
//! attacks. When the cache is full, the oldest entries are evicted to make room.
//!
//! # Usage
//!
//! ```
//! use rustberg::catalog::IdempotencyCache;
//! use std::time::Duration;
//!
//! let cache = IdempotencyCache::new(Duration::from_secs(86400)); // 24h TTL
//! // Use cache.get() and cache.set() in handlers
//! ```
//!
//! # Header Format
//!
//! The `Idempotency-Key` header should contain a unique identifier (preferably UUIDv7).
//! Example: `Idempotency-Key: 01895c3e-8844-7fff-a5cb-7a583a3e51fe`

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use dashmap::DashMap;
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Header name for idempotency keys.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Response header indicating an idempotency key was used.
pub const IDEMPOTENCY_KEY_USED_HEADER: &str = "idempotency-key-used";

/// Default TTL for idempotency keys (24 hours).
pub const DEFAULT_TTL: Duration = Duration::from_secs(86400);

/// Maximum length for idempotency keys.
const MAX_KEY_LENGTH: usize = 256;

/// Maximum number of entries in the idempotency cache.
/// SEC-026: Bounded cache size prevents memory exhaustion attacks.
const MAX_CACHE_SIZE: usize = 100_000;

// ============================================================================
// Idempotency Key
// ============================================================================

/// Represents a validated idempotency key.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct IdempotencyKey {
    key: String,
    /// Method + path combination to scope the key
    scope: String,
}

impl IdempotencyKey {
    /// Creates a new idempotency key with scope.
    pub fn new(key: impl Into<String>, method: &str, path: &str) -> Option<Self> {
        let key = key.into();

        // Validate key length
        if key.is_empty() || key.len() > MAX_KEY_LENGTH {
            return None;
        }

        // Validate key characters (alphanumeric, hyphens, underscores)
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return None;
        }

        Some(Self {
            key,
            scope: format!("{}:{}", method, path),
        })
    }

    /// Extracts an idempotency key from request headers.
    pub fn from_headers(headers: &HeaderMap, method: &str, path: &str) -> Option<Self> {
        headers
            .get(IDEMPOTENCY_KEY_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|key| Self::new(key, method, path))
    }

    /// Returns the raw key value.
    pub fn value(&self) -> &str {
        &self.key
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
    pub fn from_json<T: Serialize>(status: StatusCode, value: &T) -> Option<Self> {
        serde_json::to_vec(value).ok().map(|body| Self {
            status,
            body: Bytes::from(body),
            content_type: Some("application/json".to_string()),
            cached_at: Instant::now(),
        })
    }

    /// Checks if this response has expired.
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }

    /// Converts to an Axum response.
    pub fn into_axum_response(self) -> axum::response::Response {
        use axum::http::header::CONTENT_TYPE;
        use axum::response::IntoResponse;

        let mut response = (self.status, self.body).into_response();

        if let Some(content_type) = self.content_type {
            if let Ok(value) = HeaderValue::from_str(&content_type) {
                response.headers_mut().insert(CONTENT_TYPE, value);
            }
        }

        // Add header indicating this was a cached response
        response.headers_mut().insert(
            IDEMPOTENCY_KEY_USED_HEADER,
            HeaderValue::from_static("true"),
        );

        response
    }
}

// ============================================================================
// Idempotency Cache
// ============================================================================

/// Thread-safe cache for idempotent responses.
#[derive(Clone)]
pub struct IdempotencyCache {
    /// Map of idempotency keys to cached responses.
    cache: Arc<DashMap<IdempotencyKey, CachedResponse>>,
    /// Time-to-live for cached responses.
    ttl: Duration,
}

impl IdempotencyCache {
    /// Creates a new idempotency cache with the specified TTL.
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Creates a new idempotency cache with default TTL (24 hours).
    pub fn default_cache() -> Self {
        Self::new(DEFAULT_TTL)
    }

    /// Gets a cached response for the given key.
    ///
    /// Returns `Some(response)` if found and not expired, `None` otherwise.
    pub fn get(&self, key: &IdempotencyKey) -> Option<CachedResponse> {
        self.cache.get(key).and_then(|entry| {
            if entry.is_expired(self.ttl) {
                // Remove expired entry
                drop(entry);
                self.cache.remove(key);
                None
            } else {
                Some(entry.clone())
            }
        })
    }

    /// Stores a response for the given key.
    ///
    /// SEC-026: If cache is at capacity, evict oldest entries first.
    pub fn set(&self, key: IdempotencyKey, response: CachedResponse) {
        // Check if we need to evict entries
        if self.cache.len() >= MAX_CACHE_SIZE {
            self.evict_oldest();
        }
        self.cache.insert(key, response);
    }

    /// Evicts the oldest entries from the cache.
    ///
    /// This is called when the cache reaches MAX_CACHE_SIZE.
    /// Removes approximately 10% of entries (oldest by cached_at time).
    fn evict_oldest(&self) {
        let evict_count = MAX_CACHE_SIZE / 10;

        // Collect entries with their age
        let mut entries: Vec<(IdempotencyKey, Instant)> = self
            .cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().cached_at))
            .collect();

        // Sort by cached_at (oldest first)
        entries.sort_by_key(|(_, cached_at)| *cached_at);

        // Remove the oldest entries
        for (key, _) in entries.into_iter().take(evict_count) {
            self.cache.remove(&key);
        }

        tracing::debug!(
            evicted = evict_count,
            remaining = self.cache.len(),
            "Evicted oldest idempotency cache entries"
        );
    }

    /// Removes a cached response.
    pub fn remove(&self, key: &IdempotencyKey) {
        self.cache.remove(key);
    }

    /// Checks if a key is already being processed.
    ///
    /// This can be used for in-flight request detection.
    pub fn contains(&self, key: &IdempotencyKey) -> bool {
        self.cache.contains_key(key)
    }

    /// Cleans up expired entries.
    ///
    /// Call this periodically to prevent unbounded memory growth.
    pub fn cleanup(&self) {
        self.cache
            .retain(|_, response| !response.is_expired(self.ttl));
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Returns the configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

impl Default for IdempotencyCache {
    fn default() -> Self {
        Self::default_cache()
    }
}

// ============================================================================
// Idempotency Guard
// ============================================================================

/// Guard for idempotency key processing.
///
/// This is returned when a request with an idempotency key is being processed.
/// When dropped without `complete()` being called, the entry is removed to allow retries.
#[allow(dead_code)]
pub struct IdempotencyGuard<'a> {
    cache: &'a IdempotencyCache,
    key: IdempotencyKey,
    completed: bool,
}

#[allow(dead_code)]
impl<'a> IdempotencyGuard<'a> {
    /// Creates a new guard.
    fn new(cache: &'a IdempotencyCache, key: IdempotencyKey) -> Self {
        Self {
            cache,
            key,
            completed: false,
        }
    }

    /// Marks the operation as complete and stores the response.
    pub fn complete(mut self, response: CachedResponse) {
        self.completed = true;
        self.cache.set(self.key.clone(), response);
    }
}

impl<'a> Drop for IdempotencyGuard<'a> {
    fn drop(&mut self) {
        if !self.completed {
            // Request failed or was cancelled, allow retry
            self.cache.remove(&self.key);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_idempotency_key_validation() {
        // Valid keys
        assert!(IdempotencyKey::new("abc123", "POST", "/v1/tables").is_some());
        assert!(IdempotencyKey::new("uuid-with-dashes", "POST", "/v1/tables").is_some());
        assert!(IdempotencyKey::new("key_with_underscores", "POST", "/v1/tables").is_some());

        // Invalid keys
        assert!(IdempotencyKey::new("", "POST", "/v1/tables").is_none()); // Empty
        assert!(IdempotencyKey::new("key with spaces", "POST", "/v1/tables").is_none()); // Spaces
        assert!(IdempotencyKey::new("key@symbol", "POST", "/v1/tables").is_none()); // Invalid char

        // Too long
        let long_key = "a".repeat(MAX_KEY_LENGTH + 1);
        assert!(IdempotencyKey::new(&long_key, "POST", "/v1/tables").is_none());
    }

    #[test]
    fn test_idempotency_key_scoping() {
        let key1 = IdempotencyKey::new("same-key", "POST", "/v1/tables").unwrap();
        let key2 = IdempotencyKey::new("same-key", "DELETE", "/v1/tables").unwrap();
        let key3 = IdempotencyKey::new("same-key", "POST", "/v1/namespaces").unwrap();

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

        let key = IdempotencyKey::from_headers(&headers, "POST", "/v1/tables").unwrap();
        assert_eq!(key.value(), "test-key-123");
    }

    #[test]
    fn test_cached_response_expiry() {
        let response = CachedResponse::new(
            StatusCode::OK,
            Bytes::from("test"),
            Some("application/json".to_string()),
        );

        // Not expired immediately
        assert!(!response.is_expired(Duration::from_secs(60)));

        // Would be expired if TTL was 0
        assert!(response.is_expired(Duration::from_nanos(1)));
    }

    #[test]
    fn test_idempotency_cache_basic() {
        let cache = IdempotencyCache::new(Duration::from_secs(60));
        let key = IdempotencyKey::new("test-key", "POST", "/v1/tables").unwrap();

        // Initially empty
        assert!(cache.get(&key).is_none());

        // Store response
        let response = CachedResponse::new(
            StatusCode::CREATED,
            Bytes::from(r#"{"result": "ok"}"#),
            Some("application/json".to_string()),
        );
        cache.set(key.clone(), response);

        // Should be retrievable
        let cached = cache.get(&key).unwrap();
        assert_eq!(cached.status, StatusCode::CREATED);
    }

    #[test]
    fn test_idempotency_cache_expiry() {
        let cache = IdempotencyCache::new(Duration::from_millis(10));
        let key = IdempotencyKey::new("test-key", "POST", "/v1/tables").unwrap();

        let response = CachedResponse::new(StatusCode::OK, Bytes::from("test"), None);
        cache.set(key.clone(), response);

        // Available immediately
        assert!(cache.get(&key).is_some());

        // Wait for expiry
        thread::sleep(Duration::from_millis(20));

        // Should be expired now
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_idempotency_cache_cleanup() {
        let cache = IdempotencyCache::new(Duration::from_millis(10));

        // Add some entries
        for i in 0..5 {
            let key = IdempotencyKey::new(format!("key-{}", i), "POST", "/v1/tables").unwrap();
            let response = CachedResponse::new(StatusCode::OK, Bytes::from("test"), None);
            cache.set(key, response);
        }

        assert_eq!(cache.len(), 5);

        // Wait for expiry
        thread::sleep(Duration::from_millis(20));

        // Cleanup should remove all expired entries
        cache.cleanup();
        assert_eq!(cache.len(), 0);
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
        assert!(std::str::from_utf8(&response.body)
            .unwrap()
            .contains("success"));
    }

    #[test]
    fn test_idempotency_cache_bounded_size() {
        // SEC-026: Test that cache evicts entries when at capacity
        let cache = IdempotencyCache::new(Duration::from_secs(3600));

        // Add MAX_CACHE_SIZE entries
        // Note: We use a smaller number for testing to avoid slow tests
        let test_size = 1000;
        for i in 0..test_size {
            let key = IdempotencyKey::new(format!("key-{}", i), "POST", "/v1/tables").unwrap();
            let response = CachedResponse::new(StatusCode::OK, Bytes::from("test"), None);
            cache.set(key, response);
        }

        assert_eq!(cache.len(), test_size);

        // Adding more entries should trigger eviction when we hit MAX_CACHE_SIZE
        // For unit testing, we just verify the evict_oldest function works
        cache.evict_oldest();

        // Should have evicted ~10% of entries
        assert!(cache.len() < test_size);
    }
}
