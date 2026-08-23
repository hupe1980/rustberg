//! Rate limiting for authentication and API requests.
//!
//! This module provides rate limiting to protect against brute-force attacks,
//! denial-of-service attacks, and resource exhaustion.
//!
//! # Features
//!
//! - **Per-IP rate limiting**: Limits requests from individual IP addresses
//! - **Per-tenant rate limiting**: Limits requests per authenticated tenant
//! - **Per-key rate limiting**: Limits requests per API key (for failed attempts)
//! - **Sliding window**: Uses sliding window rate limiting for smooth throttling
//! - **Response headers**: Returns standard rate limit headers
//!
//! # Configuration
//!
//! Rate limits are configurable via `RateLimitConfig`:
//!
//! ```rust
//! use rustberg::auth::RateLimitConfig;
//!
//! let config = RateLimitConfig::builder()
//!     .per_ip_requests(1000)  // 1000 req/min per IP
//!     .per_ip_burst(100)      // Burst of 100 requests
//!     .per_tenant_requests(10000) // 10000 req/min per tenant
//!     .enabled(true)
//!     .build();
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use moka::sync::Cache;
use parking_lot::Mutex;
use serde::Serialize;

// ============================================================================
// Rate Limit Configuration
// ============================================================================

/// Configuration for rate limiting behavior.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    pub enabled: bool,

    /// Maximum requests per minute per IP address.
    pub per_ip_requests: u32,

    /// Burst capacity for per-IP limiting (token bucket).
    pub per_ip_burst: u32,

    /// Maximum requests per minute per tenant.
    pub per_tenant_requests: u32,

    /// Burst capacity for per-tenant limiting.
    pub per_tenant_burst: u32,

    /// Maximum failed authentication attempts per IP before temporary ban.
    pub auth_fail_limit: u32,

    /// Duration to ban an IP after exceeding auth fail limit.
    pub auth_fail_ban_duration: Duration,

    /// Whether to trust proxy headers (X-Forwarded-For, X-Real-IP) for client IP.
    ///
    /// **SECURITY WARNING**: Only enable this when running behind a trusted reverse proxy
    /// that sets these headers correctly. If enabled without a trusted proxy, attackers
    /// can spoof their IP address to bypass rate limiting.
    ///
    /// Default: `false` (use connection IP only)
    pub trust_proxy_headers: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_ip_requests: 1000,      // 1000 req/min per IP
            per_ip_burst: 100,          // Allow burst of 100
            per_tenant_requests: 10000, // 10000 req/min per tenant
            per_tenant_burst: 1000,     // Allow burst of 1000
            auth_fail_limit: 10,        // 10 failed auths before ban
            auth_fail_ban_duration: Duration::from_secs(300), // 5 minute ban
            trust_proxy_headers: false, // SECURE DEFAULT: don't trust proxy headers
        }
    }
}

impl RateLimitConfig {
    /// Creates a new builder for rate limit configuration.
    pub fn builder() -> RateLimitConfigBuilder {
        RateLimitConfigBuilder::default()
    }

    /// Creates a disabled rate limit configuration (for testing).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Creates a strict rate limit configuration (for production).
    pub fn strict() -> Self {
        Self {
            enabled: true,
            per_ip_requests: 100,
            per_ip_burst: 20,
            per_tenant_requests: 1000,
            per_tenant_burst: 100,
            auth_fail_limit: 5,
            auth_fail_ban_duration: Duration::from_secs(600), // 10 minutes
            trust_proxy_headers: false, // SECURE DEFAULT: don't trust proxy headers
        }
    }

    /// Creates RateLimitConfig from file-based configuration.
    ///
    /// Returns None if rate limiting is disabled in the file config.
    pub fn from_file_config(file_config: &crate::config::RateLimitConfigFile) -> Option<Self> {
        if !file_config.enabled {
            return Some(Self::disabled());
        }

        Some(Self {
            enabled: true,
            per_ip_requests: file_config.requests_per_second * 60, // Convert from per-second to per-minute
            per_ip_burst: file_config.burst_size,
            per_tenant_requests: file_config.requests_per_second * 60 * 10, // 10x IP limit for tenant
            per_tenant_burst: file_config.burst_size * 10,
            auth_fail_limit: file_config.max_auth_failures,
            auth_fail_ban_duration: Duration::from_secs(file_config.lockout_duration_seconds),
            trust_proxy_headers: file_config.trust_proxy_headers,
        })
    }
}

/// Builder for rate limit configuration.
#[derive(Default)]
pub struct RateLimitConfigBuilder {
    config: RateLimitConfig,
}

impl RateLimitConfigBuilder {
    /// Sets whether rate limiting is enabled.
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.config.enabled = enabled;
        self
    }

    /// Sets the per-IP request limit per minute.
    pub fn per_ip_requests(mut self, requests: u32) -> Self {
        self.config.per_ip_requests = requests;
        self
    }

    /// Sets the per-IP burst capacity.
    pub fn per_ip_burst(mut self, burst: u32) -> Self {
        self.config.per_ip_burst = burst;
        self
    }

    /// Sets the per-tenant request limit per minute.
    pub fn per_tenant_requests(mut self, requests: u32) -> Self {
        self.config.per_tenant_requests = requests;
        self
    }

    /// Sets the per-tenant burst capacity.
    pub fn per_tenant_burst(mut self, burst: u32) -> Self {
        self.config.per_tenant_burst = burst;
        self
    }

    /// Sets the auth failure limit before ban.
    pub fn auth_fail_limit(mut self, limit: u32) -> Self {
        self.config.auth_fail_limit = limit;
        self
    }

    /// Sets the duration to ban after exceeding auth fail limit.
    pub fn auth_fail_ban_duration(mut self, duration: Duration) -> Self {
        self.config.auth_fail_ban_duration = duration;
        self
    }

    /// Sets whether to trust proxy headers for client IP detection.
    ///
    /// **SECURITY WARNING**: Only enable this when running behind a trusted reverse proxy.
    pub fn trust_proxy_headers(mut self, trust: bool) -> Self {
        self.config.trust_proxy_headers = trust;
        self
    }

    /// Builds the rate limit configuration.
    pub fn build(self) -> RateLimitConfig {
        self.config
    }
}

// ============================================================================
// Token Bucket Rate Limiter
// ============================================================================

/// A token bucket rate limiter implementation.
///
/// Uses the token bucket algorithm where tokens are added at a constant rate
/// and requests consume tokens. Requests are rejected when no tokens are available.
#[derive(Debug)]
struct TokenBucket {
    /// Maximum tokens (bucket capacity).
    capacity: u32,
    /// Current token count.
    tokens: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last refill timestamp.
    last_refill: std::time::Instant,
}

impl TokenBucket {
    /// Creates a new token bucket.
    fn new(capacity: u32, requests_per_minute: u32) -> Self {
        Self {
            capacity,
            tokens: capacity as f64,
            refill_rate: requests_per_minute as f64 / 60.0,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Attempts to consume a token. Returns true if successful.
    fn try_acquire(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refills tokens based on elapsed time.
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    /// Returns the number of remaining tokens (floored to integer).
    fn remaining(&self) -> u32 {
        self.tokens as u32
    }

    /// Returns estimated seconds until a token is available.
    fn retry_after(&self) -> u64 {
        if self.tokens >= 1.0 {
            0
        } else {
            let needed = 1.0 - self.tokens;
            (needed / self.refill_rate).ceil() as u64
        }
    }
}

// ============================================================================
// Auth Failure Tracker
// ============================================================================

/// Tracks failed authentication attempts per IP.
#[derive(Debug)]
struct AuthFailureEntry {
    /// Number of consecutive failures.
    failures: u32,
    /// Time of first failure in current window.
    first_failure: std::time::Instant,
    /// Ban expiration time (if banned).
    ban_until: Option<std::time::Instant>,
}

impl AuthFailureEntry {
    fn new() -> Self {
        Self {
            failures: 0,
            first_failure: std::time::Instant::now(),
            ban_until: None,
        }
    }

    fn is_banned(&self) -> bool {
        self.ban_until
            .map(|until| std::time::Instant::now() < until)
            .unwrap_or(false)
    }

    fn ban_remaining_secs(&self) -> Option<u64> {
        self.ban_until.and_then(|until| {
            let now = std::time::Instant::now();
            if now < until {
                Some((until - now).as_secs())
            } else {
                None
            }
        })
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Largest number of distinct clients tracked at once.
///
/// Every map here is keyed by something the *client* controls — its address, or
/// its tenant. An unbounded map is therefore a memory-exhaustion vector in the
/// component whose job is preventing exhaustion: a single IPv6 /64 offers more
/// source addresses than there are bytes of RAM, and NAT churn grows the map
/// without any attacker at all.
///
/// 100k entries is roughly 10 MB and far more concurrent clients than a catalog
/// sees. Past it, the least-recently-used entry is dropped.
const MAX_TRACKED_CLIENTS: u64 = 100_000;

/// How long an idle entry is kept.
///
/// A bucket refills continuously, so one untouched for this long is
/// indistinguishable from a fresh one. Auth-failure entries are held longer by
/// their own window, checked on read.
const ENTRY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Thread-safe rate limiter with per-IP and per-tenant limiting.
///
/// # Bounded by construction
///
/// State is held in LRU caches with a capacity and an idle timeout, not in
/// unbounded maps swept by a periodic task. That is a deliberate change: the
/// sweep existed, was tested, and was **never scheduled**, so the maps grew for
/// the life of the process. A bound that depends on somebody remembering to call
/// a cleanup function is not a bound.
///
/// Eviction is safe in both directions. Dropping a bucket early gives that client
/// a fresh allowance — bounded by the LRU order, so it costs an attacker more
/// traffic than it saves. Dropping a *ban* early would be worse, so bans are
/// checked against a deadline stored in the entry and the ban duration is well
/// inside the idle timeout.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-IP token buckets.
    ip_limiters: Cache<IpAddr, Arc<Mutex<TokenBucket>>>,
    /// Per-tenant token buckets.
    tenant_limiters: Cache<String, Arc<Mutex<TokenBucket>>>,
    /// Auth failure tracker per IP.
    auth_failures: Cache<IpAddr, Arc<Mutex<AuthFailureEntry>>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        fn bounded<K, V>() -> Cache<K, V>
        where
            K: std::hash::Hash + Eq + Send + Sync + 'static,
            V: Clone + Send + Sync + 'static,
        {
            Cache::builder()
                .max_capacity(MAX_TRACKED_CLIENTS)
                .time_to_idle(ENTRY_IDLE_TIMEOUT)
                .build()
        }

        Self {
            config,
            ip_limiters: bounded(),
            tenant_limiters: bounded(),
            // Held for the auth-failure window rather than the shorter bucket
            // idle timeout, so a slow brute-force cannot reset its own counter by
            // simply pausing.
            auth_failures: Cache::builder()
                .max_capacity(MAX_TRACKED_CLIENTS)
                .time_to_idle(Duration::from_secs(3600))
                .build(),
        }
    }

    /// Creates a new rate limiter with default configuration.
    pub fn default_limiter() -> Arc<Self> {
        Arc::new(Self::new(RateLimitConfig::default()))
    }

    /// Returns whether rate limiting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns whether proxy headers should be trusted for IP detection.
    pub fn trust_proxy_headers(&self) -> bool {
        self.config.trust_proxy_headers
    }

    /// Checks if an IP is currently banned due to auth failures.
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.auth_failures
            .get(ip)
            .map(|entry| entry.lock().is_banned())
            .unwrap_or(false)
    }

    /// Returns the ban remaining seconds for an IP.
    pub fn ip_ban_remaining(&self, ip: &IpAddr) -> Option<u64> {
        self.auth_failures
            .get(ip)
            .and_then(|entry| entry.lock().ban_remaining_secs())
    }

    /// Records a failed authentication attempt for an IP.
    pub fn record_auth_failure(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }

        let entry = self
            .auth_failures
            .get_with(*ip, || Arc::new(Mutex::new(AuthFailureEntry::new())));

        let mut entry = entry.lock();

        // Reset if first failure was more than 1 hour ago
        if entry.first_failure.elapsed() > Duration::from_secs(3600) {
            *entry = AuthFailureEntry::new();
        }

        // Use saturating_add to prevent overflow (defense-in-depth)
        entry.failures = entry.failures.saturating_add(1);

        // Check if we should ban
        if entry.failures >= self.config.auth_fail_limit {
            entry.ban_until = Some(std::time::Instant::now() + self.config.auth_fail_ban_duration);
            tracing::warn!(
                ip = %ip,
                failures = entry.failures,
                ban_duration_secs = self.config.auth_fail_ban_duration.as_secs(),
                "IP banned due to excessive auth failures"
            );
        }
    }

    /// Records a successful authentication, resetting failure count.
    pub fn record_auth_success(&self, ip: &IpAddr) {
        if !self.config.enabled {
            return;
        }

        // Remove failure tracking on successful auth
        self.auth_failures.invalidate(ip);
    }

    /// Checks the per-IP rate limit. Returns Ok if allowed, Err with retry info if limited.
    pub fn check_ip_limit(&self, ip: &IpAddr) -> Result<RateLimitInfo, RateLimitExceeded> {
        if !self.config.enabled {
            return Ok(RateLimitInfo::unlimited());
        }

        // Check if IP is banned
        if self.is_ip_banned(ip) {
            let retry_after = self.ip_ban_remaining(ip).unwrap_or(60);
            return Err(RateLimitExceeded {
                limit: self.config.per_ip_requests,
                remaining: 0,
                retry_after,
                limit_type: LimitType::IpBanned,
            });
        }

        let entry = self.ip_limiters.get_with(*ip, || {
            Arc::new(Mutex::new(TokenBucket::new(
                self.config.per_ip_burst,
                self.config.per_ip_requests,
            )))
        });

        let mut bucket = entry.lock();

        if bucket.try_acquire() {
            Ok(RateLimitInfo {
                limit: self.config.per_ip_requests,
                remaining: bucket.remaining(),
                reset_secs: 60, // Window resets in ~60 seconds
                limit_type: LimitType::PerIp,
            })
        } else {
            Err(RateLimitExceeded {
                limit: self.config.per_ip_requests,
                remaining: 0,
                retry_after: bucket.retry_after(),
                limit_type: LimitType::PerIp,
            })
        }
    }

    /// Checks the per-tenant rate limit. Returns Ok if allowed, Err with retry info if limited.
    pub fn check_tenant_limit(&self, tenant_id: &str) -> Result<RateLimitInfo, RateLimitExceeded> {
        if !self.config.enabled {
            return Ok(RateLimitInfo::unlimited());
        }

        let entry = self.tenant_limiters.get_with(tenant_id.to_string(), || {
            Arc::new(Mutex::new(TokenBucket::new(
                self.config.per_tenant_burst,
                self.config.per_tenant_requests,
            )))
        });

        let mut bucket = entry.lock();

        if bucket.try_acquire() {
            Ok(RateLimitInfo {
                limit: self.config.per_tenant_requests,
                remaining: bucket.remaining(),
                reset_secs: 60,
                limit_type: LimitType::PerTenant,
            })
        } else {
            Err(RateLimitExceeded {
                limit: self.config.per_tenant_requests,
                remaining: 0,
                retry_after: bucket.retry_after(),
                limit_type: LimitType::PerTenant,
            })
        }
    }

    /// Checks both IP and tenant limits. Returns the most restrictive result.
    pub fn check_limits(
        &self,
        ip: &IpAddr,
        tenant_id: Option<&str>,
    ) -> Result<RateLimitInfo, RateLimitExceeded> {
        // First check IP limit (applies to all requests)
        let ip_result = self.check_ip_limit(ip)?;

        // Then check tenant limit (only for authenticated requests)
        if let Some(tenant_id) = tenant_id {
            let tenant_result = self.check_tenant_limit(tenant_id)?;

            // Return the more restrictive limit info
            if tenant_result.remaining < ip_result.remaining {
                return Ok(tenant_result);
            }
        }

        Ok(ip_result)
    }

    /// Returns the current rate limit state for an IP without consuming a token.
    ///
    /// Use this to populate rate-limit response headers after the request has
    /// already been admitted by `check_ip_limit`.
    pub fn peek_ip_limit(&self, ip: &IpAddr) -> Option<RateLimitInfo> {
        if !self.config.enabled {
            return Some(RateLimitInfo::unlimited());
        }

        self.ip_limiters.get(ip).map(|entry| {
            let bucket = entry.lock();
            RateLimitInfo {
                limit: self.config.per_ip_requests,
                remaining: bucket.remaining(),
                reset_secs: 60,
                limit_type: LimitType::PerIp,
            }
        })
    }

    /// Number of clients currently tracked, for tests and diagnostics.
    ///
    /// There is deliberately no `cleanup()`. One existed, was tested, and was
    /// never called from anywhere in the server — so the maps it was meant to
    /// bound grew for the life of the process. Eviction is now a property of the
    /// data structure instead of an obligation on the caller.
    pub fn tracked_clients(&self) -> u64 {
        self.ip_limiters.run_pending_tasks();
        self.ip_limiters.entry_count()
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

// ============================================================================
// Rate Limit Info
// ============================================================================

/// Information about current rate limit state.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum requests allowed in the window.
    pub limit: u32,
    /// Remaining requests in the current window.
    pub remaining: u32,
    /// Seconds until the window resets.
    pub reset_secs: u64,
    /// Type of rate limit.
    pub limit_type: LimitType,
}

impl RateLimitInfo {
    /// Creates info for unlimited (rate limiting disabled).
    fn unlimited() -> Self {
        Self {
            limit: u32::MAX,
            remaining: u32::MAX,
            reset_secs: 0,
            limit_type: LimitType::None,
        }
    }

    /// Returns response headers for this rate limit info.
    pub fn headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        if matches!(self.limit_type, LimitType::None) {
            return vec![];
        }

        vec![
            (
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(self.limit),
            ),
            (
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(self.remaining),
            ),
            (
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from(self.reset_secs),
            ),
        ]
    }
}

/// Type of rate limit being applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    /// No rate limiting.
    None,
    /// Per-IP address limit.
    PerIp,
    /// Per-tenant limit.
    PerTenant,
    /// IP is temporarily banned.
    IpBanned,
}

// ============================================================================
// Rate Limit Exceeded
// ============================================================================

/// Error returned when rate limit is exceeded.
#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    /// Maximum requests allowed.
    pub limit: u32,
    /// Remaining requests (always 0 when exceeded).
    pub remaining: u32,
    /// Seconds until retry is allowed.
    pub retry_after: u64,
    /// Type of limit that was exceeded.
    pub limit_type: LimitType,
}

impl RateLimitExceeded {
    /// Returns response headers for this rate limit error.
    pub fn headers(&self) -> Vec<(HeaderName, HeaderValue)> {
        vec![
            (
                HeaderName::from_static("x-ratelimit-limit"),
                HeaderValue::from(self.limit),
            ),
            (
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from(self.remaining),
            ),
            (
                HeaderName::from_static("retry-after"),
                HeaderValue::from(self.retry_after),
            ),
        ]
    }
}

/// Error response body for rate limit exceeded.
#[derive(Debug, Serialize)]
pub struct RateLimitErrorResponse {
    pub error: RateLimitErrorBody,
}

/// Error body with details.
#[derive(Debug, Serialize)]
pub struct RateLimitErrorBody {
    pub code: u16,
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub retry_after: u64,
}

impl IntoResponse for RateLimitExceeded {
    fn into_response(self) -> Response {
        let message = match self.limit_type {
            LimitType::IpBanned => format!(
                "IP temporarily banned due to excessive authentication failures. Retry after {} seconds.",
                self.retry_after
            ),
            LimitType::PerIp => format!(
                "Rate limit exceeded for IP address. Limit: {} requests/minute. Retry after {} seconds.",
                self.limit, self.retry_after
            ),
            LimitType::PerTenant => format!(
                "Rate limit exceeded for tenant. Limit: {} requests/minute. Retry after {} seconds.",
                self.limit, self.retry_after
            ),
            LimitType::None => "Rate limit exceeded".to_string(),
        };

        let body = RateLimitErrorResponse {
            error: RateLimitErrorBody {
                code: StatusCode::TOO_MANY_REQUESTS.as_u16(),
                message,
                error_type: "RateLimitExceededException".to_string(),
                retry_after: self.retry_after,
            },
        };

        let mut response = (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();

        // Add rate limit headers
        for (name, value) in self.headers() {
            response.headers_mut().insert(name, value);
        }

        response
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let limiter = RateLimiter::new(RateLimitConfig::disabled());
        let ip = test_ip();

        // Should always succeed when disabled
        for _ in 0..10000 {
            assert!(limiter.check_ip_limit(&ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_basic() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(10)
            .per_ip_burst(5)
            .build();

        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // First 5 requests should succeed (burst capacity)
        for i in 0..5 {
            let result = limiter.check_ip_limit(&ip);
            assert!(result.is_ok(), "Request {} should succeed", i);
        }

        // 6th request should fail (burst exhausted)
        let result = limiter.check_ip_limit(&ip);
        assert!(result.is_err(), "Request 6 should be rate limited");
    }

    #[test]
    fn test_rate_limit_info_headers() {
        let info = RateLimitInfo {
            limit: 1000,
            remaining: 500,
            reset_secs: 60,
            limit_type: LimitType::PerIp,
        };

        let headers = info.headers();
        assert_eq!(headers.len(), 3);
    }

    #[test]
    fn test_auth_failure_tracking() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .auth_fail_limit(3)
            .auth_fail_ban_duration(Duration::from_secs(10))
            .build();

        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Record failures
        limiter.record_auth_failure(&ip);
        assert!(!limiter.is_ip_banned(&ip));

        limiter.record_auth_failure(&ip);
        assert!(!limiter.is_ip_banned(&ip));

        limiter.record_auth_failure(&ip);
        assert!(
            limiter.is_ip_banned(&ip),
            "IP should be banned after 3 failures"
        );

        // Check that requests are rejected
        let result = limiter.check_ip_limit(&ip);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().limit_type, LimitType::IpBanned);
    }

    #[test]
    fn test_auth_success_resets_failures() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .auth_fail_limit(5)
            .build();

        let limiter = RateLimiter::new(config);
        let ip = test_ip();

        // Record some failures
        limiter.record_auth_failure(&ip);
        limiter.record_auth_failure(&ip);

        // Record success
        limiter.record_auth_success(&ip);

        // Failures should be reset
        assert!(!limiter.is_ip_banned(&ip));
    }

    #[test]
    fn test_tenant_rate_limiting() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_tenant_requests(5)
            .per_tenant_burst(3)
            .build();

        let limiter = RateLimiter::new(config);
        let tenant = "test-tenant";

        // First 3 requests should succeed (burst)
        for i in 0..3 {
            let result = limiter.check_tenant_limit(tenant);
            assert!(result.is_ok(), "Request {} should succeed", i);
        }

        // 4th request should fail
        let result = limiter.check_tenant_limit(tenant);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().limit_type, LimitType::PerTenant);
    }

    #[test]
    fn test_combined_limits() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(100)
            .per_ip_burst(50)
            .per_tenant_requests(10)
            .per_tenant_burst(5)
            .build();

        let limiter = RateLimiter::new(config);
        let ip = test_ip();
        let tenant = "test-tenant";

        // Should respect the more restrictive tenant limit
        for _ in 0..5 {
            let result = limiter.check_limits(&ip, Some(tenant));
            assert!(result.is_ok());
        }

        // 6th request should fail due to tenant limit
        let result = limiter.check_limits(&ip, Some(tenant));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().limit_type, LimitType::PerTenant);
    }

    #[test]
    fn test_rate_limit_response() {
        let exceeded = RateLimitExceeded {
            limit: 1000,
            remaining: 0,
            retry_after: 60,
            limit_type: LimitType::PerIp,
        };

        let response = exceeded.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().contains_key("retry-after"));
        assert!(response.headers().contains_key("x-ratelimit-limit"));
    }

    #[test]
    fn test_config_builder() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(500)
            .per_ip_burst(50)
            .per_tenant_requests(5000)
            .per_tenant_burst(500)
            .auth_fail_limit(10)
            .auth_fail_ban_duration(Duration::from_secs(600))
            .build();

        assert!(config.enabled);
        assert_eq!(config.per_ip_requests, 500);
        assert_eq!(config.per_ip_burst, 50);
        assert_eq!(config.per_tenant_requests, 5000);
        assert_eq!(config.auth_fail_limit, 10);
    }

    #[test]
    fn test_strict_config() {
        let config = RateLimitConfig::strict();
        assert!(config.enabled);
        assert_eq!(config.per_ip_requests, 100);
        assert_eq!(config.auth_fail_limit, 5);
    }

    /// Tracking state is keyed by the client's own address, so it must be
    /// bounded by the data structure rather than by a sweep somebody has to
    /// remember to schedule.
    ///
    /// The previous implementation used unbounded maps with a `cleanup()` that
    /// was tested here and called from nowhere in the server, so a flood of
    /// distinct source addresses grew memory for the life of the process — a
    /// denial of service in the denial-of-service defence.
    #[test]
    fn tracked_clients_are_bounded() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(1000)
            .per_ip_burst(1000)
            .build();

        let limiter = RateLimiter::new(config);

        // Far more distinct addresses than a real deployment sees, and trivial
        // for one host to produce from an IPv6 range.
        for i in 0..250_000u32 {
            let ip: IpAddr = std::net::Ipv4Addr::from(i).into();
            let _ = limiter.check_ip_limit(&ip);
        }

        let tracked = limiter.tracked_clients();
        assert!(
            tracked <= MAX_TRACKED_CLIENTS,
            "tracked {tracked} clients, over the {MAX_TRACKED_CLIENTS} bound"
        );
    }

    /// Eviction must not drop an active limit while it is still doing work: a
    /// client under the cap keeps its bucket across consecutive requests.
    #[test]
    fn an_active_client_keeps_its_bucket() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(10)
            .per_ip_burst(3)
            .build();

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check_ip_limit(&ip).is_ok());
        assert!(limiter.check_ip_limit(&ip).is_ok());
        assert!(limiter.check_ip_limit(&ip).is_ok());

        // The burst is spent; a fourth request must be refused rather than
        // served from a freshly created bucket.
        assert!(
            limiter.check_ip_limit(&ip).is_err(),
            "the bucket was recreated, so the limit did not apply"
        );
    }

    #[test]
    fn test_peek_ip_limit_does_not_consume_token() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(10)
            .per_ip_burst(10)
            .build();

        let limiter = RateLimiter::new(config);
        let ip: std::net::IpAddr = "10.0.0.1".parse().unwrap();

        // First consume a token so the bucket exists
        let info = limiter.check_ip_limit(&ip).unwrap();
        let remaining_after_check = info.remaining;

        // Peek should return the same remaining count (no consumption)
        let peek_info = limiter.peek_ip_limit(&ip).expect("bucket should exist");
        assert_eq!(peek_info.remaining, remaining_after_check);

        // Peek again — still no consumption
        let peek_info2 = limiter.peek_ip_limit(&ip).expect("bucket should exist");
        assert_eq!(peek_info2.remaining, remaining_after_check);
    }

    #[test]
    fn test_peek_ip_limit_returns_none_for_unknown_ip() {
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(10)
            .per_ip_burst(10)
            .build();

        let limiter = RateLimiter::new(config);
        let ip: std::net::IpAddr = "10.0.0.99".parse().unwrap();

        // No bucket exists yet
        assert!(limiter.peek_ip_limit(&ip).is_none());
    }
}
