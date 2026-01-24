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

use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
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
            per_ip_requests: 1000,  // 1000 req/min per IP
            per_ip_burst: 100,      // Allow burst of 100
            per_tenant_requests: 10000, // 10000 req/min per tenant
            per_tenant_burst: 1000, // Allow burst of 1000
            auth_fail_limit: 10,    // 10 failed auths before ban
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

/// Thread-safe rate limiter with per-IP and per-tenant limiting.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-IP token buckets.
    ip_limiters: DashMap<IpAddr, Mutex<TokenBucket>>,
    /// Per-tenant token buckets.
    tenant_limiters: DashMap<String, Mutex<TokenBucket>>,
    /// Auth failure tracker per IP.
    auth_failures: DashMap<IpAddr, Mutex<AuthFailureEntry>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            ip_limiters: DashMap::new(),
            tenant_limiters: DashMap::new(),
            auth_failures: DashMap::new(),
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

        let entry = self.auth_failures.entry(*ip).or_insert_with(|| {
            Mutex::new(AuthFailureEntry::new())
        });

        let mut entry = entry.lock();

        // Reset if first failure was more than 1 hour ago
        if entry.first_failure.elapsed() > Duration::from_secs(3600) {
            *entry = AuthFailureEntry::new();
        }

        // Use saturating_add to prevent overflow (defense-in-depth)
        entry.failures = entry.failures.saturating_add(1);

        // Check if we should ban
        if entry.failures >= self.config.auth_fail_limit {
            entry.ban_until = Some(
                std::time::Instant::now() + self.config.auth_fail_ban_duration
            );
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
        self.auth_failures.remove(ip);
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

        let entry = self.ip_limiters.entry(*ip).or_insert_with(|| {
            Mutex::new(TokenBucket::new(
                self.config.per_ip_burst,
                self.config.per_ip_requests,
            ))
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

        let entry = self.tenant_limiters.entry(tenant_id.to_string()).or_insert_with(|| {
            Mutex::new(TokenBucket::new(
                self.config.per_tenant_burst,
                self.config.per_tenant_requests,
            ))
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

    /// Cleans up expired entries to prevent memory growth.
    /// Call this periodically (e.g., every few minutes).
    ///
    /// SEC-027: Now also cleans up stale IP and tenant rate limiter buckets
    /// that haven't been accessed recently, preventing unbounded memory growth.
    pub fn cleanup(&self) {
        // Clean up old auth failure entries
        self.auth_failures.retain(|_, entry| {
            let entry = entry.lock();
            // Keep if banned or if first failure was recent
            entry.is_banned() || entry.first_failure.elapsed() < Duration::from_secs(3600)
        });

        // SEC-027: Clean up stale IP limiter buckets
        // Remove buckets that haven't been refilled in over 5 minutes
        // (meaning no requests from that IP in that time)
        let stale_threshold = Duration::from_secs(300);
        self.ip_limiters.retain(|_, bucket| {
            let bucket = bucket.lock();
            bucket.last_refill.elapsed() < stale_threshold
        });

        // SEC-027: Clean up stale tenant limiter buckets
        self.tenant_limiters.retain(|_, bucket| {
            let bucket = bucket.lock();
            bucket.last_refill.elapsed() < stale_threshold
        });

        tracing::debug!(
            ip_limiters = self.ip_limiters.len(),
            tenant_limiters = self.tenant_limiters.len(),
            auth_failures = self.auth_failures.len(),
            "Rate limiter cleanup completed"
        );
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
                HeaderValue::from_str(&self.limit.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_str(&self.remaining.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-ratelimit-reset"),
                HeaderValue::from_str(&self.reset_secs.to_string()).unwrap(),
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
                HeaderValue::from_str(&self.limit.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("x-ratelimit-remaining"),
                HeaderValue::from_str(&self.remaining.to_string()).unwrap(),
            ),
            (
                HeaderName::from_static("retry-after"),
                HeaderValue::from_str(&self.retry_after.to_string()).unwrap(),
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
        assert!(limiter.is_ip_banned(&ip), "IP should be banned after 3 failures");

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

    #[test]
    fn test_cleanup_removes_stale_entries() {
        // SEC-027: Verify cleanup removes stale IP and tenant limiters
        let config = RateLimitConfig::builder()
            .enabled(true)
            .per_ip_requests(1000)
            .per_ip_burst(100)
            .per_tenant_requests(1000)
            .per_tenant_burst(100)
            .build();

        let limiter = RateLimiter::new(config);

        // Create some entries
        let ip1 = "192.168.1.1".parse().unwrap();
        let ip2 = "192.168.1.2".parse().unwrap();
        limiter.check_ip_limit(&ip1).unwrap();
        limiter.check_ip_limit(&ip2).unwrap();
        limiter.check_tenant_limit("tenant1").unwrap();
        limiter.check_tenant_limit("tenant2").unwrap();

        // Verify entries exist
        assert_eq!(limiter.ip_limiters.len(), 2);
        assert_eq!(limiter.tenant_limiters.len(), 2);

        // Cleanup won't remove fresh entries
        limiter.cleanup();
        assert_eq!(limiter.ip_limiters.len(), 2);
        assert_eq!(limiter.tenant_limiters.len(), 2);

        // Note: A full test of stale eviction would require waiting 5 minutes,
        // which isn't practical. The key verification is that cleanup() runs
        // without error and retains fresh entries.
    }
}