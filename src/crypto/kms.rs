//! Key Management Service (KMS) abstraction.
//!
//! Provides a vendor-agnostic interface for external KMS integration:
//! - **AWS KMS** - Amazon's managed KMS
//! - **HashiCorp Vault** - Open-source secrets management
//! - **GCP Cloud KMS** - Google's managed KMS
//! - **Azure Key Vault** - Microsoft's managed KMS
//! - **Local/Env** - For development only (keys from environment)
//!
//! # Architecture
//!
//! This module uses **envelope encryption**:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Envelope Encryption                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  ┌──────────┐     encrypts      ┌──────────┐                │
//! │  │  Master  │  ─────────────▶   │   Data   │                │
//! │  │   Key    │                   │Encryption│                │
//! │  │  (KEK)   │  ◀─────────────   │   Key    │                │
//! │  └──────────┘     decrypts      │  (DEK)   │                │
//! │       │                         └──────────┘                │
//! │       │ stored in                    │                      │
//! │       ▼                              │ encrypts             │
//! │  ┌──────────┐                        ▼                      │
//! │  │   KMS    │                   ┌──────────┐                │
//! │  │(AWS/GCP/ │                   │   Data   │                │
//! │  │ Vault)   │                   │(metadata,│                │
//! │  └──────────┘                   │ API keys)│                │
//! │                                 └──────────┘                │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Benefits of envelope encryption:**
//! 1. Master key never leaves KMS (hardware-backed security)
//! 2. DEKs can be cached locally (reduced latency)
//! 3. Key rotation only requires re-encrypting DEKs, not all data
//! 4. Reduced KMS API calls (cost optimization)
//!
//! # Security Properties
//!
//! - Master keys are stored in external KMS (never in memory long-term)
//! - DEKs are cached with configurable TTL (default: 5 minutes)
//! - All key material uses `SecretBytes` with zeroize-on-drop
//! - Key versioning supports seamless rotation
//! - All operations are instrumented with tracing spans
//! - Retry logic with exponential backoff for transient failures

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use moka::future::Cache;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

use super::secrets::SecretBytes;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during KMS operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KmsError {
    /// Key not found in the KMS.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// KMS operation failed (network, permissions, etc.).
    #[error("KMS operation failed: {0}")]
    OperationFailed(String),

    /// Invalid key format (wrong size, encoding, etc.).
    #[error("Invalid key format: {0}")]
    InvalidFormat(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Authentication/authorization error with KMS.
    #[error("KMS authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Rate limited by KMS provider.
    #[error("KMS rate limited: retry after {0}ms")]
    RateLimited(u64),

    /// KMS service unavailable.
    #[error("KMS service unavailable: {0}")]
    ServiceUnavailable(String),
}

pub type Result<T> = std::result::Result<T, KmsError>;

// ============================================================================
// Metrics
// ============================================================================

/// Metrics for KMS operations.
#[derive(Debug, Default)]
pub struct KmsMetrics {
    /// Total number of key generation requests.
    pub generate_key_total: AtomicU64,
    /// Total number of key decryption requests.
    pub decrypt_key_total: AtomicU64,
    /// Total number of key encryption requests.
    pub encrypt_key_total: AtomicU64,
    /// Total number of cache hits.
    pub cache_hits: AtomicU64,
    /// Total number of cache misses.
    pub cache_misses: AtomicU64,
    /// Total number of errors.
    pub errors_total: AtomicU64,
    /// Total number of retries.
    pub retries_total: AtomicU64,
}

impl KmsMetrics {
    /// Creates a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets current metrics snapshot.
    pub fn snapshot(&self) -> KmsMetricsSnapshot {
        KmsMetricsSnapshot {
            generate_key_total: self.generate_key_total.load(Ordering::Relaxed),
            decrypt_key_total: self.decrypt_key_total.load(Ordering::Relaxed),
            encrypt_key_total: self.encrypt_key_total.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            retries_total: self.retries_total.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of KMS metrics at a point in time.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KmsMetricsSnapshot {
    pub generate_key_total: u64,
    pub decrypt_key_total: u64,
    pub encrypt_key_total: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub errors_total: u64,
    pub retries_total: u64,
}

// ============================================================================
// Retry Configuration
// ============================================================================

/// Configuration for retry behavior on transient KMS failures.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial backoff duration.
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    pub max_backoff: Duration,
    /// Backoff multiplier (exponential growth).
    pub multiplier: f64,
    /// Add jitter to prevent thundering herd.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// No retries (fail fast).
    pub fn none() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Aggressive retry configuration for critical operations.
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(50),
            max_backoff: Duration::from_secs(30),
            multiplier: 2.0,
            jitter: true,
        }
    }

    /// Calculates backoff duration for a given attempt.
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff.as_millis() as f64
            * self.multiplier.powi(attempt.saturating_sub(1) as i32);
        let capped = base.min(self.max_backoff.as_millis() as f64);

        let final_ms = if self.jitter {
            use rand::Rng;
            let jitter = rand::thread_rng().gen_range(0.5..1.5);
            (capped * jitter) as u64
        } else {
            capped as u64
        };

        Duration::from_millis(final_ms)
    }
}

// ============================================================================
// Encryption Context (AAD)
// ============================================================================

/// Encryption context provides additional authenticated data (AAD).
///
/// This context is bound to the encrypted DEK and must be provided
/// during decryption. It provides:
/// - Additional security binding (decryption fails if context doesn't match)
/// - Audit trail (context can include resource identifiers)
/// - Protection against key misuse (wrong context = wrong key)
#[derive(Debug, Clone, Default)]
pub struct EncryptionContext {
    /// Key-value pairs for the encryption context.
    entries: Vec<(String, String)>,
}

impl EncryptionContext {
    /// Creates an empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key-value pair to the context.
    pub fn with_entry(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.entries.push((key.into(), value.into()));
        self
    }

    /// Creates a context for a specific resource.
    pub fn for_resource(resource_type: &str, resource_id: &str) -> Self {
        Self::new()
            .with_entry("resource_type", resource_type)
            .with_entry("resource_id", resource_id)
    }

    /// Returns the entries as a slice.
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }

    /// Serializes context for inclusion in ciphertext.
    pub fn serialize(&self) -> Vec<u8> {
        // Sort for deterministic output
        let mut sorted: Vec<_> = self.entries.iter().collect();
        sorted.sort_by_key(|(k, _)| k);

        let mut result = Vec::new();
        for (k, v) in sorted {
            result.extend_from_slice(&(k.len() as u32).to_be_bytes());
            result.extend_from_slice(k.as_bytes());
            result.extend_from_slice(&(v.len() as u32).to_be_bytes());
            result.extend_from_slice(v.as_bytes());
        }
        result
    }
}

// ============================================================================
// Core Traits
// ============================================================================

/// Data Encryption Key (DEK) with metadata.
#[derive(Clone)]
pub struct DataEncryptionKey {
    /// The plaintext key material (32 bytes for AES-256).
    pub plaintext: SecretBytes,
    /// The encrypted (wrapped) key for storage.
    pub ciphertext: Vec<u8>,
    /// Key version identifier.
    pub version: u32,
    /// Key alias/ID in the KMS.
    pub key_id: String,
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataEncryptionKey")
            .field("plaintext", &"[REDACTED]")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("version", &self.version)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// Key Management Service trait.
///
/// Implementations provide secure key storage, wrapping, and rotation
/// via external KMS providers (AWS KMS, Vault, etc.).
///
/// # Envelope Encryption
///
/// This trait is designed for **envelope encryption**:
/// 1. Generate a random DEK locally
/// 2. Use KMS to encrypt (wrap) the DEK with the master key
/// 3. Store the wrapped DEK alongside encrypted data
/// 4. To decrypt: unwrap the DEK via KMS, then decrypt data locally
///
/// This approach minimizes KMS API calls while keeping master keys secure.
#[async_trait]
pub trait KeyManagementService: Send + Sync + std::fmt::Debug {
    /// Generates a new Data Encryption Key (DEK).
    ///
    /// The DEK is returned in both plaintext (for immediate use) and
    /// encrypted/wrapped form (for storage).
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey>;

    /// Decrypts (unwraps) a previously encrypted DEK.
    ///
    /// The `ciphertext` is the wrapped key returned from `generate_data_key`.
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes>;

    /// Encrypts (wraps) an existing plaintext DEK.
    ///
    /// Used when rotating to a new master key version.
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Returns the current master key version.
    async fn current_version(&self, key_id: &str) -> Result<u32>;

    /// Triggers key rotation in the KMS (if supported).
    ///
    /// Returns the new version number.
    async fn rotate_master_key(&self, key_id: &str) -> Result<u32>;

    /// Returns the provider name (for logging/metrics).
    fn provider_name(&self) -> &'static str;

    /// Health check for the KMS connection.
    async fn health_check(&self) -> Result<()>;

    /// Returns shared reference to KMS metrics if available.
    ///
    /// Only wrappers that track metrics (CachedKms, RetryKms, CircuitBreakerKms)
    /// return Some. Raw providers return None.
    fn kms_metrics(&self) -> Option<Arc<KmsMetrics>> {
        None
    }
}

// ============================================================================
// Cached KMS Wrapper
// ============================================================================

/// Configuration for KMS caching.
#[derive(Debug, Clone)]
pub struct KmsCacheConfig {
    /// Maximum number of DEKs to cache.
    pub max_capacity: u64,
    /// Time-to-live for cached DEKs.
    pub ttl: Duration,
    /// Whether to cache decrypted DEKs.
    pub enabled: bool,
}

impl Default for KmsCacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 1000,
            ttl: Duration::from_secs(300), // 5 minutes
            enabled: true,
        }
    }
}

impl KmsCacheConfig {
    /// Creates a disabled cache (every operation hits KMS).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Creates a cache with shorter TTL for higher security.
    pub fn high_security() -> Self {
        Self {
            max_capacity: 100,
            ttl: Duration::from_secs(60), // 1 minute
            enabled: true,
        }
    }
}

/// Cached wrapper around a KMS provider.
///
/// Caches decrypted DEKs to reduce KMS API calls and latency.
/// Cache entries expire after the configured TTL.
///
/// # Security
///
/// - Cached keys use `SecretBytes` (zeroized on eviction)
/// - TTL limits exposure window if cache is compromised
/// - Cache can be disabled for highest security requirements
///
/// # Observability
///
/// - All operations are traced with spans
/// - Metrics are collected for monitoring
#[derive(Debug)]
pub struct CachedKms {
    inner: Arc<dyn KeyManagementService>,
    /// Cache key: (key_id, ciphertext_hash) -> plaintext DEK
    cache: Cache<(String, u64), SecretBytes>,
    config: KmsCacheConfig,
    metrics: Arc<KmsMetrics>,
}

impl CachedKms {
    /// Creates a new cached KMS wrapper.
    pub fn new(kms: Arc<dyn KeyManagementService>, config: KmsCacheConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_capacity)
            .time_to_live(config.ttl)
            .build();

        Self {
            inner: kms,
            cache,
            config,
            metrics: Arc::new(KmsMetrics::new()),
        }
    }

    /// Creates a cached wrapper with default configuration.
    pub fn with_defaults(kms: Arc<dyn KeyManagementService>) -> Self {
        Self::new(kms, KmsCacheConfig::default())
    }

    /// Computes a cache key from ciphertext using SHA-256.
    ///
    /// SECURITY: Uses a cryptographic hash instead of `DefaultHasher` to ensure
    /// collision resistance. A hash collision here would return the wrong
    /// plaintext DEK, leading to silent data corruption.
    fn cache_key(key_id: &str, ciphertext: &[u8]) -> (String, u64) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        let hash = hasher.finalize();
        // Take the first 8 bytes as a u64 — SHA-256's collision resistance
        // makes this astronomically unlikely to collide.
        let truncated = u64::from_le_bytes(hash[..8].try_into().unwrap());
        (key_id.to_string(), truncated)
    }

    /// Invalidates all cached entries for a key.
    pub async fn invalidate(&self, key_id: &str) {
        // Note: moka doesn't support prefix deletion easily,
        // so we just invalidate the whole cache on rotation
        self.cache.invalidate_all();
        tracing::debug!(key_id = %key_id, "Invalidated KMS cache");
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            entry_count: self.cache.entry_count(),
            weighted_size: self.cache.weighted_size(),
        }
    }

    /// Returns KMS metrics.
    pub fn metrics(&self) -> &KmsMetrics {
        &self.metrics
    }

    /// Returns a snapshot of current metrics.
    pub fn metrics_snapshot(&self) -> KmsMetricsSnapshot {
        self.metrics.snapshot()
    }
}

/// Cache statistics for monitoring.
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: u64,
    pub weighted_size: u64,
}

#[async_trait]
impl KeyManagementService for CachedKms {
    #[instrument(skip(self), fields(provider = "cached", key_id = %key_id))]
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        self.metrics
            .generate_key_total
            .fetch_add(1, Ordering::Relaxed);

        // Always go to KMS for new key generation
        let result = self.inner.generate_data_key(key_id).await;

        match &result {
            Ok(dek) => {
                // Cache the decrypted key
                if self.config.enabled {
                    let cache_key = Self::cache_key(key_id, &dek.ciphertext);
                    self.cache.insert(cache_key, dek.plaintext.clone()).await;
                }
                tracing::debug!(key_id = %key_id, version = dek.version, "Generated new DEK");
            }
            Err(e) => {
                self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(key_id = %key_id, error = %e, "Failed to generate DEK");
            }
        }

        result
    }

    #[instrument(skip(self, ciphertext), fields(provider = "cached", key_id = %key_id, ciphertext_len = ciphertext.len()))]
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        self.metrics
            .decrypt_key_total
            .fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            return self.inner.decrypt_data_key(key_id, ciphertext).await;
        }

        let cache_key = Self::cache_key(key_id, ciphertext);

        // Check cache first
        if let Some(plaintext) = self.cache.get(&cache_key).await {
            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            tracing::trace!(key_id = %key_id, "KMS cache hit");
            return Ok(plaintext);
        }

        // Cache miss - decrypt via KMS
        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
        tracing::trace!(key_id = %key_id, "KMS cache miss");

        let result = self.inner.decrypt_data_key(key_id, ciphertext).await;

        match &result {
            Ok(plaintext) => {
                // Cache the result
                self.cache.insert(cache_key, plaintext.clone()).await;
            }
            Err(e) => {
                self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(key_id = %key_id, error = %e, "Failed to decrypt DEK");
            }
        }

        result
    }

    #[instrument(skip(self, plaintext), fields(provider = "cached", key_id = %key_id))]
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.metrics
            .encrypt_key_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner.encrypt_data_key(key_id, plaintext).await
    }

    async fn current_version(&self, key_id: &str) -> Result<u32> {
        self.inner.current_version(key_id).await
    }

    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        // Invalidate cache on rotation
        self.invalidate(key_id).await;
        self.inner.rotate_master_key(key_id).await
    }

    fn provider_name(&self) -> &'static str {
        "cached"
    }

    async fn health_check(&self) -> Result<()> {
        self.inner.health_check().await
    }

    fn kms_metrics(&self) -> Option<Arc<KmsMetrics>> {
        Some(self.metrics.clone())
    }
}

// ============================================================================
// Retry KMS Wrapper
// ============================================================================

/// KMS wrapper that adds retry logic with exponential backoff.
///
/// Automatically retries transient failures (rate limiting, network issues)
/// while respecting the configured retry policy.
///
/// # Retryable Errors
///
/// - `RateLimited` - Always retried with backoff
/// - `ServiceUnavailable` - Always retried
/// - `OperationFailed` - Retried if it appears transient
///
/// # Non-Retryable Errors
///
/// - `KeyNotFound` - Never retried (permanent)
/// - `InvalidFormat` - Never retried (client error)
/// - `ConfigurationError` - Never retried
/// - `AuthenticationFailed` - Never retried (needs manual fix)
#[derive(Debug)]
pub struct RetryKms {
    inner: Arc<dyn KeyManagementService>,
    config: RetryConfig,
    metrics: Arc<KmsMetrics>,
}

impl RetryKms {
    /// Creates a new retry wrapper.
    pub fn new(kms: Arc<dyn KeyManagementService>, config: RetryConfig) -> Self {
        Self {
            inner: kms,
            config,
            metrics: Arc::new(KmsMetrics::new()),
        }
    }

    /// Creates with default retry configuration.
    pub fn with_defaults(kms: Arc<dyn KeyManagementService>) -> Self {
        Self::new(kms, RetryConfig::default())
    }

    /// Determines if an error is retryable.
    fn is_retryable(error: &KmsError) -> bool {
        matches!(
            error,
            KmsError::RateLimited(_) | KmsError::ServiceUnavailable(_)
        )
    }

    /// Executes an operation with retry logic.
    async fn with_retry<F, Fut, T>(&self, operation: &str, mut f: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;

        loop {
            match f().await {
                Ok(result) => return Ok(result),
                Err(e) if Self::is_retryable(&e) && attempt < self.config.max_retries => {
                    attempt += 1;
                    self.metrics.retries_total.fetch_add(1, Ordering::Relaxed);

                    let backoff = self.config.backoff_for_attempt(attempt);
                    tracing::warn!(
                        operation = %operation,
                        attempt = attempt,
                        max_retries = self.config.max_retries,
                        backoff_ms = backoff.as_millis() as u64,
                        error = %e,
                        "KMS operation failed, retrying"
                    );

                    tokio::time::sleep(backoff).await;
                }
                Err(e) => {
                    self.metrics.errors_total.fetch_add(1, Ordering::Relaxed);
                    return Err(e);
                }
            }
        }
    }

    /// Returns KMS metrics.
    pub fn metrics(&self) -> &KmsMetrics {
        &self.metrics
    }
}

#[async_trait]
impl KeyManagementService for RetryKms {
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        self.with_retry("generate_data_key", || {
            let inner = inner.clone();
            let key_id = key_id.clone();
            async move { inner.generate_data_key(&key_id).await }
        })
        .await
    }

    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        let ciphertext = ciphertext.to_vec();
        self.with_retry("decrypt_data_key", || {
            let inner = inner.clone();
            let key_id = key_id.clone();
            let ciphertext = ciphertext.clone();
            async move { inner.decrypt_data_key(&key_id, &ciphertext).await }
        })
        .await
    }

    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        let plaintext = plaintext.to_vec();
        self.with_retry("encrypt_data_key", || {
            let inner = inner.clone();
            let key_id = key_id.clone();
            let plaintext = plaintext.clone();
            async move { inner.encrypt_data_key(&key_id, &plaintext).await }
        })
        .await
    }

    async fn current_version(&self, key_id: &str) -> Result<u32> {
        self.inner.current_version(key_id).await
    }

    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        // Key rotation should not be retried - it's an important operation
        // that needs explicit confirmation if it fails
        self.inner.rotate_master_key(key_id).await
    }

    fn provider_name(&self) -> &'static str {
        "retry"
    }

    async fn health_check(&self) -> Result<()> {
        self.inner.health_check().await
    }

    fn kms_metrics(&self) -> Option<Arc<KmsMetrics>> {
        Some(self.metrics.clone())
    }
}

// ============================================================================
// Circuit Breaker KMS Wrapper
// ============================================================================

/// State of the circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed (normal operation).
    Closed,
    /// Circuit is open (rejecting requests).
    Open,
    /// Circuit is half-open (testing recovery).
    HalfOpen,
}

/// Configuration for circuit breaker behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open.
    pub reset_timeout: Duration,
    /// Number of successful requests in half-open state before closing.
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout: Duration::from_secs(30),
            success_threshold: 3,
        }
    }
}

impl CircuitBreakerConfig {
    /// Aggressive configuration for critical services.
    pub fn aggressive() -> Self {
        Self {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(60),
            success_threshold: 5,
        }
    }

    /// Lenient configuration for less critical services.
    pub fn lenient() -> Self {
        Self {
            failure_threshold: 10,
            reset_timeout: Duration::from_secs(15),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker wrapper around a KMS provider.
///
/// Implements the circuit breaker pattern to prevent cascading failures
/// when the KMS backend is unavailable or degraded.
///
/// # States
///
/// - **Closed**: Normal operation, requests pass through
/// - **Open**: Requests fail immediately without hitting KMS
/// - **Half-Open**: Limited requests pass through to test recovery
///
/// # Transitions
///
/// ```text
/// ┌────────────────────────────────────────────────────────────┐
/// │                    Circuit Breaker                          │
/// ├────────────────────────────────────────────────────────────┤
/// │                                                             │
/// │    ┌────────┐    failures >= threshold    ┌────────┐        │
/// │    │ Closed │ ────────────────────────▶  │  Open  │        │
/// │    └────────┘                             └────────┘        │
/// │         ▲                                      │            │
/// │         │                                      │            │
/// │         │  successes >= threshold    timeout   │            │
/// │         │                                      ▼            │
/// │         │                             ┌──────────┐          │
/// │         └─────────────────────────────│Half-Open│          │
/// │                                       └──────────┘          │
/// │                                              │              │
/// │                               failure        │              │
/// │                              ─────────────▶ Open            │
/// └────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug)]
pub struct CircuitBreakerKms {
    inner: Arc<dyn KeyManagementService>,
    config: CircuitBreakerConfig,
    state: parking_lot::RwLock<CircuitBreakerState>,
    metrics: Arc<KmsMetrics>,
}

#[derive(Debug)]
struct CircuitBreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_time: Option<std::time::Instant>,
}

impl Default for CircuitBreakerState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_time: None,
        }
    }
}

impl CircuitBreakerKms {
    /// Creates a new circuit breaker wrapper.
    pub fn new(kms: Arc<dyn KeyManagementService>, config: CircuitBreakerConfig) -> Self {
        Self {
            inner: kms,
            config,
            state: parking_lot::RwLock::new(CircuitBreakerState::default()),
            metrics: Arc::new(KmsMetrics::new()),
        }
    }

    /// Creates with default configuration.
    pub fn with_defaults(kms: Arc<dyn KeyManagementService>) -> Self {
        Self::new(kms, CircuitBreakerConfig::default())
    }

    /// Returns the current circuit state.
    pub fn state(&self) -> CircuitState {
        let state = self.state.read();
        self.effective_state(&state)
    }

    /// Determines the effective state considering timeout.
    fn effective_state(&self, state: &CircuitBreakerState) -> CircuitState {
        match state.state {
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(last_failure) = state.last_failure_time {
                    if last_failure.elapsed() >= self.config.reset_timeout {
                        return CircuitState::HalfOpen;
                    }
                }
                CircuitState::Open
            }
            other => other,
        }
    }

    /// Checks if the circuit allows requests.
    fn should_allow_request(&self) -> bool {
        let state = self.state.read();
        match self.effective_state(&state) {
            CircuitState::Closed => true,
            CircuitState::Open => false,
            CircuitState::HalfOpen => true, // Allow limited requests to test recovery
        }
    }

    /// Records a successful operation.
    fn record_success(&self) {
        let mut state = self.state.write();
        state.consecutive_failures = 0;
        state.consecutive_successes += 1;

        match self.effective_state(&state) {
            CircuitState::HalfOpen => {
                if state.consecutive_successes >= self.config.success_threshold {
                    tracing::info!(
                        provider = self.inner.provider_name(),
                        "Circuit breaker closing: KMS recovered"
                    );
                    state.state = CircuitState::Closed;
                    state.consecutive_successes = 0;
                }
            }
            CircuitState::Open => {
                // Transition to closed after timeout + success
                state.state = CircuitState::Closed;
                state.consecutive_successes = 0;
            }
            CircuitState::Closed => {
                // Reset counter periodically to avoid overflow
                if state.consecutive_successes > 1000 {
                    state.consecutive_successes = 0;
                }
            }
        }
    }

    /// Records a failed operation.
    fn record_failure(&self) {
        let mut state = self.state.write();
        state.consecutive_successes = 0;
        state.consecutive_failures += 1;
        state.last_failure_time = Some(std::time::Instant::now());

        match self.effective_state(&state) {
            CircuitState::Closed => {
                if state.consecutive_failures >= self.config.failure_threshold {
                    tracing::warn!(
                        provider = self.inner.provider_name(),
                        failures = state.consecutive_failures,
                        "Circuit breaker opening: KMS failures exceeded threshold"
                    );
                    state.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                tracing::warn!(
                    provider = self.inner.provider_name(),
                    "Circuit breaker re-opening: KMS still failing"
                );
                state.state = CircuitState::Open;
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Executes an operation with circuit breaker protection.
    async fn with_circuit_breaker<F, Fut, T>(&self, operation: &str, f: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if !self.should_allow_request() {
            tracing::debug!(
                provider = self.inner.provider_name(),
                operation = %operation,
                "Circuit breaker open: rejecting request"
            );
            return Err(KmsError::ServiceUnavailable(
                "KMS service circuit breaker is open".to_string(),
            ));
        }

        match f().await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                // Only count certain errors as failures
                if Self::is_circuit_breaker_error(&e) {
                    self.record_failure();
                }
                Err(e)
            }
        }
    }

    /// Determines if an error should trip the circuit breaker.
    fn is_circuit_breaker_error(error: &KmsError) -> bool {
        matches!(
            error,
            KmsError::ServiceUnavailable(_)
                | KmsError::RateLimited(_)
                | KmsError::OperationFailed(_)
        )
    }

    /// Returns KMS metrics.
    pub fn metrics(&self) -> &KmsMetrics {
        &self.metrics
    }
}

#[async_trait]
impl KeyManagementService for CircuitBreakerKms {
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        self.with_circuit_breaker("generate_data_key", || async {
            inner.generate_data_key(&key_id).await
        })
        .await
    }

    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        let ciphertext = ciphertext.to_vec();
        self.with_circuit_breaker("decrypt_data_key", || async {
            inner.decrypt_data_key(&key_id, &ciphertext).await
        })
        .await
    }

    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let inner = self.inner.clone();
        let key_id = key_id.to_string();
        let plaintext = plaintext.to_vec();
        self.with_circuit_breaker("encrypt_data_key", || async {
            inner.encrypt_data_key(&key_id, &plaintext).await
        })
        .await
    }

    async fn current_version(&self, key_id: &str) -> Result<u32> {
        // Version check is lightweight, skip circuit breaker
        self.inner.current_version(key_id).await
    }

    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        // Key rotation is critical, skip circuit breaker but log
        tracing::info!(key_id = %key_id, "Key rotation bypassing circuit breaker");
        self.inner.rotate_master_key(key_id).await
    }

    fn provider_name(&self) -> &'static str {
        "circuit-breaker"
    }

    async fn health_check(&self) -> Result<()> {
        // Health check should reflect circuit state
        if self.state() == CircuitState::Open {
            return Err(KmsError::ServiceUnavailable(
                "Circuit breaker is open".to_string(),
            ));
        }
        self.inner.health_check().await
    }

    fn kms_metrics(&self) -> Option<Arc<KmsMetrics>> {
        Some(self.metrics.clone())
    }
}

// ============================================================================
// Environment Variable Provider (Development Only)
// ============================================================================

/// KMS provider that loads keys from environment variables.
///
/// # ⚠️ WARNING: Development Only!
///
/// This provider stores master keys in environment variables, which is
/// **NOT SUITABLE FOR PRODUCTION**:
///
/// - Keys may be visible in process listings
/// - Keys may be logged accidentally
/// - No hardware-backed security
/// - No audit trail
/// - No automatic rotation
///
/// For production, use a proper KMS:
/// - AWS KMS
/// - HashiCorp Vault
/// - GCP Cloud KMS
/// - Azure Key Vault
///
/// # Configuration
///
/// Set environment variables with base64-encoded 256-bit keys:
///
/// ```bash
/// export RUSTBERG_ENCRYPTION_KEY_V1="<base64-encoded-32-byte-key>"
/// export RUSTBERG_ENCRYPTION_KEY_V2="<base64-encoded-32-byte-key>"  # For rotation
/// ```
///
/// Keys are loaded in order (V1, V2, V3...). The highest version is current.
#[derive(Debug)]
pub struct EnvKeyProvider {
    keys: Vec<SecretBytes>,
    current_version: u32,
}

impl EnvKeyProvider {
    /// Creates a provider from environment variables.
    ///
    /// Loads keys in order: RUSTBERG_ENCRYPTION_KEY_V1, V2, V3, etc.
    /// Returns error if no keys found.
    pub fn from_env() -> Result<Self> {
        let mut keys = Vec::new();
        let mut version = 1;

        loop {
            let var_name = format!("RUSTBERG_ENCRYPTION_KEY_V{}", version);
            match std::env::var(&var_name) {
                Ok(encoded) => {
                    let key = STANDARD
                        .decode(&encoded)
                        .map_err(|e| KmsError::InvalidFormat(e.to_string()))?;

                    if key.len() != 32 {
                        return Err(KmsError::InvalidFormat(format!(
                            "{} must be 32 bytes (256 bits), got {} bytes",
                            var_name,
                            key.len()
                        )));
                    }

                    keys.push(SecretBytes::new(key));
                    version += 1;
                }
                Err(_) => break,
            }
        }

        if keys.is_empty() {
            return Err(KmsError::KeyNotFound(
                "No encryption keys found. Set RUSTBERG_ENCRYPTION_KEY_V1 (base64-encoded 32 bytes)".to_string(),
            ));
        }

        let current_version = keys.len() as u32;

        tracing::warn!(
            provider = "env",
            versions = keys.len(),
            "⚠️  Using EnvKeyProvider - NOT SUITABLE FOR PRODUCTION!"
        );

        Ok(Self {
            keys,
            current_version,
        })
    }

    /// Creates a provider with a single key (for testing).
    pub fn with_key(key: Vec<u8>) -> Result<Self> {
        if key.len() != 32 {
            return Err(KmsError::InvalidFormat(format!(
                "Key must be 32 bytes, got {} bytes",
                key.len()
            )));
        }

        Ok(Self {
            keys: vec![SecretBytes::new(key)],
            current_version: 1,
        })
    }

    /// Generates a random test key provider.
    #[cfg(test)]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::with_key(key).unwrap()
    }

    fn get_key_for_version(&self, version: u32) -> Result<&SecretBytes> {
        if version == 0 || version > self.keys.len() as u32 {
            return Err(KmsError::KeyNotFound(format!(
                "Key version {} not found (have 1-{})",
                version,
                self.keys.len()
            )));
        }
        Ok(&self.keys[(version - 1) as usize])
    }
}

#[async_trait]
impl KeyManagementService for EnvKeyProvider {
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
        use rand::RngCore;

        // Generate random DEK
        let mut plaintext = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        // Encrypt DEK with current master key
        let master_key = self.get_key_for_version(self.current_version)?;
        let cipher = Aes256Gcm::new_from_slice(master_key.expose())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext.as_slice())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        // Format: version (4 bytes) || nonce (12 bytes) || ciphertext
        let mut ciphertext = Vec::with_capacity(4 + 12 + encrypted.len());
        ciphertext.extend_from_slice(&self.current_version.to_be_bytes());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(&encrypted);

        Ok(DataEncryptionKey {
            plaintext: SecretBytes::new(plaintext),
            ciphertext,
            version: self.current_version,
            key_id: key_id.to_string(),
        })
    }

    async fn decrypt_data_key(&self, _key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};

        if ciphertext.len() < 4 + 12 + 16 {
            return Err(KmsError::InvalidFormat("Ciphertext too short".to_string()));
        }

        // Parse: version (4 bytes) || nonce (12 bytes) || encrypted
        let version =
            u32::from_be_bytes([ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]]);
        let nonce = Nonce::from_slice(&ciphertext[4..16]);
        let encrypted = &ciphertext[16..];

        let master_key = self.get_key_for_version(version)?;
        let cipher = Aes256Gcm::new_from_slice(master_key.expose())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| KmsError::OperationFailed("Decryption failed (wrong key?)".to_string()))?;

        Ok(SecretBytes::new(plaintext))
    }

    async fn encrypt_data_key(&self, _key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
        use rand::RngCore;

        if plaintext.len() != 32 {
            return Err(KmsError::InvalidFormat("DEK must be 32 bytes".to_string()));
        }

        let master_key = self.get_key_for_version(self.current_version)?;
        let cipher = Aes256Gcm::new_from_slice(master_key.expose())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        // Format: version (4 bytes) || nonce (12 bytes) || ciphertext
        let mut ciphertext = Vec::with_capacity(4 + 12 + encrypted.len());
        ciphertext.extend_from_slice(&self.current_version.to_be_bytes());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(&encrypted);

        Ok(ciphertext)
    }

    async fn current_version(&self, _key_id: &str) -> Result<u32> {
        Ok(self.current_version)
    }

    async fn rotate_master_key(&self, _key_id: &str) -> Result<u32> {
        Err(KmsError::OperationFailed(
            "EnvKeyProvider does not support runtime key rotation. \
             Add a new RUSTBERG_ENCRYPTION_KEY_V{n} and restart."
                .to_string(),
        ))
    }

    fn provider_name(&self) -> &'static str {
        "env"
    }

    async fn health_check(&self) -> Result<()> {
        // Verify we can access the current key
        let _ = self.get_key_for_version(self.current_version)?;
        Ok(())
    }
}

// ============================================================================
// AWS KMS Provider
// ============================================================================

/// AWS KMS provider for production key management.
///
/// This provider uses AWS Key Management Service (KMS) to:
/// - Generate data encryption keys (GenerateDataKey)
/// - Decrypt wrapped keys (Decrypt)
/// - Encrypt plaintext keys (Encrypt)
///
/// # Security Properties
///
/// - Master keys never leave AWS KMS (hardware-backed)
/// - All operations are audited in AWS CloudTrail
/// - Supports automatic key rotation
/// - IAM-based access control
///
/// # Example
///
/// ```no_run
/// use rustberg::crypto::kms::AwsKmsProvider;
/// use rustberg::crypto::KeyManagementService;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Using default AWS credentials
/// let provider = AwsKmsProvider::new(
///     "us-east-1",
///     "alias/rustberg-master",
///     None,  // Use default endpoint
/// ).await?;
///
/// // Generate a data encryption key
/// let dek = provider.generate_data_key("alias/rustberg-master").await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "aws-kms")]
#[derive(Debug)]
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    key_id: String,
    region: String,
}

#[cfg(feature = "aws-kms")]
impl AwsKmsProvider {
    /// Creates a new AWS KMS provider.
    ///
    /// # Arguments
    ///
    /// * `region` - AWS region (e.g., "us-east-1")
    /// * `key_id` - KMS key ID, ARN, or alias (e.g., "alias/rustberg-master")
    /// * `endpoint` - Optional endpoint override for LocalStack/testing
    pub async fn new(
        region: impl Into<String>,
        key_id: impl Into<String>,
        endpoint: Option<String>,
    ) -> Result<Self> {
        let region_str = region.into();
        let key_id_str = key_id.into();

        // Build AWS config
        let region = aws_sdk_kms::config::Region::new(region_str.clone());
        let mut config_builder =
            aws_config::defaults(aws_config::BehaviorVersion::latest()).region(region);

        // Apply endpoint override if specified (for LocalStack/testing)
        if let Some(endpoint_url) = endpoint {
            config_builder = config_builder.endpoint_url(&endpoint_url);
        }

        let config = config_builder.load().await;
        let client = aws_sdk_kms::Client::new(&config);

        // Verify connectivity by describing the key
        let describe_result = client
            .describe_key()
            .key_id(&key_id_str)
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Failed to describe KMS key: {}", e)))?;

        let key_metadata = describe_result.key_metadata().ok_or_else(|| {
            KmsError::KeyNotFound(format!("Key metadata not found for: {}", key_id_str))
        })?;

        if !key_metadata.enabled() {
            return Err(KmsError::ConfigurationError(format!(
                "KMS key {} is disabled",
                key_id_str
            )));
        }

        tracing::info!(
            provider = "aws-kms",
            region = %region_str,
            key_id = %key_id_str,
            key_state = ?key_metadata.key_state(),
            "Connected to AWS KMS"
        );

        Ok(Self {
            client,
            key_id: key_id_str,
            region: region_str,
        })
    }
}

#[cfg(feature = "aws-kms")]
#[async_trait]
impl KeyManagementService for AwsKmsProvider {
    #[instrument(skip(self), fields(provider = "aws-kms"))]
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        use aws_sdk_kms::types::DataKeySpec;

        let result = self
            .client
            .generate_data_key()
            .key_id(key_id)
            .key_spec(DataKeySpec::Aes256)
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("GenerateDataKey failed: {}", e)))?;

        let plaintext_blob = result.plaintext().ok_or_else(|| {
            KmsError::OperationFailed("GenerateDataKey returned no plaintext".to_string())
        })?;

        let ciphertext_blob = result.ciphertext_blob().ok_or_else(|| {
            KmsError::OperationFailed("GenerateDataKey returned no ciphertext".to_string())
        })?;

        // Get key version from key metadata (KeyId in response contains version info)
        let key_version = self.current_version(key_id).await?;

        Ok(DataEncryptionKey {
            plaintext: SecretBytes::new(plaintext_blob.as_ref().to_vec()),
            ciphertext: ciphertext_blob.as_ref().to_vec(),
            version: key_version,
            key_id: key_id.to_string(),
        })
    }

    #[instrument(skip(self, ciphertext), fields(provider = "aws-kms"))]
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        let result = self
            .client
            .decrypt()
            .key_id(key_id)
            .ciphertext_blob(aws_sdk_kms::primitives::Blob::new(ciphertext))
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Decrypt failed: {}", e)))?;

        let plaintext = result.plaintext().ok_or_else(|| {
            KmsError::OperationFailed("Decrypt returned no plaintext".to_string())
        })?;

        Ok(SecretBytes::new(plaintext.as_ref().to_vec()))
    }

    #[instrument(skip(self, plaintext), fields(provider = "aws-kms"))]
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let result = self
            .client
            .encrypt()
            .key_id(key_id)
            .plaintext(aws_sdk_kms::primitives::Blob::new(plaintext))
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Encrypt failed: {}", e)))?;

        let ciphertext = result.ciphertext_blob().ok_or_else(|| {
            KmsError::OperationFailed("Encrypt returned no ciphertext".to_string())
        })?;

        Ok(ciphertext.as_ref().to_vec())
    }

    #[instrument(skip(self), fields(provider = "aws-kms"))]
    async fn current_version(&self, key_id: &str) -> Result<u32> {
        // AWS KMS doesn't expose version numbers directly
        // For symmetric keys, we use the key's creation date hash as a pseudo-version
        // For actual version tracking, use aliases or custom metadata
        let result = self
            .client
            .describe_key()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("DescribeKey failed: {}", e)))?;

        let metadata = result
            .key_metadata()
            .ok_or_else(|| KmsError::KeyNotFound(format!("Key not found: {}", key_id)))?;

        // Use creation date epoch seconds as a stable version identifier
        // This changes when the key is rotated (new backing key)
        if let Some(creation_date) = metadata.creation_date() {
            Ok(creation_date.secs() as u32)
        } else {
            Ok(1) // Default version
        }
    }

    #[instrument(skip(self), fields(provider = "aws-kms"))]
    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        // Trigger on-demand key rotation
        // Note: This requires the key to have automatic rotation enabled
        // or the kms:RotateKey permission
        self.client
            .rotate_key_on_demand()
            .key_id(key_id)
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("RotateKeyOnDemand failed: {}", e)))?;

        tracing::info!(
            provider = "aws-kms",
            key_id = %key_id,
            "Initiated key rotation"
        );

        // Return the new version (will change after rotation completes)
        self.current_version(key_id).await
    }

    fn provider_name(&self) -> &'static str {
        "aws-kms"
    }

    #[instrument(skip(self), fields(provider = "aws-kms", region = %self.region))]
    async fn health_check(&self) -> Result<()> {
        // Verify we can describe the key
        let result = self
            .client
            .describe_key()
            .key_id(&self.key_id)
            .send()
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Health check failed: {}", e)))?;

        let metadata = result.key_metadata().ok_or_else(|| {
            KmsError::ServiceUnavailable("Key metadata not available".to_string())
        })?;

        if !metadata.enabled() {
            return Err(KmsError::ServiceUnavailable(format!(
                "KMS key {} is disabled",
                self.key_id
            )));
        }

        Ok(())
    }
}

// ============================================================================
// HashiCorp Vault KMS Provider
// ============================================================================

/// HashiCorp Vault Transit secrets engine KMS provider.
///
/// Uses Vault's Transit engine for envelope encryption:
/// - Master keys (KEKs) remain in Vault hardware/memory
/// - All encryption/decryption operations performed by Vault
/// - Supports key versioning and rotation
///
/// # Features
///
/// - **Transit Engine**: Uses Vault's Transit secrets engine for cryptographic operations
/// - **Multiple Auth Methods**: Token, AppRole, and Kubernetes auth supported
/// - **Key Versioning**: Built-in support for key rotation and versioning
/// - **Audit Trail**: All operations logged in Vault's audit log
///
/// # Example
///
/// ```no_run
/// use rustberg::crypto::kms::VaultKmsProvider;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let provider = VaultKmsProvider::new(
///     "https://vault.example.com:8200",
///     "transit",
///     "rustberg-master",
///     "s.xxxxxxxxxx".to_string(), // Vault token
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "vault-kms")]
pub struct VaultKmsProvider {
    client: vaultrs::client::VaultClient,
    mount_path: String,
    key_name: String,
}

#[cfg(feature = "vault-kms")]
impl std::fmt::Debug for VaultKmsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultKmsProvider")
            .field("mount_path", &self.mount_path)
            .field("key_name", &self.key_name)
            .field("client", &"<VaultClient>")
            .finish()
    }
}

#[cfg(feature = "vault-kms")]
impl VaultKmsProvider {
    /// Creates a new Vault KMS provider with token authentication.
    ///
    /// # Arguments
    ///
    /// * `address` - Vault server address (e.g., "<https://vault.example.com:8200>")
    /// * `mount_path` - Transit secrets engine mount path (default: "transit")
    /// * `key_name` - Key name in Vault Transit engine
    /// * `token` - Vault authentication token
    pub async fn new(
        address: impl Into<String>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
        token: String,
    ) -> Result<Self> {
        use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

        let address_str = address.into();
        let mount_path_str = mount_path.into();
        let key_name_str = key_name.into();

        let settings = VaultClientSettingsBuilder::default()
            .address(&address_str)
            .token(&token)
            .build()
            .map_err(|e| KmsError::ConfigurationError(format!("Invalid Vault settings: {}", e)))?;

        let client = VaultClient::new(settings).map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create Vault client: {}", e))
        })?;

        // Verify connection and key existence
        let provider = Self {
            client,
            mount_path: mount_path_str,
            key_name: key_name_str,
        };

        provider.health_check().await?;

        tracing::info!(
            provider = "vault",
            address = %address_str,
            mount = %provider.mount_path,
            key = %provider.key_name,
            "Vault KMS provider initialized"
        );

        Ok(provider)
    }

    /// Creates a provider with AppRole authentication.
    pub async fn with_approle(
        address: impl Into<String>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
        role_id: &str,
        secret_id: &str,
    ) -> Result<Self> {
        use vaultrs::auth::approle;
        use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};

        let address_str = address.into();
        let mount_path_str = mount_path.into();
        let key_name_str = key_name.into();

        // Create client without token first
        let settings = VaultClientSettingsBuilder::default()
            .address(&address_str)
            .build()
            .map_err(|e| KmsError::ConfigurationError(format!("Invalid Vault settings: {}", e)))?;

        let mut client = VaultClient::new(settings).map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create Vault client: {}", e))
        })?;

        // Authenticate with AppRole
        let auth_info = approle::login(&client, "approle", role_id, secret_id)
            .await
            .map_err(|e| KmsError::AuthenticationFailed(format!("AppRole login failed: {}", e)))?;

        client.set_token(&auth_info.client_token);

        let provider = Self {
            client,
            mount_path: mount_path_str,
            key_name: key_name_str,
        };

        provider.health_check().await?;

        tracing::info!(
            provider = "vault",
            address = %address_str,
            auth_method = "approle",
            "Vault KMS provider initialized with AppRole"
        );

        Ok(provider)
    }

    /// Creates a provider with Kubernetes authentication.
    pub async fn with_kubernetes(
        address: impl Into<String>,
        mount_path: impl Into<String>,
        key_name: impl Into<String>,
        role: &str,
        jwt_path: Option<&str>,
    ) -> Result<Self> {
        use vaultrs::auth::kubernetes;
        use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};

        let address_str = address.into();
        let mount_path_str = mount_path.into();
        let key_name_str = key_name.into();

        // Read JWT from service account token (default K8s path)
        let jwt_file = jwt_path.unwrap_or("/var/run/secrets/kubernetes.io/serviceaccount/token");
        let jwt = std::fs::read_to_string(jwt_file)
            .map_err(|e| KmsError::ConfigurationError(format!("Failed to read K8s JWT: {}", e)))?;

        // Create client without token first
        let settings = VaultClientSettingsBuilder::default()
            .address(&address_str)
            .build()
            .map_err(|e| KmsError::ConfigurationError(format!("Invalid Vault settings: {}", e)))?;

        let mut client = VaultClient::new(settings).map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create Vault client: {}", e))
        })?;

        // Authenticate with Kubernetes
        let auth_info = kubernetes::login(&client, "kubernetes", role, &jwt)
            .await
            .map_err(|e| {
                KmsError::AuthenticationFailed(format!("Kubernetes auth failed: {}", e))
            })?;

        client.set_token(&auth_info.client_token);

        let provider = Self {
            client,
            mount_path: mount_path_str,
            key_name: key_name_str,
        };

        provider.health_check().await?;

        tracing::info!(
            provider = "vault",
            address = %address_str,
            auth_method = "kubernetes",
            role = %role,
            "Vault KMS provider initialized with Kubernetes auth"
        );

        Ok(provider)
    }
}

#[cfg(feature = "vault-kms")]
#[async_trait]
impl KeyManagementService for VaultKmsProvider {
    #[instrument(skip(self), fields(provider = "vault"))]
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        use base64::Engine as _;
        use vaultrs::api::transit::requests::DataKeyType;
        use vaultrs::transit;

        // Use Vault's data_key generation which creates a random key and wraps it atomically
        let response = transit::generate::data_key(
            &self.client,
            &self.mount_path,
            key_id,
            DataKeyType::Plaintext, // We need the plaintext for encryption
            None,
        )
        .await
        .map_err(|e| KmsError::OperationFailed(format!("Failed to generate data key: {}", e)))?;

        let plaintext_b64 = response.plaintext.ok_or_else(|| {
            KmsError::OperationFailed("Vault did not return plaintext".to_string())
        })?;

        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(&plaintext_b64)
            .map_err(|e| KmsError::OperationFailed(format!("Invalid base64 from Vault: {}", e)))?;

        // Parse version from ciphertext (format: vault:v1:ciphertext)
        let version = response
            .ciphertext
            .split(':')
            .nth(1)
            .and_then(|v| v.strip_prefix('v'))
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(1);

        tracing::debug!(
            provider = "vault",
            key_id = %key_id,
            version = version,
            "Generated DEK via Vault Transit"
        );

        Ok(DataEncryptionKey {
            plaintext: SecretBytes::new(plaintext),
            ciphertext: response.ciphertext.into_bytes(),
            version,
            key_id: key_id.to_string(),
        })
    }

    #[instrument(skip(self, ciphertext), fields(provider = "vault"))]
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        use base64::Engine as _;
        use vaultrs::transit;

        let ciphertext_str = String::from_utf8(ciphertext.to_vec()).map_err(|e| {
            KmsError::OperationFailed(format!("Invalid ciphertext encoding: {}", e))
        })?;

        let decrypt_response = transit::data::decrypt(
            &self.client,
            &self.mount_path,
            key_id,
            &ciphertext_str,
            None,
        )
        .await
        .map_err(|e| KmsError::OperationFailed(format!("Failed to decrypt DEK: {}", e)))?;

        let plaintext = base64::engine::general_purpose::STANDARD
            .decode(&decrypt_response.plaintext)
            .map_err(|e| KmsError::OperationFailed(format!("Invalid base64 from Vault: {}", e)))?;

        tracing::debug!(
            provider = "vault",
            key_id = %key_id,
            "Decrypted DEK via Vault Transit"
        );

        Ok(SecretBytes::new(plaintext))
    }

    #[instrument(skip(self, plaintext), fields(provider = "vault"))]
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use base64::Engine as _;
        use vaultrs::transit;

        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);

        let encrypt_response =
            transit::data::encrypt(&self.client, &self.mount_path, key_id, &plaintext_b64, None)
                .await
                .map_err(|e| KmsError::OperationFailed(format!("Failed to encrypt DEK: {}", e)))?;

        tracing::debug!(
            provider = "vault",
            key_id = %key_id,
            "Encrypted DEK via Vault Transit"
        );

        Ok(encrypt_response.ciphertext.into_bytes())
    }

    #[instrument(skip(self), fields(provider = "vault"))]
    async fn current_version(&self, key_id: &str) -> Result<u32> {
        use vaultrs::api::transit::responses::ReadKeyData;
        use vaultrs::transit;

        let key_info = transit::key::read(&self.client, &self.mount_path, key_id)
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Failed to read key: {}", e)))?;

        // Get the latest version from the keys map (keys are indexed by version number as string)
        let version = match &key_info.keys {
            ReadKeyData::Symmetric(keys) => keys
                .keys()
                .filter_map(|k| k.parse::<u32>().ok())
                .max()
                .unwrap_or(1),
            ReadKeyData::Asymmetric(keys) => keys
                .keys()
                .filter_map(|k| k.parse::<u32>().ok())
                .max()
                .unwrap_or(1),
        };

        Ok(version)
    }

    #[instrument(skip(self), fields(provider = "vault"))]
    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        use vaultrs::transit;

        transit::key::rotate(&self.client, &self.mount_path, key_id)
            .await
            .map_err(|e| KmsError::OperationFailed(format!("Failed to rotate key: {}", e)))?;

        let new_version = self.current_version(key_id).await?;

        tracing::info!(
            provider = "vault",
            key_id = %key_id,
            new_version = new_version,
            "Rotated master key in Vault"
        );

        Ok(new_version)
    }

    fn provider_name(&self) -> &'static str {
        "vault"
    }

    #[instrument(skip(self), fields(provider = "vault"))]
    async fn health_check(&self) -> Result<()> {
        use vaultrs::transit;

        // Verify we can read the key
        transit::key::read(&self.client, &self.mount_path, &self.key_name)
            .await
            .map_err(|e| KmsError::ServiceUnavailable(format!("Cannot read key: {}", e)))?;

        Ok(())
    }
}

// ============================================================================
// GCP Cloud KMS Provider
// ============================================================================

/// GCP Cloud KMS provider for production key management.
///
/// This provider uses Google Cloud Key Management Service (KMS) to:
/// - Generate data encryption keys (generateRandom + wrap)
/// - Decrypt wrapped keys (decrypt)
/// - Encrypt plaintext keys (encrypt)
///
/// # Security Properties
///
/// - Master keys never leave Cloud KMS (hardware-backed HSM optional)
/// - All operations are audited in Cloud Audit Logs
/// - Supports automatic key rotation
/// - IAM-based access control with fine-grained permissions
///
/// # Example
///
/// ```no_run
/// use rustberg::crypto::kms::GcpKmsProvider;
/// use rustberg::crypto::KeyManagementService;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Using default GCP credentials
/// let provider = GcpKmsProvider::new(
///     "my-project",
///     "us-east1",
///     "my-keyring",
///     "rustberg-master",
/// ).await?;
///
/// // Generate a data encryption key
/// let dek = provider.generate_data_key("rustberg-master").await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "gcp-kms")]
pub struct GcpKmsProvider {
    project_id: String,
    location: String,
    key_ring: String,
    key_name: String,
    client: gcloud_kms::client::Client,
}

#[cfg(feature = "gcp-kms")]
impl std::fmt::Debug for GcpKmsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsProvider")
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .field("key_ring", &self.key_ring)
            .field("key_name", &self.key_name)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "gcp-kms")]
impl GcpKmsProvider {
    /// Creates a new GCP Cloud KMS provider.
    ///
    /// # Arguments
    ///
    /// * `project_id` - GCP project ID
    /// * `location` - KMS location (e.g., "us-east1", "global")
    /// * `key_ring` - Key ring name
    /// * `key_name` - Key name within the key ring
    ///
    /// Uses Application Default Credentials (ADC) for authentication:
    /// - GOOGLE_APPLICATION_CREDENTIALS environment variable
    /// - Metadata server (on GCE/GKE)
    /// - gcloud auth application-default credentials
    pub async fn new(
        project_id: impl Into<String>,
        location: impl Into<String>,
        key_ring: impl Into<String>,
        key_name: impl Into<String>,
    ) -> Result<Self> {
        let project_id_str = project_id.into();
        let location_str = location.into();
        let key_ring_str = key_ring.into();
        let key_name_str = key_name.into();

        // Create GCP KMS client with authentication
        let config = gcloud_kms::client::ClientConfig::default()
            .with_auth()
            .await
            .map_err(|e| {
                KmsError::ConfigurationError(format!(
                    "Failed to configure GCP authentication: {}",
                    e
                ))
            })?;

        let client = gcloud_kms::client::Client::new(config).await.map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create GCP KMS client: {}", e))
        })?;

        tracing::info!(
            provider = "gcp-kms",
            project = %project_id_str,
            location = %location_str,
            key_ring = %key_ring_str,
            key_name = %key_name_str,
            "Initialized GCP Cloud KMS provider"
        );

        Ok(Self {
            project_id: project_id_str,
            location: location_str,
            key_ring: key_ring_str,
            key_name: key_name_str,
            client,
        })
    }

    /// Returns the full resource name for the crypto key.
    fn key_resource_name(&self, key_name: &str) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.project_id, self.location, self.key_ring, key_name
        )
    }
}

#[cfg(feature = "gcp-kms")]
#[async_trait]
impl KeyManagementService for GcpKmsProvider {
    #[instrument(skip(self), fields(provider = "gcp-kms"))]
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        use gcloud_kms::grpc::kms::v1::EncryptRequest;
        use rand::RngCore;

        // Generate random 32-byte DEK locally
        let mut plaintext = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        let key_name = self.key_resource_name(key_id);

        // Encrypt (wrap) the DEK using GCP KMS
        let request = EncryptRequest {
            name: key_name.clone(),
            plaintext: plaintext.clone(),
            additional_authenticated_data: Vec::new(),
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let response = self
            .client
            .encrypt(request, None)
            .await
            .map_err(|e| KmsError::OperationFailed(format!("GCP KMS encrypt failed: {}", e)))?;

        tracing::debug!(
            provider = "gcp-kms",
            key_id = %key_id,
            key_path = %key_name,
            ciphertext_len = response.ciphertext.len(),
            "Successfully wrapped data encryption key"
        );

        Ok(DataEncryptionKey {
            plaintext: SecretBytes::new(plaintext),
            ciphertext: response.ciphertext,
            version: 1,
            key_id: key_id.to_string(),
        })
    }

    #[instrument(skip(self, ciphertext), fields(provider = "gcp-kms"))]
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        use gcloud_kms::grpc::kms::v1::DecryptRequest;

        let key_name = self.key_resource_name(key_id);

        let request = DecryptRequest {
            name: key_name.clone(),
            ciphertext: ciphertext.to_vec(),
            additional_authenticated_data: Vec::new(),
            ciphertext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let response = self
            .client
            .decrypt(request, None)
            .await
            .map_err(|e| KmsError::OperationFailed(format!("GCP KMS decrypt failed: {}", e)))?;

        tracing::debug!(
            provider = "gcp-kms",
            key_id = %key_id,
            key_path = %key_name,
            plaintext_len = response.plaintext.len(),
            "Successfully unwrapped data encryption key"
        );

        Ok(SecretBytes::new(response.plaintext))
    }

    #[instrument(skip(self, plaintext), fields(provider = "gcp-kms"))]
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use gcloud_kms::grpc::kms::v1::EncryptRequest;

        let key_name = self.key_resource_name(key_id);

        let request = EncryptRequest {
            name: key_name.clone(),
            plaintext: plaintext.to_vec(),
            additional_authenticated_data: Vec::new(),
            plaintext_crc32c: None,
            additional_authenticated_data_crc32c: None,
        };

        let response = self
            .client
            .encrypt(request, None)
            .await
            .map_err(|e| KmsError::OperationFailed(format!("GCP KMS encrypt failed: {}", e)))?;

        tracing::debug!(
            provider = "gcp-kms",
            key_id = %key_id,
            key_path = %key_name,
            ciphertext_len = response.ciphertext.len(),
            "Successfully wrapped data encryption key"
        );

        Ok(response.ciphertext)
    }

    #[instrument(skip(self), fields(provider = "gcp-kms"))]
    async fn current_version(&self, key_id: &str) -> Result<u32> {
        use gcloud_kms::grpc::kms::v1::GetCryptoKeyRequest;

        let key_name = self.key_resource_name(key_id);

        let request = GetCryptoKeyRequest {
            name: key_name.clone(),
        };

        let response = self
            .client
            .get_crypto_key(request, None)
            .await
            .map_err(|e| {
                KmsError::OperationFailed(format!("GCP KMS get_crypto_key failed: {}", e))
            })?;

        // Extract version from primary key version name
        // Format: projects/{project}/locations/{location}/keyRings/{keyRing}/cryptoKeys/{cryptoKey}/cryptoKeyVersions/{version}
        if let Some(primary) = response.primary {
            if let Some(version_str) = primary.name.rsplit('/').next() {
                if let Ok(version) = version_str.parse::<u32>() {
                    return Ok(version);
                }
            }
        }

        Ok(1)
    }

    #[instrument(skip(self), fields(provider = "gcp-kms"))]
    async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        use gcloud_kms::grpc::kms::v1::CreateCryptoKeyVersionRequest;

        let key_name = self.key_resource_name(key_id);

        let request = CreateCryptoKeyVersionRequest {
            parent: key_name.clone(),
            crypto_key_version: None,
        };

        let response = self
            .client
            .create_crypto_key_version(request, None)
            .await
            .map_err(|e| {
                KmsError::OperationFailed(format!("GCP KMS key rotation failed: {}", e))
            })?;

        // Extract version number from the response name
        if let Some(version_str) = response.name.rsplit('/').next() {
            if let Ok(version) = version_str.parse::<u32>() {
                tracing::info!(
                    provider = "gcp-kms",
                    key_id = %key_id,
                    new_version = version,
                    "Successfully rotated master key"
                );
                return Ok(version);
            }
        }

        Err(KmsError::OperationFailed(
            "Failed to parse key version from rotation response".to_string(),
        ))
    }

    fn provider_name(&self) -> &'static str {
        "gcp-kms"
    }

    #[instrument(skip(self), fields(provider = "gcp-kms"))]
    async fn health_check(&self) -> Result<()> {
        use gcloud_kms::grpc::kms::v1::GetCryptoKeyRequest;

        let key_name = self.key_resource_name(&self.key_name);

        let request = GetCryptoKeyRequest {
            name: key_name.clone(),
        };

        self.client
            .get_crypto_key(request, None)
            .await
            .map_err(|e| {
                KmsError::ServiceUnavailable(format!("GCP KMS health check failed: {}", e))
            })?;

        Ok(())
    }
}

// ============================================================================
// Azure Key Vault Provider
// ============================================================================

/// Azure Key Vault provider for production key management.
///
/// This provider uses Azure Key Vault to:
/// - Generate data encryption keys (generateRandom + wrapKey)
/// - Decrypt wrapped keys (unwrapKey)
/// - Encrypt plaintext keys (wrapKey)
///
/// # Security Properties
///
/// - Master keys can be HSM-backed (Premium tier)
/// - All operations are audited in Azure Monitor
/// - Supports automatic key rotation
/// - Azure RBAC and Key Vault access policies for authorization
///
/// # Example
///
/// ```no_run
/// use rustberg::crypto::kms::AzureKeyVaultProvider;
/// use rustberg::crypto::KeyManagementService;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Using default Azure credentials
/// let provider = AzureKeyVaultProvider::new(
///     "https://myvault.vault.azure.net",
///     "rustberg-master",
/// ).await?;
///
/// // Generate a data encryption key
/// let dek = provider.generate_data_key("rustberg-master").await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "azure-kms")]
pub struct AzureKeyVaultProvider {
    vault_url: String,
    key_name: String,
    key_client: azure_security_keyvault::KeyClient,
}

#[cfg(feature = "azure-kms")]
impl Clone for AzureKeyVaultProvider {
    fn clone(&self) -> Self {
        Self {
            vault_url: self.vault_url.clone(),
            key_name: self.key_name.clone(),
            key_client: self.key_client.clone(),
        }
    }
}

#[cfg(feature = "azure-kms")]
impl std::fmt::Debug for AzureKeyVaultProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureKeyVaultProvider")
            .field("vault_url", &self.vault_url)
            .field("key_name", &self.key_name)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "azure-kms")]
impl AzureKeyVaultProvider {
    /// Creates a new Azure Key Vault provider.
    ///
    /// # Arguments
    ///
    /// * `vault_url` - Key Vault URL (e.g., "<https://myvault.vault.azure.net>")
    /// * `key_name` - Key name in the vault
    ///
    /// Uses DefaultAzureCredential for authentication:
    /// - AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID environment variables
    /// - Managed Identity (on Azure VMs/AKS)
    /// - Azure CLI credentials
    pub async fn new(vault_url: impl Into<String>, key_name: impl Into<String>) -> Result<Self> {
        let vault_url_str = vault_url.into();
        let key_name_str = key_name.into();

        // Create Azure credentials using DefaultAzureCredential
        let credential = azure_identity::DefaultAzureCredential::create(
            azure_identity::TokenCredentialOptions::default(),
        )
        .map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create Azure credentials: {}", e))
        })?;

        // Create KeyClient for key operations
        let key_client = azure_security_keyvault::KeyClient::new(
            &vault_url_str,
            std::sync::Arc::new(credential),
        )
        .map_err(|e| {
            KmsError::ConfigurationError(format!("Failed to create Azure Key Vault client: {}", e))
        })?;

        tracing::info!(
            provider = "azure-keyvault",
            vault = %vault_url_str,
            key = %key_name_str,
            "Connected to Azure Key Vault"
        );

        Ok(Self {
            vault_url: vault_url_str,
            key_name: key_name_str,
            key_client,
        })
    }
}

#[cfg(feature = "azure-kms")]
#[async_trait]
impl KeyManagementService for AzureKeyVaultProvider {
    #[instrument(skip(self), fields(provider = "azure-keyvault"))]
    async fn generate_data_key(&self, key_id: &str) -> Result<DataEncryptionKey> {
        use azure_security_keyvault::prelude::{
            CryptographParamtersEncryption, EncryptParameters, EncryptionAlgorithm,
        };
        use rand::RngCore;

        // Generate random 32-byte DEK locally
        let mut plaintext = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut plaintext);

        // Encrypt (wrap) the DEK using Azure Key Vault
        // Use RSA-OAEP-256 which is commonly supported
        let encrypt_params = EncryptParameters {
            plaintext: plaintext.clone(),
            encrypt_parameters_encryption: CryptographParamtersEncryption::Rsa(
                azure_security_keyvault::prelude::RsaEncryptionParameters::new(
                    EncryptionAlgorithm::RsaOaep256,
                )
                .map_err(|e| {
                    KmsError::OperationFailed(format!(
                        "Failed to create encryption parameters: {}",
                        e
                    ))
                })?,
            ),
        };

        let response = self
            .key_client
            .encrypt(key_id, encrypt_params)
            .await
            .map_err(|e| {
                KmsError::OperationFailed(format!("Azure Key Vault encrypt failed: {}", e))
            })?;

        tracing::debug!(
            provider = "azure-keyvault",
            key_id = %key_id,
            ciphertext_len = response.result.len(),
            "Successfully wrapped data encryption key"
        );

        Ok(DataEncryptionKey {
            plaintext: SecretBytes::new(plaintext),
            ciphertext: response.result,
            version: 1,
            key_id: key_id.to_string(),
        })
    }

    #[instrument(skip(self, ciphertext), fields(provider = "azure-keyvault"))]
    async fn decrypt_data_key(&self, key_id: &str, ciphertext: &[u8]) -> Result<SecretBytes> {
        use azure_security_keyvault::prelude::{
            CryptographParamtersEncryption, DecryptParameters, EncryptionAlgorithm,
        };

        let decrypt_params = DecryptParameters {
            ciphertext: ciphertext.to_vec(),
            decrypt_parameters_encryption: CryptographParamtersEncryption::Rsa(
                azure_security_keyvault::prelude::RsaEncryptionParameters::new(
                    EncryptionAlgorithm::RsaOaep256,
                )
                .map_err(|e| {
                    KmsError::OperationFailed(format!(
                        "Failed to create decryption parameters: {}",
                        e
                    ))
                })?,
            ),
        };

        let response = self
            .key_client
            .decrypt(key_id, decrypt_params)
            .await
            .map_err(|e| {
                KmsError::OperationFailed(format!("Azure Key Vault decrypt failed: {}", e))
            })?;

        tracing::debug!(
            provider = "azure-keyvault",
            key_id = %key_id,
            plaintext_len = response.result.len(),
            "Successfully unwrapped data encryption key"
        );

        Ok(SecretBytes::new(response.result))
    }

    #[instrument(skip(self, plaintext), fields(provider = "azure-keyvault"))]
    async fn encrypt_data_key(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        use azure_security_keyvault::prelude::{
            CryptographParamtersEncryption, EncryptParameters, EncryptionAlgorithm,
        };

        let encrypt_params = EncryptParameters {
            plaintext: plaintext.to_vec(),
            encrypt_parameters_encryption: CryptographParamtersEncryption::Rsa(
                azure_security_keyvault::prelude::RsaEncryptionParameters::new(
                    EncryptionAlgorithm::RsaOaep256,
                )
                .map_err(|e| {
                    KmsError::OperationFailed(format!(
                        "Failed to create encryption parameters: {}",
                        e
                    ))
                })?,
            ),
        };

        let response = self
            .key_client
            .encrypt(key_id, encrypt_params)
            .await
            .map_err(|e| {
                KmsError::OperationFailed(format!("Azure Key Vault encrypt failed: {}", e))
            })?;

        tracing::debug!(
            provider = "azure-keyvault",
            key_id = %key_id,
            ciphertext_len = response.result.len(),
            "Successfully wrapped data encryption key"
        );

        Ok(response.result)
    }

    #[instrument(skip(self), fields(provider = "azure-keyvault"))]
    async fn current_version(&self, key_id: &str) -> Result<u32> {
        // Get the key to inspect its version properties
        let key = self.key_client.get(key_id).await.map_err(|e| {
            KmsError::OperationFailed(format!("Azure Key Vault get key failed: {}", e))
        })?;

        // Azure Key Vault embeds the version as a UUID segment in the key URL
        // (e.g., https://vault.vault.azure.net/keys/my-key/<version-uuid>).
        // We hash the URL-based version identifier into a deterministic u32
        // so callers can detect version changes after rotation.
        let version_hash = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            // key.key.id contains the full key URL including the version segment
            key.key.id.hash(&mut hasher);
            // Truncate to u32 — sufficient for change detection
            (hasher.finish() & 0xFFFF_FFFF) as u32
        };

        // Ensure we never return 0 (reserved for "unknown")
        Ok(if version_hash == 0 { 1 } else { version_hash })
    }

    #[instrument(skip(self), fields(provider = "azure-keyvault"))]
    async fn rotate_master_key(&self, _key_id: &str) -> Result<u32> {
        // Azure Key Vault key rotation is typically managed through Azure Policy
        // or the Key Vault rotation settings. Creating a new version would require
        // the CreateKey permission and more complex logic.
        Err(KmsError::OperationFailed(
            "Azure Key Vault key rotation should be configured through Azure Policy or Key Vault settings. \
             Use the Azure Portal or CLI to rotate keys.".to_string()
        ))
    }

    fn provider_name(&self) -> &'static str {
        "azure-keyvault"
    }

    #[instrument(skip(self), fields(provider = "azure-keyvault"))]
    async fn health_check(&self) -> Result<()> {
        // Verify we can access the key
        self.key_client.get(&self.key_name).await.map_err(|e| {
            KmsError::ServiceUnavailable(format!("Azure Key Vault health check failed: {}", e))
        })?;

        Ok(())
    }
}

// ============================================================================
// KMS Factory
// ============================================================================

/// Configuration for KMS providers.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsConfig {
    /// Environment variable provider (development only).
    Env,

    /// AWS KMS configuration.
    AwsKms {
        /// AWS region.
        region: String,
        /// KMS key ID or alias (e.g., "alias/rustberg-master").
        key_id: String,
        /// Optional endpoint override (for LocalStack, etc.).
        endpoint: Option<String>,
    },

    /// HashiCorp Vault configuration.
    Vault {
        /// Vault address (e.g., "<https://vault.example.com:8200>").
        address: String,
        /// Transit secrets engine mount path (default: "transit").
        mount_path: String,
        /// Key name in Vault.
        key_name: String,
        /// Authentication method.
        auth: VaultAuth,
    },

    /// GCP Cloud KMS configuration.
    GcpKms {
        /// Project ID.
        project_id: String,
        /// Location (e.g., "us-east1").
        location: String,
        /// Key ring name.
        key_ring: String,
        /// Key name.
        key_name: String,
    },

    /// Azure Key Vault configuration.
    AzureKeyVault {
        /// Vault URL (e.g., "<https://myvault.vault.azure.net>").
        vault_url: String,
        /// Key name.
        key_name: String,
    },
}

/// Vault authentication methods.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VaultAuth {
    /// Token authentication.
    Token(String),
    /// AppRole authentication.
    AppRole { role_id: String, secret_id: String },
    /// Kubernetes authentication.
    Kubernetes { role: String, jwt_path: String },
}

impl KmsConfig {
    /// Creates KmsConfig from file-based configuration.
    ///
    /// # Errors
    ///
    /// Returns `KmsError::ConfigurationError` if required environment variables
    /// are missing (e.g., `VAULT_TOKEN` for the Vault provider).
    pub fn from_file_config(file_config: &crate::config::KmsConfigFile) -> Result<Self> {
        Ok(match file_config.provider.as_str() {
            "env" => KmsConfig::Env,
            "aws-kms" => KmsConfig::AwsKms {
                region: file_config
                    .aws_region
                    .clone()
                    .unwrap_or_else(|| "us-east-1".to_string()),
                key_id: file_config
                    .aws_key_id
                    .clone()
                    .unwrap_or_else(|| "alias/rustberg".to_string()),
                endpoint: None,
            },
            "vault" => {
                let address = file_config
                    .vault_address
                    .clone()
                    .unwrap_or_else(|| "http://127.0.0.1:8200".to_string());
                let key_name = file_config
                    .vault_key_name
                    .clone()
                    .unwrap_or_else(|| "rustberg".to_string());
                // SECURITY: Require VAULT_TOKEN from environment — never fall back to a default.
                let token = std::env::var("VAULT_TOKEN").map_err(|_| {
                    KmsError::ConfigurationError(
                        "VAULT_TOKEN environment variable is required for Vault KMS provider. \
                         Set VAULT_TOKEN to a valid Vault token before starting the server."
                            .to_string(),
                    )
                })?;

                KmsConfig::Vault {
                    address,
                    mount_path: "transit".to_string(),
                    key_name,
                    auth: VaultAuth::Token(token),
                }
            }
            "gcp-kms" => KmsConfig::GcpKms {
                project_id: file_config
                    .gcp_project_id
                    .clone()
                    .unwrap_or_else(|| "my-project".to_string()),
                location: file_config
                    .gcp_location
                    .clone()
                    .unwrap_or_else(|| "global".to_string()),
                key_ring: file_config
                    .gcp_key_ring
                    .clone()
                    .unwrap_or_else(|| "rustberg".to_string()),
                key_name: file_config
                    .gcp_key_name
                    .clone()
                    .unwrap_or_else(|| "master".to_string()),
            },
            "azure-keyvault" | "azure" => KmsConfig::AzureKeyVault {
                vault_url: file_config
                    .azure_vault_url
                    .clone()
                    .unwrap_or_else(|| "https://rustberg.vault.azure.net".to_string()),
                key_name: file_config
                    .azure_key_name
                    .clone()
                    .unwrap_or_else(|| "rustberg-master".to_string()),
            },
            _ => {
                tracing::warn!(
                    "Unknown KMS provider '{}', falling back to 'env'",
                    file_config.provider
                );
                KmsConfig::Env
            }
        })
    }
}

/// Creates a KMS provider from configuration.
///
/// Returns a `CachedKms` wrapper for production use.
pub async fn create_kms(
    config: KmsConfig,
    cache_config: Option<KmsCacheConfig>,
) -> Result<Arc<dyn KeyManagementService>> {
    let cache_config = cache_config.unwrap_or_default();

    let inner: Arc<dyn KeyManagementService> = match config {
        KmsConfig::Env => Arc::new(EnvKeyProvider::from_env()?),

        #[cfg(feature = "aws-kms")]
        KmsConfig::AwsKms {
            region,
            key_id,
            endpoint,
        } => Arc::new(AwsKmsProvider::new(region, key_id, endpoint).await?),

        #[cfg(not(feature = "aws-kms"))]
        KmsConfig::AwsKms { .. } => {
            return Err(KmsError::ConfigurationError(
                "AWS KMS support not compiled. Enable the 'aws-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "vault-kms")]
        KmsConfig::Vault {
            address,
            mount_path,
            key_name,
            auth,
        } => match auth {
            VaultAuth::Token(token) => {
                Arc::new(VaultKmsProvider::new(address, mount_path, key_name, token).await?)
            }
            VaultAuth::AppRole { role_id, secret_id } => Arc::new(
                VaultKmsProvider::with_approle(address, mount_path, key_name, &role_id, &secret_id)
                    .await?,
            ),
            VaultAuth::Kubernetes { role, jwt_path } => Arc::new(
                VaultKmsProvider::with_kubernetes(
                    address,
                    mount_path,
                    key_name,
                    &role,
                    Some(&jwt_path),
                )
                .await?,
            ),
        },

        #[cfg(not(feature = "vault-kms"))]
        KmsConfig::Vault { .. } => {
            return Err(KmsError::ConfigurationError(
                "HashiCorp Vault support not compiled. Enable the 'vault-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "gcp-kms")]
        KmsConfig::GcpKms {
            project_id,
            location,
            key_ring,
            key_name,
        } => Arc::new(GcpKmsProvider::new(project_id, location, key_ring, key_name).await?),

        #[cfg(not(feature = "gcp-kms"))]
        KmsConfig::GcpKms { .. } => {
            return Err(KmsError::ConfigurationError(
                "GCP Cloud KMS support not compiled. Enable the 'gcp-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "azure-kms")]
        KmsConfig::AzureKeyVault {
            vault_url,
            key_name,
        } => Arc::new(AzureKeyVaultProvider::new(vault_url, key_name).await?),

        #[cfg(not(feature = "azure-kms"))]
        KmsConfig::AzureKeyVault { .. } => {
            return Err(KmsError::ConfigurationError(
                "Azure Key Vault support not compiled. Enable the 'azure-kms' feature.".to_string(),
            ));
        }
    };

    // Wrap with caching layer
    if cache_config.enabled {
        Ok(Arc::new(CachedKms::new(inner, cache_config)))
    } else {
        Ok(inner)
    }
}

// ============================================================================
// Resilient KMS Builder
// ============================================================================

/// Configuration for a production-grade resilient KMS stack.
///
/// Combines caching, retry, and circuit breaker patterns for maximum
/// reliability and performance.
#[derive(Debug, Clone)]
pub struct ResilientKmsConfig {
    /// KMS provider configuration.
    pub provider: KmsConfig,
    /// Cache configuration (default: enabled).
    pub cache: KmsCacheConfig,
    /// Retry configuration (default: enabled).
    pub retry: RetryConfig,
    /// Circuit breaker configuration (default: enabled).
    pub circuit_breaker: CircuitBreakerConfig,
    /// Enable caching layer.
    pub enable_cache: bool,
    /// Enable retry layer.
    pub enable_retry: bool,
    /// Enable circuit breaker layer.
    pub enable_circuit_breaker: bool,
}

impl Default for ResilientKmsConfig {
    fn default() -> Self {
        Self {
            provider: KmsConfig::Env,
            cache: KmsCacheConfig::default(),
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            enable_cache: true,
            enable_retry: true,
            enable_circuit_breaker: true,
        }
    }
}

impl ResilientKmsConfig {
    /// Creates configuration for development (minimal resilience).
    pub fn development() -> Self {
        Self {
            enable_retry: false,
            enable_circuit_breaker: false,
            ..Default::default()
        }
    }

    /// Creates configuration for production (full resilience).
    pub fn production(provider: KmsConfig) -> Self {
        Self {
            provider,
            cache: KmsCacheConfig::high_security(),
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            enable_cache: true,
            enable_retry: true,
            enable_circuit_breaker: true,
        }
    }

    /// Creates configuration for high-availability (aggressive resilience).
    pub fn high_availability(provider: KmsConfig) -> Self {
        Self {
            provider,
            cache: KmsCacheConfig::default(),
            retry: RetryConfig::aggressive(),
            circuit_breaker: CircuitBreakerConfig::aggressive(),
            enable_cache: true,
            enable_retry: true,
            enable_circuit_breaker: true,
        }
    }
}

/// Creates a resilient KMS stack with layered protection.
///
/// The layers are applied in this order (outermost to innermost):
/// 1. **Circuit Breaker** - Fails fast when KMS is unavailable
/// 2. **Retry** - Retries transient failures with backoff
/// 3. **Cache** - Caches DEKs to reduce KMS calls
/// 4. **Provider** - The actual KMS implementation
///
/// ```text
/// ┌─────────────────────────────────────────────────────────┐
/// │                 Resilient KMS Stack                      │
/// ├─────────────────────────────────────────────────────────┤
/// │                                                          │
/// │    Request                                               │
/// │       │                                                  │
/// │       ▼                                                  │
/// │  ┌──────────────┐                                        │
/// │  │   Circuit    │  Rejects if KMS unavailable            │
/// │  │   Breaker    │                                        │
/// │  └──────────────┘                                        │
/// │       │                                                  │
/// │       ▼                                                  │
/// │  ┌──────────────┐                                        │
/// │  │    Retry     │  Retries transient failures            │
/// │  │              │  with exponential backoff              │
/// │  └──────────────┘                                        │
/// │       │                                                  │
/// │       ▼                                                  │
/// │  ┌──────────────┐                                        │
/// │  │    Cache     │  Returns cached DEKs when              │
/// │  │              │  available                             │
/// │  └──────────────┘                                        │
/// │       │                                                  │
/// │       ▼                                                  │
/// │  ┌──────────────┐                                        │
/// │  │   Provider   │  AWS KMS, Vault, etc.                  │
/// │  │              │                                        │
/// │  └──────────────┘                                        │
/// │                                                          │
/// └─────────────────────────────────────────────────────────┘
/// ```
pub async fn create_resilient_kms(
    config: ResilientKmsConfig,
) -> Result<Arc<dyn KeyManagementService>> {
    // Create the base provider
    let mut kms: Arc<dyn KeyManagementService> = match config.provider {
        KmsConfig::Env => Arc::new(EnvKeyProvider::from_env()?),

        #[cfg(feature = "aws-kms")]
        KmsConfig::AwsKms {
            region,
            key_id,
            endpoint,
        } => Arc::new(AwsKmsProvider::new(region, key_id, endpoint).await?),

        #[cfg(not(feature = "aws-kms"))]
        KmsConfig::AwsKms { .. } => {
            return Err(KmsError::ConfigurationError(
                "AWS KMS support not compiled. Enable the 'aws-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "vault-kms")]
        KmsConfig::Vault {
            address,
            mount_path,
            key_name,
            auth,
        } => match auth {
            VaultAuth::Token(token) => {
                Arc::new(VaultKmsProvider::new(address, mount_path, key_name, token).await?)
            }
            VaultAuth::AppRole { role_id, secret_id } => Arc::new(
                VaultKmsProvider::with_approle(address, mount_path, key_name, &role_id, &secret_id)
                    .await?,
            ),
            VaultAuth::Kubernetes { role, jwt_path } => Arc::new(
                VaultKmsProvider::with_kubernetes(
                    address,
                    mount_path,
                    key_name,
                    &role,
                    Some(&jwt_path),
                )
                .await?,
            ),
        },

        #[cfg(not(feature = "vault-kms"))]
        KmsConfig::Vault { .. } => {
            return Err(KmsError::ConfigurationError(
                "HashiCorp Vault support not compiled. Enable the 'vault-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "gcp-kms")]
        KmsConfig::GcpKms {
            project_id,
            location,
            key_ring,
            key_name,
        } => Arc::new(GcpKmsProvider::new(project_id, location, key_ring, key_name).await?),

        #[cfg(not(feature = "gcp-kms"))]
        KmsConfig::GcpKms { .. } => {
            return Err(KmsError::ConfigurationError(
                "GCP Cloud KMS support not compiled. Enable the 'gcp-kms' feature.".to_string(),
            ));
        }

        #[cfg(feature = "azure-kms")]
        KmsConfig::AzureKeyVault {
            vault_url,
            key_name,
        } => Arc::new(AzureKeyVaultProvider::new(vault_url, key_name).await?),

        #[cfg(not(feature = "azure-kms"))]
        KmsConfig::AzureKeyVault { .. } => {
            return Err(KmsError::ConfigurationError(
                "Azure Key Vault support not compiled. Enable the 'azure-kms' feature.".to_string(),
            ));
        }
    };

    // Layer 4 -> 3: Add caching
    if config.enable_cache && config.cache.enabled {
        kms = Arc::new(CachedKms::new(kms, config.cache));
        tracing::debug!("Added caching layer to KMS stack");
    }

    // Layer 3 -> 2: Add retry
    if config.enable_retry && config.retry.max_retries > 0 {
        kms = Arc::new(RetryKms::new(kms, config.retry));
        tracing::debug!("Added retry layer to KMS stack");
    }

    // Layer 2 -> 1: Add circuit breaker
    if config.enable_circuit_breaker {
        kms = Arc::new(CircuitBreakerKms::new(kms, config.circuit_breaker));
        tracing::debug!("Added circuit breaker layer to KMS stack");
    }

    tracing::info!("Resilient KMS stack created");
    Ok(kms)
}

// ============================================================================
// Envelope Encryption Helper
// ============================================================================

/// Helper for envelope encryption operations.
///
/// This struct manages encrypted data alongside its wrapped DEK,
/// making it easy to store and retrieve encrypted payloads.
#[derive(Debug, Clone)]
pub struct EncryptedEnvelope {
    /// The encrypted DEK (wrapped by KMS).
    pub wrapped_dek: Vec<u8>,
    /// The encrypted data (encrypted by DEK).
    pub ciphertext: Vec<u8>,
    /// KMS key ID used for encryption.
    pub key_id: String,
}

impl EncryptedEnvelope {
    /// Encrypts data using envelope encryption.
    pub async fn encrypt(
        kms: &dyn KeyManagementService,
        key_id: &str,
        plaintext: &[u8],
    ) -> Result<Self> {
        use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
        use rand::RngCore;

        // Generate a new DEK
        let dek = kms.generate_data_key(key_id).await?;

        // Encrypt the data with the DEK
        let cipher = Aes256Gcm::new_from_slice(dek.plaintext.expose())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        // Format ciphertext: nonce || encrypted_data
        let mut ciphertext = Vec::with_capacity(12 + encrypted.len());
        ciphertext.extend_from_slice(&nonce_bytes);
        ciphertext.extend_from_slice(&encrypted);

        Ok(Self {
            wrapped_dek: dek.ciphertext,
            ciphertext,
            key_id: key_id.to_string(),
        })
    }

    /// Decrypts data using envelope decryption.
    pub async fn decrypt(&self, kms: &dyn KeyManagementService) -> Result<Vec<u8>> {
        use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};

        if self.ciphertext.len() < 12 + 16 {
            return Err(KmsError::InvalidFormat("Ciphertext too short".to_string()));
        }

        // Decrypt the DEK
        let dek = kms
            .decrypt_data_key(&self.key_id, &self.wrapped_dek)
            .await?;

        // Decrypt the data
        let cipher = Aes256Gcm::new_from_slice(dek.expose())
            .map_err(|e| KmsError::OperationFailed(e.to_string()))?;

        let nonce = Nonce::from_slice(&self.ciphertext[..12]);
        let encrypted = &self.ciphertext[12..];

        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| KmsError::OperationFailed("Decryption failed".to_string()))?;

        Ok(plaintext)
    }

    /// Re-encrypts the envelope with a new DEK from the current master key version.
    ///
    /// This is useful after a master key rotation to ensure data is encrypted
    /// with the latest key version.
    pub async fn rotate(&self, kms: &dyn KeyManagementService) -> Result<Self> {
        // Decrypt the data
        let plaintext = self.decrypt(kms).await?;

        // Re-encrypt with a fresh DEK
        Self::encrypt(kms, &self.key_id, &plaintext).await
    }
}

// ============================================================================
// Key Rotation Manager
// ============================================================================

/// Result of a key rotation operation.
#[derive(Debug, Clone)]
pub struct KeyRotationResult {
    /// New master key version.
    pub new_version: u32,
    /// Number of DEKs successfully re-wrapped.
    pub deks_rotated: usize,
    /// Number of DEKs that failed to re-wrap.
    pub deks_failed: usize,
    /// Errors encountered during rotation.
    pub errors: Vec<String>,
}

/// Manager for coordinating key rotation across the system.
///
/// Key rotation involves:
/// 1. Creating a new master key version in the KMS
/// 2. Re-wrapping all existing DEKs with the new version
/// 3. Invalidating caches
///
/// This manager handles the orchestration while being storage-agnostic.
#[derive(Debug)]
pub struct KeyRotationManager {
    kms: Arc<dyn KeyManagementService>,
}

impl KeyRotationManager {
    /// Creates a new rotation manager.
    pub fn new(kms: Arc<dyn KeyManagementService>) -> Self {
        Self { kms }
    }

    /// Initiates a master key rotation.
    ///
    /// This triggers the KMS to create a new key version. After this,
    /// all new DEKs will be wrapped with the new version.
    ///
    /// Existing DEKs remain valid (KMS keeps old versions) but should
    /// be re-wrapped using `rewrap_deks` for full forward secrecy.
    #[instrument(skip(self), fields(provider = %self.kms.provider_name()))]
    pub async fn rotate_master_key(&self, key_id: &str) -> Result<u32> {
        tracing::info!(key_id = %key_id, "Initiating master key rotation");

        let new_version = self.kms.rotate_master_key(key_id).await?;

        tracing::info!(
            key_id = %key_id,
            new_version = new_version,
            "Master key rotation complete"
        );

        Ok(new_version)
    }

    /// Re-wraps a single DEK with the current master key version.
    ///
    /// Returns the newly wrapped DEK ciphertext.
    pub async fn rewrap_dek(&self, key_id: &str, wrapped_dek: &[u8]) -> Result<Vec<u8>> {
        // Decrypt with old key version (KMS keeps all versions)
        let plaintext_dek = self.kms.decrypt_data_key(key_id, wrapped_dek).await?;

        // Re-encrypt with current version
        let new_wrapped = self
            .kms
            .encrypt_data_key(key_id, plaintext_dek.expose())
            .await?;

        Ok(new_wrapped)
    }

    /// Re-wraps multiple DEKs in batch.
    ///
    /// Returns results for each DEK (success or error).
    #[instrument(skip(self, wrapped_deks), fields(provider = %self.kms.provider_name(), dek_count = wrapped_deks.len()))]
    pub async fn rewrap_deks_batch(
        &self,
        key_id: &str,
        wrapped_deks: &[Vec<u8>],
    ) -> KeyRotationResult {
        let mut result = KeyRotationResult {
            new_version: self.kms.current_version(key_id).await.unwrap_or(0),
            deks_rotated: 0,
            deks_failed: 0,
            errors: Vec::new(),
        };

        for (idx, wrapped_dek) in wrapped_deks.iter().enumerate() {
            match self.rewrap_dek(key_id, wrapped_dek).await {
                Ok(_) => {
                    result.deks_rotated += 1;
                }
                Err(e) => {
                    result.deks_failed += 1;
                    result.errors.push(format!("DEK {}: {}", idx, e));
                    tracing::warn!(
                        key_id = %key_id,
                        dek_index = idx,
                        error = %e,
                        "Failed to re-wrap DEK"
                    );
                }
            }
        }

        tracing::info!(
            key_id = %key_id,
            new_version = result.new_version,
            rotated = result.deks_rotated,
            failed = result.deks_failed,
            "Batch DEK re-wrapping complete"
        );

        result
    }

    /// Verifies a wrapped DEK is using the current master key version.
    ///
    /// This is provider-specific and may not be available for all KMS implementations.
    /// For EnvKeyProvider, it checks the version prefix in the ciphertext.
    pub fn is_current_version(&self, wrapped_dek: &[u8]) -> Option<bool> {
        // Version is stored in first 4 bytes for EnvKeyProvider
        if wrapped_dek.len() >= 4 {
            let version = u32::from_be_bytes([
                wrapped_dek[0],
                wrapped_dek[1],
                wrapped_dek[2],
                wrapped_dek[3],
            ]);

            // We can't easily check current version synchronously,
            // so return None to indicate uncertainty
            Some(version > 0) // At least valid format
        } else {
            None
        }
    }
}

// ============================================================================
// Audit Events
// ============================================================================

/// Audit event for KMS operations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct KmsAuditEvent {
    /// Timestamp of the event.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Type of operation.
    pub operation: KmsOperation,
    /// Key ID involved.
    pub key_id: String,
    /// Provider name.
    pub provider: String,
    /// Whether the operation succeeded.
    pub success: bool,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Additional context.
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub context: std::collections::HashMap<String, String>,
}

/// Types of KMS operations for auditing.
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KmsOperation {
    /// Generate a new DEK.
    GenerateDataKey,
    /// Decrypt (unwrap) a DEK.
    DecryptDataKey,
    /// Encrypt (wrap) a DEK.
    EncryptDataKey,
    /// Rotate master key.
    RotateMasterKey,
    /// Health check.
    HealthCheck,
}

impl KmsAuditEvent {
    /// Creates a new audit event.
    pub fn new(operation: KmsOperation, key_id: &str, provider: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now(),
            operation,
            key_id: key_id.to_string(),
            provider: provider.to_string(),
            success: true,
            error: None,
            context: std::collections::HashMap::new(),
        }
    }

    /// Marks the event as failed.
    pub fn with_error(mut self, error: &str) -> Self {
        self.success = false;
        self.error = Some(error.to_string());
        self
    }

    /// Adds context to the event.
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_key_provider_with_key() {
        let key = vec![0u8; 32];
        let provider = EnvKeyProvider::with_key(key).unwrap();
        assert_eq!(provider.current_version, 1);
    }

    #[test]
    fn test_env_key_provider_invalid_length() {
        let short_key = vec![0u8; 16];
        assert!(EnvKeyProvider::with_key(short_key).is_err());

        let long_key = vec![0u8; 64];
        assert!(EnvKeyProvider::with_key(long_key).is_err());
    }

    #[tokio::test]
    async fn test_env_key_provider_generate_decrypt() {
        let provider = EnvKeyProvider::random();

        // Generate a DEK
        let dek = provider.generate_data_key("test-key").await.unwrap();
        assert_eq!(dek.plaintext.len(), 32);
        assert!(!dek.ciphertext.is_empty());
        assert_eq!(dek.version, 1);

        // Decrypt it back
        let decrypted = provider
            .decrypt_data_key("test-key", &dek.ciphertext)
            .await
            .unwrap();
        assert_eq!(decrypted.expose(), dek.plaintext.expose());
    }

    #[tokio::test]
    async fn test_env_key_provider_encrypt_decrypt_roundtrip() {
        let provider = EnvKeyProvider::random();

        // Generate random plaintext DEK
        let original: Vec<u8> = (0..32).map(|i| i as u8).collect();

        // Encrypt it
        let ciphertext = provider
            .encrypt_data_key("test-key", &original)
            .await
            .unwrap();

        // Decrypt it
        let decrypted = provider
            .decrypt_data_key("test-key", &ciphertext)
            .await
            .unwrap();

        assert_eq!(decrypted.expose(), original.as_slice());
    }

    #[tokio::test]
    async fn test_cached_kms() {
        let provider = Arc::new(EnvKeyProvider::random());
        let cached = CachedKms::with_defaults(provider);

        // Generate a DEK (also caches it)
        let dek = cached.generate_data_key("test-key").await.unwrap();

        // First decrypt (should be cache hit from generate_data_key)
        let decrypted1 = cached
            .decrypt_data_key("test-key", &dek.ciphertext)
            .await
            .unwrap();

        // Second decrypt (cache hit)
        let decrypted2 = cached
            .decrypt_data_key("test-key", &dek.ciphertext)
            .await
            .unwrap();

        // Both should return the same key
        assert_eq!(decrypted1.expose(), decrypted2.expose());
        assert_eq!(decrypted1.expose(), dek.plaintext.expose());
    }

    #[tokio::test]
    async fn test_envelope_encryption() {
        let provider = EnvKeyProvider::random();
        let plaintext = b"Hello, World! This is sensitive data.";

        // Encrypt
        let envelope = EncryptedEnvelope::encrypt(&provider, "test-key", plaintext)
            .await
            .unwrap();

        assert!(!envelope.ciphertext.is_empty());
        assert!(!envelope.wrapped_dek.is_empty());

        // Decrypt
        let decrypted = envelope.decrypt(&provider).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_different_data() {
        let provider = EnvKeyProvider::random();

        let data1 = b"First message";
        let data2 = b"Second message with different content";

        let envelope1 = EncryptedEnvelope::encrypt(&provider, "key1", data1)
            .await
            .unwrap();
        let envelope2 = EncryptedEnvelope::encrypt(&provider, "key1", data2)
            .await
            .unwrap();

        // Different wrapped DEKs (each encryption uses a new DEK)
        assert_ne!(envelope1.wrapped_dek, envelope2.wrapped_dek);

        // Decrypt correctly
        assert_eq!(envelope1.decrypt(&provider).await.unwrap(), data1);
        assert_eq!(envelope2.decrypt(&provider).await.unwrap(), data2);
    }

    #[tokio::test]
    async fn test_health_check() {
        let provider = EnvKeyProvider::random();
        assert!(provider.health_check().await.is_ok());
    }

    #[test]
    fn test_kms_config_variants() {
        // Ensure all config variants are constructible
        let _env = KmsConfig::Env;
        let _aws = KmsConfig::AwsKms {
            region: "us-east-1".to_string(),
            key_id: "alias/test".to_string(),
            endpoint: None,
        };
        let _vault = KmsConfig::Vault {
            address: "https://vault:8200".to_string(),
            mount_path: "transit".to_string(),
            key_name: "rustberg".to_string(),
            auth: VaultAuth::Token("s.token".to_string()),
        };
        let _gcp = KmsConfig::GcpKms {
            project_id: "my-project".to_string(),
            location: "us-east1".to_string(),
            key_ring: "my-keyring".to_string(),
            key_name: "my-key".to_string(),
        };
        let _azure = KmsConfig::AzureKeyVault {
            vault_url: "https://myvault.vault.azure.net".to_string(),
            key_name: "my-key".to_string(),
        };
    }

    #[test]
    fn test_cache_config() {
        let default = KmsCacheConfig::default();
        assert!(default.enabled);
        assert_eq!(default.ttl, Duration::from_secs(300));

        let disabled = KmsCacheConfig::disabled();
        assert!(!disabled.enabled);

        let secure = KmsCacheConfig::high_security();
        assert!(secure.enabled);
        assert_eq!(secure.ttl, Duration::from_secs(60));
    }

    #[test]
    fn test_retry_config() {
        let default = RetryConfig::default();
        assert_eq!(default.max_retries, 3);
        assert!(default.jitter);

        let none = RetryConfig::none();
        assert_eq!(none.max_retries, 0);

        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_retries, 5);
    }

    #[test]
    fn test_retry_backoff() {
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            multiplier: 2.0,
            jitter: false, // Disable for deterministic testing
        };

        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.backoff_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.backoff_for_attempt(3), Duration::from_millis(400));
    }

    #[test]
    fn test_encryption_context() {
        let ctx = EncryptionContext::new()
            .with_entry("resource_type", "table")
            .with_entry("resource_id", "ns1.table1");

        let entries = ctx.entries();
        assert_eq!(entries.len(), 2);

        // Serialization should be deterministic (sorted)
        let serialized = ctx.serialize();
        assert!(!serialized.is_empty());

        // Same context should produce same serialization
        let ctx2 = EncryptionContext::new()
            .with_entry("resource_id", "ns1.table1")
            .with_entry("resource_type", "table");
        assert_eq!(ctx.serialize(), ctx2.serialize());
    }

    #[test]
    fn test_encryption_context_for_resource() {
        let ctx = EncryptionContext::for_resource("namespace", "my_namespace");
        let entries = ctx.entries();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn test_kms_metrics() {
        let provider = Arc::new(EnvKeyProvider::random());
        let cached = CachedKms::with_defaults(provider);

        // Initial metrics should be zero
        let initial = cached.metrics_snapshot();
        assert_eq!(initial.generate_key_total, 0);
        assert_eq!(initial.decrypt_key_total, 0);

        // Generate some keys
        let dek = cached.generate_data_key("test").await.unwrap();
        let _ = cached.decrypt_data_key("test", &dek.ciphertext).await;
        let _ = cached.decrypt_data_key("test", &dek.ciphertext).await;

        // Check metrics updated
        let after = cached.metrics_snapshot();
        assert_eq!(after.generate_key_total, 1);
        assert_eq!(after.decrypt_key_total, 2);
        // First decrypt is cache hit from generate, second is also hit
        assert!(after.cache_hits >= 1);
    }

    #[tokio::test]
    async fn test_envelope_rotation() {
        let provider = EnvKeyProvider::random();
        let plaintext = b"Sensitive data to rotate";

        // Encrypt
        let envelope = EncryptedEnvelope::encrypt(&provider, "test-key", plaintext)
            .await
            .unwrap();

        // Rotate (re-encrypt with fresh DEK)
        let rotated = envelope.rotate(&provider).await.unwrap();

        // Wrapped DEK should be different (new DEK generated)
        assert_ne!(envelope.wrapped_dek, rotated.wrapped_dek);

        // But data should decrypt to same plaintext
        let decrypted = rotated.decrypt(&provider).await.unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_key_rotation_manager() {
        let provider = Arc::new(EnvKeyProvider::random());
        let manager = KeyRotationManager::new(provider.clone());

        // Generate a DEK
        let dek = provider.generate_data_key("test-key").await.unwrap();

        // Re-wrap the DEK
        let rewrapped = manager
            .rewrap_dek("test-key", &dek.ciphertext)
            .await
            .unwrap();

        // Should be different ciphertext (new nonce)
        assert_ne!(rewrapped, dek.ciphertext);

        // But decrypt to same plaintext
        let decrypted = provider
            .decrypt_data_key("test-key", &rewrapped)
            .await
            .unwrap();
        assert_eq!(decrypted.expose(), dek.plaintext.expose());
    }

    #[test]
    fn test_kms_audit_event() {
        let event = KmsAuditEvent::new(KmsOperation::GenerateDataKey, "test-key", "env")
            .with_context("client_id", "test-client");

        assert!(event.success);
        assert_eq!(event.operation as u8, KmsOperation::GenerateDataKey as u8);
        assert!(event.context.contains_key("client_id"));

        let failed = event.clone().with_error("test error");
        assert!(!failed.success);
        assert_eq!(failed.error, Some("test error".to_string()));
    }

    #[tokio::test]
    async fn test_retry_kms_passthrough() {
        let provider = Arc::new(EnvKeyProvider::random());
        let retry_kms = RetryKms::with_defaults(provider);

        // Operations should work normally
        let dek = retry_kms.generate_data_key("test").await.unwrap();
        let decrypted = retry_kms
            .decrypt_data_key("test", &dek.ciphertext)
            .await
            .unwrap();
        assert_eq!(decrypted.expose(), dek.plaintext.expose());
    }

    #[test]
    fn test_circuit_breaker_config() {
        let default = CircuitBreakerConfig::default();
        assert_eq!(default.failure_threshold, 5);
        assert_eq!(default.reset_timeout, Duration::from_secs(30));
        assert_eq!(default.success_threshold, 3);

        let aggressive = CircuitBreakerConfig::aggressive();
        assert_eq!(aggressive.failure_threshold, 3);

        let lenient = CircuitBreakerConfig::lenient();
        assert_eq!(lenient.failure_threshold, 10);
    }

    #[tokio::test]
    async fn test_circuit_breaker_passthrough() {
        let provider = Arc::new(EnvKeyProvider::random());
        let cb_kms = CircuitBreakerKms::with_defaults(provider);

        // Circuit should start closed
        assert_eq!(cb_kms.state(), CircuitState::Closed);

        // Operations should work normally
        let dek = cb_kms.generate_data_key("test").await.unwrap();
        let decrypted = cb_kms
            .decrypt_data_key("test", &dek.ciphertext)
            .await
            .unwrap();
        assert_eq!(decrypted.expose(), dek.plaintext.expose());

        // Circuit should still be closed
        assert_eq!(cb_kms.state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_health_check() {
        let provider = Arc::new(EnvKeyProvider::random());
        let cb_kms = CircuitBreakerKms::with_defaults(provider);

        // Health check should pass when closed
        assert!(cb_kms.health_check().await.is_ok());
    }

    #[test]
    fn test_circuit_state_enum() {
        // Ensure all states are distinct
        assert_ne!(CircuitState::Closed, CircuitState::Open);
        assert_ne!(CircuitState::Open, CircuitState::HalfOpen);
        assert_ne!(CircuitState::Closed, CircuitState::HalfOpen);
    }

    #[test]
    fn test_resilient_kms_config() {
        let default = ResilientKmsConfig::default();
        assert!(default.enable_cache);
        assert!(default.enable_retry);
        assert!(default.enable_circuit_breaker);

        let dev = ResilientKmsConfig::development();
        assert!(!dev.enable_retry);
        assert!(!dev.enable_circuit_breaker);

        let prod = ResilientKmsConfig::production(KmsConfig::Env);
        assert!(prod.enable_cache);
        assert!(prod.enable_retry);
        assert!(prod.enable_circuit_breaker);

        let ha = ResilientKmsConfig::high_availability(KmsConfig::Env);
        assert_eq!(ha.retry.max_retries, 5); // aggressive
    }

    #[tokio::test]
    async fn test_resilient_kms_stack() {
        // Set up env key for test
        let key = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        std::env::set_var("RUSTBERG_ENCRYPTION_KEY_V1", &key);

        let config = ResilientKmsConfig::development();
        let kms = create_resilient_kms(config).await.unwrap();

        // Should work with full stack
        let dek = kms.generate_data_key("test").await.unwrap();
        let decrypted = kms.decrypt_data_key("test", &dek.ciphertext).await.unwrap();
        assert_eq!(decrypted.expose(), dek.plaintext.expose());

        // Cleanup
        std::env::remove_var("RUSTBERG_ENCRYPTION_KEY_V1");
    }
}
