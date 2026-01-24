//! Cryptographic primitives and key management.
//!
//! This module provides encryption-at-rest for storage backends,
//! secrets management, and key derivation.

pub mod encryption;
pub mod kms;
pub mod secrets;

pub use encryption::{Aes256GcmProvider, EncryptionProvider, NoopEncryptionProvider};
pub use kms::{
    create_kms, create_resilient_kms, CachedKms, CircuitBreakerConfig, CircuitBreakerKms,
    CircuitState, DataEncryptionKey, EncryptedEnvelope, EncryptionContext, EnvKeyProvider,
    KeyManagementService, KeyRotationManager, KeyRotationResult, KmsAuditEvent,
    KmsCacheConfig, KmsConfig, KmsError, KmsMetrics, KmsMetricsSnapshot, KmsOperation,
    ResilientKmsConfig, RetryConfig, RetryKms, VaultAuth,
};
#[cfg(feature = "aws-kms")]
pub use kms::AwsKmsProvider;
#[cfg(feature = "vault-kms")]
pub use kms::VaultKmsProvider;
#[cfg(feature = "gcp-kms")]
pub use kms::GcpKmsProvider;
#[cfg(feature = "azure-kms")]
pub use kms::AzureKeyVaultProvider;
pub use secrets::{EncryptionKey, SecretBytes, SecretKey, SecretString};
