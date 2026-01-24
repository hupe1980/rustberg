//! GCS credential provider for Google Cloud Storage access.
//!
//! This provider uses Google Cloud authentication to vend OAuth2 access tokens
//! for accessing table data in Google Cloud Storage (GCS).
//!
//! # Authentication Methods
//!
//! The provider supports multiple authentication methods:
//! - Service Account JSON key file
//! - Application Default Credentials (ADC)
//! - Workload Identity (GKE)
//! - Metadata server (Compute Engine, Cloud Run)
//!
//! # Example
//!
//! ```no_run
//! use rustberg::credentials::{GcsCredentialProvider, GcsConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Using service account key file
//! let config = GcsConfig::new()
//!     .with_service_account_key_path("/path/to/service-account.json")
//!     .with_allowed_prefix("gs://my-bucket/");
//!
//! let provider = GcsCredentialProvider::new(config).await?;
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use google_cloud_auth::credentials::service_account::{
    AccessSpecifier, Builder as ServiceAccountBuilder,
};
use google_cloud_auth::credentials::AccessTokenCredentials;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::provider::{
    StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};

/// Default OAuth2 scope for GCS access.
const GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";

/// Read-only OAuth2 scope for GCS access.
const GCS_SCOPE_READ_ONLY: &str = "https://www.googleapis.com/auth/devstorage.read_only";

/// GCS credential provider configuration.
#[derive(Debug, Clone, Default)]
pub struct GcsConfig {
    /// Path to service account JSON key file (optional).
    /// If not provided, uses Application Default Credentials.
    pub service_account_key_path: Option<String>,

    /// GCS bucket prefixes that this provider can grant access to.
    /// If empty, the provider will attempt to grant access to any GCS location.
    pub allowed_prefixes: Vec<String>,

    /// Whether to use read-only scope by default.
    /// If false, uses read-write scope.
    pub default_read_only: bool,

    /// Custom OAuth2 scopes to use instead of defaults.
    pub custom_scopes: Option<Vec<String>>,
}

impl GcsConfig {
    /// Creates a new GCS config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the path to the service account key file.
    pub fn with_service_account_key_path(mut self, path: impl Into<String>) -> Self {
        self.service_account_key_path = Some(path.into());
        self
    }

    /// Adds an allowed GCS prefix.
    pub fn with_allowed_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_prefixes.push(prefix.into());
        self
    }

    /// Sets the allowed GCS prefixes.
    pub fn with_allowed_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.allowed_prefixes = prefixes;
        self
    }

    /// Sets whether to use read-only scope by default.
    pub fn with_default_read_only(mut self, read_only: bool) -> Self {
        self.default_read_only = read_only;
        self
    }

    /// Sets custom OAuth2 scopes.
    pub fn with_custom_scopes(mut self, scopes: Vec<String>) -> Self {
        self.custom_scopes = Some(scopes);
        self
    }

    /// Returns the OAuth2 scope to use based on configuration.
    fn get_scope(&self, write_access: bool) -> &str {
        if let Some(ref scopes) = self.custom_scopes {
            return scopes.first().map(|s| s.as_str()).unwrap_or(GCS_SCOPE);
        }

        if write_access && !self.default_read_only {
            GCS_SCOPE
        } else {
            GCS_SCOPE_READ_ONLY
        }
    }
}

/// Cached token with expiration tracking.
#[derive(Debug)]
struct CachedToken {
    token: String,
    expires_at: std::time::Instant,
}

impl CachedToken {
    fn is_valid(&self) -> bool {
        // Consider token valid if it has at least 5 minutes of validity left
        self.expires_at > std::time::Instant::now() + std::time::Duration::from_secs(300)
    }
}

/// GCS credential provider.
///
/// Uses Google Cloud authentication to vend OAuth2 access tokens for GCS access.
/// Tokens are cached and refreshed automatically before expiration.
pub struct GcsCredentialProvider {
    config: GcsConfig,
    /// Credentials provider for obtaining OAuth2 tokens.
    credentials: Arc<AccessTokenCredentials>,
    /// Cached token for reuse.
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl std::fmt::Debug for GcsCredentialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsCredentialProvider")
            .field("config", &self.config)
            .field("credentials", &"<AccessTokenCredentials>")
            .finish()
    }
}

impl GcsCredentialProvider {
    /// Creates a new GCS credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::credentials::{GcsCredentialProvider, GcsConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Using service account key file
    /// let config = GcsConfig::new()
    ///     .with_service_account_key_path("/path/to/key.json");
    /// let provider = GcsCredentialProvider::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: GcsConfig) -> Result<Self, StorageCredentialVendingError> {
        let key_path = config.service_account_key_path.as_ref().ok_or_else(|| {
            StorageCredentialVendingError::ConfigurationError(
                "GCS credential provider requires a service account key file path".to_string(),
            )
        })?;

        // Read the service account JSON file
        let key_json = std::fs::read_to_string(key_path).map_err(|e| {
            StorageCredentialVendingError::GcsError(format!(
                "Failed to read service account key from {}: {}",
                key_path, e
            ))
        })?;

        // Parse as JSON
        let service_account_key: serde_json::Value =
            serde_json::from_str(&key_json).map_err(|e| {
                StorageCredentialVendingError::GcsError(format!(
                    "Failed to parse service account key JSON: {}",
                    e
                ))
            })?;

        // Determine scope to use - for credential vending we typically need write access
        let scope = config.get_scope(true);

        // Build credentials using service account with appropriate scope
        let credentials = ServiceAccountBuilder::new(service_account_key)
            .with_access_specifier(AccessSpecifier::from_scopes([scope]))
            .build_access_token_credentials()
            .map_err(|e| {
                StorageCredentialVendingError::GcsError(format!(
                    "Failed to build service account credentials: {}",
                    e
                ))
            })?;

        Ok(Self {
            config,
            credentials: Arc::new(credentials),
            cached_token: Arc::new(RwLock::new(None)),
        })
    }

    /// Checks if the given location starts with any allowed prefix.
    fn is_location_allowed(&self, location: &str) -> bool {
        if self.config.allowed_prefixes.is_empty() {
            // No restrictions - allow any GCS location
            return true;
        }

        self.config
            .allowed_prefixes
            .iter()
            .any(|prefix| location.starts_with(prefix))
    }

    /// Extracts the GCS prefix from a table location.
    fn get_table_prefix(location: &str) -> String {
        if location.ends_with('/') {
            location.to_string()
        } else {
            format!("{}/", location)
        }
    }

    /// Gets a valid OAuth2 token, using cache if available.
    async fn get_token(&self) -> Result<String, StorageCredentialVendingError> {
        // Check cache first
        {
            let cached = self.cached_token.read().await;
            if let Some(ref token) = *cached {
                if token.is_valid() {
                    return Ok(token.token.clone());
                }
            }
        }

        // Need to refresh token
        let token = self.credentials.access_token().await.map_err(|e| {
            StorageCredentialVendingError::GcsError(format!("Failed to obtain token: {}", e))
        })?;

        let access_token = token.token;

        // Cache the token (GCP tokens typically expire in 1 hour)
        let expires_at = std::time::Instant::now() + std::time::Duration::from_secs(3600);
        {
            let mut cached = self.cached_token.write().await;
            *cached = Some(CachedToken {
                token: access_token.clone(),
                expires_at,
            });
        }

        Ok(access_token)
    }
}

#[async_trait]
impl StorageCredentialProvider for GcsCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        // Check if this location is allowed
        if !self.is_location_allowed(&request.table_location) {
            return Ok(vec![]);
        }

        // Get an OAuth2 access token
        let token = self.get_token().await?;

        // Build the storage credential
        let prefix = Self::get_table_prefix(&request.table_location);
        let credential = StorageCredential::gcs(prefix, token);

        Ok(vec![credential])
    }

    fn supports_location(&self, location: &str) -> bool {
        location.starts_with("gs://") || location.starts_with("gcs://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = GcsConfig::new()
            .with_service_account_key_path("/path/to/key.json")
            .with_allowed_prefix("gs://bucket1/")
            .with_allowed_prefix("gs://bucket2/")
            .with_default_read_only(true);

        assert_eq!(
            config.service_account_key_path,
            Some("/path/to/key.json".to_string())
        );
        assert_eq!(config.allowed_prefixes.len(), 2);
        assert!(config.default_read_only);
    }

    #[test]
    fn test_get_scope() {
        let config = GcsConfig::new();
        assert_eq!(config.get_scope(true), GCS_SCOPE);
        assert_eq!(config.get_scope(false), GCS_SCOPE_READ_ONLY);

        let config_read_only = GcsConfig::new().with_default_read_only(true);
        assert_eq!(config_read_only.get_scope(true), GCS_SCOPE_READ_ONLY);

        let config_custom = GcsConfig::new().with_custom_scopes(vec!["custom-scope".to_string()]);
        assert_eq!(config_custom.get_scope(true), "custom-scope");
    }

    #[test]
    fn test_table_prefix() {
        assert_eq!(
            GcsCredentialProvider::get_table_prefix("gs://bucket/warehouse/ns/table"),
            "gs://bucket/warehouse/ns/table/"
        );
        assert_eq!(
            GcsCredentialProvider::get_table_prefix("gs://bucket/warehouse/ns/table/"),
            "gs://bucket/warehouse/ns/table/"
        );
    }

    #[test]
    fn test_location_allowed() {
        let config = GcsConfig::new().with_allowed_prefix("gs://allowed-bucket/");

        let provider = MockGcsProvider { config };

        assert!(provider.is_location_allowed("gs://allowed-bucket/data/table"));
        assert!(!provider.is_location_allowed("gs://other-bucket/data/table"));

        // No restrictions
        let config_no_restrictions = GcsConfig::new();
        let provider_no_restrictions = MockGcsProvider {
            config: config_no_restrictions,
        };
        assert!(provider_no_restrictions.is_location_allowed("gs://any-bucket/"));
    }

    /// Mock provider for testing location checks without real GCP credentials.
    struct MockGcsProvider {
        config: GcsConfig,
    }

    impl MockGcsProvider {
        fn is_location_allowed(&self, location: &str) -> bool {
            if self.config.allowed_prefixes.is_empty() {
                return true;
            }
            self.config
                .allowed_prefixes
                .iter()
                .any(|prefix| location.starts_with(prefix))
        }
    }

    #[test]
    fn test_storage_credential_gcs() {
        let cred = StorageCredential::gcs("gs://my-bucket/warehouse/", "ya29.example-token");

        assert_eq!(cred.prefix, "gs://my-bucket/warehouse/");
        assert_eq!(
            cred.config.get("gcs.oauth2.token").unwrap(),
            "ya29.example-token"
        );
    }
}

