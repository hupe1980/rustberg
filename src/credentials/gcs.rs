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
use google_cloud_auth::credentials::AccessTokenCredentials;
use google_cloud_auth::credentials::service_account::{
    AccessSpecifier, Builder as ServiceAccountBuilder,
};
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
    /// Cached source token. Only ever the *input* to downscoping — the token
    /// handed to a client is derived per request and never cached.
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    /// Client for the STS downscoping exchange.
    http: reqwest::Client,
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
    /// // The prefixes are the provider's whole scope: it vends for these and
    /// // nothing else, and naming none means it vends for nothing.
    /// let config = GcsConfig::new()
    ///     .with_service_account_key_path("/path/to/key.json")
    ///     .with_allowed_prefix("gs://my-warehouse/");
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
            http: reqwest::Client::new(),
        })
    }

    /// Whether `location` falls under one of the configured prefixes.
    ///
    /// Containment is segment-wise ([`crate::location::is_within`]), not a
    /// string prefix test: `gs://bucket/wh-evil/t` merely *spells* like
    /// `gs://bucket/wh` and must not be admitted by it.
    ///
    /// An empty prefix list grants nothing — see [`crate::location::is_vendable`]
    /// for why that direction and not the other.
    fn is_location_allowed(config: &GcsConfig, location: &str) -> bool {
        crate::location::is_vendable(&config.allowed_prefixes, location)
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
            if let Some(ref token) = *cached
                && token.is_valid()
            {
                return Ok(token.token.clone());
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

    /// Splits a `gs://bucket/key/prefix` location into `(bucket, key_prefix)`.
    fn split_location(location: &str) -> Option<(&str, &str)> {
        let rest = location
            .strip_prefix("gs://")
            .or_else(|| location.strip_prefix("gcs://"))?;
        match rest.split_once('/') {
            Some((bucket, key)) => Some((bucket, key.trim_end_matches('/'))),
            None => Some((rest, "")),
        }
    }

    /// Builds a Credential Access Boundary scoped to one table's prefix.
    ///
    /// A raw service-account token carries every permission the account has, on
    /// every bucket. Google's downscoping exchange trades it for a token bounded
    /// by these rules, so what the client receives can only be narrower.
    ///
    /// The boundary names the bucket as its resource and constrains objects with
    /// an `availabilityCondition` on the name prefix; `inRole:` sets the ceiling
    /// on what is permitted there.
    fn access_boundary(bucket: &str, key_prefix: &str, write_access: bool) -> serde_json::Value {
        let role = if write_access {
            "inRole:roles/storage.objectAdmin"
        } else {
            "inRole:roles/storage.objectViewer"
        };

        // An empty prefix means the whole bucket; anything else is bounded to
        // objects whose name starts with the table's prefix.
        let condition = if key_prefix.is_empty() {
            None
        } else {
            Some(serde_json::json!({
                "title": "table-prefix",
                "expression": format!(
                    "resource.name.startsWith('projects/_/buckets/{bucket}/objects/{key_prefix}/')"
                )
            }))
        };

        let mut rule = serde_json::json!({
            "availableResource": format!("//storage.googleapis.com/projects/_/buckets/{bucket}"),
            "availablePermissions": [role],
        });
        if let Some(condition) = condition {
            rule["availabilityCondition"] = condition;
        }

        serde_json::json!({ "accessBoundary": { "accessBoundaryRules": [rule] } })
    }

    /// Exchanges a full-scope token for one bounded by `boundary`.
    ///
    /// Uses Google's STS token-exchange endpoint. A failure here must not fall
    /// back to the original token: that would hand out exactly the broad
    /// credential the exchange exists to avoid.
    async fn downscope(
        &self,
        token: &str,
        boundary: serde_json::Value,
    ) -> Result<String, StorageCredentialVendingError> {
        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
        }

        let response = self
            .http
            .post("https://sts.googleapis.com/v1/token")
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("subject_token", token),
                ("options", &boundary.to_string()),
            ])
            .send()
            .await
            .map_err(|e| {
                StorageCredentialVendingError::GcsError(format!("Downscoping request failed: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(StorageCredentialVendingError::GcsError(format!(
                "Downscoping rejected with {status}: {body}"
            )));
        }

        Ok(response
            .json::<TokenResponse>()
            .await
            .map_err(|e| {
                StorageCredentialVendingError::GcsError(format!(
                    "Malformed downscoping response: {e}"
                ))
            })?
            .access_token)
    }
}

#[async_trait]
impl StorageCredentialProvider for GcsCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        // Check if this location is allowed
        if !Self::is_location_allowed(&self.config, &request.table_location) {
            return Ok(vec![]);
        }

        let (bucket, key_prefix) =
            Self::split_location(&request.table_location).ok_or_else(|| {
                StorageCredentialVendingError::GcsError(format!(
                    "Cannot scope credentials: '{}' is not a GCS location",
                    request.table_location
                ))
            })?;

        // The service-account token is the ceiling, not the credential. It is
        // exchanged for one bounded to this table and this access level, so the
        // client never receives the account's full rights — which is what an
        // earlier version handed out, cached and shared across every caller.
        let source = self.get_token().await?;
        let boundary = Self::access_boundary(bucket, key_prefix, request.write_access);
        let scoped = self.downscope(&source, boundary).await?;

        let prefix = Self::get_table_prefix(&request.table_location);
        Ok(vec![StorageCredential::gcs(prefix, scoped)])
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
        let allowed = |loc: &str| GcsCredentialProvider::is_location_allowed(&config, loc);

        assert!(allowed("gs://allowed-bucket/data/table"));
        assert!(!allowed("gs://other-bucket/data/table"));

        // Nothing configured grants nothing, rather than everything.
        let unscoped = GcsConfig::new();
        assert!(!GcsCredentialProvider::is_location_allowed(
            &unscoped,
            "gs://any-bucket/"
        ));
    }

    /// A bucket that merely *spells* like an allowed prefix is a different
    /// bucket. A `starts_with` test admits it; containment must not.
    #[test]
    fn a_sibling_prefix_is_not_allowed() {
        let config = GcsConfig::new().with_allowed_prefix("gs://bucket/wh");
        let allowed = |loc: &str| GcsCredentialProvider::is_location_allowed(&config, loc);

        assert!(allowed("gs://bucket/wh/db/events"));
        assert!(!allowed("gs://bucket/wh-evil/db/events"));
        assert!(!allowed("gs://bucket/whatever"));
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
    // ── Access boundary scoping ─────────────────────────────────────────

    #[test]
    fn splits_gcs_locations() {
        assert_eq!(
            GcsCredentialProvider::split_location("gs://bucket/wh/db/t"),
            Some(("bucket", "wh/db/t"))
        );
        assert_eq!(
            GcsCredentialProvider::split_location("gs://bucket/wh/db/t/"),
            Some(("bucket", "wh/db/t"))
        );
        assert_eq!(
            GcsCredentialProvider::split_location("gs://bucket"),
            Some(("bucket", ""))
        );
        assert_eq!(GcsCredentialProvider::split_location("s3://b/x"), None);
    }

    #[test]
    fn boundary_is_scoped_to_the_table_prefix() {
        let b = GcsCredentialProvider::access_boundary("bucket", "wh/db/events", false);
        let rule = &b["accessBoundary"]["accessBoundaryRules"][0];

        assert_eq!(
            rule["availableResource"],
            "//storage.googleapis.com/projects/_/buckets/bucket"
        );
        let expr = rule["availabilityCondition"]["expression"]
            .as_str()
            .unwrap();
        assert!(
            expr.contains("buckets/bucket/objects/wh/db/events/"),
            "{expr}"
        );
    }

    /// A read-only request must not carry an object-write role. An earlier
    /// version returned the raw service-account token, so `write_access` was
    /// discarded entirely.
    #[test]
    fn read_only_request_gets_viewer_role() {
        let b = GcsCredentialProvider::access_boundary("bucket", "wh/db/t", false);
        let perms = &b["accessBoundary"]["accessBoundaryRules"][0]["availablePermissions"];
        assert_eq!(perms[0], "inRole:roles/storage.objectViewer");
    }

    #[test]
    fn write_request_gets_admin_role() {
        let b = GcsCredentialProvider::access_boundary("bucket", "wh/db/t", true);
        let perms = &b["accessBoundary"]["accessBoundaryRules"][0]["availablePermissions"];
        assert_eq!(perms[0], "inRole:roles/storage.objectAdmin");
    }

    #[test]
    fn sibling_tables_get_different_boundaries() {
        let a = GcsCredentialProvider::access_boundary("bucket", "wh/db/a", true);
        let b = GcsCredentialProvider::access_boundary("bucket", "wh/db/b", true);
        assert_ne!(
            a["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"],
            b["accessBoundary"]["accessBoundaryRules"][0]["availabilityCondition"]
        );
    }

    /// A bucket-root location has nothing to constrain, so no condition is set
    /// rather than one that would never match.
    #[test]
    fn bucket_root_has_no_condition() {
        let b = GcsCredentialProvider::access_boundary("bucket", "", false);
        assert!(
            b["accessBoundary"]["accessBoundaryRules"][0]
                .get("availabilityCondition")
                .is_none()
        );
    }
}
