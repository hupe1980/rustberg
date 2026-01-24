//! Core traits and types for storage credential vending.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Errors that can occur during credential vending.
#[derive(Debug, Error)]
pub enum StorageCredentialVendingError {
    /// AWS STS error during credential vending.
    #[error("AWS STS error: {0}")]
    AwsStsError(String),

    /// GCS credential error.
    #[error("GCS credential error: {0}")]
    GcsError(String),

    /// Azure credential error.
    #[error("Azure credential error: {0}")]
    AzureError(String),

    /// The requested storage location is not supported by this provider.
    #[error("Unsupported storage location: {0}")]
    UnsupportedLocation(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Permission denied for the requested operation.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// A vended storage credential with a prefix indicating where it applies.
///
/// Clients should select the credential with the longest matching prefix
/// for a given storage location.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCredential {
    /// Storage location prefix where this credential is valid (e.g., "s3://bucket/prefix/").
    pub prefix: String,

    /// Configuration map containing the actual credentials.
    ///
    /// For S3, this typically includes:
    /// - `s3.access-key-id` - AWS access key ID
    /// - `s3.secret-access-key` - AWS secret access key  
    /// - `s3.session-token` - AWS session token (for temporary credentials)
    ///
    /// For GCS, this typically includes:
    /// - `gcs.oauth2.token` - OAuth2 access token
    ///
    /// For Azure, this typically includes:
    /// - `adls.sas-token.<account>` - SAS token for the storage account
    pub config: HashMap<String, String>,
}

impl StorageCredential {
    /// Creates a new storage credential.
    pub fn new(prefix: impl Into<String>, config: HashMap<String, String>) -> Self {
        Self {
            prefix: prefix.into(),
            config,
        }
    }

    /// Creates an S3 credential from AWS temporary credentials.
    pub fn s3(
        prefix: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
    ) -> Self {
        let mut config = HashMap::new();
        config.insert("s3.access-key-id".to_string(), access_key_id.into());
        config.insert(
            "s3.secret-access-key".to_string(),
            secret_access_key.into(),
        );
        if let Some(token) = session_token {
            config.insert("s3.session-token".to_string(), token);
        }
        Self::new(prefix, config)
    }

    /// Creates a GCS credential from an OAuth2 token.
    pub fn gcs(prefix: impl Into<String>, oauth2_token: impl Into<String>) -> Self {
        let mut config = HashMap::new();
        config.insert("gcs.oauth2.token".to_string(), oauth2_token.into());
        Self::new(prefix, config)
    }

    /// Creates an Azure ADLS credential from a SAS token.
    pub fn azure(
        prefix: impl Into<String>,
        account: impl Into<String>,
        sas_token: impl Into<String>,
    ) -> Self {
        let mut config = HashMap::new();
        let key = format!("adls.sas-token.{}", account.into());
        config.insert(key, sas_token.into());
        Self::new(prefix, config)
    }
}

/// Request for vending storage credentials.
#[derive(Debug, Clone)]
pub struct StorageCredentialRequest {
    /// The tenant ID requesting credentials.
    pub tenant_id: String,

    /// The namespace of the table.
    pub namespace: Vec<String>,

    /// The table name.
    pub table_name: String,

    /// The table's storage location (e.g., "s3://bucket/warehouse/ns/table").
    pub table_location: String,

    /// Whether write access is required.
    pub write_access: bool,
}

impl StorageCredentialRequest {
    /// Creates a new credential request for read-only access.
    pub fn read_only(
        tenant_id: impl Into<String>,
        namespace: Vec<String>,
        table_name: impl Into<String>,
        table_location: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            namespace,
            table_name: table_name.into(),
            table_location: table_location.into(),
            write_access: false,
        }
    }

    /// Creates a new credential request with write access.
    pub fn with_write_access(
        tenant_id: impl Into<String>,
        namespace: Vec<String>,
        table_name: impl Into<String>,
        table_location: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            namespace,
            table_name: table_name.into(),
            table_location: table_location.into(),
            write_access: true,
        }
    }

    /// Returns a session identifier for audit purposes.
    pub fn session_name(&self) -> String {
        let ns = self.namespace.join("-");
        format!("rustberg-{}-{}-{}", self.tenant_id, ns, self.table_name)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64) // AWS session name limit
            .collect()
    }
}

/// Trait for storage credential providers.
///
/// Implementations vend temporary credentials for accessing data in cloud storage.
/// Each provider is responsible for a specific cloud platform (AWS, GCS, Azure).
#[async_trait]
pub trait StorageCredentialProvider: Send + Sync + fmt::Debug {
    /// Vends credentials for accessing the specified table's storage.
    ///
    /// Returns a list of credentials, one for each storage prefix the provider
    /// can grant access to. Returns an empty list if the provider cannot grant
    /// access to any locations for this request.
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError>;

    /// Returns true if this provider can handle the given storage location.
    fn supports_location(&self, location: &str) -> bool;
}

/// A no-op credential provider that returns empty credentials.
///
/// Use this when credential vending is disabled or for local file system storage.
#[derive(Debug, Clone, Default)]
pub struct NoopCredentialProvider;

impl NoopCredentialProvider {
    /// Creates a new no-op credential provider.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StorageCredentialProvider for NoopCredentialProvider {
    async fn vend_credentials(
        &self,
        _request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        Ok(vec![])
    }

    fn supports_location(&self, _location: &str) -> bool {
        // Noop provider doesn't claim to support any location
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_credential_s3() {
        let cred = StorageCredential::s3(
            "s3://my-bucket/warehouse/",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("token123".to_string()),
        );

        assert_eq!(cred.prefix, "s3://my-bucket/warehouse/");
        assert_eq!(
            cred.config.get("s3.access-key-id").unwrap(),
            "AKIAIOSFODNN7EXAMPLE"
        );
        assert_eq!(
            cred.config.get("s3.secret-access-key").unwrap(),
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        assert_eq!(cred.config.get("s3.session-token").unwrap(), "token123");
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

    #[test]
    fn test_storage_credential_azure() {
        let cred = StorageCredential::azure(
            "abfss://container@account.dfs.core.windows.net/warehouse/",
            "account",
            "?sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacupitfx",
        );

        assert_eq!(
            cred.prefix,
            "abfss://container@account.dfs.core.windows.net/warehouse/"
        );
        assert_eq!(
            cred.config.get("adls.sas-token.account").unwrap(),
            "?sv=2021-06-08&ss=bfqt&srt=sco&sp=rwdlacupitfx"
        );
    }

    #[test]
    fn test_credential_request_session_name() {
        let request = StorageCredentialRequest::read_only(
            "tenant-123",
            vec!["prod".to_string(), "analytics".to_string()],
            "sales_data",
            "s3://bucket/warehouse/prod/analytics/sales_data",
        );

        let session_name = request.session_name();
        assert!(session_name.starts_with("rustberg-tenant-123-prod-analytics-sales_data"));
        assert!(session_name.len() <= 64);
    }

    #[tokio::test]
    async fn test_noop_provider() {
        let provider = NoopCredentialProvider::new();
        let request = StorageCredentialRequest::read_only(
            "tenant-1",
            vec!["ns".to_string()],
            "table",
            "s3://bucket/ns/table",
        );

        let credentials = provider.vend_credentials(&request).await.unwrap();
        assert!(credentials.is_empty());
        assert!(!provider.supports_location("s3://bucket/"));
    }
}
