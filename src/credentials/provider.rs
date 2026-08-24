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
///
/// Note: Custom Debug implementation redacts secret values in config.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub config: HashMap<String, String>,
}

impl std::fmt::Debug for StorageCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact sensitive config values while keeping keys visible
        let redacted_config: HashMap<&str, &str> = self
            .config
            .keys()
            .map(|k| {
                let v = if k.contains("secret") || k.contains("token") || k.contains("password") {
                    "[REDACTED]"
                } else {
                    // Keep access-key-id visible (non-sensitive identifier)
                    self.config.get(k).map(|s| s.as_str()).unwrap_or("")
                };
                (k.as_str(), v)
            })
            .collect();

        f.debug_struct("StorageCredential")
            .field("prefix", &self.prefix)
            .field("config", &redacted_config)
            .finish()
    }
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
        config.insert("s3.secret-access-key".to_string(), secret_access_key.into());
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

    /// Creates an ADLS credential from a user-delegation SAS.
    ///
    /// There is deliberately **no** `adls.account-key` constructor. An account
    /// key grants the whole storage account — every container, delete included —
    /// to anyone permitted to read one table, and it neither scopes nor expires,
    /// which is the opposite of downgrade-only. A user-delegation SAS is signed
    /// with a key obtained from the storage account under the server's own Entra
    /// identity, so what it grants is the intersection of the SAS and that
    /// identity's RBAC: like an S3 session policy, it can only narrow.
    pub fn adls(
        prefix: impl Into<String>,
        account_name: impl Into<String>,
        sas_token: impl Into<String>,
    ) -> Self {
        let mut config = HashMap::new();
        config.insert("adls.sas-token".to_string(), sas_token.into());
        config.insert("adls.account-name".to_string(), account_name.into());
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

    /// Who the credential is being minted for.
    ///
    /// Carried into the STS session name, so the cloud provider's own audit
    /// trail attributes an object read to a principal rather than only to
    /// Rustberg's role. Without it CloudTrail can say which table was read and
    /// not by whom, and joining the two trails means correlating on time.
    pub principal_id: Option<String>,
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
            principal_id: None,
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
            principal_id: None,
        }
    }

    /// Names the principal this credential is for.
    pub fn for_principal(mut self, principal_id: impl Into<String>) -> Self {
        self.principal_id = Some(principal_id.into());
        self
    }

    /// The STS session name, which is what CloudTrail records.
    ///
    /// Principal first, then table: AWS caps the name at 64 characters and
    /// truncates the tail, so the identity survives a long namespace path.
    /// Characters outside the permitted set are dropped rather than escaped —
    /// AWS rejects them, and a rejected `AssumeRole` is a vend that fails for a
    /// reason nothing in the message names.
    pub fn session_name(&self) -> String {
        let principal = self.principal_id.as_deref().unwrap_or(&self.tenant_id);
        format!("rustberg-{}-{}", principal, self.table_name)
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(64)
            .collect()
    }
}

/// How long to wait for a cloud provider's token endpoint to accept a
/// connection.
///
/// Gated with [`exchange_client`] on the two providers that perform an HTTPS
/// exchange of their own. AWS goes through its own SDK, which brings its own
/// timeouts, so a build with only `aws-credentials` has no caller for these.
#[cfg(any(feature = "gcp-credentials", feature = "azure-credentials"))]
const EXCHANGE_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait for it to answer.
///
/// Comfortably under the server's own 30-second request timeout, for the same
/// reason a federated mount's client is ([`catalog::rest`]): a stalled exchange
/// has to surface as an error naming the exchange, not as a request timeout
/// naming nothing. `reqwest`'s default is *no* timeout, so a token endpoint that
/// accepts a connection and never answers would otherwise hold a `loadTable`
/// open until the outer layer gave up on it.
///
/// [`catalog::rest`]: crate::catalog
#[cfg(any(feature = "gcp-credentials", feature = "azure-credentials"))]
const EXCHANGE_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The HTTP client every credential exchange uses.
///
/// One constructor rather than a `Client::new()` per provider, because the two
/// that need it are on the `loadTable` path and a client with no timeout there
/// is not a detail either of them would have thought to configure.
#[cfg(any(feature = "gcp-credentials", feature = "azure-credentials"))]
#[must_use]
pub fn exchange_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(EXCHANGE_CONNECT_TIMEOUT)
        .timeout(EXCHANGE_REQUEST_TIMEOUT)
        .build()
        // Falls back rather than failing: the builder errors only when the TLS
        // backend cannot be initialised, and a provider that cannot vend is
        // better reported by the exchange than by a panic at construction.
        .unwrap_or_default()
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
    fn test_credential_request_session_name() {
        let request = StorageCredentialRequest::read_only(
            "tenant-123",
            vec!["prod".to_string(), "analytics".to_string()],
            "sales_data",
            "s3://bucket/warehouse/prod/analytics/sales_data",
        );

        let session_name = request.session_name();
        assert_eq!(session_name, "rustberg-tenant-123-sales_data");
        assert!(session_name.len() <= 64);

        // Naming the principal is what lets CloudTrail attribute the access.
        let named = request.clone().for_principal("svc-etl");
        assert_eq!(named.session_name(), "rustberg-svc-etl-sales_data");

        // A long path must not push the identity past the 64-character cap.
        let deep = StorageCredentialRequest::read_only(
            "tenant-123",
            (0..20).map(|i| format!("level{i}")).collect(),
            "sales_data",
            "s3://bucket/x",
        )
        .for_principal("svc-etl");
        assert!(deep.session_name().starts_with("rustberg-svc-etl-"));
        assert!(deep.session_name().len() <= 64);
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

    #[test]
    fn test_credential_debug_redacts_secrets() {
        let cred = StorageCredential::s3(
            "s3://bucket/",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            Some("session-token-value".to_string()),
        );

        let debug_output = format!("{:?}", cred);

        // Access key ID should be visible (non-sensitive identifier)
        assert!(
            debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
            "access-key-id should be visible in debug output"
        );
        // Secret access key must be redacted
        assert!(
            !debug_output.contains("wJalrXUtnFEMI"),
            "secret-access-key must be redacted"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "redacted placeholder must appear"
        );
        // Session token must be redacted
        assert!(
            !debug_output.contains("session-token-value"),
            "session-token must be redacted"
        );
    }

    /// The SAS is the secret; the account name is not, and an operator reading a
    /// log needs it to tell which account a credential was for.
    #[test]
    fn adls_debug_redacts_the_sas_but_not_the_account() {
        let cred = StorageCredential::adls(
            "abfss://fs@acct.dfs.core.windows.net/wh/db/t/",
            "acct",
            "sv=2023-11-03&sig=SUPER-SECRET-SIGNATURE",
        );

        let debug_output = format!("{:?}", cred);

        assert!(
            !debug_output.contains("SUPER-SECRET-SIGNATURE"),
            "the SAS must be redacted"
        );
        assert!(debug_output.contains("[REDACTED]"));
        assert!(
            debug_output.contains("acct"),
            "the account name identifies the credential and stays visible"
        );
    }

    #[test]
    fn test_credential_debug_redacts_gcs_token() {
        let cred = StorageCredential::gcs("gs://bucket/", "ya29.super-secret-token");

        let debug_output = format!("{:?}", cred);

        assert!(
            !debug_output.contains("ya29.super-secret-token"),
            "GCS OAuth2 token must be redacted"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }
}
