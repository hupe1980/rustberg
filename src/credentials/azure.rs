//! Azure credential provider for Azure Blob Storage / ADLS Gen2 access.
//!
//! This provider vends Azure storage credentials for accessing table data in Azure storage.
//!
//! # Authentication Methods
//!
//! The provider supports multiple authentication methods:
//! - **SAS Token** - Pre-generated Shared Access Signature token
//! - **Account Key** - Storage account access key
//! - **Connection String** - Full Azure connection string
//!
//! # Example
//!
//! ```no_run
//! use rustberg::credentials::{AzureCredentialProvider, AzureConfig};
//!
//! // Using SAS token
//! let config = AzureConfig::new()
//!     .with_account_name("mystorageaccount")
//!     .with_sas_token("sv=2022-11-02&ss=b&srt=sco&sp=rwdlacitfx...")
//!     .with_allowed_prefix("abfss://container@mystorageaccount.dfs.core.windows.net/");
//!
//! let provider = AzureCredentialProvider::new(config)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # ADLS Gen2 URIs
//!
//! The provider supports multiple URI schemes for Azure storage:
//! - `abfss://container@account.dfs.core.windows.net/path` - ADLS Gen2 (secure)
//! - `abfs://container@account.dfs.core.windows.net/path` - ADLS Gen2
//! - `wasbs://container@account.blob.core.windows.net/path` - Blob Storage (secure)
//! - `wasb://container@account.blob.core.windows.net/path` - Blob Storage
//!
//! # Credential Config Keys
//!
//! The credentials returned use the following Iceberg config keys:
//! - `adls.sas-token.<account>` - SAS token for the storage account
//! - `adls.account-key.<account>` - Storage account key
//! - `adls.connection-string.<account>` - Full connection string

use async_trait::async_trait;
use std::collections::HashMap;

use super::provider::{
    StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};

/// Azure credential provider configuration.
#[derive(Debug, Clone, Default)]
pub struct AzureConfig {
    /// Azure storage account name.
    pub account_name: Option<String>,

    /// SAS token for the storage account (without leading `?`).
    pub sas_token: Option<String>,

    /// Storage account access key.
    pub account_key: Option<String>,

    /// Full connection string (alternative to individual settings).
    pub connection_string: Option<String>,

    /// Azure storage prefixes that this provider can grant access to.
    /// If empty, the provider will attempt to grant access to any Azure location.
    pub allowed_prefixes: Vec<String>,
}

impl AzureConfig {
    /// Creates a new Azure config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the Azure storage account name.
    pub fn with_account_name(mut self, name: impl Into<String>) -> Self {
        self.account_name = Some(name.into());
        self
    }

    /// Sets the SAS token (without leading `?`).
    pub fn with_sas_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        // Strip leading `?` if present
        self.sas_token = Some(token.strip_prefix('?').unwrap_or(&token).to_string());
        self
    }

    /// Sets the storage account access key.
    pub fn with_account_key(mut self, key: impl Into<String>) -> Self {
        self.account_key = Some(key.into());
        self
    }

    /// Sets the full connection string.
    pub fn with_connection_string(mut self, conn_string: impl Into<String>) -> Self {
        self.connection_string = Some(conn_string.into());
        self
    }

    /// Adds an allowed Azure storage prefix.
    pub fn with_allowed_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_prefixes.push(prefix.into());
        self
    }

    /// Sets the allowed Azure storage prefixes.
    pub fn with_allowed_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.allowed_prefixes = prefixes;
        self
    }

    /// Validates the configuration.
    fn validate(&self) -> Result<(), StorageCredentialVendingError> {
        // Must have account name (unless using connection string)
        if self.connection_string.is_none() && self.account_name.is_none() {
            return Err(StorageCredentialVendingError::ConfigurationError(
                "Azure credential provider requires either account_name or connection_string"
                    .to_string(),
            ));
        }

        // Must have at least one credential type
        if self.sas_token.is_none()
            && self.account_key.is_none()
            && self.connection_string.is_none()
        {
            return Err(StorageCredentialVendingError::ConfigurationError(
                "Azure credential provider requires sas_token, account_key, or connection_string"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Azure credential provider.
///
/// Vends Azure storage credentials for accessing table data in Azure Blob Storage
/// or ADLS Gen2.
#[derive(Debug)]
pub struct AzureCredentialProvider {
    config: AzureConfig,
}

impl AzureCredentialProvider {
    /// Creates a new Azure credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::credentials::{AzureCredentialProvider, AzureConfig};
    ///
    /// let config = AzureConfig::new()
    ///     .with_account_name("mystorageaccount")
    ///     .with_sas_token("sv=2022-11-02&ss=b&srt=sco...");
    /// let provider = AzureCredentialProvider::new(config)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn new(config: AzureConfig) -> Result<Self, StorageCredentialVendingError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Checks if the given location starts with any allowed prefix.
    fn is_location_allowed(&self, location: &str) -> bool {
        if self.config.allowed_prefixes.is_empty() {
            // No restrictions - allow any Azure location
            return true;
        }

        self.config
            .allowed_prefixes
            .iter()
            .any(|prefix| location.starts_with(prefix))
    }

    /// Extracts the storage account name from an Azure URI.
    ///
    /// Supported formats:
    /// - `abfss://container@account.dfs.core.windows.net/path`
    /// - `wasbs://container@account.blob.core.windows.net/path`
    fn extract_account_from_uri(uri: &str) -> Option<String> {
        // Format: scheme://container@account.*.core.windows.net/path
        let without_scheme = uri
            .strip_prefix("abfss://")
            .or_else(|| uri.strip_prefix("abfs://"))
            .or_else(|| uri.strip_prefix("wasbs://"))
            .or_else(|| uri.strip_prefix("wasb://"))?;

        // Find @account part
        let at_pos = without_scheme.find('@')?;
        let after_at = &without_scheme[at_pos + 1..];

        // Account name is before the first `.`
        let dot_pos = after_at.find('.')?;
        Some(after_at[..dot_pos].to_string())
    }

    /// Extracts the table prefix from a table location.
    fn get_table_prefix(location: &str) -> String {
        if location.ends_with('/') {
            location.to_string()
        } else {
            format!("{}/", location)
        }
    }

    /// Builds credential config map based on the configuration.
    fn build_credential_config(&self, account: &str) -> HashMap<String, String> {
        let mut config = HashMap::new();

        // Priority: SAS token > Account key > Connection string
        if let Some(ref sas) = self.config.sas_token {
            let key = format!("adls.sas-token.{}", account);
            config.insert(key, sas.clone());
        } else if let Some(ref key) = self.config.account_key {
            let config_key = format!("adls.account-key.{}", account);
            config.insert(config_key, key.clone());
        } else if let Some(ref conn_str) = self.config.connection_string {
            let key = format!("adls.connection-string.{}", account);
            config.insert(key, conn_str.clone());
        }

        config
    }
}

#[async_trait]
impl StorageCredentialProvider for AzureCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        // Check if this location is allowed
        if !self.is_location_allowed(&request.table_location) {
            return Ok(vec![]);
        }

        // Try to extract account from URI, fall back to configured account
        let account = Self::extract_account_from_uri(&request.table_location)
            .or_else(|| self.config.account_name.clone())
            .ok_or_else(|| {
                StorageCredentialVendingError::AzureError(
                    "Cannot determine storage account from location or config".to_string(),
                )
            })?;

        // Build the storage credential
        let prefix = Self::get_table_prefix(&request.table_location);
        let config = self.build_credential_config(&account);

        Ok(vec![StorageCredential::new(prefix, config)])
    }

    fn supports_location(&self, location: &str) -> bool {
        location.starts_with("abfss://")
            || location.starts_with("abfs://")
            || location.starts_with("wasbs://")
            || location.starts_with("wasb://")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("sv=2022-11-02&ss=b")
            .with_allowed_prefix("abfss://container@myaccount.dfs.core.windows.net/");

        assert_eq!(config.account_name, Some("myaccount".to_string()));
        assert_eq!(config.sas_token, Some("sv=2022-11-02&ss=b".to_string()));
        assert_eq!(config.allowed_prefixes.len(), 1);
    }

    #[test]
    fn test_sas_token_strips_leading_question_mark() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("?sv=2022-11-02&ss=b");

        assert_eq!(config.sas_token, Some("sv=2022-11-02&ss=b".to_string()));
    }

    #[test]
    fn test_config_validation_missing_account() {
        let config = AzureConfig::new().with_sas_token("token");
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_missing_credentials() {
        let config = AzureConfig::new().with_account_name("myaccount");
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_valid() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("token");
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_extract_account_from_uri_abfss() {
        let uri = "abfss://container@myaccount.dfs.core.windows.net/path/to/table";
        assert_eq!(
            AzureCredentialProvider::extract_account_from_uri(uri),
            Some("myaccount".to_string())
        );
    }

    #[test]
    fn test_extract_account_from_uri_wasbs() {
        let uri = "wasbs://container@myaccount.blob.core.windows.net/path";
        assert_eq!(
            AzureCredentialProvider::extract_account_from_uri(uri),
            Some("myaccount".to_string())
        );
    }

    #[test]
    fn test_extract_account_from_uri_invalid() {
        let uri = "gs://bucket/path";
        assert_eq!(AzureCredentialProvider::extract_account_from_uri(uri), None);
    }

    #[test]
    fn test_table_prefix() {
        assert_eq!(
            AzureCredentialProvider::get_table_prefix(
                "abfss://container@account.dfs.core.windows.net/warehouse/ns/table"
            ),
            "abfss://container@account.dfs.core.windows.net/warehouse/ns/table/"
        );

        assert_eq!(
            AzureCredentialProvider::get_table_prefix(
                "abfss://container@account.dfs.core.windows.net/warehouse/ns/table/"
            ),
            "abfss://container@account.dfs.core.windows.net/warehouse/ns/table/"
        );
    }

    #[test]
    fn test_location_allowed() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("token")
            .with_allowed_prefix("abfss://allowed@myaccount.dfs.core.windows.net/");

        let provider = AzureCredentialProvider::new(config).unwrap();

        assert!(provider
            .is_location_allowed("abfss://allowed@myaccount.dfs.core.windows.net/data/table"));
        assert!(!provider
            .is_location_allowed("abfss://other@myaccount.dfs.core.windows.net/data/table"));
    }

    #[test]
    fn test_location_allowed_no_restrictions() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("token");

        let provider = AzureCredentialProvider::new(config).unwrap();

        assert!(provider.is_location_allowed("abfss://any@account.dfs.core.windows.net/any/path"));
    }

    #[test]
    fn test_supports_location() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("token");

        let provider = AzureCredentialProvider::new(config).unwrap();

        assert!(provider.supports_location("abfss://container@account.dfs.core.windows.net/"));
        assert!(provider.supports_location("abfs://container@account.dfs.core.windows.net/"));
        assert!(provider.supports_location("wasbs://container@account.blob.core.windows.net/"));
        assert!(provider.supports_location("wasb://container@account.blob.core.windows.net/"));
        assert!(!provider.supports_location("gs://bucket/path"));
        assert!(!provider.supports_location("s3://bucket/path"));
    }

    #[test]
    fn test_build_credential_config_sas() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("sv=2022&ss=b");

        let provider = AzureCredentialProvider::new(config).unwrap();
        let cred_config = provider.build_credential_config("myaccount");

        assert_eq!(
            cred_config.get("adls.sas-token.myaccount").unwrap(),
            "sv=2022&ss=b"
        );
    }

    #[test]
    fn test_build_credential_config_account_key() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_account_key("secret-key");

        let provider = AzureCredentialProvider::new(config).unwrap();
        let cred_config = provider.build_credential_config("myaccount");

        assert_eq!(
            cred_config.get("adls.account-key.myaccount").unwrap(),
            "secret-key"
        );
    }

    #[tokio::test]
    async fn test_vend_credentials() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("sv=2022&ss=b");

        let provider = AzureCredentialProvider::new(config).unwrap();

        let request = StorageCredentialRequest {
            tenant_id: "tenant1".to_string(),
            namespace: vec!["ns".to_string()],
            table_name: "table".to_string(),
            table_location: "abfss://container@myaccount.dfs.core.windows.net/warehouse/ns/table"
                .to_string(),
            write_access: false,
        };

        let credentials = provider.vend_credentials(&request).await.unwrap();

        assert_eq!(credentials.len(), 1);
        let cred = &credentials[0];
        assert_eq!(
            cred.prefix,
            "abfss://container@myaccount.dfs.core.windows.net/warehouse/ns/table/"
        );
        assert_eq!(
            cred.config.get("adls.sas-token.myaccount").unwrap(),
            "sv=2022&ss=b"
        );
    }

    #[tokio::test]
    async fn test_vend_credentials_location_not_allowed() {
        let config = AzureConfig::new()
            .with_account_name("myaccount")
            .with_sas_token("token")
            .with_allowed_prefix("abfss://allowed@myaccount.dfs.core.windows.net/");

        let provider = AzureCredentialProvider::new(config).unwrap();

        let request = StorageCredentialRequest {
            tenant_id: "tenant1".to_string(),
            namespace: vec!["ns".to_string()],
            table_name: "table".to_string(),
            table_location: "abfss://other@myaccount.dfs.core.windows.net/warehouse/ns/table"
                .to_string(),
            write_access: false,
        };

        let credentials = provider.vend_credentials(&request).await.unwrap();
        assert!(credentials.is_empty());
    }
}
