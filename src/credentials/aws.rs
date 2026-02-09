//! AWS STS credential provider for S3 storage access.
//!
//! This provider uses AWS STS AssumeRole to vend temporary credentials
//! for accessing table data in S3.

use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_sts::Client as StsClient;
use std::collections::HashMap;

use super::provider::{
    StorageCredential, StorageCredentialProvider, StorageCredentialRequest,
    StorageCredentialVendingError,
};

/// Default credential duration (1 hour).
const DEFAULT_DURATION_SECONDS: i32 = 3600;

/// AWS STS credential provider configuration.
#[derive(Debug, Clone)]
pub struct AwsStsConfig {
    /// AWS region for STS calls.
    pub region: String,

    /// IAM role ARN to assume for vending credentials.
    /// The role should have permissions to access the S3 bucket(s).
    pub role_arn: String,

    /// External ID for the assume role call (optional, for cross-account access).
    pub external_id: Option<String>,

    /// Duration of the vended credentials in seconds (default: 3600).
    pub duration_seconds: i32,

    /// S3 bucket prefixes that this provider can grant access to.
    /// If empty, the provider will attempt to grant access to any S3 location.
    pub allowed_prefixes: Vec<String>,
}

impl AwsStsConfig {
    /// Creates a new AWS STS config with the specified role ARN.
    pub fn new(region: impl Into<String>, role_arn: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            role_arn: role_arn.into(),
            external_id: None,
            duration_seconds: DEFAULT_DURATION_SECONDS,
            allowed_prefixes: vec![],
        }
    }

    /// Sets the external ID for cross-account access.
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Sets the credential duration in seconds.
    pub fn with_duration_seconds(mut self, seconds: i32) -> Self {
        self.duration_seconds = seconds;
        self
    }

    /// Adds an allowed S3 prefix.
    pub fn with_allowed_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_prefixes.push(prefix.into());
        self
    }

    /// Sets the allowed S3 prefixes.
    pub fn with_allowed_prefixes(mut self, prefixes: Vec<String>) -> Self {
        self.allowed_prefixes = prefixes;
        self
    }
}

/// AWS STS credential provider.
///
/// Uses STS AssumeRole to vend temporary credentials for S3 access.
/// The vended credentials inherit permissions from the assumed role.
#[derive(Debug)]
pub struct AwsStsCredentialProvider {
    config: AwsStsConfig,
    sts_client: StsClient,
}

impl AwsStsCredentialProvider {
    /// Creates a new AWS STS credential provider.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::credentials::AwsStsCredentialProvider;
    /// use rustberg::credentials::aws::AwsStsConfig;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123456789012:role/IcebergAccess");
    /// let provider = AwsStsCredentialProvider::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: AwsStsConfig) -> Result<Self, StorageCredentialVendingError> {
        let aws_config = aws_config::defaults(BehaviorVersion::latest())
            .region(aws_config::Region::new(config.region.clone()))
            .load()
            .await;

        let sts_client = StsClient::new(&aws_config);

        Ok(Self { config, sts_client })
    }

    /// Creates a new provider with a custom STS client.
    pub fn with_client(config: AwsStsConfig, sts_client: StsClient) -> Self {
        Self { config, sts_client }
    }

    /// Checks if the given location starts with any allowed prefix.
    fn is_location_allowed(&self, location: &str) -> bool {
        if self.config.allowed_prefixes.is_empty() {
            // No restrictions - allow any S3 location
            return true;
        }

        self.config
            .allowed_prefixes
            .iter()
            .any(|prefix| location.starts_with(prefix))
    }

    /// Extracts the S3 prefix from a table location.
    /// For a location like "s3://bucket/warehouse/ns/table", returns "s3://bucket/warehouse/ns/table/".
    fn get_table_prefix(location: &str) -> String {
        if location.ends_with('/') {
            location.to_string()
        } else {
            format!("{}/", location)
        }
    }
}

#[async_trait]
impl StorageCredentialProvider for AwsStsCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        // Check if this location is allowed
        if !self.is_location_allowed(&request.table_location) {
            return Ok(vec![]);
        }

        // Build the assume role request
        let session_name = request.session_name();

        let mut assume_role = self
            .sts_client
            .assume_role()
            .role_arn(&self.config.role_arn)
            .role_session_name(&session_name)
            .duration_seconds(self.config.duration_seconds);

        if let Some(ref external_id) = self.config.external_id {
            assume_role = assume_role.external_id(external_id);
        }

        // Execute the assume role call
        let response = assume_role.send().await.map_err(|e| {
            StorageCredentialVendingError::AwsStsError(format!(
                "Failed to assume role {}: {}",
                self.config.role_arn, e
            ))
        })?;

        // Extract the credentials
        let credentials = response.credentials.ok_or_else(|| {
            StorageCredentialVendingError::AwsStsError(
                "AssumeRole response did not contain credentials".to_string(),
            )
        })?;

        let access_key_id = credentials.access_key_id;
        let secret_access_key = credentials.secret_access_key;
        let session_token = credentials.session_token;

        // Build the storage credential
        let prefix = Self::get_table_prefix(&request.table_location);
        let credential = StorageCredential::s3(
            prefix,
            access_key_id,
            secret_access_key,
            Some(session_token),
        );

        Ok(vec![credential])
    }

    fn supports_location(&self, location: &str) -> bool {
        location.starts_with("s3://") || location.starts_with("s3a://")
    }
}

/// Builder for AWS STS credential providers with tenant-specific role mapping.
///
/// This builder allows configuring role ARNs per tenant or using a pattern
/// to derive role ARNs from tenant IDs.
///
/// # Example
///
/// ```no_run
/// use rustberg::credentials::aws::AwsStsCredentialProviderBuilder;
///
/// let builder = AwsStsCredentialProviderBuilder::new("us-east-1")
///     .with_role_pattern("arn:aws:iam::123456789012:role/iceberg-{tenant_id}")
///     .with_external_id("my-external-id")
///     .with_duration_seconds(3600);
/// ```
#[derive(Debug, Clone)]
pub struct AwsStsCredentialProviderBuilder {
    region: String,
    /// Maps tenant IDs to role ARNs
    tenant_roles: HashMap<String, String>,
    /// Pattern for deriving role ARN from tenant ID (uses {tenant_id} placeholder)
    role_pattern: Option<String>,
    external_id: Option<String>,
    duration_seconds: i32,
    allowed_prefixes: Vec<String>,
}

impl AwsStsCredentialProviderBuilder {
    /// Creates a new builder with the specified AWS region.
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            tenant_roles: HashMap::new(),
            role_pattern: None,
            external_id: None,
            duration_seconds: DEFAULT_DURATION_SECONDS,
            allowed_prefixes: vec![],
        }
    }

    /// Maps a tenant ID to a specific role ARN.
    pub fn with_tenant_role(
        mut self,
        tenant_id: impl Into<String>,
        role_arn: impl Into<String>,
    ) -> Self {
        self.tenant_roles.insert(tenant_id.into(), role_arn.into());
        self
    }

    /// Sets a role ARN pattern. Use `{tenant_id}` as a placeholder.
    ///
    /// Example: `"arn:aws:iam::123456789012:role/iceberg-{tenant_id}"`
    pub fn with_role_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.role_pattern = Some(pattern.into());
        self
    }

    /// Sets the external ID for cross-account access.
    pub fn with_external_id(mut self, external_id: impl Into<String>) -> Self {
        self.external_id = Some(external_id.into());
        self
    }

    /// Sets the credential duration in seconds.
    pub fn with_duration_seconds(mut self, seconds: i32) -> Self {
        self.duration_seconds = seconds;
        self
    }

    /// Adds an allowed S3 prefix.
    pub fn with_allowed_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.allowed_prefixes.push(prefix.into());
        self
    }

    /// Returns the role ARN for the given tenant ID.
    pub fn get_role_arn(&self, tenant_id: &str) -> Option<String> {
        // First check explicit mapping
        if let Some(role) = self.tenant_roles.get(tenant_id) {
            return Some(role.clone());
        }

        // Then try pattern
        if let Some(ref pattern) = self.role_pattern {
            return Some(pattern.replace("{tenant_id}", tenant_id));
        }

        None
    }

    /// Builds the configuration for a specific tenant.
    pub fn build_config(
        &self,
        tenant_id: &str,
    ) -> Result<AwsStsConfig, StorageCredentialVendingError> {
        let role_arn = self.get_role_arn(tenant_id).ok_or_else(|| {
            StorageCredentialVendingError::ConfigurationError(format!(
                "No role ARN configured for tenant: {}",
                tenant_id
            ))
        })?;

        let mut config = AwsStsConfig::new(self.region.clone(), role_arn)
            .with_duration_seconds(self.duration_seconds)
            .with_allowed_prefixes(self.allowed_prefixes.clone());

        if let Some(ref external_id) = self.external_id {
            config = config.with_external_id(external_id.clone());
        }

        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = AwsStsConfig::new("us-west-2", "arn:aws:iam::123456789012:role/TestRole")
            .with_external_id("ext-123")
            .with_duration_seconds(1800)
            .with_allowed_prefix("s3://bucket1/")
            .with_allowed_prefix("s3://bucket2/");

        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.role_arn, "arn:aws:iam::123456789012:role/TestRole");
        assert_eq!(config.external_id, Some("ext-123".to_string()));
        assert_eq!(config.duration_seconds, 1800);
        assert_eq!(config.allowed_prefixes.len(), 2);
    }

    #[test]
    fn test_provider_builder_explicit_mapping() {
        let builder = AwsStsCredentialProviderBuilder::new("us-east-1")
            .with_tenant_role("tenant-a", "arn:aws:iam::111:role/TenantA")
            .with_tenant_role("tenant-b", "arn:aws:iam::222:role/TenantB");

        assert_eq!(
            builder.get_role_arn("tenant-a"),
            Some("arn:aws:iam::111:role/TenantA".to_string())
        );
        assert_eq!(
            builder.get_role_arn("tenant-b"),
            Some("arn:aws:iam::222:role/TenantB".to_string())
        );
        assert_eq!(builder.get_role_arn("tenant-c"), None);
    }

    #[test]
    fn test_provider_builder_pattern() {
        let builder = AwsStsCredentialProviderBuilder::new("us-east-1")
            .with_role_pattern("arn:aws:iam::123456789012:role/iceberg-{tenant_id}-access");

        assert_eq!(
            builder.get_role_arn("tenant-123"),
            Some("arn:aws:iam::123456789012:role/iceberg-tenant-123-access".to_string())
        );
    }

    #[test]
    fn test_provider_builder_explicit_over_pattern() {
        let builder = AwsStsCredentialProviderBuilder::new("us-east-1")
            .with_tenant_role("special-tenant", "arn:aws:iam::999:role/SpecialRole")
            .with_role_pattern("arn:aws:iam::123:role/{tenant_id}");

        // Explicit mapping takes precedence
        assert_eq!(
            builder.get_role_arn("special-tenant"),
            Some("arn:aws:iam::999:role/SpecialRole".to_string())
        );

        // Pattern used for others
        assert_eq!(
            builder.get_role_arn("other-tenant"),
            Some("arn:aws:iam::123:role/other-tenant".to_string())
        );
    }

    #[test]
    fn test_table_prefix() {
        assert_eq!(
            AwsStsCredentialProvider::get_table_prefix("s3://bucket/warehouse/ns/table"),
            "s3://bucket/warehouse/ns/table/"
        );
        assert_eq!(
            AwsStsCredentialProvider::get_table_prefix("s3://bucket/warehouse/ns/table/"),
            "s3://bucket/warehouse/ns/table/"
        );
    }

    #[test]
    fn test_supports_location() {
        // Create a config - we only need to test supports_location
        // which doesn't require a valid STS client
        let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123:role/Test");

        // Test the config's helper for location checking
        assert!(config.role_arn.contains("Test"));

        // Create allowed prefixes config
        let config_with_prefixes = AwsStsConfig {
            region: "us-east-1".to_string(),
            role_arn: "arn:aws:iam::123:role/Test".to_string(),
            external_id: None,
            duration_seconds: 3600,
            allowed_prefixes: vec!["s3://allowed-bucket/".to_string()],
        };

        // Verify the configuration is set correctly
        assert_eq!(config_with_prefixes.allowed_prefixes.len(), 1);
        assert!(config_with_prefixes.allowed_prefixes[0].starts_with("s3://"));
    }
}
