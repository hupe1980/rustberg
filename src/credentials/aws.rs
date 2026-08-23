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
    /// // The prefixes are the provider's whole scope: it signs for these and
    /// // nothing else, and naming none means it signs for nothing.
    /// let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123456789012:role/IcebergAccess")
    ///     .with_allowed_prefix("s3://my-warehouse/");
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

    /// Whether `location` falls under one of the configured prefixes.
    ///
    /// Containment is segment-wise ([`crate::location::is_vendable`]), not a
    /// string prefix test: `s3://bucket/wh-evil/t` merely *spells* like
    /// `s3://bucket/wh` and must not be admitted by it. An empty prefix list
    /// grants nothing — see there for why that direction and not the other.
    fn is_location_allowed(config: &AwsStsConfig, location: &str) -> bool {
        crate::location::is_vendable(&config.allowed_prefixes, location)
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

    /// Splits an `s3://bucket/key/prefix` location into `(bucket, key_prefix)`.
    fn split_location(location: &str) -> Option<(&str, &str)> {
        let rest = location
            .strip_prefix("s3://")
            .or_else(|| location.strip_prefix("s3a://"))
            .or_else(|| location.strip_prefix("s3n://"))?;
        match rest.split_once('/') {
            Some((bucket, key)) => Some((bucket, key.trim_end_matches('/'))),
            // A bare bucket with no key prefix.
            None => Some((rest, "")),
        }
    }

    /// Builds an inline STS session policy scoped to one table's prefix.
    ///
    /// Without this, `AssumeRole` returns the role's *full* permissions: a
    /// caller asking to read one table receives credentials for everything the
    /// role can reach, and a read-only request is indistinguishable from a write
    /// one. The session policy is the mechanism that makes vending
    /// downgrade-only — the effective permission is the intersection of the role
    /// and this document.
    ///
    /// # Errors
    ///
    /// Returns an error if the location is not an S3 URL, or if the resulting
    /// policy exceeds the STS limit. AWS caps an inline session policy at 2048
    /// characters of plaintext; a single-prefix policy is far below that, but a
    /// pathological location could not be scoped safely and must fail rather
    /// than fall back to an unscoped credential.
    fn session_policy(
        location: &str,
        write_access: bool,
    ) -> Result<String, StorageCredentialVendingError> {
        const MAX_SESSION_POLICY: usize = 2048;

        let (bucket, key_prefix) = Self::split_location(location).ok_or_else(|| {
            StorageCredentialVendingError::AwsStsError(format!(
                "Cannot scope credentials: '{location}' is not an S3 location"
            ))
        })?;

        let object_arn = if key_prefix.is_empty() {
            format!("arn:aws:s3:::{bucket}/*")
        } else {
            format!("arn:aws:s3:::{bucket}/{key_prefix}/*")
        };
        let list_prefix = if key_prefix.is_empty() {
            "*".to_string()
        } else {
            format!("{key_prefix}/*")
        };

        let mut object_actions = vec!["s3:GetObject", "s3:GetObjectVersion"];
        if write_access {
            object_actions.extend_from_slice(&[
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:AbortMultipartUpload",
            ]);
        }

        let policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "TableObjects",
                    "Effect": "Allow",
                    "Action": object_actions,
                    "Resource": object_arn
                },
                {
                    // Listing is bucket-scoped in S3, so it is constrained by an
                    // explicit prefix condition instead of by the resource ARN.
                    "Sid": "ListTablePrefix",
                    "Effect": "Allow",
                    "Action": "s3:ListBucket",
                    "Resource": format!("arn:aws:s3:::{bucket}"),
                    "Condition": { "StringLike": { "s3:prefix": [list_prefix] } }
                }
            ]
        })
        .to_string();

        if policy.len() > MAX_SESSION_POLICY {
            return Err(StorageCredentialVendingError::AwsStsError(format!(
                "Scoped session policy for '{location}' is {} characters, over the STS limit of \
                 {MAX_SESSION_POLICY}; refusing to vend an unscoped credential",
                policy.len()
            )));
        }

        Ok(policy)
    }
}

#[async_trait]
impl StorageCredentialProvider for AwsStsCredentialProvider {
    async fn vend_credentials(
        &self,
        request: &StorageCredentialRequest,
    ) -> Result<Vec<StorageCredential>, StorageCredentialVendingError> {
        // Check if this location is allowed
        if !Self::is_location_allowed(&self.config, &request.table_location) {
            return Ok(vec![]);
        }

        // Build the assume role request
        let session_name = request.session_name();

        // Scope the credential to this table and this access level. The
        // effective permission is the intersection of the role and this policy,
        // so the result can only ever be narrower than what Rustberg holds.
        let policy = Self::session_policy(&request.table_location, request.write_access)?;

        let mut assume_role = self
            .sts_client
            .assume_role()
            .role_arn(&self.config.role_arn)
            .role_session_name(&session_name)
            .duration_seconds(self.config.duration_seconds)
            .policy(policy);

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
        // Every alias `split_location` accepts. Listing fewer here meant a
        // legitimate `s3n://` table was reported as unsupported rather than
        // vended for, which reaches the client as a `200` with no credentials.
        ["s3://", "s3a://", "s3n://"]
            .iter()
            .any(|scheme| location.starts_with(scheme))
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

    /// A bucket prefix that merely *spells* like an allowed one is a different
    /// prefix. A `starts_with` test admits it; containment must not.
    #[test]
    fn a_sibling_prefix_is_not_allowed() {
        let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123:role/Test")
            .with_allowed_prefix("s3://bucket/wh");
        let allowed = |loc: &str| AwsStsCredentialProvider::is_location_allowed(&config, loc);

        assert!(allowed("s3://bucket/wh/db/events"));
        assert!(!allowed("s3://bucket/wh-evil/db/events"));
        assert!(!allowed("s3://other-bucket/wh/db/events"));
    }

    /// Hadoop-style URLs name the same bucket, so a warehouse written `s3://`
    /// must still admit a table addressed `s3a://`.
    #[test]
    fn hadoop_scheme_aliases_are_allowed() {
        let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123:role/Test")
            .with_allowed_prefix("s3://bucket/wh");
        assert!(AwsStsCredentialProvider::is_location_allowed(
            &config,
            "s3a://bucket/wh/db/t"
        ));
    }

    /// A provider told about no prefixes vends for nothing.
    ///
    /// The dangerous reading is the other one: a config built without naming a
    /// scope would sign for any bucket the assumed role can reach, which is the
    /// server's whole storage authority handed to whoever asked first.
    #[test]
    fn an_unscoped_config_allows_no_location() {
        let config = AwsStsConfig::new("us-east-1", "arn:aws:iam::123:role/Test");
        assert!(config.allowed_prefixes.is_empty());
        assert!(!AwsStsCredentialProvider::is_location_allowed(
            &config,
            "s3://any-bucket/anything"
        ));
    }
    // ── Session policy scoping ──────────────────────────────────────────

    fn policy(location: &str, write: bool) -> serde_json::Value {
        let raw = AwsStsCredentialProvider::session_policy(location, write).expect("scopable");
        serde_json::from_str(&raw).expect("valid JSON")
    }

    #[test]
    fn splits_s3_locations() {
        assert_eq!(
            AwsStsCredentialProvider::split_location("s3://bucket/wh/db/t"),
            Some(("bucket", "wh/db/t"))
        );
        assert_eq!(
            AwsStsCredentialProvider::split_location("s3://bucket/wh/db/t/"),
            Some(("bucket", "wh/db/t"))
        );
        assert_eq!(
            AwsStsCredentialProvider::split_location("s3://bucket"),
            Some(("bucket", ""))
        );
        assert_eq!(AwsStsCredentialProvider::split_location("gs://b/x"), None);
    }

    /// The credential must reach the requested table's prefix and nothing above it.
    #[test]
    fn policy_is_scoped_to_the_table_prefix() {
        let p = policy("s3://bucket/wh/db/events", false);
        let objects = &p["Statement"][0];

        assert_eq!(objects["Resource"], "arn:aws:s3:::bucket/wh/db/events/*");
        assert_eq!(
            p["Statement"][1]["Condition"]["StringLike"]["s3:prefix"][0],
            "wh/db/events/*"
        );
    }

    /// A read-only request must not yield write permissions. Previously
    /// `AssumeRole` was called with no policy at all, so `write_access` was
    /// discarded and every caller received the role's full rights.
    #[test]
    fn read_only_request_grants_no_writes() {
        let actions = policy("s3://bucket/wh/db/t", false)["Statement"][0]["Action"].clone();
        let actions: Vec<String> = serde_json::from_value(actions).unwrap();

        assert!(actions.contains(&"s3:GetObject".to_string()));
        for forbidden in ["s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload"] {
            assert!(
                !actions.contains(&forbidden.to_string()),
                "read-only credential granted {forbidden}"
            );
        }
    }

    #[test]
    fn write_request_grants_writes() {
        let actions = policy("s3://bucket/wh/db/t", true)["Statement"][0]["Action"].clone();
        let actions: Vec<String> = serde_json::from_value(actions).unwrap();

        for expected in ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"] {
            assert!(
                actions.contains(&expected.to_string()),
                "missing {expected}"
            );
        }
    }

    /// Two tables in the same bucket must not be reachable from one another's
    /// credential.
    #[test]
    fn sibling_tables_are_not_reachable() {
        let a = policy("s3://bucket/wh/db/a", true);
        let b = policy("s3://bucket/wh/db/b", true);
        assert_ne!(a["Statement"][0]["Resource"], b["Statement"][0]["Resource"]);
        assert_eq!(
            a["Statement"][0]["Resource"],
            "arn:aws:s3:::bucket/wh/db/a/*"
        );
    }

    /// A non-S3 location cannot be scoped, so it must fail rather than fall back
    /// to an unscoped credential.
    #[test]
    fn unscopable_location_is_refused() {
        assert!(AwsStsCredentialProvider::session_policy("gs://bucket/x", false).is_err());
    }

    /// STS caps an inline session policy at 2048 characters.
    #[test]
    fn policy_fits_the_sts_limit() {
        let deep = format!("s3://bucket/{}", vec!["level"; 20].join("/"));
        let raw = AwsStsCredentialProvider::session_policy(&deep, true).expect("scopable");
        assert!(raw.len() <= 2048, "policy was {} characters", raw.len());
    }
}
