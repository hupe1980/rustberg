//! Building a credential provider from configuration.
//!
//! # Why this module exists
//!
//! The AWS and GCS providers were reachable only through the library's builder,
//! so the shipped server always ran with [`NoopCredentialProvider`] — the
//! feature was implemented, tested and documented, and no deployment could
//! switch it on. This is the missing half: it turns a `[credentials]` section
//! into a live provider.
//!
//! # Prefixes default to the warehouse
//!
//! An unset `allowed_prefixes` becomes exactly the warehouse location, never
//! "anywhere". Both halves of the defence then agree: the catalog refuses to
//! *record* a table outside the warehouse ([`crate::location`]), and the
//! provider refuses to *vend* for one. Either alone closes the hole; together
//! neither is load-bearing on its own.
//!
//! # Features
//!
//! `aws-credentials` and `gcp-credentials` are optional. Configuring a provider
//! that was not compiled in is a startup failure naming the feature, rather than
//! a server that silently vends nothing while its configuration says otherwise.

use std::sync::Arc;

use crate::config::server_config::CredentialsConfig;
use crate::error::AppError;

use super::{NoopCredentialProvider, StorageCredentialProvider};

/// Builds the credential provider described by `config`.
///
/// `warehouse_location` supplies the default prefix scope.
///
/// # Errors
///
/// Returns [`AppError::Internal`] when the provider is unknown, its settings
/// are missing, the Cargo feature backing it was not compiled in, or a named
/// secret environment variable is unset. All of these are startup failures on
/// purpose: a deployment that asked for credential vending and did not get it
/// must not come up pretending otherwise.
pub async fn build_credential_provider(
    config: &CredentialsConfig,
    managed_warehouses: &[String],
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    let prefixes = effective_prefixes(config, managed_warehouses);

    match config.provider.trim().to_ascii_lowercase().as_str() {
        "none" | "" => Ok(Arc::new(NoopCredentialProvider::new())),

        "aws" => build_aws(config, prefixes),
        "gcs" | "gcp" => build_gcs(config, prefixes).await,
        "azure" | "adls" => build_azure(config, prefixes),

        other => Err(AppError::Internal(format!(
            "Unknown credentials provider '{other}'. Valid values are 'none', 'aws', 'gcs' \
             and 'azure'."
        ))),
    }
}

/// The prefixes a provider may vend for: the configured ones, or every
/// warehouse this server manages.
///
/// Plural because of federation: each mount has its own warehouse, and a
/// provider that only knew the server's would refuse to vend for every mounted
/// table — silently, since a refused vend still returns the metadata.
fn effective_prefixes(config: &CredentialsConfig, managed_warehouses: &[String]) -> Vec<String> {
    if config.allowed_prefixes.is_empty() {
        managed_warehouses.to_vec()
    } else {
        config.allowed_prefixes.clone()
    }
}

/// Builds the request signer described by `config.signing`.
///
/// Signing is independent of vending: either, both or neither may be on.
///
/// # Errors
///
/// [`AppError::Internal`] when signing is enabled but the `remote-signing`
/// feature was not compiled in — a startup failure rather than a server that
/// advertises the endpoint and refuses every request.
pub async fn build_request_signer(
    config: &CredentialsConfig,
    managed_warehouses: &[String],
) -> Result<Arc<dyn super::RequestSigner>, AppError> {
    let Some(signing) = config.signing.as_ref().filter(|s| s.enabled) else {
        return Ok(Arc::new(super::NoopRequestSigner));
    };

    build_signer(
        config,
        signing,
        effective_prefixes(config, managed_warehouses),
    )
    .await
}

#[cfg(feature = "remote-signing")]
async fn build_signer(
    config: &CredentialsConfig,
    signing: &crate::config::server_config::SigningConfig,
    prefixes: Vec<String>,
) -> Result<Arc<dyn super::RequestSigner>, AppError> {
    // The region only matters as a fallback: a client sends the region it
    // resolved, and the signature must be for that one.
    let region = signing
        .region
        .clone()
        .or_else(|| config.aws.as_ref().map(|aws| aws.region.clone()))
        .unwrap_or_else(|| "us-east-1".to_string());

    Ok(Arc::new(super::AwsSigV4Signer::new(region, prefixes).await))
}

#[cfg(not(feature = "remote-signing"))]
async fn build_signer(
    _config: &CredentialsConfig,
    _signing: &crate::config::server_config::SigningConfig,
    _prefixes: Vec<String>,
) -> Result<Arc<dyn super::RequestSigner>, AppError> {
    Err(AppError::Internal(
        "credentials.signing.enabled is true, but this binary was built without the \
         'remote-signing' Cargo feature. Rebuild with --features remote-signing."
            .to_string(),
    ))
}

#[cfg(feature = "aws-credentials")]
fn build_aws(
    config: &CredentialsConfig,
    prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    use super::aws::{AwsStsConfig, AwsStsCredentialProvider};

    let aws = config.aws.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credentials.provider is 'aws' but no [credentials.aws] section was given. \
             It needs at least 'region' and 'role_arn'."
                .to_string(),
        )
    })?;

    let mut sts = AwsStsConfig::new(&aws.region, &aws.role_arn)
        .with_duration_seconds(aws.duration_seconds)
        .with_allowed_prefixes(prefixes);

    if let Some(ref var) = aws.external_id_env {
        sts = sts.with_external_id(crate::config::secret::from_env(
            var,
            "credentials.aws.external_id_env",
        )?);
    }

    // `AwsStsCredentialProvider::new` resolves the ambient AWS config, which is
    // async. Blocking here would deadlock inside the runtime, so this is built
    // on the caller's runtime by the async wrapper below.
    let provider = block_on_current_runtime(AwsStsCredentialProvider::new(sts))?;
    Ok(Arc::new(provider))
}

/// Runs an AWS SDK constructor to completion on the current runtime.
///
/// `AwsStsCredentialProvider::new` is `async` only because loading ambient AWS
/// configuration is; there is no I/O that can block indefinitely. Keeping
/// [`build_aws`] synchronous lets the feature-gated variants share one
/// signature.
#[cfg(feature = "aws-credentials")]
fn block_on_current_runtime<T>(
    fut: impl std::future::Future<Output = Result<T, super::StorageCredentialVendingError>>,
) -> Result<T, AppError> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current()
            .block_on(fut)
            .map_err(|e| {
                AppError::Internal(format!("Failed to initialise AWS credential vending: {e}"))
            })
    })
}

#[cfg(not(feature = "aws-credentials"))]
fn build_aws(
    _config: &CredentialsConfig,
    _prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    Err(AppError::Internal(
        "credentials.provider is 'aws', but this binary was built without the \
         'aws-credentials' Cargo feature. Rebuild with --features aws-credentials."
            .to_string(),
    ))
}

#[cfg(feature = "azure-credentials")]
fn build_azure(
    config: &CredentialsConfig,
    prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    use super::azure::{AzureConfig, AzureSasCredentialProvider};

    let azure = config.azure.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credentials.provider is 'azure' but no [credentials.azure] section was given. \
             It needs 'account', 'tenant_id', 'client_id' and 'client_secret_env'."
                .to_string(),
        )
    })?;

    let secret = crate::config::secret::from_env(
        &azure.client_secret_env,
        "credentials.azure.client_secret_env",
    )?;

    let provider = AzureSasCredentialProvider::new(
        AzureConfig::new(&azure.account, &azure.tenant_id, &azure.client_id, secret)
            .with_duration_seconds(azure.duration_seconds)
            .with_allowed_prefixes(prefixes),
    )
    .map_err(|e| {
        AppError::Internal(format!(
            "Failed to initialise Azure credential vending: {e}"
        ))
    })?;

    Ok(Arc::new(provider))
}

#[cfg(not(feature = "azure-credentials"))]
fn build_azure(
    _config: &CredentialsConfig,
    _prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    Err(AppError::Internal(
        "credentials.provider is 'azure', but this binary was built without the \
         'azure-credentials' Cargo feature. Rebuild with --features azure-credentials."
            .to_string(),
    ))
}

#[cfg(feature = "gcp-credentials")]
async fn build_gcs(
    config: &CredentialsConfig,
    prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    use super::gcs::{GcsConfig, GcsCredentialProvider};

    let gcs = config.gcs.as_ref().ok_or_else(|| {
        AppError::Internal(
            "credentials.provider is 'gcs' but no [credentials.gcs] section was given. \
             It needs 'service_account_key_path'."
                .to_string(),
        )
    })?;

    let provider = GcsCredentialProvider::new(
        GcsConfig::new()
            .with_service_account_key_path(&gcs.service_account_key_path)
            .with_allowed_prefixes(prefixes),
    )
    .await
    .map_err(|e| AppError::Internal(format!("Failed to initialise GCS credential vending: {e}")))?;

    Ok(Arc::new(provider))
}

#[cfg(not(feature = "gcp-credentials"))]
async fn build_gcs(
    _config: &CredentialsConfig,
    _prefixes: Vec<String>,
) -> Result<Arc<dyn StorageCredentialProvider>, AppError> {
    Err(AppError::Internal(
        "credentials.provider is 'gcs', but this binary was built without the \
         'gcp-credentials' Cargo feature. Rebuild with --features gcp-credentials."
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(provider: &str) -> CredentialsConfig {
        CredentialsConfig {
            provider: provider.to_string(),
            ..Default::default()
        }
    }

    /// The default must be "vend nothing". A deployment that never mentions
    /// credentials must not acquire the ability to mint them.
    #[tokio::test]
    async fn the_default_provider_vends_nothing() {
        let provider =
            build_credential_provider(&CredentialsConfig::default(), &["s3://b/wh".to_string()])
                .await
                .expect("the default configuration builds");
        assert!(!provider.supports_location("s3://b/wh/db/t"));
    }

    #[tokio::test]
    async fn none_is_accepted_explicitly() {
        assert!(
            build_credential_provider(&config("none"), &["s3://b/wh".to_string()])
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_unknown_provider_is_a_startup_failure() {
        let err = build_credential_provider(&config("oracle"), &["s3://b/wh".to_string()])
            .await
            .unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("Unknown credentials provider"),
            "{message}"
        );
        assert!(
            message.contains("aws") && message.contains("gcs") && message.contains("azure"),
            "the refusal should name every provider that does exist: {message}"
        );
    }

    /// The security default: vending is confined to the warehouse unless an
    /// operator deliberately narrows it further.
    #[test]
    fn prefixes_default_to_the_warehouse() {
        assert_eq!(
            effective_prefixes(
                &CredentialsConfig::default(),
                &["s3://bucket/wh".to_string()]
            ),
            vec!["s3://bucket/wh".to_string()]
        );
    }

    /// Under federation a mount has its own warehouse. A provider that only
    /// knew the server's would refuse every mounted table — silently, because a
    /// refused vend still returns the metadata.
    #[test]
    fn prefixes_cover_every_managed_warehouse() {
        let managed = vec![
            "s3://bucket/wh".to_string(),
            "s3://other/prod".to_string(),
            "file:///srv/legacy".to_string(),
        ];
        assert_eq!(
            effective_prefixes(&CredentialsConfig::default(), &managed),
            managed
        );
    }

    #[test]
    fn configured_prefixes_win() {
        let config = CredentialsConfig {
            allowed_prefixes: vec!["s3://bucket/wh/public".to_string()],
            ..Default::default()
        };
        assert_eq!(
            effective_prefixes(&config, &["s3://bucket/wh".to_string()]),
            vec!["s3://bucket/wh/public".to_string()],
            "an operator may narrow vending below the warehouse"
        );
    }

    /// Configuring a provider the binary cannot serve must fail loudly rather
    /// than come up vending nothing while the config says otherwise.
    #[tokio::test]
    #[cfg(not(feature = "aws-credentials"))]
    async fn aws_without_the_feature_names_the_feature() {
        let err = build_credential_provider(&config("aws"), &["s3://b/wh".to_string()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("aws-credentials"));
    }

    #[tokio::test]
    #[cfg(feature = "aws-credentials")]
    async fn aws_without_its_section_says_what_is_missing() {
        let err = build_credential_provider(&config("aws"), &["s3://b/wh".to_string()])
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[credentials.aws]"), "{msg}");
        assert!(msg.contains("role_arn"), "{msg}");
    }

    #[tokio::test]
    #[cfg(feature = "azure-credentials")]
    async fn azure_without_its_section_says_what_is_missing() {
        let err = build_credential_provider(
            &config("azure"),
            &["abfss://fs@a.dfs.core.windows.net/wh".to_string()],
        )
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("[credentials.azure]"), "{msg}");
        assert!(msg.contains("client_secret_env"), "{msg}");
    }

    /// A named-but-unset secret is a startup failure, not an unauthenticated
    /// provider that fails later with Entra's own error.
    #[tokio::test]
    #[cfg(feature = "azure-credentials")]
    async fn azure_with_a_missing_secret_fails_at_startup() {
        let mut cfg = config("azure");
        cfg.azure = Some(crate::config::server_config::AzureCredentialsConfig {
            account: "acct".to_string(),
            tenant_id: "tenant".to_string(),
            client_id: "client".to_string(),
            client_secret_env: "RUSTBERG_TEST_AZURE_SECRET_UNSET".to_string(),
            duration_seconds: 3600,
        });

        let err = build_credential_provider(
            &cfg,
            &["abfss://fs@acct.dfs.core.windows.net/wh".to_string()],
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("RUSTBERG_TEST_AZURE_SECRET_UNSET"));
    }

    #[tokio::test]
    #[cfg(not(feature = "azure-credentials"))]
    async fn azure_without_the_feature_names_the_feature() {
        let err = build_credential_provider(
            &config("azure"),
            &["abfss://fs@a.dfs.core.windows.net/wh".to_string()],
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("azure-credentials"));
    }

    #[tokio::test]
    #[cfg(feature = "gcp-credentials")]
    async fn gcs_without_its_section_says_what_is_missing() {
        let err = build_credential_provider(&config("gcs"), &["gs://b/wh".to_string()])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("service_account_key_path"));
    }
}
