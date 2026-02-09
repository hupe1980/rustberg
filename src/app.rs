//! Application builder and state management.
//!
//! This module provides the main App structure that configures and runs
//! the Iceberg REST Catalog service.

use axum::http::{HeaderName, HeaderValue, Method};
use axum::Router;
use iceberg::memory::MemoryCatalogBuilder;
use iceberg::CatalogBuilder;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

use crate::auth::{
    AllowAllAuthenticator, AllowAllAuthorizer, ApiKeyAuthenticator, Authenticator, Authorizer,
    ChainAuthenticator, ChainAuthorizer, InMemoryApiKeyStore, JwtAuthenticator, JwtConfig,
    RateLimitConfig, RateLimiter, RbacAuthorizer, TenantIsolationAuthorizer,
};
use crate::catalog::{
    self, CatalogExt, EncryptedCatalog, ExtendedCatalog, IdempotencyCache, MemoryViewStore,
    ViewStorage, ViewStore,
};
use crate::config;
use crate::config::CorsConfig;
use crate::credentials::{NoopCredentialProvider, StorageCredentialProvider};
use crate::crypto::create_kms;
#[cfg(feature = "slatedb-storage")]
use crate::crypto::{Aes256GcmProvider, EncryptionProvider};
use crate::observability::metrics::MetricsRegistry;
#[cfg(feature = "slatedb-storage")]
use crate::storage::KvApiKeyStore;
use crate::utils::temp_path;

// ============================================================================
// App State
// ============================================================================

/// Shared application state passed to all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// The authenticator for validating credentials.
    pub authenticator: Arc<dyn Authenticator>,
    /// The authorizer for checking permissions.
    pub authorizer: Arc<dyn Authorizer>,
    /// The Iceberg catalog implementation with extended commit capabilities.
    pub catalog: Arc<dyn CatalogExt + Send + Sync>,
    /// Storage credential provider for vending temporary credentials.
    pub credential_provider: Arc<dyn StorageCredentialProvider>,
    /// Rate limiter for protecting against DoS and brute-force attacks.
    pub rate_limiter: Arc<RateLimiter>,
    /// Idempotency cache for preventing duplicate request processing.
    pub idempotency_cache: Arc<IdempotencyCache>,
    /// View storage for view CRUD operations.
    /// Can be backed by in-memory (development) or SlateDB (production).
    pub view_storage: Arc<dyn ViewStore>,
    /// Prometheus metrics registry for observability.
    pub metrics: Arc<MetricsRegistry>,
    /// Base warehouse location for table storage.
    pub warehouse_location: String,
    /// Default tenant ID for single-tenant deployments.
    pub default_tenant_id: String,
}

impl AppState {
    /// Returns the default tenant ID.
    pub fn default_tenant_id(&self) -> &str {
        &self.default_tenant_id
    }
}

// ============================================================================
// App
// ============================================================================

/// The main application structure.
///
/// Use `App::builder()` to construct an App with the desired configuration.
#[derive(Clone)]
pub struct App {
    app_state: AppState,
    cors_config: CorsConfig,
}

impl App {
    /// Creates a new App builder.
    pub fn builder() -> AppBuilder {
        AppBuilder::default()
    }

    /// Returns the shared application state.
    pub fn state(&self) -> &AppState {
        &self.app_state
    }

    /// Converts the App into an Axum Router ready for serving.
    pub fn into_router(self) -> Router {
        use crate::auth::{auth_middleware, routes as auth_routes, AuthState};
        use crate::observability;
        use axum::middleware;
        use tower_http::limit::RequestBodyLimitLayer;
        use tower_http::set_header::SetResponseHeaderLayer;
        use tower_http::timeout::TimeoutLayer;

        let auth_state = AuthState::with_rate_limiter(
            self.app_state.authenticator.clone(),
            self.app_state.rate_limiter.clone(),
        );

        let catalog_routes = catalog::create_routes(self.app_state.clone());
        let config_routes = config::create_routes(self.app_state.clone());
        let auth_context_routes = auth_routes::create_routes(self.app_state.clone());
        let health_routes = observability::create_health_routes(Arc::new(self.app_state.clone()));
        let metrics_routes =
            observability::metrics::create_routes(Arc::new(self.app_state.clone()));

        // Default request body limit: 10MB
        // This prevents memory exhaustion from oversized requests
        const MAX_REQUEST_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB

        // Request timeout: 30 seconds
        // Protects against slowloris attacks and resource exhaustion
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

        // Request ID header for distributed tracing
        let x_request_id = HeaderName::from_static("x-request-id");

        // CORS configuration from App settings
        let is_permissive = self.cors_config.allowed_origins.is_empty()
            || self.cors_config.allowed_origins.iter().any(|o| o == "*");

        if is_permissive {
            tracing::warn!(
                "CORS is configured to allow all origins. \
                 For production, restrict allowed_origins in configuration."
            );
        }

        let cors = self.build_cors_layer(&x_request_id);

        // Security headers
        // These headers protect against common web vulnerabilities
        let x_content_type_options = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        );
        let x_frame_options = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        );
        let content_security_policy = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
        );
        let cache_control = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        let x_xss_protection = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );

        Router::new()
            // Observability endpoints (no auth required for health/metrics)
            .merge(health_routes)
            .merge(metrics_routes)
            // Catalog and config endpoints (auth required)
            .merge(catalog_routes)
            .merge(config_routes)
            // Auth introspection endpoints (auth required)
            .merge(auth_context_routes)
            .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            .layer(middleware::from_fn_with_state(auth_state, auth_middleware))
            // CORS (must be before auth for preflight requests)
            .layer(cors)
            // Request ID propagation for distributed tracing
            .layer(PropagateRequestIdLayer::new(x_request_id.clone()))
            .layer(SetRequestIdLayer::new(x_request_id, MakeRequestUuid))
            // Response compression (gzip, deflate, br)
            .layer(CompressionLayer::new())
            // Security headers (applied to all responses)
            .layer(x_content_type_options)
            .layer(x_frame_options)
            .layer(content_security_policy)
            .layer(cache_control)
            .layer(x_xss_protection)
            .layer(
                TraceLayer::new_for_http()
                    .make_span_with(trace::DefaultMakeSpan::new().level(Level::INFO))
                    .on_response(trace::DefaultOnResponse::new().level(Level::INFO)),
            )
    }

    /// Builds the CORS layer from the configuration.
    fn build_cors_layer(&self, x_request_id: &HeaderName) -> CorsLayer {
        use tower_http::cors::AllowOrigin;

        // Parse allowed methods
        let methods: Vec<Method> = self
            .cors_config
            .allowed_methods
            .iter()
            .filter_map(|m| m.parse().ok())
            .collect();

        let methods = if methods.is_empty() {
            vec![
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::HEAD,
                Method::OPTIONS,
            ]
        } else {
            methods
        };

        // Build base CORS layer
        let mut cors = CorsLayer::new()
            .allow_methods(methods)
            .expose_headers([x_request_id.clone()]);

        // Configure allowed origins
        if self.cors_config.allowed_origins.is_empty()
            || self.cors_config.allowed_origins.iter().any(|o| o == "*")
        {
            cors = cors.allow_origin(Any);
        } else {
            // Parse specific origins
            let origins: Vec<_> = self
                .cors_config
                .allowed_origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();

            if origins.is_empty() {
                cors = cors.allow_origin(Any);
            } else {
                cors = cors.allow_origin(AllowOrigin::list(origins));
            }
        }

        // Configure allowed headers
        if self.cors_config.allowed_headers.is_empty()
            || self.cors_config.allowed_headers.iter().any(|h| h == "*")
        {
            cors = cors.allow_headers(Any);
        } else {
            let headers: Vec<HeaderName> = self
                .cors_config
                .allowed_headers
                .iter()
                .filter_map(|h| h.parse().ok())
                .collect();

            if headers.is_empty() {
                cors = cors.allow_headers(Any);
            } else {
                cors = cors.allow_headers(headers);
            }
        }

        cors
    }
}

// ============================================================================
// App Builder
// ============================================================================

/// Builder for constructing an App with custom configuration.
#[derive(Default)]
pub struct AppBuilder {
    catalog: Option<Arc<dyn CatalogExt + Send + Sync>>,
    warehouse_location: Option<String>,
    authenticator: Option<Arc<dyn Authenticator>>,
    authorizer: Option<Arc<dyn Authorizer>>,
    credential_provider: Option<Arc<dyn StorageCredentialProvider>>,
    rate_limit_config: Option<RateLimitConfig>,
    idempotency_ttl: Option<Duration>,
    default_tenant_id: Option<String>,
    enable_auth: bool,
    jwt_config: Option<JwtConfig>,
    cors_config: Option<CorsConfig>,
    kms_config: Option<crate::crypto::KmsConfig>,
    storage_backend_url: Option<String>,
    encryption_key: Option<[u8; 32]>,
    /// Whether to enable table metadata encryption via EncryptedCatalog
    enable_table_encryption: bool,
    /// KMS key ID for table metadata encryption
    kms_key_id: Option<String>,
    /// IO timeout configuration for storage operations
    #[cfg(feature = "slatedb-storage")]
    io_timeout_config: Option<crate::catalog::IoTimeoutConfig>,
}

impl AppBuilder {
    /// Sets a custom Iceberg catalog implementation.
    ///
    /// The catalog must implement `CatalogExt` for table commit support.
    pub fn with_catalog(mut self, catalog: Arc<dyn CatalogExt + Send + Sync>) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Sets the warehouse location for table storage.
    pub fn with_warehouse_location<S: Into<String>>(mut self, location: S) -> Self {
        self.warehouse_location = Some(location.into());
        self
    }

    /// Sets a custom authenticator.
    pub fn with_authenticator(mut self, authenticator: Arc<dyn Authenticator>) -> Self {
        self.authenticator = Some(authenticator);
        self
    }

    /// Sets a custom authorizer.
    pub fn with_authorizer(mut self, authorizer: Arc<dyn Authorizer>) -> Self {
        self.authorizer = Some(authorizer);
        self
    }

    /// Sets a custom storage credential provider.
    ///
    /// Use this to enable credential vending for S3, GCS, or Azure storage.
    pub fn with_credential_provider(
        mut self,
        provider: Arc<dyn StorageCredentialProvider>,
    ) -> Self {
        self.credential_provider = Some(provider);
        self
    }

    /// Sets rate limiting configuration.
    ///
    /// Use this to configure per-IP and per-tenant rate limits.
    pub fn with_rate_limit_config(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit_config = Some(config);
        self
    }

    /// Enables rate limiting with default configuration.
    pub fn with_rate_limiting(mut self) -> Self {
        self.rate_limit_config = Some(RateLimitConfig::default());
        self
    }

    /// Enables strict rate limiting (for production).
    pub fn with_strict_rate_limiting(mut self) -> Self {
        self.rate_limit_config = Some(RateLimitConfig::strict());
        self
    }

    /// Sets the idempotency cache TTL.
    ///
    /// Use this to configure how long idempotency keys are cached.
    /// Default is 24 hours.
    pub fn with_idempotency_ttl(mut self, ttl: Duration) -> Self {
        self.idempotency_ttl = Some(ttl);
        self
    }

    /// Sets the default tenant ID for single-tenant deployments.
    pub fn with_default_tenant_id<S: Into<String>>(mut self, tenant_id: S) -> Self {
        self.default_tenant_id = Some(tenant_id.into());
        self
    }

    /// Enables authentication and authorization.
    ///
    /// When enabled, uses API key authentication with RBAC authorization
    /// and tenant isolation by default.
    pub fn with_auth_enabled(mut self) -> Self {
        self.enable_auth = true;
        self
    }

    /// Configures JWT/OIDC authentication.
    ///
    /// When set, the app will support both API Key and JWT authentication.
    /// JWT authentication is tried first, falling back to API Keys if no JWT is present.
    pub fn with_jwt_config(mut self, config: JwtConfig) -> Self {
        self.jwt_config = Some(config);
        self
    }

    /// Sets CORS configuration.
    ///
    /// Use this to configure Cross-Origin Resource Sharing (CORS) policy.
    /// By default, CORS allows all origins (development mode).
    /// For production, specify allowed origins, methods, and headers.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::App;
    /// use rustberg::config::CorsConfig;
    ///
    /// let cors = CorsConfig {
    ///     allowed_origins: vec!["https://your-domain.com".to_string()],
    ///     allowed_methods: vec!["GET".to_string(), "POST".to_string()],
    ///     allowed_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
    /// };
    /// let app = App::builder().with_cors_config(cors).build();
    /// ```
    pub fn with_cors_config(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Sets the KMS configuration for encryption-at-rest.
    ///
    /// # Example
    /// ```no_run
    /// use rustberg::App;
    /// use rustberg::crypto::KmsConfig;
    ///
    /// let kms_config = KmsConfig::Env; // Use environment variables
    /// let app = App::builder().with_kms_config(kms_config).build();
    /// ```
    pub fn with_kms_config(mut self, config: crate::crypto::KmsConfig) -> Self {
        self.kms_config = Some(config);
        self
    }

    /// Sets the storage backend URL.
    ///
    /// Supported schemes:
    /// - `file:///path` - Local filesystem (default)
    /// - `s3://bucket/prefix` - Amazon S3
    /// - `gs://bucket/prefix` - Google Cloud Storage
    /// - `az://container/prefix` - Azure Blob Storage
    ///
    /// # Example
    /// ```no_run
    /// use rustberg::App;
    ///
    /// let app = App::builder()
    ///     .with_storage_backend("s3://my-bucket/catalog")
    ///     .build();
    /// ```
    pub fn with_storage_backend<S: Into<String>>(mut self, url: S) -> Self {
        self.storage_backend_url = Some(url.into());
        self
    }

    /// Sets the encryption key for API key storage encryption-at-rest.
    ///
    /// When set, API keys stored in persistent storage (KvApiKeyStore) will be
    /// encrypted using AES-256-GCM. The key must be exactly 32 bytes.
    ///
    /// # Security
    ///
    /// - Store this key securely (e.g., in a secrets manager)
    /// - Loss of this key = loss of access to stored API keys
    /// - Use `Aes256GcmProvider::generate_key()` to create a secure random key
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::App;
    /// use rustberg::crypto::Aes256GcmProvider;
    ///
    /// # async fn example() {
    /// // Generate a new key (store this securely!)
    /// let key = Aes256GcmProvider::generate_key();
    ///
    /// let (app, api_key_store) = App::builder()
    ///     .with_encryption_key(key)
    ///     .build_with_api_key_auth_async()
    ///     .await;
    /// # }
    /// ```
    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Enables table metadata encryption using the configured KMS.
    ///
    /// When enabled, table metadata properties are encrypted at rest using
    /// envelope encryption. Requires a KMS configuration to be set.
    ///
    /// # Security
    ///
    /// - Uses envelope encryption: per-table DEKs wrapped by KMS master key
    /// - DEKs are cached with configurable TTL for performance
    /// - Master key never leaves the KMS (AWS KMS, Vault, GCP, Azure)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::App;
    /// use rustberg::crypto::KmsConfig;
    ///
    /// # async fn example() {
    /// let (app, store) = App::builder()
    ///     .with_kms_config(KmsConfig::Env)
    ///     .with_table_encryption("rustberg-master")
    ///     .build_with_api_key_auth_async()
    ///     .await;
    /// # }
    /// ```
    pub fn with_table_encryption<S: Into<String>>(mut self, kms_key_id: S) -> Self {
        self.enable_table_encryption = true;
        self.kms_key_id = Some(kms_key_id.into());
        self
    }

    /// Sets IO timeout configuration for storage operations.
    ///
    /// Controls how long FileIO operations (metadata reads/writes) are allowed
    /// to take before being cancelled. Useful for preventing stalled cloud
    /// storage connections from blocking workers indefinitely.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::App;
    /// use std::time::Duration;
    ///
    /// let app = App::builder()
    ///     .with_io_timeouts(Duration::from_secs(90), Duration::from_secs(45))
    ///     .build();
    /// ```
    #[cfg(feature = "slatedb-storage")]
    pub fn with_io_timeouts(mut self, read_timeout: Duration, write_timeout: Duration) -> Self {
        self.io_timeout_config = Some(crate::catalog::IoTimeoutConfig::new(
            read_timeout,
            write_timeout,
        ));
        self
    }

    /// Creates a catalog based on the storage backend URL.
    /// Creates both a catalog and view store based on the storage backend URL.
    /// Uses the same SlateDB instance for both, ensuring persistent views.
    ///
    /// Supported backends:
    /// - `memory://` or None → MemoryCatalog (development/testing)
    /// - `file:///path` → SlateCatalog with local filesystem
    /// - `s3://bucket/path` → SlateCatalog with S3
    /// - `gs://bucket/path` → SlateCatalog with GCS
    /// - `az://container/path` → SlateCatalog with Azure Blob
    #[cfg(feature = "slatedb-storage")]
    async fn create_catalog_and_view_store(
        backend_url: Option<&str>,
        warehouse_location: &str,
        io_timeout_config: Option<crate::catalog::IoTimeoutConfig>,
    ) -> Result<(Arc<dyn CatalogExt + Send + Sync>, Arc<dyn ViewStore>), crate::error::AppError>
    {
        let (catalog, view_storage, _) =
            Self::create_all_stores(backend_url, warehouse_location, io_timeout_config).await?;
        Ok((catalog, view_storage))
    }

    /// Creates catalog, view store, and idempotency store based on storage backend URL.
    /// Uses the same SlateDB instance for all, ensuring persistence across restarts.
    #[cfg(feature = "slatedb-storage")]
    async fn create_all_stores(
        backend_url: Option<&str>,
        warehouse_location: &str,
        io_timeout_config: Option<crate::catalog::IoTimeoutConfig>,
    ) -> Result<
        (
            Arc<dyn CatalogExt + Send + Sync>,
            Arc<dyn ViewStore>,
            Option<Arc<dyn crate::catalog::IdempotencyStore>>,
        ),
        crate::error::AppError,
    > {
        use crate::catalog::{SlateCatalog, SlateDbIdempotencyStore, SlateDbViewStore};
        use object_store::local::LocalFileSystem;
        use object_store::ObjectStore;
        use slatedb::Db;

        match backend_url {
            Some(url) if url.starts_with("file://") => {
                let path = url.strip_prefix("file://").unwrap_or(url);
                tracing::info!(
                    backend = url,
                    path = path,
                    "Creating SlateDB catalog with local filesystem"
                );

                // Create directory if it doesn't exist
                std::fs::create_dir_all(path).map_err(|e| {
                    crate::error::AppError::Internal(format!("Failed to create directory: {}", e))
                })?;

                // Create local filesystem object store for SlateDB
                let object_store: Arc<dyn ObjectStore> =
                    Arc::new(LocalFileSystem::new_with_prefix(path).map_err(|e| {
                        crate::error::AppError::Internal(format!(
                            "Failed to create LocalFileSystem: {}",
                            e
                        ))
                    })?);

                // Create SlateDB instance at "catalog" path within the object store
                let db = Arc::new(Db::builder("catalog", object_store).build().await.map_err(
                    |e| crate::error::AppError::Internal(format!("Failed to open SlateDB: {}", e)),
                )?);

                // Create SlateDbViewStore with shared db instance
                let view_storage: Arc<dyn ViewStore> = Arc::new(SlateDbViewStore::new(db.clone()));

                // Create SlateDbIdempotencyStore with shared db instance
                let idempotency_store: Arc<dyn crate::catalog::IdempotencyStore> =
                    Arc::new(SlateDbIdempotencyStore::new(db.clone()));

                // Create SlateCatalog with FileIO pointed at warehouse location
                let io_timeouts = io_timeout_config.clone().unwrap_or_default();
                let slate_catalog =
                    SlateCatalog::with_timeouts(db, warehouse_location.to_string(), io_timeouts)
                        .await
                        .map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to create SlateCatalog: {}",
                                e
                            ))
                        })?;

                Ok((
                    Arc::new(ExtendedCatalog::new(slate_catalog)),
                    view_storage,
                    Some(idempotency_store),
                ))
            }
            Some(url)
                if url.starts_with("s3://")
                    || url.starts_with("gs://")
                    || url.starts_with("az://") =>
            {
                tracing::info!(backend = url, "Creating SlateDB catalog with cloud storage");

                // Parse cloud storage URL and create object store
                let (object_store, cloud_path) =
                    object_store::parse_url(&url::Url::parse(url).map_err(|e| {
                        crate::error::AppError::Internal(format!("Invalid URL: {}", e))
                    })?)
                    .map_err(|e| {
                        crate::error::AppError::Internal(format!(
                            "Failed to create object store: {}",
                            e
                        ))
                    })?;

                // Create SlateDB instance at "catalog" path within the cloud path
                let catalog_path = format!("{}/catalog", cloud_path);
                let db = Arc::new(
                    Db::builder(catalog_path, Arc::new(object_store))
                        .build()
                        .await
                        .map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to open SlateDB: {}",
                                e
                            ))
                        })?,
                );

                // Create SlateDbViewStore with shared db instance
                let view_storage: Arc<dyn ViewStore> = Arc::new(SlateDbViewStore::new(db.clone()));

                // Create SlateDbIdempotencyStore with shared db instance
                let idempotency_store: Arc<dyn crate::catalog::IdempotencyStore> =
                    Arc::new(SlateDbIdempotencyStore::new(db.clone()));

                // Create SlateCatalog with FileIO pointed at warehouse location
                let io_timeouts = io_timeout_config.unwrap_or_default();
                let slate_catalog =
                    SlateCatalog::with_timeouts(db, warehouse_location.to_string(), io_timeouts)
                        .await
                        .map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Failed to create SlateCatalog: {}",
                                e
                            ))
                        })?;

                Ok((
                    Arc::new(ExtendedCatalog::new(slate_catalog)),
                    view_storage,
                    Some(idempotency_store),
                ))
            }
            Some("memory://") | None => {
                tracing::info!("Creating MemoryCatalog for development/testing");

                let mut props = HashMap::new();
                props.insert("warehouse".to_string(), warehouse_location.to_string());

                let memory_catalog: iceberg::MemoryCatalog = MemoryCatalogBuilder::default()
                    .load("memory", props)
                    .await
                    .map_err(|e| {
                        crate::error::AppError::Internal(format!(
                            "Failed to create MemoryCatalog: {}",
                            e
                        ))
                    })?;

                // Use in-memory view storage for MemoryCatalog
                let view_storage: Arc<dyn ViewStore> = Arc::new(ViewStorage::new());

                // No persistent idempotency store for memory backend
                Ok((
                    Arc::new(ExtendedCatalog::new(memory_catalog)),
                    view_storage,
                    None,
                ))
            }
            Some(url) => Err(crate::error::AppError::Internal(format!(
                "Unsupported storage backend: {}",
                url
            ))),
        }
    }

    /// Creates a catalog when SlateDB feature is disabled.
    #[cfg(not(feature = "slatedb-storage"))]
    async fn create_catalog(
        backend_url: Option<&str>,
        warehouse_location: &str,
    ) -> Result<Arc<dyn CatalogExt + Send + Sync>, crate::error::AppError> {
        let (catalog, _) =
            Self::create_catalog_and_view_store(backend_url, warehouse_location).await?;
        Ok(catalog)
    }

    /// Creates both a catalog and view store when SlateDB feature is disabled.
    #[cfg(not(feature = "slatedb-storage"))]
    async fn create_catalog_and_view_store(
        backend_url: Option<&str>,
        warehouse_location: &str,
    ) -> Result<(Arc<dyn CatalogExt + Send + Sync>, Arc<dyn ViewStore>), crate::error::AppError>
    {
        if let Some(url) = backend_url {
            if !url.starts_with("memory://") {
                tracing::warn!(
                    backend = url,
                    "Storage backend specified but slatedb-storage feature not enabled. Using MemoryCatalog."
                );
            }
        }

        let mut props = HashMap::new();
        props.insert("warehouse".to_string(), warehouse_location.to_string());

        let memory_catalog: iceberg::MemoryCatalog = MemoryCatalogBuilder::default()
            .load("memory", props)
            .await
            .map_err(|e| {
                crate::error::AppError::Internal(format!("Failed to create MemoryCatalog: {}", e))
            })?;

        // Always use in-memory view storage when slatedb-storage is disabled
        let view_storage: Arc<dyn ViewStore> = Arc::new(ViewStorage::new());

        Ok((Arc::new(ExtendedCatalog::new(memory_catalog)), view_storage))
    }

    /// Creates an App with API key authentication pre-configured (async version).
    ///
    /// Returns both the App and the API key store for management.
    /// Use this when building from within an async context.
    pub async fn build_with_api_key_auth_async(self) -> (App, Arc<InMemoryApiKeyStore>) {
        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());

        let (base_catalog, view_storage) = if let Some(catalog) = self.catalog {
            // When custom catalog is provided, use in-memory view storage
            (catalog, Arc::new(ViewStorage::new()) as Arc<dyn ViewStore>)
        } else {
            // Create catalog and view storage based on storage backend URL
            #[cfg(feature = "slatedb-storage")]
            let result = Self::create_catalog_and_view_store(
                self.storage_backend_url.as_deref(),
                &warehouse_location,
                self.io_timeout_config.clone(),
            )
            .await
            .expect("Failed to create catalog");
            #[cfg(not(feature = "slatedb-storage"))]
            let result = Self::create_catalog_and_view_store(
                self.storage_backend_url.as_deref(),
                &warehouse_location,
            )
            .await
            .expect("Failed to create catalog");
            result
        };

        // Wrap catalog with encryption if enabled, and capture KMS metrics
        let (catalog, kms_metrics): (
            Arc<dyn CatalogExt + Send + Sync>,
            Option<Arc<crate::crypto::KmsMetrics>>,
        ) = if self.enable_table_encryption {
            if let Some(kms_config) = self.kms_config {
                let kms = create_kms(kms_config, None)
                    .await
                    .expect("Failed to create KMS for table encryption");

                // Extract KMS metrics before moving kms into EncryptedCatalog
                let kms_metrics = kms.kms_metrics();

                let key_id = self
                    .kms_key_id
                    .unwrap_or_else(|| "rustberg-master".to_string());
                tracing::info!(key_id = %key_id, "Table metadata encryption enabled with KMS");
                (
                    Arc::new(EncryptedCatalog::new(base_catalog, kms, key_id)),
                    kms_metrics,
                )
            } else {
                tracing::warn!(
                    "Table encryption requested but no KMS configured. \
                         Use with_kms_config() to configure KMS. Proceeding without encryption."
                );
                (base_catalog, None)
            }
        } else {
            (base_catalog, None)
        };

        // Create API key store
        let api_key_store = Arc::new(InMemoryApiKeyStore::new());

        // Create authenticator: API Key + optional JWT
        let authenticator: Arc<dyn Authenticator> = if let Some(jwt_config) = self.jwt_config {
            // Create JWT authenticator
            let jwt_auth = Arc::new(
                JwtAuthenticator::new(jwt_config).expect("Failed to create JWT authenticator"),
            );
            let api_key_auth = Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()));

            // Chain: JWT first (Bearer token), then API Key
            Arc::new(ChainAuthenticator::new(vec![jwt_auth, api_key_auth]))
        } else {
            // API Key only
            Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()))
        };

        // Create authorizer with tenant isolation and RBAC
        let rbac = Arc::new(RbacAuthorizer::new());
        let authorizer: Arc<dyn Authorizer> = Arc::new(ChainAuthorizer::new(vec![
            Arc::new(TenantIsolationAuthorizer::new(rbac.clone())),
            rbac,
        ]));

        // Use provided credential provider or default to noop
        let credential_provider = self
            .credential_provider
            .unwrap_or_else(|| Arc::new(NoopCredentialProvider::new()));

        // Create rate limiter (enabled by default for API key auth)
        let rate_limiter = Arc::new(RateLimiter::new(self.rate_limit_config.unwrap_or_default()));

        // Create idempotency cache
        let idempotency_cache = Arc::new(IdempotencyCache::new(
            self.idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL),
        ));

        // Create metrics registry with optional KMS metrics
        let mut registry = MetricsRegistry::new();
        if let Some(kms_m) = kms_metrics {
            registry.set_kms_metrics(kms_m);
            tracing::debug!("KMS metrics integrated with /metrics endpoint");
        }
        let metrics = Arc::new(registry);

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            rate_limiter,
            idempotency_cache,
            view_storage,
            metrics,
            warehouse_location,
            default_tenant_id,
        };

        let cors_config = self.cors_config.clone().unwrap_or_default();

        (
            App {
                app_state,
                cors_config,
            },
            api_key_store,
        )
    }

    /// Creates an App with persistent API key storage using KvApiKeyStore.
    ///
    /// Unlike `build_with_api_key_auth_async`, this method stores API keys in
    /// persistent storage (SlateDB) that survives server restarts.
    ///
    /// # Features
    ///
    /// - **Persistent storage**: API keys survive restarts
    /// - **Optional encryption**: AES-256-GCM encryption when key is provided
    /// - **K8s ready**: Horizontal scaling with S3/GCS object storage
    ///
    /// # Storage Backend
    ///
    /// Uses the same storage backend URL as the catalog:
    /// - `file:///path` - Local filesystem (single node)
    /// - `s3://bucket/prefix` - S3 (K8s horizontal scaling)
    /// - `memory://` - In-memory (testing only)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rustberg::App;
    /// use rustberg::crypto::Aes256GcmProvider;
    ///
    /// # async fn example() {
    /// // With encryption (recommended for production)
    /// let key = Aes256GcmProvider::generate_key();
    /// let (app, store) = App::builder()
    ///     .with_storage_backend("file:///data/catalog")
    ///     .with_encryption_key(key)
    ///     .build_with_persistent_api_key_auth_async()
    ///     .await;
    ///
    /// // Without encryption (for development)
    /// let (app, store) = App::builder()
    ///     .with_storage_backend("memory://")
    ///     .build_with_persistent_api_key_auth_async()
    ///     .await;
    /// # }
    /// ```
    #[cfg(feature = "slatedb-storage")]
    pub async fn build_with_persistent_api_key_auth_async(self) -> (App, Arc<KvApiKeyStore>) {
        use crate::storage::SlateDbStore;

        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());
        let storage_backend_url = self.storage_backend_url.clone();
        let enable_table_encryption = self.enable_table_encryption;
        let kms_config = self.kms_config.clone();
        let kms_key_id = self.kms_key_id.clone();
        let idempotency_ttl = self.idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL);

        // Create catalog, view storage, and idempotency store based on storage backend URL
        let (base_catalog, view_storage, idempotency_store) = if let Some(catalog) = self.catalog {
            // When custom catalog is provided, use in-memory stores
            (
                catalog,
                Arc::new(ViewStorage::new()) as Arc<dyn ViewStore>,
                None,
            )
        } else {
            Self::create_all_stores(
                storage_backend_url.as_deref(),
                &warehouse_location,
                self.io_timeout_config.clone(),
            )
            .await
            .expect("Failed to create catalog and storage")
        };

        // Wrap catalog with encryption if enabled, and capture KMS metrics
        let (catalog, kms_metrics): (
            Arc<dyn CatalogExt + Send + Sync>,
            Option<Arc<crate::crypto::KmsMetrics>>,
        ) = if enable_table_encryption {
            if let Some(kms_config) = kms_config {
                let kms = create_kms(kms_config, None)
                    .await
                    .expect("Failed to create KMS for table encryption");

                // Extract KMS metrics before moving kms into EncryptedCatalog
                let kms_metrics = kms.kms_metrics();

                let key_id = kms_key_id.unwrap_or_else(|| "rustberg-master".to_string());
                tracing::info!(key_id = %key_id, "Table metadata encryption enabled with KMS");
                (
                    Arc::new(EncryptedCatalog::new(base_catalog, kms, key_id)),
                    kms_metrics,
                )
            } else {
                tracing::warn!(
                    "Table encryption requested but no KMS configured. \
                         Use with_kms_config() to configure KMS. Proceeding without encryption."
                );
                (base_catalog, None)
            }
        } else {
            (base_catalog, None)
        };

        // Create KvStore for API key storage
        // Use "apikeys" subdirectory to separate from catalog data
        let kv_url = match &storage_backend_url {
            Some(url) if url.starts_with("file://") => {
                let base = url.strip_prefix("file://").unwrap_or(url);
                format!("file://{}/apikeys", base)
            }
            Some(url)
                if url.starts_with("s3://")
                    || url.starts_with("gs://")
                    || url.starts_with("az://") =>
            {
                format!("{}/apikeys", url.trim_end_matches('/'))
            }
            _ => "memory://apikeys".to_string(),
        };

        // Ensure directory exists for file:// URLs
        if kv_url.starts_with("file://") {
            let path = kv_url.strip_prefix("file://").unwrap_or(&kv_url);
            if let Err(e) = std::fs::create_dir_all(path) {
                tracing::warn!(path = %path, error = %e, "Failed to create API key storage directory");
            }
        }

        let kv = Arc::new(
            SlateDbStore::open_url(&kv_url)
                .await
                .expect("Failed to open API key storage"),
        );

        // Create encryption provider if key is provided
        let encryption: Option<Arc<dyn EncryptionProvider>> = self.encryption_key.map(|key| {
            Arc::new(Aes256GcmProvider::new(&key).expect("Invalid encryption key"))
                as Arc<dyn EncryptionProvider>
        });

        // Log encryption status
        if encryption.is_some() {
            tracing::info!(
                storage = %kv_url,
                "Created persistent API key store with AES-256-GCM encryption"
            );
        } else {
            tracing::warn!(
                storage = %kv_url,
                "Created persistent API key store WITHOUT encryption. \
                 Use with_encryption_key() for production deployments."
            );
        }

        // Create persistent API key store
        let api_key_store = Arc::new(KvApiKeyStore::new(kv, encryption));

        // Create authenticator: API Key + optional JWT
        let authenticator: Arc<dyn Authenticator> = if let Some(jwt_config) = self.jwt_config {
            let jwt_auth = Arc::new(
                JwtAuthenticator::new(jwt_config).expect("Failed to create JWT authenticator"),
            );
            let api_key_auth = Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()));
            Arc::new(ChainAuthenticator::new(vec![jwt_auth, api_key_auth]))
        } else {
            Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()))
        };

        // Create authorizer with tenant isolation and RBAC
        let rbac = Arc::new(RbacAuthorizer::new());
        let authorizer: Arc<dyn Authorizer> = Arc::new(ChainAuthorizer::new(vec![
            Arc::new(TenantIsolationAuthorizer::new(rbac.clone())),
            rbac,
        ]));

        // Use provided credential provider or default to noop
        let credential_provider = self
            .credential_provider
            .unwrap_or_else(|| Arc::new(NoopCredentialProvider::new()));

        // Create rate limiter (enabled by default for API key auth)
        let rate_limiter = Arc::new(RateLimiter::new(self.rate_limit_config.unwrap_or_default()));

        // Create idempotency cache with optional persistent backing store
        let idempotency_cache = if let Some(store) = idempotency_store {
            let cache = IdempotencyCache::with_persistent_store(idempotency_ttl, store);
            // Bootstrap from persistent store
            if let Err(e) = cache.bootstrap_from_store().await {
                tracing::warn!(error = %e, "Failed to bootstrap idempotency cache from persistent store");
            }
            Arc::new(cache)
        } else {
            Arc::new(IdempotencyCache::new(idempotency_ttl))
        };

        // Create metrics registry with optional KMS metrics
        let mut registry = MetricsRegistry::new();
        if let Some(kms_m) = kms_metrics {
            registry.set_kms_metrics(kms_m);
            tracing::debug!("KMS metrics integrated with /metrics endpoint");
        }
        let metrics = Arc::new(registry);

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            rate_limiter,
            idempotency_cache,
            view_storage,
            metrics,
            warehouse_location,
            default_tenant_id,
        };

        let cors_config = self.cors_config.clone().unwrap_or_default();

        (
            App {
                app_state,
                cors_config,
            },
            api_key_store,
        )
    }

    /// Creates an App with API key authentication pre-configured.
    ///
    /// Returns both the App and the API key store for management.
    ///
    /// # Panics
    ///
    /// Panics if called from within an async context (use `build_with_api_key_auth_async` instead).
    /// Also panics if the Tokio runtime, catalog, or KMS cannot be created.
    pub fn build_with_api_key_auth(self) -> (App, Arc<InMemoryApiKeyStore>) {
        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());
        let rate_limit_config = self.rate_limit_config.clone();
        let idempotency_ttl = self.idempotency_ttl;
        let jwt_config = self.jwt_config.clone();
        let storage_backend_url = self.storage_backend_url.clone();
        let warehouse_clone = warehouse_location.clone();
        let enable_table_encryption = self.enable_table_encryption;
        let kms_config = self.kms_config.clone();

        let (base_catalog, view_storage): (Arc<dyn CatalogExt + Send + Sync>, Arc<dyn ViewStore>) =
            if let Some(catalog) = self.catalog {
                (catalog, Arc::new(ViewStorage::new()))
            } else {
                // Create catalog and view storage using tokio runtime
                tokio::runtime::Runtime::new()
                    .expect("Failed to create Tokio runtime — do not call from async context, use build_with_api_key_auth_async() instead")
                    .block_on(async {
                    #[cfg(feature = "slatedb-storage")]
                    let result = Self::create_catalog_and_view_store(storage_backend_url.as_deref(), &warehouse_clone, self.io_timeout_config.clone())
                        .await
                        .expect("Failed to create catalog");
                    #[cfg(not(feature = "slatedb-storage"))]
                    let result = Self::create_catalog_and_view_store(storage_backend_url.as_deref(), &warehouse_clone)
                        .await
                        .expect("Failed to create catalog");
                    result
                })
            };

        // Wrap catalog with encryption if enabled, and capture KMS metrics
        let (catalog, kms_metrics): (
            Arc<dyn CatalogExt + Send + Sync>,
            Option<Arc<crate::crypto::KmsMetrics>>,
        ) = if enable_table_encryption {
            if let Some(kms_config) = kms_config {
                // Create KMS using tokio runtime
                let kms = tokio::runtime::Runtime::new()
                    .expect("Failed to create Tokio runtime for KMS")
                    .block_on(async {
                        create_kms(kms_config, None)
                            .await
                            .expect("Failed to create KMS for table encryption")
                    });

                // Extract KMS metrics before moving kms into EncryptedCatalog
                let kms_metrics = kms.kms_metrics();

                let key_id = self
                    .kms_key_id
                    .unwrap_or_else(|| "rustberg-master".to_string());
                tracing::info!(key_id = %key_id, "Table metadata encryption enabled with KMS");
                (
                    Arc::new(EncryptedCatalog::new(base_catalog, kms, key_id)),
                    kms_metrics,
                )
            } else {
                tracing::warn!(
                    "Table encryption requested but no KMS configured. \
                         Use with_kms_config() to configure KMS. Proceeding without encryption."
                );
                (base_catalog, None)
            }
        } else {
            (base_catalog, None)
        };

        // Create API key store
        let api_key_store = Arc::new(InMemoryApiKeyStore::new());

        // Create authenticator: API Key + optional JWT
        let authenticator: Arc<dyn Authenticator> = if let Some(jwt_config) = jwt_config {
            // Create JWT authenticator
            let jwt_auth = Arc::new(
                JwtAuthenticator::new(jwt_config).expect("Failed to create JWT authenticator"),
            );
            let api_key_auth = Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()));

            // Chain: JWT first (Bearer token), then API Key
            Arc::new(ChainAuthenticator::new(vec![jwt_auth, api_key_auth]))
        } else {
            // API Key only
            Arc::new(ApiKeyAuthenticator::new(api_key_store.clone()))
        };

        // Create authorizer with tenant isolation and RBAC
        let rbac = Arc::new(RbacAuthorizer::new());
        let authorizer: Arc<dyn Authorizer> = Arc::new(ChainAuthorizer::new(vec![
            Arc::new(TenantIsolationAuthorizer::new(rbac.clone())),
            rbac,
        ]));

        // Use provided credential provider or default to noop
        let credential_provider = self
            .credential_provider
            .unwrap_or_else(|| Arc::new(NoopCredentialProvider::new()));

        // Create rate limiter (enabled by default for API key auth)
        let rate_limiter = Arc::new(RateLimiter::new(rate_limit_config.unwrap_or_default()));

        // Create idempotency cache
        let idempotency_cache = Arc::new(IdempotencyCache::new(
            idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL),
        ));

        // Create metrics registry with optional KMS metrics
        let mut registry = MetricsRegistry::new();
        if let Some(kms_m) = kms_metrics {
            registry.set_kms_metrics(kms_m);
            tracing::debug!("KMS metrics integrated with /metrics endpoint");
        }
        let metrics = Arc::new(registry);

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            rate_limiter,
            idempotency_cache,
            view_storage,
            metrics,
            warehouse_location,
            default_tenant_id,
        };

        let cors_config = self.cors_config.unwrap_or_default();

        (
            App {
                app_state,
                cors_config,
            },
            api_key_store,
        )
    }

    /// Builds the App with the configured options (async version).
    ///
    /// Use this when building from within an async context.
    pub async fn build_async(self) -> App {
        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());

        let (catalog, view_storage) = if let Some(catalog) = self.catalog {
            // If custom catalog provided, use MemoryViewStore
            (
                catalog,
                Arc::new(MemoryViewStore::new()) as Arc<dyn ViewStore>,
            )
        } else {
            // Create catalog and view store based on storage backend URL
            #[cfg(feature = "slatedb-storage")]
            let result = Self::create_catalog_and_view_store(
                self.storage_backend_url.as_deref(),
                &warehouse_location,
                self.io_timeout_config.clone(),
            )
            .await
            .expect("Failed to create catalog and view store");
            #[cfg(not(feature = "slatedb-storage"))]
            let result = Self::create_catalog_and_view_store(
                self.storage_backend_url.as_deref(),
                &warehouse_location,
            )
            .await
            .expect("Failed to create catalog and view store");
            result
        };

        let (authenticator, authorizer): (Arc<dyn Authenticator>, Arc<dyn Authorizer>) = if self
            .enable_auth
        {
            // Default secure configuration
            let api_key_store = Arc::new(InMemoryApiKeyStore::new());

            // Create authenticator: API Key + optional JWT
            let authenticator: Arc<dyn Authenticator> = if let Some(jwt_config) = self.jwt_config {
                // Create JWT authenticator
                let jwt_auth = Arc::new(
                    JwtAuthenticator::new(jwt_config).expect("Failed to create JWT authenticator"),
                );
                let api_key_auth = Arc::new(ApiKeyAuthenticator::new(api_key_store));

                // Chain: JWT first (Bearer token), then API Key
                Arc::new(ChainAuthenticator::new(vec![jwt_auth, api_key_auth]))
            } else {
                // API Key only
                Arc::new(ApiKeyAuthenticator::new(api_key_store))
            };

            let rbac = Arc::new(RbacAuthorizer::new());
            let authorizer = Arc::new(ChainAuthorizer::new(vec![
                Arc::new(TenantIsolationAuthorizer::new(rbac.clone())),
                rbac,
            ]));

            (authenticator, authorizer)
        } else {
            // Development mode - allow all
            let authenticator = self
                .authenticator
                .unwrap_or_else(|| Arc::new(AllowAllAuthenticator));

            let authorizer = self
                .authorizer
                .unwrap_or_else(|| Arc::new(AllowAllAuthorizer));

            (authenticator, authorizer)
        };

        // Use provided credential provider or default to noop
        let credential_provider = self
            .credential_provider
            .unwrap_or_else(|| Arc::new(NoopCredentialProvider::new()));

        // Create rate limiter (disabled by default in dev mode for build_async, unless explicitly configured)
        let rate_limiter = Arc::new(RateLimiter::new(self.rate_limit_config.unwrap_or_else(
            || {
                if self.enable_auth {
                    RateLimitConfig::default()
                } else {
                    RateLimitConfig::disabled()
                }
            },
        )));

        // Create idempotency cache
        let idempotency_cache = Arc::new(IdempotencyCache::new(
            self.idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL),
        ));

        // Create metrics registry
        let metrics = Arc::new(MetricsRegistry::new());

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            rate_limiter,
            idempotency_cache,
            view_storage,
            metrics,
            warehouse_location,
            default_tenant_id,
        };

        let cors_config = self.cors_config.clone().unwrap_or_default();

        App {
            app_state,
            cors_config,
        }
    }

    /// Builds the App with the configured options.
    ///
    /// # Panics
    ///
    /// Panics if called from within an async context (use `build_async` instead).
    /// Also panics if the Tokio runtime, catalog, or KMS cannot be created.
    pub fn build(self) -> App {
        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());
        let storage_backend_url = self.storage_backend_url.clone();
        let warehouse_clone = warehouse_location.clone();
        let enable_table_encryption = self.enable_table_encryption;
        let kms_config = self.kms_config.clone();

        let (base_catalog, view_storage): (Arc<dyn CatalogExt + Send + Sync>, Arc<dyn ViewStore>) =
            if let Some(catalog) = self.catalog {
                // If custom catalog provided, use MemoryViewStore
                (
                    catalog,
                    Arc::new(MemoryViewStore::new()) as Arc<dyn ViewStore>,
                )
            } else {
                // Create catalog and view store using tokio runtime
                tokio::runtime::Runtime::new()
                .expect("Failed to create Tokio runtime — do not call from async context, use build_async() instead")
                .block_on(async {
                #[cfg(feature = "slatedb-storage")]
                let result = Self::create_catalog_and_view_store(storage_backend_url.as_deref(), &warehouse_clone, self.io_timeout_config.clone())
                    .await
                    .expect("Failed to create catalog and view store");
                #[cfg(not(feature = "slatedb-storage"))]
                let result = Self::create_catalog_and_view_store(storage_backend_url.as_deref(), &warehouse_clone)
                    .await
                    .expect("Failed to create catalog and view store");
                result
            })
            };

        // Wrap catalog with encryption if enabled, and capture KMS metrics
        let (catalog, kms_metrics): (
            Arc<dyn CatalogExt + Send + Sync>,
            Option<Arc<crate::crypto::KmsMetrics>>,
        ) = if enable_table_encryption {
            if let Some(kms_config) = kms_config {
                // Create KMS using tokio runtime
                let kms = tokio::runtime::Runtime::new()
                    .expect("Failed to create Tokio runtime for KMS")
                    .block_on(async {
                        create_kms(kms_config, None)
                            .await
                            .expect("Failed to create KMS for table encryption")
                    });

                // Extract KMS metrics before moving kms into EncryptedCatalog
                let kms_metrics = kms.kms_metrics();

                let key_id = self
                    .kms_key_id
                    .clone()
                    .unwrap_or_else(|| "rustberg-master".to_string());
                tracing::info!(key_id = %key_id, "Table metadata encryption enabled with KMS");
                (
                    Arc::new(EncryptedCatalog::new(base_catalog, kms, key_id)),
                    kms_metrics,
                )
            } else {
                tracing::warn!(
                    "Table encryption requested but no KMS configured. \
                         Use with_kms_config() to configure KMS. Proceeding without encryption."
                );
                (base_catalog, None)
            }
        } else {
            (base_catalog, None)
        };

        let (authenticator, authorizer): (Arc<dyn Authenticator>, Arc<dyn Authorizer>) = if self
            .enable_auth
        {
            // Default secure configuration
            let api_key_store = Arc::new(InMemoryApiKeyStore::new());

            // Create authenticator: API Key + optional JWT
            let authenticator: Arc<dyn Authenticator> = if let Some(jwt_config) = self.jwt_config {
                // Create JWT authenticator
                let jwt_auth = Arc::new(
                    JwtAuthenticator::new(jwt_config).expect("Failed to create JWT authenticator"),
                );
                let api_key_auth = Arc::new(ApiKeyAuthenticator::new(api_key_store));

                // Chain: JWT first (Bearer token), then API Key
                Arc::new(ChainAuthenticator::new(vec![jwt_auth, api_key_auth]))
            } else {
                // API Key only
                Arc::new(ApiKeyAuthenticator::new(api_key_store))
            };

            let rbac = Arc::new(RbacAuthorizer::new());
            let authorizer = Arc::new(ChainAuthorizer::new(vec![
                Arc::new(TenantIsolationAuthorizer::new(rbac.clone())),
                rbac,
            ]));

            (authenticator, authorizer)
        } else {
            // Development mode - allow all
            let authenticator = self
                .authenticator
                .unwrap_or_else(|| Arc::new(AllowAllAuthenticator));

            let authorizer = self
                .authorizer
                .unwrap_or_else(|| Arc::new(AllowAllAuthorizer));

            (authenticator, authorizer)
        };

        // Use provided credential provider or default to noop
        let credential_provider = self
            .credential_provider
            .unwrap_or_else(|| Arc::new(NoopCredentialProvider::new()));

        // Create rate limiter (disabled by default in dev mode, unless explicitly configured)
        let rate_limiter = Arc::new(RateLimiter::new(self.rate_limit_config.unwrap_or_else(
            || {
                if self.enable_auth {
                    RateLimitConfig::default()
                } else {
                    RateLimitConfig::disabled()
                }
            },
        )));

        // Create idempotency cache
        let idempotency_cache = Arc::new(IdempotencyCache::new(
            self.idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL),
        ));

        // Create metrics registry with optional KMS metrics
        let mut registry = MetricsRegistry::new();
        if let Some(kms_m) = kms_metrics {
            registry.set_kms_metrics(kms_m);
            tracing::debug!("KMS metrics integrated with /metrics endpoint");
        }
        let metrics = Arc::new(registry);

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            rate_limiter,
            idempotency_cache,
            view_storage,
            metrics,
            warehouse_location,
            default_tenant_id,
        };

        let cors_config = self.cors_config.unwrap_or_default();

        App {
            app_state,
            cors_config,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_builder_default() {
        let app = App::builder().build();
        assert!(!app.state().warehouse_location.is_empty());
        assert_eq!(app.state().default_tenant_id(), "default");
    }

    #[test]
    fn test_app_builder_custom_warehouse() {
        // Use a cross-platform compatible path format
        // On Windows, paths with drive letters are misinterpreted as URL schemes
        let warehouse = if cfg!(windows) {
            "file:///C:/custom/warehouse".to_string()
        } else {
            "/custom/warehouse".to_string()
        };

        let app = App::builder().with_warehouse_location(&warehouse).build();

        assert_eq!(app.state().warehouse_location, warehouse);
    }

    #[test]
    fn test_app_builder_custom_tenant() {
        let app = App::builder().with_default_tenant_id("my-tenant").build();

        assert_eq!(app.state().default_tenant_id(), "my-tenant");
    }

    #[test]
    fn test_app_with_api_key_auth() {
        let (app, store) = App::builder().build_with_api_key_auth();
        assert!(Arc::strong_count(&store) >= 1);
        assert_eq!(app.state().default_tenant_id(), "default");
    }

    #[tokio::test]
    async fn test_security_headers_present() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // Build the app synchronously (no async needed for in-memory setup)
        let warehouse = crate::utils::temp_path();
        let mut props = HashMap::new();
        props.insert("warehouse".to_string(), warehouse.clone());

        let memory_catalog: iceberg::MemoryCatalog = MemoryCatalogBuilder::default()
            .load("memory", props)
            .await
            .unwrap();

        let catalog = Arc::new(ExtendedCatalog::new(memory_catalog));

        let app = App::builder()
            .with_catalog(catalog)
            .with_warehouse_location(&warehouse)
            .build();
        let router = app.into_router();

        // Make a request to the health endpoint
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify security headers are present
        assert!(response.headers().contains_key("x-content-type-options"));
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );

        assert!(response.headers().contains_key("x-frame-options"));
        assert_eq!(response.headers().get("x-frame-options").unwrap(), "DENY");

        assert!(response.headers().contains_key("content-security-policy"));
        assert_eq!(
            response.headers().get("content-security-policy").unwrap(),
            "default-src 'none'; frame-ancestors 'none'"
        );

        assert!(response.headers().contains_key("cache-control"));
        assert_eq!(
            response.headers().get("cache-control").unwrap(),
            "no-store, no-cache, must-revalidate"
        );

        assert!(response.headers().contains_key("x-xss-protection"));
        assert_eq!(
            response.headers().get("x-xss-protection").unwrap(),
            "1; mode=block"
        );
    }

    #[cfg(feature = "slatedb-storage")]
    #[tokio::test]
    async fn test_build_with_persistent_api_key_auth_async() {
        use crate::auth::{ApiKeyBuilder, ApiKeyStore};

        // Build with memory backend (no encryption)
        let (app, store) = App::builder()
            .with_storage_backend("memory://")
            .build_with_persistent_api_key_auth_async()
            .await;

        assert!(Arc::strong_count(&store) >= 1);
        assert_eq!(app.state().default_tenant_id(), "default");

        // Verify we can use the store
        let (key, _plaintext) = ApiKeyBuilder::new("Test Key", "test-tenant")
            .with_role("read")
            .build();

        store.store(key.clone()).await.unwrap();

        let loaded = store.get_by_id(&key.id).await;
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "Test Key");
    }

    #[cfg(feature = "slatedb-storage")]
    #[tokio::test]
    async fn test_build_with_persistent_api_key_auth_with_encryption() {
        use crate::auth::{ApiKeyBuilder, ApiKeyStore};
        use crate::crypto::Aes256GcmProvider;

        // Generate encryption key
        let enc_key = Aes256GcmProvider::generate_key();

        // Build with memory backend + encryption
        let (app, store) = App::builder()
            .with_storage_backend("memory://")
            .with_encryption_key(enc_key)
            .build_with_persistent_api_key_auth_async()
            .await;

        assert!(Arc::strong_count(&store) >= 1);
        assert_eq!(app.state().default_tenant_id(), "default");

        // Verify we can use the store with encryption
        let (api_key, _plaintext) = ApiKeyBuilder::new("Encrypted Key", "test-tenant")
            .with_role("admin")
            .build();

        store.store(api_key.clone()).await.unwrap();

        let loaded = store.get_by_id(&api_key.id).await;
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().name, "Encrypted Key");
    }
}
