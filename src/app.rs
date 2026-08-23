//! Application builder and state management.
//!
//! This module provides the main App structure that configures and runs
//! the Iceberg REST Catalog service.

use axum::Router;
use axum::http::{HeaderName, HeaderValue, Method};
use std::sync::Arc;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::{self, TraceLayer};
use tracing::Level;

use crate::auth::{
    AllowAllAuthenticator, AllowAllAuthorizer, ApiKeyAuthenticator, Authenticator, Authorizer,
    CedarAuthorizer, ChainAuthenticator, InMemoryApiKeyStore, JwtAuthenticator, JwtConfig,
    RateLimitConfig, RateLimiter,
};
use crate::catalog::{self, CatalogStore, IdempotencyCache};
use crate::config;
use crate::config::CorsConfig;
use crate::credentials::{NoopCredentialProvider, StorageCredentialProvider};
use crate::observability::metrics::MetricsRegistry;
use crate::utils::temp_path;

// ============================================================================
// App State
// ============================================================================

/// This server's own warehouse.
///
/// A newtype rather than a `String`, and deliberately without `Display` or
/// `Deref`, so it cannot be passed anywhere a warehouse is expected. Under
/// federation there is no such thing as *the* warehouse — each mount has its
/// own — and reaching for this one has twice produced a bug that compiled
/// perfectly: once checking a client-supplied location against the wrong
/// warehouse, once building a view's default location in it.
///
/// The two accessors name the only situations where "this server's own" is the
/// right question. Anything else wants [`AppState::warehouse_for`], and now has
/// to say so to the type checker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultWarehouse(String);

impl DefaultWarehouse {
    /// Wraps the configured warehouse.
    pub fn new(location: impl Into<String>) -> Self {
        Self(location.into())
    }

    /// The value `GET /v1/config` advertises as `overrides.warehouse`.
    ///
    /// The override names the catalog a client is talking to, and no namespace
    /// is in scope to resolve a mount's warehouse from. It is the default, not
    /// a claim that everything lives there.
    pub fn advertised(&self) -> &str {
        &self.0
    }

    /// The warehouse to use when a catalog declares none of its own.
    ///
    /// Only [`AppState::warehouse_for`] should call this; it is the tail of
    /// that resolution, not a way around it.
    pub fn as_fallback(&self) -> &str {
        &self.0
    }
}

/// Everything needed to administer policy at runtime.
///
/// Absent for a deployment whose authorizer does not evaluate policy — the
/// `--no-auth` development mode — where the management endpoints answer `501`
/// rather than pretending to administer something nothing consults.
#[derive(Clone)]
pub struct PolicyAdmin {
    /// The append-only log of policy revisions.
    pub store: Arc<dyn crate::auth::policy_store::PolicyStore>,
    /// The live authorizer, so a change takes effect without a restart.
    pub authorizer: Arc<crate::auth::reloadable::ReloadableAuthorizer>,
    /// Keeps the replica in step with the store; stops when the last clone of
    /// this state is dropped.
    ///
    /// Never read, and that is the whole mechanism: the field exists so the
    /// poller's lifetime is tied to the application's. Removing it because
    /// nothing reads it would restore the leak it was added to close.
    #[allow(dead_code, reason = "held for its Drop; see above")]
    poller: Arc<crate::auth::reloadable::PolicyPoller>,
}

impl std::fmt::Debug for PolicyAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyAdmin")
            .field("loaded_sequence", &self.authorizer.loaded_sequence())
            .finish_non_exhaustive()
    }
}

/// Shared application state passed to all request handlers.
#[derive(Clone)]
pub struct AppState {
    /// The authenticator for validating credentials.
    pub authenticator: Arc<dyn Authenticator>,
    /// The authorizer for checking permissions.
    pub authorizer: Arc<dyn Authorizer>,
    /// The Iceberg catalog implementation with extended commit capabilities.
    pub catalog: Arc<dyn CatalogStore>,
    /// Storage credential provider for vending temporary credentials.
    pub credential_provider: Arc<dyn StorageCredentialProvider>,
    /// Signs individual storage requests, for clients that hold no credential.
    pub request_signer: Arc<dyn crate::credentials::RequestSigner>,
    /// How the sign endpoint reads storage addresses, and whether it is served.
    pub signing: crate::catalog::v1::sign::SigningEndpointConfig,
    /// Rate limiter for protecting against DoS and brute-force attacks.
    pub rate_limiter: Arc<RateLimiter>,
    /// Idempotency cache for preventing duplicate request processing.
    pub idempotency_cache: Arc<IdempotencyCache>,
    /// Prometheus metrics registry for observability.
    pub metrics: Arc<MetricsRegistry>,
    /// Where authorization decisions are recorded.
    pub auditor: Arc<crate::auth::Auditor>,
    /// Fallback warehouse, for a namespace whose catalog declares none.
    ///
    /// **Prefer [`warehouse_for`](Self::warehouse_for).** Under federation this
    /// is not "the" warehouse — each mount has its own, and a table created in a
    /// mount belongs in that one. Reading this field where a namespace is in
    /// scope confines a location to the wrong warehouse, or builds a default
    /// location in it.
    ///
    /// Legitimate uses are the ones that genuinely mean *this server's own*:
    /// the `warehouse` override in `GET /v1/config`, and the fallback inside
    /// `warehouse_for` itself. Its type enforces that.
    pub default_warehouse: DefaultWarehouse,
    /// Default tenant ID for single-tenant deployments.
    pub default_tenant_id: String,
    /// The identity provider's token endpoint, advertised to clients.
    pub oauth2_server_uri: Option<String>,
    /// Runtime policy administration, when this deployment evaluates policy.
    pub policy_admin: Option<PolicyAdmin>,
    /// What every mount supports, which is what `/v1/config` advertises.
    pub capabilities: crate::catalog::Capabilities,
}

impl AppState {
    /// The warehouse governing `namespace`.
    ///
    /// The answer differs per namespace once mounts exist, so this asks the
    /// catalog rather than assuming. Falls back to
    /// [`default_warehouse`](Self::default_warehouse) for a backend that
    /// declares none — a remote mount, which stores nothing of its own.
    ///
    /// Every location decision goes through here: the confinement check that
    /// keeps a client-supplied location inside a warehouse, and the default
    /// location a view is created at.
    pub async fn warehouse_for(&self, namespace: &iceberg::NamespaceIdent) -> String {
        self.catalog
            .warehouse_for(namespace)
            .await
            .unwrap_or_else(|| self.default_warehouse.as_fallback().to_string())
    }

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

    /// The catalog as Rust, acting as `principal`.
    ///
    /// This is the in-process form of the product: the same operations the REST
    /// handlers expose, authorized by the same [`guard`], with no router and no
    /// serialisation. Authentication is the host's — it has already established
    /// who the caller is, and should not have to attach a JWKS client to say so.
    ///
    /// A policy reading `context.source_ip` fails closed here unless the host
    /// supplies it with
    /// [`Session::with_request_context`](crate::catalog::Session::with_request_context),
    /// which is correct: an in-process call has no connection behind it.
    ///
    /// [`guard`]: crate::catalog::v1::guard
    pub fn as_principal(&self, principal: crate::auth::Principal) -> crate::catalog::Session {
        crate::catalog::Session::new(self.app_state.clone(), principal)
    }

    /// Converts the App into an Axum Router ready for serving.
    pub fn into_router(self) -> Router {
        use crate::auth::{AuthState, auth_middleware, routes as auth_routes};
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
        // Rustberg's own administration surface, deliberately outside `/v1`
        // so `GET /v1/config` stays a complete description of the Iceberg API.
        let management_routes = crate::management::create_routes(self.app_state.clone());
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

        // Only an explicit `*` is permissive. An empty list means no cross-origin
        // access, which is the default — see `default_allowed_origins`.
        if self.cors_config.allowed_origins.iter().any(|o| o == "*") {
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
        // A default rather than an override: catalog responses carry metadata and
        // credentials and must not be cached, but the sign endpoint is required
        // to mark a read signature `private` so a client may reuse it. An
        // overriding layer erased that and turned one signature per file into one
        // per request.
        let cache_control = SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store, no-cache, must-revalidate"),
        );
        let x_xss_protection = SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-xss-protection"),
            HeaderValue::from_static("1; mode=block"),
        );

        // Everything that speaks for a caller, and therefore needs one.
        //
        // Layered onto *these routes only*. A `layer` applies to every route
        // merged above it, so layering auth onto the whole router would make
        // `/health` answer `401` — and a Kubernetes liveness probe carries no
        // credential, so every pod would restart-loop.
        let protected = Router::new()
            .merge(catalog_routes)
            .merge(config_routes)
            .merge(auth_context_routes)
            .nest("/management", management_routes)
            .layer(middleware::from_fn_with_state(auth_state, auth_middleware));

        // Open by design: a liveness probe cannot hold a credential, and a
        // Prometheus scrape should not need one. Neither endpoint reveals
        // catalog contents — `/health` and `/ready` report reachability, and the
        // metrics are aggregate counters with no tenant, namespace or table
        // labels. Restrict them at the network layer if a deployment needs to;
        // the Helm chart's NetworkPolicy is where that belongs.
        let public = Router::new()
            .merge(health_routes)
            .merge(metrics_routes)
            .merge(auth_routes::create_public_routes());

        Router::new()
            .merge(public)
            .merge(protected)
            .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_SIZE))
            .layer(TimeoutLayer::with_status_code(
                axum::http::StatusCode::REQUEST_TIMEOUT,
                REQUEST_TIMEOUT,
            ))
            // Outside the auth layer, so a CORS preflight — which carries no
            // credentials by design — is answered rather than rejected.
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
    ///
    /// An empty origin list yields a layer that permits no origin, so no
    /// `Access-Control-Allow-Origin` is sent and a browser blocks the response.
    /// Non-browser clients are unaffected — CORS is enforced by the browser, not
    /// by the server.
    ///
    /// A configured origin that fails to parse is **dropped with a warning**,
    /// never widened to `Any`. Falling back to `Any` on an empty parse result
    /// would turn a single typo in one origin into an open policy.
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
        if self.cors_config.allowed_origins.iter().any(|o| o == "*") {
            cors = cors.allow_origin(Any);
        } else {
            let mut origins = Vec::new();
            for origin in &self.cors_config.allowed_origins {
                match origin.parse() {
                    Ok(parsed) => origins.push(parsed),
                    Err(_) => tracing::warn!(
                        origin = %origin,
                        "Ignoring unparseable CORS origin; it will not be allowed"
                    ),
                }
            }
            // An empty list permits nothing. This is the default.
            cors = cors.allow_origin(AllowOrigin::list(origins));
        }

        // Configure allowed headers. Unlike origins, `*` here is the sensible
        // default: the headers an Iceberg client sends are fixed by the spec, and
        // restricting them protects nothing that the origin check does not.
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

/// Builds the Cedar authorizer from an optional policy source.
///
/// Panics on invalid policies: serving with an authorization policy the operator
/// believes is active but which does not typecheck is strictly worse than
/// refusing to start.
fn build_authorizer(policies: Option<&str>) -> CedarAuthorizer {
    match policies {
        Some(src) => CedarAuthorizer::new(src).expect("Cedar policies must validate"),
        None => CedarAuthorizer::with_default_policies().expect("default policies must validate"),
    }
}

// ============================================================================
// App Builder
// ============================================================================

/// Builder for constructing an App with custom configuration.
#[derive(Default)]
pub struct AppBuilder {
    catalog: Option<Arc<dyn CatalogStore>>,
    warehouse_location: Option<String>,
    authenticator: Option<Arc<dyn Authenticator>>,
    authorizer: Option<Arc<dyn Authorizer>>,
    credential_provider: Option<Arc<dyn StorageCredentialProvider>>,
    request_signer: Option<Arc<dyn crate::credentials::RequestSigner>>,
    rate_limit_config: Option<RateLimitConfig>,
    idempotency_ttl: Option<Duration>,
    default_tenant_id: Option<String>,
    enable_auth: bool,
    jwt_config: Option<JwtConfig>,
    cors_config: Option<CorsConfig>,
    catalog_url: Option<String>,
    /// Cedar policy source; the built-in defaults are used when absent.
    policies: Option<String>,
    /// API keys, supplied by configuration rather than stored.
    api_keys: Vec<crate::auth::ApiKey>,
    /// Where authorization decisions are recorded.
    auditor: Option<Arc<crate::auth::Auditor>>,
    /// The identity provider's token endpoint, advertised to clients.
    oauth2_server_uri: Option<String>,
    /// Credential vending, from the `[credentials]` config section.
    credentials_config: Option<crate::config::server_config::CredentialsConfig>,
    /// Federated mounts, from `[mount.*]`.
    mounts: Vec<crate::catalog::Mount>,
    /// Where policy revisions live, when supplied directly.
    policy_store: Option<Arc<dyn crate::auth::policy_store::PolicyStore>>,
}

impl AppBuilder {
    /// Sets a custom Iceberg catalog implementation.
    ///
    /// The catalog must implement [`CatalogStore`].
    pub fn with_catalog(mut self, catalog: Arc<dyn CatalogStore>) -> Self {
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

    /// Sets a custom request signer, for remote signing.
    pub fn with_request_signer(
        mut self,
        signer: Arc<dyn crate::credentials::RequestSigner>,
    ) -> Self {
        self.request_signer = Some(signer);
        self
    }

    /// Configures credential vending from a `[credentials]` section.
    ///
    /// The provider is constructed during [`build`](Self::build), because it
    /// needs the resolved warehouse location to default its allowed prefixes.
    /// An explicit [`with_credential_provider`](Self::with_credential_provider)
    /// takes precedence, so a library embedding Rustberg can supply its own.
    pub fn with_credentials_config(
        mut self,
        config: crate::config::server_config::CredentialsConfig,
    ) -> Self {
        self.credentials_config = Some(config);
        self
    }

    /// Sets where policy revisions are stored.
    ///
    /// Only needed alongside [`with_catalog`](Self::with_catalog): a catalog
    /// Rustberg opens itself also serves as the policy store, but one supplied
    /// from outside is not required to. Without this, such a deployment has no
    /// runtime policy administration and the management endpoints say so.
    ///
    /// The two may be the same object — [`RedbCatalog`](crate::catalog::RedbCatalog)
    /// and `PostgresCatalog` implement both traits, which is what keeps a
    /// deployment to one database to back up.
    pub fn with_policy_store(
        mut self,
        store: Arc<dyn crate::auth::policy_store::PolicyStore>,
    ) -> Self {
        self.policy_store = Some(store);
        self
    }

    /// Adds federated mounts.
    ///
    /// Each mount claims a top-level namespace; everything beneath it is served
    /// by that backend. Mounting is additive — names no mount claims still reach
    /// the catalog underneath.
    pub fn with_mounts(mut self, mounts: Vec<crate::catalog::Mount>) -> Self {
        self.mounts = mounts;
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

    /// Sets the API keys this server accepts.
    ///
    /// Keys are configuration, not state: they arrive from a config file or a
    /// mounted secret and are held only in memory. There is deliberately no key
    /// store — nothing to encrypt at rest, back up, or guard with a
    /// "who may mint keys" policy, and rotation is a config change.
    pub fn with_api_keys(mut self, keys: impl IntoIterator<Item = crate::auth::ApiKey>) -> Self {
        self.api_keys = keys.into_iter().collect();
        self
    }

    /// Advertises the identity provider's OAuth2 token endpoint to clients.
    ///
    /// Sent as `oauth2-server-uri` in `/v1/config`, which is what the Iceberg
    /// spec recommends instead of hosting a token endpoint here.
    pub fn with_oauth2_server_uri(mut self, uri: impl Into<String>) -> Self {
        self.oauth2_server_uri = Some(uri.into());
        self
    }

    /// Sets where authorization decisions are recorded.
    ///
    /// Defaults to discarding them, which suits an embedding host that audits
    /// through its own pipeline. The binary configures a real sink.
    pub fn with_auditor(mut self, auditor: Arc<crate::auth::Auditor>) -> Self {
        self.auditor = Some(auditor);
        self
    }

    /// Sets the Cedar policy source.
    ///
    /// Replaces the built-in default policies entirely. Policies are validated
    /// against the schema when the app is built, so a policy that does not
    /// typecheck is a startup failure rather than a rule that never matches.
    pub fn with_policies<S: Into<String>>(mut self, policies: S) -> Self {
        self.policies = Some(policies.into());
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
    /// # async fn example(cors: CorsConfig) {
    /// let app = App::builder().with_cors_config(cors).build().await.unwrap();
    /// # }
    /// ```
    pub fn with_cors_config(mut self, config: CorsConfig) -> Self {
        self.cors_config = Some(config);
        self
    }

    /// Sets where the catalog database lives.
    ///
    /// The catalog is a local redb file, so only two forms are accepted:
    /// - `file:///path/to/dir` — a directory holding `catalog.redb`
    /// - `memory://` — ephemeral, for tests
    ///
    /// Object-store URLs are rejected at build time. The *warehouse* is
    /// separate and may live on any compiled-in scheme — see
    /// [`with_warehouse_location`](Self::with_warehouse_location).
    ///
    /// Leaving this unset gives an ephemeral catalog in a temp directory, which
    /// is only appropriate for tests.
    ///
    /// # Example
    /// ```no_run
    /// use rustberg::App;
    ///
    /// # async fn example() {
    /// let app = App::builder()
    ///     .with_catalog_url("file:///var/lib/rustberg/data")
    ///     .build().await.unwrap();
    /// # }
    /// ```
    pub fn with_catalog_url<S: Into<String>>(mut self, url: S) -> Self {
        self.catalog_url = Some(url.into());
        self
    }

    /// Creates the catalog for a catalog URL.
    ///
    /// `memory://` (or no URL) gives an ephemeral catalog for tests; anything
    /// else is a redb file path, and the warehouse may live on any storage
    /// scheme compiled in.
    async fn create_all_stores(
        catalog_url: Option<&str>,
        warehouse_location: &str,
    ) -> Result<
        (
            Arc<dyn CatalogStore>,
            Option<Arc<dyn crate::auth::policy_store::PolicyStore>>,
            Option<Arc<dyn crate::catalog::v1::idempotency::SharedIdempotencyStore>>,
        ),
        crate::error::AppError,
    > {
        use crate::catalog::RedbCatalog;

        #[cfg(feature = "catalog-postgres")]
        if let Some(url) = catalog_url
            && crate::catalog::PostgresCatalog::handles(url)
        {
            tracing::info!("Opening Postgres catalog");
            let catalog = crate::catalog::PostgresCatalog::connect(url, warehouse_location)
                .await
                .map_err(|e| {
                    crate::error::AppError::Internal(format!(
                        "Failed to open Postgres catalog: {e}"
                    ))
                })?;
            // One handle serving all three traits, so a deployment has one
            // database to configure, back up and make durable.
            let catalog = Arc::new(catalog);
            return Ok((
                catalog.clone() as Arc<dyn CatalogStore>,
                Some(catalog.clone() as Arc<dyn crate::auth::policy_store::PolicyStore>),
                Some(catalog as Arc<dyn crate::catalog::v1::idempotency::SharedIdempotencyStore>),
            ));
        }

        let db_path = match catalog_url {
            Some("memory://") | None => {
                if catalog_url.is_none() {
                    tracing::warn!(
                        "No catalog URL configured; using an ephemeral temp catalog. \
                         All state is lost on shutdown. Set `storage.catalog_url`."
                    );
                }
                std::env::temp_dir()
                    .join(format!("rustberg-{}", uuid::Uuid::new_v4()))
                    .join("catalog.redb")
            }
            Some(url) => {
                let base = url.strip_prefix("file://").unwrap_or(url);
                if base.contains("://") {
                    return Err(crate::error::AppError::Internal(format!(
                        "Unsupported catalog URL '{url}'. The catalog is a local redb file \
                         (or Postgres, with the `catalog-postgres` feature); \
                         use `file:///path` or `memory://`. The *warehouse* may still live on \
                         object storage."
                    )));
                }
                std::path::PathBuf::from(base).join("catalog.redb")
            }
        };

        tracing::info!(path = %db_path.display(), "Opening redb catalog");

        let catalog = RedbCatalog::open(&db_path, warehouse_location)
            .await
            .map_err(|e| {
                crate::error::AppError::Internal(format!("Failed to open redb catalog: {e}"))
            })?;

        let catalog = Arc::new(catalog);
        // No shared idempotency store: redb takes an exclusive file lock, so a
        // second replica cannot open it and there is nobody to share with.
        Ok((
            catalog.clone() as Arc<dyn CatalogStore>,
            Some(catalog as Arc<dyn crate::auth::policy_store::PolicyStore>),
            None,
        ))
    }

    /// Builds a mount's backend from its configuration.
    ///
    /// Only `native` exists today: another Rustberg catalog — a redb file or a
    /// Postgres database — with its own warehouse. That is genuinely useful on
    /// its own (per-team files, per-tenant databases, warehouses in different
    /// regions) and it is the same routing every future adapter will use.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown backend, or when the backend cannot be
    /// opened. Both are startup failures: a mount that silently did not load
    /// would make its whole namespace subtree vanish.
    pub async fn build_mount(
        name: &str,
        config: &crate::config::server_config::MountConfig,
    ) -> Result<crate::catalog::Mount, crate::error::AppError> {
        use crate::catalog::{Capabilities, Mount};

        let (store, capabilities): (Arc<dyn CatalogStore>, Capabilities) =
            match config.backend.trim().to_ascii_lowercase().as_str() {
                "native" => {
                    let (store, _policy, _idempotency) = Self::create_all_stores(
                        Some(&config.catalog_url),
                        &config.warehouse_location,
                    )
                    .await
                    .map_err(|e| {
                        crate::error::AppError::Internal(format!(
                            "Mount '{name}' could not be opened: {e}"
                        ))
                    })?;

                    // A read-only native mount is refused every mutation rather than
                    // trusted not to attempt one. The point of the flag is that
                    // another system owns that catalog.
                    let capabilities = if config.read_only {
                        Capabilities::read_only()
                    } else {
                        Capabilities::full()
                    };
                    (store, capabilities)
                }

                "rest" => {
                    // Read from the environment, so the config file holds no
                    // credential.
                    let token = match config.token_env.as_deref() {
                        Some(var) => Some(crate::config::secret::from_env(
                            var,
                            &format!("mount.{name}.token_env"),
                        )?),
                        None => None,
                    };

                    let remote = crate::catalog::RestCatalog::connect(&config.catalog_url, token)
                        .await
                        .map_err(|e| {
                            crate::error::AppError::Internal(format!(
                                "Mount '{name}' could not connect: {e}"
                            ))
                        })?;

                    // Negotiated from the remote's own config response rather than
                    // assumed: a remote serving no views produces a mount reporting
                    // none, instead of one that offers them and fails on use.
                    let capabilities = remote.capabilities();
                    (Arc::new(remote) as Arc<dyn CatalogStore>, capabilities)
                }

                other => {
                    return Err(crate::error::AppError::Internal(format!(
                        "Mount '{name}' names backend '{other}', which does not exist. \
                     Supported backends: native, rest."
                    )));
                }
            };

        // Only a backend that stores something has a warehouse. A `rest` mount
        // reads from a catalog Rustberg does not own, so it contributes no
        // prefix that credentials may be vended for.
        let warehouse = match config.backend.trim().to_ascii_lowercase().as_str() {
            "rest" => None,
            _ => Some(config.warehouse_location.clone()),
        };

        Ok(Mount {
            name: name.to_string(),
            store,
            capabilities,
            owner: config.owner.clone(),
            warehouse,
        })
    }

    /// Loads the policy set from the store, seeding it when empty.
    ///
    /// # Precedence, and why the store wins
    ///
    /// A configured policy file **seeds an empty store** and is then no longer
    /// authoritative. The alternative — file wins on every start — would
    /// silently discard every change made through the API the moment a pod
    /// restarted, which is a data-loss bug wearing a configuration hat.
    ///
    /// Divergence between the two is logged loudly at startup, because an
    /// operator who edits the file and restarts expecting it to apply is
    /// otherwise left with no signal at all.
    ///
    /// # Errors
    ///
    /// Refuses to start when the effective policy set permits nothing. An
    /// authenticated deployment whose policy set is empty accepts nobody — for
    /// anything, including fixing the policy set — so coming up would produce a
    /// server that cannot be recovered without a restart it did not ask for.
    async fn load_policy_admin(
        store: Arc<dyn crate::auth::policy_store::PolicyStore>,
        configured: Option<&str>,
    ) -> Result<PolicyAdmin, crate::error::AppError> {
        use crate::auth::DEFAULT_POLICIES;
        use crate::auth::policy_store::version_of;
        use crate::auth::reloadable::ReloadableAuthorizer;

        let revision = match store.current().await? {
            Some(current) => {
                if let Some(configured) = configured
                    && version_of(configured) != current.version
                {
                    tracing::warn!(
                        stored_version = %current.version,
                        stored_sequence = current.sequence,
                        "The configured policy file differs from the stored policy set, \
                         and the STORE is authoritative. The file seeds an empty store \
                         only. Change policy through PUT /management/v1/policies."
                    );
                }
                current
            }
            None => {
                let seed = configured.unwrap_or(DEFAULT_POLICIES);
                let source = if configured.is_some() {
                    "file"
                } else {
                    "defaults"
                };
                let revision = store
                    .append(seed, "system:bootstrap", Some("Seeded at startup"))
                    .await?;
                tracing::info!(
                    seeded_from = source,
                    version = %revision.version,
                    "Policy store was empty; seeded it"
                );
                revision
            }
        };

        let authorizer = CedarAuthorizer::new(&revision.source).map_err(|e| {
            crate::error::AppError::Internal(format!(
                "The stored policy set (revision {}) is not usable: {e}. It \
                 typechecked when it was stored, so the schema has changed \
                 underneath it.",
                revision.sequence
            ))
        })?;

        if authorizer.is_empty() {
            return Err(crate::error::AppError::Internal(format!(
                "The policy set (revision {}) contains no policies, so this server would \
                 accept nobody — including anyone trying to fix it. Configure \
                 `server.auth.policy_file`, or start with the built-in defaults.",
                revision.sequence
            )));
        }

        tracing::info!(
            sequence = revision.sequence,
            version = %revision.version,
            "Policy set loaded"
        );

        let authorizer = Arc::new(ReloadableAuthorizer::new(authorizer, revision.sequence));

        // Replicas converge by polling. A single-replica deployment swaps
        // locally on write and never needs this, but it is harmless there and
        // its absence would be silently wrong the moment a second replica
        // appeared.
        // Held, not discarded: a spawned task keeps its own `Arc`s alive, so a
        // forgotten poller outlives the application and goes on querying the
        // database until the process exits.
        let poller = crate::auth::reloadable::spawn_policy_poller(
            store.clone(),
            authorizer.clone(),
            crate::auth::reloadable::POLL_INTERVAL,
        );

        Ok(PolicyAdmin {
            store,
            authorizer,
            poller: Arc::new(poller),
        })
    }

    /// Builds the App with the configured options (async version).
    ///
    /// Builds the App with the configured options.
    ///
    /// Builds the app.
    ///
    /// Async because opening the catalog is async. There is deliberately no
    /// blocking variant: one would need a temporary Tokio runtime, which panics
    /// when called from an async context and leaves the catalog holding a handle
    /// to a runtime that is about to be dropped.
    pub async fn build(self) -> Result<App, crate::error::AppError> {
        self.assemble(None).await
    }

    /// Builds the app with API-key authentication.
    ///
    /// Keys come from configuration ([`Self::with_api_keys`]); there is no
    /// key store to manage, encrypt, or back up.
    pub async fn build_with_api_keys(
        self,
    ) -> Result<(App, Arc<InMemoryApiKeyStore>), crate::error::AppError> {
        let keys = Arc::new(InMemoryApiKeyStore::with_keys(self.api_keys.clone()));
        let store = keys.clone();
        Ok((self.assemble(Some(keys)).await?, store))
    }

    /// The single assembly path.
    ///
    /// The public builders differ only in how API keys are stored, so that is
    /// the only thing parameterised here. Catalog construction, authenticator
    /// wiring, rate-limit defaults and state assembly happen once, so they
    /// cannot drift between entry points.
    async fn assemble(
        self,
        api_keys: Option<Arc<InMemoryApiKeyStore>>,
    ) -> Result<App, crate::error::AppError> {
        let warehouse_location = self.warehouse_location.unwrap_or_else(temp_path);
        let default_tenant_id = self
            .default_tenant_id
            .unwrap_or_else(|| "default".to_string());

        // A catalog Rustberg opens is also the policy store. One supplied from
        // outside is not required to be, so such a deployment gets runtime
        // policy administration only if it also supplies a store — otherwise the
        // management endpoints say it is unavailable rather than half-working.
        let (catalog, opened_policy_store, shared_idempotency) = match self.catalog {
            Some(catalog) => (catalog, None, None),
            None => {
                Self::create_all_stores(self.catalog_url.as_deref(), &warehouse_location).await?
            }
        };
        let policy_store = self.policy_store.or(opened_policy_store);

        // Mounts layer over whatever catalog was built, so adding one does not
        // disturb the namespaces that were already there.
        let mut capabilities = crate::catalog::Capabilities::full();
        // Every warehouse this server manages, which is what credential vending
        // may be scoped to. A mount's warehouse missing from here would make its
        // tables silently un-credentialed: the provider refuses, the request
        // still succeeds, and the client gets metadata it cannot read.
        let mut managed_warehouses = vec![warehouse_location.clone()];
        let catalog: Arc<dyn CatalogStore> = if self.mounts.is_empty() {
            catalog
        } else {
            let names: Vec<String> = self.mounts.iter().map(|m| m.name.clone()).collect();
            let federated = crate::catalog::FederatedCatalog::new(catalog, self.mounts)
                .map_err(|e| crate::error::AppError::Internal(format!("Invalid mounts: {e}")))?;
            // A mount whose name already exists underneath would hide it, and a
            // subtree that silently does not exist is worse than a server that
            // refuses to start — the same rule C1 applies to a mount that cannot
            // be opened.
            federated
                .ensure_no_shadowing()
                .await
                .map_err(|e| crate::error::AppError::Internal(e.to_string()))?;
            capabilities = federated.effective_capabilities();
            managed_warehouses = federated.warehouses(&warehouse_location);
            tracing::info!(
                mounts = ?names,
                ?capabilities,
                "Federating mounted catalogs"
            );
            Arc::new(federated)
        };

        // Every configured mechanism, tried in order: an explicitly supplied
        // authenticator wins outright, then OIDC/JWT, then API keys.
        //
        // Assembled from what was configured, never from one of its inputs. A
        // chain keyed on "is there an API key store" answers the wrong question:
        // a host that configures OIDC alone has no key store, and would fall
        // through to a fallback that authenticates nobody while its own
        // configuration says otherwise. A mechanism that was asked for and does
        // not attach is a startup failure rather than an open door.
        let mut mechanisms: Vec<Arc<dyn Authenticator>> = Vec::new();
        if let Some(explicit) = self.authenticator {
            mechanisms.push(explicit);
        }
        if let Some(cfg) = self.jwt_config {
            // A `Result` builder has no business panicking on a configuration
            // value: an unreachable JWKS URL or a missing audience is an
            // operator error to report, not a crash to debug from a backtrace.
            mechanisms.push(Arc::new(JwtAuthenticator::new(cfg).map_err(|e| {
                crate::error::AppError::Internal(format!(
                    "OIDC/JWT authentication was configured but could not be built: {e}"
                ))
            })?));
        }
        if let Some(store) = api_keys.clone() {
            mechanisms.push(Arc::new(ApiKeyAuthenticator::new(store)));
        }

        let authenticated = !mechanisms.is_empty();
        let authenticator: Arc<dyn Authenticator> = if mechanisms.is_empty() {
            // Nothing was configured, so there is nothing to check. Said out
            // loud, because the difference between "no authentication" and
            // "authentication that silently did not attach" is the whole finding
            // above, and a log line is what makes the two distinguishable.
            tracing::warn!(
                "No authenticator configured: every request is the anonymous principal. \
                 Policy still decides what it may do, and by default that is nothing. \
                 Configure OIDC (`with_jwt_config`) or API keys (`build_with_api_keys`)."
            );
            Arc::new(AllowAllAuthenticator)
        } else if mechanisms.len() == 1 {
            mechanisms.remove(0)
        } else {
            Arc::new(ChainAuthenticator::new(mechanisms))
        };

        let (authorizer, policy_admin): (Arc<dyn Authorizer>, Option<PolicyAdmin>) = match self
            .authorizer
        {
            // An explicitly supplied authorizer always wins, and is not
            // administrable: Rustberg does not know how to rebuild it.
            Some(authorizer) => (authorizer, None),
            None if authenticated => match policy_store {
                Some(store) => {
                    let admin = Self::load_policy_admin(store, self.policies.as_deref()).await?;
                    let authorizer = admin.authorizer.clone() as Arc<dyn Authorizer>;
                    (authorizer, Some(admin))
                }
                // Cedar without a store: policy is whatever was configured,
                // and changing it is a restart.
                None => (
                    Arc::new(build_authorizer(self.policies.as_deref())) as Arc<dyn Authorizer>,
                    None,
                ),
            },
            // Unauthenticated development mode.
            None => (Arc::new(AllowAllAuthorizer), None),
        };

        let rate_limiter = Arc::new(RateLimiter::new(self.rate_limit_config.unwrap_or_else(
            || {
                if authenticated {
                    RateLimitConfig::default()
                } else {
                    RateLimitConfig::disabled()
                }
            },
        )));

        // An explicitly supplied provider wins; otherwise the `[credentials]`
        // section decides. It is resolved here rather than at the call site
        // because defaulting the allowed prefixes needs the warehouse location,
        // which is only settled by this point.
        let credential_provider: Arc<dyn StorageCredentialProvider> = match self.credential_provider
        {
            Some(provider) => provider,
            None => match self.credentials_config.as_ref() {
                Some(config) => {
                    crate::credentials::build_credential_provider(config, &managed_warehouses)
                        .await?
                }
                None => Arc::new(NoopCredentialProvider::new()),
            },
        };

        // Signing is configured alongside vending and is independent of it: a
        // deployment may offer either, both or neither.
        let signing_config = self
            .credentials_config
            .as_ref()
            .and_then(|config| config.signing.clone())
            .unwrap_or_default();

        let request_signer: Arc<dyn crate::credentials::RequestSigner> = match self.request_signer {
            Some(signer) => signer,
            None => match self.credentials_config.as_ref() {
                Some(config) => {
                    crate::credentials::build_request_signer(config, &managed_warehouses).await?
                }
                None => Arc::new(crate::credentials::NoopRequestSigner),
            },
        };

        let signing = crate::catalog::v1::sign::SigningEndpointConfig {
            // A host that supplied its own signer means to serve the endpoint,
            // whether or not it wrote a `[credentials.signing]` section.
            enabled: signing_config.enabled || !request_signer.allowed_prefixes().is_empty(),
            url_style: Some(crate::catalog::v1::sign::UrlStyle::parse(
                &signing_config.url_style,
            )?),
            endpoint_host: signing_config.endpoint_host.clone(),
            fallback_region: signing_config.region.clone(),
        };

        let app_state = AppState {
            authenticator,
            authorizer,
            catalog,
            credential_provider,
            request_signer,
            signing,
            rate_limiter,
            idempotency_cache: Arc::new({
                let cache = IdempotencyCache::new(
                    self.idempotency_ttl.unwrap_or(crate::catalog::DEFAULT_TTL),
                );
                match shared_idempotency {
                    Some(store) => cache.with_shared_store(store),
                    None => cache,
                }
            }),
            metrics: Arc::new(MetricsRegistry::new()),
            auditor: self
                .auditor
                .unwrap_or_else(|| Arc::new(crate::auth::Auditor::disabled())),
            default_warehouse: DefaultWarehouse::new(warehouse_location),
            default_tenant_id,
            oauth2_server_uri: self.oauth2_server_uri,
            policy_admin,
            capabilities,
        };

        Ok(App {
            app_state,
            cors_config: self.cors_config.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builds_with_defaults() {
        let app = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .build()
            .await
            .unwrap();

        assert!(!app.state().default_warehouse.advertised().is_empty());
        assert_eq!(app.state().default_tenant_id(), "default");
    }

    #[tokio::test]
    async fn honours_the_configured_tenant() {
        let app = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .with_default_tenant_id("acme")
            .build()
            .await
            .unwrap();

        assert_eq!(app.state().default_tenant_id(), "acme");
    }

    // ── Authentication attaches, or the build fails ───────────────────────

    fn jwt_config() -> crate::auth::JwtConfig {
        crate::auth::JwtConfig {
            issuer: "https://issuer.example.com".to_string(),
            audience: "rustberg-api".to_string(),
            jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            ..Default::default()
        }
    }

    /// Configuring OIDC alone must install the JWT authenticator and a real
    /// authorizer.
    ///
    /// The binary always builds with an API key store, so a fallback keyed on
    /// that store is never exercised there — only on the library surface, which
    /// is documented as carrying the same guarantees as the server.
    #[tokio::test]
    async fn configuring_oidc_alone_still_authenticates_and_authorizes() {
        let app = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .with_jwt_config(jwt_config())
            .build()
            .await
            .unwrap();

        assert_eq!(
            app.state().authenticator.auth_method(),
            crate::auth::AuthMethod::Bearer,
            "the configured JWT authenticator must be the one installed"
        );

        // An anonymous caller must not be permitted anything.
        let anonymous = crate::auth::AuthzContext::new(
            crate::auth::Principal::anonymous(),
            crate::auth::Resource::table("default", ["ns".to_string()], "t"),
            crate::auth::Action::Read,
        );
        assert!(
            !app.state().authorizer.permits(&anonymous).await,
            "an unauthenticated caller must be denied by policy"
        );
    }

    /// The same hole, reached through a host's own authenticator rather than
    /// through OIDC: it too left `authenticated` false and the authorizer open.
    #[tokio::test]
    async fn a_host_supplied_authenticator_also_engages_policy() {
        let app = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .with_authenticator(Arc::new(crate::auth::DenyAllAuthenticator))
            .build()
            .await
            .unwrap();

        let anonymous = crate::auth::AuthzContext::new(
            crate::auth::Principal::anonymous(),
            crate::auth::Resource::table("default", ["ns".to_string()], "t"),
            crate::auth::Action::Read,
        );
        assert!(!app.state().authorizer.permits(&anonymous).await);
    }

    /// A configuration error is reported, not panicked on: a `Result` builder
    /// has no business aborting the process over a value an operator typed.
    #[tokio::test]
    async fn unbuildable_oidc_configuration_is_an_error_not_a_panic() {
        let err = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .with_jwt_config(crate::auth::JwtConfig {
                audience: String::new(), // required
                ..jwt_config()
            })
            .build()
            .await
            .err()
            .expect("an unbuildable authenticator must not silently vanish");

        assert!(
            err.to_string().contains("OIDC/JWT"),
            "the message must name what failed to attach: {err}"
        );
    }

    /// Keys are configuration: the store is built from what the caller supplied,
    /// with nothing persisted.
    #[tokio::test]
    async fn api_keys_come_from_configuration() {
        use crate::auth::{ApiKeyBuilder, ApiKeyStore};

        let (key, _plaintext) = ApiKeyBuilder::new("ci", "acme").with_role("reader").build();
        let id = key.id;

        let (_app, store) = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .with_api_keys([key])
            .build_with_api_keys()
            .await
            .unwrap();

        assert_eq!(
            store.get_by_id(&id).await.expect("configured key").name,
            "ci"
        );
    }

    /// Without configured keys there is nothing to authenticate against, so the
    /// server must not silently accept unauthenticated callers as privileged.
    #[tokio::test]
    async fn no_keys_means_an_empty_store() {
        use crate::auth::ApiKeyStore;

        let (_app, store) = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .build_with_api_keys()
            .await
            .unwrap();

        assert!(store.list_for_tenant("acme").await.is_empty());
    }

    #[tokio::test]
    async fn security_headers_are_set() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = App::builder()
            .with_warehouse_location(crate::utils::temp_path())
            .build()
            .await
            .unwrap();

        let response = app
            .into_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let headers = response.headers();
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            headers.get("content-security-policy").unwrap(),
            "default-src 'none'; frame-ancestors 'none'"
        );
    }
}
