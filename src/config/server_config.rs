//! Server configuration structures and file-based configuration loader.
//!
//! Supports TOML configuration files with sensible defaults.
//! Configuration can be loaded from:
//! 1. Config file (TOML)
//! 2. Environment variables
//! 3. Command-line arguments (highest priority)
//!
//! # Example config.toml
//!
//! ```toml
//! host = "0.0.0.0"
//! port = 8000
//!
//! [auth]
//! api_key_enabled = true
//! jwt_enabled = false
//!
//! [tls]
//! enabled = true
//! cert_path = "/path/to/cert.pem"
//! key_path = "/path/to/key.pem"
//!
//! [storage]
//! catalog_url = "file:///var/lib/rustberg/data"
//! warehouse_location = "s3://my-bucket/warehouse"
//!
//!
//! [rate_limit]
//! requests_per_second = 100
//! burst_size = 200
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn default_true() -> bool {
    true
}

use crate::auth::JwtConfig;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Server host address
    #[serde(default = "default_host")]
    pub host: String,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Authentication configuration
    #[serde(default)]
    pub auth: AuthConfig,

    /// CORS configuration
    #[serde(default)]
    pub cors: CorsConfig,

    /// Address ranges that are forwarding infrastructure rather than callers.
    ///
    /// Empty — the default — means no proxy is trusted and the caller's address
    /// is always the TCP peer; `X-Forwarded-For` and `X-Real-IP` are not read at
    /// all. Behind a load balancer, name the subnet it runs in
    /// (`["10.0.0.0/8"]`) and the forwarding chain is walked from the right
    /// until it leaves that infrastructure.
    ///
    /// This is one setting for three consumers — the rate-limit bucket,
    /// `context.source_ip` in a Cedar policy, and the address on an audit
    /// record — because they must agree, and because an address a caller can
    /// choose is an authorization bypass in the second of them. See
    /// [`crate::remote_ip`].
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// How long to keep serving after `SIGTERM` before draining, in seconds.
    ///
    /// Zero — the default — begins the graceful shutdown immediately, which is
    /// right for every shape where nothing is routing to this process but the
    /// person who started it.
    ///
    /// Behind a **load balancer it is not**, and Kubernetes is the case that
    /// makes it obvious. Removing a pod from its Service's endpoints and sending
    /// it `SIGTERM` are concurrent, and the removal has to propagate to every
    /// kube-proxy and ingress before they stop routing. A server that stops
    /// accepting the instant it is signalled refuses the requests that arrive in
    /// that window, and they surface to clients as connection errors during
    /// every rolling update.
    ///
    /// The usual answer is a `preStop` hook that sleeps, and **it cannot work
    /// here**: the image is distroless, so there is no shell to run `sleep` in.
    /// So the wait is in-process, which is better anyway — it does not depend on
    /// the orchestrator, and it is one number rather than two that have to agree.
    ///
    /// It applies to `SIGTERM` only, never to `Ctrl+C`: an orchestrator is
    /// taking this process out of rotation, and a person at a terminal is not.
    ///
    /// Keep it comfortably below the orchestrator's own grace period — the Helm
    /// chart sets both, and sizes `terminationGracePeriodSeconds` to cover this
    /// plus the drain that follows it.
    #[serde(default)]
    pub shutdown_delay_seconds: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            auth: AuthConfig::default(),
            cors: CorsConfig::default(),
            trusted_proxies: Vec::new(),
            shutdown_delay_seconds: 0,
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Enable API key authentication (default: true)
    #[serde(default = "default_true")]
    pub api_key_enabled: bool,

    /// Enable JWT/OIDC authentication (default: false)
    #[serde(default)]
    pub jwt_enabled: bool,

    /// JWT/OIDC configuration (required if jwt_enabled is true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwt: Option<JwtConfigSerde>,

    /// Path to a Cedar policy file.
    ///
    /// When unset, the built-in default policies are used. When set, the file
    /// *replaces* them — the defaults are not merged in, because silently
    /// unioning a deployment's policies with grants it did not write is how an
    /// authorization system ends up permitting more than its operator believes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_file: Option<std::path::PathBuf>,

    /// API keys this server accepts.
    ///
    /// Keys are configuration, not state: there is no key store to encrypt, back
    /// up, or guard with a "who may mint keys" policy, and rotation is a config
    /// change plus a restart.
    #[serde(default, rename = "api_keys")]
    pub api_keys: Vec<ApiKeyConfig>,
}

/// One configured API key.
///
/// The secret itself is read from an environment variable rather than written
/// here, so the config file can be committed and the credential lives in
/// whatever secret manager the deployment already uses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Human-readable name, for audit records.
    pub name: String,

    /// Tenant this key acts for.
    pub tenant: String,

    /// Roles the key carries. These become Cedar groups.
    #[serde(default)]
    pub roles: Vec<String>,

    /// Environment variable holding the secret.
    pub key_env: String,
}

impl ApiKeyConfig {
    /// Reads the secret and builds the key.
    ///
    /// The plaintext is hashed immediately and never retained, so the running
    /// process holds no usable credential.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ValidationError`] if the environment variable is
    /// unset or empty — failing closed, because a key that silently does not
    /// exist looks identical to one that was revoked on purpose.
    pub fn to_api_key(&self) -> Result<crate::auth::ApiKey, ConfigError> {
        self.build_from(std::env::var(&self.key_env).ok().as_deref())
    }

    /// The rule, separated from the lookup, so a test can state it without
    /// mutating the process environment — `set_var` races every other thread
    /// reading it, which in a parallel test suite is all of them.
    fn build_from(&self, secret: Option<&str>) -> Result<crate::auth::ApiKey, ConfigError> {
        // `Zeroizing` wipes the plaintext when it drops, so the secret does not
        // linger in freed heap memory after hashing. It is still readable in the
        // process environment — that is the operator's boundary, not ours — but
        // this keeps the window as short as we control.
        let secret = Zeroizing::new(secret.map(str::to_string).ok_or_else(|| {
            ConfigError::ValidationError(format!(
                "API key '{}' expects its secret in ${}, which is not set",
                self.name, self.key_env
            ))
        })?);

        if secret.trim().is_empty() {
            return Err(ConfigError::ValidationError(format!(
                "API key '{}': ${} is empty",
                self.name, self.key_env
            )));
        }

        // The same rule the JWT path applies to a claim, applied to a config
        // value — a tenant id is the first segment of every Cedar entity id
        // either way, and `acme␟analytics` would build the ids of tenant
        // `acme`'s `analytics` namespace. Here it is a **startup failure**
        // rather than a rejected credential, because an operator who wrote it
        // believes something about the deployment that is not true.
        crate::names::validate_tenant_id(&self.tenant)
            .map_err(|e| ConfigError::ValidationError(format!("API key '{}': {e}", self.name)))?;

        // And the same rule for a role, which becomes `Group::"…"`. A token's
        // roles are *dropped* when they cannot be rendered, because the caller
        // neither chose nor can fix them (`names::unusable_role_char`); one
        // written in this file is a startup failure, because an operator can.
        for role in &self.roles {
            if let Some(found) = crate::names::unusable_role_char(role) {
                return Err(ConfigError::ValidationError(format!(
                    "API key '{}' declares a role containing U+{:04X}, which cannot be a \
                     Cedar group id — it is a control, formatting, private-use or \
                     unassigned character, or the role is empty, over-long, or not in \
                     normalization form NFC. No policy could name it, so the key would \
                     authenticate and match nothing.",
                    self.name, found as u32
                )));
            }
        }

        Ok(crate::auth::ApiKeyBuilder::new(&self.name, &self.tenant)
            .with_roles(self.roles.clone())
            .build_with_key(&secret))
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_key_enabled: true,
            jwt_enabled: false,
            policy_file: None,
            api_keys: Vec::new(),
            jwt: None,
        }
    }
}

/// JWT configuration (serializable version of JwtConfig)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfigSerde {
    /// OIDC issuer URL (e.g., "<https://accounts.google.com>")
    pub issuer: String,

    /// Audiences a token may name. A token is accepted when its `aud` matches
    /// any of them.
    ///
    /// More than one is ordinary: an identity provider registers one client per
    /// application, so Spark, Trino and a notebook are three audiences reaching
    /// one catalog.
    pub audiences: Vec<String>,

    /// JWKS endpoint URL.
    ///
    /// Omit it and the issuer's `/.well-known/openid-configuration` is read to
    /// find it, with the document's own `issuer` checked against this one. Set
    /// it for a provider with a non-standard layout, or where the discovery
    /// document is not reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<String>,

    /// Default tenant ID if not in JWT claims (default: "default")
    #[serde(default = "default_tenant_id")]
    pub default_tenant_id: String,

    /// Claim name for tenant ID (default: "tenant_id")
    #[serde(default = "default_tenant_claim")]
    pub tenant_claim: String,

    /// Claim name for roles (default: "roles")
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,

    /// JWKS cache TTL in seconds (default: 3600)
    #[serde(default = "default_jwks_cache_ttl")]
    pub jwks_cache_ttl_seconds: u64,

    /// Your identity provider's OAuth2 token endpoint.
    ///
    /// Advertised to clients as `oauth2-server-uri` in `/v1/config`, so a client
    /// configured with only a catalog URI can find where to authenticate. This
    /// is the migration path the Iceberg spec recommends in place of the
    /// deprecated `oauth/tokens` endpoint.
    ///
    /// Set explicitly rather than taken from the discovery document's
    /// `token_endpoint`. Discovery happens lazily, at the first token that needs
    /// a signing key, and `GET /v1/config` is answered before any of those — so
    /// deriving this would make the advertised endpoint depend on whether
    /// anyone had authenticated yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth2_server_uri: Option<String>,
}

impl From<JwtConfigSerde> for JwtConfig {
    fn from(config: JwtConfigSerde) -> Self {
        JwtConfig {
            issuer: config.issuer,
            audiences: config.audiences,
            jwks_url: config.jwks_url,
            default_tenant_id: config.default_tenant_id,
            tenant_claim: config.tenant_claim,
            roles_claim: config.roles_claim,
            jwks_cache_ttl: Duration::from_secs(config.jwks_cache_ttl_seconds),
            ..Default::default()
        }
    }
}

/// CORS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Allowed origins (default: ["*"])
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,

    /// Allowed methods (default: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,

    /// Allowed headers (default: ["*"])
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
        }
    }
}

// Default value functions
fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    // The same value the CLI falls back to. Two defaults for one setting is how
    // a deployment ends up on a port neither its config nor its flags name.
    8000
}

fn default_tenant_id() -> String {
    "default".to_string()
}

fn default_tenant_claim() -> String {
    "tenant_id".to_string()
}

fn default_roles_claim() -> String {
    "roles".to_string()
}

fn default_jwks_cache_ttl() -> u64 {
    3600
}

/// No cross-origin access by default.
///
/// CORS exists to let a *browser* make cross-origin requests. The clients here
/// are Spark, Trino, PyIceberg and DuckDB, none of which is a browser, so a
/// permissive default buys nothing — and production mode refuses to serve with
/// wildcard CORS, so it would also make the default configuration unstartable in
/// the default mode.
///
/// A deployment serving a browser UI sets `allowed_origins` explicitly.
fn default_allowed_origins() -> Vec<String> {
    Vec::new()
}

fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
        "OPTIONS".to_string(),
    ]
}

fn default_allowed_headers() -> Vec<String> {
    vec!["*".to_string()]
}

// ============================================================================
// Extended Configuration Sections
// ============================================================================

/// Full configuration file structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RustbergConfig {
    /// Server configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfigFile,

    /// Catalog and warehouse locations.
    #[serde(default)]
    pub storage: StorageConfig,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfigFile,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Where authorization decisions are recorded.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Storage credential vending.
    #[serde(default)]
    pub credentials: CredentialsConfig,

    /// Federated mounts, keyed by top-level namespace.
    ///
    /// Empty — the default — means one catalog and no routing.
    #[serde(default)]
    pub mount: std::collections::HashMap<String, MountConfig>,
}

// ============================================================================
// Federation
// ============================================================================

/// One mounted catalog.
///
/// The key in `[mount.<name>]` becomes the top-level namespace. Everything
/// beneath it is served by this backend, with the mount name stripped on the way
/// down — a mounted catalog has its own namespaces and has never heard of the
/// name it is mounted under.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountConfig {
    /// Backend type.
    ///
    /// - `native` — another Rustberg catalog: a redb file or a Postgres
    ///   database, addressed exactly like `storage.catalog_url`.
    /// - `rest` — somebody else's Iceberg REST catalog, served **read-only**.
    #[serde(default = "default_mount_backend")]
    pub backend: String,

    /// Where the backend lives.
    ///
    /// For `native`: `file:///path`, `memory://`, or a Postgres DSN.
    /// For `rest`: the base URI, e.g. `https://catalog.partner.example`.
    pub catalog_url: String,

    /// Warehouse for tables in this mount.
    ///
    /// Separate from the main warehouse, because the point of a mount is usually
    /// that its data lives somewhere else. Unused by `rest`, which reads
    /// locations from the remote's own metadata.
    #[serde(default)]
    pub warehouse_location: String,

    /// Environment variable holding a bearer token for a `rest` mount.
    ///
    /// Named rather than inlined, so this file holds no credential. A variable
    /// that is set but empty is a startup failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,

    /// Tenant that owns everything in this mount.
    ///
    /// Authoritative for the whole mount, not a default. A mount is a separate
    /// catalog whose namespace properties Rustberg does not control, so reading
    /// ownership from inside it would let whoever can write there decide who
    /// owns it here.
    pub owner: String,

    /// Refuse every mutating operation on this mount.
    ///
    /// For mounting a catalog that another system owns: reads are served, and a
    /// write is refused with `501` naming the mount rather than reaching a
    /// catalog somebody else is responsible for.
    #[serde(default)]
    pub read_only: bool,
}

fn default_mount_backend() -> String {
    "native".to_string()
}

// ============================================================================
// Credential vending
// ============================================================================

/// Storage credential vending.
///
/// When a provider is configured, a client that asks for delegation
/// (`X-Iceberg-Access-Delegation: vended-credentials`) receives a short-lived
/// credential scoped to the one table it named — never the server's own rights.
/// With no provider, nothing is vended and the credentials endpoint answers
/// `501`, which is the honest report for a deployment where engines carry their
/// own storage credentials.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialsConfig {
    /// Which provider to use: `none` (default), `aws`, or `gcs`.
    #[serde(default = "default_credentials_provider")]
    pub provider: String,

    /// Locations this server will ever mint a credential for.
    ///
    /// Left empty — the normal case — this becomes every warehouse the server
    /// manages: its own, plus each mount's. That is the right default and not
    /// merely a convenient one: the catalog already refuses to record a table
    /// outside one of them, so a wider prefix could only ever authorize a
    /// location the catalog will not serve.
    ///
    /// Set it only to *narrow* vending. Setting it replaces the list entirely,
    /// so a federated deployment that sets it must name each mount's warehouse
    /// it wants credentials for — omitting one makes that mount's tables
    /// silently un-credentialed.
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,

    /// AWS STS settings, required when `provider = "aws"`.
    #[serde(default)]
    pub aws: Option<AwsCredentialsConfig>,

    /// GCS settings, required when `provider = "gcs"`.
    #[serde(default)]
    pub gcs: Option<GcsCredentialsConfig>,

    /// Azure settings, required when `provider = "azure"`.
    #[serde(default)]
    pub azure: Option<AzureCredentialsConfig>,

    /// Remote request signing.
    ///
    /// Independent of `provider`: a deployment may offer signing, vending, both,
    /// or neither, and a client picks with `X-Iceberg-Access-Delegation`. Signing
    /// is the stronger form — the engine holds no credential and every object
    /// request is authorized here — and the more expensive one, at a round trip
    /// per object.
    #[serde(default)]
    pub signing: Option<SigningConfig>,
}

/// Remote request signing (`POST …/tables/{table}/sign`).
///
/// Only S3 and S3-compatible storage today. GCS and ADLS have no equivalent
/// request-signing protocol in the Iceberg spec, so a deployment on those uses
/// vending.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningConfig {
    /// Whether to serve the sign endpoint.
    #[serde(default)]
    pub enabled: bool,

    /// Region to sign for when a client does not name one.
    ///
    /// A client normally sends the region it resolved, and that value is used.
    /// This is the fallback for clients that send an empty one.
    #[serde(default)]
    pub region: Option<String>,

    /// How to read a bucket out of a request URI: `auto`, `path` or
    /// `virtual-host`.
    ///
    /// `auto` recognises AWS's own hostnames and falls back to path style for
    /// anything else, which is what MinIO, Ceph and R2 deployments use. Set it
    /// explicitly when a custom endpoint serves virtual-host style, because
    /// guessing wrong here fails **closed** — the bucket is read from the wrong
    /// place, the location does not match the table, and the request is
    /// refused rather than mis-signed.
    #[serde(default = "default_url_style")]
    pub url_style: String,

    /// Host of a custom S3 endpoint, when one is used.
    ///
    /// Lets `auto` tell `minio:9000/bucket/key` (path style) from
    /// `bucket.minio:9000/key` (virtual-host style) on the same endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_host: Option<String>,
}

fn default_url_style() -> String {
    "auto".to_string()
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            region: None,
            url_style: default_url_style(),
            endpoint_host: None,
        }
    }
}

fn default_credentials_provider() -> String {
    "none".to_string()
}

/// AWS STS credential vending.
///
/// Rustberg calls `AssumeRole` with an inline session policy scoped to the
/// requested table's prefix, so the returned credential is the intersection of
/// this role and that one prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsCredentialsConfig {
    /// Region for the STS endpoint.
    pub region: String,

    /// Role to assume. It needs access to the warehouse; the session policy
    /// narrows each vended credential to one table beneath it.
    pub role_arn: String,

    /// Environment variable holding the STS external ID, for cross-account
    /// assumption. Named rather than inlined so this file holds no secret; a
    /// variable that is set but empty is a startup failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id_env: Option<String>,

    /// Lifetime of a vended credential, in seconds.
    #[serde(default = "default_credential_duration")]
    pub duration_seconds: i32,
}

/// GCS credential vending, via a Credential Access Boundary token exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcsCredentialsConfig {
    /// Path to the service-account JSON key used as the exchange's input.
    pub service_account_key_path: String,
}

/// Azure credential vending, via user-delegation SAS.
///
/// Rustberg authenticates as a Microsoft Entra service principal, asks the
/// storage account for a user delegation key, and signs a SAS scoped to one
/// table prefix. It has no code path that can emit an account key: that would
/// grant the whole storage account to anyone permitted to read one table.
///
/// The principal needs **Storage Blob Data Contributor** (or Reader, for a
/// read-only deployment) on the account — a SAS can only ever narrow those
/// rights, never widen them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureCredentialsConfig {
    /// Storage account name, without the domain.
    pub account: String,

    /// Microsoft Entra tenant the service principal lives in.
    pub tenant_id: String,

    /// The service principal's application (client) ID.
    pub client_id: String,

    /// Environment variable holding the service principal's secret. Named
    /// rather than inlined, so this file holds no credential.
    pub client_secret_env: String,

    /// Lifetime of a vended SAS, in seconds.
    #[serde(default = "default_azure_duration")]
    pub duration_seconds: i64,
}

/// One hour, matching the other providers.
fn default_azure_duration() -> i64 {
    3600
}

/// One hour: long enough for a large write, short enough that a leaked
/// credential expires before it is useful.
fn default_credential_duration() -> i32 {
    3600
}

/// Where authorization decisions are recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Sink: `stdout`, `file`, or `none`.
    #[serde(default = "default_audit_sink")]
    pub sink: String,

    /// Path for the `file` sink.
    #[serde(default)]
    pub path: Option<std::path::PathBuf>,

    /// Refuse a mutating request whose record could not be written.
    ///
    /// An unrecorded change is the one event an audit exists to capture, so the
    /// default is to refuse. Reads are unaffected either way.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            sink: default_audit_sink(),
            path: None,
            fail_closed: true,
        }
    }
}

fn default_audit_sink() -> String {
    "stdout".to_string()
}

/// TLS configuration from file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfigFile {
    /// Enable TLS.
    #[serde(default)]
    pub enabled: bool,

    /// Path to TLS certificate file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_path: Option<String>,

    /// Path to TLS private key file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<String>,

    /// Allow insecure HTTP (development only).
    #[serde(default)]
    pub insecure_http: bool,
}

impl Default for TlsConfigFile {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default, enable with cert/key paths
            cert_path: None,
            key_path: None,
            insecure_http: true, // Allow HTTP for local development
        }
    }
}

/// Catalog and warehouse locations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Where the catalog database lives.
    ///
    /// The catalog is a local redb file, so only two forms are valid:
    /// - `file:///path/to/dir` — a directory holding `catalog.redb` (default)
    /// - `memory://` — ephemeral, discarded on shutdown; for tests only
    ///
    /// Object-store URLs are **not** valid here and are rejected at startup.
    /// Earlier versions advertised `s3://`/`gs://`/`az://` for this field, from
    /// when catalog state itself lived on object storage. The *warehouse* still
    /// may — see [`warehouse_location`](Self::warehouse_location).
    #[serde(default = "default_catalog_url")]
    pub catalog_url: String,

    /// Warehouse location for table data and metadata.
    ///
    /// Any storage scheme compiled in: `file://`, `s3://`, `gs://`, `az://`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warehouse_location: Option<String>,

    /// Object-store configuration, by Iceberg property name.
    ///
    /// Passed to the `FileIO` every catalog in this process reads and writes
    /// through: `s3.endpoint`, `s3.region`, `s3.path-style-access`,
    /// `gcs.project-id`, and so on. Without it a warehouse on object storage
    /// works only when the backend finds ambient credentials, and an
    /// S3-compatible endpoint — MinIO, Ceph, R2 — cannot be reached at all.
    ///
    /// One set for the whole process. Keys are scheme-prefixed, so different
    /// clouds compose; two accounts on the *same* cloud do not, and need a
    /// process each.
    ///
    /// Secrets belong in the environment rather than in this file. A value of
    /// the form `env:NAME` is read from that environment variable at startup,
    /// and a variable that is unset or empty is a startup failure rather than a
    /// silently absent property.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub properties: HashMap<String, String>,

    /// How far inside the warehouse a client may put a resource's files.
    ///
    /// - `"table"` (default) — under `<warehouse>/<namespace>/<name>`, the
    ///   layout this catalog assigns. The storage hierarchy is then the policy
    ///   hierarchy, which is what makes a location-scoped credential a faithful
    ///   enforcement of a namespace-scoped grant.
    /// - `"warehouse"` — anywhere in the warehouse. For adopting a lake whose
    ///   layout predates this catalog. A caller permitted to write **one** table
    ///   can then point it at any prefix in the warehouse and be credentialed
    ///   there.
    ///
    /// See [`crate::location::LocationScope`] for the full argument.
    #[serde(default = "default_location_scope")]
    pub location_scope: String,
}

/// The tight bound, because the loose one hands a caller with one grant the
/// whole warehouse.
fn default_location_scope() -> String {
    "table".to_string()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            catalog_url: default_catalog_url(),
            warehouse_location: None,
            location_scope: default_location_scope(),
            properties: HashMap::new(),
        }
    }
}

fn default_catalog_url() -> String {
    "file:///var/lib/rustberg/data".to_string()
}

/// Rate limiting configuration from file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfigFile {
    /// Enable rate limiting.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Requests per second (per IP).
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size.
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    /// Authentication failure tracking enabled.
    #[serde(default = "default_true")]
    pub track_auth_failures: bool,

    /// Maximum auth failures before lockout.
    #[serde(default = "default_max_auth_failures")]
    pub max_auth_failures: u32,

    /// Auth failure lockout duration in seconds.
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration_seconds: u64,
}

impl Default for RateLimitConfigFile {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: default_requests_per_second(),
            burst_size: default_burst_size(),
            track_auth_failures: true,
            max_auth_failures: default_max_auth_failures(),
            lockout_duration_seconds: default_lockout_duration(),
        }
    }
}

fn default_requests_per_second() -> u32 {
    100
}

fn default_burst_size() -> u32 {
    200
}

fn default_max_auth_failures() -> u32 {
    5
}

fn default_lockout_duration() -> u64 {
    300 // 5 minutes
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: "trace", "debug", "info", "warn", "error".
    #[serde(default = "default_log_level")]
    pub level: String,

    /// JSON log format for SIEM ingestion.
    #[serde(default)]
    pub json_format: bool,

    /// Include span events in logs.
    #[serde(default = "default_true")]
    pub with_span_events: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json_format: false,
            with_span_events: true,
        }
    }
}

impl StorageConfig {
    /// Marks a property value that names an environment variable to read.
    const ENV_PREFIX: &'static str = "env:";

    /// The storage properties with every `env:NAME` value resolved.
    ///
    /// Object-store configuration is mostly not secret — an endpoint, a region,
    /// a bucket-addressing style — but the access key beside it is, and a
    /// deployment should not have to choose between committing its config file
    /// and configuring its storage. `env:` follows the same rule the rest of
    /// this file already applies to secrets ([`crate::config::secret`]): a named
    /// variable that is unset or blank is a startup failure, never a silently
    /// absent property.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::AppError`] naming the property and the variable when a named
    /// variable is unset or empty.
    pub fn resolved_properties(&self) -> Result<HashMap<String, String>, crate::error::AppError> {
        self.resolve_with(|var| std::env::var(var).ok())
    }

    /// The rule, separated from the lookup. See
    /// [`ApiKeyConfig::build_from`](ApiKeyConfig::to_api_key) for why.
    fn resolve_with(
        &self,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<HashMap<String, String>, crate::error::AppError> {
        self.properties
            .iter()
            .map(|(key, value)| match value.strip_prefix(Self::ENV_PREFIX) {
                Some(var) => crate::config::secret::resolve(
                    lookup(var).as_deref(),
                    var,
                    &format!("storage.properties.{key}"),
                )
                .map(|resolved| (key.clone(), resolved)),
                None => Ok((key.clone(), value.clone())),
            })
            .collect()
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

// ============================================================================
// Configuration Loader
// ============================================================================

/// Errors that can occur when loading configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read config file.
    #[error("Failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    /// Failed to parse config file.
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] toml::de::Error),

    /// Invalid configuration.
    #[error("Invalid configuration: {0}")]
    ValidationError(String),
}

impl RustbergConfig {
    /// Loads configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        let config: RustbergConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads configuration from a TOML string.
    pub fn parse_str(content: &str) -> Result<Self, ConfigError> {
        let config: RustbergConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ValidationError`] describing the first problem found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // TLS needs both halves of the keypair, or neither.
        if self.tls.enabled && (self.tls.cert_path.is_none() != self.tls.key_path.is_none()) {
            return Err(ConfigError::ValidationError(
                "TLS requires both cert_path and key_path, or neither (for a self-signed cert)"
                    .to_string(),
            ));
        }

        // A rate limiter configured to zero refuses everything rather than
        // limiting anything: with no refill rate the bucket never fills, and
        // with no capacity it starts empty. Either is a server that answers
        // `429` to every request after the first burst, which reads as an
        // outage. Switching rate limiting off is what `enabled = false` is for.
        if self.rate_limit.enabled {
            if self.rate_limit.requests_per_second == 0 {
                return Err(ConfigError::ValidationError(
                    "rate_limit.requests_per_second must be > 0. To turn rate limiting off, \
                     set rate_limit.enabled = false."
                        .to_string(),
                ));
            }
            if self.rate_limit.burst_size == 0 {
                return Err(ConfigError::ValidationError(
                    "rate_limit.burst_size must be > 0: a bucket with no capacity never \
                     admits a request. To turn rate limiting off, set rate_limit.enabled = \
                     false."
                        .to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Serializes configuration to TOML.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Generates a sample configuration file.
    pub fn sample() -> String {
        let sample = Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8000,
                auth: AuthConfig {
                    api_key_enabled: true,
                    jwt_enabled: false,
                    jwt: None,
                    policy_file: None,
                    api_keys: Vec::new(),
                },
                cors: CorsConfig::default(),
                trusted_proxies: Vec::new(),
                shutdown_delay_seconds: 0,
            },
            tls: TlsConfigFile {
                enabled: true,
                cert_path: Some("/path/to/cert.pem".to_string()),
                key_path: Some("/path/to/key.pem".to_string()),
                insecure_http: false,
            },
            storage: StorageConfig {
                location_scope: default_location_scope(),
                catalog_url: default_catalog_url(),
                warehouse_location: Some("s3://my-bucket/warehouse".to_string()),
                properties: HashMap::from([
                    ("s3.region".to_string(), "us-east-1".to_string()),
                    (
                        "s3.access-key-id".to_string(),
                        "env:RUSTBERG_S3_ACCESS_KEY_ID".to_string(),
                    ),
                ]),
            },
            rate_limit: RateLimitConfigFile::default(),
            logging: LoggingConfig::default(),
            audit: AuditConfig::default(),
            // The sample ships vending off. It needs a real role ARN or key
            // file, and a sample that looks configured but names a role nobody
            // owns fails at startup for a reason the operator did not choose.
            credentials: CredentialsConfig::default(),
            // No mounts in the sample: federation is opt-in, and a sample
            // naming catalogs nobody has would fail at startup.
            mount: std::collections::HashMap::new(),
        };

        sample.to_toml().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8000);
        assert!(config.auth.api_key_enabled);
        assert!(!config.auth.jwt_enabled);
        assert!(config.auth.jwt.is_none());
    }

    // ── Storage properties ────────────────────────────────────────────────

    /// The gap this closed: three storage Cargo features and a documented
    /// `warehouse_location = "s3://…"` with no way to say *which* S3 — so an
    /// S3-compatible endpoint could not be reached at all.
    #[test]
    fn plain_storage_properties_pass_through() {
        let storage = StorageConfig {
            location_scope: default_location_scope(),
            catalog_url: default_catalog_url(),
            warehouse_location: None,
            properties: HashMap::from([
                (
                    "s3.endpoint".to_string(),
                    "http://localhost:9000".to_string(),
                ),
                ("s3.path-style-access".to_string(), "true".to_string()),
            ]),
        };

        let resolved = storage.resolved_properties().unwrap();
        assert_eq!(
            resolved.get("s3.endpoint").map(String::as_str),
            Some("http://localhost:9000")
        );
        assert_eq!(
            resolved.get("s3.path-style-access").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn an_env_property_is_read_from_the_environment() {
        let storage = StorageConfig {
            location_scope: default_location_scope(),
            catalog_url: default_catalog_url(),
            warehouse_location: None,
            properties: HashMap::from([(
                "s3.access-key-id".to_string(),
                "env:RUSTBERG_TEST_S3_KEY".to_string(),
            )]),
        };

        let resolved = storage
            .resolve_with(|var| (var == "RUSTBERG_TEST_S3_KEY").then(|| "AKIAEXAMPLE".to_string()))
            .unwrap();
        assert_eq!(
            resolved.get("s3.access-key-id").map(String::as_str),
            Some("AKIAEXAMPLE")
        );
    }

    /// A named-but-missing secret is a startup failure, never a silently absent
    /// property — the same rule `config::secret` applies everywhere else.
    #[test]
    fn a_missing_env_property_names_itself_and_its_setting() {
        let storage = StorageConfig {
            location_scope: default_location_scope(),
            catalog_url: default_catalog_url(),
            warehouse_location: None,
            properties: HashMap::from([(
                "s3.secret-access-key".to_string(),
                "env:RUSTBERG_TEST_DEFINITELY_UNSET_STORAGE".to_string(),
            )]),
        };

        let message = storage.resolved_properties().unwrap_err().to_string();
        assert!(message.contains("RUSTBERG_TEST_DEFINITELY_UNSET_STORAGE"));
        assert!(message.contains("storage.properties.s3.secret-access-key"));
    }

    #[test]
    fn test_jwt_config_conversion() {
        let jwt_config_serde = JwtConfigSerde {
            issuer: "https://issuer.example.com".to_string(),
            audiences: vec!["rustberg-api".to_string()],
            jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
            default_tenant_id: "test-tenant".to_string(),
            tenant_claim: "custom_tenant".to_string(),
            roles_claim: "custom_roles".to_string(),
            jwks_cache_ttl_seconds: 7200,
            oauth2_server_uri: None,
        };

        let jwt_config: JwtConfig = jwt_config_serde.into();
        assert_eq!(jwt_config.issuer, "https://issuer.example.com");
        assert_eq!(jwt_config.audiences, vec!["rustberg-api".to_string()]);
        assert_eq!(jwt_config.default_tenant_id, "test-tenant");
        assert_eq!(jwt_config.tenant_claim, "custom_tenant");
        assert_eq!(jwt_config.roles_claim, "custom_roles");
        assert_eq!(jwt_config.jwks_cache_ttl, Duration::from_secs(7200));
    }

    #[test]
    fn test_server_config_serialization() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 9000,
            shutdown_delay_seconds: 0,
            auth: AuthConfig {
                api_key_enabled: true,
                jwt_enabled: true,
                policy_file: None,
                api_keys: Vec::new(),
                jwt: Some(JwtConfigSerde {
                    issuer: "https://issuer.example.com".to_string(),
                    audiences: vec!["rustberg-api".to_string()],
                    jwks_url: Some("https://issuer.example.com/.well-known/jwks.json".to_string()),
                    default_tenant_id: "default".to_string(),
                    tenant_claim: "tenant_id".to_string(),
                    roles_claim: "roles".to_string(),
                    jwks_cache_ttl_seconds: 3600,
                    oauth2_server_uri: None,
                }),
            },
            cors: CorsConfig::default(),
            trusted_proxies: vec!["10.0.0.0/8".to_string()],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.host, "127.0.0.1");
        assert_eq!(deserialized.port, 9000);
        assert!(deserialized.auth.api_key_enabled);
        assert!(deserialized.auth.jwt_enabled);
        assert!(deserialized.auth.jwt.is_some());
        assert_eq!(deserialized.trusted_proxies, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn test_rustberg_config_from_toml() {
        let toml_content = r#"
            [server]
            host = "127.0.0.1"
            port = 9000

            [server.auth]
            api_key_enabled = true
            jwt_enabled = false

            [tls]
            enabled = false
            insecure_http = true

            [storage]
            catalog_url = "file:///tmp/rustberg"

            [rate_limit]
            enabled = true
            requests_per_second = 50

            [logging]
            level = "debug"
        "#;

        let config = RustbergConfig::parse_str(toml_content).unwrap();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 9000);
        assert!(!config.tls.enabled);
        assert!(config.storage.catalog_url.starts_with("file://"));
        assert_eq!(config.rate_limit.requests_per_second, 50);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn test_rustberg_config_validation_tls() {
        let config = RustbergConfig {
            tls: TlsConfigFile {
                enabled: true,
                cert_path: Some("/path/to/cert".to_string()),
                key_path: None,
                insecure_http: false,
            },
            ..Default::default()
        };

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_rustberg_config_sample() {
        let sample = RustbergConfig::sample();
        assert!(sample.contains("[server]"));
        assert!(sample.contains("[tls]"));
        assert!(sample.contains("[storage]"));
    }

    #[test]
    fn test_rustberg_config_roundtrip() {
        let config = RustbergConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = RustbergConfig::parse_str(&toml_str).unwrap();

        assert_eq!(config.server.host, parsed.server.host);
        assert_eq!(config.server.port, parsed.server.port);
    }
    // ── API keys from configuration ──────────────────────────────────────

    #[test]
    fn api_keys_parse_from_toml() {
        let toml = r#"
[server]
host = "0.0.0.0"
port = 8000

[[server.auth.api_keys]]
name = "ci"
tenant = "acme"
roles = ["writer"]
key_env = "RUSTBERG_KEY_CI"
"#;
        let config: RustbergConfig = toml::from_str(toml).unwrap();
        let keys = &config.server.auth.api_keys;

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].name, "ci");
        assert_eq!(keys[0].tenant, "acme");
        assert_eq!(keys[0].roles, vec!["writer"]);
        assert_eq!(keys[0].key_env, "RUSTBERG_KEY_CI");
    }

    #[test]
    fn no_api_keys_is_valid() {
        let config: RustbergConfig =
            toml::from_str("[server]\nhost = \"0.0.0.0\"\nport = 8000\n").unwrap();
        assert!(config.server.auth.api_keys.is_empty());
    }

    /// The secret lives in the environment, so the config file itself never
    /// holds a usable credential.
    #[test]
    fn key_is_built_from_the_environment() {
        let cfg = ApiKeyConfig {
            name: "ci".into(),
            tenant: "acme".into(),
            roles: vec!["reader".into()],
            key_env: "RUSTBERG_TEST_KEY_PRESENT".into(),
        };

        let key = cfg
            .build_from(Some("rb_supersecretvalue"))
            .expect("secret is set");
        assert_eq!(key.name, "ci");
        assert_eq!(key.tenant_id, "acme");
        assert_eq!(key.roles, vec!["reader".to_string()]);
        // Only the hash is retained.
        assert_ne!(key.key_hash, "rb_supersecretvalue");
        assert!(!key.key_hash.is_empty());
    }

    /// A missing secret must fail loudly: a key that silently does not exist is
    /// indistinguishable from one revoked on purpose.
    #[test]
    fn missing_secret_is_rejected() {
        let cfg = ApiKeyConfig {
            name: "ci".into(),
            tenant: "acme".into(),
            roles: vec![],
            key_env: "RUSTBERG_TEST_KEY_DEFINITELY_UNSET".into(),
        };

        let err = cfg.to_api_key().unwrap_err();
        assert!(
            err.to_string()
                .contains("RUSTBERG_TEST_KEY_DEFINITELY_UNSET")
        );
    }

    #[test]
    fn empty_secret_is_rejected() {
        let cfg = ApiKeyConfig {
            name: "ci".into(),
            tenant: "acme".into(),
            roles: vec![],
            key_env: "RUSTBERG_TEST_KEY_EMPTY".into(),
        };

        assert!(cfg.build_from(Some("   ")).is_err());
        assert!(cfg.build_from(None).is_err());
    }
    /// An unknown key is an error rather than a silent no-op, so a typo or a
    /// setting that does not exist fails at startup instead of being ignored.
    #[test]
    fn an_unknown_storage_key_is_rejected() {
        let err = RustbergConfig::parse_str(
            r#"
            [storage]
            backend = "file:///srv/rustberg"
        "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("backend"), "{err}");
    }

    /// An unset `[storage]` section must still name a durable path. If it
    /// defaulted to nothing, the server would fall back to a temp catalog and
    /// lose every table on restart.
    #[test]
    fn storage_defaults_to_a_durable_path() {
        let config = RustbergConfig::parse_str("[server]\nport = 8000\n").unwrap();
        assert_eq!(config.storage.catalog_url, "file:///var/lib/rustberg/data");
    }
    /// Every optional feature is checked on its own in CI.
    ///
    /// The workflow's matrix is a hand-written list — a GitHub Actions matrix
    /// cannot read `Cargo.toml` — so it is the one place that can silently stop
    /// covering a feature added after it. That is not hypothetical: it happened
    /// to `remote-signing`, and `--all-features` cannot notice, because a
    /// feature broken *alone* is exactly what a full build hides.
    ///
    /// `default` and `storage-all` are excluded: both are aggregates of entries
    /// the list already has, so checking them proves nothing new.
    #[test]
    fn ci_checks_every_optional_feature_on_its_own() {
        let manifest = crate::utils::normalize_newlines(include_str!("../../Cargo.toml"));
        let workflow =
            crate::utils::normalize_newlines(include_str!("../../.github/workflows/ci.yml"));

        let declared: Vec<&str> = manifest
            .lines()
            .skip_while(|line| line.trim() != "[features]")
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with('['))
            .filter_map(|line| line.split_once('=').map(|(name, _)| name.trim()))
            .filter(|name| !name.is_empty() && !name.starts_with('#'))
            .filter(|name| !matches!(*name, "default" | "storage-all"))
            .collect();

        assert!(
            declared.len() >= 8,
            "the [features] section was not read: {declared:?}"
        );

        let missing: Vec<&&str> = declared
            .iter()
            .filter(|feature| !workflow.contains(&format!("- {feature}\n")))
            .collect();

        assert!(
            missing.is_empty(),
            "these features are declared but absent from the CI feature matrix in \
             .github/workflows/ci.yml, so nothing checks that they build alone: {missing:?}"
        );
    }

    // ── Documented configuration must parse ─────────────────────────────

    /// Every ```toml block in the docs is parsed against the real schema.
    ///
    /// A documented key that is not a real key fails the build. Without this,
    /// documentation drifts silently: `deny_unknown_fields` catches it at load
    /// time for an operator, but only this test catches it for a reader.
    #[test]
    fn documented_toml_matches_the_schema() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));

        // TOML embedded in a Kubernetes ConfigMap is what an operator copies, so
        // it is checked alongside the fenced blocks.
        /// TOML embedded in a YAML block scalar.
        ///
        /// Two spellings, because two things do it: a Kubernetes ConfigMap keys
        /// the file by name (`config.toml: |`), and the Helm chart passes it as
        /// a value (`config: |`). Both are this schema handed to a cluster, and
        /// the chart's copy is the one furthest from this file.
        fn configmap_blocks(doc: &str) -> Vec<String> {
            let mut out = Vec::new();
            for marker in ["config.toml: |", "config: |"] {
                let mut rest = doc;
                while let Some(at) = rest.find(marker) {
                    rest = &rest[at + marker.len()..];
                    let mut block = String::new();
                    for line in rest.lines() {
                        // The block ends at the first line that is neither blank
                        // nor indented into it.
                        if !line.trim().is_empty() && !line.starts_with("    ") {
                            break;
                        }
                        block.push_str(line.trim_start());
                        block.push('\n');
                    }
                    out.push(block);
                }
            }
            out
        }

        let mut sources: Vec<(String, String)> = vec![(
            "config.example.toml".to_string(),
            crate::utils::read_repo_text(root.join("config.example.toml"))
                .expect("read example config"),
        )];

        // The whole documentation tree, discovered rather than listed: a page
        // added later is covered without anyone remembering to add it here.
        let mut files: Vec<std::path::PathBuf> =
            std::fs::read_dir(root.join("site").join("content").join("docs"))
                .expect("read the documentation directory")
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|e| e == "md"))
                .collect();
        files.push(root.join("README.md"));
        // The design document too: it shows a mount table, and a design
        // document whose examples do not parse is one a reader copies from.
        files.push(root.join("CONCEPT.md"));
        // And the Helm chart, whose `config:` block is this exact schema handed
        // to a cluster. It is the copy furthest from this file and so the one
        // most likely to drift.
        files.push(root.join("charts").join("rustberg").join("README.md"));
        files.sort();

        for path in files {
            let Ok(text) = crate::utils::read_repo_text(&path) else {
                continue;
            };
            let label = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (n, block) in extract_toml_blocks(&text).into_iter().enumerate() {
                sources.push((format!("{label} block {}", n + 1), block));
            }
            for (n, block) in configmap_blocks(&text).into_iter().enumerate() {
                sources.push((format!("{label} ConfigMap {}", n + 1), block));
            }
        }

        assert!(sources.len() > 10, "expected to find documented TOML");

        let mut failures = Vec::new();
        for (label, body) in &sources {
            if let Err(e) = toml::from_str::<RustbergConfig>(body) {
                failures.push(format!("{label}: {e}"));
            }
        }

        assert!(
            failures.is_empty(),
            "documented TOML does not match the config schema:\n{}",
            failures.join("\n")
        );
    }

    /// Pulls fenced ```toml blocks out of markdown.
    ///
    /// Blocks tagged `toml,ignore` are skipped: those are deliberate fragments
    /// (a single section shown out of context) rather than whole configs.
    fn extract_toml_blocks(markdown: &str) -> Vec<String> {
        let mut blocks = Vec::new();
        let mut current: Option<String> = None;

        for line in markdown.lines() {
            match current.as_mut() {
                Some(buf) => {
                    if line.trim_start().starts_with("```") {
                        blocks.push(std::mem::take(buf));
                        current = None;
                    } else {
                        buf.push_str(line);
                        buf.push('\n');
                    }
                }
                None => {
                    if line.trim() == "```toml" {
                        current = Some(String::new());
                    }
                }
            }
        }

        blocks
    }

    /// A key that does not exist must be rejected, not ignored. Silently
    /// accepting a typo means an operator's setting never takes effect and
    /// nothing says so.
    #[test]
    fn unknown_keys_are_rejected() {
        let err = RustbergConfig::parse_str(
            r#"
            [storage]
            catalog_url = "file:///tmp/x"
            read_timeout_secs = 60
        "#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("read_timeout_secs"),
            "error should name the offending key: {err}"
        );
    }
    /// A limiter configured to zero refuses everything rather than limiting
    /// anything, which reads as an outage. `enabled = false` is how you turn it
    /// off.
    #[test]
    fn a_rate_limit_of_zero_is_refused_rather_than_serving_nothing() {
        for (rps, burst) in [(0u32, 200u32), (100, 0)] {
            let mut config = RustbergConfig::default();
            config.rate_limit.enabled = true;
            config.rate_limit.requests_per_second = rps;
            config.rate_limit.burst_size = burst;

            assert!(
                config.validate().is_err(),
                "rps={rps} burst={burst} must be refused"
            );
        }
    }

    #[test]
    fn a_disabled_limiter_does_not_have_to_be_configured() {
        let mut config = RustbergConfig::default();
        config.rate_limit.enabled = false;
        config.rate_limit.requests_per_second = 0;
        config.rate_limit.burst_size = 0;
        assert!(config.validate().is_ok());
    }
}
