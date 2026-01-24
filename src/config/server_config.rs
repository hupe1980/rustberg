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
//! backend = "file:///var/lib/rustberg/data"  # or "s3://bucket/prefix?region=us-east-1"
//!
//! [kms]
//! type = "env"
//! # For production: type = "aws-kms", key_id = "alias/rustberg"
//!
//! [rate_limit]
//! requests_per_second = 100
//! burst_size = 200
//! ```

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

use crate::auth::JwtConfig;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            auth: AuthConfig::default(),
            cors: CorsConfig::default(),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_key_enabled: true,
            jwt_enabled: false,
            jwt: None,
        }
    }
}

/// JWT configuration (serializable version of JwtConfig)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfigSerde {
    /// OIDC issuer URL (e.g., "https://accounts.google.com")
    pub issuer: String,

    /// Expected audience (e.g., "rustberg-api")
    pub audience: String,

    /// JWKS endpoint URL (e.g., "https://accounts.google.com/.well-known/jwks.json")
    pub jwks_url: String,

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
}

impl From<JwtConfigSerde> for JwtConfig {
    fn from(config: JwtConfigSerde) -> Self {
        JwtConfig {
            issuer: config.issuer,
            audience: config.audience,
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
    8080
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

fn default_allowed_origins() -> Vec<String> {
    vec!["*".to_string()]
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
pub struct RustbergConfig {
    /// Server configuration.
    #[serde(default)]
    pub server: ServerConfig,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfigFile,

    /// Storage backend configuration.
    #[serde(default)]
    pub storage: StorageConfig,

    /// KMS configuration.
    #[serde(default)]
    pub kms: KmsConfigFile,

    /// Rate limiting configuration.
    #[serde(default)]
    pub rate_limit: RateLimitConfigFile,

    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// TLS configuration from file.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Storage backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend URL.
    ///
    /// Supported schemes:
    /// - `file:///path` - Local filesystem (single-node, default)
    /// - `s3://bucket/prefix?region=us-east-1` - Amazon S3 (K8s HA)
    /// - `gs://bucket/prefix` - Google Cloud Storage (K8s HA)
    /// - `az://container/prefix` - Azure Blob Storage (K8s HA)
    /// - `memory://` - In-memory only (testing)
    #[serde(default = "default_storage_type")]
    pub backend: String,

    /// Warehouse location for table data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warehouse_location: Option<String>,

    /// AWS region for S3 object store (can also be in URL query string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_region: Option<String>,

    /// Local cache directory for SlateDB (optional, improves read latency).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_type(),
            warehouse_location: None,
            aws_region: None,
            cache_dir: None,
        }
    }
}

fn default_storage_type() -> String {
    "file:///var/lib/rustberg/data".to_string()
}

/// KMS configuration from file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsConfigFile {
    /// KMS provider type: "env", "aws-kms", "vault", "gcp-kms", "azure-keyvault".
    #[serde(default = "default_kms_type")]
    pub provider: String,

    /// AWS KMS key ID (for aws-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_key_id: Option<String>,

    /// AWS region (for aws-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_region: Option<String>,

    /// Vault address (for vault provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_address: Option<String>,

    /// Vault key name (for vault provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_key_name: Option<String>,

    /// GCP project ID (for gcp-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_project_id: Option<String>,

    /// GCP location/region (for gcp-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_location: Option<String>,

    /// GCP key ring name (for gcp-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_key_ring: Option<String>,

    /// GCP key name (for gcp-kms provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gcp_key_name: Option<String>,

    /// Azure Key Vault URL (for azure-keyvault provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_vault_url: Option<String>,

    /// Azure key name (for azure-keyvault provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub azure_key_name: Option<String>,

    /// Cache TTL in seconds (default: 300).
    #[serde(default = "default_kms_cache_ttl")]
    pub cache_ttl_seconds: u64,

    /// Enable circuit breaker.
    #[serde(default = "default_true")]
    pub circuit_breaker_enabled: bool,
}

impl Default for KmsConfigFile {
    fn default() -> Self {
        Self {
            provider: default_kms_type(),
            aws_key_id: None,
            aws_region: None,
            vault_address: None,
            vault_key_name: None,
            gcp_project_id: None,
            gcp_location: None,
            gcp_key_ring: None,
            gcp_key_name: None,
            azure_vault_url: None,
            azure_key_name: None,
            cache_ttl_seconds: default_kms_cache_ttl(),
            circuit_breaker_enabled: true,
        }
    }
}

fn default_kms_type() -> String {
    "env".to_string()
}

fn default_kms_cache_ttl() -> u64 {
    300
}

/// Rate limiting configuration from file.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Trust proxy headers (X-Forwarded-For, X-Real-IP) for client IP detection.
    ///
    /// **SECURITY WARNING**: Only enable this when running behind a trusted reverse proxy
    /// that sets these headers correctly. If enabled without a trusted proxy, attackers
    /// can spoof their IP address to bypass rate limiting.
    ///
    /// Default: `false` (use connection IP only)
    #[serde(default)]
    pub trust_proxy_headers: bool,
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
            trust_proxy_headers: false, // SECURE DEFAULT
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

    /// Tries to load from file, falls back to defaults.
    pub fn load_or_default<P: AsRef<Path>>(path: P) -> Self {
        match Self::from_file(path.as_ref()) {
            Ok(config) => {
                tracing::info!(path = %path.as_ref().display(), "Loaded configuration from file");
                config
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.as_ref().display(),
                    error = %e,
                    "Failed to load config, using defaults"
                );
                Self::default()
            }
        }
    }

    /// Searches for config in common locations.
    pub fn discover() -> Self {
        let search_paths = [
            "rustberg.toml",
            "/etc/rustberg/config.toml",
            "config/rustberg.toml",
        ];

        for path in search_paths {
            if Path::new(path).exists() {
                if let Ok(config) = Self::from_file(path) {
                    tracing::info!(path = %path, "Discovered configuration file");
                    return config;
                }
            }
        }

        tracing::debug!("No config file found, using defaults");
        Self::default()
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // Validate TLS configuration
        if self.tls.enabled {
            if self.tls.cert_path.is_none() && !self.tls.insecure_http {
                return Err(ConfigError::ValidationError(
                    "TLS enabled but no cert_path provided and insecure_http is false".to_string(),
                ));
            }
            if self.tls.key_path.is_none() && self.tls.cert_path.is_some() {
                return Err(ConfigError::ValidationError(
                    "TLS cert_path provided but no key_path".to_string(),
                ));
            }
        }

        // Validate KMS configuration
        match self.kms.provider.as_str() {
            "env" => { /* No additional config needed */ }
            "aws-kms" => {
                if self.kms.aws_key_id.is_none() {
                    return Err(ConfigError::ValidationError(
                        "AWS KMS provider requires aws_key_id".to_string(),
                    ));
                }
            }
            "vault" => {
                if self.kms.vault_address.is_none() || self.kms.vault_key_name.is_none() {
                    return Err(ConfigError::ValidationError(
                        "Vault provider requires vault_address and vault_key_name".to_string(),
                    ));
                }
            }
            provider => {
                return Err(ConfigError::ValidationError(format!(
                    "Unknown KMS provider: {}",
                    provider
                )));
            }
        }

        // Validate rate limit configuration
        if self.rate_limit.enabled && self.rate_limit.requests_per_second == 0 {
            return Err(ConfigError::ValidationError(
                "requests_per_second must be > 0".to_string(),
            ));
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
                },
                cors: CorsConfig::default(),
            },
            tls: TlsConfigFile {
                enabled: true,
                cert_path: Some("/path/to/cert.pem".to_string()),
                key_path: Some("/path/to/key.pem".to_string()),
                insecure_http: false,
            },
            storage: StorageConfig {
                backend: "file:///var/lib/rustberg/data".to_string(),
                warehouse_location: Some("s3://my-bucket/warehouse".to_string()),
                aws_region: None,
                cache_dir: None,
            },
            kms: KmsConfigFile {
                provider: "env".to_string(),
                aws_key_id: None,
                aws_region: None,
                vault_address: None,
                vault_key_name: None,
                gcp_project_id: None,
                gcp_location: None,
                gcp_key_ring: None,
                gcp_key_name: None,
                azure_vault_url: None,
                azure_key_name: None,
                cache_ttl_seconds: 300,
                circuit_breaker_enabled: true,
            },
            rate_limit: RateLimitConfigFile::default(),
            logging: LoggingConfig::default(),
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
        assert_eq!(config.port, 8080);
        assert!(config.auth.api_key_enabled);
        assert!(!config.auth.jwt_enabled);
        assert!(config.auth.jwt.is_none());
    }

    #[test]
    fn test_jwt_config_conversion() {
        let jwt_config_serde = JwtConfigSerde {
            issuer: "https://issuer.example.com".to_string(),
            audience: "rustberg-api".to_string(),
            jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            default_tenant_id: "test-tenant".to_string(),
            tenant_claim: "custom_tenant".to_string(),
            roles_claim: "custom_roles".to_string(),
            jwks_cache_ttl_seconds: 7200,
        };

        let jwt_config: JwtConfig = jwt_config_serde.into();
        assert_eq!(jwt_config.issuer, "https://issuer.example.com");
        assert_eq!(jwt_config.audience, "rustberg-api");
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
            auth: AuthConfig {
                api_key_enabled: true,
                jwt_enabled: true,
                jwt: Some(JwtConfigSerde {
                    issuer: "https://issuer.example.com".to_string(),
                    audience: "rustberg-api".to_string(),
                    jwks_url: "https://issuer.example.com/.well-known/jwks.json".to_string(),
                    default_tenant_id: "default".to_string(),
                    tenant_claim: "tenant_id".to_string(),
                    roles_claim: "roles".to_string(),
                    jwks_cache_ttl_seconds: 3600,
                }),
            },
            cors: CorsConfig::default(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ServerConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.host, "127.0.0.1");
        assert_eq!(deserialized.port, 9000);
        assert!(deserialized.auth.api_key_enabled);
        assert!(deserialized.auth.jwt_enabled);
        assert!(deserialized.auth.jwt.is_some());
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
            backend = "file:///tmp/rustberg"

            [kms]
            provider = "env"

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
        assert!(config.storage.backend.starts_with("file://"));
        assert_eq!(config.kms.provider, "env");
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
    fn test_rustberg_config_validation_kms() {
        let config = RustbergConfig {
            kms: KmsConfigFile {
                provider: "aws-kms".to_string(),
                aws_key_id: None, // Missing required field
                ..Default::default()
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
        assert!(sample.contains("[kms]"));
    }

    #[test]
    fn test_rustberg_config_roundtrip() {
        let config = RustbergConfig::default();
        let toml_str = config.to_toml().unwrap();
        let parsed = RustbergConfig::parse_str(&toml_str).unwrap();

        assert_eq!(config.server.host, parsed.server.host);
        assert_eq!(config.server.port, parsed.server.port);
        assert_eq!(config.kms.provider, parsed.kms.provider);
    }
}
