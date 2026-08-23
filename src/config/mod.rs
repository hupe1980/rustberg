pub mod secret;
pub mod server_config;
mod v1;

use axum::Router;

use crate::app::AppState;

// Re-export configuration types
pub use server_config::{
    AuditConfig, AuthConfig, AwsCredentialsConfig, AzureCredentialsConfig, ConfigError, CorsConfig,
    CredentialsConfig, GcsCredentialsConfig, JwtConfigSerde, LoggingConfig, MountConfig,
    RateLimitConfigFile, RustbergConfig, ServerConfig, StorageConfig, TlsConfigFile,
};

pub fn create_routes(app_state: AppState) -> Router {
    let v1_routes = v1::create_routes(app_state.clone());

    Router::new().nest("/v1", v1_routes)
}
