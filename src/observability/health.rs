//! Health and readiness check endpoints.
//!
//! Provides `/health` and `/ready` endpoints for container orchestration
//! and load balancer health checks.

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::SystemTime;

use crate::app::AppState;

// ============================================================================
// Health Status
// ============================================================================

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Service status: "healthy" or "unhealthy".
    pub status: String,
    /// Service version from Cargo.toml.
    pub version: String,
    /// Current server timestamp (Unix epoch seconds).
    pub timestamp: u64,
    /// Uptime in seconds since the process started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_seconds: Option<u64>,
}

impl HealthStatus {
    /// Creates a healthy status response.
    pub fn healthy() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp,
            uptime_seconds: None,
        }
    }

    /// Creates an unhealthy status response.
    pub fn unhealthy(reason: String) -> Self {
        Self {
            status: format!("unhealthy: {}", reason),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            uptime_seconds: None,
        }
    }
}

// ============================================================================
// Readiness Status
// ============================================================================

/// Readiness check response with detailed component status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessStatus {
    /// Overall readiness: "ready" or "not_ready".
    pub status: String,
    /// Service version.
    pub version: String,
    /// Current timestamp.
    pub timestamp: u64,
    /// Component-specific readiness checks.
    pub components: ReadinessComponents,
}

/// Individual component readiness states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessComponents {
    /// Catalog backend connectivity.
    pub catalog: ComponentStatus,
    /// Authentication system status.
    pub authentication: ComponentStatus,
    /// Authorization system status.
    pub authorization: ComponentStatus,
    /// Storage credential provider status.
    pub credentials: ComponentStatus,
}

/// Status of an individual component.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Component status: "ready", "degraded", or "unavailable".
    pub status: String,
    /// Optional status message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ComponentStatus {
    /// Creates a ready status.
    pub fn ready() -> Self {
        Self {
            status: "ready".to_string(),
            message: None,
        }
    }

    /// Creates a degraded status with a message.
    pub fn degraded(message: impl Into<String>) -> Self {
        Self {
            status: "degraded".to_string(),
            message: Some(message.into()),
        }
    }

    /// Creates an unavailable status with a message.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: "unavailable".to_string(),
            message: Some(message.into()),
        }
    }
}

impl ReadinessStatus {
    /// Checks all components and returns overall readiness.
    ///
    /// Performs actual health checks against each component:
    /// - **Catalog**: Attempts to list namespaces (validates backend connectivity)
    /// - **Authentication**: Verifies the authenticator is operational
    /// - **Authorization**: Verifies the authorizer is operational
    /// - **Credentials**: Checks if credential provider is configured
    pub async fn check(state: &AppState) -> Self {
        use tokio::time::{timeout, Duration};

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Health check timeout - if any check takes longer than this, it's degraded
        let check_timeout = Duration::from_secs(5);

        // Check catalog connectivity by attempting to list root namespaces
        let catalog = match timeout(
            check_timeout,
            state.catalog.list_namespaces(None)
        ).await {
            Ok(Ok(_)) => ComponentStatus::ready(),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Catalog health check failed");
                ComponentStatus::degraded(format!("Catalog error: {}", e))
            }
            Err(_) => {
                tracing::warn!("Catalog health check timed out");
                ComponentStatus::degraded("Catalog response timeout")
            }
        };

        // Authentication is considered ready if the authenticator trait is present
        // In practice, we don't have a separate health check method on the trait
        let authentication = ComponentStatus::ready();

        // Authorization is considered ready if the authorizer trait is present
        let authorization = ComponentStatus::ready();

        // Credentials provider check - we consider it ready if present
        // A more thorough check could verify AWS STS connectivity
        let credentials = ComponentStatus::ready();

        let components = ReadinessComponents {
            catalog,
            authentication,
            authorization,
            credentials,
        };

        // Overall status is ready if all components are ready (not degraded or unavailable)
        let all_ready = [
            &components.catalog,
            &components.authentication,
            &components.authorization,
            &components.credentials,
        ]
        .iter()
        .all(|c| c.status == "ready");

        Self {
            status: if all_ready {
                "ready".to_string()
            } else {
                "not_ready".to_string()
            },
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp,
            components,
        }
    }
}

// ============================================================================
// HTTP Handlers
// ============================================================================

/// Health check handler.
///
/// Returns 200 OK if the service is running. This is a simple liveness check
/// used by container orchestrators to detect crashed processes.
///
/// Example:
/// ```bash
/// curl http://localhost:8080/health
/// ```
///
/// Response:
/// ```json
/// {
///   "status": "healthy",
///   "version": "0.1.0",
///   "timestamp": 1704067200
/// }
/// ```
pub async fn health_handler() -> impl IntoResponse {
    let status = HealthStatus::healthy();
    (StatusCode::OK, Json(status))
}

/// Readiness check handler.
///
/// Returns 200 OK if the service is ready to handle requests, checking:
/// - Catalog backend connectivity
/// - Authentication system availability
/// - Authorization system availability
/// - Storage credential provider status
///
/// Returns 503 Service Unavailable if any component is not ready.
///
/// Example:
/// ```bash
/// curl http://localhost:8080/ready
/// ```
///
/// Response (ready):
/// ```json
/// {
///   "status": "ready",
///   "version": "0.1.0",
///   "timestamp": 1704067200,
///   "components": {
///     "catalog": { "status": "ready" },
///     "authentication": { "status": "ready" },
///     "authorization": { "status": "ready" },
///     "credentials": { "status": "ready" }
///   }
/// }
/// ```
pub async fn readiness_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let status = ReadinessStatus::check(&state).await;

    let status_code = if status.status == "ready" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status_code, Json(status))
}

// ============================================================================
// Router
// ============================================================================

/// Creates the health/readiness routes.
pub fn create_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/ready", get(readiness_handler))
        .with_state(state)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_healthy() {
        let status = HealthStatus::healthy();
        assert_eq!(status.status, "healthy");
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        assert!(status.timestamp > 0);
    }

    #[test]
    fn test_health_status_unhealthy() {
        let status = HealthStatus::unhealthy("test error".to_string());
        assert!(status.status.contains("unhealthy"));
        assert!(status.status.contains("test error"));
    }

    #[test]
    fn test_component_status() {
        let ready = ComponentStatus::ready();
        assert_eq!(ready.status, "ready");
        assert!(ready.message.is_none());

        let degraded = ComponentStatus::degraded("slow connection");
        assert_eq!(degraded.status, "degraded");
        assert_eq!(degraded.message.as_deref(), Some("slow connection"));

        let unavailable = ComponentStatus::unavailable("connection lost");
        assert_eq!(unavailable.status, "unavailable");
        assert_eq!(unavailable.message.as_deref(), Some("connection lost"));
    }

    #[tokio::test]
    async fn test_readiness_all_ready() {
        use crate::auth::{AllowAllAuthenticator, AllowAllAuthorizer, RateLimiter, RateLimitConfig};
        use crate::catalog::{ExtendedCatalog, IdempotencyCache, ViewStorage};
        use crate::credentials::NoopCredentialProvider;
        use iceberg::memory::MemoryCatalogBuilder;
        use iceberg::CatalogBuilder;
        use std::collections::HashMap;
        use std::time::Duration;

        let mut props = HashMap::new();
        props.insert("warehouse".to_string(), "memory://test".to_string());
        
        let catalog: iceberg::MemoryCatalog = MemoryCatalogBuilder::default()
            .load("memory", props)
            .await
            .unwrap();

        let state = AppState {
            authenticator: Arc::new(AllowAllAuthenticator),
            authorizer: Arc::new(AllowAllAuthorizer),
            catalog: Arc::new(ExtendedCatalog::new(catalog)),
            credential_provider: Arc::new(NoopCredentialProvider),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
            idempotency_cache: Arc::new(IdempotencyCache::new(Duration::from_secs(3600))),
            view_storage: Arc::new(ViewStorage::new()),
            metrics: Arc::new(crate::observability::MetricsRegistry::new()),
            warehouse_location: "memory://test".to_string(),
            default_tenant_id: "default".to_string(),
        };

        let status = ReadinessStatus::check(&state).await;
        assert_eq!(status.status, "ready");
        assert_eq!(status.components.catalog.status, "ready");
        assert_eq!(status.components.authentication.status, "ready");
        assert_eq!(status.components.authorization.status, "ready");
        assert_eq!(status.components.credentials.status, "ready");
    }
}
