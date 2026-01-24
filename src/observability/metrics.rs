//! Prometheus metrics registry and exposition.
//!
//! This module provides Prometheus-compatible metrics for monitoring
//! Rustberg's operational health and performance.
//!
//! ## Available Metrics
//!
//! - `rustberg_info` - Service information (version)
//! - `rustberg_requests_total` - Total HTTP requests by method, path, status
//! - `rustberg_catalog_operations_total` - Catalog operations by type and result
//! - `rustberg_auth_attempts_total` - Authentication attempts by method and result
//! - `rustberg_rate_limit_exceeded_total` - Rate limit exceeded events

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Router};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::app::AppState;

// ============================================================================
// Metrics Registry
// ============================================================================

/// Thread-safe counter for a single metric.
#[derive(Debug, Default)]
pub struct Counter(AtomicU64);

impl Counter {
    /// Increments the counter by 1.
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current value.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Metrics registry for Prometheus exposition.
///
/// Provides real-time metrics counters that are updated by the application.
/// All counters are lock-free using atomic operations.
#[derive(Debug, Default)]
pub struct MetricsRegistry {
    // Request counters by method
    pub requests_get: Counter,
    pub requests_post: Counter,
    pub requests_delete: Counter,
    pub requests_head: Counter,

    // Catalog operation counters
    pub catalog_list_namespaces: Counter,
    pub catalog_create_namespace: Counter,
    pub catalog_delete_namespace: Counter,
    pub catalog_list_tables: Counter,
    pub catalog_create_table: Counter,
    pub catalog_load_table: Counter,
    pub catalog_commit_table: Counter,
    pub catalog_delete_table: Counter,
    pub catalog_register_table: Counter,
    pub catalog_rename_table: Counter,
    pub catalog_operation_errors: Counter,

    // Auth counters
    pub auth_api_key_success: Counter,
    pub auth_api_key_failure: Counter,
    pub auth_jwt_success: Counter,
    pub auth_jwt_failure: Counter,

    // Rate limiting
    pub rate_limit_exceeded: Counter,

    // Error counters by type
    pub errors_400: Counter,
    pub errors_401: Counter,
    pub errors_403: Counter,
    pub errors_404: Counter,
    pub errors_409: Counter,
    pub errors_429: Counter,
    pub errors_500: Counter,
}

impl MetricsRegistry {
    /// Creates a new metrics registry with all counters initialized to 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns Prometheus-formatted metrics text.
    pub fn render(&self) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default() // Safe: returns Duration::ZERO if clock is before epoch
            .as_secs();

        format!(
            r#"# HELP rustberg_info Service information
# TYPE rustberg_info gauge
rustberg_info{{version="{version}"}} 1

# HELP rustberg_build_timestamp_seconds Build timestamp in Unix epoch
# TYPE rustberg_build_timestamp_seconds gauge
rustberg_build_timestamp_seconds {timestamp}

# HELP rustberg_requests_total Total number of HTTP requests
# TYPE rustberg_requests_total counter
rustberg_requests_total{{method="GET"}} {get}
rustberg_requests_total{{method="POST"}} {post}
rustberg_requests_total{{method="DELETE"}} {delete}
rustberg_requests_total{{method="HEAD"}} {head}

# HELP rustberg_catalog_operations_total Total catalog operations
# TYPE rustberg_catalog_operations_total counter
rustberg_catalog_operations_total{{operation="list_namespaces",result="success"}} {list_ns}
rustberg_catalog_operations_total{{operation="create_namespace",result="success"}} {create_ns}
rustberg_catalog_operations_total{{operation="delete_namespace",result="success"}} {delete_ns}
rustberg_catalog_operations_total{{operation="list_tables",result="success"}} {list_tbl}
rustberg_catalog_operations_total{{operation="create_table",result="success"}} {create_tbl}
rustberg_catalog_operations_total{{operation="load_table",result="success"}} {load_tbl}
rustberg_catalog_operations_total{{operation="commit_table",result="success"}} {commit_tbl}
rustberg_catalog_operations_total{{operation="delete_table",result="success"}} {delete_tbl}
rustberg_catalog_operations_total{{operation="register_table",result="success"}} {register_tbl}
rustberg_catalog_operations_total{{operation="rename_table",result="success"}} {rename_tbl}
rustberg_catalog_operations_total{{operation="any",result="error"}} {op_errors}

# HELP rustberg_auth_attempts_total Authentication attempts
# TYPE rustberg_auth_attempts_total counter
rustberg_auth_attempts_total{{method="api_key",result="success"}} {api_key_ok}
rustberg_auth_attempts_total{{method="api_key",result="failure"}} {api_key_fail}
rustberg_auth_attempts_total{{method="jwt",result="success"}} {jwt_ok}
rustberg_auth_attempts_total{{method="jwt",result="failure"}} {jwt_fail}

# HELP rustberg_rate_limit_exceeded_total Rate limit exceeded counter
# TYPE rustberg_rate_limit_exceeded_total counter
rustberg_rate_limit_exceeded_total {rate_limit}

# HELP rustberg_errors_total HTTP errors by status code
# TYPE rustberg_errors_total counter
rustberg_errors_total{{status="400"}} {err_400}
rustberg_errors_total{{status="401"}} {err_401}
rustberg_errors_total{{status="403"}} {err_403}
rustberg_errors_total{{status="404"}} {err_404}
rustberg_errors_total{{status="409"}} {err_409}
rustberg_errors_total{{status="429"}} {err_429}
rustberg_errors_total{{status="500"}} {err_500}
"#,
            version = env!("CARGO_PKG_VERSION"),
            timestamp = timestamp,
            get = self.requests_get.get(),
            post = self.requests_post.get(),
            delete = self.requests_delete.get(),
            head = self.requests_head.get(),
            list_ns = self.catalog_list_namespaces.get(),
            create_ns = self.catalog_create_namespace.get(),
            delete_ns = self.catalog_delete_namespace.get(),
            list_tbl = self.catalog_list_tables.get(),
            create_tbl = self.catalog_create_table.get(),
            load_tbl = self.catalog_load_table.get(),
            commit_tbl = self.catalog_commit_table.get(),
            delete_tbl = self.catalog_delete_table.get(),
            register_tbl = self.catalog_register_table.get(),
            rename_tbl = self.catalog_rename_table.get(),
            op_errors = self.catalog_operation_errors.get(),
            api_key_ok = self.auth_api_key_success.get(),
            api_key_fail = self.auth_api_key_failure.get(),
            jwt_ok = self.auth_jwt_success.get(),
            jwt_fail = self.auth_jwt_failure.get(),
            rate_limit = self.rate_limit_exceeded.get(),
            err_400 = self.errors_400.get(),
            err_401 = self.errors_401.get(),
            err_403 = self.errors_403.get(),
            err_404 = self.errors_404.get(),
            err_409 = self.errors_409.get(),
            err_429 = self.errors_429.get(),
            err_500 = self.errors_500.get(),
        )
    }
}

// ============================================================================
// HTTP Handler
// ============================================================================

/// Metrics endpoint handler.
///
/// Returns Prometheus-formatted metrics in text format.
///
/// Example:
/// ```bash
/// curl http://localhost:8080/metrics
/// ```
///
/// Response:
/// ```text
/// # HELP rustberg_requests_total Total HTTP requests
/// # TYPE rustberg_requests_total counter
/// rustberg_requests_total{method="GET"} 42
/// ...
/// ```
pub async fn metrics_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let metrics_text = state.metrics.render();

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        metrics_text,
    )
}

// ============================================================================
// Router
// ============================================================================

/// Creates the metrics routes.
pub fn create_routes(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_increment() {
        let counter = Counter::default();
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc();
        counter.inc();
        assert_eq!(counter.get(), 3);
    }

    #[test]
    fn test_metrics_registry_render() {
        let registry = MetricsRegistry::new();
        registry.requests_get.inc();
        registry.requests_get.inc();
        registry.auth_api_key_success.inc();

        let output = registry.render();

        // Verify Prometheus format basics
        assert!(output.contains("# HELP"));
        assert!(output.contains("# TYPE"));
        assert!(output.contains("rustberg_info"));
        assert!(output.contains("rustberg_requests_total"));
        assert!(output.contains("rustberg_auth_attempts_total"));
        assert!(output.contains("rustberg_rate_limit_exceeded_total"));

        // Verify counters have correct values
        assert!(output.contains(r#"rustberg_requests_total{method="GET"} 2"#));
        assert!(
            output.contains(r#"rustberg_auth_attempts_total{method="api_key",result="success"} 1"#)
        );
    }

    #[test]
    fn test_metrics_include_version() {
        let registry = MetricsRegistry::new();
        let output = registry.render();
        assert!(output.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn test_metrics_timestamp_safety() {
        // This test verifies that render() doesn't panic even with edge cases
        let registry = MetricsRegistry::new();
        let output = registry.render();
        assert!(output.contains("rustberg_build_timestamp_seconds"));
    }
}
