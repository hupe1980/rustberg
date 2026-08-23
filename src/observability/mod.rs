//! Observability module providing health checks and metrics.
//!
//! This module implements production-grade observability features:
//! - `/health` - Liveness probe for container orchestrators
//! - `/ready` - Readiness probe checking dependencies  
//! - `/metrics` - Prometheus-compatible metrics endpoint
//!
//! ## Health vs Ready
//!
//! - **Health**: Simple liveness check. Returns 200 if the process is running.
//!   Used by Kubernetes `livenessProbe` to restart crashed containers.
//!
//! - **Ready**: Readiness check verifying the service can handle requests.
//!   Checks catalog connectivity, storage availability, etc.
//!   Used by Kubernetes `readinessProbe` to route traffic only to healthy instances.
//!
//! ## Metrics
//!
//! Exposes key operational metrics in Prometheus format:
//! - Request rates and latencies (p50, p95, p99)
//! - Authentication success/failure rates
//! - Authorization decision counts
//! - Rate limit hits
//! - Error rates by type
//! - Active connections
//!
//! Example scrape config:
//! ```yaml
//! scrape_configs:
//!   - job_name: 'rustberg'
//!     static_configs:
//!       - targets: ['localhost:8080']
//!     metrics_path: '/metrics'
//! ```

pub mod diagnostics;
pub mod health;
pub mod metrics;
pub mod perf;

pub use diagnostics::{StartupDiagnostics, StartupDiagnosticsBuilder};
pub use health::{HealthStatus, ReadinessStatus, create_routes as create_health_routes};
pub use metrics::MetricsRegistry;
