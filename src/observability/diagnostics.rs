//! Startup diagnostics and configuration banner.
//!
//! Displays system configuration at startup for operational visibility.

use std::time::SystemTime;

/// Startup diagnostics configuration.
#[derive(Debug, Clone)]
pub struct StartupDiagnostics {
    /// Service name.
    pub service_name: String,
    /// Service version.
    pub version: String,
    /// Build timestamp (from compile time).
    pub build_time: Option<String>,
    /// Git commit hash (if available).
    pub git_commit: Option<String>,
    /// Server bind address.
    pub bind_address: String,
    /// Server port.
    pub port: u16,
    /// TLS enabled.
    pub tls_enabled: bool,
    /// Authentication mode.
    pub auth_mode: String,
    /// Storage backend.
    pub storage_backend: String,
    /// Warehouse location.
    pub warehouse_location: Option<String>,
    /// Default tenant ID.
    pub default_tenant_id: String,
}

impl Default for StartupDiagnostics {
    fn default() -> Self {
        Self {
            service_name: "Rustberg".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            build_time: option_env!("VERGEN_BUILD_TIMESTAMP").map(String::from),
            git_commit: option_env!("VERGEN_GIT_SHA").map(String::from),
            bind_address: "0.0.0.0".to_string(),
            port: 8000,
            tls_enabled: false,
            auth_mode: "disabled".to_string(),
            storage_backend: "memory".to_string(),
            warehouse_location: None,
            default_tenant_id: "default".to_string(),
        }
    }
}

impl StartupDiagnostics {
    /// Creates a new diagnostics builder.
    pub fn builder() -> StartupDiagnosticsBuilder {
        StartupDiagnosticsBuilder::default()
    }

    /// Prints the startup banner with configuration summary.
    ///
    /// Uses `tracing::info!` for structured logging so log aggregators
    /// capture startup configuration. The ASCII banner goes to stdout
    /// for terminal visibility.
    pub fn print_banner(&self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // ASCII art logo — stdout for terminal visibility
        let logo = r#"
  ██████╗ ██╗   ██╗███████╗████████╗██████╗ ███████╗██████╗  ██████╗ 
  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔══██╗██╔════╝ 
  ██████╔╝██║   ██║███████╗   ██║   ██████╔╝█████╗  ██████╔╝██║  ███╗
  ██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██╔══╝  ██╔══██╗██║   ██║
  ██║  ██║╚██████╔╝███████║   ██║   ██████╔╝███████╗██║  ██║╚██████╔╝
  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ 
  Apache Iceberg REST Catalog
"#;

        println!("{}", logo);

        // Log startup configuration via tracing for structured capture
        let protocol = if self.tls_enabled { "https" } else { "http" };
        let listen_url = format!("{}://{}:{}", protocol, self.bind_address, self.port);

        let auth_status = match self.auth_mode.as_str() {
            "disabled" => "disabled (INSECURE)",
            "api_key" => "API key",
            "jwt" => "JWT/OIDC",
            "api_key+jwt" => "API key + JWT",
            other => other,
        };

        tracing::info!(
            service = %self.service_name,
            version = %self.version,
            listen_url = %listen_url,
            tls = self.tls_enabled,
            auth_mode = %auth_status,
            storage_backend = %self.storage_backend,
            warehouse = self.warehouse_location.as_deref().unwrap_or("(none)"),
            default_tenant = %self.default_tenant_id,
            started_at = now,
            "Server starting"
        );

        if let Some(ref commit) = self.git_commit {
            tracing::info!(commit = %&commit[..commit.len().min(8)], "Build info");
        }

        // Also print a compact table to stdout for terminal readability
        println!("╔════════════════════════════════════════════════════════════════════╗");
        println!("║  {} v{:<54}║", self.service_name, self.version);
        if let Some(ref commit) = self.git_commit {
            println!("║  Commit: {:<57}║", &commit[..commit.len().min(8)]);
        }
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║  Listen URL:      {:<48}║", listen_url);
        println!(
            "║  TLS:             {:<48}║",
            if self.tls_enabled {
                "✓ enabled"
            } else {
                "✗ disabled (INSECURE)"
            }
        );
        println!("║  Authentication:  {:<48}║", auth_status);
        println!("║  Storage Backend: {:<48}║", self.storage_backend);
        if let Some(ref warehouse) = self.warehouse_location {
            let truncated = if warehouse.len() > 45 {
                format!("{}...", &warehouse[..42])
            } else {
                warehouse.clone()
            };
            println!("║  Warehouse:       {:<48}║", truncated);
        }
        println!("║  Default Tenant:  {:<48}║", self.default_tenant_id);
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║  Health:  GET /health                                              ║");
        println!("║  Ready:   GET /ready                                               ║");
        println!("║  Metrics: GET /metrics                                             ║");
        println!("║  API:     /v1/namespaces, /v1/{{namespace}}/tables                  ║");
        println!("║  Views:   /v1/{{namespace}}/views                                   ║");
        println!("╠════════════════════════════════════════════════════════════════════╣");
        println!("║  Started at Unix timestamp: {:<38}║", now);
        println!("╚════════════════════════════════════════════════════════════════════╝");
        println!();

        // Security warnings
        if !self.tls_enabled {
            tracing::warn!("⚠️  TLS is disabled - credentials transmitted in plaintext!");
        }
        if self.auth_mode == "disabled" {
            tracing::warn!("⚠️  Authentication is disabled - anyone can access the catalog!");
        }
    }
}

/// Builder for startup diagnostics.
#[derive(Debug, Clone, Default)]
pub struct StartupDiagnosticsBuilder {
    inner: StartupDiagnostics,
}

impl StartupDiagnosticsBuilder {
    /// Sets the bind address.
    pub fn bind_address(mut self, addr: impl Into<String>) -> Self {
        self.inner.bind_address = addr.into();
        self
    }

    /// Sets the port.
    pub fn port(mut self, port: u16) -> Self {
        self.inner.port = port;
        self
    }

    /// Sets TLS enabled status.
    pub fn tls_enabled(mut self, enabled: bool) -> Self {
        self.inner.tls_enabled = enabled;
        self
    }

    /// Sets authentication mode.
    pub fn auth_mode(mut self, mode: impl Into<String>) -> Self {
        self.inner.auth_mode = mode.into();
        self
    }

    /// Sets storage backend.
    pub fn storage_backend(mut self, backend: impl Into<String>) -> Self {
        self.inner.storage_backend = backend.into();
        self
    }

    /// Sets warehouse location.
    pub fn warehouse_location(mut self, location: Option<String>) -> Self {
        self.inner.warehouse_location = location;
        self
    }

    /// Sets default tenant ID.
    pub fn default_tenant_id(mut self, tenant: impl Into<String>) -> Self {
        self.inner.default_tenant_id = tenant.into();
        self
    }

    /// Builds the diagnostics.
    pub fn build(self) -> StartupDiagnostics {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_diagnostics() {
        let diag = StartupDiagnostics::default();
        assert_eq!(diag.service_name, "Rustberg");
        assert_eq!(diag.bind_address, "0.0.0.0");
        assert_eq!(diag.port, 8000);
        assert!(!diag.tls_enabled);
    }

    #[test]
    fn test_diagnostics_builder() {
        let diag = StartupDiagnostics::builder()
            .bind_address("127.0.0.1")
            .port(9000)
            .tls_enabled(true)
            .auth_mode("api_key")
            .storage_backend("file:///var/lib/rustberg")
            .warehouse_location(Some("s3://bucket/warehouse".to_string()))
            .default_tenant_id("my-tenant")
            .build();

        assert_eq!(diag.bind_address, "127.0.0.1");
        assert_eq!(diag.port, 9000);
        assert!(diag.tls_enabled);
        assert_eq!(diag.auth_mode, "api_key");
        assert!(diag.storage_backend.starts_with("file://"));
        assert_eq!(
            diag.warehouse_location,
            Some("s3://bucket/warehouse".to_string())
        );
        assert_eq!(diag.default_tenant_id, "my-tenant");
    }

    #[test]
    fn test_print_banner_does_not_panic() {
        let diag = StartupDiagnostics::builder()
            .bind_address("0.0.0.0")
            .port(8000)
            .tls_enabled(false)
            .auth_mode("disabled")
            .build();

        // Just verify it doesn't panic - actual output goes to stdout
        diag.print_banner();
    }
}
