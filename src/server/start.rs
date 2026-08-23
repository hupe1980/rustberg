//! Server startup and TLS configuration.
//!
//! This module provides both HTTP and HTTPS server implementations
//! with graceful shutdown support.

use axum::Router;
use std::net::SocketAddr;
#[cfg(feature = "tls")]
use std::path::Path;
use tokio::net::TcpListener;
use tokio::signal;
use tracing::{info, warn};

/// Configuration for the Axum server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls: Option<TlsConfig>,
}

/// TLS configuration for HTTPS.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to the TLS certificate file (PEM format)
    pub cert_path: String,
    /// Path to the TLS private key file (PEM format)
    pub key_path: String,
}

impl ServerConfig {
    /// Returns the bind address as a `SocketAddr`.
    pub fn address(&self) -> Result<SocketAddr, std::net::AddrParseError> {
        Ok(SocketAddr::new(self.host.parse()?, self.port))
    }

    /// Creates a default HTTP server config (`0.0.0.0:8000`)
    pub fn default_http() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8000,
            tls: None,
        }
    }

    /// Creates a default HTTPS server config (`0.0.0.0:8443`)
    pub fn default_https(cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8443,
            tls: Some(TlsConfig {
                cert_path: cert_path.into(),
                key_path: key_path.into(),
            }),
        }
    }

    /// Checks if TLS is enabled.
    pub fn is_tls(&self) -> bool {
        self.tls.is_some()
    }
}

/// Starts the Axum server (HTTP or HTTPS based on config).
pub async fn start_server(
    app: Router,
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(tls_config) = &config.tls {
        #[cfg(feature = "tls")]
        {
            start_server_tls(app, &config, tls_config).await
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = tls_config;
            Err("TLS support not compiled in. Enable the 'tls' feature.".into())
        }
    } else {
        start_server_http(app, &config).await
    }
}

/// Starts an HTTP server (plaintext).
async fn start_server_http(
    app: Router,
    config: &ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = config.address()?;
    let listener = TcpListener::bind(addr).await?;

    warn!(
        "⚠️  Server starting at http://{} (PLAINTEXT - NOT SECURE)",
        addr
    );
    warn!("⚠️  Use --tls-cert and --tls-key for production deployments");

    // `ConnectInfo` must be supplied here, or the peer address never reaches the
    // request. Everything that identifies a caller by address depends on it:
    // per-IP rate limiting, auth-failure banning, `context.source_ip` in a
    // policy, and the client address in an audit record. Without it they do not
    // error — they silently do nothing.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(handle_shutdown_signal())
    .await?;

    info!("🛑 Server has shut down gracefully");

    Ok(())
}

/// Starts an HTTPS server with TLS.
#[cfg(feature = "tls")]
async fn start_server_tls(
    app: Router,
    config: &ServerConfig,
    tls_config: &TlsConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use axum_server::Handle;
    use axum_server::tls_rustls::RustlsConfig;

    // Install the ring crypto provider for rustls 0.23+
    // This must be done before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = config.address()?;

    // Load TLS configuration
    let rustls_config = RustlsConfig::from_pem_file(&tls_config.cert_path, &tls_config.key_path)
        .await
        .map_err(|e| format!("Failed to load TLS certificates: {}", e))?;

    info!("🔐 HTTPS server starting at https://{}", addr);
    info!("   Certificate: {}", tls_config.cert_path);
    info!("   Private key: {}", tls_config.key_path);

    // Create a handle for graceful shutdown
    let handle = Handle::new();
    let shutdown_handle = handle.clone();

    // Spawn shutdown listener
    tokio::spawn(async move {
        handle_shutdown_signal().await;
        info!("Initiating graceful shutdown...");
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    info!("🛑 Server has shut down gracefully");

    Ok(())
}

/// Waits for shutdown signals (`Ctrl+C` or `SIGTERM`).
async fn handle_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C signal");
            },
            _ = terminate.recv() => {
                info!("Received SIGTERM signal");
            },
        }
    }

    #[cfg(not(unix))]
    {
        // Only handle Ctrl+C on non-Unix platforms
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!("Failed to listen for Ctrl+C: {}", e);
        } else {
            info!("Received Ctrl+C");
        }
    }
}

/// Generates a self-signed TLS certificate for development/testing.
///
/// Returns (cert_pem, key_pem) as strings.
#[cfg(feature = "tls")]
pub fn generate_self_signed_cert(
    common_name: &str,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    use rcgen::{CertifiedKey, generate_simple_self_signed};

    let subject_alt_names = vec![common_name.to_string(), "localhost".to_string()];

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(subject_alt_names)?;

    Ok((cert.pem(), signing_key.serialize_pem()))
}

/// Writes a self-signed certificate and key to files.
#[cfg(feature = "tls")]
pub fn write_self_signed_cert(
    common_name: &str,
    cert_path: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_pem, key_pem) = generate_self_signed_cert(common_name)?;

    std::fs::write(&cert_path, cert_pem)?;
    std::fs::write(&key_path, key_pem)?;

    info!(
        "Generated self-signed certificate: {}",
        cert_path.as_ref().display()
    );
    info!("Generated private key: {}", key_path.as_ref().display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_address() {
        let config = ServerConfig::default_http();
        let addr = config.address().unwrap();
        assert_eq!(addr.port(), 8000);
    }

    #[test]
    fn test_tls_detection() {
        let http_config = ServerConfig::default_http();
        assert!(!http_config.is_tls());

        let https_config = ServerConfig::default_https("cert.pem", "key.pem");
        assert!(https_config.is_tls());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_generate_self_signed_cert() {
        let (cert, key) = generate_self_signed_cert("test.local").unwrap();
        assert!(cert.contains("BEGIN CERTIFICATE"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }
}
