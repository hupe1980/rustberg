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
    /// How long to keep serving after `SIGTERM` before draining.
    ///
    /// Zero begins the drain immediately, which is right wherever nothing routes
    /// to this process but whoever started it. Behind a load balancer, taking an
    /// instance out of rotation takes time to propagate and requests arriving in
    /// that window would be refused, so a few seconds covers it. Applies to
    /// `SIGTERM` only, never to `Ctrl+C`.
    pub shutdown_delay: std::time::Duration,
}

/// How long a drain waits for in-flight requests before closing the rest.
///
/// Both transports, because where TLS is terminated is not something a
/// deployment should have to know to predict how it drains — and the plaintext
/// path is the one behind a proxy.
///
/// Comfortably over the request timeout, so a request that is going to finish
/// has.
const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
            shutdown_delay: std::time::Duration::ZERO,
        }
    }

    /// Sets how long to keep serving after `SIGTERM` before draining.
    #[must_use]
    pub fn with_shutdown_delay(mut self, delay: std::time::Duration) -> Self {
        self.shutdown_delay = delay;
        self
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
            shutdown_delay: std::time::Duration::ZERO,
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
    // `axum::serve`'s graceful shutdown waits for in-flight connections with no
    // deadline of its own, so the drain is bounded here: the shutdown future
    // signals when it fires, and the timer starts from that point rather than
    // from process start.
    //
    // The same bound the TLS path gets from `Handle::graceful_shutdown`. Where
    // TLS is terminated should not change how a deployment drains, and the
    // plaintext path is the one behind a proxy.
    let (draining, drained) = tokio::sync::oneshot::channel();
    let delay = config.shutdown_delay;

    let serve = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        wait_for_shutdown(delay).await;
        // The receiver is dropped once serving ends, so a send that fails means
        // there is nothing left to time out.
        let _ = draining.send(());
    });

    tokio::select! {
        result = serve => result?,
        () = async move {
            if drained.await.is_ok() {
                tokio::time::sleep(DRAIN_TIMEOUT).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            warn!(
                seconds = DRAIN_TIMEOUT.as_secs(),
                "Connections were still open when the drain ran out; closing them"
            );
        }
    }

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
    let delay = config.shutdown_delay;
    tokio::spawn(async move {
        wait_for_shutdown(delay).await;
        info!("Initiating graceful shutdown...");
        shutdown_handle.graceful_shutdown(Some(DRAIN_TIMEOUT));
    });

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    info!("🛑 Server has shut down gracefully");

    Ok(())
}

/// Waits for shutdown signals (`Ctrl+C` or `SIGTERM`).
/// Waits for a shutdown signal, then holds the door open for `delay`.
///
/// # Why the wait is here and not in a `preStop` hook
///
/// Kubernetes removes a pod from its Service's endpoints and sends it `SIGTERM`
/// concurrently, and the removal has to reach every kube-proxy and ingress
/// before they stop routing to it. A server that stops accepting the instant it
/// is signalled refuses whatever arrives in that window, which clients see as
/// connection errors on every rolling update.
///
/// The usual answer is a `preStop` hook that sleeps, and it cannot work here:
/// the runtime image is distroless, so there is no shell to run `sleep` in.
/// In-process is better regardless — it does not depend on the orchestrator, and
/// it is one number rather than two that have to be kept in step.
///
/// **`SIGTERM` only.** `Ctrl+C` is a person who wants this to stop now, not an
/// orchestrator taking it out of rotation, and making them wait through a drain
/// that protects nothing is the wrong trade.
async fn wait_for_shutdown(delay: std::time::Duration) {
    let signal = handle_shutdown_signal().await;

    if signal == Signal::Terminate && !delay.is_zero() {
        info!(
            seconds = delay.as_secs(),
            "SIGTERM received; still serving while this instance is taken out of rotation"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Which signal asked for the shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Signal {
    /// An orchestrator taking this instance out of rotation.
    Terminate,
    /// A person at a terminal.
    Interrupt,
}

async fn handle_shutdown_signal() -> Signal {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received Ctrl+C signal");
                Signal::Interrupt
            },
            _ = terminate.recv() => {
                info!("Received SIGTERM signal");
                Signal::Terminate
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
        Signal::Interrupt
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
