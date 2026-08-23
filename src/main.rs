//! Rustberg - Apache Iceberg REST Catalog Server
//!
//! A production-grade, single-binary Iceberg catalog server written in Rust.

use clap::{Parser, Subcommand};
use rustberg::auth::{ApiKeyBuilder, ApiKeyStore, Auditor, InMemoryApiKeyStore};
use rustberg::server::{ServerConfig, TlsConfig};
use rustberg::{App, start_server};
use std::path::PathBuf;
use std::sync::Arc;

/// Rustberg - Apache Iceberg REST Catalog
#[derive(Parser)]
#[command(name = "rustberg")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to configuration file (TOML)
    #[arg(short, long, env = "RUSTBERG_CONFIG")]
    config: Option<PathBuf>,

    /// Server bind address
    ///
    /// No `default_value`, deliberately: clap cannot tell "not passed" from
    /// "passed the default", so a default here silently outranks the
    /// configuration file. The default is applied in [`bind_address`] instead.
    #[arg(long, env = "RUSTBERG_HOST")]
    host: Option<String>,

    /// Server bind port
    #[arg(short, long, env = "RUSTBERG_PORT")]
    port: Option<u16>,

    /// Warehouse location for table storage
    #[arg(short, long, env = "RUSTBERG_WAREHOUSE")]
    warehouse: Option<String>,

    /// Where the catalog database lives: `file:///path`, `postgres://…`, or
    /// `memory://`.
    ///
    /// `file://` is an embedded redb file — one process, since redb holds an
    /// exclusive lock. `postgres://` is what multiple replicas share. Never an
    /// object-store URL: that is the *warehouse*, which is a separate setting.
    ///
    /// Required unless supplied in a config file or running with --dev.
    #[arg(long, env = "RUSTBERG_CATALOG_URL")]
    catalog_url: Option<String>,

    /// Default tenant ID
    #[arg(short, long, env = "RUSTBERG_TENANT_ID", default_value = "default")]
    tenant_id: String,

    /// Disable authentication (NOT RECOMMENDED - for development only)
    /// Authentication is enabled by default for security.
    #[arg(long, env = "RUSTBERG_NO_AUTH")]
    no_auth: bool,

    /// Enable development mode - relaxes security requirements
    /// Allows: wildcard CORS origins, self-signed TLS, insecure HTTP
    /// Production mode (default) requires: explicit CORS origins, proper TLS
    #[arg(long, env = "RUSTBERG_DEV")]
    dev: bool,

    /// Log level
    #[arg(long, env = "RUST_LOG", default_value = DEFAULT_LOG_LEVEL)]
    log_level: String,

    // =========================================================================
    // TLS Configuration
    // =========================================================================
    /// Path to TLS certificate file (PEM format)
    #[arg(long, env = "RUSTBERG_TLS_CERT")]
    tls_cert: Option<String>,

    /// Path to TLS private key file (PEM format)
    #[arg(long, env = "RUSTBERG_TLS_KEY")]
    tls_key: Option<String>,

    /// Allow insecure HTTP connections (required if no TLS configured)
    #[arg(long, env = "RUSTBERG_INSECURE_HTTP")]
    insecure_http: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new API key
    GenerateKey {
        /// Name for the API key
        #[arg(short, long)]
        name: String,

        /// Tenant ID for the key
        #[arg(short, long, default_value = "default")]
        tenant: String,

        /// Roles to assign (comma-separated)
        #[arg(short, long, default_value = "reader,writer")]
        roles: String,

        /// Description of the key
        #[arg(short, long)]
        description: Option<String>,
    },

    /// Generate a self-signed TLS certificate for development
    #[cfg(feature = "tls")]
    GenerateCert {
        /// Common name for the certificate
        #[arg(short, long, default_value = "localhost")]
        common_name: String,

        /// Output directory for cert and key files
        #[arg(short, long, default_value = ".")]
        output_dir: String,
    },

    /// Generate a sample configuration file
    GenerateConfig {
        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Create a backup of the catalog database
    Backup {
        /// Output file path for the backup
        #[arg(short, long)]
        output: String,

        /// Catalog data directory to backup
        #[arg(short, long, default_value = "/var/lib/rustberg/data")]
        data_dir: String,

        /// Compress the backup with gzip
        #[arg(long, default_value = "true")]
        compress: bool,
    },

    /// Restore a catalog database from backup
    Restore {
        /// Input backup file path
        #[arg(short, long)]
        input: String,

        /// Target catalog data directory
        #[arg(short, long, default_value = "/var/lib/rustberg/data")]
        data_dir: String,

        /// Force restore even if target directory exists
        #[arg(long)]
        force: bool,
    },

    /// Validate a backup file without restoring
    ValidateBackup {
        /// Backup file to validate
        #[arg(short, long)]
        input: String,
    },

    /// Show catalog statistics and health
    Status {
        /// Catalog data directory
        #[arg(short, long, default_value = "/var/lib/rustberg/data")]
        data_dir: String,
    },

    /// Run startup/performance benchmarks
    Benchmark {
        /// Number of iterations
        #[arg(short, long, default_value = "10")]
        iterations: u32,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // The configuration file is read *before* logging is initialised, because
    // `[logging]` lives in it and a subscriber cannot be replaced once it is
    // installed. So the outcome is held and reported one step later — the two
    // lines below are the only place in this binary where something happens
    // before there is anywhere to log it.
    let loaded_config = cli.config.as_ref().map(|path| {
        (
            path.clone(),
            rustberg::config::RustbergConfig::from_file(path),
        )
    });

    let logging = loaded_config
        .as_ref()
        .and_then(|(_, result)| result.as_ref().ok())
        .map(|config| config.logging.clone())
        .unwrap_or_default();

    init_logging(&logging, &cli.log_level);

    let file_config = match loaded_config {
        None => None,
        Some((path, Ok(config))) => {
            tracing::info!(path = %path.display(), "Loaded configuration from file");
            Some(config)
        }
        Some((path, Err(e))) => {
            tracing::error!(error = %e, path = %path.display(), "Failed to load configuration file");
            std::process::exit(1);
        }
    };

    // Object-store configuration, before any catalog opens. A `FileIO` captures
    // these when it is built, so setting them afterwards would configure nothing
    // that had already started.
    if let Some(config) = file_config.as_ref() {
        match config.storage.resolved_properties() {
            Ok(props) if props.is_empty() => {}
            Ok(props) => {
                let keys: Vec<&String> = props.keys().collect();
                // Names only. A value here can be an access key.
                tracing::info!(properties = ?keys, "Configured object storage");
                rustberg::catalog::file_io::set_storage_properties(props);
            }
            Err(e) => {
                tracing::error!("❌ Failed to start: {e}");
                std::process::exit(1);
            }
        }
    }

    // Handle subcommands
    if let Some(command) = cli.command {
        match command {
            Commands::GenerateKey {
                name,
                tenant,
                roles,
                description,
            } => {
                generate_api_key(&name, &tenant, &roles, description.as_deref());
                return;
            }
            #[cfg(feature = "tls")]
            Commands::GenerateCert {
                common_name,
                output_dir,
            } => {
                generate_certificate(&common_name, &output_dir);
                return;
            }
            Commands::GenerateConfig { output } => {
                generate_config(output.as_deref());
                return;
            }
            Commands::Backup {
                output,
                data_dir,
                compress,
            } => {
                backup_catalog(&data_dir, &output, compress);
                return;
            }
            Commands::Restore {
                input,
                data_dir,
                force,
            } => {
                restore_catalog(&input, &data_dir, force);
                return;
            }
            Commands::ValidateBackup { input } => {
                validate_backup(&input);
                return;
            }
            Commands::Status { data_dir } => {
                show_status(&data_dir);
                return;
            }
            Commands::Benchmark { iterations } => {
                run_benchmarks(iterations).await;
                return;
            }
        }
    }

    // Security validation (secure by default)
    let cors_config = file_config.as_ref().map(|c| &c.server.cors);
    // Only an explicit `*` counts. With no config file there is no CORS policy
    // at all, which permits no origin — so the default configuration starts in
    // the default mode.
    let has_wildcard_cors = cors_config
        .map(|c| c.allowed_origins.iter().any(|o| o == "*"))
        .unwrap_or(false);

    if cli.dev {
        tracing::warn!("⚠️  Running in DEVELOPMENT mode - security requirements relaxed");

        if has_wildcard_cors {
            tracing::warn!("   CORS allows all origins (\"*\")");
        }
        if cli.no_auth {
            tracing::warn!("   Authentication DISABLED");
        }
        if cli.insecure_http {
            tracing::warn!("   Running over insecure HTTP");
        }
    } else {
        // Production mode (default) - enforce security
        tracing::info!("🔒 Running in PRODUCTION mode (default) - enforcing security requirements");

        // Check CORS configuration
        if has_wildcard_cors {
            tracing::error!("❌ CORS allows all origins (\"*\") - not allowed in production");
            tracing::error!("   Configure server.cors.allowed_origins in your config file");
            tracing::error!("   Example: allowed_origins = [\"https://your-domain.com\"]");
            tracing::error!("   Use --dev to bypass this check for local development");
            std::process::exit(1);
        }

        // Check authentication
        if cli.no_auth {
            tracing::error!("❌ --no-auth is not allowed in production mode");
            tracing::error!("   Use --dev to bypass this check for local development");
            std::process::exit(1);
        }

        // Warn if no TLS but allow it (may be behind load balancer)
        if cli.insecure_http {
            tracing::warn!("⚠️  Running without TLS - ensure TLS termination at load balancer");
        }

        tracing::info!("✅ Security checks passed");
    }

    // Resolve where the catalog lives. CLI wins over the config file; if neither
    // names a location the server has nowhere durable to write, which is a
    // startup error rather than a silent temp directory that discards every
    // table on restart. --dev opts into the ephemeral catalog explicitly.
    let catalog_url: Option<String> = cli
        .catalog_url
        .clone()
        .or_else(|| file_config.as_ref().map(|c| c.storage.catalog_url.clone()));

    if catalog_url.is_none() && !cli.dev {
        tracing::error!("❌ No catalog location configured");
        tracing::error!(
            "   Set --catalog-url file:///var/lib/rustberg/data (or RUSTBERG_CATALOG_URL),"
        );
        tracing::error!("   or storage.catalog_url in a config file.");
        tracing::error!("   Use --dev for an ephemeral catalog discarded on shutdown.");
        std::process::exit(1);
    }

    // Validate TLS configuration
    let tls_config = match (&cli.tls_cert, &cli.tls_key) {
        (Some(cert), Some(key)) => {
            // TLS enabled with provided certificates
            Some(TlsConfig {
                cert_path: cert.clone(),
                key_path: key.clone(),
            })
        }
        (None, None) => {
            // No TLS configured
            if cli.insecure_http {
                tracing::warn!(
                    "⚠️  Running in INSECURE HTTP mode - credentials will be transmitted in plaintext!"
                );
                tracing::warn!("⚠️  This is NOT suitable for production!");
                None
            } else {
                // Auto-generate self-signed certificate for development
                #[cfg(feature = "tls")]
                {
                    tracing::info!(
                        "🔐 No TLS certificate provided - generating self-signed certificate for development"
                    );
                    match generate_dev_certificate(&bind_host(
                        cli.host.as_deref(),
                        file_config.as_ref(),
                    )) {
                        Ok(config) => {
                            tracing::warn!("⚠️  Using auto-generated self-signed certificate");
                            tracing::warn!(
                                "⚠️  This is for DEVELOPMENT ONLY - use proper certificates in production!"
                            );
                            Some(config)
                        }
                        Err(e) => {
                            tracing::error!("Failed to generate self-signed certificate: {}", e);
                            tracing::error!(
                                "Use --insecure-http to run without TLS (not recommended)"
                            );
                            std::process::exit(1);
                        }
                    }
                }
                #[cfg(not(feature = "tls"))]
                {
                    tracing::error!(
                        "TLS feature not enabled. Use --insecure-http or rebuild with --features tls"
                    );
                    std::process::exit(1);
                }
            }
        }
        _ => {
            tracing::error!("Both --tls-cert and --tls-key must be provided together");
            std::process::exit(1);
        }
    };

    // Build the application
    // Authentication is ENABLED BY DEFAULT for security
    let app = if cli.no_auth {
        tracing::warn!("⚠️  Authentication DISABLED via --no-auth - NOT SUITABLE FOR PRODUCTION!");
        tracing::warn!("⚠️  Any client can access and modify all catalogs without credentials.");

        let mut builder = App::builder()
            .with_default_tenant_id(&cli.tenant_id)
            .with_auditor(build_auditor(file_config.as_ref().map(|c| &c.audit)));
        if let Some(ref url) = catalog_url {
            builder = builder.with_catalog_url(url);
        }

        builder = apply_shared_config(builder, file_config.as_ref(), cli.warehouse.as_deref());
        builder = builder.with_mounts(build_mounts(file_config.as_ref()).await);

        // Use async variant to avoid nested runtime when TLS is enabled
        match builder.build().await {
            Ok(app) => app,
            Err(e) => {
                tracing::error!("❌ Failed to start: {e}");
                std::process::exit(1);
            }
        }
    } else {
        tracing::info!("Starting with authentication enabled (default)");

        // Create app with API key auth (use async variant to avoid nested runtime)
        let (app, api_key_store) = {
            let mut builder = App::builder()
                .with_default_tenant_id(&cli.tenant_id)
                .with_auditor(build_auditor(file_config.as_ref().map(|c| &c.audit)));
            if let Some(ref url) = catalog_url {
                builder = builder.with_catalog_url(url);
            }

            builder = apply_shared_config(builder, file_config.as_ref(), cli.warehouse.as_deref());
            builder = builder.with_mounts(build_mounts(file_config.as_ref()).await);

            // Apply configuration from file if loaded
            if let Some(ref config) = file_config {
                // JWT configuration if enabled
                if config.server.auth.jwt_enabled
                    && let Some(ref jwt_serde) = config.server.auth.jwt
                {
                    if let Some(ref uri) = jwt_serde.oauth2_server_uri {
                        builder = builder.with_oauth2_server_uri(uri);
                    }
                    builder = builder.with_jwt_config(jwt_serde.clone().into());
                }

                // Cedar policies. A policy file replaces the built-in defaults.
                if let Some(ref path) = config.server.auth.policy_file {
                    let policies = std::fs::read_to_string(path).unwrap_or_else(|e| {
                        panic!("Failed to read policy file {}: {e}", path.display())
                    });
                    builder = builder.with_policies(policies);
                }

                // API keys. Each secret is read from its environment variable;
                // a missing one is fatal rather than a silently absent key.
                let keys: Vec<_> = config
                    .server
                    .auth
                    .api_keys
                    .iter()
                    .map(|k| {
                        k.to_api_key()
                            .unwrap_or_else(|e| panic!("Invalid API key configuration: {e}"))
                    })
                    .collect();

                if !keys.is_empty() {
                    tracing::info!(count = keys.len(), "Loaded API keys from configuration");
                    builder = builder.with_api_keys(keys);
                }
            }

            // CLI overrides take precedence
            if let Some(warehouse) = cli.warehouse.as_ref() {
                builder = builder.with_warehouse_location(warehouse);
            }

            match builder.build_with_api_keys().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!("❌ Failed to start: {e}");
                    std::process::exit(1);
                }
            }
        };

        // With authentication on and nothing configured to authenticate against,
        // the server would answer 401 to every request. Mint one admin key so a
        // bare `rustberg serve` is usable, and say so loudly.
        let oidc_configured = file_config
            .as_ref()
            .is_some_and(|c| c.server.auth.jwt_enabled && c.server.auth.jwt.is_some());
        let keys_configured = file_config
            .as_ref()
            .is_some_and(|c| !c.server.auth.api_keys.is_empty());

        if !keys_configured && !oidc_configured {
            let persistent = catalog_url.as_deref().is_some_and(|url| url != "memory://");
            // The address this server is actually about to listen on, so the
            // printed `curl` is one a reader can paste — a hardcoded
            // `localhost:8000` is wrong for anything with `--port` or TLS.
            let (host, port) = bind_address(cli.host.as_deref(), cli.port, file_config.as_ref());
            let base = quickstart_base_url(&host, port, tls_config.is_some());
            bootstrap_admin_key(&api_key_store, &cli.tenant_id, persistent, &base).await;
        }

        app
    };

    let (host, port) = bind_address(cli.host.as_deref(), cli.port, file_config.as_ref());
    let server_config = ServerConfig {
        host,
        port,
        tls: tls_config,
    };

    // Start the server
    if let Err(e) = start_server(app.into_router(), server_config).await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

/// Where to listen: the flag if given, then the file, then the built-in default.
///
/// One resolution for both halves, and one place the default lives. Two
/// defaults for one setting — one on the clap argument and one on the serde
/// field — lets `[server] host` and `port` be parsed from the file and then
/// overridden by a flag nobody passed.
fn bind_address(
    cli_host: Option<&str>,
    cli_port: Option<u16>,
    file: Option<&rustberg::config::RustbergConfig>,
) -> (String, u16) {
    let host = bind_host(cli_host, file);
    let port = cli_port
        .or_else(|| file.map(|config| config.server.port))
        .unwrap_or(DEFAULT_PORT);
    (host, port)
}

/// The host half, which the TLS certificate generator also needs.
fn bind_host(cli_host: Option<&str>, file: Option<&rustberg::config::RustbergConfig>) -> String {
    cli_host
        .map(str::to_string)
        .or_else(|| file.map(|config| config.server.host.clone()))
        .unwrap_or_else(|| DEFAULT_HOST.to_string())
}

/// Builds the audit sink from configuration.
///
/// A sink that cannot be opened is fatal. A deployment that asked for an audit
/// file and did not get one would otherwise serve unaudited while believing it
/// had a trail.
/// Applies the settings both startup paths share.
///
/// Authenticated and `--no-auth` startups differ only in how a caller is
/// identified; warehouse, rate limiting, CORS and credential vending are the
/// same either way. Applying them twice in near-identical blocks leaves a
/// setting added to one branch simply missing from the other.
///
/// `cli_warehouse` is applied last because a command-line flag overrides the
/// file.
fn apply_shared_config(
    mut builder: rustberg::AppBuilder,
    file_config: Option<&rustberg::config::RustbergConfig>,
    cli_warehouse: Option<&str>,
) -> rustberg::AppBuilder {
    if let Some(config) = file_config {
        if let Some(ref warehouse) = config.storage.warehouse_location {
            builder = builder.with_warehouse_location(warehouse);
        }
        if let Some(rate_config) =
            rustberg::auth::RateLimitConfig::from_file_config(&config.rate_limit)
        {
            builder = builder.with_rate_limit_config(rate_config);
        }
        builder = builder.with_cors_config(config.server.cors.clone());
        builder = builder.with_credentials_config(config.credentials.clone());
    }

    if let Some(warehouse) = cli_warehouse {
        builder = builder.with_warehouse_location(warehouse);
    }

    builder
}

/// Opens every configured mount, in a stable order.
///
/// A mount that cannot be opened is a startup failure rather than a namespace
/// subtree that silently does not exist.
async fn build_mounts(
    file_config: Option<&rustberg::config::RustbergConfig>,
) -> Vec<rustberg::catalog::Mount> {
    let Some(config) = file_config else {
        return Vec::new();
    };

    // Sorted so startup logs and error messages are reproducible.
    let mut names: Vec<&String> = config.mount.keys().collect();
    names.sort();

    let mut mounts = Vec::with_capacity(names.len());
    for name in names {
        match rustberg::AppBuilder::build_mount(name, &config.mount[name]).await {
            Ok(mount) => mounts.push(mount),
            Err(e) => {
                tracing::error!("❌ Failed to start: {e}");
                std::process::exit(1);
            }
        }
    }

    mounts
}

fn build_auditor(config: Option<&rustberg::config::AuditConfig>) -> Arc<Auditor> {
    let Some(config) = config else {
        return Arc::new(Auditor::stdout());
    };

    let sink: Box<dyn rustberg::auth::AuditSink> = match config.sink.as_str() {
        "stdout" => Box::new(rustberg::auth::StdoutSink),
        "none" => {
            tracing::warn!("Audit trail disabled: authorization decisions will not be recorded");
            Box::new(rustberg::auth::NullSink)
        }
        "file" => {
            let Some(path) = config.path.as_ref() else {
                tracing::error!("❌ audit.sink = \"file\" requires audit.path");
                std::process::exit(1);
            };
            match rustberg::auth::FileSink::open(path) {
                Ok(sink) => Box::new(sink),
                Err(e) => {
                    tracing::error!("❌ Cannot open audit file {}: {e}", path.display());
                    std::process::exit(1);
                }
            }
        }
        other => {
            tracing::error!("❌ Unknown audit.sink '{other}'; expected stdout, file or none");
            std::process::exit(1);
        }
    };

    let auditor = Auditor::new(sink, config.fail_closed);
    tracing::info!("Audit: {}", auditor.describe());
    Arc::new(auditor)
}

/// Installs the tracing subscriber from `[logging]`, with `--log-level` on top.
///
/// # Application logs go to stderr
///
/// The audit trail is JSON Lines on **stdout**, so `rustberg | jq` has to be a
/// stream of records and nothing else. `tracing_subscriber::fmt()` defaults to
/// stdout, so the subscriber is pointed at stderr explicitly — where a
/// diagnostic belongs anyway. Getting it wrong is invisible from inside the
/// server and shows up only in whatever consumes the trail.
///
/// # Precedence
///
/// `--log-level`/`RUST_LOG` wins over the file when it was actually supplied,
/// and the file wins over the built-in default. Clap cannot distinguish "not
/// passed" from "passed the default value", so the comparison against the
/// default is what makes the file's setting reachable at all.
fn init_logging(config: &rustberg::config::LoggingConfig, cli_level: &str) {
    use tracing_subscriber::{EnvFilter, fmt};

    let directive = if cli_level == DEFAULT_LOG_LEVEL {
        config.level.as_str()
    } else {
        cli_level
    };

    // `EnvFilter` rather than a bare level, so `RUST_LOG=rustberg=debug,hyper=warn`
    // — the syntax every Rust operator already knows — works. A directive that
    // does not parse falls back to `info` and says so, because silently serving
    // at the wrong verbosity is how a diagnostic session goes in circles.
    let filter = EnvFilter::try_new(directive).unwrap_or_else(|e| {
        eprintln!("Invalid log filter '{directive}' ({e}); falling back to 'info'");
        EnvFilter::new(DEFAULT_LOG_LEVEL)
    });

    let span_events = if config.with_span_events {
        fmt::format::FmtSpan::NEW | fmt::format::FmtSpan::CLOSE
    } else {
        fmt::format::FmtSpan::NONE
    };

    let builder = fmt()
        .with_env_filter(filter)
        .with_span_events(span_events)
        .with_writer(std::io::stderr);

    if config.json_format {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// The `--log-level` default, and the fallback for an unparseable filter.
/// Bind address when neither a flag nor the configuration file names one.
const DEFAULT_HOST: &str = "0.0.0.0";

/// Bind port when neither a flag nor the configuration file names one.
const DEFAULT_PORT: u16 = 8000;

const DEFAULT_LOG_LEVEL: &str = "info";

/// Generates a new API key and prints it.
fn generate_api_key(name: &str, tenant: &str, roles_str: &str, description: Option<&str>) {
    let roles: Vec<String> = roles_str.split(',').map(|s| s.trim().to_string()).collect();

    let mut builder = ApiKeyBuilder::new(name, tenant).with_roles(roles);

    if let Some(desc) = description {
        builder = builder.with_description(desc);
    }

    let (key, plaintext) = builder.build();

    println!("\n✅ API Key Generated Successfully");
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│ IMPORTANT: Save this key securely!                     │");
    println!("│ It will NOT be shown again.                            │");
    println!("└─────────────────────────────────────────────────────────┘\n");
    println!("API Key:     {}", plaintext.as_str());
    println!("Name:        {}", key.name);
    println!("Tenant:      {}", key.tenant_id);
    println!("Roles:       {:?}", key.roles);
    println!("ID:          {}", key.id);
    if let Some(desc) = key.description {
        println!("Description: {}", desc);
    }
    println!("\n⚠️  Store this key in your environment as:");
    println!("   export X_API_KEY=\"{}\"", plaintext.as_str());
    println!();
    println!("🔒 Security reminder: clear your shell history to avoid leaking the key:");
    println!("   history -d $(history 1 | awk '{{print $1}}')   # bash");
    println!("   fc -W                                         # zsh");
    println!();
}

/// Generates a self-signed TLS certificate.
#[cfg(feature = "tls")]
fn generate_certificate(common_name: &str, output_dir: &str) {
    use std::path::Path;

    let cert_path = Path::new(output_dir).join("server.crt");
    let key_path = Path::new(output_dir).join("server.key");

    match rustberg::server::write_self_signed_cert(common_name, &cert_path, &key_path) {
        Ok(()) => {
            println!("\n✅ Self-signed TLS Certificate Generated");
            println!("┌─────────────────────────────────────────────────────────┐");
            println!("│ WARNING: Self-signed certificates are for DEVELOPMENT  │");
            println!("│ Use properly signed certificates in production!        │");
            println!("└─────────────────────────────────────────────────────────┘\n");
            println!("Certificate: {}", cert_path.display());
            println!("Private Key: {}", key_path.display());
            println!("\n🚀 Start server with:");
            println!(
                "   rustberg --tls-cert {} --tls-key {}\n",
                cert_path.display(),
                key_path.display()
            );
        }
        Err(e) => {
            eprintln!("❌ Failed to generate certificate: {}", e);
            std::process::exit(1);
        }
    }
}

/// Generates a self-signed TLS certificate for development and returns TlsConfig.
/// Writes temporary cert/key files to a temp directory.
#[cfg(feature = "tls")]
fn generate_dev_certificate(host: &str) -> Result<TlsConfig, String> {
    // Create a temporary directory for the certificates
    let temp_dir = std::env::temp_dir().join("rustberg_tls");
    std::fs::create_dir_all(&temp_dir).map_err(|e| format!("Failed to create temp dir: {}", e))?;

    let cert_path = temp_dir.join("dev_server.crt");
    let key_path = temp_dir.join("dev_server.key");

    // Determine the common name - use localhost if binding to 0.0.0.0 or 127.0.0.1
    let common_name = if host == "0.0.0.0" || host == "127.0.0.1" {
        "localhost"
    } else {
        host
    };

    rustberg::server::write_self_signed_cert(common_name, &cert_path, &key_path)
        .map_err(|e| format!("Failed to generate certificate: {}", e))?;

    Ok(TlsConfig {
        cert_path: cert_path.to_string_lossy().to_string(),
        key_path: key_path.to_string_lossy().to_string(),
    })
}

/// Generates a sample configuration file.
fn generate_config(output: Option<&std::path::Path>) {
    use rustberg::config::RustbergConfig;

    let sample = RustbergConfig::sample();

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &sample) {
                eprintln!("❌ Failed to write config: {}", e);
                std::process::exit(1);
            }
            println!("✅ Sample configuration written to: {}", path.display());
            println!("\nEdit the file and start with:");
            println!("   rustberg --config {}", path.display());
        }
        None => {
            println!("{}", sample);
        }
    }
}

/// Mints a single admin key when a deployment has no other way in.
///
/// # Why this exists
///
/// Authentication is on by default, which is right. But a `rustberg serve` with
/// no configuration file then had *no* accepted credential, so the server came up
/// and answered `401` to every request — including `/v1/config`, the first call
/// every Iceberg client makes. Nothing was broken and nothing worked, which is
/// the worst of both: an operator's first experience was an unusable server with
/// no message explaining why.
///
/// The alternatives were to refuse to start, or to default to no authentication.
/// Refusing to start makes the quickstart a two-step, and defaulting to open
/// authentication is how a development shortcut reaches production. Minting one
/// key and printing it keeps the server secure *and* usable in one command, and
/// the key's existence is impossible to miss in the log.
///
/// It is only ever called when nothing else is configured — a config file with
/// API keys, or OIDC, suppresses it entirely.
/// The base URL a reader can paste, given what this process is about to serve.
///
/// A wildcard bind address is rendered as `localhost`: `0.0.0.0` is a valid
/// thing to listen on and not a valid thing to connect to, and printing it sends
/// the reader to a URL that does not work.
fn quickstart_base_url(host: &str, port: u16, tls: bool) -> String {
    let scheme = if tls { "https" } else { "http" };
    let host = match host {
        "0.0.0.0" | "::" | "[::]" => "localhost",
        // A bare IPv6 address needs brackets in a URL.
        other if other.contains(':') => return format!("{scheme}://[{other}]:{port}"),
        other => other,
    };
    format!("{scheme}://{host}:{port}")
}

async fn bootstrap_admin_key(
    store: &Arc<InMemoryApiKeyStore>,
    tenant_id: &str,
    persistent: bool,
    base_url: &str,
) {
    let (key, plaintext) = ApiKeyBuilder::new("bootstrap-admin", tenant_id)
        .with_role("admin")
        .with_description("Auto-generated because no credentials were configured")
        .build();

    if let Err(e) = store.store(key).await {
        tracing::error!("Failed to mint the bootstrap admin key: {e}");
        return;
    }

    tracing::warn!("No API keys or OIDC configured — minted a temporary admin key.");
    tracing::warn!("");
    tracing::warn!("    X-API-Key: {}", plaintext.as_str());
    tracing::warn!("");
    tracing::warn!(
        "    curl -H 'X-API-Key: {}' {base_url}/v1/config",
        plaintext.as_str()
    );
    tracing::warn!("");
    // Keys are configuration rather than state, so this one lives only in memory
    // and a restart mints a different one. Worth saying plainly: a client
    // configured with this key stops working after a restart, which looks like a
    // bug if you were not told.
    tracing::warn!("This key is held in memory only. Restarting mints a new one and");
    tracing::warn!("invalidates this one.");
    if persistent {
        // The catalog survives restarts but the key does not, so the mismatch is
        // more surprising here than in the fully ephemeral case.
        tracing::warn!("");
        tracing::warn!("The catalog is persistent but this credential is not. Configure");
        tracing::warn!("`[[server.auth.api_keys]]` or OIDC before relying on this deployment.");
    }
}

// ============================================================================
// Backup & Restore Commands
// ============================================================================

/// Creates a backup of the catalog.
/// Archives the catalog directory.
///
/// # Consistency
///
/// This copies files as they are on disk. redb commits are atomic, so a copy
/// taken while the server is running captures a valid *past* state rather than a
/// corrupt one — but it may miss commits made during the copy. For a backup that
/// is exactly a known point in time, stop the server first; the deployment is
/// single-writer anyway, so that is a short window.
fn backup_catalog(data_dir: &str, output: &str, compress: bool) {
    use std::fs::{self, File};
    use std::io::{BufWriter, Write};
    use std::path::Path;
    use std::time::SystemTime;

    let data_path = Path::new(data_dir);
    let output_path = Path::new(output);

    // Verify source exists
    if !data_path.exists() {
        eprintln!("❌ Data directory does not exist: {}", data_dir);
        std::process::exit(1);
    }

    // Create output directory if needed
    if let Some(parent) = output_path.parent()
        && !parent.exists()
        && let Err(e) = fs::create_dir_all(parent)
    {
        eprintln!("❌ Failed to create output directory: {}", e);
        std::process::exit(1);
    }

    println!("📦 Creating backup...");
    println!("   Source: {}", data_dir);
    println!("   Output: {}", output);

    // Create tar archive
    let file = match File::create(output_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to create output file: {}", e);
            std::process::exit(1);
        }
    };

    let writer: Box<dyn Write> = if compress {
        println!("   Compression: gzip");
        Box::new(flate2::write::GzEncoder::new(
            BufWriter::new(file),
            flate2::Compression::default(),
        ))
    } else {
        Box::new(BufWriter::new(file))
    };

    let mut archive = tar::Builder::new(writer);

    // Add all files from data directory
    if let Err(e) = archive.append_dir_all("data", data_path) {
        eprintln!("❌ Failed to create archive: {}", e);
        std::process::exit(1);
    }

    // Finish archive
    if let Err(e) = archive.finish() {
        eprintln!("❌ Failed to finalize archive: {}", e);
        std::process::exit(1);
    }

    // Get file size
    let metadata = fs::metadata(output_path).ok();
    let size = metadata.map(|m| m.len()).unwrap_or(0);

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("\n✅ Backup completed successfully!");
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│ Backup Summary                                         │");
    println!("├─────────────────────────────────────────────────────────┤");
    println!("│ File:      {:<44}│", output);
    println!("│ Size:      {:<44}│", format_bytes(size));
    println!("│ Timestamp: {:<44}│", timestamp);
    println!("└─────────────────────────────────────────────────────────┘");
    println!("\n💡 To restore: rustberg restore --input {}", output);
}

/// Restores a catalog from backup.
fn restore_catalog(input: &str, data_dir: &str, force: bool) {
    use std::fs::{self, File};
    use std::io::BufReader;
    use std::path::Path;

    let input_path = Path::new(input);
    let data_path = Path::new(data_dir);

    // Verify backup exists
    if !input_path.exists() {
        eprintln!("❌ Backup file does not exist: {}", input);
        std::process::exit(1);
    }

    // Check if target directory exists
    if data_path.exists() && !force {
        eprintln!("❌ Target directory already exists: {}", data_dir);
        eprintln!("   Use --force to overwrite");
        std::process::exit(1);
    }

    println!("📥 Restoring backup...");
    println!("   Source: {}", input);
    println!("   Target: {}", data_dir);

    // Remove existing data if force is set
    if data_path.exists() && force {
        println!("   ⚠️  Removing existing data directory...");
        if let Err(e) = fs::remove_dir_all(data_path) {
            eprintln!("❌ Failed to remove existing directory: {}", e);
            std::process::exit(1);
        }
    }

    // Create target directory
    if let Err(e) = fs::create_dir_all(data_path) {
        eprintln!("❌ Failed to create target directory: {}", e);
        std::process::exit(1);
    }

    // Open archive
    let file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open backup file: {}", e);
            std::process::exit(1);
        }
    };

    // Detect compression by file extension
    let is_compressed = input.ends_with(".gz") || input.ends_with(".tgz");

    let reader: Box<dyn std::io::Read> = if is_compressed {
        println!("   Compression: gzip");
        Box::new(flate2::read::GzDecoder::new(BufReader::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    let mut archive = tar::Archive::new(reader);

    // SECURITY: Prevent Zip Slip attacks by validating all paths before extraction
    // We manually extract each entry with path validation instead of using unpack()
    let extract_path = data_path.parent().unwrap_or(Path::new("."));
    let canonical_extract = match extract_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("❌ Failed to resolve extract path: {}", e);
            std::process::exit(1);
        }
    };

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("❌ Failed to read archive entries: {}", e);
            eprintln!("   The backup file may be corrupted or in an unsupported format.");
            std::process::exit(1);
        }
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("❌ Failed to read archive entry: {}", e);
                std::process::exit(1);
            }
        };

        let entry_path = match entry.path() {
            Ok(p) => p.into_owned(),
            Err(e) => {
                eprintln!("❌ Invalid path in archive: {}", e);
                std::process::exit(1);
            }
        };

        // Construct the full destination path
        let dest_path = extract_path.join(&entry_path);

        // SECURITY: Validate that the resolved path is within the extract directory
        // This prevents path traversal attacks (Zip Slip) via paths like "../../../etc/passwd"
        let canonical_dest = match dest_path.parent() {
            Some(parent) => {
                // Create parent directories first so we can canonicalize
                if let Err(e) = std::fs::create_dir_all(parent) {
                    eprintln!("❌ Failed to create directory: {}", e);
                    std::process::exit(1);
                }
                match parent.canonicalize() {
                    Ok(p) => p.join(dest_path.file_name().unwrap_or_default()),
                    Err(_) => dest_path.clone(),
                }
            }
            None => dest_path.clone(),
        };

        if !canonical_dest.starts_with(&canonical_extract) {
            eprintln!("❌ SECURITY: Path traversal attempt detected in archive!");
            eprintln!("   Malicious path: {:?}", entry_path);
            eprintln!("   This backup file may be compromised.");
            std::process::exit(1);
        }

        // Now it's safe to unpack this entry
        if let Err(e) = entry.unpack(&dest_path) {
            eprintln!("❌ Failed to extract {:?}: {}", entry_path, e);
            std::process::exit(1);
        }
    }

    println!("\n✅ Restore completed successfully!");
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│ Restore Summary                                        │");
    println!("├─────────────────────────────────────────────────────────┤");
    println!("│ Data restored to: {:<37}│", data_dir);
    println!("└─────────────────────────────────────────────────────────┘");
    println!("\n💡 Start server: rustberg --data-dir {}", data_dir);
}

/// Validates a backup file without restoring.
fn validate_backup(input: &str) {
    use std::fs::File;
    use std::io::BufReader;
    use std::path::Path;

    let input_path = Path::new(input);

    if !input_path.exists() {
        eprintln!("❌ Backup file does not exist: {}", input);
        std::process::exit(1);
    }

    println!("🔍 Validating backup: {}", input);

    let file = match File::open(input_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Failed to open backup file: {}", e);
            std::process::exit(1);
        }
    };

    let is_compressed = input.ends_with(".gz") || input.ends_with(".tgz");

    let reader: Box<dyn std::io::Read> = if is_compressed {
        Box::new(flate2::read::GzDecoder::new(BufReader::new(file)))
    } else {
        Box::new(BufReader::new(file))
    };

    let mut archive = tar::Archive::new(reader);

    let mut file_count = 0;
    let mut total_size: u64 = 0;
    let mut has_catalog_files = false;

    match archive.entries() {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        file_count += 1;
                        total_size += e.size();

                        let path = e.path().unwrap_or_default();
                        let path_str = path.to_string_lossy();

                        // The catalog is a single redb file, so this is the
                        // only artifact that marks a backup as complete.
                        if path_str.ends_with(".redb") {
                            has_catalog_files = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("❌ Corrupted entry in archive: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to read archive: {}", e);
            std::process::exit(1);
        }
    }

    // Get compressed size
    let compressed_size = std::fs::metadata(input_path).map(|m| m.len()).unwrap_or(0);

    println!("\n✅ Backup is valid!");
    println!("┌─────────────────────────────────────────────────────────┐");
    println!("│ Backup Validation Summary                              │");
    println!("├─────────────────────────────────────────────────────────┤");
    println!("│ File:            {:<38}│", input);
    println!("│ Compressed size: {:<38}│", format_bytes(compressed_size));
    println!("│ Uncompressed:    {:<38}│", format_bytes(total_size));
    println!("│ Files:           {:<38}│", file_count);
    println!(
        "│ Catalog data:    {:<38}│",
        if has_catalog_files {
            "✓ Present"
        } else {
            "✗ Missing"
        }
    );
    println!("└─────────────────────────────────────────────────────────┘");

    if !has_catalog_files {
        eprintln!("\n⚠️  Warning: No catalog files detected in backup!");
        eprintln!("   This backup may not contain catalog data.");
    }
}

/// Shows catalog status and statistics.
fn show_status(data_dir: &str) {
    use std::fs;
    use std::path::Path;

    let data_path = Path::new(data_dir);

    println!("📊 Rustberg Catalog Status");
    println!("══════════════════════════════════════════════════════════\n");

    // Version info
    println!("Version:     {}", env!("CARGO_PKG_VERSION"));

    // Check data directory
    if !data_path.exists() {
        println!("Data Dir:    {} (not found)", data_dir);
        println!("\n⚠️  No catalog data found. Start the server to initialize.");
        return;
    }

    // Calculate directory size
    let mut total_size: u64 = 0;
    let mut file_count: u64 = 0;

    if let Ok(entries) = fs::read_dir(data_path) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata()
                && metadata.is_file()
            {
                total_size += metadata.len();
                file_count += 1;
            }
        }
    }

    println!("Data Dir:    {}", data_dir);
    println!("Size:        {}", format_bytes(total_size));
    println!("Files:       {}", file_count);

    // Check for catalog files
    let has_manifest = fs::read_dir(data_path)
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().contains("manifest"))
        })
        .unwrap_or(false);
    let has_sst = fs::read_dir(data_path)
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".sst"))
        })
        .unwrap_or(false);

    println!("\nCatalog Status:");
    println!("  Manifest file: {}", if has_manifest { "✓" } else { "✗" });
    println!("  SST files:     {}", if has_sst { "✓" } else { "✗" });

    if has_manifest || has_sst {
        println!("\n✅ Catalog appears healthy");
    } else {
        println!("\n⚠️  Catalog may be empty or uninitialized");
    }

    println!("\n💡 For detailed diagnostics, check /health and /ready endpoints");
}

/// Formats bytes into human-readable string.
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Runs startup and performance benchmarks.
/// `rustberg bench` — the numbers this project claims, measured here.
///
/// Deliberately the *same* measurements the CI gate asserts, through the same
/// code in `observability::perf`. Two implementations would drift, and the one
/// an operator reproduces would stop corresponding to the one that fails the
/// build — which is how a performance claim quietly becomes untrue while
/// everything still passes.
///
/// A catalog request is a policy decision and a pointer lookup, so those are
/// what this times.
async fn run_benchmarks(iterations: u32) {
    use rustberg::auth::{
        Action, AuthMethod, Authorizer, AuthzContext, CedarAuthorizer, PrincipalBuilder,
        PrincipalType, Resource,
    };
    use rustberg::observability::perf::{measure, measure_async, resident_bytes};
    use std::sync::Arc;
    use std::time::Instant;

    let iterations = iterations.max(1) as usize;

    println!("Rustberg {} — performance", env!("CARGO_PKG_VERSION"));
    println!("{}", "─".repeat(78));
    if cfg!(debug_assertions) {
        println!("⚠️  debug build; these numbers are several times slower than a release build");
    }
    println!("iterations: {iterations}\n");

    // ── Authorization ───────────────────────────────────────────────────
    // On every request, so a regression here is paid by everything.
    let authorizer = match CedarAuthorizer::with_default_policies() {
        Ok(authorizer) => Arc::new(authorizer),
        Err(e) => {
            tracing::error!("Could not compile the default policies: {e}");
            std::process::exit(1);
        }
    };

    let context = AuthzContext::new(
        PrincipalBuilder::new(
            "bench",
            "Bench",
            PrincipalType::User,
            "acme",
            AuthMethod::ApiKey,
        )
        .with_role("reader")
        .build(),
        Resource::table("acme", ["analytics", "web"], "events"),
        Action::Read,
    );

    let authorization = measure_async("authorization (point op)", iterations, || {
        let authorizer = authorizer.clone();
        let context = context.clone();
        async move {
            let _ = authorizer.decide(&context).await;
        }
    })
    .await;
    println!("{}", authorization.describe());

    // ── Policy compilation ──────────────────────────────────────────────
    // Inside cold start, and the part that grows with a deployment's policies.
    let compile = measure("policy compile + validate", iterations.min(100), || {
        let _ = CedarAuthorizer::with_default_policies();
    });
    println!("{}", compile.describe());

    // ── loadTable ───────────────────────────────────────────────────────
    // The whole stack, because that is what a client waits for.
    let app = match rustberg::App::builder()
        .with_warehouse_location("memory://bench")
        .with_default_tenant_id("default")
        .build()
        .await
    {
        Ok(app) => app,
        Err(e) => {
            tracing::error!("Could not build a benchmark server: {e}");
            std::process::exit(1);
        }
    };

    let router = app.clone().into_router();
    let created = bench_request(
        &router,
        "POST",
        "/v1/namespaces",
        Some(r#"{"namespace":["bench"]}"#),
    )
    .await
        && bench_request(
            &router,
            "POST",
            "/v1/namespaces/bench/tables",
            Some(
                r#"{"name":"events","schema":{"type":"struct","fields":[{"id":1,"name":"id","required":true,"type":"long"}]}}"#,
            ),
        )
        .await;

    if created {
        let load = measure_async("loadTable (full stack)", iterations, || {
            let app = app.clone();
            async move {
                let router = app.into_router();
                let _ =
                    bench_request(&router, "GET", "/v1/namespaces/bench/tables/events", None).await;
            }
        })
        .await;
        println!("{}", load.describe());
    }

    // ── Cold start ──────────────────────────────────────────────────────
    let mut starts = Vec::new();
    for _ in 0..iterations.min(20) {
        let started = Instant::now();
        let built = rustberg::App::builder()
            .with_warehouse_location("memory://bench")
            .with_default_tenant_id("default")
            .build()
            .await;
        if built.is_ok() {
            starts.push(started.elapsed());
        }
    }
    if !starts.is_empty() {
        println!(
            "{}",
            rustberg::observability::perf::Measurement::from_samples("cold start (build)", starts)
                .describe()
        );
    }

    // ── Footprint ───────────────────────────────────────────────────────
    match resident_bytes() {
        Some(bytes) => println!(
            "\n{:<28} {:.1} MiB resident",
            "idle footprint",
            bytes as f64 / (1024.0 * 1024.0)
        ),
        // macOS needs `task_info`, which this crate will not carry for a
        // diagnostic. `ps -o rss=` reports it from outside the process.
        None => println!(
            "\n{:<28} not readable here; use: ps -o rss= -p $(pgrep -n rustberg)",
            "idle footprint"
        ),
    }
}

/// Issues one in-process request, reporting whether it succeeded.
async fn bench_request(router: &axum::Router, method: &str, uri: &str, body: Option<&str>) -> bool {
    use tower::ServiceExt;

    let mut builder = axum::http::Request::builder().method(method).uri(uri);
    let request = match body {
        Some(json) => {
            builder = builder.header("Content-Type", "application/json");
            builder.body(axum::body::Body::from(json.to_string()))
        }
        None => builder.body(axum::body::Body::empty()),
    };

    match request {
        Ok(request) => match router.clone().oneshot(request).await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_config(host: &str, port: u16) -> rustberg::config::RustbergConfig {
        let mut config = rustberg::config::RustbergConfig::default();
        config.server.host = host.to_string();
        config.server.port = port;
        config
    }

    /// The flag wins, then the file, then the built-in default.
    ///
    /// A `default_value` on the clap argument would make the third case
    /// indistinguishable from the first, so `[server] host` and `port` would be
    /// parsed from the file and then silently overridden by a flag nobody
    /// passed.
    #[test]
    fn the_bind_address_prefers_the_flag_then_the_file() {
        let file = file_config("127.0.0.1", 9000);

        assert_eq!(
            bind_address(Some("10.0.0.1"), Some(1234), Some(&file)),
            ("10.0.0.1".to_string(), 1234)
        );
        assert_eq!(
            bind_address(None, None, Some(&file)),
            ("127.0.0.1".to_string(), 9000)
        );
        assert_eq!(
            bind_address(None, None, None),
            (DEFAULT_HOST.to_string(), DEFAULT_PORT)
        );
    }

    /// Each half resolves on its own: a `--port` alone must not drag the
    /// default host in over the file's.
    #[test]
    fn the_host_and_the_port_resolve_independently() {
        let file = file_config("127.0.0.1", 9000);

        assert_eq!(
            bind_address(None, Some(1234), Some(&file)),
            ("127.0.0.1".to_string(), 1234)
        );
        assert_eq!(
            bind_address(Some("10.0.0.1"), None, Some(&file)),
            ("10.0.0.1".to_string(), 9000)
        );
    }

    /// One setting, one default. Two — one on the flag and one on the serde
    /// field — put a deployment on a port neither its config nor its flags name.
    #[test]
    fn the_cli_and_the_file_agree_on_the_default_port() {
        assert_eq!(
            rustberg::config::RustbergConfig::default().server.port,
            DEFAULT_PORT
        );
        assert_eq!(
            rustberg::config::RustbergConfig::default().server.host,
            DEFAULT_HOST
        );
    }

    /// Every environment variable the documentation names must exist on the CLI.
    ///
    /// The two drifted: the configuration page listed `RUSTBERG_LOG_LEVEL`, which
    /// has never been read by anything — the flag's variable is `RUST_LOG` — and
    /// gave `127.0.0.1` as the default bind address, which is `0.0.0.0`. A reader
    /// setting the first gets no effect and no error, which is the worst shape a
    /// configuration mistake can take.
    ///
    /// Read out of `clap` rather than out of a second list, so there is nothing
    /// here to keep in sync.
    #[test]
    fn every_documented_environment_variable_exists() {
        use clap::CommandFactory;

        let known: std::collections::HashSet<String> = Cli::command()
            .get_arguments()
            .filter_map(|arg| arg.get_env())
            .map(|env| env.to_string_lossy().into_owned())
            .collect();

        // Secrets are named *by* a setting rather than fixed — a `*_env` value or
        // an `env:NAME` property — so such a name in an example is an
        // illustration of the convention and not a variable Rustberg reads.
        const EXAMPLES: &[&str] = &[
            "RUSTBERG_KEY_",
            "RUSTBERG_STS_",
            "RUSTBERG_AZURE_",
            "RUSTBERG_PARTNER_",
            "RUSTBERG_TEST_",
            // `[storage.properties]` values written as `env:NAME`.
            "RUSTBERG_S3_",
            "RUSTBERG_GCS_",
            "RUSTBERG_ADLS_",
        ];

        let pages: &[(&str, &str)] = &[
            (
                "configuration",
                include_str!("../site/content/docs/configuration.md"),
            ),
            (
                "getting-started",
                include_str!("../site/content/docs/getting-started.md"),
            ),
        ];

        let mut checked = 0;
        for (page, text) in pages {
            for token in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if !token.starts_with("RUSTBERG_") {
                    continue;
                }
                if EXAMPLES.iter().any(|prefix| token.starts_with(prefix)) {
                    continue;
                }
                assert!(
                    known.contains(token),
                    "the {page} page documents `{token}`, which no CLI argument reads. \
                     Either add the argument or correct the page."
                );
                checked += 1;
            }
        }

        assert!(
            checked > 5,
            "expected to find documented variables, found {checked} — has the table moved?"
        );
    }

    /// The printed quickstart is the first thing anyone runs, so the URL in it
    /// has to name the address this process is about to listen on.
    #[test]
    fn the_quickstart_url_names_the_address_being_served() {
        assert_eq!(
            quickstart_base_url("0.0.0.0", 8099, false),
            "http://localhost:8099"
        );
        assert_eq!(
            quickstart_base_url("127.0.0.1", 8000, false),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            quickstart_base_url("0.0.0.0", 8443, true),
            "https://localhost:8443"
        );
    }

    /// A wildcard bind is a valid thing to listen on and not a valid thing to
    /// connect to, so it is rendered as `localhost` rather than echoed.
    #[test]
    fn a_wildcard_bind_is_rendered_as_localhost() {
        for wildcard in ["0.0.0.0", "::", "[::]"] {
            assert_eq!(
                quickstart_base_url(wildcard, 8000, false),
                "http://localhost:8000",
                "{wildcard} is not connectable"
            );
        }
    }

    /// A literal IPv6 address needs brackets, or the port reads as another
    /// group of the address.
    #[test]
    fn a_literal_ipv6_address_is_bracketed() {
        assert_eq!(quickstart_base_url("::1", 8000, false), "http://[::1]:8000");
    }
}
