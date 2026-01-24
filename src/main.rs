//! Rustberg - Apache Iceberg REST Catalog Server
//!
//! A production-grade, single-binary Iceberg catalog server written in Rust.

use clap::{Parser, Subcommand};
use rustberg::auth::{ApiKeyBuilder, ApiKeyStore, InMemoryApiKeyStore};
use rustberg::server::{ServerConfig, TlsConfig};
use rustberg::{start_server, App};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::Level;

/// Rustberg - Apache Iceberg REST Catalog
#[derive(Parser)]
#[command(name = "rustberg")]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to configuration file (TOML)
    #[arg(short, long, env = "RUSTBERG_CONFIG")]
    config: Option<PathBuf>,

    /// Server bind address
    #[arg(long, env = "RUSTBERG_HOST", default_value = "0.0.0.0")]
    host: String,

    /// Server bind port
    #[arg(short, long, env = "RUSTBERG_PORT", default_value = "8000")]
    port: u16,

    /// Warehouse location for table storage
    #[arg(short, long, env = "RUSTBERG_WAREHOUSE")]
    warehouse: Option<String>,

    /// Default tenant ID
    #[arg(short, long, env = "RUSTBERG_TENANT_ID", default_value = "default")]
    tenant_id: String,

    /// Disable authentication (NOT RECOMMENDED - for development only)
    /// Authentication is enabled by default for security.
    #[arg(long, env = "RUSTBERG_NO_AUTH")]
    no_auth: bool,

    /// Log level
    #[arg(long, env = "RUST_LOG", default_value = "info")]
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

    /// Generate OpenAPI specification
    OpenApi {
        /// Output format: json or yaml
        #[arg(short, long, default_value = "json")]
        format: String,

        /// Output file path (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Create a backup of the catalog database
    Backup {
        /// Output file path for the backup
        #[arg(short, long)]
        output: String,

        /// SlateDB data directory to backup
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

        /// Target SlateDB data directory
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
        /// SlateDB data directory
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

    // Initialize logging
    let log_level = parse_log_level(&cli.log_level);
    tracing_subscriber::fmt().with_max_level(log_level).init();

    // Load configuration file if provided
    let file_config = if let Some(config_path) = &cli.config {
        match rustberg::config::RustbergConfig::from_file(config_path) {
            Ok(config) => {
                tracing::info!(path = %config_path.display(), "Loaded configuration from file");
                Some(config)
            }
            Err(e) => {
                tracing::error!(error = %e, path = %config_path.display(), "Failed to load configuration file");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

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
            Commands::OpenApi { format, output } => {
                generate_openapi(&format, output.as_deref());
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
                tracing::warn!("⚠️  Running in INSECURE HTTP mode - credentials will be transmitted in plaintext!");
                tracing::warn!("⚠️  This is NOT suitable for production!");
                None
            } else {
                // Auto-generate self-signed certificate for development
                #[cfg(feature = "tls")]
                {
                    tracing::info!("🔐 No TLS certificate provided - generating self-signed certificate for development");
                    match generate_dev_certificate(&cli.host) {
                        Ok(config) => {
                            tracing::warn!("⚠️  Using auto-generated self-signed certificate");
                            tracing::warn!("⚠️  This is for DEVELOPMENT ONLY - use proper certificates in production!");
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
                    tracing::error!("TLS feature not enabled. Use --insecure-http or rebuild with --features tls");
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

        let mut builder = App::builder().with_default_tenant_id(&cli.tenant_id);

        // Apply configuration from file if loaded
        if let Some(ref config) = file_config {
            if let Some(ref warehouse) = config.storage.warehouse_location {
                builder = builder.with_warehouse_location(warehouse);
            }
            // Storage backend URL
            if !config.storage.backend.is_empty()
                && config.storage.backend != "file:///var/lib/rustberg/data"
            {
                builder = builder.with_storage_backend(&config.storage.backend);
            }
            // KMS configuration
            let kms_config = rustberg::crypto::KmsConfig::from_file_config(&config.kms);
            builder = builder.with_kms_config(kms_config);
            // Rate limiting
            if let Some(rate_config) =
                rustberg::auth::RateLimitConfig::from_file_config(&config.rate_limit)
            {
                builder = builder.with_rate_limit_config(rate_config);
            }
            // CORS
            builder = builder.with_cors_config(config.server.cors.clone());
        }

        // CLI overrides take precedence
        if let Some(warehouse) = cli.warehouse.as_ref() {
            builder = builder.with_warehouse_location(warehouse);
        }

        // Use async variant to avoid nested runtime when TLS is enabled
        builder.build_async().await
    } else {
        tracing::info!("Starting with authentication enabled (default)");

        // Create app with API key auth (use async variant to avoid nested runtime)
        let (app, api_key_store) = {
            let mut builder = App::builder().with_default_tenant_id(&cli.tenant_id);

            // Apply configuration from file if loaded
            if let Some(ref config) = file_config {
                if let Some(ref warehouse) = config.storage.warehouse_location {
                    builder = builder.with_warehouse_location(warehouse);
                }
                // Storage backend URL
                if !config.storage.backend.is_empty()
                    && config.storage.backend != "file:///var/lib/rustberg/data"
                {
                    builder = builder.with_storage_backend(&config.storage.backend);
                }
                // KMS configuration
                let kms_config = rustberg::crypto::KmsConfig::from_file_config(&config.kms);
                builder = builder.with_kms_config(kms_config);
                // Rate limiting
                if let Some(rate_config) =
                    rustberg::auth::RateLimitConfig::from_file_config(&config.rate_limit)
                {
                    builder = builder.with_rate_limit_config(rate_config);
                }
                // CORS
                builder = builder.with_cors_config(config.server.cors.clone());
                // JWT configuration if enabled
                if config.server.auth.jwt_enabled {
                    if let Some(ref jwt_serde) = config.server.auth.jwt {
                        builder = builder.with_jwt_config(jwt_serde.clone().into());
                    }
                }
            }

            // CLI overrides take precedence
            if let Some(warehouse) = cli.warehouse.as_ref() {
                builder = builder.with_warehouse_location(warehouse);
            }

            builder.build_with_api_key_auth_async().await
        };

        // Pre-create a demo admin key for development
        if std::env::var("RUSTBERG_CREATE_DEMO_KEY").is_ok() {
            create_demo_key(&api_key_store, &cli.tenant_id).await;
        }

        app
    };

    // Build server configuration
    let server_config = ServerConfig {
        host: cli.host,
        port: cli.port,
        tls: tls_config,
    };

    // Start the server
    if let Err(e) = start_server(app.into_router(), server_config).await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

/// Parses a log level string into a tracing Level.
fn parse_log_level(level: &str) -> Level {
    match level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    }
}

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
    println!("API Key:     {}", plaintext);
    println!("Name:        {}", key.name);
    println!("Tenant:      {}", key.tenant_id);
    println!("Roles:       {:?}", key.roles);
    println!("ID:          {}", key.id);
    if let Some(desc) = key.description {
        println!("Description: {}", desc);
    }
    println!("\n⚠️  Store this key in your environment as:");
    println!("   export X_API_KEY=\"{}\"", plaintext);
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

/// Generates the OpenAPI specification.
fn generate_openapi(format: &str, output: Option<&std::path::Path>) {
    use rustberg::openapi::ApiDoc;

    let spec = match format.to_lowercase().as_str() {
        "yaml" | "yml" => ApiDoc::yaml(),
        _ => ApiDoc::json(),
    };

    match output {
        Some(path) => {
            if let Err(e) = std::fs::write(path, &spec) {
                eprintln!("❌ Failed to write OpenAPI spec: {}", e);
                std::process::exit(1);
            }
            println!("✅ OpenAPI specification written to: {}", path.display());
        }
        None => {
            println!("{}", spec);
        }
    }
}

/// Creates a demo admin API key for development.
async fn create_demo_key(store: &Arc<InMemoryApiKeyStore>, tenant_id: &str) {
    let (key, plaintext) = ApiKeyBuilder::new("demo-admin", tenant_id)
        .with_role("admin")
        .with_description("Demo admin key (auto-generated)")
        .build();

    if let Err(e) = store.store(key).await {
        tracing::error!("Failed to create demo key: {}", e);
        return;
    }

    tracing::warn!("╔══════════════════════════════════════════════════════════╗");
    tracing::warn!("║ DEMO API KEY CREATED                                     ║");
    tracing::warn!("║ This is for DEVELOPMENT ONLY - DO NOT use in production ║");
    tracing::warn!("╚══════════════════════════════════════════════════════════╝");
    tracing::info!("Demo API Key: {}", plaintext);
    tracing::info!(
        "Use: curl -H 'X-API-Key: {}' http://localhost:8000/v1/config",
        plaintext
    );
}

// ============================================================================
// Backup & Restore Commands
// ============================================================================

/// Creates a backup of the SlateDB catalog.
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
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            if let Err(e) = fs::create_dir_all(parent) {
                eprintln!("❌ Failed to create output directory: {}", e);
                std::process::exit(1);
            }
        }
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
    let mut has_slatedb_files = false;

    match archive.entries() {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(e) => {
                        file_count += 1;
                        total_size += e.size();

                        let path = e.path().unwrap_or_default();
                        let path_str = path.to_string_lossy();

                        // Check for SlateDB files (SST, manifest, etc.)
                        if path_str.contains("manifest")
                            || path_str.contains("compacted")
                            || path_str.ends_with(".sst")
                            || path_str.contains("wal")
                        {
                            has_slatedb_files = true;
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
        "│ SlateDB data:    {:<38}│",
        if has_slatedb_files {
            "✓ Present"
        } else {
            "✗ Missing"
        }
    );
    println!("└─────────────────────────────────────────────────────────┘");

    if !has_slatedb_files {
        eprintln!("\n⚠️  Warning: No SlateDB files detected in backup!");
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
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    total_size += metadata.len();
                    file_count += 1;
                }
            }
        }
    }

    println!("Data Dir:    {}", data_dir);
    println!("Size:        {}", format_bytes(total_size));
    println!("Files:       {}", file_count);

    // Check for SlateDB files
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

    println!("\nSlateDB Status:");
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
async fn run_benchmarks(iterations: u32) {
    use std::time::{Duration, Instant};

    println!("🏃 Rustberg Performance Benchmark");
    println!("══════════════════════════════════════════════════════════\n");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));
    println!("Iterations: {}\n", iterations);

    // Benchmark 1: API Key generation (includes Argon2id hashing)
    println!("📊 API Key Generation (Argon2id)");
    let mut keygen_times: Vec<Duration> = Vec::with_capacity(iterations as usize);

    for i in 0..iterations {
        let start = Instant::now();
        let _key = rustberg::auth::ApiKeyBuilder::new(format!("bench-{}", i), "benchmark")
            .with_role("reader")
            .build();
        keygen_times.push(start.elapsed());
        print!(".");
    }
    println!();

    let keygen_avg = keygen_times.iter().sum::<Duration>() / iterations;
    let keygen_min = keygen_times.iter().min().unwrap_or(&Duration::ZERO);
    let keygen_max = keygen_times.iter().max().unwrap_or(&Duration::ZERO);

    println!("   Min: {:?}", keygen_min);
    println!("   Max: {:?}", keygen_max);
    println!("   Avg: {:?}", keygen_avg);
    println!();

    // Benchmark 2: API Key verification (Argon2id hash)
    println!("📊 API Key Hash Verification (Argon2id)");
    let (_key, plaintext) = rustberg::auth::ApiKeyBuilder::new("verify-test", "benchmark")
        .with_role("reader")
        .build();

    let mut verify_times: Vec<Duration> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _hash = rustberg::auth::hash_api_key(&plaintext);
        verify_times.push(start.elapsed());
        print!(".");
    }
    println!();

    let verify_avg = verify_times.iter().sum::<Duration>() / iterations;
    let verify_min = verify_times.iter().min().unwrap_or(&Duration::ZERO);
    let verify_max = verify_times.iter().max().unwrap_or(&Duration::ZERO);

    println!("   Min: {:?}", verify_min);
    println!("   Max: {:?}", verify_max);
    println!("   Avg: {:?}", verify_avg);
    println!();

    // Benchmark 3: OpenAPI generation
    println!("📊 OpenAPI Spec Generation");
    let mut openapi_times: Vec<Duration> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _spec = rustberg::openapi::ApiDoc::yaml();
        openapi_times.push(start.elapsed());
        print!(".");
    }
    println!();

    let openapi_avg = openapi_times.iter().sum::<Duration>() / iterations;
    let openapi_min = openapi_times.iter().min().unwrap_or(&Duration::ZERO);
    let openapi_max = openapi_times.iter().max().unwrap_or(&Duration::ZERO);

    println!("   Min: {:?}", openapi_min);
    println!("   Max: {:?}", openapi_max);
    println!("   Avg: {:?}", openapi_avg);
    println!();

    // Benchmark 4: Config parsing
    println!("📊 TOML Config Parsing");
    let sample_config = rustberg::config::RustbergConfig::sample();
    let mut config_times: Vec<Duration> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let _config: rustberg::config::RustbergConfig = match toml::from_str(&sample_config) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Config parse error: {}", e);
                return;
            }
        };
        config_times.push(start.elapsed());
        print!(".");
    }
    println!();

    let config_avg = config_times.iter().sum::<Duration>() / iterations;
    let config_min = config_times.iter().min().unwrap_or(&Duration::ZERO);
    let config_max = config_times.iter().max().unwrap_or(&Duration::ZERO);

    println!("   Min: {:?}", config_min);
    println!("   Max: {:?}", config_max);
    println!("   Avg: {:?}", config_avg);
    println!();

    // Memory info (best effort)
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            println!("📊 Memory Usage");
            for line in status.lines() {
                if line.starts_with("VmRSS:") || line.starts_with("VmHWM:") {
                    println!("   {}", line.trim());
                }
            }
            println!();
        }
    }

    // Summary
    println!("══════════════════════════════════════════════════════════");
    println!("✅ Benchmark complete\n");
    println!("📈 Summary (averages):");
    println!("   Key generation:  {:?}", keygen_avg);
    println!("   Key verification: {:?}", verify_avg);
    println!("   OpenAPI gen:     {:?}", openapi_avg);
    println!("   Config parse:    {:?}", config_avg);

    // Performance targets
    println!();
    println!("🎯 Performance Targets:");
    if keygen_avg < Duration::from_millis(100) {
        println!("   ✅ Key gen < 100ms (secure Argon2id)");
    } else {
        println!("   ⚠️  Key gen >= 100ms");
    }
    if verify_avg < Duration::from_millis(100) {
        println!("   ✅ Key verify < 100ms");
    } else {
        println!("   ⚠️  Key verify >= 100ms");
    }
    if openapi_avg < Duration::from_millis(10) {
        println!("   ✅ OpenAPI gen < 10ms");
    } else {
        println!("   ⚠️  OpenAPI gen >= 10ms");
    }
    if config_avg < Duration::from_millis(1) {
        println!("   ✅ Config parse < 1ms");
    } else {
        println!("   ⚠️  Config parse >= 1ms");
    }
}
