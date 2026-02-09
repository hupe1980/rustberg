---
layout: default
title: Configuration
nav_order: 8
description: "Complete Rustberg configuration reference: TOML, environment variables, CLI"
permalink: /docs/configuration
---

# Configuration
{: .no_toc }

Complete configuration reference for Rustberg.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Configuration Sources

Rustberg loads configuration from multiple sources (in priority order):

1. **CLI arguments** (highest priority)
2. **Environment variables**
3. **TOML config file**
4. **Default values** (lowest priority)

---

## Quick Start

### Minimal Config

```toml
# rustberg.toml
[server]
host = "0.0.0.0"
port = 8181

[storage]
object_store_url = "s3://my-bucket/catalog"
```

### Run with Config

```bash
./rustberg --config rustberg.toml
```

---

## Complete Reference

### Server Section

```toml
[server]
# Bind address
host = "127.0.0.1"

# Listen port
port = 8181

# Request timeout in seconds
request_timeout_secs = 30

# Maximum request body size in bytes
max_body_size = 10485760  # 10 MB

# Enable gzip compression
compression = true
```

### Storage Section

```toml
[storage]
# Storage backend URL
# Options: memory://, file:///path, s3://bucket/prefix, gs://bucket/prefix, az://container/prefix
object_store_url = "s3://my-bucket/catalog"

# AWS configuration (for S3)
aws_region = "us-east-1"
aws_endpoint = ""  # Custom endpoint for MinIO

# GCS configuration
# Uses GOOGLE_APPLICATION_CREDENTIALS env var

# Azure configuration
azure_storage_account = ""

# IO timeout configuration (seconds)
# Prevents stalled cloud storage connections from blocking workers indefinitely.
read_timeout_secs = 60   # Timeout for metadata reads (default: 60)
write_timeout_secs = 30  # Timeout for metadata writes (default: 30)
```

### Authentication Section

```toml
[auth]
# Require authentication (default: true)
require_authentication = true

# API key prefix (default: "rustberg_")
api_key_prefix = "rustberg_"

# Enable persistent API key storage
persistent_api_keys = true

# Encryption key environment variable
encryption_key_env = "RUSTBERG_MASTER_KEY"
```

### JWT Section

```toml
[auth.jwt]
# JWKS URL for token validation
jwks_url = "https://auth.example.com/.well-known/jwks.json"

# Expected token issuer
issuer = "https://auth.example.com"

# Expected token audience
audience = "rustberg-catalog"

# JWKS cache TTL in seconds
jwks_cache_ttl_secs = 3600
```

### Authorization Section

```toml
[authorization]
# Authorization engine (default: "cedar")
engine = "cedar"

# Policy file path
policy_file = "/etc/rustberg/policies/catalog.cedar"

# Enable hot reload of policies
hot_reload = true

# Hot reload check interval in seconds
hot_reload_interval_secs = 30
```

### Rate Limiting Section

```toml
[rate_limit]
# Enable rate limiting (default: true)
enabled = true

# Requests per second limit
requests_per_second = 100

# Burst size (token bucket)
burst_size = 200

# Trust X-Forwarded-For header (default: false)
# Only enable behind a trusted proxy
trust_proxy_headers = false

# Cleanup interval for stale buckets
cleanup_interval_secs = 60
```

### TLS Section

```toml
[tls]
# Enable TLS (default: true in production)
enabled = true

# Certificate file path
cert_path = "/etc/rustberg/tls/cert.pem"

# Private key file path
key_path = "/etc/rustberg/tls/key.pem"

# Minimum TLS version (default: "1.2")
min_version = "1.2"

# Generate self-signed cert (for development)
self_signed = false
```

### KMS Section

```toml
[kms]
# KMS provider: "env", "aws", "vault", "gcp", "azure"
provider = "env"

# EnvKeyProvider config
key_env_var = "RUSTBERG_MASTER_KEY"

# AWS KMS config
key_id = "arn:aws:kms:us-east-1:123456789:key/your-key-id"
aws_region = "us-east-1"

# Vault config
vault_addr = "https://vault.example.com:8200"
vault_token_env = "VAULT_TOKEN"
key_name = "rustberg-key"
transit_mount = "transit"

# GCP Cloud KMS config
project_id = "your-project"
location = "global"
key_ring = "rustberg-keyring"
crypto_key = "rustberg-key"

# Azure Key Vault config
vault_url = "https://rustberg-vault.vault.azure.net"
# key_name = "rustberg-key"  (same as vault)

# DEK caching
dek_cache_size = 1000
dek_cache_ttl_secs = 300
```

### Logging Section

```toml
[logging]
# Log level: "trace", "debug", "info", "warn", "error"
level = "info"

# Log format: "json" or "pretty"
format = "json"

# Include span events
include_spans = false
```

### CORS Section

```toml
[cors]
# Enable CORS (default: false)
enabled = false

# Allowed origins (use "*" for any)
allowed_origins = ["https://dashboard.example.com"]

# Allowed methods
allowed_methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]

# Allowed headers
allowed_headers = ["Authorization", "Content-Type"]

# Max age for preflight cache
max_age_secs = 3600
```

---

## Environment Variables

All config options can be set via environment variables:

| Variable | Config Path | Description |
|----------|-------------|-------------|
| `RUSTBERG_HOST` | server.host | Bind address |
| `RUSTBERG_PORT` | server.port | Listen port |
| `RUSTBERG_STORAGE` | storage.object_store_url | Storage URL |
| `RUSTBERG_LOG_LEVEL` | logging.level | Log level |
| `RUSTBERG_MASTER_KEY` | kms.key_env_var | Encryption key |
| `AWS_REGION` | storage.aws_region | AWS region |
| `AWS_ACCESS_KEY_ID` | - | AWS credentials |
| `AWS_SECRET_ACCESS_KEY` | - | AWS credentials |
| `GOOGLE_APPLICATION_CREDENTIALS` | - | GCP credentials |
| `AZURE_STORAGE_ACCOUNT` | storage.azure_storage_account | Azure account |
| `AZURE_STORAGE_KEY` | - | Azure key |
| `VAULT_ADDR` | kms.vault_addr | Vault address |
| `VAULT_TOKEN` | - | Vault token |

---

## CLI Arguments

```bash
./rustberg --help

USAGE:
    rustberg [OPTIONS] [COMMAND]

COMMANDS:
    generate-key     Generate a new API key
    generate-cert    Generate a self-signed TLS certificate for development
    generate-config  Generate a sample configuration file
    open-api         Generate OpenAPI specification
    backup           Create a backup of the catalog database
    restore          Restore a catalog database from backup
    validate-backup  Validate a backup file without restoring
    status           Show catalog statistics and health
    benchmark        Run startup/performance benchmarks
    help             Print help for a subcommand

OPTIONS:
    -c, --config <FILE>      Configuration file path
        --host <HOST>        Bind address [default: 0.0.0.0]
    -p, --port <PORT>        Listen port [default: 8000]
    -w, --warehouse <URL>    Warehouse location for table storage (see below)
    -t, --tenant-id <ID>     Default tenant ID [default: default]
        --no-auth            Disable authentication (NOT RECOMMENDED)
        --log-level <LEVEL>  Log level [default: info]
        --tls-cert <FILE>    TLS certificate path (PEM format)
        --tls-key <FILE>     TLS private key path (PEM format)
        --insecure-http      Allow HTTP (no TLS)
    -V, --version            Print version
    -h, --help               Print help
```

### Warehouse Location

The `--warehouse` option specifies where table data files are stored. Supported formats:

| Format | Example | Description |
|--------|---------|-------------|
| Relative path | `file://warehouse` | Resolves to `file://<current_dir>/warehouse` |
| Absolute path | `file:///var/lib/data` | Local filesystem (absolute) |
| S3 | `s3://bucket/prefix` | Amazon S3 |
| GCS | `gs://bucket/prefix` | Google Cloud Storage |
| Azure | `az://container/prefix` | Azure Blob Storage |

{: .note }
> For local filesystem paths, Rustberg automatically creates the directory if it doesn't exist and converts relative paths to absolute paths.

**Examples:**

```bash
# Local development with relative path (creates ./warehouse directory)
./rustberg --no-auth --insecure-http --warehouse file://warehouse

# Local development with absolute path
./rustberg --no-auth --insecure-http --warehouse file:///tmp/rustberg-warehouse

# S3 backend
./rustberg --warehouse s3://my-bucket/iceberg-warehouse

# GCS backend
./rustberg --warehouse gs://my-bucket/iceberg-warehouse
```

---

## Example Configurations

### Development

```toml
[server]
host = "127.0.0.1"
port = 8181

[storage]
object_store_url = "memory://"

[auth]
require_authentication = false

[tls]
enabled = false

[logging]
level = "debug"
format = "pretty"
```

### Single-Node Production

```toml
[server]
host = "0.0.0.0"
port = 8181

[storage]
object_store_url = "file:///var/lib/rustberg"

[auth]
require_authentication = true
persistent_api_keys = true
encryption_key_env = "RUSTBERG_MASTER_KEY"

[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"

[logging]
level = "info"
format = "json"
```

### Kubernetes Production

```toml
[server]
host = "0.0.0.0"
port = 8181

[storage]
object_store_url = "s3://my-bucket/rustberg-catalog"
aws_region = "us-east-1"

[auth]
require_authentication = true
persistent_api_keys = true

[auth.jwt]
jwks_url = "https://auth.company.com/.well-known/jwks.json"
issuer = "https://auth.company.com"
audience = "rustberg"

[authorization]
engine = "cedar"
policy_file = "/etc/rustberg/policies/catalog.cedar"
hot_reload = true

[kms]
provider = "aws"
key_id = "arn:aws:kms:us-east-1:123456789:key/..."
aws_region = "us-east-1"

[rate_limit]
enabled = true
requests_per_second = 1000
trust_proxy_headers = true

[logging]
level = "info"
format = "json"
```

---

## Generate Config

Generate a sample configuration file:

```bash
./rustberg generate-config > rustberg.toml
```

---

## Next Steps

- [Getting Started](/rustberg/docs/getting-started) - Quick setup
- [Storage Backends](/rustberg/docs/storage) - Configure storage
- [Authentication](/rustberg/docs/authentication) - Secure access
