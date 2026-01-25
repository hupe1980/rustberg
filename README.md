# Rustberg

<p align="center">
  <strong>A production-grade, cross-platform, single-binary Apache Iceberg REST Catalog server written in Rust.</strong>
</p>

<p align="center">
  <a href="https://hupe1980.github.io/rustberg">Documentation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="https://hupe1980.github.io/rustberg/docs/security">Security</a> •
  <a href="https://hupe1980.github.io/rustberg/docs/api">API</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/tests-460%20passing-brightgreen" alt="Tests">
  <img src="https://img.shields.io/badge/clippy-0%20warnings-brightgreen" alt="Clippy">
  <img src="https://img.shields.io/badge/memory-~9MB-blue" alt="Memory">
  <img src="https://img.shields.io/badge/binary-7.4MB-blue" alt="Binary Size">
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License">
</p>

---

## Why Rustberg?

**Rustberg** is a production-grade Apache Iceberg REST Catalog designed for simplicity and performance:

### Core Capabilities

- 🚀 **Instant Startup** — Sub-10ms cold start, ready immediately
- 📦 **Single Binary** — No JVM, no PostgreSQL, no external services required
- 🔐 **Security First** — TLS 1.3, API keys, JWT/OIDC, Cedar policies, AES-256-GCM encryption
- ☸️ **Kubernetes Native** — SlateDB on S3/GCS/Azure for horizontal scaling
- 🌍 **Cross-Platform** — Linux, macOS, Windows with first-class support
- 📋 **Full Iceberg REST API** — Tables, views, namespaces, transactions, credential vending

---

## Quick Start

### Option 1: Pre-built Binaries

```bash
# Linux (x86_64)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-linux-x86_64 -o rustberg

# Linux (ARM64)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-linux-aarch64 -o rustberg

# macOS (Apple Silicon)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-darwin-aarch64 -o rustberg

# Make executable and run
chmod +x rustberg
./rustberg
```

### Option 2: Docker

```bash
# Start Rustberg
docker run -d -p 8181:8181 --name rustberg \
  -e RUSTBERG_INSECURE_HTTP=true \
  ghcr.io/hupe1980/rustberg:latest

# Verify it's running
curl http://localhost:8181/health

# Create a namespace
curl -X POST http://localhost:8181/v1/namespaces \
  -H "Content-Type: application/json" \
  -d '{"namespace": ["my_namespace"]}'
```

### Option 3: Helm Chart (Kubernetes)

```bash
# Clone repository
git clone https://github.com/hupe1980/rustberg
cd rustberg

# Install with Helm
helm install rustberg charts/rustberg \
  --set rustberg.storage.type=s3 \
  --set rustberg.storage.s3.bucket=my-catalog-bucket

# Or with custom values
helm install rustberg charts/rustberg -f my-values.yaml
```

### Option 4: Build from Source

Requires **Rust 1.89+** ([install](https://rustup.rs/))

```bash
# Clone and build
git clone https://github.com/hupe1980/rustberg
cd rustberg
cargo build --release --all-features

# Generate TLS certificate (development)
./target/release/rustberg generate-cert

# Start server
./target/release/rustberg --tls-cert server.crt --tls-key server.key
```

---

## Features

### Core Iceberg API

- ✅ **Namespace CRUD** - Create, list, update, delete namespaces
- ✅ **Table CRUD** - Full table lifecycle management
- ✅ **Table Commits** - Optimistic concurrency with requirements
- ✅ **Register Table** - Import existing tables from metadata location
- ✅ **Multi-table Transactions** - Atomic commits across multiple tables
- ✅ **Metrics Reporting** - Client telemetry collection
- ✅ **Credential Vending** - AWS STS + GCS + Azure temporary credentials
- ✅ **Pagination** - Cursor-based with configurable page size
- ✅ **Idempotency** - Request deduplication via idempotency keys

### Security

- ✅ **API Key Authentication** - Argon2id hashed, constant-time validation
- ✅ **JWT/OIDC Authentication** - JWKS validation, configurable claims
- ✅ **Cedar Policy Authorization** - Fine-grained ABAC beyond simple RBAC
- ✅ **Multi-Tenancy** - Hard isolation between tenants
- ✅ **Rate Limiting** - Token bucket per IP/tenant
- ✅ **Encryption at Rest** - AES-256-GCM with envelope encryption + AWS KMS
- ✅ **TLS/HTTPS** - TLS 1.2/1.3 via rustls
- ✅ **Security Headers** - CSP, X-Frame-Options, X-Content-Type-Options
- ✅ **CORS Support** - Configurable cross-origin resource sharing
- ✅ **Audit Logging** - Structured JSON for SIEM

### Operations

- ✅ **Health Checks** - `/health` and `/ready` endpoints
- ✅ **Metrics** - Prometheus-compatible `/metrics` with 25+ counters
- ✅ **Request Tracing** - X-Request-Id propagation for distributed tracing
- ✅ **Response Compression** - Gzip/deflate/brotli automatic compression
- ✅ **Graceful Shutdown** - SIGTERM handling with connection drain
- ✅ **Backup/Restore** - CLI commands for disaster recovery
- ✅ **TOML Configuration** - File-based config with env override

---

## Security

### Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SECURITY LAYERS                              │
├─────────────────────────────────────────────────────────────────────┤
│  TLS 1.2/1.3 (rustls)                           Transport Security  │
│  ├── Rate Limiting (token bucket)               DoS Protection      │
│  ├── Request Size Limits (10MB)                 Resource Protection │
│  ├── Request Timeouts (30s)                     Hang Protection     │
│  ├── Security Headers (CSP, X-Frame-Options)    Browser Security    │
│  ├── X-Request-Id Tracing                       Distributed Tracing │
│  ├── CORS Middleware                            Cross-Origin Policy │
│  ├── API Key / JWT Authentication               Identity            │
│  ├── Cedar Policy Authorization                 Access Control      │
│  ├── Input Validation                           Injection Defense   │
│  ├── Audit Logging                              Forensics           │
│  └── AES-256-GCM Encryption                     Data at Rest        │
│      └── KMS (env/AWS/Vault) + Circuit Breaker  Key Management      │
└─────────────────────────────────────────────────────────────────────┘
```

### Authentication

```bash
# Generate an API key
rustberg generate-key --name admin --roles admin,writer

# Use the key
curl -H "X-API-Key: rb_abc123..." https://localhost:8000/v1/namespaces
```

### Authorization (Cedar Policies)

```cedar
// Allow readers to list namespaces
permit(
  principal,
  action == Action::"ListNamespaces",
  resource
) when {
  principal.roles.contains("reader")
};

// Deny cross-tenant access
forbid(
  principal,
  action,
  resource
) when {
  principal.tenant_id != resource.tenant_id
};
```

---

## API

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `GET` | `/ready` | Readiness check with dependencies |
| `GET` | `/metrics` | Prometheus metrics |
| `GET` | `/v1/config` | Catalog configuration |
| `GET` | `/v1/namespaces` | List namespaces |
| `POST` | `/v1/namespaces` | Create namespace |
| `GET` | `/v1/namespaces/{ns}` | Get namespace |
| `POST` | `/v1/namespaces/{ns}` | Update namespace |
| `DELETE` | `/v1/namespaces/{ns}` | Delete namespace |
| `GET` | `/v1/namespaces/{ns}/tables` | List tables |
| `POST` | `/v1/namespaces/{ns}/tables` | Create table |
| `POST` | `/v1/namespaces/{ns}/register` | Register existing table |
| `GET` | `/v1/namespaces/{ns}/tables/{table}` | Load table |
| `DELETE` | `/v1/namespaces/{ns}/tables/{table}` | Drop table |
| `POST` | `/v1/namespaces/{ns}/tables/{table}` | Commit table update |
| `HEAD` | `/v1/namespaces/{ns}/tables/{table}` | Check table exists |
| `POST` | `/v1/namespaces/{ns}/tables/{table}/metrics` | Report metrics |
| `POST` | `/v1/tables/rename` | Rename table |
| `POST` | `/v1/transactions/commit` | Multi-table transaction |

### Example: Create a Table

```bash
curl -X POST https://localhost:8000/v1/namespaces/my_ns/tables \
  -H "Content-Type: application/json" \
  -H "X-API-Key: rb_abc123..." \
  -d '{
    "name": "my_table",
    "schema": {
      "type": "struct",
      "fields": [
        {"id": 1, "name": "id", "type": "long", "required": true},
        {"id": 2, "name": "data", "type": "string", "required": false}
      ]
    }
  }'
```

---

## Configuration

### TOML Configuration File

```toml
# rustberg.toml

[server]
host = "0.0.0.0"
port = 8000

[server.auth]
api_key_enabled = true
jwt_enabled = false

[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"

[storage]
# Single-node (local storage)
backend = "file:///var/lib/rustberg/data"

# K8s HA (S3-compatible)
# backend = "s3://rustberg-bucket/catalog?region=us-east-1"

[kms]
provider = "env"  # or "aws-kms", "vault"
cache_ttl_seconds = 300
circuit_breaker_enabled = true

[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200

[logging]
level = "info"
json_format = false
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTBERG_HOST` | `0.0.0.0` | Bind address |
| `RUSTBERG_PORT` | `8000` | Bind port |
| `RUSTBERG_WAREHOUSE` | - | Warehouse location |
| `RUSTBERG_TENANT_ID` | `default` | Default tenant |
| `RUSTBERG_NO_AUTH` | `false` | Disable authentication (dev only) |
| `RUSTBERG_TLS_CERT` | - | TLS certificate path |
| `RUSTBERG_TLS_KEY` | - | TLS key path |
| `RUSTBERG_INSECURE_HTTP` | `false` | Allow HTTP (dev only) |
| `RUSTBERG_MASTER_KEY` | - | Encryption master key (hex) |
| `RUST_LOG` | `info` | Log level |

---

## Deployment

### Production Checklist

- [ ] TLS enabled with valid certificates
- [ ] Authentication enabled (default - ensure `RUSTBERG_NO_AUTH` is NOT set)
- [ ] Master key stored securely (KMS recommended)
- [ ] Rate limiting configured appropriately
- [ ] Audit logging to persistent storage
- [ ] Health checks configured in orchestrator
- [ ] Backup schedule established

### Kubernetes

Rustberg supports both single-node (with PVC) and highly-available (with S3) deployments:

#### Single-Node (PVC Storage)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 1  # Single node only with file:// storage
  template:
    spec:
      containers:
        - name: rustberg
          image: ghcr.io/hupe1980/rustberg:latest
          ports:
            - containerPort: 8000
          env:
            - name: STORAGE_BACKEND
              value: "file:///var/lib/rustberg/data"
            - name: RUSTBERG_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: rustberg-secrets
                  key: master-key
          volumeMounts:
            - name: data
              mountPath: /var/lib/rustberg/data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: rustberg-data
```

#### High-Availability (S3/GCS/MinIO)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 3  # Multiple replicas with shared S3 storage
  template:
    spec:
      containers:
        - name: rustberg
          image: ghcr.io/hupe1980/rustberg:latest
          ports:
            - containerPort: 8000
          env:
            - name: STORAGE_BACKEND
              value: "s3://rustberg-bucket/catalog?region=us-east-1"
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: rustberg-secrets
                  key: aws-access-key
            - name: AWS_SECRET_ACCESS_KEY
              valueFrom:
                secretKeyRef:
                  name: rustberg-secrets
                  key: aws-secret-key
            - name: RUSTBERG_MASTER_KEY
              valueFrom:
                secretKeyRef:
                  name: rustberg-secrets
                  key: master-key
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 5
          readinessProbe:
            httpGet:
              path: /ready
              port: 8000
            initialDelaySeconds: 5
```

### Backup & Restore

```bash
# Create backup
rustberg backup --output /backup/rustberg-$(date +%Y%m%d).tar.gz

# Validate backup
rustberg validate-backup --input /backup/rustberg-20260123.tar.gz

# Restore (stops server first!)
rustberg restore --input /backup/rustberg-20260123.tar.gz --force
```

---

## CLI Reference

```bash
# Start server
rustberg [OPTIONS]

# Generate API key
rustberg generate-key --name <NAME> --tenant <TENANT> --roles <ROLES>

# Generate TLS certificate (development)
rustberg generate-cert --common-name localhost --output-dir /tmp/tls

# Generate sample configuration file
rustberg generate-config --output config.toml

# Generate OpenAPI specification
rustberg open-api --format yaml --output openapi.yaml

# Backup catalog
rustberg backup --output <FILE> --data-dir <DIR>

# Restore catalog
rustberg restore --input <FILE> --data-dir <DIR> [--force]

# Validate backup
rustberg validate-backup --input <FILE>

# Show status
rustberg status --data-dir <DIR>

# Run performance benchmark
rustberg benchmark --iterations 10
```

---

## Engine Compatibility

| Engine | Read | Write | Notes |
|--------|------|-------|-------|
| PyIceberg | ✅ | ✅ | Full support |
| Trino | ✅ | ✅ | Full support |
| DuckDB | ✅ | - | Read-only |

---

## Development

```bash
# Run tests
cargo test --all-features

# Run with debug logging
RUST_LOG=debug cargo run --all-features -- --insecure-http

# Format code
cargo fmt

# Lint
cargo clippy --all-features
```

---

## License

Apache License 2.0
