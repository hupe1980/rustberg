---
layout: default
title: Getting Started
nav_order: 2
description: "Quick start guide for Rustberg Apache Iceberg REST Catalog"
permalink: /docs/getting-started
---

# Getting Started
{: .no_toc }

Get Rustberg running in under 5 minutes.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Prerequisites

- **Rust 1.85+** (for building from source)
- **Docker** (optional, for integration testing)

---

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform:

```bash
# Linux (x86_64)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-linux-x86_64 -o rustberg

# Linux (ARM64)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-linux-aarch64 -o rustberg

# macOS (Apple Silicon)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-darwin-aarch64 -o rustberg

# Windows (x86_64)
curl -L https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-windows-x86_64.exe -o rustberg.exe

# Make executable (Linux/macOS)
chmod +x rustberg
```

### Docker

```bash
docker pull ghcr.io/hupe1980/rustberg:latest
docker run -d -p 8181:8181 --name rustberg ghcr.io/hupe1980/rustberg:latest
```

### Helm Chart (Kubernetes)

```bash
# Clone and install
git clone https://github.com/hupe1980/rustberg
helm install rustberg rustberg/charts/rustberg

# With S3 backend
helm install rustberg charts/rustberg \
  --set rustberg.storage.type=s3 \
  --set rustberg.storage.s3.bucket=my-catalog-bucket
```

See [Kubernetes documentation](/rustberg/docs/kubernetes) for full configuration options.

### From Source (Development)

```bash
# Clone repository
git clone https://github.com/hupe1980/rustberg.git
cd rustberg

# Build release binary
cargo build --release --all-features

# Binary location
./target/release/rustberg --version
```

---

## Quick Start

### 1. Start the Server

```bash
# Development mode (in-memory, auto-generated API key)
./rustberg

# Output:
# ⚠️  DEMO MODE: Using auto-generated API key
# Demo API Key: rustberg_xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# 🚀 Rustberg listening on https://127.0.0.1:8181
```

{: .warning }
> Demo mode generates a new API key on each restart. For production, use persistent storage.

### 2. Test the Connection

```bash
# Get catalog configuration
curl -H "Authorization: Bearer rustberg_xxxxx" \
     http://localhost:8181/v1/config

# Expected response:
# {"defaults":{},"overrides":{}}
```

### 3. Create a Namespace

```bash
curl -X POST http://localhost:8181/v1/namespaces \
     -H "Authorization: Bearer rustberg_xxxxx" \
     -H "Content-Type: application/json" \
     -d '{"namespace": ["analytics"], "properties": {}}'
```

---

## Production Deployment

### Single-Node (Persistent Storage)

```bash
# Create data directory
mkdir -p /var/lib/rustberg

# Start with file:// backend
./rustberg \
    --storage file:///var/lib/rustberg \
    --host 0.0.0.0 \
    --port 8181

# Or use a config file
./rustberg --config /etc/rustberg/config.toml
```

### Kubernetes (S3 Backend)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rustberg
  template:
    metadata:
      labels:
        app: rustberg
    spec:
      containers:
      - name: rustberg
        image: ghcr.io/hupe1980/rustberg:latest
        ports:
        - containerPort: 8181
        env:
        - name: RUSTBERG_STORAGE
          value: "s3://my-bucket/rustberg-catalog"
        - name: AWS_REGION
          value: "us-east-1"
        resources:
          requests:
            memory: "32Mi"
            cpu: "100m"
          limits:
            memory: "128Mi"
            cpu: "500m"
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RUSTBERG_HOST` | Bind address | `127.0.0.1` |
| `RUSTBERG_PORT` | Listen port | `8181` |
| `RUSTBERG_STORAGE` | Storage backend URL | `memory://` |
| `RUSTBERG_LOG_LEVEL` | Log verbosity | `info` |
| `RUSTBERG_MASTER_KEY` | Encryption key (base64) | None |

### TOML Configuration

```toml
# /etc/rustberg/config.toml

[server]
host = "0.0.0.0"
port = 8181
request_timeout_secs = 30

[storage]
object_store_url = "s3://my-bucket/rustberg-catalog"
aws_region = "us-east-1"

[auth]
require_authentication = true
api_key_prefix = "rustberg_"

[rate_limit]
requests_per_second = 100
burst_size = 200

[logging]
level = "info"
format = "json"
```

---

## Client Integration

### PyIceberg

```python
from pyiceberg.catalog import load_catalog

catalog = load_catalog(
    "rustberg",
    **{
        "uri": "http://localhost:8181",
        "credential": "rustberg_your_api_key_here",
    }
)

# List namespaces
namespaces = catalog.list_namespaces()
print(namespaces)

# Create table
from pyiceberg.schema import Schema
from pyiceberg.types import NestedField, StringType, LongType

schema = Schema(
    NestedField(1, "id", LongType(), required=True),
    NestedField(2, "name", StringType(), required=False),
)

table = catalog.create_table(
    "analytics.users",
    schema=schema,
    location="s3://my-data/users",
)
```

### Spark

```scala
spark.conf.set("spark.sql.catalog.rustberg", "org.apache.iceberg.spark.SparkCatalog")
spark.conf.set("spark.sql.catalog.rustberg.type", "rest")
spark.conf.set("spark.sql.catalog.rustberg.uri", "http://localhost:8181")
spark.conf.set("spark.sql.catalog.rustberg.credential", "rustberg_your_api_key")

// Use the catalog
spark.sql("USE rustberg")
spark.sql("CREATE NAMESPACE analytics")
spark.sql("CREATE TABLE analytics.events (id LONG, event STRING) USING iceberg")
```

### Trino

```properties
# catalog/rustberg.properties
connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=http://rustberg:8181
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.credential=rustberg_your_api_key
```

```sql
-- Query tables
SELECT * FROM rustberg.analytics.events LIMIT 10;
```

---

## Next Steps

- [Authentication Guide](/rustberg/docs/authentication) - API keys, JWT, OAuth
- [Authorization Guide](/rustberg/docs/authorization) - Cedar policies, RBAC
- [Storage Backends](/rustberg/docs/storage) - S3, GCS, Azure, local
- [Encryption Guide](/rustberg/docs/encryption) - KMS, envelope encryption
- [API Reference](/rustberg/docs/api) - Full REST API documentation

---

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Find process using port
lsof -i :8181

# Use different port
./rustberg --port 8182
```

**Permission denied on storage:**
```bash
# Check directory permissions
ls -la /var/lib/rustberg

# Fix permissions
sudo chown -R $(whoami) /var/lib/rustberg
```

**S3 authentication failed:**
```bash
# Verify AWS credentials
aws sts get-caller-identity

# Set credentials explicitly
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

---

## Getting Help

- [GitHub Issues](https://github.com/hupe1980/rustberg/issues) - Bug reports and feature requests
- [GitHub Discussions](https://github.com/hupe1980/rustberg/discussions) - Questions and community
