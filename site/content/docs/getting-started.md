+++
title = "Getting started"
description = "Install Rustberg, start a catalog with one command, and connect an engine to it."
weight = 1
+++
One command brings up a working catalog. The rest of this page is what to do
with it, and what to change before it holds anything you care about.

## Install

### Pre-built binary

Nothing to install underneath it — no JVM, no database, no runtime.

Releases carry one archive per platform, each holding a single executable.

```bash
# Pick one: linux-x86_64, linux-aarch64, darwin-aarch64
TARGET=linux-x86_64

curl -L "https://github.com/hupe1980/rustberg/releases/latest/download/rustberg-$TARGET.tar.gz" \
  | tar -xz
mv "rustberg-$TARGET" rustberg
```

Every release also publishes `checksums.txt`.

The Linux builds are statically linked against musl, so there is nothing to
install underneath — no JVM, no database, no runtime.

Releases cover **Linux and macOS**. Anywhere else, including Windows, run the
container: it carries the same statically linked binary, and it is what CI
starts and probes on every change.

### Docker

```bash
docker pull ghcr.io/hupe1980/rustberg:latest
docker run -d -p 8000:8000 --name rustberg ghcr.io/hupe1980/rustberg:latest
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

See [Kubernetes documentation](@/docs/kubernetes.md) for full configuration options.

### From source

Requires Rust 1.94.1 or newer.

```bash
git clone https://github.com/hupe1980/rustberg.git
cd rustberg
cargo build --release --all-features
./target/release/rustberg --version
```

## Run it

### 1. Start the server

```bash
./rustberg --dev --insecure-http
```

Authentication is on by default. With nothing configured to authenticate against,
Rustberg mints one admin key at startup and prints it:

```text
WARN rustberg: No API keys or OIDC configured — minted a temporary admin key.
WARN rustberg:
WARN rustberg:     X-API-Key: rb_sOYl2CxcSLwECS2K8Ri8Y14JgqsBpYydrX7hZqVRxrc
WARN rustberg:
WARN rustberg:     curl -H 'X-API-Key: rb_sOYl…' http://localhost:8000/v1/config
WARN rustberg:
WARN rustberg: This key is held in memory only. Restarting mints a new one and
WARN rustberg: invalidates this one.
```

> **The key changes on every restart.** It lives in memory only — keys are
> configuration, not stored state. Configure `[[server.auth.api_keys]]` or OIDC
> before relying on a deployment. See [authentication](@/docs/authentication.md).

`--dev` gives an ephemeral catalog in a temp directory and allows plaintext HTTP.
Production mode — the default — requires an explicit `--catalog-url` and refuses
wildcard CORS, so real metadata never lands in a directory that disappears on
reboot and a development shortcut cannot reach production by inertia.

### 2. Check the connection

```bash
export API_KEY=rb_...   # from the startup banner (a shell variable, not one Rustberg reads)

curl -H "X-API-Key: $API_KEY" http://localhost:8000/v1/config
```

```json
{
  "overrides": { "warehouse": "..." },
  "defaults": {},
  "endpoints": ["GET /v1/{prefix}/namespaces", "..."],
  "idempotency-key-lifetime": "PT24H"
}
```

Either header works, and both carry the same key:

| Header | Use |
|--------|-----|
| `X-API-Key: rb_…` | Explicit; what these examples use |
| `Authorization: Bearer rb_…` | What Iceberg clients send — PyIceberg, Spark and Trino put their `token` property here |

### 3. Create a namespace and a table

```bash
curl -X POST http://localhost:8000/v1/namespaces \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"namespace": ["analytics"]}'

curl -X POST http://localhost:8000/v1/namespaces/analytics/tables \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"name": "events",
          "schema": {"type": "struct",
                     "fields": [{"id": 1, "name": "id", "type": "long", "required": true}]}}'
```

### 4. Connect a client

```python
from pyiceberg.catalog.rest import RestCatalog

catalog = RestCatalog("rustberg", uri="http://localhost:8000", token="rb_...")
print(catalog.list_namespaces())
```

See [clients](@/docs/clients.md) for Spark, Trino and DuckDB.

### Check who you are

If a request is unexpectedly refused, ask what identity the server sees:

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/auth/context
```

The `roles` it reports are the Cedar groups your policies must name. A policy
naming `Group::"analysts"` matches nothing if the key carries `analyst`.

---

## Production Deployment

### Single-Node (Persistent Storage)

```bash
# Create the catalog directory
mkdir -p /var/lib/rustberg/data

# Start with the embedded redb catalog
./rustberg \
    --catalog-url file:///var/lib/rustberg/data \
    --warehouse s3://my-bucket/warehouse \
    --host 0.0.0.0 \
    --port 8000

# Or use a config file
./rustberg --config /etc/rustberg/config.toml
```

Without `--catalog-url` (or `storage.catalog_url` in a config file) the server
refuses to start rather than writing to a temporary directory it will lose. Pass
`--dev` if an ephemeral catalog is what you want.

### Kubernetes (Postgres catalog, S3 warehouse)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 3   # stateless: the catalog is in Postgres
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
        - containerPort: 8000
        env:
        - name: RUSTBERG_CATALOG_URL
          valueFrom:
            secretKeyRef:
              name: rustberg-catalog
              key: dsn
        - name: RUSTBERG_WAREHOUSE
          value: "s3://my-bucket/warehouse"
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

### Environment variables

Every CLI flag has one. The full list is in
[configuration](@/docs/configuration.md#environment-variables); these are the
ones a first deployment needs.

| Variable | Description | Default |
|----------|-------------|---------|
| `RUSTBERG_HOST` | Bind address | `0.0.0.0` |
| `RUSTBERG_PORT` | Listen port | `8000` |
| `RUSTBERG_CATALOG_URL` | Catalog: `file:///path`, `postgres://…` or `memory://` | none — required outside `--dev` |
| `RUSTBERG_WAREHOUSE` | Warehouse root | none |
| `RUST_LOG` | Log verbosity | `info` |
| `RUSTBERG_DEV` | Development mode | `false` |
| `RUSTBERG_NO_AUTH` | Disable authentication — development only | `false` |

### TOML Configuration

```toml
# /etc/rustberg/config.toml

[server]
host = "0.0.0.0"
port = 8000

[server.cors]
allowed_origins = ["https://analytics.example.com"]

[server.auth]
api_key_enabled = true

[[server.auth.api_keys]]
name    = "spark-etl"
tenant  = "acme"
roles   = ["writer"]
key_env = "RUSTBERG_KEY_SPARK"

[storage]
# A local file for the catalog; the bucket is the warehouse, not the catalog.
catalog_url = "file:///var/lib/rustberg/data"
warehouse_location = "s3://my-bucket/warehouse"

[rate_limit]
requests_per_second = 100
burst_size = 200

[logging]
level = "info"
json_format = true
```

---

## Client Integration

### PyIceberg

```python
from pyiceberg.catalog import load_catalog

catalog = load_catalog(
    "rustberg",
    **{
        "uri": "http://localhost:8000",
        "token": "rb_...",
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
spark.conf.set("spark.sql.catalog.rustberg.uri", "http://localhost:8000")
spark.conf.set("spark.sql.catalog.rustberg.token", "rb_...")

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
iceberg.rest-catalog.uri=http://rustberg:8000
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.token=rb_...
```

```sql
-- Query tables
SELECT * FROM rustberg.analytics.events LIMIT 10;
```

---

## Next Steps

- [Authentication Guide](@/docs/authentication.md) - API keys, JWT, OAuth
- [Authorization Guide](@/docs/authorization.md) - Cedar policies
- [Storage Backends](@/docs/storage.md) - S3, GCS, Azure, local
- [Encryption Guide](@/docs/encryption.md) - what is encrypted, and what is not
- [API Reference](@/docs/api.md) - Full REST API documentation

---

## Troubleshooting

Having issues? See the [Troubleshooting Guide](@/docs/troubleshooting.md) for solutions to common problems.

---

## Getting Help

- [GitHub Issues](https://github.com/hupe1980/rustberg/issues) - Bug reports and feature requests
