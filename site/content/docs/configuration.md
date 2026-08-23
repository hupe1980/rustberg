+++
title = "Configuration"
description = "Every Rustberg setting: the TOML file, environment variables, and CLI flags, and which wins."
weight = 10
+++
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
port = 8000

[storage]
catalog_url = "file:///var/lib/rustberg/data"
warehouse_location = "s3://my-bucket/warehouse"
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
host = "0.0.0.0"

# Listen port
port = 8000
```

Request timeout (30 s), maximum body size (10 MB) and gzip compression are fixed
rather than configurable. They are limits that protect the server from its
clients, and an operator who can raise them can also disable the protection by
accident; when a real deployment needs a different value, that is the point to
make it a setting.

### Storage Section

Two distinct locations — see [storage](@/docs/storage.md).

```toml
[storage]
# Where the catalog database lives. A local redb file: `file:///path` or
# `memory://`. Object-store URLs are rejected here.
catalog_url = "file:///var/lib/rustberg/data"

# Where tables live. Any scheme whose feature is compiled in:
# file://, s3://, gs://, abfss://
warehouse_location = "s3://my-bucket/warehouse"
```

#### Reaching the warehouse

`[storage.properties]` configures the object store the catalog reads and writes
metadata through, by Iceberg property name. A `file://` warehouse needs nothing
here; an object-store warehouse works without it only when the backend finds
ambient credentials, and an S3-compatible endpoint cannot be reached at all.

```toml
[storage.properties]
"s3.region"            = "eu-central-1"
"s3.access-key-id"     = "env:RUSTBERG_S3_ACCESS_KEY_ID"
"s3.secret-access-key" = "env:RUSTBERG_S3_SECRET_ACCESS_KEY"
```

A value written as `env:NAME` is read from that environment variable at startup,
so the file holds no secret and can be committed. A variable that is unset or
blank is a **startup failure**, not a silently absent property — the same rule
every other secret in the configuration follows.

MinIO, Ceph, Cloudflare R2 and anything else speaking the S3 API need the
endpoint and path-style addressing:

```toml
[storage.properties]
"s3.endpoint"          = "http://localhost:9000"
"s3.path-style-access" = "true"
"s3.region"            = "us-east-1"
```

This is one set of properties for the whole process. Keys are scheme-prefixed,
so a deployment spanning S3 *and* GCS composes fine; two accounts on the **same**
cloud with different endpoints do not, and need a process each.

Credentials may also come from the ambient environment
(`AWS_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_STORAGE_ACCOUNT`, …)
when nothing is set here.

### Authentication

Authentication lives under `[server.auth]`. Both mechanisms may be enabled at
once; JWT is tried first, then API keys.

```toml
[server.auth]
# Accept API keys (default: true)
api_key_enabled = true

# Accept OIDC/JWT bearer tokens (default: false)
jwt_enabled = false

# Cedar policy file. When unset, the built-in default policies apply. When set,
# the file REPLACES them — the defaults are not merged in, because silently
# unioning your policies with grants you did not write is how an authorization
# system permits more than its operator believes. Policies are validated at
# startup; one that does not typecheck is a startup failure rather than a rule
# that silently never matches.
policy_file = "/etc/rustberg/policies/catalog.cedar"
```

**`policy_file` seeds an empty policy store and is then no longer
authoritative.** Policy is stored as a versioned log and changed through
[`PUT /management/v1/policies`](@/docs/authorization.md#administering-policy-at-runtime),
which takes effect without a restart. If the file won on every start, every
change made through the API would vanish the moment a pod restarted.

When the file and the store diverge, startup logs a warning naming the stored
version. A server whose effective policy set contains no policies refuses to
start: it would accept nobody, including anyone trying to repair it.

#### API keys

Keys are configuration, not stored state — there is no key database to encrypt
or back up. The secret is read from an environment variable, so this file holds
no usable credential:

```toml
[[server.auth.api_keys]]
name    = "spark-etl"      # appears in audit records
tenant  = "acme"
roles   = ["writer"]       # become Cedar groups
key_env = "RUSTBERG_KEY_SPARK"
```

A referenced variable that is unset or empty is a startup failure. Rotation is a
config change plus a restart; if you need revocation without a restart, use JWT.

#### JWT / OIDC

```toml
[server.auth.jwt]
issuer   = "https://auth.example.com"
audience = "rustberg"
jwks_url = "https://auth.example.com/.well-known/jwks.json"

# Claim carrying the tenant; used for isolation. A dotted path addresses a
# nested object, and the longest literal key wins — so a namespaced claim whose
# name contains dots resolves as itself.
tenant_claim = "tenant"
# Claim carrying roles; each becomes a Cedar group. Keycloak: "realm_access.roles"
roles_claim = "groups"
# Fallback tenant when the claim is absent
default_tenant_id = "default"
# How long to cache JWKS
jwks_cache_ttl_seconds = 3600

# Your IdP's token endpoint, advertised to clients as `oauth2-server-uri` in
# /v1/config. Rustberg does not issue tokens — see
# /rustberg/docs/authentication#rustberg-does-not-issue-tokens
oauth2_server_uri = "https://auth.example.com/oauth2/token"
```

### CORS

**The default is to allow no origin, and most deployments should leave it there.**
CORS is enforced by browsers; Spark, Trino, PyIceberg and DuckDB are not browsers
and are unaffected by this setting. Configure it only if a browser application
calls the catalog directly.

```toml
[server.cors]
allowed_origins = ["https://dashboard.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
allowed_headers = ["*"]
```

An origin that fails to parse is dropped with a warning rather than widening the
policy — a typo in one entry does not turn a restrictive configuration into an
open one.

> `allowed_origins = ["*"]` is **refused in production mode**. Either list your
> origins or pass `--dev`. It is not the default: omitting the section entirely
> allows no cross-origin request, which is the safe answer and the usual one.

### Rate limiting

```toml
[rate_limit]
enabled = true
requests_per_second = 100   # per client IP
burst_size = 200

# Lock out an IP after repeated authentication failures
track_auth_failures = true
max_auth_failures = 5
lockout_duration_seconds = 300
```

### TLS

```toml
[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"

# Serve plaintext HTTP. Only behind a proxy that terminates TLS.
insecure_http = false
```

Omitting both paths with `enabled = true` generates a self-signed certificate —
useful for development only. Supplying one path without the other is a startup
error rather than a silent fallback. Rustberg is rustls-only; there is no
OpenSSL in the dependency tree.

### Audit

```toml
[audit]
sink = "stdout"      # stdout | file | none
# path = "/var/log/rustberg/audit.jsonl"   # required when sink = "file"

# Refuse a mutating request whose record could not be written.
fail_closed = true
```

Every authorization decision is recorded as one JSON object per line. See
[security](@/docs/security.md#audit).

### Credentials

Storage credential vending. Omit the section entirely — the default — and
nothing is vended; engines use their own storage credentials, which is the
common deployment and not a lesser one.

```toml,ignore
[credentials]
provider = "aws"        # none (default) | aws | gcs

# Locations this server may ever mint a credential for.
# Left unset, this is exactly `storage.warehouse_location`.
# allowed_prefixes = ["s3://my-bucket/warehouse/public"]

[credentials.aws]
region   = "us-east-1"
role_arn = "arn:aws:iam::123456789012:role/RustbergVending"
# Environment variable holding the STS external ID (cross-account assumption).
# Named, not inlined, so this file holds no secret.
external_id_env  = "RUSTBERG_STS_EXTERNAL_ID"
duration_seconds = 3600
```

For GCS:

```toml,ignore
[credentials]
provider = "gcs"

[credentials.gcs]
service_account_key_path = "/etc/rustberg/gcp-service-account.json"
```

For Azure:

```toml,ignore
[credentials]
provider = "azure"

[credentials.azure]
account           = "mystorageaccount"
tenant_id         = "00000000-0000-0000-0000-000000000000"
client_id         = "11111111-1111-1111-1111-111111111111"
client_secret_env = "RUSTBERG_AZURE_CLIENT_SECRET"
duration_seconds  = 3600
```

The Entra service principal needs **Storage Blob Data Contributor** on the
account (or Reader, for a read-only deployment). A vended SAS can only narrow
those rights, never widen them.

| Setting | Default | Meaning |
|---|---|---|
| `provider` | `none` | `none`, `aws`, `gcs`, or `azure` |
| `allowed_prefixes` | the warehouse | Locations vending is permitted for |
| `aws.region` | — | Region for the STS endpoint |
| `aws.role_arn` | — | Role to assume; needs access to the warehouse |
| `aws.external_id_env` | none | Variable holding the STS external ID |
| `aws.duration_seconds` | `3600` | Lifetime of a vended credential |
| `gcs.service_account_key_path` | — | Service-account JSON used as the exchange input |
| `azure.account` | — | Storage account name, without the domain |
| `azure.tenant_id` | — | Entra tenant the service principal lives in |
| `azure.client_id` | — | Service principal's application ID |
| `azure.client_secret_env` | — | Variable holding the principal's secret |
| `azure.duration_seconds` | `3600` | Lifetime of a vended SAS |

**`allowed_prefixes` defaults to the warehouse, and that is the right default.**
The catalog already refuses to record a table outside the warehouse, so a wider
prefix could only ever authorize a location it will not serve. Set it only to
*narrow* vending below the warehouse.

Misconfiguration is a **startup failure**, never a server that comes up vending
nothing while the config says otherwise: a provider with no matching section, a
named environment variable that is unset or empty, or a provider whose Cargo
feature (`aws-credentials`, `gcp-credentials`, `azure-credentials`) was not
compiled in. Release binaries are built with all features.

See [security](@/docs/security.md#credential-vending) for what the vended
credential is actually scoped to.

### Remote signing

The other delegation form: the engine holds no credential at all, and every
object request is authorized and signed here. Independent of `provider` — a
deployment may offer signing, vending, both, or neither, and the client picks
with `X-Iceberg-Access-Delegation`.

```toml,ignore
[credentials.signing]
enabled = true

# Region to sign for when a client sends none. Clients normally send the region
# they resolved, and that value is used.
region = "eu-central-1"

# How to read a bucket out of a request URI: auto | path | virtual-host.
# `auto` recognises AWS's own hostnames and falls back to path style, which is
# what MinIO, Ceph and R2 use.
url_style = "auto"

# Host of a custom S3 endpoint, so `auto` can tell `minio:9000/bucket/key`
# (path style) from `bucket.minio:9000/key` (virtual-host style).
# endpoint_host = "minio:9000"
```

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve `POST …/tables/{table}/sign` |
| `region` | `credentials.aws.region`, else `us-east-1` | Region used when a client sends none |
| `url_style` | `auto` | `auto`, `path`, or `virtual-host` |
| `endpoint_host` | none | Host of a custom S3 endpoint |

Signing uses the same credential chain and the same `allowed_prefixes` as
vending, so there is no second set of secrets. Getting `url_style` wrong fails
**closed**: the bucket is read from the wrong place, containment does not match
the table, and the request is refused rather than mis-signed.

Enabling this without the `remote-signing` Cargo feature is a startup failure.
Release binaries are built with all features.

See [the API reference](@/docs/api.md#remote-signing) for what is signed and what
is refused.

### Federation

> Conceptual overview, including what the mount table refuses and why:
> [Federation](@/docs/federation.md).


Mount other catalogs under this endpoint. Each mount claims a **top-level
namespace**; everything beneath it is served by that backend.

```toml,ignore
[mount.prod]
backend            = "native"
catalog_url        = "postgres://user:pw@host/prod"
warehouse_location = "s3://prod-bucket/warehouse"
owner              = "acme"

[mount.legacy]
backend            = "native"
catalog_url        = "file:///var/lib/rustberg/legacy"
warehouse_location = "s3://legacy-bucket/warehouse"
owner              = "acme"
read_only          = true
```

```text
prod.analytics.events   →  mount "prod"  →  namespace analytics.events
scratch.tmp             →  unmounted     →  storage.catalog_url
```

The mount name is **stripped** on the way down and restored on the way up: a
mounted catalog has its own namespaces and has never heard of the name it is
mounted under. Mounting is additive — names no mount claims still reach the main
catalog, so adding a mount does not disturb what was already there.

| Setting | Required | Meaning |
|---|---|---|
| `backend` | no (`native`) | `native` or `rest` |
| `catalog_url` | **yes** | Backend location — see below |
| `warehouse_location` | for `native` | Where this mount's tables live |
| `owner` | **yes** | Tenant that owns everything in the mount |
| `read_only` | no (`false`) | Refuse every mutation (`native` only) |
| `token_env` | no | Variable holding a bearer token (`rest` only) |

#### Backends

| `backend` | `catalog_url` | Capabilities |
|---|---|---|
| `native` | `file:///path`, `memory://`, or a Postgres DSN | Full, or read-only with `read_only = true` |
| `rest` | Base URI of an Iceberg REST catalog | **Read-only**, views negotiated from the remote |

A `rest` mount serves somebody else's Iceberg REST catalog:

```toml,ignore
[mount.partner]
backend     = "rest"
catalog_url = "https://catalog.partner.example"
owner       = "acme"
token_env   = "RUSTBERG_PARTNER_TOKEN"
```

It is **read-only**: reads are what federation is for — one endpoint, one
identity, over catalogs that already exist — while a write that lands in a
catalog Rustberg does not own is a different promise from one it does. Writes go
to the catalog that owns them.

Its capabilities are **negotiated**, not assumed: Rustberg reads the remote's own
`GET /v1/config` at startup, and a remote serving no view endpoints produces a
mount that reports no views, rather than one that offers them and fails on use.

A `rest` mount that cannot be reached at startup is a **startup failure**. A
subtree that silently looks empty is indistinguishable from one you may not see.

`token_env` names an environment variable rather than holding the token, so this
file carries no credential. A variable that is named but unset or blank is a
startup failure — not an anonymous connection that fails later with the remote's
`401`.

**Credential vending covers every mount.** With `allowed_prefixes` unset, a
provider may vend for the server's warehouse *and* each mount's — so a table in
a mount gets credentials like any other. A `rest` mount contributes nothing:
Rustberg does not own a remote catalog's storage.

**Each mount governs its own warehouse.** A client-supplied table or view
location is confined to the warehouse of the mount it is being created in — not
to the server's — and a table or view created *without* an explicit location
defaults into that mount's warehouse too. Checking against a single warehouse would reject every
legitimate table in every mount that stores its data elsewhere, which is all of
them; and a mount does not govern anywhere *else*, so the confused-deputy
boundary is intact in both directions.

**`owner` is authoritative for the whole mount**, not a default. A mount is a
separate catalog whose namespace properties Rustberg does not control, so
reading ownership from inside it would let whoever can write there decide who
owns it here. Set it to the same tenant as the rest of the catalog unless you
mean the mount to belong to a different one — a rename between two tenants is
refused regardless of mounts.

A mount that cannot be opened is a **startup failure**. A namespace subtree that
silently does not exist is worse than a server that refuses to come up.

#### What is advertised

`GET /v1/config` publishes the **intersection** of what every mount supports.
One read-only mount removes every mutating endpoint from the advertised list:

```console
$ curl -s localhost:8000/v1/config | jq '.endpoints | length'
7
```

Those operations still work on the mounts that support them — the refusal is
per-request, not per-server. What the intersection governs is only what the
catalog *promises*, because `endpoints` is one list and a client feature-detects
from it once.

#### What cannot cross a mount

| Operation | Across mounts |
|---|---|
| Read, list, load | Fine |
| Create, commit, drop | Fine *within* one mount |
| Rename a table or view | **Refused** (`501`) |
| Multi-table transaction | **Refused** (`501`) |

Neither can be made atomic between two independent catalogs. Rustberg could
sequence them and usually get away with it; it would also, sometimes, leave a
table dropped from one catalog and never created in the other.

### Logging

Application logs go to **stderr**. That is what keeps stdout a clean stream of
audit records, so `rustberg serve | jq` works and a log shipper reading the audit
trail never has to filter human-readable lines out of it.

```toml
[logging]
# A bare level, or a full RUST_LOG filter such as
# "rustberg=debug,tower_http=info,warn".
level = "info"
# One JSON object per log line, for SIEM ingestion. This is the *application*
# log; the audit trail is configured separately under [audit].
json_format = true
# Emit an event when a span opens and closes.
with_span_events = true
```

`--log-level` and the `RUST_LOG` environment variable override `level`.

---

## Environment variables

Environment variables set the same things the CLI flags do — clap reads both, so
each variable is the flag's `env`. They are **not** a general override for the
TOML file: anything with no flag has no variable, and is set in the file.

Precedence is CLI flag, then environment variable, then config file, then the
default.

| Variable | Equivalent flag | Description |
|----------|-----------------|-------------|
| `RUSTBERG_CONFIG` | `--config` | Path to the TOML configuration file |
| `RUSTBERG_HOST` | `--host` | Bind address. Default `0.0.0.0` |
| `RUSTBERG_PORT` | `--port` | Listen port. Default `8000` |
| `RUSTBERG_CATALOG_URL` | `--catalog-url` | `file:///path`, `postgres://…` or `memory://` |
| `RUSTBERG_WAREHOUSE` | `--warehouse` | Warehouse root |
| `RUSTBERG_TENANT_ID` | `--tenant-id` | Default tenant. Default `default` |
| `RUSTBERG_TLS_CERT` | `--tls-cert` | TLS certificate, PEM |
| `RUSTBERG_TLS_KEY` | `--tls-key` | TLS private key, PEM |
| `RUSTBERG_INSECURE_HTTP` | `--insecure-http` | Serve plaintext HTTP |
| `RUSTBERG_DEV` | `--dev` | Development mode |
| `RUSTBERG_NO_AUTH` | `--no-auth` | Disable authentication — development only |
| `RUST_LOG` | `--log-level` | Log verbosity. Default `info` |

Cloud SDK variables are read by the SDKs themselves, not by Rustberg:

| Variable | Used for |
|----------|----------|
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | The server's own S3 access, and STS for credential vending |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCS |
| `AZURE_STORAGE_ACCOUNT` | The server's own Azure access. Client credential vending is configured under `[credentials.azure]` |

Secrets named by a `*_env` setting — API keys, mount tokens, the Azure client
secret — are read from whatever variable that setting names. They are
deliberately not fixed names, so one process can hold several.

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
| Azure | `abfss://fs@account.dfs.core.windows.net/prefix` | Azure Data Lake Storage |

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
port = 8000

[storage]
catalog_url = "memory://"
warehouse_location = "file:///tmp/rustberg-warehouse"

[tls]
enabled = false
insecure_http = true

[logging]
level = "debug"
json_format = false
```

Run it with `--dev --no-auth`; production mode refuses wildcard CORS and
`--no-auth`.

### Single-node production

```toml
[server]
host = "0.0.0.0"
port = 8000

[server.cors]
allowed_origins = ["https://analytics.example.com"]

[server.auth]
api_key_enabled = true
policy_file = "/etc/rustberg/policies/catalog.cedar"

[[server.auth.api_keys]]
name    = "spark-etl"
tenant  = "acme"
roles   = ["writer"]
key_env = "RUSTBERG_KEY_SPARK"

[storage]
catalog_url = "file:///var/lib/rustberg/data"
warehouse_location = "s3://my-bucket/warehouse"

[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"
insecure_http = false

[logging]
level = "info"
json_format = true
```

### Kubernetes with OIDC

```toml
[server]
host = "0.0.0.0"
port = 8000

[server.cors]
allowed_origins = ["https://analytics.example.com"]

[server.auth]
api_key_enabled = false
jwt_enabled = true
policy_file = "/etc/rustberg/policies/catalog.cedar"

[server.auth.jwt]
issuer     = "https://auth.company.com"
audience   = "rustberg"
jwks_url   = "https://auth.company.com/.well-known/jwks.json"
tenant_claim = "tenant"
roles_claim  = "groups"

[storage]
catalog_url = "file:///var/lib/rustberg/data"   # a PersistentVolume
warehouse_location = "s3://my-bucket/warehouse"

[tls]
enabled = false
insecure_http = true    # TLS terminated at the ingress

[rate_limit]
enabled = true
requests_per_second = 1000

[logging]
level = "info"
json_format = true
```

Note `catalog_url` is a **path on a volume**, not a bucket, even in Kubernetes.
The catalog is a local file; the warehouse is what lives in S3. See
[storage](@/docs/storage.md#deployment-shape).

---

## Generate Config

Generate a sample configuration file:

```bash
./rustberg generate-config > rustberg.toml
```

---

## Next Steps

- [Getting Started](@/docs/getting-started.md) - Quick setup
- [Storage Backends](@/docs/storage.md) - Configure storage
- [Authentication](@/docs/authentication.md) - Secure access
