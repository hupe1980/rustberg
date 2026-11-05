+++
title = "Configuration"
description = "Every Rustberg setting: the TOML file, environment variables, and CLI flags, and which wins."
weight = 10
+++
## Configuration Sources

Priority, highest first:

1. **CLI arguments**
2. **Environment variables**
3. **TOML config file**
4. **Default values**

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

# Address ranges that are forwarding infrastructure rather than callers.
# Empty (the default) means X-Forwarded-For is not read at all and the caller's
# address is the TCP peer.
trusted_proxies = ["10.0.0.0/8"]

# Seconds to keep serving after SIGTERM, before draining. Zero (the default)
# drains immediately; set a few seconds behind a load balancer.
shutdown_delay_seconds = 0
```

#### `trusted_proxies`

Determines the client address for three consumers: the rate-limit bucket,
`context.source_ip` in Cedar policies, and audit records. It is a security
setting, not a rate-limiting option: a spoofable address is an authorization
bypass.

- Default (empty): `X-Forwarded-For` is ignored; the client is the TCP peer.
- With ranges: the chain is `X-Forwarded-For` plus the TCP peer, walked **from
  the right**, skipping hops inside a trusted range. The first untrusted address
  is the client.
- `X-Real-IP` is honoured only when the peer is trusted and no chain was sent.
- The leftmost entry is never trusted: a client can prepend its own.
- A range that does not parse is a **startup failure**.

#### `shutdown_delay_seconds`

Seconds to keep accepting requests after `SIGTERM`, before draining in-flight
requests.

- `0` (default): fine when nothing but the starter routes to the process
  (laptop, Docker Compose, systemd).
- Behind a load balancer, set a few seconds: removal from rotation and the
  signal happen together, and requests arriving before the removal propagates
  are refused (in Kubernetes: connection errors on every rolling update).
- A sleeping `preStop` hook cannot work — the image is distroless, with no shell.
- Applies to `SIGTERM` only, never `Ctrl+C`.
- Also settable as `--shutdown-delay` or `RUSTBERG_SHUTDOWN_DELAY` (the Helm
  chart uses this).
- After the delay, in-flight requests get 30 seconds on either transport.

Fixed, not configurable: request timeout (30 s), maximum body size (10 MB),
gzip compression. They protect the server from its clients.

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

# How far inside the warehouse a client-supplied location may point.
# "table" (default) or "warehouse" — see below. This is a security boundary.
location_scope = "table"
```

#### Where a client may put a table's files

`location_scope` bounds client-supplied locations: `location` on `createTable`
and `createView`, the file `registerTable` names, and `set-location` on a commit.

| | Bound | For |
|---|---|---|
| `"table"` | `<warehouse>/<namespace>/<name>` | Default. The layout the catalog assigns anyway |
| `"warehouse"` | the whole warehouse | Adopting a lake whose files are not where a name would put them |

The default is a **security boundary**: grants follow the namespace tree and
storage access is scoped to a path, so the two match only while files stay where
the name puts them. Under `"warehouse"`, a caller allowed to write one table can
point it at any warehouse prefix and receive a correctly-scoped credential for
it. Use it only where something outside Rustberg enforces isolation, or every
writer is trusted with the whole warehouse. See
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).

Either way, a resource may lay out files freely *under* its own prefix:
`s3://bucket/warehouse/db/events/data/2024/` is fine for table `db.events`.

#### Reaching the warehouse

`[storage.properties]` configures the object store the catalog uses for
metadata, by Iceberg property name. A `file://` warehouse needs nothing. An
object-store warehouse works without it only with ambient credentials; an
S3-compatible endpoint cannot be reached without it.

```toml
[storage.properties]
"s3.region"            = "eu-central-1"
"s3.access-key-id"     = "env:RUSTBERG_S3_ACCESS_KEY_ID"
"s3.secret-access-key" = "env:RUSTBERG_S3_SECRET_ACCESS_KEY"
```

`env:NAME` reads the value from that environment variable at startup, so the
file holds no secret. An unset or blank variable is a **startup failure**, as for
every other secret in the configuration.

MinIO, Ceph, Cloudflare R2 and other S3-compatible stores need the endpoint and
path-style addressing:

```toml
[storage.properties]
"s3.endpoint"          = "http://localhost:9000"
"s3.path-style-access" = "true"
"s3.region"            = "us-east-1"
```

One set of properties per process. Keys are scheme-prefixed, so S3 *and* GCS
compose; two accounts on the **same** cloud with different endpoints need a
process each.

When nothing is set, credentials may come from the ambient environment
(`AWS_REGION`, `GOOGLE_APPLICATION_CREDENTIALS`, `AZURE_STORAGE_ACCOUNT`, …).

### Authentication

Under `[server.auth]`. Both mechanisms may be enabled; JWT is tried first, then
API keys.

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

**`policy_file` only seeds an empty policy store.** After that, policy is a
versioned log changed through
[`PUT /management/v1/policies`](@/docs/authorization.md#administering-policy-at-runtime),
effective without a restart; the file does not overwrite it on start.

- File and store diverge: startup logs a warning naming the stored version.
- Effective policy set is empty: the server refuses to start.

#### API keys

Keys are configuration, not stored state — there is no key database. The secret
is read from an environment variable, so the file holds no usable credential:

```toml
[[server.auth.api_keys]]
name    = "spark-etl"      # appears in audit records
tenant  = "acme"
roles   = ["writer"]       # become Cedar groups
key_env = "RUSTBERG_KEY_SPARK"
```

An unset or empty variable is a startup failure. Rotation is a config change plus
a restart; for revocation without a restart, use JWT.

#### JWT / OIDC

```toml
[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg"]

# Omitted: the signing keys are found by reading the issuer's
# `/.well-known/openid-configuration`, whose own `issuer` is checked against the
# one above. Set `jwks_url` to skip discovery.

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

**Default: no origin allowed — leave it unless a browser application calls the
catalog directly.** Spark, Trino, PyIceberg and DuckDB are not browsers and are
unaffected.

```toml
[server.cors]
allowed_origins = ["https://dashboard.example.com"]
allowed_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
allowed_headers = ["*"]
```

An origin that fails to parse is dropped with a warning; it never widens the
policy.

> `allowed_origins = ["*"]` is **refused in production mode**: list your origins
> or pass `--dev`. Omitting the section allows no cross-origin request.

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

The client IP is determined by
[`[server] trusted_proxies`](#trusted-proxies).

What counts toward the lockout:

- **Counts:** a credential presented and rejected — wrong API key, JWT with a bad
  signature, expired or malformed. Signature verification is the costliest thing
  an unauthenticated caller can request.
- **Does not count:** a request with **no** credential (so a stray health checker
  cannot lock out its address).
- **Does not count:** a server-side failure, such as an unreachable identity
  provider.

### TLS

```toml
[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"

# Serve plaintext HTTP. Only behind a proxy that terminates TLS.
insecure_http = false
```

- Both paths omitted with `enabled = true`: a self-signed certificate is
  generated (development only).
- Only one path supplied: startup error.
- rustls only; no OpenSSL in the dependency tree (enforced by `cargo deny`).

### Audit

```toml
[audit]
sink = "stdout"      # stdout | file | none
# path = "/var/log/rustberg/audit.jsonl"   # required when sink = "file"

# Refuse a mutating request whose record could not be written.
fail_closed = true
```

Every authorization decision is one JSON object per line. See
[security](@/docs/security.md#audit).

### Credentials

Storage credential vending. Omitted (the default): nothing is vended and engines
use their own storage credentials — a common, fully supported deployment.

```toml,ignore
[credentials]
provider = "aws"        # none (default) | aws | gcs | azure

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
account (Reader for read-only). A vended SAS can only narrow those rights.

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
| `azure.tenant_id` | — | Entra tenant of the service principal |
| `azure.client_id` | — | Service principal's application ID |
| `azure.client_secret_env` | — | Variable holding the principal's secret |
| `azure.duration_seconds` | `3600` | Lifetime of a vended SAS |

**`allowed_prefixes`:** set it only to *narrow* vending below the warehouse. The
catalog refuses tables outside the warehouse, so a wider prefix authorizes
nothing it serves.

**Startup failures:** a provider with no matching section; a named environment
variable that is unset or empty; a provider whose Cargo feature
(`aws-credentials`, `gcp-credentials`, `azure-credentials`) is not compiled in.
Release binaries include all features.

See [security](@/docs/security.md#credential-vending) for the vended
credential's scope.

### Remote signing

The engine holds no credential; every object request is authorized and signed
here. Independent of `provider`: a deployment may offer signing, vending, both,
or neither, and the client chooses with `X-Iceberg-Access-Delegation`.

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

- Uses the same credential chain and `allowed_prefixes` as vending; no second set
  of secrets.
- A wrong `url_style` fails **closed**: the bucket is misread, containment does
  not match, and the request is refused rather than mis-signed.
- Enabling it without the `remote-signing` Cargo feature is a startup failure.
  Release binaries include all features.

See [the API reference](@/docs/api.md#remote-signing) for what is signed and
refused.

### Federation

> Conceptual overview, including what the mount table refuses and why:
> [Federation](@/docs/federation.md).


Mount other catalogs under this endpoint. Each mount claims a **top-level
namespace** and serves everything beneath it.

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

The mount name is **stripped** on the way down and restored on the way up. Names
no mount claims still reach the main catalog, so adding a mount does not disturb
existing names.

| Setting | Required | Meaning |
|---|---|---|
| `backend` | no (`native`) | `native` or `rest` |
| `catalog_url` | **yes** | Backend location — see below |
| `warehouse_location` | for `native` | Where this mount's tables live |
| `owner` | **yes** | Tenant that owns everything in the mount |
| `read_only` | no (`false`) | Refuse every mutation (`native` only). Reads, including [scan planning](@/docs/api.md#scan-planning), are unaffected; a `rest` mount has no declared warehouse for scan planning |
| `token_env` | no | Variable holding a bearer token (`rest` only) |

#### Backends

| `backend` | `catalog_url` | Capabilities |
|---|---|---|
| `native` | `file:///path`, `memory://`, or a Postgres DSN | Full, or read-only with `read_only = true` |
| `rest` | Base URI of an Iceberg REST catalog | **Read-only**, views negotiated from the remote |

A `rest` mount serves another Iceberg REST catalog:

```toml,ignore
[mount.partner]
backend     = "rest"
catalog_url = "https://catalog.partner.example"
owner       = "acme"
token_env   = "RUSTBERG_PARTNER_TOKEN"
```

- **Read-only.** Writes go to the catalog that owns them.
- **Capabilities are negotiated** from the remote's `GET /v1/config` at startup;
  a remote without view endpoints yields a mount that reports no views.
- **Unreachable at startup:** startup failure.
- `token_env` names a variable; the file carries no credential. Named but unset
  or blank: startup failure.

**Credential vending covers every mount.** With `allowed_prefixes` unset, a
provider may vend for the server's warehouse *and* each mount's. A `rest` mount
contributes nothing; Rustberg does not own its storage.

**Each mount governs its own warehouse.** A client-supplied table or view
location is confined to the warehouse of the mount it is created in, and a
resource created without a location defaults into that warehouse. The
confused-deputy boundary holds in both directions.

**`owner` is authoritative for the whole mount**, not a default; ownership is
never read from the mounted catalog's namespace properties. Set it to the rest of
the catalog's tenant unless the mount belongs to another one. A rename between
two tenants is refused regardless of mounts.

A mount that cannot be opened is a **startup failure**.

#### What is advertised

`GET /v1/config` publishes the **intersection** of what every mount supports. One
read-only mount removes every mutating endpoint from the list:

```console
$ curl -s localhost:8000/v1/config | jq '.endpoints | length'
7
```

Those operations still work on mounts that support them; refusal is per-request.
The intersection governs only what the catalog advertises, because clients
feature-detect once from one `endpoints` list.

#### What cannot cross a mount

| Operation | Across mounts |
|---|---|
| Read, list, load | Fine |
| Create, commit, drop | Fine *within* one mount |
| Rename a table or view | **Refused** (`501`) |
| Multi-table transaction | **Refused** (`501`) |

Neither can be made atomic between two independent catalogs.

### Logging

Application logs go to **stderr**, keeping stdout a clean stream of audit
records (`rustberg | jq` works).

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

Each variable is a CLI flag's `env` (clap reads both). They are **not** a general
TOML override: a setting with no flag has no variable and is set in the file.

Precedence: CLI flag, environment variable, config file, default.

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

Cloud SDK variables, read by the SDKs rather than Rustberg:

| Variable | Used for |
|----------|----------|
| `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | The server's own S3 access, and STS for credential vending |
| `GOOGLE_APPLICATION_CREDENTIALS` | GCS |
| `AZURE_STORAGE_ACCOUNT` | The server's own Azure access. Client credential vending is configured under `[credentials.azure]` |

Secrets named by a `*_env` setting (API keys, mount tokens, the Azure client
secret) are read from whatever variable that setting names, so one process can
hold several.

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
    healthcheck      Probe a running server's /ready and set the exit status
    bench            Measure the numbers this project claims, the way CI does
    help             Print help for a subcommand

OPTIONS:
    -c, --config <FILE>      Configuration file path
        --host <HOST>        Bind address [default: 0.0.0.0]
    -p, --port <PORT>        Listen port [default: 8000]
    -w, --warehouse <URL>    Warehouse location for table storage (see below)
        --catalog-url <URL>  Catalog database: file:///…, postgres://…, memory://
    -t, --tenant-id <ID>     Default tenant ID [default: default]
        --dev                Development mode (ephemeral catalog, relaxed checks)
        --no-auth            Disable authentication (NOT RECOMMENDED)
        --log-level <LEVEL>  Log level [default: info]
        --tls-cert <FILE>    TLS certificate path (PEM format)
        --tls-key <FILE>     TLS private key path (PEM format)
        --insecure-http      Allow HTTP (no TLS)
    -V, --version            Print version
    -h, --help               Print help
```

There is no `backup`, `restore` or `status` subcommand. Backup belongs to the
backend (stopped-server file copy for redb, `pg_dump` for Postgres; see
[catalog and warehouse](@/docs/storage.md#backup-and-restore)). Status is
`/health` and `/ready` on the running server.

`healthcheck` is for the distroless image's `HEALTHCHECK` (no shell, no `curl`).
It reads `/ready` on `127.0.0.1` at the server's port and exits non-zero unless
the answer is `200`:

```bash
rustberg healthcheck                                  # http://127.0.0.1:8000/ready
rustberg --port 9000 healthcheck                      # a different port
rustberg healthcheck --url https://catalog/ready      # anywhere else
```

Kubernetes does not need it: the Helm chart uses kubelet `httpGet` probes.

### Warehouse Location

`--warehouse` sets where table data files are stored:

| Format | Example | Description |
|--------|---------|-------------|
| Relative path | `file://warehouse` | Resolves to `file://<current_dir>/warehouse` |
| Absolute path | `file:///var/lib/data` | Local filesystem (absolute) |
| S3 | `s3://bucket/prefix` | Amazon S3 |
| GCS | `gs://bucket/prefix` | Google Cloud Storage |
| Azure | `abfss://fs@account.dfs.core.windows.net/prefix` | Azure Data Lake Storage |

> Local directories are created if missing; relative paths are made absolute.

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

Run with `--dev --no-auth`; production mode refuses wildcard CORS and
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
issuer       = "https://auth.company.com"
audiences    = ["rustberg"]
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

`catalog_url` is a **path on a volume**, not a bucket, even in Kubernetes; only
the warehouse lives in S3. See [storage](@/docs/storage.md#deployment-shape).

---

## Generate Config

```bash
./rustberg generate-config > rustberg.toml
```

---

## Next Steps

- [Getting Started](@/docs/getting-started.md) - Quick setup
- [Storage Backends](@/docs/storage.md) - Configure storage
- [Authentication](@/docs/authentication.md) - Secure access
