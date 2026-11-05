+++
title = "Catalog and warehouse"
description = "Where Rustberg keeps the catalog — an embedded redb file or Postgres — and where the tables themselves live."
weight = 7
+++
Rustberg stores two different things in two places. Confusing them is the most
common misconfiguration.

## Two locations, not one

| | What it holds | Where it lives | Config key |
|---|---|---|---|
| **Catalog** | Namespaces, tables, views — the pointers | A local [redb](https://github.com/cberner/redb) file, or Postgres | `storage.catalog_url` |
| **Warehouse** | Iceberg metadata and data files | Object storage or a filesystem | `storage.warehouse_location` |

The catalog holds one metadata *pointer* per table, not the metadata. Manifests,
manifest lists and data files live in the warehouse and are fetched by the engine
directly, never proxied through Rustberg.

```toml
[storage]
catalog_url = "file:///var/lib/rustberg/data"
warehouse_location = "s3://my-bucket/warehouse"
```

Local catalog plus remote warehouse is the normal production shape.

---

## The catalog

**Valid values for `catalog_url`:**

| Value | Replicas | Use |
|-------|----------|-----|
| `postgres://user:pass@host/db` | many | Kubernetes, any HA deployment |
| `file:///absolute/path` | exactly 1 | Embedded, single node, the single binary |
| `memory://` | 1, ephemeral | Tests |

`file:///var/lib/rustberg/data` creates `catalog.redb` in that directory.
Postgres requires the `catalog-postgres` feature, not in the default build:

```bash
cargo build --release --features catalog-postgres
```

> Object-store URLs (`s3://`, `gs://`, `az://`) are **rejected** for
> `catalog_url` at startup: a catalog needs compare-and-swap, which object stores
> lack. Point `catalog_url` at a disk or database and `warehouse_location` at the
> bucket.

### Which backend

**Postgres** if more than one replica may run — in Kubernetes almost
always, since a rolling update alone is two pods. Replicas share one registry;
commits compare-and-swap the metadata pointer, so lost updates are impossible.

**redb** for embedding as a library, single-node installs, and the "one binary,
no dependencies" case. It is faster (a local B-tree read, no network round trip)
and single-writer: redb locks the file exclusively, so a second process fails to
start with *Database already open* instead of corrupting anything.

Both store the same data behind the same REST API. Switching means recreating
namespaces and re-registering tables; the warehouse is untouched.

If `catalog_url` is unset, Rustberg logs a warning and uses a temporary directory
discarded on shutdown — for embedding and tests only, never a server.

### Postgres

```toml
[storage]
catalog_url = "postgres://rustberg:secret@postgres.internal:5432/rustberg"
warehouse_location = "s3://my-bucket/warehouse"
```

Or, keeping the password out of the config file:

```bash
export RUSTBERG_CATALOG_URL="postgres://rustberg:secret@postgres.internal/rustberg"
```

Rustberg creates its tables on first start with `IF NOT EXISTS`, so every replica
runs the same startup path; there is no migration step or init job:
`rustberg_namespaces`, `rustberg_object_names`, `rustberg_tables`,
`rustberg_views`, `rustberg_staged_tables`, `rustberg_policy_revisions`,
`rustberg_idempotency`, `rustberg_schema_version`.

`rustberg_object_names` is the shared primary key that makes a name unique across
tables *and* views ([one name, one thing](@/docs/api.md#one-name-one-thing)); both
relations cascade from it, and the namespace foreign key reaches them through it.

`rustberg_schema_version` holds one row naming the schema the database was
created with. Rustberg **refuses to start** against a different schema, naming
both versions and the build that wrote it — `IF NOT EXISTS` would otherwise hide
a schema mismatch as missing tables or columns.

Rustberg is pre-release and ships no migrations. Point `catalog_url` at a fresh
database, or drop the `rustberg_*` relations and start again.

No special database configuration is needed: the default isolation level
suffices, since correctness rests on conditional `UPDATE`s.

Use a managed instance (RDS, Cloud SQL, Azure Database) or an operator such as
[CloudNativePG](https://cloudnative-pg.io/). Rustberg ships no bundled database.

### Filesystem layout (redb)

```
/var/lib/rustberg/data/
└── catalog.redb        # the entire catalog: one file
```

Backup is a file copy of a stopped server (see [below](#backup-and-restore));
there is no cluster to operate.

The file carries the same schema stamp as Postgres, and Rustberg refuses to open
one written with a different schema. Point `catalog_url` at a new file, or move
this one aside.

### Permissions

```bash
sudo mkdir -p /var/lib/rustberg/data
sudo chown rustberg:rustberg /var/lib/rustberg/data
chmod 700 /var/lib/rustberg/data
```

Use absolute paths: a relative path resolves against the working directory,
which differs between a shell and a systemd unit.

---

## The warehouse

`warehouse_location` accepts any scheme whose feature is compiled in:

| Scheme | Feature | Example |
|--------|---------|---------|
| Local filesystem | always | `file:///srv/warehouse` |
| Amazon S3 | `storage-s3` | `s3://bucket/warehouse` |
| Google Cloud Storage | `storage-gcs` | `gs://bucket/warehouse` |
| Azure Data Lake Storage | `storage-azure` | `abfss://fs@account.dfs.core.windows.net/warehouse` |

The default build enables all three (`storage-all`). Building only what you
deploy gives a smaller binary:

```bash
cargo build --release --no-default-features --features cli,tls,storage-s3
```

### The layout inside it

A resource's files go to `<warehouse>/<namespace levels>/<name>`:

```text
s3://bucket/warehouse/
├── analytics/                     namespace  analytics
│   ├── events/                    table      analytics.events
│   │   ├── data/
│   │   └── metadata/
│   └── web/                       namespace  analytics.web
│       └── sessions/              table      analytics.web.sessions
└── finance/
    └── payroll/
```

This is also a bound: a **client-supplied** location must sit inside the prefix
the resource's name gives it, because storage access is scoped to that location.
See [configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files)
for the setting and
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary) for
the rationale.

Under its own prefix a table is laid out freely, so
`.../events/data/dt=2024-01-01/` needs no configuration.

Views share the layout, so a namespace holds **one thing per name**. Both
`createTable` and `createView` answer `409` when either kind holds the name
([one name, one thing](@/docs/api.md#one-name-one-thing)).

### Reaching the warehouse

The *server* reads and writes table metadata, so it needs warehouse access,
configured under `[storage.properties]` by Iceberg property name:

```toml
[storage]
warehouse_location = "s3://my-bucket/warehouse"

[storage.properties]
"s3.region"            = "eu-central-1"
"s3.access-key-id"     = "env:RUSTBERG_S3_ACCESS_KEY_ID"
"s3.secret-access-key" = "env:RUSTBERG_S3_SECRET_ACCESS_KEY"
```

`env:NAME` reads the value from that environment variable at startup, so the file
holds no secret. An unset or blank variable is a startup failure.

One set per process. Keys are scheme-prefixed, so S3 *and* GCS compose; two
accounts on the same cloud need a process each.

For Google Cloud Storage and Azure Data Lake:

```toml
[storage.properties]
"gcs.project-id"       = "my-project"
"gcs.credentials-json" = "env:RUSTBERG_GCS_CREDENTIALS"
# or
"adls.account-name"    = "myaccount"
"adls.account-key"     = "env:RUSTBERG_ADLS_ACCOUNT_KEY"
```

Without `[storage.properties]`, the backend uses ambient credentials — an
instance role, a workload-identity token, `GOOGLE_APPLICATION_CREDENTIALS`. On
EKS/GKE/AKS prefer workload identity over static keys; see
[Kubernetes](@/docs/kubernetes.md).

*Clients* need none of this with credential vending enabled: they receive a
short-lived credential scoped to the requested table. See
[credential vending](@/docs/security.md#credential-vending).

### S3 bucket settings

| Setting | Recommended | Why |
|---------|-------------|-----|
| Versioning | Enabled | Recover from an accidental purge |
| Encryption | SSE-S3 or SSE-KMS | At-rest protection; see [encryption](@/docs/encryption.md) |
| Lifecycle | Expire old noncurrent versions | Versioning is not free |

### MinIO and other S3-compatible stores

Name the endpoint explicitly and use path-style addressing (virtual-host style
needs DNS the store lacks):

```toml
[storage]
warehouse_location = "s3://warehouse/"

[storage.properties]
"s3.endpoint"          = "http://minio:9000"
"s3.path-style-access" = "true"
"s3.region"            = "us-east-1"
"s3.access-key-id"     = "env:MINIO_ACCESS_KEY"
"s3.secret-access-key" = "env:MINIO_SECRET_KEY"
```

```yaml
services:
  minio:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin

  rustberg:
    image: ghcr.io/hupe1980/rustberg:latest
    ports: ["8000:8000"]
    environment:
      RUSTBERG_CONFIG: /etc/rustberg/config.toml
      MINIO_ACCESS_KEY: minioadmin
      MINIO_SECRET_KEY: minioadmin
    volumes:
      - ./config.toml:/etc/rustberg/config.toml:ro
      - rustberg-data:/var/lib/rustberg/data
    depends_on: [minio]

volumes:
  rustberg-data:
```

The volume is required: without it the catalog file lives in the container's
writable layer and disappears with the container.

Cloudflare R2, Ceph RADOS Gateway and Wasabi work the same way with a different
endpoint.

---

## Deployment shape

### With Postgres

Stateless pods in an ordinary Deployment, scaled freely:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: rustberg
        image: ghcr.io/hupe1980/rustberg:latest
        env:
        - name: RUSTBERG_CATALOG_URL
          valueFrom:
            secretKeyRef: { name: rustberg-catalog, key: dsn }
        - name: RUSTBERG_WAREHOUSE
          value: "s3://my-bucket/warehouse"
```

No volume, no `Recreate`, no single-writer constraint. This is the Helm chart's
default — see [Kubernetes](@/docs/kubernetes.md).

Idempotency receipts live in the same database, so a retry on a different pod
replays the first response instead of executing again — as
`idempotency-key-lifetime` in `/v1/config` promises.

### With redb

The catalog is one local file, so **exactly one Rustberg process may open it**.
This follows from redb being an embedded database.

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: rustberg
spec:
  replicas: 1                # one writer, by construction
  serviceName: rustberg
  template:
    spec:
      containers:
      - name: rustberg
        image: ghcr.io/hupe1980/rustberg:latest
        env:
        - name: RUSTBERG_WAREHOUSE
          value: "s3://my-bucket/warehouse"
        volumeMounts:
        - name: data
          mountPath: /var/lib/rustberg/data
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

A `Deployment` also works with `strategy: Recreate`. The default `RollingUpdate`
starts the new pod before stopping the old one, and the new pod cannot open the
catalog file.

### What redb costs, and what it buys

- **Costs:** horizontal scale-out.
- **Buys:** serialisable commits without a consensus protocol, a p99 that is a
  local disk read, and one file to operate — no database to run, back up or
  upgrade.

Right for an embedded catalog; for a cluster, use Postgres.

---

## Backup and restore

There is no backup subcommand; each backend's own backup tool does the job.

### redb

Copy the file *while the server is stopped*:

```bash
systemctl stop rustberg
cp /var/lib/rustberg/data/catalog.redb /backups/catalog-$(date +%F).redb
systemctl start rustberg
```

Restore is the same copy in reverse, server stopped.

A copy taken during a commit can capture a half-written file that reads back
fine until a torn page is needed. Since the deployment is single-writer, the
window is a restart.

If stopping is not acceptable, take a **filesystem or volume snapshot** (LVM,
ZFS, EBS/PD snapshot); these are atomic at the block layer.

### Postgres

`pg_dump`, or your managed service's backups. No downtime, and it covers the
policy revisions and idempotency receipts stored alongside the catalog:

```bash
pg_dump --format=custom "$RUSTBERG_CATALOG_URL" > /backups/rustberg-$(date +%F).dump
```

### The warehouse is separate, and that is the part that needs care

Neither backup touches table data or metadata files; use the object store's
versioning and replication. Restore catalog and warehouse to **consistent
points**, or the catalog points at missing metadata files:

- Catalog *older* than the warehouse: safe — recent commits are lost, but every
  pointer resolves.
- Catalog newer than the warehouse: tables that cannot be loaded.

---

## Troubleshooting

**"Unsupported catalog URL"** — `catalog_url` got an object-store URL. It takes
`postgres://`, `file://` or `memory://`; the bucket belongs in
`warehouse_location`. A rejected `postgres://` URL means the binary lacks the
`catalog-postgres` feature.

**Catalog empty after restart** — `catalog_url` is unset (check the startup
warning) or the path is not on a persistent volume.

**"Database already open. Cannot acquire lock."** — another Rustberg process
holds the redb file. Check for a previous pod still terminating, or switch to
Postgres.

**403 from the warehouse** — the *server's* credentials are wrong. Verify with
`aws sts get-caller-identity` or `gcloud auth list`, then confirm the identity
can list the warehouse prefix. For client-side 403s see
[authorization](@/docs/authorization.md).

---

## Next steps

- [Configuration](@/docs/configuration.md) — every setting
- [Kubernetes](@/docs/kubernetes.md) — production deployment
- [Security](@/docs/security.md) — credential vending and enforcement
