+++
title = "Catalog and warehouse"
description = "Where Rustberg keeps the catalog — an embedded redb file or Postgres — and where the tables themselves live."
weight = 7
+++
Rustberg stores two different things in two different places. Confusing them is
the most common misconfiguration.

## Two locations, not one

| | What it holds | Where it lives | Config key |
|---|---|---|---|
| **Catalog** | Namespaces, tables, views — the pointers | A local [redb](https://github.com/cberner/redb) file, or Postgres | `storage.catalog_url` |
| **Warehouse** | Iceberg metadata and data files | Object storage or a filesystem | `storage.warehouse_location` |

The catalog is deliberately small: it holds a metadata *pointer* per table, not
the metadata itself. Everything a query engine reads — manifests, manifest
lists, data files — lives in the warehouse and is fetched by the engine
directly, never proxied through Rustberg.

```toml
[storage]
catalog_url = "file:///var/lib/rustberg/data"
warehouse_location = "s3://my-bucket/warehouse"
```

That pairing — local catalog, remote warehouse — is the normal production shape.

---

## The catalog

**Valid values for `catalog_url`:**

| Value | Replicas | Use |
|-------|----------|-----|
| `postgres://user:pass@host/db` | many | Kubernetes, any HA deployment |
| `file:///absolute/path` | exactly 1 | Embedded, single node, the single binary |
| `memory://` | 1, ephemeral | Tests |

`file:///var/lib/rustberg/data` creates `catalog.redb` inside that directory.
Postgres support is behind the `catalog-postgres` feature, which is not in the
default build:

```bash
cargo build --release --features catalog-postgres
```

> Object-store URLs (`s3://`, `gs://`, `az://`) are **not** valid for
> `catalog_url` and are rejected at startup: a catalog needs compare-and-swap,
> which an object store does not offer. Point `catalog_url` at a disk or a
> database, and `warehouse_location` at the bucket.

### Which backend

**Postgres** if more than one replica will ever run — which in Kubernetes is
essentially always, since a rolling update alone is two pods. Replicas share one
registry and the database resolves concurrency; commits use a compare-and-swap
on the metadata pointer, so a lost update is not possible.

**redb** for embedding Rustberg as a library, for a single-node install, and for
the "one binary, no dependencies" case. It is faster — a local B-tree read
instead of a network round trip — and it is genuinely single-writer: redb takes
an exclusive lock on the file, so a second process fails to start with *Database
already open* rather than corrupting anything.

Both backends store the same thing and speak the same REST API. Moving between
them means recreating the namespaces and re-registering the tables; the warehouse
is untouched.

If `catalog_url` is unset entirely, Rustberg logs a warning and uses a temporary
directory that is discarded on shutdown. This is a convenience for embedding and
tests — never leave it unset for a server.

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

Rustberg creates its tables on first start — `rustberg_namespaces`,
`rustberg_object_names`, `rustberg_tables`, `rustberg_views`,
`rustberg_staged_tables`, `rustberg_policy_revisions`, `rustberg_idempotency`
and `rustberg_schema_version` — with `IF NOT EXISTS` so that every replica can
run the same startup path. There is no migration step and no separate init job.

`rustberg_object_names` is the shared primary key that makes a name unique
across tables *and* views ([one name, one thing](@/docs/api.md#one-name-one-thing));
the two relations cascade from it, and the namespace foreign key reaches them
through it.

`rustberg_schema_version` holds one row naming the schema this database was
created with. Rustberg **refuses to start** against a database stamped with a
different one, naming both versions and the build that wrote it.

That check exists because `IF NOT EXISTS` is exactly what makes a schema change
invisible: a relation added later is created empty and the rows that belong in it
are not there, a column added later is simply absent. Nothing about that looks
like a schema problem — it looks like a catalog that has lost its tables. Being
told at startup is the difference.

There are no migrations and there will not be while Rustberg is pre-release. The
answer is to point `catalog.url` at a fresh database, or drop the `rustberg_*`
relations in this one and start again.

The database needs no special configuration — the default isolation level is
sufficient, because correctness rests on conditional `UPDATE`s rather than on
transaction isolation.

Use a managed instance (RDS, Cloud SQL, Azure Database) or an operator such as
[CloudNativePG](https://cloudnative-pg.io/). Rustberg deliberately ships no
bundled database.

### Filesystem layout (redb)

```
/var/lib/rustberg/data/
└── catalog.redb        # the entire catalog: one file
```

One file is the whole point: backup is a file copy of a stopped server (see
[below](#backup-and-restore)), and there is no cluster to operate.

The file carries the same schema stamp the Postgres backend does, and Rustberg
refuses to open one written by a build with a different schema. It matters more
here rather than less: the file outlives the binary that wrote it, sitting in a
volume somebody mounts into the next image. Same answer — point `catalog.url` at
a new file, or move this one aside.

### Permissions

```bash
sudo mkdir -p /var/lib/rustberg/data
sudo chown rustberg:rustberg /var/lib/rustberg/data
chmod 700 /var/lib/rustberg/data
```

Use absolute paths. A relative path resolves against the process working
directory, which differs between a shell and a systemd unit.

---

## The warehouse

`warehouse_location` accepts any scheme whose feature is compiled in:

| Scheme | Feature | Example |
|--------|---------|---------|
| Local filesystem | always | `file:///srv/warehouse` |
| Amazon S3 | `storage-s3` | `s3://bucket/warehouse` |
| Google Cloud Storage | `storage-gcs` | `gs://bucket/warehouse` |
| Azure Data Lake Storage | `storage-azure` | `abfss://fs@account.dfs.core.windows.net/warehouse` |

The default build enables all three (`storage-all`). Building with only what you
deploy makes a smaller binary:

```bash
cargo build --release --no-default-features --features cli,tls,storage-s3
```

### The layout inside it

Rustberg puts a resource's files at `<warehouse>/<namespace levels>/<name>`:

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

That is a bound as well as a convention: a **client-supplied** location must sit
inside the prefix the resource's own name puts it in, because storage access is
scoped to that location. See
[configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files)
for the setting and
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary) for
why.

Underneath its own prefix a table lays itself out however its writer likes, so
`.../events/data/dt=2024-01-01/` needs nothing configured.

Views use the same layout, so a namespace holds **one thing per name** — a table
and a view called `events` would share a directory. Both `createTable` and
`createView` answer `409` when either kind holds the name
([one name, one thing](@/docs/api.md#one-name-one-thing)).

### Reaching the warehouse

Rustberg reads and writes table metadata itself, so the *server* needs warehouse
access. Configure it under `[storage.properties]`, by Iceberg property name:

```toml
[storage]
warehouse_location = "s3://my-bucket/warehouse"

[storage.properties]
"s3.region"            = "eu-central-1"
"s3.access-key-id"     = "env:RUSTBERG_S3_ACCESS_KEY_ID"
"s3.secret-access-key" = "env:RUSTBERG_S3_SECRET_ACCESS_KEY"
```

A value written as `env:NAME` is read from that environment variable at startup,
so the file holds no secret and can be committed. A named variable that is unset
or blank is a startup failure, not a silently absent property.

These are one set for the whole process. Keys are scheme-prefixed, so S3 *and*
GCS compose; two accounts on the same cloud need a process each.

For Google Cloud Storage and Azure Data Lake:

```toml
[storage.properties]
"gcs.project-id"       = "my-project"
"gcs.credentials-json" = "env:RUSTBERG_GCS_CREDENTIALS"
# or
"adls.account-name"    = "myaccount"
"adls.account-key"     = "env:RUSTBERG_ADLS_ACCOUNT_KEY"
```

Leaving `[storage.properties]` out entirely falls back to whatever ambient
credentials the storage backend discovers — an instance role, a workload-identity
token, `GOOGLE_APPLICATION_CREDENTIALS`. On EKS/GKE/AKS that is the right choice:
prefer the workload-identity mechanism over static keys, and see
[Kubernetes](@/docs/kubernetes.md).

*Clients* do not need any of this when credential vending is enabled: Rustberg
hands them a short-lived credential scoped to the one table they asked for. See
[credential vending](@/docs/security.md#credential-vending).

### S3 bucket settings

| Setting | Recommended | Why |
|---------|-------------|-----|
| Versioning | Enabled | Recover from an accidental purge |
| Encryption | SSE-S3 or SSE-KMS | At-rest protection; see [encryption](@/docs/encryption.md) |
| Lifecycle | Expire old noncurrent versions | Versioning is not free |

### MinIO and other S3-compatible stores

An S3-compatible store needs the endpoint named explicitly, and path-style
addressing — virtual-host style requires DNS the store does not have:

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

The volume is not optional. Without it the catalog file lives in the container's
writable layer and disappears with the container.

Cloudflare R2, Ceph RADOS Gateway and Wasabi are configured the same way; only
the endpoint changes.

---

## Deployment shape

### With Postgres

Stateless pods, ordinary Deployment, scale as you like:

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

No volume, no `Recreate`, no single-writer constraint. This is what the Helm
chart does by default — see [Kubernetes](@/docs/kubernetes.md).

Idempotency receipts live in the same database, so a retry that lands on a
different pod is replayed from the first response rather than executed again.
That is what `idempotency-key-lifetime` in `/v1/config` promises, and a
per-process cache would not keep it.

### With redb

The catalog is a single local file, so **exactly one Rustberg process may open
it**. This is not a tuning choice to revisit later; it follows from redb being
an embedded database rather than a distributed one.

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

A `Deployment` works too, provided you set `strategy: Recreate` — the default
`RollingUpdate` starts the new pod before terminating the old one, and the
second process cannot open the catalog file.

### What redb costs, and what it buys

It costs horizontal scale-out. It buys serialisable commits without a consensus
protocol, a p99 that is a local disk read, and an operational surface of exactly
one file — no database to run, back up, or upgrade. For an embedded catalog that
is the right trade. For a cluster it is not, which is what Postgres is for.

---

## Backup and restore

**There is no backup subcommand, deliberately.** Both backends already have a
backup tool that is better than one Rustberg could ship, and the one that was
here was worse than either: it archived a directory while the server held it
open, which for redb means capturing a file mid-commit, and it did nothing at all
for a Postgres deployment — the backend the production guide recommends.

### redb

The catalog is one file. Copying it *while the server is stopped* is the backup:

```bash
systemctl stop rustberg
cp /var/lib/rustberg/data/catalog.redb /backups/catalog-$(date +%F).redb
systemctl start rustberg
```

Restoring is the same copy in reverse, with the server stopped.

Stopping is not fussiness. redb holds an exclusive lock on the file and commits
atomically, so a copy taken during a commit is a copy of a half-written file —
and a redb catalog is exactly the kind of thing that reads back fine until the
one page you need is the torn one. The deployment is single-writer anyway, so
the window is a restart.

If stopping is not acceptable, take a **filesystem or volume snapshot** (LVM,
ZFS, or an EBS/PD snapshot). Those are atomic at the block layer, which is the
property the copy above is missing.

### Postgres

`pg_dump`, or whatever your managed service already does. No downtime, and it
covers the policy revisions and idempotency receipts that live there alongside
the catalog:

```bash
pg_dump --format=custom "$RUSTBERG_CATALOG_URL" > /backups/rustberg-$(date +%F).dump
```

### The warehouse is separate, and that is the part that needs care

Neither of the above touches table data or metadata files; those are backed up by
the object store's own versioning and replication. The two have to be restored to
**consistent points**, or the catalog points at metadata files that no longer
exist. Restoring a catalog that is *older* than the warehouse is the safe
direction — it loses recent commits but every pointer still resolves. The other
way round leaves tables that cannot be loaded at all.

---

## Troubleshooting

**"Unsupported catalog URL"** — you gave `catalog_url` an object-store URL. It
takes `postgres://`, `file://` or `memory://`; the bucket belongs in
`warehouse_location`. A `postgres://` URL rejected here means the binary was
built without the `catalog-postgres` feature.

**Catalog empty after restart** — either `catalog_url` is unset (check the
startup warning) or the path is not on a persistent volume.

**"Database already open. Cannot acquire lock."** — another Rustberg process
holds the redb catalog file. Check for a previous pod that has not terminated,
or switch to the Postgres backend, which is designed for this.

**403 from the warehouse** — the *server's* credentials are wrong. Verify with
`aws sts get-caller-identity` or `gcloud auth list`, then confirm the identity
can list the warehouse prefix. Client-side 403s are a different problem: check
[authorization](@/docs/authorization.md).

---

## Next steps

- [Configuration](@/docs/configuration.md) — every setting
- [Kubernetes](@/docs/kubernetes.md) — production deployment
- [Security](@/docs/security.md) — credential vending and enforcement
