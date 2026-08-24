# Rustberg Helm Chart

A Helm chart for [Rustberg](https://github.com/hupe1980/rustberg) — an Apache
Iceberg REST Catalog written in Rust.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- A PostgreSQL database (see below)

## The catalog backend decides everything else

Rustberg has two catalog backends, and which one you pick determines whether the
deployment can have more than one pod.

| `rustberg.catalog.backend` | Replicas | Needs |
|---|---|---|
| `postgres` *(default)* | any | A database |
| `redb` | exactly 1 | A PersistentVolume |

**redb** is one file with an exclusive lock. A second process does not contend —
it fails to start with *Database already open*. That includes the extra pod a
rolling update creates, which is why the chart forces `strategy: Recreate` when
redb is selected. It is the right backend for embedding and single-node
installs, and the wrong one for a cluster.

**Postgres** is the default here for that reason. The pods hold no state, so
replicas, rolling updates and autoscaling all work normally.

The chart refuses configurations that cannot work — more than one replica on
redb, redb without persistence, autoscaling on redb, postgres without a DSN —
with an error naming the fix, rather than letting the pod crash-loop.

## Installation

```bash
git clone https://github.com/hupe1980/rustberg
cd rustberg

kubectl create secret generic rustberg-catalog \
  --from-literal=dsn="postgres://rustberg:secret@postgres:5432/rustberg"

helm install rustberg charts/rustberg \
  --set rustberg.catalog.postgres.existingSecret=rustberg-catalog \
  --set rustberg.warehouse.location=s3://my-bucket/warehouse
```

> **Note.** The chart is not published to a registry; install it from a clone.

### Where the database comes from

This chart bundles no database, on purpose. A Postgres subchart would be a
StatefulSet without backups, failover, or an upgrade path — everything a real
deployment needs from its database, missing. Use a managed instance (RDS, Cloud
SQL, Azure Database) or an operator such as
[CloudNativePG](https://cloudnative-pg.io/), and hand Rustberg the DSN.

Rustberg creates its own tables on first start; there is no migration job.

## Configuration

See [values.yaml](values.yaml) for every parameter.

### Production with S3

```yaml
replicaCount: 3

rustberg:
  catalog:
    backend: postgres
    postgres:
      existingSecret: rustberg-catalog   # key: dsn

  warehouse:
    location: s3://my-iceberg-bucket/warehouse

  storage:
    type: s3          # credentials the server uses to reach the warehouse
    s3:
      region: us-east-1
      existingSecret: aws-credentials

  # Authentication and policy come from the TOML config, not chart values.
  config: |
    [server.auth]
    jwt_enabled = true
    policy_file = "/config/catalog.cedar"

    [server.auth.jwt]
    issuer    = "https://auth.example.com"
    audiences = ["rustberg"]

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: iceberg.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: rustberg-tls
      hosts:
        - iceberg.example.com

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 8

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

### Production with GCS

```yaml
rustberg:
  catalog:
    backend: postgres
    postgres:
      existingSecret: rustberg-catalog

  warehouse:
    location: gs://my-iceberg-bucket/warehouse

  storage:
    type: gcs
    gcs:
      projectId: my-project
      existingSecret: gcp-credentials

serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: rustberg@my-project.iam.gserviceaccount.com
```

Prefer Workload Identity over a mounted service-account key.

### Single node with the embedded catalog

```yaml
replicaCount: 1

rustberg:
  catalog:
    backend: redb
    path: /data/catalog
  warehouse:
    location: s3://my-bucket/warehouse

persistence:
  enabled: true       # required: the catalog is a file on this volume
  size: 10Gi
```

### Authentication and policy

Both are configured through `rustberg.config`, the full Rustberg TOML file,
which the chart mounts at `/config/rustberg.toml`.

There are no `rustberg.auth.*` or `rustberg.authorization.*` values: a chart
value no template reads is a setting that silently does nothing.

API key secrets belong in environment variables, referenced from the config by
name — see [authentication](https://hupe1980.github.io/rustberg/docs/authentication/).
Add them with `rustberg.extraEnv`.

## Monitoring

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
```

## Network policies

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            name: data-platform
```

Remember to allow egress to the Postgres service and to object storage.

## Upgrading

```bash
helm upgrade rustberg charts/rustberg -f values.yaml
```

With the Postgres backend this is an ordinary rolling update. With redb it is a
`Recreate`, so expect a few seconds of downtime.

A pod leaving rotation keeps serving for `shutdown.drainDelaySeconds` after
`SIGTERM`, so its removal from the Service's endpoints has time to reach every
kube-proxy and ingress before it stops answering. There is no `preStop` hook —
the image is distroless and has no shell — so the wait is in the binary, and
`shutdown.terminationGracePeriodSeconds` has to cover it plus the 30-second
drain that follows.

## Uninstalling

```bash
helm uninstall rustberg
```

The catalog database is not touched. With redb, the PersistentVolumeClaim
survives per your reclaim policy.

## License

Apache License 2.0
