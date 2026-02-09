---
layout: default
title: Storage Backends
nav_order: 5
description: "Storage backends for Rustberg: S3, GCS, Azure Blob, local filesystem"
permalink: /docs/storage
---

# Storage Backends
{: .no_toc }

Configure persistent storage for catalog metadata.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Rustberg uses **SlateDB** (100% pure Rust) for catalog metadata storage:

| Backend | URL Scheme | K8s HA | Use Case |
|---------|------------|--------|----------|
| Memory | `memory://` | ❌ | Development, testing |
| Local File | `file:///path` | ❌ | Single-node production |
| AWS S3 | `s3://bucket/prefix` | ✅ | Cloud production |
| GCS | `gs://bucket/prefix` | ✅ | Cloud production |
| Azure Blob | `az://container/prefix` | ✅ | Cloud production |
| MinIO | `s3://bucket` + endpoint | ✅ | Air-gapped |

### What Gets Stored

SlateDB stores all catalog metadata, including:

| Data Type | Key Pattern | Persistence |
|-----------|-------------|-------------|
| Namespaces | `namespace:{name}` | ✅ Durable |
| Tables | `table:{namespace}:{name}` | ✅ Durable |
| Views | `view:{namespace}:{name}` | ✅ Durable |
| Idempotency Keys | `idempotency:{scope}:{key}` | ✅ Durable |
| API Keys | `apikey:{prefix}` | ✅ Durable (with slatedb-storage) |

All data survives server restarts when using persistent backends (file, S3, GCS, Azure).

---

## Quick Start

### Memory (Default)

```bash
# In-memory storage (data lost on restart)
./rustberg
```

### Local Filesystem

```bash
# Persistent local storage
./rustberg --storage file:///var/lib/rustberg
```

### AWS S3

```bash
# S3 backend (K8s HA ready)
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
./rustberg --storage s3://my-bucket/rustberg-catalog
```

---

## Memory Backend

**URL:** `memory://`

Best for:
- Development
- CI/CD testing
- Ephemeral workloads

```toml
[storage]
object_store_url = "memory://"
```

{: .warning }
> Data is lost when the process restarts. Not for production.

---

## Local Filesystem

**URL:** `file:///absolute/path`

Best for:
- Single-node production
- Edge deployments
- Simple setups

### Configuration

```toml
[storage]
object_store_url = "file:///var/lib/rustberg"
```

### Directory Structure

```
/var/lib/rustberg/
├── slatedb/           # SlateDB LSM-tree data
│   ├── wal/           # Write-ahead log
│   ├── sst/           # Sorted string tables
│   └── manifest/      # Metadata
└── backup/            # Optional backup location
```

### Permissions

```bash
# Create directory
sudo mkdir -p /var/lib/rustberg
sudo chown rustberg:rustberg /var/lib/rustberg
chmod 700 /var/lib/rustberg
```

{: .important }
> Use absolute paths. Relative paths may cause issues.

---

## AWS S3

**URL:** `s3://bucket/prefix`

Best for:
- Kubernetes deployments
- High availability
- Multi-replica setups

### Configuration

```toml
[storage]
object_store_url = "s3://my-bucket/rustberg-catalog"
aws_region = "us-east-1"
```

### Authentication

#### Environment Variables (Recommended)

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_REGION=us-east-1
```

#### IAM Role (EC2/EKS)

```yaml
# EKS Service Account with IRSA
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/rustberg-role
```

#### IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/rustberg-catalog/*"
      ]
    }
  ]
}
```

### S3 Bucket Settings

| Setting | Recommended Value | Why |
|---------|------------------|-----|
| Versioning | Enabled | Disaster recovery |
| Encryption | SSE-S3 or SSE-KMS | Data protection |
| Lifecycle | 30 days for old versions | Cost optimization |
| Replication | Optional | Multi-region HA |

---

## Google Cloud Storage

**URL:** `gs://bucket/prefix`

Best for:
- GKE deployments
- Google Cloud workloads

### Configuration

```toml
[storage]
object_store_url = "gs://my-bucket/rustberg-catalog"
```

### Authentication

#### Service Account Key

```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

#### Workload Identity (GKE)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  annotations:
    iam.gke.io/gcp-service-account: rustberg@project.iam.gserviceaccount.com
```

#### IAM Permissions

```bash
gsutil iam ch serviceAccount:rustberg@project.iam.gserviceaccount.com:objectAdmin \
  gs://my-bucket
```

---

## Azure Blob Storage

**URL:** `az://container/prefix`

Best for:
- AKS deployments
- Azure workloads

### Configuration

```toml
[storage]
object_store_url = "az://my-container/rustberg-catalog"
azure_storage_account = "mystorageaccount"
```

### Authentication

#### Access Key

```bash
export AZURE_STORAGE_ACCOUNT=mystorageaccount
export AZURE_STORAGE_KEY=your_storage_key
```

#### Managed Identity (AKS)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  annotations:
    azure.workload.identity/client-id: <client-id>
```

---

## MinIO (Self-Hosted S3)

**URL:** `s3://bucket` with custom endpoint

Best for:
- Air-gapped environments
- On-premises deployments
- Development with S3 API

### Configuration

```toml
[storage]
object_store_url = "s3://rustberg-bucket/catalog"
aws_endpoint = "http://minio.local:9000"
aws_region = "us-east-1"
aws_allow_http = true  # Only for development
```

### Docker Compose Example

```yaml
version: '3.8'
services:
  minio:
    image: minio/minio
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    command: server /data --console-address ":9001"

  rustberg:
    image: ghcr.io/hupe1980/rustberg:latest
    ports:
      - "8181:8181"
    environment:
      RUSTBERG_STORAGE: "s3://rustberg/catalog"
      AWS_ENDPOINT_URL: "http://minio:9000"
      AWS_ACCESS_KEY_ID: minioadmin
      AWS_SECRET_ACCESS_KEY: minioadmin
      AWS_REGION: us-east-1
    depends_on:
      - minio
```

---

## Kubernetes Horizontal Scaling

SlateDB enables **horizontal scaling** without external coordination:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
spec:
  replicas: 3  # ✅ Multiple replicas!
  selector:
    matchLabels:
      app: rustberg
  template:
    spec:
      containers:
      - name: rustberg
        image: ghcr.io/hupe1980/rustberg:latest
        env:
        - name: RUSTBERG_STORAGE
          value: "s3://my-bucket/rustberg-catalog"
```

### How It Works

1. **No leader election** - SlateDB's `writer_epoch` fencing handles coordination
2. **CAS operations** - Object storage provides atomic compare-and-swap
3. **Automatic retry** - Contention resolved with exponential backoff
4. **11-nines durability** - Inherits S3/GCS durability

```
┌─────────────────────────────────────────────────────────────────┐
│                    Rustberg K8s Deployment                       │
├─────────────────────────────────────────────────────────────────┤
│   ┌──────────┐  ┌──────────┐  ┌──────────┐                     │
│   │  Pod 1   │  │  Pod 2   │  │  Pod 3   │                     │
│   │ Rustberg │  │ Rustberg │  │ Rustberg │                     │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘                     │
│        └─────────────┼─────────────┘                            │
│                      ▼                                          │
│        ┌─────────────────────────────┐                         │
│        │         SlateDB             │                         │
│        │  (writer_epoch fencing)     │                         │
│        └─────────────┬───────────────┘                         │
│                      ▼                                          │
│        ┌─────────────────────────────┐                         │
│        │      S3 / GCS / MinIO       │                         │
│        │   (CAS + 11-nines durable)  │                         │
│        └─────────────────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Backup and Restore

### Backup

```bash
# Backup catalog to archive
./rustberg backup \
  --storage s3://my-bucket/rustberg-catalog \
  --output /backups/catalog-2026-01-24.tar.gz
```

### Restore

```bash
# Restore from backup
./rustberg restore \
  --input /backups/catalog-2026-01-24.tar.gz \
  --storage s3://my-bucket/rustberg-catalog
```

### Validate Backup

```bash
# Verify backup integrity
./rustberg validate-backup \
  --input /backups/catalog-2026-01-24.tar.gz
```

---

## Performance Tuning

### S3 Optimization

```toml
[storage]
object_store_url = "s3://my-bucket/catalog"
aws_region = "us-east-1"

# Performance settings
s3_multipart_threshold_mb = 8
s3_multipart_chunk_size_mb = 8
s3_max_concurrent_requests = 100
```

### Local Filesystem

```toml
[storage]
object_store_url = "file:///var/lib/rustberg"

# Use SSD for best performance
# Mount with noatime for reduced I/O
```

---

## Troubleshooting

### S3 Access Denied

```bash
# Verify credentials
aws sts get-caller-identity

# Test bucket access
aws s3 ls s3://my-bucket/rustberg-catalog/

# Check bucket policy
aws s3api get-bucket-policy --bucket my-bucket
```

### GCS Permission Denied

```bash
# Verify service account
gcloud auth list

# Test bucket access
gsutil ls gs://my-bucket/rustberg-catalog/
```

### Local Filesystem Issues

```bash
# Check permissions
ls -la /var/lib/rustberg

# Check disk space
df -h /var/lib/rustberg

# Check for lock files
ls -la /var/lib/rustberg/slatedb/
```

---

## Next Steps

- [Encryption Guide](/rustberg/docs/encryption) - Encrypt data at rest
- [Kubernetes Guide](/rustberg/docs/kubernetes) - Production K8s deployment
- [Backup Guide](/rustberg/docs/backup) - Disaster recovery
