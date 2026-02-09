# Rustberg Helm Chart

A Helm chart for deploying [Rustberg](https://github.com/hupe1980/rustberg) - a production-ready Apache Iceberg REST Catalog written in Rust.

> ⚠️ **Important:** Rustberg currently supports **single-writer deployments only**. Set `replicaCount: 1` for write workloads. Multiple replicas can be used for read-heavy workloads with leader election (not yet implemented).

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+

## Installation

```bash
# Add the Helm repository (if published)
helm repo add rustberg https://hupe1980.github.io/rustberg/charts
helm repo update

# Install with default values
helm install rustberg rustberg/rustberg

# Install with custom values
helm install rustberg rustberg/rustberg -f values.yaml
```

## Configuration

See [values.yaml](values.yaml) for the full list of configurable parameters.

### Quick Examples

#### Development Mode (Memory Storage)

```yaml
rustberg:
  storage:
    type: memory
```

#### Production with S3

```yaml
# IMPORTANT: Use replicaCount: 1 until distributed coordination is implemented
replicaCount: 1

rustberg:
  storage:
    type: s3
    s3:
      bucket: my-iceberg-bucket
      region: us-east-1
      existingSecret: aws-credentials

  auth:
    enabled: true
    jwt:
      enabled: true
      issuer: https://auth.example.com
      audience: rustberg

  encryption:
    enabled: true
    kmsProvider: aws-kms
    awsKms:
      keyId: alias/rustberg-key
      region: us-east-1

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

# Disable autoscaling until multi-writer support is added
autoscaling:
  enabled: false
  maxReplicas: 10

podDisruptionBudget:
  enabled: true
  minAvailable: 2
```

#### Production with GCS

```yaml
rustberg:
  storage:
    type: gcs
    gcs:
      bucket: my-iceberg-bucket
      projectId: my-project
      existingSecret: gcp-credentials

serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: rustberg@my-project.iam.gserviceaccount.com
```

#### Production with Azure

```yaml
rustberg:
  storage:
    type: azure
    azure:
      container: iceberg
      accountName: myaccount
      existingSecret: azure-storage-credentials
```

### Authentication

```yaml
rustberg:
  auth:
    enabled: true
    
    # API Key authentication
    apiKeys:
      enabled: true
      keys:
        - name: admin
          key: rk_xxxxx
          roles: [admin]
    
    # JWT/OIDC authentication
    jwt:
      enabled: true
      issuer: https://accounts.google.com
      audience: rustberg
      jwksUri: https://www.googleapis.com/oauth2/v3/certs
```

### Encryption

```yaml
rustberg:
  encryption:
    enabled: true
    
    # HashiCorp Vault
    kmsProvider: vault
    vault:
      address: https://vault.example.com
      transitMount: transit
      keyName: rustberg
      existingSecret: vault-token
```

## Monitoring

Enable Prometheus ServiceMonitor:

```yaml
serviceMonitor:
  enabled: true
  interval: 30s
```

## Network Policies

```yaml
networkPolicy:
  enabled: true
  ingress:
    from:
      - namespaceSelector:
          matchLabels:
            name: data-platform
```

## Upgrading

```bash
helm upgrade rustberg rustberg/rustberg -f values.yaml
```

## Uninstalling

```bash
helm uninstall rustberg
```

## License

Apache License 2.0
