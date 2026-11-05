+++
title = "Kubernetes"
description = "Deploying Rustberg on Kubernetes: the Helm chart, replica shapes, probes, and network policy."
weight = 11
+++
> **Use the Postgres catalog.** The embedded redb catalog is a file with an
> exclusive lock, so a second pod cannot start, including the extra pod of a
> rolling update. With `catalog_url` pointing at Postgres, replicas are ordinary
> stateless pods. The Helm chart defaults to this.


Production Kubernetes deployment: stateless replicas over a shared catalog.

## Overview

| Feature | Benefit |
|---------|---------|
| **~31 ms startup** | Fast rescheduling and readiness |
| **~15 MB idle RSS** | Dense packing, low cost per replica |
| **Stateless pods** | Catalog in Postgres, warehouse in object storage |
| **No leader election** | Concurrency resolved by the database |
| **Health endpoints** | Native `/health` and `/ready` probes |

Startup and memory are measured; see [performance](@/docs/benchmarks.md).

---

## Helm Chart (Recommended)

The chart lives in the repository and is not published to a registry; clone the
repository to install it.

### Installation

```bash
# Clone the repository
git clone https://github.com/hupe1980/rustberg
cd rustberg

# The chart needs a catalog database. Point it at an existing Postgres:
kubectl create secret generic rustberg-catalog \
  --from-literal=dsn="postgres://rustberg:secret@postgres.internal:5432/rustberg"

helm install rustberg charts/rustberg \
  --set rustberg.catalog.postgres.existingSecret=rustberg-catalog \
  --set rustberg.warehouse.location=s3://my-bucket/warehouse

# Or install with custom values
helm install rustberg charts/rustberg -f my-values.yaml
```

### Basic Configuration

```yaml
# values.yaml
replicaCount: 2

rustberg:
  catalog:
    backend: postgres
    postgres:
      existingSecret: rustberg-catalog   # holds key `dsn`

  warehouse:
    location: s3://my-iceberg-bucket/warehouse

  storage:
    type: s3        # credentials the server uses to reach the warehouse
    s3:
      region: us-east-1
      existingSecret: aws-credentials

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: iceberg.example.com
      paths:
        - path: /
          pathType: Prefix
```

### Production Configuration

```yaml
# production-values.yaml
replicaCount: 3

rustberg:
  catalog:
    backend: postgres
    postgres:
      existingSecret: rustberg-catalog

  warehouse:
    location: s3://production-warehouse/

  storage:
    type: s3
    s3:
      region: us-east-1

  auth:
    enabled: true
    jwt:
      enabled: true
      issuer: https://auth.example.com
      audiences: ["rustberg"]

resources:
  requests:
    memory: "64Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "1000m"

autoscaling:
  enabled: true      # safe with the postgres catalog
  minReplicas: 2
  maxReplicas: 6
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

serviceMonitor:
  enabled: true
  interval: 30s

shutdown:
  drainDelaySeconds: 5
  terminationGracePeriodSeconds: 60
```

### Rolling updates without dropped requests

Kubernetes sends `SIGTERM` **while** removing the pod from Service endpoints,
and kube-proxies and ingress controllers learn of the removal later. A pod that
stops accepting at once refuses requests in that window.

The distroless image has no shell for a `preStop` sleep. Instead, after
`SIGTERM` Rustberg keeps serving for
`shutdown.drainDelaySeconds` (passed as `--shutdown-delay`), then drains
in-flight requests for up to 30 seconds.

- `terminationGracePeriodSeconds` must cover the delay *plus* the drain, or the
  kubelet `SIGKILL`s the process. The chart sets both.
- A readiness probe does not replace the delay: it fails after the ingress has
  already routed to the pod.
- A `podDisruptionBudget` bounds how many pods drain at once.

### Helm Commands

```bash
# Lint chart
helm lint charts/rustberg

# Template (dry-run)
helm template rustberg charts/rustberg -f values.yaml

# Install
helm install rustberg charts/rustberg -n rustberg --create-namespace

# Upgrade
helm upgrade rustberg charts/rustberg -f values.yaml

# Uninstall
helm uninstall rustberg
```

Full chart documentation: [charts/rustberg/README.md](https://github.com/hupe1980/rustberg/tree/main/charts/rustberg).

---

## Quick Start (Without Helm)

### Minimal Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
  labels:
    app: rustberg
spec:
  replicas: 3   # stateless: the catalog lives in Postgres
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
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 1
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: rustberg
spec:
  selector:
    app: rustberg
  ports:
  - port: 8000
    targetPort: 8000
  type: ClusterIP
```

### Apply

```bash
kubectl apply -f rustberg.yaml
```

---

## Production Deployment

### Full Manifest

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rustberg
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: rustberg-config
  namespace: rustberg
data:
  config.toml: |
    [server]
    host = "0.0.0.0"
    port = 8000
    # The pod CIDR the ingress controller runs in. Without this every request is
    # attributed to the ingress pod, and X-Forwarded-For is ignored entirely.
    trusted_proxies = ["10.0.0.0/8"]

    [storage]
    # Postgres for a multi-replica deployment; supplied via RUSTBERG_CATALOG_URL
    # from the Secret below, so it is not repeated here.
    warehouse_location = "s3://my-bucket/warehouse"

    [server.auth]
    api_key_enabled = true

    [[server.auth.api_keys]]
    name    = "spark-etl"
    tenant  = "acme"
    roles   = ["writer"]
    key_env = "RUSTBERG_KEY_SPARK"

    [rate_limit]
    enabled = true
    requests_per_second = 1000

    [audit]
    sink = "stdout"
    fail_closed = true

    [logging]
    level = "info"
    json_format = true
---
apiVersion: v1
kind: Secret
metadata:
  name: rustberg-secrets
  namespace: rustberg
type: Opaque
stringData:
  # The catalog DSN, read by RUSTBERG_CATALOG_URL.
  dsn: "postgres://rustberg:secret@postgres:5432/rustberg"
  AWS_ACCESS_KEY_ID: "your-aws-key"
  AWS_SECRET_ACCESS_KEY: "your-aws-secret"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rustberg
  namespace: rustberg
  labels:
    app: rustberg
spec:
  replicas: 3   # stateless: the catalog lives in Postgres
  selector:
    matchLabels:
      app: rustberg
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    metadata:
      labels:
        app: rustberg
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8000"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: rustberg
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: rustberg
        image: ghcr.io/hupe1980/rustberg:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 8000
          name: http
        env:
        - name: AWS_REGION
          value: "us-east-1"
        envFrom:
        - secretRef:
            name: rustberg-secrets
        volumeMounts:
        - name: config
          mountPath: /etc/rustberg
          readOnly: true
        args:
        - "--config"
        - "/etc/rustberg/config.toml"
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "1000m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 1
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
      volumes:
      - name: config
        configMap:
          name: rustberg-config
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: rustberg
              topologyKey: kubernetes.io/hostname
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  namespace: rustberg
---
apiVersion: v1
kind: Service
metadata:
  name: rustberg
  namespace: rustberg
spec:
  selector:
    app: rustberg
  ports:
  - port: 8000
    targetPort: 8000
    name: http
  type: ClusterIP
---
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: rustberg
  namespace: rustberg
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: rustberg
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: rustberg
  namespace: rustberg
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: rustberg
  minReplicas: 2   # safe: the catalog is shared, pods are stateless
  maxReplicas: 6
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

---

## AWS EKS

### IAM Role for Service Account (IRSA)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  namespace: rustberg
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/rustberg-role
```

### IAM Policy

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
    },
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::123456789:role/rustberg-vending"
    }
  ]
}
```

### Trust Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:rustberg:rustberg"
        }
      }
    }
  ]
}
```

### Enabling credential vending

The `sts:AssumeRole` grant only lets the pod *reach* the vending role. Vending
needs a `[credentials]` section; otherwise the endpoint answers `501` and
clients use their own storage credentials.

```yaml
rustberg:
  config: |
    [storage]
    warehouse_location = "s3://my-bucket/rustberg-catalog"

    [credentials]
    provider = "aws"

    [credentials.aws]
    region           = "us-east-1"
    role_arn         = "arn:aws:iam::123456789:role/rustberg-vending"
    duration_seconds = 3600
```

| Role | Held by | Purpose |
|---|---|---|
| `rustberg-role` | the pod, via IRSA | Read and write catalog metadata |
| `rustberg-vending` | assumed per request | Downscoped and handed to clients |

- `rustberg-vending` needs the whole warehouse; an inline session policy
  narrows each credential to the requested table. Its trust policy must allow
  `rustberg-role`.
- `allowed_prefixes` defaults to the warehouse. Set it only to narrow vending.
- A misconfigured section (missing role, unset environment variable) is a
  **startup failure**: the container never becomes ready.

---

## GKE

### Workload Identity

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  namespace: rustberg
  annotations:
    iam.gke.io/gcp-service-account: rustberg@project-id.iam.gserviceaccount.com
```

### GCP IAM Binding

```bash
gcloud iam service-accounts add-iam-policy-binding \
  rustberg@project-id.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:project-id.svc.id.goog[rustberg/rustberg]"
```

### Storage Bucket Permissions

```bash
gsutil iam ch \
  serviceAccount:rustberg@project-id.iam.gserviceaccount.com:objectAdmin \
  gs://my-bucket
```

---

## AKS

### Workload Identity

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: rustberg
  namespace: rustberg
  annotations:
    azure.workload.identity/client-id: "<client-id>"
  labels:
    azure.workload.identity/use: "true"
```

### Federated Credential

```bash
az identity federated-credential create \
  --name rustberg-federated \
  --identity-name rustberg-identity \
  --resource-group mygroup \
  --issuer "${AKS_OIDC_ISSUER}" \
  --subject system:serviceaccount:rustberg:rustberg
```

---

## Ingress

### NGINX Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rustberg
  namespace: rustberg
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - catalog.example.com
    secretName: rustberg-tls
  rules:
  - host: catalog.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rustberg
            port:
              number: 8000
```

### AWS ALB

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: rustberg
  namespace: rustberg
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internet-facing
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:...
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS":443}]'
spec:
  rules:
  - host: catalog.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: rustberg
            port:
              number: 8000
```

---

## Monitoring

### ServiceMonitor (Prometheus Operator)

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: rustberg
  namespace: rustberg
spec:
  selector:
    matchLabels:
      app: rustberg
  endpoints:
  - port: http
    path: /metrics
    interval: 30s
```

### Grafana

No dashboard is shipped. Build one from what `/metrics` exports:

| Metric | Type | Labels |
|---|---|---|
| `rustberg_info` | gauge | `version` |
| `rustberg_build_timestamp_seconds` | gauge | — |
| `rustberg_requests_total` | counter | `method` |
| `rustberg_catalog_operations_total` | counter | `operation`, `result` |
| `rustberg_auth_attempts_total` | counter | `method`, `result` |
| `rustberg_rate_limit_exceeded_total` | counter | — |

`curl http://<pod>:8000/metrics` is the authoritative list (what the
`ServiceMonitor` scrapes).

---

## Troubleshooting

### Pod Not Starting

```bash
# Check events
kubectl describe pod -l app=rustberg -n rustberg

# Check logs
kubectl logs -l app=rustberg -n rustberg --tail=100
```

### S3 Permission Issues

The **distroless** image has no shell, `aws` or `curl`; only `rustberg` can be
`exec`d. Test from a throwaway pod with the *same* service account (it sets the
identity):

```bash
kubectl run s3-probe -n rustberg --rm -it --restart=Never \
  --image=amazon/aws-cli \
  --overrides='{"spec":{"serviceAccountName":"rustberg"}}' \
  -- s3 ls s3://my-bucket/rustberg-catalog/
```

A `403` here is the same IAM problem. Success here but failure in Rustberg is a
Rustberg configuration problem.

### Health Check Failures

The readiness probe is a kubelet `httpGet`; it needs nothing in the container.
By hand:

```bash
# From outside — the probe's own view
kubectl port-forward -n rustberg deployment/rustberg 8000:8000 &
curl -s localhost:8000/ready | jq

# From inside — the binary probes itself, which is also what the container
# image's own HEALTHCHECK runs
kubectl exec deployment/rustberg -n rustberg -- rustberg healthcheck
```

`/ready` names the component that is not ready (catalog store or warehouse).
`/health` only reports that the process is up.

---

## Best Practices

### Security

> - Use **network policies** to restrict pod communication
> - Enable **Pod Security Standards** (restricted)
> - Use **secrets management** (External Secrets, Vault)
> - Enable **audit logging** in the cluster

### High Availability

Rustberg uses **optimistic concurrency control**, not leader election:

```yaml
# Two or more replicas, with a Postgres catalog
replicaCount: 2

# Use pod anti-affinity to spread across nodes
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app.kubernetes.io/name
            operator: In
            values:
            - rustberg
        topologyKey: kubernetes.io/hostname
```

- All pods are equal: each accepts writes and serves reads. No active/passive,
  no failover, no replica to promote.
- Version-based CAS prevents dual writes (no split-brain); conflicts return
  `409` and clients retry.
- Reads need no coordination; pod restarts have no impact.

> - With the embedded redb catalog: **exactly 1 replica**, `strategy: Recreate`
> - Use **PodDisruptionBudget** to prevent simultaneous pod loss
> - Spread across **availability zones** with topology constraints
> - Monitor **409 Conflict** rate in metrics (should be low)

### Performance

> - Set appropriate **resource limits**
> - An HPA is safe with the Postgres catalog, and impossible with redb
> - Monitor **latency percentiles**
> - Use **regional** S3/GCS buckets

---

## Next Steps

- [Storage Backends](@/docs/storage.md) - Configure S3/GCS/Azure
- [Authentication](@/docs/authentication.md) - Secure access
- [Configuration](@/docs/configuration.md) - Full config reference
