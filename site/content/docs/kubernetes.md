+++
title = "Kubernetes"
description = "Deploying Rustberg on Kubernetes: the Helm chart, replica shapes, probes, and network policy."
weight = 11
+++
> **Use the Postgres catalog.** The embedded redb catalog is a file with an
> exclusive lock, so a second pod cannot start — not even the extra pod a rolling
> update creates. On Kubernetes, point `catalog_url` at Postgres and the replicas
> are ordinary stateless pods. The Helm chart defaults to this.


Production Kubernetes deployment: stateless replicas over a shared catalog.

## Overview

Rustberg is designed for Kubernetes from the ground up:

| Feature | Benefit |
|---------|---------|
| **~35 ms startup** | Fast rescheduling, near-instant readiness |
| **~15 MB idle RSS** | Dense packing, low cost per replica |
| **Stateless pods** | Catalog in Postgres, warehouse in object storage |
| **No leader election** | Concurrency resolved by the database |
| **Health endpoints** | Native `/health` and `/ready` probes |

Startup and memory are measured; see [performance](@/docs/benchmarks.md).

---

## Helm Chart (Recommended)

The easiest way to deploy Rustberg on Kubernetes is using the Helm chart included in the repository.

> The Helm chart is not published to a registry. You must clone the repository to install it.

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

Kubernetes removes a pod from its Service's endpoints and sends it `SIGTERM` **at
the same time**, and the removal still has to reach every kube-proxy and ingress
controller. A pod that stops accepting the instant it is signalled refuses
whatever arrives in that window — connection errors on every rolling update.

A `preStop` hook that sleeps cannot fix it here: the image is distroless, so
there is no shell. Rustberg waits itself. After `SIGTERM` it keeps serving for
`shutdown.drainDelaySeconds` (passed as `--shutdown-delay`), then drains
in-flight requests, which get 30 seconds.

`terminationGracePeriodSeconds` must cover the delay *plus* the drain, or the
kubelet `SIGKILL`s the process partway through. The chart sets both.

A readiness probe does not replace this — it fails once the pod stops answering,
which is after the ingress has already routed to it. A `podDisruptionBudget`
bounds how many pods drain at once.

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

For full Helm chart documentation, see [charts/rustberg/README.md](https://github.com/hupe1980/rustberg/tree/main/charts/rustberg).

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

The `sts:AssumeRole` grant above lets the pod *reach* the vending role. It does
not switch vending on — that needs a `[credentials]` section, or the endpoint
answers `501` and clients fall back to their own storage credentials.

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

Two roles, doing different jobs:

| Role | Held by | Purpose |
|---|---|---|
| `rustberg-role` | the pod, via IRSA | Read and write catalog metadata |
| `rustberg-vending` | assumed per request | Downscoped and handed to clients |

`rustberg-vending` needs access to the whole warehouse; the inline session
policy narrows each vended credential to the one table the client asked for. Its
trust policy must allow `rustberg-role` to assume it.

`allowed_prefixes` is unset here, so it defaults to the warehouse — which is
what you want. Set it only to narrow vending further.

A misconfigured section is a **startup failure**, not a silently degraded pod:
the container will not become ready if the role is missing or an environment
variable it names is unset.

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

There is no dashboard to import — a JSON blob in the repository goes stale
against every Grafana release and against its own metric names. Build one from
what `/metrics` actually exports:

| Metric | Type | Labels |
|---|---|---|
| `rustberg_info` | gauge | `version` |
| `rustberg_build_timestamp_seconds` | gauge | — |
| `rustberg_requests_total` | counter | `method` |
| `rustberg_catalog_operations_total` | counter | `operation`, `result` |
| `rustberg_auth_attempts_total` | counter | `method`, `result` |
| `rustberg_rate_limit_exceeded_total` | counter | — |

`curl http://<pod>:8000/metrics` is the authoritative list; it is what the
`ServiceMonitor` above scrapes.

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

The image is **distroless** — no shell, no `aws`, no `curl` — so nothing can be
`exec`d into it except the `rustberg` binary itself. To test the pod's
credentials, run a throwaway pod with the *same* service account, which is what
actually decides the identity:

```bash
kubectl run s3-probe -n rustberg --rm -it --restart=Never \
  --image=amazon/aws-cli \
  --overrides='{"spec":{"serviceAccountName":"rustberg"}}' \
  -- s3 ls s3://my-bucket/rustberg-catalog/
```

A `403` here and a `403` from Rustberg are the same problem; a success here and a
failure there is a Rustberg configuration problem, not an IAM one.

### Health Check Failures

The readiness probe is an `httpGet` made by the kubelet, so it needs nothing
inside the container. To ask the same question by hand:

```bash
# From outside — the probe's own view
kubectl port-forward -n rustberg deployment/rustberg 8000:8000 &
curl -s localhost:8000/ready | jq

# From inside — the binary probes itself, which is also what the container
# image's own HEALTHCHECK runs
kubectl exec deployment/rustberg -n rustberg -- rustberg healthcheck
```

`/ready` names the component that is not ready — the catalog store or the
warehouse — which is the part worth reading. `/health` only reports that the
process is up.

---

## Best Practices

### Security

> - Use **network policies** to restrict pod communication
> - Enable **Pod Security Standards** (restricted)
> - Use **secrets management** (External Secrets, Vault)
> - Enable **audit logging** in the cluster

### High Availability

Rustberg achieves high availability through **optimistic concurrency control** rather than leader election:

```yaml
# Deploy 3+ replicas for HA
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

**How It Works:**
- All pods accept writes simultaneously (no active/passive)
- Version-based CAS prevents conflicting updates
- Conflicts return `409` status and clients retry
- No coordination overhead for reads

**Benefits:**
- **No split-brain:** Version numbers prevent dual writes
- **No leader failover:** All pods are equal
- **Read scaling:** every pod serves reads; there is no replica to promote
- **Automatic recovery:** Pod restarts have no impact

> - Run **exactly 1 replica** with `strategy: Recreate`
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
