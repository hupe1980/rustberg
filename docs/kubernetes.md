---
layout: default
title: Kubernetes
nav_order: 10
description: "Deploy Rustberg on Kubernetes with horizontal scaling"
permalink: /docs/kubernetes
---

# Kubernetes Deployment
{: .no_toc }

Production-ready Kubernetes deployment with horizontal scaling.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Overview

Rustberg is designed for Kubernetes from the ground up:

| Feature | Benefit |
|---------|---------|
| **Sub-10ms startup** | Fast pod scheduling, instant readiness |
| **~9MB memory** | Dense packing, lower costs |
| **Stateless** | Horizontal scaling with shared storage |
| **SlateDB + S3** | No leader election needed |
| **Health endpoints** | Native K8s probes |

---

## Helm Chart (Recommended)

The easiest way to deploy Rustberg on Kubernetes is using the Helm chart included in the repository.

{: .note }
> The Helm chart is not published to a registry. You must clone the repository to install it.

### Installation

```bash
# Clone the repository
git clone https://github.com/hupe1980/rustberg
cd rustberg

# Install with default values
helm install rustberg charts/rustberg

# Or install with custom values
helm install rustberg charts/rustberg -f my-values.yaml
```

### Basic Configuration

```yaml
# values.yaml
replicaCount: 3

rustberg:
  storage:
    type: s3
    s3:
      bucket: my-iceberg-bucket
      region: us-east-1
      existingSecret: aws-credentials

  auth:
    enabled: true
    apiKeys:
      enabled: true

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
  storage:
    type: s3
    s3:
      bucket: production-catalog
      region: us-east-1

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
      keyId: alias/rustberg-dek
      region: us-east-1

resources:
  requests:
    memory: "64Mi"
    cpu: "100m"
  limits:
    memory: "256Mi"
    cpu: "1000m"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

podDisruptionBudget:
  enabled: true
  minAvailable: 2

serviceMonitor:
  enabled: true
  interval: 30s
```

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
  replicas: 3
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
        - containerPort: 8181
        env:
        - name: RUSTBERG_STORAGE
          value: "s3://my-bucket/rustberg-catalog"
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
            port: 8181
          initialDelaySeconds: 1
          periodSeconds: 5
        livenessProbe:
          httpGet:
            path: /health
            port: 8181
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
  - port: 8181
    targetPort: 8181
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
    port = 8181
    request_timeout_secs = 30

    [storage]
    object_store_url = "s3://my-bucket/rustberg-catalog"

    [auth]
    require_authentication = true
    persistent_api_keys = true

    [rate_limit]
    enabled = true
    requests_per_second = 1000
    trust_proxy_headers = true

    [logging]
    level = "info"
    format = "json"
---
apiVersion: v1
kind: Secret
metadata:
  name: rustberg-secrets
  namespace: rustberg
type: Opaque
stringData:
  RUSTBERG_MASTER_KEY: "your-base64-encoded-32-byte-key"
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
  replicas: 3
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
        prometheus.io/port: "8181"
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
        - containerPort: 8181
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
            port: 8181
          initialDelaySeconds: 1
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3
        livenessProbe:
          httpGet:
            path: /health
            port: 8181
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
  - port: 8181
    targetPort: 8181
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
  minReplicas: 3
  maxReplicas: 10
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
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789:key/*"
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
              number: 8181
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
              number: 8181
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

### Grafana Dashboard

Import the Rustberg dashboard from `docs/grafana-dashboard.json`.

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

```bash
# Test from pod
kubectl exec -it deployment/rustberg -n rustberg -- \
  aws s3 ls s3://my-bucket/rustberg-catalog/
```

### Health Check Failures

```bash
# Manual health check
kubectl exec -it deployment/rustberg -n rustberg -- \
  curl -s localhost:8181/health
```

---

## Best Practices

### Security

{: .important }
> - Use **network policies** to restrict pod communication
> - Enable **Pod Security Standards** (restricted)
> - Use **secrets management** (External Secrets, Vault)
> - Enable **audit logging** in the cluster

### High Availability

Rustberg achieves high availability through **optimistic concurrency control** rather than leader election:

```yaml
# Deploy 3+ replicas for HA
replicaCount: 3

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
- **Linear read scaling:** N replicas = N× read throughput
- **Automatic recovery:** Pod restarts have no impact

{: .important }
> - Run **minimum 3 replicas** for fault tolerance
> - Use **PodDisruptionBudget** to prevent simultaneous pod loss
> - Spread across **availability zones** with topology constraints
> - Monitor **409 Conflict** rate in metrics (should be low)

### Performance

{: .important }
> - Set appropriate **resource limits**
> - Use **HPA** for auto-scaling
> - Monitor **latency percentiles**
> - Use **regional** S3/GCS buckets

---

## Next Steps

- [Storage Backends](/rustberg/docs/storage) - Configure S3/GCS/Azure
- [Authentication](/rustberg/docs/authentication) - Secure access
- [Configuration](/rustberg/docs/configuration) - Full config reference
