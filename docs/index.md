---
layout: home
title: Home
nav_order: 1
description: "Rustberg is a production-ready, single-binary Apache Iceberg REST Catalog written in 100% Rust."
permalink: /
---

# Rustberg
{: .fs-9 }

Zero-dependency Apache Iceberg REST Catalog
{: .fs-6 .fw-300 }

A **production-ready**, **single-binary** Apache Iceberg REST Catalog written in **100% Rust**. No JVM, no PostgreSQL, no C++ dependencies.
{: .fs-5 .fw-300 }

[Get Started](/rustberg/docs/getting-started){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/hupe1980/rustberg){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Why Rustberg?

Rustberg takes a different approach to Iceberg catalogs:

```bash
# That's it. One binary, no dependencies.
./rustberg --storage s3://my-bucket/catalog
```

No JVM warmup. No connection pool configuration. No external database. Just download and run.

---

## Key Features

| Feature | Description |
|---------|-------------|
| 🚀 **Instant Startup** | Sub-10ms cold start. No JVM warmup, no connection pooling delays. |
| 📦 **Single Binary** | One small executable. Deploy anywhere: Kubernetes, Lambda, bare metal, edge. |
| 📚 **Library Support** | Use as a crate to build custom Lambda handlers or embed in your application. |
| 🔐 **Security First** | API Keys (Argon2id), JWT/OIDC, Cedar authorization, TLS 1.3, rate limiting. |
| ☁️ **Cloud Native** | S3, GCS, Azure Blob storage. Horizontal scaling with SlateDB. |
| 🔌 **Full REST API** | Complete Iceberg REST spec: tables, views, transactions, credentials, metrics. |
| 🛡️ **Multi-Tenant** | Hard tenant isolation, Cedar policies, audit logging, credential vending. |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Rustberg Binary                           │
├──────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  REST API   │  │    Auth     │  │   Cedar     │              │
│  │  (Axum)     │  │  (JWT/Key)  │  │   AuthZ     │              │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘              │
│         │                │                │                      │
│         └────────────────┼────────────────┘                      │
│                          │                                       │
│  ┌───────────────────────▼───────────────────────┐              │
│  │              Iceberg Catalog                   │              │
│  │  • Namespaces  • Tables  • Views  • Commits   │              │
│  └───────────────────────┬───────────────────────┘              │
│                          │                                       │
│  ┌───────────────────────▼───────────────────────┐              │
│  │              SlateDB (Pure Rust)               │              │
│  └───────────────────────┬───────────────────────┘              │
│                          │                                       │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │ file:// │  │  s3://  │  │  gs://  │  │  az://  │            │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘            │
└──────────────────────────────────────────────────────────────────┘
```

---

## Use Cases

| Use Case | Why Rustberg? |
|----------|---------------|
| **Development** | Instant startup, zero config, embedded in tests |
| **CI/CD Testing** | Single binary, no Docker dependencies |
| **Edge Computing** | Tiny footprint, runs anywhere |
| **Kubernetes** | Helm chart included, horizontal scaling |
| **Single-Node Production** | Battle-tested, full feature set |

---

## Sponsors

Rustberg is open source under the [Apache License 2.0](https://github.com/hupe1980/rustberg/blob/main/LICENSE).

[⭐ Star on GitHub](https://github.com/hupe1980/rustberg){: .btn .btn-outline .fs-5 }

---

<small>Built with ❤️ in Rust</small>
