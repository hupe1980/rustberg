---
layout: default
title: API Reference
nav_order: 7
description: "Iceberg REST Catalog API reference: endpoints, authentication, examples"
permalink: /docs/api
---

# API Reference
{: .no_toc }

Complete Iceberg REST Catalog API documentation.
{: .fs-6 .fw-300 }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Base URL

```
https://your-rustberg-host:8181
```

## Authentication

All endpoints require authentication via `Authorization` header:

```bash
Authorization: Bearer rustberg_your_api_key_here
```

Or JWT token:

```bash
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

---

## Configuration

### Get Configuration

Returns catalog configuration and defaults.

```http
GET /v1/config
```

**Response:**

```json
{
  "defaults": {},
  "overrides": {}
}
```

---

## Namespaces

### List Namespaces

```http
GET /v1/namespaces
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `parent` | string | Parent namespace (optional) |
| `pageToken` | string | Pagination token |
| `pageSize` | integer | Results per page (default: 100) |

**Response:**

```json
{
  "namespaces": [
    ["analytics"],
    ["raw", "events"]
  ],
  "next-page-token": "abc123"
}
```

### Create Namespace

```http
POST /v1/namespaces
```

**Request:**

```json
{
  "namespace": ["analytics"],
  "properties": {
    "owner": "data-team"
  }
}
```

**Response:** `200 OK`

```json
{
  "namespace": ["analytics"],
  "properties": {
    "owner": "data-team"
  }
}
```

### Get Namespace

```http
GET /v1/namespaces/{namespace}
```

**Response:**

```json
{
  "namespace": ["analytics"],
  "properties": {
    "owner": "data-team"
  }
}
```

### Update Namespace Properties

```http
POST /v1/namespaces/{namespace}/properties
```

**Request:**

```json
{
  "updates": {
    "description": "Analytics tables"
  },
  "removals": ["deprecated-key"]
}
```

### Drop Namespace

```http
DELETE /v1/namespaces/{namespace}
```

**Response:** `204 No Content`

---

## Tables

### List Tables

```http
GET /v1/namespaces/{namespace}/tables
```

**Response:**

```json
{
  "identifiers": [
    {
      "namespace": ["analytics"],
      "name": "events"
    },
    {
      "namespace": ["analytics"],
      "name": "users"
    }
  ]
}
```

### Create Table

```http
POST /v1/namespaces/{namespace}/tables
```

**Request:**

```json
{
  "name": "events",
  "location": "s3://my-bucket/analytics/events",
  "schema": {
    "type": "struct",
    "schema-id": 0,
    "fields": [
      {
        "id": 1,
        "name": "id",
        "required": true,
        "type": "long"
      },
      {
        "id": 2,
        "name": "event_type",
        "required": true,
        "type": "string"
      },
      {
        "id": 3,
        "name": "timestamp",
        "required": true,
        "type": "timestamptz"
      }
    ]
  },
  "partition-spec": {
    "spec-id": 0,
    "fields": [
      {
        "source-id": 3,
        "field-id": 1000,
        "name": "ts_day",
        "transform": "day"
      }
    ]
  },
  "properties": {
    "write.format.default": "parquet"
  }
}
```

**Response:** `200 OK` with table metadata

### Load Table

```http
GET /v1/namespaces/{namespace}/tables/{table}
```

**Response:**

```json
{
  "metadata-location": "s3://bucket/metadata/v1.metadata.json",
  "metadata": {
    "format-version": 2,
    "table-uuid": "abc123",
    "location": "s3://bucket/table",
    "schema": {...},
    "partition-spec": {...},
    "properties": {...}
  },
  "config": {
    "s3.access-key-id": "AKIA...",
    "s3.secret-access-key": "..."
  }
}
```

### Update Table (Commit)

```http
POST /v1/namespaces/{namespace}/tables/{table}
```

**Request:**

```json
{
  "identifier": {
    "namespace": ["analytics"],
    "name": "events"
  },
  "requirements": [
    {
      "type": "assert-current-schema-id",
      "current-schema-id": 0
    }
  ],
  "updates": [
    {
      "action": "add-schema",
      "schema": {
        "type": "struct",
        "fields": [...]
      }
    },
    {
      "action": "set-current-schema",
      "schema-id": 1
    }
  ]
}
```

### Table Exists

```http
HEAD /v1/namespaces/{namespace}/tables/{table}
```

**Response:** `204 No Content` (exists) or `404 Not Found`

### Drop Table

```http
DELETE /v1/namespaces/{namespace}/tables/{table}
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `purgeRequested` | boolean | Also delete data files |

**Response:** `204 No Content`

### Rename Table

```http
POST /v1/tables/rename
```

**Request:**

```json
{
  "source": {
    "namespace": ["analytics"],
    "name": "events_old"
  },
  "destination": {
    "namespace": ["analytics"],
    "name": "events_new"
  }
}
```

### Register Table

Register an existing table from a metadata file location.

```http
POST /v1/namespaces/{namespace}/register
```

**Request:**

```json
{
  "name": "imported_events",
  "metadata-location": "s3://bucket/metadata/v1.metadata.json"
}
```

---

## Views

### List Views

```http
GET /v1/namespaces/{namespace}/views
```

### Create View

```http
POST /v1/namespaces/{namespace}/views
```

### Load View

```http
GET /v1/namespaces/{namespace}/views/{view}
```

### Drop View

```http
DELETE /v1/namespaces/{namespace}/views/{view}
```

### View Exists

```http
HEAD /v1/namespaces/{namespace}/views/{view}
```

### Commit View

```http
POST /v1/namespaces/{namespace}/views/{view}
```

### Rename View

```http
POST /v1/views/rename
```

---

## Transactions

### Commit Transaction

Atomically commit changes to multiple tables.

```http
POST /v1/transactions/commit
```

**Request:**

```json
{
  "table-changes": [
    {
      "identifier": {
        "namespace": ["analytics"],
        "name": "events"
      },
      "requirements": [...],
      "updates": [...]
    },
    {
      "identifier": {
        "namespace": ["analytics"],
        "name": "events_summary"
      },
      "requirements": [...],
      "updates": [...]
    }
  ]
}
```

**Response:** `204 No Content` on success

---

## Metrics

### Report Metrics

Report table operation metrics from clients.

```http
POST /v1/namespaces/{namespace}/tables/{table}/metrics
```

**Request:**

```json
{
  "table-name": "analytics.events",
  "snapshot-id": 1234567890,
  "filter": "timestamp > '2026-01-01'",
  "schema-id": 0,
  "projected-field-ids": [1, 2, 3],
  "projected-field-names": ["id", "event_type", "timestamp"],
  "metrics": {
    "total-planning-duration": {"unit": "nanos", "value": 123456},
    "total-data-manifests": {"unit": "count", "value": 5},
    "total-files-size": {"unit": "bytes", "value": 1073741824}
  }
}
```

---

## Search

### Search Catalog

Search for tables and views across namespaces.

```http
GET /v1/search
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `query` | string | Search query |
| `type` | string | `table` or `view` (optional) |

**Response:**

```json
{
  "results": [
    {
      "type": "table",
      "identifier": {
        "namespace": ["analytics"],
        "name": "events"
      }
    }
  ]
}
```

---

## Credentials

### Load Credentials

Get temporary credentials for accessing table storage.

```http
GET /v1/namespaces/{namespace}/tables/{table}/credentials
```

**Response:**

```json
{
  "s3.access-key-id": "ASIATEMP...",
  "s3.secret-access-key": "...",
  "s3.session-token": "...",
  "expiration-ms": 3600000
}
```

---

## Health & Metrics

### Health Check

```http
GET /health
```

**Response:** `200 OK`

```json
{
  "status": "healthy"
}
```

### Readiness Check

```http
GET /ready
```

**Response:** `200 OK` when ready to serve traffic

### Prometheus Metrics

```http
GET /metrics
```

**Response:** Prometheus text format

```
# HELP rustberg_requests_total Total HTTP requests
# TYPE rustberg_requests_total counter
rustberg_requests_total{method="GET",status="200"} 1234
```

---

## Error Responses

### Error Format

```json
{
  "error": {
    "message": "Table not found",
    "type": "NoSuchTableException",
    "code": 404
  }
}
```

### Error Codes

| Code | Type | Description |
|------|------|-------------|
| 400 | BadRequestException | Invalid request format |
| 401 | NotAuthenticatedException | Missing/invalid auth |
| 403 | NotAuthorizedException | Insufficient permissions |
| 404 | NoSuchNamespaceException | Namespace not found |
| 404 | NoSuchTableException | Table not found |
| 409 | AlreadyExistsException | Resource already exists |
| 409 | CommitFailedException | Optimistic concurrency failure |
| 422 | ValidationException | Business rule violation |
| 429 | TooManyRequestsException | Rate limited |
| 500 | ServiceException | Internal error |

---

## Rate Limiting

When rate limited, response includes:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1706313600
```

---

## Pagination

List endpoints support cursor-based pagination:

```http
GET /v1/namespaces?pageSize=50&pageToken=abc123
```

**Response:**

```json
{
  "namespaces": [...],
  "next-page-token": "def456"
}
```

When `next-page-token` is null or absent, no more results.

---

## Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes | Bearer token |
| `Content-Type` | Yes (POST) | `application/json` |
| `X-Request-Id` | No | Request correlation ID |
| `X-Iceberg-Access-Delegation` | No | `vended-credentials` |

---

## Next Steps

- [Getting Started](/rustberg/docs/getting-started) - Quick setup
- [Authentication](/rustberg/docs/authentication) - API keys and JWT
- [Authorization](/rustberg/docs/authorization) - Cedar policies
