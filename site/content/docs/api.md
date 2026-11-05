+++
title = "API reference"
description = "Every Iceberg REST endpoint Rustberg serves, what it returns, and what it declines with which status code."
weight = 9
+++
## Base URL

```
https://your-rustberg-host:8000
```

## Authentication

Every catalog endpoint requires authentication; `/health`, `/ready` and
`/metrics` do not.

An **API key** is accepted in either header:

```bash
X-API-Key: rb_your_api_key_here
Authorization: Bearer rb_your_api_key_here
```

The bearer form is how Iceberg clients send their `token` property. If both
headers are sent, `X-API-Key` wins.

A **JWT** is accepted as a bearer token:

```bash
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

When both are configured, a bearer value is tried as a JWT first, then as an API
key. API keys carry the `rb_` prefix, so the two never collide.

### Rustberg does not issue tokens

`POST /v1/oauth/tokens` returns `501`; the Iceberg spec deprecates it for removal.

Pass an API key as the client's **`token`** property, not `credential`. With OIDC,
set `oauth2-server-uri` to your identity provider — `/v1/config` advertises it
when configured. See [authentication](@/docs/authentication.md#rustberg-does-not-issue-tokens).

### Who am I?

```http
GET /auth/context
```

```json
{
  "principal": {
    "id": "f681b22f-2048-411f-9577-4dcc436888a9",
    "name": "bootstrap-admin",
    "principal_type": "api_key",
    "tenant_id": "acme",
    "roles": ["admin"],
    "auth_method": "api_key",
    "expires_at": "2026-01-25T12:00:00+00:00"
  }
}
```

Reports the caller's own identity only. Check `roles` when policies do not match:
they become Cedar groups, so `Group::"analysts"` matches nothing if the
credential says `analyst`. `expires_at` is omitted for a non-expiring credential.

There is **no capability summary**: authorization is per-resource and may depend
on request context, so ask about a specific resource.

---

## Configuration

### Get Configuration

Returns catalog configuration and defaults.

```http
GET /v1/config
```

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `warehouse` | Optional. Selects a warehouse. Rustberg serves a single warehouse, so naming a different one returns `400`. |

**Response:**

```json
{
  "overrides": { "warehouse": "s3://my-bucket/warehouse" },
  "defaults": {},
  "endpoints": [
    "GET /v1/{prefix}/namespaces",
    "POST /v1/{prefix}/namespaces",
    "GET /v1/{prefix}/namespaces/{namespace}/tables/{table}"
  ],
  "idempotency-key-lifetime": "PT24H"
}
```

`endpoints` lists every operation this server implements, in the spec's
`<VERB> <path>` form, with the `{prefix}` segment exactly as the OpenAPI spec
writes it. Clients feature-detect from it.

Two entries depend on **storage access** configuration and appear only when they
can succeed:

| Entry | Present when |
|---|---|
| `POST …/tables/{table}/sign` | remote signing is configured ([`[credentials.signing]`](@/docs/configuration.md)) |
| `GET …/tables/{table}/credentials` | a credential provider covers **every** warehouse this catalog serves |

Both endpoints stay routed either way, so a mixed deployment keeps working where
it can; without a credential provider, `loadCredentials` answers `501`.

> **Schemas.** Rustberg ships no copy of the Iceberg REST OpenAPI document.
> Generate clients from Apache Iceberg's
> [`rest-catalog-open-api.yaml`](https://github.com/apache/iceberg/blob/main/open-api/rest-catalog-open-api.yaml);
> `endpoints` above says which operations this server implements.

---

## Namespaces

### List Namespaces

```http
GET /v1/namespaces
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `parent` | string | Parent namespace; levels joined with `\u001F`. Lists direct children only. |
| `pageToken` | string | See [Pagination](#pagination) |
| `pageSize` | integer | See [Pagination](#pagination) |

Only namespaces the caller may read are returned.

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

**Response:** `204 No Content`, or `409 Conflict` if the namespace still holds
tables or views, or carries `rustberg.protected = "true"` — see
[protection](#drop-table).

---

## Tables

### List Tables

```http
GET /v1/namespaces/{namespace}/tables
```

Supports `pageToken` and `pageSize` — see [Pagination](#pagination). Only tables
the caller may read are returned, so the listing and `loadTable` agree.

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
  ],
  "next-page-token": null
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
    "format-version": "3",
    "write.format.default": "parquet"
  }
}
```

**Response:** `200 OK` with table metadata

`format-version` selects the table format version — `1`, `2` or `3`, default
**2**. It is metadata, not a stored property. The other reserved names (`uuid`,
`current-snapshot-id`, `snapshot-count` and the rest) are read-only and rejected
with `400`.

> **Staged table creation** (`stage-create: true`) is supported — see
> [staged creation](#staged-creation-create-table-as-select) below. Spark's
> `CREATE TABLE AS SELECT` depends on it.

### Load Table

```http
GET /v1/namespaces/{namespace}/tables/{table}
```

| Query parameter | Values | Default | Meaning |
|---|---|---|---|
| `snapshots` | `all`, `refs` | `all` | How much snapshot history to return |

| Request header | Meaning |
|---|---|
| `If-None-Match` | An `ETag` you already hold; an unchanged table answers `304` |
| `X-Iceberg-Access-Delegation` | Ask for `vended-credentials` or `remote-signing` (nothing is delegated unrequested) |

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
  "config": {},
  "storage-credentials": []
}
```

The response carries an `ETag` naming this exact metadata version.

#### Conditional loading

Echo the `ETag` back to skip re-sending unchanged metadata:

```console
$ curl -sD- -o/dev/null http://localhost:8000/v1/namespaces/analytics/tables/events
HTTP/1.1 200 OK
etag: "6f1c0a2b9d3e4f5061728394a5b6c7d8"

$ curl -sD- -o/dev/null \
    -H 'If-None-Match: "6f1c0a2b9d3e4f5061728394a5b6c7d8"' \
    http://localhost:8000/v1/namespaces/analytics/tables/events
HTTP/1.1 304 Not Modified
etag: "6f1c0a2b9d3e4f5061728394a5b6c7d8"
```

A `304` has no body and is answered from the catalog's metadata *pointer*,
without fetching the metadata document. `createTable` and the commit endpoint
also return an `ETag`.

The tag differs between `snapshots=refs` and `snapshots=all`, and between callers
whose policies restrict the table **differently**, as well as whenever the
metadata changes.

`If-None-Match` is evaluated **after** authorization: a caller that may not see
the table gets `404`, never `304`.

Tagged responses carry `Cache-Control: private, no-cache` (revalidate before
reuse, so a revoked grant is caught on the next load). Untagged responses keep
the catalog-wide default of `no-store`.

##### Delegation and caching

`X-Iceberg-Access-Delegation` decides which representation `loadTable` returns.

| Asked for | `ETag`? | Why |
|---|---|---|
| Nothing | yes | Metadata only |
| `remote-signing` | yes, a **different** one | The signer block holds no secret, but it is a different document |
| `remote-signing`, on a table policy restricts | yes, a **third** one | No signer block; the tag covers *which* `read-restrictions` apply |
| `vended-credentials` | **no** | The response carries a freshly minted, expiring credential |

A credentialed load is never answered `304`, never tagged, and keeps
`Cache-Control: no-store`.

#### Snapshot scope

A client planning a query usually needs only the snapshots branches and tags
point at:

```http
GET /v1/namespaces/analytics/tables/events?snapshots=refs
```

| Value | Returns |
|---|---|
| `all` (default) | Every snapshot the table retains |
| `refs` | Only snapshots a branch or tag points at |

`all` is the default because time travel and snapshot expiry need unreferenced
history. Any other value is `400`.

#### View chain (`referenced-by`)

A load reached through views may name the chain: outermost first,
comma-separated, each entry `{namespace}{separator}{name}`, with the separator
from `/config` (default `%1F`):

```http
GET /v1/namespaces/analytics/tables/events?referenced-by=prod%1Fanalytics%1Fquarterly
```

The chain is audited only; authorization is unchanged. An unreadable chain is
ignored. Send a comma inside a name as `%2C`.

### Staged creation (`CREATE TABLE AS SELECT`)

A two-step flow that lets an engine write data files before the table appears.
Spark uses it for `CTAS` and `REPLACE TABLE AS SELECT`.

**1. Stage.** The catalog returns the table's first metadata *without creating
the table*:

```http
POST /v1/namespaces/analytics/tables
{
  "name": "summary",
  "schema": { ... },
  "stage-create": true
}
```

The response is a `LoadTableResult` **with no `metadata-location`**.

Until committed, the table is not listed, `GET` returns `404`, and it holds **no
claim on the name**; if another client creates the name first, the staged commit
loses.

**2. Commit.** The engine commits atomically with `assert-create`:

```http
POST /v1/namespaces/analytics/tables/summary
{
  "requirements": [{ "type": "assert-create" }],
  "updates": [
    { "action": "add-snapshot", "snapshot": { ... } },
    { "action": "set-snapshot-ref", "ref-name": "main", ... }
  ]
}
```

The table appears at this moment, with its data; it never exists empty.

| Situation | Result |
|---|---|
| Name taken by a real table before the commit | `409 Conflict` — re-read and decide |
| Staging the same name twice | Allowed; each mints fresh metadata and supersedes the last |
| Namespace dropped while staged | `404` |
| `assert-create` with nothing staged | `404`, saying staging was expected |
| Stage abandoned | Nothing to clean up; it reserved nothing |

An `Idempotency-Key` on a staged create is **ignored**, since each call mints
fresh metadata.

In a multi-replica deployment the staging note lives in Postgres, so any replica
can commit it.

### Unregister Table

```http
POST /v1/namespaces/{namespace}/tables/{table}/unregister
```

Releases the catalog's pointer and leaves all files in place, so another catalog
can adopt the table with `register`. Answers `204`. `DELETE` without
`purgeRequested` reaches the same state, but `unregister` cannot purge, so
prefer it for migrations.

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

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `purgeRequested` | boolean | `false` | When `true`, also delete all underlying data files |

**Purge Behavior:**

When `purgeRequested=true`, the catalog walks the table's manifests and deletes
the files they reference — data files, delete files, manifests, manifest lists,
Puffin statistics and metadata files — **that live under the table's own
`location`**.

- **Files outside the location** are skipped and logged by path, because
  manifests are engine-written and the catalog deletes with its own storage role.
  A skipped file is left as an orphan.
- **No recursive delete** of the location: two tables can share a prefix
  (`s3://wh/db/events` and `s3://wh/db/events-archive`). Unreferenced files are
  left for [orphan-file cleanup](#known-limitations), a maintenance job.
- **An unreadable manifest** leaves its files as orphans; a warning counts them
  and the drop succeeds (the table is already dropped by then). The usual cause
  is a snapshot expired outside this catalog.
- **`write.data.path` and `write.metadata.path` are not honoured** as extra
  roots. Files a table declares outside its location survive a purge, with a
  warning at purge time.

Likewise, every metadata file the catalog writes for a table or view goes to
`<location>/metadata/`, whatever `write.metadata.path` says. The property stays
on the table, unchanged, for engines writing with their own credentials.

Data files are also gated by the table's `gc.enabled` property: `false` keeps
the data on a purge.

**Protection**

A table, view or namespace carrying `rustberg.protected = "true"` refuses to be
dropped or purged:

```bash
curl -X DELETE http://localhost:8000/v1/namespaces/analytics/tables/events \
  -H "X-API-Key: $API_KEY"
# 409 Conflict
# Table 'analytics.events' is protected from deletion. Clear the
# 'rustberg.protected' property first, then retry.
```

`409`, not `403`: you are permitted, but the resource's state forbids it. Set the
property at creation, or later:

```bash
curl -X POST http://localhost:8000/v1/namespaces/analytics/tables/events \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"requirements": [],
       "updates": [{"action": "set-properties",
                    "updates": {"rustberg.protected": "true"}}]}'
```

Only the exact value `true` protects, case-insensitively. `"yes"`, `"1"` and
`""` do not.

> **This stops an accident, not an adversary.** Anyone who can set the property
> can clear it. For a hard stop, write a Cedar `forbid` on `Delete`.

**Example:**

```bash
# Drop table (keep data files)
curl -X DELETE "$CATALOG_URL/v1/namespaces/analytics/tables/events"

# Drop table and purge all data
curl -X DELETE "$CATALOG_URL/v1/namespaces/analytics/tables/events?purgeRequested=true"
```

Purge cannot be undone.

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

### Register View

```http
POST /v1/namespaces/{namespace}/register-view
{
  "name": "summary",
  "metadata-location": "s3://bucket/warehouse/analytics/summary/metadata/00003-....json"
}
```

Adopts view metadata already in storage, like `register` for tables. The file is
**read, never rewritten**, so version history survives the move.

The location is confined to the view's name prefix, and the file's own
`location` is re-checked after reading. See
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).

### Drop View

```http
DELETE /v1/namespaces/{namespace}/views/{view}
```

**Response:** `204 No Content`, or `409 Conflict` if the view carries
`rustberg.protected = "true"` — see [protection](#drop-table).

### View Exists

```http
HEAD /v1/namespaces/{namespace}/views/{view}
```

### Commit View

```http
POST /v1/namespaces/{namespace}/views/{view}
```

Takes `requirements` and `updates` like a table commit; the only view
requirement in the spec is `assert-view-uuid`.

Concurrency is optimistic: the pointer swaps **only if it still points at what
was loaded**, otherwise `409 CommitFailedException`. Reload and re-apply.

`assert-view-uuid` only pins the view's *identity*; every version shares one
UUID, so it does not detect concurrent changes.

### Rename View

```http
POST /v1/views/rename
```

---

## Transactions

### Commit Transaction

Commit changes to multiple tables atomically: every table advances or none does.

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

**Atomicity Guarantee:**
- All requirements validated across all tables BEFORE any changes
- All metadata files written (orphan files are safe)
- Every pointer swapped inside one backend transaction, re-verifying each table's version
- A conflict rolls everything back; automatic retry with exponential backoff (up to 10 retries)

**On Failure:**

- HTTP 409 for commit conflicts (after max retries exhausted)
- HTTP 500 for other failures
- The error message states the all-or-nothing semantics
- No partial commits — either all tables are updated or none are

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

## Credentials

### Load Credentials

Short-lived storage credentials for a table, without its metadata — for
refreshing an expiring credential.

```http
GET /v1/namespaces/{namespace}/tables/{table}/credentials
```

**Response:**

```json
{
  "storage-credentials": [
    {
      "prefix": "s3://bucket/warehouse/analytics/events/",
      "config": {
        "s3.access-key-id": "ASIATEMP...",
        "s3.secret-access-key": "...",
        "s3.session-token": "..."
      }
    }
  ]
}
```

Each entry applies to one `prefix`; clients pick the longest match. An STS
session policy scopes each credential to that prefix and no wider.

**Access follows the caller's permissions.** `Update` on the table yields a
write-capable credential; read-only principals get one without `s3:PutObject`.

**Responses:**

| Status | Meaning |
|--------|---------|
| `200` | Credentials vended |
| `403` | Policy attaches a row filter or column mask to this table — see below |
| `404` | No such table, or the caller may not read it |
| `501` | No credential provider is configured for this storage location |
| `503` | The exchange failed (STS timeout, role cannot be assumed). Retrying is reasonable |

`501` usually means no `[credentials]` section (the default) — see
[configuration](@/docs/configuration.md#credentials). `503` means vending is
configured but failed; the server log names the cause.

`403` is a policy outcome: a table whose matching permits carry `@row_filter` or
`@column_mask` is **never** given a storage credential, since a prefix-scoped
credential cannot express a row filter. The message names the restricted columns
but never quotes the filter. See
[authorization](@/docs/authorization.md#what-an-annotation-actually-does).

Likewise, a restricted `loadTable` returns `200` with metadata and no
`storage-credentials` field. A `loadTable` whose requested credential exchange
failed is a `503`.

### `read-restrictions`

A restricted `loadTable` also carries `read-restrictions`, the Iceberg REST
extension telling a conforming reader what to apply:

```json
{
  "metadata-location": "s3://warehouse/db/people/metadata/00001-....json",
  "metadata": { "...": "..." },
  "read-restrictions": {
    "required-row-filter": {
      "type": "eq",
      "left":  { "type": "reference", "id": 1 },
      "right": { "type": "literal", "value": "EU" }
    },
    "required-column-projections": [
      { "action": "replace-with-null", "field-id": 2 }
    ]
  }
}
```

Columns are addressed by **field id**, surviving renames. A supporting reader
must apply both, or **fail the query** rather than return raw, partial or empty
results.

- **It relaxes nothing.** The credential is still withheld and the signer block
  absent. It is for engines reading with their *own* storage credentials, and is
  cooperative: a hostile engine ignores it.
- **A mask becomes `replace-with-null` on an optional column and
  `mask-to-fixed-value` on a required one**; the spec forbids nulling a required
  field.
- **A filter this table cannot carry becomes `false`.** A tenant-wide
  `@row_filter` naming a column a table lacks publishes
  `"required-row-filter": false` there: metadata readable, no rows. It is never
  omitted, since omission would mean unrestricted.

The field is absent when no policy restricts the caller on that table.

### Server-side planning and pre-signed URLs

A restricted `loadTable` also sets `scan-planning-mode` in `config`:

```json
{ "config": { "scan-planning-mode": "server" } }
```

The specification defines `server` as *"Clients MUST use server-side scan planning
via the `planTableScan` endpoint"*. The client never reads manifests, so never
sees files the policy filter excluded; selected files come back as
**pre-signed URLs**, one per file.

```json
{
  "file-scan-tasks": [
    { "data-file": {
        "content": "data",
        "file-path": "https://wh.s3.eu-west-1.amazonaws.com/db/t/data/00000-0-....parquet?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=900&X-Amz-Signature=..."
    }}
  ]
}
```

The caller still gets **no** `storage-credentials` and **no**
`remote-signing-config`.

Limits:

- **A pre-signed URL is a bearer token** until it expires.
  `credentials.signing.presign_ttl_seconds` sets the window; default `900`.
- **S3 only.** On GCS or ADLS a restricted table's plan is refused with `501`:
  there is no pre-signed URL form to deliver it with.
- **A client ignoring the MUST** and reading manifests sees excluded files'
  *metadata* but cannot fetch them: no credential, signature, or URL.

An unrestricted table sets no `scan-planning-mode`; its plan returns ordinary
paths.

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

**Response:** `200 OK` when this replica can serve, `503` when it cannot.

```json
{
  "status": "ready",
  "version": "0.4.1",
  "timestamp": 1704067200,
  "components": {
    "catalog": { "status": "ready" },
    "storage": { "status": "ready", "message": "s3:12ms" }
  }
}
```

The two components are the only things that can be unreachable at runtime.

The probe is cached for two seconds, because `/ready` is unauthenticated and not
rate-limited.

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

**Every** catalog error uses this envelope, including malformed JSON bodies,
invalid path parameters and unparseable namespaces. Only `/health` and `/ready`
(own shapes) and `/metrics` (Prometheus text) differ.

`message` is a sentence; `type` is the machine-readable name. A full-sentence
message has no prefix (`"The namespace contains U+200B, which is…"`, not
`"Bad request: the namespace contains…"`); a bare-identifier message keeps its
verb prefix: `"Table does not exist: analytics.events"`.

### Every 401 is the same 401

Missing, malformed, unknown, revoked, expired, bad signature — all get the
identical response, because some are reachable only after the constant-time hash
comparison succeeds and naming them would confirm a real key. Operators find the
reason in the audit record, joined by `X-Request-Id`.

Every `401` carries `WWW-Authenticate: Bearer realm="rustberg"`, as RFC 9110
requires. `Bearer` covers both mechanisms: an API key is also accepted as
`Authorization: Bearer <key>`, which PyIceberg's `token` property uses.

### Error Codes

These are the exact `type` values the server emits.

| Code | Type | Description |
|------|------|-------------|
| 400 | BadRequestException | Invalid request, identifier, schema, page token, or JSON body |
| 401 | NotAuthorizedException | Missing or invalid credentials — one answer for every way of failing, see [below](#every-401-is-the-same-401) |
| 403 | ForbiddenException | Authenticated, but not permitted |
| 404 | NoSuchNamespaceException | Namespace not found |
| 404 | NoSuchTableException | Table not found |
| 404 | NoSuchViewException | View not found |
| 404 | NoSuchSnapshotException | Snapshot id not in this table |
| 404 | NoSuchReferenceException | Branch or tag not in this table |
| 404 | NoSuchPlanIdException | Every plan completes inline; see [Scan planning](#scan-planning) |
| 404 | NoSuchPlanTaskException | The same, for `fetchScanTasks` |
| 404 | NotFoundException | The path is not part of this catalog's API |
| 405 | MethodNotAllowedException | The path exists but does not take that method |
| 409 | AlreadyExistsException | Namespace already exists, or the identifier is already a table **or** a view — see [one name, one thing](#one-name-one-thing) |
| 409 | CommitFailedException | Optimistic concurrency conflict — retry |
| 409 | NamespaceNotEmptyException | Namespace still has tables or children |
| 409 | ProtectedException | `rustberg.protected = "true"` refuses the drop or purge |
| 422 | UnprocessableEntityException | Well-formed but semantically invalid |
| 429 | TooManyRequestsException | Rate limited |
| 500 | InternalServerError | Internal error |
| 501 | UnsupportedOperationException | Understood, but not provided by this deployment |
| 503 | ServiceUnavailableException | Temporarily unavailable |

`409 CommitFailedException` is the normal result of two writers racing; retry
with exponential backoff. On a **format version 3** table it also covers two
writers stamping the same `first-row-id` from the same read; the loser refreshes
and retries (it is not reported as the metadata library's "invalid row id"
`400`).

`501` means the spec defines the operation but this deployment does not offer
it, e.g. credential vending with no provider.

### 404 versus 403

A resource the caller may not **read** is reported as `404`, like a missing one,
so hidden resources cannot be enumerated.

| Caller may read it? | Action permitted? | Answer |
|---|---|---|
| — (does not exist) | — | `404` |
| no | no | `404` |
| yes | no | `403` |
| yes | yes | proceeds |

`403` appears only when the caller can already see the resource. **When
debugging, treat a `404` on a resource you know exists as a missing `Read`
grant.** Listings likewise omit what the caller may not read.

---

## Scan planning

`POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan`

The catalog reads the snapshot's manifests, prunes files a filter cannot match,
and returns the surviving scan tasks, so engines do not read manifests
themselves.

```bash
curl -X POST http://localhost:8000/v1/namespaces/analytics/tables/events/plan \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"filter": {"type": "eq", "term": "region", "value": "EU"}}'
```

```json
{
  "status": "completed",
  "plan-id": "9a5f…",
  "file-scan-tasks": [
    {
      "data-file": {
        "content": "data",
        "file-path": "s3://wh/analytics/events/data/region=EU/00000.parquet",
        "file-format": "parquet",
        "spec-id": 0,
        "partition": ["EU"],
        "file-size-in-bytes": 1234,
        "record-count": 2
      },
      "residual-filter": {
        "type": "eq",
        "left": { "type": "reference", "id": 2 },
        "right": { "type": "literal", "value": "EU" }
      }
    }
  ]
}
```

Every plan completes in this response. Rustberg never answers `submitted` and
emits no `plan-tasks`.

The follow-up endpoints are routed and return Iceberg error bodies (not a bare
router `404`):

| | |
|---|---|
| `GET …/plan/{plan-id}` | `404 NoSuchPlanIdException` — the plan already finished |
| `DELETE …/plan/{plan-id}` | `204` — a no-op, so clients can clean up unconditionally |
| `POST …/tasks` (`fetchScanTasks`) | `404 NoSuchPlanTaskException` — no `plan-task` was ever issued |

All three are advertised in `endpoints` alongside `POST …/plan`, and disappear
together on a mount that cannot plan.

### The filter

A subset of the spec's JSON expression grammar, bound by column **name** — the
same grammar as a Cedar
[`@row_filter`](@/docs/authorization.md#writing-a-row-filter). A matching
permit's filter is ANDed with yours.

| Accepted | |
|---|---|
| `true`, `false` | bare booleans, and the deprecated `{"type": "true"}` objects |
| `and`, `or`, `not` | `left`/`right`, and `child` for `not` |
| `is-null`, `not-null`, `is-nan`, `not-nan` | `child` (preferred) or `term` |
| `lt`, `lt-eq`, `gt`, `gt-eq`, `eq`, `not-eq`, `starts-with`, `not-starts-with` | `left`/`right`, or the deprecated `term`/`value` |
| `in`, `not-in` | `child`/`term` plus `values` |

Literals are typed by their column, in the spec's single-value form: a date is
`"2023-01-01"`, decimals and UUIDs are strings, binary and fixed are hex. Every
timestamp type, including `timestamp_ns` and `timestamptz_ns`, accepts that
string or the stored integer.

*Unsupported* terms — a transform, `apply`, a field-id reference, an operator
from a newer spec — are **widened**, not refused: they stop contributing to
pruning, so you get a *superset* of matching files, and `residual-filter` still
carries the whole predicate. Widening is polarity-aware (under a `not` it widens
to "everything"), so a plan never returns fewer files than needed.

*Malformed* filters — an unknown column, a literal that does not fit its column,
a missing operand, `is-nan` on a non-float column — are `400`. Every operator,
including unary ones, binds its column against the schema.

> **A Cedar `@row_filter` is the other way round.** A policy filter that cannot
> be bound to the planned table selects **no files** — the same `false`
> `read-restrictions` publish.
>
> An operator or term outside the table above cannot bind against *any* table, so
> it is refused when the **policy set loads**: a misspelled `"type": "equals"` is
> a startup failure, not a `403` at query time.

Each task's `residual-filter` is your filter plus any matching permit's
`@row_filter`; the policy half references columns by **field id**, as
`read-restrictions` do. Apply both halves: pruning is conservative, so a
surviving file may hold rows the policy filter excludes.

### Column statistics

Withheld unless requested, because they carry each column's minimum and maximum.

```json
{ "stats-fields": ["id", "region"] }
```

Only the named fields appear in `column-sizes`, `value-counts`,
`null-value-counts`, `nan-value-counts`, `lower-bounds` and `upper-bounds`.
Naming a column the table does not have is a `400`.

Names resolve with the request's `case-sensitive` flag. The **mask** check then
ignores case, so the flag cannot unlock a masked column's bounds under another
spelling.

It compares the **full dotted path**, as `@column_mask` names it: a mask on
`user.ssn` withholds statistics for `user.ssn`, not for a top-level `ssn`.

### What is declined

| | Status | |
|---|---|---|
| Incremental scans (`start-snapshot-id`, `end-snapshot-id`) | `501` | A full scan would return far more than asked for |
| `stats-fields` naming a masked column | `403` | Statistics expose the column's minimum and maximum, which the mask hides |
| A `@column_mask` over a column the table is **partitioned** on | `403` | Every file carries its partition tuple, and Iceberg writes partition values into the object key, so a plan would publish the column |
| A policy row filter that cannot be applied to this table | `403` | Refused rather than returning files the filter was meant to withhold |
| A table in a federated `rest` mount | `501` | Its manifests are in storage this server does not manage. Refused **per namespace**: native tables beside it still plan, though `/v1/config` stops advertising the endpoint once any mount cannot plan |
| More than 25 000 files in one plan | `400` | One plan is one response; a silently short plan would read less than asked |

---

## Remote signing

`POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/sign`

The engine holds **no** storage credential. Each object request is sent here
first, authorized against the current policy set, and signed only if permitted.

| | Vended credentials | Remote signing |
|---|---|---|
| The engine holds | a credential scoped to the table prefix, for its lifetime | nothing |
| Rustberg sees | one request | every object request |
| A revoked grant takes effect | at the next credential expiry | on the next object read |
| Cost | one exchange per table | one round trip per object |

Ask for it with the delegation header. `loadTable` then returns
`remote-signing-config` and sets `s3.remote-signing-enabled`, `s3.signer` and
`s3.signer.endpoint` in `config`, which routes PyIceberg and Java client reads
through the endpoint:

```bash
curl http://localhost:8000/v1/namespaces/analytics/tables/events \
  -H "X-API-Key: $API_KEY" \
  -H "X-Iceberg-Access-Delegation: remote-signing"
```

The request and response are the spec's `RemoteSignRequest` and
`RemoteSignResult`:

```json
{
  "region": "eu-west-1",
  "method": "GET",
  "uri": "https://wh.s3.eu-west-1.amazonaws.com/analytics/events/data/00000.parquet",
  "headers": { "x-amz-content-sha256": ["UNSIGNED-PAYLOAD"] }
}
```

```json
{
  "uri": "https://wh.s3.eu-west-1.amazonaws.com/analytics/events/data/00000.parquet",
  "headers": { "Authorization": ["AWS4-HMAC-SHA256 Credential=…"] }
}
```

Only the headers signing *adds* come back; merge them into your request. **Use
the returned `uri`**, not the one you sent: it is the resolved form the signature
covers. `Cache-Control: private` on a read allows reusing the signature for that
exact request; a write is `no-cache`.

### What is signed, and what is refused

A signature is minted only when all of these hold:

1. The caller may `Read` the table, and `Update` it for anything mutating.
2. The table carries no row filter or column mask.
3. The table's storage is a warehouse this server manages — never a mount's.
4. The request is one of the S3 operations this endpoint knows how to authorize.
5. Every location the request touches is inside the table's own location.

Points 4 and 5 need care: neither the operation nor the locations are reliably
in the path.

#### The operation is not the method

S3 dispatches on a **sub-resource** in the query string, so one `PUT` to one key
is `PutObject`, `PutObjectAcl`, `PutObjectTagging` or `RestoreObject`. Only the
first writes data: `PUT …/events/data/00000.parquet?acl` with
`x-amz-acl: public-read` passes every containment check and publishes the file.

So the endpoint signs an **allowlist** of operations:

| Signed | Not signed |
|---|---|
| `GetObject`, `HeadObject`, `PutObject`, `DeleteObject` | `?acl`, `?policy`, `?ownershipControls` — who may read it |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` (`?uploads`, `?uploadId`) | `?retention`, `?legal-hold`, `?object-lock`, `?lifecycle` — how long it survives |
| `DeleteObjects` (`?delete`) | `?requestPayment`, `?restore`, `?intelligent-tiering` — what it costs |
| `ListObjectsV2` (`?list-type=2`) | `?replication`, `?notification`, `?logging`, `?inventory` — what leaves the bucket |
| `UploadPartCopy`/`CopyObject`, when the source is inside the same table | `?tagging`, `?versioning`, `?website`, `?cors`, `?encryption`, `?select`, `?torrent` |

`x-amz-acl` and `x-amz-grant-*` are refused too: a signature authorizes *this*
request, not future grants to others.

Only S3 sub-resources are filtered; ordinary SDK parameters (`x-id`,
`versionId`, response-header overrides, list continuation tokens) pass through.

#### A location can be in the body, the query string, or a header

`DeleteObjects` names keys in an XML body; `ListObjectsV2` names a prefix in the
query string. Both are resolved and confined; a list prefix must sit *strictly*
inside the table location, since `…/events` also matches `…/events-secret`.

`x-amz-copy-source` is confined like the destination. Otherwise a `PUT` to
`…/events/data/00000.parquet` with

```
x-amz-copy-source: /other-bucket/secrets/private.parquet
```

would copy an object you may not read into your table, using **the catalog's**
storage role.

#### The URI that comes back is the URI that was checked

Locations are resolved with a URL parser, which removes `.` and `..` segments
and, under `http`/`https`, treats a backslash as a separator. All three of

```
https://wh.s3.amazonaws.com/other/../analytics/events/data/00000.parquet
https://wh.s3.amazonaws.com/other\..\..\analytics\events\data\00000.parquet
https://wh.s3.amazonaws.com/analytics/events/data/x/%2E%2E/00000.parquet
```

resolve to `…/analytics/events/data/00000.parquet`, though S3 takes keys
literally. The endpoint signs and returns the **resolved** URI, so what was
checked is what was signed; S3 refuses any other spelling. PyIceberg and the
Java `S3V4RestSignerClient` already use the returned `uri`.

**Anything not resolvable to a location and an allowlisted operation is
refused**: bucket-level operations other than `DeleteObjects` and
`ListObjectsV2`, methods outside GET/HEAD/PUT/POST/DELETE/PATCH, and a
`DeleteObjects` body or `x-amz-copy-source` this endpoint cannot read exactly.

| Status | Means |
|---|---|
| `200` | Signed; merge `headers` into the request |
| `400` | The request cannot be resolved to a location, or is an operation this endpoint does not sign |
| `403` | Outside the table, or the table is under row or column policy |
| `404` | The caller cannot see the table |
| `501` | This deployment does not offer remote signing |
| `503` | The signature could not be produced; retry is reasonable |

S3 and S3-compatible storage only; use vending on GCS or ADLS.

Configure it with [`[credentials.signing]`](@/docs/configuration.md#remote-signing).
Unconfigured, the endpoint is absent from `/v1/config` and answers `501`.

---

## Idempotency

Send an `Idempotency-Key` on a mutating POST, and a retry returns the original
response instead of a `409`:

```bash
curl -X POST http://localhost:8000/v1/namespaces/analytics/tables \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: 01895c3e-8844-7fff-a5cb-7a583a3e51fe" \
  -d '{"name": "events", "schema": {...}}'
```

Supported on `createNamespace`, `createTable`, `registerTable`, `commitTable`,
`createView`, `commitView` and `commitTransaction`. The reuse window is reported
as `idempotency-key-lifetime` in `/v1/config` (24 hours by default).

With a Postgres catalog the receipt lives in the database, so a retry on another
replica is replayed. A replayed response carries `Idempotency-Key-Used: true`.

**Use a fresh UUID per logical operation.** Keys must be 1–256 ASCII letters,
digits, `-` and `_`; other keys are ignored and the request runs without
idempotency.

### What a key is scoped to

An entry belongs to **one principal, one method and one path**; callers sharing
a key never see each other's responses.

A replay is authorized like any request: a grant revoked since the original call
refuses the retry.

### Credentials are not replayed

A cached `createTable` or `registerTable` response omits `storage-credentials`,
which could have expired; call `loadTable` or the credentials endpoint instead.

### Across replicas

With a Postgres catalog the receipts are shared, so a retry on another replica
is replayed. (The embedded catalog runs one replica.)

---

## Rate Limiting

A rate-limited response carries:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 60
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1706313600
```

---

## Pagination

`listNamespaces`, `listTables` and `listViews` are paged:

```http
GET /v1/namespaces?pageSize=50&pageToken=abc123
```

```json
{
  "namespaces": [...],
  "next-page-token": "def456"
}
```

| Parameter | Default | Maximum |
|-----------|---------|---------|
| `pageSize` | 100 | 1000 (values above are clamped) |
| `pageToken` | — | Opaque; pass back verbatim |

### Stop on the token, not on the page

**Keep requesting while `next-page-token` is present, even if a page is short or
empty. Only an absent token means the listing has ended.**

Listings are filtered by policy, so a page can be short or empty while matches
remain, and a request that reaches its scan bound returns early with a token.

### The token is opaque

It encodes the backend's cursor. Pass it back unmodified; do not parse,
construct, or reuse it across listings. An undecodable token is `400`, not a
silent restart. A token naming a different namespace is ignored.

### Cost

Paging is keyset-based (redb seeks its sorted index; Postgres uses
`WHERE name > $cursor ... LIMIT n`), never `OFFSET`: every page costs the same,
and concurrent inserts cannot shift rows across pages.

---

## Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | One of these | `Bearer <api-key>` or `Bearer <jwt>` |
| `X-API-Key` | One of these | An API key, explicitly |
| `Content-Type` | Yes (POST) | `application/json` |
| `Idempotency-Key` | No | Makes a retried POST safe — see [Idempotency](#idempotency) |
| `X-Request-Id` | No | Request correlation ID; echoed back |
| `X-Iceberg-Access-Delegation` | No | `vended-credentials`, `remote-signing`, or both |

Storage access is delegated **only** when `X-Iceberg-Access-Delegation` asks for
it, except on the credentials endpoint, where the call itself is the request.
`vended-credentials` returns a short-lived credential in `storage-credentials`;
`remote-signing` returns none and signs each object request — see
[Remote signing](#remote-signing). Ask for both to get both; the client picks.

---

## Response headers

| Header | On | Meaning |
|---|---|---|
| `ETag` | `loadTable`, `createTable`, commit | Names this metadata version; echo it in `If-None-Match` |
| `X-Request-Id` | All | Request correlation ID |
| `Idempotency-Key-Used` | Replayed POSTs | The response came from the idempotency cache |

---

## Management API

Rustberg's own administration surface, under `/management/v1` — outside `/v1`,
which `GET /v1/config` describes completely.

| Method | Path | Requires |
|---|---|---|
| `GET` | `/management/v1/policies` | `Read` on the policy set |
| `PUT` | `/management/v1/policies` | `Manage` on the policy set |
| `GET` | `/management/v1/policies/history` | `Read` on the policy set |
| `GET` | `/management/v1/policies/revisions/{sequence}` | `Read` on the policy set |
| `POST` | `/management/v1/policies/rollback` | `Manage` on the policy set |

Policy changes take effect without a restart and reach other replicas within
seconds. Details in
[authorization](@/docs/authorization.md#administering-policy-at-runtime).

**Responses:**

| Status | Meaning |
|---|---|
| `200` | The revision **this replica enforces**, plus `latest_sequence` from the store |
| `400` | The policy set does not typecheck, or would lock the author out |
| `403` | The caller may not administer policy |
| `404` | Rollback named a revision that does not exist |
| `501` | This deployment evaluates no policy (`--no-auth`) |

---

## Spec coverage

Rustberg implements the Iceberg REST Catalog v1 API. `GET /v1/config` reports
the exact endpoint list this server serves; the list below is what it contains.

### Implemented

| Area | Endpoints |
|---|---|
| Config | `GET /v1/config` |
| Namespaces | list, create, load, exists, drop, update properties |
| Tables | list, create, **stage-create**, load, exists, commit, drop, purge, rename, register, **unregister** |
| Views | list, create, load, exists, commit, drop, rename, **register-view** |
| Transactions | `POST /v1/{prefix}/transactions/commit` (atomic, multi-table) |
| Metrics | `POST …/tables/{table}/metrics` |
| Credentials | `GET …/tables/{table}/credentials` |
| Remote signing | `POST …/tables/{table}/sign`, when configured |
| Scan planning | `POST …/tables/{table}/plan`, plus `GET`/`DELETE` on `…/plan/{plan-id}` |

Also implemented: cursor pagination on every listing, `Idempotency-Key` on
mutating POSTs, `snapshots=all|refs`, `ETag`/`If-None-Match`, `stage-create`
with `assert-create` commits, and table format versions 1, 2 and 3 (default v2).

### Federation and capabilities

With [mounted](@/docs/configuration.md#federation) catalogs, `endpoints` is the
**intersection** of what every mount supports; one read-only mount removes every
mutating endpoint.

An operation a mount cannot perform is refused with `501` naming the mount:

```json
{
  "error": {
    "message": "Mount 'legacy' does not support writing. It is served by a backend that cannot perform this operation, so it is refused rather than partially applied.",
    "type": "UnsupportedOperationException",
    "code": 501
  }
}
```

Renames and multi-table transactions **across** mounts are refused; they cannot
be atomic between independent catalogs.

A `rest` mount over another catalog is read-only, with capabilities taken from
that catalog's `GET /v1/config` (no remote view endpoints, no views).

### Known limitations

Each is declined explicitly, never a silent partial success.

| Not implemented | Status | Why, and what to do instead |
|---|---|---|
| Asynchronous scan planning (`plan-tasks`, `fetchScanTasks`) | — | Every plan is answered inline. See [Scan planning](#scan-planning). |
| Incremental scan planning | `501` | Declined rather than answered as a full scan. |
| `POST /v1/oauth/tokens` | `501` | Deprecated for removal in the spec; Rustberg validates tokens, it does not issue them. Use `oauth2-server-uri` in the config response for your IdP. The path is *routed* and answers without a credential, since `credential=` clients call it first and a `401` would read as a bad key. |
| SQL UDFs (`…/namespaces/{ns}/functions`) | `404` | `iceberg-rust` does not model function metadata. |
| Row filters enforced against a hostile engine | — | Enforced at **file** granularity: an unplanned file gets no pre-signed URL and no credential. Rows inside a delivered file are the reader's to filter. See [authorization](@/docs/authorization.md). |
| Column masks as anything but advisory | — | Needs Parquet modular encryption; the masked bytes are in the downloaded file. |
| Compaction and file-level maintenance | — | Not a catalog operation. See [Table maintenance](#table-maintenance). |

### Table maintenance

Rustberg does not compact, rewrite manifests or hunt orphan files. All three
rewrite data, which would put the catalog in the data path that the
[row- and column-security story](@/docs/authorization.md) requires it to stay out
of, and need durable long-running jobs that stateless replicas do not run.

**The metadata half is served through the ordinary REST surface**, with
compare-and-swap commits, per-operation authorization, and an audit record
naming the principal:

| Operation | How it arrives |
|---|---|
| Expire snapshots | `RemoveSnapshots` in `POST …/tables/{table}` |
| Drop a branch or tag | `RemoveSnapshotRef` in the same call |
| Discard statistics | `RemoveStatistics`, `RemovePartitionStatistics` |
| Delete a dropped table's files | `DELETE …/tables/{table}?purgeRequested=true` |

Spark's `expire_snapshots`, or any Iceberg REST maintenance system, works
against Rustberg; data rewriting needs its own engine.

### One name, one thing

A namespace holds one thing per name. `createTable`, `createView`, `renameTable`
and `renameView` answer `409` when the identifier is taken by a table *or* a
view, as the spec requires. (Both kinds live at `<warehouse>/<namespace>/<name>`,
so a collision would let a table purge delete a view's files.)

Staging does not claim a name; the claim happens at the commit.

### A storage location is confined to the resource that names it

Client-supplied locations on `createTable`, `createView` and `registerTable`,
and `set-location` on a commit, are confined to `<warehouse>/<namespace>/<name>`
(the layout this catalog assigns anyway). Anything outside is `400`. Any layout
*under* that prefix is allowed.

`add-snapshot`, `set-statistics` and `set-partition-statistics` are confined to
the table's **own location**, where a renamed table's files still are (a rename
never moves them).

The bound is the resource's prefix, not the warehouse, because it is a security
boundary; see
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).

A registered resource's metadata is read and its declared `location` checked
*before* the catalog records anything.

`storage.location_scope = "warehouse"` widens the bound to the warehouse, for
adopting a pre-existing lake. See
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary) and
[configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files).

---

## Next Steps

- [Getting Started](@/docs/getting-started.md) - Quick setup
- [Authentication](@/docs/authentication.md) - API keys and JWT
- [Authorization](@/docs/authorization.md) - Cedar policies
