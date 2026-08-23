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

Every catalog endpoint requires authentication. `/health`, `/ready` and
`/metrics` do not — a liveness probe cannot carry a credential.

An **API key** is accepted in either header:

```bash
X-API-Key: rb_your_api_key_here
Authorization: Bearer rb_your_api_key_here
```

The bearer form exists because Iceberg clients send their `token` property that
way; it carries the same key, and the explicit header wins if both are sent.

A **JWT** is accepted as a bearer token:

```bash
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

When both are configured, a bearer value is tried as a JWT first and falls through
to API-key validation. API keys carry the `rb_` prefix, so the two never collide.

### Rustberg does not issue tokens

`POST /v1/oauth/tokens` returns `501`. The Iceberg spec marks that endpoint
deprecated for removal and advises against implementing it; a catalog that mints
the credentials it validates has become an authorization server.

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

Reports the caller's own identity and nothing else. `roles` is the field to check
when policies are not matching: those strings become Cedar groups, so a policy
naming `Group::"analysts"` matches nothing if the credential says `analyst`.
`expires_at` is omitted when the credential does not expire.

This endpoint deliberately reports **no capability summary**. Whether a principal
"can create tables" has no single answer — authorization is per-resource and may
depend on request context — so no server-wide verdict is offered. Ask about a
specific resource instead.

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
`<VERB> <path>` form. Clients feature-detect from it, so paths carry the
`{prefix}` segment exactly as the OpenAPI spec writes them.

> **Schemas.** Rustberg does not ship its own copy of the Iceberg REST OpenAPI
> document. The authoritative one is
> [`rest-catalog-open-api.yaml`](https://github.com/apache/iceberg/blob/main/open-api/rest-catalog-open-api.yaml)
> in Apache Iceberg; generate clients from that. Which of its operations *this*
> server implements is answered at runtime by `endpoints` above — a maintained
> copy of the spec would only drift from both.

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

**Response:** `204 No Content`

---

## Tables

### List Tables

```http
GET /v1/namespaces/{namespace}/tables
```

Supports `pageToken` and `pageSize` — see [Pagination](#pagination). Only tables
the caller may read are returned, so this listing and a subsequent `loadTable`
always agree.

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

`format-version` selects the table format version — `1`, `2` or `3`, defaulting
to **2**. It is metadata rather than a property, so it is not stored among the
table's properties on the way out. The other reserved names (`uuid`,
`current-snapshot-id`, `snapshot-count` and the rest) are read-only and rejected
with `400`.

> **Staged table creation** (`stage-create: true`) is supported — see
> [staged creation](#staged-creation-create-table-as-select) below. This is what
> makes Spark's `CREATE TABLE AS SELECT` work. AWS Glue and S3 Tables both
> decline it.

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

`loadTable` is the most repeated call in the API — every query plan starts with
one — and the response is the whole metadata document, almost always unchanged.
Echo the `ETag` back to skip it entirely:

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

A `304` carries no body. `createTable` and the commit endpoint return an `ETag`
too, so a client that just wrote a table can make its next load conditional
without an intervening read.

A `304` is answered from the catalog's metadata *pointer* and never fetches the
metadata document — against object storage that document is a network round
trip, and skipping it is the point. A request that sends no `If-None-Match`
pays nothing for this: the tag is computed from the load that was happening
anyway.

The tag changes whenever the metadata does, and also when `snapshots` changes —
a tag obtained with `snapshots=refs` will not satisfy a request for
`snapshots=all`, because that is different content.

`If-None-Match` is evaluated **after** authorization. A caller that may not see
a table gets `404`, never `304`.

#### Snapshot scope

Table metadata carries every snapshot the table has ever retained. On a heavily
written table that is the bulk of the document, and a client planning a query
needs only what its branches and tags point at:

```http
GET /v1/namespaces/analytics/tables/events?snapshots=refs
```

| Value | Returns |
|---|---|
| `all` (default) | Every snapshot the table retains |
| `refs` | Only snapshots a branch or tag points at |

`all` remains the default because time travel and snapshot expiry both need
history that no ref points at; pruning by default would silently break them. A
value that is neither is `400`, not a silent fallback — a client that asked for
less must not be handed the full document while believing otherwise.

### Staged creation (`CREATE TABLE AS SELECT`)

`CREATE TABLE AS SELECT` has a chicken-and-egg problem: the engine must write
data files somewhere before the table exists, but the table should not appear
until the data is there. The spec solves it with a two-step flow, and Spark uses
it for both `CTAS` and `REPLACE TABLE AS SELECT`.

**1. Stage.** The catalog builds the table's first metadata and hands it back
*without creating the table*:

```http
POST /v1/namespaces/analytics/tables
{
  "name": "summary",
  "schema": { ... },
  "stage-create": true
}
```

The response is a normal `LoadTableResult` **with no `metadata-location`** — the
metadata is initialised but uncommitted, and the spec omits the field in exactly
that case.

At this point the table does not exist. It is not listed, `GET` returns `404`,
and it holds **no claim on the name**: another client may create the same name
for real, and the staged commit will then lose.

**2. Commit.** Once the engine has written its data files, it commits the whole
thing atomically with an `assert-create` requirement:

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

The table becomes visible at this moment, carrying its data from the first
snapshot. There is no window in which it exists and is empty.

| Situation | Result |
|---|---|
| Name taken by a real table before the commit | `409 Conflict` — re-read and decide |
| Staging the same name twice | Allowed; each mints fresh metadata and supersedes the last |
| Namespace dropped while staged | `404` — a staged table cannot be promoted into a namespace that no longer exists |
| `assert-create` with nothing staged | `404`, saying staging was expected |
| Stage abandoned | Nothing to clean up; it reserved nothing |

An `Idempotency-Key` on a staged create is **ignored**. Staging is not
idempotent by nature — each call mints fresh metadata — and replaying an older
response would leave the client committing against a base the catalog has
already replaced.

In a multi-replica deployment the staging note lives in Postgres, so a table
staged through one replica commits through any other. It is not process-local
state.

### Unregister Table

```http
POST /v1/namespaces/{namespace}/tables/{table}/unregister
```

Releases the catalog's pointer, leaving metadata and data files where they are,
so another catalog can adopt the table with `register`. Answers `204`.

`DELETE …/tables/{table}` without `purgeRequested` reaches the same state, so
why both? Intent. `DELETE` says *this table is finished*, and one query
parameter (`?purgeRequested=true`) turns it into data destruction. `unregister`
says *this table is moving*, and has no way to spell "delete the files" at all.
A migration script should not be one typo away from erasing a table.

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

When `purgeRequested=true`:
1. Table metadata is loaded to determine the storage location
2. Table is removed from the catalog registry
3. All files in the table's location are recursively deleted (data files, manifest files, metadata files)

**Example:**

```bash
# Drop table (keep data files)
curl -X DELETE "$CATALOG_URL/v1/namespaces/analytics/tables/events"

# Drop table and purge all data
curl -X DELETE "$CATALOG_URL/v1/namespaces/analytics/tables/events?purgeRequested=true"
```

Purge is a destructive operation and cannot be undone. All data files will be permanently deleted from storage.

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

Adopts view metadata that already exists in storage — the mirror of `register`
for tables. The metadata file is **read, never rewritten**, so the view's
version history survives being moved between catalogs.

The location is confined to the warehouse, and the `location` the metadata file
itself declares is re-checked after reading. See
[security](@/docs/security.md#credential-vending).

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

Commit changes to multiple tables atomically.

> **Multi-table transactions are atomic.** Every table advances or none does.
> Requirements are checked and new metadata files written first; then every
> pointer swaps inside a single backend transaction, re-verifying each table's
> version as it goes. A conflict rolls the whole thing back and is retried with
> exponential backoff.

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
- Every registry entry swapped inside one backend transaction
- Automatic retry with exponential backoff on conflicts (up to 10 retries)

**On Failure:**

- HTTP 409 for commit conflicts (after max retries exhausted)
- HTTP 500 for other failures
- Error message indicates all-or-nothing semantics
- No partial commits - either all tables are updated or none are

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


---

## Credentials

### Load Credentials

Short-lived credentials for a table's storage, without its metadata. Use this to
refresh an expiring credential when the client already holds the metadata.

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

Each entry applies to one `prefix`; clients pick the longest match. Credentials
are scoped to that prefix and no wider — an STS session policy restricts the
assumed role to the table's own objects.

**Access level follows the caller's permissions.** A principal permitted to
`Update` the table receives a credential that can write under the prefix; a
read-only principal receives one with no `s3:PutObject`.

**Responses:**

| Status | Meaning |
|--------|---------|
| `200` | Credentials vended |
| `403` | Policy attaches a row filter or column mask to this table — see below |
| `404` | No such table, or the caller may not read it |
| `501` | No credential provider is configured for this storage location |
| `503` | The exchange itself failed — an STS call that timed out, a role that cannot be assumed. Retrying is reasonable |

A `501` most often means the deployment simply has no `[credentials]` section,
which is the default. Configure one to enable vending — see
[configuration](@/docs/configuration.md#credentials). A `503` is different: the
mechanism is configured and broke, so it is not reported as an absent capability
and the server log names the cause.

A `403` here is a policy outcome, not a misconfiguration. A table whose matching
permits carry `@row_filter` or `@column_mask` is **never** handed a storage
credential: a credential is prefix-shaped and cannot express a row filter, so
vending one would grant strictly more than policy allows. The message names the
restricted columns but never quotes the filter expression. See
[authorization](@/docs/authorization.md#what-an-annotation-actually-does).

The same applies to `loadTable`: a restricted table returns `200` with metadata
and no `storage-credentials` field. A `loadTable` that *asked* for credentials
and could not be given them because the exchange failed is a `503`, not a silent
`200` — the response would otherwise carry metadata the caller cannot read and
look exactly like the ordinary uncredentialed case.

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

These are the exact `type` values the server emits.

| Code | Type | Description |
|------|------|-------------|
| 400 | BadRequestException | Invalid request, identifier, schema, page token, or JSON body |
| 401 | NotAuthorizedException | Missing or invalid credentials |
| 403 | ForbiddenException | Authenticated, but not permitted |
| 404 | NoSuchNamespaceException | Namespace not found |
| 404 | NoSuchTableException | Table not found |
| 404 | NoSuchViewException | View not found |
| 409 | AlreadyExistsException | Namespace, table, or view already exists |
| 409 | CommitFailedException | Optimistic concurrency conflict — retry |
| 409 | NamespaceNotEmptyException | Namespace still has tables or children |
| 422 | UnprocessableEntityException | Well-formed but semantically invalid |
| 429 | TooManyRequestsException | Rate limited |
| 500 | InternalServerError | Internal error |
| 501 | UnsupportedOperationException | Understood, but not provided by this deployment |
| 503 | ServiceUnavailableException | Temporarily unavailable |

A `409 CommitFailedException` is the normal outcome of two writers racing on one
table; clients retry with exponential backoff. A `501` means the operation exists
in the spec but this deployment does not offer it — credential vending with no
provider configured, for example.

Every error — including a malformed request body — uses this envelope. A client
can parse `error.type` on any failure without special-casing.

### 404 versus 403

A resource the caller may not **read** is reported as `404`, not `403` — the same
answer a genuinely missing resource gets. Otherwise the status code would let any
authenticated caller enumerate resources it cannot see, by distinguishing "exists
but forbidden" from "does not exist".

| Caller may read it? | Action permitted? | Answer |
|---|---|---|
| — (does not exist) | — | `404` |
| no | no | `404` |
| yes | no | `403` |
| yes | yes | proceeds |

So `403` appears only when the caller can already see the resource, which keeps
ordinary permission errors diagnosable. **When debugging, treat a `404` on a
resource you know exists as a missing `Read` grant.**

The same rule is why listings omit rather than fail: `listNamespaces`,
`listTables` and `listViews` return only what the caller may read.

---

## Scan planning

`POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/plan`

The catalog reads the snapshot's manifests, prunes the files a filter cannot
match, and returns the surviving scan tasks. That moves the manifest read off
every engine and onto one server.

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
      "residual-filter": { "type": "eq", "term": "region", "value": "EU" }
    }
  ]
}
```

Every plan completes in this response. Rustberg never answers `submitted`, emits
no `plan-tasks`, and therefore never uses `fetchScanTasks`: issuing work to poll
for means per-plan server-side state, which a replica set cannot share without a
session store. The `plan-id` names a plan that has already finished — `GET`ting
it reports that nothing is in progress, and `DELETE`ing it succeeds because there
is nothing to cancel.

### The filter

A subset of the spec's JSON expression grammar, bound by column **name**. The
same grammar a Cedar
[`@row_filter`](@/docs/authorization.md#writing-a-row-filter) is written in — and
when a matching permit carries one, it is conjoined with the filter you sent, so
a restricted caller is told about fewer files and the `residual-filter` carries
both halves.

| Accepted | |
|---|---|
| `true`, `false` | bare booleans, and the deprecated `{"type": "true"}` objects |
| `and`, `or`, `not` | `left`/`right`, and `child` for `not` |
| `is-null`, `not-null`, `is-nan`, `not-nan` | `child` (preferred) or `term` |
| `lt`, `lt-eq`, `gt`, `gt-eq`, `eq`, `not-eq`, `starts-with`, `not-starts-with` | `left`/`right`, or the deprecated `term`/`value` |
| `in`, `not-in` | `child`/`term` plus `values` |

Literals are typed by the column they are compared against, in the spec's
single-value form — a date is `"2023-01-01"`, a decimal and a UUID are strings,
binary and fixed are hex.

**Anything outside this is refused with `400`, never silently dropped.** That
covers transform terms, `apply`, references by field id, a column the table does
not have, and a literal that does not fit its column. A planner that ignored a
filter it could not read would prune against a predicate you did not write and
return *fewer* files than the scan needs — a wrong answer rather than a slow one.
If your filter is outside the grammar, send none and prune client-side.

The `residual-filter` on each task is the filter you sent, unchanged. That is
always correct because the client applies it, and it never claims a narrowing
that did not happen.

### Column statistics

Withheld unless asked for. Statistics carry the minimum and maximum value of
every column they describe, so sending them unasked publishes the contents of
columns a mask would hide.

```json
{ "stats-fields": ["id", "region"] }
```

Only the named fields appear in `column-sizes`, `value-counts`,
`null-value-counts`, `nan-value-counts`, `lower-bounds` and `upper-bounds`.
Naming a column the table does not have is a `400`.

### What is declined

| | Status | |
|---|---|---|
| Incremental scans (`start-snapshot-id`, `end-snapshot-id`) | `501` | Answering them as a full scan would return far more than was asked for |
| `stats-fields` naming a masked column | `403` | Statistics name the column's minimum and maximum values, which is what the mask hides |
| A policy row filter that cannot be applied to this table | `403` | Refused rather than returning files the filter was meant to withhold |
| A federated `rest` mount | `501` | Its manifests are in storage this server does not manage. The endpoint is absent from `/v1/config` when any mount cannot plan |
| More than 25 000 files in one plan | `400` | One plan is one response; a silently short plan reads less than the query asked for |

---

## Remote signing

`POST /v1/{prefix}/namespaces/{namespace}/tables/{table}/sign`

The delegation form where the engine holds **no** storage credential. Every
object request it wants to make is sent here first, authorized against the
policy set at that moment, and signed only if it is permitted.

| | Vended credentials | Remote signing |
|---|---|---|
| The engine holds | a credential scoped to the table prefix, for its lifetime | nothing |
| Rustberg sees | one request | every object request |
| A revoked grant takes effect | at the next credential expiry | on the next object read |
| Cost | one exchange per table | one round trip per object |

Ask for it with the delegation header. `loadTable` then returns
`remote-signing-config` and sets `s3.remote-signing-enabled`, `s3.signer` and
`s3.signer.endpoint` in `config`, which is what makes PyIceberg and the Java
client route their reads through the endpoint:

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

Only the headers signing *adds* come back — merge them into the request you
already built. `Cache-Control: private` on a read says the signature may be
reused for that exact request; a write is `no-cache`.

### What is signed, and what is refused

A signature is minted only when all of these hold:

1. The caller may `Read` the table, and `Update` it for anything mutating.
2. The table carries no row filter or column mask.
3. The table's storage is a warehouse this server manages — never a mount's.
4. Every location the request touches is inside the table's own location.

The fourth is where the work is, because the location is not always in the path.
`DeleteObjects` addresses the bucket and names its keys in an XML body;
`ListObjectsV2` addresses the bucket and names its prefix in the query string.
Both are resolved and confined, and a list prefix must sit *strictly* inside the
table location, because S3 matches prefixes as raw strings and `…/events` also
returns the keys of `…/events-secret`.

**Anything that cannot be resolved to a location is refused with `400`.** That
covers bucket-level sub-resources (`?versions`, `?uploads`, `?location`), methods
other than GET/HEAD/PUT/POST/DELETE/PATCH, and a `DeleteObjects` body this
endpoint cannot read exactly.

| Status | Means |
|---|---|
| `200` | Signed; merge `headers` into the request |
| `400` | The request cannot be resolved to a location inside a table |
| `403` | Outside the table, or the table is under row or column policy |
| `404` | The caller cannot see the table |
| `501` | This deployment does not offer remote signing |
| `503` | The signature could not be produced; retry is reasonable |

Only S3 and S3-compatible storage. GCS and ADLS have no equivalent
request-signing protocol in the Iceberg spec, so deployments there use vending.

Configure it with [`[credentials.signing]`](@/docs/configuration.md#remote-signing).
When it is not configured the endpoint is absent from `/v1/config` and answers
`501`.

---

## Idempotency

Send an `Idempotency-Key` on a mutating POST and a retry returns the original
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

On a Postgres catalog the receipt is stored in the same database, so a retry that
lands on a different replica is replayed rather than executed again.

A replayed response carries `Idempotency-Key-Used: true`.

**Use a fresh UUID per logical operation.** Keys must be 1–256 characters of ASCII
letters, digits, `-` and `_`; anything else is ignored, and the request proceeds
without idempotency rather than failing.

### What a key is scoped to

An entry belongs to **one principal, one method and one path**. Two callers
sending the same key never collide — the value is client-chosen, so collisions
would otherwise be routine, and a shared entry would let one caller read another's
response.

A replay is authorized like any other request. If your grant was revoked between
the original call and the retry, the retry is refused; a cached response is never
a way around policy.

### Credentials are not replayed

A cached `createTable` or `registerTable` response omits `storage-credentials`.
Vended credentials are short-lived and scoped to the request that minted them, so
replaying one from a 24-hour cache would hand back an expired secret. Call
`loadTable` or the credentials endpoint if a replay needs credentials.

### Across replicas

The cache is per-process. Behind a load balancer, a retry landing on another
replica is executed again rather than replayed — which is safe, because commits
are compare-and-swap: the retry either succeeds or returns `409`, and neither
loses data.

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

This matters because listings are filtered by policy: a page whose rows the caller
may not read comes back short — occasionally empty — while matches remain further
on. Rustberg pulls from the backend until the page is full or the source is
exhausted, so short pages are rare, but a request that reaches its scan bound
returns early with a token rather than scanning indefinitely. A client that stops
on an empty page silently truncates its results.

An absent token is definitive: there is nothing more.

### The token is opaque

It encodes the backend's own cursor. Pass it back unmodified; do not parse,
construct, or reuse one across a different listing. A token that cannot be decoded
is rejected with `400` rather than silently restarting from the first page, which
would make a client with a corrupted token loop forever. A token naming a
different namespace is ignored rather than honoured.

### Cost

Paging is keyset-based — redb seeks its sorted index, Postgres uses
`WHERE name > $cursor ... LIMIT n`. Neither uses `OFFSET`, so the thousandth page
costs what the first costs, and a concurrent insert cannot shift rows across a
page boundary.

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
it. A client running with its own storage credentials does not want the catalog
minting more, so nothing is vended or signed unrequested. (The dedicated
credentials endpoint is the exception — calling it *is* the request.)

Ask for `vended-credentials` to receive a short-lived credential in
`storage-credentials`, or `remote-signing` to hold none and have every object
request signed instead — see [Remote signing](#remote-signing). Ask for both and
you get both, and the client picks.

---

## Response headers

| Header | On | Meaning |
|---|---|---|
| `ETag` | `loadTable`, `createTable`, commit | Names this metadata version; echo it in `If-None-Match` |
| `X-Request-Id` | All | Request correlation ID |
| `Idempotency-Key-Used` | Replayed POSTs | The response came from the idempotency cache |

---

## Management API

Rustberg's own administration surface, under `/management/v1`. Deliberately
outside `/v1`, which is the Iceberg REST API that `GET /v1/config` claims to
describe completely.

| Method | Path | Requires |
|---|---|---|
| `GET` | `/management/v1/policies` | `Read` on the policy set |
| `PUT` | `/management/v1/policies` | `Manage` on the policy set |
| `GET` | `/management/v1/policies/history` | `Read` on the policy set |
| `POST` | `/management/v1/policies/rollback` | `Manage` on the policy set |

Policy changes take effect without a restart, and propagate to other replicas
within seconds. Full details in
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
the exact endpoint list this server serves, so clients feature-detect rather
than assume — the list below is what that response contains.

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

Also implemented, beyond the endpoint list: cursor pagination on every listing,
`Idempotency-Key` on mutating POSTs, `snapshots=all|refs`, `ETag`/`If-None-Match`
conditional loading, `stage-create` with `assert-create` commits, and table
format versions 1, 2 and 3 (new tables default to v2).

### Federation and capabilities

When catalogs are [mounted](@/docs/configuration.md#federation), the
`endpoints` list is the **intersection** of what every mount supports. One
read-only mount removes every mutating endpoint from it.

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

Renames and multi-table transactions are refused **across** mounts, because
neither can be made atomic between two independent catalogs.

A `rest` mount over somebody else's catalog is served read-only, and its
capabilities are negotiated from that catalog's own `GET /v1/config` — a remote
serving no view endpoints produces a mount reporting no views.

### Known limitations

Each of these is declined explicitly — a clear status code, never a silent
partial success.

| Not implemented | Status | Why, and what to do instead |
|---|---|---|
| Asynchronous scan planning (`plan-tasks`, `fetchScanTasks`) | — | Every plan is answered inline; there is nothing to poll for. See [Scan planning](#scan-planning). |
| Incremental scan planning | `501` | Declined rather than answered as a full scan. |
| `POST /v1/oauth/tokens` | `404` | Deprecated in the spec. Rustberg validates tokens, it does not issue them — `oauth2-server-uri` in the config response points at your IdP. |
| SQL UDFs (`…/namespaces/{ns}/functions`) | `404` | Function metadata is a third metadata document alongside tables and views, and `iceberg-rust` models none of it. |
| Row filters enforced against a hostile engine | — | Applied in the scan plan and withheld from credentials, but nothing makes an unplanned file unfetchable. See [authorization](@/docs/authorization.md). |
| Column masks as anything but advisory | — | Needs Parquet modular encryption; the masked bytes are in the file the engine downloads. |

### Storage locations are confined to the warehouse

`createTable`, `createView` and `registerTable` accept a client-supplied
location. Any location outside `storage.warehouse_location` is refused with
`400`. A registered table's metadata is read and its declared `location` checked
*before* the catalog records anything — a file at a legitimate path can still
declare a `location` elsewhere. See
[security](@/docs/security.md#credential-vending).

---

## Next Steps

- [Getting Started](@/docs/getting-started.md) - Quick setup
- [Authentication](@/docs/authentication.md) - API keys and JWT
- [Authorization](@/docs/authorization.md) - Cedar policies
