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

Two entries depend on how **storage access** was configured rather than on a
backend, and appear only when they can succeed:

| Entry | Present when |
|---|---|
| `POST …/tables/{table}/sign` | remote signing is configured ([`[credentials.signing]`](@/docs/configuration.md)) |
| `GET …/tables/{table}/credentials` | a credential provider covers **every** warehouse this catalog serves |

A deployment with no credential provider can only ever answer `501` on
`loadCredentials`, and an advertised endpoint that always fails is worse than an
absent one — a client feature-detects once at startup and then assumes. The
endpoints stay routed either way, so a mixed deployment keeps working where it
can; what it stops doing is promising.

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

The tag changes whenever the metadata does, and also whenever anything else
about the document does: `snapshots=refs` and `snapshots=all` are different
content and never share a tag, and neither do a caller whose policy restricts the
table and one whose policy does not — a restricted caller is refused delegation,
so its response is missing the signer block. Different content, different tag,
in all three directions.

`If-None-Match` is evaluated **after** authorization. A caller that may not see
a table gets `404`, never `304`.

A response carrying a tag also carries `Cache-Control: private, no-cache`.
`no-cache` does not mean *do not cache* — it means the stored copy may not be
reused without revalidating here first, which is what a validator is for, and why
a grant revoked since the last load is caught on the next one. `private` keeps
the response, which is scoped to one principal, out of shared caches. Responses
without a tag keep the catalog-wide default of `no-store`.

##### Delegation and caching

`loadTable` is not one representation, and `X-Iceberg-Access-Delegation` decides
which one you get.

| Asked for | `ETag`? | Why |
|---|---|---|
| Nothing | yes | Metadata only, and it changes only when the table does |
| `remote-signing` | yes, a **different** one | The signer block is derived from the table's identity and holds no secret, so it caches — but it is a different document, and must not share a tag with the plain one |
| `remote-signing`, on a table policy restricts | yes, a **third** one | A restricted table is refused delegation, so the signer block is absent. Two principals asking the same question of the same table get two documents, and they must not share a tag either |
| `vended-credentials` | **no** | The response carries a freshly minted, expiring credential |

A credentialed load is never answered `304` and never carries a tag. A `304` has
no body, so a client that echoed a tag *and* asked for a credential would be told
"unchanged" and handed nothing to read the table with — with nothing in the
exchange saying so. The response has no stable identity, so it is given no
validator, and it keeps `Cache-Control: no-store`: nothing carrying a credential
should be written to a cache at all.

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

When `purgeRequested=true`, the catalog walks the table's manifests and deletes
exactly the files they reference — data files, delete files, manifests, manifest
lists, Puffin statistics and metadata files — **that live under the table's own
`location`**.

Anything else the metadata names is skipped and logged by path. A manifest is
written by the engine and lists data files by path, so "delete everything this
metadata names" is an instruction a caller can partly write — and the catalog
deletes with the *server's* storage role, which reaches the whole warehouse.
Without the bound, an engine could list another tenant's data files in its own
manifest and delete them by dropping its own table. Skipping leaves an orphan,
which costs storage and can be found; deleting leaves nothing to find.

It does **not** recursively delete the table's location either. Two tables can
share a prefix, and a recursive delete of `s3://wh/db/events` would take
`s3://wh/db/events-archive` with it. Anything under the location that no manifest
references — an orphan from an abandoned write — is left in place; removing those
is [orphan-file cleanup](#known-limitations), which is a maintenance job rather
than a catalog operation.

A manifest the purge cannot **read** gets the same answer as one it may not
delete: the files it names are left as orphans, a warning counts them, and the
drop succeeds. The table is dropped before its files are walked — the metadata
naming them is reached through the entry being removed — so failing instead would
answer `500` for a drop that already happened, and `404` on the retry. The usual
cause is a snapshot expired outside this catalog.

`write.data.path` and `write.metadata.path` are deliberately **not** honoured as
extra roots. A table may point them anywhere, so a table naming another tenant's
prefix would reopen the same hole one field along; confining them to the
warehouse does not help, because the warehouse is where the other tenants are,
and confining them to the table's location makes them redundant. A table that
declares one outside its location keeps those files after a purge, and says so in
a warning at purge time.

Data files are additionally gated by the table's own `gc.enabled` property, which
is Iceberg's way of saying "these files are not shared with another table". A
table that sets it to `false` keeps its data on a purge.

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

`409`, not `403`: you *are* permitted, and the resource is in a state that
forbids the operation. Set it at creation, or later:

```bash
curl -X POST http://localhost:8000/v1/namespaces/analytics/tables/events \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"requirements": [],
       "updates": [{"action": "set-properties",
                    "updates": {"rustberg.protected": "true"}}]}'
```

Only the exact value `true` protects, case-insensitively. `"yes"`, `"1"` and
`""` do not — a value that looks like it might mean protected and does not is
worse than no value at all.

> **This stops an accident, not an adversary.** It is an ordinary property, so
> anyone who can set it can clear it. It is there for the `DROP TABLE` typed
> against the wrong catalog and the migration script pointed at prod. For a hard
> stop, write a Cedar `forbid` on `Delete` — that is a rule the holder of the
> property cannot edit.

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

The location is confined to the prefix this view's name puts it in, and the
`location` the metadata file itself declares is re-checked after reading. See
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

Takes `requirements` and `updates` like a table commit. The one requirement the
spec defines for views is `assert-view-uuid`.

Concurrency is optimistic and answers `409 CommitFailedException`, exactly as a
table commit does — but it is worth saying explicitly, because a view commit is
the shape that most often is not: the server loads the current metadata, applies
your updates to it, and swaps the pointer **only if it still points at what was
loaded**. Two clients editing one view from the same read is a race, the first
one through wins, and the second is told rather than silently overwriting it.
Reload and re-apply, which is the same thing you do for a table.

`assert-view-uuid` does not substitute for that. It pins the view's *identity* —
that this is still the same view and not a recreated one under the same name —
and every version of a view shares one UUID, so it cannot tell you the version
moved.

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

**Response:** `200 OK` when this replica can serve, `503` when it cannot.

```json
{
  "status": "ready",
  "version": "0.1.0",
  "timestamp": 1704067200,
  "components": {
    "catalog": { "status": "ready" },
    "storage": { "status": "ready", "message": "s3:12ms" }
  }
}
```

Two components, because two things can actually be unreachable. Everything else
a replica needs is a value that exists or the process did not start.

The probe is cached for two seconds. `/ready` carries no credential and is
therefore outside rate limiting, so an uncached probe would let any caller turn
one HTTP request into a database query and an object-store round trip at
whatever rate it chose.

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

**Every** error uses this envelope, including the ones a web framework normally
answers on its own: a malformed JSON body, a path parameter that fails
validation, an unparseable namespace. Those arrive as plain text from most
servers, and a client that reads `error.message` out of JSON gets a parse failure
instead of the sentence — so "your namespace contains `..`" becomes an unhandled
client-side error. The two exceptions are outside the catalog API entirely:
`/health` and `/ready` answer with their own shapes, and `/metrics` with
Prometheus text.

`message` is a sentence and `type` is the machine-readable name, and neither
repeats the other. An error whose message is a full sentence carries no prefix —
`"The namespace contains U+200B, which is…"` rather than `"Bad request: the
namespace contains…"` beside a `type` that already says `BadRequestException`.
Where the payload is a bare identifier the prefix is the verb and stays:
`"Table does not exist: analytics.events"`.

### Every 401 is the same 401

Missing, malformed, unknown, revoked, expired, bad signature — all the identical
response. Two of those are reachable only *after* the server's constant-time hash
comparison succeeds, so naming them would confirm that the key sent is a real
one. The reason is in the server's audit record, joined to your request by
`X-Request-Id`; ask an operator rather than the API.

Every `401` carries `WWW-Authenticate: Bearer realm="rustberg"`, as RFC 9110
requires. `Bearer` covers both mechanisms — an API key is accepted as
`Authorization: Bearer <key>` as well as in `X-API-Key`, which is what makes
PyIceberg's `token` property work against a catalog that issues no JWTs.

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

A `409 CommitFailedException` is the normal outcome of two writers racing on one
table; clients retry with exponential backoff. On a **format version 3** table it
also covers a second kind of race: every row has an id, a writer stamps its
snapshot with `first-row-id` taken from the metadata it read, and two writers that
read the same metadata stamp the same value — so the second is stale and must
refresh and re-derive it. That is a lost race like any other and is reported as
one, rather than as the "invalid row id" `400` the underlying metadata library
raises, which no client would retry. A `501` means the operation exists
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

Every plan completes in this response. Rustberg never answers `submitted` and
emits no `plan-tasks`: issuing work to poll for means per-plan server-side state,
which a replica set cannot share without a session store.

The follow-up endpoints are routed anyway, and answer the spec's own errors:

| | |
|---|---|
| `GET …/plan/{plan-id}` | `404 NoSuchPlanIdException` — the plan already finished, in the response above |
| `DELETE …/plan/{plan-id}` | `204` — cancelling a finished plan is a no-op, so a client can clean up unconditionally |
| `POST …/tasks` (`fetchScanTasks`) | `404 NoSuchPlanTaskException` — no `plan-task` was ever issued to exchange |

Routed rather than left to the router's own `404`, because the two are different
things to a client: an Iceberg error body naming `NoSuchPlanIdException` says
"there is no such plan", and a bare `404` with no body reads as "this server does
not implement the REST protocol".

All three are advertised in `endpoints` alongside `POST …/plan`, and all three
disappear together on a mount that cannot plan. Listing two of the three would
say this server implements part of an interface it implements all of.

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
binary and fixed are hex. Every timestamp type takes that string spelling,
including `timestamp_ns` and `timestamptz_ns`; the integer count each is stored
as is accepted beside it, because engines send it.

**Two different failures, two different answers.**

*Unsupported* — a transform term, `apply`, a reference by field id, an operator
from a newer spec — is **widened**, not refused. It stops contributing to
pruning, so you get a *superset* of the files your filter selects, and the
`residual-filter` still carries the whole predicate for you to apply. Widening is
polarity-aware, so a term under a `not` widens to "everything" rather than
collapsing to "nothing". A planner that *dropped* such a term instead would prune
against a predicate you did not write and return **fewer** files than the scan
needs — a wrong answer rather than a slow one.

*Malformed* — a column the table does not have, a literal that does not fit its
column, a missing operand, an `is-nan` on a column that is not a float or a
double — is a `400`. Widening a typo into a silent full scan would hide it. Every
operator binds its column against the schema, including the unary ones that carry
no literal to type-check.

> **A Cedar `@row_filter` is the other way round.** Widening a *restriction*
> removes it — `@row_filter("region = 'EU'")` silently becoming everything — so a
> policy filter that cannot be bound to the table being planned is a `403` naming
> the term. Same grammar, opposite safe direction: one is a request, the other a
> limit.
>
> An operator or a term outside the table below cannot bind against *any* table,
> so it is refused when the **policy set loads** rather than at plan time — a
> misspelled `"type": "equals"` is a startup failure, not a `403` on whichever
> query happens to hit it first.

The `residual-filter` on each task is the filter you sent, plus whatever a
matching permit's `@row_filter` added. Both halves are needed: pruning is
conservative, so a file that survives may still hold rows the policy filter
excludes, and an engine that applied only the half it sent would read them.

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

Names resolve with the request's own `case-sensitive` flag, like every other
column reference in a plan. The **mask** check that follows is deliberately
looser — it compares the resolved schema name without regard to case either way —
so the flag cannot be used to ask for a masked column's bounds under a different
spelling.

It compares the column's **full dotted path**, which is what a `@column_mask`
names: a mask on `user.ssn` withholds the statistics of `user.ssn` and of an
unrelated top-level `ssn` neither.

### What is declined

| | Status | |
|---|---|---|
| Incremental scans (`start-snapshot-id`, `end-snapshot-id`) | `501` | Answering them as a full scan would return far more than was asked for |
| `stats-fields` naming a masked column | `403` | Statistics name the column's minimum and maximum values, which is what the mask hides |
| A `@column_mask` over a column the table is **partitioned** on | `403` | Every file carries its partition tuple, and Iceberg writes partition values into the object key, so a plan cannot be served without publishing the column |
| A policy row filter that cannot be applied to this table | `403` | Refused rather than returning files the filter was meant to withhold |
| A table in a federated `rest` mount | `501` | Its manifests are in storage this server does not manage. The refusal is **per namespace**: native tables beside it still plan, even though `/v1/config` stops advertising the endpoint once any mount cannot plan |
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
already built. **Use the `uri` that comes back**, not the one you sent: it is the
same URI in resolved form, and it is the one the signature covers. `Cache-Control:
private` on a read says the signature may be reused for that exact request; a
write is `no-cache`.

### What is signed, and what is refused

A signature is minted only when all of these hold:

1. The caller may `Read` the table, and `Update` it for anything mutating.
2. The table carries no row filter or column mask.
3. The table's storage is a warehouse this server manages — never a mount's.
4. The request is one of the S3 operations this endpoint knows how to authorize.
5. Every location the request touches is inside the table's own location.

The last two are where the work is, because neither the operation nor the
locations are reliably in the path.

#### The operation is not the method

S3 dispatches on a **sub-resource** in the query string, so one `PUT` to one key
is `PutObject`, `PutObjectAcl`, `PutObjectTagging` or `RestoreObject` depending
on a parameter a location check never looks at. Only the first writes data —
`PUT …/events/data/00000.parquet?acl` with `x-amz-acl: public-read` is inside the
table location, passes every containment check, and publishes the file to the
internet.

So the endpoint signs an **allowlist** of operations:

| Signed | Not signed |
|---|---|
| `GetObject`, `HeadObject`, `PutObject`, `DeleteObject` | `?acl`, `?policy`, `?ownershipControls` — who may read it |
| `CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload` (`?uploads`, `?uploadId`) | `?retention`, `?legal-hold`, `?object-lock`, `?lifecycle` — how long it survives |
| `DeleteObjects` (`?delete`) | `?requestPayment`, `?restore`, `?intelligent-tiering` — what it costs |
| `ListObjectsV2` (`?list-type=2`) | `?replication`, `?notification`, `?logging`, `?inventory` — what leaves the bucket |
| `UploadPartCopy`/`CopyObject`, when the source is inside the same table | `?tagging`, `?versioning`, `?website`, `?cors`, `?encryption`, `?select`, `?torrent` |

`x-amz-acl` and `x-amz-grant-*` are refused with them: a signature authorizes
*this* request, never an unbounded set of future ones by somebody who never
reached this catalog.

Only the S3 sub-resource set is filtered, so ordinary parameters an SDK adds —
`x-id`, `versionId`, response-header overrides, list continuation tokens — pass
through untouched.

#### A location can be in the body, the query string, or a header

`DeleteObjects` addresses the bucket and names its keys in an XML body;
`ListObjectsV2` addresses the bucket and names its prefix in the query string.
Both are resolved and confined, and a list prefix must sit *strictly* inside the
table location, because S3 matches prefixes as raw strings and `…/events` also
returns the keys of `…/events-secret`.

`x-amz-copy-source` is the sharpest case. A `PUT` to
`…/events/data/00000.parquet` with

```
x-amz-copy-source: /other-bucket/secrets/private.parquet
```

has a destination squarely inside your own table, and asks S3 to fill it with an
object you were never permitted to read — using **the catalog's** storage role,
which reaches it. Signing only the destination would turn this endpoint into a
read of everything that role can reach, from nothing but `Update` on one table
you legitimately own. So the copy source is confined exactly like the
destination.

#### The URI that comes back is the URI that was checked

Locations are resolved out of the URI with a URL parser, and a URL parser
*resolves* a path: `.` and `..` segments are removed, and under `http`/`https` a
backslash is a separator. So all three of

```
https://wh.s3.amazonaws.com/other/../analytics/events/data/00000.parquet
https://wh.s3.amazonaws.com/other\..\..\analytics\events\data\00000.parquet
https://wh.s3.amazonaws.com/analytics/events/data/x/%2E%2E/00000.parquet
```

read here as `…/analytics/events/data/00000.parquet` — inside the table — while
S3 takes the key literally and would act on one that is not.

Rather than refuse spellings — which would turn an ordinary key carrying an
unusual byte into a `400` for no safety gained — the endpoint signs the
**resolved** URI and returns it. The string checked, the string signed and the
string in the response are one string, so anything else sent to S3 is refused by
S3 itself.

Clients that use the returned `uri` need do nothing; PyIceberg and the Java
`S3V4RestSignerClient` both do.

**Anything that cannot be resolved to a location, or to an operation on this
list, is refused.** That covers bucket-level operations other than
`DeleteObjects` and `ListObjectsV2`, methods outside
GET/HEAD/PUT/POST/DELETE/PATCH, and a `DeleteObjects` body or
`x-amz-copy-source` this endpoint cannot read exactly.

| Status | Means |
|---|---|
| `200` | Signed; merge `headers` into the request |
| `400` | The request cannot be resolved to a location, or is an operation this endpoint does not sign |
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
| `POST /v1/oauth/tokens` | `501` | Deprecated for removal in the spec. Rustberg validates tokens, it does not issue them — `oauth2-server-uri` in the config response points at your IdP. The path is *routed* and answers without a credential, because a client configured with `credential=` calls it before anything else and a bare `401` there reads as a bad key. |
| SQL UDFs (`…/namespaces/{ns}/functions`) | `404` | Function metadata is a third metadata document alongside tables and views, and `iceberg-rust` models none of it. |
| Row filters enforced against a hostile engine | — | Applied in the scan plan and withheld from credentials, but nothing makes an unplanned file unfetchable. See [authorization](@/docs/authorization.md). |
| Column masks as anything but advisory | — | Needs Parquet modular encryption; the masked bytes are in the file the engine downloads. |
| Compaction and file-level maintenance | — | Data rewriting is not a catalog operation. See [Table maintenance](#table-maintenance). |

### Table maintenance

Rustberg does not compact, rewrite manifests or hunt orphan files, and this is a
boundary rather than a gap. All three are *data rewriting*: they need a Parquet
reader and writer, which would put the catalog in the data path that the whole
[row- and column-security story](@/docs/authorization.md) depends on it staying
out of. They are also a different availability shape — a compaction run holds
work for minutes to hours and needs durable job state, retries and workers,
against a server built around microsecond decisions and stateless replicas.

Apache Polaris reached the same conclusion and delegates to a pluggable table
maintenance system; Lakekeeper emits events for an external one to react to.

**The metadata half is served, through the ordinary REST surface.** A maintenance
job pointed at Rustberg gets compare-and-swap commits, an authorization decision
per operation, and an audit record naming the principal that performed it:

| Operation | How it arrives |
|---|---|
| Expire snapshots | `RemoveSnapshots` in `POST …/tables/{table}` |
| Drop a branch or tag | `RemoveSnapshotRef` in the same call |
| Discard statistics | `RemoveStatistics`, `RemovePartitionStatistics` |
| Delete a dropped table's files | `DELETE …/tables/{table}?purgeRequested=true` |

So Spark's `expire_snapshots`, or any maintenance system that speaks Iceberg
REST, works against Rustberg today. What it must bring is the engine that rewrites
the data.

### One name, one thing

A namespace holds one thing per name, whichever kind it is. `createTable`,
`createView`, `renameTable` and `renameView` all answer `409` when the
identifier is already taken — by a table *or* by a view, which is what the spec
asks for on each of the four.

It is not only an interoperability rule. Both kinds live at
`<warehouse>/<namespace>/<name>`, so a collision would put two metadata
documents in one directory and let `dropTable?purgeRequested=true` delete the
view's files along with the table's — and no engine can resolve
`SELECT * FROM db.events` when `db.events` is both.

Staging does not claim a name: a `stage-create` that is never committed leaves
the name free, and the claim happens at the commit.

### A storage location is confined to the resource that names it

`createTable`, `createView` and `registerTable` accept a client-supplied
location, and `set-location` on a commit changes one. All of them are confined
to `<warehouse>/<namespace>/<name>` — the prefix the resource's own name puts it
in, and the layout this catalog assigns anyway. Anything outside is `400`.

`add-snapshot`, `set-statistics` and `set-partition-statistics` name files
rather than move the table, so they are confined to the table's **own location**
instead — which is where a renamed table's files still are, since a rename never
moves them.

The bound is the resource's prefix rather than the warehouse because it is a
security boundary, not a layout rule; see
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary).
Laying a table out freely *under* its own prefix is unaffected.

A registered resource's metadata is read and its declared `location` checked
*before* the catalog records anything — a file at a legitimate path can still
declare a `location` elsewhere.

`storage.location_scope = "warehouse"` widens the bound back for adopting a lake
that predates this catalog. See
[security](@/docs/security.md#the-storage-boundary-is-the-policy-boundary) and
[configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files).

---

## Next Steps

- [Getting Started](@/docs/getting-started.md) - Quick setup
- [Authentication](@/docs/authentication.md) - API keys and JWT
- [Authorization](@/docs/authorization.md) - Cedar policies
