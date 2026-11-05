+++
title = "Security"
description = "Rustberg's threat model, what it enforces, where enforcement stops, and what a deployment must guarantee itself."
weight = 5
+++
## Security Model

Rustberg layers its defences:

```
TLS 1.2/1.3 ──► Rate Limiting ──► Authentication ──► Authorization ──► Validation ──► Audit
                    │
                    └─ IP tracking (spoofing protection)
```

---

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|------------|
| Unauthorized access | API key/JWT authentication |
| Privilege escalation | Cedar policies (path-scoped, tenant-scoped) |
| Data tampering | Metadata files are never overwritten; commits are compare-and-swap |
| Network eavesdropping | TLS 1.2 and 1.3 |
| DoS attacks | Rate limiting, timeouts |
| Injection attacks | Input validation |
| Cross-tenant access | Tenant isolation |

### Out of Scope

| Threat | Reason |
|--------|--------|
| Physical access | Rely on infrastructure security |
| Supply chain attacks | Use audited dependencies |
| Side-channel attacks | Not applicable (no shared state) |
| Quantum attacks | TLS is the only cryptography on the data path; use a PQ-capable terminator |

---

## Authentication Security

### API Keys

| Property | Implementation |
|----------|----------------|
| **Entropy** | 256 bits from the OS CSPRNG |
| **Hashing** | SHA-256, unsalted |
| **Timing** | Constant-time comparison |
| **Enumeration** | Dummy verification for unknown prefixes |

No password KDF: its work factor protects low-entropy secrets and adds nothing
for a 256-bit random token, at a cost on every request. See
[authentication](@/docs/authentication.md#why-not-a-password-kdf).

Keys are configured in `[[server.auth.api_keys]]` and authenticate as
`Rustberg::ApiKey::"<name>"` — see [identity](#and-from-the-identity-side).

### JWT Validation

| Check | Description |
|-------|-------------|
| Signature | RS256 / ES256 / EdDSA by default; the algorithm list is configuration, never taken from the token |
| Issuer | Must match configured `iss` |
| Audience | Must match one of the configured `audiences`, which may not be empty |
| Expiration | Token must not be expired |
| Not Before | Token must be active |
| Subject | Required — a token without one would authenticate as the empty string |

**The token does not choose how it is verified.** The header's `alg` selects the
key only; the validator is built from the configured algorithm list. No `HS*`
algorithm can be enabled — configuring one is a startup error — because an HMAC
against a JWKS would turn your provider's public key into a forgeable shared
secret.

**Keys come from the issuer, checked.**

- The JWKS URL is discovered from `{issuer}/.well-known/openid-configuration`,
  whose own `issuer` must match the configured one.
- Redirects are not followed; both documents are read with a size ceiling.
- Keys are selected by `kid` **and** purpose: an encryption key
  (`"use": "enc"`) in the same JWKS is skipped.

---

## Authorization Security

### Cedar Policy Engine

- **Default deny** — no access without an explicit permit, including on
  evaluation error. Cedar ignores a policy that fails to evaluate, so a raising
  `forbid` would not apply; Rustberg denies the request instead and names the
  policy in the log
- **Tenant isolation** — expressed *by the policies*, not by a separate layer
- **Validated at startup** — a policy that does not typecheck is a startup
  failure
- **Audit trail** — every denial recorded

```cedar
// Tenant isolation, as the default policies express it.
// The attribute is `tenant` on both sides — it is part of the schema, so a
// misspelling here would fail validation at startup rather than at runtime.
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };
```

### What a denial reveals

A resource the caller may not read reports `404`, identical to one that does not
exist, so callers cannot enumerate other tenants' namespaces and tables. `403`
appears only when the caller can already see the resource. Listings filter the
same way. See [authorization](@/docs/authorization.md#visibility-and-error-codes).

`404` means **only** "you cannot see this". A backend that cannot answer — an
unreachable database, a mount whose remote is down — is a server error, so an
outage is distinguishable from a revocation or a deletion. This leaks nothing: a
store failure is the same for every caller.

### Where enforcement stops

The catalog hands out metadata pointers and credentials; the engine reads Parquet
directly from object storage. **An engine holding a file URL and a credential
reads every row and column in that file.**

| Control | Enforced by Rustberg? |
|---|---|
| Which tables a caller may load, list, create, drop | **Yes** — every request is authorized |
| Which tenant owns a namespace | **Yes** — recorded server-side, not client-supplied |
| Scope of a vended credential | **Yes** — an STS session policy restricts it to the table's prefix |
| Scope of a signed request | **Yes** — every location it touches must be inside the table |
| Read-only versus writable access | **Yes** — follows the caller's `Update` permission |
| Row filters (`@row_filter`) | **At file granularity, against any engine that reads through this catalog** — see below |
| Column masks (`@column_mask`) | **Against a cooperating engine only** — see below |

An annotated table gets no vended credential and no signer block, since neither
can express a row predicate. Instead:

- **Which files you are told about is enforced.** [Scan
  planning](@/docs/api.md#scan-planning) conjoins the `@row_filter` with the
  client's filter, so a restricted caller sees fewer files.
- **Which files you can fetch is enforced.** `loadTable` sets
  `scan-planning-mode: server` (*"Clients MUST use server-side scan
  planning"*), and the plan returns a **pre-signed URL** per selected file. An
  excluded file has no URL and no credential to build one.

Limits:

- **Row filtering is file-granular.** If permitted and forbidden rows share a
  Parquet file, that file is delivered and the residual predicate is advisory.
  Partition on the security boundary to make file selection row enforcement.
- **Column masks are cooperative.** They travel as
  [`read-restrictions`](@/docs/api.md#read-restrictions), which a conforming
  reader must apply or fail the query. The bytes are still in the Parquet file;
  only Parquet modular encryption would change that, and Rustberg does not
  implement it.
- **An engine with its own storage credentials** reads files directly. It
  receives `read-restrictions`, and nothing compels it to honour them.
- **A pre-signed URL is a bearer token** for its lifetime —
  `presign_ttl_seconds`, 15 minutes by default — and is S3-only.

**Precondition:** Rustberg must be the only path to the object store. If a caller
can reach the warehouse bucket with its own credentials, every guarantee above is
void. That is your IAM and network configuration; Rustberg cannot verify it.

---

## Storage access

Storage access is granted only on request, in the form the client asks for:

```http
GET /v1/namespaces/analytics/tables/events
X-Iceberg-Access-Delegation: vended-credentials
```

```http
GET /v1/namespaces/analytics/tables/events
X-Iceberg-Access-Delegation: remote-signing
```

- **Vending** hands over a credential scoped to the table for its lifetime.
- **Signing** hands over nothing and authorizes each object request, so a revoked
  grant takes effect on the next read. See
  [the API reference](@/docs/api.md#remote-signing).

### Credential vending

The vended credential is always **strictly weaker** than the server's own:

| Provider | Mechanism | Result |
|---|---|---|
| AWS | `AssumeRole` with an inline **session policy** | Effective permission is the intersection of the role and one table prefix |
| GCS | **Credential Access Boundary** token exchange | Token is bounded to one table prefix |
| Azure | **User-delegation SAS** signed with an Entra-issued key | Token is scoped to one table prefix and expires |

**S3:** the session policy grants `GetObject` under `s3://bucket/<table>/*` and
`ListBucket` conditioned on that prefix. `PutObject`, `DeleteObject` and
`AbortMultipartUpload` are added only when the caller holds `Update`; a
read-only caller cannot receive a writable credential. If the policy cannot be
built — a location that cannot be scoped, or one exceeding the STS 2 048-character
limit — the request **fails rather than falling back to an unscoped
credential**.

**Azure:** Rustberg authenticates as a Microsoft Entra service principal, obtains
a delegation key, and signs a SAS scoped to the table's prefix with `sr=d`
(directory scope). Effective permissions are the *intersection* of the SAS and
the principal's RBAC rights.

Rustberg has **no code path that can emit an `adls.account-key`**, which would
grant full, unscoped, non-expiring control of the whole storage account.

### The storage boundary is the policy boundary

`createTable`, `createView` and `registerTable` let a client name a storage
location, which becomes the prefix of any credential vended for the resource.
Unchecked, that is a confused deputy:

```http
POST /v1/namespaces/mine/register
{ "name": "borrowed", "metadata-location": "s3://someone-elses-bucket/secrets/…json" }
```

So every client-supplied location is checked before it is recorded, and a
registered resource's metadata is re-checked after reading, since it may declare
a `location` elsewhere.

**The bound is `<warehouse>/<namespace>/<name>`**, not just the warehouse.
Grants follow the namespace tree; storage access follows paths. With only a
warehouse bound:

1. A caller may write `public.mine` and cannot see `finance.secret`.
2. It commits `set-location` on its own table, naming `finance/secret`'s prefix.
3. It loads its table with `vended-credentials` and receives a credential for
   the other namespace's data.

Names are unique per namespace and namespaces nest by segment, so these prefixes
are disjoint by construction, with no lookup. A resource lays out its files
freely *under* its prefix.

`storage.location_scope = "warehouse"` widens the bound back and reopens the
sequence above — see
[configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files).

Containment rules:

- **Segment-wise**, not a string prefix: `s3://bucket/wh-evil` is not inside
  `s3://bucket/wh` and is refused.
- `s3a://` and `s3://` are treated as the same bucket.
- A `..` segment is refused outright.
- **An empty segment is a segment.** `s3://bucket//wh/db/t` is the key
  `/wh/db/t`, not inside `wh`, and is refused — so the string checked is the
  string signed. On a `file://` warehouse repeated separators are folded, as
  POSIX does.
- A trailing slash on the *warehouse* is ignored: `s3://bucket/wh` and
  `s3://bucket/wh/` are one prefix.

Under [federation](@/docs/configuration.md#federation) the governing warehouse is
the **mount's**. The bound is per-mount, in both directions: a mount's warehouse
does not reach the server's, nor the reverse.

Storage access is checked against that per-mount bound too, not against any
managed warehouse — a remote's returned `location` is its own choice and could
name another tenant's prefix here. A namespace whose catalog declares no
warehouse — a `rest` mount stores nothing — gets no credential and no signature.

`credentials.allowed_prefixes` is a second, independent defence — see
[configuration](@/docs/configuration.md#credentials). Unset, it equals the
warehouse. Either half alone closes the hole.

**Commits name locations too.** Four updates carry one:

| Update | Names |
|---|---|
| `set-location` | the table's location — it *moves* the table |
| `add-snapshot` | a manifest list, which scan planning reads and a purge deletes |
| `set-statistics` | a Puffin file, which a purge deletes |
| `set-partition-statistics` | the same |

- `set-location` changes what credentials are scoped to, so it is held to
  the bound above.
- The three that name **files** are held to the table's own `location` — not its
  name, because a rename never moves files (`db.old` renamed to `db.new` keeps
  `…/db/old`).

Both checks run on `commitTable`, `commitTransaction`, `commitView` and the
in-process `Session`.

**Manifest contents are not checked on commit** — that would put the catalog in
the data path. Instead a [purge](@/docs/api.md#drop-table) deletes only what
lives under the table's own storage, and names what it skipped.

### A signature authorizes one request, not a standing grant

Remote signing confines every object request to the table's location, including
locations not in the path:

- `DeleteObjects` keys (XML body) and `ListObjectsV2` prefix (query string),
  which otherwise address the whole bucket.
- `x-amz-copy-source`, the header naming a server-side copy's source — otherwise
  a `PUT` into your table could copy from another bucket using the catalog's
  role.

**The operation is allowlisted:** object access, multipart upload,
`DeleteObjects`, `ListObjectsV2`. Sub-resources that change who may reach an
object (e.g. `PUT …/f.parquet?acl`) and the headers `x-amz-acl` and
`x-amz-grant-*` are refused.

**The signature covers the URI that was checked.** URL parsers resolve `.`/`..`
and treat `\` as a separator while S3 takes keys literally, so the endpoint
resolves the URI once, then checks, signs and returns that form. Anything else
sent to S3 fails with `SignatureDoesNotMatch`.

Full detail in [the API reference](@/docs/api.md#remote-signing).

### A table name reaches two policy languages

A vended credential's scope ends in the table's *name*, which may be any Unicode
outside category `C`. Two providers splice it into a language with
metacharacters:

| Provider | The hazard | What Rustberg does |
|---|---|---|
| AWS | `*` and `?` are wildcards in an IAM `Resource` ARN; `${…}` is a policy variable. A table named `*` would scope to `bucket/wh/db/*/*` — every sibling table | Written in IAM's literal forms `${*}`, `${?}`, `${$}` |
| GCS | The access boundary is a **CEL expression** with the prefix in a quoted literal. A table named `x') \|\| true \|\| ('` would match the whole bucket | The apostrophe and backslash are escaped |
| Azure | None — the path goes into a canonical resource that is **signed** | Nothing to escape |

Characters are escaped rather than banned, consistent with
[input validation](#input-validation): `*` is legal in Iceberg.

### Obligations withhold a broad credential

If the permitting policies carry a `@row_filter` or `@column_mask`, **no
credential is vended** — see [authorization](@/docs/authorization.md). Access is
not refused: the scan plan returns pre-signed URLs for exactly the selected files
— see
[storage access delegation](@/docs/api.md#server-side-planning-and-pre-signed-urls).

### Operational notes

- Vended credentials are short-lived (`duration_seconds`, default one hour) and
  scoped to the request that minted them.
- They are **never** stored in the 24-hour idempotency cache; a replayed create
  must request credentials again.
- With no provider configured, the credentials endpoint answers `501` — correct
  for the common deployment where engines carry their own credentials.

---

## Input Validation

All user input is validated:

| Validation | Implementation |
|------------|----------------|
| **Name length** | Max 255 **characters**, the same limit in every script |
| **Namespace depth** | Max 10 levels |
| **Properties count** | Max 100 per resource |
| **Path separators** | Block `/` and `\\` inside a name |
| **Directory names** | Block `.` and `..` as whole segments |
| **Unicode category `C`** | Block control, format, private-use and unassigned code points — covers `\0`, the `␟` the entity encoding depends on, and every invisible or directional character |
| **Normalization** | Names must be NFC; another form is refused, with the accepted spelling in the error |
| **Surrounding whitespace** | Blocked, so two visually identical names cannot be distinct strings |
| **JWT size** | Tokens over 16 KB rejected before parsing |
| **Identity claims** | `tenant`, `sub` and each role are held to the same rule as a name — see [below](#and-from-the-identity-side) |
| **Page tokens** | Validated against the namespace being listed; a forged one restarts the scan rather than seeking |
| **Correlation ids** | An inbound `X-Request-Id` over 128 characters, outside a token alphabet, or sent twice is **replaced** with a minted one, which is both echoed and recorded |

### What the rule is derived from

A name is used as three things:

| Used as | Rules out |
|---------|-----------|
| A path segment in the table's storage location | `/`, `\\`, `.`, `..` |
| A segment of a Cedar entity id, joined with `␟` | every code point in general category `C`, which includes the unit separator |
| A field in an audit record and a log line | the same, again |

Path scoping relies on the entity encoding being **injective**: a name containing
`␟` could make a policy for one resource match another. Refusing category `C`
guarantees this.

#### One rendering, one resource

Two names that *display* identically but differ in bytes are two Cedar resources,
and a policy covers only one. Hence:

- **All of category `C` is refused.** `Cf` includes zero-width space, soft
  hyphen, byte-order mark and bidirectional overrides: `events` and
  `events<ZWSP>` look identical.
- **Names must be NFC.** Composed and decomposed `café` differ in bytes, key,
  entity id and storage path. Other forms are refused, not rewritten, and the
  error names the accepted spelling.

There is no homoglyph or mixed-script check: `а` (Cyrillic) and `a` are both
legitimate.

Everything else is allowed — `分析`, `café_visits`, `Ω_measurements`. Windows
device names (`CON`, `LPT1`) and leading dots are accepted.

Validation applies on **every** path a name arrives by: URL path segments, and
table names in `commitTable` and `commitTransaction` request bodies.

#### And from the identity side

Values from a **token** also become entity ids, and are held to the same rule:

| From a token | Becomes | A value that fails the rule |
|---|---|---|
| `tenant_claim` | the first segment of every resource id | rejected credential — `acme␟analytics` builds the ids of tenant `acme`'s `analytics` namespace |
| `sub` | `User::"…"` | rejected credential — it names who the audit trail says acted |
| `roles_claim` | `Group::"…"` | the role is **dropped**; the principal keeps the rest |

A dropped role grants nothing anyway — no policy can name it — so dropping it
denies by default without locking out a caller over a claim it cannot fix.

An **API key** configured in `[[server.auth.api_keys]]` authenticates as
`ApiKey::"…"`, using its configured `name`. That is a separate principal kind
from `User::"…"`: a token whose `sub` equals a key's name is a different
principal. Key names follow the same rule (no category `C`, NFC).

A tenant, role or API key name in **configuration** that fails the rule is a
startup failure.

---

## What is reachable without a credential

These routes sit outside authentication, for liveness probes and Prometheus
scrapes:

| Route | What it returns |
|---|---|
| `GET /health` | Liveness. A status word, the version, a timestamp. |
| `GET /ready` | Readiness. `ready` / `degraded` for the **two** components actually probed — catalog and storage — a **category** for each failure, and the storage backend kind with a round-trip time. |
| `GET /metrics` | Aggregate counters. No tenant, namespace or table labels. |

- `/ready` omits backend error text, which would expose hosts, buckets, keys and
  mount names; the detail goes to the server log.
- It reports only what it probes; everything else a replica needs is checked at
  startup.
- The probe is cached for two seconds, because these routes are also outside rate
  limiting.

Restrict them at the network layer if needed — the Helm chart's `NetworkPolicy`.

### Every credential rejection is the same rejection

A missing credential, a malformed, unknown, revoked or expired key, and a bad JWT
signature all answer `401 NotAuthorizedException` with the same sentence.

API key comparison is constant-time — a miss verifies against a dummy hash — and
*disabled* or *expired* is known only after a match, so naming either would
confirm the key exists.

The reason goes to the audit record, joined by `request_id`. See
[debugging a 401](@/docs/authentication.md#401-unauthorized).

## What an error response says

- A **caller's** failure — a missing table, a commit conflict, a forbidden
  action — is described in full.
- A **server's** failure returns a fixed message and status code; the cause goes
  to the log.

This holds in every build, independent of compile profile. The spec's optional
`stack` field is always empty, since a trace exposes source paths and symbols.

---

## Encryption

### At Rest

Rustberg encrypts nothing at rest: engines read metadata and data files directly
from object storage, so catalog-side encryption would protect the wrong layer.

| Concern | Where it belongs |
|---------|------------------|
| Warehouse objects | Object-store encryption (SSE-S3, SSE-KMS, CMEK) |
| Column secrecy | Parquet modular encryption — a table-level concern |
| API keys | Nothing to encrypt: they are config, not stored state |

See [encryption](@/docs/encryption.md).

### In Transit

| Component | Algorithm |
|-----------|-----------|
| TLS version | 1.2 or 1.3 |
| Implementation | rustls (memory-safe) |
| Cipher suites | AES-GCM, ChaCha20-Poly1305 |

### In Memory

| Protection | Implementation |
|------------|----------------|
| Zeroize | Secrets cleared on drop |
| Redacted Debug | Custom Debug traits redact sensitive fields |
| No Clone | Controlled copies |

Structs with custom Debug implementations that redact secrets:
- `ApiKey` — redacts `key_hash`
- `StorageCredential` — redacts config values containing `secret`, `token`, or `password`

### In an error message

A server-side problem — a database failure, an unreachable identity provider, a
configuration mistake — is answered as "an internal error occurred, check the
server log", with the full text on **stderr**. A credential failure never says
which part failed, so error text cannot enumerate keys.

Both are unconditional in every build, not keyed on `cfg!(debug_assertions)`;
identity-provider fetch errors can carry internal hostnames and tokens.

---

## Rate Limiting

Token bucket algorithm with:

| Feature | Value |
|---------|-------|
| Default limit | 100 req/s per client |
| Burst size | 200 requests |
| Per-tenant | Ten times the per-client allowance, applied after authentication |
| One client means | one IPv4 address, or one IPv6 **/64** |
| Client address | Resolved once, in `[server] trusted_proxies` — see below |
| `X-Forwarded-For` | **Ignored unless `[server] trusted_proxies` names the proxy** |

**Why a /64.** It is the smallest IPv6 allocation, so per-address keying would
give an attacker unlimited fresh buckets and let it evict real clients from the
bounded tracking map. Hosts sharing a /64 share an allowance, as with IPv4 NAT.

**Proxy headers are ignored by default** — they are client-supplied, and trusting
them would let a caller spoof its address past rate limiting and address-scoped
Cedar policies.

With `trusted_proxies` set, Rustberg walks `X-Forwarded-For` **from the right**,
skipping hops inside a trusted range, and takes the first non-infrastructure
address (a client-sent header arrives as `<spoofed>, <real client>`). The result
feeds the rate-limit bucket, `context.source_ip` in Cedar, and the audit record.

A hop written as `unknown` or an obfuscated identifier (RFC 7239) **stops** the
walk. The address is then unknown, so a policy guarded with
`context has source_ip` does not apply.

> Leave `trusted_proxies` empty unless behind a load balancer whose subnet you
> can name.

---

## Audit

Everything security-relevant goes to **one sink**. There are exactly five event
kinds:

| `action` | `category` | Says | Refuses the request if unrecordable |
|---|---|---|---|
| `authenticate` | `authentication` | a credential was presented and accepted, or rejected | no |
| `decision` | `authorization` | a policy decision, permit and deny alike | for a **permitted** mutation |
| `vend_credentials` | `storage_access` | what was vended, and whether it could **write** | when a write credential was **granted** |
| `sign_request` | `storage_access` | what was signed, and **which objects** | when a write signature was **minted** |
| `rate_limit` | `system` | which bucket ran out, `ip` or `tenant` | no |

Only grants are refused when unrecordable; a refusal never fails for that reason.
See [fail-closed](#fail-closed).

Permits are recorded as well as denials, so the trail answers "who read this
table".

### Record shape

One JSON object per line:

```json
{
  "event_id": "01a021b4-e829-7583-817d-81e02b832dc9",
  "timestamp": "2026-08-21T00:24:59.177+00:00",
  "timestamp_ms": 1787271899177,
  "category": "authorization",
  "action": "decision",
  "outcome": "success",
  "severity": "info",
  "operation": "Create",
  "principal_id": "ci-pipeline",
  "principal_type": "api_key",
  "tenant_id": "acme",
  "client_ip": "10.0.0.5",
  "request_id": "15f42462-e096-45c1-bcbb-26021401102f",
  "resource_type": "namespace",
  "resource_id": "acme/analytics",
  "matched_policies": ["policy1"],
  "policy_set_version": "9f2c41ab7d0e5163"
}
```

`principal_type` says what `principal_id` names — `api_key` (a key, by its
configured name) or `user` (a token's subject) — because the two may share a
name and are still different principals.

`outcome` is `success` for a permit, `denied` for a refusal, and `failure` when
policy permitted but the operation failed — e.g. a credential exchange the cloud
provider refused.

`operation`:

- On a decision: the action **as the policy file spells it**, so a denial naming
  `Update` greps against `Rustberg::Action::"Update"`.
- On a vended credential: `read`, `read-write` or `none` (withheld — no width was
  decided, which differs from `read`).
- On a signature: `read` or `write`.

`request_id` matches the `X-Request-Id` echoed to the client. It is assigned
before anything can be refused, so `401` and `429` records join too.

An inbound id is carried through only if it is at most 128 characters, in a
conservative token alphabet, and sent once; otherwise it is **replaced** with a
minted one. Every request has exactly one id, and the echo and the record always
match.

#### How the request said it got here

`referenced_by` appears when the client sent the spec's `referenced-by`
parameter: the views a table or view was reached *through*, outermost first,
rendered as resource paths.

It is a **caller's claim**, never consulted for authorization — every load is
authorized on its own. A chain naming nonexistent views is recorded as sent; an
unreadable chain is dropped, not refused. The field is absent when no chain was
sent.

#### Which rule decided

`matched_policies` and `policy_set_version` say *which rule decided*, and
whether it is the rule you think you wrote.

| Field | On a permit | On a denial |
|---|---|---|
| `matched_policies` | The permits that matched | The **forbids** that matched |
| `matched_policies` empty | — | **Deny by default**: nothing forbade it, nothing permitted it |

An empty list on a denial means a missing permit; a non-empty one names a rule
to read.

`policy_set_version` is derived from the policy set's **content**:

- Records sharing it were evaluated against byte-identical rules.
- Replicas with the same policies report the same version, so divergent replicas
  show up as two versions in one stream.
- A version differing from the current one marks a decision made under since-changed
  rules, which makes it reproducible.

### Storage access

A decision record says a caller may `Read` a table, not that it received a
credential able to write. That gets its own record:

```json
{
  "category": "storage_access",
  "action": "sign_request",
  "outcome": "denied",
  "operation": "write",
  "resource_id": "acme/db/events",
  "details": {
    "locations": "s3://wh/db/other/secrets.parquet",
    "location_count": "1"
  }
}
```

- Signature records name the **objects** signed. Long lists are truncated to the
  first few plus a count; every listed location is inside the named table.
- Refusals are recorded and name what was reached for.
- Nothing is recorded when nothing was handed over: an uncredentialed
  `loadTable` writes no vending record.

### Configuration

```toml
[audit]
sink = "stdout"      # stdout | file | none
# path = "/var/log/rustberg/audit.jsonl"   # required when sink = "file"
fail_closed = true
```

- Records go to **stdout**; application logs go to stderr.
- A `file` sink that cannot be opened is a startup failure.
- Every event kind goes to this one sink; none is diverted to the application
  log.

> [!WARNING]
> **Whatever reads stdout must keep reading it.** Audit writes are on the request
> path; an undrained stdout pipe fills and blocks the server mid-record, which
> looks like a hang. Container runtimes, systemd and `| jq` drain correctly; a
> script that collects output to read later does not. Use `sink = "file"` there.

### Fail-closed

**When the sink fails, a permitted mutation fails** with `503`, as does a grant
of **write** storage access (a read-write credential or a write signature).
Everything else keeps serving, and the loss is counted:

| Unrecordable | Answer | Why |
|---|---|---|
| A permitted mutation | `503` | It would be a change nothing recorded |
| A granted write credential, a minted write signature | `503` | Authority over the warehouse, handed out unrecorded |
| A **denied** mutation | the denial | Nothing changed; `503` would wrongly suggest a retry |
| A read or a listing | the response | A full disk should not become an outage |
| Authentication, rate limiting | the response | Same, and decided before a mutation is known |

Set `fail_closed = false` to trade the guarantee for availability. Losses are
counted either way.

> Secrets (tokens, keys, passwords) are **never** recorded.

---

## Secure Defaults

Production mode (the default) enforces:

| Setting | Default | Rationale |
|---------|---------|-----------|
| TLS | Required | Prevent eavesdropping |
| Authentication | Required | Prevent unauthorized access |
| CORS origins | **None allowed** | Iceberg clients are not browsers; a browser needs an explicit grant |
| Catalog location | Must be explicit | Real metadata must not land in a temp directory |
| `trusted_proxies` | empty | Forwarding headers are ignored, so an address cannot be spoofed |
| Rate limiting | Enabled | Prevent DoS |

With authentication required and no credential configured, Rustberg mints one
admin key at startup and prints it. It is held in memory only, so a restart
invalidates it — configure API keys or OIDC for anything lasting.

### Development Mode

Use `--dev` flag or `RUSTBERG_DEV=1` to relax security for local development:

```bash
# Local development only
./rustberg --dev --insecure-http
```

> Development mode allows wildcard CORS and disables some security checks.
> **Never use `--dev` in production.**

---

## Operating it safely

### Before production

- [ ] TLS terminated, here or at a proxy
- [ ] Authentication configured — API keys or OIDC, not the bootstrap key
- [ ] Policies written and loaded; the default set is a starting point, not a deployment
- [ ] Audit sink configured, `fail_closed` left on, and whatever reads stdout draining it
- [ ] Rate limits set for the traffic you expect
- [ ] `allowed_prefixes` narrowed if vending should not cover every warehouse
- [ ] Network policy restricting who can reach the endpoint
- [ ] Secrets in the environment or a mounted secret, never in the config file

### Ongoing

- [ ] API keys rotated; rotation is a config change plus a restart
- [ ] Dependencies updated — `cargo deny` gates advisories in CI
- [ ] Audit records shipped somewhere they are read
- [ ] Denials monitored: a rise in `403` is usually a policy change, a rise in `401` is usually a rotation

---

## Reporting a vulnerability

Report privately through [GitHub security
advisories](https://github.com/hupe1980/rustberg/security/advisories/new) rather
than a public issue. Include reproduction steps.

---

## Next Steps

- [Authentication](@/docs/authentication.md) - Configure auth
- [Authorization](@/docs/authorization.md) - Cedar policies
- [Encryption](@/docs/encryption.md) - what is encrypted
