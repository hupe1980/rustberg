+++
title = "Security"
description = "Rustberg's threat model, what it enforces, where enforcement stops, and what a deployment must guarantee itself."
weight = 5
+++
## Security Model

Rustberg implements **defense-in-depth** with multiple security layers:

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
| Network eavesdropping | TLS 1.3 encryption |
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

A password KDF is deliberately *not* used: its work factor defends a
low-entropy secret, and buys nothing against a 256-bit random token while
costing the server on every request. See
[authentication](@/docs/authentication.md#why-not-a-password-kdf).

### JWT Validation

| Check | Description |
|-------|-------------|
| Signature | RS256/RS384/RS512, ES256/ES384/ES512 |
| Issuer | Must match configured `iss` |
| Audience | Must match configured `aud` |
| Expiration | Token must not be expired |
| Not Before | Token must be active |

---

## Authorization Security

### Cedar Policy Engine

- **Default deny** — no access without an explicit permit, including on
  evaluation error
- **Tenant isolation** — expressed *by the policies*, not by a separate layer
- **Validated at startup** — a policy that does not typecheck is a startup
  failure, never a rule that silently never matches
- **Audit trail** — every denial recorded

```cedar
// Tenant isolation, as the default policies express it.
// The attribute is `tenant` on both sides — it is part of the schema, so a
// misspelling here would fail validation at startup rather than at runtime.
permit(principal in Rustberg::Group::"admin", action, resource)
  when { resource.tenant == principal.tenant };
```

### What a denial reveals

A resource the caller may not read reports `404`, identically to one that does not
exist. Without that, the status code distinguishes "exists but forbidden" from
"absent", and any authenticated caller can enumerate other tenants' namespaces and
tables. `403` appears only when the caller can already see the resource. Listings
filter for the same reason. See
[authorization](@/docs/authorization.md#visibility-and-error-codes).

`404` means **exactly** "you cannot see this", and nothing else. A backend that
cannot answer — an unreachable database, a mount whose remote is down — is a
server error, never a `404`. Collapsing the two would make an outage
indistinguishable from a revocation and from a deletion, for the client and for
whoever has to diagnose it. Nothing is revealed by the distinction: a store
failure is the same failure for every caller, permitted or not, so unlike an
existence check it is not an oracle.

### Where enforcement stops

This is the boundary worth being precise about, because it decides what the
catalog can actually promise.

A catalog hands out metadata pointers and credentials; the engine then reads
Parquet directly from object storage. **Once an engine holds a file URL and a
credential, it reads every row and every column in that file.** No policy language
changes that.

| Control | Enforced by Rustberg? |
|---|---|
| Which tables a caller may load, list, create, drop | **Yes** — every request is authorized |
| Which tenant owns a namespace | **Yes** — recorded server-side, not client-supplied |
| Scope of a vended credential | **Yes** — an STS session policy restricts it to the table's prefix |
| Scope of a signed request | **Yes** — every location it touches must be inside the table |
| Read-only versus writable access | **Yes** — follows the caller's `Update` permission |
| Row filters (`@row_filter`) | **Against a cooperating engine only** — see below |
| Column masks (`@column_mask`) | **No** — see below |

An annotated table is refused every form of storage access Rustberg grants —
no credential and no signature — because neither can express a row predicate,
and granting one while calling the filter enforced would be a false claim.

What Rustberg *does* enforce is which files it tells you about. A `@row_filter`
is an Iceberg predicate, so [scan planning](@/docs/api.md#scan-planning) conjoins
it with the client's own filter: a restricted caller is told about fewer files,
and the residual on each task carries both halves. An engine that follows the
plan reads only permitted rows. One carrying its own storage credentials reads
the table unfiltered, and nothing here changes that.

That is file-level selection, the enforceable half of row-level security — but
here it is still *advice*, because nothing makes an unplanned file unfetchable.
[Signing](@/docs/api.md#remote-signing) would, except a signature is confined to
the whole table rather than to the files one plan named. A column mask
additionally needs Parquet modular encryption to be more than advisory, since the
masked bytes are in the file the engine downloads.

**The precondition behind all of it:** Rustberg must be the only path to the
object store. If a caller can reach the warehouse bucket directly with its own
credentials, every guarantee above is void. That is a property of your IAM and
network configuration, not something Rustberg can verify or enforce.

---

## Storage access

A client that wants Rustberg to grant storage access asks for it, and says which
form it wants:

```http
GET /v1/namespaces/analytics/tables/events
X-Iceberg-Access-Delegation: vended-credentials
```

```http
GET /v1/namespaces/analytics/tables/events
X-Iceberg-Access-Delegation: remote-signing
```

Nothing is granted unrequested. An engine already running with an instance role
does not want the catalog minting more, and granting into every response would
widen the authority carried by traffic nobody asked to be sensitive.

Vending hands over a credential scoped to the table for its lifetime; signing
hands over nothing and authorizes every object request individually, so a
revoked grant takes effect on the next read rather than at the next expiry. See
[the API reference](@/docs/api.md#remote-signing) for what a signature is
confined to.

### Credential vending

### What makes it a downscope, not a handoff

The vended credential is always **strictly weaker** than the server's own:

| Provider | Mechanism | Result |
|---|---|---|
| AWS | `AssumeRole` with an inline **session policy** | Effective permission is the intersection of the role and one table prefix |
| GCS | **Credential Access Boundary** token exchange | Token is bounded to one table prefix |
| Azure | **User-delegation SAS** signed with an Entra-issued key | Token is scoped to one table prefix and expires |

For S3 the session policy grants `GetObject` under `s3://bucket/<table>/*` plus
`ListBucket` conditioned on that prefix, and adds `PutObject`, `DeleteObject`
and `AbortMultipartUpload` only when the caller also holds `Update`. A read-only
caller cannot receive a writable credential. If the policy cannot be built — a
location that will not scope, or one that would exceed the STS 2 048-character
limit — Rustberg **fails the request rather than falling back to an unscoped
credential**.

For Azure the token is a **user-delegation SAS**: Rustberg authenticates as a
Microsoft Entra service principal, obtains a delegation key from the storage
account, and signs a SAS scoped to the table's prefix with `sr=d` (directory
scope). The permissions granted are the *intersection* of what the SAS says and
what the principal is allowed by RBAC, so it can only narrow the server's own
rights.

Rustberg has **no code path that can emit an `adls.account-key`**. An account
key grants full control of the entire storage account — every container, delete
included — to anyone permitted to read one table, and it neither scopes nor
expires.

### Locations are confined to the warehouse

`createTable`, `createView` and `registerTable` all let a client name a storage
location, and that location becomes the prefix of any credential vended for the
resulting table. Left unchecked it is a confused-deputy hole:

```http
POST /v1/namespaces/mine/register
{ "name": "borrowed", "metadata-location": "s3://someone-elses-bucket/secrets/…json" }
```

A caller permitted only in its own namespace would borrow *the server's*
authority over a prefix its policy never mentioned. So every client-supplied
location is checked to lie within the warehouse before it is recorded, and a
registered table's metadata is re-checked after reading — a file at a legitimate
path can still declare a `location` pointing elsewhere.

Containment is **segment-wise**, not a string prefix test. `s3://bucket/wh-evil`
merely spells like `s3://bucket/wh`; it is a different prefix and is refused.
`s3a://` and `s3://` name the same bucket and are treated as one. A `..`
segment is refused outright.

Under [federation](@/docs/configuration.md#federation) the governing
warehouse is the **mount's**, not the server's: each mount has its own, and a
table created in a mount belongs in that one. The boundary is per-mount rather
than global, and holds in both directions — a mount's warehouse is not a way
into the server's, and the server's is not a way into a mount's.

`credentials.allowed_prefixes` is the second, independent half of the same
defence — see [configuration](@/docs/configuration.md#credentials). Left
unset it becomes exactly the warehouse. Either half alone closes the hole.

### Obligations make a table undelegatable

If the policies that permitted the request carry a `@row_filter` or
`@column_mask`, **no credential is vended at all** — see
[authorization](@/docs/authorization.md). A prefix-shaped credential cannot
express a row filter, so vending one while calling the filter enforced would be
a false claim.

### Operational notes

- Vended credentials are short-lived (`duration_seconds`, default one hour) and
  scoped to the request that minted them.
- They are **never** stored in the idempotency cache. Replaying a create from a
  24-hour cache would hand back a long-expired credential and keep a live secret
  in memory long after the request that minted it; a client replaying a create
  asks for credentials again if it wants them.
- With no provider configured, the dedicated credentials endpoint answers `501`
  rather than pretending. That is the correct report for a deployment where
  engines carry their own credentials — the common case, and not a lesser one.

---

## Input Validation

All user input is validated:

| Validation | Implementation |
|------------|----------------|
| **Name length** | Max 255 characters |
| **Namespace depth** | Max 10 levels |
| **Properties count** | Max 100 per resource |
| **Path traversal** | Block `..` patterns |
| **Null bytes** | Block `\0` injection |
| **Control chars** | Block non-printable |
| **Hidden files** | Block `.` prefix |
| **Windows reserved** | Block CON, PRN, AUX, etc. |
| **JWT size** | Tokens over 16 KB rejected before parsing |
| **Page tokens** | Validated against the namespace being listed; a forged one restarts the scan rather than seeking |
| **Correlation ids** | An inbound `X-Request-Id` over 128 characters, or outside a token alphabet, is dropped rather than recorded |

```rust
// Character whitelist
const ALLOWED: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
```

The whitelist is narrower than the Iceberg spec allows, and deliberately so. A
namespace or table name becomes a segment of a Cedar entity id, and the whole
path-scoping model rests on that encoding being **injective**: segments are
joined with `␟` (`\u{1F}`), and a name that could contain one would let a policy
written for one resource silently match another. Rejecting the character class
outright is what makes truncation exact. The cost is that a table cannot be named
`café`; the alternative is an authorization layer that is ambiguous by
construction.

Validation applies to **every** path a name can arrive by. Most arrive through
the URL and are checked by the path extractor; `commitTable` and
`commitTransaction` may also name their table in the request body, and those are
validated too. The injectivity argument rests on the rules holding everywhere, so
a body-supplied name that skipped them would weaken the claim to "the two
encodings happen to agree".

---

## What is reachable without a credential

Two routes sit outside the authentication layer, because a Kubernetes liveness
probe cannot hold one and a Prometheus scrape should not need one:

| Route | What it returns |
|---|---|
| `GET /health` | Liveness. A status word, the version, a timestamp. |
| `GET /ready` | Readiness. Per-component `ready` / `degraded`, a **category** for each failure, and the storage backend kind with a round-trip time. |
| `GET /metrics` | Aggregate counters. No tenant, namespace or table labels. |

`/ready` deliberately does **not** carry the backend's own error text. A database
error names the host and database, an object-store error names the bucket and
key, and a federated catalog's health message names every unreachable mount —
which is deployment topology, handed to anyone who can open a socket. The detail
goes to the server log instead.

Restrict these at the network layer if a deployment needs to; the Helm chart's
`NetworkPolicy` is where that belongs.

## What an error response says

A failure that is the **caller's** — a missing table, a commit conflict, a
forbidden action — is described in full. The caller supplied the input and can
act on the answer.

A failure that is the **server's** returns a fixed message and a status code, and
the cause is written to the log. That holds in every build: it is not conditioned
on the compile profile, so what you see under test is what a production binary
does. The spec's optional `stack` field is always empty — a trace names source
paths and symbols, and it would be sent to whoever made the failing request,
including one that failed *because* it was not permitted.

---

## Encryption

### At Rest

Rustberg encrypts nothing at rest, deliberately. Catalog-side encryption
protected the wrong layer: engines read metadata and data files straight from
object storage, where they were plaintext regardless.

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

---

## Rate Limiting

Token bucket algorithm with:

| Feature | Value |
|---------|-------|
| Default limit | 100 req/s per client IP |
| Burst size | 200 requests |
| Per-tenant | Configurable, applied after authentication |
| Client IP | The connected socket address |
| `X-Forwarded-For` | **Ignored unless `trust_proxy_headers = true`** |

Proxy headers are ignored by default because they are client-supplied: trusting
them without a proxy in front lets any caller spoof its address and bypass both
rate limiting and any address-scoped Cedar policy. Enable
`trust_proxy_headers` only behind a proxy that *overwrites* the header.

> Set `trust_proxy_headers = false` unless behind a trusted load balancer.

---

## Audit

Every authorization decision is recorded — **permits as well as denials**. A trail
of denials answers "who was turned away" but not "who read this table", which is
where an investigation starts.

### Record shape

One JSON object per line:

```json
{
  "event_id": "01a021b4-e829-7583-817d-81e02b832dc9",
  "timestamp": "2026-08-21T00:24:59.177+00:00",
  "timestamp_ms": 1787271899177,
  "category": "authorization",
  "action": "permission_check",
  "outcome": "success",
  "severity": "info",
  "principal_id": "44a3372c-5664-4670-a64d-c6cfb92aafc6",
  "tenant_id": "acme",
  "client_ip": "10.0.0.5",
  "request_id": "15f42462-e096-45c1-bcbb-26021401102f",
  "resource_type": "namespace",
  "resource_id": "acme/analytics",
  "matched_policies": ["policy1"],
  "policy_set_version": "9f2c41ab7d0e5163",
  "details": { "action": "create" }
}
```

`outcome` is `success` for a permit and `denied` for a refusal. `request_id`
matches the `X-Request-Id` echoed to the client, so a record joins to an
application log line.

#### Which rule decided

`matched_policies` and `policy_set_version` are what make this a governance
record rather than a log line. "Permitted" is the least useful half; the
question an operator arrives with is *which rule did this, and is it the rule I
thought I wrote*.

| Field | On a permit | On a denial |
|---|---|---|
| `matched_policies` | The permits that matched | The **forbids** that matched |
| `matched_policies` empty | — | **Deny by default**: nothing forbade it, nothing permitted it |

That last row matters. Deny-by-default and deny-by-rule are identical to a
client and entirely different to whoever has to fix the policy set — one is a
missing permit, the other is a rule to go read.

`policy_set_version` is derived from the **content** of the policy set, so:

- Two records sharing it were evaluated against byte-identical rules.
- It is the same on every replica that loaded the same policies — two replicas
  serving different policy files appear immediately as two versions in one
  stream.
- A record whose version differs from today's was decided under rules that have
  since changed, which is what makes an old decision reproducible.

It needs no counter and no central authority, which is why it works today rather
than waiting for a policy administration API.

### Configuration

```toml
[audit]
sink = "stdout"      # stdout | file | none
# path = "/var/log/rustberg/audit.jsonl"   # required when sink = "file"
fail_closed = true
```

Records go to **stdout** while application logs go to stderr, so the two streams
route separately without parsing. A `file` sink that cannot be opened is a startup
failure — a deployment that asked for an audit file and did not get one would
otherwise serve unaudited.

> [!WARNING]
> **Whatever reads stdout must keep reading it.** The audit stream is a real
> write on the request path, so a supervisor that captures stdout into a pipe
> nobody drains will fill the pipe buffer and block the server mid-record — which
> looks like a hang, arriving whenever traffic happens to cross the buffer size.
> Container runtimes, systemd and `| jq` all drain correctly; a script that
> collects output to read later does not. Use `sink = "file"` there.

### Fail-closed

**When the sink fails, mutating requests fail** with `503`. An unrecorded change
is precisely the event an audit exists to capture, so keeping the change and
losing the record is the one outcome a governance product cannot offer.

Reads degrade the other way: the failure is counted and serving continues.
Refusing reads because a disk filled turns an observability problem into an
outage, and a lost read record is not a lost change.

Set `fail_closed = false` to trade the guarantee for availability. Losses are
counted either way.

> Secrets (tokens, keys, passwords) are **never** recorded.

---

## Secure Defaults

Rustberg is **secure by default**. Production mode (default) enforces:

| Setting | Default | Rationale |
|---------|---------|-----------|
| TLS | Required | Prevent eavesdropping |
| Authentication | Required | Prevent unauthorized access |
| CORS origins | **None allowed** | Iceberg clients are not browsers; a browser needs an explicit grant |
| Catalog location | Must be explicit | Real metadata must not land in a temp directory |
| trust_proxy_headers | false | Prevent IP spoofing |
| Rate limiting | Enabled | Prevent DoS |

With authentication required and no credential configured, Rustberg mints one
admin key at startup and prints it, rather than starting unusable or defaulting to
open access. It is held in memory only, so a restart invalidates it — configure
API keys or OIDC for anything lasting.

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
