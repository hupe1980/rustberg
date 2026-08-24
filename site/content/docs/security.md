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

A password KDF is deliberately *not* used: its work factor defends a
low-entropy secret, and buys nothing against a 256-bit random token while
costing the server on every request. See
[authentication](@/docs/authentication.md#why-not-a-password-kdf).

### JWT Validation

| Check | Description |
|-------|-------------|
| Signature | RS256 / ES256 / EdDSA by default; the algorithm list is configuration, never taken from the token |
| Issuer | Must match configured `iss` |
| Audience | Must match one of the configured `audiences`, which may not be empty |
| Expiration | Token must not be expired |
| Not Before | Token must be active |
| Subject | Required — a token without one would authenticate as the empty string |

**The token does not choose how it is verified.** Its header's `alg` selects the
key and nothing else; the validator is built from the configured algorithm list.
No `HS*` algorithm can be enabled, at all: an HMAC verifies with the same secret
it signs with, so accepting one against a JWKS turns the *public* key your
provider publishes into a shared secret anyone who can read it could forge with.
Configuring one is a startup error.

**Keys come from the issuer, checked.** The JWKS URL is discovered from
`{issuer}/.well-known/openid-configuration`, whose own `issuer` must match the
configured one — a document naming another issuer would make every token *that*
issuer signs valid here. Redirects are not followed, and both documents are read
with a size ceiling. Keys are selected by `kid` **and** by purpose, so an
encryption key (`"use": "enc"`) in the same JWKS is skipped rather than handed to
the verifier.

---

## Authorization Security

### Cedar Policy Engine

- **Default deny** — no access without an explicit permit, including on
  evaluation error. Cedar's own rule is that a policy which fails to evaluate
  contributes nothing, so a `forbid` that raises would simply not apply;
  Rustberg reads the evaluation diagnostics and denies the request instead,
  naming the policy in the log
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

### The storage boundary is the policy boundary

`createTable`, `createView` and `registerTable` all let a client name a storage
location, and that location becomes the prefix of any credential vended for the
resulting table. Left unchecked it is a confused-deputy hole:

```http
POST /v1/namespaces/mine/register
{ "name": "borrowed", "metadata-location": "s3://someone-elses-bucket/secrets/…json" }
```

A caller permitted only in its own namespace would borrow *the server's*
authority over a prefix its policy never mentioned. So every client-supplied
location is checked before it is recorded, and a registered resource's metadata
is re-checked after reading — a file at a legitimate path can still declare a
`location` pointing elsewhere.

**Inside the warehouse is not a tight enough bound.** A grant is written over the
*namespace tree*; storage access is scoped to a *path*. Those are one hierarchy
only while a resource's files stay where its name puts them — otherwise:

1. A caller may write `public.mine` and cannot even *see* `finance.secret`.
2. It commits `set-location` on its own table, naming `finance/secret`'s prefix.
   Permitted caller, own table, location inside the warehouse.
3. It loads its own table asking for `vended-credentials` and is handed a
   correctly-scoped credential — for the other namespace's data.

Every step there is permitted; the location was simply not the caller's to
choose. So the bound is `<warehouse>/<namespace>/<name>`, the prefix the
resource's own name puts it in. It holds with no lookup and no scan: names are
unique within a namespace and namespaces nest by segment, so two resources'
prefixes are disjoint by construction. A resource still lays itself out freely
*under* its own prefix.

`storage.location_scope = "warehouse"` widens the bound back, and gives the
sequence above back with it — see
[configuration](@/docs/configuration.md#where-a-client-may-put-a-table-s-files).

Containment is **segment-wise**, not a string prefix test. `s3://bucket/wh-evil`
merely spells like `s3://bucket/wh`; it is a different prefix and is refused.
`s3a://` and `s3://` name the same bucket and are treated as one. A `..`
segment is refused outright.

Under [federation](@/docs/configuration.md#federation) the governing
warehouse is the **mount's**, not the server's: each mount has its own, and a
table created in a mount belongs in that one. The boundary is per-mount rather
than global, and holds in both directions — a mount's warehouse is not a way
into the server's, and the server's is not a way into a mount's.

That per-mount bound is also what **storage access** is checked against, and not
merely "some warehouse this server manages". A mount is somebody else's catalog
sitting on the request path of every call into its subtree, and the table
`location` it returns is a string it chose. Against the union of managed
warehouses, a remote reporting a location inside *this* server's warehouse would
be credentialed for it — another tenant's prefix, for a caller who only ever had
`Read` on the mount. A namespace whose catalog declares no warehouse at all — a
`rest` mount stores nothing — gets no credential and no signature.

`credentials.allowed_prefixes` is the second, independent half of the same
defence — see [configuration](@/docs/configuration.md#credentials). Left
unset it becomes exactly the warehouse. Either half alone closes the hole.

**A commit names locations too, and that is the easy one to miss.** Creating a
table reads as "here is a path"; committing to one reads as "change the schema,
add a snapshot". Four updates carry a location anyway:

| Update | Names |
|---|---|
| `set-location` | the table's location — it *moves* the table |
| `add-snapshot` | a manifest list, which scan planning reads and a purge deletes |
| `set-statistics` | a Puffin file, which a purge deletes |
| `set-partition-statistics` | the same |

**Two bounds, because the four ask different questions.** `set-location`
*changes* what a credential will be scoped to, so it is held to the bound above.
The three that name **files** are held to the table's own `location`: the table
already owns that, and a credential is already scoped to exactly it, so a
manifest list underneath grants nothing new. It also has to be the location
rather than the name, because a rename moves a table's registry entry and never
its files — `db.old` renamed to `db.new` keeps its files at `…/db/old`.

Both run on every commit path: `commitTable`, `commitTransaction`, `commitView`
and the in-process `Session`.

**A commit cannot check the inside of a manifest**, which lists data files by
path; reading every manifest on every write would put the catalog in the data
path. The bound moves to where those paths are acted on instead: a
[purge](@/docs/api.md#drop-table) deletes only what lives under the table's own
storage, and names what it skipped.

### A signature authorizes one request, not a standing grant

Remote signing confines every object request to the table's own location — and
"the location a request touches" is not always in the path.

`DeleteObjects` names its keys in an XML body and `ListObjectsV2` names its
prefix in the query string; both address the *bucket*, so reading only the path
would authorize them against all of it. `x-amz-copy-source` names, in a header,
the object a server-side copy reads **from**: a `PUT` into your own table with a
copy source in somebody else's bucket has a destination that passes every
containment check, and asks S3 to fill it using *the catalog's* storage role. All
three are resolved and confined.

The operation is checked too, because S3 dispatches on a query-string
sub-resource rather than on the method. `PUT …/f.parquet?acl` with `x-amz-acl:
public-read` is inside the table and publishes it to the internet. So the
endpoint signs an allowlist — object access, multipart upload, `DeleteObjects`,
`ListObjectsV2` — and refuses both the sub-resources that change who may reach an
object and the headers (`x-amz-acl`, `x-amz-grant-*`) that grant access outright.

And the signature covers the URI the *check* ran on. A URL parser resolves `.`
and `..` out of a path and reads a backslash as a separator, so a URI whose raw
path leaves the table can read here as one that stays inside it — while S3 takes
the key literally. The endpoint resolves the URI once, checks that, signs that,
and returns that, so anything else a client sends to S3 is refused by S3 as
`SignatureDoesNotMatch`. Containment is enforced by the signature rather than by
a list of spellings somebody had to anticipate.

Full detail in [the API reference](@/docs/api.md#remote-signing).

### A table name reaches two policy languages

A vended credential is scoped to the table's storage location, and the last
segment of that location is the table's *name* — which may be any Unicode
outside category `C`. Two of the three providers then splice that into a
language that has metacharacters:

| Provider | The hazard | What Rustberg does |
|---|---|---|
| AWS | `*` and `?` are wildcards in an IAM `Resource` ARN; `${…}` is a policy variable. A table named `*` scopes the credential to `bucket/wh/db/*/*` — every sibling table | Written in IAM's literal forms `${*}`, `${?}`, `${$}` |
| GCS | The access boundary is a **CEL expression** and the prefix sits in a quoted string literal. A table named `x') \|\| true \|\| ('` closes the literal and makes the condition true for the whole bucket | The apostrophe and backslash are escaped |
| Azure | None — the path goes into a canonical resource that is **signed** | Nothing to escape |

Escaping at the boundary rather than banning the characters is the same choice
made about [what a name is validated for](#input-validation): `*` is legal in
Iceberg, and it is dangerous only where it is spliced into IAM's pattern
language.

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
| **Name length** | Max 255 **characters**, so the limit means the same in every script |
| **Namespace depth** | Max 10 levels |
| **Properties count** | Max 100 per resource |
| **Path separators** | Block `/` and `\\` inside a name |
| **Directory names** | Block `.` and `..` as whole segments |
| **Unicode category `C`** | Block control, format, private-use and unassigned code points — covers `\0`, the `␟` the entity encoding depends on, and every invisible or directional character |
| **Normalization** | Names must be NFC; another form is refused, with the accepted spelling in the error |
| **Surrounding whitespace** | Block, so two visually identical names cannot be distinct strings |
| **JWT size** | Tokens over 16 KB rejected before parsing |
| **Identity claims** | `tenant`, `sub` and each role are held to the same rendering rule as a name — see [below](#and-from-the-identity-side) |
| **Page tokens** | Validated against the namespace being listed; a forged one restarts the scan rather than seeking |
| **Correlation ids** | An inbound `X-Request-Id` over 128 characters, outside a token alphabet, or sent twice is **replaced** with a minted one, which is then both echoed and recorded |

### What the rule is derived from

A name is used as three things, and each one rules something out:

| Used as | Rules out |
|---------|-----------|
| A path segment in the table's storage location | `/`, `\\`, `.`, `..` |
| A segment of a Cedar entity id, joined with `␟` | every code point in general category `C`, which includes the unit separator |
| A field in an audit record and a log line | the same, again |

That is the whole list. The path-scoping model rests on the entity encoding being
**injective** — a name that could contain `␟` would let a policy written for one
resource silently match another — and refusing category `C` is what makes
truncation exact.

#### One rendering, one resource

A Cedar policy names a resource by an id built from these segments, so two names
that *display* identically and store differently are two resources — and your
policy covers only one of them. Two rules follow:

- **Category `C` is refused, not just control characters.** `Cf` is where the
  hazard is: zero-width space, soft hyphen, byte-order mark, and the
  bidirectional overrides. `events` and `events<ZWSP>` are two tables no reviewer
  reading your policy file can tell apart.
- **Names must be in NFC.** `café` is one code point for `é` composed and two
  decomposed: different bytes, different key, different entity id, different
  storage path. The other forms are refused rather than rewritten — a client that
  asked for one name and got another back has been lied to — and the error names
  the accepted spelling.

Neither is a homoglyph or mixed-script check: `а` (Cyrillic) and `a` are
different letters a legitimate deployment may both use.

Everything else in Unicode is allowed. A table may be called `分析`, `café_visits`
or `Ω_measurements`.

There is no allowlist beyond the rules above, and no filesystem folklore:
Windows device names (`CON`, `LPT1`) and leading dots are accepted, because
neither is a security control and refusing them costs interoperability.

Validation applies to **every** path a name can arrive by. Most arrive through
the URL and are checked by the path extractor; `commitTable` and
`commitTransaction` may also name their table in the request body, and those are
validated too. The injectivity argument rests on the rules holding everywhere, so
a body-supplied name that skipped them would weaken the claim to "the two
encodings happen to agree".

#### And from the identity side

A request path is not the only way an entity id is built. Three values arrive
from a **token** and each becomes part of one, so each is held to the rule above:

| From a token | Becomes | A value that fails the rule |
|---|---|---|
| `tenant_claim` | the first segment of every resource id | rejected credential — `acme␟analytics` builds the ids of tenant `acme`'s `analytics` namespace |
| `sub` | `User::"…"` | rejected credential — it names who the audit trail says acted |
| `roles_claim` | `Group::"…"` | the role is **dropped**; the principal keeps the rest |

The tenant and the subject are load-bearing, so neither has a safe partial
answer. A role is one grant among several and an unrepresentable one grants
nothing — no policy names a string with an invisible character in it — so
dropping it is the deny-by-default direction, where failing the token would lock
a caller out over a claim it neither chose nor can fix.

A tenant or a role written into **configuration** is a startup failure instead:
an operator wrote it, and can fix it.

---

## What is reachable without a credential

Two routes sit outside the authentication layer, because a Kubernetes liveness
probe cannot hold one and a Prometheus scrape should not need one:

| Route | What it returns |
|---|---|
| `GET /health` | Liveness. A status word, the version, a timestamp. |
| `GET /ready` | Readiness. `ready` / `degraded` for the **two** components actually probed — catalog and storage — a **category** for each failure, and the storage backend kind with a round-trip time. |
| `GET /metrics` | Aggregate counters. No tenant, namespace or table labels. |

`/ready` deliberately does **not** carry the backend's own error text. A database
error names the host and database, an object-store error names the bucket and
key, and a federated catalog's health message names every unreachable mount —
which is deployment topology, handed to anyone who can open a socket. The detail
goes to the server log instead.

It reports only what it probed: anything else a replica needs is a value that
exists or the process did not start, and a component that could only ever read
`ready` would say something was checked when nothing was.

The probe is cached for two seconds. These routes are outside the authentication
layer and therefore outside rate limiting, so without the cache one
unauthenticated request becomes a database query plus an object-store round trip
at a rate the caller picks.

Restrict these at the network layer if a deployment needs to; the Helm chart's
`NetworkPolicy` is where that belongs.

### Every credential rejection is the same rejection

A missing credential, a malformed key, an unknown key, a revoked key, an expired
key and a bad JWT signature all answer `401 NotAuthorizedException` with one
sentence between them.

The API key comparison is constant-time — a lookup that misses still verifies
against a dummy hash — and *disabled* and *expired* are reachable only after it
**succeeds**, so an error naming either is a positive answer to "is this key
real". Saying it in prose would give back what the constant-time comparison
denies.

The reason goes to the audit record instead, joined to the request by
`request_id`. See [debugging a 401](@/docs/authentication.md#401-unauthorized).

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

### In an error message

Anything that is *this server's* problem — a database failure, an unreachable
identity provider, a configuration mistake — is answered as "an internal error
occurred, check the server log" and the full text goes to **stderr** instead. A
credential failure never says which part failed, so error text cannot be used to
enumerate keys.

Both are unconditional, in every build. Keying redaction on
`cfg!(debug_assertions)` would make the behaviour under test differ from the
behaviour in production, which is the one place a difference matters — and a
debug binary is what an engineer points at a *real* identity provider, whose
fetch errors carry internal hostnames and sometimes a token in a query string.

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

**Why a /64 and not an address.** A `/64` is the smallest IPv6 allocation anyone
receives, and it holds 2^64 addresses. A limiter keyed by full address hands an
attacker a fresh bucket for every request it sends — and the bounded tracking map
that is supposed to prevent memory exhaustion becomes the attack instead, since
100k requests from one prefix evict every real client's bucket. Two hosts behind
one prefix share an allowance, which is the trade NAT already imposes on IPv4.

Proxy headers are ignored by default because they are client-supplied: trusting
them without a proxy in front lets any caller spoof its address and bypass both
rate limiting and any address-scoped Cedar policy.

Naming the proxies is what makes the header safe to read. `X-Forwarded-For` is
*appended to* at each hop, so a client that sends one of its own arrives as
`<spoofed>, <real client>` — reading it left to right believes the attacker.
Rustberg walks the chain from the right instead, skipping hops inside a trusted
range, and takes the first address that is not infrastructure. One setting, in
`[server]`, because the same answer feeds the rate-limit bucket,
`context.source_ip` in a Cedar policy, and the audit record.

A hop the chain does not spell out — RFC 7239 lets a proxy write `unknown` or an
obfuscated identifier — **stops** the walk rather than being skipped over.
Skipping it would let the walk continue past the client's real position and land
on whatever the client itself wrote further left. The address is then reported as
unknown, so a policy guarded with `context has source_ip` does not apply.

> Leave `trusted_proxies` empty unless behind a load balancer whose subnet you
> can name.

---

## Audit

Everything security-relevant goes to **one sink**, and there is no second path.
Five kinds of event are recorded, and the list is closed — an event kind nothing
emits would be a claim about the trail that reading the trail disproves.

| `action` | `category` | Says | Refuses the request if unrecordable |
|---|---|---|---|
| `authenticate` | `authentication` | a credential was presented and accepted, or rejected | no |
| `decision` | `authorization` | a policy decision, permit and deny alike | for a **permitted** mutation |
| `vend_credentials` | `storage_access` | what was vended, and whether it could **write** | when a write credential was **granted** |
| `sign_request` | `storage_access` | what was signed, and **which objects** | when a write signature was **minted** |
| `rate_limit` | `system` | which bucket ran out, `ip` or `tenant` | no |

Every "yes" in that last column is a grant that happened; nothing fails because a
refusal could not be recorded. See [fail-closed](#fail-closed).

Permits are recorded as well as denials. A trail of denials answers "who was
turned away" but not "who read this table", which is where an investigation
starts.

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
  "principal_id": "44a3372c-5664-4670-a64d-c6cfb92aafc6",
  "tenant_id": "acme",
  "client_ip": "10.0.0.5",
  "request_id": "15f42462-e096-45c1-bcbb-26021401102f",
  "resource_type": "namespace",
  "resource_id": "acme/analytics",
  "matched_policies": ["policy1"],
  "policy_set_version": "9f2c41ab7d0e5163"
}
```

`outcome` is `success` for a permit, `denied` for a refusal, and `failure` when
policy said yes and the thing failed anyway — a credential exchange the cloud
provider refused, for instance. One is a policy question and the other is an
outage, and they are not the same line to page on.

`operation` says what was being done. On a decision it is the action **spelled as
the policy file spells it**, so a denial naming `Update` greps against
`Rustberg::Action::"Update"`. On a storage-access record it is the access level:
`read`, `read-write` or `none` for a vended credential, and `read` or `write` for
a signature. `none` is not the same as `read` — a withheld credential never had a
width decided for it.

`request_id` matches the `X-Request-Id` echoed to the client, so a record joins to
an application log line — and it is read before anything can be refused, so a
`401` and a `429` join as well as a served request does.

An inbound id is carried through so a trace survives the hop, but only if it is
something this server will carry: at most 128 characters, a conservative token
alphabet, and not sent twice. An id that fails any of those is **replaced** by a
minted one rather than ignored. Ignoring it would leave the response echoing the
caller's value while the record named nothing — which lets a caller unjoin its
own requests from the trail by sending an oversized id, turning a bound meant to
stop the trail growing into a way around it. Every request has exactly one id,
and the echo and the record always name it.

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

### Storage access

The decision record says a caller was permitted to `Read` a table. It does not say
that the caller walked away with a credential that could overwrite it. That is a
different fact, and *who could have written this object* is the question the trail
is kept to answer, so it gets its own record:

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

A signature is request-shaped rather than table-shaped, so the record names the
objects: "signed a `DeleteObjects` over nine hundred files" and "signed a `GET` of
one" are the difference the trail exists to show. Long lists are truncated to the
first few plus a count so the record stays one line; every location in one is
inside the table it names, since the containment check ran first. Refusals are
recorded too, and name what was reached for.

Nothing is recorded when nothing was handed over: an uncredentialed `loadTable`
writes no vending record, and one per read would say nothing.

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

Every event in the table above goes to this one sink. A record on a second path —
the application log on stderr, say — is missing from the file, and a
`sink = "file"` describing what callers were permitted to do but never who they
were reads as complete.

> [!WARNING]
> **Whatever reads stdout must keep reading it.** The audit stream is a real
> write on the request path, so a supervisor that captures stdout into a pipe
> nobody drains will fill the pipe buffer and block the server mid-record — which
> looks like a hang, arriving whenever traffic happens to cross the buffer size.
> Container runtimes, systemd and `| jq` all drain correctly; a script that
> collects output to read later does not. Use `sink = "file"` there.

### Fail-closed

**When the sink fails, a permitted mutation fails** with `503`. An unrecorded
change is precisely the event an audit exists to capture, so keeping the change
and losing the record is the one outcome a governance product cannot offer. A
grant of **write** access to storage counts as one: a vended read-write
credential and a signature over a write are refused rather than issued
unrecorded.

Everything else keeps serving, and the loss is counted:

| Unrecordable | Answer | Why |
|---|---|---|
| A permitted mutation | `503` | It would be a change nothing recorded |
| A granted write credential, a minted write signature | `503` | Same: authority over the warehouse, handed out unrecorded |
| A **denied** mutation | the denial | It changed nothing, so there is nothing unrecorded to refuse — and `503` would tell a caller to retry when what it needs is a permit |
| A read or a listing | the response | Refusing reads because a disk filled turns an observability problem into an outage |
| Authentication, rate limiting | the response | Same, and they are decided before the server knows whether a mutation was coming |

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
| `trusted_proxies` | empty | Forwarding headers are ignored, so an address cannot be spoofed |
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
