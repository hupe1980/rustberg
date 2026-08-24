+++
title = "Authentication"
description = "How Rustberg establishes who a caller is: OIDC/JWT with JWKS rotation, and API keys as configuration."
weight = 3
+++
## Rustberg does not issue tokens

There is no working `/v1/oauth/tokens`. The Iceberg REST spec marks that endpoint
**deprecated for removal** and says: *"It is not recommended to implement this
endpoint, unless you are fully aware of the potential security implications."* It
leaves the spec in Iceberg 2.0.

The reasoning is the same as Rustberg's own: a catalog that mints the credentials
it also validates has become an authorization server, and token lifetime and
revocation belong to the identity provider that owns them.

Two consequences for client configuration:

| You have | Use |
|----------|-----|
| An API key | The client's **`token`** property |
| OIDC | `oauth2-server-uri` pointing at **your identity provider's** token endpoint |

**Do not use `credential`.** That property makes the client perform an OAuth2
client-credentials exchange against the catalog, which fails before any catalog
call. Requesting a token from Rustberg returns `501` with this explanation rather
than a bare `401`.

When `[server.auth.jwt].oauth2_server_uri` is configured, `/v1/config` advertises
it as `oauth2-server-uri`, so a client given only the catalog URI can find where
to authenticate.


## Overview

Rustberg supports multiple authentication mechanisms:

| Method | Use Case | Production Ready |
|--------|----------|------------------|
| **API Keys** | Service-to-service, CI/CD | ✅ Recommended |
| **JWT/OIDC** | User authentication, SSO | ✅ Ready |
| **Chain Auth** | JWT with API Key fallback | ✅ Ready |

> All authentication is **required by default**. Anonymous access must be explicitly enabled (not recommended).

---

## API Key Authentication

### How It Works

1. Rustberg generates a key as 32 bytes from the OS CSPRNG, prefixed `rb_`
2. The key is hashed with **SHA-256** and only the hash is kept
3. Clients send it as `Authorization: Bearer <key>`
4. The server looks the key up by prefix and compares hashes in constant time

### Security properties

| Property | Implementation |
|----------|----------------|
| **Entropy** | 256 bits from the OS CSPRNG |
| **Hashing** | SHA-256, unsalted |
| **Timing** | Constant-time comparison |
| **Storage** | Prefix-indexed; the plaintext is never retained |
| **Enumeration** | An unknown prefix still runs a dummy verification |

#### Why not a password KDF

A password KDF makes each guess expensive, which matters when the secret is
low-entropy: a human-chosen password has perhaps 30 bits, so an attacker holding
the hash can enumerate the space. A Rustberg API key has 256 bits of uniform
entropy — there is nothing to enumerate.

So a work factor multiplies an already-impossible search by a constant, while the
*server* pays that constant on every authenticated request, and on requests
bearing no valid key at all. Argon2id at OWASP password parameters (19 MiB, two
passes) would hand unauthenticated callers a memory-hard amplification primitive.

SHA-256 over a high-entropy bearer token is what GitHub, Stripe and AWS do. No
salt: salting defeats precomputation across a shared, low-entropy input space,
and there is no such space here.

### Performance

Verification takes **~0.55 µs**, measured with `rustberg bench` — cheap
enough that caching results would only add a window in which a rotated key keeps
working.

### Creating API Keys

#### Programmatic (Recommended)

```rust
use rustberg::auth::ApiKeyStore;

// Create store (in-memory or persistent)
let store = ApiKeyStore::new();

// Generate new API key
let (key_id, plaintext) = store.create_key(
    "spark-etl",           // name
    Some("tenant-123"),    // tenant_id
    vec!["data-writer"],   // roles
).await?;

// plaintext = "rb_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
// Store this securely! It cannot be retrieved later.
```

#### CLI Tool

```bash
# Generate API key (outputs to stdout)
./rustberg generate-key \
    --name "spark-etl" \
    --tenant "tenant-123" \
    --roles "data-writer,data-reader"
```

### Using API Keys

```bash
# HTTP Header
curl -H "Authorization: Bearer rb_..." \
     http://localhost:8000/v1/namespaces

# Query parameter (not recommended)
# Credentials are read from headers only — never a query parameter, which
# would land the secret in access logs and browser history.
```

### Configuring API keys

API keys are **configuration, not state**. There is no key store: nothing to
encrypt at rest, back up, or guard with a "who may mint keys" policy. Rotation is
a config change plus a restart.

The secret itself lives in an environment variable, so the config file holds no
usable credential and can be committed:

```toml
[[server.auth.api_keys]]
name    = "ci-pipeline"
tenant  = "acme"
roles   = ["writer"]
key_env = "RUSTBERG_KEY_CI"

[[server.auth.api_keys]]
name    = "analytics-readonly"
tenant  = "acme"
roles   = ["reader"]
key_env = "RUSTBERG_KEY_ANALYTICS"
```

```bash
export RUSTBERG_KEY_CI="$(openssl rand -hex 32)"
export RUSTBERG_KEY_ANALYTICS="$(openssl rand -hex 32)"
```

The plaintext is hashed at startup and never retained, so the running
process holds no usable credential either.

A referenced variable that is unset or empty is a **startup failure**. That is
deliberate: a key that silently does not exist is indistinguishable from one
revoked on purpose, and the difference matters when you are debugging a 401.

`roles` become Cedar groups — see [authorization](@/docs/authorization.md).

### Embedding

```rust
use rustberg::App;
use rustberg::auth::ApiKeyBuilder;

let key = ApiKeyBuilder::new("ci-pipeline", "acme")
    .with_role("writer")
    .build_with_key(&std::env::var("RUSTBERG_KEY_CI")?);

let (app, _keys) = App::builder()
    .with_api_keys([key])
    .build_with_api_keys()
    .await;
```

### Revocation

Remove the entry (or unset its variable) and restart. For a deployment that is
already single-writer with `strategy: Recreate`, that is a few seconds.

If you need revocation without a restart, use **OIDC/JWT** instead — token
lifetime and revocation are then the identity provider's job, which is where that
responsibility belongs.
## JWT Authentication

### Naming the provider is enough

Rustberg validates JWTs against your identity provider's published signing keys,
and finds them by reading the issuer's discovery document. Two values are
required:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg-catalog"]
```

At the first token that needs a key, Rustberg fetches
`https://auth.example.com/.well-known/openid-configuration` and takes `jwks_uri`
from it. The document names the issuer it describes, and Rustberg **checks that
it matches the one you configured**: taking signing keys from a document naming
another issuer would make every token that issuer signs valid here. Redirects are
not followed, for the same reason.

Discovery is lazy, so a provider that is unreachable when the pod starts does not
stop it starting.

### More than one audience

A token is accepted when its `aud` matches any entry. That is the ordinary case:
an identity provider registers one client per application, so Spark, Trino and a
notebook are three audiences reaching one catalog.

The list must not be empty — that means *check nothing*, which accepts every
token your issuer has minted, including ones addressed to other services.
Rustberg refuses to start rather than accept it.

### Setting the JWKS URL explicitly

Skip discovery by naming the endpoint. Useful for a provider with a non-standard
document layout, or where the discovery document is not reachable:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg-catalog"]
jwks_url  = "https://auth.example.com/.well-known/jwks.json"

# Claims carrying tenant and roles. Shown with their defaults.
tenant_claim = "tenant_id"
roles_claim = "roles"
jwks_cache_ttl_seconds = 3600
```

### Signature algorithms

The default is **RS256, ES256 and EdDSA**, so a provider that rotates from RSA
onto elliptic-curve keys keeps working with no configuration change. The
algorithm is taken from this list, never from the token's own header.

No `HS*` algorithm can be enabled. An HMAC verifies with the same secret it signs
with, so accepting one against a JWKS would turn the *public* key your provider
publishes into a shared secret anyone could forge with. Configuring one is a
startup error.

### Naming the claims

`tenant_claim` and `roles_claim` name the claims identity is read from, so a
token that already carries the right information does not have to be reshaped.
Both accept a **dotted path** into a nested object, and both resolve the longest
literal key first — which is what makes namespaced claims work, since their names
contain dots of their own:

```toml
[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg-catalog"]

# Keycloak puts realm roles inside an object.
roles_claim = "realm_access.roles"

# Auth0 and Okta namespace custom claims with a URL. The whole URL is one key,
# and `.tenant` addresses a field inside the object it holds.
tenant_claim = "https://acme.example/claims.tenant"
```

A roles claim may be an array of strings or a single string — `"roles": "admin"`
is one role. Elements that are not strings are dropped, because a role that is a
number has no name for a Cedar group to match.

**A token with no roles joins no group.** Nothing is invented: an absent claim
yields an absent group, so such a principal matches only policies written about
the principal itself. Deny-by-default reaches here too.

**A role that cannot be a Cedar group id is dropped too**, and the principal
keeps the rest. A role becomes `Group::"analysts"` and a policy matches that
string byte for byte, so a role carrying a zero-width space is a group no policy
names and no reviewer can distinguish from `analysts`. Roles are held to the same
rendering rule as a [name](@/docs/security.md#and-from-the-identity-side):
Unicode general category `C` refused, NFC, no surrounding whitespace, length
bound. A warning names the offending code point rather than the role, since the
role's rendering is the thing in question.

A role in `[[server.auth.api_keys]]` is a **startup failure** instead — an
operator wrote it, and can fix it.

### Key rotation

An unknown `kid` triggers an immediate JWKS refetch, so a provider that rotates
its signing key is followed within seconds rather than at the end of the cache
TTL. Refetches provoked this way are rate-limited to one every 30 seconds, so a
flood of tokens bearing invented key ids cannot become a flood of requests at
your identity provider.

Refreshing the JWKS also purges every cached decoding key, so a signing key the
provider has withdrawn stops being honoured within one cache cycle
(`jwks_cache_ttl_seconds`, default one hour).

Keys are selected by `kid` **and** by purpose, so encryption keys (`"use":
"enc"`) published in the same JWKS are skipped rather than handed to the verifier
as signing keys.

### Token Requirements

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | ✅ | Must match configured issuer |
| `aud` | ✅ | Must match one of the configured `audiences` |
| `exp` | ✅ | Token expiration time |
| `sub` | ✅ | User/service identifier |
| `tenant_id` | ⚠️ | Required for multi-tenant; renameable with `tenant_claim` |
| `roles` | ⚠️ | Optional; become Cedar groups. Renameable with `roles_claim` |

The `Authorization` scheme is matched case-insensitively, so `bearer` and
`Bearer` are both accepted.

### A signed token is not a validated one

Two claims are checked for their *content* once the signature verifies. A token
failing either is rejected as an invalid token.

**The tenant** gets the rule a namespace level gets, because it is one: a Cedar
entity id begins with it — `Table::"acme␟analytics␟web␟events"`. A tenant reading
`acme␟analytics` builds, for its *own* namespace `web`, the exact id of a table
in tenant `acme`, so a policy scoped to `Namespace::"acme␟analytics"` would cover
resources it was never written for.

Refused: the unit separator and everything else in Unicode general category `C`,
non-NFC spellings, `/` and `\`, `.` and `..`, surrounding whitespace, and
anything past 255 characters. The rest of Unicode is fine — `分析` is a
legitimate tenant.

**The subject** becomes `User::"…"` and is never joined into a path, so `/` is
allowed: `auth0|5f3c`, `alice@example.com` and `https://accounts.example/u/17`
are all accepted. What is refused is anything that changes how it *renders*,
because the subject is written into every audit record and log line — a newline
forges an entry, `U+202E` reverses the rest of one. Category `C`, NFC and the
length bound; nothing else.

The tenant rule also applies to `[[server.auth.api_keys]]`, where it is a
**startup failure** rather than a rejected credential.

### Example JWT Payload

```json
{
  "iss": "https://auth.example.com",
  "aud": "rustberg-catalog",
  "sub": "user@example.com",
  "exp": 1706313600,
  "tenant_id": "tenant-123",
  "roles": ["data-reader", "data-writer"]
}
```

### Provider Examples

#### Auth0

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer    = "https://your-tenant.auth0.com/"
audiences = ["rustberg-api"]
```

#### Keycloak

Realm roles arrive inside `realm_access`, so the roles claim names the path:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer      = "https://keycloak.example.com/realms/myrealm"
audiences   = ["rustberg"]
roles_claim = "realm_access.roles"
```

The JWKS path here is `/protocol/openid-connect/certs`, which is Keycloak's own
and changes with the realm — exactly the value discovery saves you writing.

#### Okta

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer    = "https://your-org.okta.com/oauth2/default"
audiences = ["rustberg"]
```

---

## Chain Authentication

Chain authentication tries multiple methods in order:

1. **JWT** - Check `Authorization: Bearer <jwt>` header
2. **API Key** - Fall back to `Authorization: Bearer <api_key>`

This enables:
- User authentication via SSO (JWT)
- Service accounts via API keys
- Gradual migration between methods

### Configuration

```toml
[server.auth]
# Enabling both chains them: JWT is tried first, then API keys.
jwt_enabled = true
api_key_enabled = true

[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg"]
```

---

## Rate Limiting

Protect against abuse with token bucket rate limiting:

```toml
[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
```

Rate limiting is per client IP, applied before authentication so that unauthenticated
floods are cheap to shed.

There are no per-tenant limits: a limit keyed on the
tenant would have to authenticate the request first, which is the work being
protected against.

---

## Trusted proxies

Which address counts as "the client" is **not** a rate-limiting setting. The same
answer decides three things — the rate-limit bucket, `context.source_ip` in a
Cedar policy, and the address on an audit record — so it is configured once, in
`[server]`:

```toml
[server]
# The subnet the load balancer runs in. Empty (the default) trusts no proxy.
trusted_proxies = ["10.0.0.0/8"]
```

**Empty is the default and it means headers are ignored.** The caller's address
is the TCP peer, full stop. That is the only correct behaviour for a server that
might be reachable directly.

With ranges configured, Rustberg builds the forwarding chain as
`X-Forwarded-For` left to right with the TCP peer appended, and walks it **from
the right**, skipping hops inside a trusted range. The first address that is not
a trusted proxy is the client.

Reading the *leftmost* entry instead — which is all a "trust proxy headers"
boolean can mean — is a spoof. `X-Forwarded-For` is appended to at each hop, so a
client that sends `X-Forwarded-For: 10.0.0.1` arrives as
`10.0.0.1, <real client>`: it would get to choose its own `context.source_ip`,
defeating any policy conditioned on the address, and give itself a fresh
rate-limit bucket on every request.

A hop *count* would also work and is one number shorter. It is wrong the moment a
request arrives by a second path — a health checker, a mesh sidecar, an internal
caller going straight to the pod — and it is wrong in the direction that fails
open.

`X-Real-IP` is honoured only when the peer is itself a trusted proxy and no
forwarding chain was sent.

A range that does not parse is a **startup failure**. The alternative is
attributing every request to the load balancer's own address while looking like
working software.

---

## Security Best Practices

### API Keys

> - **Never** commit API keys to source control
> - **Rotate** keys periodically (90 days recommended)
> - **Use** separate keys per service/environment
> - **Monitor** key usage via audit logs

### JWT

> - **Validate** all claims (iss, aud, exp)
> - **Use** short-lived tokens (15 minutes recommended)
> - **Enable** token refresh flows
> - **Monitor** for unusual token patterns

### TLS

> Always use TLS in production. Rustberg warns when running without TLS.

```bash
# Enable TLS (recommended)
./rustberg --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem

# Self-signed for development
./rustberg generate-cert --common-name localhost
./rustberg --tls-cert ./cert.pem --tls-key ./key.pem
```

---

## Audit Logging

All authentication decisions are logged:

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "event": "auth_success",
  "principal": "spark-etl",
  "tenant_id": "tenant-123",
  "method": "api_key",
  "ip": "10.0.0.5",
  "request_id": "abc123"
}
```

### Failed Authentication

```json
{
  "timestamp": "2026-01-24T12:00:01Z",
  "event": "auth_failure",
  "reason": "invalid_token",
  "method": "jwt",
  "ip": "10.0.0.6",
  "request_id": "def456"
}
```

> Secrets (tokens, keys) are **never** logged.

---

## Troubleshooting

### "401 Unauthorized"

**Every** way of failing authentication answers the same `401`, with the same
type and the same sentence — missing, malformed, unknown, revoked, expired, bad
signature. That is deliberate: *disabled* and *expired* are reachable only after
the key's hash matches, so naming either would confirm to whoever sent a stolen
key that it is a real one.

So debug it from the **server side**, where the reason is kept:

```bash
# The audit trail names the specific reason, per request.
jq -c 'select(.action == "authenticate" and .outcome == "denied")
       | {reason: .details.reason, ip: .client_ip, request: .request_id}' \
  /var/log/rustberg/audit.jsonl
```

`request_id` matches the `X-Request-Id` the client got back, so you can join a
user's report to the exact record.

From the client side, the checklist is unchanged:

1. Verify the API key/JWT is correct
2. Check the `Authorization` header format: `Bearer <token>`
3. Ensure the token hasn't expired
4. Verify JWKS URL is accessible

### "403 Forbidden"

Authentication succeeded but authorization failed:

1. Check tenant isolation (correct `tenant_id`?)
2. Verify roles/permissions in Cedar policies
3. Check audit logs for the specific denial reason

### JWT Validation Failures

```bash
# Debug JWT claims
echo 'eyJhbGc...' | cut -d. -f2 | base64 -d | jq

# Test JWKS endpoint
curl https://auth.example.com/.well-known/jwks.json | jq
```

---

## Next Steps

- [Authorization Guide](@/docs/authorization.md) - Cedar policies
- [Encryption Guide](@/docs/encryption.md) - what is encrypted, and what deliberately is not
- [API Reference](@/docs/api.md) - Authentication endpoints
