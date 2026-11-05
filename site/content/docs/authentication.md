+++
title = "Authentication"
description = "How Rustberg establishes who a caller is: OIDC/JWT with JWKS rotation, and API keys as configuration."
weight = 3
+++
## Rustberg does not issue tokens

There is no working `/v1/oauth/tokens`: the Iceberg REST spec marks it
**deprecated for removal**, advises against implementing it, and drops it in
Iceberg 2.0. Token lifetime and revocation belong to your identity provider.

Configure clients as follows:

| You have | Use |
|----------|-----|
| An API key | The client's **`token`** property |
| OIDC | `oauth2-server-uri` pointing at **your identity provider's** token endpoint |

**Do not use `credential`.** It triggers an OAuth2 client-credentials exchange
against the catalog, which fails before any catalog call: Rustberg returns `501`
with an explanation, not a bare `401`.

When `[server.auth.jwt].oauth2_server_uri` is set, `/v1/config` advertises it as
`oauth2-server-uri`, so a client given only the catalog URI can find where to
authenticate.


## Overview

| Method | Use Case | Production Ready |
|--------|----------|------------------|
| **API Keys** | Service-to-service, CI/CD | ✅ Recommended |
| **JWT/OIDC** | User authentication, SSO | ✅ Ready |
| **Chain Auth** | JWT with API Key fallback | ✅ Ready |

> Authentication is **required by default**. Anonymous access must be explicitly enabled (not recommended).

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

A work factor protects low-entropy secrets such as passwords. A key with 256
bits of uniform entropy has nothing to enumerate, so a work factor would only
cost the server on every request, including unauthenticated ones: Argon2id at
OWASP parameters (19 MiB, two passes) would be a memory-hard amplification
primitive.

No salt: there is no shared, low-entropy input space to precompute.

### Performance

Verification is one SHA-256 and a constant-time compare, so results are not
cached; a cache would only let a rotated key keep working longer.

### Creating API Keys

```bash
./rustberg generate-key --name spark-etl --tenant acme --roles writer
```

It prints the secret once, as an `export`, and the `[[server.auth.api_keys]]`
entry to paste into the configuration. A key is `rb_` followed by 10–61
URL-safe characters; a secret that is not one fails startup.

### Using API Keys

```bash
# A bearer token, as Iceberg clients send it (X-API-Key works too)
curl -H "Authorization: Bearer rb_..." \
     http://localhost:8000/v1/namespaces
```

Credentials are read from headers only, never from a query parameter.

### Configuring API keys

API keys are **configuration, not state**: no key store to encrypt, back up, or
guard with a "who may mint keys" policy. Adding, rotating or revoking a key is
a config change plus a restart.

The secret lives in an environment variable, so the config file can be
committed:

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
export RUSTBERG_KEY_CI="rb_$(openssl rand -hex 24)"
export RUSTBERG_KEY_ANALYTICS="rb_$(openssl rand -hex 24)"
```

The plaintext is hashed at startup and never retained.

A referenced variable that is unset or empty is a **startup failure**, so a
missing key is never mistaken for a revoked one.

`roles` become Cedar groups — see [authorization](@/docs/authorization.md).

**The name is the principal.** A key authenticates as
`Rustberg::ApiKey::"<name>"` — a separate kind from a token subject,
`Rustberg::User::"<sub>"`. Policies, the audit trail and policy history use that
name, stable across restarts and replicas. A name follows the token-subject rule
(no control or formatting characters); breaking it is a startup failure.

**Rotating a key** uses two entries with the same name and different secrets:
add the new one, deploy, move the client over, then delete the old entry. Both
secrets are the one principal, so no request is refused and the audit trail is
unbroken. Entries sharing a name must agree on
`tenant` and `roles`, or startup fails.

```toml
[[server.auth.api_keys]]          # the secret being retired
name    = "ci-pipeline"
tenant  = "acme"
roles   = ["writer"]
key_env = "RUSTBERG_KEY_CI"

[[server.auth.api_keys]]          # its replacement
name    = "ci-pipeline"
tenant  = "acme"
roles   = ["writer"]
key_env = "RUSTBERG_KEY_CI_NEXT"
```

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

Remove the entry and restart — a few seconds for a
single-writer deployment with `strategy: Recreate`.

For revocation without a restart, use **OIDC/JWT**: the identity provider then
owns token lifetime and revocation.

## JWT Authentication

### Naming the provider is enough

Rustberg finds the signing keys through the issuer's discovery document. Two
values are required:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer    = "https://auth.example.com"
audiences = ["rustberg-catalog"]
```

On the first token that needs a key, Rustberg fetches
`https://auth.example.com/.well-known/openid-configuration` and reads
`jwks_uri`. It **checks the document's issuer matches the configured one** and
does not follow redirects, so another issuer's tokens are never valid here.

Discovery is lazy: an unreachable provider does not stop the pod starting.

### More than one audience

A token is accepted when its `aud` matches any entry (e.g. Spark, Trino and a
notebook as three registered clients).

An empty list is a startup failure: it would accept every token your issuer
mints, including ones for other services.

### Setting the JWKS URL explicitly

Name the endpoint to skip discovery — for a provider whose discovery document is
non-standard or unreachable:

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

The default is **RS256, ES256 and EdDSA**, so a provider moving from RSA to
elliptic-curve keys needs no configuration change. The algorithm comes from this
list, never from the token's header.

No `HS*` algorithm can be enabled; configuring one is a startup error (an HMAC
would turn your provider's public key into a shared secret).

### Naming the claims

`tenant_claim` and `roles_claim` name the claims identity is read from. Both
accept a **dotted path** into a nested object and resolve the longest literal key
first, so namespaced claims whose names contain dots work:

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

A roles claim may be an array of strings or a single string (`"roles": "admin"`
is one role). Non-string elements are dropped.

**A token with no roles joins no group**; it matches only policies written about
the principal itself.

**A role that cannot be a Cedar group id is dropped**; the principal keeps the
rest. Group ids match byte for byte, so a role with a zero-width space would be
indistinguishable from `analysts` to a reviewer. Roles follow the [name](@/docs/security.md#and-from-the-identity-side) rendering rule:
Unicode general category `C` refused, NFC, no surrounding whitespace, length
bound. The warning names the offending code point, not the role.

A role in `[[server.auth.api_keys]]` that breaks the rule is a **startup
failure** instead.

### Key rotation

An unknown `kid` triggers an immediate JWKS refetch, so provider key rotation is
followed within seconds. Such refetches are limited to one every 30 seconds, so
invented key ids cannot flood your identity provider.

A JWKS refresh purges every cached decoding key, so a withdrawn signing key stops
being honoured within one cache cycle (`jwks_cache_ttl_seconds`, default one
hour).

Keys are selected by `kid` **and** purpose: encryption keys (`"use": "enc"`) in
the same JWKS are skipped.

### Token Requirements

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | ✅ | Must match configured issuer |
| `aud` | ✅ | Must match one of the configured `audiences` |
| `exp` | ✅ | Token expiration time |
| `sub` | ✅ | User/service identifier |
| `tenant_id` | ⚠️ | Required for multi-tenant; renameable with `tenant_claim` |
| `roles` | ⚠️ | Optional; become Cedar groups. Renameable with `roles_claim` |

The `Authorization` scheme is case-insensitive: `bearer` and `Bearer` both work.

### A signed token is not a validated one

After the signature verifies, two claims are checked for content; a token
failing either is rejected as invalid.

**The tenant** follows the namespace-level rule, because it begins every Cedar
entity id (`Table::"acme␟analytics␟web␟events"`): a tenant `acme␟analytics`
could otherwise build, for its namespace `web`, the id of a table in tenant
`acme`.

Refused: the unit separator and the rest of Unicode general category `C`,
non-NFC spellings, `/` and `\`, `.` and `..`, surrounding whitespace, and
anything past 255 characters. Other Unicode is fine — `分析` is a legitimate
tenant.

**The subject** becomes `User::"…"` and is never joined into a path, so `/` is
allowed: `auth0|5f3c`, `alice@example.com` and `https://accounts.example/u/17`
are accepted. Because it is written into every audit record and log line, only
what changes its rendering is refused (a newline, `U+202E`): category `C`, NFC
and the length bound.

The tenant rule also applies to `[[server.auth.api_keys]]`, as a **startup
failure**.

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

Realm roles sit inside `realm_access`:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
issuer      = "https://keycloak.example.com/realms/myrealm"
audiences   = ["rustberg"]
roles_claim = "realm_access.roles"
```

Discovery supplies Keycloak's realm-specific JWKS path
(`/protocol/openid-connect/certs`).

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

Chain authentication tries methods in order:

1. **JWT** - Check `Authorization: Bearer <jwt>` header
2. **API Key** - Fall back to `Authorization: Bearer <api_key>`

Use it for SSO users alongside API-key service accounts, or to migrate between
methods.

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

Token-bucket rate limiting:

```toml
[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
```

Limits are per client IP and applied before authentication, so unauthenticated
floods are cheap to shed. There are no per-tenant limits (they would require
authenticating first).

---

## Trusted proxies

The client address decides the rate-limit bucket, `context.source_ip` in Cedar,
and the audit record address. Configure it once, in `[server]`:

```toml
[server]
# The subnet the load balancer runs in. Empty (the default) trusts no proxy.
trusted_proxies = ["10.0.0.0/8"]
```

**Empty, the default, ignores forwarding headers**: the client is the TCP peer.

With ranges configured, Rustberg takes `X-Forwarded-For` left to right, appends
the TCP peer, and walks the chain **from the right**, skipping hops inside a
trusted range. The first address that is not a trusted proxy is the client.

The leftmost entry is never trusted: a client sending
`X-Forwarded-For: 10.0.0.1` arrives as `10.0.0.1, <real client>`, and could
otherwise pick its own `context.source_ip` and rate-limit bucket.

`X-Real-IP` is honoured only when the peer is itself a trusted proxy and no
forwarding chain was sent.

A range that does not parse is a **startup failure**.

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

Every authentication, accepted or refused, is an audit record:

```json
{
  "timestamp": "2026-01-24T12:00:00Z",
  "category": "authentication",
  "action": "authenticate",
  "outcome": "success",
  "operation": "api_key",
  "principal_id": "spark-etl",
  "principal_type": "api_key",
  "tenant_id": "acme",
  "client_ip": "10.0.0.5",
  "request_id": "abc123"
}
```

A refusal has `"outcome": "denied"`, no principal, and the reason in
`details.reason` (for example `credential expired`).

> Secrets (tokens, keys) are **never** logged.

---

## Troubleshooting

### "401 Unauthorized"

**Every** authentication failure — missing, malformed, unknown, revoked,
expired, bad signature — answers the same `401`, type and sentence. *Disabled*
and *expired* are reachable only after the hash matches, so naming them would
confirm a stolen key.

Debug from the **server side**, where the audit trail records the reason:

```bash
# The audit trail names the specific reason, per request.
jq -c 'select(.action == "authenticate" and .outcome == "denied")
       | {reason: .details.reason, ip: .client_ip, request: .request_id}' \
  /var/log/rustberg/audit.jsonl
```

`request_id` matches the `X-Request-Id` the client got back.

From the client side:

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
