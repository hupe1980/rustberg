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

Verification takes **~0.55 µs**, measured with `rustberg benchmark` — cheap
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

### JWKS Configuration

Rustberg validates JWTs against a JWKS (JSON Web Key Set) endpoint:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "rustberg-catalog"

# Claims carrying tenant and roles. Shown with their defaults.
tenant_claim = "tenant_id"
roles_claim = "roles"
jwks_cache_ttl_seconds = 3600
```

### Naming the claims

`tenant_claim` and `roles_claim` name the claims identity is read from, so a
token that already carries the right information does not have to be reshaped.
Both accept a **dotted path** into a nested object, and both resolve the longest
literal key first — which is what makes namespaced claims work, since their names
contain dots of their own:

```toml
[server.auth.jwt]
jwks_url = "https://auth.example.com/.well-known/jwks.json"
issuer   = "https://auth.example.com"
audience = "rustberg-catalog"

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

### Key rotation

An unknown `kid` triggers an immediate JWKS refetch, so a provider that rotates
its signing key is followed within seconds rather than at the end of the cache
TTL. Refetches provoked this way are rate-limited to one every 30 seconds, so a
flood of tokens bearing invented key ids cannot become a flood of requests at
your identity provider.

Refreshing the JWKS also purges every cached decoding key, so a signing key the
provider has withdrawn stops being honoured within one cache cycle
(`jwks_cache_ttl_seconds`, default one hour).

### Token Requirements

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | ✅ | Must match configured issuer |
| `aud` | ✅ | Must match configured audience |
| `exp` | ✅ | Token expiration time |
| `sub` | ✅ | User/service identifier |
| `tenant_id` | ⚠️ | Required for multi-tenant; renameable with `tenant_claim` |
| `roles` | ⚠️ | Optional; become Cedar groups. Renameable with `roles_claim` |

The `Authorization` scheme is matched case-insensitively, so `bearer` and
`Bearer` are both accepted.

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
jwks_url = "https://your-tenant.auth0.com/.well-known/jwks.json"
issuer = "https://your-tenant.auth0.com/"
audience = "rustberg-api"
```

#### Keycloak

Realm roles arrive inside `realm_access`, so the roles claim names the path:

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
jwks_url = "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
issuer = "https://keycloak.example.com/realms/myrealm"
audience = "rustberg"
roles_claim = "realm_access.roles"
```

#### Okta

```toml
[server.auth]
jwt_enabled = true

[server.auth.jwt]
jwks_url = "https://your-org.okta.com/oauth2/default/v1/keys"
issuer = "https://your-org.okta.com/oauth2/default"
audience = "rustberg"
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
jwks_url = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "rustberg"
```

---

## Rate Limiting

Protect against abuse with token bucket rate limiting:

```toml
[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
trust_proxy_headers = false  # Set true behind load balancer
```

Rate limiting is per client IP, applied before authentication so that unauthenticated
floods are cheap to shed. There are no per-tenant limits: a limit keyed on the
tenant would have to authenticate the request first, which is the work being
protected against.

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
