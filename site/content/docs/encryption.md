+++
title = "Encryption"
description = "What Rustberg encrypts, what it deliberately does not, and where table encryption actually belongs."
weight = 6
+++
## Scope

Rustberg encrypts one thing:

| What | How |
|------|-----|
| Everything in transit | TLS 1.3 |

That is the whole surface, and the boundary is deliberate — see below for what is
deliberately *not* covered here.

### Why the catalog does not encrypt table metadata

Encrypting properties inside the catalog would protect the wrong layer:

- Query engines read table metadata files **directly from object storage**, where
  they are plaintext regardless. The catalog encrypting its own copy changes
  nothing an attacker with bucket access can see.
- It would not touch data files at all.

Encrypting a lakehouse is a **table-level** concern, not a catalog-level one. The
Iceberg answer is [Parquet modular encryption](https://iceberg.apache.org/spec/),
where per-column keys are held by a KMS and released to authorised readers. That
protects the bytes wherever they are read from, which catalog-side encryption
cannot.

Use object-store encryption (SSE-S3, SSE-KMS, CMEK) for at-rest protection of the
warehouse, and table-level encryption where column secrecy matters.

---

## API keys

There is nothing to encrypt: API keys are **configuration**, not stored state.
Secrets live in environment variables (or a mounted secret), are hashed at
startup, and the hash is all the running process keeps. See
[authentication](@/docs/authentication.md).

This is a deliberate simplification. Persisting keys and encrypting that store
would mean a database file to secure, a key to manage for the key store, and an
authorization question about who may mint keys. Treating keys as configuration
removes all three.

## TLS

Rustberg is rustls-only. There is no OpenSSL or native-tls anywhere in the
dependency tree, in any feature combination — which is what lets the binary
cross-compile statically.

```toml
[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"
```

Omit both paths to have Rustberg generate a self-signed certificate — useful for
development, not for production. Supplying one path without the other is a
startup error rather than a silent fallback.

`insecure_http = true` disables TLS entirely. Only do this behind a proxy that
terminates TLS itself.

---

## What protects what

| Threat | Mitigation |
|--------|------------|
| Network eavesdropping | TLS 1.3 |
| Stolen config file | The file holds no secret; keys come from the environment |
| Stolen warehouse objects | Object-store encryption (SSE-KMS/CMEK) — configured on the bucket |
| Unauthorised column access | Parquet modular encryption — a table-level concern |
| Unauthorised catalog access | [Cedar policies](@/docs/authorization.md) |

Rustberg owns the first two rows. The rest belong to the storage layer and the
table format, and this page is explicit about that rather than implying broader
coverage than exists.

---

## Next steps

- [Authorization](@/docs/authorization.md) — Cedar policies
- [Security](@/docs/security.md) — enforcement boundaries
- [Configuration](@/docs/configuration.md) — TLS settings
