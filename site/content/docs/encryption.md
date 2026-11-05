+++
title = "Encryption"
description = "What Rustberg encrypts, what it deliberately does not, and where table encryption actually belongs."
weight = 6
+++
## Scope

Rustberg encrypts one thing:

| What | How |
|------|-----|
| Everything in transit | TLS 1.2 and 1.3, via rustls |

Everything else is deliberately out of scope — see below.

### Why the catalog does not encrypt table metadata

Catalog-side encryption would protect the wrong layer:

- Engines read table metadata files **directly from object storage**, where they
  are plaintext regardless.
- It would not touch data files.

Lakehouse encryption is a **table-level** concern. The Iceberg answer is
[Parquet modular encryption](https://iceberg.apache.org/spec/): per-column keys
held by a KMS and released to authorised readers, protecting the bytes wherever
they are read.

Use object-store encryption (SSE-S3, SSE-KMS, CMEK) for the warehouse at rest,
and table-level encryption where column secrecy matters.

---

## API keys

Nothing to encrypt: API keys are **configuration**, not stored state. Secrets
live in environment variables (or a mounted secret), are hashed at startup, and
only the hash is kept. See [authentication](@/docs/authentication.md).

## TLS

Rustberg is rustls-only: no OpenSSL or native-tls in the dependency tree, in any
feature combination, so the binary cross-compiles statically. `openssl`,
`openssl-sys` and `native-tls` are on `cargo deny`'s ban list, checked in CI with
`--all-features`.

```toml
[tls]
enabled = true
cert_path = "/etc/rustberg/tls/cert.pem"
key_path = "/etc/rustberg/tls/key.pem"
```

- Omit both paths for a generated self-signed certificate — for development
  only.
- Supplying one path without the other is a startup error.
- `insecure_http = true` disables TLS entirely; use it only behind a proxy that
  terminates TLS.

---

## What protects what

| Threat | Mitigation |
|--------|------------|
| Network eavesdropping | TLS 1.2 and 1.3 |
| Stolen config file | The file holds no secret; keys come from the environment |
| Stolen warehouse objects | Object-store encryption (SSE-KMS/CMEK) — configured on the bucket |
| Unauthorised column access | Parquet modular encryption — a table-level concern |
| Unauthorised catalog access | [Cedar policies](@/docs/authorization.md) |

Rustberg owns the first two rows; the rest belong to the storage layer and the
table format.

---

## Next steps

- [Authorization](@/docs/authorization.md) — Cedar policies
- [Security](@/docs/security.md) — enforcement boundaries
- [Configuration](@/docs/configuration.md) — TLS settings
