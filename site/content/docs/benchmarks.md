+++
title = "Performance"
description = "What Rustberg's performance actually is, how it is measured, and which claims are gated in CI."
weight = 14
+++
## What this page is

Every number here is either reproducible with the shipped binary, or explicitly
labelled as an unmeasured target. Nothing is extrapolated from an instance type.

---

## Measured

### The `benchmark` subcommand

```bash
rustberg bench --iterations 1000
```

It covers the parts of a request that are Rustberg's own work rather than the
storage backend's. On an Apple M-series laptop, release build:

| | Average |
|---|---|
| API key generation (CSPRNG + SHA-256) | ~4 µs |
| **API key verification** (per request) | **~0.55 µs** |
| TOML config parse (startup only) | ~8 µs |

Key verification is the number that matters, because it happens on every
API-key-authenticated request.

> A password KDF here would cost ~20–40 ms per request instead. Its work factor
> defends a low-entropy secret; a Rustberg API key is 32 bytes from the OS
> CSPRNG, so there is no search space to slow down — the cost would fall entirely
> on the server, including the dummy verification run for requests carrying no
> valid key. See [authentication](@/docs/authentication.md#why-not-a-password-kdf).

### Request latency

Release build, `--all-features`, Apple M-series, redb catalog on local disk. The
targets are design goals; the measurements next to them are asserted on every
pull request against looser ceilings — see [Gated in CI](#gated-in-ci).

| | p50 | p99 | Target |
|---|---|---|---|
| **Authorization** (one Cedar decision) | 24 µs | **31 µs** | < 1 ms |
| **`loadTable`** (full HTTP stack) | 285 µs | **370 µs** | < 5 ms |
| `loadTable` answering `304` | 265 µs | 321 µs | — |
| Policy compile + validate (startup) | 525 µs | 704 µs | — |
| Cold start (build → first answer) | 30 ms | **45 ms** | < 100 ms |

Authorization is the number with the most leverage: it runs on every request, so
a regression there is paid by everything.

A `304` is cheaper than a `200` because it is answered from the catalog's
metadata *pointer* and never fetches the metadata document. On a local disk with
a warm page cache that saving is small; against object storage the document is a
network round trip, and skipping it is the point of
[conditional loading](@/docs/api.md#conditional-loading).

### Startup and footprint

| | Value |
|---|---|
| Cold start (exec → accepting connections) | ~30 ms |
| Idle RSS | gated at < 50 MB, measured on Linux in CI |
| Binary (`--all-features`, stripped) | ~24 MB |

Reproduce with:

```bash
time rustberg --dev --no-auth --insecure-http --catalog-url file:///tmp/rb --port 8000
ps -o rss= -p "$(pgrep -n rustberg)"
```

> The binary carries every optional feature — Postgres, all three object stores,
> AWS and GCP credential vending, TLS — because that is what release builds ship.
> A build with `--no-default-features` is considerably smaller, and a deployment
> that needs only one storage backend can cut most of the difference.

### Reproducing the latency table

```bash
cargo test --release --all-features --test performance_tests -- --ignored --nocapture
```

The harness lives in `observability::perf` rather than in the test, so
`rustberg bench` and the CI gate measure the same thing — two implementations
would drift, and the one an operator runs would stop matching the one that fails
the build.

### Gated in CI

These are pass/fail on every pull request, which is a stronger claim than a
number on a page:

- PyIceberg, DuckDB and Trino conformance suites against the built binary
- Concurrent-commit tests asserting zero lost updates, on both catalog backends,
  including two replicas committing to one table over a real Postgres
- The latency table above, against regression ceilings
- Linux (gnu + musl, x86-64 and aarch64), macOS and Windows builds and test runs
- Every optional Cargo feature compiled on its own, not only all together
- The declared MSRV, against that toolchain
- `cargo deny` over advisories, licences, bans and sources

The ceilings that fail the build are deliberately much looser than the targets.
CI runners are shared and noisy, and a gate that flakes gets disabled — at which
point it protects nothing. These catch order-of-magnitude regressions, which is
what work added to a hot path actually looks like.

---

## Not measured

These have no benchmark asserting them, and are listed separately so the
distinction stays visible:

| | Why not |
|---|---|
| **Commit p99** | Dominated by the object store writing the metadata file, not by the catalog. A number here would mostly measure your S3. |
| **`loadTable` when federated** | The target is < 1.2× the mounted catalog's own latency, which needs a remote catalog of known latency to compare against. A unit-test harness cannot supply one. |
| **Throughput under concurrency** | Depends on your hardware, your catalog backend and your object store far more than on Rustberg. Measure it where it will run — see [load testing](#load-testing). |

---

## What determines your latency

For a catalog request, the time goes to three places:

1. **Object storage.** `loadTable` reads a metadata JSON file; a commit writes
   one. On S3 that is a single-digit-to-tens-of-milliseconds round trip, and it
   dominates everything Rustberg does by one to two orders of magnitude. Deploy
   in the same region as the bucket.
2. **The catalog registry.** With redb, a local B-tree read — microseconds. With
   Postgres, a network round trip to the database.
3. **Rustberg itself.** Authentication (~0.5 µs), Cedar evaluation, JSON
   serialisation.

The practical consequence is that catalog tuning is mostly *storage* tuning.
Moving Rustberg closer to the bucket helps far more than anything on this page.

### Backend choice

| | redb | Postgres |
|---|---|---|
| Registry read | local, microseconds | network round trip |
| Replicas | exactly 1 | many |
| Operational surface | one file | a database to run |

redb is faster per operation; Postgres is what lets you run more than one
replica. See [storage](@/docs/storage.md).

---

## Load testing

The honest way to get numbers for your deployment. With
[k6](https://k6.io):

```javascript
// load-test.js
import http from 'k6/http';
import { check } from 'k6';

export const options = {
    vus: 50,
    duration: '2m',
    thresholds: {
        http_req_duration: ['p(95)<100', 'p(99)<200'],
        http_req_failed: ['rate<0.01'],
    },
};

const BASE = __ENV.BASE_URL;
const KEY = __ENV.API_KEY;

export default function () {
    const res = http.get(`${BASE}/v1/namespaces/analytics/tables/events`, {
        headers: { Authorization: `Bearer ${KEY}` },
    });
    check(res, { 'status is 200': (r) => r.status === 200 });
}
```

```bash
BASE_URL=https://rustberg.example.com API_KEY=$KEY k6 run load-test.js
```

Point it at a warehouse on the storage you actually use. A run against a local
filesystem warehouse measures your disk, not your production latency.

---

## Next steps

- [Storage](@/docs/storage.md) — backend choice and deployment shape
- [Kubernetes](@/docs/kubernetes.md) — running it in a cluster
- [Architecture](@/docs/architecture.md) — where the time goes
