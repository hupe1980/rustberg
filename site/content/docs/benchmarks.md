+++
title = "Performance"
description = "What Rustberg's performance actually is, how it is measured, and which claims are gated in CI."
weight = 15
+++
## What this page is

Every number is either reproducible with the shipped binary or labelled as an
unmeasured target. Nothing is extrapolated from an instance type.

---

## Measured

### The `bench` subcommand

```bash
rustberg bench --iterations 1000
```

It measures Rustberg's own work, not the storage backend's. Verifying an API
key on each request is one SHA-256 of the presented key and a constant-time
compare.

> A password KDF would cost ~20–40 ms per request. API keys are 32 bytes from the
> OS CSPRNG, so a work factor protects nothing. See
> [authentication](@/docs/authentication.md#why-not-a-password-kdf).

### Request latency

`rustberg bench --iterations 200`, release build with `--all-features`, redb
catalog on local disk: **Rustberg 0.4.0, Apple M4 Pro (14 core), macOS 26.6.2,
rustc 1.99.1, 2026-11-05**. One machine, one day: read as an order of magnitude.
Targets are design goals; measurements are asserted on every pull request
against looser ceilings ([Gated in CI](#gated-in-ci)).

| | p50 | p99 | Target |
|---|---|---|---|
| **Authorization** (one Cedar decision) | 23.5 µs | **32.9 µs** | < 1 ms |
| **`loadTable`** (full HTTP stack) | 315 µs | **420 µs** | < 5 ms |
| Policy compile + validate (startup) | 694 µs | 875 µs | — |
| Cold start (build → first answer) | 31.0 ms | **37.1 ms** | < 100 ms |

Authorization runs on every request, so a regression there costs everything.

A `304` is answered from the metadata *pointer* without fetching the metadata
document. On a warm local disk the saving is small; against object storage it
skips a network round trip
([conditional loading](@/docs/api.md#conditional-loading)).

### Startup and footprint

| | Value |
|---|---|
| Cold start (exec → accepting connections) | ~30 ms |
| Idle RSS | **15.7 MB** idle on macOS (`ps` against a `--dev` server); gated at < 50 MB on Linux in CI |
| Binary (`--all-features`, stripped) | ~24 MB |

Reproduce with:

```bash
time rustberg --dev --no-auth --insecure-http --catalog-url file:///tmp/rb --port 8000
ps -o rss= -p "$(pgrep -n rustberg)"
```

> Release builds carry every optional feature: Postgres, all three object stores,
> AWS and GCP credential vending, TLS. A `--no-default-features` build with one
> storage backend is considerably smaller.

### Reproducing the latency table

```bash
cargo test --release --all-features --test performance_tests -- --ignored --nocapture
```

The harness lives in `observability::perf`, so `rustberg bench` and the CI gate
measure the same code path.

### Gated in CI

Pass/fail on every pull request:

- PyIceberg, DuckDB and Trino conformance suites against the built binary
- Concurrent-commit tests asserting zero lost updates, on both catalog backends,
  including two replicas committing to one table over a real Postgres
- The latency table above, against regression ceilings
- Linux (gnu + musl, x86-64 and aarch64) and macOS builds and test runs
- Every optional Cargo feature compiled on its own, not only all together
- The declared MSRV, against that toolchain
- `cargo deny` over advisories, licences, bans and sources

CI ceilings are deliberately much looser than the targets, because runners are
noisy. They catch order-of-magnitude regressions.

---

## Not measured

No benchmark asserts these:

| | Why not |
|---|---|
| **Commit p99** | Dominated by the object store writing the metadata file; it would mostly measure your S3. |
| **`loadTable` when federated** | Target < 1.2× the mounted catalog's own latency; needs a remote catalog of known latency, which a unit-test harness cannot supply. |
| **Throughput under concurrency** | Depends on your hardware, catalog backend and object store more than on Rustberg. See [load testing](#load-testing). |

---

## What determines your latency

A catalog request spends its time in:

1. **Object storage.** `loadTable` reads a metadata JSON file; a commit writes
   one. On S3 that round trip is single-digit to tens of milliseconds, one to two
   orders of magnitude above Rustberg's work. Deploy in the bucket's region.
2. **The catalog registry.** redb: a local B-tree read, microseconds. Postgres: a
   network round trip.
3. **Rustberg itself.** Authentication (~0.5 µs), Cedar evaluation, JSON
   serialisation.

Catalog tuning is mostly *storage* tuning.

### Backend choice

| | redb | Postgres |
|---|---|---|
| Registry read | local, microseconds | network round trip |
| Replicas | exactly 1 | many |
| Operational surface | one file | a database to run |

redb is faster per operation; Postgres allows more than one replica. See
[storage](@/docs/storage.md).

---

## Load testing

Measure your own deployment, e.g. with [k6](https://k6.io):

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

Use a warehouse on your production storage; a local filesystem warehouse
measures your disk.

---

## Next steps

- [Storage](@/docs/storage.md) — backend choice and deployment shape
- [Kubernetes](@/docs/kubernetes.md) — running it in a cluster
- [Architecture](@/docs/architecture.md) — where the time goes
