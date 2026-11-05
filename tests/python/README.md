# Client conformance tests

PyIceberg and DuckDB against the built binary, plus a policy-pruning suite that
checks a restricted caller receives only the files its row filter selects. CI
runs them on every change.

```bash
just test-clients        # builds the binary, then runs everything here
```

Or by hand, from the repository root (needs [uv](https://github.com/astral-sh/uv)):

```bash
cargo build --all-features
uv sync
RUSTBERG_BINARY=target/debug/rustberg uv run pytest tests/python -v
uv run pytest tests/python -m duckdb        # one client: pyiceberg | duckdb
uv run pytest tests/python -m "not slow"
```

| Path | Covers |
|---|---|
| `test_pyiceberg/` | config, namespaces, tables, scan planning |
| `test_duckdb/` | attach, scans, time travel, aggregation |
| `test_policy_pruning.py` | `@row_filter` enforced through server-side planning |

| Variable | Default | |
|---|---|---|
| `RUSTBERG_BINARY` | auto-detected | the binary to start |
| `RUSTBERG_HOST`, `RUSTBERG_PORT` | `localhost`, `8181` | where it listens |

Markers: `pyiceberg`, `duckdb`, `integration`, `slow`.
