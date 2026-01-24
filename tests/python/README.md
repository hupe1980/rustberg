# Rustberg Python Integration Tests

This directory contains Python integration tests that validate Rustberg compatibility with popular Iceberg clients:

- **PyIceberg** — Python Iceberg client library
- **PySpark** — Apache Spark's Iceberg integration  
- **DuckDB** — Embedded analytical database with Iceberg extension

## Setup

### Prerequisites

- Python 3.10+
- [uv](https://github.com/astral-sh/uv) (fast Python package manager)
- Rustberg binary (built with `cargo build --all-features`)
- Java 11+ (for PySpark tests only)

### Install Dependencies

From the repository root:

```bash
uv sync
```

## Running Tests

### All Python Tests

```bash
# Build Rustberg first
cargo build --all-features

# Run all Python tests
uv run pytest tests/python -v
```

### PyIceberg Tests Only

```bash
uv run pytest tests/python/test_pyiceberg -v -m pyiceberg
```

### PySpark Tests Only

```bash
uv run pytest tests/python/test_pyspark -v -m spark
```

### DuckDB Tests Only

```bash
uv run pytest tests/python/test_duckdb -v -m duckdb
```

### Skip Slow Tests

```bash
uv run pytest tests/python -v -m "not slow"
```

### Against Running Rustberg Instance

If you have Rustberg already running:

```bash
RUSTBERG_HOST=localhost RUSTBERG_PORT=8181 uv run pytest tests/python -v
```

## Test Organization

```
tests/python/
├── conftest.py            # Shared fixtures (server management, catalog setup)
├── README.md              # This file
├── test_pyiceberg/        # PyIceberg client tests
│   ├── __init__.py
│   ├── conftest.py        # PyIceberg-specific fixtures
│   ├── test_catalog.py    # Config endpoint, health checks
│   ├── test_namespaces.py # Namespace CRUD operations
│   └── test_tables.py     # Table CRUD, schemas, partitions
├── test_pyspark/          # Apache Spark tests
│   ├── __init__.py
│   └── test_spark_integration.py
└── test_duckdb/           # DuckDB tests
    ├── __init__.py
    └── test_duckdb_integration.py
```

## Test Markers

| Marker | Description |
|--------|-------------|
| `pyiceberg` | Tests using PyIceberg client |
| `spark` | Tests requiring PySpark + Java |
| `duckdb` | Tests using DuckDB |
| `slow` | Tests that take longer to run |
| `integration` | All integration tests |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUSTBERG_HOST` | `localhost` | Rustberg server host |
| `RUSTBERG_PORT` | `8181` | Rustberg server port |
| `RUSTBERG_BINARY` | auto-detect | Path to Rustberg binary |

## Client-Specific Requirements

### PySpark

PySpark tests require Java 11+:

**macOS:**
```bash
brew install openjdk@11
export JAVA_HOME=$(/usr/libexec/java_home -v 11)
```

**Ubuntu:**
```bash
sudo apt-get install openjdk-11-jdk
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
```

### DuckDB

DuckDB tests require the Iceberg extension:
- The extension is automatically installed by DuckDB on first use
- No additional setup required

## Coverage

### PyIceberg Tests
- ✅ Config endpoint validation
- ✅ Health/readiness endpoints
- ✅ Namespace CRUD operations
- ✅ Namespace properties
- ✅ Nested/hierarchical namespaces
- ✅ Table creation with various schemas
- ✅ Complex types (struct, list, map)
- ✅ Partition specifications
- ✅ Sort orders
- ✅ Table properties
- ✅ Table loading and listing
- ✅ Table deletion (drop, purge)
- ✅ Error handling (403, 404, 409)

### PySpark Tests
- ✅ Catalog integration
- ✅ Namespace operations
- ✅ Table creation (simple, partitioned, all types)
- ✅ Data insertion and selection
- ✅ DataFrame writes
- ✅ UPDATE operations
- ✅ DELETE operations
- ✅ MERGE INTO (upsert)
- ✅ Schema evolution (ADD COLUMN)
- ✅ Snapshot history
- ✅ Table maintenance (expire_snapshots, rewrite_data_files)

### DuckDB Tests
- ✅ Iceberg extension loading
- ✅ Table metadata scanning
- ✅ Snapshot information
- ✅ Direct table reads (iceberg_scan)
- ✅ Column projection
- ✅ Filter pushdown
- ✅ Decimal types
- ✅ Timestamp types
- ✅ Time travel queries
- ✅ Aggregation queries (COUNT, SUM, AVG, GROUP BY)
- ✅ JOIN operations between Iceberg tables

## CI Integration

These tests run automatically in GitHub Actions:

```yaml
# PyIceberg tests
- name: Run PyIceberg Integration Tests
  run: uv run pytest tests/python/test_pyiceberg -v --tb=short

# PySpark tests (requires Java)
- name: Run PySpark Integration Tests
  run: uv run pytest tests/python/test_pyspark -v --tb=short -m spark

# DuckDB tests
- name: Run DuckDB Integration Tests
  run: uv run pytest tests/python/test_duckdb -v --tb=short -m duckdb
```
