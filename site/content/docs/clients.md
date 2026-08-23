+++
title = "Clients and engines"
description = "Connecting PyIceberg, Spark, Trino, Flink and DuckDB to Rustberg, with working configuration."
weight = 12
+++
> Use the **`token`** property, not `credential`. `credential` makes the client
> perform an OAuth2 client-credentials exchange against `/v1/oauth/tokens`, which
> Rustberg does not implement — the request fails with `401` before any catalog
> call. An API key is a bearer token: pass it as `token`.


## Apache Spark

### PySpark with PyIceberg Catalog

```python
from pyspark.sql import SparkSession

spark = SparkSession.builder \
    .appName("RustbergExample") \
    .config("spark.jars.packages", 
            "org.apache.iceberg:iceberg-spark-runtime-3.5_2.12:1.5.0") \
    .config("spark.sql.extensions", 
            "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions") \
    .config("spark.sql.catalog.rustberg", 
            "org.apache.iceberg.spark.SparkCatalog") \
    .config("spark.sql.catalog.rustberg.type", "rest") \
    .config("spark.sql.catalog.rustberg.uri", "https://rustberg.example.com") \
    .config("spark.sql.catalog.rustberg.token", "rb_...") \
    .config("spark.sql.catalog.rustberg.warehouse", "s3://my-warehouse/") \
    .config("spark.sql.catalog.rustberg.io-impl", 
            "org.apache.iceberg.aws.s3.S3FileIO") \
    .config("spark.sql.defaultCatalog", "rustberg") \
    .getOrCreate()

# Create a namespace
spark.sql("CREATE NAMESPACE IF NOT EXISTS analytics")

# Create a table
spark.sql("""
    CREATE TABLE analytics.events (
        event_id STRING,
        event_type STRING,
        user_id STRING,
        timestamp TIMESTAMP,
        properties MAP<STRING, STRING>
    )
    USING iceberg
    PARTITIONED BY (days(timestamp))
""")

# Insert data
spark.sql("""
    INSERT INTO analytics.events VALUES
    ('evt-001', 'page_view', 'user-123', current_timestamp(), map('page', '/home')),
    ('evt-002', 'click', 'user-456', current_timestamp(), map('button', 'signup'))
""")

# Query data
df = spark.sql("SELECT * FROM analytics.events WHERE event_type = 'click'")
df.show()

# Time travel
spark.sql("SELECT * FROM analytics.events VERSION AS OF 1").show()
```

### Spark: `CREATE TABLE AS SELECT`

CTAS and `REPLACE TABLE AS SELECT` work, and they are atomic:

```python
spark.sql("""
    CREATE TABLE rustberg.analytics.summary
    USING iceberg
    AS SELECT CAST(ts AS DATE) AS day, count(*) AS events
    FROM rustberg.analytics.events
    GROUP BY 1
""")
```

Spark performs this as a *staged* create — it asks the catalog to initialise
metadata without creating the table, writes the data files, then commits both
together with an `assert-create` requirement. Rustberg implements that flow, so
the table appears only once its data is there: there is no window in which it
exists and is empty, and a failed job leaves nothing behind.

If the name is taken between the stage and the commit, the commit fails with
`409` rather than clobbering the existing table — the same conflict any
concurrent writer would get.

This works the same behind multiple replicas: the staging note lives in
Postgres, not in one process's memory, so the commit may land on a different pod
than the stage. See [staged creation](@/docs/api.md#staged-creation-create-table-as-select).

### Scala Spark

```scala
import org.apache.spark.sql.SparkSession

val spark = SparkSession.builder()
  .appName("RustbergScala")
  .config("spark.sql.catalog.rustberg", "org.apache.iceberg.spark.SparkCatalog")
  .config("spark.sql.catalog.rustberg.type", "rest")
  .config("spark.sql.catalog.rustberg.uri", "https://rustberg.example.com")
  .config("spark.sql.catalog.rustberg.token", sys.env("RUSTBERG_API_KEY"))
  .config("spark.sql.catalog.rustberg.warehouse", "s3://my-warehouse/")
  .config("spark.sql.extensions", 
          "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
  .getOrCreate()

// Use SQL
spark.sql("SELECT * FROM rustberg.analytics.events").show()

// Use DataFrame API
import org.apache.iceberg.spark.Spark3Util

val table = Spark3Util.loadIcebergTable(spark, "rustberg.analytics.events")
val snapshots = table.snapshots()
```

---

## Trino

### Connector Configuration

```properties
# /etc/trino/catalog/rustberg.properties
connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=https://rustberg.example.com
iceberg.rest-catalog.security=OAUTH2
iceberg.rest-catalog.oauth2.token=your-api-key

# S3 configuration
hive.s3.aws-access-key=${ENV:AWS_ACCESS_KEY_ID}
hive.s3.aws-secret-key=${ENV:AWS_SECRET_ACCESS_KEY}
hive.s3.region=us-east-1
```

### SQL Examples

```sql
-- Show catalogs
SHOW CATALOGS;

-- List schemas
SHOW SCHEMAS FROM rustberg;

-- Create schema
CREATE SCHEMA IF NOT EXISTS rustberg.analytics;

-- Create table
CREATE TABLE rustberg.analytics.page_views (
    view_id VARCHAR,
    page_url VARCHAR,
    user_id VARCHAR,
    view_time TIMESTAMP(6) WITH TIME ZONE,
    duration_seconds INTEGER
)
WITH (
    format = 'PARQUET',
    partitioning = ARRAY['day(view_time)']
);

-- Insert data
INSERT INTO rustberg.analytics.page_views
SELECT 
    uuid() as view_id,
    '/products/' || CAST(n AS VARCHAR) as page_url,
    'user-' || CAST(n % 1000 AS VARCHAR) as user_id,
    current_timestamp as view_time,
    (random() * 300)::INTEGER as duration_seconds
FROM UNNEST(sequence(1, 10000)) AS t(n);

-- Query with partition pruning
SELECT user_id, COUNT(*) as views
FROM rustberg.analytics.page_views
WHERE view_time >= TIMESTAMP '2024-01-01 00:00:00'
GROUP BY user_id
ORDER BY views DESC
LIMIT 10;

-- Time travel query
SELECT * FROM rustberg.analytics.page_views FOR VERSION AS OF 1234567890123;

-- Show table history
SELECT * FROM "rustberg.analytics.page_views$snapshots";

-- Rollback to previous snapshot
CALL rustberg.system.rollback_to_snapshot('analytics', 'page_views', 1234567890123);
```

---

## Apache Flink

### Flink SQL

```sql
-- Create Iceberg catalog
CREATE CATALOG rustberg WITH (
    'type' = 'iceberg',
    'catalog-type' = 'rest',
    'uri' = 'https://rustberg.example.com',
    'credential' = 'your-api-key',
    'warehouse' = 's3://my-warehouse/',
    'io-impl' = 'org.apache.iceberg.aws.s3.S3FileIO'
);

USE CATALOG rustberg;
USE analytics;

-- Create streaming table
CREATE TABLE clicks (
    click_id STRING,
    user_id STRING,
    click_time TIMESTAMP(3),
    url STRING,
    WATERMARK FOR click_time AS click_time - INTERVAL '5' SECOND
) WITH (
    'format-version' = '2',
    'write.upsert.enabled' = 'true'
);

-- Streaming insert from Kafka
INSERT INTO clicks
SELECT 
    click_id,
    user_id,
    click_time,
    url
FROM kafka_source;
```

### Flink Java API

```java
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.table.api.bridge.java.StreamTableEnvironment;
import org.apache.iceberg.flink.FlinkCatalogFactory;

public class FlinkIcebergExample {
    public static void main(String[] args) {
        StreamExecutionEnvironment env = 
            StreamExecutionEnvironment.getExecutionEnvironment();
        StreamTableEnvironment tableEnv = 
            StreamTableEnvironment.create(env);
        
        // Register Rustberg catalog
        tableEnv.executeSql("""
            CREATE CATALOG rustberg WITH (
                'type' = 'iceberg',
                'catalog-type' = 'rest',
                'uri' = 'https://rustberg.example.com',
                'credential' = '%s'
            )
        """.formatted(System.getenv("RUSTBERG_API_KEY")));
        
        tableEnv.useCatalog("rustberg");
        
        // Execute queries
        tableEnv.executeSql("SELECT * FROM analytics.events").print();
    }
}
```

---

## PyIceberg

### Basic Usage

```python
from pyiceberg.catalog import load_catalog
from pyiceberg.schema import Schema
from pyiceberg.types import (
    NestedField, StringType, TimestampType, 
    LongType, MapType
)

# Connect to Rustberg
catalog = load_catalog(
    "rustberg",
    **{
        "uri": "https://rustberg.example.com",
        "token": "rb_...",
        "warehouse": "s3://my-warehouse/",
        "s3.access-key-id": "your-access-key",
        "s3.secret-access-key": "your-secret-key",
        "s3.region": "us-east-1",
    }
)

# List namespaces
for ns in catalog.list_namespaces():
    print(f"Namespace: {ns}")

# Create namespace
catalog.create_namespace("analytics", {"owner": "data-team"})

# Define schema
schema = Schema(
    NestedField(1, "event_id", StringType(), required=True),
    NestedField(2, "event_type", StringType(), required=True),
    NestedField(3, "user_id", StringType(), required=False),
    NestedField(4, "timestamp", TimestampType(), required=True),
    NestedField(5, "properties", MapType(6, StringType(), 7, StringType())),
)

# Create table
from pyiceberg.partitioning import PartitionSpec, PartitionField
from pyiceberg.transforms import DayTransform

partition_spec = PartitionSpec(
    PartitionField(
        source_id=4, 
        field_id=1000, 
        transform=DayTransform(), 
        name="day"
    )
)

table = catalog.create_table(
    identifier="analytics.events",
    schema=schema,
    partition_spec=partition_spec,
)

print(f"Created table: {table.identifier}")
```

### Reading and Writing with Arrow

```python
import pyarrow as pa
from pyiceberg.catalog import load_catalog

catalog = load_catalog("rustberg", uri="https://rustberg.example.com")
table = catalog.load_table("analytics.events")

# Read as Arrow table
arrow_table = table.scan().to_arrow()
print(arrow_table.to_pandas())

# Read with filters
filtered = table.scan(
    row_filter="event_type = 'click' AND timestamp > '2024-01-01'"
).to_arrow()

# Write Arrow data
new_data = pa.table({
    "event_id": ["evt-100", "evt-101"],
    "event_type": ["purchase", "refund"],
    "user_id": ["user-789", "user-789"],
    "timestamp": [
        pa.scalar("2024-01-15T10:30:00").cast(pa.timestamp("us")),
        pa.scalar("2024-01-15T11:00:00").cast(pa.timestamp("us")),
    ],
    "properties": [{"amount": "99.99"}, {"reason": "defective"}],
})

table.append(new_data)
```

### Schema Evolution

```python
from pyiceberg.catalog import load_catalog

catalog = load_catalog("rustberg", uri="https://rustberg.example.com")
table = catalog.load_table("analytics.events")

# Add a new column
with table.update_schema() as update:
    update.add_column("session_id", StringType())

# Rename a column
with table.update_schema() as update:
    update.rename_column("properties", "metadata")

# Make column optional
with table.update_schema() as update:
    update.make_column_optional("user_id")
```

---

## DuckDB

### Direct Connection

```python
import duckdb

# Install and load Iceberg extension
duckdb.sql("INSTALL iceberg; LOAD iceberg;")

# Attach Rustberg catalog
duckdb.sql("""
    ATTACH 'https://rustberg.example.com' AS rustberg (
        TYPE ICEBERG,
        CREDENTIAL 'your-api-key'
    )
""")

# Query tables
result = duckdb.sql("""
    SELECT event_type, COUNT(*) as count
    FROM rustberg.analytics.events
    GROUP BY event_type
    ORDER BY count DESC
""").fetchall()

print(result)
```

### With PyIceberg

```python
import duckdb
from pyiceberg.catalog import load_catalog

# Load table via PyIceberg
catalog = load_catalog("rustberg", uri="https://rustberg.example.com")
table = catalog.load_table("analytics.events")

# Convert to Arrow and query with DuckDB
arrow_table = table.scan().to_arrow()

result = duckdb.sql("""
    SELECT 
        DATE_TRUNC('hour', timestamp) as hour,
        COUNT(*) as events
    FROM arrow_table
    GROUP BY 1
    ORDER BY 1
""").fetchdf()

print(result)
```

---

## Polars

```python
import polars as pl
from pyiceberg.catalog import load_catalog

catalog = load_catalog("rustberg", uri="https://rustberg.example.com")
table = catalog.load_table("analytics.events")

# Scan to Polars DataFrame
arrow_table = table.scan(
    selected_fields=["event_id", "event_type", "timestamp"]
).to_arrow()

df = pl.from_arrow(arrow_table)

# Polars operations
result = (
    df
    .with_columns(pl.col("timestamp").dt.date().alias("date"))
    .group_by("date", "event_type")
    .agg(pl.count().alias("count"))
    .sort("date", "count", descending=[False, True])
)

print(result)
```

---

## AWS SDK Integration

### boto3 for S3 FileIO

```python
import boto3
from pyiceberg.catalog import load_catalog
from pyiceberg.io.pyarrow import PyArrowFileIO

# Configure AWS session
session = boto3.Session(
    aws_access_key_id="your-access-key",
    aws_secret_access_key="your-secret-key",
    region_name="us-east-1"
)

# Use with PyIceberg
catalog = load_catalog(
    "rustberg",
    uri="https://rustberg.example.com",
    credential="your-api-key",
    **{
        "s3.access-key-id": session.get_credentials().access_key,
        "s3.secret-access-key": session.get_credentials().secret_key,
        "s3.region": "us-east-1",
    }
)

table = catalog.load_table("analytics.events")
```

### Assume Role for Cross-Account Access

```python
import boto3
from pyiceberg.catalog import load_catalog

# Assume role in target account
sts = boto3.client('sts')
response = sts.assume_role(
    RoleArn="arn:aws:iam::123456789012:role/IcebergDataAccess",
    RoleSessionName="rustberg-session"
)

creds = response['Credentials']

catalog = load_catalog(
    "rustberg",
    uri="https://rustberg.example.com",
    credential="your-api-key",
    **{
        "s3.access-key-id": creds['AccessKeyId'],
        "s3.secret-access-key": creds['SecretAccessKey'],
        "s3.session-token": creds['SessionToken'],
        "s3.region": "us-east-1",
    }
)
```

---

## REST API Direct Usage

### curl Examples

```bash
# Set API key
export API_KEY="your-api-key"
export RUSTBERG_URL="https://rustberg.example.com"

# List namespaces
curl -s -H "Authorization: Bearer $API_KEY" \
    "$RUSTBERG_URL/v1/namespaces" | jq

# Get namespace
curl -s -H "Authorization: Bearer $API_KEY" \
    "$RUSTBERG_URL/v1/namespaces/analytics" | jq

# Create namespace
curl -s -X POST \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"namespace": ["analytics"], "properties": {"owner": "data-team"}}' \
    "$RUSTBERG_URL/v1/namespaces" | jq

# List tables
curl -s -H "Authorization: Bearer $API_KEY" \
    "$RUSTBERG_URL/v1/namespaces/analytics/tables" | jq

# Load table
curl -s -H "Authorization: Bearer $API_KEY" \
    "$RUSTBERG_URL/v1/namespaces/analytics/tables/events" | jq

# Get config
curl -s -H "Authorization: Bearer $API_KEY" \
    "$RUSTBERG_URL/v1/config" | jq
```

### Python requests

```python
import requests

class RustbergClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers["Authorization"] = f"Bearer {api_key}"
        self.session.headers["Content-Type"] = "application/json"
    
    def list_namespaces(self) -> list:
        resp = self.session.get(f"{self.base_url}/v1/namespaces")
        resp.raise_for_status()
        return resp.json()["namespaces"]
    
    def create_namespace(self, namespace: str, properties: dict = None):
        data = {
            "namespace": namespace.split("."),
            "properties": properties or {}
        }
        resp = self.session.post(f"{self.base_url}/v1/namespaces", json=data)
        resp.raise_for_status()
        return resp.json()
    
    def load_table(self, namespace: str, table: str) -> dict:
        resp = self.session.get(
            f"{self.base_url}/v1/namespaces/{namespace}/tables/{table}"
        )
        resp.raise_for_status()
        return resp.json()

# Usage
client = RustbergClient("https://rustberg.example.com", "your-api-key")
namespaces = client.list_namespaces()
print(namespaces)
```

---

## Jupyter Notebook Example

```python
# Cell 1: Setup
%pip install pyiceberg[s3] pyarrow pandas matplotlib

from pyiceberg.catalog import load_catalog
import pandas as pd
import matplotlib.pyplot as plt

catalog = load_catalog("rustberg", uri="https://localhost:8000")

# Cell 2: Explore data
table = catalog.load_table("analytics.events")

# Show schema
print("Schema:")
print(table.schema())

# Show partitioning
print("\nPartition Spec:")
print(table.spec())

# Cell 3: Query data
df = table.scan(
    row_filter="timestamp >= '2024-01-01'"
).to_arrow().to_pandas()

print(f"Loaded {len(df)} rows")
df.head(10)

# Cell 4: Visualize
event_counts = df.groupby('event_type').size()
event_counts.plot(kind='bar', title='Events by Type')
plt.tight_layout()
plt.show()

# Cell 5: Time series analysis
df['date'] = pd.to_datetime(df['timestamp']).dt.date
daily_counts = df.groupby('date').size()
daily_counts.plot(kind='line', title='Daily Event Volume')
plt.tight_layout()
plt.show()
```

---

## Error Handling Best Practices

```python
from pyiceberg.catalog import load_catalog
from pyiceberg.exceptions import (
    NoSuchTableError,
    NoSuchNamespaceError,
    TableAlreadyExistsError,
    CommitFailedException,
)
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def safe_load_table(catalog, table_id: str):
    """Load table with proper error handling."""
    try:
        return catalog.load_table(table_id)
    except NoSuchTableError:
        logger.warning(f"Table {table_id} does not exist")
        return None
    except NoSuchNamespaceError:
        logger.error(f"Namespace for {table_id} does not exist")
        raise
    except Exception as e:
        logger.error(f"Unexpected error loading {table_id}: {e}")
        raise

def safe_append(table, data, retries: int = 3):
    """Append data with retry logic for conflicts."""
    for attempt in range(retries):
        try:
            table.append(data)
            return True
        except CommitFailedException as e:
            logger.warning(f"Commit conflict (attempt {attempt + 1}): {e}")
            if attempt == retries - 1:
                raise
            # Refresh table metadata and retry
            table.refresh()
    return False
```

---

## Configuration Reference

### Common PyIceberg Configuration

```python
catalog_config = {
    # Catalog connection
    "uri": "https://rustberg.example.com",
    "token": "rb_...",
    "warehouse": "s3://my-warehouse/",
    
    # S3 configuration
    "s3.access-key-id": "...",
    "s3.secret-access-key": "...",
    "s3.region": "us-east-1",
    "s3.endpoint": "https://s3.us-east-1.amazonaws.com",
    
    # GCS configuration (alternative)
    # "gcs.project-id": "my-project",
    # "gcs.oauth2.token": "...",
    
    # Azure configuration (alternative)
    # "adls.account-name": "mystorageaccount",
    # "adls.account-key": "...",
    
    # Performance tuning
    "rest.retries": "3",
    "rest.retry-delay-ms": "1000",
    "rest.timeout-ms": "30000",
}

catalog = load_catalog("rustberg", **catalog_config)
```

### Spark Configuration Reference

```python
spark_config = {
    # Catalog
    "spark.sql.catalog.rustberg": "org.apache.iceberg.spark.SparkCatalog",
    "spark.sql.catalog.rustberg.type": "rest",
    "spark.sql.catalog.rustberg.uri": "https://rustberg.example.com",
    "spark.sql.catalog.rustberg.token": "rb_...",
    "spark.sql.catalog.rustberg.warehouse": "s3://my-warehouse/",
    
    # S3 configuration
    "spark.sql.catalog.rustberg.io-impl": "org.apache.iceberg.aws.s3.S3FileIO",
    "spark.hadoop.fs.s3a.access.key": "...",
    "spark.hadoop.fs.s3a.secret.key": "...",
    "spark.hadoop.fs.s3a.endpoint": "s3.us-east-1.amazonaws.com",
    
    # Performance
    "spark.sql.catalog.rustberg.cache-enabled": "true",
    "spark.sql.catalog.rustberg.cache.expiration-interval-ms": "60000",
}
```
