"""
PySpark Integration Tests for Rustberg

These tests validate that Apache Spark can use Rustberg as an Iceberg REST catalog.
This is the most important compatibility test suite - Spark is the most common
Iceberg query engine in production.

Requirements:
    - PySpark 3.5+
    - Iceberg Spark runtime JAR (auto-downloaded by Spark)
    - Rustberg server running

Run with:
    uv run pytest tests/python/pyspark -v -m spark
"""

import pytest
from datetime import date, datetime
from decimal import Decimal


# Mark all tests in this module as Spark tests
pytestmark = [pytest.mark.spark, pytest.mark.slow]


class TestSparkCatalogIntegration:
    """Test Spark catalog integration with Rustberg."""

    def test_spark_session_creation(self, spark_session):
        """Test that Spark session is created successfully with Rustberg catalog."""
        # Verify Spark is running
        assert spark_session is not None
        assert spark_session.sparkContext.appName == "RustbergIntegrationTests"
        
        # Verify Rustberg catalog is configured
        catalogs = spark_session.sql("SHOW CATALOGS").collect()
        catalog_names = [row.catalog for row in catalogs]
        assert "rustberg" in catalog_names

    def test_catalog_config(self, spark_session):
        """Test that catalog configuration is correct."""
        # Use the catalog
        spark_session.sql("USE rustberg")
        
        # Get current catalog
        result = spark_session.sql("SELECT current_catalog()").collect()
        assert result[0][0] == "rustberg"


class TestSparkNamespaceOperations:
    """Test Spark namespace (database) operations."""

    def test_create_namespace(self, spark_session, spark_temp_namespace):
        """Test creating a namespace via Spark."""
        # Namespace is created by the fixture
        # Verify it exists
        namespaces = spark_session.sql("SHOW NAMESPACES IN rustberg").collect()
        namespace_names = [row.namespace for row in namespaces]
        
        # Extract just the namespace name without catalog prefix
        ns_name = spark_temp_namespace.split(".")[-1]
        assert ns_name in namespace_names

    def test_namespace_properties(self, spark_session):
        """Test namespace properties via Spark."""
        import uuid
        ns = f"test_ns_props_{uuid.uuid4().hex[:8]}"
        full_ns = f"rustberg.{ns}"
        
        try:
            # Create namespace with properties
            spark_session.sql(f"""
                CREATE NAMESPACE {full_ns}
                WITH DBPROPERTIES ('owner' = 'spark-test', 'env' = 'test')
            """)
            
            # Verify properties
            props = spark_session.sql(f"DESCRIBE NAMESPACE EXTENDED {full_ns}").collect()
            props_dict = {row.info_name: row.info_value for row in props}
            
            # Check properties are stored
            assert "owner" in str(props_dict) or "spark-test" in str(props_dict)
        finally:
            spark_session.sql(f"DROP NAMESPACE IF EXISTS {full_ns}")


class TestSparkTableOperations:
    """Test Spark table CRUD operations."""

    def test_create_simple_table(self, spark_session, spark_temp_namespace):
        """Test creating a simple Iceberg table via Spark."""
        table_name = f"{spark_temp_namespace}.test_simple"
        
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                name STRING,
                value DOUBLE
            ) USING iceberg
        """)
        
        # Verify table exists
        tables = spark_session.sql(f"SHOW TABLES IN {spark_temp_namespace}").collect()
        table_names = [row.tableName for row in tables]
        assert "test_simple" in table_names

    def test_create_partitioned_table(self, spark_session, spark_temp_namespace):
        """Test creating a partitioned Iceberg table."""
        table_name = f"{spark_temp_namespace}.test_partitioned"
        
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                name STRING,
                created_date DATE,
                region STRING
            ) USING iceberg
            PARTITIONED BY (created_date, region)
        """)
        
        # Verify partition spec
        desc = spark_session.sql(f"DESCRIBE TABLE EXTENDED {table_name}").collect()
        desc_dict = {row.col_name: row.data_type for row in desc if row.col_name}
        
        # Table should have the columns
        assert "id" in desc_dict
        assert "created_date" in desc_dict
        assert "region" in desc_dict

    def test_create_table_with_all_types(self, spark_session, spark_temp_namespace):
        """Test creating a table with various Iceberg data types."""
        table_name = f"{spark_temp_namespace}.test_all_types"
        
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                bool_col BOOLEAN,
                int_col INT,
                long_col BIGINT,
                float_col FLOAT,
                double_col DOUBLE,
                decimal_col DECIMAL(10, 2),
                date_col DATE,
                timestamp_col TIMESTAMP,
                string_col STRING,
                binary_col BINARY
            ) USING iceberg
        """)
        
        # Verify all columns exist
        desc = spark_session.sql(f"DESCRIBE TABLE {table_name}").collect()
        col_names = [row.col_name for row in desc if row.col_name and not row.col_name.startswith("#")]
        
        expected_cols = [
            "bool_col", "int_col", "long_col", "float_col", "double_col",
            "decimal_col", "date_col", "timestamp_col", "string_col", "binary_col"
        ]
        for col in expected_cols:
            assert col in col_names, f"Column {col} not found in table"


class TestSparkDataOperations:
    """Test Spark data read/write operations."""

    def test_insert_and_select(self, spark_session, spark_temp_namespace):
        """Test inserting and selecting data."""
        table_name = f"{spark_temp_namespace}.test_insert"
        
        # Create table
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                name STRING
            ) USING iceberg
        """)
        
        # Insert data
        spark_session.sql(f"""
            INSERT INTO {table_name} VALUES
                (1, 'Alice'),
                (2, 'Bob'),
                (3, 'Charlie')
        """)
        
        # Select and verify
        result = spark_session.sql(f"SELECT * FROM {table_name} ORDER BY id").collect()
        assert len(result) == 3
        assert result[0].id == 1
        assert result[0].name == "Alice"
        assert result[2].id == 3
        assert result[2].name == "Charlie"

    def test_insert_with_dataframe(self, spark_session, spark_temp_namespace):
        """Test inserting data using a DataFrame."""
        table_name = f"{spark_temp_namespace}.test_df_insert"
        
        # Create table
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                value DOUBLE
            ) USING iceberg
        """)
        
        # Create DataFrame and insert
        data = [(1, 1.1), (2, 2.2), (3, 3.3)]
        df = spark_session.createDataFrame(data, ["id", "value"])
        df.writeTo(table_name).append()
        
        # Verify
        result = spark_session.sql(f"SELECT COUNT(*) as cnt FROM {table_name}").collect()
        assert result[0].cnt == 3

    def test_update_data(self, spark_session, spark_temp_namespace):
        """Test updating data in an Iceberg table."""
        table_name = f"{spark_temp_namespace}.test_update"
        
        # Create and populate table
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                status STRING
            ) USING iceberg
        """)
        spark_session.sql(f"""
            INSERT INTO {table_name} VALUES (1, 'active'), (2, 'active'), (3, 'inactive')
        """)
        
        # Update
        spark_session.sql(f"""
            UPDATE {table_name} SET status = 'updated' WHERE id = 1
        """)
        
        # Verify
        result = spark_session.sql(f"""
            SELECT status FROM {table_name} WHERE id = 1
        """).collect()
        assert result[0].status == "updated"

    def test_delete_data(self, spark_session, spark_temp_namespace):
        """Test deleting data from an Iceberg table."""
        table_name = f"{spark_temp_namespace}.test_delete"
        
        # Create and populate
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT,
                name STRING
            ) USING iceberg
        """)
        spark_session.sql(f"""
            INSERT INTO {table_name} VALUES (1, 'keep'), (2, 'delete'), (3, 'keep')
        """)
        
        # Delete
        spark_session.sql(f"DELETE FROM {table_name} WHERE id = 2")
        
        # Verify
        result = spark_session.sql(f"SELECT COUNT(*) as cnt FROM {table_name}").collect()
        assert result[0].cnt == 2
        
        # Verify specific row is gone
        result = spark_session.sql(f"""
            SELECT * FROM {table_name} WHERE id = 2
        """).collect()
        assert len(result) == 0

    def test_merge_into(self, spark_session, spark_temp_namespace):
        """Test MERGE INTO (upsert) operation."""
        target_table = f"{spark_temp_namespace}.test_merge_target"
        
        # Create target table
        spark_session.sql(f"""
            CREATE TABLE {target_table} (
                id BIGINT,
                value INT
            ) USING iceberg
        """)
        spark_session.sql(f"""
            INSERT INTO {target_table} VALUES (1, 100), (2, 200)
        """)
        
        # Create source data
        source_df = spark_session.createDataFrame([
            (1, 111),  # Update existing
            (3, 300),  # Insert new
        ], ["id", "value"])
        source_df.createOrReplaceTempView("source_data")
        
        # Merge
        spark_session.sql(f"""
            MERGE INTO {target_table} t
            USING source_data s
            ON t.id = s.id
            WHEN MATCHED THEN UPDATE SET value = s.value
            WHEN NOT MATCHED THEN INSERT *
        """)
        
        # Verify
        result = spark_session.sql(f"""
            SELECT * FROM {target_table} ORDER BY id
        """).collect()
        
        assert len(result) == 3
        assert result[0].value == 111  # Updated
        assert result[1].value == 200  # Unchanged
        assert result[2].value == 300  # Inserted


class TestSparkTableMetadata:
    """Test Spark table metadata operations."""

    def test_describe_table(self, spark_session, spark_temp_namespace):
        """Test describing table schema."""
        table_name = f"{spark_temp_namespace}.test_describe"
        
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT COMMENT 'Primary key',
                name STRING COMMENT 'User name'
            ) USING iceberg
            COMMENT 'Test table for describe'
        """)
        
        # Describe table
        result = spark_session.sql(f"DESCRIBE TABLE {table_name}").collect()
        col_names = [row.col_name for row in result]
        
        assert "id" in col_names
        assert "name" in col_names

    def test_show_table_properties(self, spark_session, spark_temp_namespace):
        """Test showing table properties."""
        table_name = f"{spark_temp_namespace}.test_properties"
        
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
            TBLPROPERTIES ('custom.prop' = 'test-value')
        """)
        
        # Get properties
        result = spark_session.sql(f"SHOW TBLPROPERTIES {table_name}").collect()
        props = {row.key: row.value for row in result}
        
        # Custom property should be present
        assert "custom.prop" in props or any("test-value" in str(v) for v in props.values())

    def test_alter_table_add_column(self, spark_session, spark_temp_namespace):
        """Test adding a column to a table."""
        table_name = f"{spark_temp_namespace}.test_alter"
        
        # Create table
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
        """)
        
        # Add column
        spark_session.sql(f"""
            ALTER TABLE {table_name} ADD COLUMN name STRING
        """)
        
        # Verify
        result = spark_session.sql(f"DESCRIBE TABLE {table_name}").collect()
        col_names = [row.col_name for row in result]
        
        assert "name" in col_names


class TestSparkTimeTravelAndSnapshots:
    """Test Spark time travel and snapshot features."""

    def test_snapshot_history(self, spark_session, spark_temp_namespace):
        """Test viewing snapshot history."""
        table_name = f"{spark_temp_namespace}.test_snapshots"
        
        # Create table and make multiple commits
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
        """)
        spark_session.sql(f"INSERT INTO {table_name} VALUES (1)")
        spark_session.sql(f"INSERT INTO {table_name} VALUES (2)")
        spark_session.sql(f"INSERT INTO {table_name} VALUES (3)")
        
        # View history
        history = spark_session.sql(f"""
            SELECT * FROM {table_name}.history
        """).collect()
        
        # Should have multiple snapshots (at least 3 inserts)
        assert len(history) >= 3

    def test_snapshots_table(self, spark_session, spark_temp_namespace):
        """Test querying the snapshots metadata table."""
        table_name = f"{spark_temp_namespace}.test_snapshots_meta"
        
        # Create and populate
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
        """)
        spark_session.sql(f"INSERT INTO {table_name} VALUES (1)")
        
        # Query snapshots
        snapshots = spark_session.sql(f"""
            SELECT snapshot_id, committed_at, operation
            FROM {table_name}.snapshots
        """).collect()
        
        assert len(snapshots) >= 1
        # First snapshot should be from an append operation
        assert any(s.operation == "append" for s in snapshots)


class TestSparkTableMaintenance:
    """Test Spark table maintenance operations."""

    def test_expire_snapshots(self, spark_session, spark_temp_namespace):
        """Test expiring old snapshots."""
        table_name = f"{spark_temp_namespace}.test_expire"
        
        # Create table with multiple snapshots
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
        """)
        spark_session.sql(f"INSERT INTO {table_name} VALUES (1)")
        spark_session.sql(f"INSERT INTO {table_name} VALUES (2)")
        
        # Expire snapshots (keep only recent)
        # Note: This may not actually expire anything if all snapshots are recent
        spark_session.sql(f"""
            CALL rustberg.system.expire_snapshots(
                table => '{table_name}',
                retain_last => 1
            )
        """)
        
        # Table should still be queryable
        result = spark_session.sql(f"SELECT COUNT(*) as cnt FROM {table_name}").collect()
        assert result[0].cnt == 2

    def test_rewrite_data_files(self, spark_session, spark_temp_namespace):
        """Test compacting data files."""
        table_name = f"{spark_temp_namespace}.test_rewrite"
        
        # Create table with many small inserts
        spark_session.sql(f"""
            CREATE TABLE {table_name} (
                id BIGINT
            ) USING iceberg
        """)
        
        for i in range(5):
            spark_session.sql(f"INSERT INTO {table_name} VALUES ({i})")
        
        # Compact files
        spark_session.sql(f"""
            CALL rustberg.system.rewrite_data_files(
                table => '{table_name}'
            )
        """)
        
        # Verify data is intact
        result = spark_session.sql(f"SELECT COUNT(*) as cnt FROM {table_name}").collect()
        assert result[0].cnt == 5
