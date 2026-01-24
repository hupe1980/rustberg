"""
PyIceberg Table Integration Tests

Tests table operations using PyIceberg client against Rustberg.
"""

import pytest
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.schema import Schema
from pyiceberg.types import (
    IntegerType,
    LongType,
    StringType,
    TimestampType,
    DoubleType,
    BooleanType,
    FloatType,
    NestedField,
    StructType,
    ListType,
    MapType,
)
from pyiceberg.partitioning import PartitionSpec, PartitionField
from pyiceberg.transforms import DayTransform, IdentityTransform, BucketTransform, TruncateTransform
from pyiceberg.table.sorting import SortOrder, SortField
from pyiceberg.exceptions import (
    NoSuchTableError,
    NoSuchNamespaceError,
    TableAlreadyExistsError,
)


class TestTableCreation:
    """Test table creation operations."""

    def test_create_simple_table(self, catalog: RestCatalog, temp_namespace: str, sample_schema: Schema):
        """Test creating a simple table with a basic schema."""
        table_name = f"{temp_namespace}.simple_table"
        
        table = catalog.create_table(
            identifier=table_name,
            schema=sample_schema,
        )
        
        assert table is not None
        assert table.name() == ("simple_table",) or str(table.identifier) == table_name
        
        # Verify table exists
        tables = catalog.list_tables(temp_namespace)
        assert any("simple_table" in str(t) for t in tables)

    def test_create_table_with_partition_spec(
        self, 
        catalog: RestCatalog, 
        temp_namespace: str, 
        sample_schema: Schema,
        sample_partition_spec: PartitionSpec,
    ):
        """Test creating a table with a partition specification."""
        table_name = f"{temp_namespace}.partitioned_table"
        
        table = catalog.create_table(
            identifier=table_name,
            schema=sample_schema,
            partition_spec=sample_partition_spec,
        )
        
        assert table is not None
        # Verify partition spec
        spec = table.spec()
        assert spec is not None

    def test_create_table_with_sort_order(
        self,
        catalog: RestCatalog,
        temp_namespace: str,
        sample_schema: Schema,
        sample_sort_order: SortOrder,
    ):
        """Test creating a table with a sort order."""
        table_name = f"{temp_namespace}.sorted_table"
        
        table = catalog.create_table(
            identifier=table_name,
            schema=sample_schema,
            sort_order=sample_sort_order,
        )
        
        assert table is not None
        # Verify sort order
        order = table.sort_order()
        assert order is not None

    def test_create_table_with_properties(
        self,
        catalog: RestCatalog,
        temp_namespace: str,
        sample_schema: Schema,
    ):
        """Test creating a table with custom properties."""
        table_name = f"{temp_namespace}.props_table"
        properties = {
            "write.format.default": "parquet",
            "commit.retry.num-retries": "5",
            "custom.property": "custom-value",
        }
        
        table = catalog.create_table(
            identifier=table_name,
            schema=sample_schema,
            properties=properties,
        )
        
        assert table is not None
        # Verify properties
        table_props = table.properties
        assert table_props.get("custom.property") == "custom-value"

    def test_create_table_in_nonexistent_namespace(
        self,
        catalog: RestCatalog,
        sample_schema: Schema,
    ):
        """Test that creating a table in a nonexistent namespace fails."""
        with pytest.raises((NoSuchNamespaceError, Exception)):
            catalog.create_table(
                identifier="nonexistent_ns_12345.my_table",
                schema=sample_schema,
            )

    def test_create_duplicate_table(
        self,
        catalog: RestCatalog,
        temp_namespace: str,
        sample_schema: Schema,
    ):
        """Test that creating a duplicate table fails."""
        table_name = f"{temp_namespace}.dup_table"
        
        # Create first table
        catalog.create_table(
            identifier=table_name,
            schema=sample_schema,
        )
        
        # Second create should fail
        with pytest.raises(TableAlreadyExistsError):
            catalog.create_table(
                identifier=table_name,
                schema=sample_schema,
            )


class TestComplexSchemas:
    """Test tables with complex schema types."""

    def test_nested_struct_schema(self, catalog: RestCatalog, temp_namespace: str):
        """Test creating a table with nested struct types."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(
                field_id=2,
                name="user",
                field_type=StructType(
                    NestedField(field_id=3, name="name", field_type=StringType(), required=True),
                    NestedField(field_id=4, name="email", field_type=StringType(), required=False),
                    NestedField(
                        field_id=5,
                        name="address",
                        field_type=StructType(
                            NestedField(field_id=6, name="street", field_type=StringType(), required=False),
                            NestedField(field_id=7, name="city", field_type=StringType(), required=False),
                        ),
                        required=False,
                    ),
                ),
                required=True,
            ),
        )
        
        table_name = f"{temp_namespace}.nested_struct_table"
        table = catalog.create_table(identifier=table_name, schema=schema)
        
        assert table is not None
        loaded = catalog.load_table(table_name)
        assert loaded.schema().find_field("user.name") is not None

    def test_list_type_schema(self, catalog: RestCatalog, temp_namespace: str):
        """Test creating a table with list types."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(
                field_id=2,
                name="tags",
                field_type=ListType(element_id=3, element_type=StringType(), element_required=False),
                required=False,
            ),
            NestedField(
                field_id=4,
                name="scores",
                field_type=ListType(element_id=5, element_type=DoubleType(), element_required=True),
                required=False,
            ),
        )
        
        table_name = f"{temp_namespace}.list_table"
        table = catalog.create_table(identifier=table_name, schema=schema)
        
        assert table is not None

    def test_map_type_schema(self, catalog: RestCatalog, temp_namespace: str):
        """Test creating a table with map types."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(
                field_id=2,
                name="metadata",
                field_type=MapType(
                    key_id=3,
                    key_type=StringType(),
                    value_id=4,
                    value_type=StringType(),
                    value_required=False,
                ),
                required=False,
            ),
        )
        
        table_name = f"{temp_namespace}.map_table"
        table = catalog.create_table(identifier=table_name, schema=schema)
        
        assert table is not None


class TestTableLoading:
    """Test table loading operations."""

    def test_load_table(self, catalog: RestCatalog, temp_namespace: str, sample_schema: Schema):
        """Test loading an existing table."""
        table_name = f"{temp_namespace}.load_test_table"
        
        # Create table
        created = catalog.create_table(identifier=table_name, schema=sample_schema)
        
        # Load table
        loaded = catalog.load_table(table_name)
        
        assert loaded is not None
        assert loaded.schema() == created.schema()

    def test_load_nonexistent_table(self, catalog: RestCatalog, temp_namespace: str):
        """Test loading a table that doesn't exist."""
        with pytest.raises(NoSuchTableError):
            catalog.load_table(f"{temp_namespace}.nonexistent_table_12345")

    def test_table_exists(self, catalog: RestCatalog, temp_namespace: str, sample_schema: Schema):
        """Test checking if a table exists."""
        table_name = f"{temp_namespace}.exists_test_table"
        
        # Create table
        catalog.create_table(identifier=table_name, schema=sample_schema)
        
        # Check existence - this varies by PyIceberg version
        tables = catalog.list_tables(temp_namespace)
        assert any("exists_test_table" in str(t) for t in tables)


class TestTableDeletion:
    """Test table deletion operations."""

    def test_drop_table(self, catalog: RestCatalog, temp_namespace: str, sample_schema: Schema):
        """Test dropping a table."""
        table_name = f"{temp_namespace}.drop_test_table"
        
        # Create and then drop
        catalog.create_table(identifier=table_name, schema=sample_schema)
        catalog.drop_table(table_name)
        
        # Verify it's gone
        tables = catalog.list_tables(temp_namespace)
        assert not any("drop_test_table" in str(t) for t in tables)

    def test_drop_nonexistent_table(self, catalog: RestCatalog, temp_namespace: str):
        """Test dropping a table that doesn't exist."""
        with pytest.raises(NoSuchTableError):
            catalog.drop_table(f"{temp_namespace}.nonexistent_table_12345")

    def test_purge_table(self, catalog: RestCatalog, temp_namespace: str, sample_schema: Schema):
        """Test purging a table (drop with data deletion)."""
        table_name = f"{temp_namespace}.purge_test_table"
        
        # Create and purge
        catalog.create_table(identifier=table_name, schema=sample_schema)
        
        # Note: purge behavior depends on implementation
        try:
            catalog.drop_table(table_name, purge_requested=True)
        except TypeError:
            # Older PyIceberg versions may not support purge_requested
            catalog.drop_table(table_name)
        
        # Verify it's gone
        tables = catalog.list_tables(temp_namespace)
        assert not any("purge_test_table" in str(t) for t in tables)


class TestTableListing:
    """Test table listing operations."""

    def test_list_tables_empty_namespace(self, catalog: RestCatalog, temp_namespace: str):
        """Test listing tables in an empty namespace."""
        tables = catalog.list_tables(temp_namespace)
        assert isinstance(tables, list)
        assert len(tables) == 0

    def test_list_tables_with_tables(
        self,
        catalog: RestCatalog,
        temp_namespace: str,
        sample_schema: Schema,
    ):
        """Test listing tables in a namespace with tables."""
        # Create multiple tables
        for i in range(3):
            catalog.create_table(
                identifier=f"{temp_namespace}.list_table_{i}",
                schema=sample_schema,
            )
        
        tables = catalog.list_tables(temp_namespace)
        assert len(tables) == 3
        
        table_names = [str(t) for t in tables]
        for i in range(3):
            assert any(f"list_table_{i}" in name for name in table_names)

    def test_list_tables_nonexistent_namespace(self, catalog: RestCatalog):
        """Test listing tables in a nonexistent namespace."""
        with pytest.raises(NoSuchNamespaceError):
            catalog.list_tables("nonexistent_namespace_12345")


class TestPartitionSpecs:
    """Test various partition specifications."""

    def test_day_partitioning(self, catalog: RestCatalog, temp_namespace: str):
        """Test day-based partitioning."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(field_id=2, name="ts", field_type=TimestampType(), required=True),
        )
        
        spec = PartitionSpec(
            PartitionField(source_id=2, field_id=1000, transform=DayTransform(), name="ts_day"),
        )
        
        table = catalog.create_table(
            identifier=f"{temp_namespace}.day_part_table",
            schema=schema,
            partition_spec=spec,
        )
        
        assert table is not None
        assert len(table.spec().fields) > 0

    def test_bucket_partitioning(self, catalog: RestCatalog, temp_namespace: str):
        """Test bucket-based partitioning."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(field_id=2, name="category", field_type=StringType(), required=True),
        )
        
        spec = PartitionSpec(
            PartitionField(source_id=2, field_id=1000, transform=BucketTransform(16), name="category_bucket"),
        )
        
        table = catalog.create_table(
            identifier=f"{temp_namespace}.bucket_part_table",
            schema=schema,
            partition_spec=spec,
        )
        
        assert table is not None

    def test_identity_partitioning(self, catalog: RestCatalog, temp_namespace: str):
        """Test identity partitioning."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(field_id=2, name="region", field_type=StringType(), required=True),
        )
        
        spec = PartitionSpec(
            PartitionField(source_id=2, field_id=1000, transform=IdentityTransform(), name="region"),
        )
        
        table = catalog.create_table(
            identifier=f"{temp_namespace}.identity_part_table",
            schema=schema,
            partition_spec=spec,
        )
        
        assert table is not None

    def test_truncate_partitioning(self, catalog: RestCatalog, temp_namespace: str):
        """Test truncate partitioning."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(field_id=2, name="code", field_type=StringType(), required=True),
        )
        
        spec = PartitionSpec(
            PartitionField(source_id=2, field_id=1000, transform=TruncateTransform(3), name="code_trunc"),
        )
        
        table = catalog.create_table(
            identifier=f"{temp_namespace}.truncate_part_table",
            schema=schema,
            partition_spec=spec,
        )
        
        assert table is not None

    def test_multiple_partition_fields(self, catalog: RestCatalog, temp_namespace: str):
        """Test partitioning with multiple fields."""
        schema = Schema(
            NestedField(field_id=1, name="id", field_type=LongType(), required=True),
            NestedField(field_id=2, name="ts", field_type=TimestampType(), required=True),
            NestedField(field_id=3, name="region", field_type=StringType(), required=True),
        )
        
        spec = PartitionSpec(
            PartitionField(source_id=2, field_id=1000, transform=DayTransform(), name="ts_day"),
            PartitionField(source_id=3, field_id=1001, transform=IdentityTransform(), name="region"),
        )
        
        table = catalog.create_table(
            identifier=f"{temp_namespace}.multi_part_table",
            schema=schema,
            partition_spec=spec,
        )
        
        assert table is not None
        assert len(table.spec().fields) == 2
