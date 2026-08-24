"""
Server-side scan planning against a table that actually holds data.

The Rust suite covers the request grammar and the refusals; only a client that
writes real Parquet can prove the planner reads its own manifests and returns
files an engine could open. PyIceberg writes the data, and the plan endpoint is
called directly because no released client speaks it yet.
"""

import urllib.error
import urllib.request
import json
from datetime import date, datetime
from decimal import Decimal

import pyarrow as pa
import pytest
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import Schema
from pyiceberg.transforms import DayTransform, IdentityTransform
from pyiceberg.types import (
    DateType,
    DecimalType,
    LongType,
    NestedField,
    StringType,
    TimestampType,
)


def plan(base_url: str, namespace: str, table: str, body: dict):
    """POSTs a plan request, returning (status, parsed body)."""
    request = urllib.request.Request(
        f"{base_url}/v1/namespaces/{namespace}/tables/{table}/plan",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


@pytest.fixture
def partitioned_table(pyiceberg_catalog: RestCatalog, temp_namespace: str):
    """A table partitioned on `region`, holding two files: EU and US."""
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "region", StringType(), required=True),
    )
    spec = PartitionSpec(
        PartitionField(source_id=2, field_id=1000, transform=IdentityTransform(), name="region")
    )

    table = pyiceberg_catalog.create_table(
        f"{temp_namespace}.events", schema=schema, partition_spec=spec
    )

    arrow_schema = pa.schema(
        [
            pa.field("id", pa.int64(), nullable=False),
            pa.field("region", pa.string(), nullable=False),
        ]
    )
    table.append(
        pa.Table.from_pylist(
            [
                {"id": 1, "region": "EU"},
                {"id": 2, "region": "EU"},
                {"id": 3, "region": "US"},
            ],
            schema=arrow_schema,
        )
    )

    return table


@pytest.fixture
def typed_partition_table(pyiceberg_catalog: RestCatalog, temp_namespace: str):
    """A table partitioned on the three types whose JSON form is not their literal.

    `date`, `timestamp` and `decimal` all arrive in a manifest as an integer —
    a day count, a microsecond count, an unscaled value — and the spec
    serialises all three as strings. A planner that encodes the tuple from the
    literal alone therefore emits a number, and no client parses that. Nothing
    catches it on a string-partitioned table, which is why this exists beside
    one.
    """
    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "d", DateType(), required=True),
        NestedField(3, "ts", TimestampType(), required=True),
        NestedField(4, "amount", DecimalType(9, 2), required=True),
    )
    spec = PartitionSpec(
        PartitionField(source_id=2, field_id=1000, transform=IdentityTransform(), name="d"),
        PartitionField(source_id=3, field_id=1001, transform=DayTransform(), name="ts_day"),
        PartitionField(
            source_id=4, field_id=1002, transform=IdentityTransform(), name="amount"
        ),
    )

    table = pyiceberg_catalog.create_table(
        f"{temp_namespace}.typed", schema=schema, partition_spec=spec
    )

    arrow_schema = pa.schema(
        [
            pa.field("id", pa.int64(), nullable=False),
            pa.field("d", pa.date32(), nullable=False),
            pa.field("ts", pa.timestamp("us"), nullable=False),
            pa.field("amount", pa.decimal128(9, 2), nullable=False),
        ]
    )
    table.append(
        pa.Table.from_pylist(
            [
                {
                    "id": 1,
                    "d": date(2024, 1, 1),
                    "ts": datetime(2024, 1, 1, 0, 0, 0),
                    "amount": Decimal("14.20"),
                }
            ],
            schema=arrow_schema,
        )
    )

    return table


@pytest.mark.pyiceberg
class TestScanPlanning:
    def test_plan_returns_spec_shaped_tasks(
        self, rustberg_server: str, temp_namespace: str, partitioned_table
    ):
        """Every task carries a DataFile with the fields the spec requires."""
        status, result = plan(rustberg_server, temp_namespace, "events", {})

        assert status == 200, result
        assert result["status"] == "completed"
        assert result["plan-id"]

        tasks = result["file-scan-tasks"]
        assert len(tasks) == 2, "one file per partition"

        for task in tasks:
            data_file = task["data-file"]
            for required in (
                "content",
                "file-path",
                "file-format",
                "spec-id",
                "partition",
                "file-size-in-bytes",
                "record-count",
            ):
                assert required in data_file, f"{required} missing from {data_file}"

            assert data_file["content"] == "data"
            assert data_file["file-format"] == "parquet"
            assert data_file["file-path"].endswith(".parquet")
            assert data_file["file-size-in-bytes"] > 0
            assert data_file["partition"] in (["EU"], ["US"])

            # Statistics are withheld unless asked for: they carry min and max
            # values for every column they describe.
            assert "lower-bounds" not in data_file
            assert "column-sizes" not in data_file

    def test_a_partition_filter_prunes_files(
        self, rustberg_server: str, temp_namespace: str, partitioned_table
    ):
        """The point of planning: the caller is told about fewer files."""
        status, result = plan(
            rustberg_server,
            temp_namespace,
            "events",
            {"filter": {"type": "eq", "term": "region", "value": "EU"}},
        )

        assert status == 200, result
        tasks = result["file-scan-tasks"]
        assert len(tasks) == 1, "the US partition cannot match and must be pruned"
        assert tasks[0]["data-file"]["partition"] == ["EU"]

        # The residual comes back unchanged, so the client filters what remains.
        assert tasks[0]["residual-filter"]["term"] == "region"

    def test_partition_values_are_serialised_by_their_type(
        self, rustberg_server: str, temp_namespace: str, typed_partition_table
    ):
        """A partition tuple is JSON single-value serialisation, not the literal.

        The spec writes a `date` as `"2024-01-01"`, a `timestamp` as an ISO
        string and a `decimal` with its scale. All three reach the planner as
        integers, so encoding from the literal emits numbers a client cannot
        read back — and `days(ts)` is the most common partition spec there is.
        """
        status, result = plan(rustberg_server, temp_namespace, "typed", {})

        assert status == 200, result
        tasks = result["file-scan-tasks"]
        assert len(tasks) == 1, result

        partition = tasks[0]["data-file"]["partition"]
        assert partition[0] == "2024-01-01", f"a date is a date string: {partition}"
        assert partition[1] == "2024-01-01", f"days(ts) yields a date: {partition}"
        assert partition[2] == "14.20", f"a decimal carries its scale: {partition}"

    def test_stats_fields_sends_only_what_was_asked_for(
        self, rustberg_server: str, temp_namespace: str, partitioned_table
    ):
        status, result = plan(
            rustberg_server, temp_namespace, "events", {"stats-fields": ["id"]}
        )

        assert status == 200, result
        data_file = result["file-scan-tasks"][0]["data-file"]

        assert "lower-bounds" in data_file
        assert data_file["lower-bounds"]["keys"] == [1], "only the field that was asked for"
        assert "upper-bounds" in data_file

    def test_a_filter_matching_nothing_plans_nothing(
        self, rustberg_server: str, temp_namespace: str, partitioned_table
    ):
        status, result = plan(
            rustberg_server,
            temp_namespace,
            "events",
            {"filter": {"type": "eq", "term": "region", "value": "APAC"}},
        )

        assert status == 200, result
        assert result["file-scan-tasks"] == []
