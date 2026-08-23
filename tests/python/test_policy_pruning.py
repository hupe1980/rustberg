"""
A Cedar row filter prunes the plan.

This is the assertion that the policy layer and the planner are one system: a
caller whose permit carries `@row_filter` is told about fewer files than one
whose permit does not, against the same table and the same data.

Runs its own server, because it needs API keys and a policy file rather than the
shared `--no-auth` fixture.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pyarrow as pa
import pytest
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import Schema
from pyiceberg.transforms import IdentityTransform
from pyiceberg.types import LongType, NestedField, StringType

# `@row_filter` carries an Iceberg predicate as JSON. A Cedar annotation is a
# string, so the quotes are escaped — which is what an operator writes too.
POLICIES = r'''
permit(
  principal in Rustberg::Group::"writer",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List",
             Rustberg::Action::"Create", Rustberg::Action::"Update"],
  resource
) when { resource.tenant == principal.tenant };

@row_filter("{\"type\":\"eq\",\"term\":\"region\",\"value\":\"EU\"}")
permit(
  principal in Rustberg::Group::"eu",
  action in [Rustberg::Action::"Read", Rustberg::Action::"List"],
  resource
) when { resource.tenant == principal.tenant };
'''

WRITER_KEY = "rb_test_writer_key_0000000000000000000000"
EU_KEY = "rb_test_eu_key_000000000000000000000000000"

CONFIG = """
[server]
host = "127.0.0.1"
port = {port}

[server.auth]
api_key_enabled = true
policy_file = "{policy_file}"

[[server.auth.api_keys]]
name = "writer"
tenant = "acme"
roles = ["writer"]
key_env = "RUSTBERG_WRITER_KEY"

[[server.auth.api_keys]]
name = "eu"
tenant = "acme"
roles = ["eu"]
key_env = "RUSTBERG_EU_KEY"

[storage]
catalog_url = "file://{catalog}"
warehouse_location = "file://{warehouse}"
"""


@pytest.fixture(scope="module")
def policy_server(rustberg_binary: str):
    """A server with two identities: one unrestricted, one under a row filter."""
    root = tempfile.mkdtemp(prefix="rustberg_policy_")
    catalog = os.path.join(root, "catalog")
    warehouse = os.path.join(root, "warehouse")
    os.makedirs(catalog)
    os.makedirs(warehouse)

    policy_file = os.path.join(root, "policies.cedar")
    with open(policy_file, "w") as handle:
        handle.write(POLICIES)

    # A free port, picked by the OS rather than hardcoded: a fixed one collides
    # with whatever the last run left behind.
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    config_file = os.path.join(root, "config.toml")
    with open(config_file, "w") as handle:
        handle.write(
            CONFIG.format(
                port=port, policy_file=policy_file, catalog=catalog, warehouse=warehouse
            )
        )

    env = os.environ.copy()
    env["RUST_LOG"] = "warn"
    env["RUSTBERG_WRITER_KEY"] = WRITER_KEY
    env["RUSTBERG_EU_KEY"] = EU_KEY

    process = subprocess.Popen(
        [rustberg_binary, "--config", config_file, "--insecure-http"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if process.poll() is not None:
            out, err = process.communicate()
            raise RuntimeError(f"server exited: {err.decode()[-2000:]}")
        try:
            request = urllib.request.Request(
                f"{url}/v1/config", headers={"X-API-Key": WRITER_KEY}
            )
            with urllib.request.urlopen(request, timeout=1):
                break
        except Exception:
            time.sleep(0.2)
    else:
        process.terminate()
        out, err = process.communicate(timeout=5)
        raise RuntimeError(
            f"server did not start on {url}\nstdout: {out.decode()[-1500:]}\n"
            f"stderr: {err.decode()[-2500:]}"
        )

    yield url

    process.terminate()
    process.wait(timeout=10)
    shutil.rmtree(root, ignore_errors=True)


def plan(url: str, key: str, table: str, body: dict):
    request = urllib.request.Request(
        f"{url}/v1/namespaces/db/tables/{table}/plan",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "X-API-Key": key},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


@pytest.mark.pyiceberg
def test_a_row_filter_prunes_the_plan(policy_server: str):
    catalog = RestCatalog("policy", uri=policy_server, token=WRITER_KEY)
    catalog.create_namespace("db")

    schema = Schema(
        NestedField(1, "id", LongType(), required=True),
        NestedField(2, "region", StringType(), required=True),
    )
    spec = PartitionSpec(
        PartitionField(source_id=2, field_id=1000, transform=IdentityTransform(), name="region")
    )
    table = catalog.create_table("db.events", schema=schema, partition_spec=spec)

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
                {"id": 2, "region": "US"},
                {"id": 3, "region": "APAC"},
            ],
            schema=arrow_schema,
        )
    )

    # The unrestricted identity sees every partition.
    status, unrestricted = plan(policy_server, WRITER_KEY, "events", {})
    assert status == 200, unrestricted
    assert len(unrestricted["file-scan-tasks"]) == 3

    # The identity under `@row_filter` is told about one.
    status, restricted = plan(policy_server, EU_KEY, "events", {})
    assert status == 200, restricted
    tasks = restricted["file-scan-tasks"]
    assert len(tasks) == 1, "the policy filter pruned the other partitions"
    assert tasks[0]["data-file"]["partition"] == ["EU"]

    # And the residual carries it, so a cooperating engine applies the same
    # restriction to the rows inside the file it reads.
    assert tasks[0]["residual-filter"] == {
        "type": "eq",
        "term": "region",
        "value": "EU",
    }


@pytest.mark.pyiceberg
def test_a_client_filter_is_conjoined_with_the_policy_filter(policy_server: str):
    """Both halves must survive: the client's, and the one policy imposes."""
    status, result = plan(
        policy_server,
        EU_KEY,
        "events",
        {"filter": {"type": "eq", "term": "region", "value": "US"}},
    )

    assert status == 200, result
    assert result["file-scan-tasks"] == [], (
        "region = 'US' AND region = 'EU' selects nothing; a plan that returned the "
        "US partition would have applied only the client's half"
    )
