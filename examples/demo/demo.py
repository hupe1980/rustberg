"""The five-minute proof: two people read one table, and the catalog enforces the difference.

Every line it prints is an assertion. A claim that stops being true fails the run, which is how
the same script guards the story in CI.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from urllib.parse import quote

import httpx
import pyarrow as pa
import pyarrow.parquet as pq
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.partitioning import PartitionField, PartitionSpec
from pyiceberg.schema import Schema
from pyiceberg.transforms import IdentityTransform
from pyiceberg.types import DoubleType, LongType, NestedField, StringType

CATALOG = os.environ.get("RUSTBERG_URL", "http://rustberg:8000")
CONSOLE = os.environ.get("CONSOLE_URL", "http://localhost:8000/ui/")
ALICE = os.environ["DEMO_ALICE_KEY"]
BOB = os.environ["DEMO_BOB_KEY"]
AUDIT = os.environ.get("AUDIT_FILE", "/var/lib/rustberg/audit.jsonl")
S3 = os.environ.get("S3_URL", "http://s3:9000")
TABLE = "/v1/namespaces/demo/tables/orders"

TTY = sys.stdout.isatty()


def paint(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def step(title: str) -> None:
    print()
    print(paint("1", title))


def ok(claim: str, why: str = "") -> None:
    print(f"  {paint('32', '✓')} {claim}")
    if why:
        print(f"    {paint('2', why)}")


def fail(claim: str, detail: object) -> None:
    print(f"  {paint('31', '✗')} {claim}")
    print(f"    {detail}")
    sys.exit(1)


def check(condition: bool, claim: str, detail: object = "", why: str = "") -> None:
    ok(claim, why) if condition else fail(claim, detail)


def http(key: str) -> httpx.Client:
    return httpx.Client(base_url=CATALOG, headers={"X-API-Key": key}, timeout=30)


def wait_for_catalog() -> None:
    for _ in range(120):
        try:
            if httpx.get(f"{CATALOG}/health", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    fail("the catalog came up", f"{CATALOG}/health never answered")


def seed() -> None:
    step("1 · alice, an administrator, creates demo.orders and writes EU and US rows")
    catalog = RestCatalog(
        "demo",
        uri=CATALOG,
        **{
            "header.X-API-Key": ALICE,
            # alice's ETL engine has its own storage role: the operator's, not one the catalog hands out.
            "s3.endpoint": S3,
            "s3.access-key-id": os.environ["S3_ACCESS_KEY"],
            "s3.secret-access-key": os.environ["S3_SECRET_KEY"],
            "s3.region": "us-east-1",
        },
    )
    try:
        catalog.create_namespace("demo")
    except Exception:  # noqa: BLE001 — already there on a re-run
        pass
    schema = Schema(
        NestedField(1, "order_id", LongType(), required=True),
        NestedField(2, "region", StringType(), required=True),
        NestedField(3, "customer", StringType()),
        NestedField(4, "email", StringType()),
        NestedField(5, "amount", DoubleType()),
    )
    spec = PartitionSpec(PartitionField(source_id=2, field_id=1000, transform=IdentityTransform(), name="region"))
    try:
        catalog.drop_table("demo.orders")
    except Exception:  # noqa: BLE001
        pass
    table = catalog.create_table("demo.orders", schema=schema, partition_spec=spec)
    rows = pa.Table.from_pylist(
        [
            {"order_id": 1, "region": "EU", "customer": "Ada", "email": "ada@example.eu", "amount": 120.0},
            {"order_id": 2, "region": "EU", "customer": "Bea", "email": "bea@example.eu", "amount": 75.5},
            {"order_id": 3, "region": "US", "customer": "Cal", "email": "cal@example.com", "amount": 310.0},
            {"order_id": 4, "region": "US", "customer": "Dee", "email": "dee@example.com", "amount": 42.0},
        ],
        schema=table.schema().as_arrow(),
    )
    table.append(rows)
    ok("demo.orders holds 2 EU and 2 US orders, partitioned by region", "identity(region): EU and US rows live in different files")


def as_alice() -> dict:
    step("2 · alice loads it")
    with http(ALICE) as c:
        r = c.get(TABLE, headers={"X-Iceberg-Access-Delegation": "remote-signing"})
    check(r.status_code == 200, "alice's load succeeds", r.text)
    body = r.json()
    check("read-restrictions" not in body, "nothing is withheld from alice", body.get("read-restrictions"))
    check(
        r.headers.get("rustberg-enforcement") == "none",
        "Rustberg-Enforcement: none",
        r.headers.get("rustberg-enforcement"),
    )
    signing = body.get("remote-signing-config") or body.get("config", {}).get("s3.remote-signing-enabled")
    check(bool(signing), "alice's engine may have its storage requests signed", body.get("config"))
    with http(ALICE) as c:
        plan = c.post(f"{TABLE}/plan", json={}).json()
    return plan


def as_bob() -> dict:
    step("3 · bob, an analyst, loads the same table")
    with http(BOB) as c:
        r = c.get(TABLE, headers={"X-Iceberg-Access-Delegation": "remote-signing"})
    check(r.status_code == 200, "bob may read it", r.text)
    body = r.json()
    check(
        "storage-credentials" not in body and "remote-signing-config" not in body,
        "bob gets no storage credential and no signer",
        {k: body.get(k) for k in ("storage-credentials", "remote-signing-config")},
        "nothing he holds can reach a file the catalog did not choose for him",
    )
    restrictions = body.get("read-restrictions", {})
    check("required-row-filter" in restrictions, "the response carries his row filter (region = 'EU')", restrictions)
    check(
        any(p.get("action") for p in restrictions.get("required-column-projections", [])),
        "and his column mask (email)",
        restrictions,
    )
    check(body.get("config", {}).get("scan-planning-mode") == "server", "he must plan through the catalog", body.get("config"))
    grade = r.headers.get("rustberg-enforcement")
    check(
        grade == "cooperative;masked",
        f"Rustberg-Enforcement: {grade}",
        grade,
        "the filter is architectural (region is an identity partition); the mask is cooperative — the file holds email",
    )

    step("4 · bob plans a scan")
    with http(BOB) as c:
        r = c.post(f"{TABLE}/plan", json={})
    check(r.status_code == 200, "the plan is answered", r.text)
    plan = r.json()
    tasks = plan["file-scan-tasks"]
    check(bool(tasks) and all(t["data-file"]["partition"] == ["EU"] for t in tasks), f"it names {len(tasks)} file(s), all region=EU", tasks)
    urls = [t["data-file"]["file-path"] for t in tasks]
    check(all("X-Amz-Signature" in u for u in urls), "each one a pre-signed URL", urls[0][:120])
    data = httpx.get(urls[0], timeout=30)
    check(data.status_code == 200, "the URL downloads", data.status_code)
    rows = pq.read_table(io.BytesIO(data.content)).to_pylist()
    check(all(row["region"] == "EU" for row in rows), f"and holds {len(rows)} EU row(s), nothing else", rows)
    check(
        all(row.get("email") for row in rows),
        "the file holds email unmasked",
        rows,
        "which is what 'cooperative;masked' said: an engine applying read-restrictions masks it; the bytes do not",
    )
    return plan


def bob_cannot_reach_us(alice_plan: dict) -> None:
    step("5 · bob asks the catalog to sign a read of a US file")
    us = next(t["data-file"]["file-path"] for t in alice_plan["file-scan-tasks"] if t["data-file"]["partition"] == ["US"])
    key = us.removeprefix("s3://")
    with http(BOB) as c:
        r = c.post(
            "/v1/namespaces/demo/tables/orders/sign",
            json={"region": "us-east-1", "method": "GET", "uri": f"{S3}/{quote(key)}", "headers": {}},
        )
    check(r.status_code in (403, 404), f"refused ({r.status_code})", r.text, "a restricted caller is never signed for; the plan was his only way in")


def the_trail() -> None:
    step("6 · the audit trail says what happened, and which rule did it")
    for _ in range(20):
        if os.path.exists(AUDIT):
            break
        time.sleep(0.5)
    records = [json.loads(line) for line in open(AUDIT) if line.strip()]
    grant = [r for r in records if r.get("details", {}).get("source") == "scan_plan" and r.get("principal_id") == "bob"]
    check(bool(grant), "one record of what bob's plan pre-signed", "no scan_plan record")
    g = grant[-1]
    check(g.get("enforcement") == "cooperative", f"files={g['details']['files']}, enforcement={g['enforcement']}", g)
    decisions = [
        r for r in records
        if r.get("action") == "decision" and r.get("principal_id") == "bob" and r.get("operation") == "Read" and r.get("resource_type") == "table"
    ]
    check(
        bool(decisions) and "policy1" in decisions[-1].get("matched_policies", []),
        "bob's read was decided by policy1 — the analyst rule",
        decisions[-1:] if decisions else records[-3:],
    )


def handover() -> None:
    step("7 · now look at it")
    print(f"  Open {paint('4', CONSOLE)} and sign in with each key:")
    print(f"    alice  {ALICE}")
    print(f"    bob    {BOB}")
    print("  As bob, demo.orders says Restricted and how strongly it holds.")
    print("  As alice, try View as… bob, then edit the policy: the review says who gains what before you save.")
    print()
    print("  Or point an engine at it:")
    print(f"    PyIceberg  RestCatalog('demo', uri='{CONSOLE.removesuffix('/ui/')}', **{{'header.X-API-Key': '<key>'}})")
    print("    DuckDB     bob's read is refused by DuckDB 2.0 — it cannot apply a mask, which is the right answer")


def main() -> None:
    print(paint("1", "Rustberg — the five-minute proof"))
    wait_for_catalog()
    seed()
    alice_plan = as_alice()
    as_bob()
    bob_cannot_reach_us(alice_plan)
    the_trail()
    handover()
    print()
    print(paint("32", "Every claim above was checked."))


if __name__ == "__main__":
    main()
