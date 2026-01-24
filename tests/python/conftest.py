"""
Rustberg Python Integration Tests - Shared Fixtures

This module provides pytest fixtures for testing Rustberg compatibility
with PyIceberg and PySpark clients.
"""

import os
import subprocess
import time
import tempfile
import shutil
from typing import Generator, Optional
from pathlib import Path

import pytest


# =============================================================================
# Configuration
# =============================================================================

RUSTBERG_HOST = os.getenv("RUSTBERG_HOST", "localhost")
RUSTBERG_PORT = int(os.getenv("RUSTBERG_PORT", "8181"))
RUSTBERG_URL = f"http://{RUSTBERG_HOST}:{RUSTBERG_PORT}"
RUSTBERG_BINARY = os.getenv("RUSTBERG_BINARY", None)
RUSTBERG_STARTUP_TIMEOUT = 30  # seconds


# =============================================================================
# Rustberg Server Management
# =============================================================================

class RustbergServer:
    """Manages a Rustberg server process for testing."""
    
    def __init__(self, binary_path: str, data_dir: str, port: int):
        self.binary_path = binary_path
        self.data_dir = data_dir
        self.port = port
        self.process: Optional[subprocess.Popen] = None
        
    def start(self) -> None:
        """Start the Rustberg server."""
        if self.process is not None:
            raise RuntimeError("Server already running")
            
        env = os.environ.copy()
        env["RUST_LOG"] = "warn"
        
        self.process = subprocess.Popen(
            [
                self.binary_path,
                "--insecure-http",
                "--no-auth",
                "--host", "127.0.0.1",
                "--port", str(self.port),
            ],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        # Wait for server to be ready
        self._wait_for_ready()
        
    def _wait_for_ready(self) -> None:
        """Wait for the server to accept connections."""
        import urllib.request
        import urllib.error
        
        url = f"http://127.0.0.1:{self.port}/v1/config"
        start = time.time()
        
        while time.time() - start < RUSTBERG_STARTUP_TIMEOUT:
            # Check if process has exited unexpectedly
            if self.process and self.process.poll() is not None:
                exit_code = self.process.returncode
                stderr_output = ""
                stdout_output = ""
                if self.process.stderr:
                    stderr_output = self.process.stderr.read().decode("utf-8", errors="replace")
                if self.process.stdout:
                    stdout_output = self.process.stdout.read().decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"Rustberg server exited unexpectedly with code {exit_code}\n"
                    f"Binary: {self.binary_path}\n"
                    f"Stdout: {stdout_output}\n"
                    f"Stderr: {stderr_output}"
                )
            
            try:
                urllib.request.urlopen(url, timeout=1)
                return
            except (urllib.error.URLError, ConnectionRefusedError):
                time.sleep(0.1)
        
        # On timeout, also try to get any output
        stderr_output = ""
        stdout_output = ""
        if self.process:
            if self.process.stderr:
                # Non-blocking read attempt
                import select
                if hasattr(select, 'select'):
                    readable, _, _ = select.select([self.process.stderr], [], [], 0)
                    if readable:
                        stderr_output = self.process.stderr.read().decode("utf-8", errors="replace")
        
        raise TimeoutError(
            f"Rustberg server did not start within {RUSTBERG_STARTUP_TIMEOUT}s\n"
            f"Binary: {self.binary_path}\n"
            f"Stderr: {stderr_output}"
        )
        
    def stop(self) -> None:
        """Stop the Rustberg server."""
        if self.process is None:
            return
            
        # Send SIGTERM for graceful shutdown
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            
        self.process = None


def find_rustberg_binary() -> Optional[str]:
    """Find the Rustberg binary."""
    if RUSTBERG_BINARY:
        return RUSTBERG_BINARY
        
    # Check common locations relative to workspace root
    workspace_root = Path(__file__).parent.parent.parent
    candidates = [
        workspace_root / "target" / "release" / "rustberg",
        workspace_root / "target" / "debug" / "rustberg",
    ]
    
    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)
            
    return None


# =============================================================================
# Session-scoped Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def rustberg_binary() -> str:
    """Get the path to the Rustberg binary."""
    binary = find_rustberg_binary()
    if binary is None:
        pytest.skip("Rustberg binary not found. Build with: cargo build --all-features")
    return binary


@pytest.fixture(scope="session")
def rustberg_server(rustberg_binary: str) -> Generator[str, None, None]:
    """
    Start a Rustberg server for the test session.
    
    Yields the server URL.
    """
    # Create temporary data directory
    data_dir = tempfile.mkdtemp(prefix="rustberg_test_")
    
    try:
        server = RustbergServer(rustberg_binary, data_dir, RUSTBERG_PORT)
        server.start()
        
        yield f"http://127.0.0.1:{RUSTBERG_PORT}"
        
        server.stop()
    finally:
        # Cleanup data directory
        shutil.rmtree(data_dir, ignore_errors=True)


@pytest.fixture(scope="session")
def warehouse_path() -> Generator[str, None, None]:
    """Create a temporary warehouse directory for test data."""
    warehouse = tempfile.mkdtemp(prefix="rustberg_warehouse_")
    yield warehouse
    shutil.rmtree(warehouse, ignore_errors=True)


# =============================================================================
# PyIceberg Fixtures
# =============================================================================

@pytest.fixture(scope="session")
def pyiceberg_catalog(rustberg_server: str):
    """Create a PyIceberg RestCatalog connected to Rustberg."""
    from pyiceberg.catalog.rest import RestCatalog
    
    return RestCatalog(
        name="rustberg_test",
        uri=rustberg_server,
    )


@pytest.fixture
def temp_namespace(pyiceberg_catalog) -> Generator[str, None, None]:
    """
    Create a temporary namespace for a test.
    
    Yields the namespace name. Cleans up after the test.
    """
    import uuid
    
    namespace = f"test_ns_{uuid.uuid4().hex[:8]}"
    pyiceberg_catalog.create_namespace(namespace)
    
    yield namespace
    
    # Cleanup: drop all tables first, then the namespace
    try:
        for table in pyiceberg_catalog.list_tables(namespace):
            pyiceberg_catalog.drop_table(table)
        pyiceberg_catalog.drop_namespace(namespace)
    except Exception:
        pass  # Best effort cleanup


# =============================================================================
# Schema Fixtures
# =============================================================================

@pytest.fixture
def sample_schema():
    """Create a sample Iceberg schema for testing."""
    from pyiceberg.schema import Schema
    from pyiceberg.types import (
        IntegerType,
        LongType,
        StringType,
        TimestampType,
        DoubleType,
        BooleanType,
        NestedField,
    )
    
    return Schema(
        NestedField(field_id=1, name="id", field_type=LongType(), required=True),
        NestedField(field_id=2, name="name", field_type=StringType(), required=True),
        NestedField(field_id=3, name="created_at", field_type=TimestampType(), required=True),
        NestedField(field_id=4, name="value", field_type=DoubleType(), required=False),
        NestedField(field_id=5, name="is_active", field_type=BooleanType(), required=False),
        NestedField(field_id=6, name="count", field_type=IntegerType(), required=False),
    )


@pytest.fixture
def sample_partition_spec():
    """Create a sample partition spec for testing."""
    from pyiceberg.partitioning import PartitionSpec, PartitionField
    from pyiceberg.transforms import DayTransform
    
    return PartitionSpec(
        PartitionField(source_id=3, field_id=1000, transform=DayTransform(), name="created_day"),
    )


@pytest.fixture
def sample_sort_order():
    """Create a sample sort order for testing."""
    from pyiceberg.table.sorting import SortOrder, SortField
    from pyiceberg.transforms import IdentityTransform
    
    return SortOrder(
        SortField(source_id=1, transform=IdentityTransform()),
    )


# =============================================================================
# PySpark Fixtures
# =============================================================================

def _is_java_available() -> bool:
    """Check if Java is available locally."""
    import shutil
    if not shutil.which("java"):
        return False
    # Also verify it actually runs
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


@pytest.fixture(scope="session")
def spark_session(rustberg_server: str, warehouse_path: str):
    """
    Create a PySpark session configured to use Rustberg as the catalog.
    
    This fixture is session-scoped to avoid the overhead of creating
    multiple Spark sessions.
    
    Requires Java 11+ to be installed. Skips tests if Java is not available.
    """
    if not _is_java_available():
        pytest.skip("PySpark tests require Java 11+ - install Java or run in CI")
        return
    
    from pyspark.sql import SparkSession
    
    spark = (
        SparkSession.builder
        .appName("RustbergIntegrationTests")
        .master("local[2]")
        # Iceberg configuration
        .config("spark.sql.extensions", "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
        .config("spark.sql.catalog.rustberg", "org.apache.iceberg.spark.SparkCatalog")
        .config("spark.sql.catalog.rustberg.type", "rest")
        .config("spark.sql.catalog.rustberg.uri", rustberg_server)
        .config("spark.sql.catalog.rustberg.warehouse", warehouse_path)
        # Use local warehouse for test data
        .config("spark.sql.warehouse.dir", warehouse_path)
        # Performance tuning for tests
        .config("spark.driver.memory", "1g")
        .config("spark.executor.memory", "1g")
        .config("spark.sql.shuffle.partitions", "2")
        # Disable UI for tests
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    
    yield spark
    
    spark.stop()


@pytest.fixture
def spark_temp_namespace(spark_session) -> Generator[str, None, None]:
    """
    Create a temporary namespace in Spark for testing.
    
    Yields the fully qualified namespace name (catalog.namespace).
    """
    import uuid
    
    namespace = f"test_ns_{uuid.uuid4().hex[:8]}"
    full_namespace = f"rustberg.{namespace}"
    
    spark_session.sql(f"CREATE NAMESPACE {full_namespace}")
    
    yield full_namespace
    
    # Cleanup
    try:
        # Drop all tables in namespace
        tables = spark_session.sql(f"SHOW TABLES IN {full_namespace}").collect()
        for table in tables:
            spark_session.sql(f"DROP TABLE IF EXISTS {full_namespace}.{table.tableName}")
        spark_session.sql(f"DROP NAMESPACE IF EXISTS {full_namespace}")
    except Exception:
        pass  # Best effort cleanup
