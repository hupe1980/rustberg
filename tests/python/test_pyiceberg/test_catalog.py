"""
PyIceberg Config and Compatibility Tests

Tests the REST catalog configuration endpoint and overall compatibility.
"""

import pytest
import httpx
from pyiceberg.catalog.rest import RestCatalog


class TestCatalogConfig:
    """Test catalog configuration endpoint."""

    def test_config_endpoint(self, rustberg_server: str):
        """Test that the /v1/config endpoint returns valid configuration."""
        response = httpx.get(f"{rustberg_server}/v1/config")
        
        assert response.status_code == 200
        
        data = response.json()
        assert "defaults" in data or "overrides" in data or isinstance(data, dict)

    def test_config_with_warehouse(self, rustberg_server: str):
        """Test config endpoint with warehouse parameter."""
        response = httpx.get(f"{rustberg_server}/v1/config", params={"warehouse": "test"})
        
        assert response.status_code == 200


class TestHealthEndpoints:
    """Test health and readiness endpoints."""

    def test_health_endpoint(self, rustberg_server: str):
        """Test the /health endpoint."""
        response = httpx.get(f"{rustberg_server}/health")
        
        assert response.status_code == 200

    def test_ready_endpoint(self, rustberg_server: str):
        """Test the /ready endpoint."""
        response = httpx.get(f"{rustberg_server}/ready")
        
        assert response.status_code == 200


class TestCatalogProperties:
    """Test catalog-level properties and capabilities."""

    def test_catalog_properties(self, catalog: RestCatalog):
        """Test that catalog returns its properties."""
        props = catalog.properties
        assert isinstance(props, dict)

    def test_catalog_name(self, catalog: RestCatalog):
        """Test that catalog has a name."""
        assert catalog.name is not None
        assert len(catalog.name) > 0


class TestErrorHandling:
    """Test proper error handling and HTTP status codes."""

    def test_not_found_table(self, rustberg_server: str):
        """Test 404 for non-existent table."""
        response = httpx.get(
            f"{rustberg_server}/v1/namespaces/nonexistent/tables/nonexistent"
        )
        
        # Should be 404 Not Found
        assert response.status_code == 404

    def test_not_found_namespace(self, rustberg_server: str):
        """Test 404 for non-existent namespace."""
        response = httpx.get(
            f"{rustberg_server}/v1/namespaces/nonexistent_namespace_12345"
        )
        
        # Should be 404 Not Found
        assert response.status_code == 404

    def test_method_not_allowed(self, rustberg_server: str):
        """Test 405 for unsupported HTTP methods."""
        # PATCH on config endpoint should not be allowed
        response = httpx.patch(f"{rustberg_server}/v1/config")
        
        # Should be 405 Method Not Allowed
        assert response.status_code in [404, 405]

    def test_invalid_json_body(self, rustberg_server: str):
        """Test 400 for invalid JSON in request body."""
        response = httpx.post(
            f"{rustberg_server}/v1/namespaces",
            content="not valid json",
            headers={"Content-Type": "application/json"},
        )
        
        # Should be 400 Bad Request or 422 Unprocessable Entity
        assert response.status_code in [400, 422]


class TestIcebergRESTSpec:
    """Test compliance with Iceberg REST Catalog specification."""

    def test_namespace_list_response_format(self, rustberg_server: str):
        """Test that namespace list returns proper format."""
        response = httpx.get(f"{rustberg_server}/v1/namespaces")
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have 'namespaces' key
        assert "namespaces" in data
        assert isinstance(data["namespaces"], list)

    def test_namespace_create_response_format(self, rustberg_server: str):
        """Test that namespace create returns proper format."""
        import uuid
        ns_name = f"spec_test_{uuid.uuid4().hex[:8]}"
        
        response = httpx.post(
            f"{rustberg_server}/v1/namespaces",
            json={"namespace": [ns_name], "properties": {}},
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Should have 'namespace' and 'properties' keys
        assert "namespace" in data
        assert "properties" in data
        
        # Cleanup
        httpx.delete(f"{rustberg_server}/v1/namespaces/{ns_name}")

    def test_table_list_response_format(self, rustberg_server: str):
        """Test that table list returns proper format."""
        import uuid
        ns_name = f"table_list_test_{uuid.uuid4().hex[:8]}"
        
        # Create namespace first
        httpx.post(
            f"{rustberg_server}/v1/namespaces",
            json={"namespace": [ns_name], "properties": {}},
        )
        
        try:
            response = httpx.get(f"{rustberg_server}/v1/namespaces/{ns_name}/tables")
            
            assert response.status_code == 200
            data = response.json()
            
            # Should have 'identifiers' key
            assert "identifiers" in data
            assert isinstance(data["identifiers"], list)
        finally:
            httpx.delete(f"{rustberg_server}/v1/namespaces/{ns_name}")

    def test_error_response_format(self, rustberg_server: str):
        """Test that errors return proper Iceberg error format."""
        response = httpx.get(
            f"{rustberg_server}/v1/namespaces/nonexistent_namespace_12345"
        )
        
        assert response.status_code == 404
        data = response.json()
        
        # Iceberg errors should have 'error' object with 'message' and 'type'
        assert "error" in data
        assert "message" in data["error"]
        assert "type" in data["error"]

    def test_content_type_json(self, rustberg_server: str):
        """Test that responses have correct Content-Type."""
        response = httpx.get(f"{rustberg_server}/v1/namespaces")
        
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")


class TestConcurrency:
    """Test concurrent operations."""

    def test_concurrent_namespace_creation(self, catalog: RestCatalog):
        """Test creating multiple namespaces concurrently."""
        import concurrent.futures
        import uuid
        
        def create_namespace(i: int) -> str:
            ns = f"concurrent_ns_{uuid.uuid4().hex[:8]}"
            catalog.create_namespace(ns)
            return ns
        
        created_namespaces = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(create_namespace, i) for i in range(5)]
                for future in concurrent.futures.as_completed(futures):
                    created_namespaces.append(future.result())
            
            # All should have been created
            assert len(created_namespaces) == 5
            
            # All should be listable
            all_namespaces = catalog.list_namespaces()
            for ns in created_namespaces:
                assert any(ns in str(n) for n in all_namespaces)
        finally:
            # Cleanup
            for ns in created_namespaces:
                try:
                    catalog.drop_namespace(ns)
                except Exception:
                    pass

    def test_concurrent_table_creation(
        self,
        catalog: RestCatalog,
        temp_namespace: str,
        sample_schema,
    ):
        """Test creating multiple tables concurrently."""
        import concurrent.futures
        import uuid
        
        def create_table(i: int) -> str:
            table_name = f"concurrent_table_{uuid.uuid4().hex[:8]}"
            catalog.create_table(
                identifier=f"{temp_namespace}.{table_name}",
                schema=sample_schema,
            )
            return table_name
        
        created_tables = []
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(create_table, i) for i in range(5)]
                for future in concurrent.futures.as_completed(futures):
                    created_tables.append(future.result())
            
            # All should have been created
            assert len(created_tables) == 5
            
            # All should be listable
            all_tables = catalog.list_tables(temp_namespace)
            for table in created_tables:
                assert any(table in str(t) for t in all_tables)
        finally:
            # Cleanup handled by temp_namespace fixture
            pass
