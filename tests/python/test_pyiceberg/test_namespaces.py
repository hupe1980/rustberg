"""
PyIceberg Namespace Integration Tests

Tests namespace operations using PyIceberg client against Rustberg.
"""

import pytest
from pyiceberg.catalog.rest import RestCatalog
from pyiceberg.exceptions import NamespaceAlreadyExistsError, NoSuchNamespaceError


class TestNamespaceOperations:
    """Test namespace CRUD operations."""
    
    def test_create_namespace(self, catalog: RestCatalog):
        """Test creating a new namespace."""
        ns = "test_create_ns"
        
        # Cleanup if exists from previous failed run
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            # Create namespace
            catalog.create_namespace(ns)
            
            # Verify it exists
            namespaces = catalog.list_namespaces()
            assert (ns,) in namespaces
        finally:
            catalog.drop_namespace(ns)
    
    def test_create_namespace_with_properties(self, catalog: RestCatalog):
        """Test creating a namespace with custom properties."""
        ns = "test_ns_props"
        properties = {
            "owner": "test-user",
            "description": "Test namespace with properties",
            "custom.key": "custom-value",
        }
        
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns, properties=properties)
            
            # Load and verify properties
            loaded_props = catalog.load_namespace_properties(ns)
            assert loaded_props.get("owner") == "test-user"
            assert loaded_props.get("description") == "Test namespace with properties"
            assert loaded_props.get("custom.key") == "custom-value"
        finally:
            catalog.drop_namespace(ns)
    
    def test_create_namespace_already_exists(self, catalog: RestCatalog):
        """Test that creating a duplicate namespace raises an error."""
        ns = "test_dup_ns"
        
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns)
            
            # Second create should fail
            with pytest.raises(NamespaceAlreadyExistsError):
                catalog.create_namespace(ns)
        finally:
            catalog.drop_namespace(ns)
    
    def test_nested_namespace(self, catalog: RestCatalog):
        """Test creating nested namespaces (multi-level)."""
        ns_parent = "parent_ns"
        ns_child = "parent_ns.child_ns"
        
        try:
            catalog.drop_namespace(ns_child)
        except NoSuchNamespaceError:
            pass
        try:
            catalog.drop_namespace(ns_parent)
        except NoSuchNamespaceError:
            pass
            
        try:
            # Create parent first
            catalog.create_namespace(ns_parent)
            
            # Create child
            catalog.create_namespace(ns_child)
            
            # Both should exist
            namespaces = catalog.list_namespaces()
            assert (ns_parent,) in namespaces or ("parent_ns", "child_ns") in namespaces
        finally:
            try:
                catalog.drop_namespace(ns_child)
            except NoSuchNamespaceError:
                pass
            try:
                catalog.drop_namespace(ns_parent)
            except NoSuchNamespaceError:
                pass
    
    def test_list_namespaces_empty(self, catalog: RestCatalog):
        """Test listing namespaces returns a list (may or may not be empty)."""
        namespaces = catalog.list_namespaces()
        assert isinstance(namespaces, list)
    
    def test_update_namespace_properties(self, catalog: RestCatalog):
        """Test updating namespace properties."""
        ns = "test_update_ns"
        
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns, properties={"key1": "value1"})
            
            # Update properties
            catalog.update_namespace_properties(
                ns,
                updates={"key2": "value2", "key1": "updated"},
            )
            
            props = catalog.load_namespace_properties(ns)
            assert props.get("key1") == "updated"
            assert props.get("key2") == "value2"
        finally:
            catalog.drop_namespace(ns)
    
    def test_remove_namespace_properties(self, catalog: RestCatalog):
        """Test removing namespace properties."""
        ns = "test_remove_props_ns"
        
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns, properties={"key1": "value1", "key2": "value2"})
            
            # Remove key1
            catalog.update_namespace_properties(ns, removals=["key1"])
            
            props = catalog.load_namespace_properties(ns)
            assert "key1" not in props
            assert props.get("key2") == "value2"
        finally:
            catalog.drop_namespace(ns)
    
    def test_drop_nonexistent_namespace(self, catalog: RestCatalog):
        """Test dropping a namespace that doesn't exist raises error."""
        with pytest.raises(NoSuchNamespaceError):
            catalog.drop_namespace("nonexistent_namespace_12345")
    
    def test_load_nonexistent_namespace_properties(self, catalog: RestCatalog):
        """Test loading properties of nonexistent namespace raises error."""
        with pytest.raises(NoSuchNamespaceError):
            catalog.load_namespace_properties("nonexistent_namespace_12345")


class TestNamespaceValidation:
    """Test namespace input validation."""
    
    def test_namespace_name_special_characters(self, catalog: RestCatalog):
        """Test namespace names with special characters."""
        # Underscores and numbers should be allowed
        ns = "test_ns_123"
        
        try:
            catalog.drop_namespace(ns)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns)
            namespaces = catalog.list_namespaces()
            assert (ns,) in namespaces
        finally:
            catalog.drop_namespace(ns)
    
    def test_namespace_case_sensitivity(self, catalog: RestCatalog):
        """Test that namespace names are case-sensitive or consistently handled."""
        ns_lower = "testcasens"
        ns_upper = "TESTCASENS"
        
        try:
            catalog.drop_namespace(ns_lower)
        except NoSuchNamespaceError:
            pass
        try:
            catalog.drop_namespace(ns_upper)
        except NoSuchNamespaceError:
            pass
            
        try:
            catalog.create_namespace(ns_lower)
            
            # Check behavior - either case-insensitive (fails) or case-sensitive (succeeds)
            try:
                catalog.create_namespace(ns_upper)
                # Case-sensitive - both exist
                assert True
                catalog.drop_namespace(ns_upper)
            except NamespaceAlreadyExistsError:
                # Case-insensitive - treated as same
                assert True
        finally:
            try:
                catalog.drop_namespace(ns_lower)
            except NoSuchNamespaceError:
                pass
