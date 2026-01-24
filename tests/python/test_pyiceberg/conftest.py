"""
PyIceberg-specific test configuration.

Maps the shared fixtures to the names expected by the migrated tests.
"""

import pytest


# Map the shared pyiceberg_catalog fixture to 'catalog' for compatibility
@pytest.fixture
def catalog(pyiceberg_catalog):
    """Alias for pyiceberg_catalog fixture."""
    return pyiceberg_catalog
