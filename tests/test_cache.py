"""Tests for modules/cache.py (created in Phase 2)."""
import json
import time
import pytest
from pathlib import Path


@pytest.fixture
def cache(tmp_path):
    """Create a fresh OsintCache instance backed by a temp DB."""
    from modules.cache import OsintCache
    return OsintCache(db_path=str(tmp_path / "test_cache.db"))


class TestOsintCache:
    def test_miss_returns_none(self, cache):
        result = cache.get("missing_key")
        assert result is None

    def test_set_and_get(self, cache):
        cache.set("key1", {"data": "value"})
        result = cache.get("key1")
        assert result == {"data": "value"}

    def test_ttl_expiry(self, cache):
        cache.set("expire_key", {"x": 1}, ttl=1)
        time.sleep(1.1)
        result = cache.get("expire_key")
        assert result is None

    def test_overwrite(self, cache):
        cache.set("k", {"v": 1})
        cache.set("k", {"v": 2})
        assert cache.get("k") == {"v": 2}

    def test_delete(self, cache):
        cache.set("del_key", {"x": "y"})
        cache.delete("del_key")
        assert cache.get("del_key") is None

    def test_delete_nonexistent_ok(self, cache):
        cache.delete("nonexistent")  # Should not raise

    def test_clear(self, cache):
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None

    def test_make_key(self, cache):
        k1 = cache.make_key("whois", "example.com")
        k2 = cache.make_key("whois", "example.com")
        k3 = cache.make_key("dns", "example.com")
        assert k1 == k2
        assert k1 != k3

    def test_stats(self, cache):
        cache.set("s1", 1)
        cache.set("s2", 2)
        stats = cache.stats()
        assert stats["total_entries"] >= 2

    def test_cleanup_expired(self, cache):
        cache.set("old", {"x": 1}, ttl=1)
        time.sleep(1.1)
        cache.cleanup_expired()
        assert cache.get("old") is None

    def test_complex_value(self, cache):
        complex_val = {
            "list": [1, 2, 3],
            "nested": {"key": "value"},
            "number": 42,
            "bool": True,
        }
        cache.set("complex", complex_val)
        assert cache.get("complex") == complex_val
