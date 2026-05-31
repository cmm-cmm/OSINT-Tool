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

    def test_clear_by_module(self, cache):
        cache.set("a", {"v": 1}, module="whois")
        cache.set("b", {"v": 2}, module="dns")
        deleted = cache.clear(module="whois")
        assert deleted == 1
        assert cache.get("a") is None
        assert cache.get("b") == {"v": 2}

    def test_clear_all_returns_count(self, cache):
        cache.set("x", 1)
        cache.set("y", 2)
        cache.set("z", 3)
        deleted = cache.clear()
        assert deleted == 3

    def test_stats_by_module(self, cache):
        cache.set("k1", 1, module="whois")
        cache.set("k2", 2, module="whois")
        cache.set("k3", 3, module="dns")
        stats = cache.stats()
        assert stats["by_module"].get("whois", 0) == 2
        assert stats["by_module"].get("dns", 0) == 1

    def test_stats_total_hits(self, cache):
        cache.set("h", {"data": "val"})
        cache.get("h")
        cache.get("h")
        stats = cache.stats()
        assert stats["total_hits"] >= 2

    def test_stats_active_vs_expired(self, cache):
        cache.set("active", 1, ttl=9999)
        cache.set("expired", 2, ttl=1)
        time.sleep(1.1)
        stats = cache.stats()
        assert stats["expired_entries"] >= 1
        assert stats["active_entries"] >= 1


class TestCachedDecorator:
    def test_caches_function_result(self, tmp_path):
        from modules.cache import OsintCache, cached
        import modules.cache as cache_module

        test_cache = OsintCache(db_path=str(tmp_path / "dec_test.db"))
        original = cache_module._cache_instance
        cache_module._cache_instance = test_cache

        try:
            call_count = []

            @cached("test_module", ttl=3600)
            def my_function(target: str) -> dict:
                call_count.append(1)
                return {"target": target, "data": "result"}

            result1 = my_function("example.com")
            result2 = my_function("example.com")

            assert result1 == result2
            assert len(call_count) == 1  # only called once
        finally:
            cache_module._cache_instance = original

    def test_different_args_different_cache_entries(self, tmp_path):
        from modules.cache import OsintCache, cached
        import modules.cache as cache_module

        test_cache = OsintCache(db_path=str(tmp_path / "dec_test2.db"))
        original = cache_module._cache_instance
        cache_module._cache_instance = test_cache

        try:
            call_count = []

            @cached("test_module2", ttl=3600)
            def lookup(target: str) -> dict:
                call_count.append(target)
                return {"target": target}

            lookup("a.com")
            lookup("b.com")
            lookup("a.com")  # should be cached

            assert len(call_count) == 2  # "a.com" and "b.com" each called once
        finally:
            cache_module._cache_instance = original

    def test_none_result_not_cached(self, tmp_path):
        from modules.cache import OsintCache, cached
        import modules.cache as cache_module

        test_cache = OsintCache(db_path=str(tmp_path / "dec_none.db"))
        original = cache_module._cache_instance
        cache_module._cache_instance = test_cache

        try:
            call_count = []

            @cached("none_module", ttl=3600)
            def returns_none(target: str):
                call_count.append(1)
                return None

            r1 = returns_none("target")
            r2 = returns_none("target")

            assert r1 is None
            assert r2 is None
            assert len(call_count) == 2  # not cached, called twice
        finally:
            cache_module._cache_instance = original

    def test_preserves_function_name(self):
        from modules.cache import cached

        @cached("test_preserve")
        def my_special_function(x):
            return x

        assert my_special_function.__name__ == "my_special_function"

    def test_cache_module_attribute(self):
        from modules.cache import cached

        @cached("my_module", ttl=1800)
        def some_func(x):
            return x

        assert some_func._cache_module == "my_module"
        assert some_func._cache_ttl == 1800

    def test_kwargs_affect_cache_key(self, tmp_path):
        from modules.cache import OsintCache, cached
        import modules.cache as cache_module

        test_cache = OsintCache(db_path=str(tmp_path / "dec_kwargs.db"))
        original = cache_module._cache_instance
        cache_module._cache_instance = test_cache

        try:
            call_count = []

            @cached("kwarg_module", ttl=3600)
            def query(target: str, extra: str = "") -> dict:
                call_count.append((target, extra))
                return {"target": target, "extra": extra}

            query("t.com", extra="v1")
            query("t.com", extra="v2")  # different kwargs → different cache key

            assert len(call_count) == 2
        finally:
            cache_module._cache_instance = original
