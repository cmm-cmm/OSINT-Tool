"""
SQLite-backed response cache for OSINT Tool.

Prevents redundant API calls by storing results with configurable TTL.
Thread-safe via connection-per-call pattern.
"""
import json
import hashlib
import sqlite3
import time
import logging
from pathlib import Path
from typing import Any

from modules.constants import USER_CONFIG_DIR

logger = logging.getLogger("osint.cache")

DEFAULT_TTL = 3600 * 24  # 24 hours
DEFAULT_DB_PATH = str(USER_CONFIG_DIR / "cache.db")

# Schema: key (SHA-256 hex), value (JSON), expires_at (unix timestamp)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS cache (
    key       TEXT PRIMARY KEY,
    value     TEXT NOT NULL,
    expires_at REAL NOT NULL,
    created_at REAL NOT NULL,
    module    TEXT DEFAULT '',
    hits      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_module  ON cache(module);
"""


class OsintCache:
    """
    Thread-safe SQLite cache for OSINT module results.

    Usage::
        cache = OsintCache()
        key = cache.make_key("whois", "example.com")
        data = cache.get(key)
        if data is None:
            data = perform_whois("example.com")
            cache.set(key, data, ttl=3600)
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH, default_ttl: int = DEFAULT_TTL):
        self.db_path = db_path
        self.default_ttl = default_ttl
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except sqlite3.Error as e:
            logger.warning("Cache DB init failed: %s", e)

    @staticmethod
    def make_key(module: str, target: str, extra: str = "") -> str:
        """Generate a deterministic cache key from module + target."""
        raw = f"{module}:{target}:{extra}".lower().strip()
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, key: str) -> Any | None:
        """Return cached value or None if missing/expired."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
                ).fetchone()
                if row is None:
                    return None
                if row["expires_at"] < time.time():
                    conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                    return None
                conn.execute("UPDATE cache SET hits = hits + 1 WHERE key = ?", (key,))
                return json.loads(row["value"])
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.debug("Cache get failed for %s: %s", key, e)
            return None

    def set(self, key: str, value: Any, ttl: int | None = None, module: str = "") -> bool:
        """Store value with TTL. Returns True on success."""
        effective_ttl = ttl if ttl is not None else self.default_ttl
        try:
            serialized = json.dumps(value, ensure_ascii=False, default=str)
            now = time.time()
            with self._connect() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO cache
                       (key, value, expires_at, created_at, module, hits)
                       VALUES (?, ?, ?, ?, ?, 0)""",
                    (key, serialized, now + effective_ttl, now, module),
                )
            return True
        except (sqlite3.Error, TypeError) as e:
            logger.debug("Cache set failed for %s: %s", key, e)
            return False

    def delete(self, key: str) -> None:
        """Remove a single cache entry."""
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        except sqlite3.Error as e:
            logger.debug("Cache delete failed: %s", e)

    def clear(self, module: str = "") -> int:
        """Delete all entries (or only entries for a specific module). Returns count."""
        try:
            with self._connect() as conn:
                if module:
                    cur = conn.execute("DELETE FROM cache WHERE module = ?", (module,))
                else:
                    cur = conn.execute("DELETE FROM cache")
                return cur.rowcount
        except sqlite3.Error:
            return 0

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns number deleted."""
        try:
            with self._connect() as conn:
                cur = conn.execute("DELETE FROM cache WHERE expires_at < ?", (time.time(),))
                deleted = cur.rowcount
            if deleted:
                logger.debug("Cache: pruned %d expired entries", deleted)
            return deleted
        except sqlite3.Error:
            return 0

    def stats(self) -> dict:
        """Return cache statistics."""
        try:
            with self._connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
                expired = conn.execute(
                    "SELECT COUNT(*) FROM cache WHERE expires_at < ?", (time.time(),)
                ).fetchone()[0]
                by_module = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT module, COUNT(*) FROM cache GROUP BY module"
                    ).fetchall()
                    if row[0]
                }
                total_hits = conn.execute("SELECT SUM(hits) FROM cache").fetchone()[0] or 0
            return {
                "total_entries": total,
                "expired_entries": expired,
                "active_entries": total - expired,
                "total_hits": total_hits,
                "by_module": by_module,
                "db_path": self.db_path,
            }
        except sqlite3.Error:
            return {"total_entries": 0, "error": "stats unavailable"}


# Module-level singleton (lazy-initialized)
_cache_instance: OsintCache | None = None


def get_cache() -> OsintCache:
    """Return the shared OsintCache singleton."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = OsintCache()
    return _cache_instance


def cached(module: str, ttl: int = DEFAULT_TTL):
    """
    Decorator: cache a function's result by (module, first_arg).

    Usage::
        @cached("whois", ttl=3600)
        def whois_lookup(domain: str) -> dict:
            ...
    """
    def decorator(func):
        import functools

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            target = str(args[0]) if args else ""
            extra = str(sorted(kwargs.items()))
            key = OsintCache.make_key(module, target, extra)
            cache = get_cache()
            hit = cache.get(key)
            if hit is not None:
                logger.debug("Cache HIT: %s/%s", module, target)
                return hit
            result = func(*args, **kwargs)
            if result is not None:
                cache.set(key, result, ttl=ttl, module=module)
            return result

        wrapper._cache_module = module
        wrapper._cache_ttl = ttl
        return wrapper
    return decorator
