"""
SQLite database backend for OSINT Tool scan results.

Provides persistent storage, querying, and deduplication of scan results.
"""
from __future__ import annotations
import json
import sqlite3
import datetime
import hashlib
import logging
from pathlib import Path

from modules.constants import USER_CONFIG_DIR

logger = logging.getLogger("osint.db")

DEFAULT_DB_PATH = str(USER_CONFIG_DIR / "scans.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    modules     TEXT NOT NULL,
    data        TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    tags        TEXT DEFAULT '[]',
    notes       TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_updated ON scans(updated_at);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT REFERENCES scans(id),
    module      TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity    TEXT DEFAULT 'info',
    title       TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_type  ON findings(finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_sev   ON findings(severity);
"""


def _scan_id(target: str, modules: list[str]) -> str:
    raw = f"{target}:{','.join(sorted(modules))}:{datetime.datetime.utcnow().date()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class OsintDB:
    """
    SQLite backend for persisting OSINT scan results with search capabilities.

    Usage::
        db = OsintDB()
        scan_id = db.save_scan("example.com", ["whois", "dns"], all_data)
        results = db.search("example.com")
        record = db.get_scan(scan_id)
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=15)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        try:
            with self._connect() as conn:
                conn.executescript(_SCHEMA)
        except sqlite3.Error as e:
            logger.error("DB init failed: %s", e)

    def save_scan(
        self,
        target: str,
        modules: list[str],
        data: dict,
        tags: list[str] | None = None,
        notes: str = "",
        upsert: bool = True,
    ) -> str:
        """
        Save scan results. Returns the scan ID.
        If upsert=True, updates existing record for same target+day.
        """
        scan_id = _scan_id(target, modules)
        now = datetime.datetime.utcnow().isoformat(timespec="seconds")
        tag_list = tags or []

        try:
            with self._connect() as conn:
                if upsert:
                    existing = conn.execute(
                        "SELECT id FROM scans WHERE id = ?", (scan_id,)
                    ).fetchone()
                    if existing:
                        conn.execute(
                            "UPDATE scans SET data=?, updated_at=?, tags=?, notes=? WHERE id=?",
                            (json.dumps(data, default=str), now,
                             json.dumps(tag_list), notes, scan_id),
                        )
                        logger.debug("DB: updated scan %s", scan_id)
                        return scan_id

                conn.execute(
                    "INSERT INTO scans (id, target, modules, data, created_at, updated_at, tags, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id, target, json.dumps(sorted(modules)),
                     json.dumps(data, default=str), now, now,
                     json.dumps(tag_list), notes),
                )
                self._extract_findings(conn, scan_id, data, now)
                logger.debug("DB: saved scan %s for %s", scan_id, target)
        except sqlite3.Error as e:
            logger.error("DB save failed: %s", e)

        return scan_id

    def get_scan(self, scan_id: str) -> dict | None:
        """Retrieve a scan record by ID."""
        try:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM scans WHERE id = ?", (scan_id,)
                ).fetchone()
                if row:
                    return self._row_to_dict(row)
        except sqlite3.Error:
            pass
        return None

    def search(
        self,
        query: str = "",
        module: str = "",
        limit: int = 20,
        offset: int = 0,
    ) -> list[dict]:
        """Search scans by target string and/or module."""
        try:
            with self._connect() as conn:
                if query and module:
                    rows = conn.execute(
                        "SELECT id, target, modules, created_at, updated_at, tags FROM scans"
                        " WHERE target LIKE ? AND modules LIKE ?"
                        " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                        [f"%{query}%", f'%"{module}"%', limit, offset],
                    ).fetchall()
                elif query:
                    rows = conn.execute(
                        "SELECT id, target, modules, created_at, updated_at, tags FROM scans"
                        " WHERE target LIKE ?"
                        " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                        [f"%{query}%", limit, offset],
                    ).fetchall()
                elif module:
                    rows = conn.execute(
                        "SELECT id, target, modules, created_at, updated_at, tags FROM scans"
                        " WHERE modules LIKE ?"
                        " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                        [f'%"{module}"%', limit, offset],
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT id, target, modules, created_at, updated_at, tags FROM scans"
                        " ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                        [limit, offset],
                    ).fetchall()
                return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def list_targets(self, limit: int = 50) -> list[str]:
        """Return unique targets sorted by most recent scan."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT DISTINCT target FROM scans ORDER BY updated_at DESC LIMIT ?", (limit,)
                ).fetchall()
                return [r[0] for r in rows]
        except sqlite3.Error:
            return []

    def get_findings(self, scan_id: str | None = None, severity: str | None = None) -> list[dict]:
        """Return findings, optionally filtered by scan ID and/or severity."""
        try:
            with self._connect() as conn:
                if scan_id and severity:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE scan_id = ? AND severity = ?"
                        " ORDER BY created_at DESC",
                        [scan_id, severity],
                    ).fetchall()
                elif scan_id:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE scan_id = ? ORDER BY created_at DESC",
                        [scan_id],
                    ).fetchall()
                elif severity:
                    rows = conn.execute(
                        "SELECT * FROM findings WHERE severity = ? ORDER BY created_at DESC",
                        [severity],
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM findings ORDER BY created_at DESC"
                    ).fetchall()
                return [dict(r) for r in rows]
        except sqlite3.Error:
            return []

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and its associated findings."""
        try:
            with self._connect() as conn:
                conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                return cur.rowcount > 0
        except sqlite3.Error:
            return False

    def stats(self) -> dict:
        """Return database statistics."""
        try:
            with self._connect() as conn:
                total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                total_targets = conn.execute("SELECT COUNT(DISTINCT target) FROM scans").fetchone()[0]
                total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                severity_counts = {
                    row[0]: row[1]
                    for row in conn.execute(
                        "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                    ).fetchall()
                }
            return {
                "total_scans": total_scans,
                "unique_targets": total_targets,
                "total_findings": total_findings,
                "findings_by_severity": severity_counts,
                "db_path": self.db_path,
            }
        except sqlite3.Error:
            return {}

    def _extract_findings(self, conn: sqlite3.Connection, scan_id: str, data: dict, now: str) -> None:
        """Auto-extract notable findings from scan data and store them."""
        import uuid

        def add(module: str, finding_type: str, title: str, detail: str = "", severity: str = "info"):
            fid = str(uuid.uuid4())[:12]
            conn.execute(
                "INSERT INTO findings (id, scan_id, module, finding_type, severity, title, detail, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (fid, scan_id, module, finding_type, severity, title, detail, now)
            )

        # Email breaches
        hibp = data.get("email", {}).get("hibp", {})
        for breach in (hibp.get("breaches", []) or []):
            add("email", "breach", f"Found in breach: {breach.get('name', '?')}",
                f"Date: {breach.get('date', '?')}, Records: {breach.get('pwn_count', 0):,}",
                severity="high")

        # Open ports / CVEs
        shodan = data.get("ip", {}).get("shodan", {})
        for vuln in (shodan.get("vulns", []) or []):
            add("ip", "cve", f"CVE detected: {vuln}", severity="critical")
        if shodan.get("ports"):
            add("ip", "open_ports",
                f"{len(shodan['ports'])} open ports found",
                str(shodan["ports"])[:200], severity="info")

        # Secrets
        for finding in (data.get("secrets", {}).get("findings", []) or []):
            sev = "high" if finding.get("severity") in ("HIGH", "CRITICAL") else "medium"
            add("secrets", "exposure",
                f"Secret exposed: {finding.get('type', '?')}",
                f"File: {finding.get('file', '?')}", severity=sev)

        # Username found on platforms
        for item in (data.get("username", {}).get("found", []) or [])[:5]:
            add("username", "profile_found",
                f"Username found on {item.get('platform', '?')}",
                item.get("url", ""), severity="info")

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        for field in ("data", "modules", "tags"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d


# Module-level singleton
_db_instance: OsintDB | None = None


def get_db() -> OsintDB:
    """Return the shared OsintDB singleton."""
    global _db_instance
    if _db_instance is None:
        _db_instance = OsintDB()
    return _db_instance
