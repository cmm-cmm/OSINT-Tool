"""Tests for modules/db.py."""
import json
import pytest
from pathlib import Path


@pytest.fixture
def db(tmp_path):
    """Create a fresh OsintDB backed by a temp SQLite file."""
    from modules.db import OsintDB
    return OsintDB(db_path=str(tmp_path / "test_scans.db"))


SAMPLE_DATA = {
    "whois": {"registrar": "TestRegistrar", "emails": ["admin@example.com"]},
    "dns": {"records": {"A": ["1.2.3.4"]}},
}


class TestOsintDBInit:
    def test_creates_db_file(self, tmp_path):
        from modules.db import OsintDB
        db_path = str(tmp_path / "new.db")
        OsintDB(db_path=db_path)
        assert Path(db_path).exists()

    def test_creates_parent_dirs(self, tmp_path):
        from modules.db import OsintDB
        db_path = str(tmp_path / "nested" / "dir" / "scans.db")
        OsintDB(db_path=db_path)
        assert Path(db_path).exists()


class TestSaveScan:
    def test_returns_scan_id_string(self, db):
        scan_id = db.save_scan("example.com", ["whois", "dns"], SAMPLE_DATA)
        assert isinstance(scan_id, str)
        assert len(scan_id) == 16

    def test_scan_is_retrievable(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        assert record is not None
        assert record["target"] == "example.com"

    def test_upsert_updates_existing(self, db):
        scan_id1 = db.save_scan("example.com", ["whois"], {"whois": {"v": 1}})
        scan_id2 = db.save_scan("example.com", ["whois"], {"whois": {"v": 2}})
        # Same target + same day = same ID (upsert)
        assert scan_id1 == scan_id2
        record = db.get_scan(scan_id1)
        assert record["data"]["whois"]["v"] == 2

    def test_upsert_false_creates_new_on_conflict(self, db):
        """With upsert=False, a duplicate ID should either insert or be ignored gracefully."""
        scan_id = db.save_scan("example.com", ["whois"], {"v": 1}, upsert=False)
        assert isinstance(scan_id, str)

    def test_tags_stored(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA, tags=["pentest", "vip"])
        record = db.get_scan(scan_id)
        assert "pentest" in record["tags"]
        assert "vip" in record["tags"]

    def test_notes_stored(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA, notes="Important client")
        record = db.get_scan(scan_id)
        assert record["notes"] == "Important client"

    def test_modules_sorted_in_id(self, db):
        """Scan IDs should be deterministic regardless of module order."""
        from modules.db import _scan_id
        id1 = _scan_id("example.com", ["whois", "dns"])
        id2 = _scan_id("example.com", ["dns", "whois"])
        assert id1 == id2


class TestGetScan:
    def test_nonexistent_returns_none(self, db):
        result = db.get_scan("nonexistent_id_12345")
        assert result is None

    def test_data_deserialized(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        assert isinstance(record["data"], dict)
        assert isinstance(record["modules"], list)
        assert isinstance(record["tags"], list)


class TestSearch:
    def test_search_by_target(self, db):
        db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        db.save_scan("other.org", ["dns"], {})
        results = db.search(query="example")
        assert len(results) == 1
        assert results[0]["target"] == "example.com"

    def test_search_empty_returns_all(self, db):
        db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        db.save_scan("other.org", ["dns"], {})
        results = db.search()
        assert len(results) == 2

    def test_search_by_module(self, db):
        db.save_scan("example.com", ["whois", "dns"], SAMPLE_DATA)
        db.save_scan("other.org", ["ssl"], {})
        results = db.search(module="ssl")
        assert len(results) == 1
        assert results[0]["target"] == "other.org"

    def test_search_limit(self, db):
        for i in range(5):
            db.save_scan(f"target{i}.com", ["whois"], {})
        results = db.search(limit=3)
        assert len(results) == 3

    def test_search_no_match(self, db):
        db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        results = db.search(query="zzznomatch")
        assert results == []


class TestListTargets:
    def test_returns_unique_targets(self, db):
        db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        db.save_scan("other.org", ["dns"], {})
        targets = db.list_targets()
        assert "example.com" in targets
        assert "other.org" in targets

    def test_empty_db(self, db):
        targets = db.list_targets()
        assert targets == []

    def test_limit_respected(self, db):
        for i in range(10):
            db.save_scan(f"t{i}.com", [f"mod{i}"], {})
        targets = db.list_targets(limit=3)
        assert len(targets) == 3


class TestDeleteScan:
    def test_delete_existing(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        result = db.delete_scan(scan_id)
        assert result is True
        assert db.get_scan(scan_id) is None

    def test_delete_nonexistent_returns_false(self, db):
        result = db.delete_scan("no_such_id")
        assert result is False

    def test_findings_deleted_with_scan(self, db):
        data_with_breach = {
            "email": {"hibp": {"breaches": [{"name": "Adobe", "date": "2013-10-04", "pwn_count": 153000000}]}}
        }
        scan_id = db.save_scan("test@ex.com", ["email"], data_with_breach)
        db.delete_scan(scan_id)
        findings = db.get_findings(scan_id=scan_id)
        assert findings == []


class TestStats:
    def test_empty_db_stats(self, db):
        stats = db.stats()
        assert stats["total_scans"] == 0
        assert stats["unique_targets"] == 0
        assert stats["total_findings"] == 0

    def test_counts_scans(self, db):
        db.save_scan("a.com", ["whois"], SAMPLE_DATA)
        db.save_scan("b.com", ["dns"], {})
        stats = db.stats()
        assert stats["total_scans"] == 2
        assert stats["unique_targets"] == 2

    def test_db_path_in_stats(self, db):
        stats = db.stats()
        assert "db_path" in stats
        assert stats["db_path"] == db.db_path


class TestExtractFindings:
    def test_breach_creates_finding(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [
                        {"name": "Adobe", "date": "2013-10-04", "pwn_count": 153000000}
                    ]
                }
            }
        }
        scan_id = db.save_scan("test@example.com", ["email"], data)
        findings = db.get_findings(scan_id=scan_id)
        assert any(f["finding_type"] == "breach" for f in findings)
        assert any("Adobe" in f["title"] for f in findings)

    def test_cve_creates_critical_finding(self, db):
        data = {
            "ip": {
                "shodan": {
                    "vulns": ["CVE-2021-44228", "CVE-2022-0001"],
                    "ports": [80, 443]
                }
            }
        }
        scan_id = db.save_scan("1.2.3.4", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        cve_findings = [f for f in findings if f["finding_type"] == "cve"]
        assert len(cve_findings) == 2
        assert all(f["severity"] == "critical" for f in cve_findings)

    def test_open_ports_creates_finding(self, db):
        data = {"ip": {"shodan": {"ports": [22, 80, 443, 8080]}}}
        scan_id = db.save_scan("1.2.3.4", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        port_findings = [f for f in findings if f["finding_type"] == "open_ports"]
        assert len(port_findings) == 1

    def test_secret_exposure_finding(self, db):
        data = {
            "secrets": {
                "findings": [
                    {"type": "AWS_ACCESS_KEY", "file": "config.py", "severity": "HIGH"}
                ]
            }
        }
        scan_id = db.save_scan("repo", ["secrets"], data)
        findings = db.get_findings(scan_id=scan_id)
        secret_findings = [f for f in findings if f["finding_type"] == "exposure"]
        assert len(secret_findings) == 1
        assert secret_findings[0]["severity"] == "high"

    def test_username_platforms_finding(self, db):
        data = {
            "username": {
                "found": [
                    {"platform": "Twitter", "url": "https://twitter.com/user"},
                    {"platform": "GitHub", "url": "https://github.com/user"},
                ]
            }
        }
        scan_id = db.save_scan("testuser", ["username"], data)
        findings = db.get_findings(scan_id=scan_id)
        profile_findings = [f for f in findings if f["finding_type"] == "profile_found"]
        assert len(profile_findings) == 2


class TestGetFindings:
    def test_filter_by_severity(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [{"name": "Breach1", "date": "2020-01-01", "pwn_count": 1000}]
                }
            }
        }
        scan_id = db.save_scan("u@e.com", ["email"], data)
        high_findings = db.get_findings(severity="high")
        assert all(f["severity"] == "high" for f in high_findings)

    def test_no_filter_returns_all(self, db):
        data = {"ip": {"shodan": {"vulns": ["CVE-2021-1234"], "ports": [80]}}}
        scan_id = db.save_scan("1.1.1.1", ["ip"], data)
        all_findings = db.get_findings()
        assert len(all_findings) >= 2


class TestRowToDict:
    def test_json_fields_deserialized(self, db):
        scan_id = db.save_scan("example.com", ["whois", "dns"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        # These fields should be Python objects, not JSON strings
        assert isinstance(record["data"], dict)
        assert isinstance(record["modules"], list)
        assert isinstance(record["tags"], list)