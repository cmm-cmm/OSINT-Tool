"""Tests for modules/db.py (OsintDB SQLite backend)."""
import json
import datetime
import pytest
from pathlib import Path


@pytest.fixture
def db(tmp_path):
    """Create a fresh OsintDB instance backed by a temp DB."""
    from modules.db import OsintDB
    return OsintDB(db_path=str(tmp_path / "test_scans.db"))


SAMPLE_DATA = {
    "whois": {"registrar": "Test Registrar", "creation_date": "2010-01-01"},
    "dns": {"records": {"A": ["93.184.216.34"]}},
}


class TestOsintDBInit:
    def test_creates_db_file(self, tmp_path):
        from modules.db import OsintDB
        db_path = str(tmp_path / "new_db.db")
        OsintDB(db_path=db_path)
        assert Path(db_path).exists()

    def test_creates_parent_dirs(self, tmp_path):
        from modules.db import OsintDB
        db_path = str(tmp_path / "nested" / "dir" / "scans.db")
        OsintDB(db_path=db_path)
        assert Path(db_path).exists()


class TestSaveScan:
    def test_save_returns_id(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        assert isinstance(scan_id, str)
        assert len(scan_id) == 16

    def test_save_and_get(self, db):
        scan_id = db.save_scan("example.com", ["whois", "dns"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        assert record is not None
        assert record["target"] == "example.com"

    def test_data_is_deserialized(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        assert isinstance(record["data"], dict)
        assert isinstance(record["modules"], list)

    def test_tags_stored_correctly(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA, tags=["test", "scheduled"])
        record = db.get_scan(scan_id)
        assert "test" in record["tags"]
        assert "scheduled" in record["tags"]

    def test_notes_stored(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA, notes="Test note")
        record = db.get_scan(scan_id)
        assert record["notes"] == "Test note"

    def test_upsert_updates_existing(self, db):
        scan_id1 = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        new_data = {"whois": {"registrar": "Updated Registrar"}}
        scan_id2 = db.save_scan("example.com", ["whois"], new_data, upsert=True)
        assert scan_id1 == scan_id2
        record = db.get_scan(scan_id1)
        assert record["data"]["whois"]["registrar"] == "Updated Registrar"

    def test_upsert_false_does_not_insert_duplicate(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA, upsert=False)
        # Second call with upsert=False should not crash; same key returned
        scan_id2 = db.save_scan("example.com", ["whois"], SAMPLE_DATA, upsert=False)
        assert scan_id == scan_id2

    def test_modules_sorted(self, db):
        scan_id = db.save_scan("example.com", ["dns", "whois"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        assert record["modules"] == ["dns", "whois"]

    def test_different_targets_different_ids(self, db):
        id1 = db.save_scan("a.com", ["whois"], {})
        id2 = db.save_scan("b.com", ["whois"], {})
        assert id1 != id2


class TestGetScan:
    def test_missing_id_returns_none(self, db):
        result = db.get_scan("nonexistent123456")
        assert result is None

    def test_returned_dict_has_expected_keys(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        record = db.get_scan(scan_id)
        for key in ("id", "target", "modules", "data", "created_at", "updated_at"):
            assert key in record


class TestSearch:
    def test_search_by_target(self, db):
        db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        db.save_scan("other.com", ["whois"], {})
        results = db.search(query="example")
        assert len(results) == 1
        assert results[0]["target"] == "example.com"

    def test_search_empty_returns_all(self, db):
        db.save_scan("a.com", ["whois"], {})
        db.save_scan("b.com", ["dns"], {})
        results = db.search()
        assert len(results) == 2

    def test_search_by_module(self, db):
        db.save_scan("a.com", ["whois"], {})
        db.save_scan("b.com", ["dns"], {})
        results = db.search(module="dns")
        assert len(results) == 1
        assert results[0]["target"] == "b.com"

    def test_search_limit(self, db):
        for i in range(5):
            db.save_scan(f"target{i}.com", ["whois"], {})
        results = db.search(limit=3)
        assert len(results) == 3

    def test_search_no_match_returns_empty(self, db):
        db.save_scan("example.com", ["whois"], {})
        results = db.search(query="zzz_no_match")
        assert results == []


class TestListTargets:
    def test_returns_unique_targets(self, db):
        db.save_scan("a.com", ["whois"], {})
        db.save_scan("b.com", ["whois"], {})
        targets = db.list_targets()
        assert set(targets) == {"a.com", "b.com"}

    def test_empty_db_returns_empty_list(self, db):
        assert db.list_targets() == []

    def test_limit_respected(self, db):
        for i in range(10):
            db.save_scan(f"t{i}.com", ["whois"], {})
        targets = db.list_targets(limit=5)
        assert len(targets) == 5


class TestDeleteScan:
    def test_delete_existing(self, db):
        scan_id = db.save_scan("example.com", ["whois"], SAMPLE_DATA)
        result = db.delete_scan(scan_id)
        assert result is True
        assert db.get_scan(scan_id) is None

    def test_delete_nonexistent_returns_false(self, db):
        result = db.delete_scan("does_not_exist")
        assert result is False


class TestStats:
    def test_empty_db_stats(self, db):
        stats = db.stats()
        assert stats["total_scans"] == 0
        assert stats["unique_targets"] == 0
        assert stats["total_findings"] == 0

    def test_stats_after_save(self, db):
        db.save_scan("a.com", ["whois"], {})
        db.save_scan("b.com", ["whois"], {})
        stats = db.stats()
        assert stats["total_scans"] == 2
        assert stats["unique_targets"] == 2

    def test_stats_contains_db_path(self, db):
        stats = db.stats()
        assert "db_path" in stats
        assert stats["db_path"] == db.db_path


class TestExtractFindings:
    def test_email_breach_creates_finding(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [{"name": "BreachDB", "date": "2021-01-01", "pwn_count": 5000}]
                }
            }
        }
        scan_id = db.save_scan("victim@example.com", ["email"], data)
        findings = db.get_findings(scan_id=scan_id)
        breach_findings = [f for f in findings if f["finding_type"] == "breach"]
        assert len(breach_findings) == 1
        assert "BreachDB" in breach_findings[0]["title"]
        assert breach_findings[0]["severity"] == "high"

    def test_shodan_cve_creates_critical_finding(self, db):
        data = {
            "ip": {
                "shodan": {"vulns": ["CVE-2021-44228"], "ports": [80, 443]}
            }
        }
        scan_id = db.save_scan("192.0.2.1", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        cve_findings = [f for f in findings if f["finding_type"] == "cve"]
        assert len(cve_findings) == 1
        assert cve_findings[0]["severity"] == "critical"

    def test_open_ports_creates_info_finding(self, db):
        data = {
            "ip": {
                "shodan": {"ports": [22, 80, 443], "vulns": []}
            }
        }
        scan_id = db.save_scan("10.0.0.1", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        port_findings = [f for f in findings if f["finding_type"] == "open_ports"]
        assert len(port_findings) == 1
        assert port_findings[0]["severity"] == "info"

    def test_username_found_creates_finding(self, db):
        data = {
            "username": {
                "found": [{"platform": "Twitter", "url": "https://twitter.com/user"}]
            }
        }
        scan_id = db.save_scan("testuser", ["username"], data)
        findings = db.get_findings(scan_id=scan_id)
        username_findings = [f for f in findings if f["finding_type"] == "profile_found"]
        assert len(username_findings) == 1

    def test_no_findings_for_clean_data(self, db):
        scan_id = db.save_scan("clean.com", ["whois"], {"whois": {"registrar": "ICANN"}})
        findings = db.get_findings(scan_id=scan_id)
        assert findings == []


class TestGetFindings:
    def test_filter_by_severity(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [{"name": "TestBreachDB", "date": "2020-01-01", "pwn_count": 1000}]
                }
            }
        }
        scan_id = db.save_scan("user@test.com", ["email"], data)
        high_findings = db.get_findings(scan_id=scan_id, severity="high")
        assert all(f["severity"] == "high" for f in high_findings)

    def test_all_findings_when_no_filter(self, db):
        data = {
            "email": {"hibp": {"breaches": [{"name": "B1", "date": "2020-01-01", "pwn_count": 100}]}},
            "ip": {"shodan": {"ports": [22], "vulns": []}}
        }
        scan_id = db.save_scan("test@test.com", ["email", "ip"], data)
        all_findings = db.get_findings(scan_id=scan_id)
        assert len(all_findings) >= 2


class TestScanIdDeterminism:
    def test_same_target_same_day_same_id(self):
        from modules.db import _scan_id
        id1 = _scan_id("example.com", ["whois", "dns"])
        id2 = _scan_id("example.com", ["whois", "dns"])
        assert id1 == id2

    def test_module_order_normalized(self):
        from modules.db import _scan_id
        id1 = _scan_id("example.com", ["whois", "dns"])
        id2 = _scan_id("example.com", ["dns", "whois"])
        assert id1 == id2

    def test_different_targets_different_ids(self):
        from modules.db import _scan_id
        id1 = _scan_id("a.com", ["whois"])
        id2 = _scan_id("b.com", ["whois"])
        assert id1 != id2

    def test_id_is_16_chars(self):
        from modules.db import _scan_id
        scan_id = _scan_id("example.com", ["whois"])
        assert len(scan_id) == 16