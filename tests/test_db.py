"""Tests for modules/db.py — SQLite scan result storage."""
import json
import pytest
from pathlib import Path


@pytest.fixture
def db(tmp_path):
    """Return a fresh OsintDB backed by a temporary file."""
    from modules.db import OsintDB
    return OsintDB(db_path=str(tmp_path / "test_scans.db"))


class TestOsintDBInit:
    def test_creates_db_file(self, tmp_path):
        from modules.db import OsintDB
        db_path = str(tmp_path / "sub" / "scans.db")
        db = OsintDB(db_path=db_path)
        assert Path(db_path).exists()

    def test_db_path_stored(self, db, tmp_path):
        assert "test_scans.db" in db.db_path


class TestSaveScan:
    def test_returns_scan_id(self, db):
        scan_id = db.save_scan("example.com", ["whois"], {"whois": {"registrar": "Test"}})
        assert isinstance(scan_id, str)
        assert len(scan_id) > 0

    def test_save_and_retrieve(self, db):
        data = {"whois": {"registrar": "ACME Corp"}}
        scan_id = db.save_scan("example.com", ["whois"], data)
        record = db.get_scan(scan_id)
        assert record is not None
        assert record["target"] == "example.com"

    def test_data_preserved(self, db):
        data = {"dns": {"A": ["1.2.3.4"]}, "whois": {"name": "John"}}
        scan_id = db.save_scan("test.com", ["dns", "whois"], data)
        record = db.get_scan(scan_id)
        loaded_data = record["data"]
        assert "dns" in loaded_data
        assert "whois" in loaded_data

    def test_modules_sorted_and_stored(self, db):
        scan_id = db.save_scan("test.com", ["dns", "whois"], {})
        record = db.get_scan(scan_id)
        # modules should be a list after deserialization
        assert isinstance(record["modules"], list)

    def test_upsert_updates_existing(self, db):
        data1 = {"whois": {"registrar": "Old Registrar"}}
        data2 = {"whois": {"registrar": "New Registrar"}}
        id1 = db.save_scan("example.com", ["whois"], data1, upsert=True)
        id2 = db.save_scan("example.com", ["whois"], data2, upsert=True)
        assert id1 == id2
        record = db.get_scan(id1)
        assert record["data"]["whois"]["registrar"] == "New Registrar"

    def test_upsert_false_skips_update(self, db):
        data1 = {"whois": {"registrar": "Old"}}
        data2 = {"whois": {"registrar": "New"}}
        id1 = db.save_scan("unique-upsert-false.com", ["whois"], data1, upsert=False)
        # Second call with upsert=False on same ID should attempt insert but fail silently
        id2 = db.save_scan("unique-upsert-false.com", ["whois"], data2, upsert=False)
        # Both IDs should be the same (same target+modules+date)
        assert id1 == id2

    def test_tags_stored(self, db):
        scan_id = db.save_scan("example.com", ["whois"], {}, tags=["pentest", "client"])
        record = db.get_scan(scan_id)
        assert "pentest" in record["tags"]
        assert "client" in record["tags"]

    def test_notes_stored(self, db):
        scan_id = db.save_scan("example.com", ["dns"], {}, notes="Test note")
        record = db.get_scan(scan_id)
        assert record["notes"] == "Test note"


class TestGetScan:
    def test_missing_id_returns_none(self, db):
        result = db.get_scan("nonexistent_id")
        assert result is None

    def test_returns_dict(self, db):
        scan_id = db.save_scan("example.com", ["whois"], {})
        record = db.get_scan(scan_id)
        assert isinstance(record, dict)

    def test_has_expected_fields(self, db):
        scan_id = db.save_scan("example.com", ["whois"], {})
        record = db.get_scan(scan_id)
        assert "target" in record
        assert "created_at" in record
        assert "updated_at" in record
        assert "data" in record


class TestSearch:
    def test_search_by_target(self, db):
        db.save_scan("searchable.com", ["whois"], {})
        results = db.search(query="searchable")
        assert len(results) >= 1
        assert any("searchable.com" in r["target"] for r in results)

    def test_search_no_match(self, db):
        results = db.search(query="zzz_no_match_xyz_abc")
        assert results == []

    def test_search_empty_query_returns_all(self, db):
        db.save_scan("a.com", ["whois"], {})
        db.save_scan("b.com", ["dns"], {})
        results = db.search(query="", limit=100)
        assert len(results) >= 2

    def test_search_by_module(self, db):
        db.save_scan("modtest.com", ["ssl"], {})
        results = db.search(module="ssl")
        assert any("modtest.com" in r["target"] for r in results)

    def test_search_limit(self, db):
        for i in range(5):
            db.save_scan(f"limit{i}.com", ["whois"], {})
        results = db.search(limit=2)
        assert len(results) <= 2

    def test_search_offset(self, db):
        for i in range(4):
            db.save_scan(f"offset{i}.com", ["dns"], {})
        all_results = db.search(query="offset", limit=100)
        offset_results = db.search(query="offset", limit=100, offset=2)
        assert len(offset_results) <= len(all_results)


class TestListTargets:
    def test_returns_list(self, db):
        result = db.list_targets()
        assert isinstance(result, list)

    def test_unique_targets(self, db):
        db.save_scan("unique1.com", ["whois"], {})
        db.save_scan("unique2.com", ["dns"], {})
        targets = db.list_targets(limit=100)
        assert "unique1.com" in targets
        assert "unique2.com" in targets
        # Check for uniqueness
        assert len(targets) == len(set(targets))

    def test_limit_respected(self, db):
        for i in range(5):
            db.save_scan(f"target{i}.com", ["whois"], {})
        targets = db.list_targets(limit=2)
        assert len(targets) <= 2


class TestDeleteScan:
    def test_delete_existing(self, db):
        scan_id = db.save_scan("delete-me.com", ["whois"], {})
        result = db.delete_scan(scan_id)
        assert result is True
        assert db.get_scan(scan_id) is None

    def test_delete_nonexistent(self, db):
        result = db.delete_scan("nonexistent_id")
        assert result is False


class TestStats:
    def test_returns_dict(self, db):
        stats = db.stats()
        assert isinstance(stats, dict)

    def test_counts_scans(self, db):
        db.save_scan("stats1.com", ["whois"], {})
        db.save_scan("stats2.com", ["dns"], {})
        stats = db.stats()
        assert stats.get("total_scans", 0) >= 2

    def test_unique_targets_counted(self, db):
        db.save_scan("u1.com", ["whois"], {})
        db.save_scan("u2.com", ["whois"], {})
        stats = db.stats()
        assert stats.get("unique_targets", 0) >= 2

    def test_db_path_in_stats(self, db):
        stats = db.stats()
        assert "db_path" in stats


class TestFindings:
    def test_findings_extracted_from_breaches(self, db):
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
        assert len(findings) >= 1
        assert any("Adobe" in f["title"] for f in findings)

    def test_findings_extracted_from_cve(self, db):
        data = {
            "ip": {
                "shodan": {
                    "vulns": ["CVE-2021-44228"],
                    "ports": [80, 443],
                }
            }
        }
        scan_id = db.save_scan("1.2.3.4", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        assert any("CVE" in f["title"] for f in findings)

    def test_findings_extracted_from_open_ports(self, db):
        data = {
            "ip": {
                "shodan": {
                    "ports": [22, 80, 443, 8080],
                }
            }
        }
        scan_id = db.save_scan("1.2.3.4", ["ip"], data)
        findings = db.get_findings(scan_id=scan_id)
        assert any("port" in f["title"].lower() or "open" in f["title"].lower() for f in findings)

    def test_findings_filter_by_severity(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [
                        {"name": "TestBreach", "date": "2021-01-01", "pwn_count": 1000}
                    ]
                }
            }
        }
        scan_id = db.save_scan("breach@example.com", ["email"], data)
        high_findings = db.get_findings(scan_id=scan_id, severity="high")
        assert isinstance(high_findings, list)

    def test_get_findings_no_filter(self, db):
        scan_id = db.save_scan("nofind.com", ["whois"], {})
        findings = db.get_findings()
        assert isinstance(findings, list)

    def test_findings_deleted_with_scan(self, db):
        data = {
            "email": {
                "hibp": {
                    "breaches": [{"name": "Breach", "date": "2020", "pwn_count": 100}]
                }
            }
        }
        scan_id = db.save_scan("del@example.com", ["email"], data)
        db.delete_scan(scan_id)
        findings = db.get_findings(scan_id=scan_id)
        assert findings == []


class TestRowToDict:
    def test_json_fields_deserialized(self, db):
        scan_id = db.save_scan("parse.com", ["whois", "dns"], {"k": "v"}, tags=["t1"])
        record = db.get_scan(scan_id)
        # tags and modules should be list, not string
        assert isinstance(record["modules"], list)
        assert isinstance(record["tags"], list)
        assert isinstance(record["data"], dict)


class TestGetDB:
    def test_singleton_returns_same_instance(self):
        from modules.db import get_db
        db1 = get_db()
        db2 = get_db()
        assert db1 is db2