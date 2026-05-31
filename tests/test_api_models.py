"""Tests for api/models.py — Pydantic request/response models."""
import pytest
from pydantic import ValidationError


class TestScanRequest:
    def test_minimal_valid(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.target == "example.com"

    def test_default_modules(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.modules == ["whois", "dns"]

    def test_default_output_format(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.output_format == "json"

    def test_default_use_cache(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.use_cache is True

    def test_default_cache_ttl(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.cache_ttl == 3600

    def test_custom_modules(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", modules=["ip", "ssl", "breach"])
        assert req.modules == ["ip", "ssl", "breach"]

    def test_target_required(self):
        from api.models import ScanRequest
        with pytest.raises(ValidationError):
            ScanRequest()

    def test_all_fields_set(self):
        from api.models import ScanRequest
        req = ScanRequest(
            target="test@example.com",
            modules=["email"],
            output_format="interactive",
            use_cache=False,
            cache_ttl=7200,
        )
        assert req.target == "test@example.com"
        assert req.modules == ["email"]
        assert req.output_format == "interactive"
        assert req.use_cache is False
        assert req.cache_ttl == 7200

    def test_serializable_to_dict(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        d = req.model_dump()
        assert isinstance(d, dict)
        assert d["target"] == "example.com"

    def test_empty_modules_list_allowed(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", modules=[])
        assert req.modules == []


class TestModuleResult:
    def test_required_fields(self):
        from api.models import ModuleResult
        result = ModuleResult(module="whois", target="example.com", status="success")
        assert result.module == "whois"
        assert result.target == "example.com"
        assert result.status == "success"

    def test_defaults(self):
        from api.models import ModuleResult
        result = ModuleResult(module="dns", target="example.com", status="success")
        assert result.data == {}
        assert result.error is None
        assert result.cached is False
        assert result.duration_ms == 0

    def test_with_data(self):
        from api.models import ModuleResult
        result = ModuleResult(
            module="whois",
            target="example.com",
            status="success",
            data={"registrar": "NameCheap"},
            cached=True,
            duration_ms=250,
        )
        assert result.data["registrar"] == "NameCheap"
        assert result.cached is True
        assert result.duration_ms == 250

    def test_error_status(self):
        from api.models import ModuleResult
        result = ModuleResult(
            module="ssl",
            target="example.com",
            status="error",
            error="Connection timeout",
        )
        assert result.error == "Connection timeout"
        assert result.status == "error"

    def test_missing_required_fields(self):
        from api.models import ModuleResult
        with pytest.raises(ValidationError):
            ModuleResult(module="whois")  # missing target and status


class TestScanResponse:
    def test_required_fields(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="abc12345",
            started_at="2024-01-01T10:00:00",
            completed_at="2024-01-01T10:00:05",
            duration_ms=5000,
            modules_run=["whois", "dns"],
            results={"whois": {"registrar": "NameCheap"}},
        )
        assert resp.target == "example.com"
        assert resp.scan_id == "abc12345"
        assert resp.duration_ms == 5000

    def test_default_report_paths(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="abc",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=100,
            modules_run=[],
            results={},
        )
        assert resp.report_paths == {}

    def test_with_report_paths(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="abc",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=100,
            modules_run=["whois"],
            results={},
            report_paths={"html": "/reports/example.html"},
        )
        assert resp.report_paths["html"] == "/reports/example.html"

    def test_serializable(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="x",
            started_at="t",
            completed_at="t",
            duration_ms=0,
            modules_run=[],
            results={},
        )
        d = resp.model_dump()
        assert d["target"] == "example.com"

    def test_complex_results(self):
        from api.models import ScanResponse
        results = {
            "whois": {"registrar": "NameCheap", "emails": ["admin@example.com"]},
            "dns": {"A": ["1.2.3.4"]},
        }
        resp = ScanResponse(
            target="example.com",
            scan_id="abc",
            started_at="t",
            completed_at="t",
            duration_ms=100,
            modules_run=["whois", "dns"],
            results=results,
        )
        assert resp.results["whois"]["registrar"] == "NameCheap"


class TestCacheStatsResponse:
    def test_all_required_fields(self):
        from api.models import CacheStatsResponse
        stats = CacheStatsResponse(
            total_entries=10,
            active_entries=8,
            expired_entries=2,
            total_hits=50,
            db_path="/tmp/cache.db",
        )
        assert stats.total_entries == 10
        assert stats.active_entries == 8
        assert stats.expired_entries == 2
        assert stats.total_hits == 50
        assert stats.db_path == "/tmp/cache.db"

    def test_default_by_module(self):
        from api.models import CacheStatsResponse
        stats = CacheStatsResponse(
            total_entries=0,
            active_entries=0,
            expired_entries=0,
            total_hits=0,
            db_path="/tmp/cache.db",
        )
        assert stats.by_module == {}

    def test_with_by_module(self):
        from api.models import CacheStatsResponse
        stats = CacheStatsResponse(
            total_entries=5,
            active_entries=5,
            expired_entries=0,
            total_hits=20,
            by_module={"whois": 3, "dns": 2},
            db_path="/tmp/cache.db",
        )
        assert stats.by_module["whois"] == 3

    def test_missing_fields_raises(self):
        from api.models import CacheStatsResponse
        with pytest.raises(ValidationError):
            CacheStatsResponse(total_entries=0)  # missing required fields


class TestHistoryEntry:
    def test_all_fields(self):
        from api.models import HistoryEntry
        entry = HistoryEntry(
            ts="2024-01-01T10:00:00",
            module="whois",
            target="example.com",
            status="ok",
        )
        assert entry.ts == "2024-01-01T10:00:00"
        assert entry.module == "whois"
        assert entry.target == "example.com"
        assert entry.status == "ok"

    def test_required_fields(self):
        from api.models import HistoryEntry
        with pytest.raises(ValidationError):
            HistoryEntry(ts="2024-01-01")  # missing module, target, status

    def test_serializable(self):
        from api.models import HistoryEntry
        entry = HistoryEntry(ts="t", module="m", target="tgt", status="ok")
        d = entry.model_dump()
        assert d["status"] == "ok"


class TestErrorResponse:
    def test_required_error_field(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Something went wrong")
        assert err.error == "Something went wrong"

    def test_default_optional_fields(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Oops")
        assert err.detail is None
        assert err.module is None

    def test_with_all_fields(self):
        from api.models import ErrorResponse
        err = ErrorResponse(
            error="Module failed",
            detail="Connection refused",
            module="ip",
        )
        assert err.detail == "Connection refused"
        assert err.module == "ip"

    def test_missing_error_raises(self):
        from api.models import ErrorResponse
        with pytest.raises(ValidationError):
            ErrorResponse()

    def test_json_serializable(self):
        from api.models import ErrorResponse
        import json
        err = ErrorResponse(error="test", detail="details", module="whois")
        serialized = err.model_dump_json()
        data = json.loads(serialized)
        assert data["error"] == "test"