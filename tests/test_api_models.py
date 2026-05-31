"""Tests for api/models.py (Pydantic request/response models)."""
import pytest


class TestScanRequest:
    def test_minimal_valid_request(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.target == "example.com"

    def test_default_modules(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.modules == ["whois", "dns"]

    def test_custom_modules(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", modules=["whois", "dns", "ip", "email"])
        assert req.modules == ["whois", "dns", "ip", "email"]

    def test_default_output_format_json(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.output_format == "json"

    def test_custom_output_format(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", output_format="interactive")
        assert req.output_format == "interactive"

    def test_default_use_cache_true(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.use_cache is True

    def test_use_cache_false(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", use_cache=False)
        assert req.use_cache is False

    def test_default_cache_ttl(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com")
        assert req.cache_ttl == 3600

    def test_custom_cache_ttl(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", cache_ttl=7200)
        assert req.cache_ttl == 7200

    def test_target_required(self):
        from api.models import ScanRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ScanRequest()

    def test_from_dict(self):
        from api.models import ScanRequest
        req = ScanRequest(**{
            "target": "192.168.1.1",
            "modules": ["ip"],
            "output_format": "html",
            "use_cache": False,
            "cache_ttl": 1800,
        })
        assert req.target == "192.168.1.1"
        assert req.modules == ["ip"]
        assert req.output_format == "html"
        assert req.use_cache is False
        assert req.cache_ttl == 1800


class TestModuleResult:
    def test_basic_creation(self):
        from api.models import ModuleResult
        r = ModuleResult(module="whois", target="example.com", status="success")
        assert r.module == "whois"
        assert r.target == "example.com"
        assert r.status == "success"

    def test_default_data_empty_dict(self):
        from api.models import ModuleResult
        r = ModuleResult(module="dns", target="example.com", status="success")
        assert r.data == {}

    def test_default_error_none(self):
        from api.models import ModuleResult
        r = ModuleResult(module="dns", target="example.com", status="success")
        assert r.error is None

    def test_default_cached_false(self):
        from api.models import ModuleResult
        r = ModuleResult(module="dns", target="example.com", status="success")
        assert r.cached is False

    def test_default_duration_ms_zero(self):
        from api.models import ModuleResult
        r = ModuleResult(module="dns", target="example.com", status="success")
        assert r.duration_ms == 0

    def test_error_status_with_error_message(self):
        from api.models import ModuleResult
        r = ModuleResult(module="whois", target="example.com", status="error", error="Connection timeout")
        assert r.status == "error"
        assert r.error == "Connection timeout"

    def test_data_with_nested_values(self):
        from api.models import ModuleResult
        data = {"registrar": "ICANN", "ips": ["1.2.3.4"]}
        r = ModuleResult(module="whois", target="example.com", status="success", data=data)
        assert r.data == data

    def test_cached_result(self):
        from api.models import ModuleResult
        r = ModuleResult(module="whois", target="example.com", status="success", cached=True, duration_ms=5)
        assert r.cached is True
        assert r.duration_ms == 5


class TestScanResponse:
    def test_basic_creation(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="abc12345",
            started_at="2024-01-01T10:00:00",
            completed_at="2024-01-01T10:00:05",
            duration_ms=5000,
            modules_run=["whois", "dns"],
            results={"whois": {"registrar": "ICANN"}},
        )
        assert resp.target == "example.com"
        assert resp.scan_id == "abc12345"
        assert resp.duration_ms == 5000

    def test_default_report_paths_empty(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="t",
            scan_id="id",
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
            target="t",
            scan_id="id",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=100,
            modules_run=["whois"],
            results={},
            report_paths={"html": "/reports/t.html", "json": "/reports/t.json"},
        )
        assert "html" in resp.report_paths


class TestCacheStatsResponse:
    def test_basic_creation(self):
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

    def test_default_by_module_empty(self):
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
            total_hits=10,
            by_module={"whois": 3, "dns": 2},
            db_path="/tmp/cache.db",
        )
        assert stats.by_module["whois"] == 3
        assert stats.by_module["dns"] == 2


class TestHistoryEntry:
    def test_basic_creation(self):
        from api.models import HistoryEntry
        entry = HistoryEntry(
            ts="2024-01-01T12:00:00",
            module="whois",
            target="example.com",
            status="ok",
        )
        assert entry.ts == "2024-01-01T12:00:00"
        assert entry.module == "whois"
        assert entry.target == "example.com"
        assert entry.status == "ok"

    def test_error_status(self):
        from api.models import HistoryEntry
        entry = HistoryEntry(ts="2024-01-01T12:00:00", module="dns", target="bad.com", status="error")
        assert entry.status == "error"

    def test_all_fields_required(self):
        from api.models import HistoryEntry
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            HistoryEntry(ts="2024-01-01", module="whois")  # missing target and status


class TestErrorResponse:
    def test_basic_creation(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Something went wrong")
        assert err.error == "Something went wrong"

    def test_default_detail_none(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="error")
        assert err.detail is None

    def test_default_module_none(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="error")
        assert err.module is None

    def test_with_detail_and_module(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="API error", detail="Rate limited by HIBP", module="email")
        assert err.detail == "Rate limited by HIBP"
        assert err.module == "email"

    def test_error_required(self):
        from api.models import ErrorResponse
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            ErrorResponse()

    def test_serializable_to_dict(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Test error", detail="Details here", module="whois")
        d = err.model_dump()
        assert d["error"] == "Test error"
        assert d["detail"] == "Details here"
        assert d["module"] == "whois"


class TestModelSerialization:
    def test_scan_request_model_json(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", modules=["whois"])
        data = req.model_dump()
        assert data["target"] == "example.com"
        assert data["modules"] == ["whois"]

    def test_scan_request_from_json(self):
        from api.models import ScanRequest
        import json
        json_str = '{"target": "example.com", "modules": ["whois", "dns"]}'
        req = ScanRequest.model_validate_json(json_str)
        assert req.target == "example.com"

    def test_scan_response_model_dump(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="testid",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=1000,
            modules_run=["whois"],
            results={"whois": {}},
        )
        data = resp.model_dump()
        assert "target" in data
        assert "results" in data