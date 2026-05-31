"""Tests for api/models.py — Pydantic request/response models."""
import pytest

pydantic = pytest.importorskip("pydantic", reason="pydantic not installed (optional dependency)")


class TestScanRequest:
    def test_minimal_required_fields(self):
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
        req = ScanRequest(target="example.com", modules=["whois", "dns", "ip", "ssl"])
        assert req.modules == ["whois", "dns", "ip", "ssl"]

    def test_custom_output_format(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", output_format="interactive")
        assert req.output_format == "interactive"

    def test_disable_cache(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", use_cache=False)
        assert req.use_cache is False

    def test_custom_cache_ttl(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", cache_ttl=7200)
        assert req.cache_ttl == 7200

    def test_target_required(self):
        from api.models import ScanRequest
        with pytest.raises(Exception):  # pydantic ValidationError
            ScanRequest()

    def test_dict_serialization(self):
        from api.models import ScanRequest
        req = ScanRequest(target="example.com", modules=["whois"])
        d = req.model_dump()
        assert d["target"] == "example.com"
        assert d["modules"] == ["whois"]

    def test_json_serialization(self):
        from api.models import ScanRequest
        import json
        req = ScanRequest(target="test.com")
        json_str = req.model_dump_json()
        data = json.loads(json_str)
        assert data["target"] == "test.com"


class TestModuleResult:
    def test_basic_creation(self):
        from api.models import ModuleResult
        result = ModuleResult(module="whois", target="example.com", status="success")
        assert result.module == "whois"
        assert result.target == "example.com"
        assert result.status == "success"

    def test_default_data_empty_dict(self):
        from api.models import ModuleResult
        result = ModuleResult(module="dns", target="test.com", status="success")
        assert result.data == {}

    def test_default_cached_false(self):
        from api.models import ModuleResult
        result = ModuleResult(module="dns", target="test.com", status="success")
        assert result.cached is False

    def test_default_duration_zero(self):
        from api.models import ModuleResult
        result = ModuleResult(module="ip", target="1.2.3.4", status="success")
        assert result.duration_ms == 0

    def test_error_status(self):
        from api.models import ModuleResult
        result = ModuleResult(
            module="ssl", target="example.com", status="error",
            error="Connection refused"
        )
        assert result.status == "error"
        assert result.error == "Connection refused"

    def test_with_data(self):
        from api.models import ModuleResult
        data = {"registrar": "ACME Corp", "expiry": "2025-01-01"}
        result = ModuleResult(module="whois", target="example.com", status="success", data=data)
        assert result.data["registrar"] == "ACME Corp"

    def test_cached_result(self):
        from api.models import ModuleResult
        result = ModuleResult(
            module="whois", target="example.com", status="success",
            cached=True, duration_ms=5
        )
        assert result.cached is True
        assert result.duration_ms == 5

    def test_null_error_default(self):
        from api.models import ModuleResult
        result = ModuleResult(module="whois", target="example.com", status="success")
        assert result.error is None


class TestScanResponse:
    def test_basic_creation(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="abc12345",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=1000,
            modules_run=["whois", "dns"],
            results={"whois": {"registrar": "Test"}},
        )
        assert resp.target == "example.com"
        assert resp.scan_id == "abc12345"
        assert resp.duration_ms == 1000

    def test_default_report_paths_empty(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="id1",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=100,
            modules_run=["whois"],
            results={},
        )
        assert resp.report_paths == {}

    def test_with_report_paths(self):
        from api.models import ScanResponse
        resp = ScanResponse(
            target="example.com",
            scan_id="id1",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=100,
            modules_run=["whois"],
            results={},
            report_paths={"html": "/reports/example.html", "json": "/reports/example.json"},
        )
        assert "html" in resp.report_paths
        assert "json" in resp.report_paths

    def test_results_accepts_any_dict(self):
        from api.models import ScanResponse
        results = {
            "whois": {"registrar": "Test", "nested": {"key": "val"}},
            "dns": {"A": ["1.2.3.4"]},
            "error_module": {"error": "failed"},
        }
        resp = ScanResponse(
            target="example.com",
            scan_id="id1",
            started_at="2024-01-01T00:00:00",
            completed_at="2024-01-01T00:00:01",
            duration_ms=500,
            modules_run=list(results.keys()),
            results=results,
        )
        assert resp.results["whois"]["registrar"] == "Test"


class TestCacheStatsResponse:
    def test_basic_creation(self):
        from api.models import CacheStatsResponse
        stats = CacheStatsResponse(
            total_entries=10,
            active_entries=8,
            expired_entries=2,
            total_hits=50,
            db_path="/path/to/cache.db",
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
            db_path="/path/cache.db",
        )
        assert stats.by_module == {}

    def test_with_module_breakdown(self):
        from api.models import CacheStatsResponse
        stats = CacheStatsResponse(
            total_entries=5,
            active_entries=5,
            expired_entries=0,
            total_hits=10,
            by_module={"whois": 3, "dns": 2},
            db_path="/cache.db",
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
        entry = HistoryEntry(ts="2024-01-01T12:00:00", module="ssl", target="bad.com", status="error")
        assert entry.status == "error"


class TestErrorResponse:
    def test_basic_creation(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Something went wrong")
        assert err.error == "Something went wrong"

    def test_default_detail_none(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Test error")
        assert err.detail is None

    def test_default_module_none(self):
        from api.models import ErrorResponse
        err = ErrorResponse(error="Test error")
        assert err.module is None

    def test_with_detail_and_module(self):
        from api.models import ErrorResponse
        err = ErrorResponse(
            error="Module failed",
            detail="Connection timed out after 30s",
            module="ip",
        )
        assert err.detail == "Connection timed out after 30s"
        assert err.module == "ip"

    def test_error_required(self):
        from api.models import ErrorResponse
        with pytest.raises(Exception):  # pydantic ValidationError
            ErrorResponse()


class TestModelImports:
    def test_all_models_importable(self):
        from api.models import (
            ScanRequest, ModuleResult, ScanResponse,
            CacheStatsResponse, HistoryEntry, ErrorResponse
        )
        assert ScanRequest is not None
        assert ModuleResult is not None
        assert ScanResponse is not None
        assert CacheStatsResponse is not None
        assert HistoryEntry is not None
        assert ErrorResponse is not None

    def test_models_are_pydantic(self):
        from api.models import ScanRequest
        from pydantic import BaseModel
        assert issubclass(ScanRequest, BaseModel)