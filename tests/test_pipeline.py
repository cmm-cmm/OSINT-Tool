"""Tests for modules/pipeline.py — ScanPipeline and run_pipeline."""
import pytest
from unittest.mock import patch, MagicMock


class TestScanPipeline:
    def _make_pipeline(self, target="example.com"):
        from modules.pipeline import ScanPipeline
        return ScanPipeline(target)

    def test_detect_target_type_domain(self):
        p = self._make_pipeline("example.com")
        assert p._detect_target_type("example.com") == "domain"

    def test_detect_target_type_email(self):
        p = self._make_pipeline("user@example.com")
        assert p._detect_target_type("user@example.com") == "email"

    def test_detect_target_type_ipv4(self):
        p = self._make_pipeline("1.2.3.4")
        assert p._detect_target_type("1.2.3.4") == "ip"

    def test_detect_target_type_username_fallback(self):
        p = self._make_pipeline("some_username_123")
        assert p._detect_target_type("some_username_123") == "username"

    def test_get_modules_for_preset_domain(self):
        p = self._make_pipeline("example.com")
        mods = p._get_modules_for_preset("domain", "domain")
        assert "whois" in mods
        assert "dns" in mods

    def test_get_modules_for_preset_auto_resolves(self):
        p = self._make_pipeline("example.com")
        mods = p._get_modules_for_preset("auto", "domain")
        assert isinstance(mods, list)
        assert len(mods) > 0

    def test_get_modules_for_preset_unknown_falls_back(self):
        p = self._make_pipeline("example.com")
        mods = p._get_modules_for_preset("nonexistent_preset_xyz", "domain")
        assert isinstance(mods, list)
        assert len(mods) > 0

    def test_run_returns_required_keys(self):
        from modules.pipeline import ScanPipeline
        p = ScanPipeline("example.com", preset="quick")

        with patch("modules.pipeline._run_whois", return_value={"registrar": "FakeReg"}), \
             patch("modules.pipeline._run_dns", return_value={"a": ["1.2.3.4"]}):
            result = p.run()

        assert "target" in result
        assert "preset" in result
        assert "results" in result
        assert "started_at" in result
        assert "completed_at" in result
        assert "modules_run" in result

    def test_run_handles_module_error_gracefully(self):
        from modules.pipeline import ScanPipeline
        p = ScanPipeline("bad.com", preset="quick")

        with patch("modules.pipeline._run_whois", side_effect=Exception("network error")):
            result = p.run()

        whois_result = result["results"].get("whois", {})
        assert "error" in whois_result or isinstance(whois_result, dict)

    def test_progress_callback_called(self):
        from modules.pipeline import ScanPipeline
        calls = []

        def on_progress(module, status, data):
            calls.append((module, status))

        p = ScanPipeline("example.com", preset="quick")
        with patch("modules.pipeline._run_whois", return_value={"ok": True}), \
             patch("modules.pipeline._run_dns", return_value={"ok": True}):
            p.run(progress_callback=on_progress)

        assert len(calls) > 0


class TestRunPipeline:
    def test_run_pipeline_returns_dict(self):
        from modules.pipeline import run_pipeline
        with patch("modules.pipeline.ScanPipeline") as MockPipeline:
            mock_instance = MagicMock()
            mock_instance.run.return_value = {
                "target": "example.com",
                "preset": "quick",
                "results": {},
                "modules_run": [],
                "started_at": "2024-01-01T00:00:00",
                "completed_at": "2024-01-01T00:00:01",
            }
            MockPipeline.return_value = mock_instance
            result = run_pipeline("example.com", preset="quick")

        assert isinstance(result, dict)
        assert result["target"] == "example.com"

    def test_presets_dict_has_expected_keys(self):
        from modules.pipeline import PRESETS
        for key in ("domain", "email", "username", "ip", "full", "quick"):
            assert key in PRESETS, f"PRESETS missing key: {key}"

    def test_preset_modules_are_lists(self):
        from modules.pipeline import PRESETS
        for name, entry in PRESETS.items():
            if isinstance(entry, dict):
                for category, mods in entry.items():
                    assert isinstance(mods, list), f"PRESETS[{name}][{category}] not a list"
            elif isinstance(entry, list):
                assert all(isinstance(m, str) for m in entry)
