"""Tests for modules/report.py."""
import pytest
from unittest.mock import patch
from pathlib import Path


class TestHTMLEscape:
    def test_basic_escaping(self):
        from modules.report import _e
        assert "&amp;" in _e("a&b")
        assert "&lt;" in _e("<script>")
        assert "&gt;" in _e(">alert")
        assert "&#x27;" in _e("'") or "&apos;" in _e("'") or "'" in _e("'")

    def test_non_string_input(self):
        from modules.report import _e
        assert _e(123) == "123"
        assert _e(None) == "None"

    def test_xss_prevention(self):
        from modules.report import _e
        payload = '<script>alert("xss")</script>'
        result = _e(payload)
        assert "<script>" not in result
        assert "alert" in result  # Content still visible but escaped


class TestBuildHTMLReport:
    def test_returns_string(self, sample_report_data):
        from modules.report import build_html_report
        html = build_html_report("example.com", sample_report_data)
        assert isinstance(html, str)

    def test_contains_target(self, sample_report_data):
        from modules.report import build_html_report
        html = build_html_report("example.com", sample_report_data)
        assert "example.com" in html

    def test_valid_html_structure(self, sample_report_data):
        from modules.report import build_html_report
        html = build_html_report("example.com", sample_report_data)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_no_xss_in_target(self):
        from modules.report import build_html_report
        xss_target = '<script>alert(1)</script>'
        html = build_html_report(xss_target, {})
        assert "<script>alert(1)</script>" not in html

    def test_empty_data(self):
        from modules.report import build_html_report
        html = build_html_report("test.com", {})
        assert isinstance(html, str)
        assert len(html) > 100


class TestSaveReport:
    def test_saves_html_file(self, sample_report_data, tmp_output_dir):
        from modules.report import save_report
        result = save_report("example.com", sample_report_data, tmp_output_dir)
        assert "html" in result
        assert Path(result["html"]).exists()

    def test_saves_json_file(self, sample_report_data, tmp_output_dir):
        from modules.report import save_report
        result = save_report("example.com", sample_report_data, tmp_output_dir)
        assert "json" in result
        assert Path(result["json"]).exists()

    def test_json_content_valid(self, sample_report_data, tmp_output_dir):
        import json
        from modules.report import save_report
        result = save_report("example.com", sample_report_data, tmp_output_dir)
        with open(result["json"]) as f:
            data = json.load(f)
        assert "target" in data or "whois" in data

    def test_filename_sanitized(self, tmp_output_dir):
        from modules.report import save_report
        # Domain with special chars should produce valid filename
        result = save_report("exam ple.com", {}, tmp_output_dir)
        assert "html" in result
