"""Tests for modules/report_interactive.py."""
import json
import pytest
from pathlib import Path


MINIMAL_DATA = {
    "whois": {"whois": {"registrar": "TestRegistrar", "creation_date": "2020-01-01"}},
    "dns": {"records": {"A": ["1.2.3.4"], "MX": ["mail.example.com"]}, "subdomains": ["www.example.com"]},
}

FULL_DATA = {
    "whois": {"whois": {"registrar": "NameCheap", "creation_date": "2018-05-15"}},
    "dns": {
        "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
        "subdomains": ["www.example.com", "api.example.com"],
    },
    "ip": {
        "geo": {"data": {"query": "93.184.216.34", "country": "US", "city": "Los Angeles"}},
        "shodan": {"success": True, "ports": [80, 443, 8080], "org": "IANA", "vulns": []},
    },
    "email": {
        "email": "admin@example.com",
        "hibp": {
            "breaches": [
                {"name": "Adobe", "date": "2013-10-04", "pwn_count": 153000000,
                 "data_classes": ["Email addresses", "Password hints", "Passwords"]},
                {"name": "LinkedIn", "date": "2016-05-05", "pwn_count": 164611595,
                 "data_classes": ["Email addresses"]},
            ]
        },
    },
    "username": {
        "found": [
            {"platform": "Twitter", "url": "https://twitter.com/testuser"},
            {"platform": "GitHub", "url": "https://github.com/testuser"},
        ]
    },
    "ssl": {
        "grade": "A",
        "certificate": {
            "subject": "example.com",
            "issuer": "Let's Encrypt",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
            "sans": ["www.example.com", "example.com"],
        },
    },
    "breach": {
        "source1": {"found": True, "emails": ["admin@example.com"]},
    },
    "social": {
        "twitter": {"exists": True, "username": "testuser", "followers": 1000},
        "instagram": {"exists": False},
    },
    "secrets": {
        "findings": [
            {"type": "AWS_KEY", "file": "config.py", "severity": "HIGH"},
        ]
    },
}


class TestBuildInteractiveHtmlReport:
    def test_returns_string(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert isinstance(html, str)

    def test_valid_html_structure(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_target_in_output(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", {})
        assert "example.com" in html

    def test_xss_safe_target(self):
        from modules.report_interactive import build_interactive_html_report
        xss_target = "<script>alert('xss')</script>"
        html = build_interactive_html_report(xss_target, {})
        assert "<script>alert('xss')</script>" not in html

    def test_empty_data_returns_html(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", {})
        assert "No data sections" in html or len(html) > 500

    def test_whois_section_present(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "WHOIS" in html or "whois" in html.lower()

    def test_dns_section_present(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "DNS" in html

    def test_ip_section_present(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", FULL_DATA)
        assert "Geolocation" in html or "IP" in html

    def test_email_breach_section(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("admin@example.com", FULL_DATA)
        assert "Adobe" in html
        assert "LinkedIn" in html

    def test_no_breach_shows_clean(self):
        from modules.report_interactive import build_interactive_html_report
        clean_data = {
            "email": {"email": "clean@example.com", "hibp": {"breaches": []}}
        }
        html = build_interactive_html_report("clean@example.com", clean_data)
        assert "No breaches found" in html or "HIBP" in html

    def test_username_platforms(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("testuser", FULL_DATA)
        assert "Twitter" in html
        assert "GitHub" in html

    def test_ssl_grade_displayed(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", FULL_DATA)
        assert 'Grade' in html and "A" in html

    def test_shodan_ports_section(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", FULL_DATA)
        assert "Shodan" in html or "Open Ports" in html or "80" in html

    def test_social_section(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("testuser", FULL_DATA)
        assert "Twitter" in html or "twitter" in html.lower()

    def test_secrets_section(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", FULL_DATA)
        assert "AWS_KEY" in html or "Secrets" in html or "Exposed" in html

    def test_contains_search_box(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "search-box" in html

    def test_contains_filter_buttons(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "filter-btn" in html

    def test_contains_chart_js(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "chart.js" in html.lower() or "Chart" in html

    def test_disclaimer_present(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", {})
        assert "DISCLAIMER" in html

    def test_section_categories_present(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", FULL_DATA)
        assert 'data-category="network"' in html or "data-category" in html

    def test_subdomains_in_output(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "www.example.com" in html

    def test_breach_timeline_for_multiple(self):
        from modules.report_interactive import build_interactive_html_report
        html = build_interactive_html_report("test@example.com", FULL_DATA)
        # Multiple breaches should show timeline
        assert "timeline" in html.lower() or "Adobe" in html

    def test_extra_data_fallback(self):
        """Unknown top-level keys with flat dicts should still appear."""
        from modules.report_interactive import build_interactive_html_report
        data = {"custom_module": {"key1": "value1", "key2": "value2"}}
        html = build_interactive_html_report("target", data)
        assert "value1" in html or "Custom Module" in html


class TestMakeSummaryCards:
    def test_no_data_returns_empty(self):
        from modules.report_interactive import _make_summary_cards
        result = _make_summary_cards({})
        assert result == ""

    def test_dns_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"dns": {"records": {"A": ["1.2.3.4", "5.6.7.8"], "MX": ["mail.example.com"]}}}
        result = _make_summary_cards(data)
        assert "summary-grid" in result
        assert "DNS Records" in result

    def test_breach_count_red_when_found(self):
        from modules.report_interactive import _make_summary_cards
        data = {"email": {"hibp": {"breaches": [{"name": "Adobe"}]}}}
        result = _make_summary_cards(data)
        assert "#f85149" in result  # red color for breaches

    def test_breach_count_green_when_clean(self):
        from modules.report_interactive import _make_summary_cards
        data = {"email": {"hibp": {"breaches": []}}}
        result = _make_summary_cards(data)
        assert "#3fb950" in result  # green for no breaches

    def test_ssl_grade_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ssl": {"grade": "A+"}}
        result = _make_summary_cards(data)
        assert "SSL Grade" in result
        assert "A+" in result

    def test_open_ports_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [80, 443, 8080]}}}
        result = _make_summary_cards(data)
        assert "Open Ports" in result
        assert "3" in result

    def test_cve_card_when_vulns(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [80], "vulns": ["CVE-2021-1234", "CVE-2022-5678"]}}}
        result = _make_summary_cards(data)
        assert "CVEs" in result

    def test_username_platforms_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"username": {"found": [{"platform": "Twitter"}, {"platform": "GitHub"}]}}
        result = _make_summary_cards(data)
        assert "Platforms Found" in result

    def test_registrar_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": "NameCheap"}}}
        result = _make_summary_cards(data)
        assert "Registrar" in result

    def test_registrar_list(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": ["NameCheap", "OldReg"]}}}
        result = _make_summary_cards(data)
        assert "Registrar" in result


class TestSaveInteractiveReport:
    def test_creates_html_file(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        assert "interactive_html" in paths
        assert Path(paths["interactive_html"]).exists()

    def test_html_file_content_valid(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        content = Path(paths["interactive_html"]).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_filename_contains_target(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", {}, str(tmp_path))
        filename = Path(paths["interactive_html"]).name
        assert "example.com" in filename or "example_com" in filename

    def test_filename_sanitized(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("target with spaces!", {}, str(tmp_path))
        filename = Path(paths["interactive_html"]).name
        assert " " not in filename

    def test_creates_output_dir(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        nested = str(tmp_path / "new_dir" / "reports")
        paths = save_interactive_report("example.com", {}, nested)
        assert Path(paths["interactive_html"]).exists()

    def test_filename_ends_with_interactive(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", {}, str(tmp_path))
        assert "interactive" in Path(paths["interactive_html"]).name