"""Tests for modules/report_interactive.py — interactive HTML report generator."""
import pytest
from pathlib import Path


MINIMAL_DATA = {
    "whois": {
        "whois": {
            "registrar": "Test Registrar",
            "creation_date": "2000-01-01",
        }
    },
    "dns": {
        "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
        "subdomains": ["www.example.com", "api.example.com"],
    },
}

FULL_SCAN_DATA = {
    "whois": {
        "whois": {
            "registrar": "Test Registrar",
            "creation_date": "2000-01-01",
            "emails": ["admin@example.com"],
        }
    },
    "dns": {
        "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
        "subdomains": ["www.example.com", "api.example.com"],
    },
    "ip": {
        "geo": {"data": {"query": "93.184.216.34", "country": "US", "city": "Boston"}},
        "shodan": {
            "success": True,
            "ports": [80, 443, 8080],
            "org": "ACME Corp",
            "vulns": ["CVE-2021-44228"],
        }
    },
    "email": {
        "email": "test@example.com",
        "hibp": {
            "breaches": [
                {"name": "Adobe", "date": "2013-10-04", "pwn_count": 153000000,
                 "data_classes": ["Email", "Password"]},
                {"name": "LinkedIn", "date": "2012-06-05", "pwn_count": 164611595,
                 "data_classes": ["Email", "Password", "Username"]},
            ]
        }
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
            "not_after": "2024-04-01",
            "sans": ["example.com", "www.example.com"],
        }
    },
    "breach": {
        "leakcheck": {"found": True, "source": "LeakCheck"},
        "intel_x": {"found": False},
        "_meta": {"checked": True},  # Private key, should be skipped
    },
    "social": {
        "twitter": {
            "username": "testuser",
            "followers": 1500,
            "security_notes": ["Account created recently"],
        }
    },
    "secrets": {
        "findings": [
            {"type": "AWS Key", "file": "config.py", "severity": "HIGH"},
            {"type": "Private Key", "file": "deploy.sh", "severity": "CRITICAL"},
        ]
    },
}


class TestMakeSummaryCards:
    def test_returns_string(self):
        from modules.report_interactive import _make_summary_cards
        result = _make_summary_cards(MINIMAL_DATA)
        assert isinstance(result, str)

    def test_empty_data_returns_empty(self):
        from modules.report_interactive import _make_summary_cards
        result = _make_summary_cards({})
        assert result == ""

    def test_dns_records_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"dns": {"records": {"A": ["1.2.3.4", "1.2.3.5"], "MX": ["mail.x.com"]}}}
        result = _make_summary_cards(data)
        assert "DNS Records" in result
        assert "3" in result  # 2 + 1 = 3 total records

    def test_whois_registrar_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": "NameCheap"}}}
        result = _make_summary_cards(data)
        assert "Registrar" in result
        assert "NameCheap" in result

    def test_breach_card_red_when_found(self):
        from modules.report_interactive import _make_summary_cards
        data = {
            "email": {
                "hibp": {
                    "breaches": [{"name": "Adobe"}]
                }
            }
        }
        result = _make_summary_cards(data)
        assert "Breaches Found" in result
        assert "#f85149" in result  # Red for breaches

    def test_breach_card_green_when_clean(self):
        from modules.report_interactive import _make_summary_cards
        data = {"email": {"hibp": {"breaches": []}}}
        result = _make_summary_cards(data)
        assert "Breaches Found" in result
        assert "#3fb950" in result  # Green for no breaches

    def test_username_platforms_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"username": {"found": [{"platform": "GitHub"}, {"platform": "Twitter"}]}}
        result = _make_summary_cards(data)
        assert "Platforms Found" in result
        assert "2" in result

    def test_open_ports_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [80, 443, 8080]}}}
        result = _make_summary_cards(data)
        assert "Open Ports" in result
        assert "3" in result

    def test_cve_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [80], "vulns": ["CVE-2021-44228"]}}}
        result = _make_summary_cards(data)
        assert "CVEs" in result

    def test_ssl_grade_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ssl": {"grade": "A+"}}
        result = _make_summary_cards(data)
        assert "SSL Grade" in result
        assert "A+" in result

    def test_ssl_f_grade_red(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ssl": {"grade": "F"}}
        result = _make_summary_cards(data)
        assert "#f85149" in result

    def test_wrapped_in_summary_grid(self):
        from modules.report_interactive import _make_summary_cards
        data = {"dns": {"records": {"A": ["1.2.3.4"]}}}
        result = _make_summary_cards(data)
        assert "summary-grid" in result

    def test_registrar_as_list(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": ["NameCheap", "NameCheap Inc"]}}}
        result = _make_summary_cards(data)
        assert "Registrar" in result

    def test_registrar_none_skipped(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": None}}}
        result = _make_summary_cards(data)
        # No registrar card when registrar is None
        assert isinstance(result, str)


class TestSectionInteractive:
    def test_returns_html_string(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive("Test Section", "<p>content</p>", "network")
        assert isinstance(result, str)

    def test_contains_title(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive("My Title", "<p>body</p>", "network")
        assert "My Title" in result

    def test_contains_category(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive("Section", "content", "security")
        assert 'data-category="security"' in result

    def test_default_category(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive("Section", "content")
        assert 'data-category="general"' in result

    def test_xss_prevention_in_title(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive('<script>alert(1)</script>', 'ok', 'network')
        assert '<script>alert(1)</script>' not in result

    def test_section_structure(self):
        from modules.report_interactive import _section_interactive
        result = _section_interactive("Title", "<p>body</p>", "network")
        assert 'class="section"' in result
        assert 'section-header' in result
        assert 'section-body' in result


class TestBuildInteractiveHtmlReport:
    def test_returns_string(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert isinstance(result, str)

    def test_valid_html_structure(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "<!DOCTYPE html>" in result
        assert "<html" in result
        assert "</html>" in result
        assert "<head>" in result
        assert "<body>" in result

    def test_contains_target(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "example.com" in result

    def test_xss_prevention_in_target(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report('<script>alert(1)</script>', {})
        assert '<script>alert(1)</script>' not in result

    def test_contains_search_box(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert 'search-box' in result

    def test_contains_filter_buttons(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert 'filter-btn' in result

    def test_contains_disclaimer(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "DISCLAIMER" in result

    def test_empty_data_shows_no_sections_message(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "No data sections to display" in result

    def test_whois_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "WHOIS" in result.upper()

    def test_dns_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", MINIMAL_DATA)
        assert "DNS" in result.upper()

    def test_ip_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"ip": {"geo": {"data": {"query": "1.2.3.4", "country": "US"}}}}
        result = build_interactive_html_report("1.2.3.4", data)
        assert "Geolocation" in result or "IP" in result

    def test_email_section_with_breaches(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "email": {
                "email": "test@example.com",
                "hibp": {"breaches": [
                    {"name": "Adobe", "date": "2013-10-04", "pwn_count": 100, "data_classes": ["Email"]}
                ]}
            }
        }
        result = build_interactive_html_report("test@example.com", data)
        assert "Adobe" in result
        assert "breach" in result.lower()

    def test_email_section_no_breach(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"email": {"email": "safe@example.com", "hibp": {"breaches": []}}}
        result = build_interactive_html_report("safe@example.com", data)
        assert "No breaches found" in result

    def test_username_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"username": {"found": [
            {"platform": "GitHub", "url": "https://github.com/user"}
        ]}}
        result = build_interactive_html_report("user", data)
        assert "GitHub" in result

    def test_ssl_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"ssl": {"grade": "A+", "certificate": {"subject": "example.com"}}}
        result = build_interactive_html_report("example.com", data)
        assert "A+" in result
        assert "SSL" in result

    def test_social_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "social": {
                "twitter": {
                    "username": "testuser",
                    "followers": 500,
                }
            }
        }
        result = build_interactive_html_report("testuser", data)
        assert "twitter" in result.lower() or "Twitter" in result

    def test_secrets_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "secrets": {
                "findings": [
                    {"type": "AWS Key", "file": "config.py", "severity": "HIGH"}
                ]
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "Secret" in result or "AWS" in result

    def test_breach_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "breach": {
                "leakcheck": {"found": True, "source": "LeakCheck DB"},
                "_meta": {"checked": True},  # Private key, skipped
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "Breach" in result

    def test_breach_private_keys_skipped(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"breach": {"_meta": {"checked": True}}}
        result = build_interactive_html_report("example.com", data)
        # _meta should not create a section
        assert "_meta" not in result

    def test_fallback_section_for_unknown_modules(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"custom_module": {"key": "value", "another": "data"}}
        result = build_interactive_html_report("example.com", data)
        assert "Custom Module" in result or "custom" in result.lower()

    def test_shodan_with_vulns(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "shodan": {
                    "success": True,
                    "ports": [80, 443],
                    "vulns": ["CVE-2021-44228", "CVE-2022-0001"],
                    "org": "Test Corp",
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "CVE" in result

    def test_shodan_without_vulns(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "shodan": {
                    "success": True,
                    "ports": [80, 443],
                    "org": "Test Corp",
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "80" in result

    def test_breach_timeline_multiple_breaches(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "email": {
                "email": "victim@example.com",
                "hibp": {
                    "breaches": [
                        {"name": "Adobe", "date": "2013-10-04", "pwn_count": 100, "data_classes": []},
                        {"name": "LinkedIn", "date": "2012-06-05", "pwn_count": 200, "data_classes": []},
                    ]
                }
            }
        }
        result = build_interactive_html_report("victim@example.com", data)
        assert "timeline" in result.lower()

    def test_full_data_no_exception(self):
        from modules.report_interactive import build_interactive_html_report
        # Should not raise for complex data
        result = build_interactive_html_report("example.com", FULL_SCAN_DATA)
        assert len(result) > 1000


class TestSaveInteractiveReport:
    def test_returns_dict_with_path(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        assert "interactive_html" in result

    def test_creates_file(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        assert Path(result["interactive_html"]).exists()

    def test_file_is_html(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        assert result["interactive_html"].endswith(".html")

    def test_filename_contains_interactive(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("example.com", {}, str(tmp_path))
        fname = Path(result["interactive_html"]).name
        assert "interactive" in fname

    def test_filename_sanitized(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("test@example.com", {}, str(tmp_path))
        fname = Path(result["interactive_html"]).name
        assert "@" not in fname

    def test_creates_output_dir(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        subdir = str(tmp_path / "nested" / "reports")
        save_interactive_report("example.com", {}, subdir)
        assert Path(subdir).exists()

    def test_file_content_is_valid_html(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        result = save_interactive_report("example.com", MINIMAL_DATA, str(tmp_path))
        content = Path(result["interactive_html"]).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "example.com" in content

    def test_default_output_dir(self, tmp_path):
        """Test with default output_dir parameter."""
        from modules.report_interactive import save_interactive_report
        import os
        old_cwd = os.getcwd()
        try:
            os.chdir(str(tmp_path))
            result = save_interactive_report("test.com", {})
            assert "interactive_html" in result
        finally:
            os.chdir(old_cwd)
            # Cleanup
            import glob
            for f in glob.glob(str(tmp_path / "*.html")):
                Path(f).unlink(missing_ok=True)


class TestInteractiveCssAndJs:
    def test_css_constant_defined(self):
        from modules.report_interactive import INTERACTIVE_CSS_EXTRA
        assert isinstance(INTERACTIVE_CSS_EXTRA, str)
        assert len(INTERACTIVE_CSS_EXTRA) > 100

    def test_js_constant_defined(self):
        from modules.report_interactive import INTERACTIVE_JS
        assert isinstance(INTERACTIVE_JS, str)
        assert "<script>" in INTERACTIVE_JS

    def test_template_defined(self):
        from modules.report_interactive import INTERACTIVE_TEMPLATE
        assert isinstance(INTERACTIVE_TEMPLATE, str)
        assert "{target}" in INTERACTIVE_TEMPLATE
        assert "{content}" in INTERACTIVE_TEMPLATE
        assert "{timestamp}" in INTERACTIVE_TEMPLATE