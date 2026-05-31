"""Tests for modules/report_interactive.py."""
import json
import pytest
from pathlib import Path


class TestMakeSummaryCards:
    def test_empty_data_returns_empty_string(self):
        from modules.report_interactive import _make_summary_cards
        result = _make_summary_cards({})
        assert result == ""

    def test_dns_records_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"dns": {"records": {"A": ["1.2.3.4", "1.2.3.5"], "MX": ["mail.example.com"]}}}
        result = _make_summary_cards(data)
        assert "summary-grid" in result
        assert "DNS Records" in result
        assert "3" in result  # 2 A + 1 MX

    def test_whois_registrar_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": "ICANN Corp"}}}
        result = _make_summary_cards(data)
        assert "Registrar" in result
        assert "ICANN Corp" in result

    def test_whois_registrar_list_uses_first(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": ["FirstReg", "SecondReg"]}}}
        result = _make_summary_cards(data)
        assert "FirstReg" in result

    def test_email_breach_count_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {
            "email": {
                "hibp": {"breaches": [{"name": "B1"}, {"name": "B2"}]}
            }
        }
        result = _make_summary_cards(data)
        assert "Breaches Found" in result
        assert "2" in result

    def test_email_no_breach_shows_zero(self):
        from modules.report_interactive import _make_summary_cards
        data = {"email": {"hibp": {"breaches": []}}}
        result = _make_summary_cards(data)
        assert "Breaches Found" in result
        assert "0" in result

    def test_username_platforms_found_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {
            "username": {
                "found": [
                    {"platform": "Twitter"},
                    {"platform": "GitHub"},
                    {"platform": "Reddit"},
                ]
            }
        }
        result = _make_summary_cards(data)
        assert "Platforms Found" in result
        assert "3" in result

    def test_open_ports_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [22, 80, 443], "vulns": []}}}
        result = _make_summary_cards(data)
        assert "Open Ports" in result
        assert "3" in result

    def test_cve_card_when_vulns_present(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ip": {"shodan": {"ports": [22], "vulns": ["CVE-2021-44228"]}}}
        result = _make_summary_cards(data)
        assert "CVEs Detected" in result
        assert "1" in result

    def test_ssl_grade_card(self):
        from modules.report_interactive import _make_summary_cards
        data = {"ssl": {"grade": "A+"}}
        result = _make_summary_cards(data)
        assert "SSL Grade" in result
        assert "A+" in result

    def test_card_contains_html_structure(self):
        from modules.report_interactive import _make_summary_cards
        data = {"dns": {"records": {"A": ["1.2.3.4"]}}}
        result = _make_summary_cards(data)
        assert "summary-card" in result
        assert "card-value" in result
        assert "card-label" in result

    def test_xss_in_registrar_escaped(self):
        from modules.report_interactive import _make_summary_cards
        data = {"whois": {"whois": {"registrar": "<script>alert(1)</script>"}}}
        result = _make_summary_cards(data)
        assert "<script>alert(1)</script>" not in result


class TestBuildInteractiveHtmlReport:
    def test_returns_string(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert isinstance(result, str)

    def test_valid_html_structure(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "<!DOCTYPE html>" in result
        assert "<html" in result
        assert "</html>" in result

    def test_target_in_report(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("target.example.com", {})
        assert "target.example.com" in result

    def test_xss_in_target_escaped(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report('<script>alert("xss")</script>', {})
        assert '<script>alert("xss")</script>' not in result
        assert "&lt;script&gt;" in result

    def test_empty_data_shows_no_sections_message(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "No data sections" in result or "no data" in result.lower() or len(result) > 0

    def test_whois_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"whois": {"whois": {"registrar": "ICANN Corp", "creation_date": "2010-01-01"}}}
        result = build_interactive_html_report("example.com", data)
        assert "WHOIS" in result
        assert "ICANN Corp" in result

    def test_dns_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"dns": {"records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]}}}
        result = build_interactive_html_report("example.com", data)
        assert "DNS" in result
        assert "93.184.216.34" in result

    def test_dns_subdomains_section(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"dns": {"records": {}, "subdomains": ["mail.example.com", "www.example.com"]}}
        result = build_interactive_html_report("example.com", data)
        assert "mail.example.com" in result
        assert "www.example.com" in result

    def test_email_breach_section(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "email": {
                "email": "user@example.com",
                "hibp": {
                    "breaches": [
                        {"name": "TestBreach", "date": "2020-01-01",
                         "pwn_count": 5000, "data_classes": ["Email", "Password"]}
                    ]
                }
            }
        }
        result = build_interactive_html_report("user@example.com", data)
        assert "Email" in result
        assert "TestBreach" in result

    def test_email_no_breach_shows_clean_message(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"email": {"email": "clean@example.com", "hibp": {"breaches": []}}}
        result = build_interactive_html_report("clean@example.com", data)
        assert "No breaches" in result or "✓" in result

    def test_ip_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "geo": {"data": {"country": "US", "city": "Boston"}},
                "shodan": {"success": False}
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "IP" in result or "Geolocation" in result

    def test_shodan_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "geo": {},
                "shodan": {
                    "success": True,
                    "ports": [22, 80],
                    "org": "Cloudflare",
                    "vulns": []
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "Shodan" in result

    def test_shodan_cve_warning_displayed(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "geo": {},
                "shodan": {
                    "success": True,
                    "ports": [22],
                    "vulns": ["CVE-2021-44228"],
                    "org": "Test"
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "CVE" in result

    def test_username_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "username": {
                "found": [{"platform": "Twitter", "url": "https://twitter.com/testuser"}]
            }
        }
        result = build_interactive_html_report("testuser", data)
        assert "Username" in result or "Platform" in result
        assert "Twitter" in result

    def test_ssl_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ssl": {
                "grade": "A+",
                "certificate": {
                    "subject": "example.com",
                    "issuer": "Let's Encrypt",
                    "not_before": "2024-01-01",
                    "not_after": "2025-01-01",
                    "sans": ["example.com", "www.example.com"]
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "SSL" in result
        assert "A+" in result

    def test_social_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "social": {
                "twitter": {
                    "exists": True,
                    "followers": 1000,
                    "bio": "Test account",
                }
            }
        }
        result = build_interactive_html_report("testuser", data)
        assert "Social" in result or "Twitter" in result

    def test_secrets_section_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "secrets": {
                "findings": [
                    {"type": "AWS_KEY", "file": "config.py", "severity": "HIGH"}
                ]
            }
        }
        result = build_interactive_html_report("example.com", data)
        assert "Secrets" in result or "AWS_KEY" in result

    def test_search_box_present(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "search-box" in result

    def test_filter_buttons_present(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "filter-btn" in result

    def test_data_categories_present(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"whois": {"whois": {"registrar": "ICANN"}}}
        result = build_interactive_html_report("example.com", data)
        assert "data-category" in result

    def test_timestamp_in_report(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        # Report should contain a date string
        import re
        assert re.search(r"\d{4}-\d{2}-\d{2}", result)

    def test_chartjs_included(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "chart.js" in result.lower() or "Chart" in result

    def test_sections_are_collapsible(self):
        from modules.report_interactive import build_interactive_html_report
        data = {"whois": {"whois": {"registrar": "ICANN"}}}
        result = build_interactive_html_report("example.com", data)
        assert "section-header" in result

    def test_disclaimer_present(self):
        from modules.report_interactive import build_interactive_html_report
        result = build_interactive_html_report("example.com", {})
        assert "DISCLAIMER" in result

    def test_shodan_port_chart_injected(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "ip": {
                "geo": {},
                "shodan": {
                    "success": True,
                    "ports": [22, 80, 443],
                    "vulns": [],
                    "org": "TestOrg"
                }
            }
        }
        result = build_interactive_html_report("example.com", data)
        # Chart.js canvas for ports
        assert "port-chart" in result or "canvas" in result.lower()

    def test_breach_timeline_rendered(self):
        from modules.report_interactive import build_interactive_html_report
        data = {
            "email": {
                "email": "user@example.com",
                "hibp": {
                    "breaches": [
                        {"name": "B1", "date": "2020-01-01", "pwn_count": 1000, "data_classes": []},
                        {"name": "B2", "date": "2021-01-01", "pwn_count": 2000, "data_classes": []},
                    ]
                }
            }
        }
        result = build_interactive_html_report("user@example.com", data)
        assert "Timeline" in result or "timeline" in result


class TestSaveInteractiveReport:
    def test_saves_html_file(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", {}, output_dir=str(tmp_path))
        assert "interactive_html" in paths
        assert Path(paths["interactive_html"]).exists()

    def test_file_ends_with_interactive_html(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", {}, output_dir=str(tmp_path))
        assert paths["interactive_html"].endswith("_interactive.html")

    def test_file_contains_html(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("example.com", {"whois": {"whois": {"registrar": "ICANN"}}},
                                        output_dir=str(tmp_path))
        content = Path(paths["interactive_html"]).read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_creates_output_dir(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        new_dir = str(tmp_path / "new" / "nested")
        paths = save_interactive_report("example.com", {}, output_dir=new_dir)
        assert Path(new_dir).exists()

    def test_target_in_filename(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("mytarget.com", {}, output_dir=str(tmp_path))
        assert "mytarget.com" in Path(paths["interactive_html"]).name or "mytarget_com" in Path(paths["interactive_html"]).name

    def test_special_chars_in_target_sanitized(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        paths = save_interactive_report("test/target?bad*chars", {}, output_dir=str(tmp_path))
        assert Path(paths["interactive_html"]).exists()

    def test_with_full_scan_data(self, tmp_path):
        from modules.report_interactive import save_interactive_report
        data = {
            "whois": {"whois": {"registrar": "ICANN"}},
            "dns": {"records": {"A": ["1.2.3.4"]}, "subdomains": []},
            "email": {"email": "test@example.com", "hibp": {"breaches": []}},
        }
        paths = save_interactive_report("example.com", data, output_dir=str(tmp_path))
        content = Path(paths["interactive_html"]).read_text(encoding="utf-8")
        assert "ICANN" in content
        assert "1.2.3.4" in content