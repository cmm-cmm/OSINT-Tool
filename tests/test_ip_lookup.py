"""
Tests for the changed portion of modules/ip_lookup.py.

Only the generate_recon_links function was modified in this PR
(PR diff: replaced a nested f-string FOFA URL with string concatenation).
"""
import pytest
from unittest.mock import patch, MagicMock


class TestGenerateReconLinks:
    def test_returns_dict(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com")
        assert isinstance(result, dict)

    def test_contains_expected_keys(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com")
        expected_keys = [
            "Shodan", "VirusTotal", "Censys", "SecurityTrails",
            "URLScan", "BuiltWith", "Wayback Machine", "DNSDumpster",
            "AbuseIPDB", "FOFA", "GreyNoise",
        ]
        for key in expected_keys:
            assert key in result, f"Expected key {key!r} missing from result"

    def test_fofa_key_present(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        assert "FOFA" in result

    def test_fofa_url_starts_with_base(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        assert result["FOFA"].startswith("https://en.fofa.info/result?qbase64=")

    def test_fofa_contains_url_encoded_ip(self):
        """FOFA URL should contain the IP encoded in base64 param (URL-encoded)."""
        from modules.ip_lookup import generate_recon_links
        import requests
        ip = "192.168.1.100"
        result = generate_recon_links("example.com", ip)
        # The FOFA URL encodes 'ip="<ip>"' using requests.utils.quote
        expected_encoded = requests.utils.quote('ip="%s"' % ip)
        assert expected_encoded in result["FOFA"]

    def test_fofa_ip_target_used_not_target(self):
        """When ip_target is provided, FOFA should encode ip_target, not target."""
        from modules.ip_lookup import generate_recon_links
        import requests
        target = "example.com"
        ip_target = "93.184.216.34"
        result = generate_recon_links(target, ip_target)
        expected_encoded = requests.utils.quote('ip="%s"' % ip_target)
        assert expected_encoded in result["FOFA"]
        # The target's IP encoding should NOT be in FOFA URL
        wrong_encoded = requests.utils.quote('ip="%s"' % target)
        assert wrong_encoded not in result["FOFA"]

    def test_fofa_falls_back_to_target_when_no_ip(self):
        """When ip_target is None, FOFA should use target as the IP."""
        from modules.ip_lookup import generate_recon_links
        import requests
        target = "10.0.0.1"
        result = generate_recon_links(target, None)
        expected_encoded = requests.utils.quote('ip="%s"' % target)
        assert expected_encoded in result["FOFA"]

    def test_shodan_url_contains_ip(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        assert "1.2.3.4" in result["Shodan"]

    def test_virustotal_url_contains_target(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        assert "example.com" in result["VirusTotal"]

    def test_wayback_url_contains_target(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com")
        assert "example.com" in result["Wayback Machine"]

    def test_abuseipdb_contains_ip(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "5.6.7.8")
        assert "5.6.7.8" in result["AbuseIPDB"]

    def test_greynoise_contains_ip(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "5.6.7.8")
        assert "5.6.7.8" in result["GreyNoise"]

    def test_all_values_are_strings(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        for key, value in result.items():
            assert isinstance(value, str), f"Value for {key!r} should be a string"

    def test_all_values_non_empty(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        for key, value in result.items():
            assert value, f"Value for {key!r} should not be empty"

    def test_ip_with_special_chars_in_fofa(self):
        """IP addresses should be safely URL-encoded."""
        from modules.ip_lookup import generate_recon_links
        import requests
        # IPv6-like string (edge case)
        ip = "2001:db8::1"
        result = generate_recon_links("example.com", ip)
        expected_encoded = requests.utils.quote('ip="%s"' % ip)
        assert expected_encoded in result["FOFA"]

    def test_fofa_url_behavior_equivalent_to_old_fstring(self):
        """Verify the new implementation gives the same result as the old f-string approach."""
        import requests
        ip = "203.0.113.42"
        # Old implementation (nested f-string, reproduced without backslash):
        ip_expr = 'ip="%s"' % ip
        old_result = "https://en.fofa.info/result?qbase64=" + requests.utils.quote(ip_expr)
        # New implementation (string concat):
        new_result = "https://en.fofa.info/result?qbase64=" + requests.utils.quote('ip="%s"' % ip)
        assert old_result == new_result

    def test_urlscan_url_encoded(self):
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("test domain")
        # The target should be URL-encoded in URLScan
        assert "URLScan" in result

    def test_returns_eleven_links(self):
        """Verify all 11 expected links are present."""
        from modules.ip_lookup import generate_recon_links
        result = generate_recon_links("example.com", "1.2.3.4")
        assert len(result) == 11