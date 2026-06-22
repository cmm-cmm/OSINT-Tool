"""Tests for modules/social/tiktok.py — deep-scan OSINT functions."""
import pytest
from unittest.mock import patch, MagicMock


# ── lookup_by_email_or_phone ──────────────────────────────────────────────────

class TestLookupByEmailOrPhone:
    def _fn(self):
        from modules.social.tiktok import lookup_by_email_or_phone
        return lookup_by_email_or_phone

    def test_returns_error_without_api_key(self, monkeypatch):
        monkeypatch.delenv("TOKAPI_KEY", raising=False)
        monkeypatch.delenv("RAPIDAPI_KEY", raising=False)
        fn = self._fn()
        result = fn("user@example.com", api_key="")
        assert "error" in result

    def test_detects_email_query(self, monkeypatch):
        monkeypatch.setenv("TOKAPI_KEY", "fake_key")
        fn = self._fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "unique_id": "testuser",
                "nickname": "Test User",
                "uid": "123456",
                "avatar_thumb": {"url_list": ["https://example.com/pic.jpg"]},
                "region": "VN",
            }
        }
        with patch("requests.get", return_value=mock_resp) as mock_get:
            result = fn("user@example.com", api_key="fake_key")
        call_url = mock_get.call_args[0][0]
        assert "email" in call_url
        assert result["found"] is True
        assert result["username"] == "testuser"
        assert result["source"] == "EmailPhoneLookup"

    def test_detects_phone_query(self, monkeypatch):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": {"unique_id": "phoneuser", "nickname": "Phone", "uid": "789"}}
        with patch("requests.get", return_value=mock_resp) as mock_get:
            fn = self._fn()
            fn("+84901234567", api_key="fake_key")
        call_url = mock_get.call_args[0][0]
        assert "phone" in call_url

    def test_handles_http_error(self):
        fn = self._fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        with patch("requests.get", return_value=mock_resp):
            result = fn("user@example.com", api_key="fake_key")
        assert result.get("found") is False
        assert result.get("http_status") == 404

    def test_handles_network_exception(self):
        fn = self._fn()
        with patch("requests.get", side_effect=Exception("timeout")):
            result = fn("user@example.com", api_key="fake_key")
        assert "error" in result


# ── check_web_archive ─────────────────────────────────────────────────────────

class TestCheckWebArchive:
    def _fn(self):
        from modules.social.tiktok import check_web_archive
        return check_web_archive

    def _make_cdx_response(self, rows):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "data"
        mock_resp.json.return_value = rows
        return mock_resp

    def test_returns_unavailable_on_empty_result(self):
        fn = self._fn()
        with patch("requests.get", return_value=self._make_cdx_response([])):
            result = fn("testuser")
        assert result["available"] is False
        assert result["snapshots"] == 0

    def test_returns_unavailable_on_header_only(self):
        fn = self._fn()
        rows = [["timestamp", "original", "statuscode", "digest"]]
        with patch("requests.get", return_value=self._make_cdx_response(rows)):
            result = fn("testuser")
        assert result["available"] is False

    def test_parses_snapshots_correctly(self):
        fn = self._fn()
        rows = [
            ["timestamp", "original", "statuscode", "digest"],
            ["20240615120000", "https://www.tiktok.com/@testuser", "200", "abc123"],
            ["20230101000000", "https://www.tiktok.com/@testuser", "200", "def456"],
        ]
        with patch("requests.get", return_value=self._make_cdx_response(rows)):
            result = fn("testuser")
        assert result["available"] is True
        assert result["snapshots"] == 2
        assert result["latest"] == "2024-06-15"
        assert result["earliest"] == "2023-01-01"
        assert "archive_search" in result
        assert len(result["recent"]) <= 5

    def test_wayback_url_format(self):
        fn = self._fn()
        rows = [
            ["timestamp", "original", "statuscode", "digest"],
            ["20240615120000", "https://www.tiktok.com/@testuser", "200", "abc"],
        ]
        with patch("requests.get", return_value=self._make_cdx_response(rows)):
            result = fn("testuser")
        snap = result["recent"][0]
        assert snap["wayback_url"].startswith("https://web.archive.org/web/")
        assert "20240615120000" in snap["wayback_url"]

    def test_handles_http_error(self):
        fn = self._fn()
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp):
            result = fn("testuser")
        assert result["available"] is False

    def test_handles_network_exception(self):
        fn = self._fn()
        with patch("requests.get", side_effect=Exception("timeout")):
            result = fn("testuser")
        assert result["available"] is False
        assert "error" in result


# ── reverse_image_search_links ────────────────────────────────────────────────

class TestReverseImageSearchLinks:
    def _fn(self):
        from modules.social.tiktok import reverse_image_search_links
        return reverse_image_search_links

    def test_returns_empty_for_no_image(self):
        fn = self._fn()
        assert fn(None) == []
        assert fn("") == []

    def test_returns_list_of_dicts(self):
        fn = self._fn()
        results = fn("https://example.com/avatar.jpg", username="testuser")
        assert isinstance(results, list)
        assert len(results) >= 4
        for item in results:
            assert "engine" in item
            assert "url" in item

    def test_google_lens_link_contains_encoded_url(self):
        fn = self._fn()
        img_url = "https://p16-sign.tiktokcdn.com/avatar.jpg"
        results = fn(img_url)
        lens = next(r for r in results if r["engine"] == "Google Lens")
        assert "lens.google.com" in lens["url"]
        # URL should be encoded
        assert "https%3A" in lens["url"] or "p16" in lens["url"]

    def test_tineye_link_present(self):
        fn = self._fn()
        results = fn("https://example.com/photo.jpg")
        tineye = next((r for r in results if r["engine"] == "TinEye"), None)
        assert tineye is not None
        assert "tineye.com" in tineye["url"]

    def test_yandex_link_present(self):
        fn = self._fn()
        results = fn("https://example.com/photo.jpg")
        yandex = next((r for r in results if "Yandex" in r["engine"]), None)
        assert yandex is not None
        assert "yandex.com" in yandex["url"]


# ── cross_platform_pivot_links ────────────────────────────────────────────────

class TestCrossPlatformPivotLinks:
    def _fn(self):
        from modules.social.tiktok import cross_platform_pivot_links
        return cross_platform_pivot_links

    def test_returns_dict_with_expected_categories(self):
        fn = self._fn()
        result = fn("testuser")
        assert "username_search" in result
        assert "breach_lookup" in result
        assert "profile_search" in result

    def test_username_encoded_in_urls(self):
        fn = self._fn()
        result = fn("test user 123")
        for item in result["username_search"]:
            assert " " not in item.get("url", "")

    def test_email_pivot_added_when_emails_provided(self):
        fn = self._fn()
        result = fn("testuser", bio_emails=["contact@example.com", "admin@test.org"])
        assert "email_pivot" in result
        assert len(result["email_pivot"]) == 2
        assert result["email_pivot"][0]["email"] == "contact@example.com"

    def test_email_pivot_not_added_when_no_emails(self):
        fn = self._fn()
        result = fn("testuser", bio_emails=[])
        assert "email_pivot" not in result

    def test_max_three_emails_in_pivot(self):
        fn = self._fn()
        emails = ["a@x.com", "b@x.com", "c@x.com", "d@x.com"]
        result = fn("testuser", bio_emails=emails)
        assert len(result["email_pivot"]) == 3

    def test_display_name_used_in_search_when_provided(self):
        fn = self._fn()
        result = fn("testuser123", display_name="Real Name")
        # Some pivot links use display_name
        assert result is not None
        assert len(result["username_search"]) > 0

    def test_whatsmyname_link_present(self):
        fn = self._fn()
        result = fn("myusername")
        tools = [item["tool"] for item in result["username_search"]]
        assert any("WhatsMyName" in t for t in tools)

    def test_hibp_link_present_in_breach_lookup(self):
        fn = self._fn()
        result = fn("myusername")
        tools = [item["tool"] for item in result["breach_lookup"]]
        assert any("HaveIBeenPwned" in t for t in tools)


# ── tiktok_recon integration ──────────────────────────────────────────────────

class TestTikTokReconIntegration:
    def _run_recon(self, username="testuser", **kwargs):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch("requests.get", return_value=mock_resp), \
             patch("requests.Session") as mock_session:
            sess_inst = MagicMock()
            sess_inst.get.return_value = mock_resp
            mock_session.return_value = sess_inst
            return tiktok_recon(username, **kwargs)

    def test_result_has_web_archive_key(self):
        result = self._run_recon()
        assert "web_archive" in result

    def test_result_has_reverse_image_links_key(self):
        result = self._run_recon()
        assert "reverse_image_links" in result

    def test_result_has_pivot_links_key(self):
        result = self._run_recon()
        assert "pivot_links" in result

    def test_web_archive_skipped_when_disabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch("requests.get", return_value=mock_resp), \
             patch("modules.social.tiktok.check_web_archive") as mock_wa, \
             patch("requests.Session") as mock_session:
            sess_inst = MagicMock()
            sess_inst.get.return_value = mock_resp
            mock_session.return_value = sess_inst
            tiktok_recon("testuser", web_archive=False)

        mock_wa.assert_not_called()

    def test_pivot_links_skipped_when_disabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""

        with patch("requests.get", return_value=mock_resp), \
             patch("modules.social.tiktok.cross_platform_pivot_links") as mock_pl, \
             patch("requests.Session") as mock_session:
            sess_inst = MagicMock()
            sess_inst.get.return_value = mock_resp
            mock_session.return_value = sess_inst
            tiktok_recon("testuser", pivot_links=False)

        mock_pl.assert_not_called()

    def test_pivot_links_contain_username_search(self):
        result = self._run_recon()
        pl = result.get("pivot_links", {})
        assert "username_search" in pl

    def test_username_stripped_of_at_sign(self):
        result = self._run_recon(username="@someuser")
        assert result["username"] == "someuser"
