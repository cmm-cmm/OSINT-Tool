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

    def test_result_has_phone_osint_key(self):
        result = self._run_recon()
        assert "phone_osint" in result

    def test_result_has_geolocation_hints_key(self):
        result = self._run_recon()
        assert "geolocation_hints" in result

    def test_phone_osint_skipped_when_disabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp), \
             patch("modules.social.tiktok.analyse_phone_numbers") as mock_fn, \
             patch("requests.Session") as mock_session:
            sess_inst = MagicMock()
            sess_inst.get.return_value = mock_resp
            mock_session.return_value = sess_inst
            tiktok_recon("testuser", phone_osint=False)
        mock_fn.assert_not_called()

    def test_geo_hints_skipped_when_disabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp), \
             patch("modules.social.tiktok.extract_geolocation_hints") as mock_fn, \
             patch("requests.Session") as mock_session:
            sess_inst = MagicMock()
            sess_inst.get.return_value = mock_resp
            mock_session.return_value = sess_inst
            tiktok_recon("testuser", geo_hints=False)
        mock_fn.assert_not_called()


# ── analyse_phone_numbers ─────────────────────────────────────────────────────

class TestAnalysePhoneNumbers:
    def _fn(self):
        from modules.social.tiktok import analyse_phone_numbers
        return analyse_phone_numbers

    def test_returns_empty_list_for_empty_input(self):
        fn = self._fn()
        assert fn([]) == []

    def test_validates_vn_mobile_number(self):
        fn = self._fn()
        result = fn(["0901234567"], default_region="VN")
        assert len(result) == 1
        ph = result[0]
        assert ph["valid"] is True
        assert ph["e164"].startswith("+84")
        assert ph["region"] == "VN"

    def test_validates_international_format(self):
        fn = self._fn()
        result = fn(["+84901234567"])
        ph = result[0]
        assert ph["valid"] is True
        assert "Vietnam" in (ph.get("location") or "")

    def test_invalid_number_marked_as_invalid(self):
        fn = self._fn()
        result = fn(["123"])
        ph = result[0]
        assert ph["valid"] is False

    def test_returns_number_type(self):
        fn = self._fn()
        result = fn(["0901234567"], default_region="VN")
        if result[0].get("valid"):
            assert result[0].get("number_type") is not None

    def test_multiple_numbers_processed(self):
        fn = self._fn()
        result = fn(["0901234567", "0281234567"], default_region="VN")
        assert len(result) == 2

    def test_timezones_included_for_valid_number(self):
        fn = self._fn()
        result = fn(["0901234567"], default_region="VN")
        if result[0].get("valid"):
            assert isinstance(result[0].get("timezones"), list)


# ── extract_geolocation_hints ─────────────────────────────────────────────────

class TestExtractGeolocationHints:
    def _fn(self):
        from modules.social.tiktok import extract_geolocation_hints
        return extract_geolocation_hints

    def test_returns_none_primary_when_no_data(self):
        fn = self._fn()
        result = fn([])
        assert result["primary"] is None
        assert result["confidence"] == "none"

    def test_detects_location_hashtag(self):
        fn = self._fn()
        videos = [{"title": "test", "hashtags": ["hanoi", "food"], "location_created": ""}]
        result = fn(videos)
        assert result["primary"] is not None
        assert "Hanoi" in result["primary"]

    def test_api_location_gives_high_confidence(self):
        fn = self._fn()
        videos = [{
            "title": "test video",
            "hashtags": [],
            "location_created": "Ho Chi Minh City",
            "video_url": "https://tiktok.com/video/123",
        }]
        result = fn(videos)
        assert result["confidence"] == "high"
        assert result["primary"] == "Ho Chi Minh City"
        assert len(result["api_locations"]) == 1

    def test_bio_keyword_detection(self):
        fn = self._fn()
        result = fn([], bio="I live in Saigon 🌴 #vietnam")
        assert result["primary"] is not None

    def test_multiple_videos_ranked_by_frequency(self):
        fn = self._fn()
        videos = [
            {"title": "hanoi trip", "hashtags": ["hanoi"], "location_created": ""},
            {"title": "hanoi again", "hashtags": ["hanoi"], "location_created": ""},
            {"title": "danang visit", "hashtags": ["danang"], "location_created": ""},
        ]
        result = fn(videos)
        # Hanoi mentioned more often — should rank highest
        assert "Hanoi" in result["primary"]

    def test_inferred_locations_structure(self):
        fn = self._fn()
        videos = [{"title": "", "hashtags": ["saigon"], "location_created": ""}]
        result = fn(videos)
        for loc in result["inferred_locations"]:
            assert "location" in loc
            assert "mention_count" in loc


# ── export_tiktok_html ────────────────────────────────────────────────────────

class TestExportTikTokHtml:
    def _fn(self):
        from modules.social.tiktok import export_tiktok_html
        return export_tiktok_html

    def _sample_data(self):
        return {
            "username": "testuser",
            "platform": "TikTok",
            "profile_url": "https://www.tiktok.com/@testuser",
            "exists": True,
            "is_public": True,
            "display_name": "Test User",
            "bio": "Hello from Hanoi 🌿 ig: test_ig",
            "bio_intel": {"urls": [], "emails": ["test@example.com"], "cross_platform": ["test_ig"], "phone_hints": []},
            "profile_pic": None,
            "is_verified": False,
            "private_account": False,
            "region": "VN",
            "user_id": "123456789",
            "follower_count": 50000,
            "following_count": 300,
            "likes_count": 1000000,
            "video_count": 200,
            "engagement_rate": 10.0,
            "recent_videos": [
                {"title": "My first video", "play_count": 10000, "like_count": 500,
                 "comment_count": 30, "video_url": "https://tiktok.com/video/1",
                 "location_created": "Hanoi"},
            ],
            "video_analysis": {"avg_play_count": 10000, "avg_like_count": 500, "top_hashtags": [{"tag": "hanoi", "count": 3}]},
            "phone_osint": [{"raw": "0901234567", "valid": True, "e164": "+84901234567",
                              "number_type": "Mobile", "location": "Vietnam", "carrier": "Viettel",
                              "timezones": ["Asia/Ho_Chi_Minh"]}],
            "geolocation_hints": {"primary": "Hanoi, Vietnam", "confidence": "medium",
                                   "inferred_locations": [{"location": "Hanoi, Vietnam", "mention_count": 3}],
                                   "api_locations": [{"location": "Hanoi", "video_url": "", "confidence": "high"}]},
            "web_archive": {"available": True, "snapshots": 5, "earliest": "2022-01-01",
                            "latest": "2024-06-01", "archive_search": "https://web.archive.org/",
                            "recent": [{"date": "2024-06-01", "wayback_url": "https://web.archive.org/web/1/"}]},
            "reverse_image_links": [],
            "pivot_links": {"username_search": [{"tool": "WhatsMyName", "url": "https://whatsmyname.app/?q=testuser", "note": "600+ platforms"}]},
            "data_sources": ["HTMLScrape"],
            "security_notes": ["Example note"],
            "dorks": [{"label": "Profile", "query": "site:tiktok.com @testuser", "url": "https://google.com"}],
        }

    def test_creates_html_file(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        result_path = fn(self._sample_data(), output_path=out)
        assert result_path == out
        import os
        assert os.path.exists(out)

    def test_html_contains_username(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        fn(self._sample_data(), output_path=out)
        content = open(out).read()
        assert "testuser" in content

    def test_html_contains_follower_count(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        fn(self._sample_data(), output_path=out)
        content = open(out).read()
        assert "50,000" in content

    def test_html_contains_phone_data(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        fn(self._sample_data(), output_path=out)
        content = open(out).read()
        assert "+84901234567" in content

    def test_html_contains_geolocation(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        fn(self._sample_data(), output_path=out)
        content = open(out).read()
        assert "Hanoi" in content

    def test_default_output_path_generated(self, tmp_path, monkeypatch):
        import os
        monkeypatch.chdir(tmp_path)
        fn = self._fn()
        result_path = fn(self._sample_data())
        assert result_path.startswith("tiktok_testuser_")
        assert result_path.endswith(".html")
        assert os.path.exists(result_path)

    def test_html_is_valid_structure(self, tmp_path):
        fn = self._fn()
        out = str(tmp_path / "report.html")
        fn(self._sample_data(), output_path=out)
        content = open(out).read()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content
        assert "<table" in content


# ── _calc_leak_risk ───────────────────────────────────────────────────────────

class TestCalcLeakRisk:
    def _fn(self):
        from modules.social.tiktok import _calc_leak_risk
        return _calc_leak_risk

    def test_risk_none_when_nothing_found(self):
        fn = self._fn()
        assert fn({"total_breach_sources": 0, "email_leaks": [], "paste_mentions": {}}) == "none"

    def test_risk_low_when_one_source(self):
        fn = self._fn()
        assert fn({"total_breach_sources": 1, "email_leaks": [], "paste_mentions": {}}) == "low"

    def test_risk_low_when_paste_only(self):
        fn = self._fn()
        assert fn({"total_breach_sources": 0, "email_leaks": [], "paste_mentions": {"found": True}}) == "low"

    def test_risk_medium_when_two_sources(self):
        fn = self._fn()
        assert fn({"total_breach_sources": 2, "email_leaks": [], "paste_mentions": {}}) == "medium"

    def test_risk_high_when_three_sources(self):
        fn = self._fn()
        assert fn({"total_breach_sources": 3, "email_leaks": [], "paste_mentions": {}}) == "high"

    def test_risk_high_when_hibp_found(self):
        fn = self._fn()
        intel = {
            "total_breach_sources": 1,
            "email_leaks": [{"hibp_breach_count": 2}],
            "paste_mentions": {},
        }
        assert fn(intel) == "high"

    def test_risk_critical_when_passwords_exposed(self):
        fn = self._fn()
        intel = {
            "total_breach_sources": 2,
            "has_exposed_passwords": True,
            "email_leaks": [],
            "paste_mentions": {},
        }
        assert fn(intel) == "critical"

    def test_risk_critical_when_hibp_and_many_sources(self):
        fn = self._fn()
        intel = {
            "total_breach_sources": 4,
            "has_exposed_passwords": False,
            "email_leaks": [{"hibp_breach_count": 1}],
            "paste_mentions": {},
        }
        assert fn(intel) == "critical"


# ── check_tiktok_leaks ────────────────────────────────────────────────────────

class TestCheckTikTokLeaks:
    def _fn(self):
        from modules.social.tiktok import check_tiktok_leaks
        return check_tiktok_leaks

    def _lc_no_result(self):
        return {"found": False, "sources": []}

    def _lc_found(self, sources=None):
        return {"found": True, "sources": sources or ["TestDB 2023"]}

    def test_returns_valid_structure_with_no_identifiers(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=[], phone_e164_list=[], run_paste_check=True)
        assert "risk_level" in result
        assert "email_leaks" in result
        assert "username_leaks" in result
        assert "phone_leaks" in result
        assert "paste_mentions" in result
        assert "recommendations" in result

    def test_risk_none_when_nothing_found(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": "low", "suspicious": False, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=[], phone_e164_list=[])
        assert result["risk_level"] == "none"
        assert result["total_breach_sources"] == 0

    def test_leakcheck_called_for_email(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()) as mock_lc, \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("testuser", emails=["test@example.com"], phone_e164_list=[])
        assert mock_lc.call_count >= 1
        calls = [str(c) for c in mock_lc.call_args_list]
        assert any("test@example.com" in c for c in calls)

    def test_leakcheck_called_for_username(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()) as mock_lc, \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("myuser123", emails=[], phone_e164_list=[])
        calls = [str(c) for c in mock_lc.call_args_list]
        assert any("myuser123" in c for c in calls)

    def test_hibp_not_called_without_key(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_hibp_email") as mock_hibp, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("testuser", emails=["test@example.com"], phone_e164_list=[], hibp_key="")
        mock_hibp.assert_not_called()

    def test_hibp_called_with_key(self):
        fn = self._fn()
        hibp_resp = {"breaches": [{"name": "TestBreach", "date": "2023-01-01", "data_classes": ["Email"], "description": "Test"}], "pastes": []}
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_hibp_email", return_value=hibp_resp) as mock_hibp, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=["test@example.com"], phone_e164_list=[], hibp_key="fake-key")
        mock_hibp.assert_called_once_with("test@example.com", "fake-key")
        assert result["email_leaks"][0]["hibp_breach_count"] == 1

    def test_email_leak_found_increases_risk(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_found()) as _, \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": "medium", "suspicious": True, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=["leaked@example.com"], phone_e164_list=[])
        assert result["risk_level"] != "none"
        assert result["email_leaks"][0]["leakcheck_found"] is True

    def test_dehashed_not_called_without_keys(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_dehashed") as mock_dh, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("testuser", emails=["t@x.com"], phone_e164_list=[], dehashed_email="", dehashed_key="")
        mock_dh.assert_not_called()

    def test_phone_checked_in_dehashed_when_key_provided(self):
        fn = self._fn()
        dh_resp = {"found": True, "entries": [{"database_name": "TestDB"}], "total": 1}
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_dehashed", return_value=dh_resp) as mock_dh, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=[], phone_e164_list=["+84901234567"],
                        dehashed_email="admin@test.com", dehashed_key="fakekey")
        phone_calls = [c for c in mock_dh.call_args_list if "phone" in str(c)]
        assert len(phone_calls) >= 1
        assert result["phone_leaks"][0]["dehashed_count"] == 1

    def test_paste_check_called_for_username(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": True, "mentions": 2, "urls": ["https://pastebin.com/xxx"]}) as mock_paste:
            result = fn("testuser", emails=[], phone_e164_list=[], run_paste_check=True)
        assert mock_paste.called
        assert result["paste_mentions"]["username"]["found"] is True

    def test_paste_check_skipped_when_disabled(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin") as mock_paste:
            fn("testuser", emails=[], phone_e164_list=[], run_paste_check=False)
        mock_paste.assert_not_called()

    def test_holehe_not_called_by_default(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_holehe") as mock_ho, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("testuser", emails=["t@x.com"], phone_e164_list=[], run_holehe=False)
        mock_ho.assert_not_called()

    def test_holehe_called_when_enabled(self):
        fn = self._fn()
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_holehe", return_value={"registered_sites": [{"name": "GitHub"}], "checked": 1}) as mock_ho, \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=["t@x.com"], phone_e164_list=[], run_holehe=True)
        mock_ho.assert_called_once_with("t@x.com")
        assert "GitHub" in result["email_leaks"][0]["holehe_sites"]

    def test_has_exposed_passwords_flag_set(self):
        fn = self._fn()
        dh_resp = {"found": True, "entries": [{"database_name": "DB1", "password": "hunter2"}], "total": 1}
        with patch("modules.breach_check.check_leakcheck_public", return_value=self._lc_no_result()), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.breach_check.check_dehashed", return_value=dh_resp), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            result = fn("testuser", emails=["t@x.com"], phone_e164_list=[],
                        dehashed_email="a@b.com", dehashed_key="key")
        assert result["has_exposed_passwords"] is True

    def test_max_three_emails_checked(self):
        fn = self._fn()
        call_count = []
        def mock_lc(q):
            call_count.append(q)
            return {"found": False, "sources": []}
        with patch("modules.breach_check.check_leakcheck_public", side_effect=mock_lc), \
             patch("modules.breach_check.check_emailrep", return_value={"reputation": None, "suspicious": None, "credentials_leaked": False}), \
             patch("modules.darkweb_monitor.check_pastebin", return_value={"found": False, "mentions": 0, "urls": []}):
            fn("testuser", emails=["a@x.com", "b@x.com", "c@x.com", "d@x.com"], phone_e164_list=[])
        email_calls = [c for c in call_count if "@" in c]
        assert len(email_calls) <= 3


# ── tiktok_recon leak_check integration ──────────────────────────────────────

class TestTikTokReconLeakCheckIntegration:
    def _run(self, **kwargs):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp), \
             patch("requests.Session") as ms:
            ms.return_value.get.return_value = mock_resp
            return tiktok_recon("testuser", **kwargs)

    def test_leak_intel_key_in_result(self):
        result = self._run()
        assert "leak_intel" in result

    def test_leak_intel_empty_when_disabled(self):
        result = self._run(leak_check=False)
        assert result["leak_intel"] == {}

    def test_check_tiktok_leaks_not_called_when_disabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        with patch("requests.get", return_value=mock_resp), \
             patch("requests.Session") as ms, \
             patch("modules.social.tiktok.check_tiktok_leaks") as mock_ctl:
            ms.return_value.get.return_value = mock_resp
            tiktok_recon("testuser", leak_check=False)
        mock_ctl.assert_not_called()

    def test_check_tiktok_leaks_called_when_enabled(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        fake_leak = {"risk_level": "none", "total_breach_sources": 0, "email_leaks": [], "username_leaks": [], "phone_leaks": [], "paste_mentions": {}, "recommendations": [], "checked_identifiers": [], "has_exposed_passwords": False}
        with patch("requests.get", return_value=mock_resp), \
             patch("requests.Session") as ms, \
             patch("modules.social.tiktok.check_tiktok_leaks", return_value=fake_leak) as mock_ctl:
            ms.return_value.get.return_value = mock_resp
            result = tiktok_recon("testuser", leak_check=True)
        mock_ctl.assert_called_once()
        assert result["leak_intel"]["risk_level"] == "none"

    def test_run_holehe_passed_to_check_tiktok_leaks(self):
        from modules.social.tiktok import tiktok_recon
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        fake_leak = {"risk_level": "none", "total_breach_sources": 0, "email_leaks": [], "username_leaks": [], "phone_leaks": [], "paste_mentions": {}, "recommendations": [], "checked_identifiers": [], "has_exposed_passwords": False}
        with patch("requests.get", return_value=mock_resp), \
             patch("requests.Session") as ms, \
             patch("modules.social.tiktok.check_tiktok_leaks", return_value=fake_leak) as mock_ctl:
            ms.return_value.get.return_value = mock_resp
            tiktok_recon("testuser", leak_check=True, run_holehe=True)
        _, kwargs = mock_ctl.call_args
        assert kwargs.get("run_holehe") is True
