"""Tests for modules/darkweb_monitor.py — Pastebin, leaks, dark web."""
import pytest
from unittest.mock import patch, MagicMock


class TestCheckPastebin:
    def test_returns_dict_with_required_keys(self):
        from modules.darkweb_monitor import check_pastebin
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = ""
            mock_sess.return_value.post.return_value = mock_resp
            mock_sess.return_value.get.return_value = mock_resp
            result = check_pastebin("example.com")
        assert "found" in result
        assert "mentions" in result
        assert "urls" in result
        assert result["source"] == "pastebin"

    def test_found_false_when_no_results(self):
        from modules.darkweb_monitor import check_pastebin
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html>no results</html>"
            mock_sess.return_value.post.return_value = mock_resp
            mock_sess.return_value.get.return_value = mock_resp
            result = check_pastebin("unlikely_target_xyz123")
        assert result["found"] is False
        assert result["mentions"] == 0

    def test_handles_network_error_gracefully(self):
        from modules.darkweb_monitor import check_pastebin
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_sess.return_value.post.side_effect = Exception("network error")
            mock_sess.return_value.get.side_effect = Exception("network error")
            result = check_pastebin("example.com")
        assert isinstance(result, dict)
        assert result["found"] is False


class TestCheckLeakDatabases:
    def test_returns_dict_with_required_keys(self):
        from modules.darkweb_monitor import check_leak_databases
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"found": False, "sources": []}
            mock_sess.return_value.get.return_value = mock_resp
            result = check_leak_databases("example.com")
        assert "found" in result
        assert "sources" in result
        assert "count" in result
        assert "provider" in result

    def test_authenticated_api_used_when_key_provided(self):
        from modules.darkweb_monitor import check_leak_databases
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "found": 2,
                "sources": [{"name": "breach1"}],
                "result": [{"email": "test@example.com"}],
            }
            mock_sess.return_value.get.return_value = mock_resp
            result = check_leak_databases("test@example.com", api_key="fake_key")
        assert result["provider"] == "leakcheck_api"
        assert result["found"] is True

    def test_falls_back_gracefully_on_error(self):
        from modules.darkweb_monitor import check_leak_databases
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_sess.return_value.get.side_effect = Exception("timeout")
            result = check_leak_databases("example.com")
        assert isinstance(result, dict)
        assert "found" in result


class TestCheckDarkwebMentions:
    def test_no_tor_proxy_returns_unavailable(self):
        from modules.darkweb_monitor import check_darkweb_mentions
        result = check_darkweb_mentions("example.com", tor_proxy="")
        assert result["available"] is False
        assert result.get("reason") == "no_tor_proxy"

    def test_with_tor_proxy_calls_ahmia(self):
        from modules.darkweb_monitor import check_darkweb_mentions
        with patch("modules.darkweb_monitor.make_session") as mock_sess:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html>no results</html>"
            mock_sess.return_value.get.return_value = mock_resp
            result = check_darkweb_mentions("example.com", tor_proxy="socks5h://127.0.0.1:9050")
        assert result["available"] is True
        assert "found" in result


class TestDarkwebMonitor:
    def test_returns_all_sections(self):
        from modules.darkweb_monitor import darkweb_monitor
        with patch("modules.darkweb_monitor.check_pastebin",
                   return_value={"found": False, "mentions": 0, "urls": [], "source": "pastebin"}), \
             patch("modules.darkweb_monitor.check_leak_databases",
                   return_value={"found": False, "sources": [], "count": 0, "details": [], "provider": "none"}), \
             patch("modules.darkweb_monitor.check_darkweb_mentions",
                   return_value={"available": False, "reason": "no_tor_proxy"}):
            result = darkweb_monitor("example.com")

        assert "target" in result
        assert "pastebin" in result
        assert "leak_databases" in result
        assert "darkweb" in result
        assert "summary" in result

    def test_risk_level_low_when_nothing_found(self):
        from modules.darkweb_monitor import darkweb_monitor
        with patch("modules.darkweb_monitor.check_pastebin",
                   return_value={"found": False, "mentions": 0, "urls": [], "source": "pastebin"}), \
             patch("modules.darkweb_monitor.check_leak_databases",
                   return_value={"found": False, "sources": [], "count": 0, "details": [], "provider": "none"}), \
             patch("modules.darkweb_monitor.check_darkweb_mentions",
                   return_value={"available": False, "reason": "no_tor_proxy"}):
            result = darkweb_monitor("clean.com")

        assert result["summary"]["risk_level"] == "low"
        assert result["summary"]["any_found"] is False

    def test_risk_level_high_when_leaks_and_darkweb(self):
        from modules.darkweb_monitor import darkweb_monitor
        with patch("modules.darkweb_monitor.check_pastebin",
                   return_value={"found": True, "mentions": 3, "urls": ["https://pastebin.com/abc"], "source": "pastebin"}), \
             patch("modules.darkweb_monitor.check_leak_databases",
                   return_value={"found": True, "sources": ["breach1"], "count": 5, "details": [], "provider": "leakcheck_public"}), \
             patch("modules.darkweb_monitor.check_darkweb_mentions",
                   return_value={"available": True, "found": True, "mentions": 2, "urls": [], "source": "ahmia"}):
            result = darkweb_monitor("compromised.com")

        assert result["summary"]["any_found"] is True
        assert result["summary"]["risk_level"] == "high"
