"""Tests for modules/utils.py."""
import time
import pytest
from unittest.mock import patch, MagicMock
from modules.utils import (
    make_session, safe_get, RateLimiter,
    sanitize_for_shell, check_internet,
    append_scan_history, read_scan_history,
)


class TestMakeSession:
    def test_returns_session(self):
        import requests
        session = make_session()
        assert isinstance(session, requests.Session)

    def test_browser_ua(self):
        session = make_session(browser_ua=True)
        assert "Mozilla" in session.headers.get("User-Agent", "")

    def test_generic_ua(self):
        session = make_session(browser_ua=False)
        assert "OSINT" in session.headers.get("User-Agent", "")

    def test_ssl_verification(self):
        session = make_session()
        assert session.verify  # Should be set to certifi path


class TestSafeGet:
    def test_returns_none_on_exception(self):
        with patch("modules.utils.make_session") as mock_sess:
            mock_sess.return_value.get.side_effect = Exception("timeout")
            result = safe_get("https://nonexistent.invalid/")
        assert result is None

    def test_returns_response_on_success(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("modules.utils.make_session") as mock_sess:
            mock_sess.return_value.get.return_value = mock_resp
            result = safe_get("https://example.com")
        assert result is mock_resp


class TestRateLimiter:
    def test_allows_calls_within_limit(self):
        rl = RateLimiter(calls=5, period=1.0)
        for _ in range(5):
            with rl:
                pass  # Should not block

    def test_context_manager_protocol(self):
        rl = RateLimiter(calls=10, period=1.0)
        with rl as r:
            assert r is rl

    def test_single_call_no_delay(self):
        rl = RateLimiter(calls=5, period=1.0)
        start = time.monotonic()
        with rl:
            pass
        elapsed = time.monotonic() - start
        assert elapsed < 0.1  # No significant delay for first call


class TestSanitizeForShell:
    def test_safe_values(self):
        safe_cases = ["example.com", "user@host.com", "test-123", "hello_world"]
        for val in safe_cases:
            assert sanitize_for_shell(val) == val

    def test_rejects_shell_injection(self):
        bad_cases = [
            "test; rm -rf /",
            "$(whoami)",
            "test`id`",
            "test|cat /etc/passwd",
        ]
        for val in bad_cases:
            with pytest.raises(ValueError):
                sanitize_for_shell(val)

    def test_too_long(self):
        with pytest.raises(ValueError):
            sanitize_for_shell("a" * 300)


class TestCheckInternet:
    def test_returns_bool(self):
        import socket
        with patch("socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock()
            mock_conn.return_value.__exit__ = MagicMock()
            result = check_internet(timeout=1)
        assert isinstance(result, bool)

    def test_returns_false_on_all_failures(self):
        import socket
        with patch("socket.create_connection", side_effect=OSError("refused")):
            result = check_internet(timeout=1)
        assert result is False


class TestScanHistory:
    def test_append_and_read(self, tmp_path):
        from modules import constants as c
        orig = c.USER_CONFIG_DIR
        try:
            c.USER_CONFIG_DIR = tmp_path
            append_scan_history("TestModule", "example.com", "ok")
            records = read_scan_history(limit=10)
            assert len(records) >= 1
            assert records[0]["module"] == "TestModule"
            assert records[0]["target"] == "example.com"
            assert records[0]["status"] == "ok"
        finally:
            c.USER_CONFIG_DIR = orig

    def test_read_empty_history(self, tmp_path):
        from modules import constants as c
        orig = c.USER_CONFIG_DIR
        try:
            c.USER_CONFIG_DIR = tmp_path
            records = read_scan_history()
        finally:
            c.USER_CONFIG_DIR = orig
        assert records == []
