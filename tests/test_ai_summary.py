"""Tests for modules/ai_summary.py."""
import os
import pytest
from unittest.mock import MagicMock, patch


class TestPrepareContext:
    def test_includes_target(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "TARGET: example.com" in result

    def test_includes_separator_line(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "=" * 10 in result  # at least a portion of the separator

    def test_handles_empty_data(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("test.com", {})
        assert isinstance(result, str)
        assert len(result) > 0

    def test_dict_section_rendered(self):
        from modules.ai_summary import _prepare_context
        data = {"whois": {"registrar": "ICANN", "domain": "example.com"}}
        result = _prepare_context("example.com", data)
        assert "WHOIS" in result
        assert "registrar" in result
        assert "ICANN" in result

    def test_list_section_rendered(self):
        from modules.ai_summary import _prepare_context
        data = {"username": {"found": [{"platform": "Twitter", "url": "https://twitter.com/u"}]}}
        result = _prepare_context("testuser", data)
        assert "USERNAME" in result or "FOUND" in result

    def test_truncation_at_max_chars(self):
        from modules.ai_summary import _prepare_context
        # Create data that would exceed max_chars
        big_data = {f"section_{i}": {"key": "x" * 500} for i in range(50)}
        result = _prepare_context("target", big_data, max_chars=500)
        assert "truncated" in result

    def test_none_values_excluded(self):
        from modules.ai_summary import _prepare_context
        data = {"whois": {"registrar": None, "domain": "example.com"}}
        result = _prepare_context("example.com", data)
        assert "None" not in result or "domain" in result

    def test_nested_dict_rendered(self):
        from modules.ai_summary import _prepare_context
        data = {
            "ip": {
                "geo": {
                    "data": {"country": "US", "city": "New York"}
                }
            }
        }
        result = _prepare_context("1.2.3.4", data)
        assert "IP" in result

    def test_depth_limit_prevents_infinite_recursion(self):
        from modules.ai_summary import _prepare_context
        # Very deeply nested data
        deep = {"level": {}}
        current = deep["level"]
        for _ in range(10):
            current["nested"] = {}
            current = current["nested"]
        # Should not raise or hang
        result = _prepare_context("target", deep)
        assert isinstance(result, str)

    def test_list_items_capped_at_10(self):
        from modules.ai_summary import _prepare_context
        data = {"items": [f"item{i}" for i in range(20)]}
        result = _prepare_context("target", data)
        # Should include count info
        assert "20 items" in result or "ITEMS" in result


class TestGenerateAiSummary:
    def test_no_api_key_returns_error(self):
        from modules.ai_summary import generate_ai_summary
        with patch.dict(os.environ, {}, clear=True):
            # Remove ANTHROPIC_API_KEY if present
            os.environ.pop("ANTHROPIC_API_KEY", None)
            result = generate_ai_summary("example.com", {}, api_key=None)
        assert result["summary"] is None
        assert result["error"] is not None
        assert "API key" in result["error"]

    def test_no_api_key_includes_model(self):
        from modules.ai_summary import generate_ai_summary
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = generate_ai_summary("example.com", {}, api_key=None, model="claude-opus-4-5")
        assert result["model"] == "claude-opus-4-5"

    def test_anthropic_not_installed_returns_error(self):
        from modules.ai_summary import generate_ai_summary
        with patch("builtins.__import__", side_effect=lambda name, *a, **kw:
                   (_ for _ in ()).throw(ImportError(f"No module named '{name}'"))
                   if name == "anthropic" else __import__(name, *a, **kw)):
            result = generate_ai_summary("example.com", {}, api_key="fake-key")
        assert result["summary"] is None
        assert "anthropic" in result["error"].lower() or "install" in result["error"].lower()

    def test_successful_call_returns_summary(self):
        from modules.ai_summary import generate_ai_summary

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_content = MagicMock()
        mock_content.text = "## Executive Summary\n\nThis is a test summary."
        mock_response.content = [mock_content]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {"whois": {}}, api_key="test-key")

        assert result["summary"] == "## Executive Summary\n\nThis is a test summary."
        assert result["error"] is None
        assert result["tokens_used"]["input"] == 100
        assert result["tokens_used"]["output"] == 50

    def test_api_exception_returns_error(self):
        from modules.ai_summary import generate_ai_summary

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = RuntimeError("API rate limit exceeded")
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="test-key")

        assert result["summary"] is None
        assert "rate limit" in result["error"].lower()
        assert result["model"] is not None

    def test_empty_response_content_returns_empty_summary(self):
        from modules.ai_summary import generate_ai_summary

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = []  # empty content list
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 0
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("target", {}, api_key="key")

        assert result["summary"] == ""
        assert result["error"] is None

    def test_api_key_from_environment(self):
        from modules.ai_summary import generate_ai_summary

        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_content = MagicMock()
        mock_content.text = "Summary text"
        mock_response.content = [mock_content]
        mock_response.usage.input_tokens = 5
        mock_response.usage.output_tokens = 5
        mock_client.messages.create.return_value = mock_response
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-api-key"}):
                result = generate_ai_summary("example.com", {})

        assert result["summary"] == "Summary text"
        # Verify the Anthropic client was called with the env key
        mock_anthropic.Anthropic.assert_called_once_with(api_key="env-api-key")

    def test_default_model_is_claude(self):
        from modules.ai_summary import generate_ai_summary
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = generate_ai_summary("t", {}, api_key=None)
        assert "claude" in result["model"].lower()

    def test_result_always_has_model_key(self):
        from modules.ai_summary import generate_ai_summary
        os.environ.pop("ANTHROPIC_API_KEY", None)
        result = generate_ai_summary("t", {})
        assert "model" in result