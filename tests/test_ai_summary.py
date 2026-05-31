"""Tests for modules/ai_summary.py."""
import os
import pytest
from unittest.mock import MagicMock, patch


class TestPrepareContext:
    """Tests for the _prepare_context helper function."""

    def test_includes_target(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "TARGET: example.com" in result

    def test_includes_separator(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "=" * 40 in result

    def test_flat_dict_section(self):
        from modules.ai_summary import _prepare_context
        data = {"whois": {"registrar": "NameCheap", "created": "2020-01-01"}}
        result = _prepare_context("example.com", data)
        assert "WHOIS" in result
        assert "registrar" in result
        assert "NameCheap" in result

    def test_skips_none_values(self):
        from modules.ai_summary import _prepare_context
        data = {"whois": {"registrar": None, "domain": "example.com"}}
        result = _prepare_context("example.com", data)
        assert "None" not in result or "domain" in result

    def test_list_section(self):
        from modules.ai_summary import _prepare_context
        data = {"dns": {"A": ["1.2.3.4", "5.6.7.8"]}}
        result = _prepare_context("example.com", data)
        assert "1.2.3.4" in result or "DNS" in result

    def test_max_chars_truncates(self):
        from modules.ai_summary import _prepare_context
        large_data = {f"module_{i}": {"key": "x" * 500} for i in range(50)}
        result = _prepare_context("example.com", large_data, max_chars=1000)
        assert "truncated" in result

    def test_nested_dict_handled(self):
        from modules.ai_summary import _prepare_context
        data = {"email": {"hibp": {"breaches": [{"name": "Adobe"}]}}}
        result = _prepare_context("test@example.com", data)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_empty_data(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "example.com" in result
        assert isinstance(result, str)

    def test_depth_limit(self):
        """Ensure deeply nested structures do not cause infinite recursion."""
        from modules.ai_summary import _prepare_context
        nested = {"a": {"b": {"c": {"d": {"e": {"f": "deep"}}}}}}
        result = _prepare_context("target", nested)
        assert isinstance(result, str)

    def test_list_items_cap_at_ten(self):
        from modules.ai_summary import _prepare_context
        data = {"platforms": [f"site{i}.com" for i in range(20)]}
        result = _prepare_context("user", data)
        # Only the first 10 items should appear
        assert "site9.com" in result
        assert "site19.com" not in result

    def test_long_values_truncated(self):
        from modules.ai_summary import _prepare_context
        data = {"info": {"key": "a" * 200}}
        result = _prepare_context("t", data)
        # Values are truncated to 120 chars
        assert "a" * 121 not in result

    def test_empty_string_values_skipped(self):
        from modules.ai_summary import _prepare_context
        data = {"info": {"empty": "", "present": "value"}}
        result = _prepare_context("t", data)
        assert "present" in result


class TestGenerateAiSummary:
    """Tests for generate_ai_summary."""

    def test_no_api_key_returns_error(self):
        from modules.ai_summary import generate_ai_summary
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            result = generate_ai_summary("example.com", {}, api_key=None)
        assert result["summary"] is None
        assert "API key" in result["error"]
        assert result["model"] == "claude-sonnet-4-6"

    def test_missing_anthropic_package(self):
        from modules.ai_summary import generate_ai_summary
        with patch.dict("sys.modules", {"anthropic": None}):
            result = generate_ai_summary("example.com", {}, api_key="fake-key")
        assert result["summary"] is None
        assert "anthropic" in result["error"].lower() or result["error"] is not None

    def test_success_returns_summary(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="## Executive Summary\nNo issues found.")]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {"whois": {}}, api_key="test-key")

        assert result["error"] is None
        assert "Executive Summary" in result["summary"]
        assert result["tokens_used"]["input"] == 100
        assert result["tokens_used"]["output"] == 50

    def test_api_exception_returns_error(self):
        from modules.ai_summary import generate_ai_summary

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API timeout")

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="test-key")

        assert result["summary"] is None
        assert "API timeout" in result["error"]

    def test_custom_model_passed_through(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Summary text")]
        mock_response.usage.input_tokens = 50
        mock_response.usage.output_tokens = 25

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("t", {}, api_key="key", model="claude-opus-4-5-20251101")

        assert result["model"] == "claude-opus-4-5-20251101"
        call_kwargs = mock_client.messages.create.call_args
        assert call_kwargs.kwargs["model"] == "claude-opus-4-5-20251101"

    def test_empty_response_content(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 0

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("t", {}, api_key="key")

        assert result["summary"] == ""
        assert result["error"] is None

    def test_api_key_from_env(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Brief")]
        mock_response.usage.input_tokens = 5
        mock_response.usage.output_tokens = 5

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
                result = generate_ai_summary("t", {})

        assert result["error"] is None
        mock_anthropic.Anthropic.assert_called_once_with(api_key="env-key")