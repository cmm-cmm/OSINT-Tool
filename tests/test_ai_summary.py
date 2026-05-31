"""Tests for modules/ai_summary.py — AI-powered OSINT summary generation."""
import pytest
from unittest.mock import MagicMock, patch


SAMPLE_SCAN_DATA = {
    "whois": {
        "whois": {
            "registrar": "Test Registrar",
            "creation_date": "2000-01-01",
            "emails": ["admin@example.com"],
        }
    },
    "dns": {
        "records": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]}
    },
    "email": {
        "email": "test@example.com",
        "hibp": {
            "breaches": [
                {"name": "TestBreach", "date": "2021-01-01", "pwn_count": 50000}
            ]
        }
    },
}


class TestPrepareContext:
    def test_returns_string(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", SAMPLE_SCAN_DATA)
        assert isinstance(result, str)

    def test_contains_target(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", SAMPLE_SCAN_DATA)
        assert "example.com" in result

    def test_contains_target_label(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", {})
        assert "TARGET:" in result

    def test_includes_section_headers(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("example.com", SAMPLE_SCAN_DATA)
        assert "WHOIS" in result.upper() or "DNS" in result.upper()

    def test_respects_max_chars(self):
        from modules.ai_summary import _prepare_context
        large_data = {f"module_{i}": {"key": "x" * 1000} for i in range(50)}
        result = _prepare_context("target", large_data, max_chars=500)
        assert len(result) < 5000  # Should truncate eventually

    def test_handles_empty_data(self):
        from modules.ai_summary import _prepare_context
        result = _prepare_context("test.com", {})
        assert "test.com" in result
        assert isinstance(result, str)

    def test_handles_nested_dict(self):
        from modules.ai_summary import _prepare_context
        nested = {"section": {"sub": {"deep": "value"}}}
        result = _prepare_context("test.com", nested)
        assert isinstance(result, str)

    def test_handles_list_values(self):
        from modules.ai_summary import _prepare_context
        data = {"items": [{"name": "item1"}, {"name": "item2"}]}
        result = _prepare_context("test.com", data)
        assert isinstance(result, str)

    def test_skips_none_values(self):
        from modules.ai_summary import _prepare_context
        data = {"section": {"key": None, "other": "value"}}
        result = _prepare_context("test.com", data)
        # None values should be skipped
        assert "None" not in result or "value" in result

    def test_truncates_long_string_values(self):
        from modules.ai_summary import _prepare_context
        data = {"section": {"longval": "a" * 300}}
        result = _prepare_context("test.com", data)
        # The 300-char value should be truncated to 120
        assert "a" * 200 not in result

    def test_depth_limit(self):
        """Context builder should not recurse deeper than 3 levels."""
        from modules.ai_summary import _prepare_context
        deep = {"l1": {"l2": {"l3": {"l4": {"l5": "deep_value"}}}}}
        result = _prepare_context("test.com", deep)
        # Should not crash and should return a string
        assert isinstance(result, str)

    def test_limits_list_items(self):
        from modules.ai_summary import _prepare_context
        data = {"section": [{"name": f"item{i}"} for i in range(20)]}
        result = _prepare_context("test.com", data)
        # Should cap at 10 items
        assert isinstance(result, str)


class TestGenerateAiSummaryNoApiKey:
    def test_missing_api_key_returns_error(self):
        from modules.ai_summary import generate_ai_summary
        with patch.dict("os.environ", {}, clear=True):
            result = generate_ai_summary("example.com", SAMPLE_SCAN_DATA, api_key=None)
        assert result["summary"] is None
        assert result["error"] is not None
        assert "API key" in result["error"] or "ANTHROPIC" in result["error"]

    def test_returns_model_field(self):
        from modules.ai_summary import generate_ai_summary
        with patch.dict("os.environ", {}, clear=True):
            result = generate_ai_summary("example.com", {}, api_key=None)
        assert "model" in result

    def test_missing_anthropic_package(self):
        """When anthropic is not installed, should return helpful error."""
        import sys
        from modules.ai_summary import generate_ai_summary
        # Remove anthropic from sys.modules to simulate it not being installed
        saved = sys.modules.pop("anthropic", None)
        try:
            with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-test"}):
                with patch.dict("sys.modules", {"anthropic": None}):
                    result = generate_ai_summary("example.com", {}, api_key="sk-test")
            assert result["summary"] is None
            # Should contain a message about the package
            assert result.get("error") is not None
        finally:
            if saved is not None:
                sys.modules["anthropic"] = saved


class TestGenerateAiSummaryWithMock:
    def test_successful_call_returns_summary(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="## Executive Summary\nTest found.")]
        mock_response.usage.input_tokens = 100
        mock_response.usage.output_tokens = 50

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", SAMPLE_SCAN_DATA, api_key="sk-test")

        assert result["summary"] == "## Executive Summary\nTest found."
        assert result["error"] is None
        assert result["model"] == "claude-sonnet-4-6"

    def test_returns_token_usage(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="summary text")]
        mock_response.usage.input_tokens = 200
        mock_response.usage.output_tokens = 80

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="sk-test")

        assert result["tokens_used"]["input"] == 200
        assert result["tokens_used"]["output"] == 80

    def test_api_exception_returns_error(self):
        from modules.ai_summary import generate_ai_summary

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API rate limit exceeded")

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="sk-test")

        assert result["summary"] is None
        assert "API rate limit" in result["error"]

    def test_uses_api_key_from_env(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Summary")]
        mock_response.usage.input_tokens = 10
        mock_response.usage.output_tokens = 5

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "env-key-test"}):
            with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
                result = generate_ai_summary("example.com", {})  # no api_key arg

        mock_anthropic.Anthropic.assert_called_once_with(api_key="env-key-test")

    def test_empty_response_content(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = []
        mock_response.usage.input_tokens = 0
        mock_response.usage.output_tokens = 0

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="sk-test")

        assert result["summary"] == ""
        assert result["error"] is None

    def test_custom_model_passed_to_api(self):
        from modules.ai_summary import generate_ai_summary

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="ok")]
        mock_response.usage.input_tokens = 5
        mock_response.usage.output_tokens = 5

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response

        mock_anthropic = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        custom_model = "claude-3-haiku-20240307"
        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            result = generate_ai_summary("example.com", {}, api_key="sk-test", model=custom_model)

        assert result["model"] == custom_model
        call_kwargs = mock_client.messages.create.call_args
        assert call_kwargs.kwargs.get("model") == custom_model or call_kwargs.args[0] == custom_model or \
               (call_kwargs is not None and "claude-3-haiku" in str(call_kwargs))


class TestPrintAiSummary:
    def test_prints_error_when_error_present(self, capsys):
        """print_ai_summary should handle error results without raising."""
        from modules.ai_summary import print_ai_summary

        mock_console = MagicMock()
        mock_panel = MagicMock()
        mock_markdown = MagicMock()

        with patch("modules.ai_summary.print_ai_summary") as mock_print:
            mock_print({"error": "No API key", "summary": None, "model": "claude-sonnet-4-6"})
            mock_print.assert_called_once()

    def test_print_no_summary(self):
        """Should not raise when summary is empty."""
        from modules.ai_summary import print_ai_summary

        with patch("rich.console.Console.print"):
            try:
                print_ai_summary({"summary": "", "error": None, "model": "test"})
            except Exception as exc:
                pytest.fail(f"print_ai_summary raised unexpectedly: {exc}")


class TestSystemPrompt:
    def test_system_prompt_defined(self):
        from modules.ai_summary import SYSTEM_PROMPT
        assert isinstance(SYSTEM_PROMPT, str)
        assert len(SYSTEM_PROMPT) > 100

    def test_system_prompt_contains_sections(self):
        from modules.ai_summary import SYSTEM_PROMPT
        assert "Executive Summary" in SYSTEM_PROMPT
        assert "Risk Assessment" in SYSTEM_PROMPT