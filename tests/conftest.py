"""
Pytest configuration and shared fixtures for OSINT Tool tests.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Make sure project root is importable
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def mock_requests_session():
    """Return a mock requests.Session for HTTP call isolation."""
    session = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {}
    mock_resp.text = ""
    session.get.return_value = mock_resp
    session.post.return_value = mock_resp
    return session


@pytest.fixture
def sample_domain():
    return "example.com"


@pytest.fixture
def sample_ip():
    return "93.184.216.34"


@pytest.fixture
def sample_email():
    return "test@example.com"


@pytest.fixture
def sample_username():
    return "testuser123"


@pytest.fixture
def sample_report_data():
    """Minimal all_data dict accepted by save_report / build_html_report."""
    return {
        "whois": {"domain": "example.com", "registrar": "Test Registrar"},
        "dns": {"A": ["93.184.216.34"], "MX": ["mail.example.com"]},
    }


@pytest.fixture
def tmp_output_dir(tmp_path):
    """Provide a temporary directory for report output."""
    return str(tmp_path)
