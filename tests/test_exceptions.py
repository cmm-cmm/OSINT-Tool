"""Tests for the unified exception hierarchy."""
import pytest
from modules.exceptions import (
    OsintError, NetworkError, APIError, APIKeyMissingError,
    RateLimitError, ValidationError, TargetNotFoundError,
    DependencyMissingError, ParseError, CacheError, ReportError,
)


class TestOsintError:
    def test_basic_message(self):
        exc = OsintError("something went wrong")
        assert str(exc) == "something went wrong"
        assert exc.message == "something went wrong"

    def test_with_module(self):
        exc = OsintError("failed", module="whois")
        assert "[whois]" in str(exc)

    def test_with_target(self):
        exc = OsintError("not found", module="dns", target="example.com")
        assert exc.target == "example.com"

    def test_is_exception(self):
        exc = OsintError("test")
        assert isinstance(exc, Exception)


class TestNetworkError:
    def test_is_osint_error(self):
        exc = NetworkError("timeout")
        assert isinstance(exc, OsintError)

    def test_message(self):
        exc = NetworkError("connection refused", module="ip_lookup")
        assert "connection refused" in str(exc)


class TestAPIError:
    def test_status_code(self):
        exc = APIError("forbidden", status_code=403)
        assert exc.status_code == 403

    def test_default_status_code(self):
        exc = APIError("error")
        assert exc.status_code == 0

    def test_is_osint_error(self):
        assert isinstance(APIError("x"), OsintError)


class TestAPIKeyMissingError:
    def test_key_name_in_message(self):
        exc = APIKeyMissingError("SHODAN_KEY")
        assert "SHODAN_KEY" in str(exc)
        assert exc.key_name == "SHODAN_KEY"

    def test_is_osint_error(self):
        assert isinstance(APIKeyMissingError("X"), OsintError)


class TestRateLimitError:
    def test_is_api_error(self):
        exc = RateLimitError(service="HIBP")
        assert isinstance(exc, APIError)
        assert exc.status_code == 429

    def test_retry_after(self):
        exc = RateLimitError(service="HIBP", retry_after=60)
        assert exc.retry_after == 60
        assert "60" in str(exc)

    def test_service_in_message(self):
        exc = RateLimitError(service="Shodan")
        assert "Shodan" in str(exc)


class TestDependencyMissingError:
    def test_dep_name(self):
        exc = DependencyMissingError("holehe", install_cmd="pip install holehe")
        assert exc.dep_name == "holehe"
        assert "holehe" in str(exc)
        assert "pip install" in str(exc)

    def test_no_install_cmd(self):
        exc = DependencyMissingError("maigret")
        assert isinstance(exc, OsintError)


class TestValidationError:
    def test_basic(self):
        exc = ValidationError("invalid email format")
        assert "invalid email" in str(exc)
        assert isinstance(exc, OsintError)


class TestTargetNotFoundError:
    def test_basic(self):
        exc = TargetNotFoundError("user not found", target="ghost_user")
        assert exc.target == "ghost_user"


class TestInheritanceChain:
    def test_catch_as_base(self):
        errors = [
            NetworkError("x"), APIError("x"), RateLimitError(),
            ValidationError("x"), DependencyMissingError("x"),
        ]
        for e in errors:
            assert isinstance(e, OsintError), f"{type(e)} should be OsintError"

    def test_catch_as_exception(self):
        with pytest.raises(OsintError):
            raise NetworkError("test")

    def test_catch_api_error_catches_rate_limit(self):
        with pytest.raises(APIError):
            raise RateLimitError(service="test")


class TestSchedulerError:
    def test_basic_message(self):
        from modules.exceptions import SchedulerError
        exc = SchedulerError("No job found with ID: abc123")
        assert "No job found" in str(exc)

    def test_is_osint_error(self):
        from modules.exceptions import SchedulerError
        exc = SchedulerError("scheduler failed")
        assert isinstance(exc, OsintError)

    def test_is_exception(self):
        from modules.exceptions import SchedulerError
        exc = SchedulerError("test")
        assert isinstance(exc, Exception)

    def test_with_module(self):
        from modules.exceptions import SchedulerError
        exc = SchedulerError("job failed", module="scheduler")
        assert "[scheduler]" in str(exc)

    def test_raise_and_catch_as_osint_error(self):
        from modules.exceptions import SchedulerError
        with pytest.raises(OsintError):
            raise SchedulerError("test scheduler error")

    def test_message_attribute(self):
        from modules.exceptions import SchedulerError
        exc = SchedulerError("custom message")
        assert exc.message == "custom message"
