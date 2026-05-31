"""
Unified exception hierarchy for OSINT Tool.
All modules should raise these instead of bare Exception.
"""

class OsintError(Exception):
    """Base exception for all OSINT Tool errors."""
    def __init__(self, message: str, module: str = "", target: str = ""):
        super().__init__(message)
        self.message = message
        self.module = module
        self.target = target

    def __str__(self):
        prefix = f"[{self.module}]" if self.module else ""
        return f"{prefix} {self.message}".strip()


class NetworkError(OsintError):
    """Raised when a network request fails (timeout, DNS, connection)."""

class APIError(OsintError):
    """Raised when an external API returns an error response."""
    def __init__(self, message: str, status_code: int = 0, **kwargs):
        super().__init__(message, **kwargs)
        self.status_code = status_code

class APIKeyMissingError(OsintError):
    """Raised when a required API key is not configured."""
    def __init__(self, key_name: str, **kwargs):
        super().__init__(f"API key not set: {key_name}. Add it to .env", **kwargs)
        self.key_name = key_name

class RateLimitError(APIError):
    """Raised when hitting rate limits (HTTP 429)."""
    def __init__(self, service: str = "", retry_after: int = 0, **kwargs):
        msg = f"Rate limited by {service}" if service else "Rate limited"
        if retry_after:
            msg += f" (retry after {retry_after}s)"
        super().__init__(msg, status_code=429, **kwargs)
        self.retry_after = retry_after

class ValidationError(OsintError):
    """Raised when input validation fails."""

class TargetNotFoundError(OsintError):
    """Raised when the OSINT target does not exist on the platform."""

class DependencyMissingError(OsintError):
    """Raised when an optional dependency is required but not installed."""
    def __init__(self, dep_name: str, install_cmd: str = "", **kwargs):
        msg = f"Optional dependency '{dep_name}' is not installed."
        if install_cmd:
            msg += f" Install with: {install_cmd}"
        super().__init__(msg, **kwargs)
        self.dep_name = dep_name
        self.install_cmd = install_cmd

class ParseError(OsintError):
    """Raised when parsing/extracting data from a response fails."""

class CacheError(OsintError):
    """Raised when cache read/write operations fail."""

class ReportError(OsintError):
    """Raised when report generation fails."""

class SchedulerError(OsintError):
    """Raised when the scan scheduler encounters an error."""
