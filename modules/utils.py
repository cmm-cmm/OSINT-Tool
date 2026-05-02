"""
Shared utilities for OSINT Tool modules.

Provides:
  - Centralized HTTP session factory with retry logic
  - Common request headers
  - Rate-limited request helper
  - Input sanitization helpers
  - Internet connectivity check
  - Scan history logging
"""
import re
import time
import logging
import datetime
import certifi
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("osint")

# ─── Common HTTP headers ──────────────────────────────────────────────────────

HEADERS_GENERIC = {
    "User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)",
    "Accept": "application/json",
}

HEADERS_BROWSER = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

DEFAULT_TIMEOUT = 10  # seconds


# ─── Session factory ──────────────────────────────────────────────────────────

def make_session(
    retries: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple = (429, 500, 502, 503, 504),
    browser_ua: bool = False,
) -> requests.Session:
    """
    Return a requests.Session with:
    - Automatic retry with exponential backoff
    - SSL verification via certifi CA bundle
    - Standard OSINT-Tool headers

    Args:
        retries: Number of retry attempts on transient errors.
        backoff_factor: Seconds between retries (doubles each attempt).
        status_forcelist: HTTP status codes that trigger a retry.
        browser_ua: Use browser-like User-Agent instead of tool identifier.
    """
    session = requests.Session()
    session.verify = certifi.where()

    headers = HEADERS_BROWSER if browser_ua else HEADERS_GENERIC
    session.headers.update(headers)

    retry = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["GET", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)

    return session


def safe_get(
    url: str,
    session: requests.Session | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    **kwargs,
) -> requests.Response | None:
    """
    Perform a GET request, catching all exceptions.
    Returns the Response or None on failure.
    SSL always verified via certifi.
    """
    s = session or make_session()
    kwargs.setdefault("timeout", timeout)
    kwargs["verify"] = certifi.where()
    try:
        return s.get(url, **kwargs)
    except Exception as exc:
        logger.debug("GET %s failed: %s", url, exc)
        return None


# ─── Simple rate limiter ──────────────────────────────────────────────────────

class RateLimiter:
    """Token-bucket rate limiter for HTTP calls.

    Example::

        rl = RateLimiter(calls=5, period=1.0)  # 5 calls/second
        with rl:
            response = requests.get(url)
    """

    def __init__(self, calls: int = 5, period: float = 1.0) -> None:
        self.calls = calls
        self.period = period
        self._timestamps: list[float] = []

    def __enter__(self):
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self.period]
        if len(self._timestamps) >= self.calls:
            sleep_for = self.period - (now - self._timestamps[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
        self._timestamps.append(time.monotonic())
        return self

    def __exit__(self, *_):
        pass


# ─── Input sanitization ───────────────────────────────────────────────────────

# Allow only safe characters for values passed to external commands
_SAFE_CMD_VALUE_RE = re.compile(r'^[\w.@+\-]+$')


def sanitize_for_shell(value: str, max_length: int = 256) -> str:
    """
    Validate that ``value`` is safe to pass as an argument to a subprocess.
    Raises ValueError if it contains shell-unsafe characters.

    Only alphanumerics, dots, @, +, hyphen, underscore are allowed.
    """
    if len(value) > max_length:
        raise ValueError(f"Value too long ({len(value)} > {max_length})")
    if not _SAFE_CMD_VALUE_RE.match(value):
        raise ValueError(
            f"Value contains unsafe characters for shell invocation: {value!r}"
        )
    return value


# ─── Internet connectivity check ─────────────────────────────────────────────

def check_internet(timeout: int = 6) -> bool:
    """
    Return True if an outbound HTTPS connection can be made.
    Tries GitHub first, then Google, then Cloudflare DNS as fallback.
    Does NOT raise — always returns bool.
    """
    test_hosts = [
        ("github.com", 443),
        ("www.google.com", 443),
        ("1.1.1.1", 443),
    ]
    import socket
    for host, port in test_hosts:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except OSError:
            continue
    return False


# ─── Scan history logging ─────────────────────────────────────────────────────

def append_scan_history(module_title: str, target: str, status: str = "ok") -> None:
    """
    Append a one-line JSON record to ~/.osint-tool/history.jsonl.
    Fields: timestamp, module, target, status.
    Silently ignores write errors.
    """
    from modules.constants import USER_CONFIG_DIR
    try:
        history_file = USER_CONFIG_DIR / "history.jsonl"
        USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.datetime.now().isoformat(timespec="seconds"),
            "module": module_title,
            "target": target,
            "status": status,
        }
        import json
        with open(history_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass


def read_scan_history(limit: int = 50) -> list[dict]:
    """Return last `limit` scan records from history.jsonl, newest first."""
    from modules.constants import USER_CONFIG_DIR
    import json
    history_file = USER_CONFIG_DIR / "history.jsonl"
    if not history_file.exists():
        return []
    try:
        lines = history_file.read_text(encoding="utf-8").splitlines()
        records = []
        for line in lines:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return list(reversed(records[-limit:]))
    except Exception:
        return []
