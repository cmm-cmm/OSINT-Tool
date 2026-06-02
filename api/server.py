"""
OSINT Tool REST API Server

Exposes core OSINT modules as a RESTful HTTP API using FastAPI.
Start with: uvicorn api.server:app --reload --port 8000

Authentication: Set API_KEYS=key1,key2 in .env and pass X-API-Key header.
               If API_KEYS is unset, the server runs without auth (dev mode).
Rate limiting:  Set RATE_LIMIT=60 (requests per minute per key) in .env.
"""
import ipaddress
import os
import re
import uuid
import time
import datetime
import sys
import collections
import threading
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from fastapi import FastAPI, HTTPException, Query, Request, Depends
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.security import APIKeyHeader
    import uvicorn
except ImportError:
    raise ImportError(
        "FastAPI and uvicorn are required for the API server. "
        "Install with: pip install fastapi uvicorn[standard]"
    )

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from api.models import ScanRequest, ScanResponse, CacheStatsResponse, HistoryEntry
from modules.cache import get_cache, OsintCache
from modules.utils import read_scan_history, append_scan_history
from modules.report import save_report
from modules.report_interactive import save_interactive_report

logger = logging.getLogger("osint.api")

app = FastAPI(
    title="OSINT Tool API",
    description="RESTful API for OSINT Tool — gather public intelligence programmatically.",
    version="1.3.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

def _safe_cors_origins() -> list[str]:
    """Parse CORS_ORIGINS env var, accepting only well-formed http(s) origins."""
    _origin_re = re.compile(r'^https?://[a-zA-Z0-9.\-]+(:\d{1,5})?$')
    raw = os.getenv("CORS_ORIGINS", "")
    validated = [o.strip() for o in raw.split(",") if _origin_re.match(o.strip())]
    return validated if validated else ["http://localhost:8000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_safe_cors_origins(),
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"],
)


# ── API Key Authentication ────────────────────────────────────────────────────

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

def _load_api_keys() -> set[str]:
    """Load valid API keys from env (comma-separated). Empty = auth disabled."""
    raw = os.getenv("API_KEYS", "").strip()
    return {k.strip() for k in raw.split(",") if k.strip()} if raw else set()

async def verify_api_key(api_key: str | None = Depends(_API_KEY_HEADER)) -> str | None:
    """Dependency: validate API key if auth is configured."""
    valid_keys = _load_api_keys()
    if not valid_keys:
        return "anonymous"
    if not api_key or api_key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header")
    return api_key


# ── Rate Limiting ─────────────────────────────────────────────────────────────

_rate_lock = threading.Lock()
_rate_windows: dict[str, list[float]] = collections.defaultdict(list)
_RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))   # requests per minute per key
_RATE_WINDOW = 60.0                                 # seconds

def _check_rate_limit(key: str) -> None:
    """Raise 429 if the key has exceeded the rate limit."""
    if _RATE_LIMIT <= 0:
        return
    now = time.monotonic()
    with _rate_lock:
        window = _rate_windows[key]
        cutoff = now - _RATE_WINDOW
        while window and window[0] < cutoff:
            window.pop(0)
        if len(window) >= _RATE_LIMIT:
            retry_after = int(_RATE_WINDOW - (now - window[0])) + 1
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({_RATE_LIMIT} req/min). Retry after {retry_after}s",
                headers={"Retry-After": str(retry_after)},
            )
        window.append(now)


async def _auth_and_rate(api_key: str | None = Depends(verify_api_key)) -> str:
    """Combined dependency: auth + rate limit check."""
    key_id = api_key or "anonymous"
    _check_rate_limit(key_id)
    return key_id

# Input validation regexes for SSRF prevention
_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
_EMAIL_RE = re.compile(
    r'^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$'
)
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-@+]{1,100}$')


def _validate_scan_target(raw_target: str, scan_type: str) -> str:
    """Validate and sanitize scan target to prevent SSRF. Raises HTTPException on invalid input."""
    if not raw_target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    target = raw_target.strip()
    if len(target) > 253:
        raise HTTPException(status_code=400, detail="Target too long (max 253 characters)")

    if scan_type in ("domain", "ssl", "whois", "dns", "ip"):
        try:
            addr = ipaddress.ip_address(target)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                raise HTTPException(status_code=400, detail="Private/internal addresses not allowed")
            return str(addr)
        except ValueError:
            if not _DOMAIN_RE.match(target):
                raise HTTPException(status_code=400, detail="Invalid domain, IP, or hostname format")
            return urlparse(f"https://{target}/").hostname or target
    elif scan_type == "email":
        if not _EMAIL_RE.match(target):
            raise HTTPException(status_code=400, detail="Invalid email address format")
        return target
    elif scan_type in ("username", "breach"):
        if not _EMAIL_RE.match(target) and not _USERNAME_RE.match(target):
            raise HTTPException(status_code=400, detail="Invalid username or email format")
        return target

    return target


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health() -> dict:
    """Return API health status."""
    return {
        "status": "ok",
        "version": "1.3.0",
        "timestamp": datetime.datetime.now().isoformat(),
        "auth_enabled": bool(_load_api_keys()),
        "rate_limit": _RATE_LIMIT,
    }


# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/scan/domain", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def scan_domain(target: str = Query(..., description="Domain or IP to scan"),
                      use_cache: bool = True):
    """Run domain/IP intelligence scan (WHOIS, DNS, IP geo)."""
    safe_target = _validate_scan_target(target, "domain")
    return await _run_module("domain", safe_target, use_cache)  # NOSONAR


@app.post("/scan/email", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def scan_email(target: str = Query(..., description="Email address to scan"),
                     use_cache: bool = True):
    """Run email OSINT (validation, breach check, SMTP verify)."""
    safe_target = _validate_scan_target(target, "email")
    return await _run_module("email", safe_target, use_cache)  # NOSONAR


@app.post("/scan/username", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def scan_username(target: str = Query(..., description="Username to search"),
                        use_cache: bool = True):
    """Search username across 40+ platforms."""
    safe_target = _validate_scan_target(target, "username")
    return await _run_module("username", safe_target, use_cache)  # NOSONAR


@app.post("/scan/ip", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def scan_ip(target: str = Query(..., description="IP address to scan"),
                  use_cache: bool = True):
    """Run IP geolocation and intelligence scan."""
    safe_target = _validate_scan_target(target, "ip")
    return await _run_module("ip", safe_target, use_cache)  # NOSONAR


@app.post("/scan/breach", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def scan_breach(target: str = Query(..., description="Email or username to check"),
                      use_cache: bool = True):
    """Check for data breaches."""
    safe_target = _validate_scan_target(target, "breach")
    return await _run_module("breach", safe_target, use_cache)  # NOSONAR


@app.post("/scan", response_model=ScanResponse, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def full_scan(request: ScanRequest):
    """
    Run multiple OSINT modules in one request.

    Supported modules: whois, dns, ip, email, username, ssl, breach, cloud, social
    """
    validated_target = _validate_scan_target(request.target, "domain")
    scan_id = str(uuid.uuid4())[:8]
    started_at = datetime.datetime.now().isoformat()
    start_ms = time.monotonic()
    results: dict[str, Any] = {}
    cache = get_cache() if request.use_cache else None

    for module in request.modules:
        cache_key = OsintCache.make_key(module, validated_target) if cache else None

        if cache and cache_key:
            cached = cache.get(cache_key)
            if cached:
                results[module] = cached
                continue

        try:
            data = await _dispatch_module(module, validated_target)  # NOSONAR
            results[module] = data
            if cache and cache_key and data:
                cache.set(cache_key, data, ttl=request.cache_ttl, module=module)
            append_scan_history(module, validated_target, "ok")
        except Exception as exc:
            results[module] = {"error": str(exc)}
            append_scan_history(module, validated_target, "error")

    # Generate reports
    output_dir = os.getenv("OSINT_OUTPUT_DIR", "./reports")
    report_paths = {}
    try:
        paths = save_report(validated_target, results, output_dir)
        report_paths.update(paths)
    except Exception:
        pass

    if request.output_format == "interactive":
        try:
            ipaths = save_interactive_report(validated_target, results, output_dir)
            report_paths.update(ipaths)
        except Exception:
            pass

    completed_at = datetime.datetime.now().isoformat()
    duration_ms = int((time.monotonic() - start_ms) * 1000)

    return ScanResponse(
        target=validated_target,
        scan_id=scan_id,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=duration_ms,
        modules_run=request.modules,
        results=results,
        report_paths=report_paths,
    )


# ── Pipeline endpoint ─────────────────────────────────────────────────────────

@app.post("/scan/pipeline", response_model=dict, tags=["Scan"],
          dependencies=[Depends(_auth_and_rate)])
async def pipeline_scan(
    target: str = Query(..., description="Target to scan"),
    preset: str = Query(default="auto", description="Preset: auto, domain, email, username, ip, quick, full"),
):
    """Run a full pipeline scan with automatic module selection based on preset."""
    safe_target = _validate_scan_target(target, "domain")
    try:
        from modules.pipeline import run_pipeline
        result = run_pipeline(safe_target, preset=preset)  # NOSONAR
        return result
    except ImportError:
        raise HTTPException(status_code=503, detail="Pipeline module not available")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Export endpoints ──────────────────────────────────────────────────────────

@app.post("/export/stix", tags=["Export"],
          dependencies=[Depends(_auth_and_rate)])
async def export_stix(
    target: str = Query(..., description="Target to export (must have been scanned)"),
):
    """Export scan results as STIX 2.1 + MISP format."""
    safe_target = _validate_scan_target(target, "domain")
    try:
        from modules.db import get_db
        from modules.export_stix import to_stix_bundle, to_misp_event
        db = get_db()
        records = db.search(query=safe_target, limit=1)
        if not records:
            raise HTTPException(status_code=404, detail=f"No scan data found for {safe_target}")
        scan_data = db.get_scan(records[0]["id"])
        data = scan_data.get("data", {}) if scan_data else {}
        return {
            "stix_bundle": to_stix_bundle(safe_target, data),
            "misp_event": to_misp_event(safe_target, data),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── Cache endpoints ───────────────────────────────────────────────────────────

@app.get("/cache/stats", response_model=CacheStatsResponse, tags=["Cache"])
def cache_stats():
    """Return cache statistics."""
    stats = get_cache().stats()
    return CacheStatsResponse(
        total_entries=stats.get("total_entries", 0),
        active_entries=stats.get("active_entries", 0),
        expired_entries=stats.get("expired_entries", 0),
        total_hits=stats.get("total_hits", 0),
        by_module=stats.get("by_module", {}),
        db_path=stats.get("db_path", ""),
    )


@app.delete("/cache", tags=["Cache"])
def clear_cache(module: str = Query(default="", description="Module to clear (empty = all)")):
    """Clear cache entries. Optionally filter by module."""
    deleted = get_cache().clear(module=module)
    return {"deleted": deleted, "module": module or "all"}


@app.post("/cache/cleanup", tags=["Cache"])
def cleanup_cache():
    """Remove expired cache entries."""
    deleted = get_cache().cleanup_expired()
    return {"expired_entries_removed": deleted}


# ── History endpoints ─────────────────────────────────────────────────────────

@app.get("/history", response_model=list[HistoryEntry], tags=["History"])
def get_history(limit: int = Query(default=50, le=500, description="Max records to return")):
    """Return recent scan history."""
    records = read_scan_history(limit=limit)
    return [HistoryEntry(**r) for r in records]


# ── Report endpoints ──────────────────────────────────────────────────────────

@app.get("/reports", tags=["Reports"])
def list_reports():
    """List available report files from the configured output directory."""
    p = Path(os.getenv("OSINT_OUTPUT_DIR", "./reports"))
    if not p.exists():
        return {"reports": []}
    files = [
        {"name": f.name, "size_kb": round(f.stat().st_size / 1024, 1),
         "modified": datetime.datetime.fromtimestamp(f.stat().st_mtime).isoformat()}
        for f in sorted(p.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)
        if f.is_file() and f.suffix in (".html", ".json", ".csv")
    ]
    return {"reports": files, "directory": str(p.absolute())}


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _run_module(module: str, target: str, use_cache: bool = True) -> dict:
    """Run a single module, with optional cache lookup."""
    cache = get_cache() if use_cache else None
    cache_key = OsintCache.make_key(module, target) if cache else None

    if cache and cache_key:
        hit = cache.get(cache_key)
        if hit:
            return {"target": target, "module": module, "data": hit, "cached": True}

    t0 = time.monotonic()
    try:
        data = await _dispatch_module(module, target)  # NOSONAR
        duration_ms = int((time.monotonic() - t0) * 1000)
        if cache and cache_key and data:
            cache.set(cache_key, data, module=module)
        append_scan_history(module, target, "ok")
        return {"target": target, "module": module, "data": data, "cached": False, "duration_ms": duration_ms}
    except Exception as exc:
        append_scan_history(module, target, "error")
        raise HTTPException(status_code=500, detail=str(exc))


async def _dispatch_module(module: str, target: str) -> dict:
    """Dispatch to the appropriate OSINT module. Target is pre-validated by _validate_scan_target."""
    if module == "whois":
        from modules.whois_lookup import whois_lookup
        return whois_lookup(target) or {}  # NOSONAR
    elif module == "dns":
        from modules.whois_lookup import dns_enum
        return dns_enum(target) or {}  # NOSONAR
    elif module == "ip":
        from modules.ip_lookup import ip_lookup
        return ip_lookup(target) or {}  # NOSONAR
    elif module == "email":
        from modules.email_recon import email_recon
        key = os.getenv("HIBP_API_KEY", "")
        return email_recon(target, hibp_api_key=key) or {}  # NOSONAR
    elif module == "username":
        from modules.username_search import username_search
        return username_search(target) or {}  # NOSONAR
    elif module == "ssl":
        from modules.ssl_analyzer import ssl_analyze
        return ssl_analyze(target) or {}  # NOSONAR
    elif module == "breach":
        from modules.breach_check import breach_check
        key = os.getenv("HIBP_API_KEY", "")
        return breach_check(target, hibp_key=key) or {}  # NOSONAR
    elif module == "cloud":
        from modules.cloud_recon import cloud_recon
        return cloud_recon(target) or {}  # NOSONAR
    elif module == "social":
        from modules.social_recon import facebook_recon
        fb_key = os.getenv("FACEBOOK_SCRAPER_KEY", "")
        return facebook_recon(target, fb_scraper_key=fb_key) or {}  # NOSONAR
    else:
        raise ValueError(f"Unknown module: {module}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
