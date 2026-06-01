"""
OSINT Tool REST API Server

Exposes core OSINT modules as a RESTful HTTP API using FastAPI.
Start with: uvicorn api.server:app --reload --port 8000
"""
import ipaddress
import os
import re
import uuid
import time
import datetime
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from fastapi import FastAPI, HTTPException, Query
    from fastapi.middleware.cors import CORSMiddleware
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

app = FastAPI(
    title="OSINT Tool API",
    description="RESTful API for OSINT Tool — gather public intelligence programmatically.",
    version="1.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

_cors_origins_env = os.getenv("CORS_ORIGINS", "")
_cors_origins: list[str] = [
    o.strip() for o in _cors_origins_env.split(",")
    if o.strip() and o.strip() not in ("*", "")
]
if not _cors_origins:
    _cors_origins = ["http://localhost:8000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,  # NOSONAR - wildcard explicitly excluded above
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Input validation regexes for SSRF prevention
_DOMAIN_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)
_EMAIL_RE = re.compile(
    r'^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,}$'
)
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9._\-@+]{1,100}$')


def _validate_scan_target(target: str, scan_type: str) -> str:
    """Validate and sanitize scan target to prevent SSRF. Raises HTTPException on invalid input."""
    if not target:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    target = target.strip()
    if len(target) > 253:
        raise HTTPException(status_code=400, detail="Target too long (max 253 characters)")

    if scan_type in ("domain", "ssl", "whois", "dns"):
        try:
            addr = ipaddress.ip_address(target)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                raise HTTPException(status_code=400, detail="Private/internal addresses not allowed")
            return str(addr)
        except ValueError:
            if not _DOMAIN_RE.match(target):
                raise HTTPException(status_code=400, detail="Invalid domain or IP address format")
            return urlparse(f"https://{target}/").hostname or target
    elif scan_type == "ip":
        try:
            addr = ipaddress.ip_address(target)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast:
                raise HTTPException(status_code=400, detail="Private/internal IP addresses not allowed")
            return str(addr)
        except ValueError:
            if not _DOMAIN_RE.match(target):
                raise HTTPException(status_code=400, detail="Invalid IP address or hostname format")
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
        "version": "1.2.0",
        "timestamp": datetime.datetime.now().isoformat(),
    }


# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/scan/domain", response_model=dict, tags=["Scan"])
async def scan_domain(target: str = Query(..., description="Domain or IP to scan"),
                      use_cache: bool = True):
    """Run domain/IP intelligence scan (WHOIS, DNS, IP geo)."""
    safe_target = _validate_scan_target(target, "domain")
    return await _run_module("domain", safe_target, use_cache)


@app.post("/scan/email", response_model=dict, tags=["Scan"])
async def scan_email(target: str = Query(..., description="Email address to scan"),
                     use_cache: bool = True):
    """Run email OSINT (validation, breach check, SMTP verify)."""
    safe_target = _validate_scan_target(target, "email")
    return await _run_module("email", safe_target, use_cache)


@app.post("/scan/username", response_model=dict, tags=["Scan"])
async def scan_username(target: str = Query(..., description="Username to search"),
                        use_cache: bool = True):
    """Search username across 40+ platforms."""
    safe_target = _validate_scan_target(target, "username")
    return await _run_module("username", safe_target, use_cache)


@app.post("/scan/ip", response_model=dict, tags=["Scan"])
async def scan_ip(target: str = Query(..., description="IP address to scan"),
                  use_cache: bool = True):
    """Run IP geolocation and intelligence scan."""
    safe_target = _validate_scan_target(target, "ip")
    return await _run_module("ip", safe_target, use_cache)


@app.post("/scan/breach", response_model=dict, tags=["Scan"])
async def scan_breach(target: str = Query(..., description="Email or username to check"),
                      use_cache: bool = True):
    """Check for data breaches."""
    safe_target = _validate_scan_target(target, "breach")
    return await _run_module("breach", safe_target, use_cache)


@app.post("/scan", response_model=ScanResponse, tags=["Scan"])
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
            data = await _dispatch_module(module, validated_target)
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
        data = await _dispatch_module(module, target)
        duration_ms = int((time.monotonic() - t0) * 1000)
        if cache and cache_key and data:
            cache.set(cache_key, data, module=module)
        append_scan_history(module, target, "ok")
        return {"target": target, "module": module, "data": data, "cached": False, "duration_ms": duration_ms}
    except Exception as exc:
        append_scan_history(module, target, "error")
        raise HTTPException(status_code=500, detail=str(exc))


async def _dispatch_module(module: str, target: str) -> dict:
    """Dispatch to the appropriate OSINT module."""
    if module == "whois":
        from modules.whois_lookup import whois_lookup
        return whois_lookup(target) or {}
    elif module == "dns":
        from modules.whois_lookup import dns_enum
        return dns_enum(target) or {}
    elif module == "ip":
        from modules.ip_lookup import ip_lookup
        return ip_lookup(target) or {}
    elif module == "email":
        from modules.email_recon import email_recon
        key = os.getenv("HIBP_API_KEY", "")
        return email_recon(target, hibp_api_key=key) or {}
    elif module == "username":
        from modules.username_search import username_search
        return username_search(target) or {}
    elif module == "ssl":
        from modules.ssl_analyzer import ssl_analyze
        return ssl_analyze(target) or {}
    elif module == "breach":
        from modules.breach_check import breach_check
        key = os.getenv("HIBP_API_KEY", "")
        return breach_check(target, hibp_key=key) or {}
    elif module == "cloud":
        from modules.cloud_recon import cloud_recon
        return cloud_recon(target) or {}
    elif module == "social":
        from modules.social_recon import facebook_recon
        fb_key = os.getenv("FACEBOOK_SCRAPER_KEY", "")
        return facebook_recon(target, fb_scraper_key=fb_key) or {}
    else:
        raise ValueError(f"Unknown module: {module}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
