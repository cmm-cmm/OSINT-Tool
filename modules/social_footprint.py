"""
Social Footprint Module
Search username mentions across social platforms via DuckDuckGo site: operator.

Features:
  - Platform-specific search  (site:instagram.com "username")
  - Global internet search    ("username")
  - Limited search            — only results where username appears in the URL
  - Two-person association    — find URLs containing BOTH usernames (detect connections)

Inspired by sosialrel (https://github.com/rafosw/sosialrel) — rewritten for
OSINT Tool conventions: Rich UI, RateLimiter, structured return dicts, report support.
"""

from __future__ import annotations

import logging
import time

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules.constants import (
    THEME_PRIMARY, THEME_ACCENT, THEME_SUCCESS,
    THEME_WARNING, THEME_ERROR, THEME_DIM,
)
from modules.utils import RateLimiter

logger = logging.getLogger(__name__)
console = Console()

# ── Supported platforms ───────────────────────────────────────────────────────

PLATFORMS: dict[str, str] = {
    "instagram":  "instagram.com",
    "tiktok":     "tiktok.com",
    "twitter":    "x.com",
    "x":          "x.com",
    "github":     "github.com",
    "facebook":   "facebook.com",
    "linkedin":   "linkedin.com",
    "youtube":    "youtube.com",
    "reddit":     "reddit.com",
    "pinterest":  "pinterest.com",
    "snapchat":   "snapchat.com",
    "tumblr":     "tumblr.com",
    "medium":     "medium.com",
    "telegram":   "t.me",
    "vk":         "vk.com",
}

# Rate limit: max 3 searches per 2 seconds to avoid DDGS blocking
_rate_limiter = RateLimiter(calls=3, period=2.0)


# ── Core search ───────────────────────────────────────────────────────────────

def _ddg_search(query: str, max_results: int) -> list[dict]:
    """
    Execute a DuckDuckGo text search and return raw results.
    Returns list of {url, title, body} dicts. Empty list on failure.
    """
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        try:
            from ddgs import DDGS
        except ImportError:
            logger.error("ddgs not installed. Run: pip install ddgs")
            return []

    results = []
    try:
        with _rate_limiter:
            raw = DDGS().text(query, max_results=max_results)
        for r in (raw or []):
            url = r.get("href", "")
            if url:
                results.append({
                    "url":   url,
                    "title": r.get("title", ""),
                    "body":  r.get("body", ""),
                })
    except Exception as exc:
        logger.warning("DuckDuckGo search failed: %s", exc)

    return results


def _resolve_platform(platform: str) -> tuple[str | None, str]:
    """
    Return (domain, display_name) for a platform string.
    platform can be a known keyword (e.g. 'instagram') or a raw domain (e.g. 'example.com').
    Returns (None, 'All Internet') for 'all'.
    """
    p = platform.strip().lower()
    if p in ("all", ""):
        return None, "All Internet"
    if p in PLATFORMS:
        domain = PLATFORMS[p]
        return domain, domain.split(".")[0].capitalize()
    # Treat as raw domain
    return p, p


def _build_query(username: str, domain: str | None, username2: str | None = None) -> str:
    site_part = f"site:{domain} " if domain else ""
    if username2:
        return f'{site_part}"{username}" "{username2}"'
    return f'{site_part}"{username}"'


# ── Public API ────────────────────────────────────────────────────────────────

def footprint_search(
    username: str,
    platform: str = "all",
    limit: int = 10,
    limited: bool = False,
) -> dict:
    """
    Search for a username's footprint on the web.

    Args:
        username: Username or search text.
        platform: Platform keyword (e.g. 'instagram'), raw domain, or 'all'.
        limit:    Max results to retrieve from DuckDuckGo.
        limited:  If True, only keep results where username appears in the URL.

    Returns:
        {
          "username": str,
          "platform": str,
          "domain": str | None,
          "limited": bool,
          "query": str,
          "results": [{"url", "title", "body", "username_in_url"}, ...],
          "total": int,
          "error": str | None,
        }
    """
    domain, display = _resolve_platform(platform)
    query = _build_query(username, domain)
    uname_lower = username.lower()

    raw = _ddg_search(query, max_results=limit)

    results = []
    for r in raw:
        url_lower = r["url"].lower()
        in_url = uname_lower in url_lower
        if limited and not in_url:
            continue
        results.append({
            "url":            r["url"],
            "title":          r["title"],
            "body":           r["body"],
            "username_in_url": in_url,
        })

    return {
        "username": username,
        "platform": display,
        "domain":   domain,
        "limited":  limited,
        "query":    query,
        "results":  results,
        "total":    len(results),
        "error":    None,
    }


def association_search(
    username1: str,
    username2: str,
    platform: str = "all",
    limit: int = 10,
) -> dict:
    """
    Two-person association search: find URLs containing BOTH usernames.
    Useful for detecting connections (follows, comments, tags, co-mentions).

    Returns:
        {
          "username1": str,
          "username2": str,
          "platform": str,
          "domain": str | None,
          "query": str,
          "results": [{"url", "title", "body", "u1_in_url", "u2_in_url"}, ...],
          "total": int,
          "error": str | None,
        }
    """
    domain, display = _resolve_platform(platform)
    query = _build_query(username1, domain, username2)
    u1_lower = username1.lower()
    u2_lower = username2.lower()

    raw = _ddg_search(query, max_results=limit)

    results = []
    for r in raw:
        url_lower = r["url"].lower()
        u1_in_url = u1_lower in url_lower
        u2_in_url = u2_lower in url_lower
        # Only keep URLs with both (association)
        if not (u1_in_url and u2_in_url):
            continue
        results.append({
            "url":      r["url"],
            "title":    r["title"],
            "body":     r["body"],
            "u1_in_url": u1_in_url,
            "u2_in_url": u2_in_url,
        })

    return {
        "username1": username1,
        "username2": username2,
        "platform":  display,
        "domain":    domain,
        "query":     query,
        "results":   results,
        "total":     len(results),
        "error":     None,
    }


# ── Display ───────────────────────────────────────────────────────────────────

def _highlight(text: str, terms: list[str]) -> Text:
    """Return a Rich Text with all occurrences of terms highlighted in red."""
    rich_text = Text()
    remaining = text
    terms_lower = [t.lower() for t in terms]

    while remaining:
        earliest_pos = len(remaining)
        earliest_term = None

        for term, term_lower in zip(terms, terms_lower):
            idx = remaining.lower().find(term_lower)
            if idx != -1 and idx < earliest_pos:
                earliest_pos = idx
                earliest_term = term

        if earliest_term is None:
            rich_text.append(remaining)
            break

        rich_text.append(remaining[:earliest_pos])
        match_text = remaining[earliest_pos:earliest_pos + len(earliest_term)]
        rich_text.append(match_text, style="bold red")
        remaining = remaining[earliest_pos + len(earliest_term):]

    return rich_text


def print_footprint_results(data: dict) -> None:
    """Display footprint_search() results with Rich formatting."""
    username = data.get("username", "")
    platform = data.get("platform", "")
    limited  = data.get("limited", False)
    query    = data.get("query", "")
    results  = data.get("results", [])
    total    = data.get("total", 0)

    mode_tag = " [LIMITED]" if limited else ""
    title_str = f"🔍 Social Footprint — @{username} on {platform}{mode_tag}"

    console.print()
    console.print(Panel(
        f"[{THEME_DIM}]Query:[/{THEME_DIM}] [cyan]{query}[/cyan]",
        title=f"[{THEME_PRIMARY}]{title_str}[/{THEME_PRIMARY}]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 2),
    ))

    if not results:
        console.print(f"  [{THEME_WARNING}]⚠ No results found.[/{THEME_WARNING}]")
        return

    console.print(f"  [{THEME_SUCCESS}]✔ {total} result(s) found[/{THEME_SUCCESS}]\n")

    for i, r in enumerate(results, 1):
        url_text   = _highlight(r["url"],   [username])
        title_text = _highlight(r["title"], [username])
        body_text  = _highlight(r["body"],  [username])

        in_url_badge = (
            f" [{THEME_SUCCESS}][in URL][/{THEME_SUCCESS}]"
            if r.get("username_in_url") else ""
        )

        console.print(f"[bold cyan][{i}][/bold cyan]{in_url_badge}")
        console.print(f"    URL:     ", end="")
        console.print(url_text)
        console.print(f"    Title:   ", end="")
        console.print(title_text)
        console.print(f"    Caption: ", end="")
        console.print(body_text)
        console.print(f"    [dim]{'─' * 60}[/dim]")


def print_association_results(data: dict) -> None:
    """Display association_search() results with Rich formatting."""
    u1      = data.get("username1", "")
    u2      = data.get("username2", "")
    platform = data.get("platform", "")
    query   = data.get("query", "")
    results = data.get("results", [])
    total   = data.get("total", 0)

    console.print()
    console.print(Panel(
        f"[{THEME_DIM}]Query:[/{THEME_DIM}] [cyan]{query}[/cyan]",
        title=f"[{THEME_PRIMARY}]🔗 Association — @{u1} ↔ @{u2} on {platform}[/{THEME_PRIMARY}]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 2),
    ))

    if not results:
        console.print(f"  [{THEME_WARNING}]⚠ No association URLs found — no confirmed link on {platform}.[/{THEME_WARNING}]")
        return

    console.print(f"  [{THEME_ERROR}]⚡ {total} URL(s) contain BOTH usernames — possible connection![/{THEME_ERROR}]\n")

    for i, r in enumerate(results, 1):
        url_text   = _highlight(r["url"],   [u1, u2])
        title_text = _highlight(r["title"], [u1, u2])
        body_text  = _highlight(r["body"],  [u1, u2])

        console.print(f"[bold cyan][{i}][/bold cyan]")
        console.print(f"    URL:     ", end="")
        console.print(url_text)
        console.print(f"    Title:   ", end="")
        console.print(title_text)
        console.print(f"    Caption: ", end="")
        console.print(body_text)
        console.print(f"    [dim]{'─' * 60}[/dim]")
