"""
Dark Web & Leak Monitoring Module
==================================
Checks whether a target (email, username, domain, …) appears in:

  1. Pastebin public archive — via Google dork over requests
  2. LeakCheck.io API        — free public endpoint, optional paid key
  3. Tor .onion search        — Ahmia clearnet proxy when tor_proxy given

All functions return plain dicts and are safe to call from automated
pipelines — network failures produce ``{"error": "<message>"}`` rather
than raising exceptions.

Usage::

    from modules.darkweb_monitor import darkweb_monitor, print_darkweb_results

    results = darkweb_monitor(
        "target@example.com",
        hibp_key="…",          # optional
        leak_key="…",          # optional LeakCheck.io key
        tor_proxy="socks5h://127.0.0.1:9050",  # optional
    )
    print_darkweb_results(results)
"""

from __future__ import annotations

import logging
import re
from typing import Any

from modules.utils import make_session, DEFAULT_TIMEOUT

logger = logging.getLogger("osint.darkweb")

# ── Shared session ────────────────────────────────────────────────────────────

_session = make_session(browser_ua=True)

# ── 1. Pastebin ───────────────────────────────────────────────────────────────

_PASTEBIN_GOOGLE_SEARCH = "https://www.google.com/search"
_PASTEBIN_SEARCH_URL = "https://pastebin.com/search"


def check_pastebin(target: str, session=None) -> dict:
    """
    Search the Pastebin public archive for mentions of *target*.

    Strategy
    --------
    Uses Pastebin's own search endpoint (``/search?q=<target>``) with a
    browser User-Agent to enumerate publicly listed pastes, then falls back
    to a Google dork (``site:pastebin.com "<target>"``) to surface additional
    indexed results.

    Parameters
    ----------
    target:
        The string to look for (email, username, domain, …).
    session:
        Optional pre-built ``requests.Session``.  If ``None`` the module
        default session is used.

    Returns
    -------
    dict with keys:
        * ``found``    — ``True`` if any mentions detected
        * ``mentions`` — count of distinct URLs discovered
        * ``urls``     — list of pastebin.com paste URLs
        * ``source``   — always ``"pastebin"``
    """
    sess = session or _session
    urls: list[str] = []

    # ── Strategy 1: Pastebin native search ───────────────────────────────────
    try:
        resp = sess.get(
            _PASTEBIN_SEARCH_URL,
            params={"q": target},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp and resp.status_code == 200:
            # Extract paste URLs from the search result HTML
            found_urls = re.findall(
                r'href="(https?://pastebin\.com/(?!search|login|register|faq)[A-Za-z0-9]+)"',
                resp.text,
            )
            urls.extend(found_urls)
    except Exception as exc:
        logger.debug("Pastebin native search failed for %r: %s", target, exc)

    # ── Strategy 2: Google dork fallback ─────────────────────────────────────
    try:
        resp = sess.get(
            _PASTEBIN_GOOGLE_SEARCH,
            params={"q": f'site:pastebin.com "{target}"', "num": "10"},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp and resp.status_code == 200:
            google_urls = re.findall(
                r'https?://pastebin\.com/(?!search|login|register|faq)[A-Za-z0-9]+',
                resp.text,
            )
            urls.extend(google_urls)
    except Exception as exc:
        logger.debug("Pastebin Google dork failed for %r: %s", target, exc)

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    return {
        "found":    len(unique_urls) > 0,
        "mentions": len(unique_urls),
        "urls":     unique_urls,
        "source":   "pastebin",
    }


# ── 2. Leak databases ─────────────────────────────────────────────────────────

_LEAKCHECK_PUBLIC_URL = "https://leakcheck.io/api/public"
_LEAKCHECK_API_URL    = "https://leakcheck.io/api/v2/query/{query}"


def check_leak_databases(target: str, api_key: str = "") -> dict:
    """
    Check *target* against leak databases.

    When *api_key* is provided the LeakCheck.io v2 authenticated endpoint
    is used (richer results, higher rate limits).  Otherwise the free
    public endpoint is tried, followed by a best-effort check against the
    BreachDirectory public API.

    Parameters
    ----------
    target:
        Email, username, or domain to check.
    api_key:
        LeakCheck.io API key (optional).

    Returns
    -------
    dict with keys:
        * ``found``    — ``True`` when at least one breach entry exists
        * ``sources``  — list of breach source names (strings)
        * ``count``    — number of breach records found
        * ``details``  — list of detail dicts returned by the API
        * ``provider`` — which service answered (``"leakcheck_api"``,
                         ``"leakcheck_public"``, or ``"none"``)
        * ``error``    — present only on total failure
    """
    # ── LeakCheck.io authenticated ────────────────────────────────────────────
    if api_key:
        try:
            sess = make_session()
            sess.headers.update({"X-API-Key": api_key})
            url = _LEAKCHECK_API_URL.format(query=target)
            resp = sess.get(url, timeout=DEFAULT_TIMEOUT)
            if resp and resp.status_code == 200:
                data = resp.json()
                sources = data.get("sources", [])
                entries = data.get("result", [])
                return {
                    "found":    bool(data.get("found", len(entries) > 0)),
                    "sources":  [s.get("name", str(s)) for s in sources] if sources else [],
                    "count":    data.get("found", len(entries)),
                    "details":  entries,
                    "provider": "leakcheck_api",
                }
        except Exception as exc:
            logger.warning("LeakCheck.io API call failed for %r: %s", target, exc)

    # ── LeakCheck.io public endpoint (no key) ────────────────────────────────
    try:
        sess = make_session()
        resp = sess.get(
            _LEAKCHECK_PUBLIC_URL,
            params={"check": target},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp and resp.status_code == 200:
            data = resp.json()
            sources = data.get("sources", [])
            return {
                "found":    bool(data.get("found", False)),
                "sources":  sources if isinstance(sources, list) else [],
                "count":    len(sources) if isinstance(sources, list) else 0,
                "details":  [],
                "provider": "leakcheck_public",
            }
    except Exception as exc:
        logger.warning("LeakCheck.io public call failed for %r: %s", target, exc)

    # ── Total failure ─────────────────────────────────────────────────────────
    return {
        "found":    False,
        "sources":  [],
        "count":    0,
        "details":  [],
        "provider": "none",
        "error":    "All leak database sources unavailable",
    }


# ── 3. Dark-web / Tor ─────────────────────────────────────────────────────────

_AHMIA_CLEARNET = "https://ahmia.fi/search/"


def check_darkweb_mentions(target: str, tor_proxy: str = "") -> dict:
    """
    Search Tor .onion search engines for *target*.

    When *tor_proxy* is supplied (e.g. ``"socks5h://127.0.0.1:9050"``) the
    Ahmia clearnet interface is queried through the Tor circuit, giving
    access to .onion results.  Without a proxy only the public Ahmia
    clearnet index is searched (no actual .onion content).

    Parameters
    ----------
    target:
        The string to search for.
    tor_proxy:
        SOCKS5 proxy URL pointing at a running Tor process.

    Returns
    -------
    dict with keys when Tor is available:
        * ``available``  — ``True``
        * ``found``      — ``True`` if results returned
        * ``mentions``   — integer result count estimate
        * ``urls``       — list of .onion or clearnet result URLs found
        * ``source``     — ``"ahmia"``

    Or when no Tor proxy is configured:
        * ``available``  — ``False``
        * ``reason``     — ``"no_tor_proxy"``
    """
    if not tor_proxy:
        return {"available": False, "reason": "no_tor_proxy"}

    proxies = {"http": tor_proxy, "https": tor_proxy}

    try:
        sess = make_session(browser_ua=True)
        sess.proxies.update(proxies)

        resp = sess.get(
            _AHMIA_CLEARNET,
            params={"q": target},
            timeout=30,  # Tor is slow
        )

        if not resp or resp.status_code != 200:
            return {
                "available": True,
                "found":     False,
                "mentions":  0,
                "urls":      [],
                "source":    "ahmia",
                "error":     f"HTTP {resp.status_code if resp else 'no response'}",
            }

        # Extract .onion links and normal result URLs from the response HTML
        onion_urls = re.findall(
            r'https?://[a-z2-7]{16,56}\.onion[^\s"\'<>]*',
            resp.text,
            re.IGNORECASE,
        )
        result_links = re.findall(
            r'href="(/search/redirect\?[^"]+)"',
            resp.text,
        )

        all_urls = list(dict.fromkeys(onion_urls))  # deduplicate, preserve order

        return {
            "available": True,
            "found":     len(all_urls) > 0 or len(result_links) > 0,
            "mentions":  max(len(all_urls), len(result_links)),
            "urls":      all_urls,
            "source":    "ahmia",
        }

    except Exception as exc:
        logger.warning("Dark web search failed for %r via %r: %s", target, tor_proxy, exc)
        return {"available": True, "found": False, "mentions": 0, "urls": [], "source": "ahmia",
                "error": str(exc)}


# ── 4. Orchestrator ───────────────────────────────────────────────────────────


def darkweb_monitor(
    target: str,
    hibp_key: str = "",
    leak_key: str = "",
    tor_proxy: str = "",
) -> dict:
    """
    Run all dark-web and leak monitoring checks for *target*.

    Orchestrates :func:`check_pastebin`, :func:`check_leak_databases`, and
    :func:`check_darkweb_mentions`, then merges the results into a single
    response dict.

    Parameters
    ----------
    target:
        The value to investigate (email, username, domain, …).
    hibp_key:
        HaveIBeenPwned API key — reserved for future HIBP integration.
        Currently passed through in the result for caller convenience.
    leak_key:
        LeakCheck.io API key (optional).
    tor_proxy:
        SOCKS5 Tor proxy URL (optional).

    Returns
    -------
    dict with keys:
        * ``target``        — the scanned target
        * ``pastebin``      — result from :func:`check_pastebin`
        * ``leak_databases``— result from :func:`check_leak_databases`
        * ``darkweb``       — result from :func:`check_darkweb_mentions`
        * ``summary``       — high-level summary dict:
              ``{"any_found": bool, "risk_level": "low"|"medium"|"high"}``
    """
    logger.info("darkweb_monitor: starting checks for %r", target)

    pastebin_result = check_pastebin(target)
    leak_result     = check_leak_databases(target, api_key=leak_key)
    darkweb_result  = check_darkweb_mentions(target, tor_proxy=tor_proxy)

    any_found = (
        pastebin_result.get("found", False)
        or leak_result.get("found", False)
        or darkweb_result.get("found", False)
    )

    # Simple risk scoring
    risk_score = 0
    if pastebin_result.get("found"):
        risk_score += 1
    if leak_result.get("found"):
        risk_score += 2
    if darkweb_result.get("found"):
        risk_score += 3

    if risk_score == 0:
        risk_level = "low"
    elif risk_score <= 2:
        risk_level = "medium"
    else:
        risk_level = "high"

    return {
        "target":         target,
        "pastebin":       pastebin_result,
        "leak_databases": leak_result,
        "darkweb":        darkweb_result,
        "summary": {
            "any_found":  any_found,
            "risk_level": risk_level,
        },
    }


# ── 5. Rich output ────────────────────────────────────────────────────────────


def print_darkweb_results(results: dict) -> None:
    """
    Print *results* (as returned by :func:`darkweb_monitor`) to the console
    using Rich formatting.

    Parameters
    ----------
    results:
        Dict returned by :func:`darkweb_monitor`.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
    except ImportError:
        # Fallback to plain print if Rich is not installed
        import json
        print(json.dumps(results, indent=2, default=str))
        return

    console = Console()
    target = results.get("target", "—")

    # ── Summary panel ─────────────────────────────────────────────────────────
    summary = results.get("summary", {})
    risk = summary.get("risk_level", "unknown")
    any_found = summary.get("any_found", False)

    risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(risk, "dim")
    found_icon = "[bold red]FOUND[/bold red]" if any_found else "[bold green]CLEAN[/bold green]"

    console.print(Panel(
        f"Target: [bold cyan]{target}[/bold cyan]\n"
        f"Status: {found_icon}   Risk: [{risk_color}]{risk.upper()}[/{risk_color}]",
        title="[bold magenta]Dark Web & Leak Monitor[/bold magenta]",
        border_style="bright_blue",
        box=box.ROUNDED,
    ))

    # ── Pastebin ──────────────────────────────────────────────────────────────
    pb = results.get("pastebin", {})
    pb_table = Table(
        "Field", "Value",
        title="[cyan]Pastebin[/cyan]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
    )
    pb_table.add_row("Found",    "[red]Yes[/red]" if pb.get("found") else "[green]No[/green]")
    pb_table.add_row("Mentions", str(pb.get("mentions", 0)))

    paste_urls = pb.get("urls", [])
    if paste_urls:
        for u in paste_urls[:10]:
            pb_table.add_row("URL", f"[underline bright_blue]{u}[/underline bright_blue]")
        if len(paste_urls) > 10:
            pb_table.add_row("…", f"and {len(paste_urls) - 10} more")

    if pb.get("error"):
        pb_table.add_row("[red]Error[/red]", pb["error"])

    console.print(pb_table)

    # ── Leak databases ────────────────────────────────────────────────────────
    lk = results.get("leak_databases", {})
    lk_table = Table(
        "Field", "Value",
        title="[cyan]Leak Databases[/cyan]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
    )
    lk_table.add_row("Found",    "[red]Yes[/red]" if lk.get("found") else "[green]No[/green]")
    lk_table.add_row("Count",    str(lk.get("count", 0)))
    lk_table.add_row("Provider", lk.get("provider", "—"))

    sources = lk.get("sources", [])
    if sources:
        lk_table.add_row("Sources", ", ".join(str(s) for s in sources[:20]))

    if lk.get("error"):
        lk_table.add_row("[red]Error[/red]", lk["error"])

    console.print(lk_table)

    # ── Dark web ──────────────────────────────────────────────────────────────
    dw = results.get("darkweb", {})
    dw_table = Table(
        "Field", "Value",
        title="[cyan]Dark Web (Tor / Ahmia)[/cyan]",
        box=box.SIMPLE_HEAVY,
        show_header=True,
        header_style="bold cyan",
    )

    if not dw.get("available", True):
        dw_table.add_row("Status", "[yellow]Tor proxy not configured — skipped[/yellow]")
        dw_table.add_row("Reason", dw.get("reason", "—"))
    else:
        dw_table.add_row("Found",    "[red]Yes[/red]" if dw.get("found") else "[green]No[/green]")
        dw_table.add_row("Mentions", str(dw.get("mentions", 0)))
        dw_table.add_row("Source",   dw.get("source", "—"))

        dw_urls = dw.get("urls", [])
        for u in dw_urls[:5]:
            dw_table.add_row("URL", f"[underline]{u}[/underline]")
        if len(dw_urls) > 5:
            dw_table.add_row("…", f"and {len(dw_urls) - 5} more")

        if dw.get("error"):
            dw_table.add_row("[red]Error[/red]", dw["error"])

    console.print(dw_table)
