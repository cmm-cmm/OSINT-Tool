"""
Username HTTP Site Checker — tookie-osint inspired

Checks 260+ sites for a username via HTTP status codes and error-message
validation. No external dependencies beyond `requests` (already required).
Uses concurrent.futures for fast parallel scanning.
"""

from __future__ import annotations

import json
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Literal

import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

# ── Site database ──────────────────────────────────────────────────────────────

_SITES_PATH = Path(__file__).parent.parent / "data" / "username_sites.json"

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
]


def _load_sites() -> list[dict]:
    try:
        with open(_SITES_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# ── HTTP check ─────────────────────────────────────────────────────────────────

def _check_one(
    site_entry: dict,
    username: str,
    timeout: int,
    skip_nsfw: bool,
) -> dict | None:
    """Check a single site. Returns a result dict or None on error."""
    if skip_nsfw and site_entry.get("nsfw", "false") == "true":
        return None

    url = site_entry["site"] + username
    error_msg = site_entry.get("errorMessage", "")
    headers = {"User-Agent": random.choice(_USER_AGENTS)}

    try:
        resp = requests.get(url, headers=headers, timeout=timeout,
                            allow_redirects=True)
        status = resp.status_code

        # Heuristic: 2xx/3xx is a positive hit unless error message present
        if 200 <= status <= 305:
            if error_msg and error_msg.lower() != "none":
                if error_msg.lower() in resp.text.lower():
                    return {"url": url, "found": False, "status": status, "reason": "error_msg"}
            return {"url": url, "found": True, "status": status, "reason": "http_ok"}
        else:
            return {"url": url, "found": False, "status": status, "reason": "http_error"}

    except requests.exceptions.Timeout:
        return {"url": url, "found": False, "status": 0, "reason": "timeout"}
    except requests.exceptions.RequestException:
        return {"url": url, "found": False, "status": 0, "reason": "connection_error"}


# ── Main scan ──────────────────────────────────────────────────────────────────

def check_username_sites(
    username: str,
    threads: int = 10,
    timeout: int = 8,
    skip_nsfw: bool = True,
    found_only: bool = True,
) -> dict:
    """Scan 260+ sites for *username*.

    Returns::

        {
            "username": str,
            "total_checked": int,
            "found_count": int,
            "results": [{"url": str, "found": bool, "status": int, "reason": str}]
        }
    """
    sites = _load_sites()
    if not sites:
        return {
            "username": username,
            "total_checked": 0,
            "found_count": 0,
            "results": [],
            "error": f"Site database not found at {_SITES_PATH}",
        }

    results: list[dict] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"[cyan]Scanning {len(sites)} sites…", total=len(sites))
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(_check_one, s, username, timeout, skip_nsfw): s
                for s in sites
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    results.append(result)
                progress.advance(task)

    found = [r for r in results if r["found"]]
    all_results = found if found_only else results

    return {
        "username": username,
        "total_checked": len(sites),
        "found_count": len(found),
        "results": sorted(all_results, key=lambda r: (not r["found"], r["url"])),
    }


# ── Display ────────────────────────────────────────────────────────────────────

def print_username_site_results(data: dict) -> None:
    username = data.get("username", "")
    total = data.get("total_checked", 0)
    found = data.get("found_count", 0)

    if "error" in data:
        console.print(f"\n[red]✗ Error: {data['error']}[/red]")
        return

    console.print(f"\n[bold cyan]👤 Username Site Scan — {username}[/bold cyan]")
    console.print(f"[dim]Checked {total} sites[/dim]\n")

    if not found:
        console.print("[yellow]⚠ Username not found on any site.[/yellow]")
        return

    console.print(f"[green]✔ Found on {found} site(s)[/green]\n")

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("URL", style="bold white")
    table.add_column("Status", style="cyan", width=8, justify="center")
    table.add_column("Reason", style="dim", width=14)

    for r in data["results"]:
        status_str = str(r["status"]) if r["status"] else "—"
        if r["found"]:
            status_style = "green"
            found_icon = "✔"
        else:
            status_style = "dim"
            found_icon = "✗"
        table.add_row(
            f"[{status_style}]{found_icon}[/{status_style}] {r['url']}",
            f"[{status_style}]{status_str}[/{status_style}]",
            r.get("reason", ""),
        )

    console.print(table)
