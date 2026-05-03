"""
Domain Typosquatting Detection — dnstwist wrapper

Generates permutations of a domain name (omission, addition, transposition,
homoglyph, IDN bitsquatting…) and resolves which ones are registered.
Requires: dnstwist  (pip install dnstwist)
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ── dnstwist discovery ─────────────────────────────────────────────────────────

def _dnstwist_cmd() -> list[str] | None:
    """Return a runnable dnstwist command or None if unavailable."""
    # Installed as CLI in current venv or PATH
    exe = shutil.which("dnstwist") or shutil.which("dnstwist.exe")
    if exe:
        return [exe]
    # Fallback: python -m dnstwist (works when installed via pip)
    try:
        import dnstwist as _dt  # noqa: F401
        return [sys.executable, "-m", "dnstwist"]
    except ImportError:
        pass
    return None


def _is_available() -> bool:
    return _dnstwist_cmd() is not None


# ── Core scan function ─────────────────────────────────────────────────────────

def twist_domain(
    domain: str,
    limit: int = 100,
    registered_only: bool = True,
    threads: int = 8,
) -> dict:
    """Run dnstwist against *domain* and return structured results.

    Returns a dict::

        {
            "domain": str,
            "registered_only": bool,
            "total": int,
            "results": [
                {
                    "fuzzer": str,
                    "domain": str,
                    "dns_a": list[str],
                    "dns_mx": list[str],
                    "geoip_country": str,
                }
            ],
            "error": str   # only on failure
        }
    """
    cmd = _dnstwist_cmd()
    if cmd is None:
        return {
            "domain": domain,
            "registered_only": registered_only,
            "total": 0,
            "results": [],
            "error": "dnstwist is not installed. Run: pip install dnstwist",
        }

    args = cmd + [
        "--format", "json",
        "--threads", str(threads),
    ]
    if registered_only:
        args.append("--registered")
    args.append(domain)

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        return {
            "domain": domain,
            "registered_only": registered_only,
            "total": 0,
            "results": [],
            "error": "dnstwist timed out after 180 seconds",
        }
    except FileNotFoundError as exc:
        return {
            "domain": domain,
            "registered_only": registered_only,
            "total": 0,
            "results": [],
            "error": f"Could not execute dnstwist: {exc}",
        }

    raw = proc.stdout.strip()
    if not raw:
        err = proc.stderr.strip() or "No output from dnstwist"
        return {
            "domain": domain,
            "registered_only": registered_only,
            "total": 0,
            "results": [],
            "error": err,
        }

    try:
        raw_results: list[dict] = json.loads(raw)
    except json.JSONDecodeError as exc:
        return {
            "domain": domain,
            "registered_only": registered_only,
            "total": 0,
            "results": [],
            "error": f"Could not parse dnstwist output: {exc}",
        }

    # Normalise field names (dnstwist uses hyphenated keys)
    normalised: list[dict] = []
    for r in raw_results:
        entry = {
            "fuzzer": r.get("fuzzer", ""),
            "domain": r.get("domain", ""),
            "dns_a": r.get("dns-a", []) or [],
            "dns_mx": r.get("dns-mx", []) or [],
            "geoip_country": r.get("geoip-country", "") or "",
        }
        normalised.append(entry)

    if limit:
        normalised = normalised[:limit]

    return {
        "domain": domain,
        "registered_only": registered_only,
        "total": len(normalised),
        "results": normalised,
    }


# ── Display ────────────────────────────────────────────────────────────────────

def print_twist_results(data: dict) -> None:
    domain = data.get("domain", "")
    total = data.get("total", 0)

    if "error" in data:
        console.print(f"\n[red]✗ dnstwist error: {data['error']}[/red]")
        return

    console.print(f"\n[bold cyan]🌀 Domain Typosquatting — {domain}[/bold cyan]")
    reg_label = "registered only" if data.get("registered_only") else "all permutations"
    console.print(f"[dim]Mode: {reg_label}[/dim]\n")

    if not total:
        console.print("[yellow]⚠ No suspicious domains found.[/yellow]")
        return

    console.print(f"[green]✔ {total} domain(s) detected[/green]\n")

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("Fuzzer", style="cyan", width=20)
    table.add_column("Domain", style="bold white")
    table.add_column("DNS-A", style="yellow")
    table.add_column("DNS-MX", style="dim")
    table.add_column("Country", style="dim", width=10)

    for r in data["results"]:
        dns_a = ", ".join(r["dns_a"]) if r["dns_a"] else ""
        dns_mx = ", ".join(r["dns_mx"]) if r["dns_mx"] else ""
        table.add_row(
            r["fuzzer"],
            r["domain"],
            dns_a,
            dns_mx,
            r["geoip_country"],
        )

    console.print(table)
