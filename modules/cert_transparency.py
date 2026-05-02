"""
Certificate Transparency Search Module
=======================================
Discover subdomains and certificates via CT logs:
  - crt.sh (public, no key)
  - certspotter (basic tier, no key)
"""
from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box as _box

from modules.utils import make_session

console = Console()


def search_crt_sh(domain: str, timeout: int = 15) -> dict:
    """
    Query crt.sh Certificate Transparency log for ``domain``.

    Returns: domain, certificates (list), unique_domains (set), error.
    """
    result: dict = {
        "domain": domain,
        "certificates": [],
        "unique_domains": set(),
        "error": None,
    }

    session = make_session()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code != 200:
            result["error"] = f"crt.sh returned HTTP {resp.status_code}"
            return result

        entries = resp.json()
        seen_ids: set[int] = set()

        for entry in entries:
            cert_id = entry.get("id")
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            name_value: str = entry.get("name_value", "") or ""
            san_names = sorted(
                {n.strip() for n in name_value.splitlines() if n.strip()}
            )

            cert = {
                "id": cert_id,
                "logged_at":   entry.get("entry_timestamp", ""),
                "not_before":  entry.get("not_before", ""),
                "not_after":   entry.get("not_after", ""),
                "common_name": entry.get("common_name", ""),
                "issuer":      entry.get("issuer_name", ""),
                "san_names":   san_names,
            }
            result["certificates"].append(cert)

            # Collect unique domain names
            for name in [cert["common_name"]] + san_names:
                name = name.lstrip("*.")
                if name:
                    result["unique_domains"].add(name)

    except Exception as exc:
        result["error"] = str(exc)

    return result


def search_certspotter(domain: str, timeout: int = 10) -> dict:
    """
    Query CertSpotter API (no key required for basic use) for ``domain``.

    Returns: domain, certificates (list with dns_names), error.
    """
    result: dict = {
        "domain": domain,
        "certificates": [],
        "error": None,
    }

    session = make_session()
    url = (
        f"https://api.certspotter.com/v1/issuances"
        f"?domain={domain}&include_subdomains=true&expand=dns_names"
    )
    try:
        resp = session.get(url, timeout=timeout)
        if resp.status_code == 429:
            result["error"] = "CertSpotter rate limit reached (try again later)"
            return result
        if resp.status_code != 200:
            result["error"] = f"CertSpotter returned HTTP {resp.status_code}"
            return result

        for entry in resp.json():
            result["certificates"].append({
                "id":          entry.get("id"),
                "not_before":  entry.get("not_before", ""),
                "not_after":   entry.get("not_after", ""),
                "dns_names":   entry.get("dns_names", []),
                "issuer":      (entry.get("issuer") or {}).get("name", ""),
            })

    except Exception as exc:
        result["error"] = str(exc)

    return result


def cert_recon(domain: str) -> dict:
    """
    Run crt.sh + CertSpotter, deduplicate unique domains discovered.

    Returns merged results useful for subdomain discovery.
    """
    console.print("[dim]  → Querying crt.sh...[/dim]")
    crtsh = search_crt_sh(domain)

    console.print("[dim]  → Querying CertSpotter...[/dim]")
    certspotter = search_certspotter(domain)

    # Merge unique domains from both sources
    unique: set[str] = set(crtsh.get("unique_domains", set()))
    for cert in certspotter.get("certificates", []):
        for name in cert.get("dns_names", []):
            unique.add(name.lstrip("*."))

    return {
        "domain": domain,
        "crtsh": crtsh,
        "certspotter": certspotter,
        "unique_domains": sorted(unique),
        "total_certs": len(crtsh.get("certificates", [])) + len(certspotter.get("certificates", [])),
    }


def print_cert_results(data: dict):
    """Rich-formatted Certificate Transparency results."""
    domain = data.get("domain", "")
    total = data.get("total_certs", 0)
    unique = data.get("unique_domains", [])

    console.print(
        Panel(
            f"[bold cyan]Certificate Transparency Log Search[/bold cyan]\n"
            f"[dim]Domain: {domain}[/dim]\n"
            f"Total certs found: [bold]{total}[/bold] | "
            f"Unique domains/subdomains: [bold green]{len(unique)}[/bold green]",
            border_style="bright_blue",
            title="[bold magenta]CT Log Recon[/bold magenta]",
        )
    )

    # crt.sh certs table
    crtsh = data.get("crtsh", {})
    if crtsh.get("error"):
        console.print(f"[yellow]⚠ crt.sh: {crtsh['error']}[/yellow]")
    else:
        certs = crtsh.get("certificates", [])[:30]
        if certs:
            tbl = Table(
                title=f"crt.sh — {len(crtsh['certificates'])} certificate(s)",
                box=_box.SIMPLE_HEAVY,
                show_lines=False,
            )
            tbl.add_column("Common Name", style="cyan", max_width=35)
            tbl.add_column("Issuer", style="dim", max_width=30)
            tbl.add_column("Not Before", style="green", width=12)
            tbl.add_column("Not After",  style="yellow", width=12)
            for c in certs:
                tbl.add_row(
                    c.get("common_name", "")[:35],
                    (c.get("issuer", "") or "")[:30],
                    (c.get("not_before", "") or "")[:10],
                    (c.get("not_after",  "") or "")[:10],
                )
            console.print(tbl)
            if len(crtsh["certificates"]) > 30:
                console.print(f"  [dim]... and {len(crtsh['certificates']) - 30} more certificates[/dim]")

    # CertSpotter
    certspotter = data.get("certspotter", {})
    if certspotter.get("error"):
        console.print(f"[yellow]⚠ CertSpotter: {certspotter['error']}[/yellow]")

    # Unique subdomains
    if unique:
        console.print(f"\n[bold green]✓ Unique domains/subdomains discovered ({len(unique)}):[/bold green]")
        # Filter to actual subdomains of target domain
        subdomains = [d for d in unique if d.endswith(f".{domain}") and d != domain]
        others = [d for d in unique if not d.endswith(f".{domain}") or d == domain]

        if subdomains:
            console.print(f"  [cyan]Subdomains of {domain}:[/cyan]")
            for sub in sorted(subdomains)[:50]:
                console.print(f"    • {sub}")
            if len(subdomains) > 50:
                console.print(f"    [dim]... and {len(subdomains) - 50} more[/dim]")

        if others:
            console.print(f"  [dim]Other domains ({len(others)}):[/dim]")
            for d in sorted(others)[:10]:
                console.print(f"    [dim]• {d}[/dim]")
    else:
        console.print("[yellow]No unique domains discovered[/yellow]")
