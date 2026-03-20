"""
WHOIS & DNS Enumeration Module
"""
import asyncio
import socket
import threading
import whois
import dns.resolver
import dns.reversename
import requests
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]
HEADERS = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "admin", "vpn",
    "remote", "secure", "shop", "blog", "app", "static", "cdn", "ns1", "ns2",
    "smtp", "pop", "imap", "webmail", "portal", "forum", "wiki", "docs", "git",
    "gitlab", "jenkins", "support", "help", "mx", "m", "mobile", "assets",
    "media", "images", "download", "upload", "backup", "db", "status",
    "monitor", "dashboard", "panel", "cpanel", "whm", "beta", "alpha", "demo",
    "new", "old", "web", "auth", "login", "sso", "vpn2", "intranet",
]


def whois_lookup(target: str, timeout: int = 15) -> dict:
    result = {"target": target, "whois": {}, "error": None}
    container = {}

    def _do_whois():
        try:
            container["data"] = whois.whois(target)
        except Exception as e:
            container["error"] = str(e)

    t = threading.Thread(target=_do_whois, daemon=True)
    t.start()
    t.join(timeout)

    if t.is_alive():
        result["error"] = f"WHOIS timed out after {timeout}s"
        return result

    if "error" in container:
        result["error"] = container["error"]
        return result

    w = container.get("data")
    if w:
        result["whois"] = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "updated_date": str(w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
            "state": w.state,
            "city": w.city,
            "address": w.address,
        }
    return result


def dns_enum(target: str) -> dict:
    result = {"target": target, "records": {}, "error": None}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            result["records"][rtype] = [str(r) for r in answers]
        except Exception:
            pass

    # Reverse DNS for IP
    try:
        if all(c.isdigit() or c == "." for c in target):
            rev = dns.reversename.from_address(target)
            answers = resolver.resolve(rev, "PTR")
            result["records"]["PTR"] = [str(r) for r in answers]
    except Exception:
        pass

    return result


def resolve_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "N/A"


def print_whois(data: dict):
    console.print("\n[bold cyan]═══ WHOIS LOOKUP ═══[/bold cyan]")
    if data.get("error"):
        console.print(f"[red]Error: {data['error']}[/red]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Field", style="cyan", width=20)
    table.add_column("Value", style="white")

    w = data.get("whois", {})
    for field, value in w.items():
        if value and value not in ("None", "[]", "{}"):
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value[:5])
            table.add_row(field.replace("_", " ").title(), str(value))

    console.print(table)


def print_dns(data: dict):
    console.print("\n[bold cyan]═══ DNS ENUMERATION ═══[/bold cyan]")
    if not data.get("records"):
        console.print("[yellow]No DNS records found[/yellow]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type", style="green", width=8)
    table.add_column("Records", style="white")

    for rtype, records in data["records"].items():
        table.add_row(rtype, "\n".join(records))

    console.print(table)


def subdomain_enum(domain: str) -> dict:
    """Enumerate subdomains:
    1. Certificate Transparency via crt.sh (public SSL certs — most comprehensive)
    2. DNS brute-force wordlist via async resolution
    """
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

    result = {
        "target": domain,
        "found": [],
        "crtsh_count": 0,
        "dns_checked": len(COMMON_SUBDOMAINS),
    }

    # ── Step 1: crt.sh Certificate Transparency ────────────────────────────
    crtsh_subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get("name_value", "")
                for n in name.splitlines():
                    n = n.strip().lstrip("*.")
                    if n.endswith(f".{domain}") or n == domain:
                        sub = n.replace(f".{domain}", "").strip()
                        if sub and "." not in sub:  # only direct subdomains
                            crtsh_subs.add(sub)
            result["crtsh_count"] = len(crtsh_subs)
    except Exception:
        pass

    # Merge wordlist with crt.sh results
    all_subs = sorted(set(COMMON_SUBDOMAINS) | crtsh_subs)
    result["dns_checked"] = len(all_subs)

    # ── Step 2: Async DNS resolution ──────────────────────────────────────
    async def _resolve(sub: str) -> dict | None:
        fqdn = f"{sub}.{domain}"
        loop = asyncio.get_running_loop()
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        try:
            answers = await loop.run_in_executor(None, lambda: resolver.resolve(fqdn, "A"))
            return {"subdomain": sub, "fqdn": fqdn, "ips": [str(r) for r in answers], "source": "dns"}
        except Exception:
            return None

    async def _run_all():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[cyan]{task.completed}[/cyan]/[bold]{task.total}[/bold]"),
            TimeElapsedColumn(),
            transient=True,
            console=console,
        ) as progress:
            task_id = progress.add_task(
                f"[cyan]Resolving {len(all_subs)} subdomains (crt.sh + wordlist)...",
                total=len(all_subs),
            )
            sem = asyncio.Semaphore(30)

            async def _resolve_with_sem(sub):
                async with sem:
                    r = await _resolve(sub)
                    progress.advance(task_id)
                    return r

            tasks = [_resolve_with_sem(s) for s in all_subs]
            return [r for r in await asyncio.gather(*tasks) if r]

    found = asyncio.run(_run_all())
    result["found"] = sorted(found, key=lambda x: x["subdomain"])
    return result


def print_subdomains(data: dict):
    console.print(f"\n[bold cyan]═══ SUBDOMAIN ENUMERATION ═══[/bold cyan]")
    found = data.get("found", [])
    checked = data.get("dns_checked", 0)
    crtsh = data.get("crtsh_count", 0)
    console.print(
        f"  crt.sh discovered: [cyan]{crtsh}[/cyan] | "
        f"DNS resolved: [bold]{checked}[/bold] candidates | "
        f"[green]Active: {len(found)}[/green]"
    )
    if found:
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Subdomain", style="green", width=18)
        table.add_column("FQDN", style="cyan")
        table.add_column("IP(s)", style="white")
        for item in found:
            table.add_row(item["subdomain"], item["fqdn"], ", ".join(item["ips"]))
        console.print(table)
    else:
        console.print("  [yellow]No active subdomains found[/yellow]")
