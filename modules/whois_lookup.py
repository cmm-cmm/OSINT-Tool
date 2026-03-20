"""
WHOIS & DNS Enumeration Module
"""
import asyncio
import ipaddress
import socket
import threading
import whois
import dns.resolver
import dns.reversename
import dns.query
import dns.zone
import dns.exception
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

    # Reverse DNS for IP addresses (both IPv4 and IPv6)
    try:
        ipaddress.ip_address(target)
        rev = dns.reversename.from_address(target)
        answers = resolver.resolve(rev, "PTR")
        result["records"]["PTR"] = [str(r) for r in answers]
    except ValueError:
        pass  # Not an IP address
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


# ─── Email Security (SPF / DKIM / DMARC) ──────────────────────────────────────

# Common DKIM selectors used by popular mail providers
_DKIM_SELECTORS = [
    "default", "google", "mail", "email", "dkim", "selector1", "selector2",
    "k1", "k2", "mandrill", "smtp", "s1", "s2", "mimecast", "protonmail",
    "20230601", "20210112",
]


def check_email_security(domain: str) -> dict:
    """
    Kiểm tra cấu hình bảo mật email của domain:
      - SPF (Sender Policy Framework)
      - DMARC (Domain-based Message Authentication)
      - DKIM (DomainKeys Identified Mail) — thử nhiều selector phổ biến
    """
    result = {
        "domain": domain,
        "spf": {"found": False, "record": None, "policy": None, "issues": []},
        "dmarc": {"found": False, "record": None, "policy": None, "issues": []},
        "dkim": {"found": False, "selectors": [], "checked": _DKIM_SELECTORS},
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # ── SPF ────────────────────────────────────────────────────────────────
    try:
        txt_records = resolver.resolve(domain, "TXT")
        for r in txt_records:
            rdata = str(r).strip('"')
            if rdata.startswith("v=spf1"):
                result["spf"]["found"] = True
                result["spf"]["record"] = rdata

                # Policy analysis
                if "-all" in rdata:
                    result["spf"]["policy"] = "hard fail (-all) — Tốt"
                elif "~all" in rdata:
                    result["spf"]["policy"] = "soft fail (~all) — Trung bình"
                    result["spf"]["issues"].append("Dùng '~all' (soft fail) thay vì '-all' (hard fail)")
                elif "?all" in rdata:
                    result["spf"]["policy"] = "neutral (?all) — Yếu"
                    result["spf"]["issues"].append("Dùng '?all' (neutral) — không ngăn spoofing")
                elif "+all" in rdata:
                    result["spf"]["policy"] = "pass (+all) — NGUY HIỂM"
                    result["spf"]["issues"].append("'+all' cho phép BẤT KỲ server nào gửi email — cực kỳ nguy hiểm!")
                else:
                    result["spf"]["policy"] = "Không có policy cuối"
                    result["spf"]["issues"].append("SPF không có all mechanism")
                break
    except Exception:
        pass

    if not result["spf"]["found"]:
        result["spf"]["issues"].append("Không có SPF record — dễ bị giả mạo email (spoofing)")

    # ── DMARC ──────────────────────────────────────────────────────────────
    try:
        dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in dmarc_records:
            rdata = str(r).strip('"')
            if rdata.startswith("v=DMARC1"):
                result["dmarc"]["found"] = True
                result["dmarc"]["record"] = rdata

                # Policy extraction
                for part in rdata.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        p = part[2:].strip()
                        if p == "reject":
                            result["dmarc"]["policy"] = "reject — Tốt nhất"
                        elif p == "quarantine":
                            result["dmarc"]["policy"] = "quarantine — Trung bình"
                            result["dmarc"]["issues"].append("DMARC policy=quarantine, nên dùng p=reject")
                        elif p == "none":
                            result["dmarc"]["policy"] = "none — Chỉ giám sát, không bảo vệ"
                            result["dmarc"]["issues"].append("DMARC policy=none không ngăn delivery email giả")
                        break
                break
    except Exception:
        pass

    if not result["dmarc"]["found"]:
        result["dmarc"]["issues"].append("Không có DMARC record — email không được xác thực đầu cuối")

    # ── DKIM ──────────────────────────────────────────────────────────────
    for selector in _DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver.resolve(dkim_domain, "TXT")
            for r in answers:
                rdata = str(r).strip('"')
                if "v=DKIM1" in rdata or "p=" in rdata:
                    result["dkim"]["found"] = True
                    result["dkim"]["selectors"].append({
                        "selector": selector,
                        "record": rdata[:120] + ("..." if len(rdata) > 120 else ""),
                    })
                    break
        except Exception:
            pass

    if not result["dkim"]["found"]:
        result["dmarc"]["issues"].append(
            "Không tìm thấy DKIM key với các selector phổ biến — có thể dùng selector tùy chỉnh"
        )

    return result


def print_email_security(data: dict):
    """Hiển thị kết quả kiểm tra SPF/DKIM/DMARC."""
    domain = data.get("domain", "")
    console.print(f"\n[bold cyan]═══ EMAIL SECURITY: {domain} ═══[/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Protocol", style="bold", width=8)
    table.add_column("Trạng thái", width=14)
    table.add_column("Chi tiết", style="white")

    # SPF
    spf = data.get("spf", {})
    if spf.get("found"):
        policy = spf.get("policy", "")
        color = "green" if "hard fail" in (policy or "") else "yellow"
        table.add_row(
            "SPF", f"[{color}]✓ Có[/{color}]",
            f"{policy}\n[dim]{(spf.get('record') or '')[:80]}[/dim]"
        )
    else:
        table.add_row("SPF", "[red]✗ Thiếu[/red]", "[red]Không có SPF record[/red]")

    # DMARC
    dmarc = data.get("dmarc", {})
    if dmarc.get("found"):
        policy = dmarc.get("policy", "")
        color = "green" if "reject" in (policy or "") else "yellow"
        table.add_row(
            "DMARC", f"[{color}]✓ Có[/{color}]",
            f"{policy}\n[dim]{(dmarc.get('record') or '')[:80]}[/dim]"
        )
    else:
        table.add_row("DMARC", "[red]✗ Thiếu[/red]", "[red]Không có DMARC record[/red]")

    # DKIM
    dkim = data.get("dkim", {})
    if dkim.get("found"):
        selectors = dkim.get("selectors", [])
        sel_names = ", ".join(s["selector"] for s in selectors)
        table.add_row("DKIM", "[green]✓ Có[/green]", f"Selector(s): {sel_names}")
    else:
        table.add_row("DKIM", "[yellow]? Không rõ[/yellow]",
                      "[dim]Không tìm thấy với các selector phổ biến[/dim]")

    console.print(table)

    # Issues
    all_issues = (
        (data.get("spf", {}).get("issues") or []) +
        (data.get("dmarc", {}).get("issues") or [])
    )
    if all_issues:
        console.print("\n  [bold yellow]Vấn đề cần khắc phục:[/bold yellow]")
        for issue in all_issues:
            console.print(f"    [yellow]⚠[/yellow] {issue}")


# ─── Zone Transfer Test (AXFR) ────────────────────────────────────────────────

def test_zone_transfer(domain: str) -> dict:
    """
    Thử AXFR zone transfer với từng nameserver của domain.
    Nếu thành công → lỗ hổng nghiêm trọng: toàn bộ DNS zone bị lộ.
    """
    result = {
        "domain": domain,
        "nameservers": [],
        "vulnerable": False,
        "leaked_records": [],
        "tested_ns": [],
        "error": None,
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Get nameservers
    try:
        ns_records = resolver.resolve(domain, "NS")
        result["nameservers"] = [str(r).rstrip(".") for r in ns_records]
    except Exception as e:
        result["error"] = f"Cannot resolve NS records: {e}"
        return result

    # Try AXFR on each NS
    for ns in result["nameservers"]:
        result["tested_ns"].append(ns)
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(
                dns.query.xfr(ns_ip, domain, timeout=8, lifetime=12)
            )
            # Zone transfer SUCCEEDED — vulnerability found!
            result["vulnerable"] = True
            records = []
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "value": str(rdata),
                        })
            result["leaked_records"] = records
            break  # One success is enough to confirm vulnerability
        except (dns.exception.FormError, EOFError, ConnectionRefusedError,
                socket.timeout, TimeoutError):
            pass  # AXFR refused — expected behavior
        except Exception:
            pass

    return result


def print_zone_transfer(data: dict):
    """Hiển thị kết quả kiểm tra zone transfer."""
    domain = data.get("domain", "")
    console.print(f"\n[bold cyan]═══ ZONE TRANSFER TEST: {domain} ═══[/bold cyan]")

    ns_list = ", ".join(data.get("nameservers", []))
    console.print(f"  Nameservers: [dim]{ns_list or 'N/A'}[/dim]")

    if data.get("error"):
        console.print(f"  [yellow]⚠ {data['error']}[/yellow]")
        return

    if data.get("vulnerable"):
        records = data.get("leaked_records", [])
        console.print(
            f"\n  [bold red]🚨 LỖ HỔNG NGHIÊM TRỌNG: Zone Transfer thành công![/bold red]"
        )
        console.print(
            f"  [red]Toàn bộ DNS zone bị lộ — {len(records)} DNS record(s) bị rò rỉ[/red]"
        )
        if records:
            table = Table(show_header=True, header_style="bold red")
            table.add_column("Name", style="cyan", width=25)
            table.add_column("Type", style="yellow", width=8)
            table.add_column("Value", style="white")
            for r in records[:30]:
                table.add_row(r["name"], r["type"], r["value"])
            console.print(table)
            if len(records) > 30:
                console.print(f"  [dim]... và {len(records) - 30} record khác[/dim]")
    else:
        tested = ", ".join(data.get("tested_ns", []))
        console.print(f"  [green]✓ Zone transfer bị từ chối bởi tất cả nameservers[/green]")
        console.print(f"  [dim]Đã kiểm tra: {tested}[/dim]")
