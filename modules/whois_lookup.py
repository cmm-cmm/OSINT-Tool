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
    # Core
    "www", "www2", "www3", "m", "mobile", "wap",
    "app", "apps", "web", "site", "home",
    # API
    "api", "api1", "api2", "api3", "api4", "api-v1", "api-v2", "api-v3",
    "v1", "v2", "v3", "rest", "graphql", "gql", "grpc",
    # Mail
    "mail", "mail2", "mail3", "smtp", "smtp2", "smtps",
    "imap", "pop", "pop3", "webmail", "email", "mx", "mx1", "mx2", "mx3",
    "autodiscover", "autoconfig",
    # FTP / Files
    "ftp", "ftp2", "sftp", "files", "file", "transfer", "uploads", "upload",
    "download", "downloads",
    # CDN / Static
    "cdn", "cdn1", "cdn2", "static", "static1", "static2",
    "assets", "asset", "img", "images", "image", "media", "video", "videos",
    "audio", "content", "resources", "res", "pub", "public",
    # Dev / Environment
    "dev", "dev1", "dev2", "development", "local",
    "staging", "stage", "stg", "uat", "qa", "qas",
    "test", "test1", "test2", "testing", "sandbox", "preview",
    "beta", "alpha", "demo", "canary", "rc", "release",
    # Admin / Control panels
    "admin", "admin2", "administrator", "administration",
    "panel", "dashboard", "cpanel", "whm", "plesk", "directadmin",
    "manage", "management", "control", "console", "backend",
    # Security / Auth
    "auth", "auth2", "oauth", "oauth2", "oidc", "saml",
    "sso", "sso2", "login", "logout", "account", "accounts",
    "id", "identity", "iam", "keycloak", "okta", "ping",
    "cert", "certs", "crl", "ca", "pki", "vault",
    # Networking
    "vpn", "vpn1", "vpn2", "vpn3", "remote", "rdp", "citrix",
    "proxy", "gateway", "gw", "fw", "firewall", "waf",
    "lb", "loadbalancer", "ha", "ha1", "ha2",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    # Infrastructure / DevOps
    "git", "gitlab", "github", "bitbucket", "svn",
    "jenkins", "ci", "cd", "cicd", "build", "builds",
    "docker", "registry", "k8s", "kubernetes", "helm",
    "ansible", "puppet", "chef", "terraform",
    "nexus", "artifactory", "sonar", "sonarqube",
    "jira", "confluence", "wiki", "docs",
    # Monitoring / Logging
    "monitor", "monitoring", "monitor2",
    "status", "healthcheck", "health", "ping",
    "metrics", "stats", "statistics",
    "grafana", "kibana", "elasticsearch", "elastic", "splunk",
    "prometheus", "alertmanager", "zabbix", "nagios", "datadog",
    "logs", "log", "logging", "graylog", "logstash",
    # Database
    "db", "db1", "db2", "db3", "database", "mysql", "mariadb",
    "postgres", "postgresql", "redis", "redis1", "redis2",
    "mongo", "mongodb", "cassandra", "couchdb", "elasticsearch",
    "memcache", "memcached", "rabbitmq", "kafka", "zookeeper",
    # E-commerce / Business
    "shop", "store", "market", "marketplace",
    "cart", "checkout", "payment", "pay", "billing",
    "invoice", "invoices", "order", "orders", "track",
    "crm", "erp", "sales", "support", "helpdesk", "help",
    "desk", "ticket", "tickets", "service",
    # Communication
    "chat", "im", "voip", "conference", "meet", "video",
    "forum", "forums", "community", "social",
    "newsletter", "news", "blog", "blog2", "press",
    # Storage / Backup
    "backup", "backups", "bak", "restore", "storage", "s3", "bucket",
    "archive", "archives", "repo", "repository",
    # Network ranges
    "intranet", "internal", "private", "extranet",
    "office", "corp", "corporate",
    "secure", "ssl", "tls",
    # Geographic — Global
    "us", "us-east", "us-west", "eu", "eu-west", "eu-central",
    "ap", "ap-southeast", "ap-northeast",
    "sg", "hk", "jp", "kr", "au", "uk", "de", "fr", "nl",
    "ca", "br", "in",
    # Geographic — Vietnam specific
    "vn", "hn", "hanoi", "hcm", "saigon", "hcmc",
    "dn", "danang", "hp", "haiphong", "ct", "cantho",
    "hue", "qn", "quangnguyen", "dl", "dalat", "vt", "vungtau",
    "binhduong", "dongnai",
    # Vietnam platforms / portals
    "portal", "dichvu", "dang-ky", "tra-cuu",
    "evn", "vnpt", "viettel",
    # Security research targets
    "bounty", "bug", "security", "vuln", "pentest",
    # Misc
    "old", "new", "legacy", "deprecated",
    "redirect", "link", "url", "short",
    "verify", "verification", "activate", "activation",
    "token", "reset", "recover", "recovery",
    "sitemap", "rss", "feed", "feeds", "webhook",
    "sandbox2", "integration", "external", "ext",
]


def check_rdap(domain: str) -> dict:
    """Query RDAP for richer registrant/contact data (often bypasses GDPR-redacted WHOIS)."""
    rdap_urls = [
        f"https://rdap.org/domain/{domain}",
        f"https://rdap.verisign.com/com/v1/domain/{domain}",
    ]
    for url in rdap_urls:
        try:
            resp = requests.get(url, headers=HEADERS, timeout=8)
            if resp.status_code == 200:
                d = resp.json()
                result = {"found": True, "registrar": None, "status": [], "contacts": []}
                result["status"] = d.get("status", [])
                for entity in d.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard_data = entity.get("vcardArray", [None, []])
                    vcard_fields = vcard_data[1] if len(vcard_data) > 1 else []
                    contact = {"roles": roles}
                    for field in vcard_fields:
                        if not isinstance(field, list) or len(field) < 4:
                            continue
                        name = field[0]
                        value = field[3]
                        if name == "fn":
                            contact["name"] = value
                        elif name == "email":
                            contact["email"] = value
                        elif name == "tel":
                            contact["phone"] = str(value)
                        elif name == "adr" and isinstance(value, list):
                            parts = [str(p) for p in value if p]
                            contact["address"] = " ".join(parts)
                        elif name == "org":
                            contact["org"] = value
                    if len(contact) > 1:  # has more than just 'roles'
                        result["contacts"].append(contact)
                    if "registrar" in roles and contact.get("name"):
                        result["registrar"] = contact["name"]
                return result
        except Exception:
            continue
    return {"found": False}


def whois_lookup(target: str, timeout: int = 15) -> dict:
    result = {"target": target, "whois": {}, "rdap": None, "error": None}
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

    # RDAP enrichment — richer contact data, often available even when WHOIS is redacted
    rdap = check_rdap(target)
    if rdap.get("found"):
        result["rdap"] = rdap

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


def check_dns_security(target: str) -> dict:
    """
    Check DNS security features: DNSSEC, CAA records, DANE (TLSA).
    Returns dict with security status and recommendations.
    """
    result = {
        "target": target,
        "dnssec": {"enabled": False, "details": []},
        "caa": {"records": [], "has_issue": False, "has_wildcard": False},
        "dane": {"records": [], "enabled": False},
        "security_score": 0,
        "recommendations": [],
    }

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    # Check DNSSEC
    try:
        # Try to get DNSKEY records (indicates DNSSEC is configured)
        answers = resolver.resolve(target, "DNSKEY")
        if answers:
            result["dnssec"]["enabled"] = True
            result["dnssec"]["details"].append(f"Found {len(answers)} DNSKEY records")
            result["security_score"] += 30
        else:
            result["recommendations"].append("Enable DNSSEC to prevent DNS spoofing attacks")
    except dns.resolver.NoAnswer:
        result["dnssec"]["details"].append("DNSSEC not configured")
        result["recommendations"].append("Enable DNSSEC to prevent DNS spoofing attacks")
    except Exception as e:
        result["dnssec"]["details"].append(f"Unable to check: {str(e)[:50]}")

    # Check CAA records (Certificate Authority Authorization)
    try:
        answers = resolver.resolve(target, "CAA")
        for rdata in answers:
            caa_str = str(rdata)
            result["caa"]["records"].append(caa_str)

            # Parse CAA record
            if "issue" in caa_str.lower():
                result["caa"]["has_issue"] = True
            if "issuewild" in caa_str.lower():
                result["caa"]["has_wildcard"] = True

        if result["caa"]["records"]:
            result["security_score"] += 25
        else:
            result["recommendations"].append(
                "Add CAA records to control which CAs can issue certificates for your domain"
            )
    except dns.resolver.NoAnswer:
        result["recommendations"].append(
            "Add CAA records to control which CAs can issue certificates for your domain"
        )
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass

    # Check DANE/TLSA records (for _443._tcp subdomain)
    try:
        tlsa_query = f"_443._tcp.{target}"
        answers = resolver.resolve(tlsa_query, "TLSA")
        for rdata in answers:
            result["dane"]["records"].append(str(rdata))
            result["dane"]["enabled"] = True

        if result["dane"]["enabled"]:
            result["security_score"] += 20
    except Exception:
        pass

    # Grade security score
    if result["security_score"] >= 70:
        result["grade"] = "A"
    elif result["security_score"] >= 50:
        result["grade"] = "B"
    elif result["security_score"] >= 30:
        result["grade"] = "C"
    else:
        result["grade"] = "F"

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

    # RDAP enrichment display
    rdap = data.get("rdap")
    if rdap and rdap.get("found"):
        console.print("\n[bold cyan]─── RDAP Contact Data ───[/bold cyan]")
        if rdap.get("registrar"):
            console.print(f"  Registrar: [green]{rdap['registrar']}[/green]")
        if rdap.get("status"):
            console.print(f"  Status: [yellow]{', '.join(rdap['status'])}[/yellow]")
        for contact in rdap.get("contacts", []):
            roles = ", ".join(contact.get("roles", []))
            console.print(f"  [bold]Contact ({roles})[/bold]")
            for key in ("name", "org", "email", "phone", "address"):
                val = contact.get(key)
                if val:
                    console.print(f"    {key.title()}: {val}")


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


def print_dns_security(data: dict):
    """Display DNS security analysis results (DNSSEC, CAA, DANE)."""
    target = data.get("target", "")
    console.print(f"\n[bold cyan]═══ DNS SECURITY ANALYSIS: {target} ═══[/bold cyan]")

    score = data.get("security_score", 0)
    grade = data.get("grade", "F")
    grade_colors = {"A": "bold green", "B": "green", "C": "yellow", "F": "red"}
    grade_color = grade_colors.get(grade, "white")

    console.print(f"  [bold]DNS Security Grade:[/bold] [{grade_color}]{grade}[/{grade_color}] ({score}/75)")

    # DNSSEC
    dnssec = data.get("dnssec", {})
    if dnssec.get("enabled"):
        console.print("\n  [bold green]✓ DNSSEC:[/bold green] [green]Enabled[/green]")
        for detail in dnssec.get("details", []):
            console.print(f"    • {detail}")
    else:
        console.print("\n  [bold red]✗ DNSSEC:[/bold red] [red]Not configured[/red]")
        for detail in dnssec.get("details", []):
            console.print(f"    • {detail}")

    # CAA Records
    caa = data.get("caa", {})
    caa_records = caa.get("records", [])
    if caa_records:
        console.print(f"\n  [bold green]✓ CAA Records:[/bold green] [green]{len(caa_records)} record(s) found[/green]")
        for record in caa_records[:5]:
            console.print(f"    • {record}")
        if len(caa_records) > 5:
            console.print(f"    [dim]... and {len(caa_records) - 5} more[/dim]")
    else:
        console.print("\n  [bold red]✗ CAA Records:[/bold red] [red]Not configured[/red]")

    # DANE/TLSA
    dane = data.get("dane", {})
    if dane.get("enabled"):
        console.print(f"\n  [bold green]✓ DANE/TLSA:[/bold green] [green]{len(dane['records'])} record(s) found[/green]")
        for record in dane.get("records", [])[:3]:
            console.print(f"    • {record}")
    else:
        console.print("\n  [bold yellow]⚠ DANE/TLSA:[/bold yellow] [yellow]Not configured (optional)[/yellow]")

    # Recommendations
    recommendations = data.get("recommendations", [])
    if recommendations:
        console.print("\n  [bold yellow]📋 Security Recommendations:[/bold yellow]")
        for i, rec in enumerate(recommendations, 1):
            console.print(f"    {i}. {rec}")


# ─── External Tool Wrappers ───────────────────────────────────────────────────

import shutil as _shutil
import subprocess as _subprocess
import json as _json
import tempfile as _tempfile
import os as _os


def run_theharvester(domain: str, sources: str = "all", timeout: int = 60) -> dict:
    """Run theHarvester to gather emails, subdomains, IPs from public sources."""
    result = {"available": False, "emails": [], "subdomains": [], "ips": [], "error": None, "note": None}
    if not _shutil.which("theHarvester"):
        result["note"] = "theHarvester not installed. Run: pip install theHarvester"
        return result
    result["available"] = True
    with _tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        tmpfile = tf.name
    try:
        _subprocess.run(
            ["theHarvester", "-d", domain, "-b", sources, "-f", tmpfile.replace(".json", "")],
            capture_output=True, text=True, timeout=timeout,
        )
        if _os.path.exists(tmpfile):
            data = _json.loads(open(tmpfile).read())
            result["emails"]     = data.get("emails", [])
            result["subdomains"] = data.get("hosts", [])
            result["ips"]        = data.get("ips", [])
    except _subprocess.TimeoutExpired:
        result["error"] = f"theHarvester timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            _os.unlink(tmpfile)
        except Exception:
            pass
    return result


def run_subfinder(domain: str, timeout: int = 60) -> dict:
    """Run subfinder for passive subdomain enumeration."""
    result = {"available": False, "subdomains": [], "error": None, "note": None}
    if not _shutil.which("subfinder"):
        result["note"] = "subfinder not installed. See: https://github.com/projectdiscovery/subfinder"
        return result
    result["available"] = True
    try:
        proc = _subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=timeout,
        )
        subdomains = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    obj = _json.loads(line)
                    subdomains.append(obj.get("host", line))
                except _json.JSONDecodeError:
                    subdomains.append(line)
        result["subdomains"] = list(set(subdomains))
    except _subprocess.TimeoutExpired:
        result["error"] = f"subfinder timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    return result

