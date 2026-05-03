#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════╗
║            OSINT Tool - Open Source Intelligence      ║
║      Thu thập thông tin công khai hợp pháp            ║
║  For: Security Research / Investigation / Education   ║
╚═══════════════════════════════════════════════════════╝

DISCLAIMER: Tool này chỉ sử dụng dữ liệu công khai và API hợp pháp.
Người dùng chịu trách nhiệm tuân thủ luật pháp địa phương.
"""

import sys

# ── Python version gate ────────────────────────────────────────────────────────
if sys.version_info < (3, 10):
    print(
        f"\n[ERROR] Python 3.10 or newer is required.\n"
        f"  Detected: Python {sys.version_info.major}.{sys.version_info.minor}\n"
        f"  Install: https://www.python.org/downloads/\n"
    )
    sys.exit(1)

import os
import re
import json
from ipaddress import AddressValueError, IPv4Address, ip_address
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
import click
from rich.prompt import Prompt, Confirm

load_dotenv(Path(__file__).parent / ".env")
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box

from modules.whois_lookup import (
    whois_lookup, dns_enum, resolve_ip, print_whois, print_dns,
    subdomain_enum, print_subdomains,
    check_email_security, print_email_security,
    test_zone_transfer, print_zone_transfer,
    check_dns_security, print_dns_security,
)
from modules.email_recon import email_recon, print_email_results, validate_email
from modules.username_search import username_search, print_username_results, monitor_username
from modules.ip_lookup import ip_lookup, print_ip_results
from modules.phone_lookup import phone_lookup, print_phone_results
from modules.google_dorks import generate_dorks, print_dorks
from modules.report import save_report
from modules.ssl_analyzer import ssl_analyze, print_ssl_results
from modules.secrets_scanner import secrets_scan, print_secrets_results
from modules.cloud_recon import cloud_recon, print_cloud_recon
from modules.instagram_recon import instagram_recon, print_instagram_results
from modules.cert_transparency import cert_recon, print_cert_results

console = Console()

_DOMAIN_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)
_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _normalize_target(target: str) -> str:
    """Strip scheme, path, port and trailing slash — extract bare hostname/IP."""
    t = target.strip().rstrip("/")
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.hostname or t
    else:
        # Handle case like www.example.com/path
        t = t.split("/")[0]
    # Strip port if present (e.g. example.com:8080)
    t = t.split(":")[0] if ":" in t and not _IP_RE.match(t) else t
    return t.lower()


def _is_valid_target(target: str) -> bool:
    if _DOMAIN_RE.match(target):
        return True

    try:
        IPv4Address(target)
        return True
    except AddressValueError:
        return False


def _load_targets(single: str | None, targets_file: str | None, mode: str) -> list:
    """Return list of targets from single arg or file."""
    if targets_file:
        lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    if single:
        return [single]
    return []


BANNER = Panel(
    Align.center(
        Text.from_markup(
            "[bold cyan]OSINT Tool[/bold cyan]\n"
            "[white]Open Source Intelligence Toolkit[/white]\n"
            "[dim]Educational and lawful research only[/dim]"
        )
    ),
    box=box.ROUNDED,
    border_style="bright_blue",
    title="[bold magenta]OSINT[/bold magenta]",
    subtitle="[green]v1.2.0[/green]",
    padding=(1, 2),
)


def print_banner():
    console.clear()
    console.print(BANNER)


def print_section_header(title: str, subtitle: str | None = None) -> None:
    header = Text(title, style="bold white")
    if subtitle:
        header.append("\n")
        header.append(subtitle, style="dim")
    console.print(
        Panel(
            Align.center(header),
            box=box.ROUNDED,
            border_style="cyan",
            padding=(1, 2),
            expand=False,
        )
    )


# ─── CLI Commands ────────────────────────────────────────────────────────────

@click.group()
@click.version_option("1.0.0", prog_name="OSINT Tool")
def cli():
    """OSINT Tool - Thu thập thông tin công khai hợp pháp."""
    pass


@cli.command("domain")
@click.argument("target", required=False, default=None)
@click.option("--targets", "targets_file", default=None, type=click.Path(exists=True), help="File with one domain/IP per line")
@click.option("--whois/--no-whois", "do_whois", default=True, help="WHOIS lookup")
@click.option("--dns/--no-dns", "do_dns", default=True, help="DNS enumeration")
@click.option("--subdomain/--no-subdomain", "do_subdomain", default=True, help="Subdomain enumeration")
@click.option("--dorks/--no-dorks", "do_dorks", default=True, help="Google dorks")
@click.option("--ip/--no-ip", "do_ip", default=True, help="IP intelligence")
@click.option("--ssl/--no-ssl", "do_ssl", default=True, help="SSL/TLS analysis")
@click.option("--email-sec/--no-email-sec", "do_email_sec", default=True, help="SPF/DKIM/DMARC + zone transfer")
@click.option("--secrets/--no-secrets", "do_secrets", default=False, help="Scan for exposed files/secrets")
@click.option("--cloud/--no-cloud", "do_cloud", default=False, help="Cloud bucket enumeration")
@click.option("--report", is_flag=True, help="Save HTML+JSON+CSV report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format")
def cmd_domain(target, targets_file, do_whois, do_dns, do_subdomain, do_dorks, do_ip,
               do_ssl, do_email_sec, do_secrets, do_cloud, report, output, out_fmt):
    """Investigate a domain or IP address.

    Example: python osint.py domain example.com --report
    Example: python osint.py domain example.com --secrets --cloud --report
    Example: python osint.py domain --targets domains.txt --report
    """
    targets = _load_targets(target, targets_file, "domain")
    if not targets:
        console.print("[red]✗ Provide a TARGET or --targets FILE[/red]")
        raise SystemExit(1)

    for t in targets:
        _run_domain(t, do_whois, do_dns, do_subdomain, do_dorks, do_ip,
                    do_ssl, do_email_sec, do_secrets, do_cloud, report, output, out_fmt)


def _run_domain(target, do_whois, do_dns, do_subdomain, do_dorks, do_ip,
                do_ssl=True, do_email_sec=True, do_secrets=False, do_cloud=False,
                report=False, output=".", out_fmt="table"):
    """Core domain scan logic (reusable for single and batch)."""
    target = _normalize_target(target)
    if not _is_valid_target(target):
        console.print(f"[red]✗ Invalid domain or IP address: '{target}'[/red]")
        return
    try:
        ip_address(target)
        is_ip_target = True
    except ValueError:
        is_ip_target = False

    if out_fmt == "table":
        print_banner()
        print_section_header(f"Target: [green]{target}[/green]", "Domain/IP investigation")

    all_data = {}

    if do_whois:
        if out_fmt == "table":
            console.print("[dim]Running WHOIS lookup...[/dim]")
        data = whois_lookup(target)
        all_data["whois"] = data
        if out_fmt == "table":
            print_whois(data)

    if do_dns:
        if out_fmt == "table":
            console.print("[dim]Enumerating DNS records...[/dim]")
        data = dns_enum(target)
        all_data["dns"] = data
        if out_fmt == "table":
            print_dns(data)

    # Email security (SPF/DKIM/DMARC + Zone Transfer) — only for domains, not IPs
    if do_email_sec and not is_ip_target:
        if out_fmt == "table":
            console.print("[dim]Checking email security (SPF/DKIM/DMARC)...[/dim]")
        email_sec_data = check_email_security(target)
        all_data["email_security"] = email_sec_data
        if out_fmt == "table":
            print_email_security(email_sec_data)

        if out_fmt == "table":
            console.print("[dim]Testing zone transfer (AXFR)...[/dim]")
        zt_data = test_zone_transfer(target)
        all_data["zone_transfer"] = zt_data
        if out_fmt == "table":
            print_zone_transfer(zt_data)

        # DNS Security Analysis (DNSSEC, CAA, DANE)
        if out_fmt == "table":
            console.print("[dim]Analyzing DNS security (DNSSEC, CAA, DANE)...[/dim]")
        dns_sec_data = check_dns_security(target)
        all_data["dns_security"] = dns_sec_data
        if out_fmt == "table":
            print_dns_security(dns_sec_data)

    if do_subdomain:
        if out_fmt == "table":
            console.print("[dim]Enumerating subdomains...[/dim]")
        data = subdomain_enum(target)
        all_data["subdomains"] = data
        if out_fmt == "table":
            print_subdomains(data)

    # SSL/TLS analysis — only for domains, not IPs
    if do_ssl and not is_ip_target:
        if out_fmt == "table":
            console.print("[dim]Analyzing SSL/TLS...[/dim]")
        ssl_data = ssl_analyze(target)
        all_data["ssl"] = ssl_data
        if out_fmt == "table":
            print_ssl_results(ssl_data)

    if do_ip:
        if out_fmt == "table":
            console.print("[dim]Running IP/domain intelligence...[/dim]")
        data = ip_lookup(
            target,
            virustotal_key=os.getenv("VIRUSTOTAL_KEY"),
            shodan_key=os.getenv("SHODAN_KEY"),
            abuseipdb_key=os.getenv("ABUSEIPDB_KEY"),
        )
        all_data["ip"] = data
        if out_fmt == "table":
            print_ip_results(data)

    if do_secrets:
        if out_fmt == "table":
            console.print("[dim]Scanning for exposed files and secrets...[/dim]")
        secrets_data = secrets_scan(target)
        all_data["secrets"] = secrets_data
        if out_fmt == "table":
            print_secrets_results(secrets_data)

    if do_cloud:
        if out_fmt == "table":
            console.print("[dim]Enumerating cloud storage buckets...[/dim]")
        cloud_data = cloud_recon(target)
        all_data["cloud"] = cloud_data
        if out_fmt == "table":
            print_cloud_recon(cloud_data)

    if do_dorks:
        dorks = generate_dorks(target, "domain")
        all_data["dorks"] = dorks
        if out_fmt == "table":
            print_dorks(target, "domain")

    if out_fmt == "json":
        print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))
    elif out_fmt == "csv":
        from modules.report import build_csv_report
        csv_data = build_csv_report(all_data)
        if csv_data:
            print(csv_data)

    if report:
        save_report(target, all_data, output)


@cli.command("email")
@click.argument("email_addr")
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None, help="HaveIBeenPwned API key")
@click.option("--hunter-key", envvar="HUNTER_KEY", default=None, help="Hunter.io API key (env: HUNTER_KEY)")
@click.option("--emailrep-key", envvar="EMAILREP_KEY", default=None, help="EmailRep.io key (env: EMAILREP_KEY, optional)")
@click.option("--dorks/--no-dorks", "do_dorks", default=True, help="Generate email dorks")
@click.option("--holehe/--no-holehe", "do_holehe", default=False, help="Check email on 120+ sites via holehe (must be installed)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def cmd_email(email_addr, hibp_key, hunter_key, emailrep_key, do_dorks, do_holehe, report, output, out_fmt):
    """Investigate an email address.

    Example: python osint.py email user@example.com --hibp-key YOUR_KEY
    Example: python osint.py email user@example.com --holehe
    """
    if not validate_email(email_addr):
        console.print(f"[red]✗ Invalid email format: '{email_addr}'[/red]")
        raise SystemExit(1)
    if out_fmt == "table":
        print_banner()

    all_data = {}

    if out_fmt == "table":
        console.print("[dim]Analyzing email...[/dim]")
    data = email_recon(
        email_addr,
        hibp_api_key=hibp_key,
        hunter_key=hunter_key or os.getenv("HUNTER_KEY"),
        emailrep_key=emailrep_key if emailrep_key is not None else os.getenv("EMAILREP_KEY", ""),
        do_holehe=do_holehe,
    )
    all_data["email"] = data
    if out_fmt == "table":
        print_email_results(data)

    if do_dorks:
        dorks = generate_dorks(email_addr, "email")
        all_data["dorks"] = dorks
        if out_fmt == "table":
            print_dorks(email_addr, "email")

    if out_fmt == "json":
        print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))

    if report:
        save_report(email_addr, all_data, output)


@cli.command("username")
@click.argument("username")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--monitor", is_flag=True, default=False, help="Watch mode: re-scan periodically and alert on status changes")
@click.option("--interval", default=60, show_default=True, help="Seconds between re-scans in watch mode")
@click.option("--duration", default=3600, show_default=True, help="Total watch duration in seconds (default: 1 hour)")
@click.option("--maigret/--no-maigret", "do_maigret", default=False, help="Deep username search via maigret 3000+ sites (must be installed)")
def cmd_username(username, report, output, monitor, interval, duration, do_maigret):
    """Search a username across 40+ platforms.

    \b
    Examples:
      python osint.py username johndoe --report
      python osint.py username johndoe --monitor --interval 120 --duration 7200
      python osint.py username johndoe --maigret
    """
    print_banner()

    if monitor:
        console.print(f"\n[dim]Starting monitor for @{username}...[/dim]\n")
        history = monitor_username(username, interval=interval, duration=duration)
        if report:
            save_report(username, {"monitor_history": history}, output)
        return

    console.print(f"\n[dim]Searching for @{username} across platforms...[/dim]\n")
    data = username_search(username)
    all_data = {"username": data}

    if do_maigret:
        from modules.username_search import run_maigret
        console.print("[dim]Running maigret deep scan...[/dim]")
        maigret_data = run_maigret(username)
        data["maigret"] = maigret_data
        all_data["maigret"] = maigret_data

    print_username_results(data)

    if report:
        save_report(username, all_data, output)


@cli.command("phone")
@click.argument("phone_number")
@click.option("--region", default="VN", help="Default region (e.g. VN, US, GB)")
@click.option("--numverify-key", envvar="NUMVERIFY_KEY", default=None, help="NumVerify API key (env: NUMVERIFY_KEY)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def cmd_phone(phone_number, region, numverify_key, report, output, out_fmt):
    """Analyze a phone number (offline + public data).

    Example: python osint.py phone +84901234567
    Example: python osint.py phone 0901234567 --region VN
    """
    if out_fmt == "table":
        print_banner()

    data = phone_lookup(phone_number, region=region, numverify_key=numverify_key or os.getenv("NUMVERIFY_KEY"))
    all_data = {"phone": data}
    if out_fmt == "table":
        print_phone_results(data)
    elif out_fmt == "json":
        print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))

    if report:
        save_report(phone_number, all_data, output)


@cli.command("instagram")
@click.argument("username")
@click.option("--shadowban", is_flag=True, default=False, help="Run shadowban heuristic check (requires instaloader)")
@click.option("--engagement", is_flag=True, default=False, help="Estimate engagement rate (requires instaloader)")
@click.option("--hashtag", default=None, help="Run OSINT on this hashtag (e.g. #python)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table")
def cmd_instagram(username, shadowban, engagement, hashtag, report, output, out_fmt):
    """Instagram profile OSINT — public data only.

    \b
    Examples:
      python osint.py instagram johndoe
      python osint.py instagram johndoe --engagement --shadowban
      python osint.py instagram johndoe --hashtag "#python" --report
      python osint.py instagram johndoe --output-format json
    """
    if out_fmt == "table":
        print_banner()

    username = username.lstrip("@").strip()
    console.print(f"[dim]Gathering Instagram OSINT for @{username}...[/dim]")

    data = instagram_recon(
        username,
        do_shadowban=shadowban,
        do_engagement=engagement,
        hashtag=hashtag,
    )
    all_data = {"instagram": data}

    if out_fmt == "table":
        print_instagram_results(data)
    elif out_fmt == "json":
        print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))

    if report:
        save_report(username, all_data, output)


@cli.command("person")
@click.argument("name")
@click.option("--dorks/--no-dorks", "do_dorks", default=True)
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_person(name, do_dorks, report, output):
    """Generate investigation dorks for a person or organization.

    Example: python osint.py person "Nguyen Van A"
    """
    print_banner()

    all_data = {}

    if do_dorks:
        dorks = generate_dorks(name, "person")
        all_data["dorks"] = dorks
        print_dorks(name, "person")

    if report:
        save_report(name, all_data, output)


@cli.command("ssl")
@click.argument("target")
@click.option("--port", default=443, show_default=True, help="HTTPS port")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_ssl(target, port, report, output):
    """Analyze SSL/TLS security of a domain (grade A+ to F).

    \b
    Examples:
      python osint.py ssl example.com
      python osint.py ssl example.com --port 8443
      python osint.py ssl example.com --report
    """
    print_banner()
    target = _normalize_target(target)
    console.print(f"[dim]Analyzing SSL/TLS for {target}:{port}...[/dim]")
    data = ssl_analyze(target, port=port)
    print_ssl_results(data)
    if report:
        save_report(target, {"ssl": data}, output)


@cli.command("secrets")
@click.argument("target")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_secrets(target, report, output):
    """Scan website for exposed files, credentials, and secrets.

    Scans for: .git directory, .env files, backup files,
    security.txt, sensitive paths, API keys in source.

    \b
    Examples:
      python osint.py secrets example.com
      python osint.py secrets https://example.com --report
    """
    print_banner()
    console.print(f"[dim]Scanning {target} for exposed files...[/dim]")
    data = secrets_scan(target)
    print_secrets_results(data)
    if report:
        save_report(target, {"secrets": data}, output)


@cli.command("cloud")
@click.argument("target")
@click.option("--max-buckets", "max_buckets", default=30, show_default=True,
              help="Max bucket name variations to test")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_cloud(target, max_buckets, report, output):
    """Enumerate public cloud storage buckets (AWS S3, GCS, Azure, DO Spaces).

    \b
    Examples:
      python osint.py cloud example.com
      python osint.py cloud mycompany --max-buckets 50
      python osint.py cloud example.com --report
    """
    print_banner()
    console.print(f"[dim]Enumerating cloud buckets for {target}...[/dim]")
    data = cloud_recon(target, max_buckets=max_buckets)
    print_cloud_recon(data)
    if report:
        save_report(target, {"cloud": data}, output)


@cli.command("breach")
@click.argument("target")
@click.option("--password", default=None, metavar="PASSWORD",
              help="Mật khẩu cần kiểm tra qua HIBP Pwned Passwords (không lưu/log)")
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None,
              help="HaveIBeenPwned API key (env: HIBP_API_KEY)")
@click.option("--breachdir-key", envvar="BREACHDIRECTORY_KEY", default=None,
              help="BreachDirectory RapidAPI key (env: BREACHDIRECTORY_KEY)")
@click.option("--report", is_flag=True, help="Lưu báo cáo HTML+JSON")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."),
              help="Thư mục lưu báo cáo")
def cmd_breach(target, password, hibp_key, breachdir_key, report, output):
    """Kiểm tra email/username trong các vụ rò rỉ dữ liệu.

    Nguồn miễn phí (không cần key):
      - LeakCheck.io public endpoint
      - HIBP Pwned Passwords (kiểm tra mật khẩu qua --password)

    Nguồn miễn phí sau khi đăng ký:
      - BreachDirectory (RapidAPI free tier — env: BREACHDIRECTORY_KEY)

    Tùy chọn (có phí nhỏ):
      - HaveIBeenPwned email+paste (env: HIBP_API_KEY)

    \b
    Ví dụ:
      python osint.py breach user@example.com
      python osint.py breach user@example.com --password "mympassword"
      python osint.py breach johndoe --report
    """
    from modules.breach_check import breach_check, print_breach_results
    print_banner()
    console.print(f"[dim]Đang kiểm tra '{target}' trong các nguồn rò rỉ dữ liệu...[/dim]")
    data = breach_check(
        target, password=password, hibp_key=hibp_key, breachdir_key=breachdir_key,
        dehashed_email=os.getenv("DEHASHED_EMAIL"),
        dehashed_key=os.getenv("DEHASHED_KEY"),
        snusbase_key=os.getenv("SNUSBASE_KEY"),
        emailrep_key=os.getenv("EMAILREP_KEY"),
        hunter_key=os.getenv("HUNTER_KEY"),
    )
    print_breach_results(data)
    if report:
        save_report(target, {"breach": data}, output)


@cli.command("social")
@click.option("--facebook", "fb_id", default=None, metavar="ID_OR_URL",
              help="Facebook username, profile URL, or numeric ID")
@click.option("--tiktok", "tt_user", default=None, metavar="USERNAME",
              help="TikTok username (with or without @)")
@click.option("--instagram", "ig_user", default=None, metavar="USERNAME",
              help="Instagram username (with or without @)")
@click.option("--twitter", "tw_user", default=None, metavar="USERNAME",
              help="Twitter/X username (with or without @)")
@click.option("--reddit", "reddit_user", default=None, metavar="USERNAME",
              help="Reddit username (with or without u/)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_social(fb_id, tt_user, ig_user, tw_user, reddit_user, report, output):
    """Investigate Facebook, TikTok, Instagram, Twitter/X and Reddit public profiles.

    Examples:
    \b
    python osint.py social --facebook johndoe
    python osint.py social --tiktok johndoe
    python osint.py social --instagram johndoe
    python osint.py social --twitter johndoe
    python osint.py social --reddit johndoe
    python osint.py social --facebook johndoe --reddit johndoe --report
    """
    from modules.social_recon import (
        facebook_recon, tiktok_recon, print_facebook_results, print_tiktok_results,
        instagram_recon, print_instagram_results, twitter_recon, print_twitter_results,
        reddit_recon, print_reddit_results,
        detect_suspicious_account, print_account_analysis,
    )

    if not fb_id and not tt_user and not ig_user and not tw_user and not reddit_user:
        console.print("[red]✗ Provide at least one platform: --facebook, --tiktok, --instagram, --twitter, or --reddit[/red]")
        raise SystemExit(1)

    print_banner()
    all_data = {}

    if fb_id:
        console.print("[dim]Fetching Facebook profile...[/dim]")
        fb_data = facebook_recon(
            fb_id,
            fb_scraper_key=os.getenv("FACEBOOK_SCRAPER_KEY"),
            hibp_key=os.getenv("HIBP_API_KEY"),
            breachdir_key=os.getenv("BREACHDIRECTORY_KEY"),
            intelx_key=os.getenv("INTELX_KEY"),
            dehashed_email=os.getenv("DEHASHED_EMAIL"),
            dehashed_key=os.getenv("DEHASHED_KEY"),
            snusbase_key=os.getenv("SNUSBASE_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY"),
            hunter_key=os.getenv("HUNTER_KEY"),
        )
        all_data["facebook"] = fb_data
        print_facebook_results(fb_data)
        analysis = detect_suspicious_account(fb_data, platform="Facebook")
        all_data["facebook_analysis"] = analysis
        print_account_analysis(analysis)

    if tt_user:
        console.print("[dim]Fetching TikTok profile...[/dim]")
        tt_data = tiktok_recon(
            tt_user,
            tokapi_key=os.getenv("TOKAPI_KEY"),
            tiktok_api_key=os.getenv("TIKTOK_API_KEY"),
        )
        all_data["tiktok"] = tt_data
        print_tiktok_results(tt_data)
        analysis = detect_suspicious_account(tt_data, platform="TikTok")
        all_data["tiktok_analysis"] = analysis
        print_account_analysis(analysis)

    if ig_user:
        console.print("[dim]Fetching Instagram profile...[/dim]")
        ig_data = instagram_recon(ig_user, api_key=os.getenv("INSTAGRAM_KEY"))
        all_data["instagram"] = ig_data
        print_instagram_results(ig_data)
        analysis = detect_suspicious_account(ig_data, platform="Instagram")
        all_data["instagram_analysis"] = analysis
        print_account_analysis(analysis)

    if tw_user:
        console.print("[dim]Fetching Twitter/X profile...[/dim]")
        tw_data = twitter_recon(tw_user, bearer_token=os.getenv("TWITTER_BEARER_TOKEN"))
        all_data["twitter"] = tw_data
        print_twitter_results(tw_data)
        analysis = detect_suspicious_account(tw_data, platform="Twitter/X")
        all_data["twitter_analysis"] = analysis
        print_account_analysis(analysis)

    if reddit_user:
        console.print("[dim]Fetching Reddit profile...[/dim]")
        reddit_data = reddit_recon(reddit_user)
        all_data["reddit"] = reddit_data
        print_reddit_results(reddit_data)
        analysis = detect_suspicious_account(reddit_data, platform="Reddit")
        all_data["reddit_analysis"] = analysis
        print_account_analysis(analysis)

    if report:
        identifier = fb_id or tt_user or ig_user or tw_user or reddit_user
        save_report(identifier, all_data, output)


@cli.command("footprint")
@click.argument("username")
@click.option("--platform", "-p", default="all",
              help="Platform: instagram, tiktok, twitter, github, facebook, linkedin, "
                   "youtube, reddit, pinterest, snapchat, all, or any domain (default: all)")
@click.option("--associate", "-a", default=None, metavar="USERNAME2",
              help="Second username — detect connection between two people")
@click.option("--limited", "-l", is_flag=True, default=False,
              help="Only return results where the username appears in the URL")
@click.option("--limit", "max_results", default=10, show_default=True,
              help="Max number of results to retrieve")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."),
              help="Output directory for report")
@click.option("--output-format", "out_fmt",
              type=click.Choice(["table", "json"]), default="table")
def cmd_footprint(username, platform, associate, limited, max_results, report, output, out_fmt):
    """Search username footprint across social platforms via DuckDuckGo.

    Uses DuckDuckGo site: operator — no API key needed.
    Finds mentions, comments, tags, and profile links beyond just profile existence.

    \b
    Examples:
      python osint.py footprint johndoe
      python osint.py footprint johndoe --platform instagram
      python osint.py footprint johndoe --platform instagram --limited
      python osint.py footprint johndoe --associate janedoe --platform facebook
      python osint.py footprint johndoe --platform all --limit 20 --report
    """
    from modules.social_footprint import (
        footprint_search, association_search,
        print_footprint_results, print_association_results,
    )

    username = username.lstrip("@").strip()

    if out_fmt == "table":
        print_banner()

    all_data: dict = {}

    if associate:
        associate = associate.lstrip("@").strip()
        if out_fmt == "table":
            console.print(f"[dim]Searching association between @{username} and @{associate}...[/dim]")
        data = association_search(username, associate, platform=platform, limit=max_results)
        all_data["association"] = data
        if out_fmt == "table":
            print_association_results(data)
        elif out_fmt == "json":
            print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))
    else:
        if out_fmt == "table":
            mode = "limited" if limited else "standard"
            console.print(f"[dim]Searching @{username} on {platform} ({mode} mode)...[/dim]")
        data = footprint_search(username, platform=platform, limit=max_results, limited=limited)
        all_data["social_footprint"] = data
        if out_fmt == "table":
            print_footprint_results(data)
        elif out_fmt == "json":
            print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))

    if report:
        label = f"{username}+{associate}" if associate else username
        save_report(label, all_data, output)


@cli.command("dorker")
@click.argument("target", default="")
@click.option("--mode", "-m",
              type=click.Choice(["files", "emails", "phones", "pages", "person", "dork"]),
              default="files", show_default=True,
              help="Scan mode")
@click.option("--filetypes", "-f", default=None,
              help="Comma-separated file types for 'files' mode (e.g. pdf,xls,sql,env)")
@click.option("--country-code", "-c", default="+1", show_default=True,
              help="Country dialing code for 'phones' mode (e.g. +84)")
@click.option("--surname", "-s", default="", help="Surname for 'person' mode")
@click.option("--phone", default="", help="Phone/number hint for 'person' mode")
@click.option("--categories", default=None,
              help="Comma-separated page keywords for 'pages' mode (e.g. admin,login,backup)")
@click.option("--dork", "-d", "dork_query", default=None,
              help="Raw dork query for 'dork' mode")
@click.option("--limit", default=10, show_default=True, help="Max results per query")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."),
              help="Output directory for report")
@click.option("--output-format", "out_fmt",
              type=click.Choice(["table", "json"]), default="table")
def cmd_dorker(target, mode, filetypes, country_code, surname, phone,
               categories, dork_query, limit, report, output, out_fmt):
    """Execute Google dork queries via DuckDuckGo and retrieve live results.

    Amera-inspired: file discovery, email/phone harvest, person OSINT, custom dork.
    Complements the 'person' command which only generates dork URLs.

    \b
    Examples:
      python osint.py dorker example.com --mode files
      python osint.py dorker example.com --mode files --filetypes pdf,xls,sql
      python osint.py dorker example.com --mode emails
      python osint.py dorker example.com --mode phones --country-code +84
      python osint.py dorker example.com --mode pages --categories admin,login,backup
      python osint.py dorker "John" --mode person --surname "Doe" --phone "+84"
      python osint.py dorker --mode dork --dork 'site:github.com "api_key" filetype:env'
    """
    from modules.dorker_search import (
        file_search, email_harvest, phone_harvest,
        page_search, person_search, custom_dork,
        print_file_results, print_email_results, print_phone_results,
        print_page_results, print_person_results, print_custom_dork_results,
    )

    if out_fmt == "table":
        print_banner()

    all_data: dict = {}

    if mode == "files":
        if not target:
            console.print("[red]✗ TARGET domain is required for 'files' mode.[/red]")
            return
        ft_list = [f.strip() for f in filetypes.split(",")] if filetypes else None
        if out_fmt == "table":
            console.print(f"[dim]Discovering exposed files on {target}...[/dim]")
        data = file_search(target, filetypes=ft_list, limit_per_type=limit)
        all_data["file_discovery"] = data
        if out_fmt == "table":
            print_file_results(data)

    elif mode == "emails":
        if not target:
            console.print("[red]✗ TARGET domain is required for 'emails' mode.[/red]")
            return
        if out_fmt == "table":
            console.print(f"[dim]Harvesting emails from {target}...[/dim]")
        data = email_harvest(target, limit=limit)
        all_data["email_harvest"] = data
        if out_fmt == "table":
            print_email_results(data)

    elif mode == "phones":
        if not target:
            console.print("[red]✗ TARGET domain is required for 'phones' mode.[/red]")
            return
        if out_fmt == "table":
            console.print(f"[dim]Searching phone numbers on {target} (code: {country_code})...[/dim]")
        data = phone_harvest(target, country_code=country_code, limit=limit)
        all_data["phone_harvest"] = data
        if out_fmt == "table":
            print_phone_results(data)

    elif mode == "pages":
        if not target:
            console.print("[red]✗ TARGET domain is required for 'pages' mode.[/red]")
            return
        cat_list = [c.strip() for c in categories.split(",")] if categories else None
        if out_fmt == "table":
            console.print(f"[dim]Discovering pages on {target}...[/dim]")
        data = page_search(target, categories=cat_list, limit_per_cat=limit)
        all_data["page_search"] = data
        if out_fmt == "table":
            print_page_results(data)

    elif mode == "person":
        name = target
        if not name:
            console.print("[red]✗ TARGET (first name) is required for 'person' mode.[/red]")
            return
        if out_fmt == "table":
            full = f"{name} {surname}".strip()
            console.print(f"[dim]Searching for person: {full}...[/dim]")
        data = person_search(name, surname=surname, phone=phone, limit=limit)
        all_data["person"] = data
        if out_fmt == "table":
            print_person_results(data)

    elif mode == "dork":
        if not dork_query:
            console.print("[red]✗ --dork is required for 'dork' mode.[/red]")
            return
        if out_fmt == "table":
            console.print(f"[dim]Executing: {dork_query}...[/dim]")
        data = custom_dork(dork_query, limit=limit)
        all_data["custom_dork"] = data
        if out_fmt == "table":
            print_custom_dork_results(data)

    if out_fmt == "json":
        print(json.dumps(all_data, indent=2, ensure_ascii=False, default=str))

    if report:
        save_report(target or "dork", all_data, output)


@cli.command("youtube")
@click.argument("channel")
@click.option("--yt-key", "yt_key", envvar="YOUTUBE_V2_KEY", default=None, help="YouTube V2 RapidAPI key")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_youtube(channel, yt_key, report, output):
    """Investigate a YouTube channel by handle, channel ID, or URL.

    Examples:
    \b
    python osint.py youtube @mrbeast
    python osint.py youtube UCX6OQ3DkcsbYNE6H8uQQuVA
    python osint.py youtube https://www.youtube.com/@mkbhd --report
    """
    from modules.youtube_recon import youtube_recon, print_youtube_results
    print_banner()
    console.print("[dim]Fetching YouTube channel...[/dim]")
    yt_data = youtube_recon(channel, youtube_v2_key=yt_key or os.getenv("YOUTUBE_V2_KEY"))
    print_youtube_results(yt_data)
    if report:
        save_report(channel, {"youtube": yt_data}, output)


@cli.command("contacts")
@click.argument("url")
@click.option("--api-key", "api_key", envvar="WEBSITE_CONTACTS_KEY", default=None,
              help="Website Contacts Scraper RapidAPI key (env: WEBSITE_CONTACTS_KEY)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_contacts(url, api_key, report, output):
    """Scrape emails, phone numbers, and social links from a website.

    Examples:
    \b
    python osint.py contacts example.com
    python osint.py contacts https://shopee.vn --report
    python osint.py contacts vnexpress.net --report
    """
    from modules.website_contacts import website_contacts_scrape, print_website_contacts
    print_banner()
    console.print(f"[dim]Scraping contacts from {url}...[/dim]")
    contacts_data = website_contacts_scrape(url, api_key=api_key or os.getenv("WEBSITE_CONTACTS_KEY"))
    print_website_contacts(contacts_data)
    if report:
        save_report(url, {"website_contacts": contacts_data}, output)


@cli.command("full")
@click.argument("target")
@click.option("--type", "target_type",
              type=click.Choice(["domain", "email", "username", "phone", "person"]),
              required=True, help="Type of target")
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None)
@click.option("--region", default="VN")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_full(target, target_type, hibp_key, region, output):  # region kept for future use
    """Run full OSINT investigation and save report.

    Examples:
    \b
    python osint.py full example.com --type domain
    python osint.py full user@example.com --type email
    python osint.py full johndoe --type username
    python osint.py full +84901234567 --type phone
    python osint.py full "Nguyen Van A" --type person
    """
    print_banner()

    if target_type == "domain":
        target = _normalize_target(target)
        if not _is_valid_target(target):
            console.print(f"[red]✗ Invalid domain or IP address: '{target}'[/red]")
            raise SystemExit(1)

    console.print(f"\n[bold green]Full OSINT scan: {target} ({target_type})[/bold green]\n")

    all_data = {}

    if target_type == "domain":
        _run_domain(
            target,
            do_whois=True, do_dns=True, do_subdomain=True, do_dorks=True, do_ip=True,
            do_ssl=True, do_email_sec=True, do_secrets=True, do_cloud=True,
            report=True, output=output, out_fmt="table",
        )
        return  # _run_domain handles save_report internally

    elif target_type == "email":
        all_data["email"] = email_recon(
            target,
            hibp_api_key=hibp_key,
            hunter_key=os.getenv("HUNTER_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY", ""),
        )
        print_email_results(all_data["email"])
        all_data["dorks"] = generate_dorks(target, "email")
        print_dorks(target, "email")

    elif target_type == "username":
        console.print("[dim]Scanning platforms...[/dim]")
        all_data["username"] = username_search(target)
        print_username_results(all_data["username"])

    elif target_type == "phone":
        all_data["phone"] = phone_lookup(target, numverify_key=os.getenv("NUMVERIFY_KEY"))
        print_phone_results(all_data["phone"])  # offline analysis only

    elif target_type == "person":
        all_data["dorks"] = generate_dorks(target, "person")
        print_dorks(target, "person")
        org_dorks = generate_dorks(target, "organization")
        all_data["dorks"].extend(org_dorks)
        print_dorks(target, "organization")

    save_report(target, all_data, output)


@cli.command("image")
@click.argument("image_path")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_image(image_path, report, output):
    """Extract EXIF metadata and GPS from an image file.

    \b
    Examples:
      python osint.py image photo.jpg
      python osint.py image /path/to/image.jpg --report
    """
    from modules.image_recon import analyze_image_metadata, print_image_results
    print_banner()
    if not os.path.exists(image_path):
        console.print(f"[red]✗ File not found: {image_path}[/red]")
        raise SystemExit(1)
    console.print(f"[dim]Analyzing image: {image_path}[/dim]")
    data = analyze_image_metadata(image_path)
    print_image_results(data)
    if report:
        save_report(os.path.basename(image_path), {"image": data}, output)


@cli.command("certs")
@click.argument("domain")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_certs(domain, report, output):
    """Search Certificate Transparency logs for a domain (crt.sh + certspotter).

    Useful for discovering subdomains via certificate records.

    \b
    Examples:
      python osint.py certs example.com
      python osint.py certs example.com --report
    """
    print_banner()
    domain = _normalize_target(domain)
    console.print(f"[dim]Searching Certificate Transparency logs for {domain}...[/dim]")
    data = cert_recon(domain)
    print_cert_results(data)
    if report:
        save_report(domain, {"certs": data}, output)


@cli.command("install")
def cmd_install():
    """Create a system launcher so you can run 'osint-tool' from anywhere.

    \b
    Windows: creates osint-tool.bat in the current directory and adds it to
             the user PATH via the registry (requires no admin rights).
    Linux/macOS: creates ~/bin/osint-tool shell script (adds ~/bin to PATH
                 hint if not already there).

    Example: python osint.py install
    """
    import shutil
    root = Path(__file__).resolve().parent
    python = Path(sys.executable)

    if sys.platform == "win32":
        # Create a .bat launcher next to osint.py
        bat = root / "osint-tool.bat"
        bat.write_text(
            f'@echo off\n"{python}" "{root / "osint.py"}" %*\n',
            encoding="utf-8",
        )
        # Try to add root dir to user PATH via reg
        import subprocess
        try:
            result = subprocess.run(
                ["reg", "query", "HKCU\\Environment", "/v", "PATH"],
                capture_output=True, text=True,
            )
            current_path = ""
            for line in result.stdout.splitlines():
                if "PATH" in line:
                    current_path = line.split("    ")[-1].strip()
                    break

            if str(root) not in current_path:
                new_path = f"{current_path};{root}" if current_path else str(root)
                subprocess.run([
                    "reg", "add", "HKCU\\Environment",
                    "/v", "PATH", "/t", "REG_EXPAND_SZ",
                    "/d", new_path, "/f",
                ], check=True, capture_output=True)
                console.print(f"[bold green]✔ Added to user PATH:[/bold green] {root}")
                console.print("[dim]Restart your terminal for PATH to take effect.[/dim]")
            else:
                console.print(f"[bold yellow]⚠ Already in PATH:[/bold yellow] {root}")
        except Exception as e:
            console.print(f"[bold yellow]⚠ Could not update PATH automatically: {e}[/bold yellow]")
            console.print(f"[dim]Add manually: {root}[/dim]")

        console.print(f"\n[bold green]✔ Launcher created:[/bold green] {bat}")
        console.print("[dim]Run from anywhere:[/dim] [bold cyan]osint-tool menu[/bold cyan]")

    else:
        # Linux / macOS: create ~/bin/osint-tool
        bin_dir = Path.home() / "bin"
        bin_dir.mkdir(exist_ok=True)
        launcher = bin_dir / "osint-tool"
        launcher.write_text(
            f'#!/bin/sh\nexec "{python}" "{root / "osint.py"}" "$@"\n'
        )
        launcher.chmod(0o755)
        console.print(f"[bold green]✔ Launcher created:[/bold green] {launcher}")

        # Check ~/bin is in PATH
        path_env = os.environ.get("PATH", "")
        if str(bin_dir) not in path_env:
            shell_rc = Path.home() / (
                ".zshrc" if shutil.which("zsh") else ".bashrc"
            )
            console.print(f"[bold yellow]⚠ {bin_dir} is not in PATH.[/bold yellow]")
            console.print(f"[dim]Add to {shell_rc}:[/dim]")
            console.print(f'  [bold cyan]export PATH="$HOME/bin:$PATH"[/bold cyan]')
        else:
            console.print("[dim]Run from anywhere:[/dim] [bold cyan]osint-tool menu[/bold cyan]")


@cli.command("update")
def cmd_update():
    """Self-update: git pull + pip install -r requirements.txt.

    \b
    Pulls the latest version from GitHub and upgrades all dependencies.

    Example: python osint.py update
    """
    import subprocess
    console.print("[bold cyan]>> Updating OSINT Tool...[/bold cyan]\n")
    root = Path(__file__).resolve().parent

    # ── Step 1: check for git ──────────────────────────────────────────────────
    import shutil
    if not shutil.which("git"):
        console.print("[bold red]✘ git not found on PATH. Install git and retry.[/bold red]")
        raise SystemExit(1)

    git_dir = root / ".git"
    if not git_dir.exists():
        console.print("[bold yellow]⚠ No .git directory found — not a git clone.[/bold yellow]")
        console.print("[dim]Download the latest release manually from:[/dim]")
        console.print("  [underline bright_blue]https://github.com/cmm-cmm/OSINT-Tool/releases[/underline bright_blue]")
        raise SystemExit(0)

    # ── Step 2: show current version + remote HEAD ────────────────────────────
    try:
        local  = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=root).decode().strip()
        branch = subprocess.check_output(["git", "branch", "--show-current"],     cwd=root).decode().strip()
        console.print(f"[dim]Branch:[/dim] [cyan]{branch}[/cyan]  "
                      f"[dim]Current commit:[/dim] [cyan]{local}[/cyan]")
    except subprocess.CalledProcessError:
        pass

    # ── Step 3: git pull ───────────────────────────────────────────────────────
    console.print("\n[bold]Step 1/2[/bold]  [dim]git pull...[/dim]")
    r = subprocess.run(["git", "pull", "--rebase", "--autostash"], cwd=root)
    if r.returncode != 0:
        console.print("[bold red]✘ git pull failed. Resolve conflicts and retry.[/bold red]")
        raise SystemExit(1)

    # ── Step 4: pip upgrade ────────────────────────────────────────────────────
    req = root / "requirements.txt"
    console.print("\n[bold]Step 2/2[/bold]  [dim]pip install -r requirements.txt --upgrade...[/dim]")
    pip = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", "-r", str(req)])
    if pip.returncode != 0:
        console.print("[bold yellow]⚠ Some packages failed to upgrade. Check requirements.txt.[/bold yellow]")
    else:
        console.print("[bold green]✔ Dependencies up to date.[/bold green]")

    try:
        new = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=root).decode().strip()
        if new != local:
            console.print(f"\n[bold green]✔ Updated:[/bold green] {local} → {new}")
        else:
            console.print("\n[bold green]✔ Already up to date.[/bold green]")
    except subprocess.CalledProcessError:
        console.print("\n[bold green]✔ Update complete.[/bold green]")


@cli.command("twist")
@click.argument("domain")
@click.option("--all-domains", "all_domains", is_flag=True,
              help="Include unregistered permutations (slow). Default: registered only.")
@click.option("--limit", default=100, show_default=True, help="Max results to display")
@click.option("--threads", default=8, show_default=True, help="DNS resolution threads")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table")
def cmd_twist(domain, all_domains, limit, threads, report, output, out_fmt):
    """Detect typosquatting domains using dnstwist permutation engine.

    Generates variations (omission, transposition, homoglyph, IDN, bitsquatting…)
    and resolves which ones are registered. Requires: pip install dnstwist

    \b
    Examples:
      python osint.py twist example.com
      python osint.py twist example.com --all-domains
      python osint.py twist example.com --limit 50 --report
    """
    from modules.domain_twist import twist_domain, print_twist_results

    if out_fmt == "table":
        print_banner()
        console.print(f"[dim]Running dnstwist on {domain}… (may take a minute)[/dim]")

    data = twist_domain(domain, limit=limit, registered_only=not all_domains, threads=threads)

    if out_fmt == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print_twist_results(data)

    if report:
        save_report(domain, {"domain_twist": data}, output)


@cli.command("username-http")
@click.argument("username")
@click.option("--all-sites", "all_sites", is_flag=True, help="Show all results, not just found.")
@click.option("--nsfw", "include_nsfw", is_flag=True, help="Include NSFW sites.")
@click.option("--threads", default=10, show_default=True, help="Parallel request threads")
@click.option("--timeout", default=8, show_default=True, help="Request timeout in seconds")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table")
def cmd_username_http(username, all_sites, include_nsfw, threads, timeout, report, output, out_fmt):
    """Scan 260+ websites for a username via HTTP (tookie-osint style).

    Uses status codes + error-message validation. No external tools required.

    \b
    Examples:
      python osint.py username-http johndoe
      python osint.py username-http johndoe --all-sites --threads 20
      python osint.py username-http johndoe --report
    """
    from modules.username_http import check_username_sites, print_username_site_results

    if out_fmt == "table":
        print_banner()
        console.print(f"[dim]Scanning 260+ sites for username: {username}…[/dim]")

    data = check_username_sites(
        username,
        threads=threads,
        timeout=timeout,
        skip_nsfw=not include_nsfw,
        found_only=not all_sites,
    )

    if out_fmt == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print_username_site_results(data)

    if report:
        save_report(username, {"username_http": data}, output)


@cli.command("email-forensics")
@click.argument("path")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table")
def cmd_email_forensics(path, report, output, out_fmt):
    """Analyse Outlook .msg files for CVE-2023-23397 (UNC-path injection).

    Detects potential NTLM credential theft via malicious calendar reminders.
    Accepts a single .msg file or a directory (scans all .msg files recursively).
    Requires: pip install compoundfiles outlook-msg extract-msg python-dateutil

    \b
    Examples:
      python osint.py email-forensics suspicious.msg
      python osint.py email-forensics /path/to/emails/ --report
    """
    from modules.email_forensics import analyse_path, print_forensics_results

    if out_fmt == "table":
        print_banner()
        console.print(f"[dim]Analysing: {path}[/dim]")

    data = analyse_path(path)

    if out_fmt == "json":
        print(json.dumps(data, indent=2, ensure_ascii=False, default=str))
    else:
        print_forensics_results(data)

    if report:
        from pathlib import Path as _P
        save_report(_P(path).stem or "forensics", {"email_forensics": data}, output)



    """Interactive TUI menu — full guided OSINT investigation.

    \b
    Features:
      - 2-column module grid with system info header
      - Dependency status indicators ✔/✘ per module
      - Search: /keyword  |  Tag filter: t tag
      - External Tools Manager (install/update/run optional tools)
      - Config viewer/editor
      - Inline help: ?

    Example: python osint.py menu
    """
    from modules.tui import run_tui
    run_tui()


if __name__ == "__main__":
    cli()
