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
from modules.username_search import username_search, print_username_results
from modules.ip_lookup import ip_lookup, print_ip_results
from modules.phone_lookup import phone_lookup, print_phone_results
from modules.google_dorks import generate_dorks, print_dorks
from modules.report import save_report
from modules.ssl_analyzer import ssl_analyze, print_ssl_results
from modules.secrets_scanner import secrets_scan, print_secrets_results
from modules.cloud_recon import cloud_recon, print_cloud_recon

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
    subtitle="[green]v1.0.0[/green]",
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
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json"]), default="table", help="Output format")
def cmd_email(email_addr, hibp_key, hunter_key, emailrep_key, do_dorks, report, output, out_fmt):
    """Investigate an email address.

    Example: python osint.py email user@example.com --hibp-key YOUR_KEY
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
def cmd_username(username, report, output):
    """Search a username across 40+ platforms.

    Example: python osint.py username johndoe --report
    """
    print_banner()

    console.print(f"\n[dim]Searching for @{username} across platforms...[/dim]\n")

    data = username_search(username)
    all_data = {"username": data}
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


@cli.command("menu")
def cmd_menu():
    """Interactive menu mode — guided OSINT investigation.

    Example: python osint.py menu
    """
    from rich.table import Table as RTable

    MENU_ITEMS = [
        ("1",  "Domain / IP Investigation",                      "domain"),
        ("2",  "Email Reconnaissance",                           "email"),
        ("3",  "Username Search (40+ platforms)",                "username"),
        ("4",  "Phone Number Analysis",                          "phone"),
        ("5",  "Person / Organization Dorks",                    "person"),
        ("6",  "Social Media Recon (FB / TikTok / IG / Twitter / Reddit)", "social"),
        ("7",  "Website Contacts Scraper",                       "contacts"),
        ("8",  "YouTube Channel Recon",                          "youtube"),
        ("9",  "Breach / Data Leak Check",                       "breach"),
        ("10", "Full Scan + Report",                             "full"),
        ("0",  "Exit",                                           None),
    ]

    while True:
        console.clear()
        print_banner()
        menu_panel = Panel(
            Align.center(Text.from_markup("[bold cyan]OSINT Interactive Menu[/bold cyan]\n[white]Select an option below to start a scan[/white]")),
            box=box.ROUNDED,
            border_style="bright_blue",
            title="[bold magenta]OSINT Tool[/bold magenta]",
            subtitle="[green]Interactive mode[/green]",
            padding=(1, 2),
        )
        console.print(menu_panel)

        menu_table = RTable(show_header=False, box=box.SIMPLE_HEAVY, padding=(0, 2))
        menu_table.add_column("Key", style="bold cyan", width=4)
        menu_table.add_column("Option", style="white")
        for key, label, _ in MENU_ITEMS:
            menu_table.add_row(f"[{key}]", label)

        console.print(menu_table)

        choice = Prompt.ask("\n[bold]Select[/bold]", choices=[m[0] for m in MENU_ITEMS], default="0", show_choices=True)
        if choice == "0":
            console.print("[dim]Goodbye.[/dim]")
            break

        _, label, mode = next(m for m in MENU_ITEMS if m[0] == choice)
        console.print(
            Panel(
                Text(label, style="bold white"),
                box=box.ROUNDED,
                border_style="cyan",
                expand=False,
            )
        )

        output_dir = os.getenv("OSINT_OUTPUT_DIR", ".")
        do_report = Confirm.ask("Save report?", default=False)
        hibp_key = os.getenv("HIBP_API_KEY") or None

        if mode == "domain":
            target = Prompt.ask("Domain or IP (or URL)")
            target = _normalize_target(target)
            if not _is_valid_target(target):
                console.print(f"[red]✗ Invalid: '{target}'[/red]")
                continue
            _run_domain(target, True, True, True, True, True, do_report, output_dir)

        elif mode == "email":
            addr = Prompt.ask("Email address")
            if not validate_email(addr):
                console.print("[red]✗ Invalid email format[/red]")
                continue
            data = email_recon(
                addr,
                hibp_api_key=hibp_key,
                hunter_key=os.getenv("HUNTER_KEY"),
                emailrep_key=os.getenv("EMAILREP_KEY", ""),
            )
            print_email_results(data)
            dorks = generate_dorks(addr, "email")
            all_data = {"email": data, "dorks": dorks}
            print_dorks(addr, "email")
            if do_report:
                save_report(addr, all_data, output_dir)

        elif mode == "username":
            uname = Prompt.ask("Username")
            console.print(f"\n[dim]Scanning {len(__import__('modules.username_search', fromlist=['PLATFORMS']).PLATFORMS)} platforms...[/dim]\n")
            data = username_search(uname)
            all_data = {"username": data}
            print_username_results(data)
            if do_report:
                save_report(uname, all_data, output_dir)

        elif mode == "phone":
            num = Prompt.ask("Phone number (e.g. 0901234567 or +84901234567)")
            data = phone_lookup(num, numverify_key=os.getenv("NUMVERIFY_KEY"))
            print_phone_results(data)
            if do_report:
                save_report(num, {"phone": data}, output_dir)

        elif mode == "person":
            name = Prompt.ask("Full name or organization")
            dorks = generate_dorks(name, "person")
            print_dorks(name, "person")
            all_data = {"dorks": dorks}
            if do_report:
                save_report(name, all_data, output_dir)

        elif mode == "social":
            from modules.social_recon import (
                facebook_recon, tiktok_recon, print_facebook_results, print_tiktok_results,
                instagram_recon, print_instagram_results, twitter_recon, print_twitter_results,
                reddit_recon, print_reddit_results,
            )
            fb_id = Prompt.ask("Facebook username / URL / numeric ID (leave blank to skip)", default="")
            tt_user = Prompt.ask("TikTok username (leave blank to skip)", default="")
            ig_user = Prompt.ask("Instagram username (leave blank to skip)", default="")
            tw_user = Prompt.ask("Twitter/X username (leave blank to skip)", default="")
            reddit_user = Prompt.ask("Reddit username (leave blank to skip)", default="")
            if not fb_id and not tt_user and not ig_user and not tw_user and not reddit_user:
                console.print("[red]✗ At least one platform is required[/red]")
                continue
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
            if tt_user:
                console.print("[dim]Fetching TikTok profile...[/dim]")
                tt_data = tiktok_recon(
                    tt_user,
                    tokapi_key=os.getenv("TOKAPI_KEY"),
                    tiktok_api_key=os.getenv("TIKTOK_API_KEY"),
                )
                all_data["tiktok"] = tt_data
                print_tiktok_results(tt_data)
            if ig_user:
                console.print("[dim]Fetching Instagram profile...[/dim]")
                ig_data = instagram_recon(ig_user, api_key=os.getenv("INSTAGRAM_KEY"))
                all_data["instagram"] = ig_data
                print_instagram_results(ig_data)
            if tw_user:
                console.print("[dim]Fetching Twitter/X profile...[/dim]")
                tw_data = twitter_recon(tw_user, bearer_token=os.getenv("TWITTER_BEARER_TOKEN"))
                all_data["twitter"] = tw_data
                print_twitter_results(tw_data)
            if reddit_user:
                console.print("[dim]Fetching Reddit profile...[/dim]")
                reddit_data = reddit_recon(reddit_user)
                all_data["reddit"] = reddit_data
                print_reddit_results(reddit_data)
            if do_report:
                save_report(fb_id or tt_user or ig_user or tw_user or reddit_user, all_data, output_dir)

        elif mode == "contacts":
            from modules.website_contacts import website_contacts_scrape, print_website_contacts
            site_url = Prompt.ask("Website URL or domain (e.g. shopee.vn or https://example.com)")
            console.print("[dim]Scraping website contacts...[/dim]")
            contacts_data = website_contacts_scrape(site_url, api_key=os.getenv("WEBSITE_CONTACTS_KEY"))
            print_website_contacts(contacts_data)
            if do_report:
                save_report(site_url, {"website_contacts": contacts_data}, output_dir)

        elif mode == "youtube":
            from modules.youtube_recon import youtube_recon, print_youtube_results
            channel = Prompt.ask("YouTube handle, channel ID, or URL")
            console.print("[dim]Fetching YouTube channel...[/dim]")
            yt_data = youtube_recon(channel, youtube_v2_key=os.getenv("YOUTUBE_V2_KEY"))
            print_youtube_results(yt_data)
            if do_report:
                save_report(channel, {"youtube": yt_data}, output_dir)

        elif mode == "breach":
            from modules.breach_check import breach_check, print_breach_results
            tgt = Prompt.ask("Email hoặc username cần kiểm tra")
            check_pw = Confirm.ask("Kiểm tra mật khẩu qua HIBP Pwned Passwords?", default=False)
            pw = None
            if check_pw:
                import getpass
                pw = getpass.getpass("  Nhập mật khẩu (không hiển thị): ")
            bd_key = os.getenv("BREACHDIRECTORY_KEY") or None
            console.print("[dim]Đang kiểm tra các nguồn rò rỉ dữ liệu...[/dim]")
            br_data = breach_check(
                tgt, password=pw, hibp_key=hibp_key, breachdir_key=bd_key,
                dehashed_email=os.getenv("DEHASHED_EMAIL"),
                dehashed_key=os.getenv("DEHASHED_KEY"),
                snusbase_key=os.getenv("SNUSBASE_KEY"),
                emailrep_key=os.getenv("EMAILREP_KEY"),
                hunter_key=os.getenv("HUNTER_KEY"),
            )
            print_breach_results(br_data)
            if do_report:
                save_report(tgt, {"breach": br_data}, output_dir)

        elif mode == "full":
            target = Prompt.ask("Target")
            ttype = Prompt.ask(
                "Type",
                choices=["domain", "email", "username", "phone", "person"],
                default="domain",
            )
            # Reuse full command logic
            from click.testing import CliRunner
            args = [target, "--type", ttype, "--output", output_dir]
            if hibp_key:
                args += ["--hibp-key", hibp_key]
            CliRunner(mix_stderr=False).invoke(cmd_full, args, catch_exceptions=False)

        if not Confirm.ask("\nContinue?", default=True):
            console.print("[dim]Goodbye.[/dim]")
            break


if __name__ == "__main__":
    cli()
