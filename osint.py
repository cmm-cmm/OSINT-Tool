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
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
import click
from rich.prompt import Prompt, Confirm

load_dotenv(Path(__file__).parent / ".env")
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from modules.whois_lookup import whois_lookup, dns_enum, resolve_ip, print_whois, print_dns, subdomain_enum, print_subdomains
from modules.email_recon import email_recon, print_email_results, validate_email
from modules.username_search import username_search, print_username_results
from modules.ip_lookup import ip_lookup, print_ip_results
from modules.phone_lookup import phone_lookup, print_phone_results
from modules.google_dorks import generate_dorks, print_dorks
from modules.report import save_report

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
    return bool(_DOMAIN_RE.match(target) or _IP_RE.match(target))


def _load_targets(single: str | None, targets_file: str | None, mode: str) -> list:
    """Return list of targets from single arg or file."""
    if targets_file:
        lines = Path(targets_file).read_text(encoding="utf-8").splitlines()
        return [l.strip() for l in lines if l.strip() and not l.startswith("#")]
    if single:
        return [single]
    return []


BANNER = """
[bold cyan]
 ██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗
██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝       ██╔══╝██╔═══██╗██╔═══██╗██║
██║   ██║███████╗██║██╔██╗ ██║   ██║    █████╗██║   ██║   ██║██║   ██║██║
██║   ██║╚════██║██║██║╚██╗██║   ██║    ╚════╝██║   ██║   ██║██║   ██║██║
╚██████╔╝███████║██║██║ ╚████║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗
 ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
[/bold cyan]
[dim]Open Source Intelligence Tool — Educational & Research Use Only[/dim]
"""


def print_banner():
    console.print(BANNER)


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
@click.option("--report", is_flag=True, help="Save HTML+JSON+CSV report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
@click.option("--output-format", "out_fmt", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format")
def cmd_domain(target, targets_file, do_whois, do_dns, do_subdomain, do_dorks, do_ip, report, output, out_fmt):
    """Investigate a domain or IP address.

    Example: python osint.py domain example.com --report
    Example: python osint.py domain --targets domains.txt --report
    """
    targets = _load_targets(target, targets_file, "domain")
    if not targets:
        console.print("[red]✗ Provide a TARGET or --targets FILE[/red]")
        raise SystemExit(1)

    for t in targets:
        _run_domain(t, do_whois, do_dns, do_subdomain, do_dorks, do_ip, report, output, out_fmt)


def _run_domain(target, do_whois, do_dns, do_subdomain, do_dorks, do_ip, report, output, out_fmt="table"):
    """Core domain scan logic (reusable for single and batch)."""
    target = _normalize_target(target)
    if not _is_valid_target(target):
        console.print(f"[red]✗ Invalid domain or IP address: '{target}'[/red]")
        return
    if out_fmt == "table":
        print_banner()
        
    console.print(f"\n[bold]Target:[/bold] [green]{target}[/green]\n")

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

    if do_subdomain:
        if out_fmt == "table":
            console.print("[dim]Enumerating subdomains...[/dim]")
        data = subdomain_enum(target)
        all_data["subdomains"] = data
        if out_fmt == "table":
            print_subdomains(data)

    if do_ip:
        if out_fmt == "table":
            console.print("[dim]Running IP/domain intelligence...[/dim]")
        ip_target = resolve_ip(target) if not target[0].isdigit() else target
        data = ip_lookup(ip_target if not target[0].isalpha() else target)
        all_data["ip"] = data
        if out_fmt == "table":
            print_ip_results(data)

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
@click.option("--dorks/--no-dorks", "do_dorks", default=True, help="Generate email dorks")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_email(email_addr, hibp_key, do_dorks, report, output):
    """Investigate an email address.

    Example: python osint.py email user@example.com --hibp-key YOUR_KEY
    """
    if not validate_email(email_addr):
        console.print(f"[red]✗ Invalid email format: '{email_addr}'[/red]")
        raise SystemExit(1)
    print_banner()   

    all_data = {}

    console.print("[dim]Analyzing email...[/dim]")
    data = email_recon(email_addr, hibp_key)
    all_data["email"] = data
    print_email_results(data)

    if do_dorks:
        dorks = generate_dorks(email_addr, "email")
        all_data["dorks"] = dorks
        print_dorks(email_addr, "email")

    if report:
        save_report(email_addr, all_data, output)


@cli.command("username")
@click.argument("username")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_username(username, report, output):
    """Search a username across 30+ platforms.

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
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_phone(phone_number, region, report, output):
    """Analyze a phone number (offline + public data).

    Example: python osint.py phone +84901234567
    Example: python osint.py phone 0901234567 --region VN
    """
    print_banner()
    
    data = phone_lookup(phone_number)
    all_data = {"phone": data}
    print_phone_results(data)

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
    data = breach_check(target, password=password, hibp_key=hibp_key, breachdir_key=breachdir_key)
    print_breach_results(data)
    if report:
        save_report(target, {"breach": data}, output)


@cli.command("social")
@click.option("--facebook", "fb_id", default=None, metavar="ID_OR_URL",
              help="Facebook username, profile URL, or numeric ID")
@click.option("--tiktok", "tt_user", default=None, metavar="USERNAME",
              help="TikTok username (with or without @)")
@click.option("--report", is_flag=True, help="Save HTML+JSON report")
@click.option("--output", default=lambda: os.getenv("OSINT_OUTPUT_DIR", "."), help="Output directory for report")
def cmd_social(fb_id, tt_user, report, output):
    """Investigate Facebook and TikTok public profiles.

    Examples:
    \b
    python osint.py social --facebook johndoe
    python osint.py social --tiktok johndoe
    python osint.py social --facebook johndoe --tiktok johndoe --report
    python osint.py social --facebook https://www.facebook.com/johndoe
    """
    from modules.social_recon import facebook_recon, tiktok_recon, print_facebook_results, print_tiktok_results

    if not fb_id and not tt_user:
        console.print("[red]✗ Provide at least --facebook USERNAME or --tiktok USERNAME[/red]")
        raise SystemExit(1)

    print_banner()
    all_data = {}

    if fb_id:
        console.print("[dim]Fetching Facebook profile...[/dim]")
        fb_data = facebook_recon(fb_id)
        all_data["facebook"] = fb_data
        print_facebook_results(fb_data)

    if tt_user:
        console.print("[dim]Fetching TikTok profile...[/dim]")
        tt_data = tiktok_recon(tt_user)
        all_data["tiktok"] = tt_data
        print_tiktok_results(tt_data)

    if report:
        identifier = fb_id or tt_user
        save_report(identifier, all_data, output)


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
        all_data["whois"] = whois_lookup(target)
        print_whois(all_data["whois"])
        all_data["dns"] = dns_enum(target)
        print_dns(all_data["dns"])
        console.print("[dim]Enumerating subdomains...[/dim]")
        all_data["subdomains"] = subdomain_enum(target)
        print_subdomains(all_data["subdomains"])
        all_data["ip"] = ip_lookup(target)
        print_ip_results(all_data["ip"])
        all_data["dorks"] = generate_dorks(target, "domain")
        print_dorks(target, "domain")

    elif target_type == "email":
        all_data["email"] = email_recon(target, hibp_key)
        print_email_results(all_data["email"])
        all_data["dorks"] = generate_dorks(target, "email")
        print_dorks(target, "email")

    elif target_type == "username":
        console.print("[dim]Scanning platforms...[/dim]")
        all_data["username"] = username_search(target)
        print_username_results(all_data["username"])

    elif target_type == "phone":
        all_data["phone"] = phone_lookup(target)
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
    print_banner()

    MENU_ITEMS = [
        ("1", "Domain / IP Investigation",        "domain"),
        ("2", "Email Reconnaissance",             "email"),
        ("3", "Username Search (40+ platforms)",  "username"),
        ("4", "Phone Number Analysis",            "phone"),
        ("5", "Person / Organization Dorks",      "person"),
        ("6", "Social Media Recon (FB / TikTok)", "social"),
        ("7", "Breach / Data Leak Check",         "breach"),
        ("8", "Full Scan + Report",               "full"),
        ("0", "Exit",                             None),
    ]

    while True:
        menu_table = RTable(show_header=False, box=None, padding=(0, 2))
        menu_table.add_column("Key", style="bold cyan", width=4)
        menu_table.add_column("Option", style="white")
        for key, label, _ in MENU_ITEMS:
            menu_table.add_row(f"[{key}]", label)

        console.print("\n[bold cyan]═══ MAIN MENU ═══[/bold cyan]")
        console.print(menu_table)

        choice = Prompt.ask("\n[bold]Select[/bold]", choices=[m[0] for m in MENU_ITEMS], default="0")
        if choice == "0":
            console.print("[dim]Goodbye.[/dim]")
            break

        _, label, mode = next(m for m in MENU_ITEMS if m[0] == choice)
        console.rule(f"[bold cyan]{label}[/bold cyan]")

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
            data = email_recon(addr, hibp_key)
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
            data = phone_lookup(num)
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
            from modules.social_recon import facebook_recon, tiktok_recon, print_facebook_results, print_tiktok_results
            fb_id = Prompt.ask("Facebook username / URL / numeric ID (leave blank to skip)", default="")
            tt_user = Prompt.ask("TikTok username (leave blank to skip)", default="")
            if not fb_id and not tt_user:
                console.print("[red]✗ At least one platform is required[/red]")
                continue
            all_data = {}
            if fb_id:
                console.print("[dim]Fetching Facebook profile...[/dim]")
                fb_data = facebook_recon(fb_id)
                all_data["facebook"] = fb_data
                print_facebook_results(fb_data)
            if tt_user:
                console.print("[dim]Fetching TikTok profile...[/dim]")
                tt_data = tiktok_recon(tt_user)
                all_data["tiktok"] = tt_data
                print_tiktok_results(tt_data)
            if do_report:
                save_report(fb_id or tt_user, all_data, output_dir)

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
            br_data = breach_check(tgt, password=pw, hibp_key=hibp_key, breachdir_key=bd_key)
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
