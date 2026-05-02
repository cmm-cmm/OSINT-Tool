"""
Base class for all OSINT Tool interactive modules.

Each subclass represents one scan category and provides:
- Metadata (TITLE, DESCRIPTION, TAGS, REQUIRES_ENV, OPTIONAL_DEPS)
- is_available property for optional dependency checking
- run_interactive() for TUI-driven execution
"""

from __future__ import annotations

import shutil
from typing import Callable

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

from modules.constants import (
    THEME_PRIMARY, THEME_SUCCESS, THEME_WARNING, THEME_ERROR,
)

console = Console()


class OsintModule:
    """
    Abstract base for an OSINT scan category shown in the TUI menu.

    Subclasses must implement run_interactive() and set class-level metadata.
    """

    TITLE: str = ""
    DESCRIPTION: str = ""
    # Short keyword tags for search/filter (e.g. ["domain", "dns", "recon"])
    TAGS: list[str] = []
    # Environment variable names that power optional features (shown in menu)
    REQUIRES_ENV: list[str] = []
    # External Python package names whose presence enables features
    OPTIONAL_DEPS: list[str] = []
    # Icon shown in menu (emoji)
    ICON: str = "🔍"
    # Set ARCHIVED=True to hide from main menu (show under option 95)
    ARCHIVED: bool = False
    ARCHIVED_REASON: str = ""
    # OS platforms where this module has full support ("windows", "linux", "darwin")
    # Empty list = all platforms supported
    SUPPORTED_OS: list[str] = []

    # ── Dependency status ──────────────────────────────────────────────────────

    @property
    def missing_deps(self) -> list[str]:
        """Return list of OPTIONAL_DEPS that are not importable/installed."""
        missing = []
        for dep in self.OPTIONAL_DEPS:
            try:
                __import__(dep.replace("-", "_"))
            except ImportError:
                # Also check as a binary on PATH
                if shutil.which(dep) is None:
                    missing.append(dep)
        return missing

    @property
    def is_available(self) -> bool:
        """True when all optional dependencies are satisfied (or there are none)."""
        return len(self.missing_deps) == 0 or not self.OPTIONAL_DEPS

    @property
    def env_status(self) -> dict[str, bool]:
        """Return {ENV_VAR: is_set} for each REQUIRES_ENV entry."""
        import os
        return {k: bool(os.getenv(k)) for k in self.REQUIRES_ENV}

    # ── Info display ───────────────────────────────────────────────────────────

    def show_info(self) -> None:
        """Print a rich panel with module metadata."""
        lines = [f"[cyan]{self.DESCRIPTION}[/cyan]"]

        if self.REQUIRES_ENV:
            env_st = self.env_status
            lines.append("")
            lines.append("[dim]API keys / env vars:[/dim]")
            for k, ok in env_st.items():
                icon = "[green]✔[/green]" if ok else "[yellow]✘[/yellow]"
                lines.append(f"  {icon} {k}")

        if self.OPTIONAL_DEPS:
            missing = self.missing_deps
            lines.append("")
            lines.append("[dim]Optional dependencies:[/dim]")
            for dep in self.OPTIONAL_DEPS:
                ok = dep not in missing
                icon = "[green]✔[/green]" if ok else "[red]✘ not installed[/red]"
                lines.append(f"  {icon} {dep}")

        if self.TAGS:
            lines.append("")
            tags_str = "  ".join(f"[dim]#{t}[/dim]" for t in self.TAGS)
            lines.append(tags_str)

        console.print(Panel(
            "\n".join(lines),
            title=f"[{THEME_PRIMARY}]{self.ICON} {self.TITLE}[/{THEME_PRIMARY}]",
            border_style="bright_blue",
            box=box.ROUNDED,
            padding=(1, 2),
        ))

    @property
    def os_note(self) -> str:
        """Return a short platform note if this module has reduced support on current OS."""
        if not self.SUPPORTED_OS:
            return ""
        import platform
        current = platform.system().lower()  # "windows", "linux", "darwin"
        if current not in self.SUPPORTED_OS:
            return "(limited on this OS)"
        return ""

    # ── Entry point ────────────────────────────────────────────────────────────

    def run_interactive(self) -> None:
        """
        Prompt the user for inputs and run the scan.
        Subclasses must override this method.
        """
        raise NotImplementedError(f"{self.__class__.__name__} must implement run_interactive()")

    def run(self, target_hint: str = "") -> None:
        """
        Public entry called by TUI. Wraps run_interactive() with:
        - Internet connectivity warning (non-blocking)
        - Scan history logging
        """
        from modules.utils import check_internet, append_scan_history

        if not check_internet():
            console.print(
                f"[bold yellow]⚠  No internet connection detected. "
                f"Results may be incomplete.[/bold yellow]\n"
            )

        try:
            self.run_interactive()
            append_scan_history(self.TITLE, target_hint or "—", status="ok")
        except KeyboardInterrupt:
            append_scan_history(self.TITLE, target_hint or "—", status="cancelled")
            raise


# ─────────────────────────────────────────────────────────────────────────────
# Concrete module wrappers
# Each class maps one CLI command → interactive TUI flow
# ─────────────────────────────────────────────────────────────────────────────

class DomainModule(OsintModule):
    TITLE = "Domain / IP Recon"
    DESCRIPTION = (
        "WHOIS, DNS, subdomains, SSL/TLS, email security (SPF/DKIM/DMARC),\n"
        "zone transfer, IP intelligence, secrets scan, cloud buckets."
    )
    TAGS = ["domain", "dns", "whois", "ssl", "recon", "subdomain"]
    ICON = "🌐"
    REQUIRES_ENV = ["SHODAN_KEY", "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.whois_lookup import (
            whois_lookup, dns_enum, print_whois, print_dns,
            subdomain_enum, print_subdomains,
            check_email_security, print_email_security,
            test_zone_transfer, print_zone_transfer,
            check_dns_security, print_dns_security,
        )
        from modules.ssl_analyzer import ssl_analyze, print_ssl_results
        from modules.ip_lookup import ip_lookup, print_ip_results
        from modules.google_dorks import generate_dorks, print_dorks
        from modules.secrets_scanner import secrets_scan, print_secrets_results
        from modules.cloud_recon import cloud_recon, print_cloud_recon
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Domain or IP[/bold cyan]").strip()
        if not target:
            return

        do_secrets = Prompt.ask(
            "[dim]Secrets scan? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        do_cloud = Prompt.ask(
            "[dim]Cloud bucket enum? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        all_data = {}

        console.print("\n[dim]Running WHOIS...[/dim]")
        d = whois_lookup(target); all_data["whois"] = d; print_whois(d)

        console.print("[dim]Enumerating DNS...[/dim]")
        d = dns_enum(target); all_data["dns"] = d; print_dns(d)

        console.print("[dim]Checking email security (SPF/DKIM/DMARC)...[/dim]")
        d = check_email_security(target); all_data["email_security"] = d; print_email_security(d)

        console.print("[dim]Testing zone transfer...[/dim]")
        d = test_zone_transfer(target); all_data["zone_transfer"] = d; print_zone_transfer(d)

        console.print("[dim]Analyzing DNS security (DNSSEC/CAA)...[/dim]")
        d = check_dns_security(target); all_data["dns_security"] = d; print_dns_security(d)

        console.print("[dim]Enumerating subdomains...[/dim]")
        d = subdomain_enum(target); all_data["subdomains"] = d; print_subdomains(d)

        console.print("[dim]Analyzing SSL/TLS...[/dim]")
        d = ssl_analyze(target); all_data["ssl"] = d; print_ssl_results(d)

        console.print("[dim]Running IP intelligence...[/dim]")
        d = ip_lookup(
            target,
            virustotal_key=os.getenv("VIRUSTOTAL_KEY"),
            shodan_key=os.getenv("SHODAN_KEY"),
            abuseipdb_key=os.getenv("ABUSEIPDB_KEY"),
        )
        all_data["ip"] = d; print_ip_results(d)

        print_dorks(target, "domain"); all_data["dorks"] = generate_dorks(target, "domain")

        if do_secrets:
            console.print("[dim]Scanning for secrets...[/dim]")
            d = secrets_scan(target); all_data["secrets"] = d; print_secrets_results(d)

        if do_cloud:
            console.print("[dim]Enumerating cloud buckets...[/dim]")
            d = cloud_recon(target); all_data["cloud"] = d; print_cloud_recon(d)

        if do_report:
            save_report(target, all_data, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved to {get_output_dir()}[/{THEME_SUCCESS}]")


class EmailModule(OsintModule):
    TITLE = "Email OSINT"
    DESCRIPTION = (
        "Validate email, check breaches (HIBP), Hunter.io, EmailRep,\n"
        "MX records, disposable detection, holehe (120+ sites)."
    )
    TAGS = ["email", "breach", "recon", "osint"]
    ICON = "📧"
    REQUIRES_ENV = ["HIBP_API_KEY", "HUNTER_KEY", "EMAILREP_KEY"]
    OPTIONAL_DEPS = ["holehe"]

    def run_interactive(self) -> None:
        import os
        from modules.email_recon import email_recon, print_email_results, validate_email
        from modules.google_dorks import generate_dorks, print_dorks
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        email = Prompt.ask("[bold cyan]Email address[/bold cyan]").strip()
        if not email or not validate_email(email):
            console.print("[red]✗ Invalid email.[/red]")
            return

        do_holehe = Prompt.ask(
            "[dim]Run holehe check? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        console.print("\n[dim]Analyzing email...[/dim]")
        data = email_recon(
            email,
            hibp_api_key=os.getenv("HIBP_API_KEY"),
            hunter_key=os.getenv("HUNTER_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY", ""),
            do_holehe=do_holehe,
        )
        print_email_results(data)
        print_dorks(email, "email")

        if do_report:
            save_report(email, {"email": data, "dorks": generate_dorks(email, "email")},
                        str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class UsernameModule(OsintModule):
    TITLE = "Username Search"
    DESCRIPTION = "Search a username across 40+ platforms. Optional: maigret (3000+ sites)."
    TAGS = ["username", "social", "osint", "recon"]
    ICON = "👤"
    OPTIONAL_DEPS = ["maigret"]

    def run_interactive(self) -> None:
        from modules.username_search import username_search, print_username_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        username = Prompt.ask("[bold cyan]Username[/bold cyan]").strip().lstrip("@")
        if not username:
            return

        do_maigret = Prompt.ask(
            "[dim]Run maigret deep scan? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        console.print(f"\n[dim]Searching @{username} across platforms...[/dim]")
        data = username_search(username)
        all_data = {"username": data}

        if do_maigret:
            from modules.username_search import run_maigret
            console.print("[dim]Running maigret deep scan...[/dim]")
            mg = run_maigret(username)
            data["maigret"] = mg
            all_data["maigret"] = mg

        print_username_results(data)

        if do_report:
            save_report(username, all_data, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class PhoneModule(OsintModule):
    TITLE = "Phone Lookup"
    DESCRIPTION = "Parse and identify phone numbers offline + NumVerify API enrichment."
    TAGS = ["phone", "osint", "recon"]
    ICON = "📞"
    REQUIRES_ENV = ["NUMVERIFY_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.phone_lookup import phone_lookup, print_phone_results
        from modules.report import save_report
        from config import get_output_dir, get_default_region

        self.show_info()
        number = Prompt.ask("[bold cyan]Phone number[/bold cyan] (e.g. +84901234567)").strip()
        if not number:
            return
        region = Prompt.ask(
            "[dim]Region[/dim]", default=get_default_region()
        ).strip().upper()
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = phone_lookup(number, region=region, numverify_key=os.getenv("NUMVERIFY_KEY"))
        print_phone_results(data)

        if do_report:
            save_report(number, {"phone": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class IPModule(OsintModule):
    TITLE = "IP Intelligence"
    DESCRIPTION = "Geo-locate IP, ASN, Shodan, VirusTotal, AbuseIPDB enrichment."
    TAGS = ["ip", "geo", "shodan", "recon"]
    ICON = "🌍"
    REQUIRES_ENV = ["SHODAN_KEY", "VIRUSTOTAL_KEY", "ABUSEIPDB_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.ip_lookup import ip_lookup, print_ip_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        ip = Prompt.ask("[bold cyan]IP address[/bold cyan]").strip()
        if not ip:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = ip_lookup(
            ip,
            virustotal_key=os.getenv("VIRUSTOTAL_KEY"),
            shodan_key=os.getenv("SHODAN_KEY"),
            abuseipdb_key=os.getenv("ABUSEIPDB_KEY"),
        )
        print_ip_results(data)

        if do_report:
            save_report(ip, {"ip": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class SSLModule(OsintModule):
    TITLE = "SSL / TLS Analyzer"
    DESCRIPTION = "Analyze SSL/TLS security, certificate chain, cipher suites (grade A+→F)."
    TAGS = ["ssl", "tls", "certificate", "security"]
    ICON = "🔒"

    def run_interactive(self) -> None:
        from modules.ssl_analyzer import ssl_analyze, print_ssl_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Domain[/bold cyan]").strip()
        if not target:
            return
        port_str = Prompt.ask("[dim]Port[/dim]", default="443")
        try:
            port = int(port_str)
        except ValueError:
            port = 443
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = ssl_analyze(target, port=port)
        print_ssl_results(data)

        if do_report:
            save_report(target, {"ssl": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class InstagramModule(OsintModule):
    TITLE = "Instagram OSINT"
    DESCRIPTION = "Public profile data, engagement rate, shadowban check, hashtag OSINT."
    TAGS = ["instagram", "social", "osint"]
    ICON = "📸"
    OPTIONAL_DEPS = ["instaloader"]

    def run_interactive(self) -> None:
        from modules.instagram_recon import instagram_recon, print_instagram_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        username = Prompt.ask("[bold cyan]Instagram username[/bold cyan]").strip().lstrip("@")
        if not username:
            return

        do_shadowban = Prompt.ask(
            "[dim]Shadowban check? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        do_engagement = Prompt.ask(
            "[dim]Engagement rate? (y/N)[/dim]", default="n"
        ).lower().startswith("y")
        hashtag = Prompt.ask(
            "[dim]Hashtag OSINT (leave blank to skip)[/dim]", default=""
        ).strip() or None
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = instagram_recon(
            username, do_shadowban=do_shadowban,
            do_engagement=do_engagement, hashtag=hashtag,
        )
        print_instagram_results(data)

        if do_report:
            save_report(username, {"instagram": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class SecretsModule(OsintModule):
    TITLE = "Secrets Scanner"
    DESCRIPTION = "Scan website for exposed .git, .env, backup files, hardcoded credentials."
    TAGS = ["secrets", "exposure", "security", "recon"]
    ICON = "🔑"

    def run_interactive(self) -> None:
        from modules.secrets_scanner import secrets_scan, print_secrets_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Domain or URL[/bold cyan]").strip()
        if not target:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = secrets_scan(target)
        print_secrets_results(data)

        if do_report:
            save_report(target, {"secrets": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class CloudModule(OsintModule):
    TITLE = "Cloud Bucket Recon"
    DESCRIPTION = "Enumerate public S3, GCS, Azure, DigitalOcean Spaces buckets."
    TAGS = ["cloud", "s3", "gcs", "azure", "recon"]
    ICON = "☁️"

    def run_interactive(self) -> None:
        from modules.cloud_recon import cloud_recon, print_cloud_recon
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Domain or company name[/bold cyan]").strip()
        if not target:
            return
        max_b = Prompt.ask("[dim]Max bucket variations[/dim]", default="30")
        try:
            max_buckets = int(max_b)
        except ValueError:
            max_buckets = 30
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = cloud_recon(target, max_buckets=max_buckets)
        print_cloud_recon(data)

        if do_report:
            save_report(target, {"cloud": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class BreachModule(OsintModule):
    TITLE = "Breach Check"
    DESCRIPTION = "Check email/username in data breaches. Sources: HIBP, LeakCheck, BreachDirectory."
    TAGS = ["breach", "email", "password", "osint"]
    ICON = "💥"
    REQUIRES_ENV = ["HIBP_API_KEY", "BREACHDIRECTORY_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.breach_check import breach_check, print_breach_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Email or username[/bold cyan]").strip()
        if not target:
            return
        password = Prompt.ask(
            "[dim]Check password via HIBP? (leave blank to skip)[/dim]", default="", password=True
        ).strip() or None
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = breach_check(
            target, password=password,
            hibp_key=os.getenv("HIBP_API_KEY"),
            breachdir_key=os.getenv("BREACHDIRECTORY_KEY"),
            dehashed_email=os.getenv("DEHASHED_EMAIL"),
            dehashed_key=os.getenv("DEHASHED_KEY"),
            snusbase_key=os.getenv("SNUSBASE_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY"),
            hunter_key=os.getenv("HUNTER_KEY"),
        )
        print_breach_results(data)

        if do_report:
            save_report(target, {"breach": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class SocialModule(OsintModule):
    TITLE = "Social Media OSINT"
    DESCRIPTION = "Investigate Facebook, TikTok, Instagram, Twitter/X and Reddit public profiles."
    TAGS = ["social", "facebook", "tiktok", "twitter", "reddit", "osint"]
    ICON = "📱"
    REQUIRES_ENV = ["FACEBOOK_SCRAPER_KEY", "TWITTER_BEARER_TOKEN"]

    def run_interactive(self) -> None:
        import os
        from modules.social_recon import (
            facebook_recon, tiktok_recon, print_facebook_results, print_tiktok_results,
            instagram_recon, print_instagram_results, twitter_recon, print_twitter_results,
            reddit_recon, print_reddit_results,
            detect_suspicious_account, print_account_analysis,
        )
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        console.print("[dim]Nhập username/ID cho nền tảng muốn điều tra (bỏ trống để bỏ qua):[/dim]")
        fb   = Prompt.ask("[bold cyan]Facebook[/bold cyan] (username/URL/ID)", default="").strip()
        tt   = Prompt.ask("[bold cyan]TikTok[/bold cyan] username", default="").strip()
        ig   = Prompt.ask("[bold cyan]Instagram[/bold cyan] username", default="").strip()
        tw   = Prompt.ask("[bold cyan]Twitter/X[/bold cyan] username", default="").strip()
        red  = Prompt.ask("[bold cyan]Reddit[/bold cyan] username", default="").strip()

        if not any([fb, tt, ig, tw, red]):
            console.print("[yellow]⚠ Không có nền tảng nào được chọn.[/yellow]")
            return

        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        all_data = {}

        if fb:
            console.print("[dim]Fetching Facebook...[/dim]")
            d = facebook_recon(fb, fb_scraper_key=os.getenv("FACEBOOK_SCRAPER_KEY"),
                               hibp_key=os.getenv("HIBP_API_KEY"))
            all_data["facebook"] = d; print_facebook_results(d)
            a = detect_suspicious_account(d, platform="Facebook")
            all_data["facebook_analysis"] = a; print_account_analysis(a)

        if tt:
            console.print("[dim]Fetching TikTok...[/dim]")
            d = tiktok_recon(tt, tokapi_key=os.getenv("TOKAPI_KEY"),
                             tiktok_api_key=os.getenv("TIKTOK_API_KEY"))
            all_data["tiktok"] = d; print_tiktok_results(d)

        if ig:
            console.print("[dim]Fetching Instagram...[/dim]")
            d = instagram_recon(ig, api_key=os.getenv("INSTAGRAM_KEY"))
            all_data["instagram"] = d; print_instagram_results(d)

        if tw:
            console.print("[dim]Fetching Twitter/X...[/dim]")
            d = twitter_recon(tw, bearer_token=os.getenv("TWITTER_BEARER_TOKEN"))
            all_data["twitter"] = d; print_twitter_results(d)

        if red:
            console.print("[dim]Fetching Reddit...[/dim]")
            d = reddit_recon(red)
            all_data["reddit"] = d; print_reddit_results(d)

        if do_report:
            ident = fb or tt or ig or tw or red
            save_report(ident, all_data, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class CertModule(OsintModule):
    TITLE = "Certificate Transparency"
    DESCRIPTION = "Query crt.sh and other CT logs for all certificates issued for a domain."
    TAGS = ["certificate", "ct", "domain", "recon"]
    ICON = "📜"

    def run_interactive(self) -> None:
        from modules.cert_transparency import cert_recon, print_cert_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        target = Prompt.ask("[bold cyan]Domain[/bold cyan]").strip()
        if not target:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = cert_recon(target)
        print_cert_results(data)

        if do_report:
            save_report(target, {"cert": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class ImageModule(OsintModule):
    TITLE = "Image / EXIF Recon"
    DESCRIPTION = "Extract EXIF metadata from images. Detect GPS coordinates, device info."
    TAGS = ["image", "exif", "metadata", "osint"]
    ICON = "🖼️"

    def run_interactive(self) -> None:
        from modules.image_recon import analyze_image_metadata, print_image_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        path = Prompt.ask("[bold cyan]Image path or URL[/bold cyan]").strip()
        if not path:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = analyze_image_metadata(path)
        print_image_results(data)

        if do_report:
            save_report(path, {"image": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class YoutubeModule(OsintModule):
    TITLE = "YouTube Channel OSINT"
    DESCRIPTION = "Investigate YouTube channels by handle, channel ID, or URL."
    TAGS = ["youtube", "social", "osint", "video"]
    ICON = "▶️"
    REQUIRES_ENV = ["YOUTUBE_V2_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.youtube_recon import youtube_recon, print_youtube_results
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        channel = Prompt.ask("[bold cyan]Channel handle, ID, or URL[/bold cyan]").strip()
        if not channel:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = youtube_recon(channel, youtube_v2_key=os.getenv("YOUTUBE_V2_KEY"))
        print_youtube_results(data)

        if do_report:
            save_report(channel, {"youtube": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class ContactsModule(OsintModule):
    TITLE = "Website Contacts Scraper"
    DESCRIPTION = "Scrape emails, phone numbers, and social links from a website."
    TAGS = ["contacts", "email", "scrape", "recon"]
    ICON = "📋"
    REQUIRES_ENV = ["WEBSITE_CONTACTS_KEY"]

    def run_interactive(self) -> None:
        import os
        from modules.website_contacts import website_contacts_scrape, print_website_contacts
        from modules.report import save_report
        from config import get_output_dir

        self.show_info()
        url = Prompt.ask("[bold cyan]Website URL or domain[/bold cyan]").strip()
        if not url:
            return
        do_report = Prompt.ask(
            "[dim]Save report? (y/N)[/dim]", default="n"
        ).lower().startswith("y")

        data = website_contacts_scrape(url, api_key=os.getenv("WEBSITE_CONTACTS_KEY"))
        print_website_contacts(data)

        if do_report:
            save_report(url, {"website_contacts": data}, str(get_output_dir()))
            console.print(f"[{THEME_SUCCESS}]✔ Report saved.[/{THEME_SUCCESS}]")


class DorksModule(OsintModule):
    TITLE = "Google Dorks Generator"
    DESCRIPTION = "Generate targeted Google dorks for domains, emails, persons and organizations."
    TAGS = ["dorks", "google", "osint", "recon"]
    ICON = "🔎"

    def run_interactive(self) -> None:
        from modules.google_dorks import generate_dorks, print_dorks

        self.show_info()
        console.print("[dim]Loại target:[/dim]")
        console.print("  [cyan]1[/cyan] Domain  [cyan]2[/cyan] Email  [cyan]3[/cyan] Person")
        choice = Prompt.ask("[bold cyan]Chọn[/bold cyan]", default="1")
        kind_map = {"1": "domain", "2": "email", "3": "person"}
        kind = kind_map.get(choice, "domain")

        target = Prompt.ask(f"[bold cyan]{kind.capitalize()}[/bold cyan]").strip()
        if not target:
            return

        print_dorks(target, kind)


# ── Registry of all modules (ordered for menu display) ────────────────────────

ALL_MODULES: list[OsintModule] = [
    DomainModule(),
    EmailModule(),
    UsernameModule(),
    PhoneModule(),
    IPModule(),
    SSLModule(),
    InstagramModule(),
    SocialModule(),
    BreachModule(),
    SecretsModule(),
    CloudModule(),
    CertModule(),
    ImageModule(),
    YoutubeModule(),
    ContactsModule(),
    DorksModule(),
]
