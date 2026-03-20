"""
Website Contacts Scraper Module
Extracts emails, phone numbers, and social media links from websites.
API: website-contacts-scraper.p.rapidapi.com
"""
import requests
from rich.console import Console
from rich.table import Table

console = Console()

WEBSITE_CONTACTS_HOST = "website-contacts-scraper.p.rapidapi.com"
SOCIAL_FIELDS = [
    "facebook", "instagram", "tiktok", "twitter",
    "linkedin", "github", "youtube", "pinterest", "snapchat",
]


def website_contacts_scrape(url: str, api_key: str | None = None) -> dict:
    """Scrape emails, phone numbers, and social links from a website URL."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {
        "url": url,
        "domain": None,
        "emails": [],
        "phone_numbers": [],
        "socials": {},
        "data_sources": [],
        "security_notes": [],
        "error": None,
    }

    if not api_key:
        result["error"] = "No API key provided (set WEBSITE_CONTACTS_KEY in .env)"
        return result

    try:
        resp = requests.get(
            f"https://{WEBSITE_CONTACTS_HOST}/scrape-contacts",
            headers={
                "x-rapidapi-host": WEBSITE_CONTACTS_HOST,
                "x-rapidapi-key": api_key,
            },
            params={
                "query": url,
                "match_email_domain": "true",
                "external_links": "1",
            },
            timeout=30,
        )
        resp.raise_for_status()
        raw = resp.json()
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
        return result
    except requests.exceptions.HTTPError as e:
        result["error"] = f"HTTP {e.response.status_code}: {e.response.text[:200]}"
        return result
    except Exception as e:
        result["error"] = f"Request failed: {e}"
        return result

    data_list = raw.get("data") or []
    if not data_list:
        result["error"] = "No data returned from API"
        return result

    data = data_list[0]
    result["domain"] = data.get("domain") or url
    result["emails"] = data.get("emails") or []
    result["phone_numbers"] = data.get("phone_numbers") or []
    result["data_sources"].append(WEBSITE_CONTACTS_HOST)

    for field in SOCIAL_FIELDS:
        val = data.get(field)
        if val:
            result["socials"][field] = val

    # Security observations
    role_prefixes = (
        "info@", "admin@", "support@", "noreply@",
        "no-reply@", "webmaster@", "postmaster@",
    )
    role_emails = [
        e["value"] for e in result["emails"]
        if e.get("value", "").lower().startswith(role_prefixes)
    ]
    if role_emails:
        result["security_notes"].append(
            f"Role-based emails found: {', '.join(role_emails[:3])}"
        )
    if len(result["emails"]) > 20:
        result["security_notes"].append(
            f"Large email footprint: {len(result['emails'])} addresses discovered"
        )

    return result


def print_website_contacts(data: dict):
    """Display website contacts results using Rich."""
    domain = data.get("domain") or data.get("url", "Unknown")
    console.print(f"\n[bold cyan]Website Contacts:[/bold cyan] [green]{domain}[/green]\n")

    if data.get("error"):
        console.print(f"[red]✗ {data['error']}[/red]")
        return

    emails = data.get("emails", [])
    phones = data.get("phone_numbers", [])
    socials = data.get("socials", {})

    # ── Emails ──────────────────────────────────────────────
    if emails:
        tbl = Table(
            title=f"[bold]Emails Found ({len(emails)})[/bold]",
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("Email Address", style="cyan")
        tbl.add_column("Source", style="dim", max_width=70)
        for entry in emails[:50]:
            val = entry.get("value", "")
            sources = entry.get("sources") or []
            tbl.add_row(val, sources[0] if sources else "")
        console.print(tbl)
        if len(emails) > 50:
            console.print(f"[dim]  ... and {len(emails) - 50} more (see full report)[/dim]")
    else:
        console.print("[dim]No emails found.[/dim]")

    # ── Phone numbers ────────────────────────────────────────
    if phones:
        tbl = Table(
            title=f"[bold]Phone Numbers Found ({len(phones)})[/bold]",
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("Phone Number", style="cyan")
        tbl.add_column("Source", style="dim", max_width=70)
        for entry in phones:
            val = entry.get("value", "")
            sources = entry.get("sources") or []
            tbl.add_row(val, sources[0] if sources else "")
        console.print(tbl)
    else:
        console.print("[dim]No phone numbers found.[/dim]")

    # ── Social links ─────────────────────────────────────────
    if socials:
        tbl = Table(
            title="[bold]Social Media Links[/bold]",
            show_header=True,
            header_style="bold magenta",
        )
        tbl.add_column("Platform", style="bold", width=14)
        tbl.add_column("URL", style="cyan")
        for platform, link_url in socials.items():
            tbl.add_row(platform.capitalize(), link_url)
        console.print(tbl)
    else:
        console.print("[dim]No social media links found.[/dim]")

    # ── Security notes ───────────────────────────────────────
    if data.get("security_notes"):
        console.print("\n[bold yellow]Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"  [yellow]⚠ {note}[/yellow]")
