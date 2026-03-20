"""
Email Reconnaissance Module
- HaveIBeenPwned (HIBP) breach check
- Email format validation
- MX record check for domain validity
- Gravatar profile check
- Public search engine lookup links
"""
import re
import hashlib
import requests
import dns.resolver
from rich.console import Console
from rich.table import Table

console = Console()

HEADERS = {
    "User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"
}


def validate_email(email: str) -> bool:
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def check_mx_record(domain: str) -> list:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        answers = resolver.resolve(domain, "MX")
        return [str(r.exchange) for r in answers]
    except Exception:
        return []


def check_hibp(email: str, api_key: str = None) -> dict:
    """
    Check HaveIBeenPwned for breaches.
    Requires a free API key from https://haveibeenpwned.com/API/Key
    """
    result = {"breaches": [], "error": None, "note": None}

    if not api_key:
        result["note"] = (
            "HIBP API key required. Get free key at https://haveibeenpwned.com/API/Key"
        )
        return result

    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {**HEADERS, "hibp-api-key": api_key}
        resp = requests.get(url, headers=headers, timeout=10, params={"truncateResponse": False})
        if resp.status_code == 200:
            result["breaches"] = [
                {
                    "name": b.get("Name"),
                    "date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in resp.json()
            ]
        elif resp.status_code == 404:
            result["breaches"] = []
        else:
            result["error"] = f"HTTP {resp.status_code}"
    except Exception as e:
        result["error"] = str(e)

    return result


def check_gravatar(email: str) -> dict:
    """Check if email has a Gravatar profile (public)."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        resp = requests.get(url, headers=HEADERS, timeout=8)
        if resp.status_code == 200:
            data = resp.json().get("entry", [{}])[0]
            return {
                "found": True,
                "display_name": data.get("displayName"),
                "profile_url": data.get("profileUrl"),
                "about_me": data.get("aboutMe"),
                "location": data.get("currentLocation"),
                "urls": [u.get("value") for u in data.get("urls", [])],
            }
    except Exception:
        pass
    return {"found": False}


def generate_search_links(email: str) -> dict:
    """Generate public search engine dork links for an email."""
    encoded = requests.utils.quote(email)
    return {
        "Google": f"https://www.google.com/search?q=%22{encoded}%22",
        "Bing": f"https://www.bing.com/search?q=%22{encoded}%22",
        "DuckDuckGo": f"https://duckduckgo.com/?q=%22{encoded}%22",
        "GitHub": f"https://github.com/search?q=%22{encoded}%22&type=users",
    }


def email_recon(email: str, hibp_api_key: str = None) -> dict:
    if not validate_email(email):
        return {"error": "Invalid email format"}

    domain = email.split("@")[1]
    return {
        "email": email,
        "domain": domain,
        "valid_format": True,
        "mx_records": check_mx_record(domain),
        "gravatar": check_gravatar(email),
        "hibp": check_hibp(email, hibp_api_key),
        "search_links": generate_search_links(email),
    }


def print_email_results(data: dict):
    if data.get("error"):
        console.print(f"[red]{data['error']}[/red]")
        return

    console.print(f"\n[bold cyan]═══ EMAIL RECON: {data['email']} ═══[/bold cyan]")

    # MX Records
    mx = data.get("mx_records", [])
    status = "[green]Valid (MX found)[/green]" if mx else "[yellow]No MX records[/yellow]"
    console.print(f"  Domain status : {status}")
    if mx:
        console.print(f"  MX Records    : {', '.join(mx[:3])}")

    # Gravatar
    g = data.get("gravatar", {})
    if g.get("found"):
        console.print(f"\n[bold green]  ✓ Gravatar Profile Found[/bold green]")
        if g.get("display_name"):
            console.print(f"    Name     : {g['display_name']}")
        if g.get("location"):
            console.print(f"    Location : {g['location']}")
        if g.get("profile_url"):
            console.print(f"    Profile  : {g['profile_url']}")
    else:
        console.print("  Gravatar      : [dim]Not found[/dim]")

    # HIBP
    hibp = data.get("hibp", {})
    if hibp.get("note"):
        console.print(f"\n  [yellow]HIBP: {hibp['note']}[/yellow]")
    elif hibp.get("error"):
        console.print(f"\n  [red]HIBP Error: {hibp['error']}[/red]")
    elif hibp.get("breaches"):
        console.print(f"\n  [bold red]⚠ Found in {len(hibp['breaches'])} breach(es):[/bold red]")
        table = Table(show_header=True, header_style="bold red")
        table.add_column("Breach", style="red")
        table.add_column("Date")
        table.add_column("Records")
        table.add_column("Data Types")
        for b in hibp["breaches"][:10]:
            table.add_row(
                b["name"],
                str(b["date"]),
                f"{b['pwn_count']:,}",
                ", ".join(b["data_classes"][:4]),
            )
        console.print(table)
    else:
        console.print("  HIBP          : [green]No breaches found[/green]")

    # Search links
    console.print("\n  [bold]Search Links:[/bold]")
    for engine, link in data.get("search_links", {}).items():
        console.print(f"    {engine:12}: [link]{link}[/link]")
