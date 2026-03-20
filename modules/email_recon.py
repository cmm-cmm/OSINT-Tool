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


def check_hunter(domain: str, api_key: str) -> dict:
    """Query Hunter.io for email pattern and known addresses on a domain (25 free req/month)."""
    url = "https://api.hunter.io/v2/domain-search"
    try:
        resp = requests.get(
            url,
            params={"domain": domain, "api_key": api_key, "limit": 10},
            headers=HEADERS,
            timeout=12,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            emails = [
                {
                    "value": e.get("value"),
                    "type": e.get("type"),
                    "confidence": e.get("confidence"),
                    "first_name": e.get("first_name"),
                    "last_name": e.get("last_name"),
                    "position": e.get("position"),
                    "linkedin": e.get("linkedin"),
                }
                for e in d.get("emails", [])[:10]
            ]
            return {
                "success": True,
                "pattern": d.get("pattern"),
                "organization": d.get("organization"),
                "domain": d.get("domain"),
                "webmail": d.get("webmail", False),
                "disposable": d.get("disposable", False),
                "total_emails": d.get("total", 0),
                "emails": emails,
                "twitter": d.get("twitter"),
                "linkedin": d.get("linkedin"),
            }
        elif resp.status_code == 401:
            return {"success": False, "error": "Invalid Hunter.io API key"}
        elif resp.status_code == 429:
            return {"success": False, "error": "Hunter.io rate limit reached (25/month free)"}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_emailrep(email: str, api_key: str = None) -> dict:
    """Query EmailRep.io for email reputation and risk signals (1000 free req/day)."""
    url = f"https://emailrep.io/{email}"
    headers = {**HEADERS}
    if api_key:
        headers["Key"] = api_key
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            d = resp.json()
            attrs = d.get("details", {})
            return {
                "success": True,
                "reputation": d.get("reputation", "none"),
                "suspicious": d.get("suspicious", False),
                "references": d.get("references", 0),
                "blacklisted": attrs.get("blacklisted", False),
                "malicious_activity": attrs.get("malicious_activity", False),
                "credentials_leaked": attrs.get("credentials_leaked", False),
                "data_breach": attrs.get("data_breach", False),
                "spam": attrs.get("spam", False),
                "free_provider": attrs.get("free_provider", False),
                "disposable": attrs.get("disposable", False),
                "profiles": attrs.get("profiles", []),
                "first_seen": attrs.get("first_seen"),
                "last_seen": attrs.get("last_seen"),
                "domain_exists": attrs.get("domain_exists", True),
                "domain_reputation": attrs.get("domain_reputation", "none"),
                "new_domain": attrs.get("new_domain", False),
            }
        elif resp.status_code == 400:
            return {"success": False, "error": "Invalid email address"}
        elif resp.status_code == 429:
            return {"success": False, "error": "EmailRep rate limit reached"}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def generate_search_links(email: str) -> dict:
    """Generate public search engine dork links for an email."""
    encoded = requests.utils.quote(email)
    return {
        "Google": f"https://www.google.com/search?q=%22{encoded}%22",
        "Bing": f"https://www.bing.com/search?q=%22{encoded}%22",
        "DuckDuckGo": f"https://duckduckgo.com/?q=%22{encoded}%22",
        "GitHub": f"https://github.com/search?q=%22{encoded}%22&type=users",
    }


def email_recon(email: str, hibp_api_key: str = None, hunter_key: str = None, emailrep_key: str = None) -> dict:
    if not validate_email(email):
        return {"error": "Invalid email format"}

    domain = email.split("@")[1]
    result = {
        "email": email,
        "domain": domain,
        "valid_format": True,
        "mx_records": check_mx_record(domain),
        "gravatar": check_gravatar(email),
        "hibp": check_hibp(email, hibp_api_key),
        "search_links": generate_search_links(email),
    }

    if hunter_key:
        result["hunter"] = check_hunter(domain, hunter_key)

    if emailrep_key is not None:  # allow empty string → unauthenticated request
        result["emailrep"] = check_emailrep(email, emailrep_key or None)

    return result


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

    # Hunter.io
    hunter = data.get("hunter", {})
    if hunter:
        if hunter.get("success"):
            console.print(f"\n  [bold]Hunter.io:[/bold]")
            if hunter.get("organization"):
                console.print(f"    Organization : {hunter['organization']}")
            if hunter.get("pattern"):
                console.print(f"    Email Pattern: [cyan]{hunter['pattern']}@{hunter.get('domain', '')}[/cyan]")
            total = hunter.get("total_emails", 0)
            console.print(f"    Total Emails : {total}")
            if hunter.get("webmail"):
                console.print(f"    [dim]Webmail provider[/dim]")
            if hunter.get("disposable"):
                console.print(f"    [red]⚠ Disposable domain[/red]")
            for e in hunter.get("emails", [])[:5]:
                name = f"{e.get('first_name','')} {e.get('last_name','')}".strip()
                pos = f" — {e['position']}" if e.get("position") else ""
                conf = f" ({e['confidence']}%)" if e.get("confidence") is not None else ""
                console.print(f"    [green]✓[/green] {e['value']}{conf}  {name}{pos}")
        else:
            console.print(f"\n  [dim]Hunter.io: {hunter.get('error', 'N/A')}[/dim]")

    # EmailRep.io
    emailrep = data.get("emailrep", {})
    if emailrep:
        if emailrep.get("success"):
            rep = emailrep.get("reputation", "none")
            rep_color = {"high": "green", "medium": "yellow", "low": "red", "none": "dim"}.get(rep, "white")
            console.print(f"\n  [bold]EmailRep.io:[/bold] [{rep_color}]{rep} reputation[/{rep_color}]")
            flags = []
            if emailrep.get("suspicious"):   flags.append("[red]suspicious[/red]")
            if emailrep.get("blacklisted"):  flags.append("[red]blacklisted[/red]")
            if emailrep.get("malicious_activity"): flags.append("[red]malicious activity[/red]")
            if emailrep.get("credentials_leaked"): flags.append("[yellow]credentials leaked[/yellow]")
            if emailrep.get("data_breach"):  flags.append("[yellow]data breach[/yellow]")
            if emailrep.get("spam"):         flags.append("[yellow]spam[/yellow]")
            if emailrep.get("disposable"):   flags.append("[yellow]disposable[/yellow]")
            if emailrep.get("free_provider"): flags.append("[dim]free provider[/dim]")
            if flags:
                console.print(f"    Flags    : {' | '.join(flags)}")
            console.print(f"    References : {emailrep.get('references', 0)}")
            if emailrep.get("profiles"):
                console.print(f"    Profiles : {', '.join(emailrep['profiles'][:8])}")
            if emailrep.get("first_seen"):
                console.print(f"    First seen: {emailrep['first_seen']}")
        else:
            console.print(f"\n  [dim]EmailRep.io: {emailrep.get('error', 'N/A')}[/dim]")

    # Search links
    console.print("\n  [bold]Search Links:[/bold]")
    for engine, link in data.get("search_links", {}).items():
        console.print(f"    {engine:12}: [link]{link}[/link]")
