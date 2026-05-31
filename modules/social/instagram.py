"""Instagram OSINT module (social context — RapidAPI scraper)."""
import requests
from rich.console import Console

console = Console()


def _generate_ig_dorks(username: str) -> list:
    encoded = requests.utils.quote(username)
    return [
        {"label": "Instagram profile", "query": f'site:instagram.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Ainstagram.com+%22{encoded}%22"},
        {"label": "Cached / indexed posts", "query": f'instagram.com/{username}',
         "url": f"https://www.google.com/search?q=instagram.com%2F{encoded}"},
        {"label": "Mentioned elsewhere", "query": f'"{username}" instagram',
         "url": f"https://www.google.com/search?q=%22{encoded}%22+instagram"},
    ]


def instagram_recon(username: str, api_key: str = None) -> dict:
    """Gather public Instagram profile info via RapidAPI instagram-scraper-api2."""
    username = username.lstrip("@").strip()
    result = {
        "username": username,
        "profile_url": f"https://www.instagram.com/{username}/",
        "is_public": False,
        "exists": False,
        "data_sources": [],
        "security_notes": [],
        "dorks": _generate_ig_dorks(username),
    }

    if not api_key:
        result["security_notes"].append("No Instagram API key — add INSTAGRAM_KEY to .env for live lookup")
        return result

    try:
        url = "https://instagram-scraper-api2.p.rapidapi.com/v1/info"
        headers = {
            "x-rapidapi-key": api_key,
            "x-rapidapi-host": "instagram-scraper-api2.p.rapidapi.com",
        }
        resp = requests.get(url, headers=headers, params={"username_or_id_or_url": username}, timeout=15)
        if resp.status_code == 200:
            data = resp.json().get("data", {}) or {}
            result["exists"] = True
            result["is_public"] = not data.get("is_private", True)
            result["data_sources"].append("instagram-scraper-api2")
            result.update({
                "user_id": str(data.get("id") or data.get("pk") or ""),
                "full_name": data.get("full_name"),
                "biography": data.get("biography"),
                "follower_count": data.get("follower_count"),
                "following_count": data.get("following_count"),
                "media_count": data.get("media_count"),
                "is_verified": data.get("is_verified", False),
                "is_private": data.get("is_private", True),
                "profile_pic": data.get("profile_pic_url_hd") or data.get("profile_pic_url"),
                "external_url": data.get("external_url"),
                "category": data.get("category_name"),
                "is_business": data.get("is_business_account", False),
                "public_email": data.get("public_email"),
                "public_phone": data.get("public_phone_number"),
                "city_name": data.get("city_name"),
                "pronouns": data.get("pronouns", []),
            })
            if result["is_verified"]:
                result["security_notes"].append("Verified account — high-value target")
            if not result["is_public"]:
                result["security_notes"].append("Private account — limited public data")
            if result.get("public_email"):
                result["security_notes"].append(f"Public email exposed: {result['public_email']}")
        elif resp.status_code == 404:
            result["security_notes"].append("Instagram account not found or suspended")
        else:
            result["security_notes"].append(f"API returned HTTP {resp.status_code}")
    except Exception as e:
        result["security_notes"].append(f"API error: {e}")

    return result


def print_instagram_results(data: dict):
    username = data.get("username", "?")
    console.print(f"\n[bold magenta]═══ Instagram: @{username} ═══[/bold magenta]")
    console.print(f"  URL       : [cyan]{data.get('profile_url')}[/cyan]")

    if not data.get("exists"):
        console.print("  Status    : [red]✗ Not Found / Account may be private or suspended[/red]")
    else:
        status = "[green]✓ Public[/green]" if data.get("is_public") else "[yellow]⚠ Private[/yellow]"
        console.print(f"  Status    : {status}")

        if data.get("full_name"):
            verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
            console.print(f"  Full Name : [bold white]{data['full_name']}[/bold white]{verified}")
        if data.get("biography"):
            console.print(f"  Bio       : [dim]{data['biography'][:180]}[/dim]")
        if data.get("category"):
            console.print(f"  Category  : {data['category']}")
        if data.get("city_name"):
            console.print(f"  City      : {data['city_name']}")
        if data.get("external_url"):
            console.print(f"  Website   : [cyan]{data['external_url']}[/cyan]")
        if data.get("public_email"):
            console.print(f"  Email     : [yellow]{data['public_email']}[/yellow]")
        if data.get("public_phone"):
            console.print(f"  Phone     : [yellow]{data['public_phone']}[/yellow]")

        stats = []
        if data.get("follower_count") is not None:
            fc = data["follower_count"]
            stats.append(f"[cyan]{fc:,}[/cyan] followers" if isinstance(fc, int) else f"[cyan]{fc}[/cyan] followers")
        if data.get("following_count") is not None:
            fw = data["following_count"]
            stats.append(f"[cyan]{fw:,}[/cyan] following" if isinstance(fw, int) else f"[cyan]{fw}[/cyan] following")
        if data.get("media_count") is not None:
            mc = data["media_count"]
            stats.append(f"[cyan]{mc:,}[/cyan] posts" if isinstance(mc, int) else f"[cyan]{mc}[/cyan] posts")
        if stats:
            console.print(f"  Stats     : {' | '.join(stats)}")

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    if data.get("dorks"):
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
            console.print(f"      [link={d['url']}][blue]Open in Google ↗[/blue][/link]")
