"""Twitter/X OSINT module — profile recon via Twitter API v2."""
import requests
from rich.console import Console

console = Console()


def _generate_tw_dorks(username: str) -> list:
    encoded = requests.utils.quote(username)
    return [
        {"label": "Twitter profile", "query": f'site:twitter.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Atwitter.com+%22{encoded}%22"},
        {"label": "Mentions / references", "query": f'"@{username}" twitter',
         "url": f"https://www.google.com/search?q=%22%40{encoded}%22+twitter"},
        {"label": "Cached tweets", "query": f'site:x.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Ax.com+%22{encoded}%22"},
    ]


def twitter_recon(username: str, bearer_token: str = None) -> dict:
    """Gather public Twitter/X profile info via Twitter API v2 (free Basic tier)."""
    username = username.lstrip("@").strip()
    result = {
        "username": username,
        "profile_url": f"https://twitter.com/{username}",
        "is_public": False,
        "exists": False,
        "data_sources": [],
        "security_notes": [],
        "dorks": _generate_tw_dorks(username),
    }

    if not bearer_token:
        result["security_notes"].append("No Twitter Bearer Token — add TWITTER_BEARER_TOKEN to .env")
        return result

    try:
        url = f"https://api.twitter.com/2/users/by/username/{username}"
        params = {
            "user.fields": (
                "name,description,public_metrics,profile_image_url,"
                "verified,location,url,created_at,entities,protected"
            )
        }
        headers = {"Authorization": f"Bearer {bearer_token}"}
        resp = requests.get(url, headers=headers, params=params, timeout=12)

        if resp.status_code == 200:
            d = resp.json().get("data", {}) or {}
            metrics = d.get("public_metrics", {})
            result["exists"] = True
            result["is_public"] = not d.get("protected", False)
            result["data_sources"].append("Twitter API v2")
            result.update({
                "user_id": str(d.get("id", "")),
                "name": d.get("name"),
                "description": d.get("description"),
                "follower_count": metrics.get("followers_count"),
                "following_count": metrics.get("following_count"),
                "tweet_count": metrics.get("tweet_count"),
                "listed_count": metrics.get("listed_count"),
                "like_count": metrics.get("like_count"),
                "is_verified": d.get("verified", False),
                "is_protected": d.get("protected", False),
                "location": d.get("location"),
                "url": d.get("url"),
                "created_at": d.get("created_at"),
                "profile_image_url": d.get("profile_image_url"),
            })
            entities = d.get("entities", {})
            urls = entities.get("url", {}).get("urls", [])
            if urls:
                result["expanded_url"] = urls[0].get("expanded_url")
            if result.get("is_verified"):
                result["security_notes"].append("Verified / Blue-check account")
            if result.get("is_protected"):
                result["security_notes"].append("Protected account — tweets are private")
        elif resp.status_code == 401:
            result["security_notes"].append("Invalid or expired Twitter bearer token")
        elif resp.status_code == 404:
            result["security_notes"].append("Twitter account not found")
        elif resp.status_code == 403:
            result["security_notes"].append("Twitter API access forbidden (check app permissions)")
        else:
            result["security_notes"].append(f"API returned HTTP {resp.status_code}")
    except Exception as e:
        result["security_notes"].append(f"API error: {e}")

    return result


def print_twitter_results(data: dict):
    username = data.get("username", "?")
    console.print(f"\n[bold cyan]═══ Twitter/X: @{username} ═══[/bold cyan]")
    console.print(f"  URL       : [cyan]{data.get('profile_url')}[/cyan]")

    if not data.get("exists"):
        console.print("  Status    : [red]✗ Not Found / Account suspended[/red]")
    else:
        status = "[green]✓ Public[/green]" if data.get("is_public") else "[yellow]⚠ Protected[/yellow]"
        console.print(f"  Status    : {status}")

        if data.get("name"):
            verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
            console.print(f"  Name      : [bold white]{data['name']}[/bold white]{verified}")
        if data.get("description"):
            console.print(f"  Bio       : [dim]{data['description'][:180]}[/dim]")
        if data.get("location"):
            console.print(f"  Location  : {data['location']}")
        if data.get("expanded_url") or data.get("url"):
            console.print(f"  Website   : [cyan]{data.get('expanded_url') or data.get('url')}[/cyan]")
        if data.get("created_at"):
            console.print(f"  Joined    : {str(data['created_at'])[:10]}")

        stats = []
        if data.get("follower_count") is not None:
            fc = data["follower_count"]
            stats.append(f"[cyan]{fc:,}[/cyan] followers" if isinstance(fc, int) else f"[cyan]{fc}[/cyan] followers")
        if data.get("following_count") is not None:
            fw = data["following_count"]
            stats.append(f"[cyan]{fw:,}[/cyan] following" if isinstance(fw, int) else f"[cyan]{fw}[/cyan] following")
        if data.get("tweet_count") is not None:
            tc = data["tweet_count"]
            stats.append(f"[cyan]{tc:,}[/cyan] tweets" if isinstance(tc, int) else f"[cyan]{tc}[/cyan] tweets")
        if stats:
            console.print(f"  Stats     : {' | '.join(stats)}")

        if data.get("profile_image_url"):
            console.print(f"  Avatar    : [link={data['profile_image_url']}][cyan]View image ↗[/cyan][/link]")
        if data.get("data_sources"):
            console.print(f"  Data Source: [dim]{', '.join(data['data_sources'])}[/dim]")

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    if data.get("dorks"):
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
            console.print(f"      [link={d['url']}][blue]Open in Google ↗[/blue][/link]")
