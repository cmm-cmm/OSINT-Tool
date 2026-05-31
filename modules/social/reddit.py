"""Reddit OSINT module — profile recon via public JSON API."""
from datetime import datetime, timezone
from urllib.parse import quote
import requests
from rich.console import Console

console = Console()

REDDIT_HEADERS = {
    "User-Agent": "OSINT-Tool/1.0 (Educational Research; github.com/osint-tool)",
    "Accept": "application/json",
}


def _reddit_dorks(username: str) -> list:
    base = "https://www.google.com/search?q="
    return [
        {"label": "All Reddit activity", "query": f'site:reddit.com u/{username}',
         "url": f"{base}{quote(f'site:reddit.com u/{username}')}"},
        {"label": "Posts & comments", "query": f'site:reddit.com/user/{username}',
         "url": f"{base}{quote(f'site:reddit.com/user/{username}')}"},
    ]


def reddit_recon(username: str) -> dict:
    """Query Reddit's public JSON API for user profile, recent posts and comments. No API key needed."""
    username = username.lstrip("u/").lstrip("@").strip()
    profile_url = f"https://www.reddit.com/user/{username}"
    result = {
        "username": username,
        "profile_url": profile_url,
        "exists": False,
        "is_suspended": False,
        "data_sources": [],
        "security_notes": [],
        "dorks": _reddit_dorks(username),
    }

    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=REDDIT_HEADERS,
            timeout=10,
        )
        if r.status_code == 404:
            result["security_notes"].append("Account not found or deleted")
            return result
        if r.status_code == 200:
            d = r.json().get("data", {})
            result["exists"] = True
            result["data_sources"].append("Reddit JSON API")
            result["name"] = d.get("name")
            result["display_name"] = d.get("subreddit", {}).get("title") or d.get("name")
            result["icon_img"] = d.get("icon_img") or d.get("snoovatar_img") or None
            result["is_employee"] = d.get("is_employee", False)
            result["is_gold"] = d.get("is_gold", False)
            result["is_mod"] = d.get("is_mod", False)
            result["comment_karma"] = d.get("comment_karma", 0)
            result["link_karma"] = d.get("link_karma", 0)
            result["total_karma"] = d.get("total_karma") or (result["comment_karma"] + result["link_karma"])
            created_utc = d.get("created_utc")
            if created_utc:
                result["created_at"] = datetime.fromtimestamp(created_utc, tz=timezone.utc).strftime("%Y-%m-%d")
            subreddit = d.get("subreddit", {})
            result["bio"] = subreddit.get("public_description") or None
            result["is_nsfw"] = subreddit.get("over_18", False)
            result["subscribers"] = subreddit.get("subscribers") or None
            if d.get("is_suspended"):
                result["is_suspended"] = True
                result["security_notes"].append("Account is suspended")
            if result.get("is_nsfw"):
                result["security_notes"].append("Profile is marked NSFW")
            if result.get("is_employee"):
                result["security_notes"].append("Reddit employee account")
        elif r.status_code == 403:
            result["security_notes"].append("Profile is private or suspended (HTTP 403)")
        else:
            result["security_notes"].append(f"Unexpected HTTP {r.status_code} from about endpoint")
    except Exception as e:
        result["security_notes"].append(f"about.json error: {e}")

    if not result["exists"]:
        return result

    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/submitted.json",
            headers=REDDIT_HEADERS,
            params={"limit": 10, "sort": "new"},
            timeout=10,
        )
        if r.status_code == 200:
            children = r.json().get("data", {}).get("children", [])
            posts = []
            subreddits_posted = set()
            for child in children:
                p = child.get("data", {})
                subreddits_posted.add(p.get("subreddit", ""))
                posts.append({
                    "title": p.get("title", "")[:120],
                    "subreddit": p.get("subreddit"),
                    "score": p.get("score", 0),
                    "num_comments": p.get("num_comments", 0),
                    "url": f"https://www.reddit.com{p.get('permalink', '')}",
                    "date": datetime.fromtimestamp(p.get("created_utc", 0), tz=timezone.utc).strftime("%Y-%m-%d") if p.get("created_utc") else None,
                    "is_nsfw": p.get("over_18", False),
                })
            result["recent_posts"] = posts
            result["subreddits_posted"] = sorted(subreddits_posted)
    except Exception as e:
        result["security_notes"].append(f"submitted.json error: {e}")

    return result


def print_reddit_results(data: dict):
    username = data.get("username", "?")
    console.print(f"\n[bold cyan]═══ Reddit: u/{username} ═══[/bold cyan]")
    console.print(f"  URL       : [cyan]{data.get('profile_url')}[/cyan]")

    if data.get("is_suspended"):
        console.print("  Status    : [red]✗ Suspended[/red]")
    elif not data.get("exists"):
        console.print("  Status    : [red]✗ Not Found / Deleted[/red]")
    else:
        console.print("  Status    : [green]✓ Active[/green]")
        if data.get("display_name") and data["display_name"] != username:
            console.print(f"  Display   : [bold white]{data['display_name']}[/bold white]")
        if data.get("created_at"):
            console.print(f"  Joined    : {data['created_at']}")
        if data.get("bio"):
            console.print(f"  Bio       : [dim]{data['bio'][:160]}[/dim]")
        karma_parts = []
        if data.get("comment_karma") is not None:
            karma_parts.append(f"[cyan]{data['comment_karma']:,}[/cyan] comment karma")
        if data.get("link_karma") is not None:
            karma_parts.append(f"[cyan]{data['link_karma']:,}[/cyan] link karma")
        if karma_parts:
            console.print(f"  Karma     : {' | '.join(karma_parts)}")

        posts = data.get("recent_posts", [])
        if posts:
            console.print(f"\n  [bold]Recent Posts ({len(posts)}):[/bold]")
            for p in posts[:5]:
                console.print(f"    r/{p.get('subreddit')} · {p.get('date', '?')} · ↑{p.get('score', 0)} · {p.get('title', '')[:60]}")

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Notes:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")
