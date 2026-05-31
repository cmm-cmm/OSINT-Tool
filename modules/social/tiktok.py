"""TikTok OSINT module — profile recon via RapidAPI + oEmbed."""
import re
import requests
from rich.console import Console
from modules.social._shared import HEADERS, SUSPICIOUS_USER_RE

console = Console()


def _try_tiktok_tokapi(username: str, api_key: str) -> dict | None:
    """Fetch TikTok profile via TokAPI (tokapi-mobile-version.p.rapidapi.com)."""
    try:
        r = requests.get(
            f"https://tokapi-mobile-version.p.rapidapi.com/v1/user/@{username}",
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "tokapi-mobile-version.p.rapidapi.com",
            },
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            u = d.get("userInfo", {}).get("user", {})
            s = d.get("userInfo", {}).get("stats", {})
            if u or s:
                return {"user": u, "stats": s}
    except Exception:
        pass
    return None


def _try_tiktok_api23(username: str, api_key: str) -> dict | None:
    """Fetch TikTok profile via TikTok API23 (tiktok-api23.p.rapidapi.com)."""
    try:
        r = requests.get(
            "https://tiktok-api23.p.rapidapi.com/api/user/info",
            params={"uniqueId": username},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "tiktok-api23.p.rapidapi.com",
            },
            timeout=12,
        )
        if r.status_code == 200:
            d = r.json()
            u = d.get("userInfo", {}).get("user", {})
            s = d.get("userInfo", {}).get("stats", {})
            if u or s:
                return {"user": u, "stats": s}
    except Exception:
        pass
    return None


def tiktok_recon(
    username: str,
    tokapi_key: str | None = None,
    tiktok_api_key: str | None = None,
) -> dict:
    """
    Gather public OSINT from a TikTok profile.
    Source priority: TokAPI → TikTok API23 → oEmbed (public, no key needed).
    """
    username = username.lstrip("@").strip()
    profile_url = f"https://www.tiktok.com/@{username}"

    result = {
        "username": username,
        "platform": "TikTok",
        "profile_url": profile_url,
        "exists": False,
        "is_public": False,
        "display_name": None,
        "bio": None,
        "profile_pic": None,
        "follower_count": None,
        "following_count": None,
        "likes_count": None,
        "video_count": None,
        "is_verified": False,
        "region": None,
        "data_sources": [],
        "security_notes": [],
        "dorks": [],
    }

    api_data = None
    if tokapi_key:
        api_data = _try_tiktok_tokapi(username, tokapi_key)
        if api_data:
            result["data_sources"].append("TokAPI")

    if not api_data and tiktok_api_key:
        api_data = _try_tiktok_api23(username, tiktok_api_key)
        if api_data:
            result["data_sources"].append("TikTok API23")

    if api_data:
        u = api_data.get("user", {})
        s = api_data.get("stats", {})
        result["exists"] = True
        result["is_public"] = True
        result["display_name"] = u.get("nickname") or None
        result["bio"] = u.get("signature") or None
        result["profile_pic"] = u.get("avatarLarger") or None
        result["is_verified"] = bool(u.get("verified", False))
        result["region"] = u.get("region") or None
        result["follower_count"] = s.get("followerCount")
        result["following_count"] = s.get("followingCount")
        result["likes_count"] = s.get("heartCount")
        result["video_count"] = s.get("videoCount")

    try:
        oembed = requests.get(
            "https://www.tiktok.com/oembed",
            params={"url": profile_url},
            headers=HEADERS,
            timeout=10,
            verify=True,
        )
        if oembed.status_code == 200:
            data = oembed.json()
            result["exists"] = True
            result["is_public"] = True
            if not result["display_name"]:
                result["display_name"] = data.get("author_name")
            if not result["profile_pic"]:
                result["profile_pic"] = data.get("thumbnail_url")
            result["data_sources"].append("oEmbed")
    except Exception:
        pass

    if not result["data_sources"]:
        result["security_notes"].append(
            "No API key configured — only oEmbed used. Add TOKAPI_KEY or TIKTOK_API_KEY to .env for full data."
        )

    if result["exists"]:
        if not result["profile_pic"]:
            result["security_notes"].append("No profile picture detected.")
        if username.isdigit():
            result["security_notes"].append("Numeric-only username — may indicate auto-generated account.")
        if len(username) < 4:
            result["security_notes"].append("Very short username — could be a reserved brand name.")
        if SUSPICIOUS_USER_RE.match(username):
            result["security_notes"].append("Username pattern typical of bot/auto-generated accounts.")
        brand_re = re.compile(r'(facebook|google|apple|tiktok|youtube|shopee|lazada|viettel|vnpay)\d+', re.IGNORECASE)
        if brand_re.search(username):
            result["security_notes"].append("Username contains brand name with digits — possible impersonation.")
    else:
        result["security_notes"].append("TikTok account not found or profile is set to private.")

    q = result["display_name"] or username
    encoded = requests.utils.quote
    result["dorks"] = [
        {"label": "TikTok profile search", "query": f'site:tiktok.com "@{username}"',
         "url": f'https://www.google.com/search?q=site%3Atiktok.com+%22%40{encoded(username)}%22'},
        {"label": "Cross-platform identity", "query": f'"{q}" tiktok OR instagram OR facebook OR youtube',
         "url": f'https://www.google.com/search?q=%22{encoded(q)}%22+tiktok+OR+instagram+OR+facebook'},
    ]
    return result


def print_tiktok_results(data: dict):
    username = data.get("username", "?")
    status_text = (
        "[green]✓ Public[/green]" if data.get("is_public")
        else "[red]✗ Not Found / Private[/red]"
    )
    console.print(f"\n[bold red]═══ TikTok: @{username} ═══[/bold red]")
    console.print(f"  URL      : [cyan]{data.get('profile_url')}[/cyan]")
    console.print(f"  Status   : {status_text}")

    if data.get("display_name"):
        verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
        console.print(f"  Name     : [bold white]{data['display_name']}[/bold white]{verified}")
    if data.get("bio"):
        console.print(f"  Bio      : [dim]{data['bio'][:180]}[/dim]")
    if data.get("region"):
        console.print(f"  Region   : {data['region']}")

    stats = []
    if data.get("follower_count") is not None:
        stats.append(f"[cyan]{data['follower_count']:,}[/cyan] followers" if isinstance(data["follower_count"], int)
                     else f"[cyan]{data['follower_count']}[/cyan] followers")
    if data.get("following_count") is not None:
        stats.append(f"[cyan]{data['following_count']}[/cyan] following")
    if data.get("video_count") is not None:
        stats.append(f"[cyan]{data['video_count']}[/cyan] videos")
    if stats:
        console.print(f"  Stats    : {' | '.join(stats)}")

    if data.get("data_sources"):
        console.print(f"  Sources  : [dim]{', '.join(data['data_sources'])}[/dim]")

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    if data.get("dorks"):
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
