"""
YouTube Recon Module
Gathers public OSINT data from YouTube channels.
Uses YouTube V2 RapidAPI (youtube-v2.p.rapidapi.com) for channel details
with YouTube website scraping as fallback for handle resolution.
"""
import re
import requests
from rich.console import Console

console = Console()

_CHANNEL_ID_RE = re.compile(r'"channelId"\s*:\s*"(UC[\w-]{22})"')
_EXTERNAL_ID_RE = re.compile(r'"externalId"\s*:\s*"(UC[\w-]{22})"')


def _resolve_channel_id(query: str) -> str | None:
    """
    Resolve a YouTube handle, URL, or bare username to a channel ID (UC...).
    Returns raw channelId string or None if resolution failed.
    """
    # Already a channel ID
    if re.match(r'^UC[\w-]{22}$', query):
        return query

    # Extract from URL patterns
    url_patterns = [
        r'youtube\.com/channel/(UC[\w-]{22})',
        r'youtube\.com/@([\w.-]+)',
        r'youtube\.com/c/([\w.-]+)',
        r'youtube\.com/user/([\w.-]+)',
    ]
    for pat in url_patterns:
        m = re.search(pat, query, re.IGNORECASE)
        if m:
            extracted = m.group(1)
            if re.match(r'^UC[\w-]{22}$', extracted):
                return extracted
            # It's a handle/username — need to scrape
            query = extracted
            break

    # Strip leading @ if present
    handle = query.lstrip("@").strip()

    # Try to resolve @handle via YouTube page scrape
    for url in [
        f"https://www.youtube.com/@{handle}",
        f"https://www.youtube.com/c/{handle}",
        f"https://www.youtube.com/user/{handle}",
    ]:
        try:
            r = requests.get(
                url,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=12,
                allow_redirects=True,
            )
            if r.status_code == 200:
                html = r.text
                for pattern in (_CHANNEL_ID_RE, _EXTERNAL_ID_RE):
                    m = pattern.search(html)
                    if m:
                        return m.group(1)
        except Exception:
            continue
    return None


def youtube_recon(query: str, youtube_v2_key: str | None = None) -> dict:
    """
    Gather public OSINT from a YouTube channel.

    Args:
        query: Channel handle (@name), channel ID (UC...), or YouTube URL.
        youtube_v2_key: RapidAPI key for youtube-v2.p.rapidapi.com
    """
    # Normalise input
    raw_query = query.strip()
    channel_url = None

    result = {
        "query": raw_query,
        "platform": "YouTube",
        "channel_id": None,
        "channel_url": None,
        "handle": None,
        "exists": False,
        "title": None,
        "description": None,
        "subscriber_count": None,
        "video_count": None,
        "view_count": None,
        "verified": False,
        "country": None,
        "has_business_email": False,
        "avatar": None,
        "banner": None,
        "links": [],
        "data_sources": [],
        "security_notes": [],
        "dorks": [],
    }

    # Step 1 — resolve channel ID
    channel_id = _resolve_channel_id(raw_query)
    if channel_id:
        result["channel_id"] = channel_id
        result["channel_url"] = f"https://www.youtube.com/channel/{channel_id}"
        # Attempt to identify the handle from the query
        m = re.search(r'@([\w.-]+)', raw_query)
        if m:
            result["handle"] = "@" + m.group(1)
        elif not re.match(r'^UC[\w-]{22}$', raw_query) and "youtube.com" not in raw_query.lower():
            result["handle"] = "@" + raw_query.lstrip("@")
    else:
        result["security_notes"].append(
            "Could not resolve channel — verify the handle, URL, or channel ID."
        )

    # Step 2 — fetch channel details via YouTube V2 API
    if channel_id and youtube_v2_key:
        try:
            r = requests.get(
                "https://youtube-v2.p.rapidapi.com/channel/details",
                params={"channel_id": channel_id},
                headers={
                    "X-RapidAPI-Key": youtube_v2_key,
                    "X-RapidAPI-Host": "youtube-v2.p.rapidapi.com",
                },
                timeout=15,
            )
            if r.status_code == 200:
                d = r.json()
                title = d.get("title")
                if title:
                    result["exists"] = True
                    result["title"] = title
                    result["description"] = d.get("description")
                    result["subscriber_count"] = d.get("subscriber_count")
                    result["video_count"] = d.get("video_count")
                    result["view_count"] = d.get("view_count")
                    result["verified"] = bool(d.get("verified", False))
                    result["country"] = d.get("country")
                    result["has_business_email"] = bool(d.get("has_business_email", False))
                    result["data_sources"].append("YouTube V2 API")

                    # Avatar — array of {url, width, height}
                    avatars = d.get("avatar") or []
                    if isinstance(avatars, list) and avatars:
                        best = max(avatars, key=lambda x: x.get("width", 0) if isinstance(x, dict) else 0)
                        result["avatar"] = best.get("url") if isinstance(best, dict) else None

                    # Banner
                    banners = d.get("banner") or []
                    if isinstance(banners, list) and banners:
                        best_b = max(banners, key=lambda x: x.get("width", 0) if isinstance(x, dict) else 0)
                        result["banner"] = best_b.get("url") if isinstance(best_b, dict) else None

                    # Links (social media / website)
                    raw_links = d.get("links") or []
                    result["links"] = [
                        lnk.get("endpoint", str(lnk)) if isinstance(lnk, dict) else str(lnk)
                        for lnk in raw_links if lnk
                    ]

                    # creation_date
                    creation = d.get("creation_date")
                    if creation:
                        result["created"] = str(creation)
                else:
                    result["security_notes"].append(
                        "YouTube V2 API returned no title — channel may be private, deleted, or the ID is invalid."
                    )
        except Exception as e:
            result["security_notes"].append(f"YouTube V2 API error: {e}")

    elif channel_id and not youtube_v2_key:
        result["security_notes"].append(
            "No YOUTUBE_V2_KEY configured — add it to .env or pass --yt-key for full channel data."
        )

    # Step 3 — mark as exists if channel ID was resolved (even without API data)
    if channel_id and not result.get("exists"):
        result["exists"] = True
        if not result["data_sources"]:
            result["data_sources"].append("Channel ID resolved (web scrape)")

    # ── Security observations ─────────────────────────────────────────────
    if result["exists"]:
        if result.get("verified"):
            result["security_notes"].append(
                "Channel has a verified badge — confirmed official identity."
            )
        if result.get("has_business_email"):
            result["security_notes"].append(
                "Channel exposes a business email — can be used for contact/spear-phishing analysis."
            )
        subs_raw = result.get("subscriber_count") or ""
        if subs_raw and re.search(r'\b[0-9]+\s*(?:K|subscribers)', str(subs_raw), re.IGNORECASE):
            result["security_notes"].append(
                "Low subscriber count (< 1K) — channel may be newly created or inactive."
            )
        if result.get("links"):
            result["security_notes"].append(
                f"Channel links out to {len(result['links'])} external URL(s) — cross-reference for broader OSINT."
            )

    # ── Investigation dorks ────────────────────────────────────────────────
    q = result.get("title") or result.get("handle") or raw_query
    q_enc = q.replace(" ", "+").lstrip("@")
    result["dorks"] = [
        {
            "label": "YouTube channel search",
            "query": f'site:youtube.com "{q}"',
            "url": f'https://www.google.com/search?q=site%3Ayoutube.com+%22{q_enc}%22',
        },
        {
            "label": "Cross-platform identity",
            "query": f'"{q}" youtube OR tiktok OR instagram OR facebook',
            "url": f'https://www.google.com/search?q=%22{q_enc}%22+youtube+OR+tiktok+OR+instagram',
        },
        {
            "label": "Contact / email leak",
            "query": f'"{q}" email OR contact OR gmail',
            "url": f'https://www.google.com/search?q=%22{q_enc}%22+email+OR+contact+OR+gmail',
        },
    ]
    return result


def print_youtube_results(data: dict):
    status_text = (
        "[green]✓ Found[/green]" if data["exists"]
        else "[red]✗ Not Found[/red]"
    )
    console.print(f"\n[bold red]═══ YouTube: {data['query']} ═══[/bold red]")
    console.print(f"  Status       : {status_text}")
    if data.get("channel_url"):
        console.print(f"  Channel URL  : [cyan]{data['channel_url']}[/cyan]")
    if data.get("channel_id"):
        console.print(f"  Channel ID   : [dim]{data['channel_id']}[/dim]")
    if data.get("handle"):
        console.print(f"  Handle       : [cyan]{data['handle']}[/cyan]")

    if data.get("title"):
        verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("verified") else ""
        console.print(f"  Channel Name : [bold white]{data['title']}[/bold white]{verified}")
    if data.get("country"):
        console.print(f"  Country      : {data['country']}")

    stats = []
    if data.get("subscriber_count"):
        stats.append(f"[cyan]{data['subscriber_count']}[/cyan]")
    if data.get("video_count"):
        stats.append(f"[cyan]{data['video_count']}[/cyan]")
    if data.get("view_count"):
        stats.append(f"[cyan]{data['view_count']}[/cyan]")
    if stats:
        console.print(f"  Stats        : {' | '.join(stats)}")

    if data.get("has_business_email"):
        console.print("  Business Email: [cyan]Yes (see About page)[/cyan]")
    if data.get("description"):
        desc = data["description"][:200] + ("..." if len(data["description"]) > 200 else "")
        console.print(f"  Description  : [dim]{desc}[/dim]")
    if data.get("links"):
        links_display = []
        for lnk in data["links"][:5]:
            href = lnk if lnk.startswith("http") else f"https://{lnk}"
            links_display.append(f"[link={href}][cyan]{lnk}[/cyan][/link]")
        console.print(f"  Links        : {' | '.join(links_display)}")
    if data.get("avatar"):
        console.print(f"  Avatar       : [link={data['avatar']}][cyan]View ↗[/cyan][/link]")
    if data.get("data_sources"):
        console.print(f"  Data Sources : [dim]{', '.join(data['data_sources'])}[/dim]")

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    if data.get("dorks"):
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
            console.print(f"      [link={d['url']}][blue]Open in Google ↗[/blue][/link]")
