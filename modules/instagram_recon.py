"""
Instagram Recon Module
Public-only OSINT for Instagram profiles.

Features:
- Profile info lookup (instaloader optional + HTML/meta fallback)
- Engagement rate analysis
- Shadowban heuristic (hashtag-presence check)
- Hashtag OSINT (visibility + search links)
- Cross-platform link extraction from bio
- Username suspicion/bot score
"""
import re
import time
from datetime import datetime
from urllib.parse import quote_plus

import requests
from rich.console import Console
from rich.table import Table

console = Console()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

try:
    import instaloader as _il_mod
    _IL = True
except ImportError:
    _il_mod = None
    _IL = False

# Cross-platform link patterns for bio extraction
_SOCIAL_LINK_PATTERNS = [
    ("Twitter/X",  re.compile(r'(?:twitter|x)\.com/([A-Za-z0-9_]{1,20})(?:[/?]|$|\s)', re.I)),
    ("YouTube",    re.compile(r'youtube\.com/(?:c/|channel/|@)([A-Za-z0-9_.\-]{1,60})', re.I)),
    ("TikTok",     re.compile(r'tiktok\.com/@([A-Za-z0-9_.]{2,30})', re.I)),
    ("LinkedIn",   re.compile(r'linkedin\.com/(?:in|company)/([A-Za-z0-9_\-]{1,60})', re.I)),
    ("Telegram",   re.compile(r't(?:elegram)?\.me/([A-Za-z0-9_]{3,32})', re.I)),
    ("Facebook",   re.compile(r'facebook\.com/([A-Za-z0-9_.]{1,60})(?:[/?]|$|\s)', re.I)),
    ("Zalo",       re.compile(r'zalo\.me/([A-Za-z0-9_\-]{3,30})', re.I)),
]

_TOXIC_WORDS = ["spam", "scam", "nsfw", "hack", "crack", "phish", "terror", "bomb"]


def _safe_get(url: str, timeout: int = 12) -> requests.Response | None:
    try:
        return requests.get(url, headers=HEADERS, timeout=timeout)
    except Exception:
        return None


def _parse_og_meta(html: str) -> dict:
    """Extract Open Graph meta tags from raw HTML."""
    out = {}
    for prop in ("title", "description", "image"):
        m = re.search(
            rf'<meta\s+property=["\']og:{prop}["\']\s+content=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        )
        if not m:
            m = re.search(
                rf'<meta\s+content=["\']([^"\']*)["\'][^>]+property=["\']og:{prop}["\']',
                html, re.IGNORECASE,
            )
        if m:
            out[prop] = m.group(1)
    return out


def _extract_links_from_bio(bio: str) -> list[dict]:
    """Return cross-platform profile handles found in an Instagram bio."""
    links = []
    for platform, pat in _SOCIAL_LINK_PATTERNS:
        for m in pat.finditer(bio):
            handle = m.group(1).rstrip("/")
            if handle not in ("", "reel", "p", "tv", "stories"):
                links.append({"platform": platform, "handle": handle})
    return links


def score_username(username: str) -> dict:
    """
    Heuristic suspicion score for a username.
    Returns score (int), level (low/medium/high), and reasons list.
    """
    score = 0
    reasons = []

    digit_count = sum(c.isdigit() for c in username)
    if digit_count >= 4:
        score += 2
        reasons.append(f"{digit_count} digits in name")
    elif digit_count >= 2:
        score += 1
        reasons.append(f"{digit_count} digits in name")

    if len(username) <= 4:
        score += 1
        reasons.append("very short (<= 4 chars)")

    if re.search(r'\d{4,}$', username):
        score += 1
        reasons.append("ends with 4+ digits")

    if re.match(r'^[a-z]{2,8}\d{4,}$', username, re.I):
        score += 1
        reasons.append("word+numbers pattern")

    if re.search(r'_{2,}', username):
        score += 1
        reasons.append("multiple consecutive underscores")

    level = "high" if score >= 4 else "medium" if score >= 2 else "low"
    return {"score": score, "level": level, "reasons": reasons}


# ──────────────────────────────────────────────
# Core functions
# ──────────────────────────────────────────────

def fetch_instagram_profile(username: str) -> dict:
    """
    Fetch public Instagram profile info.
    Tries instaloader first (richer data), falls back to HTML/OG-meta tags.
    """
    out: dict = {
        "username": username,
        "fetched": False,
        "timestamp": datetime.utcnow().isoformat(),
        "data_sources": [],
    }

    if _IL and _il_mod:
        try:
            L = _il_mod.Instaloader(
                download_pictures=False,
                download_videos=False,
                save_metadata=False,
                quiet=True,
            )
            profile = _il_mod.Profile.from_username(L.context, username)
            out.update({
                "full_name": profile.full_name,
                "bio": profile.biography,
                "external_url": profile.external_url,
                "followers": profile.followers,
                "following": profile.followees,
                "media_count": profile.mediacount,
                "is_private": profile.is_private,
                "is_verified": profile.is_verified,
                "profile_pic_url": profile.profile_pic_url,
                "fetched": True,
            })
            out["data_sources"].append("instaloader")
            if profile.biography:
                out["cross_platform_links"] = _extract_links_from_bio(profile.biography)
            return out
        except Exception as e:
            out["instaloader_error"] = str(e)

    # HTML / OG-meta fallback
    url = f"https://www.instagram.com/{username}/"
    r = _safe_get(url)
    if not r:
        out["error"] = "no_response"
        return out

    out["http_status"] = r.status_code
    if r.status_code != 200:
        out["error"] = f"http_{r.status_code}"
        return out

    html = r.text
    meta = _parse_og_meta(html)

    if meta.get("title"):
        # "Full Name (@username) • Instagram photos and videos"
        m = re.match(r'^(.+?)\s*\(@?[^)]+\)', meta["title"])
        out["full_name"] = m.group(1).strip() if m else meta["title"]

    if meta.get("description"):
        desc = meta["description"]
        out["bio_raw"] = desc
        # Parse counts embedded in og:description
        for pattern, key in [
            (r'([\d,.KkMmTt]+)\s*Followers?', "followers_str"),
            (r'([\d,.KkMmTt]+)\s*Following', "following_str"),
            (r'([\d,.KkMmTt]+)\s*Posts?', "media_count_str"),
        ]:
            m2 = re.search(pattern, desc, re.I)
            if m2:
                out[key] = m2.group(1)

    if meta.get("image"):
        out["profile_pic_url"] = meta["image"]

    out["fetched"] = bool(meta)
    out["data_sources"].append("HTML/OG-meta fallback")
    return out


def hashtag_osint(tag: str) -> dict:
    """OSINT on an Instagram hashtag — check visibility and produce search links."""
    tag = tag.lstrip("#").strip()
    ig_url = f"https://www.instagram.com/explore/tags/{quote_plus(tag)}/"
    r = _safe_get(ig_url)

    result = {
        "hashtag": f"#{tag}",
        "instagram_url": ig_url,
        "ig_status": r.status_code if r else None,
        "ig_accessible": r is not None and r.status_code == 200,
        "search_links": {
            "Google":        f"https://www.google.com/search?q=%23{quote_plus(tag)}",
            "Bing":          f"https://www.bing.com/search?q=%23{quote_plus(tag)}",
            "Twitter/X":     f"https://twitter.com/search?q={quote_plus('#' + tag)}",
            "TikTok":        f"https://www.tiktok.com/tag/{quote_plus(tag)}",
            "Google Trends": f"https://trends.google.com/trends/explore?q=%23{quote_plus(tag)}",
        },
        "toxicity_flags": [w for w in _TOXIC_WORDS if w in tag.lower()],
    }

    if r and r.status_code == 200:
        m = re.search(r'([\d,]+)\s*(?:posts?|bài đăng)', r.text, re.I)
        if m:
            result["estimated_posts"] = m.group(1)

    return result


def shadowban_heuristic(username: str, sample_posts: int = 3) -> dict:
    """
    Heuristic shadowban check: verify whether recent posts appear in their hashtag feeds.
    Requires instaloader (public profiles only).
    """
    if not _IL or not _il_mod:
        return {
            "error": "instaloader_not_installed",
            "note": "pip install instaloader",
        }

    try:
        L = _il_mod.Instaloader(quiet=True)
        profile = _il_mod.Profile.from_username(L.context, username)

        if profile.is_private:
            return {"error": "profile_private"}

        posts_checked = []
        for i, post in enumerate(profile.get_posts()):
            if i >= sample_posts:
                break
            shortcode = post.shortcode
            tags = list(post.caption_hashtags)[:5] if hasattr(post, "caption_hashtags") else []
            tag_results = {}
            for tag in tags:
                r = _safe_get(f"https://www.instagram.com/explore/tags/{tag}/")
                tag_results[tag] = (shortcode in r.text) if r and r.status_code == 200 else None
                time.sleep(0.5)
            posts_checked.append({
                "shortcode": shortcode,
                "date": post.date_utc.strftime("%Y-%m-%d"),
                "hashtags_checked": tag_results,
            })

        if not posts_checked:
            return {"error": "no_posts_found"}

        neg = sum(1 for p in posts_checked for v in p["hashtags_checked"].values() if v is False)
        total = sum(len(p["hashtags_checked"]) for p in posts_checked)
        score = (neg / total) if total else 0.0

        if score > 0.6:
            verdict = "Strong shadowban signals"
        elif score > 0.25:
            verdict = "Some shadowban signals"
        else:
            verdict = "No strong shadowban signs"

        return {
            "posts_checked": posts_checked,
            "missing_from_hashtags": neg,
            "total_hashtag_checks": total,
            "shadowban_score": round(score, 3),
            "verdict": verdict,
        }
    except Exception as e:
        return {"error": str(e)}


def estimate_engagement_rate(username: str, sample_posts: int = 12) -> dict:
    """
    Estimate engagement rate from public posts.
    Requires instaloader (public profiles only).
    """
    if not _IL or not _il_mod:
        return {
            "error": "instaloader_not_installed",
            "note": "pip install instaloader",
        }

    try:
        L = _il_mod.Instaloader(quiet=True)
        profile = _il_mod.Profile.from_username(L.context, username)

        if profile.is_private:
            return {"error": "profile_private"}

        followers = profile.followers
        likes_list: list[int] = []
        comments_list: list[int] = []

        for i, post in enumerate(profile.get_posts()):
            if i >= sample_posts:
                break
            try:
                likes_list.append(post.likes)
                comments_list.append(post.comments)
            except Exception:
                pass

        if not likes_list:
            return {"error": "no_posts"}

        avg_likes = sum(likes_list) / len(likes_list)
        avg_comments = sum(comments_list) / len(comments_list) if comments_list else 0.0
        rate = ((avg_likes + avg_comments) / followers * 100) if followers else 0.0

        if rate > 6:
            benchmark = "Excellent (>6%)"
        elif rate > 3:
            benchmark = "Good (3–6%)"
        elif rate > 1:
            benchmark = "Average (1–3%)"
        else:
            benchmark = "Low (<1%)"

        return {
            "followers": followers,
            "posts_sampled": len(likes_list),
            "avg_likes": round(avg_likes, 1),
            "avg_comments": round(avg_comments, 1),
            "engagement_rate_pct": round(rate, 3),
            "benchmark": benchmark,
        }
    except Exception as e:
        return {"error": str(e)}


def instagram_recon(
    username: str,
    do_shadowban: bool = False,
    do_engagement: bool = False,
    hashtag: str | None = None,
) -> dict:
    """Main Instagram recon entry point."""
    result: dict = {
        "target": username,
        "profile": fetch_instagram_profile(username),
        "username_score": score_username(username),
    }

    if do_engagement:
        result["engagement"] = estimate_engagement_rate(username)

    if do_shadowban:
        result["shadowban"] = shadowban_heuristic(username)

    if hashtag:
        result["hashtag"] = hashtag_osint(hashtag)

    return result


# ──────────────────────────────────────────────
# Rich display
# ──────────────────────────────────────────────

def print_instagram_results(data: dict) -> None:
    target = data.get("target", "")
    console.print(f"\n[bold magenta]═══ INSTAGRAM RECON: @{target} ═══[/bold magenta]")

    profile = data.get("profile", {})
    if profile.get("error"):
        console.print(f"  [red]✗ {profile['error']}[/red]")
        if profile.get("instaloader_error"):
            console.print(f"  [dim]Instaloader: {profile['instaloader_error']}[/dim]")
    else:
        if profile.get("full_name"):
            console.print(f"  Full Name     : [cyan]{profile['full_name']}[/cyan]")

        if profile.get("is_verified"):
            console.print("  Verified      : [green]✓ Verified[/green]")

        private = profile.get("is_private")
        if private is not None:
            label = "[yellow]Private[/yellow]" if private else "[green]Public[/green]"
            console.print(f"  Account Type  : {label}")

        # Followers / Following / Posts
        fol = profile.get("followers") or profile.get("followers_str")
        fwg = profile.get("following") or profile.get("following_str")
        med = profile.get("media_count") or profile.get("media_count_str")
        approx = " (approx)" if profile.get("followers_str") else ""
        if fol is not None:
            console.print(f"  Followers     : [green]{fol:,}[/green]{approx}" if isinstance(fol, int) else f"  Followers     : [green]{fol}[/green]{approx}")
        if fwg is not None:
            console.print(f"  Following     : {fwg:,}" if isinstance(fwg, int) else f"  Following     : {fwg}")
        if med is not None:
            console.print(f"  Posts         : {med:,}" if isinstance(med, int) else f"  Posts         : {med}")

        if profile.get("bio"):
            console.print(f"  Bio           : [dim]{profile['bio'][:200]}[/dim]")

        if profile.get("external_url"):
            console.print(f"  Website       : [link]{profile['external_url']}[/link]")

        if profile.get("profile_pic_url"):
            console.print(f"  Profile Pic   : [link]{profile['profile_pic_url']}[/link]")

        links = profile.get("cross_platform_links", [])
        if links:
            console.print("\n  [bold]Cross-Platform Links Found in Bio:[/bold]")
            for link in links:
                console.print(f"    {link['platform']:12}: @{link['handle']}")

        sources = profile.get("data_sources", [])
        if sources:
            console.print(f"\n  [dim]Data sources: {', '.join(sources)}[/dim]")

    # Username suspicion score
    sc = data.get("username_score", {})
    if sc:
        level = sc.get("level", "low")
        color = {"high": "red", "medium": "yellow", "low": "green"}.get(level, "white")
        console.print(f"\n  Username Risk : [{color}]{level.upper()}[/{color}] (score: {sc.get('score', 0)})")
        for reason in sc.get("reasons", []):
            console.print(f"    [dim]• {reason}[/dim]")

    # Engagement
    eng = data.get("engagement", {})
    if eng:
        if eng.get("error"):
            console.print(f"\n  [dim]Engagement: {eng['error']}[/dim]")
        else:
            console.print("\n  [bold]Engagement Rate:[/bold]")
            rate = eng.get("engagement_rate_pct", 0)
            rate_color = "green" if rate > 3 else "yellow" if rate > 1 else "red"
            console.print(f"    Rate      : [{rate_color}]{rate}%[/{rate_color}]  → {eng.get('benchmark', '')}")
            console.print(f"    Avg Likes : {eng.get('avg_likes', 0):,.0f}")
            console.print(f"    Avg Comms : {eng.get('avg_comments', 0):,.0f}")
            console.print(f"    Sampled   : {eng.get('posts_sampled', 0)} posts / {eng.get('followers', 0):,} followers")

    # Shadowban
    sb = data.get("shadowban", {})
    if sb:
        if sb.get("error"):
            console.print(f"\n  [dim]Shadowban: {sb['error']}[/dim]")
        else:
            verdict = sb.get("verdict", "")
            sb_color = "red" if "Strong" in verdict else "yellow" if "Some" in verdict else "green"
            console.print(f"\n  [bold]Shadowban:[/bold] [{sb_color}]{verdict}[/{sb_color}]")
            console.print(f"    Score     : {sb.get('shadowban_score', 0)}")
            console.print(f"    Missing   : {sb.get('missing_from_hashtags', 0)}/{sb.get('total_hashtag_checks', 0)} hashtag checks")

    # Hashtag OSINT
    ht = data.get("hashtag", {})
    if ht:
        console.print(f"\n  [bold]Hashtag OSINT:[/bold] {ht.get('hashtag', '')}")
        accessible = ht.get("ig_accessible")
        acc_str = "[green]Accessible[/green]" if accessible else "[red]Blocked / Not found[/red]"
        console.print(f"    Instagram : {acc_str}  (HTTP {ht.get('ig_status', '?')})")
        if ht.get("estimated_posts"):
            console.print(f"    Est. Posts: {ht['estimated_posts']}")
        if ht.get("toxicity_flags"):
            console.print(f"    [red]⚠ Toxicity flags: {', '.join(ht['toxicity_flags'])}[/red]")
        console.print("    Search Links:")
        for name, link in ht.get("search_links", {}).items():
            console.print(f"      {name:16}: [link]{link}[/link]")
