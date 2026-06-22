"""
TikTok OSINT module — comprehensive profile intelligence.

Data sources (priority order):
  1. TokAPI via RapidAPI        — TOKAPI_KEY env var
  2. TikTok API23 via RapidAPI  — TIKTOK_API_KEY env var
  3. TikTok unofficial web API  — no key, uses internal endpoints
  4. HTML scrape (__NEXT_DATA__) — no key, parses Next.js hydration JSON
  5. oEmbed API                 — no key, display name + thumbnail only

Intelligence gathered:
  - Profile metadata: username, display name, bio, verified, region
  - Statistics: followers, following, total likes, video count
  - Engagement metrics: engagement rate, likes-per-video
  - Bio analysis: embedded URLs, cross-platform mentions
  - Recent videos: titles, play counts, like counts, hashtags
  - Account behaviour: posting frequency estimate, content patterns
  - Security analysis: bot indicators, impersonation, anomaly flags
  - OSINT dorks: targeted Google queries for follow-up research
"""
from __future__ import annotations

import json
import os
import re
import time
import logging
from typing import Any
from urllib.parse import quote_plus

import requests

logger = logging.getLogger("osint.tiktok")

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_TIMEOUT = 12

# Rotate through several realistic Chrome UA strings
_USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
]

_BROWSER_HEADERS = {
    "User-Agent": _USER_AGENTS[0],
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.tiktok.com/",
    "Origin": "https://www.tiktok.com",
}

_HTML_HEADERS = {
    "User-Agent": _USER_AGENTS[1],
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}

# Patterns
_SUSPICIOUS_USERNAME_RE = re.compile(r'^[a-z]{2,}[_\d]{4,}$', re.IGNORECASE)
_BOT_SUFFIX_RE = re.compile(r'[_\d]{5,}$')
_BRAND_IMPERSONATION_RE = re.compile(
    r'(tiktok|facebook|instagram|youtube|google|apple|amazon|shopee|lazada|viettel|vnpay|grab)\d+',
    re.IGNORECASE,
)
_URL_RE = re.compile(
    r'https?://[^\s\'"<>()[\]]+|(?:www\.|bit\.ly/|t\.co/|linktr\.ee/)[^\s\'"<>()[\]]+',
    re.IGNORECASE,
)
_CROSS_PLATFORM_RE = re.compile(
    r'(?:ig|insta|instagram|twitter|x\.com|fb|facebook|youtube|yt|reddit|twitch|snapchat|telegram|discord)\s*[:/|@]?\s*([A-Za-z0-9._\-]{2,30})',
    re.IGNORECASE,
)
_HASHTAG_RE = re.compile(r'#([A-Za-z0-9_]+)')
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')


# ── Private: API data sources ─────────────────────────────────────────────────

def _try_tokapi(username: str, api_key: str) -> dict | None:
    """Fetch profile via TokAPI (tokapi-mobile-version.p.rapidapi.com)."""
    try:
        r = requests.get(
            f"https://tokapi-mobile-version.p.rapidapi.com/v1/user/@{username}",
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "tokapi-mobile-version.p.rapidapi.com",
                **_BROWSER_HEADERS,
            },
            timeout=_DEFAULT_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            u = d.get("userInfo", {}).get("user", {})
            s = d.get("userInfo", {}).get("stats", {})
            if u:
                return {"user": u, "stats": s, "source": "TokAPI"}
    except Exception as exc:
        logger.debug("TokAPI failed for %r: %s", username, exc)
    return None


def _try_api23(username: str, api_key: str) -> dict | None:
    """Fetch profile via TikTok API23 (tiktok-api23.p.rapidapi.com)."""
    try:
        r = requests.get(
            "https://tiktok-api23.p.rapidapi.com/api/user/info",
            params={"uniqueId": username},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "tiktok-api23.p.rapidapi.com",
                **_BROWSER_HEADERS,
            },
            timeout=_DEFAULT_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            u = d.get("userInfo", {}).get("user", {})
            s = d.get("userInfo", {}).get("stats", {})
            if u:
                return {"user": u, "stats": s, "source": "TikTok API23"}
    except Exception as exc:
        logger.debug("TikTok API23 failed for %r: %s", username, exc)
    return None


def _try_web_api(username: str) -> dict | None:
    """
    Query TikTok's internal web API endpoint for user detail.
    No API key required — uses public profile endpoint.
    """
    try:
        sess = requests.Session()
        sess.headers.update(_BROWSER_HEADERS)
        # Seed a session cookie by visiting the profile page first
        profile_url = f"https://www.tiktok.com/@{username}"
        head_resp = sess.get(profile_url, headers=_HTML_HEADERS, timeout=_DEFAULT_TIMEOUT, allow_redirects=True)

        # Internal user detail API — used by TikTok's own web app
        api_url = "https://www.tiktok.com/api/user/detail/"
        r = sess.get(
            api_url,
            params={
                "uniqueId": username,
                "secUid": "",
                "msToken": "",
            },
            headers={**_BROWSER_HEADERS, "Referer": profile_url},
            timeout=_DEFAULT_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            u = (d.get("userInfo") or {}).get("user") or {}
            s = (d.get("userInfo") or {}).get("stats") or {}
            if u.get("nickname") or u.get("uniqueId"):
                return {"user": u, "stats": s, "source": "WebAPI", "sec_uid": u.get("secUid", "")}
    except Exception as exc:
        logger.debug("Web API failed for %r: %s", username, exc)
    return None


def _try_nextdata_scrape(username: str) -> dict | None:
    """
    Scrape TikTok profile page and extract __NEXT_DATA__ JSON
    embedded by Next.js SSR — works on public profiles.
    """
    try:
        r = requests.get(
            f"https://www.tiktok.com/@{username}",
            headers={**_HTML_HEADERS, "User-Agent": _USER_AGENTS[2]},
            timeout=_DEFAULT_TIMEOUT,
            allow_redirects=True,
        )
        if r.status_code != 200:
            return None

        # Extract __NEXT_DATA__ JSON blob
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(\{.*?\})</script>', r.text, re.DOTALL)
        if not m:
            # Try SIGI_STATE (newer TikTok web format)
            m2 = re.search(r'<script id="SIGI_STATE"[^>]*>(\{.*?\})</script>', r.text, re.DOTALL)
            if not m2:
                return None
            blob = json.loads(m2.group(1))
            # SIGI_STATE structure
            user_detail = blob.get("UserPage", {}).get("userInfo", {})
        else:
            blob = json.loads(m.group(1))
            # __NEXT_DATA__ → props.pageProps.userInfo
            user_detail = (
                blob.get("props", {})
                .get("pageProps", {})
                .get("userInfo", {})
            )

        u = user_detail.get("user", {})
        s = user_detail.get("stats", {})
        if u.get("nickname") or u.get("uniqueId"):
            return {"user": u, "stats": s, "source": "HTMLScrape", "sec_uid": u.get("secUid", "")}
    except Exception as exc:
        logger.debug("HTML scrape failed for %r: %s", username, exc)
    return None


def _try_oembed(username: str) -> dict | None:
    """Query TikTok oEmbed API — public, no key, minimal data."""
    profile_url = f"https://www.tiktok.com/@{username}"
    try:
        r = requests.get(
            "https://www.tiktok.com/oembed",
            params={"url": profile_url},
            headers=_BROWSER_HEADERS,
            timeout=10,
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("author_name"):
                return {
                    "display_name": d.get("author_name"),
                    "thumbnail_url": d.get("thumbnail_url"),
                    "source": "oEmbed",
                }
    except Exception as exc:
        logger.debug("oEmbed failed for %r: %s", username, exc)
    return None


# ── Private: video list ───────────────────────────────────────────────────────

def _fetch_recent_videos(sec_uid: str, count: int = 12, api_key: str = "") -> list[dict]:
    """
    Fetch recent video metadata for the given secUid.
    Tries RapidAPI first (if api_key provided), falls back to web API.

    Returns list of dicts: {title, play_count, like_count, comment_count,
                             share_count, create_time, hashtags, video_url}
    """
    if not sec_uid:
        return []

    videos: list[dict] = []

    # Try via TokAPI if key provided
    if api_key:
        try:
            r = requests.get(
                "https://tokapi-mobile-version.p.rapidapi.com/v1/post/user",
                params={"secUid": sec_uid, "count": count, "cursor": 0},
                headers={
                    "X-RapidAPI-Key": api_key,
                    "X-RapidAPI-Host": "tokapi-mobile-version.p.rapidapi.com",
                },
                timeout=_DEFAULT_TIMEOUT,
            )
            if r.status_code == 200:
                items = r.json().get("aweme_list") or []
                for item in items[:count]:
                    videos.append(_parse_video_item(item))
                if videos:
                    return videos
        except Exception as exc:
            logger.debug("Video fetch via TokAPI failed: %s", exc)

    # Fallback: unofficial web post list API
    try:
        r = requests.get(
            "https://www.tiktok.com/api/post/item_list/",
            params={
                "secUid": sec_uid,
                "count": count,
                "cursor": 0,
                "aid": 1988,
            },
            headers={**_BROWSER_HEADERS, "Referer": "https://www.tiktok.com/"},
            timeout=_DEFAULT_TIMEOUT,
        )
        if r.status_code == 200:
            items = r.json().get("itemList") or []
            for item in items[:count]:
                videos.append(_parse_video_item(item))
    except Exception as exc:
        logger.debug("Video fetch via web API failed: %s", exc)

    return videos


def _parse_video_item(item: dict) -> dict:
    """Normalise a raw video item dict from any API source."""
    desc = item.get("desc", "")
    stats = item.get("stats", {})
    video = item.get("video", {})
    create_ts = item.get("createTime", 0)
    hashtags = _HASHTAG_RE.findall(desc)
    aweme_id = item.get("id") or item.get("awemeId") or item.get("aweme_id", "")
    video_url = (
        item.get("shareUrl")
        or (f"https://www.tiktok.com/video/{aweme_id}" if aweme_id else "")
    )
    return {
        "title": desc[:120],
        "play_count": stats.get("playCount", 0),
        "like_count": stats.get("diggCount", 0),
        "comment_count": stats.get("commentCount", 0),
        "share_count": stats.get("shareCount", 0),
        "create_time": create_ts,
        "hashtags": hashtags,
        "video_url": video_url,
        "duration_sec": video.get("duration", 0),
    }


# ── Private: analysis helpers ─────────────────────────────────────────────────

def _parse_api_data(api_data: dict) -> dict:
    """Extract standardised fields from any RapidAPI / web-API response."""
    u = api_data.get("user", {})
    s = api_data.get("stats", {})
    return {
        "display_name":    u.get("nickname") or None,
        "bio":             u.get("signature") or None,
        "profile_pic":     u.get("avatarLarger") or u.get("avatarMedium") or None,
        "is_verified":     bool(u.get("verified", False)),
        "region":          u.get("region") or u.get("language") or None,
        "follower_count":  s.get("followerCount"),
        "following_count": s.get("followingCount"),
        "likes_count":     s.get("heartCount") or s.get("diggCount"),
        "video_count":     s.get("videoCount"),
        "sec_uid":         u.get("secUid", "") or api_data.get("sec_uid", ""),
        "user_id":         u.get("id") or u.get("uid") or None,
        "open_favorite":   bool(u.get("openFavorite", False)),
        "private_account": bool(u.get("privateAccount", False)),
        "heart_count":     s.get("heartCount"),
        "friend_count":    s.get("friendCount"),
    }


def _calc_engagement_rate(follower_count: int | None,
                           likes_count: int | None,
                           video_count: int | None) -> float | None:
    """
    Estimate engagement rate as avg_likes_per_video / followers * 100.
    Typical TikTok: 5–20% is normal; >50% may indicate purchased followers.
    """
    if follower_count and likes_count and video_count and video_count > 0 and follower_count > 0:
        avg_likes = likes_count / video_count
        return round(avg_likes / follower_count * 100, 2)
    return None


def _extract_bio_intel(bio: str | None) -> dict:
    """Extract intelligence from the profile bio text."""
    if not bio:
        return {"urls": [], "cross_platform": [], "emails": [], "hashtags": [], "phone_hints": []}

    urls = _URL_RE.findall(bio)
    cross = _CROSS_PLATFORM_RE.findall(bio)
    emails = _EMAIL_RE.findall(bio)
    hashtags = _HASHTAG_RE.findall(bio)
    # Look for phone number hints (any digit cluster of 9+)
    phone_hints = re.findall(r'(?<!\d)\d{9,13}(?!\d)', bio)

    return {
        "urls": list(dict.fromkeys(urls)),
        "cross_platform": list(dict.fromkeys(cross)),
        "emails": list(dict.fromkeys(emails)),
        "hashtags": hashtags,
        "phone_hints": phone_hints,
    }


def _analyse_videos(videos: list[dict]) -> dict:
    """Summarise recent video statistics and content patterns."""
    if not videos:
        return {}

    play_counts = [v["play_count"] for v in videos if v["play_count"]]
    like_counts = [v["like_count"] for v in videos if v["like_count"]]
    comment_counts = [v["comment_count"] for v in videos if v["comment_count"]]
    all_hashtags: list[str] = []
    for v in videos:
        all_hashtags.extend(v.get("hashtags", []))

    # Posting frequency: interval between earliest and latest
    timestamps = sorted([v["create_time"] for v in videos if v["create_time"]])
    posts_per_week: float | None = None
    if len(timestamps) >= 2:
        span_days = (timestamps[-1] - timestamps[0]) / 86400
        if span_days > 0:
            posts_per_week = round(len(timestamps) / (span_days / 7), 1)

    # Hashtag frequency
    hashtag_freq: dict[str, int] = {}
    for tag in all_hashtags:
        hashtag_freq[tag.lower()] = hashtag_freq.get(tag.lower(), 0) + 1
    top_hashtags = sorted(hashtag_freq.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "avg_play_count":    int(sum(play_counts) / len(play_counts)) if play_counts else None,
        "avg_like_count":    int(sum(like_counts) / len(like_counts)) if like_counts else None,
        "avg_comment_count": int(sum(comment_counts) / len(comment_counts)) if comment_counts else None,
        "max_play_count":    max(play_counts) if play_counts else None,
        "posts_per_week":    posts_per_week,
        "top_hashtags":      [{"tag": t, "count": c} for t, c in top_hashtags],
        "total_analysed":    len(videos),
    }


def _build_security_notes(
    username: str,
    result: dict,
    engagement_rate: float | None,
) -> list[str]:
    """Generate security and intelligence observations."""
    notes: list[str] = []

    if not result.get("data_sources"):
        notes.append("No API keys configured — only public sources used (oEmbed/HTML). "
                     "Add TOKAPI_KEY or TIKTOK_API_KEY to .env for full data.")

    if not result.get("exists"):
        notes.append("Account not found or profile is private.")
        return notes

    # Verification / credibility
    if not result.get("profile_pic"):
        notes.append("No profile picture — may be a new, blank, or placeholder account.")

    # Username pattern analysis
    if username.isdigit():
        notes.append("Numeric-only username — unusual; typical of auto-generated accounts.")
    if len(username) < 4:
        notes.append("Very short username (< 4 chars) — may be a reserved or premium handle.")
    if _BOT_SUFFIX_RE.search(username) and len(username) > 8:
        notes.append("Username ends with many digits/underscores — common bot naming pattern.")
    if _SUSPICIOUS_USERNAME_RE.match(username):
        notes.append("Username pattern (short letters + long digit/underscore suffix) typical of bot accounts.")
    if _BRAND_IMPERSONATION_RE.search(username):
        notes.append("Username contains a well-known brand name + digits — possible impersonation.")

    # Private account flag
    if result.get("private_account"):
        notes.append("Account is set to private — limited public data available.")

    # Engagement anomaly
    fc = result.get("follower_count") or 0
    vc = result.get("video_count") or 0
    lc = result.get("likes_count") or 0
    if engagement_rate is not None:
        if engagement_rate > 200:
            notes.append(
                f"Unusually high engagement rate ({engagement_rate}%) — may indicate "
                "purchased followers or engagement pods."
            )
        elif engagement_rate < 0.5 and fc > 10000:
            notes.append(
                f"Very low engagement rate ({engagement_rate}%) for {fc:,} followers — "
                "possible follower purchase or inactive audience."
            )

    # Ghost account: many followers, zero content
    if fc > 5000 and vc == 0:
        notes.append(f"Account has {fc:,} followers but zero videos — may be a purchased/inactive account.")

    # High following relative to followers (follow-unfollow tactic)
    fw = result.get("following_count") or 0
    if fw > 1000 and fc < fw:
        notes.append(
            f"Following ({fw:,}) exceeds followers ({fc:,}) — "
            "possible follow-unfollow growth tactic."
        )

    # Bio intel
    bio_intel = result.get("bio_intel", {})
    if bio_intel.get("emails"):
        notes.append(f"Email address(es) found in bio: {', '.join(bio_intel['emails'])}")
    if bio_intel.get("phone_hints"):
        notes.append(f"Possible phone number(s) in bio: {', '.join(bio_intel['phone_hints'])}")
    if bio_intel.get("urls"):
        notes.append(f"External link(s) in bio: {', '.join(bio_intel['urls'][:3])}")

    return notes


def _build_dorks(username: str, display_name: str | None) -> list[dict]:
    """Generate targeted OSINT dork queries for follow-up research."""
    q = display_name or username
    enc_u = quote_plus(f'"{username}"')
    enc_q = quote_plus(f'"{q}"')

    return [
        {
            "label": "TikTok profile",
            "query": f'site:tiktok.com "@{username}"',
            "url":   f"https://www.google.com/search?q=site%3Atiktok.com+%22%40{quote_plus(username)}%22",
        },
        {
            "label": "Cross-platform identity",
            "query": f'"{q}" tiktok OR instagram OR twitter OR youtube OR facebook',
            "url":   f"https://www.google.com/search?q={enc_q}+tiktok+OR+instagram+OR+twitter",
        },
        {
            "label": "Leaked data / breaches",
            "query": f'"{q}" breach OR leak OR exposed OR pastebin OR database',
            "url":   f"https://www.google.com/search?q={enc_q}+breach+OR+leak+OR+exposed",
        },
        {
            "label": "News & media mentions",
            "query": f'"{q}" tiktok site:vnexpress.net OR site:tuoitre.vn OR site:dantri.vn OR site:bbc.com',
            "url":   f"https://www.google.com/search?q={enc_q}+tiktok+(site%3Avnexpress.net+OR+site%3Abbc.com)",
        },
        {
            "label": "Linked websites / linktree",
            "query": f'"{username}" site:linktr.ee OR site:beacons.ai OR site:bio.link',
            "url":   f"https://www.google.com/search?q={enc_u}+(site%3Alinktr.ee+OR+site%3Abeacons.ai)",
        },
        {
            "label": "Web Archive history",
            "query": f"https://web.archive.org/web/*/tiktok.com/@{username}",
            "url":   f"https://web.archive.org/web/*/tiktok.com/%40{username}",
        },
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def tiktok_recon(
    username: str,
    tokapi_key: str | None = None,
    tiktok_api_key: str | None = None,
    fetch_videos: bool = True,
    max_videos: int = 12,
) -> dict:
    """
    Gather comprehensive OSINT from a public TikTok profile.

    Parameters
    ----------
    username:
        TikTok username (with or without leading @).
    tokapi_key:
        TokAPI RapidAPI key (env: TOKAPI_KEY). Primary source.
    tiktok_api_key:
        TikTok API23 RapidAPI key (env: TIKTOK_API_KEY). Fallback.
    fetch_videos:
        Whether to fetch recent video metadata (requires secUid).
    max_videos:
        Maximum number of recent videos to retrieve.

    Returns
    -------
    dict with keys:
        username, platform, profile_url, exists, is_public,
        display_name, bio, bio_intel, profile_pic, is_verified,
        private_account, region, user_id, sec_uid,
        follower_count, following_count, likes_count, video_count, friend_count,
        engagement_rate, recent_videos, video_analysis,
        data_sources, security_notes, dorks
    """
    username = username.lstrip("@").strip()
    tokapi_key  = tokapi_key  or os.getenv("TOKAPI_KEY", "")
    tiktok_api_key = tiktok_api_key or os.getenv("TIKTOK_API_KEY", "")

    profile_url = f"https://www.tiktok.com/@{username}"

    result: dict[str, Any] = {
        "username":       username,
        "platform":       "TikTok",
        "profile_url":    profile_url,
        "exists":         False,
        "is_public":      False,
        "display_name":   None,
        "bio":            None,
        "bio_intel":      {},
        "profile_pic":    None,
        "is_verified":    False,
        "private_account": False,
        "region":         None,
        "user_id":        None,
        "sec_uid":        "",
        "follower_count":  None,
        "following_count": None,
        "likes_count":     None,
        "video_count":     None,
        "friend_count":    None,
        "engagement_rate": None,
        "recent_videos":   [],
        "video_analysis":  {},
        "data_sources":    [],
        "security_notes":  [],
        "dorks":           [],
    }

    # ── 1. RapidAPI sources ───────────────────────────────────────────────────
    api_data: dict | None = None

    if tokapi_key:
        api_data = _try_tokapi(username, tokapi_key)
        if api_data:
            result["data_sources"].append("TokAPI")

    if not api_data and tiktok_api_key:
        api_data = _try_api23(username, tiktok_api_key)
        if api_data:
            result["data_sources"].append("TikTok API23")

    if api_data:
        parsed = _parse_api_data(api_data)
        result.update({k: v for k, v in parsed.items() if v is not None})
        result["exists"]    = True
        result["is_public"] = not result.get("private_account", False)

    # ── 2. Unofficial web API (no key needed) ─────────────────────────────────
    if not api_data:
        web_data = _try_web_api(username)
        if web_data:
            result["data_sources"].append("WebAPI")
            parsed = _parse_api_data(web_data)
            result.update({k: v for k, v in parsed.items() if v is not None})
            result["exists"]    = True
            result["is_public"] = not result.get("private_account", False)
        else:
            # ── 3. HTML scraping fallback ─────────────────────────────────────
            html_data = _try_nextdata_scrape(username)
            if html_data:
                result["data_sources"].append("HTMLScrape")
                parsed = _parse_api_data(html_data)
                result.update({k: v for k, v in parsed.items() if v is not None})
                result["exists"]    = True
                result["is_public"] = not result.get("private_account", False)

    # ── 4. oEmbed — fill gaps for display_name / profile_pic ─────────────────
    oembed = _try_oembed(username)
    if oembed:
        result["data_sources"].append("oEmbed")
        if not result["exists"]:
            # oEmbed only works for existing public profiles
            result["exists"]    = True
            result["is_public"] = True
        if not result["display_name"]:
            result["display_name"] = oembed.get("display_name")
        if not result["profile_pic"]:
            result["profile_pic"] = oembed.get("thumbnail_url")

    # ── 5. Recent videos ──────────────────────────────────────────────────────
    if fetch_videos and result["exists"] and result.get("sec_uid"):
        videos = _fetch_recent_videos(
            result["sec_uid"],
            count=max_videos,
            api_key=tokapi_key or "",
        )
        result["recent_videos"]  = videos
        result["video_analysis"] = _analyse_videos(videos)

    # ── 6. Bio intelligence ───────────────────────────────────────────────────
    result["bio_intel"] = _extract_bio_intel(result.get("bio"))

    # ── 7. Engagement rate ────────────────────────────────────────────────────
    result["engagement_rate"] = _calc_engagement_rate(
        result.get("follower_count"),
        result.get("likes_count"),
        result.get("video_count"),
    )

    # ── 8. Security analysis ──────────────────────────────────────────────────
    result["security_notes"] = _build_security_notes(username, result, result["engagement_rate"])

    # ── 9. Investigation dorks ────────────────────────────────────────────────
    result["dorks"] = _build_dorks(username, result.get("display_name"))

    return result


# ── Rich console output ───────────────────────────────────────────────────────

def print_tiktok_results(data: dict) -> None:
    """Print TikTok profile intelligence with Rich formatting."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
    except ImportError:
        import json
        print(json.dumps(data, indent=2, default=str))
        return

    console = Console()
    username = data.get("username", "?")

    if data.get("is_public"):
        status = "[bold green]✓ Public[/bold green]"
    elif data.get("exists"):
        status = "[bold yellow]⚠ Private / Restricted[/bold yellow]"
    else:
        status = "[bold red]✗ Not Found / Private[/bold red]"

    # Header panel
    verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
    display  = data.get("display_name") or username
    console.print(Panel(
        f"[bold cyan]@{username}[/bold cyan]{verified}  —  {display}\n{status}\n"
        f"[dim]{data.get('profile_url', '')}[/dim]",
        title="[bold magenta]TikTok OSINT[/bold magenta]",
        border_style="bright_blue",
        box=box.ROUNDED,
    ))

    if not data.get("exists"):
        for note in data.get("security_notes", []):
            console.print(f"  [yellow]⚠  {note}[/yellow]")
        return

    # Profile table
    tbl = Table(box=box.SIMPLE_HEAVY, show_header=False, padding=(0, 1))
    tbl.add_column("Field", style="dim", width=18)
    tbl.add_column("Value")

    def _row(label: str, value: Any) -> None:
        if value is not None and value != "" and value != []:
            tbl.add_row(label, str(value))

    _row("Region",      data.get("region"))
    _row("User ID",     data.get("user_id"))
    _row("Private",     "Yes" if data.get("private_account") else "No")

    # Stats
    fc  = data.get("follower_count")
    fw  = data.get("following_count")
    lc  = data.get("likes_count")
    vc  = data.get("video_count")
    er  = data.get("engagement_rate")

    if fc is not None: tbl.add_row("Followers",  f"[cyan]{fc:,}[/cyan]")
    if fw is not None: tbl.add_row("Following",  f"{fw:,}")
    if lc is not None: tbl.add_row("Total Likes", f"[green]{lc:,}[/green]")
    if vc is not None: tbl.add_row("Videos",     f"{vc:,}")
    if er is not None: tbl.add_row("Engagement%", f"[{'red' if er > 200 or er < 0.5 else 'green'}]{er}%[/]")

    console.print(tbl)

    # Bio
    bio = data.get("bio")
    if bio:
        console.print(f"\n  [bold]Bio:[/bold] {bio[:200]}")

    # Bio intelligence
    bio_intel = data.get("bio_intel", {})
    if bio_intel.get("urls"):
        console.print(f"  [bold]Links:[/bold] " + "  |  ".join(f"[underline bright_blue]{u}[/]" for u in bio_intel["urls"][:4]))
    if bio_intel.get("emails"):
        console.print(f"  [bold]Emails in bio:[/bold] {', '.join(bio_intel['emails'])}")
    if bio_intel.get("cross_platform"):
        console.print(f"  [bold]Cross-platform refs:[/bold] {', '.join(bio_intel['cross_platform'][:6])}")

    # Video analysis
    va = data.get("video_analysis", {})
    if va:
        console.print("\n  [bold cyan]Recent Video Analysis[/bold cyan]")
        if va.get("avg_play_count"):
            console.print(f"    Avg plays/video  : {va['avg_play_count']:,}")
        if va.get("avg_like_count"):
            console.print(f"    Avg likes/video  : {va['avg_like_count']:,}")
        if va.get("max_play_count"):
            console.print(f"    Peak play count  : {va['max_play_count']:,}")
        if va.get("posts_per_week"):
            console.print(f"    Posts / week     : {va['posts_per_week']}")
        if va.get("top_hashtags"):
            tags = "  ".join(f"[cyan]#{t['tag']}[/cyan]({t['count']})" for t in va["top_hashtags"][:8])
            console.print(f"    Top hashtags     : {tags}")

    # Recent videos preview
    videos = data.get("recent_videos", [])
    if videos:
        console.print("\n  [bold cyan]Recent Videos (last {}):[/bold cyan]".format(len(videos)))
        for i, v in enumerate(videos[:5], 1):
            title = (v.get("title") or "")[:60]
            plays = f"{v['play_count']:,}" if v.get("play_count") else "?"
            likes = f"{v['like_count']:,}" if v.get("like_count") else "?"
            console.print(f"    [{i}] {title} | 👁 {plays}  ❤ {likes}")

    # Security notes
    notes = data.get("security_notes", [])
    if notes:
        console.print("\n  [bold yellow]Security Observations:[/bold yellow]")
        for note in notes:
            console.print(f"    [yellow]⚠  {note}[/yellow]")

    # Data sources
    sources = data.get("data_sources", [])
    if sources:
        console.print(f"\n  [dim]Sources: {', '.join(sources)}[/dim]")

    # Dorks
    dorks = data.get("dorks", [])
    if dorks:
        console.print("\n  [bold]Investigation Queries:[/bold]")
        for d in dorks:
            console.print(f"    [dim]{d['label']}:[/dim] [link={d['url']}]{d['query'][:80]}[/link]")
