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
    Scrape TikTok profile page and extract embedded JSON data.

    TikTok has used several embedded-data formats over time (newest first):
      1. __UNIVERSAL_DATA_FOR_REHYDRATION__  (2024-2025, current)
      2. SIGI_STATE                           (2023-2024)
      3. __NEXT_DATA__                        (legacy)
    All three are tried in order.
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

        html = r.text

        # ── Format 1: __UNIVERSAL_DATA_FOR_REHYDRATION__ (current 2024-2025) ──
        m1 = re.search(
            r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(\{.*?\})</script>',
            html, re.DOTALL,
        )
        if m1:
            blob = json.loads(m1.group(1))
            # Structure: blob["__DEFAULT_SCOPE__"]["webapp.user-detail"]["userInfo"]
            user_detail = (
                blob.get("__DEFAULT_SCOPE__", {})
                .get("webapp.user-detail", {})
                .get("userInfo", {})
            )
            u = user_detail.get("user", {})
            s = user_detail.get("stats", {})
            if u.get("nickname") or u.get("uniqueId"):
                return {"user": u, "stats": s, "source": "HTMLScrape(URD)", "sec_uid": u.get("secUid", "")}

        # ── Format 2: SIGI_STATE ──────────────────────────────────────────────
        m2 = re.search(r'<script id="SIGI_STATE"[^>]*>(\{.*?\})</script>', html, re.DOTALL)
        if m2:
            blob = json.loads(m2.group(1))
            user_detail = blob.get("UserPage", {}).get("userInfo", {})
            u = user_detail.get("user", {})
            s = user_detail.get("stats", {})
            if u.get("nickname") or u.get("uniqueId"):
                return {"user": u, "stats": s, "source": "HTMLScrape(SIGI)", "sec_uid": u.get("secUid", "")}

        # ── Format 3: __NEXT_DATA__ (legacy) ──────────────────────────────────
        m3 = re.search(r'<script id="__NEXT_DATA__"[^>]*>(\{.*?\})</script>', html, re.DOTALL)
        if m3:
            blob = json.loads(m3.group(1))
            user_detail = (
                blob.get("props", {}).get("pageProps", {}).get("userInfo", {})
            )
            u = user_detail.get("user", {})
            s = user_detail.get("stats", {})
            if u.get("nickname") or u.get("uniqueId"):
                return {"user": u, "stats": s, "source": "HTMLScrape(ND)", "sec_uid": u.get("secUid", "")}

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


# ── Email / phone lookup ─────────────────────────────────────────────────────

def lookup_by_email_or_phone(
    query: str,
    api_key: str = "",
) -> dict:
    """
    Find a TikTok account associated with an email address or phone number.

    Uses the "tiktok-email-phone-lookup" RapidAPI endpoint.
    Returns empty dict if no key or no result.

    Parameters
    ----------
    query:
        Email address (e.g. "user@example.com") or phone number
        in E.164 format (e.g. "+84901234567").
    api_key:
        RapidAPI key. Falls back to TOKAPI_KEY env var.
    """
    api_key = api_key or os.getenv("TOKAPI_KEY", "") or os.getenv("RAPIDAPI_KEY", "")
    if not api_key:
        return {"error": "No RapidAPI key — set TOKAPI_KEY or RAPIDAPI_KEY in .env"}

    is_email = "@" in query
    try:
        endpoint = (
            "https://tiktok-email-phone-lookup.p.rapidapi.com/v1/user/email"
            if is_email else
            "https://tiktok-email-phone-lookup.p.rapidapi.com/v1/user/phone"
        )
        r = requests.get(
            endpoint,
            params={"email": query} if is_email else {"phone": query},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "tiktok-email-phone-lookup.p.rapidapi.com",
            },
            timeout=_DEFAULT_TIMEOUT,
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "found":        bool(d.get("data")),
                "username":     (d.get("data") or {}).get("unique_id"),
                "display_name": (d.get("data") or {}).get("nickname"),
                "user_id":      (d.get("data") or {}).get("uid"),
                "avatar":       (d.get("data") or {}).get("avatar_thumb", {}).get("url_list", [None])[0],
                "country":      (d.get("data") or {}).get("region"),
                "raw":          d.get("data"),
                "source":       "EmailPhoneLookup",
            }
        return {"found": False, "http_status": r.status_code}
    except Exception as exc:
        logger.debug("Email/phone lookup failed for %r: %s", query, exc)
        return {"error": str(exc)}


# ── yt-dlp video metadata ────────────────────────────────────────────────────

def fetch_video_metadata_ytdlp(video_url: str) -> dict:
    """
    Extract rich metadata from a TikTok video URL using yt-dlp.

    Returns metadata including: uploader, upload_date, view_count,
    like_count, comment_count, description, hashtags, duration,
    resolution, vcodec, acodec, device info from User-Agent fields.

    Requires yt-dlp to be installed: pip install yt-dlp
    """
    try:
        import yt_dlp  # type: ignore[import]
    except ImportError:
        return {"error": "yt-dlp not installed. Run: pip install yt-dlp"}

    ydl_opts = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "extract_flat": False,
    }
    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=False)
            if not info:
                return {"error": "No metadata returned"}
            return {
                "video_id":     info.get("id"),
                "uploader":     info.get("uploader"),
                "uploader_id":  info.get("uploader_id"),
                "upload_date":  info.get("upload_date"),
                "title":        info.get("title"),
                "description":  info.get("description", "")[:500],
                "duration_sec": info.get("duration"),
                "view_count":   info.get("view_count"),
                "like_count":   info.get("like_count"),
                "comment_count":info.get("comment_count"),
                "repost_count": info.get("repost_count"),
                "hashtags":     _HASHTAG_RE.findall(info.get("description", "")),
                "resolution":   f"{info.get('width')}x{info.get('height')}" if info.get("width") else None,
                "vcodec":       info.get("vcodec"),
                "acodec":       info.get("acodec"),
                "tbr":          info.get("tbr"),         # total bitrate kbps
                "thumbnail":    info.get("thumbnail"),
                "webpage_url":  info.get("webpage_url"),
                "source":       "yt-dlp",
            }
    except Exception as exc:
        return {"error": str(exc)}


# ── Web Archive CDX ───────────────────────────────────────────────────────────

def check_web_archive(username: str, limit: int = 10) -> dict:
    """
    Query the Internet Archive's CDX API for cached snapshots of
    a TikTok profile page.  Returns snapshot count, earliest/latest
    dates, and direct Wayback Machine links.

    No authentication required — CDX API is free and public.
    API docs: https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server
    """
    url_pattern = f"tiktok.com/@{username}"
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url":        url_pattern,
                "output":     "json",
                "fl":         "timestamp,original,statuscode,digest",
                "collapse":   "digest",
                "limit":      limit,
                "fastLatest": "true",
            },
            timeout=15,
        )
        if r.status_code != 200 or not r.text.strip():
            return {"available": False, "snapshots": 0}

        rows = r.json()
        if not rows or len(rows) <= 1:
            return {"available": False, "snapshots": 0}

        # First row is the header
        headers_row = rows[0]
        data_rows   = rows[1:]

        snapshots = []
        for row in data_rows:
            ts = row[0]  # YYYYMMDDHHmmss
            orig = row[1]
            status = row[2]
            snapshots.append({
                "timestamp": ts,
                "date":      f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}",
                "wayback_url": f"https://web.archive.org/web/{ts}/{orig}",
                "status":    status,
            })

        return {
            "available":    True,
            "snapshots":    len(snapshots),
            "earliest":     snapshots[-1]["date"] if snapshots else None,
            "latest":       snapshots[0]["date"] if snapshots else None,
            "archive_search": f"https://web.archive.org/web/*/{url_pattern}",
            "recent":       snapshots[:5],
        }
    except Exception as exc:
        logger.debug("Web Archive CDX failed for %r: %s", username, exc)
        return {"available": False, "error": str(exc)}


# ── Reverse image search helpers ─────────────────────────────────────────────

def reverse_image_search_links(image_url: str | None, username: str = "") -> list[dict]:
    """
    Generate reverse-image-search links for a TikTok profile picture.

    Returns links to: Google Lens, TinEye, Search4Faces (TikTok-optimised),
    Yandex Images, PimEyes.

    Note: PimEyes and FaceCheck.ID require human interaction;
    the generated links open the upload page.
    """
    if not image_url:
        return []

    from urllib.parse import quote as _q
    enc = _q(image_url, safe="")
    return [
        {
            "engine":  "Google Lens",
            "url":     f"https://lens.google.com/uploadbyurl?url={enc}",
            "note":    "Best for landmark/object recognition; no face ID",
        },
        {
            "engine":  "TinEye",
            "url":     f"https://tineye.com/search?url={enc}",
            "note":    "60B+ image index; shows first appearance date",
        },
        {
            "engine":  "Search4Faces",
            "url":     "https://search4faces.com/",
            "note":    "Specialises in TikTok/VK face search — upload manually",
        },
        {
            "engine":  "Yandex Images",
            "url":     f"https://yandex.com/images/search?rpt=imageview&url={enc}",
            "note":    "Strong face recognition, especially Eastern Europe/Asia",
        },
        {
            "engine":  "PimEyes",
            "url":     "https://pimeyes.com/",
            "note":    "Advanced face search — upload manually; freemium",
        },
        {
            "engine":  "FaceCheck.ID",
            "url":     "https://facecheck.id/",
            "note":    "Face-based OSINT — upload manually",
        },
    ]


# ── Cross-platform OSINT pivot links ─────────────────────────────────────────

def cross_platform_pivot_links(
    username: str,
    display_name: str | None = None,
    bio_emails: list[str] | None = None,
) -> dict:
    """
    Generate direct investigation links for cross-platform OSINT pivoting.

    Includes Holehe (email check), Maigret / Sherlock (username),
    WhatsMyName, IntelX, and breach-check services.
    """
    from urllib.parse import quote_plus as _qp
    q_user = _qp(username)
    q_name = _qp(display_name or username)

    links: dict[str, list[dict]] = {
        "username_search": [
            {
                "tool": "WhatsMyName",
                "url":  f"https://whatsmyname.app/?q={q_user}",
                "note": "600+ platforms",
            },
            {
                "tool": "Instant Username Search",
                "url":  f"https://instantusername.com/#/{q_user}",
                "note": "Quick multi-platform check",
            },
            {
                "tool": "NameCheckr",
                "url":  f"https://www.namecheckr.com/search?name={q_user}",
                "note": "Username + domain availability",
            },
            {
                "tool": "Social Searcher",
                "url":  f"https://www.social-searcher.com/social-buzz/?q5={q_user}",
                "note": "Cross-platform mentions",
            },
        ],
        "breach_lookup": [
            {
                "tool": "HaveIBeenPwned",
                "url":  "https://haveibeenpwned.com/",
                "note": "Email breach check — enter email manually",
            },
            {
                "tool": "LeakCheck",
                "url":  f"https://leakcheck.io/search?query={q_user}",
                "note": "Email/username breach database",
            },
            {
                "tool": "IntelX",
                "url":  f"https://intelx.io/?s={q_user}",
                "note": "Leak data, dark web, paste sites",
            },
        ],
        "profile_search": [
            {
                "tool": "Google — profile pages",
                "url":  f"https://www.google.com/search?q=%22{q_user}%22+site%3Atiktok.com",
            },
            {
                "tool": "Wayback Machine",
                "url":  f"https://web.archive.org/web/*/tiktok.com/%40{q_user}",
                "note": "Historical snapshots",
            },
            {
                "tool": "TikTok Quick Search (OSINT Combine)",
                "url":  f"https://www.osintcombine.com/free-osint-tools/tiktok-quick-search",
                "note": "Multi-field TikTok search",
            },
            {
                "tool": "TTLookup.com",
                "url":  f"https://ttlookup.com/",
                "note": "Free email/username/stats lookup",
            },
        ],
    }

    if bio_emails:
        email_links = []
        for email in bio_emails[:3]:
            eq = _qp(email)
            email_links.append({
                "email": email,
                "hibp":  f"https://haveibeenpwned.com/account/{eq}",
                "intel": f"https://intelx.io/?s={eq}",
            })
        links["email_pivot"] = email_links

    return links


# ── Phone OSINT ───────────────────────────────────────────────────────────────

# Maps lowercase location keywords (hashtags / bio mentions) → readable place name
_LOCATION_KEYWORDS: dict[str, str] = {
    # Vietnam
    "hanoi": "Hanoi, Vietnam", "hanoicity": "Hanoi, Vietnam",
    "hcm": "Ho Chi Minh City, Vietnam", "hcmc": "Ho Chi Minh City, Vietnam",
    "hochiminhcity": "Ho Chi Minh City, Vietnam", "saigon": "Ho Chi Minh City, Vietnam",
    "danang": "Da Nang, Vietnam", "hue": "Hue, Vietnam",
    "cantho": "Can Tho, Vietnam", "haiphong": "Hai Phong, Vietnam",
    "nhatrang": "Nha Trang, Vietnam", "dalat": "Da Lat, Vietnam",
    "vungtau": "Vung Tau, Vietnam", "quangninh": "Quang Ninh, Vietnam",
    "vietnam": "Vietnam", "viet": "Vietnam",
    # Southeast Asia
    "bangkok": "Bangkok, Thailand", "thailand": "Thailand",
    "singapore": "Singapore", "sg": "Singapore",
    "kualalumpur": "Kuala Lumpur, Malaysia", "malaysia": "Malaysia",
    "jakarta": "Jakarta, Indonesia", "bali": "Bali, Indonesia",
    "manila": "Manila, Philippines", "phnom": "Phnom Penh, Cambodia",
    # East Asia
    "tokyo": "Tokyo, Japan", "osaka": "Osaka, Japan", "japan": "Japan",
    "seoul": "Seoul, South Korea", "korea": "South Korea",
    "beijing": "Beijing, China", "shanghai": "Shanghai, China",
    "china": "China", "taiwan": "Taiwan",
    # Other
    "newyork": "New York, USA", "losangeles": "Los Angeles, USA",
    "london": "London, UK", "paris": "Paris, France",
    "sydney": "Sydney, Australia", "dubai": "Dubai, UAE",
}


def analyse_phone_numbers(
    phone_hints: list[str],
    default_region: str = "VN",
) -> list[dict]:
    """
    Validate and enrich phone number strings found in a TikTok bio.

    Uses the `phonenumbers` library (already in requirements.txt) to:
    - Validate the number format
    - Identify country/region
    - Look up carrier/operator name
    - Determine number type (mobile, fixed-line, VoIP …)
    - Infer timezone(s)

    Parameters
    ----------
    phone_hints:
        Raw digit strings extracted from bio (e.g. ["0901234567", "+84123456789"]).
    default_region:
        ISO-3166-1 alpha-2 fallback region when no country code prefix is present.
        Defaults to "VN" (Vietnam).
    """
    if not phone_hints:
        return []

    try:
        import phonenumbers
        from phonenumbers import geocoder, carrier
        from phonenumbers import timezone as pn_tz
        from phonenumbers import PhoneNumberType, number_type
    except ImportError:
        return [{"raw": p, "valid": None, "error": "phonenumbers not installed"} for p in phone_hints]

    _type_labels = {
        PhoneNumberType.MOBILE:              "Mobile",
        PhoneNumberType.FIXED_LINE:          "Fixed line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE:"Fixed/Mobile",
        PhoneNumberType.TOLL_FREE:           "Toll-free",
        PhoneNumberType.PREMIUM_RATE:        "Premium rate",
        PhoneNumberType.VOIP:                "VoIP",
        PhoneNumberType.UNKNOWN:             "Unknown",
    }

    results: list[dict] = []
    for raw in phone_hints:
        entry: dict = {"raw": raw}
        parsed = None

        # Try bare number with default region, then with explicit + prefix
        for attempt in [raw, f"+{raw}"]:
            try:
                p = phonenumbers.parse(attempt, default_region)
                if phonenumbers.is_valid_number(p):
                    parsed = p
                    break
            except Exception:
                pass

        # Last resort: parse without validation
        if parsed is None:
            try:
                parsed = phonenumbers.parse(raw, default_region)
            except Exception:
                entry.update({"valid": False, "error": "Cannot parse"})
                results.append(entry)
                continue

        valid = phonenumbers.is_valid_number(parsed)
        fmt_e164  = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164) if valid else None
        fmt_intl  = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL) if valid else None
        region    = phonenumbers.region_code_for_number(parsed) if valid else None
        location  = geocoder.description_for_number(parsed, "en") if valid else None
        carrier_n = carrier.name_for_number(parsed, "en") if valid else None
        timezones = list(pn_tz.time_zones_for_number(parsed)) if valid else []
        ntype     = _type_labels.get(number_type(parsed), "Unknown") if valid else None

        entry.update({
            "valid":          valid,
            "e164":           fmt_e164,
            "international":  fmt_intl,
            "country_code":   parsed.country_code,
            "national_number": str(parsed.national_number),
            "region":         region,
            "location":       location,
            "carrier":        carrier_n,
            "timezones":      timezones,
            "number_type":    ntype,
        })
        results.append(entry)

    return results


# ── Video Geolocation ─────────────────────────────────────────────────────────

def extract_geolocation_hints(
    videos: list[dict],
    bio: str | None = None,
) -> dict:
    """
    Infer geographic location from available video and bio signals.

    Sources (in priority order):
    1. `locationCreated` metadata from TikTok API (high confidence)
    2. Location hashtags in video descriptions  (#hanoi, #saigon …)
    3. Keyword mentions in video titles and bio  (medium confidence)

    Returns
    -------
    dict with keys:
        primary          — most likely location string (or None)
        confidence       — "high" | "medium" | "low" | "none"
        inferred_locations — ranked list of {location, mention_count}
        api_locations      — list of {location, video_url, confidence}
    """
    location_counts: dict[str, int] = {}
    api_locations: list[dict] = []

    for v in videos:
        # Source 1: API-provided location tag
        loc = (v.get("location_created") or "").strip()
        if loc:
            api_locations.append({
                "location":  loc,
                "video_url": v.get("video_url", ""),
                "confidence": "high",
            })

        # Source 2 & 3: hashtags and title text
        for tag in v.get("hashtags", []):
            key = tag.lower().replace(" ", "").replace("_", "")
            if key in _LOCATION_KEYWORDS:
                place = _LOCATION_KEYWORDS[key]
                location_counts[place] = location_counts.get(place, 0) + 1

        title_l = (v.get("title") or "").lower()
        for kw, place in _LOCATION_KEYWORDS.items():
            if len(kw) > 5 and kw in title_l:
                location_counts[place] = location_counts.get(place, 0) + 1

    # Bio keyword scan
    if bio:
        bio_l = bio.lower()
        for kw, place in _LOCATION_KEYWORDS.items():
            if len(kw) > 4 and kw in bio_l:
                location_counts[place] = location_counts.get(place, 0) + 1

    ranked = sorted(location_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    if api_locations:
        confidence = "high"
        primary = api_locations[0]["location"]
    elif ranked:
        confidence = "medium" if ranked[0][1] >= 2 else "low"
        primary = ranked[0][0]
    else:
        confidence = "none"
        primary = None

    return {
        "primary":             primary,
        "confidence":          confidence,
        "inferred_locations":  [{"location": l, "mention_count": c} for l, c in ranked],
        "api_locations":       api_locations[:10],
    }


# ── HTML Report Export ────────────────────────────────────────────────────────

def export_tiktok_html(data: dict, output_path: str = "") -> str:
    """
    Generate a standalone HTML intelligence report from tiktok_recon() output.

    The report is self-contained (inline CSS, no external dependencies) and
    can be opened offline or shared as a single file.

    Parameters
    ----------
    data:
        Dict returned by tiktok_recon().
    output_path:
        Where to write the HTML file. Defaults to
        ``tiktok_<username>_<timestamp>.html`` in the current directory.

    Returns
    -------
    str — the output file path.
    """
    import html as _html
    from datetime import datetime

    username = data.get("username", "unknown")
    if not output_path:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_path = f"tiktok_{username}_{ts}.html"

    def _e(v: object) -> str:
        return _html.escape(str(v)) if v is not None else ""

    def _fmt(n: int | None) -> str:
        return f"{n:,}" if n is not None else "—"

    # ── profile stats ──────────────────────────────────────────────────────────
    profile_rows = ""
    for label, val in [
        ("Username",    f"@{username}"),
        ("Display Name", data.get("display_name")),
        ("Status",      "Public" if data.get("is_public") else "Private" if data.get("exists") else "Not found"),
        ("Verified",    "Yes" if data.get("is_verified") else "No"),
        ("Region",      data.get("region")),
        ("User ID",     data.get("user_id")),
        ("Followers",   _fmt(data.get("follower_count"))),
        ("Following",   _fmt(data.get("following_count"))),
        ("Total Likes", _fmt(data.get("likes_count"))),
        ("Videos",      _fmt(data.get("video_count"))),
        ("Engagement %", f"{data['engagement_rate']}%" if data.get("engagement_rate") else "—"),
        ("Private Acct", "Yes" if data.get("private_account") else "No"),
    ]:
        if val:
            profile_rows += f"<tr><td class='lbl'>{_e(label)}</td><td>{_e(val)}</td></tr>\n"

    # ── bio ────────────────────────────────────────────────────────────────────
    bio_html = ""
    bio = data.get("bio")
    if bio:
        bio_html = f"<div class='card'><h3>Bio</h3><p class='bio-text'>{_e(bio)}</p>"
        bi = data.get("bio_intel", {})
        if bi.get("urls"):
            links = " ".join(f"<a href='{_e(u)}' target='_blank'>{_e(u[:60])}</a>" for u in bi["urls"][:4])
            bio_html += f"<p><strong>Links:</strong> {links}</p>"
        if bi.get("emails"):
            bio_html += f"<p><strong>Emails:</strong> {_e(', '.join(bi['emails']))}</p>"
        if bi.get("cross_platform"):
            bio_html += f"<p><strong>Cross-platform refs:</strong> {_e(', '.join(bi['cross_platform'][:6]))}</p>"
        if bi.get("phone_hints"):
            bio_html += f"<p><strong>Phone hints:</strong> {_e(', '.join(bi['phone_hints']))}</p>"
        bio_html += "</div>"

    # ── phone OSINT ───────────────────────────────────────────────────────────
    phone_html = ""
    for ph in data.get("phone_osint", []):
        color = "valid" if ph.get("valid") else "invalid"
        phone_html += f"""
        <tr>
          <td>{_e(ph['raw'])}</td>
          <td class='{color}'>{_e(ph.get('e164') or ('Invalid' if not ph.get('valid') else ''))}</td>
          <td>{_e(ph.get('number_type', ''))}</td>
          <td>{_e(ph.get('location', ''))}</td>
          <td>{_e(ph.get('carrier', ''))}</td>
          <td>{_e(', '.join(ph.get('timezones', [])))}</td>
        </tr>"""
    phone_section = ""
    if phone_html:
        phone_section = f"""
        <div class='card'>
          <h3>Phone OSINT</h3>
          <table><thead><tr>
            <th>Raw</th><th>E.164</th><th>Type</th><th>Location</th><th>Carrier</th><th>Timezone</th>
          </tr></thead><tbody>{phone_html}</tbody></table>
        </div>"""

    # ── geolocation ───────────────────────────────────────────────────────────
    geo = data.get("geolocation_hints", {})
    geo_html = ""
    if geo.get("primary"):
        conf_badge = f"<span class='badge {geo['confidence']}'>{_e(geo['confidence'])}</span>"
        geo_html = f"<div class='card'><h3>Geolocation Hints {conf_badge}</h3>"
        geo_html += f"<p><strong>Primary location:</strong> {_e(geo['primary'])}</p>"
        if geo.get("inferred_locations"):
            geo_html += "<ul>"
            for loc in geo["inferred_locations"]:
                geo_html += f"<li>{_e(loc['location'])} — {loc['mention_count']} mention(s)</li>"
            geo_html += "</ul>"
        if geo.get("api_locations"):
            geo_html += "<p><strong>Tagged in videos:</strong></p><ul>"
            for al in geo["api_locations"][:5]:
                url = al.get("video_url", "")
                link = f"<a href='{_e(url)}' target='_blank'>{_e(url[:60])}</a>" if url else ""
                geo_html += f"<li>{_e(al['location'])} {link}</li>"
            geo_html += "</ul>"
        geo_html += "</div>"

    # ── video analysis ────────────────────────────────────────────────────────
    va = data.get("video_analysis", {})
    va_html = ""
    if va:
        va_html = "<div class='card'><h3>Video Analysis</h3><table>"
        for label, key in [
            ("Avg Plays/Video", "avg_play_count"), ("Avg Likes/Video", "avg_like_count"),
            ("Peak Play Count", "max_play_count"), ("Posts/Week", "posts_per_week"),
        ]:
            if va.get(key):
                va_html += f"<tr><td class='lbl'>{label}</td><td>{_fmt(va[key]) if isinstance(va[key], int) else _e(va[key])}</td></tr>"
        va_html += "</table>"
        if va.get("top_hashtags"):
            tags = " ".join(f"<span class='tag'>#{_e(t['tag'])} ({t['count']})</span>" for t in va["top_hashtags"][:10])
            va_html += f"<p><strong>Top hashtags:</strong> {tags}</p>"
        va_html += "</div>"

    # ── recent videos ─────────────────────────────────────────────────────────
    videos_rows = ""
    for v in data.get("recent_videos", [])[:10]:
        url = v.get("video_url", "")
        title = (_e(v.get("title") or ""))[:80]
        loc = f"📍 {_e(v['location_created'])}" if v.get("location_created") else ""
        link = f"<a href='{_e(url)}' target='_blank'>{title}</a>" if url else title
        videos_rows += f"""<tr>
          <td>{link} {loc}</td>
          <td>{_fmt(v.get('play_count'))}</td>
          <td>{_fmt(v.get('like_count'))}</td>
          <td>{_fmt(v.get('comment_count'))}</td>
        </tr>"""
    videos_section = ""
    if videos_rows:
        videos_section = f"""
        <div class='card'>
          <h3>Recent Videos</h3>
          <table><thead><tr><th>Title</th><th>Plays</th><th>Likes</th><th>Comments</th></tr></thead>
          <tbody>{videos_rows}</tbody></table>
        </div>"""

    # ── web archive ───────────────────────────────────────────────────────────
    wa = data.get("web_archive", {})
    wa_html = ""
    if wa.get("available"):
        wa_html = f"""
        <div class='card'>
          <h3>Web Archive</h3>
          <p>Found <strong>{wa['snapshots']}</strong> snapshot(s) —
             earliest: {_e(wa.get('earliest', '?'))}, latest: {_e(wa.get('latest', '?'))}</p>
          <p><a href='{_e(wa.get("archive_search",""))}' target='_blank'>Browse all snapshots</a></p>"""
        if wa.get("recent"):
            wa_html += "<ul>"
            for s in wa["recent"][:5]:
                wa_html += f"<li><a href='{_e(s['wayback_url'])}' target='_blank'>{_e(s['date'])}</a></li>"
            wa_html += "</ul>"
        wa_html += "</div>"

    # ── security notes ────────────────────────────────────────────────────────
    notes = data.get("security_notes", [])
    notes_html = ""
    if notes:
        items = "".join(f"<li>{_e(n)}</li>" for n in notes)
        notes_html = f"<div class='card warn'><h3>Security Observations</h3><ul>{items}</ul></div>"

    # ── pivot links ───────────────────────────────────────────────────────────
    pl = data.get("pivot_links", {})
    pl_html = ""
    if pl:
        pl_html = "<div class='card'><h3>Cross-Platform Pivot Links</h3>"
        for cat, items in pl.items():
            label = cat.replace("_", " ").title()
            pl_html += f"<h4>{_e(label)}</h4><ul>"
            for item in (items if isinstance(items, list) else []):
                tool = _e(item.get("tool") or item.get("email", ""))
                url  = item.get("url") or item.get("hibp") or ""
                note = f" — {_e(item['note'])}" if item.get("note") else ""
                pl_html += f"<li><a href='{_e(url)}' target='_blank'>{tool}</a>{note}</li>"
            pl_html += "</ul>"
        pl_html += "</div>"

    # ── dorks ─────────────────────────────────────────────────────────────────
    dorks = data.get("dorks", [])
    dorks_html = ""
    if dorks:
        rows = "".join(
            f"<tr><td>{_e(d['label'])}</td>"
            f"<td><a href='{_e(d['url'])}' target='_blank'>{_e(d['query'][:80])}</a></td></tr>"
            for d in dorks
        )
        dorks_html = f"<div class='card'><h3>Investigation Dorks</h3><table><tbody>{rows}</tbody></table></div>"

    # ── assemble ──────────────────────────────────────────────────────────────
    avatar = data.get("profile_pic", "")
    avatar_tag = f"<img src='{_e(avatar)}' class='avatar' alt='avatar'>" if avatar else ""
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    sources = _e(", ".join(data.get("data_sources", ["none"])))

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TikTok OSINT — @{_e(username)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d0d0d; color: #e0e0e0;
          line-height: 1.6; padding: 20px; }}
  h1 {{ color: #fe2c55; font-size: 1.8rem; }}
  h2 {{ color: #69c9d0; font-size: 1.2rem; margin-bottom: 4px; }}
  h3 {{ color: #69c9d0; font-size: 1rem; margin-bottom: 10px; border-bottom: 1px solid #333;
        padding-bottom: 4px; }}
  h4 {{ color: #aaa; font-size: 0.9rem; margin: 8px 0 4px; }}
  a {{ color: #69c9d0; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .header {{ display: flex; align-items: center; gap: 20px; margin-bottom: 24px;
             background: #1a1a1a; padding: 20px; border-radius: 12px;
             border-left: 4px solid #fe2c55; }}
  .avatar {{ width: 80px; height: 80px; border-radius: 50%; object-fit: cover;
             border: 3px solid #fe2c55; }}
  .username {{ font-size: 1.4rem; font-weight: bold; color: #fff; }}
  .status-public  {{ color: #4caf50; }}
  .status-private {{ color: #ff9800; }}
  .status-not-found {{ color: #f44336; }}
  .card {{ background: #1a1a1a; border-radius: 10px; padding: 16px;
           margin-bottom: 16px; border: 1px solid #2a2a2a; }}
  .card.warn {{ border-left: 4px solid #ff9800; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
  th {{ background: #252525; color: #aaa; text-align: left; padding: 6px 10px;
        font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid #252525; }}
  td.lbl {{ color: #aaa; width: 160px; white-space: nowrap; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 4px; font-size: 0.9rem; }}
  .tag {{ background: #252560; color: #69c9d0; padding: 2px 8px;
          border-radius: 12px; font-size: 0.8rem; display: inline-block;
          margin: 2px; }}
  .badge {{ padding: 2px 8px; border-radius: 8px; font-size: 0.75rem; font-weight: bold; }}
  .badge.high   {{ background:#1b5e20; color:#a5d6a7; }}
  .badge.medium {{ background:#e65100; color:#ffe0b2; }}
  .badge.low    {{ background:#4a148c; color:#e1bee7; }}
  .bio-text {{ font-style: italic; color: #ccc; margin-bottom: 10px; }}
  .valid   {{ color: #4caf50; }}
  .invalid {{ color: #f44336; }}
  .footer  {{ color: #555; font-size: 0.75rem; margin-top: 24px; text-align: center; }}
  .grid2   {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  @media (max-width: 700px) {{ .grid2 {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="header">
  {avatar_tag}
  <div>
    <div class="username">@{_e(username)}</div>
    <div><em>{_e(data.get('display_name') or '')}</em></div>
    <div class="{'status-public' if data.get('is_public') else 'status-private' if data.get('exists') else 'status-not-found'}">
      {'✓ Public' if data.get('is_public') else '⚠ Private' if data.get('exists') else '✗ Not Found'}
      {'  ✓ Verified' if data.get('is_verified') else ''}
    </div>
    <div style="font-size:0.8rem;color:#555;margin-top:4px">
      Sources: {sources} &nbsp;|&nbsp; Generated: {generated}
    </div>
  </div>
</div>

<div class="grid2">
  <div class="card">
    <h3>Profile</h3>
    <table><tbody>{profile_rows}</tbody></table>
  </div>
  {geo_html if geo_html else '<div></div>'}
</div>

{bio_html}
{phone_section}
{va_html}
{videos_section}
{wa_html}
{notes_html}
{pl_html}
{dorks_html}

<div class="footer">
  TikTok OSINT Report — generated {generated} — for authorised research only
</div>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)

    logger.info("HTML report written to %s", output_path)
    return output_path


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
    # Location metadata — available when creator tags a location
    poi = item.get("poi") or {}
    location_created = (
        item.get("locationCreated")
        or poi.get("name")
        or poi.get("address")
        or ""
    )
    return {
        "title":            desc[:120],
        "play_count":       stats.get("playCount", 0),
        "like_count":       stats.get("diggCount", 0),
        "comment_count":    stats.get("commentCount", 0),
        "share_count":      stats.get("shareCount", 0),
        "create_time":      create_ts,
        "hashtags":         hashtags,
        "video_url":        video_url,
        "duration_sec":     video.get("duration", 0),
        "location_created": location_created,
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
    web_archive: bool = True,
    reverse_image: bool = True,
    pivot_links: bool = True,
    phone_osint: bool = True,
    geo_hints: bool = True,
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
    web_archive:
        Query Internet Archive CDX API for historical profile snapshots.
    reverse_image:
        Generate reverse-image-search links for the profile picture.
    pivot_links:
        Generate cross-platform OSINT pivot links (Holehe, Maigret, HIBP).
    phone_osint:
        Validate & enrich phone numbers found in bio (carrier, region, timezone).
    geo_hints:
        Extract geolocation hints from video metadata, hashtags, and bio text.

    Returns
    -------
    dict with keys:
        username, platform, profile_url, exists, is_public,
        display_name, bio, bio_intel, profile_pic, is_verified,
        private_account, region, user_id, sec_uid,
        follower_count, following_count, likes_count, video_count, friend_count,
        engagement_rate, recent_videos, video_analysis,
        phone_osint, geolocation_hints,
        web_archive, reverse_image_links, pivot_links,
        data_sources, security_notes, dorks
    """
    username = username.lstrip("@").strip()
    tokapi_key  = tokapi_key  or os.getenv("TOKAPI_KEY", "")
    tiktok_api_key = tiktok_api_key or os.getenv("TIKTOK_API_KEY", "")

    profile_url = f"https://www.tiktok.com/@{username}"

    result: dict[str, Any] = {
        "username":           username,
        "platform":           "TikTok",
        "profile_url":        profile_url,
        "exists":             False,
        "is_public":          False,
        "display_name":       None,
        "bio":                None,
        "bio_intel":          {},
        "profile_pic":        None,
        "is_verified":        False,
        "private_account":    False,
        "region":             None,
        "user_id":            None,
        "sec_uid":            "",
        "follower_count":     None,
        "following_count":    None,
        "likes_count":        None,
        "video_count":        None,
        "friend_count":       None,
        "engagement_rate":    None,
        "recent_videos":      [],
        "video_analysis":     {},
        "phone_osint":         [],
        "geolocation_hints":   {},
        "web_archive":         {},
        "reverse_image_links": [],
        "pivot_links":         {},
        "data_sources":        [],
        "security_notes":      [],
        "dorks":               [],
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

    # ── 10. Phone OSINT ───────────────────────────────────────────────────────
    if phone_osint:
        hints = (result.get("bio_intel") or {}).get("phone_hints", [])
        if hints:
            result["phone_osint"] = analyse_phone_numbers(hints)

    # ── 11. Geolocation hints ─────────────────────────────────────────────────
    if geo_hints:
        result["geolocation_hints"] = extract_geolocation_hints(
            result.get("recent_videos", []),
            result.get("bio"),
        )

    # ── 12. Web Archive (Internet Archive CDX) ────────────────────────────────
    if web_archive:
        result["web_archive"] = check_web_archive(username)

    # ── 13. Reverse image search links ────────────────────────────────────────
    if reverse_image:
        result["reverse_image_links"] = reverse_image_search_links(
            result.get("profile_pic"), username
        )

    # ── 14. Cross-platform pivot links ────────────────────────────────────────
    if pivot_links:
        bio_emails = (result.get("bio_intel") or {}).get("emails", [])
        result["pivot_links"] = cross_platform_pivot_links(
            username,
            result.get("display_name"),
            bio_emails,
        )

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

    # Phone OSINT
    phone_data = data.get("phone_osint", [])
    if phone_data:
        console.print("\n  [bold cyan]Phone OSINT[/bold cyan]")
        for ph in phone_data:
            if ph.get("valid"):
                console.print(
                    f"    [green]✓[/green] {ph['raw']} → [bold]{ph.get('e164', '')}[/bold]"
                    f"  {ph.get('number_type', '')}  |  {ph.get('location', '')}  |  {ph.get('carrier', '')}"
                )
                if ph.get("timezones"):
                    console.print(f"       Timezone(s): {', '.join(ph['timezones'])}")
            else:
                console.print(f"    [red]✗[/red] {ph['raw']} — {ph.get('error', 'invalid')}")

    # Geolocation hints
    geo = data.get("geolocation_hints", {})
    if geo.get("primary"):
        conf_color = {"high": "green", "medium": "yellow", "low": "red"}.get(geo.get("confidence", "low"), "dim")
        console.print(f"\n  [bold cyan]Geolocation Hints[/bold cyan]  [[{conf_color}]{geo.get('confidence', '')}[/{conf_color}]]")
        console.print(f"    Primary location: [bold]{geo['primary']}[/bold]")
        if geo.get("api_locations"):
            console.print("    API-tagged locations:")
            for al in geo["api_locations"][:3]:
                console.print(f"      [green]📍[/green] {al['location']}")
        if geo.get("inferred_locations"):
            locs = "  ".join(f"{l['location']} ({l['mention_count']})" for l in geo["inferred_locations"][:4])
            console.print(f"    Inferred from content: {locs}")

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
            loc   = f"  [dim]📍 {v['location_created']}[/dim]" if v.get("location_created") else ""
            console.print(f"    [{i}] {title} | 👁 {plays}  ❤ {likes}{loc}")

    # Security notes
    notes = data.get("security_notes", [])
    if notes:
        console.print("\n  [bold yellow]Security Observations:[/bold yellow]")
        for note in notes:
            console.print(f"    [yellow]⚠  {note}[/yellow]")

    # Web Archive
    wa = data.get("web_archive", {})
    if wa.get("available"):
        console.print("\n  [bold cyan]Web Archive (Internet Archive)[/bold cyan]")
        console.print(f"    Snapshots found : [green]{wa['snapshots']}[/green]")
        if wa.get("earliest"):
            console.print(f"    Earliest capture: {wa['earliest']}")
        if wa.get("latest"):
            console.print(f"    Latest capture  : {wa['latest']}")
        if wa.get("archive_search"):
            console.print(f"    Browse all      : [link={wa['archive_search']}]{wa['archive_search']}[/link]")
        recent = wa.get("recent", [])
        if recent:
            console.print("    Recent snapshots:")
            for snap in recent[:3]:
                console.print(
                    f"      [dim]{snap['date']}[/dim]  "
                    f"[link={snap['wayback_url']}]{snap['wayback_url'][:80]}[/link]"
                )
    elif wa.get("error"):
        console.print(f"\n  [dim]Web Archive: error — {wa['error'][:60]}[/dim]")

    # Reverse image search
    ris = data.get("reverse_image_links", [])
    if ris:
        console.print("\n  [bold]Reverse Image Search:[/bold]")
        for link in ris:
            note = f" [dim]({link.get('note', '')})[/dim]" if link.get("note") else ""
            console.print(f"    [cyan]{link['engine']}[/cyan]{note}")
            console.print(f"      [link={link['url']}]{link['url'][:90]}[/link]")

    # Cross-platform pivot links
    pl = data.get("pivot_links", {})
    if pl:
        console.print("\n  [bold]Cross-Platform Pivot Links:[/bold]")
        for category, items in pl.items():
            label = category.replace("_", " ").title()
            console.print(f"    [bold dim]{label}:[/bold dim]")
            for item in (items if isinstance(items, list) else []):
                tool = item.get("tool") or item.get("email", "")
                url  = item.get("url") or item.get("hibp") or ""
                note = f" [dim]— {item['note']}[/dim]" if item.get("note") else ""
                console.print(f"      [cyan]{tool}[/cyan]{note}")
                if url:
                    console.print(f"        [link={url}]{url[:90]}[/link]")

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
