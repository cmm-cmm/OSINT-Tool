"""
Social Media Recon Module
Gathers public OSINT data from Facebook and TikTok profiles.
Uses only public endpoints and Open Graph metadata — no authentication required.
For security research and investigation purposes only.
"""
import json
import re
import time
import html as _html_lib
from datetime import datetime, timezone
from urllib.parse import quote
import requests
from rich.console import Console

console = Console()

FACEBOOK_GRAPH_API_VERSION = "v21.0"  # Update when Facebook retires this version
SCRAPER3_DELAY = 0.5  # Seconds between sequential RapidAPI calls to avoid HTTP 429

# Desktop User-Agent (for OG/JSON extraction)
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
}

# facebookexternalhit — the ONLY UA that Facebook returns OG data for (its own link-preview crawler)
FB_CRAWLER_HEADERS = {
    "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# OG meta tag patterns: allow arbitrary attributes between property/name and content
# re.DOTALL lets [^>]* match across newlines in multi-line meta tags
_OG_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:([^"\']+)["\'][^>]*?\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE | re.DOTALL,
)
_OG_RE2 = re.compile(
    r'<meta\s+content=["\']([^"\']*)["\'][^>]*?\s+(?:property|name)=["\']og:([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL,
)

# Patterns for IDs embedded in Facebook's JS bundles
_PAGE_ID_RE   = re.compile(r'"pageID"\s*:\s*"(\d+)"')
_USER_ID_RE   = re.compile(r'"userID"\s*:\s*"(\d+)"')
_ENTITY_ID_RE = re.compile(r'"entity_id"\s*:\s*"(\d+)"')
_PROFILE_ID_RE = re.compile(r'"profile_id"\s*:\s*(\d{5,})')
_ACTORID_RE   = re.compile(r'"actorID"\s*:\s*"(\d+)"')

# Suspicious username pattern
_SUSPICIOUS_USER_RE = re.compile(r'^[a-z]{2,}[_\d]{4,}$', re.IGNORECASE)

# Social media URL patterns for cross-platform footprint extraction
_SOCIAL_LINK_PATTERNS = [
    ("Instagram",  re.compile(r'instagram\.com/([A-Za-z0-9_][A-Za-z0-9_.]{0,29})(?:[/?]|$|\s)', re.I)),
    ("Twitter/X",  re.compile(r'(?:twitter|x)\.com/([A-Za-z0-9_]{1,20})(?:[/?]|$|\s)', re.I)),
    ("YouTube",    re.compile(r'youtube\.com/(?:c/|channel/|@)([A-Za-z0-9_.\-]{1,60})', re.I)),
    ("TikTok",     re.compile(r'tiktok\.com/@([A-Za-z0-9_.]{2,30})', re.I)),
    ("LinkedIn",   re.compile(r'linkedin\.com/(?:in|company)/([A-Za-z0-9_\-]{1,60})', re.I)),
    ("Telegram",   re.compile(r't(?:elegram)?\.me/([A-Za-z0-9_]{3,32})', re.I)),
    ("Zalo",       re.compile(r'zalo\.me/([A-Za-z0-9_\-]{3,30})', re.I)),
]

# Vietnamese & global brand names for impersonation detection
_BRAND_RE = re.compile(
    r'\b(vietcombank|agribank|bidv|techcombank|vpbank|mbbank|sacombank|acb|tpbank|'
    r'momo|zalopay|vnpay|shopeepay|viettel|mobifone|vinaphone|shopee|lazada|tiki|sendo|'
    r'facebook|google|apple|tiktok|youtube|zalo|vnptwallet)\b',
    re.IGNORECASE,
)

def _extract_og(html: str) -> dict:
    """Extract Open Graph + al:* app-link meta tags from HTML."""
    tags = {}
    for m in _OG_RE.finditer(html):
        tags[m.group(1).lower()] = _html_lib.unescape(m.group(2))
    for m in _OG_RE2.finditer(html):
        key = m.group(2).lower()
        if key not in tags:
            tags[key] = _html_lib.unescape(m.group(1))
    # al:android:url contains the numeric profile ID: "fb://profile/123456"
    al_m = re.search(r'property=["\']al:android:url["\']\s+content=["\']([^"\']*)["\']', html, re.IGNORECASE)
    al_m2 = re.search(r'content=["\']([^"\']*)["\'][^>]+property=["\']al:android:url["\']', html, re.IGNORECASE)
    if al_m:
        tags["_al_android"] = al_m.group(1)
    elif al_m2:
        tags["_al_android"] = al_m2.group(1)
    return tags


def _normalize_fb_id(identifier: str) -> str:
    """Extract Facebook username or numeric ID from a URL or bare string.

    Handles: facebook.com, m.facebook.com, mbasic.facebook.com,
             web.facebook.com, fb.com — with or without https://.
    """
    m = re.search(
        r'(?:https?://)?(?:www\.)?(?:m\.|mbasic\.|web\.)?(?:facebook\.com|fb\.com)/([^#]+?)(?:#|$)',
        identifier,
        re.IGNORECASE,
    )
    if m:
        identifier = m.group(1).rstrip("/")
        if re.match(r'profile\.php', identifier, re.IGNORECASE):
            id_m = re.search(r'id=(\d+)', identifier)
            identifier = id_m.group(1) if id_m else identifier
        else:
            identifier = identifier.split("?")[0]
    return identifier.lstrip("@").strip()


def _extract_numeric_id(html: str, og: dict) -> str | None:
    """Extract numeric Facebook ID — al:android:url first (most reliable), then HTML patterns."""
    al = og.get("_al_android", "")
    m = re.search(r'fb://(?:profile|page)/(\d+)', al)
    if m:
        return m.group(1)
    for pat in (_PAGE_ID_RE, _USER_ID_RE, _ENTITY_ID_RE, _PROFILE_ID_RE, _ACTORID_RE):
        m = pat.search(html)
        if m:
            return m.group(1)
    m = re.search(r'profile\.php\?id=(\d{5,})', html)
    if m:
        return m.group(1)
    return None


def _parse_og_description(desc: str) -> dict:
    """
    Parse Facebook's og:description which embeds engagement stats.

    Examples:
      "Coca-Cola. 107,673,233 likes · 1,686 talking about this. Page description..."
      "johndoe. 2,543 followers · 12 following. Photos and posts."
      "1.234.567 người theo dõi · 890 đang nói về điều này."  ← Vietnamese format
    """
    info = {"likes": None, "followers_og": None, "following": None, "talking_about": None, "text": desc}

    def _normalize_num(s: str) -> str:
        """Normalize both EN (1,234) and VN (1.234) thousands separators."""
        return re.sub(r'[,.]', '', s)

    m = re.search(r'([\d,.]+)\s*likes?\s*[·•]\s*([\d,.]+)\s*talking about this', desc, re.IGNORECASE)
    if m:
        info["likes"] = _normalize_num(m.group(1))
        info["talking_about"] = _normalize_num(m.group(2))

    m = re.search(r'([\d,.]+)\s*followers?\s*[·•]\s*([\d,.]+)\s*following', desc, re.IGNORECASE)
    if m:
        info["followers_og"] = _normalize_num(m.group(1))
        info["following"] = _normalize_num(m.group(2))

    if not info["followers_og"]:
        m = re.search(r'([\d,.]+)\s*(?:followers?|ng\u01b0\u1eddi theo d\u00f5i)', desc, re.IGNORECASE)
        if m:
            info["followers_og"] = _normalize_num(m.group(1))

    # Strip engagement numbers to get the actual description text
    clean = re.sub(r'[\d,.]+\s*(?:likes?|followers?|following|talking about this|người theo dõi|đang theo dõi)[^\n.]*[·•]?\s*', '', desc).strip()
    clean = re.sub(r'^[^\s.]{1,80}\.\s*', '', clean).strip()  # strip leading "PageName. " prefix
    clean = re.sub(r'^[\s.·•,]+', '', clean).strip()           # strip any remaining leading punctuation
    if clean and len(clean) > 5:
        info["text"] = clean
    return info


def _try_graph_api(result: dict, identifier: str):
    """Try Facebook Graph API without access token — returns limited data for public pages."""
    try:
        r = requests.get(
            f"https://graph.facebook.com/{FACEBOOK_GRAPH_API_VERSION}/{identifier}",
            params={
                "fields": (
                    "name,category,description,about,fan_count,followers_count,"
                    "website,phone,location,is_verified,cover,picture,general_info,"
                    "link,verification_status,founded,single_line_address,emails,"
                    "instagram_business_account,rating_count,overall_star_rating"
                )
            },
            headers=HEADERS,
            timeout=8,
            verify=True,
        )
        if r.status_code == 200:
            d = r.json()
            if "error" not in d:
                result.setdefault("display_name", d.get("name"))
                result.setdefault("category", d.get("category"))
                result.setdefault("website", d.get("website"))
                result.setdefault("phone", d.get("phone"))
                result.setdefault("founded", d.get("founded"))
                result.setdefault("general_info", d.get("general_info"))
                result.setdefault("mission", d.get("about"))
                if d.get("fan_count") is not None and not result.get("follower_count"):
                    result["follower_count"] = str(d["fan_count"])
                if d.get("followers_count") is not None and not result.get("follower_count"):
                    result["follower_count"] = str(d["followers_count"])
                if d.get("is_verified") is not None and result.get("is_verified") is None:
                    result["is_verified"] = d["is_verified"]
                if not result.get("description"):
                    result["description"] = d.get("description") or d.get("about")
                loc = d.get("location", {})
                if isinstance(loc, dict) and not result.get("location"):
                    parts = [loc.get("city"), loc.get("state"), loc.get("country")]
                    result["location"] = ", ".join(p for p in parts if p) or None
                elif isinstance(loc, str) and not result.get("location"):
                    result["location"] = loc
                pic = d.get("picture", {})
                if isinstance(pic, dict) and pic.get("data", {}).get("url"):
                    result.setdefault("profile_pic", pic["data"]["url"])
                cover = d.get("cover", {})
                if isinstance(cover, dict) and cover.get("source"):
                    result.setdefault("cover_photo", cover["source"])
                emails = d.get("emails", [])
                if emails:
                    result.setdefault("email", emails[0] if isinstance(emails, list) else emails)
                # Linked Instagram Business account (pages only)
                ig = d.get("instagram_business_account")
                if isinstance(ig, dict) and ig.get("id"):
                    result.setdefault("instagram_business_id", str(ig["id"]))
                # Page rating (trust/reputation signal for business pages)
                if d.get("rating_count") is not None:
                    result.setdefault("rating_count", int(d["rating_count"]))
                if d.get("overall_star_rating") is not None:
                    result.setdefault("overall_star_rating", round(float(d["overall_star_rating"]), 1))
                if d.get("name"):
                    result["exists"] = True
                    result["is_public"] = True
                    result["data_sources"].append("Graph API (public)")
    except Exception:
        pass


def _try_facebook_scraper3(identifier: str, api_key: str, result: dict):
    """
    Enrich facebook_recon result using Facebook Scraper3 RapidAPI.
    Searches by identifier and cross-references the top results.
    """
    try:
        r = requests.get(
            "https://facebook-scraper3.p.rapidapi.com/search/pages",
            params={"query": identifier},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "facebook-scraper3.p.rapidapi.com",
            },
            timeout=12,
        )
        if r.status_code != 200:
            return
        items = r.json().get("results", [])
        if not items:
            return
        # Find the best match: profile_url or name contains the identifier
        match = None
        ident_lower = identifier.lower()
        for item in items:
            url = item.get("profile_url", "").lower()
            name = item.get("name", "").lower()
            if ident_lower in url or ident_lower in name:
                match = item
                break
        if match is None:
            match = items[0]  # Fallback: take top result

        if not result.get("exists"):
            result["exists"] = True
        if not result.get("is_public"):
            result["is_public"] = True
        if not result.get("display_name"):
            result["display_name"] = match.get("name")
        if not result.get("numeric_id") and match.get("facebook_id"):
            result["numeric_id"] = match["facebook_id"]
        if result.get("is_verified") is None and match.get("is_verified") is not None:
            result["is_verified"] = match["is_verified"]
        img = match.get("image") or {}
        if not result.get("profile_pic") and img.get("uri"):
            result["profile_pic"] = img["uri"]
        if not result.get("profile_url") and match.get("profile_url"):
            result["profile_url"] = match["profile_url"]
        result["data_sources"].append("Facebook Scraper3 (pages)")
    except Exception:
        pass


def _try_facebook_scraper3_page_details(identifier: str, api_key: str, result: dict):
    """
    Fetch full page contact details via /page/details?url=...
    Returns phone, email, address, website, followers, categories, intro, cover.
    This is the primary source for business contact info (phone, email, address).
    """
    profile_url = (
        f"https://www.facebook.com/profile.php?id={identifier}"
        if identifier.isdigit()
        else f"https://www.facebook.com/{identifier}"
    )
    try:
        r = requests.get(
            "https://facebook-scraper3.p.rapidapi.com/page/details",
            params={"url": profile_url},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "facebook-scraper3.p.rapidapi.com",
            },
            timeout=15,
        )
        if r.status_code != 200:
            return
        d = r.json().get("results") or r.json()
        if not d or not isinstance(d, dict):
            return

        if not result.get("exists"):
            result["exists"] = True
        if not result.get("is_public"):
            result["is_public"] = True

        if not result.get("display_name"):
            result["display_name"] = d.get("name")
        if not result.get("numeric_id") and d.get("page_id"):
            result["numeric_id"] = d["page_id"]
        if result.get("is_verified") is None and d.get("verified") is not None:
            result["is_verified"] = d["verified"]

        # Contact fields — these are the primary additions
        if not result.get("phone") and d.get("phone"):
            result["phone"] = d["phone"]
        if not result.get("email") and d.get("email"):
            result["email"] = d["email"]
        if not result.get("address") and d.get("address"):
            result["address"] = d["address"]
        if not result.get("website") and d.get("website"):
            result["website"] = d["website"]

        # Stats
        if not result.get("follower_count") and d.get("followers") is not None:
            result["follower_count"] = str(d["followers"])
        if not result.get("following_count") and d.get("following") is not None:
            result["following_count"] = str(d["following"])

        # Category
        cats = d.get("categories") or []
        if not result.get("category") and cats:
            # Skip generic "Page" label; pick the first descriptive one
            desc_cats = [c for c in cats if c.lower() != "page"]
            result["category"] = ", ".join(desc_cats) if desc_cats else cats[0]

        # Description / intro
        if not result.get("description") and d.get("intro"):
            result["description"] = d["intro"]

        # Images
        if not result.get("profile_pic") and d.get("image"):
            result["profile_pic"] = d["image"]
        if not result.get("cover_photo") and d.get("cover_image"):
            result["cover_photo"] = d["cover_image"]

        if not result.get("profile_url") and d.get("url"):
            result["profile_url"] = d["url"]

        result["data_sources"].append("Facebook Scraper3 (page/details)")
    except Exception:
        pass


def _try_facebook_scraper3_people(identifier: str, api_key: str, result: dict):
    """
    Search Facebook personal profiles via /search/people.
    Fills the gap when /search/pages misses personal profiles.
    Only enriches if a strong URL/name match is found.
    """
    try:
        r = requests.get(
            "https://facebook-scraper3.p.rapidapi.com/search/people",
            params={"query": identifier},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "facebook-scraper3.p.rapidapi.com",
            },
            timeout=12,
        )
        if r.status_code != 200:
            return
        items = r.json().get("results", [])
        if not items:
            return
        # Require a strong URL or name match — people search is noisy
        match = None
        ident_lower = identifier.lower()
        for item in items:
            url = item.get("url", "").lower()
            name = item.get("name", "").lower()
            if ident_lower in url or ident_lower in name:
                match = item
                break
        if match is None:
            return
        if not result.get("exists"):
            result["exists"] = True
        if not result.get("is_public"):
            result["is_public"] = True
        if not result.get("display_name"):
            result["display_name"] = match.get("name")
        pid = str(match.get("profile_id", ""))
        if not result.get("numeric_id") and pid.isdigit():
            result["numeric_id"] = pid
        if not result.get("profile_url") and match.get("url"):
            result["profile_url"] = match["url"]
        pp = match.get("profile_picture") or {}
        if not result.get("profile_pic") and pp.get("uri"):
            result["profile_pic"] = pp["uri"]
        # Only assert Personal Profile if the /search/pages lookup didn't already find this entity
        if not result.get("account_type") and "Facebook Scraper3 (pages)" not in result["data_sources"]:
            result["account_type"] = "Personal Profile"
        if result.get("is_verified") is None and match.get("is_verified") is not None:
            result["is_verified"] = match["is_verified"]
        result["data_sources"].append("Facebook Scraper3 (people)")
    except Exception:
        pass


def _try_facebook_scraper3_posts(identifier: str, api_key: str, result: dict):
    """
    Fetch the 5 most recent posts from a Facebook Page using /page/posts.
    Requires a numeric page ID in result["numeric_id"].
    Also computes avg_engagement across fetched posts.
    """
    page_id = result.get("numeric_id")
    if not page_id or not str(page_id).isdigit():
        return
    try:
        r = requests.get(
            "https://facebook-scraper3.p.rapidapi.com/page/posts",
            params={"page_id": page_id, "count": 5},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "facebook-scraper3.p.rapidapi.com",
            },
            timeout=15,
        )
        if r.status_code != 200:
            return
        posts_raw = r.json().get("results", [])
        if not posts_raw:
            return
        result["recent_posts"] = []
        total_reactions = 0
        total_comments = 0
        for p in posts_raw:
            ts = p.get("timestamp")
            date_str = (
                datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
                if ts else None
            )
            post = {
                "url": p.get("url"),
                "message": (p.get("message") or "")[:200],
                "date": date_str,
                "reactions": p.get("reactions_count", 0) or 0,
                "comments": p.get("comments_count", 0) or 0,
                "shares": p.get("reshare_count", 0) or 0,
                "type": p.get("type", "post"),
            }
            result["recent_posts"].append(post)
            total_reactions += post["reactions"]
            total_comments += post["comments"]
        n = len(result["recent_posts"])
        if n:
            result["avg_engagement"] = round((total_reactions + total_comments) / n)
            result["data_sources"].append(f"Facebook Scraper3 (page posts: {n})")
    except Exception:
        pass


def _try_facebook_scraper3_search_posts(identifier: str, api_key: str, result: dict):
    """
    Search for public posts mentioning this identifier/name via /search/posts.
    Useful when the target is a person whose posts aren't accessible via /page/posts.
    Stores up to 5 representative recent posts.
    """
    query = result.get("display_name") or identifier
    try:
        r = requests.get(
            "https://facebook-scraper3.p.rapidapi.com/search/posts",
            params={"query": query, "count": 5},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "facebook-scraper3.p.rapidapi.com",
            },
            timeout=15,
        )
        if r.status_code != 200:
            return
        posts_raw = r.json().get("results", [])
        if not posts_raw:
            return
        # Only populate if we don't already have posts
        if result.get("recent_posts"):
            return
        result["recent_posts"] = []
        total_reactions = 0
        total_comments = 0
        for p in posts_raw:
            ts = p.get("timestamp")
            date_str = (
                datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")
                if ts else None
            )
            author = p.get("author") or {}
            post = {
                "url": p.get("url"),
                "message": (p.get("message") or "")[:200],
                "date": date_str,
                "reactions": p.get("reactions_count", 0) or 0,
                "comments": p.get("comments_count", 0) or 0,
                "shares": p.get("reshare_count", 0) or 0,
                "type": p.get("type", "post"),
                "author_name": author.get("name"),
            }
            result["recent_posts"].append(post)
            total_reactions += post["reactions"]
            total_comments += post["comments"]
        n = len(result["recent_posts"])
        if n:
            result["avg_engagement"] = round((total_reactions + total_comments) / n)
            result["data_sources"].append(f"Facebook Scraper3 (post search: {n})")
    except Exception:
        pass


# ─── Facebook analysis helpers ───────────────────────────────────────────────

def _extract_linked_socials(result: dict) -> list:
    """
    Scan all text fields for linked social media handles.
    Returns a list of {platform, handle} dicts for cross-platform investigation.
    """
    search_text = " ".join(filter(None, [
        result.get("website") or "",
        result.get("description") or "",
        result.get("general_info") or "",
        result.get("mission") or "",
        result.get("profile_url") or "",
    ]))
    found = []
    seen: set = set()
    for platform, pat in _SOCIAL_LINK_PATTERNS:
        m = pat.search(search_text)
        if m:
            handle = m.group(1).rstrip("/")
            key = f"{platform}:{handle.lower()}"
            if key not in seen:
                seen.add(key)
                found.append({"platform": platform, "handle": handle})
    return found


def _analyze_post_patterns(posts: list) -> dict | None:
    """
    Analyse post date strings from recent_posts to estimate posting frequency.
    Returns None if fewer than 2 dated posts are available.
    High frequency (>15/day) is flagged as a potential automation indicator.
    """
    if len(posts) < 2:
        return None
    dates = []
    for p in posts:
        d = p.get("date")
        if d:
            try:
                dates.append(datetime.strptime(d, "%Y-%m-%d"))
            except ValueError:
                pass
    if len(dates) < 2:
        return None
    dates.sort()
    date_range_days = max((dates[-1] - dates[0]).days, 1)
    posts_per_day = round(len(dates) / date_range_days, 2)
    return {
        "posts_scanned": len(dates),
        "oldest_date": dates[0].strftime("%Y-%m-%d"),
        "newest_date": dates[-1].strftime("%Y-%m-%d"),
        "posts_per_day_est": posts_per_day,
    }


def _calculate_engagement_metrics(result: dict):
    """
    Compute engagement_rate (avg reactions+comments+shares per post / followers * 100)
    and like_follower_ratio (page-likes ÷ current followers).
    Appends anomaly notes to result["security_notes"] when thresholds are breached.

    Typical healthy engagement rate benchmarks:
      - >10 % : exceptionally high (verify authenticity)
      - 3–10 % : strong organic engagement
      - 1–3 %  : industry average
      - 0.1–1 %: below average
      - <0.1 % : very low — possible bot/purchased audience
    """
    # Resolve follower count (prefer follower_count, fall back to likes_count)
    followers = None
    for fc in (result.get("follower_count"), result.get("likes_count")):
        if fc and str(fc).isdigit():
            v = int(fc)
            if v > 0:
                followers = v
                break

    # Engagement rate from recent posts
    posts = result.get("recent_posts") or []
    if posts and followers:
        total_eng = sum(
            (p.get("reactions") or 0) + (p.get("comments") or 0) + (p.get("shares") or 0)
            for p in posts
        )
        avg_per_post = total_eng / len(posts)
        er = round(avg_per_post / followers * 100, 3)
        result["engagement_rate"] = er
        if er < 0.05 and followers > 10_000:
            result["security_notes"].append(
                f"⚠ Extremely low engagement rate ({er:.3f}%) despite {followers:,} followers — "
                "strong indicator of purchased/bot-inflated follower count."
            )
        elif er > 20.0:
            result["security_notes"].append(
                f"⚠ Unusually high engagement rate ({er:.1f}%) — may indicate coordinated brigading "
                "or engagement-pod manipulation of reach."
            )

    # Like / follower ratio (old bought-like detection for pages)
    likes = result.get("likes_count")
    if likes and followers and str(likes).isdigit():
        ratio = round(int(likes) / followers, 3)
        result["like_follower_ratio"] = ratio
        if ratio > 5.0:
            result["security_notes"].append(
                f"⚠ Page-likes to followers ratio is very high ({ratio:.1f}×) — "
                "possible old bought-like campaign (tactic common before 2020)."
            )

    # Talking-about / follower ratio (page health)
    talking = result.get("talking_about")
    if talking and str(talking).isdigit() and followers and followers > 50_000:
        ta_ratio = int(talking) / followers * 100
        if ta_ratio < 0.01:
            result["security_notes"].append(
                f"ℹ Very low 'talking about this' ratio ({ta_ratio:.4f}%) — "
                "audience appears inactive; page may rely on paid reach rather than organic engagement."
            )


# ─── Facebook ────────────────────────────────────────────────────────────────

# ── Breach intelligence helpers (auto-enrich when email/phone is discovered) ──

def _try_intelx_phonebook(query: str, api_key: str) -> dict | None:
    """
    IntelligenceX Phonebook Search — discovers leaked email addresses, domains,
    and phone numbers associated with the query term (email/username).
    Free tier: ~10 req/day. Obtain a key at https://intelx.io/
    API: POST https://2.intelx.io/phonebook/search  →  GET /phonebook/search/result?id=...
    """
    try:
        r = requests.post(
            "https://2.intelx.io/phonebook/search",
            headers={"x-key": api_key, "Content-Type": "application/json"},
            json={"term": query, "maxresults": 30, "media": 0, "target": 0, "timeout": 10},
            timeout=12,
            verify=True,
        )
        if r.status_code != 200:
            return None
        search_id = r.json().get("id")
        if not search_id:
            return None
        time.sleep(1.5)
        r2 = requests.get(
            "https://2.intelx.io/phonebook/search/result",
            headers={"x-key": api_key},
            params={"id": search_id, "limit": 30, "offset": 0},
            timeout=12,
            verify=True,
        )
        if r2.status_code != 200:
            return None
        selectors = r2.json().get("selectors", [])
        if not selectors:
            return None
        emails, domains, phones = [], [], []
        for item in selectors:
            value = item.get("selectorvalue", "")
            stype = item.get("selectortype", 0)
            if stype == 1 and value not in emails:
                emails.append(value)
            elif stype == 2 and value not in domains:
                domains.append(value)
            elif stype == 4 and value not in phones:
                phones.append(value)
        return {
            "emails": emails[:15],
            "domains": domains[:10],
            "phones": phones[:10],
            "total": len(selectors),
        }
    except Exception:
        return None


def _enrich_breach_intel(
    result: dict,
    breachdir_key: str | None = None,
    hibp_key: str | None = None,
    intelx_key: str | None = None,
    dehashed_email: str | None = None,
    dehashed_key: str | None = None,
    snusbase_key: str | None = None,
    emailrep_key: str | None = None,
    hunter_key: str | None = None,
):
    """
    Auto-enrich Facebook recon with breach intelligence.
    Checks discovered email and phone against known breach databases.
    Populates result["breach_intel"] only when actionable contact data is available.

    Sources used:
      1. LeakCheck.io public — free, no key, checks email & phone
      2. BreachDirectory (RapidAPI) — free 100 req/month, reveals exact field types
      3. HaveIBeenPwned v3 — optional paid ($3.95/mo), most comprehensive breach list
      4. IntelligenceX Phonebook — optional free tier, discovers associated leaked identifiers
      5. Dehashed — actual breach records with passwords/names/addresses/phones ($5/mo)
      6. Snusbase — actual breach records ($2/mo)
      7. Holehe — check which 100+ websites the email is registered on (free)
      8. EmailRep.io — email reputation & breach signals (free 1000/day)
      9. Hunter.io — person enrichment: name, job, phone, social profiles (free 25/mo)
    """
    from modules.breach_check import (
        check_leakcheck_public,
        check_breachdirectory,
        check_hibp_email,
        check_dehashed,
        check_snusbase,
        check_holehe,
        check_emailrep,
        check_hunter_email,
        calculate_breach_severity,
    )

    email = result.get("email")
    phone = result.get("phone")
    if not email and not phone:
        return

    intel: dict = {
        "email": email,
        "phone": phone,
        "leakcheck_email": None,
        "leakcheck_phone": None,
        "breachdirectory": None,
        "hibp": None,
        "intelx": None,
        "dehashed": None,
        "snusbase": None,
        "holehe": None,
        "emailrep": None,
        "hunter": None,
        "data_classes_exposed": [],
        "leaked_hashes": [],
        "associated_names": [],
        "associated_phones": [],
        "associated_addresses": [],
        "associated_ips": [],
        "registered_sites": [],
        "risk_level": None,
        "risk_score": 0,
        "risk_color": "dim",
        "total_breach_sources": 0,
        "alerts": [],
    }

    associated_names: set = set()
    associated_phones: set = set()
    associated_addresses: set = set()
    associated_ips: set = set()
    leaked_hashes: list = []

    email_valid = bool(email and re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email))
    phone_clean = None
    if phone:
        phone_clean = re.sub(r'[\s\-\(\)\.\+]', '', phone)
        if re.match(r'^\d{7,15}$', phone_clean):
            # Preserve leading '+' for international format LeakCheck expects
            phone_clean = re.sub(r'[\s\-\(\)\.]', '', phone)
        else:
            phone_clean = None

    # ── 1. LeakCheck.io (email) — free, always run ────────────────────────
    if email_valid:
        lc_e = check_leakcheck_public(email)
        intel["leakcheck_email"] = lc_e
        if lc_e.get("found"):
            n = len(lc_e.get("sources", []))
            intel["total_breach_sources"] += n
            intel["alerts"].append(
                f"Email '{email}' xuất hiện trong {n} nguồn rò rỉ dữ liệu (LeakCheck)."
            )

    # ── 2. BreachDirectory — reveals exact data field types leaked ────────
    if email_valid and breachdir_key:
        bd = check_breachdirectory(email, breachdir_key)
        intel["breachdirectory"] = bd
        if bd.get("found"):
            for entry in bd.get("result", []):
                for field in entry.get("fields", []):
                    if field not in intel["data_classes_exposed"]:
                        intel["data_classes_exposed"].append(field)
            size = bd.get("size") or len(bd.get("result", []))
            intel["total_breach_sources"] += size
            exposed_str = ", ".join(intel["data_classes_exposed"][:8])
            intel["alerts"].append(
                f"BreachDirectory: {size} bản ghi — trường dữ liệu bị lộ: {exposed_str}."
            )
            # Raise specific high-value alerts
            cl = {f.lower() for f in intel["data_classes_exposed"]}
            if any(k in cl for k in ("password", "hash", "md5", "sha1")):
                intel["alerts"].append(
                    "⚠ CRITICAL: Hash/mật khẩu của tài khoản này đã bị lộ trong breach database!"
                )
            if any(k in cl for k in ("address", "street", "physical address")):
                intel["alerts"].append(
                    "⚠ Địa chỉ thực (physical address) có thể đã bị lộ trong breach."
                )
            if "phone" in cl or "phone number" in cl:
                intel["alerts"].append(
                    "⚠ Số điện thoại liên kết với email này đã bị lộ trong breach."
                )
            if any(k in cl for k in ("credit card", "bank", "financial")):
                intel["alerts"].append(
                    "⚠ CRITICAL: Thông tin tài chính / thẻ ngân hàng có thể đã bị lộ!"
                )

    # ── 3. HIBP (optional, paid key) ─────────────────────────────────────
    if email_valid and hibp_key:
        hibp_r = check_hibp_email(email, hibp_key)
        intel["hibp"] = hibp_r
        for breach in hibp_r.get("breaches", []):
            for dc in breach.get("data_classes", []):
                if dc not in intel["data_classes_exposed"]:
                    intel["data_classes_exposed"].append(dc)
        n_b = len(hibp_r.get("breaches", []))
        n_p = len(hibp_r.get("pastes", []))
        if n_b or n_p:
            intel["total_breach_sources"] += n_b
            intel["alerts"].append(
                f"HIBP: email xuất hiện trong {n_b} breach và {n_p} paste(s)."
            )

    # ── 4. LeakCheck.io (phone) — free, always run ────────────────────────
    if phone_clean:
        lc_p = check_leakcheck_public(phone_clean)
        intel["leakcheck_phone"] = lc_p
        if lc_p.get("found"):
            n = len(lc_p.get("sources", []))
            intel["total_breach_sources"] += n
            intel["alerts"].append(
                f"Số điện thoại '{phone_clean}' xuất hiện trong {n} nguồn rò rỉ (LeakCheck)."
            )

    # ── 5. IntelligenceX Phonebook (optional, free tier key) ─────────────
    if intelx_key and email_valid:
        ix = _try_intelx_phonebook(email, intelx_key)
        if ix and ix.get("total", 0) > 0:
            intel["intelx"] = ix
            intel["alerts"].append(
                f"IntelligenceX: {ix['total']} selector(s) liên quan — "
                f"{len(ix.get('emails', []))} email, "
                f"{len(ix.get('domains', []))} domain, "
                f"{len(ix.get('phones', []))} phone số."
            )

    # ── 6. Dehashed — actual breach records ──────────────────────────────
    if dehashed_email and dehashed_key:
        q_type = "email" if email_valid else ("phone" if phone_clean else "username")
        q_value = email if email_valid else (phone_clean or "")
        if q_value:
            dh = check_dehashed(q_value, q_type, dehashed_email, dehashed_key)
            intel["dehashed"] = dh
            entries = dh.get("entries") or []
            if dh.get("found") and entries:
                intel["total_breach_sources"] += dh.get("total", len(entries))
                intel["alerts"].append(
                    f"Dehashed: {dh.get('total', len(entries))} bản ghi thực tế tìm thấy!"
                )
                for entry in entries[:50]:
                    n = (entry.get("name") or "").strip()
                    p = (entry.get("phone") or "").strip()
                    a = (entry.get("address") or "").strip()
                    ip = (entry.get("ip_address") or "").strip()
                    pw = entry.get("password") or ""
                    hp = entry.get("hashed_password") or ""
                    db = entry.get("database_name") or "?"
                    if n:
                        associated_names.add(n)
                    if p and p not in (phone or ""):
                        associated_phones.add(p)
                    if a:
                        associated_addresses.add(a)
                    if ip:
                        associated_ips.add(ip)
                    if pw or hp:
                        leaked_hashes.append({"source": db, "password": pw, "hash": hp, "hash_type": ""})
                    # Alert if plaintext password found
                    if pw:
                        intel["alerts"].append(
                            f"⚠ CRITICAL: Tìm thấy mật khẩu plaintext trong Dehashed ({db})!"
                        )
                        break  # only one critical alert per source

    # ── 7. Snusbase — actual breach records ──────────────────────────────
    if snusbase_key:
        q_type = "email" if email_valid else ("phone" if phone_clean else "username")
        q_value = email if email_valid else (phone_clean or "")
        if q_value:
            sn = check_snusbase(q_value, q_type, snusbase_key)
            intel["snusbase"] = sn
            entries = sn.get("entries") or []
            if sn.get("found") and entries:
                intel["total_breach_sources"] += sn.get("total", len(entries))
                intel["alerts"].append(
                    f"Snusbase: {sn.get('total', len(entries))} bản ghi thực tế tìm thấy!"
                )
                for entry in entries[:50]:
                    n = (entry.get("name") or "").strip()
                    p_val = (entry.get("ip") or "").strip()
                    pw = entry.get("password") or ""
                    h = entry.get("hash") or ""
                    ht = entry.get("hash_type") or ""
                    tbl = entry.get("table") or "?"
                    if n:
                        associated_names.add(n)
                    if p_val:
                        associated_ips.add(p_val)
                    if pw or h:
                        leaked_hashes.append({"source": tbl, "password": pw, "hash": h, "hash_type": ht})
                    if pw:
                        intel["alerts"].append(
                            f"⚠ CRITICAL: Tìm thấy mật khẩu plaintext trong Snusbase ({tbl})!"
                        )
                        break

    # ── 8. Holehe — email registration on 100+ sites ──────────────────────
    if email_valid:
        ho = check_holehe(email)
        intel["holehe"] = ho
        sites = ho.get("registered_sites") or []
        if sites:
            intel["registered_sites"] = sites
            intel["alerts"].append(
                f"Holehe: email được đăng ký trên {len(sites)} dịch vụ — "
                + ", ".join(s.get("name", "") for s in sites[:5])
                + (" ..." if len(sites) > 5 else "")
            )

    # ── 9. EmailRep — reputation signals ─────────────────────────────────
    if email_valid:
        er = check_emailrep(email, emailrep_key)
        intel["emailrep"] = er
        if er.get("suspicious") or er.get("credentials_leaked"):
            flags = []
            if er.get("credentials_leaked"): flags.append("credentials_leaked")
            if er.get("blacklisted"):         flags.append("blacklisted")
            if er.get("malicious_activity"): flags.append("malicious_activity")
            if flags:
                intel["alerts"].append(
                    f"EmailRep: {', '.join(flags)} — reputation: {er.get('reputation', '?')}"
                )

    # ── 10. Hunter.io — person enrichment ────────────────────────────────
    if email_valid and hunter_key:
        hu = check_hunter_email(email, hunter_key)
        intel["hunter"] = hu
        if hu.get("found"):
            name_parts = " ".join(filter(None, [hu.get("first_name"), hu.get("last_name")]))
            if name_parts:
                associated_names.add(name_parts)
                intel["alerts"].append(
                    f"Hunter.io: tìm thấy tên thật '{name_parts}'"
                    + (f", công ty: {hu['organization']}" if hu.get("organization") else "")
                )
            if hu.get("phone_number"):
                associated_phones.add(hu["phone_number"])

    # Aggregate extracted values into intel dict
    intel["leaked_hashes"] = leaked_hashes[:30]
    intel["associated_names"] = sorted(associated_names)[:20]
    intel["associated_phones"] = sorted(associated_phones)[:20]
    intel["associated_addresses"] = sorted(associated_addresses)[:20]
    intel["associated_ips"] = sorted(associated_ips)[:20]

    # ── Risk assessment ───────────────────────────────────────────────────
    if intel["data_classes_exposed"]:
        sev = calculate_breach_severity(intel["data_classes_exposed"])
        intel["risk_level"] = sev["risk_level"]
        intel["risk_score"] = sev["score"]
        intel["risk_color"] = sev["color"]
    elif intel["total_breach_sources"] > 0:
        intel["risk_level"] = "MEDIUM"
        intel["risk_score"] = 35
        intel["risk_color"] = "yellow"
    elif email_valid or phone_clean:
        intel["risk_level"] = "NOT FOUND"
        intel["risk_score"] = 0
        intel["risk_color"] = "green"

    result["breach_intel"] = intel

def facebook_recon(
    identifier: str,
    fb_scraper_key: str | None = None,
    hibp_key: str | None = None,
    breachdir_key: str | None = None,
    intelx_key: str | None = None,
    dehashed_email: str | None = None,
    dehashed_key: str | None = None,
    snusbase_key: str | None = None,
    emailrep_key: str | None = None,
    hunter_key: str | None = None,
) -> dict:
    """
    Gather public OSINT from a Facebook profile, page, or numeric ID.

    Fetching strategy (no auth required):
      1. www.facebook.com with facebookexternalhit/1.1 UA — the ONLY UA that
         Facebook whitelists for returning full OG tags (its link-preview crawler)
      2. graph.facebook.com — public fields for Pages without an access token
      3. Facebook Scraper3 RapidAPI (optional) — enriches with verified badge, numeric ID, pic
    """
    identifier = _normalize_fb_id(identifier)
    profile_url = (
        f"https://www.facebook.com/profile.php?id={identifier}"
        if identifier.isdigit()
        else f"https://www.facebook.com/{identifier}"
    )

    result = {
        "identifier": identifier,
        "platform": "Facebook",
        "profile_url": profile_url,
        "canonical_url": None,
        "exists": False,
        "is_public": False,
        "display_name": None,
        "description": None,
        "profile_pic": None,
        "cover_photo": None,
        "account_type": None,
        "numeric_id": None,
        "is_verified": None,
        "follower_count": None,
        "likes_count": None,
        "talking_about": None,
        "following_count": None,
        "website": None,
        "email": None,
        "phone": None,
        "category": None,
        "founded": None,
        "location": None,
        "address": None,
        "general_info": None,
        "mission": None,
        "recent_posts": [],
        "avg_engagement": None,
        "data_sources": [],
        "security_notes": [],
        "dorks": [],
        # ── Derived / enriched fields ──────────────────────────────────────
        "linked_accounts": [],        # cross-platform handles found in profile text
        "engagement_rate": None,      # avg post engagement / followers × 100 (%)
        "like_follower_ratio": None,  # page-likes ÷ followers (bought-like detector)
        "post_pattern": None,         # {posts_per_day_est, oldest_date, newest_date}
        "ad_library_url": None,       # direct link to Facebook Ad Library transparency page
        "rating_count": None,         # number of public star ratings (business pages)
        "overall_star_rating": None,  # average star rating 1–5 (business pages)
        "instagram_business_id": None,# linked Instagram Business account ID
        "breach_intel": None,          # auto-enriched breach/leak intelligence (email+phone)
    }

    # ── Fetch using facebookexternalhit/1.1 UA ─────────────────────────────
    # Facebook only returns OG tags for this specific UA (its own OG crawler).
    # Regular browser UAs return HTTP 400; mbasic also returns 400.
    try:
        resp = requests.get(
            profile_url,
            headers=FB_CRAWLER_HEADERS,
            timeout=15,
            verify=True,
            allow_redirects=True,
        )
        final_url = resp.url.lower()

        if "login" in final_url or "checkpoint" in final_url:
            result["security_notes"].append(
                "Profile required login to view — account is private, restricted, or suspended."
            )
        elif resp.status_code == 404:
            result["security_notes"].append("Account not found (404) — username may not exist.")
        elif resp.status_code in (400, 403):
            result["security_notes"].append(
                f"Facebook returned HTTP {resp.status_code} — page may not exist or this identifier is invalid."
            )
        elif resp.status_code == 200:
            result["exists"] = True
            result["data_sources"].append("OG Tags (facebookexternalhit)")
            html = resp.text
            og = _extract_og(html)

            # Canonical URL after redirect (e.g. cocacola → Coca-Cola)
            result["canonical_url"] = og.get("url") or resp.url
            result["profile_url"] = result["canonical_url"]

            # Display name
            title = og.get("title", "").strip()
            if title and title.lower() not in ("facebook", "error", ""):
                result["display_name"] = title
            if not result["display_name"]:
                m = re.search(r'<title>([^|<]{2,80})', html)
                if m:
                    name = m.group(1).strip()
                    if name.lower() not in ("facebook", "error"):
                        result["display_name"] = name

            # Profile picture
            result["profile_pic"] = og.get("image")

            # Numeric ID (from al:android:url — most reliable)
            result["numeric_id"] = _extract_numeric_id(html, og)

            # Account type from og:type
            og_type = og.get("type", "").lower()
            if "profile" in og_type:
                result["account_type"] = "Personal Profile"
            elif og_type in ("video.other", "website"):
                result["account_type"] = "Page / Business"
            elif "group" in og_type:
                result["account_type"] = "Group"
            elif og_type:
                result["account_type"] = og_type.replace(".", " ").title()

            # Parse og:description — contains likes/followers/talking_about + description text
            desc_raw = og.get("description", "")
            if desc_raw:
                parsed = _parse_og_description(desc_raw)
                result["likes_count"]     = parsed["likes"]
                result["follower_count"]  = parsed["followers_og"] or parsed["likes"]
                result["talking_about"]   = parsed["talking_about"]
                result["following_count"] = parsed["following"]
                result["description"]     = parsed["text"] or desc_raw[:400]

            if result.get("display_name"):
                result["is_public"] = True
            else:
                result["security_notes"].append(
                    "No public profile data in OG tags — personal profile with restricted visibility, "
                    "or the account name was not found."
                )
    except requests.exceptions.ConnectionError:
        result["security_notes"].append("Network error when connecting to Facebook.")
    except requests.exceptions.SSLError:
        result["security_notes"].append("SSL error — check network / proxy settings.")
    except Exception as e:
        result["security_notes"].append(f"Fetch error: {e}")

    # ── Graph API (pages, no access token required) ─────────────────────────
    _try_graph_api(result, identifier)

    # ── Facebook Scraper3 RapidAPI (optional enrichment) ─────────────────
    if fb_scraper_key:
        _try_facebook_scraper3(identifier, fb_scraper_key, result)
        time.sleep(SCRAPER3_DELAY)
        _try_facebook_scraper3_page_details(identifier, fb_scraper_key, result)
        time.sleep(SCRAPER3_DELAY)
        _try_facebook_scraper3_people(identifier, fb_scraper_key, result)
        time.sleep(SCRAPER3_DELAY)
        _try_facebook_scraper3_posts(identifier, fb_scraper_key, result)
        time.sleep(SCRAPER3_DELAY)
        _try_facebook_scraper3_search_posts(identifier, fb_scraper_key, result)

    # ── Cross-platform linked accounts ────────────────────────────────────
    result["linked_accounts"] = _extract_linked_socials(result)

    # ── Post pattern analysis ─────────────────────────────────────────────
    pattern = _analyze_post_patterns(result.get("recent_posts") or [])
    if pattern:
        result["post_pattern"] = pattern

    # ── Engagement metrics (requires follower count + posts) ──────────────
    if result["exists"]:
        _calculate_engagement_metrics(result)

    # ── Facebook Ad Library URL (public transparency tool) ────────────────
    if result.get("numeric_id"):
        result["ad_library_url"] = (
            f"https://www.facebook.com/ads/library/?id={result['numeric_id']}&media_type=all"
        )
    else:
        result["ad_library_url"] = (
            f"https://www.facebook.com/ads/library/?q={quote(identifier)}&search_type=page"
        )

    # ── Infer account type ─────────────────────────────────────────────────
    if not result.get("account_type"):
        if result.get("category"):
            result["account_type"] = "Page / Business"
        elif result.get("likes_count"):
            result["account_type"] = "Page / Business / Public Figure"
        else:
            result["account_type"] = "Unknown"

    # ── Security observations ──────────────────────────────────────────────
    if result["exists"]:
        if result.get("is_verified"):
            result["security_notes"].append(
                "Account has a verified badge (blue checkmark) — confirmed official identity."
            )

        pic = result.get("profile_pic") or ""
        if not pic or any(k in pic for k in ("silhouette", "default_pic", "static", "no_photo")):
            result["security_notes"].append(
                "Default or no profile picture — possible indicator of a fake or newly created account."
            )

        if identifier.isdigit():
            result["security_notes"].append(
                f"Numeric Facebook ID ({identifier}) is permanent — account can be tracked "
                "even if the username or display name changes."
            )

        name = result.get("display_name") or ""
        if name and sum(c.isdigit() for c in name) > max(2, len(name) // 3):
            result["security_notes"].append(
                "Display name contains many digits — possible indicator of an auto-generated or fake account."
            )

        if _SUSPICIOUS_USER_RE.match(identifier):
            result["security_notes"].append(
                "Username pattern (letters + many numbers/underscores) is typical of bot or auto-generated accounts."
            )

        followers = None
        for fc in (result.get("follower_count"), result.get("likes_count")):
            if fc and str(fc).isdigit():
                followers = int(fc)
                break
        if followers is not None and followers < 100:
            result["security_notes"].append(
                f"Very low engagement count ({followers:,}) — account may be newly created or rarely used."
            )

        brand_re = re.compile(
            r'(facebook|google|apple|tiktok|youtube|shopee|lazada|viettel|vnpay|zalo|momo)\d*',
            re.IGNORECASE,
        )
        if brand_re.search(identifier) and not result.get("is_verified"):
            result["security_notes"].append(
                "Username contains a well-known brand name but is NOT verified — possible impersonation account."
            )

        # ── Cover photo: business pages without a cover are suspicious ─────
        if not result.get("cover_photo") and result.get("account_type") in (
            "Page / Business", "Page / Business / Public Figure",
        ):
            result["security_notes"].append(
                "ℹ No cover photo detected for a business/page account — uncommon for legitimate brands."
            )

        # ── Star rating signal (business pages) ───────────────────────────
        if result.get("overall_star_rating") and result.get("rating_count"):
            star = result["overall_star_rating"]
            cnt  = result["rating_count"]
            if star < 2.0 and cnt > 50:
                result["security_notes"].append(
                    f"⚠ Very low public rating ({star}/5 from {cnt:,} reviews) — "
                    "may indicate fraudulent activity, poor service, or scam complaints."
                )
            elif star >= 4.5 and cnt < 20:
                result["security_notes"].append(
                    f"ℹ High rating ({star}/5) but only {cnt} reviews — "
                    "too few reviews to establish credibility; may be manipulated."
                )

        # ── Linked Instagram Business account ─────────────────────────────
        if result.get("instagram_business_id"):
            result["security_notes"].append(
                f"ℹ Linked Instagram Business account detected (ID: {result['instagram_business_id']}) — "
                "investigate the linked IG profile for additional context."
            )

        # ── Cross-platform linked accounts ────────────────────────────────
        for acct in result.get("linked_accounts") or []:
            result["security_notes"].append(
                f"ℹ Linked {acct['platform']} account found: @{acct['handle']} — "
                "expand cross-platform investigation."
            )

        # ── Post frequency anomaly ────────────────────────────────────────
        pat = result.get("post_pattern")
        if pat and pat.get("posts_per_day_est", 0) > 15:
            result["security_notes"].append(
                f"⚠ Very high posting frequency (~{pat['posts_per_day_est']} posts/day) — "
                "consistent with automated or bot-managed content distribution."
            )

        # ── Brand impersonation (Vietnamese & global brands) ─────────────
        if _BRAND_RE.search(identifier) and not result.get("is_verified"):
            result["security_notes"].append(
                "⚠ Username/vanity URL contains a known brand name but is NOT verified — "
                "high risk of impersonation or phishing targeting users of that brand."
            )

    elif not result.get("security_notes"):
        result["security_notes"].append(
            "Profile could not be fetched — account may be private, suspended, or the identifier is incorrect."
        )

    # ── Investigation dorks ─────────────────────────────────────────────────
    q = result.get("display_name") or identifier
    enc_q = quote(q)
    enc_id = quote(identifier)
    result["dorks"] = [
        {
            "label": "Profile on Facebook",
            "query": f'site:facebook.com "{identifier}"',
            "url": f'https://www.google.com/search?q=site%3Afacebook.com+%22{enc_id}%22',
        },
        {
            "label": "Cross-platform identity",
            "query": f'"{q}" site:facebook.com OR site:instagram.com OR site:tiktok.com',
            "url": f'https://www.google.com/search?q=%22{enc_q}%22+site%3Afacebook.com+OR+site%3Atiktok.com',
        },
        {
            "label": "Phone / email linked to name",
            "query": f'"{q}" phone OR email OR contact',
            "url": f'https://www.google.com/search?q=%22{enc_q}%22+phone+OR+email+OR+contact',
        },
        {
            "label": "Leaked data mentions",
            "query": f'"{q}" breach OR leak OR pastebin',
            "url": f'https://www.google.com/search?q=%22{enc_q}%22+breach+OR+leak+OR+pastebin',
        },
        {
            "label": "LinkedIn identity match",
            "query": f'site:linkedin.com "{q}"',
            "url": f'https://www.google.com/search?q=site%3Alinkedin.com+%22{enc_q}%22',
        },
        {
            "label": "News & media coverage",
            "query": f'"{q}" site:news.google.com OR inurl:article OR inurl:news',
            "url": f'https://news.google.com/search?q=%22{enc_q}%22',
        },
        {
            "label": "Archived / historical version",
            "query": f"Wayback Machine snapshots of this Facebook profile",
            "url": f"https://web.archive.org/web/*/{profile_url}",
        },
        {
            "label": "Facebook Ad Library — ads run by this page",
            "query": "Ad transparency: active/paused ads, spend range, reach regions",
            "url": result["ad_library_url"],
        },
        {
            "label": "Archive.today cached snapshot",
            "query": "archive.today / archive.ph cached version of this profile",
            "url": f"https://archive.ph/{quote(profile_url)}",
        },
        {
            "label": "Telegram & Pastebin mentions",
            "query": f'"{q}" site:t.me OR site:pastebin.com OR site:paste.ee',
            "url": f'https://www.google.com/search?q=%22{enc_q}%22+site%3At.me+OR+site%3Apastebin.com',
        },
        {
            "label": "Google Image Search — profile picture",
            "query": "Find other accounts reusing the same profile picture",
            "url": (
                f"https://lens.google.com/uploadbyurl?url={quote(result['profile_pic'])}"
                if result.get("profile_pic")
                else "https://lens.google.com/"
            ),
        },
    ]
    # ── Conditional dorks based on discovered contact data ─────────────────
    if result.get("email"):
        enc_email = quote(result["email"])
        result["dorks"].append({
            "label": "Email breach check — Have I Been Pwned",
            "query": f"Check if {result['email']} appeared in known data breaches",
            "url": f"https://haveibeenpwned.com/account/{enc_email}",
        })
    if result.get("phone"):
        enc_phone = quote(re.sub(r'\s+', '', result["phone"]))
        result["dorks"].append({
            "label": "Phone number cross-reference",
            "query": f'"{result["phone"]}" owner OR registration OR contact',
            "url": f'https://www.google.com/search?q=%22{enc_phone}%22+owner+OR+contact+OR+registration',
        })
    if result.get("website"):
        enc_site = quote(result["website"])
        result["dorks"].append({
            "label": "Website WHOIS / hosting lookup",
            "query": f"WHOIS and hosting info for {result['website']}",
            "url": f"https://www.whois.com/whois/{enc_site}",
        })

    # ── Breach intelligence enrichment ────────────────────────────────────
    # Runs automatically when email or phone was discovered in the profile.
    # Uses LeakCheck (free), BreachDirectory (keyed), HIBP (optional), IntelX (optional).
    if result.get("email") or result.get("phone"):
        console.print("[dim]  → Checking discovered contact data against breach databases...[/dim]")
        _enrich_breach_intel(
            result,
            breachdir_key=breachdir_key,
            hibp_key=hibp_key,
            intelx_key=intelx_key,
            dehashed_email=dehashed_email,
            dehashed_key=dehashed_key,
            snusbase_key=snusbase_key,
            emailrep_key=emailrep_key,
            hunter_key=hunter_key,
        )

    return result


# ─── TikTok ──────────────────────────────────────────────────────────────────

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

    # 1. TokAPI (preferred RapidAPI source)
    api_data = None
    if tokapi_key:
        api_data = _try_tiktok_tokapi(username, tokapi_key)
        if api_data:
            result["data_sources"].append("TokAPI")

    # 2. TikTok API23 (fallback RapidAPI source)
    if not api_data and tiktok_api_key:
        api_data = _try_tiktok_api23(username, tiktok_api_key)
        if api_data:
            result["data_sources"].append("TikTok API23")

    # Parse RapidAPI response fields
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

    # 3. oEmbed API — always attempt; fills gaps when no RapidAPI key is configured
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

    # ── Security observations ──────────────────────────────────────────────
    if not result["data_sources"]:
        result["security_notes"].append(
            "No API key configured — only oEmbed used. Add TOKAPI_KEY or TIKTOK_API_KEY to .env for full data."
        )
    if result["exists"]:
        if not result["profile_pic"]:
            result["security_notes"].append(
                "No profile picture detected — may be a new, blank, or private account."
            )
        if username.isdigit():
            result["security_notes"].append(
                "Numeric-only username — unusual, may indicate an auto-generated account."
            )
        if len(username) < 4:
            result["security_notes"].append(
                "Very short username — could be a reserved brand name or impersonation attempt."
            )
        if _SUSPICIOUS_USER_RE.match(username):
            result["security_notes"].append(
                "Username pattern (letters + many numbers/underscores) is typical of bot or auto-generated accounts."
            )
        brand_re = re.compile(r'(facebook|google|apple|tiktok|youtube|shopee|lazada|viettel|vnpay)\d+', re.IGNORECASE)
        if brand_re.search(username):
            result["security_notes"].append(
                "Username contains a well-known brand name with appended digits — possible impersonation account."
            )
    else:
        result["security_notes"].append(
            "TikTok account not found or profile is set to private."
        )

    # Generate dorks
    q = result["display_name"] or username
    result["dorks"] = [
        {
            "label": "TikTok profile search",
            "query": f'site:tiktok.com "@{username}"',
            "url": f'https://www.google.com/search?q=site%3Atiktok.com+%22%40{username}%22',
        },
        {
            "label": "Cross-platform identity",
            "query": f'"{q}" tiktok OR instagram OR facebook OR youtube',
            "url": f'https://www.google.com/search?q=%22{q.replace(" ", "+")}%22+tiktok+OR+instagram+OR+facebook',
        },
        {
            "label": "Leaked data / mentions",
            "query": f'"{q}" breach OR leak OR exposed OR data',
            "url": f'https://www.google.com/search?q=%22{q.replace(" ", "+")}%22+breach+OR+leak+OR+exposed',
        },
    ]
    return result


# ─── Print helpers ───────────────────────────────────────────────────────────

def print_facebook_results(data: dict):
    status_text = (
        "[green]✓ Public[/green]" if data["is_public"]
        else "[yellow]⚠ Exists (restricted)[/yellow]" if data["exists"]
        else "[red]✗ Not Found / Private[/red]"
    )
    console.print(f"\n[bold blue]═══ Facebook: {data['identifier']} ═══[/bold blue]")
    console.print(f"  URL          : [cyan]{data['profile_url']}[/cyan]")
    console.print(f"  Status       : {status_text}")

    if data.get("display_name"):
        verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
        console.print(f"  Display Name : [bold white]{data['display_name']}[/bold white]{verified}")
    if data.get("account_type"):
        console.print(f"  Account Type : {data['account_type']}")
    if data.get("category"):
        console.print(f"  Category     : {data['category']}")
    if data.get("numeric_id"):
        console.print(f"  Numeric ID   : [dim]{data['numeric_id']}[/dim]")

    # Engagement stats
    stats = []
    if data.get("follower_count"):
        stats.append(f"[cyan]{int(data['follower_count']):,}[/cyan] followers" if str(data["follower_count"]).isdigit()
                     else f"[cyan]{data['follower_count']}[/cyan] followers")
    if data.get("following_count"):
        stats.append(f"[cyan]{data['following_count']}[/cyan] following")
    if data.get("likes_count"):
        stats.append(f"[cyan]{data['likes_count']}[/cyan] likes")
    if data.get("talking_about"):
        stats.append(f"[cyan]{data['talking_about']}[/cyan] talking about this")
    if stats:
        console.print(f"  Stats        : {' | '.join(stats)}")

    # Engagement rate
    if data.get("engagement_rate") is not None:
        er = data["engagement_rate"]
        if er < 0.05 or er > 20.0:
            er_color = "red"
        elif er >= 1.0:
            er_color = "green"
        else:
            er_color = "yellow"
        ratio_str = (
            f"  (likes/flwr ratio: {data['like_follower_ratio']:.2f}\u00d7)"
            if data.get("like_follower_ratio") else ""
        )
        console.print(f"  Engagement   : [{er_color}]{er:.3f}% engagement rate[/{er_color}]{ratio_str}")

    # Post frequency
    pat = data.get("post_pattern")
    if pat:
        freq = pat.get("posts_per_day_est", 0)
        fc = "red" if freq > 15 else ("green" if freq >= 0.1 else "yellow")
        console.print(
            f"  Post Freq    : [{fc}]~{freq} posts/day[/{fc}]"
            f"  (sampled {pat['posts_scanned']} posts,"
            f" {pat['oldest_date']} \u2192 {pat['newest_date']})"
        )

    # Star rating (business pages)
    if data.get("overall_star_rating") and data.get("rating_count"):
        stars = "\u2605" * int(round(data["overall_star_rating"])) + "\u2606" * (5 - int(round(data["overall_star_rating"])))
        console.print(f"  Rating       : {data['overall_star_rating']}/5  {stars}  ({data['rating_count']:,} reviews)")

    # Identity fields
    if data.get("location"):
        console.print(f"  Location     : {data['location']}")
    if data.get("address"):
        console.print(f"  Address      : {data['address']}")
    if data.get("website"):
        console.print(f"  Website      : [cyan]{data['website']}[/cyan]")
    if data.get("email"):
        console.print(f"  Email        : [cyan]{data['email']}[/cyan]")
    if data.get("phone"):
        console.print(f"  Phone        : {data['phone']}")
    if data.get("founded"):
        console.print(f"  Founded      : {data['founded']}")
    if data.get("ad_library_url"):
        console.print(f"  Ad Library   : [link={data['ad_library_url']}][cyan]View Ad Transparency \u2197[/cyan][/link]")

    if data.get("description"):
        desc = data["description"][:200] + ("..." if len(data.get("description","")) > 200 else "")
        console.print(f"  About        : [dim]{desc}[/dim]")
    if data.get("general_info"):
        gi = data["general_info"][:200] + ("..." if len(data.get("general_info","")) > 200 else "")
        console.print(f"  General Info : [dim]{gi}[/dim]")
    if data.get("mission"):
        console.print(f"  Mission      : [dim]{data['mission'][:200]}[/dim]")

    if data.get("profile_pic"):
        console.print(f"  Profile Pic  : [link={data['profile_pic']}][cyan]View image ↗[/cyan][/link]")
    if data.get("cover_photo"):
        console.print(f"  Cover Photo  : [link={data['cover_photo']}][cyan]View image \u2197[/cyan][/link]")

    # Linked social accounts
    linked = data.get("linked_accounts") or []
    if linked:
        console.print(f"\n  [bold]Linked Social Accounts:[/bold]")
        for acct in linked:
            console.print(f"    [cyan]{acct['platform']}[/cyan]: @{acct['handle']}")

    # Recent posts table
    posts = data.get("recent_posts") or []
    if posts:
        avg = data.get("avg_engagement")
        avg_str = f"  (avg engagement: {avg:,})" if avg else ""
        console.print(f"\n  [bold]Recent Posts[/bold]{avg_str}:")
        from rich.table import Table
        tbl = Table(show_header=True, header_style="bold cyan", show_lines=False, padding=(0, 1))
        tbl.add_column("Date", style="dim", width=11)
        tbl.add_column("Type", width=6)
        tbl.add_column("Message", min_width=30, max_width=55)
        tbl.add_column("❤", justify="right", width=7)
        tbl.add_column("💬", justify="right", width=7)
        tbl.add_column("URL", min_width=18, max_width=40, style="cyan")
        for p in posts:
            msg = (p.get("message") or "")[:55] + ("…" if len(p.get("message") or "") > 55 else "")
            author_note = f" [dim]({p['author_name']})[/dim]" if p.get("author_name") else ""
            tbl.add_row(
                p.get("date") or "—",
                p.get("type") or "post",
                msg + author_note,
                str(p.get("reactions") or 0),
                str(p.get("comments") or 0),
                p.get("url") or "—",
            )
        console.print(tbl)

    if data["security_notes"]:
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    # ── Breach Intelligence section ───────────────────────────────────────
    bi = data.get("breach_intel")
    if bi:
        from rich.table import Table as _Table
        risk_color = bi.get("risk_color") or "dim"
        risk_level = bi.get("risk_level") or "UNKNOWN"
        score = bi.get("risk_score", 0)
        total = bi.get("total_breach_sources", 0)
        console.print(f"\n  [bold red]═ Breach / Leak Intelligence ═[/bold red]")
        if bi.get("email"):
            console.print(f"  Email checked : [cyan]{bi['email']}[/cyan]")
        if bi.get("phone"):
            console.print(f"  Phone checked : [cyan]{bi['phone']}[/cyan]")
        console.print(
            f"  Risk Level    : [{risk_color}]{risk_level}[/{risk_color}]"
            f"  (score: {score}/100, ~{total} breach source(s))"
        )

        # Alerts
        for alert in bi.get("alerts") or []:
            color = "bold red" if "CRITICAL" in alert or "⚠" in alert else "yellow"
            console.print(f"    [{color}]• {alert}[/{color}]")

        # Data classes exposed (BreachDirectory / HIBP)
        dc = bi.get("data_classes_exposed") or []
        if dc:
            console.print(f"  Data Exposed  : [red]{', '.join(dc)}[/red]")

        # LeakCheck email sources table
        lc_e = bi.get("leakcheck_email") or {}
        if lc_e.get("found") and lc_e.get("sources"):
            srcs = lc_e["sources"]
            console.print(f"\n  [bold]LeakCheck.io — Email sources ({len(srcs)}):[/bold]")
            t = _Table(show_header=False, box=None, padding=(0, 2))
            t.add_column("📁", style="dim")
            for s in srcs[:12]:
                t.add_row(str(s))
            console.print(t)
            if len(srcs) > 12:
                console.print(f"    [dim]... và {len(srcs) - 12} nguồn khác[/dim]")

        # LeakCheck phone sources
        lc_p = bi.get("leakcheck_phone") or {}
        if lc_p.get("found") and lc_p.get("sources"):
            srcs_p = lc_p["sources"]
            console.print(f"\n  [bold]LeakCheck.io — Phone sources ({len(srcs_p)}):[/bold]")
            t2 = _Table(show_header=False, box=None, padding=(0, 2))
            t2.add_column("📱", style="dim")
            for s in srcs_p[:10]:
                t2.add_row(str(s))
            console.print(t2)

        # BreachDirectory detailed records
        bd = bi.get("breachdirectory") or {}
        if bd.get("found") and bd.get("result"):
            records = bd["result"]
            size = bd.get("size") or len(records)
            console.print(f"\n  [bold]BreachDirectory — {size} bản ghi:[/bold]")
            bt = _Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
            bt.add_column("Nguồn", style="dim", min_width=18)
            bt.add_column("Trường dữ liệu bị lộ")
            bt.add_column("Hash type", style="dim", width=10)
            for entry in records[:15]:
                raw_src = entry.get("sources", [])
                src = raw_src[0] if isinstance(raw_src, list) and raw_src else str(raw_src or "?")
                fields = ", ".join(entry.get("fields", [])) or "—"
                h_type = entry.get("password_type", "—") or "—"
                bt.add_row(src, fields, h_type)
            console.print(bt)
            if size > 15:
                console.print(f"    [dim]... và {size - 15} bản ghi khác[/dim]")

        # HIBP breaches table
        hibp = bi.get("hibp") or {}
        if hibp.get("breaches"):
            breaches = hibp["breaches"]
            console.print(f"\n  [bold]HaveIBeenPwned — {len(breaches)} breach(es):[/bold]")
            ht = _Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
            ht.add_column("Breach", min_width=16)
            ht.add_column("Date", style="dim", width=11)
            ht.add_column("Records", justify="right", width=10)
            ht.add_column("Data Exposed")
            for b in breaches[:10]:
                cnt = f"{b.get('pwn_count', 0):,}" if b.get("pwn_count") else "?"
                dcs = ", ".join(b.get("data_classes", [])[:5])
                ht.add_row(b.get("name") or "?", b.get("date") or "?", cnt, dcs)
            console.print(ht)

        # IntelligenceX results
        ix = bi.get("intelx") or {}
        if ix and ix.get("total", 0) > 0:
            console.print(f"\n  [bold]IntelligenceX Phonebook ({ix['total']} selectors):[/bold]")
            if ix.get("emails"):
                console.print(f"    Emails  : {', '.join(ix['emails'][:8])}")
            if ix.get("phones"):
                console.print(f"    Phones  : {', '.join(ix['phones'][:8])}")
            if ix.get("domains"):
                console.print(f"    Domains : {', '.join(ix['domains'][:6])}")

        # Dehashed actual records
        dh = bi.get("dehashed") or {}
        dh_entries = dh.get("entries") or []
        if dh.get("found") and dh_entries:
            total_dh = dh.get("total", len(dh_entries))
            console.print(f"\n  [bold red]Dehashed — {total_dh} bản ghi thực tế:[/bold red]")
            dht = _Table(show_header=True, header_style="bold red", show_lines=True, padding=(0, 1))
            dht.add_column("Database", min_width=16, style="dim")
            dht.add_column("Email", min_width=20)
            dht.add_column("Tên thật", min_width=14)
            dht.add_column("Password / Hash", min_width=20)
            dht.add_column("SĐT", min_width=12)
            dht.add_column("IP", width=15)
            for e in dh_entries[:15]:
                pw = e.get("password") or ""
                hp = e.get("hashed_password") or ""
                pw_disp = pw if pw else (f"[dim]{hp[:24]}…[/dim]" if hp else "—")
                dht.add_row(
                    (e.get("database_name") or "?")[:20],
                    (e.get("email") or "—")[:28],
                    (e.get("name") or "—")[:16],
                    pw_disp,
                    (e.get("phone") or "—")[:14],
                    (e.get("ip_address") or "—")[:15],
                )
            console.print(dht)
            if total_dh > 15:
                console.print(f"    [dim]... và {total_dh - 15} bản ghi khác[/dim]")
        elif dh.get("note"):
            console.print(f"\n  [dim]Dehashed: {dh['note']}[/dim]")

        # Snusbase actual records
        sn = bi.get("snusbase") or {}
        sn_entries = sn.get("entries") or []
        if sn.get("found") and sn_entries:
            total_sn = sn.get("total", len(sn_entries))
            console.print(f"\n  [bold red]Snusbase — {total_sn} bản ghi thực tế:[/bold red]")
            snt = _Table(show_header=True, header_style="bold red", show_lines=True, padding=(0, 1))
            snt.add_column("Database", min_width=16, style="dim")
            snt.add_column("Email", min_width=22)
            snt.add_column("Username", min_width=14)
            snt.add_column("Password", min_width=18)
            snt.add_column("Hash / type", min_width=16)
            snt.add_column("IP", width=15)
            for e in sn_entries[:15]:
                h = e.get("hash") or ""
                ht_val = e.get("hash_type") or ""
                hash_disp = f"{h[:20]}… [{ht_val}]" if h else "—"
                snt.add_row(
                    (e.get("table") or "?")[:20],
                    (e.get("email") or "—")[:28],
                    (e.get("username") or "—")[:16],
                    (e.get("password") or "—")[:20],
                    hash_disp,
                    (e.get("ip") or "—")[:15],
                )
            console.print(snt)
            if total_sn > 15:
                console.print(f"    [dim]... và {total_sn - 15} bản ghi khác[/dim]")
        elif sn.get("note"):
            console.print(f"\n  [dim]Snusbase: {sn['note']}[/dim]")

        # Extracted leaked data summary
        names = bi.get("associated_names") or []
        phones = bi.get("associated_phones") or []
        addrs = bi.get("associated_addresses") or []
        ips = bi.get("associated_ips") or []
        hashes = bi.get("leaked_hashes") or []
        if any([names, phones, addrs, ips, hashes]):
            console.print(f"\n  [bold yellow]Dữ liệu trích xuất từ breach records:[/bold yellow]")
            if names:
                console.print(f"    Tên thật tìm thấy : [bold]{', '.join(names[:8])}[/bold]")
            if phones:
                console.print(f"    Điện thoại liên kết: [red]{', '.join(phones[:8])}[/red]")
            if addrs:
                console.print(f"    Địa chỉ liên kết  : [red]{', '.join(addrs[:5])}[/red]")
            if ips:
                console.print(f"    IP liên kết       : [yellow]{', '.join(ips[:8])}[/yellow]")
            if hashes:
                pw_sources = list({h["source"] for h in hashes if h.get("password")})
                hash_sources = list({h["source"] for h in hashes if h.get("hash")})
                if pw_sources:
                    console.print(f"    Plaintext pw leaks: [bold red]{', '.join(pw_sources[:5])}[/bold red]")
                if hash_sources:
                    console.print(f"    Hash pw leaks     : [red]{', '.join(hash_sources[:5])}[/red]")

        # Holehe — registered sites
        ho = bi.get("holehe") or {}
        ho_sites = ho.get("registered_sites") or bi.get("registered_sites") or []
        if ho_sites:
            console.print(f"\n  [bold]Holehe — email đăng ký trên {len(ho_sites)} dịch vụ:[/bold]")
            hot = _Table(show_header=False, box=None, padding=(0, 2))
            hot.add_column("🌐", style="cyan", min_width=18)
            hot.add_column("Domain", style="dim")
            for s in ho_sites:
                hot.add_row(s.get("name", "?"), s.get("domain", ""))
            console.print(hot)
        elif ho.get("note"):
            console.print(f"\n  [dim]Holehe: {ho['note']}[/dim]")

        # EmailRep signals
        er = bi.get("emailrep") or {}
        if er and not er.get("error"):
            rep = er.get("reputation") or "unknown"
            sus = er.get("suspicious")
            rep_color = "red" if sus else ("yellow" if rep in ("low", "none") else "green")
            console.print(f"\n  [bold]EmailRep.io:[/bold]  Reputation [{rep_color}]{rep}[/{rep_color}]  Suspicious: [{rep_color}]{sus}[/{rep_color}]  References: {er.get('references', 0)}")
            er_flags = []
            if er.get("blacklisted"):        er_flags.append("[bold red]Blacklisted[/bold red]")
            if er.get("credentials_leaked"):  er_flags.append("[red]Credentials leaked[/red]")
            if er.get("data_breach"):         er_flags.append("[red]Data breach[/red]")
            if er.get("malicious_activity"):  er_flags.append("[red]Malicious activity[/red]")
            if er_flags:
                console.print("    Flags : " + "  ".join(er_flags))
            if er.get("profiles"):
                console.print(f"    Profiles: [cyan]{', '.join(er['profiles'][:8])}[/cyan]")

        # Hunter.io person enrichment
        hu = bi.get("hunter") or {}
        if hu and hu.get("found") and not hu.get("error"):
            name = " ".join(filter(None, [hu.get("first_name"), hu.get("last_name")])) or "?"
            console.print(f"\n  [bold]Hunter.io enrichment:[/bold]  Tên: [bold]{name}[/bold]")
            if hu.get("position"):     console.print(f"    Chức danh : {hu['position']}")
            if hu.get("organization"): console.print(f"    Công ty   : {hu['organization']}")
            if hu.get("phone_number"): console.print(f"    Điện thoại: [red]{hu['phone_number']}[/red]")
            if hu.get("linkedin"):     console.print(f"    LinkedIn  : [cyan]{hu['linkedin']}[/cyan]")
            if hu.get("twitter"):      console.print(f"    Twitter   : [cyan]@{hu['twitter']}[/cyan]")

        # Manual search links for tools we can't auto-query
        console.print("\n  [bold]Manual Breach Lookup Links:[/bold]")
        if bi.get("email"):
            enc = quote(bi["email"])
            console.print(f"    Dehashed    : [link=https://www.dehashed.com/search?query={enc}][cyan]Search '{bi['email']}' ↗[/cyan][/link]")
            console.print(f"    Snusbase    : [link=https://snusbase.com/][cyan]snusbase.com ↗[/cyan][/link]")
            console.print(f"    IntelX      : [link=https://intelx.io/?s={enc}][cyan]intelx.io ↗[/cyan][/link]")
        if bi.get("phone"):
            enc_ph = quote(bi["phone"])
            console.print(f"    Phone OSINT : [link=https://www.google.com/search?q=%22{enc_ph}%22+owner+OR+name+OR+address][cyan]Google ↗[/cyan][/link]")

    if data["dorks"]:
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
            console.print(f"      [link={d['url']}][blue]Open ↗[/blue][/link]")


def print_tiktok_results(data: dict):
    status_text = (
        "[green]✓ Public[/green]" if data["is_public"]
        else "[red]✗ Not Found / Private[/red]"
    )
    console.print(f"\n[bold red]═══ TikTok: @{data['username']} ═══[/bold red]")
    console.print(f"  URL          : [cyan]{data['profile_url']}[/cyan]")
    console.print(f"  Status       : {status_text}")
    if data.get("display_name"):
        verified = " [bold yellow]✓ Verified[/bold yellow]" if data.get("is_verified") else ""
        console.print(f"  Display Name : [bold white]{data['display_name']}[/bold white]{verified}")
    if data.get("bio"):
        console.print(f"  Bio          : [dim]{data['bio'][:160]}[/dim]")
    if data.get("region"):
        console.print(f"  Region       : {data['region']}")

    # Stats row
    stats = []
    if data.get("follower_count") is not None:
        fc = data["follower_count"]
        stats.append(f"[cyan]{fc:,}[/cyan] followers" if isinstance(fc, int) else f"[cyan]{fc}[/cyan] followers")
    if data.get("following_count") is not None:
        fwg = data["following_count"]
        stats.append(f"[cyan]{fwg:,}[/cyan] following" if isinstance(fwg, int) else f"[cyan]{fwg}[/cyan] following")
    if data.get("likes_count") is not None:
        lc = data["likes_count"]
        stats.append(f"[cyan]{lc:,}[/cyan] likes" if isinstance(lc, int) else f"[cyan]{lc}[/cyan] likes")
    if data.get("video_count") is not None:
        vc = data["video_count"]
        stats.append(f"[cyan]{vc:,}[/cyan] videos" if isinstance(vc, int) else f"[cyan]{vc}[/cyan] videos")
    if stats:
        console.print(f"  Stats        : {' | '.join(stats)}")

    if data.get("profile_pic"):
        console.print(f"  Profile Pic  : [link={data['profile_pic']}][cyan]View image ↗[/cyan][/link]")
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


# ─────────────────────────────────────────────
# Instagram Recon
# ─────────────────────────────────────────────

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


def _generate_ig_dorks(username: str) -> list:
    encoded = requests.utils.quote(username)
    dorks = [
        {"label": "Instagram profile", "query": f'site:instagram.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Ainstagram.com+%22{encoded}%22"},
        {"label": "Cached / indexed posts", "query": f'instagram.com/{username}',
         "url": f"https://www.google.com/search?q=instagram.com%2F{encoded}"},
        {"label": "Mentioned elsewhere", "query": f'"{username}" instagram',
         "url": f"https://www.google.com/search?q=%22{encoded}%22+instagram"},
    ]
    return dorks


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

        if data.get("profile_pic"):
            console.print(f"  Profile Pic: [link={data['profile_pic']}][cyan]View image ↗[/cyan][/link]")
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


# ─────────────────────────────────────────────
# Twitter / X Recon
# ─────────────────────────────────────────────

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
            # Extract expanded URLs from entities
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


def _generate_tw_dorks(username: str) -> list:
    encoded = requests.utils.quote(username)
    dorks = [
        {"label": "Twitter profile", "query": f'site:twitter.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Atwitter.com+%22{encoded}%22"},
        {"label": "Mentions / references", "query": f'"@{username}" twitter',
         "url": f"https://www.google.com/search?q=%22%40{encoded}%22+twitter"},
        {"label": "Cached tweets", "query": f'site:x.com "{username}"',
         "url": f"https://www.google.com/search?q=site%3Ax.com+%22{encoded}%22"},
    ]
    return dorks


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


# ─────────────────────────────────────────────────────────────────────────────
# Reddit Recon — no API key required, uses public JSON endpoints
# ─────────────────────────────────────────────────────────────────────────────

REDDIT_HEADERS = {
    "User-Agent": "OSINT-Tool/1.0 (Educational Research; github.com/osint-tool)",
    "Accept": "application/json",
}


def _reddit_dorks(username: str) -> list:
    base = "https://www.google.com/search?q="
    return [
        {"label": "All Reddit activity", "query": f'site:reddit.com u/{username}',
         "url": f"{base}{quote(f'site:reddit.com u/{username}')}"},
        {"label": "Posts & comments",    "query": f'site:reddit.com/user/{username}',
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

    # --- About ---
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
            if result["is_nsfw"]:
                result["security_notes"].append("Profile is marked NSFW")
            if result["is_employee"]:
                result["security_notes"].append("Reddit employee account")
        elif r.status_code == 403:
            result["security_notes"].append("Profile is private or suspended (HTTP 403)")
        else:
            result["security_notes"].append(f"Unexpected HTTP {r.status_code} from about endpoint")
    except Exception as e:
        result["security_notes"].append(f"about.json error: {e}")

    if not result["exists"]:
        return result

    # --- Recent Posts ---
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

    # --- Recent Comments ---
    try:
        r = requests.get(
            f"https://www.reddit.com/user/{username}/comments.json",
            headers=REDDIT_HEADERS,
            params={"limit": 5, "sort": "new"},
            timeout=10,
        )
        if r.status_code == 200:
            children = r.json().get("data", {}).get("children", [])
            comments = []
            for child in children:
                c = child.get("data", {})
                comments.append({
                    "body": c.get("body", "")[:200],
                    "subreddit": c.get("subreddit"),
                    "score": c.get("score", 0),
                    "url": f"https://www.reddit.com{c.get('permalink', '')}",
                    "date": datetime.fromtimestamp(c.get("created_utc", 0), tz=timezone.utc).strftime("%Y-%m-%d") if c.get("created_utc") else None,
                })
            result["recent_comments"] = comments
    except Exception as e:
        result["security_notes"].append(f"comments.json error: {e}")

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

        badges = []
        if data.get("is_employee"):   badges.append("[bold red]Reddit Employee[/bold red]")
        if data.get("is_gold"):       badges.append("[bold yellow]Gold[/bold yellow]")
        if data.get("is_mod"):        badges.append("[bold green]Moderator[/bold green]")
        if data.get("is_nsfw"):       badges.append("[bold red]NSFW[/bold red]")
        if badges:
            console.print(f"  Badges    : {' | '.join(badges)}")

        ck = data.get("comment_karma", 0)
        lk = data.get("link_karma", 0)
        tk = data.get("total_karma", ck + lk)
        console.print(f"  Karma     : [cyan]{tk:,}[/cyan] total  ([dim]{lk:,} post | {ck:,} comment[/dim])")

        if data.get("subscribers"):
            console.print(f"  Followers : [cyan]{data['subscribers']:,}[/cyan]")

        if data.get("subreddits_posted"):
            subs = ", ".join(f"r/{s}" for s in data["subreddits_posted"][:12])
            extra = f" (+{len(data['subreddits_posted'])-12} more)" if len(data["subreddits_posted"]) > 12 else ""
            console.print(f"  Active in : [dim]{subs}{extra}[/dim]")

        if data.get("icon_img"):
            clean_icon = data["icon_img"].split("?")[0]
            console.print(f"  Avatar    : [link={clean_icon}][cyan]View image ↗[/cyan][/link]")

        if data.get("recent_posts"):
            console.print(f"\n  [bold]Recent Posts ({len(data['recent_posts'])}):[/bold]")
            for p in data["recent_posts"][:5]:
                nsfw = " [red][NSFW][/red]" if p.get("is_nsfw") else ""
                console.print(
                    f"    [dim]{p.get('date','?')}[/dim] "
                    f"[cyan]r/{p['subreddit']}[/cyan]{nsfw} — "
                    f"{p['title']} "
                    f"[dim](↑{p.get('score',0)} | 💬{p.get('num_comments',0)})[/dim]"
                )

        if data.get("recent_comments"):
            console.print(f"\n  [bold]Recent Comments ({len(data['recent_comments'])}):[/bold]")
            for c in data["recent_comments"][:3]:
                body = c.get("body", "").replace("\n", " ")[:100]
                console.print(
                    f"    [dim]{c.get('date','?')}[/dim] "
                    f"[cyan]r/{c.get('subreddit','?')}[/cyan] — "
                    f"[dim]{body}[/dim] "
                    f"[dim](↑{c.get('score',0)})[/dim]"
                )

    if data.get("security_notes"):
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

    if data.get("dorks"):
        console.print("\n  [bold]Investigation Dorks:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [dim]{d['label']}[/dim]: [cyan]{d['query']}[/cyan]")
            console.print(f"      [link={d['url']}][blue]Open in Google ↗[/blue][/link]")


# ─── Bot / Fake Account Detection ────────────────────────────────────────────

def detect_suspicious_account(profile: dict, platform: str = "unknown") -> dict:
    """
    Phân tích các dấu hiệu tài khoản giả/bot dựa trên metadata profile.

    Args:
        profile:  Dict chứa profile data (từ bất kỳ platform nào)
        platform: Tên nền tảng (để tùy chỉnh phân tích)

    Returns dict:
        suspicion_score: 0-100 (0=bình thường, 100=rất đáng ngờ)
        risk_level: CLEAN / LOW / MEDIUM / HIGH / SUSPICIOUS
        indicators: danh sách dấu hiệu bất thường phát hiện được
        positive_signals: dấu hiệu cho thấy tài khoản thật
    """
    indicators = []
    positive_signals = []
    score = 0

    username = str(profile.get("username") or profile.get("name") or "")
    followers = profile.get("followers") or profile.get("follower_count") or 0
    following = profile.get("following") or profile.get("following_count") or 0
    bio = profile.get("bio") or profile.get("description") or profile.get("about") or ""
    verified = profile.get("verified") or False
    post_count = profile.get("post_count") or profile.get("video_count") or profile.get("tweet_count") or 0
    created_at = profile.get("created_at") or profile.get("joined") or None

    try:
        followers = int(followers)
        following = int(following)
        post_count = int(post_count)
    except (ValueError, TypeError):
        followers = following = post_count = 0

    # Username analysis
    if username:
        if re.match(r'^[a-z]{2,6}[0-9]{4,}$', username.lower()):
            score += 15
            indicators.append(f"Username pattern ngẫu nhiên: '{username}' (chữ + nhiều số)")
        if len(username) > 20 and sum(1 for c in username if c.isdigit()) > 5:
            score += 10
            indicators.append(f"Username quá dài với nhiều số ({len(username)} ký tự)")

    # Follower/Following ratio
    if following > 0:
        ratio = followers / following
        if following > 5000 and followers < 100:
            score += 30
            indicators.append(
                f"Following rất cao ({following:,}) nhưng follower thấp ({followers:,}) — dấu hiệu follow spam"
            )
        elif following > 2000 and ratio < 0.1:
            score += 20
            indicators.append(f"Tỷ lệ follower/following thấp ({ratio:.2f}) — có thể mua follower hoặc bot")
        elif ratio > 100 and followers > 100000:
            positive_signals.append(f"Tỷ lệ follower/following cao ({ratio:.0f}x) — dấu hiệu tài khoản uy tín")

    # Bio analysis
    if not bio or len(bio.strip()) == 0:
        score += 10
        indicators.append("Bio trống — tài khoản thiếu thông tin cá nhân")
    elif len(bio) < 10:
        score += 5
        indicators.append(f"Bio quá ngắn ('{bio}')")
    else:
        positive_signals.append("Có bio đầy đủ")

    # Verification status
    if verified:
        score -= 20
        positive_signals.append("Tài khoản đã được xác minh (verified badge)")

    # Post count vs followers
    if post_count == 0 and followers > 1000:
        score += 25
        indicators.append(f"Không có bài đăng nhưng có {followers:,} followers — dấu hiệu mua follower")
    elif post_count > 0 and followers > 0:
        posts_per_follower = followers / post_count
        if posts_per_follower > 10000:
            score += 15
            indicators.append(
                f"Tỷ lệ follower/post bất thường ({posts_per_follower:.0f}/post) — có thể fake followers"
            )

    # Profile picture
    profile_pic = (
        profile.get("profile_picture") or profile.get("avatar") or
        profile.get("profile_image_url") or profile.get("thumbnail") or ""
    )
    if not profile_pic:
        score += 10
        indicators.append("Không có ảnh đại diện")

    # Account age
    if created_at:
        try:
            if isinstance(created_at, str):
                for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d", "%a %b %d %H:%M:%S %z %Y"):
                    try:
                        dt = datetime.strptime(created_at[:25], fmt)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        age_days = (datetime.now(timezone.utc) - dt).days
                        if age_days < 30:
                            score += 20
                            indicators.append(f"Tài khoản mới tạo (chỉ {age_days} ngày trước)")
                        elif age_days < 180:
                            score += 5
                            indicators.append(f"Tài khoản dưới 6 tháng tuổi ({age_days} ngày)")
                        elif age_days > 730:
                            positive_signals.append(f"Tài khoản lâu đời ({age_days // 365} năm)")
                        break
                    except ValueError:
                        continue
        except Exception:
            pass

    score = max(0, min(100, score))

    if score >= 60:
        risk_level = "SUSPICIOUS"
        color = "bold red"
    elif score >= 40:
        risk_level = "HIGH"
        color = "red"
    elif score >= 20:
        risk_level = "MEDIUM"
        color = "yellow"
    elif score > 0:
        risk_level = "LOW"
        color = "cyan"
    else:
        risk_level = "CLEAN"
        color = "green"

    return {
        "platform": platform,
        "suspicion_score": score,
        "risk_level": risk_level,
        "color": color,
        "indicators": indicators,
        "positive_signals": positive_signals,
    }


def print_account_analysis(analysis: dict):
    """Hiển thị kết quả phân tích bot/fake account."""
    score = analysis.get("suspicion_score", 0)
    risk = analysis.get("risk_level", "UNKNOWN")
    color = analysis.get("color", "white")
    platform = analysis.get("platform", "")

    label = f"[{platform}] " if platform and platform != "unknown" else ""
    console.print(f"\n  [bold]🔍 {label}Bot/Fake Account Analysis:[/bold]")
    console.print(f"  Suspicion Score: [{color}]{score}/100 — {risk}[/{color}]")

    indicators = analysis.get("indicators", [])
    positives = analysis.get("positive_signals", [])

    if indicators:
        console.print("  [bold yellow]Dấu hiệu đáng ngờ:[/bold yellow]")
        for ind in indicators:
            console.print(f"    [yellow]⚠ {ind}[/yellow]")

    if positives:
        console.print("  [bold green]Tín hiệu tích cực:[/bold green]")
        for pos in positives:
            console.print(f"    [green]✓ {pos}[/green]")

    if not indicators and not positives:
        console.print("  [dim]Không đủ dữ liệu để phân tích[/dim]")
