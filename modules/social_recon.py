"""
Social Media Recon Module
Gathers public OSINT data from Facebook and TikTok profiles.
Uses only public endpoints and Open Graph metadata — no authentication required.
For security research and investigation purposes only.
"""
import json
import re
import html as _html_lib
import requests
from rich.console import Console

console = Console()

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

_OG_RE = re.compile(
    r'<meta\s+(?:property|name)=["\']og:([^"\']+)["\']\s+content=["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_OG_RE2 = re.compile(
    r'<meta\s+content=["\']([^"\']*)["\'\s]+(?:property|name)=["\']og:([^"\']+)["\']',
    re.IGNORECASE,
)

# Patterns for IDs embedded in Facebook's JS bundles
_PAGE_ID_RE   = re.compile(r'"pageID"\s*:\s*"(\d+)"')
_USER_ID_RE   = re.compile(r'"userID"\s*:\s*"(\d+)"')
_ENTITY_ID_RE = re.compile(r'"entity_id"\s*:\s*"(\d+)"')
_PROFILE_ID_RE = re.compile(r'"profile_id"\s*:\s*(\d{5,})')
_ACTORID_RE   = re.compile(r'"actorID"\s*:\s*"(\d+)"')

# Suspicious username pattern
_SUSPICIOUS_USER_RE = re.compile(r'^[a-z]{2,}[_\d]{4,}$', re.IGNORECASE)

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
    """Extract Facebook username or numeric ID from a URL or bare string."""
    if "facebook.com/" in identifier:
        identifier = identifier.rstrip("/").split("facebook.com/")[-1]
        if identifier.startswith("profile.php"):
            m = re.search(r'id=(\d+)', identifier)
            identifier = m.group(1) if m else identifier
        else:
            identifier = identifier.split("?")[0].split("#")[0]
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
    """
    info = {"likes": None, "followers_og": None, "following": None, "talking_about": None, "text": desc}

    m = re.search(r'([\d,]+)\s*likes?\s*[·•]\s*([\d,]+)\s*talking about this', desc, re.IGNORECASE)
    if m:
        info["likes"] = m.group(1).replace(",", "")
        info["talking_about"] = m.group(2).replace(",", "")

    m = re.search(r'([\d,]+)\s*followers?\s*[·•]\s*([\d,]+)\s*following', desc, re.IGNORECASE)
    if m:
        info["followers_og"] = m.group(1).replace(",", "")
        info["following"] = m.group(2).replace(",", "")

    if not info["followers_og"]:
        m = re.search(r'([\d,]+)\s*(?:followers?|ng\u01b0\u1eddi theo d\u00f5i)', desc, re.IGNORECASE)
        if m:
            info["followers_og"] = m.group(1).replace(",", "")

    # Strip engagement numbers to get the actual description text
    clean = re.sub(r'[\d,]+\s*(?:likes?|followers?|following|talking about this)[^\n.]*[·•]?\s*', '', desc).strip()
    clean = re.sub(r'^[^\s.]{1,80}\.\s*', '', clean).strip()  # strip leading "PageName. " prefix
    clean = re.sub(r'^[\s.·•,]+', '', clean).strip()           # strip any remaining leading punctuation
    if clean and len(clean) > 5:
        info["text"] = clean
    return info


def _try_graph_api(result: dict, identifier: str):
    """Try Facebook Graph API without access token — returns limited data for public pages."""
    try:
        r = requests.get(
            f"https://graph.facebook.com/v21.0/{identifier}",
            params={
                "fields": (
                    "name,category,description,about,fan_count,followers_count,"
                    "website,phone,location,is_verified,cover,picture,general_info,"
                    "link,verification_status,founded,single_line_address,emails"
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
        result["data_sources"].append("Facebook Scraper3")
    except Exception:
        pass


# ─── Facebook ────────────────────────────────────────────────────────────────

def facebook_recon(identifier: str, fb_scraper_key: str | None = None) -> dict:
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
        "general_info": None,
        "mission": None,
        "data_sources": [],
        "security_notes": [],
        "dorks": [],
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

    elif not result.get("security_notes"):
        result["security_notes"].append(
            "Profile could not be fetched — account may be private, suspended, or the identifier is incorrect."
        )

    # ── Investigation dorks ─────────────────────────────────────────────────
    q = result.get("display_name") or identifier
    enc_q = q.replace(" ", "+")
    enc_id = identifier.replace(" ", "+")
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
            "label": "Reverse image search profile pic",
            "query": "Find accounts sharing the same profile picture",
            "url": (
                f"https://www.google.com/searchbyimage?image_url={result['profile_pic']}"
                if result.get("profile_pic")
                else "https://images.google.com/"
            ),
        },
    ]
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
        stats.append(f"[cyan]{int(data['follower_count']):,}[/cyan] followers" if data["follower_count"].isdigit()
                     else f"[cyan]{data['follower_count']}[/cyan] followers")
    if data.get("friend_count"):
        stats.append(f"[cyan]{data['friend_count']}[/cyan] friends")
    if data.get("posts_count"):
        stats.append(f"[cyan]{data['posts_count']}[/cyan] posts")
    if stats:
        console.print(f"  Stats        : {' | '.join(stats)}")

    # Identity fields
    if data.get("location"):
        console.print(f"  Location     : {data['location']}")
    if data.get("hometown"):
        console.print(f"  Hometown     : {data['hometown']}")
    if data.get("work_education"):
        console.print(f"  Work/Edu     : {data['work_education']}")
    if data.get("website"):
        console.print(f"  Website      : [cyan]{data['website']}[/cyan]")
    if data.get("email"):
        console.print(f"  Email        : [cyan]{data['email']}[/cyan]")
    if data.get("phone"):
        console.print(f"  Phone        : {data['phone']}")
    if data.get("founded"):
        console.print(f"  Founded      : {data['founded']}")
    if data.get("joined"):
        console.print(f"  Joined       : {data['joined']}")

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
        console.print(f"  Cover Photo  : [link={data['cover_photo']}][cyan]View image ↗[/cyan][/link]")

    if data["security_notes"]:
        console.print("\n  [bold yellow]⚠ Security Observations:[/bold yellow]")
        for note in data["security_notes"]:
            console.print(f"    [yellow]• {note}[/yellow]")

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
