"""Shared constants and helpers for social media recon modules."""
import re
import requests

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

# facebookexternalhit UA — the only one Facebook returns OG data for
FB_CRAWLER_HEADERS = {
    "User-Agent": "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Accept-Language": "en-US,en;q=0.9,vi;q=0.8",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Suspicious username pattern
SUSPICIOUS_USER_RE = re.compile(r'^[a-z]{2,}[_\d]{4,}$', re.IGNORECASE)

# Social media URL patterns for cross-platform footprint extraction
SOCIAL_LINK_PATTERNS = [
    ("Instagram",  re.compile(r'instagram\.com/([A-Za-z0-9_][A-Za-z0-9_.]{0,29})(?:[/?]|$|\s)', re.I)),
    ("Twitter/X",  re.compile(r'(?:twitter|x)\.com/([A-Za-z0-9_]{1,20})(?:[/?]|$|\s)', re.I)),
    ("YouTube",    re.compile(r'youtube\.com/(?:c/|channel/|@)([A-Za-z0-9_.\-]{1,60})', re.I)),
    ("TikTok",     re.compile(r'tiktok\.com/@([A-Za-z0-9_.]{2,30})', re.I)),
    ("LinkedIn",   re.compile(r'linkedin\.com/(?:in|company)/([A-Za-z0-9_\-]{1,60})', re.I)),
    ("Telegram",   re.compile(r't(?:elegram)?\.me/([A-Za-z0-9_]{3,32})', re.I)),
    ("Zalo",       re.compile(r'zalo\.me/([A-Za-z0-9_\-]{3,30})', re.I)),
]

BRAND_RE = re.compile(
    r'\b(vietcombank|agribank|bidv|techcombank|vpbank|mbbank|sacombank|acb|tpbank|'
    r'momo|zalopay|vnpay|shopeepay|viettel|mobifone|vinaphone|shopee|lazada|tiki|sendo|'
    r'facebook|google|apple|tiktok|youtube|zalo|vnptwallet)\b',
    re.IGNORECASE,
)


def make_dork(label: str, query: str) -> dict:
    """Return a dork dict with a pre-built Google search URL."""
    encoded = requests.utils.quote(query)
    return {
        "label": label,
        "query": query,
        "url": f"https://www.google.com/search?q={encoded}",
    }
