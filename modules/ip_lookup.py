"""
IP & Domain Intelligence Module
- IP geolocation (ip-api.com - free, no key required)
- ASN / ISP info
- Shodan link generation
- Reverse IP lookup via HackerTarget (free tier)
- HTTP Security Headers Scoring
- Tech stack detection
"""
import time
import requests
from rich.console import Console
from rich.table import Table

console = Console()
HEADERS = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}

# Security header scoring weights
_SEC_HEADERS = {
    "strict-transport-security": ("HSTS", 20),
    "content-security-policy": ("CSP", 25),
    "x-frame-options": ("X-Frame-Options", 15),
    "x-content-type-options": ("X-Content-Type-Options", 10),
    "referrer-policy": ("Referrer-Policy", 10),
    "permissions-policy": ("Permissions-Policy", 10),
    "x-xss-protection": ("X-XSS-Protection", 10),
}

# Tech fingerprinting signatures
_TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Joomla": ["joomla", "/components/com_"],
    "Drupal": ["drupal", "sites/default/files"],
    "Laravel": ["laravel_session", "x-powered-by: laravel"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "ASP.NET": ["asp.net", "__viewstate", "x-powered-by: asp.net"],
    "PHP": ["x-powered-by: php", "phpsessid"],
    "React": ["__react", "data-reactroot", "_next"],
    "Vue.js": ["__vue", "data-v-"],
    "Angular": ["ng-version", "_angular"],
    "Cloudflare": ["cf-ray", "cloudflare"],
    "Nginx": ["server: nginx"],
    "Apache": ["server: apache"],
    "IIS": ["server: microsoft-iis", "x-powered-by: asp.net"],
    "Shopify": ["shopify", "cdn.shopify.com"],
    "Wix": ["wix.com", "wixsite.com"],
}


def ip_geolocation(ip_or_domain: str) -> dict:
    """Free geolocation via ip-api.com (no API key needed, 45 req/min limit).
    Includes exponential backoff on 429 rate-limit responses.
    """
    url = (
        f"http://ip-api.com/json/{ip_or_domain}"
        "?fields=status,message,country,countryCode,region,regionName,city,zip,"
        "lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    )
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code == 429:
                wait = 2 ** attempt
                console.print(f"  [yellow]ip-api.com rate limited — retrying in {wait}s...[/yellow]")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                return {"success": True, "data": data}
            return {"success": False, "error": data.get("message", "Unknown error")}
        except Exception as e:
            if attempt == 2:
                return {"success": False, "error": str(e)}
            time.sleep(2 ** attempt)
    return {"success": False, "error": "Max retries exceeded"}


def reverse_ip_lookup(ip: str) -> list:
    """Find domains hosted on same IP via HackerTarget free API."""
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code == 200 and "error" not in resp.text.lower():
            domains = [d.strip() for d in resp.text.splitlines() if d.strip()]
            return domains
    except Exception:
        pass
    return []


def get_headers_info(domain: str) -> dict:
    """Grab HTTP headers from target for tech fingerprinting and security scoring."""
    result = {}
    for scheme in ("https", "http"):
        try:
            resp = requests.head(
                f"{scheme}://{domain}", headers=HEADERS, timeout=8,
                allow_redirects=True, verify=True
            )
            interesting = [
                "server", "x-powered-by", "x-generator", "cf-ray",
                "x-frame-options", "strict-transport-security",
                "content-security-policy", "x-content-type-options",
                "referrer-policy", "permissions-policy", "x-xss-protection",
            ]
            for h in interesting:
                if h in resp.headers:
                    result[h] = resp.headers[h]
            result["_status_code"] = resp.status_code
            result["_final_url"] = str(resp.url)
            result["_scheme"] = scheme
            break
        except Exception:
            continue
    return result


def score_security_headers(headers: dict) -> dict:
    """Score HTTP security headers. Returns score 0-100 and grade A-F."""
    if not headers:
        return {"score": 0, "grade": "F", "present": [], "missing": list(_SEC_HEADERS.keys())}

    present = []
    missing = []
    score = 0
    h_lower = {k.lower(): v for k, v in headers.items()}

    for header, (label, weight) in _SEC_HEADERS.items():
        if header in h_lower:
            present.append({"header": header, "label": label, "value": h_lower[header][:80]})
            score += weight
        else:
            missing.append({"header": header, "label": label})

    if score >= 90:
        grade = "A+"
    elif score >= 75:
        grade = "A"
    elif score >= 60:
        grade = "B"
    elif score >= 40:
        grade = "C"
    elif score >= 20:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade, "present": present, "missing": missing}


def detect_tech_stack(domain: str, existing_headers: dict = None) -> dict:
    """Detect CMS, framework, server tech from HTTP headers + HTML body."""
    detected = []
    headers_lower = {}

    if existing_headers:
        headers_lower = {k.lower(): str(v).lower() for k, v in existing_headers.items()
                         if not k.startswith("_")}

    # Try to fetch HTML body
    body = ""
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}", headers=HEADERS, timeout=8,
                allow_redirects=True, verify=True
            )
            body = resp.text.lower()[:50000]  # cap at 50KB
            # merge any additional response headers
            for h in resp.headers:
                headers_lower.setdefault(h.lower(), resp.headers[h].lower())
            break
        except Exception:
            continue

    combined = body + " " + " ".join(headers_lower.values())

    for tech, signatures in _TECH_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            detected.append(tech)

    return {"technologies": detected}


def generate_recon_links(target: str) -> dict:
    encoded = requests.utils.quote(target)
    return {
        "Shodan": f"https://www.shodan.io/host/{target}",
        "VirusTotal": f"https://www.virustotal.com/gui/domain/{target}",
        "Censys": f"https://search.censys.io/hosts/{target}",
        "SecurityTrails": f"https://securitytrails.com/domain/{target}/history/a",
        "URLScan": f"https://urlscan.io/search/#page.domain%3A{encoded}",
        "BuiltWith": f"https://builtwith.com/{target}",
        "Wayback Machine": f"https://web.archive.org/web/*/{target}",
        "DNSDumpster": f"https://dnsdumpster.com/ (search: {target})",
    }


def ip_lookup(target: str) -> dict:
    geo = ip_geolocation(target)
    rev = []
    headers_info = {}
    sec_score = {}
    tech_stack = {}

    if geo.get("success"):
        ip = geo["data"].get("query", target)
        if not any(c.isalpha() for c in target):  # is IP
            rev = reverse_ip_lookup(ip)

    if any(c.isalpha() for c in target):
        headers_info = get_headers_info(target)
        sec_score = score_security_headers(headers_info)
        tech_stack = detect_tech_stack(target, headers_info)

    return {
        "target": target,
        "geo": geo,
        "reverse_ip": rev,
        "http_headers": headers_info,
        "security_score": sec_score,
        "tech_stack": tech_stack,
        "recon_links": generate_recon_links(target),
    }


def print_ip_results(data: dict):
    console.print(f"\n[bold cyan]═══ IP/DOMAIN INTELLIGENCE: {data['target']} ═══[/bold cyan]")

    geo = data.get("geo", {})
    if geo.get("success"):
        d = geo["data"]
        table = Table(show_header=False)
        table.add_column("Field", style="cyan", width=18)
        table.add_column("Value", style="white")

        fields = [
            ("IP Address", "query"), ("Country", "country"),
            ("Region", "regionName"), ("City", "city"),
            ("ZIP", "zip"), ("Lat/Lon", None),
            ("Timezone", "timezone"), ("ISP", "isp"),
            ("Organization", "org"), ("ASN", "as"),
            ("Proxy/VPN", "proxy"), ("Hosting", "hosting"),
            ("Mobile", "mobile"), ("Reverse DNS", "reverse"),
        ]
        for label, key in fields:
            if key is None:
                val = f"{d.get('lat')}, {d.get('lon')}"
            else:
                val = str(d.get(key, ""))
            if val and val not in ("None", "False", ""):
                flag = "🚨 " if label in ("Proxy/VPN", "Hosting") and val == "True" else ""
                table.add_row(label, f"{flag}{val}")
        console.print(table)
    else:
        console.print(f"  [red]Geo lookup failed: {geo.get('error')}[/red]")

    # Reverse IP
    rev = data.get("reverse_ip", [])
    if rev:
        console.print(f"\n  [bold]Domains on same IP ({len(rev)}):[/bold]")
        for d in rev[:10]:
            console.print(f"    • {d}")
        if len(rev) > 10:
            console.print(f"    [dim]... and {len(rev)-10} more[/dim]")

    # HTTP Headers
    headers = data.get("http_headers", {})
    if headers:
        console.print("\n  [bold]HTTP Fingerprint:[/bold]")
        for k, v in headers.items():
            if not k.startswith("_"):
                console.print(f"    {k}: [yellow]{v[:80]}[/yellow]")
        if headers.get("_final_url"):
            console.print(f"  Final URL : {headers['_final_url']}")

    # Security Headers Score
    sec = data.get("security_score", {})
    if sec:
        grade = sec.get("grade", "?")
        score = sec.get("score", 0)
        grade_color = {"A+": "bold green", "A": "green", "B": "cyan",
                       "C": "yellow", "D": "dark_orange", "F": "red"}.get(grade, "white")
        console.print(f"\n  [bold]Security Headers Score:[/bold] [{grade_color}]{grade}[/{grade_color}] ({score}/100)")
        if sec.get("missing"):
            missing_labels = ", ".join(m["label"] for m in sec["missing"])
            console.print(f"  [dim]  Missing: {missing_labels}[/dim]")
        if sec.get("present"):
            for p in sec["present"]:
                console.print(f"    [green]✓[/green] {p['label']}")

    # Tech Stack
    tech = data.get("tech_stack", {})
    if tech.get("technologies"):
        techs = ", ".join(tech["technologies"])
        console.print(f"\n  [bold]Detected Technologies:[/bold] [magenta]{techs}[/magenta]")

    # Recon links
    console.print("\n  [bold]External Recon Links:[/bold]")
    for name, url in data.get("recon_links", {}).items():
        console.print(f"    {name:20}: [link]{url}[/link]")
