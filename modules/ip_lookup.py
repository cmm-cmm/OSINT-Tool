"""
IP & Domain Intelligence Module
- IP geolocation (ip-api.com - free, no key required)
- ASN / ISP info
- Shodan link generation
- Reverse IP lookup via HackerTarget (free tier)
- HTTP Security Headers Scoring
- Tech stack detection
- Port scanning and service detection
- Advanced vulnerability analysis
"""
import time
import socket
import concurrent.futures
import requests
from rich.console import Console
from rich.table import Table
from modules.utils import make_session, HEADERS_GENERIC as HEADERS

console = Console()
_session = make_session()

# Common ports to scan for security research
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,  # Common services
    3306, 5432, 1433, 27017, 6379,  # Databases
    3389, 5900,  # Remote desktop
    8080, 8443, 8888,  # Alt HTTP
    445, 139,  # SMB
    389, 636,  # LDAP
    1521,  # Oracle
]

# Security header scoring weights with remediation guidance
_SEC_HEADERS = {
    "strict-transport-security": (
        "HSTS", 20,
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    ),
    "content-security-policy": (
        "CSP", 25,
        "Add: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'"
    ),
    "x-frame-options": (
        "X-Frame-Options", 15,
        "Add: X-Frame-Options: DENY or SAMEORIGIN"
    ),
    "x-content-type-options": (
        "X-Content-Type-Options", 10,
        "Add: X-Content-Type-Options: nosniff"
    ),
    "referrer-policy": (
        "Referrer-Policy", 10,
        "Add: Referrer-Policy: strict-origin-when-cross-origin"
    ),
    "permissions-policy": (
        "Permissions-Policy", 10,
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
    ),
    "x-xss-protection": (
        "X-XSS-Protection", 10,
        "Add: X-XSS-Protection: 1; mode=block (legacy browsers)"
    ),
}

# Service identification by port
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB",
    6379: "Redis", 3389: "RDP", 5900: "VNC",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    389: "LDAP", 636: "LDAPS", 1521: "Oracle",
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


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single port and return status."""
    result = {"port": port, "state": "closed", "service": PORT_SERVICES.get(port, "unknown"), "banner": ""}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((host, port))

        if result_code == 0:
            result["state"] = "open"
            # Try to grab banner
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                if banner:
                    result["banner"] = banner[:200]
            except:
                pass

        sock.close()
    except socket.timeout:
        result["state"] = "filtered"
    except socket.error:
        result["state"] = "closed"
    except Exception:
        result["state"] = "error"

    return result


def port_scan(host: str, ports: list = None, max_workers: int = 50) -> dict:
    """Scan multiple ports concurrently for open services."""
    if ports is None:
        ports = COMMON_PORTS

    open_ports = []
    filtered_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {executor.submit(scan_port, host, port): port for port in ports}

        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result()
                if result["state"] == "open":
                    open_ports.append(result)
                elif result["state"] == "filtered":
                    filtered_ports.append(result)
            except Exception:
                pass

    # Sort by port number
    open_ports.sort(key=lambda x: x["port"])
    filtered_ports.sort(key=lambda x: x["port"])

    return {
        "total_scanned": len(ports),
        "open_ports": open_ports,
        "filtered_ports": filtered_ports,
        "open_count": len(open_ports),
        "filtered_count": len(filtered_ports),
    }


def get_headers_info(domain: str) -> dict:
    """Grab HTTP headers from target for tech fingerprinting and security scoring."""
    result = {}
    for scheme in ("https", "http"):
        for verify_ssl in (True, False):
            try:
                resp = requests.head(
                    f"{scheme}://{domain}", headers=HEADERS, timeout=8,
                    allow_redirects=True, verify=verify_ssl
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
                if not verify_ssl:
                    result["_ssl_warning"] = "SSL certificate verification skipped"
                return result
            except requests.exceptions.SSLError:
                if verify_ssl:
                    continue  # retry without SSL verification
                break
            except Exception:
                break
    return result


def score_security_headers(headers: dict) -> dict:
    """Score HTTP security headers with detailed remediation guidance."""
    if not headers:
        return {
            "score": 0,
            "grade": "F",
            "present": [],
            "missing": [{"header": k, "label": v[0], "fix": v[2]} for k, v in _SEC_HEADERS.items()],
        }

    present = []
    missing = []
    score = 0
    h_lower = {k.lower(): v for k, v in headers.items()}

    for header, (label, weight, fix_advice) in _SEC_HEADERS.items():
        if header in h_lower:
            value = h_lower[header]
            # Analyze header value for security issues
            issues = []
            if header == "strict-transport-security":
                if "max-age" not in value.lower():
                    issues.append("Missing max-age directive")
                elif "max-age=0" in value.lower() or "max-age = 0" in value.lower():
                    issues.append("max-age is 0 (HSTS disabled)")
                if "includesubdomains" not in value.lower().replace(" ", ""):
                    issues.append("Consider adding includeSubDomains")
            elif header == "x-frame-options":
                if value.lower() not in ["deny", "sameorigin"]:
                    issues.append(f"Weak value: {value}")
            elif header == "content-security-policy":
                if "'unsafe-eval'" in value.lower() or "'unsafe-inline'" in value.lower():
                    issues.append("Contains unsafe directives")

            present.append({
                "header": header,
                "label": label,
                "value": value[:80],
                "issues": issues
            })
            # Reduce score if there are issues
            score += weight if not issues else weight // 2
        else:
            missing.append({"header": header, "label": label, "fix": fix_advice})

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
            for h in resp.headers:
                headers_lower.setdefault(h.lower(), resp.headers[h].lower())
            break
        except requests.exceptions.SSLError:
            # Retry over plain HTTP if HTTPS has cert issues
            continue
        except Exception:
            break
    if body:
        pass  # already fetched

    combined = body + " " + " ".join(headers_lower.values())

    for tech, signatures in _TECH_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            detected.append(tech)

    return {"technologies": detected}


def check_virustotal(target: str, api_key: str) -> dict:
    """Query VirusTotal v3 API for domain/IP threat intel (1000 free req/day)."""
    is_ip = not any(c.isalpha() for c in target)
    endpoint = "ip_addresses" if is_ip else "domains"
    url = f"https://www.virustotal.com/api/v3/{endpoint}/{target}"
    try:
        resp = requests.get(url, headers={"x-apikey": api_key, **HEADERS}, timeout=12)
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "success": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "country": attrs.get("country"),
                "as_owner": attrs.get("as_owner"),
            }
        elif resp.status_code == 401:
            return {"success": False, "error": "Invalid API key"}
        elif resp.status_code == 404:
            return {"success": False, "error": "Not found in VirusTotal database"}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_shodan(ip: str, api_key: str) -> dict:
    """Query Shodan for open ports, banners, CVEs on an IP (free tier: 100 req/month)."""
    url = f"https://api.shodan.io/shodan/host/{ip}"
    try:
        resp = requests.get(url, params={"key": api_key}, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            # Build full CVE list with CVSS scores from Shodan vuln data
            vulns_raw = data.get("vulns", {})
            cve_details = []
            for cve_id, vuln_info in vulns_raw.items():
                if isinstance(vuln_info, dict):
                    cvss = vuln_info.get("cvss", vuln_info.get("cvss3", vuln_info.get("score")))
                    cve_details.append({
                        "id": cve_id,
                        "cvss": cvss,
                        "summary": (vuln_info.get("summary") or "")[:150],
                        "references": (vuln_info.get("references") or [])[:2],
                    })
                else:
                    cve_details.append({"id": cve_id, "cvss": None, "summary": "", "references": []})
            # Sort by CVSS descending
            cve_details.sort(key=lambda x: float(x["cvss"] or 0), reverse=True)

            return {
                "success": True,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org"),
                "os": data.get("os"),
                "country_name": data.get("country_name"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "last_update": data.get("last_update"),
                "vulns": list(vulns_raw.keys()),
                "cve_details": cve_details,
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product"),
                        "version": s.get("version"),
                        "cpe": s.get("cpe", []),
                        "banner": (s.get("data") or "")[:100].replace("\n", " "),
                    }
                    for s in data.get("data", [])[:15]
                ],
            }
        elif resp.status_code == 401:
            return {"success": False, "error": "Invalid Shodan API key"}
        elif resp.status_code == 404:
            return {"success": False, "error": "No information available for this IP"}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for IP reputation / abuse reports (1000 free req/day)."""
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        resp = requests.get(
            url,
            headers={"Key": api_key, "Accept": "application/json", **HEADERS},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=10,
        )
        if resp.status_code == 200:
            d = resp.json().get("data", {})
            return {
                "success": True,
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "last_reported_at": d.get("lastReportedAt"),
                "country_code": d.get("countryCode"),
                "usage_type": d.get("usageType"),
                "isp": d.get("isp"),
                "domain": d.get("domain"),
                "is_whitelisted": d.get("isWhitelisted", False),
                "is_tor": d.get("isTor", False),
            }
        elif resp.status_code == 401:
            return {"success": False, "error": "Invalid AbuseIPDB API key"}
        elif resp.status_code == 422:
            return {"success": False, "error": "Invalid IP address format"}
        else:
            return {"success": False, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def generate_recon_links(target: str, ip_target: str = None) -> dict:
    encoded = requests.utils.quote(target)
    ip = ip_target or target
    return {
        "Shodan": f"https://www.shodan.io/host/{ip}",
        "VirusTotal": f"https://www.virustotal.com/gui/domain/{target}",
        "Censys": f"https://search.censys.io/hosts/{ip}",
        "SecurityTrails": f"https://securitytrails.com/domain/{target}/history/a",
        "URLScan": f"https://urlscan.io/search/#page.domain%3A{encoded}",
        "BuiltWith": f"https://builtwith.com/{target}",
        "Wayback Machine": f"https://web.archive.org/web/*/{target}",
        "DNSDumpster": f"https://dnsdumpster.com/ (search: {target})",
        "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
        "FOFA": f"https://en.fofa.info/result?qbase64={requests.utils.quote(f'ip=\"{ip}\"')}",
        "GreyNoise": f"https://viz.greynoise.io/ip/{ip}",
    }


def rdap_lookup(ip_or_domain: str) -> dict:
    """
    RDAP (Registration Data Access Protocol) lookup — thay thế WHOIS hiện đại.
    Cho phép tra cứu thông tin IP network/block, ASN, abuse contacts.
    Free, không cần API key.
    """
    result = {"success": False, "data": {}, "error": None}

    is_ip = all(c.isdigit() or c == "." or c == ":" for c in ip_or_domain)

    # RDAP bootstrap — try ARIN first, then fallback to common registries
    rdap_urls = []
    if is_ip:
        rdap_urls = [
            f"https://rdap.arin.net/registry/ip/{ip_or_domain}",
            f"https://rdap.lacnic.net/rdap/ip/{ip_or_domain}",
            f"https://rdap.apnic.net/ip/{ip_or_domain}",
            f"https://rdap.ripe.net/ip/{ip_or_domain}",
            f"https://rdap.afrinic.net/rdap/ip/{ip_or_domain}",
        ]
    else:
        rdap_urls = [
            f"https://rdap.iana.org/domain/{ip_or_domain}",
            f"https://rdap.verisign.com/com/v1/domain/{ip_or_domain}",
        ]

    for url in rdap_urls:
        try:
            resp = requests.get(
                url, headers={**HEADERS, "Accept": "application/rdap+json"},
                timeout=8, allow_redirects=True
            )
            if resp.status_code == 200:
                raw = resp.json()
                # Extract useful fields
                parsed = {
                    "objectClass": raw.get("objectClassName"),
                    "handle": raw.get("handle"),
                    "name": raw.get("name"),
                    "type": raw.get("type"),
                    "country": raw.get("country"),
                    "start_ip": raw.get("startAddress"),
                    "end_ip": raw.get("endAddress"),
                    "ip_version": raw.get("ipVersion"),
                    "parent_handle": raw.get("parentHandle"),
                    "cidr": None,
                    "registrant": None,
                    "abuse_contact": None,
                    "remarks": [],
                    "source_url": url,
                }

                # CIDR blocks
                cidrs = raw.get("cidr0_cidrs", [])
                if cidrs:
                    cidr_strs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                                 for c in cidrs if c.get("v4prefix") or c.get("v6prefix")]
                    parsed["cidr"] = ", ".join(cidr_strs[:3])

                # Entities (registrant, abuse, etc.)
                for entity in raw.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [])
                    name_val = ""
                    email_val = ""
                    if vcard and len(vcard) > 1:
                        for entry in vcard[1]:
                            if entry[0] == "fn":
                                name_val = entry[3]
                            elif entry[0] == "email":
                                email_val = entry[3]
                    if "registrant" in roles or "technical" in roles:
                        parsed["registrant"] = f"{name_val} {email_val}".strip()
                    if "abuse" in roles and email_val:
                        parsed["abuse_contact"] = email_val

                # Remarks
                for remark in raw.get("remarks", []):
                    for desc in remark.get("description", []):
                        if desc.strip():
                            parsed["remarks"].append(desc.strip())

                result["success"] = True
                result["data"] = parsed
                return result

        except Exception:
            continue

    result["error"] = "RDAP lookup failed across all registries"
    return result


def ip_lookup(target: str, virustotal_key: str = None, shodan_key: str = None, abuseipdb_key: str = None,
              enable_port_scan: bool = True) -> dict:
    geo = ip_geolocation(target)
    rev = []
    headers_info = {}
    sec_score = {}
    tech_stack = {}
    port_scan_results = {}
    is_ip = not any(c.isalpha() for c in target)

    if geo.get("success"):
        ip = geo["data"].get("query", target)
        if is_ip:
            rev = reverse_ip_lookup(ip)

    if not is_ip:
        headers_info = get_headers_info(target)
        sec_score = score_security_headers(headers_info)
        tech_stack = detect_tech_stack(target, headers_info)

    result = {
        "target": target,
        "geo": geo,
        "reverse_ip": rev,
        "http_headers": headers_info,
        "security_score": sec_score,
        "tech_stack": tech_stack,
    }

    ip_for_api = geo["data"].get("query", target) if geo.get("success") else target
    # resolved_ip: use the geo-resolved IP for Shodan/AbuseIPDB even when target is a domain
    resolved_ip = ip_for_api if (ip_for_api and not any(c.isalpha() for c in ip_for_api)) else None

    # Port scanning (if enabled and we have an IP)
    if enable_port_scan and resolved_ip:
        console.print("  [dim]Scanning common ports...[/dim]")
        port_scan_results = port_scan(resolved_ip)
        result["port_scan"] = port_scan_results

    # RDAP lookup (free, no key needed)
    console.print("  [dim]Running RDAP lookup...[/dim]")
    rdap_target = resolved_ip or target
    result["rdap"] = rdap_lookup(rdap_target)

    # Build recon links: use resolved IP for IP-only services when target is a domain
    recon_target_ip = resolved_ip or target
    result["recon_links"] = generate_recon_links(target, recon_target_ip)

    if virustotal_key:
        console.print("  [dim]Querying VirusTotal...[/dim]")
        result["virustotal"] = check_virustotal(target, virustotal_key)

    if shodan_key and resolved_ip:
        console.print("  [dim]Querying Shodan...[/dim]")
        result["shodan"] = check_shodan(resolved_ip, shodan_key)

    if abuseipdb_key and resolved_ip:
        console.print("  [dim]Querying AbuseIPDB...[/dim]")
        result["abuseipdb"] = check_abuseipdb(resolved_ip, abuseipdb_key)

    return result


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

    # RDAP
    rdap = data.get("rdap", {})
    if rdap and rdap.get("success"):
        d = rdap.get("data", {})
        console.print("\n  [bold]RDAP Network Info:[/bold]")
        if d.get("name"):
            console.print(f"    Network  : [cyan]{d['name']}[/cyan]")
        if d.get("handle"):
            console.print(f"    Handle   : {d['handle']}")
        if d.get("cidr"):
            console.print(f"    CIDR     : {d['cidr']}")
        if d.get("start_ip") and d.get("end_ip"):
            console.print(f"    Range    : {d['start_ip']} — {d['end_ip']}")
        if d.get("country"):
            console.print(f"    Country  : {d['country']}")
        if d.get("registrant"):
            console.print(f"    Registrant: {d['registrant']}")
        if d.get("abuse_contact"):
            console.print(f"    Abuse    : [yellow]{d['abuse_contact']}[/yellow]")

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

        if sec.get("present"):
            console.print("\n  [bold green]✓ Present Headers:[/bold green]")
            for p in sec["present"]:
                status = "[green]✓[/green]" if not p.get("issues") else "[yellow]⚠[/yellow]"
                console.print(f"    {status} {p['label']}: [dim]{p['value'][:60]}[/dim]")
                if p.get("issues"):
                    for issue in p["issues"]:
                        console.print(f"      [yellow]⚠ {issue}[/yellow]")

        if sec.get("missing"):
            console.print("\n  [bold red]✗ Missing Headers:[/bold red]")
            for m in sec["missing"]:
                console.print(f"    [red]✗[/red] {m['label']}")
                console.print(f"      [dim]{m['fix']}[/dim]")

    # Port Scan Results
    port_scan = data.get("port_scan", {})
    if port_scan and port_scan.get("open_count", 0) > 0:
        open_ports = port_scan.get("open_ports", [])
        console.print(f"\n  [bold]Port Scan Results:[/bold] [cyan]{port_scan['open_count']} open port(s)[/cyan] / {port_scan['total_scanned']} scanned")

        from rich.table import Table as RTable
        port_tbl = RTable(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
        port_tbl.add_column("Port", width=8)
        port_tbl.add_column("State", width=10)
        port_tbl.add_column("Service", width=15)
        port_tbl.add_column("Banner", style="dim", max_width=50)

        for p in open_ports[:20]:  # Show top 20
            state_color = "green" if p["state"] == "open" else "yellow"
            port_tbl.add_row(
                str(p["port"]),
                f"[{state_color}]{p['state']}[/{state_color}]",
                p["service"],
                p.get("banner", "")[:50]
            )

        console.print(port_tbl)

        # Security warnings for risky ports
        risky_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB"}
        open_risky = [p for p in open_ports if p["port"] in risky_ports]
        if open_risky:
            console.print("\n  [bold red]⚠ Security Warning:[/bold red]")
            for p in open_risky:
                console.print(f"    [red]• Port {p['port']} ({risky_ports[p['port']]}) is open - potential security risk[/red]")

    elif port_scan:
        console.print(f"\n  [dim]Port Scan: No open ports found ({port_scan['total_scanned']} ports scanned)[/dim]")

    # Tech Stack
    tech = data.get("tech_stack", {})
    if tech.get("technologies"):
        techs = ", ".join(tech["technologies"])
        console.print(f"\n  [bold]Detected Technologies:[/bold] [magenta]{techs}[/magenta]")

    # VirusTotal
    vt = data.get("virustotal", {})
    if vt:
        if vt.get("success"):
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            rep = vt.get("reputation", 0)
            color = "red" if mal > 0 else ("yellow" if sus > 0 else "green")
            console.print(f"\n  [bold]VirusTotal:[/bold] [{color}]{mal} malicious / {sus} suspicious[/{color}]  (reputation: {rep})")
            if vt.get("as_owner"):
                console.print(f"    AS Owner : {vt['as_owner']}")
            if vt.get("country"):
                console.print(f"    Country  : {vt['country']}")
        else:
            console.print(f"\n  [dim]VirusTotal: {vt.get('error', 'N/A')}[/dim]")

    # Shodan
    shodan = data.get("shodan", {})
    if shodan:
        if shodan.get("success"):
            ports = shodan.get("ports", [])
            vulns = shodan.get("vulns", [])
            console.print(f"\n  [bold]Shodan:[/bold] {len(ports)} open port(s): [cyan]{', '.join(str(p) for p in ports[:20])}[/cyan]")
            if shodan.get("org"):
                console.print(f"    Org      : {shodan['org']}")
            if shodan.get("os"):
                console.print(f"    OS       : {shodan['os']}")
            if shodan.get("last_update"):
                console.print(f"    Updated  : {shodan['last_update']}")

            # CVE details table
            cve_details = shodan.get("cve_details", [])
            if cve_details:
                console.print(f"\n    [bold red]⚠ {len(cve_details)} CVE(s) detected:[/bold red]")
                from rich.table import Table as RTable
                cve_tbl = RTable(show_header=True, header_style="bold red", box=None, padding=(0, 1))
                cve_tbl.add_column("CVE ID", style="red", width=16)
                cve_tbl.add_column("CVSS", width=6, justify="right")
                cve_tbl.add_column("Severity", width=9)
                cve_tbl.add_column("Summary", style="dim", max_width=60)
                for cve in cve_details:
                    cvss_val = cve.get("cvss")
                    if cvss_val is not None:
                        try:
                            cvss_f = float(cvss_val)
                            cvss_str = f"{cvss_f:.1f}"
                            if cvss_f >= 9.0:
                                severity = "[bold red]CRITICAL[/bold red]"
                            elif cvss_f >= 7.0:
                                severity = "[red]HIGH[/red]"
                            elif cvss_f >= 4.0:
                                severity = "[yellow]MEDIUM[/yellow]"
                            else:
                                severity = "[dim]LOW[/dim]"
                        except (ValueError, TypeError):
                            cvss_str = str(cvss_val)
                            severity = "[dim]?[/dim]"
                    else:
                        cvss_str = "N/A"
                        severity = "[dim]?[/dim]"
                    cve_tbl.add_row(
                        cve.get("id", ""), cvss_str, severity,
                        (cve.get("summary") or "")[:80]
                    )
                console.print(cve_tbl)
            elif vulns:
                console.print(f"    [bold red]CVEs ({len(vulns)}):[/bold red] [red]{', '.join(vulns[:15])}[/red]")

            # Services table
            services = shodan.get("services", [])
            if services:
                from rich.table import Table as RTable
                svc_tbl = RTable(show_header=True, header_style="bold cyan", box=None, padding=(0, 1))
                svc_tbl.add_column("Port", width=8)
                svc_tbl.add_column("Proto", width=5)
                svc_tbl.add_column("Product", width=20)
                svc_tbl.add_column("Version", width=14)
                svc_tbl.add_column("Banner snippet", style="dim", max_width=45)
                for svc in services[:10]:
                    svc_tbl.add_row(
                        str(svc.get("port", "")),
                        svc.get("transport", "tcp"),
                        svc.get("product") or "",
                        svc.get("version") or "",
                        svc.get("banner") or "",
                    )
                console.print(svc_tbl)
        else:
            console.print(f"\n  [dim]Shodan: {shodan.get('error', 'N/A')}[/dim]")

    # AbuseIPDB
    abuse = data.get("abuseipdb", {})
    if abuse:
        if abuse.get("success"):
            score = abuse.get("abuse_confidence_score", 0)
            reports = abuse.get("total_reports", 0)
            color = "red" if score >= 50 else ("yellow" if score >= 10 else "green")
            console.print(f"\n  [bold]AbuseIPDB:[/bold] [{color}]{score}% abuse confidence[/{color}]  ({reports} reports)")
            if abuse.get("usage_type"):
                console.print(f"    Usage    : {abuse['usage_type']}")
            if abuse.get("isp"):
                console.print(f"    ISP      : {abuse['isp']}")
            if abuse.get("is_tor"):
                console.print(f"    [red]⚠ TOR Exit Node[/red]")
            if abuse.get("last_reported_at"):
                console.print(f"    Last seen: {abuse['last_reported_at']}")
        else:
            console.print(f"\n  [dim]AbuseIPDB: {abuse.get('error', 'N/A')}[/dim]")

    # Recon links
    console.print("\n  [bold]External Recon Links:[/bold]")
    for name, url in data.get("recon_links", {}).items():
        console.print(f"    {name:20}: [link]{url}[/link]")
