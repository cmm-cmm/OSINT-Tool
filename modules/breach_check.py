"""
Breach & Data Leak Check Module
=====================================================
Kiểm tra email / username trong các vụ rò rỉ dữ liệu công khai.

Dịch vụ miễn phí (không cần API key):
  ① HIBP Pwned Passwords – kiểm tra mật khẩu qua k-anonymity SHA-1
  ② LeakCheck.io         – public endpoint, không cần đăng ký

Dịch vụ miễn phí sau khi đăng ký (free tier):
  ③ BreachDirectory      – qua RapidAPI, 100 req/tháng miễn phí
                           → env: BREACHDIRECTORY_KEY

Dịch vụ tùy chọn (có phí nhỏ):
  ④ HaveIBeenPwned       – email breach + paste check
                           → env: HIBP_API_KEY  ($3.95/month)
"""
import re
import hashlib
import requests
from rich.console import Console
from rich.table import Table
from modules.utils import make_session, HEADERS_GENERIC as _HEADERS

console = Console()
_session = make_session()


# ─── ① HIBP Pwned Passwords — hoàn toàn miễn phí, không cần key ──────────

def check_pwned_password(password: str) -> dict:
    """
    Kiểm tra mật khẩu có bị lộ trong các vụ breach không.
    Chỉ gửi 5 ký tự đầu của SHA-1 hash (k-anonymity) — mật khẩu thật
    không bao giờ rời khỏi máy.
    API: https://api.pwnedpasswords.com/range/{prefix}
    """
    result = {"exposed": False, "count": 0, "error": None}
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "OSINT-Tool/1.0-EducationalUse", "Add-Padding": "true"},
            timeout=10,
            verify=True,
        )
        r.raise_for_status()
        for line in r.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0] == suffix:
                result["exposed"] = True
                result["count"] = int(parts[1])
                break
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ② LeakCheck.io public — miễn phí, không cần key ─────────────────────

def check_leakcheck_public(query: str) -> dict:
    """
    LeakCheck.io public endpoint.
    Trả về found=True/False + danh sách tên nguồn (không có mật khẩu).
    Không cần API key.
    """
    result = {"found": False, "sources": [], "error": None, "note": None}
    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": query},
            headers=_HEADERS,
            timeout=10,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json()
            result["found"] = bool(data.get("found"))
            raw_sources = data.get("sources", [])
            # Chuẩn hóa: có thể là list[str] hoặc list[dict]
            normalized = []
            for s in raw_sources:
                if isinstance(s, dict):
                    name = s.get("name") or s.get("title") or str(s)
                    date = s.get("date") or ""
                    normalized.append(f"{name}" + (f" ({date})" if date else ""))
                else:
                    normalized.append(str(s))
            result["sources"] = normalized
        elif r.status_code == 429:
            result["note"] = "Rate limited — thử lại sau."
        elif r.status_code == 403:
            result["note"] = "LeakCheck yêu cầu tài khoản miễn phí để xem chi tiết."
        elif r.status_code == 400:
            result["note"] = "Định dạng email / username không hợp lệ với LeakCheck."
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ③ BreachDirectory via RapidAPI — free tier 100 req/tháng ────────────

def check_breachdirectory(query: str, api_key: str | None) -> dict:
    """
    BreachDirectory qua RapidAPI.
    Đăng ký miễn phí tại: https://rapidapi.com/rohan-patra/api/breachdirectory
    Đặt biến môi trường: BREACHDIRECTORY_KEY=<your_key>
    """
    result = {"found": False, "result": [], "size": 0, "error": None, "note": None}
    if not api_key:
        result["note"] = (
            "Chưa có API key (đăng ký miễn phí).\n"
            "  1. Truy cập: https://rapidapi.com/rohan-patra/api/breachdirectory\n"
            "  2. Đăng ký tài khoản RapidAPI miễn phí\n"
            "  3. Subscribe gói Basic (free, 100 req/tháng)\n"
            "  4. Thêm vào .env: BREACHDIRECTORY_KEY=your_rapidapi_key"
        )
        return result
    try:
        r = requests.get(
            "https://breachdirectory.p.rapidapi.com/",
            params={"func": "auto", "term": query},
            headers={
                "X-RapidAPI-Key": api_key,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
            },
            timeout=12,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json()
            result["found"] = bool(data.get("found"))
            result["result"] = data.get("result", [])
            # API đôi khi trả size=0 dù có result
            result["size"] = data.get("size") or len(result["result"])
        elif r.status_code == 429:
            result["error"] = "Rate limited — free tier: 100 req/tháng."
        elif r.status_code in (401, 403):
            result["error"] = "API key không hợp lệ hoặc chưa subscribe."
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ④ HaveIBeenPwned — tùy chọn ($3.95/month) ───────────────────────────

def check_hibp_email(email: str, api_key: str | None) -> dict:
    """
    HaveIBeenPwned v3 — kiểm tra email trong breaches + pastes.
    Lấy key tại: https://haveibeenpwned.com/API/Key
    """
    result = {"breaches": [], "pastes": [], "error": None, "note": None}
    if not api_key:
        result["note"] = (
            "HIBP API key chưa được cài đặt (tùy chọn).\n"
            "  Lấy key tại: https://haveibeenpwned.com/API/Key ($3.95/tháng)\n"
            "  Thêm vào .env: HIBP_API_KEY=your_key"
        )
        return result
    try:
        h = {**_HEADERS, "hibp-api-key": api_key}
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            headers=h, timeout=10,
            params={"truncateResponse": False},
        )
        if r.status_code == 200:
            result["breaches"] = [
                {
                    "name": b.get("Name"),
                    "date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "description": re.sub(r"<[^>]+>", "", b.get("Description", ""))[:200],
                }
                for b in r.json()
            ]
        elif r.status_code == 404:
            result["breaches"] = []
        elif r.status_code == 401:
            result["error"] = "HIBP API key không hợp lệ."
        else:
            result["error"] = f"Breaches: HTTP {r.status_code}"

        # Pastes
        r2 = requests.get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
            headers=h, timeout=10,
        )
        if r2.status_code == 200:
            result["pastes"] = r2.json()
        elif r2.status_code != 404:
            err2 = f"Pastes: HTTP {r2.status_code}"
            result["error"] = f"{result['error']} | {err2}" if result["error"] else err2
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ⑤ Dehashed — trả về bản ghi rò rỉ thực tế ($5/tháng) ─────────────────

def check_dehashed(
    query_value: str,
    query_type: str = "email",
    api_email: str | None = None,
    api_key: str | None = None,
) -> dict:
    """
    Dehashed — tra cứu breach database trả về dữ liệu thực tế.
    Đăng ký tại: https://dehashed.com ($5/tháng, 5.000 queries)
    Thêm vào .env: DEHASHED_EMAIL=your@email.com  DEHASHED_KEY=your_api_key

    query_type: email | username | password | name | ip_address | address | phone | vin
    Trả về entries với: email, name, username, password, hashed_password, address, phone, ip_address, database_name
    """
    result = {
        "found": False, "entries": [], "total": 0,
        "balance": None, "error": None, "note": None,
    }
    if not api_email or not api_key:
        result["note"] = (
            "Chưa có Dehashed API key ($5/tháng — 5.000 queries).\n"
            "  Đăng ký: https://dehashed.com\n"
            "  Thêm vào .env: DEHASHED_EMAIL=your@email DEHASHED_KEY=your_api_key"
        )
        return result
    _allowed = {"email", "username", "password", "hashed_password", "name",
                "ip_address", "address", "phone", "vin"}
    if query_type not in _allowed:
        result["error"] = f"query_type không hợp lệ: {query_type}"
        return result
    try:
        r = requests.get(
            "https://api.dehashed.com/search",
            params={"query": f"{query_type}:{query_value}", "size": 100},
            auth=(api_email, api_key),
            headers={"Accept": "application/json", "User-Agent": "OSINT-Tool/1.0"},
            timeout=15,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json()
            result["found"] = bool(data.get("entries"))
            result["entries"] = data.get("entries") or []
            result["total"] = data.get("total", 0)
            result["balance"] = data.get("balance")
        elif r.status_code == 401:
            result["error"] = "Dehashed: Email hoặc API key không hợp lệ"
        elif r.status_code == 429:
            result["error"] = "Dehashed: Rate limited — thử lại sau"
        elif r.status_code == 400:
            result["error"] = f"Dehashed: Bad request — {r.text[:120]}"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ⑥ Snusbase — breach database thực tế ($2/tháng) ────────────────────

def check_snusbase(
    query_value: str,
    query_type: str = "email",
    api_key: str | None = None,
) -> dict:
    """
    Snusbase v3 — breach record lookup trả về dữ liệu thực tế.
    Đăng ký tại: https://snusbase.com ($2/tháng)
    Thêm vào .env: SNUSBASE_KEY=your_api_key

    query_type: email | username | password | hash | name | ip
    Trả về entries với: email, username, password, hash, hash_type, name, ip, table (tên database)
    """
    result = {
        "found": False, "entries": [], "total": 0,
        "error": None, "note": None,
    }
    if not api_key:
        result["note"] = (
            "Chưa có Snusbase API key ($2/tháng).\n"
            "  Đăng ký: https://snusbase.com\n"
            "  Thêm vào .env: SNUSBASE_KEY=your_api_key"
        )
        return result
    _allowed = {"email", "username", "password", "hash", "name", "ip"}
    if query_type not in _allowed:
        result["error"] = f"query_type không hợp lệ: {query_type}"
        return result
    try:
        r = requests.post(
            "https://api3.snusbase.com/data/search",
            headers={
                "Authorization": api_key,
                "Content-Type": "application/json",
                "User-Agent": "OSINT-Tool/1.0",
            },
            json={"terms": [query_value], "types": [query_type], "wildcard": False},
            timeout=15,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json()
            all_entries: list[dict] = []
            for entries_list in (data.get("results") or {}).values():
                if isinstance(entries_list, list):
                    all_entries.extend(entries_list)
            result["found"] = bool(all_entries)
            result["entries"] = all_entries
            result["total"] = data.get("size", len(all_entries))
        elif r.status_code == 401:
            result["error"] = "Snusbase: API key không hợp lệ"
        elif r.status_code == 429:
            result["error"] = "Snusbase: Rate limited"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ⑦ Holehe — email đã đăng ký trên những trang nào (free) ────────────

def check_holehe(email: str) -> dict:
    """
    Holehe — kiểm tra email đã được đăng ký trên 100+ dịch vụ nào.
    Miễn phí, không cần API key. Cần cài: pip install holehe

    Trả về danh sách {name, domain} của các dịch vụ tìm thấy email này.
    """
    result = {"registered_sites": [], "checked": 0, "error": None, "note": None}
    try:
        import subprocess, re as _re, sys
        from modules.utils import sanitize_for_shell
        try:
            safe_email = sanitize_for_shell(email)
        except ValueError as ve:
            result["error"] = f"Địa chỉ email không hợp lệ để chạy holehe: {ve}"
            return result
        proc = subprocess.run(
            [sys.executable, "-m", "holehe", "--no-color", "--only-registered", safe_email],
            capture_output=True, text=True, timeout=90, encoding="utf-8",
        )
        output = proc.stdout + proc.stderr
        if "ModuleNotFoundError" in output or "No module named" in output:
            result["note"] = "holehe chưa được cài: pip install holehe"
            return result
        registered = []
        for line in output.splitlines():
            m = _re.match(r"\[\+\]\s+(.+?)\s*(?:-\s*([\w.\-]+))?$", line.strip())
            if m:
                registered.append({
                    "name": m.group(1).strip().rstrip("-").strip(),
                    "domain": (m.group(2) or "").strip(),
                })
        total_lines = output.count("[+]") + output.count("[-]") + output.count("[x]")
        result["registered_sites"] = registered
        result["checked"] = total_lines
    except FileNotFoundError:
        result["note"] = "holehe chưa được cài: pip install holehe"
    except subprocess.TimeoutExpired:
        result["error"] = "holehe timeout (>90s)"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ⑧ EmailRep.io — email reputation & breach signals (free/key optional) ─

def check_emailrep(email: str, api_key: str | None = None) -> dict:
    """
    EmailRep.io — tín hiệu reputation về email: suspicious, blacklisted,
    credentials_leaked, malicious_activity, first_seen, profiles liên kết.
    Free: 1000 req/ngày (không cần key), có key thì rate limit cao hơn.
    Thêm vào .env: EMAILREP_KEY=your_key
    """
    result = {
        "reputation": None, "suspicious": None, "references": 0,
        "blacklisted": False, "credentials_leaked": False,
        "malicious_activity": False, "data_breach": False,
        "first_seen": None, "last_seen": None,
        "profiles": [], "error": None,
    }
    try:
        headers: dict = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}
        if api_key:
            headers["Key"] = api_key
        r = requests.get(
            f"https://emailrep.io/{email}",
            headers=headers,
            timeout=10,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json()
            result["reputation"] = data.get("reputation")
            result["suspicious"] = data.get("suspicious")
            result["references"] = data.get("references", 0)
            det = data.get("details") or {}
            result["blacklisted"] = bool(det.get("blacklisted"))
            result["credentials_leaked"] = bool(det.get("credentials_leaked"))
            result["malicious_activity"] = bool(det.get("malicious_activity"))
            result["data_breach"] = bool(det.get("data_breach"))
            result["first_seen"] = det.get("first_seen")
            result["last_seen"] = det.get("last_seen")
            result["profiles"] = det.get("profiles") or []
        elif r.status_code == 429:
            result["error"] = "EmailRep: Rate limited (free: 1000/ngày)"
        elif r.status_code == 401:
            result["error"] = "EmailRep: API key không hợp lệ"
        elif r.status_code == 400:
            result["error"] = "EmailRep: Email không hợp lệ"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result


# ─── ⑨ Hunter.io — email person enrichment (25 req/tháng free) ─────────

def check_hunter_email(email: str, api_key: str | None = None) -> dict:
    """
    Hunter.io email enrichment — tìm tên, chức danh, công ty, SĐT, LinkedIn, Twitter
    liên quan đến địa chỉ email.
    Free: 25 enrichments/tháng. Đăng ký: https://hunter.io
    Thêm vào .env: HUNTER_KEY=your_api_key
    """
    result = {
        "found": False, "first_name": None, "last_name": None,
        "position": None, "organization": None, "phone_number": None,
        "twitter": None, "linkedin": None, "city": None, "country": None,
        "error": None, "note": None,
    }
    if not api_key:
        result["note"] = (
            "HUNTER_KEY chưa được cài (free: 25 enrichments/tháng).\n"
            "  Đăng ký: https://hunter.io/users/sign_up\n"
            "  Thêm vào .env: HUNTER_KEY=your_api_key"
        )
        return result
    try:
        r = requests.get(
            "https://api.hunter.io/v2/email-enrichment",
            params={"email": email, "api_key": api_key},
            headers={"User-Agent": "OSINT-Tool/1.0"},
            timeout=12,
            verify=True,
        )
        if r.status_code == 200:
            data = r.json().get("data") or {}
            result["found"] = bool(data)
            result["first_name"] = data.get("first_name")
            result["last_name"] = data.get("last_name")
            result["position"] = data.get("position")
            result["organization"] = data.get("organization")
            result["phone_number"] = data.get("phone_number")
            result["twitter"] = data.get("twitter")
            result["linkedin"] = data.get("linkedin_url")
            result["city"] = data.get("city")
            result["country"] = data.get("country")
        elif r.status_code == 404:
            result["found"] = False
        elif r.status_code == 429:
            result["error"] = "Hunter.io: Rate limited — free: 25/tháng"
        elif r.status_code == 401:
            result["error"] = "Hunter.io: API key không hợp lệ"
        else:
            result["error"] = f"HTTP {r.status_code}"
    except Exception as e:
        result["error"] = str(e)
    return result




# Severity scoring based on data classes exposed in breaches
_DATA_CLASS_SEVERITY = {
    # CRITICAL
    "Passwords": 10, "Password hints": 8, "Credit cards": 10,
    "CVVs": 10, "PIN numbers": 9, "Bank account numbers": 10,
    "Social security numbers": 10, "Passport numbers": 9,
    "Biometric data": 10, "Private messages": 7,
    # HIGH
    "Physical addresses": 6, "Phone numbers": 6, "Dates of birth": 6,
    "Government issued IDs": 8, "Driver's licence numbers": 8,
    "Tax identification numbers": 8, "Medical records": 9,
    "Health insurance information": 8, "Financial transactions": 8,
    "Crypto wallet hashes": 7,
    # MEDIUM
    "Email addresses": 4, "Usernames": 4, "Names": 3,
    "Gender": 2, "Ages": 2, "Geographic locations": 3,
    "IP addresses": 3, "Device information": 3,
    "Browser user agent details": 2, "Purchases": 4,
    # LOW
    "Website activity": 2, "Chat logs": 5, "Time zones": 1,
    "Languages": 1, "Education levels": 2, "Job titles": 2,
    "Employers": 2,
}


def calculate_breach_severity(data_classes: list[str]) -> dict:
    """
    Tính mức độ nghiêm trọng của vụ rò rỉ dựa trên loại dữ liệu bị lộ.

    Returns:
        dict với score (0-100), risk_level (LOW/MEDIUM/HIGH/CRITICAL),
        critical_items (các mục nguy hiểm nhất)
    """
    if not data_classes:
        return {"score": 0, "risk_level": "UNKNOWN", "critical_items": []}

    max_score = 0
    total_score = 0
    critical_items = []

    for dc in data_classes:
        severity = _DATA_CLASS_SEVERITY.get(dc, 2)
        total_score += severity
        if severity >= max_score:
            max_score = severity
        if severity >= 7:
            critical_items.append(dc)

    # Normalize: higher total = worse, but cap at 100
    normalized = min(100, int((max_score * 6) + (total_score * 0.5)))

    if normalized >= 70 or max_score >= 9:
        risk_level = "CRITICAL"
        color = "bold red"
    elif normalized >= 50 or max_score >= 7:
        risk_level = "HIGH"
        color = "red"
    elif normalized >= 30 or max_score >= 4:
        risk_level = "MEDIUM"
        color = "yellow"
    else:
        risk_level = "LOW"
        color = "green"

    return {
        "score": normalized,
        "risk_level": risk_level,
        "color": color,
        "critical_items": critical_items,
        "total_data_classes": len(data_classes),
    }

def _breach_dorks(query: str) -> list:
    from urllib.parse import quote_plus
    enc = quote_plus(query)
    return [
        {
            "label": "HaveIBeenPwned (tra cứu thủ công)",
            "url": f"https://haveibeenpwned.com/account/{query}",
        },
        {
            "label": "Dehashed (tìm kiếm dữ liệu rò rỉ)",
            "url": f"https://www.dehashed.com/search?query={enc}",
        },
        {
            "label": "IntelligenceX (Darknet + Pastebin)",
            "url": f"https://intelx.io/?s={enc}",
        },
        {
            "label": "Snusbase (breach database)",
            "url": "https://snusbase.com/",
        },
        {
            "label": "Google: Pastebin",
            "url": f'https://www.google.com/search?q=%22{enc}%22+site%3Apastebin.com',
        },
        {
            "label": "Google: paste / leak sites",
            "url": f'https://www.google.com/search?q=%22{enc}%22+site%3Apastebin.com+OR+site%3Arentry.co+OR+site%3Apaste.ee',
        },
        {
            "label": "Google: leak / breach / dump",
            "url": f'https://www.google.com/search?q=%22{enc}%22+leak+OR+breach+OR+dump+OR+password',
        },
        {
            "label": "GitHub: có trong code bị lộ không",
            "url": f'https://github.com/search?q=%22{enc}%22&type=code',
        },
    ]


# ─── Master function ──────────────────────────────────────────────────────

def breach_check(
    target: str,
    password: str | None = None,
    hibp_key: str | None = None,
    breachdir_key: str | None = None,
    dehashed_email: str | None = None,
    dehashed_key: str | None = None,
    snusbase_key: str | None = None,
    emailrep_key: str | None = None,
    hunter_key: str | None = None,
) -> dict:
    """
    Kiểm tra toàn diện: email/username có bị lộ trong các vụ breach không.

    Nguồn miễn phí (không cần key):
      ① LeakCheck.io   — tìm tên nguồn breach
      ⑦ Holehe          — email đăng ký trên 100+ dịch vụ nào
      ⑧ EmailRep.io     — reputation, blacklist, breach signals

    Nguồn free tier (cần đăng ký miễn phí):
      ② BreachDirectory — loại dữ liệu bị lộ (env: BREACHDIRECTORY_KEY)
      ④ HIBP            — danh sách breach nổi tiếng ($3.95/mo, env: HIBP_API_KEY)
      ⑨ Hunter.io       — enrichment người liên kết (env: HUNTER_KEY)

    Nguồn trả phí (bản ghi đầy đủ — password, name, address, phone thực tế):
      ⑤ Dehashed        — $5/mo (env: DEHASHED_EMAIL + DEHASHED_KEY)
      ⑥ Snusbase        — $2/mo (env: SNUSBASE_KEY)
    """
    result = {
        "target": target,
        "leakcheck": None,
        "breachdirectory": None,
        "hibp": None,
        "dehashed": None,
        "snusbase": None,
        "holehe": None,
        "emailrep": None,
        "hunter": None,
        "pwned_password": None,
        "dorks": _breach_dorks(target),
        "summary": {
            "total_breaches": 0,
            "total_pastes": 0,
            "sources_checked": [],
        },
    }

    is_email = bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target))

    # ① LeakCheck public (hoàn toàn miễn phí)
    lc = check_leakcheck_public(target)
    result["leakcheck"] = lc
    result["summary"]["sources_checked"].append("LeakCheck.io")
    if lc.get("found"):
        result["summary"]["total_breaches"] += max(len(lc.get("sources", [])), 1)

    # ② BreachDirectory (free RapidAPI key)
    bd = check_breachdirectory(target, breachdir_key)
    result["breachdirectory"] = bd
    if breachdir_key:
        result["summary"]["sources_checked"].append("BreachDirectory")
        if bd.get("found"):
            result["summary"]["total_breaches"] += bd.get("size") or len(bd.get("result", []))

    # ③ HIBP email (tùy chọn, cần paid key)
    hibp = check_hibp_email(target, hibp_key)
    result["hibp"] = hibp
    if hibp_key:
        result["summary"]["sources_checked"].append("HaveIBeenPwned")
        result["summary"]["total_breaches"] += len(hibp.get("breaches", []))
        result["summary"]["total_pastes"] += len(hibp.get("pastes", []))

    # ④ HIBP Pwned Passwords (nếu nhập mật khẩu)
    if password:
        pwned = check_pwned_password(password)
        result["pwned_password"] = pwned
        result["summary"]["sources_checked"].append("HIBP Pwned Passwords")

    # ⑤ Dehashed — bản ghi thực tế (email, name, phone, address, ip, hash)
    dh = check_dehashed(target, "email" if is_email else "username",
                        dehashed_email, dehashed_key)
    result["dehashed"] = dh
    if dehashed_email and dehashed_key:
        result["summary"]["sources_checked"].append("Dehashed")
        if dh.get("found"):
            result["summary"]["total_breaches"] += min(dh.get("total", 0), 9999)

    # ⑥ Snusbase — bản ghi thực tế
    sn = check_snusbase(target, "email" if is_email else "username", snusbase_key)
    result["snusbase"] = sn
    if snusbase_key:
        result["summary"]["sources_checked"].append("Snusbase")
        if sn.get("found"):
            result["summary"]["total_breaches"] += sn.get("total", 0)

    # ⑦ Holehe — tìm xem email đăng ký trên dịch vụ nào (chỉ chạy với email)
    if is_email:
        result["holehe"] = check_holehe(target)
        result["summary"]["sources_checked"].append("Holehe")

    # ⑧ EmailRep (miễn phí, key tùy chọn) — chỉ chạy với email
    if is_email:
        result["emailrep"] = check_emailrep(target, emailrep_key)
        result["summary"]["sources_checked"].append("EmailRep.io")

    # ⑨ Hunter.io enrichment (cần key, miễn phí 25/tháng) — chỉ với email
    if is_email and hunter_key:
        result["hunter"] = check_hunter_email(target, hunter_key)
        result["summary"]["sources_checked"].append("Hunter.io")

    return result


# ─── Rich console output ──────────────────────────────────────────────────

def print_breach_results(data: dict):
    target = data.get("target", "")
    summary = data.get("summary", {})
    total = summary.get("total_breaches", 0)
    total_pastes = summary.get("total_pastes", 0)
    srcs = summary.get("sources_checked", [])

    console.print(f"\n[bold red]═══ Breach Check: {target} ═══[/bold red]")

    # Tổng kết
    if total > 0 or total_pastes > 0:
        console.print(f"  [bold red]⚠  TÌM THẤY trong ~{total} vụ rò rỉ"
                      + (f" + {total_pastes} paste(s)" if total_pastes else "") + "[/bold red]")
    else:
        console.print("  [bold green]✓  Không tìm thấy trong các nguồn đã kiểm tra[/bold green]")

    if srcs:
        console.print(f"  [dim]Nguồn đã kiểm tra: {', '.join(srcs)}[/dim]")

    # ② LeakCheck
    lc = data.get("leakcheck", {}) or {}
    console.print("\n  [bold cyan]① LeakCheck.io[/bold cyan] [dim](miễn phí, không cần key)[/dim]")
    if lc.get("error"):
        console.print(f"    [red]✗ Lỗi: {lc['error']}[/red]")
    elif lc.get("note"):
        console.print(f"    [dim]{lc['note']}[/dim]")
    elif lc.get("found"):
        sources = lc.get("sources", [])
        console.print(f"    [red]⚠ Xuất hiện trong {len(sources)} nguồn rò rỉ:[/red]")
        for s in sources[:12]:
            console.print(f"      • {s}")
    else:
        console.print("    [green]✓ Không tìm thấy[/green]")

    # ③ BreachDirectory
    bd = data.get("breachdirectory", {}) or {}
    console.print("\n  [bold cyan]② BreachDirectory[/bold cyan] [dim](RapidAPI free tier)[/dim]")
    if bd.get("note"):
        for line in bd["note"].splitlines():
            console.print(f"    [dim]{line}[/dim]")
    elif bd.get("error"):
        console.print(f"    [red]✗ {bd['error']}[/red]")
    elif bd.get("found"):
        results = bd.get("result", [])
        size = bd.get("size", len(results))
        console.print(f"    [red]⚠ Tìm thấy {size} bản ghi trong database rò rỉ:[/red]")
        t = Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
        t.add_column("Nguồn (Source)", style="dim", min_width=20)
        t.add_column("Loại dữ liệu bị lộ")
        t.add_column("Hash type", style="dim")
        for entry in results[:15]:
            src_raw = entry.get("sources", [])
            src = src_raw[0] if isinstance(src_raw, list) and src_raw else str(src_raw or "?")
            fields = entry.get("fields", [])
            h_type = entry.get("password_type", "")
            t.add_row(src, ", ".join(fields) if fields else "—", h_type or "—")
        console.print(t)
        if size > 15:
            console.print(f"    [dim]... và {size - 15} bản ghi khác[/dim]")
    else:
        console.print("    [green]✓ Không tìm thấy[/green]")

    # ④ HIBP
    hibp = data.get("hibp", {}) or {}
    console.print("\n  [bold cyan]③ HaveIBeenPwned[/bold cyan] [dim](tùy chọn — $3.95/tháng)[/dim]")
    if hibp.get("note"):
        for line in hibp["note"].splitlines():
            console.print(f"    [dim]{line}[/dim]")
    elif hibp.get("error"):
        console.print(f"    [red]✗ {hibp['error']}[/red]")
    else:
        breaches = hibp.get("breaches", [])
        pastes = hibp.get("pastes", [])
        if breaches:
            console.print(f"    [red]⚠ Có trong {len(breaches)} vụ rò rỉ:[/red]")
            t = Table(show_header=True, header_style="bold red", box=None, padding=(0, 2))
            t.add_column("Tên vụ rò rỉ", min_width=20)
            t.add_column("Ngày")
            t.add_column("Số bản ghi", justify="right")
            t.add_column("Loại dữ liệu")
            t.add_column("Mức độ", width=10)
            for b in breaches:
                data_classes = b.get("data_classes") or []
                sev = calculate_breach_severity(data_classes)
                risk = sev.get("risk_level", "?")
                risk_color = sev.get("color", "white")
                t.add_row(
                    b.get("name") or "?",
                    b.get("date") or "?",
                    f'{b["pwn_count"]:,}' if b.get("pwn_count") else "?",
                    ", ".join(data_classes[:4]),
                    f"[{risk_color}]{risk}[/{risk_color}]",
                )
            console.print(t)
            # Show most critical items across all breaches
            all_critical = set()
            for b in breaches:
                sev = calculate_breach_severity(b.get("data_classes") or [])
                all_critical.update(sev.get("critical_items", []))
            if all_critical:
                console.print(f"    [bold red]Dữ liệu nhạy cảm nhất bị lộ: {', '.join(sorted(all_critical))}[/bold red]")
        else:
            console.print("    [green]✓ Không tìm thấy trong HIBP breaches[/green]")
        if pastes:
            console.print(f"    [yellow]⚠ Xuất hiện trong {len(pastes)} paste(s) công khai[/yellow]")

    # ⑤ Dehashed — actual breach records
    dh = data.get("dehashed") or {}
    console.print("\n  [bold cyan]⑤ Dehashed[/bold cyan] [dim](bản ghi thực tế — $5/tháng)[/dim]")
    if dh.get("note"):
        for line in dh["note"].splitlines():
            console.print(f"    [dim]{line}[/dim]")
    elif dh.get("error"):
        console.print(f"    [red]✗ {dh['error']}[/red]")
    elif dh.get("found"):
        entries = dh.get("entries") or []
        total = dh.get("total", len(entries))
        bal = f"  [dim](balance: {dh['balance']} queries còn lại)[/dim]" if dh.get("balance") else ""
        console.print(f"    [bold red]⚠ {total} bản ghi tìm thấy{bal}:[/bold red]")
        dt = Table(show_header=True, header_style="bold red", show_lines=True, padding=(0, 1))
        dt.add_column("Database", min_width=16, style="dim")
        dt.add_column("Email", min_width=20)
        dt.add_column("Tên thật", min_width=14)
        dt.add_column("Password / Hash", min_width=20)
        dt.add_column("Số điện thoại", min_width=12)
        dt.add_column("Địa chỉ", min_width=14)
        dt.add_column("IP", width=16)
        for e in entries[:20]:
            pw = e.get("password") or ""
            hp = (e.get("hashed_password") or "")
            pw_display = pw if pw else (f"[dim]{hp[:28]}…[/dim]" if hp else "—")
            dt.add_row(
                (e.get("database_name") or "?")[:20],
                (e.get("email") or "—")[:30],
                (e.get("name") or "—")[:16],
                pw_display,
                (e.get("phone") or "—")[:14],
                (e.get("address") or "—")[:20],
                (e.get("ip_address") or "—")[:16],
            )
        console.print(dt)
        if total > 20:
            console.print(f"    [dim]... và {total - 20} bản ghi khác[/dim]")
    else:
        console.print("    [green]✓ Không tìm thấy[/green]")

    # ⑥ Snusbase — actual breach records
    sn = data.get("snusbase") or {}
    console.print("\n  [bold cyan]⑥ Snusbase[/bold cyan] [dim](bản ghi thực tế — $2/tháng)[/dim]")
    if sn.get("note"):
        for line in sn["note"].splitlines():
            console.print(f"    [dim]{line}[/dim]")
    elif sn.get("error"):
        console.print(f"    [red]✗ {sn['error']}[/red]")
    elif sn.get("found"):
        entries = sn.get("entries") or []
        total = sn.get("total", len(entries))
        console.print(f"    [bold red]⚠ {total} bản ghi tìm thấy:[/bold red]")
        st = Table(show_header=True, header_style="bold red", show_lines=True, padding=(0, 1))
        st.add_column("Database (table)", min_width=16, style="dim")
        st.add_column("Email", min_width=22)
        st.add_column("Username", min_width=14)
        st.add_column("Password", min_width=18)
        st.add_column("Hash / type", min_width=16)
        st.add_column("Tên thật", min_width=14)
        st.add_column("IP", width=16)
        for e in entries[:20]:
            h = (e.get("hash") or "")
            ht = e.get("hash_type") or ""
            hash_display = f"{h[:20]}… [{ht}]" if h else "—"
            st.add_row(
                (e.get("table") or "?")[:20],
                (e.get("email") or "—")[:30],
                (e.get("username") or "—")[:16],
                (e.get("password") or "—")[:22],
                hash_display,
                (e.get("name") or "—")[:16],
                (e.get("ip") or "—")[:16],
            )
        console.print(st)
        if total > 20:
            console.print(f"    [dim]... và {total - 20} bản ghi khác[/dim]")
    else:
        console.print("    [green]✓ Không tìm thấy[/green]")

    # ⑦ Holehe — sites registered
    ho = data.get("holehe")
    if ho is not None:
        console.print("\n  [bold cyan]⑦ Holehe[/bold cyan] [dim](email đăng ký trên dịch vụ nào — miễn phí)[/dim]")
        if ho.get("note"):
            console.print(f"    [dim]{ho['note']}[/dim]")
        elif ho.get("error"):
            console.print(f"    [red]✗ {ho['error']}[/red]")
        else:
            sites = ho.get("registered_sites") or []
            checked = ho.get("checked", 0)
            if sites:
                console.print(f"    [red]⚠ Tìm thấy trên {len(sites)}/{checked} dịch vụ được kiểm tra:[/red]")
                ht = Table(show_header=False, box=None, padding=(0, 2))
                ht.add_column("🌐", style="cyan", min_width=18)
                ht.add_column("Domain", style="dim")
                for row in sites:
                    ht.add_row(row.get("name", "?"), row.get("domain", ""))
                console.print(ht)
            else:
                console.print(f"    [green]✓ Không tìm thấy trên {checked} dịch vụ đã kiểm tra[/green]")

    # ⑧ EmailRep reputation
    er = data.get("emailrep")
    if er is not None:
        console.print("\n  [bold cyan]⑧ EmailRep.io[/bold cyan] [dim](reputation & breach signals — miễn phí)[/dim]")
        if er.get("error"):
            console.print(f"    [red]✗ {er['error']}[/red]")
        else:
            rep = er.get("reputation") or "unknown"
            sus = er.get("suspicious")
            rep_color = "red" if sus else ("yellow" if rep in ("low", "none") else "green")
            console.print(f"    Reputation : [{rep_color}]{rep}[/{rep_color}]  Suspicious: [{rep_color}]{sus}[/{rep_color}]  References: {er.get('references', 0)}")
            flags = []
            if er.get("blacklisted"):       flags.append("[bold red]Blacklisted[/bold red]")
            if er.get("credentials_leaked"): flags.append("[red]Credentials leaked[/red]")
            if er.get("data_breach"):        flags.append("[red]Data breach[/red]")
            if er.get("malicious_activity"): flags.append("[red]Malicious activity[/red]")
            if flags:
                console.print("    Flags      : " + "  ".join(flags))
            if er.get("first_seen"):
                console.print(f"    Email seen : first {er['first_seen']}  →  last {er.get('last_seen') or '?'}")
            profiles = er.get("profiles") or []
            if profiles:
                console.print(f"    Profiles   : [cyan]{', '.join(profiles[:10])}[/cyan]")

    # ⑨ Hunter.io enrichment
    hu = data.get("hunter")
    if hu is not None:
        console.print("\n  [bold cyan]⑨ Hunter.io[/bold cyan] [dim](enrichment — 25/tháng free)[/dim]")
        if hu.get("note"):
            console.print(f"    [dim]{hu['note']}[/dim]")
        elif hu.get("error"):
            console.print(f"    [red]✗ {hu['error']}[/red]")
        elif hu.get("found"):
            name = " ".join(filter(None, [hu.get("first_name"), hu.get("last_name")])) or "?"
            console.print(f"    Tên thật   : [bold]{name}[/bold]")
            if hu.get("position"):    console.print(f"    Chức danh  : {hu['position']}")
            if hu.get("organization"): console.print(f"    Công ty    : {hu['organization']}")
            if hu.get("phone_number"): console.print(f"    Điện thoại : [red]{hu['phone_number']}[/red]")
            if hu.get("linkedin"):     console.print(f"    LinkedIn   : [cyan]{hu['linkedin']}[/cyan]")
            if hu.get("twitter"):      console.print(f"    Twitter    : [cyan]@{hu['twitter']}[/cyan]")
            if hu.get("city") or hu.get("country"):
                console.print(f"    Vị trí     : {hu.get('city', '')} {hu.get('country', '')}")
        else:
            console.print("    [dim]Không tìm thấy thông tin enrichment[/dim]")

    # ④ Pwned Passwords
    pwned = data.get("pwned_password")
    if pwned is not None:
        console.print("\n  [bold cyan]⑩ HIBP Pwned Passwords[/bold cyan] [dim](mật khẩu — miễn phí)[/dim]")
        if pwned.get("error"):
            console.print(f"    [red]✗ {pwned['error']}[/red]")
        elif pwned.get("exposed"):
            console.print(
                f"    [bold red]⚠  MẬT KHẨU ĐÃ BỊ LỘ {pwned['count']:,} LẦN![/bold red]"
            )
            console.print("    [red]→ Hãy đổi mật khẩu này ngay lập tức trên tất cả dịch vụ sử dụng nó.[/red]")
        else:
            console.print("    [green]✓ Mật khẩu chưa xuất hiện trong các vụ rò rỉ đã biết[/green]")

    # Dorks
    if data.get("dorks"):
        console.print("\n  [bold]Tra cứu thêm:[/bold]")
        for d in data["dorks"]:
            console.print(f"    [cyan]{d['label']}:[/cyan]")
            console.print(f"      [dim]{d['url']}[/dim]")

