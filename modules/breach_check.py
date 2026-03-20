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

console = Console()

_HEADERS = {
    "User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)",
    "Accept": "application/json",
}


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


# ─── Investigation dorks ──────────────────────────────────────────────────

def _breach_dorks(query: str) -> list:
    enc = query.replace(" ", "+").replace("@", "%40").replace("_", "%5F")
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
) -> dict:
    """
    Kiểm tra toàn diện: email/username có bị lộ trong các vụ breach không.

    Args:
        target:        Email hoặc username cần kiểm tra.
        password:      Mật khẩu để kiểm tra qua HIBP Pwned Passwords (tùy chọn).
        hibp_key:      HIBP API key (env: HIBP_API_KEY).
        breachdir_key: BreachDirectory RapidAPI key (env: BREACHDIRECTORY_KEY).
    """
    result = {
        "target": target,
        "leakcheck": None,
        "breachdirectory": None,
        "hibp": None,
        "pwned_password": None,
        "dorks": _breach_dorks(target),
        "summary": {
            "total_breaches": 0,
            "total_pastes": 0,
            "sources_checked": [],
        },
    }

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
            for b in breaches:
                t.add_row(
                    b.get("name") or "?",
                    b.get("date") or "?",
                    f'{b["pwn_count"]:,}' if b.get("pwn_count") else "?",
                    ", ".join((b.get("data_classes") or [])[:4]),
                )
            console.print(t)
        else:
            console.print("    [green]✓ Không tìm thấy trong HIBP breaches[/green]")
        if pastes:
            console.print(f"    [yellow]⚠ Xuất hiện trong {len(pastes)} paste(s) công khai[/yellow]")

    # ⑤ Pwned Passwords
    pwned = data.get("pwned_password")
    if pwned is not None:
        console.print("\n  [bold cyan]④ HIBP Pwned Passwords[/bold cyan] [dim](mật khẩu — miễn phí)[/dim]")
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
