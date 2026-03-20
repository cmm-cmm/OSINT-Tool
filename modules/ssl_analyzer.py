"""
SSL/TLS Analyzer Module
=======================
Phân tích bảo mật SSL/TLS của domain:
  - Thông tin chứng chỉ: subject, issuer, validity dates, SANs, serial
  - Phiên bản TLS đang dùng (TLS 1.0/1.1 = nguy hiểm, 1.2 = ok, 1.3 = tốt nhất)
  - Cipher suite đang dùng
  - HSTS header + max-age
  - Certificate Transparency (crt.sh entries count)
  - Tính điểm bảo mật A+/A/B/C/D/F

Chỉ dùng thư viện chuẩn (ssl, socket, datetime) + requests (đã có).
"""
import ssl
import socket
import datetime
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()
HEADERS = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}

# TLS version mapping
_TLS_VERSIONS = {
    "TLSv1":   ("TLS 1.0", "critical", "Đã bị vô hiệu hóa trong hầu hết trình duyệt"),
    "TLSv1.1": ("TLS 1.1", "high",     "Deprecated theo RFC 8996 (2021)"),
    "TLSv1.2": ("TLS 1.2", "ok",       "Chấp nhận được, nhưng nên dùng TLS 1.3"),
    "TLSv1.3": ("TLS 1.3", "best",     "Phiên bản bảo mật tốt nhất hiện tại"),
}

# Data classes đánh giá cipher suite
_WEAK_CIPHERS = {"RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"}


def _get_ssl_cert(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Kết nối SSL và lấy thông tin certificate + TLS negotiation."""
    result = {
        "connected": False,
        "tls_version": None,
        "cipher_name": None,
        "cipher_bits": None,
        "cert_raw": None,
        "error": None,
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                result["connected"] = True
                result["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_name"] = cipher[0]
                    result["cipher_bits"] = cipher[2]
                result["cert_raw"] = ssock.getpeercert()
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except socket.timeout:
        result["error"] = f"Connection timed out ({timeout}s)"
    except ConnectionRefusedError:
        result["error"] = "Connection refused (port 443 closed)"
    except Exception as e:
        result["error"] = str(e)
    return result


def _parse_cert(cert_raw: dict) -> dict:
    """Trích xuất thông tin hữu ích từ cert dict trả về bởi ssl.getpeercert()."""
    if not cert_raw:
        return {}

    parsed = {}

    # Subject
    subject = dict(x[0] for x in cert_raw.get("subject", []))
    parsed["common_name"] = subject.get("commonName", "N/A")
    parsed["org"] = subject.get("organizationName", "N/A")
    parsed["country"] = subject.get("countryName", "N/A")

    # Issuer
    issuer = dict(x[0] for x in cert_raw.get("issuer", []))
    parsed["issuer_cn"] = issuer.get("commonName", "N/A")
    parsed["issuer_org"] = issuer.get("organizationName", "N/A")

    # Serial
    parsed["serial_number"] = cert_raw.get("serialNumber", "N/A")

    # Validity dates
    not_before_str = cert_raw.get("notBefore", "")
    not_after_str = cert_raw.get("notAfter", "")
    fmt = "%b %d %H:%M:%S %Y %Z"
    try:
        parsed["not_before"] = datetime.datetime.strptime(not_before_str, fmt)
    except Exception:
        parsed["not_before"] = None

    try:
        parsed["not_after"] = datetime.datetime.strptime(not_after_str, fmt)
    except Exception:
        parsed["not_after"] = None

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if parsed.get("not_after"):
        delta = parsed["not_after"] - now
        parsed["days_until_expiry"] = delta.days
        parsed["expired"] = delta.days < 0
        parsed["expiring_soon"] = 0 <= delta.days <= 30
    else:
        parsed["days_until_expiry"] = None
        parsed["expired"] = False
        parsed["expiring_soon"] = False

    # Subject Alternative Names
    sans = []
    for san_type, san_value in cert_raw.get("subjectAltName", []):
        if san_type == "DNS":
            sans.append(san_value)
    parsed["sans"] = sans
    parsed["san_count"] = len(sans)

    # Wildcard check
    parsed["is_wildcard"] = any(s.startswith("*.") for s in sans)

    return parsed


def _check_hsts(hostname: str, timeout: int = 8) -> dict:
    """Kiểm tra HSTS header và max-age."""
    result = {"enabled": False, "max_age": None, "include_subdomains": False,
              "preload": False, "raw": None}
    try:
        resp = requests.get(
            f"https://{hostname}", headers=HEADERS, timeout=timeout,
            allow_redirects=True, verify=True
        )
        hsts = resp.headers.get("strict-transport-security", "")
        if hsts:
            result["enabled"] = True
            result["raw"] = hsts
            for part in hsts.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age"):
                    try:
                        result["max_age"] = int(part.split("=", 1)[1].strip())
                    except (ValueError, IndexError):
                        pass
                elif part == "includesubdomains":
                    result["include_subdomains"] = True
                elif part == "preload":
                    result["preload"] = True
    except Exception:
        pass
    return result


def _grade_ssl(tls_version: str | None, cipher_name: str | None,
               cert: dict, hsts: dict) -> tuple[str, list]:
    """
    Tính điểm SSL/TLS theo thang A+/A/B/C/D/F.
    Trả về (grade, list_of_issues).
    """
    issues = []
    deductions = 0

    if not tls_version:
        return "F", ["Không thể kết nối SSL/TLS"]

    # TLS version check
    ver_label, ver_status, ver_msg = _TLS_VERSIONS.get(tls_version, (tls_version, "ok", ""))
    if ver_status == "critical":
        deductions += 50
        issues.append(f"🔴 {ver_label}: {ver_msg}")
    elif ver_status == "high":
        deductions += 30
        issues.append(f"🟠 {ver_label}: {ver_msg}")
    elif ver_status == "best":
        pass  # bonus
    else:
        deductions += 5  # TLS 1.2 is ok but not perfect

    # Cipher suite check
    if cipher_name:
        for weak in _WEAK_CIPHERS:
            if weak in cipher_name.upper():
                deductions += 30
                issues.append(f"🔴 Cipher yếu: {cipher_name}")
                break
        if cipher_name.startswith("ECDHE") or "DHE" in cipher_name:
            pass  # Forward secrecy — good
        elif "RSA" in cipher_name and "ECDHE" not in cipher_name:
            deductions += 10
            issues.append(f"🟡 Không có Forward Secrecy: {cipher_name}")

    # Certificate issues
    if cert.get("expired"):
        deductions += 50
        issues.append("🔴 Chứng chỉ đã HẾT HẠN")
    elif cert.get("expiring_soon"):
        days = cert.get("days_until_expiry", 0)
        deductions += 15
        issues.append(f"🟠 Chứng chỉ sắp hết hạn ({days} ngày)")

    # HSTS check
    if not hsts.get("enabled"):
        deductions += 15
        issues.append("🟡 Thiếu HSTS header (strict-transport-security)")
    else:
        max_age = hsts.get("max_age", 0) or 0
        if max_age < 31536000:
            deductions += 5
            issues.append(f"🟡 HSTS max-age quá thấp: {max_age}s (nên >= 31536000)")
        if not hsts.get("preload"):
            issues.append("ℹ️  HSTS chưa có 'preload' directive")

    # Grading
    score = max(0, 100 - deductions)
    if score >= 95 and not issues:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 65:
        grade = "C"
    elif score >= 50:
        grade = "D"
    else:
        grade = "F"

    return grade, issues


def ssl_analyze(hostname: str, port: int = 443) -> dict:
    """
    Phân tích SSL/TLS đầy đủ cho một domain/hostname.

    Returns dict với:
      - connected, tls_version, cipher, cert, hsts, grade, issues
    """
    result = {
        "hostname": hostname,
        "port": port,
        "connected": False,
        "tls_version": None,
        "tls_label": None,
        "tls_status": None,
        "cipher_name": None,
        "cipher_bits": None,
        "cert": {},
        "hsts": {},
        "grade": "N/A",
        "issues": [],
        "error": None,
    }

    # Step 1: SSL connection
    conn = _get_ssl_cert(hostname, port)
    result["connected"] = conn["connected"]
    result["error"] = conn.get("error")

    if not conn["connected"]:
        return result

    result["tls_version"] = conn["tls_version"]
    result["cipher_name"] = conn["cipher_name"]
    result["cipher_bits"] = conn["cipher_bits"]

    if conn["tls_version"] in _TLS_VERSIONS:
        label, status, _ = _TLS_VERSIONS[conn["tls_version"]]
        result["tls_label"] = label
        result["tls_status"] = status

    # Step 2: Parse certificate
    result["cert"] = _parse_cert(conn["cert_raw"])

    # Step 3: HSTS check
    result["hsts"] = _check_hsts(hostname)

    # Step 4: Grade
    result["grade"], result["issues"] = _grade_ssl(
        conn["tls_version"], conn["cipher_name"],
        result["cert"], result["hsts"]
    )

    return result


def print_ssl_results(data: dict):
    """Hiển thị kết quả phân tích SSL/TLS bằng Rich."""
    hostname = data.get("hostname", "")
    console.print(f"\n[bold cyan]═══ SSL/TLS ANALYSIS: {hostname} ═══[/bold cyan]")

    if not data.get("connected"):
        error = data.get("error") or "Không thể kết nối"
        console.print(f"  [red]✗ {error}[/red]")
        console.print("  [dim]Lưu ý: Một số domain không hỗ trợ HTTPS hoặc dùng cổng khác[/dim]")
        return

    # Grade badge
    grade = data.get("grade", "N/A")
    grade_colors = {"A+": "bold green", "A": "green", "B": "cyan",
                    "C": "yellow", "D": "orange3", "F": "red", "N/A": "dim"}
    grade_color = grade_colors.get(grade, "white")
    console.print(f"\n  SSL Grade: [{grade_color}] {grade} [/{grade_color}]")

    # Main info table
    table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
    table.add_column("Thuộc tính", style="cyan", width=26)
    table.add_column("Giá trị", style="white")

    tls_ver = data.get("tls_label") or data.get("tls_version") or "N/A"
    tls_status = data.get("tls_status", "ok")
    tls_colors = {"best": "green", "ok": "yellow", "high": "orange3", "critical": "red"}
    tls_color = tls_colors.get(tls_status, "white")
    table.add_row("TLS Version", f"[{tls_color}]{tls_ver}[/{tls_color}]")

    cipher = data.get("cipher_name", "N/A")
    bits = data.get("cipher_bits")
    cipher_str = f"{cipher} ({bits}-bit)" if bits else cipher
    table.add_row("Cipher Suite", cipher_str)

    cert = data.get("cert", {})
    if cert:
        table.add_row("Common Name", cert.get("common_name", "N/A"))
        table.add_row("Tổ chức", cert.get("org", "N/A"))
        table.add_row("Issuer", cert.get("issuer_cn", "N/A"))
        table.add_row("Issuer Org", cert.get("issuer_org", "N/A"))

        not_after = cert.get("not_after")
        days = cert.get("days_until_expiry")
        if not_after:
            exp_str = not_after.strftime("%Y-%m-%d")
            if cert.get("expired"):
                exp_str = f"[bold red]{exp_str} (ĐÃ HẾT HẠN)[/bold red]"
            elif cert.get("expiring_soon"):
                exp_str = f"[yellow]{exp_str} (còn {days} ngày)[/yellow]"
            else:
                exp_str = f"[green]{exp_str} (còn {days} ngày)[/green]"
            table.add_row("Hết hạn", exp_str)

        table.add_row("Wildcard cert", "✓ Có" if cert.get("is_wildcard") else "✗ Không")
        san_count = cert.get("san_count", 0)
        table.add_row("SAN count", str(san_count))

    # HSTS
    hsts = data.get("hsts", {})
    if hsts.get("enabled"):
        max_age = hsts.get("max_age")
        hsts_str = f"[green]✓ Bật[/green]"
        if max_age:
            years = max_age // 31536000
            hsts_str += f" — max-age={max_age:,}s"
            if years >= 1:
                hsts_str += f" (~{years} năm)"
        if hsts.get("include_subdomains"):
            hsts_str += " + includeSubDomains"
        if hsts.get("preload"):
            hsts_str += " [green]+ preload[/green]"
    else:
        hsts_str = "[red]✗ Chưa bật[/red]"
    table.add_row("HSTS", hsts_str)

    console.print(table)

    # SANs list (first 10)
    sans = cert.get("sans", [])
    if sans:
        console.print(f"\n  [bold]Subject Alternative Names ({len(sans)}):[/bold]")
        for san in sans[:10]:
            console.print(f"    • {san}")
        if len(sans) > 10:
            console.print(f"    [dim]... và {len(sans) - 10} SAN khác[/dim]")

    # Issues
    issues = data.get("issues", [])
    if issues:
        console.print("\n  [bold yellow]Vấn đề bảo mật:[/bold yellow]")
        for issue in issues:
            console.print(f"    {issue}")
    else:
        console.print("\n  [green]✓ Không phát hiện vấn đề bảo mật SSL/TLS nghiêm trọng[/green]")
