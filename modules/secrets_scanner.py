"""
Secrets & Exposed Files Scanner Module
=======================================
Quét các file nhạy cảm bị lộ trên website:
  - .git directory exposure (source code leak)
  - .env file exposure (credentials/keys leak)
  - Backup files (.bak, .old, .zip, .tar.gz, db.sql, ...)
  - security.txt / .well-known/security.txt
  - robots.txt (hidden paths)
  - Sensitive admin/config paths
  - API key patterns trong page source
  - AWS/GCP/Azure key patterns
  - Cloud storage bucket URLs trong source
  - phpinfo() exposure
  - Vulnerability risk scoring

Không cần API key — chỉ dùng requests.
"""
import re
import certifi
import requests
from rich.console import Console
from rich.table import Table
from rich import box
from modules.utils import make_session, RateLimiter

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; OSINT-Tool/1.0; +Research)"}
_session = make_session(retries=2, backoff_factor=0.3)
_rate_limiter = RateLimiter(calls=10, period=1.0)
TIMEOUT = 8

# Severity levels for findings
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Path severity mapping
PATH_SEVERITY = {
    ".git/": SEVERITY_CRITICAL,
    ".env": SEVERITY_CRITICAL,
    ".env.production": SEVERITY_CRITICAL,
    "id_rsa": SEVERITY_CRITICAL,
    "database.sql": SEVERITY_CRITICAL,
    "db.sql": SEVERITY_CRITICAL,
    "dump.sql": SEVERITY_CRITICAL,
    "backup.sql": SEVERITY_CRITICAL,
    "wp-config.php": SEVERITY_CRITICAL,
    ".htpasswd": SEVERITY_HIGH,
    "phpinfo.php": SEVERITY_HIGH,
    "actuator/env": SEVERITY_HIGH,
    "backup.zip": SEVERITY_HIGH,
    "admin/": SEVERITY_MEDIUM,
    "swagger.json": SEVERITY_MEDIUM,
    "graphql": SEVERITY_MEDIUM,
    "robots.txt": SEVERITY_INFO,
    "security.txt": SEVERITY_INFO,
}

def get_finding_severity(path: str, has_secrets: bool = False) -> str:
    """Determine severity of a finding based on path and content."""
    if has_secrets:
        return SEVERITY_CRITICAL

    path_lower = path.lower()

    # Check exact matches first
    for pattern, severity in PATH_SEVERITY.items():
        if pattern in path_lower:
            return severity

    # Default based on file type
    if any(ext in path_lower for ext in ['.bak', '.old', '.backup', '.sql', '.zip', '.tar.gz']):
        return SEVERITY_HIGH
    elif any(word in path_lower for word in ['config', 'credentials', 'password', 'secret']):
        return SEVERITY_HIGH
    elif any(word in path_lower for word in ['admin', 'debug', 'test', 'swagger', 'api-docs']):
        return SEVERITY_MEDIUM

    return SEVERITY_LOW

# ─── Sensitive paths to probe ─────────────────────────────────────────────────

_GIT_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/COMMIT_EDITMSG",
    ".git/index",
]

_ENV_PATHS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".env.backup",
    ".env.bak",
    ".env.example",
    ".env.sample",
    ".env.dist",
    "config.env",
    "app.env",
    ".envrc",
    "env.js",
    "env.json",
]

_BACKUP_PATHS = [
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backup.tar",
    "backup.7z",
    "db.sql",
    "database.sql",
    "dump.sql",
    "data.sql",
    "site.zip",
    "www.zip",
    "public_html.zip",
    "html.zip",
    "web.zip",
    "wp-config.php.bak",
    "config.php.bak",
    "config.bak",
    "web.config.bak",
    "settings.py.bak",
    ".htpasswd",
    ".htaccess",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "known_hosts",
    "authorized_keys",
]

_SENSITIVE_PATHS = [
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
    "admin/",
    "wp-admin/",
    "administrator/",
    "phpmyadmin/",
    "pma/",
    "mysql/",
    "adminer.php",
    "server-status",       # Apache mod_status
    "server-info",
    "actuator",            # Spring Boot Actuator
    "actuator/env",
    "actuator/health",
    "actuator/mappings",
    "actuator/beans",
    "actuator/loggers",
    "api/swagger.json",
    "api/v1/swagger.json",
    "api/v2/swagger.json",
    "swagger.json",
    "swagger-ui.html",
    "swagger-ui/index.html",
    "openapi.json",
    "api-docs",
    "graphql",             # GraphQL introspection
    "console",             # Grails/Play console
    "web.config",
    "crossdomain.xml",
    "clientaccesspolicy.xml",
    "sitemap.xml",
    # Config files commonly left accessible
    "config.yml",
    "config.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "appsettings.json",
    "appsettings.Development.json",
    "application.properties",
    "application.yml",
    "settings.json",
    "credentials.json",
    "secrets.json",
    "secrets.yaml",
    "config.json",
    "parameters.yml",
    "database.yml",
    "wp-config.php",
    "configuration.php",
    "settings.php",
    # Node.js / JS
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "composer.json",
    "requirements.txt",
    # Source map
    "main.js.map",
    "app.js.map",
    "bundle.js.map",
    # Monitoring / debug
    "_profiler",           # Symfony profiler
    "_debugbar",
    "telescope",           # Laravel Telescope
    "horizon",             # Laravel Horizon
    "kibana",
    "grafana",
    "prometheus",
    "metrics",
]

_SECURITY_TXT_PATHS = [
    ".well-known/security.txt",
    "security.txt",
]

# ─── API Key Patterns ─────────────────────────────────────────────────────────

_API_KEY_PATTERNS = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s:='\"][\s]*([A-Za-z0-9/+=]{40})", "AWS Secret Key"),
    # Google
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
    # GitHub
    (r"(?i)github[_\-\s]?(?:api[_\-\s]?)?(?:token|key|secret)[\s:='\"][\s]*([A-Za-z0-9_\-]{35,40})", "GitHub Token"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
    (r"ghs_[A-Za-z0-9]{36}", "GitHub App Token"),
    # Generic API key patterns
    (r"(?i)api[_\-\s]?key[\s:='\"][\s]*([A-Za-z0-9_\-]{20,})", "Generic API Key"),
    (r"(?i)(?:password|passwd|pwd)[\s:='\"][\s]*([A-Za-z0-9@#$%^&*!_\-]{8,})", "Password"),
    (r"(?i)(?:secret|token)[\s:='\"][\s]*([A-Za-z0-9_\-\.]{20,})", "Secret/Token"),
    # Stripe
    (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Live Secret Key"),
    (r"pk_live_[0-9a-zA-Z]{24}", "Stripe Live Public Key"),
    # Twilio
    (r"AC[a-fA-F0-9]{32}", "Twilio Account SID"),
    (r"SK[a-fA-F0-9]{32}", "Twilio Auth Token"),
    # SendGrid
    (r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}", "SendGrid API Key"),
    # Firebase
    (r"[a-z0-9\-]+\.firebaseio\.com", "Firebase Database URL"),
    # Slack
    (r"xox[baprs]-[A-Za-z0-9\-]{10,48}", "Slack Token"),
    (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "Slack Webhook"),
    # Azure
    (r"(?i)AccountKey=[A-Za-z0-9+/=]{86}==", "Azure Storage Key"),
    # JWT (3-part base64url)
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "JWT Token"),
    # Mailchimp / Mailgun
    (r"[a-f0-9]{32}-us[0-9]{1,2}", "Mailchimp API Key"),
    (r"key-[a-zA-Z0-9]{32}", "Mailgun API Key"),
    # NPM
    (r"npm_[A-Za-z0-9]{36}", "NPM Access Token"),
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Private Key"),
]

# Cloud bucket patterns
_BUCKET_PATTERNS = [
    (r"[a-z0-9\-\.]+\.s3\.amazonaws\.com", "AWS S3 Bucket"),
    (r"s3://[a-z0-9\-\.]+", "AWS S3 URI"),
    (r"[a-z0-9\-\.]+\.blob\.core\.windows\.net", "Azure Blob Storage"),
    (r"[a-z0-9\-\.]+\.storage\.googleapis\.com", "GCS Bucket"),
    (r"storage\.cloud\.google\.com/[a-z0-9\-\.]+", "GCS Bucket (alt)"),
    (r"[a-z0-9\-]+\.digitaloceanspaces\.com", "DigitalOcean Spaces"),
]


def _probe_path(base_url: str, path: str) -> dict | None:
    """Thử request một path và trả về kết quả nếu accessible."""
    url = f"{base_url.rstrip('/')}/{path}"
    try:
        with _rate_limiter:
            resp = _session.get(url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=False, verify=certifi.where())
        # Only flag if actually returns content (not redirect to login)
        if resp.status_code in (200, 206):
            content_len = len(resp.content)
            content_preview = resp.text[:200].strip() if resp.text else ""

            # Determine severity
            severity = get_finding_severity(path, has_secrets=False)

            return {
                "path": path,
                "url": url,
                "status": resp.status_code,
                "size": content_len,
                "preview": content_preview,
                "severity": severity,
            }
        elif resp.status_code == 403:
            # 403 means it exists but access is denied (still useful intel)
            severity = get_finding_severity(path, has_secrets=False)
            return {
                "path": path,
                "url": url,
                "status": 403,
                "size": 0,
                "preview": "(access denied — file exists)",
                "severity": severity,
            }
    except requests.exceptions.SSLError:
        pass
    except Exception:
        pass
    return None


def _scan_page_for_secrets(url: str) -> list:
    """Tải page source và tìm pattern API key / credential bị lộ."""
    findings = []
    try:
        with _rate_limiter:
            resp = _session.get(url, headers=HEADERS, timeout=12, verify=certifi.where())
        if resp.status_code != 200:
            return findings
        source = resp.text

        for pattern, label in _API_KEY_PATTERNS:
            matches = re.findall(pattern, source)
            for match in matches[:3]:  # limit to 3 per pattern
                value = match if isinstance(match, str) else str(match)
                # Basic dedup and noise filtering
                if len(value) >= 8 and value not in ("undefined", "null", "false", "true"):
                    findings.append({
                        "type": label,
                        "value": value[:60] + ("..." if len(value) > 60 else ""),
                        "source": url,
                    })

        for pattern, label in _BUCKET_PATTERNS:
            matches = re.findall(pattern, source)
            for match in matches[:5]:
                findings.append({
                    "type": label,
                    "value": match,
                    "source": url,
                })

    except Exception:
        pass
    return findings


def _extract_js_urls(base_url: str, page_source: str) -> list:
    """Extract unique JS bundle URLs from HTML source (limit 8)."""
    from urllib.parse import urljoin
    seen = set()
    scripts = []
    for match in re.finditer(
        r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']',
        page_source,
        re.IGNORECASE,
    ):
        src = match.group(1)
        if src.startswith(("http://", "https://")):
            url = src
        elif src.startswith("//"):
            url = "https:" + src
        else:
            url = urljoin(base_url, src)
        if url not in seen:
            seen.add(url)
            scripts.append(url)
        if len(scripts) >= 8:
            break
    return scripts


def secrets_scan(target: str) -> dict:
    """
    Quét đầy đủ website để tìm file nhạy cảm bị lộ và credential leak.

    Args:
        target: Domain hoặc URL (e.g. example.com hoặc https://example.com)

    Returns dict với:
      - exposed_git, exposed_env, exposed_backups, exposed_sensitive,
        security_txt, robots_txt, secrets_in_source, summary
    """
    target = target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        base_url = f"https://{target}"
        # Fallback to http if https fails
    else:
        base_url = target

    result = {
        "target": target,
        "base_url": base_url,
        "exposed_git": [],
        "exposed_env": [],
        "exposed_backups": [],
        "exposed_sensitive": [],
        "security_txt": None,
        "robots_txt": None,
        "secrets_in_source": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "total_findings": 0,
        },
        "error": None,
    }

    # ── Test HTTP connectivity ──────────────────────────────────────────────
    reachable = False
    for scheme in ("https", "http"):
        try:
            test_url = f"{scheme}://{target.replace('https://', '').replace('http://', '')}"
            r = _session.head(test_url, headers=HEADERS, timeout=8,
                              allow_redirects=True, verify=certifi.where())
            if r.status_code < 500:
                base_url = test_url
                result["base_url"] = base_url
                reachable = True
                break
        except Exception:
            pass

    if not reachable:
        result["error"] = f"Không thể kết nối tới {target}"
        return result

    console.print(f"  [dim]Scanning {base_url} for exposed files...[/dim]")

    # ── .git directory ──────────────────────────────────────────────────────
    for path in _GIT_PATHS:
        hit = _probe_path(base_url, path)
        if hit:
            # Verify .git/HEAD looks like a real git repo
            if path == ".git/HEAD" and "ref:" not in hit.get("preview", ""):
                continue
            result["exposed_git"].append(hit)

    # ── .env files ──────────────────────────────────────────────────────────
    for path in _ENV_PATHS:
        hit = _probe_path(base_url, path)
        if hit and hit["status"] == 200:
            result["exposed_env"].append(hit)

    # ── Backup files ────────────────────────────────────────────────────────
    for path in _BACKUP_PATHS:
        hit = _probe_path(base_url, path)
        if hit:
            result["exposed_backups"].append(hit)

    # ── Sensitive paths ──────────────────────────────────────────────────────
    for path in _SENSITIVE_PATHS:
        hit = _probe_path(base_url, path)
        if hit and hit["status"] == 200:
            result["exposed_sensitive"].append(hit)

    # ── security.txt ────────────────────────────────────────────────────────
    for path in _SECURITY_TXT_PATHS:
        hit = _probe_path(base_url, path)
        if hit and hit["status"] == 200:
            # Parse key fields
            parsed = {}
            for line in hit["preview"].splitlines():
                line = line.strip()
                if line.startswith("Contact:"):
                    parsed["contact"] = line.split(":", 1)[1].strip()
                elif line.startswith("Expires:"):
                    parsed["expires"] = line.split(":", 1)[1].strip()
                elif line.startswith("Encryption:"):
                    parsed["encryption"] = line.split(":", 1)[1].strip()
                elif line.startswith("Acknowledgments:"):
                    parsed["acknowledgments"] = line.split(":", 1)[1].strip()
            result["security_txt"] = {**hit, "parsed": parsed}
            break

    # ── robots.txt ──────────────────────────────────────────────────────────
    hit = _probe_path(base_url, "robots.txt")
    if hit and hit["status"] == 200:
        disallowed = []
        for line in hit["preview"].splitlines():
            if line.lower().startswith("disallow:"):
                path_val = line.split(":", 1)[1].strip()
                if path_val and path_val != "/":
                    disallowed.append(path_val)
        result["robots_txt"] = {**hit, "disallowed_paths": disallowed}

    # ── Scan home page source for secrets ────────────────────────────────────
    result["secrets_in_source"] = _scan_page_for_secrets(base_url)

    # ── Scan linked JS bundles for secrets ───────────────────────────────────
    try:
        home_resp = _session.get(base_url, headers=HEADERS, timeout=12, verify=certifi.where())
        if home_resp.status_code == 200:
            js_urls = _extract_js_urls(base_url, home_resp.text)
            if js_urls:
                console.print(f"  [dim]Scanning {len(js_urls)} JS bundle(s)...[/dim]")
            for js_url in js_urls:
                js_secrets = _scan_page_for_secrets(js_url)
                result["secrets_in_source"].extend(js_secrets)
    except Exception:
        pass

    # ── Summary ──────────────────────────────────────────────────────────────
    crit = len(result["exposed_git"]) + len(result["exposed_env"])
    high = len([b for b in result["exposed_backups"] if b["status"] == 200])
    medium = len(result["exposed_sensitive"]) + len(result["secrets_in_source"])
    result["summary"] = {
        "critical": crit,
        "high": high,
        "medium": medium,
        "total_findings": crit + high + medium,
    }

    return result


def print_secrets_results(data: dict):
    """Hiển thị kết quả quét file nhạy cảm."""
    target = data.get("target", "")
    console.print(f"\n[bold cyan]═══ SECRETS & EXPOSED FILES: {target} ═══[/bold cyan]")

    if data.get("error"):
        console.print(f"  [red]✗ {data['error']}[/red]")
        return

    summary = data.get("summary", {})
    total = summary.get("total_findings", 0)
    if total == 0:
        console.print("  [green]✓ Không phát hiện file nhạy cảm bị lộ[/green]")
    else:
        crit = summary.get("critical", 0)
        high = summary.get("high", 0)
        med = summary.get("medium", 0)
        console.print(
            f"  [bold red]⚠ Phát hiện {total} vấn đề:[/bold red] "
            f"[red]CRITICAL: {crit}[/red]  "
            f"[orange3]HIGH: {high}[/orange3]  "
            f"[yellow]MEDIUM: {med}[/yellow]"
        )

    # .git exposure — CRITICAL
    git_hits = data.get("exposed_git", [])
    if git_hits:
        console.print("\n  [bold red]🔴 CRITICAL: Git Repository Exposed[/bold red]")
        console.print("  [red]Toàn bộ source code có thể bị tải về bằng git-dumper![/red]")
        for h in git_hits:
            console.print(f"    • {h['url']} [dim]({h['size']} bytes)[/dim]")
        console.print("  [dim]Tool khai thác: https://github.com/arthaud/git-dumper[/dim]")

    # .env exposure — CRITICAL
    env_hits = data.get("exposed_env", [])
    if env_hits:
        console.print("\n  [bold red]🔴 CRITICAL: Environment File Exposed[/bold red]")
        console.print("  [red]Credentials, API keys, database passwords có thể bị lộ![/red]")
        for h in env_hits:
            preview = h.get("preview", "")[:100]
            console.print(f"    • {h['url']} [dim]({h['size']} bytes)[/dim]")
            if preview:
                console.print(f"      [dim]Preview: {preview}[/dim]")

    # Backup files — HIGH
    backup_hits = data.get("exposed_backups", [])
    accessible = [b for b in backup_hits if b["status"] == 200]
    if accessible:
        console.print(f"\n  [bold orange3]🟠 HIGH: Backup Files Accessible ({len(accessible)})[/bold orange3]")
        for h in accessible:
            console.print(f"    • {h['url']} [dim]({h['size']:,} bytes)[/dim]")
    elif backup_hits:
        console.print(f"\n  [yellow]⚠ Backup paths exist but access denied ({len(backup_hits)}):[/yellow]")
        for h in backup_hits:
            console.print(f"    • {h['url']} [dim](403 — exists)[/dim]")

    # Sensitive paths — MEDIUM
    sensitive_hits = data.get("exposed_sensitive", [])
    if sensitive_hits:
        console.print(f"\n  [bold yellow]🟡 MEDIUM: Sensitive Paths Accessible ({len(sensitive_hits)})[/bold yellow]")
        tbl = Table(show_header=True, header_style="bold yellow", box=box.SIMPLE)
        tbl.add_column("Path", style="cyan")
        tbl.add_column("URL", style="dim")
        tbl.add_column("Size", justify="right")
        for h in sensitive_hits[:20]:
            tbl.add_row(h["path"], h["url"], f"{h['size']:,}B")
        console.print(tbl)

    # security.txt
    sec_txt = data.get("security_txt")
    if sec_txt:
        parsed = sec_txt.get("parsed", {})
        console.print(f"\n  [green]✓ security.txt tìm thấy[/green]")
        if parsed.get("contact"):
            console.print(f"    Contact: [cyan]{parsed['contact']}[/cyan]")
        if parsed.get("expires"):
            console.print(f"    Expires: {parsed['expires']}")
        if parsed.get("encryption"):
            console.print(f"    Encryption key: {parsed['encryption']}")
    else:
        console.print("\n  [dim]ℹ️  Không có security.txt (nên thêm để tiếp nhận báo cáo lỗ hổng)[/dim]")

    # robots.txt
    robots = data.get("robots_txt")
    if robots:
        disallowed = robots.get("disallowed_paths", [])
        if disallowed:
            console.print(f"\n  [cyan]ℹ️  robots.txt — {len(disallowed)} đường dẫn ẩn:[/cyan]")
            for p in disallowed[:15]:
                console.print(f"    [dim]Disallow: {p}[/dim]")

    # Secrets in source
    secrets = data.get("secrets_in_source", [])
    if secrets:
        console.print(f"\n  [bold red]🔴 Credentials/Keys phát hiện trong source ({len(secrets)}):[/bold red]")
        tbl = Table(show_header=True, header_style="bold red", box=box.SIMPLE)
        tbl.add_column("Loại", style="red", width=28)
        tbl.add_column("Giá trị (đã che một phần)", style="dim")
        for s in secrets[:20]:
            val = s.get("value", "")
            # Partially mask sensitive values
            if len(val) > 12:
                masked = val[:6] + "***" + val[-4:]
            else:
                masked = val[:4] + "***"
            tbl.add_row(s["type"], masked)
        console.print(tbl)


# ─── Git Repo Secret Scanners ─────────────────────────────────────────────────

import shutil as _shutil
import subprocess as _subprocess
import json as _json


def scan_git_repo_trufflehog(repo_url: str, timeout: int = 120) -> dict:
    """
    Use TruffleHog to scan a git repo for leaked secrets.
    repo_url: GitHub/GitLab HTTPS URL like https://github.com/org/repo
    """
    result = {"available": False, "findings": [], "error": None, "note": None, "tool": "trufflehog"}
    if not _shutil.which("trufflehog"):
        result["note"] = "trufflehog not installed. Run: pip install trufflehog"
        return result
    result["available"] = True
    try:
        proc = _subprocess.run(
            ["trufflehog", "git", repo_url, "--json", "--no-update"],
            capture_output=True, text=True, timeout=timeout,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    finding = _json.loads(line)
                    result["findings"].append({
                        "detector":    finding.get("DetectorName", "Unknown"),
                        "verified":    finding.get("Verified", False),
                        "raw":         finding.get("Raw", "")[:100],
                        "source_file": finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("file", ""),
                        "commit":      finding.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("commit", ""),
                    })
                except _json.JSONDecodeError:
                    pass
    except _subprocess.TimeoutExpired:
        result["error"] = f"trufflehog timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    return result


def scan_git_repo_gitleaks(repo_path: str, timeout: int = 60) -> dict:
    """
    Use Gitleaks to scan a local git repo for secrets.
    repo_path: local filesystem path to a git repository.
    """
    result = {"available": False, "findings": [], "error": None, "note": None, "tool": "gitleaks"}
    if not _shutil.which("gitleaks"):
        result["note"] = "gitleaks not installed. See: https://github.com/gitleaks/gitleaks"
        return result
    result["available"] = True
    try:
        proc = _subprocess.run(
            ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-banner"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.stdout.strip():
            try:
                findings_raw = _json.loads(proc.stdout)
                for f in (findings_raw if isinstance(findings_raw, list) else []):
                    result["findings"].append({
                        "rule":           f.get("RuleID", "Unknown"),
                        "file":           f.get("File", ""),
                        "line":           f.get("StartLine", 0),
                        "secret_snippet": (f.get("Secret", "") or "")[:50] + "...",
                        "commit":         f.get("Commit", ""),
                        "author":         f.get("Author", ""),
                    })
            except _json.JSONDecodeError:
                pass
    except _subprocess.TimeoutExpired:
        result["error"] = f"gitleaks timed out after {timeout}s"
    except Exception as e:
        result["error"] = str(e)
    return result


def print_git_secrets_results(data: dict):
    """Print TruffleHog or Gitleaks results with rich formatting."""
    from rich.panel import Panel as _Panel
    tool = data.get("tool", "unknown")
    if not data.get("available"):
        console.print(f"[yellow]⚠ {tool}: {data.get('note', 'not available')}[/yellow]")
        return
    if data.get("error"):
        console.print(f"[red]✗ {tool} error: {data['error']}[/red]")
        return
    findings = data.get("findings", [])
    if not findings:
        console.print(f"[green]✓ {tool}: No secrets found[/green]")
        return

    console.print(_Panel(f"[bold red]⚠ {tool}: {len(findings)} secret(s) found![/bold red]", border_style="red"))
    table = Table(box=box.SIMPLE_HEAVY, show_lines=True)
    if tool == "trufflehog":
        table.add_column("Detector", style="red bold")
        table.add_column("Verified", style="bold")
        table.add_column("File", style="cyan")
        table.add_column("Snippet", style="dim")
        for f in findings[:20]:
            v = "[green]YES[/green]" if f.get("verified") else "[dim]no[/dim]"
            table.add_row(f.get("detector", "?"), v, f.get("source_file", "?"), f.get("raw", "")[:60])
    else:
        table.add_column("Rule", style="red bold")
        table.add_column("File", style="cyan")
        table.add_column("Line")
        table.add_column("Author", style="dim")
        for f in findings[:20]:
            table.add_row(f.get("rule", "?"), f.get("file", "?"), str(f.get("line", "")), f.get("author", "?"))
    console.print(table)

