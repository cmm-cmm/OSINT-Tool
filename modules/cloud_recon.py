"""
Cloud Storage Bucket Recon Module
==================================
Tìm kiếm public cloud storage buckets liên quan đến target:
  - AWS S3 Buckets
  - Google Cloud Storage (GCS)
  - Azure Blob Storage
  - DigitalOcean Spaces

Dựa trên naming patterns từ domain name.
Không cần API key.
"""
import re
import requests
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()
HEADERS = {"User-Agent": "OSINT-Tool/1.0 (Educational/Research Purpose)"}
TIMEOUT = 8


def _generate_bucket_names(domain_or_name: str) -> list[str]:
    """Tạo danh sách tên bucket tiềm năng từ domain hoặc tên công ty."""
    # Clean up domain: remove TLD and www
    name = domain_or_name.lower().strip()
    # Remove scheme
    name = re.sub(r"^https?://", "", name)
    # Remove common TLDs and www
    name = re.sub(r"\.(com|net|org|io|vn|co|app|dev|xyz|info|biz)(\.[a-z]{2})?$", "", name)
    name = re.sub(r"^www\.", "", name)
    # Base name
    base = name.replace(".", "-").replace("_", "-")

    candidates = set()
    # Core variations
    candidates.add(base)
    candidates.add(base.replace("-", ""))
    candidates.add(base.replace("-", "_"))

    # Common suffixes
    for suffix in [
        "backup", "backups", "bak", "assets", "static", "media", "files",
        "uploads", "images", "img", "data", "logs", "archive", "dev",
        "staging", "test", "prod", "production", "cdn", "storage",
        "public", "private", "internal", "admin", "api", "resources",
        "bucket", "store", "s3", "cloud", "web", "app",
    ]:
        candidates.add(f"{base}-{suffix}")
        candidates.add(f"{base}.{suffix}")
        candidates.add(f"{suffix}-{base}")
        candidates.add(f"{suffix}.{base}")

    return sorted(candidates)


def _check_s3_bucket(bucket_name: str) -> dict:
    """Kiểm tra AWS S3 bucket có public không."""
    result = {
        "provider": "AWS S3",
        "bucket": bucket_name,
        "url": f"https://{bucket_name}.s3.amazonaws.com",
        "status": "unknown",
        "accessible": False,
        "listing_enabled": False,
        "object_count": None,
        "details": None,
    }
    try:
        resp = requests.get(
            result["url"], headers=HEADERS, timeout=TIMEOUT, verify=True
        )
        if resp.status_code == 200:
            result["status"] = "public"
            result["accessible"] = True
            # Check if directory listing is enabled
            if "<ListBucketResult" in resp.text:
                result["listing_enabled"] = True
                # Count objects
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                result["object_count"] = len(keys)
                result["details"] = f"Directory listing ON — {len(keys)} objects visible"
            else:
                result["details"] = "Accessible but no directory listing"
        elif resp.status_code == 403:
            result["status"] = "exists_private"
            result["details"] = "Bucket exists but access denied"
        elif resp.status_code == 404:
            result["status"] = "not_found"
        else:
            result["status"] = f"http_{resp.status_code}"
    except requests.exceptions.ConnectionError:
        result["status"] = "not_found"
    except Exception:
        pass
    return result


def _check_gcs_bucket(bucket_name: str) -> dict:
    """Kiểm tra Google Cloud Storage bucket."""
    result = {
        "provider": "Google Cloud Storage",
        "bucket": bucket_name,
        "url": f"https://storage.googleapis.com/{bucket_name}",
        "status": "unknown",
        "accessible": False,
        "listing_enabled": False,
        "object_count": None,
        "details": None,
    }
    try:
        resp = requests.get(
            result["url"], headers=HEADERS, timeout=TIMEOUT, verify=True
        )
        if resp.status_code == 200:
            result["status"] = "public"
            result["accessible"] = True
            if "<ListBucketResult" in resp.text or "<Contents>" in resp.text:
                result["listing_enabled"] = True
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                result["object_count"] = len(keys)
                result["details"] = f"Directory listing ON — {len(keys)} objects"
            else:
                result["details"] = "Accessible"
        elif resp.status_code == 403:
            result["status"] = "exists_private"
            result["details"] = "Bucket exists (access denied)"
        elif resp.status_code == 404:
            result["status"] = "not_found"
        else:
            result["status"] = f"http_{resp.status_code}"
    except requests.exceptions.ConnectionError:
        result["status"] = "not_found"
    except Exception:
        pass
    return result


def _check_azure_blob(account_name: str, container_name: str = "$web") -> dict:
    """Kiểm tra Azure Blob Storage."""
    # Azure storage accounts have strict naming (3-24 chars, lowercase alphanumeric only)
    az_name = re.sub(r"[^a-z0-9]", "", account_name.lower())[:24]
    if len(az_name) < 3:
        return {"provider": "Azure Blob", "status": "invalid_name", "accessible": False}

    result = {
        "provider": "Azure Blob Storage",
        "bucket": az_name,
        "url": f"https://{az_name}.blob.core.windows.net/{container_name}?restype=container&comp=list",
        "status": "unknown",
        "accessible": False,
        "listing_enabled": False,
        "object_count": None,
        "details": None,
    }
    try:
        resp = requests.get(
            result["url"], headers=HEADERS, timeout=TIMEOUT, verify=True
        )
        if resp.status_code == 200:
            result["status"] = "public"
            result["accessible"] = True
            result["listing_enabled"] = True
            blobs = re.findall(r"<Name>([^<]+)</Name>", resp.text)
            result["object_count"] = len(blobs)
            result["details"] = f"Public container — {len(blobs)} blobs"
        elif resp.status_code == 403:
            result["status"] = "exists_private"
            result["details"] = "Container exists (access denied)"
        elif resp.status_code == 404:
            result["status"] = "not_found"
        else:
            result["status"] = f"http_{resp.status_code}"
    except requests.exceptions.ConnectionError:
        result["status"] = "not_found"
    except Exception:
        pass
    return result


def _check_do_space(bucket_name: str, region: str = "sgp1") -> dict:
    """Kiểm tra DigitalOcean Spaces (Singapore region default cho VN)."""
    result = {
        "provider": f"DigitalOcean Spaces ({region})",
        "bucket": bucket_name,
        "url": f"https://{bucket_name}.{region}.digitaloceanspaces.com",
        "status": "unknown",
        "accessible": False,
        "listing_enabled": False,
        "object_count": None,
        "details": None,
    }
    try:
        resp = requests.get(
            result["url"], headers=HEADERS, timeout=TIMEOUT, verify=True
        )
        if resp.status_code == 200:
            result["status"] = "public"
            result["accessible"] = True
            if "<ListBucketResult" in resp.text:
                result["listing_enabled"] = True
                keys = re.findall(r"<Key>([^<]+)</Key>", resp.text)
                result["object_count"] = len(keys)
                result["details"] = f"Public space — {len(keys)} objects"
        elif resp.status_code == 403:
            result["status"] = "exists_private"
            result["details"] = "Space exists (private)"
        elif resp.status_code == 404:
            result["status"] = "not_found"
        else:
            result["status"] = f"http_{resp.status_code}"
    except requests.exceptions.ConnectionError:
        result["status"] = "not_found"
    except Exception:
        pass
    return result


def cloud_recon(target: str, max_buckets: int = 30) -> dict:
    """
    Liệt kê và kiểm tra public cloud storage buckets liên quan đến target.

    Args:
        target:      Domain hoặc tên công ty (e.g. example.com, shopee)
        max_buckets: Số lượng bucket names tối đa để kiểm tra (default 30)

    Returns dict với found_buckets, checked_count, summary
    """
    result = {
        "target": target,
        "found_buckets": [],      # public/accessible buckets
        "private_buckets": [],    # exist but private
        "checked_count": 0,
        "bucket_names_tested": [],
        "summary": {
            "public": 0,
            "private": 0,
            "listing_enabled": 0,
        },
    }

    candidates = _generate_bucket_names(target)[:max_buckets]
    result["bucket_names_tested"] = candidates
    result["checked_count"] = len(candidates)

    console.print(f"  [dim]Testing {len(candidates)} bucket name variations across AWS/GCS/Azure/DO...[/dim]")

    for bucket_name in candidates:
        # AWS S3
        s3 = _check_s3_bucket(bucket_name)
        if s3["status"] == "public":
            result["found_buckets"].append(s3)
        elif s3["status"] == "exists_private":
            result["private_buckets"].append(s3)

        # GCS
        gcs = _check_gcs_bucket(bucket_name)
        if gcs["status"] == "public":
            result["found_buckets"].append(gcs)
        elif gcs["status"] == "exists_private":
            result["private_buckets"].append(gcs)

        # Azure (using bucket_name as account name)
        azure = _check_azure_blob(bucket_name)
        if azure.get("status") == "public":
            result["found_buckets"].append(azure)
        elif azure.get("status") == "exists_private":
            result["private_buckets"].append(azure)

        # DigitalOcean — only check exact match and close variations (to avoid too many requests)
        if bucket_name == candidates[0]:
            do = _check_do_space(bucket_name)
            if do["status"] == "public":
                result["found_buckets"].append(do)
            elif do["status"] == "exists_private":
                result["private_buckets"].append(do)

    result["summary"]["public"] = len(result["found_buckets"])
    result["summary"]["private"] = len(result["private_buckets"])
    result["summary"]["listing_enabled"] = sum(
        1 for b in result["found_buckets"] if b.get("listing_enabled")
    )

    return result


def print_cloud_recon(data: dict):
    """Hiển thị kết quả cloud bucket recon."""
    target = data.get("target", "")
    console.print(f"\n[bold cyan]═══ CLOUD STORAGE RECON: {target} ═══[/bold cyan]")

    checked = data.get("checked_count", 0)
    summary = data.get("summary", {})
    public = summary.get("public", 0)
    private = summary.get("private", 0)
    listing = summary.get("listing_enabled", 0)

    console.print(
        f"  Đã kiểm tra [cyan]{checked}[/cyan] bucket name variations | "
        f"[green]Public: {public}[/green] | [yellow]Private: {private}[/yellow]"
    )

    found = data.get("found_buckets", [])
    if found:
        severity = "CRITICAL" if listing > 0 else "HIGH"
        color = "bold red" if listing > 0 else "bold orange3"
        console.print(f"\n  [{color}]🚨 {severity}: {len(found)} Public Bucket(s) Found![/{color}]")
        if listing > 0:
            console.print(f"  [red]{listing} bucket(s) có Directory Listing — dữ liệu bị lộ công khai![/red]")

        tbl = Table(show_header=True, header_style="bold red", box=box.SIMPLE)
        tbl.add_column("Provider", style="bold", width=26)
        tbl.add_column("Bucket Name", style="cyan")
        tbl.add_column("URL", style="dim", max_width=55)
        tbl.add_column("Listing", width=8)
        tbl.add_column("Objects", justify="right", width=8)
        for b in found:
            listing_str = "[red]✓ ON[/red]" if b.get("listing_enabled") else "[green]✗ OFF[/green]"
            obj_str = str(b.get("object_count") or "?")
            tbl.add_row(
                b.get("provider", ""), b.get("bucket", ""),
                b.get("url", ""), listing_str, obj_str
            )
        console.print(tbl)
    else:
        console.print("  [green]✓ Không tìm thấy public cloud bucket[/green]")

    private_list = data.get("private_buckets", [])
    if private_list:
        console.print(f"\n  [yellow]ℹ️  {len(private_list)} bucket tồn tại nhưng đã khóa (private):[/yellow]")
        for b in private_list[:5]:
            console.print(f"    • [{b['provider']}] {b['url']}")
        if len(private_list) > 5:
            console.print(f"    [dim]... và {len(private_list) - 5} khác[/dim]")
