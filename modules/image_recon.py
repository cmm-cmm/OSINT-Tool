"""
Image OSINT Module
==================
Extract EXIF metadata, GPS coordinates, and generate reverse image search links.

Dependencies (graceful fallback if not installed):
  - Pillow (PIL)  : pip install Pillow
  - exifread      : pip install exifread
"""
from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box as _box

console = Console()

# ─── Optional imports ────────────────────────────────────────────────────────

try:
    from PIL import Image as _PILImage
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    import exifread as _exifread
    _EXIFREAD_AVAILABLE = True
except ImportError:
    _EXIFREAD_AVAILABLE = False


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _dms_to_decimal(dms_values, ref: str) -> float | None:
    """Convert DMS (degrees/minutes/seconds) list from exifread to decimal degrees."""
    try:
        def _ratio_to_float(r) -> float:
            if hasattr(r, "num") and hasattr(r, "den"):
                return r.num / r.den if r.den != 0 else 0.0
            return float(r)

        degrees = _ratio_to_float(dms_values[0])
        minutes = _ratio_to_float(dms_values[1])
        seconds = _ratio_to_float(dms_values[2])
        decimal = degrees + minutes / 60 + seconds / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None


def _parse_gps(exif_data: dict) -> dict | None:
    """Parse GPS EXIF tags into decimal lat/lon/altitude."""
    try:
        lat_tag  = exif_data.get("GPS GPSLatitude")
        lat_ref  = exif_data.get("GPS GPSLatitudeRef")
        lon_tag  = exif_data.get("GPS GPSLongitude")
        lon_ref  = exif_data.get("GPS GPSLongitudeRef")

        if not (lat_tag and lon_tag):
            return None

        lat_ref_val = str(lat_ref.values).strip() if lat_ref else "N"
        lon_ref_val = str(lon_ref.values).strip() if lon_ref else "E"

        lat = _dms_to_decimal(lat_tag.values, lat_ref_val)
        lon = _dms_to_decimal(lon_tag.values, lon_ref_val)

        if lat is None or lon is None:
            return None

        gps = {"latitude": lat, "longitude": lon}

        # Altitude
        alt_tag = exif_data.get("GPS GPSAltitude")
        alt_ref = exif_data.get("GPS GPSAltitudeRef")
        if alt_tag:
            try:
                alt_val = alt_tag.values[0]
                alt_float = alt_val.num / alt_val.den if hasattr(alt_val, "den") and alt_val.den != 0 else float(alt_val)
                if alt_ref and str(alt_ref.values) == "\x01":
                    alt_float = -alt_float
                gps["altitude_m"] = round(alt_float, 2)
            except Exception:
                pass

        gps["google_maps"] = f"https://maps.google.com/maps?q={lat},{lon}"
        return gps
    except Exception:
        return None


# ─── Public API ───────────────────────────────────────────────────────────────

def extract_exif(image_path: str) -> dict:
    """
    Extract EXIF tags from a local image file using Pillow + exifread.

    Returns dict with keys:
      error, basic, exif, gps, camera, datetime_taken
    """
    result: dict = {
        "error": None,
        "basic": {},
        "exif": {},
        "gps": None,
        "camera": {},
        "datetime_taken": None,
    }

    path = Path(image_path)
    if not path.exists():
        result["error"] = f"File not found: {image_path}"
        return result

    # ── Basic info via Pillow ────────────────────────────────────────────────
    if _PIL_AVAILABLE:
        try:
            with _PILImage.open(path) as img:
                result["basic"] = {
                    "filename": path.name,
                    "format": img.format,
                    "mode": img.mode,
                    "width": img.width,
                    "height": img.height,
                    "size_bytes": path.stat().st_size,
                }
        except Exception as exc:
            result["error"] = f"Pillow error: {exc}"
    else:
        result["basic"] = {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "note": "Pillow not installed — install with: pip install Pillow",
        }

    # ── Full EXIF via exifread ───────────────────────────────────────────────
    if _EXIFREAD_AVAILABLE:
        try:
            with open(path, "rb") as f:
                tags = _exifread.process_file(f, details=False, stop_tag="GPS GPSAltitudeRef")

            # Re-open for full tags
            with open(path, "rb") as f:
                tags = _exifread.process_file(f, details=False)

            raw_exif: dict = {}
            for key, val in tags.items():
                try:
                    raw_exif[key] = str(val)
                except Exception:
                    pass
            result["exif"] = raw_exif

            # GPS
            gps = _parse_gps(tags)
            if gps:
                result["gps"] = gps

            # Camera info
            camera: dict = {}
            for field, tag in [
                ("make",     "Image Make"),
                ("model",    "Image Model"),
                ("software", "Image Software"),
                ("lens",     "EXIF LensModel"),
            ]:
                val = tags.get(tag)
                if val:
                    camera[field] = str(val).strip()
            result["camera"] = camera

            # Datetime
            for dt_tag in ("EXIF DateTimeOriginal", "EXIF DateTime", "Image DateTime"):
                val = tags.get(dt_tag)
                if val:
                    result["datetime_taken"] = str(val)
                    break

        except Exception as exc:
            if not result["error"]:
                result["error"] = f"exifread error: {exc}"
    else:
        if not result.get("exif"):
            result["exif"] = {"note": "exifread not installed — install with: pip install exifread"}

    return result


def get_reverse_image_links(
    image_path: str | None = None,
    image_url: str | None = None,
) -> dict:
    """
    Return reverse image search URLs for Google Images, TinEye, Yandex, Bing.

    Provide either a local ``image_path`` (will hint to use file upload)
    or an ``image_url`` (publicly accessible URL).
    """
    links: dict = {}

    if image_url:
        enc = quote(image_url, safe="")
        links["Google Images"] = f"https://www.google.com/searchbyimage?image_url={enc}"
        links["TinEye"]        = f"https://www.tineye.com/search?url={enc}"
        links["Yandex"]        = f"https://yandex.com/images/search?url={enc}&rpt=imageview"
        links["Bing Visual"]   = f"https://www.bing.com/images/searchbyimage?imgurl={enc}"
    elif image_path:
        abs_path = os.path.abspath(image_path)
        links["Google Images"] = "https://images.google.com/ (upload file manually)"
        links["TinEye"]        = "https://www.tineye.com/ (upload file manually)"
        links["Yandex"]        = "https://yandex.com/images/ (upload file manually)"
        links["Bing Visual"]   = "https://www.bing.com/visualsearch (upload file manually)"
        links["_local_path"]   = abs_path
    else:
        links["note"] = "Provide image_path or image_url"

    return links


def analyze_image_metadata(image_path: str) -> dict:
    """
    Full image OSINT: EXIF extraction + reverse search links + privacy risk assessment.
    """
    exif_data = extract_exif(image_path)
    reverse_links = get_reverse_image_links(image_path=image_path)

    # Privacy risk
    has_gps    = exif_data.get("gps") is not None
    has_camera = bool(exif_data.get("camera"))

    if has_gps:
        privacy_risk = "high"
    elif has_camera or exif_data.get("datetime_taken"):
        privacy_risk = "medium"
    else:
        privacy_risk = "low"

    return {
        "image_path": image_path,
        **exif_data,
        "reverse_image_links": reverse_links,
        "privacy_risk": privacy_risk,
    }


def print_image_results(data: dict):
    """Rich output for image EXIF analysis results."""
    path = data.get("image_path", "")
    privacy_risk = data.get("privacy_risk", "low")
    risk_colors = {"high": "bold red", "medium": "bold yellow", "low": "bold green"}
    risk_color = risk_colors.get(privacy_risk, "white")

    console.print(
        Panel(
            f"[bold cyan]Image EXIF & GPS Analysis[/bold cyan]\n"
            f"[dim]{path}[/dim]\n"
            f"Privacy Risk: [{risk_color}]{privacy_risk.upper()}[/{risk_color}]",
            border_style="bright_blue",
            title="[bold magenta]Image Recon[/bold magenta]",
        )
    )

    if data.get("error"):
        console.print(f"[red]✗ {data['error']}[/red]")

    # Basic info
    basic = data.get("basic", {})
    if basic and "note" not in basic:
        tbl = Table(box=_box.SIMPLE, show_header=False, padding=(0, 1))
        tbl.add_column("Key", style="cyan", width=16)
        tbl.add_column("Value")
        for k, v in basic.items():
            if k == "size_bytes":
                tbl.add_row(k, f"{v:,} bytes ({v / 1024:.1f} KB)")
            else:
                tbl.add_row(k, str(v))
        console.print(tbl)

    # GPS
    gps = data.get("gps")
    if gps:
        console.print(
            Panel(
                f"[bold]Latitude:[/bold]  {gps['latitude']}\n"
                f"[bold]Longitude:[/bold] {gps['longitude']}\n"
                + (f"[bold]Altitude:[/bold]  {gps['altitude_m']} m\n" if "altitude_m" in gps else "")
                + f"[underline bright_blue]{gps['google_maps']}[/underline bright_blue]",
                title="[bold red]⚠ GPS Location Found[/bold red]",
                border_style="red",
            )
        )
    else:
        console.print("[dim]  No GPS data found in EXIF[/dim]")

    # Camera info
    camera = data.get("camera", {})
    if camera:
        console.print("\n[bold]Camera Info:[/bold]")
        for k, v in camera.items():
            console.print(f"  {k:10}: [cyan]{v}[/cyan]")

    # Datetime
    dt = data.get("datetime_taken")
    if dt:
        console.print(f"  Taken     : [cyan]{dt}[/cyan]")

    # EXIF tag count
    exif = data.get("exif", {})
    tag_count = len([k for k in exif if "note" not in k.lower()])
    if tag_count:
        console.print(f"\n  [dim]Total EXIF tags: {tag_count}[/dim]")

    # Reverse image search
    reverse = data.get("reverse_image_links", {})
    if reverse:
        console.print("\n[bold]Reverse Image Search:[/bold]")
        for engine, url in reverse.items():
            if engine.startswith("_"):
                continue
            console.print(f"  {engine:15}: [link]{url}[/link]")
