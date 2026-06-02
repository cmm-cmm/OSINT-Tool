"""
STIX 2.1 and MISP Export Module
Converts OSINT scan results to STIX 2.1 Bundle and MISP Event formats.
No external stix2 library required — dicts are built manually.
"""
import json
import logging
import os
import uuid
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

logger = logging.getLogger("osint.export")
console = Console()


def _now_iso() -> str:
    """Return current UTC time in STIX/MISP ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_iso() -> str:
    """Return today's date as YYYY-MM-DD."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _stix_id(obj_type: str) -> str:
    """Generate a STIX id string of the form <type>--<uuid4>."""
    return f"{obj_type}--{uuid.uuid4()}"


# ---------------------------------------------------------------------------
# STIX 2.1 object builders
# ---------------------------------------------------------------------------

def _make_identity(created: str, modified: str) -> dict:
    return {
        "type": "identity",
        "id": _stix_id("identity"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "name": "OSINT-Tool",
        "description": "Automated OSINT scanning tool",
        "identity_class": "system",
    }


def _make_threat_actor(name: str, created: str, modified: str) -> dict:
    return {
        "type": "threat-actor",
        "id": _stix_id("threat-actor"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "name": name,
        "threat_actor_types": ["unknown"],
    }


def _make_domain(value: str, created: str, modified: str) -> dict:
    return {
        "type": "domain-name",
        "id": _stix_id("domain-name"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "value": value,
    }


def _make_ipv4(value: str, created: str, modified: str) -> dict:
    return {
        "type": "ipv4-addr",
        "id": _stix_id("ipv4-addr"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "value": value,
    }


def _make_email(value: str, created: str, modified: str) -> dict:
    return {
        "type": "email-addr",
        "id": _stix_id("email-addr"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "value": value,
    }


def _make_url(value: str, created: str, modified: str) -> dict:
    return {
        "type": "url",
        "id": _stix_id("url"),
        "spec_version": "2.1",
        "created": created,
        "modified": modified,
        "value": value,
    }


# ---------------------------------------------------------------------------
# Data-extraction helpers
# ---------------------------------------------------------------------------

def _extract_ips(all_data: dict) -> list[str]:
    """Extract IP addresses from various known scan result keys."""
    ips: list[str] = []
    for key in ("ip", "ips", "ip_addresses", "resolved_ips", "a_records"):
        val = all_data.get(key)
        if isinstance(val, str) and val:
            ips.append(val)
        elif isinstance(val, list):
            ips.extend(v for v in val if isinstance(v, str) and v)
        elif isinstance(val, dict):
            # Module result dict, e.g. all_data["ip"] = {"ip": "1.2.3.4", ...}
            for k in ("ip", "ips", "ip_address", "addr"):
                inner = val.get(k)
                if isinstance(inner, str) and inner:
                    ips.append(inner)
                elif isinstance(inner, list):
                    ips.extend(x for x in inner if isinstance(x, str) and x)
    # dns / whois sub-dicts
    for sub_key in ("dns", "whois", "passive_dns"):
        sub = all_data.get(sub_key)
        if isinstance(sub, dict):
            for k in ("a", "A", "ip", "ips"):
                v = sub.get(k)
                if isinstance(v, str) and v:
                    ips.append(v)
                elif isinstance(v, list):
                    ips.extend(x for x in v if isinstance(x, str) and x)
    return list(dict.fromkeys(ips))  # deduplicate, preserve order


def _extract_emails(all_data: dict) -> list[str]:
    """Extract email addresses from scan results."""
    emails: list[str] = []
    for key in ("emails", "email", "email_addresses", "contacts"):
        val = all_data.get(key)
        if isinstance(val, str) and "@" in val:
            emails.append(val)
        elif isinstance(val, list):
            emails.extend(v for v in val if isinstance(v, str) and "@" in v)
    return list(dict.fromkeys(emails))


def _extract_urls(all_data: dict) -> list[str]:
    """Extract URLs from scan results."""
    urls: list[str] = []
    for key in ("urls", "links", "endpoints", "subdomains"):
        val = all_data.get(key)
        if isinstance(val, str) and val.startswith("http"):
            urls.append(val)
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str) and v.startswith("http"):
                    urls.append(v)
                elif isinstance(v, dict):
                    for uk in ("url", "link", "href"):
                        u = v.get(uk)
                        if isinstance(u, str) and u.startswith("http"):
                            urls.append(u)
    return list(dict.fromkeys(urls))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def to_stix_bundle(target: str, all_data: dict) -> dict:
    """Convert scan results to a STIX 2.1 Bundle dict.

    Parameters
    ----------
    target:
        The scan target (domain, IP, email, etc.).
    all_data:
        Dictionary of all collected scan results.

    Returns
    -------
    dict
        A STIX 2.1 Bundle containing identity, optional threat-actor,
        domain-name, ipv4-addr, email-addr, and url objects.
    """
    created = _now_iso()
    modified = created

    objects: list[dict] = []

    # Identity — the tool itself
    identity = _make_identity(created, modified)
    objects.append(identity)

    # Threat-actor — only if explicitly flagged in scan data
    threat_actor_name = all_data.get("threat_actor") or all_data.get("actor")
    if threat_actor_name and isinstance(threat_actor_name, str):
        objects.append(_make_threat_actor(threat_actor_name, created, modified))

    # Domain-name — target itself (if it looks like a domain) plus extras
    if target and not target.replace(".", "").isdigit():
        objects.append(_make_domain(target, created, modified))
    for domain in all_data.get("domains", []):
        if isinstance(domain, str) and domain and domain != target:
            objects.append(_make_domain(domain, created, modified))

    # IPv4 addresses
    for ip in _extract_ips(all_data):
        objects.append(_make_ipv4(ip, created, modified))

    # Email addresses
    for email in _extract_emails(all_data):
        objects.append(_make_email(email, created, modified))

    # URLs
    for url in _extract_urls(all_data):
        objects.append(_make_url(url, created, modified))

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    logger.info("Built STIX bundle with %d objects for target '%s'", len(objects), target)
    return bundle


def to_misp_event(target: str, all_data: dict) -> dict:
    """Convert scan results to a MISP event dict.

    Parameters
    ----------
    target:
        The scan target.
    all_data:
        Dictionary of all collected scan results.

    Returns
    -------
    dict
        A MISP Event dict with Attribute list.
    """
    attributes: list[dict] = []
    seen_values: set[str] = set()

    def add_attr(attr_type: str, category: str, value: str, comment: str = "") -> None:
        key = f"{attr_type}:{value}"
        if value and key not in seen_values:
            seen_values.add(key)
            attributes.append({
                "type": attr_type,
                "category": category,
                "value": value,
                "comment": comment,
            })

    # Target itself
    if target:
        if "@" in target:
            add_attr("email-dst", "Network activity", target, "Scan target (email)")
        elif target.replace(".", "").isdigit():
            add_attr("ip-dst", "Network activity", target, "Scan target (IP)")
        else:
            add_attr("domain", "Network activity", target, "Scan target (domain)")

    # IPs
    for ip in _extract_ips(all_data):
        add_attr("ip-dst", "Network activity", ip, "Resolved IP address")

    # Emails
    for email in _extract_emails(all_data):
        add_attr("email-dst", "Network activity", email, "Discovered email address")

    # URLs
    for url in _extract_urls(all_data):
        add_attr("url", "External analysis", url, "Discovered URL")

    # Subdomains as domain attributes
    for sub in all_data.get("subdomains", []):
        if isinstance(sub, str):
            add_attr("domain", "Network activity", sub, "Discovered subdomain")
        elif isinstance(sub, dict):
            val = sub.get("subdomain") or sub.get("host") or sub.get("name")
            if val:
                add_attr("domain", "Network activity", val, "Discovered subdomain")

    # Generic text fields (e.g. AS number, org name)
    for text_key, comment_label in (
        ("asn", "ASN"),
        ("org", "Organisation"),
        ("isp", "ISP"),
        ("country", "Country"),
    ):
        val = all_data.get(text_key)
        if isinstance(val, str) and val:
            add_attr("text", "External analysis", val, comment_label)

    event: dict = {
        "Event": {
            "info": f"OSINT scan: {target}",
            "date": _today_iso(),
            "threat_level_id": "2",
            "analysis": "2",
            "Attribute": attributes,
        }
    }
    logger.info("Built MISP event with %d attributes for target '%s'", len(attributes), target)
    return event


def save_stix(target: str, all_data: dict, output_dir: str = ".") -> dict:
    """Save STIX 2.1 and MISP JSON files to *output_dir*.

    Parameters
    ----------
    target:
        The scan target (used to derive filenames).
    all_data:
        Dictionary of all collected scan results.
    output_dir:
        Directory where files will be written (created if absent).

    Returns
    -------
    dict
        {"stix": "<absolute path>", "misp": "<absolute path>"}
    """
    os.makedirs(output_dir, exist_ok=True)

    safe_target = target.replace("/", "_").replace(":", "_").replace("@", "_at_")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    stix_filename = f"stix_{safe_target}_{timestamp}.json"
    misp_filename = f"misp_{safe_target}_{timestamp}.json"

    stix_path = os.path.abspath(os.path.join(output_dir, stix_filename))
    misp_path = os.path.abspath(os.path.join(output_dir, misp_filename))

    stix_bundle = to_stix_bundle(target, all_data)
    misp_event = to_misp_event(target, all_data)

    with open(stix_path, "w", encoding="utf-8") as fh:
        json.dump(stix_bundle, fh, indent=2, ensure_ascii=False)
    logger.info("Saved STIX bundle to %s", stix_path)

    with open(misp_path, "w", encoding="utf-8") as fh:
        json.dump(misp_event, fh, indent=2, ensure_ascii=False)
    logger.info("Saved MISP event to %s", misp_path)

    return {"stix": stix_path, "misp": misp_path}


def print_export_summary(paths: dict) -> None:
    """Display a Rich summary of exported STIX/MISP files.

    Parameters
    ----------
    paths:
        Dict returned by :func:`save_stix` — keys ``"stix"`` and ``"misp"``.
    """
    console.print("\n[bold cyan]═══ EXPORT SUMMARY ═══[/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Format", style="cyan", width=10)
    table.add_column("File path", style="white")

    stix_path = paths.get("stix", "")
    misp_path = paths.get("misp", "")

    if stix_path:
        table.add_row("STIX 2.1", stix_path)
    if misp_path:
        table.add_row("MISP", misp_path)

    console.print(table)

    if stix_path and os.path.isfile(stix_path):
        size_kb = os.path.getsize(stix_path) / 1024
        console.print(f"  [green]STIX file written ({size_kb:.1f} KB)[/green]")
    if misp_path and os.path.isfile(misp_path):
        size_kb = os.path.getsize(misp_path) / 1024
        console.print(f"  [green]MISP file written ({size_kb:.1f} KB)[/green]")
