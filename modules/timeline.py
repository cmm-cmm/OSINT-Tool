"""
Timeline Module

Aggregates scan history from the database, computes diffs between consecutive
scans, and renders a dark-themed HTML timeline snippet matching existing reports.
"""
from __future__ import annotations

import html as _html
import json
import logging
import datetime
from typing import Any

logger = logging.getLogger("osint.timeline")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _e(value: Any) -> str:
    """Escape HTML entities in plain-text values."""
    return _html.escape(str(value), quote=True)


def _iso(ts: str) -> str:
    """Normalise an ISO timestamp to a display-friendly format."""
    try:
        dt = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, AttributeError):
        return str(ts)


def _flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """
    Recursively flatten a nested dict/list into dot-notation key→leaf-value
    pairs.  Lists are truncated to their length (not individual items) to keep
    diff output readable.
    """
    result: dict[str, Any] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                result.update(_flatten(v, full_key))
            else:
                result[full_key] = v
    elif isinstance(obj, list):
        # Represent lists by their length so changes in count are surfaced
        result[prefix] = f"[{len(obj)} items]"
        # Also recurse into the first item to expose its structure
        if obj and isinstance(obj[0], dict):
            result.update(_flatten(obj[0], f"{prefix}[0]"))
    else:
        result[prefix] = obj
    return result


def _module_from_key(key: str) -> str:
    """Guess the originating module from a dot-notation data key."""
    top = key.split(".")[0]
    return top if top else "unknown"


# ── Public API ────────────────────────────────────────────────────────────────

def build_timeline(target: str, limit: int = 50) -> list[dict]:
    """
    Read scan history for *target* from the database and return a list of
    timeline events sorted in ascending time order.

    Each event has the shape::

        {
            "ts":      str,   # ISO timestamp
            "type":    str,   # "scan"
            "module":  str,   # comma-joined module names
            "summary": str,   # short human-readable description
            "data":    dict,  # full scan data payload
        }

    Args:
        target: The OSINT target (domain, email, username, …)
        limit:  Maximum number of scan records to include

    Returns:
        List of event dicts, oldest first.  Empty list if no history found.
    """
    try:
        from modules.db import get_db
        db = get_db()
    except Exception as exc:
        logger.error("build_timeline: could not connect to DB: %s", exc)
        return []

    try:
        records = db.search(query=target, limit=limit)
    except Exception as exc:
        logger.error("build_timeline: DB search failed for '%s': %s", target, exc)
        return []

    if not records:
        logger.debug("build_timeline: no records found for '%s'", target)
        return []

    events: list[dict] = []
    for rec in records:
        # Fetch full data (search() omits the data column)
        try:
            full = db.get_scan(rec["id"])
        except Exception:
            full = None

        scan_data: dict = {}
        if full and isinstance(full.get("data"), dict):
            scan_data = full["data"]
        elif full and isinstance(full.get("data"), str):
            try:
                scan_data = json.loads(full["data"])
            except (json.JSONDecodeError, TypeError):
                pass

        ts = rec.get("updated_at") or rec.get("created_at") or ""
        modules_raw = rec.get("modules", [])
        if isinstance(modules_raw, str):
            try:
                modules_raw = json.loads(modules_raw)
            except (json.JSONDecodeError, TypeError):
                modules_raw = [modules_raw]
        module_str = ", ".join(modules_raw) if modules_raw else "unknown"

        # Build a one-line summary
        parts: list[str] = [f"{len(modules_raw)} module(s) run"]
        ip_data = scan_data.get("ip", {})
        if ip_data.get("geo", {}).get("data", {}).get("query"):
            parts.append(f"IP {ip_data['geo']['data']['query']}")
        breaches = scan_data.get("email", {}).get("hibp", {}).get("breaches", []) or []
        if breaches:
            parts.append(f"{len(breaches)} breach(es)")
        ports = ip_data.get("shodan", {}).get("ports", [])
        if ports:
            parts.append(f"{len(ports)} open port(s)")
        summary = " · ".join(parts)

        events.append(
            {
                "ts":      ts,
                "type":    "scan",
                "module":  module_str,
                "summary": summary,
                "data":    scan_data,
            }
        )

    # Sort oldest → newest
    def _sort_key(ev: dict) -> str:
        return ev.get("ts") or ""

    events.sort(key=_sort_key)
    return events


def diff_scans(old: dict, new: dict) -> list[dict]:
    """
    Compare two scan data dicts and return a list of field-level changes.

    Each change has the shape::

        {
            "field":  str,  # dot-notation path within the data dict
            "old":    Any,  # previous value (None if field is new)
            "new":    Any,  # current value (None if field was removed)
            "module": str,  # top-level module name inferred from the field path
        }

    Args:
        old: Previous scan data dict
        new: Current scan data dict

    Returns:
        List of change dicts.  Empty list if the data is identical or inputs
        are not dicts.
    """
    if not isinstance(old, dict) or not isinstance(new, dict):
        return []

    flat_old = _flatten(old)
    flat_new = _flatten(new)

    all_keys = set(flat_old) | set(flat_new)
    changes: list[dict] = []

    for key in sorted(all_keys):
        v_old = flat_old.get(key)
        v_new = flat_new.get(key)
        if v_old != v_new:
            changes.append(
                {
                    "field":  key,
                    "old":    v_old,
                    "new":    v_new,
                    "module": _module_from_key(key),
                }
            )

    return changes


def get_change_summary(changes: list[dict]) -> str:
    """
    Build a human-readable plain-text summary of a list of change dicts as
    returned by :func:`diff_scans`.

    Args:
        changes: List of change dicts

    Returns:
        Multi-line string.  Returns "No changes detected." when the list is
        empty.
    """
    if not changes:
        return "No changes detected."

    # Group by module
    by_module: dict[str, list[dict]] = {}
    for ch in changes:
        mod = ch.get("module", "unknown")
        by_module.setdefault(mod, []).append(ch)

    lines: list[str] = [f"{len(changes)} field(s) changed across {len(by_module)} module(s):", ""]

    for mod, mod_changes in sorted(by_module.items()):
        lines.append(f"[{mod}]  ({len(mod_changes)} change(s))")
        for ch in mod_changes[:10]:  # cap per-module lines for readability
            field = ch["field"]
            v_old = ch["old"]
            v_new = ch["new"]
            if v_old is None:
                lines.append(f"  + {field}: {v_new}")
            elif v_new is None:
                lines.append(f"  - {field}: {v_old}")
            else:
                lines.append(f"  ~ {field}: {v_old!r} → {v_new!r}")
        if len(mod_changes) > 10:
            lines.append(f"  … and {len(mod_changes) - 10} more")
        lines.append("")

    return "\n".join(lines).rstrip()


def render_timeline_html(events: list[dict]) -> str:
    """
    Render a list of timeline events as an HTML snippet using the dark theme
    matching the existing report modules (background #0d1117, accent #58a6ff).

    The snippet is self-contained (inline CSS included) and can be embedded
    directly inside any OSINT report page.

    Args:
        events: List of event dicts as returned by :func:`build_timeline`

    Returns:
        HTML string.  Returns an empty ``<p>`` notice when *events* is empty.
    """
    if not events:
        return (
            '<div class="section" style="background:#161b22;border:1px solid #30363d;'
            'border-radius:8px;padding:16px;">'
            '<p style="color:#8b949e;">No scan history available for this target.</p>'
            "</div>"
        )

    # Build timeline items newest → oldest for display (reverse chronological)
    items_html = ""
    for ev in reversed(events):
        ts_display = _iso(ev.get("ts", ""))
        module_str = _e(ev.get("module", ""))
        summary    = _e(ev.get("summary", ""))
        ev_type    = _e(ev.get("type", "scan"))

        items_html += (
            f'<li style="padding:10px 0 10px 28px;position:relative;font-size:0.85rem;'
            f'border-bottom:1px solid #21262d;">'
            f'<span style="position:absolute;left:0;color:#58a6ff;font-size:0.8rem;">&#9679;</span>'
            f'<span style="color:#8b949e;font-size:0.78rem;">{_e(ts_display)}</span>'
            f'&nbsp;&nbsp;'
            f'<span style="display:inline-block;padding:1px 7px;border-radius:10px;'
            f'font-size:0.72rem;background:#21262d;border:1px solid #30363d;color:#79c0ff;">'
            f'{ev_type}</span>'
            f'&nbsp;&nbsp;'
            f'<strong style="color:#e6edf3;">{summary}</strong>'
            f'<br>'
            f'<span style="color:#8b949e;font-size:0.78rem;margin-left:4px;">Modules: {module_str}</span>'
            f'</li>'
        )

    return (
        '<div class="section" style="background:#161b22;border:1px solid #30363d;'
        'border-radius:8px;padding:16px;margin-bottom:16px;">'
        '<h2 style="color:#79c0ff;font-size:1rem;text-transform:uppercase;'
        'letter-spacing:1px;margin:0 0 12px;">Scan Timeline</h2>'
        '<ul style="list-style:none;padding:0;margin:0;position:relative;">'
        f'<div style="position:absolute;left:8px;top:0;bottom:0;width:2px;background:#30363d;"></div>'
        f'{items_html}'
        "</ul>"
        f'<p style="color:#8b949e;font-size:0.78rem;margin-top:10px;">'
        f'{len(events)} scan(s) in history</p>'
        "</div>"
    )
