"""
Email Forensics — MSG file CVE-2023-23397 analyser

Analyses Outlook .msg files for signs of UNC-path injection exploitation
(CVE-2023-23397). Can process a single file or scan an entire directory.

Optional dependencies:
  pip install compoundfiles outlook-msg extract-msg python-dateutil
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ── Availability guard ─────────────────────────────────────────────────────────

def _deps_available() -> bool:
    try:
        import compoundfiles  # noqa: F401
        import extract_msg    # noqa: F401
        return True
    except ImportError:
        return False


# ── Core verifier (adapted from email-hunter) ──────────────────────────────────

def _verify_msg_file(file_path: str) -> dict:
    """Verify a single .msg file for CVE-2023-23397 indicators.

    Returns a structured result dict.
    """
    result = {
        "file_path": file_path,
        "status": "unknown",       # clean | infected | unknown | error
        "name": "CVE-2023-23397",
        "description": (
            "Outlook UNC-path injection: forces NTLM auth handshake to attacker server "
            "via calendar invite reminder sound (PidLidReminderFileParameter 0x8015)."
        ),
        "indicators": [],
        "metadata": {},
    }

    try:
        import compoundfiles
        from outlook_msg import Message
        import extract_msg
    except ImportError as exc:
        result["status"] = "error"
        result["description"] = f"Missing dependency: {exc}. Install: pip install compoundfiles outlook-msg extract-msg python-dateutil"
        return result

    # ── Try opening as Compound Document ──────────────────────────────────────
    try:
        with open(file_path) as f:
            msg = Message(f)
    except compoundfiles.errors.CompoundFileInvalidMagicError:
        result["status"] = "error"
        result["description"] = f"'{file_path}' is not a valid MSG/Compound file."
        return result
    except Exception as exc:
        result["status"] = "error"
        result["description"] = f"Could not open '{file_path}': {exc}"
        return result

    # ── Extract email metadata ─────────────────────────────────────────────────
    try:
        parsed = extract_msg.openMsg(file_path)
        meta = json.loads(parsed.getJson())
        try:
            from dateutil.parser import parse as _parse_date
            meta["date"] = _parse_date(meta.get("date", "")).isoformat()
        except Exception:
            pass
        result["metadata"] = {
            "subject": meta.get("subject", ""),
            "sender": meta.get("sender", ""),
            "date": meta.get("date", ""),
            "body_preview": (meta.get("body", "") or "")[:200],
        }
    except Exception:
        pass  # metadata extraction is best-effort

    # ── Scan for UNC paths in compound storage streams ─────────────────────────
    try:
        for entry in msg.mfs.storage:
            try:
                raw = msg.mfs.read_storage(entry.name)
                value = raw.decode("utf-16", errors="ignore")
                unc_paths = re.findall(r"\\\\[^\x00\r\n]+", value)
                if unc_paths:
                    result["indicators"].extend(unc_paths)
                    result["status"] = "infected"
            except (Exception,):
                continue
        if not result["indicators"] and result["status"] == "unknown":
            result["status"] = "clean"
    except KeyError:
        result["status"] = "clean"
    except Exception as exc:
        result["status"] = "unknown"
        result["description"] = f"Partial scan — error during stream analysis: {exc}"

    return result


# ── Directory scan ─────────────────────────────────────────────────────────────

def analyse_path(path: str) -> dict:
    """Analyse *path* (file or directory) for CVE-2023-23397.

    Returns::

        {
            "path": str,
            "files_scanned": int,
            "infected_count": int,
            "clean_count": int,
            "unknown_count": int,
            "results": [<verify_result>, ...]
        }
    """
    p = Path(path)
    msg_files: list[Path] = []

    if p.is_file():
        msg_files = [p]
    elif p.is_dir():
        msg_files = list(p.rglob("*.msg"))
    else:
        return {
            "path": path,
            "files_scanned": 0,
            "infected_count": 0,
            "clean_count": 0,
            "unknown_count": 0,
            "results": [],
            "error": f"Path not found: {path}",
        }

    if not msg_files:
        return {
            "path": path,
            "files_scanned": 0,
            "infected_count": 0,
            "clean_count": 0,
            "unknown_count": 0,
            "results": [],
            "error": "No .msg files found.",
        }

    results = []
    for mf in msg_files:
        console.print(f"[dim]  Analysing {mf.name}…[/dim]")
        results.append(_verify_msg_file(str(mf)))

    infected = sum(1 for r in results if r["status"] == "infected")
    clean = sum(1 for r in results if r["status"] == "clean")
    unknown = sum(1 for r in results if r["status"] == "unknown")

    return {
        "path": path,
        "files_scanned": len(results),
        "infected_count": infected,
        "clean_count": clean,
        "unknown_count": unknown,
        "results": results,
    }


# ── Display ────────────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "infected": "bold red",
    "clean": "bold green",
    "unknown": "yellow",
    "error": "red dim",
}
_STATUS_ICON = {
    "infected": "☠",
    "clean": "✔",
    "unknown": "?",
    "error": "✗",
}


def print_forensics_results(data: dict) -> None:
    path = data.get("path", "")
    scanned = data.get("files_scanned", 0)
    infected = data.get("infected_count", 0)

    if "error" in data and not scanned:
        console.print(f"\n[red]✗ {data['error']}[/red]")
        return

    console.print(f"\n[bold cyan]📧 Email Forensics — CVE-2023-23397[/bold cyan]")
    console.print(f"[dim]Path: {path}[/dim]")
    console.print(f"[dim]Files scanned: {scanned}[/dim]\n")

    if infected:
        console.print(f"[bold red]☠ {infected} INFECTED file(s) detected![/bold red]\n")
    elif scanned:
        console.print(f"[bold green]✔ No infected files found[/bold green]\n")

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    table.add_column("File", style="white")
    table.add_column("Status", width=12, justify="center")
    table.add_column("Indicators / Info", style="dim")

    for r in data["results"]:
        status = r["status"]
        style = _STATUS_STYLE.get(status, "dim")
        icon = _STATUS_ICON.get(status, "?")
        status_cell = f"[{style}]{icon} {status.upper()}[/{style}]"

        indicators = r.get("indicators", [])
        meta = r.get("metadata", {})
        if indicators:
            info = "UNC: " + "; ".join(indicators[:3])
        elif meta.get("subject"):
            info = f"Subject: {meta['subject'][:60]}"
        else:
            info = r.get("description", "")[:80]

        table.add_row(Path(r["file_path"]).name, status_cell, info)

    console.print(table)

    # Show detailed UNC paths for infected files
    for r in data["results"]:
        if r["status"] == "infected" and r.get("indicators"):
            console.print(
                Panel(
                    "\n".join(r["indicators"]),
                    title=f"[red]UNC Paths — {Path(r['file_path']).name}[/red]",
                    border_style="red",
                    box=box.ROUNDED,
                )
            )
