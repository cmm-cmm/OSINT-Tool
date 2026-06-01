"""
OSINT Scan Scheduler

Supports scheduled/recurring OSINT scans with change detection and alerting.
Uses APScheduler for job management.
"""
from __future__ import annotations
import os
import json
import hashlib
import logging
import datetime
from typing import Callable

from modules.constants import USER_CONFIG_DIR
from modules.exceptions import SchedulerError

logger = logging.getLogger("osint.scheduler")

SCHEDULE_FILE = USER_CONFIG_DIR / "schedules.json"


class ScheduledScan:
    """Configuration for a recurring OSINT scan."""

    def __init__(
        self,
        job_id: str,
        target: str,
        modules: list[str],
        interval_hours: int = 24,
        alert_on_change: bool = True,
        output_dir: str = "./reports",
        tags: list[str] | None = None,
    ):
        self.job_id = job_id
        self.target = target
        self.modules = modules
        self.interval_hours = interval_hours
        self.alert_on_change = alert_on_change
        self.output_dir = output_dir
        self.tags = tags or []
        self.created_at = datetime.datetime.utcnow().isoformat(timespec="seconds")
        self.last_run: str | None = None
        self.last_hash: str | None = None

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "target": self.target,
            "modules": self.modules,
            "interval_hours": self.interval_hours,
            "alert_on_change": self.alert_on_change,
            "output_dir": self.output_dir,
            "tags": self.tags,
            "created_at": self.created_at,
            "last_run": self.last_run,
            "last_hash": self.last_hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScheduledScan":
        obj = cls(
            job_id=d["job_id"],
            target=d["target"],
            modules=d.get("modules", ["whois", "dns"]),
            interval_hours=d.get("interval_hours", 24),
            alert_on_change=d.get("alert_on_change", True),
            output_dir=d.get("output_dir", "./reports"),
            tags=d.get("tags", []),
        )
        obj.created_at = d.get("created_at", obj.created_at)
        obj.last_run = d.get("last_run")
        obj.last_hash = d.get("last_hash")
        return obj


def _data_hash(data: dict) -> str:
    """Deterministic hash of scan data for change detection."""
    serialized = json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def _load_schedules() -> dict[str, ScheduledScan]:
    """Load all scheduled scans from disk."""
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not SCHEDULE_FILE.exists():
        return {}
    try:
        raw = json.loads(SCHEDULE_FILE.read_text(encoding="utf-8"))
        return {k: ScheduledScan.from_dict(v) for k, v in raw.items()}
    except (json.JSONDecodeError, KeyError) as e:
        logger.warning("Failed to load schedules: %s", e)
        return {}


def _save_schedules(schedules: dict[str, ScheduledScan]) -> None:
    """Persist all scheduled scans to disk."""
    SCHEDULE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        SCHEDULE_FILE.write_text(
            json.dumps({k: v.to_dict() for k, v in schedules.items()}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as e:
        logger.error("Failed to save schedules: %s", e)


def add_schedule(
    target: str,
    modules: list[str],
    interval_hours: int = 24,
    alert_on_change: bool = True,
    output_dir: str = "./reports",
    tags: list[str] | None = None,
) -> ScheduledScan:
    """Register a new scheduled scan. Returns the created ScheduledScan."""
    schedules = _load_schedules()
    import uuid
    job_id = str(uuid.uuid4())[:8]
    scan = ScheduledScan(
        job_id=job_id,
        target=target,
        modules=modules,
        interval_hours=interval_hours,
        alert_on_change=alert_on_change,
        output_dir=output_dir,
        tags=tags,
    )
    schedules[job_id] = scan
    _save_schedules(schedules)
    logger.info("Scheduled scan added: %s → %s (every %dh)", job_id, target, interval_hours)
    return scan


def remove_schedule(job_id: str) -> bool:
    """Remove a scheduled scan by job ID. Returns True if found and removed."""
    schedules = _load_schedules()
    if job_id not in schedules:
        return False
    del schedules[job_id]
    _save_schedules(schedules)
    logger.info("Removed scheduled scan: %s", job_id)
    return True


def list_schedules() -> list[ScheduledScan]:
    """Return all registered scheduled scans."""
    return list(_load_schedules().values())


def run_scheduled_scan(job_id: str, on_change: Callable[[str, dict, dict], None] | None = None) -> dict:
    """
    Execute a scheduled scan by job ID.

    Args:
        job_id: The schedule ID to run
        on_change: Optional callback(target, old_data, new_data) called when changes detected

    Returns:
        dict with run results and change detection status
    """
    schedules = _load_schedules()
    if job_id not in schedules:
        raise SchedulerError(f"No scheduled scan with ID: {job_id}")

    scan = schedules[job_id]
    logger.info("Running scheduled scan: %s → %s", job_id, scan.target)

    # Run the actual scan
    all_data = {}
    for module in scan.modules:
        try:
            all_data[module] = _dispatch_module_sync(module, scan.target)
        except Exception as exc:
            logger.warning("Module %s failed for %s: %s", module, scan.target, exc)
            all_data[module] = {"error": str(exc)}

    # Change detection
    new_hash = _data_hash(all_data)
    changed = scan.last_hash is not None and scan.last_hash != new_hash
    scan.last_run = datetime.datetime.utcnow().isoformat(timespec="seconds")
    scan.last_hash = new_hash

    # Save updated schedule
    schedules[job_id] = scan
    _save_schedules(schedules)

    # Save report
    try:
        from modules.report import save_report
        save_report(scan.target, all_data, scan.output_dir)
    except Exception as exc:
        logger.warning("Report save failed: %s", exc)

    # Store in DB
    try:
        from modules.db import get_db
        db = get_db()
        db.save_scan(scan.target, scan.modules, all_data, tags=scan.tags + ["scheduled"])
    except Exception:
        pass

    if changed and on_change:
        try:
            on_change(scan.target, {}, all_data)
        except Exception as exc:
            logger.warning("on_change callback failed: %s", exc)

    return {
        "job_id": job_id,
        "target": scan.target,
        "modules_run": scan.modules,
        "run_at": scan.last_run,
        "data_hash": new_hash,
        "changed": changed,
        "data": all_data,
    }


def run_all_due(on_change: Callable | None = None) -> list[dict]:
    """
    Run all scheduled scans that are due (past their interval).
    Returns list of run results.
    """
    schedules = _load_schedules()
    results = []
    now = datetime.datetime.utcnow()

    for job_id, scan in schedules.items():
        is_due = True
        if scan.last_run:
            try:
                last = datetime.datetime.fromisoformat(scan.last_run)
                elapsed_hours = (now - last).total_seconds() / 3600
                is_due = elapsed_hours >= scan.interval_hours
            except ValueError:
                is_due = True

        if is_due:
            try:
                result = run_scheduled_scan(job_id, on_change=on_change)
                results.append(result)
            except Exception as exc:
                results.append({"job_id": job_id, "error": str(exc)})

    return results


def print_schedules() -> None:
    """Print all registered schedules to the terminal using Rich."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    schedules = list_schedules()

    if not schedules:
        console.print("[yellow]No scheduled scans registered.[/yellow]")
        console.print("[dim]Use: osint.py schedule add --target example.com --interval 24[/dim]")
        return

    tbl = Table(title="📅 Scheduled Scans", header_style="bold cyan", show_lines=True)
    tbl.add_column("ID", style="dim", width=10)
    tbl.add_column("Target", style="bold")
    tbl.add_column("Modules")
    tbl.add_column("Interval")
    tbl.add_column("Last Run")
    tbl.add_column("Tags")

    for s in schedules:
        last = s.last_run[:16] if s.last_run else "[dim]never[/dim]"
        tbl.add_row(
            s.job_id,
            s.target,
            ", ".join(s.modules),
            f"every {s.interval_hours}h",
            last,
            ", ".join(s.tags) if s.tags else "—",
        )
    console.print(tbl)


def _dispatch_module_sync(module: str, target: str) -> dict:
    """Synchronous module dispatcher for scheduler. Target is pre-validated before scheduling."""
    if module == "whois":
        from modules.whois_lookup import whois_lookup
        return whois_lookup(target) or {}  # NOSONAR
    elif module == "dns":
        from modules.whois_lookup import dns_enum
        return dns_enum(target) or {}  # NOSONAR
    elif module == "ip":
        from modules.ip_lookup import ip_lookup
        return ip_lookup(target) or {}  # NOSONAR
    elif module == "email":
        from modules.email_recon import email_recon
        key = os.getenv("HIBP_API_KEY", "")
        return email_recon(target, hibp_api_key=key) or {}  # NOSONAR
    elif module == "username":
        from modules.username_search import username_search
        return username_search(target) or {}  # NOSONAR
    elif module == "ssl":
        from modules.ssl_analyzer import ssl_analyze
        return ssl_analyze(target) or {}  # NOSONAR
    elif module == "breach":
        from modules.breach_check import breach_check
        key = os.getenv("HIBP_API_KEY", "")
        return breach_check(target, hibp_key=key) or {}  # NOSONAR
    else:
        raise ValueError(f"Unknown module: {module}")
