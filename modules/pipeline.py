"""
Scan Pipeline Orchestrator
==========================
Runs multiple OSINT modules in parallel and aggregates their results into a
single structured report dict.

Usage::

    from modules.pipeline import run_pipeline

    results = run_pipeline("example.com", preset="domain")
    print(results["results"]["whois"])

Or with progress feedback::

    def on_progress(module, status, result):
        print(f"[{status}] {module}")

    results = run_pipeline("example.com", preset="auto", progress_callback=on_progress)
"""

from __future__ import annotations

import logging
import time
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

logger = logging.getLogger("osint.pipeline")

# ── Preset definitions ────────────────────────────────────────────────────────

#: Map preset name → ordered list of module names.
#: For "auto" the list is determined at runtime by _detect_target_type().
PRESETS: dict[str, dict[str, list[str]]] = {
    "domain": {
        "modules": ["whois", "dns", "ssl", "ip", "cloud", "secrets", "certs"],
    },
    "email": {
        "modules": ["email", "breach", "username"],
    },
    "username": {
        "modules": ["username", "breach"],
    },
    "ip": {
        "modules": ["ip", "ssl"],
    },
    "full": {
        # Smart order: passive recon first, then active/slow modules last
        "modules": [
            "whois", "dns", "ip", "ssl", "certs",
            "email", "username", "breach",
            "cloud", "secrets",
            "social", "instagram",
            "phone",
        ],
    },
    "quick": {
        "modules": ["whois", "dns", "ip"],
    },
}

# ── Module runner registry ────────────────────────────────────────────────────
# Each entry maps a short module name to a callable that accepts (target, **kwargs)
# and returns a dict.  Imports are done lazily so missing optional dependencies
# only break the specific module, not the whole pipeline.


def _run_whois(target: str, **_) -> dict:
    try:
        from modules.whois_lookup import whois_lookup
        return whois_lookup(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_dns(target: str, **_) -> dict:
    try:
        from modules.whois_lookup import dns_enum
        return dns_enum(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_ip(target: str, **_) -> dict:
    try:
        import os
        from modules.ip_lookup import ip_lookup
        return ip_lookup(
            target,
            virustotal_key=os.getenv("VIRUSTOTAL_KEY"),
            shodan_key=os.getenv("SHODAN_KEY"),
            abuseipdb_key=os.getenv("ABUSEIPDB_KEY"),
        )
    except Exception as exc:
        return {"error": str(exc)}


def _run_email(target: str, **_) -> dict:
    try:
        import os
        from modules.email_recon import email_recon
        return email_recon(
            target,
            hibp_api_key=os.getenv("HIBP_API_KEY"),
            hunter_key=os.getenv("HUNTER_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY", ""),
            do_holehe=False,
        )
    except Exception as exc:
        return {"error": str(exc)}


def _run_username(target: str, **_) -> dict:
    try:
        from modules.username_search import username_search
        return username_search(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_ssl(target: str, **_) -> dict:
    try:
        from modules.ssl_analyzer import ssl_analyze
        return ssl_analyze(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_breach(target: str, **_) -> dict:
    try:
        import os
        from modules.breach_check import breach_check
        return breach_check(
            target,
            hibp_key=os.getenv("HIBP_API_KEY"),
            breachdir_key=os.getenv("BREACHDIRECTORY_KEY"),
            dehashed_email=os.getenv("DEHASHED_EMAIL"),
            dehashed_key=os.getenv("DEHASHED_KEY"),
            snusbase_key=os.getenv("SNUSBASE_KEY"),
            emailrep_key=os.getenv("EMAILREP_KEY"),
            hunter_key=os.getenv("HUNTER_KEY"),
        )
    except Exception as exc:
        return {"error": str(exc)}


def _run_cloud(target: str, **_) -> dict:
    try:
        from modules.cloud_recon import cloud_recon
        return cloud_recon(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_social(target: str, **_) -> dict:
    try:
        import os
        from modules.social_recon import facebook_recon
        return facebook_recon(target, fb_scraper_key=os.getenv("FACEBOOK_SCRAPER_KEY"))
    except Exception as exc:
        return {"error": str(exc)}


def _run_certs(target: str, **_) -> dict:
    try:
        from modules.cert_transparency import cert_recon
        return cert_recon(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_secrets(target: str, **_) -> dict:
    try:
        from modules.secrets_scanner import secrets_scan
        return secrets_scan(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_instagram(target: str, **_) -> dict:
    try:
        from modules.instagram_recon import instagram_recon
        return instagram_recon(target)
    except Exception as exc:
        return {"error": str(exc)}


def _run_phone(target: str, **_) -> dict:
    try:
        import os
        from modules.phone_lookup import phone_lookup
        return phone_lookup(target, numverify_key=os.getenv("NUMVERIFY_KEY"))
    except Exception as exc:
        return {"error": str(exc)}


_MODULE_RUNNERS: dict[str, Callable] = {
    "whois":     _run_whois,
    "dns":       _run_dns,
    "ip":        _run_ip,
    "email":     _run_email,
    "username":  _run_username,
    "ssl":       _run_ssl,
    "breach":    _run_breach,
    "cloud":     _run_cloud,
    "social":    _run_social,
    "certs":     _run_certs,
    "secrets":   _run_secrets,
    "instagram": _run_instagram,
    "phone":     _run_phone,
}

# ── Pipeline class ────────────────────────────────────────────────────────────


class ScanPipeline:
    """
    Orchestrates multiple OSINT modules for a single target.

    Parameters
    ----------
    target:
        The value to investigate (domain, email address, username, IP, …).
    preset:
        Named scan profile.  One of: ``"auto"``, ``"domain"``, ``"email"``,
        ``"username"``, ``"ip"``, ``"full"``, ``"quick"``.
        When ``"auto"`` the preset is chosen by inspecting *target*.
    modules:
        Explicit list of module names to run.  When provided, *preset* is
        ignored (except for ordering purposes).
    use_cache:
        Reserved for future caching integration.  Currently unused but
        accepted so callers can pass it without breaking.
    output_dir:
        Directory for optional report files.  Not used by the pipeline
        itself; passed through in the result dict so callers can save
        reports afterwards.
    """

    MAX_WORKERS = 4

    def __init__(
        self,
        target: str,
        preset: str = "auto",
        modules: list[str] | None = None,
        use_cache: bool = True,
        output_dir: str = "./reports",
    ) -> None:
        self.target = target.strip()
        self.preset = preset
        self.modules = modules
        self.use_cache = use_cache
        self.output_dir = output_dir

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, progress_callback: Callable | None = None) -> dict:
        """
        Execute all configured modules and return a combined result dict.

        Parameters
        ----------
        progress_callback:
            Optional callable invoked after each module completes.
            Signature: ``callback(module_name: str, status: str, result: dict)``
            *status* is ``"ok"`` or ``"error"``.

        Returns
        -------
        dict with keys:
            * ``target``       — the scanned target string
            * ``preset``       — effective preset name used
            * ``modules_run``  — list of module names that were executed
            * ``results``      — ``{module_name: result_dict}``
            * ``errors``       — ``{module_name: error_message}`` for failed modules
            * ``duration_ms``  — total wall-clock time in milliseconds
            * ``started_at``   — ISO-8601 UTC timestamp when the run started
            * ``completed_at`` — ISO-8601 UTC timestamp when the run finished
        """
        started_dt = datetime.datetime.utcnow()
        t0 = time.monotonic()

        target_type = self._detect_target_type(self.target)
        effective_preset = self.preset if self.preset != "auto" else target_type

        if self.modules:
            module_list = [m for m in self.modules if m in _MODULE_RUNNERS]
        else:
            module_list = self._get_modules_for_preset(self.preset, target_type)

        logger.info(
            "Pipeline starting: target=%r preset=%r effective=%r modules=%r",
            self.target, self.preset, effective_preset, module_list,
        )

        results: dict[str, dict] = {}
        errors: dict[str, str] = {}

        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as pool:
            future_to_name = {
                pool.submit(_MODULE_RUNNERS[name], self.target): name
                for name in module_list
                if name in _MODULE_RUNNERS
            }

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"error": str(exc)}

                if "error" in result and len(result) == 1:
                    errors[name] = result["error"]
                    status = "error"
                    logger.warning("Module %r failed: %s", name, result["error"])
                else:
                    status = "ok"
                    logger.debug("Module %r completed OK", name)

                results[name] = result

                if progress_callback is not None:
                    try:
                        progress_callback(name, status, result)
                    except Exception:
                        pass  # never let a callback crash the pipeline

        completed_dt = datetime.datetime.utcnow()
        duration_ms = int((time.monotonic() - t0) * 1000)

        logger.info(
            "Pipeline finished: %d modules, %d errors, %d ms",
            len(results), len(errors), duration_ms,
        )

        return {
            "target":       self.target,
            "preset":       effective_preset,
            "modules_run":  module_list,
            "results":      results,
            "errors":       errors,
            "duration_ms":  duration_ms,
            "started_at":   started_dt.isoformat(timespec="seconds") + "Z",
            "completed_at": completed_dt.isoformat(timespec="seconds") + "Z",
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _detect_target_type(self, target: str) -> str:
        """
        Heuristically identify the kind of *target*.

        Returns one of: ``"domain"``, ``"email"``, ``"ip"``,
        ``"username"``, ``"auto"``.
        """
        import re

        target = target.strip()

        # Email: contains exactly one @ surrounded by non-whitespace
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', target):
            return "email"

        # IPv4
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
            return "ip"

        # IPv6 (very loose check)
        if re.match(r'^[0-9a-fA-F:]+:[0-9a-fA-F:]+$', target):
            return "ip"

        # Domain-like: contains a dot and only valid hostname chars
        if re.match(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$', target):
            return "domain"

        # Fall back to username for anything else (e.g. plain word)
        return "username"

    def _get_modules_for_preset(self, preset: str, target_type: str) -> list[str]:
        """
        Return the ordered list of module names for the given *preset*.

        When *preset* is ``"auto"``, *target_type* is used to pick the
        most appropriate built-in preset.
        """
        effective = preset if preset != "auto" else target_type

        if effective in PRESETS:
            return list(PRESETS[effective]["modules"])

        # Unknown preset — fall back to "quick"
        logger.warning(
            "Unknown preset %r (target_type=%r), falling back to 'quick'",
            preset, target_type,
        )
        return list(PRESETS["quick"]["modules"])


# ── Convenience wrapper ───────────────────────────────────────────────────────


def run_pipeline(
    target: str,
    preset: str = "auto",
    *,
    modules: list[str] | None = None,
    use_cache: bool = True,
    output_dir: str = "./reports",
    progress_callback: Callable | None = None,
    **kwargs,
) -> dict:
    """
    Convenience wrapper around :class:`ScanPipeline`.

    Parameters
    ----------
    target:
        The value to investigate.
    preset:
        Named scan profile (``"auto"``, ``"domain"``, ``"email"``,
        ``"username"``, ``"ip"``, ``"full"``, ``"quick"``).
    modules:
        Explicit module list; overrides *preset* when provided.
    use_cache:
        Reserved for future caching integration.
    output_dir:
        Base directory for report files.
    progress_callback:
        Called after each module: ``callback(name, status, result)``.
    **kwargs:
        Ignored; accepted for forward-compatibility.

    Returns
    -------
    dict — see :meth:`ScanPipeline.run` for key descriptions.
    """
    pipeline = ScanPipeline(
        target=target,
        preset=preset,
        modules=modules,
        use_cache=use_cache,
        output_dir=output_dir,
    )
    return pipeline.run(progress_callback=progress_callback)
