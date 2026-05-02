"""
Persistent user configuration for OSINT Tool.
Stores settings in ~/.osint-tool/config.json.
"""

import json
import logging
from pathlib import Path
from typing import Any

from modules.constants import USER_CONFIG_FILE, USER_CONFIG_DIR, DEFAULT_CONFIG

logger = logging.getLogger(__name__)


def load() -> dict[str, Any]:
    """Load config from disk, merging with defaults for any missing keys."""
    if USER_CONFIG_FILE.exists():
        try:
            on_disk = json.loads(USER_CONFIG_FILE.read_text(encoding="utf-8"))
            return {**DEFAULT_CONFIG, **on_disk}
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Config file unreadable (%s), using defaults.", exc)
    return dict(DEFAULT_CONFIG)


def save(cfg: dict[str, Any]) -> None:
    """Write config to disk, creating parent directories if needed."""
    USER_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    USER_CONFIG_FILE.write_text(
        json.dumps(cfg, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def get(key: str, default: Any = None) -> Any:
    """Get a single config value."""
    return load().get(key, default)


def set_value(key: str, value: Any) -> None:
    """Set a single config value and persist."""
    cfg = load()
    cfg[key] = value
    save(cfg)


def get_output_dir() -> Path:
    """Return configured output directory, falling back to CWD."""
    import os
    d = os.getenv("OSINT_OUTPUT_DIR") or get("output_dir", ".")
    p = Path(d).expanduser().resolve()
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_default_region() -> str:
    """Return configured default phone region."""
    import os
    return os.getenv("OSINT_REGION") or get("default_region", "VN")
