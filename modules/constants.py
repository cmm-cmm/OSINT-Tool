"""Shared constants for OSINT Tool."""

import platform
import shutil
from pathlib import Path

VERSION = "1.2.0"
VERSION_DISPLAY = f"v{VERSION}"

# ── Tool identity ─────────────────────────────────────────────────────────────
TOOL_NAME     = "OSINT Tool"
TOOL_UA       = "OSINT-Tool/1.2 (Educational/Research Purpose)"
REPO_URL      = "https://github.com/cmm-cmm/OSINT-Tool"

# ── User config paths ─────────────────────────────────────────────────────────
USER_CONFIG_DIR  = Path.home() / ".osint-tool"
USER_CONFIG_FILE = USER_CONFIG_DIR / "config.json"
USER_LOG_FILE    = USER_CONFIG_DIR / "osint-tool.log"

# ── Default config ─────────────────────────────────────────────────────────────
DEFAULT_CONFIG: dict = {
    "output_dir":     ".",
    "default_region": "VN",
    "version":        VERSION,
    "show_tips":      True,
}

# ── UI Theme ──────────────────────────────────────────────────────────────────
THEME_PRIMARY  = "bold magenta"
THEME_ACCENT   = "bold cyan"
THEME_SUCCESS  = "bold green"
THEME_ERROR    = "bold red"
THEME_WARNING  = "bold yellow"
THEME_DIM      = "dim white"
THEME_URL      = "underline bright_blue"
THEME_BORDER   = "bright_blue"
THEME_ARCHIVED = "dim yellow"

# ── Platform detection ────────────────────────────────────────────────────────
_IS_WINDOWS = platform.system() == "Windows"
_HAS_GO     = shutil.which("go") is not None
_HAS_WINGET = shutil.which("winget") is not None
_HAS_SCOOP  = shutil.which("scoop") is not None

def _go_install_note() -> str:
    """Return a friendly note about installing Go on Windows."""
    if _HAS_WINGET:
        return "winget install GoLang.Go"
    if _HAS_SCOOP:
        return "scoop install go"
    return "https://go.dev/dl/"


# ── Optional external tool definitions ───────────────────────────────────────
# install_cmd   : primary install command (used on Linux/Mac or when Go is available)
# install_win   : Windows-specific alternative (winget / scoop / release URL)
# binary        : executable name to check with shutil.which / venv Scripts
# py_module     : Python module name to import-check (for pip-based tools)
# requires_go   : True if the tool requires `go` to be installed
OPTIONAL_TOOLS: dict[str, dict] = {
    "holehe": {
        "install":     "pip install holehe",
        "install_win": "pip install holehe",
        "description": "Email → 120+ site registration check",
        "binary":      "holehe",
        "py_module":   "holehe",
        "requires_go": False,
    },
    "maigret": {
        "install":     "pip install maigret",
        "install_win": "pip install maigret",
        "description": "Username OSINT across 3000+ sites",
        "binary":      "maigret",
        "py_module":   "maigret",
        "requires_go": False,
    },
    "theHarvester": {
        "install":     "pip install git+https://github.com/laramies/theHarvester.git",
        "install_win": "pip install git+https://github.com/laramies/theHarvester.git",
        "description": "Emails, subdomains, IPs from public sources",
        "binary":      "theHarvester",
        "py_module":   None,
        "requires_go": False,
    },
    "subfinder": {
        "install":     "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "install_win": "https://github.com/projectdiscovery/subfinder/releases/latest",
        "description": "Fast passive subdomain enumeration",
        "binary":      "subfinder",
        "py_module":   None,
        "requires_go": True,
    },
    "amass": {
        "install":     "go install github.com/owasp-amass/amass/v4/...@master",
        "install_win": "https://github.com/owasp-amass/amass/releases/latest",
        "description": "In-depth subdomain & attack surface mapping",
        "binary":      "amass",
        "py_module":   None,
        "requires_go": True,
    },
    "trufflehog": {
        "install":     "pip install trufflehog",
        "install_win": "pip install trufflehog",
        "description": "Find & verify leaked credentials in git repos",
        "binary":      "trufflehog",
        "py_module":   "trufflehog",
        "requires_go": False,
    },
    "gitleaks": {
        "install":     "go install github.com/gitleaks/gitleaks/v8@latest",
        "install_win": "https://github.com/gitleaks/gitleaks/releases/latest",
        "description": "Detect hardcoded secrets in git history",
        "binary":      "gitleaks",
        "py_module":   None,
        "requires_go": True,
    },
    "instaloader": {
        "install":     "pip install instaloader",
        "install_win": "pip install instaloader",
        "description": "Full Instagram profile & post OSINT",
        "binary":      "instaloader",
        "py_module":   "instaloader",
        "requires_go": False,
    },
}
