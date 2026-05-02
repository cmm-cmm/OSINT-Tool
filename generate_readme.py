#!/usr/bin/env python3
"""
generate_readme.py — Auto-rebuild README.md from the live module registry.

Run from the project root:
    python generate_readme.py

What it does:
  1. Reads README_template.md (must exist)
  2. Replaces {{modules_table}} with a Markdown table built from ALL_MODULES
  3. Replaces {{ext_tools_table}} with a table built from ALL_EXTERNAL_TOOLS
  4. Writes the result to README.md
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Allow running from any directory
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from modules.base import ALL_MODULES
from modules.external_tools import ALL_EXTERNAL_TOOLS
from modules.constants import VERSION_DISPLAY


# ── Helpers ───────────────────────────────────────────────────────────────────

def _status_badge(available: bool) -> str:
    return "✅" if available else "⚠️"


def _modules_table() -> str:
    lines = [
        "| # | Module | Tags | Optional deps |",
        "|---|--------|------|--------------|",
    ]
    for i, m in enumerate(ALL_MODULES, start=1):
        tags = ", ".join(f"`{t}`" for t in m.TAGS) if m.TAGS else "—"
        deps = ", ".join(f"`{d}`" for d in m.OPTIONAL_DEPS) if m.OPTIONAL_DEPS else "—"
        archived = " *(archived)*" if m.ARCHIVED else ""
        lines.append(f"| {i} | {m.ICON} **{m.TITLE}**{archived} | {tags} | {deps} |")
    return "\n".join(lines)


def _ext_tools_table() -> str:
    lines = [
        "| Tool | Description | Install | Requires Go |",
        "|------|-------------|---------|-------------|",
    ]
    for t in ALL_EXTERNAL_TOOLS:
        go = "Yes" if t.requires_go else "No"
        install = f"`{t.install_cmd}`"
        lines.append(f"| **{t.name}** | {t.description} | {install} | {go} |")
    return "\n".join(lines)


# ── Main ──────────────────────────────────────────────────────────────────────

def generate() -> None:
    template_path = ROOT / "README_template.md"
    output_path   = ROOT / "README.md"

    if not template_path.exists():
        # Create a minimal template if it doesn't exist yet
        template_path.write_text(
            f"# OSINT Tool {VERSION_DISPLAY}\n\n"
            "A modular open-source intelligence toolkit.\n\n"
            "## Modules\n\n"
            "{{modules_table}}\n\n"
            "## External Tools\n\n"
            "{{ext_tools_table}}\n",
            encoding="utf-8",
        )
        print(f"[!] Created starter template: {template_path}")

    content = template_path.read_text(encoding="utf-8")
    content = content.replace("{{modules_table}}", _modules_table())
    content = content.replace("{{ext_tools_table}}", _ext_tools_table())
    # Also update version placeholder if used
    content = re.sub(r"v\d+\.\d+\.\d+", VERSION_DISPLAY, content, count=1)

    output_path.write_text(content, encoding="utf-8")
    print(f"[+] README.md updated — {len(ALL_MODULES)} modules, {len(ALL_EXTERNAL_TOOLS)} external tools.")


if __name__ == "__main__":
    generate()
