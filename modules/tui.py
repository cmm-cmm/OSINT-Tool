"""
Interactive TUI menu engine for OSINT Tool.

Provides:
- Main menu with 2-column grid, system info header, random security quote
- Module selection with inline search (/), tag filter (t), inline help (?)
- Dependency status indicators ✔/✘ for each module
- Install-all optional deps shortcut (97)
- External Tools Manager (integrated)
- Config viewer/editor
"""

from __future__ import annotations

import datetime
import os
import platform
import random
import socket
import sys

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from modules.base import ALL_MODULES, OsintModule
from modules.constants import (
    THEME_PRIMARY, THEME_ACCENT, THEME_SUCCESS, THEME_WARNING,
    THEME_ERROR, THEME_DIM, VERSION_DISPLAY, REPO_URL,
)

console = Console()

# ── Security quotes (shown randomly in header) ────────────────────────────────

_QUOTES: list[str] = [
    '"The quieter you become, the more you can hear."',
    '"Offense informs defense."',
    '"There is no patch for human stupidity."',
    '"In God we trust. All others we monitor."',
    '"Enumerate before you exploit."',
    '"A scope defines your playground."',
    '"Security is a process, not a product."',
    '"Knowledge is power — use it responsibly."',
    '"Every record, every trace, tells a story."',
    '"Open source intelligence: truth from public sources."',
]

# ── Banner art ────────────────────────────────────────────────────────────────

_BANNER_ART: list[str] = [
    " ██████╗ ███████╗██╗███╗   ██╗████████╗",
    "██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝",
    "██║   ██║███████╗██║██╔██╗ ██║   ██║   ",
    "██║   ██║╚════██║██║██║╚██╗██║   ██║   ",
    "╚██████╔╝███████║██║██║ ╚████║   ██║   ",
    " ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝  ",
    "                                        ",
    "████████╗ ██████╗  ██████╗ ██╗          ",
    "╚══██╔══╝██╔═══██╗██╔═══██╗██║          ",
    "   ██║   ██║   ██║██║   ██║██║          ",
    "   ██║   ██║   ██║██║   ██║██║          ",
    "   ██║   ╚██████╔╝╚██████╔╝███████╗     ",
    "   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝     ",
]


# ── System info ───────────────────────────────────────────────────────────────

def _sys_info() -> dict:
    info: dict = {}
    try:
        info["os"] = f"{platform.system()} {platform.release()}"
    except Exception:
        info["os"] = "Unknown"
    try:
        info["user"] = os.getlogin()
    except Exception:
        info["user"] = os.environ.get("USERNAME", os.environ.get("USER", "user"))
    info["host"] = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        s.connect(("10.254.254.254", 1))
        info["ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        info["ip"] = "127.0.0.1"
    info["time"] = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M")
    info["python"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return info


# ── Header builder ─────────────────────────────────────────────────────────────

def _build_header() -> Panel:
    info = _sys_info()

    stat_lines = [
        ("  os      ›  ", info["os"][:40]),
        ("  user    ›  ", f"{info['user']} @ {info['host'][:22]}"),
        ("  ip      ›  ", info["ip"]),
        ("  time    ›  ", info["time"]),
        ("  python  ›  ", info["python"]),
        ("  version ›  ", VERSION_DISPLAY),
        ("  modules ›  ", f"{len(ALL_MODULES)} scan categories · 8 ext tools"),
        ("  status  ›  ", "✔ READY"),
        ("", ""),
        ("", ""),
        ("", ""),
        ("", ""),
        ("", ""),
    ]

    grid = Table.grid(padding=0)
    grid.add_column("art", no_wrap=True)
    grid.add_column("sep", no_wrap=True)
    grid.add_column("lbl", no_wrap=True)
    grid.add_column("val", no_wrap=True)

    for art_line, (lbl_text, val_text) in zip(_BANNER_ART, stat_lines):
        grid.add_row(
            Text(art_line, style="bold bright_cyan"),
            Text("  │ ", style="dim cyan"),
            Text(lbl_text, style="dim cyan"),
            Text(val_text, style="bright_cyan"),
        )

    quote = random.choice(_QUOTES)
    disclaimer = (
        "[dim]For educational and lawful research only. "
        "User is responsible for compliance with local laws.[/dim]"
    )

    content = Align.center(
        Text.assemble(
            ("\n", ""),
        )
    )

    return Panel(
        Columns([
            grid,
        ], expand=True),
        title=f"[bold cyan]OSINT Tool[/bold cyan]  [dim]{VERSION_DISPLAY}[/dim]",
        subtitle=f"[dim italic]{quote}[/dim italic]",
        border_style="bright_blue",
        box=box.DOUBLE_EDGE,
        padding=(0, 1),
    )


# ── Quick help ────────────────────────────────────────────────────────────────

def _show_inline_help() -> None:
    console.print(Panel(
        Text.assemble(
            ("  Main Menu\n", "bold white"),
            ("  ────────────────────────────────────\n", "dim"),
            ("  1–N      ", "bold cyan"), ("select a module\n", "white"),
            ("  95       ", "bold cyan"), ("view archived/deprecated modules\n", "white"),
            ("  97       ", "bold cyan"), ("install all missing optional deps\n", "white"),
            ("  98       ", "bold cyan"), ("open External Tools Manager\n", "white"),
            ("  /keyword ", "bold cyan"), ("search modules by name or tag\n", "white"),
            ("  t tag    ", "bold cyan"), ("filter modules by tag\n", "white"),
            ("  cfg      ", "bold cyan"), ("view/edit configuration\n", "white"),
            ("  log      ", "bold cyan"), ("view recent scan history\n", "white"),
            ("  ?        ", "bold cyan"), ("show this help\n", "white"),
            ("  q        ", "bold cyan"), ("quit OSINT Tool\n\n", "white"),
            ("  Inside a module\n", "bold white"),
            ("  ────────────────────────────────────\n", "dim"),
            ("  Answer prompts then press Enter\n", "dim"),
            ("  Ctrl+C   ", "bold cyan"), ("cancel and return to menu\n", "white"),
        ),
        title="[bold magenta] ? Quick Help [/bold magenta]",
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0, 2),
    ))
    Prompt.ask("[dim]Press Enter to return[/dim]", default="")


# ── Search / filter helpers ───────────────────────────────────────────────────

def _search_modules(query: str, modules: list[OsintModule]) -> list[OsintModule]:
    """Return modules whose title, description or tags match *query*."""
    q = query.lower()
    return [
        m for m in modules
        if q in m.TITLE.lower()
        or q in m.DESCRIPTION.lower()
        or any(q in tag for tag in m.TAGS)
    ]


def _filter_by_tag(tag: str, modules: list[OsintModule]) -> list[OsintModule]:
    """Return modules that have *tag* in their TAGS list."""
    t = tag.lower()
    return [m for m in modules if any(t in mt for mt in m.TAGS)]


# ── Archived modules menu ─────────────────────────────────────────────────────

def _show_archived_menu(archived: list[OsintModule]) -> None:
    """Show the list of deprecated/archived modules."""
    console.clear()
    console.rule("[bold yellow]Archived / Deprecated Modules[/bold yellow]", style="yellow")
    console.print("[dim]These modules are kept for reference but may be broken or unmaintained.[/dim]\n")

    table = Table(box=box.SIMPLE_HEAD, show_lines=True)
    table.add_column("No.", justify="center", style="bold yellow", width=5)
    table.add_column("Module", style="dim yellow", min_width=22)
    table.add_column("Reason", style="dim white")

    for i, m in enumerate(archived, start=1):
        table.add_row(str(i), f"{m.ICON} {m.TITLE}", m.ARCHIVED_REASON or "Deprecated")
    table.add_row("99", "Back", "")
    console.print(table)

    raw = Prompt.ask("[bold yellow]╰─>[/bold yellow]", default="99").strip()
    try:
        choice = int(raw)
        if 1 <= choice <= len(archived):
            _run_module(archived[choice - 1])
    except ValueError:
        pass


# ── Scan history viewer ────────────────────────────────────────────────────────

def _show_scan_history() -> None:
    """Display recent scan history from ~/.osint-tool/history.jsonl."""
    from modules.utils import read_scan_history
    records = read_scan_history(limit=30)

    console.clear()
    console.rule("[bold cyan]Recent Scan History[/bold cyan]", style="bright_blue")

    if not records:
        console.print("[dim]No scan history yet. Run a module to start logging.[/dim]\n")
        Prompt.ask("[dim]Press Enter to return[/dim]", default="")
        return

    table = Table(box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Time",   style="dim white",  width=20)
    table.add_column("Module", style="bold yellow", min_width=22)
    table.add_column("Target", style="cyan")
    table.add_column("Status", style="green",      width=10)

    for r in records:
        status_style = "green" if r.get("status") == "ok" else "yellow"
        table.add_row(
            r.get("ts", ""),
            r.get("module", ""),
            r.get("target", ""),
            f"[{status_style}]{r.get('status', '')}[/{status_style}]",
        )

    console.print(table)
    Prompt.ask("\n[dim]Press Enter to return[/dim]", default="")


# ── Config viewer ─────────────────────────────────────────────────────────────

def _show_config_menu() -> None:
    import config as cfg_module

    while True:
        cfg = cfg_module.load()
        console.clear()
        console.rule("[bold magenta]⚙  Configuration[/bold magenta]", style="bright_blue")

        table = Table(box=box.SIMPLE_HEAD, show_lines=True)
        table.add_column("Key", style="bold cyan")
        table.add_column("Value", style="white")
        for k, v in cfg.items():
            table.add_row(k, str(v))
        console.print(table)

        console.print(
            "\n  [bold cyan]s key value[/bold cyan]  set a config value"
            "  [bold cyan]99[/bold cyan]  back\n"
        )
        raw = Prompt.ask("[bold cyan]╰─>[/bold cyan]", default="99").strip()

        if raw in ("99", "q", "back", ""):
            return
        if raw.startswith("s "):
            parts = raw[2:].split(" ", 1)
            if len(parts) == 2:
                key, val = parts
                cfg_module.set_value(key, val)
                console.print(f"[{THEME_SUCCESS}]✔ Set {key} = {val}[/{THEME_SUCCESS}]")
                Prompt.ask("[dim]Press Enter[/dim]", default="")
            else:
                console.print(f"[{THEME_ERROR}]Usage: s key value[/{THEME_ERROR}]")
                Prompt.ask("[dim]Press Enter[/dim]", default="")


# ── Module sub-menu ────────────────────────────────────────────────────────────

def _run_module(module: OsintModule) -> None:
    """Show module info then run, catching Ctrl+C."""
    console.clear()
    try:
        module.run()
    except KeyboardInterrupt:
        console.print(f"\n[{THEME_WARNING}]⚠ Cancelled.[/{THEME_WARNING}]")
    Prompt.ask("\n[dim]Press Enter to return to menu[/dim]", default="")


# ── Main TUI menu ─────────────────────────────────────────────────────────────

def run_tui() -> None:
    """Entry point for the interactive TUI menu."""

    while True:
        console.clear()
        console.print(_build_header())

        active_modules  = [m for m in ALL_MODULES if not m.ARCHIVED]
        archived_modules = [m for m in ALL_MODULES if m.ARCHIVED]

        _print_main_menu(active_modules, archived_modules)

        console.print(
            "\n  [dim cyan]/keyword[/dim cyan][dim] search  "
            "[/dim][dim cyan]t tag[/dim cyan][dim] filter  "
            "[/dim][dim cyan]95[/dim cyan][dim] archived  "
            "[/dim][dim cyan]97[/dim cyan][dim] install deps  "
            "[/dim][dim cyan]98[/dim cyan][dim] ext tools  "
            "[/dim][dim cyan]cfg[/dim cyan][dim] config  "
            "[/dim][dim cyan]log[/dim cyan][dim] history  "
            "[/dim][dim cyan]?[/dim cyan][dim] help  "
            "[/dim][dim cyan]q[/dim cyan][dim]uit[/dim]"
        )

        raw = Prompt.ask("[bold cyan]╰─>[/bold cyan]", default="").strip()
        if not raw:
            continue

        # ── Global commands ────────────────────────────────────────────────────
        if raw.lower() in ("q", "quit", "exit"):
            console.print("\n[dim]Goodbye! Stay legal.[/dim]\n")
            raise SystemExit(0)

        if raw in ("?", "help"):
            _show_inline_help()
            continue

        if raw.lower() == "cfg":
            _show_config_menu()
            continue

        if raw.lower() == "log":
            _show_scan_history()
            continue

        # Search
        if raw.startswith("/"):
            query = raw[1:].strip()
            if query:
                results = _search_modules(query, active_modules)
                _handle_filtered_results(results, f'Search: "{query}"')
            continue

        # Tag filter
        if raw.lower().startswith("t "):
            tag = raw[2:].strip()
            if tag:
                results = _filter_by_tag(tag, active_modules)
                _handle_filtered_results(results, f"Tag: #{tag}")
            continue

        # Numeric selections
        try:
            choice = int(raw)
        except ValueError:
            console.print(f"[{THEME_ERROR}]⚠ Enter a number, /search, t tag, ? help, or q quit.[/{THEME_ERROR}]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")
            continue

        if choice == 99:
            console.print("\n[dim]Goodbye! Stay legal.[/dim]\n")
            raise SystemExit(0)

        if choice == 98:
            from modules.external_tools import show_external_tools_menu
            show_external_tools_menu()
            continue

        if choice == 97:
            _install_all_missing_deps()
            continue

        if choice == 95 and archived_modules:
            _show_archived_menu(archived_modules)
            continue

        if 1 <= choice <= len(active_modules):
            _run_module(active_modules[choice - 1])
        else:
            console.print(f"[{THEME_ERROR}]⚠ Invalid option.[/{THEME_ERROR}]")
            Prompt.ask("[dim]Press Enter[/dim]", default="")


# ── Menu renderer ──────────────────────────────────────────────────────────────

def _print_main_menu(modules: list[OsintModule], archived: list[OsintModule] | None = None) -> None:
    """Render the 2-column module grid."""

    import platform
    current_os = platform.system().lower()

    rows: list[tuple] = []
    for i, m in enumerate(modules, start=1):
        status = "[green]✔[/green]" if m.is_available else "[red]✘[/red]"
        note = ""
        if m.SUPPORTED_OS and current_os not in m.SUPPORTED_OS:
            note = " [dim yellow][OS][/dim yellow]"
        label = f"[bold cyan]{i:>2}[/bold cyan] {status} {m.ICON} [yellow]{m.TITLE}[/yellow]{note}"
        rows.append(label)

    pairs: list[tuple[str, str]] = []
    for i in range(0, len(rows), 2):
        left = rows[i]
        right = rows[i + 1] if i + 1 < len(rows) else ""
        pairs.append((left, right))

    table = Table(
        box=box.SIMPLE_HEAD,
        show_header=False,
        show_lines=False,
        padding=(0, 2),
        expand=True,
    )
    table.add_column("col1", ratio=1)
    table.add_column("col2", ratio=1)

    for left, right in pairs:
        table.add_row(left, right)

    # Footer rows
    table.add_row("", "")
    table.add_row(
        "[bold green] 97[/bold green]  [dim]Install missing optional deps[/dim]",
        "[bold magenta] 98[/bold magenta]  [dim]External Tools Manager[/dim]",
    )
    if archived:
        table.add_row(
            f"[dim yellow] 95[/dim yellow]  [dim]Archived modules ({len(archived)})[/dim]",
            " [dim cyan]log[/dim cyan]  [dim]Scan history[/dim]",
        )
    table.add_row(
        " [dim cyan]cfg[/dim cyan]  [dim]View / edit config[/dim]",
        "  [dim cyan]99[/dim cyan]  [dim]Quit[/dim]",
    )

    console.print(Panel(
        table,
        title="[bold magenta]Select a module[/bold magenta]",
        border_style="bright_blue",
        box=box.ROUNDED,
        padding=(0, 1),
    ))


# ── Filtered results menu ──────────────────────────────────────────────────────

def _handle_filtered_results(results: list[OsintModule], title: str) -> None:
    """Show a filtered list and let the user pick one."""
    if not results:
        console.print(f"[{THEME_WARNING}]⚠ No modules found for '{title}'.[/{THEME_WARNING}]")
        Prompt.ask("[dim]Press Enter[/dim]", default="")
        return

    console.clear()
    console.rule(f"[bold cyan]{title}[/bold cyan]", style="bright_blue")

    table = Table(box=box.SIMPLE_HEAD, show_lines=True)
    table.add_column("No.", justify="center", style="bold cyan", width=5)
    table.add_column("", width=2)
    table.add_column("Module", style="bold yellow", min_width=20)
    table.add_column("Tags", style="dim white")

    for i, m in enumerate(results, start=1):
        status = "[green]✔[/green]" if m.is_available else "[red]✘[/red]"
        tags = "  ".join(f"#{t}" for t in m.TAGS)
        table.add_row(str(i), status, f"{m.ICON} {m.TITLE}", tags)

    table.add_row("99", "", "Back", "")
    console.print(table)

    raw = Prompt.ask("[bold cyan]╰─>[/bold cyan]", default="99").strip()
    if raw in ("99", "q", "back", ""):
        return

    try:
        choice = int(raw)
    except ValueError:
        return

    if 1 <= choice <= len(results):
        _run_module(results[choice - 1])


# ── Install all missing optional deps ─────────────────────────────────────────

def _install_all_missing_deps() -> None:
    """Collect and install all missing optional dependencies across all modules."""
    import shutil, os

    all_missing: list[str] = []
    for m in ALL_MODULES:
        for dep in m.missing_deps:
            if dep not in all_missing:
                all_missing.append(dep)

    if not all_missing:
        console.print(f"[{THEME_SUCCESS}]✔ All optional dependencies are already installed![/{THEME_SUCCESS}]")
        Prompt.ask("[dim]Press Enter[/dim]", default="")
        return

    from modules.constants import OPTIONAL_TOOLS
    console.print(Panel(
        f"[bold]Installing {len(all_missing)} missing optional deps...[/bold]\n"
        + "  ".join(f"[yellow]{d}[/yellow]" for d in all_missing),
        border_style="green", box=box.ROUNDED,
    ))

    for i, dep in enumerate(all_missing, start=1):
        console.print(f"\n[bold cyan]({i}/{len(all_missing)})[/bold cyan] {dep}")
        if dep in OPTIONAL_TOOLS:
            cmd = OPTIONAL_TOOLS[dep]["install"]
        else:
            cmd = f"pip install {dep}"
        console.print(f"[dim]→ {cmd}[/dim]")
        os.system(cmd)

    console.print(f"\n[{THEME_SUCCESS}]✔ Done![/{THEME_SUCCESS}]")
    Prompt.ask("[dim]Press Enter to return[/dim]", default="")
