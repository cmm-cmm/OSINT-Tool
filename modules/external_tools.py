"""
External Tools Manager for OSINT Tool TUI.

Wraps optional external binaries (holehe, maigret, theHarvester, amass,
subfinder, trufflehog, gitleaks, instaloader) with install / update / run
actions that integrate seamlessly into the interactive menu.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from modules.constants import (
    OPTIONAL_TOOLS,
    THEME_SUCCESS, THEME_WARNING, THEME_ERROR, THEME_DIM,
    _IS_WINDOWS, _HAS_GO, _go_install_note,
)

console = Console()


@dataclass
class ExternalTool:
    """Represents one optional external tool with install/update/run capability."""

    name: str
    description: str
    install_cmd: str
    install_win: str
    binary: str
    py_module: str | None
    requires_go: bool
    run_args: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    # ── Status ─────────────────────────────────────────────────────────────────

    @property
    def is_installed(self) -> bool:
        """True if the binary is locatable or the Python module is importable."""
        # 1. shutil.which covers system PATH + activated venv Scripts
        if shutil.which(self.binary):
            return True
        # 2. On Windows also check the active venv Scripts directory directly,
        #    because venv may not be fully activated in every shell context.
        if _IS_WINDOWS:
            scripts_dir = Path(sys.prefix) / "Scripts"
            for ext in ("", ".exe", ".cmd"):
                if (scripts_dir / f"{self.binary}{ext}").exists():
                    return True
        # 3. Python-package import check (for pip-based tools only)
        if self.py_module:
            try:
                __import__(self.py_module)
                return True
            except ImportError:
                pass
        return False

    @property
    def _effective_install_cmd(self) -> str:
        """Return the right install command for the current platform."""
        return self.install_win if _IS_WINDOWS else self.install_cmd

    # ── Actions ────────────────────────────────────────────────────────────────

    def install(self) -> None:
        if self.is_installed:
            console.print(
                f"[{THEME_WARNING}]⚠ {self.name} is already installed.[/{THEME_WARNING}]"
            )
            return

        # Go tools on a machine without Go → explain and bail out
        if self.requires_go and not _HAS_GO:
            console.print(
                f"\n[{THEME_WARNING}]⚠  {self.name} requires the Go runtime, "
                f"which is not installed.[/{THEME_WARNING}]\n"
                f"  Install Go first:\n"
                f"    [bold cyan]{_go_install_note()}[/bold cyan]\n"
                f"  Then restart the tool and try again.\n"
                f"  [dim]Or download a pre-built Windows binary:[/dim]\n"
                f"  [underline bright_blue]{self.install_win}[/underline bright_blue]\n"
            )
            return

        # theHarvester has a stub 0.0.1 on PyPI — warn the user up front
        if self.name == "theHarvester":
            console.print(
                f"[{THEME_WARNING}]ℹ  Installing from GitHub (the PyPI package is a stub).[/{THEME_WARNING}]"
            )

        cmd = self._effective_install_cmd
        console.print(f"[cyan]→ {cmd}[/cyan]")
        ret = os.system(cmd)
        if self.is_installed:
            console.print(f"[{THEME_SUCCESS}]✔ {self.name} installed successfully.[/{THEME_SUCCESS}]")
        else:
            console.print(
                f"[{THEME_ERROR}]✘ Installation may have failed — "
                f"'{self.binary}' not found on PATH.[/{THEME_ERROR}]"
            )
            if ret != 0:
                console.print(
                    f"  [dim]Try manually:[/dim] [bold]{cmd}[/bold]"
                )

    def update(self) -> None:
        if not self.is_installed:
            console.print(f"[{THEME_WARNING}]⚠ Install {self.name} first.[/{THEME_WARNING}]")
            return
        cmd = self._effective_install_cmd
        if cmd.startswith("pip install"):
            cmd = cmd.replace("pip install", "pip install --upgrade")
        console.print(f"[cyan]→ {cmd}[/cyan]")
        os.system(cmd)
        console.print(f"[{THEME_SUCCESS}]✔ Update complete.[/{THEME_SUCCESS}]")

    def run(self) -> None:
        if not self.is_installed:
            console.print(
                f"[{THEME_WARNING}]⚠ {self.name} is not installed. "
                f"Select 'Install' first.[/{THEME_WARNING}]"
            )
            return

        # Resolve binary — prefer venv Scripts on Windows
        binary = self.binary
        if _IS_WINDOWS:
            scripts_dir = Path(sys.prefix) / "Scripts"
            for ext in (".exe", ".cmd", ""):
                candidate = scripts_dir / f"{self.binary}{ext}"
                if candidate.exists():
                    binary = str(candidate)
                    break

        if self.run_args:
            extra = Prompt.ask(
                f"[bold cyan]Args for {self.binary}[/bold cyan] "
                f"(defaults: [dim]{' '.join(self.run_args)}[/dim])",
                default=" ".join(self.run_args),
            )
            cmd = [binary] + extra.split()
        else:
            target = Prompt.ask(f"[bold cyan]{self.name} target / args[/bold cyan]").strip()
            if not target:
                return
            cmd = [binary] + target.split()

        console.print(f"[cyan]⚙ Running:[/cyan] [bold]{' '.join(cmd)}[/bold]\n")
        try:
            subprocess.run(cmd, check=False)
        except FileNotFoundError:
            console.print(f"[{THEME_ERROR}]✘ Binary not found: {binary}[/{THEME_ERROR}]")

    def show_options_menu(self) -> None:
        """Interactive sub-menu: Install / Update / Run / Back."""
        while True:
            status = "[green]✔ installed[/green]" if self.is_installed else "[red]✘ not installed[/red]"

            # Build info text
            if self.requires_go and not _HAS_GO:
                install_note = (
                    f"[bold yellow]⚠ Requires Go runtime[/bold yellow]\n"
                    f"  Install Go: [bold cyan]{_go_install_note()}[/bold cyan]\n"
                    f"  Or download binary: [underline bright_blue]{self.install_win}[/underline bright_blue]"
                )
            else:
                install_note = f"[bright_black]{self._effective_install_cmd}[/bright_black]"

            console.print(Panel(
                Text.assemble(
                    (f"{self.description}\n\n", "cyan"),
                    ("Status:  ", "dim"), (status + "\n"),
                    ("Install: ", "dim"),
                ),
                title=f"[bold magenta]{self.name}[/bold magenta]",
                border_style="bright_blue",
                box=box.ROUNDED,
                padding=(1, 2),
                subtitle=install_note,
                subtitle_align="left",
            ))

            table = Table(box=box.SIMPLE_HEAVY)
            table.add_column("No.", style="bold cyan", justify="center")
            table.add_column("Action", style="bold yellow")
            table.add_row("1", "Install")
            table.add_row("2", "Update")
            table.add_row("3", "Run")
            table.add_row("99", "Back")
            console.print(table)

            raw = Prompt.ask("[bold cyan]╰─>[/bold cyan]", default="99").strip()

            if raw == "1":
                self.install()
                Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
            elif raw == "2":
                self.update()
                Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
            elif raw == "3":
                self.run()
                Prompt.ask("[dim]Press Enter to continue[/dim]", default="")
            elif raw in ("99", "q", "back"):
                return
            elif raw in ("quit", "exit"):
                raise SystemExit(0)


# ── Tool registry ──────────────────────────────────────────────────────────────

def _build_tools() -> list[ExternalTool]:
    tools = []
    for name, meta in OPTIONAL_TOOLS.items():
        run_args: list[str] = []
        if name == "holehe":
            run_args = ["--help"]
        elif name == "maigret":
            run_args = ["--help"]
        elif name == "theHarvester":
            run_args = ["-h"]
        elif name == "amass":
            run_args = ["enum", "-h"]
        elif name == "subfinder":
            run_args = ["-h"]
        elif name == "trufflehog":
            run_args = ["--help"]
        elif name == "gitleaks":
            run_args = ["--help"]
        elif name == "instaloader":
            run_args = ["--help"]

        tools.append(ExternalTool(
            name=name,
            description=meta["description"],
            install_cmd=meta["install"],
            install_win=meta.get("install_win", meta["install"]),
            binary=meta["binary"],
            py_module=meta.get("py_module"),
            requires_go=meta.get("requires_go", False),
            run_args=run_args,
        ))
    return tools


ALL_EXTERNAL_TOOLS: list[ExternalTool] = _build_tools()


# ── Collection menu ────────────────────────────────────────────────────────────

def show_external_tools_menu() -> None:
    """Display the interactive External Tools management menu."""

    while True:
        console.clear()
        console.rule("[bold magenta]🛠  External Tools Manager[/bold magenta]", style="bright_blue")
        console.print(
            "[dim italic]Manage optional OSINT binaries — install, update, and run.[/dim italic]\n"
        )

        tools = ALL_EXTERNAL_TOOLS
        not_installed = [t for t in tools if not t.is_installed]

        table = Table(
            title="Optional Tools",
            box=box.SIMPLE_HEAD,
            show_lines=True,
        )
        table.add_column("No.", justify="center", style="bold cyan", width=5)
        table.add_column("", width=2)
        table.add_column("Tool", style="bold yellow", min_width=16)
        table.add_column("Description", style="white", overflow="fold")

        for i, tool in enumerate(tools, start=1):
            if tool.is_installed:
                status = "[green]✔[/green]"
            elif tool.requires_go and not _HAS_GO:
                status = "[yellow]⚙[/yellow]"  # needs Go
            else:
                status = "[red]✘[/red]"
            table.add_row(str(i), status, tool.name, tool.description)

        # Only installable tools are those not requiring Go (or Go is available)
        installable = [t for t in tools if not t.is_installed and not (t.requires_go and not _HAS_GO)]
        go_blocked  = [t for t in tools if not t.is_installed and t.requires_go and not _HAS_GO]

        if installable:
            table.add_row(
                "[bold green]97[/bold green]", "",
                f"[bold green]Install all ({len(installable)} installable)[/bold green]", "",
            )
        if go_blocked:
            table.add_row(
                "[bold yellow]96[/bold yellow]", "",
                f"[bold yellow]Go install guide ({len(go_blocked)} need Go)[/bold yellow]", "",
            )
        table.add_row("99", "", "Back to Main Menu", "")
        console.print(table)
        console.print(
            "  [dim cyan]?[/dim cyan][dim] help  "
            "[/dim][dim cyan]q[/dim cyan][dim]uit  "
            "[/dim][dim cyan]99[/dim cyan][dim] back[/dim]"
        )

        raw = Prompt.ask("[bold cyan]╰─>[/bold cyan]", default="").strip().lower()
        if not raw:
            continue
        if raw in ("?", "help"):
            _show_ext_help()
            continue
        if raw in ("q", "quit", "exit"):
            raise SystemExit(0)
        if raw == "99":
            return

        if raw == "96" and go_blocked:
            _show_go_install_guide(go_blocked)
            continue

        if raw == "97" and installable:
            console.print(Panel(
                f"[bold]Installing {len(installable)} tools...[/bold]",
                border_style="green", box=box.ROUNDED,
            ))
            for i, tool in enumerate(installable, start=1):
                console.print(f"\n[bold cyan]({i}/{len(installable)})[/bold cyan] {tool.name}")
                try:
                    tool.install()
                except Exception as exc:
                    console.print(f"[{THEME_ERROR}]✘ Failed: {exc}[/{THEME_ERROR}]")
            Prompt.ask("\n[dim]Press Enter to continue[/dim]", default="")
            continue

        try:
            choice = int(raw)
        except ValueError:
            console.print(f"[{THEME_ERROR}]⚠ Enter a number.[/{THEME_ERROR}]")
            continue

        if 1 <= choice <= len(tools):
            tools[choice - 1].show_options_menu()
        else:
            console.print(f"[{THEME_ERROR}]⚠ Invalid option.[/{THEME_ERROR}]")


def _show_go_install_guide(go_tools: list[ExternalTool]) -> None:
    """Show a step-by-step guide to install Go and then the blocked tools."""
    tool_names = ", ".join(t.name for t in go_tools)
    lines = Text()
    lines.append("  The following tools require the Go runtime:\n", style="bold white")
    lines.append(f"  {tool_names}\n\n", style="cyan")
    lines.append("  Step 1 — Install Go on Windows:\n", style="bold white")
    lines.append(f"    {_go_install_note()}\n\n", style="bold cyan")
    lines.append("  Step 2 — Restart your terminal, then run OSINT Tool again.\n\n", style="white")
    lines.append("  Step 3 — Come back here and press 97 to install Go tools.\n\n", style="white")
    lines.append("  Alternatively, download pre-built Windows binaries:\n", style="dim white")
    for t in go_tools:
        lines.append(f"    {t.name}: ", style="bold yellow")
        lines.append(f"{t.install_win}\n", style="underline bright_blue")
    console.print(Panel(
        lines,
        title="[bold yellow]⚙  Go Tools Install Guide[/bold yellow]",
        border_style="yellow",
        box=box.ROUNDED,
        padding=(1, 2),
    ))
    Prompt.ask("[dim]Press Enter to return[/dim]", default="")


def _show_ext_help() -> None:
    console.print(Panel(
        Text.assemble(
            ("  External Tools Menu\n", "bold white"),
            ("  ──────────────────────────────────\n", "dim"),
            ("  1–N  ", "bold cyan"), ("select a tool\n", "white"),
            ("  97   ", "bold cyan"), ("install all not-installed tools\n", "white"),
            ("  99   ", "bold cyan"), ("back to main menu\n", "white"),
            ("  ?    ", "bold cyan"), ("show this help\n", "white"),
            ("  q    ", "bold cyan"), ("quit\n", "white"),
            ("\n  Inside a tool\n", "bold white"),
            ("  ──────────────────────────────────\n", "dim"),
            ("  1    ", "bold cyan"), ("install\n", "white"),
            ("  2    ", "bold cyan"), ("update\n", "white"),
            ("  3    ", "bold cyan"), ("run\n", "white"),
            ("  99   ", "bold cyan"), ("back\n", "white"),
        ),
        title="[bold magenta] ? Quick Help [/bold magenta]",
        border_style="magenta",
        box=box.ROUNDED,
        padding=(0, 2),
    ))
    Prompt.ask("[dim]Press Enter to return[/dim]", default="")
