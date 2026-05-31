"""
AI-powered OSINT summary generator using the Claude API (Anthropic).

Produces a structured intelligence brief from raw OSINT scan data.
Requires: pip install anthropic
Set ANTHROPIC_API_KEY in .env
"""
from __future__ import annotations
import os
import json
import logging
from typing import Any

logger = logging.getLogger("osint.ai_summary")


def _prepare_context(target: str, all_data: dict, max_chars: int = 12000) -> str:
    """Flatten scan data into a compact text representation for the LLM."""
    lines = [f"TARGET: {target}", "=" * 40]

    def add_section(name: str, data: Any, depth: int = 0):
        if depth > 3:
            return
        indent = "  " * depth
        if isinstance(data, dict):
            lines.append(f"{indent}[{name.upper()}]")
            for k, v in list(data.items())[:20]:
                if isinstance(v, (dict, list)):
                    add_section(k, v, depth + 1)
                elif v and str(v) not in ("None", "[]", "{}"):
                    lines.append(f"{indent}  {k}: {str(v)[:120]}")
        elif isinstance(data, list):
            items = data[:10]
            if items:
                lines.append(f"{indent}[{name.upper()}] ({len(data)} items)")
                for item in items:
                    if isinstance(item, dict):
                        brief = {k: v for k, v in list(item.items())[:5]
                                 if v and not isinstance(v, (dict, list))}
                        lines.append(f"{indent}  - {brief}")
                    else:
                        lines.append(f"{indent}  - {str(item)[:80]}")

    for section, data in all_data.items():
        add_section(section, data)
        if sum(len(l) for l in lines) > max_chars:
            lines.append("... [truncated for length]")
            break

    return "\n".join(lines)


SYSTEM_PROMPT = """You are an expert OSINT analyst. Your job is to analyze collected intelligence data and produce a structured, factual threat/risk assessment brief.

Format your response as a structured report with these sections:
1. **Executive Summary** (2-3 sentences: what was found, overall risk)
2. **Key Findings** (bullet list of the most significant discoveries)
3. **Risk Assessment** (LOW/MEDIUM/HIGH/CRITICAL with justification)
4. **Identity Footprint** (linked accounts, email exposure, username presence)
5. **Technical Exposure** (open ports, CVEs, SSL issues, cloud exposure)
6. **Recommendations** (3-5 actionable next steps for investigators)

Be concise, factual, and professional. Do not speculate beyond the data provided. If data is missing, note it as "No data available."
"""


def generate_ai_summary(
    target: str,
    all_data: dict,
    api_key: str | None = None,
    model: str = "claude-sonnet-4-6",
) -> dict:
    """
    Generate an AI-powered intelligence brief using Claude.

    Args:
        target: The scan target (domain, email, username, etc.)
        all_data: Combined scan results from OSINT modules
        api_key: Anthropic API key (or reads ANTHROPIC_API_KEY from env)
        model: Claude model to use

    Returns:
        dict with 'summary' (str), 'model', 'tokens_used', 'error' (if any)
    """
    api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return {
            "summary": None,
            "error": "No Anthropic API key. Set ANTHROPIC_API_KEY in .env",
            "model": model,
        }

    try:
        import anthropic
    except ImportError:
        return {
            "summary": None,
            "error": "anthropic package not installed. Run: pip install anthropic",
            "model": model,
        }

    context = _prepare_context(target, all_data)
    user_message = f"Analyze the following OSINT scan data and produce an intelligence brief:\n\n{context}"

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            max_tokens=2048,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
        )
        summary_text = response.content[0].text if response.content else ""
        return {
            "summary": summary_text,
            "model": model,
            "tokens_used": {
                "input": response.usage.input_tokens,
                "output": response.usage.output_tokens,
            },
            "error": None,
        }
    except Exception as exc:
        logger.error("AI summary failed: %s", exc)
        return {
            "summary": None,
            "error": str(exc),
            "model": model,
        }


def print_ai_summary(summary_result: dict) -> None:
    """Print the AI summary to the terminal using Rich."""
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel

    console = Console()

    if summary_result.get("error"):
        console.print(f"[bold red]AI Summary Error:[/bold red] {summary_result['error']}")
        return

    summary = summary_result.get("summary", "")
    if not summary:
        console.print("[yellow]No AI summary generated.[/yellow]")
        return

    tokens = summary_result.get("tokens_used", {})
    footer = (
        f"[dim]Model: {summary_result.get('model', '?')} | "
        f"Tokens: {tokens.get('input', 0)} in / {tokens.get('output', 0)} out[/dim]"
    )

    console.print(Panel(
        Markdown(summary),
        title="[bold cyan]🤖 AI Intelligence Brief[/bold cyan]",
        subtitle=footer,
        border_style="cyan",
        padding=(1, 2),
    ))
