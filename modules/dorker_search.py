"""
Amera-inspired Dork Executor

Executes dork queries via DuckDuckGo and returns live results.
Complements google_dorks.py (which only generates clickable URLs).

Modes:
  - file_search    : find exposed files on a domain by file type
  - email_harvest  : find email addresses exposed on a domain
  - phone_harvest  : find phone numbers on a domain
  - page_search    : find admin/login/backup/etc. pages on a domain
  - person_search  : OSINT on a person by name / surname / phone
  - custom_dork    : execute any raw dork query
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich import box

from modules.utils import RateLimiter

console = Console()

_rate_limiter = RateLimiter(calls=2, period=3.0)

FILE_TYPES_DEFAULT = [
    "pdf", "docx", "xls", "xlsx", "sql", "env", "log", "bak",
]

FILE_TYPES_ALL = [
    "pdf", "txt", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "htm", "html", "zip", "tar", "gz", "bz2", "mp4", "mp3",
    "jpg", "png", "flv", "sql", "env", "cfg", "conf", "log", "bak",
]

EMAIL_PROVIDERS = [
    "@gmail.com", "@hotmail.com", "@yahoo.com", "@yandex.com",
    "@zoho.com", "@gmx.com", "@aol.com", "@outlook.com",
]

PAGE_CATEGORIES_DEFAULT = [
    "admin", "login", "backup", "database", "security",
]

PAGE_CATEGORIES_ALL = [
    "blog", "security", "admin", "login", "database", "backup",
    "documents", "complaint", "hospital", "school", "airport", "railway",
]


# ── DDGS wrapper ───────────────────────────────────────────────────────────────

def _ddg_search(query: str, limit: int = 10) -> list[dict]:
    """Execute a DuckDuckGo text search and return result dicts."""
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        try:
            from ddgs import DDGS
        except ImportError:
            return []

    results: list[dict] = []
    with _rate_limiter:
        try:
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=limit):
                    results.append(r)
        except Exception:
            pass
    return results


# ── Core search functions ──────────────────────────────────────────────────────

def file_search(
    domain: str,
    filetypes: list[str] | None = None,
    limit_per_type: int = 5,
) -> dict:
    """Search for exposed files on a domain by file type.

    Args:
        domain: Target domain (e.g. 'example.com')
        filetypes: List of extensions to search. Defaults to common sensitive types.
        limit_per_type: Max results per file type.

    Returns:
        dict with keys: domain, filetypes_searched, results (dict[ext, list]), total
    """
    ft_list = filetypes if filetypes else FILE_TYPES_DEFAULT
    results: dict[str, list] = {}

    for ft in ft_list:
        query = f"site:{domain} filetype:{ft}"
        hits = _ddg_search(query, limit=limit_per_type)
        if hits:
            results[ft] = hits

    return {
        "domain": domain,
        "filetypes_searched": ft_list,
        "results": results,
        "total": sum(len(v) for v in results.values()),
    }


def email_harvest(domain: str, limit: int = 5) -> dict:
    """Find email addresses exposed on a domain.

    Args:
        domain: Target domain (e.g. 'example.com')
        limit: Max results per email provider.

    Returns:
        dict with keys: domain, results (list), total
    """
    all_results: list[dict] = []

    for provider in EMAIL_PROVIDERS:
        query = f'site:{domain} intext:"{provider}"'
        hits = _ddg_search(query, limit=limit)
        for h in hits:
            h["_provider"] = provider
            all_results.append(h)

    return {
        "domain": domain,
        "results": all_results,
        "total": len(all_results),
    }


def phone_harvest(domain: str, country_code: str = "+1", limit: int = 10) -> dict:
    """Find phone numbers on a domain by country code.

    Args:
        domain: Target domain (e.g. 'example.com')
        country_code: Country dialing code (e.g. '+84')
        limit: Max results.

    Returns:
        dict with keys: domain, country_code, results, total
    """
    query = f'site:{domain} intext:"{country_code}"'
    hits = _ddg_search(query, limit=limit)

    return {
        "domain": domain,
        "country_code": country_code,
        "results": hits,
        "total": len(hits),
    }


def page_search(
    domain: str,
    categories: list[str] | None = None,
    limit_per_cat: int = 5,
) -> dict:
    """Search for specific page categories on a domain.

    Args:
        domain: Target domain (e.g. 'example.com')
        categories: Page keywords to search. Defaults to admin/login/backup/database/security.
        limit_per_cat: Max results per category.

    Returns:
        dict with keys: domain, categories, results (dict[cat, list]), total
    """
    cat_list = categories if categories else PAGE_CATEGORIES_DEFAULT
    results: dict[str, list] = {}

    for cat in cat_list:
        query = f"site:{domain} intext:{cat}"
        hits = _ddg_search(query, limit=limit_per_cat)
        if hits:
            results[cat] = hits

    return {
        "domain": domain,
        "categories": cat_list,
        "results": results,
        "total": sum(len(v) for v in results.values()),
    }


def person_search(
    name: str,
    surname: str = "",
    phone: str = "",
    limit: int = 10,
) -> dict:
    """Search for a person using name, surname, phone, and social media.

    Args:
        name: First name (required)
        surname: Last name (optional)
        phone: Phone number or partial number (optional)
        limit: Max results per query.

    Returns:
        dict with keys: name, surname, phone, results (dict[source, list]), total
    """
    full_name = f"{name} {surname}".strip()

    queries: dict[str, str | None] = {
        "name_only": f'intext:"{name}"',
        "full_name": f'"{full_name}"' if surname else None,
        "phone": f'"{phone}"' if phone else None,
        "instagram": f'site:instagram.com intext:"{name}"',
        "facebook": f'site:facebook.com intext:"{name}"',
        "twitter": f'site:twitter.com intext:"{name}"',
        "linkedin": f'site:linkedin.com/in intext:"{full_name}"',
        "tiktok": f'site:tiktok.com intext:"{name}"',
    }

    results: dict[str, list] = {}
    for key, q in queries.items():
        if q is None:
            continue
        hits = _ddg_search(q, limit=limit)
        if hits:
            results[key] = hits

    return {
        "name": name,
        "surname": surname,
        "phone": phone,
        "results": results,
        "total": sum(len(v) for v in results.values()),
    }


def custom_dork(dork: str, limit: int = 10) -> dict:
    """Execute a raw dork query via DuckDuckGo.

    Args:
        dork: Any Google/DDG dork string.
        limit: Max results.

    Returns:
        dict with keys: dork, results, total
    """
    hits = _ddg_search(dork, limit=limit)
    return {
        "dork": dork,
        "results": hits,
        "total": len(hits),
    }


# ── Display functions ──────────────────────────────────────────────────────────

def _result_table(title: str, cols: list[tuple[str, str, int | None]]) -> Table:
    """Create a Rich table with standard styling."""
    table = Table(
        title=title,
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
    )
    for name, style, width in cols:
        if width:
            table.add_column(name, style=style, width=width)
        else:
            table.add_column(name, style=style)
    return table


def print_file_results(data: dict) -> None:
    domain = data["domain"]
    total = data["total"]
    console.print(f"\n[bold cyan]📁 File Discovery — {domain}[/bold cyan]")
    console.print(f"[dim]Types searched: {', '.join(data['filetypes_searched'])}[/dim]")

    if not total:
        console.print("[yellow]⚠ No exposed files found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    for ft, hits in data["results"].items():
        table = _result_table(
            f"[cyan].{ft}[/cyan] files ({len(hits)})",
            [("#", "dim", 3), ("Title", "white", None), ("URL", "blue", None)],
        )
        for i, h in enumerate(hits, 1):
            table.add_row(str(i), h.get("title", ""), h.get("href", ""))
        console.print(table)


def print_email_results(data: dict) -> None:
    domain = data["domain"]
    total = data["total"]
    console.print(f"\n[bold cyan]📧 Email Harvest — {domain}[/bold cyan]")

    if not total:
        console.print("[yellow]⚠ No emails found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    table = _result_table(
        "Email Results",
        [("#", "dim", 3), ("Provider", "cyan", 18), ("Title", "white", None), ("URL", "blue", None)],
    )
    for i, h in enumerate(data["results"], 1):
        table.add_row(str(i), h.get("_provider", ""), h.get("title", ""), h.get("href", ""))
    console.print(table)


def print_phone_results(data: dict) -> None:
    domain = data["domain"]
    code = data["country_code"]
    total = data["total"]
    console.print(f"\n[bold cyan]📞 Phone Numbers — {domain} (code: {code})[/bold cyan]")

    if not total:
        console.print("[yellow]⚠ No phone numbers found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    table = _result_table(
        "Phone Results",
        [("#", "dim", 3), ("Title", "white", None), ("URL", "blue", None)],
    )
    for i, h in enumerate(data["results"], 1):
        table.add_row(str(i), h.get("title", ""), h.get("href", ""))
    console.print(table)


def print_page_results(data: dict) -> None:
    domain = data["domain"]
    total = data["total"]
    console.print(f"\n[bold cyan]🗂 Page Discovery — {domain}[/bold cyan]")

    if not total:
        console.print("[yellow]⚠ No matching pages found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    for cat, hits in data["results"].items():
        table = _result_table(
            f"[cyan]{cat}[/cyan] ({len(hits)})",
            [("#", "dim", 3), ("Title", "white", None), ("URL", "blue", None)],
        )
        for i, h in enumerate(hits, 1):
            table.add_row(str(i), h.get("title", ""), h.get("href", ""))
        console.print(table)


def print_person_results(data: dict) -> None:
    name = data["name"]
    surname = data["surname"]
    full = f"{name} {surname}".strip()
    total = data["total"]
    console.print(f"\n[bold cyan]🧑 Person Search — {full}[/bold cyan]")

    if not total:
        console.print("[yellow]⚠ No results found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    for category, hits in data["results"].items():
        table = _result_table(
            f"[cyan]{category}[/cyan] ({len(hits)})",
            [("#", "dim", 3), ("Title", "white", None), ("URL", "blue", None)],
        )
        for i, h in enumerate(hits, 1):
            table.add_row(str(i), h.get("title", ""), h.get("href", ""))
        console.print(table)


def print_custom_dork_results(data: dict) -> None:
    total = data["total"]
    dork = data["dork"]
    console.print(f"\n[bold cyan]🔎 Custom Dork:[/bold cyan] [italic]{dork}[/italic]")

    if not total:
        console.print("[yellow]⚠ No results found.[/yellow]")
        return

    console.print(f"[green]✔ {total} result(s)[/green]\n")
    table = _result_table(
        "Dork Results",
        [("#", "dim", 3), ("Title", "white", None), ("URL", "blue", None), ("Snippet", "dim", None)],
    )
    for i, h in enumerate(data["results"], 1):
        table.add_row(str(i), h.get("title", ""), h.get("href", ""), h.get("body", "")[:80])
    console.print(table)
