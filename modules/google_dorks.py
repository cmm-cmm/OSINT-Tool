"""
Google Dorks Generator Module
Generates targeted search queries for finding public information.
All results are links to standard search engines - no automated scraping.
"""
import requests
from rich.console import Console
from rich.table import Table

console = Console()


DORK_TEMPLATES = {
    "domain": [
        ('Site index', 'site:{target}'),
        ('Login pages', 'site:{target} inurl:login OR inurl:admin OR inurl:signin'),
        ('Config/Env files', 'site:{target} ext:env OR ext:cfg OR ext:conf OR ext:ini'),
        ('Database files', 'site:{target} ext:sql OR ext:db OR ext:sqlite'),
        ('Log files', 'site:{target} ext:log'),
        ('Backup files', 'site:{target} ext:bak OR ext:backup OR ext:old'),
        ('PDF documents', 'site:{target} filetype:pdf'),
        ('Excel/CSV data', 'site:{target} filetype:xlsx OR filetype:csv'),
        ('Subdomains', 'site:*.{target} -www'),
        ('Email addresses', 'site:{target} "@{target}"'),
        ('GitHub code', 'site:github.com "{target}"'),
        ('Pastebin mentions', 'site:pastebin.com "{target}"'),
        ('LinkedIn employees', 'site:linkedin.com/in "{target}"'),
        ('Shodan index', 'site:shodan.io "{target}"'),
        ('Error pages', 'site:{target} "fatal error" OR "stack trace" OR "syntax error"'),
        ('WordPress', 'site:{target} inurl:wp-content OR inurl:wp-admin'),
        ('Open directories', 'site:{target} intitle:"index of /"'),
        ('API endpoints', 'site:{target} inurl:api OR inurl:v1 OR inurl:v2'),
        ('Phone numbers', 'site:{target} "phone" OR "tel:" OR "+84"'),
        ('Wayback snapshots', 'site:web.archive.org/web/* {target}'),
    ],
    "person": [
        ('Exact name', '"{target}"'),
        ('Social profiles', '"{target}" site:linkedin.com OR site:twitter.com OR site:facebook.com'),
        ('Email pattern', '"{target}" "@gmail.com" OR "@yahoo.com" OR "@hotmail.com"'),
        ('Professional', '"{target}" CV OR resume OR portfolio'),
        ('News mentions', '"{target}" site:vnexpress.net OR site:tuoitre.vn OR site:dantri.com.vn'),
        ('Publications', '"{target}" filetype:pdf'),
        ('GitHub', 'site:github.com "{target}"'),
        ('Phone association', '"{target}" phone OR "số điện thoại" OR mobile'),
    ],
    "organization": [
        ('Company info', '"{target}" "about us" OR "contact us"'),
        ('Employee list', 'site:linkedin.com/in "{target}"'),
        ('Financial reports', '"{target}" filetype:pdf "annual report" OR "báo cáo"'),
        ('Job postings', '"{target}" site:linkedin.com/jobs OR site:topcv.vn OR site:vietnamworks.com'),
        ('News', '"{target}" site:cafef.vn OR site:vnexpress.net'),
        ('Business registry', '"{target}" site:dangkykinhdoanh.gov.vn OR site:masothue.com'),
        ('GitHub repos', 'site:github.com "{target}"'),
        ('Tech stack', 'site:{target} "powered by" OR "built with"'),
    ],
    "email": [
        ('Exact email', '"{target}"'),
        ('Data leaks', '"{target}" "password" OR "leak" OR "breach"'),
        ('Paste sites', '"{target}" site:pastebin.com OR site:rentry.co OR site:hastebin.com'),
        ('Social', '"{target}" site:twitter.com OR site:linkedin.com OR site:github.com'),
        ('Forums', '"{target}" site:reddit.com OR site:stackoverflow.com'),
    ],
}


def generate_dorks(target: str, dork_type: str = "domain") -> list:
    """Generate dork queries for a given target and type."""
    templates = DORK_TEMPLATES.get(dork_type, DORK_TEMPLATES["domain"])
    results = []
    for label, template in templates:
        query = template.replace("{target}", target)
        encoded = requests.utils.quote(query)
        results.append({
            "label": label,
            "query": query,
            "google_url": f"https://www.google.com/search?q={encoded}",
            "bing_url": f"https://www.bing.com/search?q={encoded}",
            "ddg_url": f"https://duckduckgo.com/?q={encoded}",
        })
    return results


def print_dorks(target: str, dork_type: str = "domain"):
    dorks = generate_dorks(target, dork_type)
    console.print(f"\n[bold cyan]═══ GOOGLE DORKS: {target} ({dork_type}) ═══[/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("#", style="dim", width=3)
    table.add_column("Category", style="cyan", width=22)
    table.add_column("Query", style="white")
    table.add_column("Links", style="blue")

    for i, d in enumerate(dorks, 1):
        links = f"[G] [link={d['google_url']}]Google[/link]  [B] [link={d['bing_url']}]Bing[/link]"
        table.add_row(str(i), d["label"], d["query"], links)

    console.print(table)
    return dorks
