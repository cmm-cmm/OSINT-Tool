"""
Google Dorks Generator Module
Generates targeted search queries for finding public information.
All results are links to standard search engines - no automated scraping.
"""
import requests
from rich.console import Console
from rich.table import Table

console = Console(legacy_windows=False)


DORK_TEMPLATES = {
    "domain": [
        # Discovery
        ('Site index', 'site:{target}'),
        ('Subdomains', 'site:*.{target} -www'),
        ('Open directories', 'site:{target} intitle:"index of /"'),
        # Auth & Admin
        ('Login pages', 'site:{target} inurl:login OR inurl:admin OR inurl:signin'),
        ('Exposed admin panels', 'site:{target} inurl:admin OR inurl:administrator OR inurl:phpmyadmin OR inurl:wp-admin'),
        # Sensitive files
        ('Config/Env files', 'site:{target} ext:env OR ext:cfg OR ext:conf OR ext:ini'),
        ('Database files', 'site:{target} ext:sql OR ext:db OR ext:sqlite'),
        ('Log files', 'site:{target} ext:log'),
        ('Backup files', 'site:{target} ext:bak OR ext:backup OR ext:old'),
        ('YAML/JSON configs', 'site:{target} ext:yaml OR ext:yml OR ext:json -"package.json" -"manifest.json"'),
        ('Source maps', 'site:{target} ext:map "sourceMappingURL"'),
        # Documents
        ('PDF documents', 'site:{target} filetype:pdf'),
        ('Excel/CSV data', 'site:{target} filetype:xlsx OR filetype:csv'),
        ('Word docs', 'site:{target} filetype:doc OR filetype:docx'),
        # Code & APIs
        ('GitHub code', 'site:github.com "{target}"'),
        ('API endpoints', 'site:{target} inurl:api OR inurl:v1 OR inurl:v2'),
        ('Swagger / API docs', 'site:{target} inurl:swagger OR inurl:api-docs OR inurl:openapi'),
        ('GraphQL endpoint', 'site:{target} inurl:graphql'),
        # Infrastructure
        ('WordPress', 'site:{target} inurl:wp-content OR inurl:wp-admin'),
        ('Error pages', 'site:{target} "fatal error" OR "stack trace" OR "syntax error" OR "Warning: mysql"'),
        ('Server-status', 'site:{target} inurl:server-status OR inurl:server-info'),
        # People & contact
        ('Email addresses', 'site:{target} "@{target}"'),
        ('Phone numbers', 'site:{target} "phone" OR "tel:" OR "+84"'),
        ('LinkedIn employees', 'site:linkedin.com/in "{target}"'),
        # Threat intel
        ('Shodan indexing', 'site:shodan.io "{target}"'),
        ('Pastebin mentions', 'site:pastebin.com "{target}"'),
        ('GitHub secrets', 'site:github.com "{target}" password OR secret OR api_key OR token'),
        ('Wayback snapshots', 'site:web.archive.org/web/* {target}'),
        ('URLScan reports', 'site:urlscan.io "{target}"'),
        # Vietnamese-specific
        ('VNPT domain info', '"{target}" site:vnnic.vn OR site:whois.vn'),
    ],
    "person": [
        ('Exact name', '"{target}"'),
        ('Social profiles', '"{target}" site:linkedin.com OR site:twitter.com OR site:facebook.com'),
        ('Vietnamese social', '"{target}" site:facebook.com OR site:zalo.me OR site:tiktok.com'),
        ('Email pattern', '"{target}" "@gmail.com" OR "@yahoo.com" OR "@hotmail.com" OR "@outlook.com"'),
        ('Professional', '"{target}" CV OR resume OR portfolio OR "curriculum vitae"'),
        ('News VN', '"{target}" site:vnexpress.net OR site:tuoitre.vn OR site:dantri.com.vn OR site:thanhnien.vn'),
        ('News EN', '"{target}" site:reuters.com OR site:bloomberg.com OR site:ft.com'),
        ('Publications', '"{target}" filetype:pdf'),
        ('GitHub', 'site:github.com "{target}"'),
        ('Phone association', '"{target}" phone OR "số điện thoại" OR mobile OR "di động"'),
        ('Address association', '"{target}" address OR "địa chỉ" OR "quận" OR "phường"'),
        ('Company association', '"{target}" company OR "công ty" OR organization OR employer'),
        ('Court / legal records', '"{target}" site:congbao.chinhphu.vn OR "bản án" OR verdict'),
        ('Business registry VN', '"{target}" site:dangkykinhdoanh.gov.vn OR site:masothue.com'),
    ],
    "organization": [
        ('Company info', '"{target}" "about us" OR "contact us" OR "giới thiệu"'),
        ('Employee list', 'site:linkedin.com/in "{target}"'),
        ('Financial reports', '"{target}" filetype:pdf "annual report" OR "báo cáo tài chính" OR "financial statement"'),
        ('Job postings', '"{target}" site:linkedin.com/jobs OR site:topcv.vn OR site:vietnamworks.com OR site:itviec.com'),
        ('News cafef', '"{target}" site:cafef.vn OR site:vietstock.vn OR site:tinnhanhchungkhoan.vn'),
        ('News VN', '"{target}" site:vnexpress.net OR site:tuoitre.vn OR site:nld.com.vn'),
        ('Business registry', '"{target}" site:dangkykinhdoanh.gov.vn OR site:masothue.com'),
        ('GitHub repos', 'site:github.com "{target}"'),
        ('Tech stack', 'site:{target} "powered by" OR "built with" OR "running on"'),
        ('Config files leaked', 'site:github.com "{target}" filename:.env OR filename:config.yml OR filename:docker-compose.yml'),
        ('Crunchbase', 'site:crunchbase.com "{target}"'),
        ('Court decisions', '"{target}" site:congbao.chinhphu.vn OR "bản án" OR "quyết định"'),
        ('Shodan infra', 'site:shodan.io "{target}"'),
    ],
    "email": [
        ('Exact email', '"{target}"'),
        ('Data leaks', '"{target}" "password" OR "leak" OR "breach" OR "dump"'),
        ('Paste sites', '"{target}" site:pastebin.com OR site:rentry.co OR site:hastebin.com OR site:ghostbin.com'),
        ('Social', '"{target}" site:twitter.com OR site:linkedin.com OR site:github.com OR site:facebook.com'),
        ('Forums', '"{target}" site:reddit.com OR site:stackoverflow.com OR site:forums.vn'),
        ('GitHub code leak', 'site:github.com "{target}"'),
        ('GrayhatWarfare', 'site:grayhatwarfare.com "{target}"'),
        ('Breach databases', '"{target}" site:haveibeenpwned.com OR site:dehashed.com'),
    ],
    "username": [
        ('Exact username', '"{target}"'),
        ('Social media', (
            f'"{"{target}"}" site:twitter.com OR site:instagram.com OR '
            'site:tiktok.com OR site:reddit.com OR site:github.com'
        ).replace('"{target}"', '"{target}"')),
        ('GitHub', 'site:github.com/{target}'),
        ('Paste sites', '"{target}" site:pastebin.com OR site:rentry.co'),
        ('Vietnamese forums', '"{target}" site:voz.vn OR site:spiderum.com OR site:webtretho.com'),
        ('Gaming', '"{target}" site:steam.com OR site:twitch.tv OR site:chess.com'),
    ],
    "ip": [
        ('Shodan', 'site:shodan.io "{target}"'),
        ('Censys', 'site:censys.io "{target}"'),
        ('GreyNoise', 'site:viz.greynoise.io "ip/{target}"'),
        ('AbuseIPDB', f'site:abuseipdb.com "check/{"{target}"}"'.replace('"{target}"', '{target}')),
        ('VirusTotal', 'site:virustotal.com "{target}"'),
        ('FOFA', 'site:fofa.info "{target}"'),
        ('URLScan', 'site:urlscan.io "{target}"'),
        ('Google scan', '"{target}" server OR "apache" OR "nginx" OR "port"'),
        ('Mentions', '"{target}" leak OR breach OR attack OR "ioc"'),
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
            "yandex_url": f"https://yandex.com/search/?text={encoded}",
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


# ---------------------------------------------------------------------------
# Live execution helpers
# ---------------------------------------------------------------------------

def execute_dorks_ddg(
    target: str,
    dork_type: str = "domain",
    max_dorks: int = 5,
    session=None,
) -> list[dict]:
    """Execute dork queries against DuckDuckGo's HTML endpoint.

    Uses the DuckDuckGo HTML interface (POST to https://html.duckduckgo.com/html/)
    and parses results with BeautifulSoup. No API key required.

    Parameters
    ----------
    target:
        The scan target string.
    dork_type:
        Key into DORK_TEMPLATES (e.g. "domain", "person").
    max_dorks:
        Maximum number of dork queries to execute.
    session:
        Optional ``requests.Session`` to reuse.  A new session is created if
        ``None``.

    Returns
    -------
    list[dict]
        Each element: ``{"dork": label, "query": query_str,
        "results": [{"title": ..., "url": ..., "snippet": ...}]}``.
    """
    import time

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        BeautifulSoup = None  # type: ignore[assignment,misc]

    dorks = generate_dorks(target, dork_type)[:max_dorks]
    output: list[dict] = []

    sess = session or requests.Session()
    sess.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        )
    })

    for dork in dorks:
        query = dork["query"]
        label = dork["label"]
        results: list[dict] = []

        try:
            resp = sess.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query},
                timeout=15,
            )
            resp.raise_for_status()

            if BeautifulSoup is not None:
                soup = BeautifulSoup(resp.text, "html.parser")
                for result in soup.select(".result"):
                    title_el = result.select_one(".result__title")
                    url_el = result.select_one(".result__url")
                    snippet_el = result.select_one(".result__snippet")

                    title = title_el.get_text(strip=True) if title_el else ""
                    url = url_el.get_text(strip=True) if url_el else ""
                    snippet = snippet_el.get_text(strip=True) if snippet_el else ""

                    if title or url:
                        # Normalise URL — DDG sometimes returns bare hostnames
                        if url and not url.startswith("http"):
                            url = "https://" + url
                        results.append({"title": title, "url": url, "snippet": snippet})
        except Exception:
            pass  # silently continue to next dork

        output.append({"dork": label, "query": query, "results": results})
        time.sleep(1)

    return output


def execute_dorks_serpapi(
    target: str,
    api_key: str,
    dork_type: str = "domain",
    max_dorks: int = 10,
) -> list[dict]:
    """Execute dork queries via SerpAPI (Google engine).

    Parameters
    ----------
    target:
        The scan target string.
    api_key:
        SerpAPI key.
    dork_type:
        Key into DORK_TEMPLATES.
    max_dorks:
        Maximum number of dork queries to execute.

    Returns
    -------
    list[dict]
        Same format as :func:`execute_dorks_ddg`:
        ``{"dork": label, "query": query_str,
        "results": [{"title": ..., "url": ..., "snippet": ...}]}``.
    """
    dorks = generate_dorks(target, dork_type)[:max_dorks]
    output: list[dict] = []

    for dork in dorks:
        query = dork["query"]
        label = dork["label"]
        results: list[dict] = []

        try:
            resp = requests.get(
                "https://serpapi.com/search",
                params={
                    "q": query,
                    "api_key": api_key,
                    "engine": "google",
                    "num": 10,
                },
                timeout=20,
            )

            if resp.status_code in (402, 403):
                # Quota exceeded or access denied — stop further requests
                output.append({"dork": label, "query": query, "results": results})
                break

            resp.raise_for_status()
            data = resp.json()

            for item in data.get("organic_results", []):
                title = item.get("title", "")
                url = item.get("link", "")
                snippet = item.get("snippet", "")
                if title or url:
                    results.append({"title": title, "url": url, "snippet": snippet})

        except Exception:
            pass  # silently continue to next dork

        output.append({"dork": label, "query": query, "results": results})

    return output


def print_dork_results(results: list[dict]) -> None:
    """Display dork execution results in a Rich table.

    Parameters
    ----------
    results:
        List returned by :func:`execute_dorks_ddg` or
        :func:`execute_dorks_serpapi`.
    """
    console.print("\n[bold cyan]═══ DORK EXECUTION RESULTS ═══[/bold cyan]")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Dork Name", style="cyan", width=22)
    table.add_column("Query", style="white", width=40)
    table.add_column("Results Count", style="green", width=14, justify="right")
    table.add_column("Top Result URL", style="blue")

    for item in results:
        dork_name = item.get("dork", "")
        query = item.get("query", "")
        item_results = item.get("results", [])
        count = str(len(item_results))
        top_url = item_results[0].get("url", "") if item_results else ""
        table.add_row(dork_name, query, count, top_url)

    console.print(table)
