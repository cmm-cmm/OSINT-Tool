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
