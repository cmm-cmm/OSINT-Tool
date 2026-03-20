"""
Username Search Module
Checks username availability/existence on popular platforms
using public profile URLs (no scraping, no auth required).
"""
import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

PLATFORMS = {
    # International
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Twitter/X": "https://twitter.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Reddit": "https://www.reddit.com/user/{}/",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Tumblr": "https://{}.tumblr.com",
    "Medium": "https://medium.com/@{}",
    "DevTo": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "ProductHunt": "https://www.producthunt.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Keybase": "https://keybase.io/{}",
    "Pastebin": "https://pastebin.com/u/{}",
    "DockerHub": "https://hub.docker.com/u/{}",
    "PyPI": "https://pypi.org/user/{}/",
    "NPM": "https://www.npmjs.com/~{}",
    "Replit": "https://replit.com/@{}",
    "Codepen": "https://codepen.io/{}",
    "Bitbucket": "https://bitbucket.org/{}/",
    "Flickr": "https://www.flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "About.me": "https://about.me/{}",
    # Vietnam & regional
    "Shopee VN": "https://shopee.vn/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Coc Coc": "https://id.coccoc.com/{}",
    "TopCV": "https://www.topcv.vn/{}",
    "VietnamWorks": "https://www.vietnamworks.com/{}",
    "Freelancer VN": "https://www.freelancer.com/u/{}",
    "Spiderum": "https://spiderum.com/nguoi-dung/{}",
    "Voz": "https://voz.vn/u/{}/",
    "ITViec": "https://itviec.com/{}",
}

NOT_FOUND_INDICATORS = [
    "page not found",
    "user not found",
    "this page doesn't exist",
    "404",
    "does not exist",
    "no account found",
    "sorry, this page isn't available",
    "the page you requested cannot be found",
]

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}


async def check_platform(session: aiohttp.ClientSession, platform: str, url: str, username: str) -> dict:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
            if resp.status == 200:
                text = (await resp.text()).lower()
                for indicator in NOT_FOUND_INDICATORS:
                    if indicator in text:
                        return {"platform": platform, "url": url, "status": "not_found"}
                return {"platform": platform, "url": url, "status": "found"}
            elif resp.status == 404:
                return {"platform": platform, "url": url, "status": "not_found"}
            elif resp.status in (301, 302, 403):
                return {"platform": platform, "url": url, "status": "possible"}
            else:
                return {"platform": platform, "url": url, "status": "unknown", "code": resp.status}
    except asyncio.TimeoutError:
        return {"platform": platform, "url": url, "status": "timeout"}
    except Exception as e:
        return {"platform": platform, "url": url, "status": "error", "error": str(e)}


async def _search_all(username: str) -> list:
    results = []
    connector = aiohttp.TCPConnector(limit=20, ssl=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}[/cyan]/[bold]{task.total}[/bold]"),
        TimeElapsedColumn(),
        transient=True,
        console=console,
    ) as progress:
        task_id = progress.add_task("[cyan]Scanning platforms...", total=len(PLATFORMS))

        async with aiohttp.ClientSession(headers=HEADERS, connector=connector) as session:
            pending = [
                check_platform(session, platform, url.format(username), username)
                for platform, url in PLATFORMS.items()
            ]
            for coro in asyncio.as_completed(pending):
                result = await coro
                results.append(result)
                found_count = sum(1 for r in results if r["status"] == "found")
                progress.update(
                    task_id,
                    advance=1,
                    description=f"[cyan]Scanning... [green]Found: {found_count}[/green]",
                )

    return results


def username_search(username: str) -> dict:
    username = username.strip()
    results = asyncio.run(_search_all(username))
    found = [r for r in results if r["status"] == "found"]
    possible = [r for r in results if r["status"] == "possible"]
    not_found = [r for r in results if r["status"] == "not_found"]
    return {
        "username": username,
        "found": found,
        "possible": possible,
        "not_found": not_found,
        "total_checked": len(results),
    }


def print_username_results(data: dict):
    console.print(f"\n[bold cyan]═══ USERNAME SEARCH: @{data['username']} ═══[/bold cyan]")
    console.print(f"  Checked {data['total_checked']} platforms | "
                  f"[green]Found: {len(data['found'])}[/green] | "
                  f"[yellow]Possible: {len(data['possible'])}[/yellow] | "
                  f"[dim]Not found: {len(data['not_found'])}[/dim]")

    if data["found"]:
        table = Table(show_header=True, header_style="bold green", title="✓ Found Profiles")
        table.add_column("Platform", style="green", width=16)
        table.add_column("URL", style="cyan")
        for r in sorted(data["found"], key=lambda x: x["platform"]):
            table.add_row(r["platform"], r["url"])
        console.print(table)

    if data["possible"]:
        table = Table(show_header=True, header_style="bold yellow", title="? Possible Profiles")
        table.add_column("Platform", style="yellow", width=16)
        table.add_column("URL", style="white")
        for r in sorted(data["possible"], key=lambda x: x["platform"]):
            table.add_row(r["platform"], r["url"])
        console.print(table)
