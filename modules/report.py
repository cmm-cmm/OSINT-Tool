"""
Report Generator Module
Exports all gathered intelligence to HTML and JSON formats.
"""
import json
import csv
import io
import datetime
from pathlib import Path
from rich.console import Console

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OSINT Report - {target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', monospace; background: #0d1117; color: #e6edf3; padding: 24px; }}
        h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 20px; }}
        h2 {{ color: #79c0ff; margin: 24px 0 12px; font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; }}
        .meta {{ color: #8b949e; font-size: 0.85rem; margin-bottom: 24px; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
        th {{ background: #21262d; color: #79c0ff; padding: 8px 12px; text-align: left; }}
        td {{ padding: 6px 12px; border-bottom: 1px solid #21262d; }}
        tr:last-child td {{ border-bottom: none; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .found {{ color: #3fb950; }}
        .warning {{ color: #d29922; }}
        .danger {{ color: #f85149; }}
        .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem;
                background: #21262d; border: 1px solid #30363d; margin: 2px; }}
        pre {{ background: #21262d; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.8rem; color: #79c0ff; }}
        .disclaimer {{ background: #161b22; border: 1px solid #f85149; border-radius: 8px; padding: 12px 16px;
                       margin-bottom: 20px; font-size: 0.85rem; color: #f85149; }}
    </style>
</head>
<body>
    <h1>🔍 OSINT Intelligence Report</h1>
    <div class="meta">Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {timestamp} &nbsp;|&nbsp; Tool: OSINT-Tool v1.0</div>
    <div class="disclaimer">
        ⚠ <strong>DISCLAIMER:</strong> This report was generated using publicly available data sources only.
        All information was collected for legitimate security research / investigative purposes.
        Unauthorized use of this data may violate applicable laws.
    </div>
    {content}
</body>
</html>
"""


def _section(title: str, content: str) -> str:
    return f'<div class="section"><h2>{title}</h2>{content}</div>'


def _table(rows: list, headers: list = None) -> str:
    html = "<table>"
    if headers:
        html += "<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"
    for row in rows:
        html += "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
    html += "</table>"
    return html


def _kv_table(data: dict) -> str:
    rows = [(k, v) for k, v in data.items() if v]
    return _table(rows)


def build_html_report(target: str, all_data: dict) -> str:
    sections = []

    # Whois
    if "whois" in all_data:
        w = all_data["whois"].get("whois", {})
        if w:
            sections.append(_section("WHOIS Information", _kv_table(
                {k.replace("_", " ").title(): str(v) for k, v in w.items() if v and str(v) not in ("None", "[]")}
            )))

    # DNS
    if "dns" in all_data:
        records = all_data["dns"].get("records", {})
        if records:
            rows = [(rtype, "<br>".join(vals)) for rtype, vals in records.items()]
            sections.append(_section("DNS Records", _table(rows, ["Type", "Records"])))

    # IP / Geo
    if "ip" in all_data:
        geo = all_data["ip"].get("geo", {}).get("data", {})
        if geo:
            sections.append(_section("IP / Geolocation", _kv_table(
                {k.replace("_", " ").title(): str(v) for k, v in geo.items() if v}
            )))
        rev = all_data["ip"].get("reverse_ip", [])
        if rev:
            links = "".join(f'<span class="tag"><a href="http://{d}">{d}</a></span>' for d in rev[:20])
            sections.append(_section("Reverse IP Domains", links))

        # Security Headers Score
        sec = all_data["ip"].get("security_score", {})
        if sec:
            grade = sec.get("grade", "?")
            score = sec.get("score", 0)
            grade_color = {"A+": "#3fb950", "A": "#3fb950", "B": "#79c0ff",
                           "C": "#d29922", "D": "#f0883e", "F": "#f85149"}.get(grade, "#e6edf3")
            summary = f'<p>Score: <strong style="color:{grade_color}">{grade} ({score}/100)</strong></p>'
            if sec.get("present"):
                summary += "<p>" + " ".join(
                    f'<span class="tag found">✓ {p["label"]}</span>' for p in sec["present"]
                ) + "</p>"
            if sec.get("missing"):
                summary += "<p>" + " ".join(
                    f'<span class="tag warning">✗ {m["label"]}</span>' for m in sec["missing"]
                ) + "</p>"
            sections.append(_section("Security Headers Score", summary))

        # Tech Stack
        tech = all_data["ip"].get("tech_stack", {})
        if tech.get("technologies"):
            tags = " ".join(f'<span class="tag">{t}</span>' for t in tech["technologies"])
            sections.append(_section("Detected Technologies", tags))

        links_data = all_data["ip"].get("recon_links", {})
        if links_data:
            rows = [(name, f'<a href="{url}" target="_blank">{url}</a>') for name, url in links_data.items()]
            sections.append(_section("External Recon Links", _table(rows)))

    # Email
    if "email" in all_data:
        e = all_data["email"]
        summary = f"<p>Email: <strong>{e.get('email')}</strong> &nbsp; Domain: {e.get('domain')}</p>"
        g = e.get("gravatar", {})
        if g.get("found"):
            summary += f'<p class="found">✓ Gravatar: {g.get("display_name", "")} — <a href="{g.get("profile_url","")}">Profile</a></p>'
        hibp = e.get("hibp", {})
        if hibp.get("breaches"):
            rows = [(b["name"], b["date"], f"{b['pwn_count']:,}", ", ".join(b["data_classes"][:4]))
                    for b in hibp["breaches"]]
            summary += '<p class="danger">⚠ Found in data breaches:</p>'
            summary += _table(rows, ["Breach", "Date", "Records", "Data Types"])
        else:
            summary += '<p class="found">✓ No breaches found (HIBP)</p>'
        sections.append(_section("Email Intelligence", summary))

    # Username
    if "username" in all_data:
        found = all_data["username"].get("found", [])
        if found:
            rows = [(r["platform"], f'<a href="{r["url"]}" target="_blank" class="found">{r["url"]}</a>')
                    for r in found]
            sections.append(_section(f"Username Profiles ({len(found)} found)", _table(rows, ["Platform", "URL"])))

    # Phone
    if "phone" in all_data:
        p = all_data["phone"]
        if not p.get("error"):
            phone_data = {
                "Number": p.get("international"),
                "Country": p.get("country"),
                "Type": p.get("number_type"),
                "Carrier": p.get("carrier"),
                "Timezones": ", ".join(p.get("timezones", [])),
            }
            sections.append(_section("Phone Intelligence", _kv_table(phone_data)))

    # Facebook
    if "facebook" in all_data:
        fb = all_data["facebook"]
        status_cls = "found" if fb.get("is_public") else ("warning" if fb.get("exists") else "danger")
        status_label = "Public" if fb.get("is_public") else ("Restricted" if fb.get("exists") else "Not Found / Private")
        verified_badge = ' <span class="found">✓ Verified</span>' if fb.get("is_verified") else ""
        rows = [
            ("URL", f'<a href="{fb["profile_url"]}" target="_blank">{fb["profile_url"]}</a>'),
            ("Status", f'<span class="{status_cls}">{status_label}</span>'),
        ]
        if fb.get("display_name"):
            rows.append(("Display Name", f'<strong>{fb["display_name"]}</strong>{verified_badge}'))
        if fb.get("account_type"):
            rows.append(("Account Type", fb["account_type"]))
        if fb.get("category"):
            rows.append(("Category", fb["category"]))
        if fb.get("numeric_id"):
            rows.append(("Numeric ID", fb["numeric_id"]))

        # Engagement stats
        stats = []
        if fb.get("follower_count"):
            stats.append(f"{fb['follower_count']} followers")
        if fb.get("friend_count"):
            stats.append(f"{fb['friend_count']} friends")
        if fb.get("posts_count"):
            stats.append(f"{fb['posts_count']} posts")
        if stats:
            rows.append(("Stats", " &nbsp;|&nbsp; ".join(stats)))

        if fb.get("location"):
            rows.append(("Location", fb["location"]))
        if fb.get("hometown"):
            rows.append(("Hometown", fb["hometown"]))
        if fb.get("work_education"):
            rows.append(("Work / Education", fb["work_education"]))
        if fb.get("website"):
            rows.append(("Website", f'<a href="{fb["website"]}" target="_blank">{fb["website"]}</a>'))
        if fb.get("email"):
            rows.append(("Email", fb["email"]))
        if fb.get("phone"):
            rows.append(("Phone", fb["phone"]))
        if fb.get("founded"):
            rows.append(("Founded", fb["founded"]))
        if fb.get("joined"):
            rows.append(("Joined", fb["joined"]))
        if fb.get("description"):
            rows.append(("About", fb["description"][:300]))
        if fb.get("general_info"):
            rows.append(("General Info", fb["general_info"][:300]))
        if fb.get("mission"):
            rows.append(("Mission / About", fb["mission"][:300]))
        if fb.get("profile_pic"):
            rows.append(("Profile Picture", f'<a href="{fb["profile_pic"]}" target="_blank">View image ↗</a>'))
        if fb.get("cover_photo"):
            rows.append(("Cover Photo", f'<a href="{fb["cover_photo"]}" target="_blank">View image ↗</a>'))
        html = _table(rows, ["Field", "Value"])
        if fb.get("security_notes"):
            html += "<br><strong>⚠ Security Observations:</strong><ul>"
            html += "".join(f'<li class="warning">{n}</li>' for n in fb["security_notes"])
            html += "</ul>"
        if fb.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in fb["dorks"]
            )
            html += "</ul>"
        sections.append(_section("Facebook Intelligence", html))

    # TikTok
    if "tiktok" in all_data:
        tt = all_data["tiktok"]
        status_cls = "found" if tt.get("is_public") else "danger"
        status_label = "Public" if tt.get("is_public") else "Not Found / Private"
        rows = [
            ("URL", f'<a href="{tt["profile_url"]}" target="_blank">{tt["profile_url"]}</a>'),
            ("Status", f'<span class="{status_cls}">{status_label}</span>'),
        ]
        if tt.get("display_name"):
            rows.append(("Display Name", f'<strong>{tt["display_name"]}</strong>'))
        if tt.get("bio"):
            rows.append(("Bio", tt["bio"][:200]))
        if tt.get("follower_count"):
            rows.append(("Followers", tt["follower_count"]))
        if tt.get("video_count"):
            rows.append(("Videos", tt["video_count"]))
        if tt.get("profile_pic"):
            rows.append(("Profile Picture", f'<a href="{tt["profile_pic"]}" target="_blank">View image ↗</a>'))
        html = _table(rows, ["Field", "Value"])
        if tt.get("security_notes"):
            html += "<br><strong>⚠ Security Observations:</strong><ul>"
            html += "".join(f'<li class="warning">{n}</li>' for n in tt["security_notes"])
            html += "</ul>"
        if tt.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in tt["dorks"]
            )
            html += "</ul>"
        sections.append(_section("TikTok Intelligence", html))

    # Dorks
    if "dorks" in all_data:
        rows = []
        for d in all_data["dorks"]:
            rows.append((
                d["label"],
                d["query"],
                f'<a href="{d["google_url"]}" target="_blank">Google</a> | '
                f'<a href="{d["bing_url"]}" target="_blank">Bing</a>',
            ))
        sections.append(_section("Google Dorks", _table(rows, ["Category", "Query", "Search"])))

    # Subdomains
    if "subdomains" in all_data:
        found = all_data["subdomains"].get("found", [])
        checked = all_data["subdomains"].get("checked", 0)
        if found:
            rows = [
                (item["subdomain"], item["fqdn"], ", ".join(item["ips"]))
                for item in found
            ]
            sections.append(_section(
                f"Subdomains ({len(found)}/{checked} found)",
                _table(rows, ["Subdomain", "FQDN", "IP(s)"]),
            ))

    content = "\n".join(sections)
    return HTML_TEMPLATE.format(
        target=target,
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=content,
    )


def build_csv_report(all_data: dict) -> str | None:
    """Build CSV export. Returns CSV string if there is exportable tabular data, else None."""
    output = io.StringIO()
    writer = csv.writer(output)

    if "username" in all_data:
        writer.writerow(["Platform", "URL", "Status"])
        for r in all_data["username"].get("found", []):
            writer.writerow([r["platform"], r["url"], "found"])
        for r in all_data["username"].get("possible", []):
            writer.writerow([r["platform"], r["url"], "possible"])
        return output.getvalue()

    if "dorks" in all_data and all_data["dorks"]:
        writer.writerow(["Category", "Query", "Google URL", "Bing URL", "DuckDuckGo URL"])
        for d in all_data["dorks"]:
            writer.writerow([d["label"], d["query"], d["google_url"], d["bing_url"], d["ddg_url"]])
        return output.getvalue()

    if "subdomains" in all_data:
        found = all_data["subdomains"].get("found", [])
        if found:
            writer.writerow(["Subdomain", "FQDN", "IPs"])
            for item in found:
                writer.writerow([item["subdomain"], item["fqdn"], "; ".join(item["ips"])])
            return output.getvalue()

    return None


def save_report(target: str, all_data: dict, output_dir: str = ".") -> dict:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    safe_target = "".join(c if c.isalnum() or c in "-_." else "_" for c in target)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = Path(output_dir) / f"osint_{safe_target}_{ts}"

    html_path = base.with_suffix(".html")
    json_path = base.with_suffix(".json")

    html_path.write_text(build_html_report(target, all_data), encoding="utf-8")
    json_path.write_text(json.dumps(all_data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")

    console.print(f"\n[bold green]✓ Report saved:[/bold green]")
    console.print(f"  HTML : [cyan]{html_path}[/cyan]")
    console.print(f"  JSON : [cyan]{json_path}[/cyan]")

    csv_content = build_csv_report(all_data)
    if csv_content:
        csv_path = base.with_suffix(".csv")
        csv_path.write_text(csv_content, encoding="utf-8")
        console.print(f"  CSV  : [cyan]{csv_path}[/cyan]")

    return {"html": str(html_path), "json": str(json_path)}
