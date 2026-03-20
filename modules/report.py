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

        # VirusTotal
        vt = all_data["ip"].get("virustotal", {})
        if vt and vt.get("success"):
            mal = vt.get("malicious", 0)
            sus = vt.get("suspicious", 0)
            rep = vt.get("reputation", 0)
            color_cls = "danger" if mal > 0 else ("warning" if sus > 0 else "found")
            vt_html = f'<p class="{color_cls}"><strong>{mal} malicious / {sus} suspicious</strong> (reputation score: {rep})</p>'
            if vt.get("as_owner"):
                vt_html += f'<p>AS Owner: {vt["as_owner"]}</p>'
            if vt.get("country"):
                vt_html += f'<p>Country: {vt["country"]}</p>'
            if vt.get("categories"):
                cats = ", ".join(f"{k}: {v}" for k, v in list(vt["categories"].items())[:5])
                vt_html += f'<p>Categories: {cats}</p>'
            sections.append(_section("VirusTotal Analysis", vt_html))

        # Shodan
        shodan = all_data["ip"].get("shodan", {})
        if shodan and shodan.get("success"):
            ports = shodan.get("ports", [])
            vulns = shodan.get("vulns", [])
            sh_rows = []
            sh_rows.append(("Open Ports", ", ".join(str(p) for p in ports) or "None"))
            if shodan.get("org"):
                sh_rows.append(("Organization", shodan["org"]))
            if shodan.get("os"):
                sh_rows.append(("OS", shodan["os"]))
            if shodan.get("isp"):
                sh_rows.append(("ISP", shodan["isp"]))
            if shodan.get("last_update"):
                sh_rows.append(("Last Scan", str(shodan["last_update"])[:10]))
            sh_html = _table(sh_rows, ["Field", "Value"])
            if vulns:
                sh_html += f'<p class="danger">⚠ {len(vulns)} CVE(s) detected: {", ".join(vulns[:10])}</p>'
            if shodan.get("services"):
                svc_rows = [
                    (str(s.get("port", "")), s.get("transport", "tcp"),
                     s.get("product") or "—", s.get("version") or "—")
                    for s in shodan["services"][:10]
                ]
                sh_html += "<br>" + _table(svc_rows, ["Port", "Proto", "Product", "Version"])
            sections.append(_section("Shodan Intelligence", sh_html))

        # AbuseIPDB
        abuse = all_data["ip"].get("abuseipdb", {})
        if abuse and abuse.get("success"):
            score = abuse.get("abuse_confidence_score", 0)
            reports = abuse.get("total_reports", 0)
            score_cls = "danger" if score >= 50 else ("warning" if score >= 10 else "found")
            ab_rows = [
                ("Abuse Score", f'<span class="{score_cls}"><strong>{score}%</strong></span>'),
                ("Total Reports", str(reports)),
            ]
            if abuse.get("usage_type"):
                ab_rows.append(("Usage Type", abuse["usage_type"]))
            if abuse.get("isp"):
                ab_rows.append(("ISP", abuse["isp"]))
            if abuse.get("domain"):
                ab_rows.append(("Domain", abuse["domain"]))
            if abuse.get("is_tor"):
                ab_rows.append(("TOR Node", '<span class="danger">Yes — TOR Exit Node</span>'))
            if abuse.get("last_reported_at"):
                ab_rows.append(("Last Report", str(abuse["last_reported_at"])[:16]))
            sections.append(_section("AbuseIPDB Reputation", _table(ab_rows, ["Field", "Value"])))

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

        # Hunter.io
        hunter = e.get("hunter", {})
        if hunter and hunter.get("success"):
            summary += '<br><strong>Hunter.io:</strong>'
            h_rows = []
            if hunter.get("organization"):
                h_rows.append(("Organization", hunter["organization"]))
            if hunter.get("pattern"):
                h_rows.append(("Email Pattern", f'<code>{hunter["pattern"]}@{hunter.get("domain","")}</code>'))
            h_rows.append(("Total Emails Found", str(hunter.get("total_emails", 0))))
            if hunter.get("webmail"):
                h_rows.append(("Type", "Webmail provider"))
            if hunter.get("disposable"):
                h_rows.append(("Warning", '<span class="danger">Disposable domain</span>'))
            summary += _table(h_rows, ["Field", "Value"])
            if hunter.get("emails"):
                em_rows = [
                    (
                        em.get("value", ""),
                        em.get("type", ""),
                        f'{em.get("confidence","")}%' if em.get("confidence") is not None else "—",
                        f'{em.get("first_name","")} {em.get("last_name","")}'.strip() or "—",
                        em.get("position") or "—",
                    )
                    for em in hunter["emails"][:10]
                ]
                summary += "<br>" + _table(em_rows, ["Email", "Type", "Confidence", "Name", "Position"])

        # EmailRep.io
        emailrep = e.get("emailrep", {})
        if emailrep and emailrep.get("success"):
            rep = emailrep.get("reputation", "none")
            rep_cls = {"high": "found", "medium": "warning", "low": "danger", "none": ""}.get(rep, "")
            summary += f'<br><strong>EmailRep.io:</strong> Reputation: <span class="{rep_cls}">{rep}</span>'
            flags = []
            if emailrep.get("suspicious"):         flags.append('<span class="danger">suspicious</span>')
            if emailrep.get("blacklisted"):        flags.append('<span class="danger">blacklisted</span>')
            if emailrep.get("malicious_activity"): flags.append('<span class="danger">malicious activity</span>')
            if emailrep.get("credentials_leaked"): flags.append('<span class="warning">credentials leaked</span>')
            if emailrep.get("data_breach"):        flags.append('<span class="warning">data breach</span>')
            if emailrep.get("spam"):               flags.append('<span class="warning">spam</span>')
            if emailrep.get("disposable"):         flags.append('<span class="warning">disposable</span>')
            if flags:
                summary += " | " + " | ".join(flags)
            summary += f' | {emailrep.get("references", 0)} references'
            if emailrep.get("profiles"):
                summary += f'<br>Profiles: {", ".join(emailrep["profiles"][:8])}'

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
            nv = p.get("numverify", {})
            if nv and nv.get("success") and nv.get("valid"):
                if nv.get("line_type"):
                    phone_data["Line Type (Live)"] = nv["line_type"]
                if nv.get("carrier") and nv.get("carrier") != p.get("carrier"):
                    phone_data["Carrier (Live)"] = nv["carrier"]
                if nv.get("location"):
                    phone_data["Location"] = nv["location"]
                if nv.get("country_name"):
                    phone_data["Country (Live)"] = nv["country_name"]
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
        if fb.get("address"):
            rows.append(("Address", fb["address"]))
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
        if fb.get("recent_posts"):
            avg = fb.get("avg_engagement")
            avg_str = f" &nbsp;<small>(avg engagement: {avg:,})</small>" if avg else ""
            html += f"<br><strong>Recent Posts{avg_str}:</strong>"
            html += (
                '<table border="1" cellpadding="4" cellspacing="0" style="border-collapse:collapse;width:100%">'
                '<tr><th>Date</th><th>Type</th><th>Message</th><th>❤ Reactions</th><th>💬 Comments</th><th>Shares</th><th>Link</th></tr>'
            )
            for p in fb["recent_posts"]:
                msg = (p.get("message") or "—")[:120]
                link = f'<a href="{p["url"]}" target="_blank">View ↗</a>' if p.get("url") else "—"
                author = f' <small>({p["author_name"]})</small>' if p.get("author_name") else ""
                html += (
                    f'<tr>'
                    f'<td>{p.get("date") or "—"}</td>'
                    f'<td>{p.get("type") or "post"}</td>'
                    f'<td>{msg}{author}</td>'
                    f'<td align="right">{p.get("reactions", 0)}</td>'
                    f'<td align="right">{p.get("comments", 0)}</td>'
                    f'<td align="right">{p.get("shares", 0)}</td>'
                    f'<td>{link}</td>'
                    f'</tr>'
                )
            html += "</table>"
        if fb.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in fb["dorks"]
            )
            html += "</ul>"
        sections.append(_section("Facebook Intelligence", html))

    # Breach Check
    if "breach" in all_data:
        br = all_data["breach"]
        summary = br.get("summary", {})
        total = summary.get("total_breaches", 0)
        total_pastes = summary.get("total_pastes", 0)
        status_cls = "danger" if total > 0 else "found"
        status_label = f"⚠ Tìm thấy ~{total} vụ rò rỉ" if total > 0 else "✓ Không tìm thấy"
        html = f'<p class="{status_cls}"><strong>{status_label}</strong></p>'
        srcs = summary.get("sources_checked", [])
        if srcs:
            html += f'<p class="meta">Nguồn đã kiểm tra: {", ".join(srcs)}</p>'

        # LeakCheck
        lc = br.get("leakcheck", {}) or {}
        html += "<h3 style='color:#79c0ff;margin:12px 0 6px'>① LeakCheck.io (miễn phí)</h3>"
        if lc.get("found"):
            sources = lc.get("sources", [])
            html += f'<p class="danger">⚠ Xuất hiện trong {len(sources)} nguồn</p>'
            html += "<ul>" + "".join(f"<li>{s}</li>" for s in sources) + "</ul>"
        elif lc.get("note"):
            html += f'<p class="meta">{lc["note"]}</p>'
        elif lc.get("error"):
            html += f'<p class="warning">Lỗi: {lc["error"]}</p>'
        else:
            html += '<p class="found">✓ Không tìm thấy trong LeakCheck.io</p>'

        # BreachDirectory
        bd = br.get("breachdirectory", {}) or {}
        html += "<h3 style='color:#79c0ff;margin:12px 0 6px'>② BreachDirectory (RapidAPI)</h3>"
        if bd.get("note"):
            html += "<br>".join(f'<p class="meta">{line}</p>' for line in bd["note"].splitlines())
        elif bd.get("found"):
            size = bd.get("size", len(bd.get("result", [])))
            html += f'<p class="danger">⚠ {size} bản ghi bị lộ</p>'
            rows = []
            for entry in bd.get("result", [])[:20]:
                src_raw = entry.get("sources", [])
                src = src_raw[0] if isinstance(src_raw, list) and src_raw else str(src_raw or "?")
                fields = ", ".join(entry.get("fields", [])) or "—"
                h_type = entry.get("password_type", "—")
                rows.append((src, fields, h_type))
            if rows:
                html += _table(rows, ["Nguồn (Source)", "Dữ liệu bị lộ", "Hash type"])
        elif bd.get("error"):
            html += f'<p class="warning">Lỗi: {bd["error"]}</p>'
        else:
            html += '<p class="found">✓ Không tìm thấy</p>'

        # HIBP
        hibp = br.get("hibp", {}) or {}
        html += "<h3 style='color:#79c0ff;margin:12px 0 6px'>③ HaveIBeenPwned</h3>"
        if hibp.get("note"):
            html += "<br>".join(f'<p class="meta">{line}</p>' for line in hibp["note"].splitlines())
        elif hibp.get("breaches"):
            breaches = hibp["breaches"]
            html += f'<p class="danger">⚠ Có trong {len(breaches)} vụ rò rỉ:</p>'
            rows = [
                (b.get("name", "?"), b.get("date", "?"),
                 f'{b["pwn_count"]:,}' if b.get("pwn_count") else "?",
                 ", ".join((b.get("data_classes") or [])[:4]))
                for b in breaches
            ]
            html += _table(rows, ["Tên vụ rò rỉ", "Ngày", "Số bản ghi", "Loại dữ liệu"])
        else:
            html += '<p class="found">✓ Không tìm thấy trong HIBP breaches</p>'
        if (hibp.get("pastes") or []):
            html += f'<p class="warning">⚠ Xuất hiện trong {len(hibp["pastes"])} paste(s) công khai</p>'

        # Pwned Password
        pw = br.get("pwned_password")
        if pw is not None:
            html += "<h3 style='color:#79c0ff;margin:12px 0 6px'>④ HIBP Pwned Passwords</h3>"
            if pw.get("exposed"):
                html += f'<p class="danger">⚠ Mật khẩu đã bị lộ {pw["count"]:,} lần!</p>'
            elif pw.get("error"):
                html += f'<p class="warning">Lỗi: {pw["error"]}</p>'
            else:
                html += '<p class="found">✓ Mật khẩu chưa xuất hiện trong rò rỉ đã biết</p>'

        # Dorks
        if br.get("dorks"):
            html += "<br><strong>Tra cứu thêm:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a></li>'
                for d in br["dorks"]
            )
            html += "</ul>"

        sections.append(_section(f"Breach / Data Leak Check — {br.get('target','')}", html))

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
            verified_badge = ' <span style="color:#f5a623">✓ Verified</span>' if tt.get("is_verified") else ""
            rows.append(("Display Name", f'<strong>{tt["display_name"]}</strong>{verified_badge}'))
        if tt.get("bio"):
            rows.append(("Bio", tt["bio"][:200]))
        if tt.get("region"):
            rows.append(("Region", tt["region"]))
        if tt.get("follower_count") is not None:
            fc = tt["follower_count"]
            rows.append(("Followers", f"{fc:,}" if isinstance(fc, int) else str(fc)))
        if tt.get("following_count") is not None:
            fw = tt["following_count"]
            rows.append(("Following", f"{fw:,}" if isinstance(fw, int) else str(fw)))
        if tt.get("likes_count") is not None:
            lc = tt["likes_count"]
            rows.append(("Total Likes", f"{lc:,}" if isinstance(lc, int) else str(lc)))
        if tt.get("video_count") is not None:
            vc = tt["video_count"]
            rows.append(("Videos", f"{vc:,}" if isinstance(vc, int) else str(vc)))
        if tt.get("profile_pic"):
            rows.append(("Profile Picture", f'<a href="{tt["profile_pic"]}" target="_blank">View image ↗</a>'))
        if tt.get("data_sources"):
            rows.append(("Data Sources", ", ".join(tt["data_sources"])))
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

    # Instagram
    if "instagram" in all_data:
        ig = all_data["instagram"]
        status_cls = "found" if ig.get("is_public") else ("warning" if ig.get("exists") else "danger")
        status_label = "Public" if ig.get("is_public") else ("Private" if ig.get("exists") else "Not Found")
        rows = [
            ("URL", f'<a href="{ig["profile_url"]}" target="_blank">{ig["profile_url"]}</a>'),
            ("Status", f'<span class="{status_cls}">{status_label}</span>'),
        ]
        if ig.get("full_name"):
            verified_badge = ' <span style="color:#f5a623">✓ Verified</span>' if ig.get("is_verified") else ""
            rows.append(("Full Name", f'<strong>{ig["full_name"]}</strong>{verified_badge}'))
        if ig.get("biography"):
            rows.append(("Bio", ig["biography"][:200]))
        if ig.get("category"):
            rows.append(("Category", ig["category"]))
        if ig.get("city_name"):
            rows.append(("City", ig["city_name"]))
        if ig.get("external_url"):
            rows.append(("Website", f'<a href="{ig["external_url"]}" target="_blank">{ig["external_url"]}</a>'))
        if ig.get("public_email"):
            rows.append(("Public Email", f'<span class="warning">{ig["public_email"]}</span>'))
        if ig.get("public_phone"):
            rows.append(("Public Phone", f'<span class="warning">{ig["public_phone"]}</span>'))
        stats = []
        if ig.get("follower_count") is not None:
            fc = ig["follower_count"]
            stats.append(f"{fc:,} followers" if isinstance(fc, int) else str(fc))
        if ig.get("following_count") is not None:
            fw = ig["following_count"]
            stats.append(f"{fw:,} following" if isinstance(fw, int) else str(fw))
        if ig.get("media_count") is not None:
            mc = ig["media_count"]
            stats.append(f"{mc:,} posts" if isinstance(mc, int) else str(mc))
        if stats:
            rows.append(("Stats", " | ".join(stats)))
        if ig.get("profile_pic"):
            rows.append(("Profile Picture", f'<a href="{ig["profile_pic"]}" target="_blank">View image ↗</a>'))
        if ig.get("data_sources"):
            rows.append(("Data Sources", ", ".join(ig["data_sources"])))
        html = _table(rows, ["Field", "Value"])
        if ig.get("security_notes"):
            html += "<br><strong>⚠ Security Observations:</strong><ul>"
            html += "".join(f'<li class="warning">{n}</li>' for n in ig["security_notes"])
            html += "</ul>"
        if ig.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in ig["dorks"]
            )
            html += "</ul>"
        sections.append(_section("Instagram Intelligence", html))

    # Twitter / X
    if "twitter" in all_data:
        tw = all_data["twitter"]
        status_cls = "found" if tw.get("is_public") else ("warning" if tw.get("exists") else "danger")
        status_label = "Public" if tw.get("is_public") else ("Protected" if tw.get("exists") else "Not Found")
        rows = [
            ("URL", f'<a href="{tw["profile_url"]}" target="_blank">{tw["profile_url"]}</a>'),
            ("Status", f'<span class="{status_cls}">{status_label}</span>'),
        ]
        if tw.get("name"):
            verified_badge = ' <span style="color:#f5a623">✓ Verified</span>' if tw.get("is_verified") else ""
            rows.append(("Name", f'<strong>{tw["name"]}</strong>{verified_badge}'))
        if tw.get("description"):
            rows.append(("Bio", tw["description"][:200]))
        if tw.get("location"):
            rows.append(("Location", tw["location"]))
        if tw.get("expanded_url") or tw.get("url"):
            link = tw.get("expanded_url") or tw.get("url")
            rows.append(("Website", f'<a href="{link}" target="_blank">{link}</a>'))
        if tw.get("created_at"):
            rows.append(("Joined", str(tw["created_at"])[:10]))
        stats = []
        if tw.get("follower_count") is not None:
            fc = tw["follower_count"]
            stats.append(f"{fc:,} followers" if isinstance(fc, int) else str(fc))
        if tw.get("following_count") is not None:
            fw = tw["following_count"]
            stats.append(f"{fw:,} following" if isinstance(fw, int) else str(fw))
        if tw.get("tweet_count") is not None:
            tc = tw["tweet_count"]
            stats.append(f"{tc:,} tweets" if isinstance(tc, int) else str(tc))
        if stats:
            rows.append(("Stats", " | ".join(stats)))
        if tw.get("profile_image_url"):
            rows.append(("Avatar", f'<a href="{tw["profile_image_url"]}" target="_blank">View image ↗</a>'))
        if tw.get("data_sources"):
            rows.append(("Data Sources", ", ".join(tw["data_sources"])))
        html = _table(rows, ["Field", "Value"])
        if tw.get("security_notes"):
            html += "<br><strong>⚠ Security Observations:</strong><ul>"
            html += "".join(f'<li class="warning">{n}</li>' for n in tw["security_notes"])
            html += "</ul>"
        if tw.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in tw["dorks"]
            )
            html += "</ul>"
        sections.append(_section("Twitter / X Intelligence", html))

    # YouTube
    if "youtube" in all_data:
        yt = all_data["youtube"]
        status_cls = "found" if yt.get("exists") else "danger"
        status_label = "Found" if yt.get("exists") else "Not Found"
        rows = [
            ("Status", f'<span class="{status_cls}">{status_label}</span>'),
        ]
        if yt.get("channel_url"):
            rows.append(("Channel URL", f'<a href="{yt["channel_url"]}" target="_blank">{yt["channel_url"]}</a>'))
        if yt.get("channel_id"):
            rows.append(("Channel ID", f'<code>{yt["channel_id"]}</code>'))
        if yt.get("handle"):
            rows.append(("Handle", yt["handle"]))
        if yt.get("title"):
            verified_badge = ' <span style="color:#f5a623">✓ Verified</span>' if yt.get("verified") else ""
            rows.append(("Channel Name", f'<strong>{yt["title"]}</strong>{verified_badge}'))
        if yt.get("country"):
            rows.append(("Country", yt["country"]))
        if yt.get("subscriber_count"):
            rows.append(("Subscribers", str(yt["subscriber_count"])))
        if yt.get("video_count"):
            rows.append(("Videos", str(yt["video_count"])))
        if yt.get("view_count"):
            rows.append(("Total Views", str(yt["view_count"])))
        if yt.get("has_business_email"):
            rows.append(("Business Email", "Yes (see About page)"))
        if yt.get("description"):
            rows.append(("Description", yt["description"][:200]))
        if yt.get("links"):
            def _yt_link(lnk):
                href = lnk if lnk.startswith("http") else f"https://{lnk}"
                return f'<a href="{href}" target="_blank">{lnk}</a>'
            links_html = " | ".join(_yt_link(lnk) for lnk in yt["links"][:5])
            rows.append(("Links", links_html))
        if yt.get("avatar"):
            rows.append(("Avatar", f'<a href="{yt["avatar"]}" target="_blank">View image ↗</a>'))
        if yt.get("data_sources"):
            rows.append(("Data Sources", ", ".join(yt["data_sources"])))
        html = _table(rows, ["Field", "Value"])
        if yt.get("security_notes"):
            html += "<br><strong>⚠ Security Observations:</strong><ul>"
            html += "".join(f'<li class="warning">{n}</li>' for n in yt["security_notes"])
            html += "</ul>"
        if yt.get("dorks"):
            html += "<br><strong>Investigation Dorks:</strong><ul>"
            html += "".join(
                f'<li><a href="{d["url"]}" target="_blank">{d["label"]}</a>: <code>{d["query"]}</code></li>'
                for d in yt["dorks"]
            )
            html += "</ul>"
        sections.append(_section("YouTube Intelligence", html))

    # Website Contacts
    if "website_contacts" in all_data:
        wc = all_data["website_contacts"]
        domain = wc.get("domain") or wc.get("url", "")
        emails = wc.get("emails", [])
        phones = wc.get("phone_numbers", [])
        socials = wc.get("socials", {})

        html = ""
        if wc.get("error"):
            html += f'<p class="danger">Error: {wc["error"]}</p>'
        else:
            html += f'<p>Domain: <strong>{domain}</strong></p>'

            if emails:
                email_rows = [
                    (e.get("value", ""), e.get("sources", [""])[0] if e.get("sources") else "")
                    for e in emails[:100]
                ]
                html += f"<br><strong>Emails ({len(emails)} found):</strong>"
                html += _table(email_rows, ["Email Address", "Source"])
                if len(emails) > 100:
                    html += f'<p class="warning">... and {len(emails) - 100} more addresses</p>'

            if phones:
                phone_rows = [
                    (p.get("value", ""), p.get("sources", [""])[0] if p.get("sources") else "")
                    for p in phones
                ]
                html += f"<br><strong>Phone Numbers ({len(phones)} found):</strong>"
                html += _table(phone_rows, ["Phone Number", "Source"])

            if socials:
                social_rows = [
                    (platform.capitalize(), f'<a href="{link}" target="_blank">{link}</a>')
                    for platform, link in socials.items()
                ]
                html += "<br><strong>Social Media Links:</strong>"
                html += _table(social_rows, ["Platform", "URL"])

            if wc.get("security_notes"):
                html += "<br><strong>⚠ Security Observations:</strong><ul>"
                html += "".join(f'<li class="warning">{n}</li>' for n in wc["security_notes"])
                html += "</ul>"

        sections.append(_section(f"Website Contacts — {domain}", html))

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
