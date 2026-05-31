"""
Interactive HTML report generator with search, filtering, charts, and timeline.
Extends the base report module with Chart.js-powered visualizations.
"""
import html as _html
import json
import datetime
from pathlib import Path
from modules.report import _e, _section, _table, _kv_table, build_html_report as _build_base

INTERACTIVE_CSS_EXTRA = """
    /* Search and filter bar */
    .controls { display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
    .search-box { flex: 1; min-width: 200px; padding: 8px 14px; background: #161b22;
                  border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; font-size: 0.9rem; }
    .search-box:focus { outline: none; border-color: #58a6ff; }
    .filter-btn { padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; background: #21262d;
                  color: #8b949e; cursor: pointer; font-size: 0.85rem; transition: all .2s; }
    .filter-btn:hover, .filter-btn.active { background: #388bfd26; border-color: #388bfd; color: #58a6ff; }
    /* Section animations */
    .section { transition: opacity .2s, transform .2s; }
    .section.hidden { display: none; }
    /* Highlight match */
    .highlight { background: #d29922; color: #0d1117; border-radius: 2px; padding: 0 2px; }
    /* Chart containers */
    .chart-container { position: relative; height: 260px; margin: 16px 0; }
    /* Collapsible sections */
    .section-header { cursor: pointer; user-select: none; display: flex; justify-content: space-between; align-items: center; }
    .section-header::after { content: "▼"; font-size: 0.7rem; color: #8b949e; transition: transform .2s; }
    .section-header.collapsed::after { transform: rotate(-90deg); }
    .section-body { transition: max-height .3s ease; overflow: hidden; }
    /* Summary cards */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; margin: 16px 0; }
    .summary-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px;
                    text-align: center; }
    .summary-card .card-value { font-size: 1.8rem; font-weight: bold; color: #58a6ff; }
    .summary-card .card-label { font-size: 0.75rem; color: #8b949e; margin-top: 4px; }
    /* Timeline */
    .timeline { list-style: none; padding: 0; position: relative; }
    .timeline::before { content: ""; position: absolute; left: 8px; top: 0; bottom: 0;
                        width: 2px; background: #30363d; }
    .timeline li { padding: 8px 0 8px 28px; position: relative; font-size: 0.85rem; }
    .timeline li::before { content: "●"; position: absolute; left: 0; color: #58a6ff; font-size: 0.8rem; }
    /* Risk badge */
    .risk-badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.78rem;
                  font-weight: bold; }
    .risk-clean    { background: #1a3a2a; color: #3fb950; }
    .risk-low      { background: #1a2a3a; color: #58a6ff; }
    .risk-medium   { background: #3a2a1a; color: #d29922; }
    .risk-high     { background: #3a1a1a; color: #f0883e; }
    .risk-suspicious { background: #3a0a0a; color: #f85149; }
    /* Print styles */
    @media print {
      .controls, .no-print { display: none !important; }
      .section { break-inside: avoid; }
      body { background: #fff; color: #000; }
    }
    /* Responsive */
    @media (max-width: 600px) {
      .summary-grid { grid-template-columns: repeat(2, 1fr); }
    }
"""

INTERACTIVE_JS = """
<script>
// ── Search & Filter ──────────────────────────────────────────────────────────
const searchBox = document.getElementById('search-box');
const sections = document.querySelectorAll('.section[data-category]');
const filterBtns = document.querySelectorAll('.filter-btn[data-filter]');
let activeFilter = 'all';

function normalizeText(el) {
  return el.textContent.toLowerCase().replace(/\\s+/g, ' ');
}

function clearHighlights() {
  document.querySelectorAll('.highlight').forEach(el => {
    el.replaceWith(document.createTextNode(el.textContent));
  });
}

function highlightText(node, term) {
  if (node.nodeType === 3) {
    const idx = node.nodeValue.toLowerCase().indexOf(term);
    if (idx >= 0) {
      const span = document.createElement('span');
      span.className = 'highlight';
      span.textContent = node.nodeValue.slice(idx, idx + term.length);
      const after = document.createTextNode(node.nodeValue.slice(idx + term.length));
      const before = document.createTextNode(node.nodeValue.slice(0, idx));
      node.parentNode.insertBefore(before, node);
      node.parentNode.insertBefore(span, node);
      node.parentNode.insertBefore(after, node);
      node.parentNode.removeChild(node);
    }
  } else if (node.nodeType === 1 && !['SCRIPT','STYLE','INPUT'].includes(node.tagName)) {
    Array.from(node.childNodes).forEach(child => highlightText(child, term));
  }
}

function applySearch() {
  clearHighlights();
  const term = (searchBox?.value || '').toLowerCase().trim();
  sections.forEach(sec => {
    const cat = sec.dataset.category || '';
    const matchFilter = activeFilter === 'all' || cat === activeFilter;
    const matchSearch = !term || normalizeText(sec).includes(term);
    sec.classList.toggle('hidden', !(matchFilter && matchSearch));
    if (term && matchSearch && matchFilter) highlightText(sec, term);
  });
  updateCount();
}

function updateCount() {
  const visible = document.querySelectorAll('.section[data-category]:not(.hidden)').length;
  const total = sections.length;
  const counter = document.getElementById('section-counter');
  if (counter) counter.textContent = `${visible}/${total} sections`;
}

if (searchBox) searchBox.addEventListener('input', applySearch);

filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    activeFilter = btn.dataset.filter;
    filterBtns.forEach(b => b.classList.toggle('active', b === btn));
    applySearch();
  });
});

// ── Collapsible sections ─────────────────────────────────────────────────────
document.querySelectorAll('.section-header').forEach(header => {
  header.addEventListener('click', () => {
    const body = header.nextElementSibling;
    if (!body) return;
    const isCollapsed = header.classList.toggle('collapsed');
    body.style.maxHeight = isCollapsed ? '0' : body.scrollHeight + 'px';
  });
});

// Auto-expand all sections on load
document.querySelectorAll('.section-body').forEach(b => {
  b.style.maxHeight = b.scrollHeight + 4000 + 'px';
});

// ── Keyboard shortcut: "/" to focus search ───────────────────────────────────
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== searchBox) {
    e.preventDefault();
    if (searchBox) searchBox.focus();
  }
  if (e.key === 'Escape' && searchBox) {
    searchBox.value = '';
    applySearch();
  }
});

// ── Copy to clipboard ────────────────────────────────────────────────────────
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const text = btn.dataset.copy;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied';
      setTimeout(() => btn.textContent = orig, 1500);
    });
  });
});

// ── Init count ───────────────────────────────────────────────────────────────
updateCount();
</script>
"""

INTERACTIVE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSINT Report — {target}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', monospace; background: #0d1117; color: #e6edf3; padding: 24px; }}
    h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 12px; margin-bottom: 16px; font-size: 1.4rem; }}
    h2 {{ color: #79c0ff; margin: 0 0 12px; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }}
    .meta {{ color: #8b949e; font-size: 0.82rem; margin-bottom: 16px; }}
    .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px;
                margin-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
    th {{ background: #21262d; color: #79c0ff; padding: 8px 12px; text-align: left; }}
    td {{ padding: 6px 12px; border-bottom: 1px solid #21262d; word-break: break-word; }}
    tr:last-child td {{ border-bottom: none; }}
    a {{ color: #58a6ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .found {{ color: #3fb950; }} .warning {{ color: #d29922; }} .danger {{ color: #f85149; }}
    .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem;
            background: #21262d; border: 1px solid #30363d; margin: 2px; }}
    pre {{ background: #21262d; padding: 12px; border-radius: 6px; overflow-x: auto;
           font-size: 0.8rem; color: #79c0ff; }}
    .disclaimer {{ background: #161b22; border: 1px solid #f85149; border-radius: 8px;
                   padding: 10px 14px; margin-bottom: 16px; font-size: 0.82rem; color: #f85149; }}
    .export-bar {{ display: flex; gap: 8px; margin-bottom: 16px; }}
    .btn {{ padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; background: #21262d;
            color: #c9d1d9; cursor: pointer; font-size: 0.82rem; }}
    .btn:hover {{ background: #30363d; }}
    {extra_css}
  </style>
</head>
<body>
  <h1>🔍 OSINT Intelligence Report</h1>
  <div class="meta">
    Target: <strong>{target}</strong> &nbsp;|&nbsp;
    Generated: {timestamp} &nbsp;|&nbsp;
    Tool: OSINT-Tool v1.2 &nbsp;|&nbsp;
    <span id="section-counter"></span>
  </div>
  <div class="disclaimer">
    ⚠ <strong>DISCLAIMER:</strong> Generated using publicly available data sources only.
    For legitimate security research / investigative purposes.
  </div>

  <!-- Export & controls -->
  <div class="export-bar no-print">
    <button class="btn" onclick="window.print()">🖨 Print / Save PDF</button>
    <button class="btn" onclick="expandAll()">⊞ Expand All</button>
    <button class="btn" onclick="collapseAll()">⊟ Collapse All</button>
    <button class="btn copy-btn" data-copy="{target}">📋 Copy Target</button>
  </div>

  <!-- Search + filter bar -->
  <div class="controls no-print">
    <input id="search-box" class="search-box" type="search" placeholder="🔍 Search report... (press / to focus)" />
    <button class="filter-btn active" data-filter="all">All</button>
    <button class="filter-btn" data-filter="network">Network</button>
    <button class="filter-btn" data-filter="identity">Identity</button>
    <button class="filter-btn" data-filter="social">Social</button>
    <button class="filter-btn" data-filter="security">Security</button>
    <button class="filter-btn" data-filter="intel">Intel</button>
  </div>

  <!-- Summary cards -->
  {summary_cards}

  <!-- Main content -->
  {content}

  <script>
  function expandAll() {{
    document.querySelectorAll('.section-header.collapsed').forEach(h => h.click());
  }}
  function collapseAll() {{
    document.querySelectorAll('.section-header:not(.collapsed)').forEach(h => h.click());
  }}
  </script>
  {js}
</body>
</html>
"""


def _make_summary_cards(all_data: dict) -> str:
    cards = []

    def card(value: str, label: str, color: str = "#58a6ff") -> str:
        return (
            f'<div class="summary-card">'
            f'<div class="card-value" style="color:{color}">{_e(str(value))}</div>'
            f'<div class="card-label">{_e(label)}</div>'
            f'</div>'
        )

    if "dns" in all_data:
        records = all_data["dns"].get("records", {})
        total_records = sum(len(v) if isinstance(v, list) else 1 for v in records.values())
        cards.append(card(total_records, "DNS Records"))

    if "whois" in all_data:
        w = all_data["whois"].get("whois", {})
        registrar = w.get("registrar", "—")
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else "—"
        if registrar and str(registrar) != "None":
            cards.append(card(str(registrar)[:20], "Registrar", "#79c0ff"))

    if "email" in all_data:
        hibp = all_data["email"].get("hibp", {})
        breach_count = len(hibp.get("breaches", []))
        color = "#f85149" if breach_count > 0 else "#3fb950"
        cards.append(card(breach_count, "Breaches Found", color))

    if "username" in all_data:
        found_count = len(all_data["username"].get("found", []))
        cards.append(card(found_count, "Platforms Found", "#3fb950" if found_count > 0 else "#8b949e"))

    if "ip" in all_data:
        shodan = all_data["ip"].get("shodan", {})
        if shodan.get("ports"):
            cards.append(card(len(shodan["ports"]), "Open Ports", "#d29922"))
        vuln_count = len(shodan.get("vulns", []))
        if vuln_count > 0:
            cards.append(card(vuln_count, "CVEs Detected", "#f85149"))

    if "breach" in all_data:
        results = all_data["breach"].get("results", {})
        found_in = sum(1 for v in results.values() if v and not isinstance(v, str))
        cards.append(card(found_in, "Breach DBs Hit", "#f85149" if found_in > 0 else "#3fb950"))

    if "ssl" in all_data:
        grade = all_data["ssl"].get("grade", "?")
        grade_colors = {"A+": "#3fb950", "A": "#3fb950", "B": "#79c0ff",
                        "C": "#d29922", "D": "#f0883e", "F": "#f85149"}
        cards.append(card(grade, "SSL Grade", grade_colors.get(grade, "#8b949e")))

    if not cards:
        return ""

    return '<div class="summary-grid">' + "".join(cards) + "</div>"


def _section_interactive(title: str, content: str, category: str = "general") -> str:
    return (
        f'<div class="section" data-category="{_e(category)}">'
        f'<h2 class="section-header">{_e(title)}</h2>'
        f'<div class="section-body">{content}</div>'
        f'</div>'
    )


def build_interactive_html_report(target: str, all_data: dict) -> str:
    """
    Build an interactive HTML report with search, filters, collapsible sections,
    summary cards, and Chart.js visualizations.
    """
    from modules.report import build_html_report as _base

    # Re-use base content sections but wrap them interactively
    sections = []

    # Reuse the base builder to get section content, then re-wrap
    base_html = _base(target, all_data)

    # Instead of full re-parsing, build our own sections with categories
    if "whois" in all_data:
        w = all_data["whois"].get("whois", {})
        if w:
            from modules.report import _kv_table
            content = _kv_table(
                {k.replace("_", " ").title(): str(v) for k, v in w.items() if v and str(v) not in ("None", "[]")}
            )
            sections.append(_section_interactive("WHOIS Information", content, "network"))

    if "dns" in all_data:
        records = all_data["dns"].get("records", {})
        if records:
            from modules.report import _table
            rows = [(rtype, "<br>".join(vals) if isinstance(vals, list) else str(vals))
                    for rtype, vals in records.items()]
            sections.append(_section_interactive("DNS Records", _table(rows, ["Type", "Records"]), "network"))

        # Subdomains
        subs = all_data["dns"].get("subdomains", [])
        if subs:
            sub_tags = " ".join(f'<span class="tag"><a href="http://{_e(s)}" target="_blank">{_e(s)}</a></span>' for s in subs[:50])
            sections.append(_section_interactive(f"Subdomains ({len(subs)} found)", sub_tags, "network"))

    if "ip" in all_data:
        geo = all_data["ip"].get("geo", {}).get("data", {})
        if geo:
            from modules.report import _kv_table
            sections.append(_section_interactive("IP / Geolocation",
                _kv_table({k.replace("_", " ").title(): str(v) for k, v in geo.items() if v}), "network"))

        shodan = all_data["ip"].get("shodan", {})
        if shodan and shodan.get("success"):
            ports = shodan.get("ports", [])
            from modules.report import _table
            sh_rows = [("Open Ports", ", ".join(str(p) for p in ports) or "None")]
            if shodan.get("org"):
                sh_rows.append(("Organization", _e(shodan["org"])))
            vulns = shodan.get("vulns", [])
            sh_html = _table(sh_rows, ["Field", "Value"])
            if vulns:
                sh_html += f'<p class="danger">⚠ {len(vulns)} CVE(s): {_e(", ".join(vulns[:10]))}</p>'
            # Add port chart
            if ports:
                chart_data = json.dumps(ports[:10])
                sh_html += f"""
<div class="chart-container no-print" style="height:200px">
  <canvas id="port-chart"></canvas>
</div>
<script>
new Chart(document.getElementById('port-chart'), {{
  type: 'bar',
  data: {{
    labels: {chart_data},
    datasets: [{{ label: 'Open Ports', data: {json.dumps([1]*len(ports[:10]))},
                 backgroundColor: '#388bfd88', borderColor: '#388bfd', borderWidth: 1 }}]
  }},
  options: {{ responsive: true, maintainAspectRatio: false,
              plugins: {{ legend: {{ display: false }},
                         title: {{ display: true, text: 'Open Ports', color: '#79c0ff' }} }},
              scales: {{ y: {{ display: false }}, x: {{ ticks: {{ color: '#8b949e' }},
                         grid: {{ color: '#21262d' }} }} }} }}
}});
</script>"""
            sections.append(_section_interactive("Shodan Intelligence", sh_html, "security"))

    if "email" in all_data:
        e = all_data["email"]
        summary = f"<p>Email: <strong>{_e(e.get('email', ''))}</strong></p>"
        hibp = e.get("hibp", {})
        breaches = hibp.get("breaches", [])
        if breaches:
            from modules.report import _table
            rows = [(_e(b["name"]), _e(b.get("date", "—")),
                     f"{b.get('pwn_count', 0):,}", _e(", ".join(b.get("data_classes", [])[:4])))
                    for b in breaches]
            summary += f'<p class="danger">⚠ Found in {len(breaches)} breach(es):</p>'
            summary += _table(rows, ["Breach", "Date", "Records", "Data Types"])
            # Breach timeline
            if len(breaches) > 1:
                timeline_items = "".join(
                    f'<li><strong>{_e(b["name"])}</strong> — {_e(b.get("date", "?"))} '
                    f'({b.get("pwn_count", 0):,} records)</li>'
                    for b in sorted(breaches, key=lambda x: x.get("date", ""), reverse=True)
                )
                summary += f'<br><strong>Timeline:</strong><ul class="timeline">{timeline_items}</ul>'
        else:
            summary += '<p class="found">✓ No breaches found in HIBP</p>'
        sections.append(_section_interactive("Email Intelligence", summary, "identity"))

    if "username" in all_data:
        found = all_data["username"].get("found", [])
        if found:
            from modules.report import _table
            rows = [(r["platform"], f'<a href="{_e(r["url"])}" target="_blank" class="found">{_e(r["url"])}</a>')
                    for r in found]
            sections.append(_section_interactive(
                f"Username Found on {len(found)} Platforms", _table(rows, ["Platform", "URL"]), "identity"))

    if "ssl" in all_data:
        ssl_data = all_data["ssl"]
        grade = ssl_data.get("grade", "?")
        grade_colors = {"A+": "#3fb950", "A": "#3fb950", "B": "#79c0ff",
                        "C": "#d29922", "D": "#f0883e", "F": "#f85149"}
        color = grade_colors.get(grade, "#e6edf3")
        ssl_html = f'<p>Grade: <strong style="color:{color};font-size:1.4rem">{_e(grade)}</strong></p>'
        from modules.report import _kv_table
        cert = ssl_data.get("certificate", {})
        if cert:
            ssl_html += _kv_table({
                "Subject": cert.get("subject", "—"),
                "Issuer": cert.get("issuer", "—"),
                "Valid From": cert.get("not_before", "—"),
                "Valid Until": cert.get("not_after", "—"),
                "SANs": ", ".join(cert.get("sans", [])[:5]),
            })
        sections.append(_section_interactive("SSL/TLS Certificate", ssl_html, "security"))

    if "breach" in all_data:
        breach_results = all_data["breach"]
        content_parts = []
        for source, data in breach_results.items():
            if source.startswith("_") or not data:
                continue
            if isinstance(data, dict) and data.get("found"):
                from modules.report import _kv_table
                content_parts.append(f"<h3 style='color:#79c0ff;margin-top:12px'>{_e(source)}</h3>")
                content_parts.append(_kv_table(data))
        if content_parts:
            sections.append(_section_interactive("Breach Intelligence", "".join(content_parts), "intel"))

    if "social" in all_data:
        for platform, data in all_data["social"].items():
            if not isinstance(data, dict):
                continue
            from modules.report import _kv_table
            filtered = {k: v for k, v in data.items()
                       if v and k not in ("dorks", "security_notes", "data_sources")
                       and not isinstance(v, (list, dict))}
            if filtered:
                p_html = _kv_table({k.replace("_", " ").title(): str(v) for k, v in filtered.items()})
                notes = data.get("security_notes", [])
                if notes:
                    p_html += '<ul>' + ''.join(f'<li class="warning">⚠ {_e(n)}</li>' for n in notes) + '</ul>'
                sections.append(_section_interactive(f"Social: {_e(platform.title())}", p_html, "social"))

    if "secrets" in all_data:
        findings = all_data["secrets"].get("findings", [])
        if findings:
            from modules.report import _table
            rows = [(_e(f.get("type", "")), _e(f.get("file", "")), _e(f.get("severity", "")))
                    for f in findings[:30]]
            html = _table(rows, ["Type", "File", "Severity"])
            sections.append(_section_interactive(f"Exposed Secrets ({len(findings)} found)", html, "security"))

    # Fallback: any remaining data
    for key, value in all_data.items():
        if key in ("whois", "dns", "ip", "email", "username", "ssl", "breach", "social", "secrets"):
            continue
        if not isinstance(value, dict) or not value:
            continue
        from modules.report import _kv_table
        flat = {k.replace("_", " ").title(): str(v) for k, v in value.items()
                if not isinstance(v, (list, dict)) and v}
        if flat:
            sections.append(_section_interactive(key.replace("_", " ").title(), _kv_table(flat)))

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_html = _make_summary_cards(all_data)

    return INTERACTIVE_TEMPLATE.format(
        target=_e(target),
        timestamp=now,
        extra_css=INTERACTIVE_CSS_EXTRA,
        summary_cards=summary_html,
        content="\n".join(sections) if sections else "<p style='color:#8b949e'>No data sections to display.</p>",
        js=INTERACTIVE_JS,
    )


def save_interactive_report(target: str, all_data: dict, output_dir: str = ".") -> dict:
    """Save an interactive HTML report alongside the standard reports."""
    from pathlib import Path
    import re
    safe_name = re.sub(r'[^\w\-.]', '_', target)[:80]
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    html_path = out / f"osint_{safe_name}_{ts}_interactive.html"
    html_content = build_interactive_html_report(target, all_data)
    html_path.write_text(html_content, encoding="utf-8")

    return {"interactive_html": str(html_path)}
