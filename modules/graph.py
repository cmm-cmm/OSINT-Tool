"""
OSINT Relationship Graph Builder

Generates relationship graphs from OSINT scan results in Mermaid and D3.js formats.
Use this to visualize connections between targets, platforms, and discovered data.
"""
from __future__ import annotations
import json
import hashlib
import html as _html
import datetime
import logging

logger = logging.getLogger("osint.graph")


def _e(v) -> str:
    return _html.escape(str(v), quote=True)


# ── Node and Edge types ───────────────────────────────────────────────────────

NODE_TYPES = {
    "target":    {"color": "#58a6ff", "shape": "circle",   "icon": "🎯"},
    "domain":    {"color": "#79c0ff", "shape": "rectangle","icon": "🌐"},
    "ip":        {"color": "#d29922", "shape": "hexagon",  "icon": "🖥"},
    "email":     {"color": "#3fb950", "shape": "ellipse",  "icon": "📧"},
    "username":  {"color": "#a371f7", "shape": "diamond",  "icon": "👤"},
    "platform":  {"color": "#e3b341", "shape": "rectangle","icon": "📱"},
    "breach":    {"color": "#f85149", "shape": "rectangle","icon": "💀"},
    "subdomain": {"color": "#8b949e", "shape": "circle",   "icon": "🔗"},
    "phone":     {"color": "#f0883e", "shape": "ellipse",  "icon": "📱"},
    "cert":      {"color": "#56d364", "shape": "rectangle","icon": "🔒"},
}

EDGE_TYPES = {
    "resolves_to":   {"label": "resolves to",   "color": "#388bfd"},
    "has_subdomain": {"label": "has subdomain", "color": "#8b949e"},
    "registered_by": {"label": "registered by", "color": "#79c0ff"},
    "found_on":      {"label": "found on",      "color": "#3fb950"},
    "exposed_in":    {"label": "exposed in",    "color": "#f85149"},
    "linked_to":     {"label": "linked to",     "color": "#a371f7"},
    "issued_for":    {"label": "issued for",    "color": "#56d364"},
    "owns":          {"label": "owns",          "color": "#d29922"},
}


class Node:
    def __init__(self, node_id: str, label: str, node_type: str = "target", **metadata):
        self.id = hashlib.sha256(node_id.encode()).hexdigest()[:8]
        self.raw_id = node_id
        self.label = label[:50]
        self.type = node_type
        self.metadata = metadata

    def __repr__(self):
        return f"Node({self.type}: {self.label!r})"


class Edge:
    def __init__(self, source: Node, target: Node, edge_type: str = "linked_to", **metadata):
        self.source = source
        self.target = target
        self.type = edge_type
        self.metadata = metadata


class OsintGraph:
    """
    Builds and exports OSINT relationship graphs.

    Usage::
        graph = OsintGraph()
        graph.from_scan_data("example.com", all_data)
        mermaid = graph.to_mermaid()
        html = graph.to_d3_html()
    """

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, raw_id: str, label: str, node_type: str = "target", **meta) -> Node:
        node = Node(raw_id, label, node_type, **meta)
        self.nodes[node.id] = node
        return node

    def add_edge(self, source: Node, target: Node, edge_type: str = "linked_to", **meta) -> Edge:
        edge = Edge(source, target, edge_type, **meta)
        self.edges.append(edge)
        return edge

    def get_or_create(self, raw_id: str, label: str, node_type: str) -> Node:
        temp = Node(raw_id, label, node_type)
        if temp.id in self.nodes:
            return self.nodes[temp.id]
        return self.add_node(raw_id, label, node_type)

    def from_scan_data(self, target: str, all_data: dict) -> "OsintGraph":
        """Parse scan results dict and populate the graph with nodes and edges."""
        target_node = self.add_node(target, target, "target")

        # WHOIS
        if "whois" in all_data:
            w = all_data["whois"].get("whois", {})
            registrar = w.get("registrar")
            if registrar:
                if isinstance(registrar, list):
                    registrar = registrar[0]
                reg_node = self.get_or_create(str(registrar), str(registrar)[:40], "domain")
                self.add_edge(target_node, reg_node, "registered_by")
            emails = w.get("emails", [])
            if isinstance(emails, str):
                emails = [emails]
            for email in (emails or []):
                if email and "@" in str(email):
                    em_node = self.get_or_create(str(email), str(email), "email")
                    self.add_edge(target_node, em_node, "registered_by")

        # DNS
        if "dns" in all_data:
            records = all_data["dns"].get("records", {})
            for ip in records.get("A", []):
                ip_node = self.get_or_create(ip, ip, "ip")
                self.add_edge(target_node, ip_node, "resolves_to")
            for sub in all_data["dns"].get("subdomains", [])[:20]:
                sub_node = self.get_or_create(sub, sub, "subdomain")
                self.add_edge(target_node, sub_node, "has_subdomain")

        # Email
        if "email" in all_data:
            email_val = all_data["email"].get("email", "")
            if email_val:
                email_node = self.get_or_create(email_val, email_val, "email")
                self.add_edge(target_node, email_node, "linked_to")
                hibp = all_data["email"].get("hibp", {})
                for breach in (hibp.get("breaches", []) or [])[:10]:
                    b_name = breach.get("name", "")
                    if b_name:
                        b_node = self.get_or_create(f"breach:{b_name}", b_name, "breach")
                        self.add_edge(email_node, b_node, "exposed_in")

        # Username
        if "username" in all_data:
            found = all_data["username"].get("found", [])
            for item in found[:20]:
                plat = item.get("platform", "")
                if plat:
                    p_node = self.get_or_create(f"platform:{plat}", plat, "platform")
                    self.add_edge(target_node, p_node, "found_on")

        # IP
        if "ip" in all_data:
            geo = all_data["ip"].get("geo", {}).get("data", {})
            ip_val = geo.get("query") or all_data["ip"].get("ip", "")
            if ip_val:
                ip_node = self.get_or_create(ip_val, ip_val, "ip")
                self.add_edge(target_node, ip_node, "resolves_to")

        # Certs
        if "certs" in all_data:
            for cert in (all_data["certs"].get("certificates", []) or [])[:15]:
                cn = cert.get("common_name", "")
                if cn and cn != target:
                    c_node = self.get_or_create(f"cert:{cn}", cn, "cert")
                    self.add_edge(target_node, c_node, "issued_for")

        # Social media
        if "social" in all_data:
            for platform, data in all_data["social"].items():
                if isinstance(data, dict) and data.get("exists"):
                    p_node = self.get_or_create(f"social:{platform}", platform.title(), "platform")
                    self.add_edge(target_node, p_node, "found_on")
                    linked = data.get("linked_accounts", [])
                    for acct in (linked or [])[:5]:
                        handle = acct.get("handle", "")
                        plat2 = acct.get("platform", "")
                        if handle:
                            a_node = self.get_or_create(f"{plat2}:{handle}", f"@{handle}", "username")
                            self.add_edge(p_node, a_node, "linked_to")

        return self

    def to_mermaid(self) -> str:
        """Export graph as a Mermaid flowchart diagram."""
        lines = ["flowchart LR"]
        node_styles = {
            "target":    'style {id} fill:#1c2333,stroke:#58a6ff,color:#58a6ff',
            "domain":    'style {id} fill:#1c2333,stroke:#79c0ff,color:#79c0ff',
            "ip":        'style {id} fill:#1c2333,stroke:#d29922,color:#d29922',
            "email":     'style {id} fill:#1c2333,stroke:#3fb950,color:#3fb950',
            "username":  'style {id} fill:#1c2333,stroke:#a371f7,color:#a371f7',
            "platform":  'style {id} fill:#1c2333,stroke:#e3b341,color:#e3b341',
            "breach":    'style {id} fill:#3a0a0a,stroke:#f85149,color:#f85149',
            "subdomain": 'style {id} fill:#1c2333,stroke:#8b949e,color:#8b949e',
            "cert":      'style {id} fill:#1c2333,stroke:#56d364,color:#56d364',
        }

        for node in self.nodes.values():
            label = node.label.replace('"', "'")
            icon = NODE_TYPES.get(node.type, {}).get("icon", "")
            lines.append(f'    {node.id}["{icon} {label}"]')
            style_tmpl = node_styles.get(node.type)
            if style_tmpl:
                lines.append(f"    {style_tmpl.format(id=node.id)}")

        for edge in self.edges:
            edge_info = EDGE_TYPES.get(edge.type, {})
            label = edge_info.get("label", edge.type)
            lines.append(f'    {edge.source.id} -->|{label}| {edge.target.id}')

        return "\n".join(lines)

    def to_d3_data(self) -> dict:
        """Export graph as D3.js-compatible JSON (nodes + links)."""
        return {
            "nodes": [
                {
                    "id": n.id,
                    "label": n.label,
                    "type": n.type,
                    "color": NODE_TYPES.get(n.type, {}).get("color", "#8b949e"),
                    "icon": NODE_TYPES.get(n.type, {}).get("icon", ""),
                    **{k: str(v) for k, v in n.metadata.items()},
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "source": e.source.id,
                    "target": e.target.id,
                    "type": e.type,
                    "label": EDGE_TYPES.get(e.type, {}).get("label", e.type),
                    "color": EDGE_TYPES.get(e.type, {}).get("color", "#8b949e"),
                }
                for e in self.edges
            ],
        }

    def to_d3_html(self, title: str = "OSINT Graph") -> str:
        """Export a standalone interactive D3.js HTML graph."""
        # ensure_ascii=True + replace </ to prevent script-injection via </script>
        data = json.dumps(self.to_d3_data(), ensure_ascii=True).replace("</", "<\\/")
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>OSINT Graph — {_e(title)}</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    body {{ margin: 0; background: #0d1117; font-family: monospace; color: #e6edf3; }}
    #header {{ padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d;
               display: flex; justify-content: space-between; align-items: center; }}
    #header h1 {{ font-size: 1rem; color: #58a6ff; margin: 0; }}
    #header .meta {{ font-size: 0.78rem; color: #8b949e; }}
    #graph {{ width: 100vw; height: calc(100vh - 52px); }}
    svg {{ width: 100%; height: 100%; }}
    .node circle {{ stroke-width: 2; cursor: pointer; }}
    .node text {{ font-size: 11px; fill: #e6edf3; pointer-events: none; }}
    .link {{ stroke-opacity: 0.6; }}
    .link-label {{ font-size: 9px; fill: #8b949e; }}
    #tooltip {{ position: fixed; background: #161b22; border: 1px solid #30363d;
                border-radius: 6px; padding: 8px 12px; font-size: 0.8rem;
                pointer-events: none; display: none; z-index: 100; max-width: 220px; }}
    #legend {{ position: fixed; bottom: 16px; left: 16px; background: #161b22;
               border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px;
               font-size: 0.75rem; }}
    .legend-item {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; }}
    .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  </style>
</head>
<body>
<div id="header">
  <h1>🔍 OSINT Relationship Graph — {_e(title)}</h1>
  <div class="meta">Generated {now} &nbsp;|&nbsp; {len(self.nodes)} nodes &nbsp;|&nbsp; {len(self.edges)} connections</div>
</div>
<div id="graph"></div>
<div id="tooltip"></div>
<div id="legend">
  {"".join(f'<div class="legend-item"><div class="legend-dot" style="background:{v["color"]}"></div>{v["icon"]} {k}</div>'
           for k, v in NODE_TYPES.items() if k != "target")}
</div>
<script>
const graphData = {data};

const width = window.innerWidth, height = window.innerHeight - 52;
const svg = d3.select("#graph").append("svg")
  .attr("viewBox", [0, 0, width, height]);

const defs = svg.append("defs");
defs.append("marker").attr("id", "arrow").attr("viewBox", "0 -5 10 10")
  .attr("refX", 20).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6)
  .attr("orient", "auto").append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#30363d");

const sim = d3.forceSimulation(graphData.nodes)
  .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(100))
  .force("charge", d3.forceManyBody().strength(-200))
  .force("center", d3.forceCenter(width / 2, height / 2))
  .force("collide", d3.forceCollide(30));

const link = svg.append("g").selectAll("line")
  .data(graphData.links).join("line")
  .attr("class", "link")
  .attr("stroke", d => d.color || "#30363d")
  .attr("stroke-width", 1.5)
  .attr("marker-end", "url(#arrow)");

const node = svg.append("g").selectAll("g")
  .data(graphData.nodes).join("g").attr("class", "node")
  .call(d3.drag()
    .on("start", (e, d) => {{ if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
    .on("drag",  (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
    .on("end",   (e, d) => {{ if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }}));

node.append("circle").attr("r", d => d.type === "target" ? 16 : 10)
  .attr("fill", "#0d1117").attr("stroke", d => d.color || "#58a6ff");

node.append("text").attr("dy", "0.35em").attr("x", d => d.type === "target" ? 20 : 14)
  .text(d => (d.icon || "") + " " + (d.label.length > 20 ? d.label.slice(0,18)+"…" : d.label));

const tooltip = document.getElementById("tooltip");
node.on("mouseover", (e, d) => {{
  tooltip.style.display = "block";
  tooltip.style.left = (e.clientX + 12) + "px";
  tooltip.style.top = (e.clientY - 10) + "px";
  tooltip.textContent = '';
  const s = document.createElement('strong'); s.style.color = d.color;
  s.textContent = (d.icon || '') + ' ' + d.label;
  tooltip.appendChild(s);
  tooltip.appendChild(document.createTextNode(' — ' + d.type));
}}).on("mouseout", () => tooltip.style.display = "none");

sim.on("tick", () => {{
  link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
  node.attr("transform", d => `translate(${{d.x}},${{d.y}})`);
}});

// Zoom + pan
svg.call(d3.zoom().scaleExtent([0.2, 4])
  .on("zoom", e => svg.selectAll("g").attr("transform", e.transform)));
</script>
</body>
</html>"""

    def save(self, target: str, output_dir: str = ".", formats: list[str] | None = None) -> dict[str, str]:
        """Save graph in specified formats. Returns dict of format -> path."""
        import re
        from pathlib import Path
        active_formats = formats or ["d3", "mermaid", "json"]
        safe = re.sub(r'[^\w\-.]', '_', target)[:60]
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        paths = {}

        if "d3" in active_formats:
            p = out / f"graph_{safe}_{ts}.html"
            p.write_text(self.to_d3_html(target), encoding="utf-8")
            paths["d3_html"] = str(p)

        if "mermaid" in active_formats:
            p = out / f"graph_{safe}_{ts}.mmd"
            p.write_text(self.to_mermaid(), encoding="utf-8")
            paths["mermaid"] = str(p)

        if "json" in active_formats:
            p = out / f"graph_{safe}_{ts}.json"
            p.write_text(json.dumps(self.to_d3_data(), indent=2, ensure_ascii=False), encoding="utf-8")
            paths["json"] = str(p)

        return paths


def build_graph(target: str, all_data: dict) -> OsintGraph:
    """Convenience function: build and return an OsintGraph from scan data."""
    g = OsintGraph()
    g.from_scan_data(target, all_data)
    return g
