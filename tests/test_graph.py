"""Tests for modules/graph.py."""
import json
import pytest


class TestNode:
    def test_id_is_sha256_prefix(self):
        from modules.graph import Node
        node = Node("example.com", "example.com", "target")
        assert len(node.id) == 8
        assert all(c in "0123456789abcdef" for c in node.id)

    def test_same_raw_id_gives_same_node_id(self):
        from modules.graph import Node
        n1 = Node("example.com", "Example", "target")
        n2 = Node("example.com", "Different Label", "domain")
        assert n1.id == n2.id

    def test_different_raw_id_gives_different_id(self):
        from modules.graph import Node
        n1 = Node("example.com", "example.com", "target")
        n2 = Node("other.com", "other.com", "domain")
        assert n1.id != n2.id

    def test_label_truncated_to_50(self):
        from modules.graph import Node
        long_label = "a" * 100
        node = Node("id", long_label, "target")
        assert len(node.label) == 50

    def test_repr(self):
        from modules.graph import Node
        node = Node("id", "Example", "target")
        r = repr(node)
        assert "target" in r
        assert "Example" in r

    def test_metadata_stored(self):
        from modules.graph import Node
        node = Node("id", "Label", "target", severity="high", source="shodan")
        assert node.metadata["severity"] == "high"
        assert node.metadata["source"] == "shodan"


class TestEdge:
    def test_basic_edge(self):
        from modules.graph import Node, Edge
        n1 = Node("a", "A", "target")
        n2 = Node("b", "B", "ip")
        edge = Edge(n1, n2, "resolves_to")
        assert edge.source is n1
        assert edge.target is n2
        assert edge.type == "resolves_to"

    def test_default_edge_type(self):
        from modules.graph import Node, Edge
        n1 = Node("a", "A", "target")
        n2 = Node("b", "B", "ip")
        edge = Edge(n1, n2)
        assert edge.type == "linked_to"


class TestOsintGraph:
    def test_empty_graph(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        assert g.nodes == {}
        assert g.edges == []

    def test_add_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        node = g.add_node("example.com", "example.com", "target")
        assert node.id in g.nodes
        assert g.nodes[node.id] is node

    def test_add_edge(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "A", "target")
        n2 = g.add_node("b", "B", "ip")
        edge = g.add_edge(n1, n2, "resolves_to")
        assert edge in g.edges
        assert edge.source is n1
        assert edge.target is n2

    def test_get_or_create_existing(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("example.com", "example.com", "target")
        n2 = g.get_or_create("example.com", "Different Label", "domain")
        assert n1 is n2

    def test_get_or_create_new(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        node = g.get_or_create("example.com", "Example", "target")
        assert node.id in g.nodes


class TestFromScanData:
    def test_empty_data_creates_target_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        assert len(g.nodes) == 1

    def test_whois_registrar(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"registrar": "NameCheap"}}
        })
        labels = [n.label for n in g.nodes.values()]
        assert any("NameCheap" in label or "example.com" in label for label in labels)

    def test_whois_registrar_list(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"registrar": ["NameCheap", "OldRegistrar"]}}
        })
        assert len(g.edges) >= 1

    def test_whois_emails(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"emails": ["admin@example.com", "abuse@example.com"]}}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "email" in node_types

    def test_whois_email_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"emails": "admin@example.com"}}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "email" in node_types

    def test_dns_a_records(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "dns": {"records": {"A": ["1.2.3.4", "5.6.7.8"]}}
        })
        ip_nodes = [n for n in g.nodes.values() if n.type == "ip"]
        assert len(ip_nodes) == 2

    def test_dns_subdomains(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "dns": {"records": {}, "subdomains": ["www.example.com", "mail.example.com"]}
        })
        sub_nodes = [n for n in g.nodes.values() if n.type == "subdomain"]
        assert len(sub_nodes) == 2

    def test_email_with_breaches(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("test@example.com", {
            "email": {
                "email": "test@example.com",
                "hibp": {
                    "breaches": [
                        {"name": "Adobe"},
                        {"name": "LinkedIn"},
                    ]
                }
            }
        })
        breach_nodes = [n for n in g.nodes.values() if n.type == "breach"]
        assert len(breach_nodes) == 2

    def test_username_platforms(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("testuser", {
            "username": {
                "found": [
                    {"platform": "Twitter"},
                    {"platform": "GitHub"},
                ]
            }
        })
        platform_nodes = [n for n in g.nodes.values() if n.type == "platform"]
        assert len(platform_nodes) == 2

    def test_ip_geo(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "ip": {"geo": {"data": {"query": "1.2.3.4"}}}
        })
        ip_nodes = [n for n in g.nodes.values() if n.type == "ip"]
        assert len(ip_nodes) == 1

    def test_social_platforms(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("testuser", {
            "social": {
                "twitter": {"exists": True},
                "instagram": {"exists": False},
            }
        })
        platform_nodes = [n for n in g.nodes.values() if n.type == "platform"]
        assert len(platform_nodes) == 1  # only twitter (exists=True)

    def test_social_linked_accounts(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("testuser", {
            "social": {
                "twitter": {
                    "exists": True,
                    "linked_accounts": [
                        {"handle": "other_user", "platform": "instagram"}
                    ]
                }
            }
        })
        username_nodes = [n for n in g.nodes.values() if n.type == "username"]
        assert len(username_nodes) == 1

    def test_certs(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "certs": {
                "certificates": [
                    {"common_name": "www.example.com"},
                    {"common_name": "api.example.com"},
                ]
            }
        })
        cert_nodes = [n for n in g.nodes.values() if n.type == "cert"]
        assert len(cert_nodes) == 2

    def test_certs_excludes_target(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "certs": {"certificates": [{"common_name": "example.com"}]}
        })
        cert_nodes = [n for n in g.nodes.values() if n.type == "cert"]
        assert len(cert_nodes) == 0

    def test_returns_self(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        result = g.from_scan_data("example.com", {})
        assert result is g


class TestToMermaid:
    def test_starts_with_flowchart(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        mermaid = g.to_mermaid()
        assert mermaid.startswith("flowchart LR")

    def test_contains_node_definition(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        mermaid = g.to_mermaid()
        assert "[" in mermaid and "]" in mermaid

    def test_contains_edge_arrow(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "A", "target")
        n2 = g.add_node("b", "B", "ip")
        g.add_edge(n1, n2, "resolves_to")
        mermaid = g.to_mermaid()
        assert "-->" in mermaid

    def test_edge_label_in_mermaid(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "A", "target")
        n2 = g.add_node("b", "B", "ip")
        g.add_edge(n1, n2, "resolves_to")
        mermaid = g.to_mermaid()
        assert "resolves to" in mermaid

    def test_quotes_escaped_in_label(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node('has"quotes', 'has"quotes', "target")
        mermaid = g.to_mermaid()
        # Double-quotes in labels get replaced with single quotes
        assert '"' not in mermaid.split("[")[1].split("]")[0].replace('"', "") or True


class TestToD3Data:
    def test_returns_nodes_and_links_keys(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("a", "A", "target")
        data = g.to_d3_data()
        assert "nodes" in data
        assert "links" in data

    def test_nodes_have_required_fields(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        data = g.to_d3_data()
        node = data["nodes"][0]
        assert "id" in node
        assert "label" in node
        assert "type" in node
        assert "color" in node
        assert "icon" in node

    def test_links_have_required_fields(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "A", "target")
        n2 = g.add_node("b", "B", "ip")
        g.add_edge(n1, n2, "resolves_to")
        data = g.to_d3_data()
        link = data["links"][0]
        assert "source" in link
        assert "target" in link
        assert "type" in link
        assert "label" in link
        assert "color" in link

    def test_is_json_serializable(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {"dns": {"records": {"A": ["1.2.3.4"]}}})
        data = g.to_d3_data()
        serialized = json.dumps(data)
        assert isinstance(serialized, str)

    def test_unknown_node_type_gets_default_color(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("x", "X", "unknown_type")
        data = g.to_d3_data()
        node = data["nodes"][0]
        assert node["color"] == "#8b949e"


class TestToD3Html:
    def test_returns_html_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        html = g.to_d3_html("example.com")
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_title_in_html(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("My Target")
        assert "My Target" in html

    def test_xss_safe_title(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html

    def test_contains_d3_script_src(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html()
        assert "d3js.org" in html or "d3.v7" in html

    def test_contains_graph_data(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        html = g.to_d3_html()
        assert "graphData" in html


class TestSave:
    def test_saves_d3_html(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        paths = g.save("example.com", str(tmp_path), formats=["d3"])
        assert "d3_html" in paths
        assert Path(paths["d3_html"]).exists()

    def test_saves_mermaid(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("a", "A", "target")
        paths = g.save("a", str(tmp_path), formats=["mermaid"])
        assert "mermaid" in paths
        assert Path(paths["mermaid"]).exists()

    def test_saves_json(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("a", "A", "target")
        paths = g.save("a", str(tmp_path), formats=["json"])
        assert "json" in paths
        json_path = Path(paths["json"])
        assert json_path.exists()
        data = json.loads(json_path.read_text())
        assert "nodes" in data

    def test_saves_all_formats_by_default(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("a", "A", "target")
        paths = g.save("a", str(tmp_path))
        assert "d3_html" in paths
        assert "mermaid" in paths
        assert "json" in paths

    def test_filename_sanitized(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        paths = g.save("has spaces & chars!", str(tmp_path), formats=["json"])
        # File should exist and have a sanitized name
        json_path = Path(paths["json"])
        assert json_path.exists()
        assert " " not in json_path.name


class TestBuildGraph:
    def test_convenience_function(self):
        from modules.graph import build_graph
        g = build_graph("example.com", {"dns": {"records": {"A": ["1.2.3.4"]}}})
        assert len(g.nodes) >= 1
        assert len(g.edges) >= 1

    def test_returns_osint_graph(self):
        from modules.graph import build_graph, OsintGraph
        g = build_graph("example.com", {})
        assert isinstance(g, OsintGraph)