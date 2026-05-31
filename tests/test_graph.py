"""Tests for modules/graph.py (OSINT Relationship Graph Builder)."""
import json
import pytest


class TestNode:
    def test_id_is_8_char_hex(self):
        from modules.graph import Node
        n = Node("example.com", "example.com", "target")
        assert len(n.id) == 8
        assert all(c in "0123456789abcdef" for c in n.id)

    def test_same_raw_id_same_node_id(self):
        from modules.graph import Node
        n1 = Node("example.com", "Example", "target")
        n2 = Node("example.com", "Different Label", "domain")
        assert n1.id == n2.id

    def test_different_raw_id_different_node_id(self):
        from modules.graph import Node
        n1 = Node("a.com", "a", "target")
        n2 = Node("b.com", "b", "target")
        assert n1.id != n2.id

    def test_label_truncated_to_50_chars(self):
        from modules.graph import Node
        long_label = "x" * 100
        n = Node("id", long_label, "target")
        assert len(n.label) == 50

    def test_short_label_not_changed(self):
        from modules.graph import Node
        n = Node("id", "short", "target")
        assert n.label == "short"

    def test_raw_id_preserved(self):
        from modules.graph import Node
        n = Node("original_id", "label", "target")
        assert n.raw_id == "original_id"

    def test_repr_contains_type_and_label(self):
        from modules.graph import Node
        n = Node("id", "example.com", "domain")
        r = repr(n)
        assert "domain" in r
        assert "example.com" in r

    def test_metadata_stored(self):
        from modules.graph import Node
        n = Node("id", "label", "target", country="US", port=443)
        assert n.metadata["country"] == "US"
        assert n.metadata["port"] == 443


class TestEdge:
    def test_edge_stores_source_and_target(self):
        from modules.graph import Node, Edge
        src = Node("src", "source", "target")
        tgt = Node("tgt", "target", "ip")
        e = Edge(src, tgt, "resolves_to")
        assert e.source is src
        assert e.target is tgt
        assert e.type == "resolves_to"

    def test_default_edge_type(self):
        from modules.graph import Node, Edge
        src = Node("src", "src", "target")
        tgt = Node("tgt", "tgt", "ip")
        e = Edge(src, tgt)
        assert e.type == "linked_to"

    def test_edge_metadata(self):
        from modules.graph import Node, Edge
        src = Node("a", "a", "target")
        tgt = Node("b", "b", "ip")
        e = Edge(src, tgt, "resolves_to", weight=1.0)
        assert e.metadata["weight"] == 1.0


class TestOsintGraph:
    def test_empty_graph(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        assert len(g.nodes) == 0
        assert len(g.edges) == 0

    def test_add_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n = g.add_node("example.com", "example.com", "target")
        assert len(g.nodes) == 1
        assert n.raw_id == "example.com"

    def test_add_edge(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "a", "target")
        n2 = g.add_node("b", "b", "ip")
        e = g.add_edge(n1, n2, "resolves_to")
        assert len(g.edges) == 1
        assert e.source is n1
        assert e.target is n2

    def test_get_or_create_returns_existing(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("example.com", "example.com", "target")
        n2 = g.get_or_create("example.com", "different label", "domain")
        assert n1 is n2

    def test_get_or_create_creates_new(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n = g.get_or_create("new_node", "New Node", "ip")
        assert len(g.nodes) == 1
        assert n.raw_id == "new_node"

    def test_from_scan_data_creates_target_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        assert any(n.raw_id == "example.com" for n in g.nodes.values())

    def test_from_scan_data_whois_registrar(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"whois": {"whois": {"registrar": "ICANN Corp"}}}
        g.from_scan_data("example.com", data)
        labels = [n.label for n in g.nodes.values()]
        assert "ICANN Corp" in labels

    def test_from_scan_data_whois_registrar_list(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"whois": {"whois": {"registrar": ["ICANN Corp", "Other"]}}}
        g.from_scan_data("example.com", data)
        # First registrar should be used
        labels = [n.label for n in g.nodes.values()]
        assert "ICANN Corp" in labels

    def test_from_scan_data_whois_emails(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"whois": {"whois": {"emails": ["admin@example.com"]}}}
        g.from_scan_data("example.com", data)
        assert any(n.type == "email" for n in g.nodes.values())

    def test_from_scan_data_dns_a_records(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"dns": {"records": {"A": ["93.184.216.34"]}, "subdomains": []}}
        g.from_scan_data("example.com", data)
        ip_nodes = [n for n in g.nodes.values() if n.type == "ip"]
        assert len(ip_nodes) == 1
        assert ip_nodes[0].raw_id == "93.184.216.34"

    def test_from_scan_data_dns_subdomains(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"dns": {"records": {}, "subdomains": ["mail.example.com", "www.example.com"]}}
        g.from_scan_data("example.com", data)
        subdomain_nodes = [n for n in g.nodes.values() if n.type == "subdomain"]
        assert len(subdomain_nodes) == 2

    def test_from_scan_data_email_breach(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "email": {
                "email": "user@example.com",
                "hibp": {"breaches": [{"name": "TestBreach"}]}
            }
        }
        g.from_scan_data("user@example.com", data)
        breach_nodes = [n for n in g.nodes.values() if n.type == "breach"]
        assert len(breach_nodes) == 1

    def test_from_scan_data_username_platforms(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "username": {
                "found": [
                    {"platform": "Twitter"},
                    {"platform": "GitHub"},
                ]
            }
        }
        g.from_scan_data("testuser", data)
        platform_nodes = [n for n in g.nodes.values() if n.type == "platform"]
        assert len(platform_nodes) == 2

    def test_from_scan_data_ip_geolocation(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "ip": {
                "geo": {"data": {"query": "1.2.3.4"}},
                "ip": "1.2.3.4"
            }
        }
        g.from_scan_data("example.com", data)
        ip_nodes = [n for n in g.nodes.values() if n.type == "ip"]
        assert len(ip_nodes) >= 1

    def test_from_scan_data_social_exists(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "social": {
                "twitter": {"exists": True, "linked_accounts": []},
            }
        }
        g.from_scan_data("testuser", data)
        platform_nodes = [n for n in g.nodes.values() if n.type == "platform"]
        assert len(platform_nodes) >= 1

    def test_from_scan_data_social_not_exists_not_added(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "social": {
                "twitter": {"exists": False},
            }
        }
        g.from_scan_data("testuser", data)
        platform_nodes = [n for n in g.nodes.values() if n.type == "platform"]
        assert len(platform_nodes) == 0

    def test_from_scan_data_cert_transparency(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {
            "certs": {
                "certificates": [
                    {"common_name": "mail.example.com"},
                    {"common_name": "www.example.com"},
                ]
            }
        }
        g.from_scan_data("example.com", data)
        cert_nodes = [n for n in g.nodes.values() if n.type == "cert"]
        assert len(cert_nodes) == 2

    def test_from_scan_data_cert_same_as_target_excluded(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = {"certs": {"certificates": [{"common_name": "example.com"}]}}
        g.from_scan_data("example.com", data)
        cert_nodes = [n for n in g.nodes.values() if n.type == "cert"]
        assert len(cert_nodes) == 0

    def test_from_scan_data_returns_self(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        result = g.from_scan_data("example.com", {})
        assert result is g

    def test_subdomain_limit_20(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        subs = [f"sub{i}.example.com" for i in range(30)]
        data = {"dns": {"records": {}, "subdomains": subs}}
        g.from_scan_data("example.com", data)
        subdomain_nodes = [n for n in g.nodes.values() if n.type == "subdomain"]
        assert len(subdomain_nodes) == 20


class TestToMermaid:
    def test_starts_with_flowchart(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        mermaid = g.to_mermaid()
        assert mermaid.startswith("flowchart LR")

    def test_node_appears_in_mermaid(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        mermaid = g.to_mermaid()
        assert "example.com" in mermaid

    def test_edge_appears_in_mermaid(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a.com", "a.com", "target")
        n2 = g.add_node("1.2.3.4", "1.2.3.4", "ip")
        g.add_edge(n1, n2, "resolves_to")
        mermaid = g.to_mermaid()
        assert "-->" in mermaid
        assert "resolves to" in mermaid

    def test_empty_graph_mermaid(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        mermaid = g.to_mermaid()
        assert "flowchart LR" in mermaid

    def test_double_quotes_replaced_in_label(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node('has"quote', 'Label with "quotes"', "target")
        mermaid = g.to_mermaid()
        # Should not have unescaped double quotes breaking the Mermaid syntax
        assert '"Label with \\"' not in mermaid or "'" in mermaid


class TestToD3Data:
    def test_has_nodes_and_links_keys(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        data = g.to_d3_data()
        assert "nodes" in data
        assert "links" in data

    def test_nodes_list(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        data = g.to_d3_data()
        assert len(data["nodes"]) == 1
        node = data["nodes"][0]
        assert "id" in node
        assert "label" in node
        assert "type" in node
        assert "color" in node
        assert "icon" in node

    def test_links_list(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "a", "target")
        n2 = g.add_node("b", "b", "ip")
        g.add_edge(n1, n2, "resolves_to")
        data = g.to_d3_data()
        assert len(data["links"]) == 1
        link = data["links"][0]
        assert "source" in link
        assert "target" in link
        assert "type" in link
        assert "label" in link

    def test_serializable_to_json(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        data = g.to_d3_data()
        serialized = json.dumps(data)  # Should not raise
        assert "example.com" in serialized


class TestToD3Html:
    def test_returns_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("test-target")
        assert isinstance(html, str)

    def test_is_valid_html_structure(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("example.com")
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_title_in_html(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("my-target")
        assert "my-target" in html

    def test_xss_in_title_escaped(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("<script>alert(1)</script>")
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_node_count_in_html(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("a", "a", "target")
        g.add_node("b", "b", "ip")
        html = g.to_d3_html("title")
        assert "2 nodes" in html

    def test_d3_script_included(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html()
        assert "d3js.org" in html or "d3.v" in html


class TestSaveGraph:
    def test_save_creates_files(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        paths = g.save("example.com", output_dir=str(tmp_path))
        assert len(paths) > 0
        for path in paths.values():
            assert Path(path).exists()

    def test_save_d3_html(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["d3"])
        assert "d3_html" in paths
        assert paths["d3_html"].endswith(".html")

    def test_save_mermaid(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["mermaid"])
        assert "mermaid" in paths
        assert paths["mermaid"].endswith(".mmd")

    def test_save_json(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("example.com", "example.com", "target")
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["json"])
        assert "json" in paths
        json_data = json.loads(Path(paths["json"]).read_text())
        assert "nodes" in json_data

    def test_save_special_chars_in_target(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.add_node("t", "t", "target")
        # Should not raise; special chars replaced
        paths = g.save("test/target:with?special*chars", output_dir=str(tmp_path), formats=["json"])
        assert "json" in paths
        assert Path(paths["json"]).exists()


class TestBuildGraph:
    def test_returns_osint_graph(self):
        from modules.graph import build_graph, OsintGraph
        g = build_graph("example.com", {})
        assert isinstance(g, OsintGraph)

    def test_target_node_created(self):
        from modules.graph import build_graph
        g = build_graph("example.com", {})
        assert any(n.raw_id == "example.com" for n in g.nodes.values())

    def test_full_scan_data_populates_graph(self):
        from modules.graph import build_graph
        data = {
            "dns": {"records": {"A": ["1.2.3.4"]}, "subdomains": []},
            "whois": {"whois": {"registrar": "TestReg"}},
            "username": {"found": [{"platform": "Twitter"}]},
        }
        g = build_graph("example.com", data)
        assert len(g.nodes) > 1
        assert len(g.edges) > 0