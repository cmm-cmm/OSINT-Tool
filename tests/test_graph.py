"""Tests for modules/graph.py — OSINT relationship graph builder."""
import json
import pytest


SAMPLE_SCAN_DATA = {
    "whois": {
        "whois": {
            "registrar": "Test Registrar Inc",
            "emails": ["admin@example.com"],
        }
    },
    "dns": {
        "records": {"A": ["93.184.216.34", "93.184.216.35"]},
        "subdomains": ["www.example.com", "mail.example.com", "api.example.com"],
    },
    "email": {
        "email": "test@example.com",
        "hibp": {
            "breaches": [
                {"name": "Adobe", "date": "2013-10-04"},
                {"name": "LinkedIn", "date": "2012-06-05"},
            ]
        }
    },
    "username": {
        "found": [
            {"platform": "Twitter", "url": "https://twitter.com/testuser"},
            {"platform": "GitHub", "url": "https://github.com/testuser"},
        ]
    },
    "ip": {
        "geo": {"data": {"query": "93.184.216.34", "country": "US"}},
    },
    "certs": {
        "certificates": [
            {"common_name": "www.example.com"},
            {"common_name": "mail.example.com"},
        ]
    },
    "social": {
        "twitter": {
            "exists": True,
            "linked_accounts": [
                {"handle": "otheraccount", "platform": "instagram"}
            ]
        }
    },
}


class TestNode:
    def test_id_is_hash(self):
        from modules.graph import Node
        n = Node("example.com", "example.com", "target")
        assert len(n.id) == 8
        assert n.id.isalnum()

    def test_same_input_same_id(self):
        from modules.graph import Node
        n1 = Node("example.com", "example.com", "target")
        n2 = Node("example.com", "different label", "ip")
        assert n1.id == n2.id  # ID is based on raw_id, not label

    def test_different_ids_for_different_inputs(self):
        from modules.graph import Node
        n1 = Node("example.com", "label", "target")
        n2 = Node("other.com", "label", "target")
        assert n1.id != n2.id

    def test_label_truncated_to_50(self):
        from modules.graph import Node
        long_label = "a" * 100
        n = Node("id", long_label, "target")
        assert len(n.label) <= 50

    def test_repr(self):
        from modules.graph import Node
        n = Node("id", "test", "ip")
        r = repr(n)
        assert "ip" in r
        assert "test" in r

    def test_stores_metadata(self):
        from modules.graph import Node
        n = Node("id", "label", "domain", extra="value", count=5)
        assert n.metadata.get("extra") == "value"
        assert n.metadata.get("count") == 5


class TestEdge:
    def test_basic_edge(self):
        from modules.graph import Node, Edge
        n1 = Node("a", "A", "target")
        n2 = Node("b", "B", "ip")
        e = Edge(n1, n2, "resolves_to")
        assert e.source is n1
        assert e.target is n2
        assert e.type == "resolves_to"

    def test_default_edge_type(self):
        from modules.graph import Node, Edge
        n1 = Node("a", "A", "target")
        n2 = Node("b", "B", "ip")
        e = Edge(n1, n2)
        assert e.type == "linked_to"


class TestOsintGraph:
    def test_empty_graph(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        assert g.nodes == {}
        assert g.edges == []

    def test_add_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n = g.add_node("example.com", "example.com", "target")
        assert n.id in g.nodes
        assert len(g.nodes) == 1

    def test_add_edge(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.add_node("a", "A", "target")
        n2 = g.add_node("b", "B", "ip")
        e = g.add_edge(n1, n2, "resolves_to")
        assert len(g.edges) == 1
        assert g.edges[0] is e

    def test_get_or_create_new(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n = g.get_or_create("example.com", "example.com", "target")
        assert n.id in g.nodes
        assert len(g.nodes) == 1

    def test_get_or_create_existing(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        n1 = g.get_or_create("example.com", "label1", "target")
        n2 = g.get_or_create("example.com", "label2", "target")
        assert n1.id == n2.id
        assert len(g.nodes) == 1  # Not duplicated


class TestFromScanData:
    def test_creates_target_node(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        assert len(g.nodes) == 1
        target_node = list(g.nodes.values())[0]
        assert target_node.type == "target"
        assert target_node.raw_id == "example.com"

    def test_returns_self_for_chaining(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        result = g.from_scan_data("example.com", {})
        assert result is g

    def test_processes_whois_registrar(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {"whois": {"whois": {"registrar": "ACME Corp"}}})
        node_labels = [n.label for n in g.nodes.values()]
        assert any("ACME" in label for label in node_labels)

    def test_processes_whois_emails(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"emails": ["admin@example.com"]}}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "email" in node_types

    def test_processes_dns_a_records(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "dns": {"records": {"A": ["1.2.3.4"]}, "subdomains": []}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "ip" in node_types

    def test_processes_dns_subdomains(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "dns": {"records": {}, "subdomains": ["www.example.com", "api.example.com"]}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "subdomain" in node_types

    def test_processes_username_platforms(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("testuser", {
            "username": {"found": [
                {"platform": "GitHub", "url": "https://github.com/testuser"}
            ]}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "platform" in node_types

    def test_processes_email_breaches(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("test@example.com", {
            "email": {
                "email": "test@example.com",
                "hibp": {"breaches": [{"name": "Adobe"}]}
            }
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "breach" in node_types

    def test_processes_ip_geo(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "ip": {"geo": {"data": {"query": "93.184.216.34"}}}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "ip" in node_types

    def test_processes_certificates(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "certs": {"certificates": [{"common_name": "www.example.com"}]}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "cert" in node_types

    def test_cert_same_as_target_skipped(self):
        """A cert with common_name == target should not add a new node."""
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "certs": {"certificates": [{"common_name": "example.com"}]}
        })
        # Should only have the target node
        assert all(n.raw_id != "cert:example.com" for n in g.nodes.values())

    def test_processes_social(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("testuser", {
            "social": {
                "twitter": {"exists": True, "linked_accounts": []}
            }
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "platform" in node_types

    def test_full_scan_data(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        assert len(g.nodes) > 1
        assert len(g.edges) > 0

    def test_whois_registrar_as_list(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"registrar": ["NameCheap Inc", "NameCheap"]}}
        })
        node_labels = [n.label for n in g.nodes.values()]
        assert any("NameCheap" in label for label in node_labels)

    def test_whois_email_as_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {
            "whois": {"whois": {"emails": "admin@example.com"}}
        })
        node_types = [n.type for n in g.nodes.values()]
        assert "email" in node_types


class TestToMermaid:
    def test_returns_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        result = g.to_mermaid()
        assert isinstance(result, str)

    def test_starts_with_flowchart(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        result = g.to_mermaid()
        assert result.startswith("flowchart LR")

    def test_contains_node_ids(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        result = g.to_mermaid()
        # Should contain node definitions
        assert "[" in result

    def test_empty_graph_mermaid(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        result = g.to_mermaid()
        assert "flowchart LR" in result


class TestToD3Data:
    def test_returns_dict(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        result = g.to_d3_data()
        assert isinstance(result, dict)

    def test_has_nodes_and_links(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        result = g.to_d3_data()
        assert "nodes" in result
        assert "links" in result

    def test_nodes_have_required_fields(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {"dns": {"records": {"A": ["1.2.3.4"]}}})
        data = g.to_d3_data()
        for node in data["nodes"]:
            assert "id" in node
            assert "label" in node
            assert "type" in node
            assert "color" in node

    def test_links_have_required_fields(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {"dns": {"records": {"A": ["1.2.3.4"]}}})
        data = g.to_d3_data()
        for link in data["links"]:
            assert "source" in link
            assert "target" in link
            assert "type" in link

    def test_json_serializable(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        data = g.to_d3_data()
        # Should not raise
        serialized = json.dumps(data)
        assert len(serialized) > 0


class TestToD3Html:
    def test_returns_string(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        html = g.to_d3_html()
        assert isinstance(html, str)

    def test_valid_html_doctype(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html("test target")
        assert "<!DOCTYPE html>" in html

    def test_contains_target_title(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        html = g.to_d3_html("example.com")
        assert "example.com" in html

    def test_xss_prevention_in_title(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html('<script>alert(1)</script>')
        assert "<script>alert(1)</script>" not in html

    def test_contains_d3_script(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        html = g.to_d3_html()
        assert "d3js.org" in html or "d3.v7" in html

    def test_contains_graph_data(self):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {"dns": {"records": {"A": ["1.2.3.4"]}}})
        html = g.to_d3_html()
        assert "graphData" in html


class TestSave:
    def test_save_d3_html(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", SAMPLE_SCAN_DATA)
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["d3"])
        assert "d3_html" in paths
        from pathlib import Path
        assert Path(paths["d3_html"]).exists()

    def test_save_mermaid(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["mermaid"])
        assert "mermaid" in paths
        from pathlib import Path
        assert Path(paths["mermaid"]).exists()

    def test_save_json(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        paths = g.save("example.com", output_dir=str(tmp_path), formats=["json"])
        assert "json" in paths
        from pathlib import Path
        p = Path(paths["json"])
        assert p.exists()
        data = json.loads(p.read_text())
        assert "nodes" in data
        assert "links" in data

    def test_save_all_formats(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("example.com", {})
        paths = g.save("example.com", output_dir=str(tmp_path))
        assert "d3_html" in paths
        assert "mermaid" in paths
        assert "json" in paths

    def test_save_sanitizes_filename(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        g.from_scan_data("test@example.com", {})
        paths = g.save("test@example.com", output_dir=str(tmp_path), formats=["json"])
        from pathlib import Path
        fname = Path(paths["json"]).name
        # @ should be replaced with _
        assert "@" not in fname

    def test_creates_output_dir(self, tmp_path):
        from modules.graph import OsintGraph
        g = OsintGraph()
        subdir = str(tmp_path / "nested" / "output")
        paths = g.save("target", output_dir=subdir, formats=["json"])
        from pathlib import Path
        assert Path(subdir).exists()


class TestBuildGraph:
    def test_returns_osint_graph(self):
        from modules.graph import build_graph, OsintGraph
        g = build_graph("example.com", SAMPLE_SCAN_DATA)
        assert isinstance(g, OsintGraph)

    def test_graph_has_nodes(self):
        from modules.graph import build_graph
        g = build_graph("example.com", SAMPLE_SCAN_DATA)
        assert len(g.nodes) > 0

    def test_graph_has_edges(self):
        from modules.graph import build_graph
        g = build_graph("example.com", SAMPLE_SCAN_DATA)
        assert len(g.edges) > 0


class TestNodeTypes:
    def test_all_node_types_defined(self):
        from modules.graph import NODE_TYPES
        expected = {"target", "domain", "ip", "email", "username", "platform", "breach",
                    "subdomain", "phone", "cert"}
        for ntype in expected:
            assert ntype in NODE_TYPES

    def test_node_types_have_required_fields(self):
        from modules.graph import NODE_TYPES
        for ntype, attrs in NODE_TYPES.items():
            assert "color" in attrs, f"{ntype} missing color"
            assert "shape" in attrs, f"{ntype} missing shape"
            assert "icon" in attrs, f"{ntype} missing icon"


class TestEdgeTypes:
    def test_all_edge_types_defined(self):
        from modules.graph import EDGE_TYPES
        expected = {"resolves_to", "has_subdomain", "registered_by",
                    "found_on", "exposed_in", "linked_to", "issued_for", "owns"}
        for etype in expected:
            assert etype in EDGE_TYPES

    def test_edge_types_have_label_and_color(self):
        from modules.graph import EDGE_TYPES
        for etype, attrs in EDGE_TYPES.items():
            assert "label" in attrs
            assert "color" in attrs