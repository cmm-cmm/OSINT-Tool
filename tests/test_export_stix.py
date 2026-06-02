"""Tests for modules/export_stix.py — STIX 2.1 and MISP export."""
import pytest


class TestToStixBundle:
    def test_bundle_structure(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("example.com", {})
        assert bundle["type"] == "bundle"
        assert "id" in bundle
        assert "objects" in bundle
        assert isinstance(bundle["objects"], list)

    def test_bundle_has_identity_object(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("example.com", {})
        types = [obj["type"] for obj in bundle["objects"]]
        assert "identity" in types

    def test_bundle_includes_domain_object(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("example.com", {})
        types = [obj["type"] for obj in bundle["objects"]]
        assert "domain-name" in types

    def test_bundle_includes_ip_from_data(self):
        from modules.export_stix import to_stix_bundle
        data = {"ip": {"ip": "1.2.3.4"}}
        bundle = to_stix_bundle("example.com", data)
        types = [obj["type"] for obj in bundle["objects"]]
        assert "ipv4-addr" in types

    def test_bundle_spec_version(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("example.com", {})
        for obj in bundle["objects"]:
            assert obj.get("spec_version") == "2.1"

    def test_bundle_id_format(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("example.com", {})
        assert bundle["id"].startswith("bundle--")

    def test_empty_data_no_crash(self):
        from modules.export_stix import to_stix_bundle
        bundle = to_stix_bundle("test.org", {})
        assert bundle["type"] == "bundle"

    def test_complex_data(self):
        from modules.export_stix import to_stix_bundle
        data = {
            "whois": {"registrar": "GoDaddy", "emails": ["admin@example.com"]},
            "ip": {"ip": "8.8.8.8", "org": "Google LLC"},
            "dns": {"a": ["1.2.3.4", "5.6.7.8"]},
        }
        bundle = to_stix_bundle("example.com", data)
        assert len(bundle["objects"]) > 2


class TestToMispEvent:
    def test_misp_event_structure(self):
        from modules.export_stix import to_misp_event
        event = to_misp_event("example.com", {})
        assert "Event" in event
        assert "Attribute" in event["Event"]
        assert isinstance(event["Event"]["Attribute"], list)

    def test_misp_has_domain_attribute(self):
        from modules.export_stix import to_misp_event
        event = to_misp_event("example.com", {})
        attrs = event["Event"]["Attribute"]
        domains = [a for a in attrs if a.get("value") == "example.com"]
        assert len(domains) >= 1

    def test_misp_attributes_deduplicated(self):
        from modules.export_stix import to_misp_event
        data = {"whois": {"ip": "1.2.3.4"}, "dns": {"a": ["1.2.3.4"]}}
        event = to_misp_event("example.com", data)
        values = [a["value"] for a in event["Event"]["Attribute"]]
        assert len(values) == len(set(values))

    def test_misp_no_crash_on_empty(self):
        from modules.export_stix import to_misp_event
        event = to_misp_event("user@example.com", {})
        assert "Event" in event


class TestSaveStix:
    def test_save_creates_files(self, tmp_path):
        from modules.export_stix import save_stix
        paths = save_stix("example.com", {}, str(tmp_path))
        assert "stix" in paths
        assert "misp" in paths
        import os
        assert os.path.isfile(paths["stix"])
        assert os.path.isfile(paths["misp"])

    def test_saved_files_are_valid_json(self, tmp_path):
        import json
        from modules.export_stix import save_stix
        paths = save_stix("example.com", {"whois": {"registrar": "ICANN"}}, str(tmp_path))
        with open(paths["stix"]) as f:
            stix_data = json.load(f)
        with open(paths["misp"]) as f:
            misp_data = json.load(f)
        assert stix_data["type"] == "bundle"
        assert "Event" in misp_data
