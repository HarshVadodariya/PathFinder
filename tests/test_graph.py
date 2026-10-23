from modules.asset_manager import add_relationship, load_network_json, validate_dataset
from modules.config import INTERNET
from modules.graph_builder import build_graph, host_id, svc_id, traversal_view, vuln_id
from modules.vulnerability_mapper import (add_finding, import_findings_csv, parse_cvss, severity_from_cvss,
                                          suggest_potential_matches)
import pytest


def test_node_and_edge_types(sample, rules):
    G = build_graph(sample, rules)
    types = {d["node_type"] for _, d in G.nodes(data=True)}
    assert types == {"External Entry Point", "Host", "Sensitive Asset", "Service", "Vulnerability"}
    assert G.nodes[host_id("db")]["node_type"] == "Sensitive Asset"
    assert G.has_edge(INTERNET, svc_id("web", 443)) and G.edges[INTERNET, svc_id("web", 443)]["type"] == "EXPOSES"
    assert G.edges[host_id("web"), svc_id("web", 80)]["type"] == "HOSTS"
    assert G.edges[svc_id("web", 443), vuln_id("F-002")]["type"] == "AFFECTED_BY"
    assert G.edges[vuln_id("F-002"), host_id("web")]["type"] == "POTENTIAL_TRANSITION"
    assert G.edges[host_id("gw"), host_id("app")]["type"] == "TRUSTS"
    assert not G.has_edge(INTERNET, svc_id("app", 8443))  # internal asset is not an entry point


def test_counts_follow_data(sample, rules):
    G = build_graph(sample, rules)
    n = lambda t: sum(1 for _, d in G.nodes(data=True) if d["node_type"] == t)  # noqa: E731
    assert n("Service") == len(sample["services"]) and n("Vulnerability") == len(sample["findings"])


def test_ineligible_edges_hidden_from_traversal(sample, rules):
    G = build_graph(sample, rules)
    assert G.edges[vuln_id("F-009"), host_id("web")]["eligible"] is False  # unknown CVSS excluded by default
    assert not traversal_view(G).has_edge(vuln_id("F-009"), host_id("web"))


def test_empty_dataset_builds(empty):
    G = build_graph(empty)
    assert list(G.nodes) == [INTERNET] and G.number_of_edges() == 0


def test_severity_mapping_table():
    cases = {10: "Critical", 9.0: "Critical", 8.9: "High", 7.0: "High", 6.9: "Medium", 4.0: "Medium",
             3.9: "Low", 0.1: "Low", 0.0: "Informational", None: "Unknown"}
    assert {k: severity_from_cvss(k) for k in cases} == cases


def test_cvss_validation():
    assert parse_cvss("") is None and parse_cvss("7.5") == 7.5
    for bad in ("11", "-1", "abc"):
        with pytest.raises(ValueError):
            parse_cvss(bad)


def test_finding_validation(sample):
    with pytest.raises(ValueError):
        add_finding(sample, {"asset_id": "nope", "description": "x"})
    with pytest.raises(ValueError):
        add_finding(sample, {"asset_id": "web", "port": 9999, "description": "x"})
    with pytest.raises(ValueError):
        add_finding(sample, {"asset_id": "web", "cve": "not-a-cve", "description": "x"})
    f = add_finding(sample, {"asset_id": "web", "description": "host-level", "cvss": "5"})
    assert f["severity"] == "Medium" and f["status"] == "manual_lab"


def test_missing_vulnerability_metadata(sample):
    f = add_finding(sample, {"asset_id": "db", "description": "metadata missing"})
    assert f["cvss"] is None and f["severity"] == "Unknown" and f["cve"] == ""


def test_csv_import_reports_row_errors(sample):
    csv = b"asset,port,cve,cvss,description\nweb,80,SAMPLE-X-1,6.0,ok row\nghost,80,,5,bad asset\n"
    added, errors = import_findings_csv(sample, csv)
    assert added == 1 and len(errors) == 1 and "Row 3" in errors[0]
    assert import_findings_csv(sample, b"foo,bar\n1,2")[0] == 0


def test_potential_matches_are_never_confirmed(sample):
    for f in suggest_potential_matches(sample):
        assert f["status"] == "potential"


def test_dataset_validation_and_relationships(sample):
    with pytest.raises(ValueError):
        load_network_json("{bad json")
    with pytest.raises(ValueError):
        validate_dataset({"assets": [{"id": "a", "ip": "999.1.1.1"}]})
    with pytest.raises(ValueError):
        add_relationship(sample, src="web", dst="web", type="TRUSTS")
    with pytest.raises(ValueError):
        add_relationship(sample, src="gw", dst="web", type="CONNECTS_TO", port=443)  # duplicate
