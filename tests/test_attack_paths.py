from dataclasses import replace

from modules.analysis import analyze
from modules.asset_manager import update_assets
from modules.graph_builder import build_graph, host_id
from modules.attack_path_engine import find_attack_paths


def test_finds_internet_to_database_paths(sample, rules):
    res = analyze(sample, rules)
    assert res["paths"], "sample lab must produce paths"
    assert all(p["target"] == host_id("db") and p["start"] == "INTERNET" for p in res["paths"])
    best = res["paths"][0]
    assert best["transitions"] >= 1 and best["vulnerabilities"] and best["assumptions"]
    assert "not been attempted" in best["assumptions"][0]
    assert [p["risk"]["score"] for p in res["paths"]] == sorted((p["risk"]["score"] for p in res["paths"]), reverse=True)


def test_every_path_is_a_simple_path_over_real_edges(sample, rules):
    G = build_graph(sample, rules)
    paths, _ = find_attack_paths(G, rules)
    for p in paths:
        assert len(set(p["nodes"])) == len(p["nodes"])
        assert all(G.has_edge(u, v) for u, v in p["edges"])


def test_max_transition_limit(sample, rules):
    assert analyze(sample, replace(rules, max_transitions=2))["paths"] == []
    three = analyze(sample, replace(rules, max_transitions=3))["paths"]
    assert three and all(p["transitions"] <= 3 for p in three)


def test_depth_limit(sample, rules):
    assert analyze(sample, replace(rules, max_edges=3))["paths"] == []


def test_max_paths_limit(sample, rules):
    res = analyze(sample, replace(rules, max_paths=2))
    assert len(res["paths"]) == 2 and res["truncated"]


def test_min_cvss_rule_removes_paths(sample, rules):
    assert analyze(sample, replace(rules, min_cvss=9.9))["paths"] == []


def test_disallowing_trust_removes_trust_paths(sample, rules):
    with_trust = analyze(sample, rules)["paths"]
    without = analyze(sample, replace(rules, allow_trust=False))["paths"]
    assert len(without) < len(with_trust)


def test_assumed_breach_start(sample, rules):
    res = analyze(sample, replace(rules, start="host:ws"))
    assert res["paths"] and all(p["start"] == "host:ws" for p in res["paths"])


def test_no_target_means_no_paths(sample, rules):
    for a in sample["assets"]:
        a["is_critical"] = False
    assert analyze(sample, rules)["paths"] == []


def test_empty_dataset_does_not_crash(empty, rules):
    res = analyze(empty, rules)
    assert res["paths"] == [] and res["summary"]["overall"] == 0.0 and res["summary"]["assets"] == 0


def test_removing_exposure_blocks_internet_paths(sample, rules):
    for a in sample["assets"]:
        a["exposure"] = "Internal"
    assert analyze(sample, rules)["paths"] == []
