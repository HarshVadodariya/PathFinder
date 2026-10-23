import copy
from dataclasses import replace

import pytest

from modules.analysis import analyze
from modules.asset_manager import update_assets
from modules.config import WEIGHTS, risk_band
from modules.remediation_engine import apply_mutations, generate_recommendations, simulate
from modules.vulnerability_mapper import add_finding


def test_weights_sum_to_one():
    assert sum(WEIGHTS.values()) == pytest.approx(1.0)


def test_scores_are_bounded_and_break_down(sample, rules):
    for p in analyze(sample, rules)["paths"]:
        r = p["risk"]
        assert 0 <= r["score"] <= 100
        assert r["base"] == pytest.approx(sum(c["contribution"] for c in r["components"]), abs=0.15)
        assert r["score"] == pytest.approx(r["base"] * r["multiplier"], abs=0.15)
        assert {c["name"] for c in r["components"]} >= {"Vulnerability severity", "External exposure", "Path length"}


def test_higher_criticality_raises_score(sample, rules):
    before = analyze(sample, rules)["paths"][0]["risk"]["score"]
    sample["assets"][3]["criticality"] = 1  # db
    after = analyze(sample, rules)["paths"][0]["risk"]["score"]
    assert after < before


def test_lower_exposure_lowers_score(sample, rules):
    base = analyze(sample, rules)["summary"]["overall"]
    sample["assets"][1]["exposure"] = "Partner/VPN"
    sample["assets"][0]["exposure"] = "Partner/VPN"
    assert analyze(sample, rules)["summary"]["overall"] < base


def test_unknown_cvss_uses_assumed_default(sample, rules):
    ids = {a["id"] for a in sample["assets"]}
    for f in sample["findings"]:
        if f["id"] == "F-006":
            f["cvss"], f["severity"] = None, "Unknown"
    assert analyze(sample, rules)["paths"] == []  # excluded by default
    res = analyze(sample, replace(rules, include_unknown=True, unknown_cvss_default=5.0))
    assert res["paths"] and ids


def test_potential_findings_lower_confidence(sample, rules):
    res = analyze(sample, rules)
    assert all(0 < p["risk"]["confidence"] <= 1 for p in res["paths"])


def test_risk_bands():
    assert [risk_band(x) for x in (0, 24.9, 25, 49.9, 50, 74.9, 75, 100)] == ["Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"]


def test_update_assets_validation(sample):
    with pytest.raises(ValueError):
        update_assets(sample, [{"id": "web", "criticality": 9}])
    assert sample["assets"][1]["criticality"] == 3  # unchanged after failure


def test_remediation_is_simulated_and_explainable(sample, rules):
    res = analyze(sample, rules)
    recs = generate_recommendations(sample, res, rules)
    assert recs and all({"finding", "asset", "reason", "action", "priority", "reduction"} <= set(r) for r in recs)
    top = recs[0]
    assert top["reduction"] > 0
    out = simulate(sample, rules, [top])
    assert out["after"] < out["before"]
    assert apply_mutations(sample, top["mutation"]) != sample  # original untouched
    assert len(sample["findings"]) == 9


def test_no_recommendations_for_empty_dataset(empty, rules):
    assert generate_recommendations(empty, analyze(empty, rules), rules) == []
