"""Single entry point that runs the full pipeline: graph -> paths -> risk -> summary."""
from __future__ import annotations

from collections import Counter

from .attack_path_engine import find_attack_paths
from .config import SEVERITIES, RuleConfig, risk_band
from .graph_builder import build_graph
from .risk_engine import compute_asset_risks, overall_risk


def summarize(dataset: dict, paths: list[dict], asset_risks: list[dict], overall: float) -> dict:
    sev = Counter(f["severity"] for f in dataset.get("findings", []))
    open_svcs = [s for s in dataset.get("services", []) if s.get("state") == "open"]
    labels = {a["id"]: a["hostname"] or a["ip"] for a in dataset.get("assets", [])}
    return {
        "assets": len(dataset.get("assets", [])), "open_ports": len(open_svcs),
        "findings": len(dataset.get("findings", [])),
        "severity_counts": {s: sev.get(s, 0) for s in SEVERITIES},
        "paths": len(paths), "critical_assets": sum(1 for a in dataset.get("assets", []) if a["is_critical"]),
        "overall": overall, "band": risk_band(overall) if (paths or dataset.get("assets")) else "None",
        "exposed_by_host": dict(Counter(labels[s["asset_id"]] for s in open_svcs if s.get("exposed") and s["asset_id"] in labels)),
        "top_services": dict(Counter(s["name"] for s in open_svcs).most_common(8)),
        "path_bands": dict(Counter(p["risk"]["band"] for p in paths)),
        "asset_scores": [a["score"] for a in asset_risks],
    }


def analyze(dataset: dict, rules: RuleConfig | None = None) -> dict:
    rules = rules or RuleConfig()
    G = build_graph(dataset, rules)
    paths, truncated = find_attack_paths(G, rules)
    asset_risks = compute_asset_risks(dataset, paths, rules)
    overall = overall_risk(paths, asset_risks)
    return {"graph": G, "paths": paths, "truncated": truncated, "asset_risks": asset_risks,
            "summary": summarize(dataset, paths, asset_risks, overall), "rules": rules}
