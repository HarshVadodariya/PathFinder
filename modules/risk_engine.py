"""Transparent 0-100 risk scoring. This is NOT a CVSS value.

Path score = 100 * (w_s*S + w_c*C + w_t*T + w_e*E + w_l*L) * (0.5 + 0.5*F)
  S severity   : 0.6*max(CVSS)/10 + 0.4*mean(CVSS)/10 over vulnerabilities on the path
                 (unknown CVSS -> configured default; trust-only paths -> 0.30 baseline)
  C criticality: target asset criticality / 5
  T sensitive  : 1 if the target is a designated sensitive asset, else 0
  E exposure   : exposure factor of the entry asset (Internet-facing 1.0 ... Restricted 0.3)
  L length     : max(0.2, 1 - 0.20*(transitions-1))  (shorter paths are easier)
  F confidence : mean confidence of the relationships/findings used (0-1)
"""
from __future__ import annotations

from .config import EXPOSURES, WEIGHTS, RuleConfig, risk_band


def score_path(G, path: dict, rules: RuleConfig | None = None, weights: dict | None = None) -> dict:
    rules, w = rules or RuleConfig(), weights or WEIGHTS
    cv = [v["cvss"] if v.get("cvss") is not None else rules.unknown_cvss_default for v in path["vulnerabilities"]]
    if cv:
        s = 0.6 * max(cv) / 10 + 0.4 * (sum(cv) / len(cv)) / 10
        s_note = f"max CVSS {max(cv):.1f}, mean {sum(cv) / len(cv):.1f}"
    else:
        s, s_note = 0.30, "no vulnerability on path (trust-based); baseline 0.30"
    tgt = G.nodes[path["target"]]
    c = tgt.get("criticality", 3) / 5
    t = 1.0 if tgt["node_type"] == "Sensitive Asset" else 0.0
    entry = G.nodes[path["entry_host"]]
    e = EXPOSURES.get(entry.get("exposure", "Internal"), 0.5)
    n = max(1, path["transitions"])
    length = max(0.2, 1 - 0.20 * (n - 1))
    confs = path["confidences"] or [1.0]
    f = sum(confs) / len(confs)
    rows = [
        ("Vulnerability severity", s, w["severity"], s_note),
        ("Target asset criticality", c, w["criticality"], f"{tgt.get('criticality', 3)}/5 on {tgt['label']}"),
        ("Sensitive target", t, w["sensitive"], "target is a designated sensitive asset" if t else "target not designated sensitive"),
        ("External exposure", e, w["exposure"], f"entry asset is {entry.get('exposure', 'Internal')}"),
        ("Path length", length, w["length"], f"{n} transition(s)"),
    ]
    comps = [{"name": nm, "value": round(v, 3), "weight": wt, "contribution": round(100 * wt * v, 1), "note": note}
             for nm, v, wt, note in rows]
    base = sum(c_["contribution"] for c_ in comps)
    mult = 0.5 + 0.5 * f
    score = max(0.0, min(100.0, round(base * mult, 1)))
    return {"score": score, "band": risk_band(score), "base": round(base, 1), "confidence": round(f, 2),
            "multiplier": round(mult, 3), "components": comps}


def compute_asset_risks(dataset: dict, paths: list[dict], rules: RuleConfig | None = None) -> list[dict]:
    """Asset risk = 100*(0.5*maxCVSS/10 + 0.3*criticality/5 + 0.2*exposure). Informational only."""
    rules = rules or RuleConfig()
    out = []
    for a in dataset.get("assets", []):
        fs = [f for f in dataset.get("findings", []) if f["asset_id"] == a["id"]]
        cv = [f["cvss"] if f["cvss"] is not None else rules.unknown_cvss_default for f in fs]
        mx = max(cv) if cv else 0.0
        score = 100 * (0.5 * mx / 10 + 0.3 * a["criticality"] / 5 + 0.2 * EXPOSURES.get(a["exposure"], 0.5))
        node = f"host:{a['id']}"
        out.append({"asset_id": a["id"], "label": a["hostname"] or a["ip"], "ip": a["ip"], "role": a["role"],
                    "score": round(min(100.0, score), 1), "band": risk_band(score), "findings": len(fs),
                    "paths": sum(1 for p in paths if node in p["nodes"])})
    return out


def overall_risk(paths: list[dict], asset_risks: list[dict]) -> float:
    """0.6*top path + 0.4*mean(top 3 paths); with no paths, 0.5*highest asset score."""
    if paths:
        top = sorted((p["risk"]["score"] for p in paths), reverse=True)[:3]
        return round(0.6 * top[0] + 0.4 * sum(top) / len(top), 1)
    if asset_risks:
        return round(0.5 * max(a["score"] for a in asset_risks), 1)
    return 0.0
