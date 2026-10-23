"""Rule-based, explainable remediation. Expected risk reduction is *simulated*: the fix is applied to a
copy of the dataset and the full analysis is re-run, so the number is the change in overall risk score."""
from __future__ import annotations

import copy

from .analysis import analyze
from .config import SEVERITY_RANK, RuleConfig

RISKY_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
               1433: "MSSQL", 27017: "MongoDB", 6379: "Redis", 5900: "VNC"}
ACTIONS = {
    "outdated_software": "Upgrade {what} to a supported, patched version and re-scan to confirm.",
    "exposed_service": "Disable the service if it is not required, or restrict it to trusted source addresses.",
    "weak_access": "Review permissions and authentication on {what}: enforce strong credentials/MFA and least privilege.",
    "excessive_access": "Apply network segmentation: limit {what} with firewall rules to the minimum required.",
    "critical_exposure": "Restrict access to {what} to named systems only and monitor connections to it.",
    "misconfiguration": "Harden the configuration of {what} against a vendor or CIS baseline.",
}
PRIORITIES = ["Low", "Medium", "High", "Critical"]


def apply_mutations(dataset: dict, muts: list[dict]) -> dict:
    ds = copy.deepcopy(dataset)
    for m in muts:
        op = m["op"]
        if op == "remove_finding":
            ds["findings"] = [f for f in ds["findings"] if f["id"] != m["id"]]
        elif op == "unexpose_service":
            for s in ds["services"]:
                if (s["asset_id"], s["port"]) == (m["asset_id"], m["port"]):
                    s["exposed"] = False
        elif op == "remove_relationship":
            ds["relationships"] = [r for r in ds["relationships"] if (r["src"], r["dst"], r["type"], r["port"]) !=
                                   (m["src"], m["dst"], m["type"], m["port"])]
        elif op == "restrict_inbound":
            ds["relationships"] = [r for r in ds["relationships"] if r["dst"] != m["asset"]]
    return ds


def _prio(i: int) -> str:
    return PRIORITIES[max(0, min(3, i))]


def generate_recommendations(dataset: dict, result: dict, rules: RuleConfig | None = None) -> list[dict]:
    rules = rules or RuleConfig()
    base = result["summary"]["overall"]
    G, paths = result["graph"], result["paths"]
    assets = {a["id"]: a for a in dataset["assets"]}
    label = lambda aid: assets[aid]["hostname"] or assets[aid]["ip"]  # noqa: E731

    def reduction(muts):
        return round(max(0.0, base - analyze(apply_mutations(dataset, muts), rules)["summary"]["overall"]), 1)

    def prio(floor: int, red: float) -> str:
        return _prio(max(floor, 3 if red >= 20 else 2 if red >= 8 else 1 if red > 0 else 0))

    recs = []
    for f in dataset["findings"]:
        if f["severity"] == "Informational":
            continue
        n = sum(1 for p in paths if f"vuln:{f['id']}" in p["nodes"])
        svc = next((s for s in dataset["services"] if s["asset_id"] == f["asset_id"] and s["port"] == f["port"]), None)
        what = f"{svc['product'] or svc['name']} on {label(f['asset_id'])}:{f['port']}" if svc else label(f["asset_id"])
        red = reduction([{"op": "remove_finding", "id": f["id"]}])
        recs.append({"finding": f"{f['cve'] or f['id']}: {f['description'][:90]}", "asset": label(f["asset_id"]),
                     "category": f["category"],
                     "reason": f"{f['severity']} finding ({f['status']}) appears in {n} modeled attack path(s).",
                     "action": f.get("remediation") or ACTIONS[f["category"]].format(what=what),
                     "priority": prio(SEVERITY_RANK[f["severity"]] - 1, red), "reduction": red,
                     "mutation": [{"op": "remove_finding", "id": f["id"]}]})
    for s in dataset["services"]:
        a = assets.get(s["asset_id"])
        if a and a["exposure"] == "Internet-facing" and s["exposed"] and s["port"] in RISKY_PORTS:
            m = [{"op": "unexpose_service", "asset_id": s["asset_id"], "port": s["port"]}]
            red = reduction(m)
            recs.append({"finding": f"{RISKY_PORTS[s['port']]} ({s['port']}) exposed to the Internet", "asset": label(a["id"]),
                         "category": "exposed_service",
                         "reason": "Administrative or data services on Internet-facing assets enlarge the attack surface.",
                         "action": ACTIONS["exposed_service"], "priority": prio(1, red), "reduction": red, "mutation": m})
    used = {}
    for p in paths:
        for u, v in p["edges"]:
            d = G.edges[u, v]
            if d["type"] in ("CONNECTS_TO", "TRUSTS"):
                src = G.nodes[u]["asset_id"]
                dst = G.nodes[v]["asset_id"]
                for r in dataset["relationships"]:
                    if (r["src"], r["dst"], r["type"]) == (src, dst, d["type"]) and (r["port"] in (None, G.nodes[v].get("port"))):
                        used[(r["src"], r["dst"], r["type"], r["port"])] = r
    for key, r in used.items():
        m = [{"op": "remove_relationship", "src": r["src"], "dst": r["dst"], "type": r["type"], "port": r["port"]}]
        red = reduction(m)
        what = f"{r['type']} {label(r['src'])} -> {label(r['dst'])}" + (f":{r['port']}" if r["port"] else "")
        recs.append({"finding": f"Network access used by attack paths ({what})", "asset": label(r["dst"]),
                     "category": "excessive_access",
                     "reason": "This relationship is part of at least one modeled path to a sensitive asset.",
                     "action": ACTIONS["excessive_access"].format(what=what), "priority": prio(1, red),
                     "reduction": red, "mutation": m})
    reached = {p["target"] for p in paths}
    for a in dataset["assets"]:
        if a["is_critical"] and f"host:{a['id']}" in reached:
            m = [{"op": "restrict_inbound", "asset": a["id"]}]
            red = reduction(m)
            recs.append({"finding": f"Critical asset {label(a['id'])} is reachable by modeled attack paths", "asset": label(a["id"]),
                         "category": "critical_exposure",
                         "reason": f"{sum(1 for p in paths if p['target'] == 'host:' + a['id'])} modeled path(s) end at this asset.",
                         "action": ACTIONS["critical_exposure"].format(what=label(a["id"])), "priority": prio(2, red),
                         "reduction": red, "mutation": m})
    recs.sort(key=lambda r: (-PRIORITIES.index(r["priority"]), -r["reduction"]))
    for i, r in enumerate(recs, 1):
        r["id"] = f"R-{i:03d}"
    return recs


def simulate(dataset: dict, rules: RuleConfig, recs: list[dict]) -> dict:
    """Apply several recommendations together and compare before/after."""
    before = analyze(dataset, rules)["summary"]
    after = analyze(apply_mutations(dataset, [m for r in recs for m in r["mutation"]]), rules)["summary"]
    return {"before": before["overall"], "after": after["overall"], "paths_before": before["paths"], "paths_after": after["paths"]}
