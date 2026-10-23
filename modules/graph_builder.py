"""Builds the NetworkX attack graph from a dataset.

Node types: External Entry Point, Host, Sensitive Asset, Service, Vulnerability.
Edge types: EXPOSES (Internet->service), HOSTS (host->service, display only), AFFECTED_BY
(service->vulnerability), POTENTIAL_TRANSITION (vulnerability->owning host), CONNECTS_TO
(host->service on another host), TRUSTS (host->host).
Edges carry `eligible` (does the configured rule set allow traversal?) and `confidence`.
"""
from __future__ import annotations

import networkx as nx

from .config import INTERNET, STATUS_CONFIDENCE, RuleConfig


def host_id(aid: str) -> str:
    return f"host:{aid}"


def svc_id(aid: str, port: int, proto: str = "tcp") -> str:
    return f"svc:{aid}:{port}/{proto}"


def vuln_id(fid: str) -> str:
    return f"vuln:{fid}"


def transition_eligible(finding: dict, rules: RuleConfig) -> tuple[bool, str]:
    """Rule R2: may this finding create a modeled transition?"""
    if finding.get("status") == "potential" and not rules.include_potential:
        return False, "potential matches are excluded by rule"
    cvss = finding.get("cvss")
    if cvss is None:
        return (rules.include_unknown,
                "unknown CVSS included with assumed score" if rules.include_unknown else "unknown CVSS excluded by rule")
    if cvss < rules.min_cvss:
        return False, f"CVSS {cvss} is below the minimum {rules.min_cvss}"
    return True, "meets transition rule"


def build_graph(dataset: dict, rules: RuleConfig | None = None) -> nx.DiGraph:
    rules = rules or RuleConfig()
    G = nx.DiGraph()
    G.add_node(INTERNET, node_type="External Entry Point", label="Internet", asset_id=None,
               hover="External attacker (modeled starting point)")
    assets = {a["id"]: a for a in dataset.get("assets", [])}
    for a in assets.values():
        G.add_node(host_id(a["id"]), node_type="Sensitive Asset" if a["is_critical"] else "Host",
                   label=a["hostname"] or a["ip"], ip=a["ip"], asset_id=a["id"], role=a["role"],
                   zone=a["zone"], exposure=a["exposure"], criticality=a["criticality"],
                   is_critical=a["is_critical"],
                   hover=f"{a['hostname'] or a['ip']} ({a['ip']})<br>Role: {a['role']}<br>Zone: {a['zone']}"
                         f"<br>Exposure: {a['exposure']}<br>Criticality: {a['criticality']}/5")

    svc_by_port: dict[tuple, list[str]] = {}
    svc_by_asset: dict[str, list[str]] = {}
    for s in dataset.get("services", []):
        aid = s["asset_id"]
        if aid not in assets or s.get("state", "open") != "open":
            continue
        sid = svc_id(aid, s["port"], s["protocol"])
        G.add_node(sid, node_type="Service", label=f"{s['port']}/{s['name']}", asset_id=aid, port=s["port"],
                   exposed=s["exposed"],
                   hover=f"{s['name']} on {s['port']}/{s['protocol']}<br>{s['product']} {s['version']}".strip()
                         + f"<br>Exposed: {'yes' if s['exposed'] else 'no'}")
        G.add_edge(host_id(aid), sid, type="HOSTS", confidence=1.0, eligible=True)
        svc_by_port.setdefault((aid, s["port"]), []).append(sid)
        svc_by_asset.setdefault(aid, []).append(sid)
        if assets[aid]["exposure"] == "Internet-facing" and s["exposed"]:
            G.add_edge(INTERNET, sid, type="EXPOSES", confidence=1.0, eligible=True,
                       rule="R1: externally reachable service is a modeled entry point")

    for f in dataset.get("findings", []):
        aid = f["asset_id"]
        if aid not in assets:
            continue
        vn = vuln_id(f["id"])
        conf = STATUS_CONFIDENCE.get(f["status"], 0.5)
        G.add_node(vn, node_type="Vulnerability", label=f["cve"] or f["id"], asset_id=aid, finding_id=f["id"],
                   cve=f["cve"], cvss=f["cvss"], severity=f["severity"], status=f["status"],
                   hover=f"{f['cve'] or f['id']}<br>CVSS: {f['cvss'] if f['cvss'] is not None else 'unknown'}"
                         f" ({f['severity']})<br>Status: {f['status']}<br>{f['description'][:120]}")
        sids = svc_by_port.get((aid, f["port"]), []) if f.get("port") else []
        if not sids:  # host-level finding: shown, contributes to asset risk, but creates no transition
            G.add_edge(host_id(aid), vn, type="AFFECTED_BY", confidence=conf, eligible=False)
            continue
        for sid in sids:
            G.add_edge(sid, vn, type="AFFECTED_BY", confidence=1.0, eligible=True)
        ok, why = transition_eligible(f, rules)
        G.add_edge(vn, host_id(aid), type="POTENTIAL_TRANSITION", confidence=conf, eligible=ok, reason=why,
                   rule="R2: vulnerability on a reachable service may give a foothold on the host")

    for r in dataset.get("relationships", []):
        if r["src"] not in assets or r["dst"] not in assets:
            continue
        s, d = host_id(r["src"]), host_id(r["dst"])
        if r["type"] == "TRUSTS":
            G.add_edge(s, d, type="TRUSTS", confidence=r["confidence"], eligible=rules.allow_trust,
                       note=r.get("note", ""), rule="R3: configured trust may allow direct movement")
            continue
        targets = svc_by_port.get((r["dst"], r["port"]), []) if r.get("port") else [
            x for x in svc_by_asset.get(r["dst"], []) if G.nodes[x]["exposed"]]
        for sid in targets:
            G.add_edge(s, sid, type="CONNECTS_TO", confidence=r["confidence"], eligible=True,
                       note=r.get("note", ""), rule="R4: configured network relationship allows reaching the service")
    return G


def traversal_view(G: nx.DiGraph) -> nx.DiGraph:
    """Edges the attack-path engine may traverse (excludes HOSTS and rule-ineligible edges)."""
    return nx.subgraph_view(
        G, filter_edge=lambda u, v: G.edges[u, v].get("type") != "HOSTS" and G.edges[u, v].get("eligible", True))


def graph_to_dict(G: nx.DiGraph) -> dict:
    return {"nodes": [{"id": n, **d} for n, d in G.nodes(data=True)],
            "edges": [{"source": u, "target": v, **d} for u, v, d in G.edges(data=True)]}
