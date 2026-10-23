"""Rule-based attack path discovery over the NetworkX graph (modeled paths, not proof of compromise)."""
from __future__ import annotations

from itertools import islice

import networkx as nx

from .config import RuleConfig
from .graph_builder import traversal_view
from .risk_engine import score_path

TRANSITION_TYPES = {"POTENTIAL_TRANSITION", "TRUSTS"}


def describe_path(G: nx.DiGraph, nodes: list[str]) -> dict:
    edges = [(u, v, G.edges[u, v]) for u, v in zip(nodes, nodes[1:])]
    nd = lambda n: G.nodes[n]  # noqa: E731
    hosts = [n for n in nodes if nd(n)["node_type"] in ("Host", "Sensitive Asset")]
    start = nodes[0]
    entry_host = hosts[0] if nd(start)["node_type"] != "External Entry Point" else f"host:{nd(nodes[1])['asset_id']}"
    asset_chain = ([] if nd(start)["node_type"] != "External Entry Point" else ["INTERNET"]) + [nd(h)["asset_id"] for h in hosts]
    vulns = [{**nd(n), "node": n} for n in nodes if nd(n)["node_type"] == "Vulnerability"]
    transitions = sum(1 for _, _, d in edges if d["type"] in TRANSITION_TYPES)

    a = ["Modeled potential path only: exploitation has not been attempted or verified."]
    for u, v, d in edges:
        lu, lv = nd(u)["label"], nd(v)["label"]
        t = d["type"]
        if t == "EXPOSES":
            a.append(f"Service {lv} on {nd(v)['asset_id']} is assumed reachable from the Internet (asset is Internet-facing and the service is exposed).")
        elif t == "CONNECTS_TO":
            a.append(f"{lu} can reach service {lv} on {nd(v)['asset_id']} (configured relationship, confidence {d['confidence']:.0%}"
                     f"{': ' + d['note'] if d.get('note') else ''}).")
        elif t == "POTENTIAL_TRANSITION":
            a.append(f"{lu} ({nd(u)['severity']}, {nd(u)['status']}) is assumed to give a foothold on {lv} (confidence {d['confidence']:.0%}).")
        elif t == "TRUSTS":
            a.append(f"{lu} is assumed to be able to act on {lv} through a configured trust (confidence {d['confidence']:.0%}"
                     f"{': ' + d['note'] if d.get('note') else ''}).")
    labels = [nd(n)["label"] for n in nodes if nd(n)["node_type"] in ("External Entry Point", "Host", "Sensitive Asset")]
    return {
        "nodes": nodes, "edges": [(u, v) for u, v, _ in edges], "start": start, "target": nodes[-1],
        "entry_host": entry_host, "asset_chain": asset_chain, "summary": " → ".join(labels),
        "start_label": nd(start)["label"], "target_label": nd(nodes[-1])["label"],
        "services": [nd(n)["label"] + f" ({nd(n)['asset_id']})" for n in nodes if nd(n)["node_type"] == "Service"],
        "intermediates": [nd(h)["label"] for h in hosts[:-1]] if nd(start)["node_type"] == "External Entry Point" else [nd(h)["label"] for h in hosts[1:-1]],
        "vulnerabilities": vulns, "transitions": transitions,
        "confidences": [d["confidence"] for _, _, d in edges if d["type"] != "HOSTS"], "assumptions": a,
    }


def find_attack_paths(G: nx.DiGraph, rules: RuleConfig | None = None) -> tuple[list[dict], bool]:
    """Return (paths sorted by risk, truncated). Search is bounded by rules.max_edges/max_transitions/max_paths."""
    rules = rules or RuleConfig()
    if rules.start not in G or G.number_of_nodes() < 2:
        return [], False
    view = traversal_view(G)
    targets = [n for n, d in G.nodes(data=True) if d["node_type"] == "Sensitive Asset" and n != rules.start]
    cap, paths, truncated = rules.max_paths * 5, [], False
    for t in targets:
        raw = list(islice(nx.all_simple_paths(view, rules.start, t, cutoff=rules.max_edges), cap + 1))
        truncated |= len(raw) > cap
        for nodes in raw[:cap]:
            info = describe_path(G, nodes)
            if 1 <= info["transitions"] <= rules.max_transitions:
                info["risk"] = score_path(G, info, rules)
                paths.append(info)
    paths.sort(key=lambda p: (-p["risk"]["score"], p["transitions"]))
    if len(paths) > rules.max_paths:
        paths, truncated = paths[: rules.max_paths], True
    for i, p in enumerate(paths, start=1):
        p["id"] = f"P-{i:03d}"
    return paths, truncated
