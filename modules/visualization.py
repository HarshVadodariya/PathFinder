"""Plotly figures: interactive attack graph and dashboard charts (dark theme)."""
from __future__ import annotations

import html
from collections import deque

import networkx as nx
import plotly.graph_objects as go

from .config import INTERNET, SEV_COLORS, SEVERITIES, SEVERITY_RANK

BG, PANEL, LINE, TEXT, MUTED = "rgba(0,0,0,0)", "#151D27", "#2A3746", "#E4E9EF", "#8A98A8"
ACCENT, DANGER = "#4FB3BF", "#E5645B"
EDGE_STYLE = {"EXPOSES": ("#4FB3BF", 1.4), "CONNECTS_TO": ("#7C93B0", 1.4), "AFFECTED_BY": ("#8A6F9E", 1.2),
              "POTENTIAL_TRANSITION": ("#E3A74F", 1.6), "TRUSTS": ("#D9798F", 1.6)}
NODE_STYLE = {"External Entry Point": ("star", 20, ACCENT), "Host": ("square", 18, "#6C8EAD"),
              "Sensitive Asset": ("diamond", 22, DANGER), "Service": ("circle", 11, "#4B5D70")}


def style(fig: go.Figure, height: int = 300, title: str | None = None) -> go.Figure:
    fig.update_layout(height=height, title=dict(text=title, font=dict(size=14, color=TEXT)) if title else None,
                      paper_bgcolor=BG, plot_bgcolor=BG, font=dict(color=TEXT, family="IBM Plex Sans, Segoe UI, sans-serif"),
                      margin=dict(l=10, r=10, t=40 if title else 10, b=10), legend=dict(font=dict(color=MUTED)))
    fig.update_xaxes(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE)
    fig.update_yaxes(gridcolor=LINE, zerolinecolor=LINE, linecolor=LINE)
    return fig


def bar_chart(labels, values, title, color=ACCENT, horizontal=False, colors=None, height=290) -> go.Figure:
    labels, values = list(labels), list(values)
    fig = go.Figure(go.Bar(x=values if horizontal else labels, y=labels if horizontal else values,
                           orientation="h" if horizontal else "v", marker_color=colors or color, text=values,
                           textposition="outside", cliponaxis=False))
    if horizontal:
        fig.update_yaxes(autorange="reversed")
    return style(fig, height, title)


def severity_chart(counts: dict) -> go.Figure:
    keys = [s for s in SEVERITIES]
    return bar_chart(keys, [counts.get(k, 0) for k in keys], "Findings by severity", colors=[SEV_COLORS[k] for k in keys])


def gauge(score: float, band: str) -> go.Figure:
    color = {"Critical": DANGER, "High": "#E8894F", "Medium": "#E3C04F", "Low": "#6BAE8B"}.get(band, MUTED)
    fig = go.Figure(go.Indicator(mode="gauge+number", value=score, number=dict(font=dict(color=TEXT, size=44)),
                                 gauge=dict(axis=dict(range=[0, 100], tickcolor=MUTED), bar=dict(color=color, thickness=0.28),
                                            bgcolor=PANEL, borderwidth=0,
                                            steps=[dict(range=[0, 25], color="#1B2A27"), dict(range=[25, 50], color="#2A2A1C"),
                                                   dict(range=[50, 75], color="#2E2318"), dict(range=[75, 100], color="#301D1D")])))
    return style(fig, 230, None)


def path_components_chart(paths: list[dict], top: int = 10) -> go.Figure:
    rows = paths[:top]
    fig = go.Figure()
    palette = ["#E5645B", "#E3A74F", "#4FB3BF", "#7C93B0", "#6BAE8B"]
    names = [c["name"] for c in rows[0]["risk"]["components"]] if rows else []
    for i, nm in enumerate(names):
        fig.add_bar(name=nm, y=[p["id"] for p in rows], x=[p["risk"]["components"][i]["contribution"] for p in rows],
                    orientation="h", marker_color=palette[i % 5])
    fig.update_layout(barmode="stack")
    fig.update_yaxes(autorange="reversed")
    return style(fig, 120 + 34 * len(rows), "Score contribution by component (before confidence multiplier)")


def filter_graph(G: nx.DiGraph, min_severity: str = "Unknown", asset_ids: list[str] | None = None) -> nx.DiGraph:
    floor = SEVERITY_RANK[min_severity]
    keep = []
    for n, d in G.nodes(data=True):
        if asset_ids is not None and d.get("asset_id") is not None and d["asset_id"] not in asset_ids:
            continue
        if d["node_type"] == "Vulnerability" and SEVERITY_RANK[d["severity"]] < floor:
            continue
        keep.append(n)
    return G.subgraph(keep).copy()


def layout_positions(G: nx.DiGraph) -> dict:
    depth = {}
    if INTERNET in G:
        q = deque([(INTERNET, 0)])
        depth[INTERNET] = 0
        while q:
            n, d = q.popleft()
            for m in G.successors(n):
                if m not in depth:
                    depth[m] = d + 1
                    q.append((m, d + 1))
    default = {"Host": 3, "Sensitive Asset": 3, "Service": 2, "Vulnerability": 4, "External Entry Point": 0}
    for n, d in G.nodes(data=True):
        depth.setdefault(n, default[d["node_type"]])
    layers: dict[int, list] = {}
    for n in sorted(G.nodes, key=lambda n: (G.nodes[n].get("asset_id") or "", G.nodes[n]["node_type"], n)):
        layers.setdefault(depth[n], []).append(n)
    return {n: (x * 1.0, ((len(ns) - 1) / 2 - i) * 1.0) for x, ns in layers.items() for i, n in enumerate(ns)}


def attack_graph_figure(G: nx.DiGraph, highlight: list[str] | None = None, show_labels: bool = True) -> go.Figure:
    pos = layout_positions(G)
    hl = set(highlight or [])
    hl_edges = set(zip(highlight, highlight[1:])) if highlight else set()
    fig = go.Figure()
    host_x, host_y = [], []
    for u, v, d in G.edges(data=True):
        if d["type"] == "HOSTS":
            host_x += [pos[u][0], pos[v][0], None]
            host_y += [pos[u][1], pos[v][1], None]
    fig.add_scatter(x=host_x, y=host_y, mode="lines", line=dict(color="#34475A", width=1, dash="dot"),
                    hoverinfo="skip", name="HOSTS", showlegend=False)
    arrows = []
    seen_types = set()
    for u, v, d in G.edges(data=True):
        if d["type"] == "HOSTS":
            continue
        on = (u, v) in hl_edges
        color, width = EDGE_STYLE.get(d["type"], (MUTED, 1.2))
        dim = bool(hl) and not on
        (x0, y0), (x1, y1) = pos[u], pos[v]
        arrows.append(dict(x=x1, y=y1, ax=x0, ay=y0, xref="x", yref="y", axref="x", ayref="y", showarrow=True,
                           arrowhead=3, arrowsize=1.1, arrowwidth=3.2 if on else width, standoff=9, startstandoff=9,
                           arrowcolor="#F2F5F8" if on else color, opacity=0.12 if dim else (1 if on else 0.75)))
        seen_types.add(d["type"])
    fig.update_layout(annotations=arrows)
    for t in EDGE_STYLE:  # legend entries for edge types
        if t in seen_types:
            fig.add_scatter(x=[None], y=[None], mode="lines", line=dict(color=EDGE_STYLE[t][0], width=3), name=t)
    groups: dict[str, list] = {}
    for n, d in G.nodes(data=True):
        groups.setdefault(d["node_type"], []).append(n)
    names = {"External Entry Point": "External entry point", "Host": "Host", "Sensitive Asset": "Sensitive asset",
             "Service": "Service", "Vulnerability": "Vulnerability"}
    for nt in ["External Entry Point", "Host", "Sensitive Asset", "Service", "Vulnerability"]:
        ns = groups.get(nt, [])
        if not ns:
            continue
        if nt == "Vulnerability":
            symbol, size = "triangle-up", 13
            colors = [SEV_COLORS[G.nodes[n]["severity"]] for n in ns]
        else:
            symbol, size, c = NODE_STYLE[nt]
            colors = [c] * len(ns)
        label_on = show_labels or nt in ("Host", "Sensitive Asset", "External Entry Point")
        fig.add_scatter(
            x=[pos[n][0] for n in ns], y=[pos[n][1] for n in ns], mode="markers+text" if label_on else "markers",
            text=[html.escape(G.nodes[n]["label"]) for n in ns], textposition="bottom center",
            textfont=dict(size=10 if nt in ("Service", "Vulnerability") else 12, color=TEXT if nt not in ("Service", "Vulnerability") else MUTED),
            hovertext=[G.nodes[n]["hover"] for n in ns], hoverinfo="text", name=names[nt],
            marker=dict(symbol=symbol, size=size, color=colors, opacity=[1 if (not hl or n in hl) else 0.25 for n in ns],
                        line=dict(color=["#FFFFFF" if n in hl else "#0E141B" for n in ns], width=[2.5 if n in hl else 1 for n in ns])))
    fig.update_layout(dragmode="pan", hovermode="closest", xaxis=dict(visible=False), yaxis=dict(visible=False),
                      hoverlabel=dict(bgcolor=PANEL, font_color=TEXT))
    return style(fig, 640)


PLOT_CONFIG = {"displaylogo": False, "scrollZoom": True,
               "modeBarButtonsToRemove": ["select2d", "lasso2d"]}
