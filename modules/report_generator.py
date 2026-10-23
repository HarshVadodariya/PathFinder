"""PDF (ReportLab), CSV and JSON exports."""
from __future__ import annotations

import html
import io
import json
import math
from collections import deque
from datetime import datetime, timezone

import pandas as pd
from reportlab.graphics.shapes import Drawing, Line, Polygon, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .config import SEVERITIES, WEIGHTS
from .graph_builder import graph_to_dict

TEAL, INK, GREY = colors.HexColor("#1F5F6B"), colors.HexColor("#1B2530"), colors.HexColor("#5B6877")
LIMITATIONS = [
    "All attack paths are <b>modeled potential paths</b> derived from the supplied data and configured rules. They are not proof of exploitation or compromise.",
    "A detected service version does not prove a vulnerability. Findings are labelled confirmed, manual lab or potential; potential matches are heuristic and need verification.",
    "Network relationships (connectivity, trust) are assumptions entered or inferred by the user; inferred relationships are low confidence.",
    "Risk scores (0-100) use a transparent PathFinder formula and are not CVSS values. Scores depend on asset criticality and exposure assumptions.",
    "Path search is bounded by depth, transition and path-count limits, so very large environments may be truncated.",
    "Use only on authorized lab systems or data you are permitted to assess.",
]


def esc(x) -> str:
    return html.escape(str(x if x is not None else ""))


def findings_csv(dataset: dict) -> str:
    cols = ["id", "asset_id", "port", "cve", "cvss", "severity", "status", "category", "description", "remediation"]
    df = pd.DataFrame(dataset.get("findings", []), columns=cols)
    # Neutralise spreadsheet formula injection in text cells.
    for c in ("description", "remediation", "cve"):
        df[c] = df[c].map(lambda v: "'" + v if isinstance(v, str) and v[:1] in "=+-@" else v)
    return df.to_csv(index=False)


def graph_json(dataset: dict, result: dict) -> str:
    payload = {"meta": dataset.get("meta", {}), "graph": graph_to_dict(result["graph"]),
               "paths": [{k: p[k] for k in ("id", "summary", "transitions", "assumptions", "nodes")} | {"risk": p["risk"]} for p in result["paths"]]}
    return json.dumps(payload, indent=2, default=str)


def _graph_drawing(dataset: dict, result: dict, width: float = 480) -> Drawing:
    assets = {a["id"]: a for a in dataset["assets"]}
    edges = {("INTERNET", a["id"]) for a in assets.values() if a["exposure"] == "Internet-facing"}
    edges |= {(r["src"], r["dst"]) for r in dataset["relationships"]}
    top = set()
    if result["paths"]:
        chain = result["paths"][0]["asset_chain"]
        top = set(zip(chain, chain[1:]))
    depth = {"INTERNET": 0}
    q = deque(["INTERNET"])
    while q:
        n = q.popleft()
        for a, b in edges:
            if a == n and b not in depth:
                depth[b] = depth[n] + 1
                q.append(b)
    for aid in assets:  # not reachable from the Internet: place one column before its first successor
        if aid not in depth:
            succ = [depth[b] for a, b in edges if a == aid and b in depth]
            depth[aid] = max(1, min(succ) - 1) if succ else max(depth.values()) + 1
    layers: dict[int, list] = {}
    for n in ["INTERNET"] + list(assets):
        layers.setdefault(depth[n], []).append(n)
    cols, rows = max(layers) + 1, max(len(v) for v in layers.values())
    h = max(120, rows * 46 + 30)
    d = Drawing(width, h)
    pos = {n: (50 + x * (width - 100) / max(1, cols - 1) if cols > 1 else width / 2, h - 28 - i * 46 - (rows - len(ns)) * 23)
           for x, ns in layers.items() for i, n in enumerate(ns)}
    for a, b in edges:
        if a not in pos or b not in pos:
            continue
        (x0, y0), (x1, y1) = pos[a], pos[b]
        ang = math.atan2(y1 - y0, x1 - x0)
        sx, sy, ex, ey = x0 + 38 * math.cos(ang), y0 + 11 * math.sin(ang), x1 - 38 * math.cos(ang), y1 - 11 * math.sin(ang)
        col = colors.HexColor("#C0392B") if (a, b) in top else colors.HexColor("#8A98A8")
        d.add(Line(sx, sy, ex, ey, strokeColor=col, strokeWidth=2 if (a, b) in top else 0.8))
        d.add(Polygon([ex, ey, ex - 6 * math.cos(ang - 0.4), ey - 6 * math.sin(ang - 0.4),
                       ex - 6 * math.cos(ang + 0.4), ey - 6 * math.sin(ang + 0.4)], fillColor=col, strokeColor=col))
    for n, (x, y) in pos.items():
        crit = n in assets and assets[n]["is_critical"]
        d.add(Rect(x - 38, y - 11, 76, 22, rx=3, ry=3, strokeColor=colors.HexColor("#C0392B") if crit else TEAL,
                   fillColor=colors.HexColor("#FBEAEA") if crit else colors.HexColor("#E8F3F4")))
        lab = "Internet" if n == "INTERNET" else (assets[n]["hostname"] or assets[n]["ip"])
        d.add(String(x, y - 3, lab[:16], textAnchor="middle", fontSize=7, fillColor=INK))
    return d


def generate_pdf(dataset: dict, result: dict, recs: list[dict] | None = None) -> bytes:
    recs = recs or []
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Heading1"], textColor=TEAL, fontSize=16, spaceAfter=6)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], textColor=INK, fontSize=12, spaceBefore=10, spaceAfter=4)
    B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9, leading=12)
    S = ParagraphStyle("S", parent=B, fontSize=7.5, leading=9.5)
    s = result["summary"]
    meta = dataset.get("meta", {})
    scan = meta.get("scan", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def table(header, rows, widths):
        data = [[Paragraph(f"<b>{esc(h)}</b>", S) for h in header]] + [[Paragraph(esc(c), S) for c in r] for r in rows]
        t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F3F4")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#C5CED8")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
        return t

    f = []
    f += [Paragraph("PathFinder Assessment Report", H1), Paragraph(f"{esc(meta.get('name', 'Assessment'))} &middot; generated {now}", B), Spacer(1, 6)]
    f.append(Paragraph("1. Executive summary", H2))
    sev = s["severity_counts"]
    top = result["paths"][0] if result["paths"] else None
    f.append(Paragraph(
        f"The assessment covers <b>{s['assets']}</b> assets, <b>{s['open_ports']}</b> open services and <b>{s['findings']}</b> findings "
        f"({sev['Critical']} critical, {sev['High']} high, {sev['Medium']} medium, {sev['Low']} low, {sev['Unknown']} unknown). "
        f"The model identified <b>{s['paths']}</b> potential attack path(s) to sensitive assets. Overall modeled risk is "
        f"<b>{s['overall']:.1f}/100 ({esc(s['band'])})</b>." +
        (f" The highest-scoring modeled path is <b>{esc(top['id'])}</b> ({top['risk']['score']:.1f}): {esc(top['summary'])}." if top else
         " No modeled path reaches a sensitive asset under the current rules.") +
        " These are modeled paths, not evidence of compromise.", B))
    f.append(Paragraph("2. Assessment scope", H2))
    f.append(Paragraph(f"Source: {esc(meta.get('source', 'n/a'))}. {esc(meta.get('description', ''))} Assets in scope: " +
                       (esc(", ".join(a["hostname"] or a["ip"] for a in dataset["assets"])) or "none") +
                       f". Sensitive targets: {esc(', '.join(a['hostname'] or a['ip'] for a in dataset['assets'] if a['is_critical'])) or 'none designated'}.", B))
    f.append(Paragraph("3. Scan metadata", H2))
    f.append(table(["Field", "Value"], [["Scanner", scan.get("scanner", "n/a")], ["Scanner version", scan.get("version", "")],
                                       ["Command (as recorded)", scan.get("args", "")], ["Scan start", scan.get("scan_start", "")],
                                       ["Scan end", scan.get("scan_end", "")], ["Summary", scan.get("summary", "")]], [45, 125]))
    f.append(Paragraph("4. Asset inventory", H2))
    f.append(table(["ID", "IP", "Hostname", "Role", "Zone", "Exposure", "Crit.", "Sensitive"],
                   [[a["id"], a["ip"], a["hostname"], a["role"], a["zone"], a["exposure"], a["criticality"], "yes" if a["is_critical"] else "no"]
                    for a in dataset["assets"]] or [["-"] * 8], [12, 28, 34, 30, 22, 24, 10, 14]))
    f.append(Paragraph("5. Open services", H2))
    f.append(table(["Asset", "Port", "Service", "Product / version", "Exposed"],
                   [[s_["asset_id"], f"{s_['port']}/{s_['protocol']}", s_["name"], f"{s_['product']} {s_['version']}".strip(), "yes" if s_["exposed"] else "no"]
                    for s_ in dataset["services"]] or [["-"] * 5], [20, 22, 38, 70, 20]))
    f.append(Paragraph("6. Vulnerability findings", H2))
    f.append(table(["ID", "Asset", "Port", "Identifier", "CVSS", "Severity", "Status", "Description"],
                   [[x["id"], x["asset_id"], x["port"] or "", x["cve"], "" if x["cvss"] is None else x["cvss"], x["severity"], x["status"], x["description"]]
                    for x in dataset["findings"]] or [["-"] * 8], [15, 13, 13, 40, 12, 16, 19, 46]))
    f += [Paragraph("7. Attack graph (asset level)", H2),
          Paragraph("Arrows show configured relationships; the highest-risk modeled path is highlighted in red. Red-outlined boxes are sensitive assets.", B),
          _graph_drawing(dataset, result)]
    f.append(Paragraph("8. Potential attack paths (modeled)", H2))
    f.append(table(["Path", "Score", "Band", "Hops", "Route", "Vulnerabilities used"],
                   [[p["id"], f"{p['risk']['score']:.1f}", p["risk"]["band"], p["transitions"], p["summary"],
                     ", ".join(v["cve"] or v["finding_id"] for v in p["vulnerabilities"])] for p in result["paths"][:15]] or [["-", "", "", "", "No modeled paths", ""]],
                   [14, 14, 16, 12, 70, 44]))
    f.append(Paragraph("9. Risk score breakdown", H2))
    f.append(Paragraph("Score = 100 x (" + " + ".join(f"{w:.2f}&middot;{k}" for k, w in WEIGHTS.items()) +
                       ") x (0.5 + 0.5 x confidence). Components are normalised 0-1. This is a PathFinder score, not a CVSS value.", B))
    for p in result["paths"][:3]:
        r = p["risk"]
        f.append(Paragraph(f"<b>{esc(p['id'])}</b> &ndash; {r['score']:.1f} ({esc(r['band'])}), confidence {r['confidence']:.2f}", B))
        f.append(table(["Component", "Value", "Weight", "Points", "Why"],
                       [[c["name"], c["value"], c["weight"], c["contribution"], c["note"]] for c in r["components"]], [40, 16, 16, 16, 82]))
        f.append(Spacer(1, 4))
    f.append(Paragraph("10. Remediation recommendations", H2))
    f.append(table(["#", "Finding", "Asset", "Reason", "Action", "Priority", "Risk reduction"],
                   [[r["id"], r["finding"], r["asset"], r["reason"], r["action"], r["priority"], f"-{r['reduction']:.1f}"] for r in recs[:20]] or [["-"] * 7],
                   [10, 38, 22, 36, 44, 14, 14]))
    f.append(Paragraph("Expected risk reduction is simulated: the fix is applied to a copy of the data and the overall score is recomputed.", S))
    f.append(Paragraph("11. Limitations and assumptions", H2))
    for l in LIMITATIONS:
        f.append(Paragraph("&bull; " + l, B))
    if top:
        f.append(Paragraph("Assumptions used by the top path", H2))
        for a in top["assumptions"]:
            f.append(Paragraph("&bull; " + esc(a), S))

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                      title="PathFinder Assessment Report", author="PathFinder").build(f)
    return buf.getvalue()
