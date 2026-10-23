"""The nine Streamlit pages. Each function renders one page; business logic lives in modules/."""
from __future__ import annotations

import json
from dataclasses import asdict

import pandas as pd
import streamlit as st

from modules import visualization as viz
from modules.analysis import analyze
from modules.asset_manager import (SAMPLE_XML_PATH, add_relationship, dataset_from_scan, infer_relationships,
                                   load_network_json, load_sample_network, update_assets)
from modules.config import (CATEGORIES, EXPOSURES, RELATIONSHIP_TYPES, ROLES, SEV_COLORS, SEVERITIES, STATUS_CONFIDENCE,
                            WEIGHTS, ZONES, RuleConfig)
from modules.nmap_parser import NmapParseError, parse_nmap_xml
from modules.remediation_engine import simulate
from modules.report_generator import findings_csv, generate_pdf, graph_json
from modules.vulnerability_mapper import add_finding, add_potential_matches, import_findings_csv
from ui.common import (MODELED, chip, dataset, db, header, note, plot, recommendations, require_dataset, result, rules,
                       set_dataset, table)


def _labels(ds):
    return {a["id"]: a["hostname"] or a["ip"] for a in ds["assets"]}


# 1 ---------------------------------------------------------------------------------------------
def overview():
    header("Overview", "Summary of the loaded assessment. Every value is computed from the current data.")
    if not require_dataset():
        return
    ds, res = dataset(), result()
    s = res["summary"]
    sev = s["severity_counts"]
    st.caption(f"Assessment: **{ds['meta'].get('name', 'Untitled')}** · source: {ds['meta'].get('source', 'n/a')}")
    c = st.columns(4)
    c[0].metric("Assets", s["assets"]); c[1].metric("Open ports", s["open_ports"])
    c[2].metric("Vulnerabilities", s["findings"]); c[3].metric("Potential attack paths", s["paths"])
    c = st.columns(5)
    c[0].metric("Critical", sev["Critical"]); c[1].metric("High", sev["High"]); c[2].metric("Medium", sev["Medium"])
    c[3].metric("Low", sev["Low"]); c[4].metric("Critical assets", s["critical_assets"])
    left, right = st.columns([2, 1])
    with left:
        plot(viz.severity_chart(sev), key="ov_sev")
    with right:
        st.markdown(f"**Overall assessment risk** {chip(s['band']) if s['band'] != 'None' else ''}", unsafe_allow_html=True)
        plot(viz.gauge(s["overall"], s["band"]), key="ov_gauge")
        st.caption("0.6 × top path + 0.4 × mean of top 3 paths (0.5 × highest asset score when no paths exist).")
    a, b = st.columns(2)
    with a:
        eh = s["exposed_by_host"]
        plot(viz.bar_chart(list(eh), list(eh.values()), "Exposed services by host", horizontal=True), key="ov_exp")
    with b:
        rows = sorted(res["asset_risks"], key=lambda r: -r["score"])
        plot(viz.bar_chart([r["label"] for r in rows], [r["score"] for r in rows], "Asset risk score (0-100)",
                           color="#7C93B0", horizontal=True), key="ov_asset")
    a, b = st.columns(2)
    with a:
        pb = s["path_bands"]
        order = [k for k in ["Critical", "High", "Medium", "Low"] if k in pb]
        plot(viz.bar_chart(order, [pb[k] for k in order], f"Attack paths by risk band ({s['paths']} total)",
                           colors=[SEV_COLORS[k] for k in order]), key="ov_paths")
    with b:
        ts = s["top_services"]
        plot(viz.bar_chart(list(ts), list(ts.values()), "Most frequently exposed services"), key="ov_top")
    st.subheader("Recent scan history")
    hist = db().list_scans(8)
    if st.button("Save current assessment to history"):
        db().save_scan(ds, s)
        st.rerun()
    if hist:
        table(pd.DataFrame(hist).rename(columns={"overall_risk": "risk"}))
    else:
        st.caption("No saved assessments yet.")


# 2 ---------------------------------------------------------------------------------------------
def import_scan():
    header("Import Scan", "Load authorized lab data: an Nmap XML report, the built-in sample, or a network JSON file.")
    t1, t2, t3, t4 = st.tabs(["Nmap XML", "Sample lab", "Network JSON", "Saved assessments"])
    with t1:
        note("Import results only from systems you are authorized to assess. PathFinder never runs scans; it only reads files you provide.")
        up = st.file_uploader("Nmap XML report (-oX)", type=["xml"])
        use_sample = st.checkbox("Use the bundled sample_scan.xml instead")
        raw = SAMPLE_XML_PATH.read_bytes() if use_sample else (up.getvalue() if up else None)
        if raw is not None:
            try:
                parsed = parse_nmap_xml(raw)
            except NmapParseError as exc:
                st.error(f"Import failed: {exc}")
            else:
                for w in parsed["warnings"]:
                    st.warning(w)
                m = parsed["meta"]
                st.caption(f"Scanner: {m['scanner']} {m['version']} · started {m['scan_start']} · {m['summary']}")
                rows = [{"IP": h["ip"], "Hostname": h["hostname"], "Status": h["status"], "OS": h["os"],
                         "Open ports": ", ".join(f"{p['port']}/{p['name']}" for p in h["ports"] if p["state"] == "open")}
                        for h in parsed["hosts"]]
                table(pd.DataFrame(rows))
                up_hosts = [h["ip"] for h in parsed["hosts"] if h["status"] == "up"]
                guess = dataset_from_scan(parsed)
                default_facing = [a["ip"] for a in guess["assets"] if a["exposure"] == "Internet-facing"]
                facing = st.multiselect("Internet-facing hosts (modeled entry points)", up_hosts, default=default_facing,
                                        help="Default guess: hosts that look like web servers. Roles and criticality are assumptions you can edit later.")
                name = st.text_input("Assessment name", value="Imported Nmap scan")
                if st.button("Create assessment", type="primary", disabled=not parsed["hosts"]):
                    set_dataset(dataset_from_scan(parsed, name, facing))
                    st.success("Assessment created. Review roles and sensitive assets on the Asset Inventory page.")
    with t2:
        ds = load_sample_network()
        st.write(ds["meta"]["description"])
        st.caption(f"{len(ds['assets'])} assets · {len(ds['services'])} services · {len(ds['findings'])} findings · {len(ds['relationships'])} relationships. Configurable in data/sample_network.json.")
        if st.button("Load sample lab", type="primary", key="load_sample"):
            set_dataset(ds)
            st.success("Sample lab loaded.")
    with t3:
        j = st.file_uploader("Network configuration (JSON)", type=["json"])
        if j is not None:
            try:
                ds = load_network_json(j.getvalue())
            except ValueError as exc:
                st.error(f"Invalid network file: {exc}")
            else:
                st.success(f"Valid: {len(ds['assets'])} assets, {len(ds['findings'])} findings.")
                if st.button("Load this network"):
                    set_dataset(ds)
    with t4:
        scans = db().list_scans(30)
        if not scans:
            st.caption("Nothing saved yet. Use 'Save current assessment to history' on the Overview page.")
        else:
            table(pd.DataFrame(scans))
            pick = st.selectbox("Saved assessment", [s["id"] for s in scans],
                                format_func=lambda i: next(f"#{s['id']} {s['name']} ({s['created_at']})" for s in scans if s["id"] == i))
            c1, c2 = st.columns(2)
            if c1.button("Load"):
                set_dataset(db().load_dataset(pick))
                st.success("Loaded.")
            if c2.button("Delete"):
                db().delete_scan(pick)
                st.rerun()


# 3 ---------------------------------------------------------------------------------------------
def asset_inventory():
    header("Asset Inventory", "Edit roles, criticality, exposure and sensitive-asset designation, then recalculate.")
    if not require_dataset():
        return
    ds = dataset()
    df = pd.DataFrame(ds["assets"])[["id", "ip", "hostname", "os", "role", "zone", "exposure", "criticality", "is_critical"]]
    edited = st.data_editor(
        df, hide_index=True, width="stretch", disabled=["id", "ip", "os"], key="asset_editor",
        column_config={"role": st.column_config.SelectboxColumn("Business role", options=ROLES, required=True),
                       "zone": st.column_config.SelectboxColumn("Network zone", options=ZONES, required=True),
                       "exposure": st.column_config.SelectboxColumn("Exposure", options=list(EXPOSURES), required=True),
                       "criticality": st.column_config.NumberColumn("Criticality (1-5)", min_value=1, max_value=5, step=1),
                       "is_critical": st.column_config.CheckboxColumn("Sensitive / critical")})
    if st.button("Save asset changes", type="primary"):
        try:
            update_assets(ds, edited.to_dict("records"))
            set_dataset(ds)
            st.success("Saved. The graph and risk scores were recalculated.")
        except ValueError as exc:
            st.error(str(exc))
    st.subheader("Exposed services")
    lab = _labels(ds)
    sv = pd.DataFrame([{"asset": lab[s["asset_id"]], **{k: s[k] for k in ("port", "protocol", "name", "product", "version", "state", "exposed")}}
                       for s in ds["services"]])
    if sv.empty:
        st.caption("No open services.")
    else:
        pick = st.multiselect("Filter by asset", sorted(sv["asset"].unique()))
        table(sv[sv["asset"].isin(pick)] if pick else sv)
    st.subheader("Network relationships")
    st.caption("CONNECTS_TO lets a foothold on the source reach a service on the destination. TRUSTS lets it act on the destination host directly.")
    rel = pd.DataFrame([{**r, "src": lab[r["src"]], "dst": lab[r["dst"]]} for r in ds["relationships"]])
    if not rel.empty:
        table(rel)
    ids = [a["id"] for a in ds["assets"]]
    with st.form("rel_form", clear_on_submit=True):
        c = st.columns(5)
        src = c[0].selectbox("From", ids, format_func=lab.get)
        dst = c[1].selectbox("To", ids, format_func=lab.get, index=min(1, len(ids) - 1) if ids else 0)
        rt = c[2].selectbox("Type", RELATIONSHIP_TYPES)
        port = c[3].number_input("Port (0 = any exposed)", 0, 65535, 0)
        conf = c[4].slider("Confidence", 0.0, 1.0, 0.7, 0.05)
        text = st.text_input("Note")
        if st.form_submit_button("Add relationship") and ids:
            try:
                add_relationship(ds, src=src, dst=dst, type=rt, port=port or None, confidence=conf, note=text)
                set_dataset(ds)
                st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    c1, c2 = st.columns(2)
    if ds["relationships"]:
        gone = c1.multiselect("Remove relationships", range(len(ds["relationships"])),
                              format_func=lambda i: f"{lab[ds['relationships'][i]['src']]} → {lab[ds['relationships'][i]['dst']]} ({ds['relationships'][i]['type']})")
        if gone and c1.button("Remove selected"):
            ds["relationships"] = [r for i, r in enumerate(ds["relationships"]) if i not in gone]
            set_dataset(ds)
            st.rerun()
    if c2.button("Add inferred tier-based relationships"):
        have = {(r["src"], r["dst"], r["type"], r["port"]) for r in ds["relationships"]}
        ds["relationships"] += [r for r in infer_relationships(ds) if (r["src"], r["dst"], r["type"], r["port"]) not in have]
        set_dataset(ds)
        st.rerun()


# 4 ---------------------------------------------------------------------------------------------
def findings():
    header("Vulnerability Findings", "Confirmed, potential and manually supplied lab findings are kept separate.")
    if not require_dataset():
        return
    ds = dataset()
    lab = _labels(ds)
    note("A detected service version does not prove a vulnerability. 'Potential match' findings are heuristic and are down-weighted in the model.")
    c = st.columns(3)
    sev = c[0].multiselect("Severity", SEVERITIES, default=SEVERITIES)
    stat = c[1].multiselect("Status", list(STATUS_CONFIDENCE), default=list(STATUS_CONFIDENCE))
    asset = c[2].multiselect("Asset", list(lab), format_func=lab.get)
    rows = [{"id": f["id"], "asset": lab[f["asset_id"]], "port": f["port"], "identifier": f["cve"], "cvss": f["cvss"],
             "severity": f["severity"], "status": f["status"], "category": f["category"], "description": f["description"]}
            for f in ds["findings"] if f["severity"] in sev and f["status"] in stat and (not asset or f["asset_id"] in asset)]
    if rows:
        table(pd.DataFrame(rows))
    else:
        st.caption("No findings match the filters.")
    st.download_button("Export findings (CSV)", findings_csv(ds), "findings.csv", "text/csv")
    t1, t2, t3, t4 = st.tabs(["Add finding", "Import CSV", "Potential matches", "Remove"])
    with t1, st.form("add_f", clear_on_submit=True):
        c = st.columns(4)
        a = c[0].selectbox("Affected asset", list(lab), format_func=lab.get)
        ports = [s["port"] for s in ds["services"] if s["asset_id"] == a]
        port = c[1].number_input("Affected port (0 = host-level)", 0, 65535, 0)
        cve = c[2].text_input("CVE or SAMPLE-* id")
        cvss = c[3].text_input("CVSS (blank = unknown)")
        c = st.columns(2)
        status = c[0].selectbox("Status", list(STATUS_CONFIDENCE), index=1)
        cat = c[1].selectbox("Category", CATEGORIES)
        desc = st.text_area("Description")
        rem = st.text_input("Remediation (optional)")
        if st.form_submit_button("Add finding"):
            try:
                add_finding(ds, {"asset_id": a, "port": port or None, "cve": cve, "cvss": cvss, "status": status,
                                 "category": cat, "description": desc, "remediation": rem})
                set_dataset(ds)
                st.rerun()
            except ValueError as exc:
                st.error(f"{exc}" + (f" (available ports: {ports})" if "port" in str(exc) else ""))
    with t2:
        st.caption("Columns: asset (id, IP or hostname), port, cve, cvss, status, category, description, remediation. Required: asset, description.")
        f = st.file_uploader("Findings CSV", type=["csv"])
        if f is not None and st.button("Import findings"):
            added, errs = import_findings_csv(ds, f.getvalue())
            set_dataset(ds)
            st.success(f"Imported {added} finding(s).")
            for e in errs[:20]:
                st.warning(e)
    with t3:
        st.write("Suggest heuristic matches from banner data (e.g. old SSH releases, exposed Telnet/FTP). Results are added as *potential* findings with estimated scores.")
        if st.button("Suggest potential matches"):
            n = add_potential_matches(ds)
            set_dataset(ds)
            st.success(f"Added {n} potential finding(s).") if n else st.info("No new heuristic matches.")
    with t4:
        gone = st.multiselect("Findings to remove", [f["id"] for f in ds["findings"]])
        if gone and st.button("Remove selected findings"):
            ds["findings"] = [f for f in ds["findings"] if f["id"] not in gone]
            set_dataset(ds)
            st.rerun()


# 5 ---------------------------------------------------------------------------------------------
def attack_paths():
    header("Attack Path Explorer", "Rule-based traversal from an entry point to sensitive assets.")
    if not require_dataset():
        return
    ds = dataset()
    lab = _labels(ds)
    r = rules()
    with st.expander("Analysis rules and limits", expanded=False):
        c = st.columns(4)
        starts = ["INTERNET"] + [f"host:{a}" for a in lab]
        r.start = c[0].selectbox("Start", starts, index=starts.index(r.start) if r.start in starts else 0,
                                 format_func=lambda s: "Internet (external attacker)" if s == "INTERNET" else f"Assumed foothold: {lab[s[5:]]}", key="w_start")
        r.min_cvss = c[1].slider("Minimum CVSS for a transition", 0.0, 10.0, float(r.min_cvss), 0.5, key="w_cvss")
        r.max_transitions = c[2].slider("Max host transitions", 1, 8, int(r.max_transitions), key="w_trans")
        r.max_paths = c[3].slider("Max paths", 10, 300, int(r.max_paths), 10, key="w_paths")
        c = st.columns(3)
        r.include_potential = c[0].checkbox("Include potential matches", r.include_potential, key="w_pot")
        r.include_unknown = c[1].checkbox("Include unknown CVSS (assumed 5.0)", r.include_unknown, key="w_unk")
        r.allow_trust = c[2].checkbox("Allow trust relationships", r.allow_trust, key="w_trust")
        st.session_state["rules"] = asdict(r)
    res = result()
    paths = res["paths"]
    note(MODELED)
    if res["truncated"]:
        st.warning("The search hit the configured limit; some paths were not listed. Raise the limits to explore more.")
    c1, c2 = st.columns(2)
    sev = c1.selectbox("Show vulnerabilities at or above", ["Unknown", "Informational", "Low", "Medium", "High", "Critical"], index=0)
    shown = c2.multiselect("Show assets", list(lab), default=list(lab), format_func=lab.get)
    sel = None
    if paths:
        opts = {p["id"]: f"{p['id']} · {p['risk']['score']:.1f} {p['risk']['band']} · {p['summary']}" for p in paths}
        pid = st.selectbox("Inspect path", list(opts), format_func=opts.get)
        sel = next(p for p in paths if p["id"] == pid)
    else:
        st.info("No modeled path reaches a sensitive asset with the current rules. Mark an asset as sensitive, add relationships, or relax the rules.")
    G = viz.filter_graph(res["graph"], sev, shown)
    plot(viz.attack_graph_figure(G, sel["nodes"] if sel else None, show_labels=st.toggle("Label services and vulnerabilities", True)),
         key="ap_graph", config=viz.PLOT_CONFIG)
    st.caption("Scroll to zoom, drag to pan, double-click to reset. Dotted lines show which host runs which service.")
    if sel:
        rk = sel["risk"]
        st.markdown(f"### {sel['id']} {chip(rk['band'])}  **{rk['score']:.1f}/100**", unsafe_allow_html=True)
        st.markdown(f"<div class='pf-chain'>{sel['summary']}</div>", unsafe_allow_html=True)
        a, b, c = st.columns(3)
        a.metric("Transitions", sel["transitions"]); b.metric("Confidence", f"{rk['confidence']:.0%}"); c.metric("Target", sel["target_label"])
        st.markdown("**Vulnerabilities used**")
        table(pd.DataFrame([{"id": v["cve"] or v["finding_id"], "asset": lab[v["asset_id"]], "cvss": v["cvss"], "severity": v["severity"], "status": v["status"]} for v in sel["vulnerabilities"]]))
        st.markdown("**Risk breakdown**")
        table(pd.DataFrame(rk["components"]).rename(columns={"name": "component", "contribution": "points"}))
        st.caption(f"Base {rk['base']} × confidence multiplier {rk['multiplier']} = {rk['score']}")
        with st.expander("Assumptions used by this path", expanded=True):
            for x in sel["assumptions"]:
                st.markdown(f"- {x}")


# 6 ---------------------------------------------------------------------------------------------
def risk_analysis():
    header("Risk Analysis", "How scores are built, and what changes when asset assumptions change.")
    if not require_dataset():
        return
    ds, res = dataset(), result()
    with st.expander("Scoring method", expanded=False):
        st.markdown(
            "**Path score (0-100)** = 100 × (" + " + ".join(f"{w:.2f}·{k}" for k, w in WEIGHTS.items()) + ") × (0.5 + 0.5 × confidence)\n\n"
            "- **severity**: 0.6 × max CVSS/10 + 0.4 × mean CVSS/10 over vulnerabilities on the path (unknown CVSS uses a configurable default)\n"
            "- **criticality**: target criticality / 5\n- **sensitive**: 1 if the target is a designated sensitive asset\n"
            "- **exposure**: factor of the entry asset: " + ", ".join(f"{k} {v}" for k, v in EXPOSURES.items()) + "\n"
            "- **length**: max(0.2, 1 − 0.20 × (transitions − 1))\n- **confidence**: mean confidence of relationships and findings used\n\n"
            "This is a PathFinder score, **not** a CVSS value.")
    s = res["summary"]
    c = st.columns(3)
    c[0].metric("Overall risk", f"{s['overall']:.1f}"); c[1].metric("Band", s["band"]); c[2].metric("Modeled paths", s["paths"])
    if res["paths"]:
        plot(viz.path_components_chart(res["paths"]), key="ra_comp")
    st.subheader("Asset risk")
    table(pd.DataFrame(res["asset_risks"]).sort_values("score", ascending=False))
    st.subheader("What-if: adjust assumptions")
    st.caption("Change criticality or exposure, compare the result, then apply.")
    df = pd.DataFrame(ds["assets"])[["id", "hostname", "exposure", "criticality", "is_critical"]]
    ed = st.data_editor(df, hide_index=True, width="stretch", disabled=["id", "hostname"], key="whatif",
                        column_config={"exposure": st.column_config.SelectboxColumn(options=list(EXPOSURES), required=True),
                                       "criticality": st.column_config.NumberColumn(min_value=1, max_value=5, step=1),
                                       "is_critical": st.column_config.CheckboxColumn("Sensitive")})
    import copy
    trial = copy.deepcopy(ds)
    try:
        update_assets(trial, ed.to_dict("records"))
        t = analyze(trial, rules())["summary"]
        a, b = st.columns(2)
        a.metric("Overall risk with these assumptions", f"{t['overall']:.1f}", f"{t['overall'] - s['overall']:+.1f}", delta_color="inverse")
        b.metric("Paths", t["paths"], t["paths"] - s["paths"], delta_color="inverse")
        if st.button("Apply assumptions and recalculate", type="primary"):
            update_assets(ds, ed.to_dict("records"))
            set_dataset(ds)
            st.rerun()
    except ValueError as exc:
        st.error(str(exc))


# 7 ---------------------------------------------------------------------------------------------
def remediation():
    header("Remediation Center", "Rule-based recommendations. Risk reduction is simulated by re-running the analysis.")
    if not require_dataset():
        return
    recs = recommendations()
    if not recs:
        st.info("No recommendations: there are no findings, exposed risky services, or modeled paths.")
        return
    pr = st.multiselect("Priority", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    shown = [r for r in recs if r["priority"] in pr]
    table(pd.DataFrame([{k: r[k] for k in ("id", "priority", "finding", "asset", "reason", "action", "reduction")} for r in shown])
          .rename(columns={"reduction": "expected risk reduction"}))
    st.subheader("Simulate fixes")
    pick = st.multiselect("Apply together", [r["id"] for r in recs], format_func=lambda i: next(f"{r['id']} {r['priority']}: {r['finding'][:70]}" for r in recs if r["id"] == i))
    if pick:
        out = simulate(dataset(), rules(), [r for r in recs if r["id"] in pick])
        a, b = st.columns(2)
        a.metric("Overall risk after fixes", f"{out['after']:.1f}", f"{out['after'] - out['before']:+.1f}", delta_color="inverse")
        b.metric("Attack paths after fixes", out["paths_after"], out["paths_after"] - out["paths_before"], delta_color="inverse")
        st.caption("Simulation only: nothing in your data is changed.")


# 8 ---------------------------------------------------------------------------------------------
def reports():
    header("Reports", "Download the assessment as PDF, CSV or JSON.")
    if not require_dataset():
        return
    ds, res = dataset(), result()
    if st.button("Generate PDF report", type="primary"):
        with st.spinner("Building report..."):
            pdf = generate_pdf(ds, res, recommendations())
        st.session_state["report"] = pdf
        db().log_report(None, "pathfinder_report.pdf", "pdf", len(pdf))
    c = st.columns(3)
    if "report" in st.session_state:
        c[0].download_button("Download PDF", st.session_state["report"], "pathfinder_report.pdf", "application/pdf")
    c[1].download_button("Findings (CSV)", findings_csv(ds), "findings.csv", "text/csv")
    c[2].download_button("Graph and paths (JSON)", graph_json(ds, res), "attack_graph.json", "application/json")
    st.download_button("Network dataset (JSON)", json.dumps(ds, indent=2), "network.json", "application/json")
    hist = db().list_reports(8)
    if hist:
        st.subheader("Recent reports")
        table(pd.DataFrame(hist).drop(columns=["scan_id"]))


# 9 ---------------------------------------------------------------------------------------------
def about():
    header("About PathFinder", "Attack Path Visualization and Risk Analyzer · B.Tech CSE mini-project")
    st.markdown("""
**Problem.** Vulnerability reports list findings one by one. Weaknesses, exposed services and trust relationships can combine into paths from an entry point to a sensitive asset. PathFinder models those paths so remediation can be prioritised.

**Pipeline.** Nmap XML or sample JSON → assets, services, findings, relationships → NetworkX directed graph → rule-based path search → 0-100 risk score → remediation simulation → PDF/CSV/JSON reports.

**Graph model.** Nodes: External Entry Point, Host, Sensitive Asset, Service, Vulnerability. Edges: EXPOSES, HOSTS, AFFECTED_BY, POTENTIAL_TRANSITION, CONNECTS_TO, TRUSTS.

**Transition rules.** R1 an Internet-facing exposed service is an entry point. R2 a finding on a reachable service (CVSS ≥ threshold, status allowed) may give a foothold on that host. R3 a configured trust allows direct movement. R4 a configured relationship lets a foothold reach a service on another host. Search is bounded by depth, transition and path-count limits.

**Limitations.** Paths are modeled, not verified. Relationships are assumptions. Scores are not CVSS. Heuristic matches need verification.

**Ethics.** For authorized lab data only. PathFinder does not scan, exploit, or execute anything from uploaded files.
""")
