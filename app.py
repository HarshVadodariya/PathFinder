"""PathFinder - Attack Path Visualization and Risk Analyzer (Streamlit entry point)."""
import streamlit as st

from ui import views
from ui.common import dataset, load_css, result

st.set_page_config(page_title="PathFinder", page_icon="🧭", layout="wide")
load_css()

PAGES = {
    "Overview Dashboard": views.overview, "Import Scan": views.import_scan, "Asset Inventory": views.asset_inventory,
    "Vulnerability Findings": views.findings, "Attack Path Explorer": views.attack_paths,
    "Risk Analysis": views.risk_analysis, "Remediation Center": views.remediation, "Reports": views.reports,
    "About Project": views.about,
}

with st.sidebar:
    st.markdown("### PathFinder")
    st.caption("Attack path visualization and risk analyzer")
    page = st.radio("Navigate", list(PAGES), label_visibility="collapsed")
    ds = dataset()
    if ds is not None:
        s = result()["summary"]
        st.divider()
        st.caption(f"**{ds['meta'].get('name', 'Assessment')}**")
        st.caption(f"{s['assets']} assets · {s['paths']} paths · risk {s['overall']:.0f} ({s['band']})")
    st.divider()
    st.caption("Modeled paths only. Authorized lab data only.")

PAGES[page]()
