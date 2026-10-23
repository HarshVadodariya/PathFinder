"""Shared Streamlit helpers: session state, cached analysis, small display utilities."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import streamlit as st

from modules.analysis import analyze
from modules.asset_manager import load_sample_network
from modules.config import RuleConfig
from modules.database import Database
from modules.remediation_engine import generate_recommendations

ROOT = Path(__file__).resolve().parent.parent
MODELED = "Modeled potential attack paths: derived from supplied data and configured rules. They are not proof of exploitation or compromise."


def load_css() -> None:
    st.markdown(f"<style>{(ROOT / 'assets' / 'custom.css').read_text()}</style>", unsafe_allow_html=True)


def header(title: str, sub: str = "") -> None:
    st.markdown(f"<p class='pf-title'>{title}</p><p class='pf-sub'>{sub}</p>", unsafe_allow_html=True)


def note(text: str) -> None:
    st.markdown(f"<div class='pf-note'>{text}</div>", unsafe_allow_html=True)


def chip(band: str) -> str:
    return f"<span class='pf-chip pf-{band}'>{band}</span>"


def db() -> Database:
    if "db" not in st.session_state:
        st.session_state["db"] = Database(ROOT / "data" / "pathfinder.db")
    return st.session_state["db"]


def dataset() -> dict | None:
    return st.session_state.get("dataset")


def set_dataset(ds: dict) -> None:
    st.session_state["dataset"] = ds
    for k in ("_analysis", "_recs", "report"):
        st.session_state.pop(k, None)


def rules() -> RuleConfig:
    return RuleConfig.from_dict(st.session_state.get("rules"))


def _key(ds: dict, r: RuleConfig) -> str:
    return hashlib.sha1(json.dumps([ds, r.to_dict()], sort_keys=True, default=str).encode()).hexdigest()


def result() -> dict:
    ds, r = dataset(), rules()
    k = _key(ds, r)
    if st.session_state.get("_analysis", (None,))[0] != k:
        st.session_state["_analysis"] = (k, analyze(ds, r))
    return st.session_state["_analysis"][1]


def recommendations() -> list[dict]:
    ds, r = dataset(), rules()
    k = _key(ds, r)
    if st.session_state.get("_recs", (None,))[0] != k:
        st.session_state["_recs"] = (k, generate_recommendations(ds, result(), r))
    return st.session_state["_recs"][1]


def require_dataset() -> bool:
    if dataset() is not None:
        return True
    st.info("No assessment is loaded yet. Load the built-in sample lab to explore, or import an Nmap XML file on the Import Scan page.")
    if st.button("Load sample lab", type="primary"):
        set_dataset(load_sample_network())
        st.rerun()
    return False


def table(df: pd.DataFrame, **kw) -> None:
    st.dataframe(df, hide_index=True, width="stretch", **kw)


def plot(fig, key: str | None = None, config: dict | None = None) -> None:
    st.plotly_chart(fig, width="stretch", key=key, config=config or {"displaylogo": False})
