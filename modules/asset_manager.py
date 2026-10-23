"""Assets, services and relationships: dataset creation, validation and editing.

A *dataset* is a plain dict (JSON-serialisable):
  {"meta": {...}, "assets": [...], "services": [...], "findings": [...], "relationships": [...]}
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

from .config import (EXPOSURES, RELATIONSHIP_TYPES, ROLE_DEFAULT_CRITICALITY, ROLE_TIER, ROLES, ZONES)
from .vulnerability_mapper import normalize_finding

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_network.json"
SAMPLE_XML_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_scan.xml"


def empty_dataset(name: str = "Empty assessment") -> dict:
    return {"meta": {"name": name, "source": "manual"}, "assets": [], "services": [],
            "findings": [], "relationships": []}


def normalize_asset(raw: dict) -> dict:
    aid, ip = str(raw.get("id") or "").strip(), str(raw.get("ip") or "").strip()
    if not aid or not ip:
        raise ValueError("Every asset needs an id and an IP address")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address")
    role = raw.get("role") if raw.get("role") in ROLES else "Internal Service"
    try:
        crit = int(float(raw.get("criticality") or ROLE_DEFAULT_CRITICALITY[role]))
    except (TypeError, ValueError):
        raise ValueError(f"Criticality for {aid} must be a number from 1 to 5")
    if not 1 <= crit <= 5:
        raise ValueError(f"Criticality for {aid} must be between 1 and 5")
    return {
        "id": aid, "ip": ip, "hostname": str(raw.get("hostname") or "").strip(),
        "os": str(raw.get("os") or "").strip(), "status": str(raw.get("status") or "up"),
        "role": role, "zone": raw.get("zone") if raw.get("zone") in ZONES else "Internal",
        "exposure": raw.get("exposure") if raw.get("exposure") in EXPOSURES else "Internal",
        "criticality": crit, "is_critical": bool(raw.get("is_critical", False)),
    }


def _norm_service(raw: dict) -> dict:
    try:
        port = int(raw["port"])
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"Service on {raw.get('asset_id')} has an invalid port")
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} is outside 1-65535")
    return {"asset_id": raw["asset_id"], "port": port, "protocol": raw.get("protocol", "tcp"),
            "name": raw.get("name", "unknown") or "unknown", "product": raw.get("product", "") or "",
            "version": raw.get("version", "") or "", "state": raw.get("state", "open"),
            "exposed": bool(raw.get("exposed", True))}


def normalize_relationship(raw: dict, asset_ids: set) -> dict:
    src, dst = raw.get("src"), raw.get("dst")
    if src not in asset_ids or dst not in asset_ids:
        raise ValueError(f"Relationship {src} -> {dst} references an unknown asset")
    if src == dst:
        raise ValueError("A relationship needs two different assets")
    rtype = raw.get("type", "CONNECTS_TO")
    if rtype not in RELATIONSHIP_TYPES:
        raise ValueError(f"Relationship type must be one of {RELATIONSHIP_TYPES}")
    port = raw.get("port")
    port = int(port) if port not in (None, "", 0) else None
    conf = float(raw.get("confidence", 0.8))
    if not 0.0 <= conf <= 1.0:
        raise ValueError("Confidence must be between 0 and 1")
    return {"src": src, "dst": dst, "type": rtype, "port": port, "confidence": conf,
            "note": str(raw.get("note", ""))[:200]}


def validate_dataset(d: dict) -> dict:
    """Validate and normalise a dataset dict (e.g. loaded from JSON). Raises ValueError."""
    if not isinstance(d, dict):
        raise ValueError("Network configuration must be a JSON object")
    out = empty_dataset()
    out["meta"] = dict(d.get("meta") or {})
    out["meta"].setdefault("name", "Imported network")
    for a in d.get("assets", []):
        out["assets"].append(normalize_asset(a))
    ids = [a["id"] for a in out["assets"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Asset ids must be unique")
    for s in d.get("services", []):
        if s.get("asset_id") not in ids:
            raise ValueError(f"Service references unknown asset '{s.get('asset_id')}'")
        out["services"].append(_norm_service(s))
    for f in d.get("findings", []):
        out["findings"].append(normalize_finding(f, out))
    for r in d.get("relationships", []):
        out["relationships"].append(normalize_relationship(r, set(ids)))
    return out


def load_sample_network(path: Path | str = SAMPLE_PATH) -> dict:
    with open(path, encoding="utf-8") as fh:
        return validate_dataset(json.load(fh))


def load_network_json(data: bytes | str) -> dict:
    try:
        return validate_dataset(json.loads(data))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON: {exc}") from exc


def infer_role(services: list[dict]) -> str:
    ports = {s["port"] for s in services}
    if {88, 389} <= ports:
        return "Domain Controller"
    if ports & {3306, 5432, 1433, 1521, 27017, 6379}:
        return "Database Server"
    if ports & {80, 443}:
        return "Web Server"
    if ports & {8080, 8443, 8000, 5000, 3000, 9000}:
        return "Application Server"
    if ports & {3389, 445}:
        return "Workstation"
    return "Internal Service"


def infer_relationships(dataset: dict) -> list[dict]:
    """Assumed tier-based reachability (tier N -> N+1). Low confidence; users should review."""
    out = []
    assets = dataset["assets"]
    for a in assets:
        for b in assets:
            if ROLE_TIER.get(b["role"], 1) - ROLE_TIER.get(a["role"], 1) == 1:
                out.append({"src": a["id"], "dst": b["id"], "type": "CONNECTS_TO", "port": None,
                            "confidence": 0.4, "note": "Assumed tier-based reachability (inferred, unverified)"})
    return out


def dataset_from_scan(parsed: dict, name: str | None = None, internet_facing_ips: list[str] | None = None) -> dict:
    """Build a dataset from parse_nmap_xml output. Roles/exposure are assumptions the user can edit."""
    ds = empty_dataset(name or "Imported Nmap scan")
    ds["meta"].update({"source": "nmap", "scan": parsed["meta"],
                       "imported_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
    for n, h in enumerate((h for h in parsed["hosts"] if h["status"] == "up"), start=1):
        aid = f"A{n:02d}"
        svcs = [{"asset_id": aid, "port": p["port"], "protocol": p["protocol"], "name": p["name"],
                 "product": p["product"], "version": p["version"], "state": p["state"], "exposed": True}
                for p in h["ports"] if p["state"] == "open"]
        role = infer_role(svcs)
        if internet_facing_ips is None:
            facing = role == "Web Server"
        else:
            facing = h["ip"] in internet_facing_ips
        ds["assets"].append(normalize_asset({
            "id": aid, "ip": h["ip"], "hostname": h["hostname"], "os": h["os"], "role": role,
            "zone": "DMZ" if facing else "Internal",
            "exposure": "Internet-facing" if facing else "Internal",
            "criticality": ROLE_DEFAULT_CRITICALITY[role],
            "is_critical": role in ("Database Server", "Domain Controller")}))
        ds["services"].extend(_norm_service(s) for s in svcs)
    ds["relationships"] = infer_relationships(ds)
    return ds


def update_assets(dataset: dict, rows: list[dict]) -> None:
    """Replace editable asset fields from a list of row dicts (validated first, applied atomically)."""
    by_id = {r["id"]: normalize_asset({**a, **r}) for r in rows for a in dataset["assets"] if a["id"] == r["id"]}
    dataset["assets"] = [by_id.get(a["id"], a) for a in dataset["assets"]]


def add_relationship(dataset: dict, **kw) -> dict:
    rel = normalize_relationship(kw, {a["id"] for a in dataset["assets"]})
    if any((r["src"], r["dst"], r["type"], r["port"]) == (rel["src"], rel["dst"], rel["type"], rel["port"])
           for r in dataset["relationships"]):
        raise ValueError("This relationship already exists")
    dataset["relationships"].append(rel)
    return rel
