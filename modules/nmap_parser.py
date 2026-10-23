"""Nmap XML importer. Parses data only; never executes anything from the file."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timezone

MAX_BYTES = 10 * 1024 * 1024


class NmapParseError(Exception):
    """Raised when the uploaded file cannot be treated as valid Nmap XML."""


def _iso(epoch) -> str | None:
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_nmap_xml(data) -> dict:
    """Parse Nmap XML (bytes or str) into {'meta', 'hosts', 'warnings'}.

    Raises NmapParseError for empty, oversized, malformed or non-Nmap input.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not data or not data.strip():
        raise NmapParseError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise NmapParseError(f"The file is larger than {MAX_BYTES // 1024 // 1024} MB.")
    if b"<!ENTITY" in data.upper():
        raise NmapParseError("XML entity declarations are not allowed (possible entity-expansion attack).")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise NmapParseError(f"Malformed XML: {exc}") from exc
    if root.tag != "nmaprun":
        raise NmapParseError(f"Not an Nmap XML report (root element is <{root.tag}>, expected <nmaprun>).")

    runstats = root.find("runstats/finished")
    meta = {
        "scanner": root.get("scanner", "nmap"), "version": root.get("version", ""),
        "args": root.get("args", ""), "scan_start": _iso(root.get("start")),
        "scan_end": _iso(runstats.get("time")) if runstats is not None else None,
        "summary": runstats.get("summary", "") if runstats is not None else "",
    }
    hosts, warnings = [], []
    for idx, h in enumerate(root.findall("host"), start=1):
        addr = None
        for a in h.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = addr if (addr and a.get("addrtype") == "ipv6") else a.get("addr")
        if not addr:
            warnings.append(f"Host #{idx} has no IP address and was skipped.")
            continue
        st = h.find("status")
        hn = h.find("hostnames/hostname")
        osm = h.find("os/osmatch")
        ports = []
        for p in h.findall("ports/port"):
            try:
                num = int(p.get("portid", ""))
            except ValueError:
                warnings.append(f"{addr}: invalid port id '{p.get('portid')}' skipped.")
                continue
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": num, "protocol": p.get("protocol", "tcp"),
                "state": state.get("state", "unknown") if state is not None else "unknown",
                "name": svc.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "extrainfo": svc.get("extrainfo", "") if svc is not None else "",
            })
        hosts.append({
            "ip": addr, "status": st.get("state", "unknown") if st is not None else "unknown",
            "hostname": hn.get("name", "") if hn is not None else "",
            "os": osm.get("name", "") if osm is not None else "",
            "scan_time": _iso(h.get("starttime")) or meta["scan_start"], "ports": ports,
        })
    if not hosts:
        warnings.append("No usable hosts were found in this report.")
    return {"meta": meta, "hosts": hosts, "warnings": warnings}
