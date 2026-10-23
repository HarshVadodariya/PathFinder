"""SQLite storage for scan history, assets, findings and generated reports (parameterised queries only)."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, source TEXT, created_at TEXT NOT NULL,
  scanner TEXT, scan_time TEXT, assets INTEGER, open_ports INTEGER, findings INTEGER, paths INTEGER,
  overall_risk REAL, dataset_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  asset_id TEXT, ip TEXT, hostname TEXT, role TEXT, criticality INTEGER, exposure TEXT, is_critical INTEGER);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id TEXT, asset_id TEXT, port INTEGER, cve TEXT, cvss REAL, severity TEXT, status TEXT,
  category TEXT, description TEXT);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL, filename TEXT, fmt TEXT, size_bytes INTEGER);
"""


class Database:
    def __init__(self, path: str | Path = "data/pathfinder.db"):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with closing(self._conn()) as c:
            c.executescript(SCHEMA)
            c.commit()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def save_scan(self, dataset: dict, summary: dict) -> int:
        meta = dataset.get("meta", {})
        scan = meta.get("scan", {})
        with closing(self._conn()) as c:
            cur = c.execute(
                "INSERT INTO scans (name, source, created_at, scanner, scan_time, assets, open_ports, findings, paths,"
                " overall_risk, dataset_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (meta.get("name", "Assessment"), meta.get("source", ""), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 scan.get("scanner", ""), scan.get("scan_start", ""), summary["assets"], summary["open_ports"],
                 summary["findings"], summary["paths"], summary["overall"], json.dumps(dataset)))
            sid = cur.lastrowid
            c.executemany("INSERT INTO assets (scan_id, asset_id, ip, hostname, role, criticality, exposure, is_critical)"
                          " VALUES (?,?,?,?,?,?,?,?)",
                          [(sid, a["id"], a["ip"], a["hostname"], a["role"], a["criticality"], a["exposure"], int(a["is_critical"]))
                           for a in dataset.get("assets", [])])
            c.executemany("INSERT INTO findings (scan_id, finding_id, asset_id, port, cve, cvss, severity, status, category, description)"
                          " VALUES (?,?,?,?,?,?,?,?,?,?)",
                          [(sid, f["id"], f["asset_id"], f["port"], f["cve"], f["cvss"], f["severity"], f["status"],
                            f["category"], f["description"]) for f in dataset.get("findings", [])])
            c.commit()
            return sid

    def list_scans(self, limit: int = 20) -> list[dict]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT id, name, source, created_at, assets, open_ports, findings, paths, overall_risk"
                             " FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def load_dataset(self, scan_id: int) -> dict | None:
        with closing(self._conn()) as c:
            row = c.execute("SELECT dataset_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row["dataset_json"]) if row else None

    def list_findings(self, scan_id: int) -> list[dict]:
        with closing(self._conn()) as c:
            return [dict(r) for r in c.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,)).fetchall()]

    def delete_scan(self, scan_id: int) -> None:
        with closing(self._conn()) as c:
            c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            c.commit()

    def log_report(self, scan_id: int | None, filename: str, fmt: str, size: int) -> None:
        with closing(self._conn()) as c:
            c.execute("INSERT INTO reports (scan_id, created_at, filename, fmt, size_bytes) VALUES (?,?,?,?,?)",
                      (scan_id, datetime.now(timezone.utc).isoformat(timespec="seconds"), filename, fmt, size))
            c.commit()

    def list_reports(self, limit: int = 20) -> list[dict]:
        with closing(self._conn()) as c:
            return [dict(r) for r in c.execute("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]
