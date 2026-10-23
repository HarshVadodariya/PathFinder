# PathFinder — Attack Path Visualization and Risk Analyzer

B.Tech CSE mini-project. Imports authorized Nmap XML (or a built-in synthetic lab), models assets, services,
vulnerabilities and trust relationships as a NetworkX graph, finds **modeled potential attack paths** to sensitive
assets with transparent rules, scores them 0–100, simulates remediation, and exports PDF/CSV/JSON reports.

> Paths are modeled from supplied data and configurable rules. They are not proof of exploitation. Use only on
> authorized lab data. PathFinder never scans, exploits, or executes anything from uploaded files.

## Run

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```
Open the app, then **Overview Dashboard → Load sample lab** (or Import Scan → Nmap XML → "Use the bundled sample_scan.xml").

## Test
```bash
python -m pytest -q        # 48 tests: parser, graph, paths, risk, remediation, reports, database
```

## Layout
```
app.py                      Streamlit router (9 pages)
ui/common.py, ui/views.py   UI only: session state, pages
modules/
  nmap_parser.py            Nmap XML -> hosts/ports/services (rejects entity declarations, size-limited)
  asset_manager.py          dataset model, validation, roles, inferred relationships
  vulnerability_mapper.py   CVSS->severity, finding validation, CSV import, heuristic potential matches
  graph_builder.py          NetworkX DiGraph (node/edge types, eligibility per rule)
  attack_path_engine.py     bounded all_simple_paths search, path descriptions, assumptions
  risk_engine.py            0-100 path score, asset score, overall risk
  remediation_engine.py     rule-based recommendations + simulated risk reduction
  analysis.py               graph -> paths -> risk -> summary pipeline
  visualization.py          Plotly attack graph + charts
  report_generator.py       ReportLab PDF, CSV, JSON
  database.py               SQLite (scans, assets, findings, reports)
data/sample_network.json    editable synthetic lab (SAMPLE-* identifiers only)
data/sample_scan.xml        matching Nmap XML
tests/                      pytest suite
```

## Graph model
Nodes: External Entry Point, Host, Sensitive Asset, Service, Vulnerability.
Edges: `EXPOSES` Internet→service · `HOSTS` host→service (display only) · `AFFECTED_BY` service→vulnerability ·
`POTENTIAL_TRANSITION` vulnerability→owning host · `CONNECTS_TO` host→service on another host · `TRUSTS` host→host.

## Transition rules (configurable on the Attack Path Explorer page)
- **R1** An exposed service on an Internet-facing asset is a modeled entry point.
- **R2** A finding on a reachable service may give a foothold on its host if CVSS ≥ threshold; *potential* findings are allowed/denied by a toggle; unknown-CVSS findings are excluded unless enabled.
- **R3** A configured `TRUSTS` relationship allows direct movement (toggle).
- **R4** A configured `CONNECTS_TO` relationship lets a foothold reach a service on another host.
- Limits: max host transitions, max graph depth, max paths.

## Risk score (0–100, not CVSS)
`score = 100 × (0.35·severity + 0.20·criticality + 0.05·sensitive + 0.20·exposure + 0.20·length) × (0.5 + 0.5·confidence)`

| Component | Definition |
|---|---|
| severity | 0.6·max(CVSS)/10 + 0.4·mean(CVSS)/10 over vulnerabilities on the path (unknown → configurable default; trust-only path → 0.30) |
| criticality | target criticality / 5 |
| sensitive | 1 if target is designated sensitive |
| exposure | entry asset factor: Internet-facing 1.0, Partner/VPN 0.7, Internal 0.5, Restricted 0.3 |
| length | max(0.2, 1 − 0.20·(transitions − 1)) |
| confidence | mean confidence of relationships/findings on the path (confirmed 1.0, manual lab 0.9, potential 0.5, or the relationship's own value) |

Bands: ≥75 Critical, ≥50 High, ≥25 Medium, else Low.
Overall risk = 0.6·top path + 0.4·mean(top 3 paths); with no paths, 0.5·highest asset score.
Remediation "expected risk reduction" = overall score before − after, re-running the full analysis on a copy with the fix applied.

## CSV import format (findings)
`asset,port,cve,cvss,status,category,description,remediation` — required: `asset` (id, IP or hostname), `description`.
Status: `confirmed | manual_lab | potential`. Category: `outdated_software | exposed_service | weak_access | excessive_access | critical_exposure | misconfiguration`.

## Demo flow (≈5 min)
1. Overview → *Load sample lab*; read the dashboard.
2. Asset Inventory → show roles/exposure/criticality and relationships.
3. Vulnerability Findings → point out confirmed vs potential vs lab findings; note unknown CVSS finding is excluded.
4. Attack Path Explorer → pick P-001, show highlighted route, risk breakdown, assumptions; toggle *Allow trust* and *min CVSS* and watch paths change.
5. Risk Analysis → set db criticality to 2 or web exposure to Internal; compare overall risk; apply.
6. Remediation Center → simulate the top three fixes; see the paths collapse.
7. Reports → generate the PDF and exports.
