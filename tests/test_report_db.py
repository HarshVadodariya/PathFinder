import json

from modules.analysis import analyze
from modules.database import Database
from modules.remediation_engine import generate_recommendations
from modules.report_generator import findings_csv, generate_pdf, graph_json


def test_pdf_report_generates(sample, rules):
    res = analyze(sample, rules)
    pdf = generate_pdf(sample, res, generate_recommendations(sample, res, rules))
    assert pdf.startswith(b"%PDF") and len(pdf) > 5000


def test_pdf_report_for_empty_dataset(empty, rules):
    assert generate_pdf(empty, analyze(empty, rules), []).startswith(b"%PDF")


def test_pdf_escapes_markup_in_user_data(sample, rules):
    sample["assets"][0]["hostname"] = "<b>evil</b>&host"
    assert generate_pdf(sample, analyze(sample, rules), []).startswith(b"%PDF")


def test_csv_and_json_exports(sample, rules):
    sample["findings"][0]["description"] = "=HYPERLINK(\"x\")"
    csv = findings_csv(sample)
    assert csv.splitlines()[0].startswith("id,asset_id") and "'=HYPERLINK" in csv
    data = json.loads(graph_json(sample, analyze(sample, rules)))
    assert data["graph"]["nodes"] and data["paths"]


def test_database_roundtrip(tmp_path, sample, rules):
    db = Database(tmp_path / "t.db")
    res = analyze(sample, rules)
    sid = db.save_scan(sample, res["summary"])
    assert db.list_scans()[0]["id"] == sid and db.load_dataset(sid) == sample
    assert len(db.list_findings(sid)) == len(sample["findings"])
    db.log_report(sid, "r.pdf", "pdf", 123)
    assert db.list_reports()[0]["size_bytes"] == 123
    db.delete_scan(sid)
    assert db.list_scans() == [] and db.load_dataset(sid) is None


def test_database_survives_hostile_strings(tmp_path, sample, rules):
    sample["meta"]["name"] = "x'); DROP TABLE scans;--"
    db = Database(tmp_path / "t.db")
    db.save_scan(sample, analyze(sample, rules)["summary"])
    assert db.list_scans()[0]["name"].startswith("x')")
