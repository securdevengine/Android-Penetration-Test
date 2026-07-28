"""frida_automation offline logic: categorization, drop counters, redaction.

These tests exercise the pure-Python paths (event categorization and report
redaction) without a device; the frida import is optional so the module loads
even when frida is not installed.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "dynamic_analysis"))
import frida_automation as F  # noqa: E402


def _automation(tmp_path, **kw):
    return F.FridaAutomation("com.example.app.debug", output_dir=str(tmp_path / "out"), **kw)


def test_categorizes_by_explicit_type(tmp_path):
    a = _automation(tmp_path)
    a._categorize_data({"type": "network", "url": "https://x"})
    a._categorize_data({"type": "crypto", "transformation": "AES"})
    assert len(a.data_collected["network_requests"]) == 1
    assert len(a.data_collected["crypto_operations"]) == 1
    # monotonic sequence numbers stamped
    assert a.data_collected["network_requests"][0]["seq"] == 1
    assert a.data_collected["crypto_operations"][0]["seq"] == 2


def test_content_sniff_fallback_marked(tmp_path):
    a = _automation(tmp_path)
    a._categorize_data({"message": "opened file /data/data/x"})
    ev = a.data_collected["file_operations"][0]
    assert ev["_classified_by"] == "content_sniff"


def test_bounded_queue_counts_drops(tmp_path):
    a = _automation(tmp_path)
    a.config["max_data_per_category"] = 2
    for i in range(5):
        a._categorize_data({"type": "api", "i": i})
    assert len(a.data_collected["api_calls"]) == 2
    assert a.dropped_events["api_calls"] == 3


def test_report_redacts_runtime_secrets_by_default(tmp_path):
    a = _automation(tmp_path)
    a._categorize_data({"type": "jwt", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ"})
    a._categorize_data({"type": "network", "note": "password=hunter2"})
    report = a.generate_report()
    a._save_reports(report)
    written = json.loads((tmp_path / "out" / "frida_analysis_report.json").read_text())
    blob = json.dumps(written)
    assert "eyJhbGciOiJIUzI1NiJ9" not in blob
    assert "hunter2" not in blob


def test_reveal_raw_keeps_runtime_data(tmp_path):
    a = _automation(tmp_path, reveal_raw=True)
    a._categorize_data({"type": "jwt", "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJ"})
    report = a.generate_report()
    a._save_reports(report)
    written = json.loads((tmp_path / "out" / "frida_analysis_report.json").read_text())
    assert "eyJhbGciOiJIUzI1NiJ9" in json.dumps(written)
