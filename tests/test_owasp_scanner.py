"""owasp_scanner correctness: input validation, fail-closed, HTML escaping."""

import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "owasp_validation"))
import owasp_scanner as O  # noqa: E402


def _make_apk(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("classes.dex", "stub")
    return path


def test_rejects_wrong_extension(tmp_path):
    bad = tmp_path / "notes.txt"
    bad.write_text("x")
    with pytest.raises(ValueError):
        O.OWASPMobileScanner(str(bad))


def test_rejects_oversized(tmp_path, monkeypatch):
    apk = _make_apk(tmp_path / "a.apk")
    monkeypatch.setattr(O, "_load_security_config",
                        lambda: {"max_file_size": 1, "allowed_extensions": [".apk"], "scan_timeout": 600})
    with pytest.raises(ValueError):
        O.OWASPMobileScanner(str(apk))


def test_fail_closed_when_decompilers_absent(tmp_path):
    # Path deliberately contains a space (finding #8).
    apk = _make_apk(tmp_path / "apk dir" / "sample app.apk")
    scanner = O.OWASPMobileScanner(str(apk), output_dir=str(tmp_path / "out dir"))
    scanner.decompile_apk()
    # Tools are not installed in CI -> both FAILED, scan INCOMPLETE.
    assert scanner.capabilities == {"jadx": O.FAILED, "apktool": O.FAILED}
    assert scanner.scan_complete is False


def test_report_marks_incomplete(tmp_path):
    apk = _make_apk(tmp_path / "a.apk")
    scanner = O.OWASPMobileScanner(str(apk), output_dir=str(tmp_path / "out"))
    scanner.decompile_apk()
    report = scanner.generate_report()
    assert report["scan_info"]["scan_status"] == "INCOMPLETE"


def test_html_report_escapes_untrusted_content(tmp_path):
    apk = _make_apk(tmp_path / "a.apk")
    scanner = O.OWASPMobileScanner(str(apk), output_dir=str(tmp_path / "out"))
    scanner.findings["M1_Credential_Usage"].append({
        "type": "<script>alert('xss')</script>",
        "severity": "HIGH",
        "file": 'a" onmouseover="alert(1)',
        "description": "<img src=x onerror=alert(1)>",
        "code": "</code><script>evil()</script>",
    })
    report = {
        "scan_info": {
            "apk_path": "<b>x</b>", "scan_date": "now", "scan_status": "COMPLETE",
            "capabilities": {}, "total_findings": 1,
            "severity_breakdown": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
        },
        "findings": scanner.findings,
    }
    doc = scanner.generate_html_report(report)
    assert "<script>alert('xss')</script>" not in doc
    assert "<img src=x onerror" not in doc
    assert 'onmouseover="alert(1)"' not in doc
    assert "Content-Security-Policy" in doc


def test_run_command_uses_list_not_shell_split(tmp_path):
    apk = _make_apk(tmp_path / "a.apk")
    scanner = O.OWASPMobileScanner(str(apk), output_dir=str(tmp_path / "out"))
    # A missing tool returns a clean failure, not an exception, and does not
    # naively split a path containing spaces.
    ok, out, err = scanner.run_command(["nonexistent-tool-xyz", str(tmp_path / "a b c")])
    assert ok is False
    assert "not found" in err.lower()
