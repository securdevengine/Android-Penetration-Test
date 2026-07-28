"""secret_finder: values masked by default, raw only via reveal_raw."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "static_analysis"))
import secret_finder as S  # noqa: E402


def _finder_with_secret(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Config.java").write_text(
        'String awsSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";\n'
    )
    finder = S.SecretFinder(str(src))
    finder.find_secrets()
    return finder


def test_mask_value_hides_full_secret():
    masked = S._mask_value("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert "wJalrXUtnFEMI" not in masked
    assert "REDACTED:secret" in masked


def test_save_results_masks_by_default(tmp_path):
    finder = _finder_with_secret(tmp_path)
    out = tmp_path / "results.json"
    finder.save_results(str(out))
    data = json.loads(out.read_text())
    assert data["summary"]["redacted"] is True
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in out.read_text()


def test_save_results_reveal_raw(tmp_path):
    finder = _finder_with_secret(tmp_path)
    out = tmp_path / "results_raw.json"
    finder.save_results(str(out), reveal_raw=True)
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in out.read_text()
