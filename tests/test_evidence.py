"""Redaction, encrypted evidence storage, and the tamper-evident audit log."""

import json

from core.evidence import AuditLog, EvidenceStore, redact


def test_redacts_sensitive_keys():
    out = redact({"password": "hunter2", "api_key": "abc123"})
    assert "hunter2" not in json.dumps(out)
    assert out["password"].startswith("[REDACTED")


def test_redacts_structured_secrets():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4"
    out = redact({"note": f"token is {jwt} and key AKIAABCDEFGHIJKLMNOP"})
    blob = json.dumps(out)
    assert jwt not in blob
    assert "AKIAABCDEFGHIJKLMNOP" not in blob


def test_redacts_inline_credential_assignment():
    out = redact({"log": "user logged in with password=s3cr3tvalue here"})
    assert "s3cr3tvalue" not in json.dumps(out)
    assert "password=" in out["log"]  # label preserved


def test_safe_keys_preserved():
    h = "a" * 64
    out = redact({"sha256_plaintext": h, "hash": h})
    assert out["sha256_plaintext"] == h
    assert out["hash"] == h


def test_reveal_returns_unchanged():
    data = {"password": "hunter2"}
    assert redact(data, reveal=True) == data


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", identity={"op": "x"})
    log.record("start", {"target": "a"})
    log.record("request", {"password": "leak"})
    ok, bad = log.verify()
    assert ok and bad is None

    # Secrets in details are redacted at rest.
    assert "leak" not in (tmp_path / "audit.jsonl").read_text()

    # Editing a past line breaks the chain.
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    lines[0] = lines[0].replace("start", "tampered")
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok, bad = log.verify()
    assert not ok and bad == 1


def test_evidence_encrypts_and_redacts(tmp_path):
    store = EvidenceStore(tmp_path / "ev", passphrase="p@ss", retention_days=7)
    rec = store.store("finding", {"original_token": "eyJhbG.eyJ.sig", "note": "password=abc123"})
    assert len(rec["sha256_plaintext"]) == 64
    assert rec["redacted"] is True

    # On-disk bytes are ciphertext, not plaintext.
    raw = (tmp_path / "ev" / "finding.enc").read_bytes()
    assert b"password" not in raw

    # Decrypted content is the redacted form by default.
    back = store.read("finding")
    assert "abc123" not in json.dumps(back)


def test_evidence_reveal_raw_opt_in(tmp_path):
    store = EvidenceStore(tmp_path / "ev", passphrase="p@ss")
    store.store("raw", {"original_token": "eyJhbGciX.eyJ.sig"}, reveal_raw=True)
    back = store.read("raw")
    assert "eyJhbGciX" in json.dumps(back)


def test_evidence_requires_key(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        EvidenceStore(tmp_path / "ev")  # no passphrase/key
