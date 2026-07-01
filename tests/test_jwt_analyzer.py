"""Unit tests for the JWT analyzer (parsing + report redaction).

These tests exercise pure-Python logic (base64url parsing, vulnerability
detection, report redaction) and do not require the optional PyJWT/crypto
backend, so they run even where that backend is unavailable.
"""
import base64
import json

import pytest


def _b64url(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _make_token(header: dict, payload: dict, signature: str = "sig") -> str:
    return f"{_b64url(header)}.{_b64url(payload)}.{signature}"


@pytest.fixture
def jwt_mod(load_script):
    return load_script("authentication/jwt_analyzer.py", "jwt_analyzer")


def test_parses_header_and_payload(jwt_mod):
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "role": "user"})
    analyzer = jwt_mod.JWTAnalyzer(token)

    assert analyzer.header["alg"] == "HS256"
    assert analyzer.payload["sub"] == "alice"
    assert analyzer.payload["role"] == "user"


def test_decode_base64url_handles_missing_padding(jwt_mod):
    analyzer = jwt_mod.JWTAnalyzer.__new__(jwt_mod.JWTAnalyzer)
    # "sub" -> {"a":1} style payload without padding must still decode.
    raw = base64.urlsafe_b64encode(b'{"k":"v"}').rstrip(b"=").decode()
    decoded = analyzer._decode_base64url(raw)
    assert json.loads(decoded) == {"k": "v"}


def test_none_algorithm_flagged_as_vulnerability(jwt_mod):
    token = _make_token({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, signature="")
    analyzer = jwt_mod.JWTAnalyzer(token)
    vulns = analyzer.analyze_vulnerabilities()

    assert any("none" in (v.get("type", "") + v.get("description", "")).lower() for v in vulns)


def test_report_redacts_sensitive_fields_by_default(jwt_mod):
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "email": "a@b.com"})
    analyzer = jwt_mod.JWTAnalyzer(token)
    analyzer.analyze_vulnerabilities()

    report = analyzer.generate_report()  # default: include_sensitive=False

    assert report["sensitive_data_included"] is False
    assert report["token"].startswith("[REDACTED")
    assert report["signature"].startswith("[REDACTED")
    assert report["payload"].startswith("[REDACTED")
    # Claim names are preserved for analysis, values are not.
    assert set(report["payload_claims"]) == {"sub", "email"}
    assert "a@b.com" not in json.dumps(report)


def test_report_includes_raw_data_when_opted_in(jwt_mod):
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "alice", "email": "a@b.com"})
    analyzer = jwt_mod.JWTAnalyzer(token)
    analyzer.analyze_vulnerabilities()

    report = analyzer.generate_report(include_sensitive=True)

    assert report["sensitive_data_included"] is True
    assert report["token"] == token
    assert report["payload"]["email"] == "a@b.com"


def test_verify_tls_defaults_to_true(jwt_mod):
    analyzer = jwt_mod.JWTAnalyzer(_make_token({"alg": "HS256"}, {"sub": "x"}))
    assert analyzer.verify_tls is True
