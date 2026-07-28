"""auth_flow_tester safety integration: fail-closed scope + intrusive gating."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "authentication"))
import auth_flow_tester as A  # noqa: E402

from core.errors import ScopeError  # noqa: E402
from core.netcontrol import SafeSession  # noqa: E402


def test_construction_refuses_out_of_scope_target(make_roe):
    roe = make_roe()
    session = SafeSession(roe)
    with pytest.raises(ScopeError):
        A.AuthFlowTester("https://not-in-scope.attacker.org", roe, session)


def test_construction_accepts_in_scope_target(make_roe):
    roe = make_roe()
    session = SafeSession(roe)
    tester = A.AuthFlowTester("https://staging.example.com", roe, session)
    assert tester.target_host == "staging.example.com"
    assert tester.intrusive_approved is False


def test_intrusive_tests_skipped_without_approval(make_roe):
    roe = make_roe()  # intrusive_tests_approved False by default
    session = SafeSession(roe)
    tester = A.AuthFlowTester("https://staging.example.com", roe, session)
    endpoint = {"url": "https://staging.example.com/api/login", "path": "/api/login"}
    bypasses = tester.test_authentication_bypass(endpoint)
    # Nothing ran; every technique was recorded as skipped.
    assert bypasses == []
    assert "sql_injection_bypass" in tester.skipped_intrusive
    assert "default_credentials" in tester.skipped_intrusive


def test_explicit_success_assertions_override_heuristic(make_roe):
    roe = make_roe()
    session = SafeSession(roe)
    tester = A.AuthFlowTester("https://staging.example.com", roe, session)
    tester.config["success_assertions"] = {"status": [200], "json_fields": {"authenticated": True}}

    class Resp:
        status_code = 200
        text = '{"authenticated": true}'
        cookies = {}
        def json(self):
            return {"authenticated": True}

    assert tester._is_auth_success(Resp()) is True
    assert tester._last_success_confidence == "high"


def test_heuristic_failure_signal_wins(make_roe):
    roe = make_roe()
    session = SafeSession(roe)
    tester = A.AuthFlowTester("https://staging.example.com", roe, session)

    class Resp:
        status_code = 200
        # Contains both a "token" and an error word: must NOT be a false positive.
        text = 'error: invalid token'
        cookies = {}
        def json(self):
            raise ValueError

    assert tester._is_auth_success(Resp()) is False
    assert tester._last_success_confidence == "low"
