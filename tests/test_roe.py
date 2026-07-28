"""Rules-of-Engagement authorization and scope enforcement."""

import json

import pytest

from core.errors import (
    ApprovalRequired,
    AuthorizationError,
    ScopeError,
    WindowError,
)
from core.roe import RulesOfEngagement, canonical_bytes


def test_in_scope_host_allowed(make_roe):
    roe = make_roe()
    roe.require_host("staging.example.com")          # no raise
    roe.require_host("api.staging.example.com")      # wildcard match


def test_out_of_scope_host_refused(make_roe):
    roe = make_roe()
    with pytest.raises(ScopeError):
        roe.require_host("attacker.example.org")


def test_denied_and_production_host_refused(make_roe):
    roe = make_roe()
    with pytest.raises(ScopeError):
        roe.require_host("app.prod.example.com")


def test_url_scope_and_hostname_return(make_roe):
    roe = make_roe()
    assert roe.require_url("https://staging.example.com/api/login") == "staging.example.com"
    with pytest.raises(ScopeError):
        roe.require_url("https://evil.test/login")


def test_package_scope(make_roe):
    roe = make_roe()
    roe.require_package("com.example.app.debug")
    with pytest.raises(ScopeError):
        roe.require_package("com.other.app")


def test_window_not_open(make_roe):
    roe = make_roe(window={"start": "2999-01-01T00:00:00Z", "end": "2999-02-01T00:00:00Z"})
    with pytest.raises(WindowError):
        roe.check_window()


def test_window_closed(make_roe):
    roe = make_roe(window={"start": "2000-01-01T00:00:00Z", "end": "2000-02-01T00:00:00Z"})
    with pytest.raises(WindowError):
        roe.check_window()


def test_intrusive_gate_default_denied(make_roe):
    roe = make_roe()
    with pytest.raises(ApprovalRequired):
        roe.require_intrusive_approval("sql_injection")


def test_intrusive_gate_when_approved(make_roe):
    roe = make_roe(controls={
        "intrusive_tests_approved": True,
        "production_denied": True,
        "rate_limit_per_second": 100,
        "max_concurrency": 2,
        "account_lockout_guard": True,
    })
    roe.require_intrusive_approval("sql_injection")  # no raise


def test_tampered_roe_rejected(tmp_path, authorizer):
    priv, pub_hex = authorizer
    doc = {
        "engagement_id": "T", "scope": {"allowed_hosts": ["a.com"]},
        "window": {}, "controls": {},
    }
    doc["signature"] = {
        "algorithm": "Ed25519", "public_key": pub_hex,
        "value": priv.sign(canonical_bytes(doc)).hex(),
    }
    # Tamper after signing.
    doc["scope"]["allowed_hosts"].append("evil.com")
    p = tmp_path / "t.json"
    p.write_text(json.dumps(doc))
    with pytest.raises(AuthorizationError):
        RulesOfEngagement.load(p, trusted_keys=[pub_hex])


def test_untrusted_signing_key_refused(make_roe):
    with pytest.raises(AuthorizationError):
        make_roe(trust=False)


def test_untrusted_allowed_in_lab_mode(make_roe):
    roe = make_roe(trust=False, require_trusted=False)
    assert roe.trusted is False


def test_unsigned_roe_refused(make_roe):
    with pytest.raises(AuthorizationError):
        make_roe(sign=False)


def test_kill_switch(make_roe, tmp_path):
    roe = make_roe()
    ks = tmp_path / "kill"
    roe._kill_switch_path = ks
    roe.check_kill_switch()  # not engaged
    ks.write_text("stop")
    from core.errors import KillSwitchEngaged
    with pytest.raises(KillSwitchEngaged):
        roe.check_kill_switch()
