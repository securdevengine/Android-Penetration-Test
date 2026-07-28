"""Shared pytest fixtures for the safety-layer test suite.

Adds ``scripts/`` to the import path and provides an in-process Ed25519
authorizer plus a factory that builds and signs Rules-of-Engagement documents
so tests never need external key files.
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from core.roe import RulesOfEngagement, canonical_bytes  # noqa: E402


@pytest.fixture
def authorizer():
    """A throwaway Ed25519 signing identity for the test engagement."""
    priv = Ed25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv, pub_hex


@pytest.fixture
def make_roe(tmp_path, authorizer):
    """Factory: build, sign, and load an ROE with optional overrides."""
    priv, pub_hex = authorizer

    def _factory(*, scope=None, controls=None, window=None,
                 require_trusted=True, trust=True, sign=True):
        doc = {
            "engagement_id": "TEST-0001",
            "client": "Test Client",
            "operator": {"id": "op@test", "name": "Test Operator"},
            "authorized_by": "Test Authorizer",
            "scope": scope or {
                "allowed_hosts": ["staging.example.com", "*.staging.example.com"],
                "denied_hosts": ["*.prod.example.com"],
                "allowed_packages": ["com.example.app.debug"],
                "environments_allowed": ["staging"],
            },
            "window": window or {
                "start": "2020-01-01T00:00:00Z",
                "end": "2999-01-01T00:00:00Z",
            },
            "controls": controls or {
                "intrusive_tests_approved": False,
                "production_denied": True,
                "global_request_budget": 100,
                "max_concurrency": 2,
                "rate_limit_per_second": 100,
                "account_lockout_guard": True,
            },
            "evidence": {"redact_by_default": True, "encrypt": True, "retention_days": 7},
        }
        if sign:
            doc["signature"] = {
                "algorithm": "Ed25519",
                "public_key": pub_hex,
                "value": priv.sign(canonical_bytes(doc)).hex(),
            }
        path = tmp_path / "roe.signed.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        keys = [pub_hex] if trust else ["00" * 32]
        return RulesOfEngagement.load(
            path, trusted_keys=keys, require_trusted=require_trusted
        )

    return _factory
