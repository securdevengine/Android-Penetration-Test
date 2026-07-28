"""Safe network controls: TLS policy, request budget, rate limiting."""

import time

import pytest

from core.errors import BudgetExceeded
from core.netcontrol import RequestBudget, TLSPolicy, TokenBucket


def test_tls_default_verifies():
    assert TLSPolicy().resolve() is True


def test_tls_custom_ca_bundle():
    assert TLSPolicy(ca_bundle="/etc/test-ca.pem").resolve() == "/etc/test-ca.pem"


def test_tls_insecure_opt_in():
    p = TLSPolicy(insecure=True)
    assert p.resolve() is False
    assert "DISABLED" in p.describe()


def test_request_budget_enforced():
    b = RequestBudget(3)
    assert [b.consume() for _ in range(3)] == [1, 2, 3]
    with pytest.raises(BudgetExceeded):
        b.consume()


def test_request_budget_unlimited_when_none():
    b = RequestBudget(None)
    for _ in range(50):
        b.consume()
    assert b.used == 50


def test_token_bucket_rate_limits():
    # 5 tokens/sec, burst 1: the 4th acquire must have waited a while.
    bucket = TokenBucket(rate_per_second=5, burst=1)
    start = time.monotonic()
    for _ in range(4):
        bucket.acquire()
    elapsed = time.monotonic() - start
    # 3 refills at 0.2s each => at least ~0.4s even allowing for scheduling.
    assert elapsed >= 0.4
