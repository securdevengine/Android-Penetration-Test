"""
Safe HTTP traffic controls.

:class:`SafeSession` is a drop-in-ish wrapper around ``requests.Session`` that
routes every outbound request through the engagement's safety controls:

* **TLS verification is ON by default.** Disabling it requires an explicit,
  audited ``insecure=True`` (surfaced to operators as ``--insecure``). A test
  CA bundle can be supplied instead of disabling verification entirely.
* **Scope enforcement.** Every request host is checked against the ROE, so a
  redirect or a hand-built URL cannot wander outside the authorized targets.
* **Global request budget.** A hard ceiling on total requests for the run.
* **Concurrency ceiling.** A semaphore bounds simultaneous in-flight requests.
* **Central rate limiting.** A shared token bucket enforces a requests/second
  cap across all call sites - not the ad-hoc ``time.sleep`` calls it replaces.
* **Kill-switch.** Checked before every request so an operator can stop a run
  immediately.

These are enforced centrally so individual tools cannot accidentally bypass
them.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

import requests

from .errors import BudgetExceeded
from .roe import RulesOfEngagement


@dataclass
class TLSPolicy:
    """Resolves the ``verify=`` value passed to requests.

    verify=True  -> use system trust store (default, safe)
    verify=<path>-> use a specific test CA bundle
    verify=False -> only when the operator explicitly opted into --insecure
    """

    insecure: bool = False
    ca_bundle: Optional[str] = None

    def resolve(self):
        if self.insecure:
            return False
        if self.ca_bundle:
            return self.ca_bundle
        return True

    def describe(self) -> str:
        if self.insecure:
            return "DISABLED (--insecure): TLS verification off - interception possible"
        if self.ca_bundle:
            return f"custom CA bundle: {self.ca_bundle}"
        return "system trust store (verification on)"


class TokenBucket:
    """Thread-safe token bucket for a requests-per-second ceiling."""

    def __init__(self, rate_per_second: float, burst: Optional[float] = None):
        self.rate = max(float(rate_per_second), 0.001)
        self.capacity = burst if burst is not None else max(self.rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self.capacity, self._tokens + (now - self._last) * self.rate
                )
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                deficit = 1.0 - self._tokens
                wait = deficit / self.rate
            time.sleep(min(wait, 1.0))


class RequestBudget:
    """Hard ceiling on the total number of requests in a run."""

    def __init__(self, limit: Optional[int]):
        self.limit = limit
        self._count = 0
        self._lock = threading.Lock()

    def consume(self) -> int:
        with self._lock:
            if self.limit is not None and self._count >= self.limit:
                raise BudgetExceeded(
                    f"Global request budget of {self.limit} exhausted; stopping."
                )
            self._count += 1
            return self._count

    @property
    def used(self) -> int:
        return self._count


class SafeSession:
    """A scope-, budget-, and rate-limited HTTP client bound to an ROE."""

    def __init__(
        self,
        roe: RulesOfEngagement,
        *,
        tls: Optional[TLSPolicy] = None,
        audit=None,
        user_agent: str = "AuthorizedPentest/0.1",
    ):
        self.roe = roe
        self.tls = tls or TLSPolicy()
        self.audit = audit
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

        c = roe.controls
        self.budget = RequestBudget(c.global_request_budget)
        self.bucket = TokenBucket(c.rate_limit_per_second)
        self._concurrency = threading.Semaphore(max(1, c.max_concurrency))

        if self.tls.insecure and self.audit:
            self.audit.record(
                "tls_verification_disabled",
                {"reason": "operator passed --insecure", "policy": self.tls.describe()},
            )

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        # Fail closed: kill-switch, window, scope, production guard.
        host = self.roe.require_url(url)

        # Never allow a per-call override to weaken the TLS policy.
        kwargs["verify"] = self.tls.resolve()
        kwargs.setdefault("timeout", 15)
        # Redirects can leave scope; keep them off by default and let callers
        # opt in explicitly (each hop is re-checked on the next request()).
        kwargs.setdefault("allow_redirects", False)

        n = self.budget.consume()
        self.bucket.acquire()
        with self._concurrency:
            if self.audit:
                self.audit.record(
                    "http_request",
                    {"n": n, "method": method.upper(), "host": host, "url": url},
                )
            return self._session.request(method, url, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs) -> requests.Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.request("DELETE", url, **kwargs)

    @property
    def requests_used(self) -> int:
        return self.budget.used
