"""
Rules-of-Engagement (ROE): signed authorization and scope enforcement.

An engagement is described by a JSON document that is **signed by the
authorizing party** (Ed25519). Before any active testing tool touches a
target it must load and verify this document, then ask the ROE whether a
specific host / URL / package is in scope, whether the current time is inside
the authorized window, and whether intrusive tests have been approved.

Trust model
-----------
* **Integrity** - the signature is verified against the public key embedded in
  the document, so any modification of the ROE body is detected.
* **Authenticity** - the operator supplies the authorizer's expected public
  key(s) out-of-band (``trusted_keys`` argument, ``ROE_AUTHORIZER_PUBKEYS``
  env var, or a ``*.pub`` file). The embedded key must be one of those trusted
  keys, otherwise the ROE is treated as untrusted. With ``require_trusted``
  (the default) an untrusted ROE is refused.

Everything fails closed: a missing, malformed, unsigned, out-of-window, or
out-of-scope condition raises rather than returning a permissive default.
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)

from .errors import (
    AuthorizationError,
    ApprovalRequired,
    KillSwitchEngaged,
    ScopeError,
    WindowError,
)

# DNS labels that strongly indicate a production system. Matched as whole
# labels (not substrings) so a staging subdomain like "api.staging.example.com"
# is not mistaken for production. This is a defence-in-depth backstop on top of
# the explicit denied_hosts list, which remains the primary exclusion control.
_PRODUCTION_LABELS = ("prod", "production", "prd", "live")


def canonical_bytes(document: dict) -> bytes:
    """Return the deterministic byte serialization used for signing/verifying.

    The ``signature`` block is excluded so that the signature covers exactly
    the rest of the document. Keys are sorted and whitespace is stripped so the
    encoding is stable across platforms and Python versions.
    """
    body = {k: v for k, v in document.items() if k != "signature"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _load_trusted_keys(
    trusted_keys: Optional[Sequence[str]],
) -> List[bytes]:
    """Collect trusted authorizer public keys (hex) from args/env/files."""
    collected: List[str] = []
    if trusted_keys:
        collected.extend(trusted_keys)

    env = os.environ.get("ROE_AUTHORIZER_PUBKEYS", "").strip()
    if env:
        collected.extend(part.strip() for part in env.split(",") if part.strip())

    key_file = os.environ.get("ROE_AUTHORIZER_PUBKEY_FILE", "").strip()
    if key_file and Path(key_file).is_file():
        collected.extend(
            line.strip()
            for line in Path(key_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        )

    out: List[bytes] = []
    for hexkey in collected:
        try:
            out.append(bytes.fromhex(hexkey))
        except ValueError:
            raise AuthorizationError(
                f"Trusted authorizer key is not valid hex: {hexkey[:16]}..."
            )
    return out


@dataclass
class Scope:
    allowed_hosts: List[str] = field(default_factory=list)
    denied_hosts: List[str] = field(default_factory=list)
    allowed_packages: List[str] = field(default_factory=list)
    environments_allowed: List[str] = field(default_factory=list)

    @staticmethod
    def _match_any(value: str, patterns: Iterable[str]) -> bool:
        value = value.lower()
        return any(fnmatch.fnmatch(value, p.lower()) for p in patterns)

    def host_in_scope(self, host: str) -> bool:
        if not host:
            return False
        if self._match_any(host, self.denied_hosts):
            return False
        return self._match_any(host, self.allowed_hosts)

    def package_in_scope(self, package: str) -> bool:
        return bool(package) and self._match_any(package, self.allowed_packages)


@dataclass
class Controls:
    intrusive_tests_approved: bool = False
    production_denied: bool = True
    global_request_budget: Optional[int] = None
    max_concurrency: int = 4
    rate_limit_per_second: float = 5.0
    account_lockout_guard: bool = True


class RulesOfEngagement:
    """Loaded, signature-verified rules of engagement for one engagement."""

    def __init__(self, document: dict, *, trusted: bool, source: Path):
        self._doc = document
        self.trusted = trusted
        self.source = source

        self.engagement_id: str = document.get("engagement_id", "")
        self.client: str = document.get("client", "")
        operator = document.get("operator", {}) or {}
        self.operator_id: str = operator.get("id", "")
        self.operator_name: str = operator.get("name", "")
        self.authorized_by: str = document.get("authorized_by", "")

        scope = document.get("scope", {}) or {}
        self.scope = Scope(
            allowed_hosts=list(scope.get("allowed_hosts", [])),
            denied_hosts=list(scope.get("denied_hosts", [])),
            allowed_packages=list(scope.get("allowed_packages", [])),
            environments_allowed=list(scope.get("environments_allowed", [])),
        )

        controls = document.get("controls", {}) or {}
        self.controls = Controls(
            intrusive_tests_approved=bool(
                controls.get("intrusive_tests_approved", False)
            ),
            production_denied=bool(controls.get("production_denied", True)),
            global_request_budget=controls.get("global_request_budget"),
            max_concurrency=int(controls.get("max_concurrency", 4)),
            rate_limit_per_second=float(controls.get("rate_limit_per_second", 5.0)),
            account_lockout_guard=bool(controls.get("account_lockout_guard", True)),
        )

        window = document.get("window", {}) or {}
        self._window_start = _parse_ts(window.get("start"))
        self._window_end = _parse_ts(window.get("end"))

        # Kill-switch: presence of this file (or ROE_KILL_SWITCH env) stops work.
        self._kill_switch_path = Path(
            document.get("kill_switch_file")
            or os.environ.get("ROE_KILL_SWITCH")
            or (source.parent / f".kill-{self.engagement_id or 'engagement'}")
        )

        self.evidence = document.get("evidence", {}) or {}

    # ---- construction -----------------------------------------------------

    @classmethod
    def load(
        cls,
        path: str | os.PathLike,
        *,
        trusted_keys: Optional[Sequence[str]] = None,
        require_trusted: bool = True,
    ) -> "RulesOfEngagement":
        """Load and cryptographically verify an ROE file.

        Raises :class:`AuthorizationError` if the file is missing/malformed,
        the signature is absent or invalid, or (when ``require_trusted``) the
        signing key is not among the operator-supplied trusted keys.
        """
        p = Path(path)
        if not p.is_file():
            raise AuthorizationError(f"Rules-of-Engagement file not found: {p}")

        try:
            document = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise AuthorizationError(f"Cannot parse ROE {p}: {exc}") from exc

        sig = document.get("signature") or {}
        alg = sig.get("algorithm")
        if alg != "Ed25519":
            raise AuthorizationError(
                "ROE signature.algorithm must be 'Ed25519' "
                f"(got {alg!r}). The ROE must be signed with tools/sign_roe.py."
            )

        try:
            pub_bytes = bytes.fromhex(sig["public_key"])
            sig_bytes = bytes.fromhex(sig["value"])
        except (KeyError, ValueError) as exc:
            raise AuthorizationError(
                f"ROE signature block is incomplete or malformed: {exc}"
            ) from exc

        # Integrity: signature must validate over the canonical body.
        try:
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
                sig_bytes, canonical_bytes(document)
            )
        except (InvalidSignature, ValueError) as exc:
            raise AuthorizationError(
                "ROE signature is INVALID - the document has been modified or "
                "was not signed correctly. Refusing to proceed."
            ) from exc

        # Authenticity: is the signing key one the operator trusts?
        trusted_set = _load_trusted_keys(trusted_keys)
        is_trusted = pub_bytes in trusted_set if trusted_set else False
        if require_trusted and not is_trusted:
            raise AuthorizationError(
                "ROE signature is valid but the signing key is not in the "
                "trusted authorizer key set. Provide the authorizer's public "
                "key via --trusted-key / ROE_AUTHORIZER_PUBKEYS, or pass "
                "--allow-untrusted-roe for lab use only.\n"
                f"  Signing key fingerprint: {pub_bytes.hex()[:32]}..."
            )

        return cls(document, trusted=is_trusted, source=p)

    # ---- authorization checks --------------------------------------------

    def check_kill_switch(self) -> None:
        """Raise :class:`KillSwitchEngaged` if the emergency stop is active."""
        if self._kill_switch_path.exists():
            raise KillSwitchEngaged(
                f"Kill-switch engaged ({self._kill_switch_path}); "
                "aborting all active testing."
            )

    def check_window(self, *, now: Optional[datetime] = None) -> None:
        """Raise :class:`WindowError` if the current time is out of window."""
        now = now or datetime.now(timezone.utc)
        if self._window_start and now < self._window_start:
            raise WindowError(
                f"Testing window has not opened yet (starts {self._window_start.isoformat()})."
            )
        if self._window_end and now > self._window_end:
            raise WindowError(
                f"Testing window has closed (ended {self._window_end.isoformat()})."
            )

    def looks_like_production(self, host: str) -> bool:
        host = (host or "").lower()
        # If the operator deliberately scoped production (environments_allowed
        # names it), respect that and do not second-guess the heuristic.
        allowed_env = {e.lower() for e in self.scope.environments_allowed}
        if "production" in allowed_env or "prod" in allowed_env:
            return False
        # Match production tokens as whole DNS labels, not substrings, so
        # "api.staging.example.com" is not flagged by the "api" in its name.
        labels = host.split(".")
        return any(label in _PRODUCTION_LABELS for label in labels)

    def require_host(self, host: str) -> None:
        """Full gate for a hostname: kill-switch, window, scope, prod guard."""
        self.check_kill_switch()
        self.check_window()
        if not self.scope.host_in_scope(host):
            raise ScopeError(
                f"Host {host!r} is not in the authorized scope for engagement "
                f"{self.engagement_id!r}. Allowed: {self.scope.allowed_hosts}; "
                f"denied: {self.scope.denied_hosts}."
            )
        if self.controls.production_denied and self.looks_like_production(host):
            raise ScopeError(
                f"Host {host!r} looks like a production system and "
                "controls.production_denied is set. Refusing."
            )

    def require_url(self, url: str) -> str:
        """Validate a full URL is in scope; return its hostname."""
        host = urlparse(url).hostname or ""
        if not host:
            raise ScopeError(f"Cannot determine host from URL: {url!r}")
        self.require_host(host)
        return host

    def require_package(self, package: str) -> None:
        self.check_kill_switch()
        self.check_window()
        if not self.scope.package_in_scope(package):
            raise ScopeError(
                f"Package {package!r} is not in the authorized scope for "
                f"engagement {self.engagement_id!r}. Allowed: "
                f"{self.scope.allowed_packages}."
            )

    def require_intrusive_approval(self, test_name: str) -> None:
        """Gate for intrusive tests (injection, brute force, timing, etc.)."""
        self.check_kill_switch()
        if not self.controls.intrusive_tests_approved:
            raise ApprovalRequired(
                f"Intrusive test {test_name!r} requires "
                "controls.intrusive_tests_approved=true in the signed ROE. "
                "Passive checks only until intrusive testing is approved."
            )

    # ---- accessors --------------------------------------------------------

    def identity(self) -> dict:
        """Operator/engagement identity stamped into evidence and audit logs."""
        return {
            "engagement_id": self.engagement_id,
            "client": self.client,
            "operator_id": self.operator_id,
            "operator_name": self.operator_name,
            "authorized_by": self.authorized_by,
            "roe_trusted": self.trusted,
        }


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AuthorizationError(f"Invalid ROE timestamp {value!r}: {exc}") from exc
    # Treat a naive timestamp as UTC rather than guessing the local zone.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
