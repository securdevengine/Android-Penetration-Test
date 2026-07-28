"""
Evidence protection: redaction, encrypted storage, and a tamper-evident audit log.

Captured material (JWTs, forged tokens, secrets, network data, runtime
observations) is sensitive. This module enforces three defaults:

1. **Redaction by default** - :func:`redact` walks arbitrary JSON-like data and
   replaces secrets with stable, non-reversible placeholders
   ``[REDACTED:<kind>:<8-hex>]``. The 8-hex fingerprint lets a reviewer
   correlate the same secret across a report without exposing its value.
   Revealing raw values is an explicit, audited opt-in.

2. **Encrypted evidence at rest** - :class:`EvidenceStore` encrypts every
   artifact with Fernet (AES-128-CBC + HMAC). The key is derived from an
   operator passphrase (scrypt) or supplied directly, is never written to
   disk, and is scoped per engagement. Files are written with restrictive
   permissions and recorded with a SHA-256 for chain-of-custody.

3. **Tamper-evident audit** - :class:`AuditLog` is an append-only hash chain:
   each record commits to the previous record's hash, so any later edit or
   deletion is detectable by :meth:`AuditLog.verify`.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

# Dictionary keys whose values are secret regardless of their content.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(pass(word|phrase)?|secret|token|api[_-]?key|authorization|"
    r"cookie|session|credential|private[_-]?key|forged_token|original_token)"
)

# Keys whose values are integrity/identifier data (never secrets) and must be
# preserved verbatim - otherwise the hex-secret pattern would clobber e.g. a
# SHA-256 chain-of-custody hash, defeating the audit trail.
_SAFE_KEYS = frozenset(
    {"sha256", "sha256_plaintext", "sha1", "md5", "hash", "prev",
     "fingerprint", "correlation_id"}
)

# Value patterns worth redacting even when the key looks innocuous.
_VALUE_PATTERNS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}=*")),
    ("privkey", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL)),
    ("aws_akid", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("hex_secret", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
)


# Inline "key = value" credential assignments embedded in free text, e.g.
# "password=hunter2" or "api_key: abc123". Only the value is redacted so the
# label remains for the reviewer.
_INLINE_CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?key|"
    r"token|authorization)\b(\s*[:=]\s*)([^\s,;&\"']{2,})"
)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


def _redact_string(text: str) -> str:
    text = _INLINE_CRED_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}[REDACTED:inline_cred:{_fingerprint(m.group(3))}]",
        text,
    )
    for kind, pattern in _VALUE_PATTERNS:
        text = pattern.sub(
            lambda m: f"[REDACTED:{kind}:{_fingerprint(m.group(0))}]", text
        )
    return text


def redact(obj: Any, *, reveal: bool = False) -> Any:
    """Return a deep copy of ``obj`` with secrets replaced by placeholders.

    When ``reveal`` is True the object is returned unchanged - callers must
    only pass ``reveal=True`` after an explicit, audited operator opt-in.
    """
    if reveal:
        return obj
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if isinstance(key, str) and key.lower() in _SAFE_KEYS:
                out[key] = value  # integrity/identifier value, never redacted
            elif isinstance(key, str) and _SENSITIVE_KEY_RE.search(key):
                if isinstance(value, str):
                    out[key] = f"[REDACTED:key:{_fingerprint(value)}]"
                elif value is None:
                    out[key] = value
                else:
                    out[key] = f"[REDACTED:key:{_fingerprint(json.dumps(value, default=str))}]"
            else:
                out[key] = redact(value, reveal=False)
        return out
    if isinstance(obj, (list, tuple)):
        return [redact(v, reveal=False) for v in obj]
    if isinstance(obj, str):
        return _redact_string(obj)
    return obj


# --------------------------------------------------------------------------- #
# Filesystem permission helper
# --------------------------------------------------------------------------- #

def _restrict(path: Path) -> None:
    """Best-effort tighten permissions to owner-only.

    POSIX honours chmod directly. On Windows chmod barely applies, so the
    real hardening is done once at the **directory** level with icacls (strip
    inheritance, grant only the current user, with container/object-inherit so
    new children are owner-only too). Files created inside that directory
    inherit the restricted ACL, so per-file icacls is unnecessary and - with
    directory-inherit flags applied to a file - actively harmful.
    """
    try:
        if path.is_dir():
            path.chmod(stat.S_IRWXU)  # 0o700
        else:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
    except OSError:
        pass
    if os.name == "nt" and path.is_dir():
        _restrict_windows_dir(path)


def _restrict_windows_dir(path: Path) -> None:
    import shutil
    import subprocess

    icacls = shutil.which("icacls")
    user = os.environ.get("USERNAME")
    if not icacls or not user:
        return
    domain = os.environ.get("USERDOMAIN")
    principal = f"{domain}\\{user}" if domain else user
    try:
        # Grant first, then remove inheritance, so the writer is never left
        # without access if the grant principal needs resolving.
        subprocess.run(
            [icacls, str(path), "/grant:r", f"{principal}:(OI)(CI)F"],
            capture_output=True, timeout=15, check=False,
        )
        subprocess.run(
            [icacls, str(path), "/inheritance:r"],
            capture_output=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


# --------------------------------------------------------------------------- #
# Encrypted evidence store
# --------------------------------------------------------------------------- #

def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a passphrase using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


class EvidenceStore:
    """Per-engagement encrypted, permission-restricted evidence directory."""

    def __init__(
        self,
        base_dir: str | os.PathLike,
        *,
        passphrase: Optional[str] = None,
        key: Optional[bytes] = None,
        retention_days: Optional[int] = None,
    ):
        self.base = Path(base_dir)
        self.base.mkdir(parents=True, exist_ok=True)
        _restrict(self.base)
        self.retention_days = retention_days

        if key is None:
            passphrase = passphrase or os.environ.get("EVIDENCE_PASSPHRASE")
            if not passphrase:
                raise ValueError(
                    "EvidenceStore needs a passphrase (arg or EVIDENCE_PASSPHRASE "
                    "env) or an explicit key; refusing to store evidence in the "
                    "clear."
                )
            salt = self._load_or_create_salt()
            key = derive_key(passphrase, salt)
        self._fernet = Fernet(key)

    def _load_or_create_salt(self) -> bytes:
        salt_path = self.base / ".salt"
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(16)
        salt_path.write_bytes(salt)
        _restrict(salt_path)
        return salt

    def store(
        self,
        name: str,
        data: Any,
        *,
        reveal_raw: bool = False,
        redact_first: bool = True,
    ) -> dict:
        """Encrypt and persist an artifact; return its custody record.

        By default the payload is redacted before encryption so that even a
        holder of the key sees placeholders unless ``reveal_raw=True`` was an
        explicit operator choice.
        """
        payload = data
        if redact_first and not reveal_raw:
            payload = redact(data, reveal=False)

        plaintext = json.dumps(payload, indent=2, default=str).encode("utf-8")
        sha256 = hashlib.sha256(plaintext).hexdigest()
        token = self._fernet.encrypt(plaintext)

        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        out_path = self.base / f"{safe_name}.enc"
        out_path.write_bytes(token)
        _restrict(out_path)

        record = {
            "artifact": safe_name,
            "path": str(out_path),
            "sha256_plaintext": sha256,
            "bytes_ciphertext": len(token),
            "redacted": redact_first and not reveal_raw,
            "raw_revealed": reveal_raw,
            "stored_at": datetime.now(timezone.utc).isoformat(),
            "retention_days": self.retention_days,
        }
        return record

    def read(self, name: str) -> Any:
        """Decrypt a previously stored artifact (for the authorized operator)."""
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
        path = self.base / f"{safe_name}.enc"
        plaintext = self._fernet.decrypt(path.read_bytes())
        return json.loads(plaintext)


# --------------------------------------------------------------------------- #
# Tamper-evident audit log
# --------------------------------------------------------------------------- #

class AuditLog:
    """Append-only, hash-chained audit trail (one JSON object per line)."""

    GENESIS = "0" * 64

    def __init__(self, path: str | os.PathLike, *, identity: Optional[dict] = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _restrict(self.path.parent)
        self.identity = identity or {}
        if not self.path.exists():
            self.path.touch()
            _restrict(self.path)

    def _last_hash(self) -> str:
        last = self.GENESIS
        if self.path.stat().st_size == 0:
            return last
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    @staticmethod
    def _hash_entry(entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k != "hash"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def record(self, action: str, details: Optional[dict] = None) -> dict:
        """Append an audited event. Sensitive details are redacted."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "actor": self.identity,
            "details": redact(details or {}, reveal=False),
            "prev": self._last_hash(),
        }
        entry["hash"] = self._hash_entry(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Verify the chain. Returns (ok, first_bad_line_number_or_None)."""
        prev = self.GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, lineno
                if entry.get("prev") != prev:
                    return False, lineno
                if self._hash_entry(entry) != entry.get("hash"):
                    return False, lineno
                prev = entry["hash"]
        return True, None
