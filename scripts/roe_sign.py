#!/usr/bin/env python3
"""
Rules-of-Engagement signing utility.

The authorizing party (not the operator) holds the private key and signs the
ROE. Operators verify with the corresponding public key, which they obtain
out-of-band and configure as a trusted key.

Usage
-----
Generate an authorizer key pair (do this once, keep the private key safe)::

    python scripts/roe_sign.py keygen --out-private authorizer.key

Sign an engagement definition::

    python scripts/roe_sign.py sign --in engagement.json \
        --private authorizer.key --out engagement.signed.json

Verify a signed ROE::

    python scripts/roe_sign.py verify --in engagement.signed.json
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Allow running as a plain script (python scripts/roe_sign.py ...).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core.roe import canonical_bytes  # noqa: E402


def _restrict(path: Path) -> None:
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def cmd_keygen(args: argparse.Namespace) -> int:
    private = Ed25519PrivateKey.generate()
    raw_priv = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    out = Path(args.out_private)
    out.write_text(raw_priv.hex() + "\n", encoding="utf-8")
    _restrict(out)
    print(f"[+] Private key written to {out} (keep this secret)")
    print(f"[+] Public key (share with operators as a trusted key):")
    print(f"    {raw_pub.hex()}")
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.infile).read_text(encoding="utf-8"))
    document.pop("signature", None)  # sign the body only

    priv_hex = Path(args.private).read_text(encoding="utf-8").strip()
    private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    pub_hex = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    signature = private.sign(canonical_bytes(document))
    document["signature"] = {
        "algorithm": "Ed25519",
        "public_key": pub_hex,
        "value": signature.hex(),
    }

    out = Path(args.out)
    out.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"[+] Signed ROE written to {out}")
    print(f"[+] Signing key fingerprint: {pub_hex[:32]}...")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    document = json.loads(Path(args.infile).read_text(encoding="utf-8"))
    sig = document.get("signature") or {}
    if sig.get("algorithm") != "Ed25519":
        print("[-] Missing or unsupported signature algorithm")
        return 2
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(sig["public_key"])).verify(
            bytes.fromhex(sig["value"]), canonical_bytes(document)
        )
    except Exception as exc:  # noqa: BLE001 - report any verification failure
        print(f"[-] Signature INVALID: {exc}")
        return 1
    print("[+] Signature valid.")
    print(f"    Engagement: {document.get('engagement_id')}")
    print(f"    Signing key: {sig['public_key'][:32]}...")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign/verify Rules-of-Engagement")
    sub = parser.add_subparsers(dest="command", required=True)

    p_keygen = sub.add_parser("keygen", help="Generate an authorizer key pair")
    p_keygen.add_argument("--out-private", default="authorizer.key")
    p_keygen.set_defaults(func=cmd_keygen)

    p_sign = sub.add_parser("sign", help="Sign an ROE document")
    p_sign.add_argument("--in", dest="infile", required=True)
    p_sign.add_argument("--private", required=True)
    p_sign.add_argument("--out", required=True)
    p_sign.set_defaults(func=cmd_sign)

    p_verify = sub.add_parser("verify", help="Verify a signed ROE")
    p_verify.add_argument("--in", dest="infile", required=True)
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
