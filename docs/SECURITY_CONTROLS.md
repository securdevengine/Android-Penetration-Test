# Authorization & Safety Controls

This toolkit performs **authorized** security testing only. The active tools
route every operation through a shared control layer (`scripts/core/`) that
fails **closed**: if authorization, scope, timing, or an emergency stop cannot
be satisfied, the operation is refused rather than run.

> Status: this layer currently wraps the authentication tester and the OWASP
> scanner. Other scripts (`jwt_analyzer.py`, `secret_finder.py`,
> `frida_automation.py`) are being migrated onto it — see
> [Remaining work](#remaining-work). Until a tool states it enforces the ROE,
> treat it as lab-only.

## The control layer

| Module | Responsibility |
| --- | --- |
| `core/roe.py` | Signed Rules-of-Engagement: authorization, scope allowlist, testing window, kill-switch, production guard, intrusive-test approval gate. |
| `core/evidence.py` | Redaction by default, encrypted evidence at rest, tamper-evident (hash-chained) audit log. |
| `core/netcontrol.py` | `SafeSession`: TLS verification **on by default**, per-request scope re-check, global request budget, concurrency ceiling, central token-bucket rate limiting. |
| `core/errors.py` | Typed refusal exceptions (`AuthorizationError`, `ScopeError`, `WindowError`, `KillSwitchEngaged`, `BudgetExceeded`, `ApprovalRequired`). |

## Rules of Engagement (ROE)

An engagement is a JSON document **signed by the authorizing party** with an
Ed25519 key. Operators verify it with the authorizer's public key, supplied
out-of-band. See [`config/engagement.example.json`](../config/engagement.example.json).

### 1. Authorizer generates a key pair (once)

```bash
python scripts/roe_sign.py keygen --out-private authorizer.key
```

Keep `authorizer.key` secret. Distribute the printed **public key** to operators.

### 2. Author and sign an engagement

Copy the example, edit `scope`, `window`, and `controls`, then:

```bash
python scripts/roe_sign.py sign --in engagement.json --private authorizer.key --out engagement.signed.json
```

### 3. Operators run tools against the signed ROE

```bash
export ROE_AUTHORIZER_PUBKEYS=<authorizer public key hex>
python scripts/authentication/auth_flow_tester.py https://staging.example.com \
    --roe engagement.signed.json \
    --evidence-dir ./evidence --evidence-passphrase "$EVIDENCE_PASSPHRASE" \
    --audit-log ./audit/run.jsonl -o report.json
```

Without a validly signed ROE whose signing key is trusted, and whose scope and
window admit the target, the tool exits non-zero **before sending any request**.

## Trust model

* **Integrity** — the signature covers the canonical document body, so any edit
  to scope, window, or controls invalidates it.
* **Authenticity** — the signing key must be in the operator's trusted set
  (`--trusted-key` / `ROE_AUTHORIZER_PUBKEYS` / `ROE_AUTHORIZER_PUBKEY_FILE`).
  `--allow-untrusted-roe` bypasses this **for lab use only**.

## Scope, window, production guard

* `scope.allowed_hosts` / `allowed_packages` — glob allowlist (`*.staging.example.com`).
* `scope.denied_hosts` — glob denylist; takes precedence over allow.
* `window.start` / `window.end` — ISO-8601; requests outside the window are refused.
* Production guard — hosts whose DNS labels look like production (`prod`,
  `production`, `live`) are refused when `controls.production_denied` is set,
  unless `environments_allowed` explicitly names production.

## Passive by default; intrusive tests gated

Injection payloads, credential guessing, timing analysis, and request bursts
only run when the signed ROE sets `controls.intrusive_tests_approved: true`.
Otherwise each is reported as `SKIPPED` (never silently omitted). Approval
requires the authorizer to **re-sign** the ROE — it is not a CLI flag.

## Safe traffic controls

* **TLS on by default.** `--insecure` disables verification and is written to
  the audit log; prefer `--ca-bundle <test CA>` for intercepting proxies.
* **Global request budget** (`controls.global_request_budget`) — hard ceiling.
* **Concurrency ceiling** (`controls.max_concurrency`).
* **Central rate limiting** (`controls.rate_limit_per_second`) — a shared token
  bucket, replacing ad-hoc `sleep()` calls.
* **Account-lockout guard** (`controls.account_lockout_guard`) — caps guesses
  per account and stops on the first lockout/rate-limit signal.

## Emergency stop (kill-switch)

Create the kill-switch file (default `.kill-<engagement_id>` beside the ROE, or
the path in `ROE_KILL_SWITCH` / the ROE's `kill_switch_file`). It is checked
before every request; an engaged switch aborts the run immediately.

## Evidence protection

* **Redacted by default** — reports mask JWTs, tokens, secrets, and inline
  `password=...` values with stable `[REDACTED:kind:fingerprint]` placeholders.
* **Encrypted at rest** — full findings go to the encrypted evidence store
  (`--evidence-dir`), keyed by an operator passphrase (scrypt); files are
  permission-restricted and recorded with a SHA-256 for chain of custody.
* **`--reveal-raw`** writes raw secrets into the report and is audited.
* **Tamper-evident audit log** — `--audit-log` is a hash chain; verify it with
  `AuditLog(path).verify()`.

## Verifying the controls

```bash
python -m pytest -q
```

The `tests/` suite covers scope enforcement, signature/tamper handling,
redaction, the audit chain, TLS/budget/rate-limit controls, and the scanner's
fail-closed and HTML-escaping behavior.

## Remaining work

These items from the assessment are **not yet** addressed and remain lab-only:

* Migrate `jwt_analyzer.py`, `secret_finder.py`, `frida_automation.py` onto the
  ROE + evidence layer (TLS default, redaction, capability status).
* Disposable, network-isolated APK-processing workers (sandbox enforcement).
* Capability reporting (`AVAILABLE`/`DEGRADED`/`FAILED`) for the Frida workflow.
* README / PROJECT_SUMMARY accuracy pass (remove claims for files that do not
  yet exist).
* Structured findings schema, CWE/MASVS mappings, dedup/baseline, SARIF export.
