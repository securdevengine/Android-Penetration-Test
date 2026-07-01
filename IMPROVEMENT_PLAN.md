# Improvement Plan — Android Reverse Engineering Toolkit

_Last verified: 2026-07-01_

The "target" is the toolkit described in `README.md` and `PROJECT_SUMMARY.md`: a
self-consistent, runnable framework whose documentation matches the code and
whose scripts behave predictably (including when optional runtime dependencies
or a connected device are absent). This document records what was verified and a
prioritized roadmap to close the remaining gaps.

## 1. Verification results (current state)

| Check | Result |
|-------|--------|
| Python syntax (`py_compile`) on all 11 scripts | ✅ Pass |
| Frida JS syntax (`node --check`) on all 7 scripts | ✅ Pass |
| CLI `--help` smoke test (all scripts) | ✅ Pass after fixes (see §2) |
| Required CI directories present (`scripts`, `docs`, `frida_scripts`, `config`) | ✅ Pass |
| Required CI docs (`docs/01`–`07`) present | ✅ Pass |
| Documentation matches on-disk file tree | ❌ Large drift (see §3) |

### Fixed — round 1 (CLI robustness)

1. **`owasp_scanner.py`** — replaced ad-hoc `sys.argv` parsing (which treated
   `--help` as an APK path) with `argparse`, consistent with the other
   scanners. Now supports `-h/--help` and `-o/--output`.
2. **`frida_automation.py`** — `import frida` was a hard top-level import that
   crashed the script (even `--help`) when Frida was not installed. It is now a
   guarded import with a clear runtime message: _"The 'frida' package is not
   installed..."_.
3. **`jwt_analyzer.py`** — `import jwt` (PyJWT) is now guarded so the CLI works
   without the crypto backend installed and exits with a clear install hint
   instead of an uncaught error.

### Fixed — round 2 (CI, safety, tests)

4. **CI workflow** — now triggers on PRs to `development` (not just `main`),
   diffs against the actual PR base SHA instead of `origin/main`, upgrades
   `upload-artifact` v3→v4, and installs `frida-tools` via pip instead of npm.
   Added a `unit-tests` job wired into the approval gate.
5. **TLS secure by default** — `jwt_analyzer.py` and `auth_flow_tester.py` now
   verify certificates by default; certificate verification is only disabled via
   an explicit `--insecure` flag (which also scopes the urllib3 warning
   suppression to that opt-in).
6. **JWT report redaction** — `jwt_analyzer.py` redacts the raw token,
   signature, payload values, and forged tokens in saved reports by default
   (claim *names* are preserved for analysis); `--include-sensitive` opts back
   into the full data.
7. **Dependency split** — `requirements.txt` now lists only the packages the
   shipped scripts import; dev tooling moved to `requirements-dev.txt` and
   advertised-but-unused packages to `requirements-optional.txt`.
8. **Unit tests** — added `tests/` (pytest) covering JWT parsing + redaction,
   secret detection, endpoint extraction, and manifest analysis (16 tests).

## 2. Known remaining code issues

- **`utils/diagnostic_tool.py` and `utils/env_fixer.py`** do not use `argparse`
  and run their default action on any argument (no real `--help`). Low priority
  — they function — but adding an `argparse` interface would make the toolkit
  uniform. _(P2)_
- **No test suite.** `requirements.txt` pins `pytest`/`pytest-cov` and the CI
  narrative mentions "unit and integration tests," but there is no `tests/`
  directory. _(P1)_

## 3. Documentation ↔ reality drift (highest-impact gap)

`README.md` and `PROJECT_SUMMARY.md` advertise a directory tree that is largely
not present. Either the files must be created, or the docs must be corrected to
describe what actually ships. Missing but documented:

- **Scripts:** `dynamic_analysis/network_monitor.py`, `dynamic_analysis/log_analyzer.py`,
  `authentication/token_interceptor.py`, `utils/adb_helper.py`,
  `utils/crypto_utils.py`, `utils/report_generator.py`
- **`exploits/`** (entire dir): `jwt_forge.py`, `api_fuzzer.py`, `component_exploit.py`
- **Frida scripts:** `ssl_bypass/certificate_bypass.js`, `auth_hooks/hmac_hook.js`,
  `auth_hooks/refresh_hook.js`, `anti_debug/proc_spoofing.js`,
  `anti_debug/ptrace_bypass.js`, `anti_debug/jdwp_bypass.js`, and the entire
  `frida_scripts/general/` dir (`crypto_logger.js`, `file_monitor.js`, `network_tracer.js`)
- **Config:** `config/frida_config.json`, `config/burp_config.json`, `config/mobsf_config.yml`
- **Wordlists:** `wordlists/android_secrets.txt`, `wordlists/jwt_secrets.txt`
- **Root helpers:** `verify_setup.py`, `setup_env.sh`, `tools/install_tools.sh`
- **Sample:** `samples/vulnerable_app.apk` (referenced in the Quick Start command)

Also: the README references `frida_scripts/ssl_bypass/ssl_pinning_bypass.js`, but
the file that actually ships is `universal_ssl_bypass.js` — a name mismatch that
breaks copy-paste instructions.

## 4. Prioritized roadmap

### P0 — Make the docs truthful (fastest path to a consistent "target")
- Update `README.md` and `PROJECT_SUMMARY.md` so the documented tree matches the
  files that ship. Fix the `ssl_pinning_bypass.js` → `universal_ssl_bypass.js`
  name and the `samples/vulnerable_app.apk` Quick Start reference (either ship a
  sample or change the example to a `<target.apk>` placeholder).

### P1 — Baseline quality gates
- ~~Add a `tests/` suite (pytest) covering the pure-logic helpers~~ **Done**
  (round 2): `tests/` covers JWT parsing/redaction, secret detection, endpoint
  extraction, and manifest parsing, wired into CI as the `unit-tests` job.
- Make `black`/`isort`/`flake8` blocking (currently `|| echo`, so style drift
  never fails CI). Run one formatting pass first so the gate starts green.
  _(Still pending — left non-blocking so CI does not fail on pre-existing,
  unrelated style issues.)_

### P2 — Fill the highest-value documented gaps (create, don't just delete)
- `utils/report_generator.py` (HTML/JSON consolidation — several scanners already
  emit reports that a central generator could unify).
- `utils/adb_helper.py` and `utils/crypto_utils.py` (shared helpers reused by the
  dynamic + auth scripts).
- Missing Frida hooks under `anti_debug/` and `auth_hooks/`, plus
  `config/frida_config.json` / `burp_config.json`.
- Give `diagnostic_tool.py` / `env_fixer.py` a proper `argparse` interface.

### P3 — Advertised-but-aspirational features
- `exploits/` PoCs, additional wordlists, `verify_setup.py`. Build these only
  after P0–P2, and keep each addition reflected in the docs so drift does not
  reopen.

## 5. Suggested acceptance criteria for "target achieved"
1. Every path named in `README.md`/`PROJECT_SUMMARY.md` exists on disk (or the
   docs no longer name it).
2. Every Python entry point supports `--help` and degrades gracefully when its
   optional runtime dependency (frida, PyJWT, a device) is absent.
3. CI style/type gates are blocking and green; a real (if small) test suite runs.
4. The Quick Start commands in the README run end-to-end against a provided or
   clearly-placeholdered sample.
