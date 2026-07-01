# Improvement Plan

_Last verified: 2026-07-01_

The target is a self-consistent Android security toolkit whose documentation
matches the repository, whose entry points behave predictably in a clean
environment, and whose important analysis behavior is protected by tests.

## Verified Baseline

| Check | Result |
| --- | --- |
| Python syntax for all 11 scripts | Pass |
| Frida JavaScript syntax for all 7 scripts | Pass |
| `--help` for all 11 Python entry points | Pass in a clean Python runtime |
| Documentation matches the shipped top-level capabilities | Pass |
| Automated CLI smoke suite | Added; pass |
| Device/APK/network integration tests | Not run; fixtures not provided |

## Completed in the Current Improvement Branch

- Replaced the OWASP scanner's manual argument handling with `argparse` and
  exposed its output-directory option.
- Made Frida, PyJWT, and HTTP imports dependency-safe so help can render before
  runtime dependency validation.
- Added proper help interfaces to the diagnostic, environment-fixer, and
  rooting-assistant utilities.
- Fixed `diagnostic_tool.py` so check-only mode no longer invokes repair logic;
  repairs now require `--fix`.
- Added a dependency-free smoke test covering all eleven Python entry points.
  Wiring it into CI remains blocked until the publishing credential is granted
  GitHub's `workflow` scope.
- Rewrote `README.md` and `PROJECT_SUMMARY.md` around the files and capabilities
  that actually ship. Removed the nonexistent sample APK and wrong Frida
  filename from copy-paste commands.

## Remaining Roadmap

### P1 - Protect core logic with unit tests

- Add fixtures for decoded APK trees and representative manifests.
- Cover JWT structural parsing, endpoint extraction, secret classification, and
  manifest findings without requiring a device or network.
- Add negative cases for malformed input, timeouts, and missing tools.

Acceptance: each pure analysis module has success and failure-path coverage, and
CI reports coverage without depending on an Android device.

### P2 - Make quality gates enforceable

- Apply one repository-wide formatting/import-sorting pass.
- Resolve or explicitly configure flake8 and mypy findings.
- Remove the `|| echo` fallbacks only after each corresponding check is green.
- Pin CI action major versions through a separate maintenance change.

Acceptance: formatting, linting, tests, and type checks fail CI on regressions.

### P3 - Reduce duplication and add integration seams

- Extract shared ADB command handling, subprocess timeouts, and report schemas.
- Add a report aggregator for the JSON output produced by multiple analyzers.
- Introduce mockable HTTP/session and command-runner interfaces.
- Add opt-in device tests for ADB and Frida with clear skip conditions.

Acceptance: shared infrastructure is tested once, and integration tests skip
cleanly when an authorized lab device is unavailable.

### P4 - Add features only with implementation and tests

Potential additions include focused Frida hooks, richer wordlists, and reusable
configuration profiles. Update the README in the same change that adds each
feature; do not advertise placeholder paths.

## Definition of Target Achieved

1. Every documented command refers to a shipped path and renders help cleanly.
2. Pure analysis logic has meaningful automated success and failure coverage.
3. Formatting, linting, typing, and tests are blocking and green in CI.
4. Device/network workflows have documented prerequisites and opt-in integration
   tests rather than unconditional CI dependencies.
5. New capabilities land with documentation and tests in the same change.
