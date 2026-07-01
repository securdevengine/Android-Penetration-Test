# Android Mobile Application Penetration Testing Toolkit

A command-line toolkit and set of Frida hooks for authorized Android application
security assessment. It covers APK static analysis, authentication testing,
runtime instrumentation, rooting diagnostics, and OWASP Mobile Top 10 checks.

Use it only on applications and devices you own or are explicitly authorized to
test.

## Objectives

- Extract API endpoints and potential secrets from APK contents.
- Inspect Android manifests and application structure.
- Analyze JWTs and exercise authentication flows.
- Instrument authorized test applications with Frida.
- Validate common OWASP Mobile Top 10 risks.
- Diagnose Android testing and rooting prerequisites.

## Project Structure

The tree below reflects the files that currently ship. Planned additions are
tracked in [IMPROVEMENT_PLAN.md](IMPROVEMENT_PLAN.md).

```text
.
|-- checklists/
|   `-- owasp-mobile-top10-manual-testing-checklist.md
|-- config/
|   `-- main_config.json
|-- docs/
|   |-- 01-environment-setup.md
|   |-- 02-static-analysis.md
|   |-- 03-dynamic-analysis.md
|   |-- 04-authentication-analysis.md
|   |-- 05-anti-debugging-bypass.md
|   |-- 06-rooting-techniques.md
|   `-- 07-owasp-mobile-top10-validation.md
|-- frida_scripts/
|   |-- anti_debug/universal_bypass.js
|   |-- auth_hooks/jwt_hook.js
|   |-- owasp/comprehensive_owasp_validator.js
|   |-- owasp_validation/
|   |   |-- data_storage_monitor.js
|   |   |-- network_monitor.js
|   |   `-- permission_monitor.js
|   `-- ssl_bypass/universal_ssl_bypass.js
|-- scripts/
|   |-- authentication/
|   |   |-- auth_flow_tester.py
|   |   `-- jwt_analyzer.py
|   |-- dynamic_analysis/frida_automation.py
|   |-- owasp_validation/owasp_scanner.py
|   |-- static_analysis/
|   |   |-- apk_analyzer.py
|   |   |-- endpoint_extractor.py
|   |   |-- manifest_analyzer.py
|   |   `-- secret_finder.py
|   `-- utils/
|       |-- diagnostic_tool.py
|       |-- env_fixer.py
|       `-- rooting_assistant.py
|-- tests/test_cli_smoke.py
|-- wordlists/api_endpoints.txt
|-- PROJECT_SUMMARY.md
|-- SETUP.md
|-- TROUBLESHOOTING.md
|-- requirements.txt
`-- setup.sh
```

## Quick Start

1. Set up the environment:

   ```bash
   ./setup.sh
   ```

2. Install Python dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

3. Run static analysis against an APK you are authorized to test:

   ```bash
   python scripts/static_analysis/apk_analyzer.py /path/to/target.apk
   ```

4. Attach Frida to a test application:

   ```bash
   python scripts/dynamic_analysis/frida_automation.py com.example.app
   frida -U -f com.example.app -l frida_scripts/ssl_bypass/universal_ssl_bypass.js
   ```

5. Run OWASP validation:

   ```bash
   python scripts/owasp_validation/owasp_scanner.py /path/to/target.apk
   ```

Every Python entry point supports `--help`. Device- and network-dependent
commands still require their documented tools and Python packages.

## Documentation

- [Setup](SETUP.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [Environment setup](docs/01-environment-setup.md)
- [Static analysis](docs/02-static-analysis.md)
- [Dynamic analysis](docs/03-dynamic-analysis.md)
- [Authentication analysis](docs/04-authentication-analysis.md)
- [Anti-debugging bypass](docs/05-anti-debugging-bypass.md)
- [Rooting techniques](docs/06-rooting-techniques.md)
- [OWASP Mobile Top 10 validation](docs/07-owasp-mobile-top10-validation.md)

## Tools Included

- Python analyzers for APKs, manifests, endpoints, secrets, JWTs, authentication
  flows, and OWASP checks.
- Frida hooks for SSL pinning, anti-debugging, JWT observation, network activity,
  permissions, and data storage.
- Environment diagnostics, repair guidance, and rooting assistance.

External tools such as ADB, JADX, APKTool, Frida, and Burp Suite are not bundled.
See [SETUP.md](SETUP.md) for installation requirements.

## Testing

```bash
python -m compileall -q scripts
python -m unittest discover -s tests -v
```

Frida JavaScript syntax can be checked with:

```bash
find frida_scripts -name '*.js' -exec node --check {} \;
```

## Contributing

1. Fork the repository and create a focused feature branch.
2. Add or update tests with behavior changes.
3. Run the Python and Frida checks above.
4. Open a pull request describing the tested behavior.

## License and Disclaimer

This project is licensed under the MIT License. It is intended for education and
authorized security testing only. Users are responsible for obtaining permission
and complying with applicable laws and policies.
