"""Unit tests for the AndroidManifest.xml analyzer."""
import textwrap

import pytest

MANIFEST_DEBUGGABLE = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.prodapp">
        <uses-permission android:name="android.permission.INTERNET"/>
        <application android:debuggable="true" android:allowBackup="true">
            <activity android:name=".MainActivity" android:exported="true">
                <intent-filter>
                    <action android:name="android.intent.action.MAIN"/>
                    <category android:name="android.intent.category.LAUNCHER"/>
                </intent-filter>
            </activity>
        </application>
    </manifest>
    """
)

MANIFEST_HARDENED = textwrap.dedent(
    """\
    <?xml version="1.0" encoding="utf-8"?>
    <manifest xmlns:android="http://schemas.android.com/apk/res/android"
              package="com.example.prodapp">
        <application android:debuggable="false" android:allowBackup="false"
                     android:usesCleartextTraffic="false">
            <activity android:name=".MainActivity" android:exported="false"/>
        </application>
    </manifest>
    """
)


@pytest.fixture
def manifest_mod(load_script):
    return load_script("static_analysis/manifest_analyzer.py", "manifest_analyzer")


def _write(tmp_path, content):
    path = tmp_path / "AndroidManifest.xml"
    path.write_text(content)
    return path


def test_basic_info_extracted(manifest_mod, tmp_path):
    path = _write(tmp_path, MANIFEST_DEBUGGABLE)
    results = manifest_mod.ManifestAnalyzer(str(path)).analyze()
    assert results["application_info"]["package_name"] == "com.example.prodapp"


def test_debuggable_flag_flagged(manifest_mod, tmp_path):
    path = _write(tmp_path, MANIFEST_DEBUGGABLE)
    results = manifest_mod.ManifestAnalyzer(str(path)).analyze()

    finding_types = {f["type"] for f in results["security_findings"]}
    assert "Debuggable Application" in finding_types
    assert results["application_info"]["application_flags"]["debuggable"] is True


def test_hardened_manifest_not_flagged_debuggable(manifest_mod, tmp_path):
    path = _write(tmp_path, MANIFEST_HARDENED)
    results = manifest_mod.ManifestAnalyzer(str(path)).analyze()

    finding_types = {f["type"] for f in results["security_findings"]}
    assert "Debuggable Application" not in finding_types
    assert results["application_info"]["application_flags"]["debuggable"] is False


def test_missing_manifest_returns_empty(manifest_mod, tmp_path):
    results = manifest_mod.ManifestAnalyzer(str(tmp_path / "nope.xml")).analyze()
    assert results == {}
