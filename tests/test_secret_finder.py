"""Unit tests for the hardcoded-secret finder."""
import pytest


@pytest.fixture
def secret_mod(load_script):
    return load_script("static_analysis/secret_finder.py", "secret_finder")


def test_detects_api_key_and_aws_key(secret_mod, tmp_path):
    src = tmp_path / "config.json"
    src.write_text(
        '{\n'
        '  "api_key": "AbC123dEf456GHi789xyz",\n'
        '  "aws": "AKIAZ9Q8W7E6R5T4Y3U2"\n'
        '}\n'
    )

    finder = secret_mod.SecretFinder(str(tmp_path))
    secrets = finder.find_secrets()

    found_types = {s.get("type") for s in secrets}
    assert "api_key" in found_types
    assert "aws_access_key" in found_types


def test_clean_source_reports_no_secrets(secret_mod, tmp_path):
    src = tmp_path / "Main.java"
    src.write_text(
        "public class Main {\n"
        "    public static void main(String[] args) {\n"
        "        System.out.println(\"hello world\");\n"
        "    }\n"
        "}\n"
    )

    finder = secret_mod.SecretFinder(str(tmp_path))
    secrets = finder.find_secrets()

    assert secrets == []


def test_entropy_calculation_is_higher_for_random_strings(secret_mod, tmp_path):
    finder = secret_mod.SecretFinder(str(tmp_path))
    low = finder._calculate_entropy("aaaaaaaaaa")
    high = finder._calculate_entropy("aB3$xZ9!qP")
    assert high > low
