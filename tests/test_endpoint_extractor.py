"""Unit tests for the API endpoint extractor."""
import pytest


@pytest.fixture
def endpoint_mod(load_script):
    return load_script("static_analysis/endpoint_extractor.py", "endpoint_extractor")


def test_extracts_url_from_java_source(endpoint_mod, tmp_path):
    src = tmp_path / "ApiClient.java"
    src.write_text(
        "public class ApiClient {\n"
        '    private static final String BASE_URL = "https://api.example.com/v1/users";\n'
        "}\n"
    )

    extractor = endpoint_mod.EndpointExtractor(str(tmp_path))
    endpoints = extractor.extract_endpoints()

    urls = " ".join(e.get("url", "") for e in endpoints)
    assert "api.example.com" in urls


def test_extracts_retrofit_annotation(endpoint_mod, tmp_path):
    src = tmp_path / "Service.java"
    src.write_text(
        "public interface Service {\n"
        '    @GET("/api/v2/profile")\n'
        "    Call<Profile> getProfile();\n"
        "}\n"
    )

    extractor = endpoint_mod.EndpointExtractor(str(tmp_path))
    endpoints = extractor.extract_endpoints()

    paths = " ".join(e.get("url", "") for e in endpoints)
    assert "/api/v2/profile" in paths


def test_empty_source_yields_no_endpoints(endpoint_mod, tmp_path):
    (tmp_path / "Empty.java").write_text("public class Empty {}\n")
    extractor = endpoint_mod.EndpointExtractor(str(tmp_path))
    assert extractor.extract_endpoints() == []
