"""OpenAPI/Swagger route import: parse a spec into seed requests, no network.

The mechanism exists for a target whose router Noir cannot parse (measured:
Grafana's ``pkg/api`` yields zero Noir endpoints). It is deliberately a small,
transparent parser feeding the SAME seeding path Noir does — so these tests pin
the parse, the parameter substitution, the base-path rules, and the fetch/read
boundary, all without a live target.
"""

from __future__ import annotations

import json

import pytest

from dast_orchestrator.adapters import openapi_import as oi
from dast_orchestrator.adapters.openapi_import import OpenApiError, OpenApiSpec

OPENAPI_3 = {
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/v2"}],
    "paths": {
        "/users/{id}": {"get": {}, "delete": {}},
        "/health": {"get": {}},
        "/things": {"post": {}, "parameters": []},   # parameters is not a method
        "/ref-only": {"$ref": "#/x"},                # no method key -> no route
    },
}

SWAGGER_2 = {"swagger": "2.0", "basePath": "/api",
             "paths": {"/pets/{petId}": {"get": {}, "put": {}}}}


def test_spec_paths_reads_methods_and_prepends_the_server_base():
    got = set(oi.spec_paths(OPENAPI_3))
    assert ("GET", "/v2/users/{id}") in got
    assert ("DELETE", "/v2/users/{id}") in got
    assert ("GET", "/v2/health") in got
    assert ("POST", "/v2/things") in got
    # `parameters` and a method-less `$ref` item contribute nothing
    assert not any(m == "PARAMETERS" for m, _ in got)
    assert all(p != "/v2/ref-only" for _, p in got)


def test_swagger_2_base_path_is_honoured():
    assert ("GET", "/api/pets/{petId}") in oi.spec_paths(SWAGGER_2)


def test_base_path_override_wins_over_the_spec():
    got = oi.spec_paths(OPENAPI_3, base_path_override="/mounted")
    assert all(p.startswith("/mounted/") for _, p in got)


def test_seeds_substitute_path_vars_and_carry_the_target_host():
    seeds = oi.spec_to_seeds(OPENAPI_3, "http://target-x:3000", {"id": "7"})
    urls = {s.url for s in seeds}
    assert "http://target-x:3000/v2/users/7" in urls          # {id} -> 7
    assert "http://target-x:3000/v2/health" in urls
    # the endpoint key records the template, so the artifact says where it came from
    assert any(s.endpoint_key == "openapi:GET /v2/users/{id}" for s in seeds)


def test_seeds_are_deduplicated_on_method_and_url():
    # two templates that fill to the same URL (unknown params -> "1") collapse
    doc = {"paths": {"/a/{x}": {"get": {}}, "/a/{y}": {"get": {}}}}
    seeds = oi.spec_to_seeds(doc, "http://t", {})   # x,y both fall back to "1"
    assert len(seeds) == 1


def test_a_spec_needs_exactly_one_of_url_or_file():
    with pytest.raises(OpenApiError):
        OpenApiSpec(url="u", file="f")
    with pytest.raises(OpenApiError):
        OpenApiSpec()
    OpenApiSpec(url="http://t/spec.json")   # fine
    OpenApiSpec(file="spec.yaml")           # fine


def test_spec_without_paths_is_an_error():
    with pytest.raises(OpenApiError):
        oi.spec_paths({"openapi": "3.0.0"})


def test_load_doc_fetches_a_url_spec_through_the_transport():
    captured = {}

    def fake_fetch(method, url, timeout):
        captured["url"] = url
        return 200, "", json.dumps(SWAGGER_2)

    doc = oi.load_doc(OpenApiSpec(url="http://target-x/api-docs"),
                      target_dir=None, fetch=fake_fetch)
    assert captured["url"] == "http://target-x/api-docs"
    assert ("GET", "/api/pets/{petId}") in oi.spec_paths(doc)


def test_load_doc_errors_on_an_http_error_status():
    with pytest.raises(OpenApiError):
        oi.load_doc(OpenApiSpec(url="http://t/nope"), None,
                    fetch=lambda *a: (404, "", ""))


def test_load_doc_reads_a_committed_file_spec(tmp_path):
    (tmp_path / "spec.yaml").write_text(
        "swagger: '2.0'\nbasePath: /api\npaths:\n  /x: {get: {}}\n")
    doc = oi.load_doc(OpenApiSpec(file="spec.yaml"), target_dir=tmp_path)
    assert ("GET", "/api/x") in oi.spec_paths(doc)


def test_a_file_spec_cannot_escape_the_target_directory(tmp_path):
    with pytest.raises(OpenApiError):
        oi.load_doc(OpenApiSpec(file="../../etc/passwd"), target_dir=tmp_path)


def test_a_url_spec_needs_a_transport():
    with pytest.raises(OpenApiError):
        oi.load_doc(OpenApiSpec(url="http://t/spec"), None, fetch=None)
