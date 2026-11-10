"""Unit tests for the Noir output parser and the endpoint -> ZAP seed mapping.

No live containers: everything runs against `fixtures/noir-gitea-sample.json`,
which is a verbatim excerpt of a real `noir scan --ai-context -T` run over the
pinned Gitea v1.16.0 source. Keeping it verbatim means these tests also serve
as a record of Noir's output shape for the writeup.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import pytest

from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.adapters.noir_runner import (
    NoirEndpoint,
    NoirError,
    build_ai_context_artifact,
    build_command,
    parse_endpoints,
    parse_path_vars,
    substitute_path,
    to_seed_requests,
)
# The placeholder values live on the target (YAML) now, not in the Noir wrapper;
# the substitution mechanics under test are exercised with the Gitea target's set.
from dast_orchestrator.adapters import targets as _targets
GITEA_PATH_VARS = _targets.get("gitea").path_vars

FIXTURE = FIXTURES_DIR / "noir-gitea-sample.json"
TARGET = "http://target-gitea:3000"


@pytest.fixture
def raw() -> dict:
    return json.loads(FIXTURE.read_text())


# -- parsing ---------------------------------------------------------------


def test_parse_drops_non_http_and_docs_endpoints(raw):
    endpoints = parse_endpoints(raw)
    # The fixture holds 6 chi endpoints plus one CLI entry and one netlify
    # (Gitea's docs site) entry, both of which must be filtered out.
    assert len(endpoints) == 6
    assert {e.technology for e in endpoints} == {"go_chi"}


def test_parse_drops_per_target_ignored_technologies(raw):
    # A WordPress target passes php_pure (Noir's file-as-endpoint fallback) so
    # those source-file pseudo-endpoints never reach the scan tree. Simulate one
    # in the fixture and confirm the per-target set drops it on top of netlify.
    raw = json.loads(json.dumps(raw))  # don't mutate the shared fixture
    raw["endpoints"].append({
        "protocol": "http", "method": "GET", "url": "/src/Foo.php",
        "details": {"technology": "php_pure"},
    })
    kept_default = parse_endpoints(raw)
    kept_filtered = parse_endpoints(raw, ("php_pure",))
    assert any(e.path == "/src/Foo.php" for e in kept_default)   # not global
    assert all(e.path != "/src/Foo.php" for e in kept_filtered)  # dropped per-target


def test_parse_keeps_ai_context_categories_even_when_empty(raw):
    endpoints = parse_endpoints(raw)
    for endpoint in endpoints:
        assert set(endpoint.ai_context) == set(noir_runner.AI_CONTEXT_CATEGORIES)


def test_parse_extracts_guard_and_sink(raw):
    endpoints = parse_endpoints(raw)
    icon = next(e for e in endpoints if e.path == "/apple-touch-icon.png")
    assert icon.ai_context["guards"][0]["kind"] == "auth_guard"
    assert icon.ai_context["sinks"][0]["kind"] == "redirect"
    assert icon.code_paths[0] == ("/src/routers/web/web.go", 96)


def test_parse_rejects_output_without_endpoints():
    with pytest.raises(NoirError):
        parse_endpoints({"passive_results": []})


# -- placeholder substitution ---------------------------------------------


@pytest.mark.parametrize(
    "template,expected",
    [
        ("/explore/repos", "/explore/repos"),
        ("/user/avatar/{username}/{size}", "/user/avatar/thesis/84"),
        ("/{username}/{reponame}/issues", "/thesis/demo/issues"),
        # chi allows an inline regex containing its own braces; a naive
        # non-greedy regex substitution would stop at the first '}' here.
        (
            "/{username}/{reponame}/wiki/commit/{sha:[a-f0-9]{7,40}}.{ext}",
            "/thesis/demo/wiki/commit/" + "0" * 40 + ".md",
        ),
        ("/template/*", "/template/index"),
        # Unknown placeholder names fall back rather than leaking braces
        # into the URL, which ZAP would reject.
        ("/admin/monitor/queue/{qid}/cancel/{pid}", "/admin/monitor/queue/1/cancel/1"),
    ],
)
def test_substitute_path(template, expected):
    assert substitute_path(template, GITEA_PATH_VARS) == expected


def test_substitute_path_overrides_win():
    assert (
        substitute_path("/{username}/x", {**GITEA_PATH_VARS, "username": "bob"})
        == "/bob/x"
    )


# -- endpoint -> seed request ---------------------------------------------


def test_to_seed_requests_builds_absolute_urls(raw):
    seeds = to_seed_requests(parse_endpoints(raw), TARGET)
    by_url = {s.url: s for s in seeds}
    assert f"{TARGET}/explore/repos" in by_url
    assert by_url[f"{TARGET}/explore/repos"].method == "GET"
    assert by_url[f"{TARGET}/user/login"].method == "POST"


def test_to_seed_requests_keeps_template_as_join_key(raw):
    seeds = to_seed_requests(parse_endpoints(raw), TARGET)
    avatar = next(s for s in seeds if "/user/avatar/" in s.url)
    assert avatar.endpoint_key == "GET /user/avatar/{username}/{size}"


def test_to_seed_requests_strips_trailing_slash_on_base():
    endpoints = [NoirEndpoint(method="GET", path="/a", technology="go_chi")]
    assert to_seed_requests(endpoints, TARGET + "/")[0].url == f"{TARGET}/a"


def test_to_seed_requests_dedupes_collapsed_templates():
    # Distinct templates can substitute down to the same concrete URL; sending
    # it twice adds no site-tree node, only run time.
    endpoints = [
        NoirEndpoint(method="GET", path="/repo/{id}", technology="go_chi"),
        NoirEndpoint(method="GET", path="/repo/{index}", technology="go_chi"),
        NoirEndpoint(method="POST", path="/repo/{id}", technology="go_chi"),
    ]
    seeds = to_seed_requests(endpoints, TARGET)
    assert [(s.method, s.url) for s in seeds] == [
        ("GET", f"{TARGET}/repo/1"),
        ("POST", f"{TARGET}/repo/1"),
    ]


def test_parse_path_vars():
    assert parse_path_vars(["username=thesis", "reponame=demo"]) == {
        "username": "thesis",
        "reponame": "demo",
    }


def test_parse_path_vars_rejects_missing_equals():
    with pytest.raises(NoirError):
        parse_path_vars(["username"])


# -- artifact + command ----------------------------------------------------


def test_ai_context_artifact_matches_documented_schema(raw):
    endpoints = parse_endpoints(raw)
    artifact = build_ai_context_artifact(endpoints, Path("/src"), "20260817T120000Z")
    assert artifact["schema_version"] == noir_runner.AI_CONTEXT_SCHEMA_VERSION
    assert artifact["noir_image"] == noir_runner.NOIR_IMAGE
    assert len(artifact["endpoints"]) == len(endpoints)
    entry = artifact["endpoints"][0]
    assert entry["key"].startswith(entry["method"] + " ")
    assert set(entry["ai_context"]) == set(noir_runner.AI_CONTEXT_CATEGORIES)


def test_seed_map_records_the_template_behind_every_concrete_url(raw):
    artifact = noir_runner.build_seed_map_artifact(
        parse_endpoints(raw), TARGET, "20260817T120000Z", GITEA_PATH_VARS
    )
    by_path = {(e["method"], e["path"]): e for e in artifact["entries"]}
    assert by_path[("GET", "/user/avatar/thesis/84")]["endpoint_keys"] == [
        "GET /user/avatar/{username}/{size}"
    ]
    assert by_path[("GET", "/user/avatar/thesis/84")]["url"] == (
        f"{TARGET}/user/avatar/thesis/84"
    )


def test_seed_map_keeps_colliding_templates_instead_of_deduping():
    # to_seed_requests drops the duplicate request (nothing to gain by sending
    # it twice), but the *map* must keep both: either template could be the one
    # a later finding belongs to, and silently picking one would fabricate a
    # correlation.
    endpoints = [
        NoirEndpoint(method="GET", path="/repo/{id}", technology="go_chi"),
        NoirEndpoint(method="GET", path="/repo/{index}", technology="go_chi"),
    ]
    artifact = noir_runner.build_seed_map_artifact(endpoints, TARGET, "20260817T120000Z")
    assert len(artifact["entries"]) == 1
    assert artifact["entries"][0]["endpoint_keys"] == ["GET /repo/{id}", "GET /repo/{index}"]


def test_seed_map_records_the_substitutions_it_used(raw):
    artifact = noir_runner.build_seed_map_artifact(
        parse_endpoints(raw), TARGET, "20260817T120000Z",
        {**GITEA_PATH_VARS, "username": "bob"},
    )
    # The table is part of the artifact so a stored map can be read without
    # also knowing which --path-var flags that run was given.
    assert artifact["path_vars"]["username"] == "bob"
    assert artifact["path_vars"]["reponame"] == "demo"


def test_write_artifacts_emits_all_three_files(raw, tmp_path):
    endpoints = parse_endpoints(raw)
    paths = noir_runner.write_artifacts(
        raw, endpoints, Path("/src"), tmp_path, "20260817T120000Z", TARGET
    )
    # Stable basenames inside the run's own folder data/<ts>/.
    assert [p.name for p in paths] == [
        "scan-noir-endpoints.json",
        "scan-noir-ai-context.json",
        "scan-noir-seed-map.json",
    ]
    assert all(p.parent.name == "20260817T120000Z" for p in paths)
    assert all(json.loads(p.read_text()) for p in paths)


def test_write_artifacts_separates_the_run_folder_from_the_stamp(raw, tmp_path):
    # The folder is the run id (<timestamp>-<target>); the timestamp inside the
    # artifacts stays the plain instant they were generated at.
    endpoints = parse_endpoints(raw)
    paths = noir_runner.write_artifacts(
        raw, endpoints, Path("/src"), tmp_path, "20260817T120000Z", TARGET,
        run_id="20260817T120000Z-gitea",
    )
    assert all(p.parent.name == "20260817T120000Z-gitea" for p in paths)
    seed_map = json.loads(paths[2].read_text())
    assert seed_map["generated_at"] == "20260817T120000Z"


def test_build_command_pins_image_and_mounts_source_read_only(tmp_path):
    cmd = build_command(tmp_path)
    assert noir_runner.NOIR_IMAGE in cmd
    assert ":latest" not in " ".join(cmd)
    assert f"{tmp_path.resolve()}:/src:ro" in cmd
    assert "--ai-context" in cmd


def test_run_noir_reports_missing_source_tree(tmp_path):
    with pytest.raises(NoirError, match="source tree not found"):
        noir_runner.run_noir(tmp_path / "nope")


@pytest.mark.parametrize(
    "name, expected",
    [
        # The one that caused the misreading: session plumbing on every public
        # Gitea route, reported by Noir as an auth_guard.
        ("Go middleware sessioner", "session-plumbing"),
        ("reqSignIn", "enforces-login"),
        ("reqRepoAdmin", "enforces-login"),
        ("ignSignIn", "explicitly-public"),
        # Unrecognised middleware stays unknown rather than being guessed at:
        # a wrong "protected" reading is the failure this exists to prevent.
        ("context.Toggle", "unknown"),
    ],
)
def test_classify_guard(name, expected):
    assert noir_runner.classify_guard(name) == expected
