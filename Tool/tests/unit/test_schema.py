"""Artifact-schema validation on read (§R5).

The schemas in `Tool/schemas/` are the contract between stages; `foundation.schema`
enforces it where a stage reads a file. These pin the policy — a required-field
violation is fatal, a looser one warns — and that the registered schemas are real,
loadable JSON Schemas that the actual artifact shapes satisfy.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from dast_orchestrator.foundation import schema

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# -- the registry is real --------------------------------------------------


def test_every_registered_schema_exists_and_is_a_valid_json_schema():
    for _pattern, filename in schema._REGISTRY:
        path = schema.SCHEMAS_DIR / filename
        assert path.is_file(), filename
        doc = json.loads(path.read_text())
        # Raises if the schema itself is malformed — the check must never crash a
        # run because its own schema is broken.
        jsonschema.validators.validator_for(doc).check_schema(doc)


def test_the_run_metrics_family_and_suffixed_variants_resolve():
    assert schema.schema_file_for("scan-metrics.json").name == "run-metrics.schema.json"
    assert schema.schema_file_for("triage.json").name == "triage-result.schema.json"
    assert schema.schema_file_for("triage-qwen.json").name == "triage-result.schema.json"
    assert schema.schema_file_for("verification-hybrid.json").name == "verification-result.schema.json"


def test_a_stage_metrics_file_is_not_mistaken_for_that_stage_result():
    # `<kind>-metrics.json` collides in shape with `<stage>-<suffix>.json`: for the
    # triage stage `triage-metrics.json` could read as a triage RESULT with suffix
    # "metrics". The metrics pattern is ordered first so a metrics file always wins.
    assert schema.schema_file_for("triage-metrics.json").name == "run-metrics.schema.json"
    assert schema.schema_file_for("triage-metrics-qwen.json").name == "run-metrics.schema.json"
    assert schema.schema_file_for("verify-metrics.json").name == "run-metrics.schema.json"
    assert schema.schema_file_for("report-metrics.json").name == "run-metrics.schema.json"
    assert schema.schema_file_for("static-analysis-metrics.json").name == "run-metrics.schema.json"


def test_triage_prompts_is_not_mistaken_for_a_triage_result():
    # triage-prompts.json is the dry-run prompt dump, a different shape — it must
    # NOT match the triage-result family, or a dry run would fail validation.
    assert schema.schema_file_for("triage-prompts.json") is None


def test_an_unregistered_artifact_is_not_checked():
    assert schema.schema_file_for("report.md") is None
    assert schema.check("report.md", {"anything": 1}) == []


# -- the fixtures satisfy their schemas (catches schema-vs-reality drift) ---


def test_the_zap_alerts_fixture_matches_its_schema():
    data = json.loads((FIXTURES / "zap-alerts-sample.json").read_text())
    assert schema.violations("scan-zap-alerts.json", data) == []


def test_the_triage_schema_accepts_every_suggested_tool_the_pipeline_emits():
    # The regression that cost the 2026-09-23 baseline its verify stage: the
    # synthesis pass writes `suggested_tool` from
    # ``synthesize``'s enum — sqlmap/nuclei/ffuf/interactsh/**self-evident**/
    # **out-of-scope** — and the systemic path writes ``none``, but the schema's
    # enum listed only sqlmap/nuclei/ffuf/interactsh/none. So real triage output
    # carrying a `self-evident` synthesis claim FAILED validation at verify's
    # read, AFTER the scan. Every `suggested_tool` enum in the schema must admit
    # the whole vocabulary the code can emit, or §R5 rejects a valid artifact.
    emitted = {"sqlmap", "nuclei", "ffuf", "interactsh",
               "self-evident", "out-of-scope", "none"}
    doc = json.loads((schema.SCHEMAS_DIR / "triage-result.schema.json").read_text())

    enums: list[list[str]] = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("suggested_tool"), dict) \
                    and "enum" in node["suggested_tool"]:
                enums.append(node["suggested_tool"]["enum"])
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(doc)
    assert enums, "no suggested_tool enum found — did the schema shape change?"
    for enum in enums:
        assert emitted <= set(enum), f"enum {enum} is missing {emitted - set(enum)}"


# -- the policy: fatal vs warn ---------------------------------------------


def test_a_missing_required_field_is_fatal():
    with pytest.raises(schema.ArtifactError):
        schema.check("scan-zap-alerts.json", {"target": "x"})   # no `alerts`


def test_a_wrong_schema_version_is_fatal():
    with pytest.raises(schema.ArtifactError):
        schema.check("scan-noir-seed-map.json", {"schema_version": 2, "entries": []})


def test_a_wrong_typed_required_field_is_fatal():
    # `entries` present but the wrong type — a required field violated in shape.
    with pytest.raises(schema.ArtifactError):
        schema.check("scan-noir-seed-map.json", {"schema_version": 1, "entries": {}})


def test_a_matched_template_s_cwe_may_be_the_browser_probe_s_integer():
    # nuclei writes strings and `mcp/browser_server.py` writes `[79]`, so a strict string
    # made `dast report` refuse the only runs that confirmed the frameid XSS.
    def find(node):
        if isinstance(node, dict):
            if "matched_templates" in node:
                return node["matched_templates"]
            node = list(node.values())
        for child in node if isinstance(node, list) else []:
            found = find(child)
            if found:
                return found
        return None

    doc = json.loads((schema.SCHEMAS_DIR / "verification-result.schema.json").read_text())
    templates = find(doc)
    jsonschema.validate([{"cwe": [79]}, {"cwe": ["79"]}], templates)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate([{"cwe": [None]}], templates)


def test_a_soft_deviation_only_warns(capsys):
    # An OPTIONAL field with the wrong type: the run continues, with a warning.
    out = schema.check("scan-zap-alerts.json", {"alerts": [], "alert_count": "nope"})
    assert out and "alert_count" in out[0]

# The drift test that matters — a built triage artifact satisfies its schema —
# lives in test_join, where the corpus fixtures are (test_a_built_artifact_...).


# -- the §T3.0 schema gaps: calls_log + harness results ----------------------


def _validator(name):
    import jsonschema
    doc = json.loads((schema.SCHEMAS_DIR / name).read_text())
    jsonschema.validators.validator_for(doc).check_schema(doc)
    return jsonschema.validators.validator_for(doc)(doc)


def test_run_metrics_schema_now_describes_the_per_call_log():
    v = _validator("run-metrics.schema.json")
    record = {
        "schema_version": 1, "run": "20260101T000000Z-wp-abcdef", "kind": "triage",
        "started_at": "20260101T000000Z", "total_seconds": 1.0, "host": {},
        "tools": {}, "results": {},
        "stages": {"llm_screening": {"seconds": 1.0, "calls_log": [{
            "at": "20260101T000000Z", "pass": 1, "latency_ms": 800,
            "model_requested": "deepseek/deepseek-v4-flash-0731",
            "model_served": "deepseek/deepseek-v4-flash-0731", "vendor": "deepseek",
            "provider": "fireworks", "prompt_tokens": 1200, "completion_tokens": 40,
            "cached_prompt_tokens": 0, "cost_usd": 0.0002, "outcome": "ok"}]}},
    }
    assert not list(v.iter_errors(record))


def test_harness_results_schema_validates_a_sheet_result():
    v = _validator("harness-results.schema.json")
    results = {
        "sheet": "20260101T000000Z-baseline", "started_at": "20260101T000000Z",
        "base_env": ".env", "dry_run": False,
        "executions": [{"row": "wordpress-baseline", "repeat": 1,
                        "label": "wordpress-baseline", "run": "20260101T000000Z-wp-a",
                        "failed_stage": None, "seconds": 12.0, "env_file": "wp.env"}],
        "metrics_rows": [{"run": "20260101T000000Z-wp-a", "kind": "triage",
                          "label": "wordpress-baseline", "config_digest": "abcdef",
                          "total_seconds": 5.0, "alerts": 42}],
        "variance": {},
    }
    assert not list(v.iter_errors(results))
    assert schema.schema_file_for("results.json").name == "harness-results.schema.json"
