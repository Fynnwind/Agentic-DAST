"""Check the correlation artifact against its documented schema.

Same job as `test_ai_context_schema.py` does for Phase 2's output: the schema is
the contract Phase 4 (MCP dispatch + SARIF export) will build against, so it
cannot be allowed to drift away from what `join.build_artifact` writes.
Both arms are exercised — with and without the LLM block — because `--no-llm`
is a supported, offline mode and its output has to validate too.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import jsonschema
import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.analysis.join import RunArtifacts
from dast_orchestrator.adapters.noir_runner import (
    build_ai_context_artifact,
    build_seed_map_artifact,
    parse_endpoints,
)

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "triage-result.schema.json"
FIXTURES = FIXTURES_DIR


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA.read_text())


@pytest.fixture
def run() -> RunArtifacts:
    endpoints = parse_endpoints(
        json.loads((FIXTURES / "noir-gitea-sample.json").read_text())
    )
    return RunArtifacts(
        timestamp="20260817T114501Z",
        ai_context=build_ai_context_artifact(endpoints, Path("/src"), "20260817T114501Z"),
        zap_report=json.loads((FIXTURES / "zap-alerts-sample.json").read_text()),
        seed_map=build_seed_map_artifact(
            endpoints, "http://target-gitea:3000", "20260817T114501Z"
        ),
        ai_context_path=Path("noir-ai-context-20260817T114501Z.json"),
        zap_report_path=Path("zap-alerts-20260817T114501Z.json"),
        seed_map_path=Path("noir-seed-map-20260817T114501Z.json"),
    )


@pytest.fixture
def bundles(run):
    return join.build_bundles(run)


def test_schema_is_itself_valid(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_control_arm_only_artifact_validates(schema, run, bundles):
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(run, bundles, findings, [], None)
    jsonschema.validate(artifact, schema)
    assert artifact["llm"] is None
    assert all(f["agreement"] == "not-evaluated" for f in artifact["findings"])


def test_both_arm_artifact_validates(schema, run, bundles):
    findings = join.build_findings(bundles)
    login = next(b for b in bundles if b.identifier == "POST /user/login")
    pairs = [(join.finding_id(login, g), g) for g in login.groups]

    text = (FIXTURES / "openrouter-response.json").read_text()
    by_confidence = {group.confidence: fid for fid, group in pairs}
    response = json.loads(
        json.loads(
            text.replace("__SQLI_MEDIUM__", by_confidence["Medium"])
            .replace("__SQLI_HIGH__", by_confidence["High"])
        )["choices"][0]["message"]["content"]
    )

    screening.merge_verdicts(findings, response, [fid for fid, _ in pairs])
    synth = json.loads(
        json.loads(
            (FIXTURES / "openrouter-synthesis-response.json").read_text()
            .replace("__SQLI_MEDIUM__", by_confidence["Medium"])
            .replace("__SQLI_HIGH__", by_confidence["High"])
        )["choices"][0]["message"]["content"]
    )
    correlated, _ = synthesize.collect(
        synth, [f["finding_id"] for f in findings]
    )
    usage = screening.LlmUsage(calls=1, prompt_tokens=1873, completion_tokens=291)
    artifact = join.build_artifact(
        run, bundles, findings, correlated,
        screening.run_metadata(screening.MODEL, usage, 1),
    )

    jsonschema.validate(artifact, schema)
    assert artifact["summary"]["llm_evaluated_findings"] == 2
    assert artifact["summary"]["agreement"]["both"] == 1
    assert artifact["summary"]["agreement"]["deterministic-only"] == 1
    assert artifact["summary"]["correlated_synthesis_findings"] == 1


def test_summary_counts_reconcile_with_the_scan_report(schema, run, bundles):
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(run, bundles, findings, [], None)
    summary = artifact["summary"]
    # Nothing may be lost in the collapse: every raw ZAP alert has to end up
    # inside exactly one finding.
    assert summary["raw_alerts"] == run.zap_report["alert_count"]
    assert summary["raw_alerts"] == sum(
        f["alert"]["instances"] for f in artifact["findings"]
    )
    assert sum(summary["alerts_by_join_tier"].values()) == summary["raw_alerts"]


def test_schema_rejects_an_unknown_join_tier(schema, run, bundles):
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(run, bundles, findings, [], None)
    artifact["findings"][0]["static_context"] = "guessed"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(artifact, schema)


def test_schema_rejects_a_correlated_finding_pretending_to_be_zap_derived(
    schema, run, bundles
):
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(
        run, bundles, findings,
        [{"finding_id": "c-1", "origin": "zap", "title": "t", "severity": "high",
          "confidence": "high", "reasoning": "r", "supporting_finding_ids": []}],
        None,
    )
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(artifact, schema)
