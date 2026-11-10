"""Check the produced AI-context artifact against its documented schema.

The artifact is the contract between Phase 2 (produce) and Phase 3 (the LLM
correlation pass that consumes it). Validating here means the schema cannot
silently drift away from what `noir_runner` actually writes.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import jsonschema
import pytest

from dast_orchestrator.adapters.noir_runner import build_ai_context_artifact, parse_endpoints

SCHEMA = Path(__file__).resolve().parents[2] / "schemas" / "noir-ai-context.schema.json"
FIXTURE = FIXTURES_DIR / "noir-gitea-sample.json"


@pytest.fixture
def schema() -> dict:
    return json.loads(SCHEMA.read_text())


def test_schema_is_itself_valid(schema):
    jsonschema.Draft202012Validator.check_schema(schema)


def test_generated_artifact_validates(schema):
    endpoints = parse_endpoints(json.loads(FIXTURE.read_text()))
    artifact = build_ai_context_artifact(endpoints, Path("/src"), "20260817T114501Z")
    jsonschema.validate(artifact, schema)


def test_schema_rejects_a_bad_timestamp(schema):
    endpoints = parse_endpoints(json.loads(FIXTURE.read_text()))
    artifact = build_ai_context_artifact(endpoints, Path("/src"), "2026-08-17")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(artifact, schema)
