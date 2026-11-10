"""The two ground-truth schemas describe already-frozen artifacts (§T3.0).

`cve-markers.schema.json` and `cve-detection.schema.json` are NOT wired into any
stage writer — they document the shape the analyzer vendors and are validated
here, against the real marker files and a generated assessment, so the corpus and
the frozen pipeline stay untouched (§N7-safe). → docs/DETECTABILITY.md.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
import yaml

from dast_orchestrator.foundation import run_paths, schema
from dast_orchestrator.stages import ground_truth as gt

SCHEMAS = schema.SCHEMAS_DIR
TARGETS = ("gitea", "wordpress", "grafana", "cacti")


def _validator(name: str):
    doc = json.loads((SCHEMAS / name).read_text())
    jsonschema.validators.validator_for(doc).check_schema(doc)  # the schema itself
    return jsonschema.validators.validator_for(doc)(doc)


def test_both_schemas_are_valid_json_schemas():
    _validator("cve-markers.schema.json")
    _validator("cve-detection.schema.json")


@pytest.mark.parametrize("target", TARGETS)
def test_every_marker_file_conforms(target):
    v = _validator("cve-markers.schema.json")
    doc = yaml.safe_load(gt.markers_path(target).read_text())
    errors = sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)


@pytest.mark.parametrize("target", TARGETS)
def test_a_generated_assessment_conforms(target, tmp_path):
    # Build a minimal run and assess it, then validate the artifact the writer
    # actually produces against the schema — the shape the analyzer will read.
    rid = f"20260101T000000Z-{target}-aaaaaa"
    layout = run_paths.RunLayout(tmp_path, rid).ensure()
    layout.path(run_paths.ZAP_ALERTS).write_text('{"alerts": [], "auth_mode": "user"}')
    layout.path(run_paths.TRIAGE).write_text('{"findings": []}')
    layout.path(run_paths.VERIFICATION).write_text('{"verifications": []}')
    result = gt.assess_run(gt.MarkerSet.load(target), layout)

    v = _validator("cve-detection.schema.json")
    errors = sorted(v.iter_errors(result), key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(f"{list(e.absolute_path)}: {e.message}" for e in errors)


def test_the_schema_pins_the_current_version():
    doc = json.loads((SCHEMAS / "cve-detection.schema.json").read_text())
    assert doc["properties"]["schema_version"]["const"] == 3
