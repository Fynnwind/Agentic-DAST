"""`docs/TARGETS.md` is pinned to the Target dataclass.

A target is the one thing this project claims needs no code to add, so its
reference page is the interface. Several fields — `code_context`, `spiders`,
`noir_ignore_technologies`, `structural_parameters`, `openapi` — existed with
nothing outside their docstrings describing them, which is how a "just add a
directory" claim quietly becomes "read the loader".
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from dast_orchestrator.adapters import targets

DOC = Path(__file__).resolve().parents[2] / "docs" / "TARGETS.md"

#: Fields whose YAML key differs from the dataclass attribute, because the file
#: groups them (`zap_context.structural_parameters`, `zap_scan.rules`).
YAML_KEY = {
    "structural_parameters": "structural_parameters",
    "scan_rules": "zap_scan",
    "max_rule_minutes": "max_rule_minutes",
    "openapi_specs": "openapi",
}


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.is_file(), f"{DOC} is missing"
    return DOC.read_text()


def test_every_target_field_is_documented(text):
    for field in dataclasses.fields(targets.Target):
        key = YAML_KEY.get(field.name, field.name)
        assert key in text, (
            f"target.yml field {key!r} is not in docs/TARGETS.md — a field "
            f"nothing outside the loader describes is one nobody can use")


def test_every_auth_field_is_documented(text):
    for field in dataclasses.fields(targets.AuthProfile):
        assert field.name in text, f"auth.{field.name} is undocumented"


def test_the_scan_rule_vocabularies_are_the_ones_zap_accepts(text):
    """A typo in an enum is silently ignored by the daemon, so both are pinned."""
    for value in targets.ATTACK_STRENGTHS:
        assert value in text or value.lower() in text, f"strength {value}"
    for value in targets.ALERT_THRESHOLDS:
        assert value in text or value.lower() in text, f"threshold {value}"


def test_the_document_states_that_zap_has_no_per_rule_timer(text):
    """The one thing a reader will look for and not find in the API.

    Offering a per-rule `max_minutes` would be a promise this tool cannot keep,
    so the absence has to be explained rather than left to be discovered.
    """
    assert "no per-rule time limit" in text
    assert "MaxRuleDurationInMins" in text


def test_the_document_states_the_max_rule_minutes_precedence(text):
    """Four sources, and getting the order wrong makes a sheet's rows differ."""
    for source in ("--max-rule-minutes", "SCAN_ZAP_MAX_RULE_MINUTES",
                   "zap_scan.max_rule_minutes"):
        assert source in text
