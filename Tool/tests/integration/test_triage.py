"""Unit tests for the triage driver's write guard.

Narrow on purpose: the guard exists because a `--no-llm` re-run once flattened a
completed two-arm artifact during Phase 3 development, discarding paid model
output that could only be recovered by paying for it again. The control arm is
free and instant; the LLM arm is neither. That asymmetry is the whole rule.
"""

from __future__ import annotations

import json

from dast_orchestrator.stages.triage import _would_discard_llm_results

WITH_LLM = {"llm": {"model": "deepseek/deepseek-v4-flash-0731"}, "findings": []}
WITHOUT_LLM = {"llm": None, "findings": []}


def test_control_arm_run_refuses_to_flatten_a_two_arm_artifact(tmp_path):
    path = tmp_path / "triage-20260817T114501Z.json"
    path.write_text(json.dumps(WITH_LLM))
    assert _would_discard_llm_results(path, WITHOUT_LLM) is True


def test_a_two_arm_run_may_overwrite_freely(tmp_path):
    path = tmp_path / "triage-20260817T114501Z.json"
    path.write_text(json.dumps(WITH_LLM))
    assert _would_discard_llm_results(path, WITH_LLM) is False


def test_overwriting_a_control_arm_artifact_is_fine(tmp_path):
    # Nothing of value is lost: the control arm can be recomputed for free.
    path = tmp_path / "triage-20260817T114501Z.json"
    path.write_text(json.dumps(WITHOUT_LLM))
    assert _would_discard_llm_results(path, WITHOUT_LLM) is False


def test_no_existing_file_is_not_a_conflict(tmp_path):
    assert _would_discard_llm_results(tmp_path / "nope.json", WITHOUT_LLM) is False


def test_an_unreadable_artifact_does_not_block_the_run(tmp_path):
    # A corrupt half-written file must not wedge the pipeline; there is no paid
    # output to protect if it cannot be parsed.
    path = tmp_path / "triage-20260817T114501Z.json"
    path.write_text("{ truncated")
    assert _would_discard_llm_results(path, WITHOUT_LLM) is False


# -- synthesis ensemble list parsing ---------------------------------------


def test_model_list_keeps_order_and_drops_duplicates():
    from dast_orchestrator.stages.triage import _model_list

    assert _model_list("a, b ,a") == ["a", "b"]
    assert _model_list("") == []


def test_provider_list_keeps_position_and_duplicates_for_matching():
    # A provider is matched to a model by POSITION, so unlike the model list this
    # keeps empties (a model on routing preference) and duplicates (two models on
    # one provider) — dropping either would misalign the pairing.
    from dast_orchestrator.stages.triage import _provider_list

    assert _provider_list("pa, ,pc") == ["pa", "", "pc"]
    assert _provider_list("p, p") == ["p", "p"]
    assert _provider_list("") == []
    assert _provider_list("   ") == []
