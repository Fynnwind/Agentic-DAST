"""Every model this pipeline can run is pinned to one fixed set of weights.

The invariant is in `.claude/CLAUDE.md` and it is the one axis the thesis cannot
afford to lose: a re-run whose weights moved underneath it is not a
reproduction, and two runs compared across a silent model update are not a
comparison. It applies to *every* slot — triage, synthesis (each ensemble member
included), and the verification loop.

Until now it was a convention someone had to remember. This walks the actual
defaults and the committed env files, so a floating alias cannot be introduced
without a test saying so.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dast_orchestrator.foundation import config
from dast_orchestrator.analysis import screening
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.analysis import verify_loop

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Every model slot's compiled-in default, by the name a reader would look for.
DEFAULTS = {
    "triage (screening.MODEL)": screening.MODEL,
    "synthesis (synthesize.SYNTHESIS_MODEL)": synthesize.SYNTHESIS_MODEL,
    "verification loop (verify_loop.VERIFY_MODEL)": verify_loop.VERIFY_MODEL,
}

#: The env variables that name a model, so a committed configuration is checked
#: as well as the code defaults — a run takes whichever of the two is set, and
#: the file is the one that actually gets edited between experiments.
MODEL_VARS = (
    "TRIAGE_SCREENING_MODEL",
    "TRIAGE_SYNTHESIS_MODEL",
    "VERIFY_MODEL",
)


@pytest.mark.parametrize("slot,model_id", sorted(DEFAULTS.items()))
def test_every_compiled_in_default_is_pinned(slot, model_id):
    assert screening.is_pinned(model_id), (
        f"{slot} = {model_id!r} is a floating alias or an unverified undated id. "
        "Pin it to a dated snapshot, or — if the provider offers none — look the "
        "id up in OpenRouter's model list and add it to "
        "screening.CATALOGUE_CHECKED with the date you checked."
    )


@pytest.mark.parametrize("env_file", ["config/scanner/.env",
                                      "config/scanner/default.env"])
def test_every_committed_configuration_is_pinned(env_file):
    values = config.parse_env_file(REPO_ROOT / env_file)
    checked = 0
    for var in MODEL_VARS:
        model_id = (values.get(var) or "").strip()
        if not model_id:          # empty means "fall back", not "float"
            continue
        checked += 1
        assert screening.is_pinned(model_id), \
            f"{env_file}: {var}={model_id!r} is not a pinned id"
    # A configuration file that named no model at all would pass vacuously, and
    # that is exactly how the five variables drifted out of it unnoticed once.
    assert checked, f"{env_file} names no model at all"


def test_a_synthesis_ensemble_member_is_held_to_the_same_rule():
    """TRIAGE_SYNTHESIS_MODELS is a comma-separated list, and each entry is a slot.

    An ensemble is the easiest place for a floating alias to hide: it is a list
    in a config file rather than a named constant, and its members are only ever
    read in bulk.
    """
    values = config.parse_env_file(REPO_ROOT / "config/scanner/.env")
    members = [m.strip() for m in (values.get("TRIAGE_SYNTHESIS_MODELS") or "").split(",")]
    for model_id in (m for m in members if m and m.lower() != config.SENTINEL_NONE):
        assert screening.is_pinned(model_id), \
            f"TRIAGE_SYNTHESIS_MODELS member {model_id!r} is not pinned"


def test_the_shapes_openrouter_uses_to_mark_a_moving_target_are_refused():
    assert not screening.is_pinned("~deepseek/deepseek-v4-flash-latest")
    assert not screening.is_pinned("openai/gpt-5-latest")
    # A bare family name follows that family's newest release. Shape cannot tell
    # it from a snapshot's stem, which is why an undated id needs a recorded
    # catalogue check rather than a cleverer regex.
    assert not screening.is_pinned("deepseek/deepseek-v4-flash")
    assert screening.is_pinned("deepseek/deepseek-v4-flash-0731")


def test_every_date_shape_this_catalogue_uses_counts_as_a_snapshot():
    """A dated id is pinned however the provider punctuates the date.

    The dashed ISO form was missing until 2026-09-04, so
    `qwen/qwen-plus-2025-07-28` — the model sheet 01 compared against — read as
    unpinned. The failure was conservative (a real snapshot refused, never a
    moving target accepted), but it would have kept a pinned model out of a
    committed configuration for a punctuation reason.
    """
    assert screening.is_pinned("deepseek/deepseek-v4-flash-0731")     # MMDD
    assert screening.is_pinned("anthropic/claude-haiku-4-5-20251001") # ISO
    assert screening.is_pinned("qwen/qwen-plus-2025-07-28")           # dashed
    # Still not a date: a version tag that merely ends in digits.
    assert not screening.is_pinned("minimax/minimax-m2")


def test_an_undated_id_passes_only_with_a_recorded_check_behind_it():
    """The evidence is stored, not re-derived. Re-checking is a lookup."""
    assert "minimax/minimax-m2.5" in screening.CATALOGUE_CHECKED
    assert not screening.is_pinned("minimax/minimax-m2.9")   # never checked
