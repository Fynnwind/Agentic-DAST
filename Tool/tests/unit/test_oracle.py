"""Oracle-guided mode: the rules that keep a ceiling from becoming a rubber stamp.

`--ceiling` hands every LLM stage the target's documented vulnerabilities and
measures what the pipeline still confirms. The number is an upper bound on what
this architecture could detect WITH prior knowledge — never a detection rate,
and never in the same table as a blind run.

Three things make that number worth having, and each is asserted here rather
than trusted:

* the oracle document is prose about the *application*, and never the
  measurement join — handing over `cve-markers.yml`'s `zap_rules` would measure
  whether a model can copy the answer key;
* every stage reads the SAME facts and gets its own instruction, so a stage's
  ceiling does not depend on how well its own briefing was worded;
* every instruction is also a *restraint*, because a model told a bug exists and
  nothing else confirms everything it is shown.
"""

from __future__ import annotations

import re

import pytest

from dast_orchestrator.analysis import oracle
from dast_orchestrator.adapters import targets


def test_the_oracle_is_never_the_measurement_join():
    """`cve-markers.yml` carries the rule ids the detection join uses.

    Checked mechanically because "we would never do that" is exactly what a
    later edit forgets — and the failure would be silent, producing a ceiling
    that measures transcription.
    """
    targets.load_all()
    seen = 0
    for name in sorted(targets.REGISTRY):
        text = oracle.load(targets.get(name))
        if text is None:
            continue
        seen += 1
        assert "zap_rules" not in text, f"{name}: names the join's own field"
        assert "cve-markers.yml" in text, (
            f"{name}: must say which file the measurement join lives in, so a "
            "later editor does not merge the two"
        )
        # Must say when it is read — in oracle-guided mode. Accept either flag
        # spelling during the `--ceiling` -> `--oracle` transition: `--ceiling`
        # is the dead alias the older files still carry (a §R2 doc-sweep item),
        # `--oracle` is the working flag a new file uses.
        assert ("--oracle" in text) or ("--ceiling" in text), (
            f"{name}: must say when it is read"
        )
        # No bare ZAP plugin ids. Four or five digits standing alone is what a
        # rule id looks like; version numbers and years are excluded by shape.
        stripped = re.sub(r"\b(?:3\.2\.\d+|5\.8\.\d+|1\.16\.\d+|20\d\d)\b", "", text)
        bare = re.findall(r"(?<![\w.\-/])\d{4,5}(?![\w.\-/])", stripped)
        assert not bare, f"{name}: bare numeric id(s) {bare} read as ZAP rule ids"
    assert seen, "no target has an oracle document — this test would pass vacuously"


def test_every_stage_that_can_be_given_the_oracle_has_its_own_restraint():
    """An instruction that only hands over the answer measures agreement.

    The failure mode of this mode is a model that stops analysing and starts
    confirming: the ceiling reads high and the number means nothing. Every
    instruction must therefore end by saying what the knowledge does NOT
    license.
    """
    assert set(oracle.STAGE_PROMPTS) == set(oracle.STAGES)
    for stage in oracle.STAGES:
        text = oracle.instruction(stage).text
        assert "does NOT license" in text or "does not license" in text, (
            f"{stage}: no restraint — an instruction that only hands over the "
            "answer measures agreement, not detection"
        )
        assert "already defended" in text, (
            f"{stage}: no mention of the documented-but-already-fixed items. "
            "They are the mode's own control: a run that confirms them measured "
            "compliance rather than detection"
        )


def test_the_oracle_instructions_are_files_not_string_constants():
    """They are sent verbatim to a model, so a silent edit changes a result.

    They began as string constants in `oracle.py`, where a reworded briefing
    would have changed what a stored ceiling measured with nothing in the
    artifact to say so. They are **unversioned** (generic scaffolding, not an A/B
    axis, unlike the pass prompts), so they live in `ORACLE_BLOCKS` and load by
    bare filename with `load_oracle`.
    """
    from dast_orchestrator.foundation import prompts

    for stage, name in oracle.STAGE_PROMPTS.items():
        assert name in prompts.ORACLE_BLOCKS, f"{name} is not a declared oracle block"
        assert prompts.load_oracle(name).text, f"no {name}.md on disk"
    targets.load_all()
    block = oracle.block(targets.get("gitea"), "screening")
    assert block["instruction_prompt"] == "oracle-screening"


def test_each_stages_block_carries_the_shared_facts_and_its_own_instruction():
    """Same evidence, different job. Three briefings would measure the briefings."""
    targets.load_all()
    gitea = targets.get("gitea")
    blocks = {stage: oracle.block(gitea, stage) for stage in oracle.STAGES}

    facts = {b["known_vulnerabilities"] for b in blocks.values()}
    assert len(facts) == 1, "every stage must read the SAME source of truth"
    instructions = {b["how_to_use_it_here"] for b in blocks.values()}
    assert len(instructions) == len(oracle.STAGES), "per-stage instruction"
    for block in blocks.values():
        assert "ceiling" in block["what_this_is"], (
            "every block must say what the run is measuring, in the block "
            "itself — the artifact's own label is not in front of the model"
        )


def test_a_ceiling_run_against_a_target_with_no_oracle_is_refused():
    """Silently running blind and filing it as a ceiling is the one bad outcome."""
    nowhere = targets.Target(name="no-such-target", base_url="http://x",
                             source_dir="x")
    assert oracle.load(nowhere) is None
    assert oracle.block(nowhere, "screening") is None
    with pytest.raises(oracle.OracleError, match="no oracle document"):
        oracle.require(nowhere)


def test_an_unknown_stage_is_refused_rather_than_silently_unbriefed():
    """A typo would strip the instruction and leave the facts.

    That is the one shape of this block that teaches a model nothing except to
    agree, so it fails loudly instead.
    """
    targets.load_all()
    with pytest.raises(oracle.OracleError, match="unknown oracle stage"):
        oracle.block(targets.get("gitea"), "triage-pass-1")


def test_the_ceiling_switch_reaches_both_stages_that_read_it():
    """A run where triage knew the answer and verification did not is neither.

    One env variable, two stages, same `dest` — which is also what lets a
    harness sheet set it at all (`config.STAGE_FLAGS` is the join key).
    """
    from dast_orchestrator.foundation import config

    assert config.STAGE_FLAGS["triage"]["oracle"] == "SHARED_ORACLE"
    assert config.STAGE_FLAGS["verify"]["oracle"] == "SHARED_ORACLE"


def test_the_oracle_block_leads_the_payload_it_rides_in():
    """It is what the model should read before the evidence, and it is stable.

    Byte-identical across every call of a run, so first in the payload also
    extends the cacheable prefix instead of sitting behind the one part that
    changes per endpoint.
    """
    from dast_orchestrator.analysis import screening
    from dast_orchestrator.analysis import synthesize
    from dast_orchestrator.analysis.join import Bundle

    targets.load_all()
    block = oracle.block(targets.get("gitea"), "screening")
    bundle = Bundle(endpoint_key="GET /x", match_how="seed", method="GET", path="/x")

    payload = screening.build_user_payload(bundle, [], oracle=block)
    assert next(iter(payload)) == "known_vulnerabilities_of_this_target"
    # …and it is absent entirely from a blind run, not present-and-empty.
    assert "known_vulnerabilities_of_this_target" not in \
        screening.build_user_payload(bundle, [])

    corpus = synthesize.build_corpus([bundle], [], {}, oracle=block)
    assert next(iter(corpus)) == "known_vulnerabilities_of_this_target"
    assert "known_vulnerabilities_of_this_target" not in \
        synthesize.build_corpus([bundle], [], {})


def test_a_blind_verification_loop_is_never_told_what_triage_concluded():
    """The anti-circularity invariant, and it is not negotiable in a blind run.

    Verification exists to check triage independently; a prober handed the
    hypothesis it is meant to test tests the hypothesis, not the application.
    Asserted at the *call site's* shape too — `build_context` drops
    `earlier_triage` unless the oracle block is present, so a caller passing one
    by mistake cannot quietly make a blind run circular.
    """
    from dast_orchestrator.analysis import verify_loop

    finding = {
        "finding_id": "f-1", "alert": {"name": "n", "plugin_id": "40026"},
        "deterministic": {"needs_rescan": True},
        "llm": {"verdict": "likely-true-positive", "needs_rescan": True,
                "reasoning": "the handler echoes it raw"},
    }
    task = verify_loop.build_context(
        finding, earlier_triage=verify_loop.triage_view(finding))

    assert "earlier_triage" not in task
    for leaked in ("likely-true-positive", "echoes it raw"):
        assert leaked not in str(task), (
            f"{leaked!r} reached a blind verification task — the loop is meant "
            "to check triage independently, not to be told its answer")


def test_a_ceiling_run_hands_triage_over_deliberately_and_says_what_that_costs():
    """The one exception, and the mode pays for it in what its numbers mean.

    `--ceiling` asks how much this pipeline can confirm when NOTHING is withheld
    from it, so withholding triage would be measuring the wrong thing. The
    price is that a ceiling run's verification is not independent of its own
    triage — which the prompt must say out loud, because a reader of the
    artifact would otherwise apply the blind run's guarantees to it.
    """
    from dast_orchestrator.analysis import verify_loop

    targets.load_all()
    block = oracle.block(targets.get("wordpress"), "verify")
    finding = {
        "finding_id": "f-1", "alert": {"name": "n", "plugin_id": "40026"},
        "deterministic": {"needs_rescan": True},
        "llm": {"verdict": "likely-true-positive", "needs_rescan": True,
                "reasoning": "the handler echoes it raw"},
    }
    task = verify_loop.build_context(
        finding, oracle=block, earlier_triage=verify_loop.triage_view(finding))

    assert task["known_vulnerabilities_of_this_target"] == block
    assert task["earlier_triage"]["pass1_verdict"] == "likely-true-positive"
    assert task["earlier_triage"]["deterministic_flagged_for_rescan"] is True
    assert "no longer independent" in block["how_to_use_it_here"], (
        "the verify prompt must state that this mode gives up independence — "
        "it is the reason a ceiling number cannot sit beside a blind one")


def test_a_finding_triage_never_answered_carries_no_clean_bill_of_health():
    """"Asked and unanswered" and "judged fine" must not look alike."""
    from dast_orchestrator.analysis import verify_loop

    unanswered = verify_loop.triage_view(
        {"llm_asked": True, "llm": None, "deterministic": {"needs_rescan": False}})
    assert unanswered["pass1_verdict"] == "asked-but-unanswered"
    # A finding neither arm touched carries no block at all, rather than an
    # empty one that would read as a verdict.
    assert verify_loop.triage_view({"llm": None, "deterministic": {}}) is None
