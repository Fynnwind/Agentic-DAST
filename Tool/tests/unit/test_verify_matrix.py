"""The det x llm resolution matrix, and the floor underneath it.

Every reported verification verdict in this project passes through
:func:`~dast_orchestrator.domain.verification.resolve_verdict`, so the table below is
the layer's contract in executable form. Two properties are load-bearing for the
thesis and are asserted directly rather than left to the cells:

* a reported ``confirmed`` always has tool machinery behind it — the model can
  raise doubt freely but can never manufacture a confirmation;
* a tool that did not validly run produces no verdict at all, whatever either
  reader says about it.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.domain import verification
from dast_orchestrator.domain import verification as v
from dast_orchestrator.domain.verification import (
    AGREE,
    CONFIRMED,
    FLAGGED,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
)


# wrapper, model, reported, agreement
MATRIX = [
    (CONFIRMED,    CONFIRMED,    CONFIRMED,    AGREE),
    (CONFIRMED,    REFUTED,      REFUTED,      FLAGGED),   # model catches a tool FP
    (CONFIRMED,    INCONCLUSIVE, INCONCLUSIVE, FLAGGED),
    (REFUTED,      CONFIRMED,    INCONCLUSIVE, FLAGGED),   # no upgrade
    (REFUTED,      REFUTED,      REFUTED,      AGREE),
    (REFUTED,      INCONCLUSIVE, INCONCLUSIVE, FLAGGED),
    (INCONCLUSIVE, CONFIRMED,    INCONCLUSIVE, FLAGGED),   # no upgrade
    (INCONCLUSIVE, REFUTED,      REFUTED,      FLAGGED),
    (INCONCLUSIVE, INCONCLUSIVE, INCONCLUSIVE, AGREE),
]


@pytest.mark.parametrize("wrapper,model,reported,agreement", MATRIX)
def test_the_matrix(wrapper, model, reported, agreement):
    assert v.resolve_verdict(wrapper, model, ran=True) == (reported, agreement)


@pytest.mark.parametrize("model", [CONFIRMED, REFUTED, INCONCLUSIVE])
@pytest.mark.parametrize("wrapper", [CONFIRMED, REFUTED, INCONCLUSIVE, NOT_ATTEMPTED])
def test_a_tool_that_did_not_run_is_never_rescued(wrapper, model):
    """The integrity floor. A non-run is not a verdict, and no reading changes that."""
    reported, _ = v.resolve_verdict(wrapper, model, ran=False)
    assert reported == wrapper


def test_a_reported_confirmation_always_has_tool_machinery_behind_it():
    """The single property that keeps `confirmed` worth the word.

    Exhaustive rather than by example: if any (wrapper, model, ran) combination
    could produce a reported `confirmed` without the wrapper also reading one,
    every confirmation count in the thesis would rest on the model's say-so.
    """
    for wrapper in (*v.OUTCOMES, None):
        for model in (*v.LLM_CATEGORIES, None):
            for ran in (True, False):
                reported, _ = v.resolve_verdict(wrapper, model, ran)
                if reported == CONFIRMED:
                    assert wrapper == CONFIRMED, (wrapper, model, ran)


def test_no_model_reading_leaves_the_wrapper_as_the_verdict():
    """The fully-deterministic configuration, and a model that never answered."""
    for wrapper in v.OUTCOMES:
        assert v.resolve_verdict(wrapper, None, ran=True) == (wrapper, AGREE)


def test_agreement_compares_the_two_readings_not_the_reported_one():
    """`flagged` means the readers differed — including where the model won.

    The cell where the wrapper confirmed and the model refuted REPORTS the
    model's category, and it is still a disagreement. Counting agreement against
    the reported verdict instead would silently score every such case as
    consensus and make the audit rate meaningless.
    """
    reported, agreement = v.resolve_verdict(CONFIRMED, REFUTED, ran=True)
    assert reported == REFUTED and agreement == FLAGGED


# -- the non-run predicate --------------------------------------------------


def test_tool_ran_reads_the_wrapper_s_own_flag():
    assert v.tool_ran({"outcome": REFUTED, "tested": True}) is True
    assert v.tool_ran({"outcome": INCONCLUSIVE, "tested": False}) is False


def test_a_timeout_never_counts_as_work_done():
    assert v.tool_ran({"outcome": INCONCLUSIVE, "tested": True,
                       "timed_out": True}) is False


def test_a_not_attempted_dispatch_never_counts_as_work_done():
    assert v.tool_ran({"outcome": NOT_ATTEMPTED}) is False
    assert v.tool_ran({}) is False


def test_records_written_before_the_flag_existed_still_read_correctly():
    """Backwards compatibility, and it is the *refutations* that depend on it.

    A stored artifact from before the wrappers said `tested` must not have its
    warning-qualified inconclusives read as work done — that is precisely the
    class that would otherwise be promotable to a refutation.
    """
    assert v.tool_ran({"outcome": REFUTED}) is True
    assert v.tool_ran({"outcome": INCONCLUSIVE}) is True          # ran, ambiguous
    assert v.tool_ran({"outcome": INCONCLUSIVE,
                       "tool_warnings": ["comparison unstable"]}) is False


# -- the declared signal must survive every refactor ----------------------


def test_the_response_schema_requires_a_declared_signal():
    """The pre-commitment is not optional, and leaving it so loses it silently.

    Stating what would be observed if the finding were real — *before* the tool
    runs — is this stage's novel methodological contribution: it is the only
    thing that makes a round falsifiable rather than a narration of whatever
    came back. The 2026-09-02 rebuild dropped `declared_signal` from the
    schema's `required` list where the schema it replaced had it, and the first
    live run declared a signal on **not one round**. Nothing failed; every
    verdict still looked reasonable. That is the failure mode this test exists
    for.
    """
    from dast_orchestrator.analysis import verify_loop

    assert "declared_signal" in verify_loop.ROUND_SCHEMA["required"]
    assert "tool" in verify_loop.ROUND_SCHEMA["required"]


def test_a_round_that_declares_nothing_is_counted_not_tolerated():
    from dast_orchestrator.analysis import verify_loop

    def r(i, observed, outcome, model_directed=True):
        return verification.RoundRecord(
            i, "sqlmap", {}, {}, {"observed": observed}, outcome,
            model_directed=model_directed)

    counts = verify_loop.signal_counts([
        r(1, None, REFUTED),
        r(2, True, CONFIRMED),
        # The chain-of-verification catch: the tool refuted, the model's
        # declared signal appeared anyway. The one a human should actually read.
        r(3, True, REFUTED),
        r(4, False, REFUTED),
    ])
    assert counts == {"matched": 1, "absent": 1, "contradiction": 1,
                      "not_declared": 1, "not_checkable": 0}


def test_a_deterministic_round_is_not_the_model_declining_to_predict():
    """"Was not asked" and "would not answer" must not share a column.

    The fully-deterministic control makes no prediction because nothing was
    asked to make one. Counting its rounds as undeclared signals put 30 of them
    into the column that measures whether the MODEL commits to anything, on the
    first live run.
    """
    from dast_orchestrator.analysis import verify_loop

    deterministic = verification.RoundRecord(
        1, "sqlmap", {}, {}, {"observed": None}, REFUTED, model_directed=False)
    assert verify_loop.signal_counts([deterministic]) == {
        "matched": 0, "absent": 0, "contradiction": 0, "not_declared": 0,
        "not_checkable": 0}


def test_the_model_is_told_which_nuclei_tags_exist():
    """A capability block that omits the vocabulary invites invented values.

    Measured 2026-09-03 on a baseline run: told only that it *may* narrow by
    tag, the model proposed `format-string`, `misc` and `fuzz` — none of which
    match a template in the pinned DAST set. nuclei loaded nothing, exited in
    under a second, and 6 of 25 probes tested nothing at all. The block already
    tells the model what sqlmap needs; the same duty applies here.
    """
    nuclei = v.TOOL_CAPABILITIES["nuclei"]
    assert "tags" in nuclei
    for real in ("xss", "ssti", "sqli", "redirect", "csp-bypass"):
        assert real in nuclei["tags"]
    # ...and it says what happens when the tag is not one of them, because the
    # failure is silent: nuclei warns, exits 0-ish, and tests nothing.
    assert "matches NOTHING" in nuclei["tags"]
    for invented in ("format-string", "misc"):
        assert invented not in nuclei["tags"]


# -- dispatch order: spend the budget where a tool can settle something -----


def _f(fid, risk="High", source="", det=True, llm=False):
    return {"finding_id": fid,
            "alert": {"risk": risk, "source": source},
            "deterministic": {"needs_rescan": det},
            "llm": {"needs_rescan": llm}}


def test_an_attack_backed_finding_outranks_a_passive_hint():
    """The measured problem, in one assertion.

    On the 2026-09-03 Gitea baseline 9 of 16 probes went to rule 10031 — a
    passive rule meaning a parameter value APPEARS in an HTML attribute, a hint
    of XSS rather than an observation of one — while 17 findings fell off the
    budget and only 4 probes reached rules that had actually injected. An
    independent tool can reproduce an attack; it cannot reproduce an
    observation, because there was never an attack to repeat.
    """
    passive = _f("f-hint", source="passive-scanner")
    active = _f("f-real", source="active-scanner")
    assert v.dispatch_priority(active) < v.dispatch_priority(passive)


def test_risk_still_outranks_provenance():
    """A High-risk passive finding still matters more than a Low-risk active one.

    Provenance breaks ties WITHIN a risk band, which is where the 10031 flood
    lives — it does not reorder the risk ladder itself.
    """
    high_passive = _f("f-a", risk="High", source="passive-scanner")
    low_active = _f("f-b", risk="Low", source="active-scanner")
    assert v.dispatch_priority(high_passive) < v.dispatch_priority(low_active)


def test_an_unknown_source_sorts_later_rather_than_dropping_out():
    """The cautious direction: the cost of being wrong is a probe, not a finding.

    Findings from before `source` was carried have none, and they must still be
    dispatchable.
    """
    unknown = _f("f-old", source="")
    active = _f("f-new", source="active-scanner")
    assert v.dispatch_priority(active) < v.dispatch_priority(unknown)
    assert not v.is_attack_backed(unknown)


def test_the_tiebreak_is_still_stable():
    """Without it, two runs dispatch the same budget in a different order and
    disagree about which findings fell off the cap."""
    a = _f("f-aaa", source="active-scanner")
    b = _f("f-bbb", source="active-scanner")
    assert v.dispatch_priority(a) < v.dispatch_priority(b)


def test_agreement_still_breaks_ties_within_one_provenance():
    both = _f("f-x", source="active-scanner", det=True, llm=True)
    one = _f("f-y", source="active-scanner", det=True, llm=False)
    assert v.dispatch_priority(both) < v.dispatch_priority(one)


# -- the declared signal is checked against the TARGET, not against us -----
#
# All four tests below are regressions on measured artefacts. Read by hand on
# 2026-09-05 across the 868 model-directed rounds of the sheet-10 corpus, the
# mechanism had recorded exactly one `matched` and five `contradiction`s, and
# every one of the six was an artefact of matching the wrong text. See
# `DECISIONS.md` §"The declared-signal mechanism was measuring our own
# prose".


def test_a_signal_is_not_matched_against_the_wrappers_own_verdict_prose():
    """Six confirmations of one finding, one `matched`, and the difference was wording.

    The browser oracle confirmed the WPDM `frameid` XSS on six separate rounds
    from identical output. `detail` reads "injected JavaScript EXECUTED in a
    real browser…", so the round where the model happened to predict
    `"script executed"` was scored `matched` and the five predicting the same
    fact in other words were scored `absent`. That is a measurement of our own
    vocabulary.
    """
    result = {
        "outcome": CONFIRMED,
        "evidence": "</script><script>document.title=/XSSLLJKSA397258/.source</script>",
        "detail": "injected JavaScript EXECUTED in a real browser: the payload "
                  "set document.title to this invocation's marker XSSLLJKSA397258.",
        "stdout_excerpt": "<html><head><title>XSSLLJKSA397258</title>",
        "command": "docker run --rm chromium --headless=new http://target/x?p=1",
    }
    signal = v.DeclaredSignal(expect=("script executed",),
                              require_tool_confirmed=True)
    assert v.check_signal(signal, result).observed is False

    # What the model should have predicted instead — something the *page* shows.
    real = v.DeclaredSignal(expect=("document.title",), require_tool_confirmed=True)
    assert v.check_signal(real, result).observed is True


def test_a_string_the_tool_echoes_from_its_own_command_is_not_evidence():
    """ffuf prints the matcher it was handed; expecting `root:` matched the request.

    Three of the corpus's four `contradiction` rounds are this shape: ffuf
    refuted, and the signal `expect: ["root:"]` was scored observed because
    ffuf's JSON leads with `"commandline":"ffuf … -mr root:.*:0:0: …"`.
    """
    result = {
        "outcome": REFUTED,
        "evidence": None,
        "detail": "no traversal payload read /etc/passwd via the final path segment",
        "stdout_excerpt": '{"commandline":"ffuf -w - -u http://t/avatar/FUZZ '
                          '-mr root:.*:0:0: -of json","results":[]}',
        "command": "docker run --rm secsi/ffuf:2.2.1 -w - -u "
                   "http://t/avatar/FUZZ -mr root:.*:0:0: -of json",
    }
    check = v.check_signal(v.DeclaredSignal(expect=("root:",)), result)
    assert check.code == v.SIGNAL_NOT_CHECKABLE
    assert check.observed is None


def test_a_rejection_on_its_own_can_never_be_an_observation():
    """An absent rejection is satisfied by a tool that found nothing at all."""
    result = {"outcome": REFUTED, "detail": "found nothing",
              "stdout_excerpt": '{"results":[]}', "command": "ffuf -u http://t"}
    check = v.check_signal(v.DeclaredSignal(reject=("image/png",)), result)
    assert check.code == v.SIGNAL_NOT_CHECKABLE
    # …but it still vetoes a positive half that would otherwise have held.
    guarded = v.DeclaredSignal(expect=("results",), reject=("image/png",))
    assert v.check_signal(guarded, result).observed is True
    present = {**result, "stdout_excerpt": '{"results":["image/png"]}'}
    assert v.check_signal(guarded, present).observed is False


def test_a_probe_that_never_ran_has_not_falsified_anything():
    """"We could not look" and "we looked and it was not there" are different.

    Fourteen budget-refused rounds — no tool, no output, nothing — sat in the
    `absent` column as though a prediction had been checked and failed. Same
    rule as every cost field in this project: a missing measurement and a
    measured zero must never look alike.
    """
    refused = {"outcome": NOT_ATTEMPTED, "detail": "budget: max dispatches reached"}
    check = v.check_signal(v.DeclaredSignal(expect=("root:x:0:0",)), refused)
    assert check.code == v.SIGNAL_NOT_CHECKABLE
    assert check.observed is None

    # A tool that ran but reported no observation at all — nuclei writes no
    # stdout on a refutation — is the same case: there is nothing to search.
    silent = {"outcome": REFUTED, "detail": "nuclei matched nothing",
              "stdout_excerpt": "", "command": "nuclei -u http://t -dast"}
    assert v.check_signal(
        v.DeclaredSignal(expect=("xss",)), silent).code == v.SIGNAL_NOT_CHECKABLE
    # …and `require_tool_confirmed` stays checkable there, because it reads the
    # outcome rather than the text.
    assert v.check_signal(
        v.DeclaredSignal(require_tool_confirmed=True), silent).observed is False


def test_a_round_that_could_not_be_checked_is_not_a_failed_prediction():
    from dast_orchestrator.analysis import verify_loop

    def r(code, outcome):
        return verification.RoundRecord(
            1, "nuclei", {}, {}, {"observed": None, "code": code}, outcome,
            model_directed=True)

    counts = verify_loop.signal_counts([
        r(v.SIGNAL_NOT_CHECKABLE, NOT_ATTEMPTED),
        r(v.SIGNAL_NOT_DECLARED, REFUTED),
    ])
    assert counts["not_checkable"] == 1
    assert counts["not_declared"] == 1
    assert counts["absent"] == 0


def test_the_verify_prompt_tells_the_model_what_its_signal_is_matched_against():
    """A pre-commitment checked against text the model cannot see is theatre.

    v1 said "substrings that must appear in the tool's output" and left the
    model to guess which fields those were; across the whole stored corpus it
    guessed wrong every time. The current prompt must name the substrate.
    """
    from dast_orchestrator.foundation import prompts

    text = prompts.load("verify").text
    assert "stdout_excerpt" in text and "evidence" in text
    assert "`detail`" in text


def test_a_word_from_the_tools_own_output_format_is_not_evidence():
    """The class `verify.v2` asked about in prose and the model walked into anyway.

    Sheet 13's first outing scored two `matched` signals. One was genuine; the
    other predicted `"matched"` against nuclei, whose result JSON carries
    `matched-at`. That string is present whenever nuclei matches ANYTHING, on
    any target, so it predicts nothing — the same shape as the command echo, one
    level down. A prompt alone could not close it: v1 already relied on the model
    guessing what the comparator searched, and it guessed wrong 868 times.
    """
    nuclei = {
        "outcome": CONFIRMED, "tool": "nuclei", "evidence": "cookie-injection",
        "command": "docker run --rm nuclei -u http://t -dast",
        "stdout_excerpt": '{"template-id":"cookie-injection",'
                          '"matched-at":"http://t?x=1","severity":"low"}',
    }
    only_format = v.check_signal(v.DeclaredSignal(expect=("matched",)), nuclei)
    assert only_format.code == v.SIGNAL_NOT_CHECKABLE
    assert "output format" in only_format.detail

    # A real template NAME is evidence — it says which class was reproduced.
    real = v.check_signal(v.DeclaredSignal(expect=("cookie-injection",)), nuclei)
    assert real.observed is True

    # A format word beside a genuine half does not poison it: the surviving
    # half is checked and the discarded term is named on the record.
    mixed = v.check_signal(
        v.DeclaredSignal(expect=("matched",), require_tool_confirmed=True), nuclei)
    assert mixed.observed is True
    assert "output format" in mixed.detail


def test_the_format_vocabulary_is_per_tool_and_never_a_union():
    """Discarding a term because ANOTHER tool's format has it loses a real one.

    `results` is ffuf's JSON key and meaningless there; on a browser probe it is
    ordinary page text and could be exactly what the model meant.
    """
    assert "results" in v.format_words("ffuf")
    assert "results" not in v.format_words("browser")
    assert v.format_words("browser") == frozenset(), (
        "the browser wrapper returns the rendered DOM — the target's own bytes, "
        "not a serialisation of a verdict — so it has no format words")
    assert v.format_words(None) == frozenset()
    assert v.format_words("some-future-tool") == frozenset()


def test_the_verify_prompt_names_the_output_format_class():
    from dast_orchestrator.foundation import prompts

    text = prompts.load("verify").text
    assert "output FORMAT" in text or "output format" in text
    assert "matched-at" in text, (
        "the prompt must name the actual field that caused this, not gesture at "
        "the class"
    )


def test_wrapper_command_forwards_interactsh_env_never_the_key(monkeypatch):
    """The verify wrappers must receive the run's interactsh/OOB config.

    They are stdio subprocesses the MCP SDK spawns with only a safe default
    environment, so a run's ``VERIFY_INTERACTSH_*`` overrides are dropped unless
    forwarded explicitly — the gap that made nuclei fall back to the container-
    name interactsh default, whose callback the target cannot resolve, so every
    in-pipeline OOB confirmation silently timed out. The API key must never ride
    along into a tool subprocess.
    """
    from dast_orchestrator.stages.verify import common

    monkeypatch.setenv("VERIFY_INTERACTSH_SERVER", "http://interactsh.local:8080")
    monkeypatch.setenv("VERIFY_INTERACTSH_DNS", "172.19.0.252")
    monkeypatch.setenv("SHARED_OPENROUTER_API_KEY", "sk-must-not-leak")

    cmd = common._wrapper_command("nuclei")

    assert cmd.env is not None
    assert cmd.env["VERIFY_INTERACTSH_SERVER"] == "http://interactsh.local:8080"
    assert cmd.env["VERIFY_INTERACTSH_DNS"] == "172.19.0.252"
    assert "SHARED_OPENROUTER_API_KEY" not in cmd.env
    assert not any("sk-must-not-leak" in str(val) for val in cmd.env.values())


# -- the class gate: confirmation REQUIRES an in-class match ----------------
#
# `class_gate` is the precondition applied where the verdict is formed (in
# `settle`), not a downstream revoke: a tool match confirms THIS finding only
# when it is in the flagged rule's class. Every other state — a different class,
# a match too unclassifiable to compare, or a rule whose own class cannot be
# named — is downgraded to inconclusive (the tool's reading stays in
# `wrapper_verdict`). The Gitea case (2026-10-26): a nuclei `cookie-injection`
# match "confirmed" ZAP rule 10031 (*potential XSS*).

_COOKIE_INJECTION = [{"template_id": "cookie-injection", "cwe": [],
                      "tags": ["reflected", "dast", "cookie", "injection", "vuln"]}]


def test_a_class_mismatch_confirmation_is_downgraded_to_inconclusive():
    # 10031 is XSS; the confirming template is cookie/injection — a mismatch.
    reported, extra = v.class_gate(
        CONFIRMED, "20", _COOKIE_INJECTION, rule_id="10031", tool="nuclei")
    assert reported == INCONCLUSIVE
    assert extra["classification"]["class"] == v.CLASS_MISMATCH
    assert extra["outcome_downgraded_from"] == CONFIRMED


def test_a_matching_confirmation_is_left_confirmed():
    # ZAP 10029 (Cookie Poisoning, CWE-565) confirmed by the same template is a
    # real, same-class confirmation: the gate records `match` and keeps it.
    reported, extra = v.class_gate(
        CONFIRMED, "565", _COOKIE_INJECTION, rule_id="10029", tool="nuclei")
    assert reported == CONFIRMED
    assert extra["classification"]["class"] == v.CLASS_MATCH
    assert "outcome_downgraded_from" not in extra


def test_an_unclassifiable_nuclei_match_no_longer_confirms():
    # Gap closed: a nuclei match whose template carries no CWE and no recognised
    # tag used to stay confirmed (the gate only revoked NAMEABLE mismatches).
    mystery = [{"template_id": "x", "cwe": [], "tags": ["misc"]}]
    reported, extra = v.class_gate(
        CONFIRMED, "20", mystery, rule_id="10031", tool="nuclei")
    assert reported == INCONCLUSIVE
    assert extra["classification"]["class"] == v.CLASS_UNKNOWN
    assert extra["outcome_downgraded_from"] == CONFIRMED


def test_an_unspecific_alert_confirmation_no_longer_silently_confirms():
    # Gap closed: a rule whose own class cannot be named (catch-all CWE, unknown
    # to the per-rule map) can no longer be confirmed on an unverifiable class.
    reported, extra = v.class_gate(
        CONFIRMED, "20", _COOKIE_INJECTION, rule_id="99999", tool="nuclei")
    assert reported == INCONCLUSIVE
    assert extra["classification"]["class"] == v.CLASS_UNSPECIFIC
    assert extra["outcome_downgraded_from"] == CONFIRMED


def test_a_single_class_tool_supplies_its_own_class():
    # ffuf/sqlmap/browser carry no matched_templates; the tool's identity IS the
    # class, so a traversal rule confirmed by ffuf is a MATCH, not "unknown" —
    # the Grafana CVE-2021-43798 confirmation must survive the gate.
    reported, extra = v.class_gate(
        CONFIRMED, None, None, rule_id="6", tool="ffuf")
    assert reported == CONFIRMED
    assert extra["classification"]["class"] == v.CLASS_MATCH
    assert extra["classification"]["tool_families"] == ["traversal"]
    # ...and ffuf against an XSS rule is a genuine mismatch.
    reported2, extra2 = v.class_gate(
        CONFIRMED, None, None, rule_id="10031", tool="ffuf")
    assert reported2 == INCONCLUSIVE
    assert extra2["classification"]["class"] == v.CLASS_MISMATCH


def test_command_injection_and_injection_families_agree():
    # The Cacti CVE-2022-46169 OOB confirmation: a cmdi template matching an
    # injection-classed rule. command-injection is a subtype of injection, so it
    # is a MATCH whether the alert carries CWE-78 or the (coarser) per-rule map
    # has to place it — the RCE confirmation must not hinge on the CWE field.
    cmdi = [{"template_id": "cmdi-blind-oast-polyglot", "cwe": [],
             "tags": ["cmdi", "oast", "dast", "blind", "rce", "vuln"]}]
    rep, extra = v.class_gate(CONFIRMED, "78", cmdi, rule_id="90037", tool="nuclei")
    assert rep == CONFIRMED and extra["classification"]["class"] == v.CLASS_MATCH
    rep2, extra2 = v.class_gate(CONFIRMED, None, cmdi, rule_id="90037", tool="nuclei")
    assert rep2 == CONFIRMED and extra2["classification"]["class"] == v.CLASS_MATCH


def test_a_non_confirmed_verdict_passes_the_gate_untouched():
    assert v.class_gate(REFUTED, "79", None, rule_id="40012") == (REFUTED, {})
    assert v.class_gate(INCONCLUSIVE, "79", None) == (INCONCLUSIVE, {})
