"""Unit tests for the deterministic rescan table (the control arm).

This arm is the baseline the LLM pass is measured against, so its behaviour has
to be pinned exactly: if the table quietly changes, every previously recorded
delta becomes uncomparable.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.domain import rescan_table
from dast_orchestrator.domain.rescan_table import RescanPolicy, decide, needs_rescan


def alert(plugin_id: str, confidence: str = "Medium", risk: str = "Medium") -> dict:
    return {"pluginId": plugin_id, "confidence": confidence, "risk": risk}


def test_sql_injection_is_always_rescanned_and_routed_to_sqlmap():
    decision = decide(alert("40018", "Medium", "High"))
    assert decision.needs_rescan is True
    assert decision.tool == "sqlmap"
    # High confidence must NOT downgrade an ALWAYS rule: 40018 is the case the
    # whole verification layer exists for.
    assert decide(alert("40018", "High", "High")).needs_rescan is True


def test_header_checks_are_never_rescanned():
    for plugin_id in ("10038", "10021", "10010", "10054"):
        decision = decide(alert(plugin_id, "High", "Low"))
        assert decision.needs_rescan is False
        assert decision.policy is RescanPolicy.NEVER


def test_when_uncertain_rules_respect_zap_confidence():
    # 30002 (format string). Both earlier exemplars stopped being
    # WHEN_UNCERTAIN on 2026-09-04: 40012 went to ALWAYS/browser because
    # reflection is not execution, and 40003 went to ALWAYS because it is a
    # ground-truth marker rule and a marker rule must not skip. 30002 is
    # neither, which is why it is the exemplar now.
    assert needs_rescan(alert("30002", "Medium", "High")) is True
    assert needs_rescan(alert("30002", "Low", "High")) is True
    assert needs_rescan(alert("30002", "High", "High")) is False
    # The reason must say *why* it was skipped, not just that it was.
    assert "already reports High confidence" in decide(alert("30002", "High")).reason


@pytest.mark.parametrize("plugin_id", ["40012", "40026"])
def test_xss_rules_go_to_an_execution_oracle_at_every_confidence(plugin_id):
    """Reflection and execution are different questions.

    40012 was WHEN_UNCERTAIN/nuclei, on the reasoning that at High confidence
    ZAP had already echoed its payload back so a rescan added nothing. Echoing
    back is a *reflection* oracle: measured 2026-09-04, a payload can be altered
    in transit (WordPress slash-adds quotes, defeating nuclei's verbatim
    matcher) and still execute. High confidence from a reflection-based rule is
    when an execution oracle earns its page load, not when it stops being
    needed.
    """
    for confidence in ("Low", "Medium", "High"):
        decision = decide(alert(plugin_id, "High", confidence))
        assert decision.needs_rescan is True
        assert decision.tool == "browser"


def test_noisy_but_unverifiable_rules_are_not_rescanned():
    # Timestamp disclosure is the loudest false-positive source in the Phase 2
    # run, but no external tool can adjudicate it — it belongs to the LLM arm.
    decision = decide(alert("10096", "Low", "Low"))
    assert decision.needs_rescan is False
    assert decision.tool is None


@pytest.mark.parametrize("confidence", ["Low", "Medium", "High"])
def test_an_unenumerated_rule_at_real_risk_escalates_whatever_the_confidence(confidence):
    """Changed 2026-08-28, and the old expectation was the bug.

    This test used to assert that an unknown rule at High risk and High
    confidence does NOT escalate — deferring to ZAP the way the table defers for
    rules it has judged. That deference is earned per rule and justified per
    rule; for a rule nobody has assessed it inverts, so the more confident the
    scanner is about something never judged, the less it gets verified.

    Rule 90035 (SSTI) took exactly that branch: High risk, High confidence, no
    row, "accept as reported", never dispatched — the corpus's single most
    severe finding, caught only because the LLM arm flagged it every run.
    """
    decision = decide(alert("99999", confidence, "High"))
    assert decision.in_table is False
    assert decision.needs_rescan is True
    assert "not a reason to skip" in decision.reason


def test_an_unenumerated_rule_at_low_risk_still_defers_to_confidence():
    """The change is scoped to risk that would matter, not to everything."""
    assert decide(alert("99999", "High", "Low")).needs_rescan is False
    assert decide(alert("99999", "Low", "Low")).needs_rescan is True


def test_unknown_informational_plugins_are_not_worth_the_budget():
    decision = decide(alert("99999", "Low", "Informational"))
    assert decision.in_table is False
    assert decision.needs_rescan is False


def test_missing_fields_do_not_crash_the_arm():
    # ZAP has returned alerts with an empty confidence before; the control arm
    # runs unattended in CI and must degrade rather than fail the job.
    decision = decide({})
    assert decision.in_table is False
    assert decision.confidence == "Low"


def test_every_rule_carries_a_rationale_for_the_writeup():
    for entry in rescan_table.RULES.values():
        assert len(entry.rationale) > 40, entry.plugin_id
        # A rule that says "rescan" without naming a tool cannot be dispatched
        # in Phase 4.
        if entry.policy is not RescanPolicy.NEVER:
            assert entry.tool, entry.plugin_id


def test_table_rows_are_ordered_for_the_appendix():
    ids = [int(row["plugin_id"]) for row in rescan_table.table_as_rows()]
    assert ids == sorted(ids)


def test_the_highest_severity_rule_in_the_corpus_is_enumerated():
    """90035 (SSTI) had no row until 2026-08-28.

    A table keyed on rule id silently ignores any rule nobody wrote down: the
    finding is not flagged, no tool is routed, and nothing anywhere says a
    decision was skipped rather than made. This one was High risk AND High
    confidence — the most severe finding in the corpus — and it was found only
    because the LLM arm flagged it in all six runs of sheet 5.
    """
    entry = rescan_table.RULES["90035"]
    assert entry.tool == "nuclei"
    assert rescan_table.needs_rescan(
        {"pluginId": "90035", "confidence": "High", "risk": "High"})


def test_an_unenumerated_rule_is_visibly_unjudged_not_quietly_declined():
    """The general form of the same defect, which the table still has.

    Adding 90035 fixes one instance. Any rule outside the table still returns a
    no-rescan answer indistinguishable from a considered one, so this pins the
    current behaviour as *known* rather than discovered again later.
    """
    assert "99999" not in rescan_table.RULES
    # Since 2026-08-28 it escalates rather than quietly declining, and the
    # decision says so in words a reader of the artifact can act on.
    decision = rescan_table.decide(
        {"pluginId": "99999", "confidence": "High", "risk": "High"})
    assert decision.needs_rescan is True
    assert decision.in_table is False
    assert "NOT in the table" in decision.reason


# -- ground truth must never be ruled out by the control arm ----------------


def _marker_rules() -> list[tuple[str, str, str]]:
    """``(target, marker id, zap rule)`` for every rule any marker names."""
    import yaml

    from dast_orchestrator.adapters import targets

    out = []
    for path in sorted(targets.TARGETS_DIR.glob(f"*/{targets.MARKERS_NAME}")):
        doc = yaml.safe_load(path.read_text())
        for marker in doc.get("markers") or []:
            for rule in marker.get("zap_rules") or []:
                out.append((path.parent.name, marker["id"], str(rule)))
    return out


def test_every_ground_truth_marker_rule_is_routed_at_every_confidence():
    """A marker rule the table declines makes the marker read as UNDETECTED.

    This is the expensive interaction, found by cross-check on 2026-09-04 with
    13 marker rules unenumerated. `ground_truth.assess_marker` reads the
    `+deterministic triage` layer straight off `deterministic.needs_rescan`, so
    a marker rule that is NEVER — or WHEN_UNCERTAIN meeting a High-confidence
    alert — drops that layer to "not detected". The scan found the CVE, the
    table declined to look, and the detection table reads like a triage failure
    with nothing anywhere saying otherwise.

    So: in the table, ALWAYS, and naming a tool. All three, at every confidence.
    """
    rules = _marker_rules()
    assert rules, "no markers found — this test would pass vacuously"
    for target, marker_id, rule in rules:
        assert rule in rescan_table.RULES, (
            f"{target}/{marker_id} names ZAP rule {rule}, which has no row. An "
            f"unenumerated rule escalates on risk alone and names no tool, so "
            f"the marker is flagged, dispatched nowhere, and reported "
            f"not-attempted."
        )
        for confidence in ("Low", "Medium", "High"):
            decision = decide(alert(rule, confidence, "High"))
            assert decision.needs_rescan, (
                f"{target}/{marker_id}: rule {rule} is not rescanned at "
                f"{confidence} confidence, so `+deterministic triage` reports "
                f"this marker as undetected"
            )
            assert decision.tool, (
                f"{target}/{marker_id}: rule {rule} is flagged but routes to no "
                f"tool, so nothing verifies it"
            )


def test_the_rules_ruled_out_as_noise_are_not_ground_truth_rules():
    """The other direction of the same interaction.

    Adding a NEVER row is how the 199 unroutable flags on the WordPress
    baseline were closed. It is also how a marker would be silently ruled out,
    so the two facts are checked against each other rather than by eye.
    """
    marker_rules = {rule for _, _, rule in _marker_rules()}
    never = {pid for pid, entry in rescan_table.RULES.items()
             if entry.policy is RescanPolicy.NEVER}
    assert never, "no NEVER rows — this test would pass vacuously"
    assert not (never & marker_rules), (
        f"rule(s) {sorted(never & marker_rules)} are NEVER *and* named by a CVE "
        f"marker: the marker will report as undetected at the deterministic "
        f"triage layer"
    )


def test_every_xss_rule_the_table_knows_is_in_the_execution_oracle_set():
    """A new XSS rule cannot be added to the table and forgotten in `XSS_RULES`.

    `verification.XSS_RULES` decides which propagation claims are dispatched to
    the browser oracle rather than to a string matcher, and it is a hand-written
    set because ZAP gives these rules the catch-all CWE-20 — there is no family
    to compute it from. The table's own rule names are the check: if a row says
    XSS, the set must know about it, or the 40026 defect returns quietly for
    whichever rule was added last.
    """
    from dast_orchestrator.domain import verification

    named_xss = {
        pid for pid, entry in rescan_table.RULES.items()
        if "xss" in entry.name.lower() or "cross site scripting" in entry.name.lower()
    }
    assert named_xss, "no XSS rows — this test would pass vacuously"
    assert not (named_xss - verification.XSS_RULES), (
        f"rule(s) {sorted(named_xss - verification.XSS_RULES)} are XSS by name "
        "but absent from verification.XSS_RULES, so a propagation claim "
        "anchored on one would be dispatched to a string matcher"
    )


def test_the_one_xss_rule_the_table_still_routes_to_nuclei_is_deliberate():
    """`10031` stays on nuclei, and the reason is now measured rather than argued.

    Every other XSS rule routes to `browser`. `10031` (Potential XSS) does not,
    and the argument its row was written with predates the 40026 result showing
    that reflection and execution are different questions — so the swap was
    tried on 2026-09-08 and measured, rather than reasoned about again:

    * **The browser oracle injects into a QUERY parameter only.** Of the 25
      flagged `10031` findings on the Gitea baseline, 16 inject at a query
      parameter and **9 at a form-body parameter**, which that wrapper refuses
      outright. The swap does not upgrade the oracle for those; it makes them
      unprobeable.
    * **The swap is not a verify-time knob.** `verification.selected_tool` reads
      `finding.deterministic.tool`, which the table wrote at *correlate* time,
      so re-routing and re-verifying the stored corpus produced a byte-identical
      outcome mix. Adopting it costs a re-correlate and a re-verify of both
      baselines.

    The blocker is the probe, not the routing. Revisit when the browser wrapper
    can inject into a form body. See `DECISIONS.md` §"§N3".
    """
    from dast_orchestrator.domain import verification

    still_nuclei = {pid for pid in verification.XSS_RULES
                    if rescan_table.RULES[pid].tool == "nuclei"}
    assert still_nuclei == {"10031"}
