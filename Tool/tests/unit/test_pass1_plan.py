"""Which findings pass 1 asks: the old gate whole, then the rest by risk to a limit.

The old gate (an endpoint with static context) is asked in full, whatever the
limit; the findings beyond it are ranked by ZAP risk, then source before none,
and the first ``max_unmatched_findings`` are asked. Decided before any call, so a
repeat of one scan asks the same set.
"""

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis.join import AlertGroup, Bundle
from dast_orchestrator.stages import triage


def _group(plugin, risk, *, systemic=False, evidence="e"):
    return AlertGroup(
        plugin_id=plugin, name=f"rule {plugin}", risk=risk, confidence="Medium",
        method="GET", param="q", evidence=evidence, alert_ref=f"{plugin}-1",
        tags={"SYSTEMIC": ""} if systemic else {"CWE-89": ""},
    )


def _bundle(route, *groups, context=False):
    return Bundle(
        endpoint_key=route, match_how="seed" if context else "absent-unmatched",
        method="GET", path=route, groups=list(groups),
        static_context={"key": route} if context else None,
    )


def _ids(bundles, findings):
    """finding_id per route, for readable assertions."""
    return {f["path"]: f["finding_id"] for f in findings}


def test_the_old_gate_is_asked_whole_and_nothing_beyond_it_at_zero():
    bundles = [
        _bundle("/gated", _group("10020", "Low"), _group("40018", "High"), context=True),
        _bundle("/beyond", _group("40018", "High")),
    ]
    findings = join.build_findings(bundles)
    plan = triage.plan_pass1(bundles, findings, max_unmatched_findings=0)

    gated = {f["finding_id"] for f in findings if f["path"] == "/gated"}
    assert set(plan.asked_ids) == gated
    assert plan.deferred_ids == [_ids(bundles, findings)["/beyond"]]
    assert (plan.unmatched, plan.unmatched_sent) == (1, 0)


def test_beyond_the_gate_highest_risk_first_then_source_before_none():
    bundles = [
        _bundle("/low-src", _group("10020", "Low")),
        _bundle("/med-none", _group("10021", "Medium")),
        _bundle("/high-none", _group("40018", "High")),
        _bundle("/med-src", _group("10022", "Medium")),
    ]
    findings = join.build_findings(bundles)
    ids = _ids(bundles, findings)
    with_source = {"/low-src", "/med-src"}

    def has_source(bundle):
        return bundle.path in with_source

    plan = triage.plan_pass1(bundles, findings, 2, has_source)
    assert set(plan.asked_ids) == {ids["/high-none"], ids["/med-src"]}
    assert set(plan.deferred_ids) == {ids["/med-none"], ids["/low-src"]}

    plan = triage.plan_pass1(bundles, findings, 3, has_source)
    assert ids["/med-none"] in plan.asked_ids and ids["/low-src"] in plan.deferred_ids


def test_every_limit_asks_a_superset_of_the_old_gate():
    # The author's condition for any limit: nothing the old gate asked is lost,
    # including a gated systemic finding folded with instances beyond the gate.
    csp = lambda: _group("10055", "Low", systemic=True, evidence="no CSP")
    bundles = [
        _bundle("/beyond-csp", csp()),
        _bundle("/gated", _group("40018", "High"), csp(), context=True),
        _bundle("/beyond-hi", _group("40018", "High")),
        _bundle("/beyond-info", _group("10027", "Informational", evidence="x")),
    ]
    findings = join.build_findings(bundles)
    old_gate = set(triage.plan_pass1(bundles, findings, 0).asked_ids)
    assert {f["finding_id"] for f in findings if f["path"] == "/gated"} <= old_gate

    for limit in (0, 1, 2, 250, -1):
        assert old_gate <= set(triage.plan_pass1(bundles, findings, limit).asked_ids)


def test_the_deferred_are_counted_by_risk_highest_first():
    bundles = [_bundle("/info", _group("10027", "Informational")),
               _bundle("/low", _group("10020", "Low")),
               _bundle("/hi", _group("40018", "High"))]
    findings = join.build_findings(bundles)

    plan = triage.plan_pass1(bundles, findings, 0)
    assert list(plan.deferred_by_risk.items()) == [
        ("High", 1), ("Low", 1), ("Informational", 1)]
    assert plan.deferred_note() == "3 deferred (High 1, Low 1, Informational 1)"
    assert triage.plan_pass1(bundles, findings, -1).deferred_note() == "0 deferred"


def test_no_limit_asks_every_candidate():
    bundles = [_bundle("/a", _group("40018", "High"), context=True),
               _bundle("/b", _group("10020", "Low"))]
    findings = join.build_findings(bundles)
    plan = triage.plan_pass1(bundles, findings, -1)
    assert len(plan.asked_ids) == 2 and plan.deferred_ids == []


def test_a_systemic_duplicate_beyond_the_gate_rides_on_its_gated_representative():
    # The fold prefers a representative with static context, so the old gate's
    # instance is asked and the unmatched one is answered by fan-out, not deferred.
    csp = lambda: _group("10055", "Medium", systemic=True, evidence="no CSP")
    bundles = [_bundle("/beyond", csp()), _bundle("/gated", csp(), context=True)]
    findings = join.build_findings(bundles)
    ids = _ids(bundles, findings)
    plan = triage.plan_pass1(bundles, findings, 0)

    assert set(plan.asked_ids) == {ids["/beyond"], ids["/gated"]}
    assert plan.fanout == {ids["/beyond"]: ids["/gated"]}
    assert plan.deferred_ids == []


def test_a_deferred_representative_takes_its_folded_instances_with_it():
    csp = lambda: _group("10055", "Low", systemic=True, evidence="no CSP")
    bundles = [_bundle("/a", csp()), _bundle("/b", csp()),
               _bundle("/hi", _group("40018", "High"))]
    findings = join.build_findings(bundles)
    ids = _ids(bundles, findings)
    plan = triage.plan_pass1(bundles, findings, 1)

    assert plan.asked_ids == [ids["/hi"]]
    assert set(plan.deferred_ids) == {ids["/a"], ids["/b"]}
    assert plan.fanout == {}
