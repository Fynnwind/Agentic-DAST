"""Site-wide (SYSTEMIC) alert collapse in the LLM triage arm.

The collapse folds ZAP-2.17 SYSTEMIC-tagged findings — identical header/config
issues repeated on every URL — to one representative per
``(plugin_id, alert_ref, evidence)``, so pass 1 judges them once and fans the
verdict back, instead of re-asking the model the same question per endpoint.
"""

from dast_orchestrator.stages import triage
from dast_orchestrator.analysis.join import AlertGroup, Bundle


def _bundle(route):
    return Bundle(endpoint_key=route, match_how="seed",
                  method=route.split()[0], path=route.split()[1], groups=[])


def _group(plugin, *, alert_ref="", evidence="", systemic, param="q"):
    return AlertGroup(
        plugin_id=plugin, name=f"rule {plugin}", risk="Low", confidence="Medium",
        method="GET", param=param, evidence=evidence, alert_ref=alert_ref,
        tags={"SYSTEMIC": ""} if systemic else {"CWE-79": ""},
    )


def _work(*items):
    """items: (route, [(fid, group), ...])."""
    return [(_bundle(route), pairs) for route, pairs in items]


def test_identical_systemic_findings_collapse_to_one_representative():
    csp = lambda: _group("10055", alert_ref="10055-1", evidence="no CSP", systemic=True)
    work = _work(
        ("GET /a.php", [("a1", csp())]),
        ("GET /b.php", [("b1", csp())]),
        ("GET /c.php", [("c1", csp())]),
    )
    collapsed, fanout = triage.collapse_systemic(work)
    # One representative kept (the first), the other two folded.
    kept = [fid for _b, pairs in collapsed for fid, _g in pairs]
    assert kept == ["a1"]
    assert fanout == {"b1": "a1", "c1": "a1"}


def test_a_representative_with_static_context_beats_an_earlier_one_without():
    csp = lambda: _group("10055", alert_ref="10055-1", evidence="no CSP", systemic=True)
    work = _work(
        ("GET /no-context-1", [("n1", csp())]),
        ("GET /has-context-1", [("h1", csp())]),
        ("GET /has-context-2", [("h2", csp())]),
        ("GET /no-context-2", [("n2", csp())]),
    )
    work[1][0].static_context = {"method": "GET", "path": "/has-context-1"}
    work[2][0].static_context = {"method": "GET", "path": "/has-context-2"}
    collapsed, fanout = triage.collapse_systemic(work)
    assert [fid for _b, pairs in collapsed for fid, _g in pairs] == ["h1"]
    assert fanout == {"n1": "h1", "h2": "h1", "n2": "h1"}


def test_with_no_static_context_anywhere_the_first_seen_stays_the_representative():
    csp = lambda: _group("10055", alert_ref="10055-1", evidence="no CSP", systemic=True)
    work = _work(("GET /a", [("a1", csp())]), ("GET /b", [("b1", csp())]))
    collapsed, fanout = triage.collapse_systemic(work)
    assert [fid for _b, pairs in collapsed for fid, _g in pairs] == ["a1"]
    assert fanout == {"b1": "a1"}


def test_non_systemic_findings_are_left_per_endpoint():
    xss = lambda: _group("40012", evidence="reflected", systemic=False)
    work = _work(
        ("GET /a.php", [("a1", xss())]),
        ("GET /b.php", [("b1", xss())]),
    )
    collapsed, fanout = triage.collapse_systemic(work)
    kept = sorted(fid for _b, pairs in collapsed for fid, _g in pairs)
    assert kept == ["a1", "b1"]      # both survive
    assert fanout == {}               # nothing folded


def test_same_rule_different_evidence_stays_separate():
    work = _work(
        ("GET /a.php", [("a1", _group("10036", alert_ref="10036-1",
                                      evidence="Apache/2.4.54", systemic=True))]),
        ("GET /b.php", [("b1", _group("10036", alert_ref="10036-1",
                                      evidence="nginx/1.25", systemic=True))]),
    )
    collapsed, fanout = triage.collapse_systemic(work)
    kept = sorted(fid for _b, pairs in collapsed for fid, _g in pairs)
    assert kept == ["a1", "b1"]      # different observation -> own verdict
    assert fanout == {}


def test_fan_copies_representative_verdict_with_provenance():
    det = {"needs_rescan": False}
    findings = [
        {"finding_id": "rep", "deterministic": det,
         "llm": {"needs_rescan": False, "verdict": "benign"}},
        {"finding_id": "dup", "deterministic": det, "llm": None},
    ]
    fanned = triage.fan_systemic_verdicts(findings, {"dup": "rep"})
    assert fanned == 1
    dup = next(f for f in findings if f["finding_id"] == "dup")
    assert dup["llm"]["verdict"] == "benign"
    assert dup["llm"]["fanned_from"] == "rep"           # provenance recorded
    assert "agreement" in dup


def test_fan_skips_representative_that_was_never_answered():
    # Regression: an asked-but-unanswered representative has llm == None (key
    # present, value None). Fanning must skip it, not crash on dict(None).
    findings = [
        {"finding_id": "rep", "llm": None},
        {"finding_id": "dup", "llm": None},
    ]
    fanned = triage.fan_systemic_verdicts(findings, {"dup": "rep"})
    assert fanned == 0
    assert findings[1]["llm"] is None                    # left asked-but-unanswered


def test_mixed_endpoint_keeps_actionable_and_folds_only_duplicated_systemic():
    work = _work(
        ("GET /a.php", [
            ("a_sys", _group("10055", alert_ref="10055-1", evidence="no CSP", systemic=True)),
            ("a_xss", _group("40012", evidence="reflected", systemic=False)),
        ]),
        ("GET /b.php", [
            ("b_sys", _group("10055", alert_ref="10055-1", evidence="no CSP", systemic=True)),
        ]),
    )
    collapsed, fanout = triage.collapse_systemic(work)
    kept = sorted(fid for _b, pairs in collapsed for fid, _g in pairs)
    assert kept == ["a_sys", "a_xss"]   # a keeps both; b's systemic dup folded
    assert fanout == {"b_sys": "a_sys"}
    # the endpoint that had only a folded duplicate drops out of the call list
    assert [b.identifier for b, _p in collapsed] == ["GET /a.php"]
