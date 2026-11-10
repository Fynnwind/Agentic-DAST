"""The final three-way disposition: confirmed / refuted / requires-triage.

This is the report's actionable synthesis across all three arms, so its
precedence rules are pinned here: a tool that ran outranks a model's reading,
which outranks self-evidence, which outranks "nobody settled it".
"""

from __future__ import annotations

from dast_orchestrator.domain import verification as v


def _f(plugin, name, risk="Medium", det=False, llm=None, path="/x"):
    finding = {
        "finding_id": f"f-{plugin}",
        "path": path,
        "alert": {"plugin_id": plugin, "name": name, "risk": risk},
        "deterministic": {"needs_rescan": det},
    }
    if llm is not None:
        finding["llm"] = llm
    return finding


def test_a_tool_confirmation_is_confirmed():
    d, _ = v.classify_finding(_f("40018", "SQL Injection", "High"),
                              {"outcome": "confirmed", "tool": "sqlmap"})
    assert d == v.DISPOSITION_CONFIRMED


def test_a_tool_refutation_is_refuted():
    d, _ = v.classify_finding(_f("6", "Path Traversal", "High"),
                              {"outcome": "refuted", "tool": "ffuf"})
    assert d == v.DISPOSITION_REFUTED


def test_a_tool_outranks_a_model_reading():
    # The model wanted to keep it (escalate) but the tool refuted — tool wins.
    d, _ = v.classify_finding(
        _f("40018", "SQLi", "High", llm={"needs_rescan": True, "reasoning": ""}),
        {"outcome": "refuted", "tool": "sqlmap"})
    assert d == v.DISPOSITION_REFUTED


def test_a_source_grounded_model_refutation_is_refuted():
    d, why = v.classify_finding(_f(
        "6", "Path Traversal", "High",
        llm={"needs_rescan": False,
             "reasoning": "the hash only feeds a redirect (avatar.go:46), no file read"}))
    assert d == v.DISPOSITION_REFUTED
    assert "source" in why


def test_a_cited_decline_is_a_refutation_only_if_the_model_had_source():
    cited = "the hash only feeds a redirect (avatar.go:46), no file read"
    with_source, _ = v.classify_finding(_f(
        "6", "Path Traversal", "High",
        llm={"needs_rescan": False, "had_source": True, "reasoning": cited}))
    no_source, _ = v.classify_finding(_f(
        "6", "Path Traversal", "High",
        llm={"needs_rescan": False, "had_source": False, "reasoning": cited}))
    assert with_source == v.DISPOSITION_REFUTED
    assert no_source == v.DISPOSITION_TRIAGE


def test_a_model_decline_without_a_line_is_not_a_refutation():
    # "no rescan" with no file:line is an opinion, not a refutation.
    d, _ = v.classify_finding(_f(
        "40018", "SQLi", "High",
        llm={"needs_rescan": False, "reasoning": "looks fine to me"}))
    assert d == v.DISPOSITION_TRIAGE


def test_self_evident_header_is_confirmed():
    d, _ = v.classify_finding(_f("10038", "CSP Header Not Set"))
    assert d == v.DISPOSITION_CONFIRMED


def test_identification_rule_is_informational():
    d, _ = v.classify_finding(_f("10112", "Session Management Response Identified",
                                 "Informational"))
    assert d == v.DISPOSITION_INFORMATIONAL


def test_flagged_but_unsettled_needs_triage():
    d, _ = v.classify_finding(_f("40018", "SQLi", "High", det=True))
    assert d == v.DISPOSITION_TRIAGE


def test_inconclusive_verification_needs_triage():
    d, _ = v.classify_finding(_f("40018", "SQLi", "High"),
                              {"outcome": "inconclusive", "tool": "sqlmap"})
    assert d == v.DISPOSITION_TRIAGE


def _no_tool(reason="no-tool-routed"):
    return {"outcome": "not-attempted", "not_attempted_reason": reason}


def test_a_header_rule_no_tool_exists_for_is_evident_not_triage():
    # Flagged by the table's default policy, with nothing to route it to: the
    # proof is the same captured response that settles 10038.
    d, why = v.classify_finding(
        _f("10055", "CSP: Failure to Define Directive with No Fallback", det=True),
        _no_tool())
    assert d == v.DISPOSITION_CONFIRMED
    assert "self-evident" in why


def test_a_header_rule_a_tool_could_have_run_on_stays_in_triage():
    # Only "no tool exists" settles it; a budget or a probe failure says nothing.
    for reason in ("budget", "no-probe-url", "tool-cannot-reach-parameter"):
        d, _ = v.classify_finding(_f("10055", "CSP", det=True), _no_tool(reason))
        assert d == v.DISPOSITION_TRIAGE, reason


def test_a_rule_outside_the_header_classes_with_no_tool_stays_in_triage():
    d, _ = v.classify_finding(_f("40008", "Parameter Tampering", det=True), _no_tool())
    assert d == v.DISPOSITION_TRIAGE


def test_a_cookie_rule_zap_rates_informational_is_informational():
    d, why = v.classify_finding(_f("10029", "Cookie Poisoning", "Informational"))
    assert d == v.DISPOSITION_INFORMATIONAL
    assert "no weakness" in why


def test_a_tool_verdict_still_outranks_the_informational_cookie_rule():
    finding = _f("10029", "Cookie Poisoning", "Informational",
                 llm={"needs_rescan": True, "reasoning": ""})
    assert v.classify_finding(finding, {"outcome": "refuted", "tool": "nuclei"})[0] \
        == v.DISPOSITION_REFUTED
    assert v.classify_finding(finding, {"outcome": "confirmed", "tool": "nuclei"})[0] \
        == v.DISPOSITION_CONFIRMED


def test_a_self_evident_claim_can_rest_on_a_header_rule_no_tool_exists_for():
    findings = [_f("10055", "CSP", det=True)]
    verifs = [{"finding_id": "f-10055", **_no_tool()}]
    claims = [_claim("self-evident", ["f-10055"], fid="c-1")]
    report = v.disposition_report(findings, verifs, claims, [])
    assert report["synthesis_counts"][v.DISPOSITION_CONFIRMED] == 1


def test_summary_buckets_and_counts_are_consistent():
    findings = [
        _f("10038", "CSP"),                                   # confirmed
        _f("6", "Traversal", "High", det=True),               # triage (flagged)
        _f("10112", "Ident", "Informational"),                # informational
    ]
    verifs = []
    summary = v.disposition_summary(findings, verifs)
    assert summary["counts"][v.DISPOSITION_CONFIRMED] == 1
    assert summary["counts"][v.DISPOSITION_TRIAGE] == 1
    assert summary["counts"][v.DISPOSITION_INFORMATIONAL] == 1
    assert sum(summary["counts"].values()) == len(findings)


# -- Phase 4: synthesis accountability -------------------------------------

def _claim(tool, supporting=(), severity="medium", fid="c-000"):
    return {"finding_id": fid, "title": "t", "suggested_tool": tool,
            "severity": severity, "supporting_finding_ids": list(supporting),
            "affected_routes": ["GET /a"], "pattern": "chain"}


def test_out_of_scope_synthesis_is_triage_not_confirmed():
    d, why = v.classify_synthesis(_claim("out-of-scope"))
    assert d == v.DISPOSITION_TRIAGE and "out of scope" in why


def test_self_evident_synthesis_confirmed_only_when_evidence_is():
    d, _ = v.classify_synthesis(_claim("self-evident", ["f-1"]),
                                None, {"f-1": v.DISPOSITION_CONFIRMED})
    assert d == v.DISPOSITION_CONFIRMED
    # cited finding not confirmed -> the claim drops to triage
    d, _ = v.classify_synthesis(_claim("self-evident", ["f-1"]),
                                None, {"f-1": v.DISPOSITION_TRIAGE})
    assert d == v.DISPOSITION_TRIAGE


def test_legacy_none_is_treated_as_self_evident():
    d, _ = v.classify_synthesis(_claim("none", ["f-1"]),
                                None, {"f-1": v.DISPOSITION_CONFIRMED})
    assert d == v.DISPOSITION_CONFIRMED


def test_testable_synthesis_takes_the_tool_verdict():
    assert v.classify_synthesis(_claim("nuclei"), {"outcome": "confirmed"})[0] \
        == v.DISPOSITION_CONFIRMED
    assert v.classify_synthesis(_claim("sqlmap"), {"outcome": "refuted"})[0] \
        == v.DISPOSITION_REFUTED
    assert v.classify_synthesis(_claim("ffuf"), {"outcome": "inconclusive"})[0] \
        == v.DISPOSITION_TRIAGE


def test_disposition_report_surfaces_the_manual_eval_set():
    findings = [_f("10038", "CSP")]                       # confirmed (self-evident)
    synthesis = [_claim("out-of-scope", fid="c-1"),
                 _claim("nuclei", fid="c-2")]
    corr_verifs = [{"finding_id": "c-2", "outcome": "confirmed"}]
    report = v.disposition_report(findings, [], synthesis, corr_verifs)
    ids = [x["finding_id"] for x in report["synthesis_out_of_scope"]]
    assert ids == ["c-1"]                                 # only the out-of-scope one
    # the nuclei claim landed in confirmed alongside the per-finding one
    assert report["synthesis_counts"][v.DISPOSITION_CONFIRMED] == 1
    assert report["synthesis_counts"][v.DISPOSITION_TRIAGE] == 1
