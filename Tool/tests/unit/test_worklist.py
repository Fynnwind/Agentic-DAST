"""The order a reader works through: sections of evidence, one line per ZAP rule.

The properties pinned here are the ones the report's claims rest on: nothing is lost by
rolling up, the order means the same thing in every run, and a model claim does not get
ahead of a scanner finding by accident of its id.
"""

from __future__ import annotations

from dast_orchestrator.domain import verification as v


def _f(fid, plugin, name="Rule", risk="Medium", confidence="Medium", source="passive-scanner",
       det=False, llm=None, path=None):
    finding = {
        "finding_id": fid,
        "path": path or f"/{fid}",
        "alert": {"plugin_id": plugin, "name": name, "risk": risk, "confidence": confidence,
                  "source": source},
        "deterministic": {"needs_rescan": det},
    }
    if llm is not None:
        finding["llm"] = llm
    return finding


def _claim(fid, severity="medium", tool="out-of-scope", seen=1, of=5, agreeing=None,
           supporting=("f-x",)):
    repro = {"seen_in": seen, "of": of}
    if agreeing is not None:
        repro.update(models_agreeing=agreeing, of_models=2)
    return {"finding_id": fid, "title": fid, "suggested_tool": tool, "severity": severity,
            "pattern": "p", "supporting_finding_ids": list(supporting),
            "affected_routes": ["GET /a"], "reproducibility": repro}


def _sections(worklist):
    return [ln["section"] for ln in worklist["lines"]]


def _ids(worklist, section):
    return [ln["finding_id"] for ln in worklist["lines"] if ln["section"] == section]


def test_findings_roll_up_to_one_line_per_rule_and_lose_nothing():
    findings = [_f(f"f-{i}", "10038", path=f"/r{i % 2}", det=True) for i in range(4)]
    worklist = v.build_worklist(findings)
    line = worklist["lines"][0]
    assert len(worklist["lines"]) == 1
    assert (line["count"], line["routes"]) == (4, 2)
    assert line["finding_ids"] == sorted(f["finding_id"] for f in findings)
    assert set(worklist["items"]) == {f["finding_id"] for f in findings}


def test_the_sections_run_from_reproduced_to_informational():
    findings = [
        _f("f-info", "10112", "Session", "Informational"),     # identification rule
        _f("f-refuted", "6", "Traversal", "High"),
        _f("f-evident", "10038", "CSP"),
        _f("f-open", "40018", "SQLi", "High", det=True),
        _f("f-repro", "90037", "Injection", "High"),
    ]
    verifs = [{"finding_id": "f-refuted", "outcome": "refuted", "tool": "ffuf"},
              {"finding_id": "f-repro", "outcome": "confirmed", "tool": "nuclei"}]
    worklist = v.build_worklist(findings, verifs, [_claim("c-open")])
    assert _sections(worklist) == [
        v.SECTION_REPRODUCED, v.SECTION_OPEN, v.SECTION_CLAIMS, v.SECTION_EVIDENT,
        v.SECTION_REFUTED, v.SECTION_INFORMATIONAL]


def test_evident_is_above_a_refuted_high():
    # A true finding with a fix outranks one only kept for audit, whatever ZAP rated it.
    findings = [_f("f-low", "10021", "XCTO", "Low"), _f("f-high", "6", "Traversal", "High")]
    verifs = [{"finding_id": "f-high", "outcome": "refuted", "tool": "ffuf"}]
    worklist = v.build_worklist(findings, verifs)
    assert [ln["finding_id"] for ln in worklist["lines"]] == ["f-low", "f-high"]


def test_open_lines_order_by_risk_then_attack_then_both_arms_then_confidence():
    flagged = {"needs_rescan": True, "reasoning": ""}
    findings = [
        _f("f-low", "1", risk="Low", source="active-scanner", det=True),
        _f("f-conf", "2", confidence="Low", det=True),
        _f("f-plain", "3", det=True),
        _f("f-both", "4", det=True, llm=flagged),
        _f("f-attack", "5", source="active-scanner", det=True),
        _f("f-high", "6", risk="High", det=True),
    ]
    worklist = v.build_worklist(findings)
    assert _ids(worklist, v.SECTION_OPEN) == [
        "f-high", "f-attack", "f-both", "f-plain", "f-conf", "f-low"]


def test_the_rule_id_breaks_a_tie_not_the_hash_of_a_finding_id():
    # Finding ids are hashes, so a tiebreak on them would reorder identical runs.
    findings = [_f("f-zzz", "100", det=True), _f("f-aaa", "200", det=True)]
    worklist = v.build_worklist(findings)
    assert [ln["plugin_id"] for ln in worklist["lines"]] == ["100", "200"]


def test_a_claim_does_not_jump_ahead_of_a_zap_finding_of_its_risk():
    # `c-` sorts before `f-`, which used to put every claim first by accident.
    worklist = v.build_worklist([_f("f-1", "40018", risk="High", det=True)], [],
                                [_claim("c-0", severity="high")])
    assert [ln["finding_id"] for ln in worklist["lines"]] == ["f-1", "c-0"]


def test_claims_order_by_models_then_recurrence_and_a_lead_ranks_lowest():
    claims = [_claim("c-lead", seen=1, agreeing=1), _claim("c-seen", seen=4, agreeing=1),
              _claim("c-models", seen=2, agreeing=2)]
    worklist = v.build_worklist([], [], claims)
    assert _ids(worklist, v.SECTION_CLAIMS) == ["c-models", "c-seen", "c-lead"]
    items = worklist["items"]
    assert items["c-seen"]["rank"] > items["c-lead"]["rank"]


def test_a_claim_lands_where_its_disposition_says():
    findings = [_f("f-h", "10038", "CSP")]
    claims = [_claim("c-evident", tool="self-evident", supporting=["f-h"]),
              _claim("c-tool", tool="nuclei"), _claim("c-gone", tool="sqlmap")]
    corr = [{"finding_id": "c-tool", "outcome": "confirmed"},
            {"finding_id": "c-gone", "outcome": "refuted"}]
    items = v.build_worklist(findings, [], claims, corr)["items"]
    assert items["c-evident"]["section"] == v.SECTION_EVIDENT
    assert items["c-tool"]["section"] == v.SECTION_REPRODUCED
    assert items["c-gone"]["section"] == v.SECTION_REFUTED


def test_a_reproduced_finding_keeps_its_own_line():
    findings = [_f("f-1", "6", risk="High"), _f("f-2", "6", risk="High")]
    verifs = [{"finding_id": fid, "outcome": "confirmed", "tool": "ffuf"}
              for fid in ("f-1", "f-2")]
    worklist = v.build_worklist(findings, verifs)
    assert len(worklist["lines"]) == 2
    assert worklist["lines"][0]["why"] == {"ffuf": 1}


def test_a_confirmed_sibling_is_reproduced():
    sibling = {"finding_id": "s-1", "rule_name": "Propagated", "route": "GET /o", "tool": "nuclei"}
    worklist = v.build_worklist([_f("f-1", "40018", det=True)], [], [], [], [sibling])
    assert worklist["lines"][0]["finding_id"] == "s-1"
    assert worklist["items"]["s-1"]["section"] == v.SECTION_REPRODUCED


def test_each_line_says_why_it_is_open():
    findings = [
        _f("f-budget", "40018", det=True), _f("f-reach", "40018", det=True),
        _f("f-maybe", "40018", det=True), _f("f-flag", "40018", det=True),
        _f("f-nobody", "10096", "Timestamp"),
    ]
    verifs = [
        {"finding_id": "f-budget", "outcome": "not-attempted", "not_attempted_reason": "budget"},
        {"finding_id": "f-reach", "outcome": "not-attempted",
         "not_attempted_reason": "tool-cannot-reach-parameter"},
        {"finding_id": "f-maybe", "outcome": "inconclusive", "tool": "sqlmap"},
    ]
    lines = {ln["plugin_id"]: ln for ln in v.build_worklist(findings, verifs)["lines"]}
    assert lines["40018"]["why"] == {
        "budget": 1, v.WHY_FLAGGED: 1, "inconclusive": 1, "tool-cannot-reach-parameter": 1}
    assert lines["10096"]["why"] == {v.WHY_NEITHER: 1}


def test_a_refuted_line_says_who_refuted_it():
    findings = [
        _f("f-tool", "6", "Traversal"),
        _f("f-model", "6", "Traversal",
           llm={"needs_rescan": False, "reasoning": "no file read (avatar.go:46)"}),
    ]
    verifs = [{"finding_id": "f-tool", "outcome": "refuted", "tool": "ffuf"}]
    line = v.build_worklist(findings, verifs)["lines"][0]
    assert line["why"] == {"ffuf": 1, v.WHY_MODEL_CITED: 1}


def test_rank_is_inside_sarif_s_range_and_falls_with_the_section():
    findings = [
        _f("f-repro", "90037", risk="High"), _f("f-open", "40018", risk="Informational", det=True),
        _f("f-evident", "10038", risk="Medium"), _f("f-refuted", "6", risk="High"),
        _f("f-info", "10112", risk="Informational"),
    ]
    verifs = [{"finding_id": "f-repro", "outcome": "confirmed", "tool": "nuclei"},
              {"finding_id": "f-refuted", "outcome": "refuted", "tool": "ffuf"}]
    claims = [_claim("c-seen", seen=3, severity="low"), _claim("c-lead", seen=1, severity="high")]
    items = v.build_worklist(findings, verifs, claims)["items"]
    order = ["f-repro", "f-open", "c-seen", "c-lead", "f-evident", "f-refuted", "f-info"]
    ranks = [items[fid]["rank"] for fid in order]
    assert ranks == sorted(ranks, reverse=True)
    assert len(set(ranks)) == len(ranks)
    assert all(0.0 <= rank <= 100.0 for rank in ranks)


def test_a_result_ranks_by_its_own_risk_inside_a_mixed_line():
    findings = [_f("f-high", "6", risk="High", det=True), _f("f-low", "6", risk="Low", det=True)]
    items = v.build_worklist(findings)["items"]
    assert items["f-high"]["line"] == items["f-low"]["line"]
    assert items["f-high"]["rank"] > items["f-low"]["rank"]


def test_line_numbers_run_in_order_with_no_gaps():
    findings = [_f("f-1", "1", det=True), _f("f-2", "2", det=True), _f("f-3", "10038")]
    worklist = v.build_worklist(findings)
    assert [ln["line"] for ln in worklist["lines"]] == [1, 2, 3]


def test_the_matrix_counts_zap_findings_only_and_adds_up():
    findings = [
        _f("f-repro", "90037", risk="High"), _f("f-gone", "6", risk="High"),
        _f("f-open", "40018", risk="High", det=True), _f("f-evident", "10038"),
    ]
    verifs = [{"finding_id": "f-repro", "outcome": "confirmed", "tool": "nuclei"},
              {"finding_id": "f-gone", "outcome": "refuted", "tool": "ffuf"}]
    matrix = v.build_worklist(findings, verifs, [_claim("c-0", severity="high")])["risk_matrix"]
    assert list(matrix) == ["High", "Medium"]
    high = matrix["High"]
    assert (high["findings"], high[v.SECTION_REPRODUCED], high[v.SECTION_REFUTED],
            high[v.SECTION_OPEN], high[v.SECTION_CLAIMS]) == (3, 1, 1, 1, 0)
    assert matrix["Medium"][v.SECTION_EVIDENT] == 1


def test_an_empty_run_has_an_empty_worklist():
    worklist = v.build_worklist([])
    assert worklist["lines"] == [] and worklist["items"] == {} and worklist["risk_matrix"] == {}
