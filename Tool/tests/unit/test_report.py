"""SARIF export: two rule namespaces, cross-namespace links, schema validity.

The report is validated against a locally-bundled copy of the SARIF 2.1.0
schema (``tests/fixtures/sarif-2.1.0-schema.json``) so the check is offline and
pinned, and the namespace/relationship structure is asserted directly.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from dast_orchestrator.stages import report
from dast_orchestrator.domain.verification import CONFIRMED, REFUTED

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SARIF_SCHEMA = json.loads((FIXTURES / "sarif-2.1.0-schema.json").read_text())


def _finding(fid, plugin="40018", name="SQL Injection", risk="High",
             url="http://t/x?q=1", det=True, det_tool="sqlmap"):
    return {
        "finding_id": fid,
        "static_context": "regex",
        "method": "GET",
        "path": "/x",
        "alert": {"plugin_id": plugin, "name": name, "risk": risk, "confidence": "Medium",
                  "param": "q", "cweid": "89", "example_urls": [url]},
        "deterministic": {"needs_rescan": det, "tool": det_tool, "policy": "always"},
        "llm": None,
        "agreement": "deterministic-only",
    }


def _correlation(findings, correlated=None):
    return {
        "schema_version": 1,
        "run_id": "20260101T000000Z-gitea",
        "generated_at": "20260101T000000Z",
        "run": {"target": "http://t", "zap_version": "2.17.0"},
        "summary": {"raw_alerts": 10, "findings": len(findings), "bundles": 3,
                    "bundles_with_static_context": 2,
                    "alerts_by_zap_source": {"active-scanner": 5, "passive-scanner": 5},
                    "deterministic_rescans": 1, "rescans_by_tool": {"sqlmap": 1},
                    "correlated_synthesis_findings": len(correlated or [])},
        "findings": findings,
        "correlated_findings": correlated or [],
    }


def test_build_sarif_validates_against_schema():
    doc = report.build_sarif(_correlation([_finding("f-1")]), None)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)


def test_result_carries_the_gitlab_dast_location_fields():
    # GitLab builds a DAST vulnerability location from path + method + parameter.
    # Path is the result location uri; method and the flagged parameter must ride
    # in the SARIF-native webRequest and, mirrored, in the property bag so a
    # SARIF->GitLab mapping has all three. method/param are read from the alert,
    # where the scan records them.
    finding = _finding("f-1")
    finding["alert"]["method"] = "POST"
    finding["alert"]["param"] = "redirect_to"
    finding["alert"]["attack"] = "//evil"
    doc = report.build_sarif(_correlation([finding]), None)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)   # still valid 2.1.0

    result = next(r for r in doc["runs"][0]["results"]
                  if r["properties"].get("namespace") == "zap-mirror")
    assert result["properties"]["method"] == "POST"
    assert result["properties"]["param"] == "redirect_to"
    wr = result["webRequest"]
    assert wr["method"] == "POST"
    assert wr["target"] == "http://t/x?q=1"
    assert wr["parameters"] == {"redirect_to": "//evil"}


def test_two_namespaces_present():
    doc = report.build_sarif(_correlation([_finding("f-1")]), None)
    tool = doc["runs"][0]["tool"]
    assert tool["extensions"][0]["name"] == report.ZAP_COMPONENT_NAME
    assert tool["driver"]["name"] == report.DRIVER_NAME
    # the ZAP rule is in namespace 1, on the extension
    assert [r["id"] for r in tool["extensions"][0]["rules"]] == ["40018"]


def test_correlated_result_links_to_zap_rule_across_namespaces():
    findings = [_finding("f-1", plugin="40018")]
    correlated = [{
        "finding_id": "c-0", "pattern": "propagation-shared-handler",
        "origin": "llm-cross-endpoint-synthesis", "severity": "high",
        "confidence": "medium", "title": "propagates",
        "supporting_finding_ids": ["f-1"],
        "affected_routes": ["GET /a", "GET /b"], "suggested_tool": "sqlmap",
    }]
    doc = report.build_sarif(_correlation(findings, correlated), None)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)

    driver_rules = {r["id"]: r for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    rule = driver_rules["propagation-shared-handler"]
    # rule -> rule relationship pointing into the ZAP namespace
    targets = [rel["target"]["id"] for rel in rule["relationships"]]
    assert "40018" in targets
    assert rule["relationships"][0]["target"]["toolComponent"]["name"] == "owasp-zap"

    # result -> result link via guids
    corr_result = [r for r in doc["runs"][0]["results"]
                   if r["properties"]["namespace"] == "dast-synthesis"][0]
    assert corr_result["properties"]["supportingFindingGuids"] == [report._guid("f-1")]


def test_synthesis_rules_follow_first_appearance_order_not_set_order():
    # Regression: the synthesis-rule namespace was built by iterating a *set* of
    # patterns, whose order is hash-seed-dependent, so the SARIF and its
    # cross-rule relationships serialised differently per process and the report
    # was not byte-reproducible. Rules must follow the claims' first-appearance
    # order. The chosen order ("systemic-absence" before "propagation-shared-
    # handler") is neither alphabetical nor guaranteed by a set, so it pins the
    # intended ordering specifically.
    findings = [_finding("f-1", plugin="40038"), _finding("f-2", plugin="40021")]
    correlated = [
        {"finding_id": "c-0", "pattern": "systemic-absence",
         "origin": "llm-cross-endpoint-synthesis", "severity": "high",
         "confidence": "medium", "title": "systemic", "supporting_finding_ids": ["f-1"],
         "affected_routes": ["GET /a"], "suggested_tool": "none"},
        {"finding_id": "c-1", "pattern": "propagation-shared-handler",
         "origin": "llm-cross-endpoint-synthesis", "severity": "high",
         "confidence": "medium", "title": "prop", "supporting_finding_ids": ["f-2"],
         "affected_routes": ["GET /b"], "suggested_tool": "sqlmap"},
    ]
    corr = _correlation(findings, correlated)
    expected = ["systemic-absence", "propagation-shared-handler"]
    first = [r["id"] for r in report.build_sarif(corr, None)["runs"][0]["tool"]["driver"]["rules"]]
    assert first == expected
    # identical on every rebuild (no set/dict-iteration order leaking through)
    for _ in range(5):
        again = [r["id"] for r in report.build_sarif(corr, None)["runs"][0]["tool"]["driver"]["rules"]]
        assert again == expected


def test_guid_is_deterministic():
    assert report._guid("f-1") == report._guid("f-1")
    assert report._guid("f-1") != report._guid("f-2")


def test_risk_sets_level_and_verification_does_not_downgrade():
    finding = _finding("f-1", risk="High")
    verification = {
        "verifications": [{"finding_id": "f-1", "tool": "sqlmap", "outcome": REFUTED,
                           "detail": "clean"}],
        "correlated_verifications": [],
        "source_artifact": "triage-x.json",
    }
    doc = report.build_sarif(_correlation([finding]), verification)
    result = doc["runs"][0]["results"][0]
    # refuted, but High risk keeps it at error level (not hidden)
    assert result["level"] == "error"
    assert result["properties"]["verification"]["outcome"] == REFUTED


def test_summary_md_reports_three_verdicts_and_confirmed(tmp_path):
    findings = [_finding("f-1")]
    verification = {
        "budget": {"max_dispatches": 40},
        "summary": {"selected": 1, "correlated_selected": 0, "dispatched": 1,
                    "by_outcome": {CONFIRMED: 1},
                    "by_tool": {"sqlmap": {CONFIRMED: 1}}},
        "verifications": [{"finding_id": "f-1", "rule_name": "SQL Injection",
                           "tool": "sqlmap", "outcome": CONFIRMED,
                           "evidence": "is vulnerable"}],
        "correlated_verifications": [],
        "source_artifact": "triage-x.json",
    }
    md = report.build_summary_md(_correlation(findings), verification)
    assert "Confirmed by an independent tool" in md
    assert "SQL Injection" in md
    assert "| sqlmap |" in md


# -- report shape: a missing stage has no section --------------------------


def _cve_detection():
    return {
        "target": "grafana", "target_version": "8.3.0",
        "auth_mode": "none", "oracle_guided": True,
        "summary": {
            "markers_total": 2,
            "by_outcome": {"detected": 1, "reached-unconfirmed": 0,
                           "unreached": 0, "not-applicable": 1},
            "outcomes": {
                "detected": ["grafana-plugin-path-traversal"],
                "reached-unconfirmed": [],
                "unreached": [],
                "not-applicable": ["grafana-teams-api-idor"],
            },
            "observe": {"in-band": 1, "oob": 0, "none": 1},
            "reached": 1,
        },
        "markers": [
            {"marker_id": "grafana-plugin-path-traversal", "auth": "none",
             "reach": "reached", "observe": "in-band", "outcome": "detected",
             "zap_detected": True, "zap_detected_strict": True},
            {"marker_id": "grafana-teams-api-idor", "auth": "user",
             "reach": "none", "observe": "none", "outcome": "not-applicable",
             "zap_detected": False, "zap_detected_strict": False},
        ],
    }


def test_the_ground_truth_section_renders_when_assessed():
    # The measured single-run model: the per-marker outcome distribution and the
    # per-layer counts surfaced in the report itself, not only in cve-detection.json.
    md = report.build_summary_md(_correlation([]), None,
                                 cve_detection=_cve_detection())
    assert "measured, not asserted" in md.lower()
    assert "detected" in md and "grafana-plugin-path-traversal" in md
    assert "not-applicable" in md and "grafana-teams-api-idor" in md
    # single-run, never a ladder/rate of its own
    assert "two-run comparison" in md.lower()
    headings = [line for line in md.splitlines() if line.startswith("## ")]
    assert any("Ground truth" in h for h in headings)


def test_the_ground_truth_section_is_absent_without_an_assessment():
    # Ground truth is optional: a markerless target (or a scan-only run) has no
    # cve-detection.json, and the section is omitted rather than shown empty.
    md = report.build_summary_md(_correlation([]), None, cve_detection=None)
    assert "measured cve detection" not in md.lower()
    headings = [line for line in md.splitlines() if line.startswith("## ")]
    assert not any("Ground truth" in h for h in headings)


def test_a_stage_that_did_not_run_has_no_section():
    # Not a heading with "n/a" under it: a report of a partial run should read
    # as a shorter report, not a full one with holes. A heading that is always
    # present stops carrying information.
    correlation = {
        "run_id": "20260101T000000Z-gitea", "run": {"target": "http://t:3000"},
        "summary": {"findings": 3, "deterministic_rescans": 1, "raw_alerts": 9,
                    "bundles": 2},
    }
    md = report.build_summary_md(correlation, verification_artifact=None, scan=None)
    headings = [line for line in md.splitlines() if line.startswith("## ")]
    assert not any("Verification" in h for h in headings)
    assert not any("Scan shape" in h for h in headings)
    # …and the numbering follows what survived, with no gaps.
    numbers = [int(h.split(".")[0].removeprefix("## ")) for h in headings
               if h.removeprefix("## ")[0].isdigit()]
    assert numbers == list(range(1, len(numbers) + 1))


def test_the_overview_leads_and_says_what_was_confirmed():
    correlation = {
        "run_id": "R", "run": {"target": "http://t:3000"},
        "summary": {"findings": 3, "raw_alerts": 9, "bundles": 2,
                    "deterministic_rescans": 1, "llm_rescans": 1},
    }
    verification = {"summary": {"by_outcome": {"confirmed": 1, "refuted": 2},
                                "dispatched": 3, "selected": 3,
                                "correlated_selected": 0}}
    md = report.build_summary_md(correlation, verification, scan={"auth_mode": "none"})
    head = md[:md.index("## 1.")]
    assert "## Overview" in head
    assert "1 confirmed" in head
    # A sentence a reader can quote, before any section.
    assert "reproduced by an independent tool" in head


def test_a_truncated_scan_says_so_before_any_number_is_quoted():
    correlation = {"run_id": "R", "run": {}, "summary": {"findings": 1}}
    md = report.build_summary_md(
        correlation, None, scan={"active_scan_outcome": "timeout"}
    )
    head = md[:md.index("## 1.")]
    assert "lower bound" in head


# -- run limits reach both the Markdown section and the SARIF --------------

def test_the_limits_section_names_every_ceiling_a_stage_hit(tmp_path):
    from dast_orchestrator.foundation import metrics as run_metrics
    run_id = "20260101T000000Z-gitea"
    scan = run_metrics.RunMetrics(run_id, kind="scan")
    with scan.stage("active_scan") as st:
        st.counters.update(truncated_by_cap=True, cap_minutes=45, urls_in_tree=5251)
    scan.record_results(active_scanner_alerts=0)
    scan.write(tmp_path)

    md = report.build_summary_md(_correlation([]), None, data_dir=tmp_path)
    assert "Run limits" in md
    assert "`active_scan_cap_minutes`" in md
    assert "`active_scanner_zero_alerts`" in md
    # The flat aggregation the SARIF `properties.limits` block is built from.
    names = {limit["limit"] for limit in report.run_limits(tmp_path, run_id)}
    assert names == {"active_scan_cap_minutes", "active_scanner_zero_alerts"}


def test_a_run_that_hit_no_limit_says_so_rather_than_hiding_it(tmp_path):
    from dast_orchestrator.foundation import metrics as run_metrics
    run_id = "20260101T000000Z-gitea"
    scan = run_metrics.RunMetrics(run_id, kind="scan")
    with scan.stage("active_scan") as st:
        st.counters.update(truncated_by_cap=False, cap_minutes=45, urls_in_tree=932)
    scan.record_results(active_scanner_alerts=7)
    scan.write(tmp_path)

    md = report.build_summary_md(_correlation([]), None, data_dir=tmp_path)
    assert "No stage hit a configured limit" in md


# -- the reproducibility signal has to reach the reader ---------------------

def _corr(claims):
    return {"correlated_findings": claims, "findings": [], "summary": {}}


def test_a_sampled_run_shows_which_claims_recur_and_ranks_by_it():
    """Sampling that surfaces more claims while hiding which hold up is worse.

    62% of synthesis claims appear in one run of a corpus; a claim from 1 of 5
    samples recurs ~6% of the time against ~67% for one from all 5. The report
    is where that distinction has to land.
    """
    section = report._correlated_section(_corr([
        {"finding_id": "c-000", "pattern": "p", "title": "one-off",
         "supporting_finding_ids": ["f-1"], "reproducibility": {"seen_in": 1, "of": 5}},
        {"finding_id": "c-001", "pattern": "q", "title": "solid",
         "supporting_finding_ids": ["f-2"], "reproducibility": {"seen_in": 5, "of": 5}},
    ]))
    text = "\n".join(section)

    assert "5 independent whole-corpus samples" in text
    assert "**1 of 2** were produced by more than one sample" in text
    assert "lead, not a result" in text
    # Most-reproduced first: the ordering is the recommendation.
    assert text.index("solid") < text.index("one-off")
    # And it must not be sold as a quality ranking.
    assert "reproducibility, not importance" in text


def test_an_unsampled_or_older_artifact_renders_exactly_as_before():
    """No `reproducibility` means the run never measured it — say nothing."""
    section = report._correlated_section(_corr([
        {"finding_id": "c-000", "pattern": "p", "title": "single call",
         "supporting_finding_ids": ["f-1"]},
    ]))
    text = "\n".join(section)

    assert "samples" not in text
    assert "seen in" not in text
    assert "single call" in text


def test_the_report_leads_with_cross_model_agreement_when_there_was_an_ensemble():
    correlated = [
        {"finding_id": "c-000", "pattern": "shared-handler", "severity": "High",
         "confidence": "medium", "title": "Reached by two models",
         "supporting_finding_ids": ["f-1"],
         "reproducibility": {"seen_in": 2, "of": 6,
                             "models_agreeing": 2, "of_models": 2}},
        {"finding_id": "c-001", "pattern": "other", "severity": "Low",
         "confidence": "low", "title": "One model, three draws",
         "supporting_finding_ids": ["f-2"],
         "reproducibility": {"seen_in": 3, "of": 6,
                             "models_agreeing": 1, "of_models": 2}},
    ]
    text = "\n".join(report._correlated_section(_corr(correlated)))
    assert "2 different models" in text
    # Agreement outranks the sample count in the ordering, and the badge says so.
    assert text.index("Reached by two models") < text.index("One model, three draws")
    assert "2/2 models" in text


def test_a_single_model_run_says_nothing_about_models():
    correlated = [
        {"finding_id": "c-000", "pattern": "p", "severity": "Low",
         "confidence": "low", "title": "t", "supporting_finding_ids": ["f-1"],
         "reproducibility": {"seen_in": 5, "of": 5}},
    ]
    text = "\n".join(report._correlated_section(_corr(correlated)))
    assert "models" not in text.lower().replace("model_", "")


def test_the_report_says_whether_a_finding_came_from_zap_or_was_synthesized():
    """The distinction this architecture exists to make, said on every line.

    A ZAP finding is a rule firing on a request the scanner made; a synthesized
    one is a claim the LLM layer built across endpoints, tied to no single
    alert. They are evidenced differently and they fail differently, so a
    report that mixes them silently lets the second borrow the first's
    credibility. The marker leads each line rather than trailing it: a reader
    decides what to trust before reading the claim, not after.
    """
    findings = [{
        "finding_id": "f-1", "alert": {"name": "SQL Injection", "risk": "High",
                                       "plugin_id": "40018"},
        "deterministic": {"needs_rescan": True, "tool": "sqlmap"},
    }]
    synthesis = [{
        "finding_id": "c-0", "title": "One handler, three routes",
        "severity": "medium", "suggested_tool": "out-of-scope",
        "affected_routes": ["/a", "/b"], "cited_finding_ids": ["f-1"],
    }]
    text = "\n".join(report._disposition_section(findings, [], synthesis, []))

    assert "`[ZAP]` `f-1`" in text
    assert "`[SYNTHESIZED]` `c-0`" in text
    assert "**1 came from a ZAP alert**" in text
    assert "**1 were SYNTHESIZED**" in text


def test_the_propagation_section_reports_counts_not_a_route_table():
    """Per-route detail belongs to the artifact, not to the report.

    `sibling_verifications` carries every predicted route with its status and
    outcome; the report says how many were probed and names the CONFIRMED ones,
    because those are the only ones that are findings.
    """
    artifact = {
        "summary": {"siblings": {"considered": 3, "claims": 1, "probed": 1,
                                 "by_outcome": {"refuted": 1},
                                 "routes_not_served": 1,
                                 "routes_not_probeable": 1}},
        "sibling_verifications": [
            {"claim_id": "c-0", "route": "GET /issues", "route_status": 200,
             "outcome": "refuted", "finding_id": "s-1"},
            {"claim_id": "c-0", "route": "GET /gone", "route_status": 404,
             "outcome": "sibling-unreachable", "finding_id": "s-2"},
            {"claim_id": "c-0", "route": "GET /err", "route_status": 500,
             "outcome": "sibling-not-probeable", "finding_id": "s-3"},
        ],
    }
    text = "\n".join(report._propagation_section(artifact))
    assert "| route |" not in text and "| claim |" not in text
    assert "1 probed of 3 considered" in text
    # The counts that say what happened to the rest are still there.
    assert "1 of them are not served at all" in text
    assert "1 are served but were not probed" in text


# -- disposition travels into the SARIF, from the summary's own classifier -----


def _verif(findings_v=None, corr_v=None, siblings=None):
    return {
        "budget": {"max_dispatches": 40},
        "summary": {"selected": 0, "correlated_selected": 0, "dispatched": 0,
                    "by_outcome": {}, "by_tool": {}},
        "verifications": findings_v or [],
        "correlated_verifications": corr_v or [],
        "sibling_verifications": siblings or [],
        "source_artifact": "triage-x.json",
    }


def test_every_sarif_result_carries_the_summary_s_disposition():
    """`properties.disposition` is computed by the SAME classifier the Markdown
    summary reads, so the two outputs can never disagree about an item.

    A ZAP finding a tool reproduced is `confirmed`; an out-of-scope synthesis
    claim is `requires-triage` — the honest manual-evaluation set. Each carries
    its one-line reason, and the pair is asserted byte-identical to what
    `verification.disposition_report` (the summary's own call) produces.
    """
    findings = [_finding("f-1", risk="High")]
    correlated = [{
        "finding_id": "c-0", "pattern": "propagation-shared-handler",
        "severity": "high", "title": "propagates",
        "supporting_finding_ids": ["f-1"],
        "affected_routes": ["GET /a"], "suggested_tool": "out-of-scope",
    }]
    verification = _verif(
        findings_v=[{"finding_id": "f-1", "tool": "sqlmap", "outcome": CONFIRMED}])
    doc = report.build_sarif(_correlation(findings, correlated), verification)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)   # still valid 2.1.0

    by_id = {r["properties"]["finding_id"]: r for r in doc["runs"][0]["results"]}
    assert by_id["f-1"]["properties"]["disposition"] == "confirmed"
    assert "reproduced it" in by_id["f-1"]["properties"]["disposition_reason"]
    assert by_id["c-0"]["properties"]["disposition"] == "requires-triage"
    assert "out of scope" in by_id["c-0"]["properties"]["disposition_reason"]

    # Byte-identical to the summary's own disposition_report over the same inputs.
    from dast_orchestrator.domain import verification as verif_mod
    summary = verif_mod.disposition_report(
        findings, verification["verifications"], correlated,
        verification["correlated_verifications"])
    want = {row["finding_id"]: (disp, row["reason"])
            for disp, rows in summary["buckets"].items() for row in rows}
    for fid, result in by_id.items():
        assert (result["properties"]["disposition"],
                result["properties"]["disposition_reason"]) == want[fid]


def test_a_confirmed_sibling_carries_disposition_and_the_gitlab_location_fields():
    # A sibling (`s-` id) is a confirmed finding classified by the SAME function
    # every tool-confirmed result uses, and — optional — mirrors the finding's
    # GitLab location fields: method + probed parameter, in the SARIF-native
    # webRequest and (mirrored) the property bag.
    findings = [_finding("f-1")]
    sibling = {"finding_id": "s-abc", "claim_id": "c-0", "route": "GET /other",
               "via_finding_id": "f-1", "target": "http://t/other?q=1",
               "tool": "nuclei", "method": "GET", "param": "q",
               "outcome": CONFIRMED, "evidence": "reached sink", "detail": "d",
               "url_source": "route-template", "rule_name": "Propagated XSS"}
    doc = report.build_sarif(_correlation(findings), _verif(siblings=[sibling]))
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)

    sib = next(r for r in doc["runs"][0]["results"]
               if str(r["properties"]["finding_id"]).startswith("s-"))
    assert sib["properties"]["disposition"] == "confirmed"
    assert "reproduced it" in sib["properties"]["disposition_reason"]
    wr = sib["webRequest"]
    assert wr["method"] == "GET"
    assert wr["target"] == "http://t/other?q=1"
    assert wr["parameters"] == {"q": ""}   # attack value not kept on the record
    assert sib["properties"]["method"] == "GET"
    assert sib["properties"]["param"] == "q"


# -- the worklist: the reader's order, in the summary and the SARIF ------------


def _rule_finding(fid, plugin, name, risk="Medium", det=True, path=None):
    return {"finding_id": fid, "path": path or f"/{fid}",
            "alert": {"plugin_id": plugin, "name": name, "risk": risk, "confidence": "Medium"},
            "deterministic": {"needs_rescan": det}}


def test_every_open_rule_is_named_however_long_the_list():
    # The old 15-row cap showed 2 of 12 rule families on a real Cacti run.
    findings = [_rule_finding(f"f-{i:03}", str(9000 + i % 20), f"Rule {i % 20}")
                for i in range(400)]
    text = "\n".join(report._disposition_section(findings, []))
    for number in range(20):
        assert f"**Rule {number}**" in text
    assert "more (see" not in text
    assert "400 findings on 20 rules" in text


def test_an_open_line_gives_its_count_routes_and_why_in_plain_words():
    findings = [_rule_finding("f-1", "40018", "SQL Injection", "High"),
                _rule_finding("f-2", "40018", "SQL Injection", "High")]
    verifs = [{"finding_id": "f-1", "outcome": "not-attempted", "not_attempted_reason": "budget"},
              {"finding_id": "f-2", "outcome": "inconclusive", "tool": "sqlmap"}]
    text = "\n".join(report._disposition_section(findings, verifs))
    assert "2 findings on 2 route(s)" in text
    assert "Open because: 1 the budget ran out, 1 a tool was inconclusive" in text


def test_the_summary_separates_reproduced_from_evident():
    # Saying "1433 confirmed" under an overview saying "0 confirmed" misreads as a contradiction.
    findings = [_rule_finding("f-h", "10038", "CSP", det=False),
                _rule_finding("f-t", "40018", "SQL Injection", "High")]
    verifs = [{"finding_id": "f-t", "outcome": "confirmed", "tool": "sqlmap"}]
    text = "\n".join(report._disposition_section(findings, verifs))
    assert "**1 reproduced by a tool**" in text
    assert "**1 evident from the captured response**" in text
    assert "No tool read these" in text
    assert text.index("### Reproduced by a tool") < text.index("### Evident from the captured")


def test_the_risk_matrix_shows_what_became_of_zap_s_high_findings():
    findings = [_rule_finding("f-1", "40018", "SQL Injection", "High"),
                _rule_finding("f-2", "6", "Traversal", "High")]
    verifs = [{"finding_id": "f-2", "outcome": "refuted", "tool": "ffuf"}]
    md = report.build_summary_md(_correlation(findings),
                                 _verif(findings_v=verifs))
    assert md.index("ZAP's risk against what the chain settled") < md.index("Disposition —")
    assert "| High | 2 | 0 | 0 | 1 | 1 | 0 |" in md
    assert ("Of ZAP's **2** High findings, **0** were reproduced by a tool, **1** were "
            "refuted and **1** stay open") in md


def test_only_an_unsettled_claim_is_called_a_lead():
    def claim(fid, tool, supporting=("f-h",)):
        return {"finding_id": fid, "title": fid, "severity": "medium", "pattern": "p",
                "suggested_tool": tool, "supporting_finding_ids": list(supporting),
                "affected_routes": ["GET /a"], "reproducibility": {"seen_in": 1, "of": 5}}

    findings = [_rule_finding("f-h", "10038", "CSP", det=False)]
    lines = report._disposition_section(
        findings, [], [claim("c-open", "out-of-scope"), claim("c-settled", "self-evident")], [])
    by_id = {fid: next(ln for ln in lines if f"`{fid}`" in ln) for fid in ("c-open", "c-settled")}
    assert "lead, not a result" in by_id["c-open"]
    assert "lead, not a result" not in by_id["c-settled"]
    assert "seen in 1/5 samples" in by_id["c-settled"]


def test_a_run_with_no_findings_has_no_risk_matrix():
    md = report.build_summary_md(_correlation([]), None)
    assert "ZAP's risk against" not in md


def test_report_md_keeps_what_the_analyzer_parses():
    # Copies of Thesis-Analyzer's spread.py patterns: the funnel and the thesis scripts read
    # these three lines out of report.md, with `*` already stripped.
    import re

    findings = [_rule_finding("f-1", "40018", "SQL Injection", "High"),
                _rule_finding("f-2", "10096", "Timestamp", "Low", det=False)]
    verification = _verif(findings_v=[{"finding_id": "f-1", "outcome": "not-attempted",
                                       "not_attempted_reason": "budget"}])
    verification["summary"]["by_outcome"] = {"confirmed": 3, "refuted": 4, "inconclusive": 5,
                                             "not-attempted": 6}
    md = report.build_summary_md(_correlation(findings), verification).replace("*", "")

    alerts = re.search(r"alerts.{1,8}findings\s*\|\s*([\d,]+)\D+?([\d,]+)\s+across", md)
    assert alerts and alerts.groups() == ("10", "2")
    verified = re.search(r"verified\s*\|\s*(\d+)\s*confirmed,\s*(\d+)\s*refuted,"
                         r"\s*(\d+)\s*inconclusive,\s*(\d+)\s*not", md)
    assert verified and verified.groups() == ("3", "4", "5", "6")
    triage = re.search(r"([\d,]+)\s*require triage", md)
    assert triage and triage.group(1) == "2"


def test_every_sarif_result_carries_its_place_and_stays_schema_valid():
    findings = [_finding("f-1", risk="High"), _finding("f-2", risk="High")]
    correlated = [{"finding_id": "c-0", "pattern": "propagation-shared-handler",
                   "severity": "high", "title": "propagates", "supporting_finding_ids": ["f-1"],
                   "affected_routes": ["GET /a"], "suggested_tool": "out-of-scope"}]
    sibling = {"finding_id": "s-abc", "claim_id": "c-0", "route": "GET /other",
               "via_finding_id": "f-1", "target": "http://t/other?q=1", "tool": "nuclei",
               "method": "GET", "param": "q", "outcome": CONFIRMED, "rule_name": "Propagated"}
    doc = report.build_sarif(_correlation(findings, correlated), _verif(siblings=[sibling]))
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)

    results = {r["properties"]["finding_id"]: r for r in doc["runs"][0]["results"]}
    for result in results.values():
        assert 0.0 <= result["rank"] <= 100.0
        assert result["properties"]["worklist_section"] in report.verification.SECTIONS
        assert result["properties"]["worklist_line"] >= 1
    # One rule's findings share a group, which is how a reader's line is counted.
    assert (results["f-1"]["properties"]["worklist_group"]
            == results["f-2"]["properties"]["worklist_group"])
    assert results["s-abc"]["rank"] > results["f-1"]["rank"] > results["c-0"]["rank"]


def test_the_order_never_touches_level_and_never_sets_kind():
    # SARIF 3.27.10: `level` must be `none` on any kind but `fail`, and ZAP's risk owns level.
    finding = _finding("f-1", risk="High")
    verification = _verif(findings_v=[{"finding_id": "f-1", "tool": "sqlmap", "outcome": REFUTED}])
    result = report.build_sarif(_correlation([finding]), verification)["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["properties"]["worklist_section"] == "refuted"
    assert "kind" not in result


def test_a_result_carries_zap_s_instance_count_when_it_has_a_real_one():
    counted, uncounted = _finding("f-1"), _finding("f-2", plugin="6")
    counted["alert"]["instances"] = 7
    uncounted["alert"]["instances"] = 0
    doc = report.build_sarif(_correlation([counted, uncounted]), None)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)
    results = {r["properties"]["finding_id"]: r for r in doc["runs"][0]["results"]}
    assert results["f-1"]["occurrenceCount"] == 7
    assert "occurrenceCount" not in results["f-2"]


def test_the_target_and_zap_version_come_from_where_triage_writes_them():
    # A real triage artifact has `source`, not `run`: reading only `run` printed target `?`.
    correlation = _correlation([_finding("f-1")])
    del correlation["run"]
    correlation["source"] = {"target": "http://target-cacti", "zap_version": "2.17.0"}
    md = report.build_summary_md(correlation, None, scan={"auth_mode": "none"})
    assert "| target | `http://target-cacti` (auth `none`) |" in md
    assert "| ZAP version | 2.17.0 |" in md
    run = report.build_sarif(correlation, None)["runs"][0]
    assert run["tool"]["extensions"][0]["version"] == "2.17.0"
    assert run["properties"]["source_triage"]["target"] == "http://target-cacti"


def test_the_sarif_invocation_records_the_run_window():
    # Optional: invocations[0] carries the analysis window in RFC-3339, from the
    # run id (start) and the latest artifact generated_at (end).
    doc = report.build_sarif(_correlation([_finding("f-1")]), None)
    jsonschema.Draft7Validator(SARIF_SCHEMA).validate(doc)
    inv = doc["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["startTimeUtc"] == "2026-01-01T00:00:00Z"
    assert inv["endTimeUtc"] == "2026-01-01T00:00:00Z"
