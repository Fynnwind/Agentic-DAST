"""Unit tests for pass 2, the cross-endpoint synthesis pass.

The pass exists because pass 1 structurally cannot produce cross-endpoint
findings: it sees one endpoint per call. So what is tested here is mostly that
the corpus genuinely carries the *cross*-endpoint signal — the shared-handler
map above all — and that a synthesis finding citing no observed evidence is
thrown away rather than stored.
"""

from __future__ import annotations

import json
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import jsonschema
import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis import synthesize
from dast_orchestrator.analysis.join import RunArtifacts
from dast_orchestrator.adapters.noir_runner import (
    build_ai_context_artifact,
    build_seed_map_artifact,
    parse_endpoints,
)

FIXTURES = FIXTURES_DIR


@pytest.fixture
def run() -> RunArtifacts:
    endpoints = parse_endpoints(
        json.loads((FIXTURES / "noir-gitea-sample.json").read_text())
    )
    return RunArtifacts(
        timestamp="20260817T114501Z",
        ai_context=build_ai_context_artifact(endpoints, Path("/src"), "20260817T114501Z"),
        zap_report=json.loads((FIXTURES / "zap-alerts-sample.json").read_text()),
        seed_map=build_seed_map_artifact(
            endpoints, "http://target-gitea:3000", "20260817T114501Z"
        ),
        ai_context_path=Path("a.json"),
        zap_report_path=Path("b.json"),
        seed_map_path=Path("c.json"),
    )


@pytest.fixture
def bundles(run):
    return join.build_bundles(run)


@pytest.fixture
def findings(bundles):
    return join.build_findings(bundles)


@pytest.fixture
def corpus(bundles, findings):
    summary = join.summarise(bundles, findings, [])
    return synthesize.build_corpus(bundles, findings, summary)


# -- the corpus ------------------------------------------------------------


def test_corpus_holds_many_endpoints_at_once(corpus):
    # The whole point: pass 1 sees one endpoint per call and therefore cannot
    # correlate across endpoints. If this ever collapses to one, the pass is
    # pointless.
    assert len(corpus["endpoints"]) > 1


def test_corpus_drops_informational_noise_but_says_so(corpus, findings):
    shown = corpus["scan_shape"]["findings_shown"]
    suppressed = corpus["scan_shape"]["findings_suppressed_as_informational_noise"]
    assert shown + suppressed == len(findings)
    # A model shown a filtered view must be told it is filtered, or it will read
    # the absence of a rule as a property of the target.
    assert "filter" in corpus["note_on_suppression"]


def test_corpus_keeps_findings_the_control_arm_already_flagged(corpus):
    # Informational-risk findings that the table flags for rescan (10031) stay
    # in, because a cross-cutting pattern can rest on them.
    flagged = [
        f
        for endpoint in corpus["endpoints"]
        for f in endpoint["findings"]
        if f["already_flagged_for_rescan"]
    ]
    assert flagged


def test_corpus_carries_static_names_without_source_snippets(corpus):
    # Shallow-but-wide is what makes one call affordable. Pass 1 already read
    # the code in depth; repeating snippets here would blow the budget that
    # breadth needs.
    blob = json.dumps(corpus)
    assert "snippet" not in blob
    with_context = [e for e in corpus["endpoints"] if e["static_context"] == "present"]
    assert any("guards" in e or "callees" in e for e in with_context)


def test_shared_handlers_link_routes_that_share_code():
    # The propagation signal, built by hand so the relationship is unambiguous:
    # two routes reaching one handler, one of which carries a finding.
    from dast_orchestrator.analysis.join import AlertGroup, Bundle

    def bundle(key: str, callee: str, groups=()) -> Bundle:
        return Bundle(
            endpoint_key=key,
            match_how="seed",
            method="GET",
            path=key.split(" ", 1)[1],
            static_context={
                "path": key.split(" ", 1)[1],
                "ai_context": {"callees": [{"name": callee, "confidence": 90}]},
            },
            groups=list(groups),
        )

    hit = AlertGroup(
        plugin_id="40018", name="SQL Injection", risk="High", confidence="Medium",
        param="q", evidence="", method="GET", zap_alert_ids=["1"],
    )
    scanned = bundle("GET /a", "repo.Shared", [hit])
    unscanned = bundle("GET /b", "repo.Shared")
    shared = synthesize.shared_handlers([scanned, unscanned], {"GET /a"})
    assert shared["repo.Shared"] == ["GET /a", "GET /b"]


def test_a_handler_shared_by_everything_is_not_a_link():
    # Gitea's `bindIgnErr` is on 110 routes; it connects nothing to anything in
    # particular and would drown the real links.
    from dast_orchestrator.analysis.join import Bundle

    many = [
        Bundle(
            endpoint_key=f"GET /r{i}", match_how="seed", method="GET", path=f"/r{i}",
            static_context={
                "path": f"/r{i}",
                "ai_context": {"callees": [{"name": "bindIgnErr", "confidence": 90}]},
            },
        )
        for i in range(join.MAX_ENDPOINTS_PER_SHARED_HANDLER + 5)
    ]
    assert "bindIgnErr" not in synthesize.shared_handlers(many, {"GET /r0"})


def test_a_shared_handler_with_no_findings_is_not_a_correlation():
    from dast_orchestrator.analysis.join import Bundle

    quiet = [
        Bundle(
            endpoint_key=f"GET /q{i}", match_how="seed", method="GET", path=f"/q{i}",
            static_context={
                "path": f"/q{i}",
                "ai_context": {"callees": [{"name": "repo.Quiet", "confidence": 90}]},
            },
        )
        for i in range(2)
    ]
    assert synthesize.shared_handlers(quiet, set()) == {}


# -- the contract ----------------------------------------------------------


def test_synthesis_schema_is_valid_and_forbids_alert_verdicts():
    jsonschema.Draft202012Validator.check_schema(synthesize.SYNTHESIS_SCHEMA)
    # Pass 2 must not re-triage; that is pass 1's job and its numbers.
    assert "alert_verdicts" not in synthesize.SYNTHESIS_SCHEMA["properties"]


def test_recorded_synthesis_response_matches_the_schema():
    raw = json.loads((FIXTURES / "openrouter-synthesis-response.json").read_text())
    payload = json.loads(raw["choices"][0]["message"]["content"])
    for item in payload["correlated_findings"]:
        item.pop("supporting_alert_ids", None)  # tolerated extra in the recording
    jsonschema.validate(payload, synthesize.SYNTHESIS_SCHEMA)


def test_messages_are_system_plus_one_json_corpus(corpus):
    messages = synthesize.build_messages(corpus)
    assert [m["role"] for m in messages] == ["system", "user"]
    json.loads(messages[1]["content"])


# -- validation ------------------------------------------------------------


def test_findings_citing_no_real_evidence_are_dropped(findings):
    raw = json.loads((FIXTURES / "openrouter-synthesis-response.json").read_text())
    real = findings[0]["finding_id"]
    text = (
        raw["choices"][0]["message"]["content"]
        .replace("__SQLI_MEDIUM__", real)
        .replace("__SQLI_HIGH__", real)
    )
    kept, dropped = synthesize.collect(
        json.loads(text), [f["finding_id"] for f in findings]
    )
    # The fixture holds one evidenced finding and one citing an invented id.
    assert len(kept) == 1
    assert dropped == 1
    assert kept[0]["pattern"] == "propagation-shared-handler"
    assert kept[0]["origin"] == "llm-cross-endpoint-synthesis"
    assert kept[0]["supporting_finding_ids"] == [real]


def test_affected_routes_may_include_routes_the_scanner_never_flagged(findings):
    # This is the value of the pass: naming code the scan never reached.
    raw = json.loads((FIXTURES / "openrouter-synthesis-response.json").read_text())
    real = findings[0]["finding_id"]
    text = (
        raw["choices"][0]["message"]["content"]
        .replace("__SQLI_MEDIUM__", real)
        .replace("__SQLI_HIGH__", real)
    )
    kept, _ = synthesize.collect(
        json.loads(text), [f["finding_id"] for f in findings]
    )
    assert "GET /user/recover_account" in kept[0]["affected_routes"]


def test_the_same_finding_cited_twice_counts_once(findings):
    real = findings[0]["finding_id"]
    response = {
        "correlated_findings": [
            {
                "title": "t", "pattern": "chain", "severity": "low",
                "confidence": "low", "reasoning": "r",
                "supporting_finding_ids": [real, real, "f-000000000000"],
                "affected_routes": [], "suggested_tool": "self-evident",
            }
        ]
    }
    kept, dropped = synthesize.collect(
        response, [f["finding_id"] for f in findings]
    )
    assert kept[0]["supporting_finding_ids"] == [real]
    assert dropped == 0


# -- pass 1 feeding pass 2 -------------------------------------------------


def _corpus_findings(corpus):
    return [f for e in corpus["endpoints"] for f in e["findings"]]


def test_pass1_verdict_and_reasoning_reach_pass2(bundles, findings):
    # Pass 2 never sees source code. Pass 1's reasoning IS the source read,
    # compressed — without it, pass 2 asserts things about handlers whose
    # contents it knows nothing about.
    target = findings[0]
    target["llm_asked"] = True
    target["llm"] = {
        "needs_rescan": True,
        "verdict": "likely-true-positive",
        "confidence": "high",
        "reasoning": "The handler reaches filepath.Join with an unvalidated segment.",
        "suggested_tool": "ffuf",
    }
    corpus = synthesize.build_corpus(
        bundles, findings, join.summarise(bundles, findings, [])
    )
    seen = {f["finding_id"]: f for f in _corpus_findings(corpus)}
    entry = seen[target["finding_id"]]
    assert entry["pass1_verdict"] == "likely-true-positive"
    assert entry["pass1_wants_rescan"] is True
    assert "filepath.Join" in entry["pass1_reasoning"]


def test_asked_but_unanswered_is_not_reported_as_a_clean_result(bundles, findings):
    # 22 findings on the last run were put to pass 1 and came back with nothing.
    # A synthesis pass that read that as "fine" would build on an absence it
    # mistook for a verdict.
    target = findings[0]
    target["llm_asked"] = True
    target["llm"] = None
    corpus = synthesize.build_corpus(
        bundles, findings, join.summarise(bundles, findings, [])
    )
    entry = {f["finding_id"]: f for f in _corpus_findings(corpus)}[target["finding_id"]]
    assert entry["pass1_verdict"] == "asked-but-unanswered"
    assert "pass1_reasoning" not in entry


def test_never_triaged_is_distinct_from_both(bundles, findings):
    corpus = synthesize.build_corpus(
        bundles, findings, join.summarise(bundles, findings, [])
    )
    assert all(
        f["pass1_verdict"] == "not-screened" for f in _corpus_findings(corpus)
    )


def test_pass1_reasoning_is_trimmed_so_breadth_survives(bundles, findings):
    findings[0]["llm"] = {
        "needs_rescan": False, "verdict": "likely-false-positive",
        "confidence": "low", "reasoning": "word " * 400, "suggested_tool": "self-evident",
    }
    corpus = synthesize.build_corpus(
        bundles, findings, join.summarise(bundles, findings, [])
    )
    for f in _corpus_findings(corpus):
        if "pass1_reasoning" in f:
            assert len(f["pass1_reasoning"]) <= synthesize.MAX_SCREENING_REASONING_CHARS


def test_the_prompt_explains_how_to_read_pass1_output():
    # The fields are useless, and actively dangerous, if the model is not told
    # that an unanswered triage is missing information rather than a pass.
    prompt = synthesize.SYNTHESIS_SYSTEM_PROMPT
    for field in ("pass1_reasoning", "asked-but-unanswered", "not-screened",
                  "likely-false-positive", "likely-true-positive"):
        assert field in prompt
    assert "NOT a clean bill of health" in prompt


def test_guards_carry_their_semantics_not_just_their_name(bundles, findings):
    # Noir tags Gitea's session middleware as an auth_guard on every public
    # route. A bare name reads as "protected"; pass 2 believed that and called
    # public routes protected, then invented route groups to justify it.
    corpus = synthesize.build_corpus(
        bundles, findings, join.summarise(bundles, findings, [])
    )
    guards = [g for e in corpus["endpoints"] for g in e.get("guards", [])]
    assert guards, "fixture should carry at least one guard"
    assert all("(" in g and ")" in g for g in guards)
    assert any("session-plumbing" in g for g in guards)


def test_corpus_can_be_narrowed_for_the_truncation_fallback(bundles, findings):
    # Pass 2 cannot chunk without defeating itself, so the only safe response to
    # a truncation is a narrower corpus — busiest endpoints first.
    summary = join.summarise(bundles, findings, [])
    full = synthesize.build_corpus(bundles, findings, summary)
    narrow = synthesize.build_corpus(bundles, findings, summary, max_endpoints=1)
    assert len(narrow["endpoints"]) == 1
    assert len(narrow["endpoints"]) < len(full["endpoints"])
    # The busiest endpoint survives the narrowing.
    assert narrow["endpoints"][0]["route"] == full["endpoints"][0]["route"]


def test_synthesis_gets_a_larger_ceiling_than_triage():
    from dast_orchestrator.analysis import screening

    # Pass 1 absorbs a truncation by splitting; pass 2 loses the whole pass, so
    # it must not share pass 1's budget. An 8192 ceiling cost a live run.
    assert synthesize.SYNTHESIS_MAX_TOKENS > screening.MAX_TOKENS


# -- repeats: sampling, not chunking ----------------------------------------

def test_a_claim_is_identified_by_its_evidence_not_its_prose():
    """Two calls word the same correlation differently every time."""
    a = {"pattern": "propagation-shared-handler",
         "supporting_finding_ids": ["f-2", "f-1"], "title": "Handler X links A and B"}
    b = {"pattern": "propagation-shared-handler",
         "supporting_finding_ids": ["f-1", "f-2"],
         "title": "Routes A and B share handler X, so the gap propagates"}

    assert synthesize.claim_key(a) == synthesize.claim_key(b)


def test_repeats_are_unioned_and_scored_by_how_many_produced_each():
    common = {"pattern": "p", "supporting_finding_ids": ["f-1"], "title": "seen thrice"}
    rare = {"pattern": "q", "supporting_finding_ids": ["f-9"], "title": "seen once"}
    merged = synthesize.merge_repeats([[common], [common, rare], [common]])

    assert [c["title"] for c in merged] == ["seen thrice", "seen once"]
    assert merged[0]["reproducibility"] == {"seen_in": 3, "of": 3}
    assert merged[1]["reproducibility"] == {"seen_in": 1, "of": 3}


def test_a_claim_repeated_within_one_call_still_counts_once():
    """Otherwise a model that restates itself looks like independent agreement."""
    twice = {"pattern": "p", "supporting_finding_ids": ["f-1"], "title": "x"}
    merged = synthesize.merge_repeats([[twice, dict(twice)], [twice]])

    assert merged[0]["reproducibility"] == {"seen_in": 2, "of": 2}


def test_the_merged_order_is_deterministic_not_arrival_order():
    """Two runs of one scan must diff cleanly, as everywhere else in the pipeline."""
    a = {"pattern": "b-pattern", "supporting_finding_ids": ["f-1"], "title": "A"}
    b = {"pattern": "a-pattern", "supporting_finding_ids": ["f-2"], "title": "B"}

    one = synthesize.merge_repeats([[a], [b]])
    two = synthesize.merge_repeats([[b], [a]])

    assert [c["pattern"] for c in one] == [c["pattern"] for c in two]
    assert [c["finding_id"] for c in one] == ["c-000", "c-001"]


def test_one_sample_reproduces_the_historical_shape():
    single = [{"pattern": "p", "supporting_finding_ids": ["f-1"], "title": "x"}]
    merged = synthesize.merge_repeats([single])

    assert merged[0]["finding_id"] == "c-000"
    assert merged[0]["reproducibility"] == {"seen_in": 1, "of": 1}


# -- the multi-model ensemble ----------------------------------------------

def _claim(pattern, ids, title="x"):
    return {"pattern": pattern, "supporting_finding_ids": list(ids), "title": title}


def test_a_single_model_ensemble_carries_no_agreement_fields():
    """Nothing about the one-model artifact may move; it is the baseline."""
    merged = synthesize.merge_samples([
        synthesize.Sample("m1", [_claim("p", ["f-1"])]),
        synthesize.Sample("m1", [_claim("p", ["f-1"])]),
    ])
    assert merged[0]["reproducibility"] == {"seen_in": 2, "of": 2}


def test_agreement_counts_distinct_models_not_samples():
    shared = _claim("p", ["f-1"])
    solo = _claim("q", ["f-2"])
    merged = synthesize.merge_samples([
        synthesize.Sample("m1", [shared, solo]),
        synthesize.Sample("m1", [shared, solo]),
        synthesize.Sample("m2", [shared]),
    ])
    by_pattern = {c["pattern"]: c["reproducibility"] for c in merged}
    assert by_pattern["p"]["models_agreeing"] == 2
    assert by_pattern["p"]["by_model"] == {"m1": 2, "m2": 1}
    # Two samples, one model: more draws, but no more agreement.
    assert by_pattern["q"]["models_agreeing"] == 1
    assert by_pattern["q"]["seen_in"] == 2


def test_agreement_outranks_sample_count_in_the_order():
    """A claim two models reach once beats one model's four draws of its own idea."""
    agreed = _claim("agreed", ["f-1"])
    repeated = _claim("repeated", ["f-2"])
    merged = synthesize.merge_samples([
        synthesize.Sample("m1", [agreed, repeated]),
        synthesize.Sample("m1", [repeated]),
        synthesize.Sample("m1", [repeated]),
        synthesize.Sample("m2", [agreed]),
    ])
    assert [c["pattern"] for c in merged] == ["agreed", "repeated"]
    assert merged[0]["reproducibility"]["seen_in"] == 2
    assert merged[1]["reproducibility"]["seen_in"] == 3


def test_one_model_claiming_the_same_thing_twice_is_one_draw():
    """Or a repetitive model would outscore an agreeing one."""
    claim = _claim("p", ["f-1"])
    merged = synthesize.merge_samples([
        synthesize.Sample("m1", [claim, dict(claim)]),
        synthesize.Sample("m2", [claim]),
    ])
    assert merged[0]["reproducibility"]["seen_in"] == 2
    assert merged[0]["reproducibility"]["by_model"] == {"m1": 1, "m2": 1}


def test_the_ensemble_order_is_deterministic_not_arrival_order():
    a = synthesize.Sample("m2", [_claim("b-pattern", ["f-1"])])
    b = synthesize.Sample("m1", [_claim("a-pattern", ["f-2"])])
    assert ([c["pattern"] for c in synthesize.merge_samples([a, b])]
            == [c["pattern"] for c in synthesize.merge_samples([b, a])])
