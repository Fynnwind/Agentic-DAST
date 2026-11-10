"""Unit tests for the Noir <-> ZAP join and the bundling that follows it.

The join is the load-bearing piece of Phase 3 — a wrong template match silently
attaches the wrong source code to a finding, and nothing downstream would
notice — so the tiers, the ambiguity ranking and the two "no static context"
reasons are all pinned here.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

#: Shared fixture corpus, one level up now that tests are grouped by kind.
FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"

import pytest

from dast_orchestrator.analysis import join
from dast_orchestrator.analysis.join import (
    CONTEXT_ABSENT_API,
    AlertGroup,
    Bundle,
    CONTEXT_ABSENT_UNMATCHED,
    MATCH_REGEX,
    MATCH_REGEX_PATH_ONLY,
    MATCH_SEED,
    EndpointJoiner,
    RunArtifacts,
)
from dast_orchestrator.adapters.noir_runner import (
    build_ai_context_artifact,
    build_seed_map_artifact,
    parse_endpoints,
    template_specificity,
    template_to_regex,
)

FIXTURES = FIXTURES_DIR
TARGET = "http://target-gitea:3000"


@pytest.fixture
def endpoints():
    return parse_endpoints(json.loads((FIXTURES / "noir-gitea-sample.json").read_text()))


@pytest.fixture
def ai_context(endpoints):
    return build_ai_context_artifact(endpoints, Path("/src"), "20260817T114501Z")


@pytest.fixture
def seed_map(endpoints):
    from dast_orchestrator.adapters import targets
    return build_seed_map_artifact(endpoints, TARGET, "20260817T114501Z", targets.get("gitea").path_vars)


@pytest.fixture
def run(ai_context, seed_map) -> RunArtifacts:
    return RunArtifacts(
        timestamp="20260817T114501Z",
        ai_context=ai_context,
        zap_report=json.loads((FIXTURES / "zap-alerts-sample.json").read_text()),
        seed_map=seed_map,
        ai_context_path=Path("noir-ai-context-20260817T114501Z.json"),
        zap_report_path=Path("zap-alerts-20260817T114501Z.json"),
        seed_map_path=Path("noir-seed-map-20260817T114501Z.json"),
    )


# -- template -> regex, the reverse of substitute_path ---------------------


@pytest.mark.parametrize(
    "template, path, expected",
    [
        ("/explore/repos", "/explore/repos", True),
        ("/user/avatar/{username}/{size}", "/user/avatar/thesis/84", True),
        # A placeholder is one segment, so it must not swallow a separator.
        ("/user/avatar/{username}/{size}", "/user/avatar/thesis/84/extra", False),
        # The inline regex is reused verbatim, braces and all, so it keeps its
        # precision instead of degrading to "any segment".
        (
            "/{u}/{r}/wiki/commit/{sha:[a-f0-9]{7,40}}.{ext}",
            "/thesis/demo/wiki/commit/0a1b2c3.md",
            True,
        ),
        (
            "/{u}/{r}/wiki/commit/{sha:[a-f0-9]{7,40}}.{ext}",
            "/thesis/demo/wiki/commit/nothex.md",
            False,
        ),
        # chi's catch-all may span separators.
        ("/template/*", "/template/a/b/c", True),
    ],
)
def test_template_to_regex(template, path, expected):
    assert bool(template_to_regex(template).match(path)) is expected


def test_specificity_prefers_the_more_literal_template():
    # The real Gitea case: /org/thesis/milestones matches all three.
    ranked = sorted(
        [
            "/{username}/{reponame}/{type}",
            "/{username}/{reponame}/milestones",
            "/org/{org}/milestones",
        ],
        key=template_specificity,
        reverse=True,
    )
    assert ranked[0] == "/org/{org}/milestones"
    assert ranked[-1] == "/{username}/{reponame}/{type}"


# -- the join --------------------------------------------------------------


def test_seed_map_beats_regex(endpoints, seed_map):
    joiner = EndpointJoiner(
        [e for e in build_ai_context_artifact(endpoints, Path("/src"), "x")["endpoints"]],
        seed_map,
    )
    match = joiner.match("GET", "/user/avatar/thesis/84")
    assert match.how == MATCH_SEED
    assert match.endpoint_key == "GET /user/avatar/{username}/{size}"


def test_regex_tier_catches_urls_that_were_never_seeded(ai_context):
    # No seed map at all: a spider-discovered URL still finds its template.
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    match = joiner.match("GET", "/user/avatar/someone-else/512")
    assert match.how == MATCH_REGEX
    assert match.endpoint_key == "GET /user/avatar/{username}/{size}"


def test_path_only_match_is_reported_as_a_weaker_tier(ai_context):
    # /user/login is registered for POST; an alert on the GET of the same path
    # must not silently claim the POST handler's static context.
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    match = joiner.match("GET", "/user/login")
    assert match.how == MATCH_REGEX_PATH_ONLY
    assert match.endpoint_key == "POST /user/login"


def test_api_urls_are_marked_as_the_known_noir_gap(ai_context):
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    match = joiner.match("GET", "/api/v1/repos/thesis/demo/issues")
    assert match.endpoint_key is None
    assert match.how == CONTEXT_ABSENT_API


def test_other_misses_are_not_disguised_as_the_api_gap(ai_context):
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    assert joiner.match("GET", "/admin/monitor").how == CONTEXT_ABSENT_UNMATCHED


def test_a_generic_template_may_not_swallow_an_api_url(ai_context):
    # Regression: /api/v1/notifications has four segments, so it matches the
    # greedy /{username}/{reponame}/{type} template and used to arrive carrying
    # an unrelated repo-view handler's source. Noir sees none of the /api/v1
    # tree, so any such match is a false correlation and must stay labelled as
    # the documented router gap.
    endpoints = ai_context["endpoints"] + [
        {
            "key": "GET /{username}/{reponame}/{type}",
            "method": "GET",
            "path": "/{username}/{reponame}/{type}",
            "technology": "go_chi",
            "ai_context": {},
        }
    ]
    joiner = EndpointJoiner(endpoints, None)
    match = joiner.match("GET", "/api/v1/notifications")
    assert match.endpoint_key is None
    assert match.how == CONTEXT_ABSENT_API


def test_a_real_api_route_keeps_its_match(ai_context):
    # /api/swagger is a genuine routers/web route, which is why the rule is a
    # prefix comparison and not a blanket exclusion of /api/.
    endpoints = ai_context["endpoints"] + [
        {
            "key": "GET /api/swagger",
            "method": "GET",
            "path": "/api/swagger",
            "technology": "go_chi",
            "ai_context": {},
        }
    ]
    joiner = EndpointJoiner(endpoints, None)
    match = joiner.match("GET", "/api/swagger")
    assert match.endpoint_key == "GET /api/swagger"
    assert match.how == MATCH_REGEX


def test_ambiguous_matches_keep_their_alternatives(ai_context):
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    # /template/* also matches this, but the avatar route is more literal.
    match = joiner.match("GET", "/user/avatar/thesis/84")
    assert match.endpoint_key == "GET /user/avatar/{username}/{size}"
    assert "GET /template/*" not in match.alternatives  # different prefix


def test_join_is_deterministic_across_repeated_runs(ai_context):
    joiner = EndpointJoiner(ai_context["endpoints"], None)
    first = [joiner.match("GET", "/user/avatar/a/1") for _ in range(5)]
    assert len({m.endpoint_key for m in first}) == 1


# -- bundling and the deterministic arm ------------------------------------


def test_bundles_collapse_instances_but_not_confidences(run):
    bundles = {b.identifier: b for b in join.build_bundles(run)}
    login = bundles["POST /user/login"]
    # Two SQLi alerts on the same rule but different parameters and
    # confidences: they must stay separate findings, because the control arm
    # decides on confidence.
    assert len(login.groups) == 2
    assert {g.confidence for g in login.groups} == {"Medium", "High"}


def test_findings_carry_both_join_tier_and_control_arm_verdict(run):
    findings = join.build_findings(join.build_bundles(run))
    by_key = {(f["endpoint_key"], f["alert"]["param"]): f for f in findings}

    sqli_medium = by_key[("POST /user/login", "user_name")]
    assert sqli_medium["deterministic"]["needs_rescan"] is True
    assert sqli_medium["deterministic"]["tool"] == "sqlmap"
    assert sqli_medium["static_context"] == MATCH_SEED

    csp = by_key[("GET /explore/repos", "")]
    assert csp["deterministic"]["needs_rescan"] is False
    assert csp["deterministic"]["policy"] == "never"


def test_findings_without_static_context_say_why(run):
    findings = join.build_findings(join.build_bundles(run))
    absent = {f["path"]: f for f in findings if not f["static_context_present"]}
    assert absent["/api/v1/repos/thesis/demo/issues"]["static_context"] == CONTEXT_ABSENT_API
    assert absent["/admin/monitor"]["static_context"] == CONTEXT_ABSENT_UNMATCHED


def test_finding_ids_are_stable_across_rebuilds(run):
    first = {f["finding_id"] for f in join.build_findings(join.build_bundles(run))}
    second = {f["finding_id"] for f in join.build_findings(join.build_bundles(run))}
    assert first == second


#: One passive header alert on a route the fixture registers for POST. Two of
#: these differing in a single field are two findings inside one bundle, which
#: is the shape that collided.
HEADER_ALERT = {
    "id": "900",
    "pluginId": "10036",
    "name": 'Server Leaks Version Information via "Server" HTTP Response Header Field',
    "risk": "Low",
    "confidence": "High",
    "url": f"{TARGET}/user/login",
    "method": "POST",
    "param": "",
    "evidence": "nginx/1.25.3",
    "cweid": "497",
    "wascid": "13",
}


def _with_alerts(run: RunArtifacts, alerts: list[dict]) -> RunArtifacts:
    """The shared run with its ZAP alerts swapped out, everything else intact."""
    return replace(run, zap_report={**run.zap_report, "alerts": alerts})


@pytest.mark.parametrize("field, other_value", [("method", "GET"), ("risk", "Medium")])
def test_findings_differing_in_one_identity_field_get_different_ids(
    run, field, other_value
):
    # Both alerts land in the *same* bundle — a GET on a POST-only route still
    # joins to it, one tier down — so only the id's own hash separates them.
    # Until 2026-09-02 neither `method` nor `risk` reached that hash, and the
    # stored corpus holds 33 ids that address two findings each as a result.
    run = _with_alerts(run, [dict(HEADER_ALERT),
                             {**HEADER_ALERT, "id": "901", field: other_value}])
    findings = join.build_findings(join.build_bundles(run))

    assert len(findings) == 2, "the two alerts must not collapse into one group"
    assert len({f["endpoint_key"] for f in findings}) == 1, "same bundle"
    assert len({f["finding_id"] for f in findings}) == 2


def test_identical_alerts_still_collapse_to_one_finding(run):
    # The other half of the property: widening the hash must not turn one
    # finding into two. Same alert twice, on two concrete URLs.
    avatar = {**HEADER_ALERT, "method": "GET",
              "url": f"{TARGET}/user/avatar/thesis/84"}
    run = _with_alerts(run, [avatar,
                             {**avatar, "id": "901",
                              "url": f"{TARGET}/user/avatar/other/32"}])
    findings = join.build_findings(join.build_bundles(run))

    assert len(findings) == 1
    assert findings[0]["alert"]["instances"] == 2


def test_build_artifact_refuses_to_publish_a_duplicated_finding_id(run):
    # The loud failure: every downstream join (verification, ground truth,
    # SARIF) keys on finding_id and would silently resolve a duplicate to
    # whichever entry came first.
    duplicated = [{"finding_id": "f-aaaaaaaaaaaa"}, {"finding_id": "f-aaaaaaaaaaaa"}]
    with pytest.raises(join.JoinError, match="not unique"):
        join.build_artifact(run, [], duplicated, [], None)


def test_build_artifact_accepts_distinct_ids(run):
    bundles = join.build_bundles(run)
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(run, bundles, findings, [], None)
    assert len(artifact["findings"]) == len(findings)


def test_a_built_triage_artifact_satisfies_its_schema(run):
    # §R5 drift guard: what the join WRITES must match triage-result.schema.json,
    # so the read-time validation never rejects the pipeline's own output.
    from dast_orchestrator.foundation import schema

    bundles = join.build_bundles(run)
    findings = join.build_findings(bundles)
    artifact = join.build_artifact(run, bundles, findings, [], None)
    assert schema.violations("triage.json", artifact) == []


def test_llm_candidates_exclude_informational_only_endpoints(run):
    bundles = {b.identifier: b for b in join.build_bundles(run)}
    # Has a Medium-risk CSP alert alongside the informational one.
    assert join.is_llm_candidate(bundles["GET /explore/repos"]) is True
    # Only a Session Management identification alert: nothing to correlate, and
    # this is the case that keeps the pass down to 52 calls on a real run.
    assert join.is_llm_candidate(bundles["GET /apple-touch-icon.png"]) is False


def test_informational_alerts_the_table_flags_are_still_candidates(run):
    # 10031 is Informational *risk* but ALWAYS rescan: "potential XSS" is
    # exactly the kind of alert that needs an independent probe, so risk alone
    # must not be the filter.
    bundles = {b.identifier: b for b in join.build_bundles(run)}
    assert join.is_llm_candidate(bundles["GET /user/avatar/{username}/{size}"]) is True


def test_asked_but_unanswered_is_not_the_same_as_never_asked(run):
    # The first live run put 277 findings to the model and got 178 back, but the
    # artifact labelled the missing 99 identically to the 726 that were never
    # sent. That makes every agreement percentage misleading, so the two states
    # are kept apart.
    findings = join.build_findings(join.build_bundles(run))
    asked = [f["finding_id"] for f in findings[:3]]
    join.mark_asked(findings, asked)

    by_id = {f["finding_id"]: f for f in findings}
    for fid in asked:
        assert by_id[fid]["llm_asked"] is True
        assert by_id[fid]["agreement"] == join.ASKED_NO_VERDICT
    untouched = [f for f in findings if f["finding_id"] not in asked]
    assert all(f["agreement"] == join.NOT_SENT for f in untouched)
    assert all(f["llm_asked"] is False for f in untouched)


def test_summary_reports_the_unanswered_gap(run):
    bundles = join.build_bundles(run)
    findings = join.build_findings(bundles)
    join.mark_asked(findings, [f["finding_id"] for f in findings[:4]])
    # Answer only one of the four that were asked.
    findings[0]["llm"] = {"needs_rescan": True, "verdict": "likely-true-positive",
                          "confidence": "high", "reasoning": "r", "suggested_tool": "sqlmap"}
    findings[0]["agreement"] = join.label_agreement(findings[0])

    summary = join.summarise(bundles, findings, [], run.zap_report["alerts"])
    assert summary["llm_findings_asked"] == 4
    assert summary["llm_evaluated_findings"] == 1
    assert summary["llm_findings_unanswered"] == 3


def test_summary_separates_active_from_passive_zap_alerts(run):
    # 1564 of 1566 alerts in the real run were passive. A number that large
    # changes how every downstream result reads, so it is recorded, not implied.
    bundles = join.build_bundles(run)
    findings = join.build_findings(bundles)
    summary = join.summarise(bundles, findings, [], run.zap_report["alerts"])
    assert summary["alerts_by_zap_source"] == {"active-scanner": 2, "passive-scanner": 7}


def test_unrecognised_zap_source_is_labelled_not_silently_bucketed():
    from dast_orchestrator.adapters.zap_client import alert_source_name

    assert alert_source_name({"sourceid": "9"}) == "unrecognised-9"
    assert alert_source_name({}) == "unknown"


def test_a_finding_with_no_static_context_still_goes_to_the_model(run):
    bundles = {b.identifier: b for b in join.build_bundles(run)}
    api_bundle = bundles["GET /api/v1/repos/thesis/demo/issues"]
    assert api_bundle.has_static_context is False
    assert join.is_llm_candidate(api_bundle) is True


# -- the gated non-interactive-PHP prune (NEXT_SESSION §R3.3) ----------------


def _php_bundle(path: str, technology: str = "php_pure") -> Bundle:
    """A candidate bundle: has static context and one Medium-risk finding, so it
    passes `is_llm_candidate` and the only question is whether the prune drops it.
    """
    group = AlertGroup(plugin_id="40012", name="XSS", risk="Medium",
                       confidence="Medium", param="q", evidence="x", method="GET")
    return Bundle(endpoint_key=path, match_how=join.MATCH_SEED, method="GET",
                  path=path, static_context={"path": path, "technology": technology},
                  groups=[group])


def test_noninteractive_php_is_php_pure_under_cli_only():
    assert join.is_noninteractive_php(_php_bundle("/cli/poller.php")) is True
    assert join.is_noninteractive_php(_php_bundle("cli/index.php")) is True
    # A real web endpoint of the same app is NOT pruned.
    assert join.is_noninteractive_php(_php_bundle("/graph_view.php")) is False
    # install/ was validated OUT (§R3.4): the Cacti installer is reachable and
    # carries deterministic-rescan findings, so it stays in the LLM arm.
    assert join.is_noninteractive_php(_php_bundle("/install/install.php")) is False
    # `cli` only counts as the FIRST segment — a route that merely contains it,
    # or an endpoint Noir tagged as something other than php_pure, is untouched.
    assert join.is_noninteractive_php(_php_bundle("/lib/cli/helper.php")) is False
    assert join.is_noninteractive_php(_php_bundle("/cli/x.php", "rails")) is False
    # No static context, so no technology to read.
    assert join.is_noninteractive_php(
        Bundle(endpoint_key="GET /cli/x", match_how=join.MATCH_REGEX,
               method="GET", path="/cli/x.php")) is False


def test_select_llm_candidates_prunes_only_when_gated_and_counts():
    bundles = [_php_bundle("/graph_view.php"), _php_bundle("/cli/poller.php"),
               _php_bundle("/install/install.php")]
    # Off by default: every candidate is kept, nothing counted.
    kept, pruned = join.select_llm_candidates(bundles)
    assert len(kept) == 3 and pruned == 0
    # Gated on: only the cli/ script drops; the web endpoint AND the reachable
    # installer stay, count is 1.
    kept, pruned = join.select_llm_candidates(bundles, prune_noninteractive_php=True)
    assert [b.path for b in kept] == ["/graph_view.php", "/install/install.php"]
    assert pruned == 1


# -- self-consistency of the LLM arm ---------------------------------------


def _consistency_bundle(route, plugin, handler):
    return Bundle(
        endpoint_key=route, match_how="seed",
        method=route.split()[0], path=route.split()[1],
        static_context={
            "path": route.split()[1],
            "ai_context": {"callees": [{"name": handler, "confidence": 90}]},
        },
        groups=[AlertGroup(plugin_id=plugin, name=f"rule {plugin}", risk="Low",
                           confidence="Medium", method=route.split()[0],
                           param="q", evidence="", urls=["http://t/x"])],
    )


def _judged(bundles, verdicts):
    """One finding per bundle, carrying the given LLM verdict."""
    out = []
    for bundle, verdict in zip(bundles, verdicts):
        group = bundle.groups[0]
        out.append({
            "finding_id": join.finding_id(bundle, group),
            "llm": None if verdict is None else {"needs_rescan": verdict},
        })
    return out


def test_the_same_rule_judged_both_ways_on_one_handler_is_a_contradiction():
    # The shape pass 2 caught in prose: rule 10031 "flagged for rescan" on one
    # route and "dismissed as likely-false-positive" on another that runs the
    # same handler.
    bundles = [_consistency_bundle("POST /user/login", "10031", "user.SignIn"),
               _consistency_bundle("POST /user/sign_up", "10031", "user.SignIn")]
    result = join.self_consistency(bundles, _judged(bundles, [True, False]))
    assert result["shared_handler_comparisons"] == 1
    assert result["shared_handler_contradictions"] == 1
    assert result["shared_handler_examples"][0]["rule"] == "10031"


def test_agreeing_verdicts_on_one_handler_are_not_a_contradiction():
    bundles = [_consistency_bundle("POST /a", "10031", "h"),
               _consistency_bundle("POST /b", "10031", "h")]
    result = join.self_consistency(bundles, _judged(bundles, [True, True]))
    assert result["shared_handler_comparisons"] == 1
    assert result["shared_handler_contradictions"] == 0


def test_different_handlers_can_legitimately_differ():
    # Two routes with the same rule and genuinely different code *should* be
    # allowed to differ, so they are not compared.
    bundles = [_consistency_bundle("POST /a", "10031", "one"),
               _consistency_bundle("POST /b", "10031", "two")]
    result = join.self_consistency(bundles, _judged(bundles, [True, False]))
    assert result["shared_handler_comparisons"] == 0
    # The wider measure still records that the rule was judged both ways.
    assert result["rules_with_split_verdicts"] == 1


def test_an_unanswered_finding_is_not_counted_as_agreement():
    # Counting a missing verdict as agreement would let a lossy run look
    # perfectly self-consistent.
    bundles = [_consistency_bundle("POST /a", "10031", "h"),
               _consistency_bundle("POST /b", "10031", "h")]
    result = join.self_consistency(bundles, _judged(bundles, [True, None]))
    assert result["shared_handler_comparisons"] == 0
    assert result["rules_judged"] == 1


def test_the_summary_counts_rescans_the_table_cannot_route(run):
    """A flag with no tool is a defect in the table, and it needs a number.

    An unenumerated rule at real risk escalates through `UNKNOWN_RULE_POLICY`
    and names no tool, so the finding is flagged and dispatched to nothing.
    Verification then records `not-attempted`, which reads like a budget
    decision. Measured 2026-09-04: 200 of 283 flagged findings on the WordPress
    baseline, one of them rule 40026 — the corpus's only true positive.
    """
    # 99999 is in no table row; High risk makes it escalate on risk alone.
    unknown = {**HEADER_ALERT, "id": "902", "pluginId": "99999",
               "risk": "High", "confidence": "Medium",
               "name": "Some Rule Nobody Enumerated"}
    run = _with_alerts(run, [unknown])
    findings = join.build_findings(join.build_bundles(run))
    flagged = [f for f in findings if f["deterministic"]["needs_rescan"]]
    assert flagged and not flagged[0]["deterministic"]["tool"]

    summary = join.summarise(
        join.build_bundles(run), findings, [], run.zap_report["alerts"])
    assert summary["deterministic_rescans_unroutable"] == len(flagged)
    assert summary["unroutable_rescan_rules"] == ["99999"]


def test_a_routable_rescan_is_not_counted_as_unroutable(run):
    """The other half: a rule the table routes must not inflate the count."""
    sqli = {**HEADER_ALERT, "id": "903", "pluginId": "40018", "risk": "High",
            "param": "id", "name": "SQL Injection"}
    run = _with_alerts(run, [sqli])
    findings = join.build_findings(join.build_bundles(run))
    summary = join.summarise(
        join.build_bundles(run), findings, [], run.zap_report["alerts"])
    assert summary["deterministic_rescans"] >= 1
    assert summary["deterministic_rescans_unroutable"] == 0
    assert summary["unroutable_rescan_rules"] == []


# -- query-dispatched routes (WordPress admin-ajax) ---------------------------


from dast_orchestrator.adapters.noir_runner import query_satisfies, split_template_query

AJAX = "/wp-admin/admin-ajax.php"


def _ajax_endpoint(action: str, method: str = "GET") -> dict:
    path = f"{AJAX}?action={action}"
    return {"key": f"{method} {path}", "method": method, "path": path}


def _ajax_seed_map(*actions: str, method: str = "GET") -> dict:
    return {"entries": [
        {"method": method, "path": f"{AJAX}?action={a}",
         "url": f"http://t{AJAX}?action={a}",
         "endpoint_keys": [f"{method} {AJAX}?action={a}"]}
        for a in actions
    ]}


@pytest.mark.parametrize(
    "template, expected",
    [
        ("/repo/{id}", ("/repo/{id}", ())),
        (f"{AJAX}?action=x", (AJAX, (("action", "x"),))),
        ("/p?a=1&b=two%20words", ("/p", (("a", "1"), ("b", "two words")))),
        # A `?` inside a placeholder is an inline regex's, not a query.
        ("/c/{sha:[a-f0-9]+?}", ("/c/{sha:[a-f0-9]+?}", ())),
    ],
)
def test_split_template_query(template, expected):
    assert split_template_query(template) == expected


def test_query_satisfies_needs_every_pair_and_tolerates_extras():
    required = (("action", "x"),)
    assert query_satisfies((), "")
    assert query_satisfies(required, "action=x")
    assert query_satisfies(required, "foo=1&action=x")
    assert not query_satisfies(required, "action=y")
    assert not query_satisfies(required, "")
    assert not query_satisfies(required, "xaction=x")


@pytest.mark.parametrize("seeded", [True, False], ids=["seed-tier", "regex-tier"])
def test_a_query_dispatched_route_joins_on_its_discriminator(seeded):
    """Every action shares one path, so the action value is what picks the
    handler — in both tiers, or every admin-ajax alert stays unmatched."""
    endpoints = [_ajax_endpoint("alpha"), _ajax_endpoint("beta")]
    joiner = EndpointJoiner(endpoints, _ajax_seed_map("alpha", "beta") if seeded else None)
    how = MATCH_SEED if seeded else MATCH_REGEX
    assert joiner.match("GET", AJAX, "action=alpha") == join.Match(
        f"GET {AJAX}?action=alpha", how)
    assert joiner.match("GET", AJAX, "action=beta&_=1").endpoint_key == (
        f"GET {AJAX}?action=beta")


def test_a_query_dispatched_route_never_claims_a_url_without_its_action():
    joiner = EndpointJoiner([_ajax_endpoint("alpha")], _ajax_seed_map("alpha"))
    for query in ("", "action=gamma", "action=%27alpha"):
        match = joiner.match("GET", AJAX, query)
        assert match.endpoint_key is None
        assert match.how == CONTEXT_ABSENT_UNMATCHED


def test_a_required_query_outranks_the_bare_path():
    endpoints = [{"key": f"GET {AJAX}", "method": "GET", "path": AJAX},
                 _ajax_endpoint("alpha")]
    joiner = EndpointJoiner(endpoints, None)
    match = joiner.match("GET", AJAX, "action=alpha")
    assert match.endpoint_key == f"GET {AJAX}?action=alpha"
    assert match.alternatives == (f"GET {AJAX}",)
    # Without the action only the bare path can claim it.
    assert joiner.match("GET", AJAX, "").endpoint_key == f"GET {AJAX}"


def test_bundles_split_admin_ajax_alerts_by_action(run):
    """End to end through build_bundles: the alert URL's query reaches the join."""
    alerts = [dict(HEADER_ALERT, id=str(900 + i), url=f"http://t{AJAX}?action={a}",
                   method="GET")
              for i, a in enumerate(("alpha", "beta", "beta"))]
    ajax_run = replace(
        _with_alerts(run, alerts),
        ai_context={"endpoints": [_ajax_endpoint("alpha"), _ajax_endpoint("beta")]},
        seed_map=_ajax_seed_map("alpha", "beta"),
    )
    bundles = {b.identifier: b for b in join.build_bundles(ajax_run)}
    assert set(bundles) == {f"GET {AJAX}?action=alpha", f"GET {AJAX}?action=beta"}
    assert all(b.has_static_context for b in bundles.values())
    assert bundles[f"GET {AJAX}?action=beta"].groups[0].instances == 2
