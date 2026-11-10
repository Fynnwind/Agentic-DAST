"""The dispatch driver: routing, budget enforcement, result parsing, selection.

No containers and no live MCP session — the MCP boundary is exercised only
through :func:`_parse_tool_result` with stand-in result objects, and the budget
logic through :class:`Dispatcher` with no session opened. The live round-trip is
covered by the wrapper smoke path, not here.
"""

from __future__ import annotations

import json
import time

import pytest

from dast_orchestrator.domain import verification
from dast_orchestrator.stages import verify
from dast_orchestrator.analysis.join import JoinError
from dast_orchestrator.domain.verification import (
    CONFIRMED,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
    DispatchBudget,
)


def _finding(fid, plugin="40018", risk="High", method="GET", param="q",
             url="http://target/x?q=1", det=True, det_tool="sqlmap",
             llm=None, llm_tool=None, endpoint_key="GET /x"):
    return {
        "finding_id": fid,
        "endpoint_key": endpoint_key,
        "method": method,
        "path": "/x",
        "alert": {"plugin_id": plugin, "name": "n", "risk": risk, "param": param,
                  "method": method, "example_urls": [url]},
        "deterministic": {"needs_rescan": det, "tool": det_tool},
        "llm": ({"needs_rescan": llm, "suggested_tool": llm_tool}
                if llm is not None else None),
    }


# -- routing ---------------------------------------------------------------


def test_build_dispatch_routes_get_sqli_to_sqlmap():
    plan = verify.build_dispatch(_finding("f-1"), {})
    assert plan["tool"] == "sqlmap"
    assert plan["arguments"]["target"] == "http://target/x?q=1"
    assert "data" not in plan["arguments"]  # GET carries no body


def test_build_dispatch_post_reconstructs_form_body():
    login = "GET /user/login"
    f_user = _finding("f-u", method="POST", param="user_name",
                      url="http://t/user/login", endpoint_key=login)
    f_pw = _finding("f-p", method="POST", param="password",
                    url="http://t/user/login", endpoint_key=login)
    by_ep = {login: [f_user, f_pw]}
    fillers = {"password": "Password123!", "user_name": "thesis"}
    plan = verify.build_dispatch(f_user, by_ep, fillers)
    body = plan["arguments"]["data"]
    assert "user_name=" in body and "password=" in body
    # companion fields get benign fillers from the target
    assert "password=Password123!" in body


def test_build_dispatch_threads_cookie_when_authenticated():
    auth_ctx = {"cookie": "i_like_gitea=abc", "csrf_field": "_csrf",
                "csrf_url": "http://t/user/login"}
    plan = verify.build_dispatch(_finding("f-1"), {}, auth_ctx=auth_ctx)
    assert plan["arguments"]["cookie"] == "i_like_gitea=abc"


def test_form_body_drops_non_form_pseudo_params():
    # ZAP attaches pseudo-params for header/cookie/UA-fuzzer alerts on the same
    # endpoint; these are not form fields and must not pollute the POST body.
    login = "GET /user/login"
    real = _finding("f-u", method="POST", param="user_name", endpoint_key=login)
    junk = [
        _finding("f-h", method="POST", param="Header User-Agent", endpoint_key=login),
        _finding("f-x", method="POST", param="x-content-type-options", endpoint_key=login),
        _finding("f-c", method="POST", param="i_like_gitea", endpoint_key=login),
    ]
    by_ep = {login: [real] + junk}
    body = verify._form_body(by_ep, real, {"user_name": "thesis"},
                             drop_names={"i_like_gitea"})
    assert "user_name=thesis" in body
    assert "Header User-Agent" not in body   # space-containing -> dropped
    assert "i_like_gitea" not in body         # session cookie -> dropped


def test_apply_auth_adds_csrf_unauthenticated_for_form_post():
    # The login-SQLi fix: CSRF handling is applied even without a cookie, so an
    # unauthenticated form POST is not refuted merely for lacking a token.
    ctx = {"csrf_field": "_csrf", "csrf_url": "http://t/user/login",
           "session_cookie": "i_like_gitea"}  # no 'cookie' key -> unauthenticated
    args = {"method": "POST"}
    verify._apply_auth("sqlmap", args, "POST", ctx)
    assert args["csrf_field"] == "_csrf" and args["csrf_url"] == "http://t/user/login"
    assert "cookie" not in args               # none injected when unauthenticated


def test_build_dispatch_adds_sqlmap_csrf_only_for_guarded_post():
    login = "GET /user/login"
    f = _finding("f-p", method="POST", param="user_name",
                 url="http://t/user/login", endpoint_key=login)
    auth_ctx = {"cookie": "i_like_gitea=abc", "csrf_field": "_csrf",
                "csrf_url": "http://t/user/login"}
    plan = verify.build_dispatch(f, {login: [f]}, auth_ctx=auth_ctx)
    assert plan["arguments"]["csrf_field"] == "_csrf"
    assert plan["arguments"]["csrf_url"] == "http://t/user/login"
    # a GET SQLi carries the cookie but needs no CSRF token fetch
    get_plan = verify.build_dispatch(_finding("f-g"), {}, auth_ctx=auth_ctx)
    assert "csrf_field" not in get_plan["arguments"]


def test_sqlmap_csrf_token_comes_from_the_probed_page():
    # Signed in, Cacti's login page carries no token field, so every POST probe
    # that fetched its token there was skipped; the form's own page carries one.
    ctx = {"cookie": "Cacti=abc", "csrf_field": "__csrf_magic",
           "csrf_url": "http://t/index.php"}
    args = {"target": "http://t/automation_graph_rules.php", "method": "POST"}
    verify._apply_auth("sqlmap", args, "POST", ctx)
    assert args["csrf_url"] == "http://t/automation_graph_rules.php"
    marked = {"target": "http://t/rules/7*/save", "method": "POST"}
    verify._apply_auth("sqlmap", marked, "POST", ctx)
    assert marked["csrf_url"] == "http://t/rules/7/save"   # the marker is not a page


def test_build_dispatch_no_auth_keeps_args_clean():
    plan = verify.build_dispatch(_finding("f-1"), {})
    assert "cookie" not in plan["arguments"]


def test_build_dispatch_refuses_without_url():
    # A tool was named but there is nothing to aim it at. Distinct from "no arm
    # named a tool", and the artifact records which of the two it was.
    f = _finding("f-x")
    f["alert"]["example_urls"] = []
    plan = verify.build_dispatch(f, {})
    assert plan["tool"] is None
    assert plan["refusal"] == verify.URL_NONE_RECORDED


def test_a_payload_substituted_into_a_path_is_stripped_back():
    # ZAP's format-string rule REPLACES the segment rather than appending to it,
    # so the flagged value is gone from the URL and only the payload is there.
    attack = "ZAP %1!s%2!s%3!s%4!s%5!s"
    f = _finding(
        "f-fmt", plugin="30002", param="548daa12ba3fcbbcdf17bb74bdb154c5",
        url="http://target-gitea:3000/avatars/ZAP%20%251!s%252!s%253!s%254!s%255!s",
    )
    f["alert"]["attack"] = attack
    probe = verify.probe_target(f)
    assert probe.probeable
    assert probe.url_source == verify.URL_PATH_STRIPPED
    assert probe.url.endswith("/avatars/548daa12ba3fcbbcdf17bb74bdb154c5")
    assert "%251!s" not in probe.url


def test_a_path_payload_with_nothing_to_restore_is_refused():
    # The same alert collapsed with an empty param: the payload is in the path
    # and nothing says what the segment held. Probing it would test the payload.
    f = _finding(
        "f-fmt2", plugin="30002", param="",
        url="http://target-gitea:3000/avatars/ZAP%20%251!s%252!s%253!s%254!s%255!s",
    )
    f["alert"]["attack"] = "ZAP %1!s%2!s%3!s%4!s%5!s"
    probe = verify.probe_target(f)
    assert not probe.probeable
    assert probe.url_source == verify.URL_PAYLOAD_UNRECOVERABLE
    plan = verify.build_dispatch(f, {})
    assert plan["tool"] is None and plan["refusal"] == verify.URL_PAYLOAD_UNRECOVERABLE


def test_a_traversal_attack_equal_to_the_segment_is_left_alone():
    # ZAP records `attack` even when it injected nothing into the path: the
    # traversal alert on /avatar/avatar has attack == the segment itself.
    f = _finding("f-trav", plugin="6", param="user",
                 url="http://target-gitea:3000/avatar/avatar")
    f["alert"]["attack"] = "avatar"
    probe = verify.probe_target(f)
    assert probe.probeable and probe.url == "http://target-gitea:3000/avatar/avatar"


def test_build_dispatch_none_when_no_tool():
    f = _finding("f-x", det=False, det_tool=None)
    assert verify.build_dispatch(f, {}) is None


def test_correlated_dispatch_borrows_supporting_url():
    support = _finding("f-sup", url="http://t/commit/abc", param="sha")
    corr = {"finding_id": "c-0", "pattern": "propagation-shared-handler",
            "suggested_tool": "sqlmap", "supporting_finding_ids": ["f-sup"]}
    plan = verify.build_correlated_dispatch(corr, {"f-sup": support})
    assert plan["tool"] == "sqlmap"
    assert plan["via_finding_id"] == "f-sup"
    assert plan["arguments"]["target"] == "http://t/commit/abc"


def test_correlated_dispatch_none_when_tool_is_none():
    corr = {"finding_id": "c-1", "pattern": "systemic-absence",
            "suggested_tool": "none", "supporting_finding_ids": ["f-sup"]}
    assert verify.build_correlated_dispatch(corr, {}) is None


# -- the dispatch half of a propagation claim (§P1) -------------------------
#
# Synthesis v5 makes a propagation claim enumerate the routes it predicts,
# unflagged siblings included. Until 2026-09-05 verification probed only the one
# flagged finding the claim cites, so the routes that are the entire content of
# the prediction were never touched. These pin the half that goes and looks.


def _gitea():
    from dast_orchestrator.adapters import targets

    return targets.get("gitea")


def _propagation(routes, tool="nuclei", support="f-sup", claim="c-0"):
    return {"finding_id": claim, "pattern": "propagation-shared-handler",
            "suggested_tool": tool, "supporting_finding_ids": [support],
            "affected_routes": routes, "title": "shared handler XSS",
            "severity": "medium"}


def test_a_propagation_claim_probes_the_routes_it_predicts():
    """The point of the claim is the routes the scanner never flagged."""
    anchor_key = "GET /{username}/{reponame}/commits/branch/*"
    support = _finding(
        "f-sup", plugin="10031", param="q", endpoint_key=anchor_key,
        url="http://target-gitea:3000/thesis/demo/commits/branch/master/search?q=ZAP")
    claim = _propagation([
        anchor_key,                                          # the anchor itself
        "GET /{username}/{reponame}/commits/tag/*",
        "GET /{username}/{reponame}/commits/commit/*",
    ])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), already_verified=set(), cap=5)

    assert [p["route"] for p in probes] == [
        "GET /{username}/{reponame}/commits/tag/*",
        "GET /{username}/{reponame}/commits/commit/*",
    ], "the anchor route is not its own sibling"
    # The anchor's own observed URL supplies the placeholder values, so the
    # probe lands on a page the application actually serves — the difference
    # between a probe and the `/1/1/commits/tag/index` the generic defaults
    # would have produced.
    assert probes[0]["arguments"]["target"] == (
        "http://target-gitea:3000/thesis/demo/commits/tag/master/search?q=1")
    assert probes[0]["url_source"] == verify.URL_ROUTE_TEMPLATE_BOUND


def test_an_xss_claim_goes_to_the_execution_oracle_not_a_string_matcher():
    """The 40026 lesson, one level up.

    The synthesis schema's `suggested_tool` enum has no `browser` in it, so a
    model reasoning about a reflected-XSS propagation claim can only ask for
    nuclei — and nuclei refuted a live XSS on this very pipeline because output
    escaping altered its payload without preventing execution.
    """
    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation(["GET /a", "GET /b"], tool="nuclei")
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    assert plan["tool"] == "browser"
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=5)
    assert {p["tool"] for p in probes} == {"browser"}

    # A non-XSS rule keeps the tool the claim asked for.
    sqli = _finding("f-sql", plugin="40018", param="id")
    sqli_claim = _propagation(["GET /a"], tool="sqlmap", support="f-sql")
    assert verify.build_correlated_dispatch(
        sqli_claim, {"f-sql": sqli})["tool"] == "sqlmap"


def test_a_route_already_being_verified_is_never_probed_twice():
    """The double-verification trap the v5 prompt forbids, enforced at dispatch.

    Probing a route both per-endpoint and as a sibling would produce two
    verdicts about one route and let them be counted as independent evidence.
    """
    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation(["GET /a", "GET /b", "GET /c"])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), already_verified={"GET /b"}, cap=5)
    assert [p["route"] for p in probes] == ["GET /a", "GET /c"]


def test_one_broad_claim_cannot_exhaust_the_dispatch_budget():
    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation([f"GET /r{n}" for n in range(20)])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=3)
    assert len(probes) == 3
    assert verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=0) == []


def test_only_a_propagation_claim_has_siblings_worth_probing():
    """A systemic-absence claim's routes are where it was OBSERVED, not predicted.

    Its `affected_routes` are the dozens of pages already carrying the finding,
    so probing them verifies nothing new and would spend the whole budget.
    """
    support = _finding("f-sup", plugin="10031", param="q")
    claim = {**_propagation(["GET /a", "GET /b"]), "pattern": "systemic-absence"}
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    assert verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=5) == []


def test_prose_in_affected_routes_is_skipped_not_guessed_at():
    """The field is model-authored, and on the stored corpus it holds prose.

    `"All 40+ routes with session-plumbing guard"` is a real entry from the
    sheet-10 ensemble run. A claim whose routes a reader cannot turn into
    requests is what the synthesis prompt forbids; the honest handling is to
    probe the entries that are routes and leave the rest alone.
    """
    assert verify.parse_route("All 40+ routes with session-plumbing guard") is None
    assert verify.parse_route("GET /{username}/{reponame}/commits/*") == (
        "GET", "/{username}/{reponame}/commits/*")

    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation(["All 40+ routes with session-plumbing guard", "GET /a"])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=5)
    assert [p["route"] for p in probes] == ["GET /a"]


def test_a_post_sibling_is_not_probed_at_an_invented_request():
    """The URL is already constructed; a synthesised body as well is a fiction.

    The execution oracle loads a URL and cannot POST at all, and a body invented
    for a route nothing was ever observed on would make a refutation meaningless
    twice over.
    """
    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation(["POST /{username}/{reponame}/lastcommit/*", "GET /a"])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    probes = verify.build_sibling_dispatches(
        claim, plan, support, _gitea(), set(), cap=5)
    assert [p["route"] for p in probes] == ["GET /a"]


def test_a_confirmed_sibling_is_a_first_class_finding_with_its_provenance():
    """The headline of §P1: a real vulnerability ZAP should have found and did not.

    It gets its own id in its own namespace, and provenance saying which layer
    reached it — so the detection-rate accounting can separate the LLM layer's
    reach from the crawl's without filing the finding as suspect.
    """
    probe = {"tool": "browser", "route": "GET /{u}/{r}/commits/tag/*",
             "claim_id": "c-0", "via_finding_id": "f-sup", "plugin_id": "10031",
             "url_source": verify.URL_ROUTE_TEMPLATE_BOUND,
             "arguments": {"target": "http://t/thesis/demo/commits/tag/x?q=1",
                           "param": "q", "method": "GET"}}
    result = {"outcome": verification.CONFIRMED, "evidence": "<script>…",
              "detail": "injected JavaScript EXECUTED in a real browser"}
    record = verify.sibling_record(probe, result, _propagation(["GET /a"]),
                                   verify.loop_config())

    assert record["finding_id"].startswith("s-")
    assert record["outcome"] == verification.CONFIRMED
    assert record["found_by"]["route_never_flagged"] is True
    assert record["found_by"]["layer"] == "llm-cross-endpoint-synthesis"
    # Stable across runs, so two runs confirming the same propagation agree.
    assert record["finding_id"] == verify.sibling_finding_id(
        "c-0", "GET /{u}/{r}/commits/tag/*")


def test_a_refuted_sibling_stays_out_of_the_report():
    """Asymmetric on purpose: the URL was constructed, so a 404 refutes the URL.

    Listing a constructed-URL refutation as "checked and clean" would put the
    strongest claim in the report on the weakest evidence in it.
    """
    from dast_orchestrator.stages import report

    artifact = {"sibling_verifications": [
        {"finding_id": "s-a", "outcome": verification.CONFIRMED, "route": "GET /a"},
        {"finding_id": "s-b", "outcome": verification.REFUTED, "route": "GET /b"},
        {"finding_id": "s-c", "outcome": verification.INCONCLUSIVE, "route": "GET /c"},
    ]}
    assert [r["finding_id"] for r in report.confirmed_siblings(artifact)] == ["s-a"]


def test_sibling_counts_never_join_the_flagged_tally():
    """Two populations, one column would be two mistakes at once.

    A constructed-URL refutation added to the flagged refutation rate depresses
    it with probes of routes that may not exist; a sibling confirmation added to
    it credits the scanner with a route it never reached.
    """
    flagged = [{"finding_id": "f-1", "outcome": verification.REFUTED,
                "rounds_used": 1}]
    siblings = [{"finding_id": "s-1", "claim_id": "c-0",
                 "outcome": verification.CONFIRMED},
                {"finding_id": "s-2", "claim_id": "c-0",
                 "outcome": verification.REFUTED}]
    summary = verify.summarise(flagged, [], {}, None, siblings)

    assert summary["by_outcome"] == {verification.REFUTED: 1}
    assert summary["siblings"]["probed"] == 2
    assert summary["siblings"]["claims"] == 1
    assert summary["siblings"]["confirmed_finding_ids"] == ["s-1"]


def test_a_route_the_pre_check_found_unserved_was_never_a_probe():
    """"Considered" and "probed" are different numbers and must stay so.

    A route the application does not serve was never a test of anything.
    Counting it among the probes would put a fact about a constructed URL into
    a column about the application — and it is the same conflation, one level
    down, that the sibling block exists to keep out of the flagged tally.
    """
    siblings = [
        {"finding_id": "s-1", "claim_id": "c-0", "outcome": verification.REFUTED,
         "route_status": 200},
        {"finding_id": "s-2", "claim_id": "c-0",
         "outcome": verification.SIBLING_UNREACHABLE, "route_status": 404},
    ]
    block = verify.summarise([], [], {}, None, siblings)["siblings"]
    assert block["considered"] == 2
    assert block["probed"] == 1
    assert block["routes_not_served"] == 1


# -- result parsing --------------------------------------------------------


class _Content:
    def __init__(self, text):
        self.text = text


class _Result:
    def __init__(self, content, is_error=False):
        self.content = content
        self.is_error = is_error


def test_parse_tool_result_reads_json_verdict():
    payload = {"tool": "ffuf", "outcome": REFUTED, "detail": "nope"}
    parsed = verify._parse_tool_result(_Result([_Content(json.dumps(payload))]), "ffuf")
    assert parsed["outcome"] == REFUTED


def test_parse_tool_result_surfaces_error_text():
    parsed = verify._parse_tool_result(
        _Result([_Content("Unknown tool: sqlmap")], is_error=True), "sqlmap"
    )
    assert parsed["outcome"] == INCONCLUSIVE
    assert "Unknown tool" in parsed["detail"]


# -- budget enforcement ----------------------------------------------------


def _dispatcher(budget):
    d = verify.Dispatcher(budget, stack=None)
    return d


def test_budget_blocks_on_the_run_total():
    d = _dispatcher(DispatchBudget(max_dispatches_total=2))
    d.dispatched = 2
    block = d._budget_block("40018")
    assert block and "run total cap" in block


def test_budget_blocks_on_per_rule_cap():
    d = _dispatcher(DispatchBudget(max_dispatch_all_rules=1))
    d.per_rule["10031"] = 1
    assert "all-rules cap" in d._budget_block("10031")
    # a different rule is still allowed
    assert d._budget_block("40018") is None


def test_budget_blocks_on_wall_clock():
    d = _dispatcher(DispatchBudget(max_minutes=1))
    d.started = time.monotonic() - 120
    assert "wall-clock" in d._budget_block("40018")


def test_a_ceiling_set_to_NO_CAP_is_the_one_that_stops_being_enforced():
    """Coverage on this workload is a budget choice, so it must be removable.

    Measured on the 2026-09-05 WordPress baseline: 83 of 105 selected findings
    were never dispatched, 66 of them refused by the per-rule cap on two rules
    and only 7 by the total — the wall clock never bit. That makes "what would
    those 83 have said?" a question about one number, and it is only askable if
    the number can be switched off. Each ceiling is independent: switching one
    off must not switch off the others.
    """
    exhaustive = DispatchBudget(max_dispatch_all_rules=verification.NO_CAP,
                                max_dispatches_total=verification.NO_CAP,
                                max_minutes=verification.NO_CAP)
    d = _dispatcher(exhaustive)
    d.started = time.monotonic() - 86400
    d.dispatched = 10_000
    d.per_rule["40018"] = 10_000
    assert d._budget_block("40018") is None

    # …and only the one that was zeroed. A run that removes the per-rule cap to
    # get complete outcomes on a noisy rule is still bounded by the other two.
    only_per_rule = _dispatcher(
        DispatchBudget(max_dispatch_all_rules=verification.NO_CAP))
    only_per_rule.per_rule["40018"] = 10_000
    assert only_per_rule._budget_block("40018") is None
    only_per_rule.dispatched = DispatchBudget().max_dispatches_total
    assert "run total cap" in only_per_rule._budget_block("40018")


def test_a_rule_named_individually_is_capped_apart_from_every_other_rule():
    """The whole point of the per-rule layer, asserted at the refusal.

    And the refusal must say WHICH ceiling refused it: "raise the cap" means a
    different edit for a rule with its own number than for one riding the
    blanket default.
    """
    d = _dispatcher(DispatchBudget(max_dispatch_all_rules=1,
                                   rule_caps=(("40018", 3),)))
    d.per_rule["40018"] = 2
    d.per_rule["10031"] = 1
    assert d._budget_block("40018") is None          # its own cap, not reached
    assert "all-rules cap (1)" in d._budget_block("10031")
    d.per_rule["40018"] = 3
    assert "rule cap (3) reached for plugin 40018" in d._budget_block("40018")


def test_a_per_rule_cap_of_zero_means_never_dispatch_that_rule():
    """0 keeps its arithmetic meaning; -1 is the sentinel for no limit.

    Muting one noisy rule is the most useful thing a per-rule cap can say, and
    a sentinel that claimed 0 for "unlimited" would make it inexpressible.
    """
    d = _dispatcher(DispatchBudget(rule_caps=(("10031", 0),)))
    assert "rule cap (0) reached for plugin 10031" in d._budget_block("10031")
    assert d._budget_block("40018") is None


def test_the_shipped_defaults_are_real_ceilings_and_none_is_NO_CAP():
    """The sentinel exists for a deliberate run, never as a default.

    An unbounded verification stage is precisely what `DispatchBudget` was
    written to prevent — a rule firing 348 times must not be able to make CI
    cost unbounded — so a default that drifted to 0 would silently undo the
    layer while every test above still passed.
    """
    for name, value in DispatchBudget().as_dict().items():
        assert value != verification.NO_CAP, f"{name} defaults to no ceiling"


# -- selection, summary, discovery ----------------------------------------


def test_select_findings_orders_and_filters():
    flagged_hi = _finding("f-hi", risk="High")
    flagged_info = _finding("f-info", plugin="10031", risk="Informational",
                            det_tool="nuclei")
    unflagged = _finding("f-no", det=False, det_tool=None)
    selected = verify.select_findings([flagged_info, unflagged, flagged_hi])
    assert [f["finding_id"] for f in selected] == ["f-hi", "f-info"]


def _round(outcome, seconds=0.0, index=1):
    return {"index": index, "tool": "sqlmap", "arguments": {},
            "wrapper_outcome": outcome, "tool_ran": True,
            "tool_result": {"outcome": outcome, "seconds": seconds}}


def test_summarise_counts_by_outcome_and_tool():
    verifs = [
        {"outcome": CONFIRMED, "tool": "sqlmap", "rounds_used": 1,
         "rounds": [_round(CONFIRMED, 1.0)]},
        {"outcome": REFUTED, "tool": "sqlmap", "rounds_used": 1,
         "rounds": [_round(REFUTED, 2.0)]},
        {"outcome": NOT_ATTEMPTED, "tool": "nuclei", "rounds_used": 0, "rounds": []},
    ]
    s = verify.summarise(verifs, [], {"40018": 2})
    assert s["by_outcome"][CONFIRMED] == 1
    assert s["by_tool"]["sqlmap"][REFUTED] == 1
    assert s["dispatched"] == 2  # NOT_ATTEMPTED does not count
    # Tool seconds are summed over every ROUND, not per finding: a loop that
    # took three rounds cost three tool invocations, and reporting only the last
    # would understate the stage by exactly the work the loop exists to do.
    assert s["tool_seconds"] == 3.0
    assert s["rounds_used"] == {"1": 2, "0": 1}


def test_a_run_with_no_model_claims_no_agreement():
    """A deterministic run has no disagreement rate, and 0.0% is not one.

    The first live run of the rebuilt layer reported "614 agree / 0 flagged
    (0.0%)" for a configuration that never called a model. On a comparison
    sheet that 0% sits in the same column as the LLM rows' real rate and invites
    exactly the wrong conclusion. A missing measurement and a measured zero must
    not look alike — the same rule the cost fields already follow.
    """
    verifs = [
        {"outcome": REFUTED, "wrapper_verdict": REFUTED, "llm_verdict": None,
         "agreement": "agree", "tool": "sqlmap", "rounds_used": 1,
         "rounds": [_round(REFUTED)]},
    ]
    info = {"config": verify.loop_config("deterministic"),
            "findings_looped": 0, "rounds_run": 1, "tool_rounds": 1,
            "agreement": {"agree": 0, "flagged": 0}}
    s = verify.summarise(verifs, [], {}, info)
    assert s["loop"]["audited"] == 0
    assert s["loop"]["flagged_rate"] is None      # not 0.0
    # ...and the deterministic reading is still there to be the control.
    assert s["by_wrapper_verdict"] == {REFUTED: 1}


def test_a_budget_refusal_is_a_loop_round_but_not_a_tool_round():
    """38 "rounds" for 17 invocations, on the first live run.

    A round the budget refused before anything ran is a loop iteration, not
    tool work, and reporting one number for both overstated the stage's
    dispatch by a third.
    """
    verdict = verification.LoopVerdict(
        finding_id="f", reported=NOT_ATTEMPTED, wrapper_verdict=NOT_ATTEMPTED,
        llm_verdict=None, agreement=verification.AGREE,
        rounds=(verification.RoundRecord(1, "sqlmap", {}, {}, {}, REFUTED, True, {}),
                verification.RoundRecord(2, "sqlmap", {}, {}, {}, NOT_ATTEMPTED,
                                         False, {})),
    )
    assert verdict.rounds_used == 2
    assert verify._tool_rounds(verdict) == 1


def test_summarise_keeps_both_readings_side_by_side():
    """The deterministic control must never vanish from a run's summary.

    Without the wrapper's own counts beside the reported ones, "the model
    verifies well" has no number to be false against.
    """
    verifs = [
        {"outcome": REFUTED, "wrapper_verdict": CONFIRMED, "agreement": "flagged",
         "tool": "sqlmap", "rounds_used": 1, "rounds": [_round(CONFIRMED)]},
        {"outcome": REFUTED, "wrapper_verdict": REFUTED, "agreement": "agree",
         "tool": "sqlmap", "rounds_used": 2, "rounds": [_round(REFUTED)]},
    ]
    info = {"config": {"tool_choice": "table", "invocation": "llm"},
            "findings_looped": 2, "rounds_run": 3, "tool_rounds": 3,
            "agreement": {"agree": 1, "flagged": 1}}
    s = verify.summarise(verifs, [], {}, info)
    assert s["by_outcome"][REFUTED] == 2
    assert s["by_wrapper_verdict"] == {CONFIRMED: 1, REFUTED: 1}
    assert s["loop"]["audited"] == 2
    assert s["loop"]["flagged"] == 1 and s["loop"]["flagged_rate"] == 0.5


def _run(tmp_path, run_id, name="triage.json"):
    d = tmp_path / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text("{}")


def test_find_correlation_prefers_named_run(tmp_path):
    _run(tmp_path, "20260101T000000Z-gitea")
    _run(tmp_path, "20260202T000000Z-gitea")
    layout, path = verify._find_correlation(tmp_path, "20260101T000000Z-gitea")
    assert layout.run_id == "20260101T000000Z-gitea"
    assert path == tmp_path / "20260101T000000Z-gitea" / "triage.json"


def test_find_correlation_newest_run(tmp_path):
    _run(tmp_path, "20260101T000000Z-gitea")
    _run(tmp_path, "20260202T000000Z-gitea")
    layout, _ = verify._find_correlation(tmp_path, None)
    assert layout.run_id == "20260202T000000Z-gitea"          # newest run id wins


def test_find_correlation_honours_suffix(tmp_path):
    _run(tmp_path, "20260101T000000Z-gitea", "triage.json")
    _run(tmp_path, "20260101T000000Z-gitea", "triage-qwen235b.json")
    layout, path = verify._find_correlation(tmp_path, "20260101T000000Z-gitea", "qwen235b")
    assert path.name == "triage-qwen235b.json"


def test_find_correlation_raises_when_absent(tmp_path):
    with pytest.raises(JoinError):
        verify._find_correlation(tmp_path, None)


def test_build_artifact_validates_against_schema():
    import json
    from pathlib import Path

    import jsonschema

    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "schemas"
         / "verification-result.schema.json").read_text()
    )
    verifs = [{"finding_id": "f-1", "tool": "sqlmap", "outcome": REFUTED,
               "reported_verdict": REFUTED, "wrapper_verdict": CONFIRMED,
               "llm_verdict": REFUTED, "agreement": "flagged", "rounds_used": 1,
               "stopped_because": "model concluded at round 1",
               "config": {"tool_choice": "table", "invocation": "llm",
                          "max_rounds": 3},
               "rounds": [_round(CONFIRMED, 2.0)],
               "detail": "clean", "evidence": None}]
    correlated = [{"finding_id": "c-0", "tool": None, "outcome": NOT_ATTEMPTED,
                   "reported_verdict": NOT_ATTEMPTED,
                   "wrapper_verdict": NOT_ATTEMPTED, "llm_verdict": None,
                   "agreement": "agree", "rounds_used": 0, "rounds": [],
                   "detail": "no tool", "evidence": None}]
    artifact = verify.build_artifact(
        "triage-x.json", "20260101T000000Z", DispatchBudget(),
        verifs, correlated, {"40018": 1},
        {"config": {"tool_choice": "table", "invocation": "llm", "max_rounds": 3},
         "findings_looped": 1, "rounds_run": 1,
         "agreement": {"agree": 1, "flagged": 1}},
    )
    jsonschema.Draft7Validator(schema).validate(artifact)
    assert artifact["config"]["invocation"] == "llm"


# -- probe targets: ZAP's example URLs carry the attack payload ------------
#
# The URL on an alert is the request that *raised* it, not the endpoint's own.
# Handing it to another tool re-probes an already-broken request, so the second
# tool measures the first one's payload rather than the endpoint. These tests pin
# the three shapes the recorded runs actually contain.


def _payload_finding(param, attack, url, plugin="40018", endpoint_key="GET /x"):
    f = _finding("f-p", plugin=plugin, param=param, url=url, endpoint_key=endpoint_key)
    f["alert"]["attack"] = attack
    return f


def test_query_parameter_value_is_reset_not_reused():
    # The payload sits in the flagged parameter's *value*; the name and the rest
    # of the URL are what the tool needs. A broken SQL string left in place makes
    # every baseline request 500, which is not a measurement of anything.
    f = _payload_finding(
        "redirect_to", "/repo/commit/abc' AND '1'='1' -- ",
        "http://t/user/login?redirect_to=%2Frepo%2Fcommit%2Fabc%27+AND+%271%27%3D%271%27+--+",
    )
    probe = verify.probe_target(f)
    assert probe.injection_point == verify.INJECT_QUERY
    assert probe.url_source == verify.URL_QUERY_RESET
    assert "AND" not in probe.url and "%27" not in probe.url
    assert "redirect_to=1" in probe.url
    assert probe.param == "redirect_to"


def test_query_reset_prefers_the_targets_own_benign_value():
    f = _payload_finding("q", "x' OR 1=1--", "http://t/s?q=x%27+OR+1%3D1--")
    assert "q=hello" in verify.probe_target(f, {"q": "hello"}).url


def test_path_parameter_payload_is_stripped_exactly():
    # url-path injection: `param` is the segment *value* and `attack` is that
    # value with the payload appended, so it strips off exactly. This is the
    # commit `.patch` finding that landed inconclusive for the wrong reason.
    f = _payload_finding(
        "663a2a0.patch", "663a2a0.patch'",
        "http://t/thesis/demo/commit/663a2a0.patch'",
        endpoint_key="GET /{username}/{reponame}/commit/{sha}.{ext}",
    )
    probe = verify.probe_target(f)
    assert probe.injection_point == verify.INJECT_PATH
    assert probe.url_source == verify.URL_PATH_STRIPPED
    assert probe.url == "http://t/thesis/demo/commit/663a2a0.patch"


def test_path_parameter_gets_an_injection_marker_and_no_named_param():
    # A path segment has no name, so `-p` addresses nothing and sqlmap tests
    # nothing however clean the URL is. The marker is the parameter.
    f = _payload_finding(
        "663a2a0.patch", "663a2a0.patch'",
        "http://t/thesis/demo/commit/663a2a0.patch'",
        endpoint_key="GET /{username}/{reponame}/commit/{sha}.{ext}",
    )
    plan = verify.build_dispatch(f, {})
    assert plan["tool"] == "sqlmap"
    # Appended to the value, not substituted for it: sqlmap replaces the marker
    # with each payload, so `/commit/*` drops the commit id and 404s.
    assert plan["arguments"]["target"] == "http://t/thesis/demo/commit/663a2a0.patch*"
    assert plan["arguments"]["param"] == ""
    assert plan["injection_point"] == verify.INJECT_PATH
    assert "injection-marker" in plan["url_source"]


def test_marker_refuses_an_ambiguous_or_literal_segment():
    # `/api/v1/settings/api`: two segments equal the value and no template says
    # which ZAP injected — marking either would probe a literal path component.
    assert verify.mark_path_injection("http://t/api/v1/settings/api", "api") is None
    # The template rules out a literal segment even when it is unique.
    assert verify.mark_path_injection(
        "http://t/repo/settings", "settings", "GET /{name}/settings"
    ) is None
    assert verify.mark_path_injection(
        "http://t/repo/settings", "repo", "GET /{name}/settings"
    ) == "http://t/repo*/settings"


def test_unmarkable_path_finding_is_refused_rather_than_probed_blindly():
    """And the refusal says a TOOL was named, so it is not a routing gap.

    This returned a bare `None` until 2026-09-04, which `run_loop` cannot tell
    apart from "no arm named a tool" — so two rule-40018 findings on the
    WordPress baseline, both routed to sqlmap, were counted under a warning
    that says each is a rule the rescan table does not route.
    """
    f = _payload_finding("api", "api", "http://t/api/v1/settings/api",
                         endpoint_key="")
    plan = verify.build_dispatch(f, {})
    assert plan is not None and plan["tool"] is None
    assert plan["refusal"] == verify.PATH_NOT_MARKABLE
    assert "not a rule the table cannot route" in verify._refusal_detail(
        verify.PATH_NOT_MARKABLE)


def test_attack_equal_to_the_parameter_changes_nothing():
    # ZAP records this when it injected nothing into the path; a no-op must stay
    # a no-op rather than mangling the URL.
    f = _payload_finding("api", "api", "http://t/settings/api", endpoint_key="")
    probe = verify.probe_target(f)
    assert probe.url == "http://t/settings/api"
    assert probe.url_source == verify.URL_AS_RECORDED


def test_dispatch_records_how_the_url_was_derived():
    # The artifact should say what was aimed at, not leave it to be inferred
    # from a command line.
    plan = verify.build_dispatch(_finding("f-1"), {})
    # Nothing needed changing here, and the label says so rather than claiming a
    # rewrite: "as-recorded" and "rewritten" must stay distinguishable.
    assert plan["url_source"] == verify.URL_AS_RECORDED
    assert plan["injection_point"] == verify.INJECT_QUERY

    payload = _payload_finding("q", "1' OR 1=1--", "http://t/x?q=1%27+OR+1%3D1--")
    assert verify.build_dispatch(payload, {})["url_source"] == verify.URL_QUERY_RESET


def test_pass_one_records_no_cost_rather_than_a_zero_one():
    # Pass 1 dispatches tools and calls no model, so there is nothing to
    # measure. `$0.0000` read as "a model ran and was free", which is a
    # different claim — and this project's rule is that a missing measurement
    # and a measured zero must never look alike.
    from dast_orchestrator.foundation import metrics as run_metrics

    record = {"run": "R", "kind": "verify", "label": "", "started_at": "t",
              "total_seconds": 1.0, "stages": {},
              "results": {"dispatched": 3, "confirmed": 0, "cost_usd": None}}
    row = run_metrics.index_row(record)
    assert row["cost_usd"] is None


# -- the verification loop -------------------------------------------------
#
# No docker, no key: a stub dispatcher stands in for the MCP wrappers and a stub
# client for the model, so the loop's wiring is exercised end to end — propose ->
# validate -> execute -> classify -> react -> resolve — and the two readings it
# exists to produce are asserted directly.

import anyio  # noqa: E402

from dast_orchestrator.analysis import verify_loop


class _StubDispatcher:
    """Stands in for verify.Dispatcher: records calls, returns canned results."""

    def __init__(self, results):
        # tool -> one result, or a list consumed one per call so a loop can be
        # given a DIFFERENT answer on its second round. That is the whole point
        # of looping, so a stub that could not change its mind would make every
        # multi-round test vacuous.
        self._results = {k: list(v) if isinstance(v, list) else [v]
                         for k, v in results.items()}
        self.per_rule = {}
        self.calls = []

    async def run(self, tool, arguments, plugin_id=""):
        self.calls.append((tool, arguments, plugin_id))
        queue = self._results.get(tool)
        if not queue:
            return {"outcome": REFUTED, "detail": "clean", "tested": True,
                    "stdout_excerpt": "nothing"}
        return queue.pop(0) if len(queue) > 1 else queue[0]


class _StubClient:
    """Stands in for OpenRouterCorrelator: returns a canned round per call."""

    def __init__(self, rounds):
        self._rounds = list(rounds)
        self.model = "stub/verify"
        self.usage = None
        self.calls = []

    def complete(self, messages, **kw):
        # A snapshot, not the caller's list: the loop appends to the same
        # conversation each round, so keeping the reference would make every
        # recorded call look like the last one.
        self.calls.append((list(messages), kw))
        return self._rounds.pop(0)


def _loop(finding, plan, rounds, results, cfg=None, ctx=None):
    client = _StubClient(rounds)
    dispatcher = _StubDispatcher(results)
    verdict = anyio.run(
        verify.run_loop, dispatcher, finding, plan, ctx or {},
        cfg or verify.loop_config(), client, {},
    )
    return verdict, dispatcher, client


def _plan(tool="sqlmap", target="http://target/x?q=1", param="q"):
    return {"tool": tool, "plugin_id": "40018", "url_source": "as-recorded",
            "injection_point": "query",
            "arguments": {"target": target, "param": param, "method": "GET"}}


def _confirming_round():
    return [{"action": "conclude", "category": CONFIRMED, "tool": "sqlmap",
             "arguments": {"param": "q", "target": "http://target/x?q=1"},
             "declared_signal": {"require_tool_confirmed": True},
             "reasoning": "done"}]


def _confirming_result():
    return {"sqlmap": {"outcome": CONFIRMED, "evidence": "injectable",
                       "tested": True, "detail": "confirmed"}}


def test_pull_mode_hands_the_loop_the_retrieval_session_and_tools():
    # RETRIEVAL=pull: the loop must pass this finding's session, the tool
    # contract and the per-finding call ceiling to every model call, so the
    # model can ask the context server for more source mid-loop.
    class _Session:
        def close(self):
            pass

    class _Arm:
        tools = [{"function": {"name": "get_symbol_source"}}]
        max_calls = 4

    client = _StubClient(_confirming_round())
    dispatcher = _StubDispatcher(_confirming_result())
    session = _Session()

    async def _go():
        return await verify.run_loop(
            dispatcher, _finding("f-r", param="q"), _plan(), {},
            verify.loop_config(), client, {}, retrieval=_Arm(), session=session)

    anyio.run(_go)
    _, kw = client.calls[0]
    assert kw["retrieval"] is session
    assert kw["retrieval_tools"] == _Arm.tools
    assert kw["max_retrievals"] == 4


def test_push_mode_sends_no_retrieval_session_or_tools():
    # The default: nothing pulled, so the model gets no session, no tools, and a
    # zero ceiling — the loop reasons from what build_context pushed.
    _, _, client = _loop(_finding("f-p", param="q"), _plan(),
                         _confirming_round(), _confirming_result())
    _, kw = client.calls[0]
    assert kw["retrieval"] is None
    assert kw["retrieval_tools"] is None
    assert kw["max_retrievals"] == 0


def test_a_confirming_round_is_reported_confirmed():
    verdict, dispatcher, _ = _loop(
        _finding("f-1", param="q"), _plan(),
        [{"action": "conclude", "category": CONFIRMED, "tool": "sqlmap",
          "arguments": {"param": "q", "target": "http://evil"},
          "declared_signal": {"require_tool_confirmed": True},
          "reasoning": "name the injection point"}],
        {"sqlmap": {"outcome": CONFIRMED, "evidence": "injectable", "tested": True,
                    "detail": "confirmed", "stdout_excerpt": "Parameter: q"}},
    )
    assert verdict.reported == CONFIRMED
    assert verdict.wrapper_verdict == CONFIRMED and verdict.llm_verdict == CONFIRMED
    assert verdict.agreement == verification.AGREE
    # The model may not aim the tool: validate_probe dropped its target and the
    # executor derived the finding's own.
    assert "evil" not in dispatcher.calls[0][1]["target"]


def test_the_model_may_not_manufacture_a_confirmation():
    """The one place the model is blocked, and why a `confirmed` is worth the word.

    The tool ran and reported nothing; the model says confirmed anyway. That
    lands as a FLAGGED inconclusive — a countable disagreement — rather than as
    silent trust in an unbacked claim.
    """
    verdict, _, _ = _loop(
        _finding("f-2"), _plan(),
        [{"action": "conclude", "category": CONFIRMED, "tool": "sqlmap",
          "arguments": {}, "declared_signal": {"expect": ["boom"]},
          "reasoning": "I believe it"}],
        {"sqlmap": {"outcome": REFUTED, "detail": "no injection", "tested": True,
                    "stdout_excerpt": "clean"}},
    )
    assert verdict.reported == INCONCLUSIVE
    assert verdict.llm_verdict == CONFIRMED and verdict.wrapper_verdict == REFUTED
    assert verdict.agreement == verification.FLAGGED


def test_the_model_may_downgrade_a_tool_confirmation():
    """The model catching a tool false positive is the direction it is trusted in."""
    verdict, _, _ = _loop(
        _finding("f-3"), _plan(),
        [{"action": "conclude", "category": REFUTED, "tool": "sqlmap",
          "arguments": {}, "declared_signal": {"require_tool_confirmed": True},
          "reasoning": "the match is the error page, not an injection"}],
        {"sqlmap": {"outcome": CONFIRMED, "evidence": "?", "tested": True,
                    "detail": "confirmed", "stdout_excerpt": "maybe"}},
    )
    assert verdict.reported == REFUTED
    assert verdict.agreement == verification.FLAGGED


def test_a_tool_that_never_ran_cannot_be_rescued_into_a_verdict():
    """The integrity floor: a non-run is never a verdict, whatever the model says."""
    verdict, _, _ = _loop(
        _finding("f-4"), _plan(tool="nuclei"),
        [{"action": "conclude", "category": REFUTED, "tool": "nuclei",
          "arguments": {}, "declared_signal": {"expect": ["x"]},
          "reasoning": "nothing matched"}],
        {"nuclei": {"outcome": INCONCLUSIVE, "tested": False,
                    "detail": "nuclei ran no templates",
                    "tool_warnings": ["no templates provided"],
                    "stdout_excerpt": ""}},
    )
    assert verdict.reported == INCONCLUSIVE      # the wrapper's, not the model's
    assert verdict.llm_verdict == REFUTED
    assert verdict.agreement == verification.FLAGGED
    assert verdict.rounds[0].tool_ran is False


def test_the_loop_reacts_to_what_the_tool_returned():
    """Round 2 sees round 1's raw output, and can correct an invocation.

    This is the ceiling the single-shot design could not pass: the model never
    saw the tool's answer, so it could not fix a probe it had aimed wrong — and
    every verdict-moving fix in this project's history was about invocation.
    """
    # Both parameters are really in the request: since 2026-09-04 a sqlmap probe
    # naming one that is in neither the URL nor the body is refused before
    # dispatch, so a correction has to be to something addressable.
    url = "http://target/x?q=1&sort=asc"
    verdict, dispatcher, client = _loop(
        _finding("f-5", param="q", url=url), _plan(target=url),
        [{"action": "continue", "tool": "sqlmap", "arguments": {"param": "q"},
          "declared_signal": {"require_tool_confirmed": True}, "reasoning": "try q"},
         {"action": "continue", "tool": "sqlmap", "arguments": {"param": "sort"},
          "declared_signal": {"require_tool_confirmed": True},
          "note": "the 404 says q is not the injectable parameter",
          "reasoning": "aim at sort instead"},
         {"action": "conclude", "category": CONFIRMED,
          "note": "sort is injectable", "reasoning": "sqlmap named the point"}],
        {"sqlmap": [
            {"outcome": INCONCLUSIVE, "tested": False, "detail": "404",
             "stdout_excerpt": "[CRITICAL] page not found (404)"},
            {"outcome": CONFIRMED, "tested": True, "evidence": "injectable",
             "detail": "confirmed", "stdout_excerpt": "Parameter: sort"},
        ]},
    )
    # Two probes, three model turns: the concluding turn reads the output it was
    # handed rather than spending the budget on a question already answered.
    assert verdict.rounds_used == 2 and len(client.calls) == 3
    assert dispatcher.calls[0][1]["param"] == "q"
    assert dispatcher.calls[1][1]["param"] == "sort"
    # Round 2's prompt carried round 1's actual output, verbatim.
    round_two_prompt = client.calls[1][0][-1]["content"]
    assert "page not found (404)" in round_two_prompt
    # ...and only the newest turn is new: the rest is marked as a cache prefix,
    # which is the only lever there is against a loop re-sending its whole
    # conversation every turn.
    assert client.calls[1][1]["cache_prefix"] == 2
    assert client.calls[2][1]["cache_prefix"] == 3
    assert verdict.reported == CONFIRMED
    # The verdict is the FINAL round's wrapper reading, not the first's.
    assert verdict.wrapper_verdict == CONFIRMED
    # ...and the trajectory survives, so a first-time settle and a corrected one
    # are distinguishable.
    assert [r.wrapper_outcome for r in verdict.rounds] == [INCONCLUSIVE, CONFIRMED]


def test_the_round_cap_forces_a_conclusion():
    rounds = [{"action": "continue", "tool": "sqlmap", "arguments": {},
               "declared_signal": {"expect": ["x"]}, "reasoning": "again"}
              for _ in range(5)]
    verdict, dispatcher, _ = _loop(
        _finding("f-6"), _plan(), rounds,
        {"sqlmap": {"outcome": REFUTED, "tested": True, "detail": "clean",
                    "stdout_excerpt": "nothing"}},
        cfg=verify.loop_config(max_rounds=2),
    )
    # A runaway loop is a mistake to make impossible, not to apologise for.
    assert verdict.rounds_used == 2 and len(dispatcher.calls) == 2
    assert "cap" in verdict.stopped_because
    assert verdict.reported == REFUTED


def test_the_deterministic_configuration_calls_no_model_and_never_loops():
    dispatcher = _StubDispatcher(
        {"sqlmap": {"outcome": REFUTED, "tested": True, "detail": "clean"}})
    verdict = anyio.run(
        verify.run_loop, dispatcher, _finding("f-7"), _plan(), {},
        verify.loop_config("deterministic"), None, {},
    )
    assert len(dispatcher.calls) == 1          # single-shot by nature
    assert verdict.reported == REFUTED
    assert verdict.wrapper_verdict == REFUTED
    # No model ran, so there is no second reading — and no agreement claim.
    assert verdict.llm_verdict is None
    assert verdict.agreement == verification.AGREE


def test_a_finding_with_no_probeable_url_is_not_attempted_not_refuted():
    dispatcher = _StubDispatcher({})
    verdict = anyio.run(
        verify.run_loop, dispatcher, _finding("f-8"),
        {"tool": None, "refusal": verify.URL_NONE_RECORDED}, {},
        verify.loop_config(), None, {},
    )
    assert verdict.reported == NOT_ATTEMPTED and dispatcher.calls == []
    assert "no example URL" in verdict.detail


def test_a_model_that_stops_answering_leaves_the_tool_evidence_standing():
    """Losing the model must not lose the work the budget already paid for."""
    from dast_orchestrator.analysis.screening import LlmError

    class _DyingClient(_StubClient):
        def complete(self, messages, **kw):
            if self.calls:
                raise LlmError("upstream 502", "transient")
            self.calls.append((messages, kw))
            return {"action": "continue", "tool": "sqlmap", "arguments": {},
                    "declared_signal": {"expect": ["x"]}, "reasoning": "go"}

    dispatcher = _StubDispatcher(
        {"sqlmap": {"outcome": REFUTED, "tested": True, "detail": "clean"}})
    verdict = anyio.run(
        verify.run_loop, dispatcher, _finding("f-11"), _plan(), {},
        verify.loop_config(), _DyingClient([]), {},
    )
    assert verdict.rounds_used == 1
    assert verdict.wrapper_verdict == REFUTED
    assert verdict.llm_verdict is None          # the model never categorised
    assert verdict.reported == REFUTED          # the wrapper's reading stands
    assert "stopped answering" in verdict.stopped_because


def test_the_task_carries_the_handler_source_and_no_triage_conclusion():
    """The anti-circularity invariant, asserted on the actual prompt.

    Verification exists to check triage independently; a prober handed triage's
    hypothesis tests the hypothesis rather than the application.
    """
    finding = _finding("f-12")
    finding["llm"] = {"needs_rescan": True, "suggested_tool": "nuclei",
                      "reasoning": "TRIAGE SAID THIS IS REAL",
                      "verdict": "agree"}
    context = verify_loop.build_context(
        finding, exchange={"request": {"method": "GET"}},
        source={"blocks": [{"symbol": "repo.Issues", "text": "func Issues() {}"}]},
        fixed_tool="sqlmap")
    blob = json.dumps(context)
    assert "func Issues() {}" in blob
    assert "TRIAGE SAID THIS IS REAL" not in blob
    assert "triage" not in blob.lower()
    assert context["tool_is_fixed"]["tool"] == "sqlmap"


def test_a_run_without_code_context_says_so_rather_than_implying_an_empty_handler():
    context = verify_loop.build_context(_finding("f-13"), source=None)
    assert "No handler source is available" in context["handler_source"]["note"]


def test_a_conclude_on_the_last_round_is_honoured_after_its_probe_runs():
    """A round that both proposes and concludes still has its probe executed.

    Otherwise the model's category would rest on the *previous* round's output,
    and the wrapper would be auditing a different call than the one the model
    read — which audits nothing.
    """
    verdict, dispatcher, _ = _loop(
        _finding("f-14"), _plan(),
        [{"action": "conclude", "category": REFUTED, "tool": "sqlmap",
          "arguments": {"param": "q"},
          "declared_signal": {"require_tool_confirmed": True}, "reasoning": "x"}],
        {"sqlmap": {"outcome": REFUTED, "tested": True, "detail": "clean"}},
    )
    assert len(dispatcher.calls) == 1
    assert verdict.rounds_used == 1 and verdict.reported == REFUTED


def test_the_model_is_not_paid_for_a_probe_the_budget_will_refuse():
    """The model budget and the dispatch budget are spent on different things.

    An LLM configuration pays for its proposal BEFORE the executor sees it, so a
    finding the dispatch budget will refuse — or one no arm routed anywhere —
    costs real money for a proposal discarded unread. On the WordPress corpus
    576 of 604 findings route nowhere and they sort among the rest, so the whole
    model allowance could go to findings no tool was ever going to touch.
    """
    from contextlib import AsyncExitStack

    async def _check():
        async with AsyncExitStack() as stack:
            d = verify.Dispatcher(DispatchBudget(max_dispatches_total=1), stack)
            assert verify._can_dispatch(d, _plan()) is True
            # a finding no arm routed anywhere
            assert verify._can_dispatch(d, None) is False
            assert verify._can_dispatch(d, {"tool": None, "refusal": "x"}) is False
            # ...and once the budget is spent, nothing more is worth asking about
            d.dispatched = 1
            assert verify._can_dispatch(d, _plan()) is False

    anyio.run(_check)


def test_a_budget_refusal_does_not_erase_the_evidence_already_gathered():
    """"We did not check" must never overwrite "we checked and it was clean".

    A loop can gather real tool evidence and then have a later round refused by
    the budget. Taking that refusal as the finding's verdict reports
    `not-attempted` for something a tool had in fact tested a round earlier —
    it throws away work already paid for and, worse, records the one state the
    whole four-outcome vocabulary exists to keep separate.
    """
    from contextlib import AsyncExitStack

    async def _check():
        async with AsyncExitStack() as stack:
            # Room for exactly one dispatch, then the budget bites.
            d = verify.Dispatcher(DispatchBudget(max_dispatches_total=1), stack)
            d._sessions["sqlmap"] = None            # never opened: run() is stubbed
            results = iter([
                {"outcome": REFUTED, "tested": True, "detail": "clean"},
            ])

            async def run(tool, arguments, plugin_id=""):
                block = d._budget_block(plugin_id)
                if block is not None:
                    return {"outcome": NOT_ATTEMPTED, "tool": tool, "detail": block}
                d.dispatched += 1
                return next(results)

            d.run = run
            return await verify.run_loop(
                d, _finding("f-b"), _plan(), {}, verify.loop_config(), client,
                {}), client

    client = _StubClient([
        {"action": "continue", "tool": "sqlmap", "arguments": {},
         "declared_signal": {"expect": ["x"]}, "reasoning": "one"},
        {"action": "continue", "tool": "sqlmap", "arguments": {},
         "declared_signal": {"expect": ["y"]}, "reasoning": "two"},
        {"action": "continue", "tool": "sqlmap", "arguments": {},
         "declared_signal": {"expect": ["z"]}, "reasoning": "three"},
    ])
    verdict, client = anyio.run(_check)
    assert verdict.rounds_used == 2
    assert [r.wrapper_outcome for r in verdict.rounds] == [REFUTED, NOT_ATTEMPTED]
    # The verdict rests on the round that actually ran, not on the refusal.
    assert verdict.reported == REFUTED and verdict.wrapper_verdict == REFUTED
    assert "budget refused" in verdict.stopped_because
    # ...and the loop stopped rather than spending a third model call.
    assert len(client.calls) == 2


def test_the_model_can_ask_for_a_path_injection_point():
    """The one correction the loop most wanted to make, and could not.

    Watched live: on a `/commit/{sha}.{ext}` route a loop diagnosed across three
    rounds that "the actual injection point is in the URL path itself — using
    `*` marker in the URL path tells sqlmap where to inject", and then, having
    no field for it, kept proposing `-p ext` for a parameter that does not
    exist. The capability was already in the executor; setting `param` silently
    switched it off.
    """
    # The real finding, from the corpus the behaviour was observed on: a Gitea
    # commit route whose flagged "parameter" is the `{sha}.{ext}` path segment.
    finding = {
        "finding_id": "f-c107fa2873a1",
        "endpoint_key": "GET /{username}/{reponame}/commit/{sha:([a-f0-9]{7,40})}.{ext}",
        "method": "GET",
        "path": "/dastadmin/dast-public/commit/"
                "cc1d979339e0c628cbd2008d93dbf27e5457596a.patch",
        "alert": {"plugin_id": "40018", "name": "SQL Injection", "risk": "High",
                  "param": "cc1d979339e0c628cbd2008d93dbf27e5457596a.patch",
                  "method": "GET", "example_urls": [
                      "http://target-gitea:3000/dastadmin/dast-public/commit/"
                      "cc1d979339e0c628cbd2008d93dbf27e5457596a.patch"]},
        "deterministic": {"needs_rescan": True, "tool": "sqlmap"},
    }
    assert verify.probe_target(finding).injection_point == verify.INJECT_PATH

    # What the model actually proposed, three rounds running: a named parameter
    # that does not exist. Naming it used to switch the marker off, which sent
    # sqlmap at an unmarked URL with nothing to inject into. Since 2026-09-04 it
    # is refused before dispatch instead — `ext` is in neither the query string
    # nor a body, so there is nothing for sqlmap to address and the slot is not
    # spent discovering that.
    assert verify.directed_arguments(
        finding, "sqlmap", {"param": "ext"}, {}, {}, None, False) is None

    # With the lever it can now say what it meant.
    args = verify.directed_arguments(
        finding, "sqlmap", {"param": "ext", "path_injection": True}, {}, {},
        None, False)
    assert verify.SQLMAP_INJECTION_MARKER in args["target"]
    # A marked path leaves no name for `-p`, so the proposed parameter is
    # dropped rather than fighting the marker.
    assert args["param"] == ""
    # ...and the flag is an instruction to the executor, never a wrapper argument.
    assert "path_injection" not in args


def test_path_injection_is_a_permitted_probe_argument_and_a_boolean():
    from dast_orchestrator.domain import verification
    from dast_orchestrator.analysis import verify_loop

    assert "path_injection" in verification.ALLOWED_PROBE_ARGS
    clean, violations = verification.validate_probe(
        "sqlmap", {"path_injection": "yes", "param": "ext"})
    assert clean["path_injection"] is True and not violations
    assert "path_injection" in (
        verify_loop.ROUND_SCHEMA["properties"]["arguments"]["properties"])


def test_a_dropped_connection_costs_one_finding_not_the_whole_stage():
    """A flaky HTTP response must not discard a paid-for scan and triage.

    Observed 2026-09-03: `httpx.RemoteProtocolError: Server disconnected
    without sending a response` matched none of the transient markers, was
    re-raised out of the loop, and killed the WordPress baseline row at `verify`
    — after its 45-minute scan and full triage had already run. A finding is one
    unit of work; the blast radius has to match.
    """
    import httpx

    class _DroppingClient(_StubClient):
        def complete(self, messages, **kw):
            self.calls.append((list(messages), kw))
            raise httpx.RemoteProtocolError(
                "Server disconnected without sending a response.")

    dispatcher = _StubDispatcher({})
    verdict = anyio.run(
        verify.run_loop, dispatcher, _finding("f-drop"), _plan(), {},
        verify.loop_config(), _DroppingClient([]), {})

    # Recorded as a verdict, not raised as an exit.
    assert verdict.reported == NOT_ATTEMPTED
    assert "RemoteProtocolError" in verdict.stopped_because
    assert dispatcher.calls == []


def test_a_dropped_connection_is_retried_before_it_is_given_up_on():
    """...and it should rarely reach the loop at all: it is transient."""
    from dast_orchestrator.analysis.screening import OpenRouterCorrelator
    import httpx

    exc = httpx.RemoteProtocolError(
        "Server disconnected without sending a response.")
    assert OpenRouterCorrelator._is_transient(exc)


def test_an_empty_handler_source_block_is_not_counted_as_grounding():
    """The count says how many findings have SOURCE, not how many have a block.

    Every endpoint gets a block; one whose symbols the index could not resolve
    gets an empty `blocks` list plus a note. Counting blocks made the
    2026-09-04 WordPress baseline report "283 of 283 findings" grounded on a
    corpus where the real figure is 0 — and triage's own line on the same run
    said 0. It read correctly on Gitea, where grounding works, which is how it
    survived.
    """
    contexts = {
        "f-1": {"source": {"scoped_by": ["repo.Issues"],
                           "blocks": [{"symbol": "repo.Issues"}]}},
        "f-2": {"source": {"scoped_by": [], "blocks": [],
                           "note": "no handler source is attached"}},
        "f-3": {"exchange": {"request": {}}},          # no source at all
    }
    assert verify.count_grounded(contexts) == 1


def test_the_model_is_shown_what_the_tool_actually_ran():
    """An empty stdout must not reach the model as the whole story.

    nuclei with `-silent -jsonl` prints nothing when it matches nothing, so on
    2026-09-04 the loop's model saw `stdout_excerpt: ""` plus this pipeline's
    own word "refuted" — and agreed to refute a live XSS. The tool's own
    counters are the fact it can weigh instead.
    """
    record = verify_loop.RoundRecord(
        index=1, tool="nuclei", arguments={"target": "http://t/x"},
        tool_result={"outcome": "refuted", "detail": "matched nothing",
                     "stdout_excerpt": "", "exit_code": 0,
                     "scan_stats": {"templates": 195, "requests": 387,
                                    "matched": 0, "errors": 0}},
    )
    message = verify_loop.round_result_message(record, rounds_left=2)
    assert '"templates": 195' in message["content"]
    assert '"requests": 387' in message["content"]


def test_a_finding_no_arm_routed_is_distinguished_from_one_the_budget_dropped():
    """`not-attempted` had one name and three causes.

    A finding the BUDGET dropped and one nothing could ever have tested read
    identically in the artifact, which is how 200 of 283 flagged findings on the
    2026-09-04 WordPress baseline — rule 40026 among them, the corpus's only
    true positive — were routed nowhere without anything saying so.
    """
    nothing_routed = verify_loop.unattempted(
        "f-1", "no arm named a tool", code=verification.NA_NO_TOOL)
    no_url = verify_loop.unattempted(
        "f-2", "a tool was named, no probeable URL", code=verification.NA_NO_PROBE)

    assert nothing_routed.reported == verification.NOT_ATTEMPTED
    assert no_url.reported == verification.NOT_ATTEMPTED
    # Same outcome, different — and countable — cause.
    assert nothing_routed.as_dict()["not_attempted_reason"] == verification.NA_NO_TOOL
    assert no_url.as_dict()["not_attempted_reason"] == verification.NA_NO_PROBE


def test_a_finding_that_was_actually_probed_carries_no_not_attempted_reason():
    """The field must stay empty for everything that ran, or the count inflates."""
    verdict = verify_loop.unattempted("f-3", "budget")
    assert verdict.as_dict()["not_attempted_reason"] is None


def test_an_unreadable_wrapper_answer_cannot_support_a_verdict():
    """A wrapper error is a non-run, and must be recorded as one.

    Without `tested: False` here, `verification.tool_ran` falls through to its
    legacy reading and returns True — so a wrapper ERROR could back a
    refutation. Not hypothetical: the browser probe's tool name did not match
    the one the driver calls, and every round recorded `tool_ran: True` behind
    "Unknown tool: verify_browser".
    """
    class _Content:
        text = "Unknown tool: verify_browser"

    class _Result:
        is_error = True
        content = [_Content()]

    parsed = verify._parse_tool_result(_Result(), "browser")
    assert parsed["outcome"] == verification.INCONCLUSIVE
    assert parsed["tested"] is False
    assert verification.tool_ran(parsed) is False
    # And the bottom row of the resolution matrix then holds: a non-run is never
    # a verdict, whatever the model concluded.
    reported, agreement = verification.resolve_verdict(
        verification.INCONCLUSIVE, verification.REFUTED,
        ran=verification.tool_ran(parsed))
    assert reported == verification.INCONCLUSIVE
    assert agreement == verification.FLAGGED


def test_a_correlated_finding_does_not_arm_oob_behind_the_run_configuration():
    """Every dispatch path must carry the run's OOB setting, not a default.

    `build_dispatch` and `directed_arguments` set it; `build_correlated_dispatch`
    did not, so the nuclei wrapper's own default applied. Measured 2026-09-04:
    six rounds in the stored corpus ran `-iserver http://target-interactsh:8080`
    inside runs whose artifact recorded `oob_enabled: false`.
    """
    support = _finding("f-1")
    support["alert"]["example_urls"] = ["http://t/search?q=1"]
    correlated = {"finding_id": "c-000", "suggested_tool": "nuclei",
                  "supporting_finding_ids": ["f-1"]}

    off = verify.build_correlated_dispatch(correlated, {"f-1": support}, None, False)
    on = verify.build_correlated_dispatch(correlated, {"f-1": support}, None, True)
    assert off is not None and on is not None
    assert off["arguments"]["oob"] is False
    assert on["arguments"]["oob"] is True


def test_every_not_attempted_verdict_names_a_cause():
    """The counter is only worth having if it covers the population.

    First cut of `not_attempted_reason` covered the two routing causes and left
    the budget one unset, so the fresh WordPress artifact accounted for 8 of its
    76 not-attempted records and the other 68 read as uncategorised. A partial
    counter invites exactly the wrong conclusion — that the uncounted ones are
    a different, unexamined problem.
    """
    import ast
    import inspect

    # verify is a package; scan every submodule for the call sites.
    tree = ast.parse("\n".join(
        inspect.getsource(m)
        for m in (verify.common, verify.probes, verify.records, verify.driver)))
    sites = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", "") == "unattempted"
    ]
    assert sites, "no unattempted() call sites found — the check is vacuous"
    uncoded = [node.lineno for node in sites
               if not any(kw.arg == "code" for kw in node.keywords)]
    assert not uncoded, (
        f"unattempted() at line(s) {uncoded} passes no reason code, so those "
        f"records land in the artifact as uncategorised not-attempted"
    )
    # Pinned deliberately: a new cause must be added here consciously, because
    # every one of them is a different thing to do about it.
    assert set(verification.NA_REASONS) == {
        verification.NA_NO_TOOL, verification.NA_NO_PROBE,
        verification.NA_CAPPED, verification.NA_BY_DISPOSITION,
        verification.NA_TOOL_CANNOT_REACH}


def test_a_tool_is_not_asked_about_a_parameter_it_does_not_send():
    """sqlmap is the only wrapper that carries a request body.

    nuclei, ffuf and the browser oracle are handed a URL and nothing else, so a
    parameter that lives in a form body is not in the request they make — and
    what comes back is a verdict on the query string they fuzzed instead, filed
    against the body field ZAP flagged. Measured 2026-09-08 on the stored
    baselines: 9 such dispatches on WordPress and 1 on Gitea, including **6 of
    WordPress's 15 refutations**.
    """
    body_flagged = {
        "finding_id": "f-body", "method": "POST",
        "alert": {"plugin_id": "10031", "method": "POST", "param": "password",
                  "example_urls": ["http://target-gitea:3000/user/login"]},
        "deterministic": {"needs_rescan": True, "tool": "nuclei"},
    }
    assert verify.probe_target(body_flagged).injection_point == verify.INJECT_BODY

    plan = verify.build_dispatch(body_flagged, {})
    assert plan["tool"] is None
    assert plan["refusal"] == verify.PARAM_NOT_IN_TOOLS_REQUEST

    # sqlmap is exempt, because it is handed the body it needs to reach it.
    sqlmap_flagged = {**body_flagged,
                      "deterministic": {"needs_rescan": True, "tool": "sqlmap"}}
    sqlmap_plan = verify.build_dispatch(sqlmap_flagged, {})
    assert sqlmap_plan["tool"] == "sqlmap"

    # …and a QUERY parameter still reaches nuclei untouched: the refusal is
    # about where the parameter lives, never about the tool.
    query_flagged = {
        "finding_id": "f-query", "method": "GET",
        "alert": {"plugin_id": "10031", "method": "GET", "param": "q",
                  "example_urls": ["http://target-gitea:3000/explore?q=x"]},
        "deterministic": {"needs_rescan": True, "tool": "nuclei"},
    }
    assert verify.build_dispatch(query_flagged, {})["tool"] == "nuclei"


def test_a_parameter_reach_refusal_is_not_counted_as_a_missing_url():
    """`no-probe-url` says no URL could be built. Here the URL is fine.

    Folding the two together would hide a class worth 6 of WordPress's 15
    refutations behind a number that already means something else — the exact
    conflation `NA_REASONS` was introduced to end.
    """
    from dast_orchestrator.analysis import verify_loop

    for refusal in verify.PARAM_REACH_REFUSALS:
        assert refusal not in verify.URL_REFUSALS
    assert verification.NA_TOOL_CANNOT_REACH != verification.NA_NO_PROBE
    assert verify_loop.unattempted("f-1", "d", code=verification.NA_TOOL_CANNOT_REACH)


def test_sqlmap_is_not_dispatched_at_a_parameter_it_cannot_address():
    """sqlmap needs a query parameter, a body parameter, or a marked path.

    Measured on the 2026-09-04 WordPress baseline: of 15 sqlmap probes in the
    deterministic row, exactly ONE put the question to the target. The largest
    bucket was five probes naming a parameter that was simply not in the
    request — `-p wpdm_login[log]` against a body of
    `__phash=ZAP&orderby=ZAP&redirect_to=/`. sqlmap does not fail loudly on
    that; it reports that the target may have rejected the probe, which reads
    like a fact about the application rather than about the request. Those five
    held rule 40018's entire per-rule cap and settled nothing.
    """
    can = verify.sqlmap_can_address
    assert can("http://t/x?q=1", "q", "") is True             # in the query
    assert can("http://t/x", "user", "user=a&pw=b") is True   # in the body
    assert can("http://t/x/seg*", "", "") is True             # marked path
    assert can("http://t/x?q=1", "sort", "other=1") is False  # in neither
    assert can("http://t/x", "", "") is False                 # nothing at all


def test_the_refusal_says_which_request_the_parameter_is_missing_from():
    detail = verify._refusal_detail(verify.PARAM_NOT_IN_REQUEST)
    assert "query string nor the request body" in detail
    assert "marked injection point" in detail


def test_a_synthesis_claim_that_needs_no_tool_is_not_a_routing_gap():
    """`self-evident` and `out-of-scope` are dispositions, not missing rows.

    They were counted as `no-tool-routed` until 2026-09-04 — 9 of the 11 on the
    WordPress baseline — under a warning telling the reader that each is a rule
    the rescan table does not route. It sends them hunting for table rows that
    do not exist.
    """
    code = verify._synthesis_not_attempted_code
    assert code({"suggested_tool": "self-evident"}) == verification.NA_BY_DISPOSITION
    assert code({"suggested_tool": "out-of-scope"}) == verification.NA_BY_DISPOSITION
    # A claim that named a real tool and simply had no anchor is a probe
    # refusal, which is a different fact again.
    assert code({"suggested_tool": "sqlmap"}) == verification.NA_NO_PROBE


def test_a_payload_shaped_parameter_is_not_read_as_a_clean_path_segment():
    """ZAP sometimes records the injected string AS the parameter name.

    `restore_path_payload` bails out when `attack == param`, and the
    "already-clean path parameter" branch then reads the segment as clean
    because the payload is tautologically present in the path. Four of the
    fifteen sqlmap probes on the 2026-09-04 WordPress baseline went at URLs
    like `http://target-wordpress/%22+__lm_logo+`, and every one 404'd.
    """
    finding = {
        "finding_id": "f-p", "endpoint_key": "", "method": "GET", "path": "/x",
        "alert": {"plugin_id": "40018", "name": "SQL Injection", "risk": "High",
                  "param": '"+__lm_logo+', "method": "GET",
                  "example_urls": ['http://t/%22+__lm_logo+']},
        "deterministic": {"needs_rescan": True, "tool": "sqlmap"},
    }
    probe = verify.probe_target(finding)
    assert probe.probeable is False
    assert probe.url_source == verify.URL_PAYLOAD_UNRECOVERABLE
    # A parameter that merely looks unusual is still a parameter.
    assert verify.looks_like_payload("permalink") is False


def test_array_style_form_fields_find_their_declared_filler():
    """PHP posts `wpdm_login[log]`; the target declares `log`.

    An exact-match lookup missed every one, so the login SQLi probes posted
    `wpdm_login[log]=ZAP&wpdm_login[pwd]=ZAP` — credentials the application
    rejects before any injectable code runs.
    """
    fillers = {"log": "dastuser", "pwd": "secret"}
    assert verify.filler_for("wpdm_login[log]", fillers) == "dastuser"
    assert verify.filler_for("log", fillers) == "dastuser"
    assert verify.filler_for("nonce", fillers) is None
    # An explicit declaration still wins over the bracketed fallback.
    assert verify.filler_for(
        "wpdm_login[log]", {**fillers, "wpdm_login[log]": "exact"}) == "exact"


def test_the_dispatch_says_which_body_fields_were_invented():
    body = "log=dastuser&nonce=ZAP&pwd=secret"
    assert verify.placeholder_fields(body) == ["nonce"]
    assert verify.placeholder_fields("") == []


def test_a_sibling_probe_is_not_capped_by_its_anchors_noisy_rule():
    """Measured on the first live run: all 12 siblings refused, none dispatched.

    The per-rule cap stops one prolific ZAP rule spending the budget on
    near-duplicates — 10031 fires 348 times on the Gitea corpus. A sibling probe
    is not another instance of that rule: it visits a route no other probe
    visits. Counting it under the anchor's cap made the propagation half hostage
    to how noisy its anchor's rule happened to be.
    """
    import anyio
    from contextlib import AsyncExitStack

    async def scenario():
        async with AsyncExitStack() as stack:
            budget = DispatchBudget(tool_timeout_seconds=1,
                                    max_dispatch_all_rules=1,
                                    max_dispatches_total=10, max_minutes=10)
            dispatcher = verify.Dispatcher(budget, stack)
            dispatcher._sessions["nuclei"] = _StubSession()
            first = await dispatcher.run("nuclei", {"target": "http://t"}, "10031")
            capped = await dispatcher.run("nuclei", {"target": "http://t"}, "10031")
            sibling = await dispatcher.run("nuclei", {"target": "http://t"},
                                           "10031", exempt_per_rule=True)
            return first, capped, sibling

    first, capped, sibling = anyio.run(scenario)
    assert first["outcome"] != NOT_ATTEMPTED
    assert capped["outcome"] == NOT_ATTEMPTED, "the per-rule cap still bites"
    assert sibling["outcome"] != NOT_ATTEMPTED, (
        "a sibling probe must not be refused by its anchor rule's cap")


class _StubSession:
    """Answers `call_tool` with a refutation, so only the budget is under test."""

    async def call_tool(self, name, arguments):
        class _R:
            content = [type("C", (), {"text": json.dumps(
                {"outcome": REFUTED, "detail": "nothing"})})()]
            isError = False
        return _R()


# -- the sibling reachability pre-check ------------------------------------
#
# Measured on the first live run of the propagation dispatch (2026-09-05,
# sheet-10 Gitea corpus): of claim c-000's three siblings, ONE reached a real
# page and two rendered Gitea's "Page Not Found". Their `refuted` verdicts
# refuted the constructed URL, not the claim. One clean GET before the probe
# separates the two.


def test_a_route_the_application_does_not_serve_is_not_probed():
    """A 404 is a fact about the URL, so it must not be dressed as a refutation."""
    import anyio

    probes = []

    async def scenario():
        return await _run_siblings(
            probes, check_route=lambda url: 404 if "tag" in url else 200)

    records = anyio.run(scenario)
    by_route = {r["route"]: r for r in records}

    absent = by_route["GET /{u}/{r}/commits/tag/*"]
    # Its OWN outcome, not `not-attempted`. "We did not get to it" and "we asked
    # and the route does not exist" are opposite facts, and the second is a
    # result about the claim that this machinery produces and nothing else does.
    assert absent["outcome"] == verification.SIBLING_UNREACHABLE
    assert absent["outcome"] != NOT_ATTEMPTED
    assert absent["route_status"] == 404
    assert all("commits/tag" not in p for p in probes), (
        "the unserved route was probed anyway — the pre-check saved nothing")

    served = by_route["GET /{u}/{r}/commits/commit/*"]
    assert served["outcome"] == REFUTED
    assert served["route_status"] == 200


def test_a_pre_check_that_could_not_run_still_lets_the_probe_run():
    """"We could not look" is not "the route is absent".

    The same rule every cost field here follows: a missing measurement and a
    measured 404 must never look alike. A docker failure must not silently drop
    a probe that would otherwise have run.
    """
    import anyio

    probes = []
    records = anyio.run(lambda: _run_siblings(probes, check_route=lambda _u: None))

    assert len(records) == 2
    assert all("commits/tag" in u or "commits/commit" in u for u in probes[1:]), \
        "both sibling probes must still run"
    assert all(r["route_status"] is None for r in records)
    assert all(r["outcome"] == REFUTED for r in records)


def test_an_unreachable_sibling_is_its_own_outcome_not_a_not_attempted():
    """It is a FINDING this machinery produces, and a new one.

    `not-attempted` has always meant *unexamined* — a budget ran out, no tool
    was routed, nothing could be aimed. An unreachable sibling is the opposite:
    we asked, and the route the claim predicted does not exist. Filing it under
    `not-attempted` would bury a result inside the column that means "we did not
    look", which is the conflation this project refuses everywhere else.
    """
    assert verification.SIBLING_UNREACHABLE not in verification.OUTCOMES, (
        "the four flagged-population outcomes are load-bearing and must not "
        "gain a fifth member")
    assert verification.SIBLING_UNREACHABLE in verification.SIBLING_OUTCOMES
    assert set(verification.OUTCOMES) < set(verification.SIBLING_OUTCOMES)
    assert verification.SIBLING_UNREACHABLE != NOT_ATTEMPTED


def test_the_checker_turns_any_transport_failure_into_unknown():
    """The pre-check is an honesty measure, not a new way for a run to fail."""
    def explodes(method, url, timeout):
        raise RuntimeError("docker not on PATH")

    assert verify.route_checker(fetch=explodes)("http://t/x") is None
    # A status of 0 — curl could not reach the target at all — is unknown too,
    # never a 404.
    assert verify.route_checker(fetch=lambda *_a: (0, "", ""))("http://t/x") is None
    assert verify.route_checker(fetch=lambda *_a: (404, "", ""))("http://t/x") == 404


def test_only_a_not_here_counts_as_absent():
    """A guarded, broken or redirecting route is still a page worth probing."""
    for status in (301, 302, 401, 403, 500, 200):
        assert status not in verification.ROUTE_ABSENT_STATUSES, (
            f"{status} means the route EXISTS; skipping it would drop a real probe")
    assert verification.ROUTE_ABSENT_STATUSES == {404, 410}


async def _run_siblings(probes: list, check_route):
    """Drive `verify_all` over one propagation claim with two sibling routes."""
    anchor_key = "GET /{u}/{r}/commits/branch/*"
    support = _finding("f-sup", plugin="10031", param="q", endpoint_key=anchor_key,
                       url="http://target/thesis/demo/commits/branch/master?q=ZAP")
    claim = {"finding_id": "c-0", "pattern": "propagation-shared-handler",
             "suggested_tool": "nuclei", "supporting_finding_ids": ["f-sup"],
             # The anchor is not its own sibling; one served route and one the
             # application does not have.
             "affected_routes": [anchor_key, "GET /{u}/{r}/commits/tag/*",
                                 "GET /{u}/{r}/commits/commit/*"],
             "title": "shared handler XSS", "severity": "medium"}
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})

    class _Recording(_StubSession):
        async def call_tool(self, name, arguments):
            probes.append(str(arguments.get("target", "")))
            return await super().call_tool(name, arguments)

    original = verify.Dispatcher._session

    async def _stub_session(self, tool):
        return _Recording()

    verify.Dispatcher._session = _stub_session
    try:
        from dast_orchestrator.adapters import targets

        targets.load_all()
        _v, _c, siblings, _pr, _info, _os = await verify.verify_all(
            [], [(claim, plan)],
            # Keyword, not positional: the budget grew a `rule_caps` field
            # between `max_dispatch_all_rules` and the run total, and a
            # positional call silently handed an int to it.
            DispatchBudget(tool_timeout_seconds=1, max_dispatch_all_rules=10,
                           max_dispatches_total=10, max_minutes=10), {},
            verify.loop_config(invocation="deterministic"),
            findings_by_id={"f-sup": support}, target=targets.get("gitea"),
            # The propagation dispatch is off by default; these tests are of the
            # feature, so they switch it on explicitly.
            max_siblings=verify.SIBLINGS_WHEN_ENABLED,
            check_route=check_route,
        )
        return siblings
    finally:
        verify.Dispatcher._session = original


def test_the_propagation_dispatch_is_off_unless_a_run_asks_for_it():
    """The default must stay the thing every recorded number was produced by.

    It changes what a `verify` run contains — extra dispatches, a new `s-`
    finding class, its own report section, and a target the driver must reach
    over dast-net — so a run with it is not comparable with one without. Same
    rule as the synthesis ensemble, OAST and pull retrieval: a deliberate
    purchase, never a silent default.
    """
    assert verify.DEFAULT_MAX_SIBLINGS == 0
    support = _finding("f-sup", plugin="10031", param="q")
    claim = _propagation(["GET /a", "GET /b"])
    plan = verify.build_correlated_dispatch(claim, {"f-sup": support})
    from dast_orchestrator.adapters import targets

    targets.load_all()
    assert verify.build_sibling_dispatches(
        claim, plan, support, targets.get("gitea"), set(),
        verify.DEFAULT_MAX_SIBLINGS) == []
    assert verify.build_sibling_dispatches(
        claim, plan, support, targets.get("gitea"), set(),
        verify.SIBLINGS_WHEN_ENABLED) != []


def test_the_verification_artifact_says_which_routing_table_produced_it():
    """And it is the CORRELATION's table version, not the live one.

    `selected_tool` reads `finding.deterministic.tool` — a value the table wrote
    at *correlate* time — so editing a rule's `tool=` changes nothing about a
    stored corpus until `correlate` is re-run over it. Measured 2026-09-08:
    rule 10031 re-routed to `browser` and verification re-run on the stored
    Gitea corpus gave a byte-identical outcome mix, every 10031 still on nuclei.

    Stamping the live version here would therefore label an artifact with a
    table that did not route it — the field lying in precisely the case it was
    added for.
    """
    from dast_orchestrator.domain import rescan_table

    older = rescan_table.RESCAN_TABLE_VERSION - 1
    routed_by_older = verify.build_artifact(
        "triage-x.json", "20260101T000000Z-gitea-abc123",
        DispatchBudget(), [], [], {}, table_version=older)
    assert routed_by_older["rescan_table_version"] == older, (
        "the live version was stamped over a corpus an older table routed")

    # A corpus correlated before the version was recorded leaves it null rather
    # than borrowing today's number — a missing measurement and a measured value
    # must never look alike.
    unknown = verify.build_artifact(
        "triage-x.json", "20260101T000000Z-gitea-abc123",
        DispatchBudget(), [], [], {})
    assert unknown["rescan_table_version"] is None


def test_the_run_total_outranks_every_per_rule_cap():
    """A generous per-rule cap must not be able to overrun the stage's ceiling.

    This is what makes the per-rule layer safe to raise: a sheet can hand one
    noisy rule 200 dispatches without the run becoming unbounded, because the
    total still ends it. The check order in `_budget_block` IS the precedence,
    so reversing those lines would silently change the guarantee.
    """
    d = _dispatcher(DispatchBudget(max_dispatch_all_rules=1,
                                   rule_caps=(("40018", 200),),
                                   max_dispatches_total=10))
    d.per_rule["40018"] = 3
    assert d._budget_block("40018") is None        # its own cap, far from spent
    d.dispatched = 10                              # …but the run total is not
    assert "run total cap" in d._budget_block("40018")

    # And with the total switched off, the per-rule cap governs again.
    loose = _dispatcher(DispatchBudget(rule_caps=(("40018", 2),),
                                       max_dispatches_total=verification.NO_CAP))
    loose.dispatched = 10_000
    loose.per_rule["40018"] = 2
    assert "rule cap (2)" in loose._budget_block("40018")


def test_one_argument_may_carry_every_rule_cap():
    """`--max-dispatch-rule 40018=40,30002=5` rather than the flag twice.

    Same parser as the env var, so a sheet and a command line say the same thing
    the same way — and repeating the flag still works, since argparse appends
    and each item is split independently.
    """
    assert verification.parse_rule_caps(["40018=40,30002=5"]) == {
        "40018": 40, "30002": 5}
    assert verification.parse_rule_caps(["40018=40", "30002=5"]) == {
        "40018": 40, "30002": 5}
    # Whitespace around either half is a typo, not an error.
    assert verification.parse_rule_caps([" 40018 = 40 , 30002=5 "]) == {
        "40018": 40, "30002": 5}


def test_the_browser_oracle_is_given_the_form_body_it_now_knows_what_to_do_with():
    """The §N3 blocker, removed: 10031's form fields become probeable.

    9 of Gitea's 25 flagged `10031` findings inject at a form-body parameter,
    and the browser wrapper refused them because it could only build a URL. It
    can now POST, so the dispatch has to hand it the body — otherwise the
    capability exists and nothing reaches it.
    """
    finding = {
        "finding_id": "f-body", "method": "POST",
        "endpoint_key": "POST /user/login",
        "alert": {"plugin_id": "10031", "method": "POST", "param": "password",
                  "example_urls": ["http://target-gitea:3000/user/login"]},
        "deterministic": {"needs_rescan": True, "tool": "browser"},
    }
    by_endpoint = {"POST /user/login": [
        finding,
        {"alert": {"param": "user_name", "method": "POST"}},
    ]}
    plan = verify.build_dispatch(finding, by_endpoint)
    assert plan["tool"] == "browser"
    assert "password" in plan["arguments"]["data"]
    assert plan["arguments"]["method"] == "POST"

    # nuclei and ffuf still carry no body, so they are still refused rather than
    # sent to fuzz a query string and report on a field they never touched.
    for tool in ("nuclei", "ffuf"):
        assert tool not in verify.BODY_CAPABLE_TOOLS
        other = {**finding, "deterministic": {"needs_rescan": True, "tool": tool}}
        assert verify.build_dispatch(other, by_endpoint)["refusal"] == \
            verify.PARAM_NOT_IN_TOOLS_REQUEST


def test_a_body_capable_tool_with_no_body_to_send_is_still_refused(monkeypatch):
    """The capability is not the same as having used it.

    In practice `_form_body` always yields at least the flagged field — an
    endpoint with nothing recorded gets a placeholder, marked as such in
    `placeholder_fields`, and the bootstrap replaces it with the payload anyway,
    so the probe is real. The guard is for the case where it comes back empty:
    without it the plan falls through to a URL-only probe of a parameter that is
    not in the URL, which is the refutation-of-an-unasked-question the refusal
    exists to prevent.
    """
    finding = {
        "finding_id": "f-body", "method": "POST",
        "endpoint_key": "POST /x",
        "alert": {"plugin_id": "10031", "method": "POST", "param": "pw",
                  "example_urls": ["http://target-gitea:3000/x"]},
        "deterministic": {"needs_rescan": True, "tool": "browser"},
    }
    # The ordinary case: a body is built, and the invented field is declared.
    plan = verify.build_dispatch(finding, {})
    assert plan["tool"] == "browser" and plan["arguments"]["data"]
    assert plan["placeholder_fields"] == ["pw"]

    monkeypatch.setattr(verify.probes, "_form_body", lambda *a, **k: "")
    refused = verify.build_dispatch(finding, {})
    assert refused["tool"] is None
    assert refused["refusal"] == verify.PARAM_NOT_IN_TOOLS_REQUEST


def test_verify_all_forwards_the_oracle_block_to_the_finding_loop(monkeypatch):
    """Ceiling runs must hand the advisory to the FLAGGED-FINDING loop, not only
    to the synthesis-claim loop.

    Regression for the 2026-11-01 defect: ``verify_all`` called ``run_loop`` for
    dispatchable findings positionally up to ``system_prompt`` and then jumped to
    the keyword arguments, so ``oracle`` defaulted to ``None`` and
    ``build_context`` silently dropped ``known_vulnerabilities_of_this_target``
    and the earlier-triage view in every ceiling run — while the claim loop
    passed it. The existing ``test_oracle`` cases pin ``build_context`` in
    isolation; nothing exercised this wiring, which is how it went unnoticed.
    A blind run (``oracle=None``) must still receive ``None`` so its loop stays
    independent.
    """
    from dast_orchestrator.analysis import verify_loop
    from dast_orchestrator.stages.verify import records

    seen: dict[str, object] = {}

    async def _fake_run_loop(dispatcher, finding, plan, ctx, cfg, client,
                             findings_by_endpoint, fillers=None, auth_ctx=None,
                             oob=False, system_prompt=None, oracle=None,
                             retrieval=None, session=None):
        seen[str(finding.get("finding_id"))] = oracle
        return verify_loop.unattempted(
            str(finding.get("finding_id")), "stub", code=verification.NA_NO_PROBE)

    monkeypatch.setattr(records, "run_loop", _fake_run_loop)

    finding = _finding("f-oracle")
    block = {"known_vulnerabilities_of_this_target": "CVE-X at /sink"}

    async def _drive(oracle):
        return await verify.verify_all(
            [finding], [],
            DispatchBudget(max_dispatch_all_rules=10, max_dispatches_total=10,
                           max_minutes=10),
            {}, verify.loop_config(invocation="llm"),
            oracle=oracle,
        )

    seen.clear()
    anyio.run(_drive, block)
    assert seen["f-oracle"] == block, "ceiling: the finding loop must get the oracle"

    seen.clear()
    anyio.run(_drive, None)
    assert seen["f-oracle"] is None, "blind: the oracle must not leak into the loop"
