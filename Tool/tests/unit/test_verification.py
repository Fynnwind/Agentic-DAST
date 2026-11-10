"""The Phase 4 control layer: outcome vocabulary, budget, and finding selection.

Pure functions and pure data, so these tests need no containers and no MCP —
they pin the routing and prioritisation decisions the writeup rests on.
"""

from __future__ import annotations

import pytest

from dast_orchestrator.domain import verification
from dast_orchestrator.domain.verification import DispatchBudget


def _finding(fid="f-1", plugin="40018", risk="High", det=False, det_tool=None,
             llm=None, llm_tool=None, param="q"):
    return {
        "finding_id": fid,
        "method": "GET",
        "path": "/x",
        "alert": {"plugin_id": plugin, "risk": risk, "param": param,
                  "method": "GET", "example_urls": ["http://t/x?q=1"]},
        "deterministic": {"needs_rescan": det, "tool": det_tool},
        "llm": ({"needs_rescan": llm, "suggested_tool": llm_tool}
                if llm is not None else None),
    }


def test_four_outcomes_are_distinct():
    assert len(set(verification.OUTCOMES)) == 4
    assert verification.REFUTED != verification.INCONCLUSIVE
    assert verification.NOT_ATTEMPTED not in (
        verification.REFUTED, verification.INCONCLUSIVE, verification.CONFIRMED
    )


def test_budget_defaults_and_env_override(monkeypatch):
    for var in ("VERIFY_MAX_DISPATCH_ALL_RULES", "VERIFY_MAX_DISPATCH_RULE"):
        monkeypatch.delenv(var, raising=False)
    default = DispatchBudget.from_env()
    assert default.max_dispatch_all_rules == 15
    assert default.max_dispatches_total == 40
    assert default.rule_caps == ()

    monkeypatch.setenv("VERIFY_MAX_DISPATCH_ALL_RULES", "3")
    monkeypatch.setenv("VERIFY_TOOL_TIMEOUT_SECONDS", "45")
    tuned = DispatchBudget.from_env()
    assert tuned.max_dispatch_all_rules == 3 and tuned.tool_timeout_seconds == 45


def test_a_rule_named_in_the_env_gets_its_own_cap_and_the_rest_the_blanket_one(
        monkeypatch):
    """The setting the WordPress baseline could not express.

    66 of that run's 73 budget refusals were the per-rule cap and 38 of those
    were rule 40018 alone, so the useful instruction was "let that one rule go
    further" — which a single blanket number can only obey by moving every other
    rule with it.
    """
    monkeypatch.setenv("VERIFY_MAX_DISPATCH_ALL_RULES", "15")
    monkeypatch.setenv("VERIFY_MAX_DISPATCH_RULE", "40018=40, 30002=5")
    budget = DispatchBudget.from_env()
    assert budget.cap_for("40018") == 40
    assert budget.cap_for("30002") == 5
    assert budget.cap_for("10031") == 15      # unnamed: the blanket cap
    assert budget.as_dict()["max_dispatch_rule"] == {"40018": 40, "30002": 5}


def test_a_malformed_rule_cap_is_refused_rather_than_ignored():
    """Silently dropped, the whole stage runs at a budget nobody chose."""
    import pytest as _pytest

    for bad in ("40018", "40018=lots", "=15"):
        with _pytest.raises(ValueError):
            verification.parse_rule_caps([bad])


def test_NO_CAP_is_minus_one_so_zero_keeps_its_arithmetic_meaning():
    """`--max-dispatch-rule 10031=0` must mean NEVER, not WITHOUT LIMIT.

    Once a cap can be set per rule, "never dispatch this rule" is the single
    most useful thing to be able to say about a noisy one — and a sentinel that
    claimed 0 for "unlimited" would make it the one setting inexpressible.
    """
    assert verification.NO_CAP == -1
    assert verification.parse_rule_caps(["10031=0"]) == {"10031": 0}


def test_bad_env_value_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("VERIFY_MAX_DISPATCHES_TOTAL", "not-a-number")
    assert DispatchBudget.from_env().max_dispatches_total == 40


def test_selected_tool_prefers_deterministic_over_llm():
    f = _finding(det=True, det_tool="sqlmap", llm=True, llm_tool="nuclei")
    assert verification.selected_tool(f) == "sqlmap"


def test_selected_tool_uses_llm_when_table_named_none():
    f = _finding(det=True, det_tool=None, llm=True, llm_tool="nuclei")
    assert verification.selected_tool(f) == "nuclei"


def test_selected_tool_none_when_only_suggestion_is_none():
    f = _finding(det=False, llm=True, llm_tool="none")
    assert verification.selected_tool(f) is None
    assert not verification.is_dispatchable(f)


def test_selected_tool_none_when_unflagged():
    assert verification.selected_tool(_finding(det=False)) is None


def test_dispatch_priority_orders_high_risk_and_both_arms_first():
    both_high = _finding("f-a", risk="High", det=True, det_tool="sqlmap",
                         llm=True, llm_tool="sqlmap")
    det_only_high = _finding("f-b", risk="High", det=True, det_tool="sqlmap")
    info = _finding("f-c", plugin="10031", risk="Informational", det=True,
                    det_tool="nuclei")
    ordered = sorted([info, det_only_high, both_high],
                     key=verification.dispatch_priority)
    assert [f["finding_id"] for f in ordered] == ["f-a", "f-b", "f-c"]


def test_dispatch_priority_is_stable_by_finding_id():
    a = _finding("f-zzz", risk="Low", det=True, det_tool="nuclei")
    b = _finding("f-aaa", risk="Low", det=True, det_tool="nuclei")
    assert sorted([a, b], key=verification.dispatch_priority)[0]["finding_id"] == "f-aaa"


# -- budget precedence: flag > env > default -------------------------------


def test_budget_override_replaces_only_what_is_given():
    # Every other knob in the pipeline is a flag with an env default; the budget
    # was env-only, which made the one setting most often tuned per run the one
    # that could not be passed as an argument.
    base = verification.DispatchBudget(
        tool_timeout_seconds=120, max_dispatch_all_rules=15,
        max_dispatches_total=40, max_minutes=20)
    tuned = base.override(max_dispatch_all_rules=30, max_dispatches_total=None)
    assert tuned.max_dispatch_all_rules == 30
    assert tuned.max_dispatches_total == 40   # None keeps the env/default value
    assert tuned.tool_timeout_seconds == 120
    assert base.max_dispatch_all_rules == 15  # the original is untouched


def test_a_rule_cap_on_the_command_line_merges_with_the_ones_the_env_set():
    """Replacing would silently drop an env file's caps.

    A sheet sets the run's shape and a command line tunes one rule of it; if
    naming 40018 on the command line dropped the sheet's 30002 cap, the run
    would differ from the sheet in a way neither says.
    """
    from_env = verification.DispatchBudget(rule_caps=(("30002", 5),))
    tuned = from_env.override(rule_caps=(("40018", 40),))
    assert dict(tuned.rule_caps) == {"30002": 5, "40018": 40}
    # …and an explicit cap for a rule the env already named wins.
    assert dict(from_env.override(rule_caps=(("30002", 9),)).rule_caps) == {
        "30002": 9}


def test_budget_override_with_nothing_given_is_a_no_op():
    base = verification.DispatchBudget.from_env()
    assert base.override(max_dispatch_all_rules=None, max_minutes=None) == base


# -- does the confirmation confirm the finding? ----------------------------


def test_a_confirmation_in_the_rules_own_class_matches():
    check = verification.classification_match(
        79, [{"template_id": "reflected-xss", "cwe": [], "tags": ["xss", "dast"]}]
    )
    assert check["class"] == verification.CLASS_MATCH


def test_a_confirmation_in_another_class_is_recorded_as_a_mismatch():
    check = verification.classification_match(
        89, [{"template_id": "t", "cwe": ["CWE-79"], "tags": []}]
    )
    assert check["class"] == verification.CLASS_MISMATCH
    assert "sqli" in check["detail"] and "xss" in check["detail"]


# nuclei's `cookie-injection` template as it actually reports: no CWE of its
# own, and tags that place it in both the cookies and injection families. This
# is the match behind the Gitea class-check defect (fixed 2026-10-26).
_COOKIE_INJECTION = [{"template_id": "cookie-injection", "cwe": [],
                      "tags": ["reflected", "dast", "cookie", "injection", "vuln"]}]


def test_10031_cookie_injection_is_a_class_mismatch_not_unspecific():
    # ZAP rule 10031 (*potential XSS*) carries the catch-all CWE-20, which
    # cwe_family cannot place — but the rule id says XSS, so a cookie-injection
    # match is a MISMATCH, not the old `unspecific` that let it stand as a
    # confirmation of the reported XSS.
    check = verification.classification_match(20, _COOKIE_INJECTION, rule_id="10031")
    assert check["class"] == verification.CLASS_MISMATCH
    assert check["alert_family"] == "xss"
    assert "cookies" in check["tool_families"]


def test_10029_cookie_poisoning_is_confirmed_by_a_cookie_injection_match():
    # ZAP rule 10029 (Cookie Poisoning, CWE-565) and a cookie-injection match
    # are the same class — the true confirmation that must stay `match`.
    check = verification.classification_match(565, _COOKIE_INJECTION, rule_id="10029")
    assert check["class"] == verification.CLASS_MATCH
    assert check["alert_family"] == "cookies"


def test_a_catchall_cwe_without_an_xss_rule_id_stays_unspecific():
    # The XSS override is rule-driven: with no rule id the catch-all CWE-20
    # still places the alert in no family, so the class is unspecific.
    check = verification.classification_match(20, _COOKIE_INJECTION)
    assert check["class"] == verification.CLASS_UNSPECIFIC


def test_an_unclassified_template_is_unknown_not_a_mismatch():
    check = verification.classification_match(
        22, [{"template_id": "t", "cwe": [], "tags": ["dast"]}]
    )
    assert check["class"] == verification.CLASS_UNKNOWN


def test_cwe_families_are_coarse_enough_to_agree_with_themselves():
    # CWE is far more granular than any scanner's classification: 79 and 80 are
    # both reflected XSS, and reporting them as different classes would make the
    # check fire on tools that plainly agree.
    assert verification.cwe_family(79) == verification.cwe_family(80) == "xss"
    assert verification.cwe_family("CWE-89") == "sqli"
    # The catch-alls place nothing.
    assert verification.cwe_family(20) is None
    assert verification.cwe_family(None) is None


# -- routing preference -----------------------------------------------------

def _contested(table_tool, llm_tool):
    return {"deterministic": {"needs_rescan": True, "tool": table_tool},
            "llm": {"needs_rescan": True, "suggested_tool": llm_tool}}


def test_the_table_wins_a_contested_finding_by_default():
    assert verification.selected_tool(_contested("nuclei", "sqlmap")) == "nuclei"


def test_the_table_always_wins_a_contested_finding():
    """The model-picks-the-tool override was removed 2026-11-02, so when both
    arms name a tool the deterministic lookup is the only one that can win.
    ``selected_tool`` takes no preference argument any more."""
    with pytest.raises(TypeError):
        verification.selected_tool(_contested("nuclei", "sqlmap"), "llm")


def test_the_llm_choice_is_the_fallback_that_holds_the_dispatch_population_fixed():
    """What keeps the dispatched set the same as it has always been.

    The LLM's choice is consulted only when the table named none, so a finding
    only the LLM can route is still routed. The table-vs-model question is about
    WHICH tool, never WHETHER a finding is dispatched — otherwise a difference in
    outcomes would confound "a better tool was chosen" with "a different
    population was tested".
    """
    only_table = {"deterministic": {"needs_rescan": True, "tool": "ffuf"},
                  "llm": {"needs_rescan": True, "suggested_tool": "none"}}
    only_llm = {"deterministic": {"needs_rescan": False, "tool": None},
                "llm": {"needs_rescan": True, "suggested_tool": "sqlmap"}}
    neither = {"deterministic": {"needs_rescan": False},
               "llm": {"needs_rescan": False}}

    assert verification.selected_tool(only_table) == "ffuf"
    assert verification.selected_tool(only_llm) == "sqlmap"
    assert verification.selected_tool(neither) is None


def test_the_argument_contract_matches_what_the_executor_accepts():
    """The prompt's list of levers and the validator's must be the same set.

    A field described to the model but dropped by `validate_probe` is a lever
    the model is invited to use and then silently denied; one accepted but not
    described is a capability it never learns it has. The model literally asked
    for the second case — "I need to include the full original POST body" — with
    `data` already available and undocumented.
    """
    from dast_orchestrator.domain import verification

    assert set(verification.PROBE_ARG_CONTRACT) == verification.ALLOWED_PROBE_ARGS


def test_the_capability_block_tells_the_model_how_to_invoke():
    from dast_orchestrator.domain import verification

    caps = verification.tool_capabilities(["sqlmap"])
    how = caps["how_you_invoke_them"]
    assert set(how["you_set"]) == verification.ALLOWED_PROBE_ARGS
    # The boundary that keeps the loop safe is stated, not implied.
    assert "never choose WHERE" in how["the_executor_sets"]


# -- the invariants an audit of every stored artifact checks -----------------
#
# Written after a manual sweep of every verification*.json on disk (2026-09-04)
# found only already-fixed history: OAST armed on a VERIFY_OOB=0 run, an
# "Unknown tool" leak, and a non-run recorded as tested. Each had a point fix;
# these pin the invariants behind them so a regression fails a test rather than
# waiting to be re-discovered in an artifact.


def test_a_non_run_is_never_recorded_as_tested():
    """`tested` is what `tool_ran` turns on, and a non-run must fail closed.

    The three sqlmap paths that decide before dispatching a container, and the
    driver's own fallback for an unparseable wrapper answer, all set
    tested=False — so none of them can support a refutation.
    """
    from dast_orchestrator.stages import verify

    # Every wrapper refusal that precedes a container run.
    import sys
    sys.path.insert(0, str(verify.WRAPPER_DIR))
    import sqlmap_server
    import browser_server

    for out in (sqlmap_server.verify_sqlmap("http://t/x", param=""),
                browser_server.verify_browser("http://t/x", param="")):
        assert out["outcome"] == verification.INCONCLUSIVE
        assert out["tested"] is False
        assert verification.tool_ran(out) is False
        assert not out.get("command")

    # And the driver's unparseable-answer fallback.
    class _R:
        is_error = True
        content = [type("C", (), {"text": "Unknown tool: verify_x"})()]

    parsed = verify._parse_tool_result(_R(), "sqlmap")
    assert parsed["tested"] is False
    assert verification.tool_ran(parsed) is False


def test_a_refutation_requires_the_tool_to_have_run():
    """The bottom row of the resolution matrix: a non-run is never a verdict.

    Whatever the model concluded, if the tool did not validly run the reported
    verdict is the wrapper's own reading, flagged — never the model's refutation
    or confirmation.
    """
    for model in (verification.REFUTED, verification.CONFIRMED,
                  verification.INCONCLUSIVE):
        reported, agreement = verification.resolve_verdict(
            verification.INCONCLUSIVE, model, ran=False)
        assert reported == verification.INCONCLUSIVE


def test_out_of_band_is_never_armed_by_default_in_any_dispatch_path():
    """OAST reached the sink on VERIFY_OOB=0 runs through the one path that
    did not carry the flag. Every path now defaults it off.
    """
    from dast_orchestrator.stages import verify

    support = {"finding_id": "f", "endpoint_key": "GET /x", "method": "GET",
               "path": "/x",
               "alert": {"plugin_id": "40018", "param": "q", "method": "GET",
                         "example_urls": ["http://t/x?q=1"]},
               "deterministic": {"needs_rescan": True, "tool": "nuclei"}}
    # deterministic path
    plan = verify.build_dispatch(support, {"GET /x": [support]}, {}, None)
    assert plan["arguments"]["oob"] is False
    # correlated (synthesis) path — the one that leaked, defaulting oob off now
    corr = {"finding_id": "c", "suggested_tool": "nuclei",
            "supporting_finding_ids": ["f"]}
    cplan = verify.build_correlated_dispatch(corr, {"f": support}, None)
    assert cplan["arguments"]["oob"] is False


def test_oracle_scopes_the_nuclei_probe_to_the_findings_class():
    """In oracle (ceiling) mode the DAST fuzz is scoped to the finding's own class
    (injection -> cmdi), so the probe is a handful of relevant templates instead of
    the whole catalog — which on a blind-RCE sink exceeds the tool timeout and
    self-saturates the target before the OOB callback lands. A blind run keeps the
    full set, so no triage hypothesis is injected into an independent probe.
    """
    from dast_orchestrator.stages import verify

    rce = {"finding_id": "f", "endpoint_key": "GET /remote_agent.php",
           "method": "GET", "path": "/remote_agent.php",
           "alert": {"plugin_id": "90037", "param": "poller_id", "method": "GET",
                     "example_urls": ["http://t/remote_agent.php?poller_id=1"]},
           "deterministic": {"needs_rescan": True, "tool": "nuclei"}}
    by_ep = {"GET /remote_agent.php": [rce]}

    oracle_plan = verify.build_dispatch(rce, by_ep, {}, None, oob=True, oracle=True)
    assert oracle_plan["arguments"]["tags"] == "cmdi"

    blind_plan = verify.build_dispatch(rce, by_ep, {}, None, oob=True, oracle=False)
    assert "tags" not in blind_plan["arguments"]


def test_unauth_sink_probe_drops_the_session_cookie():
    """An unauthenticated CVE's probe must not carry the scan's session cookie:
    the session is unneeded there and, on a poller-auth bypass like Cacti's
    remote_agent.php, a valid admin session takes the request off its unauth
    branch and suppresses the RCE. Verify stays authenticated for every sink not
    marked unauth, so it never piggybacks an unauth probe on an auth session.
    """
    from dast_orchestrator.stages import verify

    rce = {"finding_id": "f", "endpoint_key": "GET /remote_agent.php",
           "method": "GET", "path": "/remote_agent.php",
           "alert": {"plugin_id": "90037", "param": "poller_id", "method": "GET",
                     "example_urls": ["http://t/remote_agent.php?poller_id=1"]},
           "deterministic": {"needs_rescan": True, "tool": "nuclei"}}
    by_ep = {"GET /remote_agent.php": [rce]}

    # Oracle mode fills `cookie_free_routes` in the probe's auth context; the drop
    # lives in `_apply_auth` (the one place the cookie is attached), so it is a
    # property of the auth context, not a parameter of one dispatch builder.
    gated = verify.build_dispatch(
        rce, by_ep, {},
        {"cookie": "SID=abc", "cookie_free_routes": frozenset({"/remote_agent.php"})},
        oob=True, oracle=True)
    assert "cookie" not in gated["arguments"]

    kept = verify.build_dispatch(rce, by_ep, {}, {"cookie": "SID=abc"},
                                 oob=True, oracle=True)
    assert kept["arguments"]["cookie"] == "SID=abc"


def test_model_directed_probe_also_drops_unauth_cookie():
    """The llm arm rebuilds each round's probe through ``directed_arguments``, not
    ``build_dispatch``. The unauth-sink cookie drop lives in ``_apply_auth`` — the
    one place the cookie is attached — so it applies on the model arm too. When it
    was bolted onto ``build_dispatch`` alone, the model kept the admin session on
    the unauth sink and the RCE never confirmed under ``invocation=llm``.
    """
    from dast_orchestrator.stages.verify import records

    rce = {"finding_id": "f", "endpoint_key": "GET /remote_agent.php",
           "method": "GET", "path": "/remote_agent.php",
           "alert": {"plugin_id": "90037", "param": "poller_id", "method": "GET",
                     "example_urls": ["http://t/remote_agent.php?poller_id=1"]},
           "deterministic": {"needs_rescan": True, "tool": "nuclei"}}
    by_ep = {"GET /remote_agent.php": [rce]}
    proposal = {"tool": "nuclei", "param": "poller_id", "method": "GET"}

    gated = records.directed_arguments(
        rce, "nuclei", proposal, by_ep, {},
        {"cookie": "SID=abc", "cookie_free_routes": frozenset({"/remote_agent.php"})},
        True)
    assert gated is not None and "cookie" not in gated

    kept = records.directed_arguments(
        rce, "nuclei", proposal, by_ep, {}, {"cookie": "SID=abc"}, True)
    assert kept["cookie"] == "SID=abc"


def test_a_sibling_route_that_redirects_or_errors_is_served_but_not_probeable():
    """Served is not the same as answering the probe's question.

    The rule was once "only a 404 is not worth probing", on the reasoning that a
    redirect, a 401/403 and a 500 all describe pages worth looking at. Measured
    2026-09-08 against the live target: all five served Gitea sibling routes
    answered 302 — the redirect to the login page — and all five probes came
    back `refuted`, of the login page. A 5xx is the same shape with an error
    page. A 401/403 is NOT: that is the route's own answer, and a probe that
    gets one has learned something about the route.
    """
    assert verification.route_probeable(404) == verification.SIBLING_UNREACHABLE
    assert verification.route_probeable(410) == verification.SIBLING_UNREACHABLE
    for status in (301, 302, 307, 500, 502, 503):
        assert verification.route_probeable(status) == \
            verification.SIBLING_NOT_PROBEABLE, status
    for status in (200, 204, 401, 403, 418):
        assert verification.route_probeable(status) is None, status


def test_a_pre_check_that_could_not_run_never_becomes_a_refusal():
    """`None` means we could not check, and a missing measurement is not a result.

    The same rule every cost field in this project follows: a measured value and
    an absent one must never look alike. The probe runs as it would have before.
    """
    assert verification.route_probeable(None) is None


def test_the_two_pre_check_refusals_are_distinct_outcomes():
    """One is a verdict on the claim, the other a verdict on the probe.

    `sibling-unreachable` says the route the claim PREDICTED does not exist —
    that is a result about the prediction, and the reason it was given a name of
    its own rather than being filed as `not-attempted`. `sibling-not-probeable`
    says the route exists and the probe could not be pointed at it, which says
    nothing about the claim at all. Merging them would put a fact about our
    tooling into a column that reads as a fact about the application.
    """
    assert verification.SIBLING_UNREACHABLE != verification.SIBLING_NOT_PROBEABLE
    assert set(verification.SIBLING_OUTCOMES) == set(verification.OUTCOMES) | {
        verification.SIBLING_UNREACHABLE, verification.SIBLING_NOT_PROBEABLE}
    # Neither is one of the four: a sibling pre-check refusal must never be
    # counted in the flagged population's vocabulary.
    for outcome in (verification.SIBLING_UNREACHABLE,
                    verification.SIBLING_NOT_PROBEABLE):
        assert outcome not in verification.OUTCOMES
