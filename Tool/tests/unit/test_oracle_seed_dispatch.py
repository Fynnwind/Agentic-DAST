"""The oracle-seeded verify dispatch (``VERIFY_ORACLE_SEED_DISPATCH``).

Hermetic: no container and no MCP session. The one tool call per oracle-seeded
probe is intercepted by monkeypatching :meth:`Dispatcher.run`, so these exercise
the synthesis, the oracle gate and the provenance without touching the network.

Three invariants, from the feature's spec:

* **flag OFF** (the driver passes ``oracle_seed_markers=None``) ⇒ nothing is
  seeded and the artifact gains no key — byte-identical to before;
* **flag ON + oracle + an uncovered marker** ⇒ one oracle-seeded dispatch, at the
  marker's sink with the marker's tool and auth, recorded as oracle-seeded with
  its verdict resolved through ``resolve_verdict`` (class gate included);
* **flag ON but NO oracle (blind)** ⇒ nothing seeded — the gate holds, so the
  oracle-only path can never fire in a blind run.
"""

from __future__ import annotations

import time
import types
from contextlib import AsyncExitStack

import anyio
import pytest

from dast_orchestrator.stages import verify
from dast_orchestrator.stages import ground_truth as gt
from dast_orchestrator.domain.verification import CONFIRMED, DispatchBudget


def _marker(marker_id="m-cmdi", zap_rules=("90037", "90020"), cwe="78",
            probe_path="/remote_agent.php?action=polldata&poller_id=1",
            auth="none"):
    """A command-injection marker in the shape Cacti's CVE-2022-46169 has."""
    return gt.Marker(
        id=marker_id, name="OS command injection", cve="CVE-2022-46169",
        fixed_in="1.2.23", description="", cwe=cwe, zap_rules=tuple(zap_rules),
        probe_method="GET", probe_path=probe_path, expect_status=(200,),
        signal="", auth=auth,
    )


def _target(base_url="http://target-cacti"):
    return types.SimpleNamespace(base_url=base_url, name="cacti")


def _confirmed_oob_result(tool, arguments, plugin_id="", exempt_per_rule=False):
    """A canned nuclei OOB confirmation — a template in the command-injection
    class so the class gate holds, with an interactsh evidence token."""
    return {
        "outcome": CONFIRMED,
        "tested": True,
        "evidence": "interactsh OOB callback received from the injected command",
        "matched_templates": [{"cwe": ["CWE-78"], "tags": ["cmdi", "oast"]}],
        "detail": "nuclei confirmed out of band via interactsh",
        "command": "nuclei -u ... -dast",
        "exit_code": 0,
        "seconds": 2.0,
    }


def _budget():
    return DispatchBudget(tool_timeout_seconds=1, max_dispatch_all_rules=10,
                          max_dispatches_total=10, max_minutes=10)


# -- building one dispatch from a marker (probes level) --------------------


def test_build_oracle_seed_dispatch_uses_the_markers_sink_tool_and_tag():
    """The URL is the marker's documented sink, the tool is the one the rescan
    table routes the marker's rule to, and nuclei is scoped to the class."""
    plan = verify.build_oracle_seed_dispatch(
        _marker(), _target(),
        auth_ctx={"headers": "X-Forwarded-For: 127.0.0.1"}, oob=True)

    assert plan["tool"] == "nuclei"               # 90037 -> nuclei (rescan table)
    assert plan["arguments"]["target"] == (
        "http://target-cacti/remote_agent.php?action=polldata&poller_id=1")
    assert plan["arguments"]["tags"] == "cmdi"    # 90037 -> injection -> cmdi tag
    assert plan["arguments"]["oob"] is True
    # The scan's reach header (X-Forwarded-For) is threaded for nuclei, exactly
    # as the finding-derived path does — it IS how this sink is reached.
    assert plan["arguments"]["headers"] == "X-Forwarded-For: 127.0.0.1"
    assert plan["url_source"] == verify.URL_ORACLE_SEEDED
    assert plan["marker_id"] == "m-cmdi"
    assert plan["plugin_id"] == "90037"
    assert plan["auth"] == "none"


def test_oracle_seed_drops_the_cookie_for_an_unauthenticated_sink():
    """A valid session must not ride onto an unauth sink — on Cacti's
    remote_agent.php it routes the request off its unauthenticated branch and
    suppresses the CVE. The cookie-free routes carry the unauth sink."""
    plan = verify.build_oracle_seed_dispatch(
        _marker(auth="none"), _target(),
        auth_ctx={"cookie": "session=abc",
                  "cookie_free_routes": frozenset({"/remote_agent.php"})})
    assert "cookie" not in plan["arguments"]


def test_oracle_seed_keeps_the_cookie_for_an_authenticated_sink():
    """An authenticated marker's sink is probed WITH the session — honouring
    auth both ways. /host.php is not among the cookie-free (unauth) routes."""
    plan = verify.build_oracle_seed_dispatch(
        _marker(marker_id="m-snmp", zap_rules=("90020",),
                probe_path="/host.php?action=edit&id=1", auth="admin"),
        _target(),
        auth_ctx={"cookie": "session=abc",
                  "cookie_free_routes": frozenset({"/remote_agent.php"})})
    assert plan["arguments"]["cookie"] == "session=abc"


def test_oracle_seed_tool_is_none_when_the_rule_routes_nowhere():
    """A marker whose rule the rescan table routes to no dispatchable tool is
    not seeded — there is nothing to probe its sink with."""
    assert verify.oracle_seed_tool(("10038",)) is None   # CSP header -> NEVER/no tool
    assert verify.build_oracle_seed_dispatch(
        _marker(zap_rules=("10038",)), _target()) is None


# -- the gate and the record (verify_all level) ----------------------------


def _run_verify_all(monkeypatch, *, oracle, oracle_seed_markers,
                    dispatchable=None, run=_confirmed_oob_result,
                    run_auth_mode="none"):
    async def _fake_run(self, tool, arguments, plugin_id="", exempt_per_rule=False,
                        off_budget=False):
        _fake_run.calls.append({"tool": tool, "arguments": arguments,
                                "plugin_id": plugin_id,
                                "exempt_per_rule": exempt_per_rule,
                                "off_budget": off_budget})
        return run(tool, arguments, plugin_id, exempt_per_rule)
    _fake_run.calls = []
    monkeypatch.setattr(verify.Dispatcher, "run", _fake_run)

    async def _go():
        return await verify.verify_all(
            dispatchable or [], [], _budget(), {},
            verify.loop_config(invocation="deterministic"),
            target=_target(), oracle=oracle,
            oracle_seed_markers=oracle_seed_markers,
            run_auth_mode=run_auth_mode,
        )

    result = anyio.run(_go)
    return result, _fake_run.calls


def test_flag_on_and_oracle_seeds_one_confirmed_record_via_resolve_verdict(monkeypatch):
    block = {"known_vulnerabilities_of_this_target": "CVE at /remote_agent.php"}
    (verifs, corr, sib, per_rule, info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=block, oracle_seed_markers=[_marker()])

    # Exactly one probe, at the marker's sink, dispatched exempt from the
    # per-rule cap (a marker sink is not another instance of a noisy rule).
    assert len(calls) == 1 and calls[0]["tool"] == "nuclei"
    assert calls[0]["exempt_per_rule"] is True
    assert calls[0]["arguments"]["tags"] == "cmdi"

    assert len(oseed) == 1
    rec = oseed[0]
    assert rec["finding_id"] == "o-m-cmdi"
    assert rec["origin"] == verify.ORIGIN_ORACLE_SEED
    assert rec["url_source"] == verify.URL_ORACLE_SEEDED
    assert rec["marker_id"] == "m-cmdi" and rec["cve"] == "CVE-2022-46169"
    assert rec["tool"] == "nuclei"
    assert rec["target"].endswith("/remote_agent.php?action=polldata&poller_id=1")
    # The verdict is resolve_verdict's, and the class gate held (cmdi template vs
    # a command-injection rule) so the confirmation stands.
    assert rec["outcome"] == CONFIRMED and rec["reported_verdict"] == CONFIRMED
    assert rec["classification"]["class"] == "match"
    assert "outcome_downgraded_from" not in rec

    # The artifact carries it in its OWN array and summary block.
    art = verify.build_artifact(
        "triage.json", "20260101T000000Z-cacti-abc123", _budget(),
        verifs, corr, per_rule, info, False, sib, oracle_seeded=oseed)
    assert art["oracle_seeded_verifications"] == oseed
    assert art["summary"]["oracle_seeded"]["confirmed_finding_ids"] == ["o-m-cmdi"]
    assert art["summary"]["oracle_seeded"]["markers_probed"] == 1


def test_blind_run_seeds_nothing_even_with_markers(monkeypatch):
    """The gate: no oracle block ⇒ no oracle-seeded dispatch, so the oracle-only
    path can never fire in a blind run — the same invariant build_context keeps
    for the finding loop."""
    (_v, _c, _s, _pr, _info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=None, oracle_seed_markers=[_marker()])
    assert oseed == [] and calls == []


def test_flag_off_seeds_nothing_and_the_artifact_is_unchanged(monkeypatch):
    """Flag off ⇒ the driver passes no markers ⇒ nothing seeded and the artifact
    gains no key: byte-identical to before this feature existed."""
    block = {"known_vulnerabilities_of_this_target": "CVE at /remote_agent.php"}
    (verifs, corr, sib, per_rule, info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=block, oracle_seed_markers=None)
    assert oseed == [] and calls == []

    art = verify.build_artifact(
        "triage.json", "20260101T000000Z-cacti-abc123", _budget(),
        verifs, corr, per_rule, info, False, sib, oracle_seeded=oseed)
    assert "oracle_seeded_verifications" not in art
    assert "oracle_seeded" not in art["summary"]


def test_a_marker_already_covered_by_a_finding_is_not_seeded(monkeypatch):
    """A marker whose rule a selected finding already carries is skipped — the
    normal path routed a dispatch to the sink, so a second would double-count.
    (The miss this remediates is the rule firing 0×, where no finding covers it.)"""
    block = {"known_vulnerabilities_of_this_target": "CVE at /remote_agent.php"}
    finding = {
        "finding_id": "f-1", "endpoint_key": "GET /remote_agent.php",
        "method": "GET", "path": "/remote_agent.php",
        "alert": {"plugin_id": "90037", "name": "OS cmd injection (time based)",
                  "risk": "High", "param": "poller_id", "method": "GET",
                  "example_urls": ["http://target-cacti/remote_agent.php?poller_id=1"]},
        "deterministic": {"needs_rescan": True, "tool": "nuclei"},
        "llm": None,
    }
    (_v, _c, _s, _pr, _info, oseed), _calls = _run_verify_all(
        monkeypatch, oracle=block, oracle_seed_markers=[_marker()],
        dispatchable=[finding])
    assert oseed == []


# -- the budget bug: the finding loop must not be able to starve the probe -----


def test_oracle_seed_dispatches_off_budget(monkeypatch):
    """The probe is dispatched off-budget AND exempt from the per-rule cap, so
    neither the run-total dispatch cap the finding loop spends nor a noisy rule
    can refuse it."""
    block = {"known_vulnerabilities_of_this_target": "CVE at /remote_agent.php"}
    (_v, _c, _s, _pr, _info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=block, oracle_seed_markers=[_marker()])
    assert len(calls) == 1
    assert calls[0]["off_budget"] is True and calls[0]["exempt_per_rule"] is True


def test_budget_block_exempts_an_off_budget_probe_from_run_total_and_wall_clock():
    """The regression: with the run exhausted (dispatched == the total cap) OR
    past the wall clock, a normal dispatch is refused but an off-budget probe is
    not. This is the whole reason the first Option-C run confirmed nothing — the
    finding loop spent the 40-dispatch total and the oracle-seed probe, queued
    after it, was refused before the tool ran."""
    d = verify.Dispatcher(_budget(), AsyncExitStack())  # max_dispatches_total=10
    d.dispatched = 10
    assert "run total cap" in (d._budget_block("") or "")
    assert d._budget_block("", off_budget=True) is None

    d.dispatched = 0
    d.started = time.monotonic() - 10 ** 6          # far past the 10-min wall clock
    assert "wall-clock" in (d._budget_block("") or "")
    assert d._budget_block("", off_budget=True) is None


# -- auth applicability: a marker the run cannot reach is never seeded ---------


def test_auth_applicable_follows_none_user_admin():
    """none < user < admin: a run seeds a marker only when its mode is at or
    above the marker's required auth — the single rule the detection layer uses
    for not-applicable (auth)."""
    assert gt.auth_applicable("none", "none")
    assert gt.auth_applicable("none", "admin")
    assert gt.auth_applicable("user", "admin")
    assert not gt.auth_applicable("user", "none")
    assert not gt.auth_applicable("admin", "user")
    assert not gt.auth_applicable("admin", "none")


def test_a_marker_above_the_run_auth_is_not_seeded(monkeypatch):
    """An admin-auth marker is not seeded in a user run — never probed, never
    recorded — so a miss an auth level prevented never shows as an oracle-seeded
    not-attempted/refuted. The none-auth CVE beside it still seeds."""
    block = {"known_vulnerabilities_of_this_target": "two CVEs"}
    none_marker = _marker(marker_id="m-cmdi", auth="none")
    admin_marker = _marker(marker_id="m-snmp", zap_rules=("90020",),
                           probe_path="/host.php?action=edit&id=1", auth="admin")
    (_v, _c, _s, _pr, _info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=block,
        oracle_seed_markers=[none_marker, admin_marker], run_auth_mode="user")

    assert len(calls) == 1                       # only the none-auth marker probed
    assert [r["marker_id"] for r in oseed] == ["m-cmdi"]
    assert all(r["auth"] != "admin" for r in oseed)


def test_an_admin_marker_is_seeded_in_an_admin_run(monkeypatch):
    """The counterpart: the admin-auth marker IS seeded when the run is admin."""
    block = {"known_vulnerabilities_of_this_target": "CVE at /host.php"}
    admin_marker = _marker(marker_id="m-snmp", zap_rules=("90020",),
                           probe_path="/host.php?action=edit&id=1", auth="admin")
    (_v, _c, _s, _pr, _info, oseed), calls = _run_verify_all(
        monkeypatch, oracle=block, oracle_seed_markers=[admin_marker],
        run_auth_mode="admin")
    assert len(calls) == 1 and [r["marker_id"] for r in oseed] == ["m-snmp"]
