"""The integration points no mock can vouch for, against the running system.

Every test here was written because the mocked version of the same thing would
have passed while the real one was broken — and in two cases the real one *was*.
Deselected by default; run with ``uv run pytest -m e2e``.
"""

from __future__ import annotations

import json

import pytest

pytestmark = pytest.mark.e2e


# -- the daemon can be made clean without restarting it --------------------


def test_a_new_session_empties_the_site_tree_and_the_alerts(live_zap):
    """The measurement the "restart ZAP between runs" rule used to stand in for.

    A mocked ZAP would confirm the call was made and tell you nothing about
    whether it worked. This scans one URL, checks it is in the tree, resets, and
    checks the tree is empty — which is the property every second scan on one
    daemon depends on.
    """
    from dast_orchestrator.adapters.zap_client import ZapClient

    import time

    address, key = live_zap
    with ZapClient(address, key) as zap:
        zap.wait_until_ready()
        zap.access_url("http://target-gitea:3000/explore/repos", follow_redirects=False)
        # ZAP registers the node asynchronously, so poll rather than assert
        # immediately: a fixed expectation here made the test flake under load
        # and told us nothing about the property being tested.
        for _ in range(20):
            if zap.urls():
                break
            time.sleep(0.5)
        assert zap.urls(), "the visited URL should be in the site tree"

        zap.new_session()
        assert zap.urls() == [], "a new session must empty the site tree"


def test_a_replacer_rule_survives_a_new_session_so_it_is_removed_explicitly(live_zap):
    """The bug this pairing exists to prevent, pinned against the real daemon.

    Replacer rules are *not* session state in ZAP 2.17. Resetting the session
    without removing the auth rule would leave the previous run's cookie in
    place: the next run would look unauthenticated and quietly scan as an
    administrator. Nothing but the real daemon can establish this.
    """
    from dast_orchestrator.adapters.zap_client import ZapClient

    address, key = live_zap
    rule = "e2e-probe-auth-rule"
    with ZapClient(address, key) as zap:
        zap.wait_until_ready()
        zap.remove_replacer_rule(rule)          # from an interrupted earlier run
        zap.add_replacer_rule(rule, "Cookie", "probe=1")
        try:
            zap.new_session()
            assert rule in _rule_names(zap), (
                "if this ever fails, ZAP changed and scan.py's unconditional "
                "remove_replacer_rule is no longer load-bearing — check before "
                "removing it"
            )
        finally:
            zap.remove_replacer_rule(rule)
        assert rule not in _rule_names(zap)


def _rule_names(zap) -> list[str]:
    return [r["description"] for r in zap._get("replacer/view/rules")["rules"]]


# -- the target the whole pipeline assumes --------------------------------


def test_the_target_is_reachable_by_container_name_from_dast_net(live_target):
    """ZAP reaches the target by container name, not by localhost.

    The scan config says ``http://target-gitea:3000``; if that name does not
    resolve *on dast-net* every run fails at the first request. Checked from
    inside the network, because reachability from the host proves nothing about
    it.
    """
    import subprocess

    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "dast-net",
         "curlimages/curl:8.10.1", "-s", "-o", "/dev/null",
         "-w", "%{http_code}", "http://target-gitea:3000/"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.stdout.strip() == "200", result.stderr


def test_the_seeded_fixture_the_cve_markers_need_is_present(live_target):
    """A scanner can only attack what it can reach.

    Two markers of the 1.16.0 cluster are unreachable without this content, so
    an empty target would produce a detection rate that measures the fixture.
    """
    import urllib.request

    with urllib.request.urlopen(f"{live_target}/api/v1/repos/search", timeout=10) as r:
        repos = {x["full_name"] for x in json.load(r)["data"]}
    assert {"thesis/demo", "dastadmin/dast-public"} <= repos, (
        f"fixture missing — run targets/gitea/env/seed-repo.sh (have: {repos})"
    )


# -- the MCP boundary, spoken for real ------------------------------------


def test_a_verification_wrapper_answers_over_real_stdio_mcp(docker_available):
    """One real round trip through the stdio MCP boundary.

    The unit tests stub ``run_container`` and exercise the *mapping* from tool
    output to the four-state vocabulary; they never speak MCP. A wrong tool name
    once cost 25 identical silent inconclusives, and only this shape catches it.
    """
    if not docker_available:
        pytest.skip("docker is not available")

    import anyio
    from mcp import ClientSession, StdioServerParameters, stdio_client

    from dast_orchestrator.stages.verify import WRAPPER_DIR, _parse_tool_result
    import sys

    async def call() -> dict:
        params = StdioServerParameters(
            command=sys.executable, args=[str(WRAPPER_DIR / "ffuf_server.py")]
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                assert "verify_ffuf" in names, (
                    f"the driver calls verify_ffuf; the wrapper exposes {names}"
                )
                result = await session.call_tool(
                    "verify_ffuf",
                    {"target": "http://target-gitea:3000/avatar/x",
                     "param": "x", "timeout": 60},
                )
                return _parse_tool_result(result, "ffuf")

    verdict = anyio.run(call)
    from dast_orchestrator.domain.verification import OUTCOMES

    assert verdict["outcome"] in OUTCOMES, verdict


# -- the message sidecar, fetched from the real daemon --------------------


def test_messages_by_id_returns_the_exchanges_behind_alerts(live_zap):
    """The evidence layer's foundation: the exchanges are really fetchable.

    A mocked ZAP would confirm the call shape and tell you nothing about whether
    ``core/view/messagesById`` actually returns request/response bodies keyed by
    the ids the alerts carry. This seeds one URL, drains passive scan, reads the
    alerts' message ids, and fetches them — the exact path scan.py takes to build
    scan-zap-messages.json.
    """
    import time

    from dast_orchestrator.adapters.zap_client import ZapClient
    from dast_orchestrator.context import evidence

    address, key = live_zap
    with ZapClient(address, key) as zap:
        zap.wait_until_ready()
        zap.new_session()
        zap.access_url("http://target-gitea:3000/user/login", follow_redirects=False)
        for _ in range(30):
            if zap.pscan_records_to_scan() == 0:
                break
            time.sleep(1)
        alerts = zap.alerts(base_url="http://target-gitea:3000")
        assert alerts, "the login page raises passive alerts (missing headers)"

        ids = evidence.message_ids(alerts)
        assert ids, "every alert carries a messageId"
        messages = zap.messages_by_id(ids)
        assert messages, "messagesById returns the referenced exchanges"

        # The sidecar is buildable and the body-drop policy actually fires: the
        # login page's header findings should omit their body.
        sidecar = evidence.build_message_sidecar(alerts, messages)
        assert sidecar["counts"]["messages"] == len(messages)
        one = next(iter(sidecar["messages"].values()))
        assert one["request_header"].startswith(("GET", "POST"))
