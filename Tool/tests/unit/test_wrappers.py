"""The four-state outcome mapping inside each stdio verification wrapper.

The wrappers live outside the installed package (``mcp/``), so the test
adds that directory to the path and imports them directly. The container is
never run: :func:`run_container` is monkeypatched to return a canned
:class:`ContainerResult`, so what is under test is purely how each tool's output
is mapped onto confirmed / refuted / inconclusive — the mapping the evaluation
table depends on.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER_DIR = Path(__file__).resolve().parents[2] / "mcp"
sys.path.insert(0, str(WRAPPER_DIR))

import _dispatch_common as common  # noqa: E402
import ffuf_server  # noqa: E402
import browser_server  # noqa: E402
import nuclei_server  # noqa: E402
import sqlmap_server  # noqa: E402
from _dispatch_common import CONFIRMED, INCONCLUSIVE, REFUTED  # noqa: E402


def _result(stdout="", exit_code=0, timed_out=False, stderr=""):
    return common.ContainerResult(
        ["docker", "run", "stub"], exit_code, stdout, stderr, 1.0, timed_out
    )


@pytest.fixture
def stub_container(monkeypatch):
    """Replace run_container in every wrapper with a canned result."""
    def install(result):
        for mod in (sqlmap_server, nuclei_server, ffuf_server,
                    browser_server):
            monkeypatch.setattr(mod, "run_container", lambda *a, **k: result)
    return install


# -- sqlmap ----------------------------------------------------------------


def test_sqlmap_confirms_on_vulnerable(stub_container):
    stub_container(_result("sqlmap identified the following injection point"))
    out = sqlmap_server.verify_sqlmap("http://t/x", "id")
    assert out["outcome"] == CONFIRMED
    assert out["evidence"]


def test_sqlmap_refutes_when_not_injectable(stub_container):
    stub_container(_result("all tested parameters do not appear to be injectable"))
    assert sqlmap_server.verify_sqlmap("http://t/x", "id")["outcome"] == REFUTED


def test_sqlmap_timeout_is_inconclusive_not_refuted(stub_container):
    stub_container(_result("partial", timed_out=True))
    assert sqlmap_server.verify_sqlmap("http://t/x", "id")["outcome"] == INCONCLUSIVE


def test_sqlmap_ambiguous_output_is_inconclusive(stub_container):
    stub_container(_result("connection refused"))
    assert sqlmap_server.verify_sqlmap("http://t/x", "id")["outcome"] == INCONCLUSIVE


def _sqlmap_argv(monkeypatch, **kwargs) -> list[str]:
    seen: list[list[str]] = []
    monkeypatch.setattr(sqlmap_server, "run_container",
                        lambda image, args, **k: seen.append(args) or _result("x"))
    sqlmap_server.verify_sqlmap("http://t/form.php", "id", **kwargs)
    return seen[0]


def test_sqlmap_csrf_post_carries_the_field_and_fetches_the_token_by_get(monkeypatch):
    # sqlmap only refreshes a token field the body already has: without one every
    # payload POST failed Cacti's CSRF check and sqlmap compared redirects.
    argv = _sqlmap_argv(monkeypatch, method="POST", data="id=1&name=a",
                        csrf_field="__csrf_magic", csrf_url="http://t/form.php")
    assert argv[argv.index("--data") + 1] == "id=1&name=a&__csrf_magic=x"
    assert "--csrf-token=__csrf_magic" in argv and "--csrf-method=GET" in argv
    kept = _sqlmap_argv(monkeypatch, method="POST", data="__csrf_magic=t&id=1",
                        csrf_field="__csrf_magic", csrf_url="http://t/form.php")
    assert kept[kept.index("--data") + 1] == "__csrf_magic=t&id=1"


def test_sqlmap_without_csrf_leaves_the_body_alone(monkeypatch):
    argv = _sqlmap_argv(monkeypatch, method="POST", data="id=1")
    assert argv[argv.index("--data") + 1] == "id=1"
    assert not any(a.startswith("--csrf") for a in argv)


def test_sqlmap_without_param_is_inconclusive(stub_container):
    stub_container(_result("unused"))
    assert sqlmap_server.verify_sqlmap("http://t/x", "")["outcome"] == INCONCLUSIVE


# -- nuclei ----------------------------------------------------------------


def test_nuclei_confirms_on_jsonl_match(stub_container):
    stub_container(_result('{"template-id":"xss-fuzz","matched-at":"http://t"}\n'))
    out = nuclei_server.verify_nuclei("http://t/x?q=1")
    assert out["outcome"] == CONFIRMED
    assert "xss-fuzz" in out["evidence"]


def test_nuclei_refutes_on_clean_zero_exit(stub_container):
    stub_container(_result("", exit_code=0))
    assert nuclei_server.verify_nuclei("http://t/x")["outcome"] == REFUTED


def test_nuclei_nonzero_exit_is_inconclusive(stub_container):
    stub_container(_result("", exit_code=1))
    assert nuclei_server.verify_nuclei("http://t/x")["outcome"] == INCONCLUSIVE


#: One `-stats` tick, as nuclei writes it to stderr: strings, not ints.
def _stats(templates=195, requests=387, matched=0, errors=0):
    return ('{"duration":"0:00:02","errors":"%d","hosts":"1","matched":"%d",'
            '"percent":"100","requests":"%d","rps":"187",'
            '"templates":"%d"}\n' % (errors, matched, requests, templates))


def test_nuclei_records_what_it_actually_ran(stub_container):
    """A refutation has to carry the work behind it.

    With `-silent -jsonl` a run that matches nothing prints an EMPTY stdout, so
    the verification loop's model was handed `stdout_excerpt: ""` and had only
    this wrapper's own verdict to reason from — measured 2026-09-04 on the
    rule-40026 false refutation. The counters come from nuclei's own `-stats`.
    """
    stub_container(_result("", exit_code=0, stderr=_stats()))
    out = nuclei_server.verify_nuclei("http://t/x?q=1")
    assert out["outcome"] == REFUTED
    assert out["scan_stats"] == {"templates": 195, "requests": 387,
                                 "matched": 0, "errors": 0}
    assert "195 template(s) sent 387 request(s)" in out["detail"]


def test_recorded_command_is_shell_quoted_so_redaction_keeps_trailing_headers():
    """NFR-06 regression: the recorded command must survive cookie scrubbing.

    The command reaches the artifact as a joined argv string, then NFR-06's
    header-value scrub blanks the cookie — a regex that runs to the first quote.
    A bare space-join left the value unquoted, so the scrub ate the value AND
    every token after it (the ``-H X-Forwarded-For`` the cacti sink needs).
    Shell-quoting each token bounds the value inside its own argument.
    """
    from dast_orchestrator.foundation import redaction

    result = common.ContainerResult(
        ["docker", "run", "secsi/ffuf:2.2.1",
         "-u", "http://target-cacti/poller.php/FUZZ",
         "-H", "Cookie: Cacti=SECRETSESSION",
         "-H", "X-Forwarded-For: 127.0.0.1", "-timeout", "150"],
        exit_code=0, stdout="", stderr="", seconds=1.0, timed_out=False,
    )
    payload = common.outcome(REFUTED, "ffuf", result, "nothing matched")
    scrubbed = redaction.scrub(payload["command"], cookie_names=["Cacti"])
    assert "SECRETSESSION" not in scrubbed              # the cookie value is gone
    assert "X-Forwarded-For: 127.0.0.1" in scrubbed     # the next header survives
    assert scrubbed.endswith("-timeout 150")            # and so does the tail


def test_nuclei_that_loaded_no_templates_is_inconclusive_not_refuted(stub_container):
    """Zero templates is "nothing was tested", whatever the exit code says.

    The existing guard needs nuclei to PRINT a warning; this one needs it to
    have done no work, which is the fact the guard is really about.
    """
    stub_container(_result("", exit_code=0, stderr=_stats(templates=0, requests=0)))
    out = nuclei_server.verify_nuclei("http://t/x?q=1")
    assert out["outcome"] == INCONCLUSIVE
    assert out["tested"] is False


def test_nuclei_without_stats_reports_no_counters_rather_than_zeroes(stub_container):
    """A missing measurement and a measured zero must not look alike."""
    stub_container(_result("", exit_code=0, stderr="no stats here"))
    out = nuclei_server.verify_nuclei("http://t/x?q=1")
    assert out["outcome"] == REFUTED
    assert out["scan_stats"] is None


def test_nuclei_timeout_is_inconclusive(stub_container):
    stub_container(_result("", timed_out=True))
    assert nuclei_server.verify_nuclei("http://t/x")["outcome"] == INCONCLUSIVE


# -- ffuf ------------------------------------------------------------------


def test_ffuf_confirms_on_passwd_match(stub_container):
    report = '{"results":[{"input":{"FUZZ":"../../../../etc/passwd"},"status":200}]}'
    stub_container(_result(report, exit_code=0))
    out = ffuf_server.verify_ffuf("http://t/avatar/x", "user")
    assert out["outcome"] == CONFIRMED
    assert "etc/passwd" in out["evidence"]


def test_ffuf_refutes_on_empty_results(stub_container):
    stub_container(_result('{"results":[]}', exit_code=0))
    assert ffuf_server.verify_ffuf("http://t/avatar/x", "user")["outcome"] == REFUTED


def test_ffuf_timeout_is_inconclusive(stub_container):
    stub_container(_result("", timed_out=True))
    assert ffuf_server.verify_ffuf("http://t/avatar/x", "user")["outcome"] == INCONCLUSIVE


# -- ffuf FUZZ placement ---------------------------------------------------


def test_fuzz_url_replaces_query_param_value():
    url, where = ffuf_server._fuzz_url("http://t/s?q=1&sort=new", "q")
    assert "q=FUZZ" in url and "sort=new" in url
    assert "query parameter" in where


def test_fuzz_url_falls_back_to_last_path_segment():
    url, where = ffuf_server._fuzz_url("http://t/avatar/abc", "user")
    assert url.endswith("/avatar/FUZZ")
    assert "path segment" in where


# -- run_container guard ---------------------------------------------------


def test_run_container_reports_when_docker_missing(monkeypatch):
    monkeypatch.setattr(common.shutil, "which", lambda _: None)
    res = common.run_container("img", ["--help"], timeout=5)
    assert res.exit_code is None and "docker not on PATH" in res.stderr


def test_timed_out_container_is_force_removed_by_name(monkeypatch):
    """A tool that hits its timeout must not leave its container running.

    ``subprocess.run(timeout=)`` kills the ``docker run`` client, never the
    container — dockerd keeps running it, so ``--rm`` never fires. Without an
    explicit reap a timed-out fuzzer survives into the next run and re-saturates
    the target (the cacti-ceiling between-run auth wedge). The container is
    launched under an explicit ``--name`` precisely so the timeout path can
    force-remove that exact container.
    """
    monkeypatch.setattr(common.shutil, "which", lambda _: "/usr/bin/docker")
    calls: list[list[str]] = []

    def fake_run(argv, *args, **kwargs):
        calls.append(argv)
        if argv[:3] == ["docker", "run", "--rm"]:
            raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
        return subprocess.CompletedProcess(argv, 0, b"", b"")

    monkeypatch.setattr(common.subprocess, "run", fake_run)

    res = common.run_container("img", ["--scan"], timeout=5)

    assert res.timed_out is True and res.exit_code is None
    run_argv = calls[0]
    assert "--name" in run_argv, "the tool container must carry an explicit --name"
    name = run_argv[run_argv.index("--name") + 1]
    assert name.startswith(common.CONTAINER_NAME_PREFIX)
    # the timeout reaped that exact container — not merely killed the client.
    assert ["docker", "rm", "-f", name] in calls


# -- nuclei: out-of-band (OAST) arming -------------------------------------
#
# Some classes prove themselves only by making the target call *out*, and those
# templates are excluded from a run entirely without an interactsh sink. What
# these tests pin is that the sink is the self-hosted one, that a dead sink is
# recorded rather than silently waited on, and that the poll window outlives the
# scan — an out-of-band interaction arrives on the target's schedule, not ours.


@pytest.fixture
def capture_nuclei_argv(monkeypatch):
    """Run verify_nuclei against a canned container result, keeping the argv."""
    seen: dict = {}

    def fake(image, args, timeout, **kwargs):
        seen["args"] = args
        return _result(stdout="", exit_code=0)

    monkeypatch.setattr(nuclei_server, "run_container", fake)
    return seen


def test_oob_armed_points_at_the_self_hosted_sink(monkeypatch, capture_nuclei_argv):
    monkeypatch.setattr(nuclei_server, "interactsh_reachable", lambda *a, **k: True)
    verdict = nuclei_server.verify_nuclei("http://t/x", oob=True)
    args = capture_nuclei_argv["args"]
    assert "-iserver" in args
    server = args[args.index("-iserver") + 1]
    assert server == nuclei_server.INTERACTSH_SERVER
    # Never the public pool: it would send this target's out-of-band
    # interactions to someone else's server.
    assert "oast.pro" not in server and "oast." not in server
    assert "-no-interactsh" not in args
    # The poll window outlives the scan, or the callback lands after nuclei exits.
    assert args[args.index("-interactions-cooldown-period") + 1] == str(
        nuclei_server.INTERACTSH_COOLDOWN_SECONDS
    )
    assert "OAST armed" in verdict["detail"]


def test_unreachable_sink_is_recorded_not_waited_on(monkeypatch, capture_nuclei_argv):
    # Pointing nuclei at a dead sink makes every OAST template wait and time out,
    # turning honest refutations into unexplained inconclusives.
    monkeypatch.setattr(nuclei_server, "interactsh_reachable", lambda *a, **k: False)
    verdict = nuclei_server.verify_nuclei("http://t/x", oob=True)
    args = capture_nuclei_argv["args"]
    assert "-no-interactsh" in args and "-iserver" not in args
    assert verdict["outcome"] == REFUTED
    assert "sink-unreachable" in verdict["detail"]


def test_oob_can_be_turned_off_without_probing_the_sink(monkeypatch, capture_nuclei_argv):
    def explode(*a, **k):  # the preflight must not run when OOB is off
        raise AssertionError("preflight ran for an opted-out probe")

    monkeypatch.setattr(nuclei_server, "interactsh_reachable", explode)
    verdict = nuclei_server.verify_nuclei("http://t/x", oob=False)
    assert "-no-interactsh" in capture_nuclei_argv["args"]
    assert "OAST disabled" in verdict["detail"]


def test_preflight_asks_from_inside_the_scan_network(stub_container):
    # Reachability from the host says nothing about whether nuclei's container
    # can reach the sink, so the check runs in a container on the same network.
    stub_container(_result(stdout="200", exit_code=0))
    assert nuclei_server.interactsh_reachable("http://sink:8080") is True
    stub_container(_result(stdout="000", exit_code=7))
    assert nuclei_server.interactsh_reachable("http://sink:8080") is False


# -- a refutation must mean the tool did work ------------------------------


SQLMAP_UNSTABLE = (
    "[15:04:20] [INFO] checking if the target is protected by some kind of WAF/IPS\n"
    "[15:04:21] [WARNING] target URL content is not stable (i.e. content differs). "
    "sqlmap will base the page comparison on a sequence matcher\n"
    "[15:04:30] [INFO] all tested parameters do not appear to be injectable\n"
)


def test_sqlmap_refutation_on_an_unstable_page_is_inconclusive(stub_container):
    # sqlmap has just said its own comparison basis is degraded. A refutation
    # is a claim about the target; this one would be a claim about the run.
    stub_container(_result(SQLMAP_UNSTABLE))
    out = sqlmap_server.verify_sqlmap("http://t/x", "id")
    assert out["outcome"] == INCONCLUSIVE
    assert "not stable" in out["detail"]
    assert out["tool_warnings"] and "not stable" in out["tool_warnings"][0]


def test_sqlmap_reflective_filtering_also_downgrades(stub_container):
    stub_container(_result(
        "[WARNING] reflective value(s) found and filtering out\n"
        "[INFO] all tested parameters do not appear to be injectable\n"
    ))
    assert sqlmap_server.verify_sqlmap("http://t/x", "id")["outcome"] == INCONCLUSIVE


def test_sqlmaps_routine_waf_line_is_not_a_warning(stub_container):
    # It is printed on every run and is an INFO line. Treating it as a warning
    # would downgrade every verdict the wrapper has ever produced.
    stub_container(_result(
        "[INFO] checking if the target is protected by some kind of WAF/IPS\n"
        "[INFO] all tested parameters do not appear to be injectable\n"
    ))
    assert sqlmap_server.verify_sqlmap("http://t/x", "id")["outcome"] == REFUTED


def test_a_confirmation_survives_a_degraded_comparison(stub_container):
    # Positive evidence: sqlmap found an injection point despite the noise.
    stub_container(_result(
        "[WARNING] target URL content is not stable\n"
        "sqlmap identified the following injection point\n"
    ))
    out = sqlmap_server.verify_sqlmap("http://t/x", "id")
    assert out["outcome"] == CONFIRMED
    assert out["tool_warnings"]          # recorded, not acted on


def test_nuclei_with_no_templates_is_inconclusive_not_refuted(stub_container):
    # With -silent an empty template set looks exactly like a clean sweep, so it
    # would otherwise refute every finding it was handed.
    stub_container(_result("", stderr="[FTL] Could not find any templates"))
    out = nuclei_server.verify_nuclei("http://t/x", oob=False)
    assert out["outcome"] == INCONCLUSIVE
    assert "no templates" in out["detail"]


def test_ffuf_that_never_reached_the_target_is_inconclusive(stub_container):
    stub_container(_result('{"results": []}', stderr="connection refused"))
    out = ffuf_server.verify_ffuf("http://t/x", "user")
    assert out["outcome"] == INCONCLUSIVE
    assert "could not reach" in out["detail"]


# -- what a verdict keeps for auditing -------------------------------------


def test_settled_verdicts_keep_a_readable_excerpt(stub_container):
    # 1500 characters truncate sqlmap before its own verdict lines, so an
    # inconclusive could not be audited without re-running the tool — which is
    # exactly the state where a re-run is least likely to reproduce anything.
    long_output = "x" * 5000 + "\n[CRITICAL] unable to connect to the target URL"
    stub_container(_result(long_output))
    inconclusive = sqlmap_server.verify_sqlmap("http://t/x", "id")
    assert inconclusive["outcome"] == INCONCLUSIVE
    assert len(inconclusive["stdout_excerpt"]) > common.EXCERPT_CHARS

    stub_container(_result(long_output + "\nall tested parameters do not appear "
                                         "to be injectable"))
    refuted = sqlmap_server.verify_sqlmap("http://t/x", "id")
    assert refuted["outcome"] == REFUTED
    assert len(refuted["stdout_excerpt"]) == common.EXCERPT_CHARS


def test_nuclei_reports_what_it_matched_with_its_classification(stub_container):
    stub_container(_result(
        '{"template-id":"cookie-injection","info":{"tags":["dast"],'
        '"classification":{"cwe-id":["cwe-113"]}}}\n'
    ))
    out = nuclei_server.verify_nuclei("http://t/x", oob=False)
    assert out["outcome"] == CONFIRMED
    assert out["matched_templates"] == [
        {"template_id": "cookie-injection", "cwe": ["cwe-113"], "tags": ["dast"]}
    ]


# -- nuclei must never manufacture a confirmation --------------------------


def _nuclei_result(stdout="", stderr="", exit_code=0, timed_out=False):
    from _dispatch_common import ContainerResult

    return ContainerResult(argv=["nuclei"], exit_code=exit_code, stdout=stdout,
                           stderr=stderr, seconds=1.0, timed_out=timed_out)


def test_nuclei_saying_it_ran_nothing_is_never_a_confirmation(monkeypatch):
    """The exact output that produced a false confirmed finding.

    Observed 2026-09-03 on a baseline run: nuclei found no DAST templates, said
    so on *stdout*, exited 1 — and the wrapper reported CONFIRMED with evidence
    `?`, because any non-blank stdout line counted as a match and the
    no-templates guard was checked afterwards. It became the corpus's only
    confirmed finding. In a project whose headline result is about confirmation
    rates, a path that invents confirmations is the wrong bug to have.
    """
    import nuclei_server

    result = _nuclei_result(
        stdout="\x1b[93mWRN\x1b[0m] No DAST templates found",
        stderr="[FTL] Could not run nuclei: no templates provided for scan",
        exit_code=1,
    )
    monkeypatch.setattr(nuclei_server, "run_container", lambda *a, **k: result)
    verdict = nuclei_server.verify_nuclei("http://t/x?a=1")

    assert verdict["outcome"] == nuclei_server.INCONCLUSIVE
    assert verdict["tested"] is False          # and it did not test anything
    assert "no templates" in verdict["detail"].lower()


def test_a_real_jsonl_match_still_confirms(monkeypatch):
    import nuclei_server

    result = _nuclei_result(
        stdout='{"template-id":"cookie-injection","info":{"classification":'
               '{"cwe-id":["cwe-79"]},"tags":["xss"]}}',
        exit_code=1,
    )
    monkeypatch.setattr(nuclei_server, "run_container", lambda *a, **k: result)
    verdict = nuclei_server.verify_nuclei("http://t/x?a=1")

    assert verdict["outcome"] == nuclei_server.CONFIRMED
    assert verdict["matched_templates"][0]["template_id"] == "cookie-injection"


def test_nuclei_chatter_on_stdout_is_not_a_match():
    import nuclei_server

    # Banners, progress and warnings all land on stdout; none is a match.
    assert nuclei_server._match_lines(
        "[INF] Templates loaded: 0\n[WRN] No DAST templates found\n") == []
    # ...while a malformed match is still a match nobody can classify.
    assert nuclei_server._match_lines('{"template-id":') == []
    assert nuclei_server._match_lines('{"broken": tru}') == ['{"broken": tru}']


# -- browser (the execution oracle) ----------------------------------------


def _dom(title):
    return f"<html><head><title>{title}</title></head><body>x</body></html>"


def test_browser_confirms_only_when_the_title_becomes_the_marker(
        stub_container, monkeypatch):
    """A confirmation means script RAN. The marker is this call's own."""
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom("XSSABCDEF123456")))
    out = browser_server.verify_browser("http://t/x?p=1", param="p")
    assert out["outcome"] == CONFIRMED
    assert "document.title=/XSSABCDEF123456/.source" in out["evidence"]


def test_browser_does_not_confirm_a_payload_merely_reflected_into_the_title(
        stub_container, monkeypatch):
    """The false positive this wrapper produced on its first live outing.

    WordPress's search page echoes the raw query into
    `<title>Search Results for "..."</title>`, so a *substring* test saw the
    marker and reported CONFIRMED without a line of script running. Equality
    separates execution from reflection; containment does not.
    """
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom(
        "Search Results for &#8220;</script><script>"
        "document.title=/XSSABCDEF123456/.source</script>&#8221;")))
    out = browser_server.verify_browser("http://t/x?p=1", param="p")
    assert out["outcome"] == REFUTED


def test_browser_refutes_after_trying_every_payload(stub_container, monkeypatch):
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom("Untouched")))
    out = browser_server.verify_browser("http://t/x?p=1", param="p")
    assert out["outcome"] == REFUTED
    assert len(out["payloads_tried"]) == len(browser_server.PAYLOADS)


def test_browser_needs_the_parameter_in_the_query_string(stub_container):
    """No path-segment fallback: that would probe a different finding."""
    stub_container(_result(_dom("x")))
    out = browser_server.verify_browser("http://t/x", param="p")
    assert out["outcome"] == INCONCLUSIVE
    assert out["tested"] is False


def test_browser_timeout_is_inconclusive_not_refuted(stub_container, monkeypatch):
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result("", timed_out=True))
    out = browser_server.verify_browser("http://t/x?p=1", param="p")
    assert out["outcome"] == INCONCLUSIVE
    assert out["tested"] is False


def test_browser_payloads_carry_no_quote_characters():
    """Quotes are what output escaping mangles — the trap nuclei fell into."""
    marker = browser_server.new_marker()
    js = browser_server._ASSIGN.format(marker=marker)
    for template in browser_server.PAYLOADS:
        payload = template.format(js=js)
        assert "'" not in payload and '"' not in payload, payload


# -- the driver's contract with the wrappers -------------------------------


def test_every_dispatchable_tool_exposes_the_name_the_driver_calls():
    """`verify.py` calls `verify_<tool>`; a wrapper that names it anything else
    is silently unusable.

    Found the expensive way on 2026-09-04: `browser` was registered in
    DISPATCHABLE_TOOLS, routed from the rescan table, spawned correctly and
    dispatched to the corpus's only true positive — and every round came back
    `inconclusive` with "Unknown tool: verify_browser", because the function was
    called `verify_browser_xss`. Nothing failed; the finding just stayed
    unverified, which is the failure mode this whole session has been about.
    """
    import importlib

    from dast_orchestrator.domain import verification
    from dast_orchestrator.stages import verify

    for tool in sorted(verification.DISPATCHABLE_TOOLS):
        path = verify.WRAPPER_DIR / f"{tool}_server.py"
        assert path.is_file(), f"{tool} has no wrapper at {path}"
        module = importlib.import_module(f"{tool}_server")
        assert callable(getattr(module, f"verify_{tool}", None)), (
            f"{tool}_server.py must define verify_{tool}(), the name "
            f"verify.py calls over MCP"
        )


def test_every_dispatchable_tool_declares_a_pinned_image_and_capabilities():
    """The three registration points that must move together."""
    from dast_orchestrator.domain import verification
    from dast_orchestrator.stages import verify

    for tool in sorted(verification.DISPATCHABLE_TOOLS):
        assert tool in verify.TOOL_IMAGES, f"{tool} has no pinned image"
        assert ":" in verify.TOOL_IMAGES[tool], f"{tool}'s image is not pinned"
        assert tool in verification.TOOL_CAPABILITIES, (
            f"{tool} is dispatchable but the prompt cannot describe it")
        # The fourth registration point, and the one my own version of this
        # test missed: a tool absent from the round schema's enum is one the
        # model is told about and then forbidden to choose, because structured
        # output rejects the value.
        from dast_orchestrator.analysis import verify_loop

        assert tool in verify_loop.ROUND_SCHEMA["properties"]["tool"]["enum"], (
            f"{tool} is dispatchable but the model cannot name it in a round")


def test_a_browser_confirmation_declares_its_class(stub_container, monkeypatch):
    """The class check must be able to compare it with the flagged rule.

    `verification.classification_match` reads the confirming evidence's CWE
    family off `matched_templates`. This probe has none, so the pipeline's first
    real confirmation landed as `class: unknown` — "the confirming template
    carries no CWE or recognised tag". Its class is fixed by construction:
    JavaScript executed, which is XSS.
    """
    from dast_orchestrator.domain import verification

    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom("XSSABCDEF123456")))
    out = browser_server.verify_browser("http://t/x?p=1", param="p")

    assert out["outcome"] == CONFIRMED
    check = verification.classification_match(79, out["matched_templates"])
    assert check["class"] == verification.CLASS_MATCH
    # And it still catches the other direction: this probe confirming against a
    # rule of a different family is a genuine mismatch, not a pass.
    sqli = verification.classification_match(89, out["matched_templates"])
    assert sqli["class"] == verification.CLASS_MISMATCH


@pytest.mark.parametrize("call, label", [
    (lambda: sqlmap_server.verify_sqlmap("http://t/x", ""), "sqlmap without a parameter"),
    (lambda: browser_server.verify_browser("http://t/x", ""), "browser without a parameter"),
])
def test_a_refusal_before_dispatch_did_not_test_anything(stub_container, call, label):
    """`outcome()` defaults `tested` to true for everything but not-attempted.

    That is right for a tool that ran and wrong for a refusal that precedes one,
    and `verification.tool_ran` is what the resolution rule turns on — so a path
    that never started a container and forgot the flag can support a refutation.
    Audited 2026-09-04; sqlmap's no-parameter path was one of these.
    """
    from dast_orchestrator.domain import verification

    stub_container(_result("unused"))
    out = call()
    assert out["outcome"] == INCONCLUSIVE, label
    assert out["tested"] is False, label
    assert verification.tool_ran(out) is False, label


def test_out_of_band_is_off_unless_the_caller_asks(monkeypatch, capture_nuclei_argv):
    """Arming an out-of-band channel is opt-in, at every layer.

    `oob` defaulted to True here until 2026-09-04, which meant any caller that
    omitted it sent this target's interactions to the sink. The driver's
    correlated-finding path omitted it — so on runs configured `VERIFY_OOB=0`,
    whose artifacts duly recorded `oob_enabled: false`, six nuclei rounds ran
    with `-iserver http://target-interactsh:8080` on the command line. A
    security-relevant switch must fail closed.
    """
    def explode(*a, **k):
        raise AssertionError("the sink must not be probed when OOB is off")

    monkeypatch.setattr(nuclei_server, "interactsh_reachable", explode)
    nuclei_server.verify_nuclei("http://t/x")
    args = capture_nuclei_argv["args"]
    assert "-no-interactsh" in args
    assert "-iserver" not in args


def test_browser_delivers_the_payload_in_the_body_when_given_one(
        stub_container, monkeypatch):
    """A form-field XSS is settled by execution, not by string matching.

    Chromium is navigated by URL, so before this a body parameter could not be
    probed at all: 9 of Gitea's 25 flagged `10031` findings are form fields
    (`_csrf`, `password`, `user_name`, `retype`, `email`), and every tool this
    pipeline had was handed a URL and nothing else. The bootstrap form carries
    the endpoint's own shape, with the payload in the flagged field.
    """
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom("XSSABCDEF123456")))
    out = browser_server.verify_browser(
        "http://t/login", param="password", data="user_name=x&password=y",
        method="POST")
    assert out["outcome"] == CONFIRMED

    page = browser_server.bootstrap_page(
        "http://t/login", "password", "<script>go()</script>",
        "user_name=x&password=y", "POST")
    assert 'action="http://t/login"' in page and 'method="POST"' in page
    # The endpoint's other fields ride along: a lone parameter is often rejected
    # before it ever reaches the sink.
    assert 'name="user_name" value="x"' in page
    assert "&lt;script&gt;go()&lt;/script&gt;" in page      # payload, escaped
    assert 'value="y"' not in page                          # flagged field replaced


def test_browser_adds_a_flagged_field_the_recorded_body_does_not_carry():
    """ZAP flags fields the recorded body does not always contain.

    Dropping it would probe the endpoint without the finding — a request that
    looks right and asks nothing.
    """
    page = browser_server.bootstrap_page(
        "http://t/x", "frameid", "PAYLOAD", "other=1", "POST")
    assert 'name="frameid" value="PAYLOAD"' in page
    assert 'name="other" value="1"' in page


def test_a_bootstrap_that_never_navigated_is_inconclusive_and_never_refuted(
        stub_container, monkeypatch):
    """The false-refutation class, reintroduced by the fix for it — and blocked.

    If the submit does not happen (origin rejected, navigation blocked, virtual
    time out mid-flight), what Chromium dumps is still the bootstrap page. Read
    naively that is "the target's page contained no marker" — a refutation of a
    page that was never loaded, which is precisely what this module exists to
    correct.
    """
    monkeypatch.setattr(browser_server, "new_marker", lambda *a: "XSSABCDEF123456")
    stub_container(_result(_dom(browser_server.BOOTSTRAP_TITLE)))
    out = browser_server.verify_browser(
        "http://t/login", param="password", data="password=y", method="POST")
    assert out["outcome"] == INCONCLUSIVE
    assert out["tested"] is False
    assert "never loaded" in out["detail"]

    # …and the sentinel only applies to the POST path: a GET whose page happens
    # to carry that title is an ordinary refutation.
    stub_container(_result(_dom(browser_server.BOOTSTRAP_TITLE)))
    assert browser_server.verify_browser(
        "http://t/x?p=1", param="p")["outcome"] == REFUTED
