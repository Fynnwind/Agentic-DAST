"""Unit tests for the ZAP REST client (mocked transport, no live daemon)."""

from __future__ import annotations

import io

import httpx
import pytest

from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters import zap_client
from dast_orchestrator.adapters.zap_client import ZapClient, ZapError, build_raw_request


def _client_with(handler: httpx.MockTransport) -> ZapClient:
    zap = ZapClient("http://zap:8080", "test-key")
    zap._http = httpx.Client(base_url="http://zap:8080", transport=handler)
    zap._transport = handler
    return zap


def test_version_attaches_api_key_and_parses():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["apikey"] = request.url.params.get("apikey", "")
        return httpx.Response(200, json={"version": "2.17.0"})

    zap = _client_with(httpx.MockTransport(handler))
    assert zap.version() == "2.17.0"
    assert seen["path"] == "/JSON/core/view/version/"
    assert seen["apikey"] == "test-key"


def test_logical_error_body_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": "bad_view", "message": "nope"})

    zap = _client_with(httpx.MockTransport(handler))
    with pytest.raises(ZapError):
        zap.version()


def test_spider_scan_returns_scan_id_and_bools_lowercased():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["recurse"] = request.url.params.get("recurse", "")
        return httpx.Response(200, json={"scan": "7"})

    zap = _client_with(httpx.MockTransport(handler))
    assert zap.spider_scan("http://target", recurse=True) == "7"
    assert seen["recurse"] == "true"


def test_access_url_seeds_site_tree():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["url"] = request.url.params.get("url", "")
        seen["follow"] = request.url.params.get("followRedirects", "")
        return httpx.Response(200, json={"accessUrl": []})

    zap = _client_with(httpx.MockTransport(handler))
    zap.access_url("http://target-gitea:3000/explore/repos")
    assert seen["path"] == "/JSON/core/action/accessUrl/"
    assert seen["url"] == "http://target-gitea:3000/explore/repos"
    # Redirects off: following them would add nodes the target chose, not the
    # ones Noir extracted, muddying the coverage-delta measurement.
    assert seen["follow"] == "false"


def test_build_raw_request_uses_absolute_uri_and_crlf():
    raw = build_raw_request("post", "http://target-gitea:3000/user/login")
    assert raw.startswith("POST http://target-gitea:3000/user/login HTTP/1.1\r\n")
    assert "Host: target-gitea:3000\r\n" in raw
    assert "Content-Length: 0\r\n" in raw
    assert raw.endswith("\r\n\r\n")


def test_send_request_passes_raw_request_through():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["request"] = request.url.params.get("request", "")
        return httpx.Response(200, json={"sendRequest": []})

    zap = _client_with(httpx.MockTransport(handler))
    zap.send_request(build_raw_request("POST", "http://target-gitea:3000/user/login"))
    assert seen["path"] == "/JSON/core/action/sendRequest/"
    assert seen["request"].startswith("POST http://target-gitea:3000/user/login")


def test_urls_passthrough():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"urls": ["http://t/", "http://t/a"]})

    zap = _client_with(httpx.MockTransport(handler))
    assert zap.urls("http://t") == ["http://t/", "http://t/a"]


def test_alerts_passthrough():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"alerts": [{"risk": "Low"}]})

    zap = _client_with(httpx.MockTransport(handler))
    alerts = zap.alerts("http://target")
    assert alerts == [{"risk": "Low"}]


def test_alerts_pages_large_and_stops_on_a_short_page():
    # ZAP re-reads every alert before a page's start, so the page size is the cost
    # of a large scan's collection: 500-alert pages took 9.3 min for 29k alerts.
    asked: list[tuple[int, int]] = []
    total = zap_client.ZapClient.ALERT_PAGE_SIZE * 2 + 3

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["start"])
        count = int(request.url.params["count"])
        asked.append((start, count))
        page = [{"id": str(i)} for i in range(start, min(start + count, total))]
        return httpx.Response(200, json={"alerts": page})

    zap = _client_with(httpx.MockTransport(handler))
    alerts = zap.alerts("http://target")
    size = zap_client.ZapClient.ALERT_PAGE_SIZE
    assert size >= 10_000
    assert asked == [(0, size), (size, size), (2 * size, size)]
    assert [a["id"] for a in alerts] == [str(i) for i in range(total)]


def test_alerts_drops_the_alert_zaps_second_page_repeats():
    # Measured on ZAP 2.17: a page at start=s > 0 begins at position s - 1, so the
    # first page's last alert comes back as the second page's first.
    total = 7

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["start"])
        count = int(request.url.params["count"])
        first = start - 1 if start else 0
        page = [{"id": str(i)} for i in range(first, min(first + count, total))]
        return httpx.Response(200, json={"alerts": page})

    zap = _client_with(httpx.MockTransport(handler))
    alerts = zap.alerts("http://target", page_size=3)
    assert [a["id"] for a in alerts] == [str(i) for i in range(total)]


def test_alerts_asks_a_page_that_broke_again_at_half_the_size(monkeypatch):
    # 2026-11-03: ZAP closed the connection 4.8 MB into a 265 MB page, which took the
    # finished scan down with it. ZAP still holds the session, so ask again, smaller.
    monkeypatch.setattr(ZapClient, "ALERT_PAGE_FLOOR", 2)
    asked: list[tuple[int, int]] = []
    total = 10

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params["start"])
        count = int(request.url.params["count"])
        asked.append((start, count))
        if count > 4:
            raise httpx.RemoteProtocolError("peer closed connection", request=request)
        page = [{"id": str(i)} for i in range(start, min(start + count, total))]
        return httpx.Response(200, json={"alerts": page})

    retries: list[tuple[int, int]] = []
    zap = _client_with(httpx.MockTransport(handler))
    alerts = zap.alerts("http://target", page_size=8,
                        on_retry=lambda start, size, _exc: retries.append((start, size)))
    assert [a["id"] for a in alerts] == [str(i) for i in range(total)]
    assert retries == [(0, 4)]
    assert asked[:2] == [(0, 8), (0, 4)]


def test_alerts_gives_up_when_a_page_at_the_floor_breaks(monkeypatch):
    monkeypatch.setattr(ZapClient, "ALERT_PAGE_FLOOR", 2)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer closed connection", request=request)

    zap = _client_with(httpx.MockTransport(handler))
    with pytest.raises(httpx.RemoteProtocolError):
        zap.alerts("http://target", page_size=8)


# -- polling must not lose a scan ------------------------------------------
#
# On 2026-08-25 ZAP's Insights add-on shut ZAP down at 95% heap *after* the
# active scan had raised its 5041 alerts, discarding the session. The status
# call then 400'd, the driver aborted, and a completed 21-minute scan was thrown
# away before its alerts were fetched.


def _poller(statuses, monkeypatch):
    client = zap_client.ZapClient.__new__(zap_client.ZapClient)
    monkeypatch.setattr(zap_client.time, "sleep", lambda *_a: None)
    it = iter(statuses)

    def status(_scan_id):
        value = next(it)
        if isinstance(value, Exception):
            raise value
        return value

    return client, status


def test_poll_returns_complete_at_100(monkeypatch):
    client, status = _poller([0, 50, 100], monkeypatch)
    assert client.poll_until_complete(status, "1", "ascan") == zap_client.POLL_COMPLETE


def test_a_vanished_scan_stops_polling_without_raising(monkeypatch):
    # The caller must still get to fetch the alerts ZAP already raised.
    client, status = _poller(
        [0, 50, zap_client.ZapError("does_not_exist (scanId)")], monkeypatch
    )
    assert client.poll_until_complete(status, "1", "ascan") == zap_client.POLL_UNAVAILABLE


def test_running_out_of_poll_budget_is_reported_not_raised(monkeypatch):
    client, status = _poller([10] * 100, monkeypatch)
    outcome = client.poll_until_complete(status, "1", "ascan", delay=3.0, max_wait=9)
    assert outcome == zap_client.POLL_TIMEOUT


def test_progress_prints_in_steps_not_every_change(monkeypatch, capsys):
    # A 45-minute scan polled every 3s crawls through every integer; printing on
    # change is still ~100 lines of nothing. A 5% step gives 20.
    client, status = _poller(list(range(0, 100)) + [100], monkeypatch)
    client.poll_until_complete(status, "1", "ascan", delay=3.0, max_wait=10_000,
                               heartbeat=300.0, step=5)
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert 15 <= len(lines) <= 25, len(lines)
    assert lines[-1].strip().endswith("100%")


def test_a_stalled_scan_still_reports_a_heartbeat(monkeypatch, capsys):
    # Stuck at one percent for an hour must not look like a hung process.
    client, status = _poller([37] * 400 + [100], monkeypatch)
    client.poll_until_complete(status, "1", "ascan", delay=3.0, max_wait=10_000,
                               heartbeat=300.0, step=5)
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert any("unchanged" in l for l in lines)
    # One heartbeat per 300s of a 1200s stall, not one per poll.
    assert len([l for l in lines if "unchanged" in l]) <= 6


def test_clock_only_progress_reports_once_per_heartbeat(monkeypatch, capsys):
    # A 45-minute stage is watched for liveness, not followed: one line per five
    # minutes, and no "unchanged" note — every line is a heartbeat, so the note
    # would be on all of them and inform nobody.
    client, status = _poller(list(range(0, 100)) * 10 + [100], monkeypatch)
    client.poll_until_complete(status, "1", "ascan", delay=3.0, max_wait=10_000,
                               heartbeat=300.0, step=0)
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert len(lines) <= 12, lines
    assert not any("unchanged" in l for l in lines)
    assert lines[-1].strip().endswith("100%")


# -- progress: two renderings, one of which is the fixed one ----------------


class _Tty(io.StringIO):
    def isatty(self):
        return True


def test_redirected_progress_is_stepped_lines(capsys):
    # A CI log is read after the fact and by a machine; carriage returns turn it
    # into one unreadable line. This rendering is the one whose shape is fixed.
    buf = io.StringIO()
    progress = ui.Progress("ascan", step=5, heartbeat=300, stream=buf)
    for percent in (0, 3, 5, 7, 12, 100):
        progress.update(percent, percent * 10)
    progress.close()
    assert buf.getvalue().splitlines() == [
        "  [ascan]   0%", "  [ascan]   5%", "  [ascan]  12%", "  [ascan] 100%"
    ]


def test_a_heartbeat_reprints_a_stalled_percentage():
    # A long plateau still has to show the run is alive.
    buf = io.StringIO()
    progress = ui.Progress("ascan", step=5, heartbeat=60, stream=buf)
    progress.update(40, 0)
    progress.update(40, 120)
    lines = buf.getvalue().splitlines()
    assert len(lines) == 2 and "unchanged for 1m" in lines[1]


def test_a_terminal_redraws_one_line_with_an_eta():
    buf = _Tty()
    progress = ui.Progress("ascan", stream=buf)
    progress.update(25, 300)
    progress.update(50, 600)
    progress.close()
    out = buf.getvalue()
    # First paint drops the bar + a newline; the second repaints it in place by
    # stepping up to it (`\033[1A`) and back down (`\033[1B`) — a fixed header,
    # not a line that moves.
    assert "\033[1A" in out and "\033[1B" in out
    assert "25%" in out and "50%" in out
    # Extrapolated from the rate so far, and labelled `~`: ZAP's active scanner
    # does not advance linearly, so a confident estimate would be a lie.
    assert "~10.0m left" in out


def test_closing_leaves_a_durable_line_when_it_ended_badly():
    buf = _Tty()
    progress = ui.Progress("ascan", stream=buf)
    progress.update(93, 60)
    progress.close("still at 93% when the 900s poll budget ran out")
    assert "still at 93%" in buf.getvalue().splitlines()[-1]


def test_duration_uses_one_unit():
    assert ui._duration(45) == "45s"
    assert ui._duration(600) == "10.0m"
    assert ui._duration(7200) == "2.0h"


def test_ci_gets_the_stepped_lines_even_with_a_terminal(monkeypatch):
    # Some CI systems allocate a pty. A log of carriage returns is one
    # unreadable line, so `CI` overrides the isatty check.
    monkeypatch.setenv("CI", "true")
    buf = _Tty()
    progress = ui.Progress("ascan", step=5, stream=buf)
    progress.update(10, 60)
    progress.close()
    assert buf.getvalue() == "  [ascan]  10%\n"
    assert "\r" not in buf.getvalue()


# -- a clean daemon without restarting it ----------------------------------


def test_new_session_and_rule_removal_are_both_issued(respx_mock):
    # Together they replace "restart ZAP between runs", which a harness sheet
    # has no way to do.
    import httpx

    calls = []

    def record(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"Result": "OK"})

    respx_mock.get(url__startswith="http://zap:8080/JSON/").mock(side_effect=record)
    client = zap_client.ZapClient("http://zap:8080", "k")
    client.new_session()
    client.remove_replacer_rule("dast-auth-session")
    assert "/JSON/core/action/newSession/" in calls
    assert "/JSON/replacer/action/removeRule/" in calls


def test_removing_a_rule_that_is_not_there_is_not_an_error(respx_mock):
    # ZAP reports "no such rule" as an error, and not-present is the normal
    # case: every run removes the rule, most runs never added one.
    import httpx

    respx_mock.get(url__startswith="http://zap:8080/JSON/replacer/").mock(
        return_value=httpx.Response(400, json={"code": "does_not_exist"})
    )
    client = zap_client.ZapClient("http://zap:8080", "k")
    client.remove_replacer_rule("dast-auth-session")   # must not raise


# -- output hierarchy: session > command > phase ---------------------------


def test_the_three_rule_characters_are_distinct():
    # The rule character IS the hierarchy: a sheet spawns a stage per row and
    # every stage prints its own banner, so without a heavier rule above them a
    # night's log is a wall of identical headers with no visible boundary.
    import io as _io

    buf = _io.StringIO()
    monkey = ui._write
    try:
        ui._write = lambda line, stream=None: buf.write(line + "\n")
        ui.session("Harness run — x", "2 executions")
        ui.session_divider("1/2  row-a  ·  correlate")
        ui.headline("Triage", "run R")
        ui.phase("Join")
    finally:
        ui._write = monkey
    out = buf.getvalue()
    # Descending density, distinct glyphs: `#` session, `=` run/row, `+` stage,
    # `-` phase — each level uses only its own character.
    assert "#" in out and "=" in out and "+" in out and "-" in out
    rules = [l for l in out.splitlines() if len(set(l.strip())) == 1 and l.strip()]
    assert any(set(r.strip()) == {"#"} for r in rules)   # session banner
    assert any(set(r.strip()) == {"+"} for r in rules)   # stage headline


def test_a_divider_carries_its_position():
    # The reason to scroll a night's log is "where did execution N start".
    import io as _io

    buf = _io.StringIO()
    monkey = ui._write
    try:
        ui._write = lambda line, stream=None: buf.write(line + "\n")
        ui.session_divider("7/12  ctx-full-1  ·  correlate")
    finally:
        ui._write = monkey
    assert "7/12" in buf.getvalue()


def test_in_repo_paths_are_shortened_for_the_log():
    from pathlib import Path

    root = ui._REPO_ROOT
    assert ui.short_path(root / "config" / "scanner" / ".env") == "config/scanner/.env"
    # A symlink out of the tree still shortens: .venv/bin/python3 appears in
    # every spawned command, and resolving it lands in /opt/homebrew.
    assert ui.short_path(root / ".venv" / "bin" / "python3") == ".venv/bin/python3"
    # Anything genuinely outside is left alone rather than mangled.
    assert ui.short_path(Path("/etc/hosts")) == "/etc/hosts"


def test_short_command_leaves_non_paths_alone():
    root = str(ui._REPO_ROOT)
    argv = [f"{root}/.venv/bin/python3", "-m", "dast_orchestrator.stages.scan", "gitea",
            "--env-file", f"{root}/config/scanner/.env"]
    assert ui.short_command(argv) == (
        ".venv/bin/python3 -m dast_orchestrator.stages.scan gitea "
        "--env-file config/scanner/.env"
    )


def test_session_reset_gets_its_own_long_timeout():
    """A 45-minute run must not die on its first housekeeping call.

    `newSession` does work proportional to whatever the daemon has already
    accumulated, not to the run asking for it, so the default per-request
    timeout is the wrong ceiling. Observed 2026-09-02: a baseline sheet died 38
    seconds in, on the very first call of a 45-minute scan, against a ZAP that
    had been up five days — the worst place to fail, since nothing has been
    measured yet and the whole run is lost.
    """
    seen: list[tuple[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.extensions.get("timeout")))
        return httpx.Response(200, json={"Result": "OK"})

    client = zap_client.ZapClient("http://zap", "key", timeout=5.0)
    client._http = httpx.Client(base_url="http://zap",
                                transport=httpx.MockTransport(handler))
    client.new_session()

    path, timeout = seen[0]
    assert "core/action/newSession" in path
    read = (timeout or {}).get("read")
    assert read == zap_client.SESSION_RESET_TIMEOUT_SECONDS
    assert read > 5.0        # and emphatically not the client default


# -- a genuinely clean daemon ----------------------------------------------


def test_a_failed_restart_is_an_error_not_a_shrug(monkeypatch):
    """Continuing against a daemon in an unknown state is what this avoids."""
    import subprocess

    class _Failed:
        returncode = 1
        stdout = ""
        stderr = "No such container: dast-zap"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Failed())
    client = zap_client.ZapClient("http://zap", "key")
    with pytest.raises(ZapError, match="could not restart dast-zap"):
        client.restart_daemon("dast-zap")


def test_a_daemon_that_never_comes_back_is_an_error(monkeypatch):
    """A restart that silently left ZAP down would look like a fast, empty scan.

    Which is exactly the failure this whole mode exists to prevent — see
    RESET_RESTART for the 109-second scan that reported `complete`.
    """
    import subprocess

    class _Ok:
        returncode = 0
        stdout = "dast-zap"
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Ok())
    client = zap_client.ZapClient("http://zap", "key")
    monkeypatch.setattr(client, "version",
                        lambda: (_ for _ in ()).throw(RuntimeError("refused")))
    with pytest.raises(ZapError, match="did not answer within"):
        client.restart_daemon("dast-zap", timeout=0.1)


def test_restart_is_the_only_reset_mode():
    """The session reset was dropped: every run restarts the daemon."""
    assert zap_client.RESET_RESTART == "restart"
    assert not hasattr(zap_client, "RESET_SESSION")


def test_per_rule_strength_and_threshold_reach_the_daemon():
    """The request-based limit ZAP does offer per rule.

    Verified against the live 2.17.0 daemon before this was written:
    `setScannerAttackStrength` and `setScannerAlertThreshold` take a plugin id
    and are reflected in `ascan/view/scanners`. There is deliberately no
    per-rule *time* setter here, because ZAP has none — `MaxRuleDurationInMins`
    is one global number, which is why `targets.ScanRule` offers no per-rule
    `max_minutes` to write.
    """
    calls: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, dict(request.url.params)))
        return httpx.Response(200, json={"Result": "OK"})

    zap = _client_with(httpx.MockTransport(handler))
    zap.ascan_set_scanner_strength("40026", "LOW")
    zap.ascan_set_scanner_threshold("40026", "HIGH")

    assert calls[0][0] == "/JSON/ascan/action/setScannerAttackStrength/"
    assert calls[0][1]["id"] == "40026"
    assert calls[0][1]["attackStrength"] == "LOW"
    assert calls[1][0] == "/JSON/ascan/action/setScannerAlertThreshold/"
    assert calls[1][1]["alertThreshold"] == "HIGH"

    assert not hasattr(zap, "ascan_set_scanner_duration"), (
        "ZAP exposes no per-rule time limit; a method for one would be a "
        "promise this tool cannot keep")


def test_the_no_limit_sentinel_is_translated_only_at_this_boundary():
    """Every flag in the tool says -1; ZAP's own options say 0."""
    from dast_orchestrator.foundation import config

    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(dict(request.url.params))
        return httpx.Response(200, json={"Result": "OK"})

    zap = _client_with(httpx.MockTransport(handler))
    zap.ascan_set_max_scan_duration(config.NO_LIMIT)
    zap.ascan_set_max_rule_duration(30)
    assert sent[0]["Integer"] == "0"        # translated
    assert sent[1]["Integer"] == "30"       # untouched


def test_the_addon_inventory_is_recorded_because_rules_live_in_addons():
    """"ZAP 2.17.0" does not identify the rule set a run used.

    Two runs of the same pinned image differ if an add-on updated underneath
    them, and this daemon's own log shows exactly that inside one session:
    `retire` 0.63.0 -> 0.65.0 and `webdriverlinux` 215.0.0 -> 221.0.0. Every
    other tool here is pinned by image digest or commit; this is the scanner's
    equivalent, and without it a stored run cannot say which rules produced it.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"installedAddons": [
            {"id": "ascanrules", "version": "83.0.0", "sizeInBytes": "1"},
            {"id": "alertFilters", "version": "27.0.0"},
        ]})

    zap = _client_with(httpx.MockTransport(handler))
    assert zap.installed_addons() == [
        {"id": "alertFilters", "version": "27.0.0"},   # sorted by id
        {"id": "ascanrules", "version": "83.0.0"},
    ]


def test_release_quality_is_the_bar_the_scan_filters_on():
    """alpha and beta rules are work in progress ZAP itself excludes by default.

    A daemon enables whatever its add-ons register, so nothing chooses them —
    which is how an alpha rule (100043) ran here that no marker names and that
    took live heap from 1.2 GB to 6.7 GB.
    """
    from dast_orchestrator.adapters.zap_client import ZapClient

    assert ZapClient.RELEASE_QUALITY == "release"


# -- zap_uri: what ZAP's URI parser accepts ----------------------------------


def test_zap_uri_encodes_the_brackets_accessurl_refuses():
    # WordPress's stats sink, skipped in every ceiling until 2026-11-02:
    # ZAP answered the raw `package_ids[]` with HTTP 400 illegal_parameter.
    raw = "http://wp/wp-admin/edit.php?page=wpdm-stats&package_ids[]=1"
    assert zap_client.zap_uri(raw) == (
        "http://wp/wp-admin/edit.php?page=wpdm-stats&package_ids%5B%5D=1")


def test_zap_uri_keeps_escapes_and_is_idempotent():
    encoded = "http://cacti/remote_agent.php?local_data_ids%5B0%5D=6&poller_id=1"
    assert zap_client.zap_uri(encoded) == encoded
    once = zap_client.zap_uri("http://t/a b?q={x}|y&p=100%")
    assert once == "http://t/a%20b?q=%7Bx%7D%7Cy&p=100%25"
    assert zap_client.zap_uri(once) == once


def test_zap_uri_leaves_a_valid_url_and_the_host_alone():
    plain = "http://target-gitea:3000/user/login?redirect_to=%2F&a=b;c"
    assert zap_client.zap_uri(plain) == plain
    # An IPv6 host is the one place a bracket belongs.
    assert zap_client.zap_uri("http://[::1]:8080/x?a[]=1") == "http://[::1]:8080/x?a%5B%5D=1"
