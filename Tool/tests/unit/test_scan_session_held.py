"""The scan keeps its session to the end, and says whether it did.

Regression tests for the 2026-11-03 defect: the setup gate proved the session at
the start, then Noir seeding (Gitea ``POST /user/logout``, Cacti ``/logout.php``)
or the spider (WordPress's nonce'd admin-bar link) requested the target's own
logout and the rest of every authenticated scan ran signed out. The fix keeps the
logout routes out of the scan (:func:`drop_logout_seeds`, ZAP's exclusion lists, a
request-line rewrite) and re-checks the session through ZAP (:class:`SessionWatch`).
Also: Cacti's ``X-Forwarded-For`` rule outlived its scan into every other target's.
"""
from __future__ import annotations

import glob
from pathlib import Path

import httpx
import pytest
import yaml

from dast_orchestrator.adapters import targets
from dast_orchestrator.adapters.noir_runner import SeedRequest
from dast_orchestrator.adapters.zap_client import ZapClient, ZapError
from dast_orchestrator.stages.scan import pipeline
from dast_orchestrator.stages.scan.common import (
    LOGOUT_REWRITE_SUFFIX, drop_logout_seeds, logout_regex, marker_kind)


class _Profile:
    logged_in_indicator = "Sign Out"
    logged_in_check_path = "/"


class _Bodies:
    """A ZAP whose through-ZAP fetches return the given bodies in turn."""

    def __init__(self, *bodies):
        self._bodies = list(bodies)
        self.fetched = []

    def fetch_body(self, url):
        self.fetched.append(url)
        body = self._bodies.pop(0)
        if isinstance(body, Exception):
            raise body
        return body


def _watch(zap, interval=300.0):
    return pipeline.SessionWatch(zap, target_url="http://target-gitea:3000",
                                 auth_profile=_Profile(), interval_seconds=interval,
                                 attempts=3, retry_seconds=0)


# -- keeping the logout out of the scan -------------------------------------------

def test_seeding_drops_the_logout_route_and_counts_it():
    seeds = [SeedRequest("GET", "http://t/explore", "a"),
             SeedRequest("POST", "http://t/user/logout", "b"),
             SeedRequest("GET", "http://t/user/settings", "c")]
    kept, dropped = drop_logout_seeds(seeds, ("/user/logout",))
    assert [s.url for s in kept] == ["http://t/explore", "http://t/user/settings"]
    assert dropped == 1


def test_no_markers_drops_nothing():
    seeds = [SeedRequest("POST", "http://t/user/logout", "b")]
    assert drop_logout_seeds(seeds, ()) == (seeds, 0)


def test_a_marker_is_a_url_substring_a_post_path_or_a_body_text():
    assert marker_kind("/settings") == ("url", "/settings")
    assert marker_kind("POST /admin") == ("post", "/admin")
    assert marker_kind("body:drp_action=") == ("body", "drp_action=")


def test_a_post_marker_drops_only_a_post_to_exactly_that_path():
    seeds = [SeedRequest("POST", "http://t/admin", "a"),
             SeedRequest("GET", "http://t/admin", "b"),
             SeedRequest("POST", "http://t/admin/users", "c")]
    kept, dropped = drop_logout_seeds(seeds, ("POST /admin", "body:op="))
    assert [(s.method, s.url) for s in kept] == [("GET", "http://t/admin"),
                                                 ("POST", "http://t/admin/users")]
    assert dropped == 1


def test_the_exclusion_regex_quotes_the_marker_literally():
    assert logout_regex("/logout.php") == r".*\Q/logout.php\E.*"


def test_every_target_with_a_login_declares_its_logout():
    for path in glob.glob(str(targets.TARGETS_DIR / "*" / "target.yml")):
        auth = (yaml.safe_load(Path(path).read_text()) or {}).get("auth")
        if auth:
            assert auth.get("logout_markers"), f"{path}: auth without logout_markers"


def test_the_markers_are_loaded_into_the_profile():
    target = targets.target_from_dict({
        "name": "t", "base_url": "http://t", "source_dir": "src",
        "auth": {"login_path": "/login", "session_cookie": "s",
                 "logout_markers": ["/logout", ""],
                 "destructive_markers": ["POST /admin", "body:op="]}})
    assert target.auth.logout_markers == ("/logout",)
    assert target.auth.destructive_markers == ("POST /admin", "body:op=")


def test_an_authenticated_scan_without_logout_markers_refuses_to_start():
    class _Sess:
        mode, username = "admin", "a"

    with pytest.raises(ValueError, match="logout"):
        pipeline.run_scan("http://zap:8080", "k", "http://t", 1, 1,
                          auth_session=_Sess(), target_name="")


# -- the login waits for the reset --------------------------------------------------

def _driver_scan(monkeypatch, argv, login=None):
    from dast_orchestrator.stages.scan import driver
    seen = {}
    monkeypatch.setattr(driver, "run_scan", lambda *a, **k: seen.update(k))

    def no_login(*a, **k):
        raise AssertionError("logged in before the reset")
    monkeypatch.setattr(driver.auth, "login", login or no_login)
    return driver.main(["gitea", "--api-key", "x", *argv]), seen


def test_with_a_reset_the_driver_leaves_the_login_to_after_it(monkeypatch):
    rc, seen = _driver_scan(monkeypatch, ["--auth", "admin", "--reset-target"])
    assert rc == 0
    assert seen["auth_session"] == pipeline.PendingLogin("admin")


def test_without_a_reset_the_driver_logs_in_first(monkeypatch):
    rc, seen = _driver_scan(monkeypatch, ["--auth", "admin"],
                            login=lambda url, profile, mode: f"session:{mode}")
    assert rc == 0 and seen["auth_session"] == "session:admin"


def test_a_failed_login_after_the_reset_is_a_clean_exit(monkeypatch):
    from dast_orchestrator.stages.scan import driver

    def scan(*a, **k):
        raise driver.auth.AuthError("login timed out after 30s")
    monkeypatch.setattr(driver, "run_scan", scan)
    assert driver.main(["gitea", "--api-key", "x", "--auth", "admin",
                        "--reset-target"]) == 1


def test_a_deferred_login_without_a_reset_is_refused():
    with pytest.raises(ValueError, match="reset"):
        pipeline.run_scan("http://zap:8080", "k", "http://t", 1, 1,
                          auth_session=pipeline.PendingLogin("admin"), target_name="")


# -- the ZAP setup: rules and exclusions -------------------------------------------

class _SetupZap:
    """Records the calls `_configure_zap` makes; answers with harmless defaults."""

    RELEASE_QUALITY = "release"

    def __init__(self, rules):
        self.rules = list(rules)
        self.calls = []

    def replacer_rules(self):
        return list(self.rules)

    def remove_replacer_rule(self, description):
        self.calls.append(("remove", description))
        if description in self.rules:
            self.rules.remove(description)

    def ascan_set_injectable_targets(self, mask):
        return mask

    def fetch_body(self, url):
        return "Sign Out"

    def __getattr__(self, name):
        answers = {"restart_daemon": "2.17.0", "wait_until_ready": "2.17.0",
                   "installed_addons": [], "scanners": []}

        def call(*args, **kwargs):
            self.calls.append((name, *args))
            return answers.get(name)
        return call


def _configure(zap, monkeypatch, **overrides):
    monkeypatch.setattr(pipeline.zap_session, "prepare", lambda *a, **k: "/s")
    monkeypatch.setattr(pipeline.targets, "marker_rule_ids", lambda: set())

    class _Sess:
        mode, username = "admin", "a"

        def cookie_header(self):
            return "i_like_gitea=x"

    args = dict(target_url="http://t", timestamp="ts", zap_container="dast-zap",
                zap_mode=pipeline.ZAP_MODE_REST, plan_path=None, plan_digest="",
                zap_addr="http://zap", structural_parameters=(), data_dir=Path("/tmp"),
                run_id="r", max_alerts_per_rule=-1, max_scan_minutes=1,
                max_rule_minutes=1, scan_rules=(), disabled_rules=(),
                auth_session=_Sess(), scan_headers={}, injectable_targets=1,
                add_query_param=False, auth_profile=_Profile(),
                route_markers=("/user/logout", "POST /admin", "body:drp_action="))
    args.update(overrides)
    pipeline._configure_zap(zap, **args)


def test_setup_removes_every_leftover_own_rule_but_never_zaps(monkeypatch):
    zap = _SetupZap(["Remove CSP", "scan-header-X-Forwarded-For",
                     "dast-logout-block-0"])
    _configure(zap, monkeypatch)
    removed = {c[1] for c in zap.calls if c[0] == "remove"}
    assert {"scan-header-X-Forwarded-For", "dast-logout-block-0"} <= removed
    assert "Remove CSP" not in removed


def test_setup_excludes_and_rewrites_each_logout_route(monkeypatch):
    zap = _SetupZap([])
    _configure(zap, monkeypatch)
    assert ("spider_exclude_from_scan", logout_regex("/user/logout")) in zap.calls
    assert ("ascan_exclude_from_scan", logout_regex("/user/logout")) in zap.calls
    assert ("add_request_rewrite_rule", "dast-logout-block-0", "/user/logout",
            "/user/logout" + LOGOUT_REWRITE_SUFFIX) in zap.calls


def test_a_post_marker_rewrites_only_that_request_line_and_excludes_no_url(monkeypatch):
    zap = _SetupZap([])
    _configure(zap, monkeypatch)
    assert ("add_request_rewrite_rule", "dast-logout-block-1", "POST http://t/admin ",
            f"POST http://t/admin{LOGOUT_REWRITE_SUFFIX} ") in zap.calls
    excluded = [c[1] for c in zap.calls if c[0].endswith("exclude_from_scan")]
    assert all("admin" not in rx for rx in excluded)


def test_a_body_marker_rewrites_the_request_body(monkeypatch):
    calls = []

    class _Zap(_SetupZap):
        def add_request_rewrite_rule(self, *args, **kwargs):
            calls.append((args, kwargs))

    _configure(_Zap([]), monkeypatch)
    assert (("dast-logout-block-2", "drp_action=", "drp_action=" + LOGOUT_REWRITE_SUFFIX),
            {"in_body": True}) in calls


# -- the session checks -------------------------------------------------------------

def test_require_passes_and_records_while_the_session_holds():
    zap = _Bodies("... Sign Out ...")
    watch = _watch(zap)
    watch.require("seeding")
    assert [c["phase"] for c in watch.checks] == ["seeding"]
    assert watch.checks[0]["held"] is True
    assert zap.fetched == ["http://target-gitea:3000/"]


def test_require_aborts_once_the_session_is_gone():
    watch = _watch(_Bodies("<form id=login>"))
    with pytest.raises(ZapError, match="lost during spider"):
        watch.require("spider")
    assert watch.checks[-1]["held"] is False


def test_require_retries_a_check_that_got_no_answer():
    zap = _Bodies(ZapError("internal_error"), "Sign Out")
    watch = _watch(zap)
    watch.require("spider")
    assert len(zap.fetched) == 2 and watch.checks[-1]["held"] is True


def test_require_goes_on_when_no_try_got_an_answer():
    watch = _watch(_Bodies(*[httpx.ReadTimeout("slow")] * 3))
    watch.require("spider")
    assert watch.checks == [{"phase": "spider", "at_seconds": watch.checks[0]["at_seconds"],
                             "held": None}]


def test_tick_waits_for_its_interval():
    zap = _Bodies("Sign Out")
    watch = _watch(zap, interval=3600)
    watch.tick("active_scan")
    assert zap.fetched == [] and watch.checks == []


def test_tick_records_a_loss_without_raising():
    watch = _watch(_Bodies("anonymous"), interval=0)
    watch.tick("active_scan")
    assert watch.checks[-1]["held"] is False
    assert watch.held_to_end is False


def test_a_failed_check_is_recorded_as_unknown_not_as_a_loss():
    watch = _watch(_Bodies("Sign Out", httpx.ReadTimeout("slow")), interval=0)
    watch.check("seeding")
    watch.tick("active_scan")
    assert [c["held"] for c in watch.checks] == [True, None]
    assert watch.held_to_end is True


def test_no_checks_means_unknown():
    assert _watch(_Bodies()).held_to_end is None


# -- the client calls --------------------------------------------------------------

def _client(handler):
    zap = ZapClient("http://zap:8080", "test-key")
    zap._http = httpx.Client(base_url="http://zap:8080",
                             transport=httpx.MockTransport(handler))
    return zap


def test_fetch_body_reads_the_exchange_sendrequest_returns():
    def handler(request):
        assert request.url.path == "/JSON/core/action/sendRequest/"
        assert request.url.params["followRedirects"] == "false"
        assert request.url.params["request"].startswith("GET http://t/ HTTP/1.1")
        return httpx.Response(200, json={"sendRequest": [
            {"responseHeader": "HTTP/1.1 200 OK\r\nX: y", "responseBody": "Sign Out"}]})

    assert _client(handler).send_and_read("GET", "http://t/") == (
        "HTTP/1.1 200 OK", "Sign Out")
    assert _client(handler).fetch_body("http://t/") == "Sign Out"


def test_fetch_body_raises_when_zap_returns_no_exchange():
    with pytest.raises(ZapError, match="no exchange"):
        _client(lambda r: httpx.Response(200, json={"sendRequest": []})).fetch_body("http://t/")


def test_the_rewrite_rule_matches_the_request_header_literally():
    seen = {}

    def handler(request):
        seen.update(request.url.params)
        return httpx.Response(200, json={"Result": "OK"})

    _client(handler).add_request_rewrite_rule("d", "/logout", "/logout-x")
    assert (seen["matchType"], seen["matchRegex"], seen["matchString"],
            seen["replacement"]) == ("REQ_HEADER_STR", "false", "/logout", "/logout-x")


def test_poll_calls_on_poll_between_polls_but_not_after_the_last(monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)
    zap = ZapClient("http://zap:8080", "k")
    answers = iter([10, 50, 100])
    ticks = []
    out = zap.poll_until_complete(lambda _id: next(answers), "1", "ascan",
                                  step=0, on_poll=lambda: ticks.append(1))
    assert out == "complete" and len(ticks) == 2
