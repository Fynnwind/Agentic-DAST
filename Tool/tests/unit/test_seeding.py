"""Unit tests for the Noir-endpoint -> ZAP seeding loop in the driver."""

from __future__ import annotations

import httpx
import pytest

from dast_orchestrator.adapters.noir_runner import SeedRequest
from dast_orchestrator.stages.scan import seed_zap
from dast_orchestrator.adapters.zap_client import ZapClient, ZapError

SEEDS = [
    SeedRequest("GET", "http://t/explore/repos", "GET /explore/repos"),
    SeedRequest("POST", "http://t/user/login", "POST /user/login"),
]


def _client_with(handler: httpx.MockTransport) -> ZapClient:
    zap = ZapClient("http://zap:8080", "test-key")
    zap._http = httpx.Client(base_url="http://zap:8080", transport=handler)
    return zap


def test_seed_zap_routes_get_and_non_get_to_different_actions():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(200, json={"ok": []})

    assert seed_zap(_client_with(httpx.MockTransport(handler)), SEEDS) == 2
    assert calls == ["/JSON/core/action/accessUrl/", "/JSON/core/action/sendRequest/"]


def test_seed_zap_skips_failures_instead_of_aborting_the_run():
    # A route Noir inferred may not be reachable; one rejected seed must not
    # take down a CI job that still has hundreds of good seeds to push.
    def handler(request: httpx.Request) -> httpx.Response:
        if "accessUrl" in request.url.path:
            return httpx.Response(200, json={"code": "illegal_parameter", "message": "bad url"})
        return httpx.Response(200, json={"ok": []})

    assert seed_zap(_client_with(httpx.MockTransport(handler)), SEEDS) == 1


def test_injectable_targets_default_includes_url_path():
    # The whole point of the fix: ZAP's default (query-string + post-data)
    # leaves the Noir-seeded endpoints uninjectable, because they carry no
    # query string and an empty body. url-path is where Gitea's documented
    # traversal / open-redirect bugs are reached.
    from dast_orchestrator.stages.scan import (
        DEFAULT_INJECTABLE_TARGETS,
        describe_injectable_targets,
    )

    assert DEFAULT_INJECTABLE_TARGETS & ZapClient.TARGET_URLPATH
    assert DEFAULT_INJECTABLE_TARGETS & ZapClient.TARGET_QUERYSTRING
    assert DEFAULT_INJECTABLE_TARGETS & ZapClient.TARGET_POSTDATA
    assert describe_injectable_targets(DEFAULT_INJECTABLE_TARGETS) == (
        "query-string, post-data, url-path"
    )
    assert describe_injectable_targets(0) == "none"


def test_setting_injectable_targets_reads_the_value_back():
    # A silently-rejected bitmask looks exactly like a scan that found nothing,
    # so the client reports what ZAP actually holds rather than what was sent.
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.url.params.get("Integer", "")))
        if "view" in request.url.path:
            return httpx.Response(200, json={"TargetParamsInjectable": "19"})
        return httpx.Response(200, json={"Result": "OK"})

    zap = _client_with(httpx.MockTransport(handler))
    assert zap.ascan_set_injectable_targets(19) == 19
    assert seen[0] == ("/JSON/ascan/action/setOptionTargetParamsInjectable/", "19")
    assert seen[1][0] == "/JSON/ascan/view/optionTargetParamsInjectable/"


def test_add_query_param_is_sent_as_a_lowercase_boolean():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.params.get("Boolean", ""))
        return httpx.Response(200, json={"Result": "OK"})

    _client_with(httpx.MockTransport(handler)).ascan_set_add_query_param(True)
    assert seen == ["true"]


def test_seed_zap_on_empty_list_is_a_noop():
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        pytest.fail("no request expected")

    assert seed_zap(_client_with(httpx.MockTransport(handler)), []) == 0


# -- crawler selection -----------------------------------------------------


def test_spider_lists_are_ordered_and_deduplicated():
    """Order is meaningful: each crawler adds to the tree the previous built.

    Running the cheap HTML pass first means the browser crawlers start from a
    populated tree rather than the site root.
    """
    from dast_orchestrator.stages.scan import parse_spiders, DEFAULT_SPIDERS

    assert parse_spiders("traditional,client") == ("traditional", "client")
    assert parse_spiders("client,traditional") == ("client", "traditional")
    assert parse_spiders("ajax,ajax,traditional") == ("ajax", "traditional")
    assert parse_spiders("  traditional , client  ") == ("traditional", "client")
    assert parse_spiders("") == DEFAULT_SPIDERS
    assert parse_spiders([]) == DEFAULT_SPIDERS


def test_an_unknown_spider_is_refused_by_name():
    """Silently ignoring a typo would crawl less than the run claims to."""
    from dast_orchestrator.stages.scan import parse_spiders

    with pytest.raises(ValueError, match="unknown spider 'clientt'"):
        parse_spiders("traditional,clientt")


def test_traditional_is_the_default_because_it_set_the_baseline():
    """Every recorded coverage number came from the traditional spider alone.

    A default that quietly added a browser crawler would move that baseline
    rather than adding to it, and no stored run would be comparable again.
    """
    from dast_orchestrator.stages.scan import DEFAULT_SPIDERS

    assert DEFAULT_SPIDERS == ("traditional",)


# -- scan health: ZAP reports a no-op identically to a finished scan --------


def test_a_short_silent_active_scan_is_reported_as_suspect():
    """The exact run that cost a baseline, and which nothing else caught.

    109 seconds over 223 URLs raising zero active alerts, reported by ZAP as
    `poll_outcome: complete`, `truncated_by_cap: false` — byte-identical
    reporting to the 1,364-second run over the same tree that raised 123.
    """
    from dast_orchestrator.stages.scan import scan_health

    why = scan_health(seconds=109, cap_minutes=45, active_alerts=0,
                      urls_in_tree=223)
    assert why is not None
    assert "4.0% of its 45-minute cap" in why
    assert "raised NO" in why


def test_a_scan_that_found_something_is_never_suspect():
    """Fast and productive is a good scan, not a broken one."""
    from dast_orchestrator.stages.scan import scan_health

    assert scan_health(109, 45, active_alerts=1, urls_in_tree=223) is None


def test_a_long_scan_that_found_nothing_is_not_suspect():
    """A target can genuinely have nothing to find.

    The assertion fires only on the CONJUNCTION — almost no time AND nothing
    found — because either alone is ordinary.
    """
    from dast_orchestrator.stages.scan import scan_health

    assert scan_health(1364, 45, active_alerts=0, urls_in_tree=223) is None


def test_an_empty_tree_is_not_the_active_scanner_s_fault():
    from dast_orchestrator.stages.scan import scan_health

    assert scan_health(2, 45, active_alerts=0, urls_in_tree=0) is None
    assert scan_health(2, 0, active_alerts=0, urls_in_tree=223) is None


def test_the_client_spider_is_not_polled_for_a_percentage_that_never_arrives():
    """Its `status` is not monotonic, so waiting for 100 hangs.

    Observed live on 2026-09-04: 93, then 83, 77, 72 — it is a ratio of done to
    queued work, and discovering new work moves the denominator. The first run
    with this crawler enabled sat waiting for a 100 that was never coming.
    `status` is also the only view the component exposes, so the completion
    signal has to be the thing actually wanted: the tree has stopped growing.
    """
    from dast_orchestrator.stages import scan as scan_mod

    class _Zap:
        def __init__(self, sizes):
            self.sizes = list(sizes)
            self.stopped = False
        def client_spider_status(self, scan_id):
            return 72                      # never reaches 100, as in the wild
        def urls(self, base_url=""):
            return [None] * (self.sizes.pop(0) if self.sizes else 240)
        def client_spider_stop(self, scan_id):
            self.stopped = True

    # Grows, then stalls. The stall is what ends it.
    zap = _Zap([200, 220, 240] + [240] * 20)
    scan_mod.common.CLIENT_POLL_SECONDS = 0.0     # do not actually sleep in a test
    outcome = scan_mod._poll_client_spider(zap, "http://t", "0", minutes=5)
    assert outcome == "client-stalled"
    assert zap.stopped, "a stalled crawler must be stopped, not left running"


def test_a_client_spider_that_reaches_100_is_simply_complete():
    from dast_orchestrator.stages import scan as scan_mod

    class _Zap:
        def client_spider_status(self, scan_id): return 100
        def urls(self, base_url=""): return []
        def client_spider_stop(self, scan_id): raise AssertionError("no need")

    scan_mod.common.CLIENT_POLL_SECONDS = 0.0
    assert scan_mod._poll_client_spider(_Zap(), "http://t", "0", 5) == "complete"

def test_a_dead_daemon_is_restarted_before_it_is_probed_for_readiness():
    """`--zap-reset restart` exists to recover exactly this, and could not.

    Probing for readiness first means a row fails on the corpse of the run
    before it. That cascade has happened twice: 2026-09-05, where a Gitea OOM
    took the following WordPress row down with it, and 2026-09-08, where sheet
    14's `wordpress-45` died after 2.1 minutes with "daemon not ready after 60
    attempts" because the Gitea row before it had been shut down by ZAP's
    Insights add-on at 97% heap.

    Asserted on the source order rather than by driving a scan, because what
    went wrong was two correct calls in the wrong sequence — a mock that
    answered either way would pass.
    """
    import inspect

    from dast_orchestrator.stages.scan import pipeline

    # The restart/ready order lives in the extracted ZAP-setup phase.
    source = inspect.getsource(pipeline._configure_zap)
    restart = source.index("restart_daemon(zap_container)")
    ready = source.index("zap.wait_until_ready()")
    assert restart < ready, (
        "wait_until_ready runs before restart_daemon, so a daemon that died "
        "during the previous row fails this row before the restart that would "
        "have fixed it")


def test_the_script_scan_rule_is_disabled_by_default_and_the_reason_is_a_measurement():
    """Plugin 50000 is why ZAP shut itself down, measured rather than guessed.

    A `jcmd GC.class_histogram` at three points of a 45-minute Gitea scan: live
    heap held 0.27–1.21 GB for 40 minutes across 50 rules, then reached 6.73 GB
    of 8 within a minute of `ActiveScriptScanRule` starting, and GraalJS/Truffle
    objects went from 1 MB (1.1% of live heap) to 2,876 MB (71.4%). HSQLDB
    stayed at 5.5 MB — which is what killed the earlier hypothesis that the
    session store was the term.

    Pinned because the earlier candidate was `DomXssScanRule`, chosen on time
    and yield rather than on memory. That rule is plugin 40026 — the one that
    found this project's only confirmed CVE — so acting on the guess would have
    cost the headline result and left the actual cause running.
    """
    from dast_orchestrator.stages import scan

    # BOTH ids: 50000 is the scripts add-on's dispatcher and 100043 is the one
    # script it actually runs, registered as its own plugin. The heap peaked at
    # 6.39 GB during the first and 6.73 GB during the second, so disabling only
    # the dispatcher would leave the heavier of the two a live plugin.
    assert "50000" in scan.DEFAULT_DISABLED_RULES
    assert "100043" in scan.DEFAULT_DISABLED_RULES
    assert "40026" not in scan.DEFAULT_DISABLED_RULES, (
        "40026 is the DOM-XSS rule that confirmed the WPDM frameid finding; "
        "disabling it would remove the only CVE this pipeline has detected")


def test_a_seed_holds_the_url_zap_will_hold():
    # The seed map records seed.url and the join matches ZAP's alert URLs to it,
    # so the encoding happens when the seed is made, not when it is sent.
    seed = SeedRequest("GET", "http://t/x?ids[]=1", "oracle:/x?ids[]=1")
    assert seed.url == "http://t/x?ids%5B%5D=1"
    assert seed.endpoint_key == "oracle:/x?ids[]=1"


def test_a_refused_oracle_seed_stops_the_scan():
    # A ceiling run without its sink in the tree measures no ceiling; skipping it
    # with one warning line is how WordPress's stats sink went unscanned.
    oracle = SeedRequest("GET", "http://t/sink?id=1", "oracle:/sink?id=1")

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("url") == oracle.url:
            return httpx.Response(400, json={"code": "illegal_parameter",
                                             "message": "bad url"})
        return httpx.Response(200, json={"Result": "OK"})

    zap = _client_with(httpx.MockTransport(handler))
    with pytest.raises(ZapError, match="oracle seed"):
        seed_zap(zap, [*SEEDS, oracle], required=[oracle])
    # The same refusal on an ordinary seed is still only skipped.
    assert seed_zap(zap, [*SEEDS, oracle]) == 2
