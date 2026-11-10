"""Thin, transparent wrapper over the OWASP ZAP REST API.

Deliberately raw: every call maps to a documented ZAP endpoint
(https://www.zaproxy.org/docs/api/) so behaviour stays inspectable and
reproducible for the thesis writeup. No baseline/full-scan wrapper scripts,
no hidden state.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import ui


#: How :meth:`ZapClient.poll_until_complete` ended. Recorded per stage, because
#: a run whose scan was cut short must never be comparable with a clean one.
POLL_COMPLETE = "complete"
POLL_TIMEOUT = "timeout"
POLL_UNAVAILABLE = "status-unavailable"


class ZapError(RuntimeError):
    """Raised when the ZAP API returns an error or an unexpected shape."""


#: The scheme and authority of an absolute URL, left as they are by
#: :func:`zap_uri` (an IPv6 host is the one place a bracket belongs).
_URL_HEAD = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#]*")

#: A character ZAP's URI parser refuses in a path, query or fragment: anything
#: outside RFC 2396's reserved and unreserved sets, and a ``%`` that starts no
#: escape. Brackets are among them, so ``accessUrl`` answers ``x[]=1`` with
#: HTTP 400 ``illegal_parameter``.
_URI_UNSAFE = re.compile(r"%(?![0-9A-Fa-f]{2})|[^A-Za-z0-9\-_.!~*'();/?:@&=+$,%#]")


def zap_uri(url: str) -> str:
    """``url`` with every character ZAP's URI parser refuses percent-encoded.

    Valid ``%XX`` escapes are kept, so the encoding is idempotent and a URL
    with nothing to encode comes back unchanged. The target decodes the escapes
    back, so ``x%5B%5D=1`` still reaches PHP as the array ``x[]``.

    :param url: an absolute URL or a path.
    :returns: the same URL in a form ``accessUrl`` and ``sendRequest`` accept.
    """
    head = _URL_HEAD.match(url)
    split = head.end() if head else 0
    rest = _URI_UNSAFE.sub(lambda m: quote(m.group(0), safe=""), url[split:])
    return url[:split] + rest


#: ZAP's ``Alert.Source`` enum as it appears in an alert's ``sourceid``.
ALERT_SOURCES = {
    "0": "unknown",
    "1": "active-scanner",
    "2": "manual",
    "3": "passive-scanner",
    "4": "tool",
}


def alert_source_name(alert: dict[str, Any]) -> str:
    """Decode which ZAP stage produced an alert.

    :param alert: one alert dict from ``core/view/alerts``.
    :returns: a readable source name, or ``unrecognised-<id>`` for a value not
        in :data:`ALERT_SOURCES`.
    """
    source = str(alert.get("sourceid") or "0")
    return ALERT_SOURCES.get(source, f"unrecognised-{source}")


def count_alert_sources(alerts: list[dict[str, Any]]) -> dict[str, int]:
    """Count alerts per producing stage.

    A headline result rather than a diagnostic: a report that is 99%
    passive-scanner has not meaningfully exercised the active scanner, whatever
    its total alert count says.
    """
    counts: dict[str, int] = {}
    for alert in alerts:
        name = alert_source_name(alert)
        counts[name] = counts.get(name, 0) + 1
    return dict(sorted(counts.items()))


def build_raw_request(method: str, url: str) -> str:
    """Build the raw HTTP/1.1 request string `core/action/sendRequest` expects.

    ZAP wants an absolute-URI request line and CRLF terminators, with a blank
    line closing the headers. `Content-Length: 0` is set explicitly so ZAP does
    not treat a body-bearing method as truncated.
    """
    parsed = urlparse(url)
    return (
        f"{method.upper()} {url} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
    )


def zap_unlimited(value: int) -> int:
    """Translate this project's no-limit sentinel into ZAP's.

    Every flag in this tool uses :data:`dast_orchestrator.foundation.config.NO_LIMIT`
    (``-1``) for "no ceiling"; ZAP's own options use ``0`` for the same idea on
    scan duration, rule duration and alerts-per-rule. **The two conventions meet
    here and nowhere else** — a caller that reasoned in ZAP's convention would
    have to remember which of its own flags was the odd one out, which is the
    inconsistency this function exists to end.

    Anything other than the sentinel passes through untouched, so a real ``0``
    still reaches ZAP as ``0`` and means what ``0`` means to it.
    """
    return 0 if value == config.NO_LIMIT else value


#: Ceiling on :meth:`ZapClient.new_session`, which is slow in proportion to
#: whatever the daemon has already scanned rather than to the run requesting it.
#: Deliberately generous: the alternative to waiting is losing a whole scan to a
#: teardown, and a reset that takes four minutes is still far cheaper than the
#: 45-minute run it precedes.
SESSION_RESET_TIMEOUT_SECONDS = 300.0

#: How every run starts from a clean daemon: ``restart`` is a ``docker restart``
#: of the container, which waits for it to answer again (~11s on this machine) —
#: the only genuinely fresh start, because the site tree comes back empty when
#: the process is new. It replaces the PROCESS (clearing the heap), not the
#: writable layer, so an on-disk session left by a prior run survives it — that
#: disk reclaim is `zap_session.sweep_stale`'s job, not the restart's.
#:
#: The cheaper ``core/action/newSession`` reset was dropped: it empties the site
#: tree and the alerts but **not everything**, and the gap is measurable. Three
#: WordPress scans with an identical configuration digest gave 2,083s/84 active
#: alerts, 1,364s/123, and — the one that ran immediately after a 30-minute
#: Gitea scan in the same daemon, which peaked at 10.4 GB — **109s and zero**,
#: all three reporting ``poll_outcome: complete``. Restarting *is* possible from
#: here: the pipeline already runs containers for Noir and the verification
#: tools, so it has Docker either way.
RESET_RESTART = "restart"


class ZapClient:
    """Minimal client for the subset of the ZAP API the driver needs."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        #: Transport for :meth:`_fresh_http`; ``None`` is httpx's own (tests swap it).
        self._transport: httpx.BaseTransport | None = None
        self._http = httpx.Client(base_url=self._base_url, timeout=timeout)

    def _fresh_http(self) -> httpx.Client:
        """A client on a new connection, not one the pool has kept open."""
        return httpx.Client(base_url=self._base_url, timeout=self._timeout,
                            transport=self._transport)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ZapClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- low-level ---------------------------------------------------------

    def _get(self, view_or_action: str, timeout: float | None = None,
             http: httpx.Client | None = None, **params: Any) -> dict[str, Any]:
        """Call one ZAP API endpoint.

        :param view_or_action: API path such as ``"core/view/version"`` or
            ``"spider/action/scan"``. The API key is attached to every request.
        :param http: the client to send on; the long-lived one if ``None``.
        :raises ZapError: on a non-200 response, or on a logical error, which
            ZAP reports *inside* a 200 body as ``{"code": ..., "message": ...}``.
        """
        params = {k: v for k, v in params.items() if v is not None}
        params["apikey"] = self._api_key
        url = f"/JSON/{view_or_action}/"
        # A view that has to serialise thousands of records needs longer than the
        # client default, and only the caller knows which those are.
        resp = (http or self._http).get(url, params=params,
                                        timeout=timeout or self._timeout)
        if resp.status_code != 200:
            raise ZapError(f"{url} -> HTTP {resp.status_code}: {resp.text[:300]}")
        data = resp.json()
        if isinstance(data, dict) and "code" in data and "message" in data:
            raise ZapError(f"{url} -> ZAP error: {data}")
        return data

    # -- readiness ---------------------------------------------------------

    def version(self) -> str:
        return self._get("core/view/version")["version"]

    def wait_until_ready(self, attempts: int = 60, delay: float = 2.0) -> str:
        """Poll core/view/version until the daemon answers or attempts run out."""
        last: Exception | None = None
        for _ in range(attempts):
            try:
                return self.version()
            except (httpx.HTTPError, ZapError) as exc:
                last = exc
                time.sleep(delay)
        raise ZapError(f"ZAP daemon not ready after {attempts} attempts: {last}")

    # -- seeding the site tree ---------------------------------------------

    def access_url(self, url: str, follow_redirects: bool = False) -> None:
        """Make ZAP issue a GET for `url`, adding it to the site tree."""
        self._get(
            "core/action/accessUrl",
            url=url,
            followRedirects=str(follow_redirects).lower(),
        )

    def fetch_body(self, url: str) -> str:
        """GET ``url`` THROUGH ZAP and return its response body.

        Issued like any scan request — the Replacer-injected session cookie
        rides it — so the body reflects what the scan sees, which is why the auth
        gate and the session checks use it rather than a direct client. **Does not
        follow redirects**, matching :func:`auth._confirm_authenticated`: a live
        session returns the page with its logged-in indicator, a dead one returns
        the anonymous page or a redirect whose body carries no indicator — both
        read as logged out.
        """
        return self.send_and_read("GET", url)[1]

    def send_and_read(self, method: str, url: str) -> "tuple[str, str]":
        """Send one request THROUGH ZAP and return ``(status line, body)`` of it.

        ``core/action/sendRequest`` returns the exchange it made, so nothing is
        read back from the history, whose size grows with the scan. Redirects
        are not followed.

        :raises ZapError: if ZAP returns no exchange.
        """
        sent = self._get("core/action/sendRequest",
                         request=build_raw_request(method, url),
                         followRedirects="false").get("sendRequest") or []
        if not sent:
            raise ZapError(f"sendRequest for {method} {url} returned no exchange")
        return (sent[0].get("responseHeader", "").split("\r\n", 1)[0],
                sent[0].get("responseBody") or "")

    def send_request(self, request: str, follow_redirects: bool = False) -> None:
        """Send a raw HTTP request, registering non-GET routes in the site tree.

        ``accessUrl`` can only issue GETs, but most of Gitea's routes are POSTs.
        The request carries no CSRF token or body, so the target usually rejects
        it — expected and harmless: the point is to register the (method, URL)
        pair so the active scanner attacks it.
        """
        self._get(
            "core/action/sendRequest",
            request=request,
            followRedirects=str(follow_redirects).lower(),
        )

    def urls(self, base_url: str | None = None) -> list[str]:
        """Every node in ZAP's site tree: the coverage metric for Noir seeding.

        ZAP materialises the intermediate path nodes of a seeded URL too, so
        this counts reachable surface rather than requests issued.
        """
        return self._get("core/view/urls", baseurl=base_url)["urls"]

    def new_session(self, name: str = "") -> None:
        """Discard the current session: empty site tree, zero alerts.

        **Pass a ``name``.** An unnamed session is a *temporary* one and ZAP
        keeps its message store in the JVM heap, so every request and response of
        the scan accumulates there — the cause of every ZAP memory failure this
        project has recorded, and the reason three raised ceilings did not hold.
        A name is a path, and the store goes to disk. See
        :mod:`dast_orchestrator.adapters.zap_session`, which owns the path and its
        removal. The empty default remains because releasing a named session is
        exactly a switch back to a temporary one, and that call has nothing to
        name.


        **This is what makes a second scan on one daemon mean anything.** ZAP's
        site tree is cumulative and its alerts accumulate with it, so without a
        reset a run reports the union of itself and everything the daemon
        scanned before — a coverage number that is not about this run, and a
        passive queue that can take longer to drain than the scan took to
        produce it (observed: a 2-minute scan spending 25 minutes on an earlier
        run's backlog, then failing).

        Recreating the container also achieves this, and used to be the advice.
        This is the cheaper and more precise form: one API call, no lost daemon
        warm-up, and it works from inside a harness sheet, which cannot restart
        containers.

        It does **not** clear Replacer rules — verified against 2.17.0 — which is
        why :meth:`remove_replacer_rule` exists and why the scan driver calls it
        unconditionally. A session reset that left the previous run's auth cookie
        in place would be worse than no reset at all: the run would look clean
        and quietly scan authenticated.

        **Given its own, long timeout.** The work this call does is proportional
        to what the daemon has accumulated, not to anything about the run asking
        for it, so the default per-request timeout is the wrong ceiling: a daemon
        left up for days across many scans can take minutes to tear its session
        down. Failing on the very first call is the worst possible place: nothing
        has been measured yet and the whole run is lost to a housekeeping step.
        """
        self._get("core/action/newSession", name=name, overwrite="true",
                  timeout=SESSION_RESET_TIMEOUT_SECONDS)

    def restart_daemon(self, container: str,
                       timeout: float = 180.0) -> str:
        """Restart the daemon container and wait until it answers again.

        The honest reset. :meth:`new_session` empties what ZAP exposes through
        its API; this empties the process (a ``docker restart``, so the heap and
        site tree are new; the writable layer, and any on-disk session, persist).
        Use it between runs that are meant to be independent — see
        :data:`RESET_RESTART` for the measurement that makes the distinction
        load-bearing rather than theoretical.

        :returns: the version string the fresh daemon reports, so a caller can
            log that it really came back rather than assuming.
        :raises ZapError: if docker refuses, or the daemon does not answer
            within ``timeout``. Both are worth failing on: a run that continues
            against a daemon in an unknown state is exactly what this avoids.
        """
        import subprocess
        import time as _time

        try:
            done = subprocess.run(["docker", "restart", container],
                                  capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ZapError(f"could not restart {container}: {exc}") from exc
        if done.returncode != 0:
            raise ZapError(
                f"could not restart {container}: "
                f"{done.stderr.strip() or done.stdout.strip()}")

        deadline = _time.monotonic() + timeout
        last: Exception | None = None
        while _time.monotonic() < deadline:
            try:
                return self.version()
            except Exception as exc:          # noqa: BLE001 — any failure means "not yet"
                last = exc
                _time.sleep(3)
        raise ZapError(
            f"{container} restarted but did not answer within {timeout:.0f}s "
            f"({last})")

    def remove_replacer_rule(self, description: str) -> None:
        """Delete a Replacer rule if it is there; silent when it is not.

        Called before every scan, not only after an authenticated one, because
        the rule that has to go is the one the *previous* run left behind — and
        this run has no way to know what that was.
        """
        try:
            self._get("replacer/action/removeRule", description=description)
        except ZapError:
            # Not present is the normal case, and ZAP reports it as an error.
            pass

    def add_replacer_rule(self, description: str, header: str, value: str) -> None:
        """Make ZAP add/replace a request header on every request it sends.

        This is how the seeded session is injected: a ``Cookie`` rule carries the
        authenticated session cookie onto the spider's and active scanner's
        requests, so the whole scan runs as the logged-in user. ``REQ_HEADER``
        adds the header when a request lacks it, which is the common case here.
        """
        self._get(
            "replacer/action/addRule",
            description=description,
            enabled="true",
            matchType="REQ_HEADER",
            matchString=header,
            matchRegex="false",
            replacement=value,
        )

    def add_request_rewrite_rule(self, description: str, match: str,
                                 replacement: str, in_body: bool = False) -> None:
        """Rewrite a literal string in every request ZAP sends.

        In the header (``REQ_HEADER_STR``) it covers the request line, so it changes
        the URL a request reaches — for the browser spider too, whose requests ZAP
        proxies and which has no exclusion list of its own. ``in_body`` rewrites the
        request body instead (``REQ_BODY_STR``), e.g. a form's ``action=`` field.
        """
        self._get(
            "replacer/action/addRule",
            description=description,
            enabled="true",
            matchType="REQ_BODY_STR" if in_body else "REQ_HEADER_STR",
            matchString=match,
            matchRegex="false",
            replacement=replacement,
        )

    def replacer_rules(self) -> list[str]:
        """The descriptions of every Replacer rule the daemon holds."""
        return [str(r.get("description"))
                for r in self._get("replacer/view/rules")["rules"]]

    def spider_exclude_from_scan(self, regex: str) -> None:
        """Keep the traditional spider off URLs matching ``regex`` (a whole-URL match)."""
        self._get("spider/action/excludeFromScan", regex=regex)

    def ascan_exclude_from_scan(self, regex: str) -> None:
        """Keep the active scanner off URLs matching ``regex`` (a whole-URL match)."""
        self._get("ascan/action/excludeFromScan", regex=regex)

    # -- spider ------------------------------------------------------------

    # -- contexts ----------------------------------------------------------
    #
    # A context is the only place ZAP holds a *structural parameter*: a query
    # parameter it treats as part of a URL's identity rather than as a value.
    # See :mod:`dast_orchestrator.adapters.zap_context` for why that matters here and for
    # the export/edit/import recipe these five calls make up — ZAP 2.17's REST
    # API has no action that sets one directly (confirmed against the running
    # daemon rather than assumed).

    def new_context(self, name: str) -> str:
        return str(self._get("context/action/newContext", contextName=name)["contextId"])

    def remove_context(self, name: str) -> None:
        self._get("context/action/removeContext", contextName=name)

    def include_in_context(self, name: str, regex: str) -> None:
        self._get("context/action/includeInContext", contextName=name, regex=regex)

    def export_context(self, name: str, file_path: str) -> None:
        """Write a context to ``file_path`` **inside the daemon's filesystem**."""
        self._get("context/action/exportContext", contextName=name,
                  contextFile=file_path)

    def import_context(self, file_path: str) -> str:
        """Load a context XML from ``file_path`` inside the daemon; returns its id.

        Refuses with ``bad_external_data`` when a context of that name already
        exists, so the caller removes the old one first (confirmed against the
        live daemon; the error message says nothing about the collision).
        """
        return str(self._get("context/action/importContext",
                             contextFile=file_path)["contextId"])

    def contexts(self) -> list[str]:
        return list(self._get("context/view/contextList")["contextList"])

    def context(self, name: str) -> dict[str, Any]:
        return dict(self._get("context/view/context", contextName=name)["context"])

    def spider_scan(self, target: str, recurse: bool = True) -> str:
        data = self._get(
            "spider/action/scan",
            url=target,
            recurse=str(recurse).lower(),
        )
        return data["scan"]

    def spider_status(self, scan_id: str) -> int:
        return int(self._get("spider/view/status", scanId=scan_id)["status"])

    # -- the two browser-driven spiders ------------------------------------
    #
    # Both drive a real Firefox inside the ZAP container (verified present on
    # the pinned arm64 image; its `CanCreateUserNamespace` sandbox warning is
    # cosmetic and it crawls fine). They exist because the traditional spider
    # parses HTML and never executes it, so an application whose links are built
    # by JavaScript is invisible to it — e.g. WordPress, whose admin surface is
    # JS-driven.
    #
    # They are polled differently and the asymmetry is ZAP's, not a wrapper
    # choice: the AJAX spider is a singleton with a global status, while the
    # client spider returns a scan id like the traditional one.

    def ajax_spider_scan(self, target: str, in_scope: bool = True) -> None:
        """Start the AJAX spider. Returns nothing — it is a singleton."""
        self._get("ajaxSpider/action/scan", url=target,
                  inScope=str(in_scope).lower())

    def ajax_spider_running(self) -> bool:
        return self._get("ajaxSpider/view/status")["status"] == "running"

    def ajax_spider_results_count(self) -> int:
        return int(self._get("ajaxSpider/view/numberOfResults")["numberOfResults"])

    def ajax_spider_stop(self) -> None:
        self._get("ajaxSpider/action/stop")

    def client_spider_scan(self, target: str, max_depth: int = 5,
                           browsers: int = 1) -> str:
        """Start the client spider; returns its scan id.

        ZAP's own guidance since 2026 is that this, not the AJAX spider, is the
        option to reach for on a modern application: it finds more and scales
        better. It is kept selectable rather than substituted, because every
        recorded coverage number in this project was produced by the traditional
        spider and swapping it silently would move that baseline.
        """
        return self._get("clientSpider/action/scan", url=target,
                         maxCrawlDepth=str(max_depth),
                         numberOfBrowsers=str(browsers))["scan"]

    def client_spider_status(self, scan_id: str) -> int:
        return int(self._get("clientSpider/view/status", scanId=scan_id)["status"])

    def client_spider_stop(self, scan_id: str) -> None:
        self._get("clientSpider/action/stop", scanId=scan_id)

    # -- automation framework ----------------------------------------------

    def run_plan(self, file_path: str) -> str:
        """Start an Automation Framework plan; returns its plan id.

        ``filePath`` is a path **inside the daemon's own filesystem**, not on
        the host — the API loads the file itself. See
        :mod:`dast_orchestrator.adapters.zap_plan` for how it gets there.
        """
        return str(self._get("automation/action/runPlan", filePath=file_path)["planId"])

    def plan_progress(self, plan_id: str) -> dict[str, Any]:
        """A plan's progress: ``started``, ``finished``, ``info``/``warn``/``error``.

        ``finished`` is an empty string while it runs, which is the completion
        signal — there is no separate status field.
        """
        return self._get("automation/view/planProgress", planId=str(plan_id))

    # -- passive scan ------------------------------------------------------

    def pscan_records_to_scan(self) -> int:
        return int(
            self._get("pscan/view/recordsToScan")["recordsToScan"]
        )

    # -- active scan -------------------------------------------------------

    #: Bits of ZAP's ``ScannerParam`` injectable-target mask. ZAP's own default
    #: is ``QUERYSTRING|POSTDATA``; see :meth:`ascan_set_injectable_targets`.
    TARGET_QUERYSTRING = 1
    TARGET_POSTDATA = 2
    TARGET_COOKIE = 4
    TARGET_HTTPHEADERS = 8
    TARGET_URLPATH = 16

    def ascan_set_injectable_targets(self, mask: int) -> int:
        """Choose which parts of a request the active scanner may inject into.

        ZAP defaults to query string + post data, which on a Noir-seeded target
        leaves the scanner nothing to do: Noir extracts only *path* parameters
        from Gitea's chi routes (600 of them, no query or form params) and the
        seeded requests carry no query string and an empty body. Adding
        :data:`TARGET_URLPATH` turns those 600 statically-discovered parameters
        into real attack surface, and is where Gitea 1.16.0's documented
        traversal and open-redirect bugs are reached.

        :param mask: bitwise OR of the ``TARGET_*`` constants.
        :returns: the mask ZAP reports holding afterwards. Read back rather than
            assumed — a silently rejected value looks exactly like a scan that
            found nothing, which is the failure this method exists to prevent.
        """
        self._get("ascan/action/setOptionTargetParamsInjectable", Integer=mask)
        return self.ascan_injectable_targets()

    def ascan_injectable_targets(self) -> int:
        return int(
            self._get("ascan/view/optionTargetParamsInjectable")[
                "TargetParamsInjectable"
            ]
        )

    def ascan_set_add_query_param(self, enabled: bool) -> None:
        """Make ZAP append a synthetic query parameter to parameterless URLs.

        Off by default here, and deliberately so: it fabricates a parameter the
        application never declared, so any finding on it is a finding about a
        guessed input. Useful for reaching endpoints that accept a parameter
        nobody documented, but it must be reported as a distinct scan mode
        rather than mixed into a baseline.
        """
        self._get(
            "ascan/action/setOptionAddQueryParam", Boolean=str(enabled).lower()
        )

    def ascan_set_max_scan_duration(self, minutes: int) -> None:
        """Cap total active-scan wall time. :data:`config.NO_LIMIT` = unlimited."""
        self._get("ascan/action/setOptionMaxScanDurationInMins",
                  Integer=zap_unlimited(minutes))

    def ascan_set_max_rule_duration(self, minutes: int) -> None:
        """Cap per-rule wall time so a single slow plugin can't stall the scan."""
        self._get("ascan/action/setOptionMaxRuleDurationInMins",
                  Integer=zap_unlimited(minutes))

    def ascan_disable_scanners(self, ids: "list[str]") -> None:
        """Turn off specific active scan rules for the whole run.

        The lever for a rule that is *loud rather than informative*. Rule 10104
        (User Agent Fuzzer) raised 5268 of one run's 7295 alerts — 72% — while
        being Informational and reporting only that a response differed under a
        different User-Agent. It is also the main memory driver, because every
        one of those alerts keeps its request/response in the session, which is
        what pushed ZAP past the heap ceiling its Insights add-on shuts down at.
        """
        if ids:
            self._get("ascan/action/disableScanners", ids=",".join(str(i) for i in ids))

    #: Add-on quality ZAP itself assigns a rule. Only ``release`` is a rule the
    #: project stands behind; ``alpha`` and ``beta`` are explicitly work in
    #: progress, and ZAP's own default scan policy in the desktop UI leaves them
    #: out. A daemon inherits whatever the installed add-ons register, so
    #: nothing chooses them — which is how this pipeline ended up running an
    #: alpha rule (``100043``) that no ground-truth marker names and that took
    #: live heap from 1.2 GB to 6.7 GB.
    RELEASE_QUALITY = "release"

    def scanners(self) -> list[dict[str, Any]]:
        """Every active scan rule the daemon has, with id, name and quality."""
        return self._get("ascan/view/scanners")["scanners"]

    def installed_addons(self) -> list[dict[str, str]]:
        """Each installed add-on and its version, for the run's provenance.

        Rules live in add-ons, so "ZAP 2.17.0" does not identify the rule set a
        run used: two runs of the same image can differ if an add-on updated
        underneath them. This project pins every other tool by image digest or
        commit and had no equivalent for the scanner's own rules, which an add-on
        can update between two runs of the same image.
        """
        addons = self._get("autoupdate/view/installedAddons")["installedAddons"]
        return sorted(
            ({"id": a.get("id", ""), "version": a.get("version", "")}
             for a in addons),
            key=lambda a: a["id"],
        )

    def ascan_set_scanner_strength(self, plugin_id: str, strength: str) -> None:
        """How many payloads one active rule sends — its request-based limit.

        The only per-rule *work* ceiling ZAP exposes. There is no per-rule time
        limit in the API: ``MaxRuleDurationInMins`` is one global number, which
        is why :class:`dast_orchestrator.adapters.targets.ScanRule` has no
        ``max_minutes`` field to offer.
        """
        self._get("ascan/action/setScannerAttackStrength",
                  id=plugin_id, attackStrength=strength)

    def ascan_set_scanner_threshold(self, plugin_id: str, threshold: str) -> None:
        """How much evidence one active rule needs before it raises.

        Not a limit on work — a limit on what counts as a finding — so raising
        it changes the run's *results* rather than its cost, and a run that
        moves it is not comparable with one that did not.
        """
        self._get("ascan/action/setScannerAlertThreshold",
                  id=plugin_id, alertThreshold=threshold)

    def pscan_set_max_alerts_per_rule(self, maximum: int) -> None:
        """Cap how many alerts one *passive* rule may raise.

        :data:`config.NO_LIMIT` = unlimited, translated on the way out.


        ZAP's own baseline script sets this to 10, and **on this target it does
        not do what its name suggests**: the cap value did not change the maximum
        alerts a single rule produced. Whatever it counts, it is not "alerts per
        rule per run" here. Kept as a knob because it is ZAP's
        own supported lever, defaulted to 0, and always sent explicitly so the
        daemon's configuration matches what the run records.
        """
        self._get("pscan/action/setMaxAlertsPerRule", maxAlerts=maximum)

    def ascan_scan(self, target: str, recurse: bool = True) -> str:
        data = self._get(
            "ascan/action/scan",
            url=target,
            recurse=str(recurse).lower(),
        )
        return data["scan"]

    def ascan_status(self, scan_id: str) -> int:
        return int(self._get("ascan/view/status", scanId=scan_id)["status"])

    # -- alerts ------------------------------------------------------------

    #: Alerts per ``core/view/alerts`` page. ZAP serves every page by building each
    #: alert from the first up to the page's end, its stored exchange included, so
    #: every page re-reads all alerts before it: a small page makes a large scan
    #: quadratic, while the page bounds the response ZAP builds in its heap.
    ALERT_PAGE_SIZE = 75_000
    #: Seconds one page may take: a page building 134k alerts took 24 min. A timeout
    #: here discards a finished scan, whose artifacts are written only after
    #: collection, so it errs long.
    ALERT_PAGE_TIMEOUT = 3600.0
    #: The smallest page a page that failed in transport is retried at, by halving.
    ALERT_PAGE_FLOOR = 10_000

    def alerts(
        self,
        base_url: str | None = None,
        page_size: int = ALERT_PAGE_SIZE,
        timeout: float | None = ALERT_PAGE_TIMEOUT,
        on_retry: Callable[[int, int, Exception], None] | None = None,
    ) -> list[dict[str, Any]]:
        """Every alert ZAP holds for ``base_url``, fetched in pages.

        Each page goes out on a new connection. A page that fails in transport (ZAP
        closed the connection mid-body, a timeout) is asked again from the same
        position at half the size, down to :data:`ALERT_PAGE_FLOOR`; ZAP still holds
        the session, so nothing is lost but time.

        :param base_url: only alerts whose URL starts with this; every alert if ``None``.
        :param page_size: alerts per request; see :data:`ALERT_PAGE_SIZE`.
        :param timeout: read timeout per page, in seconds.
        :param on_retry: called as ``(start, new_page_size, error)`` before each retry.
        :returns: the alerts in ZAP's order, each alert id once; a page shorter than
            ``page_size`` ends the fetch.
        :raises httpx.TransportError: when a page at the floor fails too.
        """
        collected: list[dict[str, Any]] = []
        seen: set[str] = set()
        start = 0
        while True:
            try:
                with self._fresh_http() as http:
                    page = self._get(
                        "core/view/alerts", http=http, baseurl=base_url,
                        start=start, count=page_size, timeout=timeout,
                    )["alerts"]
            except httpx.TransportError as exc:
                if page_size <= self.ALERT_PAGE_FLOOR:
                    raise
                page_size = max(self.ALERT_PAGE_FLOOR, page_size // 2)
                if on_retry is not None:
                    on_retry(start, page_size, exc)
                continue
            # ZAP's second page starts one alert early, repeating the first page's last.
            for alert in page:
                alert_id = alert.get("id")
                if alert_id is not None and alert_id in seen:
                    continue
                if alert_id is not None:
                    seen.add(alert_id)
                collected.append(alert)
            if len(page) < page_size:
                return collected
            start += page_size

    #: Message ids per ``messagesById`` call. The view takes a comma-separated
    #: list and returns each exchange in full, so the batch size trades one
    #: round trip against one response holding that many response bodies.
    #: 50 x ~16 KB is a comfortable megabyte.
    MESSAGE_BATCH = 50

    def messages_by_id(
        self,
        ids: "list[str]",
        timeout: float | None = 300.0,
    ) -> dict[str, dict[str, Any]]:
        """Fetch the HTTP exchanges behind a set of alerts, keyed by message id.

        **Only the ids asked for.** ``core/view/messages`` would page the whole
        History table, which on a 45-minute active scan is tens of thousands of
        exchanges — every payload the scanner ever sent, each carrying a full
        response body — to recover the ~2000 that back an alert. ``messagesById``
        asks for exactly the referenced set, so the sidecar's size tracks the
        findings rather than the scanning effort.

        Preferred over generating a ``traditional-json-plus`` report, which
        returns the same exchanges: the report writes a file inside the ZAP
        container, so collecting it needs a mounted directory or a ``docker cp``,
        and the driver reaches ZAP over the API from the host precisely so it
        needs neither.

        :param ids: ZAP message ids, as strings or ints; duplicates and blanks
            are ignored.
        :returns: ``{message id: message dict}`` with ZAP's own field names
            (``requestHeader``, ``requestBody``, ``responseHeader``,
            ``responseBody``, ``rtt``, ...). Ids ZAP no longer holds are simply
            absent — a session that dropped a message must not fail the run.
        """
        wanted = [str(i) for i in dict.fromkeys(ids) if str(i).strip()]
        collected: dict[str, dict[str, Any]] = {}
        for start in range(0, len(wanted), self.MESSAGE_BATCH):
            batch = wanted[start:start + self.MESSAGE_BATCH]
            try:
                page = self._get(
                    "core/view/messagesById",
                    ids=",".join(batch),
                    timeout=timeout,
                )["messagesById"]
            except ZapError as exc:
                # One unfetchable batch must not cost the other forty. The
                # missing ids are visible to the caller as absent keys, which is
                # the honest form: a message we could not read and one that was
                # never referenced look different.
                ui.warn(f"could not fetch messages {batch[0]}..{batch[-1]}: {exc}")
                continue
            for message in page:
                mid = str(message.get("id") or "")
                if mid:
                    collected[mid] = message
        return collected

    def poll_until_complete(
        self,
        status_fn: Any,
        scan_id: str,
        label: str,
        delay: float = 3.0,
        max_wait: float = 900.0,
        heartbeat: float = 300.0,
        step: int = 5,
        on_progress: Any = None,
        on_poll: Any = None,
    ) -> str:
        """Poll a ``*_status`` function until it reports 100.

        **Returns why polling stopped; never raises for a scan that ended badly.**
        A 45-minute active scan must not be discarded because its status endpoint
        stopped answering — which is exactly what an Insights heap-shutdown *after*
        the scan already raised its alerts causes: the status call 400s and the
        driver would otherwise abort, losing a completed scan before its alerts
        were fetched. The caller
        now goes on to collect whatever ZAP still has and records how the stage
        ended, so a truncated run is *reported* rather than either lost or
        silently passed off as clean.

        :param status_fn: bound method returning percent complete.
        :param label: name used in progress output.
        :param step: percent between progress lines; ``0`` reports on the
            heartbeat only. A 45-minute scan polled every 3s crawls through every
            integer, so printing on *change* still yields ~100 lines; a step of 5
            gives 20, and clock-only gives one line per ``heartbeat``.
        :param heartbeat: seconds after which a stalled percentage is reprinted,
            so a long plateau still shows the run is alive.
        :param on_poll: called with no arguments after each poll that is not the
            last — the active scan's session check rides it.
        :returns: :data:`POLL_COMPLETE`, :data:`POLL_TIMEOUT` or
            :data:`POLL_UNAVAILABLE`.
        """
        waited = 0.0
        pct = 0
        # A step, not every change: a 45-minute scan crawls through every
        # integer, and one line per percent is still 100 lines of nothing. At a
        # terminal the same updates redraw one line with a bar and an ETA; see
        # :class:`ui.Progress` for why the redirected rendering is the one whose
        # shape is fixed.
        #
        # ``on_progress`` lets a caller drive its *own* bar with this poll instead
        # — the crawl phase spans several spiders on one bar, and each spider's
        # poll reports into a segment of it. When it is given, this makes no bar
        # of its own and each poll calls ``on_progress(pct, waited)``.
        progress = None if on_progress else ui.Progress(
            label, step=step, heartbeat=heartbeat)
        while waited <= max_wait:
            try:
                pct = status_fn(scan_id)
            except ZapError as exc:
                if progress:
                    progress.close(f"status unavailable after {waited:.0f}s: {exc}")
                return POLL_UNAVAILABLE
            (on_progress or progress.update)(pct, waited)
            if pct >= 100:
                if progress:
                    progress.close()
                return POLL_COMPLETE
            if on_poll:
                on_poll()
            time.sleep(delay)
            waited += delay
        if progress:
            progress.close(f"still at {pct}% when the {max_wait:.0f}s poll budget "
                           "ran out")
        return POLL_TIMEOUT
