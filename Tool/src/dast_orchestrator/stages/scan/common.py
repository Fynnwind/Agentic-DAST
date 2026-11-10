"""Constants and phase helpers for the scan stage.

The bottom of the ``scan`` package: the rule/injectable/spider/ZAP-mode
constants and defaults, and the leaf steps :func:`run_scan` drives — seeding
(:func:`seed_zap`), the spiders (:func:`run_spiders`), Noir extraction
(:func:`run_noir_stage`), the health check and the scan config. Depends on
nothing else in the package.
"""
from __future__ import annotations
import os
import time
from pathlib import Path
from typing import Any, Collection
from dast_orchestrator.foundation import config
from dast_orchestrator.adapters import auth
from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters.noir_runner import SeedRequest
from dast_orchestrator.adapters import zap_client
from dast_orchestrator.adapters.zap_client import ZapClient, ZapError, build_raw_request

REPO_ROOT = Path(__file__).resolve().parents[4]
#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()
#: Fallback for direct callers of :func:`run_scan`; ``main`` derives the source
#: tree from the selected target instead. Sourced from the default target so no
#: target name is hard-coded here, through the one configurable targets reader.
DEFAULT_SOURCE_DIR = targets.target_source(targets.DEFAULT)


def source_is_foreign(source_dir: "Path | str", target_name: str) -> bool:
    """True when ``source_dir`` is not inside ``targets/<target_name>/``.

    A Noir-source override that points outside the target's own directory is
    almost always a stale ``SCAN_NOIR_SOURCE_DIR`` in the shell — a real environment
    variable outranks the target's ``source_dir`` by design — which silently
    analyses one target's code under another target's run id. Relative paths are
    resolved against the current directory, the same way the scan uses them.
    """
    target_root = (targets.TARGETS_DIR / target_name).resolve()
    resolved = Path(source_dir)
    if not resolved.is_absolute():
        resolved = Path.cwd() / resolved
    return not resolved.resolve().is_relative_to(target_root)

#: Query string + post data + URL path. ZAP's own default omits URL path, which
#: leaves every Noir-seeded endpoint uninjectable — the measured cause of a run
#: producing 2 active-scanner alerts out of 1566. See
#: :meth:`ZapClient.ascan_set_injectable_targets`.
DEFAULT_INJECTABLE_TARGETS = (
    ZapClient.TARGET_QUERYSTRING | ZapClient.TARGET_POSTDATA | ZapClient.TARGET_URLPATH
)

#: Active rules switched off for every run — operational exclusions (a rule this
#: pipeline cannot afford to run), not claims that they find nothing; the classes
#: they cover are unexercised, and the heap measurements behind each are in
#: DECISIONS.md. Override with ``--disable-rule`` / ``--keep-rule``.
#:
#: - ``10104`` (User Agent Fuzzer): Informational, dominated one run's alert volume
#:   and drove ZAP past its heap ceiling.
#: - ``50000`` + ``100043`` (the GraalJS active-scan-script pair): both exhaust the
#:   heap; disabling only the ``50000`` dispatcher leaves the heavier ``100043`` live.
DEFAULT_DISABLED_RULES = ("10104", "50000", "100043")

#: Ceiling on alerts from any single *passive* rule. Unlimited by default
#: (:data:`config.NO_LIMIT`, ``-1``; ZAP's API wants ``0``, translated by
#: :func:`~dast_orchestrator.adapters.zap_client.zap_unlimited`). Unlike
#: :data:`DEFAULT_DISABLED_RULES` (a memory control), a passive cap removes the
#: population the pipeline works on — rule ``10031`` (potential XSS) supplies most of
#: the deterministic arm's rescan flags and the one tool-confirmed finding — so keep
#: it for a bounded CI report, not for a run whose numbers are the result.
#: The Replacer rule carrying the seeded session cookie. A constant
#: because an authenticated run writes it and *every* run removes it —
#: the two references must be the same string or a stale cookie survives
#: into a later unauthenticated run, which would look clean and be wrong.
AUTH_REPLACER_RULE = "dast-auth-session"
#: Prefixes of the Replacer rules this tool writes per run. Every rule carrying one is
#: removed at setup, whatever target wrote it: ZAP keeps Replacer rules across a daemon
#: restart. ZAP's own rules carry none and are left alone.
SCAN_HEADER_RULE_PREFIX = "scan-header-"
LOGOUT_RULE_PREFIX = "dast-logout-block-"
OWN_RULE_PREFIXES = (SCAN_HEADER_RULE_PREFIX, LOGOUT_RULE_PREFIX)
#: What a logout marker is rewritten to in a request ZAP sends: a route the target
#: does not serve, and one a reader of the stored exchanges recognises.
LOGOUT_REWRITE_SUFFIX = "-excluded-by-dast"
#: Seconds between session checks while the active scan runs.
SESSION_CHECK_INTERVAL_SECONDS = 300.0
#: Tries for a check at a phase boundary, and the wait between them: a timed-out check
#: says nothing about the session (a busy target, PHP's per-session lock).
SESSION_CHECK_ATTEMPTS = 3
SESSION_CHECK_RETRY_SECONDS = 30.0


#: The two marker forms beyond a plain URL substring (see ``AuthProfile.destructive_markers``).
POST_MARKER_PREFIX = "POST "
BODY_MARKER_PREFIX = "body:"


def marker_kind(marker: str) -> "tuple[str, str]":
    """Split a route marker into ``(kind, text)``.

    ``kind`` is ``"post"`` (a POST to exactly the path ``text``), ``"body"`` (``text``
    in a request body) or ``"url"`` (``text`` anywhere in the URL, any method).
    """
    if marker.startswith(POST_MARKER_PREFIX):
        return "post", marker[len(POST_MARKER_PREFIX):].strip()
    if marker.startswith(BODY_MARKER_PREFIX):
        return "body", marker[len(BODY_MARKER_PREFIX):]
    return "url", marker


def logout_regex(marker: str) -> str:
    """The whole-URL Java regex ZAP's exclusion lists take for a literal ``marker``."""
    return rf".*\Q{marker}\E.*"


def drop_logout_seeds(seeds: "list[SeedRequest]",
                      markers: "tuple[str, ...]") -> "tuple[list[SeedRequest], int]":
    """Remove every seed a route marker blocks: a URL marker anywhere in its URL, a
    POST marker when it is a POST to exactly that path. Seeds carry no body.

    :returns: ``(kept seeds, number dropped)``.
    """
    from urllib.parse import urlparse

    def blocked(seed: SeedRequest) -> bool:
        for marker in markers:
            kind, text = marker_kind(marker)
            if kind == "url" and text in seed.url:
                return True
            if (kind == "post" and seed.method == "POST"
                    and urlparse(seed.url).path == text):
                return True
        return False

    kept = [s for s in seeds if not blocked(s)]
    return kept, len(seeds) - len(kept)


DEFAULT_MAX_ALERTS_PER_RULE = config.NO_LIMIT

#: ZAP's per-rule wall-clock ceiling when nothing else says. One number for
#: **every** rule — ZAP exposes no per-rule timer — which is why a target can
#: only move the whole ceiling, never one rule's.
DEFAULT_MAX_RULE_MINUTES = 1


def resolve_rule_minutes(flag: "int | None",
                         target: "targets.Target | None") -> int:
    """Per-rule ceiling: flag, then env, then the target, then the default.

    **Most specific to the invocation wins, and the target is not the most
    specific.** A harness sheet sets ``SCAN_ZAP_MAX_RULE_MINUTES`` to hold the number
    fixed across every row, and a target that outranked it could quietly make
    two rows of one experiment incomparable. So a sheet keeps control by setting
    it, and hands control to the targets by omitting it — which is the useful
    behaviour in both directions.

    The flag's own default is ``None`` precisely so these three can be told
    apart; with an env-derived default there is no way to distinguish "the user
    asked for 5" from "the environment happened to hold 5".
    """
    if flag is not None:
        return flag
    from_env = os.getenv("SCAN_ZAP_MAX_RULE_MINUTES")
    if from_env:
        return int(from_env)
    if target is not None and target.max_rule_minutes is not None:
        return target.max_rule_minutes
    return DEFAULT_MAX_RULE_MINUTES

INJECTABLE_TARGET_NAMES = (
    (ZapClient.TARGET_QUERYSTRING, "query-string"),
    (ZapClient.TARGET_POSTDATA, "post-data"),
    (ZapClient.TARGET_COOKIE, "cookie"),
    (ZapClient.TARGET_HTTPHEADERS, "http-headers"),
    (ZapClient.TARGET_URLPATH, "url-path"),
)


def describe_injectable_targets(mask: int) -> str:
    """Render an injectable-target bitmask as ``"query-string, url-path"``."""
    names = [name for bit, name in INJECTABLE_TARGET_NAMES if mask & bit]
    return ", ".join(names) if names else "none"


def _wait_for_passive_scan(zap: ZapClient, delay: float = 2.0,
                           max_wait: float = 120.0) -> int:
    """Drain the passive-scan queue. Returns how deep it was when we arrived.

    The depth is the point: "0 records left, 0.0s" reads like a stage that was
    skipped, when it usually means passive scanning kept pace with the spider.
    Reporting what was queued distinguishes the two.
    """
    waited = 0.0
    queued = zap.pscan_records_to_scan()
    if queued:
        ui.step(f"[passive] {queued} records queued")
    while waited <= max_wait:
        remaining = zap.pscan_records_to_scan()
        if remaining and remaining != queued:
            ui.step(f"[passive] {remaining} records left")
        if remaining == 0:
            return queued
        time.sleep(delay)
        waited += delay
    ui.warn("passive queue not empty within budget; continuing anyway")
    return queued


def seed_zap(zap: ZapClient, seeds: list[SeedRequest],
             required: "Collection[SeedRequest]" = ()) -> int:
    """Push seed requests into ZAP's site tree. Returns the number accepted.

    GETs go through `core/action/accessUrl`; everything else needs a raw
    request via `core/action/sendRequest`, which is the only way to register a
    non-GET node. Individual failures are logged and skipped rather than
    aborting: a route Noir inferred may simply not be reachable, and losing the
    whole run over one 400 would make the job flaky in CI.

    :param required: seeds the run is meaningless without (a ceiling's oracle
        sinks). One of these refused raises instead of being skipped.
    :raises ZapError: when ZAP refuses a ``required`` seed.
    """
    accepted = 0
    failed = 0
    for index, seed in enumerate(seeds, start=1):
        try:
            if seed.method == "GET":
                zap.access_url(seed.url)
            else:
                zap.send_request(build_raw_request(seed.method, seed.url))
            accepted += 1
        except ZapError as exc:
            if seed in required:
                raise ZapError(
                    f"ZAP refused the oracle seed {seed.method} {seed.url}: {exc}. "
                    "A ceiling run without its sink in the tree measures no "
                    "ceiling, so the scan stops here."
                ) from exc
            failed += 1
            if failed <= 5:  # keep the log readable; the count is reported below
                ui.warn(f"[seed] skipped {seed.method} {seed.url}: {exc}")
        if index % 50 == 0:
            ui.step(f"[seed] {index}/{len(seeds)}")
    ui.found(f"{accepted} seeded, {failed} skipped")
    return accepted


#: The crawlers this stage can run, in ``--spider`` order. ``traditional`` parses HTML
#: without executing it (blind to JS-built links, e.g. WordPress's admin surface); the
#: other two drive a real browser. ``traditional`` belongs in every default — every
#: recorded coverage number was produced by it alone, so dropping it moves the baseline.
#:
#: How ZAP is driven. ``rest`` (default, proven): the sequence is explicit here and the
#: run records exactly what it did. ``af`` hands crawling/scanning to an Automation
#: Framework plan (how ZAP is usually driven in CI) — not a comparable run, so the mode
#: is in the config digest and stated in the log.
ZAP_MODE_REST = "rest"
ZAP_MODE_AF = "af"
ZAP_MODES = (ZAP_MODE_REST, ZAP_MODE_AF)

#: The daemon's container name, needed only to deliver a plan into it.
DEFAULT_ZAP_CONTAINER = "dast-zap"

SPIDERS = ("traditional", "ajax", "client")
DEFAULT_SPIDERS = ("traditional",)


def parse_spiders(value: "str | Iterable[str]") -> tuple[str, ...]:
    """Parse ``traditional,client`` into an ordered, de-duplicated tuple.

    Order is kept because it is meaningful: each crawler adds to the site tree
    the previous ones built, so running the cheap HTML pass first means the
    browser crawlers start from a populated tree rather than the root.
    """
    names = ([n.strip() for n in value.split(",")] if isinstance(value, str)
             else [str(n).strip() for n in value])
    chosen: list[str] = []
    for name in names:
        if not name:
            continue
        if name not in SPIDERS:
            raise ValueError(
                f"unknown spider {name!r}; choose from {', '.join(SPIDERS)}")
        if name not in chosen:
            chosen.append(name)
    return tuple(chosen) or DEFAULT_SPIDERS


#: Consecutive polls with no new URL before the client spider is called done.
#: At :data:`CLIENT_POLL_SECONDS` apart this is a minute of silence, which is
#: long enough not to cut a slow page load short and short enough not to waste
#: the budget on a crawl that has plainly finished.
CLIENT_STALL_POLLS = 6
CLIENT_POLL_SECONDS = 10.0


def _poll_client_spider(zap: ZapClient, target_url: str, scan_id: str,
                        minutes: int, on_progress: Any = None,
                        emit: Any = None) -> str:
    """Wait for the client spider, which does not report completion usefully.

    Its ``status`` is **not** a monotonic progress percentage: observed live it
    climbs and then falls back — 93, 83, 77, 72 — because it is a ratio of done
    to queued work and discovering new work moves the denominator. Waiting for
    100 the way the traditional spider's poller does therefore hangs until a
    timeout, which is exactly what it did on the first run with this crawler
    enabled.

    ``status`` is also the only view the component exposes, so there is no
    cleaner signal to switch to. What is observable is the thing actually wanted:
    the crawler is done when it stops finding URLs. So this waits for the site
    tree to stop growing, with a wall-clock cap behind it, and reports which of
    the two ended it — a stall and a timeout are different results and the
    artifact should not conflate them.
    """
    started = time.monotonic()
    deadline = started + minutes * 60
    last_size, stalled = -1, 0
    while time.monotonic() < deadline:
        # Progress is time, not status: `status` is not monotonic, so the honest
        # thing to show for the client spider's segment of the crawl bar is how
        # much of its wall-clock cap has elapsed.
        if on_progress:
            on_progress((time.monotonic() - started) / (minutes * 60))
        if zap.client_spider_status(scan_id) >= 100:
            return "complete"
        size = len(zap.urls(base_url=target_url))
        if size == last_size:
            stalled += 1
            if stalled >= CLIENT_STALL_POLLS:
                zap.client_spider_stop(scan_id)
                return "client-stalled"
        else:
            last_size, stalled = size, 0
        time.sleep(CLIENT_POLL_SECONDS)
    zap.client_spider_stop(scan_id)
    (emit or ui.warn)(f"client spider stopped at its {minutes}-minute cap; the "
                      "tree is what it found by then")
    return "client-time-capped"


def run_spiders(zap: ZapClient, target_url: str, spiders: "tuple[str, ...]",
                browser_minutes: int = 5) -> dict[str, Any]:
    """Run each requested crawler in order, recording what each left behind.

    Returns the site-tree size after each one, so a sheet can say what the
    browser crawlers actually bought over the HTML pass — the measurement that
    decides whether they are worth their minutes on a given target.

    The AJAX spider is bounded by wall clock here rather than by ZAP: it is a
    singleton with no duration option on this API surface, and left alone it
    keeps finding variations of the same page for as long as it is allowed to.
    """
    found: dict[str, Any] = {}
    outcome = "complete"

    # One bar for the WHOLE spider stage, not one per spider: each configured
    # spider is an equal segment of it, so a run with `traditional,client` shows
    # a bar that is genuinely half-done when the traditional pass finishes rather
    # than one that hits 100% and then keeps spidering with no indicator. Within a
    # segment, the traditional spider reports a real percentage; the browser
    # spiders, which expose no honest percentage, advance on elapsed-over-cap.
    # Per-spider notes go through the bar so they do not desync its fixed header.
    n = len(spiders)
    bar = ui.Progress("spider", step=0)
    started = time.monotonic()

    def seg(index: int, sub: float) -> None:
        frac = (index + min(max(sub, 0.0), 1.0)) / n
        bar.update(int(frac * 100), time.monotonic() - started)

    def note(index: int, message: str) -> None:
        bar.line(message, int((index + 1) / n * 100), time.monotonic() - started)

    for i, name in enumerate(spiders):
        if name == "traditional":
            scan_id = zap.spider_scan(target_url)
            outcome = zap.poll_until_complete(
                zap.spider_status, scan_id, "spider",
                on_progress=lambda pct, _w, i=i: seg(i, pct / 100))
        elif name == "ajax":
            zap.ajax_spider_scan(target_url)
            deadline = time.monotonic() + browser_minutes * 60
            while zap.ajax_spider_running():
                seg(i, 1 - (deadline - time.monotonic()) / (browser_minutes * 60))
                if time.monotonic() > deadline:
                    zap.ajax_spider_stop()
                    outcome = "ajax-time-capped"
                    note(i, f"! ajax spider stopped at its {browser_minutes}-minute "
                            "cap; the tree is what it found by then")
                    break
                time.sleep(5)
            note(i, f"[ajax] {zap.ajax_spider_results_count()} result(s)")
        elif name == "client":
            scan_id = zap.client_spider_scan(target_url)
            outcome = _poll_client_spider(
                zap, target_url, scan_id, minutes=browser_minutes,
                on_progress=lambda sub, i=i: seg(i, sub),
                emit=lambda m, i=i: note(i, "! " + m))
        found[name] = len(zap.urls(base_url=target_url))
        note(i, f"[{name}] site tree now {found[name]} URLs")

    bar.close()
    found["outcome"] = outcome
    return found


#: Below this share of its cap, an active scan that raised nothing is treated as
#: suspect rather than fast. Deliberately generous — a genuinely small target CAN
#: finish quickly — so the assertion only fires when the scan was *both* very
#: short and completely silent, which is the shape of a no-op rather than of an
#: easy target.
SUSPECT_SCAN_FRACTION = 0.10


def scan_health(seconds: float, cap_minutes: int, active_alerts: int,
                urls_in_tree: int) -> "str | None":
    """Why this active scan looks like it did not happen, or ``None``.

    Nothing in ZAP's own reporting distinguishes a scan that finished because it
    was done from one that finished because it did nothing: a 109-second scan
    over 223 URLs that raised zero active alerts reported exactly the same
    ``poll_outcome: complete``, ``truncated_by_cap: false`` as the 1,364-second
    run over the same tree that raised 123. That silence cost a baseline, and the
    cause (a daemon left degraded by the previous run) took three runs to find.

    So the pipeline asserts what ZAP will not: a scan that used almost none of
    its budget AND found nothing active, on a tree with something to attack, is
    reported as suspect. It is a warning and never an error — a small target can
    legitimately finish fast, and refusing to write a run would throw away the
    passive findings that are still valid.
    """
    if not cap_minutes or urls_in_tree <= 0:
        return None
    if active_alerts > 0:
        return None
    share = seconds / (cap_minutes * 60)
    if share >= SUSPECT_SCAN_FRACTION:
        return None
    return (
        f"the active scan used {share:.1%} of its {cap_minutes}-minute cap "
        f"({seconds:.0f}s) over {urls_in_tree} URLs and raised NO "
        "active-scanner alerts. ZAP reports this identically to a scan that "
        "finished because it was done. Treat the run as suspect: check that the "
        "tree carries parameters worth attacking."
    )


def run_noir_stage(
    source_dir: Path,
    target_url: str,
    noir_image: str,
    path_vars: dict[str, str],
    timestamp: str,
    run_id: str = "",
    data_dir: "Path | None" = None,
    ignore_technologies: "tuple[str, ...]" = (),
) -> tuple[list[SeedRequest], dict[str, object]]:
    """Run Noir, write both artifacts, and return the seeds plus run metadata."""
    ui.step(f"{noir_image} over {source_dir}")
    raw = noir_runner.run_noir(source_dir, image=noir_image)
    endpoints = noir_runner.parse_endpoints(raw, ignore_technologies)
    seeds = noir_runner.to_seed_requests(endpoints, target_url, path_vars)

    raw_path, ai_path, seed_map_path = noir_runner.write_artifacts(
        raw, endpoints, source_dir, data_dir or DATA_DIR, timestamp, target_url,
        path_vars, run_id or timestamp,
    )
    ui.found(f"{len(endpoints)} HTTP endpoints → {len(seeds)} unique seed requests")
    metadata: dict[str, object] = {
        "artifacts": [raw_path.name, ai_path.name, seed_map_path.name],
        "image": noir_image,
        "source_dir": str(source_dir),
        "http_endpoints": len(endpoints),
        "seed_requests": len(seeds),
        "endpoint_inventory": raw_path.name,
        "ai_context": ai_path.name,
        "seed_map": seed_map_path.name,
    }
    return seeds, metadata


def scan_config(**values: Any) -> dict[str, Any]:
    """The scan settings that go into the run id's configuration digest.

    A pass-through with one job: to be the single, named list of *what counts as
    a different scan*. The ZAP daemon's address is deliberately absent — moving
    the daemon does not make it a different experiment — and so is every
    credential.

    The rule for adding a knob here is whether two runs differing only in it
    should be separate experiments. If yes it belongs; if no it does not, and
    leaving it out is what keeps a run's name stable across incidental changes.
    """
    return values




__all__ = [
    'REPO_ROOT',
    'DATA_DIR',
    'DEFAULT_SOURCE_DIR',
    'source_is_foreign',
    'DEFAULT_INJECTABLE_TARGETS',
    'DEFAULT_DISABLED_RULES',
    'AUTH_REPLACER_RULE',
    'SCAN_HEADER_RULE_PREFIX',
    'LOGOUT_RULE_PREFIX',
    'OWN_RULE_PREFIXES',
    'LOGOUT_REWRITE_SUFFIX',
    'SESSION_CHECK_INTERVAL_SECONDS',
    'SESSION_CHECK_ATTEMPTS',
    'SESSION_CHECK_RETRY_SECONDS',
    'POST_MARKER_PREFIX',
    'BODY_MARKER_PREFIX',
    'marker_kind',
    'logout_regex',
    'drop_logout_seeds',
    'DEFAULT_MAX_ALERTS_PER_RULE',
    'DEFAULT_MAX_RULE_MINUTES',
    'resolve_rule_minutes',
    'INJECTABLE_TARGET_NAMES',
    'describe_injectable_targets',
    '_wait_for_passive_scan',
    'seed_zap',
    'ZAP_MODE_REST',
    'ZAP_MODE_AF',
    'ZAP_MODES',
    'DEFAULT_ZAP_CONTAINER',
    'SPIDERS',
    'DEFAULT_SPIDERS',
    'parse_spiders',
    'CLIENT_STALL_POLLS',
    'CLIENT_POLL_SECONDS',
    '_poll_client_spider',
    'run_spiders',
    'SUSPECT_SCAN_FRACTION',
    'scan_health',
    'run_noir_stage',
    'scan_config',
]
