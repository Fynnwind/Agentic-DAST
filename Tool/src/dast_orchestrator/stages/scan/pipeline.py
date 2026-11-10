"""The scan pipeline: :func:`run_scan`.

Noir static extraction seeds ZAP\'s site tree, then a bounded spider and active
scan run, and the run\'s artifacts are written to ``data/``. One orchestration
function over the phases in :mod:`~dast_orchestrator.stages.scan.common`.
"""
from __future__ import annotations
import json
import subprocess
import time
import httpx
from urllib.parse import urlparse
from pathlib import Path
from dataclasses import dataclass
from typing import Any
from dast_orchestrator.foundation import config
from dast_orchestrator.adapters import zap_context
from dast_orchestrator.adapters import zap_session
from dast_orchestrator.adapters import zap_plan
from dast_orchestrator.adapters import auth
from dast_orchestrator.foundation import metrics as run_metrics
from dast_orchestrator.context import evidence
from dast_orchestrator.adapters import noir_runner
from dast_orchestrator.foundation import redaction
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui
from dast_orchestrator.adapters.noir_runner import SeedRequest
from dast_orchestrator.adapters import zap_client
from dast_orchestrator.adapters.zap_client import (
    ZapClient,
    ZapError,
    count_alert_sources,
)
from .common import *



@dataclass
class _ZapSetup:
    """What configuring the daemon produced and the rest of the scan reads."""
    version: str
    addon_versions: list
    applied_targets: int
    disabled_rules: "tuple[str, ...]"
    context_info: dict


def _configure_zap(
    zap: ZapClient, *, target_url: str, timestamp: str, zap_container: str,
    zap_mode: str,
    plan_path: "Path | None", plan_digest: str, zap_addr: str,
    structural_parameters: "tuple[str, ...]", data_dir: Path, run_id: str,
    max_alerts_per_rule: int, max_scan_minutes: int, max_rule_minutes: int,
    scan_rules: "tuple[targets.ScanRule, ...]", disabled_rules: "tuple[str, ...]",
    auth_session: "object | None", scan_headers: dict, injectable_targets: int,
    add_query_param: bool, auth_profile: "object | None" = None,
    route_markers: "tuple[str, ...]" = (),
) -> "_ZapSetup":
    """Restart the daemon, open a named session, and set every scan-wide option
    before a request is issued — the "ZAP setup" phase of :func:`run_scan`,
    extracted verbatim. Returns what the later phases read back."""
    setup = ui.open_phase("ZAP setup")
    # RESTART FIRST, THEN WAIT. Every run restarts the daemon — a session
    # reset demonstrably did not reclaim everything (three WordPress scans at
    # one digest gave 84 / 123 / ZERO active alerts, the last after a 30-min
    # Gitea scan peaked at 10.4 GB in the same daemon, all reporting
    # `complete`), so a restart is the only honest fresh start.
    #
    # Restart before probing for readiness, not after: a daemon that died
    # during the previous row is exactly what a restart is for, and waiting
    # on the corpse first means the row fails on the run before it — an OOM in
    # one row otherwise takes the next row down when it waits on the dead daemon.
    # Nothing is lost by reordering: a restart discards the daemon's state either
    # way.
    fresh = zap.restart_daemon(zap_container)
    ui.item("daemon", f"restarted — ZAP {fresh}, nothing carried over")
    version = zap.wait_until_ready()
    ui.item("driving mode",
            "REST API"
            if zap_mode == ZAP_MODE_REST else
            f"Automation Framework plan — {plan_path.name} "
            f"(sha256 {plan_digest[:12]}…)")
    ui.item("ZAP address", zap_addr)
    ui.item("ZAP version", version)
    # RULES LIVE IN ADD-ONS, so "ZAP 2.17.0" does not identify the rule set
    # a run used — two runs of the same image differ if an add-on updated
    # under them, and this daemon's log shows exactly that happening across
    # one session (`retire` 0.63.0 -> 0.65.0, `webdriverlinux` 215 -> 221).
    # Every other tool in this pipeline is pinned by image digest or commit;
    # this is the scanner's own equivalent, and without it a stored run
    # cannot say which rules produced it.
    try:
        addon_versions = zap.installed_addons()
    except ZapError as exc:
        ui.warn(f"could not read installed add-on versions: {exc}")
        addon_versions = []
    ui.item("ZAP add-ons", f"{len(addon_versions)} installed, versions "
                           "recorded in run-metrics")
    ui.item("target address", target_url)

    # A NAMED session on top of the fresh daemon, and that is the whole
    # memory story — not a reset (the restart already did that), but *where
    # ZAP stores this run's messages*. An unnamed session keeps its message
    # store in the heap; this run sends >100k messages and they accumulated
    # there until ZAP's own Insights add-on shut the daemon down at 96% heap.
    # Naming the session puts the store on disk instead. `zap_session.discard`
    # at the end removes the run's own directory, so a long-lived daemon does
    # not keep a multi-gigabyte session per scan. See `zap_session` for the
    # measurement and the four earlier attempts that raised ceilings instead.
    # No log line: the restart above already reported the clean start, and
    # this is plumbing behind it, not a step a reader acts on.
    session_file = zap_session.prepare(run_id or timestamp, zap_container)
    zap.new_session(session_file)
    zap.remove_replacer_rule(AUTH_REPLACER_RULE)

    # Immediately after the reset (which clears every context) and before a
    # single request is seeded, so the first URL already lands in a tree
    # that splits on this target's routing parameters. A structural
    # parameter changes what the scan CONTAINS — see
    # `dast_orchestrator.adapters.zap_context` — so it is in the configuration digest
    # and a failure here stops the run rather than quietly producing a
    # differently-shaped corpus under the same name.
    context_info: dict[str, Any] = {}
    if structural_parameters:
        try:
            context_info = zap_context.apply(
                zap, target_url, list(structural_parameters), zap_container,
                run_paths.RunLayout(data_dir, run_id).ensure().dir,
            )
        except zap_context.ContextError as exc:
            raise ZapError(
                f"could not make {list(structural_parameters)} structural: "
                f"{exc}"
            ) from exc

    # Global daemon options, set before seeding and spidering spend minutes
    # of wall time, so a rejected option surfaces in seconds. Passive before
    # active — a request meets the passive queue first, and the caps read in
    # that order.
    #
    # Set unconditionally, including the no-limit sentinel: skipping the call
    # when the value means "unlimited" leaves whatever the daemon had, and a
    # ZAP container reused between runs then keeps the previous run's cap
    # while this run's artifact records "uncapped". The artifact must
    # describe the daemon, not the intent.
    zap.pscan_set_max_alerts_per_rule(max_alerts_per_rule)
    ui.item("passive-scan caps",
            "uncapped (-1)" if max_alerts_per_rule == config.NO_LIMIT
            else f"{max_alerts_per_rule} alerts per rule")
    ui.item("active-scan caps",
            f"{max_scan_minutes} min total, {max_rule_minutes} min per rule")
    zap.ascan_set_max_scan_duration(max_scan_minutes)
    zap.ascan_set_max_rule_duration(max_rule_minutes)
    # Bound the noise before scanning, not after: both of these exist to keep
    # one loud rule from owning the alert volume *and* the heap.
    # NON-RELEASE RULES OFF, unless the ground truth needs one.
    #
    # A daemon enables whatever its installed add-ons register, so alpha and
    # beta rules run without anyone choosing them — ZAP's own desktop
    # default policy leaves them out. Checked against every `cve-markers.yml`:
    # not one marker names a non-release rule, so this costs no detection. What
    # it removed was `100043` (alpha), which took
    # live heap from 1.2 GB to 6.7 GB and shut the daemon down twice.
    #
    # A marker that DOES name one keeps it and says so, because ground truth
    # outranks a quality label: measuring detection against a marker whose
    # rule this code silently disabled would report the marker undetected
    # and be wrong about why.
    try:
        inventory = zap.scanners()
    except ZapError as exc:                     # an old daemon may not have it
        ui.warn(f"could not read the active rule inventory: {exc}")
        inventory = []
    needed = targets.marker_rule_ids()
    prerelease = [s for s in inventory
                  if s.get("quality") != zap.RELEASE_QUALITY
                  and str(s.get("id")) not in needed]
    kept = [s for s in inventory
            if s.get("quality") != zap.RELEASE_QUALITY
            and str(s.get("id")) in needed]
    for rule in kept:
        ui.warn(f"rule {rule['id']} ({rule['name']}) is "
                f"{rule['quality']}-quality and is kept because a "
                "cve-markers.yml names it — the detection it supports is "
                "measured against a rule ZAP does not call finished")
    if prerelease:
        disabled_rules = tuple(dict.fromkeys(
            [*disabled_rules, *(str(s["id"]) for s in prerelease)]))
        ui.item("pre-release rules off", ", ".join(
            f"{s['id']} ({s['quality']})" for s in prerelease))

    # The target's own per-rule settings, before the run-wide list. A rule
    # the target disables joins `disabled_rules` rather than being applied
    # separately, so the artifact records ONE list of what was off — a
    # reader must not have to join two fields to learn what ran.
    target_off = [r.plugin_id for r in scan_rules if not r.enabled]
    disabled_rules = tuple(dict.fromkeys([*disabled_rules, *target_off]))
    for rule in scan_rules:
        if rule.enabled and rule.strength != "DEFAULT":
            zap.ascan_set_scanner_strength(rule.plugin_id, rule.strength)
        if rule.enabled and rule.threshold != "DEFAULT":
            zap.ascan_set_scanner_threshold(rule.plugin_id, rule.threshold)
    tuned = [r for r in scan_rules if r.enabled and not r.is_default()]
    if tuned:
        ui.item("active rules tuned", ", ".join(
            f"{r.plugin_id}={r.strength.lower()}" for r in tuned))
    if disabled_rules:
        zap.ascan_disable_scanners(list(disabled_rules))
        ui.item("active rules disabled", ", ".join(disabled_rules))
    # Inject the seeded session before any request is issued, so seeding, the
    # spider and the active scan all run authenticated.
    if auth_session is not None:
        zap.add_replacer_rule(
            AUTH_REPLACER_RULE, "Cookie", auth_session.cookie_header()
        )
        ui.item("authentication",
                f"{auth_session.username!r} ({auth_session.mode}), cookie injected")
    else:
        ui.item("authentication", "none")

    # Every per-run rule an earlier run left, whichever target wrote it: ZAP keeps
    # Replacer rules across a daemon restart, so removing only this target's header
    # names let Cacti's X-Forwarded-For ride every later scan of every target.
    for rule in zap.replacer_rules():
        if rule.startswith(OWN_RULE_PREFIXES):
            zap.remove_replacer_rule(rule)

    # Fixed target request headers, injected the same way as the auth cookie
    # so seeding, the spider and the active scan all carry them. This is how a
    # header-gated sink is reached: Cacti's remote_agent.php only serves a
    # request whose X-Forwarded-For resolves to a configured poller.
    for header, value in scan_headers.items():
        zap.add_replacer_rule(f"{SCAN_HEADER_RULE_PREFIX}{header}", header, value)
    if scan_headers:
        ui.item("scan headers", ", ".join(sorted(scan_headers)))

    # The target's logout and destructive routes, kept out of the whole scan: the
    # session is a fixed injected cookie, so one logout ends it for every request
    # after, and a logged-in crawl submits every form it finds. URL markers are
    # excluded from the spider and the active scan; every kind is rewritten in
    # anything ZAP sends, the browser spider included, which has no exclusion list.
    base = target_url.rstrip("/")
    for index, marker in enumerate(route_markers):
        kind, text = marker_kind(marker)
        rule = f"{LOGOUT_RULE_PREFIX}{index}"
        if kind == "url":
            zap.spider_exclude_from_scan(logout_regex(text))
            zap.ascan_exclude_from_scan(logout_regex(text))
            zap.add_request_rewrite_rule(rule, text, text + LOGOUT_REWRITE_SUFFIX)
        elif kind == "post":
            # The request line, exactly: a GET of the same page stays scanned.
            zap.add_request_rewrite_rule(
                rule, f"POST {base}{text} ",
                f"POST {base}{text}{LOGOUT_REWRITE_SUFFIX} ")
        else:
            zap.add_request_rewrite_rule(rule, text, text + LOGOUT_REWRITE_SUFFIX,
                                         in_body=True)
    if route_markers:
        ui.item("routes blocked", ", ".join(route_markers))

    # With the session cookie and any headers now injected, prove ZAP itself is
    # logged in before a single scan request is spent — the honest gate the
    # login-time curl confirm cannot be (see `verify_zap_authenticated`).
    if auth_session is not None and auth_profile is not None:
        check_url, indicator = verify_zap_authenticated(
            zap, target_url=target_url, auth_profile=auth_profile,
            auth_session=auth_session)
        ui.item("authentication verified", f"ZAP sees {indicator!r} at {check_url}")

    applied_targets = zap.ascan_set_injectable_targets(injectable_targets)
    ui.item("injectable targets",
            f"{describe_injectable_targets(applied_targets)} (mask {applied_targets})")
    if applied_targets != injectable_targets:
        ui.warn(f"ZAP did not accept the requested targets ({injectable_targets}); "
                "the active scan may have nothing to inject into")
    if add_query_param:
        zap.ascan_set_add_query_param(True)
        ui.item("addQueryParam", "ON — a synthetic parameter is appended to "
                "URLs that declare none")
    setup.close()
    return _ZapSetup(version, addon_versions, applied_targets,
                     tuple(disabled_rules), context_info)



def _collect_findings(
    zap: ZapClient, target_url: str, *, zap_mode: str, passive_only: bool,
    ascan_seconds: float, max_scan_minutes: int, total_urls: int,
) -> "tuple[list, dict, dict, str | None, list[dict]]":
    """Read the run's product back from the daemon: the alerts, the HTTP
    exchanges behind them (the proof, unreachable once the session closes), and
    the health verdict. Returns ``(alerts, alert_sources, sidecar, scan_warning,
    fetch_retries)``, the last a record of each alert page asked again."""
    ui.phase("Collecting alerts")
    _fetch_started = time.monotonic()
    fetch_retries: list[dict] = []

    def _retried(start: int, page_size: int, exc: Exception) -> None:
        fetch_retries.append({"start": start, "page_size": page_size,
                              "error": f"{type(exc).__name__}: {exc}"[:300]})
        ui.warn(f"alert page at {start} failed ({type(exc).__name__}: {exc}); "
                f"asking again at {page_size} per page")

    alerts = zap.alerts(base_url=target_url, on_retry=_retried)
    alert_sources = count_alert_sources(alerts)
    # Asserted here, where both halves are finally known: how long the
    # active scan ran, and whether it found anything. See `scan_health`.
    scan_warning = (
        None if zap_mode == ZAP_MODE_AF or passive_only else
        scan_health(ascan_seconds, max_scan_minutes,
                    alert_sources.get("active-scanner", 0), total_urls)
    )
    if scan_warning:
        ui.warn(scan_warning)
    ui.found(f"{len(alerts)} alerts")
    ui.done(time.monotonic() - _fetch_started)

    # The HTTP exchanges behind those alerts. Fetched here and nowhere else:
    # ZAP's history is session state, so a later stage reading a stored run
    # has no way back to it — and the exchange is the proof of most findings.
    # Only the referenced ids, deduplicated; see `zap_client.messages_by_id`
    # for why not the whole history table.
    ui.phase("Collecting HTTP exchanges")
    _msg_started = time.monotonic()
    wanted = evidence.message_ids(alerts)
    raw_messages = zap.messages_by_id(wanted)
    sidecar = evidence.build_message_sidecar(alerts, raw_messages)
    ui.found(
        f"{sidecar['counts']['messages']} exchanges for {len(alerts)} alerts "
        f"({sidecar['counts']['bodies_stored']} with a stored body)"
    )
    if len(raw_messages) < len(wanted):
        ui.warn(
            f"{len(wanted) - len(raw_messages)} of {len(wanted)} referenced "
            "messages were not returned by ZAP; findings citing them will "
            "carry no exchange."
        )
    ui.done(time.monotonic() - _msg_started)
    return alerts, alert_sources, sidecar, scan_warning, fetch_retries

def reset_target_to_clean_state(target_name: str, target_dir: "Path | None") -> Path:
    """Reinitialise the target to its clean, freshly-seeded state (``--reset-target``).

    Runs the target's own ``env/reset.sh``. The scan stage reaching into the
    target's lifecycle is deliberate and opt-in; the default keeps the
    persistent target and the ephemeral scan job as independent stacks. Raises
    rather than scan a target whose state is unknown: if it ships no reset
    script, or the reset fails.
    """
    base = Path(target_dir) if target_dir else (targets.TARGETS_DIR / target_name)
    script = base / "env" / "reset.sh"
    if not script.is_file():
        raise RuntimeError(
            f"--reset-target: {target_name} has no {script} to reinitialise it. "
            f"Add one, or run without --reset-target."
        )
    result = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"--reset-target: resetting {target_name} failed "
            f"(exit {result.returncode}): {result.stderr.strip()[-400:]}"
        )
    return script


@dataclass(frozen=True)
class PendingLogin:
    """An authenticated run whose login waits for the ``--reset-target`` reset.

    The reset replaces the instance a login before it would hold a session on, and a
    target an earlier scan left broken (a changed password, a wedged app) cannot be
    logged in to until it is reset; :func:`run_scan` logs in after the reset.
    """
    mode: str


def reauthenticate_on_clean_target(target_name: str, target_url: str, mode: str):
    """Log in again AFTER a ``--reset-target`` reset, so the session the scan
    replays is one the restored instance actually holds.

    The reset restores a snapshot captured from a freshly-seeded, pre-login
    target, so the session the driver harvested *before* the reset no longer
    exists on the instance the scan runs against — replaying its cookie runs
    every probe logged out (measured: the 2026-10-29 rescan scanned three
    authenticated targets logged out this way). Re-login here binds the scan's
    session to the instance it will scan. Fail-closed: :func:`auth.login` raises
    if the clean target does not authenticate the account.
    """
    from dast_orchestrator.adapters import auth
    return auth.login(target_url, targets.get(target_name).auth, mode)


def verify_zap_authenticated(zap: ZapClient, *, target_url: str,
                             auth_profile: Any, auth_session: Any) -> "tuple[str, str]":
    """Abort unless ZAP's OWN requests are logged in.

    The login-time confirm (:func:`auth._confirm_authenticated`) proves the
    credential is valid; it runs through a one-shot curl container and so cannot
    see a ZAP-side injection failure or a session the target has since forgotten.
    This fetches the profile's logged-in check page THROUGH ZAP — the injected
    Replacer cookie rides it exactly as it rides every scan request — and
    requires the logged-in indicator, raising :class:`ZapError` otherwise. The
    gate that makes a silently logged-out authenticated corpus impossible and
    visible at the layer that actually scans.
    """
    check_url = target_url.rstrip("/") + (
        getattr(auth_profile, "logged_in_check_path", None) or "/")
    indicator = auth_profile.logged_in_indicator
    if indicator not in zap.fetch_body(check_url):
        raise ZapError(
            f"authenticated scan requested as {auth_session.username!r} "
            f"({auth_session.mode}), but ZAP's own request to {check_url} did not "
            f"show {indicator!r}: ZAP is not logged in, so the scan would run "
            "anonymously. Aborting rather than silently writing a logged-out "
            "corpus under an authenticated name."
        )
    return check_url, indicator


class SessionWatch:
    """Re-checks, through ZAP, that an authenticated scan is still logged in.

    The setup gate proves the session at the start only, and a scan can end it
    itself. Each check is the gate's own request; every one is recorded with its
    phase and the seconds since the watch began.
    """

    def __init__(self, zap: Any, *, target_url: str, auth_profile: Any,
                 interval_seconds: float = SESSION_CHECK_INTERVAL_SECONDS,
                 attempts: int = SESSION_CHECK_ATTEMPTS,
                 retry_seconds: float = SESSION_CHECK_RETRY_SECONDS) -> None:
        self._zap = zap
        self._url = target_url.rstrip("/") + (
            getattr(auth_profile, "logged_in_check_path", None) or "/")
        self._indicator = auth_profile.logged_in_indicator
        self._interval = interval_seconds
        self._attempts = attempts
        self._retry = retry_seconds
        self._started = self._last = time.monotonic()
        self._warned = False
        #: ``{"phase", "at_seconds", "held"}`` per check; ``held`` is ``None`` when
        #: no attempt got an answer, which is not evidence either way.
        self.checks: list[dict[str, Any]] = []

    def check(self, phase: str, attempts: int = 1) -> "bool | None":
        """One check, recorded; never raises.

        :param attempts: tries, ``retry_seconds`` apart, until the target answers.
        :returns: whether the answer showed the indicator; ``None`` if none came.
        """
        held = None
        for attempt in range(attempts):
            if attempt:
                time.sleep(self._retry)
            try:
                held = self._indicator in self._zap.fetch_body(self._url)
                break
            except (ZapError, httpx.HTTPError):
                continue
        self._last = time.monotonic()
        self.checks.append({"phase": phase,
                            "at_seconds": round(self._last - self._started, 1),
                            "held": held})
        return held

    def require(self, phase: str) -> None:
        """Check, retrying a check that gets no answer, and abort the scan only if
        the target answers without the indicator.

        :raises ZapError: if ZAP's request no longer shows the logged-in indicator.
        """
        held = self.check(phase, attempts=self._attempts)
        if held is False:
            raise ZapError(
                f"the scan's session was lost during {phase}: ZAP's request to "
                f"{self._url} no longer shows {self._indicator!r}. Aborting rather "
                "than scan the rest logged out under an authenticated name.")
        if held is None:
            ui.warn(f"the session check after {phase} got no answer in "
                    f"{self._attempts} tries; going on, recorded as unknown")

    def tick(self, phase: str) -> None:
        """Check once per interval while a long phase runs; warn the first time the
        session is found gone. Never raises: the alerts raised so far are kept."""
        if time.monotonic() - self._last < self._interval:
            return
        held = self.check(phase)
        if held is False and not self._warned:
            self._warned = True
            ui.warn(f"the scan's session was lost during {phase}; the rest of it runs "
                    "logged out — recorded in session_checks")

    @property
    def held_to_end(self) -> "bool | None":
        """Whether every check that answered saw the session; ``None`` with none."""
        answered = [c["held"] for c in self.checks if c["held"] is not None]
        return all(answered) if answered else None


#: Poll budget for a restarted target to serve its login page again — 90 × 2s =
#: 3 min, matching the ceiling driver's `restart_and_wait`.
RECOVERY_READY_ATTEMPTS = 90
RECOVERY_READY_DELAY_SECONDS = 2.0


def recover_target(target_name: str, *, attempts: int = RECOVERY_READY_ATTEMPTS,
                   delay: float = RECOVERY_READY_DELAY_SECONDS) -> bool:
    """Restart a wedged target's container(s) and wait until it is loginable.

    The inline twin of ``rerun-cacti-ceiling-driver.sh``'s ``restart_and_wait``.
    A target that deadlocks under sustained scanning — Cacti's CVE RCE leaks
    MariaDB connections, and its 342-endpoint seed flakes ~1 in 3, dropping the
    connection mid-scan — is brought back with a ``docker restart`` of the
    containers its :class:`~...targets.Recovery` names, then polled over
    ``dast-net`` until its login page serves the login form again: status 200
    carrying the auth profile's password field. That is login-readiness, not
    mere liveness — a wedged DB still 500s the page, so only a DB-connected app
    returns the form.

    :returns: ``True`` once the target is loginable, ``False`` if it declares no
        :attr:`~...targets.Target.recovery`, the restart fails, or it never
        recovers in time. Never raises: this is a failure-path recovery.
    """
    import subprocess
    import time

    target = targets.get(target_name)
    recovery = target.recovery
    if recovery is None:
        return False
    ui.item("target recovery",
            f"restarting {', '.join(recovery.containers)} to clear the wedge")
    try:
        subprocess.run(["docker", "restart", *recovery.containers],
                       capture_output=True, text=True, timeout=180, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        ui.warn(f"could not restart {target_name} container(s): {exc}")
        return False
    if target.auth is None:
        return True            # no login form to wait on; the restart is all we can do
    probe = target.base_url.rstrip("/") + target.auth.login_path
    needle = target.auth.password_field
    fetch = auth.container_fetch()
    for i in range(1, attempts + 1):
        try:
            status, _location, body = fetch("GET", probe, 10.0)
        except RuntimeError:
            status, body = 0, ""        # the container refuses while still restarting
        if status == 200 and needle in body:
            ui.item("target recovery",
                    f"{target_name} is loginable again (attempt {i})")
            return True
        time.sleep(delay)
    ui.warn(f"{target_name} did not reach a loginable state after {attempts} attempts")
    return False


def run_scan(
    zap_addr: str,
    api_key: str,
    target_url: str,
    max_scan_minutes: int,
    max_rule_minutes: int,
    use_noir: bool = True,
    source_dir: Path = DEFAULT_SOURCE_DIR,
    noir_image: str = noir_runner.NOIR_IMAGE,
    path_vars: dict[str, str] | None = None,
    injectable_targets: int = DEFAULT_INJECTABLE_TARGETS,
    add_query_param: bool = False,
    auth_session: "object | None" = None,
    target_name: str = "",
    disabled_rules: "tuple[str, ...]" = DEFAULT_DISABLED_RULES,
    max_alerts_per_rule: int = DEFAULT_MAX_ALERTS_PER_RULE,
    data_dir: "Path | None" = None,
    noir_ignore_technologies: "tuple[str, ...]" = (),
    oracle_seeds: "tuple[str, ...]" = (),
    openapi_specs: tuple = (),
    target_dir: "Path | None" = None,
    spiders: "tuple[str, ...]" = DEFAULT_SPIDERS,
    browser_spider_minutes: int = 5,
    zap_mode: str = ZAP_MODE_REST,
    plan_path: "Path | None" = None,
    zap_container: str = DEFAULT_ZAP_CONTAINER,
    structural_parameters: "tuple[str, ...]" = (),
    scan_headers: "dict[str, str] | None" = None,
    reset_mode: str = zap_client.RESET_RESTART,
    scan_rules: "tuple[targets.ScanRule, ...]" = (),
    keep_session: bool = False,
    passive_only: bool = False,
    reset_target: bool = False,
    force: bool = False,
) -> Path:
    """Run the full pipeline and write the run's artifacts to ``data/``.

    :param use_noir: ``False`` reproduces the Phase 1 spider-only behaviour,
        kept permanently because the coverage delta is a thesis result.
    :param injectable_targets: see :data:`DEFAULT_INJECTABLE_TARGETS`.
    :param add_query_param: append a synthetic query parameter to URLs that
        declare none. Findings then concern a *guessed* input, so report such a
        run as its own scan mode.
    :param auth_session: an :class:`auth.AuthSession` to run the scan as, or
        ``None`` for an unauthenticated scan. Its cookie is injected into every
        ZAP request via a Replacer rule, so the spider and active scanner reach
        the routes that sit behind login — the biggest lever on detection rate.
    :param target_name: names the run's directory alongside its timestamp
        (``data/<ts>-<target>-<config>/``). Which system was scanned is part of a
        run's identity, since runs against different targets are not comparable.
    :param data_dir: where the run directory is created. A parameter rather
        than the module constant so a harness can point a whole sheet at one
        directory, and so a test never writes into the real ``data/``.
    :param force: start even though another process holds this run directory's
        scan lock — see :mod:`dast_orchestrator.foundation.run_lock`.
    :returns: path of the written ``scan-zap-alerts.json``.
    :raises run_lock.Busy: if another scan is already writing this run id.
    """
    if zap_mode == ZAP_MODE_AF and plan_path is None:
        raise ValueError("SCAN_ZAP_MODE=af needs a plan: pass --zap-plan, or put a "
                         "zap.yml in the target's directory")
    # Hashed here, before anything runs, so the digest in the artifact is of the
    # bytes this run actually used. Plans are deliberately not versioned the way
    # prompts are — they are configuration for a tool, not a variable under
    # study — but a result still has to be attributable to the file that
    # produced it, and a hash answers that without pretending to a lineage.
    plan_digest = zap_plan.plan_digest(plan_path) if plan_path else ""

    # A target property applied to every run of the target, like its structural
    # parameters, and checked before anything runs: an authenticated scan of a
    # target with no declared logout route would log itself out, as every one did
    # before the routes were declared.
    try:
        target_auth = targets.get(target_name).auth if target_name else None
    except KeyError:
        target_auth = None
    logout_markers = tuple(getattr(target_auth, "logout_markers", ()) or ())
    destructive_markers = tuple(getattr(target_auth, "destructive_markers", ()) or ())
    route_markers = logout_markers + destructive_markers
    if isinstance(auth_session, PendingLogin) and not reset_target:
        raise ValueError("a login deferred to the target reset needs --reset-target")
    if auth_session is not None and not logout_markers:
        raise ValueError(
            f"an authenticated scan of {target_name or target_url} needs the target's "
            "logout routes (auth.logout_markers in its target.yml); without them the "
            "scan reaches its own logout and runs the rest logged out")

    data_dir = Path(data_dir) if data_dir else DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    timestamp = run_paths.now_timestamp()
    # Built from the arguments the scan is *actually* running with rather than
    # from the parser's view of them, so the digest in the directory name can
    # never describe a configuration other than the one that produced the files
    # in it.
    run_config = scan_config(
        target_url=target_url,
        auth_mode=getattr(auth_session, "mode", "none"),
        use_noir=use_noir,
        max_scan_minutes=max_scan_minutes,
        max_rule_minutes=max_rule_minutes,
        injectable_targets=injectable_targets,
        add_query_param=add_query_param,
        max_alerts_per_rule=max_alerts_per_rule,
        disabled_rules=list(disabled_rules),
        noir_image=noir_image if use_noir else "",
        # Two runs that differ in how ZAP was driven are not the same
        # experiment, so the mode is part of the digest and the directory name.
        zap_mode=zap_mode,
        # How the daemon was cleaned. A run that started from a restarted daemon
        # and one that started from a reset session are not interchangeable —
        # measured, the second can silently scan nothing.
        reset_mode=reset_mode,
        # Which crawlers ran — a tree built by three of them is not the tree
        # `traditional` alone produces, and the alert counts follow the tree.
        spiders=",".join(spiders) if zap_mode == ZAP_MODE_REST else "",
        # The plan's bytes, so a stored result can be matched to the YAML that
        # produced it after the fact. Empty in REST mode.
        zap_plan_sha256=plan_digest,
        # Which query parameters ZAP treated as part of a URL's identity. This
        # changes what the scan CONTAINS — 91 seeded WordPress requests are 15
        # site-tree nodes without `action` and ~90 with it — so a run carrying
        # one is a different experiment from a run that does not, and the two
        # must not share a directory name. See `zap_context`.
        structural_parameters=",".join(structural_parameters),
        # Per-rule active-scan settings, same reasoning as the line above: a
        # disabled or weakened rule changes what the scan CONTAINS, so a run
        # carrying one is a different experiment and must not share a name with
        # a run that does not. Rendered as `id=enabled:strength:threshold` so
        # the digest moves for any of the three, and the readable form lands in
        # the metrics record beside it.
        scan_rules=",".join(
            f"{r.plugin_id}={'on' if r.enabled else 'off'}"
            f":{r.strength.lower()}:{r.threshold.lower()}"
            for r in scan_rules
        ),
    )
    # Added only when set, so a normal full scan's digest is unchanged: a
    # passive-only run raises no active-scanner alerts, so it is a different
    # experiment and must not share a configuration digest with a full run.
    if passive_only:
        run_config["passive_only"] = True
    # Same rule for oracle seeding: a run that seeds documented CVE sinks reaches
    # a surface a blind run does not, so it is a different experiment and its
    # digest must differ — but a blind run (no oracle seeds) keeps the digest it
    # always had, so existing corpora are unaffected. The seeded paths themselves
    # go in, sorted, so two oracle runs seeding the same sinks share a digest.
    if oracle_seeds:
        run_config["oracle_seeds"] = ",".join(sorted(oracle_seeds))
    # Added only when set, so no existing target's digest moves: fixed request
    # headers change what the scan can REACH (Cacti's XFF-gated remote_agent.php
    # sink), so a run injecting one is a different experiment. Only the names go
    # in the digest, sorted — the value is a fixed target property, and keeping it
    # out avoids a secret ever reaching the run id.
    scan_headers = dict(scan_headers or {})
    if scan_headers:
        run_config["scan_headers"] = ",".join(sorted(scan_headers))
    # Added only when set, so no persistent-target digest moves: a reset run
    # reinitialises the target first, so it sees a clean instance rather than
    # the accumulated state a persistent run does — a different experiment, and
    # its digest must say so.
    if reset_target:
        run_config["reset_target"] = "true"
    # Added only when set, so a target that declares none keeps its digest: a scan
    # that keeps its session and its app contains a different scan from one that
    # ended or wrecked them.
    if route_markers:
        run_config["blocked_routes"] = ",".join(route_markers)
    run_id = run_paths.make_run_id(
        timestamp, target_name, run_paths.config_digest(run_config)
    )
    # The moment the run id exists and before anything is spawned. Two scans of
    # one target inside the same second under one configuration mint the *same*
    # id — the third field is a digest of the configuration, not a counter — and
    # would otherwise both write into one directory, the second overwriting the
    # first's artifacts while both reported success. Claiming creates the
    # directory, which the run was about to do anyway. Released by
    # `@run_lock.guarded` on `main`.
    run_lock.claim(run_paths.RunLayout(data_dir, run_id).dir, "scan", force=force)
    ui.headline(
        "Scan",
        f"run {run_id}  →  {run_paths.RunLayout(data_dir, run_id).dir}",
    )
    metrics = run_metrics.RunMetrics(run_id, kind="scan")
    metrics.record_config(run_config)
    with metrics.guard(data_dir):
        # Before anything touches the target: a clean, freshly-seeded instance,
        # so the spider sees what discovery finds rather than what prior
        # authenticated scans accumulated. Opt-in (`--reset-target`).
        if reset_target:
            with ui.timed_phase("Target reset (--reset-target)"):
                with metrics.stage("target_reset") as stage:
                    stage.counters["script"] = str(
                        reset_target_to_clean_state(target_name, target_dir)
                    )
        # The reset above wiped any server-side session, INCLUDING the one the
        # driver harvested before this call — so an authenticated run must
        # re-login against the clean instance, or every probe runs logged out
        # under a cookie the target has forgotten. Done here, after the reset and
        # before ZAP is configured, so the cookie injected into the scan is live.
        auth_profile = target_auth if auth_session is not None else None
        if reset_target and auth_session is not None:
            with ui.timed_phase("Re-authenticate (post-reset)"):
                auth_session = reauthenticate_on_clean_target(
                    target_name, target_url, auth_session.mode)
            ui.item("authentication",
                    f"re-logged in as {auth_session.username!r} "
                    f"({auth_session.mode}) on the reset instance")
        metrics.record_tool(
            "noir",
            image=noir_image if use_noir else None,
            digest=run_metrics.docker_image_digest(noir_image) if use_noir else None,
        )

        seeds: list[SeedRequest] = []
        noir_metadata: dict[str, object] | None = None
        # ORACLE (ceiling) seeds: the benign sinks of documented CVE markers, which
        # no static extractor names and no crawler discovers (a marker's `seed:` in
        # cve-markers.yml). Seeded ONLY under `--oracle` — the caller passes them
        # only then — because a seed chosen BECAUSE we know the CVE is there is
        # oracle knowledge: a blind run's tree must be what discovery alone found, so
        # the gap between blind and ceiling measures what discovery costs. `--oracle`
        # is in the config digest (below), so an oracle run and a blind run are never
        # confused for one corpus.
        oracle = [SeedRequest("GET", target_url.rstrip("/") + path, f"oracle:{path}")
                  for path in oracle_seeds]
        # Routes an OpenAPI/Swagger spec declares, for a target whose router Noir
        # cannot parse. Parsed HERE into the same SeedRequest list Noir produces
        # (rather than handed to ZAP's opaque importer), so every added URL is
        # recorded and counted like Noir's — see `openapi_import`. Fetched before the
        # ZAP session opens, over dast-net, carrying the run's session cookie so a
        # spec behind auth is reachable.
        openapi_seeds: list[SeedRequest] = []
        if openapi_specs:
            from dast_orchestrator.adapters import auth as _auth
            from dast_orchestrator.adapters import openapi_import
            cookie = auth_session.cookie_header() if auth_session else ""
            fetch = _auth.container_fetch(cookie=cookie)
            with ui.timed_phase(f"OpenAPI route import ({len(openapi_specs)} spec(s))"):
                with metrics.stage("openapi_import") as stage:
                    for spec in openapi_specs:
                        ref = spec.url or spec.file
                        try:
                            doc = openapi_import.load_doc(
                                spec, target_dir or (targets.TARGETS_DIR / target_name),
                                fetch)
                            got = openapi_import.spec_to_seeds(
                                doc, target_url, path_vars or {}, spec.base_path)
                            openapi_seeds += got
                            ui.found(f"{ref}: {len(got)} route(s)")
                        except openapi_import.OpenApiError as exc:
                            # A bad spec warns and is skipped, never fails the scan:
                            # the Noir/crawl/seed surface is still valid, and a run is
                            # too expensive to lose to an unreachable spec URL.
                            ui.warn(f"openapi spec skipped ({ref}): {exc}")
                    stage.counters["specs"] = len(openapi_specs)
                    stage.counters["routes"] = len(openapi_seeds)
        if use_noir:
            # Before ZAP is touched, so a missing source tree or absent docker fails
            # fast and cheaply.
            with ui.timed_phase("Noir static extraction") as phase_state:
                with metrics.stage("noir") as stage:
                    seeds, noir_metadata = run_noir_stage(
                        source_dir, target_url, noir_image, path_vars or {}, timestamp,
                        run_id, data_dir, noir_ignore_technologies,
                    )
                    stage.counters["endpoints"] = noir_metadata["http_endpoints"]
                    stage.counters["seeds"] = noir_metadata["seed_requests"]
                phase_state["files"] = list(noir_metadata.get("artifacts") or [])

        with ZapClient(zap_addr, api_key) as zap:
            setup = _configure_zap(
                zap, target_url=target_url, timestamp=timestamp,
                zap_container=zap_container, zap_mode=zap_mode,
                plan_path=plan_path, plan_digest=plan_digest, zap_addr=zap_addr,
                structural_parameters=structural_parameters, data_dir=data_dir,
                run_id=run_id, max_alerts_per_rule=max_alerts_per_rule,
                max_scan_minutes=max_scan_minutes, max_rule_minutes=max_rule_minutes,
                scan_rules=scan_rules, disabled_rules=disabled_rules,
                auth_session=auth_session, auth_profile=auth_profile,
                scan_headers=scan_headers, route_markers=route_markers,
                injectable_targets=injectable_targets, add_query_param=add_query_param,
            )
            version = setup.version
            addon_versions = setup.addon_versions
            applied_targets = setup.applied_targets
            disabled_rules = setup.disabled_rules
            context_info = setup.context_info
            watch = (SessionWatch(zap, target_url=target_url, auth_profile=auth_profile)
                     if auth_session is not None and auth_profile is not None else None)

            seeded_urls = 0
            # Noir extracts the logout route like any other (Gitea's, Cacti's), and
            # seeding it ended the session a second into the scan.
            all_seeds, blocked_seeds = drop_logout_seeds(
                seeds + oracle + openapi_seeds, route_markers)
            if all_seeds:
                label = f"Seeding {len(seeds)} Noir endpoints"
                extra = []
                if oracle:
                    extra.append(f"{len(oracle)} ORACLE sink(s)")
                if openapi_seeds:
                    extra.append(f"{len(openapi_seeds)} OpenAPI route(s)")
                if extra:
                    label += " + " + " + ".join(extra)
                with ui.timed_phase(label):
                    with metrics.stage("seeding") as stage:
                        accepted = seed_zap(zap, all_seeds, required=oracle)
                        seeded_urls = len(zap.urls(base_url=target_url))
                        stage.counters["requests"] = len(all_seeds)
                        stage.counters["accepted"] = accepted
                        # Counted apart from Noir's, so the seeding delta the thesis
                        # attributes to static extraction stays attributable to it,
                        # the oracle-sink delta to prior knowledge, and the
                        # spec-import delta to the spec.
                        stage.counters["oracle_seeds"] = len(oracle)
                        stage.counters["openapi_seeds"] = len(openapi_seeds)
                        stage.counters["blocked_seeds_dropped"] = blocked_seeds
                        stage.counters["urls_after"] = seeded_urls
                    ui.found(f"site tree after seeding: {seeded_urls} URLs")
            if watch:
                watch.require("seeding")

            if zap_mode == ZAP_MODE_AF:
                # The plan owns crawling and scanning; everything before this point
                # (session reset, auth, seeding) still applies, because a plan
                # describes what to DO and not what this pipeline has already set up.
                with ui.timed_phase("Automation Framework plan"):
                    with metrics.stage("automation_plan") as stage:
                        urls_before_plan = len(zap.urls(base_url=target_url))
                        inside = zap_plan.deliver(plan_path, zap_container)
                        progress = zap_plan.run_plan(zap, inside)
                        stage.counters["plan_sha256"] = plan_digest
                        stage.counters["urls_before"] = urls_before_plan
                        stage.counters["urls_after"] = len(zap.urls(base_url=target_url))
                        # ZAP's own account of which jobs ran. Kept whole: a plan
                        # with an unrecognised job type completes reporting no
                        # error, so this list is the only evidence of what happened.
                        stage.counters["jobs"] = " | ".join(progress.get("info") or [])
                        stage.counters["plan_errors"] = len(progress.get("error") or [])
            else:
                with ui.timed_phase(f"Spider ({'+'.join(spiders)})"):
                    with metrics.stage("spider") as stage:
                        urls_before_spider = len(zap.urls(base_url=target_url))
                        per_spider = run_spiders(zap, target_url, spiders,
                                                 browser_minutes=browser_spider_minutes)
                        spidered_urls = len(zap.urls(base_url=target_url))
                        stage.counters["spiders"] = ",".join(spiders)
                        # Per crawler, so the contribution of each is attributable
                        # rather than an aggregate nobody can decompose.
                        for name, found in per_spider.items():
                            stage.counters[f"urls_after_{name}"] = found
                        stage.counters["poll_outcome"] = per_spider.get("outcome", "complete")
                        stage.counters["urls_before"] = urls_before_spider
                        stage.counters["urls_after"] = spidered_urls
                    # The point of the stage, stated: a percentage says it ran, not what
                    # it achieved.
                    ui.found(f"site tree {urls_before_spider} → {spidered_urls} URLs "
                             f"(+{spidered_urls - urls_before_spider} found by spidering)")
                if watch:
                    watch.require("spider")

            with ui.timed_phase("Passive scan queue"):
                with metrics.stage("passive_drain") as stage:
                    queued = _wait_for_passive_scan(zap)
                    stage.counters["records_queued"] = queued
                ui.found(
                    f"{queued} record(s) drained"
                    if queued else
                    "queue already empty — passive scanning kept pace with the spider"
                )

            total_urls = len(zap.urls(base_url=target_url))

            # The caps and injectable targets were set before seeding so a bad
            # option fails fast; the scan itself is bounded by them.
            # In AF mode the plan already ran whatever scanning it declared. A REST
            # active scan on top would attack the target twice and leave the run
            # neither one mode nor the other, so the whole block is skipped and the
            # counters it would have set are left absent rather than zeroed.
            ascan_outcome = "skipped-automation-plan"
            ascan_truncated = False
            ascan_seconds = 0.0
            if zap_mode == ZAP_MODE_AF:
                ui.item("active scan", "owned by the automation plan — not run here")
            elif passive_only:
                ascan_outcome = "skipped-passive-only"
                ui.item("active scan",
                        "skipped (--passive-only) — passive findings only, no active "
                        "probing")
            else:
                ui.phase(f"Active scan (cap {max_scan_minutes} min)")
                with metrics.stage("active_scan") as stage:
                    # Sampled throughout: the active scan is the long, expensive stage,
                    # and its peak footprint is what decides whether this fits a CI
                    # runner. A single reading afterwards would only show it idling.
                    # The target's container name is its URL host on dast-net; sampling
                    # it plus ZAP keeps the resource record target-agnostic.
                    _containers = [c for c in ("dast-zap", urlparse(target_url).hostname) if c]
                    with run_metrics.ResourceSampler(_containers) as sampler:
                        ascan_id = zap.ascan_scan(target_url)
                        # max_wait gives the cap headroom to finish the current rule.
                        ascan_outcome = zap.poll_until_complete(
                            zap.ascan_status, ascan_id, "ascan",
                            max_wait=max_scan_minutes * 60 + 120,
                            # Clock only: this stage runs for half an hour and its
                            # percentage is watched to see it is alive, not followed.
                            step=0, heartbeat=300.0,
                            on_poll=(lambda: watch.tick("active_scan")) if watch else None,
                        )
                    stage.counters["urls_in_tree"] = total_urls
                    stage.counters["cap_minutes"] = max_scan_minutes
                    # How the stage ended, always. A scan whose status stopped answering
                    # collected fewer alerts than one that ran to 100%, and the two must
                    # never be compared as if they were the same run.
                    stage.counters["poll_outcome"] = ascan_outcome
                    stage.counters["resources"] = sampler.summary()

            # **`complete` does not mean `exhausted`.** ZAP reports 100% when its own
            # maxScanDurationInMins stops the scan, so a capped run and one that
            # finished its work are indistinguishable in `poll_outcome` — and were,
            # in fact, confused: three 10-minute runs were written up as "not
            # budget-starved" on the strength of that word while all three had
            # stopped exactly at the cap. Recorded as its own boolean so no reader
            # has to derive it from seconds-versus-cap. Computed *after* the stage,
            # because `stage.seconds` is only set when the context manager exits.
            if zap_mode != ZAP_MODE_AF and not passive_only:
                ascan_truncated = bool(
                    max_scan_minutes and (stage.seconds or 0.0) >= max_scan_minutes * 60
                )
                stage.counters["truncated_by_cap"] = ascan_truncated
                ascan_seconds = stage.seconds or 0.0

                ui.done(stage.seconds or 0.0,
                        f"ended: {ascan_outcome}"
                        + (f" — STOPPED AT THE {max_scan_minutes}-MIN CAP"
                           if ascan_truncated else ""))
                if ascan_truncated:
                    ui.warn(
                        f"the active scan used its whole {max_scan_minutes}-minute cap, "
                        "so it was stopped rather than finished. Its coverage is a lower "
                        "bound and its alert counts are not comparable with a run that "
                        "had time to exhaust the surface — raise --max-active-scan-minutes or "
                        "narrow the scope."
                    )
            if ascan_outcome != zap_client.POLL_COMPLETE:
                ui.warn(
                    f"the active scan ended as {ascan_outcome!r}, not complete. "
                    "Collecting what ZAP has anyway — the alerts it already raised "
                    "are real; the coverage is not comparable with a finished run."
                )

            # The last check, recorded and never raised: the scan's alerts are
            # collected either way, and the record says whether it ended logged in.
            if watch:
                if watch.check("end", attempts=SESSION_CHECK_ATTEMPTS) is None:
                    ui.warn("the end-of-scan session check got no answer")
                if watch.held_to_end is False:
                    ui.warn("the session did not hold to the end of the scan: "
                            f"{watch.checks}")
                else:
                    ui.item("session", f"held through {len(watch.checks)} checks")

            # Outside the poll's failure path on purpose: whatever happened to the
            # status endpoint, the alerts raised so far are the product of the run
            # and are worth saving.
            alerts, alert_sources, sidecar, scan_warning, fetch_retries = _collect_findings(
                zap, target_url, zap_mode=zap_mode, passive_only=passive_only,
                ascan_seconds=ascan_seconds, max_scan_minutes=max_scan_minutes,
                total_urls=total_urls,
            )

            # Everything this run needed from ZAP has been read. Release the session
            # — `newSession` with no name puts the daemon back on a temporary one and
            # closes the files — and then remove the run's own directory, so a
            # long-lived daemon does not accumulate a multi-gigabyte session per
            # scan. In CI the container is discarded anyway; on a developer's machine
            # it is not, and this tool must not litter it.
            # Cleanup is housekeeping, not data: the alerts are already read
            # into memory above. A slow daemon timing out on session release
            # (a big scan's session store can take seconds to flush — Cacti's
            # 342-endpoint corpus is the worst case) must NOT discard a
            # completed scan before its artifacts are written. Warn and carry
            # on: a `docker restart` does not reclaim the on-disk session (it
            # replaces the process, not the writable layer), so the NEXT run's
            # `zap_session.prepare` sweeps whatever is left behind here.
            try:
                zap.new_session()
                zap_session.discard(run_id, zap_container, keep=keep_session)
            except Exception as exc:
                ui.warn(f"post-scan ZAP session cleanup failed ({exc}); the "
                        "scan's alerts are already collected and will be "
                        "written — the daemon keeps this run's session until "
                        "its next restart")

        layout = run_paths.RunLayout(data_dir, run_id).ensure()
        out_path = layout.path(run_paths.ZAP_ALERTS)
        auth_mode = auth_session.mode if auth_session is not None else "none"
        report = {
            "target": target_url,
            "zap_version": version,
            # The run's directory name; ``generated_at`` is the instant inside it.
            "run_id": run_id,
            "generated_at": timestamp,
            # Which account the scan ran as (or "none"). Three runs that differ here
            # are not comparable, so it rides in the report next to the coverage.
            "auth_mode": auth_mode,
            # "complete" | "timeout" | "status-unavailable" — see zap_client.
            "active_scan_outcome": ascan_outcome,
            # Whether the cap stopped it. `active_scan_outcome` alone cannot say:
            # ZAP reports 100% when its own duration cap fires, so "complete" covers
            # both a scan that finished its work and one that ran out of time.
            "active_scan_truncated": ascan_truncated,
            # Both change what the run could have found, so they ride with it: two
            # runs that differ here are not comparable on alert volume.
            "disabled_active_rules": list(disabled_rules),
            "max_alerts_per_passive_rule": max_alerts_per_rule,
            "auth_user": auth_session.username if auth_session is not None else None,
            # Affirmative proof the scan ran logged IN, not just that a cookie was
            # obtained: `auth.login` confirms the session against the target before
            # returning it, so an authenticated run that reaches here is one whose
            # `logged_in_indicator` was observed. `null` on an unauthenticated run.
            # Recorded because a silently-logged-out authenticated corpus is exactly
            # the failure this gate was added to make impossible and visible.
            "auth_authenticated": (
                bool(getattr(auth_session, "authenticated", False))
                if auth_session is not None else None),
            "auth_login_status": (
                auth_session.status if auth_session is not None else None),
            # The gate above proves the session at the start only; these say whether
            # it held through the scan (each check's phase and second, through ZAP).
            # `null` on an unauthenticated run.
            "logout_markers": list(logout_markers),
            "destructive_markers": list(destructive_markers),
            "session_checks": watch.checks if watch else None,
            "session_held_to_end": watch.held_to_end if watch else None,
            # Alert pages that failed in transport and were asked again, smaller.
            "alert_fetch_retries": fetch_retries,
            # Coverage numbers are the comparable quantity between a --no-noir run
            # and a seeded one; keep them in the report, not just on stdout.
            "noir": noir_metadata,
            "urls_after_seeding": seeded_urls,
            "urls_before_active_scan": total_urls,
            "alert_count": len(alerts),
            # Which stage actually produced the findings, and under which caps. A
            # time-boxed active scan over a large site tree can contribute almost
            # nothing while the total alert count still looks healthy, so the split
            # is recorded next to the caps that shaped it.
            "active_scan": {
                "max_scan_minutes": max_scan_minutes,
                "max_rule_minutes": max_rule_minutes,
                # Recorded because it decides whether the seeded endpoints are
                # attackable at all, and two runs that differ here are not
                # comparable no matter how similar their alert counts look.
                "injectable_targets": applied_targets,
                "injectable_targets_names": describe_injectable_targets(applied_targets),
                "add_query_param": add_query_param,
            },
            "alerts_by_source": alert_sources,
            # The exchanges themselves live in the gitignored `scan-zap-messages.json`
            # sidecar; only the accounting rides here, so a reader of this file can
            # tell "no body stored" from "no body" without opening 30 MB of HTML.
            "messages": sidecar["counts"],
            "alerts": alerts,
        }
        # NFR-06: redact the session/CSRF cookie values and the target's seeded
        # passwords the moment the scan report and its exchange sidecar are
        # written — a live scan needed them, the stored artifacts do not. The
        # report carries ZAP's own alert evidence (independent of the sidecar),
        # so it is scrubbed in its own right; triage and report then derive from
        # these already-clean files.
        try:
            scanned = targets.get(target_name) if target_name else None
        except KeyError:
            scanned = None
        secrets = redaction.target_secrets(scanned) if scanned else ()
        cookie_names = redaction.target_cookie_names(scanned) if scanned else ()
        out_path.write_text(json.dumps(
            redaction.scrub(report, secrets, cookie_names), indent=2))

        messages_path = layout.path(run_paths.ZAP_MESSAGES)
        messages_path.write_text(json.dumps(
            redaction.scrub(sidecar, secrets, cookie_names), indent=1))

        metrics.record_tool("zap", version=version, address=zap_addr,
                            addons=addon_versions,
                            injectable_targets=applied_targets)
        metrics.record_results(
            alerts=len(alerts),
            http_exchanges=sidecar["counts"]["messages"],
            exchange_bodies_stored=sidecar["counts"]["bodies_stored"],
            auth_mode=auth_mode,
            session_held_to_end=watch.held_to_end if watch else None,
            urls_after_seeding=seeded_urls,
            urls_before_active_scan=total_urls,
            active_scanner_alerts=alert_sources.get("active-scanner", 0),
            passive_scanner_alerts=alert_sources.get("passive-scanner", 0),
            # Recorded as well as warned about, so a sheet's rows can be filtered on
            # it later rather than re-read from a log nobody kept.
            active_scan_suspect=bool(scan_warning),
            # Read back from the daemon after the import, not assumed from the
            # target definition: an accepted-but-ignored context and a working one
            # look identical from here otherwise, and the difference is the whole
            # shape of the corpus. Empty for a target that declares none.
            structural_parameters=",".join(
                (context_info or {}).get("structural_parameters") or []),
            artifact=out_path.name,
        )
    # `guard` wrote the record leaving the block above (with an abort object had
    # the scan crashed — a ZAP or Docker failure mid-scan still leaves a record).
    # Clean path only from here.

    # Summary to stdout
    by_risk: dict[str, int] = {}
    for a in alerts:
        by_risk[a.get("risk", "?")] = by_risk.get(a.get("risk", "?"), 0) + 1
    summary = ui.open_phase("Scan summary")
    ui.found(f"{len(alerts)} alerts, {len({a.get('pluginId') for a in alerts})} distinct rules")
    ui.found(f"by risk:  {dict(sorted(by_risk.items()))}")
    ui.found(f"by stage: {alert_sources}")
    # "Effectively a passive scan" (few active-scanner alerts) has two causes
    # with OPPOSITE fixes, and conflating them gave wrong advice on the first
    # Grafana run: the active scan there COMPLETED in 12 of its 45 minutes and
    # raised nothing, yet the old message told the reader to raise the cap. So
    # the advice is split on whether the cap actually cut the scan off. The
    # `scan_health` suspect-warning above already owns the "fast AND empty AND
    # something to attack" case, so this note defers to it when it fired.
    active = alert_sources.get("active-scanner", 0)
    if alerts and active / len(alerts) < 0.05 and not scan_warning:
        if ascan_truncated:
            ui.warn(
                f"only {active} of {len(alerts)} alerts came from the active "
                f"scanner, and the active scan was cut off by the "
                f"{max_scan_minutes}-minute cap over {total_urls} URLs — raise "
                "--max-active-scan-minutes or narrow the scope so it completes."
            )
        elif zap_mode != ZAP_MODE_AF and not passive_only:
            raised = "raised nothing" if active == 0 else "raised almost nothing"
            ui.found(
                f"only {active} of {len(alerts)} alerts came from the active "
                f"scanner; it COMPLETED over {total_urls} URLs and {raised}. "
                "Effectively a passive scan because the reachable attack surface "
                "is small (an auth-gated app, or injectable sinks not in the "
                "tree) — not a cap problem."
            )

    summary.close(files=[out_path.name, messages_path.name, metrics.filename])
    metrics.print_summary()
    return out_path




__all__ = [
    'run_scan',
    'recover_target',
    'PendingLogin',
]
