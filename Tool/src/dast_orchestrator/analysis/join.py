"""The join: correlate ZAP alerts (concrete URLs) with Noir endpoints (route templates) so
a finding carries its handler's static context.

Resolved in three tiers, recorded per finding: ``seed`` (the exact template→URL map,
zero inference), ``regex`` (the template read backwards, for spider-found URLs; ambiguous
matches ranked, losers kept as ``alternatives``), and ``regex-path-only`` (path matches,
method does not). A template's literal query (``admin-ajax.php?action=X``) must also be
present in the URL's query, in every tier. Unmatched findings get no context with the reason recorded; the LLM
pass still sees them, on dynamic evidence alone, and skips only bundles with no
flagged or non-informational alert. → DECISIONS.md.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from dast_orchestrator.domain import rescan_table
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation import schema
from dast_orchestrator.adapters.noir_runner import (
    query_satisfies, split_template_query, template_specificity, template_to_regex,
)
from dast_orchestrator.adapters import zap_client
from dast_orchestrator.adapters.zap_client import count_alert_sources

TRIAGE_SCHEMA_VERSION = 1

#: URL space Noir's go_chi detector cannot reach on this target.
API_PREFIX = "/api/"

MATCH_SEED = "seed"
MATCH_REGEX = "regex"
MATCH_REGEX_PATH_ONLY = "regex-path-only"

CONTEXT_ABSENT_API = "absent-api-router-gap"
CONTEXT_ABSENT_UNMATCHED = "absent-unmatched"

#: How much evidence text distinguishes one alert instance from another when
#: collapsing duplicates: long enough to keep different payloads apart, short
#: enough that a page-length reflection does not become the grouping key.
EVIDENCE_KEY_CHARS = 120

INFORMATIONAL = "Informational"


class JoinError(RuntimeError):
    """Raised when a run's artifacts are missing or do not belong together."""


# -- loading a run's artifacts ---------------------------------------------


@dataclass(frozen=True)
class RunArtifacts:
    """The files of one scan run, all sharing a timestamp."""

    timestamp: str
    ai_context: dict[str, Any]
    zap_report: dict[str, Any]
    seed_map: dict[str, Any] | None
    ai_context_path: Path
    zap_report_path: Path
    seed_map_path: Path | None


def find_latest_timestamp(data_dir: Path) -> str:
    """The newest run directory, if it holds what the correlation needs.

    **"Latest" means the newest run, not the newest *usable* run**, and that
    distinction is the whole point. Falling through to an older complete run is
    what silently sent two triages onto a week-old scan — and then overwrote its
    artifacts — while the run the user had just made sat next to it, missing its
    alerts because the scan had died. A missing artifact in the newest run is a
    failed scan, and the honest response is to say so and name the fallback,
    never to quietly pick a different experiment.
    """
    runs = run_paths.RunLayout.runs(data_dir)
    if not runs:
        raise JoinError(
            f"no runs in {data_dir}. Run `uv run scan` first."
        )
    newest = run_paths.RunLayout(data_dir, runs[-1])
    missing = [
        name for name in (run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT)
        if not newest.has(name)
    ]
    if not missing:
        return newest.run_id

    complete = run_paths.RunLayout.latest_with(
        data_dir, run_paths.ZAP_ALERTS, run_paths.NOIR_AI_CONTEXT
    )
    hint = (
        f"\n  The newest run that does have them is {complete.run_id} — pass "
        f"`--run {complete.run_id}` to triage that one deliberately."
        if complete is not None else
        f"\n  No run in {data_dir} has them at all."
    )
    raise JoinError(
        f"the newest run {newest.run_id} is missing {', '.join(missing)} — its "
        f"scan did not finish.{hint}\n"
        "  (a --no-noir run produces no static context to correlate against)"
    )


def load_run(data_dir: Path, timestamp: str | None = None) -> RunArtifacts:
    """Load one run's artifacts.

    :param timestamp: the run to load — its full ``<timestamp>-<target>`` id,
        just the timestamp (completed against ``data_dir``), or ``"latest"``.
        Defaults to the newest complete run there, which is what ``"latest"``
        means here.
    :raises JoinError: if a required artifact is missing.

    The seed map is optional on purpose: runs recorded before it existed still
    correlate, falling through to the regex tier for everything, which the
    artifact reports honestly in its join counts.
    """
    if timestamp and not run_paths.is_latest(timestamp):
        try:
            layout = run_paths.RunLayout.resolve(data_dir, timestamp)
        except ValueError as exc:
            raise JoinError(str(exc)) from exc
    else:
        layout = run_paths.RunLayout(data_dir, find_latest_timestamp(data_dir))
    timestamp = layout.run_id
    ai_path = layout.path(run_paths.NOIR_AI_CONTEXT)
    zap_path = layout.path(run_paths.ZAP_ALERTS)
    for path in (ai_path, zap_path):
        if not path.is_file():
            raise JoinError(f"missing artifact for run {timestamp}: {path}")

    seed_path = layout.path(run_paths.NOIR_SEED_MAP)
    seed_path = seed_path if seed_path.is_file() else None

    # Validate each artifact against its schema as it is read: a truncated or
    # stale scan fails here, naming the field, rather than as a KeyError once
    # triage is halfway in. A required-field violation raises; a looser deviation
    # warns. Surfaced as a JoinError so the drivers report it like any other bad
    # input. See foundation.schema (§R5).
    ai_context = json.loads(ai_path.read_text())
    zap_report = json.loads(zap_path.read_text())
    seed_map = json.loads(seed_path.read_text()) if seed_path else None
    try:
        schema.check(ai_path.name, ai_context, ai_path)
        schema.check(zap_path.name, zap_report, zap_path)
        if seed_map is not None:
            schema.check(seed_path.name, seed_map, seed_path)
    except schema.ArtifactError as exc:
        raise JoinError(str(exc)) from exc

    return RunArtifacts(
        timestamp=timestamp,
        ai_context=ai_context,
        zap_report=zap_report,
        seed_map=seed_map,
        ai_context_path=ai_path,
        zap_report_path=zap_path,
        seed_map_path=seed_path,
    )


# -- the join --------------------------------------------------------------


@dataclass(frozen=True)
class Match:
    """Result of resolving one (method, path, query) onto a Noir route template."""

    endpoint_key: str | None
    how: str
    alternatives: tuple[str, ...] = ()


def _specificity(template: str) -> tuple[int, ...]:
    """:func:`template_specificity` of the path, then how many query pairs it
    requires — the final tiebreak, so ``?action=X`` beats the bare path."""
    path, required = split_template_query(template)
    return (*template_specificity(path), len(required))


class EndpointJoiner:
    """Resolves concrete (method, URL path) pairs back onto route templates."""

    def __init__(
        self,
        endpoints: Iterable[dict[str, Any]],
        seed_map: dict[str, Any] | None = None,
    ) -> None:
        self._by_key: dict[str, dict[str, Any]] = {}
        self._patterns: list[
            tuple[str, Any, tuple[tuple[str, str], ...], str, tuple[int, ...]]] = []
        for endpoint in endpoints:
            key = endpoint["key"]
            self._by_key[key] = endpoint
            path, required = split_template_query(endpoint["path"])
            self._patterns.append(
                (
                    endpoint["method"],
                    template_to_regex(path),
                    required,
                    key,
                    _specificity(endpoint["path"]),
                )
            )
        # (method, path) -> {required query pairs -> endpoint keys}; a seed path
        # without a query has no required pairs, so it is looked up as before.
        self._seeded: dict[tuple[str, str],
                           dict[tuple[tuple[str, str], ...], list[str]]] = {}
        for entry in (seed_map or {}).get("entries", []):
            path, required = split_template_query(entry["path"])
            self._seeded.setdefault((entry["method"], path), {})[required] = list(
                entry["endpoint_keys"])

    def context_for(self, endpoint_key: str) -> dict[str, Any] | None:
        return self._by_key.get(endpoint_key)

    def _rank(self, keys: Iterable[str]) -> list[str]:
        """Order candidate templates, most specific first.

        The endpoint-key tiebreak is load-bearing: without it two equally
        specific templates would be ordered by dict iteration, and the same
        inputs could correlate differently between runs.
        """
        return sorted(
            keys,
            key=lambda k: (_specificity(self._by_key[k]["path"]), k)
            if k in self._by_key
            else ((0, 0, 0, 0), k),
            reverse=True,
        )

    def _api_consistent(self, url_path: str, endpoint_key: str) -> bool:
        """Reject a web route claiming an ``/api/`` URL it cannot serve.

        Noir sees none of Gitea's ``/api/v1`` tree, so any such URL that appears
        to match a template is a false correlation — and the generic templates
        are greedy enough to swallow them: ``/api/v1/notifications`` has four
        segments, so it matches ``/{username}/{reponame}/{type}`` and the finding
        would arrive carrying an unrelated repo-view handler's source.

        ``/api/swagger`` is why this is a prefix comparison rather than a blanket
        exclusion: it is a genuine ``routers/web`` route, so a template that is
        *itself* under ``/api/`` keeps its match.
        """
        if not url_path.startswith(API_PREFIX):
            return True
        endpoint = self._by_key.get(endpoint_key)
        return bool(endpoint) and endpoint["path"].startswith(API_PREFIX)

    def match(self, method: str, path: str, query: str = "") -> Match:
        """Resolve one request onto a template.

        :param query: the URL's raw query string; a template that requires a
            literal query (``?action=X``) matches only when it carries it.
        """
        path = path or "/"

        seeded: list[str] = []
        for required, keys in (self._seeded.get((method, path)) or {}).items():
            if not query_satisfies(required, query):
                continue
            seeded.extend(key for key in keys
                          if self._api_consistent(path, key) and key not in seeded)
        if seeded:
            ranked = self._rank(seeded)
            return Match(ranked[0], MATCH_SEED, tuple(ranked[1:]))

        same_method: list[tuple[tuple[int, int, int], str]] = []
        other_method: list[tuple[tuple[int, int, int], str]] = []
        for endpoint_method, pattern, required, key, specificity in self._patterns:
            if not pattern.match(path) or not query_satisfies(required, query):
                continue
            if not self._api_consistent(path, key):
                continue
            (same_method if endpoint_method == method else other_method).append(
                (specificity, key)
            )

        for candidates, how in ((same_method, MATCH_REGEX), (other_method, MATCH_REGEX_PATH_ONLY)):
            if candidates:
                ranked = [key for _, key in sorted(candidates, key=lambda c: (c[0], c[1]), reverse=True)]
                return Match(ranked[0], how, tuple(ranked[1:]))

        return Match(
            None,
            CONTEXT_ABSENT_API if path.startswith(API_PREFIX) else CONTEXT_ABSENT_UNMATCHED,
        )


# -- collapsing duplicate alerts -------------------------------------------


@dataclass
class AlertGroup:
    """Identical alerts across many concrete URLs, collapsed into one finding.

    Grouping is what makes the LLM pass affordable and the report readable.
    Confidence and risk are part of the grouping key because the deterministic
    arm decides on them: two instances of one rule at different confidence are
    two different decisions, not one finding.
    """

    plugin_id: str
    name: str
    risk: str
    confidence: str
    param: str
    evidence: str
    method: str
    cweid: str = ""
    alert_ref: str = ""
    attack: str = ""
    #: ZAP's own account of the rule and of what it saw. Present in every alert
    #: the API returns and stored in ``scan-zap-alerts.json`` since the first run, but
    #: dropped on the way into the prompt in an early version — which is how a
    #: High/High finding came to be judged with an empty ``evidence`` field while
    #: ``other`` held the proof. See
    #: :mod:`dast_orchestrator.context.evidence`.
    description: str = ""
    other: str = ""
    solution: str = ""
    wascid: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    #: Where ZAP injected, on the alerts that were actively attacked. Populated
    #: only on actively-attacked alerts — rare, because only the active scanner
    #: fills it, and decisive exactly there: it is the difference between "the
    #: payload went into the query string" and "into a form field", which is what
    #: a reflection judgement turns on. See DECISIONS.md.
    input_vector: str = ""
    #: Which ZAP stage raised this alert, from the alert's own ``sourceid``.
    #: Carried into the finding because it is the difference between a finding
    #: the scanner *injected for* and one a passive rule *guessed at*, and an
    #: independent tool can only settle the first kind — see
    #: :func:`~dast_orchestrator.domain.verification.dispatch_priority`.
    source: str = ""
    urls: list[str] = field(default_factory=list)
    zap_alert_ids: list[str] = field(default_factory=list)
    #: ZAP message ids behind this group, in first-seen order, so the evidence
    #: assembler can look the exchanges up in the sidecar. The first is the one
    #: quoted; the rest are kept because a group spans many concrete URLs and a
    #: reader auditing it needs to be able to reach the others.
    message_ids: list[str] = field(default_factory=list)
    source_message_ids: list[str] = field(default_factory=list)
    # Join tier per contributing alert, not per endpoint: one template's
    # concrete URLs can arrive by different routes (one seeded, one found by the
    # spider), and reporting only the endpoint's first tier would overstate how
    # much of the join was exact.
    tiers: dict[str, int] = field(default_factory=dict)

    @property
    def instances(self) -> int:
        return len(self.zap_alert_ids)

    @property
    def group_key(self) -> tuple[str, ...]:
        """The identity these alerts were collapsed on. See :func:`_identity_key`."""
        return _identity_key(self.plugin_id, self.method, self.param,
                             self.confidence, self.risk, self.evidence)

    @property
    def dominant_tier(self) -> str:
        """The tier most of this group's alerts came in on; name breaks ties."""
        if not self.tiers:
            return CONTEXT_ABSENT_UNMATCHED
        return max(self.tiers.items(), key=lambda kv: (kv[1], kv[0]))[0]

    def as_dict(self, max_urls: int = 5) -> dict[str, Any]:
        return {
            "plugin_id": self.plugin_id,
            "name": self.name,
            "risk": self.risk,
            "confidence": self.confidence,
            "param": self.param,
            "attack": self.attack,
            "evidence": self.evidence,
            "cweid": self.cweid,
            "wascid": self.wascid,
            "alert_ref": self.alert_ref,
            "method": self.method,
            "source": self.source,
            "instances": self.instances,
            "join_tiers": dict(sorted(self.tiers.items())),
            "example_urls": self.urls[:max_urls],
            "zap_alert_ids": self.zap_alert_ids,
            "message_ids": self.message_ids[:max_urls],
        }


def _identity_key(plugin_id: str, method: str, param: str, confidence: str,
                  risk: str, evidence: str) -> tuple[str, ...]:
    """What makes two alerts on one endpoint the same finding.

    One definition with two callers: :func:`_group_key` collapses raw ZAP alerts
    on it, and :func:`finding_id` hashes it. They were written out separately
    were once written out separately and drifted — the hash omitted ``method`` and
    ``risk``, so a passive rule firing on both the GET and the POST of one endpoint
    made two findings that shared one id, and every join back from a verification
    record or a SARIF result resolved them to whichever came first, silently.
    """
    return (plugin_id, method, param, confidence, risk,
            evidence[:EVIDENCE_KEY_CHARS])


def _group_key(alert: dict[str, Any]) -> tuple[str, ...]:
    return _identity_key(
        str(alert.get("pluginId") or ""),
        str(alert.get("method") or ""),
        str(alert.get("param") or ""),
        str(alert.get("confidence") or ""),
        str(alert.get("risk") or ""),
        str(alert.get("evidence") or ""),
    )


# -- bundles ---------------------------------------------------------------


@dataclass
class Bundle:
    """Everything known about one endpoint: static context plus its findings."""

    endpoint_key: str | None
    match_how: str
    method: str
    path: str
    alternatives: tuple[str, ...] = ()
    static_context: dict[str, Any] | None = None
    groups: list[AlertGroup] = field(default_factory=list)

    @property
    def has_static_context(self) -> bool:
        return self.static_context is not None

    @property
    def identifier(self) -> str:
        return self.endpoint_key or f"{self.method} {self.path}"


#: How many distinct signal names of one category travel with an endpoint when
#: it is described *to another pass* — shallow, because both passes that use
#: this are buying breadth rather than depth.
MAX_SIGNAL_NAMES_PER_CATEGORY = 6

#: How many shared handlers are worth naming at all.
MAX_SHARED_HANDLERS = 40

#: A handler shared by ~everything (Gitea's ``bindIgnErr`` is on 110 routes)
#: links nothing to anything in particular, so it is noise rather than a link.
MAX_ENDPOINTS_PER_SHARED_HANDLER = 12


def signal_names(bundle: Bundle, category: str) -> list[str]:
    """Distinct Noir signal names of one category on one endpoint, capped."""
    signals = (bundle.static_context or {}).get("ai_context", {}).get(category) or []
    seen: list[str] = []
    for signal in signals:
        name = signal.get("name", "")
        if name and name not in seen:
            seen.append(name)
        if len(seen) >= MAX_SIGNAL_NAMES_PER_CATEGORY:
            break
    return seen


def shared_handlers(bundles: Iterable[Bundle],
                    routes_with_findings: set[str]) -> dict[str, list[str]]:
    """Handler functions reached by more than one route: the propagation links.

    Lives with the join rather than with either prompt, because **both** LLM
    passes need it and for different reasons: pass 2 uses it to find
    cross-endpoint patterns, pass 1 to know which of the endpoints it is *not*
    being shown run the same code as the one it is.

    Only handlers that touch at least one route carrying a real finding are
    kept — a shared handler with nothing observed on any of its routes is not a
    correlation, just a fact about the codebase. Very widely shared handlers are
    dropped too: Gitea's `bindIgnErr` appears on 110 routes and links nothing in
    particular to anything in particular.
    """
    by_handler: dict[str, list[str]] = {}
    for bundle in bundles:
        if not bundle.static_context:
            continue
        for name in signal_names(bundle, "callees"):
            by_handler.setdefault(name, []).append(bundle.identifier)

    useful = {
        handler: sorted(set(routes))
        for handler, routes in by_handler.items()
        if 1 < len(set(routes)) <= MAX_ENDPOINTS_PER_SHARED_HANDLER
        and set(routes) & routes_with_findings
    }
    ranked = sorted(useful.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return dict(ranked[:MAX_SHARED_HANDLERS])


def build_bundles(run: RunArtifacts) -> list[Bundle]:
    """Group every alert of a run under the endpoint it belongs to."""
    joiner = EndpointJoiner(run.ai_context["endpoints"], run.seed_map)
    bundles: dict[str, Bundle] = {}
    groups: dict[tuple[str, tuple[str, ...]], AlertGroup] = {}

    for alert in run.zap_report.get("alerts", []):
        method = str(alert.get("method") or "GET")
        parsed = urlparse(str(alert.get("url") or ""))
        path = parsed.path or "/"
        match = joiner.match(method, path, parsed.query)

        # Alerts with static context are keyed on the template, so instances
        # across many concrete URLs land in one bundle. Alerts without it have
        # no template to key on, so the concrete path is the best available
        # identity.
        bundle_id = match.endpoint_key or f"{method} {path}"
        bundle = bundles.get(bundle_id)
        if bundle is None:
            context = (
                joiner.context_for(match.endpoint_key) if match.endpoint_key else None
            )
            bundle = Bundle(
                endpoint_key=match.endpoint_key,
                match_how=match.how,
                method=method,
                path=context["path"] if context else path,
                alternatives=match.alternatives,
                static_context=context,
            )
            bundles[bundle_id] = bundle

        key = (bundle_id, _group_key(alert))
        group = groups.get(key)
        if group is None:
            group = AlertGroup(
                plugin_id=str(alert.get("pluginId") or ""),
                name=str(alert.get("name") or alert.get("alert") or ""),
                risk=str(alert.get("risk") or ""),
                confidence=str(alert.get("confidence") or ""),
                param=str(alert.get("param") or ""),
                evidence=str(alert.get("evidence") or ""),
                method=method,
                cweid=str(alert.get("cweid") or ""),
                alert_ref=str(alert.get("alertRef") or ""),
                attack=str(alert.get("attack") or ""),
                description=str(alert.get("description") or alert.get("desc") or ""),
                other=str(alert.get("other") or alert.get("otherinfo") or ""),
                solution=str(alert.get("solution") or ""),
                wascid=str(alert.get("wascid") or ""),
                tags={k: str(v) for k, v in (alert.get("tags") or {}).items()},
                input_vector=str(alert.get("inputVector") or ""),
                source=zap_client.alert_source_name(alert),
            )
            groups[key] = group
            bundle.groups.append(group)
        group.tiers[match.how] = group.tiers.get(match.how, 0) + 1
        group.zap_alert_ids.append(str(alert.get("id") or ""))
        for key, target in (("messageId", group.message_ids),
                            ("sourceMessageId", group.source_message_ids)):
            mid = str(alert.get(key) or "").strip()
            if mid and mid not in target:
                target.append(mid)
        url = str(alert.get("url") or "")
        if url not in group.urls:
            group.urls.append(url)

    return sorted(bundles.values(), key=lambda b: b.identifier)


# -- the deterministic arm over bundles ------------------------------------


def finding_id(bundle: Bundle, group: AlertGroup) -> str:
    """Content hash: same endpoint + rule + evidence yields the same id.

    Deliberately not a counter — comparing two runs, or the two arms across
    runs, needs an identifier that survives a different alert ordering. Every
    hashed component is alert content or the endpoint it sits on, so nothing
    run-specific enters the digest and the id is stable across runs of one
    target.

    The hashed fields are the group's whole identity (:func:`_identity_key`)
    plus that endpoint, and it has to stay that way: any field that can split
    one bundle's alerts into two groups but does not reach the hash gives both
    groups the same id.
    """
    digest = hashlib.sha1(
        "|".join((bundle.identifier, *group.group_key)).encode()
    ).hexdigest()
    return f"f-{digest[:12]}"


def is_llm_candidate(bundle: Bundle) -> bool:
    """Whether this bundle is worth a model call. See the module docstring."""
    return any(
        group.risk != INFORMATIONAL or rescan_table.needs_rescan(_as_alert(group))
        for group in bundle.groups
    )


#: The top-level source directory a framework-less PHP app keeps its **non-web**
#: ``.php`` scripts in: the command-line tools (``cli/``), which reject an
#: ordinary HTTP request, so any passive finding Noir/ZAP records against them
#: sits on a surface no client reaches — noise the LLM arm would iterate on
#: without a live route behind it.
#:
#: **``install/`` is deliberately NOT here.** The §R3.3 hypothesis was that the
#: one-time installer was non-web too, but validating the prune on Cacti's real
#: corpus (§R3.4, run ``…-cacti-12fb0e``) showed the installer IS reachable:
#: its 61 ``php_pure`` endpoints carry ZAP alerts, and ``install/install.php`` and
#: ``install/step_json.php`` are flagged for deterministic rescan. Dropping them
#: would lose the LLM arm's refutation of a live endpoint's findings — exactly
#: the arm's value — so the prune is scoped to ``cli/`` alone, which carries no
#: active or rescan findings.
_NONINTERACTIVE_PHP_DIRS = frozenset({"cli"})


def is_noninteractive_php(bundle: Bundle) -> bool:
    """A ``php_pure`` endpoint whose source lives under ``cli/``.

    WordPress drops ``php_pure`` wholesale (``noir_ignore_technologies``); a
    framework-less PHP app (Cacti) keeps those ``.php`` endpoints because they
    *are* its web surface — but not the command-line tools under ``cli/``, which
    reject HTTP. Tight on purpose (the **first** path segment, a real top-level
    dir, not any segment named ``cli``), and gated off by default. The
    ``install/`` directory was validated OUT — see :data:`_NONINTERACTIVE_PHP_DIRS`
    — so this is ``cli/`` only. See :func:`select_llm_candidates`, NEXT_SESSION
    §R3.3/§R3.4.
    """
    if (bundle.static_context or {}).get("technology") != "php_pure":
        return False
    first = bundle.path.lstrip("/").split("/", 1)[0]
    return first in _NONINTERACTIVE_PHP_DIRS


def select_llm_candidates(
    bundles: Iterable[Bundle],
    prune_noninteractive_php: bool = False,
) -> tuple[list[Bundle], int]:
    """The bundles pass 1 will call the model on, and how many the gated
    non-interactive-PHP prune removed.

    The prune trims only what the LLM arm iterates on — the deterministic record
    (``build_findings``) and the synthesis corpus still see every bundle. Kept as
    one helper so ``dry_run`` and the live arm select the identical candidate set;
    a dry run that pruned differently would misreport the run it exists to preview.
    """
    candidates = [b for b in bundles if is_llm_candidate(b)]
    if not prune_noninteractive_php:
        return candidates, 0
    kept = [b for b in candidates if not is_noninteractive_php(b)]
    return kept, len(candidates) - len(kept)


def _as_alert(group: AlertGroup) -> dict[str, Any]:
    """The minimal dict shape `rescan_table.decide` reads."""
    return {
        "pluginId": group.plugin_id,
        "confidence": group.confidence,
        "risk": group.risk,
    }


def build_findings(bundles: Iterable[Bundle]) -> list[dict[str, Any]]:
    """One finding per (endpoint, collapsed alert), with the control-arm verdict."""
    findings: list[dict[str, Any]] = []
    for bundle in bundles:
        for group in bundle.groups:
            decision = rescan_table.decide(_as_alert(group))
            findings.append(
                {
                    "finding_id": finding_id(bundle, group),
                    "endpoint_key": bundle.endpoint_key,
                    "static_context": group.dominant_tier,
                    "static_context_present": bundle.has_static_context,
                    "match_alternatives": list(bundle.alternatives),
                    "method": bundle.method,
                    "path": bundle.path,
                    "alert": group.as_dict(),
                    "deterministic": {
                        "needs_rescan": decision.needs_rescan,
                        "policy": decision.policy.value,
                        "in_table": decision.in_table,
                        "tool": decision.tool,
                        "reason": decision.reason,
                    },
                    # Filled in by the LLM arm when the bundle was a candidate.
                    "llm_asked": False,
                    "llm_deferred": False,
                    "llm": None,
                    "agreement": NOT_SENT,
                }
            )
    return findings


AGREEMENT_LABELS = {
    (True, True): "both",
    (True, False): "deterministic-only",
    (False, True): "llm-only",
    (False, False): "neither",
}

# Two very different reasons a finding has no model verdict, deliberately kept
# apart. The first Phase 3 run conflated them and the artifact was misleading
# as a result: 36% of what the model was *asked* came back unanswered, and that
# was indistinguishable from the 726 findings never sent to it at all.
NOT_SENT = "not-evaluated"
ASKED_NO_VERDICT = "asked-no-verdict"


def label_agreement(finding: dict[str, Any]) -> str:
    """Compare the two arms on one finding. The delta metric of Phase 3."""
    llm = finding.get("llm")
    if not llm:
        return ASKED_NO_VERDICT if finding.get("llm_asked") else NOT_SENT
    return AGREEMENT_LABELS[
        (bool(finding["deterministic"]["needs_rescan"]), bool(llm["needs_rescan"]))
    ]


def mark_asked(findings: list[dict[str, Any]], finding_ids: Iterable[str]) -> None:
    """Record that these findings were put in front of the model.

    Called before the call, so a finding that is asked about and never answered
    is distinguishable afterwards from one that was never a candidate — whether
    the call failed outright or the model simply omitted it from its reply.
    """
    wanted = set(finding_ids)
    for finding in findings:
        if finding["finding_id"] in wanted:
            finding["llm_asked"] = True
            finding["agreement"] = ASKED_NO_VERDICT


def mark_deferred(findings: list[dict[str, Any]], finding_ids: Iterable[str]) -> None:
    """Record that pass 1's limit left these candidates unsent.

    Kept apart from a finding that was never a candidate, so a run's asked share
    says how much the limit, not the candidate rule, held back.
    """
    wanted = set(finding_ids)
    for finding in findings:
        if finding["finding_id"] in wanted:
            finding["llm_deferred"] = True


def top_rules(bundles: Iterable[Bundle], limit: int = 10) -> list[dict[str, Any]]:
    """Which ZAP rules produced the alert volume, most first.

    Exists because "79% of alerts came from the active scanner" was true and
    still misleading: 4931 of those 4939 were one fuzzer rule. Any claim about
    scan productivity needs this table beside it.
    """
    counts: dict[tuple[str, str, str], int] = {}
    for bundle in bundles:
        for group in bundle.groups:
            key = (group.plugin_id, group.name, group.risk)
            counts[key] = counts.get(key, 0) + group.instances
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [
        {"plugin_id": pid, "name": name, "risk": risk, "alerts": count}
        for (pid, name, risk), count in ranked[:limit]
    ]


def _count(values: Iterable[str]) -> dict[str, int]:
    """Tally values into a descending-count dict."""
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def summarise(
    bundles: list[Bundle],
    findings: list[dict[str, Any]],
    correlated: list[dict[str, Any]],
    run_alerts: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Counts the writeup needs, computed once and stored in the artifact."""
    join_counts: dict[str, int] = {}
    for bundle in bundles:
        for group in bundle.groups:
            for tier, count in group.tiers.items():
                join_counts[tier] = join_counts.get(tier, 0) + count

    agreement: dict[str, int] = {}
    for finding in findings:
        label = finding["agreement"]
        agreement[label] = agreement.get(label, 0) + 1

    evaluated = [f for f in findings if f.get("llm")]
    asked = [f for f in findings if f.get("llm_asked")]
    return {
        "bundles": len(bundles),
        "bundles_with_static_context": sum(1 for b in bundles if b.has_static_context),
        "raw_alerts": sum(g.instances for b in bundles for g in b.groups),
        "findings": len(findings),
        "alerts_by_join_tier": join_counts,
        # Which ZAP stage produced the alerts. A run whose alerts are ~all
        # passive has barely exercised the active scanner, and every downstream
        # number (what there is to verify, what there is to correlate) has to be
        # read in that light rather than as a property of the target.
        "alerts_by_zap_source": count_alert_sources(list(run_alerts)),
        # The active count on its own is misleading: one noise rule can own
        # nearly all of it (10104 User Agent Fuzzer was 4931 of 4939 in the
        # 60-minute run). The top rules are stored so the split is never quoted
        # without what produced it.
        "top_rules": top_rules(bundles),
        "deterministic_rescans": sum(
            1 for f in findings if f["deterministic"]["needs_rescan"]
        ),
        # What Phase 4 would actually dispatch, split by rule and by tool. One
        # rule supplying most of the workload is a budget decision waiting to
        # happen, so it is a stored number rather than something to rediscover.
        "rescans_by_rule": _count(
            f["alert"]["name"] for f in findings if f["deterministic"]["needs_rescan"]
        ),
        "rescans_by_tool": _count(
            f["deterministic"]["tool"] or "unassigned"
            for f in findings
            if f["deterministic"]["needs_rescan"]
        ),
        # The control arm asking for a rescan it cannot route. Its own number
        # because it is a defect in the TABLE, not a property of the corpus: the
        # rule is unenumerated, so `UNKNOWN_RULE_POLICY` escalates it on risk
        # alone and names no tool, and verification then records `not-attempted`
        # for a reason that reads like a budget decision. A ground-truth-confirmed
        # detection can sit here — flagged on risk alone, routed nowhere — which is
        # why the count is surfaced.
        "deterministic_rescans_unroutable": sum(
            1 for f in findings
            if f["deterministic"]["needs_rescan"] and not f["deterministic"]["tool"]
        ),
        "unroutable_rescan_rules": sorted({
            str(f["alert"]["plugin_id"]) for f in findings
            if f["deterministic"]["needs_rescan"] and not f["deterministic"]["tool"]
        }),
        # asked >= evaluated: the gap is findings the model was given and did
        # not answer for. Reported explicitly because it is the denominator of
        # every agreement figure below.
        "llm_findings_asked": len(asked),
        # Candidates pass 1's limit left unsent: never asked, and not counted in
        # the denominator above.
        "llm_findings_deferred": sum(1 for f in findings if f.get("llm_deferred")),
        "llm_evaluated_findings": len(evaluated),
        "llm_findings_unanswered": len(asked) - len(evaluated),
        "llm_rescans": sum(1 for f in evaluated if f["llm"]["needs_rescan"]),
        "agreement": agreement,
        "correlated_synthesis_findings": len(correlated),
        "llm_self_consistency": self_consistency(bundles, findings),
    }


def self_consistency(bundles: list[Bundle],
                     findings: list[dict[str, Any]]) -> dict[str, Any]:
    """How often the LLM arm gave one rule two different verdicts.

    Pass 1 sees exactly one endpoint per call, so it *cannot* know it judged the
    same rule differently next door — and pass 2 caught it doing so, in its own
    words: rule ``10031`` on two routes sharing one handler was "flagged for
    rescan" on ``/user/sign_up`` and "dismissed as likely-false-positive" on
    ``/user/login``. That was an anecdote from one run's prose. This makes it a
    number, computed the same way every run, so the effect of giving pass 1 more
    context (``--peer-context``) can be *measured* rather than asserted.

    Two populations, and the second is the one that matters:

    * **by rule** — the same ZAP rule judged differently anywhere in the scan.
      Some of that is legitimate: two routes with the same rule and genuinely
      different code should get different verdicts.
    * **on shared handlers** — the same rule judged differently on routes that
      run the *same handler function*. There the code is the same, so a split
      verdict is a contradiction unless the reasoning names endpoint-specific
      evidence. This is the honest measure of self-consistency.

    Only answered findings count. An unanswered one is not a disagreement, and
    counting it as agreement would let a lossy run look consistent.
    """
    by_finding = {f["finding_id"]: f for f in findings}
    verdicts: dict[tuple[str, str], set[bool]] = {}
    for bundle in bundles:
        for group in bundle.groups:
            finding = by_finding.get(finding_id(bundle, group))
            llm = (finding or {}).get("llm")
            if not llm:
                continue
            verdicts.setdefault((bundle.identifier, group.plugin_id), set()).add(
                bool(llm.get("needs_rescan"))
            )

    by_rule: dict[str, set[bool]] = {}
    for (_route, plugin), values in verdicts.items():
        by_rule.setdefault(plugin, set()).update(values)
    rules_judged = {p for p, v in by_rule.items() if v}
    rules_split = {p for p, v in by_rule.items() if len(v) > 1}

    # Routes that share a handler and both carry a judged verdict for one rule.
    handlers = shared_handlers(bundles, {b.identifier for b in bundles if b.groups})
    linked: set[frozenset[str]] = set()
    for routes in handlers.values():
        for i, a in enumerate(routes):
            for b in routes[i + 1:]:
                linked.add(frozenset((a, b)))

    pairs_compared = pairs_split = 0
    examples: list[dict[str, Any]] = []
    for pair in sorted(linked, key=lambda p: sorted(p)):
        left, right = sorted(pair)
        for plugin in by_rule:
            here = verdicts.get((left, plugin))
            there = verdicts.get((right, plugin))
            if not here or not there:
                continue
            pairs_compared += 1
            if here | there == {True, False}:
                pairs_split += 1
                if len(examples) < 10:
                    examples.append({"rule": plugin, "routes": [left, right]})

    return {
        "rules_judged": len(rules_judged),
        "rules_with_split_verdicts": len(rules_split),
        "shared_handler_comparisons": pairs_compared,
        "shared_handler_contradictions": pairs_split,
        "shared_handler_examples": examples,
    }


def _reject_duplicate_ids(findings: Iterable[dict[str, Any]],
                          correlated: Iterable[dict[str, Any]]) -> None:
    """A finding_id has to address exactly one finding, or the joins are wrong.

    The verification join (:func:`verification.disposition_summary`) and the SARIF
    writer both key on it, and a duplicate makes each of them resolve to
    whichever entry happens to come first — with no error and no way to tell
    from the artifact. Failing here is the cheap version of that bug; the two
    id spaces are checked together because ``f-`` and ``c-`` findings are
    reached from the same ``supporting_finding_ids`` lists.
    """
    counts = Counter(str(f.get("finding_id") or "")
                     for f in (*findings, *correlated))
    duplicates = sorted(fid for fid, n in counts.items() if n > 1)
    if duplicates:
        shown = ", ".join(duplicates[:5])
        if len(duplicates) > 5:
            shown += f", ... ({len(duplicates)} in total)"
        raise JoinError(
            f"finding_id is not unique: {shown}. Two findings sharing an id "
            "means some field of their identity is missing from the hash in "
            "`finding_id` — see `_identity_key`."
        )


def build_artifact(
    run: RunArtifacts,
    bundles: list[Bundle],
    findings: list[dict[str, Any]],
    correlated: list[dict[str, Any]],
    llm_metadata: dict[str, Any] | None,
    synthesis_metadata: dict[str, Any] | None = None,
    evidence_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the versioned correlation artifact written to `data/`.

    :param evidence_metadata: :meth:`~dast_orchestrator.context.evidence.Assembler.as_dict`
        — what this run's prompts actually held: the excerpt policy, how many
        HTTP exchanges were on disk, the code-context level and the symbol index
        behind it. It was printed at run time and recorded in the *metrics*, but
        never in the artifact, so a stored triage could not say what
        evidence produced it. It has to: verification reads this to resolve the
        same handler source triage saw, and a reader comparing two correlations
        cannot otherwise tell a source-grounded run from a blind one.
    """
    _reject_duplicate_ids(findings, correlated)
    return {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        # The run's directory name, and the join key to every other artifact of
        # it; ``generated_at`` stays the plain scan instant it has always been.
        "run_id": run.timestamp,
        "generated_at": run_paths.split_run_id(run.timestamp)[0],
        # The scan this triage read: its target, ZAP version and source artifacts.
        # Named ``source`` (not ``run``) so it does not read as the run *id* beside
        # it — triage does not mint a run, it is sourced from a stored scan.
        "source": {
            "target": run.zap_report.get("target", ""),
            "zap_version": run.zap_report.get("zap_version", ""),
            "zap_alerts": run.zap_report_path.name,
            "ai_context": run.ai_context_path.name,
            "seed_map": run.seed_map_path.name if run.seed_map_path else None,
        },
        "join": {
            "tiers": [MATCH_SEED, MATCH_REGEX, MATCH_REGEX_PATH_ONLY],
            "seed_map_available": run.seed_map is not None,
            "absent_reasons": {
                CONTEXT_ABSENT_API: "URL under /api/; Noir's go_chi detector does not "
                "see Gitea's locally-constructed API router, so no static context "
                "exists for it (measured recall limitation, not a join failure).",
                CONTEXT_ABSENT_UNMATCHED: "spider-discovered URL that matches no "
                "extracted route template.",
            },
        },
        "rescan_table": {
            "version": rescan_table.RESCAN_TABLE_VERSION,
            "rules": rescan_table.table_as_rows(),
        },
        "llm": llm_metadata,
        # What the prompts actually carried. Beside `llm` rather than inside it
        # because it describes both passes and neither owns it.
        "evidence": evidence_metadata,
        # Pass 2. Kept separate from `llm` because the two passes answer
        # different questions with different prompts, and a reader has to be
        # able to tell which one produced a given finding.
        "synthesis": synthesis_metadata,
        "summary": summarise(
            bundles, findings, correlated, run.zap_report.get("alerts", [])
        ),
        "findings": findings,
        "correlated_findings": correlated,
    }
