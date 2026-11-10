"""The correctness axis (``dast cve``): the project's only external measure of correctness
(everything else is internal agreement), which is why each target is pinned to a
CVE-bearing version.

Detectability is **measured, never asserted** (docs/DETECTABILITY.md): per run the tool
measures the two links it can observe — ``reach`` (did a request arrive at the marker's
sink) and ``observe`` (did success leave a signal, in-band or out-of-band) — and derives a
descriptive single-run ``outcome``; the blind-vs-seeded split is a two-run comparison of a
blind run against its ``--oracle`` counterpart. The marker file holds FACTS ONLY (identity,
one probe, ``zap_rules``, ``seed``, and the ``auth`` the CVE requires), no detectability
claim. → DECISIONS.md, docs/DETECTABILITY.md.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlparse

import yaml

from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.adapters import targets
from dast_orchestrator.foundation import ui

REPO_ROOT = Path(__file__).resolve().parents[3]


#: Beside the target's definition, like its seed scripts and its source clone —
#: under the configurable targets dir, so it follows the tool/targets split.
def markers_path(target_name: str) -> Path:
    return targets.TARGETS_DIR / target_name / targets.MARKERS_NAME


def has_markers(target_name: str) -> bool:
    """Whether a target carries a ground-truth marker set at all.

    Ground truth is an OPTIONAL evaluation layer: a target with no
    ``cve-markers.yml`` is still fully scannable (scan → triage → verify →
    report), it simply has no detection numbers. Callers check this before
    :meth:`MarkerSet.load` so a markerless target no-ops gracefully rather than
    raising — while a markers file that is *present but broken* still fails loud.
    """
    return markers_path(target_name).is_file()


# -- the measured vocabulary (docs/DETECTABILITY.md) -----------------------
#
# Nothing here is set in the marker file: reach/observe are MEASURED per run and
# the outcome is DERIVED from them. The only a-priori fact a marker carries about
# detection is `auth` — the session the CVE requires — because whether a run
# provided it is applicability, not a scanner miss.

#: Single-run reach: a request the tool issued arrived at the marker's sink.
REACH_REACHED = "reached"
REACH_NONE = "none"

#: Single-run observe: success produced a signal the tool could see, on which channel.
OBSERVE_IN_BAND = "in-band"   #: a rule fired strict on the sink, or verification confirmed there
OBSERVE_OOB = "oob"           #: an out-of-band callback landed
OBSERVE_NONE = "none"         #: nothing the tool saw

#: Single-run outcome, derived from reach × observe × auth-applicability.
OUTCOME_DETECTED = "detected"                     #: reached AND observed
OUTCOME_REACHED_UNCONFIRMED = "reached-unconfirmed"  #: reached, no signal
OUTCOME_UNREACHED = "unreached"                   #: the sink entered no tree
OUTCOME_NOT_APPLICABLE = "not-applicable"         #: the run did not provide the marker's auth

OUTCOMES = (OUTCOME_DETECTED, OUTCOME_REACHED_UNCONFIRMED,
            OUTCOME_UNREACHED, OUTCOME_NOT_APPLICABLE)

#: The auth a CVE requires, as a fact about the vulnerability — none < user < admin.
#: A run whose ``auth_mode`` is below a marker's ``auth`` cannot exercise it, which
#: is ``not-applicable (auth)``, NOT a miss.
AUTH_NONE = "none"
AUTH_USER = "user"
AUTH_ADMIN = "admin"
AUTH_VALUES = (AUTH_NONE, AUTH_USER, AUTH_ADMIN)
AUTH_RANK = {AUTH_NONE: 0, AUTH_USER: 1, AUTH_ADMIN: 2}


def auth_applicable(marker_auth: str, run_auth_mode: str) -> bool:
    """Whether a run at ``run_auth_mode`` can exercise a marker needing ``marker_auth``.

    The single source of the none < user < admin rule: a run below a marker's
    required auth cannot reach its sink, which the detection layer records as
    ``not-applicable (auth)`` (never a miss). Reused by the oracle-seeded verify
    dispatch so it never probes — or records — a marker the run cannot reach.
    """
    return AUTH_RANK[marker_auth] <= AUTH_RANK.get(run_auth_mode, 0)

#: The two-run ladder (the blind run vs its ``--oracle`` counterpart). PRINTED by
#: ``dast cve``, never persisted — the analyzer re-derives it from the two
#: single-run ``cve-detection.json`` files (derive-on-read, like ``dast costs``).
LADDER_DETECTED_BLIND = "detected-blind"     #: detected in the blind run — found unaided
LADDER_DETECTED_SEEDED = "detected-seeded"   #: detected only under --oracle
LADDER_REACHED_UNCONFIRMED = "reached-unconfirmed"  #: reached in a run, never observed
LADDER_UNREACHED = "unreached"               #: the sink entered no run's tree
LADDER_NOT_APPLICABLE = "not-applicable"     #: neither run provided the marker's auth
LADDER_TIERS = (LADDER_DETECTED_BLIND, LADDER_DETECTED_SEEDED,
                LADDER_REACHED_UNCONFIRMED, LADDER_UNREACHED, LADDER_NOT_APPLICABLE)


@dataclass(frozen=True)
class Marker:
    """One documented vulnerability, mapped to a request that exercises it.

    FACTS ONLY (docs/DETECTABILITY.md): identity/provenance, one ``probe``
    request, the ``zap_rules`` the detection join keys on, the ``--oracle``
    ``seed``, and ``auth`` — the session the CVE requires. No detectability claim:
    reach/observe/outcome are measured per run, never stored here.
    """

    id: str
    name: str
    cve: str
    fixed_in: str
    description: str
    cwe: str
    zap_rules: tuple[str, ...]
    probe_method: str
    probe_path: str
    expect_status: tuple[int, ...]
    signal: str
    #: The session the CVE requires — ``none`` / ``user`` / ``admin``. A FACT
    #: about the vulnerability (read from its own description), not a measurement:
    #: a run below this auth records ``not-applicable (auth)``, never a miss.
    auth: str = AUTH_NONE
    fix_pr: str = ""
    fix_location: str = ""
    #: Benign URL(s) that make this marker's sink REACHABLE by the scanner, for a
    #: sink no static extractor names and no crawler discovers. ORACLE KNOWLEDGE —
    #: seeded ONLY under a scan's ``--oracle`` (ceiling) mode, never in a blind
    #: run. Each entry must serve THIS marker (:meth:`serves`).
    seed: tuple[str, ...] = ()

    def serves(self, seed_path: str) -> bool:
        """Whether ``seed_path`` is a benign request AT this marker's sink.

        Either the marker's own route (a query-parameter marker, whose sink is a
        fixed route the seed adds the parameter surface to) or, for a path-payload
        marker, a request under its :attr:`seed_base` (the directory the traversal
        escapes from). This is what keeps a seed pinned to the sink it is meant to
        expose rather than widening the attack surface freely.
        """
        route = _norm_path(urlparse(seed_path).path)
        if route == self.probe_route:
            return True
        base = self.seed_base
        return bool(base and base != "/"
                    and (route == base or route.startswith(base + "/")))

    @property
    def probe_route(self) -> str:
        """The marker's own sink, as a path — no query, no trailing slash."""
        return _norm_path(urlparse(self.probe_path).path)

    @property
    def probe_params(self) -> frozenset[str]:
        """The query parameters the marker's request carries the payload in.

        Empty for a marker whose payload lives in the path itself, where the
        route alone is the sink and there is no parameter to agree on.
        """
        return frozenset(
            name for name, _ in parse_qsl(urlparse(self.probe_path).query,
                                          keep_blank_values=True)
        )

    @property
    def path_payload(self) -> bool:
        """True when the payload rides in the URL PATH, not a query parameter.

        Detected by a traversal token (``..`` / ``%2e%2e``) in the path. A query
        marker's sink IS its route; a path-payload marker's sink is a base route
        the scanner must already hold so its own path-injection can reach it (see
        :attr:`seed_base`).
        """
        path = urlparse(self.probe_path).path.lower()
        return ".." in path or "%2e%2e" in path

    @property
    def seed_base(self) -> str:
        """For a path-payload marker, the route a scanner must have in its tree to
        reach the sink: the path up to (not including) the first segment that
        carries the traversal payload. Empty for a query-param marker.
        """
        if not self.path_payload:
            return ""
        kept: list[str] = []
        for seg in urlparse(self.probe_path).path.split("/"):
            low = seg.lower()
            if ".." in low or "%2e%2e" in low:
                break
            kept.append(seg)
        return _norm_path("/".join(kept))


@dataclass
class MarkerSet:
    target: str
    version: str
    markers: list[Marker] = field(default_factory=list)

    def oracle_seeds(self) -> list[str]:
        """Every marker's benign reachability seed, for a scan's ``--oracle`` mode.

        Deduplicated, order-preserving. Seeded ONLY under ``--oracle``: each is
        oracle knowledge (a URL chosen because a documented CVE lives there), so a
        blind run never sees them and its tree is what discovery alone produced.
        """
        seen: set[str] = set()
        out: list[str] = []
        for m in self.markers:
            for s in m.seed:
                if s not in seen:
                    seen.add(s)
                    out.append(s)
        return out

    @classmethod
    def load(cls, target_name: str) -> "MarkerSet":
        path = markers_path(target_name)
        if not path.is_file():
            raise FileNotFoundError(
                f"no CVE markers for {target_name} at {path}. A target is not "
                "integrated until its markers are mapped — see "
                "targets/gitea/cve-markers.yml for the shape."
            )
        data = yaml.safe_load(path.read_text()) or {}
        markers = []
        for raw in data.get("markers", []):
            probe = raw.get("probe") or {}
            seed = tuple(str(s) for s in (raw.get("seed") or []))
            auth = str(raw.get("auth", AUTH_NONE)).strip().lower()
            if auth not in AUTH_RANK:
                raise ValueError(
                    f"{target_name}/{raw.get('id')}: auth={auth!r} is not one of "
                    f"{list(AUTH_VALUES)} — it names the session the CVE requires.")
            marker = Marker(
                id=str(raw["id"]),
                name=str(raw.get("name", raw["id"])),
                cve=str(raw.get("cve", "")),
                fixed_in=str(raw.get("fixed_in", "")),
                description=str(raw.get("description", "")).strip(),
                cwe=str(raw.get("cwe", "")),
                zap_rules=tuple(str(r) for r in (raw.get("zap_rules") or [])),
                probe_method=str(probe.get("method", "GET")).upper(),
                probe_path=str(probe.get("path", "/")),
                expect_status=tuple(int(s) for s in (probe.get("expect_status") or [])),
                signal=str(raw.get("signal", "")).strip(),
                auth=auth,
                fix_pr=str(raw.get("fix_pr", "")),
                fix_location=str(raw.get("fix_location", "")),
                seed=seed,
            )
            # The seed↔sink invariant survives the detection-block removal: a
            # `seed:` present means the marker is seedable (oracle knowledge), and
            # every seed must land at the marker's own sink — otherwise `--oracle`
            # would seed a surface unrelated to the CVE, the free surface-widening
            # the seeding rule forbids.
            for s in seed:
                if not marker.serves(s):
                    raise ValueError(
                        f"{target_name}/{marker.id}: seed {s!r} is not at this "
                        f"marker's sink (route {marker.probe_route!r}"
                        + (f" / base {marker.seed_base!r}" if marker.seed_base else "")
                        + ")")
            markers.append(marker)
        return cls(str(data.get("target", target_name)),
                   str(data.get("version", "")), markers)


# -- joining a scan's artifacts -------------------------------------------


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text()) if path.is_file() else {}


def _norm_path(path: str) -> str:
    """A path with no trailing slash, so ``/downloads`` and ``/downloads/`` agree."""
    path = path or "/"
    return path.rstrip("/") or "/"


def route_reaches_sink(marker: Marker, url: str) -> bool:
    """Did a request at ``url`` land on the marker's sink ROUTE (reach, not observe).

    Route-level only — no parameter condition, because reach asks whether the
    scanner got a request TO the sink, not whether the right input was fuzzed
    there (that is :func:`on_the_markers_own_sink`, the observe join). For a
    path-payload marker the sink is :attr:`Marker.seed_base`; for a query marker
    it is the exact route.
    """
    route = _norm_path(urlparse(url or "").path)
    if marker.path_payload:
        base = marker.seed_base
        if base and base != "/":
            return route == base or route.startswith(base + "/")
    return route == marker.probe_route


def on_the_markers_own_sink(marker: Marker, url: str, param: str) -> bool:
    """Did this alert fire on the marker's actual sink, or merely somewhere?

    The strict half of the join. The generous join asks only whether a rule of
    the right *class* fired anywhere; this asks whether it fired on the request
    the marker maps the CVE to — the same route, and, when the marker's payload
    rides in a query parameter, that same parameter.

    A path-payload marker (traversal) is on its own sink when the alert fired
    under its :attr:`Marker.seed_base` — the route the payload traverses from —
    because ZAP's own traversal payload is never byte-equal to the marker's.
    """
    alert_route = _norm_path(urlparse(url or "").path)
    if marker.path_payload:
        base = marker.seed_base
        if base and base != "/":
            return alert_route == base or alert_route.startswith(base + "/")
    if alert_route != marker.probe_route:
        return False
    return not marker.probe_params or (param or "") in marker.probe_params


#: Tool names / evidence tokens that mark an OUT-OF-BAND confirmation. The
#: pipeline records no per-verification channel field, so the honest proxy is the
#: interactsh sink showing in the tool or the evidence — the only OOB path in the
#: stack (Cacti's CVE-2022-46169 via nuclei → self-hosted interactsh).
_OOB_TOKENS = ("interactsh", "oast", "out-of-band", "out of band")


def _is_oob_confirmation(verif: Mapping[str, Any]) -> bool:
    """Whether a confirmed verification landed out of band (interactsh), by proxy."""
    haystack = " ".join(str(verif.get(k, "")) for k in
                        ("tool", "detail", "evidence", "matched_templates")).lower()
    return any(tok in haystack for tok in _OOB_TOKENS)


#: The per-layer detection fields, in report order. Kept beside the measured
#: outcome because the §T3 analyzer wants detection-per-layer (zap+noir →
#: +deterministic triage → +llm triage → +verification); each names the field an
#: assessment sets when that layer flagged the marker.
LAYERS = (
    ("zap+noir", "zap_detected"),
    ("+deterministic triage", "deterministic_flagged"),
    ("+llm triage", "llm_flagged"),
    ("+verification", "verification_confirmed"),
)


def assess_marker(
    marker: Marker,
    alerts: list[Mapping[str, Any]],
    correlation: Mapping[str, Any],
    verification: Mapping[str, Any],
    reach_paths: "frozenset[str] | None" = None,
    run_auth_mode: str = AUTH_NONE,
) -> dict[str, Any]:
    """One marker's MEASURED assessment for a finished run.

    Measures the two observable links and derives the outcome:

    * **reach** — the marker's sink route is in ``reach_paths`` (the run's
      alert-URL set ∪ its seed-map entries). A documented PROXY: passive rules
      fire on nearly every crawled page, so the alert-URL set ≈ the crawl tree,
      and the full tree is not persisted.
    * **observe** — ``in-band`` if the marker's own rule fired strict on its sink
      or a verification confirmed there; ``oob`` if a confirmation landed out of
      band; else ``none``.
    * **auth applicability** — ``marker.auth`` above ``run_auth_mode`` is
      ``not-applicable (auth)``, never ``unreached``.

    Also carries the per-layer join (generous = a rule of the right class fired
    anywhere, an UPPER bound; strict = it fired on the marker's own sink), which
    the analyzer reads for detection-per-layer.
    """
    rules = set(marker.zap_rules)
    reach_paths = reach_paths if reach_paths is not None else frozenset()
    result: dict[str, Any] = {
        "marker_id": marker.id,
        "cve": marker.cve,
        "name": marker.name,
        "cwe": marker.cwe,
        "fixed_in": marker.fixed_in,
        "auth": marker.auth,
        "zap_rules": sorted(rules),
        "probe_route": marker.probe_route,
        "probe_params": sorted(marker.probe_params),
    }

    def on_sink(url: Any, param: Any) -> bool:
        return on_the_markers_own_sink(marker, str(url or ""), str(param or ""))

    # Layer 1+2: ZAP alerts (the scan already includes Noir seeding).
    matched_alerts = [a for a in alerts if str(a.get("pluginId")) in rules]
    on_sink_alerts = [a for a in matched_alerts
                      if on_sink(a.get("url"), a.get("param"))]
    result["zap_detected"] = bool(matched_alerts)
    result["zap_detected_strict"] = bool(on_sink_alerts)
    result["zap_alert_count"] = len(matched_alerts)
    result["zap_alert_count_strict"] = len(on_sink_alerts)

    # Layer 3: LLM / deterministic triage — a matching finding an arm flagged.
    findings = correlation.get("findings", []) if correlation else []
    marker_findings = [
        f for f in findings
        if str((f.get("alert") or {}).get("plugin_id")) in rules
    ]
    strict_findings = [
        f for f in marker_findings
        if any(on_sink(u, (f.get("alert") or {}).get("param"))
               for u in ((f.get("alert") or {}).get("example_urls") or []))
    ]
    result["in_correlation"] = bool(marker_findings)
    result["in_correlation_strict"] = bool(strict_findings)
    for suffix, group in (("", marker_findings), ("_strict", strict_findings)):
        result[f"llm_flagged{suffix}"] = any(
            (f.get("llm") or {}).get("needs_rescan") for f in group)
        result[f"deterministic_flagged{suffix}"] = any(
            (f.get("deterministic") or {}).get("needs_rescan") for f in group)
        # Whether the LLM arm was ASKED at all (pass 1 is per-endpoint; a finding
        # whose alert joined no endpoint bundle carries `llm: null`). A measured
        # zero and a missing measurement must not look alike.
        result[f"llm_asked{suffix}"] = any(f.get("llm") is not None for f in group)

    # Layer 4: verification confirmed a finding on one of the rules.
    verifs = (verification.get("verifications", []) if verification else [])
    marker_verifs = [v for v in verifs if str(v.get("plugin_id")) in rules]
    strict_verifs = [v for v in marker_verifs
                     if on_sink(v.get("target"), v.get("param"))]
    result["verification_outcomes"] = [str(v.get("outcome")) for v in marker_verifs]
    result["verification_outcomes_strict"] = [
        str(v.get("outcome")) for v in strict_verifs]
    result["verification_confirmed"] = "confirmed" in result["verification_outcomes"]
    result["verification_confirmed_strict"] = (
        "confirmed" in result["verification_outcomes_strict"])

    # -- the measured links + the derived outcome --------------------------
    reached = (any(route_reaches_sink(marker, p) for p in reach_paths)
               or result["zap_detected_strict"]
               or result["verification_confirmed_strict"])
    confirmed_strict = [v for v in strict_verifs
                        if str(v.get("outcome")) == "confirmed"]
    in_band = (result["zap_detected_strict"]
               or any(not _is_oob_confirmation(v) for v in confirmed_strict))
    oob = any(_is_oob_confirmation(v) for v in confirmed_strict)
    observe = (OBSERVE_IN_BAND if in_band
               else OBSERVE_OOB if oob else OBSERVE_NONE)

    applicable = auth_applicable(marker.auth, run_auth_mode)
    if not applicable:
        outcome, reason = OUTCOME_NOT_APPLICABLE, "auth"
    elif observe != OBSERVE_NONE:
        outcome, reason, reached = OUTCOME_DETECTED, "", True
    elif reached:
        outcome, reason = OUTCOME_REACHED_UNCONFIRMED, ""
    else:
        outcome, reason = OUTCOME_UNREACHED, ""

    result["reach"] = REACH_REACHED if reached else REACH_NONE
    result["observe"] = observe
    result["outcome"] = outcome
    result["not_applicable_reason"] = reason
    return result


def single_run_table(assessments: list[dict[str, Any]]) -> dict[str, Any]:
    """The single-run summary: markers grouped by their measured outcome.

    No ladder and no rate here — the blind-vs-seeded split and the rates are a
    two-run comparison (:func:`compare_runs`). This file is what each run saw.
    """
    by_outcome: dict[str, list[str]] = {o: [] for o in OUTCOMES}
    observe_counts: dict[str, int] = {OBSERVE_IN_BAND: 0, OBSERVE_OOB: 0,
                                      OBSERVE_NONE: 0}
    for a in assessments:
        by_outcome.setdefault(a.get("outcome", OUTCOME_UNREACHED), []).append(
            a.get("marker_id", ""))
        observe_counts[a.get("observe", OBSERVE_NONE)] = (
            observe_counts.get(a.get("observe", OBSERVE_NONE), 0) + 1)
    return {
        "markers_total": len(assessments),
        "by_outcome": {o: len(ids) for o, ids in by_outcome.items()},
        "outcomes": by_outcome,
        "observe": observe_counts,
        "reached": sum(1 for a in assessments
                       if a.get("reach") == REACH_REACHED),
    }


def _reach_paths(zap: Mapping[str, Any], seed_map: Mapping[str, Any]) -> frozenset[str]:
    """The run's reach set: every path the scan touched — the alert-URL set
    (passive rules fire on nearly every crawled page, so it ≈ the crawl tree) plus
    the Noir/oracle seed-map entries. A documented PROXY (docs/DETECTABILITY.md).
    """
    paths: set[str] = set()
    for alert in zap.get("alerts", []) or []:
        url = alert.get("url")
        if url:
            paths.add(str(url))
    for entry in (seed_map.get("entries", []) if seed_map else []) or []:
        for key in ("url", "path"):
            if entry.get(key):
                paths.add(str(entry[key]))
    return frozenset(paths)


def _run_oracle_guided(run: run_paths.RunLayout, suffix: str) -> bool:
    """Whether this run was ``--oracle``-guided, from its artifacts.

    Read from the triage/verification artifact's ``oracle_guided`` flag, falling
    back to the scan's recorded ``oracle_seeds`` config — the scan writes that key
    only when it seeded documented sinks, so its presence IS the blind/ceiling
    distinction.
    """
    for name in (run_paths.TRIAGE, run_paths.VERIFICATION):
        data = _load(run.path(name, suffix))
        if "oracle_guided" in data:
            return bool(data["oracle_guided"])
    scan_cfg = (_load(run.path(run_paths.metrics_basename("scan"))) or {}).get(
        "config") or {}
    return bool(scan_cfg.get("oracle_seeds"))


def assess_run(marker_set: MarkerSet, run: run_paths.RunLayout,
               suffix: str = "") -> dict[str, Any]:
    """One run's measured assessment — the single-run ``cve-detection.json``.

    :param suffix: which variant of the triage/verification artifacts to read
        (``triage-<suffix>.json``). A harness row is a suffix; the scan's alerts
        are never suffixed.
    """
    triage_path = run.path(run_paths.TRIAGE, suffix)
    verify_path = run.path(run_paths.VERIFICATION, suffix)
    # A missing artifact and a genuinely empty one must not read alike: say which
    # is absent so the layers it feeds read as not-measured, not zero detection.
    absent = [name for name, path in (("triage", triage_path),
                                      ("verification", verify_path))
              if not path.is_file()]
    if absent:
        which = f" for suffix {suffix!r}" if suffix else ""
        ui.warn(f"{', '.join(absent)}{which} not found in {run.run_id} — the "
                f"layers it feeds (+{'/'.join(absent)}) are NOT MEASURED here, "
                "not zero detection. Pass --out-suffix for a harness row's variant.")
    zap = _load(run.path(run_paths.ZAP_ALERTS))
    seed_map = _load(run.path(run_paths.NOIR_SEED_MAP))
    correlation = _load(triage_path)
    verification = _load(verify_path)
    auth_mode = str(zap.get("auth_mode", AUTH_NONE))
    reach_paths = _reach_paths(zap, seed_map)
    assessments = [
        assess_marker(m, zap.get("alerts", []), correlation, verification,
                      reach_paths=reach_paths, run_auth_mode=auth_mode)
        for m in marker_set.markers
    ]
    return {
        "schema_version": 3,
        "run_id": run.run_id,
        "target": marker_set.target,
        "target_version": marker_set.version,
        "auth_mode": auth_mode,
        "oracle_guided": _run_oracle_guided(run, suffix),
        "suffix": suffix,
        "artifacts_present": {
            "zap_alerts": bool(zap),
            "correlation": bool(correlation),
            "verification": bool(verification),
        },
        "summary": single_run_table(assessments),
        "markers": assessments,
    }


# -- the two-run comparison (printed, never persisted) ---------------------


def compare_runs(blind: Mapping[str, Any],
                 oracle: Mapping[str, Any]) -> dict[str, Any]:
    """The blind-vs-``--oracle`` ladder, from two single-run assessments.

    Per marker: ``detected-blind`` (detected in the blind run), ``detected-seeded``
    (detected only under --oracle), ``reached-unconfirmed`` (reached in a run,
    never observed), ``unreached``, ``not-applicable`` (neither run provided the
    marker's auth). The blind/ceiling RATES are against the whole marker set.
    """
    blind_by_id = {a["marker_id"]: a for a in blind.get("markers", [])}
    oracle_by_id = {a["marker_id"]: a for a in oracle.get("markers", [])}
    ids = list(blind_by_id) + [i for i in oracle_by_id if i not in blind_by_id]

    ladder: dict[str, list[str]] = {tier: [] for tier in LADDER_TIERS}
    for mid in ids:
        b = blind_by_id.get(mid, {})
        o = oracle_by_id.get(mid, {})
        b_out, o_out = b.get("outcome"), o.get("outcome")
        if OUTCOME_NOT_APPLICABLE in (b_out, o_out) and OUTCOME_DETECTED not in (
                b_out, o_out):
            tier = LADDER_NOT_APPLICABLE
        elif b_out == OUTCOME_DETECTED:
            tier = LADDER_DETECTED_BLIND
        elif o_out == OUTCOME_DETECTED:
            tier = LADDER_DETECTED_SEEDED
        elif REACH_REACHED in (b.get("reach"), o.get("reach")):
            tier = LADDER_REACHED_UNCONFIRMED
        else:
            tier = LADDER_UNREACHED
        ladder[tier].append(mid)

    total = len(ids)
    detected_blind = len(ladder[LADDER_DETECTED_BLIND])
    detected_seeded = len(ladder[LADDER_DETECTED_SEEDED])
    return {
        "target": blind.get("target") or oracle.get("target", "?"),
        "blind_run": blind.get("run_id", ""),
        "oracle_run": oracle.get("run_id", ""),
        "markers_total": total,
        "ladder": ladder,
        "blind_rate": round(detected_blind / total, 3) if total else 0.0,
        "ceiling_rate": (round((detected_blind + detected_seeded) / total, 3)
                         if total else 0.0),
        "not_applicable": ladder[LADDER_NOT_APPLICABLE],
    }


# -- CLI -------------------------------------------------------------------


def _print_single(result: Mapping[str, Any]) -> None:
    summary = result.get("summary") or {}
    by = summary.get("by_outcome") or {}
    ui.item("run", f"{result.get('run_id','?')}  ·  auth {result.get('auth_mode','?')}"
                   f"  ·  {'--oracle' if result.get('oracle_guided') else 'blind'}")
    ui.item("markers", f"{summary.get('markers_total', 0)} total  ·  "
                       + ", ".join(f"{o} {by.get(o, 0)}" for o in OUTCOMES))


def _print_ladder(ladder: Mapping[str, Any]) -> None:
    total = ladder.get("markers_total", 0)
    ui.item("compared", f"blind {ladder.get('blind_run','?')}  vs  "
                        f"oracle {ladder.get('oracle_run','?')}")
    rungs = ladder.get("ladder") or {}
    for tier in LADDER_TIERS:
        ids = rungs.get(tier) or []
        shown = ", ".join(ids) if ids else "—"
        ui.item(tier, f"{len(ids)}/{total}  {shown}")
    ui.item("blind rate", f"{ladder.get('blind_rate', 0):.3f}  "
                          f"({len(rungs.get(LADDER_DETECTED_BLIND, []))}/{total})")
    ui.item("ceiling rate", f"{ladder.get('ceiling_rate', 0):.3f}  "
            f"({len(rungs.get(LADDER_DETECTED_BLIND, [])) + len(rungs.get(LADDER_DETECTED_SEEDED, []))}/{total})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dast cve", description=config.command_description(__doc__))
    parser.add_argument(
        "runs", nargs="+", metavar="<run-id>",
        help="One or two finished runs to assess against cve-markers.yml. TWO run "
             "ids — one blind, one --oracle — are compared and the ladder printed. "
             "ONE run id auto-runs its flipped counterpart (the same scan config "
             "with --oracle toggled), then compares. Resolved against data/runs "
             "and data/harness/* like `dast costs`; `latest` is accepted.")
    parser.add_argument(
        "--target-name", default="",
        help="Marker set to use (default: derived from the run).")
    parser.add_argument(
        "--out-suffix", dest="out_suffix", default="",
        help="Assess a SUFFIXED variant of the triage/verification artifacts "
             "(triage-<suffix>.json), which is what a harness row writes.")
    config.normalize_metavars(parser)
    return parser


# -- resolving run ids across the data layout ------------------------------


def _data_root() -> Path:
    return run_paths.DATA_ROOT


def resolve_run_anywhere(ident: str) -> "run_paths.RunLayout | None":
    """Find a run by id across ``data/runs`` AND every ``data/harness/<sheet>``.

    The same two places ``dast costs`` reads. ``latest`` resolves to the newest
    run holding a scan's alerts under ``data/runs``. Returns ``None`` when nothing
    matches — the caller turns that into an accumulated error.
    """
    root = _data_root()
    runs_dir = run_paths.default_runs_dir(root)
    if run_paths.is_latest(ident):
        return run_paths.RunLayout.latest_with(runs_dir, run_paths.ZAP_ALERTS)
    search = [runs_dir]
    harness_root = root / run_paths.HARNESS_DIR_NAME
    if harness_root.is_dir():
        search += sorted(p for p in harness_root.iterdir() if p.is_dir())
    for data_dir in search:
        layout = run_paths.RunLayout(data_dir, ident)
        if layout.dir.is_dir():
            return layout
        for run_id in run_paths.RunLayout.runs(data_dir):
            if run_id.startswith(f"{ident}-"):
                return run_paths.RunLayout(data_dir, run_id)
    return None


def _scan_config(run: run_paths.RunLayout) -> dict[str, Any]:
    """The run's recorded scan configuration (its scan-metrics ``config`` block)."""
    record = _load(run.path(run_paths.metrics_basename("scan")))
    return dict(record.get("config") or {})


def _config_fingerprint(run: run_paths.RunLayout) -> str:
    """A digest of the run's scan config with the oracle seeding REMOVED.

    Two runs that differ only in ``--oracle`` share this fingerprint; anything
    else differs, which is how the comparison warns that a pair is not strictly
    blind-vs-ceiling of one configuration.
    """
    cfg = {k: v for k, v in _scan_config(run).items() if k != "oracle_seeds"}
    return run_paths.config_digest(cfg)


# -- re-running the flipped counterpart ------------------------------------
#
# KNOWN LIMITATION — a target whose CVEs span auth modes:
#   * one scan runs at a single auth mode (`--auth`), but a target's markers can
#     require different sessions (some none, some user, some admin);
#   * the flipped counterpart re-runs at the SAME auth mode as the source run, so
#     a marker needing a higher auth stays `not-applicable (auth)` in BOTH runs
#     and the pair cannot cover it;
#   * fully covering such a target therefore needs a pair PER auth mode, and the
#     comparison warns when the pair leaves markers uncovered. (README remark.)


def _flip_argv(run: run_paths.RunLayout, oracle_guided: bool) -> list[str]:
    """The ``dast scan triage verify`` argv that reproduces this run's SCAN config
    with ``--oracle`` toggled.

    The scan configuration is what defines the corpus (the run-id digest), and it
    is cleanly replayable from the scan-metrics ``config`` block. Triage/verify
    take their configuration from the ambient env file — so a stable env file
    makes the counterpart faithful, and a drift is caught by the comparison's
    "configs differ" warning. Target-derived scan settings (structural params,
    scan headers, per-rule tuning) come from the target definition and need no
    flag.
    """
    cfg = _scan_config(run)
    target = run.target
    argv = ["scan", "triage", "verify", target, "--data-dir",
            str(run_paths.default_runs_dir())]
    flagmap: list[tuple[str, str]] = [
        ("target_url", "--target"),
        ("auth_mode", "--auth"),
        ("max_scan_minutes", "--max-active-scan-minutes"),
        ("max_rule_minutes", "--max-rule-minutes"),
        ("injectable_targets", "--injectable-targets"),
        ("max_alerts_per_rule", "--max-alerts-per-rule"),
        ("noir_image", "--noir-image"),
        ("zap_mode", "--zap-mode"),
        ("spiders", "--spider"),
    ]
    for key, flag in flagmap:
        value = cfg.get(key)
        if value not in (None, ""):
            argv += [flag, str(value)]
    argv.append("--use-noir" if cfg.get("use_noir", True) else "--no-noir")
    if cfg.get("add_query_param"):
        argv.append("--add-query-param")
    if cfg.get("passive_only"):
        argv.append("--passive-only")
    for rule in cfg.get("disabled_rules") or []:
        argv += ["--disable-rule", str(rule)]
    # Flip the oracle flag. --oracle is shared across scan/triage/verify, so one
    # flag toggles the whole chain's polarity.
    if not oracle_guided:
        argv.append("--oracle")
    return argv


def run_flipped_counterpart(run: run_paths.RunLayout, oracle_guided: bool) -> str:
    """Re-execute the pipeline with ``run``'s scan config and ``--oracle`` toggled;
    return the new run id (or ``""`` on failure).

    Live: it drives a real scan and spends the key on triage/verify. No prompt —
    the user asked for the counterpart to be produced, not offered.
    """
    from dast_orchestrator import cli

    argv = _flip_argv(run, oracle_guided)
    before = set(run_paths.RunLayout.runs(run_paths.default_runs_dir()))
    ui.step("running the flipped counterpart: "
            + ("blind" if oracle_guided else "--oracle")
            + f" ({' '.join(argv)})")
    code = cli.main(argv)
    if code != 0:
        ui.warn(f"the flipped counterpart failed (exit {code}); cannot compare.")
        return ""
    minted = sorted(set(run_paths.RunLayout.runs(run_paths.default_runs_dir()))
                    - before)
    return minted[-1] if minted else ""


def _assess_and_write(run: run_paths.RunLayout, target_name: str,
                      suffix: str) -> "dict[str, Any] | None":
    """Assess one run, write its ``cve-detection.json``, and return the result."""
    try:
        marker_set = MarkerSet.load(target_name)
    except FileNotFoundError as exc:
        ui.error(str(exc))
        return None
    result = assess_run(marker_set, run, suffix)
    out = run.ensure().path(run_paths.CVE_DETECTION, suffix)
    out.write_text(json.dumps(result, indent=2))
    ui.found(f"written to {out.name}")
    return result


def main(argv: "list[str] | None" = None) -> int:
    args = build_parser().parse_args(argv)
    errors: list[str] = []
    warnings: list[str] = []

    # Resolve every positional to a run, accumulating. A target name or a bare
    # string where a run id is needed is an error, not a silent probe.
    resolved: list[run_paths.RunLayout] = []
    for ident in args.runs:
        if ident in targets.REGISTRY:
            errors.append(
                f"{ident!r} is a target name, not a run id — `dast cve` takes "
                "finished runs only (the live-probe mode was removed).")
            continue
        layout = resolve_run_anywhere(ident)
        if layout is None:
            errors.append(f"{ident!r} resolves to no run under data/runs or "
                          "data/harness/*.")
            continue
        resolved.append(layout)

    if len(args.runs) > 2:
        errors.append(f"at most two run ids (a blind/--oracle pair); got "
                      f"{len(args.runs)}.")

    if errors:
        for line in errors:
            ui.error(line)
        return 1

    ui.headline("CVE detection — measured against ground truth",
                " · ".join(r.run_id for r in resolved))

    # One run → assess it, run the flipped counterpart, then compare.
    if len(resolved) == 1:
        run = resolved[0]
        target_name = args.target_name or run.target or "gitea"
        if not has_markers(target_name):
            ui.step(f"{target_name} carries no {targets.MARKERS_NAME} — no ground "
                    "truth to assess against.")
            return 0
        oracle_guided = _run_oracle_guided(run, args.out_suffix)
        first = _assess_and_write(run, target_name, args.out_suffix)
        if first is None:
            return 1
        _print_single(first)
        minted = run_flipped_counterpart(run, oracle_guided)
        if not minted:
            ui.warn("no counterpart to compare against; single-run result stands.")
            return 0
        other = run_paths.RunLayout(run_paths.default_runs_dir(), minted)
        second = _assess_and_write(other, target_name, args.out_suffix)
        if second is None:
            return 1
        pair = [first, second]
    else:
        pair = []
        for run in resolved:
            target_name = args.target_name or run.target or "gitea"
            if not has_markers(target_name):
                ui.step(f"{target_name} carries no {targets.MARKERS_NAME} — no "
                        "ground truth to assess against.")
                return 0
            result = _assess_and_write(run, target_name, args.out_suffix)
            if result is None:
                return 1
            _print_single(result)
            pair.append(result)

        # Both-same-polarity is an error; differing scan configs a warning.
        if pair[0].get("oracle_guided") == pair[1].get("oracle_guided"):
            which = "--oracle" if pair[0].get("oracle_guided") else "blind"
            errors.append(f"both runs are {which} — a comparison needs one blind "
                          "and one --oracle run.")
        if _config_fingerprint(resolved[0]) != _config_fingerprint(resolved[1]):
            warnings.append("the two runs' scan configs differ beyond the oracle "
                            "flag — the ladder is not a clean blind-vs-ceiling of "
                            "one configuration.")

    if errors:
        for line in errors:
            ui.error(line)
        return 1

    # Order the pair blind-first, then compare.
    blind = next((p for p in pair if not p.get("oracle_guided")), pair[0])
    oracle = next((p for p in pair if p.get("oracle_guided")), pair[-1])
    ladder = compare_runs(blind, oracle)
    if ladder["not_applicable"]:
        warnings.append(
            f"{len(ladder['not_applicable'])} marker(s) left not-applicable (auth): "
            f"{', '.join(ladder['not_applicable'])} — the pair ran at auth "
            f"{blind.get('auth_mode')!r}, below what those CVEs require. Cover "
            "them with a pair at the needed auth mode.")

    ui.phase("The ladder — blind vs the --oracle ceiling")
    _print_ladder(ladder)
    for line in warnings:
        ui.warn(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
