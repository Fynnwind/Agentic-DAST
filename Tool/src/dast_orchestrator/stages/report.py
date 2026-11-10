"""Merge the three readings into a SARIF 2.1.0 report and a Markdown summary (``dast report``).

Two rule-id namespaces, as the architecture requires: ZAP's rules mirrored on an
``owasp-zap`` tool extension, and the self-authored cross-endpoint synthesis rules on the
driver — linked via each synthesis rule's ``relationships`` and result-level
``relatedLocations`` / ``supportingFindingGuids`` (SARIF 2.1.0 has no
``result.relationships``). The verification outcome rides in a result's ``properties`` and
colours the summary but never changes ``level`` (ZAP's risk sets that), and no model writes
findings prose — templates only. → DECISIONS.md.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable

from dast_orchestrator.foundation import config
from dast_orchestrator.foundation import run_lock
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.foundation import schema
from dast_orchestrator.foundation import ui
from dast_orchestrator.domain import verification

REPO_ROOT = Path(__file__).resolve().parents[3]
#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

#: Stable namespace for result guids, so two reports of the same run agree and
#: correlated results can reference per-alert results by guid.
_GUID_NAMESPACE = uuid.UUID("6f1b1e9a-0000-4000-8000-da57da57da57")

ZAP_COMPONENT_NAME = "owasp-zap"
DRIVER_NAME = "dast-orchestrator"

#: ZAP risk -> SARIF level. Risk sets severity; the verification verdict never
#: overrides it, so a refuted finding is not hidden.
_RISK_LEVEL = {
    "High": "error",
    "Medium": "warning",
    "Low": "note",
    "Informational": "none",
}


def _guid(finding_id: str) -> str:
    return str(uuid.uuid5(_GUID_NAMESPACE, finding_id))


# -- namespace 1: mirrored ZAP rules ---------------------------------------


def zap_rules(findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """One reportingDescriptor per ZAP plugin that fired, plus an id->index map."""
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        alert = finding.get("alert") or {}
        pid = str(alert.get("plugin_id") or "")
        if not pid or pid in seen:
            continue
        seen[pid] = {
            "id": pid,
            "name": str(alert.get("name") or f"ZAP rule {pid}"),
            "shortDescription": {"text": str(alert.get("name") or f"ZAP rule {pid}")},
            "properties": {
                "namespace": "zap-mirror",
                "cweid": str(alert.get("cweid") or ""),
            },
        }
    rules = list(seen.values())
    return rules, {pid: i for i, pid in enumerate(seen)}


# -- namespace 2: self-authored synthesis rules ----------------------------

#: The one rule id in namespace 2 that describes a *concrete* vulnerability at
#: one URL rather than a cross-endpoint pattern. It exists because a confirmed
#: sibling is neither a ZAP finding (there is no alert) nor a synthesis claim
#: (it is settled, not predicted), and filing it under either would misreport
#: what the pipeline knows.
PROPAGATION_CONFIRMED_RULE = "propagation-confirmed-sibling"


#: The synthesis-rule catalogue. Ids match the synthesis ``pattern`` field, so
#: a synthesis finding's ``pattern`` is exactly its ``ruleId`` in namespace 2.
SYNTHESIS_RULES = {
    "propagation-shared-handler": (
        "Vulnerability propagates via a shared handler",
        "A finding on one route is likely to recur on sibling routes that share "
        "the same Noir-identified handler, even when the scanner never flagged them.",
    ),
    "systemic-absence": (
        "Systemic absence of a protection across a route family",
        "A missing header or guard observed across many routes of one family is a "
        "single systemic gap, not a set of independent per-endpoint misconfigurations.",
    ),
    "missing-guard-family": (
        "Missing input-validation guard across a route family",
        "A validation weakness on one route suggests the same guard is missing on "
        "the family of routes sharing its shape or handler.",
    ),
    PROPAGATION_CONFIRMED_RULE: (
        "Vulnerability confirmed on a route the scan never flagged",
        "A propagation claim named a sibling route the scanner never reached, a "
        "probe was aimed at a URL built from that route's template, and an "
        "independent tool reproduced the weakness there. This is a real finding "
        "the DAST scan did not produce: the crawl never visited the route, so no "
        "alert exists for it and no per-endpoint triage ever saw it.",
    ),
}


def synthesis_rules(correlated: list[dict[str, Any]],
                      findings_by_id: dict[str, dict[str, Any]],
                      zap_index: dict[str, int],
                      extra_patterns: "Iterable[str]" = ()) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Synthesis reportingDescriptors, each linked to the ZAP rules it rests on.

    The rule→rule link is the cross-namespace relationship: a synthesis rule
    declares ``relationships`` (kind ``relevant``) to every ZAP plugin id among
    the supporting findings of the synthesis claims that use it.

    :param extra_patterns: rule ids used by results that are not in
        ``correlated`` — today only :data:`PROPAGATION_CONFIRMED_RULE`, whose
        results come from the *verification* artifact rather than the
        synthesis claims (``correlated_findings``).
    """
    # First-appearance order (correlated claims, then extra patterns), de-duplicated.
    # NEVER a set here: its iteration order is hash-seed-dependent, which made the
    # synthesis-rule namespace and its relationships serialise differently per
    # process and broke byte-for-byte report reproducibility.
    patterns_used = list(dict.fromkeys(
        [c.get("pattern") for c in correlated] + list(extra_patterns)))
    # Which ZAP rules underpin each synthesis pattern, for the relationships.
    related_zap: dict[str, set[str]] = {}
    for c in correlated:
        pattern = c.get("pattern")
        for fid in c.get("supporting_finding_ids") or []:
            support = findings_by_id.get(fid)
            if support:
                pid = str((support.get("alert") or {}).get("plugin_id") or "")
                if pid:
                    related_zap.setdefault(pattern, set()).add(pid)

    rules: list[dict[str, Any]] = []
    for pattern in patterns_used:
        title, desc = SYNTHESIS_RULES.get(
            pattern, (pattern or "synthesis finding", "Cross-endpoint synthesis finding.")
        )
        rule: dict[str, Any] = {
            "id": pattern or "correlated-finding",
            "name": (pattern or "correlated-finding").replace("-", "_"),
            "shortDescription": {"text": title},
            "fullDescription": {"text": desc},
            "properties": {"namespace": "dast-synthesis"},
        }
        relationships = [
            {
                "target": {
                    "id": pid,
                    "index": zap_index[pid],
                    "toolComponent": {"name": ZAP_COMPONENT_NAME},
                },
                "kinds": ["relevant"],
                "description": {
                    "text": f"Correlation rests on ZAP rule {pid} findings."
                },
            }
            for pid in sorted(related_zap.get(pattern, set()))
            if pid in zap_index
        ]
        if relationships:
            rule["relationships"] = relationships
        rules.append(rule)
    return rules, {r["id"]: i for i, r in enumerate(rules)}


# -- results ---------------------------------------------------------------


def _location(url: str, message: str | None = None) -> dict[str, Any]:
    loc: dict[str, Any] = {
        "physicalLocation": {"artifactLocation": {"uri": url}}
    }
    if message:
        loc["message"] = {"text": message}
    return loc


def _attach_disposition(result: dict[str, Any],
                        disposition: "tuple[str, str] | None") -> None:
    """Mirror a result's disposition and its reason into the SARIF property bag.

    The label (confirmed / refuted / requires-triage / informational) and the
    one-line reason come from :func:`classify_finding` / :func:`classify_synthesis`
    — the same functions the Markdown summary reads — so the machine-readable
    report and the human one can never say different things about an item.

    :param disposition: the ``(label, reason)`` pair, or ``None`` to attach nothing.
    """
    if disposition:
        result["properties"]["disposition"] = disposition[0]
        result["properties"]["disposition_reason"] = disposition[1]


def _attach_worklist(result: dict[str, Any], place: dict[str, Any]) -> None:
    """Mirror where a result sits in the reader's order into the SARIF.

    ``rank`` is ordinal, not a score. ``kind`` stays unset, because SARIF §3.27.10
    requires ``level`` ``none`` on any kind but ``fail``, and ZAP's risk owns ``level``.

    :param place: the result's entry in :func:`verification.build_worklist`'s ``items``.
    """
    result["rank"] = place["rank"]
    result["properties"]["worklist_section"] = place["section"]
    result["properties"]["worklist_group"] = place["group"]
    result["properties"]["worklist_line"] = place["line"]


def _finding_result(finding: dict[str, Any], zap_index: dict[str, int],
                    verdict: dict[str, Any] | None,
                    disposition: "tuple[str, str] | None" = None) -> dict[str, Any]:
    alert = finding.get("alert") or {}
    pid = str(alert.get("plugin_id") or "")
    urls = alert.get("example_urls") or []
    det = finding.get("deterministic") or {}
    llm = finding.get("llm") or {}

    parts = [f"{alert.get('name', 'ZAP finding')} ({alert.get('risk', '?')} risk, "
             f"{alert.get('confidence', '?')} confidence)"]
    parts.append(
        f"deterministic: {'rescan' if det.get('needs_rescan') else 'accept'}"
        + (f" -> {det.get('tool')}" if det.get("needs_rescan") and det.get("tool") else "")
    )
    if llm:
        parts.append(f"llm: {'rescan' if llm.get('needs_rescan') else 'accept'} "
                     f"({llm.get('verdict', '?')})")
    if verdict:
        parts.append(f"verification: {verdict.get('outcome', '?')}"
                     + (f" — {verdict.get('evidence')}" if verdict.get("evidence") else ""))

    # GitLab builds a DAST vulnerability's *location* from path + method +
    # parameter. The path is the result location's URI; the method and the
    # flagged parameter travel both in the SARIF-native ``webRequest`` (the
    # standard home for the HTTP request behind a web result) and, mirrored, in
    # the property bag, so a SARIF->GitLab mapping has all three without parsing.
    method = str(alert.get("method") or "GET")
    param = str(alert.get("param") or "")
    result: dict[str, Any] = {
        "ruleId": pid,
        "ruleIndex": zap_index.get(pid, -1),
        "rule": {
            "id": pid,
            "index": zap_index.get(pid, -1),
            "toolComponent": {"name": ZAP_COMPONENT_NAME},
        },
        "level": _RISK_LEVEL.get(str(alert.get("risk") or ""), "none"),
        "message": {"text": " | ".join(parts)},
        "guid": _guid(finding["finding_id"]),
        "locations": [_location(urls[0])] if urls else [],
        "properties": {
            "finding_id": finding["finding_id"],
            "namespace": "zap-mirror",
            "join_tier": finding.get("static_context"),
            "deterministic": det,
            "llm": llm or None,
            "agreement": finding.get("agreement"),
            "method": method,
            "param": param,
        },
    }
    web_request: dict[str, Any] = {"method": method}
    if urls:
        web_request["target"] = urls[0]
    if param:
        # name -> the value ZAP attacked it with (empty when not recorded); the
        # name is what a GitLab location's `param` reads.
        web_request["parameters"] = {param: str(alert.get("attack") or "")}
    result["webRequest"] = web_request
    instances = alert.get("instances")
    if isinstance(instances, int) and instances >= 1:
        result["occurrenceCount"] = instances
    if verdict:
        result["properties"]["verification"] = verdict
    _attach_disposition(result, disposition)
    return result


def _correlated_result(correlated: dict[str, Any], corr_index: dict[str, int],
                       findings_by_id: dict[str, dict[str, Any]],
                       verdict: dict[str, Any] | None,
                       disposition: "tuple[str, str] | None" = None) -> dict[str, Any]:
    pattern = correlated.get("pattern") or "correlated-finding"
    severity = str(correlated.get("severity") or "medium").capitalize()
    level = {"High": "error", "Medium": "warning", "Low": "note"}.get(severity, "warning")

    related_locations = []
    supporting_guids = []
    for fid in correlated.get("supporting_finding_ids") or []:
        supporting_guids.append(_guid(fid))
        support = findings_by_id.get(fid)
        urls = (support or {}).get("alert", {}).get("example_urls") or []
        if urls:
            related_locations.append(_location(urls[0], f"supporting finding {fid}"))

    msg = correlated.get("title", "Correlated finding")
    if verdict:
        msg += f" | verification (via {verdict.get('via_finding_id', '?')}): {verdict.get('outcome')}"

    result: dict[str, Any] = {
        "ruleId": pattern,
        "ruleIndex": corr_index.get(pattern, -1),
        "level": level,
        "message": {"text": msg},
        "guid": _guid(correlated["finding_id"]),
        "relatedLocations": related_locations,
        "properties": {
            "finding_id": correlated["finding_id"],
            "namespace": "dast-synthesis",
            "origin": correlated.get("origin"),
            "confidence": correlated.get("confidence"),
            "affected_routes": correlated.get("affected_routes"),
            "supporting_finding_ids": correlated.get("supporting_finding_ids"),
            "supportingFindingGuids": supporting_guids,
        },
    }
    if verdict:
        result["properties"]["verification"] = verdict
    _attach_disposition(result, disposition)
    return result


def _sibling_result(record: dict[str, Any], corr_index: dict[str, int]) -> dict[str, Any]:
    """A confirmed sibling as its own SARIF result.

    Reported as a finding, not as a footnote to the claim that predicted it: an
    independent tool reproduced a weakness at a concrete URL, which is the same
    standard every other confirmed result in this file meets. What is different
    is only its *provenance*, and that travels in ``properties`` — the claim, the
    anchor finding, how the URL was derived, and the fact that no ZAP alert
    underlies it. A reader (and the detection-rate accounting) can therefore see
    that the LLM layer reached this route and the crawl did not, without the
    finding being filed as suspect.
    """
    result: dict[str, Any] = {
        "ruleId": PROPAGATION_CONFIRMED_RULE,
        "ruleIndex": corr_index.get(PROPAGATION_CONFIRMED_RULE, -1),
        "level": "error",
        "message": {"text": (
            f"{record.get('rule_name') or 'Propagated weakness'} — confirmed by "
            f"{record.get('tool')} at {record.get('route')}, a route the scan "
            f"never flagged. Predicted by claim {record.get('claim_id')}."
        )},
        "guid": _guid(record["finding_id"]),
        "locations": [_location(record.get("target", ""), record.get("route", ""))],
        "relatedLocations": (
            [_location(record.get("target", ""), "probe URL, built from the route "
                       "template — the scan never visited this route")]
        ),
        "properties": {
            "finding_id": record["finding_id"],
            "namespace": "dast-synthesis",
            "origin": "llm-cross-endpoint-synthesis",
            "claim_id": record.get("claim_id"),
            "via_finding_id": record.get("via_finding_id"),
            "supportingFindingGuids": (
                [_guid(str(record["via_finding_id"]))]
                if record.get("via_finding_id") else []
            ),
            "route": record.get("route"),
            "url_source": record.get("url_source"),
            "found_by": record.get("found_by"),
            "verification": {
                "tool": record.get("tool"),
                "outcome": record.get("outcome"),
                "evidence": record.get("evidence"),
                "detail": record.get("detail"),
            },
        },
    }
    # A confirmed sibling is a confirmed finding: :func:`confirmed_siblings` yields
    # only ``outcome == confirmed``, so classify_finding returns the same CONFIRMED
    # label and "an independent tool reproduced it" reason that every other
    # tool-confirmed result in this file carries — reused so the sibling's
    # disposition speaks the summary's vocabulary, not a parallel one. The empty
    # finding carries no alert, which is correct: no ZAP alert underlies a sibling.
    _attach_disposition(result, verification.classify_finding({}, record))
    # The GitLab DAST location fields, mirrored from the finding shape: method +
    # the probed parameter, in the SARIF-native webRequest and (mirrored) the
    # property bag. The attack value is not kept on the sibling record, so the
    # parameter maps to the empty string — exactly as a finding does when ZAP
    # recorded no attack value.
    method = str(record.get("method") or "GET")
    param = str(record.get("param") or "")
    web_request: dict[str, Any] = {"method": method}
    target = record.get("target") or ""
    if target:
        web_request["target"] = target
    if param:
        web_request["parameters"] = {param: ""}
    result["webRequest"] = web_request
    result["properties"]["method"] = method
    result["properties"]["param"] = param
    return result


def confirmed_siblings(
        verification_artifact: "dict[str, Any] | None") -> list[dict[str, Any]]:
    """The sibling probes that reproduced the weakness, and only those.

    A refuted sibling stays in the artifact and out of the report. Its URL was
    constructed from a route template, so a refutation may be a 404 rather than
    an absent vulnerability — reporting it as "checked and clean" would be the
    strongest claim in the file resting on the weakest evidence in it. See
    :func:`~dast_orchestrator.stages.verify.build_sibling_dispatches` for the
    asymmetry in full.
    """
    return [r for r in (verification_artifact or {}).get("sibling_verifications")
            or [] if r.get("outcome") == "confirmed"]


# -- assembly --------------------------------------------------------------


def _utc_from_compact(ts: "str | None") -> "str | None":
    """``20260101T000000Z`` -> ``2026-01-01T00:00:00Z`` (RFC 3339), or ``None``.

    Run ids and ``generated_at`` carry the compact basic-format stamp; SARIF's
    ``startTimeUtc`` / ``endTimeUtc`` want the extended RFC-3339 form. Anything
    that does not parse returns ``None``, so a malformed stamp is omitted rather
    than emitted as an invalid time.
    """
    from datetime import datetime, timezone

    try:
        dt = datetime.strptime(str(ts), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _scan_source(correlation: dict[str, Any]) -> dict[str, Any]:
    """The scan facts a triage artifact records: ``source``, or ``run`` in an older one."""
    return correlation.get("source") or correlation.get("run") or {}


def _run_invocation(correlation: dict[str, Any],
                    verification_artifact: dict[str, Any] | None) -> dict[str, Any]:
    """The analysis window behind this report, as a SARIF ``invocation``.

    ``startTimeUtc`` is the run-id timestamp (when the run began — the documented
    meaning of a run id's first field); ``endTimeUtc`` is the latest input
    ``generated_at``. Each is emitted only when it parses to a valid RFC-3339
    time. ``executionSuccessful`` records that the report was produced; it is
    never a claim about scan coverage (the summary carries that caveat).
    """
    invocation: dict[str, Any] = {"executionSuccessful": True}
    run_id = correlation.get("run_id") or ""
    start = _utc_from_compact(run_id.split("-")[0]) if run_id else None
    ends = [_utc_from_compact(correlation.get("generated_at"))]
    if verification_artifact:
        ends.append(_utc_from_compact(verification_artifact.get("generated_at")))
    end = max([e for e in ends if e], default=None)
    if start:
        invocation["startTimeUtc"] = start
    if end:
        invocation["endTimeUtc"] = end
    return invocation


def build_sarif(correlation: dict[str, Any],
                verification_artifact: dict[str, Any] | None) -> dict[str, Any]:
    findings = correlation.get("findings", [])
    correlated = correlation.get("correlated_findings", [])
    findings_by_id = {f["finding_id"]: f for f in findings}

    verdict_by_id: dict[str, dict[str, Any]] = {}
    corr_verdict_by_id: dict[str, dict[str, Any]] = {}
    if verification_artifact:
        for v in verification_artifact.get("verifications", []):
            verdict_by_id[v["finding_id"]] = v
        for v in verification_artifact.get("correlated_verifications", []):
            corr_verdict_by_id[v["finding_id"]] = v

    # Each result's disposition, reason and place in the order, computed by the SAME
    # call the Markdown summary makes (``verification.build_worklist`` over the same
    # inputs), so the machine-readable report and the human one can never disagree.
    # Dispositions are keyed by finding id, covering both ZAP findings and synthesis
    # claims; a confirmed sibling is classified inside :func:`_sibling_result` (only
    # confirmed siblings reach the report, so none is in this map).
    siblings = confirmed_siblings(verification_artifact)
    worklist = verification.build_worklist(
        findings,
        verification_artifact.get("verifications") if verification_artifact else None,
        correlated,
        (verification_artifact.get("correlated_verifications")
         if verification_artifact else None),
        siblings,
    )
    disposition_by_id: dict[str, tuple[str, str]] = {
        row["finding_id"]: (key, row["reason"])
        for key, rows in worklist["report"]["buckets"].items() for row in rows
    }

    zrules, zindex = zap_rules(findings)
    crules, cindex = synthesis_rules(
        correlated, findings_by_id, zindex,
        [PROPAGATION_CONFIRMED_RULE] if siblings else [])

    results = [_finding_result(f, zindex, verdict_by_id.get(f["finding_id"]),
                               disposition_by_id.get(f["finding_id"]))
               for f in findings]
    results += [_correlated_result(c, cindex, findings_by_id,
                                   corr_verdict_by_id.get(c["finding_id"]),
                                   disposition_by_id.get(c["finding_id"]))
                for c in correlated]
    results += [_sibling_result(r, cindex) for r in siblings]
    for result in results:
        _attach_worklist(result, worklist["items"][result["properties"]["finding_id"]])

    run_meta = _scan_source(correlation)
    driver = {
        "name": DRIVER_NAME,
        "informationUri": "https://github.com/",  # thesis prototype, no public home
        "version": str(correlation.get("schema_version", "1")),
        "rules": crules,
        "properties": {"namespace": "dast-synthesis"},
    }
    extension = {
        "name": ZAP_COMPONENT_NAME,
        "version": str(run_meta.get("zap_version") or "unknown"),
        "informationUri": "https://www.zaproxy.org/",
        "rules": zrules,
        "properties": {"namespace": "zap-mirror"},
    }
    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": driver, "extensions": [extension]},
                "invocations": [_run_invocation(correlation, verification_artifact)],
                "results": results,
                "properties": {
                    "source_triage": run_meta,
                    "verification_artifact": (
                        (verification_artifact or {}).get("source_artifact")
                    ),
                },
            }
        ],
    }


# -- human summary ---------------------------------------------------------


def build_summary_md(correlation: dict[str, Any],
                     verification_artifact: dict[str, Any] | None,
                     scan: dict[str, Any] | None = None,
                     data_dir: "Path | None" = None,
                     cve_detection: "dict[str, Any] | None" = None) -> str:
    """The human-readable report: what ran, what it found, and what it is worth.

    Written to be read by someone who was not there. The earlier version listed
    counts and stopped, which meant every question a reader actually has —
    *which* findings, on what evidence, under what scan configuration, and what
    the numbers may not be taken to mean — needed the JSON artifacts to answer.
    So this carries four things counts alone cannot:

    * the **configuration** that produced them (disabled rules, caps, auth mode,
      whether the active scan finished), because two runs differing on any of
      those are not comparable however similar their totals look;
    * the **findings themselves**, named, with the evidence a tool returned;
    * **where the arms disagreed**, which is the experiment;
    * the **caveats**, stated inline rather than left to be rediscovered.
    """
    s = correlation.get("summary", {})
    run_id = correlation.get("run_id") or correlation.get("generated_at", "?")
    scan = scan or {}
    llm = correlation.get("llm") or {}

    verifications = (verification_artifact or {}).get("verifications") or []
    correlated_verifs = (verification_artifact or {}).get(
        "correlated_verifications") or []
    synthesis_claims = correlation.get("correlated_findings") or []
    siblings = confirmed_siblings(verification_artifact)
    sections: list[tuple[str, list[str]]] = [
        ("ZAP's risk against what the chain settled",
         _risk_matrix_section(correlation.get("findings") or [], verifications,
                              synthesis_claims, correlated_verifs, siblings)),
        ("Disposition — what is settled, and what needs you",
         _disposition_section(correlation.get("findings") or [], verifications,
                              synthesis_claims, correlated_verifs, siblings)),
        ("How this run was configured", _config_section(correlation, scan, llm)),
        ("Run limits — where a stage hit a ceiling",
         _limits_section(data_dir, correlation.get("run_id"))),
        ("Scan shape", _scan_section(s, scan)),
        ("Triage — where the two arms agreed and where they did not",
         _triage_section(s)),
        ("Cross-endpoint findings (namespace 2)", _correlated_section(correlation)),
        ("Propagation — routes the scan never flagged",
         _propagation_section(verification_artifact)),
        ("Verification — the independent tool reading",
         _verification_section(verification_artifact)),
        ("Ground truth — measured CVE detection",
         _ground_truth_section(cve_detection)),
        ("What it cost", _cost_section(correlation, verification_artifact)),
        ("Run metrics", _metrics_section(correlation, data_dir)),
    ]
    lines = _overview(run_id, s, scan, correlation, verification_artifact)
    lines += _numbered(sections)
    lines.append("")
    return "\n".join(lines)


def _overview(run_id: str, s: dict[str, Any], scan: dict[str, Any],
              correlation: dict[str, Any],
              verification: dict[str, Any] | None) -> list[str]:
    """The whole run in a dozen lines, before any section.

    A reader who opens this file wants three things immediately: what was
    scanned, what came out, and whether any of it was *confirmed*. Making them
    assemble that from six sections is how a report gets skimmed and
    misquoted — so the headline numbers, and the one caveat that most changes
    how they should be read, come first.
    """
    outcomes = ((verification or {}).get("summary") or {}).get("by_outcome", {})
    confirmed = outcomes.get("confirmed", 0)
    ran = [name for name, present in (
        ("scan", bool(scan)),
        ("triage", bool(s)),
        ("LLM arm", bool(correlation.get("llm"))),
        ("verification", bool(verification)),
    ) if present]

    lines = [
        f"# DAST report — run `{run_id}`",
        "",
        "Three readings per finding: a deterministic rescan table, an LLM screening "
        "arm, and — where dispatched — an independent verification tool. Each is "
        "recorded separately; none overrides another.",
        "",
        "## Overview",
        "",
        "| | |",
        "|---|---|",
        f"| target | `{_scan_source(correlation).get('target', '?')}` "
        f"(auth `{scan.get('auth_mode', '?')}`) |",
        f"| stages in this report | {', '.join(ran) or 'none'} |",
        f"| alerts → findings | {s.get('raw_alerts', '?')} → "
        f"{s.get('findings', '?')} across {s.get('bundles', '?')} endpoints |",
        f"| flagged for verification | "
        f"{s.get('deterministic_rescans', 0)} by the table, "
        f"{s.get('llm_rescans', 0)} by the model |",
    ]
    if verification:
        lines.append(
            f"| verified | **{confirmed} confirmed**, "
            f"{outcomes.get('refuted', 0)} refuted, "
            f"{outcomes.get('inconclusive', 0)} inconclusive, "
            f"{outcomes.get('not-attempted', 0)} not attempted |"
        )
    else:
        lines.append("| verified | *not run — no finding here has a verification reading* |")

    lines += ["", _headline(confirmed, outcomes, s, scan)]
    return lines


def _headline(confirmed: int, outcomes: dict[str, Any], s: dict[str, Any],
              scan: dict[str, Any]) -> str:
    """One sentence a reader can quote, with the caveat that qualifies it.

    Deliberately conservative. Every clause here is a count from the artifact;
    none of it is an interpretation the artifact does not support.
    """
    if scan.get("active_scan_outcome") not in (None, "complete"):
        return (f"> **Read with care.** The active scan ended "
                f"`{scan.get('active_scan_outcome')}`, so this run did not cover "
                "its whole surface and its counts are a lower bound.")
    if confirmed:
        return (f"> **{confirmed} finding(s) were reproduced by an independent "
                "tool.** Everything else flagged was either refuted or left "
                "unsettled — see the verification section for which, and for the "
                "class check on each confirmation.")
    if outcomes:
        return ("> **No finding was reproduced by an independent tool in this "
                "run.** Read that as a statement about the tools, not about the "
                "findings: a refutation here means the dispatched tool did not "
                "reproduce the finding, which is not the same as the finding "
                "being false. For example, a live reflected XSS can be refuted "
                "because the probe's matcher wants its payload back verbatim and "
                "the application's output escaping altered it — "
                "escaping that defeats the detector without preventing the "
                "attack.")
    return ("> **Triage only.** No verification ran, so nothing here has been "
            "tested by a second tool.")


def _config_section(correlation: dict[str, Any], scan: dict[str, Any],
                    llm: dict[str, Any]) -> list[str]:
    lines = [
        "*Two runs that differ on any of these are not comparable, however "
        "similar their totals look.*",
        "",
        "| setting | value |",
        "|---|---|",
        f"| target | `{_scan_source(correlation).get('target', '?')}` |",
        f"| auth mode | `{scan.get('auth_mode', '?')}` |",
    ]
    if scan:
        lines += [
            f"| active scan | {scan.get('active_scan_outcome', '?')}"
            f"{_cap_note(scan)} |",
            f"| disabled active rules | {scan.get('disabled_active_rules') or 'none'} |",
            f"| passive alerts per rule | "
            f"{scan.get('max_alerts_per_passive_rule') or 'uncapped'} |",
            f"| ZAP version | {_scan_source(correlation).get('zap_version', '?')} |",
        ]
    if llm:
        caps = llm.get("model_capabilities") or {}
        lines += [
            f"| screening model | `{llm.get('model', '?')}` |",
            f"| screening prompt | `{llm.get('prompt_file', '?')}` |",
            f"| pass-1 context | `{llm.get('pass1_context', '?')}` |",
            f"| temperature / seed | {llm.get('temperature')} / {llm.get('seed')}"
            f"{'' if caps.get('seed', True) else ' *(model does not accept a seed)*'} |",
            f"| pass-1 concurrency | {llm.get('concurrency', 1)} |",
        ]
    return lines


def _scan_section(s: dict[str, Any], scan: dict[str, Any]) -> list[str]:
    """Omitted entirely when no scan artifact was available to the report."""
    if not scan:
        return []
    lines = [
        f"- **{s.get('raw_alerts', '?')}** raw ZAP alerts collapsed to "
        f"**{s.get('findings', '?')}** findings across "
        f"**{s.get('bundles', '?')}** endpoints "
        f"({s.get('bundles_with_static_context', '?')} with Noir static context).",
        f"- Produced by: {s.get('alerts_by_zap_source', {})}.",
        f"- Joined to a route template by tier: {s.get('alerts_by_join_tier', {})}.",
    ]
    gap = (s.get("alerts_by_join_tier") or {}).get("absent-api-router-gap", 0)
    if gap:
        lines.append(
            f"- **{gap}** alerts sit under `/api/`, which Noir's go_chi detector "
            "cannot see — a recall limitation of the static seeding stage, not a "
            "property of the target."
        )
    top = s.get("top_rules") or []
    if top:
        lines += ["", "| alerts | rule | risk |", "|---|---|---|"]
        for row in top[:8]:
            lines.append(f"| {row['alerts']} | {row['plugin_id']} {row['name']} "
                         f"| {row['risk']} |")
        biggest = top[0]
        share = biggest["alerts"] / max(1, s.get("raw_alerts", 1))
        if share > 0.4:
            lines += ["", f"> **Caveat.** Rule {biggest['plugin_id']} alone is "
                      f"{share:.0%} of all alerts. Read any active/passive split "
                      "together with this: one noisy rule can make a thin scan "
                      "look productive."]
    return lines


def _triage_section(s: dict[str, Any]) -> list[str]:
    if not s:
        return []
    lines = [
        f"- Deterministic arm flagged **{s.get('deterministic_rescans', 0)}** of "
        f"{s.get('findings', 0)} findings ({s.get('rescans_by_tool', {})}).",
    ]
    if s.get("llm_findings_asked"):
        asked, answered = s["llm_findings_asked"], s.get("llm_evaluated_findings", 0)
        lost = s.get("llm_findings_unanswered", 0)
        lines.append(
            f"- LLM arm answered **{answered}** of **{asked}** findings put to it "
            f"and flagged **{s.get('llm_rescans', 0)}**."
        )
        if lost:
            lines.append(
                f"- **{lost} findings ({lost / max(1, asked):.0%}) were asked "
                "about and came back with no verdict.** They are neither judged "
                "nor unexamined, and the agreement counts below cover only the "
                "answered ones — an unanswered finding is never a clean bill of "
                "health."
            )
        agreement = {k: v for k, v in (s.get("agreement") or {}).items()
                     if k not in ("not-evaluated", "asked-no-verdict")}
        lines += ["", "| both arms | deterministic only | LLM only | neither |",
                  "|---|---|---|---|",
                  f"| {agreement.get('both', 0)} | "
                  f"{agreement.get('deterministic-only', 0)} | "
                  f"{agreement.get('llm-only', 0)} | {agreement.get('neither', 0)} |"]
        consistency = s.get("llm_self_consistency") or {}
        if consistency.get("shared_handler_comparisons"):
            lines += ["", f"- Self-consistency: "
                      f"**{consistency['shared_handler_contradictions']}** of "
                      f"{consistency['shared_handler_comparisons']} same-rule "
                      "comparisons on routes sharing a handler disagree. Where "
                      "the code is identical, a split verdict is a contradiction "
                      "unless the reasoning names endpoint-specific evidence."]
    else:
        lines.append("- LLM arm did not run (`--no-llm`): this is the "
                     "deterministic control arm alone.")
    return lines


#: The measured single-run outcomes, in report order (strongest first), with the
#: one-line meaning shown beside each. Mirrors ground_truth's OUTCOME_* constants;
#: kept as literals here so the report reads without importing the stage.
_OUTCOME_ORDER = (
    ("detected", "reached AND observed — found by this run"),
    ("reached-unconfirmed", "reached, but no signal came back (the thesis says why)"),
    ("unreached", "the sink entered no tree this run built"),
    ("not-applicable", "the run's auth did not cover what the CVE requires"),
)

#: The detection layers, labelled as the assessment stores each marker's flag.
_GT_LAYERS = (
    ("zap+noir", "zap_detected"),
    ("+deterministic triage", "deterministic_flagged"),
    ("+llm triage", "llm_flagged"),
    ("+verification", "verification_confirmed"),
)


def _ground_truth_section(cve_detection: "dict[str, Any] | None") -> list[str]:
    """This run's MEASURED CVE assessment, when ground truth was assessed.

    Surfaces in the report itself — not only in cve-detection.json — the per-marker
    outcome distribution (reach × observe), the observed channels, and the
    per-layer detection counts. SINGLE RUN: the blind-vs-seeded ladder and the
    blind/ceiling rates are a two-run comparison `dast cve` prints, not a property
    of one run. Omitted whole when the run has no cve-detection.json (ground truth
    is optional). → docs/DETECTABILITY.md.
    """
    if not cve_detection:
        return []
    summary = cve_detection.get("summary") or {}
    outcomes = summary.get("outcomes") or {}
    markers = cve_detection.get("markers") or []
    total = summary.get("markers_total", len(markers))
    target = cve_detection.get("target", "?")
    version = cve_detection.get("target_version", "")
    mode = "--oracle" if cve_detection.get("oracle_guided") else "blind"
    lines = [
        f"- Measured against **{total} markers** for `{target}` {version}, "
        f"a **{mode}** run at auth `{cve_detection.get('auth_mode', '?')}`. "
        "Detectability is **measured, not asserted**: per marker the tool records "
        "whether the sink was *reached* and whether success was *observed*, and "
        "derives the outcome below. The blind-vs-seeded split and the blind/"
        "ceiling rates are a two-run comparison (`dast cve <blind> <oracle>`), "
        "never a single run's property.",
        "",
        "| outcome | n | markers | meaning |",
        "|---|---|---|---|",
    ]
    for outcome, meaning in _OUTCOME_ORDER:
        ids = outcomes.get(outcome) or []
        shown = ", ".join(f"`{m}`" for m in ids) if ids else "—"
        lines.append(f"| **{outcome}** | {len(ids)} | {shown} | {meaning} |")

    oob = [m.get("marker_id") for m in markers if m.get("observe") == "oob"]
    if oob:
        lines += ["", "- Observed **out of band** (interactsh): "
                  + ", ".join(f"`{m}`" for m in oob) + "."]

    if markers:
        lines += ["", "### Detection per layer (strict / generous)", "",
                  "| layer | detected |", "|---|---|"]
        for label, field_name in _GT_LAYERS:
            strict = sum(1 for m in markers if m.get(f"{field_name}_strict"))
            generous = sum(1 for m in markers if m.get(field_name))
            lines.append(f"| {label} | {strict}/{total} ({generous}/{total}) |")
        lines += ["", "*Strict counts a hit on the marker's own sink; generous "
                  "(in parentheses) counts a rule of the right class firing "
                  "anywhere — the upper bound.*"]
    return lines


def _metrics_section(correlation: dict[str, Any],
                     data_dir: "Path | None") -> list[str]:
    """Per-stage wall time and cost, from the metrics records on disk.

    Last, because it answers a different question from everything above it —
    "what did this cost in CI" rather than "what did it find" — and because it
    is the section a reader returns to rather than reads through.
    """
    from dast_orchestrator.foundation import metrics as run_metrics

    run_id = correlation.get("run_id")
    if not run_id or data_dir is None:
        return []
    table = run_metrics.run_summary(Path(data_dir), run_id)
    if not table:
        return []
    return ["```", table, "```", "",
            "*Measured, never estimated: an unmeasurable value is recorded as "
            "null rather than filled with a guess.*"]


def run_limits(data_dir: "Path | None", run_id: "str | None") -> list[dict[str, Any]]:
    """Every ceiling/degradation any stage of this run hit, newest stage last.

    One flat list across the run's ``*-metrics.json`` records, each entry the
    per-stage ``{stage, limit, detail}`` with the producing ``kind`` added. The
    source of both the Markdown section and the SARIF ``properties.limits`` block,
    so the human and machine reports name the same ceilings. Recomputes for
    records written before the field existed (:func:`metrics.record_limits`).
    """
    if not run_id or data_dir is None:
        return []
    from dast_orchestrator.foundation import metrics as run_metrics

    out: list[dict[str, Any]] = []
    for record in run_metrics.read_run_records(Path(data_dir), run_id):
        kind = str(record.get("kind") or "?")
        for limit in run_metrics.record_limits(record):
            out.append({"kind": kind, **limit})
    return out


def _limits_section(data_dir: "Path | None", run_id: "str | None") -> list[str]:
    """Where a stage hit a configured ceiling — named, never silently averaged in.

    A stage that hit a limit still produced its artifact, so the run is degraded,
    not void; this says which ceiling fired where. A run that hit none says so —
    the clean bill is itself the result, and the section is only skipped when
    there are no metrics records at all to read.
    """
    if not run_id or data_dir is None:
        return []
    from dast_orchestrator.foundation import metrics as run_metrics

    records = run_metrics.read_run_records(Path(data_dir), run_id)
    if not records:
        return []
    limits = run_limits(data_dir, run_id)
    if not limits:
        return ["No stage hit a configured limit: the active-scan cap, the client "
                "spider, the model budget and code-context resolution all ran to "
                "completion."]
    lines = [
        "A stage that hit a ceiling still produced its artifact — the run is "
        "**degraded, not void**. Each ceiling is named here so it is visible "
        "rather than averaged into the numbers above.",
        "",
        "| stage | limit | detail |",
        "| --- | --- | --- |",
    ]
    for limit in limits:
        lines.append(
            f"| {limit['kind']} · {limit['stage']} | `{limit['limit']}` "
            f"| {limit['detail']} |")
    return lines


def _numbered(sections: list[tuple[str, list[str]]]) -> list[str]:
    """Emit only the sections that have something to say, numbered in order.

    **A stage that did not run has no section at all** — not a heading with
    "n/a" under it. A report of a partial run should read as a shorter report,
    not as a full one with holes: a reader scanning headings must not have to
    check each for content, and a heading that is always present stops carrying
    information. Numbering follows from what survived, so the numbers never
    imply a section that is missing.
    """
    lines: list[str] = []
    number = 0
    for title, body in sections:
        if not [line for line in body if line.strip()]:
            continue
        number += 1
        lines += ["", f"## {number}. {title}", ""] + body
    return lines


def _cap_note(scan: dict[str, Any]) -> str:
    """Flag an active scan that reported 100% only because its cap fired.

    Prefers the flag the scan recorded (``active_scan_truncated``) and falls
    back to seconds-versus-cap for runs written before that existed.
    """
    stages = (scan.get("stages") or {})
    active = stages.get("active_scan") or {}
    cap = active.get("cap_minutes")
    truncated = scan.get("active_scan_truncated")
    if truncated is None:
        seconds = active.get("seconds")
        truncated = bool(seconds and cap and seconds >= cap * 60)
    if truncated:
        return (f" — **stopped at the {cap}-minute cap**, so 100% means *stopped*, "
                "not *exhausted*: coverage here is a lower bound")
    return ""


def _correlated_section(correlation: dict[str, Any]) -> list[str]:
    """Cross-endpoint findings, with what each one rests on."""
    correlated = correlation.get("correlated_findings") or []
    lines: list[str] = []
    if not correlated:
        lines.append("_None. Pass 2 ran and emitted nothing tied to more than one "
                     "endpoint._")
        return lines
    lines.append("Findings attributable to no single ZAP alert. Each **must** cite "
                 "real finding ids; one citing none is dropped and counted.")

    # How many independent samples produced each claim, when the run took more
    # than one. A claim produced by 1 of 5 samples recurs far less often than one
    # produced by all 5, so without this a reader gets a dozen claims of
    # indistinguishable standing, which is the failure sampling was
    # added to fix — surfacing more claims while hiding which ones hold up would
    # be a worse report, not a better one.
    samples = _sample_count(correlated)
    if samples > 1:
        recurring = sum(1 for c in correlated
                        if (c.get("reproducibility") or {}).get("seen_in", 1) > 1)
        lines += [
            "",
            f"Pass 2 ran **{samples} independent whole-corpus samples** and unioned "
            f"the claims by the evidence each cites. **{recurring} of "
            f"{len(correlated)}** were produced by more than one sample.",
            "",
            "*`seen_in` scores **reproducibility, not importance**. A claim seen "
            "once is a lead, not a result — it recurs in another run about 6% of "
            "the time, against roughly 67% for one seen in every sample. Severity "
            "is a separate axis: the two do not track each other, so read both.*",
        ]

    # When the samples came from several models, agreement between them is the
    # stronger claim and gets said first: repeats of one model share its failure
    # modes, two models reaching the same claim from the same evidence do not.
    ensemble = _model_count(correlated)
    if ensemble > 1:
        agreed = sum(1 for c in correlated
                     if (c.get("reproducibility") or {}).get("models_agreeing", 1) > 1)
        lines += [
            "",
            f"The samples came from **{ensemble} different models**. "
            f"**{agreed} of {len(correlated)}** claims were reached by more than "
            "one of them — a stronger signal than recurrence within one model, "
            "whose samples share whatever that model is prone to.",
        ]

    # Most-agreed, then most-reproduced: the ordering is the recommendation.
    for item in sorted(
        correlated,
        key=lambda c: (-(c.get("reproducibility") or {}).get("models_agreeing", 1),
                       -(c.get("reproducibility") or {}).get("seen_in", 1)),
    ):
        cites = item.get("supporting_finding_ids") or []
        repro = item.get("reproducibility") or {}
        seen, of = repro.get("seen_in"), repro.get("of")
        badge = ""
        if of and of > 1:
            badge = (f" · seen in {seen}/{of} samples"
                     + ("" if seen > 1 else " — **lead, not a result**"))
        agreeing, of_models = repro.get("models_agreeing"), repro.get("of_models")
        if of_models and of_models > 1:
            badge += f" · {agreeing}/{of_models} models"
        lines += [
            "",
            f"### `{item.get('finding_id')}` — {item.get('pattern')} "
            f"({item.get('severity', '?')}/{item.get('confidence', '?')}){badge}",
            "",
            f"{item.get('title') or item.get('summary', '')}",
            "",
            f"- rests on {len(cites)} finding(s): "
            + ", ".join(f"`{c}`" for c in cites[:8]),
            f"- covers {len(item.get('affected_routes') or [])} route(s): "
            + ", ".join(f"`{r}`" for r in (item.get('affected_routes') or [])[:6]),
            f"- suggested tool: `{item.get('suggested_tool', 'none')}`",
        ]
        if item.get("reasoning"):
            lines.append(f"- reasoning: {item['reasoning']}")
    return lines


def _sample_count(correlated: list[dict[str, Any]]) -> int:
    """How many synthesis samples produced this set, or 1 for a single call.

    Read off the claims rather than the run configuration: an artifact written
    before sampling existed carries no ``reproducibility`` at all, and must
    render exactly as it always did rather than claiming one sample it never
    recorded making.
    """
    return max((int((c.get("reproducibility") or {}).get("of") or 1)
                for c in correlated), default=1)


def _model_count(correlated: list[dict[str, Any]]) -> int:
    """How many models the samples came from, or 1 for a single-model run.

    Read off the claims for the same reason as :func:`_sample_count`: an
    artifact from before the ensemble existed carries no ``of_models``, and must
    render exactly as it always did.
    """
    return max((int((c.get("reproducibility") or {}).get("of_models") or 1)
                for c in correlated), default=1)


def _risk_matrix_section(findings: list[dict[str, Any]],
                         verifications: list[dict[str, Any]],
                         synthesis: "list[dict[str, Any]] | None" = None,
                         correlated_verifications: "list[dict[str, Any]] | None" = None,
                         siblings: "list[dict[str, Any]] | None" = None) -> list[str]:
    """ZAP's own priority beside what the rest of the chain did with it.

    ZAP's findings only: a claim or a sibling has no ZAP risk to compare against.
    Omitted when the run has no findings.
    """
    matrix = verification.build_worklist(
        findings, verifications, synthesis, correlated_verifications, siblings)["risk_matrix"]
    if not matrix:
        return []
    lines = [
        "*ZAP's risk still sets each result's SARIF level. This shows what "
        "verification and the rule classes did with it.*",
        "",
        "| ZAP risk | findings | reproduced by a tool | evident from the response "
        "| open | refuted | informational |",
        "|---|---|---|---|---|---|---|",
    ]
    for risk, cell in matrix.items():
        lines.append(
            f"| {risk} | {cell['findings']} | {cell[verification.SECTION_REPRODUCED]} "
            f"| {cell[verification.SECTION_EVIDENT]} | {cell[verification.SECTION_OPEN]} "
            f"| {cell[verification.SECTION_REFUTED]} "
            f"| {cell[verification.SECTION_INFORMATIONAL]} |")
    high = matrix.get("High")
    if high:
        lines += ["", f"Of ZAP's **{high['findings']}** High findings, "
                  f"**{high[verification.SECTION_REPRODUCED]}** were reproduced by a tool, "
                  f"**{high[verification.SECTION_REFUTED]}** were refuted and "
                  f"**{high[verification.SECTION_OPEN]}** stay open. A refutation is what "
                  "one tool did not find, not a proof the finding is false."]
    return lines


#: Why a line is still open, or who settled it, in a reader's words. A tool's own
#: name passes through unchanged.
_WHY_TEXT = {
    verification.NA_NO_TOOL: "no tool can test it",
    verification.NA_NO_PROBE: "no probe URL could be built",
    verification.NA_CAPPED: "the budget ran out",
    verification.NA_TOOL_CANNOT_REACH: "the tool cannot reach its parameter",
    verification.NOT_ATTEMPTED: "not attempted",
    verification.INCONCLUSIVE: "a tool was inconclusive",
    verification.WHY_FLAGGED: "flagged, not settled",
    verification.WHY_NEITHER: "flagged by neither arm",
    verification.WHY_MODEL_CITED: "the model, citing a source line",
}

#: Each section's heading, what its ``why`` counts mean, and the note under its heading.
_SECTION_TEXT = {
    verification.SECTION_REPRODUCED: ("Reproduced by a tool", "Reproduced by", ""),
    verification.SECTION_OPEN: (
        "Open — left to a person", "Open because",
        "*One line per ZAP rule, led by its worst member: ZAP's risk, then whether a "
        "scanner attacked for it, then whether both arms flagged it, then ZAP's "
        "confidence. This orders the evidence, it does not rank by true risk, and a "
        "line is a rule to read, not one fix.*"),
    verification.SECTION_CLAIMS: (
        "Claims — cross-endpoint, left to a person", "",
        "*Claims more models reached come first, then those more samples produced.*"),
    verification.SECTION_EVIDENT: (
        "Evident from the captured response", "",
        "*Header and cookie rules the response already proves. No tool read these, so "
        "they are true but not checked.*"),
    verification.SECTION_REFUTED: ("Refuted", "Refuted by", ""),
    verification.SECTION_INFORMATIONAL: ("Informational", "", ""),
}


def _worklist_path(path: Any) -> str:
    """A line's route, cut short: ZAP's payload-laden URLs run to hundreds of chars."""
    path = str(path or "")
    return path[:70] + "…" if len(path) > 70 else path


def _why_text(line: dict[str, Any]) -> str:
    """A line's ``why`` counts in words, without the count when it is the whole line."""
    parts = [(n, _WHY_TEXT.get(code, code)) for code, n in line["why"].items()]
    if len(parts) == 1 and parts[0][0] == line["count"]:
        return parts[0][1]
    return ", ".join(f"{n} {text}" for n, text in parts)


def _claim_line_md(line: dict[str, Any]) -> str:
    """One claim: never rolled up, and it says how often it recurred."""
    parts = [f"- {_origin_tag(line)} `{line['finding_id']}` **{line['rule']}** "
             f"({line['risk'] or '?'})"]
    if (line.get("of") or 1) > 1:
        # Only an unsettled claim is a lead: elsewhere its disposition already settled it.
        lead = (" — **lead, not a result**"
                if line["seen_in"] < 2 and line["section"] == verification.SECTION_CLAIMS else "")
        parts.append(f"seen in {line['seen_in']}/{line['of']} samples{lead}")
    if (line.get("of_models") or 1) > 1:
        parts.append(f"{line['models_agreeing']}/{line['of_models']} models")
    parts.append(line["reason"])
    return " · ".join(parts)


def _finding_line_md(line: dict[str, Any], why_label: str) -> str:
    """One ZAP rule's findings in a section, or one confirmed sibling."""
    text = (f"- {_origin_tag(line)} `{line['finding_id']}` **{line['rule']}** "
            f"({line['risk'] or '?'})")
    path = _worklist_path(line["path"])
    if line["count"] > 1:
        text += f" — {line['count']} findings on {line['routes']} route(s), e.g. `{path}`"
    elif path:
        text += f" on `{path}`"
    why = _why_text(line)
    return f"{text}. {why_label}: {why}" if why and why_label else text


def _disposition_section(findings: list[dict[str, Any]],
                         verifications: list[dict[str, Any]],
                         synthesis: "list[dict[str, Any]] | None" = None,
                         correlated_verifications: "list[dict[str, Any]] | None" = None,
                         siblings: "list[dict[str, Any]] | None" = None) -> list[str]:
    """The report's answer to "so what do I do with this?": the counts, then the worklist.

    Computed by :func:`verification.build_worklist`, the call behind the SARIF's ``rank`` and
    ``worklist_*`` properties. Every line carries its origin and why it sits where it does, so
    a disposition is auditable, never a bare label. A refutation is a claim about one tool's
    result, never a proof the finding is false. → DECISIONS.md.
    """
    worklist = verification.build_worklist(
        findings, verifications, synthesis, correlated_verifications, siblings)
    summary = worklist["report"]
    counts, buckets = summary["counts"], summary["buckets"]
    synth_counts = summary.get("synthesis_counts", {})
    by_section = {section: [ln for ln in worklist["lines"] if ln["section"] == section]
                  for section in verification.SECTIONS}
    size = {section: sum(ln["count"] for ln in rows) for section, rows in by_section.items()}
    settled = (verification.DISPOSITION_CONFIRMED, verification.DISPOSITION_REFUTED,
               verification.DISPOSITION_TRIAGE)
    total_findings = sum(counts[d] for d in settled) + len(siblings or [])
    from_zap = sum(1 for key in settled for row in buckets[key] if not row.get("synthesis"))
    synthesized = total_findings - from_zap
    lines = [
        f"Of **{total_findings}** findings "
        f"(plus {counts[verification.DISPOSITION_INFORMATIONAL]} informational "
        "results, not counted here):",
        "",
        f"**{from_zap} came from a ZAP alert** ({ORIGIN_ZAP}) — a scan rule "
        f"firing on a request the scanner made. **{synthesized} were "
        f"SYNTHESIZED** ({ORIGIN_SYNTHESIZED}) — cross-endpoint claims the LLM "
        "layer built, tied to no single alert. The two are evidenced "
        "differently and fail differently; every line below says which it is.",
        "",
        f"- **{size[verification.SECTION_REPRODUCED]} reproduced by a tool** — an "
        "independent tool ran and reproduced it.",
        f"- **{size[verification.SECTION_EVIDENT]} evident from the captured "
        "response** — a header or cookie rule the response already proves, or a "
        "claim resting only on confirmed findings. No tool read these.",
        f"- **{counts[verification.DISPOSITION_REFUTED]} refuted** — the "
        "dispatched tool did not reproduce it, or the model argued it away from "
        "the handler source. **Not a proof of absence**: a tool that cannot "
        "test the finding's class, or whose matcher the application's output "
        "escaping defeats, also reports nothing.",
        f"- **{counts[verification.DISPOSITION_TRIAGE]} require triage** — "
        "flagged but unsettled, inconclusive, or a semantic call. **These are "
        "left to a person**, and each line below says why.",
    ]
    for section, rows in by_section.items():
        if not rows:
            continue
        title, why_label, note = _SECTION_TEXT[section]
        rules = sum(1 for ln in rows if ln["origin"] == verification.ORIGIN_ZAP)
        tally = (f"{size[section]} findings on {rules} rules"
                 if section != verification.SECTION_REPRODUCED and rules
                 and rules == len(rows) else f"{size[section]}")
        lines += ["", f"### {title} ({tally})", ""]
        if note:
            lines += [note, ""]
        if section == verification.SECTION_CLAIMS and summary.get("synthesis_out_of_scope"):
            lines += [f"*{len(summary['synthesis_out_of_scope'])} are out of scope for "
                      "automated verification: no tool here can settle them, so they are "
                      "the honest set for manual evaluation and are **never counted as "
                      "confirmed**.*", ""]
        lines += [_claim_line_md(ln) if "reason" in ln else _finding_line_md(ln, why_label)
                  for ln in rows]
    if synth_counts:
        lines += ["", f"*Of the above, {sum(synth_counts.values())} are "
                  f"cross-endpoint synthesis claims: {synth_counts}.*"]
    return lines


#: What produced a finding, which is the first thing a reader needs about it and
#: the distinction this whole architecture exists to make. A ZAP finding is a
#: rule firing on a request the scanner made; a synthesized one is a claim the
#: LLM layer built across endpoints, tied to no single alert. They are evidenced
#: differently, they fail differently, and a report that mixes them silently
#: lets the second borrow the first's credibility.
ORIGIN_ZAP = "`[ZAP]`"
ORIGIN_SYNTHESIZED = "`[SYNTHESIZED]`"


def _origin_tag(line: dict[str, Any]) -> str:
    """The origin marker for one worklist line.

    Deliberately at the START of the line rather than a suffix: a reader
    scanning the list decides what to trust before reading the claim, and the
    old ``_(cross-endpoint)_`` suffix arrived after they already had.
    """
    return (ORIGIN_SYNTHESIZED if line.get("origin") == verification.ORIGIN_SYNTHESIS
            else ORIGIN_ZAP)


def _propagation_section(artifact: "dict[str, Any] | None") -> list[str]:
    """What the dispatch half of cross-endpoint synthesis actually found.

    Its own section rather than a line inside verification, because it answers a
    different question. Verification asks *is what ZAP reported real?*; this
    asks *is there something ZAP never reported at all?* — and only the second
    can add a finding to the report.
    """
    summary = ((artifact or {}).get("summary") or {}).get("siblings") or {}
    if not summary:
        return []
    siblings = (artifact or {}).get("sibling_verifications") or []
    confirmed = confirmed_siblings(artifact)
    # `considered` is absent from artifacts written before the reachability
    # pre-check existed, where every considered route was probed.
    considered = summary.get("considered", summary.get("probed", 0))
    unserved = summary.get("routes_not_served", 0)
    lines = [
        f"A propagation claim names the routes it predicts share a weakness, "
        f"including routes the scanner never flagged. **{considered} such "
        f"route(s)** across **{summary.get('claims', 0)} claim(s)** were "
        f"considered, at URLs built from their own route templates.",
        "",
        f"- Outcomes: {summary.get('by_outcome', {})}.",
    ]
    statuses = summary.get("by_route_status") or {}
    if statuses:
        lines += [f"- Constructed URLs answered: "
                  + ", ".join(f"`{code}` x{n}" for code, n in sorted(statuses.items()))
                  + "."]
    if unserved:
        lines += [
            f"- **{unserved} of them are not served at all** "
            "(`sibling-unreachable`). A plain GET at the constructed URL "
            "answered 404/410 before any payload, so no probe was sent: the "
            "claim predicted a route this application does not have. That is a "
            "result *about the claim*, not a probe that was skipped.",
        ]
    not_probeable = summary.get("routes_not_probeable", 0)
    if not_probeable:
        lines += [
            f"- **{not_probeable} are served but were not probed** "
            "(`sibling-not-probeable`). The constructed URL answered a redirect "
            "or a server error, so a probe would have followed it and judged "
            "the login page or an error page instead. Before this pre-check such "
            "routes came back *refuted* — of the login page, not the claim. "
            "Unlike `sibling-unreachable`, this says nothing about the "
            "claim; it says the probe could not be aimed. Read it alongside the "
            "run's `auth_mode`.",
        ]
    lines += [
        "",
        "*Read the two verdicts differently. A **confirmation** is a real "
        "vulnerability at a route this scan never visited — no ZAP alert "
        "underlies it, and the LLM layer is the only reason it was looked at. A "
        "**refutation** is weaker than a refutation elsewhere in this report: "
        "the URL was constructed rather than observed. The pre-check removes "
        "the worst of that — a route that is not served is never probed — but a "
        "page that exists is not the page the claim meant, so refutations are "
        "kept in the verification artifact and deliberately not listed as clean "
        "here. Each record carries the `route_status` its URL answered.*",
    ]
    if not confirmed:
        probed = summary.get("probed", len(siblings))
        lines += ["", f"_No sibling route was confirmed. {probed} probed of "
                      f"{considered} considered._"]
        return lines
    lines += ["", "### Confirmed at a route the scan never flagged", ""]
    for row in confirmed:
        lines += [
            f"- **`{row['finding_id']}`** — {row.get('route')} "
            f"(`{row.get('target')}`), via {row.get('tool')}.",
            f"  Predicted by claim `{row.get('claim_id')}` from finding "
            f"`{row.get('via_finding_id')}`; URL derived `{row.get('url_source')}`.",
            f"  Evidence: {row.get('evidence') or row.get('detail') or '—'}",
        ]
    return lines


def _verification_section(artifact: dict[str, Any] | None) -> list[str]:
    # Empty, not a placeholder: a stage that did not run has no section at all.
    if not artifact:
        return []
    vs = artifact.get("summary", {})
    lines = [
        f"- **{vs.get('dispatched', 0)}** dispatched of "
        f"**{vs.get('selected', 0)}** flagged + "
        f"**{vs.get('correlated_selected', 0)}** correlated findings.",
        f"- Budget: `{artifact.get('budget')}`; out-of-band "
        f"{'armed' if artifact.get('oob_enabled') else 'off'}.",
        f"- Outcomes: {vs.get('by_outcome', {})}.",
        "",
        "*A tool that ran and found nothing **refutes** — that is the "
        "false-positive verdict this stage exists to produce. A tool killed by a "
        "timeout is **inconclusive** (unknown, never a refutation), and a finding "
        "a budget dropped is **not-attempted**.*",
        "",
        "| tool | confirmed | refuted | inconclusive | not-attempted |",
        "|------|-----------|---------|--------------|---------------|",
    ]
    for tool, counts in sorted(vs.get("by_tool", {}).items()):
        lines.append(
            f"| {tool} | {counts.get(verification.CONFIRMED, 0)} | "
            f"{counts.get(verification.REFUTED, 0)} | "
            f"{counts.get(verification.INCONCLUSIVE, 0)} | "
            f"{counts.get(verification.NOT_ATTEMPTED, 0)} |"
        )

    confirmed = _confirmed_rows(artifact)
    lines += ["", "### Confirmed by an independent tool", ""]
    if confirmed:
        for row in confirmed:
            lines += [
                f"**`{row['finding_id']}` — {row.get('rule_name', '')}**",
                "",
                f"- ZAP: rule `{row.get('plugin_id')}`, risk {row.get('risk')}, "
                f"parameter `{row.get('param', '')}`",
                f"- probe: `{row.get('target')}` (URL derived: "
                f"`{row.get('url_source', 'as-recorded')}`)",
                f"- {row.get('tool')} evidence: **{row.get('evidence')}** "
                f"— {row.get('detail', '')}",
                "",
                "> Read this as *an independent tool reached a security-relevant "
                "sink on this parameter*, not necessarily as *ZAP's hypothesised "
                "class was correct*: the tool may match a different template "
                "family than the rule that flagged it.",
            ]
    else:
        lines.append("_Nothing was independently confirmed in this run._")

    refuted = [v for v in artifact.get("verifications", [])
               if v.get("outcome") == verification.REFUTED]
    if refuted:
        lines += ["", "### Refuted (the dispatched tool did not reproduce it)",
                  "",
                  "*Each row says what one tool did not find. It does not say "
                  "the finding is false — the probe may not carry a payload for "
                  "the finding's class, and its matcher may be defeated by "
                  "output escaping that does not prevent exploitation. Both "
                  "have been observed on this pipeline.*",
                  "",
                  "| finding | rule | tool | probe |", "|---|---|---|---|"]
        for row in refuted[:15]:
            lines.append(f"| `{row['finding_id']}` | {row.get('plugin_id')} "
                         f"{row.get('rule_name', '')[:34]} | {row.get('tool')} | "
                         f"`{str(row.get('target', ''))[:52]}` |")
        if len(refuted) > 15:
            lines.append(f"| … | _{len(refuted) - 15} more_ | | |")
    loop = vs.get("loop")
    if loop:
        config = loop.get("config") or {}
        rate = loop.get("flagged_rate")
        head = (f"Verified at tool choice `{config.get('tool_choice')}` / "
                f"invocation `{config.get('invocation')}`, "
                f"{loop.get('tool_rounds', loop.get('rounds_run', 0))} tool "
                f"invocation(s) over {loop.get('rounds_run', 0)} loop round(s).")
        if not loop.get("audited"):
            # No model read anything, so there is no agreement to report. Saying
            # "differed on 0" here would be the same false comparison the
            # console used to print: it reads as consensus with a model that
            # was never consulted.
            lines += ["", head + " This is the **fully-deterministic**"
                      " configuration — no model was consulted, so there is no"
                      " second reading to compare against. It is the control"
                      " every LLM configuration is measured against."]
        else:
            flagged = loop.get("flagged", 0)
            lines += ["", head + f" On {loop['audited']} finding(s) both the"
                      " deterministic wrapper and the model read the tool's"
                      f" output; they differed on **{flagged}**"
                      + (f" ({rate:.1%})" if rate is not None else "")
                      + (", each flagged in the artifact for review."
                         if flagged else
                         " — the model's reading agreed with the fixed rules"
                         " on every one.")]
    return lines


def _cost_section(correlation: dict[str, Any],
                  artifact: dict[str, Any] | None) -> list[str]:
    """What the run cost — the question the CI framing exists to answer."""
    llm = correlation.get("llm") or {}
    syn = correlation.get("synthesis") or {}
    usages = [("pass 1 (triage)", llm.get("usage") or {}),
              ("pass 2 (synthesis)", syn.get("usage") or {})]
    usages = [(n, u) for n, u in usages if u]
    if not usages:
        return []
    lines = [
             "| pass | calls | prompt | completion | cost |", "|---|---|---|---|---|"]
    total = 0.0
    for name, u in usages:
        cost = float(u.get("cost_usd", 0) or 0)
        total += cost
        lines.append(f"| {name} | {u.get('calls', 0)} | {u.get('prompt_tokens', 0)} "
                     f"| {u.get('completion_tokens', 0)} | ${cost:.4f} |")
    lines.append(f"| **total** | | | | **${total:.4f}** |")
    failures = {n: u.get("failure_kinds") for n, u in usages if u.get("failure_kinds")}
    if failures:
        lines += ["", f"Model call failures by cause: {failures}. These are calls "
                  "that were made and produced nothing usable — they are why the "
                  "asked-versus-answered distinction above matters."]
    return lines


def _confirmed_rows(verification_artifact: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for v in (verification_artifact.get("verifications", [])
              + verification_artifact.get("correlated_verifications", [])):
        if v.get("outcome") == verification.CONFIRMED:
            rows.append(v)
    return rows


# -- entry point -----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """This stage's argument parser, built without parsing anything.

    Separate from :func:`main` so ``dast`` can read the flags this stage
    accepts — that is what lets one flag be routed to the right stage of a
    sequence, and an ambiguous one be refused by name rather than silently
    applied to the wrong stage. Defaults still come from the environment, so
    the caller loads the stage's env file first.
    """
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "report")
    parser = argparse.ArgumentParser(
        description=config.command_description(__doc__), parents=[pre])
    parser.add_argument("run", metavar="<run_id>",
                        help=run_paths.RUN_ARG_HELP.format(
                            verb="report",
                            default="the newest run with a triage"))
    parser.add_argument("--data-dir", type=Path, default=DATA_DIR)
    # `out_suffix`, matching correlate and verify: the three stages mean one
    # thing by this flag, and `dast` reads the shared dest as saying so.
    parser.add_argument("--out-suffix", dest="out_suffix", default="",
                        help="Suffix the OUTPUT report: writes report-<suffix>.*."
                        "\n"
                        "--in-suffix picks the input variant and defaults to "
                        "this; shared with triage/verify.")
    parser.add_argument(
        "--in-suffix", dest="in_suffix", default=None, help="Which triage/verification variant to report "
             "(triage-<SUFFIX>.json / verification-<SUFFIX>.json); an empty "
             "string picks the base artifacts. The case for it is reporting ONE "
             "stored verification under a differently-named output.\n"
             "Falls back to --out-suffix, which is what a `verify report` "
             "sequence wants (there the same suffix names both).")
    parser.add_argument(
        "--force", action="store_true",
        help="Run even though another process holds this stage's lock on the "
             "run directory. Overrides the refusal; it does not coordinate the "
             "two runs.",
    )
    config.normalize_metavars(parser)
    return parser


@run_lock.guarded
def main(argv: "list[str] | None" = None) -> int:
    pre = argparse.ArgumentParser(add_help=False)
    config.add_env_flags(pre, "report")
    known, _ = pre.parse_known_args(argv)
    # Loaded before the parser is built, so every ``os.getenv`` default below
    # sees the stage's file and an explicit flag still wins (see config.py).
    env = config.load_stage_env("report", known.env_file)

    parser = build_parser()
    args = parser.parse_args(argv)
    overridden = config.apply_explicit_overrides(env, args, parser, argv)
    if overridden:
        ui.warn(f"{ui.short_path(known.env_file)} supplies (no flag given): "
                f"{', '.join(sorted(overridden))}")

    # The input variant to read is --in-suffix, or --out-suffix when it is unset
    # (a `verify report` sequence names both with one suffix). The output report
    # keeps --out-suffix so one stored verification can be reported under a
    # differently-named artifact.
    in_suffix = args.out_suffix if args.in_suffix is None else args.in_suffix
    corr_base = run_paths._splice_suffix(run_paths.TRIAGE, in_suffix)
    if args.run and not run_paths.is_latest(args.run):
        try:
            layout = run_paths.RunLayout.resolve(args.data_dir, args.run)
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        if not layout.has(run_paths.TRIAGE, in_suffix):
            print(f"ERROR: no {corr_base} for run {args.run}.", file=sys.stderr)
            return 1
    else:
        runs = run_paths.RunLayout.runs(args.data_dir)
        newest = run_paths.RunLayout(args.data_dir, runs[-1]) if runs else None
        if newest is not None and newest.has(run_paths.TRIAGE, in_suffix):
            layout = newest
        else:
            # "latest" is the newest run, not the newest usable one — reporting a
            # different run than the one just produced is a silent substitution.
            fallback = run_paths.RunLayout.latest_with(args.data_dir, corr_base)
            where = "" if newest is None else f"the newest run {newest.run_id} has no {corr_base}. "
            hint = ("" if fallback is None else
                    f"The newest run that does is {fallback.run_id} — pass "
                    f"`--run {fallback.run_id}` to report it.")
            print(f"ERROR: {where}{hint or f'No run has {corr_base}; run correlate-run first.'}",
                  file=sys.stderr)
            return 1
    # Cheap compared with its siblings, and locked for the same reason: two
    # reports of one variant write one `report-<suffix>.sarif.json`, and the
    # loser's is the one that survives. Released by `@run_lock.guarded`.
    run_lock.claim(layout.dir, "report", args.out_suffix, force=args.force)

    from dast_orchestrator.foundation import metrics as run_metrics

    ui.headline("Report — SARIF 2.1.0 + summary",
                f"run {layout.run_id}  →  {layout.dir}")
    metrics = run_metrics.RunMetrics(layout.run_id, kind="report", label=args.out_suffix)
    with metrics.guard(args.data_dir):
        report = ui.open_phase("Merging verdicts")
        with metrics.stage("report") as stage:
            # §R5: validate each input against its schema as it is read, so a bad
            # triage/verification fails here (naming the field) rather than as a
            # malformed report. A required-field violation raises ArtifactError.
            try:
                tpath = layout.path(run_paths.TRIAGE, in_suffix)
                correlation = json.loads(tpath.read_text())
                schema.check(tpath.name, correlation, tpath)

                verification_artifact = None
                if layout.has(run_paths.VERIFICATION, in_suffix):
                    vpath = layout.path(run_paths.VERIFICATION, in_suffix)
                    verification_artifact = json.loads(vpath.read_text())
                    schema.check(vpath.name, verification_artifact, vpath)
                    ui.item("verification", vpath.name)

                scan_artifact: dict[str, Any] = {}
                if layout.has(run_paths.ZAP_ALERTS):
                    zpath = layout.path(run_paths.ZAP_ALERTS)
                    scan_artifact = json.loads(zpath.read_text())
                    schema.check(zpath.name, scan_artifact, zpath)

                # Ground truth is OPTIONAL: include the detection-ladder section only
                # when `dast cve` was run into this run for this variant. A markerless
                # target (or a scan-only run) has no cve-detection.json and the report
                # simply omits the section rather than showing an empty one.
                cve_detection = None
                if layout.has(run_paths.CVE_DETECTION, in_suffix):
                    cve_detection = json.loads(
                        layout.path(run_paths.CVE_DETECTION, in_suffix).read_text())
            except schema.ArtifactError as exc:
                ui.fail(str(exc))
                return 1

            sarif = build_sarif(correlation, verification_artifact)
            # The run's ceilings/degradations, read from the scan/triage/verify
            # metrics on disk, on the SARIF run so the machine-readable report
            # names the same limits as the Markdown section — a drowned scan or a
            # budget-stopped verify is visible to a tool consuming the SARIF, not
            # only to a human reading the summary.
            sarif["runs"][0]["properties"]["limits"] = run_limits(
                args.data_dir, layout.run_id)
            if scan_artifact:
                # The scan's own metrics carry the stage timings the cap note needs.
                scan_metrics = layout.metrics("scan")
                if scan_metrics.is_file():
                    scan_artifact["stages"] = json.loads(scan_metrics.read_text()).get("stages", {})
            summary = build_summary_md(correlation, verification_artifact,
                                       scan_artifact, data_dir=args.data_dir,
                                       cve_detection=cve_detection)

            sarif_path = layout.ensure().path(run_paths.REPORT_SARIF, args.out_suffix)
            md_path = layout.path(run_paths.REPORT_MD, args.out_suffix)
            sarif_path.write_text(json.dumps(sarif, indent=2))
            md_path.write_text(summary)

            n_results = len(sarif["runs"][0]["results"])
            n_zap = len(sarif["runs"][0]["tool"]["extensions"][0]["rules"])
            n_corr = len(sarif["runs"][0]["tool"]["driver"]["rules"])
            props = [r["properties"] for r in sarif["runs"][0]["results"]]
            n_lines = len({p["worklist_group"] for p in props})
            n_open = len({p["worklist_group"] for p in props
                          if p["worklist_section"] == verification.SECTION_OPEN})
            stage.counters.update(results=n_results, zap_rules=n_zap,
                                  synthesis_rules=n_corr, worklist_lines=n_lines,
                                  open_rule_lines=n_open)

        ui.item("results", n_results)
        ui.item("ZAP rules (namespace 1)", n_zap)
        ui.item("synthesis rules (ns 2)", n_corr)
        # Every stage reports metrics, report included: a report-metrics.json so
        # the run summary carries a `report` row like the others, and print_summary
        # closes with the wall-clock time.
        metrics.record_results(results=n_results, zap_rules=n_zap, synthesis_rules=n_corr,
                               worklist_lines=n_lines, open_rule_lines=n_open)
    # `guard` wrote the record on the way out of the block above (with an abort
    # object had the stage crashed). Clean path only from here.
    report.close(files=[sarif_path.name, md_path.name, metrics.filename])
    metrics.print_summary()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
