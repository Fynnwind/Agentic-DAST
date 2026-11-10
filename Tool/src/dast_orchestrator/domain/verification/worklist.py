"""The order a reader works through a run's results: sections of evidence, one line per ZAP rule.

Part of the ``verification`` package, computed over :func:`disposition_report`'s own inputs so
the summary and the SARIF cannot disagree. The order is ordinal, never a score, and it never
changes a result's ``level``. → DECISIONS.md.
"""
from __future__ import annotations

from typing import Any

from dast_orchestrator.domain.verification.dispatch import (
    _RISK_RANK,
    DISPOSITION_CONFIRMED,
    DISPOSITION_INFORMATIONAL,
    DISPOSITION_REFUTED,
    DISPOSITION_TRIAGE,
    dispatch_priority,
    disposition_report,
)
from dast_orchestrator.domain.verification.outcomes import (
    CONFIRMED,
    INCONCLUSIVE,
    NOT_ATTEMPTED,
    REFUTED,
)

SECTION_REPRODUCED = "reproduced"
SECTION_OPEN = "open"
SECTION_CLAIMS = "claims"
SECTION_EVIDENT = "evident"
SECTION_REFUTED = "refuted"
SECTION_INFORMATIONAL = "informational"
#: The sections, in the order a reader works through them. Evident outranks refuted:
#: an evident finding is true and has a fix, a refuted one is only there to audit.
SECTIONS = (SECTION_REPRODUCED, SECTION_OPEN, SECTION_CLAIMS, SECTION_EVIDENT,
            SECTION_REFUTED, SECTION_INFORMATIONAL)

#: Why a finding is still open, beside the ``NA_*`` codes and ``inconclusive``.
WHY_FLAGGED = "flagged-not-settled"
WHY_NEITHER = "flagged-by-neither-arm"
#: Who refuted a finding, when it was not a tool.
WHY_MODEL_CITED = "model-cited-a-line"

ORIGIN_ZAP = "zap"
ORIGIN_SYNTHESIS = "synthesis"

#: The risk bands of the matrix, highest first.
RISK_BANDS = ("High", "Medium", "Low", "Informational")

_CONFIDENCE_RANK = {"High": 0, "Medium": 1, "Low": 2, "False Positive": 3}
#: Floor of each section's SARIF ``rank``. Ordinal only: it encodes the order, not a measurement.
_SECTION_RANK = {SECTION_REPRODUCED: 90.0, SECTION_OPEN: 70.0, SECTION_CLAIMS: 50.0,
                 SECTION_EVIDENT: 20.0, SECTION_REFUTED: 10.0, SECTION_INFORMATIONAL: 0.0}
#: A claim seen in one sample ranks below every recurring claim.
_LEAD_RANK = 40.0
#: Rank added per risk band above Informational, small enough to stay inside a section.
_RISK_STEP = 3.0


def _risk_rank(risk: Any) -> int:
    return _RISK_RANK.get(str(risk or ""), 4)


def _rank(section: str, risk: Any, *, lead: bool = False) -> float:
    """A result's SARIF ``rank``: its section's floor, raised by its risk band."""
    floor = _LEAD_RANK if lead else _SECTION_RANK[section]
    return floor + max(0, 3 - _risk_rank(risk)) * _RISK_STEP


def _why_open(finding: dict[str, Any], verdict: dict[str, Any] | None) -> str:
    """The one code saying why a finding is left to a person."""
    outcome = (verdict or {}).get("outcome")
    if outcome == NOT_ATTEMPTED:
        return str((verdict or {}).get("not_attempted_reason") or NOT_ATTEMPTED)
    if outcome == INCONCLUSIVE:
        return INCONCLUSIVE
    if ((finding.get("deterministic") or {}).get("needs_rescan")
            or (finding.get("llm") or {}).get("needs_rescan")):
        return WHY_FLAGGED
    return WHY_NEITHER


def _finding_section(disposition: str, verdict: dict[str, Any] | None) -> str:
    if disposition == DISPOSITION_CONFIRMED:
        reproduced = (verdict or {}).get("outcome") == CONFIRMED
        return SECTION_REPRODUCED if reproduced else SECTION_EVIDENT
    return {DISPOSITION_TRIAGE: SECTION_OPEN,
            DISPOSITION_REFUTED: SECTION_REFUTED,
            DISPOSITION_INFORMATIONAL: SECTION_INFORMATIONAL}[disposition]


def _claim_section(disposition: str, verdict: dict[str, Any] | None) -> str:
    if disposition == DISPOSITION_CONFIRMED:
        reproduced = (verdict or {}).get("outcome") == CONFIRMED
        return SECTION_REPRODUCED if reproduced else SECTION_EVIDENT
    return SECTION_REFUTED if disposition == DISPOSITION_REFUTED else SECTION_CLAIMS


def _zap_key(findings: list[dict[str, Any]], plugin_id: str) -> tuple:
    """Sort key of a rule's line: its worst member by :func:`dispatch_priority`, then ZAP's
    confidence, then the rule id, so the tiebreak means the same thing in every run."""
    worst = min(dispatch_priority(f)[:3] for f in findings)
    confidence = min(_CONFIDENCE_RANK.get(str((f.get("alert") or {}).get("confidence") or ""), 4)
                     for f in findings)
    return (*worst, confidence, plugin_id)


def _zap_line(section: str, group: str, members: list[dict[str, Any]],
              why: dict[str, str] | None = None) -> dict[str, Any]:
    """One line for a rule's findings in one section, led by its worst member."""
    lead = min(members, key=dispatch_priority)
    alert = lead.get("alert") or {}
    why_counts: dict[str, int] = {}
    for finding in members:
        code = (why or {}).get(str(finding.get("finding_id")))
        if code:
            why_counts[code] = why_counts.get(code, 0) + 1
    return {
        "section": section,
        "group": group,
        "origin": ORIGIN_ZAP,
        "finding_id": lead.get("finding_id"),
        "rule": alert.get("name"),
        "plugin_id": str(alert.get("plugin_id") or ""),
        "risk": alert.get("risk"),
        "count": len(members),
        "routes": len({f.get("path") for f in members}),
        "path": lead.get("path"),
        "why": dict(sorted(why_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "finding_ids": sorted(str(f.get("finding_id")) for f in members),
        "sort": _zap_key(members, str(alert.get("plugin_id") or "")),
    }


def _claim_line(section: str, claim: dict[str, Any], reason: str) -> dict[str, Any]:
    """One line for a claim, which is never rolled up: each cites its own evidence."""
    risk = str(claim.get("severity") or "").capitalize()
    repro = claim.get("reproducibility") or {}
    seen = int(repro.get("seen_in") or 1)
    agreeing = int(repro.get("models_agreeing") or 1)
    return {
        "section": section,
        "group": f"{section}:{claim.get('finding_id')}",
        "origin": ORIGIN_SYNTHESIS,
        "finding_id": claim.get("finding_id"),
        "rule": claim.get("title"),
        "plugin_id": str(claim.get("pattern") or ""),
        "risk": risk,
        "count": 1,
        "routes": len(claim.get("affected_routes") or []),
        "path": ", ".join(claim.get("affected_routes") or []),
        "why": {},
        "finding_ids": [str(claim.get("finding_id"))],
        "reason": reason,
        "seen_in": seen,
        "of": repro.get("of"),
        "models_agreeing": agreeing,
        "of_models": repro.get("of_models"),
        "out_of_scope": str(claim.get("suggested_tool")) == "out-of-scope",
        # Agreement outranks recurrence, as in the synthesis section of the report.
        "sort": ((-agreeing, -seen, _risk_rank(risk), str(claim.get("finding_id")))
                 if section == SECTION_CLAIMS
                 else (_risk_rank(risk), 2, 1, 4, str(claim.get("finding_id")))),
    }


def _sibling_line(record: dict[str, Any]) -> dict[str, Any]:
    """One line for a confirmed sibling: no ZAP alert underlies it, so it is not rolled up."""
    return {
        "section": SECTION_REPRODUCED,
        "group": f"{SECTION_REPRODUCED}:{record.get('finding_id')}",
        "origin": ORIGIN_SYNTHESIS,
        "finding_id": record.get("finding_id"),
        "rule": record.get("rule_name") or "Propagated weakness",
        "plugin_id": "",
        "risk": "High",
        "count": 1,
        "routes": 1,
        "path": record.get("route"),
        "why": {str(record.get("tool")): 1},
        "finding_ids": [str(record.get("finding_id"))],
        "sibling": True,
        "sort": (_risk_rank("High"), 2, 1, 4, str(record.get("finding_id"))),
    }


def build_worklist(
    findings: list[dict[str, Any]],
    verifications: list[dict[str, Any]] | None = None,
    synthesis: list[dict[str, Any]] | None = None,
    correlated_verifications: list[dict[str, Any]] | None = None,
    siblings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Every reported item placed on one ordered list of lines, plus ZAP risk × section.

    :param findings: the triage artifact's per-endpoint findings.
    :param verifications: their records from ``verification.json``.
    :param synthesis: the cross-endpoint claims.
    :param correlated_verifications: the claims' records from ``verification.json``.
    :param siblings: the confirmed sibling records.
    :returns: ``report`` (the :func:`disposition_report` it rests on), ``lines`` (ordered, each
        with a 1-based ``line``), ``items`` (finding id → ``section``, ``group``, ``line``,
        ``rank``) and ``risk_matrix`` (ZAP risk → section → count, ZAP findings only).
    """
    report = disposition_report(findings, verifications, synthesis, correlated_verifications)
    disposition = {row["finding_id"]: key
                   for key, rows in report["buckets"].items() for row in rows}
    reason = {row["finding_id"]: row.get("reason") or ""
              for rows in report["buckets"].values() for row in rows}
    verdicts = {v.get("finding_id"): v for v in (verifications or [])}
    claim_verdicts = {v.get("finding_id"): v for v in (correlated_verifications or [])}

    grouped: dict[str, list[dict[str, Any]]] = {}
    why: dict[str, str] = {}
    matrix: dict[str, dict[str, int]] = {}
    for finding in findings:
        fid = finding.get("finding_id")
        verdict = verdicts.get(fid)
        section = _finding_section(disposition[fid], verdict)
        alert = finding.get("alert") or {}
        risk = str(alert.get("risk") or "Unknown")
        cell = matrix.setdefault(risk, {"findings": 0, **{s: 0 for s in SECTIONS}})
        cell["findings"] += 1
        cell[section] += 1
        if section == SECTION_OPEN:
            why[str(fid)] = _why_open(finding, verdict)
        elif section == SECTION_REFUTED:
            why[str(fid)] = (str(verdict.get("tool") or "tool")
                             if (verdict or {}).get("outcome") == REFUTED else WHY_MODEL_CITED)
        elif section == SECTION_REPRODUCED:
            why[str(fid)] = str((verdict or {}).get("tool") or "tool")
        # A reproduced finding keeps a line of its own: it is named, not counted.
        key = (fid if section == SECTION_REPRODUCED
               else str(alert.get("plugin_id") or alert.get("name") or fid))
        grouped.setdefault(f"{section}:{key}", []).append(finding)

    lines = [_zap_line(group.split(":", 1)[0], group, members, why)
             for group, members in grouped.items()]
    for claim in (synthesis or []):
        fid = claim.get("finding_id")
        lines.append(_claim_line(_claim_section(disposition[fid], claim_verdicts.get(fid)),
                                 claim, reason[fid]))
    lines += [_sibling_line(record) for record in (siblings or [])]

    ordered: list[dict[str, Any]] = []
    for section in SECTIONS:
        ordered += sorted((ln for ln in lines if ln["section"] == section),
                          key=lambda ln: ln["sort"])
    items: dict[str, dict[str, Any]] = {}
    for number, line in enumerate(ordered, 1):
        line["line"] = number
        lead = line["origin"] == ORIGIN_SYNTHESIS and line["section"] == SECTION_CLAIMS \
            and line.get("seen_in", 1) < 2
        for fid in line["finding_ids"]:
            items[fid] = {"section": line["section"], "group": line["group"], "line": number,
                          "rank": _rank(line["section"], line["risk"], lead=lead)}
    # Members of one line can sit in different risk bands; each result ranks by its own.
    for finding in findings:
        fid = str(finding.get("finding_id"))
        items[fid]["rank"] = _rank(items[fid]["section"], (finding.get("alert") or {}).get("risk"))
    return {
        "report": report,
        "lines": ordered,
        "items": items,
        "risk_matrix": {band: matrix[band] for band in (*RISK_BANDS, *sorted(matrix))
                        if band in matrix},
    }
