"""Shared helpers for the triage stage: result guards, systemic collapse, defaults.

The bottom of the ``triage`` package — small leaf helpers (does a re-run risk
discarding LLM results, which findings belong to a bundle), the ZAP-2.17
SYSTEMIC-tag collapse and its fan-out, and the concurrency default. Depends on
nothing else in the package.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from dast_orchestrator.analysis import join
from dast_orchestrator.context import evidence
from dast_orchestrator.foundation import run_paths
from dast_orchestrator.analysis.join import Bundle

REPO_ROOT = Path(__file__).resolve().parents[4]
#: Runs a person started. A sheet points its stages elsewhere; see
#: :mod:`dast_orchestrator.foundation.run_paths`.
DATA_DIR = run_paths.default_runs_dir()


def _existing_model(out_path: Path) -> str | None:
    """Model id recorded in an artifact already on disk, if any."""
    if not out_path.is_file():
        return None
    try:
        return (json.loads(out_path.read_text()).get("llm") or {}).get("model")
    except (OSError, json.JSONDecodeError):
        return None


def _would_discard_llm_results(out_path: Path, artifact: dict[str, Any]) -> bool:
    """True if writing `artifact` would drop LLM output already on disk.

    Model verdicts cost money and are not reproducible for free, while the
    control arm is free and instant. So a `--no-llm` re-run must never be able
    to quietly flatten a completed two-arm run — which is exactly what happened
    once during Phase 3 development.
    """
    if artifact.get("llm") or not out_path.is_file():
        return False
    try:
        existing = json.loads(out_path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    return bool(existing.get("llm"))


def _findings_of(bundle: Bundle, findings: list[dict[str, Any]]) -> list[tuple[str, Any]]:
    """The (finding_id, alert group) pairs belonging to one bundle, in order."""
    ids = {join.finding_id(bundle, group): group for group in bundle.groups}
    known = {f["finding_id"] for f in findings}
    return [(fid, group) for fid, group in ids.items() if fid in known]


#: ZAP 2.17's alert-tags library flags site-wide configuration issues — missing
#: or incorrect headers, CSP directives, server-version leaks — with this tag.
#: Such a finding has the same root cause and identical evidence on every URL it
#: appears on, so its per-endpoint triage verdict is identical too; on a large
#: tree they are the bulk of pass 1's cost and its truncation, for no added
#: signal. The collapse below keys on this tag rather than on a rule list this
#: project would have to maintain — it is ZAP's own classification.
SYSTEMIC_TAG = "SYSTEMIC"


def collapse_systemic(
    work: list[tuple["Bundle", list[tuple[str, Any]]]],
) -> tuple[list[tuple["Bundle", list[tuple[str, Any]]]], dict[str, str]]:
    """Fold site-wide (``SYSTEMIC``-tagged) findings to one representative each.

    Keeps ONE representative per ``(plugin_id, alert_ref, evidence)`` across the
    WHOLE scan — the first seen with static context, else the first seen — drops
    the rest from the per-endpoint calls, and returns a ``dup -> representative``
    map so the representative's verdict can be fanned back to every folded instance
    (see the caller). Non-systemic findings — the injection classes the pipeline
    exists to judge per endpoint — are left untouched.

    Two findings that share a rule but differ in what they observed key
    differently (evidence is part of the key), so each still gets its own
    verdict: the collapse never merges two genuinely different observations.
    """
    def key_of(group: Any) -> tuple[str, str, str]:
        return (group.plugin_id, group.alert_ref,
                (group.evidence or "")[:join.EVIDENCE_KEY_CHARS])

    # Stable, so "first seen" still holds within each class. A no-context instance
    # must not displace a representative that has the better evidence.
    rep_by_key: dict[tuple[str, str, str], str] = {}
    for bundle, pairs in sorted(work, key=lambda item: not item[0].has_static_context):
        for fid, group in pairs:
            if SYSTEMIC_TAG in (group.tags or {}):
                rep_by_key.setdefault(key_of(group), fid)

    fanout: dict[str, str] = {}
    collapsed: list[tuple["Bundle", list[tuple[str, Any]]]] = []
    for bundle, pairs in work:
        kept: list[tuple[str, Any]] = []
        for fid, group in pairs:
            rep = (rep_by_key[key_of(group)]
                   if SYSTEMIC_TAG in (group.tags or {}) else fid)
            if rep == fid:
                kept.append((fid, group))
            else:
                fanout[fid] = rep
        if kept:
            collapsed.append((bundle, kept))
    return collapsed, fanout


def fan_systemic_verdicts(
    findings: list[dict[str, Any]], fanout: dict[str, str]
) -> int:
    """Copy each representative's verdict onto the systemic instances folded into it.

    Identical ``(rule, evidence)`` means the model's answer is the same, so this
    copies rather than re-asks and records ``llm.fanned_from`` so the artifact
    never claims a folded instance was judged independently. A representative
    whose own call did not answer (``llm`` is ``None``) has nothing to fan; its
    instances stay asked-but-unanswered. Returns how many were fanned.
    """
    by_id = {f["finding_id"]: f for f in findings}
    fanned = 0
    for dup_fid, rep_fid in fanout.items():
        rep = by_id.get(rep_fid)
        dup = by_id.get(dup_fid)
        if rep is None or dup is None or not rep.get("llm"):
            continue
        dup["llm"] = dict(rep["llm"])
        dup["llm"]["fanned_from"] = rep_fid
        dup["agreement"] = join.label_agreement(dup)
        fanned += 1
    return fanned


#: Pass-1 calls run in a bounded pool: ~60 endpoints x ~50s of round trip is
#: ~55 minutes of a CI job spent waiting on a network that was never the
#: bottleneck. The calls are independent by construction — one endpoint per
#: call is the design of this pass — so the only reasons not to parallelise are
#: rate limits and reproducibility, and both are handled: the ceiling is small
#: enough to stay well inside OpenRouter's per-model limits, and nothing about
#: the *result* depends on completion order (see :func:`run_llm_arm`).
#: ``--concurrency 1`` reproduces the old sequential behaviour exactly.
DEFAULT_CONCURRENCY = 10




__all__ = [
    'REPO_ROOT',
    'DATA_DIR',
    '_existing_model',
    '_would_discard_llm_results',
    '_findings_of',
    'SYSTEMIC_TAG',
    'collapse_systemic',
    'fan_systemic_verdicts',
    'DEFAULT_CONCURRENCY',
]
