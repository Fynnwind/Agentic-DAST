"""Pass 2 of the triage LLM arm — global synthesis: one call over the whole screened scan,
emitting only cross-endpoint (correlated) findings, never re-screening.

A separate pass because pass 1 (:mod:`~dast_orchestrator.analysis.screening`) calls the
model once per endpoint and structurally cannot notice that two endpoints share a handler
or a missing guard; this pass is shallow-but-wide (names without snippets, flagged findings
only, the whole run in one call). It is downstream of pass 1 — the corpus carries pass 1's
per-finding verdict so it can tell judged / asked-unanswered / never-asked apart — and is
built around Noir's shared-handler map. → DECISIONS.md.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from dast_orchestrator.analysis.join import (
    Bundle,
    INFORMATIONAL,
    shared_handlers,
    signal_names as _names,
)
from dast_orchestrator.foundation import prompts
from dast_orchestrator.adapters.noir_runner import classify_guard

#: **Pass 2 — cross-endpoint synthesis.** The opposite workload: exactly ONE
#: call over the whole screened scan, so the unit price is nearly irrelevant
#: (~$0.02 a run) and the quality of a single long chain of reasoning is
#: everything. Chosen for *output* price among reasoning-capable models — a
#: reasoning model bills its thinking as completion tokens, and this one is
#: $0.38/Mtok out against $1.20–$3.74 for the rest of that tier — with 14
#: providers.
#:
#: **This is the one place an expensive model is affordable**: at one call per
#: run, ``z-ai/glm-5.2`` costs about $0.09 and ``anthropic/claude-sonnet-5``
#: about $0.20. If any stage repays a stronger model, it is this one — pass 2
#: is the arm whose value the project has argued is synthesis rather than
#: per-finding screening. Compare with ``--synthesis-model``.
SYNTHESIS_MODEL = "deepseek/deepseek-v3.2"

SYNTHESIS_PROMPT_VERSION = prompts.load("synthesis").version

#: Wide and shallow: the budget goes to breadth, not to source snippets, which
#: pass 1 already read in depth.
MAX_ENDPOINTS = 120

#: Pass 1's reasoning is the only source evidence pass 2 receives, but 178
#: findings of unbounded prose would crowd out the breadth this pass exists for.
MAX_SCREENING_REASONING_CHARS = 240

#: Pass 2's own output ceiling, well above pass 1's. Pass 1 can absorb a
#: truncation by splitting the chunk; pass 2 is a single call by design, so a
#: truncation costs the whole pass — as it did on the second live run, where a
#: 31k-token corpus produced enough reasoning to exhaust an 8192 budget.
SYNTHESIS_MAX_TOKENS = 24576

#: Endpoint count for the fallback retry after a truncation. Narrower corpus,
#: same shape: better a synthesis over the busiest endpoints than none at all.
FALLBACK_MAX_ENDPOINTS = 35

SYNTHESIS_SYSTEM_PROMPT = prompts.load("synthesis").text

SYNTHESIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["correlated_findings"],
    "properties": {
        "correlated_findings": {
            "type": "array",
            "description": (
                "Cross-cutting findings only. May be empty. Never a restatement "
                "of a single ZAP alert."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "title",
                    "pattern",
                    "severity",
                    "confidence",
                    "reasoning",
                    "supporting_finding_ids",
                    "affected_routes",
                    "suggested_tool",
                ],
                "properties": {
                    "title": {"type": "string"},
                    "pattern": {
                        "type": "string",
                        "enum": [
                            "propagation-shared-handler",
                            "missing-guard-family",
                            "chain",
                            "systemic-absence",
                            "other",
                        ],
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["informational", "low", "medium", "high"],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "reasoning": {"type": "string"},
                    "supporting_finding_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "finding_ids this rests on. Must be non-empty.",
                    },
                    "affected_routes": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Route templates the finding covers, including ones "
                            "the scanner never flagged."
                        ),
                    },
                    "suggested_tool": {
                        "type": "string",
                        "enum": ["sqlmap", "nuclei", "ffuf", "interactsh",
                                 "self-evident", "out-of-scope"],
                        "description": (
                            "How this claim can be settled. A tool name means an "
                            "independent tool could test it (it is dispatched like "
                            "any finding). `self-evident` means it is provable from "
                            "the cited findings without a new probe (a systemic "
                            "absence of a control the cited findings already "
                            "confirmed). `out-of-scope` means no tool in this "
                            "prototype can test it and it needs manual evaluation "
                            "(an exploitability chain, a human judgement)."
                        ),
                    },
                },
            },
        }
    },
}


# -- corpus construction ---------------------------------------------------


def _screening_view(finding: dict[str, Any]) -> dict[str, Any]:
    """Carry pass 1's judgment forward into pass 2's corpus.

    This is the only route by which the *source code* reaches pass 2. Pass 1
    read the handler's guards, sinks and snippets in depth; pass 2 is built
    shallow so the whole scan fits one call, and would otherwise be reasoning
    about routes with no idea what their code does. Pass 1's own reasoning is
    that depth already compressed to a sentence or two — "the route is behind an
    auth guard (sessioner middleware, confidence 86)" is exactly the kind of
    statement that decides whether a propagation claim to a sibling route holds.

    Three states, kept distinct on purpose:
      * a verdict            -> pass 1 judged it, with the code in front of it
      * asked, no verdict    -> pass 1 was asked and never answered. NOT a clean
                                bill of health, and must not be read as one.
      * not asked            -> filtered out before pass 1 ran (informational
                                noise), so nothing was ever claimed about it.
    """
    screening = finding.get("llm")
    if screening:
        return {
            "pass1_verdict": screening.get("verdict", ""),
            "pass1_confidence": screening.get("confidence", ""),
            "pass1_wants_rescan": bool(screening.get("needs_rescan")),
            # The compressed source evidence. Trimmed: 178 findings of
            # unbounded prose would crowd out the breadth this pass exists for.
            "pass1_reasoning": _trim(screening.get("reasoning", ""), MAX_SCREENING_REASONING_CHARS),
        }
    if finding.get("llm_asked"):
        return {"pass1_verdict": "asked-but-unanswered"}
    return {"pass1_verdict": "not-screened"}


def _trim(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def is_interesting(finding: dict[str, Any]) -> bool:
    """What earns a finding a place in the corpus.

    The same filter the LLM candidate selection uses, for the same reason: 293
    of the 1247 findings in the 60-minute run are one informational fuzzer rule,
    and spending the synthesis budget on them would crowd out the handful of
    findings a cross-cutting pattern could actually rest on.
    """
    return (
        finding["alert"]["risk"] != INFORMATIONAL
        or finding["deterministic"]["needs_rescan"]
    )


def build_corpus(
    bundles: list[Bundle],
    findings: list[dict[str, Any]],
    scan_summary: dict[str, Any],
    max_endpoints: int = MAX_ENDPOINTS,
    oracle: "dict[str, Any] | None" = None,
) -> dict[str, Any]:
    """The whole screened scan, compressed to what a cross-endpoint view needs.

    :param max_endpoints: cap on endpoints included, busiest first. Lowered to
        :data:`FALLBACK_MAX_ENDPOINTS` on a retry after truncation.
    :param oracle: the target's documented vulnerabilities, in oracle-guided
        (``--ceiling``) runs only — see :mod:`dast_orchestrator.analysis.oracle`. This is
        the pass the knowledge should help most: it is the one that can trace a
        described weakness across a route family, which is what the shared
        handler map is for.
    """
    interesting = [f for f in findings if is_interesting(f)]
    by_endpoint: dict[str, list[dict[str, Any]]] = {}
    for finding in interesting:
        key = finding["endpoint_key"] or f"{finding['method']} {finding['path']}"
        by_endpoint.setdefault(key, []).append(finding)

    bundles_by_id = {b.identifier: b for b in bundles}
    routes_with_findings = set(by_endpoint)

    endpoints = []
    for key, group in sorted(by_endpoint.items(), key=lambda kv: -len(kv[1]))[:max_endpoints]:
        bundle = bundles_by_id.get(key)
        entry: dict[str, Any] = {
            "route": key,
            "static_context": "present" if (bundle and bundle.has_static_context) else "absent",
            "findings": [
                {
                    "finding_id": f["finding_id"],
                    "rule": f["alert"]["name"],
                    "plugin_id": f["alert"]["plugin_id"],
                    "risk": f["alert"]["risk"],
                    "zap_confidence": f["alert"]["confidence"],
                    "parameter": f["alert"]["param"],
                    "instances": f["alert"]["instances"],
                    "already_flagged_for_rescan": f["deterministic"]["needs_rescan"],
                    **_screening_view(f),
                }
                for f in group
            ],
        }
        if bundle and bundle.has_static_context:
            for category in ("guards", "sinks", "sources", "validators", "callees"):
                names = _names(bundle, category)
                if not names:
                    continue
                # Guards carry their semantics, because Noir labels Gitea's
                # session middleware as an auth guard on every public route and
                # a bare name reads as "protected" when it is not.
                entry[category] = (
                    [f"{n} ({classify_guard(n)})" for n in names]
                    if category == "guards"
                    else names
                )
        endpoints.append(entry)

    suppressed = len(findings) - len(interesting)
    return {
        **({"known_vulnerabilities_of_this_target": oracle} if oracle else {}),
        "target": scan_summary.get("target", ""),
        "scan_shape": {
            "raw_alerts": scan_summary.get("raw_alerts"),
            "findings_total": len(findings),
            "findings_shown": len(interesting),
            "findings_suppressed_as_informational_noise": suppressed,
            "alerts_by_zap_source": scan_summary.get("alerts_by_zap_source", {}),
            "top_rules": scan_summary.get("top_rules", [])[:5],
        },
        "note_on_suppression": (
            "Findings that are informational AND not flagged for rescan are "
            "omitted from this view; they are overwhelmingly one User-Agent "
            "fuzzer rule. Their absence is a filter, not a property of the target."
        ),
        "shared_handlers": shared_handlers(bundles, routes_with_findings),
        "endpoints": endpoints,
    }


def build_messages(corpus: dict[str, Any],
                   system_prompt: str | None = None) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system_prompt or SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(corpus, indent=1)},
    ]


# -- validation ------------------------------------------------------------


def collect(
    response: dict[str, Any], known_finding_ids: Iterable[str]
) -> tuple[list[dict[str, Any]], int]:
    """Normalise and validate the pass-2 output.

    Returns (findings, dropped). A synthesis finding that cites no *real*
    finding_id is dropped outright: the entire claim of this pass is that its
    output rests on observed evidence, and one that cites nothing observable is
    indistinguishable from a guess about the application.
    """
    known = set(known_finding_ids)
    out: list[dict[str, Any]] = []
    dropped = 0
    for index, item in enumerate(response.get("correlated_findings", [])):
        # Deduplicated as well as filtered: the same finding cited twice is one
        # piece of evidence, and letting it count twice would inflate how
        # well-supported a synthesis finding looks.
        supporting: list[str] = []
        for fid in item.get("supporting_finding_ids", []):
            if fid in known and fid not in supporting:
                supporting.append(fid)
        if not supporting:
            dropped += 1
            continue
        out.append(
            {
                "finding_id": f"c-{index:03d}",
                "origin": "llm-cross-endpoint-synthesis",
                "pattern": item.get("pattern", "other"),
                "title": item.get("title", ""),
                "severity": item.get("severity", ""),
                "confidence": item.get("confidence", ""),
                "reasoning": item.get("reasoning", ""),
                "supporting_finding_ids": supporting,
                "affected_routes": list(item.get("affected_routes", [])),
                # Default to the honest floor: an unclassified claim is
                # out-of-scope (manual), never silently treated as testable or
                # self-evident. The schema requires the field, so this only bites
                # a malformed response.
                "suggested_tool": item.get("suggested_tool", "out-of-scope"),
            }
        )
    return out, dropped


# -- repeats -----------------------------------------------------------------

#: How many independent synthesis calls to make over the same corpus. One is the
#: historical behaviour and stays the default; the case for more is measured
#: rather than assumed — see :func:`merge_repeats`.
DEFAULT_REPEATS = 5


def claim_key(finding: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    """Identity of a synthesis claim: its pattern plus the exact evidence it cites.

    Deliberately not the prose. Two calls describe the same correlation in
    different words every time, so comparing titles would count one claim as
    many; the *set of ZAP findings a claim rests on* is what makes it the same
    claim, and it is the thing the pass is required to ground itself in anyway.
    """
    return (str(finding.get("pattern") or "other"),
            tuple(sorted(finding.get("supporting_finding_ids") or [])))


@dataclass(frozen=True)
class Sample:
    """One whole-corpus synthesis call: which model made it, and what it claimed."""

    model: str
    claims: list[dict[str, Any]]


def merge_repeats(runs: list[list[dict[str, Any]]],
                  model: str = "") -> list[dict[str, Any]]:
    """:func:`merge_samples` for N calls to one model. Kept as the simple case."""
    return merge_samples([Sample(model, claims) for claims in runs])


def merge_samples(samples: list[Sample]) -> list[dict[str, Any]]:
    """Union the claims of N independent calls, scored by how many produced each.

    **Why repeats exist at all.** The pass is *undersampled* rather than
    unreliable: a single call surfaces a given cross-endpoint claim only a fraction
    of the time (more repeats, more reliably), yet its findings are real — each is
    grounded in cited alerts — and which ones appear is close to a lottery.
    Synthesis is one shallow call costing a fraction of a cent against a 45-minute
    scan, so buying samples is the cheapest reliability in the pipeline.

    **This does not chunk the corpus, and the distinction is load-bearing.** Each
    repeat is a *complete* call over the whole scan, exactly as before; a
    correlation spanning two endpoints is visible to every one of them. The rule
    that pass 2 must never be chunked is intact.

    **The reproducibility score is the point, not a by-product.** More samples
    also surface more one-off claims, so a bare union of eight calls is 17 claims
    of unknown quality. ``seen_in`` is what separates a claim eight calls agree
    on from one that appeared once, and it is the field a reader should sort by.
    A claim seen once is not thereby false — the high-severity one is real and
    rare — but it is a lead rather than a result.

    **Cross-model agreement is the stronger signal, and it leads the sort.**
    Repeats of one model measure how *stably* that model draws a claim; two
    different models producing the same claim from the same evidence is a
    different and better fact, because their failure modes are not shared. A
    claim every model reaches is the one to act on; a claim one model reaches
    five times may be five samples of the same idiosyncrasy. So
    ``models_agreeing`` sorts ahead of ``seen_in`` — and with a single model it
    is 1 everywhere, which leaves the single-model ordering exactly as it was.
    """
    total = len(samples)
    models = sorted({s.model for s in samples if s.model})
    order: list[tuple[str, tuple[str, ...]]] = []
    first: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    seen: dict[tuple[str, tuple[str, ...]], int] = {}
    by_model: dict[tuple[str, tuple[str, ...]], dict[str, int]] = {}
    for sample in samples:
        # De-duplicated within a sample: one call claiming the same thing twice
        # is one draw, not two, or a repetitive model would outscore an
        # agreeing one.
        for claim in {claim_key(c): c for c in sample.claims}.values():
            key = claim_key(claim)
            if key not in first:
                first[key] = claim
                order.append(key)
                by_model[key] = {}
            seen[key] = seen.get(key, 0) + 1
            if sample.model:
                by_model[key][sample.model] = by_model[key].get(sample.model, 0) + 1

    # Agreement first, then sample count, then a total order on the claim
    # itself, so two runs of the same scan produce the same artifact rather than
    # the same set in a different order.
    order.sort(key=lambda k: (-len(by_model[k]), -seen[k], k[0], k[1]))
    merged = []
    for index, key in enumerate(order):
        claim = dict(first[key])
        claim["finding_id"] = f"c-{index:03d}"
        reproducibility: dict[str, Any] = {"seen_in": seen[key], "of": total}
        if len(models) > 1:
            reproducibility["models_agreeing"] = len(by_model[key])
            reproducibility["of_models"] = len(models)
            reproducibility["by_model"] = dict(sorted(by_model[key].items()))
        claim["reproducibility"] = reproducibility
        merged.append(claim)
    return merged
